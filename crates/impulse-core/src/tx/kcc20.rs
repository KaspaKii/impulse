// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! KCC-20 templates for the builders. A leg's terms name its token's template by hash and by
//! prefix and suffix lengths only; to build a token UTXO's redeem script, and the signature
//! script of a `transfer`, a builder needs the template bytes and the ABI. They come from the
//! token's silverscript ABI artifact, which this module checks against the KCC-20 layout of
//! kcc20.sil (silverscript v1.0.0) and, per leg, against the hash and lengths in the terms.

use super::TxError;
use crate::terms::{IdentifierType, Kcc20Owner, Kcc20Token};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_contract_covenant_decl_sig_script,
    encode_runtime_state_script, template_hash, ArtifactValue, SilAbiArtifact, TypeArtifact,
};
use std::collections::BTreeMap;

/// The KCC-20 covenant declaration a token moves through.
const TRANSFER: &str = "transfer";

/// A KCC-20 UTXO's state (kcc20.sil field order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc20State {
    pub owner: Kcc20Owner,
    /// Token units; at most `i64::MAX`, the range of script integers.
    pub amount: u64,
    pub is_minter: bool,
}

impl Kcc20State {
    /// A non-minter state.
    pub fn new(owner: Kcc20Owner, amount: u64) -> Self {
        Self {
            owner,
            amount,
            is_minter: false,
        }
    }

    pub(crate) fn identifier_type_byte(&self) -> u8 {
        match self.owner.identifier_type {
            IdentifierType::PubKey => 0,
            IdentifierType::ScriptHash => 1,
            IdentifierType::CovenantId => 2,
        }
    }

    fn to_value(self) -> Result<ArtifactValue, TxError> {
        let amount = i64::try_from(self.amount).map_err(|_| TxError::Encoding {
            reason: format!("token amount {} exceeds i64::MAX", self.amount),
        })?;
        Ok(ArtifactValue::Object(BTreeMap::from([
            (
                "ownerIdentifier".to_string(),
                ArtifactValue::Bytes(self.owner.identifier.to_vec()),
            ),
            (
                "identifierType".to_string(),
                ArtifactValue::Byte(self.identifier_type_byte()),
            ),
            ("amount".to_string(), ArtifactValue::Int(amount)),
            ("isMinter".to_string(), ArtifactValue::Bool(self.is_minter)),
        ])))
    }
}

/// A checked KCC-20 template: the bytes around the state, their hash, and the ABI that encodes
/// states and `transfer` calls.
#[derive(Clone, Debug)]
pub struct Kcc20Template {
    abi: SilAbiArtifact,
    name: String,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
}

/// The KCC-20 runtime state in kcc20.sil order.
fn state_layout() -> [(&'static str, TypeArtifact); 4] {
    [
        ("ownerIdentifier", TypeArtifact::FixedBytes { len: 32 }),
        ("identifierType", TypeArtifact::Byte),
        ("amount", TypeArtifact::Int),
        ("isMinter", TypeArtifact::Bool),
    ]
}

impl Kcc20Template {
    /// Parses and checks a silverscript ABI artifact (the JSON `silverc` writes) of a KCC-20
    /// token. See [`Kcc20Template::from_artifact`].
    pub fn from_json(json: &str) -> Result<Self, TxError> {
        let abi: SilAbiArtifact =
            serde_json::from_str(json).map_err(|e| TxError::TokenTemplate {
                reason: format!("KCC-20 artifact does not parse: {e}"),
            })?;
        Self::from_artifact(abi)
    }

    /// Checks, in order: supported schema; exactly one contract; its state is the KCC-20 state
    /// (owner identifier, identifier type, amount, minter flag); its `transfer` covenant has a
    /// leader entry `(newStates, sig, witness)` and a delegate entry `(sig, witness)`; the
    /// prefix and suffix around the state are not empty and hash to the declared template hash;
    /// silverscript's own consistency check passes. Refusals are `TX_TOKEN_TEMPLATE`.
    pub fn from_artifact(abi: SilAbiArtifact) -> Result<Self, TxError> {
        let bad = |reason: String| TxError::TokenTemplate { reason };
        abi.check_schema_version().map_err(|e| bad(e.to_string()))?;
        if abi.contracts.len() != 1 {
            return Err(bad(format!(
                "a KCC-20 artifact holds one contract, found {}",
                abi.contracts.len()
            )));
        }
        let (name, contract) = abi.contracts.iter().next().expect("one contract");
        let fields: Vec<(&str, &TypeArtifact)> = contract
            .runtime_state
            .fields
            .iter()
            .map(|f| (f.name.as_str(), &f.ty))
            .collect();
        let expected = state_layout();
        let layout: Vec<(&str, &TypeArtifact)> = expected.iter().map(|(n, t)| (*n, t)).collect();
        if fields != layout {
            return Err(bad("the contract state is not the KCC-20 state".into()));
        }
        let leader = contract
            .covenant_decl_entry(TRANSFER, true)
            .ok_or_else(|| bad("no transfer covenant leader entry".into()))?;
        let delegate = contract
            .covenant_decl_entry(TRANSFER, false)
            .ok_or_else(|| bad("no transfer covenant delegate entry".into()))?;
        let state_array = TypeArtifact::dynamic_array(TypeArtifact::Struct {
            name: contract.runtime_state.source.clone(),
        });
        let params = |e: &silverscript_abi::SilEntryArtifact| -> Vec<TypeArtifact> {
            e.params.iter().map(|p| p.ty.clone()).collect()
        };
        if params(leader) != [state_array, TypeArtifact::Sig, TypeArtifact::Byte]
            || params(delegate) != [TypeArtifact::Sig, TypeArtifact::Byte]
        {
            return Err(bad(
                "the transfer entries are not (newStates, sig, witness) and (sig, witness)".into(),
            ));
        }
        let compiled = &contract.compiled;
        let (prefix, _state, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| bad("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(bad("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        if hash != compiled.template_hash {
            return Err(bad(
                "the template bytes do not hash to the declared template hash".into(),
            ));
        }
        abi.check_consistency().map_err(|e| bad(e.to_string()))?;
        let (name, prefix, suffix) = (name.clone(), prefix.to_vec(), suffix.to_vec());
        Ok(Self {
            abi,
            name,
            prefix,
            suffix,
            hash,
        })
    }

    /// silverscript's template hash of the prefix and suffix.
    pub fn template_hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn prefix_len(&self) -> usize {
        self.prefix.len()
    }

    pub fn suffix_len(&self) -> usize {
        self.suffix.len()
    }

    /// Refuses a template other than the one the leg's terms name (hash, prefix and suffix
    /// lengths): `TX_TOKEN_TEMPLATE`.
    pub fn check_token(&self, token: &Kcc20Token) -> Result<(), TxError> {
        if self.hash != token.template_hash
            || self.prefix.len() != token.template_prefix_len as usize
            || self.suffix.len() != token.template_suffix_len as usize
        {
            return Err(TxError::TokenTemplate {
                reason: "the KCC-20 template is not the one the terms name for this leg".into(),
            });
        }
        Ok(())
    }

    /// The redeem script of a token UTXO in `state`: prefix, state, suffix.
    pub fn redeem_script(&self, state: &Kcc20State) -> Result<Vec<u8>, TxError> {
        let contract = &self.abi.contracts[&self.name];
        let values = match state.to_value()? {
            ArtifactValue::Object(fields) => fields,
            _ => unreachable!("a state is an object"),
        };
        let encoded = encode_runtime_state_script(&self.abi, &contract.runtime_state, &values)
            .map_err(|e| TxError::Encoding {
                reason: format!("KCC-20 state: {e}"),
            })?;
        let mut script = Vec::with_capacity(self.prefix.len() + encoded.len() + self.suffix.len());
        script.extend_from_slice(&self.prefix);
        script.extend_from_slice(&encoded);
        script.extend_from_slice(&self.suffix);
        Ok(script)
    }

    /// The state a redeem script of this template holds (prefix, encoded state, suffix), or
    /// None if the script is not this template's or does not hold a KCC-20 state exactly as
    /// [`Kcc20Template::redeem_script`] encodes it.
    pub(crate) fn state_of(&self, redeem: &[u8]) -> Option<Kcc20State> {
        let (p, s) = (self.prefix.len(), self.suffix.len());
        if redeem.len() < p + s
            || !redeem.starts_with(&self.prefix)
            || !redeem.ends_with(&self.suffix)
        {
            return None;
        }
        let contract = &self.abi.contracts[&self.name];
        let values = decode_runtime_state_script(
            &self.abi,
            &contract.runtime_state,
            &redeem[p..redeem.len() - s],
        )
        .ok()?;
        let identifier: [u8; 32] = match values.get("ownerIdentifier")? {
            ArtifactValue::Bytes(b) => b.as_slice().try_into().ok()?,
            _ => return None,
        };
        let identifier_type = match values.get("identifierType")? {
            ArtifactValue::Byte(0) => IdentifierType::PubKey,
            ArtifactValue::Byte(1) => IdentifierType::ScriptHash,
            ArtifactValue::Byte(2) => IdentifierType::CovenantId,
            _ => return None,
        };
        let amount = match values.get("amount")? {
            ArtifactValue::Int(n) => u64::try_from(*n).ok()?,
            _ => return None,
        };
        let is_minter = match values.get("isMinter")? {
            ArtifactValue::Bool(b) => *b,
            _ => return None,
        };
        let state = Kcc20State {
            owner: Kcc20Owner {
                identifier_type,
                identifier,
            },
            amount,
            is_minter,
        };
        (self.redeem_script(&state).ok()?.as_slice() == redeem).then_some(state)
    }

    /// The P2SH scriptPubKey of a token UTXO in `state`.
    pub fn script_public_key(&self, state: &Kcc20State) -> Result<ScriptPublicKey, TxError> {
        Ok(pay_to_script_hash_script(&self.redeem_script(state)?))
    }

    /// Signature script of `transfer` as covenant leader: the new states of the covenant's
    /// outputs, the owner's signature (`sig`), the witness input index, then the redeem script.
    pub(crate) fn leader_sigscript(
        &self,
        state: &Kcc20State,
        new_states: &[Kcc20State],
        sig: &[u8; 65],
        witness: u8,
    ) -> Result<Vec<u8>, TxError> {
        let states = new_states
            .iter()
            .map(|s| s.to_value())
            .collect::<Result<Vec<_>, _>>()?;
        self.covenant_sigscript(
            state,
            true,
            &[
                ArtifactValue::Array(states),
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Byte(witness),
            ],
        )
    }

    /// Signature script of `transfer` as covenant delegate: the owner's signature and the
    /// witness input index, then the redeem script.
    pub(crate) fn delegate_sigscript(
        &self,
        state: &Kcc20State,
        sig: &[u8; 65],
        witness: u8,
    ) -> Result<Vec<u8>, TxError> {
        self.covenant_sigscript(
            state,
            false,
            &[
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Byte(witness),
            ],
        )
    }

    fn covenant_sigscript(
        &self,
        state: &Kcc20State,
        is_leader: bool,
        args: &[ArtifactValue],
    ) -> Result<Vec<u8>, TxError> {
        let mut script = encode_contract_covenant_decl_sig_script(
            &self.abi, &self.name, TRANSFER, is_leader, args,
        )
        .map_err(|e| TxError::Encoding {
            reason: format!("KCC-20 transfer: {e}"),
        })?;
        script.extend_from_slice(&super::push_data(&self.redeem_script(state)?)?);
        Ok(script)
    }
}
