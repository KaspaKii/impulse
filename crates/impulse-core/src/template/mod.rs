// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault instantiation (spec/TEMPLATE.md). The compiled template is embedded and checked
//! against contracts/TEMPLATE_HASH before first use. A leg's redeem script is the template
//! prefix, the terms and the leg index encoded as the contract state, then the template suffix;
//! its P2SH scriptPubKey is what the leg's depositor funds. Decoding reverses the splice and
//! accepts only scripts that instantiation would produce byte for byte.
//!
//! Two kinds of vault value: [`Vault`] for an existing trade (settle, refund, verify, decode),
//! and [`FundableVault`], whose terms also passed the creation checks. Only the latter has a
//! funding address (`crate::address::vault_address`).
//!
//! Adapted from an internal instantiation pattern by the owner (relicensed, see NOTICE):
//! artifact embed, prefix and suffix split, template hash check, splice, decode, template hash
//! of an instance. One change: the state span here varies in length (a KAS destination
//! scriptPubKey is a byte string), so the split uses the template's prefix and suffix lengths,
//! not the compiled example's state span. Keyless: nothing here signs or holds a private key.

mod error;
pub(crate) mod state;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

pub use error::{TemplateError, TEMPLATE_ERROR_CODES};

use crate::terms::{CreationContext, LegKind, Network, SettlementMode, Terms, ValidatedTerms};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_runtime_state_script, template_hash, RuntimeStateArtifact,
    SilAbiArtifact,
};
use std::sync::LazyLock;

/// The compiled ImpulseVault v1, as `scripts/build-template.sh` checks it against
/// the pinned silverc. Embedded so nothing at runtime needs the compiler.
const ARTIFACT_JSON: &str = include_str!("../../../../contracts/compiled/impulse_vault.v1.json");

/// The template hash every Impulse vault runs (contracts/TEMPLATE_HASH).
const TEMPLATE_HASH_FILE: &str = include_str!("../../../../contracts/TEMPLATE_HASH");

/// The contract name in the artifact.
pub const CONTRACT_NAME: &str = "ImpulseVault";

/// A loaded template, or the reason the startup check refused it.
type Checked = Result<Template, TemplateError>;

static TEMPLATE: LazyLock<Checked> =
    LazyLock::new(|| Template::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE));

/// The startup check: loads the embedded template once and returns it, or the reason it is
/// unusable. Every instantiation and decode goes through it, so a template that fails the check
/// never produces or accepts a script. Callers may run it at startup to fail early.
pub fn check() -> Result<&'static Template, TemplateError> {
    usable(&TEMPLATE)
}

/// The template if the startup check passed, else its refusal.
fn usable(template: &Checked) -> Result<&Template, TemplateError> {
    template.as_ref().map_err(Clone::clone)
}

/// The checked ImpulseVault template: the bytes around the state span, their template hash, and
/// the artifact's state layout.
#[derive(Debug)]
pub struct Template {
    abi: SilAbiArtifact,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
}

impl Template {
    /// Parses and checks an artifact against a TEMPLATE_HASH file, in this order: the artifact
    /// parses with the supported schema and holds exactly ImpulseVault; its state layout is the
    /// one this crate maps; its prefix and suffix hash to its declared template hash and to
    /// TEMPLATE_HASH; it is otherwise self-consistent.
    fn load(artifact_json: &str, template_hash_file: &str) -> Result<Self, TemplateError> {
        let invalid = |reason: String| TemplateError::ArtifactInvalid { reason };
        let abi: SilAbiArtifact = serde_json::from_str(artifact_json)
            .map_err(|e| invalid(format!("artifact does not parse: {e}")))?;
        abi.check_schema_version()
            .map_err(|e| invalid(e.to_string()))?;
        if abi.contracts.len() != 1 || !abi.contracts.contains_key(CONTRACT_NAME) {
            return Err(invalid(format!(
                "artifact must hold exactly {CONTRACT_NAME}, found {:?}",
                abi.contracts.keys().collect::<Vec<_>>()
            )));
        }
        let contract = &abi.contracts[CONTRACT_NAME];
        state::check_layout(&contract.runtime_state).map_err(invalid)?;

        let compiled = &contract.compiled;
        let (prefix, _example_state, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| invalid("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(invalid("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        if hash != compiled.template_hash {
            return Err(TemplateError::HashMismatch {
                expected: compiled.template_hash,
                found: hash,
            });
        }
        let pinned = parse_hash(template_hash_file)
            .ok_or_else(|| invalid("TEMPLATE_HASH is not 64 lowercase hex digits".into()))?;
        if hash != pinned {
            return Err(TemplateError::HashMismatch {
                expected: pinned,
                found: hash,
            });
        }
        // Span, canonical example state and template hash, as silverscript itself checks them.
        abi.check_consistency()
            .map_err(|e| invalid(e.to_string()))?;
        let (prefix, suffix) = (prefix.to_vec(), suffix.to_vec());
        Ok(Self {
            abi,
            prefix,
            suffix,
            hash,
        })
    }

    /// The template hash (silverscript's blake3 over the length-prefixed prefix and suffix).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Template bytes before the state span.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Template bytes after the state span.
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }

    /// The artifact's ABI: the builders (I5) encode `settle` and `refund` calls with it.
    pub(crate) fn abi(&self) -> &SilAbiArtifact {
        &self.abi
    }

    fn runtime_state(&self) -> &RuntimeStateArtifact {
        &self.abi.contracts[CONTRACT_NAME].runtime_state
    }

    /// The state span of `script` if it runs this template, else None.
    fn state_span<'a>(&self, script: &'a [u8]) -> Option<&'a [u8]> {
        let (p, s) = (self.prefix.len(), self.suffix.len());
        if script.len() < p + s
            || !script.starts_with(&self.prefix)
            || !script.ends_with(&self.suffix)
        {
            return None;
        }
        Some(&script[p..script.len() - s])
    }
}

/// `TEMPLATE_HASH` file content: 64 lowercase hex digits and an optional final newline.
fn parse_hash(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_suffix('\n').unwrap_or(text);
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Which leg a vault escrows. The contract checks it as `legIndex`: the asset authorizer settles
/// at input 0, the cash authorizer at input 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LegIndex {
    /// The seller's asset leg, index 0.
    Asset,
    /// The buyer's cash leg, index 1.
    Cash,
}

impl LegIndex {
    pub const ALL: [LegIndex; 2] = [LegIndex::Asset, LegIndex::Cash];

    /// The contract's `legIndex` value.
    pub fn index(self) -> u8 {
        match self {
            LegIndex::Asset => 0,
            LegIndex::Cash => 1,
        }
    }

    /// Refuses any value other than 0 and 1 (`TEMPLATE_LEG_INDEX`).
    pub fn from_index(value: i64) -> Result<Self, TemplateError> {
        match value {
            0 => Ok(LegIndex::Asset),
            1 => Ok(LegIndex::Cash),
            _ => Err(TemplateError::LegIndex { value }),
        }
    }
}

impl TryFrom<i64> for LegIndex {
    type Error = TemplateError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::from_index(value)
    }
}

/// One leg's vault: the redeem script instantiated from structure-checked terms, and its P2SH.
/// It serves an existing trade and has no funding address; see [`FundableVault`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    network: Network,
    leg: LegIndex,
    redeem_script: Vec<u8>,
}

impl Vault {
    /// The vault of `leg` of an existing trade (settle, refund, verify, decode). No creation
    /// checks run, so a trade past its expiry still yields its vaults for refunds. Refuses a leg
    /// that has no vault under the terms (`TEMPLATE_NO_VAULT`). To show a funding address, use
    /// [`Vault::instantiate_for_creation`].
    pub fn instantiate_existing(
        terms: &ValidatedTerms,
        leg: LegIndex,
    ) -> Result<Self, TemplateError> {
        instantiate_with(&TEMPLATE, terms, leg)
    }

    /// The vault of `leg` for a trade being created or accepted, before anyone funds it: runs
    /// the creation checks first (network, expiry after the creation DAA score and within the
    /// horizon; spec/ENCODING.md), then [`Vault::instantiate_existing`]. The result is the only
    /// vault value a funding address is shown for.
    pub fn instantiate_for_creation(
        terms: &ValidatedTerms,
        leg: LegIndex,
        ctx: &CreationContext,
    ) -> Result<FundableVault, TemplateError> {
        terms.validate_creation(ctx)?;
        Ok(FundableVault(Self::instantiate_existing(terms, leg)?))
    }

    /// The network the terms name; the address prefix follows it.
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn leg(&self) -> LegIndex {
        self.leg
    }

    /// The redeem script a spend of this vault reveals.
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// The vault's P2SH scriptPubKey: OpBlake2b OpData32 <script hash> OpEqual.
    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem_script)
    }

    /// blake2b-256 of the redeem script, read back out of the P2SH scriptPubKey. It is also the
    /// KCC-20 SCRIPT_HASH owner identifier of the leg's escrowed token.
    pub fn script_hash(&self) -> [u8; 32] {
        let spk = self.script_public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&spk.script()[2..34]);
        out
    }
}

/// A vault whose terms passed the creation checks as well as the structure checks: the leg of a
/// trade being created or accepted. Only [`Vault::instantiate_for_creation`] makes one, and only
/// this type has a funding address, so an expired or mis-networked trade is never shown as
/// something to fund.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundableVault(Vault);

impl FundableVault {
    pub fn vault(&self) -> &Vault {
        &self.0
    }

    pub fn into_vault(self) -> Vault {
        self.0
    }
}

/// Decodes a revealed redeem script back to the terms and the leg index. Accepts only a script
/// that [`Vault::instantiate_existing`] produces from the decoded terms, byte for byte, so every
/// vault has one decoding and every decoding one vault. The terms come back structure-checked.
pub fn decode(redeem_script: &[u8]) -> Result<(ValidatedTerms, LegIndex), TemplateError> {
    decode_with(&TEMPLATE, redeem_script)
}

/// The template hash recomputed from a script's own prefix and suffix bytes, at the template's
/// prefix and suffix lengths, without trusting any declared hash. Equal to the checked template
/// hash for every vault, whatever its state; a script of another template gives another hash.
pub fn template_hash_of_instance(script: &[u8]) -> Result<[u8; 32], TemplateError> {
    template_hash_of_instance_with(&TEMPLATE, script)
}

// The functions behind the public ones take the template explicitly, so a test can run them
// against a template that failed the startup check.

fn instantiate_with(
    template: &Checked,
    terms: &ValidatedTerms,
    leg: LegIndex,
) -> Result<Vault, TemplateError> {
    let template = usable(template)?;
    let t = terms.terms();
    has_vault(t, leg)?;
    let values = state::values(t, leg)?;
    let state = encode_runtime_state_script(&template.abi, template.runtime_state(), &values)
        .map_err(|e| TemplateError::StateMalformed {
            reason: e.to_string(),
        })?;
    let mut redeem_script =
        Vec::with_capacity(template.prefix.len() + state.len() + template.suffix.len());
    redeem_script.extend_from_slice(&template.prefix);
    redeem_script.extend_from_slice(&state);
    redeem_script.extend_from_slice(&template.suffix);
    Ok(Vault {
        network: t.network,
        leg,
        redeem_script,
    })
}

fn decode_with(
    template: &Checked,
    redeem_script: &[u8],
) -> Result<(ValidatedTerms, LegIndex), TemplateError> {
    let loaded = usable(template)?;
    let span = loaded
        .state_span(redeem_script)
        .ok_or(TemplateError::NotImpulseVault)?;
    let values =
        decode_runtime_state_script(&loaded.abi, loaded.runtime_state(), span).map_err(|e| {
            TemplateError::StateMalformed {
                reason: e.to_string(),
            }
        })?;
    let (terms, leg) = state::terms(&values)?;
    let terms = terms.validate_structure()?;
    let vault = instantiate_with(template, &terms, leg)?;
    if vault.redeem_script != redeem_script {
        return Err(TemplateError::NonCanonical);
    }
    Ok((terms, leg))
}

fn template_hash_of_instance_with(
    template: &Checked,
    script: &[u8],
) -> Result<[u8; 32], TemplateError> {
    let template = usable(template)?;
    let (p, s) = (template.prefix.len(), template.suffix.len());
    if script.len() < p + s {
        return Err(TemplateError::NotImpulseVault);
    }
    Ok(template_hash(&script[..p], &script[script.len() - s..]))
}

/// Direct terms escrow nothing, and external cash has no cash vault (spec "Settlement modes").
fn has_vault(t: &Terms, leg: LegIndex) -> Result<(), TemplateError> {
    if t.settlement_mode == SettlementMode::Direct {
        return Err(TemplateError::NoVault {
            leg,
            reason: "Direct terms escrow nothing",
        });
    }
    if leg == LegIndex::Cash && t.cash_leg.kind == LegKind::External {
        return Err(TemplateError::NoVault {
            leg,
            reason: "external cash settles off chain",
        });
    }
    Ok(())
}
