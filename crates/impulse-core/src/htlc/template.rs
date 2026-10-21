// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseHashlock instantiation (spec/V2.md section 10.1 and 10.2). The compiled template is
//! embedded and checked against contracts/TEMPLATE_HASH_HASHLOCK before first use
//! (`HTLC_ARTIFACT_INVALID`, `HTLC_HASH_MISMATCH`). A trade's redeem script is the template
//! prefix, the hashlock state (the terms with the counterpart record replaced by its hash), then
//! the template suffix; its P2SH scriptPubKey is what the seller funds. Decoding reverses the
//! splice and accepts only scripts that instantiation would produce byte for byte.
//!
//! The same pattern as the v1 template module (crate::template): artifact embed, prefix and
//! suffix split, template hash check, splice, decode, template hash of an instance. Keyless.

use super::codec::{id_type, id_type_byte, network_byte, network_of};
use super::validate::{self, HtlcCreationContext};
use super::{HtlcError, HtlcState, ValidatedHtlcTerms};
use crate::address::prefix;
use crate::terms::{Kcc20Owner, Kcc20Token, Leg, LegKind, Network};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_runtime_state_script, template_hash, ArtifactValue,
    RuntimeStateArtifact, SilAbiArtifact, TypeArtifact,
};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The compiled ImpulseHashlock v1, as `scripts/build-template-hashlock.sh` checks it against the
/// pinned silverc. Embedded so nothing at runtime needs the compiler.
const ARTIFACT_JSON: &str = include_str!("../../../../contracts/compiled/impulse_hashlock.v1.json");

/// The template hash every hashlock vault runs (contracts/TEMPLATE_HASH_HASHLOCK).
const TEMPLATE_HASH_FILE: &str = include_str!("../../../../contracts/TEMPLATE_HASH_HASHLOCK");

/// The contract name in the artifact.
pub const CONTRACT_NAME: &str = "ImpulseHashlock";

type Checked = Result<HtlcTemplate, HtlcError>;

static TEMPLATE: LazyLock<Checked> =
    LazyLock::new(|| HtlcTemplate::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE));

/// The startup check: loads the embedded hashlock template once and returns it, or the reason it
/// is unusable. Every instantiation and decode goes through it.
pub fn check() -> Result<&'static HtlcTemplate, HtlcError> {
    usable(&TEMPLATE)
}

fn usable(template: &Checked) -> Result<&HtlcTemplate, HtlcError> {
    template.as_ref().map_err(Clone::clone)
}

/// One state field's type, as silverscript-abi names it.
#[derive(Clone, Copy)]
enum Kind {
    Byte,
    Int,
    Pubkey,
    Fixed(usize),
}

impl Kind {
    fn artifact(self) -> TypeArtifact {
        match self {
            Kind::Byte => TypeArtifact::Byte,
            Kind::Int => TypeArtifact::Int,
            Kind::Pubkey => TypeArtifact::Pubkey,
            Kind::Fixed(len) => TypeArtifact::FixedBytes { len },
        }
    }
}

/// The ImpulseHashlock state in contract order (contracts/impulse_hashlock.sil, spec/V2.md
/// section 10.2).
const LAYOUT: [(&str, Kind); 18] = [
    ("version", Kind::Byte),
    ("network", Kind::Byte),
    ("nonce", Kind::Fixed(8)),
    ("sellerKey", Kind::Pubkey),
    ("buyerKey", Kind::Pubkey),
    ("assetCovenantId", Kind::Fixed(32)),
    ("assetTemplateHash", Kind::Fixed(32)),
    ("assetPrefixLen", Kind::Int),
    ("assetSuffixLen", Kind::Int),
    ("amount", Kind::Int),
    ("buyerDeliveryType", Kind::Byte),
    ("buyerDeliveryId", Kind::Fixed(32)),
    ("sellerRefundType", Kind::Byte),
    ("sellerRefundId", Kind::Fixed(32)),
    ("hashLock", Kind::Fixed(32)),
    ("expiryDaa", Kind::Int),
    ("counterpartHash", Kind::Fixed(32)),
    ("tradeRef", Kind::Fixed(32)),
];

/// The checked ImpulseHashlock template: the bytes around the state span, their template hash,
/// and the artifact's ABI.
#[derive(Debug)]
pub struct HtlcTemplate {
    abi: SilAbiArtifact,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
}

impl HtlcTemplate {
    /// Parses and checks an artifact against a TEMPLATE_HASH_HASHLOCK file, in this order: the
    /// artifact parses with the supported schema and holds exactly ImpulseHashlock; its state
    /// layout is the one this module maps; its prefix and suffix hash to its declared template
    /// hash and to the pinned hash; it is otherwise self-consistent.
    pub(super) fn load(artifact_json: &str, template_hash_file: &str) -> Result<Self, HtlcError> {
        let invalid = |reason: String| HtlcError::ArtifactInvalid { reason };
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
        check_layout(&contract.runtime_state).map_err(invalid)?;
        let compiled = &contract.compiled;
        let (prefix, _example_state, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| invalid("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(invalid("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        if hash != compiled.template_hash {
            return Err(HtlcError::HashMismatch {
                expected: compiled.template_hash,
                found: hash,
            });
        }
        let pinned = parse_hash(template_hash_file).ok_or_else(|| {
            invalid("TEMPLATE_HASH_HASHLOCK is not 64 lowercase hex digits".into())
        })?;
        if hash != pinned {
            return Err(HtlcError::HashMismatch {
                expected: pinned,
                found: hash,
            });
        }
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

    pub(super) fn abi(&self) -> &SilAbiArtifact {
        &self.abi
    }

    fn runtime_state(&self) -> &RuntimeStateArtifact {
        &self.abi.contracts[CONTRACT_NAME].runtime_state
    }

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

/// `TEMPLATE_HASH_HASHLOCK` file content: 64 lowercase hex digits and an optional final newline.
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

fn check_layout(state: &RuntimeStateArtifact) -> Result<(), String> {
    let found: Vec<(&str, &TypeArtifact)> = state
        .fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty))
        .collect();
    let same = found.len() == LAYOUT.len()
        && found
            .iter()
            .zip(LAYOUT.iter())
            .all(|((name, ty), (en, ek))| name == en && **ty == ek.artifact());
    if same {
        Ok(())
    } else {
        Err(format!(
            "state layout {found:?} is not the ImpulseHashlock v1 layout this crate maps"
        ))
    }
}

/// A hashlock trade's vault: the redeem script instantiated from structure-checked terms, and its
/// P2SH. It serves an existing trade and has no funding address; see [`FundableHtlcVault`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcVault {
    network: Network,
    redeem_script: Vec<u8>,
}

impl HtlcVault {
    /// The vault of an existing trade (claim, refund, verify after a spend). No creation checks
    /// run, so a trade past its expiry still yields its vault.
    pub fn instantiate_existing(terms: &ValidatedHtlcTerms) -> Result<Self, HtlcError> {
        instantiate_with(&TEMPLATE, &terms.terms().state())
    }

    /// The vault of a trade being created or accepted, before anyone funds it: runs the
    /// creation checks (section 10.2, "Creation"), then
    /// [`HtlcVault::instantiate_existing`]. The only vault value a funding address is shown for.
    pub fn instantiate_for_creation(
        terms: &ValidatedHtlcTerms,
        ctx: &HtlcCreationContext<'_>,
    ) -> Result<FundableHtlcVault, HtlcError> {
        refuse_mainnet(terms)?;
        terms.validate_creation(ctx)?;
        Ok(FundableHtlcVault(Self::instantiate_existing(terms)?))
    }

    /// The network the terms name; the address prefix follows it.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The redeem script a spend of this vault reveals.
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// The vault's P2SH scriptPubKey.
    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem_script)
    }

    /// blake2b-256 of the redeem script: the KCC-20 SCRIPT_HASH owner of the escrowed token.
    pub fn script_hash(&self) -> [u8; 32] {
        let spk = self.script_public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&spk.script()[2..34]);
        out
    }
}

/// The mainnet gate of spec/V2.md section 10.5, lifted by the owner's answers: D39 (b), hashlock
/// runs on mainnet with capped values and race R2 disclosed (the owner, 2026-10-11, confirmed
/// in chat 2026-10-15); D40, no further gate on the counterpart program. The per-trade value cap is
/// enforced where the value is declared (the CLI value cap, `CLI_VALUE_CAP_EXCEEDED`).
/// `HTLC_MAINNET_GATED` stays reserved and is no longer returned.
pub(crate) fn refuse_mainnet(_terms: &ValidatedHtlcTerms) -> Result<(), HtlcError> {
    Ok(())
}

/// A hashlock vault whose terms passed the creation checks, the margin rule included. Only this
/// type has a funding address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundableHtlcVault(HtlcVault);

impl FundableHtlcVault {
    /// A funding vault that skips the creation checks. Tests only: the golden vectors render
    /// addresses without a creation context.
    #[cfg(test)]
    pub(crate) fn ungated_for_tests(vault: HtlcVault) -> Self {
        Self(vault)
    }

    pub fn vault(&self) -> &HtlcVault {
        &self.0
    }

    pub fn into_vault(self) -> HtlcVault {
        self.0
    }

    /// The address the seller funds: version ScriptHash, payload the script hash, the prefix of
    /// the terms' network.
    pub fn address(&self) -> String {
        Address::new(
            prefix(self.0.network),
            Version::ScriptHash,
            &self.0.script_hash(),
        )
        .to_string()
    }
}

/// Decodes a revealed redeem script back to the hashlock state. Accepts only a script that
/// instantiation produces from the decoded state, byte for byte. In order, first failure
/// returned: the template (`HTLC_NOT_HASHLOCK_VAULT`), the state's form
/// (`HTLC_STATE_MALFORMED`), each field's value in state order (`HTLC_STATE_INVALID`), the
/// structure checks that do not need the counterpart record (`HTLC_*` and `TERMS_*`), and the
/// byte-for-byte comparison (`HTLC_NONCANONICAL`).
pub fn decode(redeem_script: &[u8]) -> Result<HtlcState, HtlcError> {
    decode_with(&TEMPLATE, redeem_script)
}

/// The template hash recomputed from a script's own first prefix-length and last suffix-length
/// bytes, without trusting any declared hash (`HTLC_NOT_HASHLOCK_VAULT` for a script shorter than
/// the template).
pub fn template_hash_of_instance(script: &[u8]) -> Result<[u8; 32], HtlcError> {
    let template = check()?;
    let (p, s) = (template.prefix.len(), template.suffix.len());
    if script.len() < p + s {
        return Err(HtlcError::NotHashlockVault);
    }
    Ok(template_hash(&script[..p], &script[script.len() - s..]))
}

pub(super) fn instantiate_with(
    template: &Checked,
    state: &HtlcState,
) -> Result<HtlcVault, HtlcError> {
    let template = usable(template)?;
    let values = values(state)?;
    let encoded = encode_runtime_state_script(&template.abi, template.runtime_state(), &values)
        .map_err(|e| HtlcError::StateMalformed {
            reason: e.to_string(),
        })?;
    let mut redeem_script =
        Vec::with_capacity(template.prefix.len() + encoded.len() + template.suffix.len());
    redeem_script.extend_from_slice(&template.prefix);
    redeem_script.extend_from_slice(&encoded);
    redeem_script.extend_from_slice(&template.suffix);
    Ok(HtlcVault {
        network: state.network,
        redeem_script,
    })
}

pub(super) fn decode_with(
    template: &Checked,
    redeem_script: &[u8],
) -> Result<HtlcState, HtlcError> {
    let loaded = usable(template)?;
    let span = loaded
        .state_span(redeem_script)
        .ok_or(HtlcError::NotHashlockVault)?;
    let values =
        decode_runtime_state_script(&loaded.abi, loaded.runtime_state(), span).map_err(|e| {
            HtlcError::StateMalformed {
                reason: e.to_string(),
            }
        })?;
    let state = state_of(&values)?;
    validate::state(&state)?;
    let vault = instantiate_with(template, &state)?;
    if vault.redeem_script != redeem_script {
        return Err(HtlcError::NonCanonical);
    }
    Ok(state)
}

/// The state values in contract order. `state` passed the structure checks, so the refusals here
/// only guard against a caller bypassing them.
fn values(s: &HtlcState) -> Result<BTreeMap<String, ArtifactValue>, HtlcError> {
    use ArtifactValue::{Byte, Bytes, Int};
    let LegKind::Kcc20(token) = s.asset_leg.kind else {
        return Err(HtlcError::AssetKind);
    };
    let v: Vec<(&str, ArtifactValue)> = vec![
        ("version", Byte(s.version)),
        ("network", Byte(network_byte(s.network))),
        ("nonce", Bytes(s.nonce.to_le_bytes().to_vec())),
        ("sellerKey", Bytes(s.seller_key.to_vec())),
        ("buyerKey", Bytes(s.buyer_key.to_vec())),
        ("assetCovenantId", Bytes(token.covenant_id.to_vec())),
        ("assetTemplateHash", Bytes(token.template_hash.to_vec())),
        ("assetPrefixLen", Int(token.template_prefix_len.into())),
        ("assetSuffixLen", Int(token.template_suffix_len.into())),
        ("amount", Int(int(s.asset_leg.amount, "amount")?)),
        (
            "buyerDeliveryType",
            Byte(id_type_byte(s.buyer_delivery.identifier_type)),
        ),
        (
            "buyerDeliveryId",
            Bytes(s.buyer_delivery.identifier.to_vec()),
        ),
        (
            "sellerRefundType",
            Byte(id_type_byte(s.seller_refund.identifier_type)),
        ),
        ("sellerRefundId", Bytes(s.seller_refund.identifier.to_vec())),
        ("hashLock", Bytes(s.hash_lock.to_vec())),
        ("expiryDaa", Int(int(s.expiry_daa, "expiryDaa")?)),
        ("counterpartHash", Bytes(s.counterpart_hash.to_vec())),
        ("tradeRef", Bytes(s.trade_ref.to_vec())),
    ];
    Ok(v.into_iter().map(|(k, x)| (k.to_string(), x)).collect())
}

/// Script integers are signed 64-bit.
fn int(value: u64, field: &'static str) -> Result<i64, HtlcError> {
    i64::try_from(value).map_err(|_| HtlcError::StateInvalid { field })
}

/// Reads the state back, field by field in state order, refusing the first value no hashlock
/// terms value holds.
fn state_of(v: &BTreeMap<String, ArtifactValue>) -> Result<HtlcState, HtlcError> {
    let r = Reader(v);
    let version = r.byte("version")?;
    let network =
        network_of(r.byte("network")?).ok_or(HtlcError::StateInvalid { field: "network" })?;
    let nonce = u64::from_le_bytes(r.fixed::<8>("nonce")?);
    let seller_key = r.fixed::<32>("sellerKey")?;
    let buyer_key = r.fixed::<32>("buyerKey")?;
    let token = Kcc20Token {
        covenant_id: r.fixed::<32>("assetCovenantId")?,
        template_hash: r.fixed::<32>("assetTemplateHash")?,
        template_prefix_len: r.length("assetPrefixLen")?,
        template_suffix_len: r.length("assetSuffixLen")?,
    };
    let amount = r.unsigned("amount")?;
    let buyer_delivery = r.owner("buyerDeliveryType", "buyerDeliveryId")?;
    let seller_refund = r.owner("sellerRefundType", "sellerRefundId")?;
    let hash_lock = r.fixed::<32>("hashLock")?;
    let expiry_daa = r.unsigned("expiryDaa")?;
    let counterpart_hash = r.fixed::<32>("counterpartHash")?;
    let trade_ref = r.fixed::<32>("tradeRef")?;
    Ok(HtlcState {
        version,
        network,
        nonce,
        seller_key,
        buyer_key,
        asset_leg: Leg {
            kind: LegKind::Kcc20(token),
            amount,
        },
        buyer_delivery,
        seller_refund,
        hash_lock,
        expiry_daa,
        counterpart_hash,
        trade_ref,
    })
}

struct Reader<'a>(&'a BTreeMap<String, ArtifactValue>);

impl Reader<'_> {
    fn get(&self, field: &'static str) -> Result<&ArtifactValue, HtlcError> {
        self.0.get(field).ok_or_else(|| HtlcError::StateMalformed {
            reason: format!("missing field {field}"),
        })
    }

    fn shape(field: &'static str) -> HtlcError {
        HtlcError::StateMalformed {
            reason: format!("field {field} has the wrong type"),
        }
    }

    fn byte(&self, field: &'static str) -> Result<u8, HtlcError> {
        match self.get(field)? {
            ArtifactValue::Byte(b) => Ok(*b),
            _ => Err(Self::shape(field)),
        }
    }

    fn int(&self, field: &'static str) -> Result<i64, HtlcError> {
        match self.get(field)? {
            ArtifactValue::Int(i) => Ok(*i),
            _ => Err(Self::shape(field)),
        }
    }

    /// An amount or DAA score: a script integer at or above zero.
    fn unsigned(&self, field: &'static str) -> Result<u64, HtlcError> {
        u64::try_from(self.int(field)?).map_err(|_| HtlcError::StateInvalid { field })
    }

    /// A template length: a script integer that fits the terms' u32.
    fn length(&self, field: &'static str) -> Result<u32, HtlcError> {
        u32::try_from(self.int(field)?).map_err(|_| HtlcError::StateInvalid { field })
    }

    fn fixed<const N: usize>(&self, field: &'static str) -> Result<[u8; N], HtlcError> {
        match self.get(field)? {
            ArtifactValue::Bytes(b) => b.as_slice().try_into().map_err(|_| Self::shape(field)),
            _ => Err(Self::shape(field)),
        }
    }

    fn owner(
        &self,
        type_field: &'static str,
        id_field: &'static str,
    ) -> Result<Kcc20Owner, HtlcError> {
        let identifier_type =
            id_type(self.byte(type_field)?).ok_or(HtlcError::StateInvalid { field: type_field })?;
        Ok(Kcc20Owner {
            identifier_type,
            identifier: self.fixed::<32>(id_field)?,
        })
    }
}
