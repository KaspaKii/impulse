// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault v2 instantiation (spec/V2.md 4.1 and 4.2). The compiled template is embedded
//! and checked against contracts/TEMPLATE_HASH_V2 before first use. A leg's redeem script is the
//! template prefix, the terms v2 and the leg index encoded as the contract state, then the
//! template suffix; its P2SH scriptPubKey is what the leg's depositor funds. Decoding reverses the
//! splice and accepts only scripts that instantiation produces byte for byte. The v1 template,
//! its hash and `crate::template` are untouched.
//!
//! Same split as v1 (`crate::template`): [`VaultV2`] for an existing trade, [`FundableVaultV2`]
//! for a trade whose terms also passed the creation checks, the only one with an address.

use super::terms::{DestinationV2, LegV2, Partial, TermsV2, ValidatedTermsV2, LEG_RECORD};
use super::V2Error;
use crate::address::prefix;
use crate::terms::{
    CreationContext, FundingMode, IdentifierType, Kcc20Token, Leg, LegKind, Network,
};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_runtime_state_script, template_hash, ArtifactValue,
    RuntimeStateArtifact, SilAbiArtifact, TypeArtifact,
};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The compiled ImpulseVault v2, as `scripts/build-template-v2.sh` checks it against the pinned
/// silverc.
pub(crate) const ARTIFACT_JSON: &str =
    include_str!("../../../../contracts/compiled/impulse_vault.v2.json");

/// The template hash every v2 vault runs (contracts/TEMPLATE_HASH_V2).
pub(crate) const TEMPLATE_HASH_FILE: &str = include_str!("../../../../contracts/TEMPLATE_HASH_V2");

/// The contract name in the v2 artifact.
pub const CONTRACT_NAME: &str = "ImpulseVaultV2";

type Checked = Result<TemplateV2, V2Error>;

static TEMPLATE: LazyLock<Checked> =
    LazyLock::new(|| TemplateV2::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE));

/// The v2 startup check: loads the embedded template once and returns it, or the reason it is
/// unusable (`TEMPLATE_V2_ARTIFACT_INVALID`, `TEMPLATE_V2_HASH_MISMATCH`).
pub fn check() -> Result<&'static TemplateV2, V2Error> {
    TEMPLATE.as_ref().map_err(Clone::clone)
}

/// The state layout of contracts/impulse_vault_v2.sil, in order (spec/V2.md 4.2).
const LAYOUT: [(&str, Kind); 15] = [
    ("version", Kind::Byte),
    ("network", Kind::Byte),
    ("nonce", Kind::Fixed(8)),
    ("hasAuthority", Kind::Bool),
    ("authorityKey", Kind::Pubkey),
    ("legCount", Kind::Int),
    ("legs", Kind::Bytes),
    ("hasEarliest", Kind::Bool),
    ("earliestDaa", Kind::Int),
    ("expiryDaa", Kind::Int),
    ("fundingMode", Kind::Byte),
    ("tradeRef", Kind::Fixed(32)),
    ("lotCount", Kind::Int),
    ("minLot", Kind::Int),
    ("legIndex", Kind::Int),
];

#[derive(Clone, Copy)]
enum Kind {
    Byte,
    Bool,
    Int,
    Pubkey,
    Fixed(usize),
    Bytes,
}

impl Kind {
    fn artifact(self) -> TypeArtifact {
        match self {
            Kind::Byte => TypeArtifact::Byte,
            Kind::Bool => TypeArtifact::Bool,
            Kind::Int => TypeArtifact::Int,
            Kind::Pubkey => TypeArtifact::Pubkey,
            Kind::Fixed(len) => TypeArtifact::FixedBytes { len },
            Kind::Bytes => TypeArtifact::Bytes,
        }
    }
}

/// The checked v2 template: the bytes around the state span, their hash, and the artifact.
#[derive(Debug)]
pub struct TemplateV2 {
    abi: SilAbiArtifact,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
}

impl TemplateV2 {
    pub(crate) fn load(artifact_json: &str, template_hash_file: &str) -> Result<Self, V2Error> {
        let invalid = |reason: String| V2Error::TemplateArtifactInvalid { reason };
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
        let found: Vec<(&str, &TypeArtifact)> = contract
            .runtime_state
            .fields
            .iter()
            .map(|f| (f.name.as_str(), &f.ty))
            .collect();
        let same = found.len() == LAYOUT.len()
            && found
                .iter()
                .zip(LAYOUT)
                .all(|((name, ty), (n, k))| *name == n && **ty == k.artifact());
        if !same {
            return Err(invalid(format!(
                "state layout {found:?} is not the ImpulseVault v2 layout this crate maps"
            )));
        }
        let compiled = &contract.compiled;
        let (prefix, _example, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| invalid("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(invalid("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        if hash != compiled.template_hash {
            return Err(V2Error::TemplateHashMismatch {
                expected: compiled.template_hash,
                found: hash,
            });
        }
        let pinned = parse_hash(template_hash_file)
            .ok_or_else(|| invalid("TEMPLATE_HASH_V2 is not 64 lowercase hex digits".into()))?;
        if hash != pinned {
            return Err(V2Error::TemplateHashMismatch {
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

    /// The v2 template hash (silverscript's blake3 over the prefix and suffix).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }

    pub(crate) fn abi(&self) -> &SilAbiArtifact {
        &self.abi
    }

    fn runtime_state(&self) -> &RuntimeStateArtifact {
        &self.abi.contracts[CONTRACT_NAME].runtime_state
    }
}

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

// =============================================================================================
// Vaults
// =============================================================================================

/// One leg's v2 vault: the redeem script instantiated from structure-checked terms, and its P2SH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultV2 {
    network: Network,
    leg: usize,
    redeem_script: Vec<u8>,
}

impl VaultV2 {
    /// The vault of `leg` of an existing trade (settle, refund, verify, decode). No creation
    /// checks run. A leg outside the terms' list is `TEMPLATE_V2_LEG_INDEX`.
    pub fn instantiate_existing(terms: &ValidatedTermsV2, leg: usize) -> Result<Self, V2Error> {
        instantiate(terms.terms(), leg)
    }

    /// The vault of `leg` for a trade being created or accepted: the creation checks first, then
    /// [`VaultV2::instantiate_existing`]. The only vault value an address is shown for.
    pub fn instantiate_for_creation(
        terms: &ValidatedTermsV2,
        leg: usize,
        ctx: &CreationContext,
    ) -> Result<FundableVaultV2, V2Error> {
        terms.validate_creation(ctx)?;
        Ok(FundableVaultV2(Self::instantiate_existing(terms, leg)?))
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The leg this vault escrows, its position in the terms' leg list.
    pub fn leg(&self) -> usize {
        self.leg
    }

    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }

    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem_script)
    }

    /// blake2b-256 of the redeem script; also the SCRIPT_HASH owner of the leg's escrowed token.
    pub fn script_hash(&self) -> [u8; 32] {
        let spk = self.script_public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&spk.script()[2..34]);
        out
    }
}

/// A v2 vault whose terms passed the creation checks: the only one with a funding address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundableVaultV2(VaultV2);

impl FundableVaultV2 {
    pub fn vault(&self) -> &VaultV2 {
        &self.0
    }

    pub fn into_vault(self) -> VaultV2 {
        self.0
    }
}

/// The address a depositor funds: version ScriptHash, payload the script hash, the prefix of the
/// terms' network (as v1, spec/TEMPLATE.md).
pub fn vault_address(vault: &FundableVaultV2) -> String {
    let v = vault.vault();
    Address::new(prefix(v.network()), Version::ScriptHash, &v.script_hash()).to_string()
}

/// The template hash recomputed from a script's own prefix and suffix bytes at the v2 lengths.
pub fn template_hash_of_instance(script: &[u8]) -> Result<[u8; 32], V2Error> {
    let t = check()?;
    let (p, s) = (t.prefix.len(), t.suffix.len());
    if script.len() < p + s {
        return Err(V2Error::TemplateNotVault);
    }
    Ok(template_hash(&script[..p], &script[script.len() - s..]))
}

/// Decodes a revealed v2 redeem script back to the terms and the leg index. Accepts only a
/// script that [`VaultV2::instantiate_existing`] produces from the decoded terms, byte for byte.
/// Refusals, first failure returned: not the v2 template (`TEMPLATE_V2_NOT_VAULT`), a state that
/// does not parse (`TEMPLATE_V2_STATE_MALFORMED`), a field no terms value holds
/// (`TEMPLATE_V2_STATE_INVALID`), a leg index outside the list (`TEMPLATE_V2_LEG_INDEX`), terms
/// that fail the structure checks (`TERMS_*`), and a script that is not the canonical
/// instantiation (`TEMPLATE_V2_NONCANONICAL`).
pub fn decode(redeem_script: &[u8]) -> Result<(ValidatedTermsV2, usize), V2Error> {
    let t = check()?;
    let (p, s) = (t.prefix.len(), t.suffix.len());
    if redeem_script.len() < p + s
        || !redeem_script.starts_with(&t.prefix)
        || !redeem_script.ends_with(&t.suffix)
    {
        return Err(V2Error::TemplateNotVault);
    }
    let span = &redeem_script[p..redeem_script.len() - s];
    let values = decode_runtime_state_script(&t.abi, t.runtime_state(), span).map_err(|e| {
        V2Error::TemplateStateMalformed {
            reason: e.to_string(),
        }
    })?;
    let (terms, leg) = read_state(&values)?;
    let terms = terms.validate_structure()?;
    let vault = VaultV2::instantiate_existing(&terms, leg)?;
    if vault.redeem_script != redeem_script {
        return Err(V2Error::TemplateNonCanonical);
    }
    Ok((terms, leg))
}

fn instantiate(t: &TermsV2, leg: usize) -> Result<VaultV2, V2Error> {
    let template = check()?;
    if leg >= t.legs.len() {
        return Err(V2Error::TemplateLegIndex {
            value: i64::try_from(leg).unwrap_or(i64::MAX),
            leg_count: t.legs.len(),
        });
    }
    let values = state_values(t, leg)?;
    let state = encode_runtime_state_script(&template.abi, template.runtime_state(), &values)
        .map_err(|e| V2Error::TemplateStateMalformed {
            reason: e.to_string(),
        })?;
    let mut redeem_script =
        Vec::with_capacity(template.prefix.len() + state.len() + template.suffix.len());
    redeem_script.extend_from_slice(&template.prefix);
    redeem_script.extend_from_slice(&state);
    redeem_script.extend_from_slice(&template.suffix);
    Ok(VaultV2 {
        network: t.network,
        leg,
        redeem_script,
    })
}

// =============================================================================================
// Terms to state (spec/V2.md 4.2)
// =============================================================================================

const KIND_KAS: u8 = 0;
const KIND_KCC20: u8 = 1;

fn int(value: u64, field: &'static str) -> Result<i64, V2Error> {
    i64::try_from(value).map_err(|_| V2Error::TemplateStateInvalid { field })
}

fn id_byte(t: IdentifierType) -> u8 {
    match t {
        IdentifierType::PubKey => 0,
        IdentifierType::ScriptHash => 1,
        IdentifierType::CovenantId => 2,
    }
}

/// The 187-byte record of one leg. Integers are 8-byte little-endian, as the template reads
/// them with `int(byte[8](...))`; structure-checked amounts and lengths are below 2^63.
pub(crate) fn leg_record(leg: &LegV2) -> Result<Vec<u8>, V2Error> {
    let zero = Kcc20Token {
        covenant_id: [0; 32],
        template_hash: [0; 32],
        template_prefix_len: 0,
        template_suffix_len: 0,
    };
    let (kind, token) = match &leg.asset.kind {
        LegKind::Kas => (KIND_KAS, zero),
        LegKind::Kcc20(token) => (KIND_KCC20, *token),
        LegKind::External => return Err(V2Error::TemplateStateInvalid { field: "legs" }),
    };
    let mut r = Vec::with_capacity(LEG_RECORD);
    r.extend_from_slice(&leg.depositor_key);
    r.push(kind);
    r.extend_from_slice(&token.covenant_id);
    r.extend_from_slice(&token.template_hash);
    r.extend_from_slice(&u64::from(token.template_prefix_len).to_le_bytes());
    r.extend_from_slice(&u64::from(token.template_suffix_len).to_le_bytes());
    r.extend_from_slice(&int(leg.asset.amount, "legs")?.to_le_bytes());
    for d in [&leg.delivery, &leg.refund] {
        r.push(id_byte(d.identifier_type));
        r.extend_from_slice(&d.identifier);
    }
    debug_assert_eq!(r.len(), LEG_RECORD);
    Ok(r)
}

fn state_values(t: &TermsV2, leg: usize) -> Result<BTreeMap<String, ArtifactValue>, V2Error> {
    use ArtifactValue::{Bool, Byte, Bytes, Int};
    let mut legs = Vec::with_capacity(LEG_RECORD * t.legs.len());
    for l in &t.legs {
        legs.extend_from_slice(&leg_record(l)?);
    }
    let (lot_count, min_lot) = t.partial.map_or((1, 1), |p| (p.lot_count, p.min_lot));
    let v: Vec<(&str, ArtifactValue)> = vec![
        ("version", Byte(t.version)),
        (
            "network",
            Byte(match t.network {
                Network::Mainnet => 0,
                Network::Testnet => 1,
            }),
        ),
        ("nonce", Bytes(t.nonce.to_le_bytes().to_vec())),
        ("hasAuthority", Bool(t.authority_key.is_some())),
        (
            "authorityKey",
            Bytes(t.authority_key.unwrap_or([0; 32]).to_vec()),
        ),
        ("legCount", Int(int(t.legs.len() as u64, "legCount")?)),
        ("legs", Bytes(legs)),
        ("hasEarliest", Bool(t.earliest_daa.is_some())),
        (
            "earliestDaa",
            Int(int(t.earliest_daa.unwrap_or(0), "earliestDaa")?),
        ),
        ("expiryDaa", Int(int(t.expiry_daa, "expiryDaa")?)),
        (
            "fundingMode",
            Byte(match t.funding_mode {
                FundingMode::Revocable => 0,
                FundingMode::Earmarked => 1,
            }),
        ),
        ("tradeRef", Bytes(t.trade_ref.to_vec())),
        ("lotCount", Int(int(lot_count, "lotCount")?)),
        ("minLot", Int(int(min_lot, "minLot")?)),
        ("legIndex", Int(int(leg as u64, "legIndex")?)),
    ];
    Ok(v.into_iter().map(|(k, x)| (k.to_string(), x)).collect())
}

// =============================================================================================
// State to terms
// =============================================================================================

struct Reader<'a>(&'a BTreeMap<String, ArtifactValue>);

impl Reader<'_> {
    fn get(&self, field: &'static str) -> Result<&ArtifactValue, V2Error> {
        self.0
            .get(field)
            .ok_or_else(|| V2Error::TemplateStateMalformed {
                reason: format!("missing field {field}"),
            })
    }

    fn shape(field: &'static str) -> V2Error {
        V2Error::TemplateStateMalformed {
            reason: format!("field {field} has the wrong type"),
        }
    }

    fn byte(&self, field: &'static str) -> Result<u8, V2Error> {
        match self.get(field)? {
            ArtifactValue::Byte(b) => Ok(*b),
            _ => Err(Self::shape(field)),
        }
    }

    fn bool(&self, field: &'static str) -> Result<bool, V2Error> {
        match self.get(field)? {
            ArtifactValue::Bool(b) => Ok(*b),
            _ => Err(Self::shape(field)),
        }
    }

    fn int(&self, field: &'static str) -> Result<i64, V2Error> {
        match self.get(field)? {
            ArtifactValue::Int(i) => Ok(*i),
            _ => Err(Self::shape(field)),
        }
    }

    fn uint(&self, field: &'static str) -> Result<u64, V2Error> {
        u64::try_from(self.int(field)?).map_err(|_| V2Error::TemplateStateInvalid { field })
    }

    fn bytes(&self, field: &'static str) -> Result<&[u8], V2Error> {
        match self.get(field)? {
            ArtifactValue::Bytes(b) => Ok(b),
            _ => Err(Self::shape(field)),
        }
    }

    fn fixed<const N: usize>(&self, field: &'static str) -> Result<[u8; N], V2Error> {
        self.bytes(field)?
            .try_into()
            .map_err(|_| Self::shape(field))
    }
}

fn read_state(v: &BTreeMap<String, ArtifactValue>) -> Result<(TermsV2, usize), V2Error> {
    let r = Reader(v);
    let invalid = |field| V2Error::TemplateStateInvalid { field };
    let version = r.byte("version")?;
    let network = match r.byte("network")? {
        0 => Network::Mainnet,
        1 => Network::Testnet,
        _ => return Err(invalid("network")),
    };
    let nonce = u64::from_le_bytes(r.fixed::<8>("nonce")?);
    let has_authority = r.bool("hasAuthority")?;
    let authority_key = r.fixed::<32>("authorityKey")?;
    let leg_count = r.uint("legCount")?;
    let records = r.bytes("legs")?;
    let leg_count = usize::try_from(leg_count).map_err(|_| invalid("legCount"))?;
    if leg_count
        .checked_mul(LEG_RECORD)
        .is_none_or(|len| len != records.len())
    {
        return Err(invalid("legs"));
    }
    let legs = records
        .chunks(LEG_RECORD)
        .map(read_leg)
        .collect::<Result<Vec<_>, _>>()?;
    let has_earliest = r.bool("hasEarliest")?;
    let earliest_daa = r.uint("earliestDaa")?;
    let expiry_daa = r.uint("expiryDaa")?;
    let funding_mode = match r.byte("fundingMode")? {
        0 => FundingMode::Revocable,
        1 => FundingMode::Earmarked,
        _ => return Err(invalid("fundingMode")),
    };
    let trade_ref = r.fixed::<32>("tradeRef")?;
    let lot_count = r.uint("lotCount")?;
    let min_lot = r.uint("minLot")?;
    let leg_index = r.int("legIndex")?;
    let leg = usize::try_from(leg_index)
        .ok()
        .filter(|i| *i < leg_count)
        .ok_or(V2Error::TemplateLegIndex {
            value: leg_index,
            leg_count,
        })?;
    let partial = (lot_count != 1 || min_lot != 1).then_some(Partial { lot_count, min_lot });
    let terms = TermsV2 {
        version,
        network,
        nonce,
        authority_key: has_authority.then_some(authority_key),
        legs,
        earliest_daa: has_earliest.then_some(earliest_daa),
        expiry_daa,
        funding_mode,
        partial,
        trade_ref,
    };
    Ok((terms, leg))
}

fn read_leg(rec: &[u8]) -> Result<LegV2, V2Error> {
    let invalid = |field| V2Error::TemplateStateInvalid { field };
    let a32 = |at: usize| -> [u8; 32] { rec[at..at + 32].try_into().expect("32 bytes") };
    let int8 = |at: usize, field| -> Result<u64, V2Error> {
        let raw = u64::from_le_bytes(rec[at..at + 8].try_into().expect("8 bytes"));
        // The engine reads the eight bytes as a sign-magnitude number: the top bit is the sign.
        if raw >> 63 == 1 {
            return Err(invalid(field));
        }
        Ok(raw)
    };
    let length = |at: usize| -> Result<u32, V2Error> {
        u32::try_from(int8(at, "legs")?).map_err(|_| invalid("legs"))
    };
    let dest = |at: usize| -> Result<DestinationV2, V2Error> {
        let identifier_type = match rec[at] {
            0 => IdentifierType::PubKey,
            1 => IdentifierType::ScriptHash,
            2 => IdentifierType::CovenantId,
            _ => return Err(invalid("legs")),
        };
        Ok(DestinationV2 {
            identifier_type,
            identifier: a32(at + 1),
        })
    };
    let token = Kcc20Token {
        covenant_id: a32(33),
        template_hash: a32(65),
        template_prefix_len: length(97)?,
        template_suffix_len: length(105)?,
    };
    let kind = match rec[32] {
        KIND_KAS => LegKind::Kas,
        KIND_KCC20 => LegKind::Kcc20(token),
        _ => return Err(invalid("legs")),
    };
    Ok(LegV2 {
        depositor_key: a32(0),
        asset: Leg {
            kind,
            amount: int8(113, "legs")?,
        },
        delivery: dest(121)?,
        refund: dest(154)?,
    })
}

/// Test hook: a redeem script with `values` as its state, spliced between the v2 prefix and suffix.
#[cfg(test)]
pub(super) fn splice(values: &BTreeMap<String, ArtifactValue>) -> Vec<u8> {
    let t = check().expect("template");
    let state = encode_runtime_state_script(&t.abi, t.runtime_state(), values).expect("state");
    [t.prefix.as_slice(), state.as_slice(), t.suffix.as_slice()].concat()
}

/// Test hook: the state values of `leg` under `t`.
#[cfg(test)]
pub(super) fn values_of(t: &TermsV2, leg: usize) -> BTreeMap<String, ArtifactValue> {
    state_values(t, leg).expect("state values")
}
