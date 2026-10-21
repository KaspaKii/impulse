// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms and leg index as the ImpulseVault state (spec/TEMPLATE.md, "State"), and back. The
//! startup check pins the artifact's state layout to `LAYOUT`, so this mapping and the contract
//! cannot drift apart. silverscript-abi encodes each field as one explicit data push.

use super::{LegIndex, TemplateError};
use crate::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, TermsError,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use silverscript_abi::{ArtifactValue, RuntimeStateArtifact, TypeArtifact};
use std::collections::BTreeMap;

/// One state field's type, as silverscript-abi names it.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Byte,
    Bool,
    Int,
    Pubkey,
    Fixed(usize),
    Bytes,
}

impl Kind {
    pub(crate) fn artifact(self) -> TypeArtifact {
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

/// The ImpulseVault v1 state in contract order (contracts/impulse_vault.sil, constructor).
pub(crate) const LAYOUT: [(&str, Kind); 34] = [
    ("version", Kind::Byte),
    ("network", Kind::Byte),
    ("nonce", Kind::Fixed(8)),
    ("sellerKey", Kind::Pubkey),
    ("buyerKey", Kind::Pubkey),
    ("hasAuthority", Kind::Bool),
    ("authorityKey", Kind::Pubkey),
    ("assetCovenantId", Kind::Fixed(32)),
    ("assetTemplateHash", Kind::Fixed(32)),
    ("assetPrefixLen", Kind::Int),
    ("assetSuffixLen", Kind::Int),
    ("amountA", Kind::Int),
    ("cashKind", Kind::Byte),
    ("cashCovenantId", Kind::Fixed(32)),
    ("cashTemplateHash", Kind::Fixed(32)),
    ("cashPrefixLen", Kind::Int),
    ("cashSuffixLen", Kind::Int),
    ("amountB", Kind::Int),
    ("buyerDeliveryType", Kind::Byte),
    ("buyerDeliveryId", Kind::Fixed(32)),
    ("sellerProceedsType", Kind::Byte),
    ("sellerProceedsId", Kind::Fixed(32)),
    ("sellerProceedsSpk", Kind::Bytes),
    ("sellerRefundType", Kind::Byte),
    ("sellerRefundId", Kind::Fixed(32)),
    ("buyerRefundType", Kind::Byte),
    ("buyerRefundId", Kind::Fixed(32)),
    ("buyerRefundSpk", Kind::Bytes),
    ("hasEarliest", Kind::Bool),
    ("earliestDaa", Kind::Int),
    ("expiryDaa", Kind::Int),
    ("fundingMode", Kind::Byte),
    ("tradeRef", Kind::Fixed(32)),
    ("legIndex", Kind::Int),
];

// Byte values the contract compares with (impulse_vault.sil constants and kcc20.sil identifier
// types). They equal the terms encoding's kind bytes (spec/ENCODING.md).
const NETWORK_MAINNET: u8 = 0;
const NETWORK_TESTNET: u8 = 1;
const CASH_KAS: u8 = 0;
const CASH_KCC20: u8 = 1;
const CASH_EXTERNAL: u8 = 2;
const ID_PUBKEY: u8 = 0;
const ID_SCRIPT_HASH: u8 = 1;
const ID_COVENANT_ID: u8 = 2;
const FUNDING_REVOCABLE: u8 = 0;
const FUNDING_EARMARKED: u8 = 1;

/// The artifact's state fields must be `LAYOUT`, name for name and type for type, in order.
pub(super) fn check_layout(state: &RuntimeStateArtifact) -> Result<(), String> {
    let found: Vec<(&str, &TypeArtifact)> = state
        .fields
        .iter()
        .map(|f| (f.name.as_str(), &f.ty))
        .collect();
    let expected: Vec<(&str, TypeArtifact)> =
        LAYOUT.iter().map(|(n, k)| (*n, k.artifact())).collect();
    let same = found.len() == expected.len()
        && found
            .iter()
            .zip(&expected)
            .all(|((fn_, ft), (en, et))| fn_ == en && *ft == et);
    if same {
        Ok(())
    } else {
        Err(format!(
            "state layout {found:?} is not the ImpulseVault v1 layout this crate maps"
        ))
    }
}

// Terms to state.

/// The state values for `leg` under `t`. Values a field does not use are zero or empty, so each
/// terms value has one state. `t` passed the structure checks, so the refusals here only guard
/// against a caller bypassing them.
pub(crate) fn values(
    t: &Terms,
    leg: LegIndex,
) -> Result<BTreeMap<String, ArtifactValue>, TemplateError> {
    use ArtifactValue::{Bool, Byte, Bytes, Int};
    let LegKind::Kcc20(asset) = &t.asset_leg.kind else {
        return Err(TermsError::AssetKindUnsupported.into());
    };
    let zero = Kcc20Token {
        covenant_id: [0; 32],
        template_hash: [0; 32],
        template_prefix_len: 0,
        template_suffix_len: 0,
    };
    let (cash_kind, cash) = match &t.cash_leg.kind {
        LegKind::Kas => (CASH_KAS, zero),
        LegKind::Kcc20(token) => (CASH_KCC20, *token),
        LegKind::External => (CASH_EXTERNAL, zero),
    };
    let buyer_delivery = owner(&t.buyer_delivery, "buyerDeliveryType")?;
    let seller_refund = owner(&t.seller_refund, "sellerRefundType")?;
    let (proceeds_type, proceeds_id, proceeds_spk) = cash_destination(&t.seller_proceeds);
    let (refund_type, refund_id, refund_spk) = cash_destination(&t.buyer_refund);

    let mut v: Vec<(&str, ArtifactValue)> = vec![
        ("version", Byte(t.version)),
        (
            "network",
            Byte(match t.network {
                Network::Mainnet => NETWORK_MAINNET,
                Network::Testnet => NETWORK_TESTNET,
            }),
        ),
        ("nonce", Bytes(t.nonce.to_le_bytes().to_vec())),
        ("sellerKey", Bytes(t.seller_key.to_vec())),
        ("buyerKey", Bytes(t.buyer_key.to_vec())),
        ("hasAuthority", Bool(t.authority_key.is_some())),
        (
            "authorityKey",
            Bytes(t.authority_key.unwrap_or([0; 32]).to_vec()),
        ),
    ];
    v.extend(token_values(asset, "asset")?);
    v.push(("amountA", Int(int(t.asset_leg.amount, "amountA")?)));
    v.push(("cashKind", Byte(cash_kind)));
    v.extend(token_values(&cash, "cash")?);
    v.push(("amountB", Int(int(t.cash_leg.amount, "amountB")?)));
    v.extend([
        ("buyerDeliveryType", Byte(buyer_delivery.0)),
        ("buyerDeliveryId", Bytes(buyer_delivery.1.to_vec())),
        ("sellerProceedsType", Byte(proceeds_type)),
        ("sellerProceedsId", Bytes(proceeds_id.to_vec())),
        ("sellerProceedsSpk", Bytes(proceeds_spk)),
        ("sellerRefundType", Byte(seller_refund.0)),
        ("sellerRefundId", Bytes(seller_refund.1.to_vec())),
        ("buyerRefundType", Byte(refund_type)),
        ("buyerRefundId", Bytes(refund_id.to_vec())),
        ("buyerRefundSpk", Bytes(refund_spk)),
        ("hasEarliest", Bool(t.earliest_daa.is_some())),
        (
            "earliestDaa",
            Int(int(t.earliest_daa.unwrap_or(0), "earliestDaa")?),
        ),
        ("expiryDaa", Int(int(t.expiry_daa, "expiryDaa")?)),
        (
            "fundingMode",
            Byte(match t.funding_mode {
                FundingMode::Revocable => FUNDING_REVOCABLE,
                FundingMode::Earmarked => FUNDING_EARMARKED,
            }),
        ),
        ("tradeRef", Bytes(t.trade_ref.to_vec())),
        ("legIndex", Int(leg.index().into())),
    ]);
    Ok(v.into_iter().map(|(k, x)| (k.to_string(), x)).collect())
}

fn token_values(
    token: &Kcc20Token,
    leg: &'static str,
) -> Result<[(&'static str, ArtifactValue); 4], TemplateError> {
    let (cov, hash, prefix, suffix) = if leg == "asset" {
        (
            "assetCovenantId",
            "assetTemplateHash",
            "assetPrefixLen",
            "assetSuffixLen",
        )
    } else {
        (
            "cashCovenantId",
            "cashTemplateHash",
            "cashPrefixLen",
            "cashSuffixLen",
        )
    };
    Ok([
        (cov, ArtifactValue::Bytes(token.covenant_id.to_vec())),
        (hash, ArtifactValue::Bytes(token.template_hash.to_vec())),
        (
            prefix,
            ArtifactValue::Int(int(token.template_prefix_len.into(), prefix)?),
        ),
        (
            suffix,
            ArtifactValue::Int(int(token.template_suffix_len.into(), suffix)?),
        ),
    ])
}

/// A KCC-20 owner as (identifier type byte, identifier).
fn owner(d: &Destination, field: &'static str) -> Result<(u8, [u8; 32]), TemplateError> {
    match d {
        Destination::Kcc20(o) => Ok((id_type_byte(o.identifier_type), o.identifier)),
        _ => Err(TemplateError::StateInvalid { field }),
    }
}

/// A cash destination as (owner type, owner identifier, scriptPubKey bytes): a KCC-20 owner
/// fills the first two, a KAS scriptPubKey the third, off chain none.
fn cash_destination(d: &Destination) -> (u8, [u8; 32], Vec<u8>) {
    match d {
        Destination::Kcc20(o) => (id_type_byte(o.identifier_type), o.identifier, vec![]),
        Destination::Kas(spk) => (0, [0; 32], spk_bytes(spk)),
        Destination::OffChain => (0, [0; 32], vec![]),
    }
}

/// A scriptPubKey as script introspection returns it: version (u16 big-endian), then the script.
fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut bytes = spk.version().to_be_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    bytes
}

fn id_type_byte(t: IdentifierType) -> u8 {
    match t {
        IdentifierType::PubKey => ID_PUBKEY,
        IdentifierType::ScriptHash => ID_SCRIPT_HASH,
        IdentifierType::CovenantId => ID_COVENANT_ID,
    }
}

/// Script integers are signed 64-bit.
fn int(value: u64, field: &'static str) -> Result<i64, TemplateError> {
    i64::try_from(value).map_err(|_| TemplateError::StateInvalid { field })
}

// State to terms.

/// Reads the state back into terms (always Vault mode: only vault terms have a script) and the
/// leg index, field by field in state order, refusing the first value no terms value can hold.
/// Each cash destination reads only the part its cash kind uses (owner, or scriptPubKey); the
/// caller's byte-for-byte comparison with a fresh instantiation refuses any unused field that
/// is not zero or empty.
pub(crate) fn terms(
    v: &BTreeMap<String, ArtifactValue>,
) -> Result<(Terms, LegIndex), TemplateError> {
    let r = Reader(v);
    let version = r.byte("version")?;
    let network = match r.byte("network")? {
        NETWORK_MAINNET => Network::Mainnet,
        NETWORK_TESTNET => Network::Testnet,
        _ => return Err(TemplateError::StateInvalid { field: "network" }),
    };
    let nonce = u64::from_le_bytes(r.fixed::<8>("nonce")?);
    let seller_key = r.fixed::<32>("sellerKey")?;
    let buyer_key = r.fixed::<32>("buyerKey")?;
    let has_authority = r.bool("hasAuthority")?;
    let authority_key = r.fixed::<32>("authorityKey")?;
    let asset = r.token("asset")?;
    let amount_a = r.amount("amountA")?;
    let cash_kind = r.byte("cashKind")?;
    if !matches!(cash_kind, CASH_KAS | CASH_KCC20 | CASH_EXTERNAL) {
        return Err(TemplateError::StateInvalid { field: "cashKind" });
    }
    let cash_token = r.token("cash")?;
    let amount_b = r.amount("amountB")?;
    let cash_kind = match cash_kind {
        CASH_KAS => LegKind::Kas,
        CASH_KCC20 => LegKind::Kcc20(cash_token),
        _ => LegKind::External,
    };
    let buyer_delivery = r.owner("buyerDeliveryType", "buyerDeliveryId")?;
    let seller_proceeds = r.cash_destination(
        &cash_kind,
        "sellerProceedsType",
        "sellerProceedsId",
        "sellerProceedsSpk",
    )?;
    let seller_refund = r.owner("sellerRefundType", "sellerRefundId")?;
    let buyer_refund = r.cash_destination(
        &cash_kind,
        "buyerRefundType",
        "buyerRefundId",
        "buyerRefundSpk",
    )?;
    let has_earliest = r.bool("hasEarliest")?;
    let earliest_daa = r.amount("earliestDaa")?;
    let expiry_daa = r.amount("expiryDaa")?;
    let funding_mode = match r.byte("fundingMode")? {
        FUNDING_REVOCABLE => FundingMode::Revocable,
        FUNDING_EARMARKED => FundingMode::Earmarked,
        _ => {
            return Err(TemplateError::StateInvalid {
                field: "fundingMode",
            })
        }
    };
    let trade_ref = r.fixed::<32>("tradeRef")?;
    let leg = LegIndex::from_index(r.int("legIndex")?)?;
    let terms = Terms {
        version,
        network,
        settlement_mode: SettlementMode::Vault,
        nonce,
        seller_key,
        buyer_key,
        authority_key: has_authority.then_some(authority_key),
        asset_leg: Leg {
            kind: LegKind::Kcc20(asset),
            amount: amount_a,
        },
        cash_leg: Leg {
            kind: cash_kind,
            amount: amount_b,
        },
        buyer_delivery,
        seller_proceeds,
        seller_refund,
        buyer_refund,
        earliest_daa: has_earliest.then_some(earliest_daa),
        expiry_daa,
        funding_mode,
        trade_ref,
    };
    Ok((terms, leg))
}

struct Reader<'a>(&'a BTreeMap<String, ArtifactValue>);

impl Reader<'_> {
    fn get(&self, field: &'static str) -> Result<&ArtifactValue, TemplateError> {
        self.0
            .get(field)
            .ok_or_else(|| TemplateError::StateMalformed {
                reason: format!("missing field {field}"),
            })
    }

    fn shape(field: &'static str) -> TemplateError {
        TemplateError::StateMalformed {
            reason: format!("field {field} has the wrong type"),
        }
    }

    fn byte(&self, field: &'static str) -> Result<u8, TemplateError> {
        match self.get(field)? {
            ArtifactValue::Byte(b) => Ok(*b),
            _ => Err(Self::shape(field)),
        }
    }

    fn bool(&self, field: &'static str) -> Result<bool, TemplateError> {
        match self.get(field)? {
            ArtifactValue::Bool(b) => Ok(*b),
            _ => Err(Self::shape(field)),
        }
    }

    fn int(&self, field: &'static str) -> Result<i64, TemplateError> {
        match self.get(field)? {
            ArtifactValue::Int(i) => Ok(*i),
            _ => Err(Self::shape(field)),
        }
    }

    /// An amount, DAA score or the like: a script integer at or above zero.
    fn amount(&self, field: &'static str) -> Result<u64, TemplateError> {
        u64::try_from(self.int(field)?).map_err(|_| TemplateError::StateInvalid { field })
    }

    /// A template length: a script integer that fits the terms' u32.
    fn length(&self, field: &'static str) -> Result<u32, TemplateError> {
        u32::try_from(self.int(field)?).map_err(|_| TemplateError::StateInvalid { field })
    }

    fn bytes(&self, field: &'static str) -> Result<&[u8], TemplateError> {
        match self.get(field)? {
            ArtifactValue::Bytes(b) => Ok(b),
            _ => Err(Self::shape(field)),
        }
    }

    fn fixed<const N: usize>(&self, field: &'static str) -> Result<[u8; N], TemplateError> {
        self.bytes(field)?
            .try_into()
            .map_err(|_| Self::shape(field))
    }

    fn token(&self, leg: &'static str) -> Result<Kcc20Token, TemplateError> {
        let names = if leg == "asset" {
            [
                "assetCovenantId",
                "assetTemplateHash",
                "assetPrefixLen",
                "assetSuffixLen",
            ]
        } else {
            [
                "cashCovenantId",
                "cashTemplateHash",
                "cashPrefixLen",
                "cashSuffixLen",
            ]
        };
        Ok(Kcc20Token {
            covenant_id: self.fixed::<32>(names[0])?,
            template_hash: self.fixed::<32>(names[1])?,
            template_prefix_len: self.length(names[2])?,
            template_suffix_len: self.length(names[3])?,
        })
    }

    fn owner(
        &self,
        type_field: &'static str,
        id_field: &'static str,
    ) -> Result<Destination, TemplateError> {
        let identifier_type = match self.byte(type_field)? {
            ID_PUBKEY => IdentifierType::PubKey,
            ID_SCRIPT_HASH => IdentifierType::ScriptHash,
            ID_COVENANT_ID => IdentifierType::CovenantId,
            _ => return Err(TemplateError::StateInvalid { field: type_field }),
        };
        Ok(Destination::Kcc20(Kcc20Owner {
            identifier_type,
            identifier: self.fixed::<32>(id_field)?,
        }))
    }

    fn cash_destination(
        &self,
        kind: &LegKind,
        type_field: &'static str,
        id_field: &'static str,
        spk_field: &'static str,
    ) -> Result<Destination, TemplateError> {
        match kind {
            LegKind::Kcc20(_) => self.owner(type_field, id_field),
            LegKind::Kas => {
                let bytes = self.bytes(spk_field)?;
                if bytes.len() < 2 {
                    return Err(TemplateError::StateInvalid { field: spk_field });
                }
                let version = u16::from_be_bytes([bytes[0], bytes[1]]);
                Ok(Destination::Kas(ScriptPublicKey::from_vec(
                    version,
                    bytes[2..].to_vec(),
                )))
            }
            LegKind::External => Ok(Destination::OffChain),
        }
    }
}
