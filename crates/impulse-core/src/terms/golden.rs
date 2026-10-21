// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden terms vectors (tests/vectors/terms/). The definitions below render to the committed
//! files byte for byte; the files are frozen, so a codec change fails `golden_files_match`.
//! scripts/vectors.sh regenerates them through `emit_vectors` and diffs the result.
//!
//! Every key, covenant ID, template hash and script hash is derived from a public label with
//! blake2b, so no private key exists for any of them. Party keys are the first label-derived
//! x-coordinates that lie on secp256k1.

use super::*;
use kaspa_consensus_core::constants::MAX_SOMPI;
use kaspa_txscript::opcodes::codes::{
    OpBlake2b, OpCheckSig, OpCheckSigECDSA, OpData32, OpData33, OpEqual,
};
use std::path::{Path, PathBuf};

/// DAA score the vectors are created at (synthetic). Every vector validates against it.
pub(crate) const CREATION_DAA: u64 = 400_000_000;
const HOUR: u64 = 36_000;
const DAY: u64 = 24 * HOUR;

pub(crate) struct Vector {
    pub name: &'static str,
    pub description: &'static str,
    pub terms: Terms,
}

pub(crate) fn label32(label: &str) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(label.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// First `label/<n>` hash that is a valid x-only public key. Nobody knows its discrete log.
pub(crate) fn xonly(label: &str) -> [u8; 32] {
    (0u32..)
        .map(|n| label32(&format!("{label}/{n}")))
        .find(|x| secp256k1::XOnlyPublicKey::from_slice(x).is_ok())
        .expect("about half of all x-coordinates lie on the curve")
}

fn nonce(label: &str) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&label32(label)[..8]);
    u64::from_le_bytes(b)
}

pub(crate) fn seller() -> [u8; 32] {
    xonly("impulse/vectors/key/seller")
}

pub(crate) fn buyer() -> [u8; 32] {
    xonly("impulse/vectors/key/buyer")
}

pub(crate) fn authority() -> [u8; 32] {
    xonly("impulse/vectors/key/authority")
}

pub(crate) fn p2pk(key: &[u8; 32]) -> Destination {
    let mut s = vec![OpData32];
    s.extend_from_slice(key);
    s.push(OpCheckSig);
    Destination::Kas(ScriptPublicKey::from_vec(0, s))
}

pub(crate) fn p2pk_ecdsa(key: &[u8; 32]) -> Destination {
    let mut s = vec![OpData33, 0x02];
    s.extend_from_slice(key);
    s.push(OpCheckSigECDSA);
    Destination::Kas(ScriptPublicKey::from_vec(0, s))
}

pub(crate) fn p2sh(script_hash: &[u8; 32]) -> Destination {
    let mut s = vec![OpBlake2b, OpData32];
    s.extend_from_slice(script_hash);
    s.push(OpEqual);
    Destination::Kas(ScriptPublicKey::from_vec(0, s))
}

pub(crate) fn owner(identifier_type: IdentifierType, identifier: [u8; 32]) -> Destination {
    Destination::Kcc20(Kcc20Owner {
        identifier_type,
        identifier,
    })
}

/// Both synthetic tokens run the same synthetic KCC-20 template, as two real KCC-20 tokens
/// with the same constants would; only the covenant IDs differ.
fn token(name: &str) -> Kcc20Token {
    Kcc20Token {
        covenant_id: label32(&format!("impulse/vectors/token/{name}/covenant-id")),
        template_hash: label32("impulse/vectors/template/kcc20"),
        template_prefix_len: 40,
        template_suffix_len: 1_420,
    }
}

fn kcc20(name: &str, amount: u64) -> Leg {
    Leg {
        kind: LegKind::Kcc20(token(name)),
        amount,
    }
}

fn kas(amount: u64) -> Leg {
    Leg {
        kind: LegKind::Kas,
        amount,
    }
}

fn external(amount: u64) -> Leg {
    Leg {
        kind: LegKind::External,
        amount,
    }
}

pub(crate) fn vectors() -> Vec<Vector> {
    use IdentifierType::{CovenantId, PubKey, ScriptHash};
    let (s, b, a) = (seller(), buyer(), authority());
    let custodian = label32("impulse/vectors/script-hash/custodian");
    let multisig = label32("impulse/vectors/script-hash/multisig");
    let buyer_covenant = label32("impulse/vectors/covenant-id/buyer-book");
    let max_expiry = CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    vec![
        Vector {
            name: "01-vault-authority-earmarked-kcc20-kcc20",
            description: "Vault mode with a settlement authority, earmarked funding. KCC-20 asset for KCC-20 cash, every destination a KCC-20 PUBKEY owner, earliest settlement set. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/01/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 1_000),
                cash_leg: kcc20("cash", 99_250_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: owner(PubKey, s),
                seller_refund: owner(PubKey, s),
                buyer_refund: owner(PubKey, b),
                earliest_daa: Some(CREATION_DAA + HOUR),
                expiry_daa: CREATION_DAA + 30 * DAY,
                funding_mode: FundingMode::Earmarked,
                trade_ref: label32("impulse/vectors/01/trade-ref"),
            },
        },
        Vector {
            name: "02-vault-authority-revocable-kcc20-kas",
            description: "Vault mode with a settlement authority, revocable funding. KCC-20 asset delivered to a custodian SCRIPT_HASH owner, KAS cash to a P2PK scriptPubKey. No earliest settlement. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/02/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 500),
                cash_leg: kas(2_500_000_000_000),
                buyer_delivery: owner(ScriptHash, custodian),
                seller_proceeds: p2pk(&s),
                seller_refund: owner(PubKey, s),
                buyer_refund: p2pk(&b),
                earliest_daa: None,
                expiry_daa: CREATION_DAA + 7 * DAY,
                funding_mode: FundingMode::Revocable,
                trade_ref: label32("impulse/vectors/02/trade-ref"),
            },
        },
        Vector {
            name: "03-vault-selfsettling-earmarked-kcc20-kcc20",
            description: "Self-settling vault mode (no authority), earmarked funding. KCC-20 for KCC-20; the asset goes to a COVENANT_ID owner and the cash to a SCRIPT_HASH owner. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/03/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: None,
                asset_leg: kcc20("asset", 250),
                cash_leg: kcc20("cash", 1_000_000),
                buyer_delivery: owner(CovenantId, buyer_covenant),
                seller_proceeds: owner(ScriptHash, custodian),
                seller_refund: owner(PubKey, s),
                buyer_refund: owner(PubKey, b),
                earliest_daa: Some(CREATION_DAA + DAY),
                expiry_daa: CREATION_DAA + 90 * DAY,
                funding_mode: FundingMode::Earmarked,
                trade_ref: label32("impulse/vectors/03/trade-ref"),
            },
        },
        Vector {
            name: "04-vault-selfsettling-revocable-kcc20-kas",
            description: "Self-settling vault mode (no authority), revocable funding. KCC-20 asset for KAS cash paid to a multisig P2SH; the KAS cash refunds to a P2PK-ECDSA scriptPubKey. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/04/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: None,
                asset_leg: kcc20("asset", 5_000),
                cash_leg: kas(10_000_000_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: p2sh(&multisig),
                seller_refund: owner(PubKey, s),
                buyer_refund: p2pk_ecdsa(&b),
                earliest_daa: None,
                expiry_daa: CREATION_DAA + 14 * DAY,
                funding_mode: FundingMode::Revocable,
                trade_ref: label32("impulse/vectors/04/trade-ref"),
            },
        },
        Vector {
            name: "05-vault-external-earmarked-kcc20",
            description: "External-cash vault mode: authority required, earmarked funding. KCC-20 asset; the cash leg settles off chain, so both cash destinations are off_chain. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/05/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 10_000),
                cash_leg: external(100_000_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: Destination::OffChain,
                seller_refund: owner(PubKey, s),
                buyer_refund: Destination::OffChain,
                earliest_daa: Some(CREATION_DAA + HOUR),
                expiry_daa: CREATION_DAA + 30 * DAY,
                funding_mode: FundingMode::Earmarked,
                trade_ref: label32("impulse/vectors/05/trade-ref"),
            },
        },
        Vector {
            name: "06-vault-external-revocable-kcc20",
            description: "External-cash vault mode: authority required, revocable funding. KCC-20 asset delivered to a custodian SCRIPT_HASH owner; cash off chain. No earliest settlement. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/06/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 20),
                cash_leg: external(2_000_000),
                buyer_delivery: owner(ScriptHash, custodian),
                seller_proceeds: Destination::OffChain,
                seller_refund: owner(PubKey, s),
                buyer_refund: Destination::OffChain,
                earliest_daa: None,
                expiry_daa: CREATION_DAA + 2 * DAY,
                funding_mode: FundingMode::Revocable,
                trade_ref: label32("impulse/vectors/06/trade-ref"),
            },
        },
        Vector {
            name: "07-direct-kcc20-kcc20",
            description: "Direct mode (no escrow, no authority), revocable as Direct requires. KCC-20 for KCC-20. A Direct transaction reads the legs, buyer_delivery and seller_proceeds; the refund targets are committed but unused. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Direct,
                nonce: nonce("impulse/vectors/07/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: None,
                asset_leg: kcc20("asset", 75),
                cash_leg: kcc20("cash", 7_500_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: owner(PubKey, s),
                seller_refund: owner(PubKey, s),
                buyer_refund: owner(PubKey, b),
                earliest_daa: None,
                expiry_daa: CREATION_DAA + DAY,
                funding_mode: FundingMode::Revocable,
                trade_ref: label32("impulse/vectors/07/trade-ref"),
            },
        },
        Vector {
            name: "08-testnet-vault-authority-earmarked-kcc20-kas",
            description: "Testnet. Vault mode with a settlement authority, earmarked funding. KCC-20 asset refunding to a SCRIPT_HASH owner, KAS cash delivered to a P2SH and refunded to a P2PK-ECDSA scriptPubKey.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Testnet,
                settlement_mode: SettlementMode::Vault,
                nonce: nonce("impulse/vectors/08/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 1),
                cash_leg: kas(100_000_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: p2sh(&custodian),
                seller_refund: owner(ScriptHash, custodian),
                buyer_refund: p2pk_ecdsa(&b),
                earliest_daa: Some(CREATION_DAA + HOUR),
                expiry_daa: CREATION_DAA + 30 * DAY,
                funding_mode: FundingMode::Earmarked,
                trade_ref: label32("impulse/vectors/08/trade-ref"),
            },
        },
        Vector {
            name: "09-vault-authority-earmarked-upper-bounds",
            description: "Upper bounds: KCC-20 asset at i64::MAX, KAS cash at MAX_SOMPI, nonce u64::MAX, expiry at the default one-year horizon, earliest equal to expiry, trade_ref all 0xff. Authority, earmarked. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: u64::MAX,
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", i64::MAX as u64),
                cash_leg: kas(MAX_SOMPI),
                buyer_delivery: owner(CovenantId, buyer_covenant),
                seller_proceeds: p2pk(&s),
                seller_refund: owner(ScriptHash, custodian),
                buyer_refund: p2pk(&b),
                earliest_daa: Some(max_expiry),
                expiry_daa: max_expiry,
                funding_mode: FundingMode::Earmarked,
                trade_ref: [0xff; 32],
            },
        },
        Vector {
            name: "10-vault-selfsettling-earmarked-lower-bounds",
            description: "Lower bounds: both amounts 1, nonce 0, earliest_daa 1 (the least present value), expiry one DAA after creation, trade_ref all zero. Self-settling, earmarked, KCC-20 for KCC-20. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Vault,
                nonce: 0,
                seller_key: s,
                buyer_key: b,
                authority_key: None,
                asset_leg: kcc20("asset", 1),
                cash_leg: kcc20("cash", 1),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: owner(PubKey, s),
                seller_refund: owner(PubKey, s),
                buyer_refund: owner(PubKey, b),
                earliest_daa: Some(1),
                expiry_daa: CREATION_DAA + 1,
                funding_mode: FundingMode::Earmarked,
                trade_ref: [0; 32],
            },
        },
        Vector {
            name: "11-direct-kcc20-kas-authority-routed",
            description: "Direct mode with an authority named for routing only (it has no on-chain role in Direct). KCC-20 asset for KAS cash paid to a P2PK scriptPubKey, earliest_daa set. Revocable. Mainnet.",
            terms: Terms {
                version: TERMS_VERSION,
                network: Network::Mainnet,
                settlement_mode: SettlementMode::Direct,
                nonce: nonce("impulse/vectors/11/nonce"),
                seller_key: s,
                buyer_key: b,
                authority_key: Some(a),
                asset_leg: kcc20("asset", 2_500),
                cash_leg: kas(25_000_000_000),
                buyer_delivery: owner(PubKey, b),
                seller_proceeds: p2pk(&s),
                seller_refund: owner(PubKey, s),
                buyer_refund: p2pk(&b),
                earliest_daa: Some(CREATION_DAA + HOUR),
                expiry_daa: CREATION_DAA + DAY,
                funding_mode: FundingMode::Revocable,
                trade_ref: label32("impulse/vectors/11/trade-ref"),
            },
        },
    ]
}

// Rendering: a fixed field order and layout, written by hand so no serializer setting can
// change the frozen bytes.

pub(crate) enum Json {
    Str(String),
    Num(u64),
    Null,
    Obj(Vec<(&'static str, Json)>),
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn dec(n: u64) -> Json {
    // u64 as a decimal string: JSON numbers above 2^53 lose precision in JavaScript.
    Json::Str(n.to_string())
}

fn leg_json(leg: &Leg) -> Json {
    let mut fields = Vec::new();
    match &leg.kind {
        LegKind::Kas => fields.push(("kind", Json::Str("kas".into()))),
        LegKind::Kcc20(t) => {
            fields.push(("kind", Json::Str("kcc20".into())));
            fields.push(("covenant_id", Json::Str(hex(&t.covenant_id))));
            fields.push(("template_hash", Json::Str(hex(&t.template_hash))));
            fields.push((
                "template_prefix_len",
                Json::Num(t.template_prefix_len.into()),
            ));
            fields.push((
                "template_suffix_len",
                Json::Num(t.template_suffix_len.into()),
            ));
        }
        LegKind::External => fields.push(("kind", Json::Str("external".into()))),
    }
    fields.push(("amount", dec(leg.amount)));
    Json::Obj(fields)
}

fn destination_json(d: &Destination) -> Json {
    match d {
        Destination::Kas(spk) => Json::Obj(vec![
            ("kind", Json::Str("kas".into())),
            ("version", Json::Num(spk.version().into())),
            ("script", Json::Str(hex(spk.script()))),
        ]),
        Destination::Kcc20(o) => Json::Obj(vec![
            ("kind", Json::Str("kcc20".into())),
            (
                "identifier_type",
                Json::Str(
                    match o.identifier_type {
                        IdentifierType::PubKey => "pubkey",
                        IdentifierType::ScriptHash => "script_hash",
                        IdentifierType::CovenantId => "covenant_id",
                    }
                    .into(),
                ),
            ),
            ("identifier", Json::Str(hex(&o.identifier))),
        ]),
        Destination::OffChain => Json::Obj(vec![("kind", Json::Str("off_chain".into()))]),
    }
}

fn terms_json(t: &Terms) -> Json {
    Json::Obj(vec![
        ("version", Json::Num(t.version.into())),
        (
            "network",
            Json::Str(
                match t.network {
                    Network::Mainnet => "mainnet",
                    Network::Testnet => "testnet",
                }
                .into(),
            ),
        ),
        (
            "settlement_mode",
            Json::Str(
                match t.settlement_mode {
                    SettlementMode::Direct => "direct",
                    SettlementMode::Vault => "vault",
                }
                .into(),
            ),
        ),
        ("nonce", dec(t.nonce)),
        ("seller_key", Json::Str(hex(&t.seller_key))),
        ("buyer_key", Json::Str(hex(&t.buyer_key))),
        (
            "authority_key",
            t.authority_key.map_or(Json::Null, |k| Json::Str(hex(&k))),
        ),
        ("asset_leg", leg_json(&t.asset_leg)),
        ("cash_leg", leg_json(&t.cash_leg)),
        ("buyer_delivery", destination_json(&t.buyer_delivery)),
        ("seller_proceeds", destination_json(&t.seller_proceeds)),
        ("seller_refund", destination_json(&t.seller_refund)),
        ("buyer_refund", destination_json(&t.buyer_refund)),
        ("earliest_daa", t.earliest_daa.map_or(Json::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            Json::Str(
                match t.funding_mode {
                    FundingMode::Revocable => "revocable",
                    FundingMode::Earmarked => "earmarked",
                }
                .into(),
            ),
        ),
        ("trade_ref", Json::Str(hex(&t.trade_ref))),
    ])
}

pub(crate) fn write_json(j: &Json, indent: usize, out: &mut String) {
    match j {
        Json::Str(s) => {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\'),
                "vector strings need no escaping: {s}"
            );
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        Json::Num(n) => out.push_str(&n.to_string()),
        Json::Null => out.push_str("null"),
        Json::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push('"');
                out.push_str(key);
                out.push_str("\": ");
                write_json(value, indent + 2, out);
                if i + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

/// The exact file content for one vector.
pub(crate) fn render(v: &Vector) -> String {
    let canonical = v.terms.encode().expect("vector encodes");
    let hash = v.terms.terms_hash().expect("vector hashes");
    let doc = Json::Obj(vec![
        ("name", Json::Str(v.name.into())),
        ("description", Json::Str(v.description.into())),
        ("terms", terms_json(&v.terms)),
        ("canonical", Json::Str(hex(&canonical))),
        ("terms_hash", Json::Str(hex(&hash))),
    ]);
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms")
}

fn file_name(v: &Vector) -> String {
    format!("{}.json", v.name)
}

#[test]
fn golden_files_match() {
    let dir = committed_dir();
    let mut expected: Vec<String> = vectors().iter().map(file_name).collect();
    expected.sort();
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        // Hidden files (.DS_Store) are ignored by git; scripts/vectors.sh catches any other stray.
        .filter(|name| !name.starts_with('.'))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "tests/vectors/terms holds exactly the golden set"
    );
    for v in vectors() {
        let path = dir.join(file_name(&v));
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == render(&v),
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

#[test]
fn golden_files_decode_and_hash() {
    let defined = vectors();
    for v in &defined {
        let path = committed_dir().join(file_name(v));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let canonical = unhex(doc["canonical"].as_str().expect("canonical"));
        let decoded = Terms::decode(&canonical).expect("committed bytes decode");
        assert_eq!(decoded, v.terms, "{}", v.name);
        assert_eq!(decoded.encode().unwrap(), canonical, "{}", v.name);
        assert_eq!(
            hex(&decoded.terms_hash().unwrap()),
            doc["terms_hash"].as_str().expect("terms_hash"),
            "{}",
            v.name
        );
        assert_eq!(doc["name"].as_str(), Some(v.name));
    }
}

#[test]
fn golden_terms_validate() {
    for v in vectors() {
        let ctx = CreationContext::new(v.terms.network, CREATION_DAA);
        let checked = v.terms.clone().validate_structure().expect(v.name);
        assert_eq!(checked.validate_creation(&ctx), Ok(()), "{}", v.name);
        assert_eq!(checked.canonical(), v.terms.encode().unwrap().as_slice());
        assert_eq!(checked.terms_hash(), v.terms.terms_hash().unwrap());
    }
}

#[test]
fn golden_hashes_distinct() {
    let mut hashes: Vec<[u8; 32]> = vectors()
        .iter()
        .map(|v| v.terms.terms_hash().unwrap())
        .collect();
    hashes.sort();
    hashes.dedup();
    assert_eq!(hashes.len(), vectors().len());
}

/// The vectors cover every mode and both leg kinds; this pins that the set covers them, and
/// every encoding branch besides.
#[test]
fn golden_set_covers_every_mode_and_kind() {
    let vs = vectors();
    let ts: Vec<&Terms> = vs.iter().map(|v| &v.terms).collect();
    let any = |f: &dyn Fn(&Terms) -> bool| ts.iter().any(|t| f(t));
    assert!(vs.len() >= 8);
    // Modes: Direct with each on-chain cash kind, and the three vault sub-modes.
    let vault = |t: &Terms| t.settlement_mode == SettlementMode::Vault;
    let direct = |t: &Terms| t.settlement_mode == SettlementMode::Direct;
    assert!(any(&|t| direct(t) && t.cash_leg.kind == LegKind::Kas));
    assert!(any(
        &|t| direct(t) && matches!(t.cash_leg.kind, LegKind::Kcc20(_))
    ));
    assert!(any(&|t| vault(t)
        && t.authority_key.is_some()
        && t.cash_leg.kind != LegKind::External));
    assert!(any(&|t| vault(t) && t.authority_key.is_none()));
    assert!(any(&|t| vault(t) && t.cash_leg.kind == LegKind::External));
    assert!(any(&|t| t.funding_mode == FundingMode::Revocable));
    assert!(any(&|t| t.funding_mode == FundingMode::Earmarked));
    // Leg kinds: the v1 asset leg is KCC-20 (D13); the cash leg is KAS, KCC-20 or external.
    assert!(ts
        .iter()
        .all(|t| matches!(t.asset_leg.kind, LegKind::Kcc20(_))));
    assert!(any(&|t| t.cash_leg.kind == LegKind::Kas));
    assert!(any(&|t| matches!(t.cash_leg.kind, LegKind::Kcc20(_))));
    // Optional fields both ways, both networks.
    assert!(any(&|t| t.earliest_daa.is_some()));
    assert!(any(&|t| t.earliest_daa.is_none()));
    assert!(any(&|t| t.network == Network::Mainnet));
    assert!(any(&|t| t.network == Network::Testnet));
    // Every destination form.
    let dests = |t: &Terms| {
        [
            t.buyer_delivery.clone(),
            t.seller_proceeds.clone(),
            t.seller_refund.clone(),
            t.buyer_refund.clone(),
        ]
    };
    let any_dest = |f: &dyn Fn(&Destination) -> bool| ts.iter().any(|t| dests(t).iter().any(f));
    use kaspa_txscript::script_class::ScriptClass;
    for class in [
        ScriptClass::PubKey,
        ScriptClass::PubKeyECDSA,
        ScriptClass::ScriptHash,
    ] {
        assert!(any_dest(
            &|d| matches!(d, Destination::Kas(spk) if ScriptClass::from_script(spk) == class)
        ));
    }
    for id in [
        IdentifierType::PubKey,
        IdentifierType::ScriptHash,
        IdentifierType::CovenantId,
    ] {
        assert!(any_dest(
            &|d| matches!(d, Destination::Kcc20(o) if o.identifier_type == id)
        ));
    }
    assert!(any_dest(&|d| *d == Destination::OffChain));
}

/// Writes the golden set to $IMPULSE_VECTORS_OUT/terms/. Run by scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    let dir = Path::new(&out).join("terms");
    std::fs::create_dir_all(&dir).expect("create output dir");
    for v in vectors() {
        std::fs::write(dir.join(file_name(&v)), render(&v)).expect("write vector");
    }
}
