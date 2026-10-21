// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden linked-sheet vectors (spec/V2.md 17.11): one file per sheet under
//! tests/vectors/linked/, with the sheet, its canonical bytes and hash, and the two derived
//! trades with their canonical bytes and terms hashes. The definitions render to the committed
//! files byte for byte; the files are frozen once on main, so a codec or derivation change fails
//! `golden_files_match`. scripts/vectors.sh regenerates them through `emit_vectors`, diffs them,
//! and re-derives and re-hashes them in Python from spec/V2.md section 17 alone.
//!
//! Every key is label-derived (nobody holds its private key), as the v2 vectors.

use super::*;
use crate::terms::golden::label32;
use crate::terms::{FundingMode, IdentifierType, LegKind, Network};
use crate::tx::ipst::{hex, write_json, J};
use crate::v2::testkit::*;
use crate::v2::{DestinationV2, LegV2, TermsV2};
use std::path::{Path, PathBuf};

const NS: &str = "vectors";
/// Return bounds the vectors use: after the testkit's expiry of 2,000,000.
const RETURN_EARLIEST: u64 = 2_500_000;
const RETURN_EXPIRY: u64 = 3_500_000;

pub(crate) struct SheetVector {
    pub name: &'static str,
    pub description: &'static str,
    pub sheet: LinkedSheet,
}

fn sheet_of(
    mut opening: TermsV2,
    return_amounts: [u64; 2],
    earliest: u64,
    expiry: u64,
) -> LinkedSheet {
    opening.trade_ref = [0u8; 32];
    LinkedSheet {
        version: LINKED_VERSION,
        opening,
        return_amounts,
        return_earliest_daa: earliest,
        return_expiry_daa: expiry,
    }
}

pub(crate) fn sheet_vectors() -> Vec<SheetVector> {
    let mut repo = two_kas(NS, true);
    repo.nonce = 0x4C49_4E4B;
    let loan = {
        let mut t = two_kcc20(NS, false);
        t.network = Network::Testnet;
        t.funding_mode = FundingMode::Earmarked;
        t
    };
    let p = |i| party(NS, i);
    let kas_pair = {
        let mut t = terms(
            NS,
            vec![
                kas_leg(p(0), p(1), 3 * KAS_AMOUNT),
                kas_leg(p(1), p(0), 5 * KAS_AMOUNT),
            ],
            false,
        );
        t.funding_mode = FundingMode::Earmarked;
        t.earliest_daa = None;
        t
    };
    let owners = {
        let mut t = two_kas(NS, true);
        t.network = Network::Testnet;
        t.earliest_daa = None;
        t.legs[0].delivery = DestinationV2 {
            identifier_type: IdentifierType::CovenantId,
            identifier: label32("impulse/vectors/linked/owner/covenant"),
        };
        t.legs[0].refund = script_hash(label32("impulse/vectors/linked/owner/script"));
        t
    };
    let bounds = two_kas(NS, false);
    vec![
        SheetVector {
            name: "01-repo-token-for-kas",
            description: "A repurchase shape: party 0 sells a token to party 1 for KAS and buys it back later for one percent more KAS. Authority present, revocable funding, mainnet. The KAS leg is refunded to a P2SH.",
            sheet: sheet_of(repo, [TOKEN_AMOUNT, KAS_AMOUNT + KAS_AMOUNT / 100], RETURN_EARLIEST, RETURN_EXPIRY),
        },
        SheetVector {
            name: "02-securities-loan-token-for-token",
            description: "A securities loan shape: party 0 lends token 0 against token 1 held by party 1; the return gives back five more units of token 0 and all of token 1. Self-settling, earmarked funding, testnet.",
            sheet: sheet_of(loan, [TOKEN_AMOUNT + 5, TOKEN_AMOUNT * 250], RETURN_EARLIEST, RETURN_EXPIRY),
        },
        SheetVector {
            name: "03-kas-for-kas",
            description: "Two KAS legs between two parties, earmarked funding, no earliest bound on the opening, a return that adds 0.01 KAS to the first leg. Mainnet.",
            sheet: sheet_of(kas_pair, [3 * KAS_AMOUNT + KAS_AMOUNT / 100, 5 * KAS_AMOUNT], RETURN_EARLIEST, RETURN_EXPIRY),
        },
        SheetVector {
            name: "04-destination-types",
            description: "A COVENANT_ID delivery owner and a SCRIPT_HASH refund owner on the token leg, so the derived return swaps them (delivery of the return leg is the opening's refund, its refund the opening's delivery). Testnet, no earliest on the opening.",
            sheet: sheet_of(owners, [TOKEN_AMOUNT, KAS_AMOUNT], RETURN_EARLIEST, RETURN_EXPIRY),
        },
        SheetVector {
            name: "05-return-bounds",
            description: "The tightest return window: return earliest one above the opening's expiry, return expiry one above the return earliest, return amounts equal to the opening's. Mainnet.",
            sheet: sheet_of(bounds, [TOKEN_AMOUNT, KAS_AMOUNT], EXPIRY + 1, EXPIRY + 2),
        },
    ]
}

fn dec(n: u64) -> J {
    J::Str(n.to_string())
}

fn id_name(t: IdentifierType) -> &'static str {
    match t {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

fn destination_json(d: &DestinationV2) -> J {
    J::Obj(vec![
        ("identifier_type", J::Str(id_name(d.identifier_type).into())),
        ("identifier", J::Str(hex(&d.identifier))),
    ])
}

fn leg_json(l: &LegV2) -> J {
    let mut asset = Vec::new();
    match &l.asset.kind {
        LegKind::Kas => asset.push(("kind", J::Str("kas".into()))),
        LegKind::Kcc20(t) => {
            asset.push(("kind", J::Str("kcc20".into())));
            asset.push(("covenant_id", J::Str(hex(&t.covenant_id))));
            asset.push(("template_hash", J::Str(hex(&t.template_hash))));
            asset.push(("template_prefix_len", J::Int(t.template_prefix_len.into())));
            asset.push(("template_suffix_len", J::Int(t.template_suffix_len.into())));
        }
        LegKind::External => asset.push(("kind", J::Str("external".into()))),
    }
    asset.push(("amount", dec(l.asset.amount)));
    J::Obj(vec![
        ("depositor_key", J::Str(hex(&l.depositor_key))),
        ("asset", J::Obj(asset)),
        ("delivery", destination_json(&l.delivery)),
        ("refund", destination_json(&l.refund)),
    ])
}

/// The JSON form of a terms v2 value, as the v2 vectors write it.
fn terms_json(t: &TermsV2) -> J {
    J::Obj(vec![
        ("version", J::Int(t.version.into())),
        (
            "network",
            J::Str(
                match t.network {
                    Network::Mainnet => "mainnet",
                    Network::Testnet => "testnet",
                }
                .into(),
            ),
        ),
        ("nonce", dec(t.nonce)),
        (
            "authority_key",
            t.authority_key.map_or(J::Null, |k| J::Str(hex(&k))),
        ),
        ("legs", J::Arr(t.legs.iter().map(leg_json).collect())),
        ("earliest_daa", t.earliest_daa.map_or(J::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            J::Str(
                match t.funding_mode {
                    FundingMode::Revocable => "revocable",
                    FundingMode::Earmarked => "earmarked",
                }
                .into(),
            ),
        ),
        ("partial", J::Null),
        ("trade_ref", J::Str(hex(&t.trade_ref))),
    ])
}

fn trade_json(t: &crate::v2::ValidatedTermsV2) -> J {
    J::Obj(vec![
        ("terms", terms_json(t.terms())),
        ("canonical", J::Str(hex(t.canonical()))),
        ("terms_hash", J::Str(hex(&t.terms_hash()))),
    ])
}

fn render(v: &SheetVector) -> String {
    let linked = v.sheet.clone().validate().expect(v.name);
    let doc = J::Obj(vec![
        ("name", J::Str(v.name.into())),
        ("description", J::Str(v.description.into())),
        (
            "sheet",
            J::Obj(vec![
                ("link_version", J::Int(v.sheet.version.into())),
                ("opening", terms_json(&v.sheet.opening)),
                (
                    "return_amounts",
                    J::Arr(v.sheet.return_amounts.iter().map(|a| dec(*a)).collect()),
                ),
                ("return_earliest_daa", dec(v.sheet.return_earliest_daa)),
                ("return_expiry_daa", dec(v.sheet.return_expiry_daa)),
            ]),
        ),
        ("canonical", J::Str(hex(linked.canonical()))),
        ("linked_hash", J::Str(hex(&linked.linked_hash()))),
        ("opening_trade", trade_json(linked.terms(Role::Opening))),
        ("return_trade", trade_json(linked.terms(Role::Return))),
    ]);
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join("linked")
}

fn all_files() -> Vec<(String, String)> {
    sheet_vectors()
        .iter()
        .map(|v| (format!("{}.json", v.name), render(v)))
        .collect()
}

#[test]
fn golden_files_match() {
    let files = all_files();
    let mut expected: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    expected.sort();
    let mut found: Vec<String> = std::fs::read_dir(dir())
        .expect("tests/vectors/linked exists")
        .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
        .filter(|name| !name.starts_with('.'))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "tests/vectors/linked holds exactly the golden set"
    );
    for (name, content) in &files {
        let path = dir().join(name);
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == *content,
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

#[test]
fn golden_sheets_decode_hash_and_derive() {
    for v in sheet_vectors() {
        let text = std::fs::read_to_string(dir().join(format!("{}.json", v.name))).expect("read");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
        let canonical =
            crate::tx::ipst::unhex(doc["canonical"].as_str().expect("canonical")).expect("hex");
        let decoded = LinkedSheet::decode(&canonical).expect("committed bytes decode");
        assert_eq!(decoded, v.sheet, "{}", v.name);
        assert_eq!(decoded.encode().unwrap(), canonical);
        assert_eq!(
            hex(&decoded.linked_hash().unwrap()),
            doc["linked_hash"].as_str().unwrap()
        );
        let linked = decoded.validate().expect(v.name);
        for (key, role) in [
            ("opening_trade", Role::Opening),
            ("return_trade", Role::Return),
        ] {
            let stored = crate::tx::ipst::unhex(doc[key]["canonical"].as_str().unwrap()).unwrap();
            assert_eq!(linked.terms(role).canonical(), stored, "{} {key}", v.name);
            assert_eq!(
                hex(&linked.terms_hash(role)),
                doc[key]["terms_hash"].as_str().unwrap()
            );
            assert_eq!(linked.terms(role).terms().trade_ref, linked.linked_hash());
        }
    }
}

/// spec/V2.md 17.11: the set covers KAS against a token, token against token, KAS against KAS,
/// both networks, both funding modes, authority present and absent, a return with a fee and
/// without, an opening with and without earliest, and every destination type.
#[test]
fn golden_set_covers_spec_17_11() {
    let vs = sheet_vectors();
    let any = |f: &dyn Fn(&LinkedSheet) -> bool| vs.iter().any(|v| f(&v.sheet));
    assert!(any(&|s| s.opening.kcc20_legs() == 1));
    assert!(any(&|s| s.opening.kcc20_legs() == 2));
    assert!(any(&|s| s.opening.kcc20_legs() == 0));
    assert!(any(&|s| s.opening.network == Network::Mainnet));
    assert!(any(&|s| s.opening.network == Network::Testnet));
    assert!(any(&|s| s.opening.funding_mode == FundingMode::Revocable));
    assert!(any(&|s| s.opening.funding_mode == FundingMode::Earmarked));
    assert!(any(&|s| s.opening.authority_key.is_some()));
    assert!(any(&|s| s.opening.authority_key.is_none()));
    assert!(any(&|s| s
        .opening
        .legs
        .iter()
        .zip(s.return_amounts)
        .any(|(l, a)| a > l.asset.amount)));
    assert!(any(&|s| s
        .opening
        .legs
        .iter()
        .zip(s.return_amounts)
        .all(|(l, a)| a == l.asset.amount)));
    assert!(any(&|s| s.opening.earliest_daa.is_none()));
    assert!(any(&|s| s.opening.earliest_daa.is_some()));
    for ty in [
        IdentifierType::PubKey,
        IdentifierType::ScriptHash,
        IdentifierType::CovenantId,
    ] {
        assert!(any(&|s| s.opening.legs.iter().any(|l| [
            l.delivery, l.refund
        ]
        .iter()
        .any(|d| d.identifier_type == ty))));
    }
    assert!(vs.iter().all(|v| !v.name.contains("net")));
}

/// Writes the set to $IMPULSE_VECTORS_OUT/linked/. Run by scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    let d = Path::new(&out).join("linked");
    std::fs::create_dir_all(&d).expect("create output dir");
    for (name, content) in all_files() {
        std::fs::write(d.join(name), content).expect("write vector");
    }
}
