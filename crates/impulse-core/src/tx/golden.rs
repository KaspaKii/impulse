// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden IPST vectors (tests/vectors/ipst/, spec/IPST.md "Golden vectors"). Each vector is an
//! unsigned IPST a builder makes from fixed inputs: terms built for the vectors with the fixture
//! KCC-20 templates, label-derived keys (nobody holds their private keys) and label-derived
//! outpoints. The files are frozen: a builder, sighash or rendering change fails
//! `golden_files_match`. scripts/vectors.sh regenerates them through `emit_vectors`, diffs them,
//! and recomputes every sighash in Python.

use super::ipst::{write_json, J};
use super::testkit::*;
use super::*;
use crate::template::{LegIndex, Vault};
use crate::terms::golden::xonly;
use crate::terms::{CreationContext, FundingMode, ValidatedTerms};
use std::path::{Path, PathBuf};

struct Vector {
    name: &'static str,
    description: &'static str,
    ipst: Ipst,
}

fn parties() -> Parties {
    Parties {
        seller: xonly("impulse/vectors/key/seller"),
        buyer: xonly("impulse/vectors/key/buyer"),
        authority: xonly("impulse/vectors/key/authority"),
        payer: xonly("impulse/vectors/key/payer"),
    }
}

fn fundable(terms: &ValidatedTerms, leg: LegIndex) -> crate::template::FundableVault {
    let ctx = CreationContext::new(terms.terms().network, NOW - 1);
    Vault::instantiate_for_creation(terms, leg, &ctx).expect("fundable")
}

fn vectors() -> Vec<Vector> {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let kas = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let kcc20 = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let self_settling = validated(Mode::vault(false, Cash::Kcc20, FundingMode::Revocable), &p);
    let external = validated(
        Mode::vault(true, Cash::External, FundingMode::Earmarked),
        &p,
    );
    let direct_kas = validated(Mode::direct(Cash::Kas), &p);
    let direct_kcc20 = validated(Mode::direct(Cash::Kcc20), &p);
    let fee = fee_payment(&p);
    let settle_of = |terms: &ValidatedTerms| {
        settle(terms, &settle_legs(&funded(terms), &a, &c), &fee, NOW).expect("settle")
    };
    let refund_of = |terms: &ValidatedTerms, leg, signer, with_token: bool| {
        let f = funded(terms);
        let (vault_utxo, escrow) = match leg {
            LegIndex::Asset => (
                f.asset_authorizer.clone(),
                Some(RefundEscrow {
                    utxo: f.asset_escrow.clone(),
                    amount: terms.terms().asset_leg.amount,
                    is_minter: false,
                    template: &a,
                }),
            ),
            LegIndex::Cash => match (&f.cash_vault, &f.cash_authorizer, &f.cash_escrow) {
                (Some(v), _, _) => (v.clone(), None),
                (_, Some(auth), Some(e)) => (
                    auth.clone(),
                    Some(RefundEscrow {
                        utxo: e.clone(),
                        amount: terms.terms().cash_leg.amount,
                        is_minter: false,
                        template: &c,
                    }),
                ),
                _ => unreachable!("vectors refund existing vaults"),
            },
        };
        let escrow = if with_token { escrow } else { None };
        refund(terms, leg, signer, &vault_utxo, escrow.as_ref(), &fee).expect("refund")
    };
    let two_tokens = Kcc20Deposit {
        tokens: vec![
            own_token("vector/seller-token-1", &a, ASSET_COV, &p.seller, 600),
            own_token("vector/seller-token-2", &a, ASSET_COV, &p.seller, 700),
        ],
        carrier: MIN_KCC20_OUTPUT,
        authorizer: MIN_KAS_OUTPUT,
    };
    let cash_deposit = Kcc20Deposit {
        tokens: vec![own_token(
            "vector/buyer-token",
            &c,
            CASH_COV,
            &p.buyer,
            KCC20_CASH,
        )],
        carrier: MIN_KCC20_OUTPUT,
        authorizer: MIN_KAS_OUTPUT,
    };
    vec![
        Vector {
            name: "01-fund-kcc20-asset-with-token-change",
            description: "fund_kcc20 asset leg from two seller tokens holding 1300 for a leg of 1000, escrow and authorizer at the minimums, token change and KAS change",
            ipst: fund_kcc20(&kas, &fundable(&kas, LegIndex::Asset), &a, &two_tokens, &fee, NOW).unwrap(),
        },
        Vector {
            name: "02-fund-kas-cash",
            description: "fund_kas cash leg of 1 KAS paid by the payer, KAS change",
            ipst: fund_kas(&kas, &fundable(&kas, LegIndex::Cash), &fee, NOW).unwrap(),
        },
        Vector {
            name: "03-fund-kcc20-cash",
            description: "fund_kcc20 cash leg from one buyer token holding exactly the leg amount, no token change",
            ipst: fund_kcc20(&kcc20, &fundable(&kcc20, LegIndex::Cash), &c, &cash_deposit, &fee, NOW).unwrap(),
        },
        Vector {
            name: "04-settle-authority-kas",
            description: "settle vault authority KAS cash earmarked, lock time earliest, authority signs inputs 0 and 1",
            ipst: settle_of(&kas),
        },
        Vector {
            name: "05-settle-authority-kcc20",
            description: "settle vault authority KCC-20 cash earmarked, both authorizers returned at outputs 2 and 3",
            ipst: settle_of(&kcc20),
        },
        Vector {
            name: "06-settle-self-settling-kcc20",
            description: "settle vault self-settling KCC-20 cash revocable, no vault input takes a signature",
            ipst: settle_of(&self_settling),
        },
        Vector {
            name: "07-settle-authority-external",
            description: "settle vault external cash, positions 1 and 3 drop out",
            ipst: settle_of(&external),
        },
        Vector {
            name: "08-refund-asset-depositor-earmarked",
            description: "refund asset leg with its token by the seller in earmarked mode, lock time expiry",
            ipst: refund_of(&kas, LegIndex::Asset, RefundSigner::Depositor, true),
        },
        Vector {
            name: "09-refund-asset-counterparty",
            description: "refund asset leg with its token by the buyer, no lock time",
            ipst: refund_of(&kas, LegIndex::Asset, RefundSigner::Counterparty, true),
        },
        Vector {
            name: "10-refund-kas-cash-authority",
            description: "refund KAS cash leg by the authority to the buyer refund scriptPubKey",
            ipst: refund_of(&kas, LegIndex::Cash, RefundSigner::Authority, false),
        },
        Vector {
            name: "11-refund-kcc20-cash-authorizer-alone",
            description: "refund KCC-20 cash leg authorizer without its token by the buyer in earmarked mode",
            ipst: refund_of(&kcc20, LegIndex::Cash, RefundSigner::Depositor, false),
        },
        Vector {
            name: "12-direct-kas",
            description: "direct seller KCC-20 asset against buyer KAS, lock time earliest",
            ipst: direct(&direct_kas, &direct_legs(&direct_kas, &p, &a, &c), &fee, NOW).unwrap(),
        },
        Vector {
            name: "13-direct-kcc20",
            description: "direct seller KCC-20 asset against buyer KCC-20 cash",
            ipst: direct(&direct_kcc20, &direct_legs(&direct_kcc20, &p, &a, &c), &fee, NOW).unwrap(),
        },
    ]
}

fn render(v: &Vector) -> String {
    let doc = J::Obj(vec![
        ("name", J::Str(v.name.into())),
        ("description", J::Str(v.description.into())),
        ("ipst", v.ipst.to_value()),
    ]);
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/ipst")
}

fn file_name(v: &Vector) -> String {
    format!("{}.json", v.name)
}

#[test]
fn golden_files_match() {
    let dir = committed_dir();
    let defined = vectors();
    let mut expected: Vec<String> = defined.iter().map(file_name).collect();
    expected.sort();
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
        .filter(|name| !name.starts_with('.'))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "tests/vectors/ipst holds exactly the golden set"
    );
    for v in &defined {
        let path = dir.join(file_name(v));
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == render(v),
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

#[test]
fn golden_files_read_back() {
    for v in vectors() {
        let text = std::fs::read_to_string(committed_dir().join(file_name(&v))).expect("read");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(doc["name"].as_str(), Some(v.name));
        let read = Ipst::from_json(&doc["ipst"].to_string()).expect("the committed IPST reads");
        assert_eq!(read, v.ipst, "{}", v.name);
        assert!(read.slots().iter().all(|s| s.signature().is_none()));
    }
}

#[test]
fn golden_set_covers_every_builder_and_mode() {
    let vs = vectors();
    let names: Vec<&str> = vs.iter().map(|v| v.name).collect();
    for word in [
        "fund-kcc20",
        "fund-kas",
        "settle-authority-kas",
        "settle-authority-kcc20",
        "self-settling",
        "external",
        "refund",
        "direct-kas",
        "direct-kcc20",
    ] {
        assert!(names.iter().any(|n| n.contains(word)), "{word}");
    }
    // Every slot kind: signed by a key, and complete without one.
    assert!(vs
        .iter()
        .any(|v| v.ipst.slots().iter().any(|s| s.signer().is_none())));
    assert!(vs
        .iter()
        .all(|v| v.ipst.slots().iter().any(|s| s.signer().is_some())));
}

/// Writes the golden set to $IMPULSE_VECTORS_OUT/ipst/. Run by scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    let dir = Path::new(&out).join("ipst");
    std::fs::create_dir_all(&dir).expect("create output dir");
    for v in vectors() {
        std::fs::write(dir.join(file_name(&v)), render(&v)).expect("write vector");
    }
}
