// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The verifier side of template v4 (spec/V3-ZK.md 22.7): `impulse_core::zkh` on transactions the
//! engine harness builds from the shipped template. Run with revealed terms, the host checker must
//! accept each fixture, refuse a terms file that differs in one byte of `blind`, name the failing
//! tag on a mutated transaction, and report a v4 vault input without the terms as hidden.
//! No proof is needed: the checker repeats what the guest proves (statement of terms-core).

mod harness;
mod v4_common;
use harness::*;
use impulse_core::zkh;
use v4_common::*;

fn parse(v: &V4) -> terms_core::Terms {
    let text = zkh::hex(&v.core.encode());
    zkh::parse_terms_file(&text).expect("terms file parses")
}

fn all_ok(v: &V4, spec: &TxSpec, label: &str) {
    let (tx, entries) = spec.build(&v.w);
    let checks = zkh::check_revealed(&tx, &entries, &parse(v)).expect(label);
    assert!(!checks.is_empty(), "{label}: no v4 input found");
    for c in &checks {
        assert_eq!(c.verdict, Ok(()), "{label}: input {}", c.input_index);
    }
}

#[test]
fn decode_with_terms_accepts_each_fixture() {
    for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
        let v = V4::fixed(Kind::Real, cash, REVOCABLE, 1);
        all_ok(
            &v,
            &v.settle(&Proofs::Zeros),
            &format!("settle cash {cash}"),
        );
    }
    let v = V4::live(Kind::Real, CASH_KCC20, REVOCABLE);
    all_ok(
        &v,
        &v.refund(ASSET_LEG, Role::Seller, &Proofs::Zeros),
        "refund asset",
    );
    all_ok(
        &v,
        &v.refund(CASH_LEG, Role::Buyer, &Proofs::Zeros),
        "refund cash",
    );
}

#[test]
fn without_terms_a_v4_input_is_reported_as_hidden() {
    let v = V4::fixed(Kind::Real, CASH_KCC20, REVOCABLE, 1);
    let (tx, _) = v.settle(&Proofs::Zeros).build(&v.w);
    let hidden = zkh::hidden_inputs(&tx).expect("hidden");
    assert_eq!(hidden.len(), 2);
    assert_eq!(hidden[0].entry, "settle");
    assert_eq!(hidden[0].commit, v.commit(0));
    assert_eq!(hidden[1].commit, v.commit(1));
    assert_eq!(hidden[0].authority, v.authority());
}

#[test]
fn a_terms_file_differing_in_one_blind_byte_is_a_mismatch() {
    let v = V4::fixed(Kind::Real, CASH_KCC20, REVOCABLE, 1);
    let (tx, entries) = v.settle(&Proofs::Zeros).build(&v.w);
    let mut other = v.core.clone();
    other.blind[0] ^= 1;
    let checks = zkh::check_revealed(&tx, &entries, &other).expect("checks");
    assert!(!checks.is_empty());
    for c in checks {
        assert_eq!(c.verdict.unwrap_err().code(), "ZK_H_TERMS_MISMATCH");
    }
}

#[test]
fn a_mutated_transaction_names_the_failing_tag() {
    let v = V4::fixed(Kind::Real, CASH_KAS, REVOCABLE, 1);
    let (mut tx, entries) = v.settle(&Proofs::Zeros).build(&v.w);
    tx.outputs[1].value += 1; // the seller's KAS proceeds one sompi over
    let checks = zkh::check_revealed(&tx, &entries, &v.core).expect("checks");
    let err = checks
        .iter()
        .find_map(|c| c.verdict.clone().err())
        .expect("one input fails");
    assert_eq!(err.code(), "ZK_H_STATEMENT_FALSE", "{err}");
    assert!(err.reason().starts_with("tag "), "{err}");
}

#[test]
fn a_v1_vault_is_not_a_v4_vault() {
    let w = World::with(Mode::new(true, CASH_KCC20, REVOCABLE), |_, _| {});
    let spec = w.settle();
    let (tx, _) = spec.build(&w);
    assert!(zkh::hidden_inputs(&tx).expect("no error").is_empty());
    let script = w.vault(0).bytecode().to_vec();
    assert_eq!(
        zkh::decode_vault(&script).unwrap_err().code(),
        "ZK_H_NOT_V4_VAULT"
    );
}

#[test]
fn the_terms_file_refuses_a_wrong_version_and_non_hex() {
    assert_eq!(
        zkh::parse_terms_file("zz").unwrap_err().code(),
        "ZK_H_TERMS_VERSION"
    );
    assert_eq!(
        zkh::parse_terms_file("0301").unwrap_err().code(),
        "ZK_H_TERMS_VERSION"
    );
}

#[test]
fn the_shipped_template_passes_its_startup_check_and_roundtrips() {
    let t = zkh::check().expect("template v4");
    assert_eq!(
        zkh::hex(&t.hash()),
        std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH_V4"))
            .unwrap()
            .trim()
    );
    let v = zkh::VaultV4::instantiate([7; 32], [9; 32]).expect("vault");
    assert_eq!(
        zkh::decode_vault(v.redeem_script()).unwrap(),
        ([7; 32], [9; 32])
    );
    let mut altered = v.redeem_script().to_vec();
    let n = altered.len();
    altered[n - 1] ^= 1;
    assert!(zkh::decode_vault(&altered).is_err());
}
