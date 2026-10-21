// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The proof gate of template v3 in the real engine, with real receipts of the list guest
//! (spec/V3-ZK.md 13.1, 13.2). The fixtures under fixtures/v3/proofs/ are real Groth16 proofs
//! bound to the real fixture vaults (vaults.json), so a valid one settles the real template v3
//! and every invalid one is refused by the precompile.
//!
//! Test names are the names of spec 13.2. A refusal by the gate is `ZkIntegrity` with the
//! precompile's cost charged; where the proof is valid for another statement, the same fixture
//! at its own vault is the accepted twin.

mod harness;
mod v3_common;
use harness::*;
use v3_common::*;

/// Every input of the settle of `fixture`'s own vault accepted: asset vault with the proof,
/// cash vault with an empty one, the tokens and the fee input.
fn assert_settles(fixture: &str) {
    let w = world_for(fixture);
    w.settle()
        .assert_all_accepted(&w, &format!("settle with fixture {fixture}"));
}

#[test]
fn v3_fixture_receipt_accepted() {
    // KAS cash: a list of one entry and of 1,000; a P2PK and a P2SH delivery owner
    for f in ["a_list1", "a_list1000", "c_list1000_p2sh"] {
        assert_settles(f);
    }
}

#[test]
fn v3_fixture_receipt_accepted_kcc20_cash() {
    assert_settles("a_list1000_kcc20");
}

/// Both owner types are covered: the fixture owners are a P2PK owner and a P2SH owner.
#[test]
fn v3_fixture_owner_types() {
    assert_eq!(
        world_for("a_list1000").terms.buyer_delivery.id_type,
        IDENTIFIER_PUBKEY
    );
    assert_eq!(
        world_for("c_list1000_p2sh").terms.buyer_delivery.id_type,
        IDENTIFIER_SCRIPT_HASH
    );
}

#[test]
fn v3_list_size_does_not_change_cost() {
    let (small, large) = (fixture("a_list1"), fixture("a_list1000"));
    assert_eq!(small.proof.len(), 128);
    assert_eq!(large.proof.len(), 128);
    let units = |name: &str| {
        let w = world_for(name);
        let (tx, entries) = w.settle().build(&w);
        let run = measure(&tx, &entries, 0);
        assert_accepted(&run, name);
        run.used.0
    };
    let (a, b) = (units("a_list1"), units("a_list1000"));
    eprintln!("asset vault settle units: list of 1 entry {a}, list of 1,000 entries {b}");
    assert_eq!(a, b);
}

#[test]
fn v3_proof_bit_flip_refused() {
    let w = world_for("a_list1000");
    let proof = w.proof.clone();
    assert_eq!(settle_with(&w, proof.clone()).result, Ok(()));
    for (byte, bit) in [
        (0usize, 0u8),
        (31, 7),
        (32, 0),
        (64, 3),
        (96, 5),
        (127, 0),
        (127, 7),
    ] {
        let mut p = proof.clone();
        p[byte] ^= 1 << bit;
        assert_gate_refused(
            &settle_with(&w, p),
            &format!("bit {bit} of byte {byte} flipped"),
        );
    }
}

#[test]
fn v3_proof_length_refused() {
    let w = world_for("a_list1000");
    let proof = w.proof.clone();
    assert_eq!(settle_with(&w, proof.clone()).result, Ok(()));
    let mut longer = proof.clone();
    longer.push(0);
    for (label, p) in [
        ("0 bytes", vec![]),
        ("127 bytes", proof[..127].to_vec()),
        ("129 bytes", longer),
    ] {
        assert_gate_refused(&settle_with(&w, p), label);
    }
}

#[test]
fn v3_proof_for_other_vault_refused() {
    // valid proof for vault B (another nonce, same root and owner), used at vault A
    let a = world_for("a_list1000");
    let b = world_for("a_list1000_vault_b");
    b.settle()
        .assert_all_accepted(&b, "vault B settles with its own proof");
    assert_gate_refused(
        &settle_with(&a, b.proof.clone()),
        "vault B's proof at vault A",
    );
    assert_gate_refused(
        &settle_with(&b, a.proof.clone()),
        "vault A's proof at vault B",
    );
}

#[test]
fn v3_proof_for_other_root_refused() {
    // a member of the list of one entry (owner A, root of list1), proof bound to the
    // list1000 vault's scriptPubKey: valid for another root only
    let w = world_for("a_list1000");
    let other = fixture("a_list1_at_vault1000");
    assert_ne!(other.root, fixture("a_list1000").root);
    assert_eq!(other.vault_spk, fixture("a_list1000").vault_spk);
    assert_gate_refused(
        &settle_with(&w, other.proof),
        "a proof for another list root",
    );
}

#[test]
fn v3_proof_for_other_owner_refused() {
    // member B's proof, bound to the same vault, used for a settle delivering to owner A
    let w = world_for("a_list1000");
    let other = fixture("b_list1000");
    assert_eq!(other.vault_spk, fixture("a_list1000").vault_spk);
    assert_gate_refused(
        &settle_with(&w, other.proof),
        "member B's proof, delivery to A",
    );
}

#[test]
fn v3_proof_owner_type_swap_refused() {
    // the proof commits A as a P2PK owner; the vault names the same 32 bytes as a script hash
    let swap = world_for("a_list1000_swap");
    assert_eq!(swap.terms.buyer_delivery.id_type, IDENTIFIER_SCRIPT_HASH);
    assert_eq!(
        swap.terms.buyer_delivery.id,
        world_for("a_list1000").terms.buyer_delivery.id
    );
    assert_gate_refused(&settle_with(&swap, swap.proof.clone()), "owner type swap");
}

#[test]
fn v3_forging_guest_refused() {
    // a guest that commits the correct J without checking a path: another image ID
    let w = world_for("a_list1000");
    let forge = fixture("forge_a_list1000");
    assert_eq!(forge.journal, fixture("a_list1000").journal, "same J");
    assert_ne!(
        forge.image_id,
        fixture("a_list1000").image_id,
        "another image ID"
    );
    assert_gate_refused(&settle_with(&w, forge.proof), "forging guest");
}

#[test]
fn v3_proof_for_cash_vault_refused() {
    // right guest, but bound to the cash vault's scriptPubKey
    let w = world_for("a_list1000");
    let f = fixture("a_list1000_cash_vault");
    assert_eq!(f.vault, "cash_list1000");
    assert_gate_refused(&settle_with(&w, f.proof), "proof bound to the cash vault");
}

/// The same proof does not move between legs of one trade in the other direction either: the
/// cash vault takes no proof and an empty one is all it accepts ([Z2] is in v3_settle.rs).
#[test]
fn v3_a_proof_is_a_128_byte_witness_item() {
    for f in [
        "a_list1",
        "a_list1000",
        "c_list1000_p2sh",
        "a_list1000_kcc20",
    ] {
        assert_eq!(fixture(f).proof.len(), 128, "{f}");
    }
}
