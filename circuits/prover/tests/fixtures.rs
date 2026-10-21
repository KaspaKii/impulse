// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The committed proof fixtures (tests/engine/fixtures/v3/proofs/) in the pinned Kaspa engine:
//! every valid proof is accepted by the proof gate of template v3 run on its own (J hashed in
//! script, the zk-sdk Groth16 fragment, tag 0x20), and every invalid case of spec/V3-ZK.md 13.2 is
//! refused. The deterministic files (inputs, journals, cases) must equal what the code computes.
use std::path::PathBuf;

use impulse_zk_prover::fixtures::{alter, case_image, check_dir};
use impulse_zk_prover::{engine_verify, read_json, sha256, ProofFile};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v3/proofs")
}

fn proof(name: &str) -> ProofFile {
    read_json(&dir().join(format!("{name}.proof.json"))).unwrap()
}

#[test]
fn committed_fixtures_check() {
    let lines = check_dir(&dir()).unwrap();
    for l in &lines {
        println!("{l}");
    }
    assert!(lines.len() >= 20);
}

#[test]
fn v3_fixture_receipt_accepted() {
    let p = proof("a_list1000");
    engine_verify(
        &p.proof_bytes(),
        &p.journal_bytes(),
        impulse_zk_prover::list_guest_image_id(),
    )
    .unwrap();
}

#[test]
fn journal_digest_is_sha256_of_j() {
    // spec/V3-ZK.md 5.2 asserted that the RISC Zero journal digest is SHA-256 of the committed
    // bytes. The gate hashes J with OpSHA256 and the real receipt verifies, so it holds for this
    // receipt; the same J with any other digest function would be refused.
    let p = proof("a_list1000");
    assert_eq!(
        hex::decode(&p.journal_hash).unwrap(),
        sha256(&p.journal_bytes())
    );
}

#[test]
fn v3_proof_bit_flip_refused_every_byte() {
    // One bit flipped in each of the 128 bytes: every one is refused.
    let p = proof("a_list1000");
    let id = impulse_zk_prover::list_guest_image_id();
    for b in 0..128 {
        let bad = alter(&p.proof_bytes(), &format!("flip:{b}:{}", b % 8));
        assert!(
            engine_verify(&bad, &p.journal_bytes(), id).is_err(),
            "byte {b}"
        );
    }
}

#[test]
fn every_journal_byte_is_bound() {
    // Flipping any one byte of J (tag, root, vault, owner) makes the valid proof fail.
    let p = proof("a_list1000");
    let id = impulse_zk_prover::list_guest_image_id();
    let j = p.journal_bytes();
    for i in 0..j.len() {
        let mut bad = j.clone();
        bad[i] ^= 0x01;
        assert!(
            engine_verify(&p.proof_bytes(), &bad, id).is_err(),
            "J byte {i}"
        );
    }
}

#[test]
fn list_size_does_not_change_proof_size() {
    // Same compressed size for a list of one and of 1,000 entries (the script units are measured by
    // the contract step's v3_list_size_does_not_change_cost).
    assert_eq!(
        proof("a_list1").proof_bytes().len(),
        proof("a_list1000").proof_bytes().len()
    );
    assert_eq!(case_image("list"), impulse_zk_prover::list_guest_image_id());
}
