// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The committed real receipts of template v4 (tests/engine/fixtures/v4/, spec/V3-ZK.md 22.9) in the
//! pinned Kaspa engine: every receipt is accepted by the proof gate run on its own (J hashed in
//! script, the zk-sdk Groth16 fragment), carries the image ID of the terms guest this build embeds,
//! and is refused for a flipped proof byte, a changed journal byte (every byte of the first receipt, a spread of the others) or another image ID. The
//! journals are those the v4 builders make (impulse-core `committed_receipts_are_the_journals_the_builders_make`).
use std::path::PathBuf;

use impulse_zk_prover::terms::terms_guest_image_id;
use impulse_zk_prover::{engine_verify, read_json, sha256, ProofFile};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v4")
}

fn fixtures() -> Vec<(String, ProofFile)> {
    let mut out: Vec<(String, ProofFile)> = std::fs::read_dir(dir())
        .expect("tests/engine/fixtures/v4 exists; run scripts/regen-fixtures-v4.sh")
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".proof.json"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                read_json::<ProofFile>(&p).unwrap(),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn there_is_a_receipt_for_every_fixture_plan() {
    let names: Vec<String> = fixtures().into_iter().map(|(n, _)| n).collect();
    for want in [
        "settle-kas-asset",
        "settle-kas-cash",
        "settle-kcc20-asset",
        "settle-kcc20-cash",
        "settle-external-asset",
        "refund-asset-depositor",
        "refund-kas-cash-counterparty",
        "refund-asset-depositor-earmarked",
    ] {
        assert!(
            names.contains(&format!("{want}.proof.json")),
            "{want} is missing"
        );
    }
}

#[test]
fn every_v4_receipt_is_accepted_by_the_engine_for_the_terms_guest() {
    let image = terms_guest_image_id();
    for (name, p) in fixtures() {
        assert_eq!(p.image_id_bytes(), image, "{name}: image ID");
        assert_eq!(
            hex::decode(&p.journal_hash).unwrap(),
            sha256(&p.journal_bytes()),
            "{name}: journal hash"
        );
        assert_eq!(p.proof_bytes().len(), 128, "{name}");
        engine_verify(&p.proof_bytes(), &p.journal_bytes(), image)
            .unwrap_or_else(|e| panic!("{name}: refused by the engine: {e}"));
    }
}

#[test]
fn a_v4_receipt_is_refused_for_any_change() {
    let image = terms_guest_image_id();
    for (n, (name, p)) in fixtures().into_iter().enumerate() {
        let (proof, journal) = (p.proof_bytes(), p.journal_bytes());
        // Every byte of the proof and of the journal of the first receipt; every sixteenth and
        // every eleventh of the others (an engine run of the gate takes tens of milliseconds).
        let (proof_step, journal_step) = if n == 0 { (1, 1) } else { (16, 11) };
        for i in (0..proof.len()).step_by(proof_step) {
            let mut bad = proof.clone();
            bad[i] ^= 1;
            assert!(
                engine_verify(&bad, &journal, image).is_err(),
                "{name}: proof byte {i} flipped, accepted"
            );
        }
        for i in (0..journal.len()).step_by(journal_step) {
            let mut bad = journal.clone();
            bad[i] ^= 1;
            assert!(
                engine_verify(&proof, &bad, image).is_err(),
                "{name}: journal byte {i} flipped, accepted"
            );
        }
        // Another image ID.
        let mut other = image;
        other[0] ^= 1;
        assert!(engine_verify(&proof, &journal, other).is_err(), "{name}");
    }
}

#[test]
fn a_receipt_proves_its_own_journal_only() {
    let all = fixtures();
    let image = terms_guest_image_id();
    for (a, pa) in &all {
        for (b, pb) in &all {
            if pa.journal_bytes() == pb.journal_bytes() {
                continue;
            }
            assert!(
                engine_verify(&pa.proof_bytes(), &pb.journal_bytes(), image).is_err(),
                "the receipt of {a} was accepted for the journal of {b}"
            );
        }
    }
}
