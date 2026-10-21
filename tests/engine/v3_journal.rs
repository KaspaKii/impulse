// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The journal the contract builds, checked without a proof (spec/V3-ZK.md 5.2, 13.1). The
//! source of template v3 is compiled with its one `r0.g16.verify` line replaced by
//! `require(journalHash == byte[32](proof))`, so the witness is compared with the SHA-256 the
//! contract computed. The test builds J from the spec (tag, root, the vault's own scriptPubKey,
//! the owner's scriptPubKey) in Rust and passes its SHA-256 as the "proof": accepted when J
//! matches byte for byte, refused when any field differs.
//!
//! This is a test of the journal construction only. It compiles a different script from
//! template v3 (the verify line is gone), so it says nothing about the gate; the gate is
//! tested with real proofs in v3_proofs.rs.

mod harness;
mod v3_common;
use harness::*;
use v3_common::*;

#[test]
fn sha256_known_answers() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

fn probe_world(vault: &str) -> World {
    let mut w = vault_world(vault);
    let source = v3_probe_source();
    // recompile both vaults from the probe source
    w.asset_vault = Compiled::new(&source, &w.terms.ctor(ASSET_LEG));
    if w.mode.cash != CASH_EXTERNAL {
        w.cash_vault = Some(Compiled::new(&source, &w.terms.ctor(CASH_LEG)));
    }
    w
}

fn journal_of(w: &World) -> Vec<u8> {
    v3_journal(
        &w.terms.zk.unwrap().list_root,
        &spk_bytes(&w.asset_vault.p2sh()),
        w.terms.buyer_delivery,
    )
}

fn try_witness(vault: &str, witness: impl FnOnce(&World) -> Vec<u8>) -> Run {
    let w = probe_world(vault);
    let proof = witness(&w);
    let w = w.with_proof(proof);
    // the probe has no proof gate to pass, so the rest of the settle must be accepted
    w.settle().run(&w, 0)
}

#[test]
fn v3_journal_accepted_for_pubkey_and_script_hash_owners() {
    for vault in [
        "asset_list1000",
        "asset_list1000_p2sh",
        "asset_list1000_swap",
    ] {
        let run = try_witness(vault, |w| sha256(&journal_of(w)).to_vec());
        assert_accepted(&run, &format!("journal of {vault}"));
    }
}

#[test]
fn v3_journal_every_field_is_bound() {
    for (label, edit) in [
        ("tag", 0usize),
        ("root", 20),
        ("vault spk", 16 + 32 + 10),
        ("owner spk", 16 + 32 + 37 + 10),
    ] {
        let run = try_witness("asset_list1000", |w| {
            let mut j = journal_of(w);
            j[edit] ^= 1;
            sha256(&j).to_vec()
        });
        assert_refused(&run, &format!("journal with a flipped byte in {label}"));
    }
    // a journal without its owner, and one with a trailing byte
    for (label, cut) in [("owner missing", true), ("trailing byte", false)] {
        let run = try_witness("asset_list1000", |w| {
            let mut j = journal_of(w);
            if cut {
                j.truncate(16 + 32 + 37);
            } else {
                j.push(0);
            }
            sha256(&j).to_vec()
        });
        assert_refused(&run, label);
    }
}
