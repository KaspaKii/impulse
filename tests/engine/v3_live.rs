// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v3 `settle` with an authority, on the real template with a proof made at test time
//! (spec/V3-ZK.md 13.1; I20 review round 1, finding 2).
//!
//! A world with an authority needs an authority signature, and the committed fixtures hold public
//! keys only (v3_common.rs). So these tests generate the throwaway keys of the harness at run
//! time (rule 1, docs/ENGINEERING-RULES.md, owner exception of 2026-10-06: random, never committed, never printed,
//! erased on drop), build the vault from them, make the Groth16 proof for THAT vault with
//! `impulse-zk-prove` on this machine, and settle in the pinned engine. The proof and the path
//! file live in a temporary directory that is removed when the test ends.
//!
//! Ignored by default: each test makes one real proof (minutes, Docker, several GiB). Run by
//! `scripts/ci-zk.sh` with `--ignored --test-threads=1`, after `impulse-zk-prove` is built:
//!
//!   cargo test -p impulse-engine-tests --test v3_live -- --ignored --test-threads=1

mod harness;
mod v3_common;
use harness::*;
use kaspa_txscript_errors::TxScriptError;
use std::path::PathBuf;
use std::process::Command;
use v3_common::*;

/// A removable temporary directory (removed on drop, also when the test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("impulse-v3-live-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The world of fixture list `a_list1000` (owner A, KAS or external cash) with an authority
/// whose key is generated now.
fn live_world(cash: u8) -> World {
    let f = fixture("a_list1000");
    World::with(Mode::new(true, cash, REVOCABLE), |terms, _| {
        terms.version = 3;
        terms.seller_key = SELLER_KEY;
        terms.buyer_key = BUYER_KEY;
        terms.buyer_delivery = owner_of(&f.owner_spk);
        terms.zk = Some(ZkTerms {
            issuer_key: ISSUER_KEY,
            list_root: f.root,
        });
        // terms.authority_key stays the public key of the throwaway authority key
    })
}

/// Makes the real proof for `w`'s asset vault with `impulse-zk-prove`.
fn prove(w: &World, label: &str) -> Vec<u8> {
    let bin = repo_path("circuits/target/release/impulse-zk-prove");
    assert!(
        bin.is_file(),
        "build the prover first: (cd circuits && cargo build --release --locked -p impulse-zk-prover --bin impulse-zk-prove)"
    );
    let f = fixture("a_list1000");
    let inputs: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(proof_dir().join("a_list1000.inputs.json")).expect("inputs"),
    )
    .expect("inputs json");
    let tmp = TempDir::new(label);
    let path_file = tmp.0.join("path.json");
    std::fs::write(&path_file, inputs["path"].to_string()).expect("write path");
    let out_file = tmp.0.join("proof.json");
    let vault_spk = vault_spk_of(w, "asset_live");
    let status = Command::new(&bin)
        .arg("--path")
        .arg(&path_file)
        .args(["--root", &hex_of(&f.root)])
        .args(["--vault-spk", &hex_of(&vault_spk)])
        .args(["--owner-spk", &hex_of(&f.owner_spk)])
        .arg("--out")
        .arg(&out_file)
        .status()
        .expect("run impulse-zk-prove");
    assert!(status.success(), "impulse-zk-prove failed: {status}");
    let proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_file).expect("proof file"))
            .expect("proof json");
    // The proof's journal is the J the vault computes for itself.
    let j = v3_journal(&f.root, &vault_spk, w.terms.buyer_delivery);
    assert_eq!(
        unhex(proof["journal"].as_str().expect("journal")),
        j,
        "the receipt's journal is the J of this vault"
    );
    let bytes = unhex(proof["proof"].as_str().expect("proof"));
    assert_eq!(bytes.len(), 128);
    bytes
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// KAS cash with an authority: the real proof passes the gate, then the authority's signature
/// is checked ([S6]) and the settle is accepted; without the signature it is refused after the
/// gate.
#[test]
#[ignore = "makes a real Groth16 proof (minutes, Docker); run by scripts/ci-zk.sh"]
fn v3_live_authority_settle_kas_cash() {
    let w = live_world(CASH_KAS);
    assert!(w.terms.has_authority);
    let w = {
        let proof = prove(&w, "kas");
        w.with_proof(proof)
    };
    // accepted at every input: gate, [S6] with the authority's real signature, [S7], deliveries
    w.settle()
        .assert_all_accepted(&w, "authority, KAS cash, real proof");
    // [S6] after the gate: the valid proof passes the precompile, the missing signature fails
    let mut unsigned = w.settle();
    unsigned.inputs[0] = In::settle_v3(&w.asset_vault, None, AUTH_VALUE, w.proof.clone());
    let run = unsigned.run(&w, 0);
    assert_refused_after_gate(&run, "[S6] real proof, no signature");
    assert!(
        matches!(run.result, Err(TxScriptError::InvalidSigHashType(0))),
        "no signature: got {:?}",
        run.result
    );
    // a signature by a party that is not the authority is refused after the gate too
    let mut wrong = w.settle();
    wrong.inputs[0] = In::settle_v3(
        &w.asset_vault,
        Some(Role::Seller),
        AUTH_VALUE,
        w.proof.clone(),
    );
    assert_refused_after_gate(&wrong.run(&w, 0), "[S6] real proof, seller's signature");
    // a flipped proof bit is refused by the gate before the signature is looked at
    let mut bad = w.proof.clone();
    bad[7] ^= 1;
    let mut spec = w.settle();
    spec.inputs[0] = In::settle_v3(&w.asset_vault, Some(Role::Authority), AUTH_VALUE, bad);
    assert_gate_refused(&spec.run(&w, 0), "flipped proof bit, authority signed");
}

/// External cash (the cash leg settles off chain, no cash vault) needs an authority: [S7]'s
/// accepted twin, on the real template with a real proof.
#[test]
#[ignore = "makes a real Groth16 proof (minutes, Docker); run by scripts/ci-zk.sh"]
fn v3_live_authority_settle_external_cash() {
    let w = live_world(CASH_EXTERNAL);
    assert!(w.external() && w.terms.has_authority);
    let proof = prove(&w, "external");
    let w = w.with_proof(proof);
    w.settle()
        .assert_all_accepted(&w, "authority, external cash, real proof");
    let mut unsigned = w.settle();
    unsigned.inputs[0] = In::settle_v3(&w.asset_vault, None, AUTH_VALUE, w.proof.clone());
    assert_refused_after_gate(&unsigned.run(&w, 0), "[S6] external cash, no signature");
}
