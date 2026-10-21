// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Shared by the v3_* test targets (spec/V3-ZK.md section 13): the fixed fixture worlds whose
//! vault scriptPubKeys the committed proof fixtures are bound to, and loaders for the fixtures.
//!
//! A proof is bound to its vault's scriptPubKey, which commits to every term, so the terms of a
//! fixture world are fixed. They use fixed PUBLIC keys only: seller, buyer and issuer keys are
//! 32 bytes no signature ever uses, and the authority key is the x coordinate of the public
//! point 3G. No private key exists for any of them in this repository (rule 1, docs/ENGINEERING-RULES.md), so
//! a fixture world with an authority cannot produce a valid authority signature: its settle is
//! refused at [S6], after the proof gate, which is exactly what the [S6] test needs.

#![allow(dead_code)]

use crate::harness::*;
use std::path::PathBuf;

pub const SELLER_KEY: [u8; 32] = [0x5A; 32];
pub const BUYER_KEY: [u8; 32] = [0xBA; 32];
pub const ISSUER_KEY: [u8; 32] = [0x15; 32];
/// x coordinate of the public point 3G.
pub const AUTHORITY_KEY: [u8; 32] = [
    0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
    0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9,
];

/// Script units the verification alone costs at least: the Groth16 precompile's fixed cost
/// (14,000,000, V3-ZK.md 3.1). A run that used fewer was refused before the proof gate.
pub const GATE_FLOOR_UNITS: u64 = 14_000_000;

pub fn proof_dir() -> PathBuf {
    repo_path("tests/engine/fixtures/v3/proofs")
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn read_json(file: &str) -> serde_json::Value {
    let path = proof_dir().join(file);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    unhex(v.as_str().expect("hex string"))
        .try_into()
        .expect("32 bytes")
}

/// One committed proof fixture: the 128 proof bytes and the J it was made for.
pub struct Fixture {
    pub name: String,
    pub proof: Vec<u8>,
    pub journal: Vec<u8>,
    pub root: [u8; 32],
    pub owner_spk: Vec<u8>,
    pub vault: String,
    pub vault_spk: Vec<u8>,
    pub image_id: [u8; 32],
}

pub fn fixture(name: &str) -> Fixture {
    let inputs = read_json(&format!("{name}.inputs.json"));
    let proof = read_json(&format!("{name}.proof.json"));
    Fixture {
        name: name.to_string(),
        proof: unhex(proof["proof"].as_str().expect("proof")),
        journal: unhex(inputs["journal"].as_str().expect("journal")),
        root: hex32(&inputs["root"]),
        owner_spk: unhex(inputs["owner_spk"].as_str().expect("owner")),
        vault: inputs["vault"].as_str().expect("vault").to_string(),
        vault_spk: unhex(inputs["vault_spk"].as_str().expect("vault spk")),
        image_id: hex32(&proof["image_id"]),
    }
}

/// The delivery owner a fixture's owner scriptPubKey names (36-byte P2PK or 37-byte P2SH).
pub fn owner_of(spk: &[u8]) -> Owner {
    match spk.len() {
        36 => Owner::pubkey(spk[3..35].try_into().expect("32")),
        37 => Owner::script_hash(spk[4..36].try_into().expect("32")),
        n => panic!("owner scriptPubKey of {n} bytes"),
    }
}

/// The names of the fixture vaults, in the order of vaults.json.
pub const VAULTS: [&str; 8] = [
    "asset_list1",
    "asset_list1000",
    "asset_list1000_p2sh",
    "asset_list1000_b",
    "cash_list1000",
    "asset_list1000_kcc20",
    "asset_list1000_auth",
    "asset_list1000_swap",
];

/// The fixed world of a fixture vault, no proof attached. `cash_list1000` is the cash vault
/// (leg 1) of the world `asset_list1000`.
pub fn vault_world(vault: &str) -> World {
    // root and delivery owner come from the committed deterministic inputs of a fixture that
    // is bound to this vault's list and owner
    let (list_of, mode, nonce, delivery) = match vault {
        "asset_list1" => ("a_list1", Mode::new(false, CASH_KAS, REVOCABLE), 0x4E, None),
        "asset_list1000" | "cash_list1000" => (
            "a_list1000",
            Mode::new(false, CASH_KAS, REVOCABLE),
            0x4E,
            None,
        ),
        "asset_list1000_p2sh" => (
            "c_list1000_p2sh",
            Mode::new(false, CASH_KAS, REVOCABLE),
            0x4E,
            None,
        ),
        "asset_list1000_b" => (
            "a_list1000",
            Mode::new(false, CASH_KAS, REVOCABLE),
            0x4F,
            None,
        ),
        "asset_list1000_kcc20" => (
            "a_list1000",
            Mode::new(false, CASH_KCC20, REVOCABLE),
            0x4E,
            None,
        ),
        "asset_list1000_auth" => (
            "a_list1000",
            Mode::new(true, CASH_KAS, REVOCABLE),
            0x4E,
            None,
        ),
        // The same bytes as owner A, but named as a script hash: the owner type swap.
        "asset_list1000_swap" => (
            "a_list1000",
            Mode::new(false, CASH_KAS, REVOCABLE),
            0x4E,
            Some(IDENTIFIER_SCRIPT_HASH),
        ),
        other => panic!("unknown fixture vault {other}"),
    };
    let f = fixture(list_of);
    let mut owner = owner_of(&f.owner_spk);
    if let Some(t) = delivery {
        owner = Owner {
            id_type: t,
            id: owner.id,
        };
    }
    World::with(mode, |terms, _| {
        terms.version = 3;
        terms.nonce = [nonce; 8];
        terms.seller_key = SELLER_KEY;
        terms.buyer_key = BUYER_KEY;
        if terms.has_authority {
            terms.authority_key = AUTHORITY_KEY;
        }
        terms.buyer_delivery = owner;
        terms.zk = Some(ZkTerms {
            issuer_key: ISSUER_KEY,
            list_root: f.root,
        });
    })
}

/// A world's vault scriptPubKey as the journal carries it: version, then the P2SH script.
pub fn vault_spk_of(world: &World, vault: &str) -> Vec<u8> {
    let c = if vault.starts_with("cash_") {
        world.cash_vault()
    } else {
        &world.asset_vault
    };
    spk_bytes(&c.p2sh())
}

/// The world of fixture `name`: its vault's fixed world, carrying the fixture's proof.
pub fn world_for(name: &str) -> World {
    let f = fixture(name);
    // the cash vault fixture is the proof for the cash vault; the asset vault of that trade
    // is the world it is tried at
    let vault = if f.vault.starts_with("cash_") {
        f.vault.replace("cash_", "asset_")
    } else {
        f.vault.clone()
    };
    vault_world(&vault).with_proof(f.proof)
}

use kaspa_txscript_errors::TxScriptError;

/// The proof gate refused: the precompile failed (ZkIntegrity), after its fixed cost was charged.
pub fn assert_gate_refused(run: &Run, label: &str) {
    assert!(
        matches!(run.result, Err(TxScriptError::ZkIntegrity(_))),
        "{label}: expected a ZkIntegrity refusal from the precompile, got {:?}",
        run.result
    );
    assert!(
        run.used.0 >= GATE_FLOOR_UNITS,
        "{label}: the precompile's cost was not charged ({} units)",
        run.used.0
    );
}

/// A script refusal (VerifyError or EvalFalse) that came before the proof gate: fewer script
/// units than the precompile's fixed cost were used, so the verification never ran.
pub fn assert_refused_before_gate(run: &Run, label: &str) {
    assert_refused(run, label);
    assert!(
        run.used.0 < GATE_FLOOR_UNITS,
        "{label}: refused after the gate ({} units)",
        run.used.0
    );
}

/// The run got past the proof gate (the precompile accepted) and was refused by a later check.
pub fn assert_refused_after_gate(run: &Run, label: &str) {
    assert!(run.result.is_err(), "{label}: expected a refusal");
    assert!(
        !matches!(run.result, Err(TxScriptError::ZkIntegrity(_))),
        "{label}: the gate refused: {:?}",
        run.result
    );
    assert!(
        run.used.0 >= GATE_FLOOR_UNITS,
        "{label}: refused before the gate ({} units): {:?}",
        run.used.0,
        run.result
    );
}

/// The asset vault's settle (input 0) of `world`, its proof replaced by `proof`.
pub fn settle_with(world: &World, proof: Vec<u8>) -> Run {
    let mut spec = world.settle();
    spec.inputs[0] = In::settle_v3(&world.asset_vault, None, AUTH_VALUE, proof);
    spec.run(world, 0)
}
