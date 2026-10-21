// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The fixture vaults (spec/V3-ZK.md 13.1): the scriptPubKey of every fixed fixture world is
//! the one `vaults.json` holds and every committed proof fixture is bound to, and each
//! fixture's journal is the journal the vault computes from its own terms.
//!
//! To bind the fixtures to the current template v3, write the map and prove again:
//!   IMPULSE_V3_WRITE_VAULTS=tests/engine/fixtures/v3/proofs/vaults.json \
//!     cargo test -p impulse-engine-tests --test v3_vaults -- v3_fixture_vault_map
//!   circuits/scripts/regen-fixtures.sh --vaults tests/engine/fixtures/v3/proofs/vaults.json

mod harness;
mod v3_common;
use harness::*;
use v3_common::*;

fn computed_map() -> std::collections::BTreeMap<String, String> {
    VAULTS
        .iter()
        .map(|name| {
            let spk = if *name == "cash_list1000" {
                spk_bytes(&vault_world("asset_list1000").cash_vault().p2sh())
            } else {
                spk_bytes(&vault_world(name).asset_vault.p2sh())
            };
            (name.to_string(), hex(&spk))
        })
        .collect()
}

#[test]
fn v3_fixture_vault_map() {
    let computed = computed_map();
    if let Some(path) = std::env::var_os("IMPULSE_V3_WRITE_VAULTS") {
        let text = serde_json::to_string_pretty(&computed).expect("json") + "\n";
        std::fs::write(&path, text).expect("write vault map");
        return;
    }
    let committed: std::collections::BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(proof_dir().join("vaults.json")).expect("vaults.json"),
    )
    .expect("parse vaults.json");
    assert_eq!(
        committed, computed,
        "vaults.json is not the vault map of template v3 as compiled now: regenerate it and the proofs"
    );
}

/// The journal a fixture was proved for equals J = tag || root || vault spk || owner spk of its
/// vault as the contract builds it (V3-ZK.md 5.2), and the fixture's vault scriptPubKey is the
/// real one, not a stand-in.
#[test]
fn v3_fixture_journal_matches_terms() {
    for name in [
        "a_list1",
        "a_list1000",
        "c_list1000_p2sh",
        "a_list1000_vault_b",
        "a_list1_at_vault1000",
        "b_list1000",
        "a_list1000_cash_vault",
        "a_list1000_kcc20",
        "a_list1000_auth",
        "a_list1000_swap",
    ] {
        let f = fixture(name);
        let inputs: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(proof_dir().join(format!("{name}.inputs.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            inputs["vault_spk_is_standin"],
            serde_json::Value::Bool(false),
            "{name}: the fixture is bound to a stand-in vault"
        );
        let vault_world_name = f.vault.replace("cash_", "asset_");
        let w = vault_world(&vault_world_name);
        assert_eq!(
            f.vault_spk,
            vault_spk_of(&w, &f.vault),
            "{name}: vault scriptPubKey"
        );
        let mut j = b"Impulse/zk/wl/v1".to_vec();
        j.extend_from_slice(&f.root);
        j.extend_from_slice(&f.vault_spk);
        j.extend_from_slice(&f.owner_spk);
        assert_eq!(f.journal, j, "{name}: journal");
        assert_eq!(f.image_id.len(), 32);
    }
}
