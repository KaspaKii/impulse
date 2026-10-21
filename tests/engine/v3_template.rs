// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v3 as a template (spec/V3-ZK.md 2, 6.1, 6.2). The committed artifact and
//! contracts/TEMPLATE_HASH_V3 are what the in-process compile of contracts/impulse_vault_v3.sil
//! gives; template v1 is untouched and a different template; every term, the list issuer key and
//! the list root, moves the address; IMAGE_ID in the source is circuits/IMAGE_ID. The same
//! artifact is checked against the pinned silverc binary by scripts/build-template-v3.sh.

mod harness;
mod v3_common;
use harness::*;
use silverscript_abi::ArtifactValue;
use v3_common::*;

fn committed_hash_v3() -> [u8; 32] {
    let text = std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH_V3")).expect("hash");
    let h = unhex(text.trim());
    assert_eq!(h.len(), 32, "TEMPLATE_HASH_V3 is 32 bytes of hex");
    h.try_into().unwrap()
}

fn committed_v3() -> Compiled {
    let ctor = std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v3.ctor.json"))
        .expect("ctor args");
    let ctor: Vec<ArtifactValue> = serde_json::from_str(&ctor).expect("constructor args JSON");
    Compiled::new(&vault_v3_source(), &ctor)
}

fn committed_v1() -> Compiled {
    let ctor = std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.ctor.json"))
        .expect("ctor args");
    let ctor: Vec<ArtifactValue> = serde_json::from_str(&ctor).expect("constructor args JSON");
    Compiled::new(&vault_source(), &ctor)
}

#[test]
fn v3_in_process_compile_reproduces_the_committed_artifact() {
    let vault = committed_v3();
    let json = silverscript_abi::to_pretty_json(&vault.artifact).expect("serialize");
    assert_eq!(
        json,
        std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v3.json")).unwrap(),
        "contracts/compiled/impulse_vault.v3.json is stale; run scripts/build-template-v3.sh --update"
    );
    assert_eq!(vault.name, "ImpulseVaultV3");
    assert_eq!(vault.template_hash(), committed_hash_v3());
    let (prefix, suffix) = vault.template_parts();
    assert_eq!(
        silverscript_lang::template::template_hash(prefix, suffix),
        committed_hash_v3()
    );
}

/// Template v3 is a different template from v1: another hash and another suffix, so the v1
/// decoder and verifier refuse a v3 script (spec 2). Template v1 is still what its pin says.
#[test]
fn v3_is_a_different_template_and_v1_is_unchanged() {
    let v1 = committed_v1();
    let v3 = committed_v3();
    let v1_pin = unhex(
        std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH"))
            .unwrap()
            .trim(),
    );
    assert_eq!(v1.template_hash().to_vec(), v1_pin, "v1 pin");
    assert_ne!(v1.template_hash(), v3.template_hash());
    assert_ne!(v1.template_parts().1, v3.template_parts().1, "suffix");
    // docs/evidence/template-fix-I26/s10-units.txt
    assert_eq!(v1.bytecode().len(), 3946, "v1 size");
}

#[test]
fn v3_size_is_recorded() {
    let v3 = committed_v3();
    let (prefix, suffix) = v3.template_lens();
    eprintln!(
        "template v3: {} bytes, prefix {prefix}, suffix {suffix}, state {}",
        v3.bytecode().len(),
        v3.bytecode().len() - prefix - suffix
    );
    // docs/evidence/template-fix-I26/s10-units.txt
    assert_eq!(v3.bytecode().len(), 4931);
}

#[test]
fn v3_image_id_in_the_source_is_the_circuits_image_id() {
    let id = std::fs::read_to_string(repo_path("circuits/IMAGE_ID")).unwrap();
    let id = id.trim();
    assert_eq!(id.len(), 64);
    assert!(
        vault_v3_source().contains(&format!("IMAGE_ID = byte[32](0x{id});")),
        "IMAGE_ID in contracts/impulse_vault_v3.sil differs from circuits/IMAGE_ID"
    );
    assert!(
        vault_v3_source().contains("JOURNAL_TAG = byte[16](0x496d70756c73652f7a6b2f776c2f7631);")
    );
}

#[test]
fn v3_every_vault_runs_the_committed_template() {
    let reference = committed_v3();
    let (prefix, suffix) = reference.template_parts();
    for name in VAULTS {
        let w = vault_world(name);
        for v in [Some(&w.asset_vault), w.cash_vault.as_ref()]
            .into_iter()
            .flatten()
        {
            assert_eq!(v.template_hash(), committed_hash_v3(), "{name}");
            assert_eq!(v.template_parts(), (prefix, suffix), "{name}");
        }
    }
}

type Edit = Box<dyn Fn(&mut Terms)>;

/// Every term, the list issuer key and the list root included, is in the script (V3-ZK.md 6.2).
#[test]
fn v3_every_term_and_the_leg_index_change_the_vault_address() {
    let w = vault_world("asset_list1000_auth");
    let mut base = w.terms.clone();
    base.seller_proceeds_spk = spk_bytes(&seller_proceeds_kas_spk());
    base.buyer_refund_spk = spk_bytes(&buyer_refund_kas_spk());
    let address = |t: &Terms, leg| t.vault(leg).script_hash();
    let reference = address(&base, ASSET_LEG);
    assert_ne!(reference, address(&base, CASH_LEG), "legIndex");
    let edits: Vec<(&str, Edit)> = vec![
        ("version", Box::new(|t| t.version ^= 1)),
        ("network", Box::new(|t| t.network ^= 1)),
        ("nonce", Box::new(|t| t.nonce[7] ^= 1)),
        ("seller_key", Box::new(|t| t.seller_key[31] ^= 1)),
        ("buyer_key", Box::new(|t| t.buyer_key[31] ^= 1)),
        ("has_authority", Box::new(|t| t.has_authority ^= true)),
        ("authority_key", Box::new(|t| t.authority_key[31] ^= 1)),
        ("asset covenant", Box::new(|t| t.asset.cov = DECOY_COV)),
        ("asset template hash", Box::new(|t| t.asset.hash[0] ^= 1)),
        ("asset prefix len", Box::new(|t| t.asset.prefix_len += 1)),
        ("asset suffix len", Box::new(|t| t.asset.suffix_len += 1)),
        ("amount_a", Box::new(|t| t.amount_a += 1)),
        ("cash kind", Box::new(|t| t.cash_kind = CASH_KCC20)),
        ("cash covenant", Box::new(|t| t.cash.cov = DECOY_COV)),
        ("cash template hash", Box::new(|t| t.cash.hash[0] ^= 1)),
        ("cash prefix len", Box::new(|t| t.cash.prefix_len += 1)),
        ("cash suffix len", Box::new(|t| t.cash.suffix_len += 1)),
        ("amount_b", Box::new(|t| t.amount_b += 1)),
        (
            "buyer_delivery type",
            Box::new(|t| t.buyer_delivery.id_type ^= 1),
        ),
        (
            "buyer_delivery id",
            Box::new(|t| t.buyer_delivery.id[0] ^= 1),
        ),
        (
            "seller_proceeds type",
            Box::new(|t| t.seller_proceeds.id_type ^= 1),
        ),
        (
            "seller_proceeds id",
            Box::new(|t| t.seller_proceeds.id[0] ^= 1),
        ),
        (
            "seller_proceeds spk",
            Box::new(|t| t.seller_proceeds_spk[3] ^= 1),
        ),
        (
            "seller_refund type",
            Box::new(|t| t.seller_refund.id_type ^= 1),
        ),
        ("seller_refund id", Box::new(|t| t.seller_refund.id[0] ^= 1)),
        (
            "buyer_refund type",
            Box::new(|t| t.buyer_refund.id_type ^= 1),
        ),
        ("buyer_refund id", Box::new(|t| t.buyer_refund.id[0] ^= 1)),
        ("buyer_refund spk", Box::new(|t| t.buyer_refund_spk[3] ^= 1)),
        ("has_earliest", Box::new(|t| t.has_earliest ^= true)),
        ("earliest_daa", Box::new(|t| t.earliest_daa += 1)),
        ("expiry_daa", Box::new(|t| t.expiry_daa += 1)),
        ("funding_mode", Box::new(|t| t.funding_mode ^= 1)),
        (
            "list_issuer_key",
            Box::new(|t| t.zk.as_mut().unwrap().issuer_key[0] ^= 1),
        ),
        (
            "list_root",
            Box::new(|t| t.zk.as_mut().unwrap().list_root[0] ^= 1),
        ),
        ("trade_ref", Box::new(|t| t.trade_ref[0] ^= 1)),
    ];
    assert_eq!(
        edits.len() + 1,
        base.ctor(ASSET_LEG).len(),
        "one edit per constructor field"
    );
    for (name, edit) in edits {
        let mut t = base.clone();
        edit(&mut t);
        assert_ne!(
            address(&t, ASSET_LEG),
            reference,
            "{name} must change the address"
        );
    }
}
