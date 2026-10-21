// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The engine tests run the committed template. Every vault the other test targets compile
//! (in process, with the same library call silverc makes) must have the template hash in
//! contracts/TEMPLATE_HASH and the exact prefix and suffix bytes of the committed artifact.
//! scripts/build-template.sh checks the same artifact against the pinned silverc binary.

mod harness;
use harness::*;
use silverscript_abi::ArtifactValue;

fn committed_hash() -> [u8; 32] {
    let text =
        std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH")).expect("TEMPLATE_HASH");
    let hex = text.trim();
    assert_eq!(hex.len(), 64, "TEMPLATE_HASH is 32 bytes of hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn committed_artifact_json() -> String {
    std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.json"))
        .expect("artifact")
}

/// The committed vault, compiled from the committed constructor args parsed as silverc parses them.
fn committed_vault() -> Compiled {
    let ctor = std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.ctor.json"))
        .expect("ctor args");
    let ctor: Vec<ArtifactValue> = serde_json::from_str(&ctor).expect("constructor args JSON");
    Compiled::new(&vault_source(), &ctor)
}

#[test]
fn in_process_compile_reproduces_the_committed_artifact() {
    let vault = committed_vault();
    let json = silverscript_abi::to_pretty_json(&vault.artifact).expect("serialize");
    assert_eq!(
        json,
        committed_artifact_json(),
        "contracts/compiled/impulse_vault.v1.json is stale; run scripts/build-template.sh --update in an increment that changes the contract"
    );
    assert_eq!(vault.name, "ImpulseVault");
    assert_eq!(vault.template_hash(), committed_hash());
    let (prefix, suffix) = vault.template_parts();
    assert_eq!(
        silverscript_lang::template::template_hash(prefix, suffix),
        committed_hash(),
        "TEMPLATE_HASH is the silverscript template hash of prefix and suffix"
    );
}

#[test]
fn every_test_vault_runs_the_committed_template() {
    let reference = committed_vault();
    let (prefix, suffix) = reference.template_parts();
    for authority in [true, false] {
        for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
            for funding in [REVOCABLE, EARMARKED] {
                let w = World::new(Mode::new(authority, cash, funding));
                let mut vaults = vec![w.asset_vault.clone(), w.terms.vault(CASH_LEG)];
                vaults.extend(w.cash_vault.clone());
                for v in &vaults {
                    assert_eq!(v.template_hash(), committed_hash());
                    assert_eq!(v.template_parts(), (prefix, suffix));
                }
            }
        }
    }
}

type Edit = Box<dyn Fn(&mut Terms)>;

/// Every term is in the script, so every term moves the address (spec: terms are the address).
#[test]
fn every_term_and_the_leg_index_change_the_vault_address() {
    let w = World::new(Mode::new(true, CASH_KAS, EARMARKED));
    let base = w.terms.clone();
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
