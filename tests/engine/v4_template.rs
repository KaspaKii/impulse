// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v4 as a template (spec/V3-ZK.md 22.2, 22.5). The committed artifact and
//! contracts/TEMPLATE_HASH_V4 are what the in-process compile of contracts/impulse_vault_v4.sil
//! gives; v1 and v3 are untouched and different templates; the commitment and the authority key
//! move the address, and so does the leg; IMAGE_ID in the source is circuits/IMAGE_ID_V4. The
//! same artifact is checked against the pinned silverc binary by scripts/build-template-v4.sh.

mod harness;
mod v4_common;
use harness::*;
use silverscript_abi::ArtifactValue;
use v4_common::*;

fn committed_hash_v4() -> [u8; 32] {
    let text = std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH_V4")).expect("hash");
    let h = unhex(text.trim());
    assert_eq!(h.len(), 32, "TEMPLATE_HASH_V4 is 32 bytes of hex");
    h.try_into().unwrap()
}

fn compiled_from(source: &str, ctor_file: &str) -> Compiled {
    let ctor = std::fs::read_to_string(repo_path(ctor_file)).expect("ctor args");
    let ctor: Vec<ArtifactValue> = serde_json::from_str(&ctor).expect("constructor args JSON");
    Compiled::new(source, &ctor)
}

fn committed_v4() -> Compiled {
    compiled_from(
        &vault_v4_source(),
        "contracts/compiled/impulse_vault.v4.ctor.json",
    )
}

#[test]
fn v4_in_process_compile_reproduces_the_committed_artifact() {
    let vault = committed_v4();
    let json = silverscript_abi::to_pretty_json(&vault.artifact).expect("serialize");
    assert_eq!(
        json,
        std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v4.json")).unwrap(),
        "contracts/compiled/impulse_vault.v4.json is stale; run scripts/build-template-v4.sh --update"
    );
    assert_eq!(vault.name, "ImpulseVaultV4");
    assert_eq!(vault.template_hash(), committed_hash_v4());
    let (prefix, suffix) = vault.template_parts();
    assert_eq!(
        silverscript_lang::template::template_hash(prefix, suffix),
        committed_hash_v4()
    );
}

/// Template v4 is a different template from v1 and v3 (another hash and another suffix), so the
/// v1 and v3 decoders and verifiers refuse a v4 script. Templates v1 and v3 are still what their
/// pins say.
#[test]
fn v4_is_a_different_template_and_v1_v3_are_unchanged() {
    let v1 = compiled_from(
        &vault_source(),
        "contracts/compiled/impulse_vault.v1.ctor.json",
    );
    let v3 = compiled_from(
        &vault_v3_source(),
        "contracts/compiled/impulse_vault.v3.ctor.json",
    );
    let v4 = committed_v4();
    let pin = |f: &str| unhex(std::fs::read_to_string(repo_path(f)).unwrap().trim());
    assert_eq!(
        v1.template_hash().to_vec(),
        pin("contracts/TEMPLATE_HASH"),
        "v1 pin"
    );
    assert_eq!(
        v3.template_hash().to_vec(),
        pin("contracts/TEMPLATE_HASH_V3"),
        "v3 pin"
    );
    assert_ne!(v4.template_hash(), v1.template_hash());
    assert_ne!(v4.template_hash(), v3.template_hash());
    assert_ne!(
        v4.template_parts().1,
        v1.template_parts().1,
        "suffix against v1"
    );
    assert_ne!(
        v4.template_parts().1,
        v3.template_parts().1,
        "suffix against v3"
    );
    // docs/evidence/template-fix-I26/s10-units.txt
    assert_eq!(v1.bytecode().len(), 3946, "v1 size");
    assert_eq!(v3.bytecode().len(), 4931, "v3 size");
}

#[test]
fn v4_size_is_recorded() {
    let v4 = committed_v4();
    let (prefix, suffix) = v4.template_lens();
    eprintln!(
        "template v4: {} bytes, prefix {prefix}, suffix {suffix}, state {}",
        v4.bytecode().len(),
        v4.bytecode().len() - prefix - suffix
    );
    // spec/V3-ZK.md 22.15
    assert_eq!(v4.bytecode().len(), 3598);
}

#[test]
fn v4_image_id_in_the_source_is_the_circuits_image_id_v4() {
    let id = std::fs::read_to_string(repo_path("circuits/IMAGE_ID_V4")).unwrap();
    let id = id.trim();
    assert_eq!(id.len(), 64);
    let list_id = std::fs::read_to_string(repo_path("circuits/IMAGE_ID")).unwrap();
    assert_ne!(
        id,
        list_id.trim(),
        "the terms guest and the list guest are different guests"
    );
    assert!(
        vault_v4_source().contains(&format!("IMAGE_ID = byte[32](0x{id});")),
        "IMAGE_ID in contracts/impulse_vault_v4.sil differs from circuits/IMAGE_ID_V4"
    );
    // the journal tag of 22.3 and the two mode bytes
    assert!(
        vault_v4_source().contains("JOURNAL_TAG = byte[16](0x496d70756c73652f7a6b2f68742f7631);")
    );
    assert!(vault_v4_source().contains("MODE_SETTLE = byte[1](0x01);"));
    assert!(vault_v4_source().contains("MODE_REFUND = byte[1](0x02);"));
}

/// Every vault of every world runs the committed template: only the state differs.
#[test]
fn v4_every_vault_runs_the_committed_template() {
    let reference = committed_v4();
    let (prefix, suffix) = reference.template_parts();
    for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
        let v = V4::fixed(Kind::Real, cash, REVOCABLE, 1);
        for vault in [Some(&v.asset), v.cash.as_ref()].into_iter().flatten() {
            assert_eq!(
                vault.template_hash(),
                committed_hash_v4(),
                "cash kind {cash}"
            );
            assert_eq!(vault.template_parts(), (prefix, suffix), "cash kind {cash}");
        }
    }
}

/// The state is two fields (22.2): the commitment and the authority key. Each moves the address,
/// and the two legs of one trade have different addresses because the leg is in the commitment.
#[test]
fn v4_commitment_authority_and_leg_change_the_vault_address() {
    let v = V4::fixed(Kind::Real, CASH_KAS, REVOCABLE, 1);
    let a0 = compile_vault(Kind::Real, v.commit(0), v.authority());
    assert_eq!(a0.script_hash(), v.asset.script_hash());
    let a1 = compile_vault(Kind::Real, v.commit(1), v.authority());
    assert_ne!(a0.script_hash(), a1.script_hash(), "leg");
    assert_eq!(a1.script_hash(), v.cash.as_ref().unwrap().script_hash());
    let mut c = v.commit(0);
    c[31] ^= 1;
    assert_ne!(
        compile_vault(Kind::Real, c, v.authority()).script_hash(),
        a0.script_hash(),
        "commitment"
    );
    let mut k = v.authority();
    k[31] ^= 1;
    assert_ne!(
        compile_vault(Kind::Real, v.commit(0), k).script_hash(),
        a0.script_hash(),
        "authority key"
    );
    // a sibling trade (another nonce) has other vaults
    let sibling = V4::fixed(Kind::Real, CASH_KAS, REVOCABLE, 2);
    assert_ne!(sibling.asset.script_hash(), v.asset.script_hash());
}

/// The terms guest reads this vault's state at a fixed place of its redeem script to build the
/// other leg's vault (`[H5]`, spec/V3-ZK.md 22.16): one byte of prefix, then `0x20 || commit ||
/// 0x20 || authority`. The compiled template must put it there, and a vault of the harness holds
/// its commitment and the authority key at those bytes.
#[test]
fn v4_template_state_span_is_the_guests() {
    use terms_core::statement::{VAULT_STATE_LEN, VAULT_STATE_OFFSET};
    let vault = committed_v4();
    let (prefix, suffix) = vault.template_lens();
    assert_eq!(prefix, VAULT_STATE_OFFSET, "template v4 prefix length");
    assert_eq!(
        vault.bytecode().len() - prefix - suffix,
        VAULT_STATE_LEN,
        "template v4 state length"
    );
    for kind in [Kind::Probe, Kind::Real] {
        let v = V4::live(kind, CASH_KCC20, REVOCABLE);
        for (leg, compiled) in [(0u8, &v.w.asset_vault), (1, v.w.cash_vault())] {
            let r = compiled.bytecode();
            let at = VAULT_STATE_OFFSET;
            assert_eq!(r[at], 0x20);
            assert_eq!(r[at + 1..at + 33], v.commit(leg));
            assert_eq!(r[at + 33], 0x20);
            assert_eq!(r[at + 34..at + 66], v.authority());
        }
    }
}
