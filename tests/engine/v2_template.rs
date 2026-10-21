// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v2 (spec/V2.md 4.1, 4.2): the engine tests run the committed v2 template. Every v2
//! vault the other test targets compile (in process, with the same library call silverc makes)
//! has the template hash in contracts/TEMPLATE_HASH_V2 and the prefix and suffix bytes of the
//! committed artifact, whatever its leg count and leg index; the layout constants the contract
//! carries for [S10] are the compiled layout; and every state field moves the address.
//! scripts/build-template-v2.sh checks the same artifact against the pinned silverc binary.

mod harness;
mod v2_harness;
use harness::*;
use silverscript_abi::ArtifactValue;
use v2_harness::*;

fn read_hash(path: &str) -> [u8; 32] {
    let text = std::fs::read_to_string(repo_path(path)).expect(path);
    let hex = text.trim();
    assert_eq!(hex.len(), 64, "{path} is 32 bytes of hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn committed_hash() -> [u8; 32] {
    read_hash("contracts/TEMPLATE_HASH_V2")
}

/// The committed v2 vault, compiled from the committed constructor args parsed as silverc parses them.
fn committed_vault() -> Compiled {
    let ctor = std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v2.ctor.json"))
        .expect("ctor args");
    let ctor: Vec<ArtifactValue> = serde_json::from_str(&ctor).expect("constructor args JSON");
    Compiled::new(&vault_v2_source(), &ctor)
}

#[test]
fn in_process_compile_reproduces_the_committed_v2_artifact() {
    let vault = committed_vault();
    let json = silverscript_abi::to_pretty_json(&vault.artifact).expect("serialize");
    assert_eq!(
        json,
        std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v2.json"))
            .expect("artifact"),
        "contracts/compiled/impulse_vault.v2.json is stale; run scripts/build-template-v2.sh --update in an increment that changes the v2 contract"
    );
    assert_eq!(vault.name, "ImpulseVaultV2");
    assert_eq!(vault.template_hash(), committed_hash());
    let (prefix, suffix) = vault.template_parts();
    assert_eq!(
        silverscript_lang::template::template_hash(prefix, suffix),
        committed_hash(),
        "TEMPLATE_HASH_V2 is the silverscript template hash of prefix and suffix"
    );
}

/// v1 stays valid alongside v2: the two pinned hashes differ, and the v1 artifact is still the
/// ImpulseVault one (template.rs checks it byte for byte against contracts/TEMPLATE_HASH).
#[test]
fn v1_and_v2_template_hashes_are_distinct() {
    assert_ne!(read_hash("contracts/TEMPLATE_HASH"), committed_hash());
    let v1 = std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.json"))
        .expect("v1 artifact");
    assert!(v1.contains("\"ImpulseVault\""));
}

/// [S10] rebuilds a sibling's redeem script from the template layout the source declares; the
/// constants must be the compiled layout, for every leg count.
#[test]
fn suffix_constant_is_the_template_suffix() {
    let source = vault_v2_source();
    let reference = committed_vault();
    let (prefix_len, suffix_len) = reference.template_lens();
    assert_eq!(prefix_len, PREFIX_LEN);
    assert_eq!(suffix_constant(&source), suffix_len, "SUFFIX_LEN");
    for n in [2usize, 3, 10] {
        let w = WorldV2::new(Setup::bilateral(n, true));
        let code = w.vaults[0].bytecode();
        assert_eq!(
            code.len(),
            PREFIX_LEN + STATE_FIXED + n * LEG_RECORD + suffix_len,
            "redeem length at N = {n}"
        );
        // legIndex is the last state field: an 8-byte push just before the suffix.
        let at = code.len() - suffix_len - 8;
        assert_eq!(code[at - 1], 0x08, "legIndex is an 8-byte push");
        assert_eq!(&code[at..at + 8], &0i64.to_le_bytes());
        assert_eq!(&w.vaults[1].bytecode()[at..at + 8], &1i64.to_le_bytes());
        assert_eq!(&code[..at], &w.vaults[1].bytecode()[..at]);
        assert_eq!(&code[at + 8..], &w.vaults[1].bytecode()[at + 8..]);
    }
}

/// The template does not depend on the terms, the leg count or the leg index.
#[test]
fn every_test_vault_runs_the_committed_template() {
    let reference = committed_vault();
    let (prefix, suffix) = reference.template_parts();
    let setups = [
        Setup::v1_kas_cash(true),
        Setup::v1_kcc20_cash(false),
        Setup::ring(3, true),
        Setup::three_with_kas(false).earmarked(),
        Setup::bilateral(10, true).partial(2, 1),
    ];
    for setup in setups {
        let w = WorldV2::new(setup);
        for v in &w.vaults {
            assert_eq!(v.template_hash(), committed_hash());
            assert_eq!(v.template_parts(), (prefix, suffix));
        }
    }
}

type Edit = Box<dyn Fn(&mut TermsV2)>;

/// Every state field and every field of a leg record is in the script, so each moves the
/// address (spec/V2.md 4.2: the address commits to every term).
#[test]
fn every_state_field_and_the_leg_index_change_the_vault_address() {
    let w = WorldV2::new(Setup::three_with_kas(true).partial(2, 1));
    let base = w.terms.clone();
    let address = |t: &TermsV2, leg| t.vault(leg).script_hash();
    let reference = address(&base, 0);
    assert_ne!(reference, address(&base, 1), "legIndex");
    let edits: Vec<(&str, Edit)> = vec![
        ("version", Box::new(|t| t.version ^= 1)),
        ("network", Box::new(|t| t.network ^= 1)),
        ("nonce", Box::new(|t| t.nonce[7] ^= 1)),
        ("has_authority", Box::new(|t| t.has_authority ^= true)),
        ("authority_key", Box::new(|t| t.authority_key[31] ^= 1)),
        ("leg_count", Box::new(|t| t.leg_count += 1)),
        ("legs", Box::new(|t| t.legs[2].refund.id[0] ^= 1)),
        ("has_earliest", Box::new(|t| t.has_earliest ^= true)),
        ("earliest_daa", Box::new(|t| t.earliest_daa += 1)),
        ("expiry_daa", Box::new(|t| t.expiry_daa += 1)),
        ("funding_mode", Box::new(|t| t.funding_mode ^= 1)),
        ("trade_ref", Box::new(|t| t.trade_ref[0] ^= 1)),
        ("lot_count", Box::new(|t| t.lot_count += 1)),
        ("min_lot", Box::new(|t| t.min_lot += 1)),
    ];
    assert_eq!(
        edits.len() + 1,
        base.ctor(0).len(),
        "one edit per constructor field"
    );
    for (name, edit) in edits {
        let mut t = base.clone();
        edit(&mut t);
        assert_ne!(address(&t, 0), reference, "{name} must change the address");
    }
    let record_edits: Vec<(&str, Edit)> = vec![
        ("depositor", Box::new(|t| t.legs[0].depositor[0] ^= 1)),
        ("kind", Box::new(|t| t.legs[0].kind ^= 1)),
        (
            "covenant",
            Box::new(|t| t.legs[0].tmpl.cov = DECOY_TOKEN_COV),
        ),
        ("template hash", Box::new(|t| t.legs[0].tmpl.hash[0] ^= 1)),
        ("prefix len", Box::new(|t| t.legs[0].tmpl.prefix_len += 1)),
        ("suffix len", Box::new(|t| t.legs[0].tmpl.suffix_len += 1)),
        ("amount", Box::new(|t| t.legs[0].amount_bytes[0] ^= 1)),
        (
            "delivery type",
            Box::new(|t| t.legs[0].delivery.id_type ^= 1),
        ),
        ("delivery id", Box::new(|t| t.legs[0].delivery.id[0] ^= 1)),
        ("refund type", Box::new(|t| t.legs[0].refund.id_type ^= 1)),
        ("refund id", Box::new(|t| t.legs[0].refund.id[0] ^= 1)),
    ];
    for (name, edit) in record_edits {
        let mut t = base.clone();
        edit(&mut t);
        assert_ne!(
            address(&t, 0),
            reference,
            "leg record {name} must change the address"
        );
    }
}
