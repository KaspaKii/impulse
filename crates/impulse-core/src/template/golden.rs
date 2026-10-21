// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden vault vectors (tests/vectors/vaults/), one per terms vector: each leg's redeem script,
//! script hash and address, or the refusal for a leg with no vault. The files are rendered from
//! the terms vectors' definitions and frozen; a change to the template, the state mapping or the
//! address encoding fails `golden_files_match`. scripts/vectors.sh regenerates them through
//! `emit_vectors`, diffs the result, and checks every file again in Python.

use super::*;
use crate::address::vault_address;
use crate::terms::golden::{hex, unhex, vectors, write_json, Json, Vector, CREATION_DAA};
use std::path::{Path, PathBuf};

/// A vector's vault as its creator sees it: creation-checked at the vectors' creation DAA score.
fn fundable(terms: &ValidatedTerms, leg: LegIndex) -> Result<FundableVault, TemplateError> {
    let ctx = CreationContext::new(terms.terms().network, CREATION_DAA);
    Vault::instantiate_for_creation(terms, leg, &ctx)
}

fn leg_json(v: &Vector, leg: LegIndex) -> Json {
    let checked = v.terms.clone().validate_structure().expect(v.name);
    let mut fields = vec![("leg_index", Json::Num(leg.index().into()))];
    match fundable(&checked, leg) {
        Ok(fundable) => {
            let vault = fundable.vault();
            fields.push(("redeem_script", Json::Str(hex(vault.redeem_script()))));
            fields.push(("script_hash", Json::Str(hex(&vault.script_hash()))));
            fields.push(("address", Json::Str(vault_address(&fundable))));
        }
        Err(e) => fields.push(("refused", Json::Str(e.code().into()))),
    }
    Json::Obj(fields)
}

/// The exact file content for one vector.
fn render(v: &Vector) -> String {
    let terms_hash = v.terms.terms_hash().expect("vector hashes");
    let template_hash = check().expect("startup check").hash();
    let doc = Json::Obj(vec![
        ("name", Json::Str(v.name.into())),
        ("terms_hash", Json::Str(hex(&terms_hash))),
        ("template_hash", Json::Str(hex(&template_hash))),
        ("asset_vault", leg_json(v, LegIndex::Asset)),
        ("cash_vault", leg_json(v, LegIndex::Cash)),
    ]);
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/vaults")
}

fn file_name(v: &Vector) -> String {
    format!("{}.json", v.name)
}

#[test]
fn golden_files_match() {
    let dir = committed_dir();
    let mut expected: Vec<String> = vectors().iter().map(file_name).collect();
    expected.sort();
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        // Hidden files (.DS_Store) are ignored by git; scripts/vectors.sh catches any other stray.
        .filter(|name| !name.starts_with('.'))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "tests/vectors/vaults holds one file per terms vector"
    );
    for v in vectors() {
        let path = dir.join(file_name(&v));
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == render(&v),
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

/// The exit test on the committed bytes: every committed redeem script decodes to its terms
/// vector and leg, and its script hash and address follow from it.
#[test]
fn golden_files_decode_to_their_terms() {
    let mut vaults = 0;
    for v in vectors() {
        let path = committed_dir().join(file_name(&v));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(doc["name"].as_str(), Some(v.name));
        assert_eq!(
            doc["terms_hash"].as_str(),
            Some(hex(&v.terms.terms_hash().unwrap()).as_str())
        );
        for (key, leg) in [
            ("asset_vault", LegIndex::Asset),
            ("cash_vault", LegIndex::Cash),
        ] {
            let j = &doc[key];
            assert_eq!(j["leg_index"].as_u64(), Some(leg.index().into()));
            let Some(script) = j["redeem_script"].as_str() else {
                assert_eq!(j["refused"].as_str(), Some("TEMPLATE_NO_VAULT"));
                continue;
            };
            vaults += 1;
            let script = unhex(script);
            let (terms, decoded_leg) = decode(&script).expect(v.name);
            assert_eq!(terms.terms(), &v.terms, "{} {key}", v.name);
            assert_eq!(decoded_leg, leg);
            let vault = Vault::instantiate_existing(&terms, leg).unwrap();
            assert_eq!(vault.redeem_script(), &script[..]);
            assert_eq!(
                j["script_hash"].as_str(),
                Some(hex(&vault.script_hash()).as_str())
            );
            let fundable = fundable(&terms, leg).unwrap();
            assert_eq!(fundable.vault(), &vault);
            assert_eq!(
                j["address"].as_str(),
                Some(vault_address(&fundable).as_str())
            );
        }
    }
    assert_eq!(vaults, 16);
}

#[test]
fn golden_set_covers_every_vault_form() {
    let docs: Vec<String> = vectors().iter().map(render).collect();
    let all = docs.concat();
    // Both networks' addresses, both refusal forms, both legs, every cash kind with a vault.
    assert!(all.contains("\"address\": \"kaspa:p"));
    assert!(all.contains("\"address\": \"kaspatest:p"));
    let refused_cash_only = vectors()
        .iter()
        .filter(|v| {
            v.terms.settlement_mode == SettlementMode::Vault
                && v.terms.cash_leg.kind == LegKind::External
        })
        .count();
    let direct = vectors()
        .iter()
        .filter(|v| v.terms.settlement_mode == SettlementMode::Direct)
        .count();
    assert!(refused_cash_only >= 1 && direct >= 1);
    assert_eq!(
        all.matches("\"refused\": \"TEMPLATE_NO_VAULT\"").count(),
        refused_cash_only + 2 * direct
    );
    for kind in [LegKind::Kas, LegKind::External] {
        assert!(vectors()
            .iter()
            .any(|v| v.terms.settlement_mode == SettlementMode::Vault
                && v.terms.cash_leg.kind == kind));
    }
    assert!(vectors()
        .iter()
        .any(|v| v.terms.settlement_mode == SettlementMode::Vault
            && matches!(v.terms.cash_leg.kind, LegKind::Kcc20(_))));
}

/// Writes the vault set to $IMPULSE_VECTORS_OUT/vaults/. Run by scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    let dir = Path::new(&out).join("vaults");
    std::fs::create_dir_all(&dir).expect("create output dir");
    for v in vectors() {
        std::fs::write(dir.join(file_name(&v)), render(&v)).expect("write vector");
    }
}
