// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms and token evidence for the verifier rows of phase 2 (ERR-10, EDGE-19, EDGE-20,
//! EDGE-21): real impulse-core terms for a harness world, the compiled artifacts of the harness
//! tokens as a token publisher's reproducible build would give them, and terms that name a
//! given token template. Reads the artifacts from the pinned compiler, never from a
//! counterparty.

use crate::harness::{
    kcc20_source, repo_path, Compiled, Kcc20State as HarnessState, Mode, Owner, Token, ASSET_COV,
    ASSET_TOKEN,
};
use crate::real_terms::{real_terms, world};
use impulse_core::terms::{Kcc20Token, LegKind, ValidatedTerms};
use silverscript_abi::ArtifactValue;

/// Real terms for the harness world of `mode`: the asset leg runs the harness asset token's
/// template, as an engine run of the same world does. Only the terms: the vaults are not
/// compared with the contract source, so a run against a mutant contract still reads them.
pub fn terms(mode: Mode) -> ValidatedTerms {
    real_terms(&world(mode)).0
}

/// The compiled artifact of `token` as silverc writes it, serialized: the evidence a funder
/// takes from the token publisher's build.
pub fn artifact_json(token: Token) -> String {
    let compiled = token.compile(HarnessState::new(Owner::pubkey([0; 32]), 0));
    serde_json::to_string(&compiled.artifact).expect("artifact serializes")
}

/// kcc20.sil with one more state field, `bool frozen`, after the four KCC-20 fields, compiled
/// at the asset token's `maxCovIns` and `maxCovOuts`. Everything else is unchanged.
pub fn frozen_kcc20() -> Compiled {
    let source = kcc20_source();
    let anchor = "bool isMinter = genesisIsMinter;";
    assert_eq!(source.matches(anchor).count(), 1);
    let source = source.replace(anchor, &format!("{anchor}\n    bool frozen = false;"));
    Compiled::new(
        &source,
        &[
            ArtifactValue::Bytes(vec![0; 32]),
            ArtifactValue::Int(0),
            ArtifactValue::Byte(0),
            ArtifactValue::Bool(false),
            ArtifactValue::Int(ASSET_TOKEN.max_cov_ins),
            ArtifactValue::Int(ASSET_TOKEN.max_cov_outs),
        ],
    )
}

/// kcc20.sil with the minter flag's state field renamed `mintable` (every use renamed with it),
/// compiled at the asset token's `maxCovIns` and `maxCovOuts`. It keeps both KCC-20 entries and
/// the four fields' types, so only the verifier's check of the state's field names finds that it
/// is not KCC-20.
pub fn renamed_state_kcc20() -> Compiled {
    let source = kcc20_source();
    assert!(source.contains("bool isMinter = genesisIsMinter;"));
    Compiled::new(
        &source.replace("isMinter", "mintable"),
        &[
            ArtifactValue::Bytes(vec![0; 32]),
            ArtifactValue::Int(0),
            ArtifactValue::Byte(0),
            ArtifactValue::Bool(false),
            ArtifactValue::Int(ASSET_TOKEN.max_cov_ins),
            ArtifactValue::Int(ASSET_TOKEN.max_cov_outs),
        ],
    )
}

/// `terms` with the asset leg naming the template of `compiled` (same covenant ID).
pub fn naming(terms: &ValidatedTerms, compiled: &Compiled) -> ValidatedTerms {
    let mut t = terms.terms().clone();
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        unreachable!("the asset leg is KCC-20")
    };
    let (prefix_len, suffix_len) = compiled.template_lens();
    t.asset_leg.kind = LegKind::Kcc20(Kcc20Token {
        template_hash: compiled.template_hash(),
        template_prefix_len: prefix_len as u32,
        template_suffix_len: suffix_len as u32,
        ..asset
    });
    t.validate_structure().expect("terms naming that template")
}

/// The KCC20Minter controller of silverscript v1.0.0: a covenant that mints KCC-20 tokens of the
/// asset token's template. It is not a KCC-20 token itself.
pub fn minter_controller() -> Compiled {
    let source = std::fs::read_to_string(repo_path("tests/engine/fixtures/kcc20/kcc20-minter.sil"))
        .expect("minter source");
    let template = ASSET_TOKEN.template();
    Compiled::new(
        &source,
        &[
            ArtifactValue::Bytes(vec![0x11; 32]),
            ArtifactValue::Bytes(ASSET_COV.as_bytes().to_vec()),
            ArtifactValue::Int(1_000_000),
            ArtifactValue::Bool(true),
            ArtifactValue::Int(template.prefix_len),
            ArtifactValue::Int(template.suffix_len),
            ArtifactValue::Bytes(template.hash.to_vec()),
        ],
    )
}

/// A template that begins with the four KCC-20 state fields and declares neither KCC-20 entry:
/// one `spend` entry that checks the owner's signature. It compiles and passes silverscript's
/// consistency check, so only the shape check of the verifier finds it is not a KCC-20 token.
pub fn spend_only_template() -> Compiled {
    let source = "contract SpendOnly(byte[32] genesisPk, int genesisAmount, byte genesisIdentifierType, bool genesisIsMinter) {
    byte[32] ownerIdentifier = genesisPk;
    byte identifierType = genesisIdentifierType;
    int amount = genesisAmount;
    bool isMinter = genesisIsMinter;

    entry spend(sig s) {
        require(checkSig(s, pubkey(ownerIdentifier)));
    }
}
";
    Compiled::new(
        source,
        &[
            ArtifactValue::Bytes(vec![0; 32]),
            ArtifactValue::Int(0),
            ArtifactValue::Byte(0),
            ArtifactValue::Bool(false),
        ],
    )
}
