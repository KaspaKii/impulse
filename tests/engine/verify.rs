// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I6 engine proof. Transactions the real engine accepts (the harness's canonical settle and
//! every signer's refund, with vaults impulse-core instantiates from real terms) decode back to
//! their terms, legs and entries, bound to the UTXOs they spend, and each spent vault input
//! verifies against the agreed terms. A vault of tampered terms is refused by the engine and by
//! the verifier alike; a signature script swapped under an unchanged transaction ID, or revealed
//! at an input the engine does not run, is refused by the bound decode. The real kcc20.sil
//! artifact, compiled with the pinned compiler, is read as a pinned KCC-20 template, and a token
//! with extended state, which the vault cannot move, is refused.

mod harness;
mod real_terms;
use harness::*;
use impulse_core::decode::{
    decode_raw, decode_transaction, decode_unbound, encode_raw, DecodeError, Entry, Outcome,
};
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{Kcc20Token, LegKind, Network};
use impulse_core::verify::{
    token_warnings, verify_spent_input, Party, PinnedKcc20, Relation, TemplateTriple,
    TokenEvidence, TokenWarning, TokenWarningKind, MAX_TOKEN_ARTIFACT_LEN, PINNED_KCC20_TEMPLATES,
};
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};
use real_terms::*;
use silverscript_abi::{ArtifactValue, SilEntryArtifact};

const AUTHORITY: [bool; 2] = [true, false];
const CASH: [u8; 3] = [CASH_KAS, CASH_KCC20, CASH_EXTERNAL];
const FUNDING: [u8; 2] = [REVOCABLE, EARMARKED];

/// Every mode real terms allow: self-settling external cash never settles and fails the
/// structure checks (instantiate.rs).
fn modes() -> Vec<Mode> {
    let mut out = Vec::new();
    for authority in AUTHORITY {
        for cash in CASH {
            for funding in FUNDING {
                if authority || cash != CASH_EXTERNAL {
                    out.push(Mode::new(authority, cash, funding));
                }
            }
        }
    }
    out
}

fn leg_of(index: i64) -> LegIndex {
    LegIndex::from_index(index).expect("0 or 1")
}

/// The scriptPublicKey each input spends, as a node reports it.
fn spent(entries: &[UtxoEntry]) -> Vec<ScriptPublicKey> {
    entries
        .iter()
        .map(|e| e.script_public_key.clone())
        .collect()
}

#[test]
fn accepted_settles_decode_to_their_trade_and_verify() {
    for mode in modes() {
        let w = core_world(mode);
        let spec = settle(&w);
        spec.assert_all_accepted(&w, &format!("settle {mode:?}"));
        let (tx, entries) = spec.build(&w);
        let (terms, _) = real_terms(&w);

        let decoded = decode_raw(&encode_raw(&tx), &spent(&entries), Network::Mainnet)
            .unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        assert_eq!(decoded.txid, tx.id().as_bytes());
        assert!(decoded.bound && decoded.refused.is_empty(), "{mode:?}");
        let legs: &[i64] = if w.external() {
            &[ASSET_LEG]
        } else {
            &[ASSET_LEG, CASH_LEG]
        };
        // The escrowed tokens and the fee input are not vault inputs.
        assert_eq!(decoded.legs.len(), legs.len(), "{mode:?}");
        assert_eq!(decoded.trades().len(), 1);
        let t = terms.terms();
        for (d, &index) in decoded.legs.iter().zip(legs) {
            let leg = leg_of(index);
            assert_eq!(d.input_index, index as usize);
            assert_eq!((d.leg, &d.terms, d.entry), (leg, &terms, Entry::Settle));
            assert_eq!(d.script_hash, w.vault(index).script_hash());
            let (amount, to) = match leg {
                LegIndex::Asset => (t.asset_leg.amount, t.buyer_delivery.clone()),
                LegIndex::Cash => (t.cash_leg.amount, t.seller_proceeds.clone()),
            };
            assert_eq!(d.outcome(), Outcome::Delivered { amount, to });

            let input = &tx.inputs[index as usize];
            let spk = &entries[index as usize].script_public_key;
            verify_spent_input(&terms, leg, input, spk).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
            let other = leg_of(1 - index);
            let swapped = verify_spent_input(&terms, other, input, spk).unwrap_err();
            let expected = if w.external() {
                "TEMPLATE_NO_VAULT" // the external-cash cash leg has no vault
            } else {
                "VERIFY_LEGS_SWAPPED"
            };
            assert_eq!(swapped.code(), expected, "{mode:?}");
        }
    }
}

#[test]
fn accepted_refunds_decode_with_their_signer() {
    for mode in modes() {
        let w = core_world(mode);
        let (terms, _) = real_terms(&w);
        let legs: &[i64] = if w.external() {
            &[ASSET_LEG]
        } else {
            &[ASSET_LEG, CASH_LEG]
        };
        let mut signers = vec![(Role::Seller, Party::Seller), (Role::Buyer, Party::Buyer)];
        if mode.authority {
            signers.push((Role::Authority, Party::Authority));
        }
        for &index in legs {
            for &(role, party) in &signers {
                let spec = w.refund(index, role);
                let label = format!("refund leg {index} by {role:?}, {mode:?}");
                spec.assert_all_accepted(&w, &label);
                let (tx, entries) = spec.build(&w);
                let decoded = decode_raw(&encode_raw(&tx), &spent(&entries), Network::Mainnet)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(decoded.legs.len(), 1, "{label}");
                let d = &decoded.legs[0];
                assert_eq!((d.input_index, d.leg), (0, leg_of(index)), "{label}");
                assert_eq!(
                    d.entry,
                    Entry::Refund {
                        signer: Some(w.xonly(role)),
                        party: Some(party)
                    },
                    "{label}"
                );
                let to = match leg_of(index) {
                    LegIndex::Asset => terms.terms().seller_refund.clone(),
                    LegIndex::Cash => terms.terms().buyer_refund.clone(),
                };
                assert_eq!(d.outcome(), Outcome::Refunded { to });
                let spk = &entries[0].script_public_key;
                verify_spent_input(&terms, leg_of(index), &tx.inputs[0], spk)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
            }
        }
    }
}

#[test]
fn a_vault_of_tampered_terms_is_refused_by_the_engine_and_the_verifier() {
    let w = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = settle(&w);
    control.assert_all_accepted(&w, "control");
    let (agreed, _) = real_terms(&w);
    let (tx, entries) = control.build(&w);
    let spk = &entries[0].script_public_key;
    verify_spent_input(&agreed, LegIndex::Asset, &tx.inputs[0], spk).expect("control");

    let mut off = agreed.terms().clone();
    off.asset_leg.amount += 1;
    let off = off.validate_structure().unwrap();
    let off_vault = Vault::instantiate_existing(&off, LegIndex::Asset).unwrap();
    let mut faulty = w.sibling(|_| {});
    let compiled = faulty.asset_vault.clone();
    faulty.asset_vault = from_core(&compiled, off_vault.redeem_script());
    let spec = settle(&faulty);
    assert_refused(&spec.run(&faulty, 0), "asset vault of amount_a + 1");

    // Decoding describes what the transaction reveals; verifying against the agreed terms judges.
    let (tx, entries) = spec.build(&faulty);
    let decoded = decode_raw(&encode_raw(&tx), &spent(&entries), Network::Mainnet).unwrap();
    assert_eq!(decoded.legs[0].terms, off);
    let spk = &entries[0].script_public_key;
    let err = verify_spent_input(&agreed, LegIndex::Asset, &tx.inputs[0], spk).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TERMS_MISMATCH");
    assert_eq!(err.to_string(), {
        "VERIFY_TERMS_MISMATCH: the script is a vault of other terms (differing: asset_leg)"
    });
}

/// The compiled artifact of `token`, as silverc writes it.
fn artifact_json(token: Token) -> String {
    let compiled = token.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
    serde_json::to_string(&compiled.artifact).expect("artifact serializes")
}

#[test]
fn the_pinned_kcc20_template_reads_as_kcc20_with_its_minter_branch() {
    let w = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let (terms, _) = real_terms(&w);
    let (asset_json, cash_json) = (artifact_json(ASSET_TOKEN), artifact_json(CASH_TOKEN));
    let asset = TokenEvidence {
        artifact_json: &asset_json,
        issuer_keys: &[],
    };
    let cash = TokenEvidence {
        artifact_json: &cash_json,
        issuer_keys: &[],
    };
    let minter = |leg| TokenWarning {
        leg,
        kind: TokenWarningKind::MinterBranch,
    };
    let unknown = |leg| TokenWarning {
        leg,
        kind: TokenWarningKind::IssuerUnknown,
    };
    // Pinned kcc20.sil builds with exactly the KCC-20 state and entries: the minter branch, and
    // no issuer keys supplied.
    assert_eq!(
        token_warnings(&terms, Some(&asset), Some(&cash)).unwrap(),
        vec![
            minter(LegIndex::Asset),
            unknown(LegIndex::Asset),
            minter(LegIndex::Cash),
            unknown(LegIndex::Cash)
        ]
    );
    // The two tokens run different templates (maxCovOuts 2 and 3): swapped, both refused.
    for (a, c) in [(&cash, &cash), (&asset, &asset)] {
        let err = token_warnings(&terms, Some(a), Some(c)).unwrap_err();
        assert_eq!(err.code(), "VERIFY_TOKEN_TEMPLATE_MISMATCH");
    }
    // I3 residual: the authority among the asset token's issuer keys.
    let keys = [w.xonly(Role::Authority)];
    let asset_issued = TokenEvidence {
        artifact_json: &asset_json,
        issuer_keys: &keys,
    };
    assert_eq!(
        token_warnings(&terms, Some(&asset_issued), Some(&cash)).unwrap(),
        vec![
            minter(LegIndex::Asset),
            TokenWarning {
                leg: LegIndex::Asset,
                kind: TokenWarningKind::PartyIsIssuer {
                    party: Party::Authority,
                    relation: Relation::Authority,
                },
            },
            minter(LegIndex::Cash),
            unknown(LegIndex::Cash),
        ]
    );
}

#[test]
fn a_pinned_kcc20_artifact_that_declares_other_entries_is_refused() {
    // Review round 1, MEDIUM 3: entry names are not covered by the template hash. Under a pinned
    // triple the bytecode is kcc20.sil's, so an artifact declaring anything else is doctored.
    let w = core_world(Mode::new(true, CASH_KAS, EARMARKED));
    let (terms, _) = real_terms(&w);
    let genuine = Token::compile(&ASSET_TOKEN, Kcc20State::new(Owner::pubkey([0; 32]), 0));
    let read = |artifact: &silverscript_abi::SilAbiArtifact| {
        let json = serde_json::to_string(artifact).unwrap();
        let evidence = TokenEvidence {
            artifact_json: &json,
            issuer_keys: &[],
        };
        token_warnings(&terms, Some(&evidence), None)
    };
    let w0 = read(&genuine.artifact).expect("control");
    assert!(w0
        .iter()
        .all(|w| w.kind != TokenWarningKind::TemplateUnpinned));

    let mut clawback = genuine.artifact.clone();
    let contract = clawback.contracts.get_mut(&genuine.name).unwrap();
    contract.entries.insert(
        "clawback".into(),
        SilEntryArtifact {
            dispatch_tag: [0xC1, 0xA7, 0xB4, 0xCC].into(),
            params: vec![],
        },
    );
    clawback
        .check_consistency()
        .expect("passes silverscript's own check");
    let err = read(&clawback).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TOKEN_ARTIFACT_INVALID", "{err}");

    // Dropping an entry the covenant metadata names fails silverscript's own check.
    let mut dropped = genuine.artifact.clone();
    let contract = dropped.contracts.get_mut(&genuine.name).unwrap();
    contract.entries.remove("__delegate");
    let err = read(&dropped).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TOKEN_ARTIFACT_INVALID", "{err}");
}

#[test]
fn the_kcc20_minter_controller_is_not_a_kcc20_token() {
    let w = core_world(Mode::new(true, CASH_KAS, EARMARKED));
    let (terms, _) = real_terms(&w);
    let source = std::fs::read_to_string(repo_path("tests/engine/fixtures/kcc20/kcc20-minter.sil"))
        .expect("minter source");
    let template = ASSET_TOKEN.template();
    let minter = Compiled::new(
        &source,
        &[
            ArtifactValue::Bytes(w.xonly(Role::Seller).to_vec()),
            ArtifactValue::Bytes(ASSET_COV.as_bytes().to_vec()),
            ArtifactValue::Int(1_000_000),
            ArtifactValue::Bool(true),
            ArtifactValue::Int(template.prefix_len),
            ArtifactValue::Int(template.suffix_len),
            ArtifactValue::Bytes(template.hash.to_vec()),
        ],
    );
    let json = serde_json::to_string(&minter.artifact).unwrap();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    // Control: terms naming the KCC-20 template refuse the minter's artifact as another template.
    let err = token_warnings(&terms, Some(&evidence), None).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TOKEN_TEMPLATE_MISMATCH");
    // Terms naming the minter's own template: its state is not the KCC-20 state.
    let (prefix_len, suffix_len) = minter.template_lens();
    let mut t = terms.terms().clone();
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        unreachable!("KCC-20 asset")
    };
    t.asset_leg.kind = LegKind::Kcc20(Kcc20Token {
        template_hash: minter.template_hash(),
        template_prefix_len: prefix_len as u32,
        template_suffix_len: suffix_len as u32,
        ..asset
    });
    let t = t.validate_structure().unwrap();
    let err = token_warnings(&t, Some(&evidence), None).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TOKEN_NOT_KCC20");
}

/// Every pinned KCC-20 template (impulse-core `PINNED_KCC20_TEMPLATES`) is the committed kcc20.sil
/// (silverscript v1.0.0) compiled with the pinned compiler, for `maxCovIns` and `maxCovOuts` from
/// 1 to 4, and nothing else is pinned. On a difference the test prints the table to commit.
#[test]
fn the_pinned_kcc20_templates_are_kcc20_sil_built_with_the_pinned_compiler() {
    let mut computed = Vec::new();
    for max_cov_ins in 1..=4u8 {
        for max_cov_outs in 1..=4u8 {
            let token = Token {
                cov: ASSET_COV,
                max_cov_ins: max_cov_ins.into(),
                max_cov_outs: max_cov_outs.into(),
            };
            let t = token.template();
            // Review round 2, MEDIUM 3: every pinned build passes the bounds the verifier puts
            // on an artifact before silverscript's consistency check, compact and as silverc
            // writes it.
            let json = artifact_json(token);
            let abi: silverscript_abi::SilAbiArtifact = serde_json::from_str(&json).unwrap();
            let pretty = silverscript_abi::to_pretty_json(&abi).unwrap();
            for text in [&json, &pretty] {
                assert!(text.len() <= MAX_TOKEN_ARTIFACT_LEN, "{}", text.len());
            }
            let contract = abi.contracts.values().next().unwrap();
            let state = &contract.runtime_state.fields;
            assert!(abi.contracts.len() == 1 && state.len() == 4);
            assert!(state.iter().all(|f| !matches!(
                f.ty,
                silverscript_abi::TypeArtifact::Struct { .. }
                    | silverscript_abi::TypeArtifact::FixedArray { .. }
                    | silverscript_abi::TypeArtifact::DynamicArray { .. }
            )));
            computed.push(PinnedKcc20 {
                max_cov_ins,
                max_cov_outs,
                triple: TemplateTriple {
                    hash: t.hash,
                    prefix_len: t.prefix_len as u64,
                    suffix_len: t.suffix_len as u64,
                },
            });
        }
    }
    if computed[..] != PINNED_KCC20_TEMPLATES[..] {
        let mut table = format!(
            "pub const PINNED_KCC20_TEMPLATES: [PinnedKcc20; {}] = [\n",
            computed.len()
        );
        for p in &computed {
            table += &format!(
                "    PinnedKcc20 {{\n        max_cov_ins: {},\n        max_cov_outs: {},\n        triple: TemplateTriple {{\n            hash: {:?},\n            prefix_len: {},\n            suffix_len: {},\n        }},\n    }},\n",
                p.max_cov_ins, p.max_cov_outs, p.triple.hash, p.triple.prefix_len, p.triple.suffix_len
            );
        }
        table += "];\n";
        panic!("PINNED_KCC20_TEMPLATES differs from the pinned build:\n{table}");
    }
    // The harness tokens are among them.
    for token in [ASSET_TOKEN, CASH_TOKEN] {
        let t = token.template();
        assert!(computed.iter().any(|p| p.triple.hash == t.hash));
    }
}

// =============================================================================================
// Review round 1, HIGH 1: the transaction ID does not commit to signature scripts
// =============================================================================================

#[test]
fn a_swapped_signature_script_is_refused_by_the_engine_and_the_bound_decode() {
    let w = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = settle(&w);
    control.assert_all_accepted(&w, "control");
    let (tx, entries) = control.build(&w);
    let (agreed, _) = real_terms(&w);
    let honest = decode_transaction(&tx, &spent(&entries), Network::Mainnet).unwrap();
    assert_eq!(honest.legs.len(), 2);

    // Another trade between the same parties; its settle's asset-vault signature script moved
    // into this transaction. The ID does not change.
    let other = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let other_spec = settle(&other);
    other_spec.assert_all_accepted(&other, "other trade");
    let (other_tx, _) = other_spec.build(&other);
    let (other_terms, _) = real_terms(&other);
    let mut forged = tx.clone();
    forged.inputs[0].signature_script = other_tx.inputs[0].signature_script.clone();
    forged.finalize();
    assert_eq!(forged.id(), tx.id());

    // The engine refuses it: the input spends this trade's asset vault, not the other's.
    assert!(execute(&forged, &entries, 0).result.is_err());
    // Unbound, it reads as the other trade.
    let unbound = decode_unbound(&forged, Network::Mainnet).unwrap();
    assert_eq!(unbound.legs[0].terms, other_terms);
    assert_ne!(other_terms, agreed);
    // Bound, input 0 is refused and the cash leg still decodes.
    let bound = decode_transaction(&forged, &spent(&entries), Network::Mainnet).unwrap();
    assert_eq!(bound.refused, vec![DecodeError::InputNotVault { index: 0 }]);
    assert_eq!(bound.legs, honest.legs[1..]);
}

#[test]
fn a_vault_script_revealed_where_the_engine_does_not_run_it_is_refused() {
    let w = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = settle(&w);
    control.assert_all_accepted(&w, "control");
    let (tx, mut entries) = control.build(&w);
    decode_transaction(&tx, &spent(&entries), Network::Mainnet).expect("control");

    // The UTXO at input 0 has script version 1: rusty-kaspa a41a333 accepts the input without
    // running anything, whatever its signature script says.
    let p2sh = entries[0].script_public_key.script().to_vec();
    entries[0].script_public_key = ScriptPublicKey::from_vec(1, p2sh);
    let mut forged = tx.clone();
    forged.inputs[0].signature_script = vec![0xac]; // not even push only
    forged.finalize();
    execute(&forged, &entries, 0)
        .result
        .expect("accepted unrun");
    // The vault's own signature script there: also accepted unrun, and refused by the decode.
    execute(&tx, &entries, 0).result.expect("accepted unrun");
    assert_eq!(
        decode_transaction(&tx, &spent(&entries), Network::Mainnet)
            .unwrap()
            .refused,
        vec![DecodeError::InputNotVault { index: 0 }]
    );
}

// =============================================================================================
// Review round 2, MEDIUM 1: a spent input verifies only where the engine runs its script
// =============================================================================================

#[test]
fn a_spent_input_verifies_only_against_the_utxo_whose_spend_runs_its_script() {
    let w = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = settle(&w);
    control.assert_all_accepted(&w, "control");
    let (tx, entries) = control.build(&w);
    let (agreed, _) = real_terms(&w);
    let honest = &entries[0].script_public_key;
    verify_spent_input(&agreed, LegIndex::Asset, &tx.inputs[0], honest).expect("control");

    // The UTXO at input 0 at script version 1, same bytes: the engine accepts the input unrun,
    // and the bound decode refuses it. So does the verifier.
    let mut unrun = entries.clone();
    unrun[0].script_public_key = ScriptPublicKey::from_vec(1, honest.script().to_vec());
    execute(&tx, &unrun, 0).result.expect("accepted unrun");
    let spk = &unrun[0].script_public_key;
    let err = verify_spent_input(&agreed, LegIndex::Asset, &tx.inputs[0], spk).unwrap_err();
    assert_eq!(err.code(), "VERIFY_INPUT_NOT_VAULT");

    // Another trade's asset-vault signature script swapped in under the same transaction ID,
    // and verified against that other trade, as a consumer shown the forged transaction would.
    let other = core_world(Mode::new(true, CASH_KCC20, EARMARKED));
    let other_spec = settle(&other);
    other_spec.assert_all_accepted(&other, "other trade");
    let (other_tx, other_entries) = other_spec.build(&other);
    let (other_terms, _) = real_terms(&other);
    assert_ne!(other_terms, agreed);
    let own = &other_entries[0].script_public_key;
    verify_spent_input(&other_terms, LegIndex::Asset, &other_tx.inputs[0], own)
        .expect("control: at its own vault");
    let mut forged = tx.clone();
    forged.inputs[0].signature_script = other_tx.inputs[0].signature_script.clone();
    forged.finalize();
    assert_eq!(forged.id(), tx.id());
    // At version 0 the engine runs it and refuses; at version 1 it accepts it unrun. The
    // verifier refuses both.
    assert!(execute(&forged, &entries, 0).result.is_err());
    execute(&forged, &unrun, 0).result.expect("accepted unrun");
    for spent in [&entries, &unrun] {
        let spk = &spent[0].script_public_key;
        let err =
            verify_spent_input(&other_terms, LegIndex::Asset, &forged.inputs[0], spk).unwrap_err();
        assert_eq!(err.code(), "VERIFY_INPUT_NOT_VAULT");
    }
}

// =============================================================================================
// Review round 1, HIGH 2: a KCC-20 token with extended state cannot move through the vault
// =============================================================================================

/// kcc20.sil (the committed v1.0.0 copy) with one more state field, `bool frozen`, after the
/// four KCC-20 fields; everything else unchanged.
fn kcc20_with_frozen_source() -> String {
    let source = kcc20_source();
    let anchor = "bool isMinter = genesisIsMinter;";
    assert_eq!(source.matches(anchor).count(), 1);
    source.replace(anchor, &format!("{anchor}\n    bool frozen = false;"))
}

/// A KCC-20 template, standard or with the frozen field, compiled at the asset token's
/// maxCovIns and maxCovOuts.
struct Kcc20Build {
    frozen: bool,
}

impl Kcc20Build {
    fn source(&self) -> String {
        if self.frozen {
            kcc20_with_frozen_source()
        } else {
            kcc20_source()
        }
    }

    fn compile(&self, state: Kcc20State) -> Compiled {
        Compiled::new(
            &self.source(),
            &[
                ArtifactValue::Bytes(state.owner.to_vec()),
                ArtifactValue::Int(state.amount),
                ArtifactValue::Byte(state.id_type),
                ArtifactValue::Bool(state.is_minter),
                ArtifactValue::Int(ASSET_TOKEN.max_cov_ins),
                ArtifactValue::Int(ASSET_TOKEN.max_cov_outs),
            ],
        )
    }

    fn template(&self) -> TemplateRef {
        let c = self.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
        let (prefix_len, suffix_len) = c.template_lens();
        TemplateRef {
            cov: ASSET_COV,
            hash: c.template_hash(),
            prefix_len: prefix_len as i64,
            suffix_len: suffix_len as i64,
        }
    }

    /// The token `transfer` leader call moving the escrow to `home`.
    fn leader(&self, escrow: Kcc20State, home: Kcc20State, witness: u8) -> Vec<u8> {
        let mut state = home.to_value();
        if self.frozen {
            let ArtifactValue::Object(fields) = &mut state else {
                unreachable!("a state object")
            };
            fields.insert("frozen".into(), ArtifactValue::Bool(false));
        }
        self.compile(escrow).covenant_sigscript(
            "transfer",
            &[
                ArtifactValue::Array(vec![state]),
                ArtifactValue::Bytes(vec![0; 65]),
                ArtifactValue::Byte(witness),
            ],
            true,
        )
    }
}

/// The asset vault's verdict (input 0) and the escrowed token's own (its transfer leader) on
/// the canonical settle and on the seller's refund, with the asset token built by `build`.
fn vault_and_token_verdicts(build: &Kcc20Build) -> [(Run, Run); 2] {
    let template = build.template();
    let base = world(Mode::new(true, CASH_KAS, EARMARKED));
    let w = base.edit(|t| t.asset = template);
    let escrow_state = w.asset_escrow_state();
    let cases = [
        (settle(&w), w.asset_escrow_idx(), w.delivered_asset(), 0),
        (
            w.refund(ASSET_LEG, Role::Seller),
            1,
            Kcc20State::new(w.terms.seller_refund, w.terms.amount_a),
            1,
        ),
    ];
    cases.map(|(mut spec, escrow_idx, home, home_out)| {
        // The token input is built as a delegate (no state arguments) and given its leader call
        // after signing: sighashes do not commit to signature scripts.
        spec.inputs[escrow_idx] = In::token_delegate(build.compile(escrow_state), ASSET_COV, 0);
        spec.outputs[home_out] = Out::token(build.compile(home), ASSET_COV, escrow_idx as u16);
        let (mut tx, entries) = spec.build(&w);
        tx.inputs[escrow_idx].signature_script = build.leader(escrow_state, home, 0);
        tx.finalize();
        (
            execute(&tx, &entries, 0),
            execute(&tx, &entries, escrow_idx),
        )
    })
}

#[test]
fn a_kcc20_token_with_extended_state_cannot_settle_or_refund_and_is_refused() {
    // A: kcc20.sil as published. Both the vault and the token accept settle and refund.
    for (vault, token) in vault_and_token_verdicts(&Kcc20Build { frozen: false }) {
        assert_accepted(&token, "standard token transfer");
        assert_accepted(&vault, "vault with the standard token");
    }
    // B: one more state field. The token's own transfer is still valid, but the vault, which
    // reads and rebuilds the four-field state, refuses both: the token would be stuck.
    for (vault, token) in vault_and_token_verdicts(&Kcc20Build { frozen: true }) {
        assert_accepted(&token, "frozen-field token transfer");
        assert_refused(&vault, "vault with the frozen-field token");
    }
    // The verifier refuses it before funding.
    let build = Kcc20Build { frozen: true };
    let w = world(Mode::new(true, CASH_KAS, EARMARKED)).edit(|t| t.asset = build.template());
    let (terms, _) = real_terms(&w);
    let json = serde_json::to_string(
        &build
            .compile(Kcc20State::new(Owner::pubkey([0; 32]), 0))
            .artifact,
    )
    .unwrap();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    let err = token_warnings(&terms, Some(&evidence), None).unwrap_err();
    assert_eq!(err.code(), "VERIFY_TOKEN_EXTENDED_STATE", "{err}");
}
