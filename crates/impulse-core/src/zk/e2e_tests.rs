// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! End-to-end tests of the v3 builders in the pinned script engine: real RISC Zero Groth16 proofs
//! (`testdata/e2e-*.proof.json`, made by `scripts/regen-zk-core-fixtures.sh` with the local
//! prover) bound to the vault scriptPubKeys of the fixture worlds below, a settle built by
//! `zk::settle`, and every input that needs no signature run through
//! `kaspa_txscript::TxScriptEngine` at the budget the builder committed.
//!
//! Keys: none. Every party, the fee payer included, is a label-derived x-only key for which
//! nobody holds a private key, and impulse-core holds no key anywhere (rule 1, docs/ENGINEERING-RULES.md). The
//! engine runs the inputs that need no signature, which are the vault inputs of the self-settling
//! worlds; the authority world stops at the authority's signature (the gate test). Everything
//! that needs a signature (funding, refunds, the fee input) is run through the command line's
//! signing module and the fake node's engine in `impulse-cli/src/zk_tests.rs`.

use super::*;
use crate::template::LegIndex;
use crate::terms::golden::xonly;
use crate::terms::{CreationContext, FundingMode, IdentifierType, Kcc20Owner};
use crate::tx::testkit::*;
use crate::tx::{FeePayment, Kcc20Deposit, RefundSigner, Utxo};
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, Transaction, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine};
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/zk/testdata")
        .join(name)
}

/// A world whose asset vault a committed proof is bound to.
struct World {
    terms: ValidatedTermsV3,
    tree: ListTree,
    owner: Kcc20Owner,
}

/// The proof-bound worlds by name: the KAS-cash trade without an authority (self-settling) and
/// with one, a KCC-20 cash trade without one, and an external-cash trade, which needs one.
const WORLDS: [&str; 4] = ["selfsettle", "authority", "kcc20cash", "external"];

fn mode_of(name: &str) -> Mode {
    match name {
        "selfsettle" => Mode::vault(false, Cash::Kas, FundingMode::Revocable),
        "authority" => Mode::vault(true, Cash::Kas, FundingMode::Revocable),
        "kcc20cash" => Mode::vault(false, Cash::Kcc20, FundingMode::Revocable),
        "external" => Mode::vault(true, Cash::External, FundingMode::Revocable),
        other => panic!("no world {other}"),
    }
}

/// The KAS-cash world with or without an authority.
fn world(authority: bool) -> World {
    world_named(if authority { "authority" } else { "selfsettle" })
}

/// The list of every world: three entries, the buyer's delivery owner in the middle.
fn world_named(name: &str) -> World {
    let p = parties();
    let v1 = terms(mode_of(name), &p);
    let owner = match &v1.buyer_delivery {
        crate::terms::Destination::Kcc20(o) => *o,
        _ => unreachable!("fixture delivery is a KCC-20 owner"),
    };
    let other = |label: &str| Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: xonly(label),
    };
    let entries = vec![
        other("impulse/tests/zk/list/a"),
        owner,
        other("impulse/tests/zk/list/c"),
    ];
    let salts: Vec<[u8; 32]> = (0u32..3)
        .map(|i| sha256(format!("impulse/tests/zk/e2e/salt/{i}").as_bytes()))
        .collect();
    let tree = ListTree::build_with_salts(entries, &salts).unwrap();
    let issuer = xonly("impulse/tests/key/list-issuer");
    let terms = TermsV3::new(v1, issuer, tree.root())
        .validate_structure()
        .expect("fixture terms v3 pass the structure checks");
    World { terms, tree, owner }
}

fn asset_vault(w: &World) -> VaultV3 {
    VaultV3::instantiate_existing(&w.terms, LegIndex::Asset).unwrap()
}

/// What the prover needs for this world's proof.
fn prover_args(w: &World) -> String {
    let path = w.tree.member_path(&w.owner).unwrap();
    let vault = asset_vault(w);
    let siblings: Vec<String> = path
        .siblings
        .iter()
        .map(|s| format!("\"{}\"", hex(s)))
        .collect();
    format!(
        "{{\"path\": {{\"index\": {}, \"salt\": \"{}\", \"siblings\": [{}]}}, \"root\": \"{}\", \"vault_spk\": \"{}\", \"owner_spk\": \"{}\"}}\n",
        path.index,
        hex(&path.salt),
        siblings.join(", "),
        hex(&w.terms.terms().list_root),
        hex(&p2sh_spk(&vault.script_hash())),
        hex(&owner_spk(&w.owner).unwrap()),
    )
}

/// Writes the prover inputs of both worlds to $IMPULSE_E2E_OUT. Run by
/// `scripts/regen-zk-core-fixtures.sh` only.
#[test]
#[ignore = "generator for scripts/regen-zk-core-fixtures.sh"]
fn emit_prover_inputs() {
    let out = std::env::var("IMPULSE_E2E_OUT").expect("IMPULSE_E2E_OUT is set");
    for name in WORLDS {
        std::fs::write(
            PathBuf::from(&out).join(format!("{name}.args.json")),
            prover_args(&world_named(name)),
        )
        .unwrap();
        std::fs::write(
            PathBuf::from(&out).join(format!("{name}.terms.hex")),
            format!("{}\n", hex(world_named(name).terms.canonical())),
        )
        .unwrap();
    }
}

// =============================================================================================
// Proofs, UTXOs and the engine
// =============================================================================================

struct Proof {
    bytes: ProofBytes,
    journal: Vec<u8>,
    image_id: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn load_proof(name: &str) -> Proof {
    let path = testdata(&format!("e2e-{name}.proof.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; make it with scripts/regen-zk-core-fixtures.sh",
            path.display()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    Proof {
        bytes: ProofBytes::parse(&unhex(v["proof"].as_str().unwrap())).unwrap(),
        journal: unhex(v["journal"].as_str().unwrap()),
        image_id: v["image_id"].as_str().unwrap().to_string(),
    }
}

/// The committed proof of `name`, checked to be the proof of `w`'s asset vault.
fn proof_for(w: &World, name: &str) -> ProofBytes {
    let p = load_proof(name);
    let want = journal(
        &w.terms.terms().list_root,
        &asset_vault(w).script_hash(),
        &w.owner,
    )
    .unwrap();
    assert_eq!(
        hex(&p.journal),
        hex(&want),
        "the committed proof e2e-{name} is bound to another vault (the template, the terms or the image changed): run scripts/regen-zk-core-fixtures.sh"
    );
    assert_eq!(
        p.image_id.as_str(),
        include_str!("../../../../circuits/IMAGE_ID").trim()
    );
    p.bytes
}

fn engine_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(MAINNET_PARAMS.mass_per_sig_op).into(),
    }
}

/// Runs input `idx` of a transaction at the budget it committed; returns the result and the
/// script units used.
fn run_input(
    tx: &Transaction,
    entries: &[UtxoEntry],
    idx: usize,
) -> (Result<(), kaspa_txscript_errors::TxScriptError>, u64) {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(1_000);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("covenant context");
    let (input, utxo) = populated.populated_input(idx);
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        input,
        idx,
        utxo,
        EngineCtx::new(&sig_cache)
            .with_reused(&reused)
            .with_covenants_ctx(&cov_ctx),
        engine_flags(),
        input.compute_commit.allowed_script_units(),
    );
    let result = vm.execute();
    (result, vm.used_script_units().0)
}

/// The transaction with every signature slot holding a placeholder (64 zero bytes and
/// SIG_HASH_ALL), as the builder's own proof check does.
fn placeholder_tx(ipst: &IpstV3) -> Transaction {
    let mut tx = ipst.transaction().clone();
    for (input, slot) in tx.inputs.iter_mut().zip(ipst.slots()) {
        let mut placeholder = [0u8; 65];
        placeholder[64] = 0x01;
        input.signature_script = slot.script_with(&placeholder);
    }
    tx
}

/// Every input that takes no signature runs to success within its budget. Returns, per input, the
/// script units used and the allowance; a signed input reports (0, 0).
fn run_unsigned_inputs(ipst: &IpstV3) -> Vec<(u64, u64)> {
    let tx = placeholder_tx(ipst);
    (0..tx.inputs.len())
        .map(|i| {
            if ipst.slots()[i].signer().is_some() {
                return (0, 0);
            }
            let (result, used) = run_input(&tx, ipst.entries(), i);
            result.unwrap_or_else(|e| panic!("input {i} failed in the engine: {e} (used {used})"));
            (used, tx.inputs[i].compute_commit.allowed_script_units().0)
        })
        .collect()
}

fn vault_utxos(w: &World) -> (Utxo, Utxo, Utxo) {
    let asset = asset_vault(w);
    let t = &w.terms.terms().fields;
    // External cash has no cash vault; its UTXO is unused, so any script stands in.
    let cash_spk = match VaultV3::instantiate_existing(&w.terms, LegIndex::Cash) {
        Ok(cash) => cash.script_public_key(),
        Err(_) => crate::tx::p2pk(&[9; 32]),
    };
    let escrow_state = crate::tx::Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: asset.script_hash(),
        },
        t.asset_leg.amount,
    );
    let escrow_spk = asset_template().script_public_key(&escrow_state).unwrap();
    (
        utxo(
            "asset-authorizer",
            AUTHORIZER,
            asset.script_public_key(),
            None,
        ),
        utxo("asset-escrow", CARRIER, escrow_spk, Some(ASSET_COV)),
        utxo("cash-vault", t.cash_leg.amount, cash_spk, None),
    )
}

/// A fee above the relay minimum of a v3 settle (the settle's compute mass is far above v1's).
const V3_FEE: u64 = 20_000_000;

/// The fee payer: a label-derived key, so no signature of it exists.
fn fee_for_payer() -> FeePayment {
    let payer = parties().payer;
    FeePayment {
        inputs: vec![utxo("fee", FEE_INPUT, crate::tx::p2pk(&payer), None)],
        fee: V3_FEE,
        change: crate::tx::p2pk(&payer),
    }
}

fn settle_world(w: &World, proof: &ProofBytes) -> Result<IpstV3, ZkError> {
    settle_world_paying(w, proof, &fee_for_payer())
}

fn settle_world_paying(w: &World, proof: &ProofBytes, fee: &FeePayment) -> Result<IpstV3, ZkError> {
    use crate::terms::LegKind;
    let (authorizer, escrow, cash_vault) = vault_utxos(w);
    let asset_tpl = asset_template();
    let cash_tpl = cash_template();
    let t = &w.terms.terms().fields;
    let cash = match t.cash_leg.kind {
        LegKind::Kas => crate::tx::SettleCash::Kas { vault: cash_vault },
        LegKind::Kcc20(_) => {
            let cv = VaultV3::instantiate_existing(&w.terms, LegIndex::Cash).unwrap();
            let state = crate::tx::Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::ScriptHash,
                    identifier: cv.script_hash(),
                },
                t.cash_leg.amount,
            );
            crate::tx::SettleCash::Kcc20 {
                authorizer: utxo("cash-authorizer", AUTHORIZER, cv.script_public_key(), None),
                escrow: utxo(
                    "cash-escrow",
                    CARRIER,
                    cash_tpl.script_public_key(&state).unwrap(),
                    Some(CASH_COV),
                ),
                token: &cash_tpl,
            }
        }
        LegKind::External => crate::tx::SettleCash::External,
    };
    let legs = crate::tx::SettleLegs {
        asset_authorizer: authorizer,
        asset_escrow: escrow,
        asset_token: &asset_tpl,
        cash,
    };
    settle(&w.terms, &legs, proof, fee, NOW)
}

// =============================================================================================
// Settle
// =============================================================================================

/// `ZK_TX_MASS`: each dimension just over its cap is refused with its own name, exactly at the
/// cap is accepted, and compute is reported before transient before storage.
#[test]
fn each_mass_dimension_over_its_cap_is_refused_with_its_name() {
    use crate::tx::Masses;
    use crate::zk::build::{
        check_v3_masses, V3_COMPUTE_MASS_CAP, V3_STORAGE_MASS_CAP, V3_TRANSIENT_MASS_CAP,
    };
    let at = Masses {
        compute: V3_COMPUTE_MASS_CAP,
        transient: V3_TRANSIENT_MASS_CAP,
        storage: V3_STORAGE_MASS_CAP,
        fee_mass: V3_COMPUTE_MASS_CAP,
    };
    check_v3_masses(&at).unwrap();
    let cases = [
        (
            "compute",
            Masses {
                compute: V3_COMPUTE_MASS_CAP + 1,
                ..at
            },
            V3_COMPUTE_MASS_CAP,
        ),
        (
            "transient",
            Masses {
                transient: V3_TRANSIENT_MASS_CAP + 1,
                ..at
            },
            V3_TRANSIENT_MASS_CAP,
        ),
        (
            "storage",
            Masses {
                storage: V3_STORAGE_MASS_CAP + 1,
                ..at
            },
            V3_STORAGE_MASS_CAP,
        ),
    ];
    for (dimension, masses, cap) in cases {
        match check_v3_masses(&masses).unwrap_err() {
            ZkError::TxMass {
                dimension: d,
                mass,
                cap: c,
            } => {
                assert_eq!((d, c, mass), (dimension, cap, cap + 1));
            }
            e => panic!("{e}"),
        }
        assert_eq!(check_v3_masses(&masses).unwrap_err().code(), "ZK_TX_MASS");
    }
    // All three over: compute is named first.
    let all = Masses {
        compute: V3_COMPUTE_MASS_CAP + 1,
        transient: V3_TRANSIENT_MASS_CAP + 1,
        storage: V3_STORAGE_MASS_CAP + 1,
        fee_mass: 0,
    };
    assert!(matches!(
        check_v3_masses(&all).unwrap_err(),
        ZkError::TxMass {
            dimension: "compute",
            ..
        }
    ));
}

/// `ZK_TX_MASS` cannot be reached by a build of a vault: the template allows at most 12 inputs
/// (`[F4]`), and a settle at that bound is built within the caps, so the builder refuses 300 fee
/// inputs with `TX_TOO_MANY_INPUTS` before any mass is computed. The mass check itself is covered
/// by the unit test above.
#[test]
fn a_settle_above_the_input_bound_is_refused_and_one_at_the_bound_fits_the_caps() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let payer = parties().payer;
    let fee_of = |n: usize| FeePayment {
        inputs: (0..n)
            .map(|i| {
                utxo(
                    &format!("fee-{i}"),
                    60_000_000,
                    crate::tx::p2pk(&payer),
                    None,
                )
            })
            .collect(),
        fee: V3_FEE,
        change: crate::tx::p2pk(&payer),
    };
    match settle_world_paying(&w, &proof, &fee_of(300)).unwrap_err() {
        ZkError::Tx(e) => assert_eq!(e.code(), "TX_TOO_MANY_INPUTS"),
        e => panic!("{e}"),
    }
    // The ordinary settle has one fee input; fill the rest of the bound with fee inputs.
    let ordinary = settle_world(&w, &proof).unwrap().transaction().inputs.len();
    let room = crate::bounds::MAX_VAULT_SPEND_INPUTS - ordinary + 1;
    settle_world_paying(&w, &proof, &fee_of(room)).expect("a settle at the bound is built");
    match settle_world_paying(&w, &proof, &fee_of(room + 1)).unwrap_err() {
        ZkError::Tx(e) => assert_eq!(e.code(), "TX_TOO_MANY_INPUTS"),
        e => panic!("{e}"),
    }
}

#[test]
fn a_settle_with_a_real_proof_runs_in_the_engine_and_fits_its_budgets() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let ipst = settle_world(&w, &proof).expect("the settle builds");
    assert_eq!(
        ipst.pending(),
        vec![3],
        "only the fee input takes a signature"
    );
    let used = run_unsigned_inputs(&ipst);
    // The asset vault paid for the verification, the cash vault did not.
    assert!(used[0].0 >= GATE_FLOOR_UNITS, "{used:?}");
    assert!(used[1].0 < GATE_FLOOR_UNITS, "{used:?}");
    assert!(
        used.iter().filter(|(u, _)| *u > 0).all(|(u, a)| u <= a),
        "{used:?}"
    );
    let masses = ipst.masses();
    assert!(
        masses.compute > crate::tx::STANDARD_MASS_CAP,
        "a v3 settle is heavier than the v1 standard cap: {masses:?}"
    );
    assert!(masses.compute <= V3_COMPUTE_MASS_CAP && masses.transient <= V3_TRANSIENT_MASS_CAP);
    // Unsigned, the document does not finalize.
    assert_eq!(ipst.finalize().unwrap_err().code(), "TX_SIGNATURE_SLOT");
    println!("script units used and allowed per input: {used:?}");
    println!("masses: {masses:?}");
}

#[test]
fn the_verification_cost_is_within_the_modelled_units() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let ipst = settle_world(&w, &proof).unwrap();
    let tx = placeholder_tx(&ipst);
    let (result, used) = run_input(&tx, ipst.entries(), 0);
    result.unwrap();
    // 14,000,000 + 250,000 * 6 for the five public inputs of the zk-sdk fragment, plus the v1
    // vault work and the journal hashing.
    assert!(used >= VERIFY_UNITS, "used {used}");
    assert!(
        used < VERIFY_UNITS + VERIFY_MARGIN_UNITS + 200_000,
        "used {used}"
    );
}

#[test]
fn a_proof_for_another_vault_is_refused_by_the_builder() {
    let w = world(false);
    let other_proof = proof_for(&world(true), "authority");
    // Valid curve points and a real proof, but of another vault's journal.
    assert_eq!(
        settle_world(&w, &other_proof).unwrap_err().code(),
        "ZK_PROOF_INVALID"
    );
}

#[test]
fn a_malformed_proof_is_refused_before_a_builder_runs() {
    assert_eq!(
        ProofBytes::parse(&[0u8; 127]).unwrap_err().code(),
        "ZK_PROOF_MALFORMED"
    );
    assert_eq!(
        ProofBytes::parse(&[0xff; 128]).unwrap_err().code(),
        "ZK_PROOF_MALFORMED"
    );
}

#[test]
fn a_proof_of_a_member_for_another_owner_is_refused() {
    let w = world(false);
    // The same terms, delivering to a different owner of the list: another vault address, so the
    // committed proof (bound to the buyer's vault) does not verify for it.
    let proof = proof_for(&w, "selfsettle");
    let mut t = w.terms.terms().clone();
    if let crate::terms::Destination::Kcc20(o) = &mut t.fields.buyer_delivery {
        o.identifier = xonly("impulse/tests/zk/list/a");
    }
    let other = World {
        terms: t.validate_structure().unwrap(),
        tree: world(false).tree,
        owner: Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: xonly("impulse/tests/zk/list/a"),
        },
    };
    assert_eq!(
        settle_world(&other, &proof).unwrap_err().code(),
        "ZK_PROOF_INVALID"
    );
}

#[test]
fn with_an_authority_the_gate_passes_and_the_signature_is_pending() {
    let w = world(true);
    let proof = proof_for(&w, "authority");
    let ipst = settle_world(&w, &proof).expect("the settle builds past the gate");
    assert_eq!(
        ipst.pending(),
        vec![0, 1, 3],
        "the authority signs both vault inputs, the fee payer its own"
    );
    // The asset vault input passes the proof gate and then fails at the authority's signature,
    // which the placeholder does not satisfy: more than the gate's units used, and a failure.
    let tx = placeholder_tx(&ipst);
    let (result, used) = run_input(&tx, ipst.entries(), 0);
    assert!(result.is_err(), "the placeholder is no signature");
    assert!(used >= GATE_FLOOR_UNITS, "the gate ran first: {used}");
    // Without the signatures the document does not finalize.
    assert_eq!(ipst.finalize().unwrap_err().code(), "TX_SIGNATURE_SLOT");
    // A wrong proof is refused even though the signature is pending.
    let wrong = proof_for(&world(false), "selfsettle");
    assert_eq!(
        settle_world(&w, &wrong).unwrap_err().code(),
        "ZK_PROOF_INVALID"
    );
}

#[test]
fn a_kcc20_cash_settle_runs_every_unsigned_input_in_the_engine() {
    let w = world_named("kcc20cash");
    let proof = proof_for(&w, "kcc20cash");
    let ipst = settle_world(&w, &proof).expect("the settle builds");
    // Inputs: asset authorizer, cash authorizer, asset escrow, cash escrow, then the fee input.
    assert_eq!(ipst.entries().len(), 5);
    assert_eq!(
        ipst.pending(),
        vec![4],
        "only the fee input takes a signature"
    );
    let used = run_unsigned_inputs(&ipst);
    assert!(
        used[0].0 >= GATE_FLOOR_UNITS && used[1].0 < GATE_FLOOR_UNITS,
        "{used:?}"
    );
    assert!(
        used.iter().filter(|(u, _)| *u > 0).all(|(u, a)| u <= a),
        "{used:?}"
    );
    let m = ipst
        .verify_against_terms(&asset_template(), Some(&cash_template()), NOW)
        .unwrap();
    assert_eq!(m.kind, crate::tx::IpstKind::Settle);
    let masses = ipst.masses();
    assert!(masses.compute <= V3_COMPUTE_MASS_CAP && masses.transient <= V3_TRANSIENT_MASS_CAP);
    println!("kcc20 cash: script units used and allowed per input: {used:?}");
    println!("kcc20 cash: masses: {masses:?}");
}

#[test]
fn an_external_cash_settle_passes_the_gate_and_waits_for_the_authority() {
    let w = world_named("external");
    let proof = proof_for(&w, "external");
    let ipst = settle_world(&w, &proof).expect("the settle builds past the gate");
    // Inputs: asset authorizer, asset escrow, the fee input; the cash is paid off chain.
    assert_eq!(ipst.entries().len(), 3);
    assert_eq!(
        ipst.pending(),
        vec![0, 2],
        "the authority and the fee payer sign"
    );
    let tx = placeholder_tx(&ipst);
    let (result, used) = run_input(&tx, ipst.entries(), 0);
    assert!(result.is_err(), "the placeholder is no authority signature");
    assert!(used >= GATE_FLOOR_UNITS, "the gate ran first: {used}");
    // The escrowed token takes no signature and runs in the engine.
    let (result, _) = run_input(&tx, ipst.entries(), 1);
    result.unwrap();
    let m = ipst
        .verify_against_terms(&asset_template(), None, NOW)
        .unwrap();
    assert_eq!(m.kind, crate::tx::IpstKind::Settle);
    // External cash has no cash vault, and a cash-vault proof has no meaning here.
    assert_eq!(
        VaultV3::instantiate_existing(&w.terms, LegIndex::Cash)
            .unwrap_err()
            .code(),
        "TEMPLATE_NO_VAULT"
    );
}

fn json_without_proof(ipst: &IpstV3, proof: &ProofBytes) -> String {
    ipst.to_json().replace(
        &format!("\"zk_proof\": \"{}\"", hex(proof.as_bytes())),
        "\"zk_proof\": null",
    )
}

#[test]
fn the_terms_check_accepts_the_builders_settle_and_nothing_else() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let ipst = settle_world(&w, &proof).unwrap();
    let asset_tpl = asset_template();
    let m = ipst
        .verify_against_terms(&asset_tpl, None, NOW)
        .expect("the terms check accepts what the builder made");
    assert_eq!(m.kind, crate::tx::IpstKind::Settle);
    // A document with another proof (the authority world's) is not what the builder makes.
    let other = proof_for(&world(true), "authority");
    let mut json = ipst.to_json();
    json = json.replace(&hex(proof.as_bytes()), &hex(other.as_bytes()));
    let tampered = IpstV3::from_json(&json).unwrap();
    assert!(tampered
        .verify_against_terms(&asset_tpl, None, NOW)
        .is_err());
    // A document with its proof removed is not a settle the builders make either.
    let without = IpstV3::from_json(&json_without_proof(&ipst, &proof)).unwrap();
    assert!(without.verify_against_terms(&asset_tpl, None, NOW).is_err());
}

#[test]
fn ipst_version_4_round_trips_and_other_readers_refuse_it() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let ipst = settle_world(&w, &proof).unwrap();
    let json = ipst.to_json();
    assert!(json.contains("\"ipst\": 4"));
    assert!(json.contains("\"zk_proof\": \""));
    assert_eq!(IpstV3::from_json(&json).unwrap(), ipst);
    assert_eq!(IpstV3::from_json(&json).unwrap().to_json(), json);
    // The v1 reader refuses version 4.
    assert_eq!(
        crate::tx::Ipst::from_json(&json).unwrap_err().code(),
        "IPST_UNSUPPORTED_VERSION"
    );
    // The v3 reader refuses a v1 document.
    let v1_json = ipst.as_v1().to_json();
    assert_eq!(
        IpstV3::from_json(&v1_json).unwrap_err().code(),
        "ZK_IPST_VERSION"
    );
    // A key given twice, a missing proof key, a malformed proof.
    let twice = json.replacen("{\n", "{\n  \"lock_time\": \"0\",\n", 1);
    assert_eq!(
        IpstV3::from_json(&twice).unwrap_err().code(),
        "IPST_MALFORMED"
    );
    let no_proof = json.replace("\"zk_proof\"", "\"zk_proof_x\"");
    assert_eq!(
        IpstV3::from_json(&no_proof).unwrap_err().code(),
        "IPST_MALFORMED"
    );
    let short = json.replace(&hex(proof.as_bytes()), &"ab".repeat(100));
    assert_eq!(
        IpstV3::from_json(&short).unwrap_err().code(),
        "ZK_PROOF_MALFORMED"
    );
}

#[test]
fn a_signature_still_has_to_match_its_slot() {
    let w = world(false);
    let proof = proof_for(&w, "selfsettle");
    let mut ipst = settle_world(&w, &proof).unwrap();
    // 64 bytes that are no signature of the slot's signer, and SIG_HASH_ALL.
    let mut bogus = [0x11u8; 65];
    bogus[64] = 0x01;
    assert_eq!(
        ipst.add_signature(3, &bogus).unwrap_err().code(),
        "TX_SIGNATURE"
    );
    assert_eq!(
        ipst.add_signature(0, &bogus).unwrap_err().code(),
        "TX_SIGNATURE_SLOT"
    );
    // combine: two copies that differ in proof do not combine.
    let other = IpstV3::from_json(&json_without_proof(&ipst, &proof)).unwrap();
    assert_eq!(ipst.combine(&other).unwrap_err().code(), "IPST_CONFLICT");
    let _ = pay_to_script_hash_script;
}

// =============================================================================================
// Funding and refunds: structure and the terms check. The engine runs of the signed forms are in
// impulse-cli/src/zk_tests.rs, where a key file signs.
// =============================================================================================

fn label_terms(authority: bool, cash: Cash, funding: FundingMode) -> ValidatedTermsV3 {
    let p = parties();
    let v1 = terms(Mode::vault(authority, cash, funding), &p);
    let owner = Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: p.buyer,
    };
    let tree = ListTree::build_with_salts(
        vec![
            owner,
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: xonly("impulse/tests/zk/list/a"),
            },
        ],
        &[[1; 32], [2; 32]],
    )
    .unwrap();
    TermsV3::new(v1, xonly("impulse/tests/key/list-issuer"), tree.root())
        .validate_structure()
        .unwrap()
}

fn cash_vault_utxo(terms: &ValidatedTermsV3) -> Utxo {
    let cash = VaultV3::instantiate_existing(terms, LegIndex::Cash).unwrap();
    utxo(
        "cash-vault",
        terms.terms().fields.cash_leg.amount,
        cash.script_public_key(),
        None,
    )
}

#[test]
fn funding_a_kas_cash_leg_pays_the_v3_cash_vault() {
    let terms = label_terms(true, Cash::Kas, FundingMode::Revocable);
    let ctx = CreationContext::new(crate::terms::Network::Mainnet, NOW);
    let vault = VaultV3::instantiate_for_creation(&terms, LegIndex::Cash, &ctx).unwrap();
    let ipst = fund_kas(&terms, &vault, &fee_for_payer(), NOW).unwrap();
    let out = &ipst.transaction().outputs[0];
    assert_eq!(out.script_public_key, vault.vault().script_public_key());
    assert_eq!(out.value, terms.terms().fields.cash_leg.amount);
    let m = ipst
        .verify_against_terms(&asset_template(), None, NOW)
        .unwrap();
    assert_eq!(m.kind, crate::tx::IpstKind::FundKas);
    // The asset leg is KCC-20: the KAS funding refuses it.
    let asset_vault = VaultV3::instantiate_for_creation(&terms, LegIndex::Asset, &ctx).unwrap();
    assert_eq!(
        fund_kas(&terms, &asset_vault, &fee_for_payer(), NOW)
            .unwrap_err()
            .code(),
        "TX_WRONG_MODE"
    );
    // A vault of other terms is not this trade's.
    let other = label_terms(false, Cash::Kas, FundingMode::Revocable);
    let foreign = VaultV3::instantiate_for_creation(&other, LegIndex::Cash, &ctx).unwrap();
    assert_eq!(
        fund_kas(&terms, &foreign, &fee_for_payer(), NOW)
            .unwrap_err()
            .code(),
        "TX_VAULT_MISMATCH"
    );
    // An expired trade is not funded.
    assert_eq!(
        fund_kas(&terms, &vault, &fee_for_payer(), EXPIRY)
            .unwrap_err()
            .code(),
        "TX_EXPIRED"
    );
}

#[test]
fn funding_a_kcc20_asset_leg_builds_the_v3_deposit() {
    let terms = label_terms(true, Cash::Kas, FundingMode::Revocable);
    let ctx = CreationContext::new(crate::terms::Network::Mainnet, NOW);
    let vault = VaultV3::instantiate_for_creation(&terms, LegIndex::Asset, &ctx).unwrap();
    let tpl = asset_template();
    let deposit = Kcc20Deposit {
        tokens: vec![own_token(
            "seller-asset",
            &tpl,
            ASSET_COV,
            &parties().seller,
            AMOUNT_A + 7,
        )],
        carrier: CARRIER,
        authorizer: AUTHORIZER,
    };
    let ipst = fund_kcc20(&terms, &vault, &tpl, &deposit, &fee_for_payer(), NOW).unwrap();
    assert_eq!(
        ipst.transaction().outputs[1].script_public_key,
        vault.vault().script_public_key()
    );
    // The escrowed token is owned by the v3 vault's script hash, not the v1 vault's.
    let escrow = crate::tx::Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.vault().script_hash(),
        },
        AMOUNT_A,
    );
    assert_eq!(
        ipst.transaction().outputs[0].script_public_key,
        tpl.script_public_key(&escrow).unwrap()
    );
    let m = ipst.verify_against_terms(&tpl, None, NOW).unwrap();
    assert_eq!(m.kind, crate::tx::IpstKind::FundKcc20(LegIndex::Asset));
}

#[test]
fn a_refund_of_the_cash_vault_needs_no_proof() {
    let terms = label_terms(true, Cash::Kas, FundingMode::Revocable);
    let cash = cash_vault_utxo(&terms);
    for signer in [
        RefundSigner::Depositor,
        RefundSigner::Counterparty,
        RefundSigner::Authority,
    ] {
        let ipst = refund(
            &terms,
            LegIndex::Cash,
            signer,
            &cash,
            None,
            &fee_for_payer(),
        )
        .unwrap();
        assert!(ipst.proof().is_none());
        let m = ipst
            .verify_against_terms(&asset_template(), None, NOW)
            .unwrap();
        assert!(matches!(
            m.kind,
            crate::tx::IpstKind::Refund {
                leg: LegIndex::Cash,
                ..
            }
        ));
        // The vault input waits for the signer's signature; the budget is the v1 rule's.
        assert_eq!(ipst.pending(), vec![0, 1], "{signer:?}");
    }
}

#[test]
fn a_refund_of_the_asset_vault_takes_its_escrowed_token_home() {
    let terms = label_terms(true, Cash::Kas, FundingMode::Revocable);
    let w = World {
        terms: terms.clone(),
        tree: ListTree::build_with_salts(vec![terms.delivery_owner()], &[[1; 32]]).unwrap(),
        owner: terms.delivery_owner(),
    };
    let (authorizer, escrow, _) = vault_utxos(&w);
    let tpl = asset_template();
    let amount = terms.terms().fields.asset_leg.amount;
    let escrow = crate::tx::RefundEscrow {
        utxo: escrow,
        amount,
        is_minter: false,
        template: &tpl,
    };
    let ipst = refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Counterparty,
        &authorizer,
        Some(&escrow),
        &fee_for_payer(),
    )
    .unwrap();
    let m = ipst.verify_against_terms(&tpl, None, NOW).unwrap();
    assert!(matches!(
        m.kind,
        crate::tx::IpstKind::Refund {
            leg: LegIndex::Asset,
            with_token: true,
            ..
        }
    ));
    // The token input is owned by the vault: it takes no signature.
    assert_eq!(ipst.slots()[1].signer(), None);
    // The counterparty cannot refund without the token.
    assert_eq!(
        refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Counterparty,
            &authorizer,
            None,
            &fee_for_payer()
        )
        .unwrap_err()
        .code(),
        "TX_REFUND_SIGNER"
    );
}

#[test]
fn an_earmarked_depositor_refund_waits_for_the_expiry() {
    let terms = label_terms(false, Cash::Kas, FundingMode::Earmarked);
    let cash = cash_vault_utxo(&terms);
    let ipst = refund(
        &terms,
        LegIndex::Cash,
        RefundSigner::Depositor,
        &cash,
        None,
        &fee_for_payer(),
    )
    .unwrap();
    assert_eq!(ipst.transaction().lock_time, EXPIRY);
    let other = refund(
        &terms,
        LegIndex::Cash,
        RefundSigner::Counterparty,
        &cash,
        None,
        &fee_for_payer(),
    )
    .unwrap();
    assert_eq!(other.transaction().lock_time, 0);
    assert_eq!(
        refund(
            &terms,
            LegIndex::Cash,
            RefundSigner::Authority,
            &cash,
            None,
            &fee_for_payer()
        )
        .unwrap_err()
        .code(),
        "TX_REFUND_SIGNER"
    );
}

#[test]
fn a_utxo_at_another_address_is_refused() {
    let terms = label_terms(false, Cash::Kas, FundingMode::Revocable);
    let stray = utxo("stray", AUTHORIZER, crate::tx::p2pk(&[7; 32]), None);
    assert_eq!(
        refund(
            &terms,
            LegIndex::Cash,
            RefundSigner::Depositor,
            &stray,
            None,
            &fee_for_payer()
        )
        .unwrap_err()
        .code(),
        "TX_NOT_AT_VAULT"
    );
}

#[test]
fn the_committed_terms_are_the_worlds_the_proofs_are_bound_to() {
    for name in WORLDS {
        let path = testdata(&format!("e2e-{name}.terms.hex"));
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; run scripts/regen-zk-core-fixtures.sh",
                path.display()
            )
        });
        assert_eq!(
            committed.trim(),
            hex(world_named(name).terms.canonical()),
            "{name}: the world changed; run scripts/regen-zk-core-fixtures.sh"
        );
    }
}
