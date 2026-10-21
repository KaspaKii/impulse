// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v4 as shipped, with real receipts made at test time by the terms guest
//! (spec/V3-ZK.md 22.9, "Valid" and "The gate"). Terms v4 always name an authority, so every
//! settle needs the authority's signature, and the committed fixtures hold public keys only
//! (v4_common.rs). These tests therefore use the harness's throwaway keys (rule 1, docs/ENGINEERING-RULES.md, owner
//! exceptions of 2026-10-06 and 2026-10-10: random, never committed, never printed, erased on
//! drop), build the real vaults from them, make a Groth16 receipt for each vault input with
//! `impulse-zk-prove-terms` on this machine, and run every input in the pinned engine. The
//! witness and the proofs live in a temporary directory removed when the test ends.
//!
//! Ignored by default: each proof takes minutes and several GiB (Docker). Run by
//! `scripts/ci-zk.sh` with `--ignored --test-threads=1` after the prover is built:
//!
//!   cargo test -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1
//!
//! Each test also appends its measurements (script units, budgets, masses, against v1) to the
//! file named by IMPULSE_V4_UNITS_OUT, which scripts/measure-v4-units.sh turns into
//! docs/measurements/v4-zk-units.txt.

mod harness;
mod v4_common;
use harness::*;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::post_toccata_p2sh_sig_scanner;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use v4_common::*;

const CAP_COMPUTE: u64 = 450_000;
const CAP_TRANSIENT: u64 = 900_000;
const CAP_STORAGE: u64 = 450_000;

/// A removable temporary directory (removed on drop, also when the test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("impulse-v4-live-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

thread_local! {
    static PROVING: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Appends the raw proving data of this test's receipts to the measurements.
fn flush_proving() {
    PROVING.with(|p| {
        for line in p.borrow_mut().drain(..) {
            out_line(&line);
        }
    });
}

fn prover() -> PathBuf {
    let bin = repo_path("circuits/target/release/impulse-zk-prove-terms");
    assert!(
        bin.is_file(),
        "build the prover first: (cd circuits && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)"
    );
    bin
}

fn read_proof(path: &std::path::Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("proof file"))
            .expect("proof json");
    (
        unhex(v["proof"].as_str().expect("proof")),
        unhex(v["journal"].as_str().expect("journal")),
        unhex(v["image_id"].as_str().expect("image id")),
    )
}

/// The real receipt for vault input `idx` of `spec`: the witness is built from the terms and the
/// transaction, `impulse-zk-prove-terms` proves it, and the receipt's journal must be the J the
/// vault computes for itself.
fn prove(v: &V4, spec: &TxSpec, idx: usize, label: &str) -> Vec<u8> {
    let tmp = TempDir::new(label);
    let witness = tmp.0.join("witness.bin");
    std::fs::write(&witness, v.witness(spec, idx).to_bytes()).expect("write witness");
    let out = tmp.0.join("proof.json");
    let status = Command::new(prover())
        .arg("--witness")
        .arg(&witness)
        .arg("--out")
        .arg(&out)
        .arg("--timings")
        .arg(tmp.0.join("timings.json"))
        .status()
        .expect("run impulse-zk-prove-terms");
    assert!(
        status.success(),
        "impulse-zk-prove-terms failed for {label}: {status}"
    );
    // raw proving data of this receipt (cycles, segments, times), loaded machine: not a checkpoint
    if let Ok(t) = std::fs::read_to_string(tmp.0.join("timings.json")) {
        PROVING.with(|p| {
            p.borrow_mut()
                .push(format!("PROVE {label}: {}", t.trim().replace('\n', " ")))
        });
    }
    let (proof, journal, image_id) = read_proof(&out);
    assert_eq!(
        journal,
        v.journal(spec, idx).to_bytes(),
        "{label}: the receipt's journal is the J of this vault"
    );
    let want = unhex(
        std::fs::read_to_string(repo_path("circuits/IMAGE_ID_V4"))
            .unwrap()
            .trim(),
    );
    assert_eq!(image_id, want, "{label}: the receipt is of the terms guest");
    assert_eq!(proof.len(), 128);
    proof
}

/// `impulse-zk-prove-terms` refuses the witness of vault input `idx` of `spec` with `want` (code
/// and tag) and writes no receipt.
fn prover_refuses(v: &V4, spec: &TxSpec, idx: usize, want: &str) {
    let tmp = TempDir::new("refused");
    let witness = tmp.0.join("witness.bin");
    std::fs::write(&witness, v.witness(spec, idx).to_bytes()).expect("write witness");
    let out = tmp.0.join("proof.json");
    let run = Command::new(prover())
        .arg("--witness")
        .arg(&witness)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run impulse-zk-prove-terms");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "the prover made a receipt: {stderr}");
    assert!(stderr.contains(want), "expected {want}, got: {stderr}");
    assert!(!out.exists(), "no receipt is written");
}

/// A receipt of the forging guest (no checks, commits the journal it is given) for the same J.
fn prove_forged(v: &V4, spec: &TxSpec, idx: usize) -> Vec<u8> {
    let tmp = TempDir::new("forged");
    let jfile = tmp.0.join("journal.bin");
    std::fs::write(&jfile, v.journal(spec, idx).to_bytes()).expect("write journal");
    let out = tmp.0.join("proof.json");
    let status = Command::new(prover())
        .arg("--forge-journal")
        .arg(&jfile)
        .arg("--out")
        .arg(&out)
        .status()
        .expect("run the forging prover");
    assert!(status.success(), "forged proof failed: {status}");
    let (proof, journal, image_id) = read_proof(&out);
    assert_eq!(journal, v.journal(spec, idx).to_bytes());
    let terms_id = unhex(
        std::fs::read_to_string(repo_path("circuits/IMAGE_ID_V4"))
            .unwrap()
            .trim(),
    );
    assert_ne!(image_id, terms_id, "the forging guest is another image");
    proof
}

fn given(proofs: &[(usize, &[u8])]) -> Proofs {
    Proofs::Given(proofs.iter().map(|(i, p)| (*i, p.to_vec())).collect())
}

/// The settle of `v` with a real receipt per vault input, all inputs accepted.
fn settle_with_real_proofs(v: &V4, label: &str) -> (TxSpec, Vec<Vec<u8>>) {
    let base = v.settle(&Proofs::Zeros);
    let vaults = if v.w.external() { 1 } else { 2 };
    let proofs: Vec<Vec<u8>> = (0..vaults)
        .map(|i| prove(v, &base, i, &format!("{label}-{i}")))
        .collect();
    let given: Vec<(usize, &[u8])> = proofs
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.as_slice()))
        .collect();
    let spec = v.settle(&self::given(&given));
    spec.assert_all_accepted(&v.w, &format!("{label}: settle with real receipts"));
    (spec, proofs)
}

fn flip(proof: &[u8], byte: usize, bit: u8) -> Vec<u8> {
    let mut p = proof.to_vec();
    p[byte] ^= 1 << bit;
    p
}

// =============================================================================================
// Measurements
// =============================================================================================

fn units_of(w: &World, spec: &TxSpec, idx: usize) -> u64 {
    let (tx, entries) = spec.build(w);
    let run = measure(&tx, &entries, idx);
    assert_accepted(&run, "measured input");
    run.used.0
}

fn sigops(w: &World, spec: &TxSpec, idx: usize) -> u64 {
    let (tx, entries) = spec.build(w);
    post_toccata_p2sh_sig_scanner(
        &tx.inputs[idx].signature_script,
        &entries[idx].script_public_key,
    )
}

fn out_line(line: &str) {
    eprintln!("{line}");
    if let Some(path) = std::env::var_os("IMPULSE_V4_UNITS_OUT") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open measurements");
        writeln!(f, "{line}").expect("write measurements");
    }
}

/// One settle shape: units per vault input on v4 (real receipts) against v1 with the same terms
/// otherwise, the budgets, sig-ops and the masses at exact covering budgets, asserted against D63.
fn measure_settle(label: &str, v: &V4, spec: &TxSpec) {
    let v1 = World::new(Mode::new(true, v.w.mode.cash, REVOCABLE));
    let spec1 = v1.settle();
    let vaults = if v.w.external() { 1 } else { 2 };
    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let (tight, budgets, _) = tighten(&v.w, spec);
    let (tx, entries) = tight.build(&v.w);
    let non = calc.calc_non_contextual_masses(&tx);
    let storage = calc
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries))
        .map(|c| c.storage_mass);
    for idx in 0..vaults {
        let (u4, u1) = (units_of(&v.w, spec, idx), units_of(&v1, &spec1, idx));
        out_line(&format!(
            "| {label} | {} | {u4} | {u1} | {} | {} | {} | {}, {} | {} |",
            if idx == 0 {
                "asset vault"
            } else {
                "cash vault"
            },
            u4 - u1,
            covering_budget(kaspa_consensus_core::mass::ScriptUnits(u4)),
            tx.inputs[idx].signature_script.len(),
            sigops(&v.w, spec, idx),
            sigops(&v1, &spec1, idx),
            if idx == 0 {
                "v4 and v1 redeem scripts"
            } else {
                ""
            },
        ));
    }
    out_line(&format!(
        "MASS | {label} | budgets {budgets:?} | compute {} | transient {} | storage {} | inputs {} | outputs {}",
        non.compute_mass,
        non.transient_mass,
        storage.map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
        tx.inputs.len(),
        tx.outputs.len()
    ));
    assert!(
        non.compute_mass <= CAP_COMPUTE && non.transient_mass <= CAP_TRANSIENT,
        "{label}: exceeds a D63 cap (compute {}, transient {}): the shape is not shipped (ZK_TX_MASS)",
        non.compute_mass,
        non.transient_mass
    );
    let _ = CAP_STORAGE;
}

fn measure_refund(label: &str, v: &V4, spec: &TxSpec, leg: i64, role: Role) {
    let v1 = World::new(Mode::new(true, v.w.mode.cash, v.w.mode.funding));
    let u4 = units_of(&v.w, spec, 0);
    let u1 = units_of(&v1, &v1.refund(leg, role), 0);
    out_line(&format!(
        "| {label} | {u4} | {u1} | {} |",
        u4 as i64 - u1 as i64
    ));
}

// =============================================================================================
// Tests
// =============================================================================================

/// KAS cash: both vault inputs of the settle carry their own receipt. Then the gate: a flipped
/// proof bit, the other vault's receipt, a receipt for a transaction that differs in one field of
/// J, a receipt of the forging guest, and the refund receipts in the settle and the reverse.
#[test]
#[ignore = "makes real Groth16 proofs (minutes each, Docker); run by scripts/ci-zk.sh"]
fn v4_live_settle_and_refund_kas_cash() {
    let v = V4::live(Kind::Real, CASH_KAS, REVOCABLE);
    let (spec, proofs) = settle_with_real_proofs(&v, "kas");
    out_line("| Shape | Input | v4 units | v1 units | difference | v4 budget (units) | v4 sigscript bytes | sig-ops (v4, v1) | note |");
    out_line("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    measure_settle("settle, KAS cash", &v, &spec);

    // [T4] after the gate: the receipt passes the precompile, the missing signature is refused
    // BEFORE it (the script checks the signature first), so a valid receipt cannot stand in for it
    let mut unsigned = spec.clone();
    unsigned.inputs[0] = In::settle_v4(
        &v.w.asset_vault,
        None,
        spec.inputs[0].value,
        proofs[0].clone(),
        v.shape_i64(),
        (ASSET_COV.as_bytes(), v.cov_c()),
    );
    assert_refused_before_gate(&unsigned.run(&v.w, 0), "[T4] real receipt, no signature");

    // the gate: a flipped bit of the proof, anywhere in the 128 bytes
    for (byte, bit) in [
        (0usize, 0u8),
        (31, 7),
        (32, 0),
        (64, 3),
        (96, 5),
        (127, 0),
        (127, 7),
    ] {
        let mut bad = spec.clone();
        v.with_proof(&mut bad, 0, flip(&proofs[0], byte, bit));
        assert_gate_refused(
            &bad.run(&v.w, 0),
            &format!("flipped bit {bit} of byte {byte}"),
        );
    }
    // a proof of another vault: the cash vault's receipt at the asset vault and the reverse
    let mut other = spec.clone();
    v.with_proof(&mut other, 0, proofs[1].clone());
    assert_gate_refused(
        &other.run(&v.w, 0),
        "the cash vault's receipt at the asset vault",
    );
    let mut other = spec.clone();
    v.with_proof(&mut other, 1, proofs[0].clone());
    assert_gate_refused(
        &other.run(&v.w, 1),
        "the asset vault's receipt at the cash vault",
    );

    // a receipt for a transaction differing in exactly one field of J: the control's receipt
    type Change = (&'static str, fn(&mut TxSpec));
    let changes: Vec<Change> = vec![
        ("value of an input", |s| s.inputs[1].value += 1),
        ("scriptPubKey of an input", |s| {
            s.inputs[2].spk = stranger_spk()
        }),
        ("value of an output", |s| s.outputs[2].value += 1),
        ("scriptPubKey of an output", |s| {
            s.outputs[1].spk = stranger_spk()
        }),
        ("lock time", |s| s.lock_time += 1),
    ];
    for (name, change) in changes {
        let mut faulty = spec.clone();
        change(&mut faulty);
        assert_gate_refused(
            &faulty.run(&v.w, 0),
            &format!("receipt for another transaction: {name}"),
        );
    }
    // the covenant ID of an input of the view: [T10] refuses a covenant ID on
    // the cash vault input before the gate (spec/V3-ZK.md 22.15), so the J field is bound twice
    let mut faulty = spec.clone();
    faulty.inputs[1].cov = Some(DECOY_COV);
    assert_refused_before_gate(
        &faulty.run(&v.w, 0),
        "[T10] a covenant ID on the cash vault input, real receipts",
    );

    // the forging guest commits the same J without checking: its image ID is not the vault's
    let forged = prove_forged(&v, &spec, 0);
    let mut f = spec.clone();
    v.with_proof(&mut f, 0, forged);
    assert_gate_refused(
        &f.run(&v.w, 0),
        "a receipt of another image ID (forging guest, same J)",
    );

    // refunds: the depositor of a revocable leg, the counterparty (token goes home with it), the
    // authority on a KAS cash leg
    let r_dep = v.refund(ASSET_LEG, Role::Seller, &Proofs::Zeros);
    let p = prove(&v, &r_dep, 0, "refund-asset-depositor");
    let r_dep = v.refund(ASSET_LEG, Role::Seller, &given(&[(0, &p)]));
    r_dep.assert_all_accepted(&v.w, "refund of the asset leg by the depositor");
    out_line("");
    out_line("Refund: script units per vault input, template v4 against template v1 (random throwaway keys)");
    out_line("| Refund | v4 units | v1 units | difference |");
    out_line("| --- | --- | --- | --- |");
    measure_refund("asset leg, depositor", &v, &r_dep, ASSET_LEG, Role::Seller);

    let r_cp = v.refund(ASSET_LEG, Role::Buyer, &Proofs::Zeros);
    let p_cp = prove(&v, &r_cp, 0, "refund-asset-counterparty");
    let r_cp = v.refund(ASSET_LEG, Role::Buyer, &given(&[(0, &p_cp)]));
    r_cp.assert_all_accepted(&v.w, "refund of the asset leg by the counterparty");
    measure_refund("asset leg, counterparty", &v, &r_cp, ASSET_LEG, Role::Buyer);

    let r_auth = v.refund(CASH_LEG, Role::Authority, &Proofs::Zeros);
    let p_auth = prove(&v, &r_auth, 0, "refund-cash-authority");
    let r_auth = v.refund(CASH_LEG, Role::Authority, &given(&[(0, &p_auth)]));
    r_auth.assert_all_accepted(&v.w, "refund of the KAS cash leg by the authority");
    measure_refund(
        "cash leg (KAS), authority",
        &v,
        &r_auth,
        CASH_LEG,
        Role::Authority,
    );

    // the mode byte: a refund's receipt in a settle and a settle's receipt in a refund
    let mut s = spec.clone();
    v.with_proof(&mut s, 0, p.clone());
    assert_gate_refused(&s.run(&v.w, 0), "a refund receipt in a settle");
    let mut r = r_dep.clone();
    v.with_proof(&mut r, 0, proofs[0].clone());
    assert_gate_refused(&r.run(&v.w, 0), "a settle receipt in a refund");
    // a refund's receipt names its signer and leg: the depositor's receipt does not serve the
    // counterparty, and the asset leg's receipt does not serve a refund of the other leg
    let mut r = r_cp.clone();
    v.with_proof(&mut r, 0, p.clone());
    assert_gate_refused(
        &r.run(&v.w, 0),
        "the depositor's refund receipt for the counterparty",
    );
    flush_proving();
}

/// KCC-20 cash: two receipts in one settle, four view inputs and outputs each; a refund of the
/// cash leg by its depositor.
#[test]
#[ignore = "makes real Groth16 proofs (minutes each, Docker); run by scripts/ci-zk.sh"]
fn v4_live_settle_and_refund_kcc20_cash() {
    let v = V4::live(Kind::Real, CASH_KCC20, REVOCABLE);
    let (spec, proofs) = settle_with_real_proofs(&v, "kcc20");
    measure_settle("settle, KCC-20 cash", &v, &spec);
    let mut bad = spec.clone();
    v.with_proof(&mut bad, 1, flip(&proofs[1], 5, 2));
    assert_gate_refused(&bad.run(&v.w, 1), "KCC-20 cash vault, flipped bit");
    // [T10] with real receipts (spec/V3-ZK.md 22.15): a foreign covenant on the fee input leaves the
    // view and both journals as they are, so both receipts still fit; the script refuses before the
    // gate at both vault inputs
    let mut foreign = spec.clone();
    let fee_at = foreign.inputs.len() - 1;
    foreign.inputs[fee_at].cov = Some(DECOY_COV);
    for idx in 0..2 {
        assert_eq!(
            v.journal(&foreign, idx).to_bytes(),
            v.journal(&spec, idx).to_bytes()
        );
        assert_refused_before_gate(
            &foreign.run(&v.w, idx),
            &format!("[T10] a foreign covenant on the fee input, real receipt at input {idx}"),
        );
    }
    // [H5] with a real receipt (spec/V3-ZK.md 22.16): the cash vault omitted and a cash token
    // owned by the asset vault at the cash escrow slot. The honest settle's receipt does not fit
    // (input 1 of the view differs), so the gate refuses it, and the prover refuses to make one for
    // this view (the statement the guest runs fails at [H5])
    let mut h5 = spec.clone();
    h5.inputs[1] = In::plain(AUTH_VALUE);
    h5.inputs[World::CASH_ESCROW_IDX] = In::token(
        CASH_TOKEN.compile(Kcc20State::new(
            Owner::script_hash(v.w.asset_vault.script_hash()),
            v.w.terms.amount_b,
        )),
        CASH_TOKEN.cov,
        vec![v.w.delivered_cash()],
        0,
    );
    assert_ne!(v.journal(&h5, 0).to_bytes(), v.journal(&spec, 0).to_bytes());
    assert_gate_refused(
        &h5.run(&v.w, 0),
        "[H5] the cash vault omitted, the honest receipt",
    );
    prover_refuses(&v, &h5, 0, "ZK_H_STATEMENT_FALSE [H5]");
    let r = v.refund(CASH_LEG, Role::Buyer, &Proofs::Zeros);
    let p = prove(&v, &r, 0, "refund-cash-depositor");
    let r = v.refund(CASH_LEG, Role::Buyer, &given(&[(0, &p)]));
    r.assert_all_accepted(&v.w, "refund of the KCC-20 cash leg by the depositor");
    measure_refund(
        "cash leg (KCC-20), depositor",
        &v,
        &r,
        CASH_LEG,
        Role::Buyer,
    );
    flush_proving();
}

/// External cash: one vault, one receipt; the authority signs for the off-chain leg.
#[test]
#[ignore = "makes a real Groth16 proof (minutes, Docker); run by scripts/ci-zk.sh"]
fn v4_live_settle_external_cash() {
    let v = V4::live(Kind::Real, CASH_EXTERNAL, REVOCABLE);
    assert!(v.w.external());
    let (spec, proofs) = settle_with_real_proofs(&v, "external");
    measure_settle("settle, external cash", &v, &spec);
    let mut bad = spec.clone();
    v.with_proof(&mut bad, 0, flip(&proofs[0], 100, 4));
    assert_gate_refused(&bad.run(&v.w, 0), "external cash, flipped bit");
    flush_proving();
}

/// An earmarked leg: the depositor's refund opens at expiry; the receipt is made for a lock time at
/// the expiry, so it is not valid one DAA score earlier.
#[test]
#[ignore = "makes a real Groth16 proof (minutes, Docker); run by scripts/ci-zk.sh"]
fn v4_live_refund_earmarked_depositor_at_expiry() {
    let v = V4::live(Kind::Real, CASH_KAS, EARMARKED);
    let r = v.refund(ASSET_LEG, Role::Seller, &Proofs::Zeros);
    let p = prove(&v, &r, 0, "refund-earmarked");
    let r = v.refund(ASSET_LEG, Role::Seller, &given(&[(0, &p)]));
    r.assert_all_accepted(&v.w, "earmarked refund by the depositor at expiry");
    // one DAA score earlier is another J: the receipt does not carry over
    let mut early = r.clone();
    early.lock_time -= 1;
    assert_gate_refused(
        &early.run(&v.w, 0),
        "the same receipt one DAA score before expiry",
    );
    flush_proving();
}

/// Known limitation L20 (spec/V3-ZK.md 22.15), with real receipts. The cash token owned by the
/// asset vault rides along in the asset leg's refund at a fee position: the view and J are those
/// of the plain refund, so the terms guest proves the statement (its receipt is made for the plain
/// refund and fits both), and the script refuses the spend before the gate ([T11]).
#[test]
#[ignore = "makes real Groth16 proofs (minutes each, Docker); run by scripts/ci-zk.sh"]
fn v4_live_a_token_of_another_covenant_is_refused() {
    let v = V4::live(Kind::Real, CASH_KCC20, REVOCABLE);
    let plan = v.refund(ASSET_LEG, Role::Seller, &Proofs::Zeros);
    let p = prove(&v, &plan, 0, "refund-asset");
    let ok = v.refund(ASSET_LEG, Role::Seller, &given(&[(0, &p)]));
    ok.assert_all_accepted(&v.w, "refund of the asset leg with a real receipt");
    let mut l20 = ok.clone();
    let at = l20.inputs.len() - 1;
    misdirected_cash_token(&v, &mut l20, at);
    assert_eq!(
        v.journal(&l20, 0).to_bytes(),
        v.journal(&ok, 0).to_bytes(),
        "the L20 refund has the plain refund's journal: the receipt fits it"
    );
    assert_refused_before_gate(&l20.run(&v.w, 0), "[T11] L20 refund, real receipt");
    flush_proving();
}
