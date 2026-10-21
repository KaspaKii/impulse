// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v4 around the proof gate, in the probe (spec/V3-ZK.md 22.5, 22.9): the verify call is
//! replaced by a comparison of sha256(J) with the proof, so a "proof" is sha256 of the journal the
//! test builds on the host. That tests, in the pinned engine and without a receipt, that the host
//! journal is the journal the script builds, field by field (the faulty case keeps the proof of the
//! control and changes one thing), and that every script require refuses. The real gate is in
//! v4_gate.rs with real receipts.
//!
//! Tags with a failing test here: [T1], [T2], [T3], [T4], [T5], [T6], [T7], [T8], [T9], [T10], [T11].
//! Each refusal is shown against an accepted control that differs only in the fault. [T10] and
//! [T11] are the covenant-ID checks of every input (spec/V3-ZK.md 22.15).

mod harness;
mod v4_common;
use harness::*;
use kaspa_txscript_errors::TxScriptError;
use v4_common::*;

fn probe(cash: u8) -> V4 {
    V4::live(Kind::Probe, cash, REVOCABLE)
}

/// The world of the require tests: the probe, or the shipped template v4 (the real verify call).
fn world(kind: Kind, cash: u8) -> V4 {
    V4::live(kind, cash, REVOCABLE)
}

/// The control settles; the faulty spec is refused at `idx` by the script (a require or the
/// comparison with sha256(J)), not by the meter or a malformed transaction.
///
/// On the shipped template (Kind::Real) no receipt exists, so the same pair reads differently and
/// proves the same thing: the control, with the same zero proof, is refused BY the precompile (the
/// gate was reached and charged), and the faulty spec is refused BEFORE the gate (fewer units than
/// the precompile's fixed cost), so the require under test is what stopped it.
fn flips(v: &V4, control: &TxSpec, faulty: &TxSpec, idx: usize, label: &str) {
    match v.kind {
        Kind::Probe => {
            control.assert_all_accepted(&v.w, &format!("{label} (control)"));
            assert_refused(&faulty.run(&v.w, idx), label);
        }
        Kind::Real => {
            assert_gate_refused(
                &control.run(&v.w, 0),
                &format!("{label} (control, shipped)"),
            );
            assert_refused_before_gate(&faulty.run(&v.w, idx), &format!("{label} (shipped)"));
        }
    }
}

fn fee_idx(spec: &TxSpec) -> usize {
    spec.inputs.len() - 1
}

// =============================================================================================
// Accepted
// =============================================================================================

#[test]
fn v4_probe_settle_accepted_every_cash_kind() {
    for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
        let v = probe(cash);
        v.settle(&Proofs::Probe)
            .assert_all_accepted(&v.w, &format!("cash kind {cash}"));
    }
}

#[test]
fn v4_probe_refund_accepted() {
    use Role::*;
    for signer in [Seller, Buyer, Authority] {
        let v = probe(CASH_KCC20);
        v.refund(ASSET_LEG, signer, &Proofs::Probe)
            .assert_all_accepted(&v.w, "asset leg");
        v.refund(CASH_LEG, signer, &Proofs::Probe)
            .assert_all_accepted(&v.w, "KCC-20 cash leg");
        let v = probe(CASH_KAS);
        v.refund(CASH_LEG, signer, &Proofs::Probe)
            .assert_all_accepted(&v.w, "KAS cash leg");
    }
    // an earmarked trade: the depositor's refund opens at expiry
    let v = V4::live(Kind::Probe, CASH_KAS, EARMARKED);
    v.refund(ASSET_LEG, Seller, &Proofs::Probe)
        .assert_all_accepted(&v.w, "earmarked, depositor, at expiry");
}

// =============================================================================================
// Settle requires
// =============================================================================================

fn t1(kind: Kind) {
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    // a second deposit of the cash vault, spent at the fee input's place (input 3): nothing else
    // of the transaction changes, so only [T1] stands between it and the gate
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    let value = FEE_VALUE;
    faulty.inputs.insert(
        at,
        In::settle_v4(
            v.w.cash_vault(),
            Some(Role::Authority),
            value,
            vec![0; 128],
            v.shape_i64(),
            (ASSET_COV.as_bytes(), v.cov_c()),
        ),
    );
    faulty.outputs.last_mut().expect("change").value += value;
    v.reprobe(&mut faulty);
    flips(&v, &control, &faulty, at, "[T1] vault at input 3");
}

fn t2(kind: Kind) {
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    // one below: nIn = 1
    let mut faulty = control.clone();
    set_view(&mut faulty.inputs[0], Some(1), None);
    v.reprobe(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T2] nIn = 1");
    // one above: nIn = 5, with a transaction that has five inputs
    let mut faulty = control.clone();
    faulty.inputs.push(In::plain(FEE_VALUE));
    faulty.inputs.push(In::plain(FEE_VALUE));
    set_view(&mut faulty.inputs[0], Some(5), None);
    v.reprobe(&mut faulty);
    assert!(faulty.inputs.len() >= 5);
    flips(&v, &control, &faulty, 0, "[T2] nIn = 5");
    // beyond the transaction: nIn = 4 with three inputs
    let mut faulty = control.clone();
    faulty.inputs.pop(); // the fee input
    faulty.outputs.pop();
    set_view(&mut faulty.inputs[0], Some(4), None);
    v.fill_zeros(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T2] nIn beyond the transaction");
}

fn t3(kind: Kind) {
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    let mut faulty = control.clone();
    set_view(&mut faulty.inputs[0], None, Some(1));
    v.reprobe(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T3] nOut = 1");
    let mut faulty = control.clone();
    faulty.outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
    faulty.outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
    set_view(&mut faulty.inputs[0], None, Some(5));
    v.reprobe(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T3] nOut = 5");
    let mut faulty = control.clone();
    faulty.outputs.pop(); // the fee change output: three outputs remain
    set_view(&mut faulty.inputs[0], None, Some(4));
    v.fill_zeros(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T3] nOut beyond the transaction");
}

fn t4(kind: Kind) {
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    // signed by the seller, not the authority
    let mut faulty = control.clone();
    set_signer(&mut faulty.inputs[0], Some(Role::Seller));
    flips(&v, &control, &faulty, 0, "[T4] seller's signature");
    // no signature at all
    let mut faulty = control.clone();
    set_signer(&mut faulty.inputs[0], None);
    flips_any(&v, &control, &faulty, 0, "[T4] no signature");
}

/// As `flips` for a refusal that is not a plain VerifyError (a null signature is refused by the
/// signature check itself).
fn flips_any(v: &V4, control: &TxSpec, faulty: &TxSpec, idx: usize, label: &str) {
    match v.kind {
        Kind::Probe => {
            control.assert_all_accepted(&v.w, &format!("{label} (control)"));
            assert!(
                faulty.run(&v.w, idx).result.is_err(),
                "{label}: expected a refusal"
            );
        }
        Kind::Real => {
            assert_gate_refused(
                &control.run(&v.w, 0),
                &format!("{label} (control, shipped)"),
            );
            assert_refused_before_gate(&faulty.run(&v.w, idx), &format!("{label} (shipped)"));
        }
    }
}

fn t8_t9(kind: Kind) {
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    // the spending input is final (sequence at its maximum): the lock time would not bind
    let mut faulty = control.clone();
    faulty.inputs[0].sequence = u64::MAX;
    v.reprobe(&mut faulty);
    flips_any(&v, &control, &faulty, 0, "[T8] final sequence, settle");
    // a lock time in the timestamp domain is not a DAA score
    let mut faulty = control.clone();
    faulty.lock_time = 500_000_000_001;
    v.reprobe(&mut faulty);
    flips_any(
        &v,
        &control,
        &faulty,
        0,
        "[T8] timestamp-domain lock time, settle",
    );
    // the same two faults against a refund
    let rc = v.refund(CASH_LEG, Role::Buyer, &Proofs::Probe);
    let mut rf = rc.clone();
    rf.inputs[0].sequence = u64::MAX;
    v.reprobe(&mut rf);
    flips_any(&v, &rc, &rf, 0, "[T9] final sequence, refund");
    let mut rf = rc.clone();
    rf.lock_time = 500_000_000_001;
    v.reprobe(&mut rf);
    flips_any(&v, &rc, &rf, 0, "[T9] timestamp-domain lock time, refund");
}

// =============================================================================================
// Refund requires
// =============================================================================================

fn t5(kind: Kind) {
    let v = world(kind, CASH_KCC20);
    let control = v.refund(ASSET_LEG, Role::Seller, &Proofs::Probe);
    // the named signer did not sign: the buyer's key signs for the seller's name
    let mut faulty = control.clone();
    set_signer(&mut faulty.inputs[0], Some(Role::Buyer));
    flips(&v, &control, &faulty, 0, "[T5] signed by another key");
    let mut faulty = control.clone();
    set_signer(&mut faulty.inputs[0], None);
    flips_any(&v, &control, &faulty, 0, "[T5] no signature");
}

fn t6(kind: Kind) {
    let v = world(kind, CASH_KCC20);
    let control = v.refund(ASSET_LEG, Role::Seller, &Proofs::Probe);
    let mut faulty = control.clone();
    if let Spend::RefundV4 { leg, .. } = &mut faulty.inputs[0].spend {
        *leg = 2;
    }
    v.reprobe(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T6] leg 2");
}

fn t7(kind: Kind) {
    let v = world(kind, CASH_KCC20);
    let control = v.refund(ASSET_LEG, Role::Seller, &Proofs::Probe);
    for (n_in, n_out, label) in [(None, Some(0), "nOut = 0"), (None, Some(3), "nOut = 3")] {
        let mut faulty = control.clone();
        set_view(&mut faulty.inputs[0], n_in, n_out);
        v.reprobe(&mut faulty);
        flips(&v, &control, &faulty, 0, &format!("[T7] {label}"));
    }
    // the input bounds on a refund whose inputs carry no covenant (a KAS cash leg and two plain
    // inputs), so that [T11] has nothing to refuse and [T7] alone stands
    let v = world(kind, CASH_KAS);
    let mut control = v.refund(CASH_LEG, Role::Buyer, &Proofs::Probe);
    let at = fee_idx(&control);
    control.inputs.insert(at, In::plain(FEE_VALUE));
    control.outputs.last_mut().expect("change").value += FEE_VALUE;
    v.reprobe(&mut control);
    assert_eq!(control.inputs.len(), 3);
    for (n_in, label) in [(0, "nIn = 0"), (3, "nIn = 3")] {
        let mut faulty = control.clone();
        set_view(&mut faulty.inputs[0], Some(n_in), None);
        v.reprobe(&mut faulty);
        flips(&v, &control, &faulty, 0, &format!("[T7] {label}"));
    }
    // beyond the transaction: a KAS cash leg refund has one vault input and the fee input; drop the
    // fee input and name two
    let v = world(kind, CASH_KAS);
    let control = v.refund(CASH_LEG, Role::Buyer, &Proofs::Probe);
    let mut faulty = control.clone();
    faulty.inputs.pop();
    set_view(&mut faulty.inputs[0], Some(2), None);
    v.fill_zeros(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T7] nIn beyond the transaction");
    let mut faulty = control.clone();
    faulty.outputs.pop();
    set_view(&mut faulty.inputs[0], None, Some(2));
    v.fill_zeros(&mut faulty);
    flips(&v, &control, &faulty, 0, "[T7] nOut beyond the transaction");
}

// =============================================================================================
// Known limitation L20: a token of another covenant at a vault's script hash
// =============================================================================================

// =============================================================================================
// The journal, field by field: the control's proof, one field of the transaction changed
// =============================================================================================

/// Each change is to exactly one field of J. The proof of the control no longer matches.
#[test]
fn v4_journal_one_field_changes() {
    let v = probe(CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    control.assert_all_accepted(&v.w, "control");
    type Change = (&'static str, fn(&mut TxSpec));
    let changes: Vec<Change> = vec![
        ("value of input 1", |s| s.inputs[1].value += 1),
        ("scriptPubKey of input 2", |s| {
            s.inputs[2].spk = stranger_spk()
        }),
        // [T10] also refuses this one before the comparison
        ("covenant ID of input 1", |s| {
            s.inputs[1].cov = Some(DECOY_COV)
        }),
        ("value of output 2", |s| s.outputs[2].value += 1),
        ("scriptPubKey of output 2", |s| {
            s.outputs[2].spk = stranger_spk()
        }),
        ("lock time", |s| s.lock_time += 1),
        // [T10] also refuses this one before the comparison
        ("count of the asset covenant", |s| {
            // one more input of the asset covenant, after the view
            let mut extra = In::plain(FEE_VALUE);
            extra.cov = Some(ASSET_COV);
            s.inputs.push(extra);
        }),
    ];
    for (name, change) in changes {
        let mut faulty = control.clone();
        change(&mut faulty);
        let (tx, entries) = faulty.build(&v.w);
        let _ = (&tx, &entries);
        let run = faulty.run(&v.w, 0);
        assert!(
            run.result.is_err(),
            "J field not covered: {name}: the control's proof still passes"
        );
        assert!(
            matches!(
                run.result,
                Err(TxScriptError::VerifyError) | Err(TxScriptError::EvalFalse)
            ),
            "{name}: expected the comparison with sha256(J) to refuse, got {:?}",
            run.result
        );
    }
    // an argument that enters J: the covenant IDs and the sizes
    let mut faulty = control.clone();
    if let Spend::SettleV4 { cov_c, .. } = &mut faulty.inputs[0].spend {
        *cov_c = [0xEE; 32];
    }
    assert_refused(&faulty.run(&v.w, 0), "cov_c argument");
    let mut faulty = control.clone();
    if let Spend::SettleV4 { cov_a, .. } = &mut faulty.inputs[0].spend {
        *cov_a = [0xEE; 32];
    }
    assert_refused(&faulty.run(&v.w, 0), "cov_a argument");
    // the signer of a refund and its leg
    let rc = probe(CASH_KCC20).refund(ASSET_LEG, Role::Seller, &Proofs::Probe);
    let v = probe(CASH_KCC20);
    let rc = {
        let _ = &rc;
        v.refund(ASSET_LEG, Role::Seller, &Proofs::Probe)
    };
    rc.assert_all_accepted(&v.w, "refund control");
    let mut f = rc.clone();
    // the buyer names and signs for itself: [T5] holds, only the signer field of J differs
    if let Spend::RefundV4 { named, signer, .. } = &mut f.inputs[0].spend {
        *named = v.w.xonly(Role::Buyer);
        *signer = Some(Role::Buyer);
    }
    assert_refused(&f.run(&v.w, 0), "refund signer");
    let mut f = rc.clone();
    if let Spend::RefundV4 { leg, .. } = &mut f.inputs[0].spend {
        *leg = 1;
    }
    assert_refused(&f.run(&v.w, 0), "refund leg");
    // a settle's proof does not open a refund and the reverse: the mode byte
    let settle = v.settle(&Proofs::Probe);
    let sj = match &settle.inputs[0].spend {
        Spend::SettleV4 { proof, .. } => proof.clone(),
        _ => unreachable!(),
    };
    let mut f = rc.clone();
    set_proof(&mut f.inputs[0], sj);
    assert_refused(&f.run(&v.w, 0), "mode byte: settle proof in a refund");
    let rj = match &rc.inputs[0].spend {
        Spend::RefundV4 { proof, .. } => proof.clone(),
        _ => unreachable!(),
    };
    let mut f = settle.clone();
    set_proof(&mut f.inputs[0], rj);
    assert_refused(&f.run(&v.w, 0), "mode byte: refund proof in a settle");
    let _ = fee_idx(&settle);
}

// =============================================================================================
// The covenant ID of every input (spec/V3-ZK.md 22.15)
// =============================================================================================

/// `n` plain inputs (no covenant) inserted before the fee input, their KAS to the change.
fn more_fee_inputs(spec: &mut TxSpec, n: usize) {
    let at = fee_idx(spec);
    for _ in 0..n {
        spec.inputs.insert(at, In::plain(FEE_VALUE));
    }
    spec.outputs.last_mut().expect("change").value += FEE_VALUE * n as u64;
}

fn t10(kind: Kind) {
    // fee inputs without a covenant pass, up to eight inputs in all
    for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
        let v = world(kind, cash);
        let mut control = v.settle(&Proofs::Probe);
        let room = 8 - control.inputs.len();
        more_fee_inputs(&mut control, room);
        assert_eq!(control.inputs.len(), 8);
        let mut nine = control.clone();
        more_fee_inputs(&mut nine, 1);
        flips(
            &v,
            &control,
            &nine,
            0,
            &format!("[T10] nine inputs, cash kind {cash}"),
        );
    }
    let v = world(kind, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    // a token of another covenant at the fee position
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty.inputs[at].cov = Some(DECOY_COV);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T10] a foreign covenant on the fee input",
    );
    // a second input of the asset covenant at input 3, where KAS cash has a fee input (covC is zero)
    let mut faulty = control.clone();
    let mut extra = In::plain(FEE_VALUE);
    extra.cov = Some(ASSET_COV);
    faulty.inputs.insert(3, extra);
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T10] the asset covenant at input 3",
    );
    // the cash vault (input 1) runs its own covA/covC arguments: a foreign covenant on the fee
    // input is refused there too, for KAS and for KCC-20 cash, each against its control
    for cash in [CASH_KAS, CASH_KCC20] {
        let v = world(kind, cash);
        let control = v.settle(&Proofs::Probe);
        let mut faulty = control.clone();
        let at = fee_idx(&faulty);
        faulty.inputs[at].cov = Some(DECOY_COV);
        flips(
            &v,
            &control,
            &faulty,
            1,
            &format!(
                "[T10] a foreign covenant on the fee input, at the cash vault, cash kind {cash}"
            ),
        );
    }
    // a covenant ID on a vault slot: the cash vault at input 1
    let mut faulty = control.clone();
    faulty.inputs[1].cov = Some(DECOY_COV);
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T10] a covenant ID on the cash vault input",
    );
    // the escrow slot of external cash is input 1: the asset covenant at input 2 is refused there
    let v = world(kind, CASH_EXTERNAL);
    let control = v.settle(&Proofs::Probe);
    let mut faulty = control.clone();
    let mut extra = In::plain(FEE_VALUE);
    extra.cov = Some(ASSET_COV);
    faulty.inputs.insert(2, extra);
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T10] external cash, the asset covenant at input 2",
    );
    // KCC-20 cash: the cash token owned by the asset vault rides along at a fee position
    let v = world(kind, CASH_KCC20);
    let control = v.settle(&Proofs::Probe);
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    misdirected_cash_token(&v, &mut faulty, at);
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T10] a second cash token at a fee position",
    );
}

fn t11(kind: Kind) {
    let v = world(kind, CASH_KCC20);
    let control = v.refund(ASSET_LEG, Role::Seller, &Proofs::Probe);
    // L20: the cash token owned by the asset vault, taken by the asset leg's refund. The view and
    // J are the control's, so the control's proof still fits; only [T11] refuses.
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    misdirected_cash_token(&v, &mut faulty, at);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T11] L20: a cash token at the asset vault",
    );
    // a foreign covenant on the fee input
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty.inputs[at].cov = Some(DECOY_COV);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T11] a foreign covenant on the fee input",
    );
    // fee inputs without a covenant pass up to eight inputs; nine are refused
    let mut eight = control.clone();
    let room = 8 - eight.inputs.len();
    more_fee_inputs(&mut eight, room);
    let mut nine = eight.clone();
    more_fee_inputs(&mut nine, 1);
    flips(&v, &eight, &nine, 0, "[T11] nine inputs");
    // the depositor's refund without the token: a one-input view. The escrowed token at input 1
    // outside the view is refused, though it carries the leg's covenant.
    let mut alone = control.clone();
    alone.inputs.remove(1);
    alone.outputs.remove(1);
    set_view(&mut alone.inputs[0], Some(1), Some(1));
    v.reprobe(&mut alone);
    let mut faulty = control.clone();
    set_view(&mut faulty.inputs[0], Some(1), Some(1));
    v.reprobe(&mut faulty);
    flips(
        &v,
        &alone,
        &faulty,
        0,
        "[T11] the leg's covenant at input 1 of a one-input view",
    );
    // a two-input view whose input 1 carries a covenant other than the leg's (the view, and so J,
    // are the faulty spec's own, so its proof fits; only [T11] refuses)
    let mut faulty = control.clone();
    faulty.inputs[1].cov = Some(DECOY_COV);
    // the token's output follows its input's covenant, or the engine refuses the genesis
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("token output")
        .covenant_id = DECOY_COV;
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T11] the wrong covenant at input 1 of a two-input view",
    );
    // a KAS cash leg: no input but the vault and the fee may carry anything but none
    let v = world(kind, CASH_KAS);
    let control = v.refund(CASH_LEG, Role::Buyer, &Proofs::Probe);
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty.inputs[at].cov = Some(ASSET_COV);
    v.reprobe(&mut faulty);
    flips(
        &v,
        &control,
        &faulty,
        0,
        "[T11] the asset covenant beside a KAS cash refund",
    );
}

#[test]
fn v4_t10_covenant_ids_of_every_settle_input_probe() {
    t10(Kind::Probe);
}

#[test]
fn v4_t10_covenant_ids_of_every_settle_input_shipped() {
    t10(Kind::Real);
}

#[test]
fn v4_t11_covenant_ids_of_every_refund_input_probe() {
    t11(Kind::Probe);
}

#[test]
fn v4_t11_covenant_ids_of_every_refund_input_shipped() {
    t11(Kind::Real);
}

fn set_view(input: &mut In, n_in: Option<i64>, n_out: Option<i64>) {
    match &mut input.spend {
        Spend::SettleV4 {
            n_in: a, n_out: b, ..
        }
        | Spend::RefundV4 {
            n_in: a, n_out: b, ..
        } => {
            if let Some(x) = n_in {
                *a = x;
            }
            if let Some(x) = n_out {
                *b = x;
            }
        }
        _ => panic!("not a v4 vault input"),
    }
}

fn set_signer(input: &mut In, who: Option<Role>) {
    match &mut input.spend {
        Spend::SettleV4 { signer, .. } | Spend::RefundV4 { signer, .. } => *signer = who,
        _ => panic!("not a v4 vault input"),
    }
}

#[test]
fn v4_t1_vault_beyond_input_1_refused_probe() {
    t1(Kind::Probe);
}

#[test]
fn v4_t1_vault_beyond_input_1_refused_shipped() {
    t1(Kind::Real);
}

#[test]
fn v4_t2_input_count_bounds_probe() {
    t2(Kind::Probe);
}

#[test]
fn v4_t2_input_count_bounds_shipped() {
    t2(Kind::Real);
}

#[test]
fn v4_t3_output_count_bounds_probe() {
    t3(Kind::Probe);
}

#[test]
fn v4_t3_output_count_bounds_shipped() {
    t3(Kind::Real);
}

#[test]
fn v4_t4_authority_signature_probe() {
    t4(Kind::Probe);
}

#[test]
fn v4_t4_authority_signature_shipped() {
    t4(Kind::Real);
}

#[test]
fn v4_t8_t9_lock_time_finality_probe() {
    t8_t9(Kind::Probe);
}

#[test]
fn v4_t8_t9_lock_time_finality_shipped() {
    t8_t9(Kind::Real);
}

#[test]
fn v4_t5_signer_signature_probe() {
    t5(Kind::Probe);
}

#[test]
fn v4_t5_signer_signature_shipped() {
    t5(Kind::Real);
}

#[test]
fn v4_t6_leg_byte_probe() {
    t6(Kind::Probe);
}

#[test]
fn v4_t6_leg_byte_shipped() {
    t6(Kind::Real);
}

#[test]
fn v4_t7_refund_view_bounds_probe() {
    t7(Kind::Probe);
}

#[test]
fn v4_t7_refund_view_bounds_shipped() {
    t7(Kind::Real);
}

// =============================================================================================
// Measurement without a receipt (spec/V3-ZK.md 22.10)
// =============================================================================================

/// Script units of every vault input of the canonical settles and refunds, in the probe (the
/// verify call replaced by a comparison, so these are the units of everything except the gate)
/// beside template v1 on the same shape. Written to $IMPULSE_V4_PROBE_OUT when set, for
/// scripts/measure-v4-units.sh. The precompile's own cost is added by the real-receipt run.
#[test]
fn v4_probe_units_beside_v1() {
    let mut lines = vec![
        "| Shape | v4 probe, asset vault | v4 probe, cash vault | v1, asset vault | v1, cash vault |"
            .to_string(),
        "| --- | --- | --- | --- | --- |".to_string(),
    ];
    for (cash, name) in [
        (CASH_KAS, "settle, KAS cash"),
        (CASH_KCC20, "settle, KCC-20 cash"),
        (CASH_EXTERNAL, "settle, external cash"),
    ] {
        let v = probe(cash);
        let spec = v.settle(&Proofs::Probe);
        let asset = spec.run(&v.w, 0);
        assert!(asset.result.is_ok(), "{name}: {:?}", asset.result);
        let cash_run = (cash != CASH_EXTERNAL).then(|| spec.run(&v.w, 1));
        let w1 = World::new(Mode::new(true, cash, REVOCABLE));
        let s1 = w1.settle();
        let a1 = s1.run(&w1, 0);
        let c1 = (cash != CASH_EXTERNAL).then(|| s1.run(&w1, 1));
        let n = |r: &Option<Run>| {
            r.as_ref()
                .map_or("none".to_string(), |r| r.used.0.to_string())
        };
        lines.push(format!(
            "| {name} | {} | {} | {} | {} |",
            asset.used.0,
            n(&cash_run),
            a1.used.0,
            n(&c1)
        ));
    }
    for (cash, leg, label) in [
        (CASH_KCC20, ASSET_LEG, "refund, asset leg, depositor"),
        (CASH_KCC20, CASH_LEG, "refund, KCC-20 cash leg, depositor"),
        (CASH_KAS, CASH_LEG, "refund, KAS cash leg, depositor"),
    ] {
        let v = probe(cash);
        let spec = v.refund(leg, Role::Seller, &Proofs::Probe);
        let r4 = spec.run(&v.w, 0);
        assert!(r4.result.is_ok(), "{label}: {:?}", r4.result);
        let w1 = World::new(Mode::new(true, cash, REVOCABLE));
        let r1 = w1.refund(leg, Role::Seller).run(&w1, 0);
        lines.push(format!(
            "| {label} | {} | n/a | {} | n/a |",
            r4.used.0, r1.used.0
        ));
    }
    if let Some(path) = std::env::var_os("IMPULSE_V4_PROBE_OUT") {
        std::fs::write(path, lines.join("\n") + "\n").expect("write probe units");
    }
}

// =============================================================================================
// [H5]: the other leg's vault in a settle (spec/V3-ZK.md 22.16; closes known limitation L20)
// =============================================================================================

/// The statement over the view of vault input `idx` refuses with `ZK_H_STATEMENT_FALSE` [H5], so
/// the terms guest makes no receipt for it.
fn statement_refuses_h5(v: &V4, spec: &TxSpec, idx: usize, label: &str) {
    let r = terms_core::statement(
        &v.witness(spec, idx),
        terms_core::StatementOptions {
            curve_checks: false,
        },
    )
    .expect_err(label);
    assert_eq!((r.code, r.tag), ("ZK_H_STATEMENT_FALSE", "H5"), "{label}");
}

fn statement_holds(v: &V4, spec: &TxSpec, idx: usize, label: &str) {
    terms_core::statement(
        &v.witness(spec, idx),
        terms_core::StatementOptions {
            curve_checks: false,
        },
    )
    .unwrap_or_else(|r| panic!("{label}: {r}"));
}

/// The cash token owned by the asset vault (misdirected funding) cannot stand in for the cash
/// escrow in a settle that omits the cash vault. The script of template v4 does not change in I26,
/// so the probe still accepts the spend whose "proof" is sha256(J): what refuses is the statement
/// the terms guest proves, so no receipt exists for it ([H5]). Before I26 the statement held here.
#[test]
fn v4_h5_own_covenant_token_at_the_other_vault_cannot_stand_in_for_its_escrow() {
    const EXCESS: i64 = 4_000;
    let v = world(Kind::Probe, CASH_KCC20);
    let control = v.settle(&Proofs::Probe);
    control.assert_all_accepted(&v.w, "control");
    statement_holds(&v, &control, 0, "control, asset vault");
    statement_holds(&v, &control, 1, "control, cash vault");
    let mut spec = control.clone();
    spec.inputs[1] = In::plain(AUTH_VALUE);
    // the stray token holds amount_b + EXCESS; the seller is paid amount_b, a stranger EXCESS
    let held = Kcc20State::new(
        Owner::script_hash(v.w.asset_vault.script_hash()),
        v.w.terms.amount_b + EXCESS,
    );
    let taken = Kcc20State::new(STRANGER_OWNER, EXCESS);
    spec.inputs[World::CASH_ESCROW_IDX] = In::token(
        CASH_TOKEN.compile(held),
        CASH_TOKEN.cov,
        vec![v.w.delivered_cash(), taken],
        0,
    );
    let at = spec.outputs.len() - 1;
    spec.outputs.insert(
        at,
        Out::token(
            CASH_TOKEN.compile(taken),
            CASH_TOKEN.cov,
            World::CASH_ESCROW_IDX as u16,
        ),
    );
    v.reprobe(&mut spec);
    statement_refuses_h5(&v, &spec, 0, "[H5] the cash vault omitted");
}

/// The same with the legs swapped: an asset token owned by the cash vault, a settle that omits
/// the asset vault.
#[test]
fn v4_h5_an_asset_token_at_the_cash_vault_cannot_settle_without_the_asset_vault() {
    let v = world(Kind::Probe, CASH_KCC20);
    let control = v.settle(&Proofs::Probe);
    let mut spec = control.clone();
    spec.inputs[0] = In::plain(AUTH_VALUE);
    let slot = v.w.asset_escrow_idx();
    let held = Kcc20State::new(
        Owner::script_hash(v.w.cash_vault().script_hash()),
        v.w.terms.amount_a,
    );
    spec.inputs[slot] = In::token(
        ASSET_TOKEN.compile(held),
        ASSET_TOKEN.cov,
        vec![v.w.delivered_asset()],
        1,
    );
    v.reprobe(&mut spec);
    statement_refuses_h5(&v, &spec, 1, "[H5] the asset vault omitted");
}

/// KAS cash: a settle that omits either vault, or puts a second UTXO of the spending vault at the
/// other slot, has no receipt.
#[test]
fn v4_h5_kas_cash_settle_needs_both_vaults() {
    let v = world(Kind::Probe, CASH_KAS);
    let control = v.settle(&Proofs::Probe);
    control.assert_all_accepted(&v.w, "control");
    for (idx, label) in [(0usize, "asset vault"), (1, "cash vault")] {
        statement_holds(&v, &control, idx, label);
        let other = 1 - idx;
        let value = control.inputs[other].value;
        // the other vault omitted
        let mut spec = control.clone();
        spec.inputs[other] = In::plain(value);
        v.reprobe(&mut spec);
        statement_refuses_h5(
            &v,
            &spec,
            idx,
            &format!("[H5] {label}: the other vault omitted"),
        );
        // a duplicate of this vault at the other slot (also refused by [T1] in its own script)
        let mut spec = control.clone();
        spec.inputs[other] = control.inputs[idx].clone();
        spec.inputs[other].value = value;
        statement_refuses_h5(&v, &spec, idx, &format!("[H5] {label}: a duplicate vault"));
    }
}
