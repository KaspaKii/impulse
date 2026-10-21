// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Lock time in the real engine: settle not before earliest_daa ([S3]) and the depositor's
//! earmarked refund not before expiry_daa ([R3]), boundaries one DAA either side. Both compile
//! to OpCheckLockTimeVerify in the DAA-score domain, so a transaction must set its lock time to
//! a DAA score of at least the bound and the vault input's sequence below the maximum.
//! These are script checks; node finality of a lock time against block DAA is I5's scope.
//! Boundary pattern after the WarpCore consensus_timeout_finality test (nothing copied: that
//! test checks a relative CSV lock, ImpulseVault an absolute one).

mod harness;
use harness::*;
use kaspa_txscript::{LOCK_TIME_THRESHOLD, MAX_TX_IN_SEQUENCE_NUM};

const SETTLE_MODE: Mode = Mode::new(true, CASH_KCC20, EARMARKED);

// =============================================================================================
// [S3] settle not before earliest_daa
// =============================================================================================

#[test]
fn settle_at_earliest() {
    let w = World::new(SETTLE_MODE);
    let spec = w.settle();
    assert_eq!(spec.lock_time, EARLIEST_DAA);
    spec.assert_all_accepted(&w, "lock time == earliest");
}

#[test]
fn settle_after_earliest() {
    let w = World::new(SETTLE_MODE);
    let mut spec = w.settle();
    spec.lock_time = EARLIEST_DAA + 1;
    spec.assert_all_accepted(&w, "lock time == earliest + 1");
}

/// No earliest_daa in the terms: no lock-time check at all, so lock time 0 and a finalized
/// sequence are fine.
#[test]
fn settle_without_earliest_needs_no_lock_time() {
    let w = World::new(SETTLE_MODE).edit(|t| {
        t.has_earliest = false;
        t.earliest_daa = 0;
    });
    let mut spec = w.settle();
    spec.lock_time = 0;
    spec.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    spec.inputs[1].sequence = MAX_TX_IN_SEQUENCE_NUM;
    spec.assert_all_accepted(&w, "no earliest");
}

#[test]
fn s3_settle_one_daa_before_earliest() {
    let w = World::new(SETTLE_MODE);
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.lock_time = EARLIEST_DAA - 1;
    assert_flips_locktime(&w, &control, &faulty, 0, "asset vault, earliest - 1");
    assert_locktime_refused(&faulty.run(&w, 1), "cash vault, earliest - 1");
}

/// A finalized input makes consensus ignore the lock time, so CLTV refuses it.
#[test]
fn s3_settle_with_finalized_vault_input() {
    let w = World::new(SETTLE_MODE);
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    assert_flips_locktime(&w, &control, &faulty, 0, "finalized asset vault input");
}

/// A timestamp-domain lock time can never satisfy a DAA-score bound.
#[test]
fn s3_settle_with_timestamp_lock_time() {
    let w = World::new(SETTLE_MODE);
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.lock_time = LOCK_TIME_THRESHOLD + EARLIEST_DAA;
    assert_flips_locktime(&w, &control, &faulty, 0, "timestamp-domain lock time");
}

// =============================================================================================
// [R3] earmarked: the depositor's refund not before expiry_daa
// =============================================================================================

#[test]
fn depositor_earmarked_refund_after_expiry() {
    let w = World::new(SETTLE_MODE);
    let mut spec = w.refund(ASSET_LEG, Role::Seller);
    spec.lock_time = EXPIRY_DAA + 1;
    spec.assert_all_accepted(&w, "depositor at expiry + 1");
}

#[test]
fn depositor_revocable_refund_needs_no_lock_time() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let mut spec = w.refund(ASSET_LEG, Role::Seller);
    spec.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    assert_eq!(spec.lock_time, 0);
    spec.assert_all_accepted(&w, "revocable depositor, lock time 0, finalized input");
}

#[test]
fn counterparty_earmarked_refund_one_daa_before_expiry() {
    let w = World::new(SETTLE_MODE);
    let mut spec = w.refund(ASSET_LEG, Role::Buyer);
    spec.lock_time = EXPIRY_DAA - 1;
    spec.assert_all_accepted(&w, "counterparty at expiry - 1");
}

#[test]
fn r3_depositor_earmarked_refund_one_daa_before_expiry() {
    let w = World::new(SETTLE_MODE);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.lock_time = EXPIRY_DAA - 1;
    assert_flips_locktime(&w, &control, &faulty, 0, "depositor at expiry - 1");
}

#[test]
fn r3_cash_depositor_earmarked_refund_one_daa_before_expiry() {
    let w = World::new(Mode::new(true, CASH_KAS, EARMARKED));
    let control = w.refund(CASH_LEG, Role::Buyer);
    assert_eq!(control.lock_time, EXPIRY_DAA);
    let mut faulty = control.clone();
    faulty.lock_time = EXPIRY_DAA - 1;
    assert_flips_locktime(
        &w,
        &control,
        &faulty,
        0,
        "buyer refunds KAS cash at expiry - 1",
    );
}

#[test]
fn r3_depositor_earmarked_refund_with_finalized_input() {
    let w = World::new(SETTLE_MODE);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    assert_flips_locktime(&w, &control, &faulty, 0, "depositor, finalized input");
}

/// Any funding-mode byte other than revocable is treated as earmarked.
#[test]
fn r3_unknown_funding_mode_is_earmarked() {
    let w = World::new(Mode::new(true, CASH_KCC20, 0x07));
    let mut control = w.refund(ASSET_LEG, Role::Seller);
    control.lock_time = EXPIRY_DAA;
    let mut faulty = control.clone();
    faulty.lock_time = 0;
    assert_flips_locktime(
        &w,
        &control,
        &faulty,
        0,
        "funding mode 0x07, depositor at 0",
    );
}
