// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v3 refund guards on the SHIPPED bytecode (review round 2, finding 2): [R3], the
//! depositor's earmarked refund not before expiry_daa, and [R8], a refund that carries a second
//! escrow deposit. A refund needs no proof, so these run on the real template, not the probe.
//! The cases are those of locktime.rs (r3_*) and escrow_release.rs (second_escrow_deposit_*_refund),
//! copied because those files also hold settle cases, which need a proof. The binary name starts
//! with v3_, so harness::World::new builds the shipped v3 template.

mod harness;
use harness::*;
use kaspa_txscript::MAX_TX_IN_SEQUENCE_NUM;

const SETTLE_MODE: Mode = Mode::new(true, CASH_KCC20, EARMARKED);
const MODE: Mode = Mode::new(true, CASH_KCC20, EARMARKED);

fn stranger_state(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

// [R3]

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

// [R8]

/// A refund that carries a second deposit of the asset: one goes home, the other to a stranger.
fn second_deposit_rides_refund(w: &World, signer: Role) -> (TxSpec, TxSpec) {
    let control = w.refund(ASSET_LEG, signer);
    let mut faulty = control.clone();
    faulty.inputs.insert(
        2,
        In::token_delegate(ASSET_TOKEN.compile(w.asset_escrow_state()), ASSET_COV, 0),
    );
    match &mut faulty.inputs[1].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states.push(stranger_state(AMOUNT_A)),
        _ => unreachable!(),
    }
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger_state(AMOUNT_A)), ASSET_COV, 1),
    );
    let (tx, entries) = faulty.build(w);
    assert_accepted(&execute(&tx, &entries, 1), "KCC-20 leader is valid");
    assert_accepted(&execute(&tx, &entries, 2), "KCC-20 delegate is valid");
    (control, faulty)
}

/// Signed by the depositor, the case only [R8] guards.
#[test]
fn second_escrow_deposit_cannot_ride_along_a_refund() {
    let w = World::new(MODE);
    let (control, faulty) = second_deposit_rides_refund(&w, Role::Seller);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a depositor refund",
    );
}

#[test]
fn second_escrow_deposit_cannot_ride_along_a_counterparty_refund() {
    let w = World::new(MODE);
    let (control, faulty) = second_deposit_rides_refund(&w, Role::Buyer);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a counterparty refund",
    );
}
