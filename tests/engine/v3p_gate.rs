// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! [Z1] and [Z2] on the template v3 probe (harness::v3_probe_by_default), where the proof gate is
//! "sha256(J) equals the proof witness" and every settle carries the correct one. With a proof
//! the gate accepts, the only reason left to refuse is the require under test, so the mutation
//! run (mutation-v3.py) can show that removing [Z1] or [Z2] flips exactly these tests. The same
//! two requires are tested with real proofs in v3_settle.rs.

mod harness;
use harness::*;

const MODE: Mode = Mode::new(false, CASH_KAS, REVOCABLE);

fn covenant_owner() -> Owner {
    Owner {
        id_type: IDENTIFIER_COVENANT_ID,
        id: [0xC0; 32],
    }
}

#[test]
fn z1_script_hash_owner_settles() {
    let w = World::with(MODE, |t, _| {
        t.buyer_delivery = Owner::script_hash([0xC0; 32])
    });
    w.settle()
        .assert_all_accepted(&w, "script hash delivery owner");
}

#[test]
fn z1_covenant_owner_refused() {
    let control = World::with(MODE, |t, _| {
        t.buyer_delivery = Owner::script_hash([0xC0; 32])
    });
    control
        .settle()
        .assert_all_accepted(&control, "[Z1] control: script hash owner");
    let w = World::with(MODE, |t, _| t.buyer_delivery = covenant_owner());
    assert_refused(&w.settle().run(&w, 0), "[Z1] COVENANT_ID delivery owner");
}

#[test]
fn z2_cash_vault_empty_proof_settles() {
    let w = World::new(MODE);
    w.settle()
        .assert_all_accepted(&w, "empty proof at the cash vault");
}

#[test]
fn z2_cash_vault_nonempty_proof_refused() {
    let w = World::new(MODE);
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::settle_v3(w.cash_vault(), None, AMOUNT_B as u64, vec![1]);
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "[Z2] cash vault with a 1 byte proof",
    );
}

/// A cash vault of a KCC-20 trade, too.
#[test]
fn z2_kcc20_cash_vault_nonempty_proof_refused() {
    let w = World::new(Mode::new(false, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::settle_v3(w.cash_vault(), None, AUTH_VALUE, vec![0; 128]);
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "[Z2] KCC-20 cash vault with a proof",
    );
}
