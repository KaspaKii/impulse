// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v3 on the shipped template with the committed Groth16 receipts
//! (spec/V3-ZK.md 6.6, "Inputs outside the layout"): each of `[F1]` to `[F5]` refuses its fault,
//! against a control the shipped template accepts with a valid proof, so the gate cannot mask the
//! refusal; every settle refusal here is before the gate (fewer units than the precompile's fixed
//! cost). The refunds need no proof. The whole suite of foreign_covenant.rs also runs against the probe
//! (v3p_foreign_covenant.rs) for the mutation run.

mod foreign_common;
mod harness;
mod v3_common;
use foreign_common::*;
use harness::*;
use v3_common::*;

fn kas() -> World {
    world_for("a_list1000")
}

fn kcc20() -> World {
    world_for("a_list1000_kcc20")
}

/// The control settles with its real proof; the faulty settle is refused at `idx` before the
/// gate.
fn flips_before_gate(w: &World, control: &TxSpec, faulty: &TxSpec, idx: usize, label: &str) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_refused_before_gate(&faulty.run(w, idx), label);
}

#[test]
fn v3_f1_a_token_of_another_covenant_is_refused_before_the_gate() {
    for w in [kas(), kcc20()] {
        let control = w.settle();
        let at = fee_idx(&control);
        let faulty = with_token_owned_by(
            &control,
            (&w.asset_vault, 0),
            FOREIGN_TOKEN,
            FOREIGN_AMOUNT,
            at,
        );
        assert_accepted(&faulty.run(&w, at), "the foreign transfer is valid");
        flips_before_gate(&w, &control, &faulty, 0, "asset vault");
        assert_refused(&faulty.run(&w, 1), "cash vault");
    }
}

#[test]
fn v3_f2_a_second_token_of_the_other_legs_covenant_is_refused_before_the_gate() {
    // The asset vault: a second cash token, owned by the asset vault.
    let w = kcc20();
    let control = w.settle();
    let (faulty, at) = with_second_token_owned_by(
        &control,
        (&w.asset_vault, 0),
        CASH_TOKEN,
        AMOUNT_B,
        World::CASH_ESCROW_IDX,
    );
    assert_accepted(&faulty.run(&w, at), "the second token's transfer is valid");
    flips_before_gate(&w, &control, &faulty, 0, "asset vault, second cash token");
    // The cash vault (it carries no proof): a second asset token, owned by the cash vault.
    let w = kas();
    let control = w.settle();
    let (faulty, _) = with_second_token_owned_by(
        &control,
        (w.cash_vault(), 1),
        ASSET_TOKEN,
        AMOUNT_A,
        w.asset_escrow_idx(),
    );
    control.assert_all_accepted(&w, "control");
    assert_refused(&faulty.run(&w, 1), "cash vault, second asset token");
}

#[test]
fn v3_f4_twelve_inputs_settle_and_a_thirteenth_is_refused_before_the_gate() {
    let w = kas();
    let control = w.settle();
    let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
    full.assert_all_accepted(&w, "12 inputs");
    let over = with_fee_inputs(&full, 1);
    flips_before_gate(&w, &full, &over, 0, "13 inputs, asset vault");
    assert_refused(&over.run(&w, 1), "13 inputs, cash vault");
}

#[test]
fn v3_f3_refund_refuses_a_token_of_another_covenant() {
    for (mode, leg, signer) in refunds() {
        let w = World::new(mode);
        let control = w.refund(leg, signer);
        let at = fee_idx(&control);
        let faulty = with_token_owned_by(
            &control,
            (w.vault(leg), 0),
            FOREIGN_TOKEN,
            FOREIGN_AMOUNT,
            at,
        );
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("{mode:?} leg {leg} by {signer:?}"),
        );
    }
}

#[test]
fn v3_f5_a_refund_with_13_inputs_is_refused() {
    for (mode, leg, signer) in refunds() {
        let w = World::new(mode);
        let control = w.refund(leg, signer);
        let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
        let over = with_fee_inputs(&full, 1);
        assert_flips(
            &w,
            &full,
            &over,
            0,
            &format!("{mode:?} leg {leg} by {signer:?}"),
        );
    }
}
