// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v1: no token rides along in a vault spend (spec/TEMPLATE.md, "Inputs outside the
//! layout"; known limitation L20). In the real engine:
//!
//! - `[F1]`: a settle in which any input other than the vault carries a covenant the layout does
//!   not name (here a KCC-20 token of another covenant owned by the vault's script hash, moved to
//!   a stranger) is refused by every vault it spends, in every mode.
//! - `[F2]`: a settle with a second token of the other leg's covenant (a token of a leg's
//!   covenant sent to the wrong vault) is refused by the vault that does not escrow that leg.
//! - `[F3]`: a refund with a token of another covenant at any input after the vault is refused,
//!   for every leg, signer and cash kind, the example of L20 included.
//! - `[F4]`, `[F5]`: fee inputs without a covenant pass up to the bound of 12 inputs; a 13th
//!   input is refused, by the contract's own bound before the compiler's loop assertion.
//! - What the check does not refuse is foreign_covenant_residual.rs.
//!
//! Every refusal goes through `assert_flips`: the canonical spend is accepted at every input, and
//! the foreign token's own KCC-20 transfer is accepted, so the vault is the only refusal.
//!
//! The same suite runs against the template v3 probe in v3p_foreign_covenant.rs (template v3
//! has the same five requires); the shipped template v3 is covered in v3_foreign_covenant.rs.

mod foreign_common;
mod harness;
use foreign_common::*;
use harness::*;

// =============================================================================================
// [F1] settle: no token of another covenant at any input
// =============================================================================================

/// Named test of [F1]: the asset vault of every mode refuses a settle that also moves a token of
/// another covenant owned by its script hash, before the fee input and after it.
#[test]
fn f1_asset_vault_settle_refuses_a_token_of_another_covenant() {
    for mode in SETTLE_MODES {
        let w = World::new(mode);
        let control = w.settle();
        for at in [fee_idx(&control), control.inputs.len()] {
            let faulty = with_token_owned_by(
                &control,
                (&w.asset_vault, 0),
                FOREIGN_TOKEN,
                FOREIGN_AMOUNT,
                at,
            );
            let label = format!("{mode:?}, foreign token at input {at}");
            assert_token_transfer_valid(&w, &faulty, at, &label);
            assert_flips(&w, &control, &faulty, 0, &label);
        }
    }
}

#[test]
fn f1_cash_vault_settle_refuses_a_token_of_another_covenant() {
    for mode in [AUTH_KAS, AUTH_KCC20, SELF_KAS, SELF_KCC20] {
        let w = World::new(mode);
        let control = w.settle();
        let at = fee_idx(&control);
        let faulty = with_token_owned_by(
            &control,
            (w.cash_vault(), 1),
            FOREIGN_TOKEN,
            FOREIGN_AMOUNT,
            at,
        );
        let label = format!("{mode:?}, foreign token owned by the cash vault");
        assert_token_transfer_valid(&w, &faulty, at, &label);
        assert_flips(&w, &control, &faulty, 1, &label);
    }
}

/// A token of another covenant owned by anyone (here a key) is refused just the same: the vault
/// reads covenant IDs, not owners.
#[test]
fn f1_settle_refuses_a_key_owned_token_of_another_covenant() {
    let w = World::new(AUTH_KCC20);
    let control = w.settle();
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            FOREIGN_TOKEN.compile(Kcc20State::new(STRANGER_OWNER, FOREIGN_AMOUNT)),
            FOREIGN_COV,
            vec![],
            0,
        ),
    );
    for idx in vault_inputs(&w) {
        assert_flips(
            &w,
            &control,
            &faulty,
            idx,
            &format!("key-owned foreign token, vault input {idx}"),
        );
    }
}

/// The fee input itself carrying a covenant ID is refused: an input outside the layout's slots
/// carries none.
#[test]
fn f1_a_fee_input_with_a_covenant_id_is_refused() {
    for mode in SETTLE_MODES {
        let w = World::new(mode);
        let control = w.settle();
        let mut faulty = control.clone();
        let fee = fee_idx(&faulty);
        faulty.inputs[fee].cov = Some(FOREIGN_COV);
        for idx in vault_inputs(&w) {
            assert_flips(
                &w,
                &control,
                &faulty,
                idx,
                &format!("{mode:?}, fee input bound to a covenant, vault input {idx}"),
            );
        }
    }
}

// =============================================================================================
// [F2] settle: the other leg's covenant has exactly one input
// =============================================================================================

/// Named test of [F2] at the asset vault: a second token of the cash covenant, owned by the asset
/// vault (the buyer's cash sent to the wrong vault), would move with the settle. Every input
/// carries a covenant the layout names and the asset escrow is in place, so only [F2] refuses at
/// input 0 (the cash vault refuses it by its own [E1]).
#[test]
fn f2_asset_vault_refuses_a_second_token_of_the_cash_covenant() {
    for mode in [AUTH_KCC20, SELF_KCC20] {
        let w = World::new(mode);
        let control = w.settle();
        let (faulty, at) = with_second_token_owned_by(
            &control,
            (&w.asset_vault, 0),
            CASH_TOKEN,
            AMOUNT_B,
            World::CASH_ESCROW_IDX,
        );
        let label = format!("{mode:?}, cash token owned by the asset vault");
        assert_token_transfer_valid(&w, &faulty, at, &label);
        assert_token_transfer_valid(&w, &faulty, World::CASH_ESCROW_IDX, &label);
        assert_flips(&w, &control, &faulty, 0, &label);
        assert_refused(&faulty.run(&w, 1), &format!("{label}: cash vault [E1]"));
    }
}

/// [F2] at the cash vault: a second token of the asset covenant, owned by the cash vault (the
/// seller's asset sent to the wrong vault). The asset vault refuses it by its own [E1].
#[test]
fn f2_cash_vault_refuses_a_second_token_of_the_asset_covenant() {
    for mode in [AUTH_KAS, AUTH_KCC20, SELF_KAS, SELF_KCC20] {
        let w = World::new(mode);
        let control = w.settle();
        let (faulty, at) = with_second_token_owned_by(
            &control,
            (w.cash_vault(), 1),
            ASSET_TOKEN,
            AMOUNT_A,
            w.asset_escrow_idx(),
        );
        let label = format!("{mode:?}, asset token owned by the cash vault");
        assert_token_transfer_valid(&w, &faulty, at, &label);
        assert_token_transfer_valid(&w, &faulty, w.asset_escrow_idx(), &label);
        assert_flips(&w, &control, &faulty, 1, &label);
        assert_refused(&faulty.run(&w, 0), &format!("{label}: asset vault [E1]"));
    }
}

// =============================================================================================
// [F3] refund: no token of another covenant after the vault
// =============================================================================================

/// Named test of [F3]: every leg and signer, a token of another covenant owned by the refunded
/// vault at the input before the fee and after it.
#[test]
fn f3_refund_refuses_a_token_of_another_covenant() {
    for (mode, leg, signer) in refunds() {
        let w = World::new(mode);
        let control = w.refund(leg, signer);
        for at in [fee_idx(&control), control.inputs.len()] {
            let faulty = with_token_owned_by(
                &control,
                (w.vault(leg), 0),
                FOREIGN_TOKEN,
                FOREIGN_AMOUNT,
                at,
            );
            let label = format!("{mode:?} leg {leg} by {signer:?}, foreign token at input {at}");
            assert_token_transfer_valid(&w, &faulty, at, &label);
            assert_flips(&w, &control, &faulty, 0, &label);
        }
    }
}

/// The example of L20: the buyer's KCC-20 cash token sent by mistake to the asset vault's
/// address does not move with the seller's refund of the asset vault.
#[test]
fn f3_a_cash_token_at_the_asset_vault_no_longer_moves_with_its_refund() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let at = fee_idx(&control);
    let faulty = with_token_owned_by(&control, (&w.asset_vault, 0), CASH_TOKEN, AMOUNT_B, at);
    assert_token_transfer_valid(&w, &faulty, at, "misdirected cash token");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "a cash token owned by the asset vault, moved to a stranger by the asset refund",
    );
}

/// The depositor's refund of the authorizer alone (the token stays): a token of another
/// covenant at input 1, where the escrow would be, is refused.
#[test]
fn f3_authorizer_alone_refuses_a_token_of_another_covenant_at_input_1() {
    let w = World::new(AUTH_KCC20);
    let mut control = w.refund(ASSET_LEG, Role::Seller);
    control.inputs.remove(1);
    control.outputs.remove(1);
    let faulty = with_token_owned_by(
        &control,
        (&w.asset_vault, 0),
        FOREIGN_TOKEN,
        FOREIGN_AMOUNT,
        1,
    );
    assert_token_transfer_valid(&w, &faulty, 1, "foreign token at input 1");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "authorizer alone, foreign token at input 1",
    );
}

/// External cash: the cash vault (whose cash covenant is zero) refunds its KAS to the buyer; any
/// token held by its script hash is of another covenant and is refused.
#[test]
fn f3_external_cash_vault_refund_refuses_any_token() {
    for funding in [REVOCABLE, EARMARKED] {
        let mut w = World::new(Mode::new(true, CASH_EXTERNAL, funding));
        w.cash_vault = Some(w.terms.vault(CASH_LEG));
        let control = w.refund(CASH_LEG, Role::Buyer);
        let at = fee_idx(&control);
        let faulty = with_token_owned_by(
            &control,
            (w.cash_vault(), 0),
            FOREIGN_TOKEN,
            FOREIGN_AMOUNT,
            at,
        );
        let label = format!("external cash vault, funding {funding}");
        assert_token_transfer_valid(&w, &faulty, at, &label);
        assert_flips(&w, &control, &faulty, 0, &label);
    }
}

/// A refund's fee input bound to a covenant is refused.
#[test]
fn f3_a_fee_input_with_a_covenant_id_is_refused() {
    for (mode, leg, signer) in refunds() {
        let w = World::new(mode);
        let control = w.refund(leg, signer);
        let mut faulty = control.clone();
        let fee = fee_idx(&faulty);
        faulty.inputs[fee].cov = Some(FOREIGN_COV);
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("{mode:?} leg {leg} by {signer:?}, fee input bound to a covenant"),
        );
    }
}

// =============================================================================================
// Fee inputs without covenants, and the bound
// =============================================================================================

/// Fee inputs without a covenant pass, up to 12 inputs in all: a KCC-20 cash settle (4 trade
/// inputs) with 8 fee inputs, an external-cash settle with 10, a refund with its token with 10.
#[test]
fn fee_inputs_without_covenants_pass_up_to_the_bound() {
    for mode in SETTLE_MODES {
        let w = World::new(mode);
        let control = w.settle();
        let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
        assert_eq!(full.inputs.len(), MAX_INPUTS);
        full.assert_all_accepted(&w, &format!("{mode:?} settle, {MAX_INPUTS} inputs"));
    }
    for (mode, leg, signer) in refunds() {
        let w = World::new(mode);
        let control = w.refund(leg, signer);
        let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
        full.assert_all_accepted(
            &w,
            &format!("{mode:?} leg {leg} refund by {signer:?}, {MAX_INPUTS} inputs"),
        );
    }
}

/// Named test of [F4]: a settle with a 13th input, even one without a covenant, is refused by
/// every vault it spends, and refused first: the run stops before a reference run of the same
/// vault at the bound (12 inputs) that the next require, [S1], refuses (the vaults swapped). The
/// compiler's own loop assertion would refuse it later, so the units show it is [F4].
#[test]
fn f4_a_settle_with_13_inputs_is_refused_at_the_bound() {
    for mode in [AUTH_KCC20, AUTH_EXTERNAL, SELF_KAS] {
        let w = World::new(mode);
        let control = w.settle();
        let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
        let over = with_fee_inputs(&full, 1);
        for idx in vault_inputs(&w) {
            assert_flips(
                &w,
                &full,
                &over,
                idx,
                &format!("{mode:?} settle, 13 inputs, vault input {idx}"),
            );
        }
    }
    let w = World::new(AUTH_KCC20);
    let full = with_fee_inputs(&w.settle(), MAX_INPUTS - 5);
    let over = with_fee_inputs(&full, 1);
    let mut swapped = full.clone();
    swapped.inputs.swap(0, 1);
    for (idx, at_s1) in [(0, 1), (1, 0)] {
        let at_bound = over.run(&w, idx);
        let reference = swapped.run(&w, at_s1);
        assert_refused(&reference, "reference refusal at [S1]");
        assert!(
            at_bound.used.0 < reference.used.0,
            "vault input {idx}: refused at [F4] after {} units, [S1] refuses after {}",
            at_bound.used.0,
            reference.used.0
        );
    }
}

/// Named test of [F5]: a refund with a 13th input is refused, before a reference refund at the
/// bound that the next require, [R1], refuses (a signer the terms do not name).
#[test]
fn f5_a_refund_with_13_inputs_is_refused_at_the_bound() {
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
            &format!("{mode:?} leg {leg} refund by {signer:?}, 13 inputs"),
        );
        let at_bound = over.run(&w, 0);
        let stranger = with_fee_inputs(
            &w.refund(leg, Role::Stranger),
            MAX_INPUTS - control.inputs.len(),
        );
        let reference = stranger.run(&w, 0);
        assert_refused(&reference, "reference refusal at [R1]");
        assert!(
            at_bound.used.0 < reference.used.0,
            "{mode:?} leg {leg}: refused at [F5] after {} units, [R1] refuses after {}",
            at_bound.used.0,
            reference.used.0
        );
    }
}

// =============================================================================================
// Tests of [E2], [D1], [R9] and [R10] whose fault carries no covenant outside the layout
// =============================================================================================
//
// The named tests of these requires in settle.rs and refund.rs put a token of a decoy covenant
// in the transaction, which [F1] or [F3] also refuse. Each test here makes the
// same fault with covenant-less UTXOs instead, so the require is still the only refusal and the
// mutation run (tests/engine/mutation.py) names these. ([E2]'s is
// settle::e2_escrow_without_covenant_binding_real_asset_elsewhere.)

fn leader_states(spec: &mut TxSpec, idx: usize) -> &mut Vec<Kcc20State> {
    match &mut spec.inputs[idx].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states,
        _ => panic!("input {idx} is not a token leader"),
    }
}

/// [D1]: output 0 holds the delivered asset's script but carries no covenant (anyone can make
/// such a UTXO), while the real asset goes to a stranger.
#[test]
fn d1_output0_without_a_covenant_real_asset_to_a_stranger() {
    let w = World::new(AUTH_KAS);
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    faulty.outputs[0].cov = None;
    *leader_states(&mut faulty, escrow) = vec![Kcc20State::new(STRANGER_OWNER, AMOUNT_A)];
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(Kcc20State::new(STRANGER_OWNER, AMOUNT_A)),
        ASSET_COV,
        escrow as u16,
    ));
    assert_token_transfer_valid(&w, &faulty, escrow, "asset to a stranger");
    assert_flips(&w, &control, &faulty, 0, "output 0 without a covenant");
}

/// [R9]: input 1 is a covenant-less UTXO with the escrow's script (anyone can make one), read in
/// place of the real escrow, which sits at input 2.
#[test]
fn r9_covenant_less_copy_at_input_1_real_escrow_at_input_2() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let real = faulty.inputs[1].clone();
    faulty.inputs[1].cov = None;
    faulty.inputs.insert(2, real);
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "covenant-less copy read in place of the escrow",
    );
}

/// [R10]: output 1 holds the home state's script but carries no covenant, while the real escrow
/// goes to a stranger.
#[test]
fn r10_home_output_without_a_covenant_escrow_to_a_stranger() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.outputs[1].cov = None;
    *leader_states(&mut faulty, 1) = vec![Kcc20State::new(STRANGER_OWNER, AMOUNT_A)];
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(Kcc20State::new(STRANGER_OWNER, AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_token_transfer_valid(&w, &faulty, 1, "escrow to a stranger");
    assert_flips(&w, &control, &faulty, 0, "home output without a covenant");
}
