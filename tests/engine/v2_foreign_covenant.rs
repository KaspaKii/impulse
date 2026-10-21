// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v2: no token rides along in a vault spend (spec/V2.md 4.4 and 4.5, "Inputs outside
//! the layout"; known limitation L20). In the real engine:
//!
//! - `[F1]`: a settle in which an input after the N vaults carries a covenant, other than the
//!   escrow slot N + j of a KCC-20 leg j, is refused by every vault it spends.
//! - `[F3]`: a refund with a token of another covenant at any input after the vault is refused.
//! - `[F4]`, `[F5]`: a settle has at most N + 18 inputs and a refund at most 12, refused first.
//!
//! Linked trades (spec/V2.md section 17) are two template v2 trades, so this covers them too.

mod harness;
mod v2_harness;
use harness::*;
use kaspa_consensus_core::Hash;
use v2_harness::*;

/// A covenant no leg names, and a token of it.
const FOREIGN_COV: Hash = Hash::from_bytes([0xF0; 32]);
const FOREIGN_AMOUNT: i64 = 777;
/// Inputs after the vaults of a settle, and inputs of a refund, at most (the contract's
/// MAX_INPUTS_AFTER_VAULTS and MAX_INPUTS).
const MAX_AFTER_VAULTS: usize = 18;
const MAX_REFUND_INPUTS: usize = 12;

fn foreign_token() -> TokenV2 {
    TokenV2::new(0xF0, 2).with_cov(FOREIGN_COV)
}

/// Settles of every shape the harness makes: (label, setup, lots).
fn settles() -> Vec<(&'static str, Setup, i64)> {
    vec![
        ("N = 2, KCC-20 and KCC-20", Setup::v1_kcc20_cash(true), 1),
        ("N = 2, KCC-20 and KAS", Setup::v1_kas_cash(false), 1),
        ("ring of 3", Setup::ring(3, true), 1),
        ("3 with a KAS leg", Setup::three_with_kas(true), 1),
        (
            "tranche of 3 of 10 lots",
            Setup::v1_kcc20_cash(true).partial(10, 1),
            3,
        ),
    ]
}

/// `tx` with a token of `token` owned by vault `owner`'s script hash inserted at input `at`, sent
/// whole to a stranger by its own transfer (witness: vault `owner`'s input), at the output before
/// the change.
fn with_token_owned_by(
    w: &WorldV2,
    tx: &TxV2,
    owner: usize,
    witness: u8,
    token: TokenV2,
    at: usize,
) -> TxV2 {
    let mut faulty = tx.clone();
    let held = Kcc20State::new(
        Owner::script_hash(w.vaults[owner].script_hash()),
        FOREIGN_AMOUNT,
    );
    let taken = Kcc20State::new(STRANGER_OWNER, FOREIGN_AMOUNT);
    faulty.inputs.insert(
        at,
        InV2::token(token.compile(held), token.cov, vec![taken], witness),
    );
    let out_at = faulty.outputs.len() - 1;
    faulty.outputs.insert(
        out_at,
        Out::token(token.compile(taken), token.cov, at as u16),
    );
    faulty
}

fn with_fee_inputs(tx: &TxV2, extra: usize) -> TxV2 {
    let mut out = tx.clone();
    for _ in 0..extra {
        out.inputs.push(InV2::plain(FEE_VALUE));
    }
    out
}

// =============================================================================================
// [F1] settle
// =============================================================================================

/// Named test of [F1]: every vault of every shape refuses a settle that also moves a token of
/// another covenant owned by vault 0, placed before the fee input (the escrow slot of a KAS leg
/// where there is one) and after it.
#[test]
fn f1_every_vault_refuses_a_token_of_another_covenant_after_the_vaults() {
    for (label, setup, lots) in settles() {
        let w = WorldV2::new(setup);
        let control = w.settle(lots);
        for at in [control.fee_idx(), control.inputs.len()] {
            let faulty = with_token_owned_by(&w, &control, 0, 0, foreign_token(), at);
            assert_accepted(
                &faulty.run(&w, at),
                &format!("{label}: the foreign transfer is valid"),
            );
            for i in 0..w.n() {
                flips(
                    &w,
                    &control,
                    &faulty,
                    i,
                    &format!("{label}, foreign token at input {at}, vault {i}"),
                );
            }
        }
    }
}

/// The other leg's token, owned by the wrong vault (leg 1's covenant at vault 0's script hash),
/// as a second input of leg 1's covenant after the escrows: vault 1 refuses it by [E1], every
/// other vault by [F1] (it sits outside the escrow slots). Only the vaults run here; the token's
/// own spend is not the point.
#[test]
fn f1_a_leg_token_owned_by_another_vault_is_refused_outside_its_slot() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.settle_final();
    let at = control.fee_idx();
    let token = w.leg(1).token();
    let mut faulty = control.clone();
    let held = Kcc20State::new(Owner::script_hash(w.vaults[0].script_hash()), 5);
    faulty
        .inputs
        .insert(at, InV2::token(token.compile(held), token.cov, vec![], 0));
    for i in 0..w.n() {
        flips(&w, &control, &faulty, i, &format!("vault {i}"));
    }
}

/// A fee input bound to a covenant is refused by every vault.
#[test]
fn f1_a_fee_input_with_a_covenant_id_is_refused() {
    for (label, setup, lots) in settles() {
        let w = WorldV2::new(setup);
        let control = w.settle(lots);
        let mut faulty = control.clone();
        let fee = faulty.fee_idx();
        faulty.inputs[fee].cov = Some(FOREIGN_COV);
        for i in 0..w.n() {
            flips(&w, &control, &faulty, i, &format!("{label}, vault {i}"));
        }
    }
}

// =============================================================================================
// [F3] refund
// =============================================================================================

/// Every leg kind and signer role of the harness: (label, setup, leg, signer, signer leg).
fn refunds() -> Vec<(&'static str, Setup, usize, Who, i64)> {
    vec![
        (
            "KCC-20 leg, depositor",
            Setup::three_with_kas(true),
            0,
            Who::Party(0),
            0,
        ),
        (
            "KCC-20 leg, authority",
            Setup::three_with_kas(true),
            0,
            Who::Authority,
            3,
        ),
        (
            "KCC-20 leg, another depositor",
            Setup::three_with_kas(true),
            1,
            Who::Party(2),
            2,
        ),
        (
            "KAS leg, depositor",
            Setup::three_with_kas(true),
            2,
            Who::Party(2),
            2,
        ),
        (
            "KAS leg, authority",
            Setup::three_with_kas(true),
            2,
            Who::Authority,
            3,
        ),
    ]
}

/// Named test of [F3]: a token of another covenant owned by the refunded vault, before the fee
/// input and after it.
#[test]
fn f3_refund_refuses_a_token_of_another_covenant() {
    for (label, setup, leg, signer, signer_leg) in refunds() {
        let w = WorldV2::new(setup);
        let control = w.refund(leg, signer, signer_leg);
        for at in [control.fee_idx(), control.inputs.len()] {
            let faulty = with_token_owned_by(&w, &control, leg, 0, foreign_token(), at);
            assert_accepted(
                &faulty.run(&w, at),
                &format!("{label}: the foreign transfer is valid"),
            );
            flips(
                &w,
                &control,
                &faulty,
                0,
                &format!("{label}, foreign token at input {at}"),
            );
        }
    }
}

/// The example of L20 in template v2: another leg's token sent to this vault's address does not
/// move with this vault's refund.
#[test]
fn f3_another_legs_token_at_the_vault_no_longer_moves_with_its_refund() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.refund(0, Who::Party(0), 0);
    let at = control.fee_idx();
    let faulty = with_token_owned_by(&w, &control, 0, 0, w.leg(1).token(), at);
    assert_accepted(
        &faulty.run(&w, at),
        "the misdirected token's transfer is valid",
    );
    flips(
        &w,
        &control,
        &faulty,
        0,
        "leg 1's token moved by vault 0's refund",
    );
}

#[test]
fn f3_a_fee_input_with_a_covenant_id_is_refused() {
    for (label, setup, leg, signer, signer_leg) in refunds() {
        let w = WorldV2::new(setup);
        let control = w.refund(leg, signer, signer_leg);
        let mut faulty = control.clone();
        let fee = faulty.fee_idx();
        faulty.inputs[fee].cov = Some(FOREIGN_COV);
        flips(&w, &control, &faulty, 0, label);
    }
}

// =============================================================================================
// [F4], [F5]: the bounds; fee inputs without covenants pass
// =============================================================================================

/// Named test of [F4]: a settle has at most N + 18 inputs. At the bound every vault accepts; one
/// more input, without a covenant, is refused by every vault, and refused first: before a
/// reference run at the bound that the next require, [S1], refuses (vaults 0 and 1 swapped).
#[test]
fn f4_a_settle_above_n_plus_18_inputs_is_refused_at_the_bound() {
    for (label, setup, lots) in settles() {
        let w = WorldV2::new(setup);
        let control = w.settle(lots);
        let full = with_fee_inputs(&control, w.n() + MAX_AFTER_VAULTS - control.inputs.len());
        assert_eq!(full.inputs.len(), w.n() + MAX_AFTER_VAULTS);
        full.assert_all_accepted(&w, &format!("{label}, N + 18 inputs"));
        let over = with_fee_inputs(&full, 1);
        for i in 0..w.n() {
            flips(
                &w,
                &full,
                &over,
                i,
                &format!("{label}, N + 19 inputs, vault {i}"),
            );
        }
        if lots != w.terms.lot_count {
            // A tranche binds continuations to the vault inputs, so they cannot be swapped.
            continue;
        }
        let mut swapped = full.clone();
        swapped.inputs.swap(0, 1);
        let reference = swapped.run(&w, 1);
        assert_refused(&reference, "reference refusal at [S1]");
        let at_bound = over.run(&w, 0);
        assert!(
            at_bound.used.0 < reference.used.0,
            "{label}: refused at [F4] after {} units, [S1] refuses after {}",
            at_bound.used.0,
            reference.used.0
        );
    }
}

/// Named test of [F5]: a refund has at most 12 inputs; a 13th is refused before a reference
/// refund at the bound that [R1] refuses (a signer leg beyond the authority).
#[test]
fn f5_a_refund_with_13_inputs_is_refused_at_the_bound() {
    for (label, setup, leg, signer, signer_leg) in refunds() {
        let w = WorldV2::new(setup);
        let control = w.refund(leg, signer, signer_leg);
        let full = with_fee_inputs(&control, MAX_REFUND_INPUTS - control.inputs.len());
        let over = with_fee_inputs(&full, 1);
        flips(&w, &full, &over, 0, &format!("{label}, 13 inputs"));
        let beyond = with_fee_inputs(
            &w.refund(leg, signer, w.n() as i64 + 1),
            MAX_REFUND_INPUTS - control.inputs.len(),
        );
        let reference = beyond.run(&w, 0);
        assert_refused(&reference, "reference refusal at [R1]");
        let at_bound = over.run(&w, 0);
        assert!(
            at_bound.used.0 < reference.used.0,
            "{label}: refused at [F5] after {} units, [R1] refuses after {}",
            at_bound.used.0,
            reference.used.0
        );
    }
}

/// Script units of a vault input with one fee input and at the bound, printed with
/// `-- --nocapture` for docs/evidence/template-fix-2026-10-19/v0.4-template-units.txt: the cost of each input after
/// the vaults that the builders budget for (spec/V2.md 6.4).
#[test]
fn units_per_input_after_the_vaults_are_measured() {
    eprintln!("| Spend | Vault input | 1 fee input | Inputs at the bound | Units | Units per extra input |");
    eprintln!("| --- | --- | --- | --- | --- | --- |");
    for (label, setup, lots) in settles() {
        let w = WorldV2::new(setup);
        let control = w.settle(lots);
        let n_in = control.inputs.len();
        let full = with_fee_inputs(&control, w.n() + MAX_AFTER_VAULTS - n_in);
        for i in 0..w.n() {
            let one = control.run(&w, i);
            let most = full.run(&w, i);
            assert_accepted(&one, label);
            assert_accepted(&most, label);
            let per = (most.used.0 - one.used.0) / (full.inputs.len() - n_in) as u64;
            eprintln!(
                "| settle {label} | {i} | {} | {} | {} | {per} |",
                one.used.0,
                full.inputs.len(),
                most.used.0
            );
        }
    }
    for (label, setup, leg, signer, signer_leg) in refunds() {
        let w = WorldV2::new(setup);
        let control = w.refund(leg, signer, signer_leg);
        let n_in = control.inputs.len();
        let full = with_fee_inputs(&control, MAX_REFUND_INPUTS - n_in);
        let one = control.run(&w, 0);
        let most = full.run(&w, 0);
        assert_accepted(&one, label);
        assert_accepted(&most, label);
        let per = (most.used.0 - one.used.0) / (MAX_REFUND_INPUTS - n_in) as u64;
        eprintln!(
            "| refund {label} | 0 | {} | {MAX_REFUND_INPUTS} | {} | {per} |",
            one.used.0, most.used.0
        );
    }
}

// =============================================================================================
// Tests of [E1], [E2], [D1], [C8], [R9] and [R10] whose fault carries no covenant [F1] or [F3]
// refuses
// =============================================================================================
//
// The named tests of these requires in v2_settle.rs and v2_refund.rs put a token of a decoy
// covenant, or a second escrow, outside the escrow slots, which [F1]
// or [F3] also refuse. Each test here makes the same fault inside the layout, so the require is still the
// only refusal of the vault run, and the mutation run (tests/engine/v2_mutation.py) names these.

fn stranger_state(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

/// [E2]: the two escrow slots hold each other's covenant (vault 0's escrow carries leg 1's
/// covenant ID, and leg 0's covenant sits at leg 1's slot), every output bound to the input of
/// its covenant. Vault 0 finds the only input of its covenant at N + 1.
#[test]
fn e2_the_escrow_slots_swap_their_covenants() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let (c0, c1) = (faulty.inputs[2].cov, faulty.inputs[3].cov);
    faulty.inputs[2].cov = c1;
    faulty.inputs[3].cov = c0;
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 3;
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    flips(&w, &control, &faulty, 0, "escrow covenants swapped");
}

/// [E1]: a second deposit of leg 0's covenant at leg 2's escrow slot (legs 0 and 2 run the same
/// template), leg 2's covenant carried by vault 2's own UTXO, which authorizes leg 2's delivery.
/// Vault 0 sees two inputs of its covenant, the first at its slot.
#[test]
fn e1_a_second_escrow_of_the_covenant_at_another_escrow_slot() {
    let mut w = WorldV2::new(Setup::ring(3, true));
    assert_eq!(
        w.leg(0).token().template_len(),
        w.leg(2).token().template_len()
    );
    let control = w.settle_final();
    // The transaction carries each input's covenant; the world's only sets them when it builds.
    w.vault_covs[2] = Some(w.leg(2).tmpl.cov);
    let mut faulty = w.settle_final();
    let n = w.n();
    faulty.inputs[n + 2] = InV2::token(
        w.leg(0)
            .token()
            .compile(w.escrow_state(0, w.leg(0).amount())),
        w.leg(0).tmpl.cov,
        vec![],
        0,
    );
    faulty.outputs[2]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    flips(
        &w,
        &control,
        &faulty,
        0,
        "second escrow of covenant 0 at leg 2's slot",
    );
}

/// [D1]: delivery 0 holds the delivered state's script but carries no covenant, while leg 0's
/// escrow goes to a stranger.
#[test]
fn d1_delivery_without_a_covenant_escrow_to_a_stranger() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    faulty.inputs[2].new_states_mut()[0] = stranger_state(TOKEN_AMOUNT);
    faulty.outputs[0].cov = None;
    faulty.outputs.push(Out::token(
        token.compile(stranger_state(TOKEN_AMOUNT)),
        w.leg(0).tmpl.cov,
        2,
    ));
    assert_accepted(&faulty.run(&w, 2), "the escrow's transfer is valid");
    flips(
        &w,
        &control,
        &faulty,
        0,
        "delivery 0 without a covenant, vault 0",
    );
    flips(
        &w,
        &control,
        &faulty,
        1,
        "delivery 0 without a covenant, vault 1",
    );
}

/// [C8]: the remainder token holds the remainder state's script but carries no covenant, while
/// the remainder goes to a stranger.
#[test]
fn c8_remainder_without_a_covenant_to_a_stranger() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let remainder = w.escrow_state(0, 7 * w.terms.unit(0));
    faulty.inputs[2].new_states_mut()[1] = stranger_state(remainder.amount);
    faulty.outputs[4].cov = None;
    faulty.outputs.push(Out::token(
        token.compile(stranger_state(remainder.amount)),
        w.leg(0).tmpl.cov,
        2,
    ));
    assert_accepted(&faulty.run(&w, 2), "the escrow's transfer is valid");
    flips(&w, &control, &faulty, 0, "remainder without a covenant");
}

/// [R9]: input 1 is a covenant-less UTXO with the escrow's script, read in place of the escrow,
/// which sits at input 2 and goes home at output 1.
#[test]
fn r9_covenant_less_copy_at_input_1_real_escrow_at_input_2() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    let real = faulty.inputs[1].clone();
    faulty.inputs[1].cov = None;
    faulty.inputs.insert(2, real);
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    flips(&w, &control, &faulty, 0, "covenant-less copy at input 1");
}

/// [R10]: output 1 holds the home state's script but carries no covenant, while the escrow goes
/// to a stranger.
#[test]
fn r10_home_output_without_a_covenant_escrow_to_a_stranger() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    faulty.inputs[1].new_states_mut()[0] = stranger_state(TOKEN_AMOUNT);
    faulty.outputs[1].cov = None;
    faulty.outputs.push(Out::token(
        token.compile(stranger_state(TOKEN_AMOUNT)),
        w.leg(0).tmpl.cov,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "the escrow's transfer is valid");
    flips(&w, &control, &faulty, 0, "home output without a covenant");
}
