// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashlock template: no token rides along in a spend of the vault (spec/V2.md 10.4,
//! "Inputs outside the layout"; known limitation L20). In the real engine:
//!
//! - `[HF1]`, `[HF3]`: a claim or a refund with a token of another covenant at any input after
//!   the vault is refused.
//! - `[HF2]`, `[HF4]`: a spend has at most 12 inputs; a 13th is refused first.
//! - Covenant-less versions of the faults of `[HE2]`, `[HD1]`, `[HR9]` and `[HR10]`, whose
//!   named tests in htlc_settle.rs and htlc_refund.rs also trip `[HF1]` or `[HF3]`.

mod harness;
mod htlc_harness;
use harness::*;
use htlc_harness::*;
use kaspa_consensus_core::Hash;

const FOREIGN_COV: Hash = Hash::from_bytes([0xF0; 32]);
const FOREIGN_TOKEN: Token = Token {
    cov: FOREIGN_COV,
    max_cov_ins: 2,
    max_cov_outs: 2,
};
const FOREIGN_AMOUNT: i64 = 777;
const MAX_INPUTS: usize = 12;

/// `tx` with a token of another covenant owned by the vault inserted at input `at`, sent whole to
/// a stranger by its own transfer (witness: the vault at input 0).
fn with_foreign_token(w: &HtlcWorld, tx: &HtlcTx, token: Token, amount: i64, at: usize) -> HtlcTx {
    let mut faulty = tx.clone();
    let held = Kcc20State::new(Owner::script_hash(w.vault.script_hash()), amount);
    faulty.inputs.insert(
        at,
        HIn::token(token.compile(held), token.cov, vec![stranger(amount)], 0),
    );
    let out_at = faulty.outputs.len() - 1;
    faulty.outputs.insert(
        out_at,
        Out::token(token.compile(stranger(amount)), token.cov, at as u16),
    );
    faulty
}

fn with_fee_inputs(tx: &HtlcTx, extra: usize) -> HtlcTx {
    let mut out = tx.clone();
    for _ in 0..extra {
        out.inputs.push(HIn::plain(FEE_VALUE));
    }
    out
}

fn spends(w: &HtlcWorld) -> Vec<(&'static str, HtlcTx)> {
    vec![
        ("claim", w.claim(&SECRET)),
        ("seller refund", w.refund(Role::Seller)),
        ("buyer refund", w.refund(Role::Buyer)),
    ]
}

// =============================================================================================
// [HF1] claim, [HF3] refund
// =============================================================================================

/// Named test of [HF1]: the claim refuses a token of another covenant owned by the vault, before
/// the fee input and after it.
#[test]
fn hf1_claim_refuses_a_token_of_another_covenant() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    for at in [control.fee_idx(), control.inputs.len()] {
        let faulty = with_foreign_token(&w, &control, FOREIGN_TOKEN, FOREIGN_AMOUNT, at);
        assert_accepted(&faulty.run(&w, at), "the foreign transfer is valid");
        assert_htlc_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("foreign token at input {at}"),
        );
    }
}

/// Named test of [HF3]: both refunds refuse a token of another covenant owned by the vault.
#[test]
fn hf3_refund_refuses_a_token_of_another_covenant() {
    let w = HtlcWorld::new();
    for signer in [Role::Seller, Role::Buyer] {
        let control = w.refund(signer);
        for at in [control.fee_idx(), control.inputs.len()] {
            let faulty = with_foreign_token(&w, &control, FOREIGN_TOKEN, FOREIGN_AMOUNT, at);
            assert_accepted(&faulty.run(&w, at), "the foreign transfer is valid");
            assert_htlc_flips(
                &w,
                &control,
                &faulty,
                0,
                &format!("{signer:?} refund, foreign token at input {at}"),
            );
        }
    }
}

/// The seller's refund of the authorizer alone refuses a token of another covenant at input 1.
#[test]
fn hf3_authorizer_alone_refuses_a_token_of_another_covenant_at_input_1() {
    let w = HtlcWorld::new();
    let mut control = w.refund(Role::Seller);
    control.inputs.remove(1);
    control.outputs.remove(1);
    let faulty = with_foreign_token(&w, &control, FOREIGN_TOKEN, FOREIGN_AMOUNT, 1);
    assert_accepted(&faulty.run(&w, 1), "the foreign transfer is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "foreign token at input 1");
}

/// A fee input bound to a covenant is refused by the claim and by both refunds.
#[test]
fn hf1_hf3_a_fee_input_with_a_covenant_id_is_refused() {
    let w = HtlcWorld::new();
    for (label, control) in spends(&w) {
        let mut faulty = control.clone();
        let fee = faulty.fee_idx();
        faulty.inputs[fee].cov = Some(FOREIGN_COV);
        assert_htlc_flips(&w, &control, &faulty, 0, label);
    }
}

// =============================================================================================
// [HF2], [HF4]: the bound; fee inputs without covenants pass
// =============================================================================================

#[test]
fn fee_inputs_without_covenants_pass_up_to_the_bound() {
    let w = HtlcWorld::new();
    for (label, control) in spends(&w) {
        let full = with_fee_inputs(&control, MAX_INPUTS - control.inputs.len());
        assert_eq!(full.inputs.len(), MAX_INPUTS);
        full.assert_all_accepted(&w, &format!("{label}, {MAX_INPUTS} inputs"));
    }
}

/// Named test of [HF2]: a claim with a 13th input is refused, before a reference claim at the
/// bound that [H2] refuses (a 33-byte secret).
#[test]
fn hf2_a_claim_with_13_inputs_is_refused_at_the_bound() {
    let w = HtlcWorld::new();
    let full = with_fee_inputs(&w.claim(&SECRET), MAX_INPUTS - 3);
    let over = with_fee_inputs(&full, 1);
    assert_htlc_flips(&w, &full, &over, 0, "claim, 13 inputs");
    let mut long = SECRET.to_vec();
    long.push(0);
    let reference = with_fee_inputs(&w.claim(&long), MAX_INPUTS - 3).run(&w, 0);
    assert_refused(&reference, "reference refusal at [H2]");
    let at_bound = over.run(&w, 0);
    assert!(
        at_bound.used.0 < reference.used.0,
        "refused at [HF2] after {} units, [H2] refuses after {}",
        at_bound.used.0,
        reference.used.0
    );
}

/// Named test of [HF4]: a refund with a 13th input is refused, before a reference refund at the
/// bound that [HR1] refuses (a stranger signs).
#[test]
fn hf4_a_refund_with_13_inputs_is_refused_at_the_bound() {
    let w = HtlcWorld::new();
    for signer in [Role::Seller, Role::Buyer] {
        let full = with_fee_inputs(&w.refund(signer), MAX_INPUTS - 3);
        let over = with_fee_inputs(&full, 1);
        assert_htlc_flips(
            &w,
            &full,
            &over,
            0,
            &format!("{signer:?} refund, 13 inputs"),
        );
        let reference = with_fee_inputs(&w.refund(Role::Stranger), MAX_INPUTS - 3).run(&w, 0);
        assert_refused(&reference, "reference refusal at [HR1]");
        let at_bound = over.run(&w, 0);
        assert!(
            at_bound.used.0 < reference.used.0,
            "{signer:?}: refused at [HF4] after {} units, [HR1] refuses after {}",
            at_bound.used.0,
            reference.used.0
        );
    }
}

/// Script units of the vault input with one fee input and at the bound, printed with
/// `-- --nocapture` for docs/evidence/template-fix-2026-10-19/v0.4-template-units.txt.
#[test]
fn units_per_input_are_measured() {
    let w = HtlcWorld::new();
    eprintln!("| Spend | 1 fee input | 12 inputs | Units per extra input |");
    eprintln!("| --- | --- | --- | --- |");
    for (label, control) in spends(&w) {
        let n = control.inputs.len();
        let full = with_fee_inputs(&control, MAX_INPUTS - n);
        let (one, most) = (control.run(&w, 0), full.run(&w, 0));
        assert_accepted(&one, label);
        assert_accepted(&most, label);
        let per = (most.used.0 - one.used.0) / (MAX_INPUTS - n) as u64;
        eprintln!("| {label} | {} | {} | {per} |", one.used.0, most.used.0);
    }
}

// =============================================================================================
// Covenant-less faults for [HE2], [HD1], [HR9] and [HR10]
// =============================================================================================

/// [HE2]: the escrow at input 1 carries no covenant (a UTXO with the escrow's script, which
/// anyone can make) while a real asset token at input 2 supplies the delivery.
#[test]
fn he2_escrow_without_a_covenant_real_asset_elsewhere() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.inputs[1].cov = None;
    *faulty.inputs[1].leader_states() = vec![];
    let at = faulty.fee_idx();
    faulty.inputs.insert(
        at,
        HIn::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            ASSET_COV,
            vec![w.delivered()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = at as u16;
    assert_accepted(&faulty.run(&w, at), "the real asset transfer is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "covenant-less escrow, real asset elsewhere",
    );
}

/// [HD1]: output 0 holds the delivered state's script but carries no covenant, while the escrow
/// goes to a stranger.
#[test]
fn hd1_output0_without_a_covenant_escrow_to_a_stranger() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.outputs[0].cov = None;
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "the escrow's transfer is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 without a covenant");
}

/// [HR9]: a covenant-less copy of the escrow at input 1 is read in place of the escrow, which
/// sits at input 2.
#[test]
fn hr9_covenant_less_copy_at_input_1_real_escrow_at_input_2() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    let real = faulty.inputs[1].clone();
    faulty.inputs[1].cov = None;
    faulty.inputs.insert(2, real);
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "covenant-less copy in place of the escrow",
    );
}

/// [HR10]: output 1 holds the home state's script but carries no covenant, while the escrow goes
/// to a stranger.
#[test]
fn hr10_home_output_without_a_covenant_escrow_to_a_stranger() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.outputs[1].cov = None;
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "the escrow's transfer is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "home output without a covenant");
}
