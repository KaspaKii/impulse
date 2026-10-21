// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault v2 `refund(s, signerLeg)` in the real engine (spec/V2.md 4.5, 11.1).
//!
//! Passing: every role (the leg's depositor, another depositor, the authority) refunds every
//! leg kind, the depositor alone takes a KCC-20 authorizer home without its token, an earmarked
//! depositor refunds at expiry, a covenant vault refunds, and N = 10 refunds. Then one refusal
//! test per refund require against an accepted control that differs only in the one fault. Test
//! names start with the require ID ([R1] etc. in contracts/impulse_vault_v2.sil);
//! tests/engine/v2_mutation.py checks the mapping.

mod harness;
mod v2_harness;
use harness::*;
use kaspa_consensus_core::tx::CovenantBinding;
use v2_harness::*;

fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

/// Party 0 deposits legs 0 (KCC-20) and 2 (KAS), party 1 deposits leg 1 (KCC-20).
fn two_legs_one_party() -> Setup {
    Setup {
        parties: 2,
        legs: vec![
            LegSpec {
                party: 0,
                asset: Asset::Token(fixture_token(0)),
                amount: TOKEN_AMOUNT,
                to: 1,
            },
            LegSpec {
                party: 1,
                asset: Asset::Token(fixture_token(1)),
                amount: TOKEN_AMOUNT,
                to: 0,
            },
            LegSpec {
                party: 0,
                asset: Asset::Kas,
                amount: KAS_AMOUNT,
                to: 1,
            },
        ],
        authority: true,
        funding: EARMARKED,
        partial: None,
    }
}

fn insert_before_fee(tx: &mut TxV2, input: InV2) -> usize {
    let at = tx.fee_idx();
    tx.inputs.insert(at, input);
    at
}

// =============================================================================================
// Passing
// =============================================================================================

/// Legs 0 and 1 are KCC-20, leg 2 is KAS. Each leg is refunded by its depositor, by another
/// depositor and by the authority.
#[test]
fn every_role_refunds_every_leg_kind() {
    let w = WorldV2::new(Setup::three_with_kas(true));
    for leg in 0..3 {
        let own = w.setup.legs[leg].party;
        let other = (leg + 1) % 3;
        w.refund(leg, Who::Party(own), leg as i64)
            .assert_all_accepted(&w, &format!("leg {leg}, depositor"));
        w.refund(leg, Who::Party(w.setup.legs[other].party), other as i64)
            .assert_all_accepted(&w, &format!("leg {leg}, another depositor"));
        w.refund(leg, Who::Authority, 3)
            .assert_all_accepted(&w, &format!("leg {leg}, authority"));
    }
}

#[test]
fn depositor_refunds_the_authorizer_without_its_token() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false));
    w.refund_holding(1, Who::Party(1), 1, None)
        .assert_all_accepted(&w, "authorizer alone");
}

#[test]
fn earmarked_depositor_refunds_at_expiry() {
    let w = WorldV2::new(Setup::v1_kas_cash(true).earmarked());
    for leg in 0..2 {
        let tx = w.refund(leg, Who::Party(leg), leg as i64);
        assert_eq!(tx.lock_time, EXPIRY_DAA);
        tx.assert_all_accepted(&w, &format!("leg {leg} at expiry"));
    }
    // A non-depositor refunds an earmarked leg at once.
    let tx = w.refund(0, Who::Party(1), 1);
    assert_eq!(tx.lock_time, 0);
    tx.assert_all_accepted(&w, "counterparty, at once");
}

#[test]
fn covenant_vault_refunds() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true).partial(10, 1));
    w.refund(0, Who::Party(0), 0)
        .assert_all_accepted(&w, "covenant vault, depositor");
    w.refund(1, Who::Authority, 2)
        .assert_all_accepted(&w, "covenant vault, authority");
}

#[test]
fn n10_refunds() {
    let w = WorldV2::new(Setup::bilateral(MAX_LEGS, true));
    for leg in [0usize, 8, 9] {
        w.refund(leg, Who::Authority, MAX_LEGS as i64)
            .assert_all_accepted(&w, &format!("N = 10, leg {leg}"));
    }
}

// =============================================================================================
// [V3], [V4], [V8], [V9], [V10]: the state's shape (crafted states)
// =============================================================================================

/// legCount 11 > MAX_LEGS with eleven records: refund has no loop, so only [V3] refuses.
#[test]
fn v3_leg_count_above_max_legs() {
    let control_world = WorldV2::new(Setup::all_tokens(MAX_LEGS, true, 0));
    let control = control_world.refund(0, Who::Party(0), 0);
    let w = WorldV2::new(Setup::all_tokens(MAX_LEGS + 1, true, 0));
    let faulty = w.refund(0, Who::Party(0), 0);
    flips_across(&control_world, &control, &w, &faulty, 0, "legCount 11");
}

#[test]
fn v4_leg_list_longer_than_leg_count() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let crafted = w.edit(|t| t.legs_extra = t.legs[1].record());
    let faulty = crafted.refund(0, Who::Party(0), 0);
    flips_across(&w, &control, &crafted, &faulty, 0, "leg list too long");
}

#[test]
fn v4_leg_list_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let crafted = w.edit(|t| t.legs_cut = 1);
    let faulty = crafted.refund(0, Who::Party(0), 0);
    flips_across(
        &w,
        &control,
        &crafted,
        &faulty,
        0,
        "leg list one byte short",
    );
}

/// A crafted vault with legIndex == legCount. Without [V8] its record reads would run off the
/// leg list and fail as a malformed script, not a verdict.
#[test]
fn v8_leg_index_equal_to_leg_count() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.inputs[0] = InV2::refund(&w.terms.vault(2), Who::Party(1), 1, KAS_AMOUNT as u64);
    flips(&w, &control, &faulty, 0, "legIndex 2 of 2");
}

#[test]
fn v8_negative_leg_index() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.inputs[0] = InV2::refund(&w.terms.vault(-1), Who::Party(1), 1, KAS_AMOUNT as u64);
    flips(&w, &control, &faulty, 0, "legIndex -1");
}

/// Leg 0's kind byte is 2. Without [V9] the record would be taken as KCC-20 and refund.
#[test]
fn v9_leg_kind_byte_2() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(1), 1);
    let crafted = w.edit(|t| t.legs[0].kind = 2);
    let faulty = crafted.refund(0, Who::Party(1), 1);
    flips_across(&w, &control, &crafted, &faulty, 0, "leg 0 kind 2");
}

/// The KAS leg's refund type is 2, paid to P2SH(id). Without [V10] type 2 takes the P2SH branch.
#[test]
fn v10_kas_refund_type_2() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.refund(1, Who::Party(0), 0);
    let crafted = w.edit(|t| t.legs[1].refund.id_type = 2);
    let faulty = crafted.refund(1, Who::Party(0), 0);
    assert_eq!(control.outputs[0].spk, faulty.outputs[0].spk);
    flips_across(&w, &control, &crafted, &faulty, 0, "KAS refund type 2");
}

// =============================================================================================
// [R1], [R16], [R2]: who signs
// =============================================================================================

/// The authority signs and names leg N + 1. Without [R1] that index would also name the
/// authority.
#[test]
fn r1_signer_leg_beyond_the_authority() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Authority, 2);
    let faulty = w.refund(0, Who::Authority, 3);
    flips(&w, &control, &faulty, 0, "signerLeg 3 of 2");
}

#[test]
fn r1_negative_signer_leg() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let faulty = w.refund(0, Who::Party(0), -1);
    flips(&w, &control, &faulty, 0, "signerLeg -1");
}

/// A crafted state with hasAuthority false and the authority's key in authorityKey (no terms v2
/// value has it). Without [R16] the key's holder could refund by naming leg N.
#[test]
fn r16_authority_signs_when_the_terms_name_none() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Authority, 2);
    let crafted = w.edit(|t| t.has_authority = false);
    let faulty = crafted.refund(0, Who::Authority, 2);
    flips_across(
        &w,
        &control,
        &crafted,
        &faulty,
        0,
        "no authority in the terms",
    );
}

#[test]
fn r2_depositor_named_stranger_signs() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let faulty = w.refund(0, Who::Stranger, 0);
    flips(&w, &control, &faulty, 0, "stranger signs as depositor 0");
}

#[test]
fn r2_another_depositor_named_stranger_signs() {
    let w = WorldV2::new(Setup::ring(3, false));
    let control = w.refund(0, Who::Party(2), 2);
    let faulty = w.refund(0, Who::Stranger, 2);
    flips(&w, &control, &faulty, 0, "stranger signs as depositor 2");
}

// =============================================================================================
// [R3] earmark
// =============================================================================================

#[test]
fn r3_earmarked_depositor_one_daa_before_expiry() {
    let w = WorldV2::new(Setup::v1_kas_cash(false).earmarked());
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.lock_time = EXPIRY_DAA - 1;
    flips_locktime(&w, &control, &faulty, 0, "earmarked, expiry - 1");
}

/// Party 0 deposited legs 0 and 2. Naming leg 2 to refund leg 0 does not escape leg 0's earmark:
/// roles are compared by key (spec/V2.md 4.5).
#[test]
fn r3_depositor_naming_another_of_its_legs_is_still_earmarked() {
    let w = WorldV2::new(two_legs_one_party());
    let control = w.refund(0, Who::Party(0), 2);
    assert_eq!(
        control.lock_time, EXPIRY_DAA,
        "the harness treats it as the depositor"
    );
    let mut faulty = control.clone();
    faulty.lock_time = 0;
    flips_locktime(
        &w,
        &control,
        &faulty,
        0,
        "party 0 names leg 2 to refund leg 0",
    );
    // The other party refunds leg 0 at once.
    w.refund(0, Who::Party(1), 1)
        .assert_all_accepted(&w, "party 1, at once");
}

// =============================================================================================
// [R4], [R5], [R15], [R6], [R7]: the vault UTXO goes home whole
// =============================================================================================

/// The KAS depositor funded twice; both UTXOs in one refund, the second at input 1 with its KAS
/// in the change (v1 [R4]).
#[test]
fn r4_second_kas_deposit_cannot_refund_off_input_0() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.inputs.insert(
        1,
        InV2::refund(&w.vaults[1], Who::Party(1), 1, KAS_AMOUNT as u64),
    );
    faulty.outputs.last_mut().expect("change").value += KAS_AMOUNT as u64;
    flips(&w, &control, &faulty, 1, "second KAS vault UTXO at input 1");
}

#[test]
fn r5_vault_kas_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    flips(&w, &control, &faulty, 0, "authorizer one sompi short");
}

/// A covenant vault's refund that leaves an output of its covenant.
#[test]
fn r15_refund_leaves_a_continuation() {
    let w = WorldV2::new(Setup::v1_kas_cash(false).partial(10, 1));
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.outputs.push(Out {
        value: 1,
        spk: w.vaults[1].p2sh(),
        cov: Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: vault_cov(1),
        }),
    });
    flips(&w, &control, &faulty, 0, "refund with a continuation");
}

#[test]
fn r6_kas_refund_to_stranger() {
    let w = WorldV2::new(Setup::v1_kas_cash(true));
    let control = w.refund(1, Who::Authority, 2);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    flips(&w, &control, &faulty, 0, "KAS refund to a stranger");
}

#[test]
fn r7_authorizer_kas_to_stranger() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(1, Who::Authority, 2);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    flips(&w, &control, &faulty, 0, "authorizer to a stranger");
}

// =============================================================================================
// [R11], [R8], [R9], [R12]: the escrowed token
// =============================================================================================

/// Another depositor cannot refund a KCC-20 authorizer without its token (v1 [R11]).
#[test]
fn r11_another_depositor_cannot_refund_the_authorizer_alone() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(1), 1);
    let faulty = w.refund_holding(0, Who::Party(1), 1, None);
    flips(
        &w,
        &control,
        &faulty,
        0,
        "party 1 refunds authorizer 0 alone",
    );
}

#[test]
fn r11_authority_cannot_refund_the_authorizer_alone() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(1, Who::Authority, 2);
    let faulty = w.refund_holding(1, Who::Authority, 2, None);
    flips(
        &w,
        &control,
        &faulty,
        0,
        "authority refunds authorizer 1 alone",
    );
}

/// Two escrows of the leg's covenant in the depositor's refund (v1 [R8]).
#[test]
fn r8_second_escrow_rides_along() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    insert_before_fee(
        &mut faulty,
        InV2::token(
            w.leg(0).token().compile(w.escrow_state(0, TOKEN_AMOUNT)),
            w.leg(0).tmpl.cov,
            vec![],
            0,
        ),
    );
    flips(&w, &control, &faulty, 0, "second escrow of covenant 0");
}

/// Input 1 is a decoy of another covenant (same template, owned by the vault); the real escrow
/// sits at input 2 and goes home at output 1 (v1 [R9]).
#[test]
fn r9_decoy_at_input_1_real_escrow_elsewhere() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let real = faulty.inputs[1].clone();
    faulty.inputs[1] = InV2::token(
        token.compile(w.escrow_state(0, TOKEN_AMOUNT)),
        DECOY_TOKEN_COV,
        vec![Kcc20State::new(STRANGER_OWNER, TOKEN_AMOUNT)],
        0,
    );
    faulty.inputs.insert(2, real);
    faulty.outputs[1]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    faulty.outputs.push(Out::token(
        token.compile(Kcc20State::new(STRANGER_OWNER, TOKEN_AMOUNT)),
        DECOY_TOKEN_COV,
        1,
    ));
    flips(&w, &control, &faulty, 0, "decoy at input 1");
}

/// Another depositor offers a token of the leg's covenant that a stranger owns (v1 [R12]).
#[test]
fn r12_foreign_token_not_owned_by_the_vault() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(1), 1);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let foreign = Kcc20State::new(standin_owner(), TOKEN_AMOUNT);
    let fee = faulty.fee_idx();
    faulty.inputs[1] = InV2::token(
        token.compile(foreign),
        w.leg(0).tmpl.cov,
        vec![Kcc20State::new(w.leg(0).refund, TOKEN_AMOUNT)],
        fee as u8,
    );
    flips(&w, &control, &faulty, 0, "foreign token");
}

// =============================================================================================
// [R14], [R17], [R18]: a non-depositor refund's token holds whole lots of the leg
// =============================================================================================

fn partial_world() -> WorldV2 {
    WorldV2::new(Setup::v1_kcc20_cash(true).partial(10, 1))
}

#[test]
fn r14_decoy_below_one_lot() {
    let w = partial_world();
    let control = w.refund_holding(0, Who::Party(1), 1, Some(TOKEN_AMOUNT / 10));
    let faulty = w.refund_holding(0, Who::Party(1), 1, Some(0));
    flips(&w, &control, &faulty, 0, "token holds 0");
}

#[test]
fn r14_without_partial_the_leg_amount_exactly() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Authority, 2);
    let faulty = w.refund_holding(0, Who::Authority, 2, Some(TOKEN_AMOUNT - 1));
    flips(&w, &control, &faulty, 0, "token one unit short");
    let faulty = w.refund_holding(0, Who::Authority, 2, Some(TOKEN_AMOUNT + 1));
    flips(&w, &control, &faulty, 0, "token one unit over");
}

#[test]
fn r17_token_above_the_leg_amount() {
    let w = partial_world();
    let control = w.refund_holding(0, Who::Party(1), 1, Some(TOKEN_AMOUNT));
    let faulty = w.refund_holding(0, Who::Party(1), 1, Some(TOKEN_AMOUNT + TOKEN_AMOUNT / 10));
    flips(&w, &control, &faulty, 0, "token holds 11 lots of 10");
}

#[test]
fn r18_token_not_whole_lots() {
    let w = partial_world();
    let control = w.refund_holding(0, Who::Party(1), 1, Some(TOKEN_AMOUNT / 10 * 9));
    let faulty = w.refund_holding(0, Who::Party(1), 1, Some(TOKEN_AMOUNT / 10 * 9 + 50));
    flips(&w, &control, &faulty, 0, "token holds 9.5 lots");
}

/// The depositor may take any token of its own vault home.
#[test]
fn depositor_refunds_any_amount() {
    let w = partial_world();
    for held in [0, 1, TOKEN_AMOUNT + 1] {
        w.refund_holding(0, Who::Party(0), 0, Some(held))
            .assert_all_accepted(&w, &format!("depositor, token holds {held}"));
    }
}

// =============================================================================================
// [R10], [R13] and the home builtin
// =============================================================================================

/// Output 1 is a decoy token of another covenant with the home state; the real escrow goes to a
/// stranger at the end (v1 [R10]).
#[test]
fn r10_home_output_under_decoy_covenant() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(0), 0);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let home = Kcc20State::new(w.leg(0).refund, TOKEN_AMOUNT);
    let to_stranger = Kcc20State::new(STRANGER_OWNER, TOKEN_AMOUNT);
    faulty.inputs[1].new_states_mut()[0] = to_stranger;
    let fee = faulty.fee_idx();
    let at = insert_before_fee(
        &mut faulty,
        InV2::token(
            token.compile(Kcc20State::new(standin_owner(), TOKEN_AMOUNT)),
            DECOY_TOKEN_COV,
            vec![home],
            (fee + 1) as u8,
        ),
    );
    faulty.outputs[1] = Out::token(token.compile(home), DECOY_TOKEN_COV, at as u16);
    faulty
        .outputs
        .push(Out::token(token.compile(to_stranger), w.leg(0).tmpl.cov, 1));
    flips(&w, &control, &faulty, 0, "home under a decoy covenant");
}

#[test]
fn r13_home_carrier_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(1, Who::Party(1), 1);
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    flips(&w, &control, &faulty, 0, "home carrier short");
}

#[test]
fn home_builtin_wrong_owner_amount_or_minter() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.refund(0, Who::Party(1), 1);
    for state in [
        Kcc20State::new(STRANGER_OWNER, TOKEN_AMOUNT),
        Kcc20State::new(w.leg(0).refund, TOKEN_AMOUNT - 1),
        Kcc20State {
            is_minter: true,
            ..Kcc20State::new(w.leg(0).refund, TOKEN_AMOUNT)
        },
    ] {
        let mut faulty = control.clone();
        faulty.inputs[1].new_states_mut()[0] = state;
        faulty.outputs[1] = Out::token(w.leg(0).token().compile(state), w.leg(0).tmpl.cov, 1);
        flips(&w, &control, &faulty, 0, &format!("home {state:?}"));
    }
}
