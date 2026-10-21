// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault v2 `settle` in the real engine (spec/V2.md 4.3, 4.4, 11.1).
//!
//! Passing: N = 2 in v1's KAS-cash and KCC-20-cash layouts (with and without an authority, and
//! position for position against the v1 harness), N = 3 (a ring of three KCC-20 legs, and one
//! with a KAS leg), N = 10 = MAX_LEGS (nine KCC-20 legs and one KAS leg; all KCC-20). Missing
//! delivery: for each leg j, a missing, redirected or short delivery j makes every vault input
//! refuse, as an N by N matrix for N = 3 and N = 10.
//!
//! Then one refusal test per settle require, each against an accepted control that differs only
//! in the one fault. Test names start with the require ID they exercise ([S1] etc. in
//! contracts/impulse_vault_v2.sil); tests/engine/v2_mutation.py checks the mapping. The tranche
//! tags ([C2] to [C9]) get their first failing test here; I17 adds its own cases.
//! Tests that need a crafted state (a field no terms v2 value encodes to) say so: the contract
//! must hold for any state, because anyone can fund any script.

mod harness;
mod v2_harness;
use harness::*;
use kaspa_consensus_core::tx::CovenantBinding;
use kaspa_consensus_core::Hash;
use v2_harness::*;

/// A token owner whose witness is any plain P2SH(OpTrue) input (the fee input here).
fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

fn stranger_owner() -> Owner {
    STRANGER_OWNER
}

/// Two KAS legs between two parties (no KCC-20 leg), for the tranche and lots cases that are
/// simplest with KAS remainders.
fn kas_pair() -> Setup {
    Setup {
        parties: 2,
        legs: vec![
            LegSpec {
                party: 0,
                asset: Asset::Kas,
                amount: KAS_AMOUNT,
                to: 1,
            },
            LegSpec {
                party: 1,
                asset: Asset::Kas,
                amount: 2 * KAS_AMOUNT,
                to: 0,
            },
        ],
        authority: false,
        funding: REVOCABLE,
        partial: None,
    }
}

/// Inserts `input` just before the fee input and returns its index.
fn insert_before_fee(tx: &mut TxV2, input: InV2) -> usize {
    let at = tx.fee_idx();
    tx.inputs.insert(at, input);
    at
}

// =============================================================================================
// Passing
// =============================================================================================

#[test]
fn n2_kas_cash_authority() {
    let w = WorldV2::new(Setup::v1_kas_cash(true));
    w.settle_final()
        .assert_all_accepted(&w, "N = 2, authority, KAS cash");
}

#[test]
fn n2_kas_cash_self_settling() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    w.settle_final()
        .assert_all_accepted(&w, "N = 2, self-settling, KAS cash");
}

#[test]
fn n2_kcc20_cash_authority() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    w.settle_final()
        .assert_all_accepted(&w, "N = 2, authority, KCC-20 cash");
}

#[test]
fn n2_kcc20_cash_self_settling() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false));
    w.settle_final()
        .assert_all_accepted(&w, "N = 2, self-settling, KCC-20 cash");
}

/// Funding mode does not gate settle (v1 settle_earmarked_funding).
#[test]
fn n2_earmarked_funding() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true).earmarked());
    w.settle_final()
        .assert_all_accepted(&w, "N = 2, authority, KCC-20 cash, earmarked");
}

/// N = 2 is v1's layout position for position (spec/V2.md 4.3): the same inputs and outputs, of
/// the same kinds and values, bound to the same authorizing inputs, as the v1 harness builds
/// for the same mode.
#[test]
fn n2_layout_is_v1_layout_position_for_position() {
    for (cash, setup) in [
        (CASH_KAS, Setup::v1_kas_cash(true)),
        (CASH_KCC20, Setup::v1_kcc20_cash(true)),
    ] {
        let v1w = World::new(Mode::new(true, cash, REVOCABLE));
        let v1 = v1w.settle();
        let w = WorldV2::new(setup);
        let v2 = w.settle_final();
        assert_eq!(v1.inputs.len(), v2.inputs.len(), "inputs, cash {cash}");
        assert_eq!(v1.outputs.len(), v2.outputs.len(), "outputs, cash {cash}");
        for (n, (a, b)) in v1.inputs.iter().zip(&v2.inputs).enumerate() {
            let kind_a = match a.spend {
                Spend::Plain => "plain",
                Spend::Settle { .. } => "vault",
                Spend::Kcc20Leader { .. } => "token",
                _ => "other",
            };
            let kind_b = match b.spend {
                SpendV2::Plain => "plain",
                SpendV2::Settle { .. } => "vault",
                SpendV2::Kcc20Leader { .. } => "token",
                _ => "other",
            };
            assert_eq!(kind_a, kind_b, "input {n}, cash {cash}");
            assert_eq!(a.value, b.value, "input {n} value, cash {cash}");
        }
        for (n, (a, b)) in v1.outputs.iter().zip(&v2.outputs).enumerate() {
            assert_eq!(a.value, b.value, "output {n} value, cash {cash}");
            assert_eq!(
                a.cov.map(|c| c.authorizing_input),
                b.cov.map(|c| c.authorizing_input),
                "output {n} binding, cash {cash}"
            );
        }
        assert_eq!(v1.lock_time, v2.lock_time);
        v2.assert_all_accepted(&w, "N = 2 layout");
    }
}

#[test]
fn n3_ring_of_three_kcc20_legs() {
    for authority in [true, false] {
        let w = WorldV2::new(Setup::ring(3, authority));
        w.settle_final().assert_all_accepted(&w, "N = 3 ring");
    }
}

#[test]
fn n3_two_kcc20_legs_and_a_kas_leg() {
    for authority in [true, false] {
        let w = WorldV2::new(Setup::three_with_kas(authority));
        w.settle_final()
            .assert_all_accepted(&w, "N = 3 with a KAS leg");
    }
}

/// N = MAX_LEGS = 10: the I16 ten-line bilateral list (nine KCC-20 legs and one KAS leg).
#[test]
fn n10_bilateral_nine_kcc20_legs_and_a_kas_leg() {
    let w = WorldV2::new(Setup::bilateral(MAX_LEGS, true));
    assert_eq!((w.n(), w.k()), (10, 9));
    w.settle_final().assert_all_accepted(&w, "N = 10 bilateral");
}

#[test]
fn n10_all_kcc20_legs_self_settling() {
    let w = WorldV2::new(Setup::all_tokens(MAX_LEGS, false, 0));
    w.settle_final()
        .assert_all_accepted(&w, "N = 10 all KCC-20");
}

/// A tranche on partial terms settles (the I17 shape; here the first test of its requires).
#[test]
fn tranche_settles_on_partial_terms() {
    for setup in [
        Setup::v1_kas_cash(true).partial(10, 2),
        Setup::v1_kcc20_cash(false).partial(10, 2),
        Setup::three_with_kas(false).partial(4, 1),
    ] {
        let w = WorldV2::new(setup);
        w.settle(2).assert_all_accepted(&w, "tranche of 2 lots");
        w.settle(w.terms.lot_count)
            .assert_all_accepted(&w, "every lot at once is final");
    }
}

/// Fixed-width integer boundary (spec/V2.md 3.2): a KCC-20 amount of i64::MAX settles.
#[test]
fn amount_i64_max_settles() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let w = w.edit(|t| t.legs[0].set_amount(i64::MAX));
    w.settle_final().assert_all_accepted(&w, "amount i64::MAX");
}

/// Fixed-width integer boundary: a crafted record whose amount has the top bit of byte 8 set is
/// read as negative (-5 here). The escrow holds 5: vault 0 refuses at [P2] (5 <= -5 is false)
/// and vault 1 at the delivery builtin of leg 0 (it expects -5 delivered). Crafted state.
#[test]
fn amount_with_top_bit_set_is_negative_and_refused() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.edit(|t| t.legs[0].set_amount(5));
    let faulty = control.edit(|t| t.legs[0].amount_bytes = [5, 0, 0, 0, 0, 0, 0, 0x80]);
    assert_eq!(faulty.leg(0).amount(), -5);
    control
        .settle_final()
        .assert_all_accepted(&control, "amount 5 (control)");
    // The escrow and the delivery are the honest ones for 5 tokens.
    let mut tx = faulty.settle_final();
    let token = faulty.leg(0).token();
    tx.inputs[2] = InV2::token(
        token.compile(faulty.escrow_state(0, 5)),
        faulty.leg(0).tmpl.cov,
        vec![faulty.delivered(0, 5)],
        0,
    );
    tx.outputs[0] = Out::token(
        token.compile(faulty.delivered(0, 5)),
        faulty.leg(0).tmpl.cov,
        2,
    );
    tx.assert_every_vault_refused(&faulty, "amount read as -5");
}

// =============================================================================================
// Missing delivery: every vault refuses, for every leg
// =============================================================================================

#[derive(Clone, Copy, Debug)]
enum Fault {
    /// The delivery slot holds a plain output of the same value to a stranger.
    Missing,
    /// Delivered to a stranger (owner or scriptPubKey).
    Redirected,
    /// One unit short.
    Short,
}

fn break_delivery(w: &WorldV2, tx: &mut TxV2, j: usize, fault: Fault) {
    let leg = w.leg(j).clone();
    let n = w.n();
    let amount = leg.amount() / w.terms.lot_count * w.terms.lot_count;
    match (leg.is_token(), fault) {
        (_, Fault::Missing) => {
            let value = tx.outputs[j].value;
            tx.outputs[j] = Out::kas(value, stranger_spk());
            if leg.is_token() {
                // The escrow's transfer now pays a stranger at the end.
                let s = Kcc20State::new(stranger_owner(), amount);
                tx.inputs[n + j].new_states_mut()[0] = s;
                tx.outputs.push(Out::token(
                    leg.token().compile(s),
                    leg.tmpl.cov,
                    (n + j) as u16,
                ));
            }
        }
        (true, Fault::Redirected) | (true, Fault::Short) => {
            let s = match fault {
                Fault::Redirected => Kcc20State::new(stranger_owner(), amount),
                _ => w.delivered(j, amount - 1),
            };
            tx.inputs[n + j].new_states_mut()[0] = s;
            tx.outputs[j] = Out::token(leg.token().compile(s), leg.tmpl.cov, (n + j) as u16);
        }
        (false, Fault::Redirected) => tx.outputs[j].spk = stranger_spk(),
        (false, Fault::Short) => tx.outputs[j].value -= 1,
    }
}

fn missing_delivery_matrix(w: &WorldV2, label: &str) {
    let control = w.settle_final();
    control.assert_all_accepted(w, &format!("{label} (control)"));
    for j in 0..w.n() {
        for fault in [Fault::Missing, Fault::Redirected, Fault::Short] {
            let mut tx = control.clone();
            break_delivery(w, &mut tx, j, fault);
            tx.assert_every_vault_refused(w, &format!("{label}: delivery {j} {fault:?}"));
        }
    }
}

#[test]
fn missing_delivery_fails_every_vault_n3_ring() {
    missing_delivery_matrix(&WorldV2::new(Setup::ring(3, false)), "N = 3 ring");
}

#[test]
fn missing_delivery_fails_every_vault_n3_with_kas() {
    missing_delivery_matrix(&WorldV2::new(Setup::three_with_kas(true)), "N = 3 with KAS");
}

#[test]
fn missing_delivery_fails_every_vault_n10() {
    missing_delivery_matrix(
        &WorldV2::new(Setup::bilateral(MAX_LEGS, false)),
        "N = 10 bilateral",
    );
}

// =============================================================================================
// Cross-vault consistency: `lots` is a per-input witness argument
// =============================================================================================

/// Every vault input of one settle is unlocked with its own `lots`. Each vault checks the same
/// delivery outputs against its own `lots`, so the vault given a different value cannot be
/// satisfied by outputs built for the others: it refuses, and the transaction as a whole is
/// invalid. The control gives every vault the same `lots` and is accepted at every input.
fn lots_mismatch_matrix(w: &WorldV2, base: i64, label: &str) {
    w.settle(base)
        .assert_all_accepted(w, &format!("{label}: all lots {base} (control)"));
    let final_lots = w.terms.lot_count;
    for i in 0..w.n() {
        for odd in [base - 1, base + 1, final_lots] {
            if odd == base || odd < 1 {
                continue;
            }
            let mut tx = w.settle(base);
            *tx.inputs[i].lots_mut() = odd;
            let (built, entries) = tx.build(w);
            let verdict = execute(&built, &entries, i);
            assert_refused(
                &verdict,
                &format!("{label}: vault {i} given lots {odd}, others {base}"),
            );
        }
    }
}

#[test]
fn lots_differ_across_vaults_n3() {
    lots_mismatch_matrix(
        &WorldV2::new(Setup::three_with_kas(false).partial(4, 1)),
        2,
        "N = 3 with KAS, partial",
    );
    lots_mismatch_matrix(
        &WorldV2::new(Setup::ring(3, true).partial(4, 1)),
        2,
        "N = 3 ring, partial",
    );
}

#[test]
fn lots_differ_across_vaults_n10() {
    lots_mismatch_matrix(
        &WorldV2::new(Setup::bilateral(MAX_LEGS, false).partial(10, 2)),
        4,
        "N = 10 bilateral, partial",
    );
}

// =============================================================================================
// [S1] position
// =============================================================================================

/// The KAS depositor funded its vault twice. In a self-settling trade anyone may submit the
/// settle; the second UTXO must not settle at another input, where delivery 1 would satisfy it a
/// second time and its KAS would go to the submitter's change (v1 [S1]).
#[test]
fn s1_second_kas_deposit_cannot_settle_off_its_index() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let at = insert_before_fee(
        &mut faulty,
        InV2::settle(&w.vaults[1], None, 1, KAS_AMOUNT as u64),
    );
    faulty.outputs.last_mut().expect("change").value += KAS_AMOUNT as u64;
    flips(
        &w,
        &control,
        &faulty,
        at,
        "second KAS vault UTXO at input 3",
    );
}

#[test]
fn s1_vault_at_another_vault_position() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.inputs.swap(0, 1);
    flips(&w, &control, &faulty, 1, "vault 0 at input 1");
}

// =============================================================================================
// [V1], [V2], [V5]: the state's shape, checked by the script itself (crafted states)
// =============================================================================================

/// A crafted state with legCount 11 > MAX_LEGS and eleven records. The silverc v1.0.0 loop
/// guard would also refuse it later; [V1] refuses first, before the escrow is read, which the
/// units consumed show (within 1,000 units of a refusal at [S1], the first require).
#[test]
fn v1_leg_count_above_max_legs() {
    let control_world = WorldV2::new(Setup::all_tokens(MAX_LEGS, true, 0));
    let control = control_world.settle_final();
    let w = WorldV2::new(Setup::all_tokens(MAX_LEGS + 1, true, 0));
    assert_eq!(w.terms.leg_count, 11);
    let faulty = w.settle_final();
    flips_across(&control_world, &control, &w, &faulty, 0, "legCount 11");
    let at_v1 = faulty.run(&w, 0);
    let mut s1 = faulty.clone();
    s1.inputs.swap(0, 1);
    let at_s1 = s1.run(&w, 1);
    assert_refused(&at_s1, "reference refusal at [S1]");
    assert!(
        at_v1.used.0 < at_s1.used.0 + 1_000,
        "refused at [V1]: {} units, [S1] refusal {} units",
        at_v1.used.0,
        at_s1.used.0
    );
}

/// A crafted state whose leg list is one record longer than legCount says. Every slice would be
/// in range; [V2] refuses.
#[test]
fn v2_leg_list_longer_than_leg_count() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let crafted = w.edit(|t| t.legs_extra = t.legs[1].record());
    let faulty = crafted.settle_final();
    flips_across(
        &w,
        &control,
        &crafted,
        &faulty,
        0,
        "leg list 3 records, legCount 2",
    );
}

/// A crafted state whose leg list is one byte short.
#[test]
fn v2_leg_list_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let crafted = w.edit(|t| t.legs_cut = 1);
    let faulty = crafted.settle_final();
    flips_across(
        &w,
        &control,
        &crafted,
        &faulty,
        0,
        "leg list one byte short",
    );
}

/// A crafted vault with legIndex == legCount, at input legCount (so [S1] holds). Without [V5]
/// its record reads would run off the leg list and fail as a malformed script, not a verdict.
#[test]
fn v5_leg_index_equal_to_leg_count() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.settle_final();
    let extra = w.terms.vault(2);
    let mut faulty = control.clone();
    faulty
        .inputs
        .insert(2, InV2::settle(&extra, None, 1, KAS_AMOUNT as u64));
    for o in faulty.outputs.iter_mut() {
        if let Some(b) = o.cov.as_mut() {
            if b.authorizing_input >= 2 {
                b.authorizing_input += 1;
            }
        }
    }
    faulty.outputs.last_mut().expect("change").value += KAS_AMOUNT as u64;
    flips(&w, &control, &faulty, 2, "legIndex 2 of 2");
}

/// legIndex -1: no input has that index, so [S1] refuses before [V5].
#[test]
fn v5_negative_leg_index_refused() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.settle_final();
    let extra = w.terms.vault(-1);
    let mut faulty = control.clone();
    let at = insert_before_fee(
        &mut faulty,
        InV2::settle(&extra, None, 1, KAS_AMOUNT as u64),
    );
    faulty.outputs.last_mut().expect("change").value += KAS_AMOUNT as u64;
    flips(&w, &control, &faulty, at, "legIndex -1");
}

// =============================================================================================
// [P1] to [P6]: lots and what the escrow holds
// =============================================================================================

/// lots = 0 on a crafted state with minLot 0 (no terms v2 value has it): every other check would
/// hold with zero deliveries and the whole escrow continuing; [P1] refuses.
#[test]
fn p1_zero_lots() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let w = w.edit(|t| t.min_lot = 0);
    let control = w.settle(1);
    let faulty = w.settle(0);
    flips(&w, &control, &faulty, 0, "lots 0");
}

/// The KAS vault holds twice its amount and the settle names two lots, so the tranche is the
/// whole UTXO and every delivery is doubled; [P2] refuses (v1 [S2], over-funded).
#[test]
fn p2_kas_vault_over_funded() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.inputs[1].value = 2 * KAS_AMOUNT as u64;
    *faulty.inputs[1].lots_mut() = 2;
    faulty.outputs[1].value = 2 * KAS_AMOUNT as u64;
    let doubled = w.delivered(0, 2 * TOKEN_AMOUNT);
    faulty.outputs[0] = Out::token(w.leg(0).token().compile(doubled), w.leg(0).tmpl.cov, 2);
    flips(&w, &control, &faulty, 1, "KAS vault holds 2x");
}

/// An escrow over-funded with the settle naming two lots (v1 [E5], over-funded).
#[test]
fn p2_escrow_over_funded() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let doubled = w.delivered(0, 2 * TOKEN_AMOUNT);
    faulty.inputs[2] = InV2::token(
        w.leg(0)
            .token()
            .compile(w.escrow_state(0, 2 * TOKEN_AMOUNT)),
        w.leg(0).tmpl.cov,
        vec![doubled],
        0,
    );
    faulty.outputs[0] = Out::token(w.leg(0).token().compile(doubled), w.leg(0).tmpl.cov, 2);
    *faulty.inputs[0].lots_mut() = 2;
    flips(&w, &control, &faulty, 0, "escrow holds 2x");
}

/// Under-funded: the KAS vault and the escrow each one unit short (v1 [S2], [E5] under-funded).
#[test]
fn p3_p4_under_funded_refused() {
    let w = WorldV2::new(Setup::v1_kas_cash(false));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.inputs[1].value -= 1;
    flips(&w, &control, &faulty, 1, "KAS vault one sompi short");
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.inputs[3] = InV2::token(
        w.leg(1).token().compile(w.escrow_state(1, KAS_AMOUNT - 1)),
        w.leg(1).tmpl.cov,
        vec![w.delivered(1, KAS_AMOUNT)],
        1,
    );
    flips(&w, &control, &faulty, 1, "escrow one unit short");
}

/// Partial terms, 10 lots: the KAS vault holds 9.6 lots. A one-lot tranche would leave a
/// remainder above min_lot; [P3] refuses because the vault holds no whole number of lots.
#[test]
fn p3_held_not_whole_lots() {
    let w = WorldV2::new(Setup::v1_kas_cash(false).partial(10, 1));
    let control = w.settle(1);
    let unit = w.terms.unit(1);
    let faulty = w.settle_holding(1, &[TOKEN_AMOUNT, 9 * unit + unit * 6 / 10]);
    flips(&w, &control, &faulty, 1, "KAS vault holds 9.6 lots");
}

/// Eleven lots of a ten-lot escrow.
#[test]
fn p4_lots_beyond_the_escrow() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(10);
    let mut faulty = control.clone();
    for i in 0..2 {
        *faulty.inputs[i].lots_mut() = 11;
    }
    for j in 0..2 {
        faulty.outputs[j].value = 11 * w.terms.unit(j) as u64;
    }
    flips(&w, &control, &faulty, 0, "11 lots of 10");
}

/// [P4] alone: a crafted state with minLot -100 (no terms v2 value has it) lets [P5] and [P6]
/// hold for a tranche one lot beyond the escrow, with negative remainder tokens; [P4] refuses.
#[test]
fn p4_tranche_beyond_held_with_crafted_negative_min_lot() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(9);
    let crafted = w.edit(|t| t.min_lot = -100);
    let faulty = crafted.settle(11);
    flips_across(
        &w,
        &control,
        &crafted,
        &faulty,
        0,
        "11 lots of 10, minLot -100",
    );
}

/// min_lot 2: a one-lot tranche.
#[test]
fn p5_tranche_below_min_lot() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true).partial(10, 2));
    let control = w.settle(2);
    let faulty = w.settle(1);
    flips(&w, &control, &faulty, 0, "1 lot, min_lot 2");
}

/// min_lot 3: eight lots of ten would leave two.
#[test]
fn p6_remainder_below_min_lot() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true).partial(10, 3));
    let control = w.settle(7);
    let faulty = w.settle(8);
    flips(&w, &control, &faulty, 0, "8 of 10 lots, min_lot 3");
}

// =============================================================================================
// [E1] to [E6]: this vault's escrow
// =============================================================================================

/// A second deposit to vault 0 under the same covenant rides along (v1 [E1]).
#[test]
fn e1_second_escrow_of_the_covenant_rides_along() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let second = InV2::token(
        w.leg(0).token().compile(w.escrow_state(0, TOKEN_AMOUNT)),
        w.leg(0).tmpl.cov,
        vec![],
        0,
    );
    insert_before_fee(&mut faulty, second);
    flips(&w, &control, &faulty, 0, "second escrow of covenant 0");
}

/// The input at N + 0 is a token of another covenant (same template, owned by vault 0, the leg
/// amount) and the real escrow sits after it (v1 [E2]).
#[test]
fn e2_escrow_at_another_position_decoy_at_its_slot() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let real = faulty.inputs[2].clone();
    faulty.inputs[2] = InV2::token(
        token.compile(w.escrow_state(0, TOKEN_AMOUNT)),
        DECOY_TOKEN_COV,
        vec![Kcc20State::new(stranger_owner(), TOKEN_AMOUNT)],
        0,
    );
    let at = insert_before_fee(&mut faulty, real);
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = at as u16;
    faulty.outputs.push(Out::token(
        token.compile(Kcc20State::new(stranger_owner(), TOKEN_AMOUNT)),
        DECOY_TOKEN_COV,
        2,
    ));
    flips(
        &w,
        &control,
        &faulty,
        0,
        "decoy at N + 0, real escrow later",
    );
}

#[test]
fn e3_escrow_owner_type_pubkey() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::pubkey(w.vaults[0].script_hash()), TOKEN_AMOUNT);
    faulty.inputs[2] = InV2::token(
        w.leg(0).token().compile(state),
        w.leg(0).tmpl.cov,
        vec![w.delivered(0, TOKEN_AMOUNT)],
        0,
    );
    flips(&w, &control, &faulty, 0, "escrow owner type PUBKEY");
}

#[test]
fn e4_escrow_owned_by_another_vault() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::script_hash(w.vaults[1].script_hash()), TOKEN_AMOUNT);
    faulty.inputs[2] = InV2::token(
        w.leg(0).token().compile(state),
        w.leg(0).tmpl.cov,
        vec![w.delivered(0, TOKEN_AMOUNT)],
        1,
    );
    flips(&w, &control, &faulty, 0, "escrow owned by vault 1");
}

/// A minter escrow would let the settler hand the minting right to any output it adds (v1 [E6]).
#[test]
fn e6_minter_escrow() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let mut state = w.escrow_state(0, TOKEN_AMOUNT);
    state.is_minter = true;
    faulty.inputs[2] = InV2::token(
        w.leg(0).token().compile(state),
        w.leg(0).tmpl.cov,
        vec![w.delivered(0, TOKEN_AMOUNT)],
        0,
    );
    flips(&w, &control, &faulty, 0, "minter escrow");
}

// =============================================================================================
// [S3] lock time
// =============================================================================================

#[test]
fn s3_settle_one_daa_before_earliest() {
    let w = WorldV2::new(Setup::ring(3, false));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.lock_time = EARLIEST_DAA - 1;
    flips_locktime(&w, &control, &faulty, 0, "lock time earliest - 1");
}

// =============================================================================================
// [V6], [V7]: kind and destination bytes of every leg (crafted states)
// =============================================================================================

/// Leg 2's kind byte is 2. Without [V6] the record would be taken as KCC-20 and settle.
#[test]
fn v6_leg_kind_byte_2() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.settle_final();
    let crafted = w.edit(|t| t.legs[2].kind = 2);
    let faulty = crafted.settle_final();
    flips_across(&w, &control, &crafted, &faulty, 0, "leg 2 kind 2");
}

/// The KAS leg's delivery type is 2, with its delivery paid to P2SH(id). Without [V7] type 2
/// would take the P2SH branch and settle.
#[test]
fn v7_kas_delivery_type_2() {
    let base = WorldV2::new(Setup::v1_kas_cash(false));
    let w = base.edit(|t| t.legs[1].delivery.id_type = DEST_P2SH);
    let control = w.settle_final();
    let crafted = w.edit(|t| t.legs[1].delivery.id_type = 2);
    let faulty = crafted.settle_final();
    assert_eq!(control.outputs[1].spk, faulty.outputs[1].spk);
    flips_across(&w, &control, &crafted, &faulty, 0, "KAS delivery type 2");
}

// =============================================================================================
// [S10]: every vault input belongs to this trade
// =============================================================================================

/// The worked case of spec/V2.md 4.4: trade A (Alice delivers X to Bob, Bob delivers Y to
/// Alice) and trade B with the same delivery table but Bob's leg deposited by someone else.
/// A settle of A's leg 0 with B's leg 1 satisfies every delivery; [S10] refuses it at both.
#[test]
fn s10_crossed_settle_of_two_trades_with_identical_deliveries() {
    for authority in [true, false] {
        let a = WorldV2::new(Setup::v1_kcc20_cash(authority));
        let stranger = a.xonly(Who::Stranger);
        let b = a.edit(|t| {
            t.legs[1].depositor = stranger;
            t.legs[1].refund = Owner::pubkey(stranger);
        });
        assert_eq!(a.leg(0).delivery, b.leg(0).delivery);
        assert_eq!(a.leg(1).delivery, b.leg(1).delivery);
        let control = a.settle_final();
        let mut crossed = control.clone();
        let b_settle = b.settle_final();
        crossed.inputs[1] = b_settle.inputs[1].clone();
        crossed.inputs[3] = b_settle.inputs[3].clone();
        crossed.outputs[3] = b_settle.outputs[3].clone();
        flips(&a, &control, &crossed, 0, "A's vault 0 beside B's vault 1");
        flips(&a, &control, &crossed, 1, "B's vault 1 beside A's vault 0");
    }
}

/// Two trades that differ only in their nonce: identical parties and deliveries.
#[test]
fn s10_crossed_settle_of_trades_differing_only_in_nonce() {
    let a = WorldV2::new(Setup::ring(3, false));
    let b = a.edit(|t| t.nonce[0] ^= 1);
    let control = a.settle_final();
    let mut crossed = control.clone();
    let b_settle = b.settle_final();
    crossed.inputs[2] = b_settle.inputs[2].clone();
    crossed.inputs[5] = b_settle.inputs[5].clone();
    crossed.assert_every_vault_refused(&a, "A's vaults 0 and 1 with B's vault 2");
    flips(&a, &control, &crossed, 0, "A's vault 0");
}

// =============================================================================================
// [S4], [S5]: KAS deliveries
// =============================================================================================

#[test]
fn s4_kas_delivery_to_stranger() {
    let w = WorldV2::new(Setup::v1_kas_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[1].spk = stranger_spk();
    flips(
        &w,
        &control,
        &faulty,
        0,
        "KAS delivery to a stranger, vault 0",
    );
    flips(
        &w,
        &control,
        &faulty,
        1,
        "KAS delivery to a stranger, vault 1",
    );
}

#[test]
fn s5_kas_delivery_short() {
    let w = WorldV2::new(Setup::v1_kas_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    flips(&w, &control, &faulty, 0, "KAS delivery short, vault 0");
    flips(&w, &control, &faulty, 1, "KAS delivery short, vault 1");
}

// =============================================================================================
// [D1], [D2] and the delivery builtin: KCC-20 deliveries
// =============================================================================================

/// Output 0 is a decoy token with the leg's template and the agreed state under another
/// covenant; the real token goes to a stranger at the end (v1 [D1]). Both vaults refuse.
#[test]
fn d1_delivery_under_decoy_covenant() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let to_stranger = Kcc20State::new(stranger_owner(), TOKEN_AMOUNT);
    faulty.inputs[2].new_states_mut()[0] = to_stranger;
    let fee = faulty.fee_idx();
    let at = insert_before_fee(
        &mut faulty,
        InV2::token(
            token.compile(Kcc20State::new(standin_owner(), TOKEN_AMOUNT)),
            DECOY_TOKEN_COV,
            vec![w.delivered(0, TOKEN_AMOUNT)],
            (fee + 1) as u8,
        ),
    );
    faulty.outputs[0] = Out::token(
        token.compile(w.delivered(0, TOKEN_AMOUNT)),
        DECOY_TOKEN_COV,
        at as u16,
    );
    faulty
        .outputs
        .push(Out::token(token.compile(to_stranger), w.leg(0).tmpl.cov, 2));
    assert_accepted(&faulty.run(&w, 2), "the real transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    flips(&w, &control, &faulty, 0, "decoy delivery, vault 0");
    flips(&w, &control, &faulty, 1, "decoy delivery, vault 1");
}

#[test]
fn d2_delivery_carrier_kas_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    flips(
        &w,
        &control,
        &faulty,
        0,
        "delivery 0 carrier short, vault 0",
    );
    flips(
        &w,
        &control,
        &faulty,
        1,
        "delivery 0 carrier short, vault 1",
    );
}

#[test]
fn delivery_builtin_wrong_owner_or_amount() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false));
    let control = w.settle_final();
    for state in [
        Kcc20State::new(stranger_owner(), KAS_AMOUNT),
        w.delivered(1, KAS_AMOUNT - 1),
        Kcc20State {
            is_minter: true,
            ..w.delivered(1, KAS_AMOUNT)
        },
    ] {
        let mut faulty = control.clone();
        faulty.inputs[3].new_states_mut()[0] = state;
        faulty.outputs[1] = Out::token(w.leg(1).token().compile(state), w.leg(1).tmpl.cov, 3);
        faulty.assert_every_vault_refused(&w, &format!("delivery 1 as {state:?}"));
        flips(&w, &control, &faulty, 0, "delivery 1 builtin");
    }
}

// =============================================================================================
// Final: [C1], [S8], [S9]
// =============================================================================================

/// A covenant vault's final settle that leaves an output of its covenant.
#[test]
fn c1_final_settle_leaves_a_continuation() {
    let w = WorldV2::new(Setup::v1_kas_cash(false).partial(10, 1));
    let control = w.settle(10);
    let mut faulty = control.clone();
    faulty.outputs.push(Out {
        value: 1,
        spk: plain_spk(),
        cov: Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: vault_cov(0),
        }),
    });
    flips(&w, &control, &faulty, 0, "final settle with a continuation");
}

#[test]
fn s8_authorizer_return_to_stranger() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[4].spk = stranger_spk();
    flips(&w, &control, &faulty, 1, "leg 1 authorizer to a stranger");
}

#[test]
fn s8_authorizer_return_omitted() {
    let w = WorldV2::new(Setup::v1_kas_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[2].spk = plain_spk();
    flips(&w, &control, &faulty, 0, "leg 0 authorizer to change");
}

#[test]
fn s9_authorizer_return_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.outputs[3].value -= 1;
    flips(&w, &control, &faulty, 1, "leg 1 authorizer short");
}

// =============================================================================================
// Tranche: [C2] to [C9] and the remainder builtin (first tests; I17 adds its own)
// =============================================================================================

/// A tranche from a plain vault (no covenant ID) is refused.
#[test]
fn c2_tranche_from_a_plain_vault_refused() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut plain = WorldV2::new(kas_pair().partial(10, 1));
    plain.vault_covs = vec![None, None];
    let faulty = plain.settle(3);
    flips_across(
        &w,
        &control,
        &plain,
        &faulty,
        0,
        "tranche from plain vaults",
    );
}

/// [C2] alone: a vault UTXO carrying the all-zero covenant ID, which no genesis can produce
/// (engine-only). Its continuation would count under that ID; [C2] refuses.
#[test]
fn c2_tranche_from_a_zero_covenant_vault() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut zero = w.edit(|_| ());
    zero.vault_covs[0] = Some(Hash::from_bytes([0; 32]));
    let faulty = zero.settle(3);
    flips_across(&w, &control, &zero, &faulty, 0, "zero covenant ID");
}

#[test]
fn c3_two_continuations() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    faulty.outputs.push(Out {
        value: 1,
        spk: w.vaults[0].p2sh(),
        cov: Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: vault_cov(0),
        }),
    });
    flips(&w, &control, &faulty, 0, "two continuations");
}

/// The bound continuation sits at the end; the slot N + i holds an unbound output with the
/// vault's script and the remainder, so only the position check refuses.
#[test]
fn c4_continuation_at_another_position() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    let slot = faulty.outputs[2].clone();
    faulty.outputs[2].cov = None;
    faulty.outputs.push(slot);
    flips(&w, &control, &faulty, 0, "continuation at the end");
}

#[test]
fn c5_continuation_with_another_script() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    faulty.outputs[2].spk = p2sh_of(&[0x51, 0x51]);
    flips(&w, &control, &faulty, 0, "continuation to another script");
}

#[test]
fn c6_kas_remainder_short() {
    let w = WorldV2::new(kas_pair().partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    faulty.outputs[2].value -= 1;
    flips(&w, &control, &faulty, 0, "KAS remainder one sompi short");
}

#[test]
fn c7_authorizer_continuation_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    faulty.outputs[2].value -= 1;
    flips(&w, &control, &faulty, 0, "authorizer continuation short");
}

/// The output at 2N + 0 is a decoy token with the remainder state under another covenant; the
/// real remainder goes to a stranger at the end.
#[test]
fn c8_remainder_under_decoy_covenant() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    let token = w.leg(0).token();
    let remainder = w.escrow_state(0, 7 * w.terms.unit(0));
    let to_stranger = Kcc20State::new(stranger_owner(), remainder.amount);
    faulty.inputs[2].new_states_mut()[1] = to_stranger;
    let fee = faulty.fee_idx();
    let at = insert_before_fee(
        &mut faulty,
        InV2::token(
            token.compile(Kcc20State::new(standin_owner(), remainder.amount)),
            DECOY_TOKEN_COV,
            vec![remainder],
            (fee + 1) as u8,
        ),
    );
    faulty.outputs[4] = Out::token(token.compile(remainder), DECOY_TOKEN_COV, at as u16);
    faulty
        .outputs
        .push(Out::token(token.compile(to_stranger), w.leg(0).tmpl.cov, 2));
    assert_accepted(&faulty.run(&w, 2), "the real transfer is valid");
    flips(&w, &control, &faulty, 0, "remainder under a decoy covenant");
}

#[test]
fn c9_remainder_carrier_short() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(3);
    let mut faulty = control.clone();
    faulty.outputs[4].value -= 1;
    flips(&w, &control, &faulty, 0, "remainder carrier short");
}

#[test]
fn remainder_builtin_wrong_amount_or_owner() {
    let w = WorldV2::new(Setup::v1_kcc20_cash(false).partial(10, 1));
    let control = w.settle(3);
    let rem = 7 * w.terms.unit(0);
    for state in [
        w.escrow_state(0, rem - 1),
        Kcc20State::new(stranger_owner(), rem),
        w.escrow_state(1, rem),
    ] {
        let mut faulty = control.clone();
        faulty.inputs[2].new_states_mut()[1] = state;
        faulty.outputs[4] = Out::token(w.leg(0).token().compile(state), w.leg(0).tmpl.cov, 2);
        flips(&w, &control, &faulty, 0, &format!("remainder {state:?}"));
    }
}

// =============================================================================================
// [S6] authority
// =============================================================================================

#[test]
fn s6_authority_signature_from_stranger() {
    let w = WorldV2::new(Setup::ring(3, true));
    let control = w.settle_final();
    let mut faulty = control.clone();
    faulty.inputs[2] = InV2::settle(&w.vaults[2], Some(Who::Stranger), 1, AUTH);
    flips(&w, &control, &faulty, 2, "stranger signs for the authority");
}
