// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault v2 partial settlement in the real engine (I17, spec/V2.md 4.3, 4.4, 4.6, 11.2).
//!
//! The tranche requires ([P5], [P6], [C1] to [C9] and the remainder builtin) each have their
//! failing test in v2_settle.rs, which v2_mutation.py maps. This file adds the sequences and the
//! cross-cutting cases of the I17 test plan: a full settle on partial terms, two tranches then a
//! final settle (each transaction spends the previous one's continuations and remainders), the
//! last tranche under min_lot, remainder leaks on every leg kind, any terms field changed in the
//! continuation, strays, a mixed final and tranche, one covenant ID shared by two vaults, and
//! refunds of a partly filled vault by each role.
//!
//! No contract change is needed for I17: the tranche branch was committed with template v2 in
//! I16 because both belong to one template (spec/V2.md 4.1), so TEMPLATE_HASH_V2 is unchanged.

mod harness;
mod v2_harness;
use harness::*;
use kaspa_consensus_core::Hash;
use v2_harness::*;

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

/// The partial setups the sequences run on: KAS legs only, KAS cash against a token, a token
/// against a token with an authority, and two tokens with a KAS leg.
fn partial_setups(min_lot: i64) -> Vec<(&'static str, Setup)> {
    vec![
        ("two KAS legs", kas_pair().partial(10, min_lot)),
        (
            "token against KAS, authority",
            Setup::v1_kas_cash(true).partial(10, min_lot),
        ),
        (
            "token against token",
            Setup::v1_kcc20_cash(false).partial(10, min_lot),
        ),
        (
            "two tokens and a KAS leg",
            Setup::three_with_kas(true).partial(10, min_lot),
        ),
    ]
}

fn full_holdings(w: &WorldV2) -> Vec<i64> {
    (0..w.n()).map(|j| w.leg(j).amount()).collect()
}

/// Every output of the transaction that carries a covenant binding to one of the vault IDs.
fn vault_bound_outputs(w: &WorldV2, tx: &TxV2) -> usize {
    tx.outputs
        .iter()
        .filter(|o| {
            o.cov
                .as_ref()
                .is_some_and(|b| w.vault_covs.contains(&Some(b.covenant_id)))
        })
        .count()
}

/// `next` spends what `prev` created: vault i's continuation at N + i and token j's remainder
/// at 2N + j, with the same script, value and covenant.
fn assert_spends_previous(w: &WorldV2, prev: &TxV2, next: &TxV2, label: &str) {
    let n = w.n();
    for i in 0..n {
        let out = &prev.outputs[n + i];
        let inp = &next.inputs[i];
        assert_eq!(inp.spk, out.spk, "{label}: vault {i} script");
        assert_eq!(inp.value, out.value, "{label}: vault {i} value");
        assert_eq!(
            inp.cov,
            out.cov.as_ref().map(|b| b.covenant_id),
            "{label}: vault {i} covenant lineage"
        );
    }
    for j in 0..n {
        if w.leg(j).is_token() {
            let out = &prev.outputs[2 * n + j];
            let inp = &next.inputs[n + j];
            assert_eq!(inp.spk, out.spk, "{label}: remainder token {j} script");
            assert_eq!(inp.value, out.value, "{label}: remainder token {j} value");
            assert_eq!(
                inp.cov,
                out.cov.as_ref().map(|b| b.covenant_id),
                "{label}: remainder token {j} covenant"
            );
        }
    }
}

/// Runs the tranches in order, each spending the previous one's outputs, and checks the lots
/// add up to every lot.
fn run_sequence(w: &WorldV2, schedule: &[i64], label: &str) {
    assert_eq!(schedule.iter().sum::<i64>(), w.terms.lot_count);
    let mut held = full_holdings(w);
    let mut prev: Option<TxV2> = None;
    for (k, &lots) in schedule.iter().enumerate() {
        let last = k == schedule.len() - 1;
        let tx = w.settle_holding(lots, &held);
        let tag = format!(
            "{label}: step {} of {} ({lots} lots)",
            k + 1,
            schedule.len()
        );
        if let Some(p) = &prev {
            assert_spends_previous(w, p, &tx, &tag);
        }
        tx.assert_all_accepted(w, &tag);
        if last {
            assert_eq!(vault_bound_outputs(w, &tx), 0, "{tag}: no continuation");
        } else {
            assert_eq!(vault_bound_outputs(w, &tx), w.n(), "{tag}: continuations");
        }
        for (j, h) in held.iter_mut().enumerate() {
            *h -= lots * w.terms.unit(j);
        }
        prev = Some(tx);
    }
    assert!(held.iter().all(|h| *h == 0), "{label}: nothing left");
}

// =============================================================================================
// Passing
// =============================================================================================

/// Every lot at once on partial terms is a final settle: no continuation, authorizers home.
#[test]
fn full_settle_on_partial_terms() {
    for (name, setup) in partial_setups(2) {
        let w = WorldV2::new(setup);
        let tx = w.settle(w.terms.lot_count);
        tx.assert_all_accepted(&w, name);
        assert_eq!(vault_bound_outputs(&w, &tx), 0, "{name}: no continuation");
    }
}

#[test]
fn two_tranches_then_final() {
    for (name, setup) in partial_setups(2) {
        let w = WorldV2::new(setup);
        run_sequence(&w, &[4, 3, 3], name);
    }
}

/// One tranche per lot at min_lot 1, and a tranche that leaves exactly min_lot lots.
#[test]
fn tranche_sequences_at_the_edges() {
    let w = WorldV2::new(Setup::v1_kas_cash(true).partial(10, 1));
    run_sequence(&w, &[1; 10], "one lot at a time");
    let w = WorldV2::new(Setup::v1_kcc20_cash(true).partial(10, 3));
    run_sequence(&w, &[7, 3], "remainder of exactly min_lot");
    run_sequence(&w, &[3, 4, 3], "min_lot, then more, then min_lot");
}

// =============================================================================================
// Under-lot: [P5], [P6]
// =============================================================================================

/// min_lot 3. A tranche of two lots is refused at the first step; the last tranche too: an
/// escrow of two lots (short-funded or a remainder from a looser sequence) cannot settle.
#[test]
fn under_lot_refused_first_and_last_tranche() {
    for (name, setup) in partial_setups(3) {
        let w = WorldV2::new(setup);
        let n = w.n();
        let unit: Vec<i64> = (0..n).map(|j| w.terms.unit(j)).collect();
        // First tranche under min_lot.
        let control = w.settle(3);
        let faulty = w.settle(2);
        for i in 0..n {
            flips(
                &w,
                &control,
                &faulty,
                i,
                &format!("{name}: first tranche, vault {i}"),
            );
        }
        // Last tranche under min_lot: the escrows hold two lots and settle both (a final).
        let held: Vec<i64> = unit.iter().map(|u| 2 * u).collect();
        let control = w.settle_holding(3, &full_holdings(&w));
        let faulty = w.settle_holding(2, &held);
        for i in 0..n {
            flips(
                &w,
                &control,
                &faulty,
                i,
                &format!("{name}: last tranche, vault {i}"),
            );
        }
        // A last tranche that is min_lot is accepted.
        let held: Vec<i64> = unit.iter().map(|u| 3 * u).collect();
        w.settle_holding(3, &held)
            .assert_all_accepted(&w, &format!("{name}: last tranche of min_lot"));
    }
}

/// min_lot 3 with 10 lots held: 8 lots would leave 2, below min_lot; 7 leaves 3.
#[test]
fn tranche_leaving_less_than_min_lot_refused() {
    for (name, setup) in partial_setups(3) {
        let w = WorldV2::new(setup);
        let control = w.settle(7);
        let faulty = w.settle(8);
        for i in 0..w.n() {
            flips(
                &w,
                &control,
                &faulty,
                i,
                &format!("{name}: remainder 2, vault {i}"),
            );
        }
        // And from a partly filled vault: 6 lots left, 4 would leave 2.
        let held: Vec<i64> = (0..w.n()).map(|j| 6 * w.terms.unit(j)).collect();
        let control = w.settle_holding(3, &held);
        let faulty = w.settle_holding(4, &held);
        for i in 0..w.n() {
            flips(
                &w,
                &control,
                &faulty,
                i,
                &format!("{name}: from 6 lots, vault {i}"),
            );
        }
    }
}

// =============================================================================================
// Remainder leak: every vault, every kind
// =============================================================================================

/// For each vault of each setup: the continuation to another script, short in KAS, the
/// remainder token short, to a stranger, or missing, and a second continuation, are all refused
/// by that vault.
#[test]
fn remainder_leak_refused_on_every_leg() {
    for (name, setup) in partial_setups(1) {
        let w = WorldV2::new(setup);
        let n = w.n();
        let control = w.settle(3);
        control.assert_all_accepted(&w, &format!("{name} (control)"));
        let stranger_spk = harness::p2pk(STRANGER_OWNER.id);
        for i in 0..n {
            let label = |s: &str| format!("{name}: vault {i}: {s}");
            let mut f = control.clone();
            f.outputs[n + i].spk = stranger_spk.clone();
            assert_refused(&f.run(&w, i), &label("continuation to a stranger"));

            let mut f = control.clone();
            f.outputs[n + i].value -= 1;
            assert_refused(&f.run(&w, i), &label("continuation one sompi short"));

            let mut f = control.clone();
            f.outputs[n + i].cov = None;
            assert_refused(
                &f.run(&w, i),
                &label("continuation unbound from the covenant"),
            );

            if w.leg(i).is_token() {
                let rem = w.escrow_state(i, 7 * w.terms.unit(i));
                let tok = w.leg(i).token();
                let cov = w.leg(i).tmpl.cov;
                let mut states: Vec<(Kcc20State, &str)> = vec![
                    (
                        w.escrow_state(i, rem.amount - 1),
                        "remainder one unit short",
                    ),
                    (
                        Kcc20State::new(STRANGER_OWNER, rem.amount),
                        "remainder to a stranger",
                    ),
                    (w.escrow_state(i, rem.amount + 1), "remainder one unit over"),
                ];
                for (state, what) in states.drain(..) {
                    let mut f = control.clone();
                    f.inputs[n + i].new_states_mut()[1] = state;
                    f.outputs[2 * n + i] = Out::token(tok.compile(state), cov, (n + i) as u16);
                    assert_refused(&f.run(&w, i), &label(what));
                }
                let mut f = control.clone();
                f.outputs[2 * n + i].value -= 1;
                assert_refused(&f.run(&w, i), &label("remainder carrier short"));
            }
        }
    }
}

// =============================================================================================
// Any terms field changed in the continuation: [C5]
// =============================================================================================

type Edit = (&'static str, fn(&mut TermsV2));

fn top_level_edits() -> Vec<Edit> {
    vec![
        ("version", |t| t.version ^= 1),
        ("network", |t| t.network ^= 1),
        ("nonce", |t| t.nonce[0] ^= 1),
        ("hasAuthority", |t| t.has_authority = !t.has_authority),
        ("authorityKey", |t| t.authority_key[0] ^= 1),
        ("legCount", |t| t.leg_count += 1),
        ("hasEarliest", |t| t.has_earliest = !t.has_earliest),
        ("earliestDaa", |t| t.earliest_daa += 1),
        ("expiryDaa", |t| t.expiry_daa += 1),
        ("fundingMode", |t| t.funding_mode ^= 1),
        ("tradeRef", |t| t.trade_ref[0] ^= 1),
        ("lotCount", |t| t.lot_count += 1),
        ("minLot", |t| t.min_lot += 1),
    ]
}

type LegEdit = (&'static str, fn(&mut LegV2));

fn leg_edits() -> Vec<LegEdit> {
    vec![
        ("depositor", |l| l.depositor[0] ^= 1),
        ("kind", |l| l.kind ^= 1),
        ("covenantId", |l| {
            l.tmpl.cov = Hash::from_bytes([0x77; 32]);
        }),
        ("templateHash", |l| l.tmpl.hash[0] ^= 1),
        ("prefixLen", |l| l.tmpl.prefix_len += 1),
        ("suffixLen", |l| l.tmpl.suffix_len += 1),
        ("amount", |l| {
            let a = l.amount();
            l.set_amount(a + 10);
        }),
        ("deliveryType", |l| l.delivery.id_type ^= 1),
        ("deliveryId", |l| l.delivery.id[0] ^= 1),
        ("refundType", |l| l.refund.id_type ^= 1),
        ("refundId", |l| l.refund.id[0] ^= 1),
    ]
}

/// A continuation locked by a script whose terms differ in exactly one field from the vault's
/// own is refused by that vault. The control continues unchanged and is accepted.
#[test]
fn any_terms_field_change_in_the_continuation_is_refused() {
    for (name, setup) in [
        (
            "token against KAS, authority",
            Setup::v1_kas_cash(true).partial(10, 2),
        ),
        (
            "token against token",
            Setup::v1_kcc20_cash(false).partial(10, 2),
        ),
    ] {
        let w = WorldV2::new(setup);
        let n = w.n();
        let control = w.settle(3);
        control.assert_all_accepted(&w, &format!("{name} (control)"));
        let refuse = |what: String, w2: &WorldV2| {
            // Vault i checks only its own continuation, so vault i sees the change in vault i's
            // script; check each vault with only its own slot changed.
            for i in 0..n {
                let mut one = control.clone();
                one.outputs[n + i].spk = w2.vaults[i].p2sh();
                assert_ne!(one.outputs[n + i].spk, control.outputs[n + i].spk, "{what}");
                assert_refused(&one.run(&w, i), &format!("{name}: {what}, vault {i}"));
            }
        };
        for (field, edit) in top_level_edits() {
            let w2 = w.edit(edit);
            refuse(field.to_string(), &w2);
        }
        for j in 0..n {
            for (field, edit) in leg_edits() {
                let w2 = w.edit(|t| edit(&mut t.legs[j]));
                refuse(format!("leg {j} {field}"), &w2);
            }
        }
        // The leg index: the continuation is another leg's vault.
        for i in 0..n {
            let mut f = control.clone();
            f.outputs[n + i].spk = w.vaults[(i + 1) % n].p2sh();
            assert_refused(&f.run(&w, i), &format!("{name}: legIndex, vault {i}"));
        }
    }
}

// =============================================================================================
// Strays (spec/V2.md 4.4, 4.6)
// =============================================================================================

/// min_lot 5, a real 10-lot escrow and a 1-lot stray in every leg: the settle that offers the
/// strays fails at [P5] and the vault UTXOs stay. With 5-lot strays it is accepted (pinned),
/// the real escrows are stranded, and with a re-funded authorizer each is refunded and,
/// separately, settled.
#[test]
fn strays_below_and_at_min_lot() {
    for (name, setup) in partial_setups(5) {
        let w = WorldV2::new(setup);
        let n = w.n();
        let stray = |lots: i64| -> Vec<i64> { (0..n).map(|j| lots * w.terms.unit(j)).collect() };
        let control = w.settle_holding(5, &stray(5));
        let one_lot = w.settle_holding(1, &stray(1));
        for i in 0..n {
            flips(
                &w,
                &control,
                &one_lot,
                i,
                &format!("{name}: 1-lot stray, vault {i}"),
            );
        }
        // 5-lot strays settle: pinned.
        control.assert_all_accepted(&w, &format!("{name}: 5-lot strays settle (pinned)"));
        // The stranded real escrow of each token leg: refunded by a non-depositor and settled.
        let full = full_holdings(&w);
        w.settle_holding(w.terms.lot_count, &full)
            .assert_all_accepted(&w, &format!("{name}: stranded escrows settle"));
        #[allow(clippy::needless_range_loop)]
        for j in 0..n {
            let signer = w.depositor(j);
            let leg_no = j as i64;
            w.refund_holding(j, signer, leg_no, Some(full[j]))
                .assert_all_accepted(&w, &format!("{name}: stranded leg {j} refunded"));
        }
    }
}

// =============================================================================================
// Mixed final and tranche in one transaction (spec/V2.md 4.3)
// =============================================================================================

/// Vault 0 holds three lots and settles them (final), vault 1 holds ten and settles three
/// (tranche). Each vault checks only its own indexes: accepted, pinned. Output 2N + 0 is a
/// filler no vault checks.
#[test]
fn mixed_final_and_tranche_is_accepted() {
    for (name, setup) in [
        ("two KAS legs", kas_pair().partial(10, 1)),
        (
            "token against token",
            Setup::v1_kcc20_cash(false).partial(10, 1),
        ),
    ] {
        let w = WorldV2::new(setup);
        let n = w.n();
        let mut held = full_holdings(&w);
        held[0] = 3 * w.terms.unit(0);
        let mut tx = w.settle_holding(3, &held);
        if w.leg(0).is_token() {
            // Vault 0 is final: its authorizer goes home at N + 0; 2N + 0 is a filler.
            tx.outputs[n] = Out::kas(AUTH, p2pk(w.leg(0).depositor));
            tx.outputs[2 * n] = Out::kas(AUTH, plain_spk());
        } else {
            // A KAS leg's final settle checks nothing at N + 0: a filler, not bound to vault 0.
            tx.outputs[n] = Out::kas(1_000, plain_spk());
        }
        tx.assert_all_accepted(&w, name);
        // Control for the filler: leaving vault 0's covenant on the slot is refused at [C1].
        let mut bound = tx.clone();
        bound.outputs[n].cov = w.settle(3).outputs[n].cov;
        assert_refused(
            &bound.run(&w, 0),
            &format!("{name}: final leaves a continuation"),
        );
    }
}

// =============================================================================================
// One covenant ID shared by two vaults (spec/V2.md 4.3)
// =============================================================================================

#[test]
fn shared_covenant_id_blocks_tranches_not_final_or_refund() {
    let mut w = WorldV2::new(kas_pair().partial(10, 1));
    let shared = vault_cov(0);
    w.vault_covs = vec![Some(shared), Some(shared)];
    // A tranche sees two continuations of one covenant: both vaults refuse at [C3].
    w.settle(3)
        .assert_every_vault_refused(&w, "shared covenant, tranche");
    // A final settle and a refund pass.
    w.settle(10)
        .assert_all_accepted(&w, "shared covenant, final");
    // The final leaves no output of the covenant, so [C1] holds for both vaults.
    assert_eq!(
        w.settle(10)
            .outputs
            .iter()
            .filter(|o| o.cov.is_some())
            .count(),
        0
    );
    w.refund(0, Who::Party(0), 0)
        .assert_all_accepted(&w, "shared covenant, refund of vault 0");
    w.refund(1, Who::Party(1), 1)
        .assert_all_accepted(&w, "shared covenant, refund of vault 1");
}

// =============================================================================================
// Refunds of a partly filled vault, by each role
// =============================================================================================

/// After a tranche of three lots each vault holds seven lots. The depositor, the counterparty
/// (named by its own leg) and the authority each refund it whole to the refund destination.
#[test]
fn refund_of_a_partly_filled_vault_by_each_role() {
    for (name, setup) in [
        (
            "token against KAS, authority",
            Setup::v1_kas_cash(true).partial(10, 2),
        ),
        (
            "token against token, authority",
            Setup::v1_kcc20_cash(true).partial(10, 2),
        ),
        (
            "two tokens and a KAS leg, authority",
            Setup::three_with_kas(true).partial(10, 2),
        ),
    ] {
        let w = WorldV2::new(setup);
        let n = w.n();
        for j in 0..n {
            let held = 7 * w.terms.unit(j);
            let dep = w.depositor(j);
            w.refund_holding(j, dep, j as i64, Some(held))
                .assert_all_accepted(&w, &format!("{name}: leg {j}, depositor"));
            // Another party of the trade, named by the leg it deposits.
            let other = (0..n).find(|k| w.setup.legs[*k].party != w.setup.legs[j].party);
            if let Some(k) = other {
                w.refund_holding(j, w.depositor(k), k as i64, Some(held))
                    .assert_all_accepted(&w, &format!("{name}: leg {j}, party of leg {k}"));
            }
            w.refund_holding(j, Who::Authority, n as i64, Some(held))
                .assert_all_accepted(&w, &format!("{name}: leg {j}, authority"));
        }
    }
}
