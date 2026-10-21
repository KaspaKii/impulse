// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The six Solana DvP instructions (IX-0 to IX-5) against Impulse. Tag format: parity.rs.
//!
//! Impulse has no instructions and no trade account. A trade is its terms; each leg's vault is
//! a P2SH script instantiated from them, and the vault has two entries, settle and refund. The
//! engine judges a spend from the transaction alone, so nothing a settle or refund does changes
//! what a later spend of the same vault address may do.

use crate::common::*;
use crate::harness::*;
use impulse_core::address::vault_address;
use impulse_core::template::{decode, LegIndex, Vault};
use impulse_core::terms::ValidatedTerms;

/// parity: IX-0 equivalent
/// Create is local and moves nothing: each party derives the same vault addresses from the canonical terms bytes alone, and each script decodes back to the terms.
#[test]
fn ix0_create_is_derived_locally_by_each_party() {
    // The seller makes the terms; the buyer is handed only the canonical bytes.
    let seller = assert_created(vector("01-"), "the seller's terms");
    let buyer = ValidatedTerms::decode(seller.canonical()).expect("the buyer decodes the bytes");
    assert_eq!(buyer, seller);
    assert_eq!(buyer.terms_hash(), seller.terms_hash());
    let ctx = creation_context(seller.terms());
    let mut addresses = Vec::new();
    for leg in LegIndex::ALL {
        let mine = Vault::instantiate_for_creation(&seller, leg, &ctx).expect("seller derives");
        let theirs = Vault::instantiate_for_creation(&buyer, leg, &ctx).expect("buyer derives");
        assert_eq!(
            vault_address(&mine),
            vault_address(&theirs),
            "{leg:?} address"
        );
        let decoded = decode(mine.vault().redeem_script()).expect("the vault decodes");
        assert_eq!(
            decoded,
            (seller.clone(), leg),
            "{leg:?} script commits to the terms"
        );
        addresses.push(vault_address(&mine));
    }
    assert_ne!(addresses[0], addresses[1], "each leg has its own vault");
}

/// parity: IX-1 equivalent
/// Reclaim is the depositor's own refund of its leg, whole and with no lock time under revocable funding; the vault address does not change, so the leg can be funded again and the trade still settles.
#[test]
fn ix1_reclaim_is_the_depositors_refund() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    for leg in [ASSET_LEG, CASH_LEG] {
        let reclaim = w.refund(leg, depositor(leg));
        assert_eq!(reclaim.lock_time, 0, "revocable: at any time");
        assert_eq!(reclaim.outputs[0].value, reclaim.inputs[0].value, "whole");
        reclaim.assert_all_accepted(&w, &format!("leg {leg}: the depositor reclaims"));
    }
    // Funded again at the same two addresses, the trade settles.
    let settle = w.settle();
    assert_eq!(settle.inputs[0].spk, w.asset_vault.p2sh());
    assert_eq!(settle.inputs[1].spk, w.cash_vault().p2sh());
    settle.assert_all_accepted(&w, "settle after the legs are funded again");
}

/// parity: IX-2 equivalent
/// Settle moves both legs in one transaction, and each vault checks both deliveries, so neither leg moves unless the other reaches its agreed destination in the same transaction.
#[test]
fn ix2_settle_moves_both_legs_in_one_transaction() {
    for cash in [CASH_KAS, CASH_KCC20] {
        let w = World::new(Mode::new(true, cash, REVOCABLE));
        let control = w.settle();

        // The cash goes elsewhere: the asset vault (input 0) refuses to release the asset.
        let mut cash_elsewhere = control.clone();
        if cash == CASH_KAS {
            cash_elsewhere.outputs[1].spk = stranger_spk();
        } else {
            let idx = World::CASH_ESCROW_IDX;
            *leader_states(&mut cash_elsewhere, idx) = vec![stranger(AMOUNT_B)];
            cash_elsewhere.outputs[1] =
                Out::token(CASH_TOKEN.compile(stranger(AMOUNT_B)), CASH_COV, idx as u16);
        }
        assert_flips(
            &w,
            &control,
            &cash_elsewhere,
            0,
            &format!("cash kind {cash}: cash not paid, asset vault"),
        );

        // The asset goes elsewhere: the cash vault (input 1) refuses to release the cash.
        let mut asset_elsewhere = control.clone();
        deliver_asset(&w, &mut asset_elsewhere, &[stranger(AMOUNT_A)]);
        assert_flips(
            &w,
            &control,
            &asset_elsewhere,
            1,
            &format!("cash kind {cash}: asset not delivered, cash vault"),
        );
    }
}

/// parity: IX-3 divergent
/// Cancel is the authority's refund of each leg, one vault UTXO per transaction, at once in either funding mode and after expiry, each leg home to its depositor; unlike Cancel it cannot drain a KCC-20 escrow holding other than the leg amount ([R14]), which only its depositor can send home, under earmarked funding from expiry_daa ([R3]).
#[test]
fn ix3_cancel_is_the_authority_refund_of_each_leg() {
    for funding in [REVOCABLE, EARMARKED] {
        let w = World::new(Mode::new(true, CASH_KCC20, funding));
        for leg in [ASSET_LEG, CASH_LEG] {
            let label = format!("funding {funding}, leg {leg}");
            let now = w.refund(leg, Role::Authority);
            assert_eq!(now.lock_time, 0, "{label}: no lock time");
            assert_eq!(now.outputs[0].spk, p2pk(w.xonly(depositor(leg))), "{label}");
            now.assert_all_accepted(&w, &format!("{label}: authority cancels"));
            let mut after_expiry = now.clone();
            after_expiry.lock_time = EXPIRY_DAA + 1;
            after_expiry.assert_all_accepted(&w, &format!("{label}: after expiry"));
        }
        // An escrow one unit short or one unit over: the authority cannot cancel it.
        for amount in [AMOUNT_A - 1, AMOUNT_A + 1] {
            assert_only_depositor_unwinds(&w, ASSET_LEG, amount, &format!("funding {funding}"));
        }
    }
}

/// parity: IX-4 divergent
/// Either party alone sends both legs home, its own as depositor and the other's as counterparty, with or without an authority in the terms; unlike Reject, a party cannot send home the other's KCC-20 escrow holding other than the leg amount ([R14]), and under earmarked funding its own leg waits for expiry_daa ([R3], EDGE-25).
#[test]
fn ix4_reject_is_a_party_refund_of_each_leg() {
    for authority in [true, false] {
        let w = World::new(Mode::new(authority, CASH_KAS, REVOCABLE));
        for party in [Role::Seller, Role::Buyer] {
            for leg in [ASSET_LEG, CASH_LEG] {
                let spec = w.refund(leg, party);
                assert_eq!(spec.lock_time, 0);
                spec.assert_all_accepted(
                    &w,
                    &format!("authority {authority}: {party:?} sends leg {leg} home"),
                );
            }
        }
    }
    // Earmarked, no authority: a party sends the other's leg home at once, its own from
    // expiry_daa; an escrow holding another amount only its depositor sends home.
    let w = World::new(Mode::new(false, CASH_KCC20, EARMARKED));
    for party in [Role::Seller, Role::Buyer] {
        for leg in [ASSET_LEG, CASH_LEG] {
            let label = format!("earmarked: {party:?} sends leg {leg} home");
            let spec = w.refund(leg, party);
            if party == depositor(leg) {
                assert_eq!(spec.lock_time, EXPIRY_DAA, "{label}");
                let mut early = spec.clone();
                early.lock_time = EXPIRY_DAA - 1;
                assert_flips_locktime(&w, &spec, &early, 0, &format!("{label}, one DAA early"));
            } else {
                assert_eq!(spec.lock_time, 0, "{label}");
                spec.assert_all_accepted(&w, &label);
            }
        }
    }
    assert_only_depositor_unwinds(&w, CASH_LEG, AMOUNT_B + 1, "earmarked");
}

/// parity: IX-5 divergent
/// A late deposit is a new UTXO at the address of the vault that settled, under the same script, and its depositor sends it home with the ordinary refund, with no tombstone and no proof that the trade existed; unlike Recover, under earmarked funding it waits for expiry_daa ([R3]), and one holding other than the leg amount only its depositor can send home ([R14]).
#[test]
fn ix5_recover_is_the_ordinary_refund() {
    for funding in [REVOCABLE, EARMARKED] {
        let w = World::new(Mode::new(true, CASH_KCC20, funding));
        let settle = w.settle();
        settle.assert_all_accepted(&w, &format!("funding {funding}: the trade settles"));
        // A late deposit to each vault address: the same script, refunded home.
        for (leg, at) in [(ASSET_LEG, 0), (CASH_LEG, 1)] {
            let label = format!("funding {funding}: a late deposit to leg {leg} goes home");
            let late = w.refund(leg, depositor(leg));
            assert_eq!(late.inputs[0].spk, settle.inputs[at].spk, "same address");
            late.assert_all_accepted(&w, &label);
            if funding == EARMARKED {
                assert_eq!(late.lock_time, EXPIRY_DAA);
                let mut early = late.clone();
                early.lock_time = EXPIRY_DAA - 1;
                assert_flips_locktime(&w, &late, &early, 0, &format!("{label}, one DAA early"));
            }
        }
        assert_only_depositor_unwinds(&w, ASSET_LEG, AMOUNT_A + 1, "a late over-deposit");
    }
}
