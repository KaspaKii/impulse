// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The other leg's vault in a settle ([S10], spec/TEMPLATE.md, "The other leg's vault"). Each
//! vault requires, where the other leg has a vault (KAS or KCC-20 cash), the input at the other
//! leg's canonical slot to run this template with this trade's terms. So a token of a leg's own
//! covenant owned by the other vault (misdirected funding) cannot stand in for that leg's escrow
//! in a settle that omits the other vault (the last case of known limitation L20), and the
//! vaults of two trades with identical deliveries do not settle together (L8). Run against
//! template v1 here and against the template v3 probe by v3p_sibling.rs.

mod foreign_common;
mod harness;
use foreign_common::*;
use harness::*;

const EXCESS: i64 = 4_000;

/// The KCC-20 cash settle of `mode` without the cash vault: input 1 is a plain input, and the
/// cash escrow at input 3 is a cash token owned by the asset vault holding amount_b + `excess`,
/// whose transfer pays amount_b to the seller (output 1) and `excess`, when not zero, to a
/// stranger (the last output).
fn settle_without_the_cash_vault(w: &World, excess: i64) -> TxSpec {
    let mut spec = w.settle();
    spec.inputs[1] = In::plain(AUTH_VALUE);
    let held = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        w.terms.amount_b + excess,
    );
    let mut states = vec![w.delivered_cash()];
    if excess > 0 {
        let taken = Kcc20State::new(STRANGER_OWNER, excess);
        states.push(taken);
        spec.outputs.push(Out::token(
            CASH_TOKEN.compile(taken),
            CASH_TOKEN.cov,
            World::CASH_ESCROW_IDX as u16,
        ));
    }
    spec.inputs[World::CASH_ESCROW_IDX] =
        In::token(CASH_TOKEN.compile(held), CASH_TOKEN.cov, states, 0);
    spec
}

/// The KCC-20 transfer itself is valid, so the asset vault's [S10] is what refuses it.
#[test]
fn s10_a_cash_token_at_the_asset_vault_cannot_pay_the_seller_without_the_cash_vault() {
    for mode in [AUTH_KCC20, SELF_KCC20] {
        let w = World::new(mode);
        w.settle()
            .assert_all_accepted(&w, &format!("{mode:?}: control"));
        for excess in [0, EXCESS] {
            let spec = settle_without_the_cash_vault(&w, excess);
            let label = format!("{mode:?}, excess {excess}");
            assert_token_transfer_valid(&w, &spec, World::CASH_ESCROW_IDX, &label);
            assert_refused(&spec.run(&w, 0), &format!("{label}: the asset vault"));
        }
    }
}

/// The settle of `mode` without the asset vault: input 0 is a plain input, and the asset escrow
/// is an asset token owned by the cash vault holding amount_a + `excess`, whose transfer
/// delivers amount_a to the buyer (output 0) and `excess`, when not zero, to a stranger.
fn settle_without_the_asset_vault(w: &World, excess: i64) -> TxSpec {
    let mut spec = w.settle();
    spec.inputs[0] = In::plain(AUTH_VALUE);
    let slot = w.asset_escrow_idx();
    let held = Kcc20State::new(
        Owner::script_hash(w.cash_vault().script_hash()),
        w.terms.amount_a + excess,
    );
    let mut states = vec![w.delivered_asset()];
    if excess > 0 {
        let taken = Kcc20State::new(STRANGER_OWNER, excess);
        states.push(taken);
        spec.outputs.push(Out::token(
            ASSET_TOKEN.compile(taken),
            ASSET_TOKEN.cov,
            slot as u16,
        ));
    }
    spec.inputs[slot] = In::token(ASSET_TOKEN.compile(held), ASSET_TOKEN.cov, states, 1);
    spec
}

/// In every mode with a cash vault; the KCC-20 transfer is valid, the cash vault's [S10] refuses.
#[test]
fn s10_an_asset_token_at_the_cash_vault_cannot_deliver_to_the_buyer_without_the_asset_vault() {
    for mode in [AUTH_KAS, SELF_KAS, AUTH_KCC20, SELF_KCC20] {
        let w = World::new(mode);
        w.settle()
            .assert_all_accepted(&w, &format!("{mode:?}: control"));
        for excess in [0, EXCESS] {
            let spec = settle_without_the_asset_vault(&w, excess);
            let label = format!("{mode:?}, excess {excess}");
            assert_token_transfer_valid(&w, &spec, w.asset_escrow_idx(), &label);
            assert_refused(&spec.run(&w, 1), &format!("{label}: the cash vault"));
        }
    }
}

/// KAS cash: the seller's proceeds paid from a plain input in place of the cash vault. The asset
/// vault sees its delivery and the proceeds, and refuses because the cash vault is not input 1.
#[test]
fn s10_asset_vault_refuses_a_kas_cash_settle_without_the_cash_vault() {
    for mode in [AUTH_KAS, SELF_KAS] {
        let w = World::new(mode);
        let control = w.settle();
        let mut faulty = control.clone();
        faulty.inputs[1] = In::plain(w.terms.amount_b as u64);
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("{mode:?}: KAS proceeds from a plain input, no cash vault"),
        );
    }
}

/// The other vault's slot holds a second UTXO of this vault's own address: not the other leg's
/// vault, refused by [S10] at input 0 (the input at 1 would also fail its own [S1]).
#[test]
fn s10_this_vault_again_at_the_other_slot_is_refused() {
    for mode in [AUTH_KAS, AUTH_KCC20] {
        let w = World::new(mode);
        let control = w.settle();
        let mut faulty = control.clone();
        faulty.inputs[1] = In::settle(&w.asset_vault, Some(Role::Authority), AUTH_VALUE);
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("{mode:?}: the asset vault at both slots"),
        );
    }
}

/// External cash has no cash vault: the asset vault settles with no vault at input 1 (input 1
/// is the asset escrow), so [S10] does not apply there.
#[test]
fn s10_external_cash_asset_vault_settles_with_no_cash_vault() {
    let w = World::new(AUTH_EXTERNAL);
    w.settle()
        .assert_all_accepted(&w, "external cash, no cash vault");
}

/// Cross-trade mixing (known limitation L8, closed): the asset vault of one trade and the cash
/// vault of a repeat trade between the same parties (another nonce and trade_ref, the same
/// deliveries) do not settle together. Each vault requires its own trade's other vault.
#[test]
fn s10_cross_trade_mixing_is_refused() {
    let a = World::new(AUTH_KCC20);
    let b = a.sibling(|t| {
        t.nonce = [0x01; 8];
        t.trade_ref = [0x02; 32];
    });
    assert_ne!(a.asset_vault.script_hash(), b.asset_vault.script_hash());
    assert_ne!(a.cash_vault().script_hash(), b.cash_vault().script_hash());
    let mixed = |asset: &World, cash: &World| {
        let mut spec = asset.settle();
        spec.inputs[1] = In::settle(cash.cash_vault(), Some(Role::Authority), AUTH_VALUE);
        spec.inputs[World::CASH_ESCROW_IDX] = In::token(
            CASH_TOKEN.compile(cash.cash_escrow_state()),
            CASH_COV,
            vec![cash.delivered_cash()],
            1,
        );
        spec
    };
    a.settle().assert_all_accepted(&a, "trade A, control");
    b.settle().assert_all_accepted(&b, "trade B, control");
    for (asset, cash, label) in [
        (&a, &b, "A asset with B cash"),
        (&b, &a, "B asset with A cash"),
    ] {
        let spec = mixed(asset, cash);
        assert_refused(&spec.run(asset, 0), &format!("{label}: the asset vault"));
        assert_refused(&spec.run(asset, 1), &format!("{label}: the cash vault"));
    }
}

#[test]
fn the_same_settle_with_the_cash_vault_present_is_refused_by_f2() {
    // With the cash vault spent beside its own escrow, the stray cash token is a second input of
    // the cash covenant: the asset vault refuses it ([F2]) and the cash vault too ([E1]).
    let w = World::new(SELF_KCC20);
    let control = w.settle();
    let (faulty, _) = with_second_token_owned_by(
        &control,
        (&w.asset_vault, 0),
        CASH_TOKEN,
        EXCESS,
        World::CASH_ESCROW_IDX,
    );
    assert_refused(&faulty.run(&w, 0), "asset vault");
    assert_refused(&faulty.run(&w, 1), "cash vault");
}
