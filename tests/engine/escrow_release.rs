// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Escrow release (I3 carried-forward exit test, I1 review). KCC-20 authorizes a token owned
//! by SCRIPT_HASH(vault) on the witness input's scriptPubKey alone, so any UTXO at the vault
//! address, spent through any entry, is a valid witness. Anyone can create a UTXO at a vault
//! address. These tests prove that no such witness lets the escrow leave except home (refund)
//! or to the agreed delivery (settle).
//!
//! In every refusal below the KCC-20 transfers are themselves asserted valid where the case
//! allows it, so the vault is the only thing refusing.

mod harness;
use harness::*;

const MODE: Mode = Mode::new(true, CASH_KCC20, EARMARKED);

/// Dust a stranger sends to the asset vault address: a second vault-address UTXO.
const DUST: u64 = 7_000;

fn stranger_state(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

/// Points the escrowed token at input `token_idx` (and its covenant output 1) at `states`.
fn send_token(spec: &mut TxSpec, token: Token, token_idx: usize, states: &[Kcc20State]) {
    match &mut spec.inputs[token_idx].spend {
        Spend::Kcc20Leader { new_states, .. } => *new_states = states.to_vec(),
        _ => panic!("input {token_idx} is not a token leader"),
    }
    spec.outputs[1] = Out::token(token.compile(states[0]), token.cov, token_idx as u16);
}

fn set_witness(spec: &mut TxSpec, token_idx: usize, to: u8) {
    match &mut spec.inputs[token_idx].spend {
        Spend::Kcc20Leader { witness, .. } | Spend::Kcc20Delegate { witness, .. } => *witness = to,
        _ => panic!("input {token_idx} is not a token"),
    }
}

/// A refund of a stranger's dust UTXO at the asset vault address, signed by the buyer, with the
/// real escrowed asset token riding at input 1 and going home. This is a legitimate refund.
fn dust_refund(w: &World) -> TxSpec {
    let mut spec = w.refund(ASSET_LEG, Role::Buyer);
    spec.inputs[0].value = DUST;
    spec.outputs[0].value = DUST;
    spec
}

// ---------------------------------------------------------------------------------------------
// Witnessed by the refund entry
// ---------------------------------------------------------------------------------------------

#[test]
fn refund_by_counterparty_cannot_send_asset_escrow_to_stranger() {
    let w = World::new(MODE);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    send_token(&mut faulty, ASSET_TOKEN, 1, &[stranger_state(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund routes the asset escrow to a stranger",
    );
}

#[test]
fn refund_by_authority_cannot_send_asset_escrow_to_stranger() {
    let w = World::new(MODE);
    let control = w.refund(ASSET_LEG, Role::Authority);
    let mut faulty = control.clone();
    send_token(&mut faulty, ASSET_TOKEN, 1, &[stranger_state(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "authority refund routes the escrow away",
    );
}

#[test]
fn refund_by_counterparty_cannot_send_cash_escrow_to_stranger() {
    let w = World::new(MODE);
    let control = w.refund(CASH_LEG, Role::Seller);
    let mut faulty = control.clone();
    send_token(&mut faulty, CASH_TOKEN, 1, &[stranger_state(AMOUNT_B)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund routes the cash escrow to a stranger",
    );
}

#[test]
fn refund_cannot_split_escrow_between_home_and_stranger() {
    let w = World::new(MODE);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let home = Kcc20State::new(SELLER_REFUND, AMOUNT_A - 1);
    send_token(&mut faulty, ASSET_TOKEN, 1, &[home, stranger_state(1)]);
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger_state(1)), ASSET_COV, 1),
    );
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund sends one unit of the escrow away",
    );
}

// ---------------------------------------------------------------------------------------------
// Witnessed by a second vault-address UTXO at another input index
// ---------------------------------------------------------------------------------------------

/// The I1 review case exactly: the escrow is witnessed by a second UTXO at the vault address,
/// spent through `refund` at input 2, and the asset goes to a stranger.
#[test]
fn second_vault_utxo_via_refund_at_input_2_cannot_release_escrow() {
    let w = World::new(MODE);
    let control = dust_refund(&w);
    let mut faulty = control.clone();
    // Fee input to the front, the dust vault UTXO to input 2, the escrow witnessing it.
    faulty.inputs.swap(0, 2);
    set_witness(&mut faulty, 1, 2);
    send_token(&mut faulty, ASSET_TOKEN, 1, &[stranger_state(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        2,
        "second vault UTXO at input 2, refund entry",
    );
}

/// The same, spent through `settle` at input 2.
#[test]
fn second_vault_utxo_via_settle_at_input_2_cannot_release_escrow() {
    let w = World::new(MODE);
    let control = dust_refund(&w);
    let mut faulty = control.clone();
    faulty.inputs.swap(0, 2);
    faulty.inputs[2] = In::settle(&w.asset_vault, Some(Role::Authority), DUST);
    set_witness(&mut faulty, 1, 2);
    send_token(&mut faulty, ASSET_TOKEN, 1, &[stranger_state(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        2,
        "second vault UTXO at input 2, settle entry",
    );
}

/// A second vault UTXO at input 0 through `refund`, with the escrow pushed to input 2 so it
/// is not where the refund looks for it.
#[test]
fn second_vault_utxo_via_refund_cannot_release_escrow_held_at_another_index() {
    let w = World::new(MODE);
    let control = dust_refund(&w);
    let mut faulty = control.clone();
    faulty.inputs.swap(1, 2);
    match &mut faulty.inputs[2].spend {
        Spend::Kcc20Leader { new_states, .. } => *new_states = vec![stranger_state(AMOUNT_A)],
        _ => unreachable!(),
    }
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(stranger_state(AMOUNT_A)), ASSET_COV, 2);
    assert_accepted(&faulty.run(&w, 2), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "escrow at input 2 sent to a stranger",
    );
}

/// A self-settling settle (anyone may submit it) that also carries a second deposit of the
/// asset to the same vault: the extra token must not ride along to a stranger.
#[test]
fn second_escrow_deposit_cannot_ride_along_a_settle() {
    let w = World::new(Mode::new(false, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    let extra_idx = faulty.inputs.len() - 1; // before the fee input
    faulty.inputs.insert(
        extra_idx,
        In::token_delegate(ASSET_TOKEN.compile(w.asset_escrow_state()), ASSET_COV, 0),
    );
    match &mut faulty.inputs[escrow].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states.push(stranger_state(AMOUNT_A)),
        _ => unreachable!(),
    }
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger_state(AMOUNT_A)),
        ASSET_COV,
        escrow as u16,
    ));
    let (tx, entries) = faulty.build(&w);
    assert_accepted(&execute(&tx, &entries, escrow), "KCC-20 leader is valid");
    assert_accepted(
        &execute(&tx, &entries, extra_idx),
        "KCC-20 delegate is valid",
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a settle",
    );
}

/// A refund that carries a second deposit of the asset: one goes home, the other to a stranger.
fn second_deposit_rides_refund(w: &World, signer: Role) -> (TxSpec, TxSpec) {
    let control = w.refund(ASSET_LEG, signer);
    let mut faulty = control.clone();
    faulty.inputs.insert(
        2,
        In::token_delegate(ASSET_TOKEN.compile(w.asset_escrow_state()), ASSET_COV, 0),
    );
    match &mut faulty.inputs[1].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states.push(stranger_state(AMOUNT_A)),
        _ => unreachable!(),
    }
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger_state(AMOUNT_A)), ASSET_COV, 1),
    );
    let (tx, entries) = faulty.build(w);
    assert_accepted(&execute(&tx, &entries, 1), "KCC-20 leader is valid");
    assert_accepted(&execute(&tx, &entries, 2), "KCC-20 delegate is valid");
    (control, faulty)
}

/// Signed by the depositor, the case only [R8] guards.
#[test]
fn second_escrow_deposit_cannot_ride_along_a_refund() {
    let w = World::new(MODE);
    let (control, faulty) = second_deposit_rides_refund(&w, Role::Seller);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a depositor refund",
    );
}

#[test]
fn second_escrow_deposit_cannot_ride_along_a_counterparty_refund() {
    let w = World::new(MODE);
    let (control, faulty) = second_deposit_rides_refund(&w, Role::Buyer);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a counterparty refund",
    );
}

// ---------------------------------------------------------------------------------------------
// Without its vault the escrow cannot move at all (KCC-20's own rule; I1 item 1)
// ---------------------------------------------------------------------------------------------

#[test]
fn escrow_cannot_move_with_no_vault_input() {
    let w = World::new(MODE);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::plain(AUTH_VALUE);
    assert_accepted(
        &control.run(&w, 1),
        "control: KCC-20 transfer witnessed by the vault",
    );
    assert_refused(
        &faulty.run(&w, 1),
        "no vault input: witness is a plain UTXO",
    );
}

#[test]
fn escrow_cannot_move_with_another_vault_as_witness() {
    let w = World::new(MODE);
    let other = World::with(MODE, |t, _| t.amount_a += 1);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::refund(
        &other.asset_vault,
        w.xonly(Role::Buyer),
        Role::Buyer,
        AUTH_VALUE,
    );
    assert_accepted(
        &control.run(&w, 1),
        "control: KCC-20 transfer witnessed by its vault",
    );
    assert_refused(
        &faulty.run(&w, 1),
        "a vault with one term changed is not the owner",
    );
}

#[test]
fn escrow_cannot_move_with_witness_pointing_away_from_its_vault() {
    let w = World::new(MODE);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    set_witness(&mut faulty, 1, 2);
    assert_accepted(
        &control.run(&w, 1),
        "control: KCC-20 transfer witnessed by its vault",
    );
    assert_refused(&faulty.run(&w, 1), "witness names the fee input");
}
