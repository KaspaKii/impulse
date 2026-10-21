// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault `settle` in the real engine. One passing test per mode combination that
//! matters for settle (authority present or absent x cash kind KAS, KCC-20, external), then
//! one refusal test per settle-side require, each against an accepted control that differs
//! only in the one fault. Test names start with the require ID they exercise
//! ([S1] etc. in contracts/impulse_vault.sil); tests/engine/mutation.py checks the mapping.
//! Lock-time requires are in locktime.rs; escrow-release cases are in escrow_release.rs.

mod harness;
use harness::*;
use kaspa_txscript_errors::TxScriptError;

fn mode(authority: bool, cash: u8) -> Mode {
    Mode::new(authority, cash, REVOCABLE)
}

fn leader_states(spec: &mut TxSpec, idx: usize) -> &mut Vec<Kcc20State> {
    match &mut spec.inputs[idx].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states,
        _ => panic!("input {idx} is not a token leader"),
    }
}

/// A token owner whose witness is any plain P2SH(OpTrue) input (the fee input here).
fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

fn stranger(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

/// Replaces the asset delivered at output 0 (and the escrow transfer's new states) by `states`;
/// states after the first become extra asset outputs at the end.
fn deliver_asset(w: &World, spec: &mut TxSpec, states: &[Kcc20State]) {
    let escrow = w.asset_escrow_idx();
    *leader_states(spec, escrow) = states.to_vec();
    spec.outputs[0] = Out::token(ASSET_TOKEN.compile(states[0]), ASSET_COV, escrow as u16);
    for s in &states[1..] {
        spec.outputs.push(Out::token(
            ASSET_TOKEN.compile(*s),
            ASSET_COV,
            escrow as u16,
        ));
    }
}

/// Replaces the escrowed asset token (its UTXO script and the redeem it carries).
fn set_asset_escrow(w: &World, spec: &mut TxSpec, token: Token, state: Kcc20State) {
    let idx = w.asset_escrow_idx();
    let new_states = leader_states(spec, idx).clone();
    let cov = spec.inputs[idx].cov;
    spec.inputs[idx] = In::token(token.compile(state), cov.expect("covenant"), new_states, 0);
    spec.inputs[idx].cov = cov;
}

fn fee_idx(spec: &TxSpec) -> usize {
    spec.inputs.len() - 1
}

// =============================================================================================
// Passing: every input of the canonical settle accepted, per mode
// =============================================================================================

#[test]
fn settle_authority_kas_cash() {
    let w = World::new(mode(true, CASH_KAS));
    w.settle().assert_all_accepted(&w, "authority, KAS cash");
}

#[test]
fn settle_authority_kcc20_cash() {
    let w = World::new(mode(true, CASH_KCC20));
    w.settle().assert_all_accepted(&w, "authority, KCC-20 cash");
}

#[test]
fn settle_authority_external_cash() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    w.settle()
        .assert_all_accepted(&w, "authority, external cash");
}

#[test]
fn settle_self_settling_kas_cash() {
    let w = World::new(mode(false, CASH_KAS));
    w.settle()
        .assert_all_accepted(&w, "self-settling, KAS cash");
}

#[test]
fn settle_self_settling_kcc20_cash() {
    let w = World::new(mode(false, CASH_KCC20));
    w.settle()
        .assert_all_accepted(&w, "self-settling, KCC-20 cash");
}

/// Funding mode does not gate settle: an earmarked trade settles exactly like a revocable one.
#[test]
fn settle_earmarked_funding() {
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    w.settle()
        .assert_all_accepted(&w, "authority, KCC-20 cash, earmarked");
}

// =============================================================================================
// [S1] canonical position
// =============================================================================================

/// The buyer funded the KAS cash vault twice. In a self-settling trade anyone may submit the
/// settle; the second cash UTXO must not settle at another input, where output 1 would
/// satisfy it a second time and its KAS would go to the submitter's change.
#[test]
fn s1_second_kas_cash_deposit_cannot_settle_off_its_index() {
    let w = World::new(mode(false, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty
        .inputs
        .insert(at, In::settle(w.cash_vault(), None, AMOUNT_B as u64));
    faulty.outputs.last_mut().expect("change").value += AMOUNT_B as u64;
    assert_flips(
        &w,
        &control,
        &faulty,
        at,
        "second cash vault UTXO at input 3",
    );
}

#[test]
fn s1_asset_vault_refuses_input_1() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs.swap(0, 1);
    assert_flips(&w, &control, &faulty, 1, "asset vault at the cash position");
}

// =============================================================================================
// [E1]..[E5] the leg's escrow holds exactly the leg amount (checkEscrow)
// =============================================================================================

/// Escrowed token UTXO with no covenant binding, nothing of the asset covenant in the tx.
#[test]
fn e1_escrow_without_covenant_binding() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    faulty.inputs[escrow].cov = None;
    faulty.outputs[0].cov = None;
    assert_flips(&w, &control, &faulty, 0, "escrow carries no covenant ID");
}

/// Escrowed token UTXO with no covenant binding while a real asset token elsewhere supplies
/// output 0.
#[test]
fn e2_escrow_without_covenant_binding_real_asset_elsewhere() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    faulty.inputs[escrow].cov = None;
    *leader_states(&mut faulty, escrow) = vec![];
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            ASSET_COV,
            vec![w.delivered_asset()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = at as u16;
    assert_accepted(&faulty.run(&w, at), "the real asset transfer is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "unbound escrow, real asset elsewhere",
    );
}

/// Escrow under another covenant (same template, same state) while a real asset token
/// elsewhere supplies output 0: the escrowed asset would stay behind. Every KCC-20 transfer
/// here is valid; only the vault refuses.
#[test]
fn e2_escrow_under_another_covenant_real_asset_elsewhere() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    faulty.inputs[escrow].cov = Some(DECOY_COV);
    *leader_states(&mut faulty, escrow) = vec![stranger(AMOUNT_A)];
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            ASSET_COV,
            vec![w.delivered_asset()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = at as u16;
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        DECOY_COV,
        escrow as u16,
    ));
    assert_accepted(
        &faulty.run(&w, escrow),
        "decoy-covenant escrow transfer is valid",
    );
    assert_accepted(&faulty.run(&w, at), "the real asset transfer is valid");
    assert_flips(&w, &control, &faulty, 0, "escrow under another covenant");
}

#[test]
fn e3_escrow_owner_type_pubkey() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::pubkey(w.asset_vault.script_hash()), AMOUNT_A);
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    assert_flips(&w, &control, &faulty, 0, "escrow owner type is PUBKEY");
}

#[test]
fn e4_escrow_owned_by_another_vault() {
    let w = World::new(mode(true, CASH_KAS));
    let other = World::with(mode(true, CASH_KAS), |t, _| t.nonce = [0x01; 8]);
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(
        Owner::script_hash(other.asset_vault.script_hash()),
        AMOUNT_A,
    );
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    assert_flips(&w, &control, &faulty, 0, "escrow owned by another vault");
}

#[test]
fn e4_escrow_owned_by_the_cash_vault() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::script_hash(w.cash_vault().script_hash()), AMOUNT_A);
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "asset escrow owned by the cash leg's vault",
    );
}

#[test]
fn e5_escrow_over_funded() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A + 1,
    );
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    deliver_asset(&w, &mut faulty, &[w.delivered_asset(), stranger(1)]);
    let escrow = w.asset_escrow_idx();
    assert_accepted(
        &faulty.run(&w, escrow),
        "the KCC-20 transfer itself is valid",
    );
    assert_flips(&w, &control, &faulty, 0, "escrow holds amount_a + 1");
}

/// Escrow holds amount_a - 1 while output 0 still shows amount_a. The vault input is judged
/// alone here; topping up from another asset input would also trip [E1].
#[test]
fn e5_escrow_under_funded() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A - 1,
    );
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    assert_flips(&w, &control, &faulty, 0, "escrow holds amount_a - 1");
}

#[test]
fn e5_cash_escrow_over_funded() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = World::CASH_ESCROW_IDX;
    let state = Kcc20State::new(
        Owner::script_hash(w.cash_vault().script_hash()),
        AMOUNT_B + 1,
    );
    faulty.inputs[idx] = In::token(
        CASH_TOKEN.compile(state),
        CASH_COV,
        vec![w.delivered_cash(), stranger(1)],
        1,
    );
    faulty.outputs.push(Out::token(
        CASH_TOKEN.compile(stranger(1)),
        CASH_COV,
        idx as u16,
    ));
    assert_accepted(&faulty.run(&w, idx), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 1, "cash escrow holds amount_b + 1");
}

/// A minter escrow: the buyer still receives a plain amount_a, but the minting right would go
/// to a stranger output the settler adds. The KCC-20 transfer itself is valid.
#[test]
fn e6_minter_escrow_cannot_hand_minting_to_a_stranger() {
    let w = World::new(mode(false, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let minter = Kcc20State {
        is_minter: true,
        ..w.asset_escrow_state()
    };
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, minter);
    let stranger_minter = Kcc20State {
        is_minter: true,
        ..stranger(0)
    };
    deliver_asset(&w, &mut faulty, &[w.delivered_asset(), stranger_minter]);
    let escrow = w.asset_escrow_idx();
    assert_accepted(
        &faulty.run(&w, escrow),
        "the KCC-20 transfer itself is valid",
    );
    assert_flips(&w, &control, &faulty, 0, "escrow is a minter");
}

/// Cash escrow holds amount_b - 1 while output 1 still shows amount_b; the cash vault input is
/// judged alone, as in the asset-leg case.
#[test]
fn e5_cash_escrow_under_funded() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = World::CASH_ESCROW_IDX;
    let state = Kcc20State::new(
        Owner::script_hash(w.cash_vault().script_hash()),
        AMOUNT_B - 1,
    );
    faulty.inputs[idx] = In::token(
        CASH_TOKEN.compile(state),
        CASH_COV,
        vec![w.delivered_cash()],
        1,
    );
    assert_flips(&w, &control, &faulty, 1, "cash escrow holds amount_b - 1");
}

// Template reads (builtin readInputStateWithTemplate, not a require): the escrow must run the
// pinned template, at the pinned prefix and suffix lengths, and hold the state it claims.

#[test]
fn escrow_under_another_template() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    let other = Token {
        max_cov_ins: 3,
        ..ASSET_TOKEN
    };
    set_asset_escrow(&w, &mut faulty, other, w.asset_escrow_state());
    faulty.outputs[0] = Out::token(other.compile(w.delivered_asset()), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "escrow runs another template");
}

#[test]
fn escrow_sigscript_claims_a_state_its_utxo_does_not_hold() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    let real = ASSET_TOKEN.compile(Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A + 5,
    ));
    faulty.inputs[1].spk = real.p2sh();
    assert_flips(&w, &control, &faulty, 0, "forged escrow state");
}

/// Terms carry the right template hash but a prefix length one too long (suffix one short):
/// the vault cannot read its escrow and never settles. Same parties, only the lengths differ.
/// Carried forward from the I1 review.
#[test]
fn escrow_read_with_wrong_prefix_len() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    w.settle()
        .assert_all_accepted(&w, "control, correct lengths");
    let bad = w.edit(|t| {
        t.asset.prefix_len += 1;
        t.asset.suffix_len -= 1;
    });
    assert_refused(
        &bad.settle().run(&bad, 0),
        "prefix length + 1, suffix length - 1",
    );
}

#[test]
fn escrow_read_with_wrong_suffix_len() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    w.settle()
        .assert_all_accepted(&w, "control, correct lengths");
    let bad = w.edit(|t| t.asset.suffix_len += 1);
    assert_refused(&bad.settle().run(&bad, 0), "suffix length + 1");
}

// =============================================================================================
// [D1] and the builtin output match: output 0 delivers amount_a of the asset to the buyer
// =============================================================================================

/// A decoy token with the same template and the same state sits at output 0; the real asset
/// goes to a stranger. Both KCC-20 transfers are valid.
#[test]
fn d1_output0_under_decoy_covenant() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    *leader_states(&mut faulty, 1) = vec![stranger(AMOUNT_A)];
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            DECOY_COV,
            vec![w.delivered_asset()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[0] = Out::token(
        ASSET_TOKEN.compile(w.delivered_asset()),
        DECOY_COV,
        at as u16,
    );
    // Token outputs are bound by covenant ID, not position: the real asset goes last.
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "the asset transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    assert_flips(&w, &control, &faulty, 0, "output 0 under a decoy covenant");
}

/// Output 1 is a decoy token with the cash template and the seller's state under another
/// covenant; the real cash goes to a stranger. Both KCC-20 transfers are valid; both vaults
/// refuse.
#[test]
fn d1_cash_output1_under_decoy_covenant() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = World::CASH_ESCROW_IDX;
    *leader_states(&mut faulty, idx) = vec![stranger(AMOUNT_B)];
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            CASH_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_B)),
            DECOY_COV,
            vec![w.delivered_cash()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[1] = Out::token(CASH_TOKEN.compile(w.delivered_cash()), DECOY_COV, at as u16);
    faulty.outputs.push(Out::token(
        CASH_TOKEN.compile(stranger(AMOUNT_B)),
        CASH_COV,
        idx as u16,
    ));
    assert_accepted(&faulty.run(&w, idx), "the cash transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    assert_flips(&w, &control, &faulty, 0, "output 1 under a decoy covenant");
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

// [D2] each delivered token carries at least its escrow's own KAS

#[test]
fn deliveries_may_carry_more_than_the_escrow_kas() {
    let w = World::new(mode(true, CASH_KCC20));
    let mut spec = w.settle();
    spec.outputs[0].value += 1;
    spec.outputs[1].value += 1;
    spec.assert_all_accepted(&w, "delivered tokens carry more KAS than their escrows");
}

#[test]
fn d2_asset_delivery_carrier_kas_short() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "asset delivered with one sompi less KAS",
    );
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

#[test]
fn d2_cash_delivery_carrier_kas_short() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "cash delivered with one sompi less KAS",
    );
    assert_refused(&faulty.run(&w, 0), "the asset vault refuses it too");
}

#[test]
fn d2_external_cash_asset_delivery_carrier_kas_short() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "external cash, asset delivered with less KAS",
    );
}

#[test]
fn output0_wrong_owner() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    deliver_asset(&w, &mut faulty, &[stranger(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 2), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "output 0 owner is not buyer_delivery",
    );
    assert_refused(&faulty.run(&w, 1), "the cash vault checks output 0 too");
}

#[test]
fn output0_wrong_owner_type() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let wrong = Kcc20State::new(Owner::script_hash(BUYER_DELIVERY.id), AMOUNT_A);
    deliver_asset(&w, &mut faulty, &[wrong]);
    assert_accepted(&faulty.run(&w, 2), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "output 0 owner type differs");
}

#[test]
fn output0_short_amount() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let short = Kcc20State::new(BUYER_DELIVERY, AMOUNT_A - 1);
    deliver_asset(&w, &mut faulty, &[short, stranger(1)]);
    assert_accepted(&faulty.run(&w, 2), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "output 0 holds amount_a - 1");
}

#[test]
fn output0_is_minter() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let minter = Kcc20State {
        is_minter: true,
        ..w.delivered_asset()
    };
    deliver_asset(&w, &mut faulty, &[minter]);
    assert_flips(&w, &control, &faulty, 0, "output 0 carries isMinter");
}

#[test]
fn output0_under_another_template() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let other = Token {
        max_cov_outs: 4,
        ..ASSET_TOKEN
    };
    faulty.outputs[0] = Out::token(other.compile(w.delivered_asset()), ASSET_COV, 2);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "output 0 is the right state, another template",
    );
}

// =============================================================================================
// [S2] KAS cash: the cash vault UTXO holds exactly amount_b
// =============================================================================================

#[test]
fn s2_kas_cash_vault_under_funded() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1].value = AMOUNT_B as u64 - 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "KAS cash vault holds amount_b - 1",
    );
}

#[test]
fn s2_kas_cash_vault_over_funded() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1].value = AMOUNT_B as u64 + 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "KAS cash vault holds amount_b + 1",
    );
}

// =============================================================================================
// [S4] [S5] and the builtin output match: output 1 delivers amount_b of cash to the seller
// =============================================================================================

#[test]
fn s4_kas_proceeds_to_stranger() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].spk = stranger_spk();
    assert_flips(&w, &control, &faulty, 0, "KAS proceeds to a stranger");
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

#[test]
fn s5_kas_proceeds_short() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].value = AMOUNT_B as u64 - 1;
    assert_flips(&w, &control, &faulty, 0, "KAS proceeds amount_b - 1");
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

#[test]
fn kcc20_proceeds_to_stranger() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = World::CASH_ESCROW_IDX;
    *leader_states(&mut faulty, idx) = vec![stranger(AMOUNT_B)];
    faulty.outputs[1] = Out::token(CASH_TOKEN.compile(stranger(AMOUNT_B)), CASH_COV, idx as u16);
    assert_accepted(&faulty.run(&w, idx), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "KCC-20 proceeds to a stranger");
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

#[test]
fn kcc20_proceeds_short() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = World::CASH_ESCROW_IDX;
    let short = Kcc20State::new(SELLER_PROCEEDS, AMOUNT_B - 1);
    *leader_states(&mut faulty, idx) = vec![short, stranger(1)];
    faulty.outputs[1] = Out::token(CASH_TOKEN.compile(short), CASH_COV, idx as u16);
    faulty.outputs.push(Out::token(
        CASH_TOKEN.compile(stranger(1)),
        CASH_COV,
        idx as u16,
    ));
    assert_accepted(&faulty.run(&w, idx), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "KCC-20 proceeds amount_b - 1");
}

/// The cash output under the asset template: each leg is matched against its own template.
#[test]
fn kcc20_proceeds_under_the_asset_template() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1] = Out::token(
        ASSET_TOKEN.compile(w.delivered_cash()),
        CASH_COV,
        World::CASH_ESCROW_IDX as u16,
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "cash delivered under the asset template",
    );
}

/// External cash has no cash vault. A leg-1 vault derived from external-cash terms cannot
/// settle: it would sit at input 1, where the asset escrow's template must be.
#[test]
fn external_cash_leg_vault_never_settles() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    let leg1 = w.terms.vault(CASH_LEG);
    faulty
        .inputs
        .insert(1, In::settle(&leg1, Some(Role::Authority), AUTH_VALUE));
    // The escrow moves to input 2 and still names the asset vault at input 0 as its witness.
    faulty.outputs[0]
        .cov
        .as_mut()
        .expect("bound")
        .authorizing_input = 2;
    assert_accepted(&faulty.run(&w, 2), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "external-cash leg-1 vault settles",
    );
}

// =============================================================================================
// [S7] external cash settles only through an authority
// =============================================================================================

/// The same parties and terms with the authority flag cleared: the asset could leave against an
/// off-chain payment nobody confirmed. The settle still carries a valid authority signature.
#[test]
fn s7_external_cash_without_authority() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    control.assert_all_accepted(&w, "control: authority set");
    let w = w.edit(|t| t.has_authority = false);
    assert_refused(
        &w.settle().run(&w, 0),
        "external cash, authority flag cleared",
    );
}

/// Self-settling terms with external cash, built as such: nobody can settle them.
#[test]
fn s7_self_settling_external_cash_never_settles() {
    let w = World::new(mode(false, CASH_EXTERNAL));
    assert_refused(&w.settle().run(&w, 0), "self-settling, external cash");
    w.refund(ASSET_LEG, Role::Buyer)
        .assert_all_accepted(&w, "its asset leg still goes home");
}

// =============================================================================================
// [S8] [S9] each KCC-20 leg's authorizer KAS goes back to its depositor, at least in full
// =============================================================================================

const SELLER_RETURN: usize = 2;
const BUYER_RETURN: usize = 3;

#[test]
fn authorizer_returns_may_exceed_the_authorizer_value() {
    let w = World::new(mode(true, CASH_KCC20));
    let mut spec = w.settle();
    spec.outputs[SELLER_RETURN].value += 1;
    spec.outputs[BUYER_RETURN].value += 1;
    spec.assert_all_accepted(&w, "returns above the authorizer value");
}

#[test]
fn s8_seller_authorizer_return_to_stranger() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[SELLER_RETURN].spk = stranger_spk();
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "asset authorizer KAS to a stranger",
    );
}

#[test]
fn s8_buyer_authorizer_return_to_stranger() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[BUYER_RETURN].spk = stranger_spk();
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "cash authorizer KAS to a stranger",
    );
}

/// Output 2 left out under KAS cash: the change output takes its place.
#[test]
fn s8_seller_authorizer_return_omitted() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    let returned = faulty.outputs.remove(SELLER_RETURN).value;
    faulty.outputs.last_mut().expect("change").value += returned;
    assert_flips(&w, &control, &faulty, 0, "asset authorizer return omitted");
}

/// Output 3 left out under KCC-20 cash: the change output takes its place.
#[test]
fn s8_buyer_authorizer_return_omitted() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    let returned = faulty.outputs.remove(BUYER_RETURN).value;
    faulty.outputs.last_mut().expect("change").value += returned;
    assert_flips(&w, &control, &faulty, 1, "cash authorizer return omitted");
}

/// External cash: the asset authorizer's KAS is at output 1; left out, the change takes its place.
#[test]
fn s8_external_cash_seller_return_omitted() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    let returned = faulty.outputs.remove(1).value;
    faulty.outputs.last_mut().expect("change").value += returned;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "external cash, asset authorizer return omitted",
    );
}

#[test]
fn s9_seller_return_short() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[SELLER_RETURN].value -= 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "asset authorizer KAS returned minus 1",
    );
}

#[test]
fn s9_buyer_return_short() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[BUYER_RETURN].value -= 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        1,
        "cash authorizer KAS returned minus 1",
    );
}

#[test]
fn s9_external_cash_seller_return_short() {
    let w = World::new(mode(true, CASH_EXTERNAL));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "external cash, asset authorizer KAS minus 1",
    );
}

// =============================================================================================
// [S6] the settlement authority signs, if there is one
// =============================================================================================

#[test]
fn s6_authority_signature_from_stranger() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[0] = In::settle(&w.asset_vault, Some(Role::Stranger), AUTH_VALUE);
    assert_flips(&w, &control, &faulty, 0, "settle signed by a stranger");
}

#[test]
fn s6_authority_signature_missing() {
    let w = World::new(mode(true, CASH_KAS));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::settle(w.cash_vault(), None, AMOUNT_B as u64);
    control.assert_all_accepted(&w, "control");
    // 65 zero bytes (what a self-settling settle passes) fail checkSig's sighash-type parse.
    let run = faulty.run(&w, 1);
    assert!(
        matches!(run.result, Err(TxScriptError::InvalidSigHashType(0))),
        "settle with no authority signature: got {:?}",
        run.result
    );
}

#[test]
fn s6_authority_signature_from_a_party() {
    let w = World::new(mode(true, CASH_KCC20));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[0] = In::settle(&w.asset_vault, Some(Role::Seller), AUTH_VALUE);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "settle signed by the seller, not the authority",
    );
}

// =============================================================================================
// Cross-trade mixing is refused by [S10]: foreign_covenant_residual.rs,
// s10_cross_trade_mixing_is_refused (not here, so the v4 differential run of this file is not
// affected).
// =============================================================================================
