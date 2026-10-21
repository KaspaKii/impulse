// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseVault `refund` in the real engine. One passing test per mode combination that
//! matters for refund (signer role depositor, counterparty, authority x funding mode revocable,
//! earmarked), the leg kinds, then one refusal test per refund-side require, each against an
//! accepted control that differs only in the one fault. Test names start with the require ID
//! ([R1] etc. in contracts/impulse_vault.sil). The expiry gate [R3] is in locktime.rs;
//! escrow-release cases ([R8] among them) are in escrow_release.rs.

mod harness;
use harness::*;

const AUTH_KCC20: Mode = Mode::new(true, CASH_KCC20, REVOCABLE);
const AUTH_KCC20_EARMARKED: Mode = Mode::new(true, CASH_KCC20, EARMARKED);

fn leader_states(spec: &mut TxSpec, idx: usize) -> &mut Vec<Kcc20State> {
    match &mut spec.inputs[idx].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states,
        _ => panic!("input {idx} is not a token leader"),
    }
}

fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

fn stranger(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

fn fee_idx(spec: &TxSpec) -> usize {
    spec.inputs.len() - 1
}

/// The same refund with the escrowed token (input 1, output 1) left out.
fn without_token(mut spec: TxSpec) -> TxSpec {
    spec.inputs.remove(1);
    spec.outputs.remove(1);
    spec
}

/// The asset escrow at input 1 replaced by `escrow`, returning home as `home` at output 1.
fn with_asset_escrow(spec: &mut TxSpec, escrow: Kcc20State, home: Kcc20State) {
    spec.inputs[1] = In::token(ASSET_TOKEN.compile(escrow), ASSET_COV, vec![home], 0);
    spec.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
}

// =============================================================================================
// Passing: signer role x funding mode (asset leg, escrowed KCC-20 riding along)
// =============================================================================================

#[test]
fn refund_depositor_revocable() {
    let w = World::new(AUTH_KCC20);
    let spec = w.refund(ASSET_LEG, Role::Seller);
    assert_eq!(spec.lock_time, 0, "revocable: no lock time needed");
    spec.assert_all_accepted(&w, "depositor, revocable");
}

#[test]
fn refund_depositor_earmarked() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    let spec = w.refund(ASSET_LEG, Role::Seller);
    assert_eq!(spec.lock_time, EXPIRY_DAA);
    spec.assert_all_accepted(&w, "depositor, earmarked, at expiry");
}

#[test]
fn refund_counterparty_revocable() {
    let w = World::new(AUTH_KCC20);
    w.refund(ASSET_LEG, Role::Buyer)
        .assert_all_accepted(&w, "counterparty, revocable");
}

#[test]
fn refund_counterparty_earmarked() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    let spec = w.refund(ASSET_LEG, Role::Buyer);
    assert_eq!(
        spec.lock_time, 0,
        "the counterparty does not wait for expiry"
    );
    spec.assert_all_accepted(&w, "counterparty, earmarked, before expiry");
}

/// A3 (hardening round 1). Earmarking blocks a depositor's own early withdrawal; it does not stop
/// the counterparty cancelling the other party's leg. In an earmarked trade with both legs
/// funded, each party can send the other's leg home at any time before expiry (lock time 0, so
/// valid at any DAA score below `expiry_daa`), and the cancelled party gets its leg back whole.
#[test]
fn a3_earmarked_counterparty_cancels_the_other_leg_before_expiry() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    // The buyer cancels the seller's asset leg.
    let asset = w.refund(ASSET_LEG, Role::Buyer);
    assert_eq!(asset.lock_time, 0);
    assert!(asset.lock_time < EXPIRY_DAA);
    asset.assert_all_accepted(&w, "buyer cancels the asset leg, earmarked, before expiry");
    // The seller cancels the buyer's cash leg.
    let cash = w.refund(CASH_LEG, Role::Seller);
    assert_eq!(cash.lock_time, 0);
    cash.assert_all_accepted(&w, "seller cancels the cash leg, earmarked, before expiry");
    // The depositor itself cannot do the same: its early refund needs lock time at expiry.
    assert_eq!(w.refund(ASSET_LEG, Role::Seller).lock_time, EXPIRY_DAA);
}

#[test]
fn refund_authority_revocable() {
    let w = World::new(AUTH_KCC20);
    w.refund(ASSET_LEG, Role::Authority)
        .assert_all_accepted(&w, "authority, revocable");
}

#[test]
fn refund_authority_earmarked() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    let spec = w.refund(ASSET_LEG, Role::Authority);
    assert_eq!(spec.lock_time, 0, "the authority does not wait for expiry");
    spec.assert_all_accepted(&w, "authority, earmarked, before expiry");
}

// Leg kinds and odd deposits: every UTXO at a vault address goes home whole.

#[test]
fn refund_kas_cash_leg() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    w.refund(CASH_LEG, Role::Buyer)
        .assert_all_accepted(&w, "KAS cash leg, depositor");
}

#[test]
fn refund_kcc20_cash_leg() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    w.refund(CASH_LEG, Role::Seller)
        .assert_all_accepted(&w, "KCC-20 cash leg, counterparty");
}

#[test]
fn refund_self_settling_trade() {
    let w = World::new(Mode::new(false, CASH_KAS, EARMARKED));
    w.refund(ASSET_LEG, Role::Buyer)
        .assert_all_accepted(&w, "no authority, counterparty");
}

#[test]
fn refund_external_cash_asset_leg() {
    let w = World::new(Mode::new(true, CASH_EXTERNAL, EARMARKED));
    w.refund(ASSET_LEG, Role::Authority)
        .assert_all_accepted(&w, "external cash, authority");
}

/// A leg-1 vault derived from external-cash terms is never used, but KAS sent to it still
/// goes home to the buyer.
#[test]
fn refund_external_cash_leg_vault_goes_home() {
    let w = World::new(Mode::new(true, CASH_EXTERNAL, REVOCABLE));
    let leg1 = w.terms.vault(CASH_LEG);
    let spec = TxSpec {
        inputs: vec![
            In::refund(&leg1, w.xonly(Role::Buyer), Role::Buyer, AUTH_VALUE),
            In::plain(FEE_VALUE),
        ],
        outputs: vec![
            Out::kas(AUTH_VALUE, p2pk(w.xonly(Role::Buyer))),
            Out::kas(FEE_VALUE / 2, plain_spk()),
        ],
        lock_time: 0,
    };
    spec.assert_all_accepted(&w, "external-cash leg-1 vault refund");
}

/// The depositor may refund the authorizer alone (no token in the transaction).
#[test]
fn refund_authorizer_without_token_by_depositor() {
    let w = World::new(AUTH_KCC20);
    without_token(w.refund(ASSET_LEG, Role::Seller)).assert_all_accepted(&w, "authorizer only");
}

/// An under-funded escrow (amount_a - 1) cannot settle but the depositor can refund it whole.
#[test]
fn refund_under_funded_escrow_goes_home_whole() {
    let w = World::new(AUTH_KCC20);
    let mut spec = w.refund(ASSET_LEG, Role::Seller);
    let escrow = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A - 1,
    );
    with_asset_escrow(
        &mut spec,
        escrow,
        Kcc20State::new(SELLER_REFUND, AMOUNT_A - 1),
    );
    spec.assert_all_accepted(&w, "escrow of amount_a - 1 refunded whole");
}

/// A minter escrow goes home as a minter.
#[test]
fn refund_minter_escrow_goes_home_as_minter() {
    let w = World::new(AUTH_KCC20);
    let mut spec = w.refund(ASSET_LEG, Role::Buyer);
    let escrow = Kcc20State {
        is_minter: true,
        ..w.asset_escrow_state()
    };
    let home = Kcc20State {
        is_minter: true,
        ..Kcc20State::new(SELLER_REFUND, AMOUNT_A)
    };
    with_asset_escrow(&mut spec, escrow, home);
    spec.assert_all_accepted(&w, "minter escrow refunded as minter");
}

// =============================================================================================
// [R1] [R2] who may refund
// =============================================================================================

#[test]
fn r1_stranger_signer() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::refund(
        &w.asset_vault,
        w.xonly(Role::Stranger),
        Role::Stranger,
        AUTH_VALUE,
    );
    assert_flips(&w, &control, &faulty, 0, "a stranger signs as himself");
}

/// Terms with no authority but a key left in the authority field: that key cannot refund.
/// Same parties and terms as the control except the authority flag.
#[test]
fn r1_authority_key_without_authority_flag() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Authority);
    control.assert_all_accepted(&w, "control: authority set");
    let w = w.edit(|t| t.has_authority = false);
    let faulty = w.refund(ASSET_LEG, Role::Authority);
    assert_refused(&faulty.run(&w, 0), "authority flag cleared, same key signs");
}

#[test]
fn r2_depositor_named_stranger_signs() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::refund(
        &w.asset_vault,
        w.xonly(Role::Seller),
        Role::Stranger,
        AUTH_VALUE,
    );
    assert_flips(&w, &control, &faulty, 0, "seller named, stranger signed");
}

#[test]
fn r2_authority_named_counterparty_signs() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Authority);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::refund(
        &w.asset_vault,
        w.xonly(Role::Authority),
        Role::Buyer,
        AUTH_VALUE,
    );
    assert_flips(&w, &control, &faulty, 0, "authority named, buyer signed");
}

// =============================================================================================
// [R4] [R5] [R6] [R7] the vault UTXO's KAS goes home whole
// =============================================================================================

/// The buyer funded the KAS cash vault twice. Both UTXOs in one refund, one output 0: the
/// second must not be satisfied by the first one's output and leak to the change.
#[test]
fn r4_second_kas_cash_deposit_cannot_refund_off_input_0() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.refund(CASH_LEG, Role::Seller);
    let mut faulty = control.clone();
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::refund(
            w.cash_vault(),
            w.xonly(Role::Seller),
            Role::Seller,
            AMOUNT_B as u64,
        ),
    );
    faulty.outputs.last_mut().expect("change").value += AMOUNT_B as u64;
    assert_flips(
        &w,
        &control,
        &faulty,
        at,
        "second KAS cash UTXO refunded at input 1",
    );
}

#[test]
fn r5_authorizer_kas_short() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    assert_flips(&w, &control, &faulty, 0, "authorizer KAS returned minus 1");
}

#[test]
fn r5_kas_cash_short() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.refund(CASH_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    assert_flips(&w, &control, &faulty, 0, "KAS cash returned minus 1");
}

#[test]
fn r6_kas_cash_to_stranger() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.refund(CASH_LEG, Role::Seller);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    assert_flips(&w, &control, &faulty, 0, "KAS cash refunded to a stranger");
}

#[test]
fn r7_authorizer_kas_to_stranger() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    assert_flips(&w, &control, &faulty, 0, "authorizer KAS to a stranger");
}

#[test]
fn r7_authorizer_kas_to_counterparty() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = p2pk(w.xonly(Role::Buyer));
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "authorizer KAS to the signing counterparty",
    );
}

// =============================================================================================
// [R9] [R10] and the builtin checks: the leg's token is the escrow at input 1 and goes home whole
// =============================================================================================

/// A decoy token (same template, another covenant, owned by this vault: anyone can mint one)
/// sits at input 1 where the refund reads the escrow; the real escrow at input 2 sends one unit
/// home and the rest to a stranger. Depositor-signed, the case only [R9] guards.
#[test]
fn r9_decoy_token_at_input_1_real_escrow_elsewhere() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let one_home = Kcc20State::new(SELLER_REFUND, 1);
    let decoy_home = Kcc20State::new(STRANGER_OWNER, 1);
    let mut real_escrow = control.inputs[1].clone();
    match &mut real_escrow.spend {
        Spend::Kcc20Leader { new_states, .. } => {
            *new_states = vec![one_home, stranger(AMOUNT_A - 1)]
        }
        _ => unreachable!(),
    }
    let faulty = TxSpec {
        inputs: vec![
            control.inputs[0].clone(),
            In::token(
                ASSET_TOKEN.compile(Kcc20State::new(
                    Owner::script_hash(w.asset_vault.script_hash()),
                    1,
                )),
                DECOY_COV,
                vec![decoy_home],
                0,
            ),
            real_escrow,
            control.inputs[2].clone(),
        ],
        outputs: vec![
            control.outputs[0].clone(),
            Out::token(ASSET_TOKEN.compile(one_home), ASSET_COV, 2),
            Out::token(ASSET_TOKEN.compile(stranger(AMOUNT_A - 1)), ASSET_COV, 2),
            Out::token(ASSET_TOKEN.compile(decoy_home), DECOY_COV, 1),
            control.outputs[2].clone(),
        ],
        lock_time: control.lock_time,
    };
    assert_accepted(&faulty.run(&w, 2), "the real escrow transfer is valid");
    assert_accepted(&faulty.run(&w, 1), "the decoy transfer is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "decoy token read in place of the escrow",
    );
}

/// The real escrow is at input 1, but output 1 is a decoy token (same template, same home
/// state, another covenant) while the real asset goes to a stranger.
#[test]
fn r10_home_output_under_decoy_covenant() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let home = Kcc20State::new(SELLER_REFUND, AMOUNT_A);
    *leader_states(&mut faulty, 1) = vec![stranger(AMOUNT_A)];
    let at = fee_idx(&faulty);
    faulty.inputs.insert(
        at,
        In::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            DECOY_COV,
            vec![home],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(home), DECOY_COV, at as u16);
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger(AMOUNT_A)), ASSET_COV, 1),
    );
    assert_accepted(&faulty.run(&w, 1), "the real escrow transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "home output under a decoy covenant",
    );
}

#[test]
fn refund_home_output_wrong_owner_type() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_state();
    let wrong = Kcc20State::new(Owner::script_hash(SELLER_REFUND.id), AMOUNT_A);
    with_asset_escrow(&mut faulty, escrow, wrong);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "home output owner type differs");
}

#[test]
fn refund_minter_escrow_cannot_lose_its_minter_flag() {
    let w = World::new(AUTH_KCC20);
    let escrow = Kcc20State {
        is_minter: true,
        ..w.asset_escrow_state()
    };
    let mut control = w.refund(ASSET_LEG, Role::Buyer);
    with_asset_escrow(
        &mut control,
        escrow,
        Kcc20State {
            is_minter: true,
            ..Kcc20State::new(SELLER_REFUND, AMOUNT_A)
        },
    );
    let mut faulty = control.clone();
    with_asset_escrow(
        &mut faulty,
        escrow,
        Kcc20State::new(SELLER_REFUND, AMOUNT_A),
    );
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "minter escrow returned as non-minter",
    );
}

#[test]
fn refund_escrow_sigscript_claims_a_state_its_utxo_does_not_hold() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let real = ASSET_TOKEN.compile(Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A + 5,
    ));
    faulty.inputs[1].spk = real.p2sh();
    assert_flips(&w, &control, &faulty, 0, "forged escrow state in a refund");
}

#[test]
fn refund_escrow_under_another_template() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let other = Token {
        max_cov_ins: 3,
        ..ASSET_TOKEN
    };
    let home = Kcc20State::new(SELLER_REFUND, AMOUNT_A);
    faulty.inputs[1] = In::token(
        other.compile(w.asset_escrow_state()),
        ASSET_COV,
        vec![home],
        0,
    );
    faulty.outputs[1] = Out::token(other.compile(home), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &faulty, 0, "escrow runs another template");
}

// =============================================================================================
// [R13] the escrowed token carries at least its own KAS home
// =============================================================================================

#[test]
fn r13_token_carrier_kas_short() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "token output carries one sompi less",
    );
}

// =============================================================================================
// [R11] a counterparty or authority refund of a KCC-20 leg takes the escrowed token with it
// =============================================================================================

fn assert_token_required(w: &World, leg: i64, signer: Role, label: &str) {
    let control = w.refund(leg, signer);
    let faulty = without_token(control.clone());
    assert_flips(w, &control, &faulty, 0, label);
}

#[test]
fn r11_counterparty_cannot_refund_asset_authorizer_without_token() {
    let w = World::new(AUTH_KCC20);
    assert_token_required(
        &w,
        ASSET_LEG,
        Role::Buyer,
        "buyer refunds the asset authorizer alone",
    );
}

#[test]
fn r11_authority_cannot_refund_asset_authorizer_without_token() {
    let w = World::new(AUTH_KCC20);
    assert_token_required(
        &w,
        ASSET_LEG,
        Role::Authority,
        "authority refunds the asset authorizer alone",
    );
}

#[test]
fn r11_counterparty_cannot_refund_cash_authorizer_without_token() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    assert_token_required(
        &w,
        CASH_LEG,
        Role::Seller,
        "seller refunds the cash authorizer alone",
    );
}

#[test]
fn r11_authority_cannot_refund_cash_authorizer_without_token() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    assert_token_required(
        &w,
        CASH_LEG,
        Role::Authority,
        "authority refunds the cash authorizer alone",
    );
}

// =============================================================================================
// [R12] the token in a refund is this vault's escrow
// =============================================================================================

/// The buyer satisfies [R11] and [R14] with a token of the asset covenant that he controls
/// (owned by a plain script, witnessed by the fee input, holding the full leg amount), sent to
/// the seller's refund owner, while the real escrow stays behind without its authorizer.
#[test]
fn r12_counterparty_cannot_substitute_a_foreign_token() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let home = Kcc20State::new(SELLER_REFUND, AMOUNT_A);
    let fee = fee_idx(&faulty) as u8;
    faulty.inputs[1] = In::token(
        ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
        ASSET_COV,
        vec![home],
        fee,
    );
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
    assert_accepted(
        &faulty.run(&w, 1),
        "the foreign KCC-20 transfer itself is valid",
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "foreign token in place of the escrow",
    );
}

// =============================================================================================
// [R14] outside the depositor's refund, the token holds exactly the leg amount
// =============================================================================================

/// A token of the leg covenant owned by this vault (anyone holding `amount` units can make one)
/// at input 1, the real escrow left out and stranded, refunded by a non-depositor.
fn decoy_refund(w: &World, leg: i64, signer: Role, amount: i64) -> (TxSpec, TxSpec) {
    let control = w.refund(leg, signer);
    let (token, vault, home_owner) = if leg == ASSET_LEG {
        (ASSET_TOKEN, &w.asset_vault, w.terms.seller_refund)
    } else {
        (CASH_TOKEN, w.cash_vault(), w.terms.buyer_refund)
    };
    let decoy = Kcc20State::new(Owner::script_hash(vault.script_hash()), amount);
    let home = Kcc20State::new(home_owner, amount);
    let mut faulty = control.clone();
    faulty.inputs[1] = In::token(token.compile(decoy), token.cov, vec![home], 0);
    faulty.outputs[1] = Out::token(token.compile(home), token.cov, 1);
    assert_accepted(
        &faulty.run(w, 1),
        "the decoy KCC-20 transfer itself is valid",
    );
    (control, faulty)
}

fn assert_decoy_refused(w: &World, leg: i64, signer: Role, amount: i64, label: &str) {
    let (control, faulty) = decoy_refund(w, leg, signer, amount);
    assert_flips(w, &control, &faulty, 0, label);
}

#[test]
fn r14_asset_decoy_amount_0() {
    let w = World::new(AUTH_KCC20);
    assert_decoy_refused(
        &w,
        ASSET_LEG,
        Role::Buyer,
        0,
        "asset leg, vault-owned decoy of 0",
    );
}

#[test]
fn r14_asset_decoy_amount_1() {
    let w = World::new(AUTH_KCC20);
    assert_decoy_refused(
        &w,
        ASSET_LEG,
        Role::Buyer,
        1,
        "asset leg, vault-owned decoy of 1",
    );
}

#[test]
fn r14_asset_decoy_amount_leg_minus_1() {
    let w = World::new(AUTH_KCC20);
    let label = "asset leg, vault-owned decoy of amount_a - 1";
    assert_decoy_refused(&w, ASSET_LEG, Role::Buyer, AMOUNT_A - 1, label);
}

#[test]
fn r14_asset_decoy_amount_0_by_authority() {
    let w = World::new(AUTH_KCC20);
    let label = "asset leg, authority, vault-owned decoy of 0";
    assert_decoy_refused(&w, ASSET_LEG, Role::Authority, 0, label);
}

#[test]
fn r14_cash_decoy_amount_0() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    assert_decoy_refused(
        &w,
        CASH_LEG,
        Role::Seller,
        0,
        "cash leg, vault-owned decoy of 0",
    );
}

#[test]
fn r14_cash_decoy_amount_1() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    assert_decoy_refused(
        &w,
        CASH_LEG,
        Role::Seller,
        1,
        "cash leg, vault-owned decoy of 1",
    );
}

#[test]
fn r14_cash_decoy_amount_leg_minus_1() {
    let w = World::new(AUTH_KCC20_EARMARKED);
    let label = "cash leg, vault-owned decoy of amount_b - 1";
    assert_decoy_refused(&w, CASH_LEG, Role::Seller, AMOUNT_B - 1, label);
}

/// The real escrow, under-funded: only its depositor can refund it.
#[test]
fn r14_counterparty_cannot_refund_under_funded_escrow() {
    let w = World::new(AUTH_KCC20);
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    let escrow = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A - 1,
    );
    with_asset_escrow(
        &mut faulty,
        escrow,
        Kcc20State::new(SELLER_REFUND, AMOUNT_A - 1),
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "counterparty refunds amount_a - 1",
    );
}

/// Accepted residual, pinned: a decoy holding the full leg amount still refunds the authorizer,
/// but it pays the depositor the whole leg, and the stranded escrow stays the depositor's to
/// refund with a new authorizer.
#[test]
fn r14_decoy_of_the_full_leg_amount_pays_the_depositor() {
    let w = World::new(AUTH_KCC20);
    let (_, decoy) = decoy_refund(&w, ASSET_LEG, Role::Buyer, AMOUNT_A);
    decoy.assert_all_accepted(&w, "full-amount decoy goes home to the seller");
}
