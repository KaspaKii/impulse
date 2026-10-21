// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseHashlock `refund` in the real engine (I18, spec/V2.md sections 10.4 and 11.3): v1's
//! asset-leg refund without the authority and always earmarked. The seller's refund opens at
//! expiry_daa; the buyer may send the asset home at any time, with the token. One refusal test
//! per refund-side require, each against an accepted control that differs only in the one
//! fault; test names start with the require ID ([HR1] etc. in contracts/impulse_hashlock.sil).

mod harness;
mod htlc_harness;
use harness::*;
use htlc_harness::*;
use kaspa_txscript::{LOCK_TIME_THRESHOLD, MAX_TX_IN_SEQUENCE_NUM};

/// The same refund with the escrowed token (input 1, output 1) left out.
fn without_token(mut spec: HtlcTx) -> HtlcTx {
    spec.inputs.remove(1);
    spec.outputs.remove(1);
    spec
}

/// The escrow at input 1 replaced by `escrow`, returning home as `home` at output 1.
fn with_escrow(spec: &mut HtlcTx, escrow: Kcc20State, home: Kcc20State) {
    spec.inputs[1] = HIn::token(ASSET_TOKEN.compile(escrow), ASSET_COV, vec![home], 0);
    spec.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
}

fn vault_owned(w: &HtlcWorld, amount: i64) -> Kcc20State {
    Kcc20State::new(Owner::script_hash(w.vault.script_hash()), amount)
}

fn home(amount: i64) -> Kcc20State {
    Kcc20State::new(SELLER_REFUND, amount)
}

// =============================================================================================
// Passing
// =============================================================================================

/// Refund after the timeout: the seller's refund at expiry_daa and after it.
#[test]
fn seller_refund_at_and_after_expiry() {
    let w = HtlcWorld::new();
    for lock_time in [EXPIRY_DAA, EXPIRY_DAA + 1, EXPIRY_DAA * 2] {
        let mut spec = w.refund(Role::Seller);
        spec.lock_time = lock_time;
        spec.assert_all_accepted(&w, &format!("seller at lock time {lock_time}"));
    }
}

/// The buyer can end the option early: its refund needs no lock time (spec section 10.6, R12).
#[test]
fn buyer_refund_at_any_time() {
    let w = HtlcWorld::new();
    let mut spec = w.refund(Role::Buyer);
    assert_eq!(spec.lock_time, 0);
    spec.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    spec.assert_all_accepted(&w, "buyer, lock time 0, finalized input");
    let mut later = w.refund(Role::Buyer);
    later.lock_time = EXPIRY_DAA + 1;
    later.assert_all_accepted(&w, "buyer after expiry");
}

/// The seller may refund the authorizer alone (no token in the transaction) after expiry.
#[test]
fn seller_refund_of_the_authorizer_alone() {
    let w = HtlcWorld::new();
    without_token(w.refund(Role::Seller)).assert_all_accepted(&w, "authorizer only");
}

/// Review round 5 (spec/V2.md section 10.6, R15): what the seller's authorizer-only refund
/// after expiry leaves behind. Pinned, not a defect of the script: the claim-lead margin is the
/// buyer's only protection against it.
/// 1. The refund of the authorizer alone is accepted after expiry (no token in the transaction).
/// 2. The escrow, still owned by the vault's script hash, cannot move without an input at the
///    vault's address: a claim with a plain input in place of the authorizer is refused by the
///    token's own template.
/// 3. The token is not destroyed: any new UTXO paid to the vault's address (here of another
///    value) authorizes the claim with the secret, its KAS going to the seller (`[HS8]`, `[HS9]`).
/// 4. The same new UTXO equally authorizes the seller's refund of the token after expiry, so
///    after expiry the first accepted transaction wins, as for R4.
#[test]
fn seller_authorizer_only_refund_after_expiry_leaves_a_race() {
    let w = HtlcWorld::new();
    let mut alone = without_token(w.refund(Role::Seller));
    alone.lock_time = EXPIRY_DAA + 1;
    alone.assert_all_accepted(&w, "1: authorizer alone after expiry");

    let fresh = AUTH_VALUE / 2;
    let mut no_authorizer = w.claim(&SECRET);
    no_authorizer.inputs[0] = HIn::plain(AUTH_VALUE);
    no_authorizer.outputs[1].spk = plain_spk();
    assert_refused(
        &no_authorizer.run(&w, 1),
        "2: escrow claimed with no input at the vault's address",
    );

    let mut claim = w.claim(&SECRET);
    claim.inputs[0] = HIn::claim(&w.vault, &SECRET, fresh);
    claim.outputs[1].value = fresh;
    claim.assert_all_accepted(&w, "3: claim through a new UTXO at the vault's address");

    let mut refund = w.refund(Role::Seller);
    refund.inputs[0] = HIn::refund(&w.vault, w.xonly(Role::Seller), Role::Seller, fresh);
    refund.outputs[0].value = fresh;
    refund.assert_all_accepted(&w, "4: seller refund through the same new UTXO");
}

/// An under-funded escrow cannot be claimed, but the seller can refund it whole.
#[test]
fn seller_refund_of_an_under_funded_escrow() {
    let w = HtlcWorld::new();
    let mut spec = w.refund(Role::Seller);
    with_escrow(&mut spec, vault_owned(&w, AMOUNT_A - 1), home(AMOUNT_A - 1));
    spec.assert_all_accepted(&w, "escrow of amount - 1 refunded whole");
}

/// A minter escrow goes home as a minter.
#[test]
fn minter_escrow_goes_home_as_minter() {
    let w = HtlcWorld::new();
    let mut spec = w.refund(Role::Buyer);
    let escrow = Kcc20State {
        is_minter: true,
        ..w.escrow_state()
    };
    let minter_home = Kcc20State {
        is_minter: true,
        ..home(AMOUNT_A)
    };
    with_escrow(&mut spec, escrow, minter_home);
    spec.assert_all_accepted(&w, "minter escrow refunded as minter");
}

// =============================================================================================
// [HR1] [HR2] who may refund
// =============================================================================================

#[test]
fn hr1_stranger_signer() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = HIn::refund(
        &w.vault,
        w.xonly(Role::Stranger),
        Role::Stranger,
        AUTH_VALUE,
    );
    assert_htlc_flips(&w, &control, &faulty, 0, "a stranger signs as himself");
}

/// There is no authority on the hashlock template: a key the v1 terms would call the authority
/// is just a stranger.
#[test]
fn hr1_no_authority() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = HIn::refund(
        &w.vault,
        w.xonly(Role::Authority),
        Role::Authority,
        AUTH_VALUE,
    );
    assert_htlc_flips(&w, &control, &faulty, 0, "a would-be authority signs");
}

#[test]
fn hr2_seller_named_stranger_signs() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.inputs[0] = HIn::refund(&w.vault, w.xonly(Role::Seller), Role::Stranger, AUTH_VALUE);
    assert_htlc_flips(&w, &control, &faulty, 0, "seller named, stranger signed");
}

/// The seller names the buyer's key to dodge the earmark, but cannot sign for it.
#[test]
fn hr2_seller_cannot_pose_as_the_buyer_before_expiry() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[0] = HIn::refund(&w.vault, w.xonly(Role::Buyer), Role::Seller, AUTH_VALUE);
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "buyer named, seller signed, lock time 0",
    );
}

// =============================================================================================
// [HR3] always earmarked: the seller's refund not before expiry_daa
// =============================================================================================

#[test]
fn hr3_seller_refund_one_daa_before_expiry() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.lock_time = EXPIRY_DAA - 1;
    assert_htlc_flips_locktime(&w, &control, &faulty, 0, "seller at expiry - 1");
}

#[test]
fn hr3_seller_refund_at_lock_time_0() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.lock_time = 0;
    assert_htlc_flips_locktime(&w, &control, &faulty, 0, "seller at lock time 0");
}

/// A finalized input makes consensus ignore the lock time, so CLTV refuses it.
#[test]
fn hr3_seller_refund_with_finalized_input() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    assert_htlc_flips_locktime(&w, &control, &faulty, 0, "seller, finalized input");
}

/// A timestamp-domain lock time can never satisfy a DAA-score bound.
#[test]
fn hr3_seller_refund_with_timestamp_lock_time() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.lock_time = LOCK_TIME_THRESHOLD + EXPIRY_DAA;
    assert_htlc_flips_locktime(&w, &control, &faulty, 0, "timestamp-domain lock time");
}

/// The seller's refund of the authorizer alone is earmarked too.
#[test]
fn hr3_seller_authorizer_alone_before_expiry() {
    let w = HtlcWorld::new();
    let control = without_token(w.refund(Role::Seller));
    let mut faulty = control.clone();
    faulty.lock_time = EXPIRY_DAA - 1;
    assert_htlc_flips_locktime(&w, &control, &faulty, 0, "authorizer alone at expiry - 1");
}

// =============================================================================================
// [HR4] [HR5] [HR7] the vault UTXO's KAS goes home whole
// =============================================================================================

/// Two UTXOs at the vault address in one refund, one output 0: the second must not be
/// satisfied by the first one's output and leak to the change.
#[test]
fn hr4_second_vault_utxo_cannot_refund_off_input_0() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    let at = faulty.fee_idx();
    faulty.inputs.insert(
        at,
        HIn::refund(&w.vault, w.xonly(Role::Buyer), Role::Buyer, AUTH_VALUE),
    );
    faulty.outputs.last_mut().expect("change").value += AUTH_VALUE;
    assert_accepted(&faulty.run(&w, 0), "the vault at input 0 is satisfied");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        at,
        "second vault UTXO refunded at input 2",
    );
}

#[test]
fn hr5_authorizer_kas_short() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS returned minus 1");
}

#[test]
fn hr5_authorizer_kas_over() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].value += 1;
    faulty.outputs.last_mut().expect("change").value -= 1;
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS returned plus 1");
}

#[test]
fn hr7_authorizer_kas_to_stranger() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS to a stranger");
}

#[test]
fn hr7_authorizer_kas_to_the_buyer() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = p2pk(w.xonly(Role::Buyer));
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "authorizer KAS to the signing buyer",
    );
}

// =============================================================================================
// [HR11] the buyer's refund takes the escrowed token with it
// =============================================================================================

#[test]
fn hr11_buyer_cannot_refund_the_authorizer_without_the_token() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let faulty = without_token(control.clone());
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "buyer refunds the authorizer alone",
    );
}

// =============================================================================================
// [HR8] [HR9] [HR10] [HR12] [HR13] and the builtins: the token is this vault's escrow at
// input 1 and goes home whole
// =============================================================================================

/// A second deposit of the asset at the vault address rides a seller refund as a KCC-20
/// delegate; one goes home, the other to a stranger.
#[test]
fn hr8_second_escrow_deposit_cannot_ride_along_a_seller_refund() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    faulty.inputs.insert(
        2,
        HIn::token_delegate(ASSET_TOKEN.compile(w.escrow_state()), ASSET_COV, 0),
    );
    faulty.inputs[1].leader_states().push(stranger(AMOUNT_A));
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger(AMOUNT_A)), ASSET_COV, 1),
    );
    assert_accepted(&faulty.run(&w, 1), "KCC-20 leader is valid");
    assert_accepted(&faulty.run(&w, 2), "KCC-20 delegate is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a seller refund",
    );
}

/// A decoy token (same template, another covenant, owned by this vault: anyone can make one)
/// sits at input 1 where the refund reads the escrow; the real escrow at input 2 sends one unit
/// home and the rest to a stranger. Seller-signed, the case only [HR9] guards.
#[test]
fn hr9_decoy_token_at_input_1_real_escrow_elsewhere() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let one_home = home(1);
    let decoy_home = Kcc20State::new(STRANGER_OWNER, 1);
    let mut real_escrow = control.inputs[1].clone();
    *real_escrow.leader_states() = vec![one_home, stranger(AMOUNT_A - 1)];
    let faulty = HtlcTx {
        inputs: vec![
            control.inputs[0].clone(),
            HIn::token(
                ASSET_TOKEN.compile(vault_owned(&w, 1)),
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
    assert_htlc_flips(
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
fn hr10_home_output_under_decoy_covenant() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    let home = home(AMOUNT_A);
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
    let at = faulty.fee_idx();
    faulty.inputs.insert(
        at,
        HIn::token(
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
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "home output under a decoy covenant",
    );
}

/// The buyer satisfies [HR11] and [HR14] with a token of the asset covenant that it controls
/// (owned by a plain script, witnessed by the fee input, holding the full amount), sent to the
/// seller's refund owner, while the real escrow stays behind without its authorizer.
#[test]
fn hr12_buyer_cannot_substitute_a_foreign_token() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    let fee = faulty.fee_idx() as u8;
    faulty.inputs[1] = HIn::token(
        ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
        ASSET_COV,
        vec![home(AMOUNT_A)],
        fee,
    );
    assert_accepted(
        &faulty.run(&w, 1),
        "the foreign KCC-20 transfer itself is valid",
    );
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "foreign token in place of the escrow",
    );
}

#[test]
fn hr13_token_carrier_kas_short() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "token output carries one sompi less",
    );
}

#[test]
fn refund_cannot_send_the_escrow_to_a_stranger() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(stranger(AMOUNT_A)), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund routes the escrow to a stranger",
    );
}

/// The escrow cannot go to the buyer's delivery owner through a refund.
#[test]
fn refund_cannot_send_the_escrow_to_the_buyer() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    *faulty.inputs[1].leader_states() = vec![w.delivered()];
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(w.delivered()), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund delivers to the buyer without the secret",
    );
}

#[test]
fn refund_cannot_split_the_escrow() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    *faulty.inputs[1].leader_states() = vec![home(AMOUNT_A - 1), stranger(1)];
    faulty.outputs[1] = Out::token(ASSET_TOKEN.compile(home(AMOUNT_A - 1)), ASSET_COV, 1);
    faulty.outputs.insert(
        2,
        Out::token(ASSET_TOKEN.compile(stranger(1)), ASSET_COV, 1),
    );
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "refund sends one unit away");
}

#[test]
fn refund_home_output_wrong_owner_type() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Seller);
    let mut faulty = control.clone();
    let wrong = Kcc20State::new(Owner::script_hash(SELLER_REFUND.id), AMOUNT_A);
    with_escrow(&mut faulty, w.escrow_state(), wrong);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "home output owner type differs");
}

#[test]
fn refund_minter_escrow_cannot_lose_its_minter_flag() {
    let w = HtlcWorld::new();
    let escrow = Kcc20State {
        is_minter: true,
        ..w.escrow_state()
    };
    let mut control = w.refund(Role::Buyer);
    with_escrow(
        &mut control,
        escrow,
        Kcc20State {
            is_minter: true,
            ..home(AMOUNT_A)
        },
    );
    let mut faulty = control.clone();
    with_escrow(&mut faulty, escrow, home(AMOUNT_A));
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "minter escrow returned as non-minter",
    );
}

#[test]
fn refund_escrow_sigscript_claims_a_state_its_utxo_does_not_hold() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    faulty.inputs[1].spk = ASSET_TOKEN.compile(vault_owned(&w, AMOUNT_A + 5)).p2sh();
    assert_htlc_flips(&w, &control, &faulty, 0, "forged escrow state in a refund");
}

#[test]
fn refund_escrow_under_another_template() {
    let w = HtlcWorld::new();
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    let other = Token {
        max_cov_ins: 3,
        ..ASSET_TOKEN
    };
    faulty.inputs[1] = HIn::token(
        other.compile(w.escrow_state()),
        ASSET_COV,
        vec![home(AMOUNT_A)],
        0,
    );
    faulty.outputs[1] = Out::token(other.compile(home(AMOUNT_A)), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow runs another template");
}

// =============================================================================================
// [HR14] in the buyer's refund, the token holds exactly the amount
// =============================================================================================

/// A token of the asset covenant owned by this vault (anyone holding `amount` units can make
/// one) at input 1, the real escrow left out and stranded, refunded by the buyer.
fn decoy_refund(w: &HtlcWorld, amount: i64) -> (HtlcTx, HtlcTx) {
    let control = w.refund(Role::Buyer);
    let mut faulty = control.clone();
    with_escrow(&mut faulty, vault_owned(w, amount), home(amount));
    assert_accepted(
        &faulty.run(w, 1),
        "the decoy KCC-20 transfer itself is valid",
    );
    (control, faulty)
}

#[test]
fn hr14_decoy_amount_0() {
    let w = HtlcWorld::new();
    let (control, faulty) = decoy_refund(&w, 0);
    assert_htlc_flips(&w, &control, &faulty, 0, "vault-owned decoy of 0");
}

#[test]
fn hr14_decoy_amount_1() {
    let w = HtlcWorld::new();
    let (control, faulty) = decoy_refund(&w, 1);
    assert_htlc_flips(&w, &control, &faulty, 0, "vault-owned decoy of 1");
}

#[test]
fn hr14_decoy_amount_minus_1() {
    let w = HtlcWorld::new();
    let (control, faulty) = decoy_refund(&w, AMOUNT_A - 1);
    assert_htlc_flips(&w, &control, &faulty, 0, "vault-owned decoy of amount - 1");
}

/// Over the amount too: the buyer's refund takes exactly the escrow home.
#[test]
fn hr14_decoy_amount_plus_1() {
    let w = HtlcWorld::new();
    let (control, faulty) = decoy_refund(&w, AMOUNT_A + 1);
    assert_htlc_flips(&w, &control, &faulty, 0, "vault-owned token of amount + 1");
}

/// Accepted residual, pinned: a decoy holding the full amount still refunds the authorizer, but
/// it pays the seller the whole amount, and the stranded escrow stays the seller's to refund
/// with a new authorizer after expiry.
#[test]
fn hr14_decoy_of_the_full_amount_pays_the_seller() {
    let w = HtlcWorld::new();
    let (_, decoy) = decoy_refund(&w, AMOUNT_A);
    decoy.assert_all_accepted(&w, "full-amount decoy goes home to the seller");
}
