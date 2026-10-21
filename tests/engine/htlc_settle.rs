// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseHashlock `settleWithPreimage` in the real engine (I18, spec/V2.md sections 10.4 and
//! 11.3). The canonical claim with the right preimage settles; then one refusal test per
//! claim-side require, each against an accepted control that differs only in the one fault.
//! Test names start with the require ID they exercise ([H1] etc. in
//! contracts/impulse_hashlock.sil); tests/engine/htlc_mutation.py checks the mapping. The claim
//! after expiry_daa is accepted by design and pinned here (spec section 10.6, R4).

mod harness;
mod htlc_harness;
use harness::*;
use htlc_harness::sha256;
use htlc_harness::*;
use kaspa_txscript::MAX_TX_IN_SEQUENCE_NUM;

/// Replaces the asset delivered at output 0 (and the escrow transfer's new states) by `states`;
/// states after the first become extra asset outputs at the end.
fn deliver(spec: &mut HtlcTx, states: &[Kcc20State]) {
    *spec.inputs[1].leader_states() = states.to_vec();
    spec.outputs[0] = Out::token(ASSET_TOKEN.compile(states[0]), ASSET_COV, 1);
    for s in &states[1..] {
        spec.outputs
            .push(Out::token(ASSET_TOKEN.compile(*s), ASSET_COV, 1));
    }
}

/// Replaces the escrowed asset token (its UTXO script and the redeem it carries), keeping its
/// covenant and its transfer's new states.
fn set_escrow(spec: &mut HtlcTx, token: Token, state: Kcc20State) {
    let new_states = spec.inputs[1].leader_states().clone();
    let cov = spec.inputs[1].cov;
    spec.inputs[1] = HIn::token(token.compile(state), ASSET_COV, new_states, 0);
    spec.inputs[1].cov = cov;
}

fn vault_owned(w: &HtlcWorld, amount: i64) -> Kcc20State {
    Kcc20State::new(Owner::script_hash(w.vault.script_hash()), amount)
}

// =============================================================================================
// Passing
// =============================================================================================

/// The right preimage settles: every input of the canonical claim is accepted. No signature is
/// in the claim, so whoever holds the secret can submit this same transaction.
#[test]
fn claim_with_the_right_preimage() {
    let w = HtlcWorld::new();
    w.claim(&SECRET)
        .assert_all_accepted(&w, "right preimage, canonical claim");
}

/// The claim has no lock-time check: lock time 0 with finalized inputs is accepted.
#[test]
fn claim_needs_no_lock_time() {
    let w = HtlcWorld::new();
    let mut spec = w.claim(&SECRET);
    for i in &mut spec.inputs {
        i.sequence = MAX_TX_IN_SEQUENCE_NUM;
    }
    spec.assert_all_accepted(&w, "lock time 0, finalized inputs");
}

/// Pinned (spec/V2.md section 10.4 and 10.6, R4): the script has only "at least" lock times, so
/// the claim cannot be forbidden after expiry_daa. A claim at and after expiry is accepted; the
/// seller's refund is valid from the same point (htlc_refund.rs), and the first accepted wins.
#[test]
fn claim_after_expiry_is_accepted() {
    let w = HtlcWorld::new();
    for lock_time in [EXPIRY_DAA, EXPIRY_DAA + 1, EXPIRY_DAA * 2] {
        let mut spec = w.claim(&SECRET);
        spec.lock_time = lock_time;
        spec.assert_all_accepted(&w, &format!("claim at lock time {lock_time}"));
    }
}

/// Outputs carry at least, not exactly, the KAS of the inputs they stand for.
#[test]
fn claim_outputs_may_carry_more_kas() {
    let w = HtlcWorld::new();
    let mut spec = w.claim(&SECRET);
    spec.outputs[0].value += 1;
    spec.outputs[1].value += 1;
    spec.outputs[2].value -= 2;
    spec.assert_all_accepted(&w, "delivery and return carry more KAS");
}

// =============================================================================================
// [H1] canonical position
// =============================================================================================

/// The seller funded the vault address twice (two authorizer UTXOs). Both in one claim: the
/// second must not be satisfied by the first one's output 1 while its KAS goes to change.
#[test]
fn h1_second_vault_utxo_cannot_claim_off_input_0() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let at = faulty.fee_idx();
    faulty
        .inputs
        .insert(at, HIn::claim(&w.vault, &SECRET, AUTH_VALUE));
    faulty.outputs.last_mut().expect("change").value += AUTH_VALUE;
    assert_accepted(&faulty.run(&w, 0), "the vault at input 0 is satisfied");
    assert_htlc_flips(&w, &control, &faulty, at, "second vault UTXO at input 2");
}

// =============================================================================================
// [H2] [H3] the preimage
// =============================================================================================

/// Terms whose hash_lock is sha256 of a secret of `len` bytes, claimed with that secret: only
/// the length check can refuse it. The control is the canonical 32-byte claim.
fn assert_length_refused(len: usize) {
    let w = HtlcWorld::new();
    w.claim(&SECRET)
        .assert_all_accepted(&w, "control, 32-byte secret");
    let secret = vec![0x5C; len];
    let w = w.edit(|t| t.hash_lock = sha256(&secret));
    let faulty = w.claim(&secret);
    assert_refused(&faulty.run(&w, 0), &format!("secret of {len} bytes"));
}

#[test]
fn h2_secret_of_31_bytes() {
    assert_length_refused(31);
}

#[test]
fn h2_secret_of_33_bytes() {
    assert_length_refused(33);
}

#[test]
fn h2_empty_secret() {
    assert_length_refused(0);
}

#[test]
fn h2_secret_of_64_bytes() {
    assert_length_refused(64);
}

#[test]
fn h3_wrong_secret() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let faulty = w.claim(&WRONG_SECRET);
    assert_htlc_flips(&w, &control, &faulty, 0, "wrong 32-byte secret");
}

/// The hash lock itself (public in the terms) is not a preimage of itself.
#[test]
fn h3_hash_lock_as_secret() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let faulty = w.claim(&w.terms.hash_lock);
    assert_htlc_flips(&w, &control, &faulty, 0, "hash_lock offered as the secret");
}

/// One bit off.
#[test]
fn h3_secret_one_bit_off() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut secret = SECRET;
    secret[31] ^= 0x01;
    let faulty = w.claim(&secret);
    assert_htlc_flips(&w, &control, &faulty, 0, "secret with its last bit flipped");
}

// =============================================================================================
// [HE1]..[HE6] the escrow holds exactly the amount
// =============================================================================================

/// A second deposit of the asset at the vault address rides along as a KCC-20 delegate, and the
/// escrow transfer sends an extra amount to a stranger. Both KCC-20 inputs are valid.
#[test]
fn he1_second_escrow_deposit_cannot_ride_along() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let at = faulty.fee_idx();
    faulty.inputs.insert(
        at,
        HIn::token_delegate(ASSET_TOKEN.compile(w.escrow_state()), ASSET_COV, 0),
    );
    faulty.inputs[1].leader_states().push(stranger(AMOUNT_A));
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "KCC-20 leader is valid");
    assert_accepted(&faulty.run(&w, at), "KCC-20 delegate is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "second asset deposit rides a claim",
    );
}

/// Escrowed token UTXO with no covenant binding, nothing of the asset covenant in the tx.
#[test]
fn he1_escrow_without_covenant_binding() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.inputs[1].cov = None;
    faulty.outputs[0].cov = None;
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow carries no covenant ID");
}

/// Escrow under another covenant (same template, same state) while a real asset token elsewhere
/// supplies output 0: the escrowed asset would go to a stranger. Every KCC-20 transfer here is
/// valid; only the vault refuses.
#[test]
fn he2_escrow_under_another_covenant_real_asset_elsewhere() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.inputs[1].cov = Some(DECOY_COV);
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
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
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        DECOY_COV,
        1,
    ));
    assert_accepted(
        &faulty.run(&w, 1),
        "decoy-covenant escrow transfer is valid",
    );
    assert_accepted(&faulty.run(&w, at), "the real asset transfer is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow under another covenant");
}

#[test]
fn he3_escrow_owner_type_pubkey() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::pubkey(w.vault.script_hash()), AMOUNT_A);
    set_escrow(&mut faulty, ASSET_TOKEN, state);
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow owner type is PUBKEY");
}

#[test]
fn he4_escrow_owned_by_another_vault() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let mut other = w.terms.clone();
    other.nonce = [0x01; 8];
    let state = Kcc20State::new(Owner::script_hash(other.vault().script_hash()), AMOUNT_A);
    set_escrow(&mut faulty, ASSET_TOKEN, state);
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "escrow owned by another hashlock vault",
    );
}

#[test]
fn he5_escrow_over_funded() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    set_escrow(&mut faulty, ASSET_TOKEN, vault_owned(&w, AMOUNT_A + 1));
    deliver(&mut faulty, &[w.delivered(), stranger(1)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow holds amount + 1");
}

/// Escrow holds amount - 1 while output 0 still shows the amount; the vault input is judged alone.
#[test]
fn he5_escrow_under_funded() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    set_escrow(&mut faulty, ASSET_TOKEN, vault_owned(&w, AMOUNT_A - 1));
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow holds amount - 1");
}

/// A minter escrow: the buyer still receives a plain amount, but the minting right would go to a
/// stranger output the claimer adds. The KCC-20 transfer itself is valid.
#[test]
fn he6_minter_escrow_cannot_hand_minting_to_a_stranger() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let minter = Kcc20State {
        is_minter: true,
        ..w.escrow_state()
    };
    set_escrow(&mut faulty, ASSET_TOKEN, minter);
    let stranger_minter = Kcc20State {
        is_minter: true,
        ..stranger(0)
    };
    deliver(&mut faulty, &[w.delivered(), stranger_minter]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow is a minter");
}

// Template reads (builtin readInputStateWithTemplate, not a require): the escrow must run the
// pinned template, at the pinned prefix and suffix lengths, and hold the state it claims.

#[test]
fn escrow_under_another_template() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let other = Token {
        max_cov_ins: 3,
        ..ASSET_TOKEN
    };
    set_escrow(&mut faulty, other, w.escrow_state());
    faulty.outputs[0] = Out::token(other.compile(w.delivered()), ASSET_COV, 1);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "escrow runs another template");
}

#[test]
fn escrow_sigscript_claims_a_state_its_utxo_does_not_hold() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.inputs[1].spk = ASSET_TOKEN.compile(vault_owned(&w, AMOUNT_A + 5)).p2sh();
    assert_htlc_flips(&w, &control, &faulty, 0, "forged escrow state");
}

#[test]
fn escrow_read_with_wrong_prefix_len() {
    let w = HtlcWorld::new();
    w.claim(&SECRET)
        .assert_all_accepted(&w, "control, correct lengths");
    let bad = w.edit(|t| {
        t.asset.prefix_len += 1;
        t.asset.suffix_len -= 1;
    });
    assert_refused(
        &bad.claim(&SECRET).run(&bad, 0),
        "prefix length + 1, suffix length - 1",
    );
}

#[test]
fn escrow_read_with_wrong_suffix_len() {
    let w = HtlcWorld::new();
    w.claim(&SECRET)
        .assert_all_accepted(&w, "control, correct lengths");
    let bad = w.edit(|t| t.asset.suffix_len += 1);
    assert_refused(&bad.claim(&SECRET).run(&bad, 0), "suffix length + 1");
}

// =============================================================================================
// [HD1] [HD2] and the builtin output match: output 0 delivers the amount to the buyer
// =============================================================================================

/// A decoy token with the same template and the same state sits at output 0; the real asset
/// goes to a stranger. Both KCC-20 transfers are valid.
#[test]
fn hd1_output0_under_decoy_covenant() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    *faulty.inputs[1].leader_states() = vec![stranger(AMOUNT_A)];
    let at = faulty.fee_idx();
    faulty.inputs.insert(
        at,
        HIn::token(
            ASSET_TOKEN.compile(Kcc20State::new(standin_owner(), AMOUNT_A)),
            DECOY_COV,
            vec![w.delivered()],
            (at + 1) as u8,
        ),
    );
    faulty.outputs[0] = Out::token(ASSET_TOKEN.compile(w.delivered()), DECOY_COV, at as u16);
    // Token outputs are bound by covenant ID, not position: the real asset goes last.
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        1,
    ));
    assert_accepted(&faulty.run(&w, 1), "the asset transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 under a decoy covenant");
}

#[test]
fn hd2_delivery_carrier_kas_short() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "asset delivered with one sompi less KAS",
    );
}

#[test]
fn output0_wrong_owner() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    deliver(&mut faulty, &[stranger(AMOUNT_A)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "output 0 owner is not buyer_delivery",
    );
}

/// The asset goes to the seller's own refund owner instead of the buyer.
#[test]
fn output0_to_the_seller() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    deliver(&mut faulty, &[w.home()]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 owner is seller_refund");
}

#[test]
fn output0_wrong_owner_type() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let wrong = Kcc20State::new(Owner::script_hash(BUYER_DELIVERY.id), AMOUNT_A);
    deliver(&mut faulty, &[wrong]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 owner type differs");
}

#[test]
fn output0_short_amount() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let short = Kcc20State::new(BUYER_DELIVERY, AMOUNT_A - 1);
    deliver(&mut faulty, &[short, stranger(1)]);
    assert_accepted(&faulty.run(&w, 1), "the KCC-20 transfer itself is valid");
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 holds amount - 1");
}

#[test]
fn output0_is_minter() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let minter = Kcc20State {
        is_minter: true,
        ..w.delivered()
    };
    deliver(&mut faulty, &[minter]);
    assert_htlc_flips(&w, &control, &faulty, 0, "output 0 carries isMinter");
}

#[test]
fn output0_under_another_template() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let other = Token {
        max_cov_outs: 4,
        ..ASSET_TOKEN
    };
    faulty.outputs[0] = Out::token(other.compile(w.delivered()), ASSET_COV, 1);
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "output 0 is the right state, another template",
    );
}

// =============================================================================================
// [HS8] [HS9] the authorizer's KAS goes back to the seller
// =============================================================================================

#[test]
fn hs8_authorizer_return_to_stranger() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.outputs[1].spk = stranger_spk();
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS to a stranger");
}

/// The claimer (the buyer, say) keeps the seller's authorizer KAS.
#[test]
fn hs8_authorizer_return_to_the_buyer() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.outputs[1].spk = p2pk(w.xonly(Role::Buyer));
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS to the buyer");
}

#[test]
fn hs8_authorizer_return_omitted() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    let returned = faulty.outputs.remove(1);
    faulty.outputs.last_mut().expect("change").value += returned.value;
    assert_htlc_flips(
        &w,
        &control,
        &faulty,
        0,
        "no authorizer return; output 1 is change",
    );
}

#[test]
fn hs9_authorizer_return_short() {
    let w = HtlcWorld::new();
    let control = w.claim(&SECRET);
    let mut faulty = control.clone();
    faulty.outputs[1].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    assert_htlc_flips(&w, &control, &faulty, 0, "authorizer KAS returned minus 1");
}
