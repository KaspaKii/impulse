// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v3 `settle` around the proof gate, on the real template with real proofs
//! (spec/V3-ZK.md 6.3, 13.1, 13.2): [Z1], [Z2], the order of the checks (every v1 require runs
//! before the gate, [S6] after it), and one refusal per v1 settle require with a VALID proof, so
//! the gate cannot mask a v1 refusal.
//!
//! A refusal before the gate used fewer script units than the precompile's fixed cost
//! (v3_common::GATE_FLOOR_UNITS); that is how a test shows which side of the gate refused.
//! Tags with a real-proof test here: [S1], [S2], [S3], [S4], [S5], [S7], [S8], [S9], [S10], [E1], [E2],
//! [E3], [E4], [E5], [E6], [D1], [D2], the delivery builtin ([Z1], [Z2] and [S6] too). The decoy
//! token cases change the transaction, not the terms, so the committed proof of the fixture
//! vault serves them. The whole v1 settle suite also runs against the v3 probe (v3p_settle.rs,
//! v3p_locktime.rs, v3p_escrow_release.rs), which has the same code minus the one verify call,
//! as extra coverage. The accepted authority settle needs a key the test generates, so its proof
//! is made at test time: v3_live.rs (ignored by default, run by scripts/ci-zk.sh).
//!
//! The fixture worlds hold public keys only (v3_common.rs), so a world with an authority has no
//! valid authority signature: its [S6] test shows the refusal after the gate, and the accepted
//! twin of [S6] and [S7] is in v3p_settle.rs.

mod harness;
mod v3_common;
use harness::*;
use kaspa_txscript_errors::TxScriptError;
use v3_common::*;

fn kas() -> World {
    world_for("a_list1000")
}

fn kcc20() -> World {
    world_for("a_list1000_kcc20")
}

fn leader_states(spec: &mut TxSpec, idx: usize) -> &mut Vec<Kcc20State> {
    match &mut spec.inputs[idx].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states,
        _ => panic!("input {idx} is not a token leader"),
    }
}

fn stranger(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

/// The control settles; the faulty settle is refused at `idx` before the proof gate.
fn flips(w: &World, control: &TxSpec, faulty: &TxSpec, idx: usize, label: &str) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_refused_before_gate(&faulty.run(w, idx), label);
}

#[test]
fn v3_settle_accepted_kas_and_kcc20() {
    let w = kas();
    w.settle().assert_all_accepted(&w, "KAS cash");
    let w = kcc20();
    w.settle().assert_all_accepted(&w, "KCC-20 cash");
}

// [Z1] the buyer delivery owner has a scriptPubKey to be a leaf

#[test]
fn v3_z1_covenant_owner_refused() {
    // The same world with the delivery owner of type COVENANT_ID (made without impulse-core).
    // Every v1 check passes and the refusal is [Z1], before the gate.
    let covenant = Owner {
        id_type: IDENTIFIER_COVENANT_ID,
        id: [0xC0; 32],
    };
    let w = kas().edit(|t| t.buyer_delivery = covenant);
    let mut spec = w.settle();
    spec.inputs[0] = In::settle_v3(&w.asset_vault, None, AUTH_VALUE, kas().proof);
    assert_refused_before_gate(&spec.run(&w, 0), "[Z1] covenant owner");
    // Twin: the same terms with a script hash owner pass [Z1] and reach the gate, which refuses
    // this proof (it is for another vault): the only difference is the owner type.
    let sh = kas().edit(|t| t.buyer_delivery = Owner::script_hash([0xC0; 32]));
    let mut spec = sh.settle();
    spec.inputs[0] = In::settle_v3(&sh.asset_vault, None, AUTH_VALUE, kas().proof);
    assert_gate_refused(&spec.run(&sh, 0), "script hash owner reaches the gate");
}

// [Z2] the cash vault carries no proof

#[test]
fn v3_z2_cash_vault_nonempty_proof_refused() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::settle_v3(w.cash_vault(), None, AMOUNT_B as u64, vec![1]);
    flips(
        &w,
        &control,
        &faulty,
        1,
        "[Z2] cash vault with a 1 byte proof",
    );
    // the asset vault's proof is not accepted at the cash vault either
    faulty.inputs[1] = In::settle_v3(w.cash_vault(), None, AMOUNT_B as u64, w.proof.clone());
    assert_refused_before_gate(&faulty.run(&w, 1), "[Z2] cash vault with the asset proof");
    // KCC-20 cash vault
    let w = kcc20();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::settle_v3(w.cash_vault(), None, AUTH_VALUE, vec![0; 128]);
    flips(
        &w,
        &control,
        &faulty,
        1,
        "[Z2] KCC-20 cash vault with a proof",
    );
}

// The order of the checks

/// A settle that fails a v1 require is refused before the gate even with a valid proof, and
/// one that fails nothing but the proof is refused by the gate.
#[test]
fn v3_checks_run_before_the_gate() {
    let w = kas();
    let mut bad_tx = w.settle();
    bad_tx.outputs[1].value -= 1; // [S5]
    assert_refused_before_gate(&bad_tx.run(&w, 0), "valid proof, v1 require fails");
    assert_gate_refused(
        &settle_with(&w, vec![0; 128]),
        "v1 requires hold, proof is zeros",
    );
}

// [S6] after the gate

#[test]
fn v3_s6_authority_checked_after_the_gate() {
    let w = world_for("a_list1000_auth");
    assert!(w.terms.has_authority);
    // The valid proof passes the gate; the signature (the world holds no authority key) fails.
    let spec = w.settle(); // signed by a random key that is not the terms' authority
    assert_refused_after_gate(&spec.run(&w, 0), "[S6] wrong authority key");
    let mut unsigned = w.settle();
    unsigned.inputs[0] = In::settle_v3(&w.asset_vault, None, AUTH_VALUE, w.proof.clone());
    let run = unsigned.run(&w, 0);
    assert_refused_after_gate(&run, "[S6] no signature");
    assert!(
        matches!(run.result, Err(TxScriptError::InvalidSigHashType(0))),
        "no signature: got {:?}",
        run.result
    );
    // A bad proof is refused by the gate before the signature is looked at.
    let mut bad = w.settle();
    bad.inputs[0] = In::settle_v3(
        &w.asset_vault,
        Some(Role::Authority),
        AUTH_VALUE,
        vec![0; 128],
    );
    assert_gate_refused(&bad.run(&w, 0), "bad proof, authority present");
}

// One refusal per v1 settle require, with a valid proof (before the gate)

#[test]
fn v3_s1_asset_vault_refuses_input_1() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs.swap(0, 1);
    flips(
        &w,
        &control,
        &faulty,
        1,
        "[S1] asset vault at the cash position",
    );
}

#[test]
fn v3_s7_external_cash_without_authority() {
    // terms for external cash with no authority (what impulse-core refuses to make): refused
    // at [S7], before the gate
    let w = kas().edit(|t| {
        t.cash_kind = CASH_EXTERNAL;
        t.cash = TemplateRef::ZERO;
        t.seller_proceeds = Owner::ZERO;
        t.seller_proceeds_spk = vec![];
        t.buyer_refund = Owner::ZERO;
        t.buyer_refund_spk = vec![];
    });
    let mut spec = w.settle();
    spec.inputs[0] = In::settle_v3(&w.asset_vault, None, AUTH_VALUE, kas().proof);
    assert_refused_before_gate(&spec.run(&w, 0), "[S7] external cash without an authority");
}

#[test]
fn v3_e5_escrow_over_funded() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let idx = w.asset_escrow_idx();
    let state = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A + 1,
    );
    let new_states = leader_states(&mut faulty, idx).clone();
    let cov = faulty.inputs[idx].cov.expect("covenant");
    faulty.inputs[idx] = In::token(ASSET_TOKEN.compile(state), cov, new_states, 0);
    faulty.inputs[idx].cov = Some(cov);
    flips(&w, &control, &faulty, 0, "[E5] escrow holds amount_a + 1");
}

#[test]
fn v3_e1_second_escrow_deposit_refused() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let at = faulty.inputs.len() - 1;
    faulty.inputs.insert(
        at,
        In::token(
            ASSET_TOKEN.compile(w.asset_escrow_state()),
            ASSET_COV,
            vec![w.delivered_asset()],
            (at + 1) as u8,
        ),
    );
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[E1] a second input of the asset covenant",
    );
}

#[test]
fn v3_d2_asset_delivery_carrier_kas_short() {
    let w = kcc20();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    faulty.outputs.last_mut().expect("change").value += 1;
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[D2] asset delivery with one sompi less KAS",
    );
}

#[test]
fn v3_delivery_to_the_wrong_owner() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    *leader_states(&mut faulty, escrow) = vec![stranger(AMOUNT_A)];
    faulty.outputs[0] = Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        escrow as u16,
    );
    flips(&w, &control, &faulty, 0, "delivery to a stranger");
}

#[test]
fn v3_delivery_short_amount() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    let short = Kcc20State::new(w.terms.buyer_delivery, AMOUNT_A - 1);
    *leader_states(&mut faulty, escrow) = vec![short, stranger(1)];
    faulty.outputs[0] = Out::token(ASSET_TOKEN.compile(short), ASSET_COV, escrow as u16);
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(1)),
        ASSET_COV,
        escrow as u16,
    ));
    flips(&w, &control, &faulty, 0, "delivery of amount_a - 1");
}

#[test]
fn v3_s2_kas_cash_vault_under_funded() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1].value = AMOUNT_B as u64 - 1;
    flips(
        &w,
        &control,
        &faulty,
        1,
        "[S2] KAS cash vault holds amount_b - 1",
    );
}

#[test]
fn v3_s4_kas_proceeds_to_stranger() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].spk = stranger_spk();
    flips(&w, &control, &faulty, 0, "[S4] KAS proceeds to a stranger");
}

#[test]
fn v3_s5_kas_proceeds_short() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[1].value = AMOUNT_B as u64 - 1;
    flips(&w, &control, &faulty, 0, "[S5] KAS proceeds amount_b - 1");
}

#[test]
fn v3_s8_authorizer_return_to_stranger() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[w.asset_escrow_idx()].spk = stranger_spk();
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[S8] asset authorizer KAS to a stranger",
    );
}

#[test]
fn v3_s9_authorizer_return_short() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.outputs[w.asset_escrow_idx()].value -= 1;
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[S9] asset authorizer KAS returned minus 1",
    );
}

#[test]
fn v3_s3_settle_before_earliest() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.lock_time = EARLIEST_DAA - 1;
    control.assert_all_accepted(&w, "[S3] control");
    let run = faulty.run(&w, 0);
    assert_locktime_refused(&run, "[S3] one DAA score before earliest");
    assert!(
        run.used.0 < GATE_FLOOR_UNITS,
        "[S3] refused before the gate"
    );
}

// Decoy token cases with a real proof: the KCC-20 transfers are valid, only the vault refuses.

/// A token owner whose witness is any plain P2SH(OpTrue) input (the fee input here).
fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

fn fee_idx(spec: &TxSpec) -> usize {
    spec.inputs.len() - 1
}

/// Replaces the escrowed asset token (its UTXO script and the redeem it carries).
fn set_asset_escrow(w: &World, spec: &mut TxSpec, token: Token, state: Kcc20State) {
    let idx = w.asset_escrow_idx();
    let new_states = leader_states(spec, idx).clone();
    let cov = spec.inputs[idx].cov;
    spec.inputs[idx] = In::token(token.compile(state), cov.expect("covenant"), new_states, 0);
    spec.inputs[idx].cov = cov;
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

// [E2] the one input of the asset covenant is the escrow

#[test]
fn v3_e2_escrow_under_another_covenant_real_asset_elsewhere() {
    let w = kas();
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
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[E2] escrow under another covenant",
    );
}

#[test]
fn v3_e2_escrow_without_covenant_binding_real_asset_elsewhere() {
    let w = kas();
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
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[E2] unbound escrow, real asset elsewhere",
    );
}

// [E3] the escrow's owner is a script hash, [E4] it is this vault

#[test]
fn v3_e3_escrow_owner_type_pubkey() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::pubkey(w.asset_vault.script_hash()), AMOUNT_A);
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    flips(&w, &control, &faulty, 0, "[E3] escrow owner type is PUBKEY");
}

#[test]
fn v3_e4_escrow_owned_by_another_vault() {
    let w = kas();
    let other = w.sibling(|t| t.nonce = [0x01; 8]);
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(
        Owner::script_hash(other.asset_vault.script_hash()),
        AMOUNT_A,
    );
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[E4] escrow owned by another vault",
    );
}

#[test]
fn v3_e4_escrow_owned_by_the_cash_vault() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let state = Kcc20State::new(Owner::script_hash(w.cash_vault().script_hash()), AMOUNT_A);
    set_asset_escrow(&w, &mut faulty, ASSET_TOKEN, state);
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[E4] escrow owned by the cash vault",
    );
}

// [E6] the escrow is not a minter

#[test]
fn v3_e6_minter_escrow_cannot_hand_minting_to_a_stranger() {
    let w = kas();
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
    flips(&w, &control, &faulty, 0, "[E6] escrow is a minter");
}

// [D1] the delivery outputs are under the leg's own covenant

#[test]
fn v3_d1_output0_under_decoy_covenant() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    let escrow = w.asset_escrow_idx();
    *leader_states(&mut faulty, escrow) = vec![stranger(AMOUNT_A)];
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
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(AMOUNT_A)),
        ASSET_COV,
        escrow as u16,
    ));
    assert_accepted(&faulty.run(&w, escrow), "the asset transfer is valid");
    assert_accepted(&faulty.run(&w, at), "the decoy transfer is valid");
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[D1] output 0 under a decoy covenant",
    );
}

#[test]
fn v3_d1_cash_output1_under_decoy_covenant() {
    let w = kcc20();
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
    flips(
        &w,
        &control,
        &faulty,
        0,
        "[D1] output 1 under a decoy covenant",
    );
    assert_refused(&faulty.run(&w, 1), "the cash vault refuses it too");
}

// D64 / spec 6.5: the gate is in the asset vault, and [S10] binds the cash vault to it

/// A v3 cash vault paired with a v1 asset vault of the same terms no longer settles: the cash
/// vault's [S10] rebuilds the asset vault from its own template v3 script, so input 0 must be
/// the gated v3 asset vault. The v1 asset vault refuses too (its [S10] wants a v1 cash vault).
#[test]
fn v3_s10_v3_cash_vault_refuses_a_v1_asset_vault() {
    let w = kas();
    let mut v1_terms = w.terms.clone();
    v1_terms.version = 1;
    v1_terms.zk = None;
    let v1_asset = v1_terms.vault(ASSET_LEG);
    assert_ne!(
        v1_asset.script_hash(),
        w.asset_vault.script_hash(),
        "the v1 asset vault is another script"
    );
    // The same world except for the asset vault; every delivery, escrow and output follows it.
    let mut ungated = World::new(w.mode);
    ungated.terms = w.terms.clone();
    ungated.asset_vault = v1_asset.clone();
    ungated.cash_vault = w.cash_vault.clone();
    let mut spec = ungated.settle();
    spec.inputs[0] = In::settle(&v1_asset, None, AUTH_VALUE);
    // Control: the gated pair settles with the committed proof.
    w.settle()
        .assert_all_accepted(&w, "v3 asset vault with v3 cash vault");
    assert_refused_before_gate(
        &spec.run(&ungated, 1),
        "[S10] the v3 cash vault, v1 asset vault at input 0",
    );
    assert_refused(
        &spec.run(&ungated, 0),
        "[S10] the v1 asset vault, v3 cash vault at input 1",
    );
}

/// [S10] on the shipped template with the committed proof: the KAS cash vault replaced by a
/// plain input paying the seller's proceeds. Refused by the asset vault before the gate.
#[test]
fn v3_s10_asset_vault_refuses_a_settle_without_the_cash_vault() {
    let w = kas();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1] = In::plain(w.terms.amount_b as u64);
    flips(&w, &control, &faulty, 0, "[S10] no cash vault at input 1");
}

/// [S10] on the shipped template: an asset token owned by the cash vault in place of the asset
/// vault's escrow, the asset vault replaced by a plain input. Refused by the cash vault, which
/// carries no proof.
#[test]
fn v3_s10_cash_vault_refuses_a_settle_without_the_asset_vault() {
    let w = kcc20();
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[0] = In::plain(AUTH_VALUE);
    let slot = w.asset_escrow_idx();
    let held = Kcc20State::new(
        Owner::script_hash(w.cash_vault().script_hash()),
        w.terms.amount_a,
    );
    faulty.inputs[slot] = In::token(
        ASSET_TOKEN.compile(held),
        ASSET_COV,
        vec![w.delivered_asset()],
        1,
    );
    flips(&w, &control, &faulty, 1, "[S10] no asset vault at input 0");
}
