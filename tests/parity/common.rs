// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Shared helpers for the parity tests: golden terms vectors as real terms, both validation
//! stages as a creator runs them, and small edits of the harness's canonical transactions
//! (written after the helpers of tests/engine/settle.rs, refund.rs and instantiate.rs).

use crate::harness::*;
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{CreationContext, Terms, ValidatedTerms};

/// The creation DAA score every golden terms vector validates under (spec/ENCODING.md).
pub const VECTOR_CREATION_DAA: u64 = 400_000_000;

/// The last DAA score in the lock-time domain: far past the creation horizon from any creation
/// DAA score the vectors use, so terms with it are terms the creation checks refuse.
pub const FAR_DAA: u64 = kaspa_txscript::LOCK_TIME_THRESHOLD - 1;

/// The golden terms vector file whose name starts with `prefix`, parsed.
pub fn vector_json(prefix: &str) -> serde_json::Value {
    let dir = repo_path("tests/vectors/terms");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("vectors directory")
        .map(|e| e.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".json"))
        })
        .collect();
    assert_eq!(paths.len(), 1, "one vector named {prefix}*");
    let text = std::fs::read_to_string(paths.remove(0)).expect("read vector");
    serde_json::from_str(&text).expect("vector parses")
}

/// The canonical bytes of a golden terms vector.
pub fn vector_bytes(prefix: &str) -> Vec<u8> {
    let hex = vector_json(prefix)["canonical"]
        .as_str()
        .expect("canonical hex")
        .to_string();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A golden terms vector as a terms value.
pub fn vector(prefix: &str) -> Terms {
    Terms::decode(&vector_bytes(prefix)).expect("vector decodes")
}

/// The context the golden vectors are created under.
pub fn creation_context(t: &Terms) -> CreationContext {
    CreationContext::new(t.network, VECTOR_CREATION_DAA)
}

/// Both validation stages, as a creator runs them; the refusal code on failure.
pub fn create(t: Terms) -> Result<ValidatedTerms, &'static str> {
    let ctx = creation_context(&t);
    let checked = t.validate_structure().map_err(|e| e.code())?;
    checked.validate_creation(&ctx).map_err(|e| e.code())?;
    Ok(checked)
}

/// The accepted control: `t` passes both stages.
pub fn assert_created(t: Terms, label: &str) -> ValidatedTerms {
    create(t).unwrap_or_else(|code| panic!("{label}: control refused with {code}"))
}

/// The fault: `t` is refused with `code`.
pub fn assert_refused_with(t: Terms, code: &str, label: &str) {
    match create(t) {
        Ok(_) => panic!("{label}: expected {code}, accepted"),
        Err(found) => assert_eq!(found, code, "{label}"),
    }
}

/// The script hash of `leg`'s vault for structure-checked terms.
pub fn vault_hash(t: &ValidatedTerms, leg: LegIndex) -> [u8; 32] {
    Vault::instantiate_existing(t, leg)
        .expect("the leg has a vault")
        .script_hash()
}

pub fn depositor(leg: i64) -> Role {
    if leg == ASSET_LEG {
        Role::Seller
    } else {
        Role::Buyer
    }
}

pub fn stranger(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}

/// The new states of the KCC-20 transfer led by input `idx`.
pub fn leader_states(spec: &mut TxSpec, idx: usize) -> &mut Vec<Kcc20State> {
    match &mut spec.inputs[idx].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states,
        _ => panic!("input {idx} is not a token leader"),
    }
}

/// The asset delivered at output 0 (and the escrow transfer's new states) replaced by `states`;
/// states after the first become extra asset outputs at the end.
pub fn deliver_asset(w: &World, spec: &mut TxSpec, states: &[Kcc20State]) {
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

/// The escrowed asset token of a settle replaced by one holding `state`.
pub fn set_asset_escrow(w: &World, spec: &mut TxSpec, state: Kcc20State) {
    let idx = w.asset_escrow_idx();
    let new_states = leader_states(spec, idx).clone();
    spec.inputs[idx] = In::token(ASSET_TOKEN.compile(state), ASSET_COV, new_states, 0);
}

/// The asset escrow of a refund (input 1) replaced by `escrow`, going home as `home` (output 1).
pub fn refund_asset_escrow(spec: &mut TxSpec, escrow: Kcc20State, home: Kcc20State) {
    spec.inputs[1] = In::token(ASSET_TOKEN.compile(escrow), ASSET_COV, vec![home], 0);
    spec.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
}

/// The asset token a refund returns at output 1 sent to `home` instead.
pub fn refund_asset_home(spec: &mut TxSpec, home: Kcc20State) {
    leader_states(spec, 1)[0] = home;
    spec.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
}

/// The same refund with the escrowed token (input 1, output 1) left out: the authorizer alone.
pub fn without_token(mut spec: TxSpec) -> TxSpec {
    spec.inputs.remove(1);
    spec.outputs.remove(1);
    spec
}

/// The harness world for `mode` with the one fixture identifier real terms refuse replaced, as
/// tests/engine/instantiate.rs does: the buyer's PUBKEY delivery owner [0xB1; 32] is not an
/// x-only key (`TERMS_INVALID_KEY`), so the asset goes to a SCRIPT_HASH owner instead. KCC-20
/// cash only (a KAS cash fixture needs a second fix).
pub fn real_world(mode: Mode) -> World {
    assert_eq!(mode.cash, CASH_KCC20, "real_world covers KCC-20 cash");
    World::with(mode, |t, _| {
        t.buyer_delivery = Owner::script_hash([0xB1; 32])
    })
}

/// The other party of `leg`'s depositor.
pub fn counterparty(leg: i64) -> Role {
    if leg == ASSET_LEG {
        Role::Buyer
    } else {
        Role::Seller
    }
}

/// The amount `leg` settles in the harness terms.
pub fn leg_amount(leg: i64) -> i64 {
    if leg == ASSET_LEG {
        AMOUNT_A
    } else {
        AMOUNT_B
    }
}

/// The refund of KCC-20 `leg` signed by `signer`, with an escrowed token holding `amount` that
/// goes home whole to the depositor's refund owner.
pub fn refund_holding(w: &World, leg: i64, signer: Role, amount: i64) -> TxSpec {
    let (token, vault, home) = if leg == ASSET_LEG {
        (ASSET_TOKEN, &w.asset_vault, w.terms.seller_refund)
    } else {
        (CASH_TOKEN, w.cash_vault(), w.terms.buyer_refund)
    };
    let escrow = Kcc20State::new(Owner::script_hash(vault.script_hash()), amount);
    let home = Kcc20State::new(home, amount);
    let mut spec = w.refund(leg, signer);
    spec.inputs[1] = In::token(token.compile(escrow), token.cov, vec![home], 0);
    spec.outputs[1] = Out::token(token.compile(home), token.cov, 1);
    spec
}

/// A KCC-20 escrow of `leg` holding `amount`, not the leg amount, unwinds only through its
/// depositor. The counterparty and the authority are refused ([R14]), each beside its control
/// with the exact leg amount, and still refused after expiry_daa. The depositor's refund is
/// accepted: at once under revocable funding, from expiry_daa under earmarked funding ([R3]).
pub fn assert_only_depositor_unwinds(w: &World, leg: i64, amount: i64, label: &str) {
    assert_ne!(amount, leg_amount(leg), "{label}: not a wrong amount");
    let mut others = vec![counterparty(leg)];
    if w.mode.authority {
        others.push(Role::Authority);
    }
    for signer in others {
        let label = format!("{label}: {signer:?} sends leg {leg} holding {amount} home");
        let mut control = refund_holding(w, leg, signer, leg_amount(leg));
        let mut faulty = refund_holding(w, leg, signer, amount);
        assert_flips(w, &control, &faulty, 0, &label);
        control.lock_time = EXPIRY_DAA + 1;
        faulty.lock_time = EXPIRY_DAA + 1;
        assert_flips(w, &control, &faulty, 0, &format!("{label}, after expiry"));
    }
    let label = format!("{label}: the depositor sends leg {leg} holding {amount} home");
    let home = refund_holding(w, leg, depositor(leg), amount);
    if w.mode.funding == EARMARKED {
        assert_eq!(home.lock_time, EXPIRY_DAA, "{label}");
        let mut early = home.clone();
        early.lock_time = EXPIRY_DAA - 1;
        assert_flips_locktime(w, &home, &early, 0, &format!("{label}, one DAA early"));
    } else {
        assert_eq!(home.lock_time, 0, "{label}");
        home.assert_all_accepted(w, &label);
    }
}
