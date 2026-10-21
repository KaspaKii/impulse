// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Shared by foreign_covenant.rs and foreign_covenant_residual.rs (and, through them, by the
//! template v3 probe binaries): the modes, the token of another covenant, and the transaction
//! edits of the input check (spec/TEMPLATE.md, "Inputs outside the layout").

#![allow(dead_code)]

use super::harness::*;
use kaspa_consensus_core::Hash;

pub const AUTH_KAS: Mode = Mode::new(true, CASH_KAS, REVOCABLE);
pub const AUTH_KCC20: Mode = Mode::new(true, CASH_KCC20, REVOCABLE);
pub const AUTH_EXTERNAL: Mode = Mode::new(true, CASH_EXTERNAL, REVOCABLE);
pub const SELF_KAS: Mode = Mode::new(false, CASH_KAS, EARMARKED);
pub const SELF_KCC20: Mode = Mode::new(false, CASH_KCC20, EARMARKED);
pub const SETTLE_MODES: [Mode; 5] = [AUTH_KAS, AUTH_KCC20, AUTH_EXTERNAL, SELF_KAS, SELF_KCC20];

/// A covenant no leg of these terms names.
pub const FOREIGN_COV: Hash = Hash::from_bytes([0xF0; 32]);
pub const FOREIGN_TOKEN: Token = Token {
    cov: FOREIGN_COV,
    max_cov_ins: 2,
    max_cov_outs: 2,
};
pub const FOREIGN_AMOUNT: i64 = 777;

/// The most inputs a spend of a vault may have (MAX_INPUTS in the contract).
pub const MAX_INPUTS: usize = 12;

pub fn fee_idx(spec: &TxSpec) -> usize {
    spec.inputs.len() - 1
}

/// `spec` with a token of `token`'s covenant owned by `vault`'s script hash inserted at input
/// `at`, moved whole to a stranger by its own KCC-20 transfer (the output before the change),
/// whose witness is the vault at input `witness`.
pub fn with_token_owned_by(
    spec: &TxSpec,
    (vault, witness): (&Compiled, u8),
    token: Token,
    amount: i64,
    at: usize,
) -> TxSpec {
    let mut faulty = spec.clone();
    let held = Kcc20State::new(Owner::script_hash(vault.script_hash()), amount);
    let taken = Kcc20State::new(STRANGER_OWNER, amount);
    faulty.inputs.insert(
        at,
        In::token(token.compile(held), token.cov, vec![taken], witness),
    );
    let out_at = faulty.outputs.len() - 1;
    faulty.outputs.insert(
        out_at,
        Out::token(token.compile(taken), token.cov, at as u16),
    );
    faulty
}

/// `spec` with a second token of a leg's covenant, owned by `vault`'s script hash (witness the
/// vault at input `witness`), spent as a delegate of that leg's escrow at input `escrow`, whose
/// transfer also sends it whole to a stranger (an output after the change).
pub fn with_second_token_owned_by(
    spec: &TxSpec,
    (vault, witness): (&Compiled, u8),
    token: Token,
    amount: i64,
    escrow: usize,
) -> (TxSpec, usize) {
    let mut faulty = spec.clone();
    let at = fee_idx(&faulty);
    let held = Kcc20State::new(Owner::script_hash(vault.script_hash()), amount);
    let taken = Kcc20State::new(STRANGER_OWNER, amount);
    faulty.inputs.insert(
        at,
        In::token_delegate(token.compile(held), token.cov, witness),
    );
    match &mut faulty.inputs[escrow].spend {
        Spend::Kcc20Leader { new_states, .. } => new_states.push(taken),
        _ => panic!("input {escrow} is not the escrow's transfer leader"),
    }
    faulty
        .outputs
        .push(Out::token(token.compile(taken), token.cov, escrow as u16));
    (faulty, at)
}

/// The foreign token's own transfer is valid in `spec`, so only a vault can refuse it.
pub fn assert_token_transfer_valid(w: &World, spec: &TxSpec, at: usize, label: &str) {
    assert_accepted(
        &spec.run(w, at),
        &format!("{label}: the token's own transfer"),
    );
}

/// `spec` with `extra` more fee inputs (no covenant) before the change.
pub fn with_fee_inputs(spec: &TxSpec, extra: usize) -> TxSpec {
    let mut out = spec.clone();
    for _ in 0..extra {
        out.inputs.push(In::plain(FEE_VALUE));
    }
    out
}

/// The vault inputs of a canonical settle.
pub fn vault_inputs(w: &World) -> Vec<usize> {
    if w.external() {
        vec![0]
    } else {
        vec![0, 1]
    }
}

/// Every refund the harness makes: (mode, leg, signer).
pub fn refunds() -> Vec<(Mode, i64, Role)> {
    vec![
        (AUTH_KCC20, ASSET_LEG, Role::Seller),
        (AUTH_KCC20, ASSET_LEG, Role::Buyer),
        (AUTH_KCC20, ASSET_LEG, Role::Authority),
        (AUTH_KCC20, CASH_LEG, Role::Buyer),
        (AUTH_KCC20, CASH_LEG, Role::Seller),
        (AUTH_KAS, CASH_LEG, Role::Buyer),
        (AUTH_KAS, CASH_LEG, Role::Authority),
        (SELF_KAS, CASH_LEG, Role::Seller),
    ]
}
