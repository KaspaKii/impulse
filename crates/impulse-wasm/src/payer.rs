// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The payer's side of signing (I11 phase 2, review round 2): steps 9 and 10 of `ipst sign` in
//! spec/CLI.md, in the SDK, so that a wallet that signs a fee input, or any input holding its own
//! funds, never commits more than it was shown.
//!
//! The terms check (`Ipst::verify_against_terms`) fixes every trade output from the trade inputs,
//! but not what the fee inputs pay into them: a counterparty who under-funds an authorizer or a
//! carrier makes the builder top the pass-through output up to its minimum, and that top-up comes
//! out of the fee payer's inputs, on top of the fee. So a signer of a fee input confirms, before
//! it signs:
//!
//! 1. the change output, if there is one, pays the address the signer accepts (its own key, or
//!    the `change` it gave): `SDK_SIGN_CHANGE_NOT_MINE`;
//! 2. the fee is at most `max_fee`, by default twice the minimum relay fee of the transaction,
//!    and without a `max_fee` the signer signs at most three fee inputs (the minimum grows with
//!    every input, and whoever built the document chose which of the signer's UTXOs it spends):
//!    `SDK_SIGN_FEE_TOO_HIGH`;
//! 3. in a settle, a refund or a Direct transaction, the payer cost beyond the fee (the top-up)
//!    is at most `max_topup`, default 0: `SDK_SIGN_TOPUP_TOO_HIGH`.
//!
//! And whoever the signer is, when it signs an input holding its own funds (every input but the
//! vault inputs of a settle or refund, which the contract governs), the outflow, what those
//! inputs hold less what comes back to the signer (the change, a funding's token change), is at
//! most what the trade takes from it plus `max_fee` and `max_topup` when it pays the fee:
//! `SDK_SIGN_OUTFLOW_TOO_HIGH`; and within the value cap: `SDK_VALUE_CAP_EXCEEDED`.
//!
//! On mainnet a change output that pays a key held only in a wallet of the page is refused too
//! (`SDK_DESTINATION_IN_WALLET`): nothing in the page spends it, and it is lost with the page.
//!
//! Ported from `crates/impulse-cli/src/ipst_cmd.rs` and `txview.rs` on main (same author): the
//! same order of checks, the same limits, and the codes under `SDK_SIGN_` names.

use crate::error::{Failure, SdkError};
use crate::json::hex;
use crate::review::{address_of, p2pk};
use crate::value::{self, ValueDeclaration};
use impulse_core::terms::{LegKind, Network};
use impulse_core::tx::{self, Ipst, IpstKind, TermsMatch};
use kaspa_consensus_core::tx::ScriptPublicKey;

/// The most fee inputs of the signer the default fee limit covers: the minimum relay fee grows
/// with every input, and the document's builder chose them.
const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;

pub(crate) fn is_funding(kind: IpstKind) -> bool {
    matches!(kind, IpstKind::FundKas | IpstKind::FundKcc20(_))
}

/// How many inputs come before the fee inputs in the builder's layout.
pub(crate) fn trade_inputs(kind: IpstKind, ipst: &Ipst) -> usize {
    let t = ipst.terms().terms();
    match kind {
        IpstKind::FundKas => 0,
        IpstKind::FundKcc20(_) => ipst
            .entries()
            .iter()
            .take_while(|e| e.covenant_id.is_some())
            .count(),
        IpstKind::Settle => match t.cash_leg.kind {
            LegKind::Kas => 3,
            LegKind::Kcc20(_) => 4,
            LegKind::External => 2,
        },
        IpstKind::Refund { with_token, .. } => 1 + usize::from(with_token),
        IpstKind::Direct => 2,
    }
}

/// How many outputs come before the change in the builder's layout.
pub(crate) fn trade_outputs(kind: IpstKind, ipst: &Ipst) -> usize {
    let t = ipst.terms().terms();
    match kind {
        IpstKind::FundKas => 1,
        // Escrowed token, authorizer, then token change if the transfer has a third covenant
        // output; the KAS change never carries a covenant.
        IpstKind::FundKcc20(_) => {
            2 + usize::from(
                ipst.transaction()
                    .outputs
                    .get(2)
                    .is_some_and(|o| o.covenant.is_some()),
            )
        }
        IpstKind::Settle => match t.cash_leg.kind {
            LegKind::Kas => 3,
            LegKind::Kcc20(_) => 4,
            LegKind::External => 2,
        },
        IpstKind::Refund { with_token, .. } => 1 + usize::from(with_token),
        IpstKind::Direct => 2,
    }
}

/// What the fee inputs put into the trade outputs beyond the fee: the trade outputs less the
/// trade inputs, or 0. For a funding this is the deposit; for a settle, a refund or a Direct
/// transaction it is the top-up of under-funded pass-through outputs (spec/TRANSACTIONS.md).
pub(crate) fn payer_cost(kind: IpstKind, ipst: &Ipst) -> u64 {
    let n_in = trade_inputs(kind, ipst);
    let n_out = trade_outputs(kind, ipst);
    let held: u64 = ipst
        .entries()
        .iter()
        .take(n_in)
        .fold(0, |s, e| s.saturating_add(e.amount));
    let paid: u64 = ipst
        .transaction()
        .outputs
        .iter()
        .take(n_out)
        .fold(0, |s, o| s.saturating_add(o.value));
    paid.saturating_sub(held)
}

/// What the signer accepts beyond the terms.
pub(crate) struct Accept {
    /// Where the change output must pay: the signer's own P2PK, or the address it gave.
    pub change: ScriptPublicKey,
    /// The most fee the signer accepts; None is twice the minimum relay fee, for at most three
    /// fee inputs.
    pub max_fee: Option<u64>,
    /// The most the fee inputs may add to the trade outputs; the default is none.
    pub max_topup: u64,
    /// The KAS each token input the signer gives carries in a Direct transaction.
    pub carrier: u64,
    /// Keys that live only in wallets of the page.
    pub held: Vec<[u8; 32]>,
}

/// What a passed check commits the signer to, for the page to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Committed {
    pub outflow: u64,
    pub limit: u64,
}

fn address_text(network: Network, spk: &ScriptPublicKey) -> String {
    address_of(network, spk)
        .unwrap_or_else(|| format!("script version {}: {}", spk.version(), hex(spk.script())))
}

/// Steps 9 and 10. `mine` are the inputs the wallet is about to sign. Returns what the signer
/// commits, or None when it signs none of its own funds.
pub(crate) fn check(
    ipst: &Ipst,
    matched: &TermsMatch,
    me: [u8; 32],
    mine: &[usize],
    accept: &Accept,
    declaration: &ValueDeclaration,
) -> Result<Option<Committed>, Failure> {
    let kind = matched.kind;
    let t = ipst.terms().terms();
    let max_fee = accept
        .max_fee
        .unwrap_or_else(|| tx::min_relay_fee(ipst.masses().fee_mass).saturating_mul(2));
    let first_fee_input = trade_inputs(kind, ipst);
    let pays_fee = mine.iter().any(|&i| i >= first_fee_input);
    let my_fee_inputs = (first_fee_input..ipst.slots().len())
        .filter(|&i| ipst.slots()[i].signer() == Some(me))
        .count();
    if pays_fee {
        if let Some(change) = &matched.change {
            if change.script_public_key != accept.change {
                return Err(SdkError::SignChangeNotMine {
                    change: format!(
                        "{} ({} sompi)",
                        address_text(t.network, &change.script_public_key),
                        change.value
                    ),
                    expected: address_text(t.network, &accept.change),
                }
                .into());
            }
            if t.network == Network::Mainnet
                && accept
                    .held
                    .iter()
                    .any(|k| p2pk(k) == change.script_public_key)
            {
                return Err(SdkError::DestinationInWallet {
                    reasons: vec![format!(
                        "the change of {} sompi pays {}, a key that lives only in a wallet of this page; give a change address you control elsewhere",
                        change.value,
                        address_text(t.network, &change.script_public_key)
                    )],
                }
                .into());
            }
        }
        if accept.max_fee.is_none() && my_fee_inputs > DEFAULT_FEE_LIMIT_INPUTS {
            return Err(SdkError::SignFeeTooHigh {
                reason: format!(
                    "you sign {my_fee_inputs} fee inputs, and the default fee limit covers at most {DEFAULT_FEE_LIMIT_INPUTS}: the fee is {} sompi; pass max_fee to accept it",
                    matched.fee
                ),
            }
            .into());
        }
        if matched.fee > max_fee {
            return Err(SdkError::SignFeeTooHigh {
                reason: format!(
                    "you sign a fee input, and the fee is {} sompi, above {max_fee}; pass max_fee to accept more",
                    matched.fee
                ),
            }
            .into());
        }
        let topup = payer_cost(kind, ipst);
        if !is_funding(kind) && topup > accept.max_topup {
            return Err(SdkError::SignTopupTooHigh {
                topup,
                max_topup: accept.max_topup,
            }
            .into());
        }
    }
    let Some((outflow, expected)) = outflow(ipst, kind, me, &accept.change, accept.carrier) else {
        return Ok(None);
    };
    // The fee and a top-up come out of the fee inputs only.
    let limit = if pays_fee {
        expected
            .saturating_add(max_fee)
            .saturating_add(accept.max_topup)
    } else {
        expected
    };
    if outflow > limit {
        return Err(SdkError::SignOutflowTooHigh {
            outflow,
            limit,
            expected,
        }
        .into());
    }
    // And within the value cap, unless it is lifted.
    value::check(t, declaration, outflow)?;
    Ok(Some(Committed { outflow, limit }))
}

/// The KAS the signer commits: the inputs it signs that hold its own funds (every input it signs,
/// except the vault inputs of a settle or refund), less what comes back to it (the change, when it
/// pays `expected_change`, and a funding's token change); and what the trade itself takes from it
/// (a funding's deposit, the KAS cash or the token carrier of a Direct trade). None when the
/// signer signs none of its own funds.
fn outflow(
    ipst: &Ipst,
    kind: IpstKind,
    me: [u8; 32],
    expected_change: &ScriptPublicKey,
    carrier: u64,
) -> Option<(u64, u64)> {
    let t = ipst.terms().terms();
    let n_in = trade_inputs(kind, ipst);
    let n_out = trade_outputs(kind, ipst);
    let vault_inputs = match kind {
        IpstKind::Settle | IpstKind::Refund { .. } => n_in,
        _ => 0,
    };
    let own: Vec<usize> = (vault_inputs..ipst.slots().len())
        .filter(|&i| ipst.slots()[i].signer() == Some(me))
        .collect();
    if own.is_empty() {
        return None;
    }
    let held = own
        .iter()
        .fold(0u64, |s, &i| s.saturating_add(ipst.entries()[i].amount));
    let outputs = &ipst.transaction().outputs;
    let mut back = outputs
        .get(n_out)
        .filter(|o| o.script_public_key == *expected_change)
        .map_or(0, |o| o.value);
    let expected = match kind {
        IpstKind::FundKas => t.cash_leg.amount,
        IpstKind::FundKcc20(_) => {
            if n_out == 3 && own.contains(&0) {
                back = back.saturating_add(outputs[2].value);
            }
            outputs[0].value.saturating_add(outputs[1].value)
        }
        IpstKind::Direct => own
            .iter()
            .filter(|&&i| i < n_in)
            .map(|&i| match (i, t.cash_leg.kind) {
                (1, LegKind::Kas) => t.cash_leg.amount,
                _ => carrier,
            })
            .fold(0u64, u64::saturating_add),
        IpstKind::Settle | IpstKind::Refund { .. } => 0,
    };
    Some((held.saturating_sub(back), expected))
}
