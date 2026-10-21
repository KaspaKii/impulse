// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The transaction lines (spec/CLI.md, "The transaction lines"): what the builders, `ipst sign`,
//! `ipst merge` and `submit` print about an IPST, one `key: value` fact per line.

use crate::funds::outpoint_text;
use crate::json::hex;
use crate::summary::{kas_address, Role};
use crate::trade::leg_name;
use impulse_core::terms::{LegKind, Network, Terms};
use impulse_core::tx::Ipst;
use impulse_core::tx::{min_relay_fee, IpstKind, RefundSigner};

/// What an IPST is: a transaction one of impulse-core's builders makes, as the terms check
/// names it, the CLI's own Direct cancellation by a party (spec/CLI.md, "direct cancel
/// build"), or a token genesis (spec/CLI.md, "Token helper (testnet only)").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Built(IpstKind),
    Cancel(Role),
    Genesis,
}

impl From<IpstKind> for Kind {
    fn from(kind: IpstKind) -> Self {
        Kind::Built(kind)
    }
}

/// The builder's name as the `ipst:` line shows it.
pub fn kind_name(kind: Kind) -> String {
    let kind = match kind {
        Kind::Built(kind) => kind,
        Kind::Genesis => return "token genesis".into(),
        Kind::Cancel(role) => return format!("direct cancel by {}", role.name()),
    };
    match kind {
        IpstKind::FundKas => "fund_kas".into(),
        IpstKind::FundKcc20(leg) => format!("fund_kcc20 {}", leg_name(leg)),
        IpstKind::Settle => "settle".into(),
        IpstKind::Direct => "direct".into(),
        IpstKind::Refund {
            leg,
            signer,
            with_token,
        } => format!(
            "refund {} by {}, {} the token",
            leg_name(leg),
            signer_name(signer),
            if with_token { "with" } else { "without" }
        ),
    }
}

pub fn signer_name(signer: RefundSigner) -> &'static str {
    match signer {
        RefundSigner::Depositor => "depositor",
        RefundSigner::Counterparty => "counterparty",
        RefundSigner::Authority => "authority",
    }
}

/// How many inputs come before the fee inputs in the builder's layout (spec/TRANSACTIONS.md);
/// a cancellation has one, the Direct input, and a token genesis none.
pub fn trade_inputs(kind: Kind, ipst: &Ipst) -> usize {
    let t = ipst.terms().terms();
    let kind = match kind {
        Kind::Built(kind) => kind,
        Kind::Genesis => return 0,
        Kind::Cancel(_) => return 1,
    };
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

/// How many outputs come before the change in the builder's layout; a cancellation has one, the
/// Direct input going home, and a token genesis one, the token.
pub fn trade_outputs(kind: Kind, ipst: &Ipst) -> usize {
    let t = ipst.terms().terms();
    let kind = match kind {
        Kind::Built(kind) => kind,
        Kind::Genesis => return 1,
        Kind::Cancel(_) => return 1,
    };
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
pub fn payer_cost(kind: Kind, ipst: &Ipst) -> u64 {
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

fn address(network: Network, spk: &kaspa_consensus_core::tx::ScriptPublicKey) -> String {
    kas_address(network, spk.version(), spk.script())
}

/// The transaction lines of an IPST. `kind` names the builder; `token_change` is the amount of
/// a funding's token change, when the caller knows it.
pub fn lines(ipst: &Ipst, kind: Kind, token_change: Option<u64>) -> Vec<String> {
    let t: &Terms = ipst.terms().terms();
    let network = t.network;
    let tx = ipst.transaction();
    let mut lines = vec![
        format!("ipst: {}", kind_name(kind)),
        format!("txid: {}", hex(&tx.id().as_bytes())),
    ];
    lines.push(if tx.lock_time == 0 {
        "lock_time: 0".into()
    } else {
        format!(
            "lock_time: {} (a block can include it from DAA score {})",
            tx.lock_time,
            tx.lock_time.saturating_add(1)
        )
    });
    for (i, ((input, entry), slot)) in tx
        .inputs
        .iter()
        .zip(ipst.entries())
        .zip(ipst.slots())
        .enumerate()
    {
        let covenant = entry.covenant_id.map_or(String::new(), |c| {
            format!(", covenant {}", hex(&c.as_bytes()))
        });
        let signer = match (slot.signer(), slot.signature()) {
            (Some(k), Some(_)) => format!("signer {} signed", hex(&k)),
            (Some(k), None) => format!("signer {} pending", hex(&k)),
            (None, _) => "takes no signature".into(),
        };
        lines.push(format!(
            "input {i}: {}, {} sompi at {}{covenant}, {signer}",
            outpoint_text(&input.previous_outpoint),
            entry.amount,
            address(network, &entry.script_public_key)
        ));
    }
    for (i, output) in tx.outputs.iter().enumerate() {
        let covenant = output.covenant.map_or(String::new(), |c| {
            format!(
                ", covenant {} from input {}",
                hex(&c.covenant_id.as_bytes()),
                c.authorizing_input
            )
        });
        lines.push(format!(
            "output {i}: {} sompi to {}{covenant}",
            output.value,
            address(network, &output.script_public_key)
        ));
    }
    let masses = ipst.masses();
    lines.push(format!(
        "fee: {} sompi (minimum relay fee {} sompi)",
        ipst.fee(),
        min_relay_fee(masses.fee_mass)
    ));
    lines.push(format!(
        "payer cost beyond the fee: {} sompi into trade outputs",
        payer_cost(kind, ipst)
    ));
    let n = trade_outputs(kind, ipst);
    lines.push(match tx.outputs.get(n) {
        Some(o) => format!(
            "change: {} sompi to {}",
            o.value,
            address(network, &o.script_public_key)
        ),
        None => "change: none".into(),
    });
    lines.push(format!(
        "masses: compute {}, transient {}, storage {}",
        masses.compute, masses.transient, masses.storage
    ));
    if let (Kind::Genesis, LegKind::Kcc20(token)) = (kind, t.asset_leg.kind) {
        lines.push(format!(
            "token: {}:0:{}",
            hex(&tx.id().as_bytes()),
            t.asset_leg.amount
        ));
        lines.push(format!("covenant: {}", hex(&token.covenant_id)));
    }
    if let (Kind::Built(IpstKind::FundKcc20(_)), 3) = (kind, n) {
        lines.push(match token_change {
            Some(amount) => format!("token change: {}:2:{amount}", hex(&tx.id().as_bytes())),
            None => format!("token change: {}:2", hex(&tx.id().as_bytes())),
        });
    }
    let pending = ipst.pending();
    lines.push(if pending.is_empty() {
        "pending: complete".into()
    } else {
        let mut signers: Vec<String> = pending
            .iter()
            .filter_map(|&i| ipst.slots()[i].signer())
            .map(|k| hex(&k))
            .collect();
        signers.dedup();
        format!("pending: {}", signers.join(", "))
    });
    lines
}
