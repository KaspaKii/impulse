// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse decode <txid>` (spec/CLI.md, "decode"): fetch an accepted transaction from the
//! user's node, with the UTXO entry each input spent, and decode it with impulse-core's decoder
//! bound to the scriptPublicKeys the node reports.

use crate::cli::{connect, hash_arg, print, Ctx};
use crate::error::CliError;
use crate::funds::outpoint_text;
use crate::json::hex;
use crate::node;
use crate::summary::{self, describe};
use crate::trade::leg_name;
use clap::Args;
use impulse_core::decode::{decode_transaction, Entry, Outcome, Party};
use kaspa_consensus_core::tx::ScriptPublicKey;
use std::io::Write;

#[derive(Args, Debug)]
pub struct DecodeArgs {
    /// The transaction ID, 64 lowercase hex digits.
    pub txid: String,
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// A chain block at or before the transaction's acceptance, 64 lowercase hex digits.
    #[arg(long, value_name = "HASH")]
    pub from_block: String,
    /// A terms file (hashed-terms vault, template v4): reconstruct and check the revealed trade.
    #[cfg(feature = "zk")]
    #[arg(long, value_name = "FILE")]
    pub with_terms: Option<std::path::PathBuf>,
}

fn party_name(p: Option<Party>) -> &'static str {
    match p {
        Some(Party::Seller) => "the seller",
        Some(Party::Buyer) => "the buyer",
        Some(Party::Authority) => "the authority",
        None => "a key that holds no role in the terms",
    }
}

pub(crate) fn decode(ctx: &Ctx, a: DecodeArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let node = connect(ctx, &a.node, ctx.network)?;
    node::check_node(node.as_ref(), ctx.network)?;
    let (block, accepted) = node::find_accepted_tx(node.as_ref(), txid, from)?;
    let block_daa = node.block(block)?.daa_score;
    let spent: Vec<ScriptPublicKey> = accepted
        .spent
        .iter()
        .map(|e| e.script_public_key.clone())
        .collect();
    #[cfg(feature = "zk")]
    let v4_lines = {
        let terms = match &a.with_terms {
            Some(p) => Some(crate::zkh_cmd::read_terms(p)?),
            None => None,
        };
        if crate::zkh_cmd::has_v4(&accepted.tx) {
            crate::zkh_cmd::lines(&accepted.tx, &accepted.spent, terms.as_ref())?
        } else if terms.is_some() {
            return Err(CliError::new(
                "ZK_H_NOT_V4_VAULT",
                "no input of this transaction spends a template v4 vault",
            ));
        } else {
            Vec::new()
        }
    };
    #[cfg(not(feature = "zk"))]
    let v4_lines: Vec<String> = Vec::new();
    let decoded = match decode_transaction(&accepted.tx, &spent, ctx.network) {
        Ok(d) => d,
        Err(impulse_core::decode::DecodeError::NoVaultInput) if !v4_lines.is_empty() => {
            let mut lines = vec![
                format!("txid: {}", hex(&accepted.tx.id().as_bytes())),
                format!(
                    "accepted: in chain block {} at DAA score {block_daa}",
                    hex(&block)
                ),
                "bound: yes, each vault input to the scriptPublicKey the node reports it spent"
                    .into(),
            ];
            lines.extend(v4_lines);
            return print(out, &lines);
        }
        Err(e) => return Err(e.into()),
    };
    let mut lines = vec![
        format!("txid: {}", hex(&decoded.txid)),
        format!(
            "accepted: in chain block {} at DAA score {block_daa}",
            hex(&block)
        ),
        "bound: yes, each vault input to the scriptPublicKey the node reports it spent".into(),
    ];
    for trade in decoded.trades() {
        let t = trade.terms.terms();
        lines.push(format!("trade: {}", hex(&trade.terms.terms_hash())));
        lines.extend(summary::summary(&trade.terms.terms_hash(), t, block_daa));
        for leg in &trade.legs {
            let entry = match leg.entry {
                Entry::Settle => "settle".to_string(),
                Entry::Refund {
                    signer: Some(k),
                    party,
                } => format!("refund signed by {} ({})", hex(&k), party_name(party)),
                Entry::Refund { signer: None, .. } => {
                    "refund (the signer argument is not a 32-byte key)".to_string()
                }
            };
            let outcome = match leg.outcome() {
                Outcome::Delivered { amount, to } => {
                    format!("delivers exactly {amount} to {}", describe(t, &to))
                }
                Outcome::Refunded { to } => format!(
                    "refunds the vault UTXO home; the escrowed leg, if this transaction carries it, goes to {}",
                    describe(t, &to)
                ),
            };
            lines.push(format!(
                "leg: input {}, {}, {} vault {}, {entry}; {outcome}",
                leg.input_index,
                outpoint_text(&leg.outpoint),
                leg_name(leg.leg),
                hex(&leg.script_hash)
            ));
        }
    }
    lines.extend(v4_lines);
    for e in &decoded.refused {
        lines.push(format!("refused: {}", CliError::from(e.clone())));
    }
    print(out, &lines)
}
