// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse zk status` and `impulse zk receipt verify` (spec/V3-ZK.md section 11, spec/V2.md
//! section 4.8): what a node showed about a v3 transaction's acceptance, with the fixed
//! disclaimer and the finality state it reports, optionally signed by whoever ran it.
//!
//! The signed part is the version 1 receipt of `receipt` (terms hash, transaction ID, accepting
//! block, DAA score, depth), whose digest and signature are unchanged; a v3 receipt wraps it with
//! the disclaimer and the state, which are text and are not signed. The terms hash is the terms
//! v3 hash. As for version 1, a receipt states that a transaction was accepted; that it settles
//! the terms is the signer's assertion only.

use crate::cli::{connect, hash_arg, print, Ctx};
use crate::error::CliError;
use crate::json::{hex, parse_strict, Json, Obj};
use crate::node;
use crate::receipt::Receipt;
use crate::terms_file::{network_name, read_text, write_new};
use crate::zk_cmd::{read_terms_v3, ZkReceiptVerifyArgs, ZkStatusArgs, DISCLAIMER};
use std::io::Write;

/// Format tag of a v3 receipt file.
pub const RECEIPT_FORMAT: &str = "impulse-zk-receipt/1";

/// The note every v3 receipt and `zk status` result carries: what a receipt does not establish.
pub const UNBOUND_NOTE: &str = "terms binding: not checked. A receipt states that txid was accepted; that txid settles terms_hash is the signer's assertion only; impulse decode <txid> shows which trades the transaction spends";

/// The finality state of spec/V2.md section 4.8 an observation reports.
fn state(depth: u64, final_depth: Option<u64>) -> (&'static str, String) {
    match final_depth {
        Some(f) if depth >= f => (
            "final",
            format!(
                "state: final: the accepting block is {depth} DAA scores below the virtual, at least the final depth {f} you chose; that depth is your choice, not a guarantee of the network"
            ),
        ),
        _ => (
            "accepted",
            "state: accepted: a chain block of your node's virtual selected chain accepted this transaction; it can still be reorganised out".to_string(),
        ),
    }
}

pub(crate) fn status(ctx: &Ctx, a: ZkStatusArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v3(ctx, &a.terms)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let node = connect(ctx, &a.node, ctx.network)?;
    let observation = node::observe(node.as_ref(), ctx.network, terms.terms_hash(), txid, from)?;
    let (state_name, state_line) = state(observation.depth, a.final_depth);
    let mut lines = vec![DISCLAIMER.to_string(), state_line];
    match (a.key_file, a.out, a.min_depth) {
        (Some(key_file), Some(path), Some(min_depth)) => {
            if observation.depth < min_depth {
                return Err(CliError::new(
                    "CLI_DEPTH_BELOW_MINIMUM",
                    format!(
                        "depth {} is below --min-depth {min_depth}; wait and run status again",
                        observation.depth
                    ),
                ));
            }
            let receipt = Receipt::sign(observation, &key_file, ctx.mainnet_explicit)?;
            let doc = Json::Obj(vec![
                ("format", Json::Str(RECEIPT_FORMAT.into())),
                ("disclaimer", Json::Str(DISCLAIMER.into())),
                ("state", Json::Str(state_name.into())),
                ("receipt", receipt.to_json()),
            ]);
            write_new(&path, &doc.render())?;
            lines.push(receipt.render().trim_end().to_string());
            lines.push(format!("wrote: {}", path.display()));
        }
        _ => lines.push(observation.render().trim_end().to_string()),
    }
    lines.push(UNBOUND_NOTE.to_string());
    print(out, &lines)
}

pub(crate) fn receipt_verify(
    ctx: &Ctx,
    a: ZkReceiptVerifyArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let malformed = |why: String| CliError::new("RECEIPT_MALFORMED", why);
    let value = parse_strict(&read_text(&a.receipt)?).map_err(malformed)?;
    let o = Obj::new("receipt file", &value).map_err(malformed)?;
    o.keys(&["format", "disclaimer", "state", "receipt"], &[])
        .map_err(malformed)?;
    if o.str("format").map_err(malformed)? != RECEIPT_FORMAT {
        return Err(malformed("receipt file: unknown format".into()));
    }
    if o.str("disclaimer").map_err(malformed)? != DISCLAIMER {
        return Err(malformed(
            "receipt file: the disclaimer is not the fixed text".into(),
        ));
    }
    let state = o.str("state").map_err(malformed)?;
    if !matches!(state, "accepted" | "final") {
        return Err(malformed(
            "receipt file: state is neither accepted nor final".into(),
        ));
    }
    let inner = serde_json::to_string(o.get("receipt").map_err(malformed)?)
        .map_err(|e| malformed(e.to_string()))?;
    let receipt = Receipt::parse(&inner)?;
    if receipt.observation.network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the receipt is for {}; pass --network {0} to act on it",
                network_name(receipt.observation.network)
            ),
        ));
    }
    let expected = a
        .signer
        .as_deref()
        .map(|s| hash_arg("signer", s))
        .transpose()?;
    let your_terms = match (&a.terms, &a.terms_hash) {
        (Some(path), _) => Some((read_terms_v3(ctx, path)?.terms_hash(), "--terms")),
        (None, Some(h)) => Some((hash_arg("terms-hash", h)?, "--terms-hash")),
        (None, None) => None,
    };
    let your_txid = a.txid.as_deref().map(|t| hash_arg("txid", t)).transpose()?;
    receipt.verify_signature()?;
    if let Some(expected) = &expected {
        receipt.check_signer(expected)?;
    }
    if let Some((terms_hash, _)) = &your_terms {
        receipt.check_terms_hash(terms_hash)?;
    }
    if let Some(txid) = &your_txid {
        receipt.check_txid(txid)?;
    }
    let ob = &receipt.observation;
    let chain = match &a.node {
        Some(url) => {
            let node = connect(ctx, url, ob.network)?;
            node::verify_receipt(node.as_ref(), &receipt)?;
            format!(
                "chain: txid {} of terms {} accepted in {} at DAA score {}, depth now at least {}",
                hex(&ob.txid),
                hex(&ob.terms_hash),
                hex(&ob.accepting_block),
                ob.daa_score,
                ob.depth
            )
        }
        None => "chain: on-chain facts not checked (pass --node)".into(),
    };
    let lines = vec![
        DISCLAIMER.to_string(),
        format!(
            "ok: the signature verifies for signer {}",
            hex(&receipt.signer)
        ),
        format!("state when signed: {state}"),
        format!(
            "terms_hash: {}, {}",
            hex(&ob.terms_hash),
            match your_terms {
                Some((_, flag)) => format!("matches {flag}"),
                None => "not compared with your trade: pass --terms or --terms-hash".into(),
            }
        ),
        format!(
            "txid: {}, {}",
            hex(&ob.txid),
            match your_txid {
                Some(_) => "matches --txid",
                None => "not compared: pass --txid",
            }
        ),
        match expected {
            Some(_) => "signer: matches --signer".into(),
            None => "signer: not authenticated: anyone can sign a receipt with their own key; pass --signer <x-only key> to require a known signer".into(),
        },
        chain,
        UNBOUND_NOTE.to_string(),
    ];
    print(out, &lines)
}
