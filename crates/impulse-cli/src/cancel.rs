// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `direct cancel build` and the cancellation check (spec/CLI.md, "direct cancel build (the
//! Direct refund)"). Direct terms escrow nothing, so a Direct trade's refund is a cancellation:
//! after the agreed expiry the buyer spends its Direct KAS cash back to itself, and a signed copy
//! of the abandoned Direct transaction then spends an input that no longer exists.
//!
//! Not one of impulse-core's builders: the transaction is built here with the builders' rules
//! and codes, rendered as an IPST (spec/IPST.md) and read back with impulse-core's IPST reader,
//! which recomputes every sighash. `ipst sign`, `ipst merge` and `submit` run [`check`] in place
//! of the core's terms check for such a document. Keyless: nothing here reads or holds a key.

use crate::build_cmd::{existing, node_now};
use crate::cli::{cap, hash_arg, print, CapArgs, Ctx};
use crate::error::CliError;
use crate::funds::{
    address_script, build_with_fee, outpoint_text, p2pk_address, parse_change, parse_outpoint,
    utxo_at, utxos_with,
};
use crate::json::hex;
use crate::summary::{self, Role};
use crate::terms_file::write_new;
use crate::txview::{self, Kind};
use clap::Args;
use impulse_core::locktime::INPUT_SEQUENCE;
use impulse_core::terms::{LegKind, SettlementMode, ValidatedTerms};
use impulse_core::tx::{
    min_output_value, min_relay_fee, sighash, FeePayment, Ipst, TxError, Utxo, IPST_VERSION,
    P2PK_BUDGET, STANDARD_MASS_CAP,
};
use kaspa_consensus_core::constants::{MAX_SOMPI, TX_VERSION_TOCCATA};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct CancelBuildArgs {
    /// The Direct trade's terms file.
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// Your side of the Direct trade. Only the buyer's KAS cash can be cancelled.
    #[arg(long, value_enum)]
    pub role: Role,
    /// Your x-only public key, 64 lowercase hex digits: the terms' key for --role.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// The IPST of the Direct transaction you cancel, signed or not: its input 1, your Direct
    /// cash, is the input this cancellation spends.
    #[arg(long, value_name = "FILE")]
    pub for_ipst: Option<PathBuf>,
    /// Your Direct input, <txid>:<index>; with --for-ipst it must be that transaction's input 1.
    /// Without either, your only UTXO of exactly the cash amount.
    #[arg(long, value_name = "TXID:INDEX")]
    pub direct_input: Option<String>,
    /// Where the change goes; default the P2PK address of --my-key.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// The exact fee in sompi; default the transaction's minimum relay fee.
    #[arg(long, value_name = "SOMPI")]
    pub fee: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// The x-only key of a version-0 P2PK Schnorr script.
pub(crate) fn p2pk_key(spk: &ScriptPublicKey) -> Option<[u8; 32]> {
    match (spk.version(), spk.script()) {
        (0, [0x20, key @ .., 0xac]) if key.len() == 32 => key.try_into().ok(),
        _ => None,
    }
}

/// A standard version-0 change script: P2PK, P2PK-ECDSA or P2SH, the scripts of the addresses
/// `--change` accepts.
pub(crate) fn standard_change(spk: &ScriptPublicKey) -> bool {
    let s = spk.script();
    spk.version() == 0
        && match s {
            [0x20, key @ .., 0xac] => key.len() == 32,
            [0x21, key @ .., 0xab] => key.len() == 33,
            [0xaa, 0x20, hash @ .., 0x87] => hash.len() == 32,
            _ => false,
        }
}

/// Builds the cancellation of `input`, a Direct input of native KAS at the P2PK address of its
/// party's key, with the fee payment (spec/CLI.md, "direct cancel build"): lock time
/// `expiry_daa`; input 0 the Direct input, then the fee inputs, all P2PK spends of that key;
/// output 0 the Direct input's amount to its own script, then the change. Refusals keep the
/// builders' codes.
pub(crate) fn build(
    terms: &ValidatedTerms,
    input: &Utxo,
    fee: &FeePayment,
) -> Result<Ipst, TxError> {
    let key = match p2pk_key(&input.entry.script_public_key) {
        Some(k) if input.entry.covenant_id.is_none() => k,
        _ => return Err(TxError::KasInput {
            index: 0,
            reason:
                "the Direct input of a cancellation is a version-0 P2PK UTXO without a covenant ID",
        }),
    };
    if fee.inputs.is_empty() {
        return Err(TxError::KasInput {
            index: 1,
            reason: "no fee input",
        });
    }
    for (i, utxo) in fee.inputs.iter().enumerate() {
        if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)
        {
            return Err(TxError::KasInput {
                index: 1 + i,
                reason: "a fee input of a cancellation is a version-0 P2PK UTXO of the cancelling key without a covenant ID",
            });
        }
    }
    let inputs: Vec<&Utxo> = std::iter::once(input).chain(&fee.inputs).collect();
    let mut seen = HashSet::new();
    for (index, utxo) in inputs.iter().enumerate() {
        if !seen.insert(utxo.outpoint) {
            return Err(TxError::DuplicateInput { index });
        }
    }
    let mut available: u64 = 0;
    for (index, utxo) in inputs.iter().enumerate() {
        let value = utxo.entry.amount;
        if value == 0 || value > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: Some(index),
                value,
            });
        }
        // Each value is at most MAX_SOMPI and so is the running total: no overflow.
        available += value;
        if available > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: None,
                value: available,
            });
        }
    }
    if !standard_change(&fee.change) {
        return Err(TxError::NonstandardChange);
    }
    let needed = input
        .entry
        .amount
        .checked_add(fee.fee)
        .ok_or(TxError::InsufficientFunds {
            available,
            needed: u64::MAX,
        })?;
    if available < needed {
        return Err(TxError::InsufficientFunds { available, needed });
    }
    // The Direct input goes home whole; the fee comes from the fee inputs (rule 5, docs/ENGINEERING-RULES.md).
    let mut outputs = vec![TransactionOutput::new(
        input.entry.amount,
        input.entry.script_public_key.clone(),
    )];
    if available > needed {
        let change = TransactionOutput::new(available - needed, fee.change.clone());
        let minimum = min_output_value(&change);
        if change.value < minimum {
            return Err(TxError::BelowMinKas {
                output: 1,
                value: change.value,
                minimum,
            });
        }
        outputs.push(change);
    }
    let entries: Vec<UtxoEntry> = inputs.iter().map(|u| u.entry.clone()).collect();
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        inputs
            .iter()
            .map(|u| {
                TransactionInput::new_with_compute_budget(
                    u.outpoint,
                    vec![],
                    INPUT_SEQUENCE,
                    P2PK_BUDGET,
                )
            })
            .collect(),
        outputs,
        terms.terms().expiry_daa,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let ipst = Ipst::from_json(&document(terms, &tx, &entries, key)?.to_string())?;
    let masses = ipst.masses();
    for (dimension, mass) in [
        ("compute", masses.compute),
        ("transient", masses.transient),
        ("storage", masses.storage),
    ] {
        if mass > STANDARD_MASS_CAP {
            return Err(TxError::Mass {
                dimension,
                mass,
                cap: STANDARD_MASS_CAP,
            });
        }
    }
    let minimum = min_relay_fee(masses.fee_mass);
    if fee.fee < minimum {
        return Err(TxError::FeeTooLow {
            fee: fee.fee,
            minimum,
        });
    }
    Ok(ipst)
}

/// The IPST document of an unsigned cancellation or token genesis (spec/IPST.md, "Document"):
/// every slot's signer is `key`, with its recomputed sighash and empty script parts around the
/// signature; each input with its own sequence and compute budget; each output with its covenant
/// binding, if any.
pub(crate) fn document(
    terms: &ValidatedTerms,
    tx: &Transaction,
    entries: &[UtxoEntry],
    key: [u8; 32],
) -> Result<Value, TxError> {
    let spk = |s: &ScriptPublicKey| json!({"version": s.version(), "script": hex(s.script())});
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for (i, (input, entry)) in tx.inputs.iter().zip(entries).enumerate() {
        inputs.push(json!({
            "transaction_id": hex(&input.previous_outpoint.transaction_id.as_bytes()),
            "index": input.previous_outpoint.index,
            "sequence": input.sequence.to_string(),
            "compute_budget": input.compute_commit.compute_budget().unwrap_or(P2PK_BUDGET),
            "utxo": {
                "amount": entry.amount.to_string(),
                "script_public_key": spk(&entry.script_public_key),
                "block_daa_score": entry.block_daa_score.to_string(),
                "is_coinbase": entry.is_coinbase,
                "covenant_id": entry.covenant_id.map(|c| hex(&c.as_bytes())),
            },
            "signer": hex(&key),
            "sighash": hex(&sighash(tx, entries, i)?),
            "signature": null,
            "script_before": "",
            "script_after": "",
        }));
    }
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .map(|o| {
            json!({
                "value": o.value.to_string(),
                "script_public_key": spk(&o.script_public_key),
                "covenant": o.covenant.map(|c| json!({
                    "authorizing_input": c.authorizing_input,
                    "covenant_id": hex(&c.covenant_id.as_bytes()),
                })),
            })
        })
        .collect();
    Ok(json!({
        "ipst": IPST_VERSION,
        "terms": hex(terms.canonical()),
        "lock_time": tx.lock_time.to_string(),
        "inputs": inputs,
        "outputs": outputs,
    }))
}

/// Whether the cancellation check, not the core's terms check, applies to `ipst`: Direct terms
/// whose input 0 spends a version-0 P2PK UTXO without a covenant ID. A Direct transaction's
/// input 0 is always the seller's token.
pub(crate) fn is_candidate(ipst: &Ipst) -> bool {
    ipst.terms().terms().settlement_mode == SettlementMode::Direct
        && ipst
            .entries()
            .first()
            .is_some_and(|e| e.covenant_id.is_none() && p2pk_key(&e.script_public_key).is_some())
}

/// The IPST's canonical text as a JSON value with every signature left out.
pub(crate) fn unsigned(ipst: &Ipst) -> Value {
    let mut v: Value = serde_json::from_str(&ipst.to_json()).expect("canonical IPST text is JSON");
    if let Some(inputs) = v.get_mut("inputs").and_then(Value::as_array_mut) {
        for input in inputs {
            input["signature"] = Value::Null;
        }
    }
    v
}

/// The cancellation check (spec/CLI.md, "direct cancel build", "The cancellation check"): input
/// 0 is the buyer's Direct KAS cash, and the document is the cancellation [`build`] makes from
/// its own parts, signatures aside (`IPST_TERMS_MISMATCH`; a rebuild refusal keeps its code).
/// Returns the fee and the change output.
pub(crate) fn check(ipst: &Ipst) -> Result<(u64, Option<TransactionOutput>), CliError> {
    let t = ipst.terms().terms();
    let mismatch = |reason| CliError::from(TxError::IpstTermsMismatch { reason });
    let entry = &ipst.entries()[0];
    let buyer_cash = address_script(&p2pk_address(&t.buyer_key, t.network));
    if t.cash_leg.kind != LegKind::Kas
        || entry.script_public_key != buyer_cash
        || entry.amount != t.cash_leg.amount
    {
        return Err(mismatch(
            "input 0 of a Direct cancellation must be the buyer's KAS cash: a UTXO at the P2PK address of buyer_key holding exactly the cash amount",
        ));
    }
    let tx = ipst.transaction();
    let utxo = |i: usize| Utxo {
        outpoint: tx.inputs[i].previous_outpoint,
        entry: ipst.entries()[i].clone(),
    };
    let change = tx.outputs.get(1).cloned();
    let fee = FeePayment {
        inputs: (1..tx.inputs.len()).map(utxo).collect(),
        fee: ipst.fee(),
        change: change
            .as_ref()
            .unwrap_or(&tx.outputs[0])
            .script_public_key
            .clone(),
    };
    let rebuilt = build(ipst.terms(), &utxo(0), &fee)?;
    if unsigned(&rebuilt) != unsigned(ipst) {
        return Err(mismatch(
            "the document is not the cancellation direct cancel build makes from its own inputs",
        ));
    }
    Ok((ipst.fee(), change))
}

/// The Direct transaction `--for-ipst` names (spec/CLI.md, "direct cancel build", check 5): an
/// IPST of the trade's terms that is not a cancellation, whose input 1 is the buyer's Direct
/// cash. Returns its transaction ID and that input's outpoint.
fn direct_of(
    ctx: &Ctx,
    path: &Path,
    terms: &ValidatedTerms,
) -> Result<([u8; 32], TransactionOutpoint), CliError> {
    let doc = crate::ipst_cmd::read_ipst(ctx, path)?;
    let mismatch = |why: String| {
        CliError::new(
            "CLI_CANCEL_INPUT_MISMATCH",
            format!("--for-ipst {}: {why}", path.display()),
        )
    };
    if doc.terms().terms_hash() != terms.terms_hash() {
        return Err(mismatch(format!(
            "it is for terms {}, not those of --terms ({})",
            hex(&doc.terms().terms_hash()),
            hex(&terms.terms_hash())
        )));
    }
    if is_candidate(&doc) {
        return Err(mismatch(
            "it is a cancellation, not a Direct transaction".into(),
        ));
    }
    let t = terms.terms();
    let buyer_cash = address_script(&p2pk_address(&t.buyer_key, t.network));
    let is_cash = doc.entries().get(1).is_some_and(|e| {
        e.script_public_key == buyer_cash
            && e.covenant_id.is_none()
            && e.amount == t.cash_leg.amount
    });
    if !is_cash {
        return Err(mismatch(
            "its input 1 is not the buyer's Direct cash, a UTXO at the P2PK address of buyer_key without a covenant ID holding exactly the cash amount".into(),
        ));
    }
    let tx = doc.transaction();
    Ok((tx.id().as_bytes(), tx.inputs[1].previous_outpoint))
}

/// `impulse direct cancel build` (spec/CLI.md, "direct cancel build (the Direct refund)").
pub(crate) fn cancel_build(
    ctx: &Ctx,
    a: CancelBuildArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    crate::node::check_transport(&a.node, ctx.network)?;
    let trade = existing(ctx, &a.terms)?;
    let terms = trade.terms();
    let t = terms.terms();
    if t.settlement_mode != SettlementMode::Direct {
        return Err(CliError::new(
            "CLI_CANCEL_NOT_DIRECT",
            "these are vault terms: a vault leg goes home with refund build",
        ));
    }
    let my_key = hash_arg("my-key", &a.my_key)?;
    let (party, leg) = match a.role {
        Role::Buyer => (t.buyer_key, &t.cash_leg),
        Role::Seller => (t.seller_key, &t.asset_leg),
    };
    if party != my_key {
        return Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            format!(
                "the terms name {}_key {}, --my-key is {}; these terms are not yours as {0}",
                a.role.name(),
                hex(&party),
                hex(&my_key)
            ),
        ));
    }
    if a.role != Role::Buyer || leg.kind != LegKind::Kas {
        return Err(CliError::new(
            "CLI_CANCEL_INPUT_NOT_KAS",
            format!(
                "the {}'s Direct input is a KCC-20 token, and no builder spends a token back to its holder; only the buyer's KAS cash can be cancelled",
                a.role.name()
            ),
        ));
    }
    let cap_line = cap(ctx, &a.cap, terms)?;
    let direct = match &a.for_ipst {
        Some(path) => Some(direct_of(ctx, path, terms)?),
        None => None,
    };
    let named = match &a.direct_input {
        Some(text) => Some(parse_outpoint("--direct-input", text)?),
        None => None,
    };
    if let (Some((txid, of_ipst)), Some(named)) = (&direct, &named) {
        if of_ipst != named {
            return Err(CliError::new(
                "CLI_CANCEL_INPUT_MISMATCH",
                format!(
                    "--direct-input {} is not the input 1 of the --for-ipst Direct transaction {}, which is {}",
                    outpoint_text(named),
                    hex(txid),
                    outpoint_text(of_ipst)
                ),
            ));
        }
    }
    let (node, daa) = node_now(ctx, &a.node)?;
    let net = ctx.network;
    let home = p2pk_address(&my_key, net);
    let home_script = address_script(&home);
    let not_found = |what: String| CliError::new("CLI_UTXO_NOT_FOUND", what);
    let wanted = match (&direct, named) {
        (Some((txid, outpoint)), _) => Some((
            *outpoint,
            format!(
                "the input 1 of the --for-ipst Direct transaction {}",
                hex(txid)
            ),
        )),
        (None, Some(outpoint)) => Some((outpoint, "--direct-input".to_string())),
        (None, None) => None,
    };
    let input = match wanted {
        Some((outpoint, what)) => {
            let utxo = utxo_at(node.as_ref(), &outpoint, &home_script, None, net, &what)
                .map_err(|e| {
                    if direct.is_some() {
                        CliError::new(
                            e.code(),
                            format!(
                                "{}: it is spent, so that Direct transaction cannot be submitted; there is nothing to cancel",
                                e.detail()
                            ),
                        )
                    } else {
                        e
                    }
                })?;
            if utxo.entry.amount != leg.amount {
                return Err(not_found(format!(
                    "{what} {} holds {} sompi, not exactly the cash amount of {}",
                    outpoint_text(&outpoint),
                    utxo.entry.amount,
                    leg.amount
                )));
            }
            utxo
        }
        None => {
            let mut exact: Vec<Utxo> = utxos_with(node.as_ref(), &home_script, None, net)?
                .into_iter()
                .filter(|u| u.entry.amount == leg.amount)
                .collect();
            match exact.len() {
                0 => {
                    return Err(not_found(format!(
                        "your Direct input: no UTXO of exactly {} sompi at {home}",
                        leg.amount
                    )))
                }
                1 => exact.remove(0),
                _ => {
                    return Err(CliError::new(
                        "CLI_CANCEL_INPUT_AMBIGUOUS",
                        format!(
                            "{home} holds {} UTXOs of exactly {} sompi, and a cancellation stops only a Direct transaction that spends its own input: name the Direct transaction with --for-ipst, or the input with --direct-input: {}",
                            exact.len(),
                            leg.amount,
                            exact
                                .iter()
                                .map(|u| outpoint_text(&u.outpoint))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ))
                }
            }
        }
    };
    let change = match &a.change {
        Some(c) => parse_change(c, net)?,
        None => home_script.clone(),
    };
    let mut candidates: Vec<Utxo> = utxos_with(node.as_ref(), &home_script, None, net)?
        .into_iter()
        .filter(|u| u.outpoint != input.outpoint)
        .collect();
    candidates.sort_by(|x, y| y.entry.amount.cmp(&x.entry.amount));
    if candidates.is_empty() {
        return Err(not_found(format!(
            "no UTXO at {home} other than the Direct input to pay the fee"
        )));
    }
    let ipst = build_with_fee(&candidates, a.fee, &change, |p| build(terms, &input, p))?;
    write_new(&a.out, &ipst.to_json())?;
    let mut lines = summary::summary(&terms.terms_hash(), t, daa);
    lines.push(cap_line);
    lines.extend(txview::lines(&ipst, Kind::Cancel(Role::Buyer), None));
    lines.push(match &direct {
        Some((txid, outpoint)) => format!(
            "cancels: Direct transaction {}, its input 1 {}",
            hex(txid),
            outpoint_text(outpoint)
        ),
        None => format!(
            "cancels: no Direct transaction named; only one that spends {} (name it with --for-ipst)",
            outpoint_text(&input.outpoint)
        ),
    });
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}
