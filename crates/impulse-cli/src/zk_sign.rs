// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse zk ipst sign`, `ipst merge`, `ipst raw` and `zk submit` (spec/V3-ZK.md section 11):
//! the v1 commands of `ipst_cmd` for IPST version 4. Every IPST the CLI is given passes the v3
//! terms check (`IpstV3::verify_against_terms`) before it is signed, merged or broadcast, which
//! rebuilds the transaction with the v3 builders from the document's own inputs and proof and
//! compares it byte for byte. Signing goes through `signing::sign` only.
//!
//! Adapted from `ipst_cmd` (relicensed, see NOTICE). The transaction analysis it shares with the
//! v1 commands (`txview`, the outflow of the signer's own funds) reads the v1 view of the
//! document, which has the same inputs, outputs and slots.

use crate::build_cmd::{TemplateArgs, Templates};
use crate::cli::{self, connect, funder, hash_arg, print, Ctx, PartyArgs};
use crate::error::CliError;
use crate::funds::{address_script, p2pk_address, parse_change};
use crate::ipst_cmd::{signed_tx_text, SignedTxFile};
use crate::json::hex;
use crate::node::{self, Node};
use crate::signing::{self, SignRequest};
use crate::summary::{self, Role};
use crate::terms_file::{network_name, read_text, write_new};
use crate::trade::{check_kas_minimum, check_pinned, leg_name};
use crate::txview::{self, Kind};
use crate::value_cap::CapPolicy;
use crate::zk_cmd::{
    read_terms_v3, DaaArgs, SignRole, ZkMergeArgs, ZkRawArgs, ZkSignArgs, ZkSubmitArgs,
};
use impulse_core::locktime::check_tx_is_finalized;
use impulse_core::template::LegIndex;
use impulse_core::terms::{LegKind, Network, Terms};
use impulse_core::tx::{min_relay_fee, IpstKind, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT};
use impulse_core::zk::{IpstV3, VaultV3, ZkError};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutput};
use std::io::Write;
use std::path::Path;

/// Reads an IPST file (version 4) on the command's network.
pub(crate) fn read_ipst(ctx: &Ctx, path: &Path) -> Result<IpstV3, CliError> {
    let ipst = IpstV3::from_json(&read_text(path)?)?;
    let network = ipst.terms().terms().fields.network;
    if network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the IPST is for {}; pass --network {0} to act on it",
                network_name(network)
            ),
        ));
    }
    Ok(ipst)
}

/// The current DAA score: from a checked node, or on testnet a typed one.
fn current_daa(ctx: &Ctx, args: &DaaArgs) -> Result<u64, CliError> {
    match (args.daa, &args.node) {
        (Some(_), _) if ctx.network == Network::Mainnet => Err(CliError::new(
            "CLI_MAINNET_NEEDS_NODE",
            "on mainnet the current DAA score is read from your node, not typed: pass --node <url>",
        )),
        (Some(daa), _) => Ok(daa),
        (None, Some(url)) => {
            let node = connect(ctx, url, ctx.network)?;
            node::creation_daa(node.as_ref(), ctx.network)
        }
        (None, None) => Err(CliError::new(
            "CLI_NODE_URL_INVALID",
            "no node URL: pass --node <url> or --daa <score>",
        )),
    }
}

struct Checked {
    kind: IpstKind,
    fee: u64,
    change: Option<TransactionOutput>,
}

/// The v3 terms check of an IPST, with the templates the user gave.
fn terms_check(ipst: &IpstV3, templates: &TemplateArgs, daa: u64) -> Result<Checked, CliError> {
    // The escrowed legs instantiate before anything else is read.
    for leg in LegIndex::ALL {
        match VaultV3::instantiate_existing(ipst.terms(), leg) {
            Ok(_) => {}
            Err(ZkError::Template(impulse_core::template::TemplateError::NoVault { .. }))
                if leg == LegIndex::Cash => {}
            Err(e) => return Err(e.into()),
        }
    }
    let templates = Templates::read(templates)?;
    let (asset, cash) = templates.for_check(&ipst.terms().terms().fields)?;
    let checked = ipst.verify_against_terms(asset, cash, daa)?;
    Ok(Checked {
        kind: checked.kind,
        fee: checked.fee,
        change: checked.change,
    })
}

fn is_funding(kind: IpstKind) -> bool {
    matches!(kind, IpstKind::FundKas | IpstKind::FundKcc20(_))
}

/// The signer's role check: `--my-key` is the role's key, and a party's own destinations pay it
/// or equal its pins. Returns the `you:` line.
fn check_signer(
    t: &Terms,
    network: Network,
    a: &ZkSignArgs,
    my_key: [u8; 32],
) -> Result<String, CliError> {
    let party_role = match a.role {
        SignRole::Buyer => Some(Role::Buyer),
        SignRole::Seller => Some(Role::Seller),
        SignRole::Authority | SignRole::Payer => None,
    };
    if let Some(role) = party_role {
        let party = cli::party(
            network,
            &PartyArgs {
                role,
                my_key: a.my_key.clone(),
                my_delivery: a.my_delivery.clone(),
                my_proceeds: a.my_proceeds.clone(),
                my_refund: a.my_refund.clone(),
            },
        )?;
        return summary::check_party(t, &party);
    }
    if a.my_delivery.is_some() || a.my_proceeds.is_some() || a.my_refund.is_some() {
        return Err(CliError::new(
            "CLI_DESTINATION_PIN_INVALID",
            format!(
                "the {} has no destination in the terms: --my-delivery, --my-proceeds and --my-refund are for the buyer and the seller",
                a.role.name()
            ),
        ));
    }
    let named = [
        ("seller", Some(t.seller_key)),
        ("buyer", Some(t.buyer_key)),
        ("authority", t.authority_key),
    ];
    match a.role {
        SignRole::Authority if t.authority_key == Some(my_key) => Ok(format!(
            "you: authority, authority_key {}",
            hex(&my_key)
        )),
        SignRole::Authority => Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            format!(
                "the terms name authority_key {}, --my-key is {}; these terms are not yours as authority",
                t.authority_key.map_or_else(|| "none".into(), |k| hex(&k)),
                hex(&my_key)
            ),
        )),
        _ => match named.iter().find(|(_, k)| *k == Some(my_key)) {
            Some((name, _)) => Err(CliError::new(
                "CLI_ROLE_KEY_MISMATCH",
                format!("--my-key is the terms' {name}_key: sign as --role {name}"),
            )),
            None => Ok(format!(
                "you: payer, a key with no role in the terms, {}",
                hex(&my_key)
            )),
        },
    }
}

/// A funding: signed by its leg's depositor only, its terms still fundable at `daa`, and a
/// KCC-20 deposit's carrier and authorizer as the signer states them.
fn check_funding(
    ctx: &Ctx,
    a: &ZkSignArgs,
    ipst: &IpstV3,
    kind: IpstKind,
    daa: u64,
) -> Result<(), CliError> {
    let leg = match kind {
        IpstKind::FundKcc20(leg) => leg,
        _ => LegIndex::Cash,
    };
    let by = funder(leg);
    let role_matches = matches!(
        (by, a.role),
        (Role::Buyer, SignRole::Buyer) | (Role::Seller, SignRole::Seller)
    );
    if !role_matches {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "this IPST funds the {} leg, which the {} funds; you sign as the {}",
                leg_name(leg),
                by.name(),
                a.role.name()
            ),
        ));
    }
    let t = &ipst.terms().terms().fields;
    ipst.terms()
        .validate_creation(&impulse_core::terms::CreationContext::new(ctx.network, daa))?;
    check_kas_minimum(t)?;
    check_pinned(t)?;
    if let IpstKind::FundKcc20(_) = kind {
        let outputs = &ipst.transaction().outputs;
        let carrier = a.carrier.unwrap_or(MIN_KCC20_OUTPUT);
        let authorizer = a.authorizer.unwrap_or(MIN_KAS_OUTPUT);
        if outputs[0].value != carrier || outputs[1].value != authorizer {
            return Err(CliError::new(
                "CLI_IPST_DEPOSIT_MISMATCH",
                format!(
                    "the deposit puts {} sompi on the escrowed token and {} on the authorizer; you confirm {carrier} and {authorizer} (pass --carrier and --authorizer to confirm other amounts)",
                    outputs[0].value, outputs[1].value
                ),
            ));
        }
    }
    Ok(())
}

const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;

/// Every check of `zk ipst sign`, then the signatures.
pub(crate) fn sign(
    ctx: &Ctx,
    a: ZkSignArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    if crate::zkh_sign::is_v5(&a.ipst) {
        return crate::zkh_sign::sign(ctx, a, out, notes);
    }
    let mut ipst = read_ipst(ctx, &a.ipst)?;
    let my_key = hash_arg("my-key", &a.my_key)?;
    let agreed = read_terms_v3(ctx, &a.terms)?.terms_hash();
    if agreed != ipst.terms().terms_hash() {
        return Err(CliError::new(
            "CLI_IPST_TERMS_NOT_AGREED",
            format!(
                "the IPST is for terms {}, not the terms you agreed to ({}); do not sign it",
                hex(&ipst.terms().terms_hash()),
                hex(&agreed)
            ),
        ));
    }
    let t = ipst.terms().terms().fields.clone();
    let you = check_signer(&t, ctx.network, &a, my_key)?;
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&ipst, &a.templates, daa)?;
    let kind = checked.kind;
    if (a.carrier.is_some() || a.authorizer.is_some()) && !matches!(kind, IpstKind::FundKcc20(_)) {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--carrier and --authorizer confirm a KCC-20 funding's deposit",
        ));
    }
    if is_funding(kind) {
        check_funding(ctx, &a, &ipst, kind, daa)?;
    }
    let policy = CapPolicy::new(ctx.env.max_value, a.cap.i_accept_the_risk)?;
    let cap_line = policy.check(&t, a.cap.kas_equivalent)?;
    let mine: Vec<usize> = ipst
        .pending()
        .into_iter()
        .filter(|&i| ipst.slots()[i].signer() == Some(my_key))
        .collect();
    if mine.is_empty() {
        return Err(CliError::new(
            "CLI_IPST_NOTHING_TO_SIGN",
            format!("no unsigned input of this IPST is for {}", hex(&my_key)),
        ));
    }
    let expected_change = match &a.change {
        Some(c) => parse_change(c, t.network)?,
        None => address_script(&p2pk_address(&my_key, t.network)),
    };
    let max_fee = match a.max_fee {
        Some(m) => m,
        None => min_relay_fee(ipst.masses().fee_mass).saturating_mul(2),
    };
    let max_topup = a.max_topup.unwrap_or(0);
    let view = Kind::Built(kind);
    let first_fee_input = txview::trade_inputs(view, ipst.as_v1());
    let pays_fee = mine.iter().any(|&i| i >= first_fee_input);
    let my_fee_inputs = (first_fee_input..ipst.slots().len())
        .filter(|&i| ipst.slots()[i].signer() == Some(my_key))
        .count();
    if pays_fee {
        if let Some(change) = &checked.change {
            if change.script_public_key != expected_change {
                return Err(CliError::new(
                    "CLI_IPST_CHANGE_NOT_MINE",
                    format!(
                        "you sign a fee input, and the change of {} sompi goes to {}, not to {}",
                        change.value,
                        summary::kas_address(
                            t.network,
                            change.script_public_key.version(),
                            change.script_public_key.script()
                        ),
                        summary::kas_address(
                            t.network,
                            expected_change.version(),
                            expected_change.script()
                        )
                    ),
                ));
            }
        }
        if a.max_fee.is_none() && my_fee_inputs > DEFAULT_FEE_LIMIT_INPUTS {
            return Err(CliError::new(
                "CLI_IPST_FEE_TOO_HIGH",
                format!(
                    "you sign {my_fee_inputs} fee inputs, and the default fee limit covers at most {DEFAULT_FEE_LIMIT_INPUTS}: the fee is {} sompi; pass --max-fee to accept it",
                    checked.fee
                ),
            ));
        }
        if checked.fee > max_fee {
            return Err(CliError::new(
                "CLI_IPST_FEE_TOO_HIGH",
                format!(
                    "you sign a fee input, and the fee is {} sompi, above {max_fee}; pass --max-fee to accept more",
                    checked.fee
                ),
            ));
        }
        let topup = txview::payer_cost(view, ipst.as_v1());
        if !is_funding(kind) && topup > max_topup {
            return Err(CliError::new(
                "CLI_IPST_TOPUP_TOO_HIGH",
                format!(
                    "you sign a fee input, and the fee inputs also put {topup} sompi into trade outputs (under-funded carriers or authorizers topped up), above {max_topup}; pass --max-topup to accept more"
                ),
            ));
        }
    }
    let mut outflow_line = None;
    if let Some((outflow, expected)) = outflow(&a, &ipst, kind, my_key, &expected_change) {
        let limit = if pays_fee {
            expected.saturating_add(max_fee).saturating_add(max_topup)
        } else {
            expected
        };
        if outflow > limit {
            return Err(CliError::new(
                "CLI_IPST_OUTFLOW_TOO_HIGH",
                format!(
                    "the inputs you sign hold {outflow} sompi of your KAS more than comes back to you, above the {limit} you accept ({expected} for the trade, and when you sign a fee input --max-fee {max_fee} and --max-topup {max_topup}); check where the change goes (--change) and what the inputs carry"
                ),
            ));
        }
        if let Some(cap) = policy.limit() {
            if outflow > cap {
                return Err(CliError::new(
                    "CLI_VALUE_CAP_EXCEEDED",
                    format!(
                        "you commit {outflow} sompi of your KAS, above the cap of {cap} sompi; pass --i-accept-the-risk to proceed"
                    ),
                ));
            }
        }
        outflow_line = Some(format!(
            "you commit: {outflow} sompi of your KAS (the inputs you sign less what comes back to you), within {limit}"
        ));
    }
    for &i in &mine {
        let digest = ipst.slots()[i]
            .sighash()
            .expect("a slot with a signer has a sighash");
        let signed = signing::sign(&SignRequest {
            key_file: &a.key_file,
            network: t.network,
            mainnet_explicit: ctx.mainnet_explicit,
            expected_signer: Some(my_key),
            digest,
        })?;
        ipst.add_signature(i, &signed.signature)?;
    }
    write_new(&a.out, &ipst.to_json())?;
    let mut lines = vec![crate::zk_cmd::DISCLAIMER.to_string()];
    lines.extend(summary::summary(&ipst.terms().terms_hash(), &t, daa));
    lines.push(you);
    lines.push(cap_line);
    lines.extend(crate::zk_cmd::tx_lines(&ipst, kind, None));
    lines.extend(outflow_line);
    lines.push(format!(
        "signed: {}",
        mine.iter()
            .map(|i| format!("input {i}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

/// The KAS the signer commits: the inputs it signs that hold its own funds (every input it signs,
/// except the vault inputs of a settle or refund), less what comes back to it; and what the
/// trade itself takes from it (a funding's deposit). None when the signer signs none of its own
/// funds.
fn outflow(
    a: &ZkSignArgs,
    ipst: &IpstV3,
    kind: IpstKind,
    my_key: [u8; 32],
    expected_change: &ScriptPublicKey,
) -> Option<(u64, u64)> {
    let view = ipst.as_v1();
    let t = &ipst.terms().terms().fields;
    let k = Kind::Built(kind);
    let n_in = txview::trade_inputs(k, view);
    let n_out = txview::trade_outputs(k, view);
    let vault_inputs = match kind {
        IpstKind::Settle | IpstKind::Refund { .. } => n_in,
        _ => 0,
    };
    let own: Vec<usize> = (vault_inputs..ipst.slots().len())
        .filter(|&i| ipst.slots()[i].signer() == Some(my_key))
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
        IpstKind::Settle | IpstKind::Refund { .. } => 0,
        // Terms v3 are never Direct.
        IpstKind::Direct => return None,
    };
    let _ = a;
    Some((held.saturating_sub(back), expected))
}

pub(crate) fn merge(ctx: &Ctx, a: ZkMergeArgs, out: &mut dyn Write) -> Result<(), CliError> {
    if crate::zkh_sign::is_v5(&a.ipsts[0]) {
        return crate::zkh_sign::merge(ctx, a, out);
    }
    let mut merged = read_ipst(ctx, &a.ipsts[0])?;
    for path in &a.ipsts[1..] {
        merged = merged.combine(&read_ipst(ctx, path)?)?;
    }
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&merged, &a.templates, daa)?;
    write_new(&a.out, &merged.to_json())?;
    let mut lines = crate::zk_cmd::tx_lines(&merged, checked.kind, None);
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

pub(crate) fn raw(ctx: &Ctx, a: ZkRawArgs, out: &mut dyn Write) -> Result<(), CliError> {
    if crate::zkh_sign::is_v5(&a.ipst) {
        return crate::zkh_sign::raw(ctx, a, out);
    }
    let ipst = read_ipst(ctx, &a.ipst)?;
    let tx = ipst.finalize()?;
    write_new(&a.out, &signed_tx_text(&tx))?;
    print(
        out,
        &[
            format!("txid: {}", hex(&tx.id().as_bytes())),
            format!("wrote: {}", a.out.display()),
        ],
    )
}

pub(crate) fn submit(ctx: &Ctx, a: ZkSubmitArgs, out: &mut dyn Write) -> Result<(), CliError> {
    if crate::zkh_sign::is_v5(&a.ipst) {
        return crate::zkh_sign::submit(ctx, a, out);
    }
    node::check_transport(&a.node, ctx.network)?;
    // The file is created before anything is read or submitted, so a path that cannot take it
    // refuses with nothing sent; it is removed again on any refusal below.
    let mut file = match &a.signed_tx_out {
        Some(path) => Some(SignedTxFile::create(path)?),
        None => None,
    };
    if a.flip_proof_bit && ctx.network != Network::Testnet {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            "--flip-proof-bit is a fault test on testnet only; this network is mainnet",
        ));
    }
    if a.flip_proof_bit && a.signed_tx_out.is_some() {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--flip-proof-bit submits a tampered copy: it writes no signed-transaction file",
        ));
    }
    let ipst = read_ipst(ctx, &a.ipst)?;
    let node: Box<dyn Node> = connect(ctx, &a.node, ctx.network)?;
    let daa = node::creation_daa(node.as_ref(), ctx.network)?;
    let checked = terms_check(&ipst, &a.templates, daa)?;
    let tx = ipst.finalize()?;
    if a.flip_proof_bit {
        return flip_and_submit(&ipst, tx, node.as_ref(), ctx.network, out);
    }
    if let Err(e) = check_tx_is_finalized(&tx, daa, 0) {
        return Err(CliError::new(
            "CLI_TX_NOT_FINAL",
            format!(
                "lock time {}: the node accepts it once its virtual DAA score is above {} (now {daa}): {e}",
                tx.lock_time, tx.lock_time
            ),
        ));
    }
    // A broadcast cannot be undone: the file is complete before the node sees the transaction.
    if let Some(f) = &mut file {
        f.write(&signed_tx_text(&tx))?;
    }
    let submitted = node::submit(node.as_ref(), &tx, ctx.network).map_err(|e| match &file {
        Some(f) => CliError::new(
            e.code(),
            format!(
                "{}; {} is removed. If the node took the transaction all the same, impulse status shows {} accepted: then write the file with impulse zk ipst raw",
                e.detail(),
                f.path.display(),
                hex(&tx.id().as_bytes())
            ),
        ),
        None => e,
    })?;
    let mut lines = crate::zk_cmd::tx_lines(&ipst, checked.kind, None);
    lines.push(format!("from_block: {}", hex(&submitted.from_block)));
    lines.push(format!("submitted: {}", hex(&submitted.txid)));
    if let Some(f) = &mut file {
        f.keep = true;
        lines.push(format!("signed_tx: {}", f.path.display()));
    }
    let _ = (LegKind::Kas, MIN_KAS_OUTPUT);
    print(out, &lines)
}

/// Fault test: the signed settle with one bit of the proof flipped, submitted so the node can
/// refuse it. The proof is not covered by any signature, so the copy differs from the real
/// transaction in that bit alone.
pub(crate) fn flip_and_submit(
    ipst: &IpstV3,
    mut tx: kaspa_consensus_core::tx::Transaction,
    node: &dyn Node,
    network: Network,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let proof = ipst.proof().ok_or_else(|| {
        CliError::new(
            "TX_WRONG_MODE",
            "this IPST carries no proof: only a settle does",
        )
    })?;
    let script = &mut tx.inputs[0].signature_script;
    let at = script
        .windows(proof.as_bytes().len())
        .position(|w| w == proof.as_bytes())
        .ok_or_else(|| {
            CliError::new(
                "TX_ENCODING",
                "the proof is not in input 0's signature script",
            )
        })?;
    script[at] ^= 1;
    tx.finalize();
    let line = format!("tampered copy: txid {}", hex(&tx.id().as_bytes()));
    match node::submit(node, &tx, network) {
        Ok(_) => Err(CliError::new(
            "ZK_PROOF_INVALID",
            format!("the node accepted a settle with a flipped proof bit ({line}): do not rely on this node"),
        )),
        Err(e) => print(
            out,
            &[
                line,
                format!("refused by the node, as expected: {}", e.detail()),
                "nothing was accepted; the real transaction was not sent".to_string(),
            ],
        ),
    }
}
