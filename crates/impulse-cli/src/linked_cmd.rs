// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse linked`: opening and return trades described by one sheet (I22, spec/V2.md section
//! 17). The sheet file, the two derived terms files v2, the return gate, the builders by role
//! (which read the node and then run the `impulse v2` builders on the derived terms) and the
//! linked receipt. Built on impulse-core's `linked` module; the v1 and v2 commands are untouched.
//!
//! Keyless except through the one signing module: `linked receipt sign` calls `signing::sign`
//! once, as `status` does, and nothing here reads, prints or holds key material. Every command
//! prints nothing until all of its checks have passed.

use crate::cli::{connect, creation, hash_arg, print, CreationArgs, Ctx};
use crate::error::CliError;
use crate::json::{hex, parse_dec, parse_strict, Json, Obj};
use crate::node::{self, AcceptedTx};
use crate::receipt::{Observation, Receipt};
use crate::signing::{self, SignRequest};
use crate::terms_file::{network_name, read_text, write_new};
use crate::v2_cmd::{self, FundArgs, RefundArgs, SettleArgs};
use crate::v2_terms::{
    self, check_kas_minimum, describe, parse_draft, parse_terms_json, read_terms,
    render_terms_file, terms_json, J,
};
use clap::{Args, Subcommand, ValueEnum};
use impulse_core::linked::{
    check_opening_settled, check_pair, check_settled, LinkedError, LinkedObservation,
    LinkedReceipt, LinkedSheet, OpeningSettled, Role, ValidatedLinked, LINKED_VERSION,
};
use impulse_core::terms::{LegKind, Network};
use impulse_core::v2::LegV2;
use kaspa_consensus_core::tx::ScriptPublicKey;
use std::io::Write;
use std::path::{Path, PathBuf};

/// What a linked trade does and does not promise (spec/V2.md 17.1), printed before anyone funds.
const EXPOSURE: [&str; 3] = [
    "the opening and the return are two separate trades, each a v2 trade that is accepted or final on its own; the pair is not one transaction",
    "if the return is never funded or never settles, each party keeps what the opening delivered to it; there is no margin, no mark to market and no remedy for a default",
    "the return can be funded only after the opening settled (the gate reads your node); the contract cannot enforce that order",
];

// =============================================================================================
// Arguments
// =============================================================================================

#[derive(Subcommand, Debug)]
pub enum LinkedCommand {
    /// Read a draft opening and write a sheet file (an opening and a return, one hash).
    New(NewArgs),
    /// Show both trades of a sheet, what each party deposits and what it gets back.
    Show(ShowArgs),
    /// Write the terms file v2 of one trade of a sheet.
    Terms(TermsArgs),
    /// Check that a terms file is the trade a sheet derives for a role.
    Check(CheckArgs),
    /// Check on your node that the opening settled, at a depth you name.
    ReturnGate(GateCommandArgs),
    /// Build an unsigned funding transaction for your leg of one trade.
    #[command(subcommand)]
    Fund(FundCommand),
    /// Build an unsigned settle of one trade.
    #[command(subcommand)]
    Settle(SettleCommand),
    /// Build an unsigned refund of one leg of one trade.
    #[command(subcommand)]
    Refund(RefundCommand),
    /// Linked receipts: both trades of a sheet tied to one terms hash.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
}

#[derive(Subcommand, Debug)]
pub enum FundCommand {
    Build(Box<LinkedFundArgs>),
}

#[derive(Subcommand, Debug)]
pub enum SettleCommand {
    Build(Box<LinkedSettleArgs>),
}

#[derive(Subcommand, Debug)]
pub enum RefundCommand {
    Build(Box<LinkedRefundArgs>),
}

#[derive(Subcommand, Debug)]
pub enum ReceiptCommand {
    /// Observe the settle of one trade on your node and sign it as a linked receipt.
    Sign(ReceiptSignArgs),
    /// Check a linked receipt against its sheet.
    Verify(ReceiptVerifyArgs),
    /// Check that an opening receipt and a return receipt are one linked trade.
    Pair(ReceiptPairArgs),
}

/// Which trade of the sheet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    Opening,
    Return,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Opening => Role::Opening,
            RoleArg::Return => Role::Return,
        }
    }
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// The opening draft: terms v2 in JSON form with a zero trade_ref (nonce, expiry_daa and
    /// funding_mode may be null).
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// The amount of asset 0 the return moves back (asset 0 is the opening's leg 0 asset).
    #[arg(long, value_name = "AMOUNT")]
    pub return_amount_0: u64,
    /// The amount of asset 1 the return moves back.
    #[arg(long, value_name = "AMOUNT")]
    pub return_amount_1: u64,
    /// The earliest DAA score the return settles at: above the opening's expiry_daa.
    #[arg(long, value_name = "DAA")]
    pub return_earliest_daa: u64,
    /// The return's expiry_daa.
    #[arg(long, value_name = "DAA")]
    pub return_expiry_daa: u64,
    /// The sheet file to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[command(flatten)]
    pub creation: CreationArgs,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    /// Your x-only public key: also say which legs you deposit and what you receive.
    #[arg(long, value_name = "HEX")]
    pub my_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct TermsArgs {
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    #[arg(long, value_enum)]
    pub role: RoleArg,
    /// The terms file v2 to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    #[arg(long, value_enum)]
    pub role: RoleArg,
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
}

/// The evidence a return needs: the opening's settle on your node.
#[derive(Args, Debug, Default)]
pub struct GateArgs {
    /// The return: the transaction ID of the opening's settle, 64 lowercase hex digits.
    #[arg(long, value_name = "TXID")]
    pub opening_txid: Option<String>,
    /// The return: a chain block at or before that settle's acceptance.
    #[arg(long, value_name = "HASH")]
    pub opening_from_block: Option<String>,
    /// The return: the least depth, in DAA scores, the opening's acceptance must have. No default.
    #[arg(long, value_name = "DAA")]
    pub min_depth: Option<u64>,
}

#[derive(Args, Debug)]
pub struct GateCommandArgs {
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "TXID")]
    pub opening_txid: String,
    #[arg(long, value_name = "HASH")]
    pub opening_from_block: String,
    #[arg(long, value_name = "DAA")]
    pub min_depth: u64,
}

#[derive(Args, Debug)]
pub struct LinkArgs {
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    #[arg(long, value_enum)]
    pub role: RoleArg,
}

#[derive(Args, Debug)]
pub struct LinkedFundArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    #[command(flatten)]
    pub gate: GateArgs,
    #[command(flatten)]
    pub inner: FundArgs,
}

#[derive(Args, Debug)]
pub struct LinkedSettleArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    #[command(flatten)]
    pub gate: GateArgs,
    #[command(flatten)]
    pub inner: SettleArgs,
}

#[derive(Args, Debug)]
pub struct LinkedRefundArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    #[command(flatten)]
    pub inner: RefundArgs,
}

#[derive(Args, Debug)]
pub struct ReceiptSignArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// The settle's transaction ID, 64 lowercase hex digits.
    #[arg(long)]
    pub txid: String,
    /// A chain block at or before the settle's acceptance.
    #[arg(long, value_name = "HASH")]
    pub from_block: String,
    /// The least depth, in DAA scores, the acceptance must have before anything is signed.
    #[arg(long, value_name = "DAA")]
    pub min_depth: u64,
    /// Your key file: 64 hex digits, readable by you only. Read by the signing module only.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
    /// The receipt file to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ReceiptVerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub receipt: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    /// Require this signer (x-only key, 64 hex digits).
    #[arg(long, value_name = "HEX")]
    pub signer: Option<String>,
    /// Require this transaction ID.
    #[arg(long, value_name = "TXID")]
    pub txid: Option<String>,
    /// Also check the receipt's on-chain facts on this node.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReceiptPairArgs {
    #[arg(long, value_name = "FILE")]
    pub opening: PathBuf,
    #[arg(long = "return", value_name = "FILE")]
    pub return_receipt: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub sheet: PathBuf,
    /// Require this signer on both receipts.
    #[arg(long, value_name = "HEX")]
    pub signer: Option<String>,
}

pub(crate) fn run(ctx: &Ctx, command: LinkedCommand, out: &mut dyn Write) -> Result<(), CliError> {
    match command {
        LinkedCommand::New(a) => new(ctx, a, out),
        LinkedCommand::Show(a) => show(ctx, a, out),
        LinkedCommand::Terms(a) => terms(ctx, a, out),
        LinkedCommand::Check(a) => check(ctx, a, out),
        LinkedCommand::ReturnGate(a) => return_gate(ctx, a, out),
        LinkedCommand::Fund(FundCommand::Build(a)) => fund_build(ctx, *a, out),
        LinkedCommand::Settle(SettleCommand::Build(a)) => settle_build(ctx, *a, out),
        LinkedCommand::Refund(RefundCommand::Build(a)) => refund_build(ctx, *a, out),
        LinkedCommand::Receipt(ReceiptCommand::Sign(a)) => receipt_sign(ctx, a, out),
        LinkedCommand::Receipt(ReceiptCommand::Verify(a)) => receipt_verify(ctx, a, out),
        LinkedCommand::Receipt(ReceiptCommand::Pair(a)) => receipt_pair(ctx, a, out),
    }
}

/// Core linked refusals keep their codes; the core's text already starts with the code.
impl From<LinkedError> for CliError {
    fn from(e: LinkedError) -> Self {
        let code = e.code();
        let text = e.to_string();
        let detail = text
            .strip_prefix(code)
            .and_then(|rest| rest.strip_prefix(": "))
            .map(str::to_string)
            .unwrap_or(text);
        CliError::new(code, detail)
    }
}

// =============================================================================================
// The sheet file
// =============================================================================================

const SHEET_KEYS: [&str; 3] = ["sheet", "canonical", "linked_hash"];
const SHEET_VIEW_KEYS: [&str; 5] = [
    "link_version",
    "opening",
    "return_amounts",
    "return_earliest_daa",
    "return_expiry_daa",
];

fn json_err(reason: String) -> CliError {
    CliError::new("CLI_TERMS_JSON", reason)
}

fn dec(n: u64) -> J {
    J::Str(n.to_string())
}

fn sheet_view(s: &LinkedSheet) -> J {
    J::Obj(vec![
        ("link_version", J::Num(s.version.into())),
        ("opening", terms_json(&s.opening)),
        (
            "return_amounts",
            J::Arr(s.return_amounts.iter().map(|a| dec(*a)).collect()),
        ),
        ("return_earliest_daa", dec(s.return_earliest_daa)),
        ("return_expiry_daa", dec(s.return_expiry_daa)),
    ])
}

/// The sheet file text: the JSON view, the canonical bytes and the sheet hash.
pub(crate) fn render_sheet_file(linked: &ValidatedLinked) -> String {
    J::Obj(vec![
        ("sheet", sheet_view(linked.sheet())),
        ("canonical", J::Str(hex(linked.canonical()))),
        ("linked_hash", J::Str(hex(&linked.linked_hash()))),
    ])
    .render()
}

/// Parses a sheet file and runs the sheet checks. Refuses a file whose three parts disagree
/// (`CLI_TERMS_FILE_INCONSISTENT`) and anything that is not one (`CLI_TERMS_JSON`).
pub(crate) fn parse_sheet_file(text: &str) -> Result<ValidatedLinked, CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&SHEET_KEYS, &[]).map_err(json_err)?;
    let view = Obj::new("sheet", obj.get("sheet").map_err(json_err)?).map_err(json_err)?;
    view.keys(&SHEET_VIEW_KEYS, &[]).map_err(json_err)?;
    let version = view.num("link_version", u8::MAX.into()).map_err(json_err)? as u8;
    let opening = parse_terms_json(view.get("opening").map_err(json_err)?)?;
    let amounts = view
        .get("return_amounts")
        .map_err(json_err)?
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| json_err("sheet.return_amounts: expected an array of two".into()))?;
    let amount = |i: usize| {
        amounts[i].as_str().and_then(parse_dec).ok_or_else(|| {
            json_err(format!(
                "sheet.return_amounts[{i}]: expected a decimal u64 string"
            ))
        })
    };
    let from_view = LinkedSheet {
        version,
        opening,
        return_amounts: [amount(0)?, amount(1)?],
        return_earliest_daa: view.dec("return_earliest_daa").map_err(json_err)?,
        return_expiry_daa: view.dec("return_expiry_daa").map_err(json_err)?,
    };
    let canonical = obj.hex("canonical").map_err(json_err)?;
    let hash = obj.hex32("linked_hash").map_err(json_err)?;
    let inconsistent = |what: &str| CliError::new("CLI_TERMS_FILE_INCONSISTENT", what.to_string());
    if from_view.encode()? != canonical {
        return Err(inconsistent("canonical is not the encoding of sheet"));
    }
    if from_view.linked_hash()? != hash {
        return Err(inconsistent("linked_hash is not the hash of sheet"));
    }
    Ok(from_view.validate()?)
}

/// Reads a sheet file on the command's network (`CLI_NETWORK_MISMATCH`).
pub(crate) fn read_sheet(ctx: &Ctx, path: &Path) -> Result<ValidatedLinked, CliError> {
    let linked = parse_sheet_file(&read_text(path)?)?;
    v2_terms::check_network(ctx, linked.sheet().opening.network, "sheet")?;
    Ok(linked)
}

// =============================================================================================
// Text
// =============================================================================================

fn asset_text(leg: &LegV2) -> String {
    match &leg.asset.kind {
        LegKind::Kas => format!(
            "KAS, {} sompi ({} KAS)",
            leg.asset.amount,
            crate::summary::kas(leg.asset.amount)
        ),
        LegKind::Kcc20(token) => format!(
            "KCC-20 token covenant_id {}, {} token units",
            hex(&token.covenant_id),
            leg.asset.amount
        ),
        LegKind::External => format!("external, amount {}", leg.asset.amount),
    }
}

fn trade_lines(linked: &ValidatedLinked, role: Role) -> Vec<String> {
    let terms = linked.terms(role);
    let t = terms.terms();
    let mut lines = vec![
        format!("{}: terms_hash {}", role.name(), hex(&terms.terms_hash())),
        format!(
            "  earliest_daa {}, expiry_daa {}",
            t.earliest_daa.map_or("none".to_string(), |d| d.to_string()),
            t.expiry_daa
        ),
    ];
    for (i, l) in t.legs.iter().enumerate() {
        lines.push(format!(
            "  {} leg {i}: depositor {} deposits {}",
            role.name(),
            hex(&l.depositor_key),
            asset_text(l)
        ));
        lines.push(format!("    delivered to: {}", describe(t, l, &l.delivery)));
        lines.push(format!("    refunded to: {}", describe(t, l, &l.refund)));
    }
    lines
}

fn sheet_lines(linked: &ValidatedLinked) -> Vec<String> {
    let open = linked.terms(Role::Opening).terms();
    let mut lines = vec![
        format!("linked_hash: {}", hex(&linked.linked_hash())),
        format!("network: {}", network_name(open.network)),
        format!("nonce: {} (both trades carry it)", open.nonce),
        format!(
            "authority_key: {}",
            open.authority_key
                .map_or("none (self-settling)".to_string(), |k| hex(&k))
        ),
        format!(
            "funding_mode: {}",
            match open.funding_mode {
                impulse_core::terms::FundingMode::Revocable => "revocable",
                impulse_core::terms::FundingMode::Earmarked => "earmarked",
            }
        ),
    ];
    lines.extend(trade_lines(linked, Role::Opening));
    lines.extend(trade_lines(linked, Role::Return));
    for (i, l) in open.legs.iter().enumerate() {
        let back = linked.sheet().return_amounts[i];
        let diff = match back.cmp(&l.asset.amount) {
            std::cmp::Ordering::Equal => "the same amount".to_string(),
            std::cmp::Ordering::Greater => format!("{} more", back - l.asset.amount),
            std::cmp::Ordering::Less => format!("{} less", l.asset.amount - back),
        };
        lines.push(format!(
            "asset {i}: {} at opening, {back} at return ({diff})",
            l.asset.amount
        ));
    }
    lines.extend(EXPOSURE.iter().map(|s| format!("note: {s}")));
    lines
}

// =============================================================================================
// Commands
// =============================================================================================

fn new(ctx: &Ctx, a: NewArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_text(&a.draft)?;
    let creation = creation(ctx, &a.creation)?;
    let (draft, notes) = parse_draft(&text, creation.creation_daa)?;
    let linked = LinkedSheet {
        version: LINKED_VERSION,
        opening: draft,
        return_amounts: [a.return_amount_0, a.return_amount_1],
        return_earliest_daa: a.return_earliest_daa,
        return_expiry_daa: a.return_expiry_daa,
    }
    .validate()?;
    linked.validate_creation(Role::Opening, &creation)?;
    for role in [Role::Opening, Role::Return] {
        check_kas_minimum(linked.terms(role).terms())?;
    }
    write_new(&a.out, &render_sheet_file(&linked))?;
    let mut lines = sheet_lines(&linked);
    lines.extend(notes);
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

fn show(ctx: &Ctx, a: ShowArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let linked = read_sheet(ctx, &a.sheet)?;
    let my_key = a
        .my_key
        .as_deref()
        .map(|k| hash_arg("my-key", k))
        .transpose()?;
    let mut lines = sheet_lines(&linked);
    if let Some(key) = my_key {
        let mut mine = false;
        for role in [Role::Opening, Role::Return] {
            for (i, l) in linked.terms(role).terms().legs.iter().enumerate() {
                if l.depositor_key == key {
                    mine = true;
                    lines.push(format!(
                        "you deposit {} leg {i}: {}",
                        role.name(),
                        asset_text(l)
                    ));
                }
            }
        }
        if !mine {
            lines.push("your key deposits no leg of this sheet".into());
        }
    }
    print(out, &lines)
}

fn terms(ctx: &Ctx, a: TermsArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let linked = read_sheet(ctx, &a.sheet)?;
    let role: Role = a.role.into();
    let t = linked.terms(role);
    write_new(&a.out, &render_terms_file(t))?;
    print(
        out,
        &[
            format!("role: {}", role.name()),
            format!("linked_hash: {}", hex(&linked.linked_hash())),
            format!("terms_hash: {}", hex(&t.terms_hash())),
            format!("wrote: {}", a.out.display()),
        ],
    )
}

fn check(ctx: &Ctx, a: CheckArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let linked = read_sheet(ctx, &a.sheet)?;
    let role: Role = a.role.into();
    let terms = read_terms(ctx, &a.terms)?;
    linked.verify_terms(role, terms.terms())?;
    print(
        out,
        &[format!(
            "ok: the terms are the {} trade of sheet {}",
            role.name(),
            hex(&linked.linked_hash())
        )],
    )
}

/// A transaction the node's chain accepts, with how deep.
struct Seen {
    block: [u8; 32],
    daa_score: u64,
    depth: u64,
    accepted: AcceptedTx,
}

impl Seen {
    fn spent(&self) -> Vec<ScriptPublicKey> {
        self.accepted
            .spent
            .iter()
            .map(|e| e.script_public_key.clone())
            .collect()
    }
}

fn accepted_at_depth(
    ctx: &Ctx,
    url: &str,
    txid: [u8; 32],
    from: [u8; 32],
    min_depth: u64,
) -> Result<Seen, CliError> {
    let node = connect(ctx, url, ctx.network)?;
    node::check_node(node.as_ref(), ctx.network)?;
    let (block, accepted) = node::find_accepted_tx(node.as_ref(), txid, from)?;
    let info = node.block(block)?;
    if !info.is_chain_block {
        return Err(CliError::new(
            "CLI_TX_NOT_ACCEPTED",
            "the accepting block left the selected chain during the walk",
        ));
    }
    let depth = node
        .dag_info()?
        .virtual_daa
        .checked_sub(info.daa_score)
        .ok_or_else(|| {
            CliError::new(
                "CLI_NODE_RPC",
                "get_block_dag_info: virtual DAA score below the block's",
            )
        })?;
    if depth < min_depth {
        return Err(CliError::new(
            "CLI_DEPTH_BELOW_MINIMUM",
            format!(
                "depth {depth} is below --min-depth {min_depth}; wait and run the command again"
            ),
        ));
    }
    Ok(Seen {
        block,
        daa_score: info.daa_score,
        depth,
        accepted,
    })
}

/// The evidence that the opening settled, read from the node, and the lines that say so.
fn opening_gate(
    ctx: &Ctx,
    linked: &ValidatedLinked,
    url: &str,
    txid: [u8; 32],
    from: [u8; 32],
    min_depth: u64,
) -> Result<(OpeningSettled, Vec<String>), CliError> {
    let seen = accepted_at_depth(ctx, url, txid, from, min_depth)?;
    let evidence = check_opening_settled(linked, &seen.accepted.tx, &seen.spent())?;
    let lines = vec![
        format!(
            "opening settled: transaction {} spends both opening vaults of sheet {} through settle",
            hex(&evidence.txid()),
            hex(&linked.linked_hash())
        ),
        format!(
            "  accepted in chain block {} at DAA score {}, depth {} (at least {min_depth})",
            hex(&seen.block),
            seen.daa_score,
            seen.depth
        ),
        "  accepted is not final: a reorganisation deeper than your --min-depth can undo it".into(),
    ];
    Ok((evidence, lines))
}

fn return_gate(ctx: &Ctx, a: GateCommandArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let linked = read_sheet(ctx, &a.sheet)?;
    let txid = hash_arg("opening-txid", &a.opening_txid)?;
    let from = hash_arg("opening-from-block", &a.opening_from_block)?;
    let (_, lines) = opening_gate(ctx, &linked, &a.node, txid, from, a.min_depth)?;
    print(out, &lines)
}

/// The checks every builder wrapper makes before it runs the `v2` builder: the terms file is the
/// sheet's trade for the role, and for the return (when `gated`) the opening settled on the node.
fn guard(
    ctx: &Ctx,
    link: &LinkArgs,
    terms_path: &Path,
    node_url: &str,
    gate: Option<&GateArgs>,
) -> Result<Vec<String>, CliError> {
    node::check_transport(node_url, ctx.network)?;
    let linked = read_sheet(ctx, &link.sheet)?;
    let role: Role = link.role.into();
    let terms = read_terms(ctx, terms_path)?;
    linked.verify_terms(role, terms.terms())?;
    let mut lines = vec![format!(
        "linked: the {} trade of sheet {}",
        role.name(),
        hex(&linked.linked_hash())
    )];
    if let (Role::Return, Some(g)) = (role, gate) {
        let (Some(txid), Some(from), Some(min_depth)) =
            (&g.opening_txid, &g.opening_from_block, g.min_depth)
        else {
            return Err(LinkedError::OpeningNotSettled.into());
        };
        let txid = hash_arg("opening-txid", txid)?;
        let from = hash_arg("opening-from-block", from)?;
        let (_, gate_lines) = opening_gate(ctx, &linked, node_url, txid, from, min_depth)?;
        lines.extend(gate_lines);
    }
    lines.extend(EXPOSURE.iter().map(|s| format!("note: {s}")));
    Ok(lines)
}

/// Runs the `v2` command into a buffer and prints the guard's lines, then its output: nothing is
/// printed unless both pass.
fn delegated(
    guard_lines: Vec<String>,
    out: &mut dyn Write,
    run: impl FnOnce(&mut dyn Write) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut buffer = Vec::new();
    run(&mut buffer)?;
    print(out, &guard_lines)?;
    out.write_all(&buffer)
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("stdout: {e}")))
}

fn fund_build(ctx: &Ctx, a: LinkedFundArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let lines = guard(ctx, &a.link, &a.inner.terms, &a.inner.node, Some(&a.gate))?;
    delegated(lines, out, |buf| v2_cmd::fund_build(ctx, a.inner, buf))
}

fn settle_build(ctx: &Ctx, a: LinkedSettleArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let lines = guard(ctx, &a.link, &a.inner.terms, &a.inner.node, Some(&a.gate))?;
    delegated(lines, out, |buf| v2_cmd::settle_build(ctx, a.inner, buf))
}

fn refund_build(ctx: &Ctx, a: LinkedRefundArgs, out: &mut dyn Write) -> Result<(), CliError> {
    // A refund only takes a depositor's own leg home: no gate.
    let lines = guard(ctx, &a.link, &a.inner.terms, &a.inner.node, None)?;
    delegated(lines, out, |buf| v2_cmd::refund_build(ctx, a.inner, buf))
}

// =============================================================================================
// Linked receipt
// =============================================================================================

const RECEIPT_KEYS: [&str; 11] = [
    "version",
    "network",
    "role",
    "linked_hash",
    "leg_terms_hash",
    "txid",
    "accepting_block",
    "daa_score",
    "depth",
    "signer",
    "signature",
];

pub(crate) fn render_receipt(r: &LinkedReceipt) -> String {
    let o = &r.observation;
    Json::Obj(vec![
        (
            "version",
            Json::Num(impulse_core::linked::LINKED_RECEIPT_VERSION.into()),
        ),
        ("network", Json::Str(network_name(o.network).into())),
        ("role", Json::Str(o.role.name().into())),
        ("linked_hash", Json::Str(hex(&o.linked_hash))),
        ("leg_terms_hash", Json::Str(hex(&o.leg_terms_hash))),
        ("txid", Json::Str(hex(&o.txid))),
        ("accepting_block", Json::Str(hex(&o.accepting_block))),
        ("daa_score", Json::Str(o.daa_score.to_string())),
        ("depth", Json::Str(o.depth.to_string())),
        ("signer", Json::Str(hex(&r.signer))),
        ("signature", Json::Str(hex(&r.signature))),
    ])
    .render()
}

/// The JSON form, nothing more (`RECEIPT_MALFORMED`). The signature is not checked here.
pub(crate) fn parse_receipt(text: &str) -> Result<LinkedReceipt, CliError> {
    let malformed = |why: String| CliError::new("RECEIPT_MALFORMED", why);
    let value = parse_strict(text).map_err(malformed)?;
    let o = Obj::new("receipt", &value).map_err(malformed)?;
    o.keys(&RECEIPT_KEYS, &[]).map_err(malformed)?;
    if o.num("version", u8::MAX.into()).map_err(malformed)?
        != u64::from(impulse_core::linked::LINKED_RECEIPT_VERSION)
    {
        return Err(malformed("receipt.version: only version 1 exists".into()));
    }
    let network = [Network::Mainnet, Network::Testnet][o
        .choice("network", &["mainnet", "testnet"])
        .map_err(malformed)?];
    let role = [Role::Opening, Role::Return][o
        .choice("role", &["opening", "return"])
        .map_err(malformed)?];
    let signature: [u8; 64] = o
        .hex("signature")
        .map_err(malformed)?
        .try_into()
        .map_err(|_| malformed("receipt.signature: expected 64 bytes".into()))?;
    Ok(LinkedReceipt {
        observation: LinkedObservation {
            network,
            role,
            linked_hash: o.hex32("linked_hash").map_err(malformed)?,
            leg_terms_hash: o.hex32("leg_terms_hash").map_err(malformed)?,
            txid: o.hex32("txid").map_err(malformed)?,
            accepting_block: o.hex32("accepting_block").map_err(malformed)?,
            daa_score: o.dec("daa_score").map_err(malformed)?,
            depth: o.dec("depth").map_err(malformed)?,
        },
        signer: o.hex32("signer").map_err(malformed)?,
        signature,
    })
}

fn receipt_sign(ctx: &Ctx, a: ReceiptSignArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let linked = read_sheet(ctx, &a.link.sheet)?;
    let role: Role = a.link.role.into();
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let seen = accepted_at_depth(ctx, &a.node, txid, from, a.min_depth)?;
    // The transaction settles this trade's vaults, as the node reports the UTXOs it spent.
    let settled = check_settled(&linked, role, &seen.accepted.tx, &seen.spent())?;
    let observation = LinkedObservation {
        network: ctx.network,
        role,
        linked_hash: linked.linked_hash(),
        leg_terms_hash: linked.terms_hash(role),
        txid: settled,
        accepting_block: seen.block,
        daa_score: seen.daa_score,
        depth: seen.depth,
    };
    let signed = signing::sign(&SignRequest {
        key_file: &a.key_file,
        network: ctx.network,
        mainnet_explicit: ctx.mainnet_explicit,
        expected_signer: None,
        digest: observation.digest(),
    })?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signed.signature[..64]);
    let receipt = LinkedReceipt {
        observation,
        signer: signed.signer,
        signature,
    };
    let text = render_receipt(&receipt);
    write_new(&a.out, &text)?;
    print(
        out,
        &[
            format!(
                "signed: the {} trade of sheet {} settled by {}",
                role.name(),
                hex(&observation.linked_hash),
                hex(&observation.txid)
            ),
            format!("  leg_terms_hash {}", hex(&observation.leg_terms_hash)),
            format!(
                "  accepted in {} at DAA score {}, depth {}",
                hex(&observation.accepting_block),
                observation.daa_score,
                observation.depth
            ),
            "  bound: the transaction spends this trade's vaults through settle, as your node reported the UTXOs it spent; a reader without a node cannot check that".into(),
            format!("wrote: {}", a.out.display()),
        ],
    )
}

/// Reads a receipt, checks its network, signature and (optional) signer, and its sheet.
fn read_receipt(
    ctx: &Ctx,
    path: &Path,
    linked: &ValidatedLinked,
    signer: Option<&[u8; 32]>,
) -> Result<LinkedReceipt, CliError> {
    let receipt = parse_receipt(&read_text(path)?)?;
    if receipt.observation.network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the receipt is for {}; pass --network {0} to act on it",
                network_name(receipt.observation.network)
            ),
        ));
    }
    receipt
        .verify_signature()
        .map_err(|why| CliError::new("RECEIPT_SIGNATURE_INVALID", why))?;
    if let Some(expected) = signer {
        if &receipt.signer != expected {
            return Err(CliError::new(
                "RECEIPT_SIGNER_MISMATCH",
                format!(
                    "signed by {}, expected {}",
                    hex(&receipt.signer),
                    hex(expected)
                ),
            ));
        }
    }
    receipt.observation.check_against(linked)?;
    Ok(receipt)
}

fn receipt_verify(ctx: &Ctx, a: ReceiptVerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let linked = read_sheet(ctx, &a.sheet)?;
    let signer = a
        .signer
        .as_deref()
        .map(|s| hash_arg("signer", s))
        .transpose()?;
    let your_txid = a.txid.as_deref().map(|t| hash_arg("txid", t)).transpose()?;
    let receipt = read_receipt(ctx, &a.receipt, &linked, signer.as_ref())?;
    let o = &receipt.observation;
    if let Some(txid) = &your_txid {
        if &o.txid != txid {
            return Err(CliError::new(
                "RECEIPT_TXID_MISMATCH",
                format!(
                    "the receipt is for transaction {}, not {}",
                    hex(&o.txid),
                    hex(txid)
                ),
            ));
        }
    }
    let chain = match &a.node {
        Some(url) => {
            let node = connect(ctx, url, o.network)?;
            // The chain facts of a version 1 receipt, for the leg trade's hash.
            let shim = Receipt {
                observation: Observation {
                    network: o.network,
                    terms_hash: o.leg_terms_hash,
                    txid: o.txid,
                    accepting_block: o.accepting_block,
                    daa_score: o.daa_score,
                    depth: o.depth,
                },
                signer: receipt.signer,
                signature: receipt.signature,
            };
            node::verify_receipt(node.as_ref(), &shim)?;
            format!(
                "chain: txid {} accepted in {} at DAA score {}, depth now at least {}",
                hex(&o.txid),
                hex(&o.accepting_block),
                o.daa_score,
                o.depth
            )
        }
        None => "chain: on-chain facts not checked (pass --node)".into(),
    };
    let mut lines = vec![
        format!(
            "ok: the signature verifies for signer {}",
            hex(&receipt.signer)
        ),
        format!(
            "linked_hash: {}, the sheet's; this is the {} trade, leg terms hash {}",
            hex(&o.linked_hash),
            o.role.name(),
            hex(&o.leg_terms_hash)
        ),
        format!(
            "txid: {}, {}",
            hex(&o.txid),
            if your_txid.is_some() {
                "matches --txid"
            } else {
                "not compared: pass --txid"
            }
        ),
        match signer {
            Some(_) => "signer: matches --signer".into(),
            None => "signer: not authenticated: anyone can sign a receipt with their own key; pass --signer <x-only key> to require a known signer".into(),
        },
        chain,
    ];
    lines.extend(not_established());
    print(out, &lines)
}

fn not_established() -> Vec<String> {
    vec![
        "not established: that the transaction spent this trade's vaults (the signer checked that against its node; `impulse decode` checks it against yours); that the return was complete or its amounts right beyond the sheet".into(),
    ]
}

fn receipt_pair(ctx: &Ctx, a: ReceiptPairArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let linked = read_sheet(ctx, &a.sheet)?;
    let signer = a
        .signer
        .as_deref()
        .map(|s| hash_arg("signer", s))
        .transpose()?;
    let opening = read_receipt(ctx, &a.opening, &linked, signer.as_ref())?;
    let ret = read_receipt(ctx, &a.return_receipt, &linked, signer.as_ref())?;
    check_pair(&opening.observation, &ret.observation)?;
    let (o, r) = (&opening.observation, &ret.observation);
    let mut lines = vec![
        format!(
            "ok: an opening receipt and a return receipt of one sheet, linked_hash {}",
            hex(&linked.linked_hash())
        ),
        format!(
            "opening: transaction {} accepted at DAA score {}, leg terms hash {}",
            hex(&o.txid),
            o.daa_score,
            hex(&o.leg_terms_hash)
        ),
        format!(
            "return: transaction {} accepted at DAA score {}, leg terms hash {}",
            hex(&r.txid),
            r.daa_score,
            hex(&r.leg_terms_hash)
        ),
        match signer {
            Some(_) => "signer: both match --signer".into(),
            None => {
                "signer: not authenticated: pass --signer <x-only key> to require a known signer"
                    .into()
            }
        },
        "chain: on-chain facts not checked; run receipt verify with --node on each".into(),
    ];
    lines.extend(not_established());
    print(out, &lines)
}
