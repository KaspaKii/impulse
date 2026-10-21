// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The `impulse` command line: `terms new`, `address`, `verify`, `status` and `receipt verify`
//! (I7 phase 1), and the dispatch of the phase 2 commands, whose bodies live in `build_cmd`,
//! `ipst_cmd`, `decode_cmd` and `misc_cmd`, and of `direct cancel build` (`cancel`). Every command acts on testnet unless
//! `--network mainnet` is passed. A command
//! prints nothing until every one of its checks has passed. Anything that shows funding
//! instructions shows the decoded terms first and checks the user's own destinations
//! (spec/CLI.md, "Terms summary and role check").

use crate::error::CliError;
use crate::json::{hex, unhex32};
use crate::node::{self, Node};
use crate::receipt::Receipt;
use crate::summary::{self, Party, Pins, Role};
use crate::terms_file::{self, read_terms_file, read_text, render_terms_file, write_new};
use crate::trade::{
    check_kas_minimum, check_pinned, leg_name, template_warnings, ExistingTrade, FundableTrade,
};
use crate::value_cap::CapPolicy;
use crate::{build_cmd, decode_cmd, ipst_cmd, misc_cmd};
use crate::{qr, uri};
use clap::{Args, Parser, Subcommand, ValueEnum};
use impulse_core::address::vault_address;
use impulse_core::template::LegIndex;
use impulse_core::terms::{CreationContext, LegKind, Network, SettlementMode, ValidatedTerms};
use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "impulse",
    version,
    about = "Impulse atomic DvP on Kaspa: terms, funding addresses and URIs, transaction builders, local signing, submission, decoding, settlement receipts",
    after_help = "Non-custodial software: it holds no funds and no keys, and signing happens only on your machine. Nothing here is financial, legal or tax advice, or an offer to buy or sell anything. Impulse issues no asset or token. Issuer terms, transfer restrictions and sanctions obligations stay your own responsibility, and Impulse does not check them. Use only values you can lose."
)]
pub struct Cli {
    /// Network to act on. Testnet unless mainnet is passed here explicitly.
    #[arg(long, global = true, value_enum)]
    pub network: Option<NetworkArg>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Hashlock exchange against a counterpart HTLC on another chain (testnet only; spec/V2.md
    /// section 10.9).
    #[command(subcommand)]
    Xchain(crate::xchain::XchainCommand),
    /// Create trade terms.
    #[command(subcommand)]
    Terms(TermsCommand),
    /// Show a trade's vault addresses, and the funding URI and QR code of a native KAS leg.
    Address(AddressArgs),
    /// Check a funding URI against a terms file.
    Verify(VerifyArgs),
    /// Report a transaction's acceptance; with --key-file, sign it as a settlement receipt.
    Status(StatusArgs),
    /// Settlement receipts.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
    /// Build an unsigned funding transaction for your leg.
    #[command(subcommand)]
    Fund(FundCommand),
    /// Build an unsigned settle (vault terms) or Direct transaction.
    #[command(subcommand)]
    Settle(SettleCommand),
    /// Build an unsigned refund of one vault UTXO.
    #[command(subcommand)]
    Refund(RefundCommand),
    /// Direct trades: the Direct refund, a cancellation after the expiry.
    #[command(subcommand)]
    Direct(DirectCommand),
    /// Sign, merge or write out Impulse partially signed transactions.
    #[command(subcommand)]
    Ipst(IpstCommand),
    /// Check a fully signed IPST again and submit it to your node.
    Submit(ipst_cmd::SubmitArgs),
    /// Fetch an accepted transaction from your node and decode the trades it spends.
    Decode(decode_cmd::DecodeArgs),
    /// Show your node's network, virtual DAA score and sink.
    Tip(misc_cmd::TipArgs),
    /// Key files.
    #[command(subcommand)]
    Key(KeyCommand),
    /// KCC-20 tokens: a template's pin check; on testnet only, a fresh token and a lookup.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Test builds only: the offline fake node.
    #[cfg(feature = "offline-fake-node")]
    #[command(subcommand, hide = true)]
    FakeNode(misc_cmd::FakeNodeCommand),
    /// FROST threshold settlement authority: key generation, signing and aggregation (I13).
    #[command(subcommand)]
    Frost(crate::frost::FrostCommand),
    /// The list-gated settle: issuer lists, terms v3 and the proof-carrying settle (I20).
    #[cfg(feature = "zk")]
    #[command(subcommand)]
    Zk(crate::zk_cmd::ZkCommand),
    /// Template v2 trades of 2 to 10 legs (I16): terms, funding, settle, refund, signing.
    #[command(subcommand)]
    V2(crate::v2_cmd::V2Command),
    /// Opening and return trades described by one sheet (I22): repo and securities lending.
    #[command(subcommand)]
    Linked(crate::linked_cmd::LinkedCommand),
}

#[derive(Subcommand, Debug)]
pub enum FundCommand {
    /// Fund your leg's vault: an unsigned IPST.
    Build(build_cmd::FundBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum SettleCommand {
    /// Settle a funded vault trade, or build a Direct trade's transaction: an unsigned IPST.
    Build(build_cmd::SettleBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum RefundCommand {
    /// Refund one vault UTXO home: an unsigned IPST.
    Build(build_cmd::RefundBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum DirectCommand {
    /// After the expiry, spend your Direct input back to yourself (the Direct refund).
    #[command(subcommand)]
    Cancel(CancelCommand),
}

#[derive(Subcommand, Debug)]
pub enum CancelCommand {
    /// Cancel your Direct KAS cash: an unsigned IPST, valid after the expiry.
    Build(crate::cancel::CancelBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum IpstCommand {
    /// Check an IPST against the terms you agreed to and sign your inputs with your key file.
    Sign(Box<ipst_cmd::SignArgs>),
    /// Combine IPSTs of one transaction.
    Merge(ipst_cmd::MergeArgs),
    /// Write a fully signed IPST's transaction as the file impulse-watch --keep-signed reads.
    Raw(ipst_cmd::RawArgs),
}

#[derive(Subcommand, Debug)]
pub enum KeyCommand {
    /// Show a key file's x-only public key and P2PK address.
    Show(misc_cmd::KeyShowArgs),
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Show a KCC-20 artifact's template hash and lengths, and whether it is pinned.
    Info(misc_cmd::TokenInfoArgs),
    /// Testnet only: create a fresh KCC-20 token of a pinned kcc20.sil build.
    #[command(subcommand)]
    Mint(MintCommand),
    /// Testnet only: find the token UTXOs a public key holds of one covenant and amount.
    List(crate::token::TokenListArgs),
}

#[derive(Subcommand, Debug)]
pub enum MintCommand {
    /// The genesis of a token whose whole, fixed supply a public key holds: an unsigned IPST.
    Build(crate::token::TokenMintBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum TermsCommand {
    /// Check a draft, show its terms hash and vault addresses, and write the terms file.
    New(TermsNewArgs),
}

#[derive(Subcommand, Debug)]
pub enum ReceiptCommand {
    /// Check a receipt's signature, and with --node its on-chain facts.
    Verify(ReceiptVerifyArgs),
}

/// Where the creation DAA score comes from: exactly one of the two.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct CreationArgs {
    /// DAA score at creation, as you read it from your node. Testnet only: on mainnet the score
    /// is read from --node.
    #[arg(long, value_name = "SCORE")]
    pub daa: Option<u64>,
    /// wRPC URL of a synced node to read the DAA score from: ws:// or wss://, and on mainnet
    /// wss:// or ws:// to this machine.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

/// Who the user is in the trade. Public key only.
#[derive(Args, Debug)]
pub struct PartyArgs {
    /// Your side of the trade.
    #[arg(long, value_enum)]
    pub role: Role,
    /// Your x-only public key, 64 lowercase hex digits: the terms' buyer_key or seller_key.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// Buyer: the exact destination your asset must be delivered to, when it does not pay
    /// --my-key (your custodian or multisig): a Kaspa address or kcc20:<type>:<hex>.
    #[arg(long, value_name = "DESTINATION")]
    pub my_delivery: Option<String>,
    /// Seller: the exact destination your proceeds must go to, when it does not pay --my-key: a
    /// Kaspa address or kcc20:<type>:<hex>.
    #[arg(long, value_name = "DESTINATION")]
    pub my_proceeds: Option<String>,
    /// The exact destination your refund must go to, when it does not pay --my-key: a Kaspa
    /// address or kcc20:<type>:<hex>.
    #[arg(long, value_name = "DESTINATION")]
    pub my_refund: Option<String>,
}

#[derive(Args, Debug)]
pub struct CapArgs {
    /// The trade's value: the KAS value of the larger leg, in sompi. Required, since the asset
    /// leg is a KCC-20 token whose KAS value the CLI cannot know.
    #[arg(long, value_name = "SOMPI")]
    pub kas_equivalent: Option<u64>,
    /// Lift the per-trade value cap for v0.1.
    #[arg(long)]
    pub i_accept_the_risk: bool,
}

#[derive(Args, Debug)]
pub struct TermsNewArgs {
    /// The draft: terms in JSON form; a missing nonce is drawn at random.
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// The terms file to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub cap: CapArgs,
}

#[derive(Args, Debug)]
pub struct AddressArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Do not draw the QR code. The code is drawn for a dark terminal background.
    #[arg(long)]
    pub no_qr: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The funding URI to check.
    #[arg(long)]
    pub uri: String,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub cap: CapArgs,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// wRPC URL (ws:// or wss://) of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// Transaction ID, 64 lowercase hex digits.
    #[arg(long)]
    pub txid: String,
    /// A chain block at or before the submission, 64 lowercase hex digits.
    #[arg(long, value_name = "HASH")]
    pub from_block: String,
    /// Sign the result as a settlement receipt with this key file.
    #[arg(long, value_name = "FILE", requires_all = ["out", "min_depth"])]
    pub key_file: Option<PathBuf>,
    /// Where to write the receipt; must not exist.
    #[arg(long, value_name = "FILE", requires = "key_file")]
    pub out: Option<PathBuf>,
    /// With --key-file: refuse to sign unless the depth (DAA scores since the accepting block)
    /// is at least this.
    #[arg(long, value_name = "DAA", requires = "key_file")]
    pub min_depth: Option<u64>,
}

#[derive(Args, Debug)]
pub struct ReceiptVerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub receipt: PathBuf,
    /// The x-only public key the receipt must be signed by.
    #[arg(long, value_name = "HEX")]
    pub signer: Option<String>,
    /// The terms file of your trade: the receipt must name its terms hash.
    #[arg(long, value_name = "FILE", conflicts_with = "terms_hash")]
    pub terms: Option<PathBuf>,
    /// The terms hash of your trade, 64 lowercase hex digits: the receipt must name it.
    #[arg(long, value_name = "HEX")]
    pub terms_hash: Option<String>,
    /// The transaction ID you expect, 64 lowercase hex digits: the receipt must name it.
    #[arg(long, value_name = "HEX")]
    pub txid: Option<String>,
    /// wRPC URL of a synced node to re-check the on-chain facts against.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

/// Opens a node connection for a network; the binary connects over wRPC, tests pass a fake.
pub type Connect<'a> = &'a dyn Fn(&str, Network) -> Result<Box<dyn Node>, CliError>;

/// What a run reads from outside its arguments.
pub struct Env<'a> {
    /// The value of `IMPULSE_MAX_VALUE`, if set.
    pub max_value: Option<&'a OsStr>,
    pub connect: Connect<'a>,
}

/// The wRPC connector the binary uses. It applies the transport check for `network` itself.
/// Builds with the `offline-fake-node` feature (tests only) also open `fake://` state files.
pub fn wrpc_connect(url: &str, network: Network) -> Result<Box<dyn Node>, CliError> {
    #[cfg(feature = "offline-fake-node")]
    if node::is_fake_url(url) {
        let path = std::path::Path::new(&url["fake://".len()..]);
        return Ok(Box::new(crate::sim::SimNode::open(path)?));
    }
    Ok(Box::new(node::WrpcNode::connect(url, network)?))
}

pub(crate) struct Ctx<'a> {
    pub(crate) network: Network,
    pub(crate) mainnet_explicit: bool,
    pub(crate) env: &'a Env<'a>,
}

pub(crate) fn line(out: &mut dyn Write, text: &str) -> Result<(), CliError> {
    writeln!(out, "{text}").map_err(|e| CliError::new("CLI_FILE_WRITE", format!("stdout: {e}")))
}

/// Prints lines prepared after every check of the command has passed.
pub(crate) fn print(out: &mut dyn Write, lines: &[String]) -> Result<(), CliError> {
    lines.iter().try_for_each(|l| line(out, l))
}

pub(crate) fn hash_arg(name: &str, value: &str) -> Result<[u8; 32], CliError> {
    unhex32(value).ok_or_else(|| {
        CliError::new(
            "CLI_HEX",
            format!("--{name} must be 64 lowercase hex digits"),
        )
    })
}

/// The limit every settlement receipt of version 1 carries (spec/CLI.md, "Settlement receipt").
pub const UNBOUND_NOTE: &str = "terms binding: not checked. A version 1 receipt states that txid was accepted; that txid settles terms_hash is the signer's assertion only; impulse decode <txid> shows which trades the transaction spends";

/// Runs one command. Results go to `out`; notes on what a result does not establish go to
/// `notes` (stderr in the binary).
pub fn run(
    cli: Cli,
    env: &Env,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    let ctx = Ctx {
        network: match cli.network {
            Some(NetworkArg::Mainnet) => Network::Mainnet,
            _ => Network::Testnet,
        },
        mainnet_explicit: cli.network == Some(NetworkArg::Mainnet),
        env,
    };
    match cli.command {
        Command::Xchain(c) => crate::xchain::run(&ctx, c, out, notes),
        Command::Terms(TermsCommand::New(a)) => terms_new(&ctx, a, out),
        Command::Address(a) => address(&ctx, a, out),
        Command::Verify(a) => verify(&ctx, a, out),
        Command::Status(a) => status(&ctx, a, out, notes),
        Command::Receipt(ReceiptCommand::Verify(a)) => receipt_verify(&ctx, a, out),
        Command::Fund(FundCommand::Build(a)) => build_cmd::fund_build(&ctx, a, out),
        Command::Settle(SettleCommand::Build(a)) => build_cmd::settle_build(&ctx, a, out),
        Command::Refund(RefundCommand::Build(a)) => build_cmd::refund_build(&ctx, a, out),
        Command::Direct(DirectCommand::Cancel(CancelCommand::Build(a))) => {
            crate::cancel::cancel_build(&ctx, a, out)
        }
        Command::Ipst(IpstCommand::Sign(a)) => ipst_cmd::sign(&ctx, *a, out),
        Command::Ipst(IpstCommand::Merge(a)) => ipst_cmd::merge(&ctx, a, out),
        Command::Ipst(IpstCommand::Raw(a)) => ipst_cmd::raw(&ctx, a, out),
        Command::Submit(a) => ipst_cmd::submit(&ctx, a, out),
        Command::Decode(a) => decode_cmd::decode(&ctx, a, out),
        Command::Tip(a) => misc_cmd::tip(&ctx, a, out),
        Command::Key(KeyCommand::Show(a)) => misc_cmd::key_show(&ctx, a, out),
        Command::Token(TokenCommand::Info(a)) => misc_cmd::token_info(a, out),
        Command::Token(TokenCommand::Mint(MintCommand::Build(a))) => {
            crate::token::mint_build(&ctx, a, out)
        }
        Command::Token(TokenCommand::List(a)) => crate::token::list(&ctx, a, out),
        #[cfg(feature = "offline-fake-node")]
        Command::FakeNode(c) => misc_cmd::fake_node(&ctx, c, out),
        Command::Frost(c) => crate::frost::run(&ctx, c, &mut std::io::stdin().lock(), out),
        #[cfg(feature = "zk")]
        Command::Zk(c) => crate::zk_cmd::run(&ctx, c, out, notes),
        Command::V2(c) => crate::v2_cmd::run(&ctx, c, out),
        Command::Linked(c) => crate::linked_cmd::run(&ctx, c, out),
    }
}

/// Connects to the node the user named, after the URL and transport checks for `network`.
pub(crate) fn connect(ctx: &Ctx, url: &str, network: Network) -> Result<Box<dyn Node>, CliError> {
    node::check_transport(url, network)?;
    (ctx.env.connect)(url, network)
}

pub(crate) fn creation(ctx: &Ctx, args: &CreationArgs) -> Result<CreationContext, CliError> {
    let daa = match (args.daa, &args.node) {
        (Some(_), _) if ctx.network == Network::Mainnet => {
            return Err(CliError::new(
                "CLI_MAINNET_NEEDS_NODE",
                "on mainnet the creation DAA score is read from your node, not typed: pass --node <url>",
            ))
        }
        (Some(daa), _) => daa,
        (None, Some(url)) => {
            let node = connect(ctx, url, ctx.network)?;
            node::creation_daa(node.as_ref(), ctx.network)?
        }
        (None, None) => {
            return Err(CliError::new(
                "CLI_NODE_URL_INVALID",
                "no node URL: pass --node <url> or --daa <score>",
            ))
        }
    };
    Ok(CreationContext::new(ctx.network, daa))
}

pub(crate) fn party(network: Network, args: &PartyArgs) -> Result<Party, CliError> {
    let key = hash_arg("my-key", &args.my_key)?;
    let (receive, other) = match args.role {
        Role::Buyer => (&args.my_delivery, ("--my-proceeds", &args.my_proceeds)),
        Role::Seller => (&args.my_proceeds, ("--my-delivery", &args.my_delivery)),
    };
    if other.1.is_some() {
        return Err(CliError::new(
            "CLI_DESTINATION_PIN_INVALID",
            format!(
                "{} is not a destination of the {}; pin {} and {} instead",
                other.0,
                args.role.name(),
                args.role.receive_flag(),
                summary::REFUND_FLAG
            ),
        ));
    }
    let pin = |flag: &str, text: &Option<String>| {
        text.as_deref()
            .map(|t| summary::parse_pin(flag, t, network))
            .transpose()
    };
    Ok(Party {
        role: args.role,
        key,
        pins: Pins {
            receive: pin(args.role.receive_flag(), receive)?,
            refund: pin(summary::REFUND_FLAG, &args.my_refund)?,
        },
    })
}

/// The decoded terms and the role check: what is shown before any vault, URI or result.
pub(crate) fn reviewed(
    trade: &FundableTrade,
    creation: &CreationContext,
    args: &PartyArgs,
) -> Result<Vec<String>, CliError> {
    let t = trade.terms();
    let you = summary::check_party(t.terms(), &party(creation.network, args)?)?;
    let mut lines = summary::summary(&t.terms_hash(), t.terms(), creation.creation_daa);
    lines.push(you);
    lines.extend(template_warnings(t.terms()));
    Ok(lines)
}

pub(crate) fn cap(ctx: &Ctx, args: &CapArgs, terms: &ValidatedTerms) -> Result<String, CliError> {
    CapPolicy::new(ctx.env.max_value, args.i_accept_the_risk)?
        .check(terms.terms(), args.kas_equivalent)
}

fn no_vault_reason(terms: &ValidatedTerms) -> &'static str {
    if terms.terms().settlement_mode == SettlementMode::Direct {
        "no vault: Direct terms escrow nothing"
    } else {
        "no vault: external cash settles off chain"
    }
}

fn no_vault_line(trade: &FundableTrade, leg: LegIndex) -> String {
    format!("{}: {}", leg_name(leg), no_vault_reason(trade.terms()))
}

fn vault_line(leg: LegIndex, vault: &impulse_core::template::FundableVault) -> String {
    format!("{} vault: {}", leg_name(leg), vault_address(vault))
}

/// Who funds a leg's vault: its depositor. The seller delivers the asset leg, the buyer pays the
/// cash leg; a refund returns a leg to its depositor's refund target, whoever sent it.
pub fn funder(leg: LegIndex) -> Role {
    match leg {
        LegIndex::Asset => Role::Seller,
        LegIndex::Cash => Role::Buyer,
    }
}

/// Refuses funding instructions for the vault the user's role does not fund
/// (`CLI_URI_NOT_YOUR_LEG`).
pub fn check_funder(leg: LegIndex, role: Role) -> Result<(), CliError> {
    let by = funder(leg);
    if by != role {
        return Err(CliError::new(
            "CLI_URI_NOT_YOUR_LEG",
            format!(
                "the URI funds the {} vault, which the {} funds; you are the {}, and what you send there is refunded to the {}, not to you",
                leg_name(leg),
                by.name(),
                role.name(),
                by.name()
            ),
        ));
    }
    Ok(())
}

fn terms_new(ctx: &Ctx, a: TermsNewArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let draft = terms_file::parse_draft(&read_text(&a.draft)?)?;
    let terms = draft.validate_structure()?;
    let creation = creation(ctx, &a.creation)?;
    // Both legs instantiate (or are vault-free by the terms) before anything is shown.
    let trade = FundableTrade::new(terms, &creation)?;
    check_kas_minimum(trade.terms().terms())?;
    let mut lines = reviewed(&trade, &creation, &a.party)?;
    lines.push(cap(ctx, &a.cap, trade.terms())?);
    write_new(&a.out, &render_terms_file(trade.terms()))?;
    for leg in LegIndex::ALL {
        lines.push(match trade.vault(leg) {
            Some(v) => vault_line(leg, v),
            None => no_vault_line(&trade, leg),
        });
    }
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

fn address(ctx: &Ctx, a: AddressArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_file(&a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    let trade = FundableTrade::new(terms, &creation)?;
    check_kas_minimum(trade.terms().terms())?;
    check_pinned(trade.terms().terms())?;
    let mut lines = reviewed(&trade, &creation, &a.party)?;
    lines.push(cap(ctx, &a.cap, trade.terms())?);
    for leg in LegIndex::ALL {
        let Some(vault) = trade.vault(leg) else {
            lines.push(no_vault_line(&trade, leg));
            continue;
        };
        lines.push(vault_line(leg, vault));
        let by = funder(leg);
        if by != a.party.role {
            lines.push(format!(
                "  funded by: the {} (your counterparty); you send nothing to this vault",
                by.name()
            ));
            continue;
        }
        lines.push(format!("  funded by: the {} (you)", by.name()));
        match uri::funding_uri(&trade, leg) {
            Some(u) => {
                let amount = match leg {
                    LegIndex::Asset => trade.terms().terms().asset_leg.amount,
                    LegIndex::Cash => trade.terms().terms().cash_leg.amount,
                };
                lines.push(format!("  funding URI: {u}"));
                lines.push(format!(
                    "  amount is in sompi: before sending, confirm your wallet shows exactly {} KAS ({amount} sompi) to this address",
                    summary::kas(amount)
                ));
                if !a.no_qr {
                    lines.push(qr::render(&u)?.trim_end().to_string());
                }
            }
            None => {
                let t = trade.terms().terms();
                let kind = match leg {
                    LegIndex::Asset => t.asset_leg.kind,
                    LegIndex::Cash => t.cash_leg.kind,
                };
                debug_assert!(matches!(kind, LegKind::Kcc20(_)));
                lines.push(format!(
                    "  escrowed token owner: script_hash {}",
                    hex(&vault.vault().script_hash())
                ));
                lines.push(
                    "  no funding URI: a KCC-20 leg is funded with two UTXOs, the escrowed token and the authorizer KAS".to_string(),
                );
            }
        }
    }
    print(out, &lines)
}

fn verify(ctx: &Ctx, a: VerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_file(&a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    let trade = FundableTrade::new(terms, &creation)?;
    check_kas_minimum(trade.terms().terms())?;
    check_pinned(trade.terms().terms())?;
    let leg = uri::verify(&a.uri, &trade)?;
    let mut lines = reviewed(&trade, &creation, &a.party)?;
    check_funder(leg, a.party.role)?;
    lines.push(cap(ctx, &a.cap, trade.terms())?);
    let t = trade.terms().terms();
    let amount = match leg {
        LegIndex::Asset => t.asset_leg.amount,
        LegIndex::Cash => t.cash_leg.amount,
    };
    lines.push(format!(
        "ok: funds the {} vault of terms {} with exactly {amount} sompi, your leg as the {}",
        leg_name(leg),
        hex(&trade.terms().terms_hash()),
        a.party.role.name()
    ));
    print(out, &lines)
}

fn status(
    ctx: &Ctx,
    a: StatusArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_file(&a.terms)?;
    if terms.terms().network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the terms are for {}; pass --network {0} to act on them",
                terms_file::network_name(terms.terms().network)
            ),
        ));
    }
    // The terms hash is shown only for terms whose escrowed legs instantiate (no creation
    // checks: status works after expiry).
    let trade = ExistingTrade::new(terms)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let node = connect(ctx, &a.node, ctx.network)?;
    let observation = node::observe(
        node.as_ref(),
        ctx.network,
        trade.terms().terms_hash(),
        txid,
        from,
    )?;
    let text = match (a.key_file, a.out, a.min_depth) {
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
            let text = receipt.render();
            write_new(&path, &text)?;
            text
        }
        _ => observation.render(),
    };
    line(out, text.trim_end())?;
    writeln!(notes, "note: {UNBOUND_NOTE}")
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("stderr: {e}")))
}

fn receipt_verify(ctx: &Ctx, a: ReceiptVerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let receipt = Receipt::parse(&read_text(&a.receipt)?)?;
    if receipt.observation.network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the receipt is for {}; pass --network {0} to act on it",
                terms_file::network_name(receipt.observation.network)
            ),
        ));
    }
    let expected = a
        .signer
        .as_deref()
        .map(|s| hash_arg("signer", s))
        .transpose()?;
    let your_terms = match (&a.terms, &a.terms_hash) {
        (Some(path), _) => Some((read_terms_file(path)?.terms_hash(), "--terms")),
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
    let o = &receipt.observation;
    let chain = match &a.node {
        Some(url) => {
            let node = connect(ctx, url, o.network)?;
            node::verify_receipt(node.as_ref(), &receipt)?;
            format!(
                "chain: txid {} of terms {} accepted in {} at DAA score {}, depth now at least {}",
                hex(&o.txid),
                hex(&o.terms_hash),
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
            "terms_hash: {}, {}",
            hex(&o.terms_hash),
            match your_terms {
                Some((_, flag)) => format!("matches {flag}"),
                None => "not compared with your trade: pass --terms or --terms-hash".into(),
            }
        ),
        format!(
            "txid: {}, {}",
            hex(&o.txid),
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
    ];
    lines.push(UNBOUND_NOTE.to_string());
    print(out, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::fake::{h as blk, FakeNode};
    use crate::signing::throwaway::key_file;
    use crate::terms_file::tests::vector_file;
    use crate::testutil::TempDir;
    use serde_json::Value;
    use std::cell::RefCell;
    use std::path::Path;

    const DAA: &str = "400000000";
    /// The URL the harness answers with its mainnet fake node; any other gets the testnet one.
    const MAINNET_NODE: &str = "ws://127.0.0.1:17110";

    fn default_node(url: &str) -> FakeNode {
        if url == MAINNET_NODE {
            FakeNode::mainnet()
        } else {
            FakeNode::testnet()
        }
    }
    /// The buyer key of every golden vector.
    const BUYER_KEY: &str = "67b2e7c8dfe143ccdad9cdd0929b9bfff2ed9039ef21a146a2caab1c2b542de3";
    /// The seller key of every golden vector.
    const SELLER_KEY: &str = "95e2f4e4fe97ed99e78ac44930508f03b408bde943a16d35bd8f1d0228a8bc3e";

    /// Whether a command takes the party arguments.
    fn takes_party(args: &[&str]) -> bool {
        let cmd: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !matches!(*a, "--network" | "mainnet" | "testnet"))
            .take(2)
            .collect();
        matches!(
            cmd.as_slice(),
            ["terms", "new"] | ["address", _] | ["verify", _]
        )
    }

    struct Harness {
        dir: TempDir,
        node: fn(&str) -> FakeNode,
        urls: RefCell<Vec<String>>,
        /// Whether a command that takes the value cap and is given neither --kas-equivalent nor
        /// --i-accept-the-risk declares the trade worth 1 KAS.
        declare: std::cell::Cell<bool>,
        /// What the last command wrote to its notes (stderr).
        notes: RefCell<String>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                dir: TempDir::new(),
                node: default_node,
                urls: RefCell::new(vec![]),
                declare: std::cell::Cell::new(true),
                notes: RefCell::new(String::new()),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// Writes the draft of a golden vector (its JSON form, KCC-20 templates pinned) and
        /// returns the path.
        fn draft(&self, prefix: &str) -> PathBuf {
            let v = pinned_vector(prefix);
            let p = self.path(&format!("draft-{prefix}json"));
            std::fs::write(&p, v["terms"].to_string()).unwrap();
            p
        }

        /// Runs a command; returns its result and everything it printed, refusal or not. A
        /// command that takes the party arguments and is given none acts as the vectors' buyer,
        /// whose destinations pay the buyer key in the vectors these tests use.
        fn exec(&self, args: &[&str], max_value: Option<&str>) -> (Result<(), CliError>, String) {
            let mut argv = vec!["impulse"];
            argv.extend_from_slice(args);
            if takes_party(args) && !args.contains(&"--role") {
                argv.extend_from_slice(&["--role", "buyer", "--my-key", BUYER_KEY]);
            }
            let takes_cap = takes_party(args);
            let flagged =
                args.contains(&"--kas-equivalent") || args.contains(&"--i-accept-the-risk");
            if takes_cap && !flagged && self.declare.get() {
                argv.extend_from_slice(&["--kas-equivalent", "100000000"]);
            }
            let cli = Cli::try_parse_from(argv).expect("arguments parse");
            let connect = |url: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
                self.urls.borrow_mut().push(url.to_string());
                Ok(Box::new((self.node)(url)))
            };
            let env = Env {
                max_value: max_value.map(OsStr::new),
                connect: &connect,
            };
            let (mut out, mut notes) = (Vec::new(), Vec::new());
            let result = run(cli, &env, &mut out, &mut notes);
            *self.notes.borrow_mut() = String::from_utf8(notes).unwrap();
            (result, String::from_utf8(out).unwrap())
        }

        /// A command that must succeed; returns what it printed.
        fn run(&self, args: &[&str], max_value: Option<&str>) -> Result<String, CliError> {
            let (result, out) = self.exec(args, max_value);
            result.map(|()| out)
        }

        /// A command that must be refused: returns the code, after checking that nothing at all
        /// was printed (no terms hash, address, URI or result before the refusal).
        fn refuse(&self, args: &[&str], max_value: Option<&str>) -> &'static str {
            let (result, out) = self.exec(args, max_value);
            let e = result.expect_err("refused");
            assert_eq!(out, "", "{} printed output before refusing", e.code());
            e.code()
        }
    }

    /// A golden terms vector file with every KCC-20 leg's template set to a pinned kcc20.sil
    /// build: `address`, `verify` and the builders refuse terms whose template is not pinned
    /// (spec/CLI.md, "Before funding"), and the vectors' templates are made up.
    fn pinned_vector(prefix: &str) -> Value {
        let mut v: Value = serde_json::from_str(&vector_file(prefix)).unwrap();
        let pin = &impulse_core::verify::PINNED_KCC20_TEMPLATES[0].triple;
        for leg in ["asset_leg", "cash_leg"] {
            let l = &mut v["terms"][leg];
            if l["kind"] == "kcc20" {
                l["template_hash"] = hex(&pin.hash).into();
                l["template_prefix_len"] = pin.prefix_len.into();
                l["template_suffix_len"] = pin.suffix_len.into();
            }
        }
        v
    }

    fn s(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    #[test]
    fn terms_new_writes_the_file_and_shows_hash_and_vaults() {
        let h = Harness::new();
        let draft = h.draft("08-");
        let out = h.path("terms.json");
        let text = h
            .run(
                &[
                    "terms",
                    "new",
                    "--draft",
                    s(&draft),
                    "--out",
                    s(&out),
                    "--daa",
                    DAA,
                ],
                None,
            )
            .unwrap();
        let written = terms_file::read_terms_file(&out).unwrap();
        assert!(text.contains(&format!("terms_hash: {}", hex(&written.terms_hash()))));
        assert!(text.contains("asset vault: kaspatest:p"));
        assert!(text.contains("cash vault: kaspatest:p"));
    }

    #[test]
    fn terms_new_shows_nothing_when_a_check_fails() {
        let h = Harness::new();
        // Vector 04 names mainnet; without --network mainnet the creation check refuses.
        let draft = h.draft("04-");
        let out = h.path("terms.json");
        let args = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--daa",
            DAA,
        ];
        assert_eq!(h.refuse(&args, None), "TERMS_NETWORK_MISMATCH");
        assert!(!out.exists(), "nothing written");
        // On mainnet a typed creation DAA score is refused; the node supplies it.
        let mut typed = vec!["--network", "mainnet"];
        typed.extend_from_slice(&args);
        typed.push("--i-accept-the-risk");
        assert_eq!(h.refuse(&typed, None), "CLI_MAINNET_NEEDS_NODE");
        assert!(h.urls.borrow().is_empty());
        let mainnet = [
            "--network",
            "mainnet",
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--node",
            MAINNET_NODE,
        ];
        // Expired at creation (the node is at the expiry): refused, nothing written.
        let mut h = h;
        h.node = |_| {
            let mut n = FakeNode::mainnet();
            n.dag.virtual_daa = 412_096_000;
            n
        };
        let mut late = mainnet.to_vec();
        late.push("--i-accept-the-risk");
        assert_eq!(h.refuse(&late, None), "TERMS_EXPIRY_NOT_AFTER_CREATION");
        assert!(!out.exists());
        h.node = default_node;
        // Vector 04 is 100 KAS: above the default cap.
        let mut over = mainnet.to_vec();
        assert_eq!(h.refuse(&over, None), "CLI_VALUE_CAP_EXCEEDED");
        assert!(!out.exists());
        over.push("--i-accept-the-risk");
        assert!(h.run(&over, None).is_ok(), "control");
        assert!(out.exists());
        assert_eq!(h.refuse(&over, None), "CLI_OUTPUT_EXISTS");
    }

    #[test]
    fn a_leg_that_fails_to_instantiate_refuses_terms_new_and_address_silently() {
        use crate::trade::fail;
        use impulse_core::template::TemplateError;
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let draft = h.draft("08-");
        let out = h.path("terms-fail.json");
        let new = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--daa",
            DAA,
        ];
        let address = ["address", "--terms", s(&terms), "--daa", DAA];
        for leg in LegIndex::ALL {
            for e in [
                TemplateError::StateInvalid { field: "amount" },
                TemplateError::StateMalformed {
                    reason: "injected".into(),
                },
            ] {
                let code = e.code();
                fail::set(leg, e);
                let refused = (h.refuse(&new, None), h.refuse(&address, None));
                fail::clear();
                assert_eq!(refused, (code, code), "{leg:?}");
                assert!(!out.exists(), "nothing written");
            }
        }
        assert!(h.run(&address, None).is_ok(), "control");
        assert!(h.run(&new, None).is_ok(), "control");
        assert!(out.exists());
    }

    #[test]
    fn address_shows_nothing_when_a_creation_check_fails() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let expiry = terms_file::read_terms_file(&terms)
            .unwrap()
            .terms()
            .expiry_daa
            .to_string();
        assert!(h
            .run(&["address", "--terms", s(&terms), "--daa", DAA], None)
            .is_ok());
        assert_eq!(
            h.refuse(&["address", "--terms", s(&terms), "--daa", &expiry], None),
            "TERMS_EXPIRY_NOT_AFTER_CREATION"
        );
        assert_eq!(
            h.refuse(&["address", "--terms", s(&terms), "--daa", "1"], None),
            "TERMS_EXPIRY_BEYOND_HORIZON"
        );
    }

    #[test]
    fn terms_new_refuses_malformed_and_invalid_drafts() {
        let h = Harness::new();
        let out = h.path("terms.json");
        let bad = h.path("bad.json");
        std::fs::write(&bad, "{}").unwrap();
        let args = [
            "terms",
            "new",
            "--draft",
            s(&bad),
            "--out",
            s(&out),
            "--daa",
            DAA,
        ];
        assert_eq!(h.refuse(&args, None), "CLI_TERMS_JSON");
        let v = pinned_vector("08-");
        let mut t = v["terms"].clone();
        t["buyer_key"] = t["seller_key"].clone();
        std::fs::write(&bad, t.to_string()).unwrap();
        assert_eq!(h.refuse(&args, None), "TERMS_PARTIES_NOT_DISTINCT");
        assert!(!out.exists());
    }

    #[test]
    fn terms_new_handles_vault_free_legs() {
        let h = Harness::new();
        for (prefix, asset, cash) in [
            (
                "05-",
                "asset vault: kaspa:p",
                "cash: no vault: external cash settles off chain",
            ),
            (
                "07-",
                "asset: no vault: Direct terms escrow nothing",
                "cash: no vault: Direct terms escrow nothing",
            ),
        ] {
            let draft = h.draft(prefix);
            let out = h.path(&format!("terms-{prefix}json"));
            let text = h
                .run(
                    &[
                        "--network",
                        "mainnet",
                        "terms",
                        "new",
                        "--draft",
                        s(&draft),
                        "--out",
                        s(&out),
                        "--node",
                        MAINNET_NODE,
                        "--kas-equivalent",
                        "5",
                    ],
                    None,
                )
                .unwrap();
            assert!(text.contains(asset), "{prefix}: {text}");
            assert!(text.contains(cash), "{prefix}: {text}");
        }
    }

    #[test]
    fn terms_new_reads_the_creation_daa_from_the_node() {
        let mut h = Harness::new();
        let draft = h.draft("08-");
        let out = h.path("terms.json");
        let args = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--node",
            "ws://127.0.0.1:17210",
        ];
        // The fake node's virtual DAA score is 1_000, before the vector's creation range, so
        // the expiry is beyond the one-year horizon from there.
        assert_eq!(h.refuse(&args, None), "TERMS_EXPIRY_BEYOND_HORIZON");
        assert_eq!(h.urls.borrow().as_slice(), ["ws://127.0.0.1:17210"]);
        h.node = |_| {
            let mut n = FakeNode::testnet();
            n.dag.virtual_daa = 400_000_000;
            n
        };
        assert!(h.run(&args, None).is_ok(), "control");
        h.node = |_| FakeNode::mainnet();
        std::fs::remove_file(&out).unwrap();
        assert_eq!(h.refuse(&args, None), "CLI_NODE_NETWORK_MISMATCH");
    }

    /// A terms file made by `terms new` from a golden vector; on mainnet the creation DAA
    /// score comes from the mainnet fake node.
    fn terms_file(h: &Harness, prefix: &str, network: &str) -> PathBuf {
        let draft = h.draft(prefix);
        let out = h.path(&format!("terms-{prefix}json"));
        let creation = match network {
            "mainnet" => ["--node", MAINNET_NODE],
            _ => ["--daa", DAA],
        };
        let mut args = vec![
            "--network",
            network,
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--i-accept-the-risk",
        ];
        args.extend_from_slice(&creation);
        h.run(&args, None).unwrap();
        out
    }

    fn uri_of(text: &str) -> String {
        text.lines()
            .find_map(|l| l.trim().strip_prefix("funding URI: "))
            .unwrap()
            .to_string()
    }

    #[test]
    fn address_prints_the_uri_and_qr_for_a_kas_leg() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let text = h
            .run(&["address", "--terms", s(&terms), "--daa", DAA], None)
            .unwrap();
        let uri = uri_of(&text);
        assert!(uri.starts_with("kaspatest:p"));
        assert!(uri.contains("?amount=100000000&impulse="));
        assert!(text.contains(
            "  amount is in sompi: before sending, confirm your wallet shows exactly 1.00000000 KAS (100000000 sompi) to this address"
        ));
        // The QR drawn is the QR of the printed URI, exactly.
        let qr = qr::render(&uri).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.trim().starts_with("funding URI: "))
            .unwrap();
        let drawn = lines[at + 2..at + 2 + qr.lines().count()].join("\n");
        assert_eq!(drawn, qr);
        assert!(text.contains("  funded by: the buyer (you)\n  funding URI: "));
        // The asset vault is the seller's to fund: no instructions for the buyer.
        assert!(text.contains(
            "  funded by: the seller (your counterparty); you send nothing to this vault"
        ));
        assert!(!text.contains("escrowed token owner"));
        assert!(!text.contains("no funding URI"));
        let plain = h
            .run(
                &["address", "--terms", s(&terms), "--daa", DAA, "--no-qr"],
                None,
            )
            .unwrap();
        assert!(!plain.contains('\u{2588}'));
        assert_eq!(uri_of(&plain), uri);
    }

    #[test]
    fn address_applies_the_cap() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let args = ["address", "--terms", s(&terms), "--daa", DAA, "--no-qr"];
        let shown = h.run(&args, None).unwrap();
        assert!(
            shown.contains("value cap: trade value 100000000 sompi (1.00000000 KAS; declared 100000000, largest KAS leg 100000000) is within the cap of 1000000000 sompi"),
            "{shown}"
        );
        assert_eq!(h.refuse(&args, Some("99999999")), "CLI_VALUE_CAP_EXCEEDED");
        assert_eq!(h.refuse(&args, Some("2000000000")), "CLI_VALUE_CAP_INVALID");
        // A declared value above the cap, though the KAS leg is 1 KAS.
        let mut high = args.to_vec();
        high.extend_from_slice(&["--kas-equivalent", "1000000001"]);
        assert_eq!(h.refuse(&high, None), "CLI_VALUE_CAP_EXCEEDED");
        // No declaration: refused for a KAS cash leg and for a token cash leg alike.
        h.declare.set(false);
        assert_eq!(h.refuse(&args, None), "CLI_VALUE_UNKNOWN");
        let token = terms_file(&h, "01-", "mainnet");
        let mainnet = [
            "--network",
            "mainnet",
            "address",
            "--terms",
            s(&token),
            "--node",
            MAINNET_NODE,
        ];
        assert_eq!(h.refuse(&mainnet, None), "CLI_VALUE_UNKNOWN");
        let mut declared = mainnet.to_vec();
        declared.extend_from_slice(&["--kas-equivalent", "1000000000"]);
        assert!(h.run(&declared, None).is_ok(), "control");
        let mut lifted = args.to_vec();
        lifted.push("--i-accept-the-risk");
        let text = h.run(&lifted, None).unwrap();
        assert!(text.contains("value cap: lifted by --i-accept-the-risk"));
    }

    #[test]
    fn verify_checks_a_uri() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let text = h
            .run(
                &["address", "--terms", s(&terms), "--daa", DAA, "--no-qr"],
                None,
            )
            .unwrap();
        let uri = uri_of(&text);
        let ok = h
            .run(
                &["verify", "--terms", s(&terms), "--uri", &uri, "--daa", DAA],
                None,
            )
            .unwrap();
        let last = ok.trim_end().lines().last().unwrap();
        assert!(last.starts_with("ok: funds the cash vault"), "{ok}");
        let bad = uri.replace("amount=100000000", "amount=100000001");
        assert_eq!(
            h.refuse(
                &["verify", "--terms", s(&terms), "--uri", &bad, "--daa", DAA],
                None
            ),
            "CLI_URI_AMOUNT_MISMATCH"
        );
        // On mainnet the same terms are refused before any URI check.
        assert_eq!(
            h.refuse(
                &[
                    "--network",
                    "mainnet",
                    "verify",
                    "--terms",
                    s(&terms),
                    "--uri",
                    &uri,
                    "--node",
                    MAINNET_NODE
                ],
                None
            ),
            "TERMS_NETWORK_MISMATCH"
        );
    }

    /// Vector 08 with one edit: the buyer's refund target is the seller's proceeds script, so a
    /// counterparty-signed refund hands the buyer's cash to the seller.
    fn evil_draft(h: &Harness) -> PathBuf {
        let v = pinned_vector("08-");
        let mut t = v["terms"].clone();
        t["buyer_refund"] = t["seller_proceeds"].clone();
        let p = h.path("evil-draft.json");
        std::fs::write(&p, t.to_string()).unwrap();
        p
    }

    /// The evil terms as a terms file, as a counterparty would send it.
    fn evil_terms(h: &Harness) -> PathBuf {
        let draft = terms_file::parse_draft(&read_text(&evil_draft(h)).unwrap()).unwrap();
        let p = h.path("evil-terms.json");
        std::fs::write(&p, render_terms_file(&draft.validate_structure().unwrap())).unwrap();
        p
    }

    #[test]
    fn a_foreign_refund_target_is_refused_before_anything_is_shown() {
        let h = Harness::new();
        let honest = terms_file(&h, "08-", "testnet");
        let evil = evil_terms(&h);
        let uri = uri_of(
            &h.run(
                &["address", "--terms", s(&honest), "--daa", DAA, "--no-qr"],
                None,
            )
            .unwrap(),
        );
        let out = h.path("t.json");
        let draft = evil_draft(&h);
        let new = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--daa",
            DAA,
        ];
        assert_eq!(h.refuse(&new, None), "CLI_DESTINATION_NOT_MINE");
        assert!(!out.exists());
        assert_eq!(
            h.refuse(&["address", "--terms", s(&evil), "--daa", DAA], None),
            "CLI_DESTINATION_NOT_MINE"
        );
        // The URI the evil terms themselves give fails on the role check, before any "ok".
        let evil_trade = FundableTrade::new(
            terms_file::read_terms_file(&evil).unwrap(),
            &CreationContext::new(Network::Testnet, 400_000_000),
        )
        .unwrap();
        let evil_uri = uri::funding_uri(&evil_trade, LegIndex::Cash).unwrap();
        assert_eq!(
            h.refuse(
                &[
                    "verify",
                    "--terms",
                    s(&evil),
                    "--uri",
                    &evil_uri,
                    "--daa",
                    DAA
                ],
                None
            ),
            "CLI_DESTINATION_NOT_MINE"
        );
        // The seller's own destinations are scripts in vector 08: with both pinned the seller may
        // proceed, and the summary shows the buyer_refund as a script of the seller's.
        let seller = [
            "address",
            "--terms",
            s(&evil),
            "--daa",
            DAA,
            "--no-qr",
            "--role",
            "seller",
            "--my-key",
            SELLER_KEY,
        ];
        assert_eq!(h.refuse(&seller, None), "CLI_DESTINATION_NOT_MINE");
        let t08 = terms_file::read_terms_file(&honest).unwrap();
        let proceeds = summary::pin_text(Network::Testnet, &t08.terms().seller_proceeds);
        let refund = summary::pin_text(Network::Testnet, &t08.terms().seller_refund);
        let mut custodian = seller.to_vec();
        custodian.extend_from_slice(&["--my-proceeds", &proceeds, "--my-refund", &refund]);
        let text = h.run(&custodian, None).unwrap();
        assert!(text.contains("buyer_refund: kaspatest:p"), "{text}");
        assert!(
            text.contains("seller_proceeds equals --my-proceeds; seller_refund equals --my-refund"),
            "{text}"
        );
        // Controls: the honest terms pass for the buyer.
        assert!(h
            .run(
                &["verify", "--terms", s(&honest), "--uri", &uri, "--daa", DAA],
                None
            )
            .is_ok());
        let control_out = h.path("t-honest.json");
        let honest_draft = h.draft("08-");
        assert!(h
            .run(
                &[
                    "terms",
                    "new",
                    "--draft",
                    s(&honest_draft),
                    "--out",
                    s(&control_out),
                    "--daa",
                    DAA
                ],
                None
            )
            .is_ok());
    }

    /// Review round 2: vector 08 with buyer_delivery and buyer_refund both paying the seller key.
    /// The blanket override is gone, and no pin makes the buyer accept these terms.
    #[test]
    fn destinations_paying_the_counterparty_are_refused_whatever_is_pinned() {
        let h = Harness::new();
        let v = pinned_vector("08-");
        let mut t = v["terms"].clone();
        t["buyer_delivery"]["identifier"] = SELLER_KEY.into();
        t["buyer_refund"] = serde_json::json!({
            "kind": "kas", "version": 0, "script": format!("20{SELLER_KEY}ac")
        });
        let draft = h.path("evil2.json");
        std::fs::write(&draft, t.to_string()).unwrap();
        let out = h.path("evil2-terms.json");
        let new = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&out),
            "--daa",
            DAA,
        ];
        assert_eq!(h.refuse(&new, None), "CLI_DESTINATION_NOT_MINE");
        let mut flagged = vec!["impulse"];
        flagged.extend_from_slice(&new);
        flagged.extend_from_slice(&["--role", "buyer", "--my-key", BUYER_KEY]);
        flagged.push("--allow-custodian-destinations");
        assert_eq!(
            Cli::try_parse_from(&flagged).unwrap_err().kind(),
            clap::error::ErrorKind::UnknownArgument
        );
        let seller_owner = format!("kcc20:pubkey:{SELLER_KEY}");
        let seller_address = summary::pin_text(
            Network::Testnet,
            &impulse_core::terms::Destination::Kas(
                kaspa_consensus_core::tx::ScriptPublicKey::from_vec(
                    0,
                    [&[0x20][..], &unhex32(SELLER_KEY).unwrap(), &[0xac]].concat(),
                ),
            ),
        );
        let custodian_owner = format!("kcc20:script_hash:{}", "05".repeat(32));
        for (delivery, refund) in [
            (seller_owner.as_str(), seller_address.as_str()),
            (custodian_owner.as_str(), seller_address.as_str()),
        ] {
            let mut pinned = new.to_vec();
            pinned.extend_from_slice(&["--my-delivery", delivery, "--my-refund", refund]);
            assert_eq!(h.refuse(&pinned, None), "CLI_DESTINATION_NOT_MINE");
            assert!(!out.exists());
        }
        // Control: the honest draft with the same arguments.
        let honest = h.draft("08-");
        let honest_out = h.path("honest-terms.json");
        assert!(h
            .run(
                &[
                    "terms",
                    "new",
                    "--draft",
                    s(&honest),
                    "--out",
                    s(&honest_out),
                    "--daa",
                    DAA
                ],
                None
            )
            .is_ok());
    }

    #[test]
    fn pins_must_parse_and_be_the_role_s() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let t = terms_file::read_terms_file(&terms).unwrap();
        let proceeds = summary::pin_text(Network::Testnet, &t.terms().seller_proceeds);
        let refund = summary::pin_text(Network::Testnet, &t.terms().seller_refund);
        let base = [
            "address",
            "--terms",
            s(&terms),
            "--daa",
            DAA,
            "--no-qr",
            "--role",
            "seller",
            "--my-key",
            SELLER_KEY,
        ];
        let with = |extra: &[&str]| -> (Result<(), CliError>, String) {
            let mut v = base.to_vec();
            v.extend_from_slice(extra);
            h.exec(&v, None)
        };
        let control = [
            "--my-proceeds",
            proceeds.as_str(),
            "--my-refund",
            refund.as_str(),
        ];
        assert!(with(&control).0.is_ok(), "control");
        let mainnet_proceeds = proceeds.replace("kaspatest:", "kaspa:");
        let cases: [(Vec<&str>, &str); 5] = [
            (
                vec![
                    "--my-proceeds",
                    &proceeds,
                    "--my-refund",
                    &refund,
                    "--my-delivery",
                    &refund,
                ],
                "CLI_DESTINATION_PIN_INVALID",
            ),
            (
                vec!["--my-proceeds", &mainnet_proceeds, "--my-refund", &refund],
                "CLI_DESTINATION_PIN_INVALID",
            ),
            (
                vec![
                    "--my-proceeds",
                    &proceeds,
                    "--my-refund",
                    "kcc20:script_hash:00",
                ],
                "CLI_DESTINATION_PIN_INVALID",
            ),
            (vec!["--my-proceeds", &proceeds], "CLI_DESTINATION_NOT_MINE"),
            (
                vec!["--my-proceeds", &refund, "--my-refund", &refund],
                "CLI_DESTINATION_NOT_MINE",
            ),
        ];
        for (extra, code) in cases {
            let (result, out) = with(&extra);
            assert_eq!(result.unwrap_err().code(), code, "{extra:?}");
            assert_eq!(out, "", "nothing printed");
        }
        // A buyer pins delivery, never proceeds.
        let buyer_proceeds = [
            "address",
            "--terms",
            s(&terms),
            "--daa",
            DAA,
            "--no-qr",
            "--my-proceeds",
            &proceeds,
        ];
        assert_eq!(
            h.refuse(&buyer_proceeds, None),
            "CLI_DESTINATION_PIN_INVALID"
        );
    }

    #[test]
    fn each_vault_is_funded_by_its_depositor_only() {
        assert_eq!(check_funder(LegIndex::Cash, Role::Buyer), Ok(()));
        assert_eq!(check_funder(LegIndex::Asset, Role::Seller), Ok(()));
        for (leg, role) in [
            (LegIndex::Cash, Role::Seller),
            (LegIndex::Asset, Role::Buyer),
        ] {
            assert_eq!(
                check_funder(leg, role).unwrap_err().code(),
                "CLI_URI_NOT_YOUR_LEG",
                "{leg:?} {role:?}"
            );
        }
    }

    /// Review round 2: a seller was shown, and blessed with ok, the buyer's cash vault URI.
    #[test]
    fn a_seller_gets_no_funding_uri_and_no_ok_for_the_buyer_s_vault() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let t = terms_file::read_terms_file(&terms).unwrap();
        let proceeds = summary::pin_text(Network::Testnet, &t.terms().seller_proceeds);
        let refund = summary::pin_text(Network::Testnet, &t.terms().seller_refund);
        let seller = [
            "--role",
            "seller",
            "--my-key",
            SELLER_KEY,
            "--my-proceeds",
            &proceeds,
            "--my-refund",
            &refund,
        ];
        let mut address = vec!["address", "--terms", s(&terms), "--daa", DAA];
        let buyer_text = h.run(&address, None).unwrap();
        let uri = uri_of(&buyer_text);
        address.extend_from_slice(&seller);
        let text = h.run(&address, None).unwrap();
        assert!(!text.contains("  funding URI: "), "{text}");
        assert!(!text.contains("?amount="), "{text}");
        assert!(!text.contains('\u{2588}'), "no QR: {text}");
        assert!(text.contains("cash vault: kaspatest:p"));
        assert!(text.contains(
            "  funded by: the buyer (your counterparty); you send nothing to this vault"
        ));
        assert!(
            text.contains("  funded by: the seller (you)\n  escrowed token owner: script_hash ")
        );
        assert!(text.contains("no funding URI: a KCC-20 leg"));
        // verify: the seller is refused the buyer's URI before any ok; the buyer is not.
        let mut verify = vec!["verify", "--terms", s(&terms), "--uri", &uri, "--daa", DAA];
        let ok = h.run(&verify, None).unwrap();
        assert!(ok.trim_end().ends_with("your leg as the buyer"), "{ok}");
        verify.extend_from_slice(&seller);
        assert_eq!(h.refuse(&verify, None), "CLI_URI_NOT_YOUR_LEG");
    }

    /// Review round 2: verify, run on a counterparty's URI just before sending, blessed a URI
    /// above the cap that address refused.
    #[test]
    fn verify_applies_the_cap() {
        let h = Harness::new();
        let v = pinned_vector("08-");
        let mut t = v["terms"].clone();
        t["cash_leg"]["amount"] = "100000000000".into();
        let draft = h.path("big.json");
        std::fs::write(&draft, t.to_string()).unwrap();
        let big = h.path("big-terms.json");
        let new = [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&big),
            "--daa",
            DAA,
            "--i-accept-the-risk",
        ];
        h.run(&new, None).unwrap();
        let shown = h
            .run(
                &[
                    "address",
                    "--terms",
                    s(&big),
                    "--daa",
                    DAA,
                    "--no-qr",
                    "--i-accept-the-risk",
                ],
                None,
            )
            .unwrap();
        let uri = uri_of(&shown);
        assert!(uri.contains("?amount=100000000000&"), "{uri}");
        let verify = ["verify", "--terms", s(&big), "--uri", &uri, "--daa", DAA];
        assert_eq!(h.refuse(&verify, None), "CLI_VALUE_CAP_EXCEEDED");
        let mut lifted = verify.to_vec();
        lifted.push("--i-accept-the-risk");
        let ok = h.run(&lifted, None).unwrap();
        assert!(
            ok.contains("value cap: lifted by --i-accept-the-risk"),
            "{ok}"
        );
        assert!(
            ok.trim_end().lines().last().unwrap().starts_with("ok: "),
            "{ok}"
        );
        // The 1 KAS trade: within the default cap, above a lowered one, unknown undeclared.
        let terms = terms_file(&h, "08-", "testnet");
        let small = uri_of(
            &h.run(
                &["address", "--terms", s(&terms), "--daa", DAA, "--no-qr"],
                None,
            )
            .unwrap(),
        );
        let verify = [
            "verify",
            "--terms",
            s(&terms),
            "--uri",
            &small,
            "--daa",
            DAA,
        ];
        let ok = h.run(&verify, None).unwrap();
        assert!(
            ok.contains("value cap: trade value 100000000 sompi"),
            "{ok}"
        );
        assert_eq!(
            h.refuse(&verify, Some("99999999")),
            "CLI_VALUE_CAP_EXCEEDED"
        );
        h.declare.set(false);
        assert_eq!(h.refuse(&verify, None), "CLI_VALUE_UNKNOWN");
    }

    /// Review round 2: on mainnet a plaintext link to another host is refused by every command
    /// that reaches a node, before the node is contacted, beside a loopback control.
    #[test]
    fn every_command_refuses_an_insecure_mainnet_node() {
        const REMOTE: &str = "ws://203.0.113.9:17110";
        let h = Harness::new();
        let terms = terms_file(&h, "04-", "mainnet");
        let draft = h.draft("04-");
        let out = h.path("t04.json");
        let uri = uri_of(
            &h.run(
                &[
                    "--network",
                    "mainnet",
                    "address",
                    "--terms",
                    s(&terms),
                    "--node",
                    MAINNET_NODE,
                    "--no-qr",
                    "--i-accept-the-risk",
                ],
                None,
            )
            .unwrap(),
        );
        let key = key_file();
        let receipt = h.path("r04.json");
        let (txid, from) = (hex(&[0xaa; 32]), hex(&[1; 32]));
        h.run(
            &[
                "--network",
                "mainnet",
                "status",
                "--node",
                MAINNET_NODE,
                "--terms",
                s(&terms),
                "--txid",
                &txid,
                "--from-block",
                &from,
                "--key-file",
                s(&key.path),
                "--out",
                s(&receipt),
                "--min-depth",
                "1",
            ],
            None,
        )
        .unwrap();
        let commands: [Vec<&str>; 4] = [
            vec!["terms", "new", "--draft", s(&draft), "--out", s(&out)],
            vec!["address", "--terms", s(&terms), "--no-qr"],
            vec!["verify", "--terms", s(&terms), "--uri", &uri],
            vec!["receipt", "verify", "--receipt", s(&receipt)],
        ];
        for command in commands {
            let with = |node: &'static str| {
                let mut v = vec!["--network", "mainnet"];
                v.extend_from_slice(&command);
                v.extend_from_slice(&["--node", node]);
                if command[0] != "receipt" {
                    v.push("--i-accept-the-risk");
                }
                v
            };
            h.urls.borrow_mut().clear();
            assert_eq!(
                h.refuse(&with(REMOTE), None),
                "CLI_NODE_INSECURE",
                "{command:?}"
            );
            assert!(h.urls.borrow().is_empty(), "no node contacted: {command:?}");
            assert!(!out.exists());
            assert!(
                h.run(&with(MAINNET_NODE), None).is_ok(),
                "control {command:?}"
            );
            assert_eq!(h.urls.borrow().as_slice(), [MAINNET_NODE], "{command:?}");
            let _ = std::fs::remove_file(&out);
        }
    }

    #[test]
    fn the_party_key_is_checked() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let base = ["address", "--terms", s(&terms), "--daa", DAA, "--no-qr"];
        let with = |role: &'static str, key: &'static str| {
            let mut v = base.to_vec();
            v.extend_from_slice(&["--role", role, "--my-key", key]);
            v
        };
        assert!(h.run(&with("buyer", BUYER_KEY), None).is_ok(), "control");
        assert_eq!(
            h.refuse(&with("buyer", SELLER_KEY), None),
            "CLI_ROLE_KEY_MISMATCH"
        );
        assert_eq!(
            h.refuse(&with("seller", BUYER_KEY), None),
            "CLI_ROLE_KEY_MISMATCH"
        );
        assert_eq!(h.refuse(&with("buyer", "AB"), None), "CLI_HEX");
    }

    #[test]
    fn the_summary_comes_before_any_address_uri_or_ok() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let text = h
            .run(&["address", "--terms", s(&terms), "--daa", DAA], None)
            .unwrap();
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        for field in [
            "terms_hash: ",
            "seller_key: ",
            "buyer_key: ",
            "authority_key: ",
            "asset_leg (seller delivers): ",
            "cash_leg (buyer pays): ",
            "buyer_delivery: ",
            "seller_proceeds: ",
            "seller_refund: ",
            "buyer_refund: ",
            "earliest_daa: ",
            "expiry_daa: 425920000, about 30 days",
            "funding_mode: earmarked",
            "you: buyer, buyer_key ",
        ] {
            assert!(at(field) < at("asset vault: "), "{field}");
        }
        assert!(at("cash vault: ") < at("  funding URI: kaspatest:"));
        assert!(at("  funding URI: kaspatest:") < at("\u{2588}"));
        let uri = uri_of(&text);
        let ok = h
            .run(
                &["verify", "--terms", s(&terms), "--uri", &uri, "--daa", DAA],
                None,
            )
            .unwrap();
        let last = ok.trim_end().lines().last().unwrap();
        assert!(last.starts_with("ok: funds the cash vault"), "{ok}");
        assert!(ok.starts_with("terms_hash: "), "{ok}");
        assert!(ok.contains("buyer_refund: kaspatest:q"), "{ok}");
    }

    #[test]
    fn no_command_has_a_default_node() {
        for args in [
            vec![
                "impulse",
                "status",
                "--terms",
                "t",
                "--txid",
                "x",
                "--from-block",
                "y",
            ],
            vec!["impulse", "address", "--terms", "t"],
            vec!["impulse", "terms", "new", "--draft", "d", "--out", "o"],
        ] {
            let e = Cli::try_parse_from(&args).unwrap_err();
            assert_eq!(
                e.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{args:?}"
            );
        }
        let both = [
            "impulse", "address", "--terms", "t", "--daa", "1", "--node", "ws://x",
        ];
        assert_eq!(
            Cli::try_parse_from(both).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        let key_without_out = [
            "impulse",
            "status",
            "--node",
            "ws://x",
            "--terms",
            "t",
            "--txid",
            "x",
            "--from-block",
            "y",
            "--key-file",
            "k",
        ];
        assert!(Cli::try_parse_from(key_without_out).is_err());
        // A key file needs --min-depth as well as --out.
        let mut no_min_depth = key_without_out.to_vec();
        no_min_depth.extend_from_slice(&["--out", "r"]);
        assert_eq!(
            Cli::try_parse_from(&no_min_depth).unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        no_min_depth.extend_from_slice(&["--min-depth", "1"]);
        assert!(Cli::try_parse_from(&no_min_depth).is_ok(), "control");
    }

    #[test]
    fn status_reports_and_signs_a_receipt() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let txid = hex(&[0xaa; 32]);
        let from = hex(&[1; 32]);
        let base = [
            "status",
            "--node",
            "ws://127.0.0.1:17210",
            "--terms",
            s(&terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
        ];
        let unsigned = h.run(&base, None).unwrap();
        let v: Value = serde_json::from_str(&unsigned).unwrap();
        assert_eq!(v["accepting_block"], hex(&blk(3)));
        assert_eq!(v["daa_score"], "903");
        assert_eq!(v["depth"], "97");
        assert!(v.get("signature").is_none());
        assert!(h.notes.borrow().contains("terms binding: not checked"));

        let key = key_file();
        let receipt_path = h.path("receipt.json");
        let mut signed = base.to_vec();
        signed.extend_from_slice(&["--key-file", s(&key.path), "--out", s(&receipt_path)]);
        // Not yet deep enough: refused, nothing signed or written.
        let mut early = signed.clone();
        early.extend_from_slice(&["--min-depth", "98"]);
        assert_eq!(h.refuse(&early, None), "CLI_DEPTH_BELOW_MINIMUM");
        assert!(!receipt_path.exists());
        signed.extend_from_slice(&["--min-depth", "97"]);
        let text = h.run(&signed, None).unwrap();
        assert!(h.notes.borrow().contains("terms binding: not checked"));
        assert!(
            !text.contains(key.content.trim_end()),
            "no key material in output"
        );
        let on_disk = std::fs::read_to_string(&receipt_path).unwrap();
        assert!(!on_disk.contains(key.content.trim_end()));
        let r = Receipt::parse(&on_disk).unwrap();
        assert_eq!(r.signer, key.signer);
        assert_eq!(
            r.observation.terms_hash,
            terms_file::read_terms_file(&terms).unwrap().terms_hash()
        );

        let ok = h
            .run(
                &[
                    "receipt",
                    "verify",
                    "--receipt",
                    s(&receipt_path),
                    "--signer",
                    &hex(&key.signer),
                    "--node",
                    "ws://127.0.0.1:17210",
                ],
                None,
            )
            .unwrap();
        assert!(
            ok.starts_with("ok: the signature verifies for signer"),
            "{ok}"
        );
        assert!(ok.contains("signer: matches --signer"), "{ok}");
        let t = terms_file::read_terms_file(&terms).unwrap();
        assert!(
            ok.contains(&format!(
                "chain: txid {txid} of terms {} accepted in ",
                hex(&t.terms_hash())
            )),
            "{ok}"
        );
        assert!(ok.contains("terms binding: not checked"), "{ok}");
        assert!(!ok.contains("not authenticated"), "{ok}");
        let offline = h
            .run(&["receipt", "verify", "--receipt", s(&receipt_path)], None)
            .unwrap();
        assert!(offline.contains("on-chain facts not checked"));
        assert!(offline.contains("signer: not authenticated"), "{offline}");
        assert!(offline.contains("terms binding: not checked"), "{offline}");
        assert_eq!(
            h.refuse(
                &[
                    "receipt",
                    "verify",
                    "--receipt",
                    s(&receipt_path),
                    "--signer",
                    &hex(&[2; 32])
                ],
                None
            ),
            "RECEIPT_SIGNER_MISMATCH"
        );
        assert_eq!(
            h.refuse(
                &[
                    "--network",
                    "mainnet",
                    "receipt",
                    "verify",
                    "--receipt",
                    s(&receipt_path)
                ],
                None
            ),
            "CLI_NETWORK_MISMATCH"
        );
        let mut forged: Value = serde_json::from_str(&on_disk).unwrap();
        forged["depth"] = "100000".into();
        let forged_path = h.path("forged.json");
        std::fs::write(&forged_path, forged.to_string()).unwrap();
        assert_eq!(
            h.refuse(&["receipt", "verify", "--receipt", s(&forged_path)], None),
            "RECEIPT_SIGNATURE_INVALID"
        );
        assert_eq!(h.refuse(&signed, None), "CLI_OUTPUT_EXISTS");
    }

    /// Review round 2: a genuine receipt of another trade read as ok unless the verifier compared
    /// hashes by eye. The output now names the trade and transaction, and --terms, --terms-hash
    /// and --txid refuse a receipt for anything else.
    #[test]
    fn receipt_verify_names_and_checks_the_trade_it_covers() {
        let h = Harness::new();
        let terms = terms_file(&h, "08-", "testnet");
        let mine = terms_file::read_terms_file(&terms).unwrap().terms_hash();
        let key = key_file();
        // A receipt for another trade (terms 11.., txid 22..), and one for this trade.
        let other = h.path("other.json");
        let r = Receipt::sign(crate::receipt::tests::observation(), &key.path, false).unwrap();
        std::fs::write(&other, r.render()).unwrap();
        let ours = h.path("ours.json");
        let mut o = crate::receipt::tests::observation();
        o.terms_hash = mine;
        std::fs::write(&ours, Receipt::sign(o, &key.path, false).unwrap().render()).unwrap();
        let (h11, h22, h33) = (hex(&[0x11; 32]), hex(&[0x22; 32]), hex(&[0x33; 32]));
        let verify = |file: &Path, extra: &[&str]| {
            let mut v = vec!["receipt", "verify", "--receipt", s(file)];
            v.extend_from_slice(extra);
            v.iter().map(|x| x.to_string()).collect::<Vec<_>>()
        };
        let run = |args: Vec<String>| {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            h.exec(&args, None)
        };
        // Without a comparison the output still names both, and says they were not compared.
        let plain = run(verify(&other, &[])).1;
        assert!(
            plain.contains(&format!(
                "terms_hash: {h11}, not compared with your trade: pass --terms or --terms-hash"
            )),
            "{plain}"
        );
        assert!(plain.contains(&format!("txid: {h22}, not compared: pass --txid")));
        // Another trade's receipt: refused, nothing printed.
        for (file, extra, code) in [
            (&other, vec!["--terms", s(&terms)], "RECEIPT_TERMS_MISMATCH"),
            (&other, vec!["--terms-hash", &h33], "RECEIPT_TERMS_MISMATCH"),
            (&other, vec!["--txid", &h33], "RECEIPT_TXID_MISMATCH"),
            (
                &ours,
                vec!["--terms", s(&terms), "--txid", &h11],
                "RECEIPT_TXID_MISMATCH",
            ),
            (&other, vec!["--txid", "AA"], "CLI_HEX"),
            (&other, vec!["--terms-hash", "AA"], "CLI_HEX"),
        ] {
            let (result, out) = run(verify(file, &extra));
            assert_eq!(result.unwrap_err().code(), code, "{extra:?}");
            assert_eq!(out, "", "{extra:?}");
        }
        // Controls: the receipt of this trade against its terms file, and the other receipt
        // against its own hash and txid.
        let (result, out) = run(verify(&ours, &["--terms", s(&terms), "--txid", &h22]));
        assert!(result.is_ok(), "{result:?}");
        assert!(
            out.contains(&format!("terms_hash: {}, matches --terms", hex(&mine))),
            "{out}"
        );
        assert!(
            out.contains(&format!("txid: {h22}, matches --txid")),
            "{out}"
        );
        let (result, out) = run(verify(&other, &["--terms-hash", &h11, "--txid", &h22]));
        assert!(result.is_ok(), "{result:?}");
        assert!(
            out.contains(&format!("terms_hash: {h11}, matches --terms-hash")),
            "{out}"
        );
        // --terms and --terms-hash are one choice.
        let mut both = vec!["impulse".to_string()];
        both.extend(verify(&ours, &["--terms", s(&terms), "--terms-hash", &h11]));
        assert_eq!(
            Cli::try_parse_from(&both).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn a_mainnet_receipt_is_signed_through_the_cli_with_network_mainnet() {
        let h = Harness::new();
        let terms = terms_file(&h, "04-", "mainnet");
        let (txid, from) = (hex(&[0xaa; 32]), hex(&[1; 32]));
        let key = key_file();
        let receipt_path = h.path("mainnet-receipt.json");
        let status = [
            "status",
            "--node",
            MAINNET_NODE,
            "--terms",
            s(&terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
            "--key-file",
            s(&key.path),
            "--out",
            s(&receipt_path),
            "--min-depth",
            "1",
        ];
        // Without --network mainnet the command acts on testnet and refuses mainnet terms.
        assert_eq!(h.refuse(&status, None), "CLI_NETWORK_MISMATCH");
        assert!(!receipt_path.exists());
        let mut explicit = vec!["--network", "mainnet"];
        explicit.extend_from_slice(&status);
        h.run(&explicit, None).unwrap();
        let r = Receipt::parse(&std::fs::read_to_string(&receipt_path).unwrap()).unwrap();
        assert_eq!(r.observation.network, Network::Mainnet);
        assert_eq!(r.signer, key.signer);
        assert_eq!(r.verify_signature(), Ok(()));
    }

    #[test]
    fn status_refuses_before_touching_the_node() {
        let h = Harness::new();
        let mainnet_terms = terms_file(&h, "04-", "mainnet");
        h.urls.borrow_mut().clear(); // terms new read the creation DAA score from the node
        let txid = hex(&[0xaa; 32]);
        let from = hex(&[1; 32]);
        let args = [
            "status",
            "--node",
            "ws://127.0.0.1:17210",
            "--terms",
            s(&mainnet_terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
        ];
        assert_eq!(h.refuse(&args, None), "CLI_NETWORK_MISMATCH");
        let bad_url = [
            "status",
            "--node",
            "http://127.0.0.1:1",
            "--terms",
            s(&mainnet_terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
        ];
        assert_eq!(h.refuse(&bad_url, None), "CLI_NODE_URL_INVALID");
        let testnet_terms = terms_file(&h, "08-", "testnet");
        let bad_txid = [
            "status",
            "--node",
            "ws://127.0.0.1:17210",
            "--terms",
            s(&testnet_terms),
            "--txid",
            "AA",
            "--from-block",
            &from,
        ];
        assert_eq!(h.refuse(&bad_txid, None), "CLI_HEX");
        // A leg that does not instantiate: the terms hash is never shown or signed.
        let good_txid = [
            "status",
            "--node",
            "ws://127.0.0.1:17210",
            "--terms",
            s(&testnet_terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
        ];
        for leg in LegIndex::ALL {
            crate::trade::fail::set(
                leg,
                impulse_core::template::TemplateError::StateInvalid { field: "amount" },
            );
            let code = h.refuse(&good_txid, None);
            crate::trade::fail::clear();
            assert_eq!(code, "TEMPLATE_STATE_INVALID", "{leg:?}");
        }
        assert!(h.urls.borrow().is_empty(), "no node was contacted");
        assert!(h.run(&good_txid, None).is_ok(), "control");
        h.urls.borrow_mut().clear();
        // On mainnet a plaintext link to another host is refused before anything is read.
        let mut insecure = vec!["--network", "mainnet"];
        insecure.extend_from_slice(&args);
        assert_eq!(insecure[3], "--node");
        insecure[4] = "ws://203.0.113.9:17110";
        assert_eq!(h.refuse(&insecure, None), "CLI_NODE_INSECURE");
        assert!(h.urls.borrow().is_empty(), "no node was contacted");
        // Before anything is read: a missing terms file is not even opened.
        assert_eq!(insecure[5], "--terms");
        insecure[6] = "/nonexistent/terms.json";
        assert_eq!(h.refuse(&insecure, None), "CLI_NODE_INSECURE");
        insecure[4] = MAINNET_NODE;
        assert_eq!(h.refuse(&insecure, None), "CLI_FILE_READ", "control");
        // A mainnet status with --network mainnet goes to the node, which here is testnet.
        let mut explicit = vec!["--network", "mainnet"];
        explicit.extend_from_slice(&args);
        assert_eq!(h.refuse(&explicit, None), "CLI_NODE_NETWORK_MISMATCH");
    }
}
