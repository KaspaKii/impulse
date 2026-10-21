// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse v2`: the commands for ImpulseVault template v2 trades (spec/V2.md 6.5): terms,
//! addresses, verify, the N-leg builders (fund, settle, per-leg refund), signing, merging,
//! submission and status. Built on impulse-core's `v2` module; the v1 commands are untouched and
//! each version refuses the other's files with the codes it already has.
//!
//! Keyless except through the one signing module: `v2 ipst sign` calls `signing::sign` once per
//! slot, as `ipst sign` does, and nothing here reads, prints or holds key material.

use crate::build_cmd::{node_now, PayArgs};
use crate::cli::{connect, hash_arg, print, CapArgs, CreationArgs, Ctx};
use crate::error::CliError;
use crate::funds::{
    address_script, fee_candidates, outpoint_text, p2pk_address, parse_change, parse_outpoint,
    parse_pay_from, parse_token, utxo_at, utxos_with,
};
use crate::ipst_cmd::{signed_tx_text, AgreedArgs, DaaArgs, SignedTxFile};
use crate::json::hex;
use crate::node::{self, Node};
use crate::receipt_v2::{Quantity, ReceiptV2};
use crate::signing::{self, SignRequest};
use crate::summary::kas_address;
use crate::terms_file::{read_text, write_new};
use crate::v2_terms::{
    self, before_funding, cap, cap_with, check_network, check_party, parse_draft, read_terms,
    render_terms_file, summary, warnings, PartyV2Args,
};
use crate::value_cap::CapPolicy;
use crate::{cli, qr};
use clap::{Args, Subcommand, ValueEnum};
use impulse_core::locktime::check_tx_is_finalized;
use impulse_core::terms::{
    CreationContext, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, LegKind, Network,
};
use impulse_core::tx::{
    min_relay_fee, FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, TokenUtxo,
    TxError, Utxo,
};
use impulse_core::v2::{
    self as v2, check_vault_utxos, fund_kas, fund_kcc20, min_v2, min_vault_v2, read_ipst,
    read_settle, refund, settle, settle_tranche, vault_address, verify_addresses, AnyIpst, IpstV2,
    IpstV2Kind, RefundSignerV2, SettleLeg, TermsV2, TokenEscrow, V2Error, ValidatedTermsV2,
    VaultUtxoWarning, VaultV2,
};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, TransactionOutput};
use std::io::Write;
use std::path::{Path, PathBuf};

// =============================================================================================
// Arguments
// =============================================================================================

#[derive(Subcommand, Debug)]
pub enum V2Command {
    /// Create v2 trade terms (2 to 10 legs).
    #[command(subcommand)]
    Terms(TermsCommand),
    /// Show every leg's vault address, and the funding URI of your own KAS legs.
    Address(AddressArgs),
    /// Check offered addresses and every leg's funding on your node.
    Verify(VerifyArgs),
    /// Build an unsigned funding transaction for one of your legs.
    #[command(subcommand)]
    Fund(FundCommand),
    /// Build an unsigned settle of every leg in one transaction.
    #[command(subcommand)]
    Settle(SettleCommand),
    /// Build an unsigned refund of one leg.
    #[command(subcommand)]
    Refund(RefundCommand),
    /// Sign, merge or write out partially signed transactions of version 2.
    #[command(subcommand)]
    Ipst(IpstCommand),
    /// Check a fully signed IPST of version 2 again and submit it to your node.
    Submit(SubmitArgs),
    /// Report a transaction's acceptance on your node; for a v2 settle, the quantity it moved.
    Status(StatusArgs),
    /// Check receipts of version 2.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
}

#[derive(Subcommand, Debug)]
pub enum ReceiptCommand {
    /// Check a signed receipt of version 2 and its quantities and lineage.
    Verify(ReceiptVerifyArgs),
}

#[derive(Subcommand, Debug)]
pub enum TermsCommand {
    /// Read a draft and write a terms file v2.
    New(TermsNewArgs),
}

#[derive(Subcommand, Debug)]
pub enum FundCommand {
    /// Fund one of your legs: an unsigned IPST of version 2.
    Build(FundArgs),
}

#[derive(Subcommand, Debug)]
pub enum SettleCommand {
    /// Settle every leg of a funded v2 trade: an unsigned IPST of version 2.
    Build(SettleArgs),
}

#[derive(Subcommand, Debug)]
pub enum RefundCommand {
    /// Refund one leg home: an unsigned IPST of version 2.
    Build(RefundArgs),
}

#[derive(Subcommand, Debug)]
pub enum IpstCommand {
    /// Check an IPST of version 2 against the terms you agreed to and sign your slots.
    Sign(Box<SignArgs>),
    /// Combine copies of one IPST of version 2.
    Merge(MergeArgs),
    /// Write a fully signed IPST's transaction as the signed-transaction file, offline.
    Raw(crate::ipst_cmd::RawArgs),
}

/// The token templates (silverc artifacts) of the trade's KCC-20 legs, matched to legs by
/// template hash and lengths.
#[derive(Args, Debug, Default)]
pub struct TemplateArgs {
    /// A KCC-20 token's silverc artifact; repeat for each token template the legs use.
    #[arg(long, value_name = "FILE")]
    pub token_template: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TermsNewArgs {
    /// The draft: terms v2 in JSON form; nonce, expiry_daa and funding_mode may be null.
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// The terms file to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyV2Args,
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
    pub party: PartyV2Args,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Do not draw the QR codes. They are drawn for a dark terminal background.
    #[arg(long)]
    pub no_qr: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub party: PartyV2Args,
    /// An address offered for a leg, <leg>=<address>; give one for every leg to check them.
    #[arg(long, value_name = "LEG=ADDRESS")]
    pub address: Vec<String>,
    #[command(flatten)]
    pub templates: TemplateArgs,
}

#[derive(Args, Debug)]
pub struct FundArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The leg to fund, from 0: one you deposit.
    #[arg(long, value_name = "LEG")]
    pub leg: usize,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub party: PartyV2Args,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// A KCC-20 leg: a token UTXO of yours to escrow, <txid>:<index>:<amount>; repeat for more.
    #[arg(long, value_name = "TXID:INDEX:AMOUNT")]
    pub token: Vec<String>,
    /// A KCC-20 leg: KAS on the escrowed token output; default MIN_V2(2, O) for these terms.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 leg: KAS on the authorizer at the vault; default MIN_V2(1, O), or MIN_V2(2, O) for partial terms (D97).
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct SettleArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Settle this many whole lots now (a tranche) and let every vault continue with the rest
    /// (partial terms only, spec/V2.md 4.4). Without it, settle everything the escrows hold.
    #[arg(long, value_name = "LOTS")]
    pub tranche: Option<u64>,
    /// The number of lots the escrows of a partial trade hold now, when it is not the lot
    /// count of the terms (after earlier tranches) and no KAS leg shows it.
    #[arg(long, value_name = "LOTS")]
    pub held_lots: Option<u64>,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Who signs a v2 refund: the depositor of a leg, named by the leg, or the authority.
fn parse_signer(text: &str) -> Result<RefundSignerV2, String> {
    if text == "authority" {
        return Ok(RefundSignerV2::Authority);
    }
    match text.parse::<usize>() {
        Ok(j) if j.to_string() == text => Ok(RefundSignerV2::Depositor(j)),
        _ => Err("expected a leg number (its depositor signs) or authority".into()),
    }
}

#[derive(Args, Debug)]
pub struct RefundArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The leg to refund, from 0.
    #[arg(long, value_name = "LEG")]
    pub leg: usize,
    /// Who signs: the depositor of leg <j> (its number), or authority.
    #[arg(long, value_name = "LEG|authority", value_parser = parse_signer)]
    pub signer: RefundSignerV2,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// The vault UTXO to refund, <txid>:<index>; needed when the vault holds several.
    #[arg(long, value_name = "TXID:INDEX")]
    pub vault_utxo: Option<String>,
    /// The leg's depositor only: refund the authorizer alone; the escrowed token stays.
    #[arg(long, conflicts_with_all = ["token_amount", "token_minter"])]
    pub without_token: bool,
    /// The escrowed token's amount, when it is not the leg amount.
    #[arg(long, value_name = "AMOUNT")]
    pub token_amount: Option<u64>,
    /// The escrowed token is a minter (it goes home as one).
    #[arg(long)]
    pub token_minter: bool,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Who signs an IPST of version 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignRole {
    /// The depositor of one or more legs.
    Depositor,
    /// The terms' authority_key.
    Authority,
    /// A key that is none of the terms' keys and only pays a fee.
    Payer,
}

impl SignRole {
    fn name(self) -> &'static str {
        match self {
            SignRole::Depositor => "depositor",
            SignRole::Authority => "authority",
            SignRole::Payer => "payer",
        }
    }
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// The IPST of version 2 to sign.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    #[command(flatten)]
    pub agreed: AgreedArgs,
    /// Your key file: 64 hex digits, readable by you only. Read by the signing module only.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
    /// Who you are in the trade.
    #[arg(long, value_enum)]
    pub role: SignRole,
    #[command(flatten)]
    pub party: PartyV2Args,
    #[command(flatten)]
    pub daa: DaaArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Where your change must go; default the P2PK of --my-key.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// When you sign a fee input: the largest fee you accept, in sompi; default twice the
    /// minimum relay fee, and only when you sign at most three fee inputs.
    #[arg(long, value_name = "SOMPI")]
    pub max_fee: Option<u64>,
    /// When you sign a fee input of a settle or refund: the most KAS you accept to top up
    /// under-funded trade outputs with, in sompi; default 0.
    #[arg(long, value_name = "SOMPI")]
    pub max_topup: Option<u64>,
    /// A KCC-20 funding: the KAS on the escrowed token, which must equal the document's;
    /// default MIN_V2(2, O).
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 funding: the KAS on the authorizer, which must equal the document's; default
    /// MIN_V2(1, O).
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Where to write the signed IPST; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct MergeArgs {
    /// The IPSTs to combine: two or more files after one --ipst, in order.
    #[arg(long = "ipst", value_name = "FILE", required = true, num_args = 2..)]
    pub ipsts: Vec<PathBuf>,
    #[command(flatten)]
    pub daa: DaaArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Where to write the combined IPST; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct SubmitArgs {
    /// The fully signed IPST of version 2.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Also write the signed transaction for impulse-watch run --keep-signed: created before
    /// anything is sent, removed if the submission is refused; must not exist.
    #[arg(long, value_name = "FILE")]
    pub signed_tx_out: Option<PathBuf>,
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
    /// Sign the result as a receipt of version 2 with this key file. The transaction must be a
    /// v2 settle of these terms (`IPST_TERMS_MISMATCH` otherwise).
    #[arg(long, value_name = "FILE", requires_all = ["out", "min_depth"])]
    pub key_file: Option<PathBuf>,
    /// Where to write the receipt; must not exist.
    #[arg(long, value_name = "FILE", requires = "key_file")]
    pub out: Option<PathBuf>,
    /// With --key-file: refuse to sign unless the depth (DAA scores since the accepting block)
    /// is at least this.
    #[arg(long, value_name = "DAA", requires = "key_file")]
    pub min_depth: Option<u64>,
    /// The receipt of the previous transaction of the lineage, for a later tranche: its
    /// cumulative is carried forward and its continuations must be what this transaction spent.
    #[arg(long, value_name = "FILE")]
    pub previous: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ReceiptVerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub receipt: PathBuf,
    /// The x-only public key the receipt must be signed by.
    #[arg(long, value_name = "HEX")]
    pub signer: Option<String>,
    /// The terms file of your trade: the receipt must name its terms hash and its quantities
    /// must follow from the terms.
    #[arg(long, value_name = "FILE", conflicts_with = "terms_hash")]
    pub terms: Option<PathBuf>,
    /// The terms hash of your trade, 64 lowercase hex digits: the receipt must name it.
    #[arg(long, value_name = "HEX")]
    pub terms_hash: Option<String>,
    /// The transaction ID you expect, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub txid: Option<String>,
    /// The receipt of the previous transaction of the lineage.
    #[arg(long, value_name = "FILE")]
    pub previous: Option<PathBuf>,
    /// wRPC URL of a synced node to re-check the on-chain facts against; with --terms the
    /// transaction is read again and its lots and lineage compared with the receipt.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

/// Runs one `impulse v2` command.
pub(crate) fn run(ctx: &Ctx, command: V2Command, out: &mut dyn Write) -> Result<(), CliError> {
    match command {
        V2Command::Terms(TermsCommand::New(a)) => terms_new(ctx, a, out),
        V2Command::Address(a) => address(ctx, a, out),
        V2Command::Verify(a) => verify(ctx, a, out),
        V2Command::Fund(FundCommand::Build(a)) => fund_build(ctx, a, out),
        V2Command::Settle(SettleCommand::Build(a)) => settle_build(ctx, a, out),
        V2Command::Refund(RefundCommand::Build(a)) => refund_build(ctx, a, out),
        V2Command::Ipst(IpstCommand::Sign(a)) => sign(ctx, *a, out),
        V2Command::Ipst(IpstCommand::Merge(a)) => merge(ctx, a, out),
        V2Command::Ipst(IpstCommand::Raw(a)) => raw(ctx, a, out),
        V2Command::Submit(a) => submit(ctx, a, out),
        V2Command::Status(a) => status(ctx, a, out),
        V2Command::Receipt(ReceiptCommand::Verify(a)) => receipt_verify(ctx, a, out),
    }
}

// =============================================================================================
// Shared pieces
// =============================================================================================

/// Core v2 refusals keep their codes; the core's text already starts with the code.
impl From<V2Error> for CliError {
    fn from(e: V2Error) -> Self {
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

/// The token templates the user gave, read and parsed.
pub(crate) struct Templates(Vec<Kcc20Template>);

impl Templates {
    pub(crate) fn read(args: &TemplateArgs) -> Result<Self, CliError> {
        args.token_template
            .iter()
            .map(|p| Ok(Kcc20Template::from_json(&read_text(p)?)?))
            .collect::<Result<Vec<_>, CliError>>()
            .map(Self)
    }

    /// The template of KCC-20 leg `leg` (`CLI_TEMPLATE_MISSING` if none given matches it).
    pub(crate) fn of(&self, leg: usize, token: &Kcc20Token) -> Result<&Kcc20Template, CliError> {
        self.0
            .iter()
            .find(|t| t.check_token(token).is_ok())
            .ok_or_else(|| {
                CliError::new(
                    "CLI_TEMPLATE_MISSING",
                    format!(
                        "leg {leg} is a KCC-20 token of template {} ({}+{}): pass --token-template <its silverc artifact>",
                        hex(&token.template_hash),
                        token.template_prefix_len,
                        token.template_suffix_len
                    ),
                )
            })
    }

    /// The templates of the KCC-20 legs in leg order, as the terms check takes them.
    pub(crate) fn for_check(&self, t: &TermsV2) -> Result<Vec<&Kcc20Template>, CliError> {
        t.legs
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match &l.asset.kind {
                LegKind::Kcc20(token) => Some(self.of(i, token)),
                _ => None,
            })
            .collect()
    }
}

fn leg_index(t: &TermsV2, leg: usize) -> Result<(), CliError> {
    if leg >= t.legs.len() {
        return Err(V2Error::TemplateLegIndex {
            value: leg as i64,
            leg_count: t.legs.len(),
        }
        .into());
    }
    Ok(())
}

fn not_found(what: String) -> CliError {
    CliError::new("CLI_UTXO_NOT_FOUND", what)
}

/// The payer, the change script and the fee from the arguments.
struct Pay {
    from: Address,
    change: ScriptPublicKey,
    fee: Option<u64>,
}

fn pay(args: &PayArgs, network: Network) -> Result<Pay, CliError> {
    let from = parse_pay_from(&args.pay_from, network)?;
    let change = match &args.change {
        Some(c) => parse_change(c, network)?,
        None => address_script(&from),
    };
    Ok(Pay {
        from,
        change,
        fee: args.fee,
    })
}

/// Builds with the first one, two, ... fee candidates until the builder accepts, and with the
/// minimum relay fee unless `fee` is given (spec/CLI.md, "Common arguments of the builders").
fn build_with_fee(
    candidates: &[Utxo],
    fee: Option<u64>,
    change: &ScriptPublicKey,
    build: impl Fn(&FeePayment) -> Result<IpstV2, V2Error>,
) -> Result<IpstV2, CliError> {
    let mut last = None;
    for k in 1..=candidates.len() {
        let mut payment = FeePayment {
            inputs: candidates[..k].to_vec(),
            fee: fee.unwrap_or_else(|| min_relay_fee(0)),
            change: change.clone(),
        };
        let mut result = build(&payment);
        if fee.is_none() {
            if let Err(V2Error::Tx(TxError::FeeTooLow { minimum, .. })) = result {
                payment.fee = minimum;
                result = build(&payment);
            }
        }
        match result {
            Ok(ipst) => return Ok(ipst),
            Err(
                e @ V2Error::Tx(TxError::InsufficientFunds { .. } | TxError::BelowMinKas { .. }),
            ) => last = Some(e),
            Err(e) => return Err(e.into()),
        }
    }
    Err(last.map_or_else(
        || CliError::new("CLI_UTXO_NOT_FOUND", "no fee input"),
        CliError::from,
    ))
}

fn script_hash_owner(vault: &VaultV2) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

/// The escrowed tokens of a vault: owned by its script hash, `amount`, the minter flag, with the
/// token's covenant ID; lowest outpoint first.
fn escrows(
    node: &dyn Node,
    vault: &VaultV2,
    template: &Kcc20Template,
    token: &Kcc20Token,
    amount: u64,
    is_minter: bool,
    network: Network,
) -> Result<Vec<Utxo>, CliError> {
    let state = Kcc20State {
        owner: script_hash_owner(vault),
        amount,
        is_minter,
    };
    utxos_with(
        node,
        &template.script_public_key(&state)?,
        Some(token.covenant_id),
        network,
    )
}

/// The UTXOs at a vault, lowest outpoint first: without a covenant ID, or for partial terms (a
/// KIP-20 genesis and its continuations, or a re-funded plain authorizer) with any.
fn at_vault(
    node: &dyn Node,
    vault: &VaultV2,
    partial: bool,
    network: Network,
) -> Result<Vec<Utxo>, CliError> {
    if !partial {
        return utxos_with(node, &vault.script_public_key(), None, network);
    }
    let spk = vault.script_public_key();
    let address = crate::funds::script_address(&spk, network).ok_or_else(|| {
        CliError::new("CLI_UTXO_NOT_FOUND", "the script has no address to look up")
    })?;
    let mut found: Vec<Utxo> = node
        .utxos(&address)?
        .into_iter()
        .filter(|u| u.entry.script_public_key == spk)
        .collect();
    found.sort_by_key(|u| (u.outpoint.transaction_id.as_bytes(), u.outpoint.index));
    Ok(found)
}

/// The lots a holding amounts to, for partial terms, as text for a status line.
fn lots_text(t: &TermsV2, leg: usize, held: u64) -> String {
    match t.partial {
        Some(p) => format!(" ({} of {} lots)", held / t.unit(leg), p.lot_count),
        None => String::new(),
    }
}

/// How many lot counts a search for a partial trade's escrow tries before it asks for
/// `--held-lots`.
const ESCROW_PROBES: u64 = 200;

/// The escrow of KCC-20 leg `leg` and the amount it holds. Without partial: the token of exactly
/// the leg amount. With partial: whole lots; `hint` lots if given, else the most lots first from
/// the lot count of the terms downward (at most [`ESCROW_PROBES`] lot counts).
#[allow(clippy::too_many_arguments)]
fn find_escrow(
    node: &dyn Node,
    t: &TermsV2,
    leg: usize,
    vault: &VaultV2,
    template: &Kcc20Template,
    token: &Kcc20Token,
    hint: Option<u64>,
    network: Network,
) -> Result<Option<(Utxo, u64)>, CliError> {
    let amount = t.legs[leg].asset.amount;
    let Some(p) = t.partial else {
        return Ok(
            escrows(node, vault, template, token, amount, false, network)?
                .into_iter()
                .next()
                .map(|u| (u, amount)),
        );
    };
    let unit = t.unit(leg);
    let candidates: Vec<u64> = match hint {
        Some(lots) => vec![lots],
        None => (p.min_lot..=p.lot_count)
            .rev()
            .take(ESCROW_PROBES as usize)
            .collect(),
    };
    for lots in candidates {
        let held = lots.saturating_mul(unit);
        if let Some(u) = escrows(node, vault, template, token, held, false, network)?
            .into_iter()
            .next()
        {
            return Ok(Some((u, held)));
        }
    }
    Ok(None)
}

/// The leg's vault UTXO a settle spends: a KAS leg's UTXO of exactly the amount (partial terms:
/// the largest of whole lots, exactly `lots` lots if named), a KCC-20 leg's authorizer holding
/// the most KAS (equal amounts by outpoint).
fn settle_vault_utxo(
    node: &dyn Node,
    t: &TermsV2,
    leg: usize,
    vault: &VaultV2,
    lots: Option<u64>,
    network: Network,
) -> Result<Utxo, CliError> {
    let mut all = at_vault(node, vault, t.partial.is_some(), network)?;
    let amount = t.legs[leg].asset.amount;
    match (t.legs[leg].asset.kind, t.partial) {
        (LegKind::Kas, None) => all
            .into_iter()
            .find(|u| u.entry.amount == amount)
            .ok_or_else(|| {
                not_found(format!(
                    "leg {leg}: no UTXO of exactly {amount} sompi at its vault: is the leg funded?"
                ))
            }),
        (LegKind::Kas, Some(_)) => {
            let unit = t.unit(leg);
            all.retain(|u| {
                u.entry.amount.is_multiple_of(unit)
                    && u.entry.amount <= amount
                    && lots.is_none_or(|l| u.entry.amount == l.saturating_mul(unit))
            });
            all.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
            all.into_iter().next().ok_or_else(|| {
                not_found(format!(
                    "leg {leg}: no UTXO of whole lots ({unit} sompi each) at its vault: is the leg funded?"
                ))
            })
        }
        _ => {
            all.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
            all.into_iter().next().ok_or_else(|| {
                not_found(format!(
                    "leg {leg}: no authorizer at its vault: is the leg funded?"
                ))
            })
        }
    }
}

/// The legs not funded on the node, other than `skip`: no UTXO without a covenant ID at the
/// vault.
fn unfunded_legs(
    node: &dyn Node,
    terms: &ValidatedTermsV2,
    skip: &[usize],
    network: Network,
) -> Result<Vec<usize>, CliError> {
    let mut legs = Vec::new();
    for i in 0..terms.terms().legs.len() {
        if skip.contains(&i) {
            continue;
        }
        let vault = VaultV2::instantiate_existing(terms, i)?;
        if at_vault(node, &vault, terms.terms().partial.is_some(), network)?.is_empty() {
            legs.push(i);
        }
    }
    Ok(legs)
}

fn legs_text(legs: &[usize]) -> String {
    legs.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every leg instantiated for creation at `ctx` (the creation checks).
fn fundable(
    terms: &ValidatedTermsV2,
    ctx: &CreationContext,
) -> Result<Vec<v2::FundableVaultV2>, CliError> {
    (0..terms.terms().legs.len())
        .map(|i| Ok(VaultV2::instantiate_for_creation(terms, i, ctx)?))
        .collect()
}

fn creation(ctx: &Ctx, args: &CreationArgs) -> Result<CreationContext, CliError> {
    cli::creation(ctx, args)
}

// =============================================================================================
// The transaction lines
// =============================================================================================

/// The `ipst:` name of an IPST of version 2.
pub(crate) fn kind_name(kind: IpstV2Kind) -> String {
    match kind {
        IpstV2Kind::FundKas { leg } => format!("v2 fund_kas leg {leg}"),
        IpstV2Kind::FundKcc20 { leg } => format!("v2 fund_kcc20 leg {leg}"),
        IpstV2Kind::Settle => "v2 settle".into(),
        IpstV2Kind::Tranche { lots } => format!("v2 settle tranche of {lots} lots"),
        IpstV2Kind::Refund {
            leg,
            signer,
            with_token,
        } => format!(
            "v2 refund leg {leg} by {}, {} the token",
            match signer {
                RefundSignerV2::Depositor(j) => format!("depositor of leg {j}"),
                RefundSignerV2::Authority => "authority".into(),
            },
            if with_token { "with" } else { "without" }
        ),
    }
}

fn is_funding(kind: IpstV2Kind) -> bool {
    matches!(
        kind,
        IpstV2Kind::FundKas { .. } | IpstV2Kind::FundKcc20 { .. }
    )
}

/// How many inputs come before the fee inputs (spec/V2.md 4.3 and 6.1).
pub(crate) fn trade_inputs(kind: IpstV2Kind, ipst: &IpstV2) -> usize {
    let t = ipst.terms().terms();
    match kind {
        IpstV2Kind::FundKas { .. } => 0,
        IpstV2Kind::FundKcc20 { .. } => ipst
            .entries()
            .iter()
            .take_while(|e| e.covenant_id.is_some())
            .count(),
        IpstV2Kind::Settle | IpstV2Kind::Tranche { .. } => t.legs.len() + t.kcc20_legs(),
        IpstV2Kind::Refund { with_token, .. } => 1 + usize::from(with_token),
    }
}

/// How many outputs come before the change.
pub(crate) fn trade_outputs(kind: IpstV2Kind, ipst: &IpstV2) -> usize {
    let t = ipst.terms().terms();
    match kind {
        IpstV2Kind::FundKas { .. } => 1,
        IpstV2Kind::FundKcc20 { .. } => {
            2 + usize::from(
                ipst.transaction()
                    .outputs
                    .get(2)
                    .is_some_and(|o| o.covenant.is_some()),
            )
        }
        IpstV2Kind::Settle => t.legs.len() + t.kcc20_legs(),
        IpstV2Kind::Tranche { .. } => 2 * t.legs.len() + t.kcc20_legs(),
        IpstV2Kind::Refund { with_token, .. } => 1 + usize::from(with_token),
    }
}

/// What the fee inputs put into the trade outputs beyond the fee.
pub(crate) fn payer_cost(kind: IpstV2Kind, ipst: &IpstV2) -> u64 {
    let held: u64 = ipst
        .entries()
        .iter()
        .take(trade_inputs(kind, ipst))
        .fold(0, |s, e| s.saturating_add(e.amount));
    let paid: u64 = ipst
        .transaction()
        .outputs
        .iter()
        .take(trade_outputs(kind, ipst))
        .fold(0, |s, o| s.saturating_add(o.value));
    paid.saturating_sub(held)
}

fn address_of(network: Network, spk: &ScriptPublicKey) -> String {
    kas_address(network, spk.version(), spk.script())
}

/// The transaction lines of an IPST of version 2 (spec/CLI.md, "The transaction lines").
pub(crate) fn lines(ipst: &IpstV2, kind: IpstV2Kind, token_change: Option<u64>) -> Vec<String> {
    let network = ipst.terms().terms().network;
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
            address_of(network, &entry.script_public_key)
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
            address_of(network, &output.script_public_key)
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
            address_of(network, &o.script_public_key)
        ),
        None => "change: none".into(),
    });
    lines.push(format!(
        "masses: compute {}, transient {}, storage {}",
        masses.compute, masses.transient, masses.storage
    ));
    if ipst.above_pre_toccata_cap() {
        lines.push(format!(
            "warning: a mass dimension is above {} grams: a node or wallet that still applies the pre-Toccata standardness cap does not relay this transaction (spec/V2.md 6.2)",
            v2::PRE_TOCCATA_MASS_CAP
        ));
    }
    if let (IpstV2Kind::FundKcc20 { .. }, 3) = (kind, n) {
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

fn finish(
    out: &mut dyn Write,
    mut lines: Vec<String>,
    ipst: &IpstV2,
    kind: IpstV2Kind,
    token_change: Option<u64>,
    path: &Path,
) -> Result<(), CliError> {
    write_new(path, &ipst.to_json())?;
    lines.extend(self::lines(ipst, kind, token_change));
    lines.push(format!("wrote: {}", path.display()));
    print(out, &lines)
}

// =============================================================================================
// terms new, address, verify
// =============================================================================================

fn vault_lines(
    terms: &ValidatedTermsV2,
    vaults: &[v2::FundableVaultV2],
    own: &[usize],
) -> Vec<String> {
    vaults
        .iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                "leg {i} vault: {}{}",
                vault_address(v),
                if own.contains(&i) {
                    " (yours to fund)".to_string()
                } else {
                    format!(
                        " (funded by its depositor {})",
                        hex(&terms.terms().legs[i].depositor_key)
                    )
                }
            )
        })
        .collect()
}

fn terms_new(ctx: &Ctx, a: TermsNewArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_text(&a.draft)?;
    let creation = creation(ctx, &a.creation)?;
    let (draft, notes) = parse_draft(&text, creation.creation_daa)?;
    let terms = draft.validate_structure()?;
    let vaults = fundable(&terms, &creation)?;
    v2_terms::check_kas_minimum(terms.terms())?;
    let (_, own, you) = check_party(terms.terms(), &a.party)?;
    let mut lines = summary(&terms, creation.creation_daa);
    lines.extend(you);
    lines.extend(warnings(terms.terms()));
    lines.extend(notes);
    lines.push(cap(ctx, &a.cap, terms.terms())?);
    write_new(&a.out, &render_terms_file(&terms))?;
    lines.extend(vault_lines(&terms, &vaults, &own));
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

fn address(ctx: &Ctx, a: AddressArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms(ctx, &a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    let vaults = fundable(&terms, &creation)?;
    let t = terms.terms();
    before_funding(t)?;
    let (_, own, you) = check_party(t, &a.party)?;
    let mut lines = summary(&terms, creation.creation_daa);
    lines.extend(you);
    lines.extend(warnings(t));
    lines.push(cap(ctx, &a.cap, t)?);
    for (i, v) in vaults.iter().enumerate() {
        let address = vault_address(v);
        lines.push(format!("leg {i} vault: {address}"));
        if !own.contains(&i) {
            lines.push(format!(
                "  funded by: its depositor {}; you send nothing to this vault (what you send there goes to that leg's refund destination, not to you)",
                hex(&t.legs[i].depositor_key)
            ));
            continue;
        }
        lines.push("  funded by: you".into());
        let amount = t.legs[i].asset.amount;
        match t.legs[i].asset.kind {
            LegKind::Kas => {
                let uri = format!(
                    "{address}?amount={amount}&impulse={}",
                    hex(&terms.terms_hash())
                );
                lines.push(format!("  funding URI: {uri}"));
                lines.push(format!(
                    "  amount is in sompi: before sending, confirm your wallet shows exactly {} KAS ({amount} sompi) to this address",
                    crate::summary::kas(amount)
                ));
                if !a.no_qr {
                    lines.push(qr::render(&uri)?.trim_end().to_string());
                }
            }
            _ => {
                lines.push(format!(
                    "  token owner: SCRIPT_HASH {} (this vault's script hash); a KCC-20 leg is funded with two outputs: build it with impulse v2 fund build --leg {i}",
                    hex(&v.vault().script_hash())
                ));
            }
        }
    }
    if t.funding_mode == FundingMode::Earmarked {
        lines.push("warning: earmarked funding: once you fund, your leg comes home before expiry_daa only if another depositor or the authority sends it home".into());
    }
    print(out, &lines)
}

/// `--address <leg>=<address>`, one per leg at most.
fn offered_addresses(texts: &[String], n: usize) -> Result<Vec<Option<String>>, CliError> {
    let mut offered = vec![None; n];
    for text in texts {
        let bad = || {
            CliError::new(
                "VERIFY_ADDRESS_MALFORMED",
                format!(
                    "--address {text:?}: expected <leg>=<address> with a leg from 0 to {}",
                    n.saturating_sub(1)
                ),
            )
        };
        let (leg_text, address) = text.split_once('=').ok_or_else(bad)?;
        let leg = leg_text
            .parse::<usize>()
            .ok()
            .filter(|l| l.to_string() == leg_text && *l < n && offered[*l].is_none())
            .ok_or_else(bad)?;
        offered[leg] = Some(address.to_string());
    }
    Ok(offered)
}

fn verify(ctx: &Ctx, a: VerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms(ctx, &a.terms)?;
    let t = terms.terms();
    let n = t.legs.len();
    let (_, own, you) = check_party(t, &a.party)?;
    let offered = offered_addresses(&a.address, n)?;
    let templates = Templates::read(&a.templates)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let net = ctx.network;
    let mut lines = summary(&terms, daa);
    lines.extend(you);
    if !a.address.is_empty() {
        let refs: Vec<Option<&str>> = offered.iter().map(|o| o.as_deref()).collect();
        let verified = verify_addresses(&terms, &CreationContext::new(net, daa), &refs)?;
        for v in verified {
            lines.push(format!(
                "address of leg {}: {} pays its vault",
                v.leg, v.address
            ));
        }
    }
    let mut vault_utxos = Vec::with_capacity(n);
    let mut tokens = Vec::with_capacity(n);
    let mut funded = Vec::new();
    for (i, l) in t.legs.iter().enumerate() {
        let vault = VaultV2::instantiate_existing(&terms, i)?;
        let utxos = at_vault(node.as_ref(), &vault, t.partial.is_some(), net)?;
        let status = match &l.asset.kind {
            LegKind::Kcc20(token) => {
                let found = match templates.of(i, token) {
                    Ok(tmpl) => Some(
                        find_escrow(node.as_ref(), t, i, &vault, tmpl, token, None, net)?
                            .into_iter()
                            .collect::<Vec<_>>(),
                    ),
                    Err(_) => None,
                };
                let status = match (&found, utxos.is_empty()) {
                    (_, true) => "unfunded".to_string(),
                    (Some(e), false) if !e.is_empty() => {
                        funded.push(i);
                        format!(
                            "funded: authorizer {} sompi, escrow of {} token units{}",
                            utxos.iter().map(|u| u.entry.amount).max().unwrap_or(0),
                            e[0].1,
                            lots_text(t, i, e[0].1)
                        )
                    }
                    (Some(_), false) => format!(
                        "authorizer only: no escrow of {} token units owned by the vault",
                        if t.partial.is_some() {
                            "whole lots of"
                        } else {
                            "exactly"
                        }
                        .to_string()
                            + &format!(" {}", l.asset.amount)
                    ),
                    (None, false) => {
                        "authorizer only: the escrow was not looked up (pass --token-template)"
                            .into()
                    }
                };
                tokens.push(found.unwrap_or_default());
                status
            }
            _ => {
                tokens.push(vec![]);
                let whole = |u: &&Utxo| match t.partial {
                    None => u.entry.amount == l.asset.amount,
                    Some(_) => {
                        u.entry.amount > 0
                            && u.entry.amount <= l.asset.amount
                            && u.entry.amount.is_multiple_of(t.unit(i))
                    }
                };
                if let Some(u) = utxos.iter().find(whole) {
                    funded.push(i);
                    format!(
                        "funded: {} sompi{}",
                        u.entry.amount,
                        lots_text(t, i, u.entry.amount)
                    )
                } else if let Some(u) = utxos.first() {
                    format!(
                        "funded, not exact: {} sompi, not the leg amount {}; it cannot settle, only be refunded",
                        u.entry.amount, l.asset.amount
                    )
                } else {
                    "unfunded".to_string()
                }
            }
        };
        lines.push(format!(
            "leg {i}{}: {status}",
            if own.contains(&i) { " (yours)" } else { "" }
        ));
        vault_utxos.push(utxos);
    }
    for w in check_vault_utxos(&terms, &vault_utxos, &tokens)? {
        lines.push(match w {
            VaultUtxoWarning::StrayEscrows { leg, count } => format!(
                "warning: leg {leg}: {count} token UTXOs owned by the vault; a settle may take a stray (spec/V2.md 4.4)"
            ),
            VaultUtxoWarning::PartialWithoutAuthority => "warning: partial terms without an authority: tranches can be front-run (D42)".into(),
            VaultUtxoWarning::BelowMinimum { leg, value, minimum } => format!(
                "warning: leg {leg}: a vault UTXO of {value} sompi is below MIN_V2 {minimum}: its settle may exceed the storage cap (spec/V2.md 6.2)"
            ),
        });
    }
    lines.extend(warnings(t));
    let unfunded: Vec<usize> = (0..n).filter(|i| !funded.contains(i)).collect();
    if own.iter().any(|i| funded.contains(i)) && !unfunded.is_empty() {
        lines.push(format!(
            "warning: legs {} are not funded; no settle can be built until every leg is funded. At the funding deadline, unwind as spec/V2.md 4.7 says",
            legs_text(&unfunded)
        ));
    }
    lines.push(
        "note: the UTXO set shows no spend; a leg whose vault was already spent reads as unfunded"
            .into(),
    );
    lines.push(format!("ok: {} of {n} legs funded", funded.len()));
    print(out, &lines)
}

// =============================================================================================
// Builders
// =============================================================================================

pub(crate) fn fund_build(ctx: &Ctx, a: FundArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let net = ctx.network;
    let creation = CreationContext::new(net, daa);
    let vaults = fundable(&terms, &creation)?;
    let t = terms.terms();
    before_funding(t)?;
    let (my_key, own, you) = check_party(t, &a.party)?;
    leg_index(t, a.leg)?;
    if !own.contains(&a.leg) {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "leg {} is deposited by {}; you deposit leg {}",
                a.leg,
                hex(&t.legs[a.leg].depositor_key),
                legs_text(&own)
            ),
        ));
    }
    let mut lines = summary(&terms, daa);
    lines.extend(you);
    lines.extend(warnings(t));
    lines.push(cap(ctx, &a.cap, t)?);
    let pay = pay(&a.pay, net)?;
    let mine = p2pk_address(&my_key, net);
    if pay.from != mine {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "--pay-from {} is not the P2PK address of --my-key ({mine}): a funding is signed by its depositor only, so it is paid from your own address",
                pay.from
            ),
        ));
    }
    let vault = &vaults[a.leg];
    let l = &t.legs[a.leg];
    let (ipst, kind, token_change) = match l.asset.kind {
        LegKind::Kcc20(token) => {
            let templates = Templates::read(&a.templates)?;
            let template = templates.of(a.leg, &token)?;
            if a.token.is_empty() {
                return Err(not_found(format!(
                    "a KCC-20 leg is funded with your token UTXOs: pass --token <txid>:<index>:<amount> (held by {})",
                    hex(&my_key)
                )));
            }
            let mut tokens = Vec::with_capacity(a.token.len());
            for text in &a.token {
                let (outpoint, amount) = parse_token("--token", text)?;
                let state = Kcc20State::new(
                    Kcc20Owner {
                        identifier_type: IdentifierType::PubKey,
                        identifier: my_key,
                    },
                    amount,
                );
                let utxo = utxo_at(
                    node.as_ref(),
                    &outpoint,
                    &template.script_public_key(&state)?,
                    Some(token.covenant_id),
                    net,
                    "--token",
                )?;
                tokens.push(TokenUtxo { utxo, state });
            }
            let held: u64 = tokens
                .iter()
                .fold(0u64, |s, t| s.saturating_add(t.state.amount));
            let deposit = Kcc20Deposit {
                tokens,
                carrier: a.carrier.unwrap_or_else(|| min_v2(t, 2)),
                authorizer: a.authorizer.unwrap_or_else(|| min_vault_v2(t)),
            };
            let exclude: Vec<TransactionOutpoint> =
                deposit.tokens.iter().map(|t| t.utxo.outpoint).collect();
            let candidates = fee_candidates(node.as_ref(), &pay.from, net, &exclude)?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                fund_kcc20(&terms, vault, template, &deposit, p, daa)
            })?;
            let change = held.checked_sub(l.asset.amount).filter(|c| *c > 0);
            (ipst, IpstV2Kind::FundKcc20 { leg: a.leg }, change)
        }
        _ => {
            if !a.token.is_empty() || a.carrier.is_some() || a.authorizer.is_some() {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS leg is funded with KAS alone: --token, --carrier and --authorizer are for KCC-20 legs",
                ));
            }
            let candidates = fee_candidates(node.as_ref(), &pay.from, net, &[])?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                fund_kas(&terms, vault, p, daa)
            })?;
            (ipst, IpstV2Kind::FundKas { leg: a.leg }, None)
        }
    };
    let others = unfunded_legs(node.as_ref(), &terms, &[a.leg], net)?;
    if !others.is_empty() {
        lines.push(format!(
            "warning: legs {} are not funded yet; fund before the funding deadline only if every party will, and unwind as spec/V2.md 4.7 says if one does not",
            legs_text(&others)
        ));
    }
    if t.funding_mode == FundingMode::Earmarked {
        lines.push("warning: earmarked funding: your leg comes home before expiry_daa only if another depositor or the authority sends it home".into());
    }
    finish(out, lines, &ipst, kind, token_change, &a.out)
}

pub(crate) fn settle_build(ctx: &Ctx, a: SettleArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let t = terms.terms();
    let net = ctx.network;
    let mut lines = summary(&terms, daa);
    lines.extend(warnings(t));
    lines.push(cap(ctx, &a.cap, t)?);
    let pay = pay(&a.pay, net)?;
    let templates = Templates::read(&a.templates)?;
    let partial = t.partial.is_some();
    let vaults = (0..t.legs.len())
        .map(|i| VaultV2::instantiate_existing(&terms, i))
        .collect::<Result<Vec<_>, _>>()?;
    // A KAS leg shows how many lots the escrows hold; the KCC-20 legs follow it.
    let mut hint = a.held_lots;
    let mut vault_utxos: Vec<Option<Utxo>> = vec![None; t.legs.len()];
    for (i, l) in t.legs.iter().enumerate() {
        if l.asset.kind == LegKind::Kas {
            let u = settle_vault_utxo(node.as_ref(), t, i, &vaults[i], hint, net)?;
            if partial {
                hint = Some(u.entry.amount / t.unit(i));
            }
            vault_utxos[i] = Some(u);
        }
    }
    let mut found = Vec::with_capacity(t.legs.len());
    let mut used = Vec::new();
    for (i, l) in t.legs.iter().enumerate() {
        let vault_utxo = match vault_utxos[i].take() {
            Some(u) => u,
            None => settle_vault_utxo(node.as_ref(), t, i, &vaults[i], hint, net)?,
        };
        used.push(vault_utxo.outpoint);
        let escrow = match &l.asset.kind {
            LegKind::Kcc20(token) => {
                let tmpl = templates.of(i, token)?;
                let (e, held) = find_escrow(
                    node.as_ref(),
                    t,
                    i,
                    &vaults[i],
                    tmpl,
                    token,
                    hint,
                    net,
                )?
                .ok_or_else(|| {
                    not_found(if partial {
                        format!(
                            "leg {i}: no escrow of whole lots owned by its vault (lot counts tried from {} down; pass --held-lots to name it): is the leg funded?",
                            t.partial.map_or(0, |p| p.lot_count)
                        )
                    } else {
                        format!(
                            "leg {i}: no escrow of {} token units owned by its vault: is the leg funded?",
                            l.asset.amount
                        )
                    })
                })?;
                if partial && hint.is_none() {
                    hint = Some(held / t.unit(i));
                }
                used.push(e.outpoint);
                Some((e, held, tmpl))
            }
            _ => None,
        };
        found.push((vault_utxo, escrow));
    }
    let legs: Vec<SettleLeg> = found
        .iter()
        .map(|(vault, escrow)| match escrow {
            Some((utxo, held, template)) => SettleLeg::Kcc20 {
                authorizer: vault.clone(),
                escrow: TokenEscrow {
                    utxo: utxo.clone(),
                    amount: *held,
                    template,
                },
            },
            None => SettleLeg::Kas {
                vault: vault.clone(),
            },
        })
        .collect();
    let held_lots = match (&found[0].1, &t.legs[0].asset.kind) {
        (Some((_, held, _)), _) => held / t.unit(0),
        (None, _) => found[0].0.entry.amount / t.unit(0),
    };
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| match a.tranche {
        Some(lots) => settle_tranche(&terms, &legs, lots, p, daa),
        None => settle(&terms, &legs, p, daa),
    })?;
    let kind = match a.tranche {
        Some(lots) if partial && lots < held_lots => IpstV2Kind::Tranche { lots },
        _ => IpstV2Kind::Settle,
    };
    if let (Some(lots), true) = (a.tranche, partial) {
        lines.push(format!(
            "tranche: {lots} of {held_lots} lots held now; each vault continues with {} (spec/V2.md 4.6: a partial trade is a sequence of transactions, atomic only within each)",
            held_lots.saturating_sub(lots)
        ));
    }
    if matches!(kind, IpstV2Kind::Tranche { .. }) {
        lines.push(format!(
            "settler cost: {} sompi go into the remainder tokens' carriers (spec/V2.md 4.6); the fee payer signs only with --max-topup of at least that",
            payer_cost(kind, &ipst)
        ));
    }
    finish(out, lines, &ipst, kind, None, &a.out)
}

pub(crate) fn refund_build(ctx: &Ctx, a: RefundArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms(ctx, &a.terms)?;
    let t = terms.terms();
    leg_index(t, a.leg)?;
    let vault = VaultV2::instantiate_existing(&terms, a.leg)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let net = ctx.network;
    let mut lines = summary(&terms, daa);
    lines.push(cap(ctx, &a.cap, t)?);
    let pay = pay(&a.pay, net)?;
    let leg = a.leg;
    let vault_utxo = match &a.vault_utxo {
        Some(text) => {
            let outpoint = parse_outpoint("--vault-utxo", text)?;
            utxo_at(
                node.as_ref(),
                &outpoint,
                &vault.script_public_key(),
                None,
                net,
                "--vault-utxo",
            )?
        }
        None => {
            let mut all = at_vault(node.as_ref(), &vault, t.partial.is_some(), net)?;
            match all.len() {
                0 => return Err(not_found(format!("no UTXO at the vault of leg {leg}"))),
                1 => all.remove(0),
                _ => {
                    return Err(CliError::new(
                        "CLI_UTXO_AMBIGUOUS",
                        format!(
                        "the vault of leg {leg} holds {} UTXOs; choose one with --vault-utxo: {}",
                        all.len(),
                        all.iter()
                            .map(|u| format!(
                                "{} ({} sompi)",
                                outpoint_text(&u.outpoint),
                                u.entry.amount
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    ))
                }
            }
        }
    };
    let l = &t.legs[leg];
    let templates = Templates::read(&a.templates)?;
    let escrowed = match &l.asset.kind {
        LegKind::Kcc20(_) if a.without_token => None,
        LegKind::Kcc20(token) => {
            let template = templates.of(leg, token)?;
            // Partial terms: the escrow a tranche left holds fewer lots than the leg amount.
            let amount = match (a.token_amount, t.partial) {
                (Some(amount), _) => amount,
                (None, Some(_)) if !a.token_minter => {
                    find_escrow(node.as_ref(), t, leg, &vault, template, token, None, net)?
                        .map_or(l.asset.amount, |(_, held)| held)
                }
                (None, _) => l.asset.amount,
            };
            let utxo = escrows(
                node.as_ref(),
                &vault,
                template,
                token,
                amount,
                a.token_minter,
                net,
            )?
            .into_iter()
            .next()
            .ok_or_else(|| {
                not_found(format!(
                    "no escrowed token of {amount} units{} owned by the vault of leg {leg}",
                    if a.token_minter { ", a minter," } else { "" }
                ))
            })?;
            Some(RefundEscrow {
                utxo,
                amount,
                is_minter: a.token_minter,
                template,
            })
        }
        _ => {
            if a.without_token || a.token_amount.is_some() || a.token_minter {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS leg has no escrowed token: --without-token, --token-amount and --token-minter are for KCC-20 legs",
                ));
            }
            None
        }
    };
    let mut used = vec![vault_utxo.outpoint];
    used.extend(escrowed.iter().map(|e| e.utxo.outpoint));
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        refund(&terms, leg, a.signer, &vault_utxo, escrowed.as_ref(), p)
    })?;
    if a.without_token {
        lines.push(format!(
            "note: the escrowed token stays owned by the vault of leg {leg}; to get it back, fund a new authorizer (any KAS) at the vault's address and refund that one with the token"
        ));
    }
    let kind = IpstV2Kind::Refund {
        leg,
        signer: a.signer,
        with_token: escrowed.is_some(),
    };
    finish(out, lines, &ipst, kind, None, &a.out)
}

// =============================================================================================
// IPST of version 2: sign, merge, raw, submit; status
// =============================================================================================

/// Reads an IPST file of version 2 on the command's network. A version 1 document is
/// `IPST_UNSUPPORTED_VERSION`: the v1 commands read it.
pub(crate) fn read_ipst_v2(ctx: &Ctx, path: &Path) -> Result<IpstV2, CliError> {
    let ipst = match read_ipst(&read_text(path)?)? {
        AnyIpst::V2(ipst) => *ipst,
        AnyIpst::V1(_) => return Err(CliError::new(
            "IPST_UNSUPPORTED_VERSION",
            "an IPST of version 1: impulse v2 reads version 2; use the impulse commands without v2",
        )),
    };
    check_network(ctx, ipst.terms().terms().network, "IPST's terms")?;
    Ok(ipst)
}

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

/// The terms check with the templates the user gave.
fn terms_check(
    ipst: &IpstV2,
    templates: &TemplateArgs,
    daa: u64,
) -> Result<v2::TermsMatchV2, CliError> {
    let templates = Templates::read(templates)?;
    let list = templates.for_check(ipst.terms().terms())?;
    Ok(ipst.verify_against_terms(&list, daa)?)
}

fn check_agreed(ctx: &Ctx, a: &AgreedArgs, terms_hash: &[u8; 32]) -> Result<(), CliError> {
    let agreed = match (&a.terms, &a.terms_hash) {
        (Some(path), _) => read_terms(ctx, path)?.terms_hash(),
        (None, Some(h)) => hash_arg("terms-hash", h)?,
        (None, None) => {
            return Err(CliError::new(
                "CLI_IPST_TERMS_NOT_AGREED",
                "name the trade you agreed to: pass --terms <file> or --terms-hash <hex>",
            ))
        }
    };
    if agreed != *terms_hash {
        return Err(CliError::new(
            "CLI_IPST_TERMS_NOT_AGREED",
            format!(
                "the IPST is for terms {}, not the terms you agreed to ({}); do not sign it",
                hex(terms_hash),
                hex(&agreed)
            ),
        ));
    }
    Ok(())
}

/// The signer's role: a depositor passes the party check; the authority is `authority_key`; a
/// payer holds no key of the terms. Returns the key and the `you:` lines.
fn check_signer(t: &TermsV2, a: &SignArgs) -> Result<([u8; 32], Vec<String>), CliError> {
    if a.role == SignRole::Depositor {
        let (key, _, lines) = check_party(t, &a.party)?;
        return Ok((key, lines));
    }
    let key = hash_arg("my-key", &a.party.my_key)?;
    if !a.party.my_delivery.is_empty() || !a.party.my_refund.is_empty() {
        return Err(CliError::new(
            "CLI_DESTINATION_PIN_INVALID",
            format!(
                "the {} has no destination in the terms: --my-delivery and --my-refund are for depositors",
                a.role.name()
            ),
        ));
    }
    let deposits = t.legs.iter().any(|l| l.depositor_key == key);
    match a.role {
        SignRole::Authority if t.authority_key == Some(key) => {
            Ok((key, vec![format!("you: authority, authority_key {}", hex(&key))]))
        }
        SignRole::Authority => Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            format!(
                "the terms name authority_key {}, --my-key is {}; these terms are not yours as authority",
                t.authority_key.map_or_else(|| "none".into(), |k| hex(&k)),
                hex(&key)
            ),
        )),
        _ if deposits => Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            "--my-key deposits a leg of these terms: sign as --role depositor",
        )),
        _ if t.authority_key == Some(key) => Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            "--my-key is the terms' authority_key: sign as --role authority",
        )),
        _ => Ok((
            key,
            vec![format!(
                "you: payer, a key with no role in the terms, {}",
                hex(&key)
            )],
        )),
    }
}

/// A funding: signed by its leg's depositor only, its terms still fundable at `daa`, the checks
/// before funding, and a KCC-20 deposit's carrier and authorizer as the signer states them.
fn check_funding(
    a: &SignArgs,
    ipst: &IpstV2,
    kind: IpstV2Kind,
    my_key: [u8; 32],
    network: Network,
    daa: u64,
) -> Result<(), CliError> {
    let leg = match kind {
        IpstV2Kind::FundKas { leg } | IpstV2Kind::FundKcc20 { leg } => leg,
        _ => return Ok(()),
    };
    let t = ipst.terms().terms();
    let depositor = t.legs[leg].depositor_key;
    if a.role != SignRole::Depositor || depositor != my_key {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "this IPST funds leg {leg}, which {} deposits; you sign as the {} {}",
                hex(&depositor),
                a.role.name(),
                hex(&my_key)
            ),
        ));
    }
    fundable(ipst.terms(), &CreationContext::new(network, daa))?;
    before_funding(t)?;
    if let IpstV2Kind::FundKcc20 { .. } = kind {
        let outputs = &ipst.transaction().outputs;
        let carrier = a.carrier.unwrap_or_else(|| min_v2(t, 2));
        let authorizer = a.authorizer.unwrap_or_else(|| min_vault_v2(t));
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

/// The most fee inputs of the signer the default fee limit covers (spec/CLI.md, "ipst sign").
const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;

/// What the signer commits: the inputs it signs that hold its own funds (every input it signs
/// but the vault inputs of a settle or refund), less what comes back to it; and what the trade
/// takes from it (a funding's deposit; nothing in a settle or refund).
fn outflow(
    ipst: &IpstV2,
    kind: IpstV2Kind,
    my_key: [u8; 32],
    expected_change: &ScriptPublicKey,
) -> Option<(u64, u64)> {
    let t = ipst.terms().terms();
    let n_in = trade_inputs(kind, ipst);
    let n_out = trade_outputs(kind, ipst);
    let vault_inputs = if is_funding(kind) { 0 } else { n_in };
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
        IpstV2Kind::FundKas { leg } => t.legs[leg].asset.amount,
        IpstV2Kind::FundKcc20 { .. } => {
            if n_out == 3 && own.contains(&0) {
                back = back.saturating_add(outputs[2].value);
            }
            outputs[0].value.saturating_add(outputs[1].value)
        }
        IpstV2Kind::Settle | IpstV2Kind::Tranche { .. } | IpstV2Kind::Refund { .. } => 0,
    };
    Some((held.saturating_sub(back), expected))
}

fn change_text(network: Network, o: &TransactionOutput) -> String {
    address_of(network, &o.script_public_key)
}

fn sign(ctx: &Ctx, a: SignArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let mut ipst = read_ipst_v2(ctx, &a.ipst)?;
    check_agreed(ctx, &a.agreed, &ipst.terms().terms_hash())?;
    let t = ipst.terms().terms().clone();
    let (my_key, you) = check_signer(&t, &a)?;
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&ipst, &a.templates, daa)?;
    let kind = checked.kind;
    if (a.carrier.is_some() || a.authorizer.is_some())
        && !matches!(kind, IpstV2Kind::FundKcc20 { .. })
    {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--carrier and --authorizer confirm a KCC-20 funding's deposit",
        ));
    }
    if is_funding(kind) {
        check_funding(&a, &ipst, kind, my_key, t.network, daa)?;
    }
    let policy = CapPolicy::new(ctx.env.max_value, a.cap.i_accept_the_risk)?;
    let cap_line = cap_with(&policy, a.cap.kas_equivalent, &t)?;
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
    let first_fee_input = trade_inputs(kind, &ipst);
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
                        change_text(t.network, change),
                        address_of(t.network, &expected_change)
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
        let topup = payer_cost(kind, &ipst);
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
    if let Some((outflow, expected)) = outflow(&ipst, kind, my_key, &expected_change) {
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
    let mut lines = summary(ipst.terms(), daa);
    lines.extend(you);
    lines.push(cap_line);
    lines.extend(self::lines(&ipst, kind, None));
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

fn merge(ctx: &Ctx, a: MergeArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let mut merged = read_ipst_v2(ctx, &a.ipsts[0])?;
    for path in &a.ipsts[1..] {
        merged = merged.combine(&read_ipst_v2(ctx, path)?)?;
    }
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&merged, &a.templates, daa)?;
    write_new(&a.out, &merged.to_json())?;
    let mut lines = self::lines(&merged, checked.kind, None);
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

fn raw(ctx: &Ctx, a: crate::ipst_cmd::RawArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let ipst = read_ipst_v2(ctx, &a.ipst)?;
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

fn submit(ctx: &Ctx, a: SubmitArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let mut file = match &a.signed_tx_out {
        Some(path) => Some(SignedTxFile::create(path)?),
        None => None,
    };
    let ipst = read_ipst_v2(ctx, &a.ipst)?;
    let node: Box<dyn Node> = connect(ctx, &a.node, ctx.network)?;
    let daa = node::creation_daa(node.as_ref(), ctx.network)?;
    let checked = terms_check(&ipst, &a.templates, daa)?;
    let tx = ipst.finalize()?;
    if let Err(e) = check_tx_is_finalized(&tx, daa, 0) {
        return Err(CliError::new(
            "CLI_TX_NOT_FINAL",
            format!(
                "lock time {}: the node accepts it once its virtual DAA score is above {} (now {daa}): {e}",
                tx.lock_time, tx.lock_time
            ),
        ));
    }
    if let Some(f) = &mut file {
        f.write(&signed_tx_text(&tx))?;
    }
    let submitted = node::submit(node.as_ref(), &tx, ctx.network).map_err(|e| match &file {
        Some(f) => CliError::new(
            e.code(),
            format!(
                "{}; {} is removed. If the node took the transaction all the same, impulse v2 status shows {} accepted: then write the file with impulse v2 ipst raw",
                e.detail(),
                f.path.display(),
                hex(&tx.id().as_bytes())
            ),
        ),
        None => e,
    })?;
    let mut lines = self::lines(&ipst, checked.kind, None);
    lines.push(format!("from_block: {}", hex(&submitted.from_block)));
    lines.push(format!("submitted: {}", hex(&submitted.txid)));
    if let Some(f) = &mut file {
        f.keep = true;
        lines.push(format!("signed_tx: {}", f.path.display()));
    }
    print(out, &lines)
}

fn status(ctx: &Ctx, a: StatusArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms(ctx, &a.terms)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let previous = a
        .previous
        .as_deref()
        .map(|p| ReceiptV2::parse(&read_text(p)?))
        .transpose()?;
    let node = connect(ctx, &a.node, ctx.network)?;
    let o = node::observe(node.as_ref(), ctx.network, terms.terms_hash(), txid, from)?;
    let mut lines = vec![
        format!("terms_hash: {}", hex(&o.terms_hash)),
        format!("txid: {}", hex(&o.txid)),
        format!("accepting_block: {}", hex(&o.accepting_block)),
        format!("daa_score: {}", o.daa_score),
        format!("depth: {}", o.depth),
        "state: accepted (a chain block of the node's virtual selected chain accepts it; it can still be reorganised out. final is the watcher's state at its configured finality depth, spec/V2.md 4.8)".into(),
    ];
    // The transaction itself: a v2 settle of these terms states its quantity and lineage.
    let (_, accepted) = node::find_accepted_tx(node.as_ref(), txid, from)?;
    let facts = read_settle(&terms, &accepted.tx, &accepted.spent);
    match &facts {
        Ok(f) => {
            let q = Quantity::derive(&terms, &o, f, previous.as_ref())?;
            lines.push("terms binding: checked: every vault input of the transaction reveals the v2 vault script of these terms".into());
            lines.extend(quantity_lines(&q, f.tranche));
            if let Some(key_file) = &a.key_file {
                let min_depth = a.min_depth.unwrap_or(0);
                if o.depth < min_depth {
                    return Err(CliError::new(
                        "CLI_DEPTH_BELOW_MINIMUM",
                        format!(
                            "depth {} is below --min-depth {min_depth}; wait and run status again",
                            o.depth
                        ),
                    ));
                }
                let receipt = ReceiptV2::sign(o, q, key_file, ctx.mainnet_explicit)?;
                let path = a.out.as_deref().expect("clap requires --out with --key-file");
                write_new(path, &receipt.render())?;
                lines.push(format!("receipt: {}", path.display()));
            }
        }
        Err(e) if a.key_file.is_some() => return Err(e.clone().into()),
        Err(e) => lines.push(format!(
            "terms binding: not checked; this transaction is not a v2 settle of these terms ({}), so no quantity is stated",
            e.code()
        )),
    }
    print(out, &lines)
}

/// The quantity part of a receipt as lines, one per leg.
fn quantity_lines(q: &Quantity, tranche: bool) -> Vec<String> {
    let mut lines = vec![
        format!(
            "lots: {} in this transaction, {} of {} in the lineage so far",
            q.lots, q.cumulative_lots, q.total_lots
        ),
        format!(
            "continues: {}",
            if tranche {
                "yes, every vault that continued is bound to its covenant"
            } else {
                "no, this transaction leaves no continuation"
            }
        ),
    ];
    for (i, l) in q.legs.iter().enumerate() {
        lines.push(format!(
            "leg {i}: moved {}, cumulative {} of {}",
            l.moved, l.cumulative, l.total
        ));
    }
    lines.push(if q.prior == [0; 32] {
        "lineage: first receipt of its chain: earlier tranches, if any, are not covered; pass --previous to chain a later tranche".into()
    } else {
        format!("lineage: continues the receipt with digest {}", hex(&q.prior))
    });
    lines
}

fn receipt_verify(ctx: &Ctx, a: ReceiptVerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_text(&a.receipt)?;
    let terms = match (&a.terms, &a.terms_hash) {
        (Some(path), _) => Some(read_terms(ctx, path)?),
        _ => None,
    };
    let receipt = match ReceiptV2::parse(&text) {
        Ok(r) => r,
        // A version 1 receipt states no quantity: for partial terms that is the missing fields.
        Err(e)
            if e.code() == "RECEIPT_MALFORMED"
                && serde_json::from_str::<serde_json::Value>(&text)
                    .is_ok_and(|v| v["version"].as_u64() == Some(1))
                && terms.as_ref().is_some_and(|t| t.terms().partial.is_some()) =>
        {
            return Err(CliError::new(
                "RECEIPT_QUANTITY_MISSING",
                "a version 1 receipt does not state the quantity moved or the cumulative quantity, which a receipt of a partial trade must",
            ))
        }
        Err(e) => return Err(e),
    };
    if receipt.observation.network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the receipt is for {}; pass --network {0} to act on it",
                crate::terms_file::network_name(receipt.observation.network)
            ),
        ));
    }
    let expected = a
        .signer
        .as_deref()
        .map(|s| hash_arg("signer", s))
        .transpose()?;
    let your_hash = match (&terms, &a.terms_hash) {
        (Some(t), _) => Some((t.terms_hash(), "--terms")),
        (None, Some(h)) => Some((hash_arg("terms-hash", h)?, "--terms-hash")),
        (None, None) => None,
    };
    let your_txid = a.txid.as_deref().map(|t| hash_arg("txid", t)).transpose()?;
    let previous = a
        .previous
        .as_deref()
        .map(|p| ReceiptV2::parse(&read_text(p)?))
        .transpose()?;
    receipt.verify_signature()?;
    if let Some(expected) = &expected {
        receipt.check_signer(expected)?;
    }
    if let Some((hash, _)) = &your_hash {
        receipt.check_terms_hash(hash)?;
    }
    if let Some(txid) = &your_txid {
        receipt.check_txid(txid)?;
    }
    if let Some(t) = &terms {
        receipt.check_quantities(t)?;
    }
    if let Some(p) = &previous {
        p.verify_signature()?;
        receipt.check_previous(p)?;
    }
    let o = &receipt.observation;
    let chain = match &a.node {
        Some(url) => {
            let node = connect(ctx, url, o.network)?;
            node::verify_observation(node.as_ref(), o)?;
            let mut text = format!(
                "chain: txid {} accepted in {} at DAA score {}, depth now at least {} (state: accepted)",
                hex(&o.txid),
                hex(&o.accepting_block),
                o.daa_score,
                o.depth
            );
            match &terms {
                Some(t) => {
                    let parent = node.block(o.accepting_block)?.selected_parent;
                    let (_, accepted) = node::find_accepted_tx(node.as_ref(), o.txid, parent)?;
                    let facts = read_settle(t, &accepted.tx, &accepted.spent)?;
                    receipt.check_facts(&facts)?;
                    text.push_str("; the transaction was read again and its lots, spent outpoints and covenant IDs match the receipt");
                }
                None => {
                    text.push_str("; the transaction was not read again: pass --terms with --node")
                }
            }
            text
        }
        None => "chain: on-chain facts not checked (pass --node)".into(),
    };
    let q = &receipt.quantity;
    let mut lines = vec![
        format!(
            "ok: the signature verifies for signer {}",
            hex(&receipt.signer)
        ),
        format!(
            "terms_hash: {}, {}",
            hex(&o.terms_hash),
            match your_hash {
                Some((_, flag)) => format!("matches {flag}"),
                None => "not compared with your trade: pass --terms or --terms-hash".into(),
            }
        ),
        format!(
            "txid: {}, {}",
            hex(&o.txid),
            if your_txid.is_some() { "matches --txid" } else { "not compared: pass --txid" }
        ),
        match expected {
            Some(_) => "signer: matches --signer".into(),
            None => "signer: not authenticated: anyone can sign a receipt with their own key; pass --signer <x-only key> to require a known signer".into(),
        },
        chain,
        match terms {
            Some(_) => "quantities: follow from the terms".into(),
            None => "quantities: not compared with the terms: pass --terms".into(),
        },
    ];
    lines.extend(quantity_lines(
        q,
        q.legs.iter().any(|l| l.continuation != [0; 32]),
    ));
    if let Some(p) = &previous {
        lines.push(format!(
            "lineage: checked against the previous receipt {} (cumulative {} of {})",
            hex(&p.digest()),
            p.quantity.cumulative_lots,
            p.quantity.total_lots
        ));
    } else if q.prior != [0; 32] {
        lines.push(
            "lineage: the previous receipt was not supplied: pass --previous to check it".into(),
        );
    }
    print(out, &lines)
}
