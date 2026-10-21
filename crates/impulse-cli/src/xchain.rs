// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse xchain` (I18, spec/V2.md section 10.9): the Kaspa side of a hashlock exchange against
//! a counterpart HTLC on another chain. Its files are read and written in `xchain_doc.rs`, the
//! counterpart chain is reached through `xchain_counterpart.rs`, and its tests are in
//! `xchain_tests.rs`. The seller creates the terms with a fresh secret and funds
//! the hashlock vault; the buyer verifies it and locks on the counterpart chain; the seller checks
//! that lock and reveals the secret by claiming it; the buyer, or anyone, reads the preimage and
//! claims the asset on Kaspa. A hashlock trade is conditional exchange across two chains with
//! residual risk (spec/V2.md section 10.6), not atomic settlement.
//!
//! Rules this module keeps: the secret is made only by `xchain new`, from the operating system's
//! random source, written only to the file the seller names (mode 0600) and never printed, logged
//! or sent; the claim takes the preimage from a secret file or from the counterpart chain, never
//! from the command line; signing goes through `signing::sign` only; every command but the
//! read-only `daa-sample` print the race R2 notice on mainnet and run under the value cap (D39 b,
//! D40); `XCHAIN_MAINNET_GATED` is reserved and no longer returned.

#[path = "xchain_counterpart.rs"]
pub mod counterpart;
#[path = "xchain_doc.rs"]
pub mod doc;
#[path = "xchain_solana.rs"]
pub mod solana;
#[cfg(test)]
#[path = "xchain_tests.rs"]
mod tests;

use crate::build_cmd::PayArgs;
use crate::cli::{connect, hash_arg, print, CapArgs, CreationArgs, Ctx};
use crate::error::CliError;
use crate::funds::{
    address_script, fee_candidates, outpoint_text, p2pk_address, parse_change, parse_outpoint,
    parse_pay_from, parse_token, script_address, utxo_at, utxos_with,
};
use crate::json::hex;
use crate::node::{self, Node, ServerInfo};
use crate::signing::{self, SignRequest};
use crate::summary::{approx_duration, parse_pin};
use crate::terms_file::{read_text, write_new};
use crate::value_cap::CapPolicy;
use clap::{Args, Subcommand, ValueEnum};
use counterpart::{Claim, CounterpartSource, Finality, Lock};
use impulse_core::htlc::{
    self, check_preimage, daa_rate_max, margin_estimate, pinned_daa_rate, DaaRate, DaaRateSample,
    FundableHtlcVault, HtlcCreationContext, HtlcError, HtlcIpst, HtlcIpstKind, HtlcRefundSigner,
    HtlcTermsMatch, HtlcVault, MarginContext, MarginEstimate, ValidatedHtlcTerms,
    DEFAULT_RETRY_SECS, FINALITY_DEPTH_DAA,
};
use impulse_core::locktime::check_tx_is_finalized;
use impulse_core::terms::{
    CreationContext, Destination, IdentifierType, Kcc20Owner, LegKind, Network,
};
use impulse_core::tx::{
    min_relay_fee, FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, TokenUtxo,
    TxError, Utxo, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use impulse_core::verify::{pinned_kcc20, TemplateTriple};
use kaspa_consensus_core::config::params::{MAINNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::network::NetworkId;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Every `XCHAIN_` refusal code, in the order of spec/V2.md section 8.5 and then section 10.9.
/// Frozen once merged: a test pins this list, and it may only grow at the end.
pub const XCHAIN_ERROR_CODES: [&str; 10] = [
    "XCHAIN_CHAIN_UNSUPPORTED",
    "XCHAIN_COUNTERPART_MISMATCH",
    "XCHAIN_NOT_FINAL",
    "XCHAIN_REVEAL_NOT_FOUND",
    "XCHAIN_MARGIN_TOO_SHORT",
    "XCHAIN_HASH_REUSED",
    "XCHAIN_NODE_BPS",
    "XCHAIN_MAINNET_GATED",
    "XCHAIN_SECRET_FILE",
    "XCHAIN_TX_UNRELATED",
];

/// The seller's claim lead before the counterpart timeout: at least two hours (spec/V2.md
/// section 10.5, D39).
pub const MIN_DELTA_CLAIM_SECS: u64 = 7_200;

// =============================================================================================
// Arguments
// =============================================================================================

#[derive(Subcommand, Debug)]
pub enum XchainCommand {
    /// Seller: create hashlock terms with a fresh secret (written to --secret-out, never shown).
    New(Box<NewArgs>),
    /// Buyer: check hashlock terms and the vault address before locking on the counterpart chain.
    Verify(Box<VerifyArgs>),
    /// Seller: build the funding of the hashlock vault.
    #[command(subcommand)]
    Fund(FundCommand),
    /// Buyer: check the funding (escrow and authorizer, unspent, final) before locking.
    VerifyFunding(VerifyFundingArgs),
    /// Seller: check the buyer's counterpart HTLC against the terms (mandatory before revealing).
    VerifyCounterpart(VerifyCounterpartArgs),
    /// Seller: claim the counterpart HTLC, revealing the secret; done only at counterpart-final.
    CounterpartClaim(CounterpartClaimArgs),
    /// Buyer: watch the counterpart chain for the claim that reveals the preimage.
    Watch(WatchArgs),
    /// Build the unsigned Kaspa claim (settleWithPreimage) with the revealed preimage.
    Claim(Box<ClaimArgs>),
    /// Build an unsigned hashlock refund.
    Refund(Box<RefundArgs>),
    /// Sign your slots of a hashlock IPST with your key file.
    Sign(Box<SignArgs>),
    /// Check and submit a fully signed hashlock IPST.
    Submit(SubmitArgs),
    /// Report the state of a Kaspa transaction of this trade (its funding, claim or refund) and,
    /// with --counterpart, the counterpart claim's.
    Status(StatusArgs),
    /// Read only: append one (unix time, virtual DAA score) point to a DAA rate sample file.
    DaaSample(DaaSampleArgs),
}

#[derive(Subcommand, Debug)]
pub enum FundCommand {
    /// Build the seller's funding of the hashlock vault (escrowed token and authorizer).
    Build(Box<FundBuildArgs>),
}

/// The inputs of the margin rule (spec/V2.md section 10.5).
#[derive(Args, Debug)]
pub struct MarginArgs {
    /// The counterpart chain's time to finalized commitment, in seconds, as its source reports it.
    #[arg(long, value_name = "SECS")]
    pub counterpart_final_secs: u64,
    /// The retry window for the Kaspa claim, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_RETRY_SECS)]
    pub retry_secs: u64,
    /// A DAA rate sample file (xchain daa-sample); required on mainnet.
    #[arg(long, value_name = "FILE")]
    pub daa_sample: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// The draft: hashlock terms in JSON form without hash_lock; a missing nonce is drawn at random.
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// Your x-only public key: the terms' seller_key.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// Your account on the counterpart chain: the counterpart record's recipient.
    #[arg(long, value_name = "HEX")]
    pub my_counterpart_account: String,
    /// The exact KCC-20 owner your refund must go to, when it is not --my-key: kcc20:<type>:<hex>.
    #[arg(long, value_name = "PIN")]
    pub my_refund: Option<String>,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub margin: MarginArgs,
    /// This installation's known hash locks; created if missing.
    #[arg(long, value_name = "FILE")]
    pub known_hashes: PathBuf,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Where the secret is written (mode 0600); must not exist. It is never shown.
    #[arg(long, value_name = "FILE")]
    pub secret_out: PathBuf,
    /// The hashlock terms file to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// Your x-only public key: the terms' buyer_key.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// Your account on the counterpart chain: the counterpart record's refund.
    #[arg(long, value_name = "HEX")]
    pub my_counterpart_account: String,
    /// The exact KCC-20 owner the asset must be delivered to, when it is not --my-key.
    #[arg(long, value_name = "PIN")]
    pub my_delivery: Option<String>,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub margin: MarginArgs,
    #[arg(long, value_name = "FILE")]
    pub known_hashes: PathBuf,
    #[command(flatten)]
    pub cap: CapArgs,
}

#[derive(Args, Debug)]
pub struct FundBuildArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// Your x-only public key: the terms' seller_key.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    #[command(flatten)]
    pub margin: MarginArgs,
    #[command(flatten)]
    pub pay: PayArgs,
    /// The asset token's silverc artifact.
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// Your token UTXOs, <txid>:<index>:<amount>.
    #[arg(long, value_name = "TOKEN")]
    pub token: Vec<String>,
    /// KAS on the escrowed token output.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// KAS on the authorizer output.
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyCounterpartArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The counterpart chain's source.
    #[arg(long, value_name = "URL")]
    pub counterpart: String,
    /// The counterpart chain's time to finalized commitment, in seconds.
    #[arg(long, value_name = "SECS")]
    pub counterpart_final_secs: u64,
}

#[derive(Args, Debug)]
pub struct CounterpartClaimArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// Your secret file, as xchain new wrote it.
    #[arg(long, value_name = "FILE")]
    pub secret_file: PathBuf,
    #[arg(long, value_name = "URL")]
    pub counterpart: String,
    #[arg(long, value_name = "SECS")]
    pub counterpart_final_secs: u64,
}

#[derive(Args, Debug)]
pub struct WatchArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub counterpart: String,
    /// Where the revealed preimage is written (mode 0600); must not exist.
    #[arg(long, value_name = "FILE")]
    pub secret_out: PathBuf,
    /// How many times to look.
    #[arg(long, default_value_t = 1)]
    pub polls: u32,
    /// Seconds between two looks.
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    pub interval_secs: u64,
}

#[derive(Args, Debug)]
#[group(id = "preimage_source", required = true, multiple = false)]
pub struct PreimageArgs {
    /// A secret file: the seller's, or the preimage xchain watch wrote.
    #[arg(long, value_name = "FILE", group = "preimage_source")]
    pub secret_file: Option<PathBuf>,
    /// Read the preimage from the counterpart chain's claim.
    #[arg(long, value_name = "URL", group = "preimage_source")]
    pub counterpart: Option<String>,
}

#[derive(Args, Debug)]
pub struct ClaimArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    #[command(flatten)]
    pub preimage: PreimageArgs,
    /// A DAA rate sample file, for the time left before expiry_daa.
    #[arg(long, value_name = "FILE")]
    pub daa_sample: Option<PathBuf>,
    /// The retry window the claim needs before expiry_daa, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_RETRY_SECS)]
    pub retry_secs: u64,
    /// Build the claim even with less than the retry window left (after expiry_daa the seller
    /// may refund, and the first accepted spend wins).
    #[arg(long)]
    pub past_margin: bool,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub cap: CapArgs,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignerArg {
    Seller,
    Buyer,
}

#[derive(Args, Debug)]
pub struct RefundArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// Who signs the refund: the seller from expiry_daa, the buyer at any time with the token.
    #[arg(long, value_enum)]
    pub signer: SignerArg,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// The vault UTXO, <txid>:<index>, when there are several.
    #[arg(long, value_name = "OUTPOINT")]
    pub vault_utxo: Option<String>,
    /// Refund the authorizer alone; the token stays owned by the vault (the seller only).
    #[arg(long)]
    pub without_token: bool,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub cap: CapArgs,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignRole {
    Seller,
    Buyer,
    Payer,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// The hashlock terms file of the trade you agreed to.
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// Your key file. Read only by the signing module; never printed.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
    #[arg(long, value_enum)]
    pub role: SignRole,
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// For a funding: the counterpart chain's time to finalized commitment (the margin rule).
    #[arg(long, value_name = "SECS")]
    pub counterpart_final_secs: Option<u64>,
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_RETRY_SECS)]
    pub retry_secs: u64,
    #[arg(long, value_name = "FILE")]
    pub daa_sample: Option<PathBuf>,
    /// Where your change must go; default the P2PK address of --my-key.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// The largest fee you accept; default twice the minimum relay fee.
    #[arg(long, value_name = "SOMPI")]
    pub max_fee: Option<u64>,
    /// The largest top-up of trade outputs you accept from your fee inputs; default 0.
    #[arg(long, value_name = "SOMPI", default_value_t = 0)]
    pub max_topup: u64,
    /// For a funding: KAS on the escrowed token output.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// For a funding: KAS on the authorizer output.
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct SubmitArgs {
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyFundingArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// The funding transaction the seller submitted, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub txid: String,
    /// A chain block at or before the submission (submit prints it).
    #[arg(long, value_name = "HASH")]
    pub from_block: String,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// A Kaspa transaction of this trade (its funding, the claim, or a refund), 64 lowercase hex
    /// digits.
    #[arg(long, value_name = "HEX")]
    pub txid: String,
    /// A chain block at or before the submission (submit prints it).
    #[arg(long, value_name = "HASH")]
    pub from_block: String,
    #[arg(long, value_name = "URL")]
    pub counterpart: Option<String>,
}

#[derive(Args, Debug)]
pub struct DaaSampleArgs {
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// The sample file; created with its header line if missing.
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
}

// =============================================================================================
// Dispatch and shared checks
// =============================================================================================

pub(crate) fn run(
    ctx: &Ctx,
    cmd: XchainCommand,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    if !matches!(cmd, XchainCommand::DaaSample(_)) {
        gate(ctx, notes)?;
    }
    match cmd {
        XchainCommand::New(a) => new(ctx, *a, out, notes),
        XchainCommand::Verify(a) => verify(ctx, *a, out),
        XchainCommand::Fund(FundCommand::Build(a)) => fund_build(ctx, *a, out),
        XchainCommand::VerifyFunding(a) => verify_funding(ctx, a, out),
        XchainCommand::VerifyCounterpart(a) => verify_counterpart(ctx, a, out),
        XchainCommand::CounterpartClaim(a) => counterpart_claim(ctx, a, out),
        XchainCommand::Watch(a) => watch(ctx, a, out),
        XchainCommand::Claim(a) => claim(ctx, *a, out, notes),
        XchainCommand::Refund(a) => refund(ctx, *a, out, notes),
        XchainCommand::Sign(a) => sign(ctx, *a, out),
        XchainCommand::Submit(a) => submit(ctx, a, out),
        XchainCommand::Status(a) => status(ctx, a, out),
        XchainCommand::DaaSample(a) => daa_sample(ctx, a, out),
    }
}

/// The race R2 disclosure printed on every mainnet hashlock command (spec/V2.md section 10.6).
pub(crate) const MAINNET_R2_NOTICE: &str = "notice: mainnet hashlock is a conditional exchange across two chains, not atomic settlement. Race R2 (spec/V2.md section 10.6): a buyer who controls or colludes with a counterpart block producer or relay can delay the seller's counterpart claim past its timeout. Claim early. Values are capped: declare --kas-equivalent within the cap, or pass --i-accept-the-risk.";

/// The hashlock mainnet gate (spec/V2.md section 10.5), lifted by the owner's answers D39 (b) and
/// D40 (the owner, 2026-10-11, confirmed in chat 2026-10-15): on mainnet the per-trade value
/// cap applies, with race R2 disclosed. XCHAIN_MAINNET_GATED stays reserved and is no longer returned.
fn gate(ctx: &Ctx, notes: &mut dyn Write) -> Result<(), CliError> {
    if ctx.network == Network::Mainnet {
        writeln!(notes, "{MAINNET_R2_NOTICE}")
            .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("cannot write to stderr: {e}")))?;
    }
    Ok(())
}

fn write_err(e: std::io::Error) -> CliError {
    CliError::new("CLI_FILE_WRITE", format!("cannot write to stderr: {e}"))
}

/// A hashlock refusal as a CLI refusal: its code, and its message without the repeated code.
pub(crate) fn htlc_err(e: HtlcError) -> CliError {
    let code = e.code();
    let text = e.to_string();
    let detail = text
        .strip_prefix(code)
        .and_then(|r| r.strip_prefix(": "))
        .map(str::to_string)
        .unwrap_or(text);
    CliError::new(code, detail)
}

/// The system clock, unix seconds.
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn terms_on(ctx: &Ctx, path: &Path) -> Result<ValidatedHtlcTerms, CliError> {
    let terms = doc::read_terms_file(path)?;
    let n = terms.terms().network;
    if n != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the terms are for {}; this command acts on {}",
                doc::network_name(n),
                doc::network_name(ctx.network)
            ),
        ));
    }
    Ok(terms)
}

fn pinned_bps(network: Network) -> u64 {
    match network {
        Network::Mainnet => MAINNET_PARAMS.bps(),
        Network::Testnet => TESTNET_PARAMS.bps(),
    }
}

/// The node's blocks-per-second from the network ID it reports (D54): mainnet and testnet-10 have
/// pinned parameters; nothing else does.
pub(crate) fn node_bps(info: &ServerInfo) -> Option<u64> {
    #[cfg(any(test, feature = "offline-fake-node"))]
    match info.network_name.as_str() {
        "fake-mainnet" => return Some(MAINNET_PARAMS.bps()),
        "fake-testnet" => return Some(TESTNET_PARAMS.bps()),
        _ => {}
    }
    let id = NetworkId::from_str(&info.network_name).ok()?;
    match (id.network_type, id.suffix) {
        (kaspa_consensus_core::network::NetworkType::Mainnet, None) => Some(MAINNET_PARAMS.bps()),
        (kaspa_consensus_core::network::NetworkType::Testnet, Some(10)) => {
            Some(TESTNET_PARAMS.bps())
        }
        _ => None,
    }
}

fn check_bps(info: &ServerInfo, network: Network) -> Result<(), CliError> {
    let want = pinned_bps(network);
    match node_bps(info) {
        Some(b) if b == want => Ok(()),
        found => Err(CliError::new(
            "XCHAIN_NODE_BPS",
            format!(
                "the node ({:?}) runs at {}; {} runs at {want} blocks per second in the pinned parameters",
                info.network_name,
                found.map_or("an unknown rate".to_string(), |b| format!("{b} blocks per second")),
                doc::network_name(network)
            ),
        )),
    }
}

/// A node on the command's network, synced, at the pinned blocks-per-second, and its virtual DAA
/// score.
fn node_now(ctx: &Ctx, url: &str) -> Result<(Box<dyn Node>, u64), CliError> {
    node::check_transport(url, ctx.network)?;
    let node = connect(ctx, url, ctx.network)?;
    let info = node::check_node(node.as_ref(), ctx.network)?;
    check_bps(&info, ctx.network)?;
    let daa = node.dag_info()?.virtual_daa;
    Ok((node, daa))
}

/// The DAA score at creation: from the node, or on testnet only typed.
fn creation_daa(ctx: &Ctx, args: &CreationArgs) -> Result<u64, CliError> {
    match (args.daa, &args.node) {
        (Some(_), _) if ctx.network == Network::Mainnet => Err(CliError::new(
            "CLI_MAINNET_NEEDS_NODE",
            "on mainnet the DAA score is read from your node: pass --node <url>",
        )),
        (Some(daa), _) => Ok(daa),
        (None, Some(url)) => Ok(node_now(ctx, url)?.1),
        (None, None) => Err(CliError::new(
            "CLI_NODE_URL_INVALID",
            "no node URL: pass --node <url> or --daa <score>",
        )),
    }
}

fn read_sample(ctx: &Ctx, path: &Option<PathBuf>) -> Result<Option<DaaRateSample>, CliError> {
    path.as_ref()
        .map(|p| doc::read_sample(p, ctx.network))
        .transpose()
}

/// The creation checks with the margin rule, and the figures to show.
fn creation_checks(
    terms: &ValidatedHtlcTerms,
    daa: u64,
    margin: &MarginArgs,
    sample: Option<&DaaRateSample>,
    now: u64,
) -> Result<(FundableHtlcVault, MarginEstimate), CliError> {
    let ctx = HtlcCreationContext {
        creation: CreationContext::new(terms.terms().network, daa),
        margin: MarginContext {
            now_unix: now,
            counterpart_final_secs: margin.counterpart_final_secs,
            retry_secs: margin.retry_secs,
            sample,
        },
    };
    let vault = HtlcVault::instantiate_for_creation(terms, &ctx).map_err(htlc_err)?;
    let estimate = margin_estimate(terms.terms(), daa, &ctx.margin).map_err(htlc_err)?;
    Ok((vault, estimate))
}

/// Δ_claim: at least two hours and ten times the counterpart's time to finalized commitment.
pub(crate) fn delta_claim(final_secs: u64) -> u64 {
    final_secs.saturating_mul(10).max(MIN_DELTA_CLAIM_SECS)
}

fn check_reveal_window(
    terms: &ValidatedHtlcTerms,
    now: u64,
    final_secs: u64,
) -> Result<u64, CliError> {
    let timeout = terms.terms().counterpart.timeout;
    let dc = delta_claim(final_secs);
    let latest = timeout.saturating_sub(dc);
    if now > latest || timeout < dc {
        return Err(CliError::new(
            "XCHAIN_MARGIN_TOO_SHORT",
            format!(
                "the counterpart timeout {timeout} leaves less than the claim lead of {dc} s after now ({now}): the seller could not reveal in time"
            ),
        ));
    }
    Ok(latest)
}

fn check_pinned_template(terms: &ValidatedHtlcTerms) -> Result<(), CliError> {
    if let LegKind::Kcc20(token) = terms.terms().asset_leg.kind {
        if pinned_kcc20(&TemplateTriple::from(&token)).is_none() {
            return Err(CliError::new(
                "CLI_TEMPLATE_UNPINNED",
                format!(
                    "the asset's KCC-20 template {} ({}+{}) is not a pinned kcc20.sil build: the hashlock budgets are measured for kcc20.sil only",
                    hex(&token.template_hash),
                    token.template_prefix_len,
                    token.template_suffix_len
                ),
            ));
        }
    }
    Ok(())
}

/// The value cap (spec/CLI.md, "Value cap") for a hashlock trade: the asset is a KCC-20 token, so
/// the value is the declared KAS equivalent.
fn cap_line(ctx: &Ctx, cap: &CapArgs) -> Result<(String, Option<u64>), CliError> {
    let policy = CapPolicy::new(ctx.env.max_value, cap.i_accept_the_risk)?;
    let Some(limit) = policy.limit() else {
        return Ok(("value cap: lifted by --i-accept-the-risk".into(), None));
    };
    let value = match cap.kas_equivalent {
        Some(0) | None => {
            return Err(CliError::new(
                "CLI_VALUE_UNKNOWN",
                "the asset is a KCC-20 token, so the trade's value is unknown: pass --kas-equivalent <sompi> (its KAS value) or --i-accept-the-risk",
            ))
        }
        Some(v) => v,
    };
    if value > limit {
        return Err(CliError::new(
            "CLI_VALUE_CAP_EXCEEDED",
            format!(
                "the trade's value of {value} sompi (declared) is above the cap of {limit} sompi"
            ),
        ));
    }
    Ok((
        format!("value cap: {value} sompi (declared) within the cap of {limit} sompi"),
        Some(limit),
    ))
}

/// The value cap on recovery (claim, refund of an already funded vault): new value does not
/// enter, so the cap never refuses; what it would have refused is noted as a warning.
fn recovery_cap_line(ctx: &Ctx, cap: &CapArgs, notes: &mut dyn Write) -> Result<String, CliError> {
    match cap_line(ctx, cap) {
        Ok((line, _)) => Ok(line),
        Err(e) => {
            writeln!(
                notes,
                "warning: the value cap is not applied to recovering a funded vault ({e})"
            )
            .map_err(write_err)?;
            Ok("value cap: not applied to recovery".into())
        }
    }
}

fn asset_template(
    terms: &ValidatedHtlcTerms,
    path: &Option<PathBuf>,
) -> Result<Kcc20Template, CliError> {
    let path = path.as_ref().ok_or_else(|| {
        CliError::new(
            "CLI_TEMPLATE_MISSING",
            "the asset leg is a KCC-20 token: pass --asset-template <silverc artifact>",
        )
    })?;
    let template = Kcc20Template::from_json(&read_text(path)?)?;
    if let LegKind::Kcc20(token) = terms.terms().asset_leg.kind {
        template.check_token(&token)?;
    }
    Ok(template)
}

fn key_owner(key: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: key,
    }
}

/// One of the user's own KCC-20 destinations (spec/CLI.md, "Terms summary and role check"): never
/// the counterparty's key; the pin if given, else a PUBKEY owner of `--my-key`.
fn own_owner(
    field: &str,
    owner: &Kcc20Owner,
    my_key: [u8; 32],
    other_key: [u8; 32],
    flag: &str,
    pin: &Option<String>,
    network: Network,
) -> Result<String, CliError> {
    if *owner == key_owner(other_key) {
        return Err(CliError::new(
            "CLI_DESTINATION_NOT_MINE",
            format!("{field} pays the counterparty's key"),
        ));
    }
    match pin {
        Some(text) => {
            let Destination::Kcc20(p) = parse_pin(flag, text, network)? else {
                return Err(CliError::new(
                    "CLI_DESTINATION_PIN_INVALID",
                    format!("{flag}: {field} is a KCC-20 owner; pin it as kcc20:<type>:<hex>"),
                ));
            };
            if p != *owner {
                return Err(CliError::new(
                    "CLI_DESTINATION_NOT_MINE",
                    format!("{field} {} is not your pin {flag}", doc::owner_text(owner)),
                ));
            }
            Ok(format!("{field}: equals its pin {flag}"))
        }
        None if *owner == key_owner(my_key) => Ok(format!("{field}: pays --my-key")),
        None => Err(CliError::new(
            "CLI_DESTINATION_NOT_MINE",
            format!(
                "{field} {} does not pay --my-key; pin it with {flag} if it is yours",
                doc::owner_text(owner)
            ),
        )),
    }
}

fn counterpart_account(
    field: &str,
    agreed: [u8; 32],
    flag_value: &str,
) -> Result<String, CliError> {
    let mine = hash_arg("my-counterpart-account", flag_value)?;
    if mine != agreed {
        return Err(CliError::new(
            "CLI_DESTINATION_NOT_MINE",
            format!(
                "the counterpart record's {field} {} is not --my-counterpart-account",
                hex(&agreed)
            ),
        ));
    }
    Ok(format!("counterpart {field}: --my-counterpart-account"))
}

/// The hashlock terms summary, shown before anything else a command prints.
fn summary(terms: &ValidatedHtlcTerms, now_daa: Option<u64>) -> Vec<String> {
    let t = terms.terms();
    let c = &t.counterpart;
    let mut lines = vec![
        format!(
            "hashlock terms: {} ({})",
            hex(&terms.terms_hash()),
            doc::network_name(t.network)
        ),
        "exchange: conditional exchange across two chains with residual risk, not atomic settlement (spec/V2.md sections 4.8 and 10.6)".into(),
        format!("trade_ref: {}", hex(&t.trade_ref)),
        format!("seller_key: {}", hex(&t.seller_key)),
        format!("buyer_key: {}", hex(&t.buyer_key)),
    ];
    if let LegKind::Kcc20(token) = t.asset_leg.kind {
        lines.push(format!(
            "asset: KCC-20 covenant {}, template {} ({}+{}), {} units",
            hex(&token.covenant_id),
            hex(&token.template_hash),
            token.template_prefix_len,
            token.template_suffix_len,
            t.asset_leg.amount
        ));
    }
    lines.push(format!(
        "buyer_delivery: {}",
        doc::owner_text(&t.buyer_delivery)
    ));
    lines.push(format!(
        "seller_refund: {}",
        doc::owner_text(&t.seller_refund)
    ));
    lines.push(format!("hash_lock: {}", hex(&t.hash_lock)));
    lines.push(match now_daa {
        Some(now) if t.expiry_daa > now => format!(
            "expiry_daa: {} (about {} from DAA score {now} at the nominal 10 per second)",
            t.expiry_daa,
            approx_duration(t.expiry_daa - now)
        ),
        Some(now) => format!("expiry_daa: {} (passed at DAA score {now})", t.expiry_daa),
        None => format!("expiry_daa: {}", t.expiry_daa),
    });
    lines.push(format!(
        "counterpart: chain {} {}, program {}, asset {}, {} base units, recipient {}, refund {}, timeout {} (unix seconds)",
        doc::chain_name(c.chain),
        hex(&c.chain_id),
        hex(&c.htlc_program),
        hex(&c.asset),
        c.amount,
        hex(&c.recipient),
        hex(&c.refund),
        c.timeout
    ));
    lines
}

fn rate_text(r: DaaRate) -> String {
    format!("{} DAA per {} s", r.daa, r.secs)
}

fn margin_lines(
    e: &MarginEstimate,
    latest_reveal: u64,
    final_secs: u64,
    sampled: bool,
) -> Vec<String> {
    vec![
        format!(
            "DAA_RATE_MAX: {} ({})",
            rate_text(e.daa_rate_max),
            if sampled {
                "1.5 times the busiest 10 minutes of the sample, never below the target rate"
            } else {
                "no sample: 2 times the target rate, testnet only"
            }
        ),
        format!(
            "expiry estimate: unix {} (early on purpose; an estimate, not a guarantee)",
            e.expiry_estimate_unix
        ),
        format!(
            "margin: delta {} s; counterpart timeout plus delta is unix {}",
            e.delta_secs, e.required_unix
        ),
        format!(
            "latest reveal: unix {latest_reveal} (counterpart timeout less the claim lead of {} s)",
            delta_claim(final_secs)
        ),
    ]
}

// =============================================================================================
// Transactions: lines, fee inputs, the document
// =============================================================================================

fn kind_name(kind: HtlcIpstKind) -> String {
    match kind {
        HtlcIpstKind::Fund => "hashlock fund".into(),
        HtlcIpstKind::Claim => "hashlock claim".into(),
        HtlcIpstKind::Refund { signer, with_token } => format!(
            "hashlock refund by {}, {}",
            match signer {
                HtlcRefundSigner::Seller => "seller",
                HtlcRefundSigner::Buyer => "buyer",
            },
            if with_token {
                "with the token"
            } else {
                "without the token"
            }
        ),
    }
}

/// Inputs before the fee inputs, in the layouts of spec/V2.md section 10.4.
fn trade_inputs(kind: HtlcIpstKind, ipst: &HtlcIpst) -> usize {
    match kind {
        HtlcIpstKind::Fund => ipst
            .entries()
            .iter()
            .take_while(|e| e.covenant_id.is_some())
            .count(),
        HtlcIpstKind::Claim => 2,
        HtlcIpstKind::Refund { with_token, .. } => 1 + usize::from(with_token),
    }
}

fn address_of(network: Network, spk: &ScriptPublicKey) -> String {
    script_address(spk, network).map_or_else(
        || format!("script {} (version {})", hex(spk.script()), spk.version()),
        |a| a.to_string(),
    )
}

/// What the fee inputs put into trade outputs, beyond the fee and the change.
fn payer_cost(m: &HtlcTermsMatch, ipst: &HtlcIpst) -> u64 {
    let from = trade_inputs(m.kind, ipst);
    let paid: u64 = ipst.entries()[from..].iter().map(|e| e.amount).sum();
    paid.saturating_sub(m.fee)
        .saturating_sub(m.change.as_ref().map_or(0, |c| c.value))
}

fn tx_lines(ipst: &HtlcIpst, m: &HtlcTermsMatch) -> Vec<String> {
    let network = ipst.terms().terms().network;
    let tx = ipst.transaction();
    let mut lines = vec![
        format!("ipst: {}", kind_name(m.kind)),
        format!("txid: {}", hex(&tx.id().as_bytes())),
        if tx.lock_time == 0 {
            "lock_time: 0".into()
        } else {
            format!(
                "lock_time: {} (a block can include it from DAA score {})",
                tx.lock_time,
                tx.lock_time.saturating_add(1)
            )
        },
    ];
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
    for (i, o) in tx.outputs.iter().enumerate() {
        let covenant = o.covenant.map_or(String::new(), |c| {
            format!(
                ", covenant {} from input {}",
                hex(&c.covenant_id.as_bytes()),
                c.authorizing_input
            )
        });
        lines.push(format!(
            "output {i}: {} sompi to {}{covenant}",
            o.value,
            address_of(network, &o.script_public_key)
        ));
    }
    let masses = ipst.masses();
    lines.push(format!(
        "fee: {} sompi (minimum relay fee {} sompi)",
        m.fee,
        min_relay_fee(masses.fee_mass)
    ));
    lines.push(format!(
        "payer cost beyond the fee: {} sompi into trade outputs",
        payer_cost(m, ipst)
    ));
    lines.push(match &m.change {
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

/// Builds with the first one, two, ... fee candidates until the builder accepts, with the
/// minimum relay fee unless `fee` is given (spec/CLI.md, "Common arguments of the builders").
fn build_with_fee(
    candidates: &[Utxo],
    fee: Option<u64>,
    change: &ScriptPublicKey,
    build: impl Fn(&FeePayment) -> Result<HtlcIpst, HtlcError>,
) -> Result<HtlcIpst, CliError> {
    let mut last = None;
    for k in 1..=candidates.len() {
        let mut payment = FeePayment {
            inputs: candidates[..k].to_vec(),
            fee: fee.unwrap_or_else(|| min_relay_fee(0)),
            change: change.clone(),
        };
        let mut result = build(&payment);
        if fee.is_none() {
            if let Err(HtlcError::Tx(TxError::FeeTooLow { minimum, .. })) = result {
                payment.fee = minimum;
                result = build(&payment);
            }
        }
        match result {
            Ok(ipst) => return Ok(ipst),
            Err(
                e @ HtlcError::Tx(TxError::InsufficientFunds { .. } | TxError::BelowMinKas { .. }),
            ) => last = Some(e),
            Err(e) => return Err(htlc_err(e)),
        }
    }
    Err(last.map_or_else(
        || CliError::new("CLI_UTXO_NOT_FOUND", "no fee input"),
        htlc_err,
    ))
}

struct Pay {
    from: kaspa_addresses::Address,
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

/// Writes the document after the terms check of what was built, and prints.
fn finish(
    out: &mut dyn Write,
    mut lines: Vec<String>,
    ipst: &HtlcIpst,
    template: &Kcc20Template,
    daa: u64,
    path: &Path,
) -> Result<(), CliError> {
    let m = ipst.verify_against_terms(template, daa).map_err(htlc_err)?;
    write_new(path, &doc::ipst_json(ipst))?;
    lines.extend(tx_lines(ipst, &m));
    lines.push(format!("wrote: {}", path.display()));
    print(out, &lines)
}

fn not_found(what: String) -> CliError {
    CliError::new("CLI_UTXO_NOT_FOUND", what)
}

fn vault_escrow(
    node: &dyn Node,
    terms: &ValidatedHtlcTerms,
    vault: &HtlcVault,
    template: &Kcc20Template,
) -> Result<Utxo, CliError> {
    let t = terms.terms();
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(not_found("the asset leg is not KCC-20".into()));
    };
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        t.asset_leg.amount,
    );
    utxos_with(
        node,
        &template.script_public_key(&state)?,
        Some(token.covenant_id),
        t.network,
    )?
    .into_iter()
    .next()
    .ok_or_else(|| {
        not_found(format!(
            "no escrowed token of {} units owned by the vault: is it funded?",
            t.asset_leg.amount
        ))
    })
}

/// A transaction the node accepted on its selected chain, with the UTXO entries it spent, and its
/// depth in DAA below the virtual DAA score.
struct Seen {
    block: [u8; 32],
    accepted: node::AcceptedTx,
    depth: u64,
}

fn seen(node: &dyn Node, txid: [u8; 32], from: [u8; 32]) -> Result<Seen, CliError> {
    let (block, accepted) = node::find_accepted_tx(node, txid, from)?;
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
    Ok(Seen {
        block,
        accepted,
        depth,
    })
}

/// What a transaction is to this trade (spec/V2.md section 10.9, `xchain status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TradeTx {
    /// It funds the vault (`htlc::verify_funding` passed); whether the escrow is still unspent.
    Funding { escrow_unspent: bool },
    /// It spends the vault with output 0 delivering the asset to buyer_delivery:
    /// `settleWithPreimage`, the only entry that pays buyer_delivery.
    Claim,
    /// It spends the vault otherwise: a refund.
    Refund,
}

/// Binds a transaction the node accepted to this trade, or refuses it. A spend of the vault: an
/// input spent a UTXO at this trade's vault address, the P2SH of this trade's vault script, so the
/// node ran that script; a claim when output 0 is the asset, exactly the amount, owned by
/// buyer_delivery, under the asset's covenant. Else, a transaction paying the vault's address or
/// the escrow's must be its funding (`htlc::verify_funding`, `HTLC_FUNDING`). Anything else is
/// not part of this trade (`XCHAIN_TX_UNRELATED`).
fn trade_tx(
    node: &dyn Node,
    terms: &ValidatedHtlcTerms,
    template: &Kcc20Template,
    a: &node::AcceptedTx,
) -> Result<TradeTx, CliError> {
    let t = terms.terms();
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(htlc_err(HtlcError::AssetKind));
    };
    let vault = HtlcVault::instantiate_existing(terms).map_err(htlc_err)?;
    let vault_spk = vault.script_public_key();
    let spends_vault = a.spent.iter().any(|e| e.script_public_key == vault_spk);
    let covenant = Some(kaspa_consensus_core::Hash::from_bytes(token.covenant_id));
    if spends_vault {
        let delivery =
            template.script_public_key(&Kcc20State::new(t.buyer_delivery, t.asset_leg.amount))?;
        let delivered = a.tx.outputs.first().is_some_and(|o| {
            o.script_public_key == delivery && o.covenant.map(|c| c.covenant_id) == covenant
        });
        return Ok(if delivered {
            TradeTx::Claim
        } else {
            TradeTx::Refund
        });
    }
    let escrow_spk = escrow_spk(terms, template, &vault)?;
    if !a
        .tx
        .outputs
        .iter()
        .any(|o| o.script_public_key == vault_spk || o.script_public_key == escrow_spk)
    {
        return Err(CliError::new(
            "XCHAIN_TX_UNRELATED",
            format!(
                "transaction {} is not part of this trade: it neither spends the vault nor pays the vault's address or its escrow",
                hex(&a.tx.id().as_bytes())
            ),
        ));
    }
    let f = htlc::verify_funding(terms, template, &a.tx).map_err(htlc_err)?;
    let escrow_unspent = match funding_unspent(node, terms, template, &f) {
        Ok(()) => true,
        Err(e) if e.code() == "CLI_UTXO_NOT_FOUND" => false,
        Err(e) => return Err(e),
    };
    Ok(TradeTx::Funding { escrow_unspent })
}

/// The escrow's scriptPublicKey: the asset's template holding exactly the amount, owned by the
/// vault's script hash, not a minter.
fn escrow_spk(
    terms: &ValidatedHtlcTerms,
    template: &Kcc20Template,
    vault: &HtlcVault,
) -> Result<ScriptPublicKey, CliError> {
    Ok(template.script_public_key(&Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        terms.terms().asset_leg.amount,
    ))?)
}

/// The node still holds the funding's escrow and authorizer unspent, as the funding created
/// them (`CLI_UTXO_NOT_FOUND` if not).
fn funding_unspent(
    node: &dyn Node,
    terms: &ValidatedHtlcTerms,
    template: &Kcc20Template,
    f: &htlc::HtlcFunding,
) -> Result<(), CliError> {
    let t = terms.terms();
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(htlc_err(HtlcError::AssetKind));
    };
    let vault = HtlcVault::instantiate_existing(terms).map_err(htlc_err)?;
    let spent = |e: CliError| {
        if e.code() == "CLI_UTXO_NOT_FOUND" {
            CliError::new(
                e.code(),
                format!("{}: the funding is spent (claimed or refunded)", e.detail()),
            )
        } else {
            e
        }
    };
    let escrow = escrow_spk(terms, template, &vault)?;
    utxo_at(
        node,
        &f.escrow,
        &escrow,
        Some(token.covenant_id),
        t.network,
        "the escrow",
    )
    .map_err(spent)?;
    utxo_at(
        node,
        &f.authorizer,
        &vault.script_public_key(),
        None,
        t.network,
        "the authorizer",
    )
    .map_err(spent)?;
    Ok(())
}

// =============================================================================================
// The counterpart chain
// =============================================================================================

fn check_chain(source: &dyn CounterpartSource, terms: &ValidatedHtlcTerms) -> Result<(), CliError> {
    let c = &terms.terms().counterpart;
    let (chain, id) = source.chain()?;
    if chain != c.chain || id != c.chain_id {
        return Err(CliError::new(
            "XCHAIN_COUNTERPART_MISMATCH",
            format!(
                "the source serves chain {} {}; the record names {} {}",
                doc::chain_name(chain),
                hex(&id),
                doc::chain_name(c.chain),
                hex(&c.chain_id)
            ),
        ));
    }
    Ok(())
}

/// The agreed lock on the counterpart chain, at any finality: the chain, then a lock equal to the
/// record in every field and funded (`XCHAIN_COUNTERPART_MISMATCH`, naming the first field that
/// differs).
fn agreed_lock(
    source: &dyn CounterpartSource,
    terms: &ValidatedHtlcTerms,
) -> Result<Lock, CliError> {
    check_chain(source, terms)?;
    let t = terms.terms();
    let locks = source.locks(&t.hash_lock)?;
    if let Some(l) = locks
        .iter()
        .find(|l| counterpart::mismatch(l, &t.counterpart, &t.hash_lock).is_none())
    {
        return Ok(l.clone());
    }
    Err(CliError::new(
        "XCHAIN_COUNTERPART_MISMATCH",
        match locks.first() {
            None => "no counterpart lock with this hash lock".to_string(),
            Some(l) => format!(
                "the counterpart lock {} differs from the record in {}",
                l.label(),
                counterpart::mismatch(l, &t.counterpart, &t.hash_lock).unwrap_or("a field")
            ),
        },
    ))
}

/// The claim of the agreed lock whose preimage passes the claim's check, most final first.
fn reveal(
    source: &dyn CounterpartSource,
    terms: &ValidatedHtlcTerms,
    lock: &Lock,
) -> Result<Option<Claim>, CliError> {
    let mut good: Vec<Claim> = source
        .claims(&lock.id)?
        .into_iter()
        .filter(|c| check_preimage(terms, &c.preimage).is_ok())
        .collect();
    good.sort_by_key(|c| std::cmp::Reverse(c.finality));
    Ok(good.into_iter().next())
}

fn counterpart_final(lock: &Lock) -> Result<(), CliError> {
    if lock.finality != Finality::Finalized {
        return Err(CliError::new(
            "XCHAIN_NOT_FINAL",
            format!(
                "the counterpart lock {} is {}, not counterpart-final: wait and run again",
                lock.label(),
                lock.finality.name()
            ),
        ));
    }
    Ok(())
}

// =============================================================================================
// Commands
// =============================================================================================

fn new(ctx: &Ctx, a: NewArgs, out: &mut dyn Write, notes: &mut dyn Write) -> Result<(), CliError> {
    let mut draft = doc::parse_draft(&read_text(&a.draft)?)?;
    let my_key = hash_arg("my-key", &a.my_key)?;
    if draft.seller_key != my_key {
        return Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            "--my-key is not the terms' seller_key: xchain new is the seller's (the seller holds the secret)",
        ));
    }
    let mut role = vec![own_owner(
        "seller_refund",
        &draft.seller_refund,
        my_key,
        draft.buyer_key,
        "--my-refund",
        &a.my_refund,
        ctx.network,
    )?];
    role.push(counterpart_account(
        "recipient",
        draft.counterpart.recipient,
        &a.my_counterpart_account,
    )?);
    // A fresh secret per trade, from the operating system's random source (D32, D50).
    let secret = htlc::HashlockSecret::generate();
    draft.hash_lock = secret.hash_lock();
    let terms = draft.validate_structure().map_err(htlc_err)?;
    let t = terms.terms();
    doc::check_known(&a.known_hashes, &t.hash_lock, &terms.terms_hash())?;
    let daa = creation_daa(ctx, &a.creation)?;
    let sample = read_sample(ctx, &a.margin.daa_sample)?;
    let now = now_unix();
    let (vault, estimate) = creation_checks(&terms, daa, &a.margin, sample.as_ref(), now)?;
    let latest = check_reveal_window(&terms, now, a.margin.counterpart_final_secs)?;
    check_pinned_template(&terms)?;
    let (cap, _) = cap_line(ctx, &a.cap)?;
    for p in [&a.secret_out, &a.out] {
        if p.exists() || p.is_symlink() {
            return Err(CliError::new(
                "CLI_OUTPUT_EXISTS",
                format!("{} exists", p.display()),
            ));
        }
    }
    let mut lines = summary(&terms, Some(daa));
    lines.extend(margin_lines(
        &estimate,
        latest,
        a.margin.counterpart_final_secs,
        sample.is_some(),
    ));
    lines.extend(role.into_iter().map(|r| format!("role check: seller, {r}")));
    lines.push(cap);
    lines.push(format!(
        "vault: {} (the seller funds it with xchain fund build)",
        vault.address()
    ));
    doc::record_known(&a.known_hashes, &t.hash_lock, &terms.terms_hash())?;
    doc::write_secret(&a.secret_out, secret.expose())?;
    drop(secret);
    if let Err(e) = write_new(&a.out, &doc::render_terms_file(&terms)) {
        let _ = std::fs::remove_file(&a.secret_out);
        return Err(e);
    }
    lines.push(format!(
        "secret: written to {} (mode 0600); not shown",
        a.secret_out.display()
    ));
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)?;
    writeln!(
        notes,
        "note: the vault is earmarked: until expiry_daa only the buyer can send the asset home, so the buyer holds a free option (spec/V2.md section 10.6, R12); keep expiry_daa as short as the margin allows"
    )
    .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("stderr: {e}")))
}

fn verify(ctx: &Ctx, a: VerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let t = terms.terms();
    let my_key = hash_arg("my-key", &a.my_key)?;
    if t.buyer_key != my_key {
        return Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            "--my-key is not the terms' buyer_key",
        ));
    }
    let role = [
        own_owner(
            "buyer_delivery",
            &t.buyer_delivery,
            my_key,
            t.seller_key,
            "--my-delivery",
            &a.my_delivery,
            ctx.network,
        )?,
        counterpart_account("refund", t.counterpart.refund, &a.my_counterpart_account)?,
    ];
    doc::check_known(&a.known_hashes, &t.hash_lock, &terms.terms_hash())?;
    let daa = creation_daa(ctx, &a.creation)?;
    let sample = read_sample(ctx, &a.margin.daa_sample)?;
    let now = now_unix();
    let (vault, estimate) = creation_checks(&terms, daa, &a.margin, sample.as_ref(), now)?;
    let latest = check_reveal_window(&terms, now, a.margin.counterpart_final_secs)?;
    check_pinned_template(&terms)?;
    let (cap, _) = cap_line(ctx, &a.cap)?;
    if !doc::check_known(&a.known_hashes, &t.hash_lock, &terms.terms_hash())? {
        doc::record_known(&a.known_hashes, &t.hash_lock, &terms.terms_hash())?;
    }
    let mut lines = summary(&terms, Some(daa));
    lines.extend(margin_lines(
        &estimate,
        latest,
        a.margin.counterpart_final_secs,
        sample.is_some(),
    ));
    lines.extend(role.into_iter().map(|r| format!("role check: buyer, {r}")));
    lines.push(cap);
    lines.push(format!(
        "vault: {} (funded by the seller; you send nothing to it)",
        vault.address()
    ));
    lines.push(
        "funding: not checked here; xchain verify-funding --txid <funding txid> checks it".into(),
    );
    lines.push(format!(
        "ok: buyer; lock the counterpart amount only once xchain verify-funding passes, and only before unix {latest}",
    ));
    print(out, &lines)
}

fn fund_build(ctx: &Ctx, a: FundBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let t = terms.terms();
    let my_key = hash_arg("my-key", &a.my_key)?;
    if t.seller_key != my_key {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            "the hashlock vault is funded by the seller; --my-key is not seller_key",
        ));
    }
    let (node, daa) = node_now(ctx, &a.node)?;
    let sample = read_sample(ctx, &a.margin.daa_sample)?;
    let now = now_unix();
    let (vault, _) = creation_checks(&terms, daa, &a.margin, sample.as_ref(), now)?;
    check_pinned_template(&terms)?;
    let (cap, _) = cap_line(ctx, &a.cap)?;
    let pay = pay(&a.pay, ctx.network)?;
    let mine = p2pk_address(&my_key, ctx.network);
    if pay.from != mine {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "--pay-from {} is not the P2PK address of --my-key ({mine}): the seller signs its funding alone",
                pay.from
            ),
        ));
    }
    let template = asset_template(&terms, &a.asset_template)?;
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(not_found("the asset leg is not KCC-20".into()));
    };
    if a.token.is_empty() {
        return Err(not_found(format!(
            "the vault is funded with your token UTXOs: pass --token <txid>:<index>:<amount> (held by {})",
            hex(&my_key)
        )));
    }
    let mut tokens = Vec::with_capacity(a.token.len());
    for text in &a.token {
        let (outpoint, amount) = parse_token("--token", text)?;
        let state = Kcc20State::new(key_owner(my_key), amount);
        let utxo = utxo_at(
            node.as_ref(),
            &outpoint,
            &template.script_public_key(&state)?,
            Some(token.covenant_id),
            ctx.network,
            "--token",
        )?;
        tokens.push(TokenUtxo { utxo, state });
    }
    let deposit = Kcc20Deposit {
        tokens,
        carrier: a.carrier.unwrap_or(MIN_KCC20_OUTPUT),
        authorizer: a.authorizer.unwrap_or(MIN_KAS_OUTPUT),
    };
    let exclude: Vec<TransactionOutpoint> =
        deposit.tokens.iter().map(|t| t.utxo.outpoint).collect();
    let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &exclude)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        htlc::fund(&terms, &vault, &template, &deposit, p, daa)
    })?;
    let mut lines = summary(&terms, Some(daa));
    lines.push(cap);
    lines.push(format!("vault: {}", vault.address()));
    finish(out, lines, &ipst, &template, daa, &a.out)
}

fn verify_counterpart(
    ctx: &Ctx,
    a: VerifyCounterpartArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let source = counterpart::open(&a.counterpart)?;
    let lock = agreed_lock(source.as_ref(), &terms)?;
    counterpart_final(&lock)?;
    // A frozen escrow is refused; a freeze authority is a warning, printed before any reveal.
    let warnings = source.claim_check(&lock)?;
    let latest = terms
        .terms()
        .counterpart
        .timeout
        .saturating_sub(delta_claim(a.counterpart_final_secs));
    let mut lines = summary(&terms, None);
    lines.push(format!(
        "counterpart lock: {} matches the record, funded, counterpart-final",
        lock.label()
    ));
    lines.extend(warnings);
    lines.push(format!(
        "ok: you may reveal by claiming it until unix {latest} on the counterpart chain's clock (now {})",
        source.now_unix()?
    ));
    print(out, &lines)
}

fn counterpart_claim(
    ctx: &Ctx,
    a: CounterpartClaimArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let secret = doc::read_secret(&a.secret_file)?;
    check_preimage(&terms, &secret).map_err(htlc_err)?;
    let source = counterpart::open(&a.counterpart)?;
    // R13: the buyer's lock is checked before anything is revealed.
    let lock = agreed_lock(source.as_ref(), &terms)?;
    counterpart_final(&lock)?;
    source.claim_check(&lock)?;
    let mine = source
        .claims(&lock.id)?
        .into_iter()
        .filter(|c| c.preimage.as_slice() == secret.as_slice())
        .max_by_key(|c| c.finality);
    match mine {
        Some(c) if c.finality == Finality::Finalized => {
            let mut lines = summary(&terms, None);
            lines.push(format!(
                "counterpart claim: {} counterpart-final; the trade completes when the Kaspa claim is final (xchain status)",
                c.label()
            ));
            return print(out, &lines);
        }
        Some(c) => {
            // A read-only source cannot resubmit: the claim is already on its chain.
            match source.submit_claim(&lock.id, &secret) {
                Err(e) if e.code() != "XCHAIN_CHAIN_UNSUPPORTED" => return Err(e),
                _ => {}
            }
            return Err(CliError::new(
                "XCHAIN_NOT_FINAL",
                format!(
                    "the counterpart claim {} is {}, not counterpart-final; submitted again: run again until it is",
                    c.label(),
                    c.finality.name()
                ),
            ));
        }
        None => {}
    }
    // R2: the first reveal only while at least the claim lead remains before the timeout.
    let now = source.now_unix()?;
    let timeout = terms.terms().counterpart.timeout;
    let dc = delta_claim(a.counterpart_final_secs);
    if now.saturating_add(dc) > timeout {
        return Err(CliError::new(
            "XCHAIN_MARGIN_TOO_SHORT",
            format!(
                "now ({now}) is less than the claim lead of {dc} s before the counterpart timeout {timeout}: do not reveal; the buyer refunds after the timeout and you refund the asset after expiry_daa"
            ),
        ));
    }
    source.submit_claim(&lock.id, &secret)?;
    Err(CliError::new(
        "XCHAIN_NOT_FINAL",
        "the counterpart claim is submitted, not yet counterpart-final: run again until it is",
    ))
}

fn watch(ctx: &Ctx, a: WatchArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    if a.secret_out.exists() || a.secret_out.is_symlink() {
        return Err(CliError::new(
            "CLI_OUTPUT_EXISTS",
            format!("{} exists", a.secret_out.display()),
        ));
    }
    let source = counterpart::open(&a.counterpart)?;
    let polls = a.polls.max(1);
    let mut seen: Option<Claim> = None;
    for p in 0..polls {
        if p > 0 {
            std::thread::sleep(std::time::Duration::from_secs(a.interval_secs));
        }
        let lock = agreed_lock(source.as_ref(), &terms)?;
        seen = reveal(source.as_ref(), &terms, &lock)?;
        if seen
            .as_ref()
            .is_some_and(|c| c.finality == Finality::Finalized)
        {
            break;
        }
    }
    let claim = seen.ok_or_else(|| {
        CliError::new(
            "XCHAIN_REVEAL_NOT_FOUND",
            "no claim of the counterpart lock reveals the preimage yet",
        )
    })?;
    if claim.finality != Finality::Finalized {
        return Err(CliError::new(
            "XCHAIN_NOT_FINAL",
            format!(
                "the claim {} reveals the preimage and is {}; xchain claim --counterpart can use it now, or watch again until counterpart-final",
                claim.label(),
                claim.finality.name()
            ),
        ));
    }
    let preimage: [u8; 32] = claim.preimage.as_slice().try_into().map_err(|_| {
        htlc_err(HtlcError::SecretLength {
            len: claim.preimage.len(),
        })
    })?;
    doc::write_secret(&a.secret_out, &preimage)?;
    let mut lines = summary(&terms, None);
    lines.push(format!("reveal: claim {} counterpart-final", claim.label()));
    lines.push(format!(
        "preimage: written to {} (mode 0600); not shown",
        a.secret_out.display()
    ));
    print(out, &lines)
}

fn claim(
    ctx: &Ctx,
    a: ClaimArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let t = terms.terms();
    let (preimage, from): (zeroize::Zeroizing<Vec<u8>>, String) =
        match (&a.preimage.secret_file, &a.preimage.counterpart) {
            (Some(path), _) => (
                doc::read_secret(path)?,
                format!("secret file {}", path.display()),
            ),
            (None, Some(url)) => {
                let source = counterpart::open(url)?;
                let lock = agreed_lock(source.as_ref(), &terms)?;
                let c = reveal(source.as_ref(), &terms, &lock)?.ok_or_else(|| {
                    CliError::new(
                        "XCHAIN_REVEAL_NOT_FOUND",
                        "no claim of the counterpart lock reveals the preimage yet",
                    )
                })?;
                let from = format!("counterpart claim {} ({})", c.label(), c.finality.name());
                (zeroize::Zeroizing::new(c.preimage), from)
            }
            (None, None) => {
                return Err(CliError::new(
                    "XCHAIN_REVEAL_NOT_FOUND",
                    "no preimage source: pass --secret-file or --counterpart",
                ))
            }
        };
    check_preimage(&terms, &preimage).map_err(htlc_err)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    // The time left is advice only and never blocks a claim (race R4): a missing, unreadable or
    // out-of-date sample falls back to the pinned worst case, with a warning.
    let now = now_unix();
    let rate = match read_sample(ctx, &a.daa_sample)
        .and_then(|sample| daa_rate_max(t.network, sample.as_ref(), now).map_err(htlc_err))
    {
        Ok(rate) => rate,
        Err(e) => {
            writeln!(
                notes,
                "warning: the DAA rate sample is not usable ({e}); the time left is estimated at the pinned worst case of twice the target rate, as advice only"
            )
            .map_err(write_err)?;
            pinned_daa_rate(t.network)
        }
    };
    let left = u128::from(t.expiry_daa.saturating_sub(daa)) * rate.secs / rate.daa;
    let mut warning = None;
    if left < u128::from(a.retry_secs) {
        if !a.past_margin {
            return Err(CliError::new(
                "XCHAIN_MARGIN_TOO_SHORT",
                format!(
                    "about {left} s may remain before expiry_daa {} (at DAA_RATE_MAX, from DAA score {daa}), less than the retry window of {} s; --past-margin builds it anyway",
                    t.expiry_daa, a.retry_secs
                ),
            ));
        }
        warning = Some(
            "warning: less than the retry window remains before expiry_daa; after it the seller may refund, and the first accepted spend wins (spec/V2.md section 10.6, R4)"
                .to_string(),
        );
    }
    let cap = recovery_cap_line(ctx, &a.cap, notes)?;
    let template = asset_template(&terms, &a.asset_template)?;
    let vault = HtlcVault::instantiate_existing(&terms).map_err(htlc_err)?;
    let mut at_vault = utxos_with(node.as_ref(), &vault.script_public_key(), None, ctx.network)?;
    at_vault.sort_by(|x, y| y.entry.amount.cmp(&x.entry.amount));
    let authorizer = at_vault
        .into_iter()
        .next()
        .ok_or_else(|| not_found("no authorizer at the vault: is it funded?".into()))?;
    let escrow = vault_escrow(node.as_ref(), &terms, &vault, &template)?;
    let pay = pay(&a.pay, ctx.network)?;
    let candidates = fee_candidates(
        node.as_ref(),
        &pay.from,
        ctx.network,
        &[authorizer.outpoint, escrow.outpoint],
    )?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        htlc::claim(&terms, &authorizer, &escrow, &template, &preimage, p)
    })?;
    let mut lines = summary(&terms, Some(daa));
    lines.push(format!("preimage: from the {from}; not shown"));
    lines.extend(warning);
    lines.push(cap);
    finish(out, lines, &ipst, &template, daa, &a.out)
}

fn refund(
    ctx: &Ctx,
    a: RefundArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    let terms = terms_on(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let cap = recovery_cap_line(ctx, &a.cap, notes)?;
    let vault = HtlcVault::instantiate_existing(&terms).map_err(htlc_err)?;
    let at_vault = utxos_with(node.as_ref(), &vault.script_public_key(), None, ctx.network)?;
    let vault_utxo = match &a.vault_utxo {
        Some(text) => {
            let o = parse_outpoint("--vault-utxo", text)?;
            at_vault
                .into_iter()
                .find(|u| u.outpoint == o)
                .ok_or_else(|| not_found(format!("--vault-utxo {text} is not at the vault")))?
        }
        None => match at_vault.len() {
            0 => return Err(not_found("no UTXO at the vault: is it funded?".into())),
            1 => at_vault.into_iter().next().expect("one"),
            _ => {
                return Err(CliError::new(
                    "CLI_UTXO_AMBIGUOUS",
                    format!(
                        "several UTXOs at the vault; name one with --vault-utxo: {}",
                        at_vault
                            .iter()
                            .map(|u| outpoint_text(&u.outpoint))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ))
            }
        },
    };
    let template = asset_template(&terms, &a.asset_template)?;
    let escrow = if a.without_token {
        None
    } else {
        Some(RefundEscrow {
            utxo: vault_escrow(node.as_ref(), &terms, &vault, &template)?,
            amount: terms.terms().asset_leg.amount,
            is_minter: false,
            template: &template,
        })
    };
    let signer = match a.signer {
        SignerArg::Seller => HtlcRefundSigner::Seller,
        SignerArg::Buyer => HtlcRefundSigner::Buyer,
    };
    let pay = pay(&a.pay, ctx.network)?;
    let mut exclude = vec![vault_utxo.outpoint];
    if let Some(e) = &escrow {
        exclude.push(e.utxo.outpoint);
    }
    let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &exclude)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        htlc::refund(&terms, signer, &vault_utxo, escrow.as_ref(), p)
    })?;
    let mut lines = summary(&terms, Some(daa));
    lines.push(cap);
    if a.without_token {
        lines.push(
            "token: stays owned by the vault; to get it back, fund a new authorizer at the vault's address and refund that one with the token".into(),
        );
    }
    finish(out, lines, &ipst, &template, daa, &a.out)
}

fn sign(ctx: &Ctx, a: SignArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let mut ipst = doc::read_ipst(&a.ipst)?;
    let n = ipst.terms().terms().network;
    if n != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!("the document is for {}", doc::network_name(n)),
        ));
    }
    let my_key = hash_arg("my-key", &a.my_key)?;
    let agreed = doc::read_terms_file(&a.terms)?;
    if agreed.terms_hash() != ipst.terms().terms_hash() {
        return Err(CliError::new(
            "CLI_IPST_TERMS_NOT_AGREED",
            "the document is for other terms than --terms",
        ));
    }
    let t = agreed.terms();
    let role_key = match a.role {
        SignRole::Seller => Some(t.seller_key),
        SignRole::Buyer => Some(t.buyer_key),
        SignRole::Payer => None,
    };
    match role_key {
        Some(k) if k != my_key => {
            return Err(CliError::new(
                "CLI_ROLE_KEY_MISMATCH",
                "--my-key is not the terms' key for --role",
            ))
        }
        None if my_key == t.seller_key || my_key == t.buyer_key => {
            return Err(CliError::new(
                "CLI_ROLE_KEY_MISMATCH",
                "a payer's key is neither party's key: sign as seller or buyer",
            ))
        }
        _ => {}
    }
    let daa = creation_daa(ctx, &a.creation)?;
    let template = asset_template(&agreed, &a.asset_template)?;
    let m = ipst
        .verify_against_terms(&template, daa)
        .map_err(htlc_err)?;
    let tx = ipst.transaction().clone();
    let mut takes = 0u64;
    if m.kind == HtlcIpstKind::Fund {
        if my_key != t.seller_key || a.role != SignRole::Seller {
            return Err(CliError::new(
                "CLI_FUND_NOT_YOUR_LEG",
                "the hashlock vault is funded by the seller, who signs its funding",
            ));
        }
        let Some(final_secs) = a.counterpart_final_secs else {
            return Err(CliError::new(
                "HTLC_TIMEOUT_MARGIN",
                "a funding is signed only after the margin rule passes again: pass --counterpart-final-secs",
            ));
        };
        let margin = MarginArgs {
            counterpart_final_secs: final_secs,
            retry_secs: a.retry_secs,
            daa_sample: a.daa_sample.clone(),
        };
        let sample = read_sample(ctx, &margin.daa_sample)?;
        creation_checks(&agreed, daa, &margin, sample.as_ref(), now_unix())?;
        check_pinned_template(&agreed)?;
        let (carrier, authorizer) = (
            a.carrier.unwrap_or(MIN_KCC20_OUTPUT),
            a.authorizer.unwrap_or(MIN_KAS_OUTPUT),
        );
        if tx.outputs[0].value != carrier || tx.outputs[1].value != authorizer {
            return Err(CliError::new(
                "CLI_IPST_DEPOSIT_MISMATCH",
                format!(
                    "the funding puts {} sompi on the token and {} on the authorizer; you expect {carrier} and {authorizer}",
                    tx.outputs[0].value, tx.outputs[1].value
                ),
            ));
        }
        takes = carrier + authorizer;
    }
    let (cap, limit) = cap_line(ctx, &a.cap)?;
    let mine: Vec<usize> = ipst
        .slots()
        .iter()
        .enumerate()
        .filter(|(_, s)| s.signer() == Some(my_key) && s.signature().is_none())
        .map(|(i, _)| i)
        .collect();
    if mine.is_empty() {
        return Err(CliError::new(
            "CLI_IPST_NOTHING_TO_SIGN",
            "no unsigned slot is for --my-key",
        ));
    }
    let first_fee = trade_inputs(m.kind, &ipst);
    let fee_inputs = mine.iter().filter(|&&i| i >= first_fee).count();
    let change_to = match &a.change {
        Some(c) => parse_change(c, ctx.network)?,
        None => address_script(&p2pk_address(&my_key, ctx.network)),
    };
    let min_fee = min_relay_fee(ipst.masses().fee_mass);
    let max_fee = match a.max_fee {
        Some(f) => f,
        None if fee_inputs > 3 => {
            return Err(CliError::new(
                "CLI_IPST_FEE_TOO_HIGH",
                "you sign more than three fee inputs: pass --max-fee",
            ))
        }
        None => min_fee.saturating_mul(2),
    };
    let change_mine = m
        .change
        .as_ref()
        .is_some_and(|c| c.script_public_key == change_to);
    if fee_inputs > 0 {
        if m.change.is_some() && !change_mine {
            return Err(CliError::new(
                "CLI_IPST_CHANGE_NOT_MINE",
                "the change does not pay --change or the P2PK address of --my-key",
            ));
        }
        if m.fee > max_fee {
            return Err(CliError::new(
                "CLI_IPST_FEE_TOO_HIGH",
                format!("the fee of {} sompi is above {max_fee}", m.fee),
            ));
        }
    }
    // What the signer commits: every input it signs except a refund's vault input, less what
    // comes back to it.
    let vault_input = matches!(m.kind, HtlcIpstKind::Refund { .. });
    let signed_in: u64 = mine
        .iter()
        .filter(|&&i| !(vault_input && i == 0))
        .map(|&i| ipst.entries()[i].amount)
        .sum();
    let mut back = if change_mine {
        m.change.as_ref().map_or(0, |c| c.value)
    } else {
        0
    };
    if m.kind == HtlcIpstKind::Fund && tx.outputs.len() > 2 {
        // Output 2 is the token change, back to the seller's key with its KAS, unless it is the
        // KAS change itself.
        let token_change = &tx.outputs[2];
        if Some(token_change) != m.change.as_ref() {
            back += token_change.value;
        }
    }
    let outflow = signed_in.saturating_sub(back);
    let allowed = takes.saturating_add(max_fee).saturating_add(a.max_topup);
    if outflow > allowed {
        return Err(CliError::new(
            "CLI_IPST_OUTFLOW_TOO_HIGH",
            format!("you commit {outflow} sompi; the trade takes {takes}, plus at most {max_fee} fee and {} top-up", a.max_topup),
        ));
    }
    if m.kind != HtlcIpstKind::Fund && payer_cost(&m, &ipst) > a.max_topup && fee_inputs > 0 {
        return Err(CliError::new(
            "CLI_IPST_TOPUP_TOO_HIGH",
            format!(
                "your fee inputs put {} sompi into trade outputs, above --max-topup {}",
                payer_cost(&m, &ipst),
                a.max_topup
            ),
        ));
    }
    if let Some(limit) = limit {
        if outflow > limit {
            return Err(CliError::new(
                "CLI_VALUE_CAP_EXCEEDED",
                format!("you commit {outflow} sompi, above the cap of {limit}"),
            ));
        }
    }
    for &i in &mine {
        let digest = ipst.slots()[i]
            .sighash()
            .expect("a slot with a signer has a sighash");
        let signed = signing::sign(&SignRequest {
            key_file: &a.key_file,
            network: n,
            mainnet_explicit: ctx.mainnet_explicit,
            expected_signer: Some(my_key),
            digest,
        })?;
        ipst.add_signature(i, &signed.signature).map_err(htlc_err)?;
    }
    write_new(&a.out, &doc::ipst_json(&ipst))?;
    let mut lines = summary(&agreed, Some(daa));
    lines.push(cap);
    lines.extend(tx_lines(&ipst, &m));
    lines.push(format!("you commit: {outflow} sompi (limit {allowed})"));
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

fn submit(ctx: &Ctx, a: SubmitArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let ipst = doc::read_ipst(&a.ipst)?;
    let n = ipst.terms().terms().network;
    if n != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!("the document is for {}", doc::network_name(n)),
        ));
    }
    let (node, daa) = node_now(ctx, &a.node)?;
    let template = asset_template(ipst.terms(), &a.asset_template)?;
    let m = ipst
        .verify_against_terms(&template, daa)
        .map_err(htlc_err)?;
    let tx = ipst.finalize().map_err(htlc_err)?;
    if let Err(e) = check_tx_is_finalized(&tx, daa, 0) {
        return Err(CliError::new(
            "CLI_TX_NOT_FINAL",
            format!(
                "lock time {}: the node accepts it once its virtual DAA score is above {} (now {daa}): {e}",
                tx.lock_time, tx.lock_time
            ),
        ));
    }
    let submitted = node::submit(node.as_ref(), &tx, ctx.network)?;
    let mut lines = tx_lines(&ipst, &m);
    lines.push(format!("from_block: {}", hex(&submitted.from_block)));
    lines.push(format!("submitted: {}", hex(&submitted.txid)));
    print(out, &lines)
}

/// The buyer's check before locking (spec/V2.md section 10.5, step 3): the transaction is
/// accepted, funds this trade's vault (`htlc::verify_funding`), its escrow and authorizer are
/// unspent, and it is at final depth.
fn verify_funding(ctx: &Ctx, a: VerifyFundingArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = terms_on(ctx, &a.terms)?;
    let template = asset_template(&terms, &a.asset_template)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let (node, _) = node_now(ctx, &a.node)?;
    let w = seen(node.as_ref(), txid, from)?;
    let f = htlc::verify_funding(&terms, &template, &w.accepted.tx).map_err(htlc_err)?;
    funding_unspent(node.as_ref(), &terms, &template, &f)?;
    if w.depth < FINALITY_DEPTH_DAA {
        return Err(CliError::new(
            "XCHAIN_NOT_FINAL",
            format!(
                "the funding is accepted at depth {} DAA, final at {FINALITY_DEPTH_DAA}: wait and run again; do not lock before",
                w.depth
            ),
        ));
    }
    let t = terms.terms();
    print(
        out,
        &[
            format!("hashlock terms: {}", hex(&terms.terms_hash())),
            format!("txid: {}", hex(&txid)),
            format!("accepting_block: {}", hex(&w.block)),
            format!(
                "escrow: {} ({} units, owned by the vault, unspent)",
                outpoint_text(&f.escrow),
                t.asset_leg.amount
            ),
            format!("authorizer: {} (unspent)", outpoint_text(&f.authorizer)),
            format!(
                "kaspa: final (depth {} DAA; final at {FINALITY_DEPTH_DAA}, the watcher's policy, not a guarantee of the network)",
                w.depth
            ),
            "ok: funding verified and final; lock the counterpart amount only before the latest time xchain verify printed".into(),
        ],
    )
}

fn status(ctx: &Ctx, a: StatusArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = terms_on(ctx, &a.terms)?;
    let template = asset_template(&terms, &a.asset_template)?;
    let txid = hash_arg("txid", &a.txid)?;
    let from = hash_arg("from-block", &a.from_block)?;
    let (node, _) = node_now(ctx, &a.node)?;
    let o = seen(node.as_ref(), txid, from)?;
    let role = trade_tx(node.as_ref(), &terms, &template, &o.accepted)?;
    let kaspa_final = o.depth >= FINALITY_DEPTH_DAA;
    let mut lines = vec![
        format!("hashlock terms: {}", hex(&terms.terms_hash())),
        format!("txid: {}", hex(&txid)),
        format!("accepting_block: {}", hex(&o.block)),
        format!(
            "transaction: {}",
            match role {
                TradeTx::Funding {
                    escrow_unspent: true,
                } => "funding (escrow unspent)",
                TradeTx::Funding {
                    escrow_unspent: false,
                } => "funding (escrow spent)",
                TradeTx::Claim => "claim (settleWithPreimage, delivery to buyer_delivery)",
                TradeTx::Refund => "refund",
            }
        ),
        format!(
            "kaspa: {} (depth {} DAA; final at {FINALITY_DEPTH_DAA}, the watcher's policy, not a guarantee of the network)",
            if kaspa_final { "final" } else { "accepted" },
            o.depth
        ),
    ];
    let mut counterpart_done = false;
    if let Some(url) = &a.counterpart {
        let source = counterpart::open(url)?;
        let lock = agreed_lock(source.as_ref(), &terms)?;
        let state = match reveal(source.as_ref(), &terms, &lock)? {
            Some(c) => {
                counterpart_done = c.finality == Finality::Finalized;
                format!("{} ({})", c.finality.name(), c.label())
            }
            None => "none".into(),
        };
        lines.push(format!("counterpart claim: {state}"));
    }
    lines.push(
        if role == TradeTx::Claim && kaspa_final && counterpart_done {
            "trade: complete (the Kaspa claim is final and the counterpart claim counterpart-final)"
        } else {
            "trade: not complete"
        }
        .into(),
    );
    print(out, &lines)
}

fn daa_sample(ctx: &Ctx, a: DaaSampleArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let (_, daa) = node_now(ctx, &a.node)?;
    let now = now_unix();
    doc::append_sample(&a.file, ctx.network, pinned_bps(ctx.network), now, daa)?;
    print(
        out,
        &[format!(
            "sample: {now} {daa} appended to {} ({}, read only)",
            a.file.display(),
            doc::network_name(ctx.network)
        )],
    )
}
