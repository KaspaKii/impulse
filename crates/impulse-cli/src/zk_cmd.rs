// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse zk ...` (spec/V3-ZK.md section 11): the list-gated settle. Issuer lists and their
//! path files, the list manifest, terms v3, the vault addresses, `verify`, and the unsigned
//! fund, settle and refund transactions, signed with the key file of the person who signs and
//! submitted to a node. Proving is `impulse-zk-prove` from `circuits/`; this command prints the
//! arguments it takes (`zk prove-args`) and reads the proof file it writes.
//!
//! Keyless like the rest of the CLI: only the signing module reads a key file, and the issuer's
//! key never comes near it. A list and its salts never leave the issuer's machine except in each
//! member's own path file, and are never printed. User text follows spec/V3-ZK.md section 9.5.

use crate::build_cmd::{node_now, LegArg, PayArgs, SignerArg, TemplateArgs, Templates};
use crate::cli::{creation, party, print, CapArgs, CreationArgs, Ctx, PartyArgs};
use crate::error::CliError;
use crate::funds::{
    address_script, fee_candidates, p2pk_address, parse_change, parse_outpoint, parse_pay_from,
    parse_token, utxo_at, utxos_with,
};
use crate::json::{hex, parse_strict, unhex, unhex32, Json, Obj};
use crate::node::{self, Node};
use crate::summary;
use crate::terms_file::{
    network_name, parse_draft, parse_terms_json, read_text, terms_json, write_new,
};
use crate::trade::{check_kas_minimum, check_pinned, leg_name};
use crate::txview;
use crate::value_cap::CapPolicy;
use crate::zkh_cmd::is_hashed_file;
use clap::{Args, Subcommand, ValueEnum};
use impulse_core::template::LegIndex;
use impulse_core::terms::{
    CreationContext, IdentifierType, Kcc20Owner, Kcc20Token, LegKind, Network,
};
use impulse_core::tx::{
    min_relay_fee, FeePayment, IpstKind, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow,
    RefundSigner, SettleCash, SettleLegs, TokenUtxo, TxError, Utxo, MIN_KAS_OUTPUT,
    MIN_KCC20_OUTPUT,
};
use impulse_core::zk::{
    self, check_template, journal, journal_hash, owner_spk, p2sh_spk, parse_list, sha256,
    FundableVaultV3, IpstV3, ListTree, Manifest, ManifestStatus, MemberPath, OfferedAddressesV3,
    PathStatus, ProofBytes, TermsV3, ValidatedTermsV3, VaultV3, ZkError,
};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};

// =============================================================================================
// The fixed texts of spec/V3-ZK.md section 9.5
// =============================================================================================

/// The disclaimer: in `impulse zk --help`, at the top of `zk verify` output and in every v3
/// receipt.
pub const DISCLAIMER: &str = "Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain.";

/// The setup line: wherever the proof check is described and in `zk verify` output.
pub const SETUP_LINE: &str =
    "The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified.";

/// The gate line (spec section 9.5, D64): in `zk --help`, in `zk verify` and `terms` output, in the
/// README v3 section and in the runbook. The cash vault does not check the proof; [S10] binds it
/// to the gated asset vault of its terms.
pub const GATE_LINE: &str = "Only the asset vault checks the proof. The cash vault settles only beside the asset vault of the same terms, so verify both vault addresses before funding cash.";

/// The cap line: in the README v3 section.
pub const CAP_LINE: &str = "Template v3 and the list prover are for values at or below the 10 KAS cap. Above it the tools refuse unless --i-accept-the-risk is passed.";

/// Printed by `terms new` and `verify` (spec section 5.6).
pub const REVOCATION_GUIDANCE: &str = "A list cannot be revoked inside these terms. Keep the refund expiry short, and name the list issuer as authority if removals must stop a settle.";

/// `verify`, terms without an authority (spec section 7.3).
const NO_AUTHORITY_WARNING: &str =
    "No authority: removal from the list after these terms were made cannot stop the settle.";

/// `verify`, no path file (spec section 9.3).
const NO_PATH_WARNING: &str =
    "No path file: the buyer cannot settle without the list issuer's path for this owner.";

/// `settle build` (spec section 10): in words, without figures.
const MASS_NOTE: &str = "This settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass.";

/// The long help of `impulse zk`: the fixed texts, each on its own line.
const ZK_LONG_HELP: &str = "\
Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain.
The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified.
Only the asset vault checks the proof. The cash vault settles only beside the asset vault of the same terms, so verify both vault addresses before funding cash.";

/// Format tags of the files this module reads and writes.
const MANIFEST_FORMAT: &str = "impulse-zk-manifest/1";
const PROOF_FORMAT: &str = "impulse-zk-proof/1";

// =============================================================================================
// Commands
// =============================================================================================

/// List-gated settlement: issuer lists, terms v3, and the transactions of a gated trade.
#[derive(Subcommand, Debug)]
#[command(after_long_help = ZK_LONG_HELP)]
pub enum ZkCommand {
    /// Issuer lists: build a root and path files, write a manifest.
    #[command(subcommand)]
    List(ListCommand),
    /// Create terms v3 (new) or terms v4 (new-hashed), or show a terms v4 leg (reveal).
    #[command(subcommand)]
    Terms(ZkTermsCommand),
    /// Show a trade's two vault addresses (terms v3 or terms v4).
    Address(AddressArgs),
    /// Check offered funding addresses against terms v4, or addresses, the list manifest and a
    /// member's path against terms v3.
    Verify(VerifyArgs),
    /// Print the arguments impulse-zk-prove takes for a trade.
    ProveArgs(ProveArgsArgs),
    /// Terms v4: write the witness file of each vault input of an IPST for impulse-zk-prove-terms.
    Witness(ZkWitnessArgs),
    /// Build an unsigned funding transaction for your leg.
    #[command(subcommand)]
    Fund(ZkFundCommand),
    /// Build an unsigned settle that carries a proof (terms v4: a plan, then the settle with its
    /// proofs).
    #[command(subcommand)]
    Settle(ZkSettleCommand),
    /// Build an unsigned refund of one vault UTXO.
    #[command(subcommand)]
    Refund(ZkRefundCommand),
    /// Sign, merge or write out IPST version 4 (terms v3) or version 5 (terms v4) documents.
    #[command(subcommand)]
    Ipst(ZkIpstCommand),
    /// Check a fully signed IPST again and submit it to your node.
    Submit(ZkSubmitArgs),
    /// Report a transaction's acceptance for terms v3; with --key-file, sign it as a receipt.
    Status(ZkStatusArgs),
    /// Settlement receipts of terms v3.
    #[command(subcommand)]
    Receipt(ZkReceiptCommand),
}

#[derive(Subcommand, Debug)]
pub enum ZkReceiptCommand {
    /// Check a receipt's signature, and with --node its on-chain facts.
    Verify(ZkReceiptVerifyArgs),
}

#[derive(Subcommand, Debug)]
pub enum ListCommand {
    /// Read a list file and write its root and one path file per entry.
    Build(ListBuildArgs),
    /// Write the manifest an issuer signs, or attach and check its signature.
    Manifest(ListManifestArgs),
}

#[derive(Subcommand, Debug)]
pub enum ZkTermsCommand {
    /// Check a draft, show its terms hash and vault addresses, and write the terms file.
    New(Box<ZkTermsNewArgs>),
    /// Show the commitment and vault address a hashed-terms (v4) terms file commits to for a leg.
    Reveal(crate::zkh_cmd::ZkTermsRevealArgs),
    /// Check a terms v4 draft, draw its blind, write the terms v4 file and read it back.
    NewHashed(Box<ZkTermsNewHashedArgs>),
}

#[derive(Subcommand, Debug)]
pub enum ZkFundCommand {
    /// Fund your leg's vault: an unsigned IPST.
    Build(ZkFundBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum ZkSettleCommand {
    /// Settle a funded trade with the proof file impulse-zk-prove wrote: an unsigned IPST.
    Build(ZkSettleBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum ZkRefundCommand {
    /// Refund one vault UTXO home: an unsigned IPST. A refund needs no proof.
    Build(ZkRefundBuildArgs),
}

#[derive(Subcommand, Debug)]
pub enum ZkIpstCommand {
    /// Check an IPST against the terms you agreed to and sign your inputs with your key file.
    Sign(Box<ZkSignArgs>),
    /// Combine IPSTs of one transaction.
    Merge(ZkMergeArgs),
    /// Write a fully signed IPST's transaction as the file impulse-watch --keep-signed reads.
    Raw(ZkRawArgs),
}

#[derive(Args, Debug)]
pub struct ListBuildArgs {
    /// The list file: one entry per line, in the order you choose. An entry is a Kaspa address of
    /// the network (Schnorr P2PK or P2SH), pubkey:<64 hex digits> or scripthash:<64 hex digits>.
    /// Lines starting with # and blank lines are skipped.
    #[arg(long, value_name = "FILE")]
    pub list: PathBuf,
    /// The directory to create for the path files, one per entry; must not exist. Each file
    /// holds that entry's salt: give it to that member only.
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct ListManifestArgs {
    /// The list root, 64 lowercase hex digits (printed by list build).
    #[arg(long, value_name = "HEX")]
    pub root: String,
    /// A name for the list, 1 to 64 bytes of UTF-8.
    #[arg(long, value_name = "TEXT")]
    pub list_id: String,
    /// The version of the list this root is.
    #[arg(long, value_name = "N")]
    pub list_version: u32,
    /// Unix seconds; default now.
    #[arg(long, value_name = "SECONDS")]
    pub issued_at: Option<u64>,
    /// The list issuer's x-only public key, 64 lowercase hex digits. Needed with --signature.
    #[arg(long, value_name = "HEX", requires = "signature")]
    pub list_issuer_key: Option<String>,
    /// The issuer's BIP-340 signature of the digest printed without it, 128 lowercase hex
    /// digits. It is checked under --list-issuer-key before anything is written.
    #[arg(long, value_name = "HEX", requires = "list_issuer_key")]
    pub signature: Option<String>,
    /// Where to write the manifest file; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ZkTermsNewArgs {
    /// The draft: terms in JSON form with version 3 and no list keys; a missing nonce is drawn
    /// at random.
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// The list issuer's x-only public key, 64 lowercase hex digits. The usual authority.
    #[arg(long, value_name = "HEX")]
    pub list_issuer_key: String,
    /// The root of the issuer list, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub list_root: String,
    /// Allow terms without an authority. Without one, removal from the list after the terms were
    /// made cannot stop the settle.
    #[arg(long)]
    pub no_authority: bool,
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

/// `zk terms new-hashed`: terms v4 from a draft.
#[derive(Args, Debug)]
pub struct ZkTermsNewHashedArgs {
    /// The draft: terms in JSON form with version 4, an authority, and no blind; a missing nonce is
    /// drawn at random. The blind is always drawn by this command.
    #[arg(long, value_name = "FILE")]
    pub draft: PathBuf,
    /// The terms file to write (lowercase hex of the canonical terms v4); must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub cap: CapArgs,
}

/// `zk witness`: the witness of each vault input of a terms v4 IPST.
#[derive(Args, Debug)]
pub struct ZkWitnessArgs {
    /// The IPST (version 5): a plan from settle build or refund build without proofs, or a
    /// document that carries them.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// The directory to create for the witness files; must not exist.
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,
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
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The address offered for the asset vault.
    #[arg(long, value_name = "ADDRESS")]
    pub asset_address: String,
    /// The address offered for the cash vault; none for external cash.
    #[arg(long, value_name = "ADDRESS")]
    pub cash_address: Option<String>,
    /// The signed list manifest file (list manifest --out, with --signature).
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// A member's path file: checked against the buyer delivery owner and the list root.
    #[arg(long, value_name = "FILE")]
    pub path: Option<PathBuf>,
    #[command(flatten)]
    pub creation: CreationArgs,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub cap: CapArgs,
}

#[derive(Args, Debug)]
pub struct ProveArgsArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZkFundBuildArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The leg to fund: your own (asset: seller, cash: buyer).
    #[arg(long, value_enum)]
    pub leg: LegArg,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub party: PartyArgs,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// A KCC-20 leg: a token UTXO of yours to escrow, <txid>:<index>:<amount>; repeat for more.
    #[arg(long, value_name = "TXID:INDEX:AMOUNT")]
    pub token: Vec<String>,
    /// A KCC-20 leg: KAS on the escrowed token output; default the minimum.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 leg: KAS on the authorizer at the vault; default the minimum.
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZkSettleBuildArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The proof file impulse-zk-prove wrote for this trade's asset vault (terms v3: required;
    /// terms v4: the asset vault's proof, and without it the result is a plan for the prover).
    #[arg(long, value_name = "FILE")]
    pub proof: Option<PathBuf>,
    /// Terms v4 only: the proof file impulse-zk-prove-terms wrote for the cash vault.
    #[arg(long, value_name = "FILE")]
    pub proof_cash: Option<PathBuf>,
    /// wRPC URL of a synced node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub pay: PayArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZkRefundBuildArgs {
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The leg to refund.
    #[arg(long, value_enum)]
    pub leg: LegArg,
    /// Who signs the refund.
    #[arg(long, value_enum)]
    pub signer: SignerArg,
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
    /// Depositor only: refund the authorizer alone; the escrowed token stays in the vault.
    #[arg(long, conflicts_with_all = ["token_amount", "token_minter"])]
    pub without_token: bool,
    /// The escrowed token's amount, when it is not the leg amount (depositor only).
    #[arg(long, value_name = "AMOUNT")]
    pub token_amount: Option<u64>,
    /// The escrowed token is a minter (it goes home as one).
    #[arg(long)]
    pub token_minter: bool,
    /// Terms v4 only: the proof file impulse-zk-prove-terms wrote for this refund; without it the
    /// result is a plan for the prover. A refund of terms v3 needs no proof.
    #[arg(long, value_name = "FILE")]
    pub proof: Option<PathBuf>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZkSignArgs {
    /// The IPST (version 4) to sign.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// The terms file of the trade you agreed to: the IPST must be for exactly these terms.
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// Your key file: 64 hex digits, readable by you only. Read by the signing module only.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
    /// Who you are in the trade; --my-key must be that role's key in the terms.
    #[arg(long, value_enum)]
    pub role: SignRole,
    /// Your x-only public key, 64 lowercase hex digits: the slots signed are those for this key.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// Buyer: the exact destination your asset must be delivered to, when it does not pay
    /// --my-key: a Kaspa address or kcc20:<type>:<hex>.
    #[arg(long, value_name = "DESTINATION")]
    pub my_delivery: Option<String>,
    /// Seller: the exact destination your proceeds must go to, when it does not pay --my-key.
    #[arg(long, value_name = "DESTINATION")]
    pub my_proceeds: Option<String>,
    /// Buyer or seller: the exact destination your refund must go to, when it does not pay
    /// --my-key.
    #[arg(long, value_name = "DESTINATION")]
    pub my_refund: Option<String>,
    #[command(flatten)]
    pub daa: DaaArgs,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Where your change must go; default the P2PK of --my-key.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// When you sign a fee input: the largest fee you accept, in sompi; default twice the
    /// minimum relay fee.
    #[arg(long, value_name = "SOMPI")]
    pub max_fee: Option<u64>,
    /// When you sign a fee input of a settle or refund: the most KAS you accept to top up
    /// under-funded trade outputs with, in sompi; default 0.
    #[arg(long, value_name = "SOMPI")]
    pub max_topup: Option<u64>,
    /// A KCC-20 funding: the KAS on the escrowed token, which must equal the document's.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 funding: the KAS on the authorizer, which must equal the document's.
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// Where to write the signed IPST; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Who signs: a party, the authority, or a payer with no role in the terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignRole {
    Buyer,
    Seller,
    Authority,
    Payer,
}

impl SignRole {
    pub(crate) fn name(self) -> &'static str {
        match self {
            SignRole::Buyer => "buyer",
            SignRole::Seller => "seller",
            SignRole::Authority => "authority",
            SignRole::Payer => "payer",
        }
    }
}

/// Where the current DAA score comes from: exactly one of the two.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DaaArgs {
    /// The current DAA score, as you read it from your node. Testnet only: on mainnet the score
    /// is read from --node.
    #[arg(long, value_name = "SCORE")]
    pub daa: Option<u64>,
    /// wRPC URL of a synced node to read the current DAA score from.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

#[derive(Args, Debug)]
pub struct ZkMergeArgs {
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
pub struct ZkRawArgs {
    /// The fully signed IPST.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// Where to write the signed transaction; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZkSubmitArgs {
    /// The fully signed IPST.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// wRPC URL of a synced node. There is no default. Submit the same document to each node you
    /// want to try with one command per node.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Also write the signed transaction as the raw form in hex that impulse-watch run
    /// --keep-signed reads: created before anything is sent, removed if the submission is
    /// refused; must not exist.
    #[arg(long, value_name = "FILE")]
    pub signed_tx_out: Option<PathBuf>,
    /// Fault test, on testnet only: submit a copy of the transaction with one bit of the proof
    /// flipped instead of the transaction. The node must refuse it; the command succeeds when it
    /// does, and fails if the node accepts it.
    #[arg(long)]
    pub flip_proof_bit: bool,
}

#[derive(Args, Debug)]
pub struct ZkStatusArgs {
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
    /// The depth, in DAA scores below the virtual, from which you call an accepted transaction
    /// final. Your choice, not a guarantee of the network; without it the state is accepted.
    #[arg(long, value_name = "DAA")]
    pub final_depth: Option<u64>,
    /// Sign the result as a settlement receipt with this key file.
    #[arg(long, value_name = "FILE", requires_all = ["out", "min_depth"])]
    pub key_file: Option<PathBuf>,
    /// Where to write the receipt; must not exist.
    #[arg(long, value_name = "FILE", requires = "key_file")]
    pub out: Option<PathBuf>,
    /// With --key-file: refuse to sign unless the depth is at least this.
    #[arg(long, value_name = "DAA", requires = "key_file")]
    pub min_depth: Option<u64>,
}

#[derive(Args, Debug)]
pub struct ZkReceiptVerifyArgs {
    #[arg(long, value_name = "FILE")]
    pub receipt: PathBuf,
    /// The x-only public key the receipt must be signed by.
    #[arg(long, value_name = "HEX")]
    pub signer: Option<String>,
    /// The terms file of your trade: the receipt must name its terms hash.
    #[arg(long, value_name = "FILE", conflicts_with = "terms_hash")]
    pub terms: Option<PathBuf>,
    /// The terms hash of your trade, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub terms_hash: Option<String>,
    /// The transaction ID you expect, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub txid: Option<String>,
    /// wRPC URL of a synced node to re-check the on-chain facts against.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

// =============================================================================================
// Dispatch
// =============================================================================================

pub(crate) fn run(
    ctx: &Ctx,
    command: ZkCommand,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        ZkCommand::List(ListCommand::Build(a)) => list_build(ctx, a, out),
        ZkCommand::List(ListCommand::Manifest(a)) => list_manifest(ctx, a, out),
        ZkCommand::Terms(ZkTermsCommand::New(a)) => terms_new(ctx, *a, out),
        ZkCommand::Terms(ZkTermsCommand::Reveal(a)) => crate::zkh_cmd::terms_reveal(ctx, a, out),
        ZkCommand::Terms(ZkTermsCommand::NewHashed(a)) => {
            crate::zkh_cmd::terms_new_hashed(ctx, *a, out)
        }
        ZkCommand::Address(a) if is_hashed_file(&a.terms) => crate::zkh_cmd::address(ctx, a, out),
        ZkCommand::Address(a) => address(ctx, a, out),
        ZkCommand::Verify(a) if is_hashed_file(&a.terms) => crate::zkh_cmd::verify(ctx, a, out),
        ZkCommand::Verify(a) => verify(ctx, a, out),
        ZkCommand::ProveArgs(a) if is_hashed_file(&a.terms) => Err(CliError::new(
            "TX_WRONG_MODE",
            "terms v4 are proved per vault input: build the plan with settle build or refund build, then impulse zk witness",
        )),
        ZkCommand::ProveArgs(a) => prove_args(ctx, a, out),
        ZkCommand::Witness(a) => crate::zkh_cmd::witness(ctx, a, out),
        ZkCommand::Fund(ZkFundCommand::Build(a)) if is_hashed_file(&a.terms) => {
            crate::zkh_cmd::fund_build(ctx, a, out)
        }
        ZkCommand::Fund(ZkFundCommand::Build(a)) => fund_build(ctx, a, out),
        ZkCommand::Settle(ZkSettleCommand::Build(a)) if is_hashed_file(&a.terms) => {
            crate::zkh_cmd::settle_build(ctx, a, out, notes)
        }
        ZkCommand::Settle(ZkSettleCommand::Build(a)) => settle_build(ctx, a, out),
        ZkCommand::Refund(ZkRefundCommand::Build(a)) if is_hashed_file(&a.terms) => {
            crate::zkh_cmd::refund_build(ctx, a, out, notes)
        }
        ZkCommand::Refund(ZkRefundCommand::Build(a)) => refund_build(ctx, a, out),
        ZkCommand::Ipst(ZkIpstCommand::Sign(a)) => crate::zk_sign::sign(ctx, *a, out, notes),
        ZkCommand::Ipst(ZkIpstCommand::Merge(a)) => crate::zk_sign::merge(ctx, a, out),
        ZkCommand::Ipst(ZkIpstCommand::Raw(a)) => crate::zk_sign::raw(ctx, a, out),
        ZkCommand::Submit(a) => crate::zk_sign::submit(ctx, a, out),
        ZkCommand::Status(a) if is_hashed_file(&a.terms) => Err(CliError::new(
            "TX_WRONG_MODE",
            "zk status is for terms v3: show a terms v4 trade with impulse decode --with-terms",
        )),
        ZkCommand::Status(a) => crate::zk_receipt::status(ctx, a, out),
        ZkCommand::Receipt(ZkReceiptCommand::Verify(a))
            if a.terms.as_deref().is_some_and(is_hashed_file) =>
        {
            Err(CliError::new(
                "TX_WRONG_MODE",
                "zk receipt is for terms v3: show a terms v4 trade with impulse decode --with-terms",
            ))
        }
        ZkCommand::Receipt(ZkReceiptCommand::Verify(a)) => {
            crate::zk_receipt::receipt_verify(ctx, a, out)
        }
    }
}

// =============================================================================================
// Files
// =============================================================================================

fn json_err(reason: String) -> CliError {
    CliError::new("CLI_TERMS_JSON", reason)
}

fn hex_arg(name: &str, value: &str) -> Result<[u8; 32], CliError> {
    unhex32(value).ok_or_else(|| {
        CliError::new(
            "CLI_HEX",
            format!("--{name} must be 64 lowercase hex digits"),
        )
    })
}

/// Terms v3 from the terms JSON object: every v1 key, `version` 3, and the two list keys.
fn parse_terms_v3_json(value: &Value) -> Result<TermsV3, CliError> {
    const KEYS: [&str; 19] = [
        "version",
        "network",
        "settlement_mode",
        "nonce",
        "seller_key",
        "buyer_key",
        "authority_key",
        "asset_leg",
        "cash_leg",
        "buyer_delivery",
        "seller_proceeds",
        "seller_refund",
        "buyer_refund",
        "earliest_daa",
        "expiry_daa",
        "funding_mode",
        "list_issuer_key",
        "list_root",
        "trade_ref",
    ];
    let obj = Obj::new("terms", value).map_err(json_err)?;
    obj.keys(&KEYS, &[]).map_err(json_err)?;
    let version = obj.num("version", u8::MAX.into()).map_err(json_err)? as u8;
    if version != zk::TERMS_V3_VERSION {
        return Err(ZkError::TermsVersion { version }.into());
    }
    let issuer = obj.hex32("list_issuer_key").map_err(json_err)?;
    let root = obj.hex32("list_root").map_err(json_err)?;
    // The rest is the v1 JSON form of the v1 fields.
    let mut v1 = value.clone();
    let map = v1.as_object_mut().expect("checked to be an object");
    map.remove("list_issuer_key");
    map.remove("list_root");
    map.insert("version".into(), Value::from(1));
    let fields = parse_terms_json(&v1)?;
    Ok(TermsV3::new(fields, issuer, root))
}

/// The JSON form of terms v3, keys in field order with the two list keys before `trade_ref`.
fn terms_v3_json(t: &TermsV3) -> Json {
    let Json::Obj(fields) = terms_json(&t.fields) else {
        unreachable!("terms render as an object")
    };
    let mut out = Vec::with_capacity(fields.len() + 2);
    for (key, value) in fields {
        match key {
            "version" => out.push((key, Json::Num(zk::TERMS_V3_VERSION.into()))),
            "trade_ref" => {
                out.push(("list_issuer_key", Json::Str(hex(&t.list_issuer_key))));
                out.push(("list_root", Json::Str(hex(&t.list_root))));
                out.push((key, value));
            }
            _ => out.push((key, value)),
        }
    }
    Json::Obj(out)
}

/// The terms v3 file text: the JSON form, the canonical bytes and the terms hash.
pub fn render_terms_v3_file(terms: &ValidatedTermsV3) -> String {
    Json::Obj(vec![
        ("terms", terms_v3_json(terms.terms())),
        ("canonical", Json::Str(hex(terms.canonical()))),
        ("terms_hash", Json::Str(hex(&terms.terms_hash()))),
    ])
    .render()
}

/// Parses a terms v3 file and runs the structure checks. Refuses a file whose three parts
/// disagree (`CLI_TERMS_FILE_INCONSISTENT`).
pub fn parse_terms_v3_file(text: &str) -> Result<ValidatedTermsV3, CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&["terms", "canonical", "terms_hash"], &[])
        .map_err(json_err)?;
    let terms = parse_terms_v3_json(obj.get("terms").map_err(json_err)?)?;
    let canonical = obj.hex("canonical").map_err(json_err)?;
    let hash = obj.hex32("terms_hash").map_err(json_err)?;
    let inconsistent = |what: &str| CliError::new("CLI_TERMS_FILE_INCONSISTENT", what.to_string());
    if terms.encode()? != canonical {
        return Err(inconsistent("canonical is not the encoding of terms"));
    }
    if terms.terms_hash()? != hash {
        return Err(inconsistent("terms_hash is not the hash of terms"));
    }
    Ok(terms.validate_structure()?)
}

pub(crate) fn read_terms_v3(ctx: &Ctx, path: &Path) -> Result<ValidatedTermsV3, CliError> {
    let terms = parse_terms_v3_file(&read_text(path)?)?;
    let network = terms.terms().fields.network;
    if network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the terms are for {}; pass --network {0} to act on them",
                network_name(network)
            ),
        ));
    }
    Ok(terms)
}

/// A path file: `{"index": n, "salt": "<hex32>", "siblings": ["<hex32>", ... 20 of them]}`, the
/// file `impulse-zk-prove --path` reads.
pub fn parse_path_file(text: &str) -> Result<MemberPath, CliError> {
    let invalid = |reason: String| ZkError::PathInvalid { reason };
    let value = parse_strict(text).map_err(|e| invalid(format!("path file: {e}")))?;
    let obj = Obj::new("", &value).map_err(|e| invalid(format!("path file: {e}")))?;
    obj.keys(&["index", "salt", "siblings"], &[])
        .map_err(|e| invalid(format!("path file: {e}")))?;
    let index = obj
        .num("index", u32::MAX.into())
        .map_err(|e| invalid(format!("path file: {e}")))? as u32;
    let salt = obj
        .hex32("salt")
        .map_err(|e| invalid(format!("path file: {e}")))?;
    let siblings = value["siblings"]
        .as_array()
        .ok_or_else(|| invalid("path file: siblings is not an array".into()))?
        .iter()
        .map(|v| {
            v.as_str().and_then(unhex32).ok_or_else(|| {
                invalid("path file: a sibling is not 64 lowercase hex digits".into())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MemberPath::new(index, salt, &siblings)?)
}

fn render_path_file(path: &MemberPath) -> String {
    let siblings: Vec<String> = path
        .siblings
        .iter()
        .map(|s| format!("    \"{}\"", hex(s)))
        .collect();
    format!(
        "{{\n  \"index\": {},\n  \"salt\": \"{}\",\n  \"siblings\": [\n{}\n  ]\n}}\n",
        path.index,
        hex(&path.salt),
        siblings.join(",\n")
    )
}

/// A manifest file with its signature, if it has one.
struct ManifestFile {
    manifest: Manifest,
    list_issuer_key: Option<[u8; 32]>,
    signature: Option<[u8; 64]>,
}

fn render_manifest_file(
    m: &Manifest,
    issuer: Option<&[u8; 32]>,
    signature: Option<&[u8; 64]>,
) -> String {
    Json::Obj(vec![
        ("format", Json::Str(MANIFEST_FORMAT.into())),
        ("manifest", Json::Str(hex(&m.encode()))),
        ("digest", Json::Str(hex(&m.digest()))),
        (
            "list_issuer_key",
            issuer.map_or(Json::Null, |k| Json::Str(hex(k))),
        ),
        (
            "signature",
            signature.map_or(Json::Null, |s| Json::Str(hex(s))),
        ),
    ])
    .render()
}

fn parse_manifest_file(text: &str) -> Result<ManifestFile, CliError> {
    let invalid = |reason: String| ZkError::ManifestInvalid {
        reason: format!("manifest file: {reason}"),
    };
    let value = parse_strict(text).map_err(invalid)?;
    let obj = Obj::new("", &value).map_err(invalid)?;
    obj.keys(
        &[
            "format",
            "manifest",
            "digest",
            "list_issuer_key",
            "signature",
        ],
        &[],
    )
    .map_err(invalid)?;
    if obj.str("format").map_err(invalid)? != MANIFEST_FORMAT {
        return Err(invalid("unknown format".into()).into());
    }
    let manifest = Manifest::decode(&obj.hex("manifest").map_err(invalid)?)?;
    if obj.hex32("digest").map_err(invalid)? != manifest.digest() {
        return Err(invalid("digest is not the digest of manifest".into()).into());
    }
    let list_issuer_key = if obj.is_null("list_issuer_key").map_err(invalid)? {
        None
    } else {
        Some(obj.hex32("list_issuer_key").map_err(invalid)?)
    };
    let signature = if obj.is_null("signature").map_err(invalid)? {
        None
    } else {
        let bytes = obj.hex("signature").map_err(invalid)?;
        Some(
            <[u8; 64]>::try_from(bytes.as_slice())
                .map_err(|_| invalid("signature is not 64 bytes".into()))?,
        )
    };
    Ok(ManifestFile {
        manifest,
        list_issuer_key,
        signature,
    })
}

/// A proof file as `impulse-zk-prove` writes it (circuits/README.md, "Proof file").
struct ProofFile {
    proof: ProofBytes,
    journal: Vec<u8>,
    image_id: [u8; 32],
}

fn parse_proof_file(text: &str) -> Result<ProofFile, CliError> {
    let malformed = |reason: String| ZkError::ProofMalformed {
        reason: format!("proof file: {reason}"),
    };
    let value = parse_strict(text).map_err(malformed)?;
    let obj = Obj::new("", &value).map_err(malformed)?;
    obj.keys(
        &[
            "format",
            "proof",
            "journal",
            "journal_hash",
            "image_id",
            "risc0_zkvm",
            "groth16_prover_image",
        ],
        &[],
    )
    .map_err(malformed)?;
    if obj.str("format").map_err(malformed)? != PROOF_FORMAT {
        return Err(malformed("unknown format".into()).into());
    }
    let proof = ProofBytes::parse(&obj.hex("proof").map_err(malformed)?)?;
    let journal = obj.hex("journal").map_err(malformed)?;
    if obj.hex32("journal_hash").map_err(malformed)? != sha256(&journal) {
        return Err(malformed("journal_hash is not SHA-256 of the journal".into()).into());
    }
    let image_id = obj.hex32("image_id").map_err(malformed)?;
    Ok(ProofFile {
        proof,
        journal,
        image_id,
    })
}

/// Writes a file that holds a salt: new, mode 0600 on unix.
pub(crate) fn write_new_secret(path: &Path, text: &str) -> Result<(), CliError> {
    write_new_bytes(path, text.as_bytes())
}

/// Writes a file of bytes: new, mode 0600 on unix.
pub(crate) fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    CliError::new("CLI_OUTPUT_EXISTS", format!("{} exists", path.display()))
                } else {
                    CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display()))
                }
            })?;
        file.write_all(bytes)
            .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))
    }
    #[cfg(not(unix))]
    {
        write_new(path, &String::from_utf8_lossy(bytes))
    }
}

// =============================================================================================
// list build, list manifest
// =============================================================================================

fn list_build(ctx: &Ctx, a: ListBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let owners = parse_list(
        &crate::terms_file::read_text_max(&a.list, crate::terms_file::MAX_LIST_FILE)?,
        ctx.network,
    )?;
    let tree = ListTree::build(owners)?;
    // The directory is created here and must not exist: path files hold salts.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&a.out_dir)
            .map_err(dir_error(&a.out_dir))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&a.out_dir).map_err(dir_error(&a.out_dir))?;
    for i in 0..tree.len() {
        let path = tree.path(i).expect("in range");
        write_new_secret(
            &a.out_dir.join(format!("path-{i:07}.json")),
            &render_path_file(&path),
        )?;
    }
    print(
        out,
        &[
            format!("list root: {}", hex(&tree.root())),
            format!("entries: {}", tree.len()),
            format!("network: {}", network_name(ctx.network)),
            format!(
                "wrote: {} path files in {}, entry i in path-<i>.json",
                tree.len(),
                a.out_dir.display()
            ),
            "Each path file holds its entry's salt. Give each file to its member only, before any trade; the list file and the salts stay on this machine.".to_string(),
        ],
    )
}

fn dir_error(path: &Path) -> impl Fn(std::io::Error) -> CliError + '_ {
    move |e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::new("CLI_OUTPUT_EXISTS", format!("{} exists", path.display()))
        } else {
            CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display()))
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A Unix time as `YYYY-MM-DD` (UTC), for the manifest status line.
pub fn utc_date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn list_manifest(ctx: &Ctx, a: ListManifestArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let root = hex_arg("root", &a.root)?;
    let manifest = Manifest::new(
        ctx.network,
        &a.list_id,
        a.list_version,
        a.issued_at.unwrap_or_else(now_unix),
        root,
    )?;
    let mut lines = vec![
        format!("network: {}", network_name(ctx.network)),
        format!("list_id: {}", a.list_id),
        format!("list_version: {}", a.list_version),
        format!("issued: {}", utc_date(manifest.issued_at)),
        format!("list root: {}", hex(&root)),
        format!("manifest: {}", hex(&manifest.encode())),
        format!("digest: {}", hex(&manifest.digest())),
    ];
    match (&a.signature, &a.list_issuer_key) {
        (Some(sig), Some(key)) => {
            let key = hex_arg("list-issuer-key", key)?;
            let sig = unhex(sig)
                .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| {
                    CliError::new("CLI_HEX", "--signature must be 128 lowercase hex digits")
                })?;
            manifest.verify_signature(&key, &sig)?;
            lines.push(format!(
                "signature: verifies under list issuer key {}",
                hex(&key)
            ));
            if let Some(path) = &a.out {
                write_new(
                    path,
                    &render_manifest_file(&manifest, Some(&key), Some(&sig)),
                )?;
                lines.push(format!("wrote: {}", path.display()));
            }
        }
        _ => {
            lines.push(
                "Sign the digest with the list issuer's own signer (BIP-340 over the 32 bytes); no Impulse command holds the issuer's key. Run this command again with --list-issuer-key and --signature to attach and check the signature.".to_string(),
            );
            if let Some(path) = &a.out {
                write_new(path, &render_manifest_file(&manifest, None, None))?;
                lines.push(format!("wrote: {} (unsigned)", path.display()));
            }
        }
    }
    print(out, &lines)
}

// =============================================================================================
// terms new, address, verify, prove-args
// =============================================================================================

fn vault_line(leg: LegIndex, vault: &FundableVaultV3) -> String {
    format!("{} vault: {}", leg_name(leg), zk::vault_address_v3(vault))
}

/// Both legs' fundable vaults; a leg the terms give no vault (external cash) is None.
fn fundable_vaults(
    terms: &ValidatedTermsV3,
    creation: &CreationContext,
) -> Result<[Option<FundableVaultV3>; 2], CliError> {
    let mut out = [None, None];
    for leg in LegIndex::ALL {
        match VaultV3::instantiate_for_creation(terms, leg, creation) {
            Ok(v) => out[usize::from(leg.index())] = Some(v),
            Err(ZkError::Template(impulse_core::template::TemplateError::NoVault { .. }))
                if leg == LegIndex::Cash => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

/// The lines every command that shows terms v3 prints first: the decoded terms and what the
/// gate is and is not.
fn terms_lines(terms: &ValidatedTermsV3, now_daa: u64) -> Vec<String> {
    let t = terms.terms();
    let mut lines = vec![
        DISCLAIMER.to_string(),
        SETUP_LINE.to_string(),
        GATE_LINE.to_string(),
    ];
    lines.extend(summary::summary(&terms.terms_hash(), &t.fields, now_daa));
    lines.push(format!("list_issuer_key: {}", hex(&t.list_issuer_key)));
    lines.push(format!("list_root: {}", hex(&t.list_root)));
    let owner = terms.delivery_owner();
    lines.push(format!(
        "buyer delivery owner (public on chain): {} {}",
        owner_type_name(&owner),
        hex(&owner.identifier)
    ));
    lines
}

fn owner_type_name(o: &Kcc20Owner) -> &'static str {
    match o.identifier_type {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

/// Warnings that follow from the shape of the terms (spec sections 5.6, 7.3).
fn term_warnings(terms: &ValidatedTermsV3) -> Vec<String> {
    let t = terms.terms();
    let mut lines = Vec::new();
    if t.fields.authority_key.is_none() {
        lines.push(NO_AUTHORITY_WARNING.to_string());
    }
    if t.list_issuer_key == t.fields.seller_key {
        lines.push("The seller is the list issuer: the seller curates this list.".to_string());
    }
    lines
}

fn cap_line(ctx: &Ctx, cap: &CapArgs, terms: &ValidatedTermsV3) -> Result<String, CliError> {
    CapPolicy::new(ctx.env.max_value, cap.i_accept_the_risk)?
        .check(&terms.terms().fields, cap.kas_equivalent)
}

fn terms_new(ctx: &Ctx, a: ZkTermsNewArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let draft = parse_draft(&read_text(&a.draft)?)?;
    if draft.version != zk::TERMS_V3_VERSION {
        return Err(ZkError::TermsVersion {
            version: draft.version,
        }
        .into());
    }
    let terms = TermsV3::new(
        draft,
        hex_arg("list-issuer-key", &a.list_issuer_key)?,
        hex_arg("list-root", &a.list_root)?,
    );
    let checked = terms.clone().validate_structure()?;
    terms.require_authority(a.no_authority)?;
    let creation = creation(ctx, &a.creation)?;
    checked.validate_creation(&creation)?;
    check_kas_minimum(&checked.terms().fields)?;
    let vaults = fundable_vaults(&checked, &creation)?;
    let you = summary::check_party(&checked.terms().fields, &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&checked, creation.creation_daa);
    lines.push(you);
    lines.extend(crate::trade::template_warnings(&checked.terms().fields));
    lines.push(cap_line(ctx, &a.cap, &checked)?);
    write_new(&a.out, &render_terms_v3_file(&checked))?;
    for leg in LegIndex::ALL {
        lines.push(match &vaults[usize::from(leg.index())] {
            Some(v) => vault_line(leg, v),
            None => format!(
                "{}: no vault: external cash settles off chain",
                leg_name(leg)
            ),
        });
    }
    lines.extend(term_warnings(&checked));
    lines.push(REVOCATION_GUIDANCE.to_string());
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

fn address(ctx: &Ctx, a: AddressArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_v3(ctx, &a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    terms.validate_creation(&creation)?;
    check_kas_minimum(&terms.terms().fields)?;
    check_pinned(&terms.terms().fields)?;
    let vaults = fundable_vaults(&terms, &creation)?;
    let you = summary::check_party(&terms.terms().fields, &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&terms, creation.creation_daa);
    lines.push(you);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    for leg in LegIndex::ALL {
        match &vaults[usize::from(leg.index())] {
            Some(v) => {
                lines.push(vault_line(leg, v));
                lines.push(format!(
                    "  funded by: the {}",
                    crate::cli::funder(leg).name()
                ));
                lines.push(format!(
                    "  escrowed token owner: script_hash {}",
                    hex(&v.vault().script_hash())
                ));
            }
            None => lines.push(format!(
                "{}: no vault: external cash settles off chain",
                leg_name(leg)
            )),
        }
    }
    lines.extend(term_warnings(&terms));
    print(out, &lines)
}

fn verify(ctx: &Ctx, a: VerifyArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_v3(ctx, &a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    check_kas_minimum(&terms.terms().fields)?;
    check_pinned(&terms.terms().fields)?;
    let manifest = a
        .manifest
        .as_ref()
        .map(|p| -> Result<_, CliError> {
            let file = parse_manifest_file(&read_text(p)?)?;
            let signature = file.signature.ok_or_else(|| ZkError::ManifestInvalid {
                reason: "the manifest file has no signature".into(),
            })?;
            if let Some(key) = file.list_issuer_key {
                if key != terms.terms().list_issuer_key {
                    return Err(ZkError::ManifestInvalid {
                        reason: "the manifest file names another list issuer key than the terms"
                            .into(),
                    }
                    .into());
                }
            }
            Ok((file.manifest, signature))
        })
        .transpose()?;
    let path = a
        .path
        .as_ref()
        .map(|p| parse_path_file(&read_text(p)?))
        .transpose()?;
    let report = zk::verify_v3(
        &terms,
        &creation,
        &OfferedAddressesV3 {
            asset: Some(&a.asset_address),
            cash: a.cash_address.as_deref(),
        },
        manifest.as_ref().map(|(m, s)| (m, s)),
        path.as_ref(),
    )?;
    let you = summary::check_party(&terms.terms().fields, &party(ctx.network, &a.party)?)?;
    let mut lines = vec![
        DISCLAIMER.to_string(),
        SETUP_LINE.to_string(),
        GATE_LINE.to_string(),
    ];
    for v in &report.addresses {
        lines.push(format!(
            "{} vault: {} (verified)",
            leg_name(v.leg),
            v.address
        ));
    }
    lines.push(format!("list_root: {}", hex(&report.list_root)));
    lines.push(format!("list_issuer_key: {}", hex(&report.list_issuer_key)));
    lines.push(match &report.manifest {
        ManifestStatus::Signed(m) => format!(
            "list manifest: signed by the list issuer key, list {} version {}, issued {}",
            m.list_id,
            m.list_version,
            utc_date(m.issued_at)
        ),
        ManifestStatus::NoneSupplied => {
            "list manifest: none supplied, nothing ties this root to the issuer key".to_string()
        }
    });
    if report.issuer_is_seller {
        lines.push("The seller is the list issuer: the seller curates this list.".to_string());
    }
    lines.push(format!(
        "buyer delivery owner (public on chain): {} {}",
        owner_type_name(&report.delivery_owner),
        hex(&report.delivery_owner.identifier)
    ));
    lines.push(match report.path {
        PathStatus::Leads => {
            "path: leads from the buyer delivery owner's salted leaf to the list root".to_string()
        }
        PathStatus::NoneSupplied => NO_PATH_WARNING.to_string(),
    });
    lines.push(if report.has_authority {
        format!(
            "authority_key: {}",
            terms
                .terms()
                .fields
                .authority_key
                .map_or_else(String::new, |k| hex(&k))
        )
    } else {
        NO_AUTHORITY_WARNING.to_string()
    });
    lines.push(REVOCATION_GUIDANCE.to_string());
    lines.push(you);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    lines.push(format!("ok: terms {}", hex(&terms.terms_hash())));
    print(out, &lines)
}

fn prove_args(ctx: &Ctx, a: ProveArgsArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_v3(ctx, &a.terms)?;
    let vault = VaultV3::instantiate_existing(&terms, LegIndex::Asset)?;
    let owner = terms.delivery_owner();
    let spk = owner_spk(&owner)?;
    let root = terms.terms().list_root;
    let j = journal(&root, &vault.script_hash(), &owner)?;
    print(
        out,
        &[
            "Run on the machine that holds the member's path file:".to_string(),
            format!(
                "impulse-zk-prove --path <PATH_FILE> --root {} --vault-spk {} --owner-spk {} --out <PROOF_FILE>",
                hex(&root),
                hex(&p2sh_spk(&vault.script_hash())),
                hex(&spk)
            ),
            format!("journal: {}", hex(&j)),
            format!("journal_hash: {}", hex(&journal_hash(&j))),
            format!(
                "image_id: {}",
                hex(&check_template()?.image_id())
            ),
        ],
    )
}

// =============================================================================================
// fund build, settle build, refund build
// =============================================================================================

fn not_found(what: String) -> CliError {
    CliError::new("CLI_UTXO_NOT_FOUND", what)
}

fn no_vault(leg: LegIndex) -> CliError {
    CliError::new(
        "TEMPLATE_NO_VAULT",
        format!(
            "the {} leg has no vault: external cash has no vault (no builder recovers a stray deposit there, owner decision D14)",
            leg_name(leg)
        ),
    )
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

fn owner(identifier_type: IdentifierType, identifier: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type,
        identifier,
    }
}

/// As the v1 helper of the same name: builds with the first one, two, ... fee candidates until
/// the builder accepts, and with the minimum relay fee unless `fee` is given.
fn build_with_fee(
    candidates: &[Utxo],
    fee: Option<u64>,
    change: &ScriptPublicKey,
    build: impl Fn(&FeePayment) -> Result<IpstV3, ZkError>,
) -> Result<IpstV3, CliError> {
    let mut last = None;
    for k in 1..=candidates.len() {
        let mut payment = FeePayment {
            inputs: candidates[..k].to_vec(),
            fee: fee.unwrap_or_else(|| min_relay_fee(0)),
            change: change.clone(),
        };
        let mut result = build(&payment);
        if fee.is_none() {
            if let Err(ZkError::Tx(TxError::FeeTooLow { minimum, .. })) = result {
                payment.fee = minimum;
                result = build(&payment);
            }
        }
        match result {
            Ok(ipst) => return Ok(ipst),
            Err(
                e @ ZkError::Tx(TxError::InsufficientFunds { .. } | TxError::BelowMinKas { .. }),
            ) => last = Some(e),
            Err(e) => return Err(e.into()),
        }
    }
    Err(last.map_or_else(
        || CliError::new("CLI_UTXO_NOT_FOUND", "no fee input"),
        CliError::from,
    ))
}

/// The UTXO at a vault without a covenant ID holding the most KAS.
fn authorizer(
    node: &dyn Node,
    vault: &VaultV3,
    network: Network,
    what: &str,
) -> Result<Utxo, CliError> {
    let mut all = utxos_with(node, &vault.script_public_key(), None, network)?;
    all.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
    all.into_iter()
        .next()
        .ok_or_else(|| not_found(format!("no {what} at the vault: is the leg funded?")))
}

/// The escrowed token of a vault: owned by the vault's script hash, `amount`, not a minter.
fn escrow(
    node: &dyn Node,
    vault: &VaultV3,
    template: &Kcc20Template,
    token: &Kcc20Token,
    amount: u64,
    network: Network,
    what: &str,
) -> Result<Utxo, CliError> {
    let state = Kcc20State::new(
        owner(IdentifierType::ScriptHash, vault.script_hash()),
        amount,
    );
    utxos_with(
        node,
        &template.script_public_key(&state)?,
        Some(token.covenant_id),
        network,
    )?
    .into_iter()
    .next()
    .ok_or_else(|| {
        not_found(format!(
            "no {what} of {amount} token units owned by the vault: is the leg funded?"
        ))
    })
}

/// The transaction lines of an IPST (spec/CLI.md, "The transaction lines"), less the `masses:`
/// line: v3 user text states no mass figure (spec/V3-ZK.md section 10); the mass note says in
/// words that a settle is heavy.
pub(crate) fn tx_lines(ipst: &IpstV3, kind: IpstKind, token_change: Option<u64>) -> Vec<String> {
    txview::lines(ipst.as_v1(), kind.into(), token_change)
        .into_iter()
        .filter(|l| !l.starts_with("masses: "))
        .collect()
}

fn finish(
    out: &mut dyn Write,
    mut lines: Vec<String>,
    ipst: &IpstV3,
    kind: IpstKind,
    token_change: Option<u64>,
    path: &Path,
) -> Result<(), CliError> {
    write_new(path, &ipst.to_json())?;
    lines.extend(tx_lines(ipst, kind, token_change));
    lines.push(format!("wrote: {}", path.display()));
    print(out, &lines)
}

/// The vaults of an existing trade, both legs, none for external cash's cash leg.
fn existing_vaults(terms: &ValidatedTermsV3) -> Result<[Option<VaultV3>; 2], CliError> {
    let mut out = [None, None];
    for leg in LegIndex::ALL {
        match VaultV3::instantiate_existing(terms, leg) {
            Ok(v) => out[usize::from(leg.index())] = Some(v),
            Err(ZkError::Template(impulse_core::template::TemplateError::NoVault { .. }))
                if leg == LegIndex::Cash => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

fn fund_build(ctx: &Ctx, a: ZkFundBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v3(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let creation = CreationContext::new(ctx.network, daa);
    terms.validate_creation(&creation)?;
    let t = &terms.terms().fields;
    check_kas_minimum(t)?;
    let vaults = fundable_vaults(&terms, &creation)?;
    let you = summary::check_party(t, &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&terms, daa);
    lines.push(you);
    let leg: LegIndex = a.leg.into();
    let by = crate::cli::funder(leg);
    if by != a.party.role {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "the {} leg is funded by the {}; you are the {}",
                leg_name(leg),
                by.name(),
                a.party.role.name()
            ),
        ));
    }
    let vault = vaults[usize::from(leg.index())]
        .as_ref()
        .ok_or_else(|| no_vault(leg))?;
    check_pinned(t)?;
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    let pay = pay(&a.pay, ctx.network)?;
    let my_key = hex_arg("my-key", &a.party.my_key)?;
    let mine = p2pk_address(&my_key, ctx.network);
    if pay.from != mine {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "--pay-from {} is not the P2PK address of --my-key ({mine}): a funding is signed by its depositor only, so it is paid from your own address",
                pay.from
            ),
        ));
    }
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let (ipst, kind, token_change) = match leg_terms.kind {
        LegKind::Kcc20(token) => {
            let templates = Templates::read(&a.templates)?;
            let template = templates.of(leg, &token)?;
            if a.token.is_empty() {
                return Err(not_found(format!(
                    "a KCC-20 leg is funded with your token UTXOs: pass --token <txid>:<index>:<amount> (held by {})",
                    hex(&my_key)
                )));
            }
            let mut tokens = Vec::with_capacity(a.token.len());
            for text in &a.token {
                let (outpoint, amount) = parse_token("--token", text)?;
                let state = Kcc20State::new(owner(IdentifierType::PubKey, my_key), amount);
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
            let held: u64 = tokens
                .iter()
                .fold(0u64, |s, t| s.saturating_add(t.state.amount));
            let deposit = Kcc20Deposit {
                tokens,
                carrier: a.carrier.unwrap_or(MIN_KCC20_OUTPUT),
                authorizer: a.authorizer.unwrap_or(MIN_KAS_OUTPUT),
            };
            let exclude: Vec<TransactionOutpoint> =
                deposit.tokens.iter().map(|t| t.utxo.outpoint).collect();
            let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &exclude)?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                zk::fund_kcc20(&terms, vault, template, &deposit, p, daa)
            })?;
            let change = held.checked_sub(leg_terms.amount).filter(|c| *c > 0);
            (ipst, IpstKind::FundKcc20(leg), change)
        }
        LegKind::Kas => {
            if !a.token.is_empty() || a.carrier.is_some() || a.authorizer.is_some() {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS cash leg is funded with KAS alone: --token, --carrier and --authorizer are for KCC-20 legs",
                ));
            }
            let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &[])?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                zk::fund_kas(&terms, vault, p, daa)
            })?;
            (ipst, IpstKind::FundKas, None)
        }
        LegKind::External => return Err(no_vault(leg)),
    };
    finish(out, lines, &ipst, kind, token_change, &a.out)
}

/// Reads and checks the proof file against this trade: it is a proof of the asset vault's
/// journal, made by the guest the template pins.
fn checked_proof(
    terms: &ValidatedTermsV3,
    vault: &VaultV3,
    path: &Path,
) -> Result<ProofBytes, CliError> {
    let file = parse_proof_file(&read_text(path)?)?;
    let expected = journal(
        &terms.terms().list_root,
        &vault.script_hash(),
        &terms.delivery_owner(),
    )?;
    if file.journal != expected {
        return Err(ZkError::ProofInvalid {
            reason: "the proof file's journal is not this trade's: it was made for another list root, vault or delivery owner (impulse zk prove-args prints the journal to expect)".into(),
        }
        .into());
    }
    let pinned = check_template()?.image_id();
    if file.image_id != pinned {
        return Err(ZkError::ImageIdMismatch {
            reason: format!(
                "the proof file's image id {} is not the one template v3 pins ({})",
                hex(&file.image_id),
                hex(&pinned)
            ),
        }
        .into());
    }
    Ok(file.proof)
}

fn settle_build(ctx: &Ctx, a: ZkSettleBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v3(ctx, &a.terms)?;
    let vaults = existing_vaults(&terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let t = &terms.terms().fields;
    let mut lines = terms_lines(&terms, daa);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    let pay = pay(&a.pay, ctx.network)?;
    let templates = Templates::read(&a.templates)?;
    let net = ctx.network;
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "the asset leg is not a KCC-20 token",
        ));
    };
    let asset_template = templates.of(LegIndex::Asset, &asset)?;
    let asset_vault = vaults[0]
        .as_ref()
        .ok_or_else(|| no_vault(LegIndex::Asset))?;
    if a.proof_cash.is_some() {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--proof-cash is for terms v4: only the asset vault of terms v3 checks a proof",
        ));
    }
    let proof_path = a.proof.as_ref().ok_or_else(|| {
        CliError::new(
            "ZK_PROOF_MALFORMED",
            "settle build for terms v3 needs --proof <the file impulse-zk-prove wrote>",
        )
    })?;
    let proof = checked_proof(&terms, asset_vault, proof_path)?;
    let asset_authorizer = authorizer(node.as_ref(), asset_vault, net, "asset authorizer")?;
    let asset_escrow = escrow(
        node.as_ref(),
        asset_vault,
        asset_template,
        &asset,
        t.asset_leg.amount,
        net,
        "asset escrow",
    )?;
    let mut used = vec![asset_authorizer.outpoint, asset_escrow.outpoint];
    let cash = match t.cash_leg.kind {
        LegKind::Kas => {
            let cash_vault = vaults[1].as_ref().ok_or_else(|| no_vault(LegIndex::Cash))?;
            let vault = utxos_with(node.as_ref(), &cash_vault.script_public_key(), None, net)?
                .into_iter()
                .find(|u| u.entry.amount == t.cash_leg.amount)
                .ok_or_else(|| {
                    not_found(format!(
                        "no UTXO of exactly {} sompi at the cash vault: is the leg funded?",
                        t.cash_leg.amount
                    ))
                })?;
            used.push(vault.outpoint);
            SettleCash::Kas { vault }
        }
        LegKind::Kcc20(cash) => {
            let cash_template = templates.of(LegIndex::Cash, &cash)?;
            let cash_vault = vaults[1].as_ref().ok_or_else(|| no_vault(LegIndex::Cash))?;
            let authorizer = authorizer(node.as_ref(), cash_vault, net, "cash authorizer")?;
            let escrow = escrow(
                node.as_ref(),
                cash_vault,
                cash_template,
                &cash,
                t.cash_leg.amount,
                net,
                "cash escrow",
            )?;
            used.extend([authorizer.outpoint, escrow.outpoint]);
            SettleCash::Kcc20 {
                authorizer,
                escrow,
                token: cash_template,
            }
        }
        LegKind::External => SettleCash::External,
    };
    let legs = SettleLegs {
        asset_authorizer,
        asset_escrow,
        asset_token: asset_template,
        cash,
    };
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        zk::settle(&terms, &legs, &proof, p, daa)
    })?;
    lines.push(MASS_NOTE.to_string());
    finish(out, lines, &ipst, IpstKind::Settle, None, &a.out)
}

fn refund_build(ctx: &Ctx, a: ZkRefundBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    if a.proof.is_some() {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "a refund of terms v3 needs no proof: --proof is for terms v4",
        ));
    }
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v3(ctx, &a.terms)?;
    let vaults = existing_vaults(&terms)?;
    let t = &terms.terms().fields;
    let leg: LegIndex = a.leg.into();
    let vault = vaults[usize::from(leg.index())]
        .as_ref()
        .ok_or_else(|| no_vault(leg))?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let mut lines = terms_lines(&terms, daa);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    let pay = pay(&a.pay, ctx.network)?;
    let net = ctx.network;
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
            let mut all = utxos_with(node.as_ref(), &vault.script_public_key(), None, net)?;
            match all.len() {
                0 => return Err(not_found(format!("no UTXO at the {} vault", leg_name(leg)))),
                1 => all.remove(0),
                _ => {
                    return Err(CliError::new(
                        "CLI_UTXO_AMBIGUOUS",
                        format!(
                            "the {} vault holds {} UTXOs; choose one with --vault-utxo: {}",
                            leg_name(leg),
                            all.len(),
                            all.iter()
                                .map(|u| format!(
                                    "{} ({} sompi)",
                                    crate::funds::outpoint_text(&u.outpoint),
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
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let templates = Templates::read(&a.templates)?;
    let escrowed = match leg_terms.kind {
        LegKind::Kas => {
            if a.without_token || a.token_amount.is_some() || a.token_minter {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS cash leg has no escrowed token: --without-token, --token-amount and --token-minter are for KCC-20 legs",
                ));
            }
            None
        }
        LegKind::Kcc20(_) if a.without_token => None,
        LegKind::Kcc20(token) => {
            let template = templates.of(leg, &token)?;
            let amount = a.token_amount.unwrap_or(leg_terms.amount);
            let state = Kcc20State {
                owner: owner(IdentifierType::ScriptHash, vault.script_hash()),
                amount,
                is_minter: a.token_minter,
            };
            let utxo = utxos_with(
                node.as_ref(),
                &template.script_public_key(&state)?,
                Some(token.covenant_id),
                net,
            )?
            .into_iter()
            .next()
            .ok_or_else(|| {
                not_found(format!(
                    "no escrowed token of {amount} units{} owned by the {} vault",
                    if a.token_minter { ", a minter," } else { "" },
                    leg_name(leg)
                ))
            })?;
            Some(RefundEscrow {
                utxo,
                amount,
                is_minter: a.token_minter,
                template,
            })
        }
        LegKind::External => return Err(no_vault(leg)),
    };
    let mut used = vec![vault_utxo.outpoint];
    used.extend(escrowed.iter().map(|e| e.utxo.outpoint));
    let signer: RefundSigner = a.signer.into();
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        zk::refund(&terms, leg, signer, &vault_utxo, escrowed.as_ref(), p)
    })?;
    if a.without_token {
        lines.push(format!(
            "note: the escrowed token stays owned by the {} vault; to get it back, fund a new authorizer (any KAS) at the vault's address and refund that one with the token",
            leg_name(leg)
        ));
    }
    let kind = IpstKind::Refund {
        leg,
        signer,
        with_token: escrowed.is_some(),
    };
    finish(out, lines, &ipst, kind, None, &a.out)
}
