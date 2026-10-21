// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `fund build`, `settle build` and `refund build` (spec/CLI.md, "Building, signing and
//! submitting"): find the UTXOs on the user's node, run the checks, build with impulse-core's
//! builders and write the unsigned IPST. Keyless: nothing here reads or holds a key.

use crate::cli::{cap, connect, funder, hash_arg, print, reviewed, CapArgs, Ctx, PartyArgs};
use crate::error::CliError;
use crate::funds::{
    address_script, build_with_fee, fee_candidates, outpoint_text, p2pk_address, parse_change,
    parse_outpoint, parse_pay_from, parse_token, utxo_at, utxos_with,
};
use crate::json::hex;
use crate::node::{self, Node};
use crate::summary;
use crate::terms_file::{network_name, read_terms_file, read_text, write_new};
use crate::trade::{check_kas_minimum, check_pinned, leg_name, ExistingTrade, FundableTrade};
use crate::txview;
use clap::{Args, ValueEnum};
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{
    CreationContext, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network, SettlementMode,
    Terms, ValidatedTerms,
};
use impulse_core::tx::{
    direct, fund_kas, fund_kcc20, refund, settle, DirectCash, DirectLegs, Ipst, IpstKind,
    Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, RefundSigner, SettleCash, SettleLegs,
    TokenUtxo, Utxo, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use std::io::Write;
use std::path::PathBuf;

/// A trade leg on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LegArg {
    Asset,
    Cash,
}

impl From<LegArg> for LegIndex {
    fn from(l: LegArg) -> Self {
        match l {
            LegArg::Asset => LegIndex::Asset,
            LegArg::Cash => LegIndex::Cash,
        }
    }
}

/// Who signs a refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignerArg {
    /// The leg's depositor: the seller for the asset leg, the buyer for the cash leg.
    Depositor,
    /// The other party.
    Counterparty,
    /// The settlement authority.
    Authority,
}

impl From<SignerArg> for RefundSigner {
    fn from(s: SignerArg) -> Self {
        match s {
            SignerArg::Depositor => RefundSigner::Depositor,
            SignerArg::Counterparty => RefundSigner::Counterparty,
            SignerArg::Authority => RefundSigner::Authority,
        }
    }
}

/// Who pays the fee, where the change goes, and the fee.
#[derive(Args, Debug)]
pub struct PayArgs {
    /// P2PK address whose UTXOs pay the fee, and when funding the deposit.
    #[arg(long, value_name = "ADDRESS")]
    pub pay_from: String,
    /// Where the change goes; default --pay-from.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// The exact fee in sompi; default the transaction's minimum relay fee.
    #[arg(long, value_name = "SOMPI")]
    pub fee: Option<u64>,
}

/// The legs' KCC-20 token artifacts (silverc JSON).
#[derive(Args, Debug, Default)]
pub struct TemplateArgs {
    /// The asset token's silverc artifact.
    #[arg(long, value_name = "FILE")]
    pub asset_template: Option<PathBuf>,
    /// The KCC-20 cash token's silverc artifact.
    #[arg(long, value_name = "FILE")]
    pub cash_template: Option<PathBuf>,
}

/// The templates the user gave, read and parsed.
pub struct Templates {
    asset: Option<Kcc20Template>,
    cash: Option<Kcc20Template>,
}

fn read_template(path: &Option<PathBuf>) -> Result<Option<Kcc20Template>, CliError> {
    path.as_ref()
        .map(|p| Ok(Kcc20Template::from_json(&read_text(p)?)?))
        .transpose()
}

impl Templates {
    pub fn read(args: &TemplateArgs) -> Result<Self, CliError> {
        Ok(Self {
            asset: read_template(&args.asset_template)?,
            cash: read_template(&args.cash_template)?,
        })
    }

    /// The template of `leg`, which must be the one the terms name (`TX_TOKEN_TEMPLATE`);
    /// missing is `CLI_TEMPLATE_MISSING`.
    pub fn of(&self, leg: LegIndex, token: &Kcc20Token) -> Result<&Kcc20Template, CliError> {
        let (given, flag) = match leg {
            LegIndex::Asset => (&self.asset, "--asset-template"),
            LegIndex::Cash => (&self.cash, "--cash-template"),
        };
        let template = given.as_ref().ok_or_else(|| {
            CliError::new(
                "CLI_TEMPLATE_MISSING",
                format!(
                    "the {} leg is a KCC-20 token: pass {flag} <silverc artifact>",
                    leg_name(leg)
                ),
            )
        })?;
        template.check_token(token)?;
        Ok(template)
    }

    /// The templates the terms check needs: always the asset's, and the cash's for KCC-20 cash.
    pub fn for_check(
        &self,
        t: &Terms,
    ) -> Result<(&Kcc20Template, Option<&Kcc20Template>), CliError> {
        let LegKind::Kcc20(asset) = t.asset_leg.kind else {
            return Err(CliError::new(
                "TX_WRONG_MODE",
                "the asset leg is not a KCC-20 token",
            ));
        };
        let asset = self.of(LegIndex::Asset, &asset)?;
        let cash = match t.cash_leg.kind {
            LegKind::Kcc20(cash) => Some(self.of(LegIndex::Cash, &cash)?),
            _ => None,
        };
        Ok((asset, cash))
    }
}

#[derive(Args, Debug)]
pub struct FundBuildArgs {
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
    /// A KCC-20 leg: KAS on the escrowed token output; default the minimum, 200000000.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 leg: KAS on the authorizer at the vault; default the minimum, 50000000.
    #[arg(long, value_name = "SOMPI")]
    pub authorizer: Option<u64>,
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct SettleBuildArgs {
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
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct RefundBuildArgs {
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
    #[command(flatten)]
    pub cap: CapArgs,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

fn leg_of(t: &Terms, leg: LegIndex) -> &Leg {
    match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    }
}

fn not_found(what: String) -> CliError {
    CliError::new("CLI_UTXO_NOT_FOUND", what)
}

fn no_vault(t: &ValidatedTerms, leg: LegIndex) -> CliError {
    let why = if t.terms().settlement_mode == SettlementMode::Direct {
        "Direct terms escrow nothing"
    } else {
        "external cash has no vault (no builder recovers a stray deposit there, owner decision D14)"
    };
    CliError::new(
        "TEMPLATE_NO_VAULT",
        format!("the {} leg has no vault: {why}", leg_name(leg)),
    )
}

/// The terms an existing-trade command acts on: the command's network, every escrowed leg a
/// vault.
pub(crate) fn existing(ctx: &Ctx, path: &std::path::Path) -> Result<ExistingTrade, CliError> {
    let terms = read_terms_file(path)?;
    if terms.terms().network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the terms are for {}; pass --network {0} to act on them",
                network_name(terms.terms().network)
            ),
        ));
    }
    ExistingTrade::new(terms)
}

/// A checked node and its virtual DAA score.
pub(crate) fn node_now(ctx: &Ctx, url: &str) -> Result<(Box<dyn Node>, u64), CliError> {
    node::check_transport(url, ctx.network)?;
    let node = connect(ctx, url, ctx.network)?;
    let daa = node::creation_daa(node.as_ref(), ctx.network)?;
    Ok((node, daa))
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

/// The UTXO at a vault without a covenant ID holding the most KAS, equal amounts by outpoint.
fn authorizer(
    node: &dyn Node,
    vault: &Vault,
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
    vault: &Vault,
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

/// A token UTXO held by a public key, exactly `amount`, not a minter.
fn held_token(
    node: &dyn Node,
    key: [u8; 32],
    template: &Kcc20Template,
    token: &Kcc20Token,
    amount: u64,
    network: Network,
    what: &str,
) -> Result<TokenUtxo, CliError> {
    let state = Kcc20State::new(owner(IdentifierType::PubKey, key), amount);
    let utxo = utxos_with(
        node,
        &template.script_public_key(&state)?,
        Some(token.covenant_id),
        network,
    )?
    .into_iter()
    .next()
    .ok_or_else(|| {
        not_found(format!(
            "{what}: no token UTXO of exactly {amount} units held by {}",
            hex(&key)
        ))
    })?;
    Ok(TokenUtxo { utxo, state })
}

fn finish(
    out: &mut dyn Write,
    mut lines: Vec<String>,
    ipst: &Ipst,
    kind: IpstKind,
    token_change: Option<u64>,
    path: &std::path::Path,
) -> Result<(), CliError> {
    write_new(path, &ipst.to_json())?;
    lines.extend(txview::lines(ipst, kind.into(), token_change));
    lines.push(format!("wrote: {}", path.display()));
    print(out, &lines)
}

pub(crate) fn fund_build(ctx: &Ctx, a: FundBuildArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let terms = read_terms_file(&a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let creation = CreationContext::new(ctx.network, daa);
    let trade = FundableTrade::new(terms, &creation)?;
    let t = trade.terms().terms();
    check_kas_minimum(t)?;
    let mut lines = reviewed(&trade, &creation, &a.party)?;
    let leg: LegIndex = a.leg.into();
    let by = funder(leg);
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
    let vault = trade
        .vault(leg)
        .ok_or_else(|| no_vault(trade.terms(), leg))?;
    check_pinned(t)?;
    lines.push(cap(ctx, &a.cap, trade.terms())?);
    let pay = pay(&a.pay, ctx.network)?;
    let my_key = hash_arg("my-key", &a.party.my_key)?;
    // ipst sign lets only a funding's depositor sign it, so the depositor pays its fee.
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
    let leg_terms = leg_of(t, leg);
    let templates = Templates::read(&a.templates)?;
    let (ipst, kind, token_change) = match leg_terms.kind {
        LegKind::Kcc20(token) => {
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
                fund_kcc20(trade.terms(), vault, template, &deposit, p, daa)
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
                fund_kas(trade.terms(), vault, p, daa)
            })?;
            (ipst, IpstKind::FundKas, None)
        }
        LegKind::External => return Err(no_vault(trade.terms(), leg)),
    };
    finish(out, lines, &ipst, kind, token_change, &a.out)
}

pub(crate) fn settle_build(
    ctx: &Ctx,
    a: SettleBuildArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let trade = existing(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let terms = trade.terms();
    let t = terms.terms();
    let mut lines = summary::summary(&terms.terms_hash(), t, daa);
    lines.push(cap(ctx, &a.cap, terms)?);
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
    let (ipst, kind) = match t.settlement_mode {
        SettlementMode::Vault => {
            let asset_vault = trade
                .vault(LegIndex::Asset)
                .ok_or_else(|| no_vault(terms, LegIndex::Asset))?;
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
                    let cash_vault = trade
                        .vault(LegIndex::Cash)
                        .ok_or_else(|| no_vault(terms, LegIndex::Cash))?;
                    let vault =
                        utxos_with(node.as_ref(), &cash_vault.script_public_key(), None, net)?
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
                    let cash_vault = trade
                        .vault(LegIndex::Cash)
                        .ok_or_else(|| no_vault(terms, LegIndex::Cash))?;
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
                settle(terms, &legs, p, daa)
            })?;
            (ipst, IpstKind::Settle)
        }
        SettlementMode::Direct => {
            let seller = held_token(
                node.as_ref(),
                t.seller_key,
                asset_template,
                &asset,
                t.asset_leg.amount,
                net,
                "the seller's asset",
            )?;
            let mut used = vec![seller.utxo.outpoint];
            let cash = match t.cash_leg.kind {
                LegKind::Kas => {
                    let spk = address_script(&p2pk_address(&t.buyer_key, net));
                    let utxo = utxos_with(node.as_ref(), &spk, None, net)?
                        .into_iter()
                        .find(|u| u.entry.amount == t.cash_leg.amount)
                        .ok_or_else(|| {
                            not_found(format!(
                                "the buyer's cash: no UTXO of exactly {} sompi at {}",
                                t.cash_leg.amount,
                                p2pk_address(&t.buyer_key, net)
                            ))
                        })?;
                    used.push(utxo.outpoint);
                    DirectCash::Kas(utxo)
                }
                LegKind::Kcc20(cash) => {
                    let template = templates.of(LegIndex::Cash, &cash)?;
                    let token = held_token(
                        node.as_ref(),
                        t.buyer_key,
                        template,
                        &cash,
                        t.cash_leg.amount,
                        net,
                        "the buyer's cash",
                    )?;
                    used.push(token.utxo.outpoint);
                    DirectCash::Kcc20 { token, template }
                }
                LegKind::External => {
                    return Err(CliError::new(
                        "TX_WRONG_MODE",
                        "Direct terms have no external cash",
                    ))
                }
            };
            let legs = DirectLegs {
                asset: seller,
                asset_token: asset_template,
                cash,
            };
            let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                direct(terms, &legs, p, daa)
            })?;
            (ipst, IpstKind::Direct)
        }
    };
    finish(out, lines, &ipst, kind, None, &a.out)
}

pub(crate) fn refund_build(
    ctx: &Ctx,
    a: RefundBuildArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let trade = existing(ctx, &a.terms)?;
    let terms = trade.terms();
    let t = terms.terms();
    let leg: LegIndex = a.leg.into();
    let vault = trade.vault(leg).ok_or_else(|| no_vault(terms, leg))?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let mut lines = summary::summary(&terms.terms_hash(), t, daa);
    lines.push(cap(ctx, &a.cap, terms)?);
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
    let leg_terms = leg_of(t, leg);
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
        LegKind::External => return Err(no_vault(terms, leg)),
    };
    let mut used = vec![vault_utxo.outpoint];
    used.extend(escrowed.iter().map(|e| e.utxo.outpoint));
    let signer: RefundSigner = a.signer.into();
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        refund(terms, leg, signer, &vault_utxo, escrowed.as_ref(), p)
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
