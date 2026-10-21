// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `ipst sign`, `ipst merge`, `ipst raw` and `submit` (spec/CLI.md): every IPST the CLI is given
//! passes the terms check (`Ipst::verify_against_terms`) before it is signed, merged or
//! broadcast; `ipst raw` broadcasts nothing. Signing goes through `signing::sign` only.

use crate::build_cmd::{TemplateArgs, Templates};
use crate::cli::{self, connect, funder, hash_arg, print, CapArgs, Ctx, PartyArgs};
use crate::error::CliError;
use crate::funds::{address_script, p2pk_address, parse_change};
use crate::json::hex;
use crate::node::{self, Node};
use crate::signing::{self, SignRequest};
use crate::summary::{self, Role};
use crate::terms_file::{network_name, read_terms_file, read_text, write_new};
use crate::trade::{check_kas_minimum, check_pinned, leg_name, ExistingTrade, FundableTrade};
use crate::txview::{self, Kind};
use crate::value_cap::CapPolicy;
use clap::{Args, ValueEnum};
use impulse_core::locktime::check_tx_is_finalized;
use impulse_core::template::LegIndex;
use impulse_core::terms::{CreationContext, LegKind, Network, Terms};
use impulse_core::tx::{min_relay_fee, Ipst, IpstKind, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutput};
use std::io::Write;
use std::path::{Path, PathBuf};

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

/// The trade the signer agreed to: exactly one of the two.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct AgreedArgs {
    /// The terms file of the trade you agreed to: the IPST must be for exactly these terms.
    #[arg(long, value_name = "FILE")]
    pub terms: Option<PathBuf>,
    /// The terms hash of the trade you agreed to, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub terms_hash: Option<String>,
}

/// Who signs: a party, the authority, or a payer with no role in the terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignRole {
    /// The terms' buyer_key.
    Buyer,
    /// The terms' seller_key.
    Seller,
    /// The terms' authority_key.
    Authority,
    /// A key that is none of the terms' keys and only pays a fee.
    Payer,
}

impl SignRole {
    fn name(self) -> &'static str {
        match self {
            SignRole::Buyer => "buyer",
            SignRole::Seller => "seller",
            SignRole::Authority => "authority",
            SignRole::Payer => "payer",
        }
    }
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// The IPST to sign.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    #[command(flatten)]
    pub agreed: AgreedArgs,
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
    /// minimum relay fee, and only when you sign at most three fee inputs.
    #[arg(long, value_name = "SOMPI")]
    pub max_fee: Option<u64>,
    /// When you sign a fee input of a settle, refund or Direct transaction: the most KAS you
    /// accept to top up under-funded trade outputs with, in sompi; default 0.
    #[arg(long, value_name = "SOMPI")]
    pub max_topup: Option<u64>,
    /// A KCC-20 funding: the KAS on the escrowed token, which must equal the document's;
    /// default 200000000. A Direct trade: the most KAS your token may carry to the counterparty;
    /// default 200000000.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// A KCC-20 funding: the KAS on the authorizer, which must equal the document's; default
    /// 50000000.
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
    /// The fully signed IPST.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    #[command(flatten)]
    pub templates: TemplateArgs,
    /// Also write the signed transaction as the raw form in hex that `impulse-watch run
    /// --keep-signed` reads: created before anything is sent, removed if the submission is
    /// refused; must not exist.
    #[arg(long, value_name = "FILE")]
    pub signed_tx_out: Option<PathBuf>,
}

/// Reads an IPST file (spec/IPST.md, "Reading an IPST") on the command's network.
pub(crate) fn read_ipst(ctx: &Ctx, path: &Path) -> Result<Ipst, CliError> {
    let ipst = Ipst::from_json(&read_text(path)?)?;
    crate::token::refuse_mainnet_genesis(&ipst)?;
    let network = ipst.terms().terms().network;
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

/// What the terms check, or the cancellation check, found: the kind, the fee, and the output
/// after the trade outputs.
struct Checked {
    kind: Kind,
    fee: u64,
    change: Option<TransactionOutput>,
}

/// The terms check of an IPST, with the templates the user gave; for a token genesis the genesis
/// check, and for a Direct cancellation the cancellation check, in its place (spec/CLI.md, "Token
/// helper (testnet only)" and "direct cancel build").
fn terms_check(ipst: &Ipst, templates: &TemplateArgs, daa: u64) -> Result<Checked, CliError> {
    ExistingTrade::new(ipst.terms().clone())?;
    // A genesis also has Direct terms and a P2PK input 0, so it is told apart first.
    if crate::token::is_genesis(ipst) {
        let (fee, change) = crate::token::check(ipst, templates)?;
        return Ok(Checked {
            kind: Kind::Genesis,
            fee,
            change,
        });
    }
    if crate::cancel::is_candidate(ipst) {
        let (fee, change) = crate::cancel::check(ipst)?;
        return Ok(Checked {
            kind: Kind::Cancel(Role::Buyer),
            fee,
            change,
        });
    }
    let templates = Templates::read(templates)?;
    let (asset, cash) = templates.for_check(ipst.terms().terms())?;
    let checked = ipst.verify_against_terms(asset, cash, daa)?;
    Ok(Checked {
        kind: checked.kind.into(),
        fee: checked.fee,
        change: checked.change,
    })
}

/// A funding, or a token genesis: what the payer's inputs put into the trade outputs is a
/// deposit, not a top-up.
fn is_funding(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Built(IpstKind::FundKas | IpstKind::FundKcc20(_)) | Kind::Genesis
    )
}

/// The IPST is for the terms the signer agreed to (`CLI_IPST_TERMS_NOT_AGREED`).
fn check_agreed(a: &AgreedArgs, terms_hash: &[u8; 32]) -> Result<(), CliError> {
    check_agreed_as(a, terms_hash, "CLI_IPST_TERMS_NOT_AGREED")
}

/// The same check under the caller's refusal code (`impulse frost sign` uses its own family).
pub(crate) fn check_agreed_as(
    a: &AgreedArgs,
    terms_hash: &[u8; 32],
    code: &'static str,
) -> Result<(), CliError> {
    let agreed = match (&a.terms, &a.terms_hash) {
        (Some(path), _) => read_terms_file(path)?.terms_hash(),
        (None, Some(h)) => hash_arg("terms-hash", h)?,
        (None, None) => {
            return Err(CliError::new(
                code,
                "name the trade you agreed to: pass --terms <file> or --terms-hash <hex>",
            ))
        }
    };
    if agreed != *terms_hash {
        return Err(CliError::new(
            code,
            format!(
                "the IPST is for terms {}, not the terms you agreed to ({}); do not sign it",
                hex(terms_hash),
                hex(&agreed)
            ),
        ));
    }
    Ok(())
}

/// The signer's role check: `--my-key` is the role's key, and a party's own destinations pay it
/// or equal its pins (spec/CLI.md, "Terms summary and role check"). Returns the `you:` line.
fn check_signer(
    t: &Terms,
    network: Network,
    a: &SignArgs,
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

/// A funding: signed by its leg's depositor only, its terms still fundable at `daa`, the two
/// "Before funding" checks, and a KCC-20 deposit's carrier and authorizer as the signer states
/// them (`CLI_IPST_DEPOSIT_MISMATCH`).
fn check_funding(
    ctx: &Ctx,
    a: &SignArgs,
    ipst: &Ipst,
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
    let t = ipst.terms().terms();
    FundableTrade::new(
        ipst.terms().clone(),
        &CreationContext::new(ctx.network, daa),
    )?;
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

/// The most fee inputs of the signer the default fee limit covers (spec/CLI.md, "ipst sign",
/// step 9): the minimum relay fee grows with every input, and the document's builder chose them.
const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;

/// Every check of `ipst sign`, then the signatures (spec/CLI.md, "ipst sign").
pub(crate) fn sign(ctx: &Ctx, a: SignArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let mut ipst = read_ipst(ctx, &a.ipst)?;
    let my_key = hash_arg("my-key", &a.my_key)?;
    check_agreed(&a.agreed, &ipst.terms().terms_hash())?;
    // The escrowed legs instantiate before anything else is read.
    ExistingTrade::new(ipst.terms().clone())?;
    let t = ipst.terms().terms().clone();
    let you = check_signer(&t, ctx.network, &a, my_key)?;
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&ipst, &a.templates, daa)?;
    let kind = checked.kind;
    if a.authorizer.is_some() && !matches!(kind, Kind::Built(IpstKind::FundKcc20(_)))
        || a.carrier.is_some()
            && !matches!(
                kind,
                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct) | Kind::Genesis
            )
    {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--carrier and --authorizer confirm a KCC-20 funding's deposit, --carrier the KAS your token carries in a Direct trade or the KAS on a token genesis' new token",
        ));
    }
    if kind == Kind::Genesis {
        crate::token::confirm_carrier(&ipst, a.carrier)?;
    }
    if let Kind::Built(built) = kind {
        if is_funding(kind) {
            check_funding(ctx, &a, &ipst, built, daa)?;
        }
    }
    let policy = CapPolicy::new(ctx.env.max_value, a.cap.i_accept_the_risk)?;
    let cap_line = if kind == Kind::Genesis {
        crate::token::cap_line(&policy)
    } else {
        policy.check(&t, a.cap.kas_equivalent)?
    };
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
    let first_fee_input = txview::trade_inputs(kind, &ipst);
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
        let topup = txview::payer_cost(kind, &ipst);
        if !is_funding(kind) && topup > max_topup {
            return Err(CliError::new(
                "CLI_IPST_TOPUP_TOO_HIGH",
                format!(
                    "you sign a fee input, and the fee inputs also put {topup} sompi into trade outputs (under-funded carriers or authorizers topped up), above {max_topup}; pass --max-topup to accept more"
                ),
            ));
        }
    }
    let committed = outflow(&a, &ipst, kind, my_key, &expected_change);
    let mut outflow_line = None;
    if let Some((outflow, expected)) = committed {
        // The fee and a top-up come out of the fee inputs only.
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
    let mut lines = if kind == Kind::Genesis {
        crate::token::summary(ipst.terms())
    } else {
        summary::summary(&ipst.terms().terms_hash(), &t, daa)
    };
    lines.push(you);
    lines.push(cap_line);
    lines.extend(txview::lines(&ipst, kind, None));
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
/// except the vault inputs of a settle or refund), less what comes back to it (the change, when
/// it pays `expected_change`, and a funding's token change); and what the trade itself takes from
/// it (a funding's deposit, the KAS cash or the token carrier of a Direct trade). None when the
/// signer signs none of its own funds.
fn outflow(
    a: &SignArgs,
    ipst: &Ipst,
    kind: Kind,
    my_key: [u8; 32],
    expected_change: &ScriptPublicKey,
) -> Option<(u64, u64)> {
    let t = ipst.terms().terms();
    let n_in = txview::trade_inputs(kind, ipst);
    let n_out = txview::trade_outputs(kind, ipst);
    let vault_inputs = match kind {
        Kind::Built(IpstKind::Settle | IpstKind::Refund { .. }) => n_in,
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
    let carrier = a.carrier.unwrap_or(MIN_KCC20_OUTPUT);
    let kind = match kind {
        Kind::Built(kind) => kind,
        // The genesis check fixed the inputs as the signer's; the token output holds --carrier,
        // which the signer confirmed.
        Kind::Genesis => return Some((held.saturating_sub(back), carrier)),
        Kind::Cancel(_) => {
            // Output 0 sends the Direct input home to its own script, which the cancellation
            // check fixed as input 0's; it comes back to a signer of input 0. The trade takes
            // nothing.
            if own.contains(&0)
                && outputs[0].script_public_key == ipst.entries()[0].script_public_key
            {
                back = back.saturating_add(outputs[0].value);
            }
            return Some((held.saturating_sub(back), 0));
        }
    };
    let expected = match kind {
        IpstKind::FundKas => t.cash_leg.amount,
        IpstKind::FundKcc20(_) => {
            if n_out == 3 && own.contains(&0) {
                back = back.saturating_add(outputs[2].value);
            }
            outputs[0].value.saturating_add(outputs[1].value)
        }
        IpstKind::Direct => own
            .iter()
            .filter(|&&i| i < n_in)
            .map(|&i| match (i, t.cash_leg.kind) {
                (1, LegKind::Kas) => t.cash_leg.amount,
                _ => carrier,
            })
            .fold(0u64, u64::saturating_add),
        IpstKind::Settle | IpstKind::Refund { .. } => 0,
    };
    Some((held.saturating_sub(back), expected))
}

pub(crate) fn merge(ctx: &Ctx, a: MergeArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let mut merged = read_ipst(ctx, &a.ipsts[0])?;
    for path in &a.ipsts[1..] {
        merged = merged.combine(&read_ipst(ctx, path)?)?;
    }
    let daa = current_daa(ctx, &a.daa)?;
    let checked = terms_check(&merged, &a.templates, daa)?;
    write_new(&a.out, &merged.to_json())?;
    let mut lines = txview::lines(&merged, checked.kind, None);
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

pub(crate) fn submit(ctx: &Ctx, a: SubmitArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    // The file is created before anything is read or submitted, so a path that cannot take it
    // refuses with nothing sent; it is removed again on any refusal below.
    let mut file = match &a.signed_tx_out {
        Some(path) => Some(SignedTxFile::create(path)?),
        None => None,
    };
    let ipst = read_ipst(ctx, &a.ipst)?;
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
    // A broadcast cannot be undone: the file is complete before the node sees the transaction.
    if let Some(f) = &mut file {
        f.write(&signed_tx_text(&tx))?;
    }
    let submitted = node::submit(node.as_ref(), &tx, ctx.network).map_err(|e| match &file {
        Some(f) => CliError::new(
            e.code(),
            format!(
                "{}; {} is removed. If the node took the transaction all the same, impulse status shows {} accepted: then write the file with impulse ipst raw",
                e.detail(),
                f.path.display(),
                hex(&tx.id().as_bytes())
            ),
        ),
        None => e,
    })?;
    let mut lines = txview::lines(&ipst, checked.kind, None);
    lines.push(format!("from_block: {}", hex(&submitted.from_block)));
    lines.push(format!("submitted: {}", hex(&submitted.txid)));
    if let Some(f) = &mut file {
        f.keep = true;
        lines.push(format!("signed_tx: {}", f.path.display()));
    }
    print(out, &lines)
}

/// `submit --signed-tx-out` (spec/CLI.md, "submit", "Signed-transaction file"): created as a new
/// file, a symbolic link never followed, before anything else; written before the submission;
/// removed when dropped unless the node took the transaction.
pub(crate) struct SignedTxFile {
    pub(crate) path: PathBuf,
    file: Option<std::fs::File>,
    pub(crate) keep: bool,
}

#[cfg(test)]
thread_local! {
    /// Test hook: the next write of a signed-transaction file fails, as a full disk would.
    pub(crate) static FAIL_SIGNED_TX_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl SignedTxFile {
    pub(crate) fn create(path: &Path) -> Result<Self, CliError> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    CliError::new("CLI_OUTPUT_EXISTS", format!("{} exists", path.display()))
                } else {
                    CliError::new(
                        "CLI_FILE_WRITE",
                        format!("{}: {e}; nothing was submitted", path.display()),
                    )
                }
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            keep: false,
        })
    }

    pub(crate) fn write(&mut self, text: &str) -> Result<(), CliError> {
        let fail = |e: std::io::Error| {
            CliError::new(
                "CLI_FILE_WRITE",
                format!("{}: {e}; nothing was submitted", self.path.display()),
            )
        };
        #[cfg(test)]
        if FAIL_SIGNED_TX_WRITE.with(|f| f.replace(false)) {
            // A handle that cannot write, so the write below fails as on a full disk.
            self.file = Some(std::fs::File::open(&self.path).map_err(fail)?);
        }
        let file = self.file.as_mut().expect("the file is open until dropped");
        file.write_all(text.as_bytes()).map_err(fail)?;
        file.sync_all().map_err(fail)
    }
}

impl Drop for SignedTxFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.keep {
            // Only the file this command created is removed.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Args, Debug)]
pub struct RawArgs {
    /// The fully signed IPST.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// Where to write the signed transaction, the file impulse-watch run --keep-signed reads;
    /// must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// `impulse ipst raw` (spec/CLI.md, "ipst raw"): the signed-transaction file of a fully signed
/// IPST, offline.
pub(crate) fn raw(ctx: &Ctx, a: RawArgs, out: &mut dyn Write) -> Result<(), CliError> {
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

/// The signed-transaction file (spec/CLI.md, "submit"): the raw form of spec/VERIFY.md, the
/// borsh encoding that carries the transaction ID last, as lowercase hex and one line feed, the
/// form `impulse-watch run --keep-signed` reads.
pub(crate) fn signed_tx_text(tx: &kaspa_consensus_core::tx::Transaction) -> String {
    format!("{}\n", hex(&impulse_core::decode::encode_raw(tx)))
}
