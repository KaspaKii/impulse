// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! From the UTXOs a node reports to the builders' inputs (I11 phase 2): which addresses to ask the
//! node about for a settle, a refund or a Direct trade, and which UTXOs of its answer each input
//! of the builder is. The page does neither: it passes the text of the node's reply to the
//! `...FromReply` function, and gets back an IPST that the builder made, or a refusal.
//!
//! The choice of a UTXO is a rule, not a guess, and every choice is shown to the signer in the
//! review (`review.rs`) as an input with its outpoint and amount:
//!
//! - a vault's authorizer or a stray vault UTXO to refund: among the plain UTXOs (no covenant) at
//!   the vault's scriptPublicKey, the one with the largest amount, ties to the lowest outpoint;
//! - an escrowed token: among the UTXOs at the scriptPublicKey of the token in the exact state the
//!   leg needs (owner the vault's script hash, the leg amount, not a minter) and the leg's
//!   covenant, the lowest outpoint;
//! - a KAS cash vault UTXO of a settle, and a Direct trade's KAS cash: exactly the leg amount,
//!   lowest outpoint;
//! - a Direct trade's tokens: the token of the party's key in the exact state, lowest outpoint;
//! - fee inputs: the fee payer's own plain P2PK UTXOs that no leg uses, the largest first, until
//!   they cover the fee and the change is zero or at least the minimum;
//! - the buyer's funding of a KAS cash vault: the same, but the inputs also cover the deposit (the
//!   cash amount), so they cover the fee and the deposit, and the change is zero or at least the
//!   minimum. It is built only when the node's reply shows the seller's asset leg funded and the
//!   cash vault not yet funded (`check_node_state`), and only for a pinned KCC-20 template
//!   (`funding::check_pinned`).
//!
//! A UTXO that is not there is `SDK_UTXO_NOT_FOUND`; the builders then check what they are given
//! (`TX_*`). A fee of `"auto"` is the minimum relay fee of the transaction's mass and 10% more,
//! found by building until the builder accepts the fee (`TX_FEE_TOO_LOW` states its minimum).

use crate::error::{Failure, SdkError};
use crate::forms;
use crate::funding;
use crate::json::{hex, network_name, Obj};
use crate::ops;
use crate::review::{address_of, p2pk, token_spk};
use crate::role;
use crate::rpc;
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{IdentifierType, Kcc20Owner, LegKind, ValidatedTerms};
use impulse_core::tx::{self, Ipst, Kcc20Template, TxError, Utxo};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_consensus_core::Hash;
use serde_json::{json, Value};

/// The fee payer, the fee and where the change goes.
pub(crate) struct Funding {
    pub payer: [u8; 32],
    /// None: the minimum relay fee and 10% more.
    pub fee: Option<u64>,
    /// Where the fee payer's change goes, as an address; None: back to the payer's own key. A
    /// payer whose key lives only in a wallet of the page should name an address it controls
    /// elsewhere (the CLI's `--change`).
    pub change: Option<String>,
}

/// `{ payer: Hex, fee: U64String | "auto", change?: Address | null }`.
pub(crate) fn funding_from_json(value: &Value) -> Result<Funding, SdkError> {
    let mut o = Obj::new(value, "funding")?;
    let payer = o.bytes32("payer")?;
    let fee = match o.value("fee")? {
        Value::String(s) if s == "auto" => None,
        Value::String(s) => match crate::json::decimal_u64(s) {
            Some(n) => Some(n),
            None => return o.fail("fee", "expected \"auto\" or a u64 as a decimal string"),
        },
        _ => return o.fail("fee", "expected \"auto\" or a u64 as a decimal string"),
    };
    let change = match o.optional("change") {
        None | Some(Value::Null) => None,
        Some(_) => Some(o.str("change")?.to_string()),
    };
    o.finish()?;
    Ok(Funding { payer, fee, change })
}

/// The scriptPublicKey the fee payer's change pays: the address given, else the payer's own key.
fn change_spk(funding: &Funding, terms: &ValidatedTerms) -> Result<ScriptPublicKey, Failure> {
    match &funding.change {
        None => Ok(p2pk(&funding.payer)),
        Some(text) => Ok(role::change_spk(
            "funding.change",
            text,
            terms.terms().network,
        )?),
    }
}

pub(crate) fn utxo_to_json(u: &Utxo) -> Value {
    json!({
        "transaction_id": hex(&u.outpoint.transaction_id.as_bytes()),
        "index": u.outpoint.index,
        "amount": u.entry.amount.to_string(),
        "script_public_key": ops::spk_json(&u.entry.script_public_key),
        "block_daa_score": u.entry.block_daa_score.to_string(),
        "is_coinbase": u.entry.is_coinbase,
        "covenant_id": u.entry.covenant_id.map(|c| hex(&c.as_bytes())),
    })
}

fn key(u: &Utxo) -> ([u8; 32], u32) {
    (u.outpoint.transaction_id.as_bytes(), u.outpoint.index)
}

/// The pool without repeated outpoints (two addresses of one query can name one UTXO twice).
fn dedupe(utxos: Vec<Utxo>) -> Vec<Utxo> {
    let mut seen = std::collections::BTreeSet::new();
    utxos.into_iter().filter(|u| seen.insert(key(u))).collect()
}

fn at<'p>(pool: &'p [Utxo], spk: &ScriptPublicKey, covenant: Option<Hash>) -> Vec<&'p Utxo> {
    pool.iter()
        .filter(|u| &u.entry.script_public_key == spk && u.entry.covenant_id == covenant)
        .collect()
}

fn largest<'a>(c: impl IntoIterator<Item = &'a Utxo>) -> Option<&'a Utxo> {
    c.into_iter().max_by(|a, b| {
        (a.entry.amount, std::cmp::Reverse(key(a)))
            .cmp(&(b.entry.amount, std::cmp::Reverse(key(b))))
    })
}

fn lowest<'a>(c: impl IntoIterator<Item = &'a Utxo>) -> Option<&'a Utxo> {
    c.into_iter().min_by_key(|u| key(u))
}

fn not_found(what: impl Into<String>) -> Failure {
    SdkError::UtxoNotFound { what: what.into() }.into()
}

fn artifact_text<'a>(artifacts: &'a Value, which: &'static str) -> Result<&'a str, SdkError> {
    artifacts.get(which).and_then(Value::as_str).ok_or_else(|| {
        SdkError::json(
            format!("artifacts.{which}"),
            "the token's artifact text is needed",
        )
    })
}

fn vault_of(terms: &ValidatedTerms, leg: LegIndex) -> Result<Vault, Failure> {
    Ok(Vault::instantiate_existing(terms, leg)?)
}

fn legs_of(terms: &ValidatedTerms) -> [(LegIndex, &'static str, &impulse_core::terms::Leg); 2] {
    let t = terms.terms();
    [
        (LegIndex::Asset, "asset", &t.asset_leg),
        (LegIndex::Cash, "cash", &t.cash_leg),
    ]
}

fn covenant_of(leg: &impulse_core::terms::Leg) -> Option<Hash> {
    match leg.kind {
        LegKind::Kcc20(token) => Some(Hash::from_bytes(token.covenant_id)),
        _ => None,
    }
}

fn script_hash_owner(vault: &Vault) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

fn pubkey_owner(key: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: key,
    }
}

fn template_for<'a>(
    terms: &ValidatedTerms,
    leg: LegIndex,
    templates: &'a (Kcc20Template, Option<Kcc20Template>),
) -> Result<&'a Kcc20Template, Failure> {
    let _ = terms;
    match leg {
        LegIndex::Asset => Ok(&templates.0),
        LegIndex::Cash => templates.1.as_ref().ok_or_else(|| {
            SdkError::json("artifacts.cash", "the cash token's artifact text is needed").into()
        }),
    }
}

fn addr(terms: &ValidatedTerms, spk: &ScriptPublicKey) -> Result<String, Failure> {
    address_of(terms.terms().network, spk)
        .ok_or_else(|| SdkError::json("address", "a scriptPublicKey with no address").into())
}

// Addresses to ask the node about.

fn finish_addresses(
    terms: &ValidatedTerms,
    mut spks: Vec<ScriptPublicKey>,
    payer: &[u8; 32],
) -> Result<Vec<String>, Failure> {
    spks.push(p2pk(payer));
    let mut out: Vec<String> = Vec::new();
    for spk in spks {
        let a = addr(terms, &spk)?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    Ok(out)
}

/// The addresses a settle needs the UTXOs of: each leg's vault, each KCC-20 leg's escrow, and the
/// fee payer.
pub(crate) fn settle_addresses(
    terms: &ValidatedTerms,
    artifacts: &Value,
    payer: &[u8; 32],
) -> Result<Vec<String>, Failure> {
    let templates = forms::artifacts(artifacts)?;
    let mut spks = Vec::new();
    for (leg, _, terms_leg) in legs_of(terms) {
        if matches!(terms_leg.kind, LegKind::External) {
            continue;
        }
        let vault = vault_of(terms, leg)?;
        spks.push(vault.script_public_key());
        if matches!(terms_leg.kind, LegKind::Kcc20(_)) {
            let template = template_for(terms, leg, &templates)?;
            spks.extend(token_spk(
                template,
                script_hash_owner(&vault),
                terms_leg.amount,
            ));
        }
    }
    finish_addresses(terms, spks, payer)
}

/// The addresses a refund of `leg` needs: its vault, its escrow if the leg is KCC-20, the payer.
pub(crate) fn refund_addresses(
    terms: &ValidatedTerms,
    leg: LegIndex,
    artifacts: &Value,
    payer: &[u8; 32],
) -> Result<Vec<String>, Failure> {
    let templates = forms::artifacts(artifacts)?;
    let (_, _, terms_leg) = legs_of(terms)[leg.index() as usize];
    let vault = vault_of(terms, leg)?;
    let mut spks = vec![vault.script_public_key()];
    if matches!(terms_leg.kind, LegKind::Kcc20(_)) {
        let template = template_for(terms, leg, &templates)?;
        spks.extend(token_spk(
            template,
            script_hash_owner(&vault),
            terms_leg.amount,
        ));
    }
    finish_addresses(terms, spks, payer)
}

/// The addresses a Direct trade needs: the seller's token, the buyer's cash, the payer.
pub(crate) fn direct_addresses(
    terms: &ValidatedTerms,
    artifacts: &Value,
    payer: &[u8; 32],
) -> Result<Vec<String>, Failure> {
    let templates = forms::artifacts(artifacts)?;
    let t = terms.terms();
    let mut spks = Vec::new();
    spks.extend(token_spk(
        &templates.0,
        pubkey_owner(t.seller_key),
        t.asset_leg.amount,
    ));
    match t.cash_leg.kind {
        LegKind::Kas => spks.push(p2pk(&t.buyer_key)),
        LegKind::Kcc20(_) => {
            let template = template_for(terms, LegIndex::Cash, &templates)?;
            spks.extend(token_spk(
                template,
                pubkey_owner(t.buyer_key),
                t.cash_leg.amount,
            ));
        }
        LegKind::External => {}
    }
    finish_addresses(terms, spks, payer)
}

// Fee inputs and the fee.

/// The fee payment: the payer's plain P2PK UTXOs outside `reserved`, largest first, enough to
/// cover `fee` and `extra` (a funding's deposit; 0 for the other builders) with a change of zero
/// or at least `MIN_KAS_OUTPUT`, the change paid to `change`.
fn fee_payment(
    pool: &[Utxo],
    reserved: &[([u8; 32], u32)],
    payer: &[u8; 32],
    change: &ScriptPublicKey,
    fee: u64,
    extra: u64,
) -> Value {
    let spk = p2pk(payer);
    let mut own: Vec<&Utxo> = at(pool, &spk, None)
        .into_iter()
        .filter(|u| !reserved.contains(&key(u)))
        .collect();
    own.sort_by(|a, b| {
        (b.entry.amount, std::cmp::Reverse(key(b)))
            .cmp(&(a.entry.amount, std::cmp::Reverse(key(a))))
    });
    let needed = fee.saturating_add(extra);
    let (mut chosen, mut sum) = (Vec::new(), 0u64);
    for u in own {
        let change = sum.saturating_sub(needed);
        let enough = sum >= needed && (change == 0 || change >= tx::MIN_KAS_OUTPUT);
        if enough {
            break;
        }
        sum = sum.saturating_add(u.entry.amount);
        chosen.push(utxo_to_json(u));
    }
    json!({
        "inputs": chosen,
        "fee": fee.to_string(),
        "change": ops::spk_json(change),
    })
}

/// Builds with `build` until the fee is the one asked for, or the minimum plus 10% for `auto`.
/// `extra` is what the payer's inputs must hold beyond the fee: a funding's deposit, else 0.
fn with_fee(
    terms: &ValidatedTerms,
    pool: &[Utxo],
    reserved: &[([u8; 32], u32)],
    funding: &Funding,
    extra: u64,
    build: impl Fn(&Value) -> Result<Ipst, Failure>,
) -> Result<Ipst, Failure> {
    let change = change_spk(funding, terms)?;
    let payment = |fee| fee_payment(pool, reserved, &funding.payer, &change, fee, extra);
    if let Some(fee) = funding.fee {
        return build(&payment(fee));
    }
    let mut fee = tx::min_relay_fee(0);
    for attempt in 0..FEE_ATTEMPTS {
        match build(&payment(fee)) {
            Err(Failure::Tx(TxError::FeeTooLow { minimum, .. })) if attempt + 1 < FEE_ATTEMPTS => {
                fee = minimum.saturating_add(minimum.div_ceil(10));
            }
            other => return other,
        }
    }
    unreachable!("the last attempt returns")
}

/// How many times a fee of `"auto"` is raised and tried: the first guess, then the minimum the
/// builder states and a tenth more, up to this many builds in all.
const FEE_ATTEMPTS: usize = 4;

fn reserve(used: &[&Utxo]) -> Vec<([u8; 32], u32)> {
    used.iter().map(|u| key(u)).collect()
}

// Settle.

/// A settle from the UTXOs of a `getUtxosByAddresses` reply text.
pub(crate) fn settle_from_reply(
    terms: &ValidatedTerms,
    artifacts: &Value,
    reply: &str,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Ipst, Failure> {
    let funding = funding_from_json(funding)?;
    let pool = dedupe(rpc::utxos_from_reply(reply)?);
    let templates = forms::artifacts(artifacts)?;
    let t = terms.terms();
    let mut used: Vec<&Utxo> = Vec::new();
    // Every leg that is escrowed: the authorizer (or the KAS cash vault UTXO) and the token.
    let mut parts: Vec<Option<(&Utxo, Option<&Utxo>)>> = Vec::new();
    for (leg, name, terms_leg) in legs_of(terms) {
        let vault = vault_of_or_none(terms, leg, terms_leg)?;
        let Some(vault) = vault else {
            parts.push(None);
            continue;
        };
        let vault_spk = vault.script_public_key();
        match terms_leg.kind {
            LegKind::Kas => {
                let u = lowest(
                    at(&pool, &vault_spk, None)
                        .into_iter()
                        .filter(|u| u.entry.amount == terms_leg.amount),
                )
                .ok_or_else(|| {
                    not_found(format!(
                        "no UTXO of exactly {} sompi at the {name} vault",
                        terms_leg.amount
                    ))
                })?;
                parts.push(Some((u, None)));
            }
            LegKind::Kcc20(_) => {
                let template = template_for(terms, leg, &templates)?;
                let authorizer = largest(at(&pool, &vault_spk, None))
                    .ok_or_else(|| not_found(format!("no plain UTXO at the {name} vault")))?;
                let escrow_spk =
                    token_spk(template, script_hash_owner(&vault), terms_leg.amount)
                        .ok_or_else(|| not_found(format!("no token script for the {name} leg")))?;
                let escrow =
                    lowest(at(&pool, &escrow_spk, covenant_of(terms_leg))).ok_or_else(|| {
                        not_found(format!(
                            "no token UTXO of exactly {} units in the {name} vault",
                            terms_leg.amount
                        ))
                    })?;
                parts.push(Some((authorizer, Some(escrow))));
            }
            LegKind::External => parts.push(None),
        }
    }
    let _ = t;
    let [asset, cash] = <[_; 2]>::try_from(parts).expect("two legs");
    let (asset_authorizer, asset_escrow) = match asset {
        Some((a, Some(e))) => (a, e),
        _ => return Err(not_found("the asset leg has no escrowed token")),
    };
    used.extend([asset_authorizer, asset_escrow]);
    let cash_json = match (&terms.terms().cash_leg.kind, cash) {
        (LegKind::Kas, Some((vault, _))) => {
            used.push(vault);
            json!({ "kind": "kas", "vault": utxo_to_json(vault) })
        }
        (LegKind::Kcc20(_), Some((authorizer, Some(escrow)))) => {
            used.extend([authorizer, escrow]);
            json!({
                "kind": "kcc20",
                "artifact": artifact_text(artifacts, "cash")?,
                "authorizer": utxo_to_json(authorizer),
                "escrow": utxo_to_json(escrow),
            })
        }
        _ => json!({ "kind": "external" }),
    };
    let legs = json!({
        "asset_artifact": artifact_text(artifacts, "asset")?,
        "asset_authorizer": utxo_to_json(asset_authorizer),
        "asset_escrow": utxo_to_json(asset_escrow),
        "cash": cash_json,
    });
    let reserved = reserve(&used);
    with_fee(terms, &pool, &reserved, &funding, 0, |payment| {
        ops::settle(terms, &legs, payment, current_daa, value)
    })
}

/// The vault of a leg the terms escrow, None for external cash.
fn vault_of_or_none(
    terms: &ValidatedTerms,
    leg: LegIndex,
    terms_leg: &impulse_core::terms::Leg,
) -> Result<Option<Vault>, Failure> {
    if matches!(terms_leg.kind, LegKind::External) {
        return Ok(None);
    }
    vault_of(terms, leg).map(Some)
}

// Refund.

/// A refund of `leg` by `signer` ("depositor", "counterparty" or "authority"). `with_token`
/// carries a KCC-20 leg's escrowed token home with its authorizer; without it only the vault UTXO
/// goes home and the token stays escrowed (the depositor's way out of a stray authorizer, and
/// only the depositor may take it). It has no meaning for a KAS cash leg.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refund_from_reply(
    terms: &ValidatedTerms,
    leg: LegIndex,
    signer: &str,
    with_token: bool,
    artifacts: &Value,
    reply: &str,
    funding: &Value,
    value: &Value,
) -> Result<Ipst, Failure> {
    let funding = funding_from_json(funding)?;
    let pool = dedupe(rpc::utxos_from_reply(reply)?);
    let (_, name, terms_leg) = legs_of(terms)[leg.index() as usize];
    let vault = vault_of(terms, leg)?;
    let vault_utxo = largest(at(&pool, &vault.script_public_key(), None))
        .ok_or_else(|| not_found(format!("no plain UTXO at the {name} vault")))?;
    let mut used = vec![vault_utxo];
    let escrow = if with_token && matches!(terms_leg.kind, LegKind::Kcc20(_)) {
        let templates = forms::artifacts(artifacts)?;
        let template = template_for(terms, leg, &templates)?;
        let spk = token_spk(template, script_hash_owner(&vault), terms_leg.amount)
            .ok_or_else(|| not_found(format!("no token script for the {name} leg")))?;
        let u = lowest(at(&pool, &spk, covenant_of(terms_leg))).ok_or_else(|| {
            not_found(format!(
                "no token UTXO of exactly {} units in the {name} vault",
                terms_leg.amount
            ))
        })?;
        used.push(u);
        Some(json!({
            "artifact": artifact_text(artifacts, if leg == LegIndex::Asset { "asset" } else { "cash" })?,
            "utxo": utxo_to_json(u),
            "amount": terms_leg.amount.to_string(),
            "is_minter": false,
        }))
    } else {
        None
    };
    let vault_json = utxo_to_json(vault_utxo);
    let reserved = reserve(&used);
    with_fee(terms, &pool, &reserved, &funding, 0, |payment| {
        ops::refund(
            terms,
            leg,
            signer,
            &vault_json,
            escrow.as_ref(),
            payment,
            value,
        )
    })
}

// Direct.

/// A Direct trade from the UTXOs of a reply text.
pub(crate) fn direct_from_reply(
    terms: &ValidatedTerms,
    artifacts: &Value,
    reply: &str,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Ipst, Failure> {
    let funding = funding_from_json(funding)?;
    let pool = dedupe(rpc::utxos_from_reply(reply)?);
    let templates = forms::artifacts(artifacts)?;
    let t = terms.terms();
    let asset_spk = token_spk(&templates.0, pubkey_owner(t.seller_key), t.asset_leg.amount)
        .ok_or_else(|| not_found("no token script for the asset leg"))?;
    let asset = lowest(at(&pool, &asset_spk, covenant_of(&t.asset_leg))).ok_or_else(|| {
        not_found(format!(
            "no token UTXO of exactly {} units owned by the seller's key",
            t.asset_leg.amount
        ))
    })?;
    let mut used = vec![asset];
    let token_json = |u: &Utxo, owner: Kcc20Owner, amount: u64| {
        json!({
            "utxo": utxo_to_json(u),
            "state": {
                "identifier_type": "pubkey",
                "identifier": hex(&owner.identifier),
                "amount": amount.to_string(),
                "is_minter": false,
            },
        })
    };
    let cash = match t.cash_leg.kind {
        LegKind::Kas => {
            let u = lowest(
                at(&pool, &p2pk(&t.buyer_key), None)
                    .into_iter()
                    .filter(|u| u.entry.amount == t.cash_leg.amount),
            )
            .ok_or_else(|| {
                not_found(format!(
                    "no UTXO of exactly {} sompi at the buyer's key",
                    t.cash_leg.amount
                ))
            })?;
            used.push(u);
            json!({ "kind": "kas", "utxo": utxo_to_json(u) })
        }
        LegKind::Kcc20(_) => {
            let template = template_for(terms, LegIndex::Cash, &templates)?;
            let spk = token_spk(template, pubkey_owner(t.buyer_key), t.cash_leg.amount)
                .ok_or_else(|| not_found("no token script for the cash leg"))?;
            let u = lowest(at(&pool, &spk, covenant_of(&t.cash_leg))).ok_or_else(|| {
                not_found(format!(
                    "no token UTXO of exactly {} units owned by the buyer's key",
                    t.cash_leg.amount
                ))
            })?;
            used.push(u);
            json!({
                "kind": "kcc20",
                "artifact": artifact_text(artifacts, "cash")?,
                "token": token_json(u, pubkey_owner(t.buyer_key), t.cash_leg.amount),
            })
        }
        LegKind::External => {
            return Err(
                SdkError::json("terms.cash_leg", "Direct trades have no external cash").into(),
            )
        }
    };
    let legs = json!({
        "asset_artifact": artifact_text(artifacts, "asset")?,
        "asset": token_json(asset, pubkey_owner(t.seller_key), t.asset_leg.amount),
        "cash": cash,
    });
    let reserved = reserve(&used);
    with_fee(terms, &pool, &reserved, &funding, 0, |payment| {
        ops::direct(terms, &legs, payment, current_daa, value)
    })
}

// Funding the buyer's KAS cash leg.

/// What the funding of the cash leg by `payer` needs of the terms, in the order of the command
/// line's `fund build` (spec/CLI.md): the KAS minimum of "Before funding"; whose leg it is (the
/// cash leg is the buyer's: `SDK_FUND_NOT_YOUR_LEG`, the command line's `CLI_FUND_NOT_YOUR_LEG`);
/// that the leg has a vault (`TEMPLATE_NO_VAULT`: Direct terms, external cash); then the template
/// check of "Before funding" (`SDK_TEMPLATE_UNPINNED`, no override).
///
/// One refusal is a limit of the SDK, not the command line's: a KCC-20 cash leg is refused here
/// (`TX_WRONG_MODE`, between the vault and the template check), because the command line funds it
/// with the depositor's token UTXOs and the SDK does not choose a token to move. The command line
/// has `TX_WRONG_MODE` only for token arguments given for a KAS leg.
fn check_cash_funding(terms: &ValidatedTerms, payer: &[u8; 32]) -> Result<(), Failure> {
    let t = terms.terms();
    funding::check_kas_minimum(terms)?;
    if *payer != t.buyer_key {
        return Err(SdkError::FundNotYourLeg {
            reason: format!(
                "the cash leg is funded by the buyer, whose key is {}, not by {}",
                hex(&t.buyer_key),
                hex(payer)
            ),
        }
        .into());
    }
    vault_of(terms, LegIndex::Cash)?;
    if !matches!(t.cash_leg.kind, LegKind::Kas) {
        return Err(TxError::WrongMode {
            reason: "the page funds a KAS cash leg; a KCC-20 leg is funded with the command line",
        }
        .into());
    }
    funding::check_pinned(terms)?;
    Ok(())
}

/// The addresses a funding of the cash leg needs the UTXOs of: the cash vault (a deposit already
/// there), the asset vault and the token escrowed in it (the seller's asset leg), and the payer.
/// Refused like the builder is, before the node is asked (`check_cash_funding`).
pub(crate) fn fund_cash_addresses(
    terms: &ValidatedTerms,
    artifacts: &Value,
    payer: &[u8; 32],
) -> Result<Vec<String>, Failure> {
    check_cash_funding(terms, payer)?;
    let templates = forms::artifacts(artifacts)?;
    let cash_vault = vault_of(terms, LegIndex::Cash)?;
    let asset_vault = vault_of(terms, LegIndex::Asset)?;
    let mut spks = vec![
        cash_vault.script_public_key(),
        asset_vault.script_public_key(),
    ];
    spks.extend(token_spk(
        &templates.0,
        script_hash_owner(&asset_vault),
        terms.terms().asset_leg.amount,
    ));
    finish_addresses(terms, spks, payer)
}

/// What the node says about the two vaults before the buyer funds the cash leg, from the UTXOs of
/// its reply. Both refusals protect the buyer, whose only way to take the deposit back unaided is
/// a refund signed by the key of the funding wallet (from the expiry in earmarked mode):
///
/// - the cash vault already holds a UTXO of exactly the cash amount: that is the deposit a settle
///   takes, so it is funded (`SDK_FUND_ALREADY_FUNDED`); a second one would only wait there;
/// - the asset leg is not funded: the node reports no plain UTXO at the asset vault (the
///   authorizer), or no token in the exact state the asset leg needs, owned by the asset vault,
///   with the leg's covenant (`SDK_FUND_ASSET_NOT_FUNDED`). The settle's own lookups, the same
///   rules as `settle_from_reply`.
fn check_node_state(
    terms: &ValidatedTerms,
    templates: &(Kcc20Template, Option<Kcc20Template>),
    pool: &[Utxo],
) -> Result<(), Failure> {
    let t = terms.terms();
    let cash_vault = vault_of(terms, LegIndex::Cash)?;
    if let Some(u) = lowest(
        at(pool, &cash_vault.script_public_key(), None)
            .into_iter()
            .filter(|u| u.entry.amount == t.cash_leg.amount),
    ) {
        return Err(SdkError::FundAlreadyFunded {
            reason: format!(
                "the cash vault already holds a deposit of exactly {} sompi ({}:{}): a settle takes that one, and a second deposit would only wait in the vault until a refund. Build the settle, or refund the first",
                t.cash_leg.amount,
                hex(&u.outpoint.transaction_id.as_bytes()),
                u.outpoint.index
            ),
        }
        .into());
    }
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(SdkError::FundAssetNotFunded {
            reason: "the asset leg is not a KCC-20 token, so there is no escrow to look for".into(),
        }
        .into());
    };
    templates.0.check_token(&token)?;
    let asset_vault = vault_of(terms, LegIndex::Asset)?;
    let missing = |what: String| {
        Failure::from(SdkError::FundAssetNotFunded {
            reason: format!(
                "the seller's asset leg is not funded on this node: {what}. Fund the cash leg only after the asset leg has been accepted, so that your deposit is not left waiting in its vault"
            ),
        })
    };
    if largest(at(pool, &asset_vault.script_public_key(), None)).is_none() {
        return Err(missing(
            "no plain UTXO at the asset vault (the authorizer)".into(),
        ));
    }
    let escrow_spk = token_spk(
        &templates.0,
        script_hash_owner(&asset_vault),
        t.asset_leg.amount,
    )
    .ok_or_else(|| missing("no token script for the asset leg".into()))?;
    if lowest(at(pool, &escrow_spk, covenant_of(&t.asset_leg))).is_none() {
        return Err(missing(format!(
            "no token UTXO of exactly {} units in the asset vault",
            t.asset_leg.amount
        )));
    }
    Ok(())
}

/// The buyer's funding of a KAS cash vault from the UTXOs of a reply text: one output of exactly
/// the cash amount at the cash vault, paid by the payer's plain P2PK UTXOs (the largest first)
/// that also pay the fee, the change to the funding's change address. `current_daa` is the
/// creation DAA score, read from a node: the creation checks run with it, on the terms' network.
/// The reply must also show the seller's asset leg funded and the cash vault not yet funded
/// (`check_node_state`).
pub(crate) fn fund_cash_from_reply(
    terms: &ValidatedTerms,
    artifacts: &Value,
    reply: &str,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Ipst, Failure> {
    let funding = funding_from_json(funding)?;
    check_cash_funding(terms, &funding.payer)?;
    let pool = dedupe(rpc::utxos_from_reply(reply)?);
    let templates = forms::artifacts(artifacts)?;
    check_node_state(terms, &templates, &pool)?;
    let t = terms.terms();
    let context = json!({
        "network": network_name(t.network),
        "creation_daa": current_daa.to_string(),
    });
    with_fee(terms, &pool, &[], &funding, t.cash_leg.amount, |payment| {
        ops::fund_kas(terms, &context, payment, value)
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::error::Refusal;
    use crate::json::terms_from_json;
    use crate::testkit::vector;
    use impulse_core::terms::Network;
    use std::cell::Cell;

    fn validated() -> ValidatedTerms {
        terms_from_json(&vector("08-")["terms"])
            .unwrap()
            .validate_structure()
            .unwrap()
    }

    fn funding(fee: Option<u64>) -> Funding {
        Funding {
            payer: [7; 32],
            fee,
            change: None,
        }
    }

    /// A builder that never accepts the fee: the retries stop at FEE_ATTEMPTS, and the last
    /// refusal is returned, not a panic. Beside it, a builder that accepts the fee it is shown.
    #[test]
    fn a_fee_of_auto_is_raised_a_bounded_number_of_times_and_then_refused_with_the_builders_code() {
        let t = validated();
        let calls = Cell::new(0usize);
        let refuses = |_: &Value| {
            calls.set(calls.get() + 1);
            Err(Failure::Tx(TxError::FeeTooLow {
                fee: calls.get() as u64,
                minimum: 1_000 * calls.get() as u64,
            }))
        };
        let err = with_fee(&t, &[], &[], &funding(None), 0, refuses).unwrap_err();
        assert_eq!(err.code(), "TX_FEE_TOO_LOW");
        assert_eq!(
            calls.get(),
            FEE_ATTEMPTS,
            "the first guess and the retries, and no more"
        );
        // The fee of each retry is the minimum the builder stated and a tenth more.
        let seen = std::cell::RefCell::new(Vec::new());
        let n = Cell::new(0u64);
        let _ = with_fee(&t, &[], &[], &funding(None), 0, |payment: &Value| {
            seen.borrow_mut()
                .push(payment["fee"].as_str().unwrap().to_string());
            n.set(n.get() + 1);
            Err(Failure::Tx(TxError::FeeTooLow {
                fee: 0,
                minimum: 1_000 * n.get(),
            }))
        });
        let seen = seen.into_inner();
        assert_eq!(seen[1], "1100", "1000 and a tenth");
        assert_eq!(seen[2], "2200");
        assert_eq!(seen[3], "3300");
        // Control: a builder that accepts the first fee is called once; a typed fee is never raised.
        let calls = Cell::new(0usize);
        let accepts = |_: &Value| -> Result<Ipst, Failure> {
            calls.set(calls.get() + 1);
            Err(Failure::Sdk(SdkError::UtxoNotFound { what: "x".into() }))
        };
        assert_eq!(
            with_fee(&t, &[], &[], &funding(None), 0, accepts)
                .unwrap_err()
                .code(),
            "SDK_UTXO_NOT_FOUND"
        );
        assert_eq!(calls.get(), 1, "another refusal is not retried");
        calls.set(0);
        let typed = |_: &Value| {
            calls.set(calls.get() + 1);
            Err(Failure::Tx(TxError::FeeTooLow { fee: 1, minimum: 5 }))
        };
        assert_eq!(
            with_fee(&t, &[], &[], &funding(Some(1)), 0, typed)
                .unwrap_err()
                .code(),
            "TX_FEE_TOO_LOW"
        );
        assert_eq!(calls.get(), 1, "a typed fee is tried once");
    }

    // The buyer's cash funding.

    use kaspa_consensus_core::tx::TransactionOutpoint;
    use kaspa_wrpc_client::prelude::{
        GetUtxosByAddressesResponse, RpcTransactionOutpoint, RpcUtxoEntry, RpcUtxosByAddressesEntry,
    };

    const ASSET_ARTIFACT: &str =
        include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
    const CASH_ARTIFACT: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-cash.json");
    /// The covenant of the asset token in the terms below, as one byte repeated.
    const ASSET_COVENANT: u8 = 0xa5;

    /// A UTXO a test puts on the node: (label, amount, scriptPublicKey, covenant). The outpoint
    /// is the label repeated, so each label is one UTXO.
    type Pooled = (u8, u64, ScriptPublicKey, Option<u8>);

    /// A `getUtxosByAddresses` reply text with these UTXOs.
    fn node_reply(utxos: &[Pooled]) -> String {
        let entries = utxos
            .iter()
            .map(|(n, amount, spk, covenant)| RpcUtxosByAddressesEntry {
                address: None,
                outpoint: RpcTransactionOutpoint {
                    transaction_id: Hash::from_bytes([*n; 32]),
                    index: 0,
                },
                utxo_entry: RpcUtxoEntry::new(
                    *amount,
                    spk.clone(),
                    1_000,
                    false,
                    covenant.map(|c| Hash::from_bytes([c; 32])),
                ),
            })
            .collect();
        json!({
            "id": 1,
            "method": "getUtxosByAddresses",
            "params": serde_json::to_value(GetUtxosByAddressesResponse::new(entries)).unwrap(),
        })
        .to_string()
    }

    fn declared() -> Value {
        json!({ "kas_equivalent": "100000000" })
    }

    fn vector_terms(prefix: &str) -> ValidatedTerms {
        terms_from_json(&vector(prefix)["terms"])
            .unwrap()
            .validate_structure()
            .unwrap()
    }

    fn artifacts() -> Value {
        json!({ "asset": ASSET_ARTIFACT, "cash": null })
    }

    /// Vector 08 (testnet, vault, KCC-20 asset, 1 KAS cash) with its asset token the fixture
    /// artifact's, a pinned kcc20.sil build, and the covenant `ASSET_COVENANT` repeated: the
    /// golden vectors name a synthetic token, which no funding accepts (`SDK_TEMPLATE_UNPINNED`).
    fn fundable_doc() -> Value {
        let mut doc = vector("08-")["terms"].clone();
        let template = ops::kcc20_template(ASSET_ARTIFACT).unwrap();
        for key in [
            "template_hash",
            "template_prefix_len",
            "template_suffix_len",
        ] {
            doc["asset_leg"][key] = template[key].clone();
        }
        doc["asset_leg"]["covenant_id"] = json!(hex(&[ASSET_COVENANT; 32]));
        doc
    }

    fn fundable_terms_of(doc: &Value) -> ValidatedTerms {
        terms_from_json(doc).unwrap().validate_structure().unwrap()
    }

    fn fundable_terms() -> ValidatedTerms {
        fundable_terms_of(&fundable_doc())
    }

    /// What the seller's funding of the asset leg leaves on the node: the authorizer at the asset
    /// vault and the token escrowed in it, in the exact state the leg needs.
    fn asset_leg(t: &ValidatedTerms) -> [Pooled; 2] {
        let vault = Vault::instantiate_existing(t, LegIndex::Asset).unwrap();
        let (template, _) = forms::artifacts(&artifacts()).unwrap();
        let escrow = token_spk(
            &template,
            script_hash_owner(&vault),
            t.terms().asset_leg.amount,
        )
        .unwrap();
        [
            (11, 50_000_000, vault.script_public_key(), None),
            (12, 200_000_000, escrow, Some(ASSET_COVENANT)),
        ]
    }

    /// The node's reply for `t`: the asset leg funded, and `more`.
    fn pool_of(t: &ValidatedTerms, more: &[Pooled]) -> String {
        let mut utxos = asset_leg(t).to_vec();
        utxos.extend_from_slice(more);
        node_reply(&utxos)
    }

    /// The DAA score a node would report for vector 08, and the payment form of a fee of `fee`.
    const CREATION: u64 = 425_000_000;
    fn payer_funding(key: &[u8; 32], fee: &str) -> Value {
        json!({ "payer": hex(key), "fee": fee })
    }

    fn fund(t: &ValidatedTerms, pool: &str, funding: &Value) -> Result<Ipst, Failure> {
        fund_cash_from_reply(t, &artifacts(), pool, funding, CREATION, &declared())
    }

    fn fund_code(t: &ValidatedTerms, pool: &str, funding: &Value) -> Option<&'static str> {
        fund(t, pool, funding).err().map(|e| e.code())
    }

    #[test]
    fn the_cash_funding_pays_the_cash_amount_to_the_cash_vault_from_the_buyers_largest_utxos() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let cash = t.terms().cash_leg.amount;
        let vault = Vault::instantiate_existing(&t, LegIndex::Cash).unwrap();
        // 1.3 KAS alone leaves a change of 0.3 KAS less the fee, below the minimum output, so the
        // next largest is taken too; the 0.01 KAS UTXO, the other key's and a token are not.
        let pool = pool_of(
            &t,
            &[
                (1, 130_000_000, p2pk(&buyer), None),
                (2, 40_000_000, p2pk(&buyer), None),
                (3, 1_000_000, p2pk(&buyer), None),
                (4, 900_000_000, p2pk(&[9; 32]), None),
                (5, 700_000_000, p2pk(&buyer), Some(8)),
            ],
        );
        let funding = payer_funding(&buyer, "auto");
        let ipst = fund(&t, &pool, &funding).unwrap();
        let (tx, entries) = (ipst.transaction(), ipst.entries());
        assert_eq!(tx.outputs[0].value, cash, "exactly the cash amount");
        assert_eq!(tx.outputs[0].script_public_key, vault.script_public_key());
        assert_eq!(
            tx.inputs.len(),
            2,
            "the largest first, until the change is at least the minimum"
        );
        assert_eq!(
            entries.iter().map(|e| e.amount).collect::<Vec<_>>(),
            [130_000_000, 40_000_000]
        );
        assert!(entries
            .iter()
            .all(|e| e.script_public_key == p2pk(&buyer) && e.covenant_id.is_none()));
        // The change goes back to the payer's own key, and the inputs pay the deposit and the fee.
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[1].script_public_key, p2pk(&buyer));
        assert_eq!(
            tx.outputs[1].value,
            170_000_000 - cash - ipst.fee(),
            "the change is the inputs less the deposit and the fee"
        );
        assert!(tx.outputs[1].value >= tx::MIN_KAS_OUTPUT);
        // The buyer signs every input, and nothing else is in the document.
        assert!(ipst
            .slots()
            .iter()
            .all(|slot| slot.signer() == Some(buyer) && slot.signature().is_none()));
        // The same transaction as the builder makes from the inputs named by hand.
        let fee = ipst.fee();
        let named: Vec<Value> = entries
            .iter()
            .zip(&tx.inputs)
            .map(|(e, input)| {
                utxo_to_json(&Utxo {
                    outpoint: TransactionOutpoint::new(
                        input.previous_outpoint.transaction_id,
                        input.previous_outpoint.index,
                    ),
                    entry: e.clone(),
                })
            })
            .collect();
        let by_hand = ops::fund_kas(
            &t,
            &json!({ "network": "testnet", "creation_daa": CREATION.to_string() }),
            &json!({ "inputs": named, "fee": fee.to_string(), "change": ops::spk_json(&p2pk(&buyer)) }),
            &declared(),
        )
        .unwrap();
        assert_eq!(ipst.to_json(), by_hand.to_json());
        // A typed fee is the fee, and the largest UTXO alone covers it.
        let typed = fund(&t, &pool, &payer_funding(&buyer, "5000000")).unwrap();
        assert_eq!(typed.fee(), 5_000_000);
        // The creation checks run on the terms' network: the same terms on mainnet fund their
        // own (mainnet) cash vault, and the same buyer coins and score are fine for them.
        let mut doc = fundable_doc();
        doc["network"] = json!("mainnet");
        let on_mainnet = fundable_terms_of(&doc);
        let main_pool = pool_of(
            &on_mainnet,
            &[
                (1, 130_000_000, p2pk(&buyer), None),
                (2, 40_000_000, p2pk(&buyer), None),
            ],
        );
        let main = fund(&on_mainnet, &main_pool, &funding).unwrap();
        assert_eq!(
            main.transaction().outputs[0].script_public_key,
            Vault::instantiate_existing(&on_mainnet, LegIndex::Cash)
                .unwrap()
                .script_public_key()
        );
        assert_ne!(
            main.transaction().outputs[0].script_public_key,
            vault.script_public_key(),
            "another network, another vault"
        );
    }

    #[test]
    fn the_cash_funding_asks_about_the_cash_vault_the_asset_vault_its_token_and_the_payer() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let network = t.terms().network;
        let vault = |leg| Vault::instantiate_existing(&t, leg).unwrap();
        let [_, escrow] = asset_leg(&t);
        let want: Vec<String> = [
            vault(LegIndex::Cash).script_public_key(),
            vault(LegIndex::Asset).script_public_key(),
            escrow.2.clone(),
            p2pk(&buyer),
        ]
        .iter()
        .map(|spk| address_of(network, spk).unwrap())
        .collect();
        assert_eq!(fund_cash_addresses(&t, &artifacts(), &buyer).unwrap(), want);
        // The artifact is the asset token's, or it is refused before the node is asked.
        let wrong = json!({ "asset": CASH_ARTIFACT, "cash": null });
        assert_eq!(
            fund_cash_addresses(&t, &wrong, &buyer).unwrap().len(),
            4,
            "an artifact of another token still names four addresses; the escrow one differs"
        );
        assert_ne!(
            fund_cash_addresses(&t, &wrong, &buyer).unwrap()[2],
            want[2],
            "the escrow address follows the artifact"
        );
        assert_eq!(
            fund_cash_from_reply(
                &t,
                &wrong,
                &pool_of(&t, &[(1, 300_000_000, p2pk(&buyer), None)]),
                &payer_funding(&buyer, "auto"),
                CREATION,
                &declared()
            )
            .err()
            .map(|e| e.code()),
            Some("TX_TOKEN_TEMPLATE"),
            "the node is not asked about a token the terms do not name"
        );
    }

    #[test]
    fn the_cash_funding_refuses_what_is_not_the_buyers_kas_cash_leg_beside_the_accepted_control() {
        let t = fundable_terms();
        let (buyer, seller) = (t.terms().buyer_key, t.terms().seller_key);
        let pool = pool_of(
            &t,
            &[
                (1, 300_000_000, p2pk(&buyer), None),
                (2, 300_000_000, p2pk(&seller), None),
            ],
        );
        let run = |t: &ValidatedTerms, payer: &[u8; 32], pool: &str, daa: u64, value: &Value| {
            fund_cash_from_reply(
                t,
                &artifacts(),
                pool,
                &payer_funding(payer, "auto"),
                daa,
                value,
            )
            .err()
            .map(|e| e.code())
        };
        assert_eq!(
            run(&t, &buyer, &pool, CREATION, &declared()),
            None,
            "control"
        );
        // Only the buyer funds the cash leg: the seller's key, and a key of neither party.
        assert_eq!(
            run(&t, &seller, &pool, CREATION, &declared()),
            Some("SDK_FUND_NOT_YOUR_LEG")
        );
        assert_eq!(
            run(&t, &[9; 32], &pool, CREATION, &declared()),
            Some("SDK_FUND_NOT_YOUR_LEG")
        );
        // The refusal says whose leg it is and who asked: the buyer's key first, then the payer's.
        let said = fund_cash_from_reply(
            &t,
            &artifacts(),
            &pool,
            &payer_funding(&seller, "auto"),
            CREATION,
            &declared(),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            said,
            format!(
                "SDK_FUND_NOT_YOUR_LEG: the cash leg is funded by the buyer, whose key is {}, not by {}",
                hex(&buyer),
                hex(&seller)
            )
        );
        // The addresses to ask about are refused the same way, before the node is asked.
        assert_eq!(
            fund_cash_addresses(&t, &artifacts(), &buyer).unwrap().len(),
            4,
            "control: the four addresses"
        );
        assert_eq!(
            fund_cash_addresses(&t, &artifacts(), &seller)
                .unwrap_err()
                .code(),
            "SDK_FUND_NOT_YOUR_LEG"
        );
        // A leg with no vault (Direct terms, external cash) and a KCC-20 cash leg are not funded
        // here. The order is the command line's for whose leg it is (first) and whether it has a
        // vault; the token cash leg is a limit of the SDK (`TX_WRONG_MODE`), after the vault.
        for (prefix, expected) in [
            ("11-", "TEMPLATE_NO_VAULT"),
            ("07-", "TEMPLATE_NO_VAULT"),
            ("05-", "TEMPLATE_NO_VAULT"),
            ("01-", "TX_WRONG_MODE"),
        ] {
            let other = vector_terms(prefix);
            let key = other.terms().buyer_key;
            assert_eq!(
                run(&other, &key, &pool, CREATION, &declared()),
                Some(expected),
                "vector {prefix}"
            );
            assert_eq!(
                fund_cash_addresses(&other, &artifacts(), &key)
                    .unwrap_err()
                    .code(),
                expected,
                "vector {prefix}, addresses"
            );
            // Whose leg it is comes first, as in `fund build`: a stranger asking for a leg that
            // is not funded here is told it is not his.
            assert_eq!(
                run(&other, &[9; 32], &pool, CREATION, &declared()),
                Some("SDK_FUND_NOT_YOUR_LEG"),
                "vector {prefix}, a stranger"
            );
        }
        // The creation checks run at the node's score: at the expiry the trade cannot be created.
        let expiry = t.terms().expiry_daa;
        assert_eq!(
            run(&t, &buyer, &pool, expiry, &declared()),
            Some("TERMS_EXPIRY_NOT_AFTER_CREATION")
        );
        assert_eq!(run(&t, &buyer, &pool, expiry - 1, &declared()), None);
        // The value cap holds: a declaration above it, and no declaration, are refused.
        assert_eq!(
            run(
                &t,
                &buyer,
                &pool,
                CREATION,
                &json!({ "kas_equivalent": "1000000001" })
            ),
            Some("SDK_VALUE_CAP_EXCEEDED")
        );
        assert_eq!(
            run(
                &t,
                &buyer,
                &pool,
                CREATION,
                &json!({ "kas_equivalent": "0" })
            ),
            Some("SDK_VALUE_UNKNOWN")
        );
        // A KAS cash leg of 100 KAS is above the 10 KAS cap.
        let mut doc = fundable_doc();
        doc["cash_leg"]["amount"] = json!("10000000000");
        let big = fundable_terms_of(&doc);
        let big_pool = pool_of(&big, &[(1, 20_000_000_000, p2pk(&buyer), None)]);
        assert_eq!(
            run(&big, &buyer, &big_pool, CREATION, &declared()),
            Some("SDK_VALUE_CAP_EXCEEDED")
        );
        // The KAS minimum of "Before funding" is the first step of `check_cash_funding`: before
        // whose leg it is, before the vault and the pin, and before the node is asked for anything.
        // A cash leg of one sompi under the minimum is refused for the buyer, the seller and a
        // stranger alike, by the addresses to ask about and by the builder; at the exact minimum
        // the same three are told what the next step says (the buyer funds, the others are told
        // it is not their leg).
        let mut doc = fundable_doc();
        doc["cash_leg"]["amount"] = json!((impulse_core::tx::MIN_KAS_OUTPUT - 1).to_string());
        let thin = fundable_terms_of(&doc);
        let thin_pool = pool_of(&thin, &[(1, 300_000_000, p2pk(&buyer), None)]);
        doc["cash_leg"]["amount"] = json!(impulse_core::tx::MIN_KAS_OUTPUT.to_string());
        let exact = fundable_terms_of(&doc);
        let exact_pool = pool_of(&exact, &[(1, 300_000_000, p2pk(&buyer), None)]);
        for (who, payer, at_minimum) in [
            ("the buyer", buyer, None),
            ("the seller", seller, Some("SDK_FUND_NOT_YOUR_LEG")),
            ("a stranger", [9; 32], Some("SDK_FUND_NOT_YOUR_LEG")),
        ] {
            assert_eq!(
                run(&thin, &payer, &thin_pool, CREATION, &declared()),
                Some("TX_BELOW_MIN_KAS"),
                "{who}, one sompi under the minimum"
            );
            assert_eq!(
                fund_cash_addresses(&thin, &artifacts(), &payer)
                    .unwrap_err()
                    .code(),
                "TX_BELOW_MIN_KAS",
                "{who}, one sompi under the minimum, addresses"
            );
            assert_eq!(
                run(&exact, &payer, &exact_pool, CREATION, &declared()),
                at_minimum,
                "{who}, at the minimum"
            );
            assert_eq!(
                fund_cash_addresses(&exact, &artifacts(), &payer)
                    .err()
                    .map(|e| e.code()),
                at_minimum,
                "{who}, at the minimum, addresses"
            );
        }
    }

    #[test]
    fn the_cash_funding_is_refused_for_an_unpinned_template_beside_the_pinned_control() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let funding = payer_funding(&buyer, "auto");
        let coin = [(1, 300_000_000, p2pk(&buyer), None)];
        assert_eq!(
            fund_code(&t, &pool_of(&t, &coin), &funding),
            None,
            "control: a pinned build"
        );
        // The golden vector names a synthetic token (a227fc3a, 40+1420): no funding accepts it.
        let unpinned = vector_terms("08-");
        assert_eq!(
            fund_code(&unpinned, &pool_of(&unpinned, &coin), &funding),
            Some("SDK_TEMPLATE_UNPINNED")
        );
        assert_eq!(
            fund_cash_addresses(&unpinned, &artifacts(), &buyer)
                .unwrap_err()
                .code(),
            "SDK_TEMPLATE_UNPINNED"
        );
        // One byte off a pinned build is not that build: the suffix length 1461 beside 1460.
        let mut near = fundable_doc();
        let suffix = near["asset_leg"]["template_suffix_len"].as_u64().unwrap();
        near["asset_leg"]["template_suffix_len"] = json!(suffix + 1);
        let near = fundable_terms_of(&near);
        assert_eq!(
            fund_code(&near, &pool_of(&near, &coin), &funding),
            Some("SDK_TEMPLATE_UNPINNED")
        );
        // The refusal names the leg, the template and why.
        let said = fund(&unpinned, &pool_of(&unpinned, &coin), &funding)
            .unwrap_err()
            .to_string();
        assert!(
            said.starts_with("SDK_TEMPLATE_UNPINNED: the asset leg's KCC-20 template a227fc3a")
                && said.contains("(40+1420)")
                && said.ends_with("such tokens are outside v1"),
            "{said}"
        );
    }

    #[test]
    fn the_cash_funding_waits_for_the_asset_leg_and_refuses_a_second_deposit() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let cash = t.terms().cash_leg.amount;
        let funding = payer_funding(&buyer, "auto");
        let coin: Pooled = (1, 300_000_000, p2pk(&buyer), None);
        let [authorizer, escrow] = asset_leg(&t);
        let reply = |utxos: &[Pooled]| node_reply(utxos);
        assert_eq!(
            fund_code(
                &t,
                &reply(&[authorizer.clone(), escrow.clone(), coin.clone()]),
                &funding
            ),
            None,
            "control: the asset leg is funded and the cash vault is empty"
        );
        // The asset leg: nothing there, only the authorizer, only the token, a token of another
        // covenant, an authorizer that carries a covenant (a token, not the vault's KAS).
        let wrong_covenant = (escrow.0, escrow.1, escrow.2.clone(), Some(0x11));
        let covenant_authorizer = (authorizer.0, authorizer.1, authorizer.2.clone(), Some(0x22));
        for (what, utxos) in [
            ("nothing", vec![coin.clone()]),
            (
                "only the authorizer",
                vec![authorizer.clone(), coin.clone()],
            ),
            ("only the token", vec![escrow.clone(), coin.clone()]),
            (
                "a token of another covenant",
                vec![authorizer.clone(), wrong_covenant, coin.clone()],
            ),
            (
                "an authorizer with a covenant",
                vec![covenant_authorizer, escrow.clone(), coin.clone()],
            ),
        ] {
            assert_eq!(
                fund_code(&t, &reply(&utxos), &funding),
                Some("SDK_FUND_ASSET_NOT_FUNDED"),
                "{what}"
            );
        }
        // A token of another amount, or owned by another script, is not the escrow the leg needs.
        let other_owner = {
            let (template, _) = forms::artifacts(&artifacts()).unwrap();
            let spk =
                token_spk(&template, pubkey_owner([9; 32]), t.terms().asset_leg.amount).unwrap();
            (escrow.0, escrow.1, spk, Some(ASSET_COVENANT))
        };
        assert_eq!(
            fund_code(
                &t,
                &reply(&[authorizer.clone(), other_owner, coin.clone()]),
                &funding
            ),
            Some("SDK_FUND_ASSET_NOT_FUNDED"),
            "a token owned by a key, not by the vault"
        );
        // The refusal says what is missing and why it matters.
        let said = fund(&t, &reply(&[escrow.clone(), coin.clone()]), &funding)
            .unwrap_err()
            .to_string();
        assert!(
            said.starts_with("SDK_FUND_ASSET_NOT_FUNDED: the seller's asset leg is not funded on this node: no plain UTXO at the asset vault (the authorizer)."),
            "{said}"
        );
        let said = fund(&t, &reply(&[authorizer.clone(), coin.clone()]), &funding)
            .unwrap_err()
            .to_string();
        assert!(
            said.contains("no token UTXO of exactly 1 units in the asset vault"),
            "{said}"
        );
        // A second deposit: a UTXO of exactly the cash amount already at the cash vault.
        let cash_vault = Vault::instantiate_existing(&t, LegIndex::Cash)
            .unwrap()
            .script_public_key();
        let deposit: Pooled = (21, cash, cash_vault.clone(), None);
        let funded = [authorizer.clone(), escrow.clone(), coin.clone()];
        let with = |extra: Pooled| {
            let mut utxos = funded.to_vec();
            utxos.push(extra);
            reply(&utxos)
        };
        assert_eq!(
            fund_code(&t, &with(deposit.clone()), &funding),
            Some("SDK_FUND_ALREADY_FUNDED")
        );
        // Other amounts at the cash vault, or a covenant-bound UTXO, are not the deposit a settle takes.
        for (what, other) in [
            ("one sompi less", (21, cash - 1, cash_vault.clone(), None)),
            ("one sompi more", (21, cash + 1, cash_vault.clone(), None)),
            (
                "the amount with a covenant",
                (21, cash, cash_vault.clone(), Some(0x33)),
            ),
        ] {
            assert_eq!(fund_code(&t, &with(other), &funding), None, "{what}");
        }
        let said = fund(&t, &with(deposit), &funding).unwrap_err().to_string();
        assert!(
            said.starts_with("SDK_FUND_ALREADY_FUNDED: the cash vault already holds a deposit of exactly 100000000 sompi (1515151515151515151515151515151515151515151515151515151515151515:0)"),
            "{said}"
        );
        // Both at once: the deposit is told first.
        assert_eq!(
            fund_code(&t, &reply(&[(21, cash, cash_vault, None), coin]), &funding),
            Some("SDK_FUND_ALREADY_FUNDED")
        );
    }

    #[test]
    fn the_cash_funding_needs_the_deposit_and_the_fee_from_the_buyers_own_utxos() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let run = |utxos: &[Pooled], fee: &str| {
            fund_code(&t, &pool_of(&t, utxos), &payer_funding(&buyer, fee))
        };
        // Control: enough for the deposit, the fee and a change above the minimum.
        assert_eq!(run(&[(1, 300_000_000, p2pk(&buyer), None)], "auto"), None);
        // No UTXO of the buyer's: a node that reports only another key's.
        assert_eq!(
            run(&[(1, 300_000_000, p2pk(&[9; 32]), None)], "auto"),
            Some("TX_KAS_INPUT")
        );
        assert_eq!(run(&[], "auto"), Some("TX_KAS_INPUT"));
        // The deposit is not covered: the buyer holds exactly the cash amount, which leaves
        // nothing for the fee; and less than it.
        assert_eq!(
            run(&[(1, 100_000_000, p2pk(&buyer), None)], "auto"),
            Some("TX_INSUFFICIENT_FUNDS")
        );
        assert_eq!(
            run(&[(1, 90_000_000, p2pk(&buyer), None)], "auto"),
            Some("TX_INSUFFICIENT_FUNDS")
        );
        // A change below the minimum output is not paid out: the inputs hold the deposit, the fee
        // and 0.1 KAS, and no other UTXO is there to lift the change to the minimum.
        assert_eq!(
            run(&[(1, 110_000_000, p2pk(&buyer), None)], "5000000"),
            Some("TX_BELOW_MIN_KAS")
        );
        // A typed fee below the relay minimum is the builder's refusal, and is not raised.
        assert_eq!(
            run(&[(1, 300_000_000, p2pk(&buyer), None)], "1"),
            Some("TX_FEE_TOO_LOW")
        );
    }

    /// The edges of the input choice: the inputs stop at the first prefix that covers the deposit
    /// and the fee exactly, or with a change of exactly the minimum, and not one UTXO later.
    #[test]
    fn the_cash_funding_stops_taking_inputs_at_exactly_enough_and_at_the_minimum_change() {
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let cash = t.terms().cash_leg.amount;
        let fee = 5_000_000u64;
        let built = |utxos: &[Pooled]| {
            fund(
                &t,
                &pool_of(&t, utxos),
                &payer_funding(&buyer, &fee.to_string()),
            )
            .unwrap()
        };
        let amounts = |i: &Ipst| i.entries().iter().map(|e| e.amount).collect::<Vec<_>>();
        // Exactly the deposit and the fee: one input, and no change output. The second UTXO, which
        // would only leave a change under the minimum, is not taken.
        let exact = built(&[
            (1, cash + fee, p2pk(&buyer), None),
            (2, 1_000_000, p2pk(&buyer), None),
        ]);
        assert_eq!(amounts(&exact), [cash + fee]);
        assert_eq!(exact.transaction().outputs.len(), 1, "no change output");
        // One sompi short of covering: the next UTXO is taken, and the change is what is left.
        let short = built(&[
            (1, cash + fee - 1, p2pk(&buyer), None),
            (2, 60_000_000, p2pk(&buyer), None),
        ]);
        assert_eq!(amounts(&short), [cash + fee - 1, 60_000_000]);
        assert_eq!(short.transaction().outputs[1].value, 59_999_999);
        // A change of exactly the minimum output is enough: one input, change exactly 0.5 KAS.
        let minimum = tx::MIN_KAS_OUTPUT;
        let edge = built(&[
            (1, cash + fee + minimum, p2pk(&buyer), None),
            (2, 1_000_000, p2pk(&buyer), None),
        ]);
        assert_eq!(amounts(&edge), [cash + fee + minimum]);
        assert_eq!(edge.transaction().outputs[1].value, minimum);
        // One sompi under the minimum change is not enough: the next UTXO is taken and lifts it.
        let under = built(&[
            (1, cash + fee + minimum - 1, p2pk(&buyer), None),
            (2, 1_000_000, p2pk(&buyer), None),
        ]);
        assert_eq!(amounts(&under), [cash + fee + minimum - 1, 1_000_000]);
        assert_eq!(under.transaction().outputs[1].value, minimum + 999_999);
        // A UTXO the node lists twice is one UTXO: the second input is the next one, not a repeat.
        let twice = built(&[
            (1, 130_000_000, p2pk(&buyer), None),
            (1, 130_000_000, p2pk(&buyer), None),
            (2, 40_000_000, p2pk(&buyer), None),
        ]);
        assert_eq!(amounts(&twice), [130_000_000, 40_000_000]);
    }

    /// The fee: a typed amount is the command line's (the same inputs give the same document byte
    /// for byte), and `auto` is not. The command line's automatic fee is the minimum relay fee of
    /// the transaction; the page's is that minimum and a tenth more, rounded up, because the
    /// inputs are chosen for the fee and a second input raises the minimum. So the default paths
    /// differ by design, and a person who wants the same bytes on both sides types the fee.
    #[test]
    fn a_typed_fee_gives_the_command_lines_document_and_auto_is_its_minimum_and_a_tenth_more() {
        use impulse_cli::funds::build_with_fee;
        use impulse_core::terms::CreationContext;
        use kaspa_consensus_core::tx::UtxoEntry;
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let pool = pool_of(&t, &[(1, 300_000_000, p2pk(&buyer), None)]);
        let vault = Vault::instantiate_for_creation(
            &t,
            LegIndex::Cash,
            &CreationContext::new(t.terms().network, CREATION),
        )
        .unwrap();
        let candidate = Utxo {
            outpoint: TransactionOutpoint::new(Hash::from_bytes([1; 32]), 0),
            entry: UtxoEntry::new(300_000_000, p2pk(&buyer), 1_000, false, None),
        };
        let cli = |fee: Option<u64>| {
            build_with_fee(
                std::slice::from_ref(&candidate),
                fee,
                &p2pk(&buyer),
                |payment| tx::fund_kas(&t, &vault, payment, CREATION),
            )
            .unwrap()
        };
        // A typed fee: byte for byte the command line's.
        for typed in [400_000u64, 5_000_000] {
            let sdk = fund(&t, &pool, &payer_funding(&buyer, &typed.to_string())).unwrap();
            assert_eq!(sdk.to_json(), cli(Some(typed)).to_json(), "fee {typed}");
        }
        // Auto: the command line's fee is the minimum relay fee; the page's is that and a tenth
        // more, rounded up. The page's document with the command line's fee typed is the command
        // line's document.
        let (theirs, ours) = (
            cli(None),
            fund(&t, &pool, &payer_funding(&buyer, "auto")).unwrap(),
        );
        let minimum = theirs.fee();
        assert_eq!(minimum, tx::min_relay_fee(theirs.masses().fee_mass));
        assert_eq!(ours.fee(), minimum + minimum.div_ceil(10));
        assert_ne!(ours.to_json(), theirs.to_json(), "the default paths differ");
        let same = fund(&t, &pool, &payer_funding(&buyer, &minimum.to_string())).unwrap();
        assert_eq!(same.to_json(), theirs.to_json());
    }

    /// The review of a funding says how the deposit comes back, in the words of the terms: whose
    /// key signs the refund and from when (the expiry in earmarked mode, at once in revocable
    /// mode), that the counterparty and the authority can trigger it too, where it pays, and
    /// what closing the page does to the key when that key lives only in the page.
    #[test]
    fn the_review_of_a_funding_says_how_the_deposit_comes_back_and_what_losing_the_key_does() {
        use crate::review;
        let review_of = |doc: &Value, held: &[[u8; 32]]| {
            let t = fundable_terms_of(doc);
            let buyer = t.terms().buyer_key;
            let pool = pool_of(&t, &[(1, 300_000_000, p2pk(&buyer), None)]);
            let ipst = fund(&t, &pool, &payer_funding(&buyer, "auto")).unwrap();
            let r = review::review(&ipst, &artifacts(), CREATION, &declared(), held).unwrap();
            (t, r)
        };
        let doc = fundable_doc();
        let key = doc["buyer_key"].as_str().unwrap().to_string();
        let held: Vec<[u8; 32]> = vec![crate::json::hex_decode(&key).unwrap().try_into().unwrap()];
        // Earmarked terms with an authority (vector 08), the buyer's key in a wallet of the page.
        let (t, r) = review_of(&doc, &held);
        let refund = crate::funding::destination_text(t.terms().network, &t.terms().buyer_refund);
        let note = r["exit_note"].as_str().unwrap().to_string();
        assert_eq!(
            note,
            format!(
                "Until this trade settles, the only way you can take this deposit back yourself is a refund of the cash leg signed with the buyer's key {key}, from DAA score 425920001 (earmarked funding: the depositor's refund opens after the expiry, DAA score 425920000). That key lives only in a wallet of this page: closing or reloading the page, or wiping the wallet, destroys it, and nothing in this page can bring it back. The seller or the authority can also trigger that refund at any time, and it pays the buyer's refund destination ({refund}) whoever signs it, but nothing makes them."
            )
        );
        assert_eq!(
            r["notes"][0],
            json!(note),
            "the first note, before any warning about the change"
        );
        // The key held elsewhere: the page does not claim to destroy it.
        let (_, elsewhere) = review_of(&doc, &[]);
        let other = elsewhere["exit_note"].as_str().unwrap();
        assert!(
            other.contains("Keep that key until the trade has settled."),
            "{other}"
        );
        assert!(
            !other.contains("lives only in a wallet of this page"),
            "{other}"
        );
        // Revocable terms without an authority: at any time, and the seller alone.
        let mut open = doc.clone();
        open["funding_mode"] = json!("revocable");
        open["authority_key"] = Value::Null;
        let (_, revocable) = review_of(&open, &held);
        let note = revocable["exit_note"].as_str().unwrap();
        assert!(
            note.contains(&format!(
                "{key}, at any time (revocable funding). That key lives"
            )),
            "{note}"
        );
        assert!(
            note.contains(" The seller can also trigger that refund at any time"),
            "{note}"
        );
        assert!(
            !note.contains("authority") && !note.contains("DAA score"),
            "{note}"
        );
    }

    /// The funder is told how long the trade has left to settle: a settle is refused at or after
    /// the expiry, so a deposit funded close to it can only be refunded. The sentence follows the
    /// score the review is made at; a settle's review has none.
    #[test]
    fn the_review_of_a_funding_says_how_long_the_trade_has_left_to_settle() {
        use crate::review;
        let t = fundable_terms();
        let buyer = t.terms().buyer_key;
        let expiry = t.terms().expiry_daa;
        let pool = pool_of(&t, &[(1, 300_000_000, p2pk(&buyer), None)]);
        let ipst = fund(&t, &pool, &payer_funding(&buyer, "auto")).unwrap();
        let window = |daa: u64| -> Vec<String> {
            let r = review::review(&ipst, &artifacts(), daa, &declared(), &[]).unwrap();
            r["notes"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|n| n.as_str())
                .filter(|n| n.starts_with("A settle of this trade can be built only before"))
                .map(str::to_string)
                .collect()
        };
        let sentence = |daa: u64, left: &str, duration: &str| {
            format!(
                "A settle of this trade can be built only before the expiry, DAA score {expiry}: at or after it the settle is refused (TX_EXPIRED). The node is at DAA score {daa}, so this funding, once accepted, has {left} ({duration} at the nominal 10 DAA scores a second; the real rate varies) to be listed by the node and settled. A trade that is not settled by then can only be refunded."
            )
        };
        // Ample time: the figures, in days, hours and minutes as the command line writes them.
        assert_eq!(
            window(CREATION),
            vec![sentence(CREATION, "920000 DAA scores", "about 25 hours")]
        );
        assert_eq!(
            window(expiry - 864_000 * 3),
            vec![sentence(
                expiry - 864_000 * 3,
                "2592000 DAA scores",
                "about 3 days"
            )]
        );
        // Close to the expiry: the same sentence with the short figures, not silence.
        assert_eq!(
            window(expiry - 6_000),
            vec![sentence(
                expiry - 6_000,
                "6000 DAA scores",
                "about 10 minutes"
            )]
        );
        assert_eq!(
            window(expiry - 1),
            vec![sentence(expiry - 1, "1 DAA score", "about 0 minutes")]
        );
        // The note comes after how the deposit comes back, and the review is of the funding alone:
        // a settle's review has neither.
        let r = review::review(&ipst, &artifacts(), CREATION, &declared(), &[]).unwrap();
        let notes: Vec<&str> = r["notes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n.as_str())
            .collect();
        assert!(
            notes[0].starts_with("Until this trade settles, "),
            "{notes:?}"
        );
        assert!(
            notes[1].starts_with("A settle of this trade can be built only before"),
            "{notes:?}"
        );
        assert_eq!(notes.len(), 2);
        let [authorizer, escrow] = asset_leg(&t);
        let cash = (
            3,
            t.terms().cash_leg.amount,
            {
                let vault = Vault::instantiate_existing(&t, LegIndex::Cash).unwrap();
                vault.script_public_key()
            },
            None,
        );
        let fee_coin = (4, 300_000_000, p2pk(&buyer), None);
        let settle_pool = node_reply(&[authorizer, escrow, cash, fee_coin]);
        let settle = settle_from_reply(
            &t,
            &artifacts(),
            &settle_pool,
            &payer_funding(&buyer, "auto"),
            CREATION,
            &declared(),
        )
        .unwrap();
        let sr = review::review(&settle, &artifacts(), CREATION, &declared(), &[]).unwrap();
        assert!(
            sr["notes"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|n| n.as_str())
                .all(|n| !n.starts_with("A settle of this trade")),
            "{:?}",
            sr["notes"]
        );
    }

    #[test]
    fn the_funding_form_is_strict_and_the_change_address_is_read_against_the_terms_network() {
        use serde_json::json;
        let payer = "ab".repeat(32);
        let ok = json!({"payer": payer, "fee": "auto"});
        let f = funding_from_json(&ok).unwrap();
        assert!(f.change.is_none() && f.fee.is_none(), "control");
        assert_eq!(
            funding_from_json(&json!({"payer": payer, "fee": "7"}))
                .unwrap()
                .fee,
            Some(7)
        );
        assert!(
            funding_from_json(&json!({"payer": payer, "fee": "auto", "change": null}))
                .unwrap()
                .change
                .is_none()
        );
        for bad in [
            json!({"payer": payer}),
            json!({"payer": payer, "fee": 7}),
            json!({"payer": payer, "fee": "07"}),
            json!({"payer": payer, "fee": "auto", "change": 5}),
            json!({"payer": payer, "fee": "auto", "other": 1}),
        ] {
            assert_eq!(
                funding_from_json(&bad).err().unwrap().code(),
                "SDK_JSON_FORM",
                "{bad}"
            );
        }
        // The change spk: the payer's key by default; an address of the terms' network otherwise.
        let t = validated();
        let own = funding(None);
        assert_eq!(change_spk(&own, &t).unwrap(), p2pk(&[7; 32]));
        let address = address_of(t.terms().network, &p2pk(&[9; 32])).unwrap();
        let to = Funding {
            change: Some(address),
            ..funding(None)
        };
        assert_eq!(change_spk(&to, &t).unwrap(), p2pk(&[9; 32]));
        let mainnet = address_of(Network::Mainnet, &p2pk(&[9; 32])).unwrap();
        for bad in [mainnet, "nonsense".to_string(), String::new()] {
            let f = Funding {
                change: Some(bad.clone()),
                ..funding(None)
            };
            assert_eq!(
                change_spk(&f, &t).unwrap_err().code(),
                "SDK_JSON_FORM",
                "{bad}"
            );
        }
    }
}
