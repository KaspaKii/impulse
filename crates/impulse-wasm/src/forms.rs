// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The JSON forms of the transaction builders' inputs (I9 phase 2), read strictly like the terms
//! form of `json.rs`: every key present, no other key, u64 values as decimal strings, bytes as
//! lowercase hex. Form only: whether a UTXO is the one a builder needs is the builder's check,
//! with impulse-core's code.
//!
//! A UTXO is the outpoint and the entry a node reports for it. The shape of its `utxo` part is
//! that of an IPST input (spec/IPST.md), so a UTXO read from an IPST's input renders as is.
//!
//! A KCC-20 template travels as the text of its silverscript ABI artifact (the JSON `silverc`
//! writes), carried by the form that needs one, where impulse-core's types hold a template. The
//! artifact is parsed and checked by `Kcc20Template::from_json`, which refuses with
//! `TX_TOKEN_TEMPLATE`, and is bounded here before it is parsed.

use crate::error::{clipped, Failure, SdkError};
use crate::json::{Obj, IDENTIFIER_TYPES};
use impulse_core::terms::Kcc20Owner;
use impulse_core::tx::{
    DirectCash, DirectLegs, FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow,
    RefundSigner, SettleCash, SettleLegs, TokenUtxo, Utxo,
};
use impulse_core::verify::MAX_TOKEN_ARTIFACT_LEN;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry};
use kaspa_consensus_core::Hash;
use serde_json::Value;

/// At most this many fee inputs, token inputs or signatures in one array. A transaction with more
/// is far past the mass cap.
pub(crate) const MAX_ARRAY: usize = 256;

pub(crate) fn script_public_key(mut o: Obj) -> Result<ScriptPublicKey, SdkError> {
    let version = o.number("version", u16::MAX.into())? as u16;
    let script = o.hex("script")?;
    o.finish()?;
    Ok(ScriptPublicKey::from_vec(version, script))
}

pub(crate) fn utxo(mut o: Obj) -> Result<Utxo, SdkError> {
    let transaction_id = o.bytes32("transaction_id")?;
    let index = o.number("index", u32::MAX.into())? as u32;
    let amount = o.u64("amount")?;
    let spk = script_public_key(o.object("script_public_key")?)?;
    let block_daa_score = o.u64("block_daa_score")?;
    let is_coinbase = o.bool("is_coinbase")?;
    let covenant_id = o.nullable("covenant_id", |o, k| o.bytes32(k))?;
    o.finish()?;
    Ok(Utxo {
        outpoint: TransactionOutpoint::new(Hash::from_bytes(transaction_id), index),
        entry: UtxoEntry::new(
            amount,
            spk,
            block_daa_score,
            is_coinbase,
            covenant_id.map(Hash::from_bytes),
        ),
    })
}

fn utxo_at(o: &mut Obj, key: &'static str) -> Result<Utxo, SdkError> {
    utxo(o.object(key)?)
}

pub(crate) fn kcc20_state(mut o: Obj) -> Result<Kcc20State, SdkError> {
    let identifier_type = o.choice("identifier_type", &IDENTIFIER_TYPES)?;
    let identifier = o.bytes32("identifier")?;
    let amount = o.u64("amount")?;
    let is_minter = o.bool("is_minter")?;
    o.finish()?;
    Ok(Kcc20State {
        owner: Kcc20Owner {
            identifier_type,
            identifier,
        },
        amount,
        is_minter,
    })
}

pub(crate) fn token_utxo(mut o: Obj) -> Result<TokenUtxo, SdkError> {
    let utxo = utxo_at(&mut o, "utxo")?;
    let state = kcc20_state(o.object("state")?)?;
    o.finish()?;
    Ok(TokenUtxo { utxo, state })
}

fn array_of<T>(
    o: &mut Obj,
    key: &'static str,
    read: impl Fn(Obj) -> Result<T, SdkError>,
) -> Result<Vec<T>, SdkError> {
    let items = o.array(key)?;
    if items.len() > MAX_ARRAY {
        return o.fail(key, format!("more than {MAX_ARRAY} elements"));
    }
    items
        .into_iter()
        .map(|(path, v)| read(Obj::new(v, &path)?))
        .collect()
}

/// `{ inputs: UtxoJson[], fee: U64String, change: ScriptPublicKeyJson }`.
pub(crate) fn fee_payment(value: &Value) -> Result<FeePayment, SdkError> {
    let mut o = Obj::new(value, "funding")?;
    let inputs = array_of(&mut o, "inputs", utxo)?;
    let fee = o.u64("fee")?;
    let change = script_public_key(o.object("change")?)?;
    o.finish()?;
    Ok(FeePayment {
        inputs,
        fee,
        change,
    })
}

/// A KCC-20 template from the text of its artifact. The text is bounded before it is parsed.
pub(crate) fn template(path: &str, text: &str) -> Result<Kcc20Template, Failure> {
    if text.len() > MAX_TOKEN_ARTIFACT_LEN {
        return Err(SdkError::json(
            path,
            format!(
                "a KCC-20 artifact is at most {MAX_TOKEN_ARTIFACT_LEN} bytes of JSON, got {} bytes starting {:?}",
                text.len(),
                clipped(text)
            ),
        )
        .into());
    }
    Ok(Kcc20Template::from_json(text)?)
}

fn template_at(o: &mut Obj, key: &'static str) -> Result<Kcc20Template, Failure> {
    let path = o.at(key);
    template(&path, o.str(key)?)
}

/// `{ artifact, tokens: TokenUtxoJson[], carrier: U64String, authorizer: U64String }`.
pub(crate) struct DepositIn {
    pub template: Kcc20Template,
    pub deposit: Kcc20Deposit,
}

pub(crate) fn deposit(value: &Value) -> Result<DepositIn, Failure> {
    let mut o = Obj::new(value, "deposit")?;
    let template = template_at(&mut o, "artifact")?;
    let tokens = array_of(&mut o, "tokens", token_utxo)?;
    let carrier = o.u64("carrier")?;
    let authorizer = o.u64("authorizer")?;
    o.finish()?;
    Ok(DepositIn {
        template,
        deposit: Kcc20Deposit {
            tokens,
            carrier,
            authorizer,
        },
    })
}

/// A settle's legs with their templates owned, so that `SettleLegs` can borrow them.
pub(crate) struct SettleIn {
    asset_template: Kcc20Template,
    asset_authorizer: Utxo,
    asset_escrow: Utxo,
    cash: SettleCashIn,
}

enum SettleCashIn {
    Kas(Utxo),
    Kcc20 {
        template: Box<Kcc20Template>,
        authorizer: Utxo,
        escrow: Utxo,
    },
    External,
}

impl SettleIn {
    pub(crate) fn legs(&self) -> SettleLegs<'_> {
        SettleLegs {
            asset_authorizer: self.asset_authorizer.clone(),
            asset_escrow: self.asset_escrow.clone(),
            asset_token: &self.asset_template,
            cash: match &self.cash {
                SettleCashIn::Kas(vault) => SettleCash::Kas {
                    vault: vault.clone(),
                },
                SettleCashIn::Kcc20 {
                    template,
                    authorizer,
                    escrow,
                } => SettleCash::Kcc20 {
                    authorizer: authorizer.clone(),
                    escrow: escrow.clone(),
                    token: template.as_ref(),
                },
                SettleCashIn::External => SettleCash::External,
            },
        }
    }
}

/// `{ asset_artifact, asset_authorizer, asset_escrow, cash }` with `cash` one of
/// `{ kind: "kas", vault }`, `{ kind: "kcc20", artifact, authorizer, escrow }`,
/// `{ kind: "external" }`.
pub(crate) fn settle_legs(value: &Value) -> Result<SettleIn, Failure> {
    #[derive(Clone, Copy)]
    enum Tag {
        Kas,
        Kcc20,
        External,
    }
    let mut o = Obj::new(value, "legs")?;
    let asset_template = template_at(&mut o, "asset_artifact")?;
    let asset_authorizer = utxo_at(&mut o, "asset_authorizer")?;
    let asset_escrow = utxo_at(&mut o, "asset_escrow")?;
    let mut c = o.object("cash")?;
    let cash = match c.choice(
        "kind",
        &[
            ("kas", Tag::Kas),
            ("kcc20", Tag::Kcc20),
            ("external", Tag::External),
        ],
    )? {
        Tag::Kas => SettleCashIn::Kas(utxo_at(&mut c, "vault")?),
        Tag::Kcc20 => SettleCashIn::Kcc20 {
            template: Box::new(template_at(&mut c, "artifact")?),
            authorizer: utxo_at(&mut c, "authorizer")?,
            escrow: utxo_at(&mut c, "escrow")?,
        },
        Tag::External => SettleCashIn::External,
    };
    c.finish()?;
    o.finish()?;
    Ok(SettleIn {
        asset_template,
        asset_authorizer,
        asset_escrow,
        cash,
    })
}

/// A Direct trade's legs with their templates owned.
pub(crate) struct DirectIn {
    asset_template: Kcc20Template,
    asset: TokenUtxo,
    cash: DirectCashIn,
}

enum DirectCashIn {
    Kas(Utxo),
    Kcc20 {
        template: Box<Kcc20Template>,
        token: TokenUtxo,
    },
}

impl DirectIn {
    pub(crate) fn legs(&self) -> DirectLegs<'_> {
        DirectLegs {
            asset: self.asset.clone(),
            asset_token: &self.asset_template,
            cash: match &self.cash {
                DirectCashIn::Kas(utxo) => DirectCash::Kas(utxo.clone()),
                DirectCashIn::Kcc20 { template, token } => DirectCash::Kcc20 {
                    token: token.clone(),
                    template: template.as_ref(),
                },
            },
        }
    }
}

/// `{ asset_artifact, asset: TokenUtxoJson, cash }` with `cash` one of
/// `{ kind: "kas", utxo }`, `{ kind: "kcc20", artifact, token }`.
pub(crate) fn direct_legs(value: &Value) -> Result<DirectIn, Failure> {
    #[derive(Clone, Copy)]
    enum Tag {
        Kas,
        Kcc20,
    }
    let mut o = Obj::new(value, "legs")?;
    let asset_template = template_at(&mut o, "asset_artifact")?;
    let asset = token_utxo(o.object("asset")?)?;
    let mut c = o.object("cash")?;
    let cash = match c.choice("kind", &[("kas", Tag::Kas), ("kcc20", Tag::Kcc20)])? {
        Tag::Kas => DirectCashIn::Kas(utxo_at(&mut c, "utxo")?),
        Tag::Kcc20 => DirectCashIn::Kcc20 {
            template: Box::new(template_at(&mut c, "artifact")?),
            token: token_utxo(c.object("token")?)?,
        },
    };
    c.finish()?;
    o.finish()?;
    Ok(DirectIn {
        asset_template,
        asset,
        cash,
    })
}

/// A refund's escrowed token with its template owned.
pub(crate) struct EscrowIn {
    template: Kcc20Template,
    utxo: Utxo,
    amount: u64,
    is_minter: bool,
}

impl EscrowIn {
    pub(crate) fn escrow(&self) -> RefundEscrow<'_> {
        RefundEscrow {
            utxo: self.utxo.clone(),
            amount: self.amount,
            is_minter: self.is_minter,
            template: &self.template,
        }
    }
}

/// `{ artifact, utxo, amount: U64String, is_minter }`.
pub(crate) fn refund_escrow(value: &Value) -> Result<EscrowIn, Failure> {
    let mut o = Obj::new(value, "escrow")?;
    let template = template_at(&mut o, "artifact")?;
    let utxo = utxo_at(&mut o, "utxo")?;
    let amount = o.u64("amount")?;
    let is_minter = o.bool("is_minter")?;
    o.finish()?;
    Ok(EscrowIn {
        template,
        utxo,
        amount,
        is_minter,
    })
}

pub(crate) fn refund_signer(name: &str) -> Result<RefundSigner, SdkError> {
    match name {
        "depositor" => Ok(RefundSigner::Depositor),
        "counterparty" => Ok(RefundSigner::Counterparty),
        "authority" => Ok(RefundSigner::Authority),
        _ => Err(SdkError::json(
            "signer",
            format!(
                "{} is not one of depositor, counterparty, authority",
                crate::error::shown(name)
            ),
        )),
    }
}

/// The templates the terms check takes: `{ asset: string, cash: string | null }`.
pub(crate) fn artifacts(value: &Value) -> Result<(Kcc20Template, Option<Kcc20Template>), Failure> {
    let mut o = Obj::new(value, "artifacts")?;
    let asset = template_at(&mut o, "asset")?;
    let cash_path = o.at("cash");
    let cash = o
        .nullable("cash", |o, k| o.str(k))?
        .map(|text| template(&cash_path, text))
        .transpose()?;
    o.finish()?;
    Ok((asset, cash))
}

/// Signatures to fill: `[{ input: number, signature: Hex }]`.
pub(crate) fn signatures(value: &Value) -> Result<Vec<(usize, Vec<u8>)>, SdkError> {
    let Value::Array(items) = value else {
        return Err(SdkError::json("signatures", "expected an array"));
    };
    if items.len() > MAX_ARRAY {
        return Err(SdkError::json(
            "signatures",
            format!("more than {MAX_ARRAY} elements"),
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mut o = Obj::new(v, &format!("signatures[{i}]"))?;
            let input = o.number("input", u32::MAX.into())? as usize;
            let signature = o.hex("signature")?;
            o.finish()?;
            Ok((input, signature))
        })
        .collect()
}
