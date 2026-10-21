// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The template v2 surface of the SDK (I16, spec/V2.md 6.5), beside the v1 one and with its
//! argument forms: terms v2 (JSON form of spec/V2.md 5.4, encode, decode, hash, structure and
//! creation checks), every leg's vault address, the four v2 builders (fund a KAS leg, fund a
//! KCC-20 leg, settle every leg, refund one leg), the partially signed transaction of version 2
//! and the v2 constants and code lists. Every operation is impulse-core's `v2` module; the value
//! cap of terms v2 (`value::check_v2`) runs before every builder and before the terms check.
//!
//! Keyless: nothing here signs, generates or holds a private key. A signature arrives as 65 bytes
//! a caller made elsewhere and is verified before it is stored.

use crate::api::JsSignedTransaction;
use crate::error::{js, Failure, SdkError};
use crate::forms;
use crate::json::{hex, Obj, IDENTIFIER_TYPES};
use crate::{
    bytes_arg, index_arg, json_arg, json_arg_tx, text_arg, u64_arg, SHORT_BYTES, TX_BYTES,
};
use impulse_core::terms::{FundingMode, IdentifierType, Kcc20Token, Leg, LegKind, Network};
use impulse_core::tx::{self, FeePayment, Kcc20Template, Utxo};
use impulse_core::v2::{
    self as v2, IpstV2, IpstV2Kind, LegV2, Partial, RefundSignerV2, SettleLeg, TermsV2,
    TokenEscrow, ValidatedTermsV2, VaultV2, MAX_LEGS, TEMPLATE_V2_ERROR_CODES,
    TERMS_V2_ERROR_CODES, TX_V2_ERROR_CODES, VERIFY_V2_ERROR_CODES,
};
use kaspa_consensus_core::tx::Transaction;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

/// At most this many UTF-16 code units in an IPST text, as for version 1.
const MAX_IPST_TEXT: u32 = 1 << 23;

const NETWORKS: [(&str, Network); 2] =
    [("mainnet", Network::Mainnet), ("testnet", Network::Testnet)];

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
/** A destination of terms v2 (spec/V2.md 5.2): a KCC-20 owner, or for a KAS leg a Schnorr P2PK key (pubkey) or a P2SH script hash. */
export interface DestinationV2Json {
  identifier_type: "pubkey" | "script_hash" | "covenant_id";
  identifier: Hex;
}

/** One leg of terms v2. */
export interface LegV2Json {
  depositor_key: Hex;
  asset: LegJson;
  delivery: DestinationV2Json;
  refund: DestinationV2Json;
}

/** The JSON form of terms v2 (spec/V2.md 5.4). Every key is required. */
export interface TermsV2Json {
  version: number;
  network: Network;
  nonce: U64String;
  authority_key: Hex | null;
  legs: LegV2Json[];
  earliest_daa: U64String | null;
  expiry_daa: U64String;
  funding_mode: "revocable" | "earmarked";
  partial: { lot_count: U64String; min_lot: U64String } | null;
  trade_ref: Hex;
}

/** One leg of a v2 settle, in leg order: a KAS leg's vault UTXO, or a KCC-20 leg's authorizer and escrowed token with its artifact. */
export type SettleLegV2Json =
  | { kind: "kas"; vault: UtxoJson }
  | { kind: "kcc20"; artifact: string; authorizer: UtxoJson; escrow: UtxoJson; amount: U64String };

/** Who signs a v2 refund: the depositor of leg n (its number), or the authority. */
export type RefundSignerV2 = number | "authority";

/** The token artifacts the v2 terms check takes; each KCC-20 leg uses the one whose template it names. */
export type ArtifactsV2Json = string[];

/** CAP_V2 per mass dimension, in grams (spec/V2.md 6.2). */
export interface CapsV2Json {
  compute: U64String;
  storage: U64String;
  transient: U64String;
}

/** Which v2 builder makes an IPST of version 2. */
export type IpstV2KindJson =
  | { builder: "fund_kas"; leg: number }
  | { builder: "fund_kcc20"; leg: number }
  | { builder: "settle" }
  | { builder: "tranche"; lots: U64String }
  | { builder: "refund"; leg: number; signer: RefundSignerV2; with_token: boolean };

/** The quantity a v2 settle states (spec/V2.md 4.6). */
export interface QuantitiesJson {
  total_lots: U64String;
  lots: U64String;
  cumulative_lots: U64String;
  legs: { leg: number; moved: U64String; cumulative: U64String; total: U64String }[];
}

/** What the v2 terms check found. */
export interface TermsMatchV2Json {
  kind: IpstV2KindJson;
  fee: U64String;
  change: { value: U64String; script_public_key: ScriptPublicKeyJson } | null;
}
"#;

fn fail(e: impl Into<Failure>) -> JsValue {
    js(e.into())
}

fn to_js(value: &Value) -> Result<JsValue, JsValue> {
    js_sys::JSON::parse(&value.to_string())
}

fn dec(n: u64) -> Value {
    Value::String(n.to_string())
}

// =============================================================================================
// JSON form of terms v2
// =============================================================================================

fn destination(mut o: Obj) -> Result<v2::DestinationV2, SdkError> {
    let d = v2::DestinationV2 {
        identifier_type: o.choice("identifier_type", &IDENTIFIER_TYPES)?,
        identifier: o.bytes32("identifier")?,
    };
    o.finish()?;
    Ok(d)
}

#[derive(Clone, Copy)]
enum LegTag {
    Kas,
    Kcc20,
    External,
}

fn asset(mut o: Obj) -> Result<Leg, SdkError> {
    let tag = o.choice(
        "kind",
        &[
            ("kas", LegTag::Kas),
            ("kcc20", LegTag::Kcc20),
            ("external", LegTag::External),
        ],
    )?;
    let kind = match tag {
        LegTag::Kas => LegKind::Kas,
        LegTag::External => LegKind::External,
        LegTag::Kcc20 => LegKind::Kcc20(Kcc20Token {
            covenant_id: o.bytes32("covenant_id")?,
            template_hash: o.bytes32("template_hash")?,
            template_prefix_len: o.number("template_prefix_len", u32::MAX.into())? as u32,
            template_suffix_len: o.number("template_suffix_len", u32::MAX.into())? as u32,
        }),
    };
    let amount = o.u64("amount")?;
    o.finish()?;
    Ok(Leg { kind, amount })
}

fn leg(mut o: Obj) -> Result<LegV2, SdkError> {
    let l = LegV2 {
        depositor_key: o.bytes32("depositor_key")?,
        asset: asset(o.object("asset")?)?,
        delivery: destination(o.object("delivery")?)?,
        refund: destination(o.object("refund")?)?,
    };
    o.finish()?;
    Ok(l)
}

/// Parses the JSON form of terms v2. Form only: the result may still fail the structure checks.
/// A list longer than `MAX_LEGS` is refused here (`SDK_JSON_FORM`), before any leg is read.
pub(crate) fn terms_from_json(value: &Value) -> Result<TermsV2, SdkError> {
    let mut o = Obj::new(value, "terms")?;
    let version = o.number("version", u8::MAX.into())? as u8;
    let network = o.choice("network", &NETWORKS)?;
    let nonce = o.u64("nonce")?;
    let authority_key = o.nullable("authority_key", |o, k| o.bytes32(k))?;
    let items = o.array("legs")?;
    if items.len() > MAX_LEGS {
        return o.fail("legs", format!("more than {MAX_LEGS} legs"));
    }
    let legs = items
        .into_iter()
        .map(|(path, v)| leg(Obj::new(v, &path)?))
        .collect::<Result<Vec<_>, _>>()?;
    let earliest_daa = o.nullable("earliest_daa", |o, k| o.u64(k))?;
    let expiry_daa = o.u64("expiry_daa")?;
    let funding_mode = o.choice(
        "funding_mode",
        &[
            ("revocable", FundingMode::Revocable),
            ("earmarked", FundingMode::Earmarked),
        ],
    )?;
    let partial = o.nullable("partial", |o, k| {
        let mut p = o.object(k)?;
        let partial = Partial {
            lot_count: p.u64("lot_count")?,
            min_lot: p.u64("min_lot")?,
        };
        p.finish()?;
        Ok(partial)
    })?;
    let trade_ref = o.bytes32("trade_ref")?;
    o.finish()?;
    Ok(TermsV2 {
        version,
        network,
        nonce,
        authority_key,
        legs,
        earliest_daa,
        expiry_daa,
        funding_mode,
        partial,
        trade_ref,
    })
}

fn id_name(t: IdentifierType) -> &'static str {
    match t {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

/// The JSON form of terms v2. serde_json orders object keys by name; JavaScript reads them all
/// the same.
pub(crate) fn terms_to_json(t: &TermsV2) -> Value {
    let destination = |d: &v2::DestinationV2| json!({"identifier_type": id_name(d.identifier_type), "identifier": hex(&d.identifier)});
    let legs: Vec<Value> = t
        .legs
        .iter()
        .map(|l| {
            let asset = match &l.asset.kind {
                LegKind::Kcc20(token) => json!({
                    "kind": "kcc20",
                    "covenant_id": hex(&token.covenant_id),
                    "template_hash": hex(&token.template_hash),
                    "template_prefix_len": token.template_prefix_len,
                    "template_suffix_len": token.template_suffix_len,
                    "amount": dec(l.asset.amount),
                }),
                LegKind::Kas => json!({"kind": "kas", "amount": dec(l.asset.amount)}),
                LegKind::External => json!({"kind": "external", "amount": dec(l.asset.amount)}),
            };
            json!({
                "depositor_key": hex(&l.depositor_key),
                "asset": asset,
                "delivery": destination(&l.delivery),
                "refund": destination(&l.refund),
            })
        })
        .collect();
    json!({
        "version": t.version,
        "network": crate::json::network_name(t.network),
        "nonce": dec(t.nonce),
        "authority_key": t.authority_key.map(|k| hex(&k)),
        "legs": legs,
        "earliest_daa": t.earliest_daa.map(dec),
        "expiry_daa": dec(t.expiry_daa),
        "funding_mode": match t.funding_mode {
            FundingMode::Revocable => "revocable",
            FundingMode::Earmarked => "earmarked",
        },
        "partial": t.partial.map(|p| json!({"lot_count": dec(p.lot_count), "min_lot": dec(p.min_lot)})),
        "trade_ref": hex(&t.trade_ref),
    })
}

// =============================================================================================
// Operations (host-testable: no JavaScript in them)
// =============================================================================================

/// The artifacts the caller gave, parsed: each KCC-20 leg uses the one whose template it names.
pub(crate) struct Artifacts(Vec<Kcc20Template>);

impl Artifacts {
    pub(crate) fn from_json(value: &Value) -> Result<Self, Failure> {
        let Value::Array(items) = value else {
            return Err(SdkError::json("artifacts", "expected an array of artifact texts").into());
        };
        if items.len() > MAX_LEGS {
            return Err(
                SdkError::json("artifacts", format!("more than {MAX_LEGS} artifacts")).into(),
            );
        }
        items
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let path = format!("artifacts[{i}]");
                let text = v
                    .as_str()
                    .ok_or_else(|| SdkError::json(&path, "expected a string"))?;
                forms::template(&path, text)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// The template of KCC-20 leg `leg` (`TX_TOKEN_TEMPLATE` if none was given).
    pub(crate) fn of(&self, leg: usize, token: &Kcc20Token) -> Result<&Kcc20Template, Failure> {
        self.0
            .iter()
            .find(|t| t.check_token(token).is_ok())
            .ok_or_else(|| {
                tx::TxError::TokenTemplate {
                    reason: format!("no artifact given for KCC-20 leg {leg}"),
                }
                .into()
            })
    }

    /// The templates of the KCC-20 legs in leg order.
    pub(crate) fn for_check(&self, t: &TermsV2) -> Result<Vec<&Kcc20Template>, Failure> {
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

fn check_value(t: &TermsV2, value: &Value, native_kas: u64) -> Result<(), Failure> {
    crate::value::check_v2(t, &crate::value::declaration_from_json(value)?, native_kas)?;
    Ok(())
}

fn leg_in(t: &TermsV2, leg: usize) -> Result<(), Failure> {
    if leg >= t.legs.len() {
        return Err(v2::V2Error::TemplateLegIndex {
            value: leg as i64,
            leg_count: t.legs.len(),
        }
        .into());
    }
    Ok(())
}

/// Every leg's funding address, after the value cap and the creation checks.
pub(crate) fn vault_addresses(
    terms: &ValidatedTermsV2,
    ctx: &Value,
    value: &Value,
) -> Result<Vec<String>, Failure> {
    let ctx = crate::json::context_from_json(ctx)?;
    check_value(terms.terms(), value, 0)?;
    (0..terms.terms().legs.len())
        .map(|i| {
            Ok(v2::vault_address(&VaultV2::instantiate_for_creation(
                terms, i, &ctx,
            )?))
        })
        .collect()
}

/// `v2::fund_kas` for `leg`.
pub(crate) fn fund_kas(
    terms: &ValidatedTermsV2,
    leg: usize,
    ctx: &Value,
    funding: &Value,
    value: &Value,
) -> Result<IpstV2, Failure> {
    leg_in(terms.terms(), leg)?;
    let ctx = crate::json::context_from_json(ctx)?;
    let funding = forms::fee_payment(funding)?;
    check_value(terms.terms(), value, funding.fee)?;
    let vault = VaultV2::instantiate_for_creation(terms, leg, &ctx)?;
    Ok(v2::fund_kas(terms, &vault, &funding, ctx.creation_daa)?)
}

/// `v2::fund_kcc20` for `leg`; `deposit` is the v1 deposit form (artifact, tokens, carrier,
/// authorizer).
pub(crate) fn fund_kcc20(
    terms: &ValidatedTermsV2,
    leg: usize,
    ctx: &Value,
    deposit: &Value,
    funding: &Value,
    value: &Value,
) -> Result<IpstV2, Failure> {
    leg_in(terms.terms(), leg)?;
    let ctx = crate::json::context_from_json(ctx)?;
    let deposit = forms::deposit(deposit)?;
    let funding = forms::fee_payment(funding)?;
    let native_kas = deposit
        .deposit
        .carrier
        .saturating_add(deposit.deposit.authorizer)
        .max(funding.fee);
    check_value(terms.terms(), value, native_kas)?;
    let vault = VaultV2::instantiate_for_creation(terms, leg, &ctx)?;
    Ok(v2::fund_kcc20(
        terms,
        &vault,
        &deposit.template,
        &deposit.deposit,
        &funding,
        ctx.creation_daa,
    )?)
}

/// A settle leg with its template owned.
enum SettleIn {
    Kas(Utxo),
    Kcc20 {
        template: Box<Kcc20Template>,
        authorizer: Utxo,
        escrow: Utxo,
        amount: u64,
    },
}

fn settle_legs(value: &Value) -> Result<Vec<SettleIn>, Failure> {
    #[derive(Clone, Copy)]
    enum Tag {
        Kas,
        Kcc20,
    }
    let Value::Array(items) = value else {
        return Err(SdkError::json("legs", "expected an array, one element per leg").into());
    };
    if items.len() > MAX_LEGS {
        return Err(SdkError::json("legs", format!("more than {MAX_LEGS} legs")).into());
    }
    items
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mut o = Obj::new(v, &format!("legs[{i}]"))?;
            let leg = match o.choice("kind", &[("kas", Tag::Kas), ("kcc20", Tag::Kcc20)])? {
                Tag::Kas => SettleIn::Kas(forms::utxo(o.object("vault")?)?),
                Tag::Kcc20 => {
                    let path = o.at("artifact");
                    SettleIn::Kcc20 {
                        template: Box::new(forms::template(&path, o.str("artifact")?)?),
                        authorizer: forms::utxo(o.object("authorizer")?)?,
                        escrow: forms::utxo(o.object("escrow")?)?,
                        amount: o.u64("amount")?,
                    }
                }
            };
            o.finish()?;
            Ok(leg)
        })
        .collect()
}

/// `v2::settle`, or with `lots` `v2::settle_tranche`.
pub(crate) fn settle(
    terms: &ValidatedTermsV2,
    lots: Option<u64>,
    legs: &Value,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<IpstV2, Failure> {
    let owned = settle_legs(legs)?;
    let funding = forms::fee_payment(funding)?;
    check_value(terms.terms(), value, funding.fee)?;
    let legs: Vec<SettleLeg> = owned
        .iter()
        .map(|l| match l {
            SettleIn::Kas(vault) => SettleLeg::Kas {
                vault: vault.clone(),
            },
            SettleIn::Kcc20 {
                template,
                authorizer,
                escrow,
                amount,
            } => SettleLeg::Kcc20 {
                authorizer: authorizer.clone(),
                escrow: TokenEscrow {
                    utxo: escrow.clone(),
                    amount: *amount,
                    template: template.as_ref(),
                },
            },
        })
        .collect();
    Ok(match lots {
        Some(lots) => v2::settle_tranche(terms, &legs, lots, &funding, current_daa)?,
        None => v2::settle(terms, &legs, &funding, current_daa)?,
    })
}

/// `RefundSignerV2` from `number | "authority"`.
pub(crate) fn refund_signer(value: &Value) -> Result<RefundSignerV2, SdkError> {
    match value {
        Value::String(s) if s == "authority" => Ok(RefundSignerV2::Authority),
        Value::Number(n) => n
            .as_u64()
            .filter(|n| *n < MAX_LEGS as u64)
            .map(|n| RefundSignerV2::Depositor(n as usize))
            .ok_or_else(|| SdkError::json("signer", "a leg number below MAX_LEGS, or authority")),
        _ => Err(SdkError::json(
            "signer",
            "expected a leg number (its depositor signs) or \"authority\"",
        )),
    }
}

/// `v2::refund`. `escrow` is None for a refund of the vault UTXO alone.
pub(crate) fn refund(
    terms: &ValidatedTermsV2,
    leg: usize,
    signer: &Value,
    vault_utxo: &Value,
    escrow: Option<&Value>,
    funding: &Value,
    value: &Value,
) -> Result<IpstV2, Failure> {
    leg_in(terms.terms(), leg)?;
    let signer = refund_signer(signer)?;
    let vault_utxo = forms::utxo(Obj::new(vault_utxo, "vault_utxo")?)?;
    let escrow = escrow.map(forms::refund_escrow).transpose()?;
    let funding: FeePayment = forms::fee_payment(funding)?;
    check_value(terms.terms(), value, funding.fee)?;
    Ok(v2::refund(
        terms,
        leg,
        signer,
        &vault_utxo,
        escrow.as_ref().map(|e| e.escrow()).as_ref(),
        &funding,
    )?)
}

/// An IPST of version 2 from its text. Version 1 is `IPST_UNSUPPORTED_VERSION`: `Ipst.fromJson`
/// reads it.
pub(crate) fn ipst_from_json(text: &str) -> Result<IpstV2, Failure> {
    match v2::read_ipst(text)? {
        v2::AnyIpst::V2(ipst) => Ok(*ipst),
        v2::AnyIpst::V1(_) => Err(tx::TxError::IpstUnsupportedVersion { version: 1 }.into()),
    }
}

fn signer_json(s: RefundSignerV2) -> Value {
    match s {
        RefundSignerV2::Depositor(j) => json!(j),
        RefundSignerV2::Authority => json!("authority"),
    }
}

pub(crate) fn kind_json(kind: IpstV2Kind) -> Value {
    match kind {
        IpstV2Kind::FundKas { leg } => json!({"builder": "fund_kas", "leg": leg}),
        IpstV2Kind::FundKcc20 { leg } => json!({"builder": "fund_kcc20", "leg": leg}),
        IpstV2Kind::Settle => json!({"builder": "settle"}),
        IpstV2Kind::Tranche { lots } => json!({"builder": "tranche", "lots": dec(lots)}),
        IpstV2Kind::Refund {
            leg,
            signer,
            with_token,
        } => json!({
            "builder": "refund",
            "leg": leg,
            "signer": signer_json(signer),
            "with_token": with_token,
        }),
    }
}

/// `IpstV2::verify_against_terms` after the value cap (the fee the document pays counts), as
/// JSON.
pub(crate) fn verify_against_terms(
    ipst: &IpstV2,
    artifacts: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Value, Failure> {
    let artifacts = Artifacts::from_json(artifacts)?;
    let templates = artifacts.for_check(ipst.terms().terms())?;
    check_value(ipst.terms().terms(), value, ipst.fee())?;
    let m = ipst.verify_against_terms(&templates, current_daa)?;
    Ok(json!({
        "kind": kind_json(m.kind),
        "fee": dec(m.fee),
        "change": m.change.map(|o| json!({
            "value": dec(o.value),
            "script_public_key": crate::ops::spk_json(&o.script_public_key),
        })),
    }))
}

pub(crate) fn slots_json(ipst: &IpstV2) -> Value {
    let opt = |b: Option<&[u8]>| b.map_or(Value::Null, |b| Value::String(hex(b)));
    Value::Array(
        ipst.slots()
            .iter()
            .enumerate()
            .map(|(input, s)| {
                json!({
                    "input": input,
                    "signer": opt(s.signer().as_ref().map(|k| k.as_slice())),
                    "sighash": opt(s.sighash().as_ref().map(|k| k.as_slice())),
                    "signature": opt(s.signature().as_ref().map(|k| k.as_slice())),
                })
            })
            .collect(),
    )
}

pub(crate) fn masses_json(ipst: &IpstV2) -> Value {
    let m = ipst.masses();
    json!({
        "compute": dec(m.compute),
        "transient": dec(m.transient),
        "storage": dec(m.storage),
        "fee_mass": dec(m.fee_mass),
        "min_relay_fee": dec(tx::min_relay_fee(m.fee_mass)),
    })
}

pub(crate) fn assemble(ipst: &IpstV2, signatures: &Value) -> Result<Transaction, Failure> {
    let signatures = forms::signatures(signatures)?;
    let pairs: Vec<(usize, &[u8])> = signatures
        .iter()
        .map(|(input, sig)| (*input, sig.as_slice()))
        .collect();
    Ok(ipst.assemble(&pairs)?)
}

pub(crate) fn caps_json(network: Network) -> Value {
    let c = v2::caps(network);
    json!({
        "compute": dec(c.compute),
        "storage": dec(c.storage),
        "transient": dec(c.transient),
    })
}

// =============================================================================================
// Bindings
// =============================================================================================

/// impulse_core::v2::TermsV2: plain terms v2, anything that decodes. Run `validateStructure`
/// before using them for anything else.
#[wasm_bindgen(js_name = TermsV2)]
pub struct JsTermsV2 {
    inner: TermsV2,
}

#[wasm_bindgen(js_class = TermsV2)]
impl JsTermsV2 {
    /// Parses the JSON form of terms v2 (spec/V2.md 5.4). Form only (`SDK_JSON_FORM`).
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        #[wasm_bindgen(unchecked_param_type = "TermsV2Json")] json: JsValue,
    ) -> Result<JsTermsV2, JsValue> {
        // Terms v2 hold a list of legs, so the reader takes arrays.
        let value = json_arg_tx(&json, "terms")?;
        Ok(JsTermsV2 {
            inner: terms_from_json(&value).map_err(js)?,
        })
    }

    /// The JSON form.
    #[wasm_bindgen(js_name = toJson, unchecked_return_type = "TermsV2Json")]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        to_js(&terms_to_json(&self.inner))
    }

    /// `TermsV2::decode`: canonical bytes only.
    pub fn decode(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: JsValue,
    ) -> Result<JsTermsV2, JsValue> {
        let bytes = bytes_arg(&bytes, "bytes", TX_BYTES)?;
        Ok(JsTermsV2 {
            inner: TermsV2::decode(&bytes).map_err(fail)?,
        })
    }

    /// `TermsV2::encode`: the canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.encode().map_err(fail)
    }

    /// blake2b-256 keyed with `Impulse/terms/v2` over the canonical bytes.
    #[wasm_bindgen(js_name = termsHash)]
    pub fn terms_hash(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.terms_hash().map(|h| h.to_vec()).map_err(fail)
    }

    /// The structure checks of spec/V2.md 5.3. These terms stay usable.
    #[wasm_bindgen(js_name = validateStructure)]
    pub fn validate_structure(&self) -> Result<JsValidatedTermsV2, JsValue> {
        Ok(JsValidatedTermsV2 {
            inner: self.inner.clone().validate_structure().map_err(fail)?,
        })
    }
}

/// impulse_core::v2::ValidatedTermsV2: terms v2 that passed the structure checks. The v2
/// builders are its methods, so they work from checked terms only.
#[wasm_bindgen(js_name = ValidatedTermsV2)]
pub struct JsValidatedTermsV2 {
    inner: ValidatedTermsV2,
}

#[wasm_bindgen(js_class = ValidatedTermsV2)]
impl JsValidatedTermsV2 {
    /// Canonical bytes, then the structure checks.
    pub fn decode(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: JsValue,
    ) -> Result<JsValidatedTermsV2, JsValue> {
        let bytes = bytes_arg(&bytes, "bytes", TX_BYTES)?;
        Ok(JsValidatedTermsV2 {
            inner: ValidatedTermsV2::decode(&bytes).map_err(fail)?,
        })
    }

    pub fn terms(&self) -> JsTermsV2 {
        JsTermsV2 {
            inner: self.inner.terms().clone(),
        }
    }

    pub fn canonical(&self) -> Vec<u8> {
        self.inner.canonical().to_vec()
    }

    #[wasm_bindgen(js_name = termsHash)]
    pub fn terms_hash(&self) -> Vec<u8> {
        self.inner.terms_hash().to_vec()
    }

    /// The creation checks (v1's, unchanged).
    #[wasm_bindgen(js_name = validateCreation)]
    pub fn validate_creation(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
    ) -> Result<(), JsValue> {
        let ctx = crate::json::context_from_json(&json_arg(&context, "context")?).map_err(js)?;
        self.inner.validate_creation(&ctx).map_err(fail)
    }

    /// MIN_V2(plurality, O) of these terms (spec/V2.md 6.2): 1 for a KAS output, 2 for a token.
    #[wasm_bindgen(js_name = minV2, unchecked_return_type = "U64String")]
    pub fn min_v2(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] plurality: JsValue,
    ) -> Result<String, JsValue> {
        let p = index_arg(&plurality, "plurality")?;
        if !(1..=2).contains(&p) {
            return Err(js(SdkError::json("plurality", "1 (KAS) or 2 (a token)")));
        }
        Ok(v2::min_v2(self.inner.terms(), p as u64).to_string())
    }

    /// Every leg's funding address, in leg order, after the value cap and the creation checks.
    #[wasm_bindgen(js_name = vaultAddresses, unchecked_return_type = "string[]")]
    pub fn vault_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsValue, JsValue> {
        let (context, value) = (json_arg(&context, "context")?, json_arg(&value, "value")?);
        let addresses = vault_addresses(&self.inner, &context, &value).map_err(js)?;
        to_js(&json!(addresses))
    }

    /// `v2::fund_kas` for KAS leg `leg`.
    #[wasm_bindgen(js_name = fundKas)]
    pub fn fund_kas(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let leg = index_arg(&leg, "leg")?;
        let (context, funding, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        Ok(JsIpstV2 {
            inner: fund_kas(&self.inner, leg, &context, &funding, &value).map_err(js)?,
        })
    }

    /// `v2::fund_kcc20` for KCC-20 leg `leg`.
    #[wasm_bindgen(js_name = fundKcc20)]
    pub fn fund_kcc20(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Kcc20DepositJson")] deposit: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let leg = index_arg(&leg, "leg")?;
        let (context, deposit, funding, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&deposit, "deposit")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        Ok(JsIpstV2 {
            inner: fund_kcc20(&self.inner, leg, &context, &deposit, &funding, &value)
                .map_err(js)?,
        })
    }

    /// `v2::settle`: every leg in one transaction.
    pub fn settle(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SettleLegV2Json[]")] legs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (legs, funding, value) = (
            json_arg_tx(&legs, "legs")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        Ok(JsIpstV2 {
            inner: settle(&self.inner, None, &legs, &funding, daa, &value).map_err(js)?,
        })
    }

    /// `v2::settle_tranche`: `lots` whole lots of every leg now (spec/V2.md 4.3 and 4.4), every
    /// vault continuing as its covenant with the rest. All lots the escrows hold is the final
    /// layout. The vault UTXOs of a tranche carry covenant IDs (`TX_LINEAGE`); the lots are within
    /// what every escrow holds and min_lot (`TX_TRANCHE`); the legs hold the same number of lots
    /// (`TX_LEGS_OUT_OF_STEP`).
    #[wasm_bindgen(js_name = settleTranche)]
    pub fn settle_tranche(
        &self,
        #[wasm_bindgen(unchecked_param_type = "U64String | bigint")] lots: JsValue,
        #[wasm_bindgen(unchecked_param_type = "SettleLegV2Json[]")] legs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let lots = u64_arg(&lots, "lots")?;
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (legs, funding, value) = (
            json_arg_tx(&legs, "legs")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        Ok(JsIpstV2 {
            inner: settle(&self.inner, Some(lots), &legs, &funding, daa, &value).map_err(js)?,
        })
    }

    /// The quantity a settle of `lots` lots states on a lineage that has moved `priorLots`
    /// (spec/V2.md 4.6): the cumulative lots, and per leg what the transaction moves, the
    /// cumulative and the terms total. `TX_TRANCHE` if the cumulative passes the lot count.
    #[wasm_bindgen(unchecked_return_type = "QuantitiesJson")]
    pub fn quantities(
        &self,
        #[wasm_bindgen(unchecked_param_type = "U64String | bigint")] lots: JsValue,
        #[wasm_bindgen(js_name = priorLots, unchecked_param_type = "U64String | bigint")]
        prior_lots: JsValue,
    ) -> Result<JsValue, JsValue> {
        let (lots, prior) = (u64_arg(&lots, "lots")?, u64_arg(&prior_lots, "priorLots")?);
        let (cumulative, legs) = v2::quantities(&self.inner, lots, prior).map_err(fail)?;
        to_js(&json!({
            "total_lots": dec(self.inner.terms().partial.map_or(1, |p| p.lot_count)),
            "lots": dec(lots),
            "cumulative_lots": dec(cumulative),
            "legs": legs.iter().map(|q| json!({
                "leg": q.leg,
                "moved": dec(q.settled),
                "cumulative": dec(q.cumulative),
                "total": dec(q.total),
            })).collect::<Vec<_>>(),
        }))
    }

    /// MIN_V2 of a vault output of these terms: MIN_V2(1, O), or MIN_V2(2, O) for partial terms,
    /// whose vault outputs carry a covenant ID.
    #[wasm_bindgen(js_name = minVaultV2, unchecked_return_type = "U64String")]
    pub fn min_vault_v2(&self) -> String {
        v2::min_vault_v2(self.inner.terms()).to_string()
    }

    /// `v2::refund` of leg `leg`; `escrow` is null for a refund of the vault UTXO alone.
    pub fn refund(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RefundSignerV2")] signer: JsValue,
        #[wasm_bindgen(js_name = vaultUtxo, unchecked_param_type = "UtxoJson")] vault_utxo: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RefundEscrowJson | null")] escrow: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let leg = index_arg(&leg, "leg")?;
        let signer = json_arg_tx(&signer, "signer")?;
        let vault_utxo = json_arg_tx(&vault_utxo, "vaultUtxo")?;
        let escrow = if escrow.is_null() {
            None
        } else {
            Some(json_arg_tx(&escrow, "escrow")?)
        };
        let (funding, value) = (
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        Ok(JsIpstV2 {
            inner: refund(
                &self.inner,
                leg,
                &signer,
                &vault_utxo,
                escrow.as_ref(),
                &funding,
                &value,
            )
            .map_err(js)?,
        })
    }
}

/// impulse_core::v2::IpstV2: a partially signed transaction of version 2.
#[wasm_bindgen(js_name = IpstV2)]
pub struct JsIpstV2 {
    inner: IpstV2,
}

#[wasm_bindgen(js_class = IpstV2)]
impl JsIpstV2 {
    /// The strict reader: every sighash recomputed, every signature verified. Version 1 is
    /// `IPST_UNSUPPORTED_VERSION` (read it with `Ipst.fromJson`).
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let text = text_arg(&text, "ipst", MAX_IPST_TEXT)?;
        Ok(JsIpstV2 {
            inner: ipst_from_json(&text).map_err(js)?,
        })
    }

    /// The canonical JSON text (`"ipst": 2`).
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> String {
        self.inner.to_json()
    }

    pub fn terms(&self) -> JsValidatedTermsV2 {
        JsValidatedTermsV2 {
            inner: self.inner.terms().clone(),
        }
    }

    #[wasm_bindgen(unchecked_return_type = "U64String")]
    pub fn fee(&self) -> String {
        self.inner.fee().to_string()
    }

    #[wasm_bindgen(unchecked_return_type = "MassesJson")]
    pub fn masses(&self) -> Result<JsValue, JsValue> {
        to_js(&masses_json(&self.inner))
    }

    /// Whether a mass dimension is above the pre-Toccata 100,000 standardness cap (a warning).
    #[wasm_bindgen(js_name = abovePreToccataCap)]
    pub fn above_pre_toccata_cap(&self) -> bool {
        self.inner.above_pre_toccata_cap()
    }

    #[wasm_bindgen(unchecked_return_type = "IpstSlotJson[]")]
    pub fn slots(&self) -> Result<JsValue, JsValue> {
        to_js(&slots_json(&self.inner))
    }

    #[wasm_bindgen(unchecked_return_type = "number[]")]
    pub fn pending(&self) -> Result<JsValue, JsValue> {
        to_js(&json!(self.inner.pending()))
    }

    #[wasm_bindgen(js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// The SIG_HASH_ALL Schnorr sighash of input `input`.
    pub fn sighash(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] input: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let input = index_arg(&input, "input")?;
        tx::sighash(self.inner.transaction(), self.inner.entries(), input)
            .map(|h| h.to_vec())
            .map_err(fail)
    }

    /// Verifies a 65-byte signature against the slot's signer and sighash, then stores it.
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "number")] input: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] signature: JsValue,
    ) -> Result<(), JsValue> {
        let input = index_arg(&input, "input")?;
        let signature = bytes_arg(&signature, "signature", SHORT_BYTES)?;
        self.inner.add_signature(input, &signature).map_err(fail)
    }

    /// Combines with another IPST of version 2 given as its JSON text.
    pub fn combine(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] other: JsValue,
    ) -> Result<JsIpstV2, JsValue> {
        let other = text_arg(&other, "other", MAX_IPST_TEXT)?;
        let other = ipst_from_json(&other).map_err(js)?;
        Ok(JsIpstV2 {
            inner: self.inner.combine(&other).map_err(fail)?,
        })
    }

    /// The signed transaction; every slot with a signer must hold a signature.
    pub fn finalize(&self) -> Result<JsSignedTransaction, JsValue> {
        let tx = self.inner.finalize().map_err(fail)?;
        Ok(JsSignedTransaction::new(&tx))
    }

    /// Stores each `{ input, signature }`, then finalizes.
    pub fn assemble(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignatureJson[]")] signatures: JsValue,
    ) -> Result<JsSignedTransaction, JsValue> {
        let signatures = json_arg_tx(&signatures, "signatures")?;
        let tx = assemble(&self.inner, &signatures).map_err(js)?;
        Ok(JsSignedTransaction::new(&tx))
    }

    /// The terms check after the value cap: whether the v2 builders make this transaction from
    /// its own inputs. `artifacts` holds the token artifacts of the KCC-20 legs.
    #[wasm_bindgen(js_name = verifyAgainstTerms, unchecked_return_type = "TermsMatchV2Json")]
    pub fn verify_against_terms(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsV2Json")] artifacts: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsValue, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (artifacts, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&value, "value")?,
        );
        to_js(&verify_against_terms(&self.inner, &artifacts, daa, &value).map_err(js)?)
    }
}

/// The terms v2 version byte, 2.
#[wasm_bindgen(js_name = termsV2Version)]
pub fn terms_v2_version() -> u8 {
    v2::TERMS_V2_VERSION
}

/// The most legs a v2 trade has (MAX_LEGS).
#[wasm_bindgen(js_name = maxLegs)]
pub fn max_legs() -> usize {
    MAX_LEGS
}

/// The pinned ImpulseVault v2 template hash (`contracts/TEMPLATE_HASH_V2`), after the startup
/// check of the embedded artifact.
#[wasm_bindgen(js_name = templateHashV2)]
pub fn template_hash_v2() -> Result<Vec<u8>, JsValue> {
    Ok(v2::check_template().map_err(fail)?.hash().to_vec())
}

/// CAP_V2 of a network (spec/V2.md 6.2).
#[wasm_bindgen(js_name = capsV2, unchecked_return_type = "CapsV2Json")]
pub fn caps_v2(
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<JsValue, JsValue> {
    to_js(&caps_json(crate::network_arg(&network)?))
}

/// The v0.2 codes appended to the TERMS_, TEMPLATE_, TX_ and IPST_, and VERIFY_ families, each
/// list frozen in impulse-core.
#[wasm_bindgen(js_name = v2ErrorCodes)]
pub fn v2_error_codes() -> Vec<String> {
    TERMS_V2_ERROR_CODES
        .iter()
        .chain(TEMPLATE_V2_ERROR_CODES.iter())
        .chain(TX_V2_ERROR_CODES.iter())
        .chain(VERIFY_V2_ERROR_CODES.iter())
        .map(|c| c.to_string())
        .collect()
}
