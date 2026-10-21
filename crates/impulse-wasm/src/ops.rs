// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The operations of the phase 2 API, on Rust values and `serde_json::Value`s, with no
//! JavaScript in them: the builders, the IPST operations, verify and decode. `api.rs` reads the
//! JavaScript arguments into JSON values and calls these; the native tests and the oracle call
//! them with the same JSON, so what the wasm module computes is checked against the same code
//! built for the host.
//!
//! Every operation here is impulse-core's. This module converts forms, applies the value cap
//! before a builder runs, and renders results as JSON values. Results that carry amounts render
//! them as decimal strings.

use crate::error::{Failure, SdkError};
use crate::forms;
use crate::json::{context_from_json, destination_to_json, hex, hex_decode, terms_to_json};
use crate::value;
use impulse_core::decode::{self, DecodedTransaction, Entry, Outcome, Party};
use impulse_core::template::{FundableVault, LegIndex, Vault};
use impulse_core::terms::{Network, ValidatedTerms};
use impulse_core::tx::{self, Ipst, IpstKind, RefundSigner, TermsMatch};
use impulse_core::verify::{
    self, OfferedAddresses, Relation, TokenEvidence, TokenWarning, TokenWarningKind,
};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
};
use kaspa_consensus_core::Hash;
use serde_json::{json, Map, Value};

fn dec(n: u64) -> Value {
    Value::String(n.to_string())
}

pub(crate) fn spk_json(spk: &ScriptPublicKey) -> Value {
    json!({ "version": spk.version(), "script": hex(spk.script()) })
}

// Builders. Each reads its forms, applies the value cap, then calls the core builder.

/// `Vault::instantiate_for_creation`, the only path to a funding address, after the value cap: a
/// funding address for a trade above the cap is not handed out (spec/CLI.md applies the cap in
/// `address`). `value` is the declaration of the builders.
pub(crate) fn instantiate_for_creation(
    terms: &ValidatedTerms,
    leg: LegIndex,
    ctx: &Value,
    value: &Value,
) -> Result<FundableVault, Failure> {
    let ctx = context_from_json(ctx)?;
    value::check(terms.terms(), &value::declaration_from_json(value)?, 0)?;
    Ok(Vault::instantiate_for_creation(terms, leg, &ctx)?)
}

/// `tx::fund_kas` for the cash leg. `ctx` is the creation context: its `creation_daa` is the
/// caller's current DAA score, read from a node it trusts.
pub(crate) fn fund_kas(
    terms: &ValidatedTerms,
    ctx: &Value,
    funding: &Value,
    value: &Value,
) -> Result<Ipst, Failure> {
    let ctx = context_from_json(ctx)?;
    let funding = forms::fee_payment(funding)?;
    value::check(
        terms.terms(),
        &value::declaration_from_json(value)?,
        funding.fee,
    )?;
    let vault = Vault::instantiate_for_creation(terms, LegIndex::Cash, &ctx)?;
    Ok(tx::fund_kas(terms, &vault, &funding, ctx.creation_daa)?)
}

/// `tx::fund_kcc20` for `leg`.
pub(crate) fn fund_kcc20(
    terms: &ValidatedTerms,
    leg: LegIndex,
    ctx: &Value,
    deposit: &Value,
    funding: &Value,
    value: &Value,
) -> Result<Ipst, Failure> {
    let ctx = context_from_json(ctx)?;
    let deposit = forms::deposit(deposit)?;
    let funding = forms::fee_payment(funding)?;
    // The carrier and the authorizer go into the vault with the token; the fee is paid away.
    let native_kas = deposit
        .deposit
        .carrier
        .saturating_add(deposit.deposit.authorizer)
        .max(funding.fee);
    value::check(
        terms.terms(),
        &value::declaration_from_json(value)?,
        native_kas,
    )?;
    let vault = Vault::instantiate_for_creation(terms, leg, &ctx)?;
    Ok(tx::fund_kcc20(
        terms,
        &vault,
        &deposit.template,
        &deposit.deposit,
        &funding,
        ctx.creation_daa,
    )?)
}

/// `tx::settle`.
pub(crate) fn settle(
    terms: &ValidatedTerms,
    legs: &Value,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Ipst, Failure> {
    let legs = forms::settle_legs(legs)?;
    let funding = forms::fee_payment(funding)?;
    value::check(
        terms.terms(),
        &value::declaration_from_json(value)?,
        funding.fee,
    )?;
    Ok(tx::settle(terms, &legs.legs(), &funding, current_daa)?)
}

/// `tx::refund`. `escrow` is None for a refund of the vault UTXO alone.
pub(crate) fn refund(
    terms: &ValidatedTerms,
    leg: LegIndex,
    signer: &str,
    vault_utxo: &Value,
    escrow: Option<&Value>,
    funding: &Value,
    value: &Value,
) -> Result<Ipst, Failure> {
    let signer: RefundSigner = forms::refund_signer(signer)?;
    let vault_utxo = forms::utxo(crate::json::Obj::new(vault_utxo, "vault_utxo")?)?;
    let escrow = escrow.map(forms::refund_escrow).transpose()?;
    let funding = forms::fee_payment(funding)?;
    value::check(
        terms.terms(),
        &value::declaration_from_json(value)?,
        funding.fee,
    )?;
    Ok(tx::refund(
        terms,
        leg,
        signer,
        &vault_utxo,
        escrow.as_ref().map(|e| e.escrow()).as_ref(),
        &funding,
    )?)
}

/// `tx::direct`.
pub(crate) fn direct(
    terms: &ValidatedTerms,
    legs: &Value,
    funding: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Ipst, Failure> {
    let legs = forms::direct_legs(legs)?;
    let funding = forms::fee_payment(funding)?;
    value::check(
        terms.terms(),
        &value::declaration_from_json(value)?,
        funding.fee,
    )?;
    Ok(tx::direct(terms, &legs.legs(), &funding, current_daa)?)
}

// The IPST.

/// At most this many inputs, and at most this many outputs, in an IPST text. An Impulse
/// transaction has at most five outputs (`MAX_OUTPUTS`) and five inputs of fixed layout besides
/// the fee and token inputs, which carry a compute budget of at least 10 units (1,000 grams) each
/// against the 100,000 gram cap the builders refuse to pass (`TX_MASS`). The reader of
/// impulse-core recomputes each signer's sighash from the whole transaction, which is quadratic
/// in the input count (measured by the review on the release module: 242 ms at 1,000 inputs,
/// 2.0 s at 4,000, 117.8 s at 11,000), so the count is bounded here, before any of that work.
pub(crate) const MAX_IPST_ENTRIES: usize = forms::MAX_ARRAY;

/// The number of elements of a JSON array, counted without keeping them.
struct Len(usize);

impl<'de> serde::Deserialize<'de> for Len {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Count;
        impl<'de> serde::de::Visitor<'de> for Count {
            type Value = Len;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an array")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Len, A::Error> {
                let mut n = 0usize;
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    n += 1;
                }
                Ok(Len(n))
            }
        }
        d.deserialize_seq(Count)
    }
}

/// The element counts of the top-level `inputs` and `outputs` arrays of an IPST text; the larger
/// count if a key repeats (impulse-core refuses a repeat anyway).
struct Counts {
    inputs: usize,
    outputs: usize,
}

impl<'de> serde::Deserialize<'de> for Counts {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Scan;
        impl<'de> serde::de::Visitor<'de> for Scan {
            type Value = Counts;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Counts, A::Error> {
                let mut counts = Counts {
                    inputs: 0,
                    outputs: 0,
                };
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "inputs" => counts.inputs = counts.inputs.max(map.next_value::<Len>()?.0),
                        "outputs" => {
                            counts.outputs = counts.outputs.max(map.next_value::<Len>()?.0)
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(counts)
            }
        }
        d.deserialize_map(Scan)
    }
}

/// Refuses an IPST text with more than `MAX_IPST_ENTRIES` inputs or outputs
/// (`SDK_JSON_FORM`). A text this scan cannot read is passed on: impulse-core's reader accepts a
/// strict subset of JSON (no escapes, fractions, exponents, leading zeros or repeated keys,
/// nesting at most 16 deep), all of which serde_json reads, so a text serde_json refuses is one
/// impulse-core refuses with its own code.
fn check_ipst_size(text: &str, argument: &'static str) -> Result<(), SdkError> {
    let Ok(counts) =
        <Counts as serde::Deserialize>::deserialize(&mut serde_json::Deserializer::from_str(text))
    else {
        return Ok(());
    };
    for (what, n) in [("inputs", counts.inputs), ("outputs", counts.outputs)] {
        if n > MAX_IPST_ENTRIES {
            return Err(SdkError::json(
                argument,
                format!("{n} {what}; an IPST of at most {MAX_IPST_ENTRIES} is read"),
            ));
        }
    }
    Ok(())
}

/// `Ipst::from_json` on a text of at most `MAX_IPST_ENTRIES` inputs and outputs.
pub(crate) fn ipst_from_json(text: &str, argument: &'static str) -> Result<Ipst, Failure> {
    check_ipst_size(text, argument)?;
    Ok(Ipst::from_json(text)?)
}

/// `Ipst::combine` with an IPST read from its JSON text (spec/IPST.md, "Combine").
pub(crate) fn combine(ipst: &Ipst, other: &str) -> Result<Ipst, Failure> {
    Ok(ipst.combine(&ipst_from_json(other, "other")?)?)
}

/// `Ipst::assemble` from `[{ input, signature }]`.
pub(crate) fn assemble(ipst: &Ipst, signatures: &Value) -> Result<Transaction, Failure> {
    let signatures = forms::signatures(signatures)?;
    let pairs: Vec<(usize, &[u8])> = signatures
        .iter()
        .map(|(input, sig)| (*input, sig.as_slice()))
        .collect();
    Ok(ipst.assemble(&pairs)?)
}

/// The transaction ID and the raw form of a signed transaction: rusty-kaspa a41a333's borsh
/// encoding, which `decode_raw` reads.
pub(crate) fn signed(tx: &Transaction) -> ([u8; 32], Vec<u8>) {
    (tx.id().as_bytes(), decode::encode_raw(tx))
}

pub(crate) fn kind_json(kind: IpstKind) -> Value {
    let signer = |s: RefundSigner| match s {
        RefundSigner::Depositor => "depositor",
        RefundSigner::Counterparty => "counterparty",
        RefundSigner::Authority => "authority",
    };
    match kind {
        IpstKind::FundKas => json!({ "builder": "fund_kas" }),
        IpstKind::FundKcc20(leg) => json!({ "builder": "fund_kcc20", "leg": leg.index() }),
        IpstKind::Settle => json!({ "builder": "settle" }),
        IpstKind::Refund {
            leg,
            signer: s,
            with_token,
        } => json!({
            "builder": "refund",
            "leg": leg.index(),
            "signer": signer(s),
            "with_token": with_token,
        }),
        IpstKind::Direct => json!({ "builder": "direct" }),
    }
}

/// `Ipst::verify_against_terms` after the value cap, as the typed result: `artifacts` is `{ asset,
/// cash }`, the templates as artifact text. This is the check a signer runs on a received
/// document before signing, so the value cap holds here (spec/CLI.md applies it in `ipst sign`);
/// the fee the document pays counts toward it.
pub(crate) fn terms_match(
    ipst: &Ipst,
    artifacts: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<TermsMatch, Failure> {
    let (asset, cash) = forms::artifacts(artifacts)?;
    value::check(
        ipst.terms().terms(),
        &value::declaration_from_json(value)?,
        ipst.fee(),
    )?;
    Ok(ipst.verify_against_terms(&asset, cash.as_ref(), current_daa)?)
}

/// [`terms_match`] rendered as JSON.
pub(crate) fn verify_against_terms(
    ipst: &Ipst,
    artifacts: &Value,
    current_daa: u64,
    value: &Value,
) -> Result<Value, Failure> {
    let TermsMatch { kind, fee, change } = terms_match(ipst, artifacts, current_daa, value)?;
    Ok(json!({
        "kind": kind_json(kind),
        "fee": dec(fee),
        "change": change.map(|o| json!({
            "value": dec(o.value),
            "script_public_key": spk_json(&o.script_public_key),
        })),
    }))
}

/// The slots of an IPST: `[{ input, signer, sighash, signature }]`, hex or null.
pub(crate) fn slots_json(ipst: &Ipst) -> Value {
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

/// The masses of the signed transaction and the minimum relay fee for them.
pub(crate) fn masses_json(ipst: &Ipst) -> Value {
    let m = ipst.masses();
    json!({
        "compute": dec(m.compute),
        "transient": dec(m.transient),
        "storage": dec(m.storage),
        "fee_mass": dec(m.fee_mass),
        "min_relay_fee": dec(tx::min_relay_fee(m.fee_mass)),
    })
}

/// The unit of the sighash: `tx::sighash` on the IPST's own transaction and entries.
pub(crate) fn sighash(ipst: &Ipst, input: usize) -> Result<[u8; 32], Failure> {
    Ok(tx::sighash(ipst.transaction(), ipst.entries(), input)?)
}

// Verify.

fn offered_addresses(value: &Value) -> Result<(Option<String>, Option<String>), SdkError> {
    let mut o = crate::json::Obj::new(value, "offered")?;
    let text = |o: &mut crate::json::Obj, key: &'static str| {
        o.nullable(key, |o, k| o.str(k).map(String::from))
    };
    let asset = text(&mut o, "asset")?;
    let cash = text(&mut o, "cash")?;
    o.finish()?;
    Ok((asset, cash))
}

/// Token evidence for one leg: the artifact text and the issuer keys the caller knows.
struct EvidenceIn {
    artifact: String,
    issuer_keys: Vec<[u8; 32]>,
}

impl EvidenceIn {
    fn evidence(&self) -> TokenEvidence<'_> {
        TokenEvidence {
            artifact_json: &self.artifact,
            issuer_keys: &self.issuer_keys,
        }
    }
}

fn evidence(value: &Value, path: &str) -> Result<EvidenceIn, SdkError> {
    let mut o = crate::json::Obj::new(value, path)?;
    let artifact = o.str("artifact")?.to_string();
    let items = o.array("issuer_keys")?;
    if items.len() > forms::MAX_ARRAY {
        return o.fail(
            "issuer_keys",
            format!("more than {} elements", forms::MAX_ARRAY),
        );
    }
    let issuer_keys = items
        .into_iter()
        .map(
            |(at, v)| match v.as_str().and_then(hex_decode).map(<[u8; 32]>::try_from) {
                Some(Ok(key)) => Ok(key),
                _ => Err(SdkError::json(at, "expected 64 lowercase hex digits")),
            },
        )
        .collect::<Result<_, _>>()?;
    o.finish()?;
    Ok(EvidenceIn {
        artifact,
        issuer_keys,
    })
}

/// `{ asset: EvidenceJson | null, cash: EvidenceJson | null }`.
fn evidences(value: &Value) -> Result<(Option<EvidenceIn>, Option<EvidenceIn>), SdkError> {
    let mut o = crate::json::Obj::new(value, "evidence")?;
    let asset_path = o.at("asset");
    let asset = o.nullable("asset", |o, k| {
        o.value(k).and_then(|v| evidence(v, &asset_path))
    })?;
    let cash_path = o.at("cash");
    let cash = o.nullable("cash", |o, k| {
        o.value(k).and_then(|v| evidence(v, &cash_path))
    })?;
    o.finish()?;
    Ok((asset, cash))
}

fn party_name(p: Party) -> &'static str {
    match p {
        Party::Seller => "seller",
        Party::Buyer => "buyer",
        Party::Authority => "authority",
    }
}

fn warning_json(w: &TokenWarning) -> Value {
    let mut m = Map::new();
    m.insert("leg".into(), json!(w.leg.index()));
    m.insert("code".into(), json!(w.code()));
    match &w.kind {
        TokenWarningKind::ExtraEntries { entries } => {
            m.insert("entries".into(), json!(entries));
        }
        TokenWarningKind::PartyIsIssuer { party, relation } => {
            m.insert("party".into(), json!(party_name(*party)));
            m.insert(
                "relation".into(),
                json!(match relation {
                    Relation::Depositor => "depositor",
                    Relation::Counterparty => "counterparty",
                    Relation::Authority => "authority",
                }),
            );
        }
        TokenWarningKind::ForeignAtVault { covenant_id } => {
            m.insert(
                "covenant_id".into(),
                json!(covenant_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()),
            );
        }
        _ => {}
    }
    Value::Object(m)
}

fn addresses_json(addresses: &[verify::VerifiedAddress]) -> Value {
    Value::Array(
        addresses
            .iter()
            .map(|a| {
                json!({
                    "leg": a.leg.index(),
                    "address": a.address,
                    "script_hash": hex(&a.script_hash),
                })
            })
            .collect(),
    )
}

/// `verify::verify_addresses`: `offered` is `{ asset: string | null, cash: string | null }`. The
/// value cap holds (spec/CLI.md applies it in `verify`).
pub(crate) fn verify_addresses(
    terms: &ValidatedTerms,
    ctx: &Value,
    offered: &Value,
    value: &Value,
) -> Result<Value, Failure> {
    let ctx = context_from_json(ctx)?;
    let (asset, cash) = offered_addresses(offered)?;
    value::check(terms.terms(), &value::declaration_from_json(value)?, 0)?;
    let offered = OfferedAddresses {
        asset: asset.as_deref(),
        cash: cash.as_deref(),
    };
    Ok(addresses_json(&verify::verify_addresses(
        terms, &ctx, &offered,
    )?))
}

/// `verify::before_funding`. The value cap holds, as in `verify_addresses`.
pub(crate) fn before_funding(
    terms: &ValidatedTerms,
    ctx: &Value,
    offered: &Value,
    evidence: &Value,
    value: &Value,
) -> Result<Value, Failure> {
    let ctx = context_from_json(ctx)?;
    let (asset, cash) = offered_addresses(offered)?;
    let (asset_evidence, cash_evidence) = evidences(evidence)?;
    value::check(terms.terms(), &value::declaration_from_json(value)?, 0)?;
    let offered = OfferedAddresses {
        asset: asset.as_deref(),
        cash: cash.as_deref(),
    };
    let check = verify::before_funding(
        terms,
        &ctx,
        &offered,
        asset_evidence.as_ref().map(|e| e.evidence()).as_ref(),
        cash_evidence.as_ref().map(|e| e.evidence()).as_ref(),
    )?;
    Ok(json!({
        "addresses": addresses_json(&check.addresses),
        "warnings": check.warnings.iter().map(warning_json).collect::<Vec<_>>(),
        "token_legs_assessed": check.token_legs_assessed(),
    }))
}

/// `verify::token_warnings`.
pub(crate) fn token_warnings(terms: &ValidatedTerms, evidence: &Value) -> Result<Value, Failure> {
    let (asset, cash) = evidences(evidence)?;
    let warnings = verify::token_warnings(
        terms,
        asset.as_ref().map(|e| e.evidence()).as_ref(),
        cash.as_ref().map(|e| e.evidence()).as_ref(),
    )?;
    Ok(Value::Array(warnings.iter().map(warning_json).collect()))
}

/// `verify::verify_revealed_script`.
pub(crate) fn verify_revealed_script(
    terms: &ValidatedTerms,
    leg: LegIndex,
    script: &[u8],
) -> Result<(), Failure> {
    Ok(verify::verify_revealed_script(terms, leg, script)?)
}

/// `verify::verify_spent_input` on a signature script and the scriptPublicKey of the UTXO the
/// input spends, as the node reports it: `{ version, script }`.
pub(crate) fn verify_spent_input(
    terms: &ValidatedTerms,
    leg: LegIndex,
    signature_script: &[u8],
    spent: &Value,
) -> Result<(), Failure> {
    let spent = forms::script_public_key(crate::json::Obj::new(spent, "spent")?)?;
    // Only the signature script of an input is read.
    let input = TransactionInput::new(
        TransactionOutpoint::new(Hash::from_bytes([0; 32]), 0),
        signature_script.to_vec(),
        0,
        0,
    );
    Ok(verify::verify_spent_input(terms, leg, &input, &spent)?)
}

// Decode.

fn decoded_json(d: &DecodedTransaction) -> Value {
    let legs: Vec<Value> = d
        .legs
        .iter()
        .map(|l| {
            let entry = match l.entry {
                Entry::Settle => json!({ "kind": "settle" }),
                Entry::Refund { signer, party } => json!({
                    "kind": "refund",
                    "signer": signer.map(|k| hex(&k)),
                    "party": party.map(party_name),
                }),
            };
            let to = |d| serde_json::from_str::<Value>(&destination_to_json(d)).unwrap_or(Value::Null);
            let outcome = match l.outcome() {
                Outcome::Delivered { amount, to: dest } => json!({
                    "kind": "delivered",
                    "amount": dec(amount),
                    "to": to(&dest),
                }),
                Outcome::Refunded { to: dest } => json!({
                    "kind": "refunded",
                    "to": to(&dest),
                }),
            };
            json!({
                "input_index": l.input_index,
                "outpoint": {
                    "transaction_id": hex(&l.outpoint.transaction_id.as_bytes()),
                    "index": l.outpoint.index,
                },
                "leg": l.leg.index(),
                "script_hash": hex(&l.script_hash),
                "terms": serde_json::from_str::<Value>(&terms_to_json(l.terms.terms())).unwrap_or(Value::Null),
                "terms_hash": hex(&l.terms.terms_hash()),
                "entry": entry,
                "outcome": outcome,
            })
        })
        .collect();
    let refused: Vec<Value> = d
        .refused
        .iter()
        .map(|e| {
            json!({
                "code": e.code(),
                "input_index": e.input_index(),
                "message": e.to_string(),
            })
        })
        .collect();
    json!({
        "txid": hex(&d.txid),
        "bound": d.bound,
        "legs": legs,
        "refused": refused,
    })
}

/// `decode::decode_raw`: the raw form and the scriptPublicKey each input spends
/// (`[{ version, script }]`, one per input, as the node reports them).
pub(crate) fn decode_raw(bytes: &[u8], spent: &Value, network: Network) -> Result<Value, Failure> {
    let Value::Array(items) = spent else {
        return Err(SdkError::json("spent", "expected an array").into());
    };
    if items.len() > forms::MAX_ARRAY {
        return Err(
            SdkError::json("spent", format!("more than {} elements", forms::MAX_ARRAY)).into(),
        );
    }
    let spent = items
        .iter()
        .enumerate()
        .map(|(i, v)| forms::script_public_key(crate::json::Obj::new(v, &format!("spent[{i}]"))?))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(decoded_json(&decode::decode_raw(bytes, &spent, network)?))
}

/// `decode::decode_raw_unbound`.
pub(crate) fn decode_raw_unbound(bytes: &[u8], network: Network) -> Result<Value, Failure> {
    Ok(decoded_json(&decode::decode_raw_unbound(bytes, network)?))
}

// KCC-20 templates.

/// The template triple the terms name a token by, from the token's artifact text.
pub(crate) fn kcc20_template(artifact: &str) -> Result<Value, Failure> {
    let t = forms::template("artifact", artifact)?;
    Ok(json!({
        "template_hash": hex(&t.template_hash()),
        "template_prefix_len": t.prefix_len(),
        "template_suffix_len": t.suffix_len(),
    }))
}

/// The P2SH scriptPublicKey of a token UTXO in `state`
/// (`{ identifier_type, identifier, amount, is_minter }`), from the token's artifact text.
pub(crate) fn kcc20_script_public_key(artifact: &str, state: &Value) -> Result<Value, Failure> {
    let t = forms::template("artifact", artifact)?;
    let state = forms::kcc20_state(crate::json::Obj::new(state, "state")?)?;
    Ok(spk_json(&t.script_public_key(&state)?))
}
