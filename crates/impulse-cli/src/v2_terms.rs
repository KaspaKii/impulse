// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms v2 at the command line (spec/V2.md 6.5): the JSON form of spec/V2.md 5.4, drafts and
//! terms files v2, the summary a party reads, the party check, the v2 value cap and the checks
//! made before anyone funds. Public keys only: nothing here reads or holds a private key.

use crate::cli::{hash_arg, CapArgs, Ctx};
use crate::error::CliError;
use crate::json::{hex, parse_strict, Obj};
use crate::summary::{self, kas, parse_pin, DAA_PER_SECOND};
use crate::terms_file::network_name;
use crate::value_cap::CapPolicy;
use clap::Args;
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
};
use impulse_core::v2::{
    kas_destination, min_v2, DestinationV2, LegV2, Partial, TermsV2, ValidatedTermsV2,
    TERMS_V2_VERSION,
};
use impulse_core::verify::{pinned_kcc20, TemplateTriple};
use serde_json::Value;
use std::path::Path;

/// The D46 default expiry: 24 hours of DAA scores at the nominal rate.
pub const DEFAULT_EXPIRY_IN: u64 = 24 * 60 * 60 * DAA_PER_SECOND;

const TERMS_KEYS: [&str; 10] = [
    "version",
    "network",
    "nonce",
    "authority_key",
    "legs",
    "earliest_daa",
    "expiry_daa",
    "funding_mode",
    "partial",
    "trade_ref",
];

/// Keys a draft may leave out or set to null.
const DRAFT_OPTIONAL: [&str; 3] = ["nonce", "expiry_daa", "funding_mode"];

fn json_err(reason: String) -> CliError {
    CliError::new("CLI_TERMS_JSON", reason)
}

// =============================================================================================
// JSON form (spec/V2.md 5.4)
// =============================================================================================

/// A JSON value in the subset the v2 terms file holds, written in field order.
pub(crate) enum J {
    Str(String),
    Num(u64),
    Null,
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

impl J {
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        write(self, 0, &mut out);
        out.push('\n');
        out
    }
}

fn write(j: &J, indent: usize, out: &mut String) {
    let pad = |n: usize| " ".repeat(n);
    match j {
        J::Str(s) => out.push_str(&Value::String(s.clone()).to_string()),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Null => out.push_str("null"),
        J::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad(indent + 2));
                write(item, indent + 2, out);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push(']');
        }
        J::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                out.push_str(&format!("{}\"{key}\": ", pad(indent + 2)));
                write(value, indent + 2, out);
                out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push('}');
        }
    }
}

const ID_NAMES: [&str; 3] = ["pubkey", "script_hash", "covenant_id"];
const ID_TYPES: [IdentifierType; 3] = [
    IdentifierType::PubKey,
    IdentifierType::ScriptHash,
    IdentifierType::CovenantId,
];

fn id_name(t: IdentifierType) -> &'static str {
    match t {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

fn dec(n: u64) -> J {
    J::Str(n.to_string())
}

fn destination_json(d: &DestinationV2) -> J {
    J::Obj(vec![
        ("identifier_type", J::Str(id_name(d.identifier_type).into())),
        ("identifier", J::Str(hex(&d.identifier))),
    ])
}

fn leg_json(l: &LegV2) -> J {
    let mut asset = Vec::new();
    match &l.asset.kind {
        LegKind::Kas => asset.push(("kind", J::Str("kas".into()))),
        LegKind::Kcc20(t) => {
            asset.push(("kind", J::Str("kcc20".into())));
            asset.push(("covenant_id", J::Str(hex(&t.covenant_id))));
            asset.push(("template_hash", J::Str(hex(&t.template_hash))));
            asset.push(("template_prefix_len", J::Num(t.template_prefix_len.into())));
            asset.push(("template_suffix_len", J::Num(t.template_suffix_len.into())));
        }
        LegKind::External => asset.push(("kind", J::Str("external".into()))),
    }
    asset.push(("amount", dec(l.asset.amount)));
    J::Obj(vec![
        ("depositor_key", J::Str(hex(&l.depositor_key))),
        ("asset", J::Obj(asset)),
        ("delivery", destination_json(&l.delivery)),
        ("refund", destination_json(&l.refund)),
    ])
}

/// The JSON form of terms v2, keys in field order (spec/V2.md 5.4).
pub(crate) fn terms_json(t: &TermsV2) -> J {
    J::Obj(vec![
        ("version", J::Num(t.version.into())),
        ("network", J::Str(network_name(t.network).into())),
        ("nonce", dec(t.nonce)),
        (
            "authority_key",
            t.authority_key.map_or(J::Null, |k| J::Str(hex(&k))),
        ),
        ("legs", J::Arr(t.legs.iter().map(leg_json).collect())),
        ("earliest_daa", t.earliest_daa.map_or(J::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            J::Str(funding_name(t.funding_mode).to_string()),
        ),
        (
            "partial",
            t.partial.map_or(J::Null, |p| {
                J::Obj(vec![
                    ("lot_count", dec(p.lot_count)),
                    ("min_lot", dec(p.min_lot)),
                ])
            }),
        ),
        ("trade_ref", J::Str(hex(&t.trade_ref))),
    ])
}

fn funding_name(m: FundingMode) -> &'static str {
    match m {
        FundingMode::Revocable => "revocable",
        FundingMode::Earmarked => "earmarked",
    }
}

fn destination(o: &Obj) -> Result<DestinationV2, String> {
    o.keys(&["identifier_type", "identifier"], &[])?;
    Ok(DestinationV2 {
        identifier_type: ID_TYPES[o.choice("identifier_type", &ID_NAMES)?],
        identifier: o.hex32("identifier")?,
    })
}

fn asset(o: &Obj) -> Result<Leg, String> {
    let kind = match o.choice("kind", &["kas", "kcc20", "external"])? {
        0 => {
            o.keys(&["kind", "amount"], &[])?;
            LegKind::Kas
        }
        1 => {
            o.keys(
                &[
                    "kind",
                    "covenant_id",
                    "template_hash",
                    "template_prefix_len",
                    "template_suffix_len",
                    "amount",
                ],
                &[],
            )?;
            LegKind::Kcc20(Kcc20Token {
                covenant_id: o.hex32("covenant_id")?,
                template_hash: o.hex32("template_hash")?,
                template_prefix_len: o.num("template_prefix_len", u32::MAX.into())? as u32,
                template_suffix_len: o.num("template_suffix_len", u32::MAX.into())? as u32,
            })
        }
        _ => {
            o.keys(&["kind", "amount"], &[])?;
            LegKind::External
        }
    };
    Ok(Leg {
        kind,
        amount: o.dec("amount")?,
    })
}

fn leg(value: &Value, path: &str) -> Result<LegV2, String> {
    let o = Obj::new(path, value)?;
    o.keys(&["depositor_key", "asset", "delivery", "refund"], &[])?;
    Ok(LegV2 {
        depositor_key: o.hex32("depositor_key")?,
        asset: asset(&o.obj("asset")?)?,
        delivery: destination(&o.obj("delivery")?)?,
        refund: destination(&o.obj("refund")?)?,
    })
}

/// The fields of the JSON form; `nonce`, `expiry_daa` and `funding_mode` as the caller read
/// them.
fn fields(
    o: &Obj,
    nonce: u64,
    expiry_daa: u64,
    funding: Option<FundingMode>,
) -> Result<TermsV2, String> {
    let version = o.num("version", u8::MAX.into())? as u8;
    if version != TERMS_V2_VERSION {
        return Err(format!(
            "version: {version}, not 2; a version 1 terms file is read by the impulse commands without v2"
        ));
    }
    let authority_key = if o.is_null("authority_key")? {
        None
    } else {
        Some(o.hex32("authority_key")?)
    };
    let earliest_daa = if o.is_null("earliest_daa")? {
        None
    } else {
        Some(o.dec("earliest_daa")?)
    };
    let legs_value = o.get("legs")?;
    let items = legs_value
        .as_array()
        .ok_or_else(|| "legs: expected an array".to_string())?;
    let legs = items
        .iter()
        .enumerate()
        .map(|(i, v)| leg(v, &format!("legs[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    let funding_mode = match funding {
        Some(m) => m,
        None if legs.len() >= 3 => FundingMode::Revocable,
        None => {
            return Err(
                "funding_mode: a trade of two legs names its funding mode (the revocable default is for 3 legs or more, D46)"
                    .into(),
            )
        }
    };
    let partial = if o.is_null("partial")? {
        None
    } else {
        let p = o.obj("partial")?;
        p.keys(&["lot_count", "min_lot"], &[])?;
        Some(Partial {
            lot_count: p.dec("lot_count")?,
            min_lot: p.dec("min_lot")?,
        })
    };
    Ok(TermsV2 {
        version,
        network: [Network::Mainnet, Network::Testnet]
            [o.choice("network", &["mainnet", "testnet"])?],
        nonce,
        authority_key,
        legs,
        earliest_daa,
        expiry_daa,
        funding_mode,
        partial,
        trade_ref: o.hex32("trade_ref")?,
    })
}

fn funding_of(o: &Obj) -> Result<Option<FundingMode>, String> {
    match o.opt("funding_mode") {
        None => Ok(None),
        Some(_) => Ok(Some(
            [FundingMode::Revocable, FundingMode::Earmarked]
                [o.choice("funding_mode", &["revocable", "earmarked"])?],
        )),
    }
}

/// The JSON form of terms v2, every key present and no other.
pub fn parse_terms_json(value: &Value) -> Result<TermsV2, CliError> {
    let o = Obj::new("terms", value).map_err(json_err)?;
    o.keys(&TERMS_KEYS, &[]).map_err(json_err)?;
    let nonce = o.dec("nonce").map_err(json_err)?;
    let expiry = o.dec("expiry_daa").map_err(json_err)?;
    let funding = funding_of(&o).map_err(json_err)?;
    if funding.is_none() {
        return Err(json_err("terms.funding_mode: missing".into()));
    }
    fields(&o, nonce, expiry, funding).map_err(json_err)
}

/// A draft v2: the JSON form, with `nonce`, `expiry_daa` and `funding_mode` allowed absent or
/// null. A missing nonce is drawn from the operating system's random source; a missing expiry is
/// `creation_daa` plus [`DEFAULT_EXPIRY_IN`] (D46); a missing funding mode is revocable for 3
/// legs or more (D46).
pub fn parse_draft(text: &str, creation_daa: u64) -> Result<(TermsV2, Vec<String>), CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let o = Obj::new("", &value).map_err(json_err)?;
    let required: Vec<&str> = TERMS_KEYS
        .into_iter()
        .filter(|k| !DRAFT_OPTIONAL.contains(k))
        .collect();
    o.keys(&required, &DRAFT_OPTIONAL).map_err(json_err)?;
    let mut notes = Vec::new();
    let nonce = match o.opt("nonce") {
        Some(_) => o.dec("nonce").map_err(json_err)?,
        None => rand::random::<u64>(),
    };
    let expiry = match o.opt("expiry_daa") {
        Some(_) => o.dec("expiry_daa").map_err(json_err)?,
        None => {
            let e = creation_daa.saturating_add(DEFAULT_EXPIRY_IN);
            notes.push(format!(
                "default: expiry_daa {e}, the creation DAA score plus {DEFAULT_EXPIRY_IN} (24 hours at {DAA_PER_SECOND} DAA scores per second, D46)"
            ));
            e
        }
    };
    let funding = funding_of(&o).map_err(json_err)?;
    let terms = fields(&o, nonce, expiry, funding).map_err(json_err)?;
    if funding.is_none() {
        notes.push("default: funding_mode revocable (3 legs or more, D46)".into());
    }
    Ok((terms, notes))
}

/// The terms file v2 text: the JSON form, the canonical bytes and the terms hash.
pub fn render_terms_file(terms: &ValidatedTermsV2) -> String {
    J::Obj(vec![
        ("terms", terms_json(terms.terms())),
        ("canonical", J::Str(hex(terms.canonical()))),
        ("terms_hash", J::Str(hex(&terms.terms_hash()))),
    ])
    .render()
}

/// Parses a terms file v2 and runs the structure checks. Refuses a file whose three parts
/// disagree (`CLI_TERMS_FILE_INCONSISTENT`), and anything that is not one (`CLI_TERMS_JSON`).
pub fn parse_terms_file(text: &str) -> Result<ValidatedTermsV2, CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&["terms", "canonical", "terms_hash"], &[])
        .map_err(json_err)?;
    let terms = parse_terms_json(obj.get("terms").map_err(json_err)?)?;
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

/// Reads a terms file v2 on the command's network (`CLI_NETWORK_MISMATCH`).
pub(crate) fn read_terms(ctx: &Ctx, path: &Path) -> Result<ValidatedTermsV2, CliError> {
    let terms = parse_terms_file(&crate::terms_file::read_text(path)?)?;
    check_network(ctx, terms.terms().network, "terms")?;
    Ok(terms)
}

pub(crate) fn check_network(ctx: &Ctx, network: Network, what: &str) -> Result<(), CliError> {
    if network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the {what} are for {}; pass --network {0} to act on them",
                network_name(network)
            ),
        ));
    }
    Ok(())
}

// =============================================================================================
// Summary
// =============================================================================================

/// The x-only key a destination pays, if it pays one: a KAS P2PK or a KCC-20 PUBKEY owner.
fn payee(d: &DestinationV2) -> Option<[u8; 32]> {
    (d.identifier_type == IdentifierType::PubKey).then_some(d.identifier)
}

fn whose(t: &TermsV2, key: [u8; 32]) -> String {
    let legs: Vec<String> = t
        .legs
        .iter()
        .enumerate()
        .filter(|(_, l)| l.depositor_key == key)
        .map(|(i, _)| i.to_string())
        .collect();
    if !legs.is_empty() {
        format!(" = depositor of leg {}", legs.join(", "))
    } else if Some(key) == t.authority_key {
        " = authority_key".into()
    } else {
        " (a key that deposits no leg and is not the authority's)".into()
    }
}

/// A leg's destination as an address or KCC-20 owner, marked with the key it pays.
pub fn describe(t: &TermsV2, leg: &LegV2, d: &DestinationV2) -> String {
    let what = match leg.asset.kind {
        LegKind::Kcc20(_) => format!(
            "KCC-20 owner {} {}",
            id_name(d.identifier_type),
            hex(&d.identifier)
        ),
        _ => {
            let spk = kas_destination(d);
            summary::kas_address(t.network, spk.version(), spk.script())
        }
    };
    let mark = match payee(d) {
        Some(k) => whose(t, k),
        None => " (a script: check who controls it)".into(),
    };
    format!("{what}{mark}")
}

fn asset_line(leg: &Leg) -> String {
    match &leg.kind {
        LegKind::Kas => format!("KAS, {} sompi ({} KAS)", leg.amount, kas(leg.amount)),
        LegKind::Kcc20(token) => format!(
            "KCC-20 token covenant_id {}, template_hash {} ({}+{}), {} token units",
            hex(&token.covenant_id),
            hex(&token.template_hash),
            token.template_prefix_len,
            token.template_suffix_len,
            leg.amount
        ),
        LegKind::External => format!("external, amount {}", leg.amount),
    }
}

/// The funding deadline of D46: half the time from `now_daa` to expiry.
pub fn funding_deadline(t: &TermsV2, now_daa: u64) -> Option<u64> {
    t.expiry_daa
        .checked_sub(now_daa)
        .filter(|left| *left > 0)
        .map(|left| now_daa + left / 2)
}

/// The decoded terms v2, one line per field a party must agree to; `now_daa` is the DAA score
/// the expiry is measured from.
pub fn summary(terms: &ValidatedTermsV2, now_daa: u64) -> Vec<String> {
    let t = terms.terms();
    let expiry = match t.expiry_daa.checked_sub(now_daa) {
        Some(left) if left > 0 => format!(
            "{}, {} after DAA score {now_daa} (at {DAA_PER_SECOND} DAA scores per second)",
            t.expiry_daa,
            summary::approx_duration(left)
        ),
        _ => format!("{}, passed at DAA score {now_daa}", t.expiry_daa),
    };
    let mut lines = vec![
        format!("terms_hash: {}", hex(&terms.terms_hash())),
        format!("version: 2 (template v2, {} legs)", t.legs.len()),
        format!("network: {}", network_name(t.network)),
        format!("trade_ref: {}", hex(&t.trade_ref)),
        format!(
            "authority_key: {}",
            t.authority_key
                .map_or("none (self-settling)".to_string(), |k| hex(&k))
        ),
    ];
    for (i, l) in t.legs.iter().enumerate() {
        lines.push(format!(
            "leg {i}: depositor {}; {}",
            hex(&l.depositor_key),
            asset_line(&l.asset)
        ));
        lines.push(format!(
            "  leg {i} delivery: {}",
            describe(t, l, &l.delivery)
        ));
        lines.push(format!("  leg {i} refund: {}", describe(t, l, &l.refund)));
    }
    lines.push(format!(
        "earliest_daa: {}",
        t.earliest_daa.map_or("none".to_string(), |d| d.to_string())
    ));
    lines.push(format!("expiry_daa: {expiry}"));
    if let Some(deadline) = funding_deadline(t, now_daa) {
        lines.push(format!(
            "funding deadline: DAA score {deadline}, half the time to expiry (D46): nobody should fund after it"
        ));
    }
    lines.push(format!(
        "funding_mode: {}",
        match t.funding_mode {
            FundingMode::Revocable => "revocable: a depositor may refund its own leg at any time",
            FundingMode::Earmarked =>
                "earmarked: a depositor may refund its own leg only from expiry_daa",
        }
    ));
    lines.push(match t.partial {
        None => "partial: none (every leg settles whole, in one transaction)".into(),
        Some(p) => format!(
            "partial: lot_count {}, min_lot {} (each transaction exchanges whole lots of every leg at the agreed ratio; quantity across transactions is not enforced, spec/V2.md 4.6)",
            p.lot_count, p.min_lot
        ),
    });
    lines.push("refunds: any depositor of these terms, or the authority, may refund any leg; a refund always goes to that leg's refund destination above".into());
    lines.push("atomicity: the settle moves every leg in one Kaspa transaction or none of them; it can be built only once every leg is funded".into());
    lines
}

/// Warnings every v2 command that shows terms prints (spec/V2.md 4.4, D42).
pub fn warnings(t: &TermsV2) -> Vec<String> {
    let mut w = Vec::new();
    if t.partial.is_some() && t.authority_key.is_none() {
        w.push("warning: partial terms without an authority: anyone can front-run a tranche with another lot count (D42); no value leaves the agreed recipients".into());
    }
    for (i, token) in unpinned(t) {
        w.push(format!("warning: {}", unpinned_text(i, &token)));
    }
    w
}

// =============================================================================================
// Party check (spec/V2.md 6.5)
// =============================================================================================

/// What the party check found: the key, the legs it deposits, and the lines that report it.
pub type PartyCheck = ([u8; 32], Vec<usize>, Vec<String>);

/// Who the user is in a v2 trade: a depositor, named by public key only.
#[derive(Args, Debug, Clone)]
pub struct PartyV2Args {
    /// Your x-only public key, 64 lowercase hex digits: the depositor key of your leg or legs.
    #[arg(long, value_name = "HEX")]
    pub my_key: String,
    /// A destination a leg is delivered to that does not pay --my-key (your custodian or
    /// multisig): a Kaspa address or kcc20:<type>:<hex>. Repeat for several.
    #[arg(long, value_name = "DESTINATION")]
    pub my_delivery: Vec<String>,
    /// A refund destination of your legs that does not pay --my-key. Repeat for several.
    #[arg(long, value_name = "DESTINATION")]
    pub my_refund: Vec<String>,
}

/// The v2 destination as the v1 pin form compares it.
fn as_pin(leg: &LegV2, d: &DestinationV2) -> Destination {
    match leg.asset.kind {
        LegKind::Kcc20(_) => Destination::Kcc20(Kcc20Owner {
            identifier_type: d.identifier_type,
            identifier: d.identifier,
        }),
        _ => Destination::Kas(kas_destination(d)),
    }
}

/// The party check: `--my-key` deposits at least one leg (`CLI_ROLE_KEY_MISMATCH`); each of its
/// legs refunds to it or to a `--my-refund` pin and never to another depositor or the authority;
/// at least one other leg delivers to it or to a `--my-delivery` pin (`CLI_DESTINATION_NOT_MINE`).
/// Returns the key, the legs it deposits and the lines that report the check.
pub fn check_party(t: &TermsV2, args: &PartyV2Args) -> Result<PartyCheck, CliError> {
    let key = hash_arg("my-key", &args.my_key)?;
    let parse = |flag: &str, texts: &[String]| {
        texts
            .iter()
            .map(|p| parse_pin(flag, p, t.network))
            .collect::<Result<Vec<_>, _>>()
    };
    let delivery_pins = parse("--my-delivery", &args.my_delivery)?;
    let refund_pins = parse("--my-refund", &args.my_refund)?;
    let own: Vec<usize> = (0..t.legs.len())
        .filter(|&i| t.legs[i].depositor_key == key)
        .collect();
    if own.is_empty() {
        return Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            format!(
                "--my-key {} deposits no leg of these terms; these terms are not yours",
                hex(&key)
            ),
        ));
    }
    let mut ok = Vec::new();
    let mut refused = Vec::new();
    for &i in &own {
        let l = &t.legs[i];
        let d = &l.refund;
        let pinned = refund_pins.contains(&as_pin(l, d));
        match payee(d) {
            Some(k) if k != key && t.legs.iter().any(|o| o.depositor_key == k) => refused.push(
                format!("leg {i} refund pays {}: another depositor's key", describe(t, l, d)),
            ),
            Some(k) if Some(k) == t.authority_key => refused.push(format!(
                "leg {i} refund pays {}: the authority's key",
                describe(t, l, d)
            )),
            _ if pinned => ok.push(format!("leg {i} refund equals --my-refund")),
            Some(k) if k == key => ok.push(format!("leg {i} refund pays --my-key")),
            _ => refused.push(format!(
                "leg {i} refund pays {}, not --my-key (if your custodian or multisig controls it, pin it with --my-refund)",
                describe(t, l, d)
            )),
        }
    }
    let mut delivered = Vec::new();
    for (j, l) in t.legs.iter().enumerate() {
        if own.contains(&j) {
            continue;
        }
        let d = &l.delivery;
        if delivery_pins.contains(&as_pin(l, d)) {
            delivered.push(format!(
                "leg {j} is delivered to you (equals --my-delivery)"
            ));
        } else if payee(d) == Some(key) {
            delivered.push(format!("leg {j} is delivered to you (pays --my-key)"));
        }
    }
    if delivered.is_empty() {
        refused.push("no leg you do not deposit is delivered to --my-key or to a --my-delivery pin: you would give your legs and receive nothing".into());
    }
    if !refused.is_empty() {
        return Err(CliError::new(
            "CLI_DESTINATION_NOT_MINE",
            format!("{}. Refuse these terms", refused.join("; ")),
        ));
    }
    let legs: Vec<String> = own.iter().map(|i| i.to_string()).collect();
    let mut lines = vec![format!(
        "you: depositor of leg {}, key {}; {}",
        legs.join(", "),
        hex(&key),
        ok.join("; ")
    )];
    lines.extend(delivered.into_iter().map(|d| format!("you: {d}")));
    Ok((key, own, lines))
}

// =============================================================================================
// Value cap and the checks before funding
// =============================================================================================

/// The v2 value cap (spec/V2.md 6.5, D57): the trade value is the larger of the declared KAS
/// value of all legs together and the sum of the KAS legs; a KCC-20 leg needs the declaration.
pub(crate) fn cap(ctx: &Ctx, args: &CapArgs, t: &TermsV2) -> Result<String, CliError> {
    let policy = CapPolicy::new(ctx.env.max_value, args.i_accept_the_risk)?;
    cap_with(&policy, args.kas_equivalent, t)
}

pub(crate) fn cap_with(
    policy: &CapPolicy,
    kas_equivalent: Option<u64>,
    t: &TermsV2,
) -> Result<String, CliError> {
    let Some(cap) = policy.limit() else {
        return Ok("value cap: lifted by --i-accept-the-risk".into());
    };
    let all_kas = t.legs.iter().all(|l| l.asset.kind == LegKind::Kas);
    let kas_sum = t
        .legs
        .iter()
        .filter(|l| l.asset.kind == LegKind::Kas)
        .fold(0u64, |s, l| s.saturating_add(l.asset.amount));
    let declared = match kas_equivalent {
        Some(0) => {
            return Err(CliError::new(
                "CLI_VALUE_UNKNOWN",
                "--kas-equivalent 0 declares no value; give the KAS value of all legs together in sompi",
            ))
        }
        Some(v) => v,
        None if all_kas => 0,
        None => {
            return Err(CliError::new(
                "CLI_VALUE_UNKNOWN",
                "a leg is not native KAS, so the trade's value is unknown: pass --kas-equivalent <sompi> (the KAS value of all legs together) or --i-accept-the-risk",
            ))
        }
    };
    let value = kas_sum.max(declared);
    if value > cap {
        return Err(CliError::new(
            "CLI_VALUE_CAP_EXCEEDED",
            format!(
                "trade value {value} sompi is above the cap of {cap} sompi; pass --i-accept-the-risk to proceed"
            ),
        ));
    }
    Ok(format!(
        "value cap: trade value {value} sompi ({} KAS; declared {declared}, KAS legs together {kas_sum}) is within the cap of {cap} sompi",
        kas(value)
    ))
}

fn unpinned(t: &TermsV2) -> Vec<(usize, Kcc20Token)> {
    t.legs
        .iter()
        .enumerate()
        .filter_map(|(i, l)| match l.asset.kind {
            LegKind::Kcc20(token) if pinned_kcc20(&TemplateTriple::from(&token)).is_none() => {
                Some((i, token))
            }
            _ => None,
        })
        .collect()
}

fn unpinned_text(leg: usize, token: &Kcc20Token) -> String {
    format!(
        "leg {leg}'s KCC-20 template {} ({}+{}) is not a pinned kcc20.sil build (silverscript v1.0.0): the builders' compute budgets are measured for kcc20.sil only, so a settle or refund of this token may fail and leave it escrowed",
        hex(&token.template_hash),
        token.template_prefix_len,
        token.template_suffix_len
    )
}

/// Before funding (spec/V2.md 6.5): a KAS leg whose unit is below MIN_V2(1, O)
/// (`TX_BELOW_MIN_KAS`), then a KCC-20 template that is not a pinned kcc20.sil build
/// (`CLI_TEMPLATE_UNPINNED`).
pub fn before_funding(t: &TermsV2) -> Result<(), CliError> {
    check_kas_minimum(t)?;
    if let Some((leg, token)) = unpinned(t).first() {
        return Err(CliError::new(
            "CLI_TEMPLATE_UNPINNED",
            format!(
                "{}; such tokens are outside v0.2",
                unpinned_text(*leg, token)
            ),
        ));
    }
    Ok(())
}

/// A KAS leg whose unit is below MIN_V2(1, O): its delivery cannot be topped up (`[S5]`), so the
/// settle could exceed the storage cap; the fund builder refuses it (`TX_BELOW_MIN_KAS`).
pub fn check_kas_minimum(t: &TermsV2) -> Result<(), CliError> {
    let minimum = min_v2(t, 1);
    for (i, l) in t.legs.iter().enumerate() {
        if l.asset.kind == LegKind::Kas && t.unit(i) < minimum {
            return Err(CliError::new(
                "TX_BELOW_MIN_KAS",
                format!(
                    "leg {i} is a KAS leg of {} sompi per lot, below MIN_V2(1, O) = {minimum} for these terms (spec/V2.md 6.2): its settle output cannot be topped up, so the fund builder refuses it; do not fund these terms",
                    t.unit(i)
                ),
            ));
        }
    }
    Ok(())
}
