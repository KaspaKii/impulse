// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The JSON form of terms (spec/ENCODING.md, "Golden vectors") and of a creation context, in
//! Rust so that no SDK logic lives only in TypeScript.
//!
//! Terms: u64 values as decimal strings, u8, u16 and u32 as numbers, byte arrays and scripts as
//! lowercase hex, an absent optional as `null`, kinds and enumerations as lowercase strings, keys
//! in field order. Rendering writes exactly the `terms` object of a golden vector, so each terms
//! value has one rendered JSON form. Parsing is strict about keys and values: every key present,
//! no other key, and no other spelling of a value (no leading zero or sign on a decimal, no
//! upper-case hex, no number for a u64, no fraction for a u32). Key order is not significant.
//! It checks form only; the terms checks stay in impulse-core.
//!
//! A creation context: `network`, `creation_daa` and an optional `max_expiry_horizon_daa`;
//! absent means `DEFAULT_MAX_EXPIRY_HORIZON_DAA`, as `CreationContext::new` sets it.

use crate::error::{clipped, shown, SdkError};
use impulse_core::terms::{
    CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg,
    LegKind, Network, SettlementMode, Terms,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde_json::{Map, Value};

/// A canonical decimal u64: digits only, no sign, no leading zero, at most `u64::MAX`.
pub(crate) fn decimal_u64(s: &str) -> Option<u64> {
    let n: u64 = s.parse().ok()?;
    (n.to_string() == s).then_some(n)
}

/// Lowercase hex, even length.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?))
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn network_from_name(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        _ => None,
    }
}

pub(crate) fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

/// One JSON object read strictly: keys are taken one by one, and `finish` refuses any key that
/// was not taken.
pub(crate) struct Obj<'a> {
    path: String,
    map: &'a Map<String, Value>,
    taken: Vec<&'static str>,
}

impl<'a> Obj<'a> {
    pub(crate) fn new(value: &'a Value, path: &str) -> Result<Self, SdkError> {
        match value {
            Value::Object(map) => Ok(Self {
                path: path.into(),
                map,
                taken: Vec::new(),
            }),
            _ => Err(SdkError::json(path, "expected an object")),
        }
    }

    pub(crate) fn at(&self, key: &str) -> String {
        format!("{}.{}", self.path, clipped(key))
    }

    pub(crate) fn fail<T>(&self, key: &str, reason: impl Into<String>) -> Result<T, SdkError> {
        Err(SdkError::json(self.at(key), reason))
    }

    pub(crate) fn optional(&mut self, key: &'static str) -> Option<&'a Value> {
        self.taken.push(key);
        self.map.get(key)
    }

    pub(crate) fn value(&mut self, key: &'static str) -> Result<&'a Value, SdkError> {
        match self.optional(key) {
            Some(v) => Ok(v),
            None => self.fail(key, "missing"),
        }
    }

    pub(crate) fn str(&mut self, key: &'static str) -> Result<&'a str, SdkError> {
        match self.value(key)? {
            Value::String(s) => Ok(s),
            _ => self.fail(key, "expected a string"),
        }
    }

    pub(crate) fn object(&mut self, key: &'static str) -> Result<Obj<'a>, SdkError> {
        let path = self.at(key);
        Obj::new(self.value(key)?, &path)
    }

    pub(crate) fn u64(&mut self, key: &'static str) -> Result<u64, SdkError> {
        let s = self.str(key)?;
        decimal_u64(s).map_or_else(
            || {
                self.fail(
                    key,
                    "expected a u64 as a decimal string without sign or leading zero",
                )
            },
            Ok,
        )
    }

    pub(crate) fn number(&mut self, key: &'static str, max: u64) -> Result<u64, SdkError> {
        match self.value(key)?.as_u64() {
            Some(n) if n <= max => Ok(n),
            _ => self.fail(key, format!("expected an integer from 0 to {max}")),
        }
    }

    pub(crate) fn bool(&mut self, key: &'static str) -> Result<bool, SdkError> {
        match self.value(key)? {
            Value::Bool(b) => Ok(*b),
            _ => self.fail(key, "expected true or false"),
        }
    }

    /// The elements of an array, each with the path that names it.
    pub(crate) fn array(
        &mut self,
        key: &'static str,
    ) -> Result<Vec<(String, &'a Value)>, SdkError> {
        match self.value(key)? {
            Value::Array(items) => Ok(items
                .iter()
                .enumerate()
                .map(|(i, v)| (format!("{}[{i}]", self.at(key)), v))
                .collect()),
            _ => self.fail(key, "expected an array"),
        }
    }

    pub(crate) fn hex(&mut self, key: &'static str) -> Result<Vec<u8>, SdkError> {
        let s = self.str(key)?;
        hex_decode(s).map_or_else(|| self.fail(key, "expected lowercase hex"), Ok)
    }

    pub(crate) fn bytes32(&mut self, key: &'static str) -> Result<[u8; 32], SdkError> {
        let s = self.str(key)?;
        match hex_decode(s).map(<[u8; 32]>::try_from) {
            Some(Ok(b)) => Ok(b),
            _ => self.fail(key, "expected 64 lowercase hex digits"),
        }
    }

    /// `null` is absent; anything else is read by `read`.
    pub(crate) fn nullable<T>(
        &mut self,
        key: &'static str,
        read: impl FnOnce(&mut Self, &'static str) -> Result<T, SdkError>,
    ) -> Result<Option<T>, SdkError> {
        if self.value(key)?.is_null() {
            return Ok(None);
        }
        read(self, key).map(Some)
    }

    pub(crate) fn choice<T: Copy>(
        &mut self,
        key: &'static str,
        names: &[(&str, T)],
    ) -> Result<T, SdkError> {
        let s = self.str(key)?;
        match names.iter().find(|(n, _)| *n == s) {
            Some((_, v)) => Ok(*v),
            None => {
                let all: Vec<&str> = names.iter().map(|(n, _)| *n).collect();
                self.fail(
                    key,
                    format!("{} is not one of {}", shown(s), all.join(", ")),
                )
            }
        }
    }

    pub(crate) fn finish(self) -> Result<(), SdkError> {
        match self.map.keys().find(|k| !self.taken.contains(&k.as_str())) {
            Some(k) => self.fail(k, "unknown key"),
            None => Ok(()),
        }
    }
}

/// The KCC-20 owner identifier types by name.
pub(crate) const IDENTIFIER_TYPES: [(&str, IdentifierType); 3] = [
    ("pubkey", IdentifierType::PubKey),
    ("script_hash", IdentifierType::ScriptHash),
    ("covenant_id", IdentifierType::CovenantId),
];

const NETWORKS: [(&str, Network); 2] =
    [("mainnet", Network::Mainnet), ("testnet", Network::Testnet)];

/// Kinds of a leg: the token fields are read after the kind.
#[derive(Clone, Copy)]
enum LegTag {
    Kas,
    Kcc20,
    External,
}

#[derive(Clone, Copy)]
enum DestinationTag {
    Kas,
    Kcc20,
    OffChain,
}

fn leg(mut o: Obj) -> Result<Leg, SdkError> {
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

fn destination(mut o: Obj) -> Result<Destination, SdkError> {
    let tag = o.choice(
        "kind",
        &[
            ("kas", DestinationTag::Kas),
            ("kcc20", DestinationTag::Kcc20),
            ("off_chain", DestinationTag::OffChain),
        ],
    )?;
    let d = match tag {
        DestinationTag::Kas => {
            let version = o.number("version", u16::MAX.into())? as u16;
            Destination::Kas(ScriptPublicKey::from_vec(version, o.hex("script")?))
        }
        DestinationTag::Kcc20 => Destination::Kcc20(Kcc20Owner {
            identifier_type: o.choice("identifier_type", &IDENTIFIER_TYPES)?,
            identifier: o.bytes32("identifier")?,
        }),
        DestinationTag::OffChain => Destination::OffChain,
    };
    o.finish()?;
    Ok(d)
}

/// Parses the JSON form of terms. Form only: the result may still fail the terms checks.
pub(crate) fn terms_from_json(value: &Value) -> Result<Terms, SdkError> {
    let mut o = Obj::new(value, "terms")?;
    let t = Terms {
        version: o.number("version", u8::MAX.into())? as u8,
        network: o.choice("network", &NETWORKS)?,
        settlement_mode: o.choice(
            "settlement_mode",
            &[
                ("direct", SettlementMode::Direct),
                ("vault", SettlementMode::Vault),
            ],
        )?,
        nonce: o.u64("nonce")?,
        seller_key: o.bytes32("seller_key")?,
        buyer_key: o.bytes32("buyer_key")?,
        authority_key: o.nullable("authority_key", |o, k| o.bytes32(k))?,
        asset_leg: leg(o.object("asset_leg")?)?,
        cash_leg: leg(o.object("cash_leg")?)?,
        buyer_delivery: destination(o.object("buyer_delivery")?)?,
        seller_proceeds: destination(o.object("seller_proceeds")?)?,
        seller_refund: destination(o.object("seller_refund")?)?,
        buyer_refund: destination(o.object("buyer_refund")?)?,
        earliest_daa: o.nullable("earliest_daa", |o, k| o.u64(k))?,
        expiry_daa: o.u64("expiry_daa")?,
        funding_mode: o.choice(
            "funding_mode",
            &[
                ("revocable", FundingMode::Revocable),
                ("earmarked", FundingMode::Earmarked),
            ],
        )?,
        trade_ref: o.bytes32("trade_ref")?,
    };
    o.finish()?;
    Ok(t)
}

/// Parses a creation context.
pub(crate) fn context_from_json(value: &Value) -> Result<CreationContext, SdkError> {
    context_at(value, "context")
}

fn context_at(value: &Value, path: &str) -> Result<CreationContext, SdkError> {
    let mut o = Obj::new(value, path)?;
    let mut ctx = CreationContext::new(o.choice("network", &NETWORKS)?, o.u64("creation_daa")?);
    if o.optional("max_expiry_horizon_daa").is_some() {
        ctx.max_expiry_horizon_daa = o.u64("max_expiry_horizon_daa")?;
    }
    o.finish()?;
    Ok(ctx)
}

/// What `fundingInstructions` reads: a creation context, whether its DAA score came from a node,
/// and the value declaration and cap of spec/CLI.md, "Value cap".
pub(crate) struct FundingOptions {
    pub context: CreationContext,
    pub daa_from_node: bool,
    /// Which party the user is, their key and pins: the role check runs before any instruction
    /// is returned (`role.rs`).
    pub party: crate::role::Party,
    pub kas_equivalent: Option<u64>,
    /// The cap as the caller wrote it; the value-cap check reads it, so a bad cap gets its own
    /// code rather than a form refusal.
    pub cap: Option<String>,
    /// The SDK's `--i-accept-the-risk`: skips every value check. Absent or `null` is false.
    pub accept_the_risk: bool,
}

/// Parses the options of `fundingInstructions`: `context`, `creation_daa_source` (`typed` or
/// `node`) and `party` are required; `kas_equivalent`, `cap` and `accept_the_risk` may be absent or
/// `null`.
pub(crate) fn funding_options_from_json(value: &Value) -> Result<FundingOptions, SdkError> {
    let mut o = Obj::new(value, "options")?;
    let context = context_at(o.value("context")?, "options.context")?;
    let daa_from_node = o.choice("creation_daa_source", &[("typed", false), ("node", true)])?;
    let party = crate::role::party_from_json(o.value("party")?, "options.party")?;
    let kas_equivalent = match o.optional("kas_equivalent") {
        None | Some(Value::Null) => None,
        Some(_) => Some(o.u64("kas_equivalent")?),
    };
    let cap = match o.optional("cap") {
        None | Some(Value::Null) => None,
        Some(_) => Some(o.str("cap")?.to_string()),
    };
    let accept_the_risk = match o.optional("accept_the_risk") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return o.fail("accept_the_risk", "expected true or false"),
    };
    o.finish()?;
    Ok(FundingOptions {
        context,
        daa_from_node,
        party,
        kas_equivalent,
        cap,
        accept_the_risk,
    })
}

/// A network name on its own (`mainnet` or `testnet`).
pub(crate) fn network_from_json(name: &str) -> Result<Network, SdkError> {
    network_from_name(name).ok_or_else(|| {
        SdkError::json(
            "network",
            format!("{} is not one of mainnet, testnet", shown(name)),
        )
    })
}

// Rendering: an ordered tree, written compactly.

enum J {
    Str(String),
    Num(u64),
    Null,
    Obj(Vec<(&'static str, J)>),
}

fn s(v: &str) -> J {
    J::Str(v.into())
}

fn dec(n: u64) -> J {
    J::Str(n.to_string())
}

fn write(j: &J, out: &mut String) {
    match j {
        // Display of a JSON string value is its quoted, escaped form.
        J::Str(v) => out.push_str(&Value::String(v.clone()).to_string()),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Null => out.push_str("null"),
        J::Obj(fields) => {
            out.push('{');
            for (i, (key, value)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(key);
                out.push_str("\":");
                write(value, out);
            }
            out.push('}');
        }
    }
}

fn leg_json(leg: &Leg) -> J {
    let mut f = Vec::new();
    match &leg.kind {
        LegKind::Kas => f.push(("kind", s("kas"))),
        LegKind::Kcc20(t) => {
            f.push(("kind", s("kcc20")));
            f.push(("covenant_id", J::Str(hex(&t.covenant_id))));
            f.push(("template_hash", J::Str(hex(&t.template_hash))));
            f.push(("template_prefix_len", J::Num(t.template_prefix_len.into())));
            f.push(("template_suffix_len", J::Num(t.template_suffix_len.into())));
        }
        LegKind::External => f.push(("kind", s("external"))),
    }
    f.push(("amount", dec(leg.amount)));
    J::Obj(f)
}

fn destination_json(d: &Destination) -> J {
    match d {
        Destination::Kas(spk) => J::Obj(vec![
            ("kind", s("kas")),
            ("version", J::Num(spk.version().into())),
            ("script", J::Str(hex(spk.script()))),
        ]),
        Destination::Kcc20(o) => J::Obj(vec![
            ("kind", s("kcc20")),
            (
                "identifier_type",
                s(match o.identifier_type {
                    IdentifierType::PubKey => "pubkey",
                    IdentifierType::ScriptHash => "script_hash",
                    IdentifierType::CovenantId => "covenant_id",
                }),
            ),
            ("identifier", J::Str(hex(&o.identifier))),
        ]),
        Destination::OffChain => J::Obj(vec![("kind", s("off_chain"))]),
    }
}

/// A destination in its JSON form, as compact JSON text.
pub(crate) fn destination_to_json(d: &Destination) -> String {
    let mut out = String::new();
    write(&destination_json(d), &mut out);
    out
}

/// The JSON form of terms as compact JSON text, keys in field order.
pub(crate) fn terms_to_json(t: &Terms) -> String {
    let j = J::Obj(vec![
        ("version", J::Num(t.version.into())),
        ("network", s(network_name(t.network))),
        (
            "settlement_mode",
            s(match t.settlement_mode {
                SettlementMode::Direct => "direct",
                SettlementMode::Vault => "vault",
            }),
        ),
        ("nonce", dec(t.nonce)),
        ("seller_key", J::Str(hex(&t.seller_key))),
        ("buyer_key", J::Str(hex(&t.buyer_key))),
        (
            "authority_key",
            t.authority_key.map_or(J::Null, |k| J::Str(hex(&k))),
        ),
        ("asset_leg", leg_json(&t.asset_leg)),
        ("cash_leg", leg_json(&t.cash_leg)),
        ("buyer_delivery", destination_json(&t.buyer_delivery)),
        ("seller_proceeds", destination_json(&t.seller_proceeds)),
        ("seller_refund", destination_json(&t.seller_refund)),
        ("buyer_refund", destination_json(&t.buyer_refund)),
        ("earliest_daa", t.earliest_daa.map_or(J::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            s(match t.funding_mode {
                FundingMode::Revocable => "revocable",
                FundingMode::Earmarked => "earmarked",
            }),
        ),
        ("trade_ref", J::Str(hex(&t.trade_ref))),
    ]);
    let mut out = String::new();
    write(&j, &mut out);
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use impulse_core::terms::DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    use std::path::Path;

    /// (name, file text) of every committed terms vector.
    fn vector_files() -> Vec<(String, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
        let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
            .expect("read tests/vectors/terms")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .map(|p| {
                let text = std::fs::read_to_string(&p).expect("read vector");
                (p.file_name().unwrap().to_string_lossy().into_owned(), text)
            })
            .collect();
        out.sort();
        assert!(out.len() >= 11, "the eleven terms vectors of I2 and I4");
        out
    }

    /// The `terms` object of a vector file as it is written there, with the layout whitespace
    /// removed. The terms strings hold no whitespace, so this keeps the file's key order and
    /// every value byte for byte.
    fn committed_terms_text(file: &str) -> String {
        let start = file.find("\"terms\": {").expect("terms key") + "\"terms\": ".len();
        let mut depth = 0usize;
        let mut end = start;
        for (i, c) in file[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        file[start..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    fn vector(file: &str) -> (Value, Vec<u8>) {
        let doc: Value = serde_json::from_str(file).expect("vector parses");
        let canonical = hex_decode(doc["canonical"].as_str().expect("canonical")).expect("hex");
        (doc["terms"].clone(), canonical)
    }

    fn vector_02() -> Value {
        let files = vector_files();
        let (_, text) = files
            .iter()
            .find(|(n, _)| n.starts_with("02-"))
            .expect("vector 02");
        vector(text).0
    }

    #[test]
    fn every_vector_parses_encodes_and_renders_byte_for_byte() {
        for (name, file) in vector_files() {
            let (json, canonical) = vector(&file);
            let terms = terms_from_json(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(terms.encode().unwrap(), canonical, "{name}: encoding");
            let decoded = Terms::decode(&canonical).unwrap();
            assert_eq!(decoded, terms, "{name}: decode");
            assert_eq!(
                terms_to_json(&decoded),
                committed_terms_text(&file),
                "{name}: rendered JSON form"
            );
        }
    }

    /// Edits vector 02's JSON form at `path` (keys separated by '/'); `None` removes the key.
    fn edited(path: &str, value: Option<Value>) -> Value {
        let mut v = vector_02();
        let mut keys: Vec<&str> = path.split('/').collect();
        let last = keys.pop().unwrap();
        let mut cur = &mut v;
        for k in keys {
            cur = cur.get_mut(k).expect("path exists");
        }
        let map = cur.as_object_mut().expect("object");
        match value {
            Some(x) => {
                map.insert(last.into(), x);
            }
            None => {
                map.remove(last);
            }
        }
        v
    }

    fn refused(v: &Value) -> SdkError {
        terms_from_json(v).expect_err("refused")
    }

    #[test]
    fn the_form_is_strict_with_an_accepted_control_for_each_refusal() {
        use serde_json::json;
        // (path, accepted value, refused value, expected path in the refusal)
        let cases: Vec<(&str, Value, Value)> = vec![
            ("version", json!(1), json!("1")),
            ("version", json!(255), json!(256)),
            ("version", json!(0), json!(-1)),
            ("version", json!(1), json!(1.5)),
            // serde_json reads the text -0 as a float; the SDK reads a JavaScript -0 the same way.
            ("version", json!(0), serde_json::from_str("-0").unwrap()),
            ("network", json!("testnet"), json!("Mainnet")),
            ("network", json!("testnet"), json!("tn10")),
            ("network", json!("testnet"), json!("testnet-10")),
            ("settlement_mode", json!("direct"), json!("escrow")),
            ("nonce", json!("0"), json!("00")),
            (
                "nonce",
                json!("18446744073709551615"),
                json!("18446744073709551616"),
            ),
            ("nonce", json!("1"), json!("+1")),
            ("nonce", json!("1"), json!(1)),
            ("nonce", json!("1"), json!(" 1")),
            (
                "seller_key",
                json!("95e2f4e4fe97ed99e78ac44930508f03b408bde943a16d35bd8f1d0228a8bc3e"),
                json!("95E2F4E4FE97ED99E78AC44930508F03B408BDE943A16D35BD8F1D0228A8BC3E"),
            ),
            (
                "seller_key",
                json!("95e2f4e4fe97ed99e78ac44930508f03b408bde943a16d35bd8f1d0228a8bc3e"),
                json!("95e2f4e4fe97ed99e78ac44930508f03b408bde943a16d35bd8f1d0228a8bc"),
            ),
            ("authority_key", Value::Null, json!("")),
            ("asset_leg/kind", json!("kcc20"), json!("KCC20")),
            (
                "asset_leg/template_prefix_len",
                json!(4294967295u64),
                json!(4294967296u64),
            ),
            (
                "asset_leg/template_suffix_len",
                json!(4294967295u64),
                json!(4294967296u64),
            ),
            ("asset_leg/amount", json!("500"), json!("5e2")),
            ("cash_leg/kind", json!("kas"), json!("sompi")),
            (
                "buyer_delivery/identifier_type",
                json!("covenant_id"),
                json!("covenant"),
            ),
            ("seller_proceeds/version", json!(65535), json!(65536)),
            ("seller_proceeds/script", json!(""), json!("2")),
            ("seller_proceeds/script", json!("ab"), json!("0xab")),
            ("seller_proceeds/script", json!("ab"), json!("AB")),
            ("earliest_daa", json!("1"), json!(0)),
            ("expiry_daa", json!("406048000"), Value::Null),
            ("funding_mode", json!("earmarked"), json!("irrevocable")),
            (
                "trade_ref",
                json!("f324be7ab26e3966603b1a046b2e7e96c75e20099c1cb6ccd3f20a6e94047a66"),
                json!([1, 2, 3]),
            ),
        ];
        for (path, accepted, refused_value) in cases {
            let ok = edited(path, Some(accepted.clone()));
            assert!(
                terms_from_json(&ok).is_ok(),
                "{path} = {accepted} is accepted"
            );
            let e = refused(&edited(path, Some(refused_value.clone())));
            assert_eq!(e.code(), "SDK_JSON_FORM", "{path} = {refused_value}");
            let want = format!("terms.{}", path.replace('/', "."));
            assert!(
                matches!(&e, SdkError::JsonForm { path: p, .. } if *p == want),
                "{path} = {refused_value}: {e}"
            );
        }
    }

    #[test]
    fn every_key_is_required_and_no_other_key_is_accepted() {
        // Removing any key of the root, a leg or a destination is refused.
        let root = vector_02();
        let mut paths: Vec<String> = Vec::new();
        for (k, v) in root.as_object().unwrap() {
            paths.push(k.clone());
            if let Value::Object(inner) = v {
                paths.extend(inner.keys().map(|ik| format!("{k}/{ik}")));
            }
        }
        assert!(paths.len() > 30);
        for path in &paths {
            let e = refused(&edited(path, None));
            assert_eq!(e.code(), "SDK_JSON_FORM", "{path} removed");
            assert!(e.to_string().ends_with("missing"), "{path}: {e}");
        }
        // An absent optional is null, never a missing key.
        let e = refused(&edited("earliest_daa", None));
        assert!(e.to_string().contains("terms.earliest_daa: missing"), "{e}");
        // An extra key anywhere is refused; the control is the unchanged vector.
        assert!(terms_from_json(&root).is_ok());
        for path in ["note", "asset_leg/note", "seller_proceeds/note"] {
            let e = refused(&edited(path, Some(Value::Bool(true))));
            assert!(e.to_string().ends_with("unknown key"), "{path}: {e}");
        }
        // A key that belongs to another kind is unknown for this one: KAS cash has no covenant.
        let e = refused(&edited(
            "cash_leg/covenant_id",
            Some(serde_json::json!("00".repeat(32))),
        ));
        assert!(
            e.to_string()
                .contains("terms.cash_leg.covenant_id: unknown key"),
            "{e}"
        );
        // Not an object at all.
        for v in [
            Value::Null,
            serde_json::json!([]),
            serde_json::json!("terms"),
        ] {
            assert_eq!(refused(&v).code(), "SDK_JSON_FORM");
        }
    }

    #[test]
    fn creation_context_form() {
        use serde_json::json;
        let ctx =
            context_from_json(&json!({"network": "mainnet", "creation_daa": "400000000"})).unwrap();
        assert_eq!(ctx, CreationContext::new(Network::Mainnet, 400_000_000));
        assert_eq!(ctx.max_expiry_horizon_daa, DEFAULT_MAX_EXPIRY_HORIZON_DAA);
        let ctx = context_from_json(&json!({
            "network": "testnet", "creation_daa": "0", "max_expiry_horizon_daa": "18446744073709551615"
        }))
        .unwrap();
        assert_eq!(ctx.network, Network::Testnet);
        assert_eq!(ctx.max_expiry_horizon_daa, u64::MAX);
        for bad in [
            json!({"network": "mainnet"}),
            json!({"network": "main", "creation_daa": "1"}),
            json!({"network": "tn10", "creation_daa": "1"}),
            json!({"network": "mainnet", "creation_daa": 1}),
            json!({"network": "mainnet", "creation_daa": "-1"}),
            json!({"network": "mainnet", "creation_daa": "1", "max_expiry_horizon_daa": null}),
            json!({"network": "mainnet", "creation_daa": "1", "creation": "1"}),
            json!("mainnet"),
        ] {
            let e = context_from_json(&bad).expect_err("refused");
            assert_eq!(e.code(), "SDK_JSON_FORM", "{bad}");
        }
    }

    #[test]
    fn decimal_and_hex_spellings() {
        assert_eq!(decimal_u64("0"), Some(0));
        assert_eq!(decimal_u64("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "-0",
            "+0",
            "01",
            "1.0",
            "1e3",
            "0x10",
            "18446744073709551616",
            " 1",
        ] {
            assert_eq!(decimal_u64(bad), None, "{bad:?}");
        }
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("00ff"), Some(vec![0, 255]));
        for bad in ["0", "0F", "zz", "0x00", " 00"] {
            assert_eq!(hex_decode(bad), None, "{bad:?}");
        }
        assert_eq!(network_from_json("testnet"), Ok(Network::Testnet));
        assert_eq!(
            network_from_json("tn10").map_err(|e| e.code()),
            Err("SDK_JSON_FORM")
        );
    }

    #[test]
    fn refusals_cut_the_caller_strings_they_echo() {
        // A short value is shown whole; a long one is cut, so a message stays short.
        let e = refused(&edited("network", Some(Value::String("tn10".into()))));
        assert_eq!(
            e.to_string(),
            "SDK_JSON_FORM: terms.network: \"tn10\" is not one of mainnet, testnet"
        );
        let long = "y".repeat(100_000);
        for e in [
            refused(&edited("network", Some(Value::String(long.clone())))),
            refused(&edited("funding_mode", Some(Value::String(long.clone())))),
            refused(&edited(&long, Some(Value::Bool(true)))),
            network_from_json(&long).unwrap_err(),
        ] {
            assert_eq!(e.code(), "SDK_JSON_FORM");
            assert!(e.to_string().len() < 200, "{e}");
        }
    }
}
