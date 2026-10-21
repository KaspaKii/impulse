// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms drafts and terms files (spec/CLI.md, "Terms draft and terms file"). The JSON form of
//! terms is the one spec/ENCODING.md defines for the golden vectors. A terms file carries the JSON
//! form, the canonical bytes and the terms hash, and is refused unless all three agree.

use crate::error::CliError;
use crate::json::{hex, parse_strict, Json, Obj};
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, ValidatedTerms,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde_json::Value;
use std::path::Path;

const TERMS_KEYS: [&str; 17] = [
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
    "trade_ref",
];

fn json_err(reason: String) -> CliError {
    CliError::new("CLI_TERMS_JSON", reason)
}

/// The most bytes `read_text` reads: every document the CLI takes (terms, drafts, IPSTs,
/// receipts, proofs, templates, manifests) is far smaller; the largest committed vector, a
/// ten-leg IPST, is under 256 KiB.
pub const MAX_TEXT_FILE: u64 = 16 << 20;
/// The cap of an owner list (`impulse zk`): up to 1,048,576 entries of about 76 bytes, and
/// comment lines.
pub const MAX_LIST_FILE: u64 = 256 << 20;

/// Reads at most `limit` bytes of a file: a longer one is refused without being read whole.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = vec![];
    file.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > limit {
        return Err(format!("larger than {limit} bytes; refused"));
    }
    Ok(buf)
}

/// Reads a whole file as UTF-8 text, up to `MAX_TEXT_FILE` bytes.
pub fn read_text(path: &Path) -> Result<String, CliError> {
    read_text_max(path, MAX_TEXT_FILE)
}

/// Reads a whole file as UTF-8 text, up to `limit` bytes.
pub fn read_text_max(path: &Path, limit: u64) -> Result<String, CliError> {
    let err = |e: String| CliError::new("CLI_FILE_READ", format!("{}: {e}", path.display()));
    String::from_utf8(read_bounded(path, limit).map_err(err)?)
        .map_err(|_| err("stream did not contain valid UTF-8".into()))
}

/// Writes `text` to a path that must not exist yet.
pub fn write_new(path: &Path, text: &str) -> Result<(), CliError> {
    write_new_bytes(path, text.as_bytes())
}

/// Writes `bytes` to a path that must not exist yet.
pub fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
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

fn parse_json(text: &str) -> Result<Value, CliError> {
    parse_strict(text).map_err(json_err)
}

/// A draft: the JSON form of terms with `nonce` absent or null allowed. A missing nonce is drawn
/// from the operating system's random source.
pub fn parse_draft(text: &str) -> Result<Terms, CliError> {
    let value = parse_json(text)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&without_nonce(), &["nonce"]).map_err(json_err)?;
    let nonce = match obj.opt("nonce") {
        Some(_) => obj.dec("nonce").map_err(json_err)?,
        None => rand::random::<u64>(),
    };
    terms_fields(&obj, nonce).map_err(json_err)
}

fn without_nonce() -> Vec<&'static str> {
    TERMS_KEYS.into_iter().filter(|k| *k != "nonce").collect()
}

/// The JSON form of terms, every key present and no other.
pub fn parse_terms_json(value: &Value) -> Result<Terms, CliError> {
    let obj = Obj::new("terms", value).map_err(json_err)?;
    obj.keys(&TERMS_KEYS, &[]).map_err(json_err)?;
    let nonce = obj.dec("nonce").map_err(json_err)?;
    terms_fields(&obj, nonce).map_err(json_err)
}

fn terms_fields(o: &Obj, nonce: u64) -> Result<Terms, String> {
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
    Ok(Terms {
        version: o.num("version", u8::MAX.into())? as u8,
        network: [Network::Mainnet, Network::Testnet]
            [o.choice("network", &["mainnet", "testnet"])?],
        settlement_mode: [SettlementMode::Direct, SettlementMode::Vault]
            [o.choice("settlement_mode", &["direct", "vault"])?],
        nonce,
        seller_key: o.hex32("seller_key")?,
        buyer_key: o.hex32("buyer_key")?,
        authority_key,
        asset_leg: leg(&o.obj("asset_leg")?)?,
        cash_leg: leg(&o.obj("cash_leg")?)?,
        buyer_delivery: destination(&o.obj("buyer_delivery")?)?,
        seller_proceeds: destination(&o.obj("seller_proceeds")?)?,
        seller_refund: destination(&o.obj("seller_refund")?)?,
        buyer_refund: destination(&o.obj("buyer_refund")?)?,
        earliest_daa,
        expiry_daa: o.dec("expiry_daa")?,
        funding_mode: [FundingMode::Revocable, FundingMode::Earmarked]
            [o.choice("funding_mode", &["revocable", "earmarked"])?],
        trade_ref: o.hex32("trade_ref")?,
    })
}

fn leg(o: &Obj) -> Result<Leg, String> {
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

fn destination(o: &Obj) -> Result<Destination, String> {
    match o.choice("kind", &["kas", "kcc20", "off_chain"])? {
        0 => {
            o.keys(&["kind", "version", "script"], &[])?;
            Ok(Destination::Kas(ScriptPublicKey::from_vec(
                o.num("version", u16::MAX.into())? as u16,
                o.hex("script")?,
            )))
        }
        1 => {
            o.keys(&["kind", "identifier_type", "identifier"], &[])?;
            let identifier_type = [
                IdentifierType::PubKey,
                IdentifierType::ScriptHash,
                IdentifierType::CovenantId,
            ][o.choice("identifier_type", &["pubkey", "script_hash", "covenant_id"])?];
            Ok(Destination::Kcc20(Kcc20Owner {
                identifier_type,
                identifier: o.hex32("identifier")?,
            }))
        }
        _ => {
            o.keys(&["kind"], &[])?;
            Ok(Destination::OffChain)
        }
    }
}

/// The JSON form of `t`, keys in field order.
pub fn terms_json(t: &Terms) -> Json {
    let dec = |n: u64| Json::Str(n.to_string());
    let s = |x: &str| Json::Str(x.to_string());
    Json::Obj(vec![
        ("version", Json::Num(t.version.into())),
        ("network", s(network_name(t.network))),
        (
            "settlement_mode",
            s(match t.settlement_mode {
                SettlementMode::Direct => "direct",
                SettlementMode::Vault => "vault",
            }),
        ),
        ("nonce", dec(t.nonce)),
        ("seller_key", Json::Str(hex(&t.seller_key))),
        ("buyer_key", Json::Str(hex(&t.buyer_key))),
        (
            "authority_key",
            t.authority_key.map_or(Json::Null, |k| Json::Str(hex(&k))),
        ),
        ("asset_leg", leg_json(&t.asset_leg)),
        ("cash_leg", leg_json(&t.cash_leg)),
        ("buyer_delivery", destination_json(&t.buyer_delivery)),
        ("seller_proceeds", destination_json(&t.seller_proceeds)),
        ("seller_refund", destination_json(&t.seller_refund)),
        ("buyer_refund", destination_json(&t.buyer_refund)),
        ("earliest_daa", t.earliest_daa.map_or(Json::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            s(match t.funding_mode {
                FundingMode::Revocable => "revocable",
                FundingMode::Earmarked => "earmarked",
            }),
        ),
        ("trade_ref", Json::Str(hex(&t.trade_ref))),
    ])
}

pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

fn leg_json(leg: &Leg) -> Json {
    let mut fields = Vec::new();
    match &leg.kind {
        LegKind::Kas => fields.push(("kind", Json::Str("kas".into()))),
        LegKind::Kcc20(t) => {
            fields.push(("kind", Json::Str("kcc20".into())));
            fields.push(("covenant_id", Json::Str(hex(&t.covenant_id))));
            fields.push(("template_hash", Json::Str(hex(&t.template_hash))));
            fields.push((
                "template_prefix_len",
                Json::Num(t.template_prefix_len.into()),
            ));
            fields.push((
                "template_suffix_len",
                Json::Num(t.template_suffix_len.into()),
            ));
        }
        LegKind::External => fields.push(("kind", Json::Str("external".into()))),
    }
    fields.push(("amount", Json::Str(leg.amount.to_string())));
    Json::Obj(fields)
}

fn destination_json(d: &Destination) -> Json {
    match d {
        Destination::Kas(spk) => Json::Obj(vec![
            ("kind", Json::Str("kas".into())),
            ("version", Json::Num(spk.version().into())),
            ("script", Json::Str(hex(spk.script()))),
        ]),
        Destination::Kcc20(o) => Json::Obj(vec![
            ("kind", Json::Str("kcc20".into())),
            (
                "identifier_type",
                Json::Str(
                    match o.identifier_type {
                        IdentifierType::PubKey => "pubkey",
                        IdentifierType::ScriptHash => "script_hash",
                        IdentifierType::CovenantId => "covenant_id",
                    }
                    .into(),
                ),
            ),
            ("identifier", Json::Str(hex(&o.identifier))),
        ]),
        Destination::OffChain => Json::Obj(vec![("kind", Json::Str("off_chain".into()))]),
    }
}

/// The terms file text for structure-checked terms.
pub fn render_terms_file(terms: &ValidatedTerms) -> String {
    Json::Obj(vec![
        ("terms", terms_json(terms.terms())),
        ("canonical", Json::Str(hex(terms.canonical()))),
        ("terms_hash", Json::Str(hex(&terms.terms_hash()))),
    ])
    .render()
}

/// Parses a terms file and runs the structure checks. Refuses a file whose three parts disagree.
pub fn parse_terms_file(text: &str) -> Result<ValidatedTerms, CliError> {
    let value = parse_json(text)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&["terms", "canonical", "terms_hash"], &[])
        .map_err(json_err)?;
    let terms = parse_terms_json(obj.get("terms").map_err(json_err)?)?;
    let canonical = obj.hex("canonical").map_err(json_err)?;
    let hash = obj.hex32("terms_hash").map_err(json_err)?;
    let inconsistent = |what: &str| CliError::new("CLI_TERMS_FILE_INCONSISTENT", what.to_string());
    let encoded = terms.encode()?;
    if encoded != canonical {
        return Err(inconsistent("canonical is not the encoding of terms"));
    }
    if terms.terms_hash()? != hash {
        return Err(inconsistent("terms_hash is not the hash of terms"));
    }
    Ok(terms.validate_structure()?)
}

/// Reads and checks a terms file from disk.
pub fn read_terms_file(path: &Path) -> Result<ValidatedTerms, CliError> {
    parse_terms_file(&read_text(path)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    pub(crate) fn vectors_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms")
    }

    /// Every committed terms vector as (name, terms file text built from its three parts).
    pub(crate) fn vector_terms_files() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(vectors_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        for p in paths {
            let doc: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            let file = serde_json::json!({
                "terms": doc["terms"],
                "canonical": doc["canonical"],
                "terms_hash": doc["terms_hash"],
            });
            out.push((doc["name"].as_str().unwrap().to_string(), file.to_string()));
        }
        assert_eq!(out.len(), 11, "the eleven golden terms vectors");
        out
    }

    pub(crate) fn vector_file(name_prefix: &str) -> String {
        vector_terms_files()
            .into_iter()
            .find(|(n, _)| n.starts_with(name_prefix))
            .unwrap()
            .1
    }

    #[test]
    fn every_golden_vector_reads_as_a_terms_file() {
        for (name, text) in vector_terms_files() {
            let checked = parse_terms_file(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            // Rendering and reading back is the identity, byte for byte on the canonical form.
            let again = parse_terms_file(&render_terms_file(&checked)).unwrap();
            assert_eq!(again, checked, "{name}");
        }
    }

    #[test]
    fn rendered_terms_match_the_committed_json_form() {
        // The vectors' `terms` objects were written by impulse-core's golden renderer; ours must
        // produce the same text, so the two JSON forms cannot drift.
        for entry in std::fs::read_dir(vectors_dir()).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            let doc: Value = serde_json::from_str(&text).unwrap();
            let terms = parse_terms_json(&doc["terms"]).unwrap();
            let rendered = terms_json(&terms).render();
            let reparsed: Value = serde_json::from_str(&rendered).unwrap();
            assert_eq!(reparsed, doc["terms"]);
            let indented: String = rendered
                .trim_end()
                .lines()
                .map(|l| format!("  {l}\n"))
                .collect();
            assert!(text.contains(indented.trim()), "text form drifted");
        }
    }

    fn edit(text: &str, f: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(text).unwrap();
        f(&mut v);
        v.to_string()
    }

    #[test]
    fn inconsistent_files_are_refused() {
        let good = vector_file("02-");
        assert!(parse_terms_file(&good).is_ok(), "control");
        // canonical alone altered: terms and terms_hash still agree with each other.
        let canonical_only = edit(&good, |v| {
            let c = format!("{}00", v["canonical"].as_str().unwrap());
            v["canonical"] = Value::String(c);
        });
        assert_eq!(
            parse_terms_file(&canonical_only).unwrap_err().code(),
            "CLI_TERMS_FILE_INCONSISTENT"
        );
        let flipped_hash = edit(&good, |v| {
            let h = v["terms_hash"].as_str().unwrap().replacen('b', "c", 1);
            v["terms_hash"] = Value::String(h);
        });
        assert_eq!(
            parse_terms_file(&flipped_hash).unwrap_err().code(),
            "CLI_TERMS_FILE_INCONSISTENT"
        );
        let other_amount = edit(&good, |v| v["terms"]["asset_leg"]["amount"] = "501".into());
        assert_eq!(
            parse_terms_file(&other_amount).unwrap_err().code(),
            "CLI_TERMS_FILE_INCONSISTENT"
        );
    }

    #[test]
    fn malformed_json_forms_are_refused() {
        let good = vector_file("02-");
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("extra key", Box::new(|v| v["extra"] = 1.into())),
            (
                "missing key",
                Box::new(|v| {
                    v["terms"].as_object_mut().unwrap().remove("trade_ref");
                }),
            ),
            (
                "nonce as number",
                Box::new(|v| v["terms"]["nonce"] = 5.into()),
            ),
            (
                "leading zero",
                Box::new(|v| v["terms"]["expiry_daa"] = "0406048000".into()),
            ),
            (
                "uppercase hex",
                Box::new(|v| {
                    let k = v["terms"]["seller_key"].as_str().unwrap().to_uppercase();
                    v["terms"]["seller_key"] = k.into();
                }),
            ),
            (
                "unknown kind",
                Box::new(|v| v["terms"]["cash_leg"]["kind"] = "btc".into()),
            ),
            (
                "kcc20 field on a kas leg",
                Box::new(|v| v["terms"]["cash_leg"]["covenant_id"] = "00".into()),
            ),
            (
                "version too big",
                Box::new(|v| v["terms"]["version"] = 256.into()),
            ),
            ("terms not an object", Box::new(|v| v["terms"] = "x".into())),
        ];
        for (what, f) in cases {
            let bad = edit(&good, f);
            assert_eq!(
                parse_terms_file(&bad).unwrap_err().code(),
                "CLI_TERMS_JSON",
                "{what}"
            );
        }
        assert_eq!(parse_terms_file("{").unwrap_err().code(), "CLI_TERMS_JSON");
        // A key given twice, with the same value or another: refused, in the file and in terms.
        let hash = format!("\"terms_hash\":\"{}\"", "00".repeat(32));
        let twice = good.replacen("\"terms_hash\":", &format!("{hash},\"terms_hash\":"), 1);
        assert_ne!(twice, good);
        assert_eq!(
            parse_terms_file(&twice).unwrap_err().code(),
            "CLI_TERMS_JSON"
        );
        let nonce = good.replacen("\"nonce\":", "\"nonce\":\"1\",\"nonce\":", 1);
        assert_ne!(nonce, good);
        assert_eq!(
            parse_terms_file(&nonce).unwrap_err().code(),
            "CLI_TERMS_JSON"
        );
        assert_eq!(
            parse_draft(&nonce_draft_twice()).unwrap_err().code(),
            "CLI_TERMS_JSON"
        );
    }

    fn nonce_draft_twice() -> String {
        let v: Value = serde_json::from_str(&vector_file("02-")).unwrap();
        let draft = v["terms"].to_string();
        assert!(parse_draft(&draft).is_ok(), "control");
        draft.replacen("\"nonce\":", "\"nonce\":\"1\",\"nonce\":", 1)
    }

    #[test]
    fn structure_checks_run_on_read() {
        // A self-consistent file whose terms fail a structure check keeps the terms code.
        let good = vector_file("02-");
        let v: Value = serde_json::from_str(&good).unwrap();
        let mut terms = parse_terms_json(&v["terms"]).unwrap();
        terms.buyer_key = terms.seller_key;
        let file = Json::Obj(vec![
            ("terms", terms_json(&terms)),
            ("canonical", Json::Str(hex(&terms.encode().unwrap()))),
            ("terms_hash", Json::Str(hex(&terms.terms_hash().unwrap()))),
        ])
        .render();
        assert_eq!(
            parse_terms_file(&file).unwrap_err().code(),
            "TERMS_PARTIES_NOT_DISTINCT"
        );
    }

    #[test]
    fn drafts_draw_a_nonce_when_absent() {
        let v: Value = serde_json::from_str(&vector_file("02-")).unwrap();
        let mut draft = v["terms"].clone();
        let with = parse_draft(&draft.to_string()).unwrap();
        assert_eq!(
            with.nonce, 18424037273184917500,
            "an explicit nonce is kept"
        );
        draft["nonce"] = Value::Null;
        let a = parse_draft(&draft.to_string()).unwrap();
        draft.as_object_mut().unwrap().remove("nonce");
        let b = parse_draft(&draft.to_string()).unwrap();
        assert_ne!(
            a.nonce, b.nonce,
            "two draws differ (probability 2^-64 of a false failure)"
        );
        draft["surprise"] = 1.into();
        assert_eq!(
            parse_draft(&draft.to_string()).unwrap_err().code(),
            "CLI_TERMS_JSON"
        );
    }

    #[test]
    fn outputs_are_never_overwritten() {
        let dir = crate::testutil::TempDir::new();
        let path = dir.path().join("terms.json");
        write_new(&path, "first").unwrap();
        assert_eq!(
            write_new(&path, "second").unwrap_err().code(),
            "CLI_OUTPUT_EXISTS"
        );
        assert_eq!(read_text(&path).unwrap(), "first");
        let missing = dir.path().join("missing.json");
        assert_eq!(read_text(&missing).unwrap_err().code(), "CLI_FILE_READ");
        let no_dir = dir.path().join("no/such/dir.json");
        assert_eq!(
            write_new(&no_dir, "x").unwrap_err().code(),
            "CLI_FILE_WRITE"
        );
    }

    /// A file over its type's cap is refused without being read whole (a sparse file, so the
    /// test writes nothing of that size).
    #[test]
    fn a_file_over_its_cap_is_refused() {
        let dir = crate::testutil::TempDir::new();
        let path = dir.path().join("big.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_TEXT_FILE + 1).unwrap();
        let e = read_text(&path).unwrap_err();
        assert_eq!(e.code(), "CLI_FILE_READ");
        assert!(e.detail().contains("larger than"), "{e}");
        f.set_len(MAX_TEXT_FILE).unwrap();
        assert_eq!(read_text(&path).unwrap().len() as u64, MAX_TEXT_FILE);
        // A list has its own, larger cap.
        f.set_len(MAX_TEXT_FILE + 1).unwrap();
        assert!(read_text_max(&path, MAX_LIST_FILE).is_ok());
        f.set_len(MAX_LIST_FILE + 1).unwrap();
        let e = read_text_max(&path, MAX_LIST_FILE).unwrap_err();
        assert_eq!(e.code(), "CLI_FILE_READ");
        // Not UTF-8 is still a read error.
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(read_text(&path).unwrap_err().code(), "CLI_FILE_READ");
    }
}
