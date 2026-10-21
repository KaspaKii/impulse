// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms documents read from text, in Rust so that no SDK logic lives only in TypeScript: the
//! reader of a page that takes pasted or fetched terms is this one.
//!
//! Three shapes are accepted, and nothing else:
//!
//! - the JSON form of terms (spec/ENCODING.md), exactly its keys;
//! - a terms file (spec/CLI.md, "Terms draft and terms file"): exactly `terms`, `canonical` and
//!   `terms_hash`;
//! - a golden vector file (spec/ENCODING.md, "Golden vectors"): exactly `name`, `description`,
//!   `terms`, `canonical` and `terms_hash`.
//!
//! For the last two the encoding of `terms` must equal `canonical` and its hash must equal
//! `terms_hash` (`SDK_TERMS_INCONSISTENT`, the CLI's `CLI_TERMS_FILE_INCONSISTENT`). The text must
//! be JSON that names no key twice at any depth: `JSON.parse` keeps the last of two equal keys
//! silently, so the page hands this reader the text, not a parsed value. The strict reader is
//! `crates/impulse-cli/src/json.rs` `parse_strict`, copied here because impulse-cli does not build
//! for wasm32; `cargo test` compares the two readers on the vectors.

use crate::error::{shown, Failure, SdkError};
use crate::json::{hex_decode, terms_from_json};
use impulse_core::terms::Terms;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// At most this many UTF-16 code units of text. The longest legal vector file holds four
/// 10,000-byte scripts three times over (the terms, the canonical hex), under 400,000 digits.
pub(crate) const MAX_FILE_TEXT: u32 = 1 << 19;

const FILE_KEYS: [&str; 3] = ["terms", "canonical", "terms_hash"];
const VECTOR_KEYS: [&str; 5] = ["name", "description", "terms", "canonical", "terms_hash"];

/// JSON text read into a value, refusing an object that names a key twice.
fn parse_strict(text: &str) -> Result<Value, SdkError> {
    serde_json::from_str::<Strict>(text)
        .map(|s| s.0)
        .map_err(|e| SdkError::json("file", format!("not JSON in the accepted form: {e}")))
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Strict, D::Error> {
        Strict::deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate key {}",
                    shown(&key)
                )));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// A string member that is lowercase hex (`want_len` bytes when given).
fn hex_member(
    map: &Map<String, Value>,
    key: &str,
    want_len: Option<usize>,
) -> Result<Vec<u8>, SdkError> {
    let at = format!("file.{key}");
    let Some(Value::String(s)) = map.get(key) else {
        return Err(SdkError::json(at, "expected a string of lowercase hex"));
    };
    match (hex_decode(s), want_len) {
        (Some(bytes), None) => Ok(bytes),
        (Some(bytes), Some(n)) if bytes.len() == n => Ok(bytes),
        (_, Some(n)) => Err(SdkError::json(
            at,
            format!("expected {} lowercase hex digits", 2 * n),
        )),
        (None, None) => Err(SdkError::json(at, "expected lowercase hex")),
    }
}

/// Reads the text of a terms document (see the module comment). Form only for the bare shape;
/// for the two file shapes also the agreement of `terms`, `canonical` and `terms_hash`. The result
/// may still fail the terms checks, as with `terms_from_json`.
pub(crate) fn terms_from_file_text(text: &str) -> Result<Terms, Failure> {
    let value = parse_strict(text)?;
    let Value::Object(map) = &value else {
        return Err(SdkError::json("file", "expected an object").into());
    };
    if !map.contains_key("terms") {
        // The bare JSON form: its own reader refuses every key it does not know.
        return Ok(terms_from_json(&value)?);
    }
    let expected: &[&str] = if map.contains_key("name") || map.contains_key("description") {
        &VECTOR_KEYS
    } else {
        &FILE_KEYS
    };
    for key in expected {
        if !map.contains_key(*key) {
            return Err(SdkError::json(format!("file.{key}"), "missing").into());
        }
    }
    if let Some(key) = map.keys().find(|k| !expected.contains(&k.as_str())) {
        return Err(SdkError::json(
            format!("file.{}", crate::error::clipped(key)),
            "unknown key",
        )
        .into());
    }
    for key in ["name", "description"] {
        if expected.contains(&key) && !map[key].is_string() {
            return Err(SdkError::json(format!("file.{key}"), "expected a string").into());
        }
    }
    let terms = terms_from_json(&map["terms"])?;
    let canonical = hex_member(map, "canonical", None)?;
    let hash = hex_member(map, "terms_hash", Some(32))?;
    let inconsistent = |reason: &str| SdkError::TermsInconsistent {
        reason: reason.into(),
    };
    if terms.encode()? != canonical {
        return Err(inconsistent("canonical is not the encoding of terms").into());
    }
    if terms.terms_hash()?.as_slice() != hash.as_slice() {
        return Err(inconsistent("terms_hash is not the hash of terms").into());
    }
    Ok(terms)
}

/// Whether `a` and `b` are the same terms: the same canonical bytes. `SDK_TERMS_INCONSISTENT`
/// otherwise, for terms read back from a form that must be the terms they were loaded from.
pub(crate) fn require_same(a: &Terms, b: &Terms) -> Result<(), Failure> {
    if a.encode()? == b.encode()? {
        return Ok(());
    }
    Err(SdkError::TermsInconsistent {
        reason: "these terms are not the terms they were loaded from".into(),
    }
    .into())
}

/// The vector-file text of terms, for tests: the file shape with its three parts.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn file_text(terms: &Terms) -> Result<String, Failure> {
    let terms_json: Value =
        serde_json::from_str(&crate::json::terms_to_json(terms)).expect("rendered terms are JSON");
    Ok(serde_json::json!({
        "terms": terms_json,
        "canonical": crate::json::hex(&terms.encode()?),
        "terms_hash": crate::json::hex(&terms.terms_hash()?),
    })
    .to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::error::Refusal;
    use serde_json::json;
    use std::path::Path;

    fn vector_texts() -> Vec<(String, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
        let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
            .expect("read tests/vectors/terms")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read_to_string(&p).expect("read vector"),
                )
            })
            .collect();
        out.sort();
        assert_eq!(out.len(), 11);
        out
    }

    fn code(r: Result<Terms, Failure>) -> &'static str {
        r.expect_err("a refusal").code()
    }

    #[test]
    fn all_eleven_vector_files_are_read_and_their_hashes_hold() {
        for (name, text) in vector_texts() {
            let doc: Value = serde_json::from_str(&text).unwrap();
            let terms = terms_from_file_text(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                crate::json::hex(&terms.terms_hash().unwrap()),
                doc["terms_hash"].as_str().unwrap(),
                "{name}"
            );
            // The bare JSON form and the three-key file read to the same terms.
            let bare = doc["terms"].to_string();
            assert_eq!(terms_from_file_text(&bare).unwrap(), terms, "{name}: bare");
            assert_eq!(
                terms_from_file_text(&file_text(&terms).unwrap()).unwrap(),
                terms,
                "{name}: file"
            );
        }
    }

    #[test]
    fn the_reader_agrees_with_the_command_lines_on_terms_files() {
        use impulse_cli::terms_file::{parse_terms_file, render_terms_file};
        for (name, text) in vector_texts() {
            let terms = terms_from_file_text(&text).unwrap();
            let validated = terms.clone().validate_structure().unwrap();
            // What the CLI writes, this reads; what this writes, the CLI reads.
            assert_eq!(
                terms_from_file_text(&render_terms_file(&validated)).unwrap(),
                terms,
                "{name}"
            );
            let ours = file_text(&terms).unwrap();
            assert_eq!(
                parse_terms_file(&ours).unwrap().terms(),
                &terms,
                "{name}: the CLI reads our file"
            );
            // The same refusals, under the SDK's codes.
            let doc: Value = serde_json::from_str(&ours).unwrap();
            for (edit, cli, sdk) in [
                (
                    json!({"terms_hash": "11".repeat(32)}),
                    "CLI_TERMS_FILE_INCONSISTENT",
                    "SDK_TERMS_INCONSISTENT",
                ),
                (
                    json!({"canonical": "00"}),
                    "CLI_TERMS_FILE_INCONSISTENT",
                    "SDK_TERMS_INCONSISTENT",
                ),
                (json!({"extra": 1}), "CLI_TERMS_JSON", "SDK_JSON_FORM"),
            ] {
                let mut bad = doc.clone();
                for (k, v) in edit.as_object().unwrap() {
                    bad[k] = v.clone();
                }
                let bad = bad.to_string();
                assert_eq!(
                    parse_terms_file(&bad).map(|_| ()).unwrap_err().code(),
                    cli,
                    "{name}: cli"
                );
                assert_eq!(code(terms_from_file_text(&bad)), sdk, "{name}: sdk");
            }
        }
    }

    #[test]
    fn each_refusal_has_an_accepted_control() {
        let (_, text) = vector_texts().remove(7); // 08, the testnet vector
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["terms"]["network"], "testnet");
        assert!(terms_from_file_text(&text).is_ok(), "control");
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut d = doc.clone();
            f(&mut d);
            d.to_string()
        };
        // A number where a u64 string is required, even one JavaScript could not hold.
        let number_amount = edit(&|d| d["terms"]["cash_leg"]["amount"] = json!(100_000_000));
        assert_eq!(code(terms_from_file_text(&number_amount)), "SDK_JSON_FORM");
        let number_nonce = text.replace("\"7989634765647131680\"", "7989634765647131680");
        assert_ne!(number_nonce, text);
        assert_eq!(code(terms_from_file_text(&number_nonce)), "SDK_JSON_FORM");
        // Unknown keys: top level of a file, top level of terms, inside a leg.
        let top = edit(&|d| d["memo"] = json!("x"));
        assert_eq!(code(terms_from_file_text(&top)), "SDK_JSON_FORM");
        let terms_key = edit(&|d| d["terms"]["memo"] = json!("x"));
        assert_eq!(code(terms_from_file_text(&terms_key)), "SDK_JSON_FORM");
        let stray = edit(&|d| d["terms"]["cash_leg"]["covenant_id"] = json!("00".repeat(32)));
        assert_eq!(code(terms_from_file_text(&stray)), "SDK_JSON_FORM");
        // A part of the file missing.
        let no_hash = edit(&|d| {
            d.as_object_mut().unwrap().remove("terms_hash");
        });
        assert_eq!(code(terms_from_file_text(&no_hash)), "SDK_JSON_FORM");
        let no_description = edit(&|d| {
            d.as_object_mut().unwrap().remove("description");
        });
        assert_eq!(code(terms_from_file_text(&no_description)), "SDK_JSON_FORM");
        let name_number = edit(&|d| d["name"] = json!(1));
        assert_eq!(code(terms_from_file_text(&name_number)), "SDK_JSON_FORM");
        // The three parts disagree.
        let wrong_hash = edit(&|d| d["terms_hash"] = json!("11".repeat(32)));
        assert_eq!(
            code(terms_from_file_text(&wrong_hash)),
            "SDK_TERMS_INCONSISTENT"
        );
        let wrong_canonical = edit(&|d| d["canonical"] = json!("00"));
        assert_eq!(
            code(terms_from_file_text(&wrong_canonical)),
            "SDK_TERMS_INCONSISTENT"
        );
        let mut other_nonce = doc.clone();
        other_nonce["terms"]["nonce"] = json!("7989634765647131681");
        assert_eq!(
            code(terms_from_file_text(&other_nonce.to_string())),
            "SDK_TERMS_INCONSISTENT",
            "terms changed under the file's own canonical and hash"
        );
        // Hex that is not lowercase or the wrong length is a form error.
        let upper =
            edit(&|d| d["terms_hash"] = json!(doc["terms_hash"].as_str().unwrap().to_uppercase()));
        assert_eq!(code(terms_from_file_text(&upper)), "SDK_JSON_FORM");
        let short = edit(&|d| d["terms_hash"] = json!("11"));
        assert_eq!(code(terms_from_file_text(&short)), "SDK_JSON_FORM");
        // Not an object, not JSON, and a key named twice at the top and in a leg.
        assert_eq!(code(terms_from_file_text("[]")), "SDK_JSON_FORM");
        assert_eq!(code(terms_from_file_text("{not json")), "SDK_JSON_FORM");
        assert_eq!(code(terms_from_file_text("")), "SDK_JSON_FORM");
        let twice_top = text.replacen("\"name\"", "\"canonical\": \"00\", \"name\"", 1);
        assert_eq!(code(terms_from_file_text(&twice_top)), "SDK_JSON_FORM");
        let twice_leg = text.replacen(
            "\"kind\": \"kas\"",
            "\"kind\": \"kas\", \"kind\": \"kas\"",
            1,
        );
        assert_ne!(twice_leg, text);
        assert_eq!(code(terms_from_file_text(&twice_leg)), "SDK_JSON_FORM");
    }

    #[test]
    fn terms_are_the_same_only_when_their_canonical_bytes_are() {
        let (_, text) = vector_texts().remove(7);
        let a = terms_from_file_text(&text).unwrap();
        assert!(require_same(&a, &a.clone()).is_ok(), "control");
        let mut b = a.clone();
        b.nonce += 1;
        assert_eq!(
            require_same(&a, &b).unwrap_err().code(),
            "SDK_TERMS_INCONSISTENT"
        );
    }
}
