// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The files the binary reads: terms files, signed-transaction files and (through `persist`) the
//! state file. Strict readers: exact key sets, lowercase hex, u64 as decimal strings with no
//! leading zero, no key given twice. Text read from a file is echoed in messages only escaped,
//! so a file cannot write control sequences or extra lines to the operator's terminal.
//!
//! Adapted from the `impulse` CLI's strict JSON reader (I7, `crates/impulse-cli/src/json.rs`;
//! copied rather than depended on, since the CLI links the signing module and the watcher must
//! not).

use crate::error::WatchError;
use crate::trades::TradeTerms;
use borsh::BorshDeserialize;
use impulse_core::linked::ValidatedLinked;
use impulse_core::terms::ValidatedTerms;
use impulse_core::v2::{ValidatedTermsV2, TERMS_V2_VERSION};
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::Transaction;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
use std::path::Path;

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex only, even length.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Exactly 32 bytes of lowercase hex.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// A u64 as the watcher writes it: decimal digits, no sign, no leading zero (except "0").
pub fn parse_dec(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Parses JSON text, refusing an object that names a key twice. `serde_json::Value` would keep
/// the last of two equal keys silently.
pub fn parse_strict(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|s| s.0)
        .map_err(|e| format!("not JSON in the accepted form: {e}"))
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
                return Err(de::Error::custom(format_args!("duplicate key {key:?}")));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// A strict reader over one JSON object. Errors are `path: reason` strings; the caller attaches
/// its code.
pub struct Obj<'a> {
    path: String,
    map: &'a Map<String, Value>,
}

impl<'a> Obj<'a> {
    pub fn new(path: &str, value: &'a Value) -> Result<Self, String> {
        match value {
            Value::Object(map) => Ok(Self {
                path: path.to_string(),
                map,
            }),
            _ => Err(format!("{path}: expected an object")),
        }
    }

    /// The object must have exactly these keys.
    pub fn keys(&self, keys: &[&str]) -> Result<(), String> {
        for key in keys {
            if !self.map.contains_key(*key) {
                return Err(format!("{}: missing key {key}", self.path));
            }
        }
        for key in self.map.keys() {
            if !keys.contains(&key.as_str()) {
                return Err(format!("{}: unexpected key {key:?}", self.path));
            }
        }
        Ok(())
    }

    fn sub(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", self.path)
        }
    }

    pub fn get(&self, key: &str) -> Result<&'a Value, String> {
        self.map
            .get(key)
            .ok_or_else(|| format!("{}: missing key {key}", self.path))
    }

    pub fn is_null(&self, key: &str) -> Result<bool, String> {
        Ok(self.get(key)?.is_null())
    }

    pub fn str(&self, key: &str) -> Result<&'a str, String> {
        self.get(key)?
            .as_str()
            .ok_or_else(|| format!("{}: expected a string", self.sub(key)))
    }

    pub fn hex32(&self, key: &str) -> Result<[u8; 32], String> {
        unhex32(self.str(key)?)
            .ok_or_else(|| format!("{}: expected 64 lowercase hex digits", self.sub(key)))
    }

    pub fn hex(&self, key: &str) -> Result<Vec<u8>, String> {
        unhex(self.str(key)?).ok_or_else(|| format!("{}: expected lowercase hex", self.sub(key)))
    }

    pub fn dec(&self, key: &str) -> Result<u64, String> {
        parse_dec(self.str(key)?).ok_or_else(|| {
            format!(
                "{}: expected a u64 as a decimal string with no leading zero",
                self.sub(key)
            )
        })
    }

    pub fn u32(&self, key: &str) -> Result<u32, String> {
        self.get(key)?
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("{}: expected a u32", self.sub(key)))
    }

    pub fn bool(&self, key: &str) -> Result<bool, String> {
        self.get(key)?
            .as_bool()
            .ok_or_else(|| format!("{}: expected true or false", self.sub(key)))
    }

    pub fn array(&self, key: &str) -> Result<&'a Vec<Value>, String> {
        self.get(key)?
            .as_array()
            .ok_or_else(|| format!("{}: expected an array", self.sub(key)))
    }

    pub fn obj(&self, key: &str) -> Result<Obj<'a>, String> {
        Obj::new(&self.sub(key), self.get(key)?)
    }

    /// `null` or a u64 decimal string.
    pub fn opt_dec(&self, key: &str) -> Result<Option<u64>, String> {
        if self.is_null(key)? {
            Ok(None)
        } else {
            self.dec(key).map(Some)
        }
    }
}

/// Reads a whole file as UTF-8 text.
pub fn read_text(path: &Path) -> Result<String, WatchError> {
    std::fs::read_to_string(path).map_err(|e| WatchError::FileRead {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// A terms file: a JSON object with exactly the keys `terms`, `canonical` and `terms_hash`, as
/// `impulse terms new` writes it. The watcher watches what `canonical` says. It decodes the
/// canonical bytes with impulse-core, runs the structure checks, and refuses the file unless
/// `terms_hash` is the hash of those bytes (`WATCH_TERMS_FILE_INCONSISTENT`). It does not read
/// the JSON view under `terms`, which the `impulse` CLI checks against `canonical`; only that the
/// key is there. Anything that is not a terms file is `WATCH_TERMS_FILE_INVALID`. A terms file v2
/// (canonical bytes that start with version 2, spec/V2.md 6.5) is decoded as terms v2.
pub fn parse_terms_file(label: &str, text: &str) -> Result<TradeTerms, WatchError> {
    let invalid = |reason: String| WatchError::TermsFileInvalid {
        path: label.to_string(),
        reason,
    };
    let value = parse_strict(text).map_err(&invalid)?;
    let obj = Obj::new("", &value).map_err(&invalid)?;
    obj.keys(&["terms", "canonical", "terms_hash"])
        .map_err(&invalid)?;
    let canonical = obj.hex("canonical").map_err(&invalid)?;
    let hash = obj.hex32("terms_hash").map_err(&invalid)?;
    let terms = if canonical.first() == Some(&TERMS_V2_VERSION) {
        TradeTerms::V2(ValidatedTermsV2::decode(&canonical).map_err(|e| invalid(e.to_string()))?)
    } else {
        TradeTerms::V1(Box::new(
            ValidatedTerms::decode(&canonical).map_err(|e| invalid(e.to_string()))?,
        ))
    };
    if terms.terms_hash() != hash {
        return Err(WatchError::TermsFileInconsistent {
            path: label.to_string(),
        });
    }
    Ok(terms)
}

pub fn read_terms_file(path: &Path) -> Result<TradeTerms, WatchError> {
    parse_terms_file(&path.display().to_string(), &read_text(path)?)
}

/// A signed transaction in the raw form of spec/VERIFY.md (rusty-kaspa a41a333's borsh
/// encoding, which carries the transaction ID last), as lowercase hex with at most one final
/// line feed. Refused (`WATCH_SIGNED_TX_INVALID`) unless it is exactly one transaction whose
/// carried ID is the ID of its contents.
pub fn parse_signed_tx(label: &str, text: &str) -> Result<Transaction, WatchError> {
    let invalid = |reason: &str| WatchError::SignedTxInvalid {
        path: label.to_string(),
        reason: reason.to_string(),
    };
    let body = text.strip_suffix('\n').unwrap_or(text);
    let bytes = unhex(body).ok_or_else(|| invalid("not lowercase hex"))?;
    let tx = Transaction::try_from_slice(&bytes)
        .map_err(|_| invalid("not exactly one borsh-encoded transaction"))?;
    if tx.id() != hashing::tx::id(&tx) {
        return Err(invalid(
            "the carried transaction ID is not the ID of the contents",
        ));
    }
    Ok(tx)
}

pub fn read_signed_tx(path: &Path) -> Result<Transaction, WatchError> {
    parse_signed_tx(&path.display().to_string(), &read_text(path)?)
}

/// A sheet file of `impulse linked new`: a JSON object with exactly the keys `sheet`, `canonical`
/// and `linked_hash`. As a terms file, the watcher watches what `canonical` says: it decodes the
/// canonical bytes with impulse-core, runs the sheet checks, and refuses the file unless
/// `linked_hash` is the hash of those bytes (`WATCH_TERMS_FILE_INCONSISTENT`). It does not read
/// the JSON view under `sheet`, which the `impulse` CLI checks against `canonical`; only that the
/// key is there. Anything else is `WATCH_TERMS_FILE_INVALID`.
pub fn parse_sheet_file(label: &str, text: &str) -> Result<ValidatedLinked, WatchError> {
    let invalid = |reason: String| WatchError::TermsFileInvalid {
        path: label.to_string(),
        reason,
    };
    let value = parse_strict(text).map_err(&invalid)?;
    let obj = Obj::new("", &value).map_err(&invalid)?;
    obj.keys(&["sheet", "canonical", "linked_hash"])
        .map_err(&invalid)?;
    let canonical = obj.hex("canonical").map_err(&invalid)?;
    let hash = obj.hex32("linked_hash").map_err(&invalid)?;
    let linked = ValidatedLinked::decode(&canonical).map_err(|e| invalid(e.to_string()))?;
    if linked.linked_hash() != hash {
        return Err(WatchError::TermsFileInconsistent {
            path: label.to_string(),
        });
    }
    Ok(linked)
}

pub fn read_sheet_file(path: &Path) -> Result<ValidatedLinked, WatchError> {
    parse_sheet_file(&path.display().to_string(), &read_text(path)?)
}
