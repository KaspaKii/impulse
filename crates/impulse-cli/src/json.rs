// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The small JSON subset the CLI writes (fixed key order, two-space indent, as the golden vectors
//! are written) and strict readers for the JSON it accepts: exact key sets, lowercase hex, u64 as
//! decimal strings with no leading zero, no key given twice. Each reader reports the failing
//! path. Text read from a file is echoed in messages only in escaped (Debug) form, so a file
//! cannot inject terminal control sequences or extra lines into the output.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// A JSON value in the subset the CLI writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Str(String),
    Num(u64),
    Null,
    Obj(Vec<(&'static str, Json)>),
    Arr(Vec<Json>),
}

impl Json {
    /// Pretty text with a final newline.
    pub fn render(&self) -> String {
        let mut out = String::new();
        write(self, 0, &mut out);
        out.push('\n');
        out
    }
}

fn write(j: &Json, indent: usize, out: &mut String) {
    match j {
        Json::Str(s) => out.push_str(&Value::String(s.clone()).to_string()),
        Json::Num(n) => out.push_str(&n.to_string()),
        Json::Null => out.push_str("null"),
        Json::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                write(item, indent + 2, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        Json::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push('"');
                out.push_str(key);
                out.push_str("\": ");
                write(value, indent + 2, out);
                if i + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

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

/// A u64 as the CLI writes it: decimal digits, no sign, no leading zero (except "0").
pub fn parse_dec(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Parses JSON text, refusing an object that names a key twice. `serde_json::Value` would keep
/// the last of two equal keys silently, and a reader that keeps the first would then see other
/// fields than the CLI checked.
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

    /// The object must have exactly these keys (`optional` keys may be absent).
    pub fn keys(&self, required: &[&str], optional: &[&str]) -> Result<(), String> {
        for key in required {
            if !self.map.contains_key(*key) {
                return Err(format!("{}: missing key {key}", self.path));
            }
        }
        for key in self.map.keys() {
            if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
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
            .ok_or_else(|| format!("{}: missing", self.sub(key)))
    }

    /// Absent and `null` both read as None.
    pub fn opt(&self, key: &str) -> Option<&'a Value> {
        self.map.get(key).filter(|v| !v.is_null())
    }

    pub fn is_null(&self, key: &str) -> Result<bool, String> {
        Ok(self.get(key)?.is_null())
    }

    pub fn obj(&self, key: &str) -> Result<Obj<'a>, String> {
        Obj::new(&self.sub(key), self.get(key)?)
    }

    pub fn str(&self, key: &str) -> Result<&'a str, String> {
        self.get(key)?
            .as_str()
            .ok_or_else(|| format!("{}: expected a string", self.sub(key)))
    }

    /// A JSON number that fits `max`.
    pub fn num(&self, key: &str, max: u64) -> Result<u64, String> {
        self.get(key)?
            .as_u64()
            .filter(|n| *n <= max)
            .ok_or_else(|| format!("{}: expected an integer from 0 to {max}", self.sub(key)))
    }

    /// A u64 as a decimal string.
    pub fn dec(&self, key: &str) -> Result<u64, String> {
        parse_dec(self.str(key)?).ok_or_else(|| {
            format!(
                "{}: expected a decimal u64 string without leading zeros",
                self.sub(key)
            )
        })
    }

    pub fn hex(&self, key: &str) -> Result<Vec<u8>, String> {
        unhex(self.str(key)?).ok_or_else(|| format!("{}: expected lowercase hex", self.sub(key)))
    }

    pub fn hex32(&self, key: &str) -> Result<[u8; 32], String> {
        unhex32(self.str(key)?)
            .ok_or_else(|| format!("{}: expected 64 lowercase hex digits", self.sub(key)))
    }

    /// One of `choices`, returned as its index.
    pub fn choice(&self, key: &str, choices: &[&str]) -> Result<usize, String> {
        let s = self.str(key)?;
        choices
            .iter()
            .position(|c| *c == s)
            .ok_or_else(|| format!("{}: expected one of {choices:?}", self.sub(key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_even() {
        assert_eq!(unhex("00ff"), Some(vec![0, 255]));
        assert_eq!(unhex("00FF"), None);
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(unhex32(&"ab".repeat(31)), None);
    }

    #[test]
    fn decimals_are_canonical() {
        assert_eq!(parse_dec("0"), Some(0));
        assert_eq!(parse_dec("18446744073709551615"), Some(u64::MAX));
        for bad in ["", "01", "+1", "-1", "1.0", "18446744073709551616", " 1"] {
            assert_eq!(parse_dec(bad), None, "{bad}");
        }
    }

    #[test]
    fn objects_have_exact_keys() {
        let v: Value = serde_json::from_str(r#"{"a": 1, "b": null}"#).unwrap();
        let o = Obj::new("", &v).unwrap();
        assert!(o.keys(&["a", "b"], &[]).is_ok());
        assert!(o
            .keys(&["a"], &[])
            .unwrap_err()
            .contains("unexpected key \"b\""));
        assert!(o.keys(&["a"], &["b"]).is_ok());
        assert!(o
            .keys(&["a", "b", "c"], &[])
            .unwrap_err()
            .contains("missing key c"));
        assert!(o.opt("b").is_none());
    }

    #[test]
    fn an_unexpected_key_is_echoed_escaped() {
        // A key carrying an escape sequence and a line break must not reach the terminal raw.
        let text = r#"{"a": 1, "x\u001b[2J\nok: forged": 2}"#;
        let v = parse_strict(text).unwrap();
        let e = Obj::new("", &v).unwrap().keys(&["a"], &[]).unwrap_err();
        assert!(!e.contains('\u{1b}'), "{e:?}");
        assert!(!e.contains('\n'), "{e:?}");
        assert!(e.contains(r#"x\u{1b}[2J\nok: forged"#), "{e:?}");
        assert!(o_keys_ok(r#"{"a": 1}"#), "control");
    }

    fn o_keys_ok(text: &str) -> bool {
        let v = parse_strict(text).unwrap();
        Obj::new("", &v).unwrap().keys(&["a"], &[]).is_ok()
    }

    #[test]
    fn a_key_given_twice_is_refused() {
        assert_eq!(
            parse_strict(r#"{"a": {"b": 1, "c": [true, null, "x", -1, 1.5]}}"#).unwrap(),
            serde_json::json!({"a": {"b": 1, "c": [true, null, "x", -1, 1.5]}}),
            "control: the strict parse is the ordinary parse"
        );
        for text in [
            r#"{"a": 1, "a": 2}"#,
            r#"{"a": {"b": 1, "b": 1}}"#,
            r#"[{"a": 1, "a": 1}]"#,
            r#"{"a": 1, "\u0061": 2}"#,
        ] {
            let e = parse_strict(text).unwrap_err();
            assert!(e.contains("duplicate key"), "{text}: {e}");
        }
        assert!(
            serde_json::from_str::<Value>(r#"{"a": 1, "a": 2}"#).is_ok(),
            "the lax parse"
        );
    }

    #[test]
    fn render_matches_the_vector_style() {
        let j = Json::Obj(vec![
            ("a", Json::Num(1)),
            ("b", Json::Obj(vec![("c", Json::Str("x".into()))])),
            ("d", Json::Null),
        ]);
        assert_eq!(
            j.render(),
            "{\n  \"a\": 1,\n  \"b\": {\n    \"c\": \"x\"\n  },\n  \"d\": null\n}\n"
        );
    }
}
