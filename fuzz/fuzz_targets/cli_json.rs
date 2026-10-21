// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The CLI's strict JSON reader (crates/impulse-cli/src/json.rs), under every file the CLI reads:
//! `parse_strict`, then every typed accessor on every key of the top object, and the hex and
//! decimal readers on every string in it. Oracles: `parse_strict` accepts only what serde_json
//! accepts; hex and decimal readers round-trip through the writers.
#![no_main]

use impulse_cli::json::{hex, parse_dec, parse_strict, unhex, unhex32, Obj};
use libfuzzer_sys::fuzz_target;

fn strings(text: &str) {
    if let Some(bytes) = unhex(text) {
        assert_eq!(hex(&bytes), text);
        assert_eq!(unhex32(text).is_some(), bytes.len() == 32);
    }
    if let Some(n) = parse_dec(text) {
        assert_eq!(n.to_string(), text);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    strings(text);
    let Ok(value) = parse_strict(text) else {
        return;
    };
    assert!(serde_json::from_str::<serde_json::Value>(text).is_ok());
    let Ok(obj) = Obj::new("fuzz", &value) else {
        return;
    };
    let keys: Vec<&str> = value
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let _ = obj.keys(&keys, &[]);
    let _ = obj.keys(&[], &keys);
    for key in &keys {
        let _ = obj.get(key);
        let _ = obj.opt(key);
        let _ = obj.is_null(key);
        let _ = obj.obj(key);
        let _ = obj.num(key, u64::MAX);
        let _ = obj.num(key, 255);
        let _ = obj.dec(key);
        let _ = obj.hex(key);
        let _ = obj.hex32(key);
        let _ = obj.choice(key, &["mainnet", "testnet"]);
        if let Ok(s) = obj.str(key) {
            strings(s);
        }
    }
});
