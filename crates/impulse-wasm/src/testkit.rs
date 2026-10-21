// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Shared helpers of the native tests that read the committed golden vectors. Test code only.

use crate::json::terms_from_json;
use impulse_core::terms::Terms;
use serde_json::Value;
use std::path::Path;

/// (file name, parsed vector document) of every committed terms vector, sorted by name.
pub(crate) fn vectors() -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
    let mut out: Vec<(String, Value)> = std::fs::read_dir(&dir)
        .expect("read tests/vectors/terms")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("read vector");
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                serde_json::from_str(&text).expect("vector parses"),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(out.len(), 11, "the eleven terms vectors");
    out
}

/// The vector document whose file name starts with `prefix` (for example `"08-"`).
pub(crate) fn vector(prefix: &str) -> Value {
    let all = vectors();
    let found: Vec<_> = all.iter().filter(|(n, _)| n.starts_with(prefix)).collect();
    assert_eq!(found.len(), 1, "one vector {prefix}");
    found[0].1.clone()
}

pub(crate) fn terms(doc: &Value) -> Terms {
    terms_from_json(&doc["terms"]).expect("the vector's terms form")
}
