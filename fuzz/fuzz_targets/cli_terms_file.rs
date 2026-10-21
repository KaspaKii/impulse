// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms files and drafts (spec/CLI.md, "Terms file"): arbitrary text into `parse_terms_file` and
//! `parse_draft`. Oracles: a terms file that reads is the file the CLI writes for those terms,
//! read again to the same terms; a draft with its nonce set reads to terms whose canonical
//! encoding decodes back to them. The summary every command prints runs on whatever reads.
#![no_main]

use impulse_cli::summary::summary;
use impulse_cli::terms_file::{parse_draft, parse_terms_file, render_terms_file};
use impulse_core::terms::Terms;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(v) = parse_terms_file(text) {
        let rendered = render_terms_file(&v);
        let again = parse_terms_file(&rendered).expect("the rendering of read terms reads");
        assert_eq!(again, v);
        let t = v.terms();
        for now in [0, t.expiry_daa, u64::MAX] {
            let _ = summary(&v.terms_hash(), t, now);
        }
    }
    if let Ok(t) = parse_draft(text) {
        let _ = summary(&[0; 32], &t, t.expiry_daa);
        if let Ok(bytes) = t.encode() {
            assert_eq!(Terms::decode(&bytes).expect("encoded terms decode"), t);
        }
    }
});
