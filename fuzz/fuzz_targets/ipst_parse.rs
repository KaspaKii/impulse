// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! IPST parse (spec/IPST.md, "Reading an IPST"): arbitrary text into `Ipst::from_json`. Oracle:
//! a document that reads renders canonically, the rendering reads back to the same document, and
//! it combines with itself into itself. Every view and check a command runs on a read IPST runs
//! here too, against the KCC-20 test templates of impulse-core.
#![no_main]

use impulse_core::tx::{Ipst, Kcc20Template};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn templates() -> &'static (Kcc20Template, Kcc20Template) {
    static T: OnceLock<(Kcc20Template, Kcc20Template)> = OnceLock::new();
    T.get_or_init(|| {
        let read = |s: &str| Kcc20Template::from_json(s).expect("impulse-core test template");
        (
            read(include_str!("../../crates/impulse-core/src/tx/testdata/kcc20-asset.json")),
            read(include_str!("../../crates/impulse-core/src/tx/testdata/kcc20-cash.json")),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(ipst) = Ipst::from_json(text) else {
        return;
    };
    let rendered = ipst.to_json();
    let again = Ipst::from_json(&rendered).expect("a canonical rendering reads back");
    assert_eq!(again, ipst);
    assert_eq!(again.to_json(), rendered);
    assert_eq!(ipst.combine(&ipst).expect("an IPST combines with itself"), ipst);
    let _ = (ipst.masses(), ipst.fee(), ipst.pending(), ipst.is_complete());
    for slot in ipst.slots() {
        let _ = (slot.signer(), slot.sighash(), slot.signature());
        let _ = (slot.script_before().len(), slot.script_after().len());
    }
    if ipst.is_complete() {
        let _ = ipst.finalize();
    }
    let (asset, cash) = templates();
    let daa = ipst.terms().terms().expiry_daa.saturating_sub(1);
    let _ = ipst.verify_against_terms(asset, Some(cash), daa);
    let _ = ipst.verify_against_terms(asset, None, 0);
});
