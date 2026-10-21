// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! FROST secret encodings (spec/THRESHOLD.md, "Encodings"): a received DKG round-2 package and a
//! party's own key-share file. The first byte picks the decoder. Any input this target accepts is
//! by construction a share encoding, so its corpus is never committed (rule 1, docs/ENGINEERING-RULES.md):
//! scripts/fuzz.sh keeps it in a temporary directory removed when the run ends, and this target
//! has no committed seeds.
#![no_main]

use impulse_core::threshold::{DkgRound2Package, KeyShare};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    if which % 2 == 0 {
        if let Ok(p) = DkgRound2Package::from_bytes(body) {
            assert_eq!(&p.to_bytes()[..], body);
        }
    } else if let Ok(k) = KeyShare::from_bytes(body) {
        assert_eq!(&k.to_bytes().expect("re-encodes")[..], body);
        let _ = (k.id(), k.shape(), k.authority_key());
    }
});
