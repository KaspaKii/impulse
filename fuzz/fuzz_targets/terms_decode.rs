// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms decode (spec/ENCODING.md): arbitrary bytes into `Terms::decode` and
//! `ValidatedTerms::decode`. Oracle: the encoding is one to one, so whatever decodes re-encodes to
//! the same bytes, and the validated form keeps them as its canonical bytes and hash.
#![no_main]

use impulse_core::terms::{CreationContext, Network, Terms, ValidatedTerms};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(terms) = Terms::decode(data) {
        assert_eq!(terms.encode().expect("decoded terms re-encode"), data);
        let hash = terms.terms_hash().expect("decoded terms hash");
        if let Ok(v) = terms.clone().validate_structure() {
            assert_eq!(v.canonical(), data);
            assert_eq!(v.terms_hash(), hash);
            for network in [Network::Mainnet, Network::Testnet] {
                let _ = v.validate_creation(&CreationContext {
                    network,
                    creation_daa: v.terms().expiry_daa.saturating_sub(1),
                    max_expiry_horizon_daa: u64::MAX,
                });
            }
        }
    }
    if let Ok(v) = ValidatedTerms::decode(data) {
        assert_eq!(v.canonical(), data);
    }
});
