// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! FROST public encodings (spec/THRESHOLD.md, "Encodings"), as `impulse frost` reads them from
//! other parties' files: DKG round-1 packages, group keys, nonce commitments and signature
//! shares. The first byte picks the decoder, the rest is its input. Oracle: whatever decodes
//! re-encodes to the same bytes (signature shares have no encoder of their input form beyond
//! their 32 bytes).
#![no_main]

use impulse_core::threshold::{Commitment, DkgRound1Package, GroupKey, SignatureShare};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    match which % 4 {
        0 => {
            if let Ok(p) = DkgRound1Package::from_bytes(body) {
                assert_eq!(p.to_bytes().expect("re-encodes"), body);
            }
        }
        1 => {
            if let Ok(g) = GroupKey::from_bytes(body) {
                assert_eq!(g.to_bytes().expect("re-encodes"), body);
                let _ = (g.shape(), g.authority_key(), g.fingerprint());
            }
        }
        2 => {
            if let Ok(c) = Commitment::from_bytes(body) {
                assert_eq!(&c.to_bytes().expect("re-encodes")[..], body);
            }
        }
        _ => {
            if let Ok(s) = SignatureShare::from_bytes(body) {
                assert_eq!(&s.to_bytes()[..], body);
            }
        }
    }
});
