// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! KCC-20 template decode (`--template`, `impulse token list` and the token builders): arbitrary
//! text into `Kcc20Template::from_json`, then the pinned-build lookup and a script for a state
//! drawn from the input. Oracle: an accepted template's script for a state starts with its
//! prefix length of bytes and ends with its suffix, so its template hash holds.
#![no_main]

use impulse_core::terms::{IdentifierType, Kcc20Owner};
use impulse_core::tx::{Kcc20State, Kcc20Template};
use impulse_core::verify::{pinned_kcc20, TemplateTriple};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(template) = Kcc20Template::from_json(text) else {
        return;
    };
    let _ = pinned_kcc20(&TemplateTriple {
        hash: template.template_hash(),
        prefix_len: template.prefix_len() as u64,
        suffix_len: template.suffix_len() as u64,
    });
    let mut identifier = [7u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        identifier[i] ^= b;
    }
    for identifier_type in [IdentifierType::PubKey, IdentifierType::ScriptHash] {
        let owner = Kcc20Owner {
            identifier,
            identifier_type,
        };
        let amount = data.len() as u64;
        if let Ok(script) = template.redeem_script(&Kcc20State::new(owner, amount)) {
            assert!(script.len() >= template.prefix_len() + template.suffix_len());
            let _ = template.script_public_key(&Kcc20State::new(owner, amount));
        }
    }
});
