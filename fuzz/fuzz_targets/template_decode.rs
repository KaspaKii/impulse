// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template decode (spec/TEMPLATE.md): an arbitrary revealed redeem script into
//! `template::decode`, `template_hash_of_instance` and `decode::revealed_script`. Oracle: a
//! script decodes only if instantiating the decoded terms and leg gives it back byte for byte.
#![no_main]

use impulse_core::decode::revealed_script;
use impulse_core::template::{self, Vault};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let pinned = template::check().expect("the embedded template passes its check");
    if let Ok((terms, leg)) = template::decode(data) {
        let vault = Vault::instantiate_existing(&terms, leg).expect("a decoded vault instantiates");
        assert_eq!(vault.redeem_script(), data);
        assert_eq!(template::template_hash_of_instance(data).ok(), Some(pinned.hash()));
    }
    let _ = template::template_hash_of_instance(data);
    if let Some(script) = revealed_script(data) {
        assert!(script.len() <= data.len());
        let _ = template::decode(script);
    }
});
