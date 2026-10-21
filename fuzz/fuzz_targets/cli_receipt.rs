// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Settlement receipts (spec/CLI.md, "Settlement receipt"), as `impulse verify-receipt` reads
//! them from anyone: arbitrary text into `Receipt::parse`, then the signature and field checks.
//! Oracle: a receipt that parses renders to text that parses to the same receipt.
#![no_main]

use impulse_cli::receipt::Receipt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(receipt) = Receipt::parse(text) else {
        return;
    };
    let again = Receipt::parse(&receipt.render()).expect("a rendered receipt parses");
    assert_eq!(again, receipt);
    let _ = receipt.verify_signature();
    let _ = receipt.check_signer(&receipt.signer);
    let _ = receipt.check_terms_hash(&receipt.observation.terms_hash);
    let _ = receipt.check_txid(&receipt.observation.txid);
    let _ = receipt.observation.render();
});
