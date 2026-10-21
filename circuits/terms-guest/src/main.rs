// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The terms guest of spec/V3-ZK.md section 22.4. Reads the encoded witness (canonical terms, the
//! journal the vault script builds, the redeem scripts of the escrowed tokens), runs the statement
//! of `terms-core`, and commits exactly J. Any refusal is a panic, so no receipt exists.
#![no_main]

use risc0_zkvm::guest::env;
use terms_core::{statement, StatementOptions, Witness};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read();
    let witness = match Witness::from_bytes(&input) {
        Ok(w) => w,
        Err(r) => panic!("impulse terms guest refused: {r}"),
    };
    match statement(&witness, StatementOptions { curve_checks: true }) {
        Ok(j) => env::commit_slice(&j),
        Err(r) => panic!("impulse terms guest refused: {r}"),
    }
}
