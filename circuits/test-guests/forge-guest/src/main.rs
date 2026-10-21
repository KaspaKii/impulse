// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! TEST ONLY: commits the bytes it is given as the journal, checking nothing (section 13.2).
#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let j: Vec<u8> = env::read();
    env::commit_slice(&j);
}
