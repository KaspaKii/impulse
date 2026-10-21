// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The list guest of spec/V3-ZK.md section 5.4. Reads the encoded input (index, salt, the 20
//! siblings, root, vault scriptPubKey, owner scriptPubKey), checks that the owner's salted leaf lies
//! under the root, and commits exactly J (section 5.2). Any refusal is a panic, so no receipt exists.
#![no_main]

use list_core::{statement, Sha256};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256 as _};

risc0_zkvm::guest::entry!(main);

struct ZkvmSha;

impl Sha256 for ZkvmSha {
    fn hash(data: &[u8]) -> [u8; 32] {
        let d = Impl::hash_bytes(data);
        let mut o = [0u8; 32];
        o.copy_from_slice(d.as_bytes());
        o
    }
}

fn main() {
    let input: Vec<u8> = env::read();
    match statement::<ZkvmSha>(&input) {
        Ok(j) => env::commit_slice(j.as_bytes()),
        Err(r) => panic!("impulse list guest refused: {r:?}"),
    }
}
