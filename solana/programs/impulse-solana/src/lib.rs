// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
#![no_std]

pub mod discriminator;
pub mod error;
// pub mod events;
pub mod instructions;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

use pinocchio::address::declare_id;
// Placeholder program ID: base58 of SHA-256("impulse-solana/program-id/placeholder/v0.2").
// Nobody holds a keypair for it. The key holder sets the deployed program ID here before a
// devnet or mainnet deploy (see README, "Deploying"); only the key holder deploys (rule 6, docs/ENGINEERING-RULES.md).
declare_id!("BE6CXjt5yfu2NWLon5kBVE4prTqMN9udAV9yKqAdrmTj");

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Impulse escrow on Solana (impulse-solana, fork of solana-foundation/dvp)",
    project_url: "https://github.com/kaspakii/impulse",
    contacts: "link:https://github.com/kaspakii/impulse/blob/main/SECURITY.md",
    policy: "https://github.com/kaspakii/impulse/blob/main/SECURITY.md",
    source_code: "https://github.com/kaspakii/impulse"
}
