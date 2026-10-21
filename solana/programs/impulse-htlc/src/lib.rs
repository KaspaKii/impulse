// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Impulse HTLC: a minimal sha256 hash time-locked token escrow for SPL Token and Token-2022.
//!
//! Example program for the Solana half of I18, written to the counterpart requirements of
//! `spec/V2.md` section 10.5: sha256 over a preimage of exactly 32 bytes, a claim
//! that pays a recipient fixed at open and is refused at or after the timeout, a refund that pays
//! a refund owner fixed at open and opens only at or after the timeout, and the preimage carried in
//! the claim instruction data. Owner decision D33; mainnet use follows D39 (capped values).
#![no_std]

pub mod error;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

use pinocchio::address::declare_id;

// Placeholder ID: base58 of sha256("Impulse HTLC example program, placeholder id, devnet only").
// It has no known private key. A deploy by the key holder replaces it with that deploy's program ID.
declare_id!("3yJqvpGhqzN2mKtUGZ9MkLRFtcWPVJ5vD7QVtFkkucq3");

/// Instruction discriminators (first byte of instruction data).
pub const IX_OPEN: u8 = 0;
pub const IX_CLAIM: u8 = 1;
pub const IX_REFUND: u8 = 2;

/// PDA seed of the HTLC state account: `["htlc", funder, hash_lock]`.
pub const HTLC_SEED: &[u8] = b"htlc";
/// PDA seed of the escrow token account: `["escrow", htlc]`.
pub const ESCROW_SEED: &[u8] = b"escrow";

/// The preimage is exactly 32 bytes (spec/V2.md 10.5, R6).
pub const PREIMAGE_LEN: usize = 32;
/// Longest allowed lifetime from open to timeout, in seconds (30 days). Bounds rent and token
/// lock-up; the cross-chain margin itself is checked off chain (spec/V2.md 10.5, margin rule).
pub const MAX_HTLC_DURATION_SECS: i64 = 30 * 24 * 60 * 60;
