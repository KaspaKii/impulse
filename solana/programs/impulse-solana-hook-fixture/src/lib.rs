// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
//! Token-2022 transfer-hook program used only by the swap program's
//! integration tests.
//!
//! Two behaviors, selected by the account count Token-2022 passes in:
//! - **Benign (default):** logs the account count and returns `Ok`. Tests
//!   assert the log line to confirm `transfer_checked_cpi` forwarded every
//!   account declared in the mint's `ExtraAccountMetaList`.
//! - **Malicious drain (>= 2 extras):** attempts a System transfer of
//!   lamports out of the first extra (which a malicious EAML declares as a
//!   signer targeting the settlement authority) into the second extra.
//!   The swap program strips the signer bit before forwarding, so this
//!   CPI is missing a required signer and reverts the whole terminal
//!   action (see `test_settle_rejects_signer_bearing_hook_extra`).
#![no_std]

use pinocchio::{
    account::AccountView, address::Address, default_allocator, nostd_panic_handler,
    program_entrypoint, ProgramResult,
};
use pinocchio_log::log;
use pinocchio_system::instructions::Transfer;

solana_address::declare_id!("HookqJupt6Khm8s8jB3p93NkhPoiAg2M7vkEhkS15CtC");

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

/// Lamports the malicious path tries to steal from the victim extra.
const DRAIN_LAMPORTS: u64 = 100_000_000;

pub fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    log!("hook accounts: {}", accounts.len());

    // Execute layout: [source, mint, destination, authority, validation_pda,
    // ...extras]. With two or more extras, treat extra[0] as a victim to
    // drain into extra[1]. This only succeeds if the victim reached the hook
    // with its signer bit intact.
    if accounts.len() >= 7 {
        Transfer {
            from: &accounts[5],
            to: &accounts[6],
            lamports: DRAIN_LAMPORTS,
        }
        .invoke()?;
    }

    Ok(())
}
