// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
//! Smart-wallet program used only by the swap program's integration
//! tests. Replicates how smart wallets like Squads v4 act on-chain: it
//! relays an arbitrary inner instruction via CPI, signing with a vault
//! PDA through `invoke_signed`.
//!
//! A real smart wallet does two things: it runs governance (collecting
//! member votes, checking the threshold), then executes the approved
//! instruction as the vault. Only the second step reaches the callee, as
//! a CPI carrying the vault PDA as a signer. The callee cannot tell that
//! CPI apart from a real smart wallet's, so this fixture implements only
//! that step and skips governance entirely.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use pinocchio::{
    account::AccountView,
    address::Address,
    cpi::{invoke_signed_with_slice, Seed, Signer},
    default_allocator,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    nostd_panic_handler, program_entrypoint, ProgramResult,
};

solana_address::declare_id!("H5tY4bRL6jk62vkxeytUVVjYDjBWgV6FQMvgnmaJNuNz");

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

/// Vault PDA seeds: [b"vault", [index]]. The index lets one test run
/// several independent vaults.
const VAULT_SEED: &[u8] = b"vault";

/// # Account Layout
/// Account 0 is the inner program. The rest are the inner instruction's
/// own accounts, in order; pass the vault as a plain (non-signer) account
/// and it receives its signer bit here.
///
/// # Instruction Data
/// `vault_index` (u8) selects the signing vault PDA; the remaining bytes
/// are the inner instruction data, forwarded verbatim.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (program_info, inner_accounts) = accounts
        .split_first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (vault_index, inner_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let index_bytes = [*vault_index];
    let (vault, bump) = Address::find_program_address(&[VAULT_SEED, &index_bytes], program_id);

    // Forward each account with its outer flags. The vault alone gains a
    // signer bit, which invoke_signed backs with the seeds below.
    let metas: Vec<InstructionAccount> = inner_accounts
        .iter()
        .map(|acc| {
            InstructionAccount::new(
                acc.address(),
                acc.is_writable(),
                acc.is_signer() || acc.address() == &vault,
            )
        })
        .collect();
    let infos: Vec<&AccountView> = inner_accounts.iter().collect();

    let instruction = InstructionView {
        program_id: program_info.address(),
        accounts: &metas,
        data: inner_data,
    };

    let bump_bytes = [bump];
    let vault_seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(index_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    invoke_signed_with_slice(&instruction, &infos, &[Signer::from(&vault_seeds)])
}
