// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
use pinocchio::{account::AccountView, entrypoint, error::ProgramError, Address, ProgramResult};

use crate::{processor, IX_CLAIM, IX_OPEN, IX_REFUND};

entrypoint!(process_instruction);
// no_std on chain: the program sets its own panic handler (none of its dependencies brings std).
#[cfg(target_os = "solana")]
pinocchio::nostd_panic_handler!();

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *tag {
        IX_OPEN => processor::open(program_id, accounts, data),
        IX_CLAIM => processor::claim(program_id, accounts, data),
        IX_REFUND => processor::refund(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
