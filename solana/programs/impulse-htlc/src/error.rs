// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
use pinocchio::error::ProgramError;

/// Custom error codes (`ProgramError::Custom(n)`). The numbers are stable and listed in
/// `docs/xchain/SOLANA-HTLC.md`; a new code is appended, never renumbered, and a retired code is
/// never reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HtlcError {
    AmountZero = 0,
    HashZero = 1,
    PartyZero = 2,
    PartiesNotDistinct = 3,
    TimeoutNotInFuture = 4,
    TimeoutTooFar = 5,
    UnsupportedTokenProgram = 6,
    MintNotSupported = 7,
    HtlcAddressMismatch = 8,
    EscrowAddressMismatch = 9,
    AccountNotEmpty = 10,
    NotHtlc = 11,
    PreimageLength = 12,
    PreimageMismatch = 13,
    ClaimExpired = 14,
    RefundTooEarly = 15,
    MintMismatch = 16,
    RecipientMismatch = 17,
    RefundAccountMismatch = 18,
    RentReceiverMismatch = 19,
    EscrowShort = 20,
    ExactAmount = 21,
    MissingSigner = 22,
    // 23 (RefundAccountRequired) is retired since review round 1 and never reused: claim no
    // longer takes a refund token account.
    TokenProgramMismatch = 24,
    // 25 (MintHasFreezeAuthority) is retired by owner decision D47 and never reused: open accepts
    // a mint with a freeze authority, whose issuer is a documented trusted party.
}

impl From<HtlcError> for ProgramError {
    fn from(e: HtlcError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
