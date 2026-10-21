// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DvpSwapInstructionDiscriminators {
    CreateDvp = 0,
    ReclaimDvp = 1,
    SettleDvp = 2,
    CancelDvp = 3,
    RejectDvp = 4,
    RecoverDvp = 5,
}

impl TryFrom<u8> for DvpSwapInstructionDiscriminators {
    type Error = ();

    fn try_from(discriminator: u8) -> Result<Self, Self::Error> {
        match discriminator {
            0 => Ok(Self::CreateDvp),
            1 => Ok(Self::ReclaimDvp),
            2 => Ok(Self::SettleDvp),
            3 => Ok(Self::CancelDvp),
            4 => Ok(Self::RejectDvp),
            5 => Ok(Self::RecoverDvp),
            _ => Err(()),
        }
    }
}
