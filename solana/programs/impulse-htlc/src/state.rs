// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The HTLC state account: fixed layout, little-endian integers.

use pinocchio::{address::Address, error::ProgramError};

use crate::error::HtlcError;

/// First byte of a live HTLC state account.
pub const HTLC_TAG: u8 = 0x48; // 'H'
/// Layout version.
pub const HTLC_VERSION: u8 = 1;

/// Byte layout of the state account.
///
/// | offset | size | field |
/// | 0 | 1 | tag 0x48 |
/// | 1 | 1 | version 1 |
/// | 2 | 1 | htlc bump |
/// | 3 | 1 | escrow bump |
/// | 4 | 32 | funder (rent payer, seed) |
/// | 36 | 32 | token program |
/// | 68 | 32 | mint |
/// | 100 | 32 | escrow token account |
/// | 132 | 32 | recipient (token account owner paid by claim) |
/// | 164 | 32 | refund (token account owner paid by refund) |
/// | 196 | 32 | hash_lock (sha256 of the 32-byte preimage) |
/// | 228 | 8 | amount (base units, u64) |
/// | 236 | 8 | timeout (unix seconds, i64, cluster clock) |
/// | 244 | 1 | mint decimals |
pub const HTLC_LEN: usize = 245;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Htlc {
    pub bump: u8,
    pub escrow_bump: u8,
    pub funder: Address,
    pub token_program: Address,
    pub mint: Address,
    pub escrow: Address,
    pub recipient: Address,
    pub refund: Address,
    pub hash_lock: [u8; 32],
    pub amount: u64,
    pub timeout: i64,
    pub decimals: u8,
}

fn addr(b: &[u8], at: usize) -> Address {
    let mut a = [0u8; 32];
    a.copy_from_slice(&b[at..at + 32]);
    Address::new_from_array(a)
}

impl Htlc {
    pub fn write(&self, out: &mut [u8]) -> Result<(), ProgramError> {
        if out.len() != HTLC_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        out[0] = HTLC_TAG;
        out[1] = HTLC_VERSION;
        out[2] = self.bump;
        out[3] = self.escrow_bump;
        out[4..36].copy_from_slice(self.funder.as_ref());
        out[36..68].copy_from_slice(self.token_program.as_ref());
        out[68..100].copy_from_slice(self.mint.as_ref());
        out[100..132].copy_from_slice(self.escrow.as_ref());
        out[132..164].copy_from_slice(self.recipient.as_ref());
        out[164..196].copy_from_slice(self.refund.as_ref());
        out[196..228].copy_from_slice(&self.hash_lock);
        out[228..236].copy_from_slice(&self.amount.to_le_bytes());
        out[236..244].copy_from_slice(&self.timeout.to_le_bytes());
        out[244] = self.decimals;
        Ok(())
    }

    pub fn read(b: &[u8]) -> Result<Self, ProgramError> {
        if b.len() != HTLC_LEN || b[0] != HTLC_TAG || b[1] != HTLC_VERSION {
            return Err(HtlcError::NotHtlc.into());
        }
        let mut hash_lock = [0u8; 32];
        hash_lock.copy_from_slice(&b[196..228]);
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&b[228..236]);
        let mut timeout = [0u8; 8];
        timeout.copy_from_slice(&b[236..244]);
        Ok(Htlc {
            bump: b[2],
            escrow_bump: b[3],
            funder: addr(b, 4),
            token_program: addr(b, 36),
            mint: addr(b, 68),
            escrow: addr(b, 100),
            recipient: addr(b, 132),
            refund: addr(b, 164),
            hash_lock,
            amount: u64::from_le_bytes(amount),
            timeout: i64::from_le_bytes(timeout),
            decimals: b[244],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = Htlc {
            bump: 254,
            escrow_bump: 253,
            funder: Address::new_from_array([1; 32]),
            token_program: Address::new_from_array([2; 32]),
            mint: Address::new_from_array([3; 32]),
            escrow: Address::new_from_array([4; 32]),
            recipient: Address::new_from_array([5; 32]),
            refund: Address::new_from_array([6; 32]),
            hash_lock: [7; 32],
            amount: 1_000_001,
            timeout: 1_800_000_000,
            decimals: 6,
        };
        let mut buf = [0u8; HTLC_LEN];
        h.write(&mut buf).unwrap();
        assert_eq!(Htlc::read(&buf).unwrap(), h);
        buf[0] = 0;
        assert_eq!(
            Htlc::read(&buf).unwrap_err(),
            ProgramError::Custom(HtlcError::NotHtlc as u32)
        );
    }
}
