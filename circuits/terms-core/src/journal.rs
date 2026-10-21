// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The journal J of spec/V3-ZK.md 22.3: the bytes the vault script builds and the guest commits.
//! Every field has a fixed width, so J parses one way.

use crate::{refuse, Refusal, SHAPE};

pub const TAG: &[u8; 16] = b"Impulse/zk/ht/v1";
pub const HEADER_LEN: usize = 228;
pub const ITEM_LEN: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Settle = 1,
    Refund = 2,
}

/// One view item: value, SHA-256 of the scriptPubKey (version u16 big-endian, then the script),
/// covenant ID (32 zero bytes when there is none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub value: u64,
    pub spk_hash: [u8; 32],
    pub cov: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub mode: Mode,
    pub vault_spk: [u8; 37],
    pub commit: [u8; 32],
    pub authority: [u8; 32],
    pub leg: u8,
    pub input_index: u8,
    pub locktime: u64,
    pub signer: [u8; 32],
    pub cov_a: [u8; 32],
    pub cov_c: [u8; 32],
    pub count_a: u8,
    pub count_c: u8,
    pub inputs: Vec<Item>,
    pub outputs: Vec<Item>,
}

impl Journal {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o =
            Vec::with_capacity(HEADER_LEN + ITEM_LEN * (self.inputs.len() + self.outputs.len()));
        o.extend_from_slice(TAG);
        o.push(self.mode as u8);
        o.extend_from_slice(&self.vault_spk);
        o.extend_from_slice(&self.commit);
        o.extend_from_slice(&self.authority);
        o.push(self.leg);
        o.push(self.input_index);
        o.extend_from_slice(&self.locktime.to_le_bytes());
        o.extend_from_slice(&self.signer);
        o.extend_from_slice(&self.cov_a);
        o.extend_from_slice(&self.cov_c);
        o.push(self.count_a);
        o.push(self.count_c);
        o.push(self.inputs.len() as u8);
        o.push(self.outputs.len() as u8);
        for it in self.inputs.iter().chain(self.outputs.iter()) {
            o.extend_from_slice(&it.value.to_le_bytes());
            o.extend_from_slice(&it.spk_hash);
            o.extend_from_slice(&it.cov);
        }
        o
    }

    /// Parses J strictly: the tag, a mode of 1 or 2, counts of at most four, and exactly the
    /// length the counts give. Anything else is `ZK_H_SHAPE`.
    pub fn parse(b: &[u8]) -> Result<Journal, Refusal> {
        if b.len() < HEADER_LEN || &b[..16] != TAG {
            return refuse(SHAPE, "J1");
        }
        let mode = match b[16] {
            1 => Mode::Settle,
            2 => Mode::Refund,
            _ => return refuse(SHAPE, "J1"),
        };
        let a32 = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().expect("32") };
        let n_in = b[226] as usize;
        let n_out = b[227] as usize;
        if n_in > 4 || n_out > 4 || b.len() != HEADER_LEN + ITEM_LEN * (n_in + n_out) {
            return refuse(SHAPE, "J1");
        }
        let item = |i: usize| -> Item {
            let at = HEADER_LEN + ITEM_LEN * i;
            Item {
                value: u64::from_le_bytes(b[at..at + 8].try_into().expect("8")),
                spk_hash: b[at + 8..at + 40].try_into().expect("32"),
                cov: b[at + 40..at + 72].try_into().expect("32"),
            }
        };
        Ok(Journal {
            mode,
            vault_spk: b[17..54].try_into().expect("37"),
            commit: a32(54),
            authority: a32(86),
            leg: b[118],
            input_index: b[119],
            locktime: u64::from_le_bytes(b[120..128].try_into().expect("8")),
            signer: a32(128),
            cov_a: a32(160),
            cov_c: a32(192),
            count_a: b[224],
            count_c: b[225],
            inputs: (0..n_in).map(item).collect(),
            outputs: (n_in..n_in + n_out).map(item).collect(),
        })
    }
}
