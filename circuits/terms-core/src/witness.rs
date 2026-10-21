// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The private input of the terms guest (spec/V3-ZK.md 22.4): the canonical terms, the journal
//! the script builds, the redeem script of every escrowed token input of the view and, in a
//! settle, the vault's own redeem script at its input index (`[H5]`, spec/V3-ZK.md 22.16). No
//! scriptPubKey is needed: every use of one compares its SHA-256 with a value the statement builds
//! (a P2PK, a token output, a KAS destination), so the journal's hashes are enough.
//!
//! Wire form (host to guest): u32 length and bytes of the terms; u32 length and bytes of the
//! journal; u8 count; per redeem: u8 input index, u32 length, bytes. Little-endian, nothing after.

use crate::{refuse, Refusal, WITNESS_INVALID};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    pub terms: Vec<u8>,
    pub journal: Vec<u8>,
    /// (input index in the view, redeem script).
    pub redeems: Vec<(u8, Vec<u8>)>,
}

impl Witness {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(self.terms.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.terms);
        o.extend_from_slice(&(self.journal.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.journal);
        o.push(self.redeems.len() as u8);
        for (i, r) in &self.redeems {
            o.push(*i);
            o.extend_from_slice(&(r.len() as u32).to_le_bytes());
            o.extend_from_slice(r);
        }
        o
    }

    pub fn from_bytes(b: &[u8]) -> Result<Witness, Refusal> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Refusal> {
            if b.len() - pos < n {
                return refuse(WITNESS_INVALID, "W1");
            }
            let s = &b[pos..pos + n];
            pos += n;
            Ok(s)
        };
        let l = u32::from_le_bytes(take(4)?.try_into().expect("4")) as usize;
        let terms = take(l)?.to_vec();
        let l = u32::from_le_bytes(take(4)?.try_into().expect("4")) as usize;
        let journal = take(l)?.to_vec();
        let n = take(1)?[0];
        let mut redeems = Vec::new();
        for _ in 0..n {
            let i = take(1)?[0];
            let l = u32::from_le_bytes(take(4)?.try_into().expect("4")) as usize;
            redeems.push((i, take(l)?.to_vec()));
        }
        if pos != b.len() {
            return refuse(WITNESS_INVALID, "W1");
        }
        Ok(Witness {
            terms,
            journal,
            redeems,
        })
    }

    pub fn redeem(&self, input: usize) -> Option<&[u8]> {
        self.redeems
            .iter()
            .find(|(i, _)| *i as usize == input)
            .map(|(_, r)| r.as_slice())
    }
}
