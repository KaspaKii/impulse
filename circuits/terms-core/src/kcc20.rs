// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The KCC-20 state as silverscript v1.0.0 writes it into a token's redeem script
//! (`compile/state.rs`, `compile_encoded_state_fields`): each field is a data push of its fixed
//! width, in the order of kcc20.sil: owner (32), identifier type (1), amount (8, sign-magnitude
//! little-endian as OpNum2Bin writes it), is_minter (1).

use crate::hashes;

pub const STATE_LEN: usize = 46;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub owner: [u8; 32],
    pub id_type: u8,
    pub amount: i64,
    pub is_minter: bool,
}

fn num2bin8(v: i64) -> [u8; 8] {
    let mag = v.unsigned_abs();
    let mut b = mag.to_le_bytes();
    if v < 0 {
        b[7] |= 0x80;
    }
    b
}

fn bin2num8(b: &[u8]) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    let neg = a[7] & 0x80 != 0;
    a[7] &= 0x7f;
    let mag = u64::from_le_bytes(a) as i64;
    if neg {
        -mag
    } else {
        mag
    }
}

pub fn encode(s: &State) -> [u8; STATE_LEN] {
    let mut o = [0u8; STATE_LEN];
    o[0] = 0x20;
    o[1..33].copy_from_slice(&s.owner);
    o[33] = 0x01;
    o[34] = s.id_type;
    o[35] = 0x08;
    o[36..44].copy_from_slice(&num2bin8(s.amount));
    o[44] = 0x01;
    o[45] = u8::from(s.is_minter);
    o
}

/// Reads the state payloads at their fixed offsets, as `readInputStateWithTemplate` does (it does
/// not look at the push prefixes). A non-zero minter byte reads as true, as a script boolean does.
pub fn decode(b: &[u8; STATE_LEN]) -> State {
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&b[1..33]);
    State {
        owner,
        id_type: b[34],
        amount: bin2num8(&b[36..44]),
        is_minter: b[45] != 0,
    }
}

/// A token input or output opened to its template: the redeem script's prefix and suffix and, for
/// an input, its state.
pub struct Opened<'a> {
    pub prefix: &'a [u8],
    pub suffix: &'a [u8],
    pub state: State,
}

/// Splits `redeem` at the template lengths and checks the template hash. The state bytes are
/// read.
pub fn open_template<'a>(
    redeem: &'a [u8],
    prefix_len: u32,
    suffix_len: u32,
    template_hash: &[u8; 32],
) -> Option<Opened<'a>> {
    let (p, s) = (prefix_len as usize, suffix_len as usize);
    if redeem.len() != p.checked_add(STATE_LEN)?.checked_add(s)? {
        return None;
    }
    let prefix = &redeem[..p];
    let suffix = &redeem[p + STATE_LEN..];
    if hashes::template_hash(prefix, suffix) != *template_hash {
        return None;
    }
    Some(Opened {
        prefix,
        suffix,
        state: decode(redeem[p..p + STATE_LEN].try_into().expect("state length")),
    })
}

/// The scriptPubKey hash (SHA-256 of version || P2SH script) of the token output a delivery
/// must be: the template around `state`.
pub fn output_spk_hash(prefix: &[u8], suffix: &[u8], state: &State) -> [u8; 32] {
    let mut redeem = Vec::with_capacity(prefix.len() + STATE_LEN + suffix.len());
    redeem.extend_from_slice(prefix);
    redeem.extend_from_slice(&encode(state));
    redeem.extend_from_slice(suffix);
    hashes::sha256(&hashes::p2sh_spk(&hashes::blake2b256(&redeem)))
}

/// SHA-256 of the scriptPubKey of the P2SH of `redeem`.
pub fn input_spk_hash(redeem: &[u8]) -> [u8; 32] {
    hashes::sha256(&hashes::p2sh_spk(&hashes::blake2b256(redeem)))
}
