// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashes of the statement: BLAKE2b-256 (keyed, for terms and commitments; unkeyed, as
//! OpBlake2b computes a P2SH hash), BLAKE3 (the template hash builtin), SHA-256 (the journal's
//! view items and the gate).

use sha2::Digest;

pub const TERMS_KEY: &[u8] = b"Impulse/terms/v4";
pub const COMMIT_KEY: &[u8] = b"Impulse/commit/v4";

pub fn blake2b256_keyed(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .key(key)
        .to_state()
        .update(msg)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// BLAKE2b-256 with no key: what OpBlake2b computes.
pub fn blake2b256(msg: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(msg)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(msg).into()
}

/// `terms_hash_v4 = BLAKE2b-256(key = "Impulse/terms/v4", canonical terms v4)`.
pub fn terms_hash(canonical: &[u8]) -> [u8; 32] {
    blake2b256_keyed(TERMS_KEY, canonical)
}

/// `commit(t, leg) = BLAKE2b-256(key = "Impulse/commit/v4", terms_hash_v4(t) || leg)`.
pub fn commit(terms_hash: &[u8; 32], leg: u8) -> [u8; 32] {
    let mut m = [0u8; 33];
    m[..32].copy_from_slice(terms_hash);
    m[32] = leg;
    blake2b256_keyed(COMMIT_KEY, &m)
}

/// The template hash builtin: BLAKE3 of the 8-byte little-endian prefix length, the prefix, the
/// 8-byte little-endian suffix length and the suffix (silverscript v1.0.0, `builtin.rs:240-248`).
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}

/// A version-0 pay-to-script-hash scriptPubKey as introspection returns it: version (u16
/// big-endian), OpBlake2b, OpData32, the hash, OpEqual.
pub fn p2sh_spk(script_hash: &[u8; 32]) -> [u8; 37] {
    let mut s = [0u8; 37];
    s[2] = 0xaa;
    s[3] = 0x20;
    s[4..36].copy_from_slice(script_hash);
    s[36] = 0x87;
    s
}

/// A version-0 Schnorr pay-to-pubkey scriptPubKey as introspection returns it.
pub fn p2pk_spk(key: &[u8; 32]) -> [u8; 36] {
    let mut s = [0u8; 36];
    s[2] = 0x20;
    s[3..35].copy_from_slice(key);
    s[35] = 0xac;
    s
}

/// The 32-byte hash of a P2SH scriptPubKey of this exact shape, else `None`.
pub fn p2sh_hash_of(spk: &[u8]) -> Option<[u8; 32]> {
    if spk.len() == 37 && spk[..4] == [0, 0, 0xaa, 0x20] && spk[36] == 0x87 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&spk[4..36]);
        Some(h)
    } else {
        None
    }
}
