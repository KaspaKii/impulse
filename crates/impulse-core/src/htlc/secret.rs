// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashlock secret (spec/V2.md section 10.5, step 1; D32, D50). Only with the non-default
//! cargo feature `htlc-secret`, which only the seller's command line enables.
//!
//! A fresh 32-byte secret per trade, drawn from the operating system's random source on the
//! seller's own machine. This type never prints, logs or transmits it: it has no `Display`, its
//! `Debug` shows no byte of it, it is not `Clone`, and its buffer is zeroed on drop. The caller
//! that writes it to the file the seller names (mode 0600) reads it through
//! [`HashlockSecret::expose`], and nothing else does. Its sha256 is the terms' hash lock.

use super::{sha256, HtlcError, SECRET_LEN};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use zeroize::Zeroizing;

/// A hashlock secret held in memory, zeroed on drop.
pub struct HashlockSecret(Zeroizing<[u8; SECRET_LEN]>);

impl HashlockSecret {
    /// A fresh secret from the operating system's random source. Panics if the source fails, so
    /// no secret ever comes from a degraded source.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// A secret read back from the seller's own file: exactly 32 bytes (`HTLC_SECRET_LENGTH`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HtlcError> {
        let array: [u8; SECRET_LEN] = bytes
            .try_into()
            .map_err(|_| HtlcError::SecretLength { len: bytes.len() })?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// The hash lock the terms carry: sha256 of the secret.
    pub fn hash_lock(&self) -> [u8; 32] {
        sha256(self.0.as_ref())
    }

    /// The secret's bytes, for the one caller that writes them to the seller's file, and for the
    /// seller's claim on the counterpart chain. Never print, log or transmit them otherwise.
    pub fn expose(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for HashlockSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashlockSecret(<redacted>)")
    }
}
