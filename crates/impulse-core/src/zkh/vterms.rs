// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms v4 as the builders use them (spec/V3-ZK.md 22.2): the canonical v4 terms of
//! `terms-core`, checked by its structure checks, together with their projection to the v1
//! fields. The v1 projection is the v4 bytes with the version byte 1 and `blind` removed, so the
//! v1 builders' shared checks, the v1 IPST and the v1 summaries read the same trade. Holds no
//! key.

use super::ZkhError;
use crate::terms::{Terms, TermsError, ValidatedTerms, TERMS_VERSION};
use terms_core::codec as tc;
use terms_core::hashes as th;

/// Terms v4 that passed the structure checks of `terms-core` (with the curve tests) and whose v1
/// projection passed the structure checks of v1. The fields are private: a value of this type
/// always holds checked terms with their canonical bytes and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTermsV4 {
    core: tc::Terms,
    canonical: Vec<u8>,
    hash: [u8; 32],
    v1: ValidatedTerms,
}

fn from_terms_error(e: TermsError) -> ZkhError {
    ZkhError::new(e.code(), e.to_string())
}

/// The v1 canonical bytes of v4 canonical bytes: version 1, `blind` removed.
fn v1_bytes(v4: &[u8]) -> Result<Vec<u8>, ZkhError> {
    if v4.len() < 1 + 64 {
        return Err(ZkhError::new(
            "ZK_H_TERMS_VERSION",
            "the terms are too short to be terms v4",
        ));
    }
    let split = v4.len() - 32;
    let mut v1 = Vec::with_capacity(v4.len() - 32);
    v1.push(TERMS_VERSION);
    v1.extend_from_slice(&v4[1..split - 32]);
    v1.extend_from_slice(&v4[split..]);
    Ok(v1)
}

impl ValidatedTermsV4 {
    /// Runs the structure checks on terms v4.
    pub fn from_core(core: tc::Terms) -> Result<Self, ZkhError> {
        if core.mode == tc::MODE_DIRECT {
            return Err(ZkhError::new(
                "ZK_H_TERMS_DIRECT",
                "terms v4 name Direct settlement",
            ));
        }
        terms_core::structure::validate(&core, true)?;
        let canonical = core.encode();
        let v1_terms = Terms::decode(&v1_bytes(&canonical)?).map_err(from_terms_error)?;
        let v1 = v1_terms.validate_structure().map_err(from_terms_error)?;
        let hash = th::terms_hash(&canonical);
        Ok(Self {
            core,
            canonical,
            hash,
            v1,
        })
    }

    /// Decodes canonical bytes (refusing every non-canonical string) and runs the checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkhError> {
        let core = tc::Terms::decode(bytes)?;
        if core.encode() != bytes {
            return Err(ZkhError::new(
                "ZK_H_TERMS_VERSION",
                "the terms are not canonical",
            ));
        }
        Self::from_core(core)
    }

    /// Terms v4 from a v1 draft (checked as v1 terms first) and a blind drawn by the caller.
    pub fn from_draft(draft: &Terms, blind: [u8; 32]) -> Result<Self, ZkhError> {
        let v1 = draft.encode().map_err(from_terms_error)?;
        let split = v1.len() - 32;
        let mut v4 = Vec::with_capacity(v1.len() + 32);
        v4.push(tc::TERMS_VERSION);
        v4.extend_from_slice(&v1[1..split]);
        v4.extend_from_slice(&blind);
        v4.extend_from_slice(&v1[split..]);
        let core = tc::Terms::decode(&v4)?;
        Self::from_core(core)
    }

    pub fn core(&self) -> &tc::Terms {
        &self.core
    }

    /// The v1 fields as structure-checked v1 terms (their canonical bytes and hash are the v1
    /// ones, not this version's).
    pub fn v1_fields(&self) -> &ValidatedTerms {
        &self.v1
    }

    /// The v1 fields.
    pub fn fields(&self) -> &Terms {
        self.v1.terms()
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// `BLAKE2b-256(key = "Impulse/terms/v4", canonical)`.
    pub fn terms_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The commitment of a leg (22.2).
    pub fn commit(&self, leg: u8) -> [u8; 32] {
        th::commit(&self.hash, leg)
    }

    /// The creation checks of v1 (network, expiry after creation and within the horizon).
    pub fn validate_creation(&self, ctx: &crate::terms::CreationContext) -> Result<(), ZkhError> {
        self.v1.validate_creation(ctx).map_err(from_terms_error)
    }
}
