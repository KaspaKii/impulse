// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The statement of the hashed-terms vault (spec/V3-ZK.md section 22): terms v4 and its two
//! commitments, the journal J, and the tag functions the terms guest proves. The guest, the host
//! checker (`impulse decode --with-terms`) and the differential test against template v1 all call
//! `statement`, so there is one definition of what a settle or a refund must satisfy.
//!
//! Every refusal is a `Refusal` carrying its stable code (spec/V3-ZK.md 22.8) and the tag of the
//! v1 require it replaces (spec/TEMPLATE.md), so a failing statement names the check.

pub mod codec;
pub mod hashes;
pub mod journal;
pub mod kcc20;
pub mod statement;
pub mod structure;
pub mod witness;

pub use codec::{Dest, Leg, Terms};
pub use journal::{Item, Journal, Mode};
pub use statement::{statement, StatementOptions};
pub use witness::Witness;

/// Lock-time domain boundary (kaspa-consensus-core `LOCK_TIME_THRESHOLD`): below it a lock time
/// is a DAA score.
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// A refusal with its stable code and the tag of the check that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub tag: &'static str,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} [{}]", self.code, self.tag)
    }
}

pub(crate) fn refuse<T>(code: &'static str, tag: &'static str) -> Result<T, Refusal> {
    Err(Refusal { code, tag })
}

pub(crate) const STATEMENT_FALSE: &str = "ZK_H_STATEMENT_FALSE";
pub(crate) const SHAPE: &str = "ZK_H_SHAPE";
pub(crate) const WITNESS_INVALID: &str = "ZK_H_WITNESS_INVALID";

/// `Ok` when `cond`, else a `ZK_H_STATEMENT_FALSE` naming `tag`.
pub(crate) fn require(cond: bool, tag: &'static str) -> Result<(), Refusal> {
    if cond {
        Ok(())
    } else {
        refuse(STATEMENT_FALSE, tag)
    }
}
