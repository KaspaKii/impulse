// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Refusals of linked trades (spec/V2.md section 17.10). Every variant maps to one stable code:
//! the `LINKED_` family below, or the code of the v2 refusal it wraps (a `TERMS_` code of the
//! sheet's opening or of the derived return, a `TX_` code of a builder). The codes are frozen:
//! integrators match on `code()`, never on the Display text.

use crate::terms::TermsError;
use crate::v2::V2Error;
use std::fmt;

/// Which of the two trades of a sheet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Opening,
    Return,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Return => "return",
        }
    }

    /// The other trade of the sheet.
    pub fn other(self) -> Self {
        match self {
            Self::Opening => Self::Return,
            Self::Return => Self::Opening,
        }
    }
}

/// Why a sheet, a terms value offered for a role, an evidence transaction or a receipt pair was
/// refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkedError {
    /// `LINKED_VERSION`.
    Version { version: u8 },
    /// `LINKED_TRUNCATED`.
    Truncated { field: &'static str },
    /// `LINKED_TRAILING_BYTES`.
    TrailingBytes { count: usize },
    /// `LINKED_LEG_COUNT`.
    LegCount { count: usize },
    /// `LINKED_PARTIAL`.
    Partial,
    /// `LINKED_TRADE_REF_SET`.
    TradeRefSet,
    /// `LINKED_RETURN_NOT_LATER`.
    ReturnNotLater {
        return_earliest_daa: u64,
        opening_expiry_daa: u64,
    },
    /// `LINKED_NOT_A_LEG`.
    NotALeg { role: Role },
    /// `LINKED_ROLE_MISMATCH`: the terms are the other role's.
    RoleMismatch { role: Role },
    /// `LINKED_TRADE_REF`.
    TradeRef { role: Role },
    /// `LINKED_OPENING_NOT_SETTLED`.
    OpeningNotSettled,
    /// `LINKED_SETTLE_EVIDENCE`.
    SettleEvidence { role: Role, reason: &'static str },
    /// `LINKED_RECEIPT_TERMS`.
    ReceiptTerms { reason: &'static str },
    /// `LINKED_RECEIPT_PAIR`.
    ReceiptPair { reason: &'static str },
    /// A v2 refusal (terms structure, builder, verifier) with its own code.
    V2(V2Error),
}

/// The `LINKED_` codes (spec/V2.md 17.10, numbers 1 to 14), in order. Frozen once merged: a test
/// pins this list, and it may only grow at the end.
pub const LINKED_ERROR_CODES: [&str; 14] = [
    "LINKED_VERSION",
    "LINKED_TRUNCATED",
    "LINKED_TRAILING_BYTES",
    "LINKED_LEG_COUNT",
    "LINKED_PARTIAL",
    "LINKED_TRADE_REF_SET",
    "LINKED_RETURN_NOT_LATER",
    "LINKED_NOT_A_LEG",
    "LINKED_ROLE_MISMATCH",
    "LINKED_TRADE_REF",
    "LINKED_OPENING_NOT_SETTLED",
    "LINKED_SETTLE_EVIDENCE",
    "LINKED_RECEIPT_TERMS",
    "LINKED_RECEIPT_PAIR",
];

impl LinkedError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Version { .. } => "LINKED_VERSION",
            Self::Truncated { .. } => "LINKED_TRUNCATED",
            Self::TrailingBytes { .. } => "LINKED_TRAILING_BYTES",
            Self::LegCount { .. } => "LINKED_LEG_COUNT",
            Self::Partial => "LINKED_PARTIAL",
            Self::TradeRefSet => "LINKED_TRADE_REF_SET",
            Self::ReturnNotLater { .. } => "LINKED_RETURN_NOT_LATER",
            Self::NotALeg { .. } => "LINKED_NOT_A_LEG",
            Self::RoleMismatch { .. } => "LINKED_ROLE_MISMATCH",
            Self::TradeRef { .. } => "LINKED_TRADE_REF",
            Self::OpeningNotSettled => "LINKED_OPENING_NOT_SETTLED",
            Self::SettleEvidence { .. } => "LINKED_SETTLE_EVIDENCE",
            Self::ReceiptTerms { .. } => "LINKED_RECEIPT_TERMS",
            Self::ReceiptPair { .. } => "LINKED_RECEIPT_PAIR",
            Self::V2(e) => e.code(),
        }
    }
}

impl From<V2Error> for LinkedError {
    fn from(e: V2Error) -> Self {
        Self::V2(e)
    }
}

impl From<TermsError> for LinkedError {
    fn from(e: TermsError) -> Self {
        Self::V2(e.into())
    }
}

impl fmt::Display for LinkedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::V2(e) = self {
            return write!(f, "{e}");
        }
        write!(f, "{}: ", self.code())?;
        match self {
            Self::Version { version } => write!(f, "link_version {version}, only 1 exists"),
            Self::Truncated { field } => write!(f, "the sheet ends inside {field}"),
            Self::TrailingBytes { count } => write!(f, "{count} bytes follow the sheet"),
            Self::LegCount { count } => {
                write!(f, "the opening has {count} legs, a linked trade has 2")
            }
            Self::Partial => write!(f, "a linked trade has no partial settlement"),
            Self::TradeRefSet => write!(
                f,
                "the opening's trade_ref must be zero in the sheet: the sheet's hash is written into it"
            ),
            Self::ReturnNotLater {
                return_earliest_daa,
                opening_expiry_daa,
            } => write!(
                f,
                "return_earliest_daa {return_earliest_daa} is not above the opening's expiry_daa {opening_expiry_daa}"
            ),
            Self::NotALeg { role } => {
                write!(f, "the terms are not the {} trade of this sheet", role.name())
            }
            Self::RoleMismatch { role } => write!(
                f,
                "the terms are the {} trade of this sheet, not the {} trade",
                role.other().name(),
                role.name()
            ),
            Self::TradeRef { role } => write!(
                f,
                "the terms are the {} trade of this sheet except for trade_ref, which is not the sheet's hash",
                role.name()
            ),
            Self::OpeningNotSettled => write!(
                f,
                "the return needs evidence that the opening settled; none was given for this sheet"
            ),
            Self::SettleEvidence { reason, .. } => write!(f, "{reason}"),
            Self::ReceiptTerms { reason } | Self::ReceiptPair { reason } => write!(f, "{reason}"),
            Self::V2(_) => unreachable!("written above"),
        }
    }
}

impl std::error::Error for LinkedError {}
