// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Verifier refusals. Every variant maps to one stable code (spec/VERIFY.md, "Error codes"); a
//! template or terms refusal met on the way keeps its own `TEMPLATE_*` or `TERMS_*` code.
//! Integrators match on `code()`, never on the Display text. Text that comes from a
//! counterparty is escaped to printable ASCII before it is stored in a variant ([`printable`]).

use super::TemplateTriple;
use crate::template::{LegIndex, TemplateError};
use crate::terms::{Network, TermsError};
use std::fmt;

/// Why a verification failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The offered address does not parse as a Kaspa address.
    AddressMalformed { leg: LegIndex, reason: String },
    /// The offered address carries another network's prefix than the terms name.
    AddressNetwork {
        leg: LegIndex,
        expected: Network,
        found: String,
    },
    /// The offered address does not pay this leg's vault, nor the other leg's.
    AddressMismatch { leg: LegIndex },
    /// The leg has a vault but no address was offered for it.
    AddressMissing { leg: LegIndex },
    /// An address was offered for a leg the terms give no vault.
    AddressUnexpected { leg: LegIndex },
    /// The address or script offered for `leg` is the other leg's vault of these terms.
    LegsSwapped { leg: LegIndex },
    /// The revealed script does not run the published template; `found` is None when the
    /// script is shorter than the template.
    TemplateMismatch {
        expected: [u8; 32],
        found: Option<[u8; 32]>,
    },
    /// The revealed script is a vault of other terms; `fields` names those that differ.
    TermsMismatch { fields: Vec<&'static str> },
    /// Token evidence was supplied for a leg that is not KCC-20.
    TokenLegKind { leg: LegIndex },
    /// The token artifact is too long, does not parse, does not hold exactly one contract,
    /// declares a name that is not an identifier or a struct-typed state field, or fails
    /// silverscript's consistency check.
    TokenArtifactInvalid { leg: LegIndex, reason: String },
    /// The token artifact's template is not the one the terms name for the leg.
    TokenTemplateMismatch {
        leg: LegIndex,
        expected: TemplateTriple,
        found: TemplateTriple,
    },
    /// The token artifact does not declare the KCC-20 state or entries the vault relies on.
    TokenNotKcc20 { leg: LegIndex, reason: String },
    /// The spent input's signature script is not push only or reveals no script.
    NothingRevealed,
    /// The token's state has fields after the four KCC-20 fields, named in `fields`. The vault
    /// reads and rebuilds the four-field state only, so it can neither settle nor refund it.
    TokenExtendedState { leg: LegIndex, fields: Vec<String> },
    /// The UTXO the spent input spends is not the version 0 P2SH of the script the input
    /// reveals, so consensus never ran that script there.
    InputNotVault,
    /// A template or terms refusal; the code is that refusal's.
    Template(TemplateError),
}

/// Every verifier refusal code, in declaration order. Frozen once merged: a test pins this
/// list, and it may only grow at the end. Template and terms refusals keep their own codes.
pub const VERIFY_ERROR_CODES: [&str; 15] = [
    "VERIFY_ADDRESS_MALFORMED",
    "VERIFY_ADDRESS_NETWORK",
    "VERIFY_ADDRESS_MISMATCH",
    "VERIFY_ADDRESS_MISSING",
    "VERIFY_ADDRESS_UNEXPECTED",
    "VERIFY_LEGS_SWAPPED",
    "VERIFY_TEMPLATE_MISMATCH",
    "VERIFY_TERMS_MISMATCH",
    "VERIFY_TOKEN_LEG_KIND",
    "VERIFY_TOKEN_ARTIFACT_INVALID",
    "VERIFY_TOKEN_TEMPLATE_MISMATCH",
    "VERIFY_TOKEN_NOT_KCC20",
    "VERIFY_NOTHING_REVEALED",
    "VERIFY_TOKEN_EXTENDED_STATE",
    "VERIFY_INPUT_NOT_VAULT",
];

impl VerifyError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AddressMalformed { .. } => "VERIFY_ADDRESS_MALFORMED",
            Self::AddressNetwork { .. } => "VERIFY_ADDRESS_NETWORK",
            Self::AddressMismatch { .. } => "VERIFY_ADDRESS_MISMATCH",
            Self::AddressMissing { .. } => "VERIFY_ADDRESS_MISSING",
            Self::AddressUnexpected { .. } => "VERIFY_ADDRESS_UNEXPECTED",
            Self::LegsSwapped { .. } => "VERIFY_LEGS_SWAPPED",
            Self::TemplateMismatch { .. } => "VERIFY_TEMPLATE_MISMATCH",
            Self::TermsMismatch { .. } => "VERIFY_TERMS_MISMATCH",
            Self::TokenLegKind { .. } => "VERIFY_TOKEN_LEG_KIND",
            Self::TokenArtifactInvalid { .. } => "VERIFY_TOKEN_ARTIFACT_INVALID",
            Self::TokenTemplateMismatch { .. } => "VERIFY_TOKEN_TEMPLATE_MISMATCH",
            Self::TokenNotKcc20 { .. } => "VERIFY_TOKEN_NOT_KCC20",
            Self::NothingRevealed => "VERIFY_NOTHING_REVEALED",
            Self::TokenExtendedState { .. } => "VERIFY_TOKEN_EXTENDED_STATE",
            Self::InputNotVault => "VERIFY_INPUT_NOT_VAULT",
            Self::Template(e) => e.code(),
        }
    }
}

impl From<TemplateError> for VerifyError {
    fn from(e: TemplateError) -> Self {
        Self::Template(e)
    }
}

impl From<TermsError> for VerifyError {
    fn from(e: TermsError) -> Self {
        Self::Template(e.into())
    }
}

/// `text` with every character outside printable ASCII escaped as `\u{..}`. Every message text
/// that comes from a counterparty (artifact names, parser and serde errors that echo their
/// input) passes through it, so none carries a terminal control sequence or an invisible or
/// bidirectional character. It does not make text safe for HTML: integrators escape for their
/// medium.
pub(super) fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == ' ' || c.is_ascii_graphic() {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::AddressMalformed { leg, reason } => {
                write!(f, "{code}: {leg:?} leg address: {reason}")
            }
            Self::AddressNetwork {
                leg,
                expected,
                found,
            } => write!(
                f,
                "{code}: {leg:?} leg address has prefix {found}, the terms name {expected:?}"
            ),
            Self::AddressMismatch { leg } => write!(
                f,
                "{code}: the {leg:?} leg address does not pay the vault of these terms"
            ),
            Self::AddressMissing { leg } => {
                write!(f, "{code}: no address offered for the {leg:?} leg vault")
            }
            Self::AddressUnexpected { leg } => write!(
                f,
                "{code}: an address was offered for the {leg:?} leg, which has no vault"
            ),
            Self::LegsSwapped { leg } => write!(
                f,
                "{code}: what was offered as the {leg:?} leg is the other leg's vault"
            ),
            Self::TemplateMismatch { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "{code}: template hash {} where {} is published",
                    hex(found),
                    hex(expected)
                ),
                None => write!(f, "{code}: the script is shorter than the template"),
            },
            Self::TermsMismatch { fields } => write!(
                f,
                "{code}: the script is a vault of other terms (differing: {})",
                fields.join(", ")
            ),
            Self::TokenLegKind { leg } => {
                write!(
                    f,
                    "{code}: token evidence for the {leg:?} leg, which is not KCC-20"
                )
            }
            Self::TokenArtifactInvalid { leg, reason } => {
                write!(f, "{code}: {leg:?} leg token artifact: {reason}")
            }
            Self::TokenTemplateMismatch {
                leg,
                expected,
                found,
            } => write!(
                f,
                "{code}: {leg:?} leg token template {found} where the terms name {expected}"
            ),
            Self::TokenNotKcc20 { leg, reason } => {
                write!(f, "{code}: {leg:?} leg token is not KCC-20: {reason}")
            }
            Self::NothingRevealed => write!(
                f,
                "{code}: the signature script is not push only or reveals no script"
            ),
            Self::TokenExtendedState { leg, fields } => write!(
                f,
                "{code}: {leg:?} leg token state has fields beyond KCC-20's four ({}); the vault cannot settle or refund it",
                fields.join(", ")
            ),
            Self::InputNotVault => write!(
                f,
                "{code}: the input does not spend the version 0 P2SH of the script it reveals, so that script never ran"
            ),
            Self::Template(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for VerifyError {}
