// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template refusals. Every variant maps to one stable code (spec/TEMPLATE.md, "Error codes");
//! a terms refusal met on the way keeps its own `TERMS_*` code. Integrators match on `code()`,
//! never on the Display text.

use super::LegIndex;
use crate::terms::TermsError;
use std::fmt;

/// Why a template, an instantiation or a redeem script was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateError {
    /// The embedded artifact or TEMPLATE_HASH file cannot be used.
    ArtifactInvalid { reason: String },
    /// The template's prefix and suffix do not hash to `expected` (the artifact's declared hash,
    /// or contracts/TEMPLATE_HASH).
    HashMismatch { expected: [u8; 32], found: [u8; 32] },
    /// A leg index other than 0 (asset) or 1 (cash).
    LegIndex { value: i64 },
    /// The terms give this leg no vault.
    NoVault { leg: LegIndex, reason: &'static str },
    /// The script does not run the ImpulseVault template.
    NotImpulseVault,
    /// The state span does not parse, or does not encode, as the ImpulseVault state.
    StateMalformed { reason: String },
    /// A state field holds, or would need, a value outside the terms' domain.
    StateInvalid { field: &'static str },
    /// The state decodes to terms whose instantiation is not this script.
    NonCanonical,
    /// The terms were refused; the code is the terms code.
    Terms(TermsError),
}

/// Every template refusal code, in declaration order. Frozen once merged: a test pins this
/// list, and it may only grow at the end. Terms refusals keep their `TERMS_*` codes.
pub const TEMPLATE_ERROR_CODES: [&str; 8] = [
    "TEMPLATE_ARTIFACT_INVALID",
    "TEMPLATE_HASH_MISMATCH",
    "TEMPLATE_LEG_INDEX",
    "TEMPLATE_NO_VAULT",
    "TEMPLATE_NOT_IMPULSE_VAULT",
    "TEMPLATE_STATE_MALFORMED",
    "TEMPLATE_STATE_INVALID",
    "TEMPLATE_NONCANONICAL",
];

impl TemplateError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ArtifactInvalid { .. } => "TEMPLATE_ARTIFACT_INVALID",
            Self::HashMismatch { .. } => "TEMPLATE_HASH_MISMATCH",
            Self::LegIndex { .. } => "TEMPLATE_LEG_INDEX",
            Self::NoVault { .. } => "TEMPLATE_NO_VAULT",
            Self::NotImpulseVault => "TEMPLATE_NOT_IMPULSE_VAULT",
            Self::StateMalformed { .. } => "TEMPLATE_STATE_MALFORMED",
            Self::StateInvalid { .. } => "TEMPLATE_STATE_INVALID",
            Self::NonCanonical => "TEMPLATE_NONCANONICAL",
            Self::Terms(e) => e.code(),
        }
    }
}

impl From<TermsError> for TemplateError {
    fn from(e: TermsError) -> Self {
        Self::Terms(e)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Terms(e) => e.fmt(f),
            Self::ArtifactInvalid { reason } => {
                write!(f, "{code}: embedded template unusable: {reason}")
            }
            Self::HashMismatch { expected, found } => write!(
                f,
                "{code}: template hash {} where {} is pinned",
                hex(found),
                hex(expected)
            ),
            Self::LegIndex { value } => write!(f, "{code}: leg index {value} is neither 0 nor 1"),
            Self::NoVault { leg, reason } => {
                write!(f, "{code}: no vault for the {leg:?} leg: {reason}")
            }
            Self::NotImpulseVault => {
                write!(
                    f,
                    "{code}: the script does not run the ImpulseVault template"
                )
            }
            Self::StateMalformed { reason } => write!(f, "{code}: state span: {reason}"),
            Self::StateInvalid { field } => {
                write!(
                    f,
                    "{code}: state field {field} holds a value outside the terms"
                )
            }
            Self::NonCanonical => write!(
                f,
                "{code}: the script is not the instantiation of the terms it decodes to"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}
