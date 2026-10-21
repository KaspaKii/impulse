// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Decoding refusals. Every variant maps to one stable code (spec/VERIFY.md, "Error codes"); a
//! template or terms refusal met on a vault input keeps its own `TEMPLATE_*` or `TERMS_*` code.
//! Integrators match on `code()`, never on the Display text.

use crate::template::TemplateError;
use std::fmt;

/// Why a transaction was not decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The raw bytes are not the borsh encoding of a transaction, or bytes are left over.
    TxMalformed { reason: String },
    /// The transaction ID the value carries is not the ID of its contents.
    TxIdMismatch {
        carried: [u8; 32],
        computed: [u8; 32],
    },
    /// Vault input `index` calls no entry of the template.
    EntryUnknown { index: usize },
    /// No input spends an Impulse vault.
    NoVaultInput,
    /// Vault input `index` reveals a script Impulse refuses; the code is that refusal's.
    Input { index: usize, error: TemplateError },
    /// The embedded template failed its startup check; the code is that refusal's.
    Template(TemplateError),
    /// The spent scriptPublicKeys supplied are not one per input.
    SpentCount { inputs: usize, spent: usize },
    /// Input `index` reveals a vault script but does not spend the version 0 P2SH of it, so
    /// consensus did not run that script for it.
    InputNotVault { index: usize },
}

/// Every decoding refusal code, in declaration order. Frozen once merged: a test pins this
/// list, and it may only grow at the end. Template and terms refusals keep their own codes.
pub const DECODE_ERROR_CODES: [&str; 6] = [
    "DECODE_TX_MALFORMED",
    "DECODE_TX_ID_MISMATCH",
    "DECODE_ENTRY_UNKNOWN",
    "DECODE_NO_VAULT_INPUT",
    "DECODE_SPENT_COUNT",
    "DECODE_INPUT_NOT_VAULT",
];

impl DecodeError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TxMalformed { .. } => "DECODE_TX_MALFORMED",
            Self::TxIdMismatch { .. } => "DECODE_TX_ID_MISMATCH",
            Self::EntryUnknown { .. } => "DECODE_ENTRY_UNKNOWN",
            Self::NoVaultInput => "DECODE_NO_VAULT_INPUT",
            Self::SpentCount { .. } => "DECODE_SPENT_COUNT",
            Self::InputNotVault { .. } => "DECODE_INPUT_NOT_VAULT",
            Self::Input { error, .. } | Self::Template(error) => error.code(),
        }
    }

    /// The input a per-input refusal names; None for a refusal of the whole transaction.
    pub fn input_index(&self) -> Option<usize> {
        match self {
            Self::EntryUnknown { index }
            | Self::Input { index, .. }
            | Self::InputNotVault { index } => Some(*index),
            _ => None,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TxMalformed { reason } => {
                write!(f, "{code}: not a borsh-encoded transaction: {reason}")
            }
            Self::TxIdMismatch { carried, computed } => write!(
                f,
                "{code}: the transaction carries ID {} but its contents hash to {}",
                hex(carried),
                hex(computed)
            ),
            Self::EntryUnknown { index } => write!(
                f,
                "{code}: vault input {index} calls no entry of the ImpulseVault template"
            ),
            Self::NoVaultInput => write!(f, "{code}: no input spends an Impulse vault"),
            Self::Input { index, error } => write!(f, "input {index}: {error}"),
            Self::Template(error) => error.fmt(f),
            Self::SpentCount { inputs, spent } => write!(
                f,
                "{code}: {spent} spent scriptPublicKeys for {inputs} inputs"
            ),
            Self::InputNotVault { index } => write!(
                f,
                "{code}: input {index} reveals a vault script but does not spend its version 0 P2SH"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}
