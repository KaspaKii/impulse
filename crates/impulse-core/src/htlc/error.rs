// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Hashlock refusals. Every variant maps to one stable code: the `HTLC_` family of spec/V2.md
//! section 8.5, or the v1 code whose meaning applies unchanged (`TERMS_*` of section 8.5, the
//! builder's `TX_*` and the verifier's `VERIFY_*`, D51). The codes are frozen: integrators match
//! on `code()`, never on the Display text.

use crate::terms::TermsError;
use crate::tx::TxError;
use crate::verify::VerifyError;
use std::fmt;

/// Why hashlock terms, a hashlock script, a builder's inputs or a verification were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HtlcError {
    /// The hashlock terms version byte is not 1.
    Version { version: u8 },
    /// The asset leg is not KCC-20.
    AssetKind,
    /// hash_lock is all zero.
    HashZero,
    /// The counterpart record names an unknown chain, has a zero amount, an all-zero
    /// identifier, or a timeout of zero or above `i64::MAX`; or, at creation, a timeout at or
    /// before the time of the check (`field`).
    Counterpart { field: &'static str },
    /// The estimated wall-clock time of expiry_daa does not reach the counterpart timeout plus
    /// the margin.
    TimeoutMargin {
        expiry_estimate_unix: u64,
        required_unix: u64,
    },
    /// The embedded hashlock artifact or `TEMPLATE_HASH_HASHLOCK` cannot be used.
    ArtifactInvalid { reason: String },
    /// The hashlock template hash differs from the artifact's or from `TEMPLATE_HASH_HASHLOCK`.
    HashMismatch { expected: [u8; 32], found: [u8; 32] },
    /// The script does not run the hashlock template.
    NotHashlockVault,
    /// The state does not parse as the hashlock state.
    StateMalformed { reason: String },
    /// A state field holds a value no hashlock terms value encodes to.
    StateInvalid { field: &'static str },
    /// The script is not the instantiation of the state it decodes to.
    NonCanonical,
    /// The preimage is not 32 bytes.
    SecretLength { len: usize },
    /// sha256 of the preimage is not hash_lock.
    SecretMismatch,
    /// On mainnet no DAA rate sample is given, or it is not a sample of the required shape, is
    /// older than 30 days, or was taken at another blocks-per-second than the network's.
    DaaSample { reason: &'static str },
    /// Reserved and no longer returned: the mainnet gate was lifted by D39 (b) and D40
    /// (spec/V2.md section 10.5). The code number stays so codes are not renumbered.
    MainnetGated,
    /// A funding transaction does not fund the terms' vault: no output, or more than one, holds
    /// the escrowed token (the asset's covenant and template, owned by the vault's script hash,
    /// exactly the amount, not a minter), or no authorizer sits at the vault (`reason`).
    Funding { reason: &'static str },
    /// A terms refusal whose v1 meaning applies unchanged; the code is that refusal's.
    Terms(TermsError),
    /// A builder, signature or slot refusal; the code is that refusal's.
    Tx(TxError),
    /// A verifier refusal whose v1 meaning applies unchanged; the code is that refusal's.
    Verify(VerifyError),
}

/// Every `HTLC_` code, in the order of spec/V2.md section 8.5. Frozen once merged: a test pins
/// this list, and it may only grow at the end.
pub const HTLC_ERROR_CODES: [&str; 16] = [
    "HTLC_VERSION",
    "HTLC_ASSET_KIND",
    "HTLC_HASH_ZERO",
    "HTLC_COUNTERPART",
    "HTLC_TIMEOUT_MARGIN",
    "HTLC_ARTIFACT_INVALID",
    "HTLC_HASH_MISMATCH",
    "HTLC_NOT_HASHLOCK_VAULT",
    "HTLC_STATE_MALFORMED",
    "HTLC_STATE_INVALID",
    "HTLC_NONCANONICAL",
    "HTLC_SECRET_LENGTH",
    "HTLC_SECRET_MISMATCH",
    "HTLC_DAA_SAMPLE",
    "HTLC_MAINNET_GATED",
    "HTLC_FUNDING",
];

impl HtlcError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Version { .. } => "HTLC_VERSION",
            Self::AssetKind => "HTLC_ASSET_KIND",
            Self::HashZero => "HTLC_HASH_ZERO",
            Self::Counterpart { .. } => "HTLC_COUNTERPART",
            Self::TimeoutMargin { .. } => "HTLC_TIMEOUT_MARGIN",
            Self::ArtifactInvalid { .. } => "HTLC_ARTIFACT_INVALID",
            Self::HashMismatch { .. } => "HTLC_HASH_MISMATCH",
            Self::NotHashlockVault => "HTLC_NOT_HASHLOCK_VAULT",
            Self::StateMalformed { .. } => "HTLC_STATE_MALFORMED",
            Self::StateInvalid { .. } => "HTLC_STATE_INVALID",
            Self::NonCanonical => "HTLC_NONCANONICAL",
            Self::SecretLength { .. } => "HTLC_SECRET_LENGTH",
            Self::SecretMismatch => "HTLC_SECRET_MISMATCH",
            Self::DaaSample { .. } => "HTLC_DAA_SAMPLE",
            Self::MainnetGated => "HTLC_MAINNET_GATED",
            Self::Funding { .. } => "HTLC_FUNDING",
            Self::Terms(e) => e.code(),
            Self::Tx(e) => e.code(),
            Self::Verify(e) => e.code(),
        }
    }
}

impl From<TxError> for HtlcError {
    fn from(e: TxError) -> Self {
        Self::Tx(e)
    }
}

impl From<VerifyError> for HtlcError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for HtlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Terms(e) => e.fmt(f),
            Self::Tx(e) => e.fmt(f),
            Self::Verify(e) => e.fmt(f),
            Self::Version { version } => write!(f, "{code}: hashlock terms version {version}"),
            Self::AssetKind => write!(f, "{code}: the hashlock asset leg must be KCC-20"),
            Self::HashZero => write!(f, "{code}: hash_lock is all zero"),
            Self::Counterpart { field } => {
                write!(f, "{code}: the counterpart record's {field} is not usable")
            }
            Self::TimeoutMargin {
                expiry_estimate_unix,
                required_unix,
            } => write!(
                f,
                "{code}: expiry_daa is estimated to arrive at unix time {expiry_estimate_unix}, before {required_unix} (the counterpart timeout plus the margin)"
            ),
            Self::ArtifactInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::HashMismatch { expected, found } => write!(
                f,
                "{code}: template hash {} is not {}",
                hex(found),
                hex(expected)
            ),
            Self::NotHashlockVault => {
                write!(f, "{code}: the script does not run the hashlock template")
            }
            Self::StateMalformed { reason } => write!(f, "{code}: {reason}"),
            Self::StateInvalid { field } => {
                write!(f, "{code}: state field {field} holds no hashlock terms value")
            }
            Self::NonCanonical => write!(
                f,
                "{code}: the script is not the instantiation of the state it decodes to"
            ),
            Self::SecretLength { len } => {
                write!(f, "{code}: the preimage is {len} bytes, not 32")
            }
            Self::SecretMismatch => write!(f, "{code}: sha256 of the preimage is not hash_lock"),
            Self::DaaSample { reason } => write!(f, "{code}: {reason}"),
            Self::Funding { reason } => write!(f, "{code}: {reason}"),
            Self::MainnetGated => write!(
                f,
                "{code}: reserved; the mainnet gate was lifted (D39 b, D40) and this code is no longer returned"
            ),
        }
    }
}

impl std::error::Error for HtlcError {}
