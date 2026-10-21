// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Threshold refusals. Every variant maps to one stable code (spec/THRESHOLD.md, "Error codes").
//! Integrators match on `code()`, never on the Display text.

use std::fmt;

/// Why a key generation round, a signing round, an aggregation or a verification was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThresholdError {
    /// The group shape is not t-of-n with 2 <= t <= n: one share alone could sign, or the
    /// group could never sign.
    Params { threshold: u16, parties: u16 },
    /// A party identifier outside 1..=parties.
    Party { id: u16, parties: u16 },
    /// A key generation round did not receive exactly one package from every other party.
    DkgPackages {
        round: u8,
        missing: Vec<u16>,
        unexpected: Vec<u16>,
    },
    /// A key generation package failed verification: a round-1 proof of knowledge (round 2) or
    /// a round-2 secret share (round 3). `culprit` names the sender when it can be identified.
    DkgCulprit { round: u8, culprit: Option<u16> },
    /// Fewer signing commitments than the threshold.
    TooFewSigners { signers: usize, threshold: u16 },
    /// The signer's own commitment is not in the signing set, or is not the commitment of the
    /// nonces it holds.
    SignerNotInSet { id: u16 },
    /// The signature shares do not come from exactly the parties of the signing set.
    SharesMismatch {
        missing: Vec<u16>,
        unexpected: Vec<u16>,
    },
    /// One or more signature shares failed verification against their party's public share.
    ShareInvalid { culprits: Vec<u16> },
    /// The authority key is not the x coordinate of a secp256k1 point.
    KeyInvalid,
    /// The signature does not verify under the authority key for this message (BIP-340).
    SignatureInvalid,
    /// Any other refusal by the FROST library (fail closed).
    Refused { reason: String },
    /// Bytes that are not the encoding of a threshold value, or an inconsistent value
    /// (spec/THRESHOLD.md, "Encodings").
    Encoding { reason: String },
    /// `sign_input` or `aggregate_input`: no such input in the transaction, or UTXO entries that
    /// do not match its inputs one for one.
    Input { input: usize },
}

/// Every threshold refusal code, in declaration order. Frozen once merged: a test pins this
/// list, and it may only grow at the end.
pub const THRESHOLD_ERROR_CODES: [&str; 13] = [
    "THRESHOLD_PARAMS",
    "THRESHOLD_PARTY",
    "THRESHOLD_DKG_PACKAGES",
    "THRESHOLD_DKG_CULPRIT",
    "THRESHOLD_TOO_FEW_SIGNERS",
    "THRESHOLD_SIGNER_NOT_IN_SET",
    "THRESHOLD_SHARES_MISMATCH",
    "THRESHOLD_SHARE_INVALID",
    "THRESHOLD_KEY_INVALID",
    "THRESHOLD_SIGNATURE_INVALID",
    "THRESHOLD_REFUSED",
    "THRESHOLD_ENCODING",
    "THRESHOLD_INPUT",
];

impl ThresholdError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Params { .. } => "THRESHOLD_PARAMS",
            Self::Party { .. } => "THRESHOLD_PARTY",
            Self::DkgPackages { .. } => "THRESHOLD_DKG_PACKAGES",
            Self::DkgCulprit { .. } => "THRESHOLD_DKG_CULPRIT",
            Self::TooFewSigners { .. } => "THRESHOLD_TOO_FEW_SIGNERS",
            Self::SignerNotInSet { .. } => "THRESHOLD_SIGNER_NOT_IN_SET",
            Self::SharesMismatch { .. } => "THRESHOLD_SHARES_MISMATCH",
            Self::ShareInvalid { .. } => "THRESHOLD_SHARE_INVALID",
            Self::KeyInvalid => "THRESHOLD_KEY_INVALID",
            Self::SignatureInvalid => "THRESHOLD_SIGNATURE_INVALID",
            Self::Refused { .. } => "THRESHOLD_REFUSED",
            Self::Encoding { .. } => "THRESHOLD_ENCODING",
            Self::Input { .. } => "THRESHOLD_INPUT",
        }
    }
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Params { threshold, parties } => write!(
                f,
                "{code}: {threshold}-of-{parties} is not a group shape (need 2 <= t <= n)"
            ),
            Self::Party { id, parties } => {
                write!(f, "{code}: party {id} is outside 1..={parties}")
            }
            Self::DkgPackages {
                round,
                missing,
                unexpected,
            } => write!(
                f,
                "{code}: key generation round {round}: missing packages from {missing:?}, \
                 unexpected packages from {unexpected:?}"
            ),
            Self::DkgCulprit { round, culprit } => match culprit {
                Some(id) => write!(
                    f,
                    "{code}: key generation round {round}: the package from party {id} failed verification"
                ),
                None => write!(
                    f,
                    "{code}: key generation round {round}: a package failed verification"
                ),
            },
            Self::TooFewSigners { signers, threshold } => write!(
                f,
                "{code}: {signers} signing commitments where the threshold is {threshold}"
            ),
            Self::SignerNotInSet { id } => write!(
                f,
                "{code}: party {id} has no commitment in the signing set that matches its nonces"
            ),
            Self::SharesMismatch {
                missing,
                unexpected,
            } => write!(
                f,
                "{code}: signature shares missing from {missing:?}, unexpected from {unexpected:?}"
            ),
            Self::ShareInvalid { culprits } => write!(
                f,
                "{code}: signature shares from {culprits:?} failed verification"
            ),
            Self::KeyInvalid => write!(f, "{code}: the authority key is not an x-only point"),
            Self::SignatureInvalid => write!(
                f,
                "{code}: the signature does not verify under the authority key"
            ),
            Self::Refused { reason } => write!(f, "{code}: refused by FROST: {reason}"),
            Self::Encoding { reason } => write!(f, "{code}: not a valid encoding: {reason}"),
            Self::Input { input } => write!(
                f,
                "{code}: input {input} is not an input of the transaction with its UTXO entries"
            ),
        }
    }
}

impl std::error::Error for ThresholdError {}
