// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms refusals. Every variant maps to one stable code (spec/ENCODING.md, "Error codes").
//! The codes are frozen: integrators match on `code()`, never on the Display text.

use super::Network;
use std::fmt;

/// Why a terms value or a terms encoding was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TermsError {
    // Decoding and encoding (canonical form).
    /// The input ended before `field` was complete.
    Truncated { field: &'static str },
    /// Bytes remain after the last field.
    TrailingBytes { count: usize },
    /// An enumeration byte holds a value with no meaning for `field`.
    InvalidTag { field: &'static str, value: u8 },
    /// A presence byte is neither 0 (absent) nor 1 (present).
    InvalidPresence { field: &'static str, value: u8 },
    /// The settlement mode byte is neither Direct nor Vault.
    UnknownSettlementMode { value: u8 },
    /// A byte string is longer than `MAX_SCRIPT_LEN`.
    FieldTooLong { field: &'static str, len: usize },
    /// The terms version is not `TERMS_VERSION`.
    UnsupportedVersion { version: u8 },

    // Structure checks (time-independent).
    /// A public key is not a valid secp256k1 point in the form `field` requires.
    InvalidKey { field: &'static str },
    /// `field` repeats the key of the other party (buyer equals seller).
    PartiesNotDistinct { field: &'static str },
    /// The authority key equals the key of `party` (seller_key or buyer_key). The contract
    /// compares keys, so one key would hold two roles: a buyer who is also the authority could
    /// release the asset of an external-cash trade unpaid.
    AuthorityIsParty { party: &'static str },
    /// The asset leg is external; only the cash leg may settle off chain.
    AssetExternal,
    /// The asset leg is a kind the v1 vault cannot escrow (KAS). KAS against a KCC-20 token is
    /// expressed by swapping buyer and seller roles (decision D13).
    AssetKindUnsupported,
    /// External cash needs a settlement authority: nobody else can attest the payment.
    ExternalWithoutAuthority,
    /// `field` holds a value Direct mode cannot carry out (external cash, earmarked funding).
    DirectIncompatible { field: &'static str },
    /// A leg amount is zero.
    AmountZero { field: &'static str },
    /// A leg amount exceeds what its kind can hold on chain.
    AmountOutOfRange {
        field: &'static str,
        amount: u64,
        max: u64,
    },
    /// Both legs are KCC-20 with the same covenant ID: one token on both sides. Each vault needs
    /// its escrow to be the only input of its leg's covenant, so such a trade could never settle.
    SameCovenant,
    /// A 32-byte identifier is all zero (an input without a covenant reports the zero covenant ID).
    ZeroIdentifier { field: &'static str },
    /// A KCC-20 template prefix or suffix length is zero, or together they exceed the script limit.
    TemplateLength {
        field: &'static str,
        prefix_len: u32,
        suffix_len: u32,
    },
    /// A destination's kind does not match its leg's kind.
    DestinationKind { field: &'static str },
    /// A KAS destination is not a standard P2PK, P2PK-ECDSA or P2SH scriptPubKey at version 0.
    NonStandardScript { field: &'static str },
    /// The expiry is not in the DAA-score lock-time domain (it would read as a timestamp).
    ExpiryNotDaa { expiry_daa: u64 },
    /// The earliest settlement score is not in the DAA-score lock-time domain.
    EarliestNotDaa { earliest_daa: u64 },
    /// `earliest_daa` is present and zero. Absent means no bound, so zero would be a second
    /// spelling of the same rule.
    EarliestZero,
    /// The earliest settlement DAA score is after the expiry.
    EarliestAfterExpiry { earliest_daa: u64, expiry_daa: u64 },

    // Creation checks (against the creator's network and DAA score).
    /// The terms name a different network from the one the caller expects.
    NetworkMismatch { expected: Network, found: Network },
    /// The expiry DAA score is not above the DAA score at creation.
    ExpiryNotAfterCreation { expiry_daa: u64, creation_daa: u64 },
    /// The expiry DAA score is further ahead than the allowed horizon.
    ExpiryBeyondHorizon {
        expiry_daa: u64,
        max_expiry_daa: u64,
    },
}

/// Every terms refusal code: the I2 codes in declaration order (decode, then check order), then
/// later additions in the order they were added. Frozen once merged: a test pins this list, and
/// it may only grow at the end.
pub const TERMS_ERROR_CODES: [&str; 28] = [
    "TERMS_TRUNCATED",
    "TERMS_TRAILING_BYTES",
    "TERMS_INVALID_TAG",
    "TERMS_INVALID_PRESENCE",
    "TERMS_UNKNOWN_SETTLEMENT_MODE",
    "TERMS_FIELD_TOO_LONG",
    "TERMS_UNSUPPORTED_VERSION",
    "TERMS_INVALID_KEY",
    "TERMS_PARTIES_NOT_DISTINCT",
    "TERMS_ASSET_EXTERNAL",
    "TERMS_ASSET_KIND_UNSUPPORTED",
    "TERMS_EXTERNAL_WITHOUT_AUTHORITY",
    "TERMS_DIRECT_INCOMPATIBLE",
    "TERMS_AMOUNT_ZERO",
    "TERMS_AMOUNT_OUT_OF_RANGE",
    "TERMS_ZERO_IDENTIFIER",
    "TERMS_TEMPLATE_LENGTH",
    "TERMS_DESTINATION_KIND",
    "TERMS_NONSTANDARD_SCRIPT",
    "TERMS_EXPIRY_NOT_DAA",
    "TERMS_EARLIEST_NOT_DAA",
    "TERMS_EARLIEST_ZERO",
    "TERMS_EARLIEST_AFTER_EXPIRY",
    "TERMS_NETWORK_MISMATCH",
    "TERMS_EXPIRY_NOT_AFTER_CREATION",
    "TERMS_EXPIRY_BEYOND_HORIZON",
    // I4.
    "TERMS_AUTHORITY_IS_PARTY",
    "TERMS_SAME_COVENANT",
];

impl TermsError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "TERMS_TRUNCATED",
            Self::TrailingBytes { .. } => "TERMS_TRAILING_BYTES",
            Self::InvalidTag { .. } => "TERMS_INVALID_TAG",
            Self::InvalidPresence { .. } => "TERMS_INVALID_PRESENCE",
            Self::UnknownSettlementMode { .. } => "TERMS_UNKNOWN_SETTLEMENT_MODE",
            Self::FieldTooLong { .. } => "TERMS_FIELD_TOO_LONG",
            Self::UnsupportedVersion { .. } => "TERMS_UNSUPPORTED_VERSION",
            Self::InvalidKey { .. } => "TERMS_INVALID_KEY",
            Self::PartiesNotDistinct { .. } => "TERMS_PARTIES_NOT_DISTINCT",
            Self::AuthorityIsParty { .. } => "TERMS_AUTHORITY_IS_PARTY",
            Self::AssetExternal => "TERMS_ASSET_EXTERNAL",
            Self::AssetKindUnsupported => "TERMS_ASSET_KIND_UNSUPPORTED",
            Self::ExternalWithoutAuthority => "TERMS_EXTERNAL_WITHOUT_AUTHORITY",
            Self::DirectIncompatible { .. } => "TERMS_DIRECT_INCOMPATIBLE",
            Self::AmountZero { .. } => "TERMS_AMOUNT_ZERO",
            Self::AmountOutOfRange { .. } => "TERMS_AMOUNT_OUT_OF_RANGE",
            Self::SameCovenant => "TERMS_SAME_COVENANT",
            Self::ZeroIdentifier { .. } => "TERMS_ZERO_IDENTIFIER",
            Self::TemplateLength { .. } => "TERMS_TEMPLATE_LENGTH",
            Self::DestinationKind { .. } => "TERMS_DESTINATION_KIND",
            Self::NonStandardScript { .. } => "TERMS_NONSTANDARD_SCRIPT",
            Self::ExpiryNotDaa { .. } => "TERMS_EXPIRY_NOT_DAA",
            Self::EarliestNotDaa { .. } => "TERMS_EARLIEST_NOT_DAA",
            Self::EarliestZero => "TERMS_EARLIEST_ZERO",
            Self::EarliestAfterExpiry { .. } => "TERMS_EARLIEST_AFTER_EXPIRY",
            Self::NetworkMismatch { .. } => "TERMS_NETWORK_MISMATCH",
            Self::ExpiryNotAfterCreation { .. } => "TERMS_EXPIRY_NOT_AFTER_CREATION",
            Self::ExpiryBeyondHorizon { .. } => "TERMS_EXPIRY_BEYOND_HORIZON",
        }
    }
}

impl fmt::Display for TermsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::Truncated { field } => write!(f, "input ends inside {field}"),
            Self::TrailingBytes { count } => write!(f, "{count} bytes after the last field"),
            Self::InvalidTag { field, value } => write!(f, "{field} has no value {value}"),
            Self::InvalidPresence { field, value } => {
                write!(f, "{field} presence byte is {value}, expected 0 or 1")
            }
            Self::UnknownSettlementMode { value } => {
                write!(
                    f,
                    "settlement_mode {value} is neither Direct (0) nor Vault (1)"
                )
            }
            Self::FieldTooLong { field, len } => write!(f, "{field} is {len} bytes long"),
            Self::UnsupportedVersion { version } => write!(f, "terms version {version}"),
            Self::InvalidKey { field } => write!(f, "{field} is not a valid public key"),
            Self::PartiesNotDistinct { field } => {
                write!(f, "{field} repeats another party's key")
            }
            Self::AuthorityIsParty { party } => {
                write!(
                    f,
                    "authority_key equals {party}; the authority must be a third key"
                )
            }
            Self::AssetExternal => write!(f, "the asset leg cannot be external"),
            Self::AssetKindUnsupported => write!(
                f,
                "the v1 asset leg must be KCC-20; for KAS against a token, swap the roles"
            ),
            Self::ExternalWithoutAuthority => {
                write!(f, "external cash needs a settlement authority")
            }
            Self::DirectIncompatible { field } => {
                write!(f, "{field} has a value Direct mode cannot carry out")
            }
            Self::AmountZero { field } => write!(f, "{field} is zero"),
            Self::AmountOutOfRange { field, amount, max } => {
                write!(f, "{field} is {amount}, above {max}")
            }
            Self::SameCovenant => write!(
                f,
                "the asset and cash legs share a covenant ID, so the trade could never settle"
            ),
            Self::ZeroIdentifier { field } => write!(f, "{field} is all zero"),
            Self::TemplateLength {
                field,
                prefix_len,
                suffix_len,
            } => write!(
                f,
                "{field} template lengths {prefix_len} and {suffix_len} are out of range"
            ),
            Self::DestinationKind { field } => {
                write!(f, "{field} does not match its leg's kind")
            }
            Self::NonStandardScript { field } => {
                write!(f, "{field} is not a standard scriptPubKey")
            }
            Self::ExpiryNotDaa { expiry_daa } => {
                write!(f, "expiry_daa {expiry_daa} is not a DAA-score lock time")
            }
            Self::EarliestNotDaa { earliest_daa } => {
                write!(
                    f,
                    "earliest_daa {earliest_daa} is not a DAA-score lock time"
                )
            }
            Self::EarliestZero => write!(f, "earliest_daa is present and zero; omit it instead"),
            Self::EarliestAfterExpiry {
                earliest_daa,
                expiry_daa,
            } => write!(
                f,
                "earliest_daa {earliest_daa} is after expiry_daa {expiry_daa}"
            ),
            Self::NetworkMismatch { expected, found } => {
                write!(f, "terms are for {found:?}, expected {expected:?}")
            }
            Self::ExpiryNotAfterCreation {
                expiry_daa,
                creation_daa,
            } => write!(
                f,
                "expiry_daa {expiry_daa} is not above creation DAA {creation_daa}"
            ),
            Self::ExpiryBeyondHorizon {
                expiry_daa,
                max_expiry_daa,
            } => write!(f, "expiry_daa {expiry_daa} is above {max_expiry_daa}"),
        }
    }
}

impl std::error::Error for TermsError {}
