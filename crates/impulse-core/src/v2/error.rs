// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! v0.2 refusals. Every variant maps to one stable code: the codes spec/V2.md section 8 appends to
//! the `TERMS_`, `TEMPLATE_`, `TX_` and `IPST_`, and `VERIFY_` families, or the v1 code whose
//! meaning applies unchanged (a wrapped `TermsError` or `TxError`, or a v1 `VERIFY_` code that a
//! v2 check raises in its v1 meaning). The codes are frozen: integrators match on `code()`, never
//! on the Display text.

use crate::terms::{Network, TermsError};
use crate::tx::TxError;
use std::fmt;

/// Why v2 terms, a v2 script, a builder's inputs, an IPST of version 2 or a v2 verification were
/// refused. Leg numbers are positions in the terms' leg list, from 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2Error {
    // TERMS_ (spec/V2.md 8.1).
    /// The terms v2 decoder or structure check was given a version other than 2.
    TermsV2Version { version: u8 },
    /// `decode_any` met a version byte that is neither 1 nor 2.
    TermsVersionUnknown { version: u8 },
    /// leg_count is below 2 or above `MAX_LEGS` (or the list is too long to encode).
    LegCount { count: usize },
    /// Every leg has the same depositor key.
    LegsOneParty,
    /// The authority key equals the depositor key of `leg`.
    AuthorityIsDepositor { leg: usize },
    /// `leg` is external; v2 legs are KAS or KCC-20 (D35).
    LegKind { leg: usize },
    /// `leg` is KCC-20 and follows a KAS leg.
    LegOrder { leg: usize },
    /// `leg` has the covenant ID of an earlier KCC-20 leg.
    LegsSameCovenant { leg: usize },
    /// lot_count is below 2, or min_lot is zero or above lot_count.
    PartialLots { lot_count: u64, min_lot: u64 },
    /// The amount of `leg` is not a multiple of lot_count.
    PartialIndivisible { leg: usize },

    // TEMPLATE_ (spec/V2.md 8.2).
    /// The embedded v2 artifact or `TEMPLATE_HASH_V2` cannot be used.
    TemplateArtifactInvalid { reason: String },
    /// The v2 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V2`.
    TemplateHashMismatch { expected: [u8; 32], found: [u8; 32] },
    /// A leg index outside 0 to leg_count - 1.
    TemplateLegIndex { value: i64, leg_count: usize },
    /// The script does not run the ImpulseVault v2 template.
    TemplateNotVault,
    /// The state does not parse as the ImpulseVault v2 state.
    TemplateStateMalformed { reason: String },
    /// A v2 state field holds a value no terms v2 value encodes to.
    TemplateStateInvalid { field: &'static str },
    /// The script is not the v2 instantiation of the terms it decodes to.
    TemplateNonCanonical,

    // TX_ and IPST_ (spec/V2.md 8.3).
    /// A vault input is not at its vault's scriptPubKey, or carries a covenant ID under terms
    /// without partial.
    NotAtVault { leg: usize },
    /// The settle is not offered exactly one vault UTXO per leg and one escrow per KCC-20 leg.
    Legs { reason: &'static str },
    /// The lots are not a whole number from 1 to what every escrow holds, are below min_lot, or
    /// leave a remainder below min_lot lots (or name a tranche on terms without partial).
    Tranche { leg: usize, reason: &'static str },
    /// Two vault UTXOs of one trade carry the same covenant ID (or another lineage fault).
    Lineage { reason: &'static str },
    /// The legs' escrows do not hold the same number of lots.
    LegsOutOfStep { leg: usize },
    /// A mass dimension exceeds its CAP_V2 cap.
    Mass {
        dimension: &'static str,
        mass: u64,
        cap: u64,
    },
    /// An IPST document whose `ipst` is neither 1 nor 2.
    IpstVersion { version: i64 },

    // VERIFY_ (spec/V2.md 8.4).
    /// The address offered for `leg` pays no leg's vault of these terms.
    AddressMismatch { leg: usize },
    /// The address or script offered for `leg` is the vault of leg `found`.
    WrongLeg { leg: usize, found: usize },
    /// The revealed script does not run the pinned v2 template.
    TemplateMismatch {
        expected: [u8; 32],
        found: Option<[u8; 32]>,
    },

    // v1 VERIFY_ codes, raised by the v2 verifier in their v1 meaning.
    /// `VERIFY_ADDRESS_MALFORMED`.
    AddressMalformed { leg: usize, reason: String },
    /// `VERIFY_ADDRESS_NETWORK`.
    AddressNetwork {
        leg: usize,
        expected: Network,
        found: String,
    },
    /// `VERIFY_ADDRESS_MISSING`.
    AddressMissing { leg: usize },
    /// `VERIFY_TERMS_MISMATCH`: the script is a vault of other terms.
    TermsMismatch,
    /// `VERIFY_NOTHING_REVEALED`.
    NothingRevealed,
    /// `VERIFY_INPUT_NOT_VAULT`.
    InputNotVault,

    /// A terms refusal whose v1 meaning applies unchanged; the code is that refusal's.
    Terms(TermsError),
    /// A builder, signature, slot or IPST refusal whose v1 meaning applies unchanged.
    Tx(TxError),
}

/// The `TERMS_` codes v0.2 appends (spec/V2.md 8.1, numbers 29 to 38), in order. Frozen once
/// merged: a test pins this list, and it may only grow at the end.
pub const TERMS_V2_ERROR_CODES: [&str; 10] = [
    "TERMS_V2_VERSION",
    "TERMS_VERSION_UNKNOWN",
    "TERMS_LEG_COUNT",
    "TERMS_LEGS_ONE_PARTY",
    "TERMS_AUTHORITY_IS_DEPOSITOR",
    "TERMS_LEG_KIND",
    "TERMS_LEG_ORDER",
    "TERMS_LEGS_SAME_COVENANT",
    "TERMS_PARTIAL_LOTS",
    "TERMS_PARTIAL_INDIVISIBLE",
];

/// The `TEMPLATE_` codes v0.2 appends (spec/V2.md 8.2, numbers 9 to 15), in order.
pub const TEMPLATE_V2_ERROR_CODES: [&str; 7] = [
    "TEMPLATE_V2_ARTIFACT_INVALID",
    "TEMPLATE_V2_HASH_MISMATCH",
    "TEMPLATE_V2_LEG_INDEX",
    "TEMPLATE_V2_NOT_VAULT",
    "TEMPLATE_V2_STATE_MALFORMED",
    "TEMPLATE_V2_STATE_INVALID",
    "TEMPLATE_V2_NONCANONICAL",
];

/// The `TX_` and `IPST_` codes v0.2 appends (spec/V2.md 8.3, numbers 26 to 32), in order.
pub const TX_V2_ERROR_CODES: [&str; 7] = [
    "TX_V2_NOT_AT_VAULT",
    "TX_LEGS",
    "TX_TRANCHE",
    "TX_LINEAGE",
    "TX_LEGS_OUT_OF_STEP",
    "TX_V2_MASS",
    "IPST_V2_VERSION",
];

/// The `VERIFY_` codes v0.2 appends (spec/V2.md 8.4, numbers 16 to 18), in order.
pub const VERIFY_V2_ERROR_CODES: [&str; 3] = [
    "VERIFY_V2_ADDRESS_MISMATCH",
    "VERIFY_V2_WRONG_LEG",
    "VERIFY_V2_TEMPLATE_MISMATCH",
];

impl V2Error {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TermsV2Version { .. } => "TERMS_V2_VERSION",
            Self::TermsVersionUnknown { .. } => "TERMS_VERSION_UNKNOWN",
            Self::LegCount { .. } => "TERMS_LEG_COUNT",
            Self::LegsOneParty => "TERMS_LEGS_ONE_PARTY",
            Self::AuthorityIsDepositor { .. } => "TERMS_AUTHORITY_IS_DEPOSITOR",
            Self::LegKind { .. } => "TERMS_LEG_KIND",
            Self::LegOrder { .. } => "TERMS_LEG_ORDER",
            Self::LegsSameCovenant { .. } => "TERMS_LEGS_SAME_COVENANT",
            Self::PartialLots { .. } => "TERMS_PARTIAL_LOTS",
            Self::PartialIndivisible { .. } => "TERMS_PARTIAL_INDIVISIBLE",
            Self::TemplateArtifactInvalid { .. } => "TEMPLATE_V2_ARTIFACT_INVALID",
            Self::TemplateHashMismatch { .. } => "TEMPLATE_V2_HASH_MISMATCH",
            Self::TemplateLegIndex { .. } => "TEMPLATE_V2_LEG_INDEX",
            Self::TemplateNotVault => "TEMPLATE_V2_NOT_VAULT",
            Self::TemplateStateMalformed { .. } => "TEMPLATE_V2_STATE_MALFORMED",
            Self::TemplateStateInvalid { .. } => "TEMPLATE_V2_STATE_INVALID",
            Self::TemplateNonCanonical => "TEMPLATE_V2_NONCANONICAL",
            Self::NotAtVault { .. } => "TX_V2_NOT_AT_VAULT",
            Self::Legs { .. } => "TX_LEGS",
            Self::Tranche { .. } => "TX_TRANCHE",
            Self::Lineage { .. } => "TX_LINEAGE",
            Self::LegsOutOfStep { .. } => "TX_LEGS_OUT_OF_STEP",
            Self::Mass { .. } => "TX_V2_MASS",
            Self::IpstVersion { .. } => "IPST_V2_VERSION",
            Self::AddressMismatch { .. } => "VERIFY_V2_ADDRESS_MISMATCH",
            Self::WrongLeg { .. } => "VERIFY_V2_WRONG_LEG",
            Self::TemplateMismatch { .. } => "VERIFY_V2_TEMPLATE_MISMATCH",
            Self::AddressMalformed { .. } => "VERIFY_ADDRESS_MALFORMED",
            Self::AddressNetwork { .. } => "VERIFY_ADDRESS_NETWORK",
            Self::AddressMissing { .. } => "VERIFY_ADDRESS_MISSING",
            Self::TermsMismatch => "VERIFY_TERMS_MISMATCH",
            Self::NothingRevealed => "VERIFY_NOTHING_REVEALED",
            Self::InputNotVault => "VERIFY_INPUT_NOT_VAULT",
            Self::Terms(e) => e.code(),
            Self::Tx(e) => e.code(),
        }
    }
}

impl From<TermsError> for V2Error {
    fn from(e: TermsError) -> Self {
        Self::Terms(e)
    }
}

impl From<TxError> for V2Error {
    fn from(e: TxError) -> Self {
        Self::Tx(e)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for V2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Terms(e) => return e.fmt(f),
            Self::Tx(e) => return e.fmt(f),
            _ => write!(f, "{code}: ")?,
        }
        match self {
            Self::TermsV2Version { version } => {
                write!(f, "terms v2 must have version 2, found {version}")
            }
            Self::TermsVersionUnknown { version } => {
                write!(f, "terms version byte {version} is neither 1 nor 2")
            }
            Self::LegCount { count } => write!(f, "{count} legs; terms v2 hold 2 to 10"),
            Self::LegsOneParty => write!(f, "every leg has the same depositor"),
            Self::AuthorityIsDepositor { leg } => {
                write!(f, "authority_key equals the depositor key of leg {leg}")
            }
            Self::LegKind { leg } => write!(f, "leg {leg} is external; v2 legs are KAS or KCC-20"),
            Self::LegOrder { leg } => write!(f, "KCC-20 leg {leg} follows a KAS leg"),
            Self::LegsSameCovenant { leg } => {
                write!(f, "leg {leg} repeats the covenant ID of an earlier leg")
            }
            Self::PartialLots { lot_count, min_lot } => write!(
                f,
                "lot_count {lot_count} and min_lot {min_lot}: lot_count is at least 2 and min_lot from 1 to lot_count"
            ),
            Self::PartialIndivisible { leg } => {
                write!(f, "the amount of leg {leg} is not a multiple of lot_count")
            }
            Self::TemplateArtifactInvalid { reason } => write!(f, "{reason}"),
            Self::TemplateHashMismatch { expected, found } => write!(
                f,
                "template hash {} where {} was expected",
                hex(found),
                hex(expected)
            ),
            Self::TemplateLegIndex { value, leg_count } => {
                write!(f, "leg index {value} with {leg_count} legs")
            }
            Self::TemplateNotVault => write!(f, "the script does not run ImpulseVault v2"),
            Self::TemplateStateMalformed { reason } => write!(f, "{reason}"),
            Self::TemplateStateInvalid { field } => {
                write!(f, "state field {field} holds a value no terms v2 value has")
            }
            Self::TemplateNonCanonical => write!(
                f,
                "the script is not the instantiation of the terms it decodes to"
            ),
            Self::NotAtVault { leg } => write!(
                f,
                "the vault input of leg {leg} is not at its vault, or carries a covenant ID the terms do not allow"
            ),
            Self::Legs { reason } => write!(f, "{reason}"),
            Self::Tranche { leg, reason } => write!(f, "leg {leg}: {reason}"),
            Self::Lineage { reason } => write!(f, "{reason}"),
            Self::LegsOutOfStep { leg } => write!(
                f,
                "the escrow of leg {leg} holds another number of lots than leg 0's"
            ),
            Self::Mass {
                dimension,
                mass,
                cap,
            } => write!(f, "{dimension} mass {mass} is above the v2 cap {cap}"),
            Self::IpstVersion { version } => write!(f, "ipst {version} is neither 1 nor 2"),
            Self::AddressMismatch { leg } => write!(
                f,
                "the address offered for leg {leg} pays no vault of these terms"
            ),
            Self::WrongLeg { leg, found } => write!(
                f,
                "what was offered as leg {leg} is the vault of leg {found}"
            ),
            Self::TemplateMismatch { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "the script runs template {}, not the pinned v2 template {}",
                    hex(found),
                    hex(expected)
                ),
                None => write!(f, "the script is shorter than the pinned v2 template"),
            },
            Self::AddressMalformed { leg, reason } => {
                write!(f, "the address offered for leg {leg}: {reason}")
            }
            Self::AddressNetwork {
                leg,
                expected,
                found,
            } => write!(
                f,
                "the address offered for leg {leg} has prefix {found}, the terms are for {expected:?}"
            ),
            Self::AddressMissing { leg } => write!(f, "no address was offered for leg {leg}"),
            Self::TermsMismatch => write!(f, "the script is a vault of other terms"),
            Self::NothingRevealed => write!(
                f,
                "the signature script is not push only or reveals no script"
            ),
            Self::InputNotVault => write!(
                f,
                "the spent UTXO is not the version 0 P2SH of the revealed script"
            ),
            Self::Terms(_) | Self::Tx(_) => unreachable!("written above"),
        }
    }
}

impl std::error::Error for V2Error {}
