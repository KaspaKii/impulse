// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Builder, signature and IPST refusals. Every variant maps to one stable code
//! (spec/TRANSACTIONS.md and spec/IPST.md, "Error codes"); a terms or template refusal met on the
//! way keeps its own `TERMS_*` or `TEMPLATE_*` code. Integrators match on `code()`, never on the
//! Display text.

use crate::template::TemplateError;
use crate::terms::TermsError;
use std::fmt;

/// Why a transaction was not built, a signature not accepted, or an IPST not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    /// The builder does not apply to these terms or to this leg (settlement mode, leg kind, or
    /// the shape of the legs passed in).
    WrongMode { reason: &'static str },
    /// The funding vault is not the vault the terms give for its leg.
    VaultMismatch,
    /// The trade can no longer settle by expiry_daa: the current DAA score is at or past it, or
    /// earliest_daa equals it (a settle then enters a block only after expiry). No fund, settle
    /// or Direct transaction is built for such a trade.
    Expired { current_daa: u64, expiry_daa: u64 },
    /// A vault input's UTXO is not at the vault's scriptPubKey, or carries a covenant ID.
    NotAtVault { input: &'static str },
    /// The escrowed token UTXO is not this vault's escrow (covenant, template script or state).
    EscrowMismatch { input: &'static str },
    /// A leg UTXO does not hold exactly the leg amount where the contract or the exact-amounts
    /// rule requires it.
    LegAmount {
        input: &'static str,
        expected: u64,
        found: u64,
    },
    /// The KCC-20 template is not a KCC-20 artifact, or not the one the leg names.
    TokenTemplate { reason: String },
    /// A party's own KCC-20 input cannot be spent by this builder.
    TokenInput { index: usize, reason: &'static str },
    /// A KAS input (fee, funding or Direct KAS cash) is not a version-0 P2PK Schnorr UTXO
    /// without a covenant, or there is no fee input.
    KasInput { index: usize, reason: &'static str },
    /// The same outpoint is spent twice.
    DuplicateInput { index: usize },
    /// The inputs do not cover the outputs and the fee.
    InsufficientFunds { available: u64, needed: u64 },
    /// An output the builder creates holds less than the minimum KAS for its storage class.
    BelowMinKas {
        output: usize,
        value: u64,
        minimum: u64,
    },
    /// A mass dimension exceeds the standard per-transaction cap.
    Mass {
        dimension: &'static str,
        mass: u64,
        cap: u64,
    },
    /// The fee is below the minimum relay fee for the transaction's mass.
    FeeTooLow { fee: u64, minimum: u64 },
    /// The change scriptPubKey is not a standard version-0 script.
    NonstandardChange,
    /// The refund signer role is not available for this leg.
    RefundSigner { reason: &'static str },
    /// A signature is malformed or does not verify.
    Signature {
        input: Option<usize>,
        reason: String,
    },
    /// A signature for a slot that does not exist or takes none, or a missing signature.
    SignatureSlot { input: usize, reason: &'static str },
    /// A signature script could not be encoded.
    Encoding { reason: String },
    /// Not an IPST document.
    IpstMalformed { reason: String },
    /// An IPST of another format version.
    IpstUnsupportedVersion { version: i64 },
    /// A stated sighash differs from the recomputed one.
    IpstSighashMismatch { input: usize },
    /// Two IPSTs that cannot be combined.
    IpstConflict { reason: &'static str },
    /// A UTXO the transaction spends holds zero sompi or more than the KAS supply
    /// (`MAX_SOMPI`), or the UTXOs hold more than the supply together (`input` None).
    UtxoValue { input: Option<usize>, value: u64 },
    /// The IPST is not the transaction the builders make for its terms from its own inputs.
    IpstTermsMismatch { reason: &'static str },
    /// The transaction would have more inputs than the vault template it spends allows
    /// (spec/TEMPLATE.md "Inputs outside the layout"); pay the fee from fewer,
    /// larger UTXOs.
    TooManyInputs { inputs: usize, max: usize },
    /// The terms were refused; the code is the terms code.
    Terms(TermsError),
    /// The template refused; the code is the template (or terms) code.
    Template(TemplateError),
}

/// Every transaction and IPST refusal code, in declaration order. Frozen once merged: a test
/// pins this list, and it may only grow at the end.
pub const TX_ERROR_CODES: [&str; 26] = [
    "TX_WRONG_MODE",
    "TX_VAULT_MISMATCH",
    "TX_EXPIRED",
    "TX_NOT_AT_VAULT",
    "TX_ESCROW_MISMATCH",
    "TX_LEG_AMOUNT",
    "TX_TOKEN_TEMPLATE",
    "TX_TOKEN_INPUT",
    "TX_KAS_INPUT",
    "TX_DUPLICATE_INPUT",
    "TX_INSUFFICIENT_FUNDS",
    "TX_BELOW_MIN_KAS",
    "TX_MASS",
    "TX_FEE_TOO_LOW",
    "TX_NONSTANDARD_CHANGE",
    "TX_REFUND_SIGNER",
    "TX_SIGNATURE",
    "TX_SIGNATURE_SLOT",
    "TX_ENCODING",
    "IPST_MALFORMED",
    "IPST_UNSUPPORTED_VERSION",
    "IPST_SIGHASH_MISMATCH",
    "IPST_CONFLICT",
    "TX_UTXO_VALUE",
    "IPST_TERMS_MISMATCH",
    "TX_TOO_MANY_INPUTS",
];

impl TxError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongMode { .. } => "TX_WRONG_MODE",
            Self::VaultMismatch => "TX_VAULT_MISMATCH",
            Self::Expired { .. } => "TX_EXPIRED",
            Self::NotAtVault { .. } => "TX_NOT_AT_VAULT",
            Self::EscrowMismatch { .. } => "TX_ESCROW_MISMATCH",
            Self::LegAmount { .. } => "TX_LEG_AMOUNT",
            Self::TokenTemplate { .. } => "TX_TOKEN_TEMPLATE",
            Self::TokenInput { .. } => "TX_TOKEN_INPUT",
            Self::KasInput { .. } => "TX_KAS_INPUT",
            Self::DuplicateInput { .. } => "TX_DUPLICATE_INPUT",
            Self::InsufficientFunds { .. } => "TX_INSUFFICIENT_FUNDS",
            Self::BelowMinKas { .. } => "TX_BELOW_MIN_KAS",
            Self::Mass { .. } => "TX_MASS",
            Self::FeeTooLow { .. } => "TX_FEE_TOO_LOW",
            Self::NonstandardChange => "TX_NONSTANDARD_CHANGE",
            Self::RefundSigner { .. } => "TX_REFUND_SIGNER",
            Self::Signature { .. } => "TX_SIGNATURE",
            Self::SignatureSlot { .. } => "TX_SIGNATURE_SLOT",
            Self::Encoding { .. } => "TX_ENCODING",
            Self::IpstMalformed { .. } => "IPST_MALFORMED",
            Self::IpstUnsupportedVersion { .. } => "IPST_UNSUPPORTED_VERSION",
            Self::IpstSighashMismatch { .. } => "IPST_SIGHASH_MISMATCH",
            Self::IpstConflict { .. } => "IPST_CONFLICT",
            Self::UtxoValue { .. } => "TX_UTXO_VALUE",
            Self::IpstTermsMismatch { .. } => "IPST_TERMS_MISMATCH",
            Self::TooManyInputs { .. } => "TX_TOO_MANY_INPUTS",
            Self::Terms(e) => e.code(),
            Self::Template(e) => e.code(),
        }
    }
}

impl From<TermsError> for TxError {
    fn from(e: TermsError) -> Self {
        Self::Terms(e)
    }
}

impl From<TemplateError> for TxError {
    fn from(e: TemplateError) -> Self {
        Self::Template(e)
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Terms(e) => e.fmt(f),
            Self::Template(e) => e.fmt(f),
            Self::WrongMode { reason } => write!(f, "{code}: {reason}"),
            Self::VaultMismatch => write!(
                f,
                "{code}: the funding vault is not the terms' vault for its leg"
            ),
            Self::Expired {
                current_daa,
                expiry_daa,
            } => write!(
                f,
                "{code}: at DAA score {current_daa} the trade can no longer settle by expiry_daa {expiry_daa}"
            ),
            Self::NotAtVault { input } => write!(
                f,
                "{code}: the {input} UTXO is not a plain UTXO at the vault's scriptPubKey"
            ),
            Self::EscrowMismatch { input } => write!(
                f,
                "{code}: the {input} UTXO is not the escrowed token this vault expects"
            ),
            Self::LegAmount {
                input,
                expected,
                found,
            } => write!(
                f,
                "{code}: the {input} holds {found}, the leg amount is {expected}"
            ),
            Self::TokenTemplate { reason } => write!(f, "{code}: {reason}"),
            Self::TokenInput { index, reason } => {
                write!(f, "{code}: token input {index}: {reason}")
            }
            Self::KasInput { index, reason } => write!(f, "{code}: KAS input {index}: {reason}"),
            Self::DuplicateInput { index } => {
                write!(f, "{code}: input {index} spends an outpoint already spent")
            }
            Self::InsufficientFunds { available, needed } => write!(
                f,
                "{code}: inputs hold {available} sompi, outputs and fee need {needed}"
            ),
            Self::BelowMinKas {
                output,
                value,
                minimum,
            } => write!(
                f,
                "{code}: output {output} would hold {value} sompi, the minimum is {minimum}"
            ),
            Self::Mass {
                dimension,
                mass,
                cap,
            } => write!(
                f,
                "{code}: {dimension} mass {mass} exceeds the standard cap {cap}"
            ),
            Self::FeeTooLow { fee, minimum } => write!(
                f,
                "{code}: fee {fee} sompi is below the minimum relay fee {minimum}"
            ),
            Self::NonstandardChange => write!(
                f,
                "{code}: the change scriptPubKey is not a standard version-0 script"
            ),
            Self::RefundSigner { reason } => write!(f, "{code}: {reason}"),
            Self::Signature { input, reason } => match input {
                Some(i) => write!(f, "{code}: input {i}: {reason}"),
                None => write!(f, "{code}: {reason}"),
            },
            Self::SignatureSlot { input, reason } => write!(f, "{code}: input {input}: {reason}"),
            Self::Encoding { reason } => write!(f, "{code}: {reason}"),
            Self::IpstMalformed { reason } => write!(f, "{code}: {reason}"),
            Self::IpstUnsupportedVersion { version } => {
                write!(f, "{code}: IPST version {version} is not 1")
            }
            Self::IpstSighashMismatch { input } => write!(
                f,
                "{code}: input {input}: the stated sighash is not the transaction's"
            ),
            Self::IpstConflict { reason } => write!(f, "{code}: {reason}"),
            Self::IpstTermsMismatch { reason } => write!(f, "{code}: {reason}"),
            Self::TooManyInputs { inputs, max } => write!(
                f,
                "{code}: the transaction would have {inputs} inputs; the vault template allows at most {max}"
            ),
            Self::UtxoValue { input, value } => match input {
                Some(i) => write!(
                    f,
                    "{code}: input {i} spends a UTXO of {value} sompi, outside 1 to MAX_SOMPI"
                ),
                None => write!(
                    f,
                    "{code}: the spent UTXOs hold {value} sompi together, above MAX_SOMPI"
                ),
            },
        }
    }
}

impl std::error::Error for TxError {}
