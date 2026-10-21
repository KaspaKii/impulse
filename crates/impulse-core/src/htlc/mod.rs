// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The Kaspa side of a hashlock exchange (I18, spec/V2.md section 10): hashlock terms and their
//! counterpart record, the canonical encoding and both hashes, structure and creation checks with
//! the margin rule of section 10.5, the ImpulseHashlock template (startup check, instantiation,
//! decoding), the fund, claim and refund builders, and the verifier.
//!
//! A separate module beside the v1 code, which it reuses and never changes: v1 terms, vaults,
//! builders and verifier behave exactly as before (spec/V2.md section 2).
//!
//! Keyless by rule (rule 1, docs/ENGINEERING-RULES.md): nothing here signs, holds or derives a private key. The
//! hashlock secret is not a key, but it is secret until the seller reveals it on the counterpart
//! chain: the default build never makes or stores one. The claim builder takes the preimage as
//! bytes, as the buyer reads it from the counterpart chain once it is public. The generator,
//! [`HashlockSecret`], exists only with the non-default cargo feature `htlc-secret` (D50); it
//! draws from the operating system's random source, never prints, logs or transmits the secret,
//! and erases it on drop.
//!
//! Mainnet (spec/V2.md section 10.5): the gate is lifted by the owner's answers D39 (b) and D40.
//! Creation, funding and address verification accept mainnet terms; the per-trade value cap is
//! enforced by the command line, and race R2 is disclosed. `HTLC_MAINNET_GATED` is reserved and
//! never returned.

mod codec;
mod error;
mod margin;
#[cfg(feature = "htlc-secret")]
mod secret;
mod template;
mod tx;
mod validate;
mod verify;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;

pub use error::{HtlcError, HTLC_ERROR_CODES};
pub use margin::{
    daa_rate_max, estimate as margin_estimate, pinned_daa_rate, DaaRate, DaaRateSample,
    MarginContext, MarginEstimate, DEFAULT_RETRY_SECS, FINALITY_DEPTH_DAA, MAX_SAMPLE_AGE_SECS,
    MAX_SAMPLE_GAP_SECS, MIN_DELTA_SECS, MIN_SAMPLE_MEAN_OF_TARGET, MIN_SAMPLE_SECS,
    RATE_WINDOW_SECS,
};
#[cfg(feature = "htlc-secret")]
pub use secret::HashlockSecret;
pub use template::{
    check as check_template, decode, template_hash_of_instance, FundableHtlcVault, HtlcTemplate,
    HtlcVault, CONTRACT_NAME,
};
pub use tx::{
    claim, fund, refund, HtlcIpst, HtlcIpstKind, HtlcRefundSigner, HtlcSlotParts, HtlcTermsMatch,
    CLAIM_VAULT_BUDGET, REFUND_VAULT_BUDGET,
};
pub use validate::HtlcCreationContext;
pub use verify::{
    verify_address, verify_funding, verify_revealed_script, verify_spent_input, HtlcFunding,
};

use crate::terms::{Kcc20Owner, Leg, Network, TermsError};
use sha2::{Digest, Sha256};

/// The hashlock terms encoding version: the only one this crate encodes, decodes and validates.
pub const HTLC_TERMS_VERSION: u8 = 1;

/// blake2b-256 key for the hashlock terms hash (15 bytes, spec/V2.md section 10.2).
pub const HTLC_TERMS_HASH_DOMAIN: &[u8] = b"Impulse/htlc/v1";

/// blake2b-256 key for the counterpart record hash (27 bytes, spec/V2.md section 10.2).
pub const COUNTERPART_HASH_DOMAIN: &[u8] = b"Impulse/htlc/counterpart/v1";

/// The preimage length both chains require (spec/V2.md section 10.6, R6).
pub const SECRET_LEN: usize = 32;

/// Length of the counterpart record encoding: chain 1, chain_id 32, htlc_program 32, asset 32,
/// amount 8, recipient 32, refund 32, timeout 8.
pub const COUNTERPART_RECORD_LEN: usize = 177;

/// The chain the counterpart HTLC lives on (spec/V2.md section 10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterpartChain {
    /// `0x01`.
    Solana,
    /// `0x02`: another chain with sha256 hashlocks.
    OtherSha256,
}

/// The counterpart HTLC as agreed: where it lives, what it locks and for whom, and when it times
/// out. The hash lock is the terms' own and is not repeated here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counterpart {
    pub chain: CounterpartChain,
    /// The counterpart chain's identity (for the first chain kind, the cluster's genesis hash).
    pub chain_id: [u8; 32],
    /// The HTLC program or contract identifier; a shorter identifier is left-padded with zeros.
    pub htlc_program: [u8; 32],
    /// The asset the counterpart HTLC locks (a mint or token identifier), confirmed by the
    /// owner from the issuer's own documentation at run time.
    pub asset: [u8; 32],
    /// In the counterpart asset's base units.
    pub amount: u64,
    /// The seller's account on that chain.
    pub recipient: [u8; 32],
    /// The buyer's account on that chain.
    pub refund: [u8; 32],
    /// The counterpart HTLC's timeout, unix seconds for both chain kinds (D51); above zero and at
    /// most `i64::MAX`.
    pub timeout: u64,
}

impl Counterpart {
    /// The counterpart record bytes (spec/V2.md section 10.2), 177 bytes.
    pub fn encode(&self) -> [u8; COUNTERPART_RECORD_LEN] {
        codec::encode_counterpart(self)
    }

    /// blake2b-256, keyed with `COUNTERPART_HASH_DOMAIN`, over the counterpart record.
    pub fn hash(&self) -> [u8; 32] {
        keyed_hash(COUNTERPART_HASH_DOMAIN, &self.encode())
    }
}

/// The agreed hashlock terms, field for field as spec/V2.md section 10.2. A plain value: anything
/// that decodes. Builders take [`ValidatedHtlcTerms`] instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcTerms {
    /// `HTLC_TERMS_VERSION`.
    pub version: u8,
    pub network: Network,
    pub nonce: u64,
    /// x-only key of the seller: the Kaspa asset's depositor and the secret holder (D32).
    pub seller_key: [u8; 32],
    /// x-only key of the buyer.
    pub buyer_key: [u8; 32],
    /// v1 Leg encoding; the structure checks require KCC-20.
    pub asset_leg: Leg,
    /// The KCC-20 owner the asset is delivered to on a claim.
    pub buyer_delivery: Kcc20Owner,
    /// The KCC-20 owner the asset goes home to on a refund.
    pub seller_refund: Kcc20Owner,
    /// sha256 of the 32-byte secret.
    pub hash_lock: [u8; 32],
    pub expiry_daa: u64,
    pub counterpart: Counterpart,
    pub trade_ref: [u8; 32],
}

impl HtlcTerms {
    /// Canonical bytes (spec/V2.md section 10.2). Refuses an unsupported version
    /// (`HTLC_VERSION`).
    pub fn encode(&self) -> Result<Vec<u8>, HtlcError> {
        codec::encode(self)
    }

    /// Parses canonical bytes. Any other byte string is refused, so the encoding is one to one.
    /// The result may still fail the structure checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, HtlcError> {
        codec::decode(bytes)
    }

    /// blake2b-256, keyed with `HTLC_TERMS_HASH_DOMAIN`, over the canonical bytes.
    pub fn terms_hash(&self) -> Result<[u8; 32], HtlcError> {
        Ok(keyed_hash(HTLC_TERMS_HASH_DOMAIN, &self.encode()?))
    }

    /// The contract state these terms instantiate: the terms with the counterpart record replaced
    /// by its hash (spec/V2.md section 10.2).
    pub fn state(&self) -> HtlcState {
        HtlcState {
            version: self.version,
            network: self.network,
            nonce: self.nonce,
            seller_key: self.seller_key,
            buyer_key: self.buyer_key,
            asset_leg: self.asset_leg,
            buyer_delivery: self.buyer_delivery,
            seller_refund: self.seller_refund,
            hash_lock: self.hash_lock,
            expiry_daa: self.expiry_daa,
            counterpart_hash: self.counterpart.hash(),
            trade_ref: self.trade_ref,
        }
    }

    /// The time-independent checks (spec/V2.md section 10.2, "Validation, structure"), in order,
    /// first failure returned. The only way to obtain [`ValidatedHtlcTerms`].
    pub fn validate_structure(self) -> Result<ValidatedHtlcTerms, HtlcError> {
        validate::structure(&self)?;
        let canonical = self.encode()?;
        let hash = keyed_hash(HTLC_TERMS_HASH_DOMAIN, &canonical);
        Ok(ValidatedHtlcTerms {
            terms: self,
            canonical,
            hash,
        })
    }
}

/// Hashlock terms that passed [`HtlcTerms::validate_structure`], with their canonical bytes and
/// hash. The fields are private, so a value of this type always holds checked terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedHtlcTerms {
    terms: HtlcTerms,
    canonical: Vec<u8>,
    hash: [u8; 32],
}

impl ValidatedHtlcTerms {
    /// Decodes canonical bytes and runs the structure checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, HtlcError> {
        HtlcTerms::decode(bytes)?.validate_structure()
    }

    pub fn terms(&self) -> &HtlcTerms {
        &self.terms
    }

    pub fn into_terms(self) -> HtlcTerms {
        self.terms
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn terms_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The checks that depend on when and where the terms are created (spec/V2.md section 10.2,
    /// "Creation"): v1's three (`TERMS_NETWORK_MISMATCH`, `TERMS_EXPIRY_NOT_AFTER_CREATION`,
    /// `TERMS_EXPIRY_BEYOND_HORIZON`), then the DAA rate (`HTLC_DAA_SAMPLE`) and the margin
    /// (`HTLC_TIMEOUT_MARGIN`) of section 10.5. Run when terms are made or accepted, not when an
    /// existing trade is claimed, refunded or verified after a spend.
    pub fn validate_creation(&self, ctx: &HtlcCreationContext<'_>) -> Result<(), HtlcError> {
        validate::creation(&self.terms, ctx)
    }
}

/// The ImpulseHashlock contract state (spec/V2.md section 10.2): the hashlock terms with the
/// counterpart record replaced by its hash. What a redeem script decodes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtlcState {
    pub version: u8,
    pub network: Network,
    pub nonce: u64,
    pub seller_key: [u8; 32],
    pub buyer_key: [u8; 32],
    /// Always KCC-20 in a decoded state.
    pub asset_leg: Leg,
    pub buyer_delivery: Kcc20Owner,
    pub seller_refund: Kcc20Owner,
    pub hash_lock: [u8; 32],
    pub expiry_daa: u64,
    pub counterpart_hash: [u8; 32],
    pub trade_ref: [u8; 32],
}

/// sha256 of a preimage: what `[H3]` compares with the hash lock.
pub fn sha256(preimage: &[u8]) -> [u8; 32] {
    Sha256::digest(preimage).into()
}

/// The claim's preimage check, as the contract makes it: exactly 32 bytes (`HTLC_SECRET_LENGTH`,
/// `[H2]`), and sha256 of it is the terms' hash lock (`HTLC_SECRET_MISMATCH`, `[H3]`).
pub fn check_preimage(terms: &ValidatedHtlcTerms, preimage: &[u8]) -> Result<(), HtlcError> {
    if preimage.len() != SECRET_LEN {
        return Err(HtlcError::SecretLength {
            len: preimage.len(),
        });
    }
    if sha256(preimage) != terms.terms().hash_lock {
        return Err(HtlcError::SecretMismatch);
    }
    Ok(())
}

pub(crate) fn keyed_hash(key: &[u8], message: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(key)
        .hash(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

impl From<TermsError> for HtlcError {
    fn from(e: TermsError) -> Self {
        Self::Terms(e)
    }
}
