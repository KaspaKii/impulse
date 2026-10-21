// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Trade terms: the schema of spec/IMPULSE-SPEC.md "Terms", its canonical encoding and
//! terms hash (spec/ENCODING.md), and validation. Keys here are public keys only.

mod codec;
mod error;
mod validate;

#[cfg(test)]
pub(crate) mod golden;
#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

pub use codec::MAX_SCRIPT_LEN;
pub use error::{TermsError, TERMS_ERROR_CODES};
pub use validate::{CreationContext, DEFAULT_MAX_EXPIRY_HORIZON_DAA, MAX_TEMPLATE_LEN};

use kaspa_consensus_core::tx::ScriptPublicKey;

/// The terms encoding version: the only one this crate encodes, decodes and validates.
pub const TERMS_VERSION: u8 = 1;

/// blake2b-256 key for the terms hash.
pub const TERMS_HASH_DOMAIN: &[u8] = b"Impulse/terms/v1";

/// The Kaspa network a trade settles on. Testnet covers every testnet suffix (TN10 and others).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// How the trade settles. The vault sub-modes (authority, self-settling, external cash) are not
/// a separate field: they follow from `authority_key` and the cash leg's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementMode {
    /// No escrow: both parties sign one transaction that spends their own UTXOs.
    Direct,
    /// Each on-chain leg is escrowed in its own ImpulseVault.
    Vault,
}

/// Whether a depositor may withdraw before expiry. Vault only; Direct terms are revocable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingMode {
    /// The depositor may refund at any time.
    Revocable,
    /// The depositor may refund only from `expiry_daa`; counterparty and authority at any time.
    Earmarked,
}

/// The KCC-20 token a leg moves: its covenant ID and the template its UTXOs run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc20Token {
    pub covenant_id: [u8; 32],
    pub template_hash: [u8; 32],
    /// Template bytes before the state span.
    pub template_prefix_len: u32,
    /// Template bytes after the state span.
    pub template_suffix_len: u32,
}

/// What a leg moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegKind {
    /// Native KAS; the amount is in sompi.
    Kas,
    /// A KCC-20 token; the amount is in token units.
    Kcc20(Kcc20Token),
    /// Cash paid outside Kaspa (cash leg only); the amount is opaque to Impulse.
    External,
}

/// One side of the exchange: the asset leg (seller delivers) or the cash leg (buyer pays).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    pub kind: LegKind,
    pub amount: u64,
}

/// KCC-20 owner identifier type, as kcc20.sil defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierType {
    PubKey,
    ScriptHash,
    CovenantId,
}

/// A KCC-20 owner: identifier type and 32-byte identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc20Owner {
    pub identifier_type: IdentifierType,
    pub identifier: [u8; 32],
}

/// Where a leg lands. The kind must match the leg: KAS to a scriptPubKey, KCC-20 to an owner,
/// external cash to no on-chain destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Kas(ScriptPublicKey),
    Kcc20(Kcc20Owner),
    OffChain,
}

/// The agreed terms of one trade, field for field as the spec's terms table. A plain value:
/// anything that decodes. Builders take [`ValidatedTerms`] instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// Terms encoding version, `TERMS_VERSION`.
    pub version: u8,
    pub network: Network,
    pub settlement_mode: SettlementMode,
    pub nonce: u64,
    /// x-only Schnorr public key.
    pub seller_key: [u8; 32],
    /// x-only Schnorr public key.
    pub buyer_key: [u8; 32],
    /// x-only Schnorr public key of the settlement authority; absent means self-settling.
    pub authority_key: Option<[u8; 32]>,
    pub asset_leg: Leg,
    pub cash_leg: Leg,
    pub buyer_delivery: Destination,
    pub seller_proceeds: Destination,
    pub seller_refund: Destination,
    pub buyer_refund: Destination,
    pub earliest_daa: Option<u64>,
    pub expiry_daa: u64,
    pub funding_mode: FundingMode,
    pub trade_ref: [u8; 32],
}

impl Terms {
    /// Canonical bytes (spec/ENCODING.md). Refuses an unsupported version or an over-long script.
    pub fn encode(&self) -> Result<Vec<u8>, TermsError> {
        codec::encode(self)
    }

    /// Parses canonical bytes. Any other byte string is refused, so encoding is one to one.
    /// The result may still fail validation; its hash is defined all the same.
    pub fn decode(bytes: &[u8]) -> Result<Self, TermsError> {
        codec::decode(bytes)
    }

    /// blake2b-256, keyed with `TERMS_HASH_DOMAIN`, over the canonical bytes.
    pub fn terms_hash(&self) -> Result<[u8; 32], TermsError> {
        Ok(hash_canonical(&self.encode()?))
    }

    /// The time-independent checks (spec/ENCODING.md, "Structure checks"). Mandatory: this is
    /// the only way to obtain [`ValidatedTerms`]. Terms past their expiry still pass.
    pub fn validate_structure(self) -> Result<ValidatedTerms, TermsError> {
        validate::structure(&self)?;
        let canonical = self.encode()?;
        let hash = hash_canonical(&canonical);
        Ok(ValidatedTerms {
            terms: self,
            canonical,
            hash,
        })
    }
}

/// Terms that passed [`Terms::validate_structure`]. The fields are private, so a value of this
/// type always holds checked terms with their canonical bytes and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTerms {
    terms: Terms,
    canonical: Vec<u8>,
    hash: [u8; 32],
}

impl ValidatedTerms {
    /// Decodes canonical bytes and runs the structure checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, TermsError> {
        Terms::decode(bytes)?.validate_structure()
    }

    pub fn terms(&self) -> &Terms {
        &self.terms
    }

    pub fn into_terms(self) -> Terms {
        self.terms
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn terms_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The checks that depend on when and where the terms are created: network, expiry after
    /// creation and within the horizon (spec/ENCODING.md, "Creation checks"). Run when terms are
    /// made or accepted, not when an existing trade is settled, refunded or verified.
    pub fn validate_creation(&self, ctx: &CreationContext) -> Result<(), TermsError> {
        validate::creation(&self.terms, ctx)
    }
}

fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(TERMS_HASH_DOMAIN)
        .hash(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}
