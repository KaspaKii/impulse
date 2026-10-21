// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The linked receipt (spec/V2.md 17.8): what a node showed about the settle of one trade of a
//! sheet, naming the sheet's hash and the leg trade's own terms hash, so that the receipts of an
//! opening and a return both link to one terms hash. Canonical bytes, the digest and the checks
//! live here; the signature is made by the command line's signing module (this crate holds no
//! key) and verified here against the signer's public key.
//!
//! As the version 1 receipt, it is the signer's assertion that a transaction was accepted at a
//! block. It does not bind the transaction to the vaults.

use super::{LinkedError, Role, ValidatedLinked};
use crate::terms::Network;
use secp256k1::{schnorr, Message, XOnlyPublicKey, SECP256K1};

/// The linked receipt format version.
pub const LINKED_RECEIPT_VERSION: u8 = 1;

/// blake2b-256 key of the linked receipt digest: the tag's 25 ASCII bytes as they are. Not the
/// transaction sighash key and not the version 1 receipt key.
pub const LINKED_RECEIPT_DOMAIN: &[u8] = b"Impulse/receipt/linked/v1";

/// Bytes of the canonical form.
pub const LINKED_RECEIPT_LEN: usize = 147;

/// What a node showed about one transaction of a linked trade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkedObservation {
    pub network: Network,
    pub role: Role,
    pub linked_hash: [u8; 32],
    /// The terms v2 hash of the settled leg trade.
    pub leg_terms_hash: [u8; 32],
    pub txid: [u8; 32],
    pub accepting_block: [u8; 32],
    pub daa_score: u64,
    pub depth: u64,
}

impl LinkedObservation {
    /// version, network, role, linked_hash, leg_terms_hash, txid, accepting_block, daa_score LE,
    /// depth LE: 147 bytes.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LINKED_RECEIPT_LEN);
        out.push(LINKED_RECEIPT_VERSION);
        out.push(match self.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        });
        out.push(match self.role {
            Role::Opening => 0,
            Role::Return => 1,
        });
        out.extend_from_slice(&self.linked_hash);
        out.extend_from_slice(&self.leg_terms_hash);
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.accepting_block);
        out.extend_from_slice(&self.daa_score.to_le_bytes());
        out.extend_from_slice(&self.depth.to_le_bytes());
        out
    }

    /// The 32 bytes the signer signs.
    pub fn digest(&self) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .key(LINKED_RECEIPT_DOMAIN)
            .hash(&self.canonical());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// The observation is of `role`'s trade of `linked`'s sheet, on the sheet's network
    /// (`LINKED_RECEIPT_TERMS`).
    pub fn check_against(&self, linked: &ValidatedLinked) -> Result<(), LinkedError> {
        let terms = |reason| Err(LinkedError::ReceiptTerms { reason });
        if self.network != linked.sheet().opening.network {
            return terms("the receipt is for another network than the sheet");
        }
        if self.linked_hash != linked.linked_hash() {
            return terms("the receipt names another sheet");
        }
        if self.leg_terms_hash != linked.terms_hash(self.role) {
            return terms(
                "the receipt's leg terms hash is not the sheet's derived hash for its role",
            );
        }
        Ok(())
    }
}

/// A signed observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkedReceipt {
    pub observation: LinkedObservation,
    /// x-only public key of the signer.
    pub signer: [u8; 32],
    /// BIP-340 signature over the observation's digest.
    pub signature: [u8; 64],
}

impl LinkedReceipt {
    /// The signature verifies over the digest for `signer`. `Err` carries the reason; the command
    /// line maps it to `RECEIPT_SIGNATURE_INVALID`.
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        let key = XOnlyPublicKey::from_slice(&self.signer)
            .map_err(|_| "signer is not a valid x-only public key")?;
        let sig = schnorr::Signature::from_slice(&self.signature)
            .map_err(|_| "signature is malformed")?;
        SECP256K1
            .verify_schnorr(&sig, &Message::from_digest(self.observation.digest()), &key)
            .map_err(|_| "the signature does not verify for signer")
    }
}

/// An opening receipt and a return receipt are one linked trade's pair (`LINKED_RECEIPT_PAIR`):
/// the same sheet and network, roles opening then return, distinct transactions, and the return
/// accepted at a higher DAA score than the opening.
pub fn check_pair(opening: &LinkedObservation, ret: &LinkedObservation) -> Result<(), LinkedError> {
    let pair = |reason| Err(LinkedError::ReceiptPair { reason });
    if opening.role != Role::Opening || ret.role != Role::Return {
        return pair("the receipts are not an opening receipt then a return receipt");
    }
    if opening.network != ret.network {
        return pair("the receipts are for different networks");
    }
    if opening.linked_hash != ret.linked_hash {
        return pair("the receipts name different sheets");
    }
    if opening.txid == ret.txid {
        return pair("the receipts name one transaction");
    }
    if ret.daa_score <= opening.daa_score {
        return pair("the return was not accepted after the opening");
    }
    Ok(())
}
