// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Canonical hashlock terms encoding, version 1 (spec/V2.md section 10.2), in v1's conventions
//! (spec/ENCODING.md, "Conventions"): fixed field order, little-endian integers, 32-byte arrays as
//! they are, a kind byte before every variant, no padding and nothing after the last field. The
//! hashlock terms hold no optional field and no variable-length byte string. Decoding refuses
//! anything else, so each terms value has exactly one encoding.

use super::{
    Counterpart, CounterpartChain, HtlcError, HtlcTerms, COUNTERPART_RECORD_LEN, HTLC_TERMS_VERSION,
};
use crate::terms::{IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network, TermsError};

const NETWORK_MAINNET: u8 = 0;
const NETWORK_TESTNET: u8 = 1;

const LEG_KAS: u8 = 0;
const LEG_KCC20: u8 = 1;
const LEG_EXTERNAL: u8 = 2;

const ID_PUBKEY: u8 = 0;
const ID_SCRIPT_HASH: u8 = 1;
const ID_COVENANT_ID: u8 = 2;

pub(super) const CHAIN_SOLANA: u8 = 0x01;
pub(super) const CHAIN_OTHER_SHA256: u8 = 0x02;

pub(super) fn encode(terms: &HtlcTerms) -> Result<Vec<u8>, HtlcError> {
    if terms.version != HTLC_TERMS_VERSION {
        return Err(HtlcError::Version {
            version: terms.version,
        });
    }
    let mut out = Vec::with_capacity(512);
    out.push(terms.version);
    out.push(network_byte(terms.network));
    out.extend_from_slice(&terms.nonce.to_le_bytes());
    out.extend_from_slice(&terms.seller_key);
    out.extend_from_slice(&terms.buyer_key);
    put_leg(&mut out, &terms.asset_leg);
    put_owner(&mut out, &terms.buyer_delivery);
    put_owner(&mut out, &terms.seller_refund);
    out.extend_from_slice(&terms.hash_lock);
    out.extend_from_slice(&terms.expiry_daa.to_le_bytes());
    out.extend_from_slice(&encode_counterpart(&terms.counterpart));
    out.extend_from_slice(&terms.trade_ref);
    Ok(out)
}

pub(super) fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => NETWORK_MAINNET,
        Network::Testnet => NETWORK_TESTNET,
    }
}

pub(super) fn id_type_byte(t: IdentifierType) -> u8 {
    match t {
        IdentifierType::PubKey => ID_PUBKEY,
        IdentifierType::ScriptHash => ID_SCRIPT_HASH,
        IdentifierType::CovenantId => ID_COVENANT_ID,
    }
}

pub(super) fn id_type(value: u8) -> Option<IdentifierType> {
    match value {
        ID_PUBKEY => Some(IdentifierType::PubKey),
        ID_SCRIPT_HASH => Some(IdentifierType::ScriptHash),
        ID_COVENANT_ID => Some(IdentifierType::CovenantId),
        _ => None,
    }
}

pub(super) fn network_of(value: u8) -> Option<Network> {
    match value {
        NETWORK_MAINNET => Some(Network::Mainnet),
        NETWORK_TESTNET => Some(Network::Testnet),
        _ => None,
    }
}

fn put_leg(out: &mut Vec<u8>, leg: &Leg) {
    match &leg.kind {
        LegKind::Kas => out.push(LEG_KAS),
        LegKind::Kcc20(token) => {
            out.push(LEG_KCC20);
            out.extend_from_slice(&token.covenant_id);
            out.extend_from_slice(&token.template_hash);
            out.extend_from_slice(&token.template_prefix_len.to_le_bytes());
            out.extend_from_slice(&token.template_suffix_len.to_le_bytes());
        }
        LegKind::External => out.push(LEG_EXTERNAL),
    }
    out.extend_from_slice(&leg.amount.to_le_bytes());
}

fn put_owner(out: &mut Vec<u8>, owner: &Kcc20Owner) {
    out.push(id_type_byte(owner.identifier_type));
    out.extend_from_slice(&owner.identifier);
}

pub(super) fn encode_counterpart(c: &Counterpart) -> [u8; COUNTERPART_RECORD_LEN] {
    let mut out = Vec::with_capacity(COUNTERPART_RECORD_LEN);
    out.push(match c.chain {
        CounterpartChain::Solana => CHAIN_SOLANA,
        CounterpartChain::OtherSha256 => CHAIN_OTHER_SHA256,
    });
    out.extend_from_slice(&c.chain_id);
    out.extend_from_slice(&c.htlc_program);
    out.extend_from_slice(&c.asset);
    out.extend_from_slice(&c.amount.to_le_bytes());
    out.extend_from_slice(&c.recipient);
    out.extend_from_slice(&c.refund);
    out.extend_from_slice(&c.timeout.to_le_bytes());
    out.try_into().expect("the record has a fixed length")
}

pub(super) fn decode(bytes: &[u8]) -> Result<HtlcTerms, HtlcError> {
    let mut r = Reader { bytes, pos: 0 };
    let version = r.u8("version")?;
    if version != HTLC_TERMS_VERSION {
        return Err(HtlcError::Version { version });
    }
    let value = r.u8("network")?;
    let network = network_of(value).ok_or(TermsError::InvalidTag {
        field: "network",
        value,
    })?;
    let nonce = r.u64("nonce")?;
    let seller_key = r.array32("seller_key")?;
    let buyer_key = r.array32("buyer_key")?;
    let asset_leg = r.leg("asset_leg")?;
    let buyer_delivery = r.owner("buyer_delivery")?;
    let seller_refund = r.owner("seller_refund")?;
    let hash_lock = r.array32("hash_lock")?;
    let expiry_daa = r.u64("expiry_daa")?;
    let counterpart = r.counterpart()?;
    let trade_ref = r.array32("trade_ref")?;
    let rest = bytes.len() - r.pos;
    if rest != 0 {
        return Err(TermsError::TrailingBytes { count: rest }.into());
    }
    Ok(HtlcTerms {
        version,
        network,
        nonce,
        seller_key,
        buyer_key,
        asset_leg,
        buyer_delivery,
        seller_refund,
        hash_lock,
        expiry_daa,
        counterpart,
        trade_ref,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize, field: &'static str) -> Result<&[u8], TermsError> {
        if self.bytes.len() - self.pos < n {
            return Err(TermsError::Truncated { field });
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, TermsError> {
        Ok(self.take(1, field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, TermsError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4, field)?);
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, TermsError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8, field)?);
        Ok(u64::from_le_bytes(b))
    }

    fn array32(&mut self, field: &'static str) -> Result<[u8; 32], TermsError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32, field)?);
        Ok(b)
    }

    fn leg(&mut self, field: &'static str) -> Result<Leg, TermsError> {
        let kind = match self.u8(field)? {
            LEG_KAS => LegKind::Kas,
            LEG_KCC20 => LegKind::Kcc20(Kcc20Token {
                covenant_id: self.array32(field)?,
                template_hash: self.array32(field)?,
                template_prefix_len: self.u32(field)?,
                template_suffix_len: self.u32(field)?,
            }),
            LEG_EXTERNAL => LegKind::External,
            value => return Err(TermsError::InvalidTag { field, value }),
        };
        let amount = self.u64(field)?;
        Ok(Leg { kind, amount })
    }

    fn owner(&mut self, field: &'static str) -> Result<Kcc20Owner, TermsError> {
        let value = self.u8(field)?;
        let identifier_type = id_type(value).ok_or(TermsError::InvalidTag { field, value })?;
        Ok(Kcc20Owner {
            identifier_type,
            identifier: self.array32(field)?,
        })
    }

    fn counterpart(&mut self) -> Result<Counterpart, HtlcError> {
        let chain = match self.u8("counterpart.chain")? {
            CHAIN_SOLANA => CounterpartChain::Solana,
            CHAIN_OTHER_SHA256 => CounterpartChain::OtherSha256,
            _ => {
                return Err(HtlcError::Counterpart {
                    field: "counterpart.chain",
                })
            }
        };
        Ok(Counterpart {
            chain,
            chain_id: self.array32("counterpart.chain_id")?,
            htlc_program: self.array32("counterpart.htlc_program")?,
            asset: self.array32("counterpart.asset")?,
            amount: self.u64("counterpart.amount")?,
            recipient: self.array32("counterpart.recipient")?,
            refund: self.array32("counterpart.refund")?,
            timeout: self.u64("counterpart.timeout")?,
        })
    }
}
