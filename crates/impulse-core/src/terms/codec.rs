// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Canonical terms encoding, version 1 (spec/ENCODING.md). Fixed field order, little-endian
//! integers, an explicit presence byte for every optional field, a kind byte before every
//! variant, and a u32 length before every byte string. Decoding refuses anything else, so each
//! terms value has exactly one encoding.

use super::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, TermsError, TERMS_VERSION,
};
use kaspa_consensus_core::tx::ScriptPublicKey;

/// Longest byte string (a KAS destination script) the encoding carries. Equal to the
/// pre-Toccata consensus script size limit; a standard destination script is at most 35 bytes.
pub const MAX_SCRIPT_LEN: usize = 10_000;

const ABSENT: u8 = 0;
const PRESENT: u8 = 1;

const NETWORK_MAINNET: u8 = 0;
const NETWORK_TESTNET: u8 = 1;

const MODE_DIRECT: u8 = 0;
const MODE_VAULT: u8 = 1;

const LEG_KAS: u8 = 0;
const LEG_KCC20: u8 = 1;
const LEG_EXTERNAL: u8 = 2;

const DEST_KAS: u8 = 0;
const DEST_KCC20: u8 = 1;
const DEST_OFF_CHAIN: u8 = 2;

const ID_PUBKEY: u8 = 0;
const ID_SCRIPT_HASH: u8 = 1;
const ID_COVENANT_ID: u8 = 2;

const FUNDING_REVOCABLE: u8 = 0;
const FUNDING_EARMARKED: u8 = 1;

pub(super) fn encode(terms: &Terms) -> Result<Vec<u8>, TermsError> {
    if terms.version != TERMS_VERSION {
        return Err(TermsError::UnsupportedVersion {
            version: terms.version,
        });
    }
    let mut out = Vec::with_capacity(512);
    out.push(terms.version);
    out.push(match terms.network {
        Network::Mainnet => NETWORK_MAINNET,
        Network::Testnet => NETWORK_TESTNET,
    });
    out.push(match terms.settlement_mode {
        SettlementMode::Direct => MODE_DIRECT,
        SettlementMode::Vault => MODE_VAULT,
    });
    out.extend_from_slice(&terms.nonce.to_le_bytes());
    out.extend_from_slice(&terms.seller_key);
    out.extend_from_slice(&terms.buyer_key);
    match &terms.authority_key {
        None => out.push(ABSENT),
        Some(key) => {
            out.push(PRESENT);
            out.extend_from_slice(key);
        }
    }
    put_leg(&mut out, &terms.asset_leg);
    put_leg(&mut out, &terms.cash_leg);
    put_destination(&mut out, &terms.buyer_delivery, "buyer_delivery")?;
    put_destination(&mut out, &terms.seller_proceeds, "seller_proceeds")?;
    put_destination(&mut out, &terms.seller_refund, "seller_refund")?;
    put_destination(&mut out, &terms.buyer_refund, "buyer_refund")?;
    match terms.earliest_daa {
        None => out.push(ABSENT),
        Some(daa) => {
            out.push(PRESENT);
            out.extend_from_slice(&daa.to_le_bytes());
        }
    }
    out.extend_from_slice(&terms.expiry_daa.to_le_bytes());
    out.push(match terms.funding_mode {
        FundingMode::Revocable => FUNDING_REVOCABLE,
        FundingMode::Earmarked => FUNDING_EARMARKED,
    });
    out.extend_from_slice(&terms.trade_ref);
    Ok(out)
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

fn put_destination(
    out: &mut Vec<u8>,
    destination: &Destination,
    field: &'static str,
) -> Result<(), TermsError> {
    match destination {
        Destination::Kas(spk) => {
            let script = spk.script();
            if script.len() > MAX_SCRIPT_LEN {
                return Err(TermsError::FieldTooLong {
                    field,
                    len: script.len(),
                });
            }
            out.push(DEST_KAS);
            out.extend_from_slice(&spk.version().to_le_bytes());
            // Bounded by MAX_SCRIPT_LEN above, so the length fits a u32.
            out.extend_from_slice(&(script.len() as u32).to_le_bytes());
            out.extend_from_slice(script);
        }
        Destination::Kcc20(owner) => {
            out.push(DEST_KCC20);
            out.push(match owner.identifier_type {
                IdentifierType::PubKey => ID_PUBKEY,
                IdentifierType::ScriptHash => ID_SCRIPT_HASH,
                IdentifierType::CovenantId => ID_COVENANT_ID,
            });
            out.extend_from_slice(&owner.identifier);
        }
        Destination::OffChain => out.push(DEST_OFF_CHAIN),
    }
    Ok(())
}

pub(super) fn decode(bytes: &[u8]) -> Result<Terms, TermsError> {
    let mut r = Reader { bytes, pos: 0 };
    let version = r.u8("version")?;
    if version != TERMS_VERSION {
        return Err(TermsError::UnsupportedVersion { version });
    }
    let network = match r.u8("network")? {
        NETWORK_MAINNET => Network::Mainnet,
        NETWORK_TESTNET => Network::Testnet,
        value => {
            return Err(TermsError::InvalidTag {
                field: "network",
                value,
            })
        }
    };
    let settlement_mode = match r.u8("settlement_mode")? {
        MODE_DIRECT => SettlementMode::Direct,
        MODE_VAULT => SettlementMode::Vault,
        value => return Err(TermsError::UnknownSettlementMode { value }),
    };
    let nonce = r.u64("nonce")?;
    let seller_key = r.array32("seller_key")?;
    let buyer_key = r.array32("buyer_key")?;
    let authority_key = if r.presence("authority_key")? {
        Some(r.array32("authority_key")?)
    } else {
        None
    };
    let asset_leg = r.leg("asset_leg")?;
    let cash_leg = r.leg("cash_leg")?;
    let buyer_delivery = r.destination("buyer_delivery")?;
    let seller_proceeds = r.destination("seller_proceeds")?;
    let seller_refund = r.destination("seller_refund")?;
    let buyer_refund = r.destination("buyer_refund")?;
    let earliest_daa = if r.presence("earliest_daa")? {
        Some(r.u64("earliest_daa")?)
    } else {
        None
    };
    let expiry_daa = r.u64("expiry_daa")?;
    let funding_mode = match r.u8("funding_mode")? {
        FUNDING_REVOCABLE => FundingMode::Revocable,
        FUNDING_EARMARKED => FundingMode::Earmarked,
        value => {
            return Err(TermsError::InvalidTag {
                field: "funding_mode",
                value,
            })
        }
    };
    let trade_ref = r.array32("trade_ref")?;
    let rest = bytes.len() - r.pos;
    if rest != 0 {
        return Err(TermsError::TrailingBytes { count: rest });
    }
    Ok(Terms {
        version,
        network,
        settlement_mode,
        nonce,
        seller_key,
        buyer_key,
        authority_key,
        asset_leg,
        cash_leg,
        buyer_delivery,
        seller_proceeds,
        seller_refund,
        buyer_refund,
        earliest_daa,
        expiry_daa,
        funding_mode,
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

    fn u16(&mut self, field: &'static str) -> Result<u16, TermsError> {
        let mut b = [0u8; 2];
        b.copy_from_slice(self.take(2, field)?);
        Ok(u16::from_le_bytes(b))
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

    fn presence(&mut self, field: &'static str) -> Result<bool, TermsError> {
        match self.u8(field)? {
            ABSENT => Ok(false),
            PRESENT => Ok(true),
            value => Err(TermsError::InvalidPresence { field, value }),
        }
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

    fn destination(&mut self, field: &'static str) -> Result<Destination, TermsError> {
        match self.u8(field)? {
            DEST_KAS => {
                let version = self.u16(field)?;
                let len = self.u32(field)? as usize;
                if len > MAX_SCRIPT_LEN {
                    return Err(TermsError::FieldTooLong { field, len });
                }
                let script = self.take(len, field)?.to_vec();
                Ok(Destination::Kas(ScriptPublicKey::from_vec(version, script)))
            }
            DEST_KCC20 => {
                let identifier_type = match self.u8(field)? {
                    ID_PUBKEY => IdentifierType::PubKey,
                    ID_SCRIPT_HASH => IdentifierType::ScriptHash,
                    ID_COVENANT_ID => IdentifierType::CovenantId,
                    value => return Err(TermsError::InvalidTag { field, value }),
                };
                Ok(Destination::Kcc20(Kcc20Owner {
                    identifier_type,
                    identifier: self.array32(field)?,
                }))
            }
            DEST_OFF_CHAIN => Ok(Destination::OffChain),
            value => Err(TermsError::InvalidTag { field, value }),
        }
    }
}
