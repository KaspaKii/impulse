// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Canonical terms v4 (spec/V3-ZK.md 22.2): the v1 layout of spec/ENCODING.md with the version byte
//! 0x04 and two fields appended after `funding_mode`: `blind` (32 bytes) then `trade_ref`
//! (32 bytes; in v1 `trade_ref` is the last field, here it still is). Decoding refuses every byte
//! string that is not exactly this form, so each terms value has one encoding.

use crate::{refuse, Refusal};

pub const TERMS_VERSION: u8 = 4;
/// Longest KAS destination script the encoding carries (ENCODING.md).
pub const MAX_SCRIPT_LEN: usize = 10_000;

pub const MODE_DIRECT: u8 = 0;
pub const MODE_VAULT: u8 = 1;
pub const FUNDING_REVOCABLE: u8 = 0;
pub const FUNDING_EARMARKED: u8 = 1;
pub const ID_PUBKEY: u8 = 0;
pub const ID_SCRIPT_HASH: u8 = 1;
pub const ID_COVENANT_ID: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Leg {
    Kas {
        amount: u64,
    },
    Kcc20 {
        cov: [u8; 32],
        template_hash: [u8; 32],
        prefix_len: u32,
        suffix_len: u32,
        amount: u64,
    },
    External {
        amount: u64,
    },
}

impl Leg {
    pub fn amount(&self) -> u64 {
        match self {
            Leg::Kas { amount } | Leg::Kcc20 { amount, .. } | Leg::External { amount } => *amount,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dest {
    /// A KAS scriptPubKey: version and script.
    Kas {
        version: u16,
        script: Vec<u8>,
    },
    /// A KCC-20 owner: identifier type and identifier.
    Owner {
        id_type: u8,
        id: [u8; 32],
    },
    OffChain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub network: u8,
    pub mode: u8,
    pub nonce: u64,
    pub seller: [u8; 32],
    pub buyer: [u8; 32],
    pub authority: Option<[u8; 32]>,
    pub asset: Leg,
    pub cash: Leg,
    pub buyer_delivery: Dest,
    pub seller_proceeds: Dest,
    pub seller_refund: Dest,
    pub buyer_refund: Dest,
    pub earliest: Option<u64>,
    pub expiry: u64,
    pub funding: u8,
    pub blind: [u8; 32],
    pub trade_ref: [u8; 32],
}

impl Terms {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(600);
        o.push(TERMS_VERSION);
        o.push(self.network);
        o.push(self.mode);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.seller);
        o.extend_from_slice(&self.buyer);
        match &self.authority {
            None => o.push(0),
            Some(k) => {
                o.push(1);
                o.extend_from_slice(k);
            }
        }
        put_leg(&mut o, &self.asset);
        put_leg(&mut o, &self.cash);
        for d in [
            &self.buyer_delivery,
            &self.seller_proceeds,
            &self.seller_refund,
            &self.buyer_refund,
        ] {
            put_dest(&mut o, d);
        }
        match self.earliest {
            None => o.push(0),
            Some(v) => {
                o.push(1);
                o.extend_from_slice(&v.to_le_bytes());
            }
        }
        o.extend_from_slice(&self.expiry.to_le_bytes());
        o.push(self.funding);
        o.extend_from_slice(&self.blind);
        o.extend_from_slice(&self.trade_ref);
        o
    }

    /// Decodes canonical bytes. Codes: `ZK_H_TERMS_VERSION` first, then v1's `TERMS_*`.
    pub fn decode(bytes: &[u8]) -> Result<Terms, Refusal> {
        let mut r = Reader { b: bytes, pos: 0 };
        if r.u8()? != TERMS_VERSION {
            return refuse("ZK_H_TERMS_VERSION", "H2");
        }
        let network = r.u8()?;
        if network > 1 {
            return refuse("TERMS_INVALID_TAG", "H2");
        }
        let mode = r.u8()?;
        if mode > 1 {
            return refuse("TERMS_UNKNOWN_SETTLEMENT_MODE", "H2");
        }
        let nonce = r.u64()?;
        let seller = r.a32()?;
        let buyer = r.a32()?;
        let authority = if r.presence()? { Some(r.a32()?) } else { None };
        let asset = r.leg()?;
        let cash = r.leg()?;
        let buyer_delivery = r.dest()?;
        let seller_proceeds = r.dest()?;
        let seller_refund = r.dest()?;
        let buyer_refund = r.dest()?;
        let earliest = if r.presence()? { Some(r.u64()?) } else { None };
        let expiry = r.u64()?;
        let funding = r.u8()?;
        if funding > 1 {
            return refuse("TERMS_INVALID_TAG", "H2");
        }
        let blind = r.a32()?;
        let trade_ref = r.a32()?;
        if r.pos != bytes.len() {
            return refuse("TERMS_TRAILING_BYTES", "H2");
        }
        Ok(Terms {
            network,
            mode,
            nonce,
            seller,
            buyer,
            authority,
            asset,
            cash,
            buyer_delivery,
            seller_proceeds,
            seller_refund,
            buyer_refund,
            earliest,
            expiry,
            funding,
            blind,
            trade_ref,
        })
    }
}

fn put_leg(o: &mut Vec<u8>, l: &Leg) {
    match l {
        Leg::Kas { amount } => {
            o.push(0);
            o.extend_from_slice(&amount.to_le_bytes());
        }
        Leg::Kcc20 {
            cov,
            template_hash,
            prefix_len,
            suffix_len,
            amount,
        } => {
            o.push(1);
            o.extend_from_slice(cov);
            o.extend_from_slice(template_hash);
            o.extend_from_slice(&prefix_len.to_le_bytes());
            o.extend_from_slice(&suffix_len.to_le_bytes());
            o.extend_from_slice(&amount.to_le_bytes());
        }
        Leg::External { amount } => {
            o.push(2);
            o.extend_from_slice(&amount.to_le_bytes());
        }
    }
}

fn put_dest(o: &mut Vec<u8>, d: &Dest) {
    match d {
        Dest::Kas { version, script } => {
            o.push(0);
            o.extend_from_slice(&version.to_le_bytes());
            o.extend_from_slice(&(script.len() as u32).to_le_bytes());
            o.extend_from_slice(script);
        }
        Dest::Owner { id_type, id } => {
            o.push(1);
            o.push(*id_type);
            o.extend_from_slice(id);
        }
        Dest::OffChain => o.push(2),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Refusal> {
        if self.b.len() - self.pos < n {
            return refuse("TERMS_TRUNCATED", "H2");
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Refusal> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn a32(&mut self) -> Result<[u8; 32], Refusal> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn presence(&mut self) -> Result<bool, Refusal> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => refuse("TERMS_INVALID_PRESENCE", "H2"),
        }
    }
    fn leg(&mut self) -> Result<Leg, Refusal> {
        match self.u8()? {
            0 => Ok(Leg::Kas {
                amount: self.u64()?,
            }),
            1 => Ok(Leg::Kcc20 {
                cov: self.a32()?,
                template_hash: self.a32()?,
                prefix_len: self.u32()?,
                suffix_len: self.u32()?,
                amount: self.u64()?,
            }),
            2 => Ok(Leg::External {
                amount: self.u64()?,
            }),
            _ => refuse("TERMS_INVALID_TAG", "H2"),
        }
    }
    fn dest(&mut self) -> Result<Dest, Refusal> {
        match self.u8()? {
            0 => {
                let version = self.u16()?;
                let len = self.u32()? as usize;
                if len > MAX_SCRIPT_LEN {
                    return refuse("TERMS_FIELD_TOO_LONG", "H2");
                }
                Ok(Dest::Kas {
                    version,
                    script: self.take(len)?.to_vec(),
                })
            }
            1 => {
                let id_type = self.u8()?;
                if id_type > 2 {
                    return refuse("TERMS_INVALID_TAG", "H2");
                }
                Ok(Dest::Owner {
                    id_type,
                    id: self.a32()?,
                })
            }
            2 => Ok(Dest::OffChain),
            _ => refuse("TERMS_INVALID_TAG", "H2"),
        }
    }
}
