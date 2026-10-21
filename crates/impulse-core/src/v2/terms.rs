// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms v2 (spec/V2.md section 5): an ordered list of legs instead of two fixed legs, its
//! canonical encoding, the keyed hash with tag `Impulse/terms/v2`, the structure checks (the only
//! way to obtain [`ValidatedTermsV2`]) and the creation checks. Encoding conventions are v1's
//! (spec/ENCODING.md): little-endian fixed-width integers, 32-byte arrays as they are, a presence
//! byte before every optional, a kind byte before every variant, nothing after the last field.
//! Terms v2 hold no variable-length byte string. Keys here are public keys only.

use super::V2Error;
use crate::terms::{
    CreationContext, FundingMode, IdentifierType, Kcc20Token, Leg, LegKind, Network, Terms,
    TermsError, MAX_TEMPLATE_LEN, TERMS_VERSION,
};
use kaspa_consensus_core::constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI};
use secp256k1::XOnlyPublicKey;

/// The terms v2 encoding version.
pub const TERMS_V2_VERSION: u8 = 2;

/// blake2b-256 key of the terms v2 hash: the tag's 16 ASCII bytes as they are (spec/V2.md 5.1).
pub const TERMS_V2_HASH_DOMAIN: &[u8] = b"Impulse/terms/v2";

/// The most legs a v2 trade has: the template's compile-time loop bound (D29; D38 keeps 10, the
/// measured N_max under CAP_V2, docs/measurements/v2-max-n.txt).
pub const MAX_LEGS: usize = 10;

/// Bytes of one leg record in the v2 vault state (spec/V2.md 4.2).
pub const LEG_RECORD: usize = 187;

const ABSENT: u8 = 0;
const PRESENT: u8 = 1;
const NETWORK_MAINNET: u8 = 0;
const NETWORK_TESTNET: u8 = 1;
const LEG_KAS: u8 = 0;
const LEG_KCC20: u8 = 1;
const LEG_EXTERNAL: u8 = 2;
const ID_PUBKEY: u8 = 0;
const ID_SCRIPT_HASH: u8 = 1;
const ID_COVENANT_ID: u8 = 2;
const FUNDING_REVOCABLE: u8 = 0;
const FUNDING_EARMARKED: u8 = 1;

/// Destination v2: an identifier type and a 32-byte identifier. For a KCC-20 leg it is a KCC-20
/// owner (PUBKEY, SCRIPT_HASH, COVENANT_ID, as kcc20.sil). For a KAS leg, `PubKey` is a Schnorr
/// P2PK of the x-only key and `ScriptHash` a P2SH of the script hash; `CovenantId` decodes and is
/// refused by the structure checks (`TERMS_DESTINATION_KIND`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationV2 {
    pub identifier_type: IdentifierType,
    pub identifier: [u8; 32],
}

/// One leg: who deposits it, what it moves (v1's leg encoding), where it is delivered on settle,
/// and where it goes home on refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegV2 {
    /// x-only Schnorr public key of the depositor.
    pub depositor_key: [u8; 32],
    pub asset: Leg,
    pub delivery: DestinationV2,
    pub refund: DestinationV2,
}

/// Partial settlement (I17): present means `partial_allowed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partial {
    pub lot_count: u64,
    pub min_lot: u64,
}

/// The agreed terms of one v2 trade, field for field as spec/V2.md 5.2. A plain value: anything
/// that decodes. Builders take [`ValidatedTermsV2`] instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermsV2 {
    /// `TERMS_V2_VERSION`.
    pub version: u8,
    pub network: Network,
    pub nonce: u64,
    /// x-only Schnorr public key of the settlement authority; absent means self-settling.
    pub authority_key: Option<[u8; 32]>,
    /// The legs, in terms order; leg_count is their number.
    pub legs: Vec<LegV2>,
    pub earliest_daa: Option<u64>,
    pub expiry_daa: u64,
    pub funding_mode: FundingMode,
    pub partial: Option<Partial>,
    pub trade_ref: [u8; 32],
}

impl TermsV2 {
    /// Canonical bytes (spec/V2.md 5.2). Refuses a version other than 2 and a list longer than
    /// the u8 leg_count holds.
    pub fn encode(&self) -> Result<Vec<u8>, V2Error> {
        encode(self)
    }

    /// Parses canonical bytes. Any other byte string is refused, so encoding is one to one. The
    /// result may still fail validation; its hash is defined all the same.
    pub fn decode(bytes: &[u8]) -> Result<Self, V2Error> {
        decode(bytes)
    }

    /// blake2b-256, keyed with `TERMS_V2_HASH_DOMAIN`, over the canonical bytes.
    pub fn terms_hash(&self) -> Result<[u8; 32], V2Error> {
        Ok(hash_canonical(&self.encode()?))
    }

    /// The structure checks of spec/V2.md 5.3, in order, first failure returned. The only way
    /// to obtain [`ValidatedTermsV2`]. Terms past their expiry still pass.
    pub fn validate_structure(self) -> Result<ValidatedTermsV2, V2Error> {
        structure(&self)?;
        let canonical = self.encode()?;
        let hash = hash_canonical(&canonical);
        Ok(ValidatedTermsV2 {
            terms: self,
            canonical,
            hash,
        })
    }

    /// The number of KCC-20 legs (K). Validated terms put them first.
    pub fn kcc20_legs(&self) -> usize {
        self.legs
            .iter()
            .filter(|l| matches!(l.asset.kind, LegKind::Kcc20(_)))
            .count()
    }

    /// The amount of one lot of `leg`: the amount over lot_count, or the whole amount without
    /// partial.
    pub fn unit(&self, leg: usize) -> u64 {
        let lots = self.partial.map_or(1, |p| p.lot_count.max(1));
        self.legs[leg].asset.amount / lots
    }
}

/// Terms v2 that passed [`TermsV2::validate_structure`]. The fields are private, so a value of
/// this type always holds checked terms with their canonical bytes and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTermsV2 {
    terms: TermsV2,
    canonical: Vec<u8>,
    hash: [u8; 32],
}

impl ValidatedTermsV2 {
    /// Decodes canonical bytes and runs the structure checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, V2Error> {
        TermsV2::decode(bytes)?.validate_structure()
    }

    pub fn terms(&self) -> &TermsV2 {
        &self.terms
    }

    pub fn into_terms(self) -> TermsV2 {
        self.terms
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn terms_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The creation checks, v1's unchanged in order and codes (`TERMS_NETWORK_MISMATCH`,
    /// `TERMS_EXPIRY_NOT_AFTER_CREATION`, `TERMS_EXPIRY_BEYOND_HORIZON`).
    pub fn validate_creation(&self, ctx: &CreationContext) -> Result<(), V2Error> {
        let t = &self.terms;
        if t.network != ctx.network {
            return Err(TermsError::NetworkMismatch {
                expected: ctx.network,
                found: t.network,
            }
            .into());
        }
        if t.expiry_daa <= ctx.creation_daa {
            return Err(TermsError::ExpiryNotAfterCreation {
                expiry_daa: t.expiry_daa,
                creation_daa: ctx.creation_daa,
            }
            .into());
        }
        let max_expiry_daa = ctx.creation_daa.saturating_add(ctx.max_expiry_horizon_daa);
        if t.expiry_daa > max_expiry_daa {
            return Err(TermsError::ExpiryBeyondHorizon {
                expiry_daa: t.expiry_daa,
                max_expiry_daa,
            }
            .into());
        }
        Ok(())
    }
}

/// Terms of either version, as [`decode_any`] reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyTerms {
    V1(Box<Terms>),
    V2(TermsV2),
}

/// Reads the version byte and calls the v1 or the v2 decoder (spec/V2.md 5.2). Empty input is
/// `TERMS_TRUNCATED`; a version byte that is neither 1 nor 2 is `TERMS_VERSION_UNKNOWN`.
pub fn decode_any(bytes: &[u8]) -> Result<AnyTerms, V2Error> {
    match bytes.first() {
        None => Err(TermsError::Truncated { field: "version" }.into()),
        Some(&TERMS_VERSION) => Ok(AnyTerms::V1(Box::new(Terms::decode(bytes)?))),
        Some(&TERMS_V2_VERSION) => Ok(AnyTerms::V2(TermsV2::decode(bytes)?)),
        Some(&version) => Err(V2Error::TermsVersionUnknown { version }),
    }
}

pub(super) fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(TERMS_V2_HASH_DOMAIN)
        .hash(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

// =============================================================================================
// Codec
// =============================================================================================

fn id_byte(t: IdentifierType) -> u8 {
    match t {
        IdentifierType::PubKey => ID_PUBKEY,
        IdentifierType::ScriptHash => ID_SCRIPT_HASH,
        IdentifierType::CovenantId => ID_COVENANT_ID,
    }
}

fn encode(t: &TermsV2) -> Result<Vec<u8>, V2Error> {
    if t.version != TERMS_V2_VERSION {
        return Err(V2Error::TermsV2Version { version: t.version });
    }
    let count = u8::try_from(t.legs.len()).map_err(|_| V2Error::LegCount {
        count: t.legs.len(),
    })?;
    let mut out = Vec::with_capacity(64 + 179 * t.legs.len());
    out.push(t.version);
    out.push(match t.network {
        Network::Mainnet => NETWORK_MAINNET,
        Network::Testnet => NETWORK_TESTNET,
    });
    out.extend_from_slice(&t.nonce.to_le_bytes());
    match &t.authority_key {
        None => out.push(ABSENT),
        Some(key) => {
            out.push(PRESENT);
            out.extend_from_slice(key);
        }
    }
    out.push(count);
    for leg in &t.legs {
        out.extend_from_slice(&leg.depositor_key);
        match &leg.asset.kind {
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
        out.extend_from_slice(&leg.asset.amount.to_le_bytes());
        for d in [&leg.delivery, &leg.refund] {
            out.push(id_byte(d.identifier_type));
            out.extend_from_slice(&d.identifier);
        }
    }
    match t.earliest_daa {
        None => out.push(ABSENT),
        Some(daa) => {
            out.push(PRESENT);
            out.extend_from_slice(&daa.to_le_bytes());
        }
    }
    out.extend_from_slice(&t.expiry_daa.to_le_bytes());
    out.push(match t.funding_mode {
        FundingMode::Revocable => FUNDING_REVOCABLE,
        FundingMode::Earmarked => FUNDING_EARMARKED,
    });
    match t.partial {
        None => out.push(ABSENT),
        Some(p) => {
            out.push(PRESENT);
            out.extend_from_slice(&p.lot_count.to_le_bytes());
            out.extend_from_slice(&p.min_lot.to_le_bytes());
        }
    }
    out.extend_from_slice(&t.trade_ref);
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<TermsV2, V2Error> {
    let mut r = Reader { bytes, pos: 0 };
    let version = r.u8("version")?;
    if version != TERMS_V2_VERSION {
        return Err(V2Error::TermsV2Version { version });
    }
    let network = match r.u8("network")? {
        NETWORK_MAINNET => Network::Mainnet,
        NETWORK_TESTNET => Network::Testnet,
        value => {
            return Err(TermsError::InvalidTag {
                field: "network",
                value,
            }
            .into())
        }
    };
    let nonce = r.u64("nonce")?;
    let authority_key = if r.presence("authority_key")? {
        Some(r.array32("authority_key")?)
    } else {
        None
    };
    let count = r.u8("leg_count")?;
    let mut legs = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        legs.push(r.leg()?);
    }
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
            }
            .into())
        }
    };
    let partial = if r.presence("partial")? {
        Some(Partial {
            lot_count: r.u64("partial.lot_count")?,
            min_lot: r.u64("partial.min_lot")?,
        })
    } else {
        None
    };
    let trade_ref = r.array32("trade_ref")?;
    let rest = bytes.len() - r.pos;
    if rest != 0 {
        return Err(TermsError::TrailingBytes { count: rest }.into());
    }
    Ok(TermsV2 {
        version,
        network,
        nonce,
        authority_key,
        legs,
        earliest_daa,
        expiry_daa,
        funding_mode,
        partial,
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

    fn presence(&mut self, field: &'static str) -> Result<bool, TermsError> {
        match self.u8(field)? {
            ABSENT => Ok(false),
            PRESENT => Ok(true),
            value => Err(TermsError::InvalidPresence { field, value }),
        }
    }

    fn leg(&mut self) -> Result<LegV2, TermsError> {
        let depositor_key = self.array32("legs.depositor_key")?;
        let field = "legs.asset";
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
        Ok(LegV2 {
            depositor_key,
            asset: Leg { kind, amount },
            delivery: self.destination("legs.delivery")?,
            refund: self.destination("legs.refund")?,
        })
    }

    fn destination(&mut self, field: &'static str) -> Result<DestinationV2, TermsError> {
        let identifier_type = match self.u8(field)? {
            ID_PUBKEY => IdentifierType::PubKey,
            ID_SCRIPT_HASH => IdentifierType::ScriptHash,
            ID_COVENANT_ID => IdentifierType::CovenantId,
            value => return Err(TermsError::InvalidTag { field, value }),
        };
        Ok(DestinationV2 {
            identifier_type,
            identifier: self.array32(field)?,
        })
    }
}

// =============================================================================================
// Structure checks (spec/V2.md 5.3), in order, first failure returned
// =============================================================================================

fn structure(t: &TermsV2) -> Result<(), V2Error> {
    // 1. Version.
    if t.version != TERMS_V2_VERSION {
        return Err(V2Error::TermsV2Version { version: t.version });
    }
    // 2. leg_count.
    let n = t.legs.len();
    if !(2..=MAX_LEGS).contains(&n) {
        return Err(V2Error::LegCount { count: n });
    }
    // 3. Keys: each depositor in leg order, then the authority.
    for leg in &t.legs {
        xonly(&leg.depositor_key, "legs.depositor_key")?;
    }
    if let Some(authority) = &t.authority_key {
        xonly(authority, "authority_key")?;
    }
    // 4. At least two parties; the authority is none of them.
    if t.legs
        .iter()
        .all(|l| l.depositor_key == t.legs[0].depositor_key)
    {
        return Err(V2Error::LegsOneParty);
    }
    if let Some(authority) = &t.authority_key {
        if let Some(leg) = t.legs.iter().position(|l| l.depositor_key == *authority) {
            return Err(V2Error::AuthorityIsDepositor { leg });
        }
    }
    // 5. Leg kinds, then KCC-20 legs first.
    if let Some(leg) = t
        .legs
        .iter()
        .position(|l| l.asset.kind == LegKind::External)
    {
        return Err(V2Error::LegKind { leg });
    }
    let mut seen_kas = false;
    for (leg, l) in t.legs.iter().enumerate() {
        match l.asset.kind {
            LegKind::Kas => seen_kas = true,
            LegKind::Kcc20(_) if seen_kas => return Err(V2Error::LegOrder { leg }),
            _ => {}
        }
    }
    // 6. Amounts and tokens, each leg in order; then distinct covenants.
    for l in &t.legs {
        let max = match l.asset.kind {
            LegKind::Kas => MAX_SOMPI,
            _ => i64::MAX as u64,
        };
        let field = "legs.asset.amount";
        if l.asset.amount == 0 {
            return Err(TermsError::AmountZero { field }.into());
        }
        if l.asset.amount > max {
            return Err(TermsError::AmountOutOfRange {
                field,
                amount: l.asset.amount,
                max,
            }
            .into());
        }
        if let LegKind::Kcc20(token) = &l.asset.kind {
            nonzero(&token.covenant_id, "legs.asset.covenant_id")?;
            nonzero(&token.template_hash, "legs.asset.template_hash")?;
            let (prefix_len, suffix_len) = (token.template_prefix_len, token.template_suffix_len);
            if prefix_len == 0
                || suffix_len == 0
                || u64::from(prefix_len) + u64::from(suffix_len) > MAX_TEMPLATE_LEN
            {
                return Err(TermsError::TemplateLength {
                    field: "legs.asset.template",
                    prefix_len,
                    suffix_len,
                }
                .into());
            }
        }
    }
    for (leg, l) in t.legs.iter().enumerate() {
        if let LegKind::Kcc20(token) = &l.asset.kind {
            let repeated = t.legs[..leg].iter().any(
                |e| matches!(&e.asset.kind, LegKind::Kcc20(o) if o.covenant_id == token.covenant_id),
            );
            if repeated {
                return Err(V2Error::LegsSameCovenant { leg });
            }
        }
    }
    // 7. Destinations: each leg's delivery, then its refund.
    for l in &t.legs {
        destination(l, &l.delivery, "legs.delivery")?;
        destination(l, &l.refund, "legs.refund")?;
    }
    // 8. DAA scores.
    if t.expiry_daa >= LOCK_TIME_THRESHOLD {
        return Err(TermsError::ExpiryNotDaa {
            expiry_daa: t.expiry_daa,
        }
        .into());
    }
    if let Some(earliest_daa) = t.earliest_daa {
        if earliest_daa >= LOCK_TIME_THRESHOLD {
            return Err(TermsError::EarliestNotDaa { earliest_daa }.into());
        }
        if earliest_daa == 0 {
            return Err(TermsError::EarliestZero.into());
        }
        if earliest_daa > t.expiry_daa {
            return Err(TermsError::EarliestAfterExpiry {
                earliest_daa,
                expiry_daa: t.expiry_daa,
            }
            .into());
        }
    }
    // 9. Partial.
    if let Some(p) = t.partial {
        if p.lot_count < 2 || p.min_lot == 0 || p.min_lot > p.lot_count {
            return Err(V2Error::PartialLots {
                lot_count: p.lot_count,
                min_lot: p.min_lot,
            });
        }
        if let Some(leg) = t
            .legs
            .iter()
            .position(|l| !l.asset.amount.is_multiple_of(p.lot_count))
        {
            return Err(V2Error::PartialIndivisible { leg });
        }
    }
    Ok(())
}

fn destination(leg: &LegV2, d: &DestinationV2, field: &'static str) -> Result<(), V2Error> {
    if leg.asset.kind == LegKind::Kas && d.identifier_type == IdentifierType::CovenantId {
        return Err(TermsError::DestinationKind { field }.into());
    }
    nonzero(&d.identifier, field)?;
    if d.identifier_type == IdentifierType::PubKey {
        xonly(&d.identifier, field)?;
    }
    Ok(())
}

fn xonly(bytes: &[u8; 32], field: &'static str) -> Result<(), V2Error> {
    XOnlyPublicKey::from_slice(bytes)
        .map(|_| ())
        .map_err(|_| TermsError::InvalidKey { field }.into())
}

fn nonzero(bytes: &[u8; 32], field: &'static str) -> Result<(), V2Error> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(TermsError::ZeroIdentifier { field }.into());
    }
    Ok(())
}
