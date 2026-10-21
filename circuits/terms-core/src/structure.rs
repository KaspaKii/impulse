// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Structure checks of terms v4 (spec/V3-ZK.md 22.2): v1's checks in v1's order with v1's codes
//! (spec/ENCODING.md, "Structure checks"), then the three of v4. Time-independent. The version byte
//! was checked first, by the decoder (`ZK_H_TERMS_VERSION`).

use crate::codec::*;
use crate::{refuse, Refusal};

/// 29,000,000,000 KAS in sompi (kaspa-consensus-core `MAX_SOMPI`).
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
/// Post-Toccata script size limit: bound on a template's prefix plus suffix.
pub const MAX_TEMPLATE_LEN: u64 = 1_000_000;

/// Whether a 32-byte string is the x coordinate of a point on secp256k1 (BIP-340 x-only).
pub fn xonly_valid(x: &[u8]) -> bool {
    if x.len() != 32 {
        return false;
    }
    let mut c = [0u8; 33];
    c[0] = 2;
    c[1..].copy_from_slice(x);
    k256::PublicKey::from_sec1_bytes(&c).is_ok()
}

fn compressed_valid(k: &[u8]) -> bool {
    k256::PublicKey::from_sec1_bytes(k).is_ok()
}

fn zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

const H2: &str = "H2";

fn fail<T>(code: &'static str) -> Result<T, Refusal> {
    refuse(code, H2)
}

/// Runs the structure checks. `curves` false skips the on-curve tests of public keys (every other
/// check runs): the differential test against v1 uses fixture keys that are not points.
pub fn validate(t: &Terms, curves: bool) -> Result<(), Refusal> {
    let key = |k: &[u8]| !curves || xonly_valid(k);
    if !key(&t.seller) || !key(&t.buyer) {
        return fail("TERMS_INVALID_KEY");
    }
    if let Some(a) = &t.authority {
        if !key(a) {
            return fail("TERMS_INVALID_KEY");
        }
    }
    if t.buyer == t.seller {
        return fail("TERMS_PARTIES_NOT_DISTINCT");
    }
    if let Some(a) = &t.authority {
        if *a == t.seller || *a == t.buyer {
            return fail("TERMS_AUTHORITY_IS_PARTY");
        }
    }
    match &t.asset {
        Leg::External { .. } => return fail("TERMS_ASSET_EXTERNAL"),
        Leg::Kas { .. } => return fail("TERMS_ASSET_KIND_UNSUPPORTED"),
        Leg::Kcc20 { .. } => {}
    }
    if matches!(t.cash, Leg::External { .. }) && t.authority.is_none() {
        return fail("TERMS_EXTERNAL_WITHOUT_AUTHORITY");
    }
    if t.mode == MODE_DIRECT
        && (matches!(t.cash, Leg::External { .. }) || t.funding == FUNDING_EARMARKED)
    {
        return fail("TERMS_DIRECT_INCOMPATIBLE");
    }
    leg(&t.asset)?;
    leg(&t.cash)?;
    if let (Leg::Kcc20 { cov: a, .. }, Leg::Kcc20 { cov: b, .. }) = (&t.asset, &t.cash) {
        if a == b {
            return fail("TERMS_SAME_COVENANT");
        }
    }
    dest(&t.asset, &t.buyer_delivery, curves)?;
    dest(&t.cash, &t.seller_proceeds, curves)?;
    dest(&t.asset, &t.seller_refund, curves)?;
    dest(&t.cash, &t.buyer_refund, curves)?;
    if t.expiry >= crate::LOCK_TIME_THRESHOLD {
        return fail("TERMS_EXPIRY_NOT_DAA");
    }
    if let Some(e) = t.earliest {
        if e >= crate::LOCK_TIME_THRESHOLD {
            return fail("TERMS_EARLIEST_NOT_DAA");
        }
        if e == 0 {
            return fail("TERMS_EARLIEST_ZERO");
        }
        if e > t.expiry {
            return fail("TERMS_EARLIEST_AFTER_EXPIRY");
        }
    }
    // The three checks of v4.
    if t.mode != MODE_VAULT {
        return fail("ZK_H_TERMS_DIRECT");
    }
    if t.authority.is_none() {
        return fail("ZK_H_AUTHORITY_REQUIRED");
    }
    if zero(&t.blind) {
        return fail("ZK_H_BLIND_INVALID");
    }
    Ok(())
}

fn leg(l: &Leg) -> Result<(), Refusal> {
    let (amount, max) = match l {
        Leg::Kas { amount } => (*amount, MAX_SOMPI),
        Leg::Kcc20 { amount, .. } | Leg::External { amount } => (*amount, i64::MAX as u64),
    };
    if amount == 0 {
        return fail("TERMS_AMOUNT_ZERO");
    }
    if amount > max {
        return fail("TERMS_AMOUNT_OUT_OF_RANGE");
    }
    if let Leg::Kcc20 {
        cov,
        template_hash,
        prefix_len,
        suffix_len,
        ..
    } = l
    {
        if zero(cov) || zero(template_hash) {
            return fail("TERMS_ZERO_IDENTIFIER");
        }
        if *prefix_len == 0
            || *suffix_len == 0
            || u64::from(*prefix_len) + u64::from(*suffix_len) > MAX_TEMPLATE_LEN
        {
            return fail("TERMS_TEMPLATE_LENGTH");
        }
    }
    Ok(())
}

fn dest(l: &Leg, d: &Dest, curves: bool) -> Result<(), Refusal> {
    let key = |k: &[u8]| !curves || xonly_valid(k);
    match (l, d) {
        (Leg::Kas { .. }, Dest::Kas { version, script }) => {
            if *version != 0 {
                return fail("TERMS_NONSTANDARD_SCRIPT");
            }
            match script.as_slice() {
                // OpData32 <x-only key> OpCheckSig
                [0x20, rest @ .., 0xac] if rest.len() == 32 => {
                    if !key(rest) {
                        return fail("TERMS_INVALID_KEY");
                    }
                }
                // OpData33 <compressed key> OpCheckSigECDSA
                [0x21, rest @ .., 0xab] if rest.len() == 33 => {
                    if curves && !compressed_valid(rest) {
                        return fail("TERMS_INVALID_KEY");
                    }
                }
                // OpBlake2b OpData32 <script hash> OpEqual
                [0xaa, 0x20, rest @ .., 0x87] if rest.len() == 32 => {
                    if zero(rest) {
                        return fail("TERMS_ZERO_IDENTIFIER");
                    }
                }
                _ => return fail("TERMS_NONSTANDARD_SCRIPT"),
            }
            Ok(())
        }
        (Leg::Kcc20 { .. }, Dest::Owner { id_type, id }) => {
            if zero(id) {
                return fail("TERMS_ZERO_IDENTIFIER");
            }
            if *id_type == ID_PUBKEY && !key(id) {
                return fail("TERMS_INVALID_KEY");
            }
            Ok(())
        }
        (Leg::External { .. }, Dest::OffChain) => Ok(()),
        _ => fail("TERMS_DESTINATION_KIND"),
    }
}
