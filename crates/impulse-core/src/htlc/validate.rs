// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Hashlock terms validation (spec/V2.md section 10.2, "Validation"). Two stages, as v1: the
//! structure checks, time-independent and mandatory, then the creation checks against the
//! creator's network, DAA score and clock. Within each stage the checks run in a fixed order and
//! the first failure is returned, so every implementation reports the same code.

use super::margin::{self, MarginContext};
use super::{Counterpart, HtlcError, HtlcState, HtlcTerms, HTLC_TERMS_VERSION};
use crate::terms::{
    CreationContext, IdentifierType, Kcc20Owner, LegKind, TermsError, MAX_TEMPLATE_LEN,
};
use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;
use secp256k1::XOnlyPublicKey;

/// What the creation checks compare the terms with: v1's creation context (network, DAA score at
/// creation, horizon) and the margin inputs of spec/V2.md section 10.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtlcCreationContext<'a> {
    pub creation: CreationContext,
    pub margin: MarginContext<'a>,
}

/// Structure checks of the terms, in the order of spec/V2.md section 10.2: version, keys,
/// distinct parties, asset KCC-20, amount and template, owners, hash lock, counterpart, expiry.
pub(super) fn structure(t: &HtlcTerms) -> Result<(), HtlcError> {
    checks(&t.state(), Some(&t.counterpart))
}

/// The same checks on a decoded contract state, which holds the counterpart record's hash only,
/// so the counterpart check is skipped.
pub(super) fn state(s: &HtlcState) -> Result<(), HtlcError> {
    checks(s, None)
}

fn checks(s: &HtlcState, counterpart: Option<&Counterpart>) -> Result<(), HtlcError> {
    if s.version != HTLC_TERMS_VERSION {
        return Err(HtlcError::Version { version: s.version });
    }
    xonly_key(&s.seller_key, "seller_key")?;
    xonly_key(&s.buyer_key, "buyer_key")?;
    if s.buyer_key == s.seller_key {
        return Err(TermsError::PartiesNotDistinct { field: "buyer_key" }.into());
    }
    let LegKind::Kcc20(token) = s.asset_leg.kind else {
        return Err(HtlcError::AssetKind);
    };
    // As v1 (spec/ENCODING.md): script integers are signed 64-bit.
    let max = i64::MAX as u64;
    if s.asset_leg.amount == 0 {
        return Err(TermsError::AmountZero {
            field: "asset_leg.amount",
        }
        .into());
    }
    if s.asset_leg.amount > max {
        return Err(TermsError::AmountOutOfRange {
            field: "asset_leg.amount",
            amount: s.asset_leg.amount,
            max,
        }
        .into());
    }
    nonzero(&token.covenant_id, "asset_leg.covenant_id")?;
    nonzero(&token.template_hash, "asset_leg.template_hash")?;
    let (prefix_len, suffix_len) = (token.template_prefix_len, token.template_suffix_len);
    if prefix_len == 0
        || suffix_len == 0
        || u64::from(prefix_len) + u64::from(suffix_len) > MAX_TEMPLATE_LEN
    {
        return Err(TermsError::TemplateLength {
            field: "asset_leg.template",
            prefix_len,
            suffix_len,
        }
        .into());
    }
    owner(&s.buyer_delivery, "buyer_delivery")?;
    owner(&s.seller_refund, "seller_refund")?;
    if s.hash_lock == [0; 32] {
        return Err(HtlcError::HashZero);
    }
    if let Some(c) = counterpart {
        counterpart_record(c)?;
    }
    if s.expiry_daa >= LOCK_TIME_THRESHOLD {
        return Err(TermsError::ExpiryNotDaa {
            expiry_daa: s.expiry_daa,
        }
        .into());
    }
    Ok(())
}

/// The counterpart record: an amount above zero, no all-zero identifier, and a timeout above zero
/// and at most `i64::MAX`, in field order (an unknown chain is refused when decoding, and cannot be built as a value).
fn counterpart_record(c: &Counterpart) -> Result<(), HtlcError> {
    let ids = [
        (&c.chain_id, "counterpart.chain_id"),
        (&c.htlc_program, "counterpart.htlc_program"),
        (&c.asset, "counterpart.asset"),
    ];
    for (id, field) in ids {
        if *id == [0; 32] {
            return Err(HtlcError::Counterpart { field });
        }
    }
    if c.amount == 0 {
        return Err(HtlcError::Counterpart {
            field: "counterpart.amount",
        });
    }
    for (id, field) in [
        (&c.recipient, "counterpart.recipient"),
        (&c.refund, "counterpart.refund"),
    ] {
        if *id == [0; 32] {
            return Err(HtlcError::Counterpart { field });
        }
    }
    // Unix seconds for both chain kinds (D51): above zero and a signed 64-bit value, as v1's
    // integers.
    if c.timeout == 0 || c.timeout > i64::MAX as u64 {
        return Err(HtlcError::Counterpart {
            field: "counterpart.timeout",
        });
    }
    Ok(())
}

/// Creation checks: v1's three, in v1's order and codes, then a counterpart timeout after now,
/// then the DAA rate and the margin.
pub(super) fn creation(t: &HtlcTerms, ctx: &HtlcCreationContext<'_>) -> Result<(), HtlcError> {
    let c = &ctx.creation;
    if t.network != c.network {
        return Err(TermsError::NetworkMismatch {
            expected: c.network,
            found: t.network,
        }
        .into());
    }
    if t.expiry_daa <= c.creation_daa {
        return Err(TermsError::ExpiryNotAfterCreation {
            expiry_daa: t.expiry_daa,
            creation_daa: c.creation_daa,
        }
        .into());
    }
    let max_expiry_daa = c.creation_daa.saturating_add(c.max_expiry_horizon_daa);
    if t.expiry_daa > max_expiry_daa {
        return Err(TermsError::ExpiryBeyondHorizon {
            expiry_daa: t.expiry_daa,
            max_expiry_daa,
        }
        .into());
    }
    // The counterpart timeout must still be ahead: one at or before now passes the margin rule
    // vacuously.
    if t.counterpart.timeout <= ctx.margin.now_unix {
        return Err(HtlcError::Counterpart {
            field: "counterpart.timeout",
        });
    }
    margin::check(t, c, &ctx.margin)
}

/// A KCC-20 owner: not all zero, and a PUBKEY owner a valid x-only key, as v1 checks every
/// KCC-20 destination (D51).
fn owner(o: &Kcc20Owner, field: &'static str) -> Result<(), HtlcError> {
    nonzero(&o.identifier, field)?;
    if o.identifier_type == IdentifierType::PubKey {
        xonly_key(&o.identifier, field)?;
    }
    Ok(())
}

fn xonly_key(bytes: &[u8], field: &'static str) -> Result<(), HtlcError> {
    XOnlyPublicKey::from_slice(bytes)
        .map(|_| ())
        .map_err(|_| TermsError::InvalidKey { field }.into())
}

fn nonzero(bytes: &[u8], field: &'static str) -> Result<(), HtlcError> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(TermsError::ZeroIdentifier { field }.into());
    }
    Ok(())
}
