// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms validation (spec/ENCODING.md, "Validation"). Two stages: structure checks, which are
//! time-independent and mandatory, then creation checks against the creator's network and DAA
//! score. Within each stage the checks run in a fixed order and the first failure is returned,
//! so every implementation reports the same code for the same terms.

use super::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Leg, LegKind, Network, SettlementMode,
    Terms, TermsError, TERMS_VERSION,
};
use kaspa_consensus_core::constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript::MAX_SCRIPTS_SIZE_POST_TOCCATA;
use secp256k1::{PublicKey, XOnlyPublicKey};

/// About one year of DAA score: 365 days at 10 DAA per second. Modelled, not measured: it
/// assumes the 10 blocks per second that mainnet and TN10 target. Callers may pass their own.
pub const DEFAULT_MAX_EXPIRY_HORIZON_DAA: u64 = 365 * 24 * 60 * 60 * 10;

/// Upper bound on a KCC-20 template's prefix plus suffix length: the post-Toccata consensus
/// script size limit (rusty-kaspa a41a333), since the template is part of one script.
pub const MAX_TEMPLATE_LEN: u64 = MAX_SCRIPTS_SIZE_POST_TOCCATA as u64;

/// What the creation checks compare the terms with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreationContext {
    /// The network the caller is on; the terms must name it.
    pub network: Network,
    /// DAA score when the terms are created; the expiry must lie after it.
    pub creation_daa: u64,
    /// How far past `creation_daa` the expiry may lie.
    pub max_expiry_horizon_daa: u64,
}

impl CreationContext {
    /// A context with the default horizon of about one year.
    pub fn new(network: Network, creation_daa: u64) -> Self {
        Self {
            network,
            creation_daa,
            max_expiry_horizon_daa: DEFAULT_MAX_EXPIRY_HORIZON_DAA,
        }
    }
}

struct LegFields {
    amount: &'static str,
    covenant_id: &'static str,
    template_hash: &'static str,
    template: &'static str,
}

const ASSET: LegFields = LegFields {
    amount: "asset_leg.amount",
    covenant_id: "asset_leg.covenant_id",
    template_hash: "asset_leg.template_hash",
    template: "asset_leg.template",
};

const CASH: LegFields = LegFields {
    amount: "cash_leg.amount",
    covenant_id: "cash_leg.covenant_id",
    template_hash: "cash_leg.template_hash",
    template: "cash_leg.template",
};

/// Structure checks: everything that holds or fails regardless of when or where it is asked.
pub(super) fn structure(t: &Terms) -> Result<(), TermsError> {
    if t.version != TERMS_VERSION {
        return Err(TermsError::UnsupportedVersion { version: t.version });
    }

    xonly_key(&t.seller_key, "seller_key")?;
    xonly_key(&t.buyer_key, "buyer_key")?;
    if let Some(authority) = &t.authority_key {
        xonly_key(authority, "authority_key")?;
    }
    if t.buyer_key == t.seller_key {
        return Err(TermsError::PartiesNotDistinct { field: "buyer_key" });
    }
    // The contract tells roles apart by key, so the authority must be a third key: otherwise
    // the depositor's refund exemptions and the authority's release would share one signer.
    if let Some(authority) = &t.authority_key {
        if *authority == t.seller_key {
            return Err(TermsError::AuthorityIsParty {
                party: "seller_key",
            });
        }
        if *authority == t.buyer_key {
            return Err(TermsError::AuthorityIsParty { party: "buyer_key" });
        }
    }

    if t.asset_leg.kind == LegKind::External {
        return Err(TermsError::AssetExternal);
    }
    // v1: the vault escrows a KCC-20 asset only (decision D13). KAS against a token is the same
    // trade with buyer and seller swapped. The encoding keeps the KAS kind for later versions.
    if !matches!(t.asset_leg.kind, LegKind::Kcc20(_)) {
        return Err(TermsError::AssetKindUnsupported);
    }
    if t.cash_leg.kind == LegKind::External && t.authority_key.is_none() {
        return Err(TermsError::ExternalWithoutAuthority);
    }
    if t.settlement_mode == SettlementMode::Direct {
        // One transaction moves both legs, so both must be on chain; nothing is deposited, so
        // there is no deposit to earmark until expiry.
        if t.cash_leg.kind == LegKind::External {
            return Err(TermsError::DirectIncompatible { field: "cash_leg" });
        }
        if t.funding_mode == FundingMode::Earmarked {
            return Err(TermsError::DirectIncompatible {
                field: "funding_mode",
            });
        }
    }
    leg(&t.asset_leg, &ASSET)?;
    leg(&t.cash_leg, &CASH)?;
    // One token on both legs: each vault requires its escrow to be the only input of its leg's
    // covenant ([E1]), so a settle would hold two and neither vault would ever release.
    if let (LegKind::Kcc20(asset), LegKind::Kcc20(cash)) = (&t.asset_leg.kind, &t.cash_leg.kind) {
        if asset.covenant_id == cash.covenant_id {
            return Err(TermsError::SameCovenant);
        }
    }

    destination(&t.asset_leg, &t.buyer_delivery, "buyer_delivery")?;
    destination(&t.cash_leg, &t.seller_proceeds, "seller_proceeds")?;
    destination(&t.asset_leg, &t.seller_refund, "seller_refund")?;
    destination(&t.cash_leg, &t.buyer_refund, "buyer_refund")?;

    if t.expiry_daa >= LOCK_TIME_THRESHOLD {
        return Err(TermsError::ExpiryNotDaa {
            expiry_daa: t.expiry_daa,
        });
    }
    if let Some(earliest_daa) = t.earliest_daa {
        if earliest_daa >= LOCK_TIME_THRESHOLD {
            return Err(TermsError::EarliestNotDaa { earliest_daa });
        }
        if earliest_daa == 0 {
            return Err(TermsError::EarliestZero);
        }
        if earliest_daa > t.expiry_daa {
            return Err(TermsError::EarliestAfterExpiry {
                earliest_daa,
                expiry_daa: t.expiry_daa,
            });
        }
    }
    Ok(())
}

/// Creation checks: the terms suit the creator's network and lie ahead of the creator's DAA
/// score. A trade that has since expired fails these and still passes `structure`.
pub(super) fn creation(t: &Terms, ctx: &CreationContext) -> Result<(), TermsError> {
    if t.network != ctx.network {
        return Err(TermsError::NetworkMismatch {
            expected: ctx.network,
            found: t.network,
        });
    }
    if t.expiry_daa <= ctx.creation_daa {
        return Err(TermsError::ExpiryNotAfterCreation {
            expiry_daa: t.expiry_daa,
            creation_daa: ctx.creation_daa,
        });
    }
    let max_expiry_daa = ctx.creation_daa.saturating_add(ctx.max_expiry_horizon_daa);
    if t.expiry_daa > max_expiry_daa {
        return Err(TermsError::ExpiryBeyondHorizon {
            expiry_daa: t.expiry_daa,
            max_expiry_daa,
        });
    }
    Ok(())
}

fn leg(leg: &Leg, fields: &LegFields) -> Result<(), TermsError> {
    // KAS cannot exceed the supply cap; script integers are signed 64-bit, so a token or
    // external amount must fit an i64 for the contract to compare it.
    let max = match leg.kind {
        LegKind::Kas => MAX_SOMPI,
        LegKind::Kcc20(_) | LegKind::External => i64::MAX as u64,
    };
    if leg.amount == 0 {
        return Err(TermsError::AmountZero {
            field: fields.amount,
        });
    }
    if leg.amount > max {
        return Err(TermsError::AmountOutOfRange {
            field: fields.amount,
            amount: leg.amount,
            max,
        });
    }
    if let LegKind::Kcc20(token) = &leg.kind {
        nonzero(&token.covenant_id, fields.covenant_id)?;
        nonzero(&token.template_hash, fields.template_hash)?;
        // The state sits between a prefix and a suffix, both non-empty, inside one script.
        let (prefix_len, suffix_len) = (token.template_prefix_len, token.template_suffix_len);
        if prefix_len == 0
            || suffix_len == 0
            || u64::from(prefix_len) + u64::from(suffix_len) > MAX_TEMPLATE_LEN
        {
            return Err(TermsError::TemplateLength {
                field: fields.template,
                prefix_len,
                suffix_len,
            });
        }
    }
    Ok(())
}

fn destination(leg: &Leg, dest: &Destination, field: &'static str) -> Result<(), TermsError> {
    match (&leg.kind, dest) {
        (LegKind::Kas, Destination::Kas(spk)) => kas_script(spk, field),
        (LegKind::Kcc20(_), Destination::Kcc20(owner)) => kcc20_owner(owner, field),
        (LegKind::External, Destination::OffChain) => Ok(()),
        _ => Err(TermsError::DestinationKind { field }),
    }
}

/// Only standard version-0 classes: a non-standard destination would make the settle or refund
/// transaction non-standard, so it would not relay and the leg could not move.
fn kas_script(spk: &ScriptPublicKey, field: &'static str) -> Result<(), TermsError> {
    let script = spk.script();
    match ScriptClass::from_script(spk) {
        // OpData32 <x-only key> OpCheckSig
        ScriptClass::PubKey => xonly_key(&script[1..33], field),
        // OpData33 <compressed key> OpCheckSigECDSA
        ScriptClass::PubKeyECDSA => PublicKey::from_slice(&script[1..34])
            .map(|_| ())
            .map_err(|_| TermsError::InvalidKey { field }),
        // OpBlake2b OpData32 <script hash> OpEqual
        ScriptClass::ScriptHash => nonzero(&script[2..34], field),
        ScriptClass::NonStandard => Err(TermsError::NonStandardScript { field }),
    }
}

fn kcc20_owner(owner: &Kcc20Owner, field: &'static str) -> Result<(), TermsError> {
    nonzero(&owner.identifier, field)?;
    if owner.identifier_type == IdentifierType::PubKey {
        xonly_key(&owner.identifier, field)?;
    }
    Ok(())
}

fn xonly_key(bytes: &[u8], field: &'static str) -> Result<(), TermsError> {
    XOnlyPublicKey::from_slice(bytes)
        .map(|_| ())
        .map_err(|_| TermsError::InvalidKey { field })
}

fn nonzero(bytes: &[u8], field: &'static str) -> Result<(), TermsError> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(TermsError::ZeroIdentifier { field });
    }
    Ok(())
}
