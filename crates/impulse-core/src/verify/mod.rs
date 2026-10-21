// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The verifier (spec/VERIFY.md). Before funding: recompute both legs' vault addresses from the
//! agreed terms and compare them with the addresses offered for funding, and read what each
//! KCC-20 leg's token template declares about issuer powers. After a spend: check a revealed
//! redeem script against the published template and the agreed terms, and a spent input also
//! against the UTXO it spends.
//!
//! Every check takes structure-checked terms ([`ValidatedTerms`]) and fails closed with a stable
//! code. Token warnings are data read from the evidence supplied, never a statement that a token
//! is safe. Keyless: nothing here signs or holds a private key.

mod error;
mod pins;
mod token;

#[cfg(test)]
mod tests;

pub use crate::decode::Party;
use error::printable;
pub use error::{VerifyError, VERIFY_ERROR_CODES};
pub use token::{
    pinned_kcc20, token_warnings, PinnedKcc20, Relation, TemplateTriple, TokenEvidence,
    TokenWarning, TokenWarningKind, KCC20_ENTRIES, KCC20_STATE, MAX_TOKEN_ARTIFACT_LEN,
    PINNED_KCC20_TEMPLATES, TOKEN_WARNING_CODES,
};

use crate::address::{prefix, vault_address};
use crate::decode::revealed_script;
use crate::template::{self, LegIndex, TemplateError, Vault};
use crate::terms::{CreationContext, Terms, ValidatedTerms};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput};
use kaspa_txscript::pay_to_script_hash_script;

/// The addresses a depositor was offered for funding, one per leg. A leg the terms give no vault
/// (the cash leg of external cash) must have none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OfferedAddresses<'a> {
    pub asset: Option<&'a str>,
    pub cash: Option<&'a str>,
}

impl<'a> OfferedAddresses<'a> {
    fn get(&self, leg: LegIndex) -> Option<&'a str> {
        match leg {
            LegIndex::Asset => self.asset,
            LegIndex::Cash => self.cash,
        }
    }
}

/// A leg's funding address, recomputed from the terms and equal to the one offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAddress {
    pub leg: LegIndex,
    /// The address as Impulse renders it.
    pub address: String,
    pub script_hash: [u8; 32],
}

/// Everything checked before funding: the verified addresses and the token warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingCheck {
    pub addresses: Vec<VerifiedAddress>,
    /// Data read from the token evidence. An empty list is not a statement that a token has no
    /// issuer powers.
    pub warnings: Vec<TokenWarning>,
}

impl FundingCheck {
    /// Whether evidence was read for every KCC-20 leg (no `TOKEN_UNASSESSED`). A caller must not
    /// present a leg as checked when this is false. True says only that evidence was read,
    /// never that a token is safe.
    pub fn token_legs_assessed(&self) -> bool {
        !self
            .warnings
            .iter()
            .any(|w| w.kind == TokenWarningKind::Unassessed)
    }
}

/// Recomputes each leg's funding address from the terms and compares it with the one offered.
///
/// In order, first failure returned: both legs instantiate for creation, so the creation checks
/// run against `ctx` (`TERMS_NETWORK_MISMATCH`, `TERMS_EXPIRY_*`) and Direct terms are
/// `TEMPLATE_NO_VAULT`; then the asset leg, then the cash leg: a leg with no vault must have no
/// address (`VERIFY_ADDRESS_UNEXPECTED`), a leg with a vault must have one
/// (`VERIFY_ADDRESS_MISSING`), which must have the canonical length of its address version and
/// parse (`VERIFY_ADDRESS_MALFORMED`), carry the terms' network prefix
/// (`VERIFY_ADDRESS_NETWORK`) and pay this leg's vault: the other leg's vault is
/// `VERIFY_LEGS_SWAPPED`, anything else `VERIFY_ADDRESS_MISMATCH`.
pub fn verify_addresses(
    terms: &ValidatedTerms,
    ctx: &CreationContext,
    offered: &OfferedAddresses<'_>,
) -> Result<Vec<VerifiedAddress>, VerifyError> {
    let mut vaults = [None, None];
    for leg in LegIndex::ALL {
        match Vault::instantiate_for_creation(terms, leg, ctx) {
            Ok(fundable) => vaults[usize::from(leg.index())] = Some(fundable),
            // External cash: the cash leg settles off chain and has no vault.
            Err(TemplateError::NoVault { .. }) if leg == LegIndex::Cash => {}
            Err(e) => return Err(e.into()),
        }
    }
    let network = terms.terms().network;
    let mut verified = Vec::new();
    for leg in LegIndex::ALL {
        let mine = &vaults[usize::from(leg.index())];
        let other = &vaults[usize::from(1 - leg.index())];
        let (fundable, text) = match (mine, offered.get(leg)) {
            (None, None) => continue,
            (None, Some(_)) => return Err(VerifyError::AddressUnexpected { leg }),
            (Some(_), None) => return Err(VerifyError::AddressMissing { leg }),
            (Some(fundable), Some(text)) => (fundable, text),
        };
        if !parsable_address(text) {
            return Err(VerifyError::AddressMalformed {
                leg,
                reason: "not a prefix, a colon and the bech32 payload of a Kaspa address".into(),
            });
        }
        let parsed = Address::try_from(text).map_err(|e| VerifyError::AddressMalformed {
            leg,
            reason: printable(&e.to_string()),
        })?;
        if parsed.prefix != prefix(network) {
            return Err(VerifyError::AddressNetwork {
                leg,
                expected: network,
                found: parsed.prefix.to_string(),
            });
        }
        let pays = |v: &Vault| {
            parsed.version == Version::ScriptHash && parsed.payload.as_slice() == v.script_hash()
        };
        if !pays(fundable.vault()) {
            if other.as_ref().is_some_and(|o| pays(o.vault())) {
                return Err(VerifyError::LegsSwapped { leg });
            }
            return Err(VerifyError::AddressMismatch { leg });
        }
        verified.push(VerifiedAddress {
            leg,
            address: vault_address(fundable),
            script_hash: fundable.vault().script_hash(),
        });
    }
    Ok(verified)
}

/// Whether `text` has the shape of a Kaspa address that rusty-kaspa a41a333 `Address::try_from`
/// can parse without panicking: a prefix, a colon, and the canonical number of lowercase bech32
/// symbols for its version byte (53 payload symbols for PubKey and ScriptHash, 32-byte payloads;
/// 55 for PubKeyECDSA, 33 bytes; then 8 checksum symbols). Once the checksum passes, upstream
/// indexes the first payload byte, which panics on 0 or 1 payload symbols, and `Address::new`
/// asserts the payload length of the version, which panics on any other length. Both are
/// reachable with a valid checksum, which anyone can compute. The prefix and the checksum are
/// left to upstream, which refuses them without panicking.
pub(crate) fn parsable_address(text: &str) -> bool {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let Some((_, payload)) = text.split_once(':') else {
        return false;
    };
    let symbols: Option<Vec<u8>> = payload
        .bytes()
        .map(|b| CHARSET.iter().position(|&c| c == b).map(|i| i as u8))
        .collect();
    let Some(symbols) = symbols else {
        return false;
    };
    let Some(payload) = symbols.len().checked_sub(8).filter(|&n| n >= 2) else {
        return false;
    };
    let version = symbols[0] << 3 | symbols[1] >> 2;
    matches!(
        (Version::try_from(version), payload),
        (Ok(Version::PubKey | Version::ScriptHash), 53) | (Ok(Version::PubKeyECDSA), 55)
    )
}

/// The full check before funding: [`verify_addresses`], then [`token_warnings`].
pub fn before_funding(
    terms: &ValidatedTerms,
    ctx: &CreationContext,
    offered: &OfferedAddresses<'_>,
    asset_token: Option<&TokenEvidence<'_>>,
    cash_token: Option<&TokenEvidence<'_>>,
) -> Result<FundingCheck, VerifyError> {
    let addresses = verify_addresses(terms, ctx, offered)?;
    let warnings = token_warnings(terms, asset_token, cash_token)?;
    Ok(FundingCheck {
        addresses,
        warnings,
    })
}

/// Checks a redeem script revealed by a spend against the agreed terms and leg. Accepts exactly
/// the script [`Vault::instantiate_existing`] makes from them; no creation checks run, so a
/// trade past its expiry still verifies.
///
/// In order, first failure returned: the terms give the leg a vault (`TEMPLATE_NO_VAULT`); the
/// script runs the published template, its template hash recomputed from its own bytes
/// (`VERIFY_TEMPLATE_MISMATCH`); it decodes (`TEMPLATE_*`, `TERMS_*`); its terms are the agreed
/// terms (`VERIFY_TERMS_MISMATCH`, naming the fields that differ); its leg is the expected leg
/// (`VERIFY_LEGS_SWAPPED`).
pub fn verify_revealed_script(
    terms: &ValidatedTerms,
    leg: LegIndex,
    redeem_script: &[u8],
) -> Result<(), VerifyError> {
    let expected = Vault::instantiate_existing(terms, leg)?;
    if expected.redeem_script() == redeem_script {
        return Ok(());
    }
    // Not the agreed vault: name the reason.
    let pinned = template::check()?.hash();
    let found = template::template_hash_of_instance(redeem_script).ok();
    if found != Some(pinned) {
        return Err(VerifyError::TemplateMismatch {
            expected: pinned,
            found,
        });
    }
    let (decoded, decoded_leg) = template::decode(redeem_script)?;
    if decoded.terms_hash() != terms.terms_hash() {
        return Err(VerifyError::TermsMismatch {
            fields: differing_fields(terms.terms(), decoded.terms()),
        });
    }
    if decoded_leg != leg {
        return Err(VerifyError::LegsSwapped { leg });
    }
    // Not reached: decoding is exact, so equal terms and leg give the expected script.
    Err(TemplateError::NonCanonical.into())
}

/// [`verify_revealed_script`] on the script a spent input reveals, bound to the UTXO the input
/// spends. `spent` is that UTXO's scriptPublicKey, as the node reports it.
///
/// In order, first failure returned: the signature script is push only and its last push is
/// data, the revealed script (`VERIFY_NOTHING_REVEALED`); `spent` is the version 0 P2SH of that
/// script (`VERIFY_INPUT_NOT_VAULT`); then [`verify_revealed_script`]. The binding is needed
/// because the transaction ID does not commit to signature scripts, and rusty-kaspa a41a333
/// runs an input's signature script only when the spent scriptPublicKey has version 0: the
/// version 0 P2SH of the revealed script is the one UTXO whose spend runs that script.
pub fn verify_spent_input(
    terms: &ValidatedTerms,
    leg: LegIndex,
    input: &TransactionInput,
    spent: &ScriptPublicKey,
) -> Result<(), VerifyError> {
    let script = revealed_script(&input.signature_script).ok_or(VerifyError::NothingRevealed)?;
    if *spent != pay_to_script_hash_script(script) {
        return Err(VerifyError::InputNotVault);
    }
    verify_revealed_script(terms, leg, script)
}

/// The names of the terms fields that differ, in field order. The pattern names every field, so
/// a new field fails to compile until it is listed.
fn differing_fields(a: &Terms, b: &Terms) -> Vec<&'static str> {
    macro_rules! differing {
        ($($field:ident),* $(,)?) => {{
            let Terms { $($field),* } = a;
            let mut out = Vec::new();
            $( if *$field != b.$field { out.push(stringify!($field)); } )*
            out
        }};
    }
    differing!(
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
    )
}
