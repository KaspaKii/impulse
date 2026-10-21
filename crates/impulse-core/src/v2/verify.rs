// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v2 verifier (spec/V2.md section 7). Before funding: every leg's address is recomputed from
//! the agreed terms and compared with the address offered for that leg. After a spend: a revealed
//! script is checked against the pinned v2 template and the agreed terms and leg, and a spent
//! input also against the UTXO it spends. On the vault UTXOs a party can see: the lineage check
//! (`TX_LINEAGE`) and the warnings of section 7, which never refuse.
//!
//! Every check takes structure-checked terms and fails closed with a stable code. Keyless.

use super::template::{self, FundableVaultV2, VaultV2};
use super::terms::ValidatedTermsV2;
use super::tx::{min_v2, min_vault_v2};
use super::{vault_address, V2Error};
use crate::address::prefix;
use crate::decode::revealed_script;
use crate::terms::{CreationContext, LegKind};
use crate::tx::Utxo;
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput};
use kaspa_txscript::pay_to_script_hash_script;
use std::collections::HashSet;

/// A leg's funding address, recomputed from the terms and equal to the one offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAddressV2 {
    pub leg: usize,
    pub address: String,
    pub script_hash: [u8; 32],
}

/// Recomputes every leg's funding address from the terms and compares it with the one offered
/// for it (`offered[i]` for leg i). In order, first failure returned: every leg instantiates for
/// creation (the creation checks against `ctx`); then each leg in order: an address was offered
/// (`VERIFY_ADDRESS_MISSING`), it parses (`VERIFY_ADDRESS_MALFORMED`), carries the terms' network
/// (`VERIFY_ADDRESS_NETWORK`) and pays this leg's vault: another leg's vault of these terms is
/// `VERIFY_V2_WRONG_LEG`, anything else `VERIFY_V2_ADDRESS_MISMATCH`.
pub fn verify_addresses(
    terms: &ValidatedTermsV2,
    ctx: &CreationContext,
    offered: &[Option<&str>],
) -> Result<Vec<VerifiedAddressV2>, V2Error> {
    let n = terms.terms().legs.len();
    let vaults = (0..n)
        .map(|i| VaultV2::instantiate_for_creation(terms, i, ctx))
        .collect::<Result<Vec<FundableVaultV2>, _>>()?;
    let network = terms.terms().network;
    let mut verified = Vec::with_capacity(n);
    for (leg, fundable) in vaults.iter().enumerate() {
        let text = offered
            .get(leg)
            .copied()
            .flatten()
            .ok_or(V2Error::AddressMissing { leg })?;
        if !parsable_address(text) {
            return Err(V2Error::AddressMalformed {
                leg,
                reason: "not a prefix, a colon and the bech32 payload of a Kaspa address".into(),
            });
        }
        let parsed = Address::try_from(text).map_err(|e| V2Error::AddressMalformed {
            leg,
            reason: printable(&e.to_string()),
        })?;
        if parsed.prefix != prefix(network) {
            return Err(V2Error::AddressNetwork {
                leg,
                expected: network,
                found: parsed.prefix.to_string(),
            });
        }
        let pays = |v: &VaultV2| {
            parsed.version == Version::ScriptHash && parsed.payload.as_slice() == v.script_hash()
        };
        if !pays(fundable.vault()) {
            if let Some(found) = vaults.iter().position(|v| pays(v.vault())) {
                return Err(V2Error::WrongLeg { leg, found });
            }
            return Err(V2Error::AddressMismatch { leg });
        }
        verified.push(VerifiedAddressV2 {
            leg,
            address: vault_address(fundable),
            script_hash: fundable.vault().script_hash(),
        });
    }
    Ok(verified)
}

/// As `crate::verify`: an address text upstream can parse without panicking.
fn parsable_address(text: &str) -> bool {
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

/// Every character outside printable ASCII escaped as `\u{..}` (as the v1 verifier does).
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == ' ' || c.is_ascii_graphic() {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

/// Checks a redeem script revealed by a spend against the agreed terms and leg. Accepts exactly
/// the script [`VaultV2::instantiate_existing`] makes from them. In order, first failure
/// returned: the leg is in the terms (`TEMPLATE_V2_LEG_INDEX`); the script runs the pinned v2
/// template, its template hash recomputed from its own bytes (`VERIFY_V2_TEMPLATE_MISMATCH`); it
/// decodes (`TEMPLATE_V2_*`, `TERMS_*`); its terms are the agreed terms (`VERIFY_TERMS_MISMATCH`);
/// its leg is the expected leg (`VERIFY_V2_WRONG_LEG`).
pub fn verify_revealed_script(
    terms: &ValidatedTermsV2,
    leg: usize,
    redeem_script: &[u8],
) -> Result<(), V2Error> {
    let expected = VaultV2::instantiate_existing(terms, leg)?;
    if expected.redeem_script() == redeem_script {
        return Ok(());
    }
    let pinned = template::check()?.hash();
    let found = template::template_hash_of_instance(redeem_script).ok();
    if found != Some(pinned) {
        return Err(V2Error::TemplateMismatch {
            expected: pinned,
            found,
        });
    }
    let (decoded, decoded_leg) = template::decode(redeem_script)?;
    if decoded.terms_hash() != terms.terms_hash() {
        return Err(V2Error::TermsMismatch);
    }
    if decoded_leg != leg {
        return Err(V2Error::WrongLeg {
            leg,
            found: decoded_leg,
        });
    }
    // Not reached: decoding is exact, so equal terms and leg give the expected script.
    Err(V2Error::TemplateNonCanonical)
}

/// [`verify_revealed_script`] on the script a spent input reveals, bound to the UTXO it spends
/// (`spent`, its scriptPublicKey as the node reports it): push-only signature script ending in
/// a data push (`VERIFY_NOTHING_REVEALED`), `spent` the version 0 P2SH of that script
/// (`VERIFY_INPUT_NOT_VAULT`), then the script check.
pub fn verify_spent_input(
    terms: &ValidatedTermsV2,
    leg: usize,
    input: &TransactionInput,
    spent: &ScriptPublicKey,
) -> Result<(), V2Error> {
    let script = revealed_script(&input.signature_script).ok_or(V2Error::NothingRevealed)?;
    if *spent != pay_to_script_hash_script(script) {
        return Err(V2Error::InputNotVault);
    }
    verify_revealed_script(terms, leg, script)
}

/// A warning of spec/V2.md section 7. Data, never a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultUtxoWarning {
    /// More than one token UTXO owned by the vault script hash of `leg` (strays, section 4.4).
    StrayEscrows { leg: usize, count: usize },
    /// Partial terms without an authority: tranches can be front-run (D42).
    PartialWithoutAuthority,
    /// A vault UTXO of a KAS leg whose lot is below MIN_V2(1, O), or a KCC-20 escrow whose
    /// carrier is below MIN_V2(2, O): its settle may exceed the storage cap (section 6.2).
    BelowMinimum {
        leg: usize,
        value: u64,
        minimum: u64,
    },
}

/// The checks on the vault UTXOs a party can see for a trade. `vaults[i]` are the UTXOs at the
/// vault address of leg i; `tokens[i]` the token UTXOs owned by that vault's script hash (each
/// with its amount, as the token's state holds it). Refuses two vault UTXOs of the trade with one
/// covenant ID (`TX_LINEAGE`); otherwise returns the warnings, which never refuse.
pub fn check_vault_utxos(
    terms: &ValidatedTermsV2,
    vaults: &[Vec<Utxo>],
    tokens: &[Vec<(Utxo, u64)>],
) -> Result<Vec<VaultUtxoWarning>, V2Error> {
    let t = terms.terms();
    let mut covenants = HashSet::new();
    for utxo in vaults.iter().flatten() {
        if let Some(cov) = utxo.entry.covenant_id {
            if !covenants.insert(cov) {
                return Err(V2Error::Lineage {
                    reason: "two vault UTXOs of one trade carry the same covenant ID",
                });
            }
        }
    }
    let mut warnings = Vec::new();
    if t.partial.is_some() && t.authority_key.is_none() {
        warnings.push(VaultUtxoWarning::PartialWithoutAuthority);
    }
    for (leg, l) in t.legs.iter().enumerate() {
        let held = tokens.get(leg).map_or(&[][..], |v| v.as_slice());
        if held.len() > 1 {
            warnings.push(VaultUtxoWarning::StrayEscrows {
                leg,
                count: held.len(),
            });
        }
        match l.asset.kind {
            LegKind::Kas => {
                let minimum = min_v2(t, 1);
                for u in vaults.get(leg).map_or(&[][..], |v| v.as_slice()) {
                    let unit = t.unit(leg).min(u.entry.amount);
                    // A partial vault UTXO carries a covenant ID: two storage units.
                    let vault_minimum = min_vault_v2(t);
                    if unit < minimum {
                        warnings.push(VaultUtxoWarning::BelowMinimum {
                            leg,
                            value: u.entry.amount,
                            minimum,
                        });
                    } else if u.entry.amount < vault_minimum {
                        warnings.push(VaultUtxoWarning::BelowMinimum {
                            leg,
                            value: u.entry.amount,
                            minimum: vault_minimum,
                        });
                    }
                }
            }
            _ => {
                let minimum = min_v2(t, 2);
                for (u, _) in held {
                    if u.entry.amount < minimum {
                        warnings.push(VaultUtxoWarning::BelowMinimum {
                            leg,
                            value: u.entry.amount,
                            minimum,
                        });
                    }
                }
            }
        }
    }
    Ok(warnings)
}
