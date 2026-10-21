// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashlock verifier (spec/V2.md section 10.5, steps 2 and 3, and D51). Before funding: the
//! buyer, or the seller, recomputes the vault address from the agreed terms, after the creation
//! checks (the margin rule included), and compares it with the address offered. After funding,
//! before the buyer locks on the counterpart chain: the funding transaction is checked to hold
//! exactly the agreed escrow and an authorizer at the vault. After a spend:
//! a revealed redeem script, or a spent input with the UTXO it spends, is checked against the
//! agreed terms.
//!
//! Codes: the v1 `VERIFY_*` codes whose meaning applies unchanged (the address checks, the
//! spent-input binding, `VERIFY_TERMS_MISMATCH`), reported for the asset leg, which is the leg a
//! hashlock vault escrows; `HTLC_NOT_HASHLOCK_VAULT` and the hashlock decode codes for a script
//! that is not, or not exactly, a hashlock vault. Nothing here talks to a node. Keyless.

use super::template::{self, HtlcVault};
use super::validate::HtlcCreationContext;
use super::{HtlcError, HtlcState, ValidatedHtlcTerms};
use crate::address::prefix;
use crate::decode::revealed_script;
use crate::template::LegIndex;
use crate::terms::{IdentifierType, Kcc20Owner, LegKind};
use crate::tx::{Kcc20State, Kcc20Template};
use crate::verify::{VerifiedAddress, VerifyError};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::pay_to_script_hash_script;

/// The leg every hashlock verifier refusal names: the hashlock vault escrows the asset leg.
const LEG: LegIndex = LegIndex::Asset;

/// Recomputes the vault's funding address from the terms and compares it with the one offered.
///
/// In order, first failure returned: the creation checks (`TERMS_NETWORK_MISMATCH`,
/// `TERMS_EXPIRY_*`, `HTLC_DAA_SAMPLE`, `HTLC_TIMEOUT_MARGIN`); an address is offered
/// (`VERIFY_ADDRESS_MISSING`); it has the canonical shape of a Kaspa address and parses
/// (`VERIFY_ADDRESS_MALFORMED`); it carries the terms' network prefix (`VERIFY_ADDRESS_NETWORK`);
/// it is version ScriptHash paying this vault (`VERIFY_ADDRESS_MISMATCH`).
pub fn verify_address(
    terms: &ValidatedHtlcTerms,
    ctx: &HtlcCreationContext<'_>,
    offered: Option<&str>,
) -> Result<VerifiedAddress, HtlcError> {
    let fundable = HtlcVault::instantiate_for_creation(terms, ctx)?;
    let text = offered.ok_or(VerifyError::AddressMissing { leg: LEG })?;
    let malformed = || VerifyError::AddressMalformed {
        leg: LEG,
        reason: "not a prefix, a colon and the bech32 payload of a Kaspa address".into(),
    };
    if !parsable_address(text) {
        return Err(malformed().into());
    }
    let parsed = Address::try_from(text).map_err(|_| malformed())?;
    let network = terms.terms().network;
    if parsed.prefix != prefix(network) {
        return Err(VerifyError::AddressNetwork {
            leg: LEG,
            expected: network,
            found: parsed.prefix.to_string(),
        }
        .into());
    }
    let vault = fundable.vault();
    if parsed.version != Version::ScriptHash || parsed.payload.as_slice() != vault.script_hash() {
        return Err(VerifyError::AddressMismatch { leg: LEG }.into());
    }
    Ok(VerifiedAddress {
        leg: LEG,
        address: fundable.address(),
        script_hash: vault.script_hash(),
    })
}

/// Where a funding transaction verified by [`verify_funding`] left the vault's two UTXOs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtlcFunding {
    /// The escrowed token: the asset's covenant, the asset's template holding exactly the amount,
    /// owned by the vault's script hash, not a minter.
    pub escrow: TransactionOutpoint,
    /// The authorizer: a plain output at the vault's address, the lowest if there are several.
    pub authorizer: TransactionOutpoint,
}

/// Checks that `funding`, a transaction the node accepted, funds the terms' vault (spec/V2.md
/// section 10.5, step 3): what the buyer checks, at final depth and still unspent, before locking
/// the counterpart amount. Its outputs only are read: their scriptPublicKeys and covenant
/// bindings, which consensus checked when it accepted the transaction. No creation checks run and
/// mainnet terms are accepted: it creates nothing, like the verifiers of a spend.
///
/// The escrow's scriptPublicKey is the P2SH of the asset's template holding the state (owner the
/// vault's script hash, exactly the amount, not a minter), so a short or long amount, a key or
/// another script as owner, a minter, or another template each give another scriptPublicKey and
/// are not the escrow.
///
/// In order, first failure returned: the template is the one the terms name
/// (`TX_TOKEN_TEMPLATE`); exactly one output pays the escrow's scriptPublicKey (`HTLC_FUNDING`),
/// and it carries the asset's covenant ID (`HTLC_FUNDING`); at least one output pays the vault's
/// address with no covenant, the authorizer (`HTLC_FUNDING`).
pub fn verify_funding(
    terms: &ValidatedHtlcTerms,
    template: &Kcc20Template,
    funding: &Transaction,
) -> Result<HtlcFunding, HtlcError> {
    let t = terms.terms();
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(HtlcError::AssetKind);
    };
    template.check_token(&token)?;
    let vault = HtlcVault::instantiate_existing(terms)?;
    let escrow_spk = template.script_public_key(&Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        t.asset_leg.amount,
    ))?;
    let mut escrows = funding
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_public_key == escrow_spk);
    let (escrow, output) = escrows.next().ok_or(HtlcError::Funding {
        reason: "no output holds the escrowed token: the asset's template holding exactly the amount, owned by the vault's script hash, not a minter",
    })?;
    if escrows.next().is_some() {
        return Err(HtlcError::Funding {
            reason: "more than one output holds the escrowed token",
        });
    }
    if output.covenant.map(|c| c.covenant_id) != Some(Hash::from_bytes(token.covenant_id)) {
        return Err(HtlcError::Funding {
            reason: "the escrow output does not carry the asset's covenant ID",
        });
    }
    let vault_spk = vault.script_public_key();
    let authorizer = funding
        .outputs
        .iter()
        .position(|o| o.script_public_key == vault_spk && o.covenant.is_none())
        .ok_or(HtlcError::Funding {
            reason: "no authorizer: no output pays the vault's address without a covenant",
        })?;
    let id = funding.id();
    Ok(HtlcFunding {
        escrow: TransactionOutpoint::new(id, escrow as u32),
        authorizer: TransactionOutpoint::new(id, authorizer as u32),
    })
}

/// Checks a redeem script revealed by a spend against the agreed terms. Accepts exactly the
/// script [`HtlcVault::instantiate_existing`] makes from them; no creation checks run, so a trade
/// past its expiry still verifies.
///
/// In order, first failure returned: the script runs the hashlock template, its template hash
/// recomputed from its own bytes (`HTLC_NOT_HASHLOCK_VAULT`); it decodes (`HTLC_*`, `TERMS_*`);
/// its state is the agreed terms' (`VERIFY_TERMS_MISMATCH`, naming the fields that differ, in
/// state order, `counterpart` for the counterpart record's hash).
pub fn verify_revealed_script(
    terms: &ValidatedHtlcTerms,
    redeem_script: &[u8],
) -> Result<(), HtlcError> {
    let expected = HtlcVault::instantiate_existing(terms)?;
    if expected.redeem_script() == redeem_script {
        return Ok(());
    }
    let pinned = template::check()?.hash();
    if template::template_hash_of_instance(redeem_script).ok() != Some(pinned) {
        return Err(HtlcError::NotHashlockVault);
    }
    let decoded = template::decode(redeem_script)?;
    let agreed = terms.terms().state();
    if decoded != agreed {
        return Err(VerifyError::TermsMismatch {
            fields: differing_fields(&agreed, &decoded),
        }
        .into());
    }
    // Not reached: decoding is exact, so an equal state gives the expected script.
    Err(HtlcError::NonCanonical)
}

/// [`verify_revealed_script`] on the script a spent input reveals, bound to the UTXO the input
/// spends (`spent`, its scriptPublicKey as the node reports it), as v1's `verify_spent_input`.
///
/// In order, first failure returned: the signature script is push only and ends with a data push
/// (`VERIFY_NOTHING_REVEALED`); `spent` is the version 0 P2SH of that script
/// (`VERIFY_INPUT_NOT_VAULT`); then [`verify_revealed_script`].
pub fn verify_spent_input(
    terms: &ValidatedHtlcTerms,
    input: &TransactionInput,
    spent: &ScriptPublicKey,
) -> Result<(), HtlcError> {
    let script = revealed_script(&input.signature_script).ok_or(VerifyError::NothingRevealed)?;
    if *spent != pay_to_script_hash_script(script) {
        return Err(VerifyError::InputNotVault.into());
    }
    verify_revealed_script(terms, script)
}

/// The names of the state fields that differ, in state order. The pattern names every field, so
/// a new field fails to compile until it is listed.
fn differing_fields(a: &HtlcState, b: &HtlcState) -> Vec<&'static str> {
    let HtlcState {
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
        counterpart_hash,
        trade_ref,
    } = a;
    let mut out = Vec::new();
    let mut differ = |same: bool, name: &'static str| {
        if !same {
            out.push(name);
        }
    };
    differ(*version == b.version, "version");
    differ(*network == b.network, "network");
    differ(*nonce == b.nonce, "nonce");
    differ(*seller_key == b.seller_key, "seller_key");
    differ(*buyer_key == b.buyer_key, "buyer_key");
    differ(*asset_leg == b.asset_leg, "asset_leg");
    differ(*buyer_delivery == b.buyer_delivery, "buyer_delivery");
    differ(*seller_refund == b.seller_refund, "seller_refund");
    differ(*hash_lock == b.hash_lock, "hash_lock");
    differ(*expiry_daa == b.expiry_daa, "expiry_daa");
    differ(*counterpart_hash == b.counterpart_hash, "counterpart");
    differ(*trade_ref == b.trade_ref, "trade_ref");
    out
}

/// Whether `text` has the shape of a Kaspa address that rusty-kaspa a41a333 `Address::try_from`
/// parses without panicking: v1's check (crate::verify, spec/VERIFY.md "Before funding"),
/// restated so that no v1 file changes. A prefix, a colon, and the canonical number of lowercase
/// bech32 symbols for the version byte (53 payload symbols for PubKey and ScriptHash, 55 for
/// PubKeyECDSA, then 8 checksum symbols).
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
