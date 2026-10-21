// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashlock builders (spec/V2.md sections 10.4 and 10.5, D51): fund the vault (escrowed
//! token and authorizer, as v1's `fund_kcc20`), claim with the preimage (`settleWithPreimage`),
//! and refund (the seller after expiry_daa, with or without the token; the buyer at any time,
//! with it). Each checks its own inputs against the terms first, then plans the inputs and
//! outputs, then runs the checks every transaction shares, in v1's order and with v1's `TX_*`
//! codes (spec/TRANSACTIONS.md).
//!
//! The builders return an [`HtlcIpst`]: the terms, the unsigned transaction, the UTXOs it spends
//! and one signature slot per input, the in-memory form of spec/IPST.md. Its document form is the
//! command line's (D52). Keyless: signatures arrive as 65-byte values and are verified before
//! they are used.
//!
//! The transaction rules of v1 (minimum KAS per output, standard mass cap, relay fee, compute
//! budgets of KCC-20 spends) are restated here from crate::tx::rules, not changed, so that no v1
//! file is edited (spec/V2.md section 2).

use super::template::{self, refuse_mainnet, FundableHtlcVault, HtlcVault, CONTRACT_NAME};
use super::{check_preimage, HtlcError, ValidatedHtlcTerms};
use crate::bounds::MAX_VAULT_SPEND_INPUTS;
use crate::locktime::INPUT_SEQUENCE;
use crate::terms::{IdentifierType, Kcc20Owner, Kcc20Token, LegKind, Network};
use crate::tx::{
    min_output_value, min_relay_fee, p2pk, p2pk_key, push_data, sighash, verify_schnorr_sig65,
    FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, Masses, RefundEscrow, TokenUtxo, TxError,
    Utxo, KCC20_KEY_OWNED_BUDGET, KCC20_VAULT_OWNED_BUDGET, MIN_KCC20_OUTPUT, P2PK_BUDGET,
    STANDARD_MASS_CAP,
};
use kaspa_consensus_core::constants::{
    MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI, TX_VERSION_TOCCATA,
};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::{ComputeBudget, MassCalculator, ScriptUnits};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpData65;
use kaspa_txscript::script_class::ScriptClass;
use silverscript_abi::{encode_contract_entry_sig_script, ArtifactValue};
use std::collections::HashSet;

// =============================================================================================
// Compute budgets
// =============================================================================================

/// Floor of the compute budget of a `settleWithPreimage` input: 30,538 script units measured for
/// the fixture token (I18 contract step, budget 3), with margin.
pub const CLAIM_VAULT_BUDGET: u16 = 5;

/// Floor of the compute budget of a hashlock `refund` input: at most 130,741 script units
/// measured for the fixture token (budget 13), with margin.
pub const REFUND_VAULT_BUDGET: u16 = 16;

/// Script units of one signature check (v1, crate::tx::rules).
const SIGOP_SCRIPT_UNITS: u64 = 100_000;

/// Hashlock entry, per byte of the KCC-20 template it reads: the escrow read with
/// `readInputStateWithTemplate` and one output validated, as v1's vault (17).
const VAULT_UNITS_PER_TEMPLATE_BYTE: u64 = 17;

/// Hashlock entry, besides its signature check and the template bytes; v1's allowance.
const VAULT_FIXED_UNITS: u64 = 20_000;

/// KCC-20 `transfer` (v1, crate::tx::rules): per template byte, 2 for the spend and 4 more for
/// each covenant output the leader validates; 10,000 plus 1,000 per covenant input and output.
const KCC20_UNITS_PER_TEMPLATE_BYTE: u64 = 2;
const KCC20_UNITS_PER_TEMPLATE_BYTE_PER_OUTPUT: u64 = 4;
const KCC20_FIXED_UNITS: u64 = 10_000;
const KCC20_UNITS_PER_COVENANT_UTXO: u64 = 1_000;

fn covering(units: u64) -> u16 {
    ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map_or(u16::MAX, |b| b.value())
}

/// Budget of a hashlock vault input that reads `template_bytes` of KCC-20 template, with or
/// without a signature check.
fn vault_budget(signed: bool, template_bytes: u64) -> u16 {
    let units = (if signed { SIGOP_SCRIPT_UNITS } else { 0 } + VAULT_FIXED_UNITS)
        .saturating_add(VAULT_UNITS_PER_TEMPLATE_BYTE.saturating_mul(template_bytes));
    let floor = if signed {
        REFUND_VAULT_BUDGET
    } else {
        CLAIM_VAULT_BUDGET
    };
    covering(units).max(floor)
}

fn kcc20_leader_budget(
    key_owned: bool,
    template_bytes: u64,
    covenant_inputs: u64,
    covenant_outputs: u64,
) -> u16 {
    let per_byte = KCC20_UNITS_PER_TEMPLATE_BYTE
        .saturating_add(KCC20_UNITS_PER_TEMPLATE_BYTE_PER_OUTPUT.saturating_mul(covenant_outputs));
    let units = (if key_owned { SIGOP_SCRIPT_UNITS } else { 0 } + KCC20_FIXED_UNITS)
        .saturating_add(
            KCC20_UNITS_PER_COVENANT_UTXO
                .saturating_mul(covenant_inputs.saturating_add(covenant_outputs)),
        )
        .saturating_add(per_byte.saturating_mul(template_bytes));
    let floor = if key_owned {
        KCC20_KEY_OWNED_BUDGET
    } else {
        KCC20_VAULT_OWNED_BUDGET
    };
    covering(units).max(floor)
}

fn kcc20_delegate_budget(template_bytes: u64) -> u16 {
    covering(
        (SIGOP_SCRIPT_UNITS + KCC20_FIXED_UNITS)
            .saturating_add(KCC20_UNITS_PER_TEMPLATE_BYTE.saturating_mul(template_bytes)),
    )
    .max(KCC20_KEY_OWNED_BUDGET)
}

// =============================================================================================
// Builders
// =============================================================================================

/// Who signs a hashlock refund (spec/V2.md section 10.4, `[HR1]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcRefundSigner {
    /// The seller: from expiry_daa (lock time expiry_daa), with the escrowed token or without it.
    Seller,
    /// The buyer: at any time (lock time 0), always with the escrowed token at exactly the amount.
    Buyer,
}

/// Funds the hashlock vault (spec/V2.md section 10.5, step 2), as v1's `fund_kcc20`: output 0
/// the escrowed token (exactly the amount, owned by the vault's script hash, carrying `carrier`
/// KAS), output 1 the authorizer at the vault's address, then the token change back to the
/// depositor's key if the tokens hold more, then KAS change. Lock time 0.
///
/// In order, first failure returned: the vault is the terms' (`TX_VAULT_MISMATCH`); the current
/// DAA score is below expiry_daa (`TX_EXPIRED`); the template is the asset's
/// (`TX_TOKEN_TEMPLATE`); the token inputs (`TX_TOKEN_INPUT`); the outputs' minimum KAS
/// (`TX_BELOW_MIN_KAS`); then the shared checks.
pub fn fund(
    terms: &ValidatedHtlcTerms,
    vault: &FundableHtlcVault,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<HtlcIpst, HtlcError> {
    refuse_mainnet(terms)?;
    if HtlcVault::instantiate_existing(terms)? != *vault.vault() {
        return Err(TxError::VaultMismatch.into());
    }
    fund_at(
        terms,
        vault.vault(),
        template,
        deposit,
        funding,
        current_daa,
    )
}

fn fund_at(
    terms: &ValidatedHtlcTerms,
    vault: &HtlcVault,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<HtlcIpst, HtlcError> {
    let t = terms.terms();
    let token = asset_token(terms);
    if current_daa >= t.expiry_daa {
        return Err(TxError::Expired {
            current_daa,
            expiry_daa: t.expiry_daa,
        }
        .into());
    }
    template.check_token(&token)?;
    let owner = own_tokens(&deposit.tokens, &token, template)?;
    let amount = t.asset_leg.amount;
    let held = deposit
        .tokens
        .iter()
        .try_fold(0u64, |sum, tok| sum.checked_add(tok.state.amount))
        .filter(|sum| *sum <= i64::MAX as u64)
        .ok_or(TxError::TokenInput {
            index: 0,
            reason: "the token amounts add up past the script integer range",
        })?;
    if held < amount {
        return Err(TxError::TokenInput {
            index: 0,
            reason: "the token inputs hold less than the leg amount",
        }
        .into());
    }
    let escrow_state = Kcc20State::new(script_hash_owner(vault), amount);
    let mut new_states = vec![escrow_state];
    let mut outputs = vec![
        token_output(
            deposit.carrier,
            template.script_public_key(&escrow_state)?,
            &token,
            0,
        ),
        TransactionOutput::new(deposit.authorizer, vault.script_public_key()),
    ];
    for (i, output) in outputs.iter().enumerate() {
        check_min(output, i)?;
    }
    if held > amount {
        let change = Kcc20State::new(owner, held - amount);
        new_states.push(change);
        outputs.push(token_output(
            MIN_KCC20_OUTPUT,
            template.script_public_key(&change)?,
            &token,
            0,
        ));
    }
    let signer = owner.identifier;
    let bytes = template_bytes(&token);
    let leader_budget = kcc20_leader_budget(
        true,
        bytes,
        deposit.tokens.len() as u64,
        new_states.len() as u64,
    );
    let mut inputs = Vec::with_capacity(deposit.tokens.len());
    for (i, tok) in deposit.tokens.iter().enumerate() {
        let (spend, budget) = if i == 0 {
            let spend = signed(signer, |sig| {
                template.leader_sigscript(&tok.state, &new_states, sig, 0)
            })?;
            (spend, leader_budget)
        } else {
            let spend = signed(signer, |sig| {
                template.delegate_sigscript(&tok.state, sig, 0)
            })?;
            (spend, kcc20_delegate_budget(bytes))
        };
        inputs.push(planned(&tok.utxo, budget, spend));
    }
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: 0,
            max_inputs: None,
        },
        funding,
    )
}

/// The claim (spec/V2.md section 10.4, `settleWithPreimage`): input 0 the vault's authorizer,
/// input 1 the escrowed token (a `transfer` leader with the vault input as witness), then the fee
/// inputs; output 0 the asset to buyer_delivery (exactly the amount, carrying at least the
/// escrow's KAS), output 1 the authorizer's KAS to the seller's key (at least in full), then the
/// change. Lock time 0. No signature but the fee payer's: anyone holding the preimage may submit.
///
/// The preimage is the secret the seller revealed on the counterpart chain; it travels in the
/// vault input's signature script, as the contract needs it.
///
/// In order, first failure returned: the preimage (`HTLC_SECRET_LENGTH`, `HTLC_SECRET_MISMATCH`);
/// the template is the asset's (`TX_TOKEN_TEMPLATE`); the authorizer is a plain UTXO at the
/// vault (`TX_NOT_AT_VAULT`); the escrow is the vault's token holding exactly the amount
/// (`TX_ESCROW_MISMATCH`); then the shared checks. Not refused after expiry_daa: the claim stays
/// valid then (spec/V2.md section 10.6, R4).
pub fn claim(
    terms: &ValidatedHtlcTerms,
    authorizer: &Utxo,
    escrow: &Utxo,
    template: &Kcc20Template,
    preimage: &[u8],
    fee: &FeePayment,
) -> Result<HtlcIpst, HtlcError> {
    check_preimage(terms, preimage)?;
    let t = terms.terms();
    let token = asset_token(terms);
    template.check_token(&token)?;
    let vault = HtlcVault::instantiate_existing(terms)?;
    at_vault(authorizer, &vault, "authorizer")?;
    let amount = t.asset_leg.amount;
    let escrow_state = Kcc20State::new(script_hash_owner(&vault), amount);
    escrow_at(escrow, &token, template, &escrow_state, "escrow")?;
    let delivered = Kcc20State::new(t.buyer_delivery, amount);
    let bytes = template_bytes(&token);
    let inputs = vec![
        planned(
            authorizer,
            vault_budget(false, bytes),
            Spend::Complete(vault_entry(
                &vault,
                "settleWithPreimage",
                vec![ArtifactValue::Bytes(preimage.to_vec())],
            )?),
        ),
        planned(
            escrow,
            kcc20_leader_budget(false, bytes, 1, 1),
            Spend::Complete(template.leader_sigscript(&escrow_state, &[delivered], &[0; 65], 0)?),
        ),
    ];
    let outputs = vec![
        topped_up(token_output(
            escrow.entry.amount,
            template.script_public_key(&delivered)?,
            &token,
            1,
        )),
        topped_up(TransactionOutput::new(
            authorizer.entry.amount,
            p2pk(&t.seller_key),
        )),
    ];
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: 0,
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

/// A hashlock refund (spec/V2.md section 10.4, `refund`): input 0 the vault UTXO, output 0 its
/// KAS, whole, to the seller's key. The escrowed token, when included, rides at input 1 and goes
/// home whole (amount, minter flag and at least its own KAS) to seller_refund at output 1. Lock
/// time expiry_daa for the seller, 0 for the buyer.
///
/// Without the token (`escrow` None, the seller only) the authorizer goes home alone and the
/// token stays owned by the vault's script hash until the seller funds a new authorizer at the
/// vault address and refunds that one with it.
///
/// In order, first failure returned: the vault UTXO is a plain UTXO at the vault
/// (`TX_NOT_AT_VAULT`); the buyer refunds with the token (`TX_REFUND_SIGNER`); the template is
/// the asset's (`TX_TOKEN_TEMPLATE`); the token is the vault's, holding the stated amount and
/// minter flag (`TX_ESCROW_MISMATCH`); in the buyer's refund exactly the amount
/// (`TX_LEG_AMOUNT`); then the shared checks.
pub fn refund(
    terms: &ValidatedHtlcTerms,
    signer: HtlcRefundSigner,
    vault_utxo: &Utxo,
    escrow: Option<&RefundEscrow<'_>>,
    fee: &FeePayment,
) -> Result<HtlcIpst, HtlcError> {
    let t = terms.terms();
    let vault = HtlcVault::instantiate_existing(terms)?;
    let signer_key = match signer {
        HtlcRefundSigner::Seller => t.seller_key,
        HtlcRefundSigner::Buyer => t.buyer_key,
    };
    at_vault(vault_utxo, &vault, "vault")?;
    let token = asset_token(terms);
    let read_bytes = escrow.map_or(0, |_| template_bytes(&token));
    let mut inputs = vec![planned(
        vault_utxo,
        vault_budget(true, read_bytes),
        signed(signer_key, |sig| {
            vault_entry(
                &vault,
                "refund",
                vec![
                    ArtifactValue::Bytes(sig.to_vec()),
                    ArtifactValue::Bytes(signer_key.to_vec()),
                ],
            )
        })?,
    )];
    let mut outputs = vec![TransactionOutput::new(
        vault_utxo.entry.amount,
        p2pk(&t.seller_key),
    )];
    match escrow {
        None if signer == HtlcRefundSigner::Buyer => {
            return Err(TxError::RefundSigner {
                reason: "the buyer's refund takes the escrowed token home with it",
            }
            .into());
        }
        None => {}
        Some(e) => {
            e.template.check_token(&token)?;
            let held = Kcc20State {
                owner: script_hash_owner(&vault),
                amount: e.amount,
                is_minter: e.is_minter,
            };
            escrow_at(&e.utxo, &token, e.template, &held, "escrowed token")?;
            if signer == HtlcRefundSigner::Buyer && e.amount != t.asset_leg.amount {
                return Err(TxError::LegAmount {
                    input: "escrowed token",
                    expected: t.asset_leg.amount,
                    found: e.amount,
                }
                .into());
            }
            let home = Kcc20State {
                owner: t.seller_refund,
                ..held
            };
            inputs.push(planned(
                &e.utxo,
                kcc20_leader_budget(false, template_bytes(&token), 1, 1),
                Spend::Complete(e.template.leader_sigscript(&held, &[home], &[0; 65], 0)?),
            ));
            outputs.push(topped_up(token_output(
                e.utxo.entry.amount,
                e.template.script_public_key(&home)?,
                &token,
                1,
            )));
        }
    }
    let lock_time = match signer {
        HtlcRefundSigner::Seller => t.expiry_daa,
        HtlcRefundSigner::Buyer => 0,
    };
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time,
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

// =============================================================================================
// Checks on the inputs
// =============================================================================================

/// The asset token of structure-checked terms.
fn asset_token(terms: &ValidatedHtlcTerms) -> Kcc20Token {
    match terms.terms().asset_leg.kind {
        LegKind::Kcc20(token) => token,
        _ => unreachable!("the structure checks make the asset leg KCC-20"),
    }
}

/// A plain UTXO at the vault's P2SH (the authorizer, a vault UTXO to refund).
fn at_vault(utxo: &Utxo, vault: &HtlcVault, input: &'static str) -> Result<(), HtlcError> {
    if utxo.entry.script_public_key != vault.script_public_key() || utxo.entry.covenant_id.is_some()
    {
        return Err(TxError::NotAtVault { input }.into());
    }
    Ok(())
}

/// The vault's escrowed token: the asset covenant, and the P2SH of the template holding `state`.
fn escrow_at(
    utxo: &Utxo,
    token: &Kcc20Token,
    template: &Kcc20Template,
    state: &Kcc20State,
    input: &'static str,
) -> Result<(), HtlcError> {
    if state.amount > i64::MAX as u64
        || utxo.entry.covenant_id != Some(Hash::from_bytes(token.covenant_id))
        || utxo.entry.script_public_key != template.script_public_key(state)?
    {
        return Err(TxError::EscrowMismatch { input }.into());
    }
    Ok(())
}

/// The depositor's own token inputs (`TX_TOKEN_INPUT`), as v1's fund_kcc20 checks them; returns
/// their common owner.
fn own_tokens(
    tokens: &[TokenUtxo],
    token: &Kcc20Token,
    template: &Kcc20Template,
) -> Result<Kcc20Owner, HtlcError> {
    let first = tokens.first().ok_or(TxError::TokenInput {
        index: 0,
        reason: "no token input",
    })?;
    for (index, tok) in tokens.iter().enumerate() {
        let refuse = |reason| -> HtlcError { TxError::TokenInput { index, reason }.into() };
        if tok.utxo.entry.covenant_id != Some(Hash::from_bytes(token.covenant_id)) {
            return Err(refuse("not of the leg's covenant"));
        }
        if tok.state.owner.identifier_type != IdentifierType::PubKey {
            return Err(refuse("the owner is not a public key"));
        }
        if secp256k1::XOnlyPublicKey::from_slice(&tok.state.owner.identifier).is_err() {
            return Err(refuse("the owner is not a valid x-only key"));
        }
        if tok.state.is_minter {
            return Err(refuse("a minter"));
        }
        if tok.state.amount == 0 || tok.state.amount > i64::MAX as u64 {
            return Err(refuse(
                "the amount is zero or past the script integer range",
            ));
        }
        if tok.utxo.entry.script_public_key != template.script_public_key(&tok.state)? {
            return Err(refuse(
                "the script is not the template holding the stated state",
            ));
        }
        if tok.state.owner != first.state.owner {
            return Err(refuse("the token inputs have different owners"));
        }
    }
    Ok(first.state.owner)
}

/// The key of a KAS input: a version-0 P2PK Schnorr UTXO with no covenant (`TX_KAS_INPUT`).
fn kas_key(utxo: &Utxo, index: usize) -> Result<[u8; 32], HtlcError> {
    let refuse = |reason| -> HtlcError { TxError::KasInput { index, reason }.into() };
    if utxo.entry.covenant_id.is_some() {
        return Err(refuse("carries a covenant ID"));
    }
    let key = p2pk_key(&utxo.entry.script_public_key)
        .ok_or_else(|| refuse("not a version-0 P2PK Schnorr scriptPubKey"))?;
    if secp256k1::XOnlyPublicKey::from_slice(&key).is_err() {
        return Err(refuse("the P2PK key is not a valid x-only key"));
    }
    Ok(key)
}

// =============================================================================================
// Outputs
// =============================================================================================

fn template_bytes(token: &Kcc20Token) -> u64 {
    u64::from(token.template_prefix_len) + u64::from(token.template_suffix_len)
}

/// The SCRIPT_HASH owner the vault's escrowed token has.
fn script_hash_owner(vault: &HtlcVault) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

fn token_output(
    value: u64,
    spk: ScriptPublicKey,
    token: &Kcc20Token,
    authorizing_input: u16,
) -> TransactionOutput {
    TransactionOutput {
        value,
        script_public_key: spk,
        covenant: Some(CovenantBinding::new(
            authorizing_input,
            Hash::from_bytes(token.covenant_id),
        )),
    }
}

/// A pass-through output holding less than its minimum KAS is topped up to it from the fee
/// inputs, where the contract checks "at least" (`[HD2]`, `[HS9]`, `[HR13]`). The refund's
/// output 0 must equal its input (`[HR5]`) and is never topped up.
fn topped_up(mut output: TransactionOutput) -> TransactionOutput {
    output.value = output.value.max(min_output_value(&output));
    output
}

fn check_min(output: &TransactionOutput, index: usize) -> Result<(), HtlcError> {
    let minimum = min_output_value(output);
    if output.value < minimum {
        return Err(TxError::BelowMinKas {
            output: index,
            value: output.value,
            minimum,
        }
        .into());
    }
    Ok(())
}

// =============================================================================================
// Spends
// =============================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
enum Spend {
    Signed {
        signer: [u8; 32],
        before: Vec<u8>,
        after: Vec<u8>,
    },
    Complete(Vec<u8>),
}

struct PlannedInput {
    utxo: Utxo,
    budget: u16,
    spend: Spend,
}

fn planned(utxo: &Utxo, budget: u16, spend: Spend) -> PlannedInput {
    PlannedInput {
        utxo: utxo.clone(),
        budget,
        spend,
    }
}

/// Encodes the signature script with two different placeholder signatures and splits it around
/// the one 65-byte push where they differ (v1's method).
fn signed(
    signer: [u8; 32],
    encode: impl Fn(&[u8; 65]) -> Result<Vec<u8>, TxError>,
) -> Result<Spend, HtlcError> {
    let a = encode(&[0x00; 65])?;
    let b = encode(&[0xFF; 65])?;
    let fault = || -> HtlcError {
        TxError::Encoding {
            reason: "the signature is not one 65-byte push in the signature script".into(),
        }
        .into()
    };
    if a.len() != b.len() {
        return Err(fault());
    }
    let first = a
        .iter()
        .zip(&b)
        .position(|(x, y)| x != y)
        .ok_or_else(fault)?;
    let last = a
        .iter()
        .zip(&b)
        .rposition(|(x, y)| x != y)
        .ok_or_else(fault)?;
    if last + 1 - first != 65 || first == 0 || a[first - 1] != OpData65 {
        return Err(fault());
    }
    Ok(Spend::Signed {
        signer,
        before: a[..first - 1].to_vec(),
        after: a[first + 65..].to_vec(),
    })
}

fn vault_entry(
    vault: &HtlcVault,
    entry: &str,
    args: Vec<ArtifactValue>,
) -> Result<Vec<u8>, TxError> {
    let template = template::check().map_err(|e| TxError::Encoding {
        reason: e.to_string(),
    })?;
    let mut script = encode_contract_entry_sig_script(template.abi(), CONTRACT_NAME, entry, &args)
        .map_err(|e| TxError::Encoding {
            reason: format!("ImpulseHashlock {entry}: {e}"),
        })?;
    script.extend_from_slice(&push_data(vault.redeem_script())?);
    Ok(script)
}

// =============================================================================================
// The shared checks
// =============================================================================================

struct Plan<'t> {
    terms: &'t ValidatedHtlcTerms,
    inputs: Vec<PlannedInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    /// The most inputs the vault template the transaction spends allows, if it sets a bound.
    max_inputs: Option<usize>,
}

/// v1's `finish` (crate::tx), restated: appends the fee inputs and the change, then checks, in
/// order: the fee inputs (`TX_KAS_INPUT`), at most the inputs the spent vault template allows
/// (`TX_TOO_MANY_INPUTS`), no outpoint twice (`TX_DUPLICATE_INPUT`), every spent value
/// (`TX_UTXO_VALUE`), the change script (`TX_NONSTANDARD_CHANGE`), enough funds
/// (`TX_INSUFFICIENT_FUNDS`), the change minimum (`TX_BELOW_MIN_KAS`); builds the unsigned
/// transaction and each slot's sighash; then the masses (`TX_MASS`) and the relay fee
/// (`TX_FEE_TOO_LOW`).
fn finish(mut plan: Plan<'_>, fee: &FeePayment) -> Result<HtlcIpst, HtlcError> {
    let first_fee = plan.inputs.len();
    if fee.inputs.is_empty() {
        return Err(TxError::KasInput {
            index: first_fee,
            reason: "no fee input",
        }
        .into());
    }
    for (i, utxo) in fee.inputs.iter().enumerate() {
        let key = kas_key(utxo, first_fee + i)?;
        plan.inputs.push(planned(
            utxo,
            P2PK_BUDGET,
            Spend::Signed {
                signer: key,
                before: vec![],
                after: vec![],
            },
        ));
    }
    if let Some(max) = plan.max_inputs {
        if plan.inputs.len() > max {
            return Err(TxError::TooManyInputs {
                inputs: plan.inputs.len(),
                max,
            }
            .into());
        }
    }
    let mut seen = HashSet::new();
    for (index, input) in plan.inputs.iter().enumerate() {
        if !seen.insert(input.utxo.outpoint) {
            return Err(TxError::DuplicateInput { index }.into());
        }
    }
    let mut available: u64 = 0;
    for (index, input) in plan.inputs.iter().enumerate() {
        let value = input.utxo.entry.amount;
        if value == 0 || value > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: Some(index),
                value,
            }
            .into());
        }
        available += value;
        if available > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: None,
                value: available,
            }
            .into());
        }
    }
    if fee.change.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION
        || ScriptClass::from_script(&fee.change) == ScriptClass::NonStandard
    {
        return Err(TxError::NonstandardChange.into());
    }
    let needed = plan
        .outputs
        .iter()
        .map(|o| o.value)
        .chain([fee.fee])
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or(TxError::InsufficientFunds {
            available,
            needed: u64::MAX,
        })?;
    if available < needed {
        return Err(TxError::InsufficientFunds { available, needed }.into());
    }
    if available > needed {
        let change = TransactionOutput::new(available - needed, fee.change.clone());
        check_min(&change, plan.outputs.len())?;
        plan.outputs.push(change);
    }

    let entries: Vec<UtxoEntry> = plan.inputs.iter().map(|i| i.utxo.entry.clone()).collect();
    let tx_inputs: Vec<TransactionInput> = plan
        .inputs
        .iter()
        .map(|i| {
            TransactionInput::new_with_compute_budget(
                i.utxo.outpoint,
                vec![],
                INPUT_SEQUENCE,
                i.budget,
            )
        })
        .collect();
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        tx_inputs,
        plan.outputs,
        plan.lock_time,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut slots: Vec<HtlcSlot> = plan
        .inputs
        .into_iter()
        .map(|i| match i.spend {
            Spend::Signed {
                signer,
                before,
                after,
            } => HtlcSlot {
                signer: Some(signer),
                sighash: None,
                signature: None,
                before,
                after,
            },
            Spend::Complete(script) => HtlcSlot {
                signer: None,
                sighash: None,
                signature: None,
                before: script,
                after: vec![],
            },
        })
        .collect();
    for (index, slot) in slots.iter_mut().enumerate() {
        if slot.signer.is_some() {
            slot.sighash = Some(sighash(&tx, &entries, index)?);
        }
    }
    let ipst = HtlcIpst {
        terms: plan.terms.clone(),
        tx,
        entries,
        slots,
    };
    let masses = ipst.masses();
    check_masses(&masses)?;
    let minimum = min_relay_fee(masses.fee_mass);
    if fee.fee < minimum {
        return Err(TxError::FeeTooLow {
            fee: fee.fee,
            minimum,
        }
        .into());
    }
    Ok(ipst)
}

/// The masses of `sized` with the pinned calculator and the network's parameters (v1's rule).
fn compute_masses(sized: &Transaction, entries: &[UtxoEntry], network: Network) -> Masses {
    let params = super::margin::params(network);
    let calculator = MassCalculator::new_with_consensus_params(params);
    let non_contextual = calculator.calc_non_contextual_masses(sized);
    let populated = PopulatedTransaction::new(sized, entries.to_vec());
    let storage = calculator
        .calc_contextual_masses(&populated)
        .map_or(u64::MAX, |m| m.storage_mass);
    let cofactors = params.mempool_block_mass_cofactors().raw_post();
    let fee_mass = non_contextual
        .compute_mass
        .max(non_contextual.normalized_transient(&cofactors));
    Masses {
        compute: non_contextual.compute_mass,
        transient: non_contextual.transient_mass,
        storage,
        fee_mass,
    }
}

/// Refuses any mass dimension above the standard cap (`TX_MASS`), in the order compute,
/// transient, storage (v1's rule).
fn check_masses(masses: &Masses) -> Result<(), TxError> {
    for (dimension, mass) in [
        ("compute", masses.compute),
        ("transient", masses.transient),
        ("storage", masses.storage),
    ] {
        if mass > STANDARD_MASS_CAP {
            return Err(TxError::Mass {
                dimension,
                mass,
                cap: STANDARD_MASS_CAP,
            });
        }
    }
    Ok(())
}

// =============================================================================================
// The partially signed transaction
// =============================================================================================

/// One input's signature slot: who signs (if anyone), the sighash, the signature once given, and
/// the signature-script bytes around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcSlot {
    signer: Option<[u8; 32]>,
    sighash: Option<[u8; 32]>,
    signature: Option<[u8; 65]>,
    before: Vec<u8>,
    after: Vec<u8>,
}

impl HtlcSlot {
    /// The x-only key whose signature fills this slot; None when the input needs none.
    pub fn signer(&self) -> Option<[u8; 32]> {
        self.signer
    }

    /// The SIG_HASH_ALL sighash the signer signs; present exactly when there is a signer.
    pub fn sighash(&self) -> Option<[u8; 32]> {
        self.sighash
    }

    /// The signature, once given and verified.
    pub fn signature(&self) -> Option<[u8; 65]> {
        self.signature
    }

    /// Signature-script bytes before the signature push (the whole script without a signer).
    pub fn script_before(&self) -> &[u8] {
        &self.before
    }

    /// Signature-script bytes after the signature push.
    pub fn script_after(&self) -> &[u8] {
        &self.after
    }

    fn script_with(&self, sig: &[u8; 65]) -> Vec<u8> {
        if self.signer.is_none() {
            return self.before.clone();
        }
        let mut script = Vec::with_capacity(self.before.len() + 66 + self.after.len());
        script.extend_from_slice(&self.before);
        script.push(OpData65);
        script.extend_from_slice(sig);
        script.extend_from_slice(&self.after);
        script
    }
}

/// One input's slot as a document states it, for [`HtlcIpst::from_parts`], which checks it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HtlcSlotParts {
    pub signer: Option<[u8; 32]>,
    pub sighash: Option<[u8; 32]>,
    pub signature: Option<[u8; 65]>,
    pub script_before: Vec<u8>,
    pub script_after: Vec<u8>,
}

/// A hashlock transaction from the builders: the terms, the unsigned transaction, the UTXOs it
/// spends and one signature slot per input. Signed slot by slot with
/// [`HtlcIpst::add_signature`], turned into the signed transaction with [`HtlcIpst::finalize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcIpst {
    terms: ValidatedHtlcTerms,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    slots: Vec<HtlcSlot>,
}

/// Which builder makes a hashlock transaction, as the terms check finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcIpstKind {
    Fund,
    Claim,
    Refund {
        signer: HtlcRefundSigner,
        with_token: bool,
    },
}

/// A transaction that passed the terms check: which builder makes it, its fee, and the output
/// after the trade outputs, if any (the change, for the payer to confirm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcTermsMatch {
    pub kind: HtlcIpstKind,
    pub fee: u64,
    pub change: Option<TransactionOutput>,
}

impl HtlcIpst {
    pub fn terms(&self) -> &ValidatedHtlcTerms {
        &self.terms
    }

    /// The unsigned transaction (empty signature scripts).
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// The UTXO each input spends, in input order.
    pub fn entries(&self) -> &[UtxoEntry] {
        &self.entries
    }

    /// The signature slots, in input order.
    pub fn slots(&self) -> &[HtlcSlot] {
        &self.slots
    }

    /// The masses of the signed transaction (every signature is 65 bytes).
    pub fn masses(&self) -> Masses {
        let mut sized = self.tx.clone();
        for (input, slot) in sized.inputs.iter_mut().zip(&self.slots) {
            input.signature_script = slot.script_with(&[0; 65]);
        }
        compute_masses(&sized, &self.entries, self.terms.terms().network)
    }

    /// What the inputs hold less what the outputs pay.
    pub fn fee(&self) -> u64 {
        let held = self
            .entries
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(e.amount));
        let paid = self
            .tx
            .outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.value));
        match (held, paid) {
            (Some(held), Some(paid)) => held.saturating_sub(paid),
            _ => 0,
        }
    }

    /// Inputs whose slot needs a signature and has none yet.
    pub fn pending(&self) -> Vec<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.signer.is_some() && s.signature.is_none())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.pending().is_empty()
    }

    /// Verifies a 65-byte signature against the slot's signer and sighash and stores it
    /// (`TX_SIGNATURE`); a slot that does not exist or takes none is `TX_SIGNATURE_SLOT`.
    pub fn add_signature(&mut self, input: usize, sig65: &[u8]) -> Result<(), HtlcError> {
        let slot = self.slots.get_mut(input).ok_or(TxError::SignatureSlot {
            input,
            reason: "no such input",
        })?;
        let (Some(signer), Some(hash)) = (slot.signer, slot.sighash) else {
            return Err(TxError::SignatureSlot {
                input,
                reason: "this input takes no signature",
            }
            .into());
        };
        verify_schnorr_sig65(&signer, &hash, sig65).map_err(|e| match e {
            TxError::Signature { reason, .. } => TxError::Signature {
                input: Some(input),
                reason,
            },
            other => other,
        })?;
        slot.signature = Some(sig65.try_into().expect("verified as 65 bytes"));
        Ok(())
    }

    /// The signed transaction: every slot with a signer holds a signature
    /// (`TX_SIGNATURE_SLOT`); then the masses (`TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`)
    /// are checked again, as v1's finalize does.
    pub fn finalize(&self) -> Result<Transaction, HtlcError> {
        let mut tx = self.tx.clone();
        for (input, (slot, tx_input)) in self.slots.iter().zip(tx.inputs.iter_mut()).enumerate() {
            let sig = match (slot.signer, slot.signature) {
                (Some(_), Some(sig)) => sig,
                (Some(_), None) => {
                    return Err(TxError::SignatureSlot {
                        input,
                        reason: "the signature is missing",
                    }
                    .into())
                }
                (None, _) => [0; 65],
            };
            tx_input.signature_script = slot.script_with(&sig);
        }
        tx.finalize();
        let masses = self.masses();
        check_masses(&masses)?;
        let (fee, minimum) = (self.fee(), min_relay_fee(masses.fee_mass));
        if fee < minimum {
            return Err(TxError::FeeTooLow { fee, minimum }.into());
        }
        Ok(tx)
    }

    /// Assembles the signed transaction from `(input, signature)` pairs: each verified as
    /// [`HtlcIpst::add_signature`] does, then [`HtlcIpst::finalize`].
    pub fn assemble(&self, signatures: &[(usize, &[u8])]) -> Result<Transaction, HtlcError> {
        let mut ipst = self.clone();
        for (input, sig) in signatures {
            ipst.add_signature(*input, sig)?;
        }
        ipst.finalize()
    }

    /// A hashlock document read back from its parts (spec/V2.md section 10.9, the version 3
    /// document of spec/IPST.md): the reading steps of spec/IPST.md after the terms decoded. In
    /// order, first failure returned: inputs and outputs not empty, every UTXO amount and output
    /// value above zero and at most `MAX_SOMPI`, their totals within it and the outputs no more
    /// than the inputs, each output's authorizing input in range, the slots' shape
    /// (`IPST_MALFORMED`); every stated sighash recomputed (`IPST_SIGHASH_MISMATCH`); every
    /// present signature verified (`TX_SIGNATURE`). Nothing a document states is trusted.
    pub fn from_parts(
        terms: ValidatedHtlcTerms,
        lock_time: u64,
        inputs: Vec<(TransactionInput, UtxoEntry, HtlcSlotParts)>,
        outputs: Vec<TransactionOutput>,
    ) -> Result<Self, HtlcError> {
        let malformed = |reason: String| -> HtlcError { TxError::IpstMalformed { reason }.into() };
        if inputs.is_empty() || outputs.is_empty() {
            return Err(malformed("inputs and outputs must not be empty".into()));
        }
        let in_range = |v: u64| v > 0 && v <= MAX_SOMPI;
        // Each running total stays at most MAX_SOMPI, so neither addition overflows.
        let mut held: u64 = 0;
        for (n, (_, entry, _)) in inputs.iter().enumerate() {
            if !in_range(entry.amount) {
                return Err(malformed(format!(
                    "input {n}: amount outside 1 to MAX_SOMPI"
                )));
            }
            held += entry.amount;
            if held > MAX_SOMPI {
                return Err(malformed("the UTXO amounts add up past MAX_SOMPI".into()));
            }
        }
        let mut paid: u64 = 0;
        for (n, output) in outputs.iter().enumerate() {
            if !in_range(output.value) {
                return Err(malformed(format!(
                    "output {n}: value outside 1 to MAX_SOMPI"
                )));
            }
            if output
                .covenant
                .is_some_and(|c| usize::from(c.authorizing_input) >= inputs.len())
            {
                return Err(malformed(format!(
                    "output {n}: authorizing_input names no input"
                )));
            }
            paid += output.value;
            if paid > held {
                return Err(malformed(
                    "the outputs pay more than the inputs hold".into(),
                ));
            }
        }
        let mut tx_inputs = Vec::with_capacity(inputs.len());
        let mut entries = Vec::with_capacity(inputs.len());
        let mut slots = Vec::with_capacity(inputs.len());
        for (n, (mut input, entry, parts)) in inputs.into_iter().enumerate() {
            match (parts.signer, parts.sighash) {
                (None, None) => {
                    if parts.signature.is_some() {
                        return Err(malformed(format!(
                            "input {n}: a signature without a signer"
                        )));
                    }
                    if !parts.script_after.is_empty() {
                        return Err(malformed(format!(
                            "input {n}: script_after is not empty without a signer"
                        )));
                    }
                }
                (Some(signer), Some(_)) => {
                    if secp256k1::XOnlyPublicKey::from_slice(&signer).is_err() {
                        return Err(malformed(format!(
                            "input {n}: the signer is not a valid x-only key"
                        )));
                    }
                }
                _ => {
                    return Err(malformed(format!(
                        "input {n}: signer and sighash must be present together"
                    )))
                }
            }
            input.signature_script = vec![];
            tx_inputs.push(input);
            entries.push(entry);
            slots.push(HtlcSlot {
                signer: parts.signer,
                sighash: parts.sighash,
                signature: parts.signature,
                before: parts.script_before,
                after: parts.script_after,
            });
        }
        let tx = Transaction::new(
            TX_VERSION_TOCCATA,
            tx_inputs,
            outputs,
            lock_time,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        for (input, slot) in slots.iter().enumerate() {
            if let Some(stated) = slot.sighash {
                if sighash(&tx, &entries, input)? != stated {
                    return Err(TxError::IpstSighashMismatch { input }.into());
                }
            }
        }
        for (input, slot) in slots.iter().enumerate() {
            if let (Some(signer), Some(hash), Some(sig)) =
                (slot.signer, slot.sighash, slot.signature)
            {
                verify_schnorr_sig65(&signer, &hash, &sig).map_err(|e| match e {
                    TxError::Signature { reason, .. } => TxError::Signature {
                        input: Some(input),
                        reason,
                    },
                    other => other,
                })?;
            }
        }
        Ok(Self {
            terms,
            tx,
            entries,
            slots,
        })
    }

    /// The terms check: whether this is the transaction the builders make for its terms from its
    /// own inputs (the trade UTXOs where the layout puts them, the token states from the redeem
    /// scripts the token inputs carry, the preimage from the claim's signature script, the fee
    /// inputs after them, this transaction's fee and change destination). Everything but the
    /// signatures is compared byte for byte. A signer runs it before signing, a submitter before
    /// broadcast.
    ///
    /// A builder's refusal of these inputs keeps its code; any other difference, or inputs no
    /// builder lays out this way, is `IPST_TERMS_MISMATCH`.
    pub fn verify_against_terms(
        &self,
        template: &Kcc20Template,
        current_daa: u64,
    ) -> Result<HtlcTermsMatch, HtlcError> {
        let (kind, trade_outputs, rebuilt) = self.rebuild(template, current_daa)?;
        let same_slots = rebuilt.slots.len() == self.slots.len()
            && rebuilt.slots.iter().zip(&self.slots).all(|(a, b)| {
                a.signer == b.signer
                    && a.sighash == b.sighash
                    && a.before == b.before
                    && a.after == b.after
            });
        if rebuilt.tx != self.tx || rebuilt.entries != self.entries || !same_slots {
            return Err(mismatch(
                "the document is not the transaction the builders make from its inputs",
            ));
        }
        Ok(HtlcTermsMatch {
            kind,
            fee: self.fee(),
            change: self.tx.outputs.get(trade_outputs).cloned(),
        })
    }

    fn rebuild(
        &self,
        template: &Kcc20Template,
        current_daa: u64,
    ) -> Result<(HtlcIpstKind, usize, HtlcIpst), HtlcError> {
        let terms = &self.terms;
        let t = terms.terms();
        let token = asset_token(terms);
        let cov = Some(Hash::from_bytes(token.covenant_id));
        let utxos: Vec<Utxo> = self
            .tx
            .inputs
            .iter()
            .zip(&self.entries)
            .map(|(input, entry)| Utxo {
                outpoint: input.previous_outpoint,
                entry: entry.clone(),
            })
            .collect();
        let unknown = || mismatch("not a transaction the builders make for these terms");
        let input = |i: usize| utxos.get(i).cloned().ok_or_else(unknown);
        let fee = |trade_inputs: usize, trade_outputs: usize| FeePayment {
            inputs: utxos.get(trade_inputs..).unwrap_or_default().to_vec(),
            fee: self.fee(),
            change: self
                .tx
                .outputs
                .get(trade_outputs)
                .map_or_else(|| p2pk(&[0; 32]), |o| o.script_public_key.clone()),
        };
        let token_state = |i: usize| -> Result<Kcc20State, HtlcError> {
            let script = self.slots.get(i).ok_or_else(unknown)?.script_with(&[0; 65]);
            let redeem = crate::tx::last_push(&script).ok_or_else(unknown)?;
            template.state_of(&redeem).ok_or_else(unknown)
        };
        let vault = HtlcVault::instantiate_existing(terms)?;
        let first = input(0)?;

        if first.entry.script_public_key == vault.script_public_key() {
            let slot = &self.slots[0];
            if slot.signer.is_none() {
                // A claim: the preimage is the first push of the vault input's script.
                let preimage = first_push(&slot.before).ok_or_else(unknown)?;
                let rebuilt = claim(terms, &first, &input(1)?, template, &preimage, &fee(2, 2))?;
                return Ok((HtlcIpstKind::Claim, 2, rebuilt));
            }
            let signer = match slot.signer {
                Some(k) if k == t.seller_key => HtlcRefundSigner::Seller,
                Some(k) if k == t.buyer_key => HtlcRefundSigner::Buyer,
                _ => return Err(unknown()),
            };
            let with_token = utxos.get(1).is_some_and(|u| u.entry.covenant_id == cov);
            let escrow = if with_token {
                let state = token_state(1)?;
                Some(RefundEscrow {
                    utxo: input(1)?,
                    amount: state.amount,
                    is_minter: state.is_minter,
                    template,
                })
            } else {
                None
            };
            let n = 1 + usize::from(with_token);
            let rebuilt = refund(terms, signer, &first, escrow.as_ref(), &fee(n, n))?;
            return Ok((HtlcIpstKind::Refund { signer, with_token }, n, rebuilt));
        }

        // Funding: the depositor's tokens lead the inputs, the authorizer is output 1.
        let authorizer_there = self
            .tx
            .outputs
            .get(1)
            .is_some_and(|o| o.script_public_key == vault.script_public_key());
        if first.entry.covenant_id != cov || !authorizer_there {
            return Err(unknown());
        }
        let count = utxos
            .iter()
            .take_while(|u| u.entry.covenant_id == cov)
            .count();
        let tokens = (0..count)
            .map(|i| {
                Ok(TokenUtxo {
                    utxo: input(i)?,
                    state: token_state(i)?,
                })
            })
            .collect::<Result<Vec<_>, HtlcError>>()?;
        let held = tokens
            .iter()
            .fold(0u64, |sum, tok| sum.saturating_add(tok.state.amount));
        let n = 2 + usize::from(held > t.asset_leg.amount);
        let deposit = Kcc20Deposit {
            tokens,
            carrier: self.tx.outputs[0].value,
            authorizer: self.tx.outputs[1].value,
        };
        let rebuilt = fund_at(
            terms,
            &vault,
            template,
            &deposit,
            &fee(count, n),
            current_daa,
        )?;
        Ok((HtlcIpstKind::Fund, n, rebuilt))
    }
}

fn mismatch(reason: &'static str) -> HtlcError {
    TxError::IpstTermsMismatch { reason }.into()
}

/// The data of the first push of a push-only script.
pub(super) fn first_push(script: &[u8]) -> Option<Vec<u8>> {
    let first =
        kaspa_txscript::parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script)
            .next()?
            .ok()?;
    first.is_push_opcode().then(|| first.get_data().to_vec())
}

#[cfg(test)]
impl HtlcIpst {
    pub(super) fn tx_mut_for_test(&mut self) -> &mut Transaction {
        &mut self.tx
    }

    pub(super) fn slots_mut_for_test(&mut self) -> &mut Vec<HtlcSlot> {
        &mut self.slots
    }
}

#[cfg(test)]
impl HtlcSlot {
    pub(super) fn set_before_for_test(&mut self, before: Vec<u8>) {
        self.before = before;
    }
}
