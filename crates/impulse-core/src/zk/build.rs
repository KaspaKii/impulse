// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v3 builders (spec/V3-ZK.md sections 6, 10, 11): fund a KAS leg, fund a KCC-20 leg, settle
//! with a proof, and refund, for terms v3. Each is the v1 builder of `crate::tx` over the
//! template v3 vaults: the same layouts, the same checks of the legs, the same plan of inputs and
//! outputs, the same shared checks (`finish`), with these differences only:
//!
//! - the asset vault's `settle` takes the proof as a second witness item, the cash vault's takes
//!   an empty one ([Z2]);
//! - the asset vault's settle input is budgeted for the proof verification;
//! - the mass caps are D63's (compute 450,000, storage 450,000, transient 900,000), refused as
//!   `ZK_TX_MASS`;
//! - the settle builder runs the asset vault's settle input in the pinned script engine before it
//!   returns anything, so it never returns a settle the chain would refuse for its proof
//!   (`ZK_PROOF_INVALID`). The one thing the run cannot judge is the authority's signature, which
//!   does not exist yet: a run that passes the proof gate and fails afterwards is accepted when
//!   the terms name an authority.
//!
//! Adapted from `crate::tx::build` (relicensed, see NOTICE). Keyless: signatures arrive later, as
//! bytes, through the IPST.

use super::ipst::IpstV3;
use super::proof::ProofBytes;
use super::template::{check as check_template, FundableVaultV3, VaultV3, CONTRACT_NAME_V3};
use super::terms::ValidatedTermsV3;
use super::ZkError;
use crate::bounds::MAX_VAULT_SPEND_INPUTS;
use crate::locktime::{refund_lock_time, settle_lock_time, INPUT_SEQUENCE};
use crate::template::LegIndex;
use crate::terms::{IdentifierType, Kcc20Owner, LegKind, SettlementMode, Terms};
use crate::tx::{
    check_min, checked_sum, complete, escrow_at, kas_destination, kas_key, kcc20_delegate_budget,
    kcc20_leader_budget, kcc20_owner, min_relay_fee, not_expired, own_tokens, p2pk_spend, planned,
    same_spend, signed, template_bytes, token_output, token_state, too_many_inputs, topped_up,
    vault_budget, FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, Masses, PlannedInput,
    RefundEscrow, RefundSigner, SettleCash, SettleLegs, Slot, Spend, TokenUtxo, TxError, Utxo,
    MAX_OUTPUTS, MIN_KCC20_OUTPUT, P2PK_BUDGET,
};
use crate::tx::{p2pk, push_data, IpstKind};
use kaspa_consensus_core::constants::{
    MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI, TX_VERSION_TOCCATA,
};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::{ComputeBudget, ScriptUnits};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
    VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
use silverscript_abi::{encode_contract_entry_sig_script, ArtifactValue};
use std::collections::HashSet;

// =============================================================================================
// Caps and budgets
// =============================================================================================

/// Per-dimension mass caps of a v3 transaction (D63, spec section 10): the caps of V2.md D37.
pub const V3_COMPUTE_MASS_CAP: u64 = 450_000;
pub const V3_STORAGE_MASS_CAP: u64 = 450_000;
pub const V3_TRANSIENT_MASS_CAP: u64 = 900_000;

/// Script units the Groth16 precompile charges before it reads a proof: its fixed cost (spec
/// section 3.1). A run of the asset vault that used fewer was refused before the proof gate.
pub const GATE_FLOOR_UNITS: u64 = 14_000_000;

/// Script units the proof verification costs a settle: `14,000,000 + 250,000 * (5 + 1)` for
/// the zk-sdk fragment's five public inputs (spec section 3.4), plus the hashing of the
/// journal. The engine figure is measured by `settle_budget_covers_the_engine` below and by
/// tests/engine/v3_measure.rs.
pub const VERIFY_UNITS: u64 = 15_500_000;

/// Slack on top of [`VERIFY_UNITS`] for the journal hashing and the fragment's own SHA-256 work
/// (modelled a few hundred units; 20,000 leaves room).
pub const VERIFY_MARGIN_UNITS: u64 = 20_000;

/// Refuses any mass dimension above its v3 cap (`ZK_TX_MASS`), in the order compute, transient,
/// storage.
pub(crate) fn check_v3_masses(masses: &Masses) -> Result<(), ZkError> {
    for (dimension, mass, cap) in [
        ("compute", masses.compute, V3_COMPUTE_MASS_CAP),
        ("transient", masses.transient, V3_TRANSIENT_MASS_CAP),
        ("storage", masses.storage, V3_STORAGE_MASS_CAP),
    ] {
        if mass > cap {
            return Err(ZkError::TxMass {
                dimension,
                mass,
                cap,
            });
        }
    }
    Ok(())
}

fn covering(units: u64) -> u16 {
    ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map_or(u16::MAX, |b| b.value())
}

/// Budget of the asset vault's settle input: the v1 vault rule plus the verification.
fn asset_settle_budget(template_bytes: u64) -> u16 {
    vault_budget(template_bytes).saturating_add(covering(VERIFY_UNITS + VERIFY_MARGIN_UNITS))
}

// =============================================================================================
// Signature scripts of the v3 vault entries
// =============================================================================================

fn vault_entry(vault: &VaultV3, entry: &str, args: Vec<ArtifactValue>) -> Result<Vec<u8>, ZkError> {
    let template = check_template()?;
    let mut script =
        encode_contract_entry_sig_script(template.abi(), CONTRACT_NAME_V3, entry, &args).map_err(
            |e| {
                ZkError::Tx(TxError::Encoding {
                    reason: format!("ImpulseVaultV3 {entry}: {e}"),
                })
            },
        )?;
    script.extend_from_slice(&push_data(vault.redeem_script())?);
    Ok(script)
}

/// ImpulseVaultV3 `settle(sig authSig, byte[] proof)`: signed by the authority, or 65 zero bytes
/// when the trade is self-settling (the contract does not read it). The cash vault's proof is
/// empty ([Z2]).
fn vault_settle(
    vault: &VaultV3,
    authority: Option<[u8; 32]>,
    proof: &[u8],
) -> Result<Spend, ZkError> {
    let encode = |sig: &[u8; 65]| {
        vault_entry(
            vault,
            "settle",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Bytes(proof.to_vec()),
            ],
        )
        .map_err(|e| match e {
            ZkError::Tx(t) => t,
            other => TxError::Encoding {
                reason: other.to_string(),
            },
        })
    };
    match authority {
        Some(key) => Ok(signed(key, encode)?),
        None => Ok(complete(encode(&[0; 65])?)),
    }
}

/// ImpulseVaultV3 `refund(sig s, pubkey signer)`.
fn vault_refund(vault: &VaultV3, signer: [u8; 32]) -> Result<Spend, ZkError> {
    Ok(signed(signer, |sig| {
        vault_entry(
            vault,
            "refund",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Bytes(signer.to_vec()),
            ],
        )
        .map_err(|e| match e {
            ZkError::Tx(t) => t,
            other => TxError::Encoding {
                reason: other.to_string(),
            },
        })
    })?)
}

// =============================================================================================
// Builders
// =============================================================================================

/// Funds a KAS cash leg: one output of exactly the cash amount at the cash vault's address,
/// paid with the funding inputs, which also pay the fee.
pub fn fund_kas(
    terms: &ValidatedTermsV3,
    vault: &FundableVaultV3,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV3, ZkError> {
    fund_kas_at(terms, consistent_vault(terms, vault)?, funding, current_daa)
}

fn fund_kas_at(
    terms: &ValidatedTermsV3,
    vault: &VaultV3,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV3, ZkError> {
    let t = &terms.terms().fields;
    if vault.leg() != LegIndex::Cash || t.cash_leg.kind != LegKind::Kas {
        return Err(TxError::WrongMode {
            reason: "fund_kas funds a KAS cash leg",
        }
        .into());
    }
    not_expired(t, current_daa)?;
    let deposit = TransactionOutput::new(t.cash_leg.amount, vault.script_public_key());
    check_min(&deposit, 0)?;
    finish(
        Plan {
            terms,
            proof: None,
            inputs: vec![],
            outputs: vec![deposit],
            lock_time: 0,
            max_inputs: None,
        },
        funding,
    )
}

/// Funds a KCC-20 leg: output 0 the escrowed token (exactly the leg amount, owned by the vault's
/// script hash, carrying `carrier` KAS), output 1 the authorizer at the vault's address, then the
/// token change back to the depositor's key if the tokens hold more, then KAS change.
pub fn fund_kcc20(
    terms: &ValidatedTermsV3,
    vault: &FundableVaultV3,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV3, ZkError> {
    let vault = consistent_vault(terms, vault)?;
    fund_kcc20_at(terms, vault, template, deposit, funding, current_daa)
}

fn fund_kcc20_at(
    terms: &ValidatedTermsV3,
    vault: &VaultV3,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV3, ZkError> {
    let t = &terms.terms().fields;
    let leg = match vault.leg() {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let LegKind::Kcc20(token) = leg.kind else {
        return Err(TxError::WrongMode {
            reason: "fund_kcc20 funds a KCC-20 leg",
        }
        .into());
    };
    not_expired(t, current_daa)?;
    template.check_token(&token)?;
    let owner = own_tokens(&deposit.tokens, &token, template)?;
    let held = deposit
        .tokens
        .iter()
        .try_fold(0u64, |sum, tok| sum.checked_add(tok.state.amount))
        .filter(|sum| *sum <= i64::MAX as u64)
        .ok_or(TxError::TokenInput {
            index: 0,
            reason: "the token amounts add up past the script integer range",
        })?;
    if held < leg.amount {
        return Err(TxError::TokenInput {
            index: 0,
            reason: "the token inputs hold less than the leg amount",
        }
        .into());
    }
    let escrow_state = Kcc20State::new(script_hash_owner(vault), leg.amount);
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
    if held > leg.amount {
        let change = Kcc20State::new(owner, held - leg.amount);
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
            proof: None,
            inputs,
            outputs,
            lock_time: 0,
            max_inputs: None,
        },
        funding,
    )
}

/// Settles a funded vault trade in the canonical layout (spec "Canonical settle transaction"),
/// carrying the proof in the asset vault's witness and an empty one in the cash vault's. The
/// proof is checked to be 128 bytes that parse as a Groth16 proof (`ZK_PROOF_MALFORMED`), and the
/// asset vault's settle input is run in the pinned engine before anything is returned
/// (`ZK_PROOF_INVALID`).
pub fn settle(
    terms: &ValidatedTermsV3,
    legs: &SettleLegs<'_>,
    proof: &ProofBytes,
    fee: &FeePayment,
    current_daa: u64,
) -> Result<IpstV3, ZkError> {
    let t = &terms.terms().fields;
    if t.settlement_mode != SettlementMode::Vault {
        return Err(TxError::WrongMode {
            reason: "settle spends vaults; Direct terms have none",
        }
        .into());
    }
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        unreachable!("structure checks make the asset leg KCC-20");
    };
    let cash_matches = matches!(
        (&legs.cash, t.cash_leg.kind),
        (SettleCash::Kas { .. }, LegKind::Kas)
            | (SettleCash::Kcc20 { .. }, LegKind::Kcc20(_))
            | (SettleCash::External, LegKind::External)
    );
    if !cash_matches {
        return Err(TxError::WrongMode {
            reason: "the cash leg passed is not of the terms' cash kind",
        }
        .into());
    }
    not_expired(t, current_daa)?;

    let asset_vault = VaultV3::instantiate_existing(terms, LegIndex::Asset)?;
    at_vault(&legs.asset_authorizer, &asset_vault, "asset authorizer")?;
    legs.asset_token.check_token(&asset)?;
    let asset_escrow_state = Kcc20State::new(script_hash_owner(&asset_vault), t.asset_leg.amount);
    escrow_at(
        &legs.asset_escrow,
        &asset,
        legs.asset_token,
        &asset_escrow_state,
        "asset escrow",
    )?;
    let authority = t.authority_key;
    let asset_delivered = Kcc20State::new(kcc20_owner(&t.buyer_delivery), t.asset_leg.amount);
    // Both vaults read the asset template, and the cash template too for KCC-20 cash.
    let read_bytes = template_bytes(&asset)
        + match t.cash_leg.kind {
            LegKind::Kcc20(cash) => template_bytes(&cash),
            _ => 0,
        };
    let cash_budget = vault_budget(read_bytes);

    let mut inputs = vec![planned(
        &legs.asset_authorizer,
        asset_settle_budget(read_bytes),
        vault_settle(&asset_vault, authority, proof.as_bytes())?,
    )];
    let asset_escrow_index: u16 = match legs.cash {
        SettleCash::External => 1,
        _ => 2,
    };
    let mut outputs = vec![topped_up(token_output(
        legs.asset_escrow.entry.amount,
        legs.asset_token.script_public_key(&asset_delivered)?,
        &asset,
        asset_escrow_index,
    ))];
    let asset_escrow_input = planned(
        &legs.asset_escrow,
        kcc20_leader_budget(false, template_bytes(&asset), 1, 1),
        complete(legs.asset_token.leader_sigscript(
            &asset_escrow_state,
            &[asset_delivered],
            &[0; 65],
            0,
        )?),
    );
    let asset_return = topped_up(TransactionOutput::new(
        legs.asset_authorizer.entry.amount,
        p2pk(&t.seller_key),
    ));

    match &legs.cash {
        SettleCash::Kas { vault } => {
            let cash_vault = VaultV3::instantiate_existing(terms, LegIndex::Cash)?;
            at_vault(vault, &cash_vault, "KAS cash")?;
            if vault.entry.amount != t.cash_leg.amount {
                return Err(TxError::LegAmount {
                    input: "KAS cash vault UTXO",
                    expected: t.cash_leg.amount,
                    found: vault.entry.amount,
                }
                .into());
            }
            inputs.push(planned(
                vault,
                cash_budget,
                vault_settle(&cash_vault, authority, &[])?,
            ));
            inputs.push(asset_escrow_input);
            outputs.push(TransactionOutput::new(
                t.cash_leg.amount,
                kas_destination(&t.seller_proceeds),
            ));
            outputs.push(asset_return);
        }
        SettleCash::Kcc20 {
            authorizer,
            escrow,
            token: template,
        } => {
            let LegKind::Kcc20(cash) = t.cash_leg.kind else {
                unreachable!("matched above");
            };
            let cash_vault = VaultV3::instantiate_existing(terms, LegIndex::Cash)?;
            at_vault(authorizer, &cash_vault, "cash authorizer")?;
            template.check_token(&cash)?;
            let cash_escrow_state =
                Kcc20State::new(script_hash_owner(&cash_vault), t.cash_leg.amount);
            escrow_at(escrow, &cash, template, &cash_escrow_state, "cash escrow")?;
            let cash_delivered =
                Kcc20State::new(kcc20_owner(&t.seller_proceeds), t.cash_leg.amount);
            inputs.push(planned(
                authorizer,
                cash_budget,
                vault_settle(&cash_vault, authority, &[])?,
            ));
            inputs.push(asset_escrow_input);
            inputs.push(planned(
                escrow,
                kcc20_leader_budget(false, template_bytes(&cash), 1, 1),
                complete(template.leader_sigscript(
                    &cash_escrow_state,
                    &[cash_delivered],
                    &[0; 65],
                    1,
                )?),
            ));
            outputs.push(topped_up(token_output(
                escrow.entry.amount,
                template.script_public_key(&cash_delivered)?,
                &cash,
                3,
            )));
            outputs.push(asset_return);
            outputs.push(topped_up(TransactionOutput::new(
                authorizer.entry.amount,
                p2pk(&t.buyer_key),
            )));
        }
        SettleCash::External => {
            inputs.push(asset_escrow_input);
            outputs.push(asset_return);
        }
    }
    let ipst = finish(
        Plan {
            terms,
            proof: Some(proof.clone()),
            inputs,
            outputs,
            lock_time: settle_lock_time(t),
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )?;
    check_proof_in_engine(&ipst)?;
    Ok(ipst)
}

/// Refunds one vault UTXO of `leg` home (spec "Entries", `refund`), as v1's: input 0 the vault
/// UTXO, output 0 its KAS, whole; a KCC-20 leg's escrowed token, when included, at input 1 and
/// home whole at output 1. A refund needs no proof.
pub fn refund(
    terms: &ValidatedTermsV3,
    leg: LegIndex,
    signer: RefundSigner,
    vault_utxo: &Utxo,
    escrow: Option<&RefundEscrow<'_>>,
    fee: &FeePayment,
) -> Result<IpstV3, ZkError> {
    let t = &terms.terms().fields;
    let vault = VaultV3::instantiate_existing(terms, leg)?;
    let (depositor, counterparty, leg_terms, home) = match leg {
        LegIndex::Asset => (t.seller_key, t.buyer_key, &t.asset_leg, &t.seller_refund),
        LegIndex::Cash => (t.buyer_key, t.seller_key, &t.cash_leg, &t.buyer_refund),
    };
    let signer_key = match signer {
        RefundSigner::Depositor => depositor,
        RefundSigner::Counterparty => counterparty,
        RefundSigner::Authority => t.authority_key.ok_or(TxError::RefundSigner {
            reason: "these terms have no settlement authority",
        })?,
    };
    at_vault(vault_utxo, &vault, "vault")?;
    // The vault reads the token's template only when the token goes home with it.
    let read_bytes = match (leg_terms.kind, escrow) {
        (LegKind::Kcc20(token), Some(_)) => template_bytes(&token),
        _ => 0,
    };
    let mut inputs = vec![planned(
        vault_utxo,
        vault_budget(read_bytes),
        vault_refund(&vault, signer_key)?,
    )];
    let mut outputs = vec![];
    match leg_terms.kind {
        LegKind::Kas => {
            if escrow.is_some() {
                return Err(TxError::WrongMode {
                    reason: "a KAS cash leg has no escrowed token",
                }
                .into());
            }
            outputs.push(TransactionOutput::new(
                vault_utxo.entry.amount,
                kas_destination(home),
            ));
        }
        LegKind::Kcc20(token) => {
            outputs.push(TransactionOutput::new(
                vault_utxo.entry.amount,
                p2pk(&depositor),
            ));
            match escrow {
                None if signer != RefundSigner::Depositor => {
                    return Err(TxError::RefundSigner {
                        reason: "a counterparty or authority refund of a KCC-20 leg takes its escrowed token home with it",
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
                    if signer != RefundSigner::Depositor && e.amount != leg_terms.amount {
                        return Err(TxError::LegAmount {
                            input: "escrowed token",
                            expected: leg_terms.amount,
                            found: e.amount,
                        }
                        .into());
                    }
                    let home_state = Kcc20State {
                        owner: kcc20_owner(home),
                        ..held
                    };
                    inputs.push(planned(
                        &e.utxo,
                        kcc20_leader_budget(false, template_bytes(&token), 1, 1),
                        complete(
                            e.template
                                .leader_sigscript(&held, &[home_state], &[0; 65], 0)?,
                        ),
                    ));
                    outputs.push(topped_up(token_output(
                        e.utxo.entry.amount,
                        e.template.script_public_key(&home_state)?,
                        &token,
                        1,
                    )));
                }
            }
        }
        LegKind::External => unreachable!("an external leg has no vault"),
    }
    finish(
        Plan {
            terms,
            proof: None,
            inputs,
            outputs,
            lock_time: refund_lock_time(t, signer == RefundSigner::Depositor),
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

// =============================================================================================
// Checks on the legs
// =============================================================================================

/// The vault of a `FundableVaultV3`, if it is the one these terms give for its leg.
fn consistent_vault<'v>(
    terms: &ValidatedTermsV3,
    vault: &'v FundableVaultV3,
) -> Result<&'v VaultV3, ZkError> {
    match VaultV3::instantiate_existing(terms, vault.vault().leg()) {
        Ok(v) if v == *vault.vault() => Ok(vault.vault()),
        _ => Err(TxError::VaultMismatch.into()),
    }
}

/// A plain UTXO at the vault's P2SH (an authorizer, the KAS cash, a vault UTXO to refund).
fn at_vault(utxo: &Utxo, vault: &VaultV3, input: &'static str) -> Result<(), ZkError> {
    if utxo.entry.script_public_key != vault.script_public_key() || utxo.entry.covenant_id.is_some()
    {
        return Err(TxError::NotAtVault { input }.into());
    }
    Ok(())
}

/// The SCRIPT_HASH owner a vault's escrowed token has.
fn script_hash_owner(vault: &VaultV3) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

// =============================================================================================
// The checks every transaction shares
// =============================================================================================

struct Plan<'t> {
    terms: &'t ValidatedTermsV3,
    proof: Option<ProofBytes>,
    inputs: Vec<PlannedInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    /// The most inputs the vault template the transaction spends allows, if it sets a bound.
    max_inputs: Option<usize>,
}

/// As v1's `finish`: appends the fee inputs and the change, then checks, in order, the fee
/// inputs (`TX_KAS_INPUT`), at most the inputs the spent vault template allows
/// (`TX_TOO_MANY_INPUTS`), no outpoint twice (`TX_DUPLICATE_INPUT`), every spent UTXO above zero
/// and at most `MAX_SOMPI` (`TX_UTXO_VALUE`), a standard change script
/// (`TX_NONSTANDARD_CHANGE`), enough funds (`TX_INSUFFICIENT_FUNDS`), the change minimum
/// (`TX_BELOW_MIN_KAS`); builds the unsigned transaction and each slot's sighash; then checks the
/// masses of the signed size against the v3 caps (`ZK_TX_MASS`) and the relay fee
/// (`TX_FEE_TOO_LOW`).
fn finish(mut plan: Plan<'_>, fee: &FeePayment) -> Result<IpstV3, ZkError> {
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
        plan.inputs
            .push(planned(utxo, P2PK_BUDGET, p2pk_spend(key)));
    }
    too_many_inputs(plan.inputs.len(), plan.max_inputs)?;
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
        // Each value is at most MAX_SOMPI and so is the running total: no overflow.
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
    let needed = checked_sum(plan.outputs.iter().map(|o| o.value).chain([fee.fee])).ok_or(
        TxError::InsufficientFunds {
            available,
            needed: u64::MAX,
        },
    )?;
    if available < needed {
        return Err(TxError::InsufficientFunds { available, needed }.into());
    }
    if available > needed {
        let change = TransactionOutput::new(available - needed, fee.change.clone());
        check_min(&change, plan.outputs.len())?;
        plan.outputs.push(change);
    }
    debug_assert!(plan.outputs.len() as u64 <= MAX_OUTPUTS);

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
    let mut slots: Vec<Slot> = plan
        .inputs
        .into_iter()
        .map(|i| match i.spend {
            Spend::Signed {
                signer,
                before,
                after,
            } => Slot {
                signer: Some(signer),
                sighash: None,
                signature: None,
                before,
                after,
            },
            Spend::Complete(script) => Slot {
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
            slot.sighash = Some(crate::tx::sighash(&tx, &entries, index)?);
        }
    }
    let ipst = IpstV3::from_parts(plan.terms.clone(), plan.proof, tx, entries, slots);
    let masses = ipst.masses();
    check_v3_masses(&masses)?;
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

// =============================================================================================
// The proof check in the pinned engine
// =============================================================================================

/// Engine flags as consensus sets them after Toccata: covenants enabled, the network's sigop
/// cost in script units.
fn engine_flags(network: crate::terms::Network) -> EngineFlags {
    use kaspa_consensus_core::mass::Gram;
    let params = match network {
        crate::terms::Network::Mainnet => &kaspa_consensus_core::config::params::MAINNET_PARAMS,
        crate::terms::Network::Testnet => &kaspa_consensus_core::config::params::TESTNET_PARAMS,
    };
    EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(params.mass_per_sig_op).into(),
    }
}

/// Runs the asset vault's settle input (input 0) of an unsigned settle in the pinned script
/// engine, every signature slot holding a placeholder, and refuses unless the proof gate passed.
///
/// The gate is the Groth16 precompile; it fails the input with a `ZkIntegrity` error when the
/// proof does not verify for the journal the script rebuilds from this vault, its list root and
/// the delivery owner. A run that fails afterwards is accepted only when the terms name an
/// authority, whose signature does not exist yet: that failure is the placeholder at [S6]. The
/// script units the run used must then show the gate ran (at least [`GATE_FLOOR_UNITS`]).
pub(crate) fn check_proof_in_engine(ipst: &IpstV3) -> Result<(), ZkError> {
    let terms = &ipst.terms().terms().fields;
    let mut tx = ipst.transaction().clone();
    for (input, slot) in tx.inputs.iter_mut().zip(ipst.slots()) {
        // 64 zero bytes and SIG_HASH_ALL: a well-formed signature that does not verify.
        let mut placeholder = [0u8; 65];
        placeholder[64] = 0x01;
        input.signature_script = slot.script_with(&placeholder);
    }
    let entries = ipst.entries().to_vec();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| ZkError::ProofInvalid {
        reason: format!("the covenant context of the settle cannot be built: {e}"),
    })?;
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(1_000);
    let (input, utxo) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        input,
        0,
        utxo,
        EngineCtx::new(&sig_cache)
            .with_reused(&reused)
            .with_covenants_ctx(&cov_ctx),
        engine_flags(terms.network),
        input.compute_commit.allowed_script_units(),
    );
    let result = vm.execute();
    let used = vm.used_script_units().0;
    match result {
        Ok(()) => Ok(()),
        Err(TxScriptError::ZkIntegrity(reason)) => Err(ZkError::ProofInvalid {
            reason: format!(
                "the proof does not verify for this vault in the pinned engine: {reason}"
            ),
        }),
        Err(e) if terms.authority_key.is_some() && used >= GATE_FLOOR_UNITS => {
            // Past the gate, then refused: the placeholder where the authority will sign.
            let _ = e;
            Ok(())
        }
        Err(e) => Err(ZkError::ProofInvalid {
            reason: format!("the asset vault's settle fails in the pinned engine: {e}"),
        }),
    }
}

// =============================================================================================
// The terms check: the transaction the builders make from an IPST's own inputs
// =============================================================================================

fn mismatch(reason: &'static str) -> ZkError {
    ZkError::Tx(TxError::IpstTermsMismatch { reason })
}

/// Rebuilds, with the v3 builders, the transaction an IPST should be: its terms, its own inputs
/// (the trade UTXOs where the builder's layout puts them, token states from the redeem scripts
/// the token inputs carry, then the fee inputs), its proof, its fee and its change destination.
/// Returns the kind, the number of trade outputs and the rebuilt IPST. A builder's refusal keeps
/// its code; inputs no builder lays out this way for these terms are `IPST_TERMS_MISMATCH`.
pub(crate) fn rebuild(
    ipst: &IpstV3,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
    current_daa: u64,
) -> Result<(IpstKind, usize, IpstV3), ZkError> {
    let terms = ipst.terms();
    let t: &Terms = &terms.terms().fields;
    let tx = ipst.transaction();
    let slots = ipst.slots();
    let utxos: Vec<Utxo> = tx
        .inputs
        .iter()
        .zip(ipst.entries())
        .map(|(input, entry)| Utxo {
            outpoint: input.previous_outpoint,
            entry: entry.clone(),
        })
        .collect();
    let unknown = || mismatch("not a transaction the builders make for these terms");
    let input = |i: usize| utxos.get(i).cloned().ok_or_else(unknown);
    let token_at = |i: usize, template: &Kcc20Template| -> Result<TokenUtxo, ZkError> {
        Ok(TokenUtxo {
            utxo: input(i)?,
            state: token_state(slots, i, template).ok_or_else(unknown)?,
        })
    };
    let cash_template = || {
        cash.ok_or_else(|| {
            ZkError::Tx(TxError::TokenTemplate {
                reason: "no template given for the KCC-20 cash leg".into(),
            })
        })
    };
    let fee = |trade_inputs: usize, trade_outputs: usize| FeePayment {
        inputs: utxos.get(trade_inputs..).unwrap_or_default().to_vec(),
        fee: ipst.fee(),
        change: tx
            .outputs
            .get(trade_outputs)
            .map_or_else(|| p2pk(&[0; 32]), |o| o.script_public_key.clone()),
    };

    let asset_vault = VaultV3::instantiate_existing(terms, LegIndex::Asset)?;
    let cash_vault = match t.cash_leg.kind {
        LegKind::External => None,
        _ => Some(VaultV3::instantiate_existing(terms, LegIndex::Cash)?),
    };
    let first = input(0)?;
    let at = |vault: &VaultV3| first.entry.script_public_key == vault.script_public_key();
    let vault_leg = if at(&asset_vault) {
        Some(LegIndex::Asset)
    } else {
        cash_vault
            .as_ref()
            .filter(|v| at(v))
            .map(|_| LegIndex::Cash)
    };

    if let Some(leg) = vault_leg {
        // Settle: the asset authorizer spent through the settle entry, with the document's proof.
        if let (LegIndex::Asset, Some(proof)) = (leg, ipst.proof()) {
            if same_spend(
                &slots[0],
                &vault_settle(&asset_vault, t.authority_key, proof.as_bytes())?,
            ) {
                let (cash_legs, escrow_input, n) = match t.cash_leg.kind {
                    LegKind::Kas => (SettleCash::Kas { vault: input(1)? }, 2, 3),
                    LegKind::Kcc20(_) => (
                        SettleCash::Kcc20 {
                            authorizer: input(1)?,
                            escrow: input(3)?,
                            token: cash_template()?,
                        },
                        2,
                        4,
                    ),
                    LegKind::External => (SettleCash::External, 1, 2),
                };
                let legs = SettleLegs {
                    asset_authorizer: first,
                    asset_escrow: input(escrow_input)?,
                    asset_token: asset,
                    cash: cash_legs,
                };
                let rebuilt = settle(terms, &legs, proof, &fee(n, n), current_daa)?;
                return Ok((IpstKind::Settle, n, rebuilt));
            }
        }
        // Refund: the role is the slot's signer.
        let signer_key = slots[0].signer().ok_or_else(unknown)?;
        let (depositor, counterparty, leg_kind) = match leg {
            LegIndex::Asset => (t.seller_key, t.buyer_key, t.asset_leg.kind),
            LegIndex::Cash => (t.buyer_key, t.seller_key, t.cash_leg.kind),
        };
        let signer = if signer_key == depositor {
            RefundSigner::Depositor
        } else if signer_key == counterparty {
            RefundSigner::Counterparty
        } else if Some(signer_key) == t.authority_key {
            RefundSigner::Authority
        } else {
            return Err(unknown());
        };
        let escrow = match leg_kind {
            LegKind::Kcc20(token)
                if utxos.get(1).is_some_and(|u| {
                    u.entry.covenant_id == Some(Hash::from_bytes(token.covenant_id))
                }) =>
            {
                let template = match leg {
                    LegIndex::Asset => asset,
                    LegIndex::Cash => cash_template()?,
                };
                let held = token_at(1, template)?;
                Some(RefundEscrow {
                    utxo: held.utxo,
                    amount: held.state.amount,
                    is_minter: held.state.is_minter,
                    template,
                })
            }
            _ => None,
        };
        let n = 1 + usize::from(escrow.is_some());
        let kind = IpstKind::Refund {
            leg,
            signer,
            with_token: escrow.is_some(),
        };
        let rebuilt = refund(terms, leg, signer, &first, escrow.as_ref(), &fee(n, n))?;
        return Ok((kind, n, rebuilt));
    }

    // Funding a KAS cash leg: the deposit at the cash vault is output 0.
    if let (LegKind::Kas, Some(vault)) = (t.cash_leg.kind, &cash_vault) {
        let deposit_there = tx
            .outputs
            .first()
            .is_some_and(|o| o.script_public_key == vault.script_public_key());
        if deposit_there && first.entry.covenant_id.is_none() {
            let rebuilt = fund_kas_at(terms, vault, &fee(0, 1), current_daa)?;
            return Ok((IpstKind::FundKas, 1, rebuilt));
        }
    }
    // Funding a KCC-20 leg: the depositor's tokens lead the inputs, the authorizer at the leg's
    // vault is output 1.
    let kcc20_legs = [
        (LegIndex::Asset, Some(&asset_vault), t.asset_leg),
        (LegIndex::Cash, cash_vault.as_ref(), t.cash_leg),
    ];
    for (leg, vault, leg_terms) in kcc20_legs {
        let (LegKind::Kcc20(token), Some(vault)) = (leg_terms.kind, vault) else {
            continue;
        };
        let cov = Some(Hash::from_bytes(token.covenant_id));
        let authorizer_there = tx
            .outputs
            .get(1)
            .is_some_and(|o| o.script_public_key == vault.script_public_key());
        if first.entry.covenant_id != cov || !authorizer_there {
            continue;
        }
        let template = match leg {
            LegIndex::Asset => asset,
            LegIndex::Cash => cash_template()?,
        };
        let count = utxos
            .iter()
            .take_while(|u| u.entry.covenant_id == cov)
            .count();
        let tokens = (0..count)
            .map(|i| token_at(i, template))
            .collect::<Result<Vec<_>, _>>()?;
        let held = tokens
            .iter()
            .fold(0u64, |sum, tok| sum.saturating_add(tok.state.amount));
        let n = 2 + usize::from(held > leg_terms.amount);
        let deposit = Kcc20Deposit {
            tokens,
            carrier: tx.outputs[0].value,
            authorizer: tx.outputs[1].value,
        };
        let rebuilt = fund_kcc20_at(
            terms,
            vault,
            template,
            &deposit,
            &fee(count, n),
            current_daa,
        )?;
        return Ok((IpstKind::FundKcc20(leg), n, rebuilt));
    }
    Err(unknown())
}
