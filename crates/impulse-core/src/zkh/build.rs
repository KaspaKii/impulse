// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v4 builders (spec/V3-ZK.md 22.5, 22.6, 22.8): fund a KAS leg, fund a KCC-20 leg, settle
//! and refund, for terms v4. Each is the v3 builder over the template v4 vaults: the same
//! layouts (asset authorizer at input 0, cash authorizer at input 1), the same exact amounts, the
//! same shared checks (`finish`), with these differences only:
//!
//! - every vault input carries a proof, not only the asset vault's: a settle has two, a refund
//!   one. A proof not given yet is 128 zero bytes in the script (a plan for the prover), which
//!   `IpstV4::finalize` refuses;
//! - the vault entries take the size of the view and the covenant IDs (22.5);
//! - the lock time and sequence are those of v1 (22.5: the guest's `[S3]` and `[R3]` read the
//!   lock time the builder sets);
//! - every builder runs the statement of `terms-core` natively on the view of each vault input
//!   it made (`ZK_H_STATEMENT_FALSE` naming the tag), so no transaction the guest would refuse
//!   is returned;
//! - the mass caps are D63's (compute 450,000, storage 450,000, transient 900,000), refused as
//!   `ZK_TX_MASS`.
//!
//! A settle or refund has at most `MAX_INPUTS_V4` inputs (`ZK_H_SHAPE`, 22.15).
//!
//! The pinned script engine runs at `IpstV4::finalize`, when the signatures exist: the vault
//! checks the signature before the proof, so a run without the signatures cannot reach the gate.
//! Adapted from `crate::zk::build` and `crate::tx::build` (relicensed, see NOTICE). Keyless:
//! signatures arrive later, as bytes, through the IPST.

use super::ipst::{IpstV4, ProofV4, PROOF_LEN};
use super::vterms::ValidatedTermsV4;
use super::{check, parse_spend_script, witness_for, VaultV4, ZkhError, CONTRACT_NAME_V4};
use crate::locktime::{refund_lock_time, settle_lock_time, INPUT_SEQUENCE};
use crate::template::LegIndex;
use crate::terms::{IdentifierType, Kcc20Owner, LegKind, SettlementMode, Terms};
use crate::tx::{
    check_min, checked_sum, complete, escrow_at, kas_destination, kas_key, kcc20_delegate_budget,
    kcc20_leader_budget, kcc20_owner, min_relay_fee, not_expired, own_tokens, p2pk, p2pk_spend,
    planned, push_data, signed, template_bytes, token_output, token_state, topped_up, vault_budget,
    FeePayment, IpstKind, Kcc20Deposit, Kcc20State, Kcc20Template, Masses, PlannedInput,
    RefundEscrow, RefundSigner, SettleCash, SettleLegs, Slot, Spend as TxSpend, TokenUtxo, TxError,
    Utxo, MAX_OUTPUTS, MIN_KCC20_OUTPUT, P2PK_BUDGET,
};
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

/// Per-dimension mass caps of a v4 transaction (D63, spec section 10): the caps of V2.md D37.
pub const V4_COMPUTE_MASS_CAP: u64 = 450_000;
pub const V4_STORAGE_MASS_CAP: u64 = 450_000;
pub const V4_TRANSIENT_MASS_CAP: u64 = 900_000;

/// Script units one Groth16 verification costs a vault input: the precompile's fixed cost and
/// the verifying key's five public inputs (spec section 3.4: `14,000,000 + 250,000 * (5 + 1)`).
pub const VERIFY_UNITS: u64 = 15_500_000;

/// What a v4 vault input costs besides the verification: the journal builder and the checks,
/// measured at 109,216 to 121,219 units in the probe build (docs/evidence/template-fix-2026-10-19/v4-1-covenant-check.txt),
/// with room for the signature check.
pub const VAULT_BASE_UNITS: u64 = 200_000;

/// The most inputs a settle or refund may have: the bound of the loop over every input's
/// covenant ID (`MAX_INPUTS` of contracts/impulse_vault_v4.sil, `[T10]`, `[T11]`).
pub const MAX_INPUTS_V4: usize = 8;

/// Refuses a settle or refund of more than `MAX_INPUTS_V4` inputs (`ZK_H_SHAPE`).
fn input_cap(trade_inputs: usize, fee: &FeePayment) -> Result<(), ZkhError> {
    let n = trade_inputs + fee.inputs.len();
    if n > MAX_INPUTS_V4 {
        return Err(ZkhError::new(
            "ZK_H_SHAPE",
            format!(
                "a v4 settle or refund takes at most {MAX_INPUTS_V4} inputs, this one would have {n} ({} fee inputs): consolidate the fee UTXOs",
                fee.inputs.len()
            ),
        ));
    }
    Ok(())
}

/// Refuses any mass dimension above its v4 cap (`ZK_TX_MASS`), in the order compute, transient,
/// storage.
pub(crate) fn check_masses(masses: &Masses) -> Result<(), ZkhError> {
    for (dimension, mass, cap) in [
        ("compute", masses.compute, V4_COMPUTE_MASS_CAP),
        ("transient", masses.transient, V4_TRANSIENT_MASS_CAP),
        ("storage", masses.storage, V4_STORAGE_MASS_CAP),
    ] {
        if mass > cap {
            return Err(ZkhError::new(
                "ZK_TX_MASS",
                format!("{dimension} mass {mass} is above the cap of {cap}"),
            ));
        }
    }
    Ok(())
}

fn covering(units: u64) -> u16 {
    ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map_or(u16::MAX, |b| b.value())
}

/// Budget of a v4 vault input: the base and the verification.
fn vault_input_budget() -> u16 {
    covering(VERIFY_UNITS + VAULT_BASE_UNITS).max(vault_budget(0))
}

// =============================================================================================
// Signature scripts of the v4 vault entries
// =============================================================================================

fn vault_entry(vault: &VaultV4, entry: &str, args: Vec<ArtifactValue>) -> Result<Vec<u8>, TxError> {
    let t = check().map_err(|e| TxError::Encoding {
        reason: e.to_string(),
    })?;
    let mut script = encode_contract_entry_sig_script(&t.abi, CONTRACT_NAME_V4, entry, &args)
        .map_err(|e| TxError::Encoding {
            reason: format!("ImpulseVaultV4 {entry}: {e}"),
        })?;
    script.extend_from_slice(&push_data(vault.redeem_script())?);
    Ok(script)
}

fn proof_arg(proof: Option<&ProofV4>) -> ArtifactValue {
    ArtifactValue::Bytes(proof.map_or_else(|| vec![0u8; PROOF_LEN], |p| p.as_bytes().to_vec()))
}

/// ImpulseVaultV4 `settle(sig authSig, byte[] proof, int nIn, int nOut, byte[32] covA,
/// byte[32] covC)`, signed by the authority.
fn vault_settle(
    vault: &VaultV4,
    proof: Option<&ProofV4>,
    (n_in, n_out): (usize, usize),
    (cov_a, cov_c): ([u8; 32], [u8; 32]),
) -> Result<TxSpend, ZkhError> {
    Ok(signed(vault.authority(), |sig| {
        vault_entry(
            vault,
            "settle",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                proof_arg(proof),
                ArtifactValue::Int(n_in as i64),
                ArtifactValue::Int(n_out as i64),
                ArtifactValue::Bytes(cov_a.to_vec()),
                ArtifactValue::Bytes(cov_c.to_vec()),
            ],
        )
    })?)
}

/// ImpulseVaultV4 `refund(sig s, pubkey signer, byte leg, byte[] proof, int nIn, int nOut,
/// byte[32] cov)`.
fn vault_refund(
    vault: &VaultV4,
    signer: [u8; 32],
    leg: LegIndex,
    proof: Option<&ProofV4>,
    (n_in, n_out): (usize, usize),
    cov: [u8; 32],
) -> Result<TxSpend, ZkhError> {
    Ok(signed(signer, |sig| {
        vault_entry(
            vault,
            "refund",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Bytes(signer.to_vec()),
                ArtifactValue::Byte(leg.index()),
                proof_arg(proof),
                ArtifactValue::Int(n_in as i64),
                ArtifactValue::Int(n_out as i64),
                ArtifactValue::Bytes(cov.to_vec()),
            ],
        )
    })?)
}

fn cov_of(kind: LegKind) -> [u8; 32] {
    match kind {
        LegKind::Kcc20(token) => token.covenant_id,
        _ => [0; 32],
    }
}

// =============================================================================================
// Builders
// =============================================================================================

/// The vault of `leg` of these terms, for a funding: the creation checks of v1 have passed and
/// the leg has a vault.
pub fn fundable_vault(
    terms: &ValidatedTermsV4,
    leg: LegIndex,
    ctx: &crate::terms::CreationContext,
) -> Result<VaultV4, ZkhError> {
    terms.validate_creation(ctx)?;
    existing_vault(terms, leg)
}

/// The vault of `leg` of terms that already exist (settle, refund, verify): `TEMPLATE_NO_VAULT`
/// for external cash.
pub fn existing_vault(terms: &ValidatedTermsV4, leg: LegIndex) -> Result<VaultV4, ZkhError> {
    let t = terms.fields();
    if t.settlement_mode != SettlementMode::Vault
        || (leg == LegIndex::Cash && t.cash_leg.kind == LegKind::External)
    {
        return Err(ZkhError::new(
            "TEMPLATE_NO_VAULT",
            "external cash has no vault: it settles off chain",
        ));
    }
    VaultV4::of_terms(terms.core(), leg.index())
}

/// Funds a KAS cash leg: one output of exactly the cash amount at the cash vault's address, paid
/// with the funding inputs, which also pay the fee.
pub fn fund_kas(
    terms: &ValidatedTermsV4,
    vault: &VaultV4,
    leg: LegIndex,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV4, ZkhError> {
    let t = terms.fields();
    consistent_vault(terms, vault, leg)?;
    if leg != LegIndex::Cash || t.cash_leg.kind != LegKind::Kas {
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
            inputs: vec![],
            outputs: vec![deposit],
            lock_time: 0,
        },
        funding,
    )
}

/// Funds a KCC-20 leg: output 0 the escrowed token (exactly the leg amount, owned by the vault's
/// script hash, carrying `carrier` KAS), output 1 the authorizer at the vault's address, then the
/// token change back to the depositor's key if the tokens hold more, then KAS change.
pub fn fund_kcc20(
    terms: &ValidatedTermsV4,
    vault: &VaultV4,
    leg: LegIndex,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV4, ZkhError> {
    let t = terms.fields();
    consistent_vault(terms, vault, leg)?;
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let LegKind::Kcc20(token) = leg_terms.kind else {
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
    if held < leg_terms.amount {
        return Err(TxError::TokenInput {
            index: 0,
            reason: "the token inputs hold less than the leg amount",
        }
        .into());
    }
    let escrow_state = Kcc20State::new(script_hash_owner(vault), leg_terms.amount);
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
    if held > leg_terms.amount {
        let change = Kcc20State::new(owner, held - leg_terms.amount);
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
        },
        funding,
    )
}

/// Settles a funded trade in the canonical layout (spec "Canonical settle transaction"), each
/// vault input carrying its own proof (`proofs[0]` the asset vault's, `proofs[1]` the cash
/// vault's; a proof not given yet is the zero placeholder of a plan). The view of each vault
/// input is checked natively against the committed terms before anything is returned
/// (`ZK_H_STATEMENT_FALSE`).
pub fn settle(
    terms: &ValidatedTermsV4,
    legs: &SettleLegs<'_>,
    proofs: &[Option<ProofV4>; 2],
    fee: &FeePayment,
    current_daa: u64,
) -> Result<IpstV4, ZkhError> {
    let t = terms.fields();
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

    let covs = (asset.covenant_id, cov_of(t.cash_leg.kind));
    let shape = match legs.cash {
        SettleCash::Kas { .. } => (3, 3),
        SettleCash::Kcc20 { .. } => (4, 4),
        SettleCash::External => (2, 2),
    };
    let budget = vault_input_budget();
    let asset_vault = existing_vault(terms, LegIndex::Asset)?;
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
    let asset_delivered = Kcc20State::new(kcc20_owner(&t.buyer_delivery), t.asset_leg.amount);

    let mut inputs = vec![planned(
        &legs.asset_authorizer,
        budget,
        vault_settle(&asset_vault, proofs[0].as_ref(), shape, covs)?,
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
            let cash_vault = existing_vault(terms, LegIndex::Cash)?;
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
                budget,
                vault_settle(&cash_vault, proofs[1].as_ref(), shape, covs)?,
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
            let cash_vault = existing_vault(terms, LegIndex::Cash)?;
            at_vault(authorizer, &cash_vault, "cash authorizer")?;
            template.check_token(&cash)?;
            let cash_escrow_state =
                Kcc20State::new(script_hash_owner(&cash_vault), t.cash_leg.amount);
            escrow_at(escrow, &cash, template, &cash_escrow_state, "cash escrow")?;
            let cash_delivered =
                Kcc20State::new(kcc20_owner(&t.seller_proceeds), t.cash_leg.amount);
            inputs.push(planned(
                authorizer,
                budget,
                vault_settle(&cash_vault, proofs[1].as_ref(), shape, covs)?,
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
    input_cap(inputs.len(), fee)?;
    let ipst = finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: settle_lock_time(t),
        },
        fee,
    )?;
    check_statement(&ipst)?;
    Ok(ipst)
}

/// Refunds one vault UTXO of `leg` home (spec "Entries", `refund`): input 0 the vault UTXO,
/// output 0 its KAS, whole; a KCC-20 leg's escrowed token, when included, at input 1 and home
/// whole at output 1. The vault input carries `proof` (the zero placeholder of a plan when
/// `None`).
pub fn refund(
    terms: &ValidatedTermsV4,
    leg: LegIndex,
    signer: RefundSigner,
    vault_utxo: &Utxo,
    escrow: Option<&RefundEscrow<'_>>,
    proof: Option<&ProofV4>,
    fee: &FeePayment,
) -> Result<IpstV4, ZkhError> {
    let t = terms.fields();
    let vault = existing_vault(terms, leg)?;
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
    let n = 1 + usize::from(escrow.is_some());
    let mut inputs = vec![planned(
        vault_utxo,
        vault_input_budget(),
        vault_refund(
            &vault,
            signer_key,
            leg,
            proof,
            (n, n),
            cov_of(leg_terms.kind),
        )?,
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
    input_cap(inputs.len(), fee)?;
    let ipst = finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: refund_lock_time(t, signer == RefundSigner::Depositor),
        },
        fee,
    )?;
    check_statement(&ipst)?;
    Ok(ipst)
}

// =============================================================================================
// Checks on the legs
// =============================================================================================

/// The vault offered for `leg` is the one these terms give for it.
fn consistent_vault(
    terms: &ValidatedTermsV4,
    vault: &VaultV4,
    leg: LegIndex,
) -> Result<(), ZkhError> {
    match existing_vault(terms, leg) {
        Ok(v) if v == *vault => Ok(()),
        _ => Err(TxError::VaultMismatch.into()),
    }
}

/// A plain UTXO at the vault's P2SH (an authorizer, the KAS cash, a vault UTXO to refund).
fn at_vault(utxo: &Utxo, vault: &VaultV4, input: &'static str) -> Result<(), ZkhError> {
    if utxo.entry.script_public_key != vault.script_public_key() || utxo.entry.covenant_id.is_some()
    {
        return Err(TxError::NotAtVault { input }.into());
    }
    Ok(())
}

/// The SCRIPT_HASH owner a vault's escrowed token has.
fn script_hash_owner(vault: &VaultV4) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

// =============================================================================================
// The statement, natively
// =============================================================================================

/// Which leg the vault at input `idx` is: the one whose commitment it holds.
fn leg_of(terms: &ValidatedTermsV4, commit: &[u8; 32]) -> Option<u8> {
    (0..=1u8).find(|l| terms.commit(*l) == *commit)
}

/// The witness of every vault input of `ipst`, in input order: `(input index, leg, witness)`.
/// This is what `impulse-zk-prove-terms` reads for that input (a file of
/// `terms_core::Witness::to_bytes`).
pub fn witnesses(ipst: &IpstV4) -> Result<Vec<(usize, u8, terms_core::Witness)>, ZkhError> {
    let tx = ipst.scripted(Some([0; 65]))?;
    let mut out = Vec::new();
    for (idx, input) in tx.inputs.iter().enumerate() {
        let Some(spend) = parse_spend_script(&input.signature_script)? else {
            continue;
        };
        let leg = leg_of(ipst.terms(), &spend.commit).ok_or_else(|| {
            ZkhError::new(
                "ZK_H_TERMS_MISMATCH",
                format!("the vault at input {idx} is not a vault of these terms"),
            )
        })?;
        let witness = witness_for(
            &tx,
            ipst.entries(),
            idx,
            &spend,
            leg,
            ipst.terms().canonical(),
        )?;
        out.push((idx, leg, witness));
    }
    Ok(out)
}

/// Runs the statement of `terms-core` on the view of each vault input: what the guest proves,
/// without a proof (`ZK_H_STATEMENT_FALSE` naming the tag).
pub fn check_statement(ipst: &IpstV4) -> Result<(), ZkhError> {
    let found = witnesses(ipst)?;
    if found.is_empty() {
        return Err(ZkhError::new(
            "ZK_H_NOT_V4_VAULT",
            "the transaction spends no v4 vault",
        ));
    }
    for (_, _, witness) in found {
        terms_core::statement(
            &witness,
            terms_core::StatementOptions { curve_checks: true },
        )?;
    }
    Ok(())
}

// =============================================================================================
// The checks every transaction shares
// =============================================================================================

struct Plan<'t> {
    terms: &'t ValidatedTermsV4,
    inputs: Vec<PlannedInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
}

/// As v3's `finish`: appends the fee inputs and the change, then checks, in order, the fee inputs
/// (`TX_KAS_INPUT`), no outpoint twice (`TX_DUPLICATE_INPUT`), every spent UTXO above zero and at
/// most `MAX_SOMPI` (`TX_UTXO_VALUE`), a standard change script (`TX_NONSTANDARD_CHANGE`), enough
/// funds (`TX_INSUFFICIENT_FUNDS`), the change minimum (`TX_BELOW_MIN_KAS`); builds the unsigned
/// transaction and each slot's sighash; then checks the masses of the signed size against the v4
/// caps (`ZK_TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`).
fn finish(mut plan: Plan<'_>, fee: &FeePayment) -> Result<IpstV4, ZkhError> {
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
            TxSpend::Signed {
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
            TxSpend::Complete(script) => Slot {
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
    let ipst = IpstV4::from_parts(plan.terms.clone(), tx, entries, slots);
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

// =============================================================================================
// The pinned engine
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

/// Runs every input of a fully signed transaction in the pinned script engine at the budgets the
/// transaction carries. A vault input refused by the Groth16 precompile is `ZK_H_PROOF_INVALID`;
/// any other refusal names the input and the engine's reason under `ZK_H_PROOF_INVALID` for a
/// vault input and `TX_SIGNATURE` for the rest (a fee or token input whose signature the engine
/// does not accept).
pub(crate) fn run_in_engine(
    tx: &Transaction,
    entries: &[UtxoEntry],
    network: crate::terms::Network,
) -> Result<(), ZkhError> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| {
        ZkhError::new(
            "ZK_H_PROOF_INVALID",
            format!("the covenant context of the transaction cannot be built: {e}"),
        )
    })?;
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(1_000);
    for index in 0..tx.inputs.len() {
        let (input, utxo) = populated.populated_input(index);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            index,
            utxo,
            EngineCtx::new(&sig_cache)
                .with_reused(&reused)
                .with_covenants_ctx(&cov_ctx),
            engine_flags(network),
            input.compute_commit.allowed_script_units(),
        );
        if let Err(e) = vm.execute() {
            let is_vault = parse_spend_script(&input.signature_script)
                .ok()
                .flatten()
                .is_some();
            return Err(match (&e, is_vault) {
                (TxScriptError::ZkIntegrity(reason), true) => ZkhError::new(
                    "ZK_H_PROOF_INVALID",
                    format!(
                        "the proof of input {index} does not verify for this vault in the pinned engine: {reason}"
                    ),
                ),
                (_, true) => ZkhError::new(
                    "ZK_H_PROOF_INVALID",
                    format!("the vault input {index} fails in the pinned engine: {e}"),
                ),
                _ => ZkhError::new(
                    "TX_SIGNATURE",
                    format!("input {index} fails in the pinned engine: {e}"),
                ),
            });
        }
    }
    Ok(())
}

// =============================================================================================
// The terms check: the transaction the builders make from an IPST's own inputs
// =============================================================================================

fn mismatch(reason: &'static str) -> ZkhError {
    TxError::IpstTermsMismatch { reason }.into()
}

/// Rebuilds, with the v4 builders, the transaction an IPST should be: its terms, its own inputs
/// (the trade UTXOs where the builder's layout puts them, token states from the redeem scripts
/// the token inputs carry, then the fee inputs), its proofs, its fee and its change destination.
/// Returns the kind, the number of trade outputs and the rebuilt IPST. A builder's refusal keeps
/// its code; inputs no builder lays out this way for these terms are `IPST_TERMS_MISMATCH`.
pub(crate) fn rebuild(
    ipst: &IpstV4,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
    current_daa: u64,
) -> Result<(IpstKind, usize, IpstV4), ZkhError> {
    let terms = ipst.terms();
    let t: &Terms = terms.fields();
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
    let token_at = |i: usize, template: &Kcc20Template| -> Result<TokenUtxo, ZkhError> {
        Ok(TokenUtxo {
            utxo: input(i)?,
            state: token_state(slots, i, template).ok_or_else(unknown)?,
        })
    };
    let cash_template = || {
        cash.ok_or_else(|| {
            ZkhError::from(TxError::TokenTemplate {
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
    let proofs = ipst.proofs()?;
    let proof_of = |idx: usize| -> Option<ProofV4> {
        proofs.iter().find(|(i, _)| *i == idx).and_then(|(_, p)| *p)
    };

    let asset_vault = existing_vault(terms, LegIndex::Asset)?;
    let cash_vault = match t.cash_leg.kind {
        LegKind::External => None,
        _ => Some(existing_vault(terms, LegIndex::Cash)?),
    };
    let first = input(0)?;
    let at = |vault: &VaultV4| first.entry.script_public_key == vault.script_public_key();
    let vault_leg = if at(&asset_vault) {
        Some(LegIndex::Asset)
    } else {
        cash_vault
            .as_ref()
            .filter(|v| at(v))
            .map(|_| LegIndex::Cash)
    };

    if let Some(leg) = vault_leg {
        let slot0 = tx_script(ipst, 0)?;
        let spend = parse_spend_script(&slot0)?.ok_or_else(unknown)?;
        // Settle: the asset authorizer spent through the settle entry.
        if leg == LegIndex::Asset && spend.settle {
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
            let rebuilt = settle(
                terms,
                &legs,
                &[proof_of(0), proof_of(1)],
                &fee(n, n),
                current_daa,
            )?;
            return Ok((IpstKind::Settle, n, rebuilt));
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
        let rebuilt = refund(
            terms,
            leg,
            signer,
            &first,
            escrow.as_ref(),
            proof_of(0).as_ref(),
            &fee(n, n),
        )?;
        return Ok((kind, n, rebuilt));
    }

    // Funding a KAS cash leg: the deposit at the cash vault is output 0.
    if let (LegKind::Kas, Some(vault)) = (t.cash_leg.kind, &cash_vault) {
        let deposit_there = tx
            .outputs
            .first()
            .is_some_and(|o| o.script_public_key == vault.script_public_key());
        if deposit_there && first.entry.covenant_id.is_none() {
            let rebuilt = fund_kas(terms, vault, LegIndex::Cash, &fee(0, 1), current_daa)?;
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
        let rebuilt = fund_kcc20(
            terms,
            vault,
            leg,
            template,
            &deposit,
            &fee(count, n),
            current_daa,
        )?;
        return Ok((IpstKind::FundKcc20(leg), n, rebuilt));
    }
    Err(unknown())
}

/// The assembled signature script of input `index` (placeholder signature).
fn tx_script(ipst: &IpstV4, index: usize) -> Result<Vec<u8>, ZkhError> {
    let tx = ipst.scripted(Some([0; 65]))?;
    tx.inputs
        .get(index)
        .map(|i| i.signature_script.clone())
        .ok_or_else(|| mismatch("not a transaction the builders make for these terms"))
}
