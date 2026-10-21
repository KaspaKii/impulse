// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v2 builders (spec/V2.md section 6): fund a KAS leg, fund a KCC-20 leg, settle all N legs in
//! one transaction (final settle, the layout of section 4.3), and refund one leg (v1's refund
//! layout). Each takes [`ValidatedTermsV2`] only, holds no key, and returns an unsigned
//! [`IpstV2`]: the transaction, the UTXOs it spends and one signature slot per input.
//!
//! Refusal order of the settle builder (fixed by I16, spec/V2.md 6.3): `TX_EXPIRED`; each offered
//! leg's vault UTXO in leg order (`TX_V2_NOT_AT_VAULT`); one vault per leg and, for a KCC-20 leg,
//! one escrow (`TX_LEGS`); each KCC-20 escrow in leg order (`TX_TOKEN_TEMPLATE`,
//! `TX_ESCROW_MISMATCH`); each leg's amount in leg order (`TX_LEG_AMOUNT` without partial,
//! `TX_TRANCHE` with it); the lineage (`TX_LINEAGE`); lockstep (`TX_LEGS_OUT_OF_STEP`); then the
//! checks every transaction shares, as v1's builders run them, with `TX_V2_MASS` for `TX_MASS`.
//!
//! The split-flow pieces (signature slots, placeholder encoding, fee inputs, sighash) are v1's
//! (`crate::tx`), reused as they are.

use super::ipst::IpstV2;
use super::template::{check as template_check, VaultV2, CONTRACT_NAME};
use super::terms::{DestinationV2, TermsV2, ValidatedTermsV2};
use super::{FundableVaultV2, V2Error};
use crate::bounds::{
    max_v2_settle_inputs, MAX_V2_SETTLE_INPUTS_AFTER_VAULTS, MAX_VAULT_SPEND_INPUTS,
};
use crate::locktime::INPUT_SEQUENCE;
use crate::terms::{FundingMode, IdentifierType, Kcc20Owner, LegKind, Network};
use crate::tx::build::{
    checked_sum, complete, escrow_at, kas_key, own_tokens, p2pk_spend, planned, same_spend, signed,
    template_bytes, token_output, token_state, too_many_inputs, PlannedInput, Spend,
};
use crate::tx::ipst::Slot;
use crate::tx::kcc20::{Kcc20State, Kcc20Template};
use crate::tx::rules::{
    compute_masses, kcc20_delegate_budget, kcc20_leader_budget, min_relay_fee, params, Masses,
    P2PK_BUDGET,
};
use crate::tx::{
    p2pk, push_data, sighash, FeePayment, Kcc20Deposit, RefundEscrow, TokenUtxo, TxError, Utxo,
};
use kaspa_consensus_core::constants::{
    MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI, STORAGE_MASS_PARAMETER, TX_VERSION_TOCCATA,
};
use kaspa_consensus_core::mass::{ComputeBudget, ScriptUnits};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, GenesisCovenantGroup, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::{OpBlake2b, OpData32, OpEqual};
use kaspa_txscript::script_class::ScriptClass;
use silverscript_abi::{encode_contract_entry_sig_script, ArtifactValue};
use std::collections::HashSet;

// =============================================================================================
// Mass caps, minimum KAS and compute budgets (spec/V2.md 6.2, 6.4 and 9.2)
// =============================================================================================

/// The D37 reserve: each CAP_V2 is the pinned block limit after Toccata less this percentage.
pub const CAP_V2_RESERVE_PERCENT: u64 = 10;

/// The pre-Toccata standardness cap per dimension. The v2 builders do not refuse above it; the
/// CLI and verify warn (spec/V2.md 6.2).
pub const PRE_TOCCATA_MASS_CAP: u64 = 100_000;

/// CAP_V2 per dimension, in grams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MassCaps {
    pub compute: u64,
    pub storage: u64,
    pub transient: u64,
}

/// CAP_V2 of a network: `Params::block_mass_limits().after()` of the pinned rusty-kaspa less the
/// D37 reserve (450,000, 450,000 and 900,000 grams on mainnet and testnet at a41a333).
pub fn caps(network: Network) -> MassCaps {
    let limits = params(network).block_mass_limits().after();
    let less = |x: u64| x - x * CAP_V2_RESERVE_PERCENT / 100;
    MassCaps {
        compute: less(limits.compute),
        storage: less(limits.storage),
        transient: less(limits.transient),
    }
}

/// The output count O of spec/V2.md 6.2: N + K + 1 without partial, 2N + K + 1 with it.
fn output_count(t: &TermsV2) -> u64 {
    let (n, k) = (t.legs.len() as u64, t.kcc20_legs() as u64);
    if t.partial.is_some() {
        2 * n + k + 1
    } else {
        n + k + 1
    }
}

/// MIN_V2(p, O) = ceil(p^2 * 10^12 * O / CAP_V2_STORAGE): the least KAS every output a v2 builder
/// creates or tops up holds, for plurality `plurality` (1 a KAS output, 2 a KCC-20 token), so the
/// storage mass of the largest transaction the leg takes part in stays within the storage cap.
pub fn min_v2(terms: &TermsV2, plurality: u64) -> u64 {
    let cap = caps(terms.network).storage;
    (plurality * plurality * STORAGE_MASS_PARAMETER * output_count(terms)).div_ceil(cap)
}

/// The least KAS a vault output holds: MIN_V2(1, O), or MIN_V2(2, O) for partial terms, whose
/// vault outputs carry a covenant ID and so occupy two storage units (the P2SH script, the fixed
/// UTXO fields and the 32-byte covenant ID come to 130 bytes; `utxo_plurality` at a41a333). The
/// genesis output of a partial funding and every tranche continuation are such outputs.
pub fn min_vault_v2(terms: &TermsV2) -> u64 {
    min_v2(terms, if terms.partial.is_some() { 2 } else { 1 })
}

/// Margin on the measured unit rules: 10,000 units plus 2 percent. The fitted rules miss every
/// measured point by at most 32 (settle) and 291 (refund) units (docs/measurements/v2-max-n.txt);
/// the margin covers destination forms and owner types the fit did not sample.
fn with_margin(units: i64) -> u64 {
    let units = u64::try_from(units.max(0)).unwrap_or(0);
    units + 10_000 + units / 50
}

fn covering(units: u64) -> u16 {
    ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map_or(u16::MAX, |b| b.value())
}

fn token_len(t: &TermsV2, leg: usize) -> i64 {
    match &t.legs[leg].asset.kind {
        LegKind::Kcc20(token) => template_bytes(token) as i64,
        _ => 0,
    }
}

/// Compute budget of vault input `leg` of a final settle: the D49 rule measured in
/// tests/engine/v2_measure.rs (`SETTLE_RULE`), units = 100,098 * auth - 13,579 + 45,585 N +
/// 1,311 N^2 + 2,210 K + 1,380 tok_i + 7 T_i + 10 S, measured with one fee input, plus 107 for
/// each further input the template allows after the vaults (`MAX_V2_SETTLE_INPUTS_AFTER_VAULTS`
/// less the K escrows and one fee input, tests/engine/v2_foreign_covenant.rs), plus the margin.
pub fn settle_budget(terms: &TermsV2, leg: usize) -> u16 {
    settle_budget_for(terms, leg, false)
}

/// As [`settle_budget`] for a tranche (I17): the rule's tranche terms are added, units += 159 +
/// 770 tok_i + 10 T_i + 7 N (`SETTLE_RULE` in tests/engine/v2_measure.rs).
pub fn tranche_budget(terms: &TermsV2, leg: usize) -> u16 {
    settle_budget_for(terms, leg, true)
}

/// Script units each input after the vaults adds to a settle, at most (measured in
/// tests/engine/v2_foreign_covenant.rs: 106 to 107).
const SETTLE_UNITS_PER_INPUT: i64 = 107;
/// Script units each input after the vault adds to a refund, at most (measured: 167 to 168).
const REFUND_UNITS_PER_INPUT: i64 = 168;

fn settle_budget_for(terms: &TermsV2, leg: usize, tranche: bool) -> u16 {
    let n = terms.legs.len() as i64;
    let k = terms.kcc20_legs() as i64;
    let auth = i64::from(terms.authority_key.is_some());
    let t_i = token_len(terms, leg);
    let tok_i = i64::from(t_i > 0);
    let s: i64 = (0..terms.legs.len()).map(|j| token_len(terms, j)).sum();
    let further = (MAX_V2_SETTLE_INPUTS_AFTER_VAULTS as i64 - k - 1).max(0);
    let mut units = 100_098 * auth - 13_579
        + 45_585 * n
        + 1_311 * n * n
        + 2_210 * k
        + 1_380 * tok_i
        + 7 * t_i
        + 10 * s
        + SETTLE_UNITS_PER_INPUT * further;
    if tranche {
        units += 159 + 770 * tok_i + 10 * t_i + 7 * n;
    }
    covering(with_margin(units))
}

/// Compute budget of the vault input of a refund of `leg`: the rule measured in
/// tests/engine/v2_measure.rs (`refund_units_are_measured`), units = 120,004 + 748 N + (a
/// depositor signs) (663 + 187 N) + (KCC-20 leg with its token) (4,290 + 17 T_i), measured with
/// one fee input, plus 168 for each further input the template allows (12 in all), plus the
/// margin.
pub fn refund_budget(terms: &TermsV2, leg: usize, depositor_signs: bool, with_token: bool) -> u16 {
    let n = terms.legs.len() as i64;
    let mut units = 120_004 + 748 * n;
    if depositor_signs {
        units += 663 + 187 * n;
    }
    if with_token {
        units += 4_290 + 17 * token_len(terms, leg);
    }
    let trade = 1 + i64::from(with_token);
    units += REFUND_UNITS_PER_INPUT * (MAX_VAULT_SPEND_INPUTS as i64 - trade - 1);
    covering(with_margin(units))
}

// =============================================================================================
// Builder inputs
// =============================================================================================

/// The escrowed token of a KCC-20 leg: a UTXO of the leg's covenant owned by the vault's script
/// hash, holding `amount` (not a minter), and the leg's token template.
#[derive(Clone, Debug)]
pub struct TokenEscrow<'a> {
    pub utxo: Utxo,
    pub amount: u64,
    pub template: &'a Kcc20Template,
}

/// One leg of a settle, in terms order.
#[derive(Clone, Debug)]
pub enum SettleLeg<'a> {
    /// A KAS leg: the UTXO at the leg's vault, holding the leg amount.
    Kas { vault: Utxo },
    /// A KCC-20 leg: the authorizer at the leg's vault and the escrowed token.
    Kcc20 {
        authorizer: Utxo,
        escrow: TokenEscrow<'a>,
    },
}

impl SettleLeg<'_> {
    fn vault(&self) -> &Utxo {
        match self {
            SettleLeg::Kas { vault } => vault,
            SettleLeg::Kcc20 { authorizer, .. } => authorizer,
        }
    }
}

/// Who signs a v2 refund (`refund(s, signerLeg)`): the depositor of leg `j`, named by that leg,
/// or the authority (signerLeg N). The contract tells the depositor of the refunded leg apart
/// by key, so a party that deposited several legs is that leg's depositor whichever it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundSignerV2 {
    Depositor(usize),
    Authority,
}

// =============================================================================================
// Builders
// =============================================================================================

/// Funds a KAS leg: output 0 exactly the leg amount at the leg's vault, paid with the funding
/// inputs, which also pay the fee. Refuses partial terms (funded as a KIP-20 genesis, I17) and a
/// leg amount below MIN_V2(1, O) (`TX_BELOW_MIN_KAS`).
pub fn fund_kas(
    terms: &ValidatedTermsV2,
    vault: &FundableVaultV2,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    let vault = consistent(terms, vault)?;
    fund_kas_at(terms, vault, funding, current_daa)
}

fn fund_kas_at(
    terms: &ValidatedTermsV2,
    vault: &VaultV2,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    let t = terms.terms();
    let leg = &t.legs[vault.leg()];
    if leg.asset.kind != LegKind::Kas {
        return Err(TxError::WrongMode {
            reason: "fund_kas funds a KAS leg",
        }
        .into());
    }
    not_expired(t, current_daa)?;
    let deposit = TransactionOutput::new(leg.asset.amount, vault.script_public_key());
    check_min(&deposit, 0, min_vault_v2(t))?;
    if t.partial.is_some() {
        // Every tranche delivers whole lots and a KAS delivery cannot be topped up ([S5]).
        let lot = TransactionOutput::new(t.unit(vault.leg()), vault.script_public_key());
        check_min(&lot, 0, min_v2(t, 1))?;
    }
    finish(
        Plan {
            terms,
            inputs: vec![],
            outputs: vec![deposit],
            lock_time: 0,
            genesis: t.partial.map(|_| 0),
            max_inputs: None,
        },
        funding,
    )
}

/// Funds a KCC-20 leg: output 0 the escrowed token (exactly the leg amount, owned by the vault's
/// script hash, carrying `carrier` KAS), output 1 the authorizer at the vault's address, then the
/// token change back to the depositor's key if the tokens hold more, then KAS change. The carrier
/// is at least MIN_V2(2, O) and the authorizer at least MIN_V2(1, O) (`TX_BELOW_MIN_KAS`).
pub fn fund_kcc20(
    terms: &ValidatedTermsV2,
    vault: &FundableVaultV2,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    let vault = consistent(terms, vault)?;
    fund_kcc20_at(terms, vault, template, deposit, funding, current_daa)
}

fn fund_kcc20_at(
    terms: &ValidatedTermsV2,
    vault: &VaultV2,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    let t = terms.terms();
    let leg = &t.legs[vault.leg()];
    let LegKind::Kcc20(token) = leg.asset.kind else {
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
    if held < leg.asset.amount {
        return Err(TxError::TokenInput {
            index: 0,
            reason: "the token inputs hold less than the leg amount",
        }
        .into());
    }
    let tok_min = min_v2(t, 2);
    let escrow_state = Kcc20State::new(script_hash_owner(vault), leg.asset.amount);
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
    check_min(&outputs[0], 0, tok_min)?;
    check_min(&outputs[1], 1, min_vault_v2(t))?;
    if held > leg.asset.amount {
        let change = Kcc20State::new(owner, held - leg.asset.amount);
        new_states.push(change);
        outputs.push(token_output(
            tok_min,
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
            genesis: t.partial.map(|_| 1),
            max_inputs: None,
        },
        funding,
    )
}

/// Settles every leg of a funded v2 trade in one transaction, final (spec/V2.md 4.3): vault i at
/// input i, the escrow of KCC-20 leg j at input N + j, the fee inputs last; the delivery of leg j
/// at output j, the authorizer of KCC-20 leg j home to its depositor at output N + j, the change
/// last. Lock time `earliest_daa` (or 0); the authority, if any, signs every vault input.
///
/// Without partial every escrow (or KAS vault UTXO) holds exactly its leg amount. With partial
/// this builds the final settle of what the escrows hold: whole lots, the same number in every
/// leg, at least min_lot. A tranche is [`settle_tranche`].
pub fn settle(
    terms: &ValidatedTermsV2,
    legs: &[SettleLeg<'_>],
    fee: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    settle_with(terms, legs, None, fee, current_daa)
}

/// Settles `lots` whole lots of every leg of a funded partial trade in one transaction (spec/V2.md
/// 4.3 and 4.4, I17). When `lots` is every lot the escrows hold, this is the final settle of
/// [`settle`]. Otherwise it is a tranche: the delivery of leg j at output j, the continuation of
/// vault i (the same script, bound to the vault input's covenant) at output N + i holding the
/// authorizer (KCC-20) or the remainder (KAS), the remainder token of KCC-20 leg j at output
/// 2N + j, the change last.
///
/// Refusals, after those of [`settle`] up to the amounts: `TX_TRANCHE` for terms without partial
/// and for lots below 1, below min_lot, above what an escrow holds or leaving a remainder below
/// min_lot lots; `TX_LINEAGE` for a tranche from a vault UTXO without a covenant ID; then the
/// same `TX_LINEAGE` for equal covenant IDs and `TX_LEGS_OUT_OF_STEP`.
pub fn settle_tranche(
    terms: &ValidatedTermsV2,
    legs: &[SettleLeg<'_>],
    lots: u64,
    fee: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    settle_with(terms, legs, Some(lots), fee, current_daa)
}

fn settle_with(
    terms: &ValidatedTermsV2,
    legs: &[SettleLeg<'_>],
    requested: Option<u64>,
    fee: &FeePayment,
    current_daa: u64,
) -> Result<IpstV2, V2Error> {
    let t = terms.terms();
    let n = t.legs.len();
    not_expired(t, current_daa)?;
    let vaults = (0..n)
        .map(|i| VaultV2::instantiate_existing(terms, i))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, leg) in legs.iter().enumerate().take(n) {
        at_vault(t, leg.vault(), &vaults[i])?;
    }
    if legs.len() != n {
        return Err(V2Error::Legs {
            reason: "the settle is not offered exactly one vault UTXO per leg",
        });
    }
    for (l, leg) in t.legs.iter().zip(legs) {
        let shape = matches!(
            (&l.asset.kind, leg),
            (LegKind::Kas, SettleLeg::Kas { .. }) | (LegKind::Kcc20(_), SettleLeg::Kcc20 { .. })
        );
        if !shape {
            return Err(V2Error::Legs {
                reason:
                    "a KCC-20 leg needs its authorizer and escrow, a KAS leg its vault UTXO only",
            });
        }
    }
    // Each escrow: the agreed template, this vault's script hash as owner, its stated amount.
    let mut held = Vec::with_capacity(n);
    for (i, leg) in legs.iter().enumerate() {
        match (leg, &t.legs[i].asset.kind) {
            (SettleLeg::Kcc20 { escrow, .. }, LegKind::Kcc20(token)) => {
                escrow.template.check_token(token)?;
                let state = Kcc20State::new(script_hash_owner(&vaults[i]), escrow.amount);
                escrow_at(&escrow.utxo, token, escrow.template, &state, "escrow")?;
                held.push(escrow.amount);
            }
            (SettleLeg::Kas { vault }, _) => held.push(vault.entry.amount),
            _ => unreachable!("shapes checked above"),
        }
    }
    // Amounts: exact without partial; whole lots, at most the amount, at least min_lot with it.
    if requested.is_some() && t.partial.is_none() {
        return Err(V2Error::Tranche {
            leg: 0,
            reason: "these terms have no partial settlement, so there is no tranche",
        });
    }
    let mut held_lots = Vec::with_capacity(n);
    for (i, h) in held.iter().enumerate() {
        let amount = t.legs[i].asset.amount;
        match t.partial {
            None => {
                if *h != amount {
                    return Err(TxError::LegAmount {
                        input: "leg escrow",
                        expected: amount,
                        found: *h,
                    }
                    .into());
                }
                held_lots.push(1);
            }
            Some(p) => {
                let unit = t.unit(i);
                if *h == 0 || *h > amount || h % unit != 0 {
                    return Err(V2Error::Tranche {
                        leg: i,
                        reason: "the escrow does not hold whole lots of at most the leg amount",
                    });
                }
                let have = h / unit;
                if have < p.min_lot {
                    return Err(V2Error::Tranche {
                        leg: i,
                        reason: "the escrow holds fewer than min_lot lots",
                    });
                }
                if let Some(lots) = requested {
                    if lots < 1 || lots > have {
                        return Err(V2Error::Tranche {
                            leg: i,
                            reason: "the tranche is not from 1 lot to what the escrow holds",
                        });
                    }
                    if lots < p.min_lot {
                        return Err(V2Error::Tranche {
                            leg: i,
                            reason: "the tranche is below min_lot lots",
                        });
                    }
                    let rest = have - lots;
                    if rest != 0 && rest < p.min_lot {
                        return Err(V2Error::Tranche {
                            leg: i,
                            reason: "the tranche leaves a remainder below min_lot lots",
                        });
                    }
                }
                held_lots.push(have);
            }
        }
    }
    let is_tranche = requested.is_some_and(|lots| lots < held_lots[0]);
    let mut covenants = HashSet::new();
    for leg in legs {
        match leg.vault().entry.covenant_id {
            Some(cov) => {
                if !covenants.insert(cov) {
                    return Err(V2Error::Lineage {
                        reason: "two vault UTXOs of one trade carry the same covenant ID",
                    });
                }
            }
            None if is_tranche => {
                return Err(V2Error::Lineage {
                    reason: "a tranche spends vault UTXOs that carry a covenant ID",
                });
            }
            None => {}
        }
    }
    if let Some(leg) = held_lots.iter().position(|l| *l != held_lots[0]) {
        return Err(V2Error::LegsOutOfStep { leg });
    }
    let lots = requested.unwrap_or(held_lots[0]);
    let unit = |j: usize| t.unit(j);
    let delivered = |j: usize| {
        if t.partial.is_some() {
            lots * unit(j)
        } else {
            held[j]
        }
    };

    let (kas_min, tok_min) = (min_v2(t, 1), min_v2(t, 2));
    let mut inputs = Vec::with_capacity(n + t.kcc20_legs());
    let mut outputs = Vec::with_capacity(2 * n + t.kcc20_legs());
    for (i, leg) in legs.iter().enumerate() {
        let budget = if is_tranche {
            tranche_budget(t, i)
        } else {
            settle_budget(t, i)
        };
        inputs.push(planned(
            leg.vault(),
            budget,
            settle_spend(&vaults[i], t.authority_key, lots)?,
        ));
    }
    let mut remainders = Vec::new();
    for (j, leg) in legs.iter().enumerate() {
        let l = &t.legs[j];
        match (leg, &l.asset.kind) {
            (SettleLeg::Kas { .. }, _) => outputs.push(TransactionOutput::new(
                delivered(j),
                kas_destination(&l.delivery),
            )),
            (SettleLeg::Kcc20 { escrow, .. }, LegKind::Kcc20(token)) => {
                let escrow_state = Kcc20State::new(script_hash_owner(&vaults[j]), held[j]);
                let delivery = Kcc20State::new(owner(&l.delivery), delivered(j));
                let mut new_states = vec![delivery];
                if is_tranche {
                    new_states.push(Kcc20State::new(
                        script_hash_owner(&vaults[j]),
                        held[j] - delivered(j),
                    ));
                }
                inputs.push(planned(
                    &escrow.utxo,
                    kcc20_leader_budget(false, template_bytes(token), 1, new_states.len() as u64),
                    complete(escrow.template.leader_sigscript(
                        &escrow_state,
                        &new_states,
                        &[0; 65],
                        j as u8,
                    )?),
                ));
                outputs.push(token_output(
                    escrow.utxo.entry.amount.max(tok_min),
                    escrow.template.script_public_key(&delivery)?,
                    token,
                    (n + j) as u16,
                ));
                if is_tranche {
                    remainders.push(token_output(
                        escrow.utxo.entry.amount.max(tok_min),
                        escrow.template.script_public_key(&new_states[1])?,
                        token,
                        (n + j) as u16,
                    ));
                }
            }
            _ => unreachable!("shapes checked above"),
        }
    }
    if is_tranche {
        for (i, leg) in legs.iter().enumerate() {
            let value = match leg {
                SettleLeg::Kas { .. } => held[i] - delivered(i),
                SettleLeg::Kcc20 { authorizer, .. } => authorizer.entry.amount.max(min_vault_v2(t)),
            };
            let cov = leg
                .vault()
                .entry
                .covenant_id
                .expect("a tranche's vault UTXOs carry covenant IDs, checked above");
            let out = TransactionOutput::with_covenant(
                value,
                vaults[i].script_public_key(),
                Some(CovenantBinding::new(i as u16, cov)),
            );
            if matches!(leg, SettleLeg::Kas { .. }) {
                check_min(&out, n + i, min_vault_v2(t))?;
            }
            outputs.push(out);
        }
        outputs.extend(remainders);
    } else {
        for (i, leg) in legs.iter().enumerate() {
            if let SettleLeg::Kcc20 { authorizer, .. } = leg {
                outputs.push(TransactionOutput::new(
                    authorizer.entry.amount.max(kas_min),
                    p2pk(&t.legs[i].depositor_key),
                ));
            }
        }
    }
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: t.earliest_daa.unwrap_or(0),
            genesis: None,
            max_inputs: Some(max_v2_settle_inputs(n)),
        },
        fee,
    )
}

/// Refunds one vault UTXO of `leg` home (spec/V2.md 4.5): input 0 the vault UTXO, output 0 its
/// KAS, whole (to the leg's refund destination for a KAS leg, to the depositor's key for a
/// KCC-20 leg); a KCC-20 leg's escrowed token, when included, at input 1 and home whole at output
/// 1. Lock time `expiry_daa` for the depositor's own refund of an earmarked leg, else 0.
///
/// Anyone named in the terms who is not the leg's depositor (another depositor, the authority)
/// refunds a KCC-20 leg only with its token, holding whole lots of at most the leg amount
/// (exactly the amount without partial).
pub fn refund(
    terms: &ValidatedTermsV2,
    leg: usize,
    signer: RefundSignerV2,
    vault_utxo: &Utxo,
    escrow: Option<&RefundEscrow<'_>>,
    fee: &FeePayment,
) -> Result<IpstV2, V2Error> {
    let t = terms.terms();
    let vault = VaultV2::instantiate_existing(terms, leg)?;
    let n = t.legs.len();
    let (signer_leg, signer_key) = match signer {
        RefundSignerV2::Depositor(j) if j < n => (j, t.legs[j].depositor_key),
        RefundSignerV2::Depositor(_) => {
            return Err(TxError::RefundSigner {
                reason: "the signer names no leg of these terms",
            }
            .into())
        }
        RefundSignerV2::Authority => (
            n,
            t.authority_key.ok_or(TxError::RefundSigner {
                reason: "these terms have no settlement authority",
            })?,
        ),
    };
    at_vault(t, vault_utxo, &vault)?;
    let l = &t.legs[leg];
    let is_depositor = signer_key == l.depositor_key;
    let with_token = escrow.is_some();
    let mut inputs = vec![planned(
        vault_utxo,
        refund_budget(t, leg, is_depositor, with_token),
        refund_spend(&vault, signer_key, signer_leg)?,
    )];
    let mut outputs = vec![];
    match l.asset.kind {
        LegKind::Kas => {
            if with_token {
                return Err(TxError::WrongMode {
                    reason: "a KAS leg has no escrowed token",
                }
                .into());
            }
            outputs.push(TransactionOutput::new(
                vault_utxo.entry.amount,
                kas_destination(&l.refund),
            ));
        }
        LegKind::Kcc20(token) => {
            outputs.push(TransactionOutput::new(
                vault_utxo.entry.amount,
                p2pk(&l.depositor_key),
            ));
            match escrow {
                None if !is_depositor => {
                    return Err(TxError::RefundSigner {
                        reason: "a refund of a KCC-20 leg by anyone but its depositor takes the escrowed token home with it",
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
                    let unit = t.unit(leg);
                    let whole =
                        e.amount >= unit && e.amount <= l.asset.amount && e.amount % unit == 0;
                    if !is_depositor && !whole {
                        return Err(TxError::LegAmount {
                            input: "escrowed token",
                            expected: l.asset.amount,
                            found: e.amount,
                        }
                        .into());
                    }
                    let home = Kcc20State {
                        owner: owner(&l.refund),
                        ..held
                    };
                    inputs.push(planned(
                        &e.utxo,
                        kcc20_leader_budget(false, template_bytes(&token), 1, 1),
                        complete(e.template.leader_sigscript(&held, &[home], &[0; 65], 0)?),
                    ));
                    outputs.push(token_output(
                        e.utxo.entry.amount.max(min_v2(t, 2)),
                        e.template.script_public_key(&home)?,
                        &token,
                        1,
                    ));
                }
            }
        }
        LegKind::External => unreachable!("structure checks refuse external v2 legs"),
    }
    let lock_time = if t.funding_mode == FundingMode::Earmarked && is_depositor {
        t.expiry_daa
    } else {
        0
    };
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time,
            genesis: None,
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

// =============================================================================================
// Checks on the legs
// =============================================================================================

fn consistent<'v>(
    terms: &ValidatedTermsV2,
    vault: &'v FundableVaultV2,
) -> Result<&'v VaultV2, V2Error> {
    match VaultV2::instantiate_existing(terms, vault.vault().leg()) {
        Ok(v) if v == *vault.vault() => Ok(vault.vault()),
        _ => Err(TxError::VaultMismatch.into()),
    }
}

/// As v1: the trade can still settle by expiry_daa.
fn not_expired(t: &TermsV2, current_daa: u64) -> Result<(), V2Error> {
    let settles_late = t.earliest_daa.is_some_and(|e| e >= t.expiry_daa);
    if current_daa >= t.expiry_daa || settles_late {
        return Err(TxError::Expired {
            current_daa,
            expiry_daa: t.expiry_daa,
        }
        .into());
    }
    Ok(())
}

/// A vault UTXO at the vault's P2SH, without a covenant ID unless the terms are partial.
fn at_vault(t: &TermsV2, utxo: &Utxo, vault: &VaultV2) -> Result<(), V2Error> {
    let covenant_ok = t.partial.is_some() || utxo.entry.covenant_id.is_none();
    if utxo.entry.script_public_key != vault.script_public_key() || !covenant_ok {
        return Err(V2Error::NotAtVault { leg: vault.leg() });
    }
    Ok(())
}

fn check_min(output: &TransactionOutput, index: usize, minimum: u64) -> Result<(), V2Error> {
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

fn script_hash_owner(vault: &VaultV2) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

fn owner(d: &DestinationV2) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: d.identifier_type,
        identifier: d.identifier,
    }
}

/// `destSpk(type, id)` of the template: a Schnorr P2PK for type 0, a P2SH for type 1. The
/// scriptPublicKey a KAS leg's delivery or refund pays.
pub fn kas_destination(d: &DestinationV2) -> ScriptPublicKey {
    match d.identifier_type {
        IdentifierType::PubKey => p2pk(&d.identifier),
        _ => {
            let mut s = Vec::with_capacity(35);
            s.push(OpBlake2b);
            s.push(OpData32);
            s.extend_from_slice(&d.identifier);
            s.push(OpEqual);
            ScriptPublicKey::from_vec(0, s)
        }
    }
}

// =============================================================================================
// Spends
// =============================================================================================

fn vault_entry(vault: &VaultV2, entry: &str, args: Vec<ArtifactValue>) -> Result<Vec<u8>, V2Error> {
    let template = template_check()?;
    let mut script = encode_contract_entry_sig_script(template.abi(), CONTRACT_NAME, entry, &args)
        .map_err(|e| TxError::Encoding {
            reason: format!("ImpulseVaultV2 {entry}: {e}"),
        })?;
    script.extend_from_slice(&push_data(vault.redeem_script())?);
    Ok(script)
}

/// `settle(sig authSig, int lots)`: signed by the authority, or 65 zero bytes when self-settling.
fn settle_spend(vault: &VaultV2, authority: Option<[u8; 32]>, lots: u64) -> Result<Spend, V2Error> {
    let lots = i64::try_from(lots).map_err(|_| TxError::Encoding {
        reason: "lots past the script integer range".into(),
    })?;
    let encode = |sig: &[u8; 65]| {
        vault_entry(
            vault,
            "settle",
            vec![ArtifactValue::Bytes(sig.to_vec()), ArtifactValue::Int(lots)],
        )
        .map_err(to_tx)
    };
    Ok(match authority {
        Some(key) => signed(key, encode)?,
        None => complete(encode(&[0; 65])?),
    })
}

/// `refund(sig s, int signerLeg)`.
fn refund_spend(vault: &VaultV2, signer: [u8; 32], signer_leg: usize) -> Result<Spend, V2Error> {
    Ok(signed(signer, |sig| {
        vault_entry(
            vault,
            "refund",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Int(signer_leg as i64),
            ],
        )
        .map_err(to_tx)
    })?)
}

/// `signed` takes a closure returning `TxError`; a v2 template refusal travels as an encoding
/// fault there and never happens once the startup check passed.
fn to_tx(e: V2Error) -> TxError {
    match e {
        V2Error::Tx(e) => e,
        other => TxError::Encoding {
            reason: other.to_string(),
        },
    }
}

// =============================================================================================
// The checks every transaction shares
// =============================================================================================

struct Plan<'t> {
    terms: &'t ValidatedTermsV2,
    inputs: Vec<PlannedInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    /// The output made a KIP-20 genesis of its own covenant group (partial funding, spec/V2.md
    /// 6.1), authorized by the first payer input.
    genesis: Option<u32>,
    /// The most inputs the vault template the transaction spends allows, if it sets a bound.
    max_inputs: Option<usize>,
}

/// v1's `finish` with the v2 rules: appends the fee inputs and the change, then checks in order
/// the fee inputs (`TX_KAS_INPUT`), at most the inputs the spent vault template allows
/// (`TX_TOO_MANY_INPUTS`), no outpoint twice (`TX_DUPLICATE_INPUT`), the spent values
/// (`TX_UTXO_VALUE`), the change script (`TX_NONSTANDARD_CHANGE`), the funds
/// (`TX_INSUFFICIENT_FUNDS`), the change at least MIN_V2(1, O) (`TX_BELOW_MIN_KAS`); builds the
/// transaction and each slot's sighash; then the masses against CAP_V2 (`TX_V2_MASS`) and the
/// relay fee (`TX_FEE_TOO_LOW`).
fn finish(mut plan: Plan<'_>, fee: &FeePayment) -> Result<IpstV2, V2Error> {
    let t = plan.terms.terms();
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
        check_min(&change, plan.outputs.len(), min_v2(t, 1))?;
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
    let mut tx = Transaction::new(
        TX_VERSION_TOCCATA,
        tx_inputs,
        plan.outputs,
        plan.lock_time,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    if let Some(output) = plan.genesis {
        tx.populate_genesis_covenants(&[GenesisCovenantGroup {
            authorizing_input: u16::try_from(first_fee).unwrap_or(u16::MAX),
            outputs: vec![output],
        }])
        .map_err(|_| V2Error::Lineage {
            reason: "the genesis covenant group does not fit the funding transaction",
        })?;
        // The bindings are part of the transaction ID.
        tx.finalize();
    }
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
            slot.sighash = Some(sighash(&tx, &entries, index)?);
        }
    }
    let ipst = IpstV2::from_parts(plan.terms.clone(), tx, entries, slots);
    let masses = ipst.masses();
    check_masses(&masses, t.network)?;
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

/// The masses of a signed-size transaction with the pinned calculator.
pub(crate) fn masses_of(sized: &Transaction, entries: &[UtxoEntry], network: Network) -> Masses {
    compute_masses(sized, entries, network)
}

/// Refuses any dimension above its CAP_V2 cap (`TX_V2_MASS`), in the order compute, transient,
/// storage (v1's order).
pub(crate) fn check_masses(masses: &Masses, network: Network) -> Result<(), V2Error> {
    let caps = caps(network);
    for (dimension, mass, cap) in [
        ("compute", masses.compute, caps.compute),
        ("transient", masses.transient, caps.transient),
        ("storage", masses.storage, caps.storage),
    ] {
        if mass > cap {
            return Err(V2Error::Mass {
                dimension,
                mass,
                cap,
            });
        }
    }
    Ok(())
}

// =============================================================================================
// The terms check: the transaction the builders make from an IPST's own inputs
// =============================================================================================

/// Which builder makes an IPST of version 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpstV2Kind {
    FundKas {
        leg: usize,
    },
    FundKcc20 {
        leg: usize,
    },
    Settle,
    /// A tranche of `lots` lots (I17), the vault continuing.
    Tranche {
        lots: u64,
    },
    Refund {
        leg: usize,
        signer: RefundSignerV2,
        with_token: bool,
    },
}

/// An IPST of version 2 that passed the terms check: which builder makes it, its fee and the
/// output after the trade outputs, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermsMatchV2 {
    pub kind: IpstV2Kind,
    pub fee: u64,
    pub change: Option<TransactionOutput>,
}

fn unknown() -> V2Error {
    TxError::IpstTermsMismatch {
        reason: "not a transaction the builders make for these terms",
    }
    .into()
}

/// Rebuilds with the builders the transaction an IPST of version 2 should be: its terms, its own
/// inputs where the layout puts them (token states read from the redeem scripts the token
/// inputs carry), its fee and its change destination. `templates[j]` is the token template of
/// KCC-20 leg j. Returns the kind, the number of trade outputs and the rebuilt IPST.
pub(crate) fn rebuild(
    ipst: &IpstV2,
    templates: &[&Kcc20Template],
    current_daa: u64,
) -> Result<(IpstV2Kind, usize, IpstV2), V2Error> {
    let terms = ipst.terms();
    let t = terms.terms();
    let n = t.legs.len();
    let k = t.kcc20_legs();
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
    let input = |i: usize| utxos.get(i).cloned().ok_or_else(unknown);
    let template = |j: usize| -> Result<&Kcc20Template, V2Error> {
        templates.get(j).copied().ok_or_else(|| {
            TxError::TokenTemplate {
                reason: format!("no template given for KCC-20 leg {j}"),
            }
            .into()
        })
    };
    let token_at = |i: usize, tmpl: &Kcc20Template| -> Result<TokenUtxo, V2Error> {
        Ok(TokenUtxo {
            utxo: input(i)?,
            state: token_state(slots, i, tmpl).ok_or_else(unknown)?,
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
    let vaults = (0..n)
        .map(|i| VaultV2::instantiate_existing(terms, i))
        .collect::<Result<Vec<_>, _>>()?;
    let first = input(0)?;
    let at = |u: &Utxo, i: usize| u.entry.script_public_key == vaults[i].script_public_key();

    // Settle: inputs 0 .. N-1 at the vaults of legs 0 .. N-1.
    if (0..n).all(|i| utxos.get(i).is_some_and(|u| at(u, i))) && n >= 2 {
        let mut legs = Vec::with_capacity(n);
        for (i, l) in t.legs.iter().enumerate() {
            legs.push(match l.asset.kind {
                LegKind::Kas => SettleLeg::Kas { vault: input(i)? },
                _ => {
                    let tmpl = template(i)?;
                    let held = token_at(n + i, tmpl)?;
                    SettleLeg::Kcc20 {
                        authorizer: input(i)?,
                        escrow: TokenEscrow {
                            utxo: held.utxo,
                            amount: held.state.amount,
                            template: tmpl,
                        },
                    }
                }
            });
        }
        if t.partial.is_some() {
            let lots =
                super::receipt::settle_lots(&slots[0].script_with(&[0; 65])).ok_or_else(unknown)?;
            let held = match &legs[0] {
                SettleLeg::Kas { vault } => vault.entry.amount,
                SettleLeg::Kcc20 { escrow, .. } => escrow.amount,
            };
            if lots < held / t.unit(0) {
                let trade_outputs = 2 * n + k;
                let rebuilt =
                    settle_tranche(terms, &legs, lots, &fee(n + k, trade_outputs), current_daa)?;
                return Ok((IpstV2Kind::Tranche { lots }, trade_outputs, rebuilt));
            }
        }
        let trade_outputs = n + k;
        let rebuilt = settle(terms, &legs, &fee(n + k, trade_outputs), current_daa)?;
        return Ok((IpstV2Kind::Settle, trade_outputs, rebuilt));
    }
    // Refund: input 0 at the vault of some leg; the role is the slot's signer and its signerLeg.
    if let Some(leg) = (0..n).find(|i| at(&first, *i)) {
        let signer_key = slots[0].signer().ok_or_else(unknown)?;
        let l = &t.legs[leg];
        let escrow = match (l.asset.kind, utxos.get(1)) {
            (LegKind::Kcc20(token), Some(u))
                if u.entry.covenant_id == Some(Hash::from_bytes(token.covenant_id)) =>
            {
                let tmpl = template(leg)?;
                let held = token_at(1, tmpl)?;
                Some(RefundEscrow {
                    utxo: held.utxo,
                    amount: held.state.amount,
                    is_minter: held.state.is_minter,
                    template: tmpl,
                })
            }
            _ => None,
        };
        let candidates = (0..n)
            .filter(|j| t.legs[*j].depositor_key == signer_key)
            .map(RefundSignerV2::Depositor)
            .chain((t.authority_key == Some(signer_key)).then_some(RefundSignerV2::Authority));
        let vault = &vaults[leg];
        for signer in candidates {
            let signer_leg = match signer {
                RefundSignerV2::Depositor(j) => j,
                RefundSignerV2::Authority => n,
            };
            if !same_spend(&slots[0], &refund_spend(vault, signer_key, signer_leg)?) {
                continue;
            }
            let trade = 1 + usize::from(escrow.is_some());
            let rebuilt = refund(
                terms,
                leg,
                signer,
                &first,
                escrow.as_ref(),
                &fee(trade, trade),
            )?;
            let kind = IpstV2Kind::Refund {
                leg,
                signer,
                with_token: escrow.is_some(),
            };
            return Ok((kind, trade, rebuilt));
        }
        return Err(unknown());
    }
    // Funding a KAS leg: the deposit at the leg's vault is output 0.
    for (leg, l) in t.legs.iter().enumerate() {
        let vault = &vaults[leg];
        let spk = vault.script_public_key();
        match l.asset.kind {
            LegKind::Kas => {
                let there = tx
                    .outputs
                    .first()
                    .is_some_and(|o| o.script_public_key == spk);
                if there && first.entry.covenant_id.is_none() {
                    let rebuilt = fund_kas_at(terms, vault, &fee(0, 1), current_daa)?;
                    return Ok((IpstV2Kind::FundKas { leg }, 1, rebuilt));
                }
            }
            LegKind::Kcc20(token) => {
                let cov = Some(Hash::from_bytes(token.covenant_id));
                let there = tx
                    .outputs
                    .get(1)
                    .is_some_and(|o| o.script_public_key == spk);
                if first.entry.covenant_id != cov || !there {
                    continue;
                }
                let tmpl = template(leg)?;
                let count = utxos
                    .iter()
                    .take_while(|u| u.entry.covenant_id == cov)
                    .count();
                let tokens = (0..count)
                    .map(|i| token_at(i, tmpl))
                    .collect::<Result<Vec<_>, _>>()?;
                let held = tokens
                    .iter()
                    .fold(0u64, |sum, tok| sum.saturating_add(tok.state.amount));
                let trade = 2 + usize::from(held > l.asset.amount);
                let deposit = Kcc20Deposit {
                    tokens,
                    carrier: tx.outputs[0].value,
                    authorizer: tx.outputs[1].value,
                };
                let rebuilt = fund_kcc20_at(
                    terms,
                    vault,
                    tmpl,
                    &deposit,
                    &fee(count, trade),
                    current_daa,
                )?;
                return Ok((IpstV2Kind::FundKcc20 { leg }, trade, rebuilt));
            }
            LegKind::External => {}
        }
    }
    Err(unknown())
}
