// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The five builders of spec/TRANSACTIONS.md: fund a KAS leg, fund a KCC-20 leg (escrowed token
//! and authorizer), settle (the canonical layout, per mode), refund (per signer role) and Direct.
//! Each checks its own inputs against the terms first, then plans the inputs and outputs, then
//! runs the checks every transaction shares (`finish`).

use super::ipst::{Ipst, Slot};
use super::kcc20::{Kcc20State, Kcc20Template};
use super::rules::{
    check_masses, check_min, kcc20_delegate_budget, kcc20_leader_budget, min_output_value,
    min_relay_fee, vault_budget, MAX_OUTPUTS, MIN_KCC20_OUTPUT, P2PK_BUDGET,
};
use super::{last_push, p2pk, p2pk_key, push_data, sighash, FeePayment, TokenUtxo, TxError, Utxo};
use crate::bounds::MAX_VAULT_SPEND_INPUTS;
use crate::locktime::{refund_lock_time, settle_lock_time, INPUT_SEQUENCE};
use crate::template::{self, FundableVault, LegIndex, Vault, CONTRACT_NAME};
use crate::terms::{
    Destination, IdentifierType, Kcc20Owner, Kcc20Token, LegKind, SettlementMode, Terms,
    ValidatedTerms,
};
use kaspa_consensus_core::constants::{
    MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI, TX_VERSION_TOCCATA,
};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpData65;
use kaspa_txscript::script_class::ScriptClass;
use silverscript_abi::{encode_contract_entry_sig_script, ArtifactValue};
use std::collections::HashSet;

// =============================================================================================
// Builder inputs
// =============================================================================================

/// The depositor's side of a KCC-20 funding: token UTXOs of the leg's covenant, all owned by one
/// public key, holding at least the leg amount together; the KAS the escrowed token carries; and
/// the KAS of the authorizer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kcc20Deposit {
    pub tokens: Vec<TokenUtxo>,
    /// KAS on the escrowed token output. At least `MIN_KCC20_OUTPUT`.
    pub carrier: u64,
    /// KAS on the authorizer output at the vault address. At least `MIN_KAS_OUTPUT`.
    pub authorizer: u64,
}

/// The vault UTXOs a settle spends.
#[derive(Clone, Debug)]
pub struct SettleLegs<'a> {
    /// KAS UTXO at the asset vault's address.
    pub asset_authorizer: Utxo,
    /// KCC-20 UTXO owned by the asset vault's script hash, holding exactly the asset amount.
    pub asset_escrow: Utxo,
    pub asset_token: &'a Kcc20Template,
    pub cash: SettleCash<'a>,
}

/// The cash side of a settle, by the terms' cash kind.
#[derive(Clone, Debug)]
pub enum SettleCash<'a> {
    /// The cash vault UTXO, holding exactly the cash amount.
    Kas { vault: Utxo },
    /// The cash authorizer and the escrowed cash token.
    Kcc20 {
        authorizer: Utxo,
        escrow: Utxo,
        token: &'a Kcc20Template,
    },
    /// No on-chain cash: the authority attests the off-chain payment.
    External,
}

/// Who signs a refund. Every refund goes home; the roles differ only in what the contract lets
/// them do (spec "Entries", `refund`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefundSigner {
    /// The leg's depositor: the seller for the asset leg, the buyer for the cash leg.
    Depositor,
    /// The other party.
    Counterparty,
    /// The settlement authority.
    Authority,
}

/// A KCC-20 UTXO owned by the vault's script hash, refunded with the authorizer. The depositor
/// may refund any amount; anyone else only exactly the leg amount. A minter goes home as a
/// minter, whoever signs.
#[derive(Clone, Debug)]
pub struct RefundEscrow<'a> {
    pub utxo: Utxo,
    pub amount: u64,
    pub is_minter: bool,
    pub template: &'a Kcc20Template,
}

/// The parties' own UTXOs a Direct transaction spends. Each holds exactly its leg amount.
#[derive(Clone, Debug)]
pub struct DirectLegs<'a> {
    /// The seller's KCC-20 UTXO, owned by a public key.
    pub asset: TokenUtxo,
    pub asset_token: &'a Kcc20Template,
    pub cash: DirectCash<'a>,
}

/// The buyer's cash in a Direct transaction.
#[derive(Clone, Debug)]
pub enum DirectCash<'a> {
    /// A version-0 P2PK Schnorr UTXO holding exactly the cash amount.
    Kas(Utxo),
    /// A KCC-20 UTXO owned by a public key, holding exactly the cash amount.
    Kcc20 {
        token: TokenUtxo,
        template: &'a Kcc20Template,
    },
}

// =============================================================================================
// Builders
// =============================================================================================

/// Funds a KAS cash leg: one output of exactly the cash amount at the cash vault's address,
/// paid with the funding inputs, which also pay the fee.
pub fn fund_kas(
    terms: &ValidatedTerms,
    vault: &FundableVault,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    fund_kas_at(terms, consistent_vault(terms, vault)?, funding, current_daa)
}

fn fund_kas_at(
    terms: &ValidatedTerms,
    vault: &Vault,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    let t = terms.terms();
    if vault.leg() != LegIndex::Cash || t.cash_leg.kind != LegKind::Kas {
        return Err(TxError::WrongMode {
            reason: "fund_kas funds a KAS cash leg",
        });
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
            max_inputs: None,
        },
        funding,
    )
}

/// Funds a KCC-20 leg: output 0 the escrowed token (exactly the leg amount, owned by the vault's
/// script hash, carrying `carrier` KAS), output 1 the authorizer at the vault's address, then the
/// token change back to the depositor's key if the tokens hold more, then KAS change.
pub fn fund_kcc20(
    terms: &ValidatedTerms,
    vault: &FundableVault,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    let vault = consistent_vault(terms, vault)?;
    fund_kcc20_at(terms, vault, template, deposit, funding, current_daa)
}

fn fund_kcc20_at(
    terms: &ValidatedTerms,
    vault: &Vault,
    template: &Kcc20Template,
    deposit: &Kcc20Deposit,
    funding: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    let t = terms.terms();
    let leg = match vault.leg() {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let LegKind::Kcc20(token) = leg.kind else {
        return Err(TxError::WrongMode {
            reason: "fund_kcc20 funds a KCC-20 leg",
        });
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
        });
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
            inputs,
            outputs,
            lock_time: 0,
            max_inputs: None,
        },
        funding,
    )
}

/// Settles a funded vault trade in the canonical layout (spec "Canonical settle transaction"):
/// the asset authorizer at input 0, the cash authorizer or KAS cash at input 1, the escrowed
/// tokens after them, the fee inputs last; the asset delivery at output 0, the cash delivery at
/// output 1, each KCC-20 authorizer's KAS back to its depositor, the change last. External cash
/// drops positions 1 and 3. Lock time `earliest_daa` (or 0); the authority signs inputs 0 and 1.
/// The transaction has at most `MAX_VAULT_SPEND_INPUTS` inputs (`TX_TOO_MANY_INPUTS`).
pub fn settle(
    terms: &ValidatedTerms,
    legs: &SettleLegs<'_>,
    fee: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    let t = terms.terms();
    if t.settlement_mode != SettlementMode::Vault {
        return Err(TxError::WrongMode {
            reason: "settle spends vaults; Direct terms have none",
        });
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
        });
    }
    not_expired(t, current_daa)?;

    let asset_vault = Vault::instantiate_existing(terms, LegIndex::Asset)?;
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
    let settle_budget = vault_budget(
        template_bytes(&asset)
            + match t.cash_leg.kind {
                LegKind::Kcc20(cash) => template_bytes(&cash),
                _ => 0,
            },
    );

    let mut inputs = vec![planned(
        &legs.asset_authorizer,
        settle_budget,
        vault_settle(&asset_vault, authority)?,
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
            let cash_vault = Vault::instantiate_existing(terms, LegIndex::Cash)?;
            at_vault(vault, &cash_vault, "KAS cash")?;
            if vault.entry.amount != t.cash_leg.amount {
                return Err(TxError::LegAmount {
                    input: "KAS cash vault UTXO",
                    expected: t.cash_leg.amount,
                    found: vault.entry.amount,
                });
            }
            inputs.push(planned(
                vault,
                settle_budget,
                vault_settle(&cash_vault, authority)?,
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
            let cash_vault = Vault::instantiate_existing(terms, LegIndex::Cash)?;
            at_vault(authorizer, &cash_vault, "cash authorizer")?;
            template.check_token(&cash)?;
            let cash_escrow_state =
                Kcc20State::new(script_hash_owner(&cash_vault), t.cash_leg.amount);
            escrow_at(escrow, &cash, template, &cash_escrow_state, "cash escrow")?;
            let cash_delivered =
                Kcc20State::new(kcc20_owner(&t.seller_proceeds), t.cash_leg.amount);
            inputs.push(planned(
                authorizer,
                settle_budget,
                vault_settle(&cash_vault, authority)?,
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
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: settle_lock_time(t),
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

/// Refunds one vault UTXO of `leg` home (spec "Entries", `refund`): input 0 the vault UTXO,
/// output 0 its KAS, whole, to the depositor (the buyer's refund scriptPubKey for KAS cash, the
/// depositor's key for a KCC-20 leg). A KCC-20 leg's escrowed token, when included, rides at
/// input 1 and goes home whole at output 1. Lock time `expiry_daa` for the depositor's refund of
/// an earmarked leg, else 0.
///
/// Without the token (`escrow` None, the depositor only) the authorizer goes home alone and the
/// escrowed token stays owned by the vault's script hash: it moves again only beside another
/// UTXO at the vault's address, so the depositor funds a new authorizer and refunds that one
/// with the token (spec/TRANSACTIONS.md, "refund").
///
/// The transaction has at most `MAX_VAULT_SPEND_INPUTS` inputs (`TX_TOO_MANY_INPUTS`).
pub fn refund(
    terms: &ValidatedTerms,
    leg: LegIndex,
    signer: RefundSigner,
    vault_utxo: &Utxo,
    escrow: Option<&RefundEscrow<'_>>,
    fee: &FeePayment,
) -> Result<Ipst, TxError> {
    let t = terms.terms();
    if t.settlement_mode != SettlementMode::Vault {
        return Err(TxError::WrongMode {
            reason: "refund spends a vault; Direct terms have none",
        });
    }
    let vault = Vault::instantiate_existing(terms, leg)?;
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
                });
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
                    });
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
                        });
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
            inputs,
            outputs,
            lock_time: refund_lock_time(t, signer == RefundSigner::Depositor),
            max_inputs: Some(MAX_VAULT_SPEND_INPUTS),
        },
        fee,
    )
}

/// The Direct transaction (spec "Settlement modes"): input 0 the seller's asset token, input 1
/// the buyer's cash, the fee inputs after them; output 0 the asset to the buyer's delivery and
/// output 1 the cash to the seller's proceeds, as in settle, then the change. Each party signs
/// its own input; lock time `earliest_daa` (or 0).
pub fn direct(
    terms: &ValidatedTerms,
    legs: &DirectLegs<'_>,
    fee: &FeePayment,
    current_daa: u64,
) -> Result<Ipst, TxError> {
    let t = terms.terms();
    if t.settlement_mode != SettlementMode::Direct {
        return Err(TxError::WrongMode {
            reason: "direct needs Direct terms",
        });
    }
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        unreachable!("structure checks make the asset leg KCC-20");
    };
    let cash_matches = matches!(
        (&legs.cash, t.cash_leg.kind),
        (DirectCash::Kas(_), LegKind::Kas) | (DirectCash::Kcc20 { .. }, LegKind::Kcc20(_))
    );
    if !cash_matches {
        return Err(TxError::WrongMode {
            reason: "the cash leg passed is not of the terms' cash kind",
        });
    }
    not_expired(t, current_daa)?;
    legs.asset_token.check_token(&asset)?;
    let seller = own_tokens(std::slice::from_ref(&legs.asset), &asset, legs.asset_token)?;
    exact(&legs.asset, t.asset_leg.amount, "seller's asset token")?;
    let delivered = Kcc20State::new(kcc20_owner(&t.buyer_delivery), t.asset_leg.amount);
    let mut inputs = vec![planned(
        &legs.asset.utxo,
        kcc20_leader_budget(true, template_bytes(&asset), 1, 1),
        signed(seller.identifier, |sig| {
            legs.asset_token
                .leader_sigscript(&legs.asset.state, &[delivered], sig, 0)
        })?,
    )];
    let mut outputs = vec![topped_up(token_output(
        legs.asset.utxo.entry.amount,
        legs.asset_token.script_public_key(&delivered)?,
        &asset,
        0,
    ))];
    match &legs.cash {
        DirectCash::Kas(utxo) => {
            let key = kas_key(utxo, 1)?;
            if utxo.entry.amount != t.cash_leg.amount {
                return Err(TxError::LegAmount {
                    input: "buyer's KAS cash",
                    expected: t.cash_leg.amount,
                    found: utxo.entry.amount,
                });
            }
            let paid =
                TransactionOutput::new(t.cash_leg.amount, kas_destination(&t.seller_proceeds));
            check_min(&paid, 1)?;
            inputs.push(planned(utxo, P2PK_BUDGET, p2pk_spend(key)));
            outputs.push(paid);
        }
        DirectCash::Kcc20 { token, template } => {
            let LegKind::Kcc20(cash) = t.cash_leg.kind else {
                unreachable!("matched above");
            };
            template.check_token(&cash)?;
            let buyer = own_tokens(std::slice::from_ref(token), &cash, template)?;
            exact(token, t.cash_leg.amount, "buyer's cash token")?;
            let paid = Kcc20State::new(kcc20_owner(&t.seller_proceeds), t.cash_leg.amount);
            inputs.push(planned(
                &token.utxo,
                kcc20_leader_budget(true, template_bytes(&cash), 1, 1),
                signed(buyer.identifier, |sig| {
                    template.leader_sigscript(&token.state, &[paid], sig, 0)
                })?,
            ));
            outputs.push(topped_up(token_output(
                token.utxo.entry.amount,
                template.script_public_key(&paid)?,
                &cash,
                1,
            )));
        }
    }
    finish(
        Plan {
            terms,
            inputs,
            outputs,
            lock_time: settle_lock_time(t),
            max_inputs: None,
        },
        fee,
    )
}

// =============================================================================================
// Checks on the legs
// =============================================================================================

/// The vault of a `FundableVault`, if it is the one these terms give for its leg.
fn consistent_vault<'v>(
    terms: &ValidatedTerms,
    vault: &'v FundableVault,
) -> Result<&'v Vault, TxError> {
    match Vault::instantiate_existing(terms, vault.vault().leg()) {
        Ok(v) if v == *vault.vault() => Ok(vault.vault()),
        _ => Err(TxError::VaultMismatch),
    }
}

/// The vault templates bound the inputs of a spend (spec/TEMPLATE.md, "Inputs outside the
/// layout").
pub(crate) fn too_many_inputs(inputs: usize, max: Option<usize>) -> Result<(), TxError> {
    match max {
        Some(max) if inputs > max => Err(TxError::TooManyInputs { inputs, max }),
        _ => Ok(()),
    }
}

/// The trade can still settle by expiry_daa: the next block (DAA score above `current_daa`) is
/// not past it, and the settle's lock time lets it in a block at or below it. A lock time of
/// `earliest_daa` enters a block from `earliest_daa + 1`, so terms with `earliest_daa` equal to
/// `expiry_daa` could only ever settle after expiry.
pub(crate) fn not_expired(t: &Terms, current_daa: u64) -> Result<(), TxError> {
    let settles_late = t.earliest_daa.is_some_and(|e| e >= t.expiry_daa);
    if current_daa >= t.expiry_daa || settles_late {
        return Err(TxError::Expired {
            current_daa,
            expiry_daa: t.expiry_daa,
        });
    }
    Ok(())
}

/// A plain UTXO at the vault's P2SH (an authorizer, the KAS cash, a vault UTXO to refund).
fn at_vault(utxo: &Utxo, vault: &Vault, input: &'static str) -> Result<(), TxError> {
    if utxo.entry.script_public_key != vault.script_public_key() || utxo.entry.covenant_id.is_some()
    {
        return Err(TxError::NotAtVault { input });
    }
    Ok(())
}

/// The vault's escrowed token: the leg's covenant, and the P2SH of the template holding `state`.
pub(crate) fn escrow_at(
    utxo: &Utxo,
    token: &Kcc20Token,
    template: &Kcc20Template,
    state: &Kcc20State,
    input: &'static str,
) -> Result<(), TxError> {
    if state.amount > i64::MAX as u64 {
        return Err(TxError::EscrowMismatch { input });
    }
    if utxo.entry.covenant_id != Some(Hash::from_bytes(token.covenant_id))
        || utxo.entry.script_public_key != template.script_public_key(state)?
    {
        return Err(TxError::EscrowMismatch { input });
    }
    Ok(())
}

/// Checks a party's own token inputs (`TX_TOKEN_INPUT`) and returns their common owner: the
/// leg's covenant, a public-key owner that is a valid x-only key, not a minter, an amount in the
/// script integer range, the scriptPubKey of the template holding the stated state, one owner.
pub(crate) fn own_tokens(
    tokens: &[TokenUtxo],
    token: &Kcc20Token,
    template: &Kcc20Template,
) -> Result<Kcc20Owner, TxError> {
    let first = tokens.first().ok_or(TxError::TokenInput {
        index: 0,
        reason: "no token input",
    })?;
    for (index, tok) in tokens.iter().enumerate() {
        let refuse = |reason| TxError::TokenInput { index, reason };
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

pub(crate) fn exact(token: &TokenUtxo, amount: u64, input: &'static str) -> Result<(), TxError> {
    if token.state.amount != amount {
        return Err(TxError::LegAmount {
            input,
            expected: amount,
            found: token.state.amount,
        });
    }
    Ok(())
}

/// The key of a KAS input: a version-0 P2PK Schnorr UTXO with no covenant (`TX_KAS_INPUT`).
pub(crate) fn kas_key(utxo: &Utxo, index: usize) -> Result<[u8; 32], TxError> {
    let refuse = |reason| TxError::KasInput { index, reason };
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

/// The length of a token's template (prefix and suffix around the state), as the terms name it
/// and as the builder's template has it (`check_token`).
pub(crate) fn template_bytes(token: &Kcc20Token) -> u64 {
    u64::from(token.template_prefix_len) + u64::from(token.template_suffix_len)
}

/// The SCRIPT_HASH owner a vault's escrowed token has.
fn script_hash_owner(vault: &Vault) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

/// A KCC-20 destination's owner. Validated terms put an owner on every KCC-20 leg's destinations.
pub(crate) fn kcc20_owner(destination: &Destination) -> Kcc20Owner {
    match destination {
        Destination::Kcc20(owner) => *owner,
        _ => unreachable!("structure checks match destinations to their leg"),
    }
}

/// A KAS destination's scriptPubKey. Validated terms put one on every KAS leg's destinations.
pub(crate) fn kas_destination(destination: &Destination) -> ScriptPublicKey {
    match destination {
        Destination::Kas(spk) => spk.clone(),
        _ => unreachable!("structure checks match destinations to their leg"),
    }
}

pub(crate) fn token_output(
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

/// A pass-through output (a token's carrier KAS, an authorizer's KAS going home) holding less
/// than its minimum KAS is topped up to the minimum; the difference comes from the fee inputs
/// (`finish` takes it out of the change). Used only where the contract checks "at least"
/// (`[D2]`, `[S9]`, `[R13]`) or no contract runs (Direct), so an under-funded authorizer or
/// carrier cannot make a settle unbuildable. Leg amounts and the KAS cash output are never
/// topped up; a refund's output 0 must equal its input (`[R5]`).
pub(crate) fn topped_up(mut output: TransactionOutput) -> TransactionOutput {
    output.value = output.value.max(min_output_value(&output));
    output
}

// =============================================================================================
// Spends: the signature script of each input, around its signature slot
// =============================================================================================

/// How an input is spent.
pub(crate) enum Spend {
    /// A signature by `signer` goes between `before` and `after`.
    Signed {
        signer: [u8; 32],
        before: Vec<u8>,
        after: Vec<u8>,
    },
    /// The whole signature script; no signature.
    Complete(Vec<u8>),
}

pub(crate) struct PlannedInput {
    pub(crate) utxo: Utxo,
    pub(crate) budget: u16,
    pub(crate) spend: Spend,
}

pub(crate) fn planned(utxo: &Utxo, budget: u16, spend: Spend) -> PlannedInput {
    PlannedInput {
        utxo: utxo.clone(),
        budget,
        spend,
    }
}

pub(crate) fn complete(script: Vec<u8>) -> Spend {
    Spend::Complete(script)
}

pub(crate) fn p2pk_spend(key: [u8; 32]) -> Spend {
    Spend::Signed {
        signer: key,
        before: vec![],
        after: vec![],
    }
}

/// Encodes the signature script with two different placeholder signatures and splits it around
/// the one 65-byte push where they differ, so the slot holds exactly the bytes around the
/// signature. Any other difference is an encoding fault (`TX_ENCODING`).
pub(crate) fn signed(
    signer: [u8; 32],
    encode: impl Fn(&[u8; 65]) -> Result<Vec<u8>, TxError>,
) -> Result<Spend, TxError> {
    let a = encode(&[0x00; 65])?;
    let b = encode(&[0xFF; 65])?;
    let fault = || TxError::Encoding {
        reason: "the signature is not one 65-byte push in the signature script".into(),
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

/// ImpulseVault `settle(sig authSig)`: signed by the authority, or 65 zero bytes when the trade
/// is self-settling (the contract does not read it).
fn vault_settle(vault: &Vault, authority: Option<[u8; 32]>) -> Result<Spend, TxError> {
    let encode =
        |sig: &[u8; 65]| vault_entry(vault, "settle", vec![ArtifactValue::Bytes(sig.to_vec())]);
    match authority {
        Some(key) => signed(key, encode),
        None => Ok(complete(encode(&[0; 65])?)),
    }
}

/// ImpulseVault `refund(sig s, pubkey signer)`.
fn vault_refund(vault: &Vault, signer: [u8; 32]) -> Result<Spend, TxError> {
    signed(signer, |sig| {
        vault_entry(
            vault,
            "refund",
            vec![
                ArtifactValue::Bytes(sig.to_vec()),
                ArtifactValue::Bytes(signer.to_vec()),
            ],
        )
    })
}

fn vault_entry(vault: &Vault, entry: &str, args: Vec<ArtifactValue>) -> Result<Vec<u8>, TxError> {
    let template = template::check()?;
    let mut script = encode_contract_entry_sig_script(template.abi(), CONTRACT_NAME, entry, &args)
        .map_err(|e| TxError::Encoding {
            reason: format!("ImpulseVault {entry}: {e}"),
        })?;
    script.extend_from_slice(&push_data(vault.redeem_script())?);
    Ok(script)
}

// =============================================================================================
// The checks every transaction shares
// =============================================================================================

pub(crate) fn checked_sum(values: impl Iterator<Item = u64>) -> Option<u64> {
    values
        .into_iter()
        .try_fold(0u64, |acc, v| acc.checked_add(v))
}

struct Plan<'t> {
    terms: &'t ValidatedTerms,
    inputs: Vec<PlannedInput>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    /// The most inputs the vault template the transaction spends allows, if it sets a bound.
    max_inputs: Option<usize>,
}

/// Appends the fee inputs and the change, then checks, in order: the fee inputs
/// (`TX_KAS_INPUT`), at most the inputs the spent vault template allows (`TX_TOO_MANY_INPUTS`),
/// no outpoint twice (`TX_DUPLICATE_INPUT`), every spent UTXO above zero and at
/// most `MAX_SOMPI`, and all of them together at most `MAX_SOMPI` (`TX_UTXO_VALUE`), a standard
/// change script (`TX_NONSTANDARD_CHANGE`), enough funds (`TX_INSUFFICIENT_FUNDS`), the change
/// minimum (`TX_BELOW_MIN_KAS`); builds the unsigned transaction and each slot's sighash; then
/// checks the masses of the signed size (`TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`). The
/// value check keeps the pinned mass calculator, which divides by every value, from a zero.
fn finish(mut plan: Plan<'_>, fee: &FeePayment) -> Result<Ipst, TxError> {
    let first_fee = plan.inputs.len();
    if fee.inputs.is_empty() {
        return Err(TxError::KasInput {
            index: first_fee,
            reason: "no fee input",
        });
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
            return Err(TxError::DuplicateInput { index });
        }
    }
    let mut available: u64 = 0;
    for (index, input) in plan.inputs.iter().enumerate() {
        let value = input.utxo.entry.amount;
        if value == 0 || value > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: Some(index),
                value,
            });
        }
        // Each value is at most MAX_SOMPI and so is the running total: no overflow.
        available += value;
        if available > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: None,
                value: available,
            });
        }
    }
    if fee.change.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION
        || ScriptClass::from_script(&fee.change) == ScriptClass::NonStandard
    {
        return Err(TxError::NonstandardChange);
    }
    let needed = checked_sum(plan.outputs.iter().map(|o| o.value).chain([fee.fee])).ok_or(
        TxError::InsufficientFunds {
            available,
            needed: u64::MAX,
        },
    )?;
    if available < needed {
        return Err(TxError::InsufficientFunds { available, needed });
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
    let slots: Vec<Slot> = plan
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

    let mut slots = slots;
    for (index, slot) in slots.iter_mut().enumerate() {
        if slot.signer.is_some() {
            slot.sighash = Some(sighash(&tx, &entries, index)?);
        }
    }
    let ipst = Ipst::from_parts(plan.terms.clone(), tx, entries, slots);
    let masses = ipst.masses();
    check_masses(&masses)?;
    let minimum = min_relay_fee(masses.fee_mass);
    if fee.fee < minimum {
        return Err(TxError::FeeTooLow {
            fee: fee.fee,
            minimum,
        });
    }
    Ok(ipst)
}

// =============================================================================================
// The terms check: the transaction the builders make from an IPST's own inputs
// =============================================================================================

/// Which builder makes an IPST, as the terms check ([`Ipst::verify_against_terms`]) finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpstKind {
    /// `fund_kas`.
    FundKas,
    /// `fund_kcc20` for this leg.
    FundKcc20(LegIndex),
    /// `settle`.
    Settle,
    /// `refund` of this leg by this signer, with the escrowed token or without it.
    Refund {
        leg: LegIndex,
        signer: RefundSigner,
        with_token: bool,
    },
    /// `direct`.
    Direct,
}

/// An IPST that passed the terms check: which builder makes it, and the fee payment it makes.
/// The check takes the fee and the change destination from the document, so they are the
/// payer's to confirm, as are a deposit's carrier and authorizer KAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermsMatch {
    pub kind: IpstKind,
    /// What the inputs hold less what the outputs pay.
    pub fee: u64,
    /// The output after the trade outputs, if the document has one.
    pub change: Option<TransactionOutput>,
}

fn mismatch(reason: &'static str) -> TxError {
    TxError::IpstTermsMismatch { reason }
}

/// Whether a slot is exactly the spend a builder plans.
pub(crate) fn same_spend(slot: &Slot, spend: &Spend) -> bool {
    match spend {
        Spend::Signed {
            signer,
            before,
            after,
        } => {
            slot.signer() == Some(*signer)
                && slot.script_before() == before.as_slice()
                && slot.script_after() == after.as_slice()
        }
        Spend::Complete(script) => {
            slot.signer().is_none() && slot.script_before() == script.as_slice()
        }
    }
}

/// The state of the token spent at input `i`, read from the redeem script its signature
/// script carries.
pub(crate) fn token_state(
    slots: &[Slot],
    i: usize,
    template: &Kcc20Template,
) -> Option<Kcc20State> {
    let script = slots.get(i)?.script_with(&[0; 65]);
    template.state_of(&last_push(&script)?)
}

/// Rebuilds, with the builders, the transaction an IPST should be: its terms, its own inputs
/// (the trade UTXOs where the builder's layout puts them, token states from the redeem scripts
/// the token inputs carry, then the fee inputs), its fee, and its change destination (the output
/// after the trade outputs). Returns the kind, the number of trade outputs and the rebuilt IPST.
/// A builder's refusal keeps its code; inputs no builder lays out this way for these terms are
/// `IPST_TERMS_MISMATCH`.
pub(crate) fn rebuild(
    ipst: &Ipst,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
    current_daa: u64,
) -> Result<(IpstKind, usize, Ipst), TxError> {
    let terms = ipst.terms();
    let t = terms.terms();
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
    let token_at = |i: usize, template: &Kcc20Template| -> Result<TokenUtxo, TxError> {
        Ok(TokenUtxo {
            utxo: input(i)?,
            state: token_state(slots, i, template).ok_or_else(unknown)?,
        })
    };
    let cash_template = || {
        cash.ok_or_else(|| TxError::TokenTemplate {
            reason: "no template given for the KCC-20 cash leg".into(),
        })
    };
    // The inputs after the trade inputs, the document's fee, and its change destination; with
    // no output there, any standard script (the builder then makes no change, or differs).
    let fee = |trade_inputs: usize, trade_outputs: usize| FeePayment {
        inputs: utxos.get(trade_inputs..).unwrap_or_default().to_vec(),
        fee: ipst.fee(),
        change: tx
            .outputs
            .get(trade_outputs)
            .map_or_else(|| p2pk(&[0; 32]), |o| o.script_public_key.clone()),
    };

    if t.settlement_mode == SettlementMode::Direct {
        let cash_leg = match t.cash_leg.kind {
            LegKind::Kas => DirectCash::Kas(input(1)?),
            LegKind::Kcc20(_) => {
                let template = cash_template()?;
                DirectCash::Kcc20 {
                    token: token_at(1, template)?,
                    template,
                }
            }
            LegKind::External => return Err(unknown()),
        };
        let legs = DirectLegs {
            asset: token_at(0, asset)?,
            asset_token: asset,
            cash: cash_leg,
        };
        let rebuilt = direct(terms, &legs, &fee(2, 2), current_daa)?;
        return Ok((IpstKind::Direct, 2, rebuilt));
    }

    let asset_vault = Vault::instantiate_existing(terms, LegIndex::Asset)?;
    let cash_vault = match t.cash_leg.kind {
        LegKind::External => None,
        _ => Some(Vault::instantiate_existing(terms, LegIndex::Cash)?),
    };
    let first = input(0)?;
    let at = |vault: &Vault| first.entry.script_public_key == vault.script_public_key();
    let vault_leg = if at(&asset_vault) {
        Some(LegIndex::Asset)
    } else {
        cash_vault
            .as_ref()
            .filter(|v| at(v))
            .map(|_| LegIndex::Cash)
    };

    if let Some(leg) = vault_leg {
        // Settle: the asset authorizer spent through the settle entry.
        if leg == LegIndex::Asset
            && same_spend(&slots[0], &vault_settle(&asset_vault, t.authority_key)?)
        {
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
            let rebuilt = settle(terms, &legs, &fee(n, n), current_daa)?;
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
