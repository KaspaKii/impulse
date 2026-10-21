// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Builder and IPST tests. Every refusal has an accepted control beside it. No private key is
//! used here (rule 1, docs/ENGINEERING-RULES.md): the parties are label-derived public keys, and every test that
//! needs a signature (the split flow, signed IPSTs, combine) runs in the engine target,
//! tests/engine/builders.rs, which also runs every builder's transaction through the real Kaspa
//! script engine.

use super::testkit::*;
use super::*;
use crate::template::{LegIndex, Vault};
use crate::terms::{
    CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner, LegKind, Network,
    SettlementMode, ValidatedTerms,
};
use kaspa_consensus_core::constants::{
    MAX_SOMPI, MAX_TX_IN_SEQUENCE_NUM, SOMPI_PER_KASPA, STORAGE_MASS_PARAMETER,
};
use kaspa_consensus_core::mass::{calc_storage_mass, UtxoCell};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutput};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpTrue;
use kaspa_txscript::pay_to_script_hash_script;

// =============================================================================================
// Helpers
// =============================================================================================

fn fundable(terms: &ValidatedTerms, leg: LegIndex) -> crate::template::FundableVault {
    let ctx = CreationContext::new(terms.terms().network, NOW - 1);
    Vault::instantiate_for_creation(terms, leg, &ctx).expect("fundable")
}

fn code<T: std::fmt::Debug>(r: Result<T, TxError>) -> &'static str {
    r.expect_err("expected a refusal").code()
}

fn settle_of(terms: &ValidatedTerms, p: &Parties) -> Result<Ipst, TxError> {
    let (a, c) = (asset_template(), cash_template());
    let f = funded(terms);
    settle(terms, &settle_legs(&f, &a, &c), &fee_payment(p), NOW)
}

/// A funded vault trade's settle with its legs edited by `edit`.
fn settle_with(
    terms: &ValidatedTerms,
    p: &Parties,
    edit: impl FnOnce(&mut Funded),
) -> Result<Ipst, TxError> {
    let (a, c) = (asset_template(), cash_template());
    let mut f = funded(terms);
    edit(&mut f);
    settle(terms, &settle_legs(&f, &a, &c), &fee_payment(p), NOW)
}

fn refund_of(
    terms: &ValidatedTerms,
    p: &Parties,
    leg: LegIndex,
    signer: RefundSigner,
    with_token: bool,
) -> Result<Ipst, TxError> {
    let f = funded(terms);
    let (a, c) = (asset_template(), cash_template());
    let (vault_utxo, escrow) = match leg {
        LegIndex::Asset => (
            f.asset_authorizer.clone(),
            Some(RefundEscrow {
                utxo: f.asset_escrow.clone(),
                amount: terms.terms().asset_leg.amount,
                is_minter: false,
                template: &a,
            }),
        ),
        LegIndex::Cash => match terms.terms().cash_leg.kind {
            LegKind::Kas => (f.cash_vault.clone().unwrap(), None),
            _ => (
                f.cash_authorizer.clone().unwrap(),
                Some(RefundEscrow {
                    utxo: f.cash_escrow.clone().unwrap(),
                    amount: terms.terms().cash_leg.amount,
                    is_minter: false,
                    template: &c,
                }),
            ),
        },
    };
    let escrow = if with_token { escrow } else { None };
    refund(
        terms,
        leg,
        signer,
        &vault_utxo,
        escrow.as_ref(),
        &fee_payment(p),
    )
}

fn deposit_for(
    terms: &ValidatedTerms,
    leg: LegIndex,
    p: &Parties,
) -> (Kcc20Template, Kcc20Deposit) {
    let t = terms.terms();
    let (template, cov, key, amount) = match leg {
        LegIndex::Asset => (asset_template(), ASSET_COV, p.seller, t.asset_leg.amount),
        LegIndex::Cash => (cash_template(), CASH_COV, p.buyer, t.cash_leg.amount),
    };
    let tokens = vec![own_token("deposit", &template, cov, &key, amount)];
    (
        template,
        Kcc20Deposit {
            tokens,
            carrier: CARRIER,
            authorizer: AUTHORIZER,
        },
    )
}

fn fund_kcc20_of(terms: &ValidatedTerms, leg: LegIndex, p: &Parties) -> Result<Ipst, TxError> {
    let (template, deposit) = deposit_for(terms, leg, p);
    fund_kcc20(
        terms,
        &fundable(terms, leg),
        &template,
        &deposit,
        &fee_payment(p),
        NOW,
    )
}

fn direct_of(terms: &ValidatedTerms, p: &Parties) -> Result<Ipst, TxError> {
    let (a, c) = (asset_template(), cash_template());
    direct(terms, &direct_legs(terms, p, &a, &c), &fee_payment(p), NOW)
}

fn signers(ipst: &Ipst) -> Vec<Option<[u8; 32]>> {
    ipst.slots().iter().map(|s| s.signer()).collect()
}

fn token_spk(template: &Kcc20Template, owner: &Destination, amount: u64) -> ScriptPublicKey {
    let Destination::Kcc20(o) = owner else {
        panic!("a KCC-20 destination")
    };
    template
        .script_public_key(&Kcc20State::new(*o, amount))
        .unwrap()
}

// =============================================================================================
// Canonical layouts
// =============================================================================================

#[test]
fn settle_layout_in_every_vault_mode() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    for mode in Mode::vaults() {
        let terms = validated(mode, &p);
        let t = terms.terms();
        let f = funded(&terms);
        let ipst = settle_of(&terms, &p).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        let tx = ipst.transaction();
        let auth = mode.authority.then_some(p.authority);
        let delivered = token_spk(&a, &t.buyer_delivery, AMOUNT_A);
        assert_eq!(tx.lock_time, EARLIEST, "{mode:?}");
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.iter().all(|i| i.sequence == 0));
        assert_eq!(tx.inputs[0].previous_outpoint, f.asset_authorizer.outpoint);
        let escrow_at = if mode.cash == Cash::External { 1 } else { 2 };
        assert_eq!(
            tx.inputs[escrow_at].previous_outpoint,
            f.asset_escrow.outpoint
        );
        assert_eq!(tx.outputs[0].script_public_key, delivered);
        assert_eq!(tx.outputs[0].value, CARRIER);
        let cov = tx.outputs[0].covenant.unwrap();
        assert_eq!(
            (cov.authorizing_input as usize, cov.covenant_id),
            (escrow_at, Hash::from_bytes(ASSET_COV))
        );
        let seller_return = TransactionOutput::new(AUTHORIZER, p2pk(&p.seller));
        let fee_change = TransactionOutput::new(FEE_INPUT - FEE, p2pk(&p.payer));
        match mode.cash {
            Cash::Kas => {
                assert_eq!(tx.inputs.len(), 4);
                assert_eq!(
                    tx.inputs[1].previous_outpoint,
                    f.cash_vault.as_ref().unwrap().outpoint
                );
                assert_eq!(
                    tx.outputs[1],
                    TransactionOutput::new(KAS_CASH, p2pk(&p.seller))
                );
                assert_eq!(tx.outputs[2], seller_return);
                assert_eq!(tx.outputs[3], fee_change);
                assert_eq!(signers(&ipst), vec![auth, auth, None, Some(p.payer)]);
            }
            Cash::Kcc20 => {
                assert_eq!(tx.inputs.len(), 5);
                assert_eq!(
                    tx.inputs[3].previous_outpoint,
                    f.cash_escrow.as_ref().unwrap().outpoint
                );
                assert_eq!(
                    tx.outputs[1].script_public_key,
                    token_spk(&c, &t.seller_proceeds, KCC20_CASH)
                );
                assert_eq!(tx.outputs[1].value, CARRIER);
                assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 3);
                assert_eq!(tx.outputs[2], seller_return);
                assert_eq!(
                    tx.outputs[3],
                    TransactionOutput::new(AUTHORIZER, p2pk(&p.buyer))
                );
                assert_eq!(tx.outputs[4], fee_change);
                assert_eq!(signers(&ipst), vec![auth, auth, None, None, Some(p.payer)]);
            }
            Cash::External => {
                assert_eq!(tx.inputs.len(), 3);
                assert_eq!(tx.outputs[1], seller_return);
                assert_eq!(tx.outputs[2], fee_change);
                assert_eq!(signers(&ipst), vec![auth, None, Some(p.payer)]);
            }
        }
        assert_eq!(ipst.fee(), FEE);
        let budget = |i: usize| tx.inputs[i].compute_commit.compute_budget().unwrap();
        assert_eq!(budget(0), VAULT_BUDGET);
        assert_eq!(budget(escrow_at), KCC20_VAULT_OWNED_BUDGET);
        assert_eq!(budget(tx.inputs.len() - 1), P2PK_BUDGET);
    }
}

#[test]
fn settle_without_earliest_has_no_lock_time() {
    let p = parties();
    let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    t.earliest_daa = None;
    let terms = t.validate_structure().unwrap();
    assert_eq!(settle_of(&terms, &p).unwrap().transaction().lock_time, 0);
}

#[test]
fn refund_layout_for_every_leg_and_signer() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    for mode in Mode::vaults() {
        let terms = validated(mode, &p);
        let t = terms.terms();
        let f = funded(&terms);
        let legs: &[LegIndex] = if mode.cash == Cash::External {
            &[LegIndex::Asset]
        } else {
            &[LegIndex::Asset, LegIndex::Cash]
        };
        for &leg in legs {
            let mut roles = vec![RefundSigner::Depositor, RefundSigner::Counterparty];
            if mode.authority {
                roles.push(RefundSigner::Authority);
            }
            for signer in roles {
                let label = format!("{mode:?} {leg:?} {signer:?}");
                let ipst = refund_of(&terms, &p, leg, signer, true)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                let tx = ipst.transaction();
                let (depositor, counterparty) = match leg {
                    LegIndex::Asset => (p.seller, p.buyer),
                    LegIndex::Cash => (p.buyer, p.seller),
                };
                let key = match signer {
                    RefundSigner::Depositor => depositor,
                    RefundSigner::Counterparty => counterparty,
                    RefundSigner::Authority => p.authority,
                };
                assert_eq!(ipst.slots()[0].signer(), Some(key), "{label}");
                let earmarked_depositor =
                    mode.funding == FundingMode::Earmarked && signer == RefundSigner::Depositor;
                assert_eq!(
                    tx.lock_time,
                    if earmarked_depositor { EXPIRY } else { 0 },
                    "{label}"
                );
                let kas_cash = leg == LegIndex::Cash && mode.cash == Cash::Kas;
                if kas_cash {
                    assert_eq!(tx.inputs.len(), 2);
                    assert_eq!(
                        tx.outputs[0],
                        TransactionOutput::new(KAS_CASH, p2pk(&p.buyer))
                    );
                } else {
                    let (vault_utxo, escrow, template, home, amount) = match leg {
                        LegIndex::Asset => (
                            &f.asset_authorizer,
                            &f.asset_escrow,
                            &a,
                            &t.seller_refund,
                            AMOUNT_A,
                        ),
                        LegIndex::Cash => (
                            f.cash_authorizer.as_ref().unwrap(),
                            f.cash_escrow.as_ref().unwrap(),
                            &c,
                            &t.buyer_refund,
                            KCC20_CASH,
                        ),
                    };
                    assert_eq!(tx.inputs[0].previous_outpoint, vault_utxo.outpoint);
                    assert_eq!(tx.inputs[1].previous_outpoint, escrow.outpoint);
                    assert_eq!(
                        tx.outputs[0],
                        TransactionOutput::new(AUTHORIZER, p2pk(&depositor))
                    );
                    assert_eq!(
                        tx.outputs[1].script_public_key,
                        token_spk(template, home, amount)
                    );
                    assert_eq!(tx.outputs[1].value, CARRIER);
                    assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 1);
                    assert_eq!(ipst.slots()[1].signer(), None);
                }
                assert_eq!(ipst.fee(), FEE);
            }
        }
    }
}

#[test]
fn depositor_may_refund_the_authorizer_alone() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    for leg in LegIndex::ALL {
        let ipst = refund_of(&terms, &p, leg, RefundSigner::Depositor, false).unwrap();
        assert_eq!(ipst.transaction().inputs.len(), 2);
        assert_eq!(ipst.transaction().outputs.len(), 2);
    }
}

#[test]
fn fund_layouts() {
    let p = parties();
    let a = asset_template();
    // KAS cash leg: exactly the cash amount at the cash vault, change last.
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let cash = fundable(&terms, LegIndex::Cash);
    let ipst = fund_kas(&terms, &cash, &fee_payment(&p), NOW).unwrap();
    let tx = ipst.transaction();
    assert_eq!(
        tx.outputs[0],
        TransactionOutput::new(KAS_CASH, cash.vault().script_public_key())
    );
    assert_eq!(
        tx.outputs[1],
        TransactionOutput::new(FEE_INPUT - KAS_CASH - FEE, p2pk(&p.payer))
    );
    assert_eq!(tx.lock_time, 0);
    assert_eq!(signers(&ipst), vec![Some(p.payer)]);

    // KCC-20 asset leg with token change: escrow, authorizer, token change, KAS change.
    let asset = fundable(&terms, LegIndex::Asset);
    let deposit = Kcc20Deposit {
        tokens: vec![
            own_token("t1", &a, ASSET_COV, &p.seller, 600),
            own_token("t2", &a, ASSET_COV, &p.seller, 700),
        ],
        carrier: CARRIER,
        authorizer: AUTHORIZER,
    };
    let ipst = fund_kcc20(&terms, &asset, &a, &deposit, &fee_payment(&p), NOW).unwrap();
    let tx = ipst.transaction();
    let escrow = escrow_state(asset.vault(), AMOUNT_A);
    assert_eq!(
        tx.outputs[0].script_public_key,
        a.script_public_key(&escrow).unwrap()
    );
    assert_eq!(tx.outputs[0].value, CARRIER);
    assert_eq!(
        tx.outputs[0].covenant,
        Some(kaspa_consensus_core::tx::CovenantBinding::new(
            0,
            Hash::from_bytes(ASSET_COV)
        ))
    );
    assert_eq!(
        tx.outputs[1],
        TransactionOutput::new(AUTHORIZER, asset.vault().script_public_key())
    );
    assert_eq!(
        tx.outputs[2].script_public_key,
        token_spk(&a, &owner(&p.seller), 1_300 - AMOUNT_A)
    );
    assert_eq!(tx.outputs[2].value, MIN_KCC20_OUTPUT);
    let kas_in = 2 * CARRIER + FEE_INPUT;
    assert_eq!(
        tx.outputs[3],
        TransactionOutput::new(
            kas_in - CARRIER - AUTHORIZER - MIN_KCC20_OUTPUT - FEE,
            p2pk(&p.payer)
        )
    );
    assert_eq!(
        signers(&ipst),
        vec![Some(p.seller), Some(p.seller), Some(p.payer)]
    );
    assert_eq!(ipst.fee(), FEE);

    // Exactly the leg amount: no token change.
    let ipst = fund_kcc20_of(&terms, LegIndex::Asset, &p).unwrap();
    assert_eq!(ipst.transaction().outputs.len(), 3);
}

#[test]
fn direct_layout() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    for cash in [Cash::Kas, Cash::Kcc20] {
        let terms = validated(Mode::direct(cash), &p);
        let t = terms.terms();
        let ipst = direct_of(&terms, &p).unwrap();
        let tx = ipst.transaction();
        assert_eq!(tx.lock_time, EARLIEST);
        assert_eq!(
            tx.outputs[0].script_public_key,
            token_spk(&a, &t.buyer_delivery, AMOUNT_A)
        );
        assert_eq!(tx.outputs[0].value, CARRIER);
        assert_eq!(tx.outputs[0].covenant.unwrap().authorizing_input, 0);
        match cash {
            Cash::Kas => assert_eq!(
                tx.outputs[1],
                TransactionOutput::new(KAS_CASH, p2pk(&p.seller))
            ),
            _ => {
                assert_eq!(
                    tx.outputs[1].script_public_key,
                    token_spk(&c, &t.seller_proceeds, KCC20_CASH)
                );
                assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 1);
            }
        }
        assert_eq!(
            signers(&ipst),
            vec![Some(p.seller), Some(p.buyer), Some(p.payer)]
        );
        assert_eq!(ipst.fee(), FEE);
    }
}

#[test]
fn no_builder_exceeds_max_outputs() {
    let p = parties();
    for mode in Mode::all() {
        let terms = validated(mode, &p);
        let mut built = vec![];
        if mode.settlement == SettlementMode::Direct {
            built.push(direct_of(&terms, &p).unwrap());
        } else {
            built.push(settle_of(&terms, &p).unwrap());
            built.push(fund_kcc20_of(&terms, LegIndex::Asset, &p).unwrap());
            built.push(
                refund_of(
                    &terms,
                    &p,
                    LegIndex::Asset,
                    RefundSigner::Counterparty,
                    true,
                )
                .unwrap(),
            );
        }
        for ipst in built {
            assert!(ipst.transaction().outputs.len() as u64 <= MAX_OUTPUTS);
            ipst.transaction()
                .outputs
                .iter()
                .for_each(|o| assert!(o.value > 0));
        }
    }
}

// =============================================================================================
// Sighash (the signed half of the split flow is in tests/engine/builders.rs)
// =============================================================================================

#[test]
fn sighash_refuses_a_missing_input() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let ipst = settle_of(&terms, &p).unwrap();
    let (tx, entries) = (ipst.transaction(), ipst.entries());
    assert!(sighash(tx, entries, 3).is_ok());
    assert_eq!(code(sighash(tx, entries, 4)), "TX_SIGNATURE_SLOT");
    assert_eq!(code(sighash(tx, &entries[1..], 0)), "TX_SIGNATURE_SLOT");
}

// =============================================================================================
// Refusals, each beside an accepted control
// =============================================================================================

#[test]
fn wrong_mode() {
    let p = parties();
    let vault_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    assert!(settle_of(&vault_terms, &p).is_ok());
    assert!(direct_of(&direct_terms, &p).is_ok());
    let (a, c) = (asset_template(), cash_template());
    let vault_legs = settle_legs(&funded(&vault_terms), &a, &c);
    assert_eq!(
        code(settle(&direct_terms, &vault_legs, &fee_payment(&p), NOW)),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        code(direct(
            &vault_terms,
            &direct_legs(&direct_terms, &p, &a, &c),
            &fee_payment(&p),
            NOW
        )),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        code(refund(
            &direct_terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &funded(&vault_terms).asset_authorizer,
            None,
            &fee_payment(&p)
        )),
        "TX_WRONG_MODE"
    );
    // A cash leg of another kind than the terms'.
    let mut legs = settle_legs(&funded(&vault_terms), &a, &c);
    legs.cash = SettleCash::External;
    assert_eq!(
        code(settle(&vault_terms, &legs, &fee_payment(&p), NOW)),
        "TX_WRONG_MODE"
    );
    let kcc20_direct = validated(Mode::direct(Cash::Kcc20), &p);
    assert_eq!(
        code(direct(
            &kcc20_direct,
            &direct_legs(&direct_terms, &p, &a, &c),
            &fee_payment(&p),
            NOW
        )),
        "TX_WRONG_MODE"
    );
    // fund_kas on a KCC-20 leg, fund_kcc20 on a KAS leg.
    assert!(fund_kas(
        &vault_terms,
        &fundable(&vault_terms, LegIndex::Cash),
        &fee_payment(&p),
        NOW
    )
    .is_ok());
    assert_eq!(
        code(fund_kas(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Asset),
            &fee_payment(&p),
            NOW
        )),
        "TX_WRONG_MODE"
    );
    let (template, deposit) = deposit_for(&vault_terms, LegIndex::Asset, &p);
    assert_eq!(
        code(fund_kcc20(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Cash),
            &template,
            &deposit,
            &fee_payment(&p),
            NOW
        )),
        "TX_WRONG_MODE"
    );
    // A token offered with a KAS cash refund.
    let f = funded(&vault_terms);
    let stray = RefundEscrow {
        utxo: f.asset_escrow.clone(),
        amount: AMOUNT_A,
        is_minter: false,
        template: &a,
    };
    assert!(refund_of(
        &vault_terms,
        &p,
        LegIndex::Cash,
        RefundSigner::Depositor,
        false
    )
    .is_ok());
    assert_eq!(
        code(refund(
            &vault_terms,
            LegIndex::Cash,
            RefundSigner::Depositor,
            f.cash_vault.as_ref().unwrap(),
            Some(&stray),
            &fee_payment(&p)
        )),
        "TX_WRONG_MODE"
    );
}

#[test]
fn external_cash_has_no_cash_vault_to_fund_or_refund() {
    // D14: no builder touches the cash-vault script of external-cash terms.
    let p = parties();
    let terms = validated(
        Mode::vault(true, Cash::External, FundingMode::Earmarked),
        &p,
    );
    assert!(refund_of(&terms, &p, LegIndex::Asset, RefundSigner::Depositor, true).is_ok());
    let any = utxo("stray", AUTHORIZER, p2pk(&p.buyer), None);
    assert_eq!(
        code(refund(
            &terms,
            LegIndex::Cash,
            RefundSigner::Depositor,
            &any,
            None,
            &fee_payment(&p)
        )),
        "TEMPLATE_NO_VAULT"
    );
}

#[test]
fn vault_mismatch() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let mut other = terms.terms().clone();
    other.nonce += 1;
    let other = other.validate_structure().unwrap();
    assert!(fund_kas(
        &terms,
        &fundable(&terms, LegIndex::Cash),
        &fee_payment(&p),
        NOW
    )
    .is_ok());
    assert_eq!(
        code(fund_kas(
            &terms,
            &fundable(&other, LegIndex::Cash),
            &fee_payment(&p),
            NOW
        )),
        "TX_VAULT_MISMATCH"
    );
    let (template, deposit) = deposit_for(&terms, LegIndex::Asset, &p);
    assert_eq!(
        code(fund_kcc20(
            &terms,
            &fundable(&other, LegIndex::Asset),
            &template,
            &deposit,
            &fee_payment(&p),
            NOW
        )),
        "TX_VAULT_MISMATCH"
    );
}

#[test]
fn expired() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let vault_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    let f = funded(&vault_terms);
    for (now, ok) in [(EXPIRY - 1, true), (EXPIRY, false), (EXPIRY + 1, false)] {
        let settled = settle(
            &vault_terms,
            &settle_legs(&f, &a, &c),
            &fee_payment(&p),
            now,
        );
        let funded_kas = fund_kas(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Cash),
            &fee_payment(&p),
            now,
        );
        let (template, deposit) = deposit_for(&vault_terms, LegIndex::Asset, &p);
        let funded_kcc20 = fund_kcc20(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Asset),
            &template,
            &deposit,
            &fee_payment(&p),
            now,
        );
        let direct_tx = direct(
            &direct_terms,
            &direct_legs(&direct_terms, &p, &a, &c),
            &fee_payment(&p),
            now,
        );
        for (label, r) in [
            ("settle", settled.map(|_| ())),
            ("fund_kas", funded_kas.map(|_| ())),
            ("fund_kcc20", funded_kcc20.map(|_| ())),
            ("direct", direct_tx.map(|_| ())),
        ] {
            if ok {
                assert_eq!(r, Ok(()), "{label} at {now}");
            } else {
                assert_eq!(code(r), "TX_EXPIRED", "{label} at {now}");
            }
        }
    }
    // A refund is never refused for expiry: it is what expiry is for.
    assert!(refund_of(
        &vault_terms,
        &p,
        LegIndex::Asset,
        RefundSigner::Depositor,
        true
    )
    .is_ok());
}

#[test]
fn expired_without_earliest() {
    // No earliest_daa: the settle's lock time is 0, so the builder's refusal is the only bound
    // and it applies at expiry_daa all the same, in every builder that checks expiry.
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let without = |terms: &ValidatedTerms| {
        let mut t = terms.terms().clone();
        t.earliest_daa = None;
        t.validate_structure().unwrap()
    };
    let vault_terms = without(&validated(
        Mode::vault(true, Cash::Kas, FundingMode::Earmarked),
        &p,
    ));
    let direct_terms = without(&validated(Mode::direct(Cash::Kas), &p));
    assert_eq!(vault_terms.terms().earliest_daa, None);
    assert_eq!(direct_terms.terms().earliest_daa, None);
    let f = funded(&vault_terms);
    for (now, ok) in [(EXPIRY - 1, true), (EXPIRY, false), (EXPIRY + 1, false)] {
        let settled = settle(
            &vault_terms,
            &settle_legs(&f, &a, &c),
            &fee_payment(&p),
            now,
        );
        let funded_kas = fund_kas(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Cash),
            &fee_payment(&p),
            now,
        );
        let (template, deposit) = deposit_for(&vault_terms, LegIndex::Asset, &p);
        let funded_kcc20 = fund_kcc20(
            &vault_terms,
            &fundable(&vault_terms, LegIndex::Asset),
            &template,
            &deposit,
            &fee_payment(&p),
            now,
        );
        let direct_tx = direct(
            &direct_terms,
            &direct_legs(&direct_terms, &p, &a, &c),
            &fee_payment(&p),
            now,
        );
        if let Ok(ipst) = &settled {
            assert_eq!(ipst.transaction().lock_time, 0, "settle at {now}");
        }
        for (label, r) in [
            ("settle", settled.map(|_| ())),
            ("fund_kas", funded_kas.map(|_| ())),
            ("fund_kcc20", funded_kcc20.map(|_| ())),
            ("direct", direct_tx.map(|_| ())),
        ] {
            if ok {
                assert_eq!(r, Ok(()), "{label} at {now}, no earliest_daa");
            } else {
                assert_eq!(code(r), "TX_EXPIRED", "{label} at {now}, no earliest_daa");
            }
        }
    }
}

#[test]
fn expired_when_earliest_equals_expiry() {
    // A settle locked at earliest_daa enters a block from earliest_daa + 1. With earliest_daa
    // equal to expiry_daa (structurally valid terms) that is always after expiry.
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    for (earliest, ok) in [(EXPIRY - 1, true), (EXPIRY, false)] {
        let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
        t.earliest_daa = Some(earliest);
        let terms = t.validate_structure().unwrap();
        let settled = settle(
            &terms,
            &settle_legs(&funded(&terms), &a, &c),
            &fee_payment(&p),
            NOW,
        );
        let funded_kas = fund_kas(
            &terms,
            &fundable(&terms, LegIndex::Cash),
            &fee_payment(&p),
            NOW,
        );
        let mut d = terms.terms().clone();
        d.settlement_mode = SettlementMode::Direct;
        d.funding_mode = FundingMode::Revocable;
        let direct_terms = d.validate_structure().unwrap();
        let direct_tx = direct_of(&direct_terms, &p);
        for (label, r) in [
            ("settle", settled.map(|_| ())),
            ("fund_kas", funded_kas.map(|_| ())),
            ("direct", direct_tx.map(|_| ())),
        ] {
            if ok {
                assert_eq!(r, Ok(()), "{label}, earliest {earliest}");
            } else {
                assert_eq!(code(r), "TX_EXPIRED", "{label}, earliest {earliest}");
            }
        }
        // Refunds are unaffected.
        assert!(refund_of(
            &terms,
            &p,
            LegIndex::Asset,
            RefundSigner::Counterparty,
            true
        )
        .is_ok());
    }
}

#[test]
fn not_at_vault() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    assert!(settle_with(&terms, &p, |_| {}).is_ok());
    let elsewhere = p2pk(&p.seller);
    for (label, edit) in [
        (
            "asset authorizer elsewhere",
            Box::new(|f: &mut Funded| {
                f.asset_authorizer.entry.script_public_key = elsewhere.clone()
            }) as Box<dyn Fn(&mut Funded)>,
        ),
        (
            "asset authorizer with a covenant",
            Box::new(|f: &mut Funded| {
                f.asset_authorizer.entry.covenant_id = Some(Hash::from_bytes(ASSET_COV))
            }),
        ),
        (
            "asset authorizer at the cash vault",
            Box::new(|f: &mut Funded| {
                f.asset_authorizer.entry.script_public_key = f
                    .cash_authorizer
                    .as_ref()
                    .unwrap()
                    .entry
                    .script_public_key
                    .clone()
            }),
        ),
        (
            "cash authorizer at the asset vault",
            Box::new(|f: &mut Funded| {
                f.cash_authorizer.as_mut().unwrap().entry.script_public_key =
                    f.asset_authorizer.entry.script_public_key.clone()
            }),
        ),
    ] {
        assert_eq!(
            code(settle_with(&terms, &p, edit)),
            "TX_NOT_AT_VAULT",
            "{label}"
        );
    }
    let kas_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    assert_eq!(
        code(settle_with(&kas_terms, &p, |f| {
            f.cash_vault.as_mut().unwrap().entry.script_public_key = p2pk(&p.buyer)
        })),
        "TX_NOT_AT_VAULT"
    );
    // A refund of a UTXO that is not at the vault.
    let f = funded(&terms);
    assert_eq!(
        code(refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.cash_authorizer.unwrap(),
            None,
            &fee_payment(&p)
        )),
        "TX_NOT_AT_VAULT"
    );
}

#[test]
fn escrow_mismatch() {
    let p = parties();
    let a = asset_template();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let asset_vault = vault(&terms, LegIndex::Asset);
    let cash_vault = vault(&terms, LegIndex::Cash);
    assert!(settle_with(&terms, &p, |_| {}).is_ok());
    let spk =
        |vault: &Vault, amount: u64| a.script_public_key(&escrow_state(vault, amount)).unwrap();
    let one_short = spk(&asset_vault, AMOUNT_A - 1);
    let one_over = spk(&asset_vault, AMOUNT_A + 1);
    let other_vault = spk(&cash_vault, AMOUNT_A);
    let minter = a
        .script_public_key(&Kcc20State {
            is_minter: true,
            ..escrow_state(&asset_vault, AMOUNT_A)
        })
        .unwrap();
    let key_owned = token_spk(&a, &owner(&p.seller), AMOUNT_A);
    for (label, script, cov) in [
        ("one unit short", one_short, Some(ASSET_COV)),
        ("one unit over", one_over, Some(ASSET_COV)),
        ("owned by the cash vault", other_vault, Some(ASSET_COV)),
        ("a minter", minter, Some(ASSET_COV)),
        ("owned by the seller's key", key_owned, Some(ASSET_COV)),
        (
            "another covenant",
            spk(&asset_vault, AMOUNT_A),
            Some(CASH_COV),
        ),
        ("no covenant", spk(&asset_vault, AMOUNT_A), None),
    ] {
        let r = settle_with(&terms, &p, |f| {
            f.asset_escrow.entry.script_public_key = script.clone();
            f.asset_escrow.entry.covenant_id = cov.map(Hash::from_bytes);
        });
        assert_eq!(code(r), "TX_ESCROW_MISMATCH", "{label}");
    }
    assert_eq!(
        code(settle_with(&terms, &p, |f| {
            f.cash_escrow.as_mut().unwrap().entry.covenant_id = Some(Hash::from_bytes(ASSET_COV))
        })),
        "TX_ESCROW_MISMATCH"
    );
    // A refund of a token held by another vault, even under the leg's covenant.
    let f = funded(&terms);
    let mut held_elsewhere = f.cash_escrow.clone().unwrap();
    held_elsewhere.entry.covenant_id = Some(Hash::from_bytes(ASSET_COV));
    assert!(refund_of(&terms, &p, LegIndex::Asset, RefundSigner::Depositor, true).is_ok());
    assert_eq!(
        code(refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.asset_authorizer,
            Some(&RefundEscrow {
                utxo: held_elsewhere,
                amount: AMOUNT_A,
                is_minter: false,
                template: &a,
            }),
            &fee_payment(&p)
        )),
        "TX_ESCROW_MISMATCH"
    );
}

#[test]
fn refund_of_a_stray_token_by_the_depositor() {
    // The depositor may refund any token held by the vault's script hash: another amount, or a
    // minter. Anyone else only exactly the leg amount (TX_LEG_AMOUNT).
    let p = parties();
    let a = asset_template();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Revocable), &p);
    let asset_vault = vault(&terms, LegIndex::Asset);
    let f = funded(&terms);
    for (amount, is_minter) in [(AMOUNT_A, false), (7, false), (AMOUNT_A, true)] {
        let state = Kcc20State {
            is_minter,
            ..escrow_state(&asset_vault, amount)
        };
        let escrow = RefundEscrow {
            utxo: utxo(
                "stray-token",
                CARRIER,
                a.script_public_key(&state).unwrap(),
                Some(ASSET_COV),
            ),
            amount,
            is_minter,
            template: &a,
        };
        let by = |signer| {
            refund(
                &terms,
                LegIndex::Asset,
                signer,
                &f.asset_authorizer,
                Some(&escrow),
                &fee_payment(&p),
            )
        };
        let ipst = by(RefundSigner::Depositor).unwrap();
        let home = Kcc20State {
            owner: Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: p.seller,
            },
            amount,
            is_minter,
        };
        assert_eq!(
            ipst.transaction().outputs[1].script_public_key,
            a.script_public_key(&home).unwrap()
        );
        for signer in [RefundSigner::Counterparty, RefundSigner::Authority] {
            if amount == AMOUNT_A {
                assert!(by(signer).is_ok());
            } else {
                assert_eq!(code(by(signer)), "TX_LEG_AMOUNT");
            }
        }
    }
}

#[test]
fn leg_amount() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let kas_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    for (delta, ok) in [(0i64, true), (-1, false), (1, false)] {
        let r = settle_with(&kas_terms, &p, |f| {
            let v = f.cash_vault.as_mut().unwrap();
            v.entry.amount = (KAS_CASH as i64 + delta) as u64;
        });
        if ok {
            assert!(r.is_ok());
        } else {
            assert_eq!(code(r), "TX_LEG_AMOUNT", "KAS cash {delta}");
        }
    }
    // Direct: the parties' inputs hold exactly the leg amounts.
    for cash in [Cash::Kas, Cash::Kcc20] {
        let terms = validated(Mode::direct(cash), &p);
        assert!(direct_of(&terms, &p).is_ok());
        let mut legs = direct_legs(&terms, &p, &a, &c);
        legs.asset = own_token("seller-asset", &a, ASSET_COV, &p.seller, AMOUNT_A + 1);
        assert_eq!(
            code(direct(&terms, &legs, &fee_payment(&p), NOW)),
            "TX_LEG_AMOUNT"
        );
        let mut legs = direct_legs(&terms, &p, &a, &c);
        legs.cash = match cash {
            Cash::Kas => DirectCash::Kas(utxo("buyer-kas", KAS_CASH - 1, p2pk(&p.buyer), None)),
            _ => DirectCash::Kcc20 {
                token: own_token("buyer-cash", &c, CASH_COV, &p.buyer, KCC20_CASH - 1),
                template: &c,
            },
        };
        assert_eq!(
            code(direct(&terms, &legs, &fee_payment(&p), NOW)),
            "TX_LEG_AMOUNT"
        );
    }
}

#[test]
fn token_template() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    assert!(settle(&terms, &settle_legs(&f, &a, &c), &fee_payment(&p), NOW).is_ok());
    // The two fixture tokens run different templates: swapped, each leg refuses.
    assert_eq!(
        code(settle(
            &terms,
            &settle_legs(&f, &c, &c),
            &fee_payment(&p),
            NOW
        )),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(
        code(settle(
            &terms,
            &settle_legs(&f, &a, &a),
            &fee_payment(&p),
            NOW
        )),
        "TX_TOKEN_TEMPLATE"
    );
    // Artifacts that are not KCC-20.
    assert_eq!(code(Kcc20Template::from_json("{}")), "TX_TOKEN_TEMPLATE");
    assert_eq!(
        code(Kcc20Template::from_json("not json")),
        "TX_TOKEN_TEMPLATE"
    );
    let vault_artifact = include_str!("../../../../contracts/compiled/impulse_vault.v1.json");
    assert_eq!(
        code(Kcc20Template::from_json(vault_artifact)),
        "TX_TOKEN_TEMPLATE"
    );
    for (label, from, to) in [
        ("renamed state field", "\"isMinter\"", "\"isBurner\""),
        ("renamed covenant", "\"transfer\"", "\"send\""),
        (
            "changed template hash",
            "\"template_hash\": [42,",
            "\"template_hash\": [43,",
        ),
        (
            "truncated template hash",
            "\"template_hash\": [42,",
            "\"template_hash\": [",
        ),
    ] {
        let edited = ASSET_ARTIFACT.replacen(from, to, 1);
        assert_ne!(edited, ASSET_ARTIFACT, "{label}");
        assert_eq!(
            code(Kcc20Template::from_json(&edited)),
            "TX_TOKEN_TEMPLATE",
            "{label}"
        );
    }
}

#[test]
fn token_template_per_builder_and_field() {
    // The template a builder is given must be the one the terms name for the leg, in all three
    // fields: terms naming another hash with the same lengths, or the same hash with a prefix or
    // suffix one byte longer, are refused by every builder that spends or makes that leg's token.
    let p = parties();
    let vault_mode = Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked);
    let direct_mode = Mode::direct(Cash::Kcc20);
    let edited = |mode: Mode, leg: LegIndex, edit: fn(&mut crate::terms::Kcc20Token)| {
        let mut t = terms(mode, &p);
        let kind = match leg {
            LegIndex::Asset => &mut t.asset_leg.kind,
            LegIndex::Cash => &mut t.cash_leg.kind,
        };
        let LegKind::Kcc20(token) = kind else {
            panic!("a KCC-20 leg")
        };
        edit(token);
        t.validate_structure().expect("still structurally valid")
    };
    let control = validated(vault_mode, &p);
    let direct_control = validated(direct_mode, &p);
    assert!(settle_of(&control, &p).is_ok());
    assert!(direct_of(&direct_control, &p).is_ok());
    for leg in LegIndex::ALL {
        assert!(fund_kcc20_of(&control, leg, &p).is_ok());
        assert!(refund_of(&control, &p, leg, RefundSigner::Counterparty, true).is_ok());
    }
    type TokenEdit = fn(&mut crate::terms::Kcc20Token);
    let edits: [(&str, TokenEdit); 3] = [
        ("another hash, same lengths", |t| t.template_hash[0] ^= 1),
        ("same hash, prefix one longer", |t| {
            t.template_prefix_len += 1
        }),
        ("same hash, suffix one longer", |t| {
            t.template_suffix_len += 1
        }),
    ];
    for (field, edit) in edits {
        for leg in LegIndex::ALL {
            let t = edited(vault_mode, leg, edit);
            let d = edited(direct_mode, leg, edit);
            for (builder, r) in [
                ("fund_kcc20", fund_kcc20_of(&t, leg, &p).map(|_| ())),
                ("settle", settle_of(&t, &p).map(|_| ())),
                (
                    "refund",
                    refund_of(&t, &p, leg, RefundSigner::Counterparty, true).map(|_| ()),
                ),
                ("direct", direct_of(&d, &p).map(|_| ())),
            ] {
                assert_eq!(
                    code(r),
                    "TX_TOKEN_TEMPLATE",
                    "{builder}, {leg:?} leg, {field}"
                );
            }
        }
    }
    // fund_kas on the cash vault of KCC-20 cash: the leg is not KAS.
    assert_eq!(
        code(fund_kas(
            &control,
            &fundable(&control, LegIndex::Cash),
            &fee_payment(&p),
            NOW
        )),
        "TX_WRONG_MODE"
    );
}

#[test]
fn token_input() {
    let p = parties();
    let a = asset_template();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let asset = fundable(&terms, LegIndex::Asset);
    let fund = |tokens: Vec<TokenUtxo>| {
        let deposit = Kcc20Deposit {
            tokens,
            carrier: CARRIER,
            authorizer: AUTHORIZER,
        };
        fund_kcc20(&terms, &asset, &a, &deposit, &fee_payment(&p), NOW)
    };
    let good = || own_token("t", &a, ASSET_COV, &p.seller, AMOUNT_A);
    assert!(fund(vec![good()]).is_ok());
    let mut wrong_cov = good();
    wrong_cov.utxo.entry.covenant_id = Some(Hash::from_bytes(CASH_COV));
    let mut script_hash_owner = good();
    script_hash_owner.state.owner.identifier_type = IdentifierType::ScriptHash;
    script_hash_owner.utxo.entry.script_public_key =
        a.script_public_key(&script_hash_owner.state).unwrap();
    let mut minter = good();
    minter.state.is_minter = true;
    minter.utxo.entry.script_public_key = a.script_public_key(&minter.state).unwrap();
    let mut lying = good();
    lying.state.amount += 1;
    let mut not_a_key = good();
    not_a_key.state.owner.identifier = [0; 32];
    not_a_key.utxo.entry.script_public_key = a.script_public_key(&not_a_key.state).unwrap();
    let short = own_token("t", &a, ASSET_COV, &p.seller, AMOUNT_A - 1);
    let other_owner = own_token("t2", &a, ASSET_COV, &p.buyer, 1);
    for (label, tokens) in [
        ("another covenant", vec![wrong_cov]),
        ("a script-hash owner", vec![script_hash_owner]),
        ("a minter", vec![minter]),
        ("a state the script does not hold", vec![lying]),
        ("an owner that is not a key", vec![not_a_key]),
        ("less than the leg amount", vec![short]),
        ("two owners", vec![good(), other_owner]),
        ("none", vec![]),
    ] {
        assert_eq!(code(fund(tokens)), "TX_TOKEN_INPUT", "{label}");
    }
}

#[test]
fn kas_input() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let control = fee_payment(&p);
    assert!(settle_of(&terms, &p).is_ok());
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let with = |inputs: Vec<Utxo>| FeePayment {
        inputs,
        ..control.clone()
    };
    let p2sh = utxo("fee", FEE_INPUT, pay_to_script_hash_script(&[OpTrue]), None);
    let with_cov = utxo("fee", FEE_INPUT, p2pk(&p.payer), Some(ASSET_COV));
    // A P2PK whose 32 bytes are not an x-only key.
    let bad_key = utxo("fee", FEE_INPUT, p2pk(&[0; 32]), None);
    for (label, fee) in [
        ("a P2SH fee input", with(vec![p2sh])),
        ("a fee input with a covenant", with(vec![with_cov])),
        ("a P2PK of an invalid key", with(vec![bad_key])),
        ("no fee input", with(vec![])),
    ] {
        assert_eq!(
            code(settle(&terms, &legs, &fee, NOW)),
            "TX_KAS_INPUT",
            "{label}"
        );
    }
    // Direct: the buyer's KAS must be P2PK.
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    let mut d = direct_legs(&direct_terms, &p, &a, &c);
    d.cash = DirectCash::Kas(utxo(
        "buyer-kas",
        KAS_CASH,
        pay_to_script_hash_script(&[OpTrue]),
        None,
    ));
    assert_eq!(
        code(direct(&direct_terms, &d, &control, NOW)),
        "TX_KAS_INPUT"
    );
    // Two fee inputs are fine.
    let two = with(vec![
        utxo("fee-1", FEE_INPUT, p2pk(&p.payer), None),
        utxo("fee-2", FEE_INPUT, p2pk(&p.buyer), None),
    ]);
    let ipst = settle(&terms, &legs, &two, NOW).unwrap();
    assert_eq!(ipst.slots()[4].signer(), Some(p.buyer));
}

#[test]
fn duplicate_input() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let mut fee = fee_payment(&p);
    assert!(settle(&terms, &legs, &fee, NOW).is_ok());
    let mut twice = fee.inputs[0].clone();
    twice.entry.amount = 1;
    fee.inputs.push(twice);
    assert_eq!(code(settle(&terms, &legs, &fee, NOW)), "TX_DUPLICATE_INPUT");
    let mut fee = fee_payment(&p);
    fee.inputs[0].outpoint = f.asset_escrow.outpoint;
    assert_eq!(code(settle(&terms, &legs, &fee, NOW)), "TX_DUPLICATE_INPUT");
}

#[test]
fn insufficient_funds_and_change() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let pay = |input: u64, fee: u64| FeePayment {
        inputs: vec![utxo("fee", input, p2pk(&p.payer), None)],
        fee,
        change: p2pk(&p.payer),
    };
    // Exactly the fee: no change output.
    let exact = settle(&terms, &legs, &pay(FEE, FEE), NOW).unwrap();
    assert_eq!(exact.transaction().outputs.len(), 3);
    assert_eq!(exact.fee(), FEE);
    assert_eq!(
        code(settle(&terms, &legs, &pay(FEE - 1, FEE), NOW)),
        "TX_INSUFFICIENT_FUNDS"
    );
    // Change below the minimum.
    assert!(settle(&terms, &legs, &pay(FEE + MIN_KAS_OUTPUT, FEE), NOW).is_ok());
    assert_eq!(
        code(settle(
            &terms,
            &legs,
            &pay(FEE + MIN_KAS_OUTPUT - 1, FEE),
            NOW
        )),
        "TX_BELOW_MIN_KAS"
    );
    assert_eq!(
        code(settle(&terms, &legs, &pay(FEE + 1, FEE), NOW)),
        "TX_BELOW_MIN_KAS"
    );
    // A KAS cash deposit the funding inputs cannot cover.
    let cash = fundable(&terms, LegIndex::Cash);
    assert_eq!(
        code(fund_kas(&terms, &cash, &pay(KAS_CASH, FEE), NOW)),
        "TX_INSUFFICIENT_FUNDS"
    );
    assert!(fund_kas(&terms, &cash, &pay(KAS_CASH + FEE, FEE), NOW).is_ok());
}

#[test]
fn nonstandard_change() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    for change in [p2pk(&p.payer), pay_to_script_hash_script(&[OpTrue])] {
        let fee = FeePayment {
            change,
            ..fee_payment(&p)
        };
        assert!(settle(&terms, &legs, &fee, NOW).is_ok());
    }
    for change in [
        ScriptPublicKey::from_vec(0, vec![OpTrue]),
        ScriptPublicKey::from_vec(1, p2pk(&p.payer).script().to_vec()),
    ] {
        let fee = FeePayment {
            change,
            ..fee_payment(&p)
        };
        assert_eq!(
            code(settle(&terms, &legs, &fee, NOW)),
            "TX_NONSTANDARD_CHANGE"
        );
    }
}

#[test]
fn refund_signer() {
    let p = parties();
    let with_authority = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let self_settling = validated(Mode::vault(false, Cash::Kcc20, FundingMode::Earmarked), &p);
    assert!(refund_of(
        &with_authority,
        &p,
        LegIndex::Asset,
        RefundSigner::Authority,
        true
    )
    .is_ok());
    assert_eq!(
        code(refund_of(
            &self_settling,
            &p,
            LegIndex::Asset,
            RefundSigner::Authority,
            true
        )),
        "TX_REFUND_SIGNER"
    );
    for leg in LegIndex::ALL {
        assert!(refund_of(&with_authority, &p, leg, RefundSigner::Depositor, false).is_ok());
        for signer in [RefundSigner::Counterparty, RefundSigner::Authority] {
            assert_eq!(
                code(refund_of(&with_authority, &p, leg, signer, false)),
                "TX_REFUND_SIGNER",
                "{leg:?} {signer:?} without the token"
            );
        }
    }
}

#[test]
fn encoding() {
    // A token amount past the script integer range cannot be encoded as KCC-20 state.
    let a = asset_template();
    let key = parties().seller;
    let state = |amount| {
        Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: key,
            },
            amount,
        )
    };
    assert!(a.redeem_script(&state(i64::MAX as u64)).is_ok());
    assert_eq!(
        code(a.redeem_script(&state(i64::MAX as u64 + 1))),
        "TX_ENCODING"
    );
}

#[test]
fn utxo_value() {
    // A UTXO of zero sompi, of more than MAX_SOMPI, or UTXOs adding up past MAX_SOMPI: refused
    // before any mass is computed (the pinned mass calculator divides by every value).
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    assert!(settle_with(&terms, &p, |_| {}).is_ok());
    for (label, edit) in [
        (
            "asset authorizer",
            Box::new(|f: &mut Funded| f.asset_authorizer.entry.amount = 0)
                as Box<dyn Fn(&mut Funded)>,
        ),
        (
            "asset escrow",
            Box::new(|f: &mut Funded| f.asset_escrow.entry.amount = 0),
        ),
        (
            "cash authorizer",
            Box::new(|f: &mut Funded| f.cash_authorizer.as_mut().unwrap().entry.amount = 0),
        ),
        (
            "cash escrow",
            Box::new(|f: &mut Funded| f.cash_escrow.as_mut().unwrap().entry.amount = 0),
        ),
    ] {
        assert_eq!(
            settle_with(&terms, &p, edit).unwrap_err(),
            TxError::UtxoValue {
                input: Some(match label {
                    "asset authorizer" => 0,
                    "cash authorizer" => 1,
                    "asset escrow" => 2,
                    _ => 3,
                }),
                value: 0
            },
            "{label}"
        );
    }
    // A refund of a vault UTXO of zero sompi.
    let f = funded(&terms);
    let mut empty = f.asset_authorizer.clone();
    assert!(refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Depositor,
        &empty,
        None,
        &fee_payment(&p)
    )
    .is_ok());
    empty.entry.amount = 0;
    assert_eq!(
        code(refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &empty,
            None,
            &fee_payment(&p)
        )),
        "TX_UTXO_VALUE"
    );
    // Direct: a seller token carrying no KAS, a buyer token carrying no KAS.
    let (a, c) = (asset_template(), cash_template());
    let direct_terms = validated(Mode::direct(Cash::Kcc20), &p);
    assert!(direct_of(&direct_terms, &p).is_ok());
    let mut legs = direct_legs(&direct_terms, &p, &a, &c);
    legs.asset.utxo.entry.amount = 0;
    assert_eq!(
        code(direct(&direct_terms, &legs, &fee_payment(&p), NOW)),
        "TX_UTXO_VALUE"
    );
    let mut legs = direct_legs(&direct_terms, &p, &a, &c);
    if let DirectCash::Kcc20 { token, .. } = &mut legs.cash {
        token.utxo.entry.amount = 0;
    }
    assert_eq!(
        code(direct(&direct_terms, &legs, &fee_payment(&p), NOW)),
        "TX_UTXO_VALUE"
    );
    // fund_kcc20: a deposited token carrying no KAS.
    let (template, mut deposit) = deposit_for(&terms, LegIndex::Asset, &p);
    let vault = fundable(&terms, LegIndex::Asset);
    assert!(fund_kcc20(&terms, &vault, &template, &deposit, &fee_payment(&p), NOW).is_ok());
    deposit.tokens[0].utxo.entry.amount = 0;
    assert_eq!(
        code(fund_kcc20(
            &terms,
            &vault,
            &template,
            &deposit,
            &fee_payment(&p),
            NOW
        )),
        "TX_UTXO_VALUE"
    );
    // Fee inputs: zero, above MAX_SOMPI, and together past MAX_SOMPI; exactly MAX_SOMPI in all
    // is accepted.
    let kas_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let cash = fundable(&kas_terms, LegIndex::Cash);
    let pay = |values: &[u64]| FeePayment {
        inputs: values
            .iter()
            .enumerate()
            .map(|(i, v)| utxo(&format!("fee-{i}"), *v, p2pk(&p.payer), None))
            .collect(),
        ..fee_payment(&p)
    };
    let funded_with = |values: &[u64]| fund_kas(&kas_terms, &cash, &pay(values), NOW);
    let ipst = funded_with(&[MAX_SOMPI - 1, 1]).unwrap();
    assert_eq!(
        ipst.entries().iter().map(|e| e.amount).sum::<u64>(),
        MAX_SOMPI
    );
    for (label, values, input) in [
        ("zero", vec![FEE_INPUT, 0], Some(1)),
        ("above MAX_SOMPI", vec![MAX_SOMPI + 1], Some(0)),
        ("u64::MAX", vec![u64::MAX], Some(0)),
        ("together past MAX_SOMPI", vec![MAX_SOMPI, 1], None),
    ] {
        match funded_with(&values) {
            Err(TxError::UtxoValue { input: i, .. }) => assert_eq!(i, input, "{label}"),
            other => panic!("{label}: expected TX_UTXO_VALUE, got {other:?}"),
        }
    }
}

// =============================================================================================
// Refusal order (spec/TRANSACTIONS.md, "Refusal order"): for each pair of adjacent checks, an
// input failing only the later one gets its code, and an input failing both gets the earlier
// =============================================================================================

fn order(
    label: &str,
    both: Result<Ipst, TxError>,
    earlier: &str,
    later_alone: Result<Ipst, TxError>,
    later: &str,
) {
    assert_eq!(code(later_alone), later, "{label}: the later check alone");
    assert_eq!(
        code(both),
        earlier,
        "{label}: both fail, the earlier check is reported"
    );
}

/// A settle with every knob the order tests turn.
#[derive(Clone)]
struct SettleCase {
    terms: ValidatedTerms,
    funded: Funded,
    asset: Kcc20Template,
    cash: Kcc20Template,
    external_legs: bool,
    fee: FeePayment,
    now: u64,
}

impl SettleCase {
    fn new(mode: Mode, p: &Parties) -> Self {
        let terms = validated(mode, p);
        Self {
            funded: funded(&terms),
            terms,
            asset: asset_template(),
            cash: cash_template(),
            external_legs: false,
            fee: fee_payment(p),
            now: NOW,
        }
    }

    fn run(&self) -> Result<Ipst, TxError> {
        let mut legs = settle_legs(&self.funded, &self.asset, &self.cash);
        if self.external_legs {
            legs.cash = SettleCash::External;
        }
        settle(&self.terms, &legs, &self.fee, self.now)
    }

    fn with(&self, edit: impl FnOnce(&mut Self)) -> Result<Ipst, TxError> {
        let mut case = self.clone();
        edit(&mut case);
        case.run()
    }
}

/// A fault edit of a settle case.
type Fault = fn(&mut SettleCase);

/// Fault edits of a settle case, by the check each one fails.
fn past_expiry(c: &mut SettleCase) {
    c.now = EXPIRY;
}
fn asset_authorizer_elsewhere(c: &mut SettleCase) {
    c.funded.asset_authorizer.entry.script_public_key = p2pk(&parties().seller);
}
fn asset_template_swapped(c: &mut SettleCase) {
    c.asset = cash_template();
}
fn asset_escrow_wrong(c: &mut SettleCase) {
    c.funded.asset_escrow.entry.covenant_id = Some(Hash::from_bytes(CASH_COV));
}
fn cash_authorizer_elsewhere(c: &mut SettleCase) {
    c.funded
        .cash_authorizer
        .as_mut()
        .unwrap()
        .entry
        .script_public_key = p2pk(&parties().buyer);
}
fn cash_template_swapped(c: &mut SettleCase) {
    c.cash = asset_template();
}
fn cash_escrow_wrong(c: &mut SettleCase) {
    c.funded.cash_escrow.as_mut().unwrap().entry.covenant_id = Some(Hash::from_bytes(ASSET_COV));
}
fn kas_cash_elsewhere(c: &mut SettleCase) {
    c.funded
        .cash_vault
        .as_mut()
        .unwrap()
        .entry
        .script_public_key = p2pk(&parties().buyer);
}
fn kas_cash_short(c: &mut SettleCase) {
    c.funded.cash_vault.as_mut().unwrap().entry.amount -= 1;
}
fn no_fee_input(c: &mut SettleCase) {
    c.fee.inputs.clear();
}

#[test]
fn refusal_order_settle() {
    let p = parties();
    let kcc20 = SettleCase::new(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let kas = SettleCase::new(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    assert!(kcc20.run().is_ok() && kas.run().is_ok());
    // Vault terms before the cash kind, the cash kind before expiry.
    let direct_terms = validated(Mode::direct(Cash::Kcc20), &p);
    order(
        "Vault terms, cash kind",
        kcc20.with(|c| {
            c.terms = direct_terms.clone();
            c.external_legs = true;
        }),
        "TX_WRONG_MODE",
        kcc20.with(|c| c.external_legs = true),
        "TX_WRONG_MODE",
    );
    order(
        "cash kind, expiry",
        kcc20.with(|c| {
            c.external_legs = true;
            past_expiry(c)
        }),
        "TX_WRONG_MODE",
        kcc20.with(past_expiry),
        "TX_EXPIRED",
    );
    let chain: [(&str, Fault, &str); 8] = [
        ("expiry", past_expiry, "TX_EXPIRED"),
        (
            "asset authorizer",
            asset_authorizer_elsewhere,
            "TX_NOT_AT_VAULT",
        ),
        (
            "asset template",
            asset_template_swapped,
            "TX_TOKEN_TEMPLATE",
        ),
        ("asset escrow", asset_escrow_wrong, "TX_ESCROW_MISMATCH"),
        (
            "cash authorizer",
            cash_authorizer_elsewhere,
            "TX_NOT_AT_VAULT",
        ),
        ("cash template", cash_template_swapped, "TX_TOKEN_TEMPLATE"),
        ("cash escrow", cash_escrow_wrong, "TX_ESCROW_MISMATCH"),
        ("fee inputs", no_fee_input, "TX_KAS_INPUT"),
    ];
    for pair in chain.windows(2) {
        let ((a, fa, ca), (b, fb, cb)) = (pair[0], pair[1]);
        order(
            &format!("KCC-20 cash: {a}, {b}"),
            kcc20.with(|c| {
                fa(c);
                fb(c)
            }),
            ca,
            kcc20.with(fb),
            cb,
        );
    }
    let chain: [(&str, Fault, &str); 4] = [
        ("asset escrow", asset_escrow_wrong, "TX_ESCROW_MISMATCH"),
        (
            "KAS cash at the vault",
            kas_cash_elsewhere,
            "TX_NOT_AT_VAULT",
        ),
        ("KAS cash amount", kas_cash_short, "TX_LEG_AMOUNT"),
        ("fee inputs", no_fee_input, "TX_KAS_INPUT"),
    ];
    for pair in chain.windows(2) {
        let ((a, fa, ca), (b, fb, cb)) = (pair[0], pair[1]);
        order(
            &format!("KAS cash: {a}, {b}"),
            kas.with(|c| {
                fa(c);
                fb(c)
            }),
            ca,
            kas.with(fb),
            cb,
        );
    }
}

#[test]
fn refusal_order_shared_checks() {
    // The checks every transaction shares, through a KAS cash settle.
    let p = parties();
    let case = SettleCase::new(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    assert!(case.run().is_ok());
    let fee_input_p2sh: Fault =
        |c| c.fee.inputs[0].entry.script_public_key = pay_to_script_hash_script(&[OpTrue]);
    let duplicate: Fault = |c| c.fee.inputs[0].outpoint = c.funded.asset_escrow.outpoint;
    let zero_value: Fault = |c| c.fee.inputs[0].entry.amount = 0;
    let nonstandard_change: Fault = |c| c.fee.change = ScriptPublicKey::from_vec(0, vec![OpTrue]);
    let short: Fault = |c| c.fee.inputs[0].entry.amount = FEE - 1;
    let chain: [(&str, Fault, &str); 5] = [
        ("fee input kind", fee_input_p2sh, "TX_KAS_INPUT"),
        ("duplicate outpoint", duplicate, "TX_DUPLICATE_INPUT"),
        ("UTXO value", zero_value, "TX_UTXO_VALUE"),
        ("change script", nonstandard_change, "TX_NONSTANDARD_CHANGE"),
        ("funds", short, "TX_INSUFFICIENT_FUNDS"),
    ];
    for pair in chain.windows(2) {
        let ((a, fa, ca), (b, fb, cb)) = (pair[0], pair[1]);
        order(
            &format!("{a}, {b}"),
            case.with(|c| {
                fa(c);
                fb(c)
            }),
            ca,
            case.with(fb),
            cb,
        );
    }
    // Funds before the change minimum cannot both fail (no change without funds). The change
    // minimum before the masses, the masses before the relay fee: a KAS cash leg below the
    // minimum puts the storage mass over the cap.
    let mut thin = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    thin.cash_leg.amount = 1_000;
    let thin_terms = thin.validate_structure().unwrap();
    let over_cap = SettleCase {
        funded: funded(&thin_terms),
        terms: thin_terms,
        ..case.clone()
    };
    let dust_change = |c: &mut SettleCase| c.fee.inputs[0].entry.amount = FEE + 1;
    order(
        "funds, masses",
        over_cap.with(short),
        "TX_INSUFFICIENT_FUNDS",
        over_cap.run(),
        "TX_MASS",
    );
    order(
        "change minimum, masses",
        over_cap.with(dust_change),
        "TX_BELOW_MIN_KAS",
        over_cap.run(),
        "TX_MASS",
    );
    order(
        "masses, relay fee",
        over_cap.with(|c| c.fee.fee = 1),
        "TX_MASS",
        case.with(|c| c.fee.fee = 1),
        "TX_FEE_TOO_LOW",
    );
}

#[test]
fn refusal_order_fund() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let mut other = terms.terms().clone();
    other.nonce += 1;
    let other = other.validate_structure().unwrap();
    let (a, c) = (asset_template(), cash_template());
    // fund_kas: the vault, the leg, expiry, the deposit's minimum.
    let kas = |terms: &ValidatedTerms, vault_terms: &ValidatedTerms, leg, fee: &FeePayment, now| {
        fund_kas(terms, &fundable(vault_terms, leg), fee, now)
    };
    let pay = fee_payment(&p);
    let none = FeePayment {
        inputs: vec![],
        ..pay.clone()
    };
    let mut below = terms.terms().clone();
    below.cash_leg.amount = MIN_KAS_OUTPUT - 1;
    let below = below.validate_structure().unwrap();
    assert!(kas(&terms, &terms, LegIndex::Cash, &pay, NOW).is_ok());
    order(
        "fund_kas: vault, leg",
        kas(&terms, &other, LegIndex::Asset, &pay, NOW),
        "TX_VAULT_MISMATCH",
        kas(&terms, &terms, LegIndex::Asset, &pay, NOW),
        "TX_WRONG_MODE",
    );
    order(
        "fund_kas: leg, expiry",
        kas(&terms, &terms, LegIndex::Asset, &pay, EXPIRY),
        "TX_WRONG_MODE",
        kas(&terms, &terms, LegIndex::Cash, &pay, EXPIRY),
        "TX_EXPIRED",
    );
    order(
        "fund_kas: expiry, deposit minimum",
        kas(&below, &below, LegIndex::Cash, &pay, EXPIRY),
        "TX_EXPIRED",
        kas(&below, &below, LegIndex::Cash, &pay, NOW),
        "TX_BELOW_MIN_KAS",
    );
    order(
        "fund_kas: deposit minimum, fee inputs",
        kas(&below, &below, LegIndex::Cash, &none, NOW),
        "TX_BELOW_MIN_KAS",
        kas(&terms, &terms, LegIndex::Cash, &none, NOW),
        "TX_KAS_INPUT",
    );
    // fund_kcc20: the vault, the leg, expiry, the template, each token input in order, their
    // total, the carrier's minimum, the authorizer's minimum.
    let token = |label: &str, amount: u64| own_token(label, &a, ASSET_COV, &p.seller, amount);
    let minter = {
        let mut t = token("m", AMOUNT_A);
        t.state.is_minter = true;
        t.utxo.entry.script_public_key = a.script_public_key(&t.state).unwrap();
        t
    };
    let wrong_cov = {
        let mut t = token("w", AMOUNT_A);
        t.utxo.entry.covenant_id = Some(Hash::from_bytes(CASH_COV));
        t
    };
    let deposit = |tokens: Vec<TokenUtxo>, carrier: u64, authorizer: u64| Kcc20Deposit {
        tokens,
        carrier,
        authorizer,
    };
    let good = || deposit(vec![token("t", AMOUNT_A)], CARRIER, AUTHORIZER);
    let k = |vault_terms: &ValidatedTerms,
             leg,
             tpl: &Kcc20Template,
             d: &Kcc20Deposit,
             fee: &FeePayment,
             now| { fund_kcc20(&terms, &fundable(vault_terms, leg), tpl, d, fee, now) };
    assert!(k(&terms, LegIndex::Asset, &a, &good(), &pay, NOW).is_ok());
    order(
        "fund_kcc20: vault, leg",
        k(&other, LegIndex::Cash, &a, &good(), &pay, NOW),
        "TX_VAULT_MISMATCH",
        k(&terms, LegIndex::Cash, &a, &good(), &pay, NOW),
        "TX_WRONG_MODE",
    );
    order(
        "fund_kcc20: leg, expiry",
        k(&terms, LegIndex::Cash, &a, &good(), &pay, EXPIRY),
        "TX_WRONG_MODE",
        k(&terms, LegIndex::Asset, &a, &good(), &pay, EXPIRY),
        "TX_EXPIRED",
    );
    order(
        "fund_kcc20: expiry, template",
        k(&terms, LegIndex::Asset, &c, &good(), &pay, EXPIRY),
        "TX_EXPIRED",
        k(&terms, LegIndex::Asset, &c, &good(), &pay, NOW),
        "TX_TOKEN_TEMPLATE",
    );
    let bad_input = deposit(vec![wrong_cov.clone()], CARRIER, AUTHORIZER);
    order(
        "fund_kcc20: template, token inputs",
        k(&terms, LegIndex::Asset, &c, &bad_input, &pay, NOW),
        "TX_TOKEN_TEMPLATE",
        k(&terms, LegIndex::Asset, &a, &bad_input, &pay, NOW),
        "TX_TOKEN_INPUT",
    );
    // Each input in order: the first failing input is the one reported, and an input's own
    // check comes before the total.
    let index = |r: Result<Ipst, TxError>| match r {
        Err(TxError::TokenInput { index, reason }) => (index, reason),
        other => panic!("expected TX_TOKEN_INPUT, got {other:?}"),
    };
    let two_bad = deposit(vec![wrong_cov, minter.clone()], CARRIER, AUTHORIZER);
    assert_eq!(
        index(k(&terms, LegIndex::Asset, &a, &two_bad, &pay, NOW)).0,
        0
    );
    let short_then_minter = deposit(vec![token("s", 1), minter], CARRIER, AUTHORIZER);
    assert_eq!(
        index(k(
            &terms,
            LegIndex::Asset,
            &a,
            &short_then_minter,
            &pay,
            NOW
        )),
        (1, "a minter")
    );
    let short = deposit(vec![token("s", AMOUNT_A - 1)], CARRIER - 1, AUTHORIZER);
    order(
        "fund_kcc20: total, carrier minimum",
        k(&terms, LegIndex::Asset, &a, &short, &pay, NOW),
        "TX_TOKEN_INPUT",
        k(
            &terms,
            LegIndex::Asset,
            &a,
            &deposit(vec![token("t", AMOUNT_A)], CARRIER - 1, AUTHORIZER),
            &pay,
            NOW,
        ),
        "TX_BELOW_MIN_KAS",
    );
    let output_of = |r: Result<Ipst, TxError>| match r {
        Err(TxError::BelowMinKas { output, .. }) => output,
        other => panic!("expected TX_BELOW_MIN_KAS, got {other:?}"),
    };
    let both_thin = deposit(vec![token("t", AMOUNT_A)], CARRIER - 1, AUTHORIZER - 1);
    let authorizer_thin = deposit(vec![token("t", AMOUNT_A)], CARRIER, AUTHORIZER - 1);
    assert_eq!(
        output_of(k(&terms, LegIndex::Asset, &a, &both_thin, &pay, NOW)),
        0
    );
    assert_eq!(
        output_of(k(&terms, LegIndex::Asset, &a, &authorizer_thin, &pay, NOW)),
        1
    );
    order(
        "fund_kcc20: authorizer minimum, fee inputs",
        k(&terms, LegIndex::Asset, &a, &authorizer_thin, &none, NOW),
        "TX_BELOW_MIN_KAS",
        k(&terms, LegIndex::Asset, &a, &good(), &none, NOW),
        "TX_KAS_INPUT",
    );
}

#[test]
fn refusal_order_refund() {
    let p = parties();
    let a = asset_template();
    let c = cash_template();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let self_settling = validated(Mode::vault(false, Cash::Kcc20, FundingMode::Earmarked), &p);
    let kas_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let external = validated(
        Mode::vault(true, Cash::External, FundingMode::Earmarked),
        &p,
    );
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    let f = funded(&terms);
    let elsewhere = utxo("elsewhere", AUTHORIZER, p2pk(&p.buyer), None);
    let pay = fee_payment(&p);
    let none = FeePayment {
        inputs: vec![],
        ..pay.clone()
    };
    let escrow = |utxo: Utxo, amount: u64, template| RefundEscrow {
        utxo,
        amount,
        is_minter: false,
        template,
    };
    let good = escrow(f.asset_escrow.clone(), AMOUNT_A, &a);
    let r = |terms: &ValidatedTerms,
             leg,
             signer,
             vault_utxo: &Utxo,
             e: Option<&RefundEscrow>,
             fee: &FeePayment| { refund(terms, leg, signer, vault_utxo, e, fee) };
    use RefundSigner::{Authority, Counterparty, Depositor};
    let asset = LegIndex::Asset;
    assert!(r(
        &terms,
        asset,
        Counterparty,
        &f.asset_authorizer,
        Some(&good),
        &pay
    )
    .is_ok());
    order(
        "Vault terms, the leg has a vault",
        r(
            &direct_terms,
            LegIndex::Cash,
            Depositor,
            &elsewhere,
            None,
            &pay,
        ),
        "TX_WRONG_MODE",
        r(&external, LegIndex::Cash, Depositor, &elsewhere, None, &pay),
        "TEMPLATE_NO_VAULT",
    );
    order(
        "the leg has a vault, the vault UTXO",
        r(&external, LegIndex::Cash, Authority, &elsewhere, None, &pay),
        "TEMPLATE_NO_VAULT",
        r(&external, asset, Authority, &elsewhere, None, &pay),
        "TX_NOT_AT_VAULT",
    );
    order(
        "the authority role, the vault UTXO",
        r(&self_settling, asset, Authority, &elsewhere, None, &pay),
        "TX_REFUND_SIGNER",
        r(&self_settling, asset, Depositor, &elsewhere, None, &pay),
        "TX_NOT_AT_VAULT",
    );
    let kas_f = funded(&kas_terms);
    order(
        "the vault UTXO, no token for KAS cash",
        r(
            &kas_terms,
            LegIndex::Cash,
            Depositor,
            &elsewhere,
            Some(&good),
            &pay,
        ),
        "TX_NOT_AT_VAULT",
        r(
            &kas_terms,
            LegIndex::Cash,
            Depositor,
            kas_f.cash_vault.as_ref().unwrap(),
            Some(&good),
            &pay,
        ),
        "TX_WRONG_MODE",
    );
    order(
        "the vault UTXO, the token present",
        r(&terms, asset, Counterparty, &elsewhere, None, &pay),
        "TX_NOT_AT_VAULT",
        r(&terms, asset, Counterparty, &f.asset_authorizer, None, &pay),
        "TX_REFUND_SIGNER",
    );
    let mut wrong_cov = good.clone();
    wrong_cov.utxo.entry.covenant_id = Some(Hash::from_bytes(CASH_COV));
    let wrong_tpl = RefundEscrow {
        template: &c,
        ..wrong_cov.clone()
    };
    order(
        "the template, the escrow",
        r(
            &terms,
            asset,
            Depositor,
            &f.asset_authorizer,
            Some(&wrong_tpl),
            &pay,
        ),
        "TX_TOKEN_TEMPLATE",
        r(
            &terms,
            asset,
            Depositor,
            &f.asset_authorizer,
            Some(&wrong_cov),
            &pay,
        ),
        "TX_ESCROW_MISMATCH",
    );
    // The stated amount 7 is not what the escrow's script holds (the leg amount): the escrow
    // check fails before the amount check would.
    let misstated = escrow(f.asset_escrow.clone(), 7, &a);
    let asset_vault = vault(&terms, LegIndex::Asset);
    let seven = escrow(
        utxo(
            "seven",
            CARRIER,
            a.script_public_key(&escrow_state(&asset_vault, 7)).unwrap(),
            Some(ASSET_COV),
        ),
        7,
        &a,
    );
    order(
        "the escrow, the leg amount",
        r(
            &terms,
            asset,
            Counterparty,
            &f.asset_authorizer,
            Some(&misstated),
            &pay,
        ),
        "TX_ESCROW_MISMATCH",
        r(
            &terms,
            asset,
            Counterparty,
            &f.asset_authorizer,
            Some(&seven),
            &pay,
        ),
        "TX_LEG_AMOUNT",
    );
    order(
        "the leg amount, fee inputs",
        r(
            &terms,
            asset,
            Counterparty,
            &f.asset_authorizer,
            Some(&seven),
            &none,
        ),
        "TX_LEG_AMOUNT",
        r(
            &terms,
            asset,
            Depositor,
            &f.asset_authorizer,
            Some(&seven),
            &none,
        ),
        "TX_KAS_INPUT",
    );
}

#[test]
fn refusal_order_direct() {
    let p = parties();
    // 'static templates, so the edits below can put them in the legs.
    let a: &'static Kcc20Template = Box::leak(Box::new(asset_template()));
    let c: &'static Kcc20Template = Box::leak(Box::new(cash_template()));
    let kas = validated(Mode::direct(Cash::Kas), &p);
    let kcc20 = validated(Mode::direct(Cash::Kcc20), &p);
    let vault_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let pay = fee_payment(&p);
    let none = FeePayment {
        inputs: vec![],
        ..pay.clone()
    };
    let run = |terms: &ValidatedTerms, edit: &dyn Fn(&mut DirectLegs), fee: &FeePayment, now| {
        let mut legs = direct_legs(terms, &p, a, c);
        edit(&mut legs);
        direct(terms, &legs, fee, now)
    };
    assert!(run(&kas, &|_| {}, &pay, NOW).is_ok() && run(&kcc20, &|_| {}, &pay, NOW).is_ok());
    let kcc20_cash = |l: &mut DirectLegs| {
        l.cash = DirectCash::Kcc20 {
            token: own_token("buyer-cash", c, CASH_COV, &p.buyer, KCC20_CASH),
            template: c,
        }
    };
    let swapped_asset_template = |l: &mut DirectLegs| l.asset_token = c;
    let seller_minter = |l: &mut DirectLegs| {
        l.asset.state.is_minter = true;
        l.asset.utxo.entry.script_public_key = a.script_public_key(&l.asset.state).unwrap();
    };
    let seller_short = |l: &mut DirectLegs| {
        l.asset = own_token("seller-asset", a, ASSET_COV, &p.seller, AMOUNT_A - 1)
    };
    let buyer_p2sh = |l: &mut DirectLegs| {
        if let DirectCash::Kas(u) = &mut l.cash {
            u.entry.script_public_key = pay_to_script_hash_script(&[OpTrue]);
        }
    };
    let buyer_short_kas = |l: &mut DirectLegs| {
        if let DirectCash::Kas(u) = &mut l.cash {
            u.entry.amount -= 1;
        }
    };
    order(
        "Direct terms, cash kind",
        run(&vault_terms, &kcc20_cash, &pay, NOW),
        "TX_WRONG_MODE",
        run(&kas, &kcc20_cash, &pay, NOW),
        "TX_WRONG_MODE",
    );
    order(
        "cash kind, expiry",
        run(&kas, &kcc20_cash, &pay, EXPIRY),
        "TX_WRONG_MODE",
        run(&kas, &|_| {}, &pay, EXPIRY),
        "TX_EXPIRED",
    );
    order(
        "expiry, asset template",
        run(&kas, &swapped_asset_template, &pay, EXPIRY),
        "TX_EXPIRED",
        run(&kas, &swapped_asset_template, &pay, NOW),
        "TX_TOKEN_TEMPLATE",
    );
    order(
        "asset template, seller's token",
        run(
            &kas,
            &|l| {
                swapped_asset_template(l);
                seller_minter(l)
            },
            &pay,
            NOW,
        ),
        "TX_TOKEN_TEMPLATE",
        run(&kas, &seller_minter, &pay, NOW),
        "TX_TOKEN_INPUT",
    );
    order(
        "seller's token, its amount",
        run(
            &kas,
            &|l| {
                seller_short(l);
                seller_minter(l)
            },
            &pay,
            NOW,
        ),
        "TX_TOKEN_INPUT",
        run(&kas, &seller_short, &pay, NOW),
        "TX_LEG_AMOUNT",
    );
    order(
        "seller's amount, buyer's KAS input",
        run(
            &kas,
            &|l| {
                seller_short(l);
                buyer_p2sh(l)
            },
            &pay,
            NOW,
        ),
        "TX_LEG_AMOUNT",
        run(&kas, &buyer_p2sh, &pay, NOW),
        "TX_KAS_INPUT",
    );
    order(
        "buyer's KAS input, its amount",
        run(
            &kas,
            &|l| {
                buyer_p2sh(l);
                buyer_short_kas(l)
            },
            &pay,
            NOW,
        ),
        "TX_KAS_INPUT",
        run(&kas, &buyer_short_kas, &pay, NOW),
        "TX_LEG_AMOUNT",
    );
    let mut thin = kas.terms().clone();
    thin.cash_leg.amount = MIN_KAS_OUTPUT - 1;
    let thin = thin.validate_structure().unwrap();
    order(
        "buyer's amount, the payment's minimum",
        run(
            &thin,
            &|l| {
                if let DirectCash::Kas(u) = &mut l.cash {
                    u.entry.amount = MIN_KAS_OUTPUT
                }
            },
            &pay,
            NOW,
        ),
        "TX_LEG_AMOUNT",
        run(&thin, &|_| {}, &pay, NOW),
        "TX_BELOW_MIN_KAS",
    );
    order(
        "the payment's minimum, fee inputs",
        run(&thin, &|_| {}, &none, NOW),
        "TX_BELOW_MIN_KAS",
        run(&kas, &|_| {}, &none, NOW),
        "TX_KAS_INPUT",
    );
    // KCC-20 cash: the seller's amount, the cash template, the buyer's token, its amount.
    let swapped_cash_template = |l: &mut DirectLegs| {
        if let DirectCash::Kcc20 { template, .. } = &mut l.cash {
            *template = a;
        }
    };
    let buyer_minter = |l: &mut DirectLegs| {
        if let DirectCash::Kcc20 { token, .. } = &mut l.cash {
            token.state.is_minter = true;
            token.utxo.entry.script_public_key = c.script_public_key(&token.state).unwrap();
        }
    };
    let buyer_short = |l: &mut DirectLegs| {
        if let DirectCash::Kcc20 { token, .. } = &mut l.cash {
            *token = own_token("buyer-cash", c, CASH_COV, &p.buyer, KCC20_CASH - 1);
        }
    };
    order(
        "seller's amount, cash template",
        run(
            &kcc20,
            &|l| {
                seller_short(l);
                swapped_cash_template(l)
            },
            &pay,
            NOW,
        ),
        "TX_LEG_AMOUNT",
        run(&kcc20, &swapped_cash_template, &pay, NOW),
        "TX_TOKEN_TEMPLATE",
    );
    order(
        "cash template, buyer's token",
        run(
            &kcc20,
            &|l| {
                swapped_cash_template(l);
                buyer_minter(l)
            },
            &pay,
            NOW,
        ),
        "TX_TOKEN_TEMPLATE",
        run(&kcc20, &buyer_minter, &pay, NOW),
        "TX_TOKEN_INPUT",
    );
    order(
        "buyer's token, its amount",
        run(
            &kcc20,
            &|l| {
                buyer_short(l);
                buyer_minter(l)
            },
            &pay,
            NOW,
        ),
        "TX_TOKEN_INPUT",
        run(&kcc20, &buyer_short, &pay, NOW),
        "TX_LEG_AMOUNT",
    );
    order(
        "buyer's amount, fee inputs",
        run(&kcc20, &buyer_short, &none, NOW),
        "TX_LEG_AMOUNT",
        run(&kcc20, &|_| {}, &none, NOW),
        "TX_KAS_INPUT",
    );
}

// =============================================================================================
// Minimum KAS, mass and fee
// =============================================================================================

#[test]
fn minimum_kas_is_derived_from_storage_mass() {
    // C * MAX_OUTPUTS / CAP = 10^12 * 5 / 10^5.
    assert_eq!(STORAGE_MASS_PARAMETER, 1_000_000_000_000);
    assert_eq!(SOMPI_PER_STORAGE_UNIT, 50_000_000);
    assert_eq!(MIN_KAS_OUTPUT, 50_000_000);
    assert_eq!(MIN_KCC20_OUTPUT, 200_000_000);
    assert_eq!(
        SOMPI_PER_STORAGE_UNIT * STANDARD_MASS_CAP,
        STORAGE_MASS_PARAMETER * MAX_OUTPUTS,
        "exact division"
    );
    // Pluralities by the pinned utxo_plurality: 1 for standard KAS scripts, 2 for a token.
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let ipst = settle_of(&terms, &p).unwrap();
    let outs = &ipst.transaction().outputs;
    assert_eq!(min_output_value(&outs[0]), MIN_KCC20_OUTPUT);
    assert_eq!(min_output_value(&outs[1]), MIN_KCC20_OUTPUT);
    assert_eq!(min_output_value(&outs[2]), MIN_KAS_OUTPUT);
    let p2sh = TransactionOutput::new(1, pay_to_script_hash_script(&[OpTrue]));
    assert_eq!(min_output_value(&p2sh), MIN_KAS_OUTPUT);
}

/// The derivation: storage mass never exceeds C * sum(p^2 / v) over the outputs, whatever the
/// inputs. At the minimum each output adds at most CAP / MAX_OUTPUTS, so a transaction of at most
/// MAX_OUTPUTS such outputs fits the cap for any fee input. At half the minimum it does not.
#[test]
fn at_the_minimum_the_worst_case_fits_the_cap() {
    let worst = |unit: u64| {
        // MAX_OUTPUTS outputs, two of them tokens (plurality 2), all at the minimum for `unit`,
        // and one huge input: the relaxed formula, where input relief is next to nothing.
        let outputs = [
            UtxoCell::new(2, 4 * unit),
            UtxoCell::new(2, 4 * unit),
            UtxoCell::new(1, unit),
            UtxoCell::new(1, unit),
            UtxoCell::new(1, unit),
        ];
        let inputs = [UtxoCell::new(1, 2_900_000_000_000_000_000)];
        calc_storage_mass(
            false,
            inputs.into_iter(),
            outputs.into_iter(),
            STORAGE_MASS_PARAMETER,
        )
        .unwrap()
    };
    assert!(worst(SOMPI_PER_STORAGE_UNIT) <= STANDARD_MASS_CAP);
    assert!(worst(SOMPI_PER_STORAGE_UNIT / 2) > STANDARD_MASS_CAP);

    // Every builder's transaction, with every leg UTXO at the minimum and the fee input from
    // small to the whole supply, stays within the cap.
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    for mode in Mode::vaults() {
        let mut t = terms(mode, &p);
        if mode.cash == Cash::Kas {
            t.cash_leg.amount = MIN_KAS_OUTPUT;
        }
        let terms = t.validate_structure().unwrap();
        let f = funded(&terms);
        for fee_input in [FEE + MIN_KAS_OUTPUT, FEE_INPUT, 2_000_000_000_000_000_000] {
            let fee = FeePayment {
                inputs: vec![utxo("fee", fee_input, p2pk(&p.payer), None)],
                fee: FEE,
                change: p2pk(&p.payer),
            };
            let ipst = settle(&terms, &settle_legs(&f, &a, &c), &fee, NOW)
                .unwrap_or_else(|e| panic!("{mode:?} {fee_input}: {e}"));
            assert!(ipst.masses().storage <= STANDARD_MASS_CAP);
        }
    }
}

#[test]
fn below_min_kas() {
    let p = parties();
    let a = asset_template();
    // A KAS cash leg below the minimum cannot be funded.
    for (amount, ok) in [(MIN_KAS_OUTPUT, true), (MIN_KAS_OUTPUT - 1, false)] {
        let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
        t.cash_leg.amount = amount;
        let terms = t.validate_structure().unwrap();
        let r = fund_kas(
            &terms,
            &fundable(&terms, LegIndex::Cash),
            &fee_payment(&p),
            NOW,
        );
        if ok {
            assert!(r.is_ok());
        } else {
            assert_eq!(code(r), "TX_BELOW_MIN_KAS");
        }
        // Nor settled Direct.
        let mut t = terms.terms().clone();
        t.settlement_mode = SettlementMode::Direct;
        t.funding_mode = FundingMode::Revocable;
        let direct_terms = t.validate_structure().unwrap();
        let r = direct_of(&direct_terms, &p);
        if ok {
            assert!(r.is_ok());
        } else {
            assert_eq!(code(r), "TX_BELOW_MIN_KAS");
        }
    }
    // The escrowed token's carrier and the authorizer.
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let asset = fundable(&terms, LegIndex::Asset);
    let fund = |carrier: u64, authorizer: u64| {
        let deposit = Kcc20Deposit {
            tokens: vec![own_token("t", &a, ASSET_COV, &p.seller, AMOUNT_A)],
            carrier,
            authorizer,
        };
        fund_kcc20(&terms, &asset, &a, &deposit, &fee_payment(&p), NOW)
    };
    assert!(fund(MIN_KCC20_OUTPUT, MIN_KAS_OUTPUT).is_ok());
    assert_eq!(
        code(fund(MIN_KCC20_OUTPUT - 1, MIN_KAS_OUTPUT)),
        "TX_BELOW_MIN_KAS"
    );
    assert_eq!(
        code(fund(MIN_KCC20_OUTPUT, MIN_KAS_OUTPUT - 1)),
        "TX_BELOW_MIN_KAS"
    );
}

#[test]
fn mass_above_the_cap() {
    // A KAS cash leg below the minimum, funded by hand: its settle output must hold exactly the
    // leg amount ([S5]), so nothing tops it up and the exact storage mass refuses it.
    let p = parties();
    let settle_kas_cash = |amount: u64| {
        let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
        t.cash_leg.amount = amount;
        let terms = t.validate_structure().unwrap();
        settle_of(&terms, &p)
    };
    assert!(settle_kas_cash(MIN_KAS_OUTPUT).is_ok());
    match settle_kas_cash(1_000) {
        Err(TxError::Mass {
            dimension: "storage",
            mass,
            cap: STANDARD_MASS_CAP,
        }) => assert!(mass > STANDARD_MASS_CAP),
        other => panic!("expected a storage mass refusal, got {other:?}"),
    }
    // A stray authorizer of 1,000 sompi goes home on its own: a refund's output 0 equals its
    // input ([R5]), and with at most two inputs and two outputs KIP-9 takes the harmonic mean of
    // the inputs too, so the small input offsets the equal small output.
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let mut stray = f.asset_authorizer.clone();
    stray.entry.amount = 1_000;
    let home = refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Depositor,
        &stray,
        None,
        &fee_payment(&p),
    )
    .unwrap();
    assert_eq!(home.transaction().outputs[0].value, 1_000);
    assert!(home.masses().storage <= STANDARD_MASS_CAP);
    // With its token at input 1 (three inputs) the relief does not apply: refused.
    let a = asset_template();
    let with_token = refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Depositor,
        &stray,
        Some(&RefundEscrow {
            utxo: f.asset_escrow.clone(),
            amount: AMOUNT_A,
            is_minter: false,
            template: &a,
        }),
        &fee_payment(&p),
    );
    assert!(matches!(
        with_token,
        Err(TxError::Mass {
            dimension: "storage",
            ..
        })
    ));
}

#[test]
fn under_funded_pass_through_outputs_are_topped_up() {
    // An authorizer or a token carrier below its minimum (funded by hand, or by a depositor that
    // wants to block the settle) no longer makes the settle unbuildable: its output is topped up
    // to the minimum from the fee inputs, which the contract allows ([S9], [D2], [R13]: "at
    // least"). The fee stays the caller's; the change pays the difference.
    let p = parties();
    let terms = validated(Mode::vault(false, Cash::Kcc20, FundingMode::Earmarked), &p);
    let control = settle_with(&terms, &p, |_| {}).unwrap();
    let change = |ipst: &Ipst| ipst.transaction().outputs.last().unwrap().value;
    for (label, edit, output, minimum) in [
        (
            "asset authorizer of 1,000 sompi",
            Box::new(|f: &mut Funded| f.asset_authorizer.entry.amount = 1_000)
                as Box<dyn Fn(&mut Funded)>,
            2,
            MIN_KAS_OUTPUT,
        ),
        (
            "cash authorizer of 1,000 sompi",
            Box::new(|f: &mut Funded| f.cash_authorizer.as_mut().unwrap().entry.amount = 1_000),
            3,
            MIN_KAS_OUTPUT,
        ),
        (
            "asset carrier of 1,000 sompi",
            Box::new(|f: &mut Funded| f.asset_escrow.entry.amount = 1_000),
            0,
            MIN_KCC20_OUTPUT,
        ),
        (
            "cash carrier of 1,000 sompi",
            Box::new(|f: &mut Funded| f.cash_escrow.as_mut().unwrap().entry.amount = 1_000),
            1,
            MIN_KCC20_OUTPUT,
        ),
    ] {
        let ipst = settle_with(&terms, &p, edit).unwrap_or_else(|e| panic!("{label}: {e}"));
        let outs = &ipst.transaction().outputs;
        assert_eq!(outs[output].value, minimum, "{label}");
        assert_eq!(ipst.fee(), FEE, "{label}");
        // The fixture input holds exactly the minimum; this one held 1,000 sompi, so the change
        // pays the difference.
        assert_eq!(change(&ipst) + minimum - 1_000, change(&control), "{label}");
        assert!(ipst.masses().storage <= STANDARD_MASS_CAP, "{label}");
    }
    // Above the minimum the KAS passes through unchanged.
    let rich = settle_with(&terms, &p, |f| {
        f.asset_authorizer.entry.amount = 3 * AUTHORIZER
    })
    .unwrap();
    assert_eq!(rich.transaction().outputs[2].value, 3 * AUTHORIZER);
    // The refunded token's carrier is topped up too; the refunded authorizer is not ([R5]).
    let a = asset_template();
    let f = funded(&terms);
    let mut thin = f.asset_escrow.clone();
    thin.entry.amount = 1_000;
    let mut thin_authorizer = f.asset_authorizer.clone();
    thin_authorizer.entry.amount = 1_000;
    let r = refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Counterparty,
        &f.asset_authorizer,
        Some(&RefundEscrow {
            utxo: thin,
            amount: AMOUNT_A,
            is_minter: false,
            template: &a,
        }),
        &fee_payment(&p),
    )
    .unwrap();
    assert_eq!(r.transaction().outputs[1].value, MIN_KCC20_OUTPUT);
    assert_eq!(r.transaction().outputs[0].value, AUTHORIZER);
    // Direct: the seller's token carrier.
    let (a, c) = (asset_template(), cash_template());
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    let mut legs = direct_legs(&direct_terms, &p, &a, &c);
    legs.asset.utxo.entry.amount = 1_000;
    let d = direct(&direct_terms, &legs, &fee_payment(&p), NOW).unwrap();
    assert_eq!(d.transaction().outputs[0].value, MIN_KCC20_OUTPUT);
}

#[test]
fn budgets_follow_the_template_length() {
    use super::rules::{
        kcc20_delegate_budget, kcc20_leader_budget, vault_budget, SIGOP_SCRIPT_UNITS,
    };
    use kaspa_consensus_core::config::params::{MAINNET_PARAMS, TESTNET_PARAMS};
    use kaspa_consensus_core::mass::SCRIPT_UNITS_PER_GRAM;
    for params in [&MAINNET_PARAMS, &TESTNET_PARAMS] {
        assert_eq!(
            params.mass_per_sig_op * SCRIPT_UNITS_PER_GRAM,
            SIGOP_SCRIPT_UNITS
        );
    }
    let (a, c) = (asset_template(), cash_template());
    let (la, lc) = (
        (a.prefix_len() + a.suffix_len()) as u64,
        (c.prefix_len() + c.suffix_len()) as u64,
    );
    // The fixture tokens: every budget is its floor, so the golden vectors keep their budgets.
    assert_eq!(vault_budget(0), VAULT_BUDGET);
    assert_eq!(vault_budget(la + lc), VAULT_BUDGET);
    assert_eq!(kcc20_leader_budget(true, la, 2, 2), KCC20_KEY_OWNED_BUDGET);
    assert_eq!(
        kcc20_leader_budget(false, lc, 1, 1),
        KCC20_VAULT_OWNED_BUDGET
    );
    assert_eq!(kcc20_delegate_budget(la), KCC20_KEY_OWNED_BUDGET);
    // Longer templates: the per-byte rules take over. 100,000 + 45,000 + 17 * 20,000 units
    // need 47 units past the free 9,999, and a 48th for the remainder.
    assert_eq!(vault_budget(20_000), 48);
    // 10,000 + 2,000 + 6 * 6,280 = 49,680 units: 4.
    assert_eq!(kcc20_leader_budget(false, 6_280, 1, 1), 4);
    // 100,000 + 10,000 + 4,000 + 10 * 6,081 = 174,810 units: 17.
    assert_eq!(kcc20_leader_budget(true, 6_081, 2, 2), 17);
    // 100,000 + 10,000 + 2 * 50,000 = 210,000 units: 21.
    assert_eq!(kcc20_delegate_budget(50_000), 21);
    // Budgets never wrap; one that large fails the compute-mass check.
    assert_eq!(vault_budget(u64::MAX), u16::MAX);
}

#[test]
fn every_mass_dimension_is_capped() {
    use super::rules::check_masses;
    let at_cap = Masses {
        compute: STANDARD_MASS_CAP,
        transient: STANDARD_MASS_CAP,
        storage: STANDARD_MASS_CAP,
        fee_mass: 0,
    };
    assert_eq!(check_masses(&at_cap), Ok(()));
    let over = STANDARD_MASS_CAP + 1;
    for (dimension, masses) in [
        (
            "compute",
            Masses {
                compute: over,
                ..at_cap
            },
        ),
        (
            "transient",
            Masses {
                transient: over,
                ..at_cap
            },
        ),
        (
            "storage",
            Masses {
                storage: over,
                ..at_cap
            },
        ),
    ] {
        assert_eq!(
            check_masses(&masses),
            Err(TxError::Mass {
                dimension,
                mass: over,
                cap: STANDARD_MASS_CAP
            })
        );
    }
    // Through a builder: the templates bound the inputs of a settle at 12, so a hundred fee
    // inputs are refused for their count (`TX_TOO_MANY_INPUTS`) before any mass is computed.
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let many = |n: usize| FeePayment {
        inputs: (0..n)
            .map(|i| utxo(&format!("fee-{i}"), FEE_INPUT, p2pk(&p.payer), None))
            .collect(),
        fee: FEE * 10,
        change: p2pk(&p.payer),
    };
    assert!(settle(&terms, &legs, &many(9), NOW).is_ok());
    assert!(matches!(
        settle(&terms, &legs, &many(100), NOW),
        Err(TxError::TooManyInputs { max: 12, .. })
    ));
}

/// The vault templates allow at most 12 inputs in a settle or refund (spec/TEMPLATE.md, "Inputs
/// outside the layout"): the builders refuse more (`TX_TOO_MANY_INPUTS`) before the duplicate,
/// value and fee checks; a fund or Direct transaction spends no vault and is not bounded.
#[test]
fn spends_have_at_most_12_inputs() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let many = |n: usize| FeePayment {
        inputs: (0..n)
            .map(|i| utxo(&format!("fee-{i}"), FEE_INPUT, p2pk(&p.payer), None))
            .collect(),
        fee: FEE * 10,
        change: p2pk(&p.payer),
    };
    for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
        let terms = validated(Mode::vault(true, cash, FundingMode::Earmarked), &p);
        let f = funded(&terms);
        let legs = settle_legs(&f, &a, &c);
        let trade = 12
            - match cash {
                Cash::Kas => 3,
                Cash::Kcc20 => 4,
                Cash::External => 2,
            };
        assert!(settle(&terms, &legs, &many(trade), NOW).is_ok(), "{cash:?}");
        assert_eq!(
            settle(&terms, &legs, &many(trade + 1), NOW),
            Err(TxError::TooManyInputs {
                inputs: 13,
                max: 12
            }),
            "{cash:?}"
        );
        // A duplicate among too many inputs: the bound is reported first.
        let mut dup = many(trade + 1);
        dup.inputs[1] = dup.inputs[0].clone();
        assert_eq!(code(settle(&terms, &legs, &dup, NOW)), "TX_TOO_MANY_INPUTS");
    }
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let escrow = RefundEscrow {
        utxo: f.asset_escrow.clone(),
        amount: terms.terms().asset_leg.amount,
        is_minter: false,
        template: &a,
    };
    let refund_of = |fee: &FeePayment| {
        refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Counterparty,
            &f.asset_authorizer,
            Some(&escrow),
            fee,
        )
    };
    assert!(refund_of(&many(10)).is_ok());
    assert_eq!(code(refund_of(&many(11))), "TX_TOO_MANY_INPUTS");
}

#[test]
fn token_amounts_outside_the_script_integer_range() {
    let p = parties();
    let a = asset_template();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let vault = fundable(&terms, LegIndex::Asset);
    let fund = |tokens: Vec<TokenUtxo>| {
        let deposit = Kcc20Deposit {
            tokens,
            carrier: CARRIER,
            authorizer: AUTHORIZER,
        };
        fund_kcc20(&terms, &vault, &a, &deposit, &fee_payment(&p), NOW)
    };
    let tok = |label: &str, amount: u64| own_token(label, &a, ASSET_COV, &p.seller, amount);
    let max = i64::MAX as u64;
    assert!(fund(vec![tok("t", AMOUNT_A)]).is_ok());
    assert!(fund(vec![tok("t", max)]).is_ok());
    let mut zero = tok("t", AMOUNT_A);
    zero.state.amount = 0;
    zero.utxo.entry.script_public_key = a.script_public_key(&zero.state).unwrap();
    // Past i64::MAX the state has no script, so the stated one is any; the amount is refused
    // first.
    let mut past = tok("t", AMOUNT_A);
    past.state.amount = max + 1;
    for (label, tokens) in [
        ("an amount of zero", vec![tok("t1", AMOUNT_A), zero]),
        ("an amount past i64::MAX", vec![past]),
        (
            "amounts adding up past i64::MAX",
            vec![tok("t1", max), tok("t2", 1)],
        ),
    ] {
        match fund(tokens) {
            Err(TxError::TokenInput { reason, .. }) => assert!(
                reason.contains("zero") || reason.contains("integer range"),
                "{label}: {reason}"
            ),
            other => panic!("{label}: expected TX_TOKEN_INPUT, got {other:?}"),
        }
    }
    // A refund escrow stated past i64::MAX is not this vault's escrow (no script holds it).
    let f = funded(&terms);
    let escrow = RefundEscrow {
        utxo: f.asset_escrow.clone(),
        amount: max + 1,
        is_minter: false,
        template: &a,
    };
    assert_eq!(
        code(refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.asset_authorizer,
            Some(&escrow),
            &fee_payment(&p)
        )),
        "TX_ESCROW_MISMATCH"
    );
}

#[test]
fn a_fee_input_of_another_script_version() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let mut fee = fee_payment(&p);
    assert!(settle(&terms, &legs, &fee, NOW).is_ok());
    fee.inputs[0].entry.script_public_key =
        ScriptPublicKey::from_vec(1, p2pk(&p.payer).script().to_vec());
    assert_eq!(code(settle(&terms, &legs, &fee, NOW)), "TX_KAS_INPUT");
}

#[test]
fn kcc20_artifacts_refused_by_each_check() {
    // Each artifact fails exactly one of Kcc20Template::from_artifact's checks.
    use silverscript_abi::template_hash;
    assert!(Kcc20Template::from_json(ASSET_ARTIFACT).is_ok());
    let doc: serde_json::Value = serde_json::from_str(ASSET_ARTIFACT).unwrap();
    let bytecode: Vec<u8> = doc["contracts"]["KCC20"]["compiled"]["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let span = &doc["contracts"]["KCC20"]["compiled"]["state_span"];
    let (offset, len) = (
        span["offset"].as_u64().unwrap() as usize,
        span["len"].as_u64().unwrap() as usize,
    );
    assert_eq!(offset, 1, "the fixture's prefix is one byte");
    // A consistent artifact whose bytecode lacks the prefix, or the suffix.
    let without = |prefix: bool| {
        let mut d = doc.clone();
        let code: Vec<u8> = if prefix {
            bytecode[offset..].to_vec()
        } else {
            bytecode[..offset + len].to_vec()
        };
        let (p, s) = if prefix {
            (vec![], bytecode[offset + len..].to_vec())
        } else {
            (bytecode[..offset].to_vec(), vec![])
        };
        let compiled = &mut d["contracts"]["KCC20"]["compiled"];
        compiled["bytecode"] = code.into();
        compiled["state_span"]["offset"] = (if prefix { 0 } else { offset }).into();
        compiled["template_hash"] = template_hash(&p, &s).to_vec().into();
        d.to_string()
    };
    let two_contracts = {
        let mut d = doc.clone();
        let copy = d["contracts"]["KCC20"].clone();
        d["contracts"]["KCC20b"] = copy;
        d.to_string()
    };
    let tag_collision = {
        let mut d = doc.clone();
        let entries = &mut d["contracts"]["KCC20"]["entries"];
        entries["__delegate"]["dispatch_tag"] =
            entries["__leader_transfer"]["dispatch_tag"].clone();
        d.to_string()
    };
    let witness_as_int = {
        let mut d = doc.clone();
        d["contracts"]["KCC20"]["entries"]["__leader_transfer"]["params"][2]["type"]["kind"] =
            "int".into();
        d.to_string()
    };
    for (label, json) in [
        ("two contracts", two_contracts),
        ("no prefix", without(true)),
        ("no suffix", without(false)),
        (
            "a dispatch tag collision (silverscript's consistency check)",
            tag_collision,
        ),
        ("a leader witness of another type", witness_as_int),
    ] {
        let parsed: silverscript_abi::SilAbiArtifact =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(
            code(Kcc20Template::from_artifact(parsed)),
            "TX_TOKEN_TEMPLATE",
            "{label}"
        );
    }
}

#[test]
fn fee_too_low() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let f = funded(&terms);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f, &a, &c);
    let masses = settle(&terms, &legs, &fee_payment(&p), NOW)
        .unwrap()
        .masses();
    let minimum = min_relay_fee(masses.fee_mass);
    // 100 sompi per gram on the larger of compute and half the transient mass.
    assert_eq!(minimum, masses.fee_mass * 100);
    assert_eq!(
        masses.fee_mass,
        masses.compute.max(masses.transient.div_ceil(2))
    );
    let pay = |fee| FeePayment {
        fee,
        ..fee_payment(&p)
    };
    assert!(settle(&terms, &legs, &pay(minimum), NOW).is_ok());
    assert_eq!(
        settle(&terms, &legs, &pay(minimum - 1), NOW).unwrap_err(),
        TxError::FeeTooLow {
            fee: minimum - 1,
            minimum
        }
    );
    assert_eq!(min_relay_fee(0), MIN_RELAY_FEE_PER_KILOGRAM);
}

#[test]
fn masses_are_within_the_cap_in_every_mode() {
    let p = parties();
    for mode in Mode::all() {
        let terms = validated(mode, &p);
        let ipst = if mode.settlement == SettlementMode::Direct {
            direct_of(&terms, &p)
        } else {
            settle_of(&terms, &p)
        }
        .unwrap();
        let m = ipst.masses();
        assert!(m.compute <= STANDARD_MASS_CAP && m.transient <= STANDARD_MASS_CAP);
        assert!(ipst.fee() >= min_relay_fee(m.fee_mass), "{mode:?}");
    }
}

#[test]
fn lock_time_and_sequences_follow_the_node_rule() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let settled = settle_of(&terms, &p).unwrap();
    let tx = settled.transaction();
    assert_eq!(
        crate::locktime::first_block_daa(tx.lock_time),
        Some(EARLIEST + 1)
    );
    assert!(crate::locktime::check_tx_is_finalized(tx, EARLIEST, 0).is_err());
    assert!(crate::locktime::check_tx_is_finalized(tx, EARLIEST + 1, 0).is_ok());
    assert!(tx
        .inputs
        .iter()
        .all(|i| i.sequence < MAX_TX_IN_SEQUENCE_NUM));
    let refunded = refund_of(&terms, &p, LegIndex::Asset, RefundSigner::Depositor, true).unwrap();
    let tx = refunded.transaction();
    assert_eq!(
        crate::locktime::first_block_daa(tx.lock_time),
        Some(EXPIRY + 1)
    );
    assert!(crate::locktime::check_tx_is_finalized(tx, EXPIRY, 0).is_err());
    assert!(crate::locktime::check_tx_is_finalized(tx, EXPIRY + 1, 0).is_ok());
}

// =============================================================================================
// IPST
// =============================================================================================

fn every_ipst(p: &Parties) -> Vec<Ipst> {
    let mut all = vec![];
    for mode in Mode::all() {
        let terms = validated(mode, p);
        if mode.settlement == SettlementMode::Direct {
            all.push(direct_of(&terms, p).unwrap());
            continue;
        }
        all.push(settle_of(&terms, p).unwrap());
        all.push(fund_kcc20_of(&terms, LegIndex::Asset, p).unwrap());
        all.push(refund_of(&terms, p, LegIndex::Asset, RefundSigner::Counterparty, true).unwrap());
        match mode.cash {
            Cash::Kas => {
                all.push(
                    fund_kas(
                        &terms,
                        &fundable(&terms, LegIndex::Cash),
                        &fee_payment(p),
                        NOW,
                    )
                    .unwrap(),
                );
                all.push(
                    refund_of(&terms, p, LegIndex::Cash, RefundSigner::Depositor, false).unwrap(),
                );
            }
            Cash::Kcc20 => all.push(fund_kcc20_of(&terms, LegIndex::Cash, p).unwrap()),
            Cash::External => {}
        }
    }
    all
}

#[test]
fn ipst_round_trips() {
    let p = parties();
    for ipst in every_ipst(&p) {
        let text = ipst.to_json();
        let read = Ipst::from_json(&text).unwrap();
        assert_eq!(read, ipst);
        assert_eq!(read.to_json(), text);
    }
}

#[test]
fn ipst_reads_any_whitespace_and_key_order() {
    let p = parties();
    let ipst = settle_of(
        &validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p),
        &p,
    )
    .unwrap();
    let text = ipst.to_json();
    let compact: String = text.split_whitespace().collect::<Vec<_>>().join("");
    assert_eq!(Ipst::from_json(&compact).unwrap(), ipst);
    // The top-level keys in reverse order.
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let obj = doc.as_object().unwrap();
    let reversed = format!(
        "{{{}}}",
        obj.iter()
            .rev()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(Ipst::from_json(&reversed).unwrap(), ipst);
}

#[test]
fn ipst_refusals() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let ipst = settle_of(&terms, &p).unwrap();
    let text = ipst.to_json();
    assert!(Ipst::from_json(&text).is_ok());
    let sighash0 = hex32(&ipst.slots()[0].sighash().unwrap());
    let signer0 = hex32(&p.authority);
    let malformed = [
        ("not json", "nope".to_string()),
        ("an array", "[]".to_string()),
        ("no version", text.replacen("\"ipst\": 1,", "", 1)),
        (
            "version as a string",
            text.replacen("\"ipst\": 1", "\"ipst\": \"1\"", 1),
        ),
        (
            "unknown key",
            text.replacen("\"ipst\": 1,", "\"ipst\": 1, \"x\": null,", 1),
        ),
        (
            "missing key",
            text.replacen("\"lock_time\"", "\"lock_tim\"", 1),
        ),
        (
            "duplicate key",
            text.replacen("\"ipst\": 1,", "\"ipst\": 1, \"ipst\": 1,", 1),
        ),
        (
            "uppercase hex",
            text.replacen(&sighash0, &sighash0.to_uppercase(), 1),
        ),
        ("short hex", text.replacen(&sighash0, &sighash0[2..], 1)),
        (
            "leading zero",
            text.replacen("\"lock_time\": \"", "\"lock_time\": \"0", 1),
        ),
        (
            "number for u64",
            text.replacen(
                &format!("\"lock_time\": \"{EARLIEST}\""),
                &format!("\"lock_time\": {EARLIEST}"),
                1,
            ),
        ),
        ("float", text.replacen("\"index\": 0", "\"index\": 0.0", 1)),
        (
            "budget out of range",
            text.replacen(
                &format!("\"compute_budget\": {VAULT_BUDGET}"),
                "\"compute_budget\": 65536",
                1,
            ),
        ),
        ("empty outputs", {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["outputs"] = serde_json::json!([]);
            d.to_string()
        }),
        ("empty inputs", {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["inputs"] = serde_json::json!([]);
            d.to_string()
        }),
        ("sighash without signer", {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["inputs"][0]["signer"] = serde_json::Value::Null;
            d.to_string()
        }),
        (
            "authorizing input out of range",
            text.replacen("\"authorizing_input\": 2", "\"authorizing_input\": 9", 1),
        ),
        (
            "signer without sighash",
            text.replacen(
                &format!("\"sighash\": \"{sighash0}\""),
                "\"sighash\": null",
                1,
            ),
        ),
        ("signature without signer", {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["inputs"][2]["signature"] = serde_json::json!("00".repeat(65));
            d.to_string()
        }),
        ("script_after without signer", {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["inputs"][2]["script_after"] = serde_json::json!("00");
            d.to_string()
        }),
        (
            "a signer that is not a key",
            text.replacen(
                &format!("\"signer\": \"{signer0}\""),
                &format!("\"signer\": \"{}\"", "00".repeat(32)),
                1,
            ),
        ),
    ];
    for (label, bad) in malformed {
        assert_ne!(bad, text, "{label}");
        assert_eq!(code(Ipst::from_json(&bad)), "IPST_MALFORMED", "{label}");
    }
    assert_eq!(
        Ipst::from_json(&text.replacen("\"ipst\": 1", "\"ipst\": 2", 1)).unwrap_err(),
        TxError::IpstUnsupportedVersion { version: 2 }
    );
    // Terms that fail the structure checks keep their code.
    let mut bad_terms = terms.terms().clone();
    bad_terms.buyer_key = bad_terms.seller_key;
    let bad_terms = hex(&bad_terms.encode().unwrap());
    assert_eq!(
        code(Ipst::from_json(&text.replacen(
            &hex(terms.canonical()),
            &bad_terms,
            1
        ))),
        "TERMS_PARTIES_NOT_DISTINCT"
    );
    // A stated sighash that is not the transaction's: a changed output, an edited sighash.
    let paid = format!("\"value\": \"{}\"", FEE_INPUT - FEE);
    let skimmed = text.replacen(&paid, &format!("\"value\": \"{}\"", FEE_INPUT - FEE - 1), 1);
    assert_ne!(skimmed, text);
    assert_eq!(
        Ipst::from_json(&skimmed).unwrap_err(),
        TxError::IpstSighashMismatch { input: 0 }
    );
    let forged = text.replacen(&sighash0, &"00".repeat(32), 1);
    assert_eq!(
        Ipst::from_json(&forged).unwrap_err(),
        TxError::IpstSighashMismatch { input: 0 }
    );
    // The first input whose stated sighash differs is the one reported.
    let sighash1 = hex32(&ipst.slots()[1].sighash().unwrap());
    let forged1 = text.replacen(&sighash1, &"00".repeat(32), 1);
    assert_eq!(
        Ipst::from_json(&forged1).unwrap_err(),
        TxError::IpstSighashMismatch { input: 1 }
    );
}

#[test]
fn ipst_reader_refuses_values_outside_the_supply() {
    // A document whose inputs hold exactly MAX_SOMPI reads; every value outside 1 to MAX_SOMPI,
    // inputs adding up past it, or outputs paying more than the inputs hold is IPST_MALFORMED,
    // refused before any sighash, mass or fee is computed.
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let ipst = fund_kas(
        &terms,
        &fundable(&terms, LegIndex::Cash),
        &FeePayment {
            inputs: vec![
                utxo("fee-0", MAX_SOMPI - FEE_INPUT, p2pk(&p.payer), None),
                utxo("fee-1", FEE_INPUT, p2pk(&p.payer), None),
            ],
            ..fee_payment(&p)
        },
        NOW,
    )
    .unwrap();
    let text = ipst.to_json();
    let read = Ipst::from_json(&text).unwrap();
    assert_eq!(read.fee(), FEE);
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut d = doc.clone();
        edit(&mut d);
        d.to_string()
    };
    let big = MAX_SOMPI + 1;
    for (label, bad) in [
        (
            "an output of zero",
            edited(&|d| d["outputs"][0]["value"] = "0".into()),
        ),
        (
            "an output above MAX_SOMPI",
            edited(&|d| d["outputs"][1]["value"] = big.to_string().into()),
        ),
        (
            "a UTXO of zero",
            edited(&|d| d["inputs"][1]["utxo"]["amount"] = "0".into()),
        ),
        (
            "a UTXO above MAX_SOMPI",
            edited(&|d| d["inputs"][0]["utxo"]["amount"] = big.to_string().into()),
        ),
        (
            "two UTXOs of u64::MAX",
            edited(&|d| {
                d["inputs"][0]["utxo"]["amount"] = u64::MAX.to_string().into();
                d["inputs"][1]["utxo"]["amount"] = u64::MAX.to_string().into();
            }),
        ),
        (
            "UTXOs adding up past MAX_SOMPI",
            edited(&|d| d["inputs"][1]["utxo"]["amount"] = (FEE_INPUT + 1).to_string().into()),
        ),
        (
            "outputs paying more than the inputs hold",
            edited(&|d| d["outputs"][1]["value"] = (MAX_SOMPI - KAS_CASH + 1).to_string().into()),
        ),
    ] {
        assert_eq!(code(Ipst::from_json(&bad)), "IPST_MALFORMED", "{label}");
    }
}

#[test]
fn ipst_combine_refuses_any_difference_but_signatures() {
    // Each document below differs from the original in one field that reading cannot catch,
    // because no sighash covers it, and so reads; combining it with the original is a conflict.
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let ipst = settle_of(&terms, &p).unwrap();
    let text = ipst.to_json();
    let same = Ipst::from_json(&text).unwrap();
    assert_eq!(ipst.combine(&same).unwrap(), ipst);
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut d = doc.clone();
        edit(&mut d);
        Ipst::from_json(&d.to_string()).expect("no sighash covers the field, so it reads")
    };
    let mut other_terms = terms.terms().clone();
    other_terms.nonce += 1;
    let other_terms = hex(&other_terms.encode().unwrap());
    let flipped = |hex_text: &str| {
        let mut b = super::ipst::unhex(hex_text).unwrap();
        let last = b.len() - 1;
        b[last] ^= 1;
        hex(&b)
    };
    let before_2 = doc["inputs"][2]["script_before"]
        .as_str()
        .unwrap()
        .to_string();
    let after_0 = doc["inputs"][0]["script_after"]
        .as_str()
        .unwrap()
        .to_string();
    for (label, other) in [
        (
            "other terms",
            edited(&|d| d["terms"] = other_terms.clone().into()),
        ),
        (
            "a UTXO entry's DAA score",
            edited(&|d| d["inputs"][1]["utxo"]["block_daa_score"] = "7".into()),
        ),
        (
            "a slot's signer",
            edited(&|d| d["inputs"][0]["signer"] = hex(&p.seller).into()),
        ),
        (
            "a slot's script_before",
            edited(&|d| d["inputs"][2]["script_before"] = flipped(&before_2).into()),
        ),
        (
            "a slot's script_after",
            edited(&|d| d["inputs"][0]["script_after"] = flipped(&after_0).into()),
        ),
    ] {
        assert_eq!(code(ipst.combine(&other)), "IPST_CONFLICT", "{label}");
        assert_eq!(code(other.combine(&ipst)), "IPST_CONFLICT", "{label}");
    }
    // A signature copied in is verified against the receiving slot first. Reading and
    // add_signature verify every signature, so this document is built in-crate.
    let mut slots = ipst.slots().to_vec();
    let mut bogus = [7u8; 65];
    bogus[64] = 0x01;
    slots[0].signature = Some(bogus);
    let forged = Ipst::from_parts(
        ipst.terms().clone(),
        ipst.transaction().clone(),
        ipst.entries().to_vec(),
        slots,
    );
    assert_eq!(code(ipst.combine(&forged)), "TX_SIGNATURE");
}

// =============================================================================================
// The terms check
// =============================================================================================

/// The same IPST with its transaction edited and every sighash recomputed: a well-formed document
/// that reads back as itself, as a dishonest builder would hand it over.
fn tampered(ipst: &Ipst, edit: impl FnOnce(&mut kaspa_consensus_core::tx::Transaction)) -> Ipst {
    tampered_with(ipst, |tx, _| edit(tx))
}

/// As [`tampered`], editing the UTXO entries too.
fn tampered_with(
    ipst: &Ipst,
    edit: impl FnOnce(
        &mut kaspa_consensus_core::tx::Transaction,
        &mut Vec<kaspa_consensus_core::tx::UtxoEntry>,
    ),
) -> Ipst {
    let mut tx = ipst.transaction().clone();
    let mut entries = ipst.entries().to_vec();
    edit(&mut tx, &mut entries);
    tx.finalize();
    let mut slots = ipst.slots().to_vec();
    for (i, slot) in slots.iter_mut().enumerate() {
        if slot.signer.is_some() {
            slot.sighash = Some(sighash(&tx, &entries, i).unwrap());
        }
    }
    let doc = Ipst::from_parts(ipst.terms().clone(), tx, entries, slots);
    let read = Ipst::from_json(&doc.to_json()).expect("the tampered document reads");
    assert_eq!(read, doc);
    read
}

fn check(ipst: &Ipst) -> Result<TermsMatch, TxError> {
    ipst.verify_against_terms(&asset_template(), Some(&cash_template()), NOW)
}

#[test]
fn the_terms_check_accepts_every_builder_ipst() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let mut all: Vec<(String, Ipst, IpstKind)> = vec![];
    for mode in Mode::all() {
        let terms = validated(mode, &p);
        let label = format!("{mode:?}");
        if mode.settlement == SettlementMode::Direct {
            all.push((label, direct_of(&terms, &p).unwrap(), IpstKind::Direct));
            continue;
        }
        all.push((
            format!("{label} settle"),
            settle_of(&terms, &p).unwrap(),
            IpstKind::Settle,
        ));
        all.push((
            format!("{label} fund asset"),
            fund_kcc20_of(&terms, LegIndex::Asset, &p).unwrap(),
            IpstKind::FundKcc20(LegIndex::Asset),
        ));
        let legs: &[LegIndex] = match mode.cash {
            Cash::External => &[LegIndex::Asset],
            _ => &[LegIndex::Asset, LegIndex::Cash],
        };
        for &leg in legs {
            let mut roles = vec![RefundSigner::Depositor, RefundSigner::Counterparty];
            if mode.authority {
                roles.push(RefundSigner::Authority);
            }
            let kas_cash = leg == LegIndex::Cash && mode.cash == Cash::Kas;
            for signer in roles {
                let ipst = refund_of(&terms, &p, leg, signer, true).unwrap();
                let with_token = !kas_cash;
                all.push((
                    format!("{label} refund {leg:?} {signer:?}"),
                    ipst,
                    IpstKind::Refund {
                        leg,
                        signer,
                        with_token,
                    },
                ));
            }
            if !kas_cash {
                all.push((
                    format!("{label} refund {leg:?} authorizer alone"),
                    refund_of(&terms, &p, leg, RefundSigner::Depositor, false).unwrap(),
                    IpstKind::Refund {
                        leg,
                        signer: RefundSigner::Depositor,
                        with_token: false,
                    },
                ));
            }
        }
        match mode.cash {
            Cash::Kas => all.push((
                format!("{label} fund cash"),
                fund_kas(
                    &terms,
                    &fundable(&terms, LegIndex::Cash),
                    &fee_payment(&p),
                    NOW,
                )
                .unwrap(),
                IpstKind::FundKas,
            )),
            Cash::Kcc20 => all.push((
                format!("{label} fund cash"),
                fund_kcc20_of(&terms, LegIndex::Cash, &p).unwrap(),
                IpstKind::FundKcc20(LegIndex::Cash),
            )),
            Cash::External => {}
        }
    }
    // Funding from two tokens with token change, and a stray minter refunded by the depositor.
    let terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let two = Kcc20Deposit {
        tokens: vec![
            own_token("t1", &a, ASSET_COV, &p.seller, 600),
            own_token("t2", &a, ASSET_COV, &p.seller, 700),
        ],
        carrier: CARRIER,
        authorizer: AUTHORIZER,
    };
    all.push((
        "fund from two tokens".into(),
        fund_kcc20(
            &terms,
            &fundable(&terms, LegIndex::Asset),
            &a,
            &two,
            &fee_payment(&p),
            NOW,
        )
        .unwrap(),
        IpstKind::FundKcc20(LegIndex::Asset),
    ));
    let stray_state = Kcc20State {
        is_minter: true,
        ..escrow_state(&vault(&terms, LegIndex::Asset), 7)
    };
    let stray = RefundEscrow {
        utxo: utxo(
            "stray",
            CARRIER,
            a.script_public_key(&stray_state).unwrap(),
            Some(ASSET_COV),
        ),
        amount: 7,
        is_minter: true,
        template: &a,
    };
    all.push((
        "stray minter by the depositor".into(),
        refund(
            &terms,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &funded(&terms).asset_authorizer,
            Some(&stray),
            &fee_payment(&p),
        )
        .unwrap(),
        IpstKind::Refund {
            leg: LegIndex::Asset,
            signer: RefundSigner::Depositor,
            with_token: true,
        },
    ));
    for (label, ipst, kind) in all {
        let found = ipst
            .verify_against_terms(&a, Some(&c), NOW)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(found.kind, kind, "{label}");
        assert_eq!(found.fee, FEE, "{label}");
        assert_eq!(
            found.change.as_ref(),
            ipst.transaction().outputs.last(),
            "{label}"
        );
        // As a document from someone else, too.
        let read = Ipst::from_json(&ipst.to_json()).unwrap();
        assert_eq!(
            read.verify_against_terms(&a, Some(&c), NOW).unwrap(),
            found,
            "{label}"
        );
    }
}

#[test]
fn the_terms_check_refuses_a_tampered_direct_ipst() {
    // The seller's token carries 100 KAS. A dishonest builder pays the buyer 2 KAS with it and
    // sends the other 98 KAS to the payer's change; the document reads, its sighashes are right
    // and its fee is the normal one, so only the terms check sees it.
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let terms = validated(Mode::direct(Cash::Kcc20), &p);
    let mut legs = direct_legs(&terms, &p, &a, &c);
    let carried = 100 * SOMPI_PER_KASPA;
    legs.asset.utxo.entry.amount = carried;
    let honest = direct(&terms, &legs, &fee_payment(&p), NOW).unwrap();
    assert_eq!(honest.transaction().outputs[0].value, carried);
    assert_eq!(check(&honest).unwrap().kind, IpstKind::Direct);
    let last = honest.transaction().outputs.len() - 1;
    let skim = tampered(&honest, |tx| {
        tx.outputs[0].value = MIN_KCC20_OUTPUT;
        tx.outputs[last].value += carried - MIN_KCC20_OUTPUT;
    });
    assert_eq!(skim.fee(), FEE);
    let budget = |b: u16| kaspa_consensus_core::mass::ComputeBudget(b).into();
    let cases: Vec<(&str, Ipst)> = vec![
        ("carrier skim", skim),
        (
            "fee drawn from a trade input",
            tampered(&honest, |tx| tx.outputs[0].value -= SOMPI_PER_KASPA),
        ),
        (
            "sequence MAX on every input",
            tampered(&honest, |tx| {
                tx.inputs
                    .iter_mut()
                    .for_each(|i| i.sequence = MAX_TX_IN_SEQUENCE_NUM)
            }),
        ),
        (
            "lock time removed",
            tampered(&honest, |tx| tx.lock_time = 0),
        ),
        (
            "lock time raised",
            tampered(&honest, |tx| tx.lock_time = EARLIEST + 1),
        ),
        (
            "a budget raised",
            tampered(&honest, |tx| {
                tx.inputs[0].compute_commit = budget(KCC20_KEY_OWNED_BUDGET + 1)
            }),
        ),
        (
            "a budget lowered",
            tampered(&honest, |tx| tx.inputs[1].compute_commit = budget(1)),
        ),
        (
            "an extra output from the change",
            tampered(&honest, |tx| {
                tx.outputs[last].value -= MIN_KAS_OUTPUT;
                tx.outputs
                    .push(TransactionOutput::new(MIN_KAS_OUTPUT, p2pk(&p.buyer)));
            }),
        ),
        (
            "the asset delivered elsewhere",
            tampered(&honest, |tx| {
                tx.outputs[0].script_public_key = token_spk(&a, &owner(&p.seller), AMOUNT_A)
            }),
        ),
    ];
    for (label, bad) in cases {
        assert_eq!(code(check(&bad)), "IPST_TERMS_MISMATCH", "{label}");
    }
}

#[test]
fn the_terms_check_refuses_tampered_vault_ipsts() {
    let p = parties();
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let budget = |b: u16| kaspa_consensus_core::mass::ComputeBudget(b).into();
    let settled = settle_of(&terms, &p).unwrap();
    let refunded = refund_of(&terms, &p, LegIndex::Cash, RefundSigner::Counterparty, true).unwrap();
    let funded_asset = fund_kcc20_of(&terms, LegIndex::Asset, &p).unwrap();
    let fund_kas_terms = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    let funded_kas = fund_kas(
        &fund_kas_terms,
        &fundable(&fund_kas_terms, LegIndex::Cash),
        &fee_payment(&p),
        NOW,
    )
    .unwrap();
    for ipst in [&settled, &refunded, &funded_asset, &funded_kas] {
        assert!(check(ipst).is_ok());
    }
    let other_vault = vault(&terms, LegIndex::Cash).script_public_key();
    let cases: Vec<(&str, Ipst)> = vec![
        (
            "settle: a vault budget lowered",
            tampered(&settled, |tx| tx.inputs[0].compute_commit = budget(1)),
        ),
        (
            "settle: sequence MAX on the vault inputs",
            tampered(&settled, |tx| {
                tx.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
                tx.inputs[1].sequence = MAX_TX_IN_SEQUENCE_NUM;
            }),
        ),
        (
            "settle: lock time raised past expiry",
            tampered(&settled, |tx| tx.lock_time = EXPIRY + 10),
        ),
        (
            "refund: the token's carrier skimmed",
            tampered(&refunded, |tx| {
                let last = tx.outputs.len() - 1;
                tx.outputs[1].value -= 1;
                tx.outputs[last].value += 1;
            }),
        ),
        (
            "fund: the escrowed token at the cash vault's address",
            tampered(&funded_asset, |tx| {
                tx.outputs[1].script_public_key = other_vault.clone()
            }),
        ),
        (
            "fund: the KAS deposit one sompi short",
            tampered(&funded_kas, |tx| {
                tx.outputs[0].value -= 1;
                tx.outputs[1].value += 1;
            }),
        ),
        (
            "not a layout any builder makes",
            tampered(&funded_kas, |tx| tx.outputs.swap(0, 1)),
        ),
    ];
    for (label, bad) in cases {
        assert_eq!(code(check(&bad)), "IPST_TERMS_MISMATCH", "{label}");
    }
}

#[test]
fn the_terms_check_keeps_the_builders_codes() {
    let p = parties();
    let (a, c) = (asset_template(), cash_template());
    let terms = validated(Mode::vault(true, Cash::Kcc20, FundingMode::Earmarked), &p);
    let settled = settle_of(&terms, &p).unwrap();
    assert!(settled.verify_against_terms(&a, Some(&c), NOW).is_ok());
    // Signing a settle the trade can no longer make by expiry.
    assert_eq!(
        code(settled.verify_against_terms(&a, Some(&c), EXPIRY)),
        "TX_EXPIRED"
    );
    // The wrong template for a leg, or none for KCC-20 cash.
    assert_eq!(
        code(settled.verify_against_terms(&c, Some(&c), NOW)),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(
        code(settled.verify_against_terms(&a, None, NOW)),
        "TX_TOKEN_TEMPLATE"
    );
    // A refund is checked at any DAA score.
    let refunded = refund_of(&terms, &p, LegIndex::Asset, RefundSigner::Depositor, true).unwrap();
    assert!(refunded
        .verify_against_terms(&a, Some(&c), EXPIRY + 1)
        .is_ok());
    // A Direct document whose buyer input does not hold exactly the cash amount: the builder
    // refuses those inputs, and the check says why.
    let direct_terms = validated(Mode::direct(Cash::Kas), &p);
    let honest = direct_of(&direct_terms, &p).unwrap();
    assert!(check(&honest).is_ok());
    let short = tampered_with(&honest, |tx, entries| {
        entries[1].amount += 1;
        let last = tx.outputs.len() - 1;
        tx.outputs[last].value += 1;
    });
    assert_eq!(code(check(&short)), "TX_LEG_AMOUNT");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex(bytes)
}

// =============================================================================================
// Codes
// =============================================================================================

#[test]
fn tx_error_codes_are_frozen() {
    assert_eq!(
        TX_ERROR_CODES,
        [
            "TX_WRONG_MODE",
            "TX_VAULT_MISMATCH",
            "TX_EXPIRED",
            "TX_NOT_AT_VAULT",
            "TX_ESCROW_MISMATCH",
            "TX_LEG_AMOUNT",
            "TX_TOKEN_TEMPLATE",
            "TX_TOKEN_INPUT",
            "TX_KAS_INPUT",
            "TX_DUPLICATE_INPUT",
            "TX_INSUFFICIENT_FUNDS",
            "TX_BELOW_MIN_KAS",
            "TX_MASS",
            "TX_FEE_TOO_LOW",
            "TX_NONSTANDARD_CHANGE",
            "TX_REFUND_SIGNER",
            "TX_SIGNATURE",
            "TX_SIGNATURE_SLOT",
            "TX_ENCODING",
            "IPST_MALFORMED",
            "IPST_UNSUPPORTED_VERSION",
            "IPST_SIGHASH_MISMATCH",
            "IPST_CONFLICT",
            "TX_UTXO_VALUE",
            "IPST_TERMS_MISMATCH",
            "TX_TOO_MANY_INPUTS",
        ]
    );
    let every = [
        TxError::WrongMode { reason: "" },
        TxError::VaultMismatch,
        TxError::Expired {
            current_daa: 0,
            expiry_daa: 0,
        },
        TxError::NotAtVault { input: "" },
        TxError::EscrowMismatch { input: "" },
        TxError::LegAmount {
            input: "",
            expected: 0,
            found: 0,
        },
        TxError::TokenTemplate { reason: "".into() },
        TxError::TokenInput {
            index: 0,
            reason: "",
        },
        TxError::KasInput {
            index: 0,
            reason: "",
        },
        TxError::DuplicateInput { index: 0 },
        TxError::InsufficientFunds {
            available: 0,
            needed: 0,
        },
        TxError::BelowMinKas {
            output: 0,
            value: 0,
            minimum: 0,
        },
        TxError::Mass {
            dimension: "",
            mass: 0,
            cap: 0,
        },
        TxError::FeeTooLow { fee: 0, minimum: 0 },
        TxError::NonstandardChange,
        TxError::RefundSigner { reason: "" },
        TxError::Signature {
            input: None,
            reason: "".into(),
        },
        TxError::SignatureSlot {
            input: 0,
            reason: "",
        },
        TxError::Encoding { reason: "".into() },
        TxError::IpstMalformed { reason: "".into() },
        TxError::IpstUnsupportedVersion { version: 0 },
        TxError::IpstSighashMismatch { input: 0 },
        TxError::IpstConflict { reason: "" },
        TxError::UtxoValue {
            input: None,
            value: 0,
        },
        TxError::IpstTermsMismatch { reason: "" },
        TxError::TooManyInputs { inputs: 0, max: 0 },
    ];
    let codes: Vec<&str> = every.iter().map(|e| e.code()).collect();
    assert_eq!(codes, TX_ERROR_CODES);
    for e in &every {
        assert!(e.to_string().starts_with(e.code()));
    }
    // Terms and template refusals keep their own codes.
    assert_eq!(
        TxError::from(crate::terms::TermsError::EarliestZero).code(),
        "TERMS_EARLIEST_ZERO"
    );
    assert_eq!(
        TxError::from(crate::template::TemplateError::NotImpulseVault).code(),
        "TEMPLATE_NOT_IMPULSE_VAULT"
    );
    // No code is shared with the terms or template catalogues.
    for c in TX_ERROR_CODES {
        assert!(!crate::terms::TERMS_ERROR_CODES.contains(&c));
        assert!(!crate::template::TEMPLATE_ERROR_CODES.contains(&c));
    }
}

#[test]
fn network_parameters_follow_the_terms() {
    // The masses come from the terms' network: mainnet or testnet parameters, told apart by
    // their network ID. The two sets price mass identically at a41a333, so the masses of the
    // same settle agree.
    use super::rules::params;
    use kaspa_consensus_core::config::params::{MAINNET_PARAMS, TESTNET_PARAMS};
    assert_eq!(params(Network::Mainnet).net, MAINNET_PARAMS.net);
    assert_eq!(params(Network::Testnet).net, TESTNET_PARAMS.net);
    assert_ne!(MAINNET_PARAMS.net, TESTNET_PARAMS.net);
    let p = parties();
    let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    t.network = Network::Testnet;
    let testnet = t.validate_structure().unwrap();
    let mainnet = validated(Mode::vault(true, Cash::Kas, FundingMode::Earmarked), &p);
    assert_eq!(
        settle_of(&testnet, &p).unwrap().masses(),
        settle_of(&mainnet, &p).unwrap().masses()
    );
}
