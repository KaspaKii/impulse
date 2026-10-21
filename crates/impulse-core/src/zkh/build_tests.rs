// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v4 builders (spec/V3-ZK.md 22.5, 22.6, 22.8) on the fixture worlds of the v1 builders: every
//! mode plans, reads back, passes the terms check and the native statement; every refusal has its
//! code. Keys: none. Every party is a label-derived x-only key for which nobody holds a private key
//! (rule 1, docs/ENGINEERING-RULES.md), so nothing here signs; the signed path (finalize in the pinned engine, with
//! a real receipt) runs in tests/engine/v4_builders_live.rs under the owner's exception for engine
//! tests.

use super::{
    check_masses, check_statement, existing_vault, fund_kas, fund_kcc20, hex, refund, settle,
    witnesses, IpstV4, ProofV4, ValidatedTermsV4, VaultV4, ZkhError, MAX_INPUTS_V4, PROOF_LEN,
    V4_COMPUTE_MASS_CAP, V4_STORAGE_MASS_CAP, V4_TRANSIENT_MASS_CAP,
};
use crate::template::LegIndex;
use crate::terms::{FundingMode, SettlementMode, Terms};
use crate::tx::testkit::*;
use crate::tx::{
    FeePayment, IpstKind, Kcc20Deposit, Kcc20State, Masses, RefundEscrow, RefundSigner, SettleCash,
    SettleLegs,
};

const BLIND: [u8; 32] = [0xB7; 32];

fn terms_for(mode: Mode) -> ValidatedTermsV4 {
    let p = parties();
    ValidatedTermsV4::from_draft(&terms(mode, &p), BLIND).expect("fixture terms v4")
}

fn vault_of(t: &ValidatedTermsV4, leg: LegIndex) -> VaultV4 {
    existing_vault(t, leg).expect("the leg has a vault")
}

struct Funded4 {
    legs: Funded,
}

/// The funded vault UTXOs of a trade, as the v4 fund builders make them.
fn funded4(t: &ValidatedTermsV4) -> Funded4 {
    let fields = t.fields();
    let asset = vault_of(t, LegIndex::Asset);
    let escrow = |vault: &VaultV4, amount: u64, template: &Kcc20Template| {
        let state = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::ScriptHash,
                identifier: vault.script_hash(),
            },
            amount,
        );
        template.script_public_key(&state).unwrap()
    };
    let mut f = Funded {
        asset_authorizer: utxo(
            "asset-authorizer",
            AUTHORIZER,
            asset.script_public_key(),
            None,
        ),
        asset_escrow: utxo(
            "asset-escrow",
            CARRIER,
            escrow(&asset, fields.asset_leg.amount, &asset_template()),
            Some(ASSET_COV),
        ),
        cash_vault: None,
        cash_authorizer: None,
        cash_escrow: None,
    };
    match fields.cash_leg.kind {
        LegKind::Kas => {
            let cash = vault_of(t, LegIndex::Cash);
            f.cash_vault = Some(utxo(
                "cash-vault",
                fields.cash_leg.amount,
                cash.script_public_key(),
                None,
            ));
        }
        LegKind::Kcc20(_) => {
            let cash = vault_of(t, LegIndex::Cash);
            f.cash_authorizer = Some(utxo(
                "cash-authorizer",
                AUTHORIZER,
                cash.script_public_key(),
                None,
            ));
            f.cash_escrow = Some(utxo(
                "cash-escrow",
                CARRIER,
                escrow(&cash, fields.cash_leg.amount, &cash_template()),
                Some(CASH_COV),
            ));
        }
        LegKind::External => {}
    }
    Funded4 { legs: f }
}

use crate::terms::{IdentifierType, Kcc20Owner, LegKind};
use crate::tx::Kcc20Template;

/// A fee above the relay minimum of every shape (a settle's is about 0.33 KAS: two verifications).
fn fee() -> FeePayment {
    FeePayment {
        fee: 60_000_000,
        ..fee_payment(&parties())
    }
}

fn plan(t: &ValidatedTermsV4, proofs: &[Option<ProofV4>; 2]) -> Result<IpstV4, ZkhError> {
    let f = funded4(t);
    let (a, c) = (asset_template(), cash_template());
    settle(t, &settle_legs(&f.legs, &a, &c), proofs, &fee(), NOW)
}

fn proof(byte: u8) -> ProofV4 {
    ProofV4::parse(&[byte; PROOF_LEN]).unwrap()
}

fn code<T>(r: Result<T, ZkhError>) -> &'static str {
    r.map(|_| ()).expect_err("refused").code()
}

fn modes() -> Vec<Mode> {
    let mut out = vec![];
    for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
        for funding in [FundingMode::Revocable, FundingMode::Earmarked] {
            out.push(Mode::vault(true, cash, funding));
        }
    }
    out
}

#[test]
fn proof_bytes_are_128_and_not_zero() {
    assert!(ProofV4::parse(&[1; PROOF_LEN]).is_ok());
    assert_eq!(code(ProofV4::parse(&[1; 127])), "ZK_H_PROOF_MALFORMED");
    assert_eq!(code(ProofV4::parse(&[1; 129])), "ZK_H_PROOF_MALFORMED");
    assert_eq!(code(ProofV4::parse(&[])), "ZK_H_PROOF_MALFORMED");
    assert_eq!(
        code(ProofV4::parse(&[0; PROOF_LEN])),
        "ZK_H_PROOF_MALFORMED"
    );
}

#[test]
fn terms_v4_project_to_v1_and_back() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    assert_eq!(t.canonical()[0], 4);
    assert_eq!(t.v1_fields().canonical()[0], 1);
    assert_eq!(t.core().encode(), t.canonical());
    assert_eq!(
        ValidatedTermsV4::decode(t.canonical()).unwrap(),
        t,
        "decode is the inverse of encode"
    );
    // The blind is not part of the v1 projection, and changes the commitments.
    let other = ValidatedTermsV4::from_draft(
        &terms(
            Mode::vault(true, Cash::Kas, FundingMode::Revocable),
            &parties(),
        ),
        [0xB8; 32],
    )
    .unwrap();
    assert_eq!(t.v1_fields().canonical(), other.v1_fields().canonical());
    assert_ne!(t.commit(0), other.commit(0));
    assert_ne!(t.commit(0), t.commit(1));
}

#[test]
fn terms_v4_refusals_have_their_codes() {
    let p = parties();
    let mut direct = terms(Mode::direct(Cash::Kas), &p);
    direct.authority_key = Some(p.authority);
    assert_eq!(
        code(ValidatedTermsV4::from_draft(&direct, BLIND)),
        "ZK_H_TERMS_DIRECT"
    );
    let no_authority = terms(Mode::vault(false, Cash::Kas, FundingMode::Revocable), &p);
    assert_eq!(
        code(ValidatedTermsV4::from_draft(&no_authority, BLIND)),
        "ZK_H_AUTHORITY_REQUIRED"
    );
    let ok = terms(Mode::vault(true, Cash::Kas, FundingMode::Revocable), &p);
    assert_eq!(
        code(ValidatedTermsV4::from_draft(&ok, [0; 32])),
        "ZK_H_BLIND_INVALID"
    );
    let mut same = ok.clone();
    same.buyer_key = same.seller_key;
    assert_eq!(
        code(ValidatedTermsV4::from_draft(&same, BLIND)),
        "TERMS_PARTIES_NOT_DISTINCT"
    );
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let mut bytes = t.canonical().to_vec();
    bytes[0] = 3;
    assert_eq!(code(ValidatedTermsV4::decode(&bytes)), "ZK_H_TERMS_VERSION");
    let mut bytes = t.canonical().to_vec();
    bytes.push(0);
    assert!(ValidatedTermsV4::decode(&bytes).is_err());
}

#[test]
fn every_mode_plans_a_settle_that_passes_every_check() {
    for mode in modes() {
        let t = terms_for(mode);
        let ipst = plan(&t, &[None, None]).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        let vaults = if mode.cash == Cash::External { 1 } else { 2 };
        let proofs = ipst.proofs().unwrap();
        assert_eq!(proofs.len(), vaults, "{mode:?}");
        assert!(
            proofs.iter().all(|(_, p)| p.is_none()),
            "a plan has no proof"
        );
        assert!(!ipst.has_all_proofs().unwrap());
        assert_eq!(witnesses(&ipst).unwrap().len(), vaults);
        check_statement(&ipst).unwrap();
        // The asset authorizer is input 0 and the cash authorizer input 1.
        assert_eq!(
            ipst.entries()[0].script_public_key,
            vault_of(&t, LegIndex::Asset).script_public_key()
        );
        if vaults == 2 {
            assert_eq!(
                ipst.entries()[1].script_public_key,
                vault_of(&t, LegIndex::Cash).script_public_key()
            );
        }
        // A settle sets the lock time the guest reads.
        assert_eq!(ipst.transaction().lock_time, EARLIEST);
        // Read back, and the terms check rebuilds the same transaction.
        let back = IpstV4::from_json(&ipst.to_json()).unwrap();
        assert_eq!(back, ipst);
        let (a, c) = (asset_template(), cash_template());
        let checked = back.verify_against_terms(&a, Some(&c), NOW).unwrap();
        assert_eq!(checked.kind, IpstKind::Settle, "{mode:?}");
        // Finalize refuses a plan (no proof), before anything about signatures.
        assert_eq!(code(ipst.finalize()), "ZK_H_PROOF_MALFORMED");
    }
}

#[test]
fn proofs_land_in_their_vault_inputs_and_in_the_terms_check() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let ipst = plan(&t, &[Some(proof(1)), Some(proof(2))]).unwrap();
    let proofs = ipst.proofs().unwrap();
    assert_eq!(proofs, vec![(0, Some(proof(1))), (1, Some(proof(2)))]);
    assert!(ipst.has_all_proofs().unwrap());
    let (a, c) = (asset_template(), cash_template());
    ipst.verify_against_terms(&a, Some(&c), NOW).unwrap();
    // The signatures are missing: finalize says so once the proofs are in.
    assert_eq!(code(ipst.finalize()), "TX_SIGNATURE_SLOT");
    // One proof only: the other input is still a plan.
    let half = plan(&t, &[Some(proof(1)), None]).unwrap();
    assert_eq!(half.proofs().unwrap()[1].1, None);
    assert!(!half.has_all_proofs().unwrap());
    // Two documents that differ in a proof are two documents.
    assert_ne!(half.to_json(), ipst.to_json());
}

#[test]
fn settle_refusals() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let f = funded4(&t);
    let (a, c) = (asset_template(), cash_template());
    let legs = settle_legs(&f.legs, &a, &c);
    let go = |legs: &SettleLegs<'_>, daa: u64| settle(&t, legs, &[None, None], &fee(), daa);
    // Expired.
    assert_eq!(code(go(&legs, 2_000_000)), "TX_EXPIRED");
    // The wrong cash kind.
    let mut wrong = legs.clone();
    wrong.cash = SettleCash::External;
    assert_eq!(code(go(&wrong, NOW)), "TX_WRONG_MODE");
    // An authorizer that is not at the asset vault.
    let mut elsewhere = legs.clone();
    elsewhere.asset_authorizer = utxo("x", AUTHORIZER, p2pk_spk(), None);
    assert_eq!(code(go(&elsewhere, NOW)), "TX_NOT_AT_VAULT");
    // The cash vault UTXO must hold exactly the cash amount.
    let mut over = legs.clone();
    if let SettleCash::Kas { vault } = &mut over.cash {
        vault.entry.amount += 1;
    }
    assert_eq!(code(go(&over, NOW)), "TX_LEG_AMOUNT");
    // Exact amounts: an escrow of the wrong amount is not accepted either.
    let mut less = legs.clone();
    let vault = vault_of(&t, LegIndex::Asset);
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        t.fields().asset_leg.amount - 1,
    );
    less.asset_escrow = utxo(
        "asset-escrow",
        CARRIER,
        a.script_public_key(&state).unwrap(),
        Some(ASSET_COV),
    );
    assert!(go(&less, NOW).is_err());
    // No fee input.
    let no_fee = FeePayment {
        inputs: vec![],
        ..fee()
    };
    assert_eq!(
        code(settle(&t, &legs, &[None, None], &no_fee, NOW)),
        "TX_KAS_INPUT"
    );
    // A fee below the relay minimum.
    let cheap = FeePayment { fee: 1, ..fee() };
    assert_eq!(
        code(settle(&t, &legs, &[None, None], &cheap, NOW)),
        "TX_FEE_TOO_LOW"
    );
    assert!(settle(&t, &legs, &[None, None], &cheap, NOW)
        .unwrap_err()
        .min_fee()
        .is_some());
    // Funds that do not cover the fee.
    let poor = FeePayment {
        inputs: vec![utxo("fee", 1_000, p2pk_spk(), None)],
        ..fee()
    };
    assert_eq!(
        code(settle(&t, &legs, &[None, None], &poor, NOW)),
        "TX_INSUFFICIENT_FUNDS"
    );
}

fn p2pk_spk() -> kaspa_consensus_core::tx::ScriptPublicKey {
    crate::tx::p2pk(&parties().payer)
}

#[test]
fn the_statement_fails_on_a_view_the_guest_would_refuse() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let ipst = plan(&t, &[None, None]).unwrap();
    // The lock time one below earliest_daa breaks [S3] and nothing else.
    let mut tx = ipst.transaction().clone();
    tx.lock_time = EARLIEST - 1;
    let early = IpstV4::from_parts(
        t.clone(),
        tx,
        ipst.entries().to_vec(),
        ipst.slots().to_vec(),
    );
    let e = check_statement(&early).unwrap_err();
    assert_eq!(e.code(), "ZK_H_STATEMENT_FALSE");
    assert!(e.reason().contains("S3"), "{e}");
    // A KAS proceeds output one sompi off breaks [S5].
    let mut tx = ipst.transaction().clone();
    tx.outputs[1].value += 1;
    let off = IpstV4::from_parts(
        t.clone(),
        tx,
        ipst.entries().to_vec(),
        ipst.slots().to_vec(),
    );
    assert!(check_statement(&off).unwrap_err().reason().contains("S5"));
    // A transaction that spends no v4 vault.
    let mut tx = ipst.transaction().clone();
    let _ = &mut tx;
    let mut entries = ipst.entries().to_vec();
    entries[0].script_public_key = p2pk_spk();
    let none = IpstV4::from_parts(t, tx, entries, ipst.slots().to_vec());
    assert!(none.proofs().is_ok());
}

#[test]
fn refunds_plan_for_every_signer_and_leg() {
    for mode in modes() {
        let t = terms_for(mode);
        let f = funded4(&t);
        let (a, c) = (asset_template(), cash_template());
        let fields = t.fields();
        for (leg, template, escrow_utxo, vault_utxo, kind) in [
            (
                LegIndex::Asset,
                &a,
                Some(&f.legs.asset_escrow),
                &f.legs.asset_authorizer,
                fields.asset_leg.kind,
            ),
            (
                LegIndex::Cash,
                &c,
                f.legs.cash_escrow.as_ref(),
                f.legs
                    .cash_vault
                    .as_ref()
                    .or(f.legs.cash_authorizer.as_ref())
                    .unwrap_or(&f.legs.asset_authorizer),
                fields.cash_leg.kind,
            ),
        ] {
            if kind == LegKind::External {
                assert_eq!(
                    code(refund(
                        &t,
                        leg,
                        RefundSigner::Depositor,
                        vault_utxo,
                        None,
                        None,
                        &fee()
                    )),
                    "TEMPLATE_NO_VAULT"
                );
                continue;
            }
            let amount = match leg {
                LegIndex::Asset => fields.asset_leg.amount,
                LegIndex::Cash => fields.cash_leg.amount,
            };
            for signer in [
                RefundSigner::Depositor,
                RefundSigner::Counterparty,
                RefundSigner::Authority,
            ] {
                let with_token = matches!(kind, LegKind::Kcc20(_));
                let escrow = with_token.then(|| RefundEscrow {
                    utxo: escrow_utxo.unwrap().clone(),
                    amount,
                    is_minter: false,
                    template,
                });
                let ipst = refund(&t, leg, signer, vault_utxo, escrow.as_ref(), None, &fee())
                    .unwrap_or_else(|e| panic!("{mode:?} {leg:?} {signer:?}: {e}"));
                assert_eq!(witnesses(&ipst).unwrap().len(), 1);
                assert_eq!(ipst.proofs().unwrap(), vec![(0, None)]);
                let expect_lock = if mode.funding == FundingMode::Earmarked
                    && signer == RefundSigner::Depositor
                {
                    EXPIRY
                } else {
                    0
                };
                assert_eq!(ipst.transaction().lock_time, expect_lock);
                let back = IpstV4::from_json(&ipst.to_json()).unwrap();
                let checked = back.verify_against_terms(&a, Some(&c), NOW).unwrap();
                assert_eq!(
                    checked.kind,
                    IpstKind::Refund {
                        leg,
                        signer,
                        with_token
                    },
                    "{mode:?}"
                );
            }
            // The depositor may refund the authorizer alone; nobody else may.
            if matches!(kind, LegKind::Kcc20(_)) {
                assert!(refund(
                    &t,
                    leg,
                    RefundSigner::Depositor,
                    vault_utxo,
                    None,
                    None,
                    &fee()
                )
                .is_ok());
                assert_eq!(
                    code(refund(
                        &t,
                        leg,
                        RefundSigner::Counterparty,
                        vault_utxo,
                        None,
                        None,
                        &fee()
                    )),
                    "TX_REFUND_SIGNER"
                );
            }
        }
    }
}

#[test]
fn a_refund_carries_its_proof() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let f = funded4(&t);
    let cash = f.legs.cash_vault.as_ref().unwrap();
    let ipst = refund(
        &t,
        LegIndex::Cash,
        RefundSigner::Depositor,
        cash,
        None,
        Some(&proof(9)),
        &fee(),
    )
    .unwrap();
    assert_eq!(ipst.proofs().unwrap(), vec![(0, Some(proof(9)))]);
    let (a, c) = (asset_template(), cash_template());
    ipst.verify_against_terms(&a, Some(&c), NOW).unwrap();
}

#[test]
fn funding_plans_pass_the_terms_check() {
    let p = parties();
    for mode in modes() {
        let t = terms_for(mode);
        let (a, c) = (asset_template(), cash_template());
        let fields = t.fields();
        // KAS cash.
        if mode.cash == Cash::Kas {
            let vault = vault_of(&t, LegIndex::Cash);
            let ipst = fund_kas(&t, &vault, LegIndex::Cash, &fee(), NOW).unwrap();
            assert_eq!(ipst.transaction().outputs[0].value, fields.cash_leg.amount);
            let checked = IpstV4::from_json(&ipst.to_json())
                .unwrap()
                .verify_against_terms(&a, Some(&c), NOW)
                .unwrap();
            assert_eq!(checked.kind, IpstKind::FundKas);
            // The asset vault is not a KAS leg.
            let asset = vault_of(&t, LegIndex::Asset);
            assert_eq!(
                code(fund_kas(&t, &asset, LegIndex::Asset, &fee(), NOW)),
                "TX_WRONG_MODE"
            );
            // A vault of other terms is refused.
            let other = ValidatedTermsV4::from_draft(&terms(mode, &parties()), [0xB8; 32]).unwrap();
            let theirs = vault_of(&other, LegIndex::Cash);
            assert_eq!(
                code(fund_kas(&t, &theirs, LegIndex::Cash, &fee(), NOW)),
                "TX_VAULT_MISMATCH"
            );
            assert_eq!(
                code(fund_kas(&t, &vault, LegIndex::Cash, &fee(), 2_000_000)),
                "TX_EXPIRED"
            );
        }
        // The asset leg, with change.
        let vault = vault_of(&t, LegIndex::Asset);
        let held = fields.asset_leg.amount + 7;
        let token = own_token("seller-asset", &a, ASSET_COV, &p.seller, held);
        let deposit = Kcc20Deposit {
            tokens: vec![token],
            carrier: CARRIER,
            authorizer: AUTHORIZER,
        };
        let ipst = fund_kcc20(&t, &vault, LegIndex::Asset, &a, &deposit, &fee(), NOW).unwrap();
        let checked = IpstV4::from_json(&ipst.to_json())
            .unwrap()
            .verify_against_terms(&a, Some(&c), NOW)
            .unwrap();
        assert_eq!(checked.kind, IpstKind::FundKcc20(LegIndex::Asset));
        // Too few tokens.
        let short = Kcc20Deposit {
            tokens: vec![own_token(
                "seller-asset",
                &a,
                ASSET_COV,
                &p.seller,
                fields.asset_leg.amount - 1,
            )],
            carrier: CARRIER,
            authorizer: AUTHORIZER,
        };
        assert_eq!(
            code(fund_kcc20(
                &t,
                &vault,
                LegIndex::Asset,
                &a,
                &short,
                &fee(),
                NOW
            )),
            "TX_TOKEN_INPUT"
        );
    }
}

#[test]
fn ipst_version_five_only() {
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let ipst = plan(&t, &[None, None]).unwrap();
    let text = ipst.to_json();
    assert!(text.contains("\"ipst\": 5"));
    assert_eq!(IpstV4::version_of(&text), Some(5));
    assert_eq!(IpstV4::version_of("not json"), None);
    // Another version is ZK_H_IPST_VERSION; a v1 reader refuses version 5.
    let v4 = text.replacen("\"ipst\": 5", "\"ipst\": 4", 1);
    assert_eq!(code(IpstV4::from_json(&v4)), "ZK_H_IPST_VERSION");
    let v1 = crate::tx::Ipst::from_json(&text).unwrap_err();
    assert_eq!(v1.code(), "IPST_UNSUPPORTED_VERSION");
    // A key twice is refused.
    let twice = text.replacen("{", "{\"ipst\": 5,", 1);
    assert!(IpstV4::from_json(&twice).is_err());
    // Terms that are not terms v4.
    let v1_terms = hex(t.v1_fields().canonical());
    let bad = text.replacen(&hex(t.canonical()), &v1_terms, 1);
    assert_eq!(code(IpstV4::from_json(&bad)), "ZK_H_TERMS_VERSION");
    // A document for other terms fails the terms check of the first.
    let other = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Earmarked));
    assert_ne!(other.canonical(), t.canonical());
}

#[test]
fn masses_over_a_cap_are_refused_by_name() {
    let ok = Masses {
        compute: V4_COMPUTE_MASS_CAP,
        transient: V4_TRANSIENT_MASS_CAP,
        storage: V4_STORAGE_MASS_CAP,
        fee_mass: 0,
    };
    assert!(check_masses(&ok).is_ok());
    for (dimension, bad) in [
        (
            "compute",
            Masses {
                compute: ok.compute + 1,
                ..ok
            },
        ),
        (
            "transient",
            Masses {
                transient: ok.transient + 1,
                ..ok
            },
        ),
        (
            "storage",
            Masses {
                storage: ok.storage + 1,
                ..ok
            },
        ),
    ] {
        let e = check_masses(&bad).unwrap_err();
        assert_eq!(e.code(), "ZK_TX_MASS");
        assert!(e.reason().contains(dimension), "{e}");
    }
}

#[test]
fn a_settle_of_every_mode_fits_the_caps() {
    // The builder refuses a settle over a cap, so a plan existing is the fit; this states it with
    // the masses of the signed size.
    for mode in modes() {
        let ipst = plan(&terms_for(mode), &[None, None]).unwrap();
        let m = ipst.masses();
        eprintln!("settle {:?} {:?}: {m:?}", mode.cash, mode.funding);
        assert!(m.compute <= V4_COMPUTE_MASS_CAP, "{mode:?}: {m:?}");
        assert!(m.transient <= V4_TRANSIENT_MASS_CAP, "{mode:?}: {m:?}");
        assert!(m.storage <= V4_STORAGE_MASS_CAP, "{mode:?}: {m:?}");
    }
}

#[test]
fn direct_terms_have_no_v4_vault() {
    let p = parties();
    let mut t = terms(Mode::vault(true, Cash::Kas, FundingMode::Revocable), &p);
    t.settlement_mode = SettlementMode::Direct;
    assert!(ValidatedTermsV4::from_draft(&t, BLIND).is_err());
    let _: Option<Terms> = None;
}

// =============================================================================================
// The committed receipts: tests/engine/fixtures/v4/
// =============================================================================================

/// One plan per committed receipt: the builders' own output for a fixed world (label-derived
/// public keys, the testkit values), so a drift in a builder, the guest's statement or the vault
/// changes a journal and the check below names it. Each entry is `(name, input index, plan)`.
fn fixture_plans() -> Vec<(&'static str, usize, IpstV4)> {
    let (a, c) = (asset_template(), cash_template());
    let mut out = Vec::new();
    for (tag, cash) in [
        ("kas", Cash::Kas),
        ("kcc20", Cash::Kcc20),
        ("external", Cash::External),
    ] {
        let t = terms_for(Mode::vault(true, cash, FundingMode::Revocable));
        let f = funded4(&t);
        let ipst = settle(
            &t,
            &settle_legs(&f.legs, &a, &c),
            &[None, None],
            &fee(),
            NOW,
        )
        .unwrap();
        let names: &[&'static str] = match tag {
            "kas" => &["settle-kas-asset", "settle-kas-cash"],
            "kcc20" => &["settle-kcc20-asset", "settle-kcc20-cash"],
            _ => &["settle-external-asset"],
        };
        for (i, name) in names.iter().enumerate() {
            out.push((*name, i, ipst.clone()));
        }
    }
    // Refunds: the asset leg with its token by the depositor (revocable), the KAS cash leg by the
    // counterparty, and the earmarked asset leg by the depositor (lock time at expiry).
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Revocable));
    let f = funded4(&t);
    let escrow = RefundEscrow {
        utxo: f.legs.asset_escrow.clone(),
        amount: t.fields().asset_leg.amount,
        is_minter: false,
        template: &a,
    };
    out.push((
        "refund-asset-depositor",
        0,
        refund(
            &t,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.legs.asset_authorizer,
            Some(&escrow),
            None,
            &fee(),
        )
        .unwrap(),
    ));
    out.push((
        "refund-kas-cash-counterparty",
        0,
        refund(
            &t,
            LegIndex::Cash,
            RefundSigner::Counterparty,
            f.legs.cash_vault.as_ref().unwrap(),
            None,
            None,
            &fee(),
        )
        .unwrap(),
    ));
    let t = terms_for(Mode::vault(true, Cash::Kas, FundingMode::Earmarked));
    let f = funded4(&t);
    let escrow = RefundEscrow {
        utxo: f.legs.asset_escrow.clone(),
        amount: t.fields().asset_leg.amount,
        is_minter: false,
        template: &a,
    };
    out.push((
        "refund-asset-depositor-earmarked",
        0,
        refund(
            &t,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.legs.asset_authorizer,
            Some(&escrow),
            None,
            &fee(),
        )
        .unwrap(),
    ));
    out
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v4")
}

/// Writes the witness of every fixture plan to the directory named by IMPULSE_V4_FIXTURE_WITNESS
/// (scripts/regen-fixtures-v4.sh proves them). Not a check: ignored.
#[test]
#[ignore = "generator for scripts/regen-fixtures-v4.sh"]
fn emit_fixture_witnesses() {
    let dir = std::path::PathBuf::from(
        std::env::var("IMPULSE_V4_FIXTURE_WITNESS").expect("IMPULSE_V4_FIXTURE_WITNESS"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    for (name, input, ipst) in fixture_plans() {
        let all = witnesses(&ipst).unwrap();
        let (_, _, w) = all.iter().find(|(i, _, _)| *i == input).unwrap();
        std::fs::write(dir.join(format!("{name}.witness.bin")), w.to_bytes()).unwrap();
    }
}

fn unhex_str(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn committed_receipts_are_the_journals_the_builders_make() {
    let image_id = super::check().unwrap().image_id();
    for (name, input, ipst) in fixture_plans() {
        let path = fixture_dir().join(format!("{name}.proof.json"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{}: {e}; run scripts/regen-fixtures-v4.sh", path.display())
        });
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let journal = unhex_str(v["journal"].as_str().unwrap());
        let all = witnesses(&ipst).unwrap();
        let (_, _, w) = all.iter().find(|(i, _, _)| *i == input).unwrap();
        assert_eq!(
            journal, w.journal,
            "{name}: the committed journal is not the one the builder makes; run scripts/regen-fixtures-v4.sh"
        );
        assert_eq!(
            unhex_str(v["image_id"].as_str().unwrap()),
            image_id,
            "{name}"
        );
        // The proof carries into the plan and reads back.
        let proof = ProofV4::parse(&unhex_str(v["proof"].as_str().unwrap())).unwrap();
        assert_eq!(
            v["journal_hash"].as_str().unwrap(),
            hex(&terms_core::hashes::sha256(&journal)),
            "{name}"
        );
        let _ = proof;
    }
}

// =============================================================================================
// Vectors: tests/vectors/journal_v4/ and tests/vectors/ipst_v5/
// =============================================================================================

/// The journal vector of one vault input of a fixture plan: every field of J by name, the bytes,
/// their hash, and the terms the commitment is of, so scripts/vectors-v4.py can rebuild J from
/// spec/V3-ZK.md 22.3 alone and check the commitment and the vault against the terms.
fn journal_vector(name: &str, input: usize, ipst: &IpstV4) -> String {
    let all = witnesses(ipst).unwrap();
    let (_, leg, w) = all.iter().find(|(i, _, _)| *i == input).unwrap();
    let j = terms_core::Journal::parse(&w.journal).unwrap();
    let items = |v: &[terms_core::Item]| {
        v.iter()
            .map(|it| {
                format!(
                    "{{\"value\": {}, \"spk_hash\": \"{}\", \"cov\": \"{}\"}}",
                    it.value,
                    hex(&it.spk_hash),
                    hex(&it.cov)
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{{\n  \"name\": \"{name}\",\n  \"canonical_terms\": \"{}\",\n  \"leg\": {leg},\n  \"mode\": {},\n  \"vault_spk\": \"{}\",\n  \"commit\": \"{}\",\n  \"authority\": \"{}\",\n  \"journal_leg\": {},\n  \"input_index\": {},\n  \"lock_time\": {},\n  \"signer\": \"{}\",\n  \"cov_a\": \"{}\",\n  \"cov_c\": \"{}\",\n  \"count_a\": {},\n  \"count_c\": {},\n  \"inputs\": [{}],\n  \"outputs\": [{}],\n  \"journal\": \"{}\",\n  \"journal_hash\": \"{}\"\n}}\n",
        hex(ipst.terms().canonical()),
        j.mode as u8,
        hex(&j.vault_spk),
        hex(&j.commit),
        hex(&j.authority),
        j.leg,
        j.input_index,
        j.locktime,
        hex(&j.signer),
        hex(&j.cov_a),
        hex(&j.cov_c),
        j.count_a,
        j.count_c,
        items(&j.inputs),
        items(&j.outputs),
        hex(&w.journal),
        hex(&terms_core::hashes::sha256(&w.journal)),
    )
}

/// `(directory, file name, content)` of the vectors the builders define.
pub(super) fn vector_files() -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (name, input, ipst) in fixture_plans() {
        out.push((
            "journal_v4",
            format!("{name}.json"),
            journal_vector(name, input, &ipst),
        ));
        // One IPST per plan (a settle plan serves its two vault inputs).
        if seen.insert(ipst.to_json()) {
            let plan = name.rsplit_once('-').map_or(name, |(head, _)| head);
            let plan = if name.starts_with("refund") {
                name
            } else {
                plan
            };
            out.push(("ipst_v5", format!("{plan}.json"), ipst.to_json()));
        }
    }
    out
}

/// The masses of the plans the builders make, at the budgets they commit and the values of the
/// fixture world (the testkit minimums). Written to the file named by IMPULSE_V4_MASS_OUT when set
/// (scripts/measure-v4-units.sh appends it to docs/measurements/v4-zk-units.txt); always asserts
/// the caps.
#[test]
fn builder_plan_masses_are_under_the_caps() {
    let mut lines = Vec::new();
    for (name, input, ipst) in fixture_plans() {
        if input != 0 {
            continue;
        }
        let m = ipst.masses();
        let budgets: Vec<u64> = ipst
            .transaction()
            .inputs
            .iter()
            .map(|i| i.compute_commit.allowed_script_units().0 / 10_000)
            .collect();
        lines.push(format!(
            "| {name} | inputs {} | vault input budgets {:?} | compute {} | transient {} | storage {} | fee mass {} | fee {} sompi at the relay minimum |",
            ipst.transaction().inputs.len(),
            &budgets[..budgets.len().min(2)],
            m.compute,
            m.transient,
            m.storage,
            m.fee_mass,
            crate::tx::min_relay_fee(m.fee_mass)
        ));
        assert!(m.compute <= V4_COMPUTE_MASS_CAP, "{name}: {m:?}");
        assert!(m.transient <= V4_TRANSIENT_MASS_CAP, "{name}: {m:?}");
        assert!(m.storage <= V4_STORAGE_MASS_CAP, "{name}: {m:?}");
    }
    if let Some(path) = std::env::var_os("IMPULSE_V4_MASS_OUT") {
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }
}

// =============================================================================================
// The input bound (spec/V3-ZK.md 22.15)
// =============================================================================================

/// `n` fee inputs of the payer, each large enough to pay the fee alone.
fn fees(n: usize) -> FeePayment {
    let p = parties();
    FeePayment {
        inputs: (0..n)
            .map(|i| {
                utxo(
                    &format!("fee-{i}"),
                    FEE_INPUT,
                    crate::tx::p2pk(&p.payer),
                    None,
                )
            })
            .collect(),
        ..fee()
    }
}

#[test]
fn a_settle_or_refund_takes_at_most_eight_inputs() {
    assert_eq!(MAX_INPUTS_V4, 8);
    let (a, c) = (asset_template(), cash_template());
    for (cash, trade) in [(Cash::Kcc20, 4), (Cash::Kas, 3), (Cash::External, 2)] {
        let t = terms_for(Mode::vault(true, cash, FundingMode::Revocable));
        let f = funded4(&t);
        let legs = settle_legs(&f.legs, &a, &c);
        let room = MAX_INPUTS_V4 - trade;
        let ipst = settle(&t, &legs, &[None, None], &fees(room), NOW)
            .unwrap_or_else(|e| panic!("{cash:?}: {room} fee inputs: {e}"));
        assert_eq!(ipst.transaction().inputs.len(), MAX_INPUTS_V4);
        assert_eq!(
            code(settle(&t, &legs, &[None, None], &fees(room + 1), NOW)),
            "ZK_H_SHAPE",
            "{cash:?}: one fee input more"
        );
    }
    let t = terms_for(Mode::vault(true, Cash::Kcc20, FundingMode::Revocable));
    let f = funded4(&t);
    let escrow = RefundEscrow {
        utxo: f.legs.asset_escrow.clone(),
        amount: t.fields().asset_leg.amount,
        is_minter: false,
        template: &a,
    };
    let go = |n: usize| {
        refund(
            &t,
            LegIndex::Asset,
            RefundSigner::Depositor,
            &f.legs.asset_authorizer,
            Some(&escrow),
            None,
            &fees(n),
        )
    };
    assert!(go(6).is_ok());
    assert_eq!(code(go(7)), "ZK_H_SHAPE");
}
