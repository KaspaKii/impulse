// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The 24 Solana DvP error codes against Impulse. Tag format: parity.rs. ERR-01 (DvpExpired)
//! is answered by the I5 settle builder and the node's lock-time rule.
//!
//! Create-time errors map to the terms checks (spec/ENCODING.md): the structure checks every
//! `ValidatedTerms` has passed, and the creation checks `Vault::instantiate_for_creation` runs
//! before any funding address exists. Those checks run in the terms library, for whoever runs
//! it; the contract does not repeat them, so each such row also runs terms that fail the check
//! through the engine and pins what the contract does with them. Settle-time and unwind-time
//! errors map to the contract's requires (spec/ERRORS.md, "On-chain refusals"), run in the real
//! engine.

use crate::common::*;
use crate::harness::*;
use crate::trade::{Trade, EARLIEST, EXPIRY, NOW};
use crate::verify_world::{artifact_json, frozen_kcc20, naming, terms as real_terms_of};
use impulse_core::template::{decode, LegIndex, Vault};
use impulse_core::terms::{
    CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner, LegKind, Terms,
    DEFAULT_MAX_EXPIRY_HORIZON_DAA,
};
use impulse_core::verify::{token_warnings, TokenEvidence, TokenWarningKind};
use kaspa_consensus_core::tx::CovenantBinding;
use kaspa_txscript_errors::TxScriptError;
use std::collections::BTreeSet;

/// The compiled ImpulseVault artifact, as committed.
fn vault_artifact() -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.json"))
            .expect("artifact"),
    )
    .expect("artifact parses")
}

/// A key that is not a valid x-only point (x above the field prime).
const OFF_CURVE: [u8; 32] = [0xff; 32];

fn script_hash_owner(id: u8) -> Destination {
    Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: [id; 32],
    })
}

/// parity: ERR-00 equivalent
/// A refund must be signed by the leg's depositor, its counterparty or the authority; a stranger's signature is refused ([R1]).
#[test]
fn err00_signer_not_party() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    for leg in [ASSET_LEG, CASH_LEG] {
        let control = w.refund(leg, depositor(leg));
        let mut faulty = control.clone();
        faulty.inputs[0] = In::refund(
            w.vault(leg),
            w.xonly(Role::Stranger),
            Role::Stranger,
            control.inputs[0].value,
        );
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("leg {leg}: stranger refunds"),
        );
    }
}

/// parity: ERR-01 divergent
/// Solana refuses a settle after the expiry second on chain, for every caller; Impulse's refusal is the settle builder's (TX_EXPIRED once the caller's DAA score reaches expiry_daa, with or without an earliest_daa, or when earliest_daa equals it), because the contract ([S3]) and the node's lock-time rule bound a settle only from below, and with no earliest_daa not at all, so a settle built one score earlier is accepted by the engine and by the node at a block long after expiry_daa.
#[test]
fn err01_dvp_expired() {
    let trade = Trade::new(FundingMode::Revocable, Some(EARLIEST), EXPIRY);
    let h = trade.holdings();
    // The control builds one score before expiry_daa; the builder refuses from expiry_daa on.
    let control = trade
        .settle(&h, EXPIRY - 1)
        .expect("a settle builds one score before expiry_daa");
    for now in [EXPIRY, EXPIRY + 1, EXPIRY + 1_000_000] {
        let refused = trade.settle(&h, now).expect_err("expired");
        assert_eq!(refused.code(), "TX_EXPIRED", "built at DAA score {now}");
    }

    // earliest_daa equal to expiry_daa passes the structure checks, but such a settle enters a
    // block only from expiry_daa + 1, so the builder refuses it at any score; one below builds.
    let edge = Trade::new(FundingMode::Revocable, Some(EXPIRY), EXPIRY);
    let refused = edge
        .settle(&edge.holdings_by_hand(), NOW)
        .expect_err("expired");
    assert_eq!(
        refused.code(),
        "TX_EXPIRED",
        "earliest_daa equals expiry_daa"
    );
    let below = Trade::new(FundingMode::Revocable, Some(EXPIRY - 1), EXPIRY);
    below
        .settle(&below.holdings_by_hand(), NOW)
        .expect("earliest_daa one below expiry_daa builds");

    // The plain self-settling trade has no earliest_daa at all: the builder's refusal is then the
    // only bound, the settle's lock time is 0, and the node accepts the settle in a block long
    // after expiry_daa.
    let open = Trade::new(FundingMode::Revocable, None, EXPIRY);
    let open_holdings = open.holdings();
    let built = open
        .settle(&open_holdings, EXPIRY - 1)
        .expect("a settle with no earliest_daa builds one score before expiry_daa");
    for now in [EXPIRY, EXPIRY + 1, EXPIRY + 1_000_000] {
        let refused = open
            .settle(&open_holdings, now)
            .expect_err("expired, with no earliest_daa");
        assert_eq!(
            refused.code(),
            "TX_EXPIRED",
            "no earliest_daa, built at DAA score {now}"
        );
    }
    let open_signed = open.sign(built);
    assert_eq!(open_signed.tx.lock_time, 0);
    for block in [EXPIRY, EXPIRY + 1, 10 * EXPIRY] {
        assert_eq!(
            open_signed.node(block),
            Ok(()),
            "no earliest_daa, block at DAA score {block}"
        );
    }

    // The refusal is policy. The settle built before expiry carries the lock time earliest_daa
    // and is valid in a block at any later score: every input runs in the engine, and the node's
    // lock-time rule asks only that the block be above the lock time.
    let signed = trade.sign(control);
    assert_eq!(signed.tx.lock_time, EARLIEST);
    for block in [EXPIRY, EXPIRY + 1, 10 * EXPIRY] {
        assert_eq!(signed.node(block), Ok(()), "block at DAA score {block}");
    }
    let early = signed
        .node(EARLIEST)
        .expect_err("not final at its lock time");
    assert!(early.starts_with("finality"), "{early}");
    // Only the lower bound exists: a lock time one score below earliest_daa fails [S3] in both
    // vaults, beside the accepted control above.
    let mut below = signed.tx.clone();
    below.lock_time = EARLIEST - 1;
    let below = trade.resign(&signed.ipst, below);
    for vault_input in [0, 1] {
        assert_locktime_refused(
            &execute(&below, signed.entries(), vault_input),
            &format!("lock time earliest_daa - 1, vault input {vault_input}"),
        );
    }
    // The same bound in the contract source under test (the builders run the embedded template).
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.lock_time = EARLIEST_DAA - 1;
    assert_flips_locktime(
        &w,
        &control,
        &faulty,
        0,
        "settle one score below earliest_daa",
    );
}

/// parity: ERR-02 equivalent
/// With an authority in the terms, settle needs its signature, so a party's or a stranger's is refused ([S6]); an authority refund signed by another key is refused too ([R2]).
#[test]
fn err02_settlement_authority_mismatch() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    for signer in [Role::Seller, Role::Buyer, Role::Stranger] {
        let mut faulty = control.clone();
        faulty.inputs[0] = In::settle(&w.asset_vault, Some(signer), AUTH_VALUE);
        assert_flips(
            &w,
            &control,
            &faulty,
            0,
            &format!("settle signed by {signer:?}"),
        );
    }
    let control = w.refund(ASSET_LEG, Role::Authority);
    let mut faulty = control.clone();
    faulty.inputs[0] = In::refund(
        &w.asset_vault,
        w.xonly(Role::Authority),
        Role::Buyer,
        AUTH_VALUE,
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "cancel named the authority, buyer signed",
    );
}

/// parity: ERR-03 equivalent
/// Settle needs a lock time of at least earliest_daa, so one DAA score earlier is refused by the lock-time check of both vaults ([S3]).
#[test]
fn err03_settlement_too_early() {
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = w.settle();
    assert_eq!(control.lock_time, EARLIEST_DAA);
    let mut faulty = control.clone();
    faulty.lock_time = EARLIEST_DAA - 1;
    assert_flips_locktime(&w, &control, &faulty, 0, "asset vault, earliest - 1");
    assert_locktime_refused(&faulty.run(&w, 1), "cash vault, earliest - 1");
}

/// parity: ERR-04 equivalent
/// A leg settles only from an escrow holding exactly its amount, so a KCC-20 escrow one unit short ([E5]) and a KAS cash vault one sompi short ([S2]) are refused.
#[test]
fn err04_leg_not_funded() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut short_asset = control.clone();
    let short = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A - 1,
    );
    set_asset_escrow(&w, &mut short_asset, short);
    assert_flips(
        &w,
        &control,
        &short_asset,
        0,
        "asset escrow holds amount_a - 1",
    );
    let mut short_cash = control.clone();
    short_cash.inputs[1].value = AMOUNT_B as u64 - 1;
    assert_flips(
        &w,
        &control,
        &short_cash,
        1,
        "KAS cash vault holds amount_b - 1",
    );
}

/// parity: ERR-05 divergent
/// The terms library's creation checks refuse an expiry not above the creation DAA score (TERMS_EXPIRY_NOT_AFTER_CREATION) and derive no funding address; unlike Solana's check at Create, the contract has no creation time: a vault whose expiry_daa has passed still settles, and its depositor's earmarked refund is open, so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err05_expiry_not_in_future() {
    let terms = vector("01-")
        .validate_structure()
        .expect("structure checks");
    let expiry = terms.terms().expiry_daa;
    let at = |creation_daa| CreationContext::new(terms.terms().network, creation_daa);
    assert!(Vault::instantiate_for_creation(&terms, LegIndex::Asset, &at(expiry - 1)).is_ok());
    let refused = Vault::instantiate_for_creation(&terms, LegIndex::Asset, &at(expiry))
        .expect_err("expiry at the creation DAA score");
    assert_eq!(refused.code(), "TERMS_EXPIRY_NOT_AFTER_CREATION");

    // The contract: a vault whose expiry_daa is behind the transaction's lock time.
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    let mut settle = w.settle();
    settle.lock_time = EXPIRY_DAA + 1;
    settle.assert_all_accepted(&w, "settle past expiry_daa");
    let mut refund = w.refund(ASSET_LEG, Role::Seller);
    refund.lock_time = EXPIRY_DAA + 1;
    refund.assert_all_accepted(&w, "the seller's earmarked refund past expiry_daa");
}

/// parity: ERR-06 divergent
/// The terms library's structure checks refuse an earliest_daa above expiry_daa (TERMS_EARLIEST_AFTER_EXPIRY), equal accepted; unlike Solana's check at Create, the contract accepts such terms: they settle from earliest_daa, past expiry_daa, and not one DAA earlier ([S3]), so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err06_earliest_after_expiry() {
    let mut control = vector("01-");
    control.earliest_daa = Some(control.expiry_daa);
    assert_created(control.clone(), "earliest == expiry");
    let mut faulty = control;
    faulty.earliest_daa = Some(faulty.expiry_daa + 1);
    assert_refused_with(
        faulty,
        "TERMS_EARLIEST_AFTER_EXPIRY",
        "earliest == expiry + 1",
    );

    // The contract, with terms the library refuses.
    let w = World::with(Mode::new(true, CASH_KCC20, REVOCABLE), |t, _| {
        t.earliest_daa = EXPIRY_DAA as i64 + 1
    });
    let mut at_earliest = w.settle();
    at_earliest.lock_time = EXPIRY_DAA + 1;
    let mut early = at_earliest.clone();
    early.lock_time = EXPIRY_DAA;
    assert_flips_locktime(
        &w,
        &at_earliest,
        &early,
        0,
        "earliest_daa = expiry_daa + 1, settle at expiry_daa",
    );
}

/// parity: ERR-07 divergent
/// The terms library's structure checks refuse a buyer key equal to the seller key (TERMS_PARTIES_NOT_DISTINCT); unlike Solana's check at Create, the contract accepts such terms: they settle, and the one key sends both legs home, so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err07_self_dvp() {
    let control = vector("01-");
    assert_created(control.clone(), "distinct parties");
    let mut faulty = control;
    faulty.buyer_key = faulty.seller_key;
    assert_refused_with(faulty, "TERMS_PARTIES_NOT_DISTINCT", "buyer == seller");

    // The contract, with terms the library refuses.
    let w = World::with(Mode::new(true, CASH_KAS, REVOCABLE), |t, _| {
        t.buyer_key = t.seller_key
    });
    w.settle()
        .assert_all_accepted(&w, "one key on both sides settles");
    for leg in [ASSET_LEG, CASH_LEG] {
        w.refund(leg, Role::Seller)
            .assert_all_accepted(&w, &format!("the one key sends leg {leg} home"));
    }
}

/// parity: ERR-08 divergent
/// The terms library's structure checks refuse two KCC-20 legs of one covenant (TERMS_SAME_COVENANT) and a KAS asset leg (TERMS_ASSET_KIND_UNSUPPORTED, decision D13), which the contract cannot express (its state has a cash kind, no asset kind); unlike Solana's check at Create, nothing on chain stops one-covenant vaults being funded, but both vaults refuse their settle, each finding two inputs of its leg's covenant (refused twice over, by the count and by the input check, so no single require is cited), though the KCC-20 transfer is valid, and each leg goes home by refund.
#[test]
fn err08_same_mint() {
    let control = vector("01-");
    assert_created(control.clone(), "two tokens");
    let asset_cov = match control.asset_leg.kind {
        LegKind::Kcc20(token) => token.covenant_id,
        _ => unreachable!("vector 01 has a KCC-20 asset"),
    };
    let mut faulty = control;
    match &mut faulty.cash_leg.kind {
        LegKind::Kcc20(token) => token.covenant_id = asset_cov,
        _ => unreachable!("vector 01 has KCC-20 cash"),
    }
    assert_refused_with(faulty, "TERMS_SAME_COVENANT", "one token on both legs");
    let control = vector("02-");
    assert_created(control.clone(), "a KCC-20 asset against KAS cash");
    let mut kas_for_kas = control;
    kas_for_kas.asset_leg.kind = LegKind::Kas;
    assert_refused_with(
        kas_for_kas,
        "TERMS_ASSET_KIND_UNSUPPORTED",
        "KAS on both legs",
    );

    // The contract state names a kind for the cash leg only: the asset leg is always KCC-20.
    let kinds: Vec<String> = vault_artifact()["contracts"]["ImpulseVault"]["runtime_state"]
        ["fields"]
        .as_array()
        .expect("state fields")
        .iter()
        .map(|f| f["name"].as_str().expect("field name").to_string())
        .filter(|name| name.ends_with("Kind"))
        .collect();
    assert_eq!(kinds, ["cashKind"]);

    // The contract, with one covenant on both legs: both escrows ride one valid KCC-20 transfer.
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    w.settle()
        .assert_all_accepted(&w, "two covenants (control)");
    let one = w.sibling(|t| t.cash = ASSET_TOKEN.template());
    let delivered = [one.delivered_asset(), one.delivered_cash()];
    let mut settle = one.settle();
    settle.inputs[2] = In::token(
        ASSET_TOKEN.compile(one.asset_escrow_state()),
        ASSET_COV,
        delivered.to_vec(),
        0,
    );
    settle.inputs[World::CASH_ESCROW_IDX] =
        In::token_delegate(ASSET_TOKEN.compile(one.cash_escrow_state()), ASSET_COV, 1);
    for (k, state) in delivered.into_iter().enumerate() {
        settle.outputs[k] = Out::token(ASSET_TOKEN.compile(state), ASSET_COV, 2);
    }
    for idx in [2, World::CASH_ESCROW_IDX] {
        assert_accepted(
            &settle.run(&one, idx),
            &format!("input {idx}: the KCC-20 transfer itself is valid"),
        );
    }
    for idx in [0, 1] {
        assert_refused(
            &settle.run(&one, idx),
            &format!("vault at input {idx}: one covenant on both legs"),
        );
    }
    one.refund(ASSET_LEG, Role::Seller)
        .assert_all_accepted(&one, "one covenant: the asset leg goes home");
    let home = Kcc20State::new(one.terms.buyer_refund, AMOUNT_B);
    let mut cash_home = one.refund(CASH_LEG, Role::Buyer);
    cash_home.inputs[1] = In::token(
        ASSET_TOKEN.compile(one.cash_escrow_state()),
        ASSET_COV,
        vec![home],
        0,
    );
    cash_home.outputs[1] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 1);
    cash_home.assert_all_accepted(&one, "one covenant: the cash leg goes home");
}

/// parity: ERR-09 divergent
/// The terms library's structure checks refuse a zero amount on either leg (TERMS_AMOUNT_ZERO), one unit accepted; unlike Solana's check at Create, the contract accepts a zero KCC-20 leg amount: such terms settle, that leg delivering nothing, so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err09_zero_amount() {
    for leg in ["asset", "cash"] {
        let amount = |t: &mut Terms, a| {
            if leg == "asset" {
                t.asset_leg.amount = a
            } else {
                t.cash_leg.amount = a
            }
        };
        let mut control = vector("01-");
        amount(&mut control, 1);
        assert_created(control.clone(), &format!("{leg} amount 1"));
        let mut faulty = control;
        amount(&mut faulty, 0);
        assert_refused_with(faulty, "TERMS_AMOUNT_ZERO", &format!("{leg} amount 0"));
    }

    // The contract, with terms the library refuses: a zero KCC-20 asset leg, a zero KCC-20 cash leg.
    let zero_asset = World::with(Mode::new(true, CASH_KAS, REVOCABLE), |t, _| t.amount_a = 0);
    assert_eq!(zero_asset.delivered_asset().amount, 0);
    zero_asset
        .settle()
        .assert_all_accepted(&zero_asset, "amount_a 0 settles");
    let zero_cash = World::with(Mode::new(true, CASH_KCC20, REVOCABLE), |t, _| {
        t.amount_b = 0
    });
    assert_eq!(zero_cash.delivered_cash().amount, 0);
    zero_cash
        .settle()
        .assert_all_accepted(&zero_cash, "KCC-20 amount_b 0 settles");
}

/// parity: ERR-10 divergent
/// Solana's Create refuses, for every caller, a mint whose extension changes amounts or blocks transfers; Impulse lets the terms name any KCC-20 template, the contract refuses at settle the delivery a taxing token would leave one unit short (the KCC-20 transfer itself valid, the vault's check on the new state refusing), and verify, run by the funder before funding, refuses a token whose state has a field beyond KCC-20's four (VERIFY_TOKEN_EXTENDED_STATE), and reports a template it does not recognise as TOKEN_TEMPLATE_UNPINNED.
#[test]
fn err10_blocked_mint_extension() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let short = Kcc20State::new(BUYER_DELIVERY, AMOUNT_A - 1);
    deliver_asset(&w, &mut faulty, &[short, stranger(1)]);
    assert_accepted(
        &faulty.run(&w, w.asset_escrow_idx()),
        "the KCC-20 transfer itself is valid",
    );
    assert_flips(&w, &control, &faulty, 0, "one unit taken on the way");

    // The funder's side. Control: the pinned kcc20.sil build the terms name reads.
    let terms = real_terms_of(Mode::new(true, CASH_KAS, REVOCABLE));
    let genuine = artifact_json(ASSET_TOKEN);
    let read = |terms: &_, json: &str| {
        let evidence = TokenEvidence {
            artifact_json: json,
            issuer_keys: &[],
        };
        token_warnings(terms, Some(&evidence), None)
    };
    let warnings = read(&terms, &genuine).expect("control: the pinned build reads");
    assert!(warnings
        .iter()
        .all(|w| w.kind != TokenWarningKind::TemplateUnpinned));

    // Fault 1: kcc20.sil with one more state field. Its own transfer works, the vault cannot
    // move it, and the terms naming it are refused at the verifier.
    let frozen = frozen_kcc20();
    let json = serde_json::to_string(&frozen.artifact).expect("artifact serializes");
    let refused = read(&naming(&terms, &frozen), &json).expect_err("extended state");
    assert_eq!(refused.code(), "VERIFY_TOKEN_EXTENDED_STATE");

    // Fault 2: a template outside the pinned kcc20.sil builds is not refused but flagged, its
    // declared state and entries unauthenticated.
    let other = Token {
        max_cov_ins: 5,
        ..ASSET_TOKEN
    };
    let other = other.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
    let json = serde_json::to_string(&other.artifact).expect("artifact serializes");
    let flagged = read(&naming(&terms, &other), &json).expect("an unrecognised template reads");
    assert!(flagged
        .iter()
        .any(|w| w.kind == TokenWarningKind::TemplateUnpinned));
}

/// parity: ERR-11 divergent
/// The terms library's structure checks refuse an authority key equal to the seller's or the buyer's (TERMS_AUTHORITY_IS_PARTY); unlike Solana's check at Create, the contract accepts such terms, and the party holding that key settles alone, the other party's signature refused ([S6]), so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err11_settlement_authority_is_party() {
    let control = vector("01-");
    assert_created(control.clone(), "a third-party authority");
    for party in [control.seller_key, control.buyer_key] {
        let mut faulty = control.clone();
        faulty.authority_key = Some(party);
        assert_refused_with(faulty, "TERMS_AUTHORITY_IS_PARTY", "authority is a party");
    }

    // The contract, with terms the library refuses: the authority key is the seller's.
    let w = World::with(Mode::new(true, CASH_KAS, REVOCABLE), |t, _| {
        t.authority_key = t.seller_key
    });
    let signed_by = |role| {
        let mut spec = w.settle();
        spec.inputs[0] = In::settle(&w.asset_vault, Some(role), AUTH_VALUE);
        spec.inputs[1] = In::settle(w.cash_vault(), Some(role), AMOUNT_B as u64);
        spec
    };
    assert_flips(
        &w,
        &signed_by(Role::Seller),
        &signed_by(Role::Buyer),
        0,
        "authority key is the seller's, the buyer signs the settle",
    );
}

/// parity: ERR-12 impossible
/// The authority is only a signing key and never has to receive funds: the canonical settle and cancels pay it nothing and are accepted, so the contract requires no output to it; the terms library requires only a valid x-only key (TERMS_INVALID_KEY).
#[test]
fn err12_settlement_authority_executable() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let authority = p2pk(w.xonly(Role::Authority));
    let mut spends = vec![w.settle()];
    spends.extend([ASSET_LEG, CASH_LEG].map(|leg| w.refund(leg, Role::Authority)));
    for spec in &spends {
        spec.assert_all_accepted(&w, "authority settle and cancel");
        assert!(spec.outputs.iter().all(|o| o.spk != authority));
    }
    let control = vector("01-");
    assert_created(control.clone(), "a valid authority key");
    let mut faulty = control;
    faulty.authority_key = Some(OFF_CURVE);
    assert_refused_with(faulty, "TERMS_INVALID_KEY", "authority key off the curve");
}

/// parity: ERR-13 impossible
/// An address can never serve new terms: the vault script commits to every term, so changed terms under the same nonce give other vaults, and the old vault still decodes to the old terms.
#[test]
fn err13_nonce_already_used() {
    let old = assert_created(vector("01-"), "the first trade");
    let mut changed = old.terms().clone();
    changed.buyer_delivery = script_hash_owner(0x42);
    assert_eq!(changed.nonce, old.terms().nonce);
    let new = assert_created(changed, "new terms, same nonce");
    for leg in LegIndex::ALL {
        assert_ne!(vault_hash(&old, leg), vault_hash(&new, leg), "{leg:?}");
        let vault = Vault::instantiate_existing(&old, leg).expect("vault");
        let (decoded, _) = decode(vault.redeem_script()).expect("decodes");
        assert_eq!(decoded, old, "{leg:?}: the old address keeps the old terms");
    }
}

/// parity: ERR-14 divergent
/// The terms library's creation checks refuse an expiry beyond the horizon, 315,360,000 DAA by default (TERMS_EXPIRY_BEYOND_HORIZON), modelled as 365 days at 10 DAA per second, not measured; unlike Solana's cap at Create, the contract accepts any DAA-score expiry: such terms settle, and under earmarked funding the depositor's own refund waits for that expiry ([R3]), so the cap protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err14_expiry_too_far_in_future() {
    assert_eq!(DEFAULT_MAX_EXPIRY_HORIZON_DAA, 315_360_000);
    let mut control = vector("01-");
    control.expiry_daa = VECTOR_CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    assert_created(control.clone(), "expiry at the horizon");
    let mut faulty = control;
    faulty.expiry_daa += 1;
    assert_refused_with(
        faulty,
        "TERMS_EXPIRY_BEYOND_HORIZON",
        "one past the horizon",
    );

    // The contract, with an expiry the library refuses: the last DAA score in the domain.
    let w = World::with(Mode::new(true, CASH_KCC20, EARMARKED), |t, _| {
        t.expiry_daa = FAR_DAA as i64
    });
    w.settle().assert_all_accepted(&w, "a far expiry settles");
    let mut home = w.refund(ASSET_LEG, Role::Seller);
    home.lock_time = FAR_DAA;
    let mut early = home.clone();
    early.lock_time = FAR_DAA - 1;
    assert_flips_locktime(
        &w,
        &home,
        &early,
        0,
        "the seller's earmarked refund one DAA before the far expiry",
    );
    early.lock_time = EXPIRY_DAA;
    assert_locktime_refused(
        &early.run(&w, 0),
        "the seller's earmarked refund at the harness expiry",
    );
}

/// parity: ERR-15 impossible
/// trade_ref is exactly 32 bytes in the type and in the encoding, its last field, so a longer reference cannot be expressed: any byte after it is refused (TERMS_TRAILING_BYTES).
#[test]
fn err15_ref_string_too_long() {
    let bytes = vector_bytes("01-");
    let terms = Terms::decode(&bytes).expect("control decodes");
    assert_eq!(&bytes[bytes.len() - 32..], &terms.trade_ref[..]);
    let mut longer = bytes;
    longer.push(0x00);
    let refused = Terms::decode(&longer).expect_err("a 33rd reference byte");
    assert_eq!(refused.code(), "TERMS_TRAILING_BYTES");
}

/// parity: ERR-16 impossible
/// A vault has no open or closed state to be in: the template has exactly two entries, settle and refund; the canonical settle and refund leave no output at a vault address, and the contract checks only the outputs it names, so a settle leaving its change at a vault address is accepted too, and the UTXO it left there goes home by the same script and terms.
#[test]
fn err16_dvp_still_open() {
    let entries: BTreeSet<String> = vault_artifact()["contracts"]["ImpulseVault"]["entries"]
        .as_object()
        .expect("entries")
        .keys()
        .cloned()
        .collect();
    assert_eq!(entries, BTreeSet::from(["refund".into(), "settle".into()]));

    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let vaults = [w.asset_vault.p2sh(), w.cash_vault().p2sh()];
    for (name, spec) in [
        ("settle", w.settle()),
        ("refund", w.refund(ASSET_LEG, Role::Seller)),
    ] {
        spec.assert_all_accepted(&w, name);
        assert!(
            spec.outputs.iter().all(|o| !vaults.contains(&o.spk)),
            "canonical {name} leaves an output at a vault address"
        );
    }

    // The settler's change sent to the asset vault's address: nothing in the contract stops it.
    let mut leaves = w.settle();
    let change = leaves.outputs.len() - 1;
    leaves.outputs[change].spk = w.asset_vault.p2sh();
    leaves.assert_all_accepted(&w, "a settle leaving its change at the asset vault");
    let left = leaves.outputs[change].value;
    let mut home = without_token(w.refund(ASSET_LEG, Role::Seller));
    home.inputs[0].value = left;
    home.outputs[0].value = left;
    assert_eq!(home.inputs[0].spk, w.asset_vault.p2sh());
    home.assert_all_accepted(&w, "the seller sends that UTXO home by the same script");
}

/// parity: ERR-17 impossible
/// No proof of existence is needed: a vault's rules are in its own script, so the revealed script decodes to its terms and leg, and a deposit there refunds by them whether or not anyone recorded the trade.
#[test]
fn err17_dvp_never_created() {
    let w = real_world(Mode::new(true, CASH_KCC20, REVOCABLE));
    for leg in [ASSET_LEG, CASH_LEG] {
        let script = w.vault(leg).bytecode();
        let (terms, index) = decode(script).expect("the script alone gives the terms");
        assert_eq!(i64::from(index.index()), leg);
        let again = Vault::instantiate_existing(&terms, index).expect("vault");
        assert_eq!(again.redeem_script(), script);
        w.refund(leg, depositor(leg))
            .assert_all_accepted(&w, &format!("leg {leg}: refund by the decoded terms"));
    }
    let not_a_vault = plain_redeem();
    assert_eq!(
        decode(&not_a_vault).expect_err("not a vault").code(),
        "TEMPLATE_NOT_IMPULSE_VAULT"
    );
}

/// parity: ERR-18 impossible
/// No balance is shared: KAS preloaded on the asset authorizer goes back to the seller in full at settle ([S9]), so a settle that passes it to the settler is refused.
#[test]
fn err18_escrow_preloaded_with_lamports() {
    const PRELOAD: u64 = 50_000;
    const SELLER_RETURN: usize = 2;
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let mut control = w.settle();
    control.inputs[0].value += PRELOAD;
    control.outputs[SELLER_RETURN].value += PRELOAD;
    let mut faulty = control.clone();
    faulty.outputs[SELLER_RETURN].value -= PRELOAD;
    faulty.outputs.last_mut().expect("change").value += PRELOAD;
    assert_flips(&w, &control, &faulty, 0, "preload to the settler's change");
}

/// parity: ERR-19 impossible
/// A destination cannot name its own vault: the vault's script hash is a hash of terms that include the destination, so setting buyer_delivery to it gives another vault (a fixed point is assumed infeasible under BLAKE2b-256 preimage resistance).
#[test]
fn err19_settlement_destination_is_swap_dvp() {
    let mut chase = assert_created(vector("01-"), "control").into_terms();
    for round in 0..3 {
        let target = vault_hash(
            &chase.clone().validate_structure().unwrap(),
            LegIndex::Asset,
        );
        chase.buyer_delivery = Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: target,
        });
        let checked = assert_created(chase.clone(), "delivery to the previous vault");
        assert_ne!(
            vault_hash(&checked, LegIndex::Asset),
            target,
            "round {round}"
        );
    }
}

/// parity: ERR-20 impossible
/// There is no trade account to preload: a vault address holds only separate UTXOs, and KAS there above amount_b cannot settle as the leg ([S2]) yet refunds whole to the buyer's refund script whoever signs ([R5], [R6]).
#[test]
fn err20_swap_dvp_preloaded_with_lamports() {
    const PRELOAD: u64 = 50_000;
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    assert_eq!(
        w.cash_vault().p2sh().script().len(),
        35,
        "a P2SH, no record"
    );
    let control = w.settle();
    let mut faulty = control.clone();
    faulty.inputs[1].value += PRELOAD;
    assert_flips(&w, &control, &faulty, 1, "cash vault UTXO above amount_b");

    let preloaded = |signer| {
        let mut spec = w.refund(CASH_LEG, signer);
        spec.inputs[0].value += PRELOAD;
        spec.outputs[0].value += PRELOAD;
        spec
    };
    for signer in [Role::Buyer, Role::Seller, Role::Authority] {
        let spec = preloaded(signer);
        assert_eq!(spec.outputs[0].spk, buyer_refund_kas_spk());
        spec.assert_all_accepted(&w, &format!("{signer:?} refunds the preload home"));
    }
    let control = preloaded(Role::Seller);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = p2pk(w.xonly(Role::Seller));
    assert_flips(&w, &control, &faulty, 0, "seller takes the preload");
    let mut withheld = control.clone();
    withheld.outputs[0].value -= PRELOAD;
    withheld.outputs.last_mut().expect("change").value += PRELOAD;
    assert_flips(&w, &control, &withheld, 0, "the refunder keeps the preload");
}

/// parity: ERR-21 impossible
/// Recipients are the owners and scripts the terms name, matched exactly in every output, so a settle delivering to another owner, or a refund paying another key ([R7]) or another refund owner, is refused.
#[test]
fn err21_recipient_ata_mismatch() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    deliver_asset(&w, &mut faulty, &[stranger(AMOUNT_A)]);
    assert_flips(&w, &control, &faulty, 0, "settle delivers to another owner");

    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    faulty.outputs[0].spk = stranger_spk();
    assert_flips(&w, &control, &faulty, 0, "refund pays another key");
    let mut faulty = control.clone();
    refund_asset_home(&mut faulty, stranger(AMOUNT_A));
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund returns the token elsewhere",
    );
}

/// parity: ERR-22 divergent
/// The terms library's structure checks refuse a party key that is not a valid x-only point, which nobody could sign for (TERMS_INVALID_KEY); unlike Solana's check at Create, the contract accepts such terms: they settle, a refund naming that key is refused ([R2], the key does not parse), and only the other party or the authority sends that party's leg home, so the refusal protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn err22_party_not_signer_capable() {
    let control = vector("01-");
    assert_created(control.clone(), "valid party keys");
    let mut seller = control.clone();
    seller.seller_key = OFF_CURVE;
    assert_refused_with(seller, "TERMS_INVALID_KEY", "seller key off the curve");
    let mut buyer = control;
    buyer.buyer_key = OFF_CURVE;
    assert_refused_with(buyer, "TERMS_INVALID_KEY", "buyer key off the curve");

    // The contract, with terms the library refuses: the buyer's key is off the curve.
    let w = World::with(Mode::new(true, CASH_KAS, REVOCABLE), |t, _| {
        t.buyer_key = OFF_CURVE
    });
    w.settle()
        .assert_all_accepted(&w, "an off-curve buyer key settles");
    for signer in [Role::Seller, Role::Authority] {
        w.refund(CASH_LEG, signer)
            .assert_all_accepted(&w, &format!("{signer:?} sends the buyer's leg home"));
    }
    let control = w.refund(CASH_LEG, Role::Seller);
    let mut named = control.clone();
    named.inputs[0] = In::refund(w.cash_vault(), OFF_CURVE, Role::Buyer, AMOUNT_B as u64);
    control.assert_all_accepted(&w, "the seller's refund (control)");
    let run = named.run(&w, 0);
    assert!(
        matches!(run.result, Err(TxScriptError::InvalidPubkey(_))),
        "a refund naming the off-curve buyer key: {:?}",
        run.result
    );
}

/// parity: ERR-23 uncovered
/// The vault pins the covenant ID and template hash the terms name, so a token recreated under another covenant (refused twice over, by the count of the leg's covenant and by the input check, so no single require is cited) and a minter escrow ([E6]) cannot settle; but nothing checks who holds the named token's minter, so a minter that changed hands after funding does not stop settle: an issuer power the parties accept with the token.
#[test]
fn err23_mint_authority_changed() {
    let w = World::new(Mode::new(false, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let idx = w.asset_escrow_idx();

    let mut other_covenant = control.clone();
    other_covenant.inputs[idx].cov = Some(DECOY_COV);
    other_covenant.outputs[0].cov = Some(CovenantBinding {
        authorizing_input: idx as u16,
        covenant_id: DECOY_COV,
    });
    assert_flips(
        &w,
        &control,
        &other_covenant,
        0,
        "escrow of another covenant",
    );

    let mut minter = control.clone();
    let escrow = Kcc20State {
        is_minter: true,
        ..w.asset_escrow_state()
    };
    set_asset_escrow(&w, &mut minter, escrow);
    let handed_on = Kcc20State {
        is_minter: true,
        ..stranger(0)
    };
    deliver_asset(&w, &mut minter, &[w.delivered_asset(), handed_on]);
    assert_accepted(&minter.run(&w, idx), "the KCC-20 transfer itself is valid");
    assert_flips(&w, &control, &minter, 0, "minter escrow");
}
