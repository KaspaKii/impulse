// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The Solana DvP README edge cases (EDGE-01 to EDGE-25) against Impulse. Tag format: parity.rs.
//! Each edge case cites the README lines it paraphrases (solana-dvp.json); every bullet of the
//! README's instruction notes is cited by at least one item.

use crate::common::*;
use crate::harness::*;
use crate::trade::{Holdings, Trade, EARLIEST, EXPIRY, KAS_CASH, LEG_AMOUNT, NOW, TOKEN_HELD};
use crate::verify_world::{
    artifact_json, minter_controller, naming, renamed_state_kcc20, spend_only_template,
    terms as real_terms_of,
};
use impulse_core::address::{prefix, vault_address};
use impulse_core::locktime::first_block_daa;
use impulse_core::template::{self, decode, template_hash_of_instance, LegIndex, Vault};
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, LegKind, ValidatedTerms,
    DEFAULT_MAX_EXPIRY_HORIZON_DAA,
};
use impulse_core::tx::{Kcc20State as CoreState, RefundSigner};
use impulse_core::verify::{
    pinned_kcc20, token_warnings, verify_addresses, verify_revealed_script, OfferedAddresses,
    Party, Relation, TemplateTriple, TokenEvidence, TokenWarning, TokenWarningKind, KCC20_ENTRIES,
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript::{LOCK_TIME_THRESHOLD, MAX_TX_IN_SEQUENCE_NUM};

fn script_hash_owner(id: u8) -> Destination {
    Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: [id; 32],
    })
}

/// parity: EDGE-01 divergent
/// Funding runs no vault script and each vault is a standard P2SH address from the terms, but a KCC-20 leg is not one plain transfer: fund_kas pays exactly amount_b to the cash vault, while fund_kcc20 makes a token of exactly amount_a owned by the asset vault's script hash plus a KAS authorizer at the vault's address, the engine accepting both; the token alone cannot move, so a token-only deposit, as Solana's single transfer would make, waits until a KAS output sits at the vault's address (the engine refuses the escrowed token's refund without the authorizer input beside the control with it, and the settle and refund builders refuse an authorizer that is not at the vault, TX_NOT_AT_VAULT); a deposit short of the leg amount, or into the vault of other terms, is refused by the builder beside the accepted control (TX_TOKEN_INPUT, TX_VAULT_MISMATCH).
#[test]
fn edge01_funding_by_plain_transfer() {
    for name in ["01-", "02-", "08-"] {
        let terms = assert_created(vector(name), name);
        let ctx = creation_context(terms.terms());
        for leg in LegIndex::ALL {
            let vault = Vault::instantiate_for_creation(&terms, leg, &ctx).expect("fundable");
            let address = Address::try_from(vault_address(&vault).as_str()).expect("address");
            assert_eq!(address.version, Version::ScriptHash, "{name} {leg:?}");
            assert_eq!(
                address.prefix,
                prefix(terms.terms().network),
                "{name} {leg:?}"
            );
            assert_eq!(address.payload.as_slice(), vault.vault().script_hash());
            let spk = vault.vault().script_public_key();
            assert_eq!(ScriptClass::from_script(&spk), ScriptClass::ScriptHash);
        }
    }

    // The fund builders make that transaction, and the engine accepts it as it stands.
    let trade = Trade::new(FundingMode::Revocable, Some(EARLIEST), EXPIRY);
    let (asset_vault, cash_vault) = (
        trade.fundable(LegIndex::Asset),
        trade.fundable(LegIndex::Cash),
    );
    let held = || vec![trade.seller_token("held", TOKEN_HELD)];
    let asset = trade.sign(trade.fund_asset(held(), NOW).expect("asset funding builds"));
    let cash = trade.sign(
        trade
            .fund_cash_into(&cash_vault, NOW)
            .expect("cash funding builds"),
    );
    asset.assert_engine_accepts("fund the asset leg");
    cash.assert_engine_accepts("fund the cash leg");
    let vaults = [
        asset_vault.vault().script_public_key(),
        cash_vault.vault().script_public_key(),
    ];
    for funding in [&asset, &cash] {
        assert!(
            funding
                .entries()
                .iter()
                .all(|spent| !vaults.contains(&spent.script_public_key)),
            "a funding transaction spends no vault"
        );
    }
    let escrowed = CoreState::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: asset_vault.vault().script_hash(),
        },
        LEG_AMOUNT,
    );
    assert_eq!(
        asset.tx.outputs[0].script_public_key,
        trade.token_script(&escrowed),
        "the escrowed token: exactly amount_a, owned by the asset vault's script hash"
    );
    assert_eq!(asset.tx.outputs[1].script_public_key, vaults[0]);
    assert_eq!(cash.tx.outputs[0].script_public_key, vaults[1]);
    assert_eq!(cash.tx.outputs[0].value, KAS_CASH);

    // Faults beside the controls above: a deposit one unit short, and the vault of other terms.
    let short = trade
        .fund_asset(vec![trade.seller_token("short", LEG_AMOUNT - 1)], NOW)
        .expect_err("a deposit short of the leg amount");
    assert_eq!(short.code(), "TX_TOKEN_INPUT");
    trade
        .fund_asset(vec![trade.seller_token("exact", LEG_AMOUNT)], NOW)
        .expect("control: exactly the leg amount");
    let other = Trade::new(FundingMode::Revocable, Some(EARLIEST), EXPIRY);
    let wrong = trade
        .fund_cash_into(&other.fundable(LegIndex::Cash), NOW)
        .expect_err("the cash vault of other terms");
    assert_eq!(wrong.code(), "TX_VAULT_MISMATCH");

    // A token-only deposit: the escrowed token moves only with an input at the vault's address.
    // Engine: the refund with its authorizer is accepted by both the vault and the token; with
    // the authorizer input (and its output) left out, the token's own owner check finds no
    // input at the vault's script hash and refuses.
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let control = w.refund(ASSET_LEG, Role::Seller);
    let mut token_only = control.clone();
    token_only.inputs.remove(0);
    token_only.outputs.remove(0);
    let home = Kcc20State::new(w.terms.seller_refund, AMOUNT_A);
    token_only.outputs[0] = Out::token(ASSET_TOKEN.compile(home), ASSET_COV, 0);
    assert_flips(
        &w,
        &control,
        &token_only,
        0,
        "the escrowed token without an input at the vault's address",
    );
    // The cause is the token's owner check: put an input at the vault's address back anywhere in
    // the transaction (here at index 1, which the vault itself would refuse, [R4]) and the token
    // is accepted again.
    let mut vault_input_present = token_only.clone();
    vault_input_present.inputs[0] = In::token(
        ASSET_TOKEN.compile(w.asset_escrow_state()),
        ASSET_COV,
        vec![home],
        1,
    );
    vault_input_present
        .inputs
        .insert(1, control.inputs[0].clone());
    vault_input_present
        .outputs
        .insert(1, control.outputs[0].clone());
    assert_accepted(
        &vault_input_present.run(&w, 0),
        "the token with an input at the vault's address",
    );
    // Builders: an authorizer that is not at the asset vault's address is refused in the settle
    // and in the refund, beside the funded holdings.
    let h = trade.holdings();
    trade
        .settle(&h, NOW)
        .expect("control: the authorizer sits at the asset vault");
    trade
        .refund_asset(&h, RefundSigner::Depositor)
        .expect("control: the refund with the authorizer at the vault");
    let elsewhere = Holdings {
        asset_authorizer: h.cash_vault.clone(),
        asset_escrow: h.asset_escrow.clone(),
        cash_vault: h.cash_vault.clone(),
    };
    let refused = trade
        .settle(&elsewhere, NOW)
        .expect_err("an authorizer at the cash vault");
    assert_eq!(refused.code(), "TX_NOT_AT_VAULT", "settle");
    let refused = trade
        .refund_asset(&elsewhere, RefundSigner::Depositor)
        .expect_err("an authorizer at the cash vault");
    assert_eq!(refused.code(), "TX_NOT_AT_VAULT", "refund");
}

/// parity: EDGE-02 impossible
/// KAS is native: the KAS cash vault UTXO is the leg itself, with no wrapped balance to sync, so it settles only at exactly amount_b ([S2]) and refunds its whole value ([R5]).
#[test]
fn edge02_native_kas_needs_no_wrapping() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    for value in [AMOUNT_B - 1, AMOUNT_B + 1] {
        let mut faulty = control.clone();
        faulty.inputs[1].value = value as u64;
        assert_flips(
            &w,
            &control,
            &faulty,
            1,
            &format!("cash vault holds {value}"),
        );
    }
    let refund = w.refund(CASH_LEG, Role::Buyer);
    assert_eq!(refund.outputs[0].value, refund.inputs[0].value);
    let mut short = refund.clone();
    short.outputs[0].value -= 1;
    assert_flips(&w, &refund, &short, 0, "refund one sompi short");
}

/// parity: EDGE-03 impossible
/// KAS sent to the asset vault after funding is its own UTXO: it cannot ride a settle at another input ([S1]), the counterparty and the authority cannot refund it without the escrowed token ([R11]), and only the seller takes it, to its own key.
#[test]
fn edge03_kas_at_a_vault_is_never_swept_to_the_closer() {
    const STRAY: u64 = 7_000;
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let at = faulty.inputs.len() - 1;
    faulty
        .inputs
        .insert(at, In::settle(&w.asset_vault, Some(Role::Authority), STRAY));
    faulty.outputs.last_mut().expect("change").value += STRAY;
    assert_flips(&w, &control, &faulty, at, "stray KAS rides the settle");

    let stray = |signer| {
        let mut spec = without_token(w.refund(ASSET_LEG, signer));
        spec.inputs[0].value = STRAY;
        spec.outputs[0].value = STRAY;
        spec
    };
    let control = stray(Role::Seller);
    assert_eq!(control.outputs[0].spk, p2pk(w.xonly(Role::Seller)));
    for signer in [Role::Buyer, Role::Authority] {
        assert_flips(
            &w,
            &control,
            &stray(signer),
            0,
            &format!("{signer:?} refunds the stray KAS"),
        );
    }
}

/// parity: EDGE-04 divergent
/// An over-deposit never pays out: an escrow above the leg amount cannot settle ([E5]), where Solana's settle clamps and refunds the surplus; only its depositor can send it home whole ([R14]), under earmarked funding from expiry_daa ([R3]).
#[test]
fn edge04_over_deposit_never_leaks() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let over = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A + 1,
    );
    let control = w.settle();
    let mut faulty = control.clone();
    set_asset_escrow(&w, &mut faulty, over);
    deliver_asset(&w, &mut faulty, &[w.delivered_asset(), stranger(1)]);
    assert_accepted(
        &faulty.run(&w, w.asset_escrow_idx()),
        "the KCC-20 transfer itself is valid",
    );
    assert_flips(&w, &control, &faulty, 0, "escrow holds amount_a + 1");

    for funding in [REVOCABLE, EARMARKED] {
        let w = World::new(Mode::new(true, CASH_KCC20, funding));
        assert_only_depositor_unwinds(&w, ASSET_LEG, AMOUNT_A + 1, &format!("funding {funding}"));
    }
}

/// parity: EDGE-05 equivalent
/// Destinations are terms bound into both vault addresses: settle pays only buyer_delivery and seller_proceeds, and a refund pays the separate refund destination, never a delivery one.
#[test]
fn edge05_settlement_destinations() {
    let agreed = assert_created(vector("01-"), "agreed terms");
    let mut moved = agreed.terms().clone();
    moved.seller_proceeds = script_hash_owner(0x43);
    let moved = assert_created(moved, "proceeds redirected");
    for leg in LegIndex::ALL {
        assert_ne!(vault_hash(&agreed, leg), vault_hash(&moved, leg), "{leg:?}");
    }

    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    w.settle()
        .assert_all_accepted(&w, "deliveries to the agreed destinations");
    let control = w.refund(ASSET_LEG, Role::Buyer);
    let mut faulty = control.clone();
    refund_asset_home(
        &mut faulty,
        Kcc20State::new(w.terms.buyer_delivery, AMOUNT_A),
    );
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "refund to the buyer's delivery owner",
    );
}

/// parity: EDGE-06 impossible
/// A destination is the owner itself, type and identifier, not an account whose owner could be reassigned: a delivery to the same identifier under another owner type is refused.
#[test]
fn edge06_no_recipient_account_to_reassign() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let same_id = Kcc20State::new(Owner::script_hash(BUYER_DELIVERY.id), AMOUNT_A);
    deliver_asset(&w, &mut faulty, &[same_id]);
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "same identifier, SCRIPT_HASH owner type",
    );
}

/// parity: EDGE-07 equivalent
/// trade_ref is an opaque 32-byte reference the contract never reads, and unlike the Solana reference it is inside the terms hash and both vault addresses.
#[test]
fn edge07_trade_reference_is_bound() {
    let terms = assert_created(vector("01-"), "control");
    let mut other = terms.terms().clone();
    other.trade_ref[0] ^= 1;
    let other = assert_created(other, "one reference bit changed");
    assert_ne!(terms.terms_hash(), other.terms_hash());
    for leg in LegIndex::ALL {
        assert_ne!(vault_hash(&terms, leg), vault_hash(&other, leg), "{leg:?}");
    }
    let w = World::with(Mode::new(true, CASH_KCC20, REVOCABLE), |t, _| {
        t.trade_ref = [0x11; 32]
    });
    w.settle().assert_all_accepted(&w, "any reference settles");
}

/// parity: EDGE-08 divergent
/// A depositor's refund returns what the UTXO actually holds, whole: an escrow one unit short goes home as it is, and a refund paying less KAS than the vault UTXO holds is refused ([R5]); unlike Solana's unwinds, the counterparty and the authority cannot drain an escrow holding other than the leg amount ([R14]), and under earmarked funding the depositor waits for expiry_daa ([R3]).
#[test]
fn edge08_unwind_returns_the_actual_balance() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let short = Kcc20State::new(
        Owner::script_hash(w.asset_vault.script_hash()),
        AMOUNT_A - 1,
    );
    let mut control = w.refund(ASSET_LEG, Role::Seller);
    refund_asset_escrow(
        &mut control,
        short,
        Kcc20State::new(SELLER_REFUND, AMOUNT_A - 1),
    );
    let mut faulty = control.clone();
    faulty.outputs[0].value -= 1;
    assert_flips(
        &w,
        &control,
        &faulty,
        0,
        "authorizer KAS refunded one sompi short",
    );
    for funding in [REVOCABLE, EARMARKED] {
        let w = World::new(Mode::new(true, CASH_KCC20, funding));
        assert_only_depositor_unwinds(&w, ASSET_LEG, AMOUNT_A - 1, &format!("funding {funding}"));
    }
}

/// parity: EDGE-09 divergent
/// A deposit landing after the counterparty sent the trade home is refundable at once by that counterparty too, and only to the depositor, so rejecting can abort a trade, never capture a deposit ([R7], output match); unlike Recover, a late deposit holding other than the leg amount only its depositor can send home ([R14]), under earmarked funding from expiry_daa ([R3]).
#[test]
fn edge09_late_deposit_after_a_reject() {
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    // The buyer rejects: it sends the seller's asset leg home with no lock time. The seller's
    // in-flight deposit lands afterwards at the same address and goes home the same way.
    let reject = w.refund(ASSET_LEG, Role::Buyer);
    assert_eq!(reject.lock_time, 0);
    reject.assert_all_accepted(&w, "the buyer sends the late deposit home");
    let mut kas_to_buyer = reject.clone();
    kas_to_buyer.outputs[0].spk = p2pk(w.xonly(Role::Buyer));
    assert_flips(&w, &reject, &kas_to_buyer, 0, "authorizer KAS to the buyer");
    let mut token_to_buyer = reject.clone();
    let buyer = Kcc20State::new(Owner::pubkey(w.xonly(Role::Buyer)), AMOUNT_A);
    refund_asset_home(&mut token_to_buyer, buyer);
    assert_flips(&w, &reject, &token_to_buyer, 0, "token to the buyer");
    assert_only_depositor_unwinds(&w, ASSET_LEG, AMOUNT_A - 1, "a late deposit one unit short");
}

/// parity: EDGE-10 impossible
/// There is no rent and no closer's reward: each authorizer's KAS goes back to its depositor at settle ([S8]), so a settle paying it to the authority is refused.
#[test]
fn edge10_no_rent_for_the_closer() {
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    for (output, vault) in [(2, 0), (3, 1)] {
        let mut faulty = control.clone();
        faulty.outputs[output].spk = p2pk(w.xonly(Role::Authority));
        assert_flips(
            &w,
            &control,
            &faulty,
            vault,
            &format!("authorizer return at output {output} to the authority"),
        );
    }
}

/// parity: EDGE-11 divergent
/// Refunds never expire, and the terms library derives no funding address at or past expiry (TERMS_EXPIRY_NOT_AFTER_CREATION); unlike Solana, settle does not stop at expiry either: the contract accepts a settle after expiry_daa, from anyone in self-settling mode, so refusing it is the I5 builder's policy (ERR-01), and under earmarked funding the depositor's refund from expiry_daa races a late settle (EDGE-25).
#[test]
fn edge11_expiry_stops_neither_refunds_nor_settle() {
    const LATE: u64 = EXPIRY_DAA + 1_000_000;
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    for leg in [ASSET_LEG, CASH_LEG] {
        for signer in [Role::Seller, Role::Buyer, Role::Authority] {
            let mut spec = w.refund(leg, signer);
            spec.lock_time = LATE;
            spec.assert_all_accepted(&w, &format!("leg {leg}, {signer:?}, after expiry"));
        }
    }
    // A settle after expiry_daa is accepted, with and without an authority, and the seller's own
    // refund of the same asset vault is valid at the same lock time: the two race.
    for authority in [true, false] {
        for funding in [REVOCABLE, EARMARKED] {
            let w = World::new(Mode::new(authority, CASH_KCC20, funding));
            let label = format!("authority {authority}, funding {funding}");
            let mut settle = w.settle();
            settle.lock_time = LATE;
            settle.assert_all_accepted(&w, &format!("{label}: settle after expiry"));
            let mut refund = w.refund(ASSET_LEG, Role::Seller);
            refund.lock_time = LATE;
            assert_eq!(refund.inputs[0].spk, settle.inputs[0].spk);
            refund.assert_all_accepted(&w, &format!("{label}: the seller's refund then"));
        }
    }
    let terms = vector("01-").validate_structure().expect("structure");
    let after = impulse_core::terms::CreationContext::new(
        terms.terms().network,
        terms.terms().expiry_daa + 1,
    );
    let before = creation_context(terms.terms());
    for leg in LegIndex::ALL {
        let fundable = Vault::instantiate_for_creation(&terms, leg, &before).expect("before");
        let refused = Vault::instantiate_for_creation(&terms, leg, &after).expect_err("after");
        assert_eq!(refused.code(), "TERMS_EXPIRY_NOT_AFTER_CREATION");
        let existing = Vault::instantiate_existing(&terms, leg).expect("existing trade");
        assert_eq!(existing.redeem_script(), fundable.vault().redeem_script());
    }
}

/// parity: EDGE-12 equivalent
/// earliest_daa is an absolute DAA-score lock time: settle is accepted at exactly earliest_daa, and with no earliest_daa it needs no lock time at all.
#[test]
fn edge12_earliest_settlement() {
    let mode = Mode::new(true, CASH_KCC20, EARMARKED);
    let w = World::new(mode);
    let at = w.settle();
    assert_eq!(at.lock_time, EARLIEST_DAA);
    at.assert_all_accepted(&w, "settle at earliest_daa");
    let unbounded = World::with(mode, |t, _| {
        t.has_earliest = false;
        t.earliest_daa = 0;
    });
    let mut spec = unbounded.settle();
    spec.lock_time = 0;
    spec.inputs[0].sequence = MAX_TX_IN_SEQUENCE_NUM;
    spec.inputs[1].sequence = MAX_TX_IN_SEQUENCE_NUM;
    spec.assert_all_accepted(&unbounded, "no earliest_daa, no lock time");
}

/// parity: EDGE-13 divergent
/// In the terms library earliest_daa may not pass expiry_daa, which may not pass the creation horizon, so earliest inherits the cap: both at the horizon are accepted, one past it refused; unlike Solana's cap at Create, the contract accepts both far past any horizon and settles from that earliest_daa, not one DAA earlier ([S3]), so the cap protects only a funder who runs the checks before funding (I6 verify).
#[test]
fn edge13_earliest_inherits_the_expiry_cap() {
    let edge = VECTOR_CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    let mut control = vector("01-");
    control.expiry_daa = edge;
    control.earliest_daa = Some(edge);
    assert_created(control.clone(), "both at the horizon");
    let mut earliest_past = control.clone();
    earliest_past.earliest_daa = Some(edge + 1);
    assert_refused_with(
        earliest_past,
        "TERMS_EARLIEST_AFTER_EXPIRY",
        "earliest past",
    );
    let mut both_past = control;
    both_past.expiry_daa = edge + 1;
    both_past.earliest_daa = Some(edge + 1);
    assert_refused_with(both_past, "TERMS_EXPIRY_BEYOND_HORIZON", "both past");

    // The contract, with both at the last DAA score in the domain.
    let w = World::with(Mode::new(true, CASH_KCC20, EARMARKED), |t, _| {
        t.earliest_daa = FAR_DAA as i64;
        t.expiry_daa = FAR_DAA as i64;
    });
    let mut at_earliest = w.settle();
    at_earliest.lock_time = FAR_DAA;
    let mut early = at_earliest.clone();
    early.lock_time = FAR_DAA - 1;
    assert_flips_locktime(
        &w,
        &at_earliest,
        &early,
        0,
        "far earliest_daa, settle one DAA early",
    );
}

/// parity: EDGE-14 divergent
/// Gates are DAA scores in the transaction's lock time, not a clock: the script compares the lock time with earliest_daa ([S3]) and, for an earmarked depositor's refund, expiry_daa ([R3]) to one score, and the node takes a lock time only in a block of a higher DAA score, so the builders' effective bounds are earliest_daa + 1 and expiry_daa + 1, each rule exact to one score with no tolerance window; a timestamp-domain bound is refused by the terms library and never satisfies the script, and how DAA scores map to wall-clock time is a model, not measured.
#[test]
fn edge14_gates_use_the_daa_score() {
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = w.settle();
    let mut timestamp = control.clone();
    timestamp.lock_time = LOCK_TIME_THRESHOLD + EARLIEST_DAA;
    assert_flips_locktime(&w, &control, &timestamp, 0, "timestamp-domain lock time");

    let control = vector("01-");
    assert_created(control.clone(), "DAA-score expiry");
    let mut faulty = control;
    faulty.expiry_daa = LOCK_TIME_THRESHOLD;
    assert_refused_with(
        faulty,
        "TERMS_EXPIRY_NOT_DAA",
        "expiry in the timestamp domain",
    );

    // The earmarked depositor's refund opens at expiry_daa in the contract source under test.
    let refund = w.refund(ASSET_LEG, Role::Seller);
    assert_eq!(refund.lock_time, EXPIRY_DAA);
    let mut early = refund.clone();
    early.lock_time = EXPIRY_DAA - 1;
    assert_flips_locktime(&w, &refund, &early, 0, "earmarked refund one score early");

    // The builders' transactions, one DAA score either side of each bound. Script rule: the
    // lock time itself. Node rule: the block's DAA score must be above the lock time.
    let trade = Trade::new(FundingMode::Earmarked, Some(EARLIEST), EXPIRY);
    let h = trade.holdings();
    let settle = trade.sign(trade.settle(&h, NOW).expect("settle builds"));
    assert_eq!(settle.tx.lock_time, EARLIEST);
    let mut early = settle.tx.clone();
    early.lock_time = EARLIEST - 1;
    let early = trade.resign(&settle.ipst, early);
    for vault_input in [0, 1] {
        assert_locktime_refused(
            &execute(&early, settle.entries(), vault_input),
            &format!("settle at earliest_daa - 1, vault input {vault_input}"),
        );
    }
    settle.assert_engine_accepts("settle at earliest_daa");
    assert_eq!(first_block_daa(settle.tx.lock_time), Some(EARLIEST + 1));
    let refused = settle
        .node(EARLIEST)
        .expect_err("not final at its lock time");
    assert!(refused.starts_with("finality"), "{refused}");
    assert_eq!(settle.node(EARLIEST + 1), Ok(()));

    let refund = trade.sign(
        trade
            .refund_asset(&h, RefundSigner::Depositor)
            .expect("the depositor's refund builds"),
    );
    assert_eq!(refund.tx.lock_time, EXPIRY);
    let mut early = refund.tx.clone();
    early.lock_time = EXPIRY - 1;
    let early = trade.resign(&refund.ipst, early);
    assert_locktime_refused(
        &execute(&early, refund.entries(), 0),
        "earmarked refund at expiry_daa - 1",
    );
    refund.assert_engine_accepts("earmarked refund at expiry_daa");
    assert_eq!(first_block_daa(refund.tx.lock_time), Some(EXPIRY + 1));
    let refused = refund.node(EXPIRY).expect_err("not final at its lock time");
    assert!(refused.starts_with("finality"), "{refused}");
    assert_eq!(refund.node(EXPIRY + 1), Ok(()));
    // The counterparty's refund has no lock time and goes at once.
    let counterparty = trade.sign(
        trade
            .refund_asset(&h, RefundSigner::Counterparty)
            .expect("the counterparty's refund builds"),
    );
    assert_eq!(counterparty.tx.lock_time, 0);
    assert_eq!(counterparty.node(NOW), Ok(()));
}

/// parity: EDGE-15 impossible
/// No address can serve other terms: other terms, or a repeat trade with a new nonce, give other vaults; identical terms give the identical vault, so later deposits there settle again as the same trade, and a repeat trade's vaults do not settle crossed with the first's even when their deliveries match, since each vault requires its own trade's other vault ([S10]; known limitation L8, closed).
#[test]
fn edge15_no_tombstone_needed() {
    let first = assert_created(vector("01-"), "first");
    let again = assert_created(vector("01-"), "the same terms again");
    let mut repeat = first.terms().clone();
    repeat.nonce = repeat.nonce.wrapping_add(1);
    let repeat = assert_created(repeat, "repeat trade");
    for leg in LegIndex::ALL {
        assert_eq!(vault_hash(&first, leg), vault_hash(&again, leg), "{leg:?}");
        assert_ne!(vault_hash(&first, leg), vault_hash(&repeat, leg), "{leg:?}");
    }

    // In the engine: the trade settles; identical terms are the same vaults, and later deposits
    // there settle again as the same trade.
    let w = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let settled = w.settle();
    settled.assert_all_accepted(&w, "the trade settles");
    let same = w.sibling(|_| {});
    let later = same.settle();
    for at in [0, 1] {
        assert_eq!(later.inputs[at].spk, settled.inputs[at].spk, "input {at}");
    }
    later.assert_all_accepted(&same, "later deposits at the same vaults settle again");

    // A repeat trade with a new nonce: other vaults, which do not settle crossed with the
    // first's ([S10]): each vault refuses the other trade's vault at the other slot.
    let next = w.sibling(|t| t.nonce = [0x01; 8]);
    assert_ne!(next.asset_vault.p2sh(), w.asset_vault.p2sh());
    assert_ne!(next.cash_vault().p2sh(), w.cash_vault().p2sh());
    let mut crossed = w.settle();
    crossed.inputs[1] = In::settle(next.cash_vault(), Some(Role::Authority), AUTH_VALUE);
    crossed.inputs[World::CASH_ESCROW_IDX] = In::token(
        CASH_TOKEN.compile(next.cash_escrow_state()),
        CASH_COV,
        vec![next.delivered_cash()],
        1,
    );
    assert_refused(
        &crossed.run(&w, 0),
        "the first trade's asset vault with the repeat's cash vault",
    );
    assert_refused(
        &crossed.run(&w, 1),
        "the repeat's cash vault with the first trade's asset vault",
    );
}

/// parity: EDGE-16 equivalent
/// Parties are single keys, as Solana's must be signer-capable accounts: the refund entry checks one signature against one x-only key, so a P2SH multisig cannot be a party and a custodian party holds a single or aggregated key; a custodian's multisig is allowed as a destination, a P2SH KAS script or a SCRIPT_HASH token owner, and the contract delivers to both.
#[test]
fn edge16_parties_are_keys_multisig_only_as_destination() {
    // A party is one key: the refund entry takes one signature and the key it is checked against.
    let artifact: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v1.json"))
            .expect("artifact"),
    )
    .expect("artifact parses");
    let params: Vec<(&str, &str)> = artifact["contracts"]["ImpulseVault"]["entries"]["refund"]
        ["params"]
        .as_array()
        .expect("refund params")
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap(),
                p["type"]["kind"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(params, [("s", "sig"), ("signer", "pubkey")]);

    let p2sh_proceeds = assert_created(vector("08-"), "P2SH KAS proceeds");
    match &p2sh_proceeds.terms().seller_proceeds {
        Destination::Kas(spk) => assert_eq!(ScriptClass::from_script(spk), ScriptClass::ScriptHash),
        other => panic!("vector 08 proceeds: {other:?}"),
    }
    let script_owner = assert_created(vector("02-"), "SCRIPT_HASH delivery");
    match &script_owner.terms().buyer_delivery {
        Destination::Kcc20(o) => assert_eq!(o.identifier_type, IdentifierType::ScriptHash),
        other => panic!("vector 02 delivery: {other:?}"),
    }

    let custodian = kaspa_txscript::pay_to_script_hash_script(&[0x51; 71]);
    let w = World::with(Mode::new(true, CASH_KAS, REVOCABLE), |t, _| {
        t.buyer_delivery = Owner::script_hash([0x44; 32]);
        t.seller_proceeds_spk = spk_bytes(&custodian);
    });
    let mut spec = w.settle();
    spec.outputs[1].spk = custodian;
    spec.assert_all_accepted(&w, "deliveries to custodian scripts");
}

/// parity: EDGE-17 impossible
/// A forged record cannot sit at the agreed address: the address is the P2SH of the terms, so forged terms (an attacker's delivery) give another address, and that vault reveals the forged term to anyone who decodes it.
#[test]
fn edge17_forged_terms_get_another_address() {
    let agreed = assert_created(vector("01-"), "agreed terms");
    let attacker = script_hash_owner(0xA7);
    let mut forged = agreed.terms().clone();
    forged.buyer_delivery = attacker.clone();
    let forged = assert_created(forged, "forged terms");
    let ctx = creation_context(agreed.terms());
    for leg in LegIndex::ALL {
        let real = Vault::instantiate_for_creation(&agreed, leg, &ctx).expect("agreed");
        let fake = Vault::instantiate_for_creation(&forged, leg, &ctx).expect("forged");
        assert_ne!(vault_address(&real), vault_address(&fake), "{leg:?}");
        let (decoded, _) = decode(fake.vault().redeem_script()).expect("decodes");
        assert_eq!(decoded.terms().buyer_delivery, attacker, "{leg:?}");
    }
}

/// parity: EDGE-18 partial
/// There is no address to take first: an address exists only as the hash of full terms, so other terms under the same nonce get another one; and the terms' JSON form carries each u64 as a decimal string, exact above 2^53.
#[test]
fn edge18_no_squatting_and_exact_u64() {
    let json = vector_json("09-");
    let terms = vector("09-");
    assert!(terms.nonce > 1 << 53 && terms.asset_leg.amount > 1 << 53);
    assert_eq!(json["terms"]["nonce"], terms.nonce.to_string());
    assert_eq!(
        json["terms"]["asset_leg"]["amount"],
        terms.asset_leg.amount.to_string()
    );
    assert_eq!(
        json["terms"]["cash_leg"]["amount"],
        terms.cash_leg.amount.to_string()
    );

    let real = assert_created(vector("01-"), "the parties' terms");
    let mut squatter = real.terms().clone();
    squatter.buyer_key = real.terms().authority_key.expect("authority");
    squatter.authority_key = Some(real.terms().buyer_key);
    let squatter = assert_created(squatter, "a third party's terms, same nonce");
    assert_eq!(squatter.terms().nonce, real.terms().nonce);
    for leg in LegIndex::ALL {
        assert_ne!(
            vault_hash(&real, leg),
            vault_hash(&squatter, leg),
            "{leg:?}"
        );
    }
}

/// parity: EDGE-19 equivalent
/// Verifying is a recomputation, not a read of a stored record: the funder recomputes each leg's address from the agreed terms and compares, and a look-alike gets a stable code (forged terms VERIFY_ADDRESS_MISMATCH, the other leg's vault VERIFY_LEGS_SWAPPED, another network VERIFY_ADDRESS_NETWORK), a revealed script is accepted only as the agreed vault byte for byte (VERIFY_TERMS_MISMATCH, VERIFY_TEMPLATE_MISMATCH), and decoding refuses a script that is not an ImpulseVault; as on Solana, running the check before depositing is the funder's.
#[test]
fn edge19_look_alike_scripts_are_refused() {
    let terms = assert_created(vector("01-"), "control");
    let pinned = template::check().expect("startup check").hash();
    let vault = Vault::instantiate_existing(&terms, LegIndex::Asset).expect("vault");
    let script = vault.redeem_script().to_vec();
    assert_eq!(
        decode(&script).expect("decodes"),
        (terms.clone(), LegIndex::Asset)
    );
    assert_eq!(template_hash_of_instance(&script).expect("hash"), pinned);
    let mut alike = script.clone();
    *alike.last_mut().expect("suffix") ^= 0x01;
    assert_eq!(
        decode(&alike).expect_err("look-alike").code(),
        "TEMPLATE_NOT_IMPULSE_VAULT"
    );
    assert_ne!(template_hash_of_instance(&alike).expect("hash"), pinned);

    // The funder's check of the offered addresses against the agreed terms.
    let ctx = creation_context(terms.terms());
    let address = |t: &ValidatedTerms, leg| {
        vault_address(&Vault::instantiate_for_creation(t, leg, &ctx).expect("fundable"))
    };
    let (asset, cash) = (
        address(&terms, LegIndex::Asset),
        address(&terms, LegIndex::Cash),
    );
    let check = |asset: &str, cash: &str| {
        verify_addresses(
            &terms,
            &ctx,
            &OfferedAddresses {
                asset: Some(asset),
                cash: Some(cash),
            },
        )
    };
    let verified = check(&asset, &cash).expect("control: the agreed vaults");
    assert_eq!(verified.len(), 2);
    let mut forged = terms.terms().clone();
    forged.buyer_delivery = script_hash_owner(0xEE);
    let forged = assert_created(forged, "forged terms are structurally valid");
    let (forged_asset, forged_cash) = (
        address(&forged, LegIndex::Asset),
        address(&forged, LegIndex::Cash),
    );
    for (offered, code, label) in [
        (
            check(&forged_asset, &cash),
            "VERIFY_ADDRESS_MISMATCH",
            "forged terms",
        ),
        (
            check(&cash, &asset),
            "VERIFY_LEGS_SWAPPED",
            "the legs swapped",
        ),
    ] {
        assert_eq!(offered.expect_err(label).code(), code, "{label}");
    }
    assert_ne!(forged_cash, cash);
    let testnet = Address::new(Prefix::Testnet, Version::ScriptHash, &vault.script_hash());
    assert_eq!(
        check(&testnet.to_string(), &cash)
            .expect_err("another network")
            .code(),
        "VERIFY_ADDRESS_NETWORK"
    );

    // The check of a revealed script: the agreed vault byte for byte, nothing else.
    verify_revealed_script(&terms, LegIndex::Asset, &script).expect("control: the agreed script");
    let forged_script = Vault::instantiate_existing(&forged, LegIndex::Asset).expect("forged");
    for (offered, code, label) in [
        (
            forged_script.redeem_script(),
            "VERIFY_TERMS_MISMATCH",
            "forged terms",
        ),
        (
            alike.as_slice(),
            "VERIFY_TEMPLATE_MISMATCH",
            "a look-alike template",
        ),
    ] {
        let refused = verify_revealed_script(&terms, LegIndex::Asset, offered);
        assert_eq!(refused.expect_err(label).code(), code, "{label}");
    }
}

/// parity: EDGE-20 divergent
/// Solana refuses amount-changing mint extensions at Create and accepts freeze, pause, permanent delegate and the like as trusted-authority risks; the terms may name any KCC-20 template and the vault limits none of its powers beyond refusing a minter escrow ([E6]) and a delivery that is not exactly the agreed amount, so verify reports the powers to the funder as data (TOKEN_MINTER_BRANCH for the pinned kcc20.sil build, TOKEN_PARTY_IS_ISSUER for the seller, the buyer or the authority among the issuer keys supplied, with its relation to each leg: depositor, counterparty or authority) and refuses a pinned build whose artifact declares an extra entry (VERIFY_TOKEN_ARTIFACT_INVALID).
#[test]
fn edge20_issuer_powers_are_the_named_templates() {
    // Nothing in the terms restricts the asset to the test token's template.
    let mut any = vector("01-");
    match &mut any.asset_leg.kind {
        LegKind::Kcc20(token) => {
            token.template_hash = [0x77; 32];
            token.template_prefix_len = 17;
            token.template_suffix_len = 23;
        }
        _ => unreachable!("vector 01 has a KCC-20 asset"),
    }
    assert_created(any, "terms naming a template no test runs");

    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let minter = Kcc20State {
        is_minter: true,
        ..w.asset_escrow_state()
    };
    set_asset_escrow(&w, &mut faulty, minter);
    let minter_out = Kcc20State {
        is_minter: true,
        ..stranger(0)
    };
    deliver_asset(&w, &mut faulty, &[w.delivered_asset(), minter_out]);
    assert_flips(&w, &control, &faulty, 0, "minter escrow");

    // The funder's side: the issuer powers verify reports, as data.
    let terms = real_terms_of(Mode::new(true, CASH_KAS, REVOCABLE));
    let genuine = artifact_json(ASSET_TOKEN);
    let read = |keys: &[[u8; 32]], json: &str| {
        let evidence = TokenEvidence {
            artifact_json: json,
            issuer_keys: keys,
        };
        token_warnings(&terms, Some(&evidence), None)
    };
    let warn = |kind| TokenWarning {
        leg: LegIndex::Asset,
        kind,
    };
    assert_eq!(
        read(&[], &genuine).expect("control"),
        vec![
            warn(TokenWarningKind::MinterBranch),
            warn(TokenWarningKind::IssuerUnknown)
        ]
    );
    let authority = terms.terms().authority_key.expect("authority");
    assert_eq!(
        read(&[authority], &genuine).expect("authority among the issuers"),
        vec![
            warn(TokenWarningKind::MinterBranch),
            warn(TokenWarningKind::PartyIsIssuer {
                party: Party::Authority,
                relation: Relation::Authority,
            })
        ]
    );
    assert_eq!(
        read(&[[0x5E; 32]], &genuine).expect("a stranger among the issuers"),
        vec![warn(TokenWarningKind::MinterBranch)]
    );
    // Every party, on both legs: a KCC-20 cash leg too, so each party is the depositor of one
    // leg and the counterparty of the other.
    let both = real_terms_of(Mode::new(true, CASH_KCC20, REVOCABLE));
    let (seller, buyer) = (both.terms().seller_key, both.terms().buyer_key);
    let authority = both.terms().authority_key.expect("authority");
    let cash_json = artifact_json(CASH_TOKEN);
    let read_both = |keys: &[[u8; 32]]| {
        let asset = TokenEvidence {
            artifact_json: &genuine,
            issuer_keys: keys,
        };
        let cash = TokenEvidence {
            artifact_json: &cash_json,
            issuer_keys: keys,
        };
        token_warnings(&both, Some(&asset), Some(&cash))
    };
    let on = |leg, party, relation| TokenWarning {
        leg,
        kind: TokenWarningKind::PartyIsIssuer { party, relation },
    };
    let minter = |leg| TokenWarning {
        leg,
        kind: TokenWarningKind::MinterBranch,
    };
    let (asset_leg, cash_leg) = (LegIndex::Asset, LegIndex::Cash);
    assert_eq!(
        read_both(&[seller, buyer, authority]).expect("all three among the issuers"),
        vec![
            minter(asset_leg),
            on(asset_leg, Party::Seller, Relation::Depositor),
            on(asset_leg, Party::Buyer, Relation::Counterparty),
            on(asset_leg, Party::Authority, Relation::Authority),
            minter(cash_leg),
            on(cash_leg, Party::Seller, Relation::Counterparty),
            on(cash_leg, Party::Buyer, Relation::Depositor),
            on(cash_leg, Party::Authority, Relation::Authority),
        ]
    );
    assert_eq!(
        read_both(&[buyer]).expect("the buyer alone"),
        vec![
            minter(asset_leg),
            on(asset_leg, Party::Buyer, Relation::Counterparty),
            minter(cash_leg),
            on(cash_leg, Party::Buyer, Relation::Depositor),
        ]
    );
    assert_eq!(
        read_both(&[[0x5E; 32]]).expect("a stranger alone"),
        vec![minter(asset_leg), minter(cash_leg)]
    );

    // A pinned build whose artifact declares an extra entry (a clawback) is not that build.
    let compiled = ASSET_TOKEN.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
    let mut doctored = compiled.artifact.clone();
    doctored
        .contracts
        .get_mut(&compiled.name)
        .expect("contract")
        .entries
        .insert(
            "clawback".into(),
            silverscript_abi::SilEntryArtifact {
                dispatch_tag: [0xC1, 0xA7, 0xB4, 0xCC].into(),
                params: vec![],
            },
        );
    doctored
        .check_consistency()
        .expect("passes the compiler's own check");
    let json = serde_json::to_string(&doctored).expect("artifact serializes");
    assert_eq!(
        read(&[], &json).expect_err("doctored").code(),
        "VERIFY_TOKEN_ARTIFACT_INVALID"
    );
}

/// parity: EDGE-21 divergent
/// There is no hook and no extra-account list: the delivery must be the escrow's own template, the one the terms name, rebuilt with the agreed state, so a delivery under another template is refused and the vault resolves nothing off chain, and verify reads the named token's shape before funding (the pinned build declares exactly the transfer leader and delegate; a template with both KCC-20 entries but the minter flag's field renamed, a template with the KCC-20 state fields and neither entry, and the KCC20Minter controller, are VERIFY_TOKEN_NOT_KCC20); whether a named template's transfers can later be blocked is that template's.
#[test]
fn edge21_no_transfer_hooks() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let other = Token {
        max_cov_outs: 4,
        ..ASSET_TOKEN
    };
    let mut faulty = control.clone();
    faulty.outputs[0] = Out::token(
        other.compile(w.delivered_asset()),
        ASSET_COV,
        w.asset_escrow_idx() as u16,
    );
    assert_flips(&w, &control, &faulty, 0, "delivery under another template");

    // The funder's side. The pinned build reads, and declares exactly the two KCC-20 entries.
    let terms = real_terms_of(Mode::new(true, CASH_KAS, REVOCABLE));
    let compiled = ASSET_TOKEN.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
    let entries: Vec<&str> = compiled.artifact.contracts[&compiled.name]
        .entries
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(entries, KCC20_ENTRIES);
    let LegKind::Kcc20(asset) = terms.terms().asset_leg.kind else {
        unreachable!("the asset leg is KCC-20")
    };
    assert!(pinned_kcc20(&TemplateTriple::from(&asset)).is_some());
    let json = artifact_json(ASSET_TOKEN);
    let read = |terms: &_, json: &str| {
        let evidence = TokenEvidence {
            artifact_json: json,
            issuer_keys: &[],
        };
        token_warnings(terms, Some(&evidence), None)
    };
    read(&terms, &json).expect("control: the pinned build");

    // Fault 1: a template with both KCC-20 entries but the minter flag's field renamed, named by
    // the terms, is refused: its shape differs from the pinned build only in its state.
    let renamed = renamed_state_kcc20();
    let json = serde_json::to_string(&renamed.artifact).expect("artifact serializes");
    let refused = read(&naming(&terms, &renamed), &json).expect_err("renamed state field");
    assert_eq!(refused.code(), "VERIFY_TOKEN_NOT_KCC20");

    // Fault 2: a template with the four KCC-20 state fields and neither KCC-20 entry, named by
    // the terms, is refused: its shape differs from the pinned build only in its entries.
    let spend_only = spend_only_template();
    let json = serde_json::to_string(&spend_only.artifact).expect("artifact serializes");
    let refused = read(&naming(&terms, &spend_only), &json).expect_err("no KCC-20 entries");
    assert_eq!(refused.code(), "VERIFY_TOKEN_NOT_KCC20");

    // Fault 3: a template that is not KCC-20 at all, named by the terms, is refused.
    let minter = minter_controller();
    let json = serde_json::to_string(&minter.artifact).expect("artifact serializes");
    let refused = read(&naming(&terms, &minter), &json).expect_err("not a KCC-20 token");
    assert_eq!(refused.code(), "VERIFY_TOKEN_NOT_KCC20");
}

/// parity: EDGE-22 impossible
/// Dust cannot block settlement: outputs create new UTXOs, so no recipient must exist beforehand, and dust sent to a vault is a separate UTXO that cannot join the settle ([E1]) and goes home through the depositor's refund.
#[test]
fn edge22_dust_cannot_block_settlement() {
    let w = World::new(Mode::new(false, CASH_KCC20, REVOCABLE));
    let control = w.settle();
    let dust = Kcc20State::new(Owner::script_hash(w.asset_vault.script_hash()), 1);
    let escrow = w.asset_escrow_idx();
    let mut faulty = control.clone();
    let at = faulty.inputs.len() - 1;
    faulty.inputs.insert(
        at,
        In::token_delegate(ASSET_TOKEN.compile(dust), ASSET_COV, 0),
    );
    leader_states(&mut faulty, escrow).push(stranger(1));
    faulty.outputs.push(Out::token(
        ASSET_TOKEN.compile(stranger(1)),
        ASSET_COV,
        escrow as u16,
    ));
    let (tx, entries) = faulty.build(&w);
    assert_accepted(
        &execute(&tx, &entries, escrow),
        "the KCC-20 leader is valid",
    );
    assert_accepted(&execute(&tx, &entries, at), "the KCC-20 delegate is valid");
    assert_flips(&w, &control, &faulty, 0, "dust swept along the settle");

    let mut home = w.refund(ASSET_LEG, Role::Seller);
    refund_asset_escrow(&mut home, dust, Kcc20State::new(SELLER_REFUND, 1));
    home.assert_all_accepted(&w, "the dust goes home with a fresh authorizer");
}

/// parity: EDGE-23 impossible
/// Settle moves each leg in a single transfer and has no surplus to return: delivering the asset to the buyer in two outputs is refused.
#[test]
fn edge23_no_second_transfer_in_settle() {
    let w = World::new(Mode::new(true, CASH_KAS, REVOCABLE));
    let control = w.settle();
    let mut faulty = control.clone();
    let parts = [
        Kcc20State::new(BUYER_DELIVERY, AMOUNT_A - 1),
        Kcc20State::new(BUYER_DELIVERY, 1),
    ];
    deliver_asset(&w, &mut faulty, &parts);
    assert_accepted(
        &faulty.run(&w, w.asset_escrow_idx()),
        "the KCC-20 transfer itself is valid",
    );
    assert_flips(&w, &control, &faulty, 0, "asset delivered in two outputs");
}

/// parity: EDGE-24 impossible
/// There is no program ID to deploy to or to get wrong: every vault is the P2SH of an instance of the template pinned in contracts/TEMPLATE_HASH, checked against that pin before any use, and each instance's recomputed template hash is that pin.
#[test]
fn edge24_no_program_deployment() {
    let text = std::fs::read_to_string(repo_path("contracts/TEMPLATE_HASH")).expect("pin");
    let pinned: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text.trim()[i..i + 2], 16).expect("hex"))
        .collect();
    let hash = template::check().expect("startup check").hash();
    assert_eq!(hash.as_slice(), pinned.as_slice());
    let mut vaults = 0;
    for n in 1..=11 {
        let terms: ValidatedTerms = vector(&format!("{n:02}-"))
            .validate_structure()
            .expect("vector");
        for leg in LegIndex::ALL {
            if let Ok(vault) = Vault::instantiate_existing(&terms, leg) {
                let of_instance = template_hash_of_instance(vault.redeem_script()).expect("hash");
                assert_eq!(of_instance, hash, "vector {n} {leg:?}");
                vaults += 1;
            }
        }
    }
    assert_eq!(vaults, 16, "every vault of the golden vectors");
}

/// parity: EDGE-25 equivalent
/// Revocable funding behaves as Reclaim. Earmarked funding blocks only the depositor's own early withdrawal ([R3]): either party can still abort at once by sending the other party's leg home, as can the authority, and from expiry_daa the depositor's refund races a late settle (EDGE-11).
#[test]
fn edge25_earmarked_funding_blocks_only_the_depositors_withdrawal() {
    let revocable = World::new(Mode::new(true, CASH_KCC20, REVOCABLE));
    let anytime = revocable.refund(ASSET_LEG, Role::Seller);
    assert_eq!(anytime.lock_time, 0);
    anytime.assert_all_accepted(&revocable, "revocable: the seller withdraws at once");

    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    let control = w.refund(ASSET_LEG, Role::Seller);
    assert_eq!(control.lock_time, EXPIRY_DAA);
    let mut early = control.clone();
    early.lock_time = EXPIRY_DAA - 1;
    assert_flips_locktime(
        &w,
        &control,
        &early,
        0,
        "earmarked: the seller one DAA early",
    );
    for signer in [Role::Buyer, Role::Authority] {
        let spec = w.refund(ASSET_LEG, signer);
        assert_eq!(spec.lock_time, 0);
        spec.assert_all_accepted(&w, &format!("earmarked: {signer:?} sends the leg home"));
    }
}
