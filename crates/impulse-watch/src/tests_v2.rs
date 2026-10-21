// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template v2 trades in the watcher (I16, spec/V2.md 6.5): terms files v2, every leg's vault
//! watched, spends read with the v2 entries at `[S1]` and `[R4]`, a v2 leg reported as its
//! index in events and in the state file. Trades come from the frozen terms v2 vectors (public
//! keys only). No test holds a key: a vault spend's signature push is stand-in bytes, and the
//! fake source plays consensus. Each refusal has an accepted control beside it.

use super::phase2::{code_of, run_args, write_signed_tx, TempDir};
use super::*;
use crate::entry::{REFUND_TAG_V2, SETTLE_TAG_V2};
use crate::files::parse_terms_file;
use crate::persist;
use crate::run::prepare;
use crate::trades::TradeTerms;
use impulse_core::v2::{ValidatedTermsV2, VaultV2};

fn vector_v2(n: u8) -> &'static str {
    match n {
        2 => include_str!("../../../tests/vectors/terms_v2/02-three-way-kcc20-kcc20-kas.json"),
        3 => include_str!("../../../tests/vectors/terms_v2/03-ten-leg-bilateral.json"),
        6 => include_str!("../../../tests/vectors/terms_v2/06-partial-min-lot-one.json"),
        _ => panic!("no fixture for terms v2 vector {n}"),
    }
}

fn terms_v2(n: u8) -> ValidatedTermsV2 {
    let v: serde_json::Value = serde_json::from_str(vector_v2(n)).unwrap();
    ValidatedTermsV2::decode(&unhex(v["canonical"].as_str().unwrap())).unwrap()
}

fn file_v2(n: u8, hash: Option<&str>) -> String {
    let v: serde_json::Value = serde_json::from_str(vector_v2(n)).unwrap();
    json!({
        "terms": v["terms"],
        "canonical": v["canonical"],
        "terms_hash": hash.map_or(v["terms_hash"].clone(), |h| json!(h)),
    })
    .to_string()
}

fn vault_v2(t: &ValidatedTermsV2, leg: usize) -> VaultV2 {
    VaultV2::instantiate_existing(t, leg).unwrap()
}

/// `settle(authSig, lots)` of a v2 vault: the signature, the lots, the v2 tag, the script.
fn settle_v2(v: &VaultV2, value: u64) -> In {
    In {
        sig: push_all(&[&SIG, &[1], &SETTLE_TAG_V2, v.redeem_script()]),
        spends: utxo(value, v.script_public_key()),
    }
}

/// `refund(s, signerLeg)` of a v2 vault.
fn refund_v2(v: &VaultV2, value: u64) -> In {
    In {
        sig: push_all(&[&SIG, &[0], &REFUND_TAG_V2, v.redeem_script()]),
        spends: utxo(value, v.script_public_key()),
    }
}

fn testnet_watcher(depth: u64) -> Watcher {
    Watcher::new(Network::Testnet, FinalityPolicy::new(depth).unwrap())
}

/// The kinds and legs of `events`, as `<kind> <leg JSON>`.
fn kinds(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .map(|e| {
            let j = e.to_json();
            format!("{} {}", j["event"].as_str().unwrap(), j["leg"])
        })
        .collect()
}

#[tokio::test]
async fn a_v2_trade_is_watched_leg_by_leg_and_settles_in_one_transaction() {
    let t = terms_v2(2);
    let kas_amount = t.terms().legs[2].asset.amount;
    let vaults: Vec<VaultV2> = (0..3).map(|i| vault_v2(&t, i)).collect();
    let mut w = testnet_watcher(10);
    let id = w.add_trade(t.clone()).unwrap().trade;
    assert_eq!(id, TradeId(t.terms_hash()));
    let node = Node::new();
    // One funding transaction per leg, as the v2 fund builders make them.
    let fund = tx(
        1,
        vec![plain_in()],
        vec![
            (50_000_000, vaults[0].script_public_key()),
            (50_000_000, vaults[1].script_public_key()),
            (kas_amount, vaults[2].script_public_key()),
        ],
    );
    let e = accept_one(&mut w, &node, fund).await;
    assert_eq!(
        kinds(&e),
        ["authorizer_seen 0", "authorizer_seen 1", "funded 2"]
    );
    assert_eq!(e[2].to_json()["exact"], json!(true));
    // The settle: vault i at input i, the escrows and a fee input after them.
    let settle = tx(
        2,
        vec![
            settle_v2(&vaults[0], 50_000_000),
            settle_v2(&vaults[1], 50_000_000),
            settle_v2(&vaults[2], kas_amount),
            plain_in(),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let e = accept_one(&mut w, &node, settle).await;
    assert_eq!(kinds(&e), ["settled 0", "settled 1", "settled 2"]);
    let j = e[2].to_json();
    assert_eq!(j["trade"], json!(id.to_string()));
    assert_eq!(j["leg"], json!(2));
    assert_eq!(j["input"], json!(2));
    assert!(j.get("code").is_none());
}

#[tokio::test]
async fn v2_spends_are_read_with_the_v2_entries_at_their_inputs() {
    let t = terms_v2(2);
    let kas_amount = t.terms().legs[2].asset.amount;
    let vaults: Vec<VaultV2> = (0..3).map(|i| vault_v2(&t, i)).collect();
    let mut w = testnet_watcher(10);
    w.add_trade(t).unwrap();
    let node = Node::new();
    // [S1]: a settle of leg 1 at input 0, and at input 2.
    let e = accept_one(
        &mut w,
        &node,
        tx(10, vec![settle_v2(&vaults[1], 1)], vec![]),
    )
    .await;
    assert_eq!(kinds(&e), ["unclassified_spend 1"]);
    assert_eq!(e[0].to_json()["code"], json!("WATCH_SPEND_UNCLASSIFIED"));
    let e = accept_one(
        &mut w,
        &node,
        tx(
            11,
            vec![plain_in(), plain_in(), settle_v2(&vaults[1], 1)],
            vec![],
        ),
    )
    .await;
    assert_eq!(kinds(&e), ["unclassified_spend 1"]);
    // The v1 settle tag on a v2 vault is no v2 entry.
    let v1_tag = In {
        sig: push_all(&[&SIG, &SETTLE_TAG, vaults[0].redeem_script()]),
        spends: utxo(1, vaults[0].script_public_key()),
    };
    let e = accept_one(&mut w, &node, tx(12, vec![v1_tag], vec![])).await;
    assert_eq!(kinds(&e), ["unclassified_spend 0"]);
    // [S5] without partial: a KAS leg settles only from the exact amount.
    let e = accept_one(
        &mut w,
        &node,
        tx(
            13,
            vec![
                plain_in(),
                plain_in(),
                settle_v2(&vaults[2], kas_amount + 1),
            ],
            vec![],
        ),
    )
    .await;
    assert_eq!(kinds(&e), ["unclassified_spend 2"]);
    // Controls: the exact KAS settle at input 2; a refund at input 0, not at input 1.
    let e = accept_one(
        &mut w,
        &node,
        tx(
            14,
            vec![plain_in(), plain_in(), settle_v2(&vaults[2], kas_amount)],
            vec![],
        ),
    )
    .await;
    assert_eq!(kinds(&e), ["settled 2"]);
    let e = accept_one(
        &mut w,
        &node,
        tx(15, vec![refund_v2(&vaults[1], 7)], vec![]),
    )
    .await;
    assert_eq!(kinds(&e), ["refunded 1"]);
    let e = accept_one(
        &mut w,
        &node,
        tx(16, vec![plain_in(), refund_v2(&vaults[0], 7)], vec![]),
    )
    .await;
    assert_eq!(kinds(&e), ["unclassified_spend 0"]);
}

#[tokio::test]
async fn a_partial_v2_kas_leg_settles_whole_lots_from_any_amount() {
    let t = terms_v2(6);
    let amount = t.terms().legs[1].asset.amount;
    let cash = vault_v2(&t, 1);
    let mut w = mainnet_watcher(10);
    w.add_trade(t).unwrap();
    let node = Node::new();
    // The vault script checked the lots; the watcher reports the settle whatever it spent.
    let e = accept_one(
        &mut w,
        &node,
        tx(20, vec![plain_in(), settle_v2(&cash, amount / 4)], vec![]),
    )
    .await;
    assert_eq!(kinds(&e), ["settled 1"]);
    // A funding of another amount is still flagged not exact.
    let e = accept_one(
        &mut w,
        &node,
        tx(
            21,
            vec![plain_in()],
            vec![(amount / 4, cash.script_public_key())],
        ),
    )
    .await;
    assert_eq!(kinds(&e), ["funded 1"]);
    assert_eq!(e[0].to_json()["code"], json!("WATCH_FUNDING_NOT_EXACT"));
}

#[test]
fn terms_files_v2_are_read_and_checked() {
    match parse_terms_file("v2.json", &file_v2(2, None)).unwrap() {
        TradeTerms::V2(t) => assert_eq!(t.terms().legs.len(), 3),
        TradeTerms::V1(_) => panic!("a terms file v2 read as v1"),
    }
    let wrong = "00".repeat(32);
    assert_eq!(
        code_of(parse_terms_file("v2.json", &file_v2(2, Some(&wrong)))),
        "WATCH_TERMS_FILE_INCONSISTENT"
    );
    // Canonical bytes that start with 2 but are not terms v2.
    let bad = json!({"terms": {}, "canonical": "02ff", "terms_hash": wrong}).to_string();
    assert_eq!(
        code_of(parse_terms_file("bad.json", &bad)),
        "WATCH_TERMS_FILE_INVALID"
    );
    // Terms v2 of another network.
    let mut w = testnet_watcher(10);
    assert_eq!(
        w.add_trade(terms_v2(3)).unwrap_err().code(),
        "WATCH_NETWORK_MISMATCH"
    );
    w.add_trade(terms_v2(2)).unwrap();
    assert_eq!(
        w.add_trade(terms_v2(2)).unwrap_err().code(),
        "WATCH_TRADE_DUPLICATE"
    );
}

#[test]
fn a_v2_settle_is_kept_for_rebroadcast_with_its_trades_expiry() {
    let t = terms_v2(2);
    let vaults: Vec<VaultV2> = (0..3).map(|i| vault_v2(&t, i)).collect();
    let mut w = testnet_watcher(10);
    w.add_trade(t.clone()).unwrap();
    let settle = tx(
        30,
        vec![
            settle_v2(&vaults[0], 1),
            settle_v2(&vaults[1], 1),
            settle_v2(&vaults[2], 1),
            plain_in(),
        ],
        vec![],
    );
    assert_eq!(
        w.trades().claimed_settle_expiry(settle.tx()),
        Some(t.terms().expiry_daa)
    );
    w.keep_signed(settle.tx().clone()).unwrap();
    // A v2 settle at the wrong inputs claims nothing and is not kept.
    let off = tx(31, vec![plain_in(), settle_v2(&vaults[0], 1)], vec![]);
    assert_eq!(
        w.keep_signed(off.tx().clone()).unwrap_err().code(),
        "WATCH_TX_NOT_TRACKED"
    );
}

#[tokio::test]
async fn the_state_file_keeps_a_v2_leg_as_its_index() {
    let t = terms_v2(3);
    let last = vault_v2(&t, 9);
    let mut w = mainnet_watcher(10);
    w.add_trade(t.clone()).unwrap();
    let node = Node::new();
    let amount = t.terms().legs[9].asset.amount;
    let e = accept_one(
        &mut w,
        &node,
        tx(
            40,
            vec![plain_in()],
            vec![(amount, last.script_public_key())],
        ),
    )
    .await;
    assert_eq!(kinds(&e), ["funded 9"]);
    let text = persist::encode(w.state(), Network::Mainnet);
    assert!(text.contains("\"leg\": 9"), "{text}");
    let back = persist::decode(&text, Network::Mainnet).unwrap();
    assert_eq!(persist::encode(&back, Network::Mainnet), text);
    // A v2 leg index is below MAX_LEGS; anything else is refused.
    for bad in ["\"leg\": 10", "\"leg\": \"9\""] {
        let edited = text.replace("\"leg\": 9", bad);
        assert_eq!(
            code_of(persist::decode(&edited, Network::Mainnet)),
            "WATCH_STATE_INVALID"
        );
    }
}

#[test]
fn the_binary_takes_a_terms_file_v2_and_a_v2_settle_to_keep() {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    let path = dir.file("ten.json");
    std::fs::write(&path, file_v2(3, None)).unwrap();
    a.trades = vec![path];
    let t = terms_v2(3);
    let inputs = (0..10).map(|i| settle_v2(&vault_v2(&t, i), 1)).collect();
    let settle = tx(50, inputs, vec![]);
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];
    let prepared = prepare(&a).unwrap();
    assert_eq!(prepared.watcher.trades().len(), 1);
    assert!(prepared.watcher.is_kept(&settle.tx().id()));
}
