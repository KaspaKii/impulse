// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Tests added by review round 5 (the second review of phase 2; see the I8 brief, "Review"): the
//! de-duplication key of an event must be unique across episodes, not only within one round.
//! Each fix has a failing test beside an accepted control. No test holds a key: vault spends
//! carry stand-in signature bytes.

use super::phase2::{run_args, write_signed_tx, Both, TempDir};
use super::*;
use crate::persist;
use crate::run::{drive, prepare, Prepared};
use serde_json::Value;
use std::time::Duration;

/// What a consumer de-duplicates on (spec/WATCH.md, "Rounds"), with or without the round.
/// Without it is the key of review round 4, which this round found to repeat across episodes.
fn key(e: &Value, with_round: bool) -> String {
    let field = |k: &str| e.get(k).map(Value::to_string).unwrap_or_default();
    let mut names: Vec<&str> = if with_round { vec!["round"] } else { vec![] };
    names.extend(if e["event"] == "rebroadcast" {
        vec!["event", "txid", "outcome", "attempt"]
    } else {
        vec![
            "event",
            "of",
            "trade",
            "leg",
            "output",
            "input",
            "txid",
            "accepting_block",
        ]
    });
    names.iter().map(|k| field(k)).collect::<Vec<_>>().join("|")
}

/// The keys that occur more than once among `events`.
fn repeated(events: &[Value], with_round: bool) -> Vec<String> {
    let mut keys: Vec<String> = events.iter().map(|e| key(e, with_round)).collect();
    keys.sort();
    let mut repeats: Vec<String> = keys
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| w[0].clone())
        .collect();
    repeats.dedup();
    repeats
}

/// One poll of the binary's logic, and the events it printed.
async fn one_round(p: &mut Prepared, node: &Both<'_>) -> Vec<Value> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(p, node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn kinds(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e.get("of") {
            Some(of) => format!("{} {}", e["event"].as_str().unwrap(), of.as_str().unwrap()),
            None => e["event"].as_str().unwrap().to_string(),
        })
        .collect()
}

fn rounds(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| e["round"].as_str().unwrap().to_string())
        .collect()
}

/// Funding accepted at block 2 and final at block 3, taken out by a side branch (a reorg of an
/// acceptance already reported final), and accepted again, final again, when the chain returns
/// to block 3. The state text before the last round is kept, as a crash would leave it.
async fn funding_accepted_final_reorged_and_accepted_again() -> (Vec<Value>, Vec<Value>, String) {
    let dir = TempDir::new();
    let KasTrade { funding, .. } = kas_trade(10);
    let a = run_args(&dir);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    assert!(one_round(&mut p, &node).await.is_empty(), "the bootstrap");

    let mut all = Vec::new();
    source.extend(block(2), 101, vec![funding]);
    all.extend(one_round(&mut p, &node).await);
    source.extend(block(3), 111, vec![]);
    all.extend(one_round(&mut p, &node).await);
    source.add_block(block(12), block(1), 102, vec![]);
    source.set_sink(block(12));
    all.extend(one_round(&mut p, &node).await);

    let before_last = std::fs::read_to_string(&a.state).unwrap();
    source.set_sink(block(3));
    let last = one_round(&mut p, &node).await;
    all.extend(last.clone());
    (all, last, before_last)
}

/// The defect: a transaction accepted again after a reorg repeated the key of its first
/// acceptance, and so did its `final`, so a consumer that de-duplicated on the key dropped the
/// second acceptance and ended on `reorg` for a transaction that is accepted.
#[tokio::test]
async fn a_transaction_accepted_again_after_a_reorg_has_keys_of_its_own() {
    let (all, last, _) = funding_accepted_final_reorged_and_accepted_again().await;
    assert_eq!(
        kinds(&all),
        [
            "authorizer_seen",
            "funded",
            "final authorizer_seen",
            "final funded",
            "reorg authorizer_seen",
            "reorg funded",
            "authorizer_seen",
            "funded",
            "final authorizer_seen",
            "final funded",
        ]
    );
    // One number per round that reported anything: 1 accepted, 2 final, 3 reorg, 4 accepted again.
    assert_eq!(
        rounds(&all),
        ["1", "1", "2", "2", "3", "3", "4", "4", "4", "4"]
    );
    assert_eq!(rounds(&last), ["4", "4", "4", "4"]);
    // Without the round the four events of the second acceptance repeat the first's keys, which
    // is what a consumer would have dropped; with it every event of the run has a key of its own.
    assert_eq!(repeated(&all, false).len(), 4);
    assert_eq!(repeated(&all, true), Vec::<String>::new());
    // Control: within one round the old key was already unique, and the reorg between the two
    // acceptances is a different event whichever key is used.
    for round in ["1", "2", "3", "4"] {
        let one: Vec<Value> = all
            .iter()
            .filter(|e| e["round"] == round)
            .cloned()
            .collect();
        assert_eq!(repeated(&one, false), Vec::<String>::new(), "round {round}");
    }
}

/// A round that reports nothing is not counted, and the count is in the state file, saved after
/// the round's events are printed: a crash between the two repeats the round under the same
/// number (so with the same keys), and the next round that reports something has the next one.
#[tokio::test]
async fn a_round_replayed_after_a_crash_keeps_its_number_and_the_next_one_moves_on() {
    let dir = TempDir::new();
    let KasTrade { funding, .. } = kas_trade(10);
    let mut a = run_args(&dir);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);

    let mut p = prepare(&a).unwrap();
    assert!(one_round(&mut p, &node).await.is_empty());
    let saved = std::fs::read_to_string(&a.state).unwrap();
    assert_eq!(
        persist::decode(&saved, Network::Mainnet).unwrap().round(),
        0
    );
    // A block with nothing for the watcher: a round with nothing to report is not counted, and
    // the state file records only the cursor.
    source.extend(block(2), 101, vec![]);
    assert!(one_round(&mut p, &node).await.is_empty());
    let quiet = std::fs::read_to_string(&a.state).unwrap();
    assert_eq!(
        persist::decode(&quiet, Network::Mainnet).unwrap().round(),
        0
    );

    source.extend(block(3), 102, vec![funding]);
    let first = one_round(&mut p, &node).await;
    assert_eq!(rounds(&first), ["1", "1"]);
    let after = std::fs::read_to_string(&a.state).unwrap();
    assert_eq!(
        persist::decode(&after, Network::Mainnet).unwrap().round(),
        1
    );
    drop(p);

    // The process died after printing and before saving: the state file is the previous round's.
    std::fs::write(&a.state, &quiet).unwrap();
    a.init = false;
    let mut p = prepare(&a).unwrap();
    let replay = one_round(&mut p, &node).await;
    assert_eq!(replay, first, "the same events under the same round number");
    let keys = |e: &[Value]| e.iter().map(|e| key(e, true)).collect::<Vec<_>>();
    assert_eq!(keys(&replay), keys(&first));
    assert_eq!(std::fs::read_to_string(&a.state).unwrap(), after);

    // Control: with the state saved, the same walk is not reported again and nothing is counted;
    // the next round that reports something is the second.
    assert!(one_round(&mut p, &node).await.is_empty());
    assert_eq!(std::fs::read_to_string(&a.state).unwrap(), after);
    source.add_block(block(12), block(2), 103, vec![]);
    source.set_sink(block(12));
    let reorg = one_round(&mut p, &node).await;
    assert_eq!(kinds(&reorg), ["reorg authorizer_seen", "reorg funded"]);
    assert_eq!(rounds(&reorg), ["2", "2"]);
}

/// The same state text with the round count taken out (or added to a state that never had one)
/// is not a state: the reader is strict.
#[test]
fn the_round_count_is_part_of_the_state_file() {
    let dir = TempDir::new();
    let p = prepare(&run_args(&dir)).unwrap();
    let text = persist::encode(p.watcher.state(), Network::Mainnet);
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["round"], "0");
    let mut with = v.clone();
    with["round"] = serde_json::json!("7");
    let state = persist::decode(&with.to_string(), Network::Mainnet).unwrap();
    assert_eq!(state.round(), 7);
    assert_eq!(
        serde_json::from_str::<Value>(&persist::encode(&state, Network::Mainnet)).unwrap(),
        with
    );
    let mut without = v.clone();
    without.as_object_mut().unwrap().remove("round");
    let e = persist::decode(&without.to_string(), Network::Mainnet).unwrap_err();
    assert_eq!(e.code(), "WATCH_STATE_INVALID");
    for bad in [
        serde_json::json!(7),
        serde_json::json!("07"),
        serde_json::json!("-1"),
        serde_json::json!("18446744073709551616"),
        serde_json::json!(null),
    ] {
        let mut v = v.clone();
        v["round"] = bad.clone();
        let e = persist::decode(&v.to_string(), Network::Mainnet).unwrap_err();
        assert_eq!(e.code(), "WATCH_STATE_INVALID", "{bad}");
    }
}

/// The defect for a rebroadcast: a kept settle taken out by two reorgs and submitted each time
/// made the same key `rebroadcast|txid|submitted|1` twice.
#[tokio::test]
async fn a_settle_rebroadcast_after_each_of_two_reorgs_has_a_key_each_time() {
    let dir = TempDir::new();
    let KasTrade {
        funding, settle, ..
    } = kas_trade(10);
    let mut a = run_args(&dir);
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    assert!(one_round(&mut p, &node).await.is_empty());

    let mut all = Vec::new();
    source.extend(block(2), 101, vec![funding]);
    source.extend(block(3), 102, vec![settle.clone()]);
    all.extend(one_round(&mut p, &node).await);
    // A branch from block 2 takes the settle out; the node takes it again, and the chain accepts
    // it at block 14. A second branch takes it out again.
    source.add_block(block(13), block(2), 103, vec![]);
    source.set_sink(block(13));
    all.extend(one_round(&mut p, &node).await);
    source.add_block(block(14), block(13), 104, vec![settle]);
    source.set_sink(block(14));
    all.extend(one_round(&mut p, &node).await);
    source.add_block(block(15), block(13), 105, vec![]);
    source.set_sink(block(15));
    all.extend(one_round(&mut p, &node).await);

    assert_eq!(
        kinds(&all),
        [
            "authorizer_seen",
            "funded",
            "settled",
            "settled",
            "reorg settled",
            "reorg settled",
            "rebroadcast",
            "settled",
            "settled",
            "reorg settled",
            "reorg settled",
            "rebroadcast",
        ]
    );
    let sent: Vec<&Value> = all.iter().filter(|e| e["event"] == "rebroadcast").collect();
    assert_eq!(sent.len(), 2);
    for s in &sent {
        assert_eq!(s["outcome"], "submitted");
        assert_eq!(s["attempt"], 1);
    }
    assert_eq!(bcast.submitted().len(), 2);
    // Without the round the two rebroadcasts are one key; with it, every event of the run is its
    // own.
    assert_eq!(
        repeated(&all, false),
        [key(sent[0], false)],
        "the two rebroadcasts share the old key"
    );
    assert_eq!(repeated(&all, true), Vec::<String>::new());
    assert_eq!(sent[0]["round"], "2");
    assert_eq!(sent[1]["round"], "4");
}
