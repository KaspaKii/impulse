// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Tests added by review round 4 (see the I8 brief, "Review"). Each fix has a failing test
//! beside an accepted control. No test holds a key: vault spends carry stand-in signature bytes.

use super::phase2::{code_of, run_args, through_text, write_signed_tx, Both, TempDir};
use super::*;
use crate::persist;
use crate::run::{drive, prepare, round};
use crate::WatchState;
use serde_json::Value;
use std::time::Duration;

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn encode(w: &Watcher) -> String {
    persist::encode(w.state(), Network::Mainnet)
}

/// The state through its text and back: it must decode, and encode to the same text.
fn restarts(text: &str) -> WatchState {
    let state = persist::decode(text, Network::Mainnet)
        .unwrap_or_else(|e| panic!("the state file does not restart: {e}\n{text}"));
    assert_eq!(
        persist::encode(&state, Network::Mainnet),
        text,
        "round trip"
    );
    state
}

// ---- retiring a trade must leave a state that restarts ----

/// A settle of trade A's asset vault that also pays trade B's asset vault. Retiring A leaves it
/// accepted for B alone, with nothing to settle: it must lose its accepted copy and its settle
/// expiry, or the state file it is written to is refused at the next start.
#[tokio::test]
async fn retiring_the_spent_trade_of_a_transaction_that_also_funds_another_leaves_a_state_that_restarts(
) {
    let node = Node::new();
    let (mut w, ida, idb, [a_asset, _, b_asset, _], names) = two_trades();
    let t = tx(
        70,
        vec![settle_in(&a_asset, AUTH), plain_in()],
        vec![(AUTH, b_asset.script_public_key())],
    );
    let tid = id(&t);
    w.keep_signed(t.tx().clone()).unwrap();
    let e = accept_one(&mut w, &node, t).await;
    assert_eq!(
        brief(&e, &names),
        [
            "accepted authorizer_seen B/asset",
            "accepted settled A/asset"
        ]
    );

    // Control: before the retire the state restarts, with the accepted copy and the expiry.
    let before = parse(&encode(&w));
    restarts(&encode(&w));
    assert!(before["accepted"][0]["tx"].is_string());
    assert!(before["accepted"][0]["settle_expiry"].is_string());
    assert_eq!(before["kept"], json!([tid.to_string()]));

    w.retire_trade(ida).unwrap();
    let after_text = encode(&w);
    restarts(&after_text);
    let after = parse(&after_text);
    assert_eq!(after["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(after["accepted"][0]["tx"], Value::Null);
    assert_eq!(after["accepted"][0]["settle_expiry"], Value::Null);
    assert_eq!(after["kept"], json!([]));
    assert!(!w.is_kept(&tid));

    // The restarted watcher goes on: the reorg reports B's funding and rebroadcasts nothing.
    let mut again = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(10).unwrap(),
        persist::decode(&after_text, Network::Mainnet).unwrap(),
    );
    let tb = terms(1);
    again.add_trade(repeat_of(&tb)).unwrap();
    node.chain.add_block(block(11), block(0), 100, vec![]);
    node.chain.set_sink(block(11));
    let e = again.poll(&node.chain).await.unwrap();
    assert_eq!(brief(&e, &names), ["reorg authorizer_seen B/asset"]);
    assert!(again.pending_rebroadcasts().is_empty());
    let _ = idb;
}

/// A kept settle of trade A's asset vault (expiry E) and trade B's cash vault (expiry E + 1000),
/// accepted at E - 3 and reorged out by a branch whose tip is at E. With both trades watched it
/// is held back (the earlier expiry). With A retired, B's expiry is the one that counts, and it
/// is submitted, whether A is retired before the reorg or while the rebroadcast is pending.
async fn two_trade_settle_reorged_at_the_earlier_expiry(
    retire_a: Option<bool>,
) -> (u64, TransactionId, Vec<Event>, Vec<TransactionId>) {
    let a = terms(1);
    let expiry = a.terms().expiry_daa;
    let ida = TradeId(a.terms_hash());
    let mut b = repeat_of(&a).terms().clone();
    b.expiry_daa = expiry + 1_000;
    let b = b.validate_structure().unwrap();
    let mixed = tx(
        65,
        vec![
            settle_in(&vault(&a, LegIndex::Asset), AUTH),
            settle_in(&vault(&b, LegIndex::Cash), AUTH),
            plain_in(),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let mut w = mainnet_watcher(10);
    w.add_trade(a).unwrap();
    w.add_trade(b).unwrap();
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    let mixed_id = w.keep_signed(mixed.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![mixed]);
    assert_eq!(w.poll(&source).await.unwrap().len(), 2);
    if retire_a == Some(false) {
        w.retire_trade(ida).unwrap();
        // The recomputed expiry is B's, in the state file.
        let v = parse(&encode(&w));
        assert_eq!(
            v["accepted"][0]["settle_expiry"],
            json!((expiry + 1_000).to_string())
        );
        restarts(&encode(&w));
    }
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry, vec![]);
    source.set_sink(block(13));
    let reorged = w.poll(&source).await.unwrap();
    assert_eq!(reorged.len(), if retire_a == Some(false) { 1 } else { 2 });
    if retire_a == Some(true) {
        w.retire_trade(ida).unwrap();
        let v = parse(&encode(&w));
        assert_eq!(
            v["pending"][0]["settle_expiry"],
            json!((expiry + 1_000).to_string())
        );
        restarts(&encode(&w));
    }
    let r = drain(&mut w, &node).await;
    (expiry, mixed_id, r, node.submitted())
}

#[tokio::test]
async fn retiring_the_earlier_trade_of_a_two_trade_settle_moves_its_expiry_to_the_later() {
    // Control: nothing retired, the settle is held back at the earlier expiry.
    let (expiry, mixed_id, r, submitted) =
        two_trade_settle_reorged_at_the_earlier_expiry(None).await;
    assert_eq!(r[0].to_json()["outcome"], "skipped_past_expiry");
    assert_eq!(r[0].to_json()["expiry_daa"], json!(expiry.to_string()));
    assert!(submitted.is_empty());

    for pending_when_retired in [false, true] {
        let (_, mixed_id2, r, submitted) =
            two_trade_settle_reorged_at_the_earlier_expiry(Some(pending_when_retired)).await;
        assert_eq!(mixed_id2, mixed_id);
        assert_eq!(r.len(), 1, "{pending_when_retired}");
        assert_eq!(
            r[0].to_json()["outcome"],
            "submitted",
            "{pending_when_retired}"
        );
        assert_eq!(submitted, vec![mixed_id]);
    }
}

/// A retired external-cash trade no longer flags deposits to its cash-vault script: an effect
/// naming a retired trade would make the state file unreadable.
#[tokio::test]
async fn a_retired_external_cash_trade_no_longer_flags_a_stray_deposit_and_the_state_restarts() {
    let t = terms(5);
    let asset = vault(&t, LegIndex::Asset);
    let stray = pay_to_script_hash_script(&stray_cash_script(asset.redeem_script()).unwrap());
    let mut w = mainnet_watcher(10);
    let trade = w.add_trade(t).unwrap().trade;
    let names = HashMap::from([(trade, "X")]);
    let source = started(&mut w).await;
    // Control: a deposit before the retire is flagged and the state restarts.
    let first = tx(56, vec![plain_in()], vec![(2_000, stray.clone())]);
    source.extend(block(2), 101, vec![first]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(brief(&e, &names), ["accepted stray_deposit X"]);
    restarts(&encode(&w));

    w.retire_trade(trade).unwrap();
    assert_eq!(w.accepted_len(), 0);
    let later = tx(57, vec![plain_in()], vec![(3_000, stray)]);
    source.extend(block(3), 102, vec![later]);
    let e = w.poll(&source).await.unwrap();
    assert!(e.is_empty(), "{e:?}");
    restarts(&encode(&w));
    assert_eq!(parse(&encode(&w))["trades"], json!([]));
}

// ---- random operations leave a state file that restarts and resumes ----

/// xorshift64*: a fixed generator, so a failing seed is a reproducible run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// A block on the sink accepting these pool transactions.
    Mine {
        txs: Vec<usize>,
        daa_step: u64,
    },
    /// A branch of `len` blocks from the block `back` below the sink, accepting `txs` in its
    /// first block; the branch tip becomes the sink.
    Reorg {
        back: usize,
        len: usize,
        txs: Vec<usize>,
    },
    Keep(usize),
    Poll,
    Drain {
        refuse: bool,
    },
    Retire(usize),
    SetLimit(usize),
}

/// The pool of transactions the random runs draw from, over trades A and B (expiry + 25).
struct Pool {
    txs: Vec<AcceptedTransaction>,
    trade_terms: [ValidatedTerms; 2],
    start_daa: u64,
}

fn pool() -> Pool {
    let a = terms(1);
    let expiry = a.terms().expiry_daa;
    let mut b = repeat_of(&a).terms().clone();
    b.expiry_daa = expiry + 25;
    let b = b.validate_structure().unwrap();
    let seller = a.terms().seller_key;
    let (aa, ac) = (vault(&a, LegIndex::Asset), vault(&a, LegIndex::Cash));
    let (ba, bc) = (vault(&b, LegIndex::Asset), vault(&b, LegIndex::Cash));
    let txs = vec![
        // 0: fundings of both asset vaults
        tx(
            200,
            vec![plain_in()],
            vec![
                (AUTH, aa.script_public_key()),
                (AUTH, ba.script_public_key()),
            ],
        ),
        // 1: A asset and B cash in one settle (cross-trade)
        tx(
            201,
            vec![
                settle_in(&aa, AUTH),
                settle_in(&bc, AUTH),
                plain_in(),
                plain_in(),
                plain_in(),
            ],
            vec![(1_000, stranger())],
        ),
        // 2: both legs of A
        tx(
            202,
            vec![
                settle_in(&aa, AUTH),
                settle_in(&ac, AUTH),
                plain_in(),
                plain_in(),
            ],
            vec![(1_000, stranger())],
        ),
        // 3: both legs of B
        tx(
            203,
            vec![
                settle_in(&ba, AUTH),
                settle_in(&bc, AUTH),
                plain_in(),
                plain_in(),
            ],
            vec![(1_000, stranger())],
        ),
        // 4: A's asset settle that also pays B's asset vault
        tx(
            204,
            vec![settle_in(&aa, AUTH), plain_in()],
            vec![(AUTH, ba.script_public_key())],
        ),
        // 5: A's asset refund
        tx(
            205,
            vec![refund_in(&aa, seller, AUTH), plain_in()],
            vec![(1_000, stranger())],
        ),
        // 6: B's cash refund paying A's cash vault
        tx(
            206,
            vec![refund_in(&bc, b.terms().seller_key, AUTH)],
            vec![(AUTH, ac.script_public_key())],
        ),
        // 7: nothing of ours
        tx(207, vec![plain_in()], vec![(500, stranger())]),
    ];
    Pool {
        txs,
        trade_terms: [a, b],
        start_daa: expiry - 20,
    }
}

/// Operations from `seed`. The generator follows the sink chain as `play` does, so that a
/// transaction is never accepted twice on one chain (a valid chain never shows that).
fn random_ops(seed: u64, n: usize, pool_len: usize) -> Vec<Op> {
    use std::collections::HashSet;
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    // The pool transactions accepted by each block of the sink chain, oldest first.
    let mut chain: Vec<HashSet<usize>> = vec![HashSet::new(), HashSet::new()];
    let fresh = |rng: &mut Rng, chain: &[HashSet<usize>]| -> Vec<usize> {
        let mut taken: HashSet<usize> = chain.iter().flatten().copied().collect();
        let mut out = Vec::new();
        for _ in 0..1 + rng.below(3) {
            // Half the picks come from the transactions that spend one trade's vault and pay
            // another's, the shapes a retirement leaves half-owned.
            let i = if rng.below(2) == 0 {
                [1, 4, 6][rng.below(3) as usize]
            } else {
                rng.below(pool_len as u64) as usize
            };
            if taken.insert(i) {
                out.push(i);
            }
        }
        out
    };
    let mut ops = Vec::new();
    let mut retired = [false; 2];
    while ops.len() < n {
        let op = match rng.below(14) {
            0..=3 => {
                let txs = fresh(&mut rng, &chain);
                chain.push(txs.iter().copied().collect());
                Op::Mine {
                    txs,
                    daa_step: 1 + rng.below(4),
                }
            }
            4 | 5 => {
                let back = rng.below(4) as usize;
                let len = 1 + rng.below(3) as usize;
                let fork = chain.len() - 1 - back.min(chain.len() - 1);
                chain.truncate(fork + 1);
                let txs = fresh(&mut rng, &chain);
                for k in 0..len {
                    chain.push(if k == 0 {
                        txs.iter().copied().collect()
                    } else {
                        HashSet::new()
                    });
                }
                Op::Reorg { back, len, txs }
            }
            6 | 7 => Op::Keep(rng.below(pool_len as u64) as usize),
            8..=10 => Op::Poll,
            11 => Op::Drain {
                refuse: rng.below(3) == 0,
            },
            12 => {
                let which = rng.below(2) as usize;
                if retired[which] {
                    continue;
                }
                retired[which] = true;
                Op::Retire(which)
            }
            _ => Op::SetLimit(1 + rng.below(3) as usize),
        };
        ops.push(op);
    }
    ops
}

/// Plays `ops` on a watcher over the pool's two trades and returns every event printed (as
/// JSON text), the state text after every op, and whether `restart` is on: the watcher is
/// rebuilt from its state text after every op, as the binary is on every start.
async fn play(ops: &[Op], restart: bool) -> (Vec<String>, Vec<String>) {
    let pool = pool();
    let depth = 8;
    let mut w = mainnet_watcher(depth);
    let mut live = [true, true];
    for t in &pool.trade_terms {
        w.add_trade(t.clone()).unwrap();
    }
    let source = FakeVirtualChainSource::new(block(0), pool.start_daa);
    source.extend(block(1), pool.start_daa + 1, vec![]);
    w.poll(&source).await.unwrap();
    // Block numbers and DAA scores of the sink chain, oldest first: (number, daa).
    let mut chain = vec![(0u64, pool.start_daa), (1, pool.start_daa + 1)];
    let mut next_block = 2u64;
    let (mut events, mut states) = (Vec::new(), Vec::new());
    let json_of = |events: &mut Vec<String>, e: &[Event]| {
        events.extend(e.iter().map(|e| e.to_json().to_string()));
    };
    for op in ops {
        match op {
            Op::Mine { txs, daa_step } => {
                let daa = chain.last().unwrap().1 + daa_step;
                let n = next_block;
                next_block += 1;
                source.extend(
                    block(n),
                    daa,
                    txs.iter().map(|i| pool.txs[*i].clone()).collect(),
                );
                chain.push((n, daa));
            }
            Op::Reorg { back, len, txs } => {
                let fork = chain.len() - 1 - (*back).min(chain.len() - 1);
                let mut parent = chain[fork];
                chain.truncate(fork + 1);
                for k in 0..*len {
                    let n = next_block;
                    next_block += 1;
                    let daa = parent.1 + 1;
                    let accepted = if k == 0 {
                        txs.iter().map(|i| pool.txs[*i].clone()).collect()
                    } else {
                        vec![]
                    };
                    source.add_block(block(n), block(parent.0), daa, accepted);
                    chain.push((n, daa));
                    parent = (n, daa);
                }
                source.set_sink(block(parent.0));
            }
            Op::Keep(i) => {
                let _ = w.keep_signed(pool.txs[*i].tx().clone());
            }
            Op::Poll => {
                // A poll can be refused only by a failed node call; the fake has none queued.
                let e = w.poll(&source).await.unwrap();
                json_of(&mut events, &e);
            }
            Op::Drain { refuse } => {
                let node = if *refuse {
                    FakeBroadcaster::refusing("busy")
                } else {
                    FakeBroadcaster::default()
                }
                .at_virtual_daa(chain.last().unwrap().1);
                let e = drain(&mut w, &node).await;
                json_of(&mut events, &e);
            }
            Op::Retire(which) => {
                let trade = TradeId(pool.trade_terms[*which].terms_hash());
                w.retire_trade(trade).unwrap();
                live[*which] = false;
            }
            Op::SetLimit(limit) => source.set_added_limit(*limit),
        }
        let text = encode(&w);
        states.push(text.clone());
        if restart {
            let state = restarts(&text);
            w = Watcher::with_state(Network::Mainnet, FinalityPolicy::new(depth).unwrap(), state);
            for (i, t) in pool.trade_terms.iter().enumerate() {
                if live[i] {
                    w.add_trade(t.clone()).unwrap();
                }
            }
        }
    }
    (events, states)
}

/// Random sequences of mining, reorgs, keeping, polls, rebroadcasts and retirements. After
/// every operation the state text decodes and encodes to itself (a state the binary writes is a
/// state it can start from), and a watcher restarted from its text after every operation
/// reports exactly what one that never restarted reports, and holds the same state.
#[tokio::test]
async fn random_operations_leave_a_state_that_restarts_and_resumes_the_same() {
    let pool_len = pool().txs.len();
    for seed in 1..=16u64 {
        let ops = random_ops(seed, 30, pool_len);
        let (events_a, states_a) = play(&ops, false).await;
        let (events_b, states_b) = play(&ops, true).await;
        assert_eq!(
            events_a, events_b,
            "seed {seed}: events differ across restarts\n{ops:?}"
        );
        assert_eq!(
            states_a, states_b,
            "seed {seed}: states differ across restarts\n{ops:?}"
        );
    }
}

// ---- the expiry guard reads the node's own clock ----

/// Trade 2 with a kept settle accepted at E - 3 and reorged out by a branch whose blocks are
/// added one per walk (the node's batch limit): the cursor stays behind a sink far above the
/// settle's expiry E. Returns the watcher, the source and the settle's id.
async fn settle_reorged_while_the_walk_is_behind(
) -> (Watcher, FakeVirtualChainSource, TransactionId, u64) {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let expiry = terms(2).terms().expiry_daa;
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry - 2, vec![]);
    source.add_block(block(14), block(13), expiry + 500, vec![]);
    source.set_sink(block(14));
    source.set_added_limit(1);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(e.len(), 2, "the reorg of the settle");
    assert_eq!(
        cursor_of(&w).map(|c| c.1),
        Some(Some(expiry - 3)),
        "the walk stopped short of the sink"
    );
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);
    (w, source, settle_id, expiry)
}

#[tokio::test]
async fn a_settle_is_held_back_by_the_nodes_own_clock_while_the_walk_is_behind() {
    // The node is past the expiry; the walk's last block is not.
    let (mut w, _source, settle_id, expiry) = settle_reorged_while_the_walk_is_behind().await;
    let node = FakeBroadcaster::default().at_virtual_daa(expiry + 500);
    let r = drain(&mut w, &node).await;
    assert_eq!(
        r.iter().map(Event::to_json).collect::<Vec<_>>(),
        [json!({
            "event": "rebroadcast",
            "txid": settle_id.to_string(),
            "outcome": "skipped_past_expiry",
            "expiry_daa": expiry.to_string(),
            "tip_daa": (expiry + 500).to_string(),
            "code": "WATCH_REBROADCAST_PAST_EXPIRY"
        })]
    );
    assert!(node.submitted().is_empty());
    assert!(w.pending_rebroadcasts().is_empty());

    // Control: a node still before the expiry is asked, and takes the settle.
    let (mut w, _source, settle_id, expiry) = settle_reorged_while_the_walk_is_behind().await;
    let node = FakeBroadcaster::default().at_virtual_daa(expiry - 1);
    let r = drain(&mut w, &node).await;
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(node.submitted(), vec![settle_id]);
    assert_eq!(node.daa_reads(), 1);
}

/// The same after a downtime: the state file's cursor is far behind the chain, the pending
/// rebroadcast is due on the first round, and the guard must not take the stale cursor for the
/// tip.
#[tokio::test]
async fn a_settle_is_held_back_on_the_first_round_after_a_downtime() {
    let (w, source, settle_id, expiry) = settle_reorged_while_the_walk_is_behind().await;
    let mut w = through_text(w, 10);
    let bcast = FakeBroadcaster::default().at_virtual_daa(expiry + 500);
    let both = super::phase2::Both::new(&source, &bcast);
    let events = round(&mut w, &both).await.unwrap();
    let rebroadcasts: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, Event::Rebroadcast { .. }))
        .collect();
    assert_eq!(rebroadcasts.len(), 1);
    assert_eq!(rebroadcasts[0].to_json()["outcome"], "skipped_past_expiry");
    assert_eq!(rebroadcasts[0].txid(), settle_id);
    assert!(bcast.submitted().is_empty());
}

#[tokio::test]
async fn a_settle_is_not_submitted_when_the_nodes_clock_cannot_be_read() {
    let (mut w, source, settle_id, expiry) = settle_reorged_while_the_walk_is_behind().await;
    let node = FakeBroadcaster::default().unreadable_virtual_daa("get_block_dag_info: no answer");
    let r = drain(&mut w, &node).await;
    let j = r[0].to_json();
    assert_eq!(j["outcome"], "refused");
    assert_eq!(j["attempt"], 1);
    assert_eq!(j["code"], "WATCH_REBROADCAST_FAILED");
    assert!(j["reason"]
        .as_str()
        .unwrap()
        .contains("virtual DAA score could not be read"));
    assert!(j["reason"].as_str().unwrap().contains("no answer"));
    assert!(node.submitted().is_empty());
    assert_eq!(
        w.pending_rebroadcasts(),
        vec![settle_id],
        "tried again after the next poll"
    );
    // Control: the clock readable and before the expiry, the next attempt (after the next poll)
    // submits, and it counts as the second.
    let node = FakeBroadcaster::default().at_virtual_daa(expiry - 1);
    w.poll(&source).await.unwrap();
    let r = drain(&mut w, &node).await;
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(r[0].to_json()["attempt"], 2);
    assert_eq!(node.submitted(), vec![settle_id]);
}

/// A refund is submitted whatever the tip, so the node's clock is not even read for it.
#[tokio::test]
async fn a_refund_does_not_ask_the_node_for_its_clock() {
    let KasTrade { mut w, .. } = kas_trade(10);
    let t = terms(2);
    let expiry = t.terms().expiry_daa;
    let asset = vault(&t, LegIndex::Asset);
    let refund = tx(
        51,
        vec![refund_in(&asset, t.terms().seller_key, AUTH), plain_in()],
        vec![],
    );
    let source = FakeVirtualChainSource::new(block(0), expiry + 10);
    source.extend(block(1), expiry + 11, vec![]);
    w.poll(&source).await.unwrap();
    let refund_id = w.keep_signed(refund.tx().clone()).unwrap();
    source.extend(block(2), expiry + 12, vec![refund]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), expiry + 12, vec![]);
    source.set_sink(block(12));
    w.poll(&source).await.unwrap();
    let node = FakeBroadcaster::default().unreadable_virtual_daa("down");
    let r = drain(&mut w, &node).await;
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(node.submitted(), vec![refund_id]);
    assert_eq!(node.daa_reads(), 0);
}

// ---- a node that remembers the settle as accepted is not a refusal ----

#[tokio::test]
async fn a_node_that_only_remembers_the_settle_as_accepted_is_asked_again_without_using_up_attempts(
) {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let settle_id = id(&settle);
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle.clone()]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.set_sink(block(12));
    w.poll(&source).await.unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);

    // More waits than the cap: none abandons, each is reported as a refusal that used no attempt.
    let waits = REBROADCAST_ATTEMPTS as usize + 2;
    let node = FakeBroadcaster::recently_accepted_first(waits);
    for k in 0..waits {
        let r = drain(&mut w, &node).await;
        assert_eq!(
            r.iter().map(Event::to_json).collect::<Vec<_>>(),
            [json!({
                "event": "rebroadcast",
                "txid": settle_id.to_string(),
                "outcome": "refused",
                "attempt": 0,
                "reason": "already accepted by the consensus",
                "code": "WATCH_REBROADCAST_FAILED"
            })],
            "wait {k}"
        );
        assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);
        assert!(
            drain(&mut w, &node).await.is_empty(),
            "one attempt per poll"
        );
        source.extend(block(20 + k as u64), 102 + k as u64, vec![]);
        w.poll(&source).await.unwrap();
    }
    // The node's record is gone: it takes the settle, as the first attempt that counts.
    let r = drain(&mut w, &node).await;
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(r[0].to_json()["attempt"], 1);
    assert!(w.pending_rebroadcasts().is_empty());
    assert_eq!(node.submitted().len(), waits + 1);

    // Control: refusals of its own do count, and the last is abandoned (the existing cap).
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.set_sink(block(12));
    w.poll(&source).await.unwrap();
    let node = FakeBroadcaster::refusing("mempool full");
    let mut last = None;
    for k in 0..REBROADCAST_ATTEMPTS as u64 {
        last = drain(&mut w, &node).await.pop();
        source.extend(block(30 + k), 102 + k, vec![]);
        w.poll(&source).await.unwrap();
    }
    assert_eq!(last.unwrap().to_json()["outcome"], "abandoned");
    assert!(w.pending_rebroadcasts().is_empty());
}

/// A node that is asked again after it said "already accepted" and then sees the chain accept
/// the settle again: the pending rebroadcast is dropped, not submitted.
#[tokio::test]
async fn a_settle_the_chain_accepts_again_while_the_node_says_already_accepted_is_not_submitted() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle.clone()]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.set_sink(block(12));
    w.poll(&source).await.unwrap();
    let node = FakeBroadcaster::recently_accepted_first(5);
    assert_eq!(drain(&mut w, &node).await.len(), 1);
    source.extend(block(13), 102, vec![settle]);
    w.poll(&source).await.unwrap();
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(node.submitted().len(), 1);
}

// ---- the URL checks are the CLI's, line for line ----

/// The one table both crates run: what `check_transport` does with each URL. The CLI's copy
/// (`crates/impulse-cli/src/node.rs`) runs the same file, so the two cannot drift apart.
#[test]
fn the_url_checks_agree_with_the_table_the_cli_runs() {
    use crate::node::check_transport;
    let table = include_str!("../../../tests/node-url-checks.txt");
    let mut rows = 0;
    for line in table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (url, expected) = line.split_once('\t').unwrap();
        let (mainnet, testnet) = (
            check_transport(url, Network::Mainnet).map_err(|e| e.code()),
            check_transport(url, Network::Testnet).map_err(|e| e.code()),
        );
        let (want_main, want_test) = match expected {
            "ok" => (Ok(()), Ok(())),
            "insecure" => (Err("WATCH_NODE_INSECURE"), Ok(())),
            "invalid" => (Err("WATCH_NODE_URL_INVALID"), Err("WATCH_NODE_URL_INVALID")),
            other => panic!("{other}"),
        };
        assert_eq!(mainnet, want_main, "mainnet {url}");
        assert_eq!(testnet, want_test, "testnet {url}");
        rows += 1;
    }
    assert!(rows > 25, "the table was read");
}

// ---- text from outside is shown escaped, and the node URL without its secrets ----

#[test]
fn a_node_url_is_shown_without_its_credentials_path_and_query() {
    use crate::node::{check_transport, redact_url};
    for (url, shown) in [
        ("ws://127.0.0.1:17110", "ws://127.0.0.1:17110"),
        ("wss://node.example:443", "wss://node.example:443"),
        (
            "wss://user:pw@node.example:443/path?key=1#f",
            "wss://***@node.example:443/...",
        ),
        ("ws://node.example/key-in-the-path", "ws://node.example/..."),
        ("ws://node.example?key=1", "ws://node.example/..."),
        ("ws://node.example#frag", "ws://node.example/..."),
        ("ws://a@b@node.example:1/x", "ws://***@node.example:1/..."),
        ("no-scheme/with/a-secret", "no-scheme/..."),
        ("", ""),
    ] {
        assert_eq!(redact_url(url), shown, "{url}");
    }
    // The refusals that echo the URL carry the redacted one.
    let secret = "SECRET-KEY";
    for url in [
        format!("http://user:{secret}@node.example/{secret}?k={secret}"),
        format!("ws://{secret}@203.0.113.9:17110/{secret}?k={secret}"),
    ] {
        let e = check_transport(&url, Network::Mainnet).unwrap_err();
        assert!(!e.to_string().contains(secret), "{e}");
    }
    // Control: the host stays, so the operator can tell which node was refused.
    let e = check_transport("ws://203.0.113.9:17110/key", Network::Mainnet).unwrap_err();
    assert!(e.to_string().contains("203.0.113.9:17110"), "{e}");
}

#[test]
fn text_from_the_remote_end_cannot_write_control_sequences_into_a_refusal() {
    use crate::node::unreachable;
    use crate::run::fatal_line;
    // A connection error that carries text from the other end is echoed escaped, the URL redacted.
    let e = unreachable(
        "ws://user:SECRET@node.example:17110/path",
        &"refused\u{1b}[2J\nsecond line",
    );
    let text = e.to_string();
    assert!(!text.contains('\u{1b}') && !text.contains('\n'), "{text:?}");
    assert!(
        text.contains("\\u{1b}[2J") && text.contains("\\n"),
        "{text:?}"
    );
    assert!(!text.contains("SECRET"), "{text:?}");
    assert!(text.contains("node.example:17110"), "{text:?}");

    // The line the binary prints for any refusal that ends it has none, whichever variant
    // carries the text raw.
    for e in [
        WatchError::SourceFailed("a\u{1b}[31mb\nc".into()),
        WatchError::NodeRpc("a\u{1b}[31mb\nc".into()),
        WatchError::ProbeFailed("a\u{1b}]0;t\u{7}\r".into()),
        WatchError::StateInvalid("a\u{1b}[31mb\nc".into()),
        WatchError::TermsFileInvalid {
            path: "p".into(),
            reason: "a\u{1b}[31mb\nc".into(),
        },
    ] {
        let line = fatal_line(&e);
        assert!(line.starts_with("impulse-watch: WATCH_"), "{line:?}");
        assert!(
            !line.chars().any(char::is_control),
            "{line:?} carries a control character"
        );
    }
    // Control: plain text is kept as it is.
    assert_eq!(
        fatal_line(&WatchError::NodeRpc("get_server_info: no answer".into())),
        "impulse-watch: WATCH_NODE_RPC: get_server_info: no answer"
    );
}

// ---- a walk of one chain: DAA scores rise ----

#[test]
fn a_walk_whose_chain_blocks_do_not_rise_in_daa_score_is_refused() {
    use super::phase2::{batch, response, v0};
    use crate::node::convert_walk;
    let (t0, s0) = v0();
    let walk = |first: u64, second: u64| {
        response(
            vec![],
            vec![block(1), block(2)],
            vec![
                batch(block(1), Some(first), vec![super::phase2::rpc_tx(&t0, &s0)]),
                batch(block(2), Some(second), vec![]),
            ],
        )
    };
    // Control: rising.
    assert!(convert_walk(&walk(100, 101)).is_ok());
    // The same score twice, and a score that falls.
    for (a, b) in [(100, 100), (101, 100)] {
        let e = convert_walk(&walk(a, b)).unwrap_err();
        assert!(e.0.contains("not above"), "{a} {b}: {}", e.0);
        assert!(e.0.contains(&block(2).to_string()), "{}", e.0);
    }
}

// ---- strict readers ----

#[test]
fn odd_length_hex_and_a_signed_decimal_are_refused_not_panicked_on() {
    use crate::files::{parse_dec, parse_signed_tx, unhex};
    assert_eq!(unhex("abc"), None);
    assert_eq!(unhex("a"), None);
    assert_eq!(unhex("ab"), Some(vec![0xab]));
    assert_eq!(unhex(""), Some(vec![]));
    assert_eq!(parse_dec("+5"), None);
    assert_eq!(parse_dec("-5"), None);
    assert_eq!(parse_dec("5"), Some(5));
    assert_eq!(
        code_of(parse_signed_tx("f", "abc")),
        "WATCH_SIGNED_TX_INVALID"
    );
    assert_eq!(
        code_of(parse_signed_tx("f", "abc\n")),
        "WATCH_SIGNED_TX_INVALID"
    );
}

// ---- the command line ----

#[test]
fn the_command_line_bounds_what_it_must() {
    use crate::cli::Cli;
    use clap::Parser;
    let base = [
        "impulse-watch",
        "run",
        "--network",
        "testnet",
        "--node",
        "ws://127.0.0.1:1",
        "--finality-depth",
        "5",
        "--state",
        "s.json",
    ];
    let parse = |extra: &[&str]| {
        let mut args: Vec<&str> = base.to_vec();
        args.extend(extra);
        Cli::try_parse_from(args)
    };
    let crate::cli::Command::Run(control) = parse(&["--max-polls", "1"]).unwrap().command else {
        panic!("run")
    };
    assert_eq!(control.max_polls, Some(1));
    // The poll interval is a mechanical default; a bound of 0 polls is not a bound.
    assert_eq!(control.poll_interval_ms, 1000);
    assert!(parse(&["--max-polls", "0"]).is_err());
    assert!(parse(&["--max-polls", "-1"]).is_err());
    let crate::cli::Command::Run(unbounded) = parse(&[]).unwrap().command else {
        panic!("run")
    };
    assert_eq!(unbounded.max_polls, None);
}

// ---- the run waits between polls ----

#[tokio::test]
async fn a_run_waits_the_interval_between_polls() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    // Three polls, two gaps: never less than two intervals (a sleep returns late, never early).
    let started = std::time::Instant::now();
    drive(
        &mut p,
        &node,
        Duration::from_millis(80),
        Some(3),
        &mut out,
        &mut err,
    )
    .await
    .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(160),
        "{:?}",
        started.elapsed()
    );
    // Control: no gap after the last poll, and none at all for an interval of 0.
    let started = std::time::Instant::now();
    drive(&mut p, &node, Duration::ZERO, Some(3), &mut out, &mut err)
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(160));
}

// ---- the retention window reaches the state file ----

/// A run of the binary's logic with `retention_daa`: the funding and a kept settle accepted at
/// DAA 101 and 102, final at 112, and 23 deep at 125. Returns the txids left in the state file.
async fn accepted_after(retention_daa: Option<u64>) -> (Vec<String>, String, String) {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    let KasTrade {
        funding, settle, ..
    } = kas_trade(10);
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];
    a.retention_daa = retention_daa;
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle.clone()]);
    source.extend(block(4), 112, vec![]);
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    source.extend(block(5), 125, vec![]);
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&a.state).unwrap()).unwrap();
    let txids = state["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["txid"].as_str().unwrap().to_string())
        .collect();
    (txids, id(&funding).to_string(), id(&settle).to_string())
}

#[tokio::test]
async fn the_retention_window_given_on_the_command_line_bounds_the_state_file() {
    // With a window of 20 the funding (24 deep, final) leaves the file and the kept settle stays.
    let (left, _funding, settle) = accepted_after(Some(20)).await;
    assert_eq!(left, [settle]);
    // Control: with no window nothing is evicted.
    let (left, funding, settle) = accepted_after(None).await;
    assert_eq!(left.len(), 2);
    assert!(left.contains(&funding) && left.contains(&settle));
    // Control: a window the funding has not reached keeps both.
    let (left, _, _) = accepted_after(Some(30)).await;
    assert_eq!(left.len(), 2);
}

// ---- the state file's exact form ----

/// The golden state: trade 2 from the start and trade 5 (external cash) added once polls had
/// run, so its `from` is a cursor; the funding of trade 2 and a settle of both its legs, two
/// deposits to trade 5's stray cash-vault script, a kept refund of trade 5 that a reorg removed
/// and a node refused once. Some acceptances final, some not.
async fn golden_watcher() -> Watcher {
    let KasTrade {
        mut w,
        funding,
        settle,
        ..
    } = kas_trade(5);
    let source = started(&mut w).await;
    let t5 = terms(5);
    let asset5 = vault(&t5, LegIndex::Asset);
    let stray5 = pay_to_script_hash_script(&stray_cash_script(asset5.redeem_script()).unwrap());
    let refund = tx(
        81,
        vec![refund_in(&asset5, t5.terms().seller_key, AUTH), plain_in()],
        vec![(1_000, stranger())],
    );
    let deposit1 = tx(82, vec![plain_in()], vec![(2_000, stray5.clone())]);
    let deposit2 = tx(83, vec![plain_in()], vec![(3_000, stray5)]);
    w.add_trade(t5).unwrap();
    w.keep_signed(settle.tx().clone()).unwrap();
    w.keep_signed(refund.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding]);
    source.extend(block(3), 102, vec![settle, deposit1]);
    source.extend(block(4), 103, vec![refund]);
    let first = w.poll(&source).await.unwrap();
    assert_eq!(w.close_round(&first), 1);
    source.add_block(block(14), block(3), 104, vec![]);
    source.add_block(block(15), block(14), 108, vec![deposit2]);
    source.set_sink(block(15));
    let mut second = w.poll(&source).await.unwrap();
    let node = FakeBroadcaster::refusing_first(&["mempool full"]);
    let r = drain(&mut w, &node).await;
    assert_eq!(r.len(), 1);
    // The reorg round and its refused rebroadcast are one round, the second that reported.
    second.extend(r);
    assert_eq!(w.close_round(&second), 2);
    w
}

const GOLDEN: &str = include_str!("../tests/golden/state-v1.json");
const GOLDEN_PATH: &str = "tests/golden/state-v1.json";

/// The state file's format is pinned by a file, not by the code that writes it: a rename of a
/// key, a field dropped or a changed spelling changes this text and fails here, instead of
/// stranding every state file already written. Regenerate with
/// `cargo test -p impulse-watch --lib regenerate_the_golden_state_file -- --ignored` only when
/// the format is meant to change (and bump its version).
#[tokio::test]
async fn the_state_file_is_the_golden_file_byte_for_byte() {
    let text = encode(&golden_watcher().await);
    assert_eq!(text, GOLDEN, "the state file's form changed");
    // Decoding the golden file and writing it again gives the same bytes.
    let state = restarts(GOLDEN);
    assert_eq!(persist::encode(&state, Network::Mainnet), GOLDEN);
    // What it holds, so the file cannot quietly shrink to something easier to keep.
    let v = parse(GOLDEN);
    assert_eq!(v["format"], "impulse-watch-state");
    assert_eq!(v["version"], 1);
    assert_eq!(v["round"], "2", "two rounds reported something");
    let froms: Vec<&Value> = v["trades"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| &t["from"])
        .collect();
    assert_eq!(froms.len(), 2);
    assert!(
        froms.iter().any(|f| f.is_null()),
        "a trade added at the start"
    );
    assert!(
        froms.iter().any(|f| f["daa"].is_string()),
        "a trade added once polls had run"
    );
    let kinds: Vec<&str> = v["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| a["effects"].as_array().unwrap())
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for kind in ["authorizer_seen", "funded", "settled", "stray_deposit"] {
        assert!(kinds.contains(&kind), "{kind} missing from {kinds:?}");
    }
    let flags: Vec<bool> = v["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["finalized"].as_bool().unwrap())
        .collect();
    assert!(flags.contains(&true) && flags.contains(&false));
    assert!(v["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["tx"].is_string() && a["settle_expiry"].is_string()));
    assert_eq!(v["kept"].as_array().unwrap().len(), 2);
    assert_eq!(v["pending"][0]["attempts"], 1);
    assert_eq!(v["pending"][0]["due"], false);
    assert_eq!(v["pending"][0]["settle_expiry"], Value::Null);
}

#[tokio::test]
#[ignore = "writes tests/golden/state-v1.json; run it only to change the format on purpose"]
async fn regenerate_the_golden_state_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_PATH);
    std::fs::write(path, encode(&golden_watcher().await)).unwrap();
}

/// Every nested object has exactly its keys, each with its own reason, and the strict spellings
/// hold in the nested places too. Each edit is one fault beside the golden file, which is the
/// accepted control.
#[test]
fn every_object_of_the_state_file_has_exactly_its_keys_and_the_strict_spellings() {
    let bad = |edit: &dyn Fn(&mut Value)| -> String {
        let mut v = parse(GOLDEN);
        edit(&mut v);
        match persist::decode(&v.to_string(), Network::Mainnet) {
            Err(WatchError::StateInvalid(reason)) => reason,
            other => panic!("expected WATCH_STATE_INVALID, got {other:?}"),
        }
    };
    assert!(persist::decode(GOLDEN, Network::Mainnet).is_ok());
    let golden = parse(GOLDEN);
    let accepted = golden["accepted"].as_array().unwrap();
    // The first accepted entry holding an effect of this kind.
    let find = |kind: &str| -> (usize, usize) {
        for (i, a) in accepted.iter().enumerate() {
            for (j, e) in a["effects"].as_array().unwrap().iter().enumerate() {
                if e["kind"] == kind {
                    return (i, j);
                }
            }
        }
        panic!("no {kind}");
    };

    // The document, a trade, a cursor and a trade's own cursor.
    assert!(bad(&|v| v["extra"] = json!(1)).contains(": unexpected key \"extra\""));
    assert!(bad(&|v| v["trades"][0]["extra"] = json!(1)).contains("trades[0]: unexpected key"));
    assert!(bad(&|v| v["trades"][1]["extra"] = json!(1)).contains("trades[1]: unexpected key"));
    // The sorted order of the golden file: the trade added after the first polls comes first.
    assert!(golden["trades"][0]["from"]["block"].is_string());
    assert_eq!(golden["trades"][1]["from"], Value::Null);
    assert!(bad(&|v| v["trades"][0]["from"]["extra"] = json!(1))
        .contains("trades[0].from: unexpected key"));
    assert!(bad(&|v| v["cursor"]["extra"] = json!(1)).contains("cursor: unexpected key"));
    assert!(bad(&|v| v["cursor"]
        .as_object_mut()
        .unwrap()
        .remove("daa")
        .map(|_| ())
        .unwrap())
    .contains("cursor: missing key daa"));
    // An accepted transaction and its effects, one of each kind.
    assert!(bad(&|v| v["accepted"][0]["extra"] = json!(1)).contains("accepted[0]: unexpected key"));
    for kind in ["authorizer_seen", "funded", "settled", "stray_deposit"] {
        let (i, j) = find(kind);
        let reason = bad(&|v| v["accepted"][i]["effects"][j]["extra"] = json!(1));
        assert!(
            reason.contains(&format!("accepted[{i}].effects[{j}]: unexpected key")),
            "{kind}: {reason}"
        );
        let reason = bad(&|v| {
            let e = v["accepted"][i]["effects"][j].as_object_mut().unwrap();
            let key = e
                .keys()
                .find(|k| *k != "kind" && *k != "trade")
                .cloned()
                .unwrap();
            e.remove(&key);
        });
        assert!(reason.contains("missing key"), "{kind}: {reason}");
    }
    // A pending rebroadcast.
    assert!(bad(&|v| v["pending"][0]["extra"] = json!(1)).contains("pending[0]: unexpected key"));
    assert!(bad(&|v| v["pending"][0]
        .as_object_mut()
        .unwrap()
        .remove("due")
        .map(|_| ())
        .unwrap())
    .contains("pending[0]: missing key due"));
    // Hex and numbers in their one spelling, in the nested places.
    assert!(bad(&|v| {
        let k = v["kept"][0].as_str().unwrap().to_uppercase();
        v["kept"][0] = json!(k);
    })
    .contains("kept[0]: expected 64 lowercase hex"));
    assert!(bad(&|v| v["kept"][0] = json!("abc")).contains("kept[0]: expected 64 lowercase hex"));
    assert!(bad(&|v| v["trades"][0]["from"]["daa"] = json!("+5")).contains("trades[0].from.daa"));
    assert!(bad(&|v| v["cursor"]["daa"] = json!("+5")).contains("cursor.daa"));
    assert!(bad(&|v| v["accepted"][0]["daa"] = json!("+101")).contains("accepted[0].daa"));
    assert!(bad(&|v| v["accepted"][0]["tx"] = json!("abc")).contains("accepted[0].tx"));
    assert!(bad(&|v| v["pending"][0]["tx"] = json!("abc")).contains("pending[0].tx"));
    // A u32 that does not fit: 2^32 + 1 is not index 1.
    let (i, j) = find("funded");
    assert!(
        bad(&|v| v["accepted"][i]["effects"][j]["index"] = json!(4_294_967_297u64))
            .contains("expected a u32")
    );
    let (i, j) = find("settled");
    assert!(
        bad(&|v| v["accepted"][i]["effects"][j]["input"] = json!(4_294_967_297u64))
            .contains("expected a u32")
    );
    assert!(
        bad(&|v| v["pending"][0]["attempts"] = json!(4_294_967_297u64)).contains("expected a u32")
    );
    // A settle expiry exactly when the transaction settles.
    let (i, _) = find("settled");
    assert!(bad(&|v| v["accepted"][i]["settle_expiry"] = Value::Null)
        .contains("a settle expiry exactly when it settles"));
    let (k, _) = find("funded");
    assert!(bad(&|v| v["accepted"][k]["settle_expiry"] = json!("5"))
        .contains("a settle expiry exactly when it settles"));
}

// ---- starting up ----

/// The order of the start-up refusals is the spec's: two faults at once give the earlier one.
/// Each pair is a failing case; the single faults and the accepted control are in
/// `prepare_refuses_in_order_and_accepts_the_control`.
#[test]
fn prepare_reports_the_earlier_of_two_faults() {
    let case = |edit: &dyn Fn(&mut crate::cli::RunArgs, &TempDir)| {
        let dir = TempDir::new();
        let mut a = run_args(&dir);
        edit(&mut a, &dir);
        code_of(prepare(&a).map(|_| ()))
    };
    let insecure = "ws://10.0.0.5:17110";
    let missing_terms: std::path::PathBuf = "/nonexistent/terms.json".into();
    // Depth, then retention, then the link, then the files.
    assert_eq!(
        case(&|a, _| {
            a.finality_depth = 0;
            a.retention_daa = Some(1);
            a.node = insecure.into();
        }),
        "WATCH_FINALITY_DEPTH_ZERO"
    );
    assert_eq!(
        case(&|a, _| {
            a.retention_daa = Some(10);
            a.node = insecure.into();
            a.trades.push(missing_terms.clone());
        }),
        "WATCH_RETENTION_TOO_SHORT"
    );
    assert_eq!(
        case(&|a, _| {
            a.node = insecure.into();
            a.trades.push(missing_terms.clone());
            a.keep_signed.push("/nonexistent/tx.hex".into());
        }),
        "WATCH_NODE_INSECURE"
    );
    // Files before the retire/watch clash, and the clash before the state file.
    assert_eq!(
        case(&|a, _| {
            a.trades.push(missing_terms.clone());
            a.retire.push(TradeId(terms(2).terms_hash()));
            std::fs::write(&a.state, "x").unwrap();
        }),
        "WATCH_FILE_READ"
    );
    assert_eq!(
        case(&|a, _| {
            a.retire.push(TradeId(terms(2).terms_hash()));
            std::fs::write(&a.state, "x").unwrap();
        }),
        "WATCH_RETIRE_WATCHED"
    );
    // The state file's place before the lock: a file that exists under --init is refused as
    // such even while another watcher holds it, and a missing one without --init likewise.
    let dir = TempDir::new();
    let mut held = run_args(&dir);
    held.init = true;
    let first = prepare(&held).unwrap();
    let mut second = run_args(&dir);
    second.init = false;
    assert_eq!(
        code_of(prepare(&second).map(|_| ())),
        "WATCH_STATE_MISSING",
        "nothing is created or locked next to a path that is not a state"
    );
    drop(first);
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    persist::write_atomic(
        &a.state,
        &persist::encode(&WatchState::default(), Network::Mainnet),
    )
    .unwrap();
    a.trades = vec![];
    a.init = false;
    let holder = prepare(&a).unwrap();
    a.init = true;
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_EXISTS");
    a.init = false;
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_LOCKED");
    drop(holder);
    // The lock before the state file's contents; the contents before the trades; adding trades
    // before retiring.
    std::fs::write(&a.state, "{}").unwrap();
    a.trades = vec![dir.file("trade2.json"), dir.file("trade2.json")];
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_INVALID");
    std::fs::write(
        &a.state,
        persist::encode(&WatchState::default(), Network::Mainnet),
    )
    .unwrap();
    a.retire = vec![TradeId([9; 32])];
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_TRADE_DUPLICATE");
    // Control: the duplicate gone, the unknown retire is what is left.
    a.trades.pop();
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_TRADE_UNKNOWN");
}

/// A mistyped state path starts nothing: no lock file next to it, and a missing directory is a
/// missing state file, not a write that failed on a file nobody named.
#[test]
fn a_mistyped_state_path_creates_nothing() {
    let dir = TempDir::new();
    let listing = |d: &TempDir| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let mut a = run_args(&dir);
    let before = listing(&dir);
    a.init = false;
    a.state = dir.file("nostate.json");
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_MISSING");
    assert_eq!(listing(&dir), before, "no lock file, no state file");
    // A directory that does not exist: missing, without --init ...
    a.state = dir.file("nodir").join("state.json");
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_MISSING");
    assert_eq!(listing(&dir), before);
    // ... and, with --init, a new state that cannot be written, naming the directory.
    a.init = true;
    let e = prepare(&a).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "WATCH_STATE_WRITE_FAILED");
    assert!(e.to_string().contains("nodir"), "{e}");
    assert!(e.to_string().contains("does not exist"), "{e}");
    assert_eq!(listing(&dir), before);
    // Control: a new state in a directory that exists starts.
    a.state = dir.file("state.json");
    assert!(prepare(&a).is_ok());
}

/// The lock file a run made goes with the run if it never started a state; one that was there
/// already, or sits beside a state file, stays.
#[test]
fn a_run_that_started_no_state_leaves_no_lock_file() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let lock = dir.file("state.json.lock");
    {
        let _p = prepare(&a).unwrap();
        assert!(lock.exists(), "held while the run lives");
    }
    assert!(!lock.exists(), "a run that saved nothing leaves nothing");

    // Control: a run that saved a state keeps the lock file beside it.
    {
        let mut p = prepare(&a).unwrap();
        let source = FakeVirtualChainSource::new(block(0), 99);
        source.extend(block(1), 100, vec![]);
        let bcast = FakeBroadcaster::default();
        let node = Both::new(&source, &bcast);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        futures_block_on(drive(
            &mut p,
            &node,
            Duration::ZERO,
            Some(1),
            &mut out,
            &mut err,
        ))
        .unwrap();
    }
    assert!(dir.file("state.json").exists());
    assert!(lock.exists());

    // Control: a lock file that was there before the run is not the run's to remove.
    let dir = TempDir::new();
    std::fs::write(dir.file("state.json.lock"), "").unwrap();
    {
        let _p = prepare(&run_args(&dir)).unwrap();
    }
    assert!(dir.file("state.json.lock").exists());
}

fn futures_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f)
}

/// What a crashed write left next to the state file is removed at the next start, and said.
#[test]
fn a_start_removes_the_temporary_files_an_earlier_crash_left() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    std::fs::write(dir.file(".state.json.tmp.123.456.7"), "an earlier state").unwrap();
    std::fs::write(dir.file(".other.json.tmp.1"), "not ours").unwrap();
    let p = prepare(&a).unwrap();
    assert!(!dir.file(".state.json.tmp.123.456.7").exists());
    assert!(dir.file(".other.json.tmp.1").exists());
    assert_eq!(p.notes.len(), 1);
    assert!(
        p.notes[0].contains("removed the leftover temporary state file"),
        "{:?}",
        p.notes
    );
    assert!(p.notes[0].contains(".state.json.tmp.123.456.7"));
}

// ---- retiring while the other trades are not (yet) added ----

/// Two trades, A (expiry E) and B (E + 1000), a settle of A's asset and B's cash vault accepted
/// at E - 3, and the watcher's state as a restart would find it.
async fn mixed_settle_state() -> (WatchState, u64, ValidatedTerms, ValidatedTerms) {
    let a = terms(1);
    let expiry = a.terms().expiry_daa;
    let mut b = repeat_of(&a).terms().clone();
    b.expiry_daa = expiry + 1_000;
    let b = b.validate_structure().unwrap();
    let mixed = tx(
        66,
        vec![
            settle_in(&vault(&a, LegIndex::Asset), AUTH),
            settle_in(&vault(&b, LegIndex::Cash), AUTH),
            plain_in(),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let mut w = mainnet_watcher(10);
    w.add_trade(a.clone()).unwrap();
    w.add_trade(b.clone()).unwrap();
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    source.extend(block(2), expiry - 3, vec![mixed]);
    assert_eq!(w.poll(&source).await.unwrap().len(), 2);
    (w.into_state(), expiry, a, b)
}

/// Retired while the other trade has not been added again, the settle of that other trade keeps
/// the earlier expiry it had: it can only be earlier than the true one, so it holds a settle
/// back and never lets one through. Added again first (as the binary does), it is exact.
#[tokio::test]
async fn retiring_a_trade_while_the_other_is_not_added_again_keeps_the_earlier_expiry() {
    let (state, expiry, a, b) = mixed_settle_state().await;
    let depth = FinalityPolicy::new(10).unwrap();
    let settle_expiry = |w: &Watcher| parse(&encode(w))["accepted"][0]["settle_expiry"].clone();

    let mut unresumed = Watcher::with_state(Network::Mainnet, depth, state.clone());
    unresumed.retire_trade(TradeId(a.terms_hash())).unwrap();
    assert_eq!(settle_expiry(&unresumed), json!(expiry.to_string()));
    restarts(&encode(&unresumed));

    // Control: with B added again first, the expiry is B's.
    let mut resumed = Watcher::with_state(Network::Mainnet, depth, state);
    resumed.add_trade(b).unwrap();
    resumed.retire_trade(TradeId(a.terms_hash())).unwrap();
    assert_eq!(settle_expiry(&resumed), json!((expiry + 1_000).to_string()));
}

/// `--retire A --trade B` keeps B's pending rebroadcast: B is added before A is retired, so the
/// book still knows B's vaults when the pending transactions are checked.
#[tokio::test]
async fn retiring_one_trade_on_the_command_line_keeps_the_others_pending_rebroadcast() {
    let a = terms(1);
    let b = repeat_of(&a);
    let dir = TempDir::new();
    let settle_b = tx(
        90,
        vec![settle_in(&vault(&b, LegIndex::Asset), AUTH), plain_in()],
        vec![(1_000, stranger())],
    );
    let mut w = mainnet_watcher(10);
    w.add_trade(a.clone()).unwrap();
    w.add_trade(b.clone()).unwrap();
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle_b.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle_b]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.set_sink(block(12));
    w.poll(&source).await.unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);

    let mut args = run_args(&dir);
    persist::write_atomic(&args.state, &encode(&w)).unwrap();
    args.init = false;
    let terms_file = |name: &str, t: &ValidatedTerms| {
        let path = dir.file(name);
        let file = json!({
            "terms": {},
            "canonical": crate::files::hex(t.canonical()),
            "terms_hash": crate::files::hex(&t.terms_hash()),
        });
        std::fs::write(&path, file.to_string()).unwrap();
        path
    };
    args.trades = vec![terms_file("b.json", &b)];
    args.retire = vec![TradeId(a.terms_hash())];
    let p = prepare(&args).unwrap();
    assert_eq!(p.watcher.pending_rebroadcasts(), vec![settle_id]);
    assert!(p.watcher.is_kept(&settle_id));
    assert_eq!(p.watcher.trades().len(), 1);
    drop(p);

    // Control: retiring B too, with nothing left that the transaction settles, drops it.
    args.trades = vec![];
    args.retire = vec![TradeId(a.terms_hash()), TradeId(b.terms_hash())];
    let p = prepare(&args).unwrap();
    assert!(p.watcher.pending_rebroadcasts().is_empty());
    assert!(!p.watcher.is_kept(&settle_id));
}

/// A refund is submitted whatever the tip, before and after a retirement recomputes the expiry
/// of what is pending: a refund has no settle expiry to inherit from its trade's.
#[tokio::test]
async fn a_pending_refund_is_still_submitted_past_expiry_after_a_retire() {
    let a = terms(1);
    let b = repeat_of(&a);
    let expiry = a.terms().expiry_daa;
    let refund = tx(
        91,
        vec![
            refund_in(&vault(&b, LegIndex::Asset), b.terms().seller_key, AUTH),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let mut w = mainnet_watcher(10);
    let ida = w.add_trade(a).unwrap().trade;
    w.add_trade(b).unwrap();
    let source = FakeVirtualChainSource::new(block(0), expiry + 1);
    source.extend(block(1), expiry + 2, vec![]);
    w.poll(&source).await.unwrap();
    let refund_id = w.keep_signed(refund.tx().clone()).unwrap();
    source.extend(block(2), expiry + 5, vec![refund]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), expiry + 6, vec![]);
    source.add_block(block(13), block(12), expiry + 9, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![refund_id]);
    w.retire_trade(ida).unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![refund_id]);
    assert_eq!(
        parse(&encode(&w))["pending"][0]["settle_expiry"],
        Value::Null
    );
    let node = FakeBroadcaster::default().at_virtual_daa(expiry + 9);
    let r = drain(&mut w, &node).await;
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(node.submitted(), vec![refund_id]);
    assert_eq!(node.daa_reads(), 0);
}

/// Under the lock the state file is looked at again: a file that appeared while the lock was
/// waited for is never overwritten by `--init`, and one that went is never started silently.
#[test]
fn under_the_lock_a_state_file_that_appeared_or_went_is_still_refused() {
    let dir = TempDir::new();
    let path = dir.file("state.json");
    let load = |init: bool| crate::run::load_state(&path, init, Network::Mainnet);
    // A new state: nothing there, --init.
    let (state, saved) = load(true).unwrap();
    assert_eq!((state.trades.len(), saved), (0, None));
    // Not there, no --init.
    assert_eq!(code_of(load(false)), "WATCH_STATE_MISSING");
    // There, --init: never overwritten.
    let text = persist::encode(&WatchState::default(), Network::Mainnet);
    std::fs::write(&path, &text).unwrap();
    assert_eq!(code_of(load(true)), "WATCH_STATE_EXISTS");
    // There, no --init: read as it is.
    let (_, saved) = load(false).unwrap();
    assert_eq!(saved.as_deref(), Some(text.as_str()));
    // Control: and refused if it is not a state, or one of another network.
    std::fs::write(&path, "{}").unwrap();
    assert_eq!(code_of(load(false)), "WATCH_STATE_INVALID");
    std::fs::write(
        &path,
        persist::encode(&WatchState::default(), Network::Testnet),
    )
    .unwrap();
    assert_eq!(code_of(load(false)), "WATCH_STATE_MISMATCH");
}

// ---- the bounds on a walk (I14, O1) ----

#[test]
fn a_walk_of_more_added_chain_blocks_than_the_cap_is_refused_before_it_is_converted() {
    use super::phase2::{batch, response};
    use crate::node::{convert_walk, MAX_ADDED_CHAIN_BLOCKS};
    let walk = |n: usize| {
        let blocks: Vec<_> = (1..=n as u64).map(block).collect();
        let batches = (1..=n as u64)
            .map(|i| batch(block(i), Some(100 + i), vec![]))
            .collect();
        response(vec![], blocks, batches)
    };
    // Control: exactly the cap converts.
    assert_eq!(
        convert_walk(&walk(MAX_ADDED_CHAIN_BLOCKS))
            .unwrap()
            .added_chain_blocks
            .len(),
        MAX_ADDED_CHAIN_BLOCKS
    );
    // One more is refused, naming both figures.
    let e = convert_walk(&walk(MAX_ADDED_CHAIN_BLOCKS + 1)).unwrap_err();
    assert!(
        e.0.contains(&format!(
            "{} added chain blocks, above the {MAX_ADDED_CHAIN_BLOCKS} a walk may carry",
            MAX_ADDED_CHAIN_BLOCKS + 1
        )),
        "{}",
        e.0
    );
}

#[test]
fn a_walk_whose_last_chain_block_is_above_the_virtual_daa_score_is_refused() {
    use super::phase2::{batch, response};
    use crate::node::{check_below_virtual, convert_walk};
    let update = convert_walk(&response(
        vec![],
        vec![block(1), block(2)],
        vec![
            batch(block(1), Some(100), vec![]),
            batch(block(2), Some(101), vec![]),
        ],
    ))
    .unwrap();
    // At and above the last block's score: accepted. One below: refused, naming the block.
    assert!(check_below_virtual(&update, 101).is_ok());
    assert!(check_below_virtual(&update, 5_000).is_ok());
    let e = check_below_virtual(&update, 100).unwrap_err();
    assert!(e.0.contains("DAA score 101"), "{}", e.0);
    assert!(e.0.contains("virtual DAA score 100"), "{}", e.0);
    assert!(e.0.contains(&block(2).to_string()), "{}", e.0);
    // A walk that adds nothing has nothing to compare.
    let empty = convert_walk(&response(vec![], vec![], vec![])).unwrap();
    assert!(check_below_virtual(&empty, 0).is_ok());
}
