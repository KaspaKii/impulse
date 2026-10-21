// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Watcher tests against the fake source. Trades come from the frozen golden terms vectors
//! (public keys only). No test holds a key: the watcher never checks a signature, so a vault
//! spend's signature push is stand-in bytes, and the fake source plays consensus.

use crate::entry::{REFUND_TAG, SETTLE_TAG};
use crate::tracker::test_support::{poll_once_then_drop, Call, FakeVirtualChainSource};
use crate::tracker::{
    AcceptanceInfo, AcceptedTransaction, AddedChainBlock, BlockHash, Cursor, FinalityPolicy,
    VirtualChainStore, VirtualChainUpdate,
};
use crate::trades::{stray_cash_script, with_cash_leg_index, Effect, Leg, TradeId};
use crate::watcher::Refusal;
use crate::{
    Broadcaster, Event, WatchError, Watcher, Watching, REBROADCAST_ATTEMPTS, WATCH_ERROR_CODES,
    WATCH_EVENT_CODES,
};
use impulse_core::template::{self, LegIndex, Vault};
use impulse_core::terms::{LegKind, Network, ValidatedTerms};
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{CovenantBinding, PopulatedTransaction};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine};
use serde_json::json;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

// ---- fixtures ----

fn vector_json(n: u8) -> &'static str {
    match n {
        1 => include_str!(
            "../../../tests/vectors/terms/01-vault-authority-earmarked-kcc20-kcc20.json"
        ),
        2 => {
            include_str!("../../../tests/vectors/terms/02-vault-authority-revocable-kcc20-kas.json")
        }
        5 => include_str!("../../../tests/vectors/terms/05-vault-external-earmarked-kcc20.json"),
        7 => include_str!("../../../tests/vectors/terms/07-direct-kcc20-kcc20.json"),
        8 => include_str!(
            "../../../tests/vectors/terms/08-testnet-vault-authority-earmarked-kcc20-kas.json"
        ),
        _ => panic!("no fixture for vector {n}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Golden terms vector `n`, structure-checked.
fn terms(n: u8) -> ValidatedTerms {
    let v: serde_json::Value = serde_json::from_str(vector_json(n)).unwrap();
    ValidatedTerms::decode(&unhex(v["canonical"].as_str().unwrap())).unwrap()
}

/// A repeat trade between the same parties: another nonce and trade_ref, the same deliveries.
fn repeat_of(t: &ValidatedTerms) -> ValidatedTerms {
    let mut r = t.terms().clone();
    r.nonce ^= 1;
    r.trade_ref = [0x42; 32];
    r.validate_structure().unwrap()
}

fn vault(t: &ValidatedTerms, leg: LegIndex) -> Vault {
    Vault::instantiate_existing(t, leg).unwrap()
}

fn mainnet_watcher(depth: u64) -> Watcher {
    Watcher::new(Network::Mainnet, FinalityPolicy::new(depth).unwrap())
}

/// Stand-in signature bytes. Not a signature and not derived from any key.
const SIG: [u8; 65] = [0x5a; 65];

fn push_all(items: &[&[u8]]) -> Vec<u8> {
    let mut b = ScriptBuilder::with_flags(EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    });
    for item in items {
        b.add_data(item).unwrap();
    }
    b.drain()
}

fn settle_call(v: &Vault) -> Vec<u8> {
    push_all(&[&SIG, &SETTLE_TAG, v.redeem_script()])
}

fn refund_call(v: &Vault, signer: [u8; 32]) -> Vec<u8> {
    push_all(&[&SIG, &signer, &REFUND_TAG, v.redeem_script()])
}

/// A plain P2PK-style spend: one signature push (fee inputs, token escrows, funding inputs).
fn plain() -> Vec<u8> {
    push_all(&[&SIG])
}

fn stranger() -> ScriptPublicKey {
    let mut script = vec![0x20];
    script.extend_from_slice(&[0x77; 32]);
    script.push(0xac);
    ScriptPublicKey::new(0, script.into())
}

/// KAS held by a KCC-20 leg's vault UTXO (the authorizer) in these tests.
const AUTH: u64 = 100_000;

/// One input: its signature script and the UTXO it spends.
struct In {
    sig: Vec<u8>,
    spends: UtxoEntry,
}

fn utxo(value: u64, spk: ScriptPublicKey) -> UtxoEntry {
    UtxoEntry::new(value, spk, 0, false, None)
}

/// A spend of `v`'s UTXO holding `value`, through the settle entry.
fn settle_in(v: &Vault, value: u64) -> In {
    In {
        sig: settle_call(v),
        spends: utxo(value, v.script_public_key()),
    }
}

/// A spend of `v`'s UTXO holding `value`, through the refund entry signed by `signer`.
fn refund_in(v: &Vault, signer: [u8; 32], value: u64) -> In {
    In {
        sig: refund_call(v, signer),
        spends: utxo(value, v.script_public_key()),
    }
}

/// A plain input spending a stranger's UTXO.
fn plain_in() -> In {
    In {
        sig: plain(),
        spends: utxo(10_000, stranger()),
    }
}

/// An accepted transaction with these inputs and outputs. `salt` sets the previous outpoints
/// (`salt`:0, `salt`:1, ...), so transactions with different salts have different txids.
fn tx(salt: u64, inputs: Vec<In>, outputs: Vec<(u64, ScriptPublicKey)>) -> AcceptedTransaction {
    let (tx_inputs, spent): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .enumerate()
        .map(|(i, In { sig, spends })| {
            let prev = TransactionOutpoint::new(Hash::from_u64_word(salt), i as u32);
            (TransactionInput::new(prev, sig, 0, 1), spends)
        })
        .unzip();
    let outputs = outputs
        .into_iter()
        .map(|(value, spk)| kaspa_consensus_core::tx::TransactionOutput::new(value, spk))
        .collect();
    let tx = Transaction::new(0, tx_inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    AcceptedTransaction::new(tx, spent).unwrap()
}

fn id(t: &AcceptedTransaction) -> TransactionId {
    t.tx().id()
}

fn block(n: u64) -> BlockHash {
    Hash::from_u64_word(0xb10c_0000 + n)
}

/// A node whose chain starts at block 0 (DAA 99) and grows one block per [`Node::mine`], each
/// at the next DAA score.
struct Node {
    chain: FakeVirtualChainSource,
    height: Cell<u64>,
}

impl Node {
    fn new() -> Self {
        Self {
            chain: FakeVirtualChainSource::new(block(0), 99),
            height: Cell::new(0),
        }
    }

    /// A block on the sink accepting `txs`, at DAA 99 + its height.
    fn mine(&self, txs: Vec<AcceptedTransaction>) {
        let h = self.height.get() + 1;
        self.height.set(h);
        self.chain.extend(block(h), 99 + h, txs);
    }
}

/// A source over block 0 (DAA 99) and an empty block 1 (DAA 100), and the watcher's first poll,
/// so that the next walk starts at block 1 and sees every block mined after it.
async fn started(w: &mut Watcher) -> FakeVirtualChainSource {
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert!(e.is_empty());
    source
}

fn at(n: u64, daa: u64) -> Option<AcceptanceInfo> {
    Some(AcceptanceInfo {
        accepting_block_hash: block(n),
        accepting_daa_score: daa,
    })
}

fn cursor_of(w: &Watcher) -> Option<(BlockHash, Option<u64>)> {
    w.tracker().store().cursor().map(
        |Cursor {
             block_hash,
             daa_score,
         }| (block_hash, daa_score),
    )
}

/// A node's submit call. Records every transaction handed to it.
struct FakeBroadcaster {
    handed: Mutex<Vec<Transaction>>,
    /// Refusals given, in order, before any submission is taken.
    refusals: Mutex<VecDeque<Refusal>>,
    /// Refuse every submission with this reason.
    always_refuse: Option<String>,
    /// The next submission never completes.
    hang_next: Mutex<bool>,
    /// What the node says its virtual DAA score is: 0 (behind every walk) unless set.
    virtual_daa: Mutex<Result<u64, String>>,
    /// How many times the node was asked for its virtual DAA score.
    daa_reads: Mutex<usize>,
}

impl Default for FakeBroadcaster {
    fn default() -> Self {
        Self {
            handed: Mutex::default(),
            refusals: Mutex::default(),
            always_refuse: None,
            hang_next: Mutex::default(),
            virtual_daa: Mutex::new(Ok(0)),
            daa_reads: Mutex::default(),
        }
    }
}

impl FakeBroadcaster {
    fn refusing(reason: &str) -> Self {
        Self {
            always_refuse: Some(reason.to_string()),
            ..Self::default()
        }
    }

    fn refusing_first(reasons: &[&str]) -> Self {
        Self {
            refusals: Mutex::new(
                reasons
                    .iter()
                    .map(|r| Refusal::Refused(r.to_string()))
                    .collect(),
            ),
            ..Self::default()
        }
    }

    /// Answers the first `n` submissions with the node's "already accepted by the consensus".
    fn recently_accepted_first(n: usize) -> Self {
        Self {
            refusals: Mutex::new(
                (0..n)
                    .map(|_| Refusal::RecentlyAccepted("already accepted by the consensus".into()))
                    .collect(),
            ),
            ..Self::default()
        }
    }

    /// The node says its virtual DAA score is `daa`.
    fn at_virtual_daa(self, daa: u64) -> Self {
        *self.virtual_daa.lock().unwrap() = Ok(daa);
        self
    }

    /// The node's virtual DAA score cannot be read.
    fn unreadable_virtual_daa(self, reason: &str) -> Self {
        *self.virtual_daa.lock().unwrap() = Err(reason.to_string());
        self
    }

    fn daa_reads(&self) -> usize {
        *self.daa_reads.lock().unwrap()
    }

    fn hanging_once() -> Self {
        Self {
            hang_next: Mutex::new(true),
            ..Self::default()
        }
    }

    /// The txids handed to the node, in order.
    fn submitted(&self) -> Vec<TransactionId> {
        self.handed.lock().unwrap().iter().map(|t| t.id()).collect()
    }

    fn handed(&self) -> Vec<Transaction> {
        self.handed.lock().unwrap().clone()
    }
}

impl Broadcaster for FakeBroadcaster {
    async fn virtual_daa_score(&self) -> Result<u64, String> {
        *self.daa_reads.lock().unwrap() += 1;
        self.virtual_daa.lock().unwrap().clone()
    }

    async fn submit(&self, tx: &Transaction) -> Result<(), Refusal> {
        let hang = std::mem::take(&mut *self.hang_next.lock().unwrap());
        if hang {
            std::future::pending::<()>().await;
        }
        self.handed.lock().unwrap().push(tx.clone());
        if let Some(reason) = &self.always_refuse {
            return Err(Refusal::Refused(reason.clone()));
        }
        match self.refusals.lock().unwrap().pop_front() {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }
}

/// Every due rebroadcast, as the binary runs them after a poll.
async fn drain(w: &mut Watcher, node: &FakeBroadcaster) -> Vec<Event> {
    let mut events = vec![];
    while let Some(e) = w.rebroadcast_next(node).await {
        events.push(e);
        assert!(events.len() < 100, "rebroadcast_next never ran dry");
    }
    events
}

/// Events in a short readable form: "<kind> <effect> <trade name>/<leg>", or
/// "rebroadcast <outcome>".
fn brief(events: &[Event], names: &HashMap<TradeId, &str>) -> Vec<String> {
    let leg = |l: Option<Leg>| match l {
        Some(Leg::Asset) => "/asset",
        Some(Leg::Cash) => "/cash",
        Some(Leg::V2(_)) => "/v2",
        None => "",
    };
    events
        .iter()
        .map(|e| match e {
            Event::Rebroadcast { outcome, .. } => format!("rebroadcast {}", outcome.name()),
            _ => {
                let effect = e.effect().unwrap();
                let kind = match e {
                    Event::Accepted { .. } => "accepted",
                    Event::Final { .. } => "final",
                    _ => "reorg",
                };
                format!(
                    "{kind} {} {}{}",
                    effect.name(),
                    names[&effect.trade()],
                    leg(effect.leg())
                )
            }
        })
        .collect()
}

fn effects(events: &[Event]) -> Vec<Effect> {
    events.iter().filter_map(|e| e.effect().copied()).collect()
}

/// One KAS-cash trade (vector 2): its watcher, id, vaults, funding and settle transactions.
struct KasTrade {
    w: Watcher,
    id: TradeId,
    names: HashMap<TradeId, &'static str>,
    funding: AcceptedTransaction,
    settle: AcceptedTransaction,
}

fn kas_trade(depth: u64) -> KasTrade {
    let t = terms(2);
    let cash_amount = t.terms().cash_leg.amount;
    let (asset, cash) = (vault(&t, LegIndex::Asset), vault(&t, LegIndex::Cash));
    let mut w = mainnet_watcher(depth);
    let id = w.add_trade(t).unwrap().trade;
    let funding = tx(
        1,
        vec![plain_in()],
        vec![
            (AUTH, asset.script_public_key()),
            (cash_amount, cash.script_public_key()),
        ],
    );
    // Canonical layout: asset authorizer at 0, KAS cash at 1, escrowed asset token at 2, fee.
    let settle = tx(
        2,
        vec![
            settle_in(&asset, AUTH),
            settle_in(&cash, cash_amount),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger()), (cash_amount, stranger())],
    );
    KasTrade {
        w,
        id,
        names: HashMap::from([(id, "T")]),
        funding,
        settle,
    }
}

// ---- phase 1 exit test: reorg, rebroadcast once, reconfirm ----

#[tokio::test]
async fn exit_settle_reorged_out_is_rebroadcast_once_and_reconfirmed() {
    let KasTrade {
        mut w,
        id: trade_id,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), 99);
    let funding_id = id(&funding);

    // Funded.
    source.extend(block(1), 100, vec![funding.clone()]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted authorizer_seen T/asset", "accepted funded T/cash"]
    );
    assert_eq!(cursor_of(&w), Some((block(1), Some(100))));
    assert_eq!(w.tracker().accepting_block(&funding_id), at(1, 100));

    // The settle is kept, then confirmed at depth 2.
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle.clone()]);
    source.extend(block(3), 103, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted settled T/asset", "accepted settled T/cash"]
    );
    assert!(matches!(e[0], Event::Accepted { depth: 2, .. }));
    assert_eq!(cursor_of(&w), Some((block(3), Some(103))));
    assert_eq!(w.tracker().accepting_block(&settle_id), at(2, 101));

    // Reorged out: blocks 2 and 3 leave the chain for a branch from block 1 that accepts
    // nothing. The funding in block 1 stays accepted.
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 103, vec![]);
    source.add_block(block(14), block(13), 104, vec![]);
    source.set_sink(block(14));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg settled T/asset", "reorg settled T/cash"]
    );
    // Control for WATCH_FINAL_REORGED: this acceptance was never reported final.
    assert!(matches!(
        e[0],
        Event::Reorg {
            was_final: false,
            ..
        }
    ));
    assert_eq!(e[0].code(), None);
    assert_eq!(
        e[0].to_json(),
        json!({
            "event": "reorg",
            "of": "settled",
            "trade": trade_id.to_string(),
            "leg": "asset",
            "input": 0,
            "spent_txid": Hash::from_u64_word(2).to_string(),
            "spent_index": 0,
            "spent_value": AUTH.to_string(),
            "txid": settle_id.to_string(),
            "accepting_block": block(2).to_string(),
            "accepting_daa": "101",
            "was_final": false
        })
    );
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(
        r[0].to_json(),
        json!({
            "event": "rebroadcast",
            "txid": settle_id.to_string(),
            "outcome": "submitted",
            "attempt": 1
        })
    );
    assert_eq!(node.handed(), vec![settle.tx().clone()]);
    assert!(w.pending_rebroadcasts().is_empty());
    assert_eq!(cursor_of(&w), Some((block(14), Some(104))));
    assert_eq!(w.tracker().accepting_block(&settle_id), None);
    assert_eq!(w.tracker().accepting_block(&funding_id), at(1, 100));

    // Still not accepted on the next walk: no second submission.
    source.extend(block(15), 105, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(node.submitted(), vec![settle_id]);
    assert_eq!(cursor_of(&w), Some((block(15), Some(105))));

    // Reconfirmed: the rebroadcast transaction is accepted again.
    source.extend(block(16), 106, vec![settle.clone()]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted settled T/asset", "accepted settled T/cash"]
    );
    assert_eq!(w.tracker().accepting_block(&settle_id), at(16, 106));

    // Final at depth N = 10: the funding (DAA 100) first, then the settle (DAA 106).
    source.extend(block(17), 116, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "final authorizer_seen T/asset",
            "final funded T/cash",
            "final settled T/asset",
            "final settled T/cash"
        ]
    );
    assert!(matches!(e[3], Event::Final { depth: 10, .. }));
    assert_eq!(
        e[3].to_json(),
        json!({
            "event": "final",
            "of": "settled",
            "trade": trade_id.to_string(),
            "leg": "cash",
            "input": 1,
            "spent_txid": Hash::from_u64_word(2).to_string(),
            "spent_index": 1,
            "spent_value": terms(2).terms().cash_leg.amount.to_string(),
            "txid": settle_id.to_string(),
            "accepting_block": block(16).to_string(),
            "accepting_daa": "106",
            "depth": "10"
        })
    );

    // Reported once.
    source.extend(block(18), 130, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(
        node.submitted(),
        vec![settle_id],
        "rebroadcast exactly once"
    );
    assert_eq!(
        source.start_hashes_seen(),
        [0, 1, 3, 14, 15, 16, 17].map(block).to_vec(),
        "each walk starts where the last one ended"
    );
}

/// A walk that adds four blocks with watched transactions in the first, second and fourth, then
/// a reorg that removes the top three, tip first, and keeps the first.
#[tokio::test]
async fn a_multi_block_walk_and_a_three_block_reorg_are_reported_in_full() {
    let KasTrade {
        mut w,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let t = terms(2);
    let cash = vault(&t, LegIndex::Cash);
    let over = tx(
        20,
        vec![plain_in()],
        vec![(t.terms().cash_leg.amount + 1, cash.script_public_key())],
    );
    let (funding_id, over_id) = (id(&funding), id(&over));
    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding]);
    source.extend(block(3), 102, vec![over]);
    source.extend(block(4), 103, vec![]);
    source.extend(block(5), 104, vec![settle]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "accepted authorizer_seen T/asset",
            "accepted funded T/cash",
            "accepted funded T/cash",
            "accepted settled T/asset",
            "accepted settled T/cash"
        ]
    );
    assert_eq!(cursor_of(&w), Some((block(5), Some(104))));
    assert_eq!(w.tracker().accepting_block(&funding_id), at(2, 101));
    assert_eq!(w.tracker().accepting_block(&over_id), at(3, 102));
    assert_eq!(w.tracker().accepting_block(&settle_id), at(5, 104));

    source.add_block(block(13), block(2), 102, vec![]);
    source.add_block(block(14), block(13), 103, vec![]);
    source.add_block(block(15), block(14), 104, vec![]);
    source.add_block(block(16), block(15), 105, vec![]);
    source.set_sink(block(16));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "reorg settled T/asset",
            "reorg settled T/cash",
            "reorg funded T/cash"
        ],
        "removed blocks are reported tip first: block 5, then block 3"
    );
    assert_eq!(e[2].txid(), over_id);
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(node.submitted(), vec![settle_id]);
    assert_eq!(cursor_of(&w), Some((block(16), Some(105))));
    assert_eq!(w.tracker().accepting_block(&funding_id), at(2, 101));
    assert_eq!(w.tracker().accepting_block(&over_id), None);
    assert_eq!(w.tracker().accepting_block(&settle_id), None);
    assert_eq!(
        source.start_hashes_seen(),
        vec![block(0), block(1), block(5)]
    );
}

#[tokio::test]
async fn a_reorg_that_accepts_again_in_the_same_walk_does_not_rebroadcast() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), 99);
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle.clone()]);
    w.poll(&source).await.unwrap();

    source.add_block(block(3), block(0), 101, vec![settle.clone()]);
    source.set_sink(block(3));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "reorg settled T/asset",
            "reorg settled T/cash",
            "accepted settled T/asset",
            "accepted settled T/cash"
        ]
    );
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(drain(&mut w, &node).await.is_empty());
    assert!(node.submitted().is_empty());
    assert_eq!(w.tracker().accepting_block(&id(&settle)), at(3, 101));
}

#[tokio::test]
async fn a_reorged_out_transaction_not_kept_is_reported_not_rebroadcast() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(3), block(0), 101, vec![]);
    source.set_sink(block(3));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg settled T/asset", "reorg settled T/cash"]
    );
    assert!(drain(&mut w, &node).await.is_empty());
    assert!(node.submitted().is_empty());
}

/// A settle whose funding left the chain in the same reorg is refused for missing inputs; it is
/// tried again once per poll and taken once the funding is back. One success ends it.
#[tokio::test]
async fn a_refused_rebroadcast_is_retried_once_per_poll_until_the_node_takes_it() {
    let KasTrade {
        mut w,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::refusing_first(&["missing inputs"]);
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle]);
    w.poll(&source).await.unwrap();

    // Both blocks leave the chain.
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.add_block(block(14), block(13), 103, vec![]);
    source.set_sink(block(14));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "reorg settled T/asset",
            "reorg settled T/cash",
            "reorg authorizer_seen T/asset",
            "reorg funded T/cash"
        ]
    );
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast refused"]);
    assert_eq!(
        r[0].to_json(),
        json!({
            "event": "rebroadcast",
            "txid": settle_id.to_string(),
            "outcome": "refused",
            "attempt": 1,
            "reason": "missing inputs",
            "code": "WATCH_REBROADCAST_FAILED"
        })
    );
    // Not tried again before the next poll.
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);

    // The funding is accepted again; the next attempt is taken.
    source.extend(block(15), 104, vec![funding]);
    w.poll(&source).await.unwrap();
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(r[0].to_json()["attempt"], json!(2));
    assert_eq!(node.submitted(), vec![settle_id, settle_id]);

    // Done: later polls submit nothing.
    source.extend(block(16), 105, vec![]);
    w.poll(&source).await.unwrap();
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(node.submitted().len(), 2);
    assert!(w.pending_rebroadcasts().is_empty());
}

#[tokio::test]
async fn a_rebroadcast_refused_every_time_is_abandoned_after_the_cap() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::refusing("inputs already spent");
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();

    let mut outcomes = vec![];
    for n in 0..REBROADCAST_ATTEMPTS as u64 {
        if n > 0 {
            source.extend(block(20 + n), 102 + n, vec![]);
            w.poll(&source).await.unwrap();
        }
        outcomes.extend(brief(&drain(&mut w, &node).await, &names));
    }
    let mut expected = vec!["rebroadcast refused".to_string(); REBROADCAST_ATTEMPTS as usize - 1];
    expected.push("rebroadcast abandoned".to_string());
    assert_eq!(outcomes, expected);
    assert!(w.pending_rebroadcasts().is_empty());

    // Nothing after the cap.
    source.extend(block(40), 140, vec![]);
    w.poll(&source).await.unwrap();
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(
        node.submitted(),
        vec![settle_id; REBROADCAST_ATTEMPTS as usize]
    );
}

#[tokio::test]
async fn the_last_refused_attempt_carries_the_abandoned_code() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let node = FakeBroadcaster::refusing("inputs already spent");
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    let mut last = None;
    for n in 0..REBROADCAST_ATTEMPTS as u64 {
        if n > 0 {
            source.extend(block(20 + n), 102 + n, vec![]);
            w.poll(&source).await.unwrap();
        }
        let r = drain(&mut w, &node).await;
        assert_eq!(r.len(), 1);
        if n + 1 < REBROADCAST_ATTEMPTS as u64 {
            assert_eq!(r[0].code(), Some("WATCH_REBROADCAST_FAILED"));
        }
        last = r.into_iter().next();
    }
    assert_eq!(
        last.unwrap().to_json(),
        json!({
            "event": "rebroadcast",
            "txid": settle_id.to_string(),
            "outcome": "abandoned",
            "attempt": REBROADCAST_ATTEMPTS,
            "reason": "inputs already spent",
            "code": "WATCH_REBROADCAST_ABANDONED"
        })
    );
}

/// The txid does not cover signature scripts. A copy with the same txid and a bogus signature
/// can be kept first, but what is submitted after a reorg is the copy the node accepted.
#[tokio::test]
async fn the_rebroadcast_is_the_accepted_copy_never_a_same_txid_variant() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let real = settle.tx().clone();
    let mut bogus = real.clone();
    let asset = vault(&terms(2), LegIndex::Asset);
    bogus.inputs[0].signature_script = push_all(&[&[0xee; 65], &SETTLE_TAG, asset.redeem_script()]);
    bogus.finalize();
    assert_eq!(hashing::tx::id(&bogus), hashing::tx::id(&real), "same txid");
    assert_ne!(
        hashing::tx::hash(&bogus),
        hashing::tx::hash(&real),
        "other bytes"
    );

    // The bogus copy is kept first; the real one is then refused as the same txid.
    let settle_id = w.keep_signed(bogus).unwrap();
    assert_eq!(
        w.keep_signed(real.clone()).unwrap_err(),
        WatchError::TxDuplicate(settle_id)
    );

    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(
        node.handed(),
        vec![real],
        "the accepted copy, byte for byte"
    );
}

/// A transaction kept only after the chain accepted it is still rebroadcast from the accepted
/// copy.
#[tokio::test]
async fn a_transaction_kept_after_its_acceptance_is_rebroadcast_from_the_accepted_copy() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![settle.clone()]);
    w.poll(&source).await.unwrap();
    let mut variant = settle.tx().clone();
    variant.inputs[2].signature_script = push_all(&[&[0x11; 65]]);
    w.keep_signed(variant).unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    drain(&mut w, &node).await;
    assert_eq!(node.handed(), vec![settle.tx().clone()]);
}

/// The reorg events of a walk never wait on a submission, and a submission dropped before the
/// node answers is made again by the next call, once.
#[tokio::test]
async fn a_rebroadcast_dropped_mid_submit_is_made_again_once() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg settled T/asset", "reorg settled T/cash"]
    );

    let node = FakeBroadcaster::hanging_once();
    assert!(!poll_once_then_drop(w.rebroadcast_next(&node)));
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id], "nothing changed");
    assert!(node.submitted().is_empty());

    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(r[0].to_json()["attempt"], json!(1));
    assert_eq!(node.submitted(), vec![settle_id]);
    source.extend(block(14), 103, vec![]);
    w.poll(&source).await.unwrap();
    assert!(drain(&mut w, &node).await.is_empty());
    assert_eq!(node.submitted(), vec![settle_id], "exactly once");
}

/// A kept transaction accepted again before it was submitted (someone else rebroadcast it) is
/// not submitted.
#[tokio::test]
async fn a_pending_rebroadcast_accepted_again_is_dropped() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![settle.clone()]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    assert_eq!(w.pending_rebroadcasts().len(), 1);
    source.extend(block(14), 103, vec![settle]);
    w.poll(&source).await.unwrap();
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(drain(&mut w, &node).await.is_empty());
    assert!(node.submitted().is_empty());
}

/// Two kept transactions, a settle of one trade and a refund of another, removed by one reorg:
/// each is submitted once, in txid order.
#[tokio::test]
async fn two_kept_transactions_removed_by_one_reorg_are_each_rebroadcast_once() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let c = terms(1);
    let c_asset = vault(&c, LegIndex::Asset);
    let seller = c.terms().seller_key;
    let idc = w.add_trade(c).unwrap().trade;
    let mut names = names;
    names.insert(idc, "C");
    let refund = tx(
        49,
        vec![refund_in(&c_asset, seller, AUTH), plain_in()],
        vec![],
    );
    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    let mut kept = vec![
        w.keep_signed(settle.tx().clone()).unwrap(),
        w.keep_signed(refund.tx().clone()).unwrap(),
    ];
    kept.sort();
    source.extend(block(2), 101, vec![settle]);
    source.extend(block(3), 102, vec![refund]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.add_block(block(14), block(13), 103, vec![]);
    source.set_sink(block(14));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "reorg refunded C/asset",
            "reorg settled T/asset",
            "reorg settled T/cash"
        ]
    );
    let r = drain(&mut w, &node).await;
    assert_eq!(
        brief(&r, &names),
        ["rebroadcast submitted", "rebroadcast submitted"]
    );
    assert_eq!(node.submitted(), kept);
}

/// A settle reorged out once the tip is at or past the expiry of the trade it settles is not
/// submitted: it is reported with WATCH_REBROADCAST_PAST_EXPIRY for the operator. A refund is
/// rebroadcast whatever the tip.
#[tokio::test]
async fn a_settle_reorged_out_past_its_trades_expiry_is_flagged_not_submitted() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let expiry = terms(2).terms().expiry_daa;
    let seller = terms(2).terms().seller_key;
    let asset = vault(&terms(2), LegIndex::Asset);
    let refund = tx(
        50,
        vec![refund_in(&asset, seller, AUTH), plain_in()],
        vec![],
    );
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    let refund_id = w.keep_signed(refund.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![settle]);
    source.extend(block(3), expiry - 2, vec![refund]);
    w.poll(&source).await.unwrap();

    // The reorg lands at the expiry.
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry - 2, vec![]);
    source.add_block(block(14), block(13), expiry, vec![]);
    source.set_sink(block(14));
    w.poll(&source).await.unwrap();
    let r = drain(&mut w, &node).await;
    let settle_event = r.iter().find(|e| e.txid() == settle_id).unwrap();
    assert_eq!(
        settle_event.to_json(),
        json!({
            "event": "rebroadcast",
            "txid": settle_id.to_string(),
            "outcome": "skipped_past_expiry",
            "expiry_daa": expiry.to_string(),
            "tip_daa": expiry.to_string(),
            "code": "WATCH_REBROADCAST_PAST_EXPIRY"
        })
    );
    // Control: the refund is submitted.
    let refund_event = r.iter().find(|e| e.txid() == refund_id).unwrap();
    assert_eq!(
        brief(std::slice::from_ref(refund_event), &names),
        ["rebroadcast submitted"]
    );
    assert_eq!(node.submitted(), vec![refund_id]);
    assert!(w.pending_rebroadcasts().is_empty());
}

#[tokio::test]
async fn a_settle_reorged_out_before_its_trades_expiry_is_submitted() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let expiry = terms(2).terms().expiry_daa;
    let node = FakeBroadcaster::default();
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![settle]);
    w.poll(&source).await.unwrap();
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry - 1, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(node.submitted(), vec![settle_id]);
}

/// A kept settle of trade A's asset vault (expiry E) and trade B's cash vault (expiry E + 1000),
/// accepted at E - 3 and reorged out by a branch whose tip is at `tip`. Returns the expiry E,
/// the settle's txid, the rebroadcast events and what the node was handed.
async fn reorg_a_two_trade_settle_at(
    tip: impl Fn(u64) -> u64,
) -> (u64, TransactionId, Vec<Event>, Vec<TransactionId>) {
    let a = terms(1);
    let expiry = a.terms().expiry_daa;
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
    let e = w.poll(&source).await.unwrap();
    assert_eq!(e.len(), 2, "settled A/asset and B/cash");
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), tip(expiry), vec![]);
    source.set_sink(block(13));
    assert_eq!(w.poll(&source).await.unwrap().len(), 2, "both reorged");
    let r = drain(&mut w, &node).await;
    assert!(w.pending_rebroadcasts().is_empty());
    (expiry, mixed_id, r, node.submitted())
}

/// A settle of two trades is held back from the earlier of their expiries, though the other
/// trade is still open.
#[tokio::test]
async fn a_settle_of_two_trades_reorged_out_at_the_earlier_expiry_is_flagged_not_submitted() {
    let (expiry, mixed_id, r, submitted) = reorg_a_two_trade_settle_at(|e| e).await;
    assert_eq!(
        r.iter().map(Event::to_json).collect::<Vec<_>>(),
        [json!({
            "event": "rebroadcast",
            "txid": mixed_id.to_string(),
            "outcome": "skipped_past_expiry",
            "expiry_daa": expiry.to_string(),
            "tip_daa": expiry.to_string(),
            "code": "WATCH_REBROADCAST_PAST_EXPIRY"
        })]
    );
    assert!(submitted.is_empty());
}

/// Control: with both trades open, the same settle is submitted.
#[tokio::test]
async fn a_settle_of_two_trades_reorged_out_before_both_expiries_is_submitted() {
    let (_, mixed_id, r, submitted) = reorg_a_two_trade_settle_at(|e| e - 1).await;
    assert_eq!(
        r.iter().map(Event::to_json).collect::<Vec<_>>(),
        [json!({
            "event": "rebroadcast",
            "txid": mixed_id.to_string(),
            "outcome": "submitted",
            "attempt": 1
        })]
    );
    assert_eq!(submitted, vec![mixed_id]);
}

#[tokio::test]
async fn finality_is_reported_at_depth_n_not_before() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![funding]);
    w.poll(&source).await.unwrap();

    source.extend(block(2), 109, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    source.extend(block(3), 110, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["final authorizer_seen T/asset", "final funded T/cash"]
    );
}

/// A reorg deeper than N is what N is chosen to make unlikely, not impossible. Finality is
/// reported per acceptance, so a transaction accepted again is reported final again.
#[tokio::test]
async fn a_final_transaction_reorged_out_is_final_again_once_accepted_again() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 100, vec![funding.clone()]);
    source.extend(block(3), 110, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names)[2..],
        ["final authorizer_seen T/asset", "final funded T/cash"]
    );

    source.add_block(block(11), block(1), 100, vec![]);
    source.add_block(block(12), block(11), 101, vec![]);
    source.add_block(block(13), block(12), 110, vec![]);
    source.set_sink(block(13));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg authorizer_seen T/asset", "reorg funded T/cash"]
    );
    for reorg in &e {
        assert!(matches!(
            reorg,
            Event::Reorg {
                was_final: true,
                ..
            }
        ));
        assert_eq!(reorg.code(), Some("WATCH_FINAL_REORGED"));
        assert_eq!(reorg.to_json()["was_final"], json!(true));
    }

    source.extend(block(14), 111, vec![funding]);
    source.extend(block(15), 121, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "accepted authorizer_seen T/asset",
            "accepted funded T/cash",
            "final authorizer_seen T/asset",
            "final funded T/cash"
        ]
    );
}

#[tokio::test]
async fn a_failed_poll_reports_nothing_and_loses_nothing() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![funding]);
    source.fail_next(Call::Walk, "connection reset");
    let err = w.poll(&source).await.unwrap_err();
    assert_eq!(err.code(), "WATCH_SOURCE_FAILED");

    // Control: the same walk, served on the next poll, is reported in full.
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted authorizer_seen T/asset", "accepted funded T/cash"]
    );
}

// ---- restart from the state object ----

/// A watcher rebuilt from `w`'s state, with trade vector 2 added again as the binary would.
fn restarted(w: Watcher) -> Watcher {
    let mut w = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(10).unwrap(),
        w.into_state(),
    );
    w.add_trade(terms(2)).unwrap();
    w
}

#[tokio::test]
async fn acceptances_from_before_a_restart_are_reported_final() {
    let KasTrade {
        mut w,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding]);
    source.extend(block(3), 102, vec![settle]);
    w.poll(&source).await.unwrap();

    let mut w = restarted(w);
    source.extend(block(4), 112, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "final authorizer_seen T/asset",
            "final funded T/cash",
            "final settled T/asset",
            "final settled T/cash"
        ]
    );

    // Reported once, across a second restart too.
    let mut w = restarted(w);
    source.extend(block(5), 130, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_reorg_after_a_restart_is_reported_and_rebroadcast() {
    let KasTrade {
        mut w,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle.clone()]);
    w.poll(&source).await.unwrap();

    let mut w = restarted(w);
    source.add_block(block(13), block(2), 102, vec![]);
    source.add_block(block(14), block(13), 103, vec![]);
    source.set_sink(block(14));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg settled T/asset", "reorg settled T/cash"]
    );
    assert_eq!(w.tracker().accepting_block(&settle_id), None);
    assert_eq!(w.tracker().accepting_block(&id(&funding)), at(2, 101));

    // The pending rebroadcast survives a restart before it is made.
    let mut w = restarted(w);
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);
    let node = FakeBroadcaster::default();
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(node.handed(), vec![settle.tx().clone()]);
}

#[tokio::test]
async fn a_resumed_state_whose_trade_is_not_added_again_is_refused() {
    let KasTrade {
        mut w,
        id: trade_id,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding]);

    // Resumed without the trade, as if its terms file were missing: refused, nothing walked.
    let mut w = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(10).unwrap(),
        w.into_state(),
    );
    let err = w.poll(&source).await.unwrap_err();
    assert_eq!(err, WatchError::TradeNotResumed(vec![trade_id]));
    assert_eq!(err.code(), "WATCH_TRADE_NOT_RESUMED");
    assert_eq!(
        err.to_string(),
        format!("WATCH_TRADE_NOT_RESUMED: trades of the resumed state not added again: {trade_id}")
    );
    assert_eq!(cursor_of(&w), Some((block(1), Some(100))));

    // Another trade does not stand in for it.
    w.add_trade(terms(1)).unwrap();
    assert_eq!(
        w.poll(&source).await.unwrap_err(),
        WatchError::TradeNotResumed(vec![trade_id])
    );

    // Control: added again, it keeps its start, and the funding accepted meanwhile is reported.
    assert_eq!(w.add_trade(terms(2)).unwrap().from, None);
    assert_eq!(
        brief(&w.poll(&source).await.unwrap(), &names),
        ["accepted authorizer_seen T/asset", "accepted funded T/cash"]
    );
}

#[tokio::test]
async fn a_refused_trade_is_not_recorded_in_the_state() {
    let mut w = mainnet_watcher(10);
    let source = started(&mut w).await;
    assert_eq!(
        w.add_trade(terms(8)).unwrap_err().code(),
        "WATCH_NETWORK_MISMATCH"
    );
    assert_eq!(
        w.add_trade(terms(7)).unwrap_err().code(),
        "TEMPLATE_NO_VAULT"
    );
    let id = w.add_trade(terms(2)).unwrap().trade;
    assert_eq!(
        w.add_trade(terms(2)).unwrap_err(),
        WatchError::TradeDuplicate(id)
    );
    source.extend(block(2), 101, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());

    // Resumed: only the trade that was added is missing.
    let mut w = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(10).unwrap(),
        w.into_state(),
    );
    assert_eq!(
        w.poll(&source).await.unwrap_err(),
        WatchError::TradeNotResumed(vec![id])
    );
    // Control: added again, the poll runs.
    w.add_trade(terms(2)).unwrap();
    source.extend(block(3), 102, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert_eq!(cursor_of(&w), Some((block(3), Some(102))));
}

// ---- trades added once polls have run ----

#[tokio::test]
async fn a_trade_added_once_polls_have_run_is_watched_from_the_cursor() {
    let KasTrade {
        id: trade_id,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);

    // Control: added before the first poll, watched from the watcher's start; the funding in
    // the first block after it is reported.
    let mut early = mainnet_watcher(10);
    let watching = early.add_trade(terms(2)).unwrap();
    assert_eq!(
        watching,
        Watching {
            trade: trade_id,
            from: None
        }
    );
    let source = started(&mut early).await;
    source.extend(block(2), 101, vec![funding.clone()]);
    assert_eq!(
        brief(&early.poll(&source).await.unwrap(), &names),
        ["accepted authorizer_seen T/asset", "accepted funded T/cash"]
    );

    // Added once the watcher has walked to block 2 (DAA 101), which accepted the funding: the
    // trade is watched from block 2 only, and add_trade says so.
    let mut w = mainnet_watcher(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    let watching = w.add_trade(terms(2)).unwrap();
    let block_2 = Some(Cursor {
        block_hash: block(2),
        daa_score: Some(101),
    });
    assert_eq!(
        watching,
        Watching {
            trade: trade_id,
            from: block_2
        }
    );
    source.extend(block(3), 102, vec![settle]);
    assert_eq!(
        brief(&w.poll(&source).await.unwrap(), &names),
        ["accepted settled T/asset", "accepted settled T/cash"]
    );

    // Resumed: the trade keeps the cursor it was first added at, not the cursor now (block
    // 3); a trade new to the resumed state is watched from the cursor now.
    let mut w = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(10).unwrap(),
        w.into_state(),
    );
    assert_eq!(w.add_trade(terms(2)).unwrap().from, block_2);
    assert_eq!(
        w.add_trade(terms(1)).unwrap().from,
        Some(Cursor {
            block_hash: block(3),
            daa_score: Some(102),
        })
    );
}

// ---- repeated and inconsistent notifications ----

/// A walk adding `hash` (already in the fake's tree) at `daa` with `txs`, delivered verbatim.
fn scripted(
    removed: &[u64],
    hash: u64,
    daa: u64,
    txs: Vec<AcceptedTransaction>,
) -> VirtualChainUpdate {
    VirtualChainUpdate {
        removed_chain_block_hashes: removed.iter().map(|n| block(*n)).collect(),
        added_chain_blocks: vec![AddedChainBlock {
            hash: block(hash),
            daa_score: daa,
            accepted_transactions: txs,
        }],
    }
}

#[tokio::test]
async fn a_walk_delivered_twice_is_reported_once() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding.clone()]);
    let walk = scripted(&[], 2, 101, vec![funding.clone()]);
    source.push_scripted(walk.clone());
    source.push_scripted(walk);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted authorizer_seen T/asset", "accepted funded T/cash"]
    );
    assert!(
        w.poll(&source).await.unwrap().is_empty(),
        "no second report"
    );
    assert_eq!(w.tracker().accepting_block(&id(&funding)), at(2, 101));
    assert_eq!(cursor_of(&w), Some((block(2), Some(101))));
}

#[tokio::test]
async fn a_removed_block_named_twice_is_reported_once() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding.clone()]);
    w.poll(&source).await.unwrap();
    source.add_block(block(3), block(1), 101, vec![]);
    source.set_sink(block(3));
    source.push_scripted(scripted(&[2, 2], 3, 101, vec![]));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg authorizer_seen T/asset", "reorg funded T/cash"]
    );
    assert_eq!(w.tracker().accepting_block(&id(&funding)), None);
    assert_eq!(cursor_of(&w), Some((block(3), Some(101))));
}

/// The same transaction delivered at another block with no removal of the first: reported as
/// a reorg of the old acceptance and an acceptance at the new one, and final again from there.
#[tokio::test]
async fn an_acceptance_moved_without_a_removal_is_reported_as_a_move() {
    let KasTrade {
        mut w,
        names,
        funding,
        ..
    } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 112, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names)[2..],
        ["final authorizer_seen T/asset", "final funded T/cash"]
    );

    source.add_block(block(4), block(3), 125, vec![funding.clone()]);
    source.set_sink(block(4));
    source.push_scripted(scripted(&[], 4, 125, vec![funding.clone()]));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "reorg authorizer_seen T/asset",
            "reorg funded T/cash",
            "accepted authorizer_seen T/asset",
            "accepted funded T/cash"
        ]
    );
    assert_eq!(w.tracker().accepting_block(&id(&funding)), at(4, 125));

    source.extend(block(5), 135, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["final authorizer_seen T/asset", "final funded T/cash"]
    );
    assert!(matches!(e[0], Event::Final { depth: 10, .. }));
}

/// One walk whose chain blocks both accept the same kept settle (a valid chain never shows
/// this): each acceptance keeps its own effects, the second is a move within the walk, and a
/// reorg of the later block is reported and rebroadcast. The control is the move across two
/// walks above.
#[tokio::test]
async fn a_transaction_accepted_by_two_blocks_of_one_walk_keeps_each_acceptance() {
    let KasTrade {
        mut w,
        names,
        funding,
        settle,
        ..
    } = kas_trade(10);
    let node = FakeBroadcaster::default();
    let source = started(&mut w).await;
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding]);
    source.extend(block(3), 102, vec![settle.clone()]);
    source.extend(block(4), 103, vec![settle.clone()]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        [
            "accepted authorizer_seen T/asset",
            "accepted funded T/cash",
            "accepted settled T/asset",
            "accepted settled T/cash",
            "reorg settled T/asset",
            "reorg settled T/cash",
            "accepted settled T/asset",
            "accepted settled T/cash"
        ]
    );
    let blocks: Vec<_> = e[2..]
        .iter()
        .map(|e| e.to_json()["accepting_block"].clone())
        .collect();
    let (b3, b4) = (json!(block(3).to_string()), json!(block(4).to_string()));
    assert_eq!(blocks, [&b3, &b3, &b3, &b3, &b4, &b4].map(Clone::clone));
    assert_eq!(w.tracker().accepting_block(&settle_id), at(4, 103));
    assert!(w.pending_rebroadcasts().is_empty());

    // Block 4 leaves the chain: its acceptance is reported undone and the settle rebroadcast.
    source.add_block(block(14), block(3), 103, vec![]);
    source.add_block(block(15), block(14), 104, vec![]);
    source.set_sink(block(15));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["reorg settled T/asset", "reorg settled T/cash"]
    );
    assert_eq!(e[0].to_json()["accepting_block"], b4);
    assert_eq!(w.pending_rebroadcasts(), vec![settle_id]);
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(node.handed(), vec![settle.tx().clone()]);
}

// ---- per-leg attribution ----

/// Two KCC-20 trades between the same parties (vector 1 and a repeat with another nonce).
fn two_trades() -> (
    Watcher,
    TradeId,
    TradeId,
    [Vault; 4],
    HashMap<TradeId, &'static str>,
) {
    let a = terms(1);
    let b = repeat_of(&a);
    let vaults = [
        vault(&a, LegIndex::Asset),
        vault(&a, LegIndex::Cash),
        vault(&b, LegIndex::Asset),
        vault(&b, LegIndex::Cash),
    ];
    let mut w = mainnet_watcher(10);
    let ida = w.add_trade(a).unwrap().trade;
    let idb = w.add_trade(b).unwrap().trade;
    let names = HashMap::from([(ida, "A"), (idb, "B")]);
    (w, ida, idb, vaults, names)
}

/// Mines one block accepting `t` and polls.
async fn accept_one(w: &mut Watcher, node: &Node, t: AcceptedTransaction) -> Vec<Event> {
    node.mine(vec![t]);
    w.poll(&node.chain).await.unwrap()
}

#[tokio::test]
async fn a_settle_mixing_two_trades_is_attributed_per_leg() {
    let node = Node::new();
    let (mut w, ida, idb, [a_asset, _, _, b_cash], names) = two_trades();
    // Trade A's asset vault at input 0 with trade B's cash vault at input 1 (cross-trade
    // mixing), then the two escrowed tokens and a fee input.
    let mixed = tx(
        3,
        vec![
            settle_in(&a_asset, AUTH),
            settle_in(&b_cash, AUTH),
            plain_in(),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let e = accept_one(&mut w, &node, mixed).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled A/asset", "accepted settled B/cash"]
    );
    assert_eq!(
        effects(&e),
        [
            Effect::Settled {
                trade: ida,
                leg: Leg::Asset,
                input: 0,
                spent: TransactionOutpoint::new(Hash::from_u64_word(3), 0),
                spent_value: AUTH,
            },
            Effect::Settled {
                trade: idb,
                leg: Leg::Cash,
                input: 1,
                spent: TransactionOutpoint::new(Hash::from_u64_word(3), 1),
                spent_value: AUTH,
            }
        ]
    );
    let mixed_id = e[0].txid();
    let settled = |trade: TradeId, leg: &str, input: u32| {
        json!({
            "event": "settled",
            "trade": trade.to_string(),
            "leg": leg,
            "input": input,
            "spent_txid": Hash::from_u64_word(3).to_string(),
            "spent_index": input,
            "spent_value": AUTH.to_string(),
            "txid": mixed_id.to_string(),
            "accepting_block": block(1).to_string(),
            "accepting_daa": "100",
            "depth": "0"
        })
    };
    assert_eq!(e[0].to_json(), settled(ida, "asset", 0));
    assert_eq!(e[1].to_json(), settled(idb, "cash", 1));
}

/// The forgery a block producer can mine: an input that spends some other, non-standard UTXO
/// that drops its pushes and leaves true (`OP_2DROP OP_DROP OP_TRUE` for a settle's three
/// pushes, `OP_2DROP OP_2DROP OP_TRUE` for a refund's four), with the signature script of a
/// settle or refund of a watched vault. Consensus accepts it (standardness is a mempool rule
/// only); the vault is untouched.
#[tokio::test]
async fn a_forged_reveal_that_spends_another_utxo_is_not_a_vault_spend() {
    let (mut w, ida, _, [a_asset, _, _, _], names) = two_trades();
    let node = Node::new();
    let forged = |salt: u64, sig: Vec<u8>, anyone: Vec<u8>| {
        tx(
            salt,
            vec![
                In {
                    sig,
                    spends: utxo(AUTH, ScriptPublicKey::new(0, anyone.into())),
                },
                plain_in(),
            ],
            vec![(1_000, stranger())],
        )
    };
    let seller = terms(1).terms().seller_key;
    let settle = forged(30, settle_call(&a_asset), vec![0x6d, 0x75, 0x51]);
    let refund = forged(31, refund_call(&a_asset, seller), vec![0x6d, 0x6d, 0x51]);

    // Evidence that the forged input is valid: the real script engine accepts it.
    for f in [&settle, &refund] {
        let entries = f.spent().to_vec();
        let populated = PopulatedTransaction::new(f.tx(), entries.clone());
        let cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        let mut vm = TxScriptEngine::from_transaction_input(
            &populated,
            &f.tx().inputs[0],
            0,
            &entries[0],
            EngineCtx::new(&cache).with_reused(&reused),
            EngineFlags {
                covenants_enabled: true,
                ..Default::default()
            },
        );
        assert_eq!(vm.execute(), Ok(()), "consensus accepts the forged input");
    }

    for f in [settle, refund] {
        let txid = id(&f);
        assert!(accept_one(&mut w, &node, f).await.is_empty());
        assert_eq!(w.tracker().accepting_block(&txid), None, "not indexed");
    }

    // Control: the same signature script spending the vault's own UTXO is the vault's settle.
    let real = tx(
        32,
        vec![settle_in(&a_asset, AUTH), plain_in()],
        vec![(1_000, stranger())],
    );
    let e = accept_one(&mut w, &node, real).await;
    assert_eq!(brief(&e, &names), ["accepted settled A/asset"]);
    assert_eq!(e[0].effect().unwrap().trade(), ida);
    let j = e[0].to_json();
    assert_eq!(j["input"], json!(0));
    assert_eq!(j["spent_txid"], json!(Hash::from_u64_word(32).to_string()));
    assert_eq!(j["spent_index"], json!(0));
    assert_eq!(j["spent_value"], json!(AUTH.to_string()));
}

/// Consensus has run the vault script for any input that spends the vault's UTXO, so a spend
/// whose signature script does not end with the vault's redeem script, or is not push-only,
/// cannot be accepted. If one is seen, the template is not the one the watcher assumes, and it
/// is never reported as a settle.
#[tokio::test]
async fn a_vault_spend_that_does_not_reveal_the_vault_script_is_unclassified() {
    let (mut w, _, _, [a_asset, _, b_asset, _], names) = two_trades();
    let node = Node::new();
    let from_a = |sig: Vec<u8>| In {
        sig,
        spends: utxo(AUTH, a_asset.script_public_key()),
    };
    // A's UTXO with B's redeem script revealed, and with a script that is not push-only.
    let wrong_reveal = tx(33, vec![from_a(settle_call(&b_asset))], vec![]);
    let not_push_only = tx(34, vec![from_a(vec![0x76])], vec![]);
    for t in [wrong_reveal, not_push_only] {
        let e = accept_one(&mut w, &node, t).await;
        assert_eq!(brief(&e, &names), ["accepted unclassified_spend A/asset"]);
        assert_eq!(e[0].code(), Some("WATCH_SPEND_UNCLASSIFIED"));
    }
    // Control: A's UTXO with A's redeem script.
    let e = accept_one(
        &mut w,
        &node,
        tx(35, vec![from_a(settle_call(&a_asset))], vec![]),
    )
    .await;
    assert_eq!(brief(&e, &names), ["accepted settled A/asset"]);
}

/// [S2]: a KAS leg settles only from a UTXO of exactly the leg amount, so a settle seen from
/// any other amount is unclassified. A refund of such a UTXO is the expected way home.
#[tokio::test]
async fn a_kas_leg_settled_from_an_inexact_utxo_is_unclassified() {
    let KasTrade { mut w, names, .. } = kas_trade(10);
    let node = Node::new();
    let t = terms(2);
    let (amount, buyer) = (t.terms().cash_leg.amount, t.terms().buyer_key);
    let cash = vault(&t, LegIndex::Cash);
    for (salt, value) in [(36, amount - 1), (37, amount + 1)] {
        let off = tx(salt, vec![plain_in(), settle_in(&cash, value)], vec![]);
        let e = accept_one(&mut w, &node, off).await;
        assert_eq!(brief(&e, &names), ["accepted unclassified_spend T/cash"]);
        assert_eq!(e[0].to_json()["spent_value"], json!(value.to_string()));
    }
    // Controls: the exact amount settles; an inexact UTXO refunds.
    let exact = tx(38, vec![plain_in(), settle_in(&cash, amount)], vec![]);
    let e = accept_one(&mut w, &node, exact).await;
    assert_eq!(brief(&e, &names), ["accepted settled T/cash"]);
    let home = tx(39, vec![refund_in(&cash, buyer, amount + 1)], vec![]);
    let e = accept_one(&mut w, &node, home).await;
    assert_eq!(brief(&e, &names), ["accepted refunded T/cash"]);
}

#[tokio::test]
async fn a_settle_of_one_trade_is_attributed_to_both_its_legs() {
    let node = Node::new();
    let (mut w, _, _, [a_asset, a_cash, _, _], names) = two_trades();
    let own = tx(
        3,
        vec![
            settle_in(&a_asset, AUTH),
            settle_in(&a_cash, AUTH),
            plain_in(),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    );
    let e = accept_one(&mut w, &node, own).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled A/asset", "accepted settled A/cash"]
    );
}

#[tokio::test]
async fn refunds_are_attributed_to_the_refunded_leg() {
    let (mut w, _, _, [a_asset, _, _, b_cash], names) = two_trades();
    let buyer = terms(1).terms().buyer_key;
    let seller = terms(1).terms().seller_key;
    let refund_b_cash = tx(
        4,
        vec![refund_in(&b_cash, buyer, AUTH), plain_in(), plain_in()],
        vec![],
    );
    let refund_a_asset = tx(
        5,
        vec![refund_in(&a_asset, seller, AUTH), plain_in()],
        vec![],
    );
    let node = Node::new();
    node.mine(vec![refund_b_cash, refund_a_asset]);
    let e = w.poll(&node.chain).await.unwrap();
    assert_eq!(
        brief(&e, &names),
        ["accepted refunded B/cash", "accepted refunded A/asset"]
    );
}

#[tokio::test]
async fn a_settle_entry_away_from_its_legs_index_is_unclassified() {
    let node = Node::new();
    let (mut w, _, _, [a_asset, a_cash, _, _], names) = two_trades();
    // The asset vault's settle at input 1.
    let shifted = tx(6, vec![plain_in(), settle_in(&a_asset, AUTH)], vec![]);
    let e = accept_one(&mut w, &node, shifted).await;
    assert_eq!(brief(&e, &names), ["accepted unclassified_spend A/asset"]);
    assert_eq!(e[0].code(), Some("WATCH_SPEND_UNCLASSIFIED"));
    assert_eq!(e[0].to_json()["input"], json!(1));
    // The cash vault's settle at input 0 and at input 2.
    let at_0 = tx(46, vec![settle_in(&a_cash, AUTH), plain_in()], vec![]);
    let at_2 = tx(
        47,
        vec![plain_in(), plain_in(), settle_in(&a_cash, AUTH)],
        vec![],
    );
    for (t, input) in [(at_0, 0), (at_2, 2)] {
        let e = accept_one(&mut w, &node, t).await;
        assert_eq!(brief(&e, &names), ["accepted unclassified_spend A/cash"]);
        assert_eq!(e[0].to_json()["input"], json!(input));
    }
    // Control: each vault at its own index.
    let own = tx(
        48,
        vec![settle_in(&a_asset, AUTH), settle_in(&a_cash, AUTH)],
        vec![],
    );
    let e = accept_one(&mut w, &node, own).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled A/asset", "accepted settled A/cash"]
    );
}

#[tokio::test]
async fn a_refund_entry_away_from_input_0_is_unclassified() {
    let node = Node::new();
    let (mut w, _, _, [_, a_cash, _, _], names) = two_trades();
    let buyer = terms(1).terms().buyer_key;
    let shifted = tx(7, vec![plain_in(), refund_in(&a_cash, buyer, AUTH)], vec![]);
    let e = accept_one(&mut w, &node, shifted).await;
    assert_eq!(brief(&e, &names), ["accepted unclassified_spend A/cash"]);
    // Control: the same refund at input 0.
    let at_zero = tx(8, vec![refund_in(&a_cash, buyer, AUTH), plain_in()], vec![]);
    let e = accept_one(&mut w, &node, at_zero).await;
    assert_eq!(brief(&e, &names), ["accepted refunded A/cash"]);
}

#[tokio::test]
async fn an_unknown_entry_tag_is_unclassified() {
    let node = Node::new();
    let (mut w, _, _, [a_asset, _, _, _], names) = two_trades();
    let unknown = In {
        sig: push_all(&[&SIG, &[0xde, 0xad, 0xbe, 0xef], a_asset.redeem_script()]),
        spends: utxo(AUTH, a_asset.script_public_key()),
    };
    let e = accept_one(&mut w, &node, tx(9, vec![unknown], vec![])).await;
    assert_eq!(brief(&e, &names), ["accepted unclassified_spend A/asset"]);
    // Control: the settle tag in the same place.
    let e = accept_one(
        &mut w,
        &node,
        tx(10, vec![settle_in(&a_asset, AUTH)], vec![]),
    )
    .await;
    assert_eq!(brief(&e, &names), ["accepted settled A/asset"]);
}

#[tokio::test]
async fn spends_and_fundings_of_unwatched_vaults_are_ignored() {
    let node = Node::new();
    let c = terms(2);
    let (c_asset, c_cash) = (vault(&c, LegIndex::Asset), vault(&c, LegIndex::Cash));
    let (mut w, _, _, _, _) = two_trades();
    let c_amount = c.terms().cash_leg.amount;
    let spend = tx(
        11,
        vec![settle_in(&c_asset, AUTH), settle_in(&c_cash, c_amount)],
        vec![],
    );
    let fund = tx(
        12,
        vec![plain_in()],
        vec![(1_000, c_asset.script_public_key())],
    );
    let e = accept_one(&mut w, &node, spend.clone()).await;
    assert!(e.is_empty());
    assert!(accept_one(&mut w, &node, fund).await.is_empty());
    assert_eq!(
        w.tracker().accepting_block(&id(&spend)),
        None,
        "not indexed"
    );

    // Control: once trade C is watched, the same kind of spend is reported.
    let idc = w.add_trade(c).unwrap().trade;
    let names = HashMap::from([(idc, "C")]);
    let spend = tx(
        13,
        vec![settle_in(&c_asset, AUTH), settle_in(&c_cash, c_amount)],
        vec![],
    );
    let e = accept_one(&mut w, &node, spend).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled C/asset", "accepted settled C/cash"]
    );
}

#[tokio::test]
async fn a_kas_leg_funded_with_another_amount_is_flagged() {
    let node = Node::new();
    let KasTrade { mut w, id, .. } = kas_trade(10);
    let t = terms(2);
    let amount = t.terms().cash_leg.amount;
    let cash = vault(&t, LegIndex::Cash);
    // Short, over, and the largest value an output can name: none of them can settle.
    for (salt, value) in [(14, amount - 1), (44, amount + 1), (45, u64::MAX)] {
        let off = tx(
            salt,
            vec![plain_in()],
            vec![(value, cash.script_public_key())],
        );
        let e = accept_one(&mut w, &node, off).await;
        assert_eq!(
            effects(&e),
            [Effect::Funded {
                trade: id,
                leg: Leg::Cash,
                index: 0,
                value,
                exact: false
            }],
            "{value}"
        );
        assert_eq!(e[0].code(), Some("WATCH_FUNDING_NOT_EXACT"), "{value}");
    }
    // Control: the exact amount carries no flag.
    let exact = tx(
        15,
        vec![plain_in()],
        vec![(amount, cash.script_public_key())],
    );
    let e = accept_one(&mut w, &node, exact).await;
    assert_eq!(
        effects(&e)[0],
        Effect::Funded {
            trade: id,
            leg: Leg::Cash,
            index: 0,
            value: amount,
            exact: true
        }
    );
    assert_eq!(e[0].code(), None);
}

/// Anyone can pay a vault address. For a KCC-20 leg the watcher sees only the authorizer, so a
/// 1-sompi deposit is reported as what it is, an authorizer seen with the escrow not verified,
/// and never as a funded leg.
#[tokio::test]
async fn a_one_sompi_deposit_to_a_kcc20_vault_is_never_reported_funded() {
    let (mut w, ida, _, [a_asset, _, _, _], names) = two_trades();
    let node = Node::new();
    let dust = tx(40, vec![plain_in()], vec![(1, a_asset.script_public_key())]);
    let dust_id = id(&dust);
    let e = accept_one(&mut w, &node, dust).await;
    assert_eq!(brief(&e, &names), ["accepted authorizer_seen A/asset"]);
    assert_eq!(
        effects(&e),
        [Effect::AuthorizerSeen {
            trade: ida,
            leg: Leg::Asset,
            index: 0,
            value: 1,
            covenant_output: false
        }]
    );
    assert_eq!(
        e[0].to_json(),
        json!({
            "event": "authorizer_seen",
            "trade": ida.to_string(),
            "leg": "asset",
            "output": 0,
            "value": "1",
            "escrow": "not_verified",
            "covenant_output": false,
            "txid": dust_id.to_string(),
            "accepting_block": block(1).to_string(),
            "accepting_daa": "100",
            "depth": "0"
        })
    );
    assert!(e.iter().all(|e| e.effect().unwrap().name() != "funded"));

    // Control: a KAS leg paid the exact amount is funded.
    let KasTrade {
        w: mut kas, names, ..
    } = kas_trade(10);
    let t = terms(2);
    let cash = vault(&t, LegIndex::Cash);
    let paid = tx(
        41,
        vec![plain_in()],
        vec![(t.terms().cash_leg.amount, cash.script_public_key())],
    );
    let e = accept_one(&mut kas, &Node::new(), paid).await;
    assert_eq!(brief(&e, &names), ["accepted funded T/cash"]);
}

/// An output bound to the leg's covenant ID in the same transaction is reported, and still
/// leaves the escrow not verified: it shows a token of that covenant moved, not where to.
#[tokio::test]
async fn an_authorizer_beside_a_token_output_of_the_legs_covenant_is_flagged_as_such() {
    let t = terms(1);
    let LegKind::Kcc20(token) = t.terms().asset_leg.kind else {
        panic!("vector 1 has a KCC-20 asset leg")
    };
    let (mut w, _, _, [a_asset, _, _, _], names) = two_trades();
    let node = Node::new();
    let with_covenant = |salt: u64, covenant: [u8; 32]| {
        let mut t = tx(
            salt,
            vec![plain_in(), plain_in()],
            vec![(AUTH, a_asset.script_public_key()), (1_000, stranger())],
        )
        .tx()
        .clone();
        t.outputs[1].covenant = Some(CovenantBinding::new(1, Hash::from_bytes(covenant)));
        t.finalize();
        let spent = vec![utxo(10_000, stranger()), utxo(1_000, stranger())];
        AcceptedTransaction::new(t, spent).unwrap()
    };
    let e = accept_one(&mut w, &node, with_covenant(42, token.covenant_id)).await;
    assert_eq!(brief(&e, &names), ["accepted authorizer_seen A/asset"]);
    assert_eq!(e[0].to_json()["covenant_output"], json!(true));
    assert_eq!(e[0].to_json()["escrow"], json!("not_verified"));
    // Control: an output under another covenant ID.
    let e = accept_one(&mut w, &node, with_covenant(43, [0x99; 32])).await;
    assert_eq!(e[0].to_json()["covenant_output"], json!(false));
}

// ---- stray deposits to the cash-vault script of external-cash terms (decision D14) ----

#[tokio::test]
async fn a_deposit_to_the_cash_vault_script_of_external_cash_terms_is_flagged() {
    let node = Node::new();
    let t = terms(5);
    let asset = vault(&t, LegIndex::Asset);
    let stray = pay_to_script_hash_script(&stray_cash_script(asset.redeem_script()).unwrap());
    let mut w = mainnet_watcher(10);
    let id = w.add_trade(t).unwrap().trade;
    let names = HashMap::from([(id, "X")]);

    let deposit = tx(
        16,
        vec![plain_in()],
        vec![(5_000, stranger()), (2_000, stray)],
    );
    let e = accept_one(&mut w, &node, deposit).await;
    assert_eq!(brief(&e, &names), ["accepted stray_deposit X"]);
    assert_eq!(e[0].code(), Some("WATCH_STRAY_DEPOSIT"));
    let j = e[0].to_json();
    assert_eq!(j["output"], json!(1));
    assert_eq!(j["value"], json!("2000"));
    assert!(j.get("leg").is_none(), "a stray deposit belongs to no leg");
    assert!(
        !j.to_string().contains("kaspa:"),
        "no address is shown for this script"
    );

    // Control: a deposit to the asset vault of the same terms is a plain funding.
    let funding = tx(
        17,
        vec![plain_in()],
        vec![(1_000, asset.script_public_key())],
    );
    let e = accept_one(&mut w, &node, funding).await;
    assert_eq!(brief(&e, &names), ["accepted authorizer_seen X/asset"]);
    assert_eq!(e[0].code(), None);
}

/// A reorg of a stray deposit keeps the flag, so the operator sees the deposit leave the chain.
#[tokio::test]
async fn a_reorged_stray_deposit_is_reported_with_its_flag() {
    let t = terms(5);
    let asset = vault(&t, LegIndex::Asset);
    let stray = pay_to_script_hash_script(&stray_cash_script(asset.redeem_script()).unwrap());
    let mut w = mainnet_watcher(10);
    let idx = w.add_trade(t).unwrap().trade;
    let names = HashMap::from([(idx, "X")]);
    let source = started(&mut w).await;
    let deposit = tx(55, vec![plain_in()], vec![(2_000, stray)]);
    let deposit_id = id(&deposit);
    source.extend(block(2), 101, vec![deposit]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(brief(&e, &names), ["accepted stray_deposit X"]);

    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 102, vec![]);
    source.set_sink(block(13));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(brief(&e, &names), ["reorg stray_deposit X"]);
    assert_eq!(
        e[0].to_json(),
        json!({
            "event": "reorg",
            "of": "stray_deposit",
            "trade": idx.to_string(),
            "output": 0,
            "value": "2000",
            "txid": deposit_id.to_string(),
            "accepting_block": block(2).to_string(),
            "accepting_daa": "101",
            "was_final": false,
            "code": "WATCH_STRAY_DEPOSIT"
        })
    );
    assert_eq!(w.tracker().accepting_block(&deposit_id), None);
}

#[test]
fn the_stray_script_is_the_template_at_leg_index_1() {
    // Where the cash leg has a vault, the same patch gives exactly impulse-core's cash vault.
    for n in [1, 2] {
        let t = terms(n);
        let asset = vault(&t, LegIndex::Asset);
        let cash = vault(&t, LegIndex::Cash);
        assert_eq!(
            with_cash_leg_index(asset.redeem_script()).unwrap(),
            cash.redeem_script()
        );
    }
    // Under external cash, impulse-core gives no cash vault and decodes the script as the
    // cash leg with no vault, as spec/TEMPLATE.md says.
    let t = terms(5);
    let asset = vault(&t, LegIndex::Asset);
    let stray = stray_cash_script(asset.redeem_script()).unwrap();
    assert_eq!(
        Vault::instantiate_existing(&t, LegIndex::Cash)
            .unwrap_err()
            .code(),
        "TEMPLATE_NO_VAULT"
    );
    assert_eq!(
        template::decode(&stray).unwrap_err().code(),
        "TEMPLATE_NO_VAULT"
    );
    assert_ne!(stray, asset.redeem_script());
    assert_eq!(stray.len(), asset.redeem_script().len());
}

#[test]
fn the_stray_script_is_derived_only_from_an_external_cash_asset_vault() {
    let kas = terms(2);
    let refused = |script: &[u8]| stray_cash_script(script).unwrap_err().code();
    // A real cash vault exists under these terms, so the patched script decodes: refused.
    assert_eq!(
        refused(vault(&kas, LegIndex::Asset).redeem_script()),
        "WATCH_STRAY_SCRIPT_UNDERIVABLE"
    );
    // Not an asset vault: its legIndex is already 1.
    assert_eq!(
        refused(vault(&kas, LegIndex::Cash).redeem_script()),
        "WATCH_STRAY_SCRIPT_UNDERIVABLE"
    );
    assert_eq!(refused(b"not a vault"), "WATCH_STRAY_SCRIPT_UNDERIVABLE");
    // Control: the asset vault of external-cash terms.
    assert!(stray_cash_script(vault(&terms(5), LegIndex::Asset).redeem_script()).is_ok());
}

// ---- watching a trade: refusals and controls ----

#[test]
fn terms_of_another_network_are_refused() {
    let mut w = mainnet_watcher(10);
    let err = w.add_trade(terms(8)).unwrap_err();
    assert_eq!(err.code(), "WATCH_NETWORK_MISMATCH");
    assert!(w.trades().is_empty());
    // Controls: mainnet terms here, the testnet terms in a testnet watcher.
    w.add_trade(terms(2)).unwrap();
    let mut tn = Watcher::new(Network::Testnet, FinalityPolicy::new(10).unwrap());
    tn.add_trade(terms(8)).unwrap();
}

#[test]
fn direct_terms_are_refused_for_having_no_vault() {
    let mut w = mainnet_watcher(10);
    let err = w.add_trade(terms(7)).unwrap_err();
    assert_eq!(err.code(), "TEMPLATE_NO_VAULT");
    assert!(w.trades().is_empty());
    // Control: vault terms.
    w.add_trade(terms(1)).unwrap();
}

#[test]
fn a_trade_watched_twice_is_refused() {
    let mut w = mainnet_watcher(10);
    let id = w.add_trade(terms(1)).unwrap().trade;
    let err = w.add_trade(terms(1)).unwrap_err();
    assert_eq!(err, WatchError::TradeDuplicate(id));
    assert_eq!(err.code(), "WATCH_TRADE_DUPLICATE");
    assert_eq!(w.trades().len(), 1);
    // Control: a repeat trade with another nonce is another trade.
    w.add_trade(repeat_of(&terms(1))).unwrap();
    assert_eq!(w.trades().len(), 2);
}

// ---- keeping a signed transaction: refusals and controls ----

#[test]
fn a_transaction_with_an_unsigned_input_is_not_kept() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let mut unsigned = settle.tx().clone();
    unsigned.inputs[3].signature_script.clear();
    let err = w.keep_signed(unsigned).unwrap_err();
    assert_eq!(err, WatchError::TxUnsigned { input: 3 });
    assert_eq!(err.code(), "WATCH_TX_UNSIGNED");
    // Control: every input signed.
    w.keep_signed(settle.tx().clone()).unwrap();
}

#[test]
fn a_transaction_that_spends_no_watched_vault_is_not_kept() {
    let KasTrade {
        mut w,
        funding,
        settle,
        ..
    } = kas_trade(10);
    assert_eq!(
        w.keep_signed(funding.tx().clone()).unwrap_err().code(),
        "WATCH_TX_NOT_TRACKED"
    );
    // An unclassified spend is not a settle or refund either.
    let asset = vault(&terms(2), LegIndex::Asset);
    let shifted = tx(18, vec![plain_in(), settle_in(&asset, AUTH)], vec![]);
    assert_eq!(
        w.keep_signed(shifted.tx().clone()).unwrap_err().code(),
        "WATCH_TX_NOT_TRACKED"
    );
    // Control: the settle.
    w.keep_signed(settle.tx().clone()).unwrap();
}

/// A claimed entry counts only at the input index the vault runs it at: refund at input 0
/// ([R4]), settle at the leg's own index ([S1]), here the cash leg's index 1.
#[test]
fn a_spend_claimed_away_from_its_entrys_index_is_not_kept() {
    let KasTrade { mut w, .. } = kas_trade(10);
    let t = terms(2);
    let (asset, cash) = (vault(&t, LegIndex::Asset), vault(&t, LegIndex::Cash));
    let (amount, seller) = (t.terms().cash_leg.amount, t.terms().seller_key);
    let refund_at_1 = tx(
        60,
        vec![plain_in(), refund_in(&asset, seller, AUTH)],
        vec![],
    );
    let cash_at_0 = tx(61, vec![settle_in(&cash, amount), plain_in()], vec![]);
    let cash_at_2 = tx(
        62,
        vec![plain_in(), plain_in(), settle_in(&cash, amount)],
        vec![],
    );
    for t in [refund_at_1, cash_at_0, cash_at_2] {
        assert_eq!(
            w.keep_signed(t.tx().clone()).unwrap_err().code(),
            "WATCH_TX_NOT_TRACKED"
        );
    }
    // Controls: the refund at input 0, and the cash vault's settle at input 1, each alone.
    let refund_at_0 = tx(
        63,
        vec![refund_in(&asset, seller, AUTH), plain_in()],
        vec![],
    );
    let cash_at_1 = tx(64, vec![plain_in(), settle_in(&cash, amount)], vec![]);
    w.keep_signed(refund_at_0.tx().clone()).unwrap();
    w.keep_signed(cash_at_1.tx().clone()).unwrap();
}

#[test]
fn a_txid_kept_twice_is_refused() {
    let KasTrade {
        mut w,
        settle,
        id: _,
        ..
    } = kas_trade(10);
    let txid = w.keep_signed(settle.tx().clone()).unwrap();
    assert_eq!(
        w.keep_signed(settle.tx().clone()).unwrap_err(),
        WatchError::TxDuplicate(txid)
    );
    // Control: another transaction.
    let asset = vault(&terms(2), LegIndex::Asset);
    let refund = tx(
        19,
        vec![refund_in(&asset, [0x11; 32], AUTH), plain_in()],
        vec![],
    );
    w.keep_signed(refund.tx().clone()).unwrap();
}

#[test]
fn the_kept_txid_is_computed_not_read_from_the_cache() {
    let KasTrade { mut w, settle, .. } = kas_trade(10);
    let t = settle.tx();
    let stale = Transaction::new_non_finalized(
        t.version,
        t.inputs.clone(),
        t.outputs.clone(),
        t.lock_time,
        t.subnetwork_id,
        t.gas,
        t.payload.clone(),
    );
    assert_ne!(
        stale.id(),
        id(&settle),
        "the cache of a non-finalised transaction is empty"
    );
    assert_eq!(w.keep_signed(stale).unwrap(), id(&settle));
}

// ---- codes and shapes ----

#[test]
fn watch_codes_are_frozen() {
    assert_eq!(
        WATCH_ERROR_CODES,
        [
            "WATCH_NETWORK_MISMATCH",
            "WATCH_TRADE_DUPLICATE",
            "WATCH_FINALITY_DEPTH_ZERO",
            "WATCH_STRAY_SCRIPT_UNDERIVABLE",
            "WATCH_TX_UNSIGNED",
            "WATCH_TX_NOT_TRACKED",
            "WATCH_TX_DUPLICATE",
            "WATCH_SOURCE_FAILED",
            "WATCH_TRADE_NOT_RESUMED",
            "WATCH_TRADE_UNKNOWN",
            "WATCH_RETENTION_TOO_SHORT",
            "WATCH_NODE_URL_INVALID",
            "WATCH_NODE_INSECURE",
            "WATCH_NODE_UNREACHABLE",
            "WATCH_NODE_NETWORK_MISMATCH",
            "WATCH_NODE_NOT_SYNCED",
            "WATCH_NODE_RPC",
            "WATCH_FILE_READ",
            "WATCH_TERMS_FILE_INVALID",
            "WATCH_TERMS_FILE_INCONSISTENT",
            "WATCH_SIGNED_TX_INVALID",
            "WATCH_STATE_INVALID",
            "WATCH_STATE_MISMATCH",
            "WATCH_STATE_WRITE_FAILED",
            "WATCH_STATE_LOCKED",
            "WATCH_RETIRE_WATCHED",
            "WATCH_PROBE_FAILED",
            "WATCH_STATE_MISSING",
            "WATCH_STATE_EXISTS",
            "WATCH_OUTPUT_FAILED",
        ]
    );
    assert_eq!(
        WATCH_EVENT_CODES,
        [
            "WATCH_STRAY_DEPOSIT",
            "WATCH_FUNDING_NOT_EXACT",
            "WATCH_SPEND_UNCLASSIFIED",
            "WATCH_REBROADCAST_FAILED",
            "WATCH_REBROADCAST_ABANDONED",
            "WATCH_REBROADCAST_PAST_EXPIRY",
            "WATCH_FINAL_REORGED",
            "WATCH_LINK_RETURN_EARLY",
            "WATCH_FOREIGN_TOKEN",
        ]
    );
    let every = [
        WatchError::NetworkMismatch {
            watcher: Network::Mainnet,
            terms: Network::Testnet,
        },
        WatchError::TradeDuplicate(TradeId([0; 32])),
        WatchError::FinalityDepthZero,
        WatchError::StrayScriptUnderivable,
        WatchError::TxUnsigned { input: 0 },
        WatchError::TxNotTracked,
        WatchError::TxDuplicate(Hash::default()),
        WatchError::SourceFailed(String::new()),
        WatchError::TradeNotResumed(vec![TradeId([0; 32])]),
        WatchError::TradeUnknown(TradeId([0; 32])),
        WatchError::RetentionTooShort {
            retain_daa: 1,
            finality_daa: 1,
        },
        WatchError::NodeUrlInvalid(String::new()),
        WatchError::NodeInsecure(String::new()),
        WatchError::NodeUnreachable(String::new()),
        WatchError::NodeNetworkMismatch {
            node: String::new(),
            watching: "mainnet",
        },
        WatchError::NodeNotSynced,
        WatchError::NodeRpc(String::new()),
        WatchError::FileRead {
            path: String::new(),
            reason: String::new(),
        },
        WatchError::TermsFileInvalid {
            path: String::new(),
            reason: String::new(),
        },
        WatchError::TermsFileInconsistent {
            path: String::new(),
        },
        WatchError::SignedTxInvalid {
            path: String::new(),
            reason: String::new(),
        },
        WatchError::StateInvalid(String::new()),
        WatchError::StateMismatch {
            state: String::new(),
            watching: "mainnet",
        },
        WatchError::StateWriteFailed {
            path: String::new(),
            reason: String::new(),
        },
        WatchError::StateLocked(String::new()),
        WatchError::RetireWatched(TradeId([0; 32])),
        WatchError::ProbeFailed(String::new()),
        WatchError::StateMissing(String::new()),
        WatchError::StateExists(String::new()),
        WatchError::OutputFailed(String::new()),
    ];
    let codes: Vec<&str> = every.iter().map(WatchError::code).collect();
    assert_eq!(codes, WATCH_ERROR_CODES);
    for e in &every {
        assert!(e.to_string().starts_with(e.code()), "{e}");
    }
}

#[tokio::test]
async fn events_serialise_as_one_json_object_each() {
    let node = Node::new();
    let KasTrade {
        mut w, id, funding, ..
    } = kas_trade(10);
    let e = accept_one(&mut w, &node, funding.clone()).await;
    assert_eq!(
        e[1].to_json(),
        json!({
            "event": "funded",
            "trade": id.to_string(),
            "leg": "cash",
            "output": 1,
            "value": terms(2).terms().cash_leg.amount.to_string(),
            "exact": true,
            "txid": funding.tx().id().to_string(),
            "accepting_block": block(1).to_string(),
            "accepting_daa": "100",
            "depth": "0"
        })
    );
    assert_eq!(e[0].to_json()["event"], json!("authorizer_seen"));
    assert_eq!(e[0].to_json()["escrow"], json!("not_verified"));
    assert!(e[0].to_json().get("exact").is_none());
}

/// u64 values are decimal strings: a JSON number above 2^53 would lose precision in a
/// JavaScript consumer.
#[tokio::test]
async fn u64_values_are_decimal_strings() {
    let node = Node::new();
    let KasTrade { mut w, .. } = kas_trade(10);
    let cash = vault(&terms(2), LegIndex::Cash);
    let big = (1u64 << 53) + 1;
    let paid = tx(51, vec![plain_in()], vec![(big, cash.script_public_key())]);
    let e = accept_one(&mut w, &node, paid).await;
    let j = e[0].to_json();
    assert_eq!(j["value"], json!("9007199254740993"));
    assert_eq!(j["accepting_daa"], json!("100"));
    assert_eq!(j["depth"], json!("0"));
    assert_eq!(j["output"], json!(0), "u32 values stay numbers");
}

/// The JSON of refunded, unclassified and stray events, field for field.
#[tokio::test]
async fn refund_unclassified_and_stray_events_have_their_frozen_shape() {
    let node = Node::new();
    let (mut w, ida, _, [a_asset, _, _, _], _) = two_trades();
    let spend = |event: &str, input: u32, txid: TransactionId, salt: u64, n: u64| {
        json!({
            "event": event,
            "trade": ida.to_string(),
            "leg": "asset",
            "input": input,
            "spent_txid": Hash::from_u64_word(salt).to_string(),
            "spent_index": input,
            "spent_value": AUTH.to_string(),
            "txid": txid.to_string(),
            "accepting_block": block(n).to_string(),
            "accepting_daa": (99 + n).to_string(),
            "depth": "0"
        })
    };
    let seller = terms(1).terms().seller_key;
    let refund = tx(
        52,
        vec![refund_in(&a_asset, seller, AUTH), plain_in()],
        vec![],
    );
    let refund_id = id(&refund);
    let e = accept_one(&mut w, &node, refund).await;
    assert_eq!(e[0].to_json(), spend("refunded", 0, refund_id, 52, 1));

    let shifted = tx(53, vec![plain_in(), settle_in(&a_asset, AUTH)], vec![]);
    let shifted_id = id(&shifted);
    let e = accept_one(&mut w, &node, shifted).await;
    let mut expected = spend("unclassified_spend", 1, shifted_id, 53, 2);
    expected["code"] = json!("WATCH_SPEND_UNCLASSIFIED");
    assert_eq!(e[0].to_json(), expected);

    let t = terms(5);
    let asset = vault(&t, LegIndex::Asset);
    let stray = pay_to_script_hash_script(&stray_cash_script(asset.redeem_script()).unwrap());
    let mut x = mainnet_watcher(10);
    let idx = x.add_trade(t).unwrap().trade;
    let deposit = tx(54, vec![plain_in()], vec![(2_000, stray)]);
    let deposit_id = id(&deposit);
    let e = accept_one(&mut x, &Node::new(), deposit).await;
    assert_eq!(
        e[0].to_json(),
        json!({
            "event": "stray_deposit",
            "trade": idx.to_string(),
            "output": 0,
            "value": "2000",
            "txid": deposit_id.to_string(),
            "accepting_block": block(1).to_string(),
            "accepting_daa": "100",
            "depth": "0",
            "code": "WATCH_STRAY_DEPOSIT"
        })
    );
}

#[test]
fn a_poll_is_send() {
    fn send<T: Send>(_: T) {}
    let mut w = mainnet_watcher(10);
    let source = FakeVirtualChainSource::new(block(0), 0);
    let node = FakeBroadcaster::default();
    send(w.poll(&source));
    send(w.rebroadcast_next(&node));
}

// ---- phase 2 ----

#[path = "tests_phase2.rs"]
mod phase2;

// ---- review round 4 ----

#[path = "tests_review.rs"]
mod review;

// ---- review round 5 ----

#[path = "tests_round.rs"]
mod round;

// ---- template v2 trades (I16) ----

#[path = "tests_v2.rs"]
mod v2;

// ---- linked trades (I22) ----

#[path = "tests_linked.rs"]
mod linked;

/// `WATCH_FOREIGN_TOKEN` is retired (I26, spec/WATCH.md and spec/ERRORS.md): every template
/// refuses a vault spend that also moves a token of a covenant that spend does not check, so the
/// watcher no longer looks for one, and such a transaction (which the vault scripts would refuse,
/// fed to the watcher here as accepted) yields only its spend effects. A `foreign_token` effect in
/// a state file written by an earlier build still reads back as written.
#[tokio::test]
async fn a_vault_spend_with_a_token_of_another_covenant_is_no_longer_flagged() {
    let node = Node::new();
    let (mut w, _, _, [a_asset, a_cash, _, _], names) = two_trades();
    let t = terms(1);
    let tt = t.terms();
    let cov = |kind: LegKind| match kind {
        LegKind::Kcc20(k) => Hash::from_bytes(k.covenant_id),
        _ => panic!("vector 1 has two KCC-20 legs"),
    };
    let (asset_cov, cash_cov) = (cov(tt.asset_leg.kind), cov(tt.cash_leg.kind));
    let other = Hash::from_bytes([0x0f; 32]);
    let token_in = |c: Hash| In {
        sig: plain(),
        spends: UtxoEntry::new(1_000, stranger(), 0, false, Some(c)),
    };
    let seller = tt.seller_key;
    let refund = tx(
        61,
        vec![
            refund_in(&a_asset, seller, AUTH),
            token_in(asset_cov),
            token_in(other),
            token_in(cash_cov),
            plain_in(),
        ],
        vec![],
    );
    let e = accept_one(&mut w, &node, refund).await;
    assert_eq!(brief(&e, &names), ["accepted refunded A/asset"]);
    let settle = tx(
        64,
        vec![
            settle_in(&a_asset, AUTH),
            settle_in(&a_cash, AUTH),
            token_in(asset_cov),
            token_in(cash_cov),
            token_in(other),
            plain_in(),
        ],
        vec![],
    );
    let e = accept_one(&mut w, &node, settle).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled A/asset", "accepted settled A/cash"]
    );
    // An earlier build's state file: the refunded effect copied as a foreign_token effect.
    let text = crate::persist::encode(w.state(), Network::Mainnet);
    assert!(!text.contains("\"foreign_token\""), "{text}");
    fn add_foreign(v: &mut serde_json::Value, covenant: &str) -> bool {
        match v {
            serde_json::Value::Array(items) => {
                let found = items.iter().position(|i| i["kind"] == json!("refunded"));
                if let Some(at) = found {
                    let mut f = serde_json::Map::new();
                    f.insert("kind".into(), json!("foreign_token"));
                    f.insert("trade".into(), items[at]["trade"].clone());
                    f.insert("leg".into(), items[at]["leg"].clone());
                    f.insert("input".into(), json!(2));
                    f.insert("covenant_id".into(), json!(covenant));
                    items.insert(at + 1, serde_json::Value::Object(f));
                    return true;
                }
                items.iter_mut().any(|i| add_foreign(i, covenant))
            }
            serde_json::Value::Object(m) => m.values_mut().any(|i| add_foreign(i, covenant)),
            _ => false,
        }
    }
    let mut old: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(add_foreign(&mut old, &other.to_string()), "{text}");
    let old = serde_json::to_string(&old).unwrap();
    let back = crate::persist::decode(&old, Network::Mainnet).unwrap();
    let again = crate::persist::encode(&back, Network::Mainnet);
    assert!(again.contains("\"foreign_token\""), "{again}");
    assert!(again.contains(&other.to_string()), "{again}");
    let twice = crate::persist::decode(&again, Network::Mainnet).unwrap();
    assert_eq!(crate::persist::encode(&twice, Network::Mainnet), again);
}
