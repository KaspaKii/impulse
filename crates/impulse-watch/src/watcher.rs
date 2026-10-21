// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The watcher: watched trades, the virtual-chain tracker, and the transactions marked for
//! rebroadcast. It holds no key and signs nothing. It submits again only the bytes the node
//! accepted, after a reorg un-accepts them.
//!
//! Two steps, each safe to drop at its await: [`Watcher::poll`] walks the chain and returns
//! every event of the walk, and records which kept transactions a reorg un-accepted;
//! [`Watcher::rebroadcast_next`] then submits one of those and returns its event. Nothing
//! changes until the node has answered, so a call dropped by a timeout or a `select!` is simply
//! repeated by the next one.

use crate::error::WatchError;
use crate::event::{Event, RebroadcastOutcome};
use crate::linked::{Link, LinkBook};
use crate::tracker::{
    AcceptanceInfo, Cursor, FinalityPolicy, VirtualChainSource, VirtualChainStore,
    VirtualChainTracker,
};
use crate::trades::TradeTerms;
use crate::trades::{Effect, TradeBook, TradeId};
use impulse_core::linked::{Role, ValidatedLinked};
use impulse_core::terms::Network;
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;

/// Why the node did not take a transaction it was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The node refused it, with its reason. Counts toward [`REBROADCAST_ATTEMPTS`].
    Refused(String),
    /// The node has no copy in its mempool, but still holds a record of the transaction as
    /// accepted by the consensus: it keeps that record for every block it processes, on or off
    /// the selected chain, for a while (120 seconds by default in the pinned rusty-kaspa), and a
    /// reorg does not undo it. So after a reorg the answer is true of a transaction the chain no
    /// longer holds. It is not a refusal of the transaction itself, so it does not count toward
    /// [`REBROADCAST_ATTEMPTS`]: the transaction stays pending and is tried again after the next
    /// poll, until a walk accepts it again, the node takes it, the expiry guard stops it or the
    /// operator retires the trade.
    RecentlyAccepted(String),
}

/// Submits a signed transaction to the node, as is, and reads the node's own clock.
pub trait Broadcaster: Send + Sync {
    /// Hands the node `tx`. `Ok` means the node holds it in its mempool (taking it, or already
    /// having it there): that is all a rebroadcast is for. It does not mean a block will include
    /// it; the next walks show whether the chain accepts it.
    fn submit(&self, tx: &Transaction) -> impl Future<Output = Result<(), Refusal>> + Send;

    /// The node's current virtual DAA score. A settle is held back once this, or the last
    /// walk's tip, reaches the settle's expiry. Required of every implementation, with no
    /// default, so that no broadcaster can leave the expiry guard to a stale tip.
    fn virtual_daa_score(&self) -> impl Future<Output = Result<u64, String>> + Send;
}

/// How many times a transaction un-accepted by one reorg is submitted before the watcher stops
/// and reports `WATCH_REBROADCAST_ABANDONED`. One attempt per poll: a settle whose funding the
/// same reorg removed is refused until the funding is accepted again.
pub const REBROADCAST_ATTEMPTS: u32 = 10;

/// One currently accepted watched transaction.
#[derive(Clone, Debug)]
pub(crate) struct Accepted {
    pub(crate) at: AcceptanceInfo,
    pub(crate) effects: Vec<Effect>,
    /// The bytes the node accepted, kept for a transaction that settles or refunds a vault.
    pub(crate) tx: Option<Transaction>,
    /// The earliest expiry DAA score among the trades it settles, if it settles any.
    pub(crate) settle_expiry: Option<u64>,
    /// Already reported final at this acceptance.
    pub(crate) finalized: bool,
}

/// A trade [`Watcher::add_trade`] watches, and from where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watching {
    pub trade: TradeId,
    /// `None`: added before the first poll, so watched from the watcher's start. `Some(cursor)`:
    /// added once polls had run, so watched from the walk after that chain block only. Nothing
    /// accepted at or before it is reported, unless a reorg brings it into a later walk. A trade
    /// added again from a resumed state keeps the value it was first added with.
    pub from: Option<Cursor>,
}

/// A kept transaction a reorg un-accepted, waiting to be submitted again.
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    pub(crate) tx: Transaction,
    pub(crate) settle_expiry: Option<u64>,
    pub(crate) attempts: u32,
    /// Set by each poll; cleared by an attempt. One attempt per poll.
    pub(crate) due: bool,
}

/// The earliest expiry DAA score among the added trades that `effects` settle; `None` if they
/// settle none.
fn settle_expiry(book: &TradeBook, effects: &[Effect]) -> Option<u64> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Settled { trade, .. } => book.terms(trade),
            _ => None,
        })
        .map(TradeTerms::expiry_daa)
        .min()
}

/// Everything a watcher restart needs but the trades' terms, which the caller adds again: the
/// trades watched and the cursor each was added at, the cursor and acceptance index, what each
/// accepted watched transaction did (with its accepted copy and whether it was reported final),
/// the kept txids, and the pending rebroadcasts. One object, written out whole after a poll by
/// the phase 2 state file, so a restart reports the finality, reorgs and rebroadcasts of what
/// was accepted before it.
#[derive(Clone, Debug, Default)]
pub struct WatchState {
    /// Every trade watched with this state, by terms hash, with the cursor it was first added
    /// at (`None`: before the first poll).
    pub(crate) trades: BTreeMap<TradeId, Option<Cursor>>,
    pub(crate) tracker: VirtualChainTracker,
    /// What each currently accepted watched transaction did, and where it was accepted.
    pub(crate) accepted: HashMap<TransactionId, Accepted>,
    /// Txids marked for rebroadcast after a reorg.
    pub(crate) kept: BTreeSet<TransactionId>,
    /// Kept transactions a reorg un-accepted, by txid.
    pub(crate) pending: BTreeMap<TransactionId, Pending>,
    /// How many rounds have reported at least one event ([`Watcher::close_round`]). The next
    /// such round is this plus one, and its events carry that number, so that two episodes of
    /// the same event (a transaction accepted again after a reorg, a rebroadcast after a second
    /// reorg) never share a de-duplication key, while a round replayed after a crash does.
    pub(crate) round: u64,
}

impl WatchState {
    /// The number of rounds that have reported at least one event.
    pub fn round(&self) -> u64 {
        self.round
    }
}

/// How long a final acceptance stays in the state. An acceptance is evicted by the poll that
/// finds it final and at least `retain_daa` DAA scores deep. After that a reorg of its block is
/// not reported and, for a transaction that was not kept, nothing about it is rebroadcast; a
/// kept transaction (marked by `keep_signed`) is never evicted. No eviction is the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    retain_daa: u64,
}

impl Retention {
    /// The window must be above the finality depth (`WATCH_RETENTION_TOO_SHORT`), so an
    /// acceptance is reported final before it can be evicted, and stays indexed past that.
    pub fn new(retain_daa: u64, finality: FinalityPolicy) -> Result<Self, WatchError> {
        if retain_daa <= finality.depth_daa() {
            return Err(WatchError::RetentionTooShort {
                retain_daa,
                finality_daa: finality.depth_daa(),
            });
        }
        Ok(Self { retain_daa })
    }

    pub fn retain_daa(&self) -> u64 {
        self.retain_daa
    }
}

/// The watcher. State in memory ([`WatchState`]); the binary writes it to a local file after
/// each round (`crate::persist`).
pub struct Watcher {
    trades: TradeBook,
    finality: FinalityPolicy,
    retention: Option<Retention>,
    state: WatchState,
    /// The linked trades (spec/V2.md 17.9). Not part of the state: the caller adds them again on
    /// every start, and their phase is read from the acceptances the state holds.
    links: LinkBook,
}

impl Watcher {
    /// A watcher for `network`, reporting finality at `finality`, from no state.
    pub fn new(network: Network, finality: FinalityPolicy) -> Self {
        Self::with_state(network, finality, WatchState::default())
    }

    /// A watcher resuming from `state`. Add every trade of the state again, from its terms,
    /// before the next poll: [`Self::poll`] refuses while one is missing
    /// (`WATCH_TRADE_NOT_RESUMED`), since its events would otherwise be lost without a sign.
    pub fn with_state(network: Network, finality: FinalityPolicy, state: WatchState) -> Self {
        Self {
            trades: TradeBook::new(network),
            finality,
            retention: None,
            state,
            links: LinkBook::default(),
        }
    }

    /// Evicts final acceptances after the window, at the end of each poll. Not part of the
    /// state: the caller sets it on every start.
    pub fn set_retention(&mut self, retention: Retention) {
        self.retention = Some(retention);
    }

    /// How many accepted watched transactions the state holds.
    pub fn accepted_len(&self) -> usize {
        self.state.accepted.len()
    }

    /// Stops watching a trade of the state, which need not have been added again. The trade
    /// leaves the state, so a resumed state no longer requires it. Every effect of the trade
    /// is dropped from the accepted transactions; a transaction left with no effect is no
    /// longer tracked (not in the acceptance index, not kept, not pending). A transaction that
    /// still has effects keeps exactly what they need: its accepted copy (and its place among
    /// the kept) only while one of them is a settle or a refund, and its settle expiry recomputed from the settles that are left
    /// (the earlier value is kept for a settle of a trade not added again, which can only be
    /// earlier than the true one, so it holds a settle back, never lets one through). A pending
    /// rebroadcast that no longer settles or refunds a vault of an added trade is dropped, and
    /// the others have their expiry recomputed: add the other trades of the state again before
    /// retiring one, as the binary does. Nothing is reported: retiring is the operator's act.
    /// `WATCH_TRADE_UNKNOWN` if the state does not hold the trade.
    pub fn retire_trade(&mut self, trade: TradeId) -> Result<(), WatchError> {
        if self.state.trades.remove(&trade).is_none() {
            return Err(WatchError::TradeUnknown(trade));
        }
        self.trades.remove(&trade);
        let book = &self.trades;
        let mut emptied = Vec::new();
        let mut no_longer_a_spend = Vec::new();
        for (txid, accepted) in self.state.accepted.iter_mut() {
            accepted.effects.retain(|e| e.trade() != trade);
            if accepted.effects.is_empty() {
                emptied.push(*txid);
                continue;
            }
            if !accepted.effects.iter().any(Effect::is_spend) {
                accepted.tx = None;
                no_longer_a_spend.push(*txid);
            }
            let settled_trades = accepted.effects.iter().filter_map(|e| match e {
                Effect::Settled { trade, .. } => Some(*trade),
                _ => None,
            });
            let mut all_known = true;
            for settled in settled_trades {
                all_known &= book.terms(&settled).is_some();
            }
            accepted.settle_expiry = if all_known {
                settle_expiry(book, &accepted.effects)
            } else {
                accepted.settle_expiry
            };
        }
        for txid in emptied {
            self.state.accepted.remove(&txid);
            self.state.tracker.forget(&txid);
            self.state.pending.remove(&txid);
            self.state.kept.remove(&txid);
        }
        // Nothing of it is left to rebroadcast.
        for txid in no_longer_a_spend {
            self.state.kept.remove(&txid);
        }
        let dropped: Vec<TransactionId> = self
            .state
            .pending
            .iter()
            .filter(|(_, p)| !book.claims_spend(&p.tx))
            .map(|(txid, _)| *txid)
            .collect();
        for txid in dropped {
            self.state.pending.remove(&txid);
            self.state.kept.remove(&txid);
        }
        for pending in self.state.pending.values_mut() {
            pending.settle_expiry = book.claimed_settle_expiry(&pending.tx);
        }
        Ok(())
    }

    /// The trades of the state that have not been added again, in trade order. Empty once
    /// every one has; [`Self::poll`] refuses while it is not.
    pub fn unresumed_trades(&self) -> Vec<TradeId> {
        self.state
            .trades
            .keys()
            .filter(|trade| self.trades.terms(trade).is_none())
            .copied()
            .collect()
    }

    /// Whether `txid` is already marked for rebroadcast (by [`Self::keep_signed`], or in a
    /// resumed state).
    pub fn is_kept(&self, txid: &TransactionId) -> bool {
        self.state.kept.contains(txid)
    }

    pub fn state(&self) -> &WatchState {
        &self.state
    }

    /// Gives the state back, for a restart.
    pub fn into_state(self) -> WatchState {
        self.state
    }

    pub fn trades(&self) -> &TradeBook {
        &self.trades
    }

    pub fn tracker(&self) -> &VirtualChainTracker {
        &self.state.tracker
    }

    /// Watches a trade's vaults and says from where; see [`TradeBook::add`] for the refusals.
    /// A trade added once polls have run is watched from the current cursor only, and its
    /// [`Watching::from`] names that chain block; a trade of a resumed state keeps the cursor it
    /// was first added at. Nothing is recorded unless the add passes.
    pub fn add_trade(&mut self, terms: impl Into<TradeTerms>) -> Result<Watching, WatchError> {
        let trade = self.trades.add(terms)?;
        let cursor = self.state.tracker.store().cursor();
        let from = *self.state.trades.entry(trade).or_insert(cursor);
        Ok(Watching { trade, from })
    }

    /// Watches both trades a sheet derives, as ordinary trades (a trade already added is not
    /// added again), and follows them as one link: [`Event::Linked`] is reported when the link's
    /// phase changes. Adding a link already added is `WATCH_TRADE_DUPLICATE` for its opening.
    pub fn add_linked(&mut self, linked: &ValidatedLinked) -> Result<[Watching; 2], WatchError> {
        let opening = TradeId(linked.terms_hash(Role::Opening));
        if self.links.contains(&linked.linked_hash()) {
            return Err(WatchError::TradeDuplicate(opening));
        }
        let mut watching = Vec::with_capacity(2);
        for role in [Role::Opening, Role::Return] {
            let id = TradeId(linked.terms_hash(role));
            if self.trades.terms(&id).is_some() {
                let from = self.state.trades.get(&id).copied().flatten();
                watching.push(Watching { trade: id, from });
            } else {
                watching.push(self.add_trade(linked.terms(role).clone())?);
            }
        }
        self.links.add(
            Link {
                linked_hash: linked.linked_hash(),
                opening,
                ret: TradeId(linked.terms_hash(Role::Return)),
            },
            &self.state.accepted,
        );
        Ok([watching[0], watching[1]])
    }

    /// Marks a signed transaction for rebroadcast after a reorg. Refuses, in order: an input
    /// with no signature script (`WATCH_TX_UNSIGNED`), a transaction whose signature scripts
    /// settle or refund no watched vault (`WATCH_TX_NOT_TRACKED`), and a txid already kept
    /// (`WATCH_TX_DUPLICATE`). The txid is computed here, never read from the transaction's
    /// cache.
    ///
    /// Only the txid is kept. What is submitted again is always the copy the node accepted:
    /// the txid does not cover signature scripts, so a copy with the same txid and other
    /// signature scripts could otherwise stand in for the real one.
    pub fn keep_signed(&mut self, tx: Transaction) -> Result<TransactionId, WatchError> {
        if let Some(input) = tx.inputs.iter().position(|i| i.signature_script.is_empty()) {
            return Err(WatchError::TxUnsigned { input });
        }
        if !self.trades.claims_spend(&tx) {
            return Err(WatchError::TxNotTracked);
        }
        let txid = hashing::tx::id(&tx);
        if !self.state.kept.insert(txid) {
            return Err(WatchError::TxDuplicate(txid));
        }
        Ok(txid)
    }

    /// Kept transactions waiting to be submitted again, in txid order.
    pub fn pending_rebroadcasts(&self) -> Vec<TransactionId> {
        self.state.pending.keys().copied().collect()
    }

    /// The DAA score depths are measured from: the last chain block of the last walk.
    fn tip_daa(&self) -> u64 {
        self.state
            .tracker
            .store()
            .cursor()
            .and_then(|c| c.daa_score)
            .unwrap_or(0)
    }

    /// One poll: walk the virtual chain once and report, in this order, the effects a reorg
    /// undid, the effects of newly accepted watched transactions in walk order, and the
    /// acceptances that reached the finality depth. A transaction two chain blocks of the walk
    /// accept is a move within the walk: its first acceptance, a reorg of it, then the second,
    /// each with its own effects. A kept transaction that a reorg removed and the same walk
    /// did not accept again is marked for [`Self::rebroadcast_next`]. A failed node call
    /// returns `WATCH_SOURCE_FAILED` and changes nothing; so does a poll dropped before the
    /// node has answered. Refused before any node call, changing nothing, while a trade of a
    /// resumed state has not been added again (`WATCH_TRADE_NOT_RESUMED`, naming each).
    pub async fn poll<S: VirtualChainSource>(
        &mut self,
        source: &S,
    ) -> Result<Vec<Event>, WatchError> {
        let missing = self.unresumed_trades();
        if !missing.is_empty() {
            return Err(WatchError::TradeNotResumed(missing));
        }
        let trades = &self.trades;
        // What each acceptance did travels with it: the same txid at two blocks of one walk
        // keeps two sets of effects.
        let result = self
            .state
            .tracker
            .poll_once(source, |_, accepted| {
                let effects = trades.classify(accepted);
                if effects.is_empty() {
                    return None;
                }
                let tx = effects
                    .iter()
                    .any(Effect::is_spend)
                    .then(|| accepted.tx().clone());
                Some((effects, tx))
            })
            .await
            .map_err(|e| WatchError::SourceFailed(e.0))?;
        // Nothing below waits.
        let tip = result.tip_daa;
        let mut events = Vec::new();

        for txid in &result.removed_txids {
            self.unaccept(txid, &mut events);
        }

        for (txid, at, (effects, tx)) in result.added {
            // Still held as accepted only if an earlier chain block of this walk accepted it
            // (every other earlier acceptance was in `removed_txids`): a move within the walk.
            self.unaccept(&txid, &mut events);
            // Accepted again, by whoever submitted it: nothing left to rebroadcast.
            self.state.pending.remove(&txid);
            let depth = tip.saturating_sub(at.accepting_daa_score);
            events.extend(effects.iter().map(|&effect| Event::Accepted {
                txid,
                effect,
                at,
                depth,
            }));
            let settle_expiry = settle_expiry(&self.trades, &effects);
            self.state.accepted.insert(
                txid,
                Accepted {
                    at,
                    effects,
                    tx,
                    settle_expiry,
                    finalized: false,
                },
            );
        }

        for pending in self.state.pending.values_mut() {
            pending.due = true;
        }

        let mut due: Vec<(u64, TransactionId)> = self
            .state
            .accepted
            .iter()
            .filter(|(_, a)| !a.finalized && self.finality.is_final(a.at.accepting_daa_score, tip))
            .map(|(txid, a)| (a.at.accepting_daa_score, *txid))
            .collect();
        due.sort();
        for (_, txid) in due {
            let Some(a) = self.state.accepted.get_mut(&txid) else {
                continue;
            };
            let depth = tip.saturating_sub(a.at.accepting_daa_score);
            events.extend(a.effects.iter().map(|&effect| Event::Final {
                txid,
                effect,
                at: a.at,
                depth,
            }));
            a.finalized = true;
        }

        // The links are read before eviction, with the final acceptances remembered.
        for (link, view) in self.links.changed(&self.state.accepted) {
            let txid = events
                .iter()
                .rev()
                .find(|e| {
                    e.effect()
                        .is_some_and(|ef| ef.trade() == link.opening || ef.trade() == link.ret)
                })
                .map_or_else(|| TransactionId::from_bytes([0; 32]), Event::txid);
            events.push(Event::Linked { txid, link, view });
        }

        if let Some(retention) = self.retention {
            let gone: Vec<TransactionId> = self
                .state
                .accepted
                .iter()
                .filter(|(txid, a)| {
                    a.finalized
                        && !self.state.kept.contains(txid)
                        && tip.saturating_sub(a.at.accepting_daa_score) >= retention.retain_daa
                })
                .map(|(txid, _)| *txid)
                .collect();
            for txid in gone {
                self.state.accepted.remove(&txid);
                self.state.tracker.forget(&txid);
            }
        }

        Ok(events)
    }

    /// Drops the acceptance of `txid`, if held: reports a reorg of each of its effects, and
    /// makes a kept transaction pending for [`Self::rebroadcast_next`].
    fn unaccept(&mut self, txid: &TransactionId, events: &mut Vec<Event>) {
        let Some(gone) = self.state.accepted.remove(txid) else {
            return;
        };
        events.extend(gone.effects.iter().map(|&effect| Event::Reorg {
            txid: *txid,
            effect,
            at: gone.at,
            was_final: gone.finalized,
        }));
        if let (true, Some(tx)) = (self.state.kept.contains(txid), gone.tx) {
            self.state.pending.insert(
                *txid,
                Pending {
                    tx,
                    settle_expiry: gone.settle_expiry,
                    attempts: 0,
                    due: true,
                },
            );
        }
    }

    /// Numbers a round whose events are `events`: the number their `round` field carries. A
    /// round that reported something is one more than the rounds before it that did, and the
    /// count moves with it; a round that reported nothing leaves the count alone, so the state
    /// changes only when something happened. Call it once per round, after the poll and the
    /// rebroadcasts, and print the events under the number it returns before the state is saved:
    /// a crash between the two reloads the previous count and the replay is numbered the same,
    /// so its events have the same de-duplication keys, while a later episode of the same event
    /// has a later number and so a key of its own.
    pub fn close_round(&mut self, events: &[Event]) -> u64 {
        if !events.is_empty() {
            self.state.round += 1;
        }
        self.state.round
    }

    /// Submits the next kept transaction a reorg un-accepted, in txid order, and reports it;
    /// `None` when none is due. Each is tried once per poll until the node takes it, the chain
    /// accepts it again, or [`REBROADCAST_ATTEMPTS`] refusals (an answer of
    /// [`Refusal::RecentlyAccepted`] is reported but does not count). A settle is not submitted
    /// once the tip is at or past the expiry of a trade it settles
    /// (`WATCH_REBROADCAST_PAST_EXPIRY`): the depositor's refund may be open, and the decision
    /// is the operator's. The tip for that guard is the larger of the last walk's and the
    /// node's own current virtual DAA score, read here: a walk that stopped short of the sink
    /// (the node's batch limit, or a watcher that was down) understates the chain. If the node's
    /// score cannot be read, the settle is not submitted and the attempt is a refusal. Call it
    /// until it returns `None` after each poll.
    pub async fn rebroadcast_next<B: Broadcaster>(&mut self, broadcaster: &B) -> Option<Event> {
        let walk_tip = self.tip_daa();
        let (txid, expiry, tx) = self
            .state
            .pending
            .iter()
            .find(|(_, p)| p.due)
            .map(|(txid, p)| (*txid, p.settle_expiry, p.tx.clone()))?;

        let answer = match expiry {
            None => broadcaster.submit(&tx).await,
            Some(expiry_daa) => match broadcaster.virtual_daa_score().await {
                Ok(node_tip) if walk_tip.max(node_tip) >= expiry_daa => {
                    self.state.pending.remove(&txid);
                    return Some(Event::Rebroadcast {
                        txid,
                        outcome: RebroadcastOutcome::PastExpiry {
                            expiry_daa,
                            tip_daa: walk_tip.max(node_tip),
                        },
                    });
                }
                Ok(_) => broadcaster.submit(&tx).await,
                Err(reason) => Err(Refusal::Refused(format!(
                    "the node's virtual DAA score could not be read, so the settle's expiry could not be checked and it was not submitted: {reason}"
                ))),
            },
        };

        // Applied only once the node has answered.
        let pending = self.state.pending.get_mut(&txid)?;
        pending.due = false;
        let outcome = match answer {
            Ok(()) => {
                pending.attempts += 1;
                RebroadcastOutcome::Submitted {
                    attempt: pending.attempts,
                }
            }
            Err(Refusal::RecentlyAccepted(reason)) => RebroadcastOutcome::Refused {
                attempt: pending.attempts,
                reason,
            },
            Err(Refusal::Refused(reason)) => {
                pending.attempts += 1;
                let attempt = pending.attempts;
                if attempt >= REBROADCAST_ATTEMPTS {
                    RebroadcastOutcome::Abandoned { attempt, reason }
                } else {
                    RebroadcastOutcome::Refused { attempt, reason }
                }
            }
        };
        if !matches!(outcome, RebroadcastOutcome::Refused { .. }) {
            self.state.pending.remove(&txid);
        }
        Some(Event::Rebroadcast { txid, outcome })
    }
}
