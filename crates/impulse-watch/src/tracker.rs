// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Virtual-chain acceptance tracking: which transactions the node's virtual selected parent
//! chain accepts, at which chain block and DAA score, and which a reorg un-accepts.
//!
//! The signal is the node's virtual-chain walk from a cursor: the chain blocks removed (tip
//! first) and added (oldest first) since the cursor, and the transactions each added chain
//! block accepted. A mempool miss is never a signal: it is equally true of an accepted and of a
//! dropped transaction.
//!
//! Pure logic over two small traits, so it runs without a node: [`VirtualChainSource`] (how to
//! ask a node for a walk) and [`VirtualChainStore`] (where the cursor and the acceptance index
//! live). The live source over wRPC is phase 2 of I8 (`node.rs`).
//!
//! Depth is measured against the walk itself: the tip is the DAA score of the last chain block
//! the walk added (the node's sink once the walk has caught up), never a second node call. A
//! depth therefore never mixes two views of the chain, and it can only understate the depth
//! below the virtual, never overstate it.
//!
//! Adapted from an internal virtual-chain tracker by the owner (relicensed, see NOTICE).
//! Stripped: the database store, its cross-process poll lock, the in-process poll mutex (the
//! tracker is polled through `&mut self`, so the borrow checker already serialises polls),
//! the environment-variable finality policy and its unenforced reorg budget, logging and the
//! source's error type. Changed: hashes are typed; each added chain block carries its DAA score
//! and the accepted transactions themselves with the UTXO entries their inputs spent (as the
//! node's virtual-chain v2 walk returns them), so the watcher can see outputs, signature scripts
//! and what each input unlocked, and no per-block DAA call is needed;
//! the tip is the walk's last chain block, so the virtual DAA call is gone; only transactions
//! the caller marks relevant are indexed (for the watcher, every funding, deposit and spend of a
//! watched vault seen since it started, third-party deposits included; unless the caller
//! `forget`s final acceptances after a retention window, the index grows with what is paid to
//! the watched vaults, see spec/WATCH.md), and what the
//! caller made of each one comes back with that acceptance, never looked up by txid; the index is
//! also kept by block, so a reorg costs the removed blocks, not the index; acceptance is
//! idempotent, so a walk delivered twice is applied once and a transaction seen again at another
//! block without a removal is a move; nothing is awaited once the walk is in hand, and the store
//! is infallible, so a walk is applied whole or not at all, and a poll dropped while waiting on
//! the node changes nothing. Keyless: nothing here signs or holds a key.

use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::{Transaction, TransactionId, UtxoEntry};
use kaspa_consensus_core::Hash;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;

/// A chain block hash.
pub type BlockHash = Hash;

/// Where a transaction is accepted into the virtual selected parent chain. No value (an
/// `Option<AcceptanceInfo>` of `None`) means not currently accepted: never seen, or seen and
/// un-accepted by a reorg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptanceInfo {
    /// The chain block that accepted the transaction.
    pub accepting_block_hash: BlockHash,
    /// That chain block's DAA score.
    pub accepting_daa_score: u64,
}

/// An accepted transaction with the UTXO entry each of its inputs spent, in input order, as
/// the v2 walk returns them (`verbose_data.utxo_entry` of each input at Full verbosity). The
/// spent entries are what make a vault spend attributable: a signature script alone proves
/// nothing about which UTXO it unlocked.
#[derive(Clone, Debug)]
pub struct AcceptedTransaction {
    tx: Transaction,
    spent: Vec<UtxoEntry>,
}

impl AcceptedTransaction {
    /// Refuses a transaction whose spent entries do not match its inputs one for one; the live
    /// source reports that as a failed node call (`WATCH_SOURCE_FAILED`).
    pub fn new(tx: Transaction, spent: Vec<UtxoEntry>) -> Result<Self, SourceError> {
        if spent.len() != tx.inputs.len() {
            return Err(SourceError(format!(
                "{} spent UTXO entries for {} inputs",
                spent.len(),
                tx.inputs.len()
            )));
        }
        Ok(Self { tx, spent })
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    /// The UTXO entry input `i` spent, for every input.
    pub fn spent(&self) -> &[UtxoEntry] {
        &self.spent
    }
}

/// One chain block a walk added, with its DAA score and the transactions it accepted.
#[derive(Clone, Debug)]
pub struct AddedChainBlock {
    pub hash: BlockHash,
    pub daa_score: u64,
    pub accepted_transactions: Vec<AcceptedTransaction>,
}

/// One virtual-chain walk from the cursor, as `get_virtual_chain_from_block_v2` returns it:
/// the chain blocks removed, tip first, and the chain blocks added, oldest first.
#[derive(Clone, Debug, Default)]
pub struct VirtualChainUpdate {
    pub removed_chain_block_hashes: Vec<BlockHash>,
    pub added_chain_blocks: Vec<AddedChainBlock>,
}

/// The last chain block a poll fully processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub block_hash: BlockHash,
    /// Its DAA score; `None` for the bootstrap cursor, until a walk adds a chain block.
    pub daa_score: Option<u64>,
}

/// A node call failed. Carries the node's message; a failed call is never read as acceptance
/// or as un-acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceError(pub String);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The node calls the tracker needs, kept free of RPC types so a fake can stand in.
pub trait VirtualChainSource: Send + Sync {
    /// Walks the virtual selected parent chain from `start_hash` (exclusive) towards the
    /// node's sink, with each added chain block's DAA score and accepted transactions. The node
    /// may stop short of the sink; the next walk continues from the new cursor.
    fn get_virtual_chain_from(
        &self,
        start_hash: BlockHash,
    ) -> impl Future<Output = Result<VirtualChainUpdate, SourceError>> + Send;

    /// The node's current sink (virtual selected parent). Used only to bootstrap a cursor.
    fn sink_hash(&self) -> impl Future<Output = Result<BlockHash, SourceError>> + Send;

    /// The selected parent of `block_hash`. Used only to bootstrap a cursor one block behind
    /// the sink, so that the first walk includes the sink block and nothing accepted there at
    /// bootstrap time is skipped.
    fn selected_parent_hash(
        &self,
        block_hash: BlockHash,
    ) -> impl Future<Output = Result<BlockHash, SourceError>> + Send;
}

/// Where the cursor and the acceptance index live. Infallible on purpose: a durable store keeps
/// this state in memory and writes it out whole after a poll, so a failed write can never leave
/// half a walk applied.
pub trait VirtualChainStore {
    /// The last chain block a poll fully processed; `None` before the first poll.
    fn cursor(&self) -> Option<Cursor>;

    fn set_cursor(&mut self, cursor: Cursor);

    /// Records, or moves, the acceptance of `txid`.
    fn upsert_acceptance(&mut self, txid: TransactionId, info: AcceptanceInfo);

    /// Drops `txid` from the acceptance index. Idempotent.
    fn unaccept(&mut self, txid: &TransactionId);

    fn acceptance(&self, txid: &TransactionId) -> Option<AcceptanceInfo>;

    /// Every indexed txid accepted by `block_hash`, in txid order.
    fn acceptances_by_block(&self, block_hash: &BlockHash) -> Vec<TransactionId>;
}

/// The in-memory [`VirtualChainStore`].
#[derive(Clone, Debug, Default)]
pub struct InMemoryVirtualChainStore {
    cursor: Option<Cursor>,
    acceptances: HashMap<TransactionId, AcceptanceInfo>,
    /// The same index by accepting block.
    by_block: HashMap<BlockHash, BTreeSet<TransactionId>>,
}

impl InMemoryVirtualChainStore {
    fn unindex(&mut self, txid: &TransactionId, block_hash: &BlockHash) {
        if let Some(txids) = self.by_block.get_mut(block_hash) {
            txids.remove(txid);
            if txids.is_empty() {
                self.by_block.remove(block_hash);
            }
        }
    }
}

impl InMemoryVirtualChainStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VirtualChainStore for InMemoryVirtualChainStore {
    fn cursor(&self) -> Option<Cursor> {
        self.cursor
    }

    fn set_cursor(&mut self, cursor: Cursor) {
        self.cursor = Some(cursor);
    }

    fn upsert_acceptance(&mut self, txid: TransactionId, info: AcceptanceInfo) {
        if let Some(old) = self.acceptances.insert(txid, info) {
            self.unindex(&txid, &old.accepting_block_hash);
        }
        self.by_block
            .entry(info.accepting_block_hash)
            .or_default()
            .insert(txid);
    }

    fn unaccept(&mut self, txid: &TransactionId) {
        if let Some(old) = self.acceptances.remove(txid) {
            self.unindex(txid, &old.accepting_block_hash);
        }
    }

    fn acceptance(&self, txid: &TransactionId) -> Option<AcceptanceInfo> {
        self.acceptances.get(txid).copied()
    }

    fn acceptances_by_block(&self, block_hash: &BlockHash) -> Vec<TransactionId> {
        self.by_block
            .get(block_hash)
            .map(|txids| txids.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// The result of one [`VirtualChainTracker::poll_once`]. `T` is what the caller's `relevant`
/// returned for a newly accepted transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollResult<T> {
    /// Relevant transactions newly recorded as accepted, in walk order, each with what
    /// `relevant` returned for it at that block. A transaction two chain blocks of one walk
    /// accept is here twice, each time with its own value (and once in `removed_txids`).
    pub added: Vec<(TransactionId, AcceptanceInfo, T)>,
    /// Indexed transactions un-accepted: first those whose accepting block a reorg removed,
    /// in the order of the removed blocks (tip first), then txid order; then those the walk
    /// shows accepted at another block without removing the first (a move), in walk order. A
    /// moved transaction is also in `added`, at its new block. When the first acceptance is in
    /// the same walk, it is in `added` too, before the move: a caller that applies
    /// `removed_txids` first meets it again in `added` while it still holds it as accepted.
    pub removed_txids: Vec<TransactionId>,
    /// The DAA score depths are measured from: the cursor's after this walk (the last chain
    /// block the walk added, or the cursor it started from). 0 while no walk has added a chain
    /// block, when nothing is indexed either.
    pub tip_daa: u64,
}

/// Finality depth N: a transaction is final once its acceptance is at least N DAA scores below
/// the tip. There is no default: N is a security choice for the operator, and a testnet figure
/// says nothing about mainnet attack cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityPolicy {
    depth_daa: u64,
}

impl FinalityPolicy {
    /// Refuses a depth of 0, which would call every transaction final on acceptance
    /// (`WATCH_FINALITY_DEPTH_ZERO`).
    pub fn new(depth_daa: u64) -> Result<Self, crate::WatchError> {
        if depth_daa == 0 {
            return Err(crate::WatchError::FinalityDepthZero);
        }
        Ok(Self { depth_daa })
    }

    pub fn depth_daa(&self) -> u64 {
        self.depth_daa
    }

    /// Whether an acceptance at `accepting_daa` is final with the tip at `tip_daa`.
    pub fn is_final(&self, accepting_daa: u64, tip_daa: u64) -> bool {
        tip_daa.saturating_sub(accepting_daa) >= self.depth_daa
    }
}

/// Tracks acceptance into the virtual selected parent chain from a cursor.
#[derive(Clone, Debug, Default)]
pub struct VirtualChainTracker<St: VirtualChainStore = InMemoryVirtualChainStore> {
    store: St,
}

impl<St: VirtualChainStore> VirtualChainTracker<St> {
    pub fn new(store: St) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &St {
        &self.store
    }

    /// Gives the store back, for a restart with the same state.
    pub fn into_store(self) -> St {
        self.store
    }

    /// Stops indexing `txid`: a later reorg of its block does not report it. Idempotent.
    pub fn forget(&mut self, txid: &TransactionId) {
        self.store.unaccept(txid);
    }

    /// One round:
    ///
    /// 1. Load the cursor, or bootstrap it to the selected parent of the node's sink on the
    ///    very first poll (no history before that point is claimed).
    /// 2. Walk the virtual chain from the cursor. Any node failure returns here, before
    ///    anything changes (the bootstrap cursor excepted). Nothing is awaited after this.
    /// 3. Un-accept every indexed txid of each removed chain block (a reorg).
    /// 4. Index each accepted transaction for which `relevant` (given its txid, computed here)
    ///    returns a value, at its block's DAA score, and return that value with the acceptance.
    ///    A transaction already indexed at the same block is skipped (the same walk delivered
    ///    twice); one indexed at another block is un-accepted there first (a move).
    /// 5. Move the cursor to the last added chain block, if any.
    pub async fn poll_once<S: VirtualChainSource, T>(
        &mut self,
        source: &S,
        mut relevant: impl FnMut(TransactionId, &AcceptedTransaction) -> Option<T>,
    ) -> Result<PollResult<T>, SourceError> {
        let cursor = self.bootstrap_or_load_cursor(source).await?;
        let update = source.get_virtual_chain_from(cursor.block_hash).await?;

        // Nothing below fails or waits, so the walk is applied whole.
        let mut removed_txids = Vec::new();
        for removed_hash in &update.removed_chain_block_hashes {
            for txid in self.store.acceptances_by_block(removed_hash) {
                self.store.unaccept(&txid);
                removed_txids.push(txid);
            }
        }

        let mut added = Vec::new();
        for block in &update.added_chain_blocks {
            let info = AcceptanceInfo {
                accepting_block_hash: block.hash,
                accepting_daa_score: block.daa_score,
            };
            for accepted in &block.accepted_transactions {
                // Computed here, never read from the transaction's cache.
                let txid = hashing::tx::id(accepted.tx());
                match self.store.acceptance(&txid) {
                    Some(known) if known == info => continue,
                    Some(_) => {
                        self.store.unaccept(&txid);
                        removed_txids.push(txid);
                    }
                    None => {}
                }
                if let Some(value) = relevant(txid, accepted) {
                    self.store.upsert_acceptance(txid, info);
                    added.push((txid, info, value));
                }
            }
        }

        if let Some(last) = update.added_chain_blocks.last() {
            self.store.set_cursor(Cursor {
                block_hash: last.hash,
                daa_score: Some(last.daa_score),
            });
        }

        Ok(PollResult {
            added,
            removed_txids,
            tip_daa: self.store.cursor().and_then(|c| c.daa_score).unwrap_or(0),
        })
    }

    async fn bootstrap_or_load_cursor<S: VirtualChainSource>(
        &mut self,
        source: &S,
    ) -> Result<Cursor, SourceError> {
        if let Some(cursor) = self.store.cursor() {
            return Ok(cursor);
        }
        let sink = source.sink_hash().await?;
        let bootstrap = Cursor {
            block_hash: source.selected_parent_hash(sink).await?,
            daa_score: None,
        };
        self.store.set_cursor(bootstrap);
        Ok(bootstrap)
    }

    /// The acceptance of `txid` as of the last poll; `None` if not currently accepted.
    pub fn accepting_block(&self, txid: &TransactionId) -> Option<AcceptanceInfo> {
        self.store.acceptance(txid)
    }

    /// DAA-score depth of `txid` with the tip at `tip_daa`, or `None` if not accepted.
    pub fn confirmations(&self, txid: &TransactionId, tip_daa: u64) -> Option<u64> {
        self.accepting_block(txid)
            .map(|info| tip_daa.saturating_sub(info.accepting_daa_score))
    }
}

/// A node-free [`VirtualChainSource`] over a small block tree. Each walk is computed from the
/// start hash it is given, as the node computes it: the start block's chain back to the first
/// block on the sink's chain is removed, tip first, and the sink's chain from there is added,
/// oldest first, up to an optional limit. Each call can be made to fail once, a walk can be
/// made to hang once (to drop a poll mid-call), and a verbatim update can be queued (to model a
/// notification delivered twice).
#[cfg(test)]
pub(crate) mod test_support {
    use super::{
        AcceptedTransaction, AddedChainBlock, BlockHash, SourceError, VirtualChainSource,
        VirtualChainUpdate,
    };
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::Mutex;

    /// A node call of the fake, for failure injection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Call {
        Walk,
        Sink,
        SelectedParent,
    }

    struct Block {
        parent: Option<BlockHash>,
        daa_score: u64,
        accepted: Vec<AcceptedTransaction>,
    }

    #[derive(Default)]
    struct Model {
        blocks: HashMap<BlockHash, Block>,
        sink: BlockHash,
        failures: Vec<(Call, String)>,
        scripted: VecDeque<VirtualChainUpdate>,
        added_limit: Option<usize>,
        hang_next_walk: bool,
        start_hashes: Vec<BlockHash>,
    }

    impl Model {
        fn take_failure(&mut self, call: Call) -> Option<SourceError> {
            let at = self.failures.iter().position(|(c, _)| *c == call)?;
            Some(SourceError(self.failures.remove(at).1))
        }

        fn walk(&self, start: BlockHash) -> Result<VirtualChainUpdate, SourceError> {
            let unknown = |h: BlockHash| SourceError(format!("unknown block {h}"));
            if !self.blocks.contains_key(&start) {
                return Err(unknown(start));
            }
            let mut on_chain = HashSet::new();
            let mut b = Some(self.sink);
            while let Some(h) = b {
                on_chain.insert(h);
                b = self.blocks[&h].parent;
            }
            let mut removed = Vec::new();
            let mut common = start;
            while !on_chain.contains(&common) {
                removed.push(common);
                common = self.blocks[&common].parent.ok_or_else(|| unknown(common))?;
            }
            let mut added = Vec::new();
            let mut b = self.sink;
            while b != common {
                let block = &self.blocks[&b];
                added.push(AddedChainBlock {
                    hash: b,
                    daa_score: block.daa_score,
                    accepted_transactions: block.accepted.clone(),
                });
                b = block.parent.ok_or_else(|| unknown(b))?;
            }
            added.reverse();
            if let Some(limit) = self.added_limit {
                added.truncate(limit);
            }
            Ok(VirtualChainUpdate {
                removed_chain_block_hashes: removed,
                added_chain_blocks: added,
            })
        }
    }

    pub(crate) struct FakeVirtualChainSource {
        model: Mutex<Model>,
    }

    impl FakeVirtualChainSource {
        /// A chain of one block, `root`, which is the sink.
        pub(crate) fn new(root: BlockHash, root_daa: u64) -> Self {
            let mut model = Model {
                sink: root,
                ..Model::default()
            };
            model.blocks.insert(
                root,
                Block {
                    parent: None,
                    daa_score: root_daa,
                    accepted: vec![],
                },
            );
            Self {
                model: Mutex::new(model),
            }
        }

        /// Adds a block under `parent` without moving the sink (a side branch, until
        /// [`Self::set_sink`] selects it).
        pub(crate) fn add_block(
            &self,
            hash: BlockHash,
            parent: BlockHash,
            daa_score: u64,
            accepted: Vec<AcceptedTransaction>,
        ) {
            let mut m = self.model.lock().unwrap();
            assert!(m.blocks.contains_key(&parent), "unknown parent");
            assert!(!m.blocks.contains_key(&hash), "block added twice");
            m.blocks.insert(
                hash,
                Block {
                    parent: Some(parent),
                    daa_score,
                    accepted,
                },
            );
        }

        /// Adds a block on the sink and makes it the sink.
        pub(crate) fn extend(
            &self,
            hash: BlockHash,
            daa_score: u64,
            accepted: Vec<AcceptedTransaction>,
        ) {
            let sink = self.model.lock().unwrap().sink;
            self.add_block(hash, sink, daa_score, accepted);
            self.set_sink(hash);
        }

        /// Moves the sink to `hash` (a reorg when `hash` is not a descendant of the sink).
        pub(crate) fn set_sink(&self, hash: BlockHash) {
            let mut m = self.model.lock().unwrap();
            assert!(m.blocks.contains_key(&hash), "unknown sink");
            m.sink = hash;
        }

        /// The next call of this kind fails with `message`.
        pub(crate) fn fail_next(&self, call: Call, message: &str) {
            self.model
                .lock()
                .unwrap()
                .failures
                .push((call, message.to_string()));
        }

        /// The next walk returns `update` verbatim, whatever its start hash: a notification
        /// delivered again, or one the node's own walk would not produce.
        pub(crate) fn push_scripted(&self, update: VirtualChainUpdate) {
            self.model.lock().unwrap().scripted.push_back(update);
        }

        /// Each walk adds at most `limit` chain blocks, as the node's batch limit does.
        pub(crate) fn set_added_limit(&self, limit: usize) {
            self.model.lock().unwrap().added_limit = Some(limit);
        }

        /// The next walk never completes.
        pub(crate) fn hang_next_walk(&self) {
            self.model.lock().unwrap().hang_next_walk = true;
        }

        pub(crate) fn start_hashes_seen(&self) -> Vec<BlockHash> {
            self.model.lock().unwrap().start_hashes.clone()
        }
    }

    impl VirtualChainSource for FakeVirtualChainSource {
        async fn get_virtual_chain_from(
            &self,
            start_hash: BlockHash,
        ) -> Result<VirtualChainUpdate, SourceError> {
            let (result, hang) = {
                let mut m = self.model.lock().unwrap();
                m.start_hashes.push(start_hash);
                let result = match m.take_failure(Call::Walk) {
                    Some(e) => Err(e),
                    None => match m.scripted.pop_front() {
                        Some(update) => Ok(update),
                        None => m.walk(start_hash),
                    },
                };
                (result, std::mem::take(&mut m.hang_next_walk))
            };
            if hang {
                std::future::pending::<()>().await;
            }
            result
        }

        async fn sink_hash(&self) -> Result<BlockHash, SourceError> {
            let mut m = self.model.lock().unwrap();
            match m.take_failure(Call::Sink) {
                Some(e) => Err(e),
                None => Ok(m.sink),
            }
        }

        async fn selected_parent_hash(
            &self,
            block_hash: BlockHash,
        ) -> Result<BlockHash, SourceError> {
            let mut m = self.model.lock().unwrap();
            if let Some(e) = m.take_failure(Call::SelectedParent) {
                return Err(e);
            }
            m.blocks
                .get(&block_hash)
                .and_then(|b| b.parent)
                .ok_or_else(|| SourceError(format!("no selected parent for {block_hash}")))
        }
    }

    /// Polls `future` exactly once and drops it, as a `select!` or a timeout does when another
    /// branch wins. Returns whether it had completed.
    pub(crate) fn poll_once_then_drop<F: std::future::Future>(future: F) -> bool {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        future.as_mut().poll(&mut cx).is_ready()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{poll_once_then_drop, Call, FakeVirtualChainSource};
    use super::*;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput, TransactionOutpoint};

    fn block(n: u64) -> BlockHash {
        BlockHash::from_u64_word(n)
    }

    fn raw(n: u64) -> Transaction {
        let input = TransactionInput::new(
            TransactionOutpoint::new(Hash::from_u64_word(0xf00d_0000 + n), 0),
            vec![0x51],
            0,
            1,
        );
        Transaction::new(0, vec![input], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    }

    fn entry() -> UtxoEntry {
        UtxoEntry::new(
            1_000,
            ScriptPublicKey::new(0, vec![0x51].into()),
            0,
            false,
            None,
        )
    }

    /// A transaction told apart by `n` (its previous outpoint), with its spent entry.
    fn tx(n: u64) -> AcceptedTransaction {
        AcceptedTransaction::new(raw(n), vec![entry()]).unwrap()
    }

    fn id(n: u64) -> TransactionId {
        raw(n).id()
    }

    fn at(n: u64, daa: u64) -> AcceptanceInfo {
        AcceptanceInfo {
            accepting_block_hash: block(n),
            accepting_daa_score: daa,
        }
    }

    fn cursor(n: u64, daa: u64) -> Option<Cursor> {
        Some(Cursor {
            block_hash: block(n),
            daa_score: Some(daa),
        })
    }

    fn all(_: TransactionId, _: &AcceptedTransaction) -> Option<()> {
        Some(())
    }

    /// The acceptances of a result, without the values `relevant` returned.
    fn added<T>(result: &PollResult<T>) -> Vec<(TransactionId, AcceptanceInfo)> {
        result
            .added
            .iter()
            .map(|(txid, at, _)| (*txid, *at))
            .collect()
    }

    /// Root block 0 at DAA 99, the sink.
    fn source() -> FakeVirtualChainSource {
        FakeVirtualChainSource::new(block(0), 99)
    }

    fn tracker() -> VirtualChainTracker {
        VirtualChainTracker::<InMemoryVirtualChainStore>::default()
    }

    /// A tracker already polled once over an empty block 1 (DAA 100), so the next walk starts
    /// there. The first poll's walk starts one block behind the sink; later walks start at the
    /// cursor and see every block mined since.
    async fn started() -> (FakeVirtualChainSource, VirtualChainTracker) {
        let source = source();
        source.extend(block(1), 100, vec![]);
        let mut tracker = tracker();
        tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
        (source, tracker)
    }

    #[tokio::test]
    async fn first_poll_bootstraps_the_cursor_to_the_sinks_selected_parent() {
        let source = source();
        source.extend(block(1), 100, vec![]);
        let mut tracker = tracker();
        assert_eq!(tracker.store().cursor(), None);
        tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(source.start_hashes_seen(), vec![block(0)]);
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
    }

    #[tokio::test]
    async fn bootstrap_includes_acceptance_into_the_sink_block_itself() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1)]);
        let mut tracker = tracker();
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&result), vec![(id(1), at(1, 100))]);
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(1, 100)));
    }

    #[tokio::test]
    async fn acceptance_is_recorded_and_depth_counts_daa_scores_to_the_walks_last_block() {
        let (source, mut tracker) = started().await;
        source.extend(block(2), 100, vec![tx(1)]);
        source.extend(block(3), 105, vec![]);
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&result), vec![(id(1), at(2, 100))]);
        assert!(result.removed_txids.is_empty());
        assert_eq!(result.tip_daa, 105);
        assert_eq!(tracker.confirmations(&id(1), 105), Some(5));
        assert_eq!(tracker.accepting_block(&id(2)), None);
        assert_eq!(tracker.confirmations(&id(2), 105), None);
    }

    #[tokio::test]
    async fn only_relevant_transactions_are_indexed() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1), tx(2)]);
        let mut tracker = tracker();
        let wanted = id(2);
        let result = tracker
            .poll_once(&source, |txid, _| (txid == wanted).then_some(()))
            .await
            .unwrap();
        assert_eq!(added(&result), vec![(wanted, at(1, 100))]);
        assert!(tracker.accepting_block(&id(1)).is_none());
    }

    /// Every added block's transactions are indexed, not only the first block's.
    #[tokio::test]
    async fn a_walk_adding_three_blocks_indexes_the_second_and_third() {
        let (source, mut tracker) = started().await;
        source.extend(block(2), 101, vec![]);
        source.extend(block(3), 101, vec![tx(1)]);
        source.extend(block(4), 102, vec![tx(2), tx(3)]);
        let result = tracker.poll_once(&source, all).await.unwrap();
        // Walk order: block by block, then as each block lists them.
        assert_eq!(
            added(&result),
            vec![
                (id(1), at(3, 101)),
                (id(2), at(4, 102)),
                (id(3), at(4, 102))
            ]
        );
        assert_eq!(result.tip_daa, 102);
        assert_eq!(tracker.store().cursor(), cursor(4, 102));
        assert_eq!(source.start_hashes_seen(), vec![block(0), block(1)]);
        let mut in_b4 = vec![id(2), id(3)];
        in_b4.sort();
        assert_eq!(tracker.store().acceptances_by_block(&block(4)), in_b4);
    }

    #[tokio::test]
    async fn the_next_walk_starts_at_the_last_added_block() {
        let (source, mut tracker) = started().await;
        source.extend(block(2), 101, vec![]);
        source.extend(block(3), 102, vec![]);
        tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(tracker.store().cursor(), cursor(3, 102));
        source.extend(block(4), 103, vec![tx(1)]);
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(
            source.start_hashes_seen(),
            vec![block(0), block(1), block(3)]
        );
        assert_eq!(added(&result), vec![(id(1), at(4, 103))]);
        assert_eq!(tracker.store().cursor(), cursor(4, 103));
    }

    #[tokio::test]
    async fn a_walk_cut_short_by_the_node_is_caught_up_on_the_next_poll() {
        let (source, mut tracker) = started().await;
        source.set_added_limit(2);
        source.extend(block(2), 101, vec![]);
        source.extend(block(3), 102, vec![tx(1)]);
        source.extend(block(4), 103, vec![tx(2)]);
        let first = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&first), vec![(id(1), at(3, 102))]);
        assert_eq!(first.tip_daa, 102, "depth is measured to what the walk saw");
        let second = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&second), vec![(id(2), at(4, 103))]);
        assert_eq!(
            source.start_hashes_seen(),
            vec![block(0), block(1), block(3)]
        );
        assert_eq!(tracker.store().cursor(), cursor(4, 103));
    }

    #[tokio::test]
    async fn a_walk_with_no_added_blocks_leaves_the_cursor() {
        let source = source();
        source.extend(block(1), 100, vec![]);
        let mut tracker = tracker();
        tracker.poll_once(&source, all).await.unwrap();
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(
            result,
            PollResult {
                added: vec![],
                removed_txids: vec![],
                tip_daa: 100
            }
        );
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
        assert_eq!(source.start_hashes_seen(), vec![block(0), block(1)]);
    }

    /// A three-block reorg: the removed blocks are reported tip first, every one of them is
    /// un-accepted, and the block below the fork keeps its acceptance.
    #[tokio::test]
    async fn a_reorg_unaccepts_every_removed_block_tip_first() {
        let (source, mut tracker) = started().await;
        source.extend(block(5), 100, vec![tx(1)]);
        tracker.poll_once(&source, all).await.unwrap();
        // Blocks 2, 3 and 4 on block 5; reuse their numbers for readability.
        source.extend(block(2), 101, vec![tx(2)]);
        source.extend(block(3), 102, vec![]);
        source.extend(block(4), 103, vec![tx(3), tx(4)]);
        tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(tracker.store().cursor(), cursor(4, 103));

        source.add_block(block(12), block(5), 101, vec![]);
        source.add_block(block(13), block(12), 102, vec![]);
        source.add_block(block(14), block(13), 103, vec![]);
        source.add_block(block(15), block(14), 104, vec![]);
        source.set_sink(block(15));
        let result = tracker.poll_once(&source, all).await.unwrap();
        let mut expected = vec![id(3), id(4)];
        expected.sort();
        expected.push(id(2));
        assert_eq!(result.removed_txids, expected, "block 4, then block 2");
        assert!(added(&result).is_empty());
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(5, 100)));
        for n in 2..=4 {
            assert_eq!(tracker.accepting_block(&id(n)), None);
        }
        assert_eq!(tracker.store().cursor(), cursor(15, 104));
        assert_eq!(
            source.start_hashes_seen(),
            vec![block(0), block(1), block(5), block(4)]
        );
    }

    /// The same walk delivered twice (a repeated notification) is applied once.
    #[tokio::test]
    async fn a_walk_delivered_twice_is_applied_once() {
        let (source, mut tracker) = started().await;
        let walk = VirtualChainUpdate {
            removed_chain_block_hashes: vec![],
            added_chain_blocks: vec![AddedChainBlock {
                hash: block(2),
                daa_score: 101,
                accepted_transactions: vec![tx(1)],
            }],
        };
        source.push_scripted(walk.clone());
        source.push_scripted(walk);
        let first = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&first), vec![(id(1), at(2, 101))]);
        let second = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(
            second,
            PollResult {
                added: vec![],
                removed_txids: vec![],
                tip_daa: 101
            }
        );
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(2, 101)));
        assert_eq!(tracker.store().acceptances_by_block(&block(2)), vec![id(1)]);
    }

    /// A removed block named twice un-accepts its transactions once.
    #[tokio::test]
    async fn a_removed_block_named_twice_is_unaccepted_once() {
        let (source, mut tracker) = started().await;
        source.extend(block(2), 101, vec![tx(1)]);
        tracker.poll_once(&source, all).await.unwrap();
        source.push_scripted(VirtualChainUpdate {
            removed_chain_block_hashes: vec![block(2), block(2)],
            added_chain_blocks: vec![AddedChainBlock {
                hash: block(3),
                daa_score: 101,
                accepted_transactions: vec![],
            }],
        });
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(result.removed_txids, vec![id(1)]);
        assert_eq!(tracker.accepting_block(&id(1)), None);
        assert!(tracker.store().acceptances_by_block(&block(2)).is_empty());
    }

    /// A transaction the walk shows accepted at another block, with no removal of the first,
    /// is moved: un-accepted at the old block and indexed at the new one.
    #[tokio::test]
    async fn an_acceptance_seen_at_another_block_without_a_removal_is_a_move() {
        let (source, mut tracker) = started().await;
        source.extend(block(2), 101, vec![tx(1), tx(2)]);
        tracker.poll_once(&source, all).await.unwrap();
        source.push_scripted(VirtualChainUpdate {
            removed_chain_block_hashes: vec![],
            added_chain_blocks: vec![AddedChainBlock {
                hash: block(3),
                daa_score: 125,
                accepted_transactions: vec![tx(1)],
            }],
        });
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(result.removed_txids, vec![id(1)]);
        assert_eq!(added(&result), vec![(id(1), at(3, 125))]);
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(3, 125)));
        assert_eq!(tracker.store().acceptances_by_block(&block(2)), vec![id(2)]);
        assert_eq!(tracker.store().acceptances_by_block(&block(3)), vec![id(1)]);
    }

    /// Two chain blocks of one walk accepting the same transaction (a valid chain never does):
    /// each acceptance comes back with the value `relevant` returned for it there, and the
    /// second is a move. The two copies differ only in their spent entries, which the txid
    /// does not cover.
    #[tokio::test]
    async fn a_transaction_accepted_by_two_blocks_of_one_walk_returns_each_value() {
        let (source, mut tracker) = started().await;
        let spent = |amount: u64| UtxoEntry::new(amount, entry().script_public_key, 0, false, None);
        let first = AcceptedTransaction::new(raw(1), vec![spent(1_000)]).unwrap();
        let second = AcceptedTransaction::new(raw(1), vec![spent(2_000)]).unwrap();
        source.extend(block(2), 101, vec![first]);
        source.extend(block(3), 102, vec![second]);
        let result = tracker
            .poll_once(&source, |_, accepted| Some(accepted.spent()[0].amount))
            .await
            .unwrap();
        assert_eq!(
            result.added,
            vec![(id(1), at(2, 101), 1_000), (id(1), at(3, 102), 2_000)]
        );
        assert_eq!(result.removed_txids, vec![id(1)]);
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(3, 102)));
        assert!(tracker.store().acceptances_by_block(&block(2)).is_empty());
    }

    #[tokio::test]
    async fn the_tracker_computes_txids_and_never_reads_the_cache() {
        let t = raw(1);
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
            t.id(),
            "the cache of a non-finalised transaction is empty"
        );
        let source = source();
        let stale = AcceptedTransaction::new(stale, vec![entry()]).unwrap();
        source.extend(block(1), 100, vec![stale]);
        let mut tracker = tracker();
        let mut seen = vec![];
        let result = tracker
            .poll_once(&source, |txid, _| {
                seen.push(txid);
                Some(())
            })
            .await
            .unwrap();
        assert_eq!(seen, vec![t.id()]);
        assert_eq!(added(&result), vec![(t.id(), at(1, 100))]);
        assert_eq!(tracker.accepting_block(&t.id()), Some(at(1, 100)));
    }

    #[tokio::test]
    async fn a_restart_resumes_from_the_stored_cursor_and_index() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1)]);
        let mut tracker = tracker();
        tracker.poll_once(&source, all).await.unwrap();

        // A new tracker over the same state; the node's sink has moved on.
        let mut restarted = VirtualChainTracker::new(tracker.into_store());
        assert_eq!(restarted.accepting_block(&id(1)), Some(at(1, 100)));
        source.extend(block(2), 101, vec![tx(2)]);
        let result = restarted.poll_once(&source, all).await.unwrap();
        assert_eq!(source.start_hashes_seen(), vec![block(0), block(1)]);
        assert_eq!(added(&result), vec![(id(2), at(2, 101))]);
    }

    #[tokio::test]
    async fn a_failed_first_walk_changes_nothing_but_the_bootstrap_cursor() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1)]);
        source.fail_next(Call::Walk, "connection reset");
        let mut tracker = tracker();
        let err = tracker.poll_once(&source, all).await.unwrap_err();
        assert_eq!(err, SourceError("connection reset".into()));
        let bootstrap = Some(Cursor {
            block_hash: block(0),
            daa_score: None,
        });
        assert_eq!(tracker.store().cursor(), bootstrap);
        assert_eq!(tracker.accepting_block(&id(1)), None);

        // Control: the same walk, served, is applied.
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&result), vec![(id(1), at(1, 100))]);
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
    }

    #[tokio::test]
    async fn a_failed_later_walk_changes_nothing_and_the_retry_reports_it_in_full() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1)]);
        let mut tracker = tracker();
        tracker.poll_once(&source, all).await.unwrap();

        // A reorg and a new acceptance are waiting; the walk fails.
        source.add_block(block(12), block(0), 100, vec![]);
        source.add_block(block(13), block(12), 101, vec![tx(2)]);
        source.set_sink(block(13));
        source.fail_next(Call::Walk, "timeout");
        assert!(tracker.poll_once(&source, all).await.is_err());
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
        assert_eq!(tracker.accepting_block(&id(1)), Some(at(1, 100)));
        assert_eq!(tracker.accepting_block(&id(2)), None);

        // Control: the retry walks from the same cursor and reports everything.
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(result.removed_txids, vec![id(1)]);
        assert_eq!(added(&result), vec![(id(2), at(13, 101))]);
        assert_eq!(
            source.start_hashes_seen(),
            vec![block(0), block(1), block(1)]
        );
    }

    #[tokio::test]
    async fn a_failed_bootstrap_call_changes_nothing() {
        for call in [Call::Sink, Call::SelectedParent] {
            let source = source();
            source.extend(block(1), 100, vec![tx(1)]);
            source.fail_next(call, "unavailable");
            let mut tracker = tracker();
            let err = tracker.poll_once(&source, all).await.unwrap_err();
            assert_eq!(err, SourceError("unavailable".into()), "{call:?}");
            assert_eq!(tracker.store().cursor(), None, "{call:?}");
            assert!(source.start_hashes_seen().is_empty(), "{call:?}: no walk");

            // Control: the next poll bootstraps and walks.
            let result = tracker.poll_once(&source, all).await.unwrap();
            assert_eq!(added(&result), vec![(id(1), at(1, 100))], "{call:?}");
        }
    }

    #[tokio::test]
    async fn a_poll_dropped_while_the_node_answers_changes_nothing() {
        let source = source();
        source.extend(block(1), 100, vec![tx(1)]);
        let mut tracker = tracker();
        tracker.poll_once(&source, all).await.unwrap();
        source.extend(block(2), 101, vec![tx(2)]);

        source.hang_next_walk();
        assert!(!poll_once_then_drop(tracker.poll_once(&source, all)));
        assert_eq!(tracker.store().cursor(), cursor(1, 100));
        assert_eq!(tracker.accepting_block(&id(2)), None);

        // Control: the next poll reports the walk in full.
        let result = tracker.poll_once(&source, all).await.unwrap();
        assert_eq!(added(&result), vec![(id(2), at(2, 101))]);
    }

    /// The store's own move: an upsert at another block leaves the old block's list.
    #[test]
    fn the_in_memory_store_moves_an_acceptance_between_blocks() {
        let mut store = InMemoryVirtualChainStore::new();
        store.upsert_acceptance(id(1), at(2, 101));
        store.upsert_acceptance(id(2), at(2, 101));
        store.upsert_acceptance(id(1), at(3, 102));
        assert_eq!(store.acceptance(&id(1)), Some(at(3, 102)));
        assert_eq!(store.acceptances_by_block(&block(2)), vec![id(2)]);
        assert_eq!(store.acceptances_by_block(&block(3)), vec![id(1)]);
        // Control: unaccept drops it from both views, and again is a no-op.
        store.unaccept(&id(1));
        store.unaccept(&id(1));
        assert_eq!(store.acceptance(&id(1)), None);
        assert!(store.acceptances_by_block(&block(3)).is_empty());
        assert_eq!(store.acceptances_by_block(&block(2)), vec![id(2)]);
    }

    #[test]
    fn spent_entries_must_match_the_inputs_one_for_one() {
        let refused = |n: usize| AcceptedTransaction::new(raw(1), vec![entry(); n]).unwrap_err();
        assert_eq!(
            refused(0),
            SourceError("0 spent UTXO entries for 1 inputs".into())
        );
        assert_eq!(
            refused(2),
            SourceError("2 spent UTXO entries for 1 inputs".into())
        );
        // Control: one entry for the one input.
        let accepted = AcceptedTransaction::new(raw(1), vec![entry()]).unwrap();
        assert_eq!(accepted.spent(), &[entry()]);
        assert_eq!(accepted.tx().id(), id(1));
    }

    #[test]
    fn finality_depth_zero_is_refused() {
        let err = FinalityPolicy::new(0).unwrap_err();
        assert_eq!(err.code(), "WATCH_FINALITY_DEPTH_ZERO");
        // Control: depth 1 is accepted.
        assert_eq!(FinalityPolicy::new(1).unwrap().depth_daa(), 1);
    }

    #[test]
    fn finality_holds_from_depth_n_not_before() {
        let policy = FinalityPolicy::new(10).unwrap();
        assert!(!policy.is_final(100, 109));
        assert!(policy.is_final(100, 110));
        assert!(
            !policy.is_final(100, 50),
            "a tip below the acceptance is depth 0"
        );
    }
}
