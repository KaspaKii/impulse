// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The node the user names: a wRPC (Borsh) client from the pinned rusty-kaspa revision, as the
//! tracker's [`VirtualChainSource`] and the watcher's [`Broadcaster`]. There is no default
//! endpoint and no resolver. The node is the watcher's only input, so on mainnet the link must
//! be private (`wss://`, or `ws://` to this machine).
//!
//! The walk is `get_virtual_chain_from_block_v2` at Full verbosity: for each added chain block
//! its header (hash, DAA score) and the transactions it accepted, and for each input the UTXO
//! entry it spent. Nothing is inferred and nothing is defaulted. A field the watcher needs that
//! the node did not send, a transaction whose recomputed ID differs from the one the node
//! reports, or an answer whose added chain blocks and accepted-transaction batches do not match
//! one for one, fails the whole call (`WATCH_SOURCE_FAILED`), and a failed call changes nothing.
//! The ID check cannot cover the two fields the ID leaves out (the compute budget or sigop
//! count, and the storage mass), which a rebroadcast of the accepted copy needs; those must be
//! present, and `impulse-watch probe` is how the owner checks a node sends them.
//!
//! Adapted from an internal wRPC adapter by the owner (relicensed, see NOTICE), and from the
//! `impulse` CLI's node wiring (I7, `crates/impulse-cli/src/node.rs`; copied rather than
//! depended on, since the CLI links the signing module and the watcher must not). Kept: the
//! connect options (blocking connect, ten second timeout, fallback strategy), the server-info
//! network check, a sink read and a selected-parent read through `get_block` for the bootstrap
//! cursor, and `submit_transaction` with orphans refused. Stripped: the WarpCore adapter enum
//! and settlement router, the wallet, UTXO cache and reservation logic, the signer, logging.
//! Changed: the v2 walk in place of `get_virtual_chain_from_block`; every call has a timeout;
//! the transport check is the CLI's. Keyless: nothing here signs or holds a key; `submit` sends
//! only a transaction the node had already accepted, as the node had accepted it.

use crate::error::WatchError;
use crate::tracker::{
    AcceptedTransaction, AddedChainBlock, BlockHash, SourceError, VirtualChainSource,
    VirtualChainUpdate,
};
use crate::watcher::{Broadcaster, Refusal};
use impulse_core::terms::Network;
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::network::NetworkType;
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_wrpc_client::prelude::{
    ConnectOptions, ConnectStrategy, GetServerInfoResponse, GetVirtualChainFromBlockV2Response,
    KaspaRpcClient, RpcApi, RpcDataVerbosityLevel, RpcOptionalTransaction, RpcState,
    RpcTransaction, WrpcEncoding,
};
use std::future::Future;
use std::time::Duration;

/// How long any one node call may take before it is treated as failed. A hung node would
/// otherwise stall the watcher without a sign. A policy choice, not a measured figure.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The URL as it may be shown: scheme and host with port, never the user information, the path
/// or the query, which can carry a credential or an API key (`ws://***@host:port/...`). A node
/// URL reaches stderr and the scripts' output, which the key holder pastes into the committed
/// brief.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((_, host)) => ("***@", host),
        None => ("", authority),
    };
    let more = if tail.is_empty() { "" } else { "/..." };
    format!("{scheme}{userinfo}{host}{more}")
}

/// Only `ws://` and `wss://` URLs with something after the scheme (copied from the CLI).
pub fn check_url(url: &str) -> Result<(), WatchError> {
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"));
    match rest {
        Some(r) if !r.is_empty() && !r.chars().any(char::is_whitespace) => Ok(()),
        _ => Err(WatchError::NodeUrlInvalid(redact_url(url))),
    }
}

/// The URL check, and on mainnet a private link: `wss://`, or `ws://` to this machine
/// (`127.0.0.1`, `[::1]` or `localhost`, optionally with a port). Plaintext to another host is
/// refused (`WATCH_NODE_INSECURE`); reach a remote node through an SSH tunnel to a loopback
/// port. Copied from the CLI's `check_transport`.
pub fn check_transport(url: &str, network: Network) -> Result<(), WatchError> {
    check_url(url)?;
    if network == Network::Testnet || url.starts_with("wss://") {
        return Ok(());
    }
    let authority = url["ws://".len()..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_len = if authority.starts_with('[') {
        authority.find(']').map_or(authority.len(), |i| i + 1)
    } else {
        authority.find(':').unwrap_or(authority.len())
    };
    let (host, port) = authority.split_at(host_len);
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if matches!(host, "127.0.0.1" | "[::1]" | "localhost") && port_ok {
        return Ok(());
    }
    Err(WatchError::NodeInsecure(redact_url(url)))
}

/// The name of an Impulse network, as the node and the files spell it.
pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

/// Mainnet and testnet map to Impulse networks; devnet and simnet map to none, so a node on
/// either never passes the network check.
fn impulse_network(info: &GetServerInfoResponse) -> Option<Network> {
    match info.network_id.network_type {
        NetworkType::Mainnet => Some(Network::Mainnet),
        NetworkType::Testnet => Some(Network::Testnet),
        NetworkType::Devnet | NetworkType::Simnet => None,
    }
}

/// The node is on `expected` and synced (`WATCH_NODE_NETWORK_MISMATCH`, `WATCH_NODE_NOT_SYNCED`).
pub fn check_server_info(
    info: &GetServerInfoResponse,
    expected: Network,
) -> Result<(), WatchError> {
    if impulse_network(info) != Some(expected) {
        return Err(WatchError::NodeNetworkMismatch {
            node: info.network_id.to_string(),
            watching: network_name(expected),
        });
    }
    if !info.is_synced {
        return Err(WatchError::NodeNotSynced);
    }
    Ok(())
}

// ---- the walk ----

fn short(what: impl std::fmt::Display) -> SourceError {
    SourceError(format!("get_virtual_chain_from_block_v2: {what}"))
}

/// The value of a field the watcher needs, or the failure naming it.
fn need<T>(value: Option<T>, what: &str) -> Result<T, SourceError> {
    value.ok_or_else(|| short(format!("the node sent no {what}")))
}

/// One accepted transaction as the watcher reads it: the transaction, rebuilt from the v2 walk's
/// optional fields, and the UTXO entry each input spent. Every field must be present. The
/// rebuilt transaction's ID must equal the ID the node reports for it.
pub(crate) fn convert_transaction(
    tx: &RpcOptionalTransaction,
) -> Result<AcceptedTransaction, SourceError> {
    let version = need(tx.version, "transaction version")?;
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    let mut spent = Vec::with_capacity(tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        let outpoint = need(
            input.previous_outpoint.as_ref(),
            &format!("outpoint of input {i}"),
        )?;
        let outpoint = TransactionOutpoint::new(
            need(
                outpoint.transaction_id,
                &format!("outpoint txid of input {i}"),
            )?,
            need(outpoint.index, &format!("outpoint index of input {i}"))?,
        );
        let signature_script = need(
            input.signature_script.clone(),
            &format!("signature script of input {i}"),
        )?;
        let sequence = need(input.sequence, &format!("sequence of input {i}"))?;
        // Version 0 commits a sigop count, later versions a compute budget.
        inputs.push(if version == 0 {
            TransactionInput::new(
                outpoint,
                signature_script,
                sequence,
                need(input.sig_op_count, &format!("sigop count of input {i}"))?,
            )
        } else {
            TransactionInput::new_with_compute_budget(
                outpoint,
                signature_script,
                sequence,
                need(
                    input.compute_budget,
                    &format!("compute budget of input {i}"),
                )?,
            )
        });
        let entry = need(
            input
                .verbose_data
                .as_ref()
                .and_then(|v| v.utxo_entry.as_ref()),
            &format!("spent UTXO entry of input {i}"),
        )?;
        spent.push(
            UtxoEntry::try_from(entry.clone())
                .map_err(|e| short(format!("spent UTXO entry of input {i}: {e}")))?,
        );
    }
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    for (i, output) in tx.outputs.iter().enumerate() {
        outputs.push(TransactionOutput::with_covenant(
            need(output.value, &format!("value of output {i}"))?,
            need(
                output.script_public_key.clone(),
                &format!("script of output {i}"),
            )?,
            output.covenant.as_ref().and_then(|c| c.0).map(|b| b.0),
        ));
    }
    let built = Transaction::new_with_mass(
        version,
        inputs,
        outputs,
        need(tx.lock_time, "lock time")?,
        need(tx.subnetwork_id, "subnetwork id")?,
        need(tx.gas, "gas")?,
        need(tx.payload.clone(), "payload")?,
        need(tx.storage_mass, "storage mass")?,
    );
    let reported = need(
        tx.verbose_data.as_ref().and_then(|v| v.transaction_id),
        "transaction id",
    )?;
    let computed = hashing::tx::id(&built);
    if computed != reported {
        return Err(short(format!(
            "transaction {reported} rebuilds to {computed}: a field the ID covers is missing or wrong"
        )));
    }
    AcceptedTransaction::new(built, spent)
}

/// The most added chain blocks one walk may carry (a policy figure, I14 O1). The pinned
/// rusty-kaspa sets the node's batch to ten times its mergeset size limit and says in a comment
/// at `rpc/service/src/service.rs` (`get_virtual_chain_from_block_v2_call`) that this is 2480 at
/// 10 bps and 1800 on mainnet. The cap is twice the largest of those, so an honest node never
/// meets it and a node that sends more is refused.
/// Removed chain blocks are not capped: the node's batch does not bound them either.
pub(crate) const MAX_ADDED_CHAIN_BLOCKS: usize = 5_000;

/// A walk whose last chain block is above the node's own virtual DAA score is not a walk of its
/// chain (I14 O1): a chain block is never above the virtual that selected it, and the virtual is
/// read after the walk, so an honest node needs no slack. A node that inflates a score to make
/// every earlier acceptance look final at once is refused. A reorg between the two calls that
/// lowers the virtual below the walk's last block fails that one poll, and the next one reads a
/// consistent pair.
pub(crate) fn check_below_virtual(
    update: &VirtualChainUpdate,
    virtual_daa: u64,
) -> Result<(), SourceError> {
    match update.added_chain_blocks.last() {
        Some(b) if b.daa_score > virtual_daa => Err(short(format!(
            "chain block {} has DAA score {}, above the node's virtual DAA score {virtual_daa}",
            b.hash, b.daa_score
        ))),
        _ => Ok(()),
    }
}

/// The walk as the tracker takes it. The added chain blocks and the accepted-transaction
/// batches must match one for one, in order, by hash (the node truncates the added list to the
/// batches it returns); each header must carry its hash and DAA score.
pub(crate) fn convert_walk(
    r: &GetVirtualChainFromBlockV2Response,
) -> Result<VirtualChainUpdate, SourceError> {
    let batches = &r.chain_block_accepted_transactions;
    if r.added_chain_block_hashes.len() > MAX_ADDED_CHAIN_BLOCKS {
        return Err(short(format!(
            "{} added chain blocks, above the {MAX_ADDED_CHAIN_BLOCKS} a walk may carry",
            r.added_chain_block_hashes.len()
        )));
    }
    if r.added_chain_block_hashes.len() != batches.len() {
        return Err(short(format!(
            "{} added chain blocks, {} accepted-transaction batches",
            r.added_chain_block_hashes.len(),
            batches.len()
        )));
    }
    let mut added: Vec<AddedChainBlock> = Vec::with_capacity(batches.len());
    for (hash, batch) in r.added_chain_block_hashes.iter().zip(batches.iter()) {
        let header = &batch.chain_block_header;
        if header.hash != Some(*hash) {
            return Err(short(format!(
                "the batch for chain block {hash} names {:?}",
                header.hash
            )));
        }
        let daa_score = need(
            header.daa_score,
            &format!("DAA score of chain block {hash}"),
        )?;
        // A chain block's DAA score is above its selected parent's: a walk whose scores do not
        // rise is not a walk of one chain.
        if let Some(previous) = added.last().filter(|b| b.daa_score >= daa_score) {
            return Err(short(format!(
                "chain block {hash} has DAA score {daa_score}, not above {} of the block before it",
                previous.daa_score
            )));
        }
        let accepted_transactions = batch
            .accepted_transactions
            .iter()
            .map(convert_transaction)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SourceError(format!("chain block {hash}: {}", e.0)))?;
        added.push(AddedChainBlock {
            hash: *hash,
            daa_score,
            accepted_transactions,
        });
    }
    Ok(VirtualChainUpdate {
        removed_chain_block_hashes: r.removed_chain_block_hashes.to_vec(),
        added_chain_blocks: added,
    })
}

/// The node's answer when the transaction is in its mempool (rusty-kaspa `mining/errors`,
/// `RuleError::RejectDuplicate`): what a rebroadcast is for has happened.
pub(crate) fn node_has_in_mempool(reason: &str, txid: &impl std::fmt::Display) -> bool {
    reason.contains(&format!("transaction {txid} is already in the mempool"))
}

/// The node's answer when it holds a record of the transaction as accepted by the consensus
/// (`RuleError::RejectAlreadyAccepted`). The record is kept for every block the node processes,
/// on or off the selected chain, and a reorg does not remove it, so this is not the mempool
/// holding the transaction: see [`Refusal::RecentlyAccepted`].
pub(crate) fn node_recently_accepted(reason: &str, txid: &impl std::fmt::Display) -> bool {
    reason.contains(&format!(
        "transaction {txid} was already accepted by the consensus"
    ))
}

/// A refused or failed connection, with the URL redacted and the error text, which may come from
/// the remote end, echoed escaped (Debug).
pub(crate) fn unreachable(url: &str, error: &dyn std::fmt::Display) -> WatchError {
    WatchError::NodeUnreachable(format!("{}: {:?}", redact_url(url), error.to_string()))
}

/// A connected wRPC client.
pub struct WrpcNode {
    client: KaspaRpcClient,
    /// How long any one call may take ([`CALL_TIMEOUT`] unless set at connect).
    call_timeout: Duration,
    /// The network the node was checked to be on, checked again after a reconnect.
    network: Network,
    /// Whether the client signalled a disconnect since this was last asked: true once per drop,
    /// whether or not the client has already re-made the link by itself.
    link_dropped: Box<dyn Fn() -> bool + Send + Sync>,
}

/// The connect options: block until the first connection, ten seconds to make it, and give up
/// at once if it fails (`Fallback`), so an unreachable node is `WATCH_NODE_UNREACHABLE` and not
/// a start that never ends.
fn connect_options() -> ConnectOptions {
    ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(10)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    }
}

impl WrpcNode {
    /// Connects to the URL the user supplied, after the transport check for `network`, then
    /// reads the server info and refuses a node on another network or not synced.
    pub async fn connect(url: &str, network: Network) -> Result<Self, WatchError> {
        Self::connect_with_timeout(url, network, CALL_TIMEOUT).await
    }

    /// As [`Self::connect`], with `call_timeout` for every call after it. The binary uses
    /// [`CALL_TIMEOUT`]; a shorter one is for tests of a node that never answers.
    pub async fn connect_with_timeout(
        url: &str,
        network: Network,
        call_timeout: Duration,
    ) -> Result<Self, WatchError> {
        check_transport(url, network)?;
        let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, None, None)
            .map_err(|e| WatchError::NodeUrlInvalid(format!("{}: {e}", redact_url(url))))?;
        client
            .connect(Some(connect_options()))
            .await
            .map_err(|e| unreachable(url, &e))?;
        // Listen for the client's own disconnect signals from here on.
        let signals = client.ctl().multiplexer().channel();
        let node = Self {
            client,
            call_timeout,
            network,
            link_dropped: Box::new(move || {
                let mut dropped = false;
                while let Ok(state) = signals.try_recv() {
                    dropped |= state == RpcState::Disconnected;
                }
                dropped
            }),
        };
        let checked = async {
            let info = node.server_info().await?;
            check_server_info(&info, network)
        }
        .await;
        if let Err(e) = checked {
            node.disconnect().await;
            return Err(e);
        }
        Ok(node)
    }

    pub async fn disconnect(&self) {
        let _ = self.client.disconnect().await;
    }

    /// The node's server info (version, network, sync state).
    pub async fn server_info(&self) -> Result<GetServerInfoResponse, WatchError> {
        self.timed(self.client.get_server_info())
            .await
            .map_err(|e| WatchError::NodeRpc(format!("get_server_info: {:?}", e.0)))
    }

    /// The raw v2 walk from `start` at Full verbosity, for the probe.
    pub(crate) async fn walk_raw(
        &self,
        start: BlockHash,
    ) -> Result<GetVirtualChainFromBlockV2Response, SourceError> {
        self.timed(self.client.get_virtual_chain_from_block_v2(
            start,
            Some(RpcDataVerbosityLevel::Full),
            None,
        ))
        .await
        .map_err(|e| short(format!("{:?}", e.0)))
    }

    /// The sink and the pruning point, for the probe.
    pub(crate) async fn dag_points(&self) -> Result<(BlockHash, BlockHash, u64), SourceError> {
        let info = self
            .timed(self.client.get_block_dag_info())
            .await
            .map_err(|e| SourceError(format!("get_block_dag_info: {:?}", e.0)))?;
        Ok((info.sink, info.pruning_point_hash, info.virtual_daa_score))
    }

    /// Makes the link again if it is down, and checks the node again if the link was lost, once
    /// per call. With `Fallback` the client tries to reconnect once when a link drops and then
    /// gives up for good, so a node that restarts, or a network that drops for a few seconds,
    /// would leave every later call failing. A link that was lost, whether the client re-made it
    /// by itself or this does, is checked as at start-up (the right network, synced) before
    /// anything is read from it, and closed again if it fails, so that the next call checks
    /// again. Nothing is retried inside a call: a poll that finds the link down and cannot make
    /// it again is a failed poll (`WATCH_SOURCE_FAILED`), and the next poll tries again. The
    /// client's disconnect signal can reach this a moment after the drop, so a poll between the
    /// two reads from the new link once before it is checked; the cursor's block hash, which a
    /// node of another chain does not know, fails such a walk.
    async fn ensure_connected(&self) -> Result<(), SourceError> {
        let dropped = (self.link_dropped)();
        if self.client.is_connected() && !dropped {
            return Ok(());
        }
        let again = async {
            if !self.client.is_connected() {
                self.client
                    .connect(Some(connect_options()))
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let info = self
                .client
                .get_server_info()
                .await
                .map_err(|e| e.to_string())?;
            check_server_info(&info, self.network).map_err(|e| e.to_string())
        };
        let outcome = match tokio::time::timeout(self.call_timeout, again).await {
            Ok(outcome) => outcome,
            Err(_) => Err(format!("no answer in {} ms", self.call_timeout.as_millis())),
        };
        match outcome {
            Ok(()) => {
                // The signals this itself caused are not drops.
                let _ = (self.link_dropped)();
                Ok(())
            }
            Err(reason) => {
                let _ = self.client.disconnect().await;
                Err(SourceError(format!(
                    "the link to the node was lost and could not be made again: {reason:?}"
                )))
            }
        }
    }

    /// Runs a node call with the timeout, after making the link again if it is down; the error
    /// text is the node's, so callers echo it escaped. A call that gets no answer in time drops
    /// the link: a link that has gone silent without closing (a half-open socket: a firewall that
    /// forgot the connection, a peer that vanished without a reset) is never reported as lost by
    /// the client, which has no keepalive, and would otherwise be called on until the operating
    /// system gives up on it, which takes minutes. After the drop the next call makes the link
    /// again and checks the node as at start-up.
    async fn timed<T, E: std::fmt::Display>(
        &self,
        call: impl Future<Output = Result<T, E>>,
    ) -> Result<T, SourceError> {
        self.ensure_connected().await?;
        match tokio::time::timeout(self.call_timeout, call).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(SourceError(e.to_string())),
            Err(_) => {
                self.drop_silent_link().await;
                Err(SourceError(format!(
                    "no answer in {} ms",
                    self.call_timeout.as_millis()
                )))
            }
        }
    }

    /// Closes the link after a call got no answer, so that the next call makes it again.
    async fn drop_silent_link(&self) {
        let _ = self.client.disconnect().await;
    }
}

impl VirtualChainSource for WrpcNode {
    async fn get_virtual_chain_from(
        &self,
        start_hash: BlockHash,
    ) -> Result<VirtualChainUpdate, SourceError> {
        let update = convert_walk(&self.walk_raw(start_hash).await?)?;
        if !update.added_chain_blocks.is_empty() {
            check_below_virtual(&update, self.dag_points().await?.2)?;
        }
        Ok(update)
    }

    async fn sink_hash(&self) -> Result<BlockHash, SourceError> {
        Ok(self.dag_points().await?.0)
    }

    /// The block's own selected parent, which `get_block` always carries in its verbose data.
    async fn selected_parent_hash(&self, block_hash: BlockHash) -> Result<BlockHash, SourceError> {
        let block = self
            .timed(self.client.get_block(block_hash, false))
            .await
            .map_err(|e| SourceError(format!("get_block: {:?}", e.0)))?;
        let verbose = block.verbose_data.ok_or_else(|| {
            SourceError(format!(
                "get_block: no verbose data for {block_hash}: cannot read the selected parent"
            ))
        })?;
        Ok(verbose.selected_parent_hash)
    }
}

impl Broadcaster for WrpcNode {
    /// Submits the transaction as given, orphans refused. The node's refusal text is returned as
    /// is (the watcher reports it escaped). A node that has the transaction in its mempool has
    /// done what a rebroadcast is for, so that answer is taken as accepted. A node that only
    /// holds a record of the transaction as accepted by the consensus has not: that is
    /// [`Refusal::RecentlyAccepted`]. An ID in the answer that is not the transaction's is a
    /// refusal.
    async fn submit(&self, tx: &Transaction) -> Result<(), Refusal> {
        let txid = hashing::tx::id(tx);
        match self
            .timed(
                self.client
                    .submit_transaction(RpcTransaction::from(tx), false),
            )
            .await
        {
            Ok(id) if id == txid => Ok(()),
            Ok(id) => Err(Refusal::Refused(format!(
                "the node answered with transaction {id}, not {txid}"
            ))),
            Err(e) if node_has_in_mempool(&e.0, &txid) => Ok(()),
            Err(e) if node_recently_accepted(&e.0, &txid) => Err(Refusal::RecentlyAccepted(e.0)),
            Err(e) => Err(Refusal::Refused(e.0)),
        }
    }

    async fn virtual_daa_score(&self) -> Result<u64, String> {
        self.dag_points().await.map(|p| p.2).map_err(|e| e.0)
    }
}

// ---- the probe ----

/// What `impulse-watch probe` found, one line each.
#[derive(Debug, Default)]
pub struct ProbeReport {
    pub lines: Vec<String>,
}

fn walk_summary(
    label: &str,
    update: &VirtualChainUpdate,
    virtual_daa: u64,
    out: &mut Vec<String>,
) -> Result<(), SourceError> {
    let blocks = update.added_chain_blocks.len();
    if blocks == 0 {
        return Err(SourceError(format!(
            "the {label} walk added no chain block"
        )));
    }
    let (mut txs, mut inputs, mut outputs) = (0usize, 0usize, 0usize);
    for block in &update.added_chain_blocks {
        for t in &block.accepted_transactions {
            txs += 1;
            inputs += t.tx().inputs.len();
            outputs += t.tx().outputs.len();
        }
    }
    let last = update.added_chain_blocks.last().map_or(0, |b| b.daa_score);
    out.push(format!(
        "ok: {label} walk: {blocks} added chain blocks, {} removed, {txs} accepted transactions, {inputs} inputs each with its spent UTXO entry and the transaction ID rebuilt, {outputs} outputs; last chain block at DAA {last} of virtual {virtual_daa}",
        update.removed_chain_block_hashes.len()
    ));
    Ok(())
}

/// Checks what the watcher relies on against a connected node, with read-only calls: the
/// server version (against `expect_version` when given), a short walk from a few chain blocks
/// behind the sink, and a long walk from the pruning point, whose size is the node's added-block
/// batch limit. Every transaction goes through the watcher's own conversion, so a field the
/// node does not send, or a transaction ID that does not rebuild, fails here (`WATCH_PROBE_FAILED`)
/// and not in the middle of a live run. Nothing is submitted.
pub async fn probe(
    node: &WrpcNode,
    network: Network,
    expect_version: Option<&str>,
) -> Result<ProbeReport, WatchError> {
    let fail = |e: SourceError| WatchError::ProbeFailed(format!("{:?}", e.0));
    let mut report = ProbeReport::default();
    let info = node.server_info().await?;
    check_server_info(&info, network)?;
    report.lines.push(format!(
        "ok: node {:?} on {}, synced, virtual DAA {}",
        info.server_version,
        network_name(network),
        info.virtual_daa_score
    ));
    if let Some(expected) = expect_version {
        if info.server_version != expected {
            return Err(WatchError::ProbeFailed(format!(
                "the node runs {:?}, expected {expected:?}",
                info.server_version
            )));
        }
        report
            .lines
            .push(format!("ok: node version is {expected:?}, as expected"));
    }

    let (sink, pruning_point, virtual_daa) = node.dag_points().await.map_err(fail)?;
    // A start a few chain blocks behind the sink, as the watcher's steady walks are.
    let mut start = sink;
    for _ in 0..10 {
        start = node.selected_parent_hash(start).await.map_err(fail)?;
    }
    let near = convert_walk(&node.walk_raw(start).await.map_err(fail)?).map_err(fail)?;
    walk_summary("short", &near, virtual_daa, &mut report.lines).map_err(fail)?;
    if !near.removed_chain_block_hashes.is_empty() {
        return Err(WatchError::ProbeFailed(
            "a walk from a chain block behind the sink removed chain blocks".into(),
        ));
    }

    let far = convert_walk(&node.walk_raw(pruning_point).await.map_err(fail)?).map_err(fail)?;
    walk_summary("batch", &far, virtual_daa, &mut report.lines).map_err(fail)?;
    let last = far.added_chain_blocks.last().map_or(0, |b| b.daa_score);
    report.lines.push(if last < virtual_daa.saturating_sub(100) {
        format!(
            "ok: the node stopped the batch walk at {} added chain blocks, short of the sink: its added-block batch limit; the watcher continues from the last block on its next poll",
            far.added_chain_blocks.len()
        )
    } else {
        format!(
            "ok: the batch walk from the pruning point reached the sink in {} added chain blocks",
            far.added_chain_blocks.len()
        )
    });
    Ok(report)
}
