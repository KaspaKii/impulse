// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The node the user names (spec/CLI.md, "Node" and "Settlement receipt"): a wRPC (Borsh)
//! client from the pinned rusty-kaspa revision behind a small synchronous [`Node`] trait, and the
//! logic that runs over it (network and sync checks, submit, acceptance walk, receipt checks),
//! which the tests drive with a fake node. There is no default endpoint and no resolver.
//!
//! Adapted from an internal wRPC adapter and virtual chain tracker by the owner (relicensed,
//! see NOTICE): connect options, the server-info network check, acceptance read from the
//! `accepted_transaction_ids` of `get_virtual_chain_from_block` (never from mempool absence),
//! removals honoured, depth as virtual DAA score minus the accepting block's DAA score, and (I7
//! phase 2) the UTXO lookup by address. The same walk over `get_virtual_chain_from_block_v2`
//! finds an accepted transaction with the UTXOs it spent, for `impulse decode`.

use crate::error::CliError;
use crate::json::hex;
use crate::receipt::{Observation, Receipt};
use crate::terms_file::network_name;
use impulse_core::terms::Network;
use impulse_core::tx::Utxo;
use kaspa_addresses::Address;
use kaspa_consensus_core::network::NetworkType;
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use kaspa_wrpc_client::prelude::{
    ConnectOptions, ConnectStrategy, GetBlockDagInfoResponse, GetBlockRequest,
    GetServerInfoResponse, GetVirtualChainFromBlockRequest, GetVirtualChainFromBlockResponse,
    GetVirtualChainFromBlockV2Request, GetVirtualChainFromBlockV2Response, KaspaRpcClient, RpcApi,
    RpcBlock, RpcDataVerbosityLevel, RpcHash, RpcTransaction, RpcUtxosByAddressesEntry,
    WrpcEncoding,
};
use std::future::Future;
use std::time::Duration;

/// How long any one node call may take before it is refused (`CLI_NODE_RPC`, `no answer in`).
/// Without it a node that takes the connection and never answers would hold the command for
/// ever. A policy figure, the watcher's, not a measured one.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The URL as it may be shown: scheme and host with port, never the user information, the path
/// or the query, which can carry a credential or an API key (`ws://***@host:port/...`). Copied
/// from `crates/impulse-watch/src/node.rs`; the two must agree.
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

/// Upper bound on virtual chain batches one acceptance walk requests.
pub const MAX_WALK_BATCHES: usize = 10_000;

/// What the node says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    /// None for devnet and simnet, which Impulse terms cannot name.
    pub network: Option<Network>,
    /// The node's own network name, for messages.
    pub network_name: String,
    pub synced: bool,
}

/// The DAG tip as the node sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DagInfo {
    pub sink: [u8; 32],
    pub virtual_daa: u64,
}

/// One block's header facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub daa_score: u64,
    pub selected_parent: [u8; 32],
    pub is_chain_block: bool,
}

/// One `get_virtual_chain_from_block` answer, with accepted transaction IDs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainUpdate {
    pub removed: Vec<[u8; 32]>,
    pub added: Vec<[u8; 32]>,
    /// (accepting chain block, transaction IDs it accepted)
    pub accepted: Vec<([u8; 32], Vec<[u8; 32]>)>,
}

/// A transaction a chain block accepted, with the UTXO entry each of its inputs spent, in input
/// order, as the node reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedTx {
    pub tx: Transaction,
    pub spent: Vec<UtxoEntry>,
}

/// One `get_virtual_chain_from_block_v2` answer at full verbosity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptedUpdate {
    pub removed: Vec<[u8; 32]>,
    pub added: Vec<[u8; 32]>,
    /// (accepting chain block, the transactions it accepted)
    pub accepted: Vec<([u8; 32], Vec<AcceptedTx>)>,
}

/// The node calls the CLI makes.
pub trait Node {
    fn server_info(&self) -> Result<ServerInfo, CliError>;
    fn dag_info(&self) -> Result<DagInfo, CliError>;
    fn block(&self, hash: [u8; 32]) -> Result<BlockInfo, CliError>;
    fn virtual_chain_from(&self, start: [u8; 32]) -> Result<ChainUpdate, CliError>;
    /// Submits a fully signed transaction; returns the ID the node assigned.
    fn submit(&self, tx: &Transaction) -> Result<[u8; 32], CliError>;
    /// The UTXOs at an address, from the node's UTXO index.
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, CliError>;
    /// The virtual chain from `start` with every accepted transaction and the UTXOs it spent.
    fn accepted_from(&self, start: [u8; 32]) -> Result<AcceptedUpdate, CliError>;
}

/// A failed RPC call. The error text may come from the node, so it is echoed escaped: a hostile
/// node cannot write control sequences to the user's terminal.
fn rpc(what: &str, e: impl std::fmt::Display) -> CliError {
    CliError::new("CLI_NODE_RPC", format!("{what}: {:?}", e.to_string()))
}

/// A `fake://` URL of the offline fake node; only builds with the `offline-fake-node` feature
/// (tests) know one (spec/CLI.md, "Offline fake node (tests only)").
pub fn is_fake_url(url: &str) -> bool {
    cfg!(feature = "offline-fake-node") && url.len() > "fake://".len() && url.starts_with("fake://")
}

/// Only `ws://` and `wss://` URLs with something after the scheme.
pub fn check_url(url: &str) -> Result<(), CliError> {
    if is_fake_url(url) {
        return Ok(());
    }
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"));
    match rest {
        Some(r) if !r.is_empty() && !r.chars().any(char::is_whitespace) => Ok(()),
        _ => Err(CliError::new(
            "CLI_NODE_URL_INVALID",
            format!("{:?} is not a ws:// or wss:// wRPC URL", redact_url(url)),
        )),
    }
}

/// The URL check, and on mainnet a private link: `wss://`, or `ws://` to this machine
/// (`127.0.0.1`, `[::1]` or `localhost`, optionally with a port). On mainnet the node is the trust
/// anchor for the creation DAA score and for signed receipts, so plaintext to another host is
/// refused (`CLI_NODE_INSECURE`); reach a remote node through an SSH tunnel to a loopback port.
pub fn check_transport(url: &str, network: Network) -> Result<(), CliError> {
    check_url(url)?;
    if network == Network::Testnet || url.starts_with("wss://") || is_fake_url(url) {
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
    Err(CliError::new(
        "CLI_NODE_INSECURE",
        format!(
            "{:?}: on mainnet the node link must be wss://, or ws:// to 127.0.0.1, [::1] or localhost (an SSH tunnel reaches a remote node)",
            redact_url(url)
        ),
    ))
}

/// The node is on `expected` and synced.
pub fn check_node(node: &dyn Node, expected: Network) -> Result<ServerInfo, CliError> {
    let info = node.server_info()?;
    if info.network != Some(expected) {
        return Err(CliError::new(
            "CLI_NODE_NETWORK_MISMATCH",
            format!(
                "the node is on {}, this command acts on {}",
                info.network_name,
                network_name(expected)
            ),
        ));
    }
    if !info.synced {
        return Err(CliError::new(
            "CLI_NODE_NOT_SYNCED",
            "the node is not synced",
        ));
    }
    Ok(info)
}

/// The virtual DAA score of a checked node: the creation DAA score for new terms.
pub fn creation_daa(node: &dyn Node, expected: Network) -> Result<u64, CliError> {
    check_node(node, expected)?;
    Ok(node.dag_info()?.virtual_daa)
}

/// A submitted transaction and the chain block to walk from when asking for its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submitted {
    pub txid: [u8; 32],
    /// The node's sink just before submission; it cannot have accepted the transaction.
    pub from_block: [u8; 32],
}

/// Submits a fully signed transaction to a checked node. Phase 2 wires it to `impulse submit`.
pub fn submit(node: &dyn Node, tx: &Transaction, expected: Network) -> Result<Submitted, CliError> {
    check_node(node, expected)?;
    let from_block = node.dag_info()?.sink;
    let own = tx.id().as_bytes();
    // A refusal here can be an answer that never arrived (a timeout, a dropped link) to a
    // submission the node took: name the transaction and how to look for it, so the user checks
    // before submitting again.
    let txid = node.submit(tx).map_err(|e| {
        CliError::new(
            e.code(),
            format!(
                "{}; the node may still have taken transaction {}: check with `impulse status --txid {} --from-block {}` before submitting it again",
                e.detail(),
                hex(&own),
                hex(&own),
                hex(&from_block)
            ),
        )
    })?;
    if txid != own {
        return Err(CliError::new(
            "CLI_NODE_TXID_MISMATCH",
            format!(
                "the node returned {}, the transaction is {}",
                hex(&txid),
                hex(&own)
            ),
        ));
    }
    Ok(Submitted { txid, from_block })
}

/// Walks the virtual selected parent chain from `from` to the sink and returns the chain block
/// that accepts `txid`. A block reported as removed after it accepted the transaction no longer
/// counts. Refuses an answer whose acceptance names a block it did not add.
pub fn find_acceptance(
    node: &dyn Node,
    txid: [u8; 32],
    from: [u8; 32],
) -> Result<[u8; 32], CliError> {
    let mut cursor = from;
    let mut found: Option<[u8; 32]> = None;
    for _ in 0..MAX_WALK_BATCHES {
        let update = node.virtual_chain_from(cursor)?;
        if found.is_some_and(|b| update.removed.contains(&b)) {
            found = None;
        }
        for (block, ids) in &update.accepted {
            if !update.added.contains(block) {
                return Err(rpc(
                    "get_virtual_chain_from_block",
                    "acceptance names a block the answer does not add",
                ));
            }
            if ids.contains(&txid) {
                found = Some(*block);
            }
        }
        match update.added.last() {
            Some(last) => cursor = *last,
            None => {
                return found.ok_or_else(|| {
                    CliError::new(
                        "CLI_TX_NOT_ACCEPTED",
                        format!(
                            "{} is not accepted on the chain from {}",
                            hex(&txid),
                            hex(&from)
                        ),
                    )
                })
            }
        }
    }
    Err(CliError::new(
        "CLI_TX_NOT_ACCEPTED",
        format!("walk limit of {MAX_WALK_BATCHES} batches reached before the sink"),
    ))
}

/// Walks the virtual chain from `from` to the sink with the accepted transactions and returns the
/// chain block that accepts `txid` and the transaction, with the UTXO entries it spent. The
/// transaction is found by its ID recomputed from its contents. A block reported as removed after
/// it accepted the transaction no longer counts; an answer whose acceptance names a block it did
/// not add is refused.
pub fn find_accepted_tx(
    node: &dyn Node,
    txid: [u8; 32],
    from: [u8; 32],
) -> Result<([u8; 32], AcceptedTx), CliError> {
    let mut cursor = from;
    let mut found: Option<([u8; 32], AcceptedTx)> = None;
    for _ in 0..MAX_WALK_BATCHES {
        let update = node.accepted_from(cursor)?;
        if found
            .as_ref()
            .is_some_and(|(b, _)| update.removed.contains(b))
        {
            found = None;
        }
        for (block, txs) in update.accepted {
            if !update.added.contains(&block) {
                return Err(rpc(
                    "get_virtual_chain_from_block_v2",
                    "acceptance names a block the answer does not add",
                ));
            }
            if let Some(a) = txs.into_iter().find(|a| a.tx.id().as_bytes() == txid) {
                if a.spent.len() != a.tx.inputs.len() {
                    return Err(rpc(
                        "get_virtual_chain_from_block_v2",
                        "the spent UTXO entries do not match the inputs",
                    ));
                }
                found = Some((block, a));
            }
        }
        match update.added.last() {
            Some(last) => cursor = *last,
            None => {
                return found.ok_or_else(|| {
                    CliError::new(
                        "CLI_TX_NOT_ACCEPTED",
                        format!(
                            "{} is not accepted on the chain from {}",
                            hex(&txid),
                            hex(&from)
                        ),
                    )
                })
            }
        }
    }
    Err(CliError::new(
        "CLI_TX_NOT_ACCEPTED",
        format!("walk limit of {MAX_WALK_BATCHES} batches reached before the sink"),
    ))
}

/// What `impulse status` reports: acceptance of `txid` on a checked node, with depth.
pub fn observe(
    node: &dyn Node,
    network: Network,
    terms_hash: [u8; 32],
    txid: [u8; 32],
    from: [u8; 32],
) -> Result<Observation, CliError> {
    check_node(node, network)?;
    let accepting_block = find_acceptance(node, txid, from)?;
    let block = node.block(accepting_block)?;
    if !block.is_chain_block {
        return Err(CliError::new(
            "CLI_TX_NOT_ACCEPTED",
            "the accepting block left the selected chain during the walk",
        ));
    }
    let depth = node
        .dag_info()?
        .virtual_daa
        .checked_sub(block.daa_score)
        .ok_or_else(|| rpc("get_block_dag_info", "virtual DAA score below the block's"))?;
    Ok(Observation {
        network,
        terms_hash,
        txid,
        accepting_block,
        daa_score: block.daa_score,
        depth,
    })
}

/// Re-verifies a receipt's on-chain facts against a checked node (spec/CLI.md, "Verification",
/// step 4). The signature is checked separately.
pub fn verify_receipt(node: &dyn Node, receipt: &Receipt) -> Result<(), CliError> {
    verify_observation(node, &receipt.observation)
}

/// [`verify_receipt`] for the observation any receipt version carries.
pub fn verify_observation(node: &dyn Node, o: &Observation) -> Result<(), CliError> {
    check_node(node, o.network)?;
    let not_accepted = |why: &str| CliError::new("RECEIPT_NOT_ACCEPTED", why.to_string());
    let block = node.block(o.accepting_block)?;
    if !block.is_chain_block {
        return Err(not_accepted("the accepting block is not a chain block"));
    }
    if block.daa_score != o.daa_score {
        return Err(CliError::new(
            "RECEIPT_DAA_MISMATCH",
            format!(
                "the accepting block's DAA score is {}, the receipt says {}",
                block.daa_score, o.daa_score
            ),
        ));
    }
    let update = node.virtual_chain_from(block.selected_parent)?;
    if !update.removed.is_empty() || update.added.first() != Some(&o.accepting_block) {
        return Err(not_accepted(
            "the chain from the block's selected parent does not continue with it",
        ));
    }
    let accepted = update
        .accepted
        .iter()
        .find(|(b, _)| *b == o.accepting_block)
        .is_some_and(|(_, ids)| ids.contains(&o.txid));
    if !accepted {
        return Err(not_accepted("the block did not accept the transaction"));
    }
    let depth = node
        .dag_info()?
        .virtual_daa
        .checked_sub(o.daa_score)
        .ok_or_else(|| rpc("get_block_dag_info", "virtual DAA score below the block's"))?;
    if depth < o.depth {
        return Err(CliError::new(
            "RECEIPT_DEPTH_UNREACHED",
            format!("current depth {depth} is below the receipt's {}", o.depth),
        ));
    }
    Ok(())
}

/// A connected wRPC client and the runtime it runs on. Calls block until the node answers.
pub struct WrpcNode {
    client: KaspaRpcClient,
    rt: tokio::runtime::Runtime,
}

impl WrpcNode {
    /// Connects to the URL the user supplied, after the transport check for `network`, so no
    /// caller reaches a node over a link the network does not allow. No default URL exists, and
    /// no resolver is used.
    pub fn connect(url: &str, network: Network) -> Result<Self, CliError> {
        check_transport(url, network)?;
        // Connection errors may carry text from the remote end: echoed escaped, as in `rpc`.
        let unreachable = |e: &dyn std::fmt::Display| {
            CliError::new(
                "CLI_NODE_UNREACHABLE",
                format!("{}: {:?}", redact_url(url), e.to_string()),
            )
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| unreachable(&e))?;
        let client = {
            let _guard = rt.enter();
            KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, None, None)
        }
        .map_err(|e| {
            CliError::new(
                "CLI_NODE_URL_INVALID",
                format!("{}: {:?}", redact_url(url), e.to_string()),
            )
        })?;
        let options = ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(10)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        };
        rt.block_on(client.connect(Some(options)))
            .map_err(|e| unreachable(&e))?;
        Ok(Self { client, rt })
    }
}

impl WrpcNode {
    /// Runs one node call on the runtime with [`CALL_TIMEOUT`].
    fn call<T, E: std::fmt::Display>(
        &self,
        what: &str,
        call: impl Future<Output = Result<T, E>>,
    ) -> Result<T, CliError> {
        within(&self.rt, CALL_TIMEOUT, what, call)
    }
}

/// `call` on `rt`, refused as `CLI_NODE_RPC` if it fails or gives no answer within `timeout`.
pub(crate) fn within<T, E: std::fmt::Display>(
    rt: &tokio::runtime::Runtime,
    timeout: Duration,
    what: &str,
    call: impl Future<Output = Result<T, E>>,
) -> Result<T, CliError> {
    match rt.block_on(async { tokio::time::timeout(timeout, call).await }) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(rpc(what, e)),
        Err(_) => Err(CliError::new(
            "CLI_NODE_RPC",
            format!("{what}: no answer in {} ms", timeout.as_millis()),
        )),
    }
}

impl Drop for WrpcNode {
    fn drop(&mut self) {
        // Bounded too: a silent link must not hold the command at exit.
        let _ = within(
            &self.rt,
            Duration::from_secs(5),
            "disconnect",
            self.client.disconnect(),
        );
    }
}

fn bytes(h: RpcHash) -> [u8; 32] {
    h.as_bytes()
}

// The mapping from the node's RPC answers to what the CLI uses, as pure functions over the
// kaspa-rpc-core types, so each field is tested without a node.

/// Mainnet and testnet map to Impulse networks; devnet and simnet map to none, so a node on
/// either never passes the network check.
pub(crate) fn map_server_info(info: &GetServerInfoResponse) -> ServerInfo {
    ServerInfo {
        network: match info.network_id.network_type {
            NetworkType::Mainnet => Some(Network::Mainnet),
            NetworkType::Testnet => Some(Network::Testnet),
            NetworkType::Devnet | NetworkType::Simnet => None,
        },
        network_name: info.network_id.to_string(),
        synced: info.is_synced,
    }
}

pub(crate) fn map_dag_info(info: &GetBlockDagInfoResponse) -> DagInfo {
    DagInfo {
        sink: bytes(info.sink),
        virtual_daa: info.virtual_daa_score,
    }
}

/// The request for one header without its transactions.
pub(crate) fn block_request(hash: [u8; 32]) -> GetBlockRequest {
    GetBlockRequest::new(RpcHash::from_bytes(hash), false)
}

/// The DAA score comes from the header; the chain-block flag and selected parent from the
/// verbose data, which a node must send.
pub(crate) fn map_block(block: &RpcBlock) -> Result<BlockInfo, CliError> {
    let verbose = block
        .verbose_data
        .as_ref()
        .ok_or_else(|| rpc("get_block", "no verbose data"))?;
    Ok(BlockInfo {
        daa_score: block.header.daa_score,
        selected_parent: bytes(verbose.selected_parent_hash),
        is_chain_block: verbose.is_chain_block,
    })
}

/// The chain request always asks for the accepted transaction IDs: acceptance is read from
/// them, never inferred.
pub(crate) fn chain_request(start: [u8; 32]) -> GetVirtualChainFromBlockRequest {
    GetVirtualChainFromBlockRequest::new(RpcHash::from_bytes(start), true, None)
}

pub(crate) fn map_chain_update(r: GetVirtualChainFromBlockResponse) -> ChainUpdate {
    ChainUpdate {
        removed: r
            .removed_chain_block_hashes
            .into_iter()
            .map(bytes)
            .collect(),
        added: r.added_chain_block_hashes.into_iter().map(bytes).collect(),
        accepted: r
            .accepted_transaction_ids
            .into_iter()
            .map(|a| {
                (
                    bytes(a.accepting_block_hash),
                    a.accepted_transaction_ids.into_iter().map(bytes).collect(),
                )
            })
            .collect(),
    }
}

/// The v2 chain request at full verbosity: each accepted transaction with every field, and each
/// input's spent UTXO entry.
pub(crate) fn chain_v2_request(start: [u8; 32]) -> GetVirtualChainFromBlockV2Request {
    GetVirtualChainFromBlockV2Request::new(
        RpcHash::from_bytes(start),
        Some(RpcDataVerbosityLevel::Full),
        None,
    )
}

/// Every field the decoder needs must be in the answer; a missing one is `CLI_NODE_RPC`.
pub(crate) fn map_chain_update_v2(
    r: GetVirtualChainFromBlockV2Response,
) -> Result<AcceptedUpdate, CliError> {
    let what = "get_virtual_chain_from_block_v2";
    let mut accepted = Vec::with_capacity(r.chain_block_accepted_transactions.len());
    for block in r.chain_block_accepted_transactions.iter() {
        let hash = block
            .chain_block_header
            .hash
            .ok_or_else(|| rpc(what, "a chain block without its hash"))?;
        let mut txs = Vec::with_capacity(block.accepted_transactions.len());
        for rtx in &block.accepted_transactions {
            let spent = rtx
                .inputs
                .iter()
                .map(|i| {
                    let entry = i
                        .verbose_data
                        .as_ref()
                        .and_then(|v| v.utxo_entry.clone())
                        .ok_or_else(|| rpc(what, "an input without its spent UTXO entry"))?;
                    UtxoEntry::try_from(entry).map_err(|e| rpc(what, e))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let tx = Transaction::try_from(rtx.clone()).map_err(|e| rpc(what, e))?;
            txs.push(AcceptedTx { tx, spent });
        }
        accepted.push((bytes(hash), txs));
    }
    Ok(AcceptedUpdate {
        removed: r
            .removed_chain_block_hashes
            .iter()
            .copied()
            .map(bytes)
            .collect(),
        added: r
            .added_chain_block_hashes
            .iter()
            .copied()
            .map(bytes)
            .collect(),
        accepted,
    })
}

pub(crate) fn map_utxos(entries: Vec<RpcUtxosByAddressesEntry>) -> Vec<Utxo> {
    entries
        .into_iter()
        .map(|e| Utxo {
            outpoint: e.outpoint.into(),
            entry: e.utxo_entry.into(),
        })
        .collect()
}

impl Node for WrpcNode {
    fn server_info(&self) -> Result<ServerInfo, CliError> {
        let info = self.call("get_server_info", self.client.get_server_info())?;
        Ok(map_server_info(&info))
    }

    fn dag_info(&self) -> Result<DagInfo, CliError> {
        let info = self.call("get_block_dag_info", self.client.get_block_dag_info())?;
        Ok(map_dag_info(&info))
    }

    fn block(&self, hash: [u8; 32]) -> Result<BlockInfo, CliError> {
        let answer = self.call(
            "get_block",
            self.client.get_block_call(None, block_request(hash)),
        )?;
        map_block(&answer.block)
    }

    fn virtual_chain_from(&self, start: [u8; 32]) -> Result<ChainUpdate, CliError> {
        let r = self.call(
            "get_virtual_chain_from_block",
            self.client
                .get_virtual_chain_from_block_call(None, chain_request(start)),
        )?;
        Ok(map_chain_update(r))
    }

    fn submit(&self, tx: &Transaction) -> Result<[u8; 32], CliError> {
        let id = self.call(
            "submit_transaction",
            self.client
                .submit_transaction(RpcTransaction::from(tx), false),
        )?;
        Ok(bytes(id))
    }

    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, CliError> {
        let entries = self.call(
            "get_utxos_by_addresses",
            self.client.get_utxos_by_addresses(vec![address.clone()]),
        )?;
        Ok(map_utxos(entries))
    }

    fn accepted_from(&self, start: [u8; 32]) -> Result<AcceptedUpdate, CliError> {
        let r = self.call(
            "get_virtual_chain_from_block_v2",
            self.client
                .get_virtual_chain_from_block_v2_call(None, chain_v2_request(start)),
        )?;
        map_chain_update_v2(r)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A scripted node: chain answers keyed by start block, everything else fixed.
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    pub(crate) struct FakeNode {
        pub(crate) info: ServerInfo,
        pub(crate) dag: DagInfo,
        pub(crate) blocks: HashMap<[u8; 32], BlockInfo>,
        pub(crate) chain: HashMap<[u8; 32], ChainUpdate>,
        /// The ID `submit` answers with; None answers with the transaction's own ID.
        pub(crate) submit_answer: Option<[u8; 32]>,
        /// v2 chain answers keyed by start block; empty unless a test scripts them.
        pub(crate) accepted: HashMap<[u8; 32], AcceptedUpdate>,
        pub(crate) submitted: RefCell<Vec<[u8; 32]>>,
        pub(crate) calls: RefCell<usize>,
        /// `submit` records the transaction and then fails, as an answer that never arrived.
        pub(crate) submit_fails: bool,
    }

    pub(crate) fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    impl FakeNode {
        /// A synced testnet node whose chain runs 1 -> 2 -> 3 -> 4 (sink); block 3 accepts
        /// transaction 0xaa; virtual DAA 1_000 with block n at DAA 900 + n.
        pub(crate) fn testnet() -> Self {
            let mut blocks = HashMap::new();
            for n in 1..=4u8 {
                blocks.insert(
                    h(n),
                    BlockInfo {
                        daa_score: 900 + u64::from(n),
                        selected_parent: h(n - 1),
                        is_chain_block: true,
                    },
                );
            }
            let mut chain = HashMap::new();
            chain.insert(
                h(1),
                ChainUpdate {
                    removed: vec![],
                    added: vec![h(2), h(3)],
                    accepted: vec![(h(2), vec![h(0xbb)]), (h(3), vec![h(0xcc), h(0xaa)])],
                },
            );
            chain.insert(
                h(2),
                ChainUpdate {
                    removed: vec![],
                    added: vec![h(3), h(4)],
                    accepted: vec![(h(3), vec![h(0xcc), h(0xaa)]), (h(4), vec![])],
                },
            );
            chain.insert(
                h(3),
                ChainUpdate {
                    removed: vec![],
                    added: vec![h(4)],
                    accepted: vec![(h(4), vec![])],
                },
            );
            chain.insert(h(4), ChainUpdate::default());
            Self {
                info: ServerInfo {
                    network: Some(Network::Testnet),
                    network_name: "testnet-10".into(),
                    synced: true,
                },
                dag: DagInfo {
                    sink: h(4),
                    virtual_daa: 1_000,
                },
                blocks,
                chain,
                submit_answer: None,
                accepted: HashMap::new(),
                submitted: RefCell::new(vec![]),
                calls: RefCell::new(0),
                submit_fails: false,
            }
        }
    }

    impl FakeNode {
        /// The same chain on a synced mainnet node at virtual DAA score 400_000_000, inside the
        /// creation range of the mainnet golden vectors.
        pub(crate) fn mainnet() -> Self {
            let mut n = Self::testnet();
            n.info.network = Some(Network::Mainnet);
            n.info.network_name = "mainnet".into();
            n.dag.virtual_daa = 400_000_000;
            n
        }
    }

    impl Node for FakeNode {
        fn server_info(&self) -> Result<ServerInfo, CliError> {
            Ok(self.info.clone())
        }
        fn dag_info(&self) -> Result<DagInfo, CliError> {
            Ok(self.dag)
        }
        fn block(&self, hash: [u8; 32]) -> Result<BlockInfo, CliError> {
            self.blocks
                .get(&hash)
                .copied()
                .ok_or_else(|| rpc("get_block", "block not found"))
        }
        fn virtual_chain_from(&self, start: [u8; 32]) -> Result<ChainUpdate, CliError> {
            *self.calls.borrow_mut() += 1;
            self.chain
                .get(&start)
                .cloned()
                .ok_or_else(|| rpc("get_virtual_chain_from_block", "unknown start"))
        }
        fn submit(&self, tx: &Transaction) -> Result<[u8; 32], CliError> {
            let id = tx.id().as_bytes();
            self.submitted.borrow_mut().push(id);
            if self.submit_fails {
                return Err(rpc("submit_transaction", "no answer in 30000 ms"));
            }
            Ok(self.submit_answer.unwrap_or(id))
        }
        fn utxos(&self, _address: &Address) -> Result<Vec<Utxo>, CliError> {
            Err(rpc("get_utxos_by_addresses", "not scripted"))
        }
        fn accepted_from(&self, start: [u8; 32]) -> Result<AcceptedUpdate, CliError> {
            *self.calls.borrow_mut() += 1;
            self.accepted
                .get(&start)
                .cloned()
                .ok_or_else(|| rpc("get_virtual_chain_from_block_v2", "unknown start"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{h, FakeNode};
    use super::*;
    use crate::signing::throwaway::key_file;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;

    /// Review round 2: node-supplied error text reached the terminal raw.
    #[test]
    fn node_error_text_is_echoed_escaped() {
        let hostile = "boom\u{1b}[2J\nnext line\u{1b}]0;title\u{7}";
        let e = rpc("get_block", hostile);
        assert_eq!(e.code(), "CLI_NODE_RPC");
        let text = e.to_string();
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert_eq!(
            text,
            r#"CLI_NODE_RPC: get_block: "boom\u{1b}[2J\nnext line\u{1b}]0;title\u{7}""#
        );
        // Control: plain text is kept, quoted.
        assert_eq!(
            rpc("get_block", "no verbose data").to_string(),
            r#"CLI_NODE_RPC: get_block: "no verbose data""#
        );
    }

    #[test]
    fn urls_are_ws_or_wss_only() {
        for good in ["ws://127.0.0.1:17210", "wss://node.example:443/path"] {
            assert_eq!(check_url(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "ws://",
            "http://127.0.0.1:16110",
            "grpc://127.0.0.1:16110",
            "127.0.0.1:17110",
            "ws://host name",
            "WS://127.0.0.1:17110",
        ] {
            assert_eq!(
                check_url(bad).unwrap_err().code(),
                "CLI_NODE_URL_INVALID",
                "{bad}"
            );
        }
    }

    #[test]
    fn mainnet_needs_a_private_link() {
        for good in [
            "wss://node.example:443/path",
            "ws://127.0.0.1:17110",
            "ws://127.0.0.1",
            "ws://localhost:17110",
            "ws://[::1]:17110",
            "ws://127.0.0.1:17110/",
        ] {
            assert_eq!(check_transport(good, Network::Mainnet), Ok(()), "{good}");
        }
        for bad in [
            "ws://203.0.113.9:17110",
            "ws://node.example:17110",
            "ws://127.0.0.1.example:17110",
            "ws://127.0.0.1@203.0.113.9:17110",
            "ws://localhost.example",
            "ws://127.0.0.2:17110",
            "ws://[::2]:17110",
            "ws://127.0.0.1:x",
            "ws://127.0.0.1:",
        ] {
            assert_eq!(
                check_transport(bad, Network::Mainnet).unwrap_err().code(),
                "CLI_NODE_INSECURE",
                "{bad}"
            );
            assert_eq!(check_transport(bad, Network::Testnet), Ok(()), "{bad}");
        }
        assert_eq!(
            check_transport("http://127.0.0.1:1", Network::Mainnet)
                .unwrap_err()
                .code(),
            "CLI_NODE_URL_INVALID"
        );
    }

    /// A node URL can carry a credential (user information, an API key in the path or query):
    /// no refusal echoes it.
    #[test]
    fn refusals_never_echo_a_credential_in_the_node_url() {
        assert_eq!(
            redact_url("wss://user:secret@node.example:443/key/abc?token=t#f"),
            "wss://***@node.example:443/..."
        );
        assert_eq!(redact_url("ws://127.0.0.1:17210"), "ws://127.0.0.1:17210");
        assert_eq!(redact_url("ws://[::1]:17110/"), "ws://[::1]:17110/...");
        let invalid = check_url("http://user:secret@node.example/?token=t").unwrap_err();
        let insecure = check_transport(
            "ws://user:secret@203.0.113.9:17110/?token=t",
            Network::Mainnet,
        )
        .unwrap_err();
        for e in [invalid, insecure] {
            let text = e.to_string();
            assert!(
                !text.contains("secret") && !text.contains("token"),
                "{text}"
            );
            assert!(text.contains("***@"), "{text}");
        }
    }

    /// A call that never answers is refused when the timeout runs out, not waited on for ever.
    #[test]
    fn a_call_that_never_answers_is_refused_at_the_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let never = std::future::pending::<Result<(), String>>();
        let started = std::time::Instant::now();
        let e = within(&rt, Duration::from_millis(50), "get_server_info", never).unwrap_err();
        assert_eq!(e.code(), "CLI_NODE_RPC");
        assert_eq!(e.detail(), "get_server_info: no answer in 50 ms");
        assert!(started.elapsed() < Duration::from_secs(5));
        let failed = within(&rt, CALL_TIMEOUT, "get_block", async {
            Err::<(), _>("refused\u{1b}[31m")
        })
        .unwrap_err();
        assert_eq!(failed.code(), "CLI_NODE_RPC");
        assert!(!failed.detail().contains('\u{1b}'), "{}", failed.detail());
        assert_eq!(
            within(&rt, CALL_TIMEOUT, "x", async { Ok::<_, String>(7) }),
            Ok(7)
        );
    }

    /// A submission whose answer never arrived names the transaction and how to look for it:
    /// the node may have taken it.
    #[test]
    fn a_failed_submission_names_the_transaction_to_look_for() {
        let mut node = FakeNode::testnet();
        node.submit_fails = true;
        let t = tx();
        let e = submit(&node, &t, Network::Testnet).unwrap_err();
        assert_eq!(e.code(), "CLI_NODE_RPC");
        let id = hex(&t.id().as_bytes());
        assert!(
            e.detail().contains(&format!(
                "impulse status --txid {id} --from-block {}",
                hex(&h(4))
            )),
            "{}",
            e.detail()
        );
        assert_eq!(node.submitted.borrow().len(), 1);
    }

    /// A node that takes the TCP connection and never answers the handshake is refused by the
    /// connect timeout, with the URL's credential not echoed.
    #[test]
    fn a_node_that_never_answers_the_handshake_is_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(20));
            drop(socket);
        });
        let started = std::time::Instant::now();
        let url = format!("ws://user:secret@127.0.0.1:{port}/?token=t");
        let err = WrpcNode::connect(&url, Network::Testnet)
            .err()
            .expect("the node never answers");
        assert_eq!(err.code(), "CLI_NODE_UNREACHABLE", "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(19),
            "{:?}",
            started.elapsed()
        );
        let text = err.to_string();
        assert!(
            !text.contains("secret") && !text.contains("token"),
            "{text}"
        );
        drop(hold);
    }

    /// The table `crates/impulse-watch` runs too: its copy of these two checks cannot drift
    /// from this one without one of the two tests failing.
    #[test]
    fn the_url_checks_agree_with_the_table_the_watcher_runs() {
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
                "insecure" => (Err("CLI_NODE_INSECURE"), Ok(())),
                "invalid" => (Err("CLI_NODE_URL_INVALID"), Err("CLI_NODE_URL_INVALID")),
                other => panic!("{other}"),
            };
            assert_eq!(mainnet, want_main, "mainnet {url}");
            assert_eq!(testnet, want_test, "testnet {url}");
            rows += 1;
        }
        assert!(rows > 25, "the table was read");
    }

    #[test]
    fn the_node_must_be_on_the_network_and_synced() {
        let mut node = FakeNode::testnet();
        assert!(check_node(&node, Network::Testnet).is_ok(), "control");
        assert_eq!(
            check_node(&node, Network::Mainnet).unwrap_err().code(),
            "CLI_NODE_NETWORK_MISMATCH"
        );
        node.info.network = None;
        node.info.network_name = "devnet".into();
        assert_eq!(
            check_node(&node, Network::Testnet).unwrap_err().code(),
            "CLI_NODE_NETWORK_MISMATCH"
        );
        let mut node = FakeNode::testnet();
        node.info.synced = false;
        assert_eq!(
            check_node(&node, Network::Testnet).unwrap_err().code(),
            "CLI_NODE_NOT_SYNCED"
        );
        assert_eq!(
            creation_daa(&node, Network::Testnet).unwrap_err().code(),
            "CLI_NODE_NOT_SYNCED"
        );
        node.info.synced = true;
        assert_eq!(creation_daa(&node, Network::Testnet), Ok(1_000));
    }

    fn tx() -> Transaction {
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    }

    #[test]
    fn submit_records_the_sink_and_checks_the_returned_id() {
        let node = FakeNode::testnet();
        let t = tx();
        let s = submit(&node, &t, Network::Testnet).unwrap();
        assert_eq!(s.txid, t.id().as_bytes());
        assert_eq!(s.from_block, h(4));
        assert_eq!(node.submitted.borrow().len(), 1);
        let mut lying = FakeNode::testnet();
        lying.submit_answer = Some(h(0x99));
        assert_eq!(
            submit(&lying, &t, Network::Testnet).unwrap_err().code(),
            "CLI_NODE_TXID_MISMATCH"
        );
        let node = FakeNode::testnet();
        assert_eq!(
            submit(&node, &t, Network::Mainnet).unwrap_err().code(),
            "CLI_NODE_NETWORK_MISMATCH"
        );
        assert!(
            node.submitted.borrow().is_empty(),
            "nothing sent to a wrong-network node"
        );
    }

    #[test]
    fn the_walk_finds_the_accepting_block() {
        let node = FakeNode::testnet();
        assert_eq!(find_acceptance(&node, h(0xaa), h(1)), Ok(h(3)));
        assert_eq!(find_acceptance(&node, h(0xbb), h(1)), Ok(h(2)));
        assert_eq!(
            find_acceptance(&node, h(0xbb), h(2)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED",
            "the start block's own acceptances are before the walk"
        );
        assert_eq!(
            find_acceptance(&node, h(0xdd), h(1)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED"
        );
    }

    #[test]
    fn a_removed_accepting_block_no_longer_counts() {
        let mut node = FakeNode::testnet();
        // From block 3 the chain reorganises: 3 is removed and 5 is added, accepting nothing.
        node.chain.insert(
            h(3),
            ChainUpdate {
                removed: vec![h(3)],
                added: vec![h(5)],
                accepted: vec![(h(5), vec![])],
            },
        );
        node.chain.insert(
            h(1),
            ChainUpdate {
                removed: vec![],
                added: vec![h(2), h(3)],
                accepted: vec![(h(2), vec![]), (h(3), vec![h(0xaa)])],
            },
        );
        node.chain.insert(h(5), ChainUpdate::default());
        assert_eq!(
            find_acceptance(&node, h(0xaa), h(1)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED"
        );
        // Re-accepted by 5 after the reorg: found again, in the new block.
        node.chain.insert(
            h(3),
            ChainUpdate {
                removed: vec![h(3)],
                added: vec![h(5)],
                accepted: vec![(h(5), vec![h(0xaa)])],
            },
        );
        assert_eq!(find_acceptance(&node, h(0xaa), h(1)), Ok(h(5)));
    }

    #[test]
    fn an_inconsistent_answer_is_refused() {
        let mut node = FakeNode::testnet();
        node.chain.insert(
            h(1),
            ChainUpdate {
                removed: vec![],
                added: vec![h(2)],
                accepted: vec![(h(7), vec![h(0xaa)])],
            },
        );
        assert_eq!(
            find_acceptance(&node, h(0xaa), h(1)).unwrap_err().code(),
            "CLI_NODE_RPC"
        );
    }

    #[test]
    fn the_walk_is_bounded() {
        let mut node = FakeNode::testnet();
        // A node that always adds the start block again never reaches a sink.
        node.chain.insert(
            h(1),
            ChainUpdate {
                removed: vec![],
                added: vec![h(1)],
                accepted: vec![],
            },
        );
        assert_eq!(
            find_acceptance(&node, h(0xaa), h(1)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED"
        );
        assert_eq!(*node.calls.borrow(), MAX_WALK_BATCHES);
    }

    #[test]
    fn observe_reports_depth_from_virtual_daa() {
        let node = FakeNode::testnet();
        let o = observe(&node, Network::Testnet, h(0x11), h(0xaa), h(1)).unwrap();
        assert_eq!(o.accepting_block, h(3));
        assert_eq!(o.daa_score, 903);
        assert_eq!(o.depth, 97);
        assert_eq!(
            observe(&node, Network::Mainnet, h(0x11), h(0xaa), h(1))
                .unwrap_err()
                .code(),
            "CLI_NODE_NETWORK_MISMATCH"
        );
        let mut left = FakeNode::testnet();
        left.blocks.get_mut(&h(3)).unwrap().is_chain_block = false;
        assert_eq!(
            observe(&left, Network::Testnet, h(0x11), h(0xaa), h(1))
                .unwrap_err()
                .code(),
            "CLI_TX_NOT_ACCEPTED"
        );
        let mut behind = FakeNode::testnet();
        behind.dag.virtual_daa = 900;
        assert_eq!(
            observe(&behind, Network::Testnet, h(0x11), h(0xaa), h(1))
                .unwrap_err()
                .code(),
            "CLI_NODE_RPC"
        );
    }

    fn receipt(node: &FakeNode) -> Receipt {
        let o = observe(node, Network::Testnet, h(0x11), h(0xaa), h(1)).unwrap();
        Receipt::sign(o, &key_file().path, false).unwrap()
    }

    #[test]
    fn a_receipt_re_verifies_against_the_node() {
        let node = FakeNode::testnet();
        let r = receipt(&node);
        assert_eq!(r.verify_signature(), Ok(()));
        assert_eq!(verify_receipt(&node, &r), Ok(()), "control");
        // Later, deeper: still valid.
        let mut later = FakeNode::testnet();
        later.dag.virtual_daa = 5_000;
        assert_eq!(verify_receipt(&later, &r), Ok(()));
    }

    /// The fake node with the chain from block 2 (block 3's selected parent) replaced.
    fn from_parent(update: ChainUpdate) -> FakeNode {
        let mut node = FakeNode::testnet();
        node.chain.insert(h(2), update);
        node
    }

    #[test]
    fn the_receipt_block_itself_must_accept_the_txid() {
        let r = receipt(&FakeNode::testnet());
        assert_eq!(r.observation.accepting_block, h(3));
        let control = from_parent(ChainUpdate {
            removed: vec![],
            added: vec![h(3), h(4)],
            accepted: vec![(h(3), vec![h(0xaa)]), (h(4), vec![])],
        });
        assert_eq!(verify_receipt(&control, &r), Ok(()), "control");
        // Block 4 accepts the txid, block 3 (which the receipt names) does not.
        let other_block = from_parent(ChainUpdate {
            removed: vec![],
            added: vec![h(3), h(4)],
            accepted: vec![(h(3), vec![]), (h(4), vec![h(0xaa)])],
        });
        assert_eq!(
            verify_receipt(&other_block, &r).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );
    }

    #[test]
    fn the_chain_from_the_parent_must_continue_with_the_block_and_remove_nothing() {
        let r = receipt(&FakeNode::testnet());
        // Removes a block, though it starts with the accepting block.
        let removes = from_parent(ChainUpdate {
            removed: vec![h(9)],
            added: vec![h(3), h(4)],
            accepted: vec![(h(3), vec![h(0xaa)]), (h(4), vec![])],
        });
        assert_eq!(
            verify_receipt(&removes, &r).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );
        // Removes nothing, but another block comes first.
        let other_first = from_parent(ChainUpdate {
            removed: vec![],
            added: vec![h(5), h(3)],
            accepted: vec![(h(5), vec![]), (h(3), vec![h(0xaa)])],
        });
        assert_eq!(
            verify_receipt(&other_first, &r).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );
    }

    #[test]
    fn receipt_refusals_have_their_codes() {
        let node = FakeNode::testnet();
        let r = receipt(&node);

        let mut wrong_net = r;
        wrong_net.observation.network = Network::Mainnet;
        assert_eq!(
            verify_receipt(&node, &wrong_net).unwrap_err().code(),
            "CLI_NODE_NETWORK_MISMATCH"
        );

        let mut off_chain = FakeNode::testnet();
        off_chain.blocks.get_mut(&h(3)).unwrap().is_chain_block = false;
        assert_eq!(
            verify_receipt(&off_chain, &r).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );

        let mut daa = r;
        daa.observation.daa_score += 1;
        assert_eq!(
            verify_receipt(&node, &daa).unwrap_err().code(),
            "RECEIPT_DAA_MISMATCH"
        );

        let mut other_tx = r;
        other_tx.observation.txid = h(0xdd);
        assert_eq!(
            verify_receipt(&node, &other_tx).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );

        let mut reorged = FakeNode::testnet();
        reorged.chain.insert(
            h(2),
            ChainUpdate {
                removed: vec![h(2)],
                added: vec![h(6)],
                accepted: vec![(h(6), vec![h(0xaa)])],
            },
        );
        assert_eq!(
            verify_receipt(&reorged, &r).unwrap_err().code(),
            "RECEIPT_NOT_ACCEPTED"
        );

        let mut deep = r;
        deep.observation.depth += 1;
        assert_eq!(
            verify_receipt(&node, &deep).unwrap_err().code(),
            "RECEIPT_DEPTH_UNREACHED"
        );

        let mut unknown = r;
        unknown.observation.accepting_block = h(0x77);
        assert_eq!(
            verify_receipt(&node, &unknown).unwrap_err().code(),
            "CLI_NODE_RPC"
        );
    }

    mod mapping {
        use super::*;
        use kaspa_consensus_core::header::Header;
        use kaspa_wrpc_client::prelude::{
            NetworkId, RpcAcceptedTransactionIds, RpcBlockVerboseData, RpcHeader,
        };

        fn hash(n: u8) -> RpcHash {
            RpcHash::from_bytes([n; 32])
        }

        fn server(network_id: NetworkId, is_synced: bool) -> GetServerInfoResponse {
            GetServerInfoResponse {
                rpc_api_version: 1,
                rpc_api_revision: 0,
                server_version: "test".into(),
                network_id,
                has_utxo_index: true,
                is_synced,
                virtual_daa_score: 7,
            }
        }

        #[test]
        fn every_network_type_maps_and_only_two_are_impulse_networks() {
            let cases = [
                (
                    NetworkId::new(NetworkType::Mainnet),
                    Some(Network::Mainnet),
                    "mainnet",
                ),
                (
                    NetworkId::with_suffix(NetworkType::Testnet, 10),
                    Some(Network::Testnet),
                    "testnet-10",
                ),
                (NetworkId::new(NetworkType::Devnet), None, "devnet"),
                (NetworkId::new(NetworkType::Simnet), None, "simnet"),
            ];
            for (id, network, name) in cases {
                let info = map_server_info(&server(id, true));
                assert_eq!(info.network, network, "{name}");
                assert_eq!(info.network_name, name);
                assert!(info.synced);
            }
            let unsynced = map_server_info(&server(NetworkId::new(NetworkType::Mainnet), false));
            assert!(!unsynced.synced);
        }

        #[test]
        fn dag_info_reads_the_sink_and_the_virtual_daa_score() {
            let info = GetBlockDagInfoResponse::new(
                NetworkId::new(NetworkType::Mainnet),
                11,
                12,
                vec![hash(1)],
                1.0,
                13,
                vec![hash(2)],
                hash(3),
                400_000_123,
                hash(4),
            );
            assert_eq!(
                map_dag_info(&info),
                DagInfo {
                    sink: [4; 32],
                    virtual_daa: 400_000_123
                }
            );
        }

        fn block(daa_score: u64, blue_score: u64, is_chain_block: bool) -> RpcBlock {
            let mut header = Header::from_precomputed_hash(hash(9), vec![hash(8)]);
            header.daa_score = daa_score;
            header.blue_score = blue_score;
            RpcBlock {
                header: RpcHeader::from(&header),
                transactions: vec![],
                verbose_data: Some(RpcBlockVerboseData {
                    hash: hash(9),
                    difficulty: 1.0,
                    selected_parent_hash: hash(8),
                    transaction_ids: vec![],
                    is_header_only: false,
                    blue_score,
                    children_hashes: vec![],
                    merge_set_blues_hashes: vec![],
                    merge_set_reds_hashes: vec![],
                    is_chain_block,
                }),
            }
        }

        #[test]
        fn a_block_maps_its_daa_score_parent_and_chain_flag() {
            assert_eq!(
                map_block(&block(903, 777, true)),
                Ok(BlockInfo {
                    daa_score: 903,
                    selected_parent: [8; 32],
                    is_chain_block: true
                })
            );
            assert!(!map_block(&block(903, 777, false)).unwrap().is_chain_block);
            let mut bare = block(903, 777, true);
            bare.verbose_data = None;
            assert_eq!(map_block(&bare).unwrap_err().code(), "CLI_NODE_RPC");
            let r = block_request([5; 32]);
            assert_eq!(r.hash, hash(5));
            assert!(!r.include_transactions);
        }

        #[test]
        fn the_chain_request_asks_for_accepted_ids() {
            let r = chain_request([6; 32]);
            assert_eq!(r.start_hash, hash(6));
            assert!(r.include_accepted_transaction_ids);
            assert_eq!(r.min_confirmation_count, None);
        }

        #[test]
        fn a_chain_update_keeps_removed_added_and_accepted() {
            let r = GetVirtualChainFromBlockResponse::new(
                vec![hash(1), hash(2)],
                vec![hash(3), hash(4)],
                vec![
                    RpcAcceptedTransactionIds {
                        accepting_block_hash: hash(3),
                        accepted_transaction_ids: vec![hash(0xaa), hash(0xbb)],
                    },
                    RpcAcceptedTransactionIds {
                        accepting_block_hash: hash(4),
                        accepted_transaction_ids: vec![],
                    },
                ],
            );
            assert_eq!(
                map_chain_update(r),
                ChainUpdate {
                    removed: vec![[1; 32], [2; 32]],
                    added: vec![[3; 32], [4; 32]],
                    accepted: vec![([3; 32], vec![[0xaa; 32], [0xbb; 32]]), ([4; 32], vec![])],
                }
            );
        }
    }

    #[test]
    fn an_unreachable_node_is_refused_offline() {
        // Bind then release a local port, so nothing listens on it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("ws://127.0.0.1:{port}");
        let started = std::time::Instant::now();
        for network in [Network::Testnet, Network::Mainnet] {
            let err = WrpcNode::connect(&url, network)
                .err()
                .expect("nothing listens");
            assert_eq!(err.code(), "CLI_NODE_UNREACHABLE", "{network:?}");
        }
        assert!(started.elapsed() < Duration::from_secs(60));
        assert_eq!(
            WrpcNode::connect("http://127.0.0.1:1", Network::Testnet)
                .err()
                .unwrap()
                .code(),
            "CLI_NODE_URL_INVALID"
        );
    }

    /// The client applies the mainnet transport rule itself: a plaintext link to another host
    /// is refused without any connection attempt (none could finish this fast to a TEST-NET-3
    /// address), whoever calls it.
    #[test]
    fn the_client_refuses_an_insecure_mainnet_link_itself() {
        let started = std::time::Instant::now();
        let err = WrpcNode::connect("ws://203.0.113.9:17110", Network::Mainnet)
            .err()
            .expect("refused");
        assert_eq!(err.code(), "CLI_NODE_INSECURE");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A fake node whose v2 walk from block 1 adds 2 and 3; block 3 accepts `tx`.
    fn v2_node(tx: &Transaction) -> FakeNode {
        let mut node = FakeNode::testnet();
        let accepted = AcceptedTx {
            tx: tx.clone(),
            spent: vec![],
        };
        node.accepted.insert(
            h(1),
            AcceptedUpdate {
                removed: vec![],
                added: vec![h(2), h(3)],
                accepted: vec![(h(2), vec![]), (h(3), vec![accepted])],
            },
        );
        node.accepted.insert(h(3), AcceptedUpdate::default());
        node
    }

    #[test]
    fn the_accepted_transaction_walk_finds_the_transaction_by_its_id() {
        let t = tx();
        let id = t.id().as_bytes();
        let node = v2_node(&t);
        let (block, found) = find_accepted_tx(&node, id, h(1)).unwrap();
        assert_eq!((block, &found.tx), (h(3), &t));
        assert_eq!(
            find_accepted_tx(&node, h(0xee), h(1)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED"
        );
        // Removed again later in the walk: no longer accepted.
        let mut removed = v2_node(&t);
        removed.accepted.insert(
            h(3),
            AcceptedUpdate {
                removed: vec![h(3)],
                added: vec![],
                accepted: vec![],
            },
        );
        assert_eq!(
            find_accepted_tx(&removed, id, h(1)).unwrap_err().code(),
            "CLI_TX_NOT_ACCEPTED"
        );
        // An acceptance in a block the answer does not add is refused. The walk could
        // otherwise go on from h(2) and end there, so only the check refuses it.
        let mut stray = v2_node(&t);
        stray.accepted.get_mut(&h(1)).unwrap().added = vec![h(2)];
        stray.accepted.insert(h(2), AcceptedUpdate::default());
        let e = find_accepted_tx(&stray, id, h(1)).unwrap_err();
        assert_eq!(e.code(), "CLI_NODE_RPC");
        assert!(
            e.to_string()
                .contains("acceptance names a block the answer does not add"),
            "{e}"
        );
        // Spent entries that do not match the inputs are refused.
        let mut one_input = tx();
        one_input
            .inputs
            .push(kaspa_consensus_core::tx::TransactionInput::new(
                Default::default(),
                vec![],
                0,
                0,
            ));
        one_input.finalize();
        let short = v2_node(&one_input);
        assert_eq!(
            find_accepted_tx(&short, one_input.id().as_bytes(), h(1))
                .unwrap_err()
                .code(),
            "CLI_NODE_RPC"
        );
    }

    #[test]
    fn fake_urls_exist_only_in_fake_node_builds() {
        let fake = "fake:///tmp/state";
        assert_eq!(check_url(fake).is_ok(), cfg!(feature = "offline-fake-node"));
        assert_eq!(
            check_transport(fake, Network::Mainnet).is_ok(),
            cfg!(feature = "offline-fake-node")
        );
        assert!(check_url("fake://").is_err(), "a path is required");
    }

    mod v2_mapping {
        use super::*;
        use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput, TransactionOutpoint};
        use kaspa_consensus_core::Hash;
        use kaspa_wrpc_client::prelude::{
            RpcChainBlockAcceptedTransactions, RpcOptionalHeader, RpcOptionalTransaction,
            RpcOptionalTransactionInputVerboseData, RpcOptionalUtxoEntry, RpcTransactionOutpoint,
            RpcUtxoEntry,
        };
        use std::sync::Arc;

        fn spending() -> (Transaction, UtxoEntry) {
            let input = TransactionInput::new(
                TransactionOutpoint::new(Hash::from_bytes([4; 32]), 1),
                vec![0x51],
                0,
                0,
            );
            let tx = Transaction::new(0, vec![input], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
            let entry = UtxoEntry::new(
                5,
                ScriptPublicKey::from_vec(0, vec![0xaa, 0x20]),
                77,
                false,
                Some(Hash::from_bytes([6; 32])),
            );
            (tx, entry)
        }

        fn response(
            tx: &Transaction,
            entry: Option<UtxoEntry>,
            hash: Option<Hash>,
        ) -> GetVirtualChainFromBlockV2Response {
            let mut rtx = RpcOptionalTransaction::from(tx);
            rtx.inputs[0].verbose_data = Some(RpcOptionalTransactionInputVerboseData {
                utxo_entry: entry.map(RpcOptionalUtxoEntry::from),
            });
            GetVirtualChainFromBlockV2Response {
                removed_chain_block_hashes: Arc::new(vec![Hash::from_bytes([1; 32])]),
                added_chain_block_hashes: Arc::new(vec![Hash::from_bytes([2; 32])]),
                chain_block_accepted_transactions: Arc::new(vec![
                    RpcChainBlockAcceptedTransactions {
                        chain_block_header: RpcOptionalHeader {
                            hash,
                            ..Default::default()
                        },
                        accepted_transactions: vec![rtx],
                    },
                ]),
            }
        }

        #[test]
        fn a_full_answer_maps_every_field() {
            let (tx, entry) = spending();
            let m = map_chain_update_v2(response(
                &tx,
                Some(entry.clone()),
                Some(Hash::from_bytes([2; 32])),
            ))
            .unwrap();
            assert_eq!(m.removed, vec![[1; 32]]);
            assert_eq!(m.added, vec![[2; 32]]);
            assert_eq!(m.accepted.len(), 1);
            let (block, txs) = &m.accepted[0];
            assert_eq!(*block, [2; 32]);
            assert_eq!(txs[0].tx, tx);
            assert_eq!(txs[0].tx.id(), tx.id());
            assert_eq!(txs[0].spent, vec![entry]);
        }

        #[test]
        fn a_missing_field_is_refused() {
            let (tx, entry) = spending();
            let no_entry =
                map_chain_update_v2(response(&tx, None, Some(Hash::from_bytes([2; 32]))));
            assert_eq!(no_entry.unwrap_err().code(), "CLI_NODE_RPC");
            let no_hash = map_chain_update_v2(response(&tx, Some(entry.clone()), None));
            assert_eq!(no_hash.unwrap_err().code(), "CLI_NODE_RPC");
            let mut partial = response(&tx, Some(entry), Some(Hash::from_bytes([2; 32])));
            Arc::make_mut(&mut partial.chain_block_accepted_transactions)[0]
                .accepted_transactions[0]
                .lock_time = None;
            assert_eq!(
                map_chain_update_v2(partial).unwrap_err().code(),
                "CLI_NODE_RPC"
            );
        }

        #[test]
        fn the_request_asks_for_full_verbosity() {
            let r = chain_v2_request([3; 32]);
            assert_eq!(r.start_hash, Hash::from_bytes([3; 32]));
            assert!(matches!(
                r.data_verbosity_level,
                Some(RpcDataVerbosityLevel::Full)
            ));
            assert_eq!(r.min_confirmation_count, None);
        }

        #[test]
        fn utxos_map_outpoint_and_entry() {
            let (_, entry) = spending();
            let e = RpcUtxosByAddressesEntry {
                address: None,
                outpoint: RpcTransactionOutpoint::from(TransactionOutpoint::new(
                    Hash::from_bytes([8; 32]),
                    3,
                )),
                utxo_entry: RpcUtxoEntry::new(
                    entry.amount,
                    entry.script_public_key.clone(),
                    entry.block_daa_score,
                    entry.is_coinbase,
                    entry.covenant_id,
                ),
            };
            let m = map_utxos(vec![e]);
            assert_eq!(
                m[0].outpoint,
                TransactionOutpoint::new(Hash::from_bytes([8; 32]), 3)
            );
            assert_eq!(m[0].entry, entry);
        }
    }
}
