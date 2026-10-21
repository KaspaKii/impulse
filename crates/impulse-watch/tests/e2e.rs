// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The `impulse-watch` binary, run as a process, against a fake wRPC node (I8 phase 2 exit test).
//!
//! The fake node is a workflow-rpc server speaking the node's own Borsh protocol on a loopback
//! port, with the node's real request and response types, so the binary's wRPC client, the v2
//! walk's wire form and its conversion are all exercised. The fake serves a block tree with a
//! movable sink (a reorg is a new sink), records every call it receives and every transaction
//! submitted to it, and can refuse a submission, fail a walk, or strip what the watcher needs
//! from the walk. Nothing leaves the machine and no test holds a key: vault spends carry
//! stand-in signature bytes, which the watcher never checks.

use impulse_core::decode::encode_raw;
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{Network, ValidatedTerms};
use impulse_watch::entry::SETTLE_TAG;
use impulse_watch::node::WrpcNode;
use impulse_watch::tracker::VirtualChainSource;
use impulse_watch::watcher::Refusal;
use impulse_watch::Broadcaster;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::EngineFlags;
use kaspa_wrpc_client::prelude::api::ops::RpcApiOps;
use kaspa_wrpc_client::prelude::*;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use workflow_rpc::server::prelude::*;
use workflow_serializer::prelude::*;

// ---- the fake node ----

struct Block {
    parent: Option<Hash>,
    daa: u64,
    accepted: Vec<RpcOptionalTransaction>,
}

struct Chain {
    blocks: HashMap<Hash, Block>,
    sink: Hash,
    pruning_point: Hash,
    network: NetworkId,
    synced: bool,
    version: String,
    /// Names of the calls received, in order.
    calls: Vec<&'static str>,
    /// Every transaction submitted, as the node would read it.
    submitted: Vec<Transaction>,
    /// Refusals handed to the next submissions, in order.
    refusals: VecDeque<String>,
    /// The next walks fail with this many errors.
    failing_walks: usize,
    /// The text of those errors.
    walk_error: String,
    /// Strip every input's spent UTXO entry from the walk.
    strip_spent_entries: bool,
    /// Fail the server-info call.
    failing_server_info: bool,
    /// A request that is not what the watcher is specified to send.
    violations: Vec<String>,
    /// Each walk adds at most this many chain blocks: the node's added-block batch limit.
    added_limit: Option<usize>,
    /// Walks answer with nothing added and nothing removed.
    empty_walks: bool,
    /// Block hashes every walk names as removed, on top of the real ones.
    forced_removed: Vec<Hash>,
    /// The next walks return the last one served, verbatim, whatever they were asked.
    replay_walks: usize,
    last_walk: Option<GetVirtualChainFromBlockV2Response>,
    /// Calls that are received and never answered.
    hangs: Vec<&'static str>,
    /// The next submissions are answered with another transaction's ID.
    wrong_id_answers: usize,
    /// Every walk first adds an empty block to the sink chain, a node that never stops.
    growing: bool,
    next_auto_block: u64,
    /// `get_block_dag_info` reports a virtual DAA score this far under the sink's own: a node
    /// whose chain blocks are above its virtual.
    virtual_daa_deficit: u64,
}

type Shared = Arc<Mutex<Chain>>;

fn h(n: u64) -> Hash {
    Hash::from_u64_word(0xe2e0_0000 + n)
}

/// A coinbase-shaped transaction (no inputs), as every accepting chain block carries.
fn coinbase(n: u64) -> RpcOptionalTransaction {
    let tx = Transaction::new(
        0,
        vec![],
        vec![TransactionOutput::new(500, miner())],
        0,
        SUBNETWORK_ID_COINBASE,
        0,
        n.to_le_bytes().to_vec(),
    );
    rpc_tx(&tx, &[])
}

fn miner() -> ScriptPublicKey {
    let mut script = vec![0x20];
    script.extend_from_slice(&[0x66; 32]);
    script.push(0xac);
    ScriptPublicKey::new(0, script.into())
}

impl Chain {
    fn new() -> Self {
        let mut blocks = HashMap::new();
        blocks.insert(
            h(0),
            Block {
                parent: None,
                daa: 99,
                accepted: vec![],
            },
        );
        Self {
            blocks,
            sink: h(0),
            pruning_point: h(0),
            network: NetworkId::new(NetworkType::Mainnet),
            synced: true,
            version: "2.1.0".into(),
            calls: vec![],
            submitted: vec![],
            refusals: VecDeque::new(),
            failing_walks: 0,
            walk_error: "walk refused by the fake node".into(),
            strip_spent_entries: false,
            failing_server_info: false,
            violations: vec![],
            added_limit: None,
            empty_walks: false,
            forced_removed: vec![],
            replay_walks: 0,
            last_walk: None,
            hangs: vec![],
            wrong_id_answers: 0,
            growing: false,
            next_auto_block: 1_000,
            virtual_daa_deficit: 0,
        }
    }

    /// A block under `parent`, not yet the sink.
    fn add(&mut self, n: u64, parent: u64, daa: u64, mut accepted: Vec<RpcOptionalTransaction>) {
        accepted.insert(0, coinbase(n));
        assert!(self.blocks.contains_key(&h(parent)));
        self.blocks.insert(
            h(n),
            Block {
                parent: Some(h(parent)),
                daa,
                accepted,
            },
        );
    }

    /// A block on the sink, made the sink.
    fn extend(&mut self, n: u64, daa: u64, accepted: Vec<RpcOptionalTransaction>) {
        let parent = (0..=n)
            .find(|p| h(*p) == self.sink)
            .expect("the sink is a numbered block");
        self.add(n, parent, daa, accepted);
        self.sink = h(n);
    }

    fn set_sink(&mut self, n: u64) {
        assert!(self.blocks.contains_key(&h(n)));
        self.sink = h(n);
    }

    fn walk(&self, start: Hash) -> Result<(Vec<Hash>, Vec<Hash>), String> {
        if !self.blocks.contains_key(&start) {
            return Err(format!("unknown block {start}"));
        }
        let mut on_chain = std::collections::HashSet::new();
        let mut b = Some(self.sink);
        while let Some(x) = b {
            on_chain.insert(x);
            b = self.blocks[&x].parent;
        }
        let (mut removed, mut common) = (vec![], start);
        while !on_chain.contains(&common) {
            removed.push(common);
            common = self.blocks[&common].parent.ok_or("no common ancestor")?;
        }
        let mut added = vec![];
        let mut b = self.sink;
        while b != common {
            added.push(b);
            b = self.blocks[&b].parent.ok_or("no common ancestor")?;
        }
        added.reverse();
        Ok((removed, added))
    }

    fn header(&self, hash: Hash) -> RpcHeader {
        let block = &self.blocks[&hash];
        let mut header =
            Header::from_precomputed_hash(hash, block.parent.into_iter().collect::<Vec<_>>());
        header.daa_score = block.daa;
        RpcHeader::from(&header)
    }
}

#[derive(Clone)]
struct Conn;

struct Handler;

#[async_trait::async_trait]
impl RpcHandler for Handler {
    type Context = Conn;

    async fn handshake(
        self: Arc<Self>,
        _peer: &SocketAddr,
        _sender: &mut WebSocketSender,
        _receiver: &mut WebSocketReceiver,
        _messenger: Arc<Messenger>,
    ) -> WebSocketResult<Conn> {
        Ok(Conn)
    }
}

fn text(e: impl std::fmt::Display) -> ServerError {
    ServerError::Text(e.to_string())
}

/// Records the call and, if the node is set to hang on it, never returns.
async fn enter(shared: &Shared, name: &'static str) {
    let hang = {
        let mut c = shared.lock().unwrap();
        c.calls.push(name);
        c.hangs.contains(&name)
    };
    if hang {
        std::future::pending::<()>().await;
    }
}

fn interface(shared: Shared) -> Interface<Shared, Conn, RpcApiOps> {
    let mut i = Interface::<Shared, Conn, RpcApiOps>::new(shared);
    i.method(
        RpcApiOps::GetServerInfo,
        method!(
            |c: Shared, _conn: Conn, _req: Serializable<GetServerInfoRequest>| async move {
                enter(&c, "get_server_info").await;
                let c = c.lock().unwrap();
                if c.failing_server_info {
                    return Err(text("server info unavailable"));
                }
                Ok(Serializable(GetServerInfoResponse {
                    rpc_api_version: 1,
                    rpc_api_revision: 0,
                    server_version: c.version.clone(),
                    network_id: c.network,
                    has_utxo_index: false,
                    is_synced: c.synced,
                    virtual_daa_score: c.blocks[&c.sink].daa,
                }))
            }
        ),
    );
    i.method(
        RpcApiOps::GetBlockDagInfo,
        method!(
            |c: Shared, _conn: Conn, _req: Serializable<GetBlockDagInfoRequest>| async move {
                enter(&c, "get_block_dag_info").await;
                let c = c.lock().unwrap();
                Ok(Serializable(GetBlockDagInfoResponse::new(
                    c.network,
                    0,
                    0,
                    vec![c.sink],
                    0.0,
                    0,
                    vec![c.sink],
                    c.pruning_point,
                    c.blocks[&c.sink].daa.saturating_sub(c.virtual_daa_deficit),
                    c.sink,
                )))
            }
        ),
    );
    i.method(
        RpcApiOps::GetBlock,
        method!(
            |c: Shared, _conn: Conn, req: Serializable<GetBlockRequest>| async move {
                enter(&c, "get_block").await;
                let mut c = c.lock().unwrap();
                let req = req.into_inner();
                if req.include_transactions {
                    c.violations.push("get_block asked for transactions".into());
                }
                let Some(block) = c.blocks.get(&req.hash) else {
                    return Err(text(format!("unknown block {}", req.hash)));
                };
                let parent = block.parent.ok_or_else(|| text("no selected parent"))?;
                Ok(Serializable(GetBlockResponse {
                    block: RpcBlock {
                        header: c.header(req.hash),
                        transactions: vec![],
                        verbose_data: Some(RpcBlockVerboseData {
                            hash: req.hash,
                            difficulty: 0.0,
                            selected_parent_hash: parent,
                            transaction_ids: vec![],
                            is_header_only: true,
                            blue_score: 0,
                            children_hashes: vec![],
                            merge_set_blues_hashes: vec![],
                            merge_set_reds_hashes: vec![],
                            is_chain_block: true,
                        }),
                    },
                }))
            }
        ),
    );
    i.method(
        RpcApiOps::GetVirtualChainFromBlockV2,
        method!(|c: Shared, _conn: Conn, req: Serializable<GetVirtualChainFromBlockV2Request>| async move {
            enter(&c, "get_virtual_chain_from_block_v2").await;
            let mut c = c.lock().unwrap();
            let req = req.into_inner();
            if !matches!(req.data_verbosity_level, Some(RpcDataVerbosityLevel::Full)) {
                c.violations.push("the walk was not asked for Full verbosity".into());
            }
            if req.min_confirmation_count.is_some() {
                c.violations.push("the walk was asked for a confirmation count".into());
            }
            if c.failing_walks > 0 {
                c.failing_walks -= 1;
                return Err(text(c.walk_error.clone()));
            }
            if c.replay_walks > 0 {
                c.replay_walks -= 1;
                if let Some(last) = c.last_walk.clone() {
                    return Ok(Serializable(last));
                }
            }
            if c.empty_walks {
                return Ok(Serializable(GetVirtualChainFromBlockV2Response {
                    removed_chain_block_hashes: Arc::new(vec![]),
                    added_chain_block_hashes: Arc::new(vec![]),
                    chain_block_accepted_transactions: Arc::new(vec![]),
                }));
            }
            if c.growing {
                let n = c.next_auto_block;
                c.next_auto_block += 1;
                let daa = c.blocks[&c.sink].daa + 1;
                let sink = c.sink;
                c.blocks.insert(h(n), Block { parent: Some(sink), daa, accepted: vec![coinbase(n)] });
                c.sink = h(n);
            }
            let (mut removed, mut added) = c.walk(req.start_hash).map_err(text)?;
            removed.extend(c.forced_removed.iter().copied());
            if let Some(limit) = c.added_limit {
                added.truncate(limit);
            }
            let batches = added
                .iter()
                .map(|hash| {
                    let block = &c.blocks[hash];
                    let mut txs = block.accepted.clone();
                    if c.strip_spent_entries {
                        for t in &mut txs {
                            for input in &mut t.inputs {
                                input.verbose_data = None;
                            }
                        }
                    }
                    RpcChainBlockAcceptedTransactions {
                        chain_block_header: RpcOptionalHeader {
                            hash: Some(*hash),
                            daa_score: Some(block.daa),
                            ..Default::default()
                        },
                        accepted_transactions: txs,
                    }
                })
                .collect();
            let response = GetVirtualChainFromBlockV2Response {
                removed_chain_block_hashes: Arc::new(removed),
                added_chain_block_hashes: Arc::new(added),
                chain_block_accepted_transactions: Arc::new(batches),
            };
            c.last_walk = Some(response.clone());
            Ok(Serializable(response))
        }),
    );
    i.method(
        RpcApiOps::SubmitTransaction,
        method!(
            |c: Shared, _conn: Conn, req: Serializable<SubmitTransactionRequest>| async move {
                enter(&c, "submit_transaction").await;
                let mut c = c.lock().unwrap();
                let req = req.into_inner();
                if req.allow_orphan {
                    c.violations.push("a rebroadcast allowed orphans".into());
                }
                let tx = Transaction::try_from(req.transaction).map_err(text)?;
                c.submitted.push(tx.clone());
                if let Some(reason) = c.refusals.pop_front() {
                    return Err(text(reason));
                }
                if c.wrong_id_answers > 0 {
                    c.wrong_id_answers -= 1;
                    return Ok(Serializable(SubmitTransactionResponse::new(
                        Hash::from_u64_word(0xbad),
                    )));
                }
                Ok(Serializable(SubmitTransactionResponse::new(tx.id())))
            }
        ),
    );
    i
}

/// A TCP forwarder between the watcher and the fake node, which can cut every link and refuse
/// new ones for a while (a node that restarts, or a network that drops), or silence every link
/// that exists while keeping it open at both ends and taking new ones (a half-open link: a
/// firewall that forgets a connection, a peer that vanished without a reset).
struct Proxy {
    links: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    refusing: Arc<AtomicBool>,
    /// A link made at one value forwards until this moves on, and then swallows everything.
    epoch: Arc<AtomicU64>,
}

impl Proxy {
    async fn start(upstream: std::net::SocketAddr) -> (Self, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let links: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let refusing = Arc::new(AtomicBool::new(false));
        let epoch = Arc::new(AtomicU64::new(0));
        let (l, r, e) = (links.clone(), refusing.clone(), epoch.clone());
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                if r.load(Ordering::SeqCst) {
                    continue; // dropped: the connection closes at once
                }
                let (mine, epoch) = (e.load(Ordering::SeqCst), e.clone());
                let handle = tokio::spawn(async move {
                    if let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await {
                        let silenced = async {
                            while epoch.load(Ordering::SeqCst) == mine {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        };
                        tokio::select! {
                            _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                            _ = silenced => {
                                // Forwards nothing and closes nothing: both ends still hold a
                                // socket that looks open.
                                std::future::pending::<()>().await;
                            }
                        }
                    }
                });
                l.lock().unwrap().push(handle);
            }
        });
        (
            Self {
                links,
                refusing,
                epoch,
            },
            addr,
        )
    }

    /// Closes every open link, and refuses new ones until [`Self::accept_again`].
    fn cut(&self) {
        self.refusing.store(true, Ordering::SeqCst);
        for link in self.links.lock().unwrap().drain(..) {
            link.abort();
        }
    }

    fn accept_again(&self) {
        self.refusing.store(false, Ordering::SeqCst);
    }

    /// Every link that exists now stops forwarding, either way, and stays open; links made
    /// after this forward as usual.
    fn blackhole(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeNode {
    url: String,
    chain: Shared,
    proxy: Option<Proxy>,
}

impl FakeNode {
    async fn start() -> Self {
        Self::start_with(Chain::new()).await
    }

    async fn start_with(chain: Chain) -> Self {
        Self::start_inner(chain, false).await
    }

    /// The watcher reaches the node through a [`Proxy`] that can cut the link.
    async fn start_proxied() -> Self {
        Self::start_inner(Chain::new(), true).await
    }

    async fn start_inner(chain: Chain, proxied: bool) -> Self {
        let chain: Shared = Arc::new(Mutex::new(chain));
        let server = RpcServer::new_with_encoding::<Shared, Conn, RpcApiOps, Id64>(
            Encoding::Borsh,
            Arc::new(Handler),
            Arc::new(interface(chain.clone())),
            None,
            false,
        );
        let listener = server.bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.listen(listener, None).await;
        });
        let (proxy, url) = if proxied {
            let (proxy, front) = Proxy::start(addr).await;
            (Some(proxy), format!("ws://{front}"))
        } else {
            (None, format!("ws://{addr}"))
        };
        Self { url, chain, proxy }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        f(&mut self.chain.lock().unwrap())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.with(|c| c.calls.clone())
    }

    fn walks(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| **c == "get_virtual_chain_from_block_v2")
            .count()
    }

    fn submitted(&self) -> Vec<Transaction> {
        self.with(|c| c.submitted.clone())
    }
}

// ---- transactions on the wire ----

fn rpc_tx(tx: &Transaction, spent: &[UtxoEntry]) -> RpcOptionalTransaction {
    RpcOptionalTransaction {
        version: Some(tx.version),
        inputs: tx
            .inputs
            .iter()
            .zip(spent)
            .map(|(i, e)| RpcOptionalTransactionInput {
                previous_outpoint: Some(RpcOptionalTransactionOutpoint {
                    transaction_id: Some(i.previous_outpoint.transaction_id),
                    index: Some(i.previous_outpoint.index),
                }),
                signature_script: Some(i.signature_script.clone()),
                sequence: Some(i.sequence),
                sig_op_count: i.compute_commit.sig_op_count(),
                compute_budget: i.compute_commit.compute_budget(),
                verbose_data: Some(RpcOptionalTransactionInputVerboseData {
                    utxo_entry: Some(RpcOptionalUtxoEntry::from(e.clone())),
                }),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| RpcOptionalTransactionOutput {
                value: Some(o.value),
                script_public_key: Some(o.script_public_key.clone()),
                verbose_data: None,
                covenant: Some(RpcNullableCovenantBinding(o.covenant.map(Into::into))),
            })
            .collect(),
        lock_time: Some(tx.lock_time),
        subnetwork_id: Some(tx.subnetwork_id),
        gas: Some(tx.gas),
        payload: Some(tx.payload.clone()),
        storage_mass: Some(tx.storage_mass()),
        verbose_data: Some(RpcOptionalTransactionVerboseData {
            transaction_id: Some(tx.id()),
            hash: None,
            compute_mass: None,
            block_hash: None,
            block_time: None,
        }),
    }
}

// ---- the trade: golden vector 2, a KCC-20 asset against KAS cash ----

const VECTOR: &str =
    include_str!("../../../tests/vectors/terms/02-vault-authority-revocable-kcc20-kas.json");
const AUTH: u64 = 100_000;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn terms() -> ValidatedTerms {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    ValidatedTerms::decode(&unhex(v["canonical"].as_str().unwrap())).unwrap()
}

fn trade_hash() -> String {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    v["terms_hash"].as_str().unwrap().to_string()
}

fn stranger() -> ScriptPublicKey {
    let mut script = vec![0x20];
    script.extend_from_slice(&[0x77; 32]);
    script.push(0xac);
    ScriptPublicKey::new(0, script.into())
}

/// A stand-in signature: not a signature, not derived from any key.
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

struct Trade {
    funding: (Transaction, Vec<UtxoEntry>),
    settle: (Transaction, Vec<UtxoEntry>),
}

fn input(salt: u64, index: u32, sig: Vec<u8>) -> TransactionInput {
    TransactionInput::new(
        TransactionOutpoint::new(Hash::from_u64_word(salt), index),
        sig,
        0,
        1,
    )
}

fn trade() -> Trade {
    let t = terms();
    let cash_amount = t.terms().cash_leg.amount;
    let asset = Vault::instantiate_existing(&t, LegIndex::Asset).unwrap();
    let cash = Vault::instantiate_existing(&t, LegIndex::Cash).unwrap();
    let entry = |value: u64, spk: ScriptPublicKey| UtxoEntry::new(value, spk, 0, false, None);
    let funding = Transaction::new(
        0,
        vec![input(1, 0, push_all(&[&SIG]))],
        vec![
            TransactionOutput::new(AUTH, asset.script_public_key()),
            TransactionOutput::new(cash_amount, cash.script_public_key()),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let call = |v: &Vault| push_all(&[&SIG, &SETTLE_TAG, v.redeem_script()]);
    let settle = Transaction::new(
        0,
        vec![
            input(2, 0, call(&asset)),
            input(2, 1, call(&cash)),
            input(2, 2, push_all(&[&SIG])),
            input(2, 3, push_all(&[&SIG])),
        ],
        vec![
            TransactionOutput::new(1_000, stranger()),
            TransactionOutput::new(cash_amount, stranger()),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    Trade {
        funding: (funding, vec![entry(10_000, stranger())]),
        settle: (
            settle,
            vec![
                entry(AUTH, asset.script_public_key()),
                entry(cash_amount, cash.script_public_key()),
                entry(10_000, stranger()),
                entry(10_000, stranger()),
            ],
        ),
    }
}

fn wire(t: &(Transaction, Vec<UtxoEntry>)) -> RpcOptionalTransaction {
    rpc_tx(&t.0, &t.1)
}

// ---- running the binary ----

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "impulse-watch-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    dir: TempDir,
    terms: PathBuf,
    settle: PathBuf,
    state: PathBuf,
    trade: Trade,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new();
        let v: Value = serde_json::from_str(VECTOR).unwrap();
        let terms = dir.file("trade.json");
        std::fs::write(
            &terms,
            json!({"terms": v["terms"], "canonical": v["canonical"], "terms_hash": v["terms_hash"]})
                .to_string(),
        )
        .unwrap();
        let trade = trade();
        let settle = dir.file("settle.hex");
        std::fs::write(&settle, format!("{}\n", hex(&encode_raw(&trade.settle.0)))).unwrap();
        let state = dir.file("state.json");
        Self {
            dir,
            terms,
            settle,
            state,
            trade,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn events(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
            .collect()
    }

    fn kinds(&self) -> Vec<String> {
        self.events()
            .iter()
            .map(|e| {
                let kind = e["event"].as_str().unwrap();
                match e.get("of") {
                    Some(of) => format!("{kind} {}", of.as_str().unwrap()),
                    None => kind.to_string(),
                }
            })
            .collect()
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_impulse-watch")
}

/// How long a process that must end on its own may take before the test kills it and fails: a
/// refusal that hangs is a defect, not a slow test.
const LIMIT: Duration = Duration::from_secs(90);

async fn exec(args: Vec<String>) -> Run {
    exec_within(args, LIMIT).await
}

async fn exec_within(args: Vec<String>, limit: Duration) -> Run {
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(bin())
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let read = |pipe: Option<Box<dyn std::io::Read + Send>>| {
            std::thread::spawn(move || {
                let mut text = String::new();
                if let Some(mut p) = pipe {
                    let _ = p.read_to_string(&mut text);
                }
                text
            })
        };
        let out = read(child.stdout.take().map(|p| Box::new(p) as _));
        let err = read(child.stderr.take().map(|p| Box::new(p) as _));
        let deadline = Instant::now() + limit;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "impulse-watch {args:?} did not end in {limit:?}: it hangs where it must end"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Run {
            code: status.code().unwrap_or(-1),
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    })
    .await
    .unwrap()
}

use std::io::Read;

/// A watcher left running, its output read as it comes. Killed when dropped.
type Lines = Arc<Mutex<Vec<String>>>;

struct Live {
    child: Child,
    out: Lines,
    err: Lines,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Live {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (out, err) = (Lines::default(), Lines::default());
        let mut readers = vec![];
        for (pipe, sink) in [
            (
                Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
                out.clone(),
            ),
            (Box::new(child.stderr.take().unwrap()), err.clone()),
        ] {
            readers.push(std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    sink.lock().unwrap().push(line);
                }
            }));
        }
        Self {
            child,
            out,
            err,
            readers,
        }
    }

    fn out(&self) -> Vec<Value> {
        self.out
            .lock()
            .unwrap()
            .iter()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
            .collect()
    }

    fn err(&self) -> Vec<String> {
        self.err.lock().unwrap().clone()
    }

    /// Waits for `cond`, up to 60 seconds, and fails with what the process had printed.
    async fn wait_until(&self, what: &str, cond: impl Fn(&Live) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !cond(self) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}\nstdout: {:?}\nstderr: {:?}",
                self.out.lock().unwrap(),
                self.err()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Kills the process (SIGKILL) and returns what it had printed.
    fn kill(mut self) -> (Vec<Value>, Vec<String>) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for r in self.readers.drain(..) {
            let _ = r.join();
        }
        (self.out(), self.err())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn path(p: &Path) -> String {
    p.display().to_string()
}

/// `impulse-watch run` on mainnet with these extra arguments.
async fn run(node: &FakeNode, f: &Fixture, depth: u64, extra: &[&str]) -> Run {
    let mut args: Vec<String> = [
        "run",
        "--network",
        "mainnet",
        "--node",
        &node.url,
        "--finality-depth",
        &depth.to_string(),
        "--state",
        &path(&f.state),
        "--trade",
        &path(&f.terms),
        "--keep-signed",
        &path(&f.settle),
        "--poll-interval-ms",
        "20",
    ]
    .map(String::from)
    .to_vec();
    if !extra.contains(&"--max-polls") {
        args.extend(["--max-polls".to_string(), "1".to_string()]);
    }
    args.extend(extra.iter().map(|a| a.to_string()));
    exec(args).await
}

fn assert_ok(r: &Run) {
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stderr.is_empty(), "stderr: {}", r.stderr);
}

fn assert_refused(r: &Run, code: &str) {
    assert_eq!(r.code, 1, "stdout: {} stderr: {}", r.stdout, r.stderr);
    assert!(
        r.stderr.starts_with(&format!("impulse-watch: {code}")),
        "expected {code}, stderr: {}",
        r.stderr
    );
    assert!(r.stdout.is_empty(), "stdout: {}", r.stdout);
}

/// What a consumer de-duplicates on (spec/WATCH.md, "Rounds"): the round, and everything that
/// names what happened, nothing that measures it (depth, reason, the node's text).
fn dedup_key(e: &Value) -> String {
    dedup_key_with(e, true)
}

/// The key of review round 4, without the round: it repeats across episodes.
fn dedup_key_with(e: &Value, with_round: bool) -> String {
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

/// The keys of the events of a run, a round or several: every one different (the second leg of
/// a settle is not the first's duplicate, and an acceptance after a reorg is not the first's).
fn keys_of(events: &[Value]) -> Vec<String> {
    let keys: Vec<String> = events.iter().map(dedup_key).collect();
    let mut unique = keys.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), keys.len(), "two events share a key: {keys:?}");
    keys
}

fn state_of(f: &Fixture) -> Value {
    serde_json::from_str(&std::fs::read_to_string(&f.state).unwrap()).unwrap()
}

/// A chain of two blocks (0 at DAA 99, 1 at DAA 100, the sink), and the fixture.
async fn started() -> (FakeNode, Fixture) {
    let node = FakeNode::start().await;
    node.with(|c| c.extend(1, 100, vec![]));
    (node, Fixture::new())
}

// ---- the exit test: reorg, rebroadcast, restart ----

#[tokio::test(flavor = "multi_thread")]
async fn exit_a_settle_reorged_out_is_rebroadcast_and_the_state_survives_every_restart() {
    let (node, f) = started().await;
    let trade_id = trade_hash();
    let funding_id = f.trade.funding.0.id().to_string();
    let settle_id = f.trade.settle.0.id().to_string();
    let cash_amount = terms().terms().cash_leg.amount;
    // Every event of every run that is not a replay, to show at the end that no two share a key.
    let mut every: Vec<Value> = vec![];

    // Run A (--init): the first poll bootstraps one block behind the sink; nothing to report.
    let a = run(&node, &f, 5, &["--init"]).await;
    assert_ok(&a);
    assert!(a.stdout.is_empty());
    assert_eq!(
        node.calls(),
        [
            "get_server_info",
            "get_block_dag_info",
            "get_block",
            "get_virtual_chain_from_block_v2",
            // The walk added a chain block, so the node's virtual DAA score is read to compare.
            "get_block_dag_info"
        ]
    );
    assert!(f.state.exists());

    // Run B: the funding and the kept settle are accepted. The settle's accepted copy is what
    // the watcher keeps; its two vault spends are reported per leg.
    node.with(|c| {
        c.extend(2, 101, vec![wire(&f.trade.funding)]);
        c.extend(3, 102, vec![wire(&f.trade.settle)]);
    });
    let state_a = std::fs::read_to_string(&f.state).unwrap();
    let b = run(&node, &f, 5, &[]).await;
    assert_ok(&b);
    assert_eq!(
        b.kinds(),
        ["authorizer_seen", "funded", "settled", "settled"]
    );
    let events = b.events();
    every.extend(events.clone());
    // The two legs of one settle are two events with different keys, and a crash between the
    // events and the state write repeats the round with the same keys.
    let keys_b = keys_of(&events);
    std::fs::write(&f.state, &state_a).unwrap();
    let b_again = run(&node, &f, 5, &[]).await;
    assert_ok(&b_again);
    assert_eq!(keys_of(&b_again.events()), keys_b);
    assert_eq!(
        events[1],
        json!({
            "round": "1",
            "event": "funded",
            "trade": trade_id,
            "leg": "cash",
            "output": 1,
            "value": cash_amount.to_string(),
            "exact": true,
            "txid": funding_id,
            "accepting_block": h(2).to_string(),
            "accepting_daa": "101",
            "depth": "1"
        })
    );
    assert_eq!(events[2]["leg"], "asset");
    assert_eq!(events[3]["leg"], "cash");
    assert_eq!(events[3]["txid"], json!(settle_id));
    assert_eq!(events[3]["depth"], "0");

    // Run C: depth 5 passes while the watcher is down; the finals are reported on this start.
    node.with(|c| c.extend(4, 108, vec![]));
    let state_b = std::fs::read_to_string(&f.state).unwrap();
    let c = run(&node, &f, 5, &[]).await;
    assert_ok(&c);
    assert_eq!(
        c.kinds(),
        [
            "final authorizer_seen",
            "final funded",
            "final settled",
            "final settled"
        ]
    );
    let keys_c = keys_of(&c.events());
    assert!(c.events().iter().all(|e| e["round"] == "2"));
    every.extend(c.events());
    std::fs::write(&f.state, &state_b).unwrap();
    let c_again = run(&node, &f, 5, &[]).await;
    assert_ok(&c_again);
    assert_eq!(keys_of(&c_again.events()), keys_c);
    // Run D: reported once.
    let d = run(&node, &f, 5, &[]).await;
    assert_ok(&d);
    assert!(d.stdout.is_empty(), "{}", d.stdout);

    // A reorg deeper than N takes the settle out; the node refuses the first rebroadcast.
    node.with(|c| {
        c.add(14, 2, 109, vec![]);
        c.set_sink(14);
        c.refusals.push_back("mempool full".into());
    });
    let e = run(&node, &f, 5, &[]).await;
    assert_ok(&e);
    assert_eq!(e.kinds(), ["reorg settled", "reorg settled", "rebroadcast"]);
    let events = e.events();
    keys_of(&events);
    assert!(
        events.iter().all(|e| e["round"] == "3"),
        "run D reported nothing"
    );
    every.extend(events.clone());
    assert_eq!(events[0]["was_final"], true);
    assert_eq!(events[0]["code"], "WATCH_FINAL_REORGED");
    assert_eq!(events[2]["outcome"], "refused");
    assert_eq!(events[2]["attempt"], 1);
    assert_eq!(events[2]["code"], "WATCH_REBROADCAST_FAILED");
    assert!(events[2]["reason"]
        .as_str()
        .unwrap()
        .contains("mempool full"));
    assert_eq!(node.submitted().len(), 1);

    // The state file after the refused rebroadcast, whole: the funding stays accepted and
    // final, the settle is pending with one attempt made and its next turn not yet come.
    let trade_id_hex = trade_hash();
    let cash = terms().terms().cash_leg.amount;
    let expiry = terms().terms().expiry_daa;
    assert_eq!(
        state_of(&f),
        json!({
            "format": "impulse-watch-state",
            "version": 1,
            "network": "mainnet",
            "trades": [{"trade": trade_id_hex, "from": null}],
            "cursor": {"block": h(14).to_string(), "daa": "109"},
            "accepted": [{
                "txid": funding_id,
                "block": h(2).to_string(),
                "daa": "101",
                "finalized": true,
                "settle_expiry": null,
                "tx": null,
                "effects": [
                    {"kind": "authorizer_seen", "trade": trade_id_hex, "leg": "asset",
                     "index": 0, "value": AUTH.to_string(), "covenant_output": false},
                    {"kind": "funded", "trade": trade_id_hex, "leg": "cash",
                     "index": 1, "value": cash.to_string(), "exact": true}
                ]
            }],
            "kept": [settle_id],
            "pending": [{
                "txid": settle_id,
                "tx": hex(&encode_raw(&f.trade.settle.0)),
                "settle_expiry": expiry.to_string(),
                "attempts": 1,
                "due": false
            }],
            "round": "3"
        })
    );

    // Run F, a restart: the pending rebroadcast was in the state file and is taken now.
    let fr = run(&node, &f, 5, &[]).await;
    assert_ok(&fr);
    assert_eq!(fr.kinds(), ["rebroadcast"]);
    assert_eq!(fr.events()[0]["outcome"], "submitted");
    assert_eq!(fr.events()[0]["attempt"], 2);
    assert_eq!(fr.events()[0]["round"], "4");
    every.extend(fr.events());
    // What the node was handed, twice, is the settle exactly as it had accepted it.
    assert_eq!(
        node.submitted(),
        vec![f.trade.settle.0.clone(), f.trade.settle.0.clone()]
    );
    // Run G: not submitted a third time.
    let g = run(&node, &f, 5, &[]).await;
    assert_ok(&g);
    assert!(g.stdout.is_empty());
    assert_eq!(node.submitted().len(), 2);

    // The rebroadcast settle is accepted again, and reaches depth 5.
    node.with(|c| c.extend(15, 110, vec![wire(&f.trade.settle)]));
    let hr = run(&node, &f, 5, &[]).await;
    assert_ok(&hr);
    assert_eq!(hr.kinds(), ["settled", "settled"]);
    assert_eq!(hr.events()[0]["accepting_block"], json!(h(15).to_string()));
    every.extend(hr.events());
    node.with(|c| c.extend(16, 116, vec![]));
    let i = run(&node, &f, 5, &[]).await;
    assert_ok(&i);
    assert_eq!(i.kinds(), ["final settled", "final settled"]);
    every.extend(i.events());

    // Across the whole story, replays aside, no two events share a key: the settle's second
    // acceptance and its second final, after the reorg, are not the first's duplicates.
    let rounds: Vec<&str> = every.iter().map(|e| e["round"].as_str().unwrap()).collect();
    assert_eq!(
        rounds,
        ["1", "1", "1", "1", "2", "2", "2", "2", "3", "3", "3", "4", "5", "5", "6", "6"]
    );
    keys_of(&every);

    assert_eq!(node.with(|c| c.violations.clone()), Vec::<String>::new());
}

/// The keys that occur more than once among `events`, with or without the round.
fn repeated_keys(events: &[Value], with_round: bool) -> Vec<String> {
    let mut keys: Vec<String> = events
        .iter()
        .map(|e| dedup_key_with(e, with_round))
        .collect();
    keys.sort();
    let mut repeats: Vec<String> = keys
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| w[0].clone())
        .collect();
    repeats.dedup();
    repeats
}

/// A funding accepted, final, taken out by a branch and accepted and final again when the chain
/// returns: the second acceptance and the second final are not the first's duplicates, so a
/// consumer that de-duplicates on the key keeps them (review round 5). The key of review round 4,
/// without the round, repeated for all four.
#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_accepted_again_after_a_reorg_is_not_a_duplicate_of_its_first_acceptance() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    let mut all = vec![];
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let first = run(&node, &f, 5, &[]).await;
    assert_ok(&first);
    assert_eq!(first.kinds(), ["authorizer_seen", "funded"]);
    all.extend(first.events());
    node.with(|c| c.extend(3, 106, vec![]));
    let fin = run(&node, &f, 5, &[]).await;
    assert_ok(&fin);
    assert_eq!(fin.kinds(), ["final authorizer_seen", "final funded"]);
    all.extend(fin.events());
    node.with(|c| {
        c.add(12, 1, 102, vec![]);
        c.set_sink(12);
    });
    let reorg = run(&node, &f, 5, &[]).await;
    assert_ok(&reorg);
    assert_eq!(reorg.kinds(), ["reorg authorizer_seen", "reorg funded"]);
    all.extend(reorg.events());
    node.with(|c| c.set_sink(3));
    let back = run(&node, &f, 5, &[]).await;
    assert_ok(&back);
    assert_eq!(
        back.kinds(),
        [
            "authorizer_seen",
            "funded",
            "final authorizer_seen",
            "final funded"
        ]
    );
    all.extend(back.events());

    let rounds: Vec<&str> = all.iter().map(|e| e["round"].as_str().unwrap()).collect();
    assert_eq!(rounds, ["1", "1", "2", "2", "3", "3", "4", "4", "4", "4"]);
    assert_eq!(repeated_keys(&all, false).len(), 4, "the defect of round 4");
    assert_eq!(repeated_keys(&all, true), Vec::<String>::new());
    // The last state a consumer would reach by applying the events in order is accepted and
    // final, which is what the node says.
    assert_eq!(state_of(&f)["accepted"][0]["finalized"], true);
    assert_eq!(state_of(&f)["round"], "4");
}

/// A kept settle taken out twice and submitted each time: the second `rebroadcast` is not the
/// first's duplicate (review round 5; it had the key `rebroadcast|txid|submitted|1` both times).
#[tokio::test(flavor = "multi_thread")]
async fn a_settle_rebroadcast_after_each_of_two_reorgs_is_not_a_duplicate() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| {
        c.extend(2, 101, vec![wire(&f.trade.funding)]);
        c.extend(3, 102, vec![wire(&f.trade.settle)]);
    });
    let mut all = vec![];
    let accepted = run(&node, &f, 5, &[]).await;
    assert_ok(&accepted);
    all.extend(accepted.events());
    node.with(|c| {
        c.add(13, 2, 103, vec![]);
        c.set_sink(13);
    });
    let first = run(&node, &f, 5, &[]).await;
    assert_ok(&first);
    assert_eq!(
        first.kinds(),
        ["reorg settled", "reorg settled", "rebroadcast"]
    );
    all.extend(first.events());
    node.with(|c| {
        c.add(14, 13, 104, vec![wire(&f.trade.settle)]);
        c.set_sink(14);
    });
    let again = run(&node, &f, 5, &[]).await;
    assert_ok(&again);
    assert_eq!(again.kinds(), ["settled", "settled"]);
    all.extend(again.events());
    node.with(|c| {
        c.add(15, 13, 105, vec![]);
        c.set_sink(15);
    });
    let second = run(&node, &f, 5, &[]).await;
    assert_ok(&second);
    assert_eq!(
        second.kinds(),
        ["reorg settled", "reorg settled", "rebroadcast"]
    );
    all.extend(second.events());

    assert_eq!(node.submitted().len(), 2, "handed to the node each time");
    let sent: Vec<&Value> = all.iter().filter(|e| e["event"] == "rebroadcast").collect();
    assert_eq!(sent.len(), 2);
    for s in &sent {
        assert_eq!(
            (s["outcome"].as_str(), s["attempt"].as_u64()),
            (Some("submitted"), Some(1))
        );
    }
    assert_eq!(
        repeated_keys(&all, false),
        [dedup_key_with(sent[0], false)],
        "the defect of round 4: the two rebroadcasts share a key"
    );
    assert_eq!(repeated_keys(&all, true), Vec::<String>::new());
    assert_eq!(
        (sent[0]["round"].as_str(), sent[1]["round"].as_str()),
        (Some("2"), Some("4"))
    );
}

/// The arguments of a watcher with no poll bound on the fixture's trade, polling every `ms`.
fn unbounded(node: &FakeNode, f: &Fixture, ms: u64) -> Vec<String> {
    [
        "run",
        "--network",
        "mainnet",
        "--node",
        &node.url,
        "--finality-depth",
        "5",
        "--state",
        &path(&f.state),
        "--trade",
        &path(&f.terms),
        "--poll-interval-ms",
        &ms.to_string(),
    ]
    .map(String::from)
    .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_killed_watcher_restarts_from_an_intact_state_file() {
    let (node, f) = started().await;
    let init = run(&node, &f, 5, &["--init"]).await;
    assert_ok(&init);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    // A watcher with no poll bound, killed hard (SIGKILL) while it runs.
    let live = Live::spawn(&unbounded(&node, &f, 10));
    live.wait_until("the funding", |l| l.out().len() == 2).await;
    live.wait_until("a few more polls", |_| node.walks() >= 4)
        .await;
    // A second watcher on the same state file is refused while the first runs.
    let second = run(&node, &f, 5, &[]).await;
    assert_refused(&second, "WATCH_STATE_LOCKED");
    let (events, _) = live.kill();
    assert_eq!(
        events.len(),
        2,
        "the funding, reported once by the killed watcher"
    );
    // The lock died with the process, and the state file is whole and says what it saw: the
    // restart does not report the funding again.
    let again = run(&node, &f, 5, &[]).await;
    assert_ok(&again);
    assert!(again.stdout.is_empty(), "{}", again.stdout);
}

/// A watcher that rewrites its state file on every poll (the node's chain grows by a block on
/// each walk), killed with SIGKILL at moments that differ each time, some of them inside the
/// write. A crash may leave a temporary file; it never leaves a state file that a restart
/// refuses, and the restart removes the leftover.
#[tokio::test(flavor = "multi_thread")]
async fn a_state_file_survives_a_kill_at_any_moment() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.growing = true);
    let mut leftovers = 0;
    for round in 0..14u64 {
        let live = Live::spawn(&unbounded(&node, &f, 1));
        let before = node.walks();
        live.wait_until("a few polls", |_| node.walks() >= before + 3)
            .await;
        // 0 to 40 ms more, a different moment each time.
        tokio::time::sleep(Duration::from_millis((round * 37) % 41)).await;
        let _ = live.kill();
        let names: Vec<String> = std::fs::read_dir(f.dir.0.as_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        leftovers += names.len();
        // The restart reads the state file whole, and clears what the crash left.
        let again = run(&node, &f, 5, &[]).await;
        assert_eq!(again.code, 0, "round {round}: {}", again.stderr);
        assert!(
            again
                .stderr
                .lines()
                .all(|l| l.contains("removed the leftover temporary state file")),
            "round {round}: {}",
            again.stderr
        );
        assert_eq!(again.stderr.lines().count(), names.len(), "round {round}");
        let still: Vec<_> = std::fs::read_dir(f.dir.0.as_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(still.is_empty(), "round {round}: {still:?}");
    }
    // Not asserted: how many kills landed inside a write (it varies with the machine).
    eprintln!("kills that left a temporary file: {leftovers} of 14");
}

// ---- refusals, each beside the accepted runs above ----

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_chosen_for_the_user_and_nothing_is_contacted_before_the_checks_pass() {
    let (node, f) = started().await;
    let url = node.url.clone();
    let base = |extra: &[&str]| {
        // Every call is bounded, so a refusal that regresses into a run fails instead of hanging.
        let mut a: Vec<String> = [
            "run",
            "--state",
            &path(&f.state),
            "--trade",
            &path(&f.terms),
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec();
        a.extend(extra.iter().map(|x| x.to_string()));
        a
    };
    // Control: all four required flags (network, node, finality depth, state) is a run.
    let ok = exec(base(&[
        "--network",
        "mainnet",
        "--node",
        &url,
        "--finality-depth",
        "5",
        "--init",
    ]))
    .await;
    assert_ok(&ok);
    let contacted = node.calls().len();
    assert!(contacted > 0);

    // A missing flag is a usage error (exit 2), with nothing on stdout and no node contact.
    for missing in [
        vec!["--node", &url, "--finality-depth", "5"],
        vec!["--network", "mainnet", "--finality-depth", "5"],
        vec!["--network", "mainnet", "--node", &url],
    ] {
        let r = exec(base(&missing)).await;
        assert_eq!(r.code, 2, "{missing:?}: {}", r.stderr);
        assert!(r.stdout.is_empty());
    }
    let no_state = exec(
        [
            "run",
            "--network",
            "mainnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_eq!(no_state.code, 2);
    // The network is never implied: no flag, no mainnet, no testnet.
    let bad_network = exec(base(&[
        "--network",
        "main",
        "--node",
        &url,
        "--finality-depth",
        "5",
    ]))
    .await;
    assert_eq!(bad_network.code, 2);

    // Refusals before any contact.
    let before = |extra: &[&str]| {
        let mut v = vec![
            "--network",
            "mainnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
        ];
        v.extend(extra);
        base(&v)
    };
    let zero = exec(base(&[
        "--network",
        "mainnet",
        "--node",
        &url,
        "--finality-depth",
        "0",
    ]))
    .await;
    assert_refused(&zero, "WATCH_FINALITY_DEPTH_ZERO");
    let short = exec(before(&["--retention-daa", "5"])).await;
    assert_refused(&short, "WATCH_RETENTION_TOO_SHORT");
    let http = exec(base(&[
        "--network",
        "mainnet",
        "--node",
        "http://127.0.0.1:17110",
        "--finality-depth",
        "5",
    ]))
    .await;
    assert_refused(&http, "WATCH_NODE_URL_INVALID");
    let remote = exec(base(&[
        "--network",
        "mainnet",
        "--node",
        "ws://192.0.2.1:17110",
        "--finality-depth",
        "5",
    ]))
    .await;
    assert_refused(&remote, "WATCH_NODE_INSECURE");
    let new_over_old = exec(before(&["--init"])).await;
    assert_refused(&new_over_old, "WATCH_STATE_EXISTS");
    let no_terms = exec(
        [
            "run",
            "--network",
            "mainnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
            "--state",
            &path(&f.state),
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_refused(&no_terms, "WATCH_TRADE_NOT_RESUMED");
    assert!(no_terms.stderr.contains(&trade_hash()));
    let missing_state = exec(
        [
            "run",
            "--network",
            "mainnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
            "--state",
            &path(&f.dir.file("none.json")),
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_refused(&missing_state, "WATCH_STATE_MISSING");
    // The state is mainnet's; terms of another network than the one watched.
    let other_net_state = exec(base(&[
        "--network",
        "testnet",
        "--node",
        &url,
        "--finality-depth",
        "5",
    ]))
    .await;
    assert_refused(&other_net_state, "WATCH_STATE_MISMATCH");
    let fresh = path(&f.dir.file("fresh.json"));
    let testnet_terms = exec(
        [
            "run",
            "--network",
            "testnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
            "--state",
            &fresh,
            "--init",
            "--trade",
            &path(&f.terms),
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_refused(&testnet_terms, "WATCH_NETWORK_MISMATCH");
    assert_eq!(
        node.calls().len(),
        contacted,
        "none of these reached the node"
    );

    // Retiring the trade is the explicit way to run without its terms file.
    let retired = exec(
        [
            "run",
            "--network",
            "mainnet",
            "--node",
            &url,
            "--finality-depth",
            "5",
            "--state",
            &path(&f.state),
            "--retire",
            &trade_hash(),
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_eq!(retired.code, 0, "{}", retired.stderr);
    assert!(retired.stderr.contains("retired trade"));
    // And it is then gone from the state: a run with the terms file adds it as new, noted.
    let again = exec(before(&[])).await;
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert!(again.stderr.contains("watched from chain block"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_on_another_network_or_not_synced_is_refused_before_any_walk() {
    let (node, f) = started().await;
    // Control: the right network, synced.
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    let walks = |n: &FakeNode| {
        n.calls()
            .iter()
            .filter(|c| c.contains("virtual_chain"))
            .count()
    };
    let before = walks(&node);

    node.with(|c| c.network = NetworkId::with_suffix(NetworkType::Testnet, 10));
    let r = run(&node, &f, 5, &[]).await;
    assert_refused(&r, "WATCH_NODE_NETWORK_MISMATCH");
    node.with(|c| {
        c.network = NetworkId::new(NetworkType::Mainnet);
        c.synced = false;
    });
    let r = run(&node, &f, 5, &[]).await;
    assert_refused(&r, "WATCH_NODE_NOT_SYNCED");
    assert_eq!(walks(&node), before);

    // A node that answers the connection but not the server-info call.
    node.with(|c| {
        c.synced = true;
        c.failing_server_info = true;
    });
    let r = run(&node, &f, 5, &[]).await;
    assert_refused(&r, "WATCH_NODE_RPC");
    assert!(r.stderr.contains("server info unavailable"), "{}", r.stderr);
    node.with(|c| c.failing_server_info = false);
    assert_ok(&run(&node, &f, 5, &[]).await);

    // Nobody listening.
    let dead = Fixture::new();
    let r = exec(
        [
            "run",
            "--network",
            "testnet",
            "--node",
            "ws://127.0.0.1:1",
            "--finality-depth",
            "5",
            "--state",
            &path(&dead.state),
            "--init",
            "--max-polls",
            "1",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_refused(&r, "WATCH_NODE_UNREACHABLE");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_walk_is_survived_and_a_walk_missing_what_the_watcher_needs_changes_nothing() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let saved = std::fs::read_to_string(&f.state).unwrap();

    // The first walk fails, the second goes through: the events come, the exit code says one
    // poll failed.
    node.with(|c| c.failing_walks = 1);
    let r = run(&node, &f, 5, &["--max-polls", "2"]).await;
    assert_eq!(r.code, 1);
    assert_eq!(r.stderr.lines().count(), 1, "{}", r.stderr);
    assert!(
        r.stderr.starts_with("impulse-watch: WATCH_SOURCE_FAILED"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("walk refused by the fake node"));
    assert_eq!(r.kinds(), ["authorizer_seen", "funded"]);
    assert_ne!(std::fs::read_to_string(&f.state).unwrap(), saved);

    // A node that writes terminal control sequences into its error is echoed escaped.
    node.with(|c| {
        c.failing_walks = 1;
        c.walk_error = "bad\u{1b}[31m\nline two".into();
    });
    let r = run(&node, &f, 5, &[]).await;
    assert_eq!(r.code, 1);
    assert!(!r.stderr.contains('\u{1b}'), "{:?}", r.stderr);
    assert_eq!(r.stderr.lines().count(), 1, "{:?}", r.stderr);
    assert!(r.stderr.contains("\\u{1b}[31m"), "{:?}", r.stderr);

    // A walk without the spent UTXO entries is refused whole: nothing printed, nothing saved.
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let saved = std::fs::read_to_string(&f.state).unwrap();
    node.with(|c| c.strip_spent_entries = true);
    let r = run(&node, &f, 5, &[]).await;
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.starts_with("impulse-watch: WATCH_SOURCE_FAILED"));
    assert!(
        r.stderr.contains("spent UTXO entry of input 0"),
        "{}",
        r.stderr
    );
    assert_eq!(std::fs::read_to_string(&f.state).unwrap(), saved);
    // Control: the same node with the entries is read.
    node.with(|c| c.strip_spent_entries = false);
    let r = run(&node, &f, 5, &[]).await;
    assert_ok(&r);
    assert_eq!(r.kinds(), ["authorizer_seen", "funded"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_walk_above_the_nodes_own_virtual_daa_score_is_refused_whole() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let saved = std::fs::read_to_string(&f.state).unwrap();
    // The node's chain block 2 is at DAA 101 and its virtual says 100: every acceptance would
    // look deeper than it is. Nothing is printed, nothing is saved.
    node.with(|c| c.virtual_daa_deficit = 1);
    let r = run(&node, &f, 5, &[]).await;
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(
        r.stderr.starts_with("impulse-watch: WATCH_SOURCE_FAILED"),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("above the node's virtual DAA score 100"),
        "{}",
        r.stderr
    );
    assert_eq!(std::fs::read_to_string(&f.state).unwrap(), saved);
    // Control: a virtual at the chain block's own score is read.
    node.with(|c| c.virtual_daa_deficit = 0);
    let r = run(&node, &f, 5, &[]).await;
    assert_ok(&r);
    assert_eq!(r.kinds(), ["authorizer_seen", "funded"]);
}

// ---- the probe ----

#[tokio::test(flavor = "multi_thread")]
async fn the_probe_checks_the_nodes_answers_and_submits_nothing() {
    let node = FakeNode::start().await;
    node.with(|c| {
        for n in 1..=14u64 {
            let accepted = if n == 12 {
                vec![wire(&trade().funding)]
            } else {
                vec![]
            };
            c.extend(n, 99 + n, accepted);
        }
    });
    let probe = |extra: &[&str]| {
        let mut a: Vec<String> = ["probe", "--network", "mainnet", "--node", &node.url]
            .map(String::from)
            .to_vec();
        a.extend(extra.iter().map(|x| x.to_string()));
        exec(a)
    };
    let ok = probe(&["--expect-version", "2.1.0"]).await;
    assert_ok(&ok);
    assert!(
        ok.stdout.contains("ok: node \"2.1.0\" on mainnet, synced"),
        "{}",
        ok.stdout
    );
    assert!(ok
        .stdout
        .contains("ok: node version is \"2.1.0\", as expected"));
    assert!(ok.stdout.contains("ok: short walk:"));
    assert!(ok.stdout.contains("ok: batch walk:"));
    assert!(ok.stdout.lines().all(|l| l.starts_with("ok: ")));
    assert!(node.submitted().is_empty());
    assert!(!node.calls().contains(&"submit_transaction"));

    let wrong = probe(&["--expect-version", "9.9.9"]).await;
    assert_refused(&wrong, "WATCH_PROBE_FAILED");
    node.with(|c| c.strip_spent_entries = true);
    let stripped = probe(&[]).await;
    assert_refused(&stripped, "WATCH_PROBE_FAILED");
    node.with(|c| c.strip_spent_entries = false);
    node.with(|c| c.synced = false);
    assert_refused(&probe(&[]).await, "WATCH_NODE_NOT_SYNCED");
    // The network is named by the user and never implied.
    let r = exec(["probe", "--node", &node.url].map(String::from).to_vec()).await;
    assert_eq!(r.code, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_script_runs_the_probe_and_refuses_what_is_not_explicit() {
    let node = FakeNode::start().await;
    node.with(|c| {
        for n in 1..=14u64 {
            c.extend(n, 99 + n, vec![]);
        }
        c.network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    });
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-vcc-v2.sh");
    let run_script = |args: Vec<String>| {
        let script = script.clone();
        tokio::task::spawn_blocking(move || {
            let out = Command::new("bash")
                .arg(&script)
                .args(&args)
                .env("IMPULSE_WATCH_BIN", bin())
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap(),
            )
        })
    };
    // Control: explicit network and node, the version the node reports.
    let (code, out, err) = run_script(
        [
            "--network",
            "testnet",
            "--node",
            &node.url,
            "--expect-version",
            "2.1.0",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ok: batch walk:"), "{out}");
    assert!(out.contains("check-vcc-v2: all checks passed"), "{out}");
    // Mainnet is never implied, and the node is never defaulted.
    for args in [
        vec![],
        vec!["--node", &node.url],
        vec!["--network", "testnet"],
        vec!["--network", "mainnet"],
        vec!["--network", "devnet", "--node", &node.url],
    ] {
        let (code, out, err) = run_script(args.iter().map(|a| a.to_string()).collect())
            .await
            .unwrap();
        assert_eq!(code, 2, "{args:?}: {out} {err}");
        assert!(out.is_empty());
    }
    // A failing check fails the script.
    let (code, _, err) = run_script(
        [
            "--network",
            "testnet",
            "--node",
            &node.url,
            "--expect-version",
            "9.9.9",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert!(err.contains("WATCH_PROBE_FAILED"), "{err}");
}

// ---- review round 4: the adapter, the clock, the link, replays, the probe, retention ----

/// A call that must answer by itself within the adapter's own timeout: if the adapter's timeout
/// is gone this fails, instead of waiting for ever.
async fn within<T>(call: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), call)
        .await
        .expect("the adapter's own timeout did not end the call")
}

/// The adapter against the node, as a library: the node's own answers to a submission, an ID
/// that is not the transaction's, and a node that never answers (a short timeout, set at
/// connect, so the test does not wait the 30 seconds the binary does).
#[tokio::test(flavor = "multi_thread")]
async fn the_adapter_reads_the_nodes_duplicate_answers_a_wrong_id_and_a_silent_node() {
    let (node, _f) = started().await;
    let tx = trade().settle.0;
    let txid = tx.id();
    let other = Hash::from_u64_word(0x0f0f);
    // A handler that never answers holds its connection (the server serves one request at a
    // time per connection), so each silent call gets a connection of its own.
    let connect = || async {
        WrpcNode::connect_with_timeout(&node.url, Network::Mainnet, Duration::from_millis(500))
            .await
            .unwrap()
    };
    let wrpc = connect().await;

    // Control: the node takes it.
    assert_eq!(wrpc.submit(&tx).await, Ok(()));
    // Already in the mempool: done.
    node.with(|c| {
        c.refusals
            .push_back(format!("transaction {txid} is already in the mempool"))
    });
    assert_eq!(wrpc.submit(&tx).await, Ok(()));
    // Only remembered as accepted by the consensus: not done, and not a refusal of its own.
    node.with(|c| {
        c.refusals.push_back(format!(
            "rejected transaction {txid}: transaction {txid} was already accepted by the consensus"
        ))
    });
    match wrpc.submit(&tx).await {
        Err(Refusal::RecentlyAccepted(reason)) => {
            assert!(
                reason.contains("already accepted by the consensus"),
                "{reason}"
            )
        }
        other => panic!("{other:?}"),
    }
    // The same answers about another transaction are refusals.
    for message in [
        format!("transaction {other} is already in the mempool"),
        format!("transaction {other} was already accepted by the consensus"),
        "mempool full".to_string(),
    ] {
        node.with(|c| c.refusals.push_back(message.clone()));
        match wrpc.submit(&tx).await {
            Err(Refusal::Refused(reason)) => assert!(reason.contains(&message), "{reason}"),
            got => panic!("{message}: {got:?}"),
        }
    }
    // An ID in the answer that is not the transaction's.
    node.with(|c| c.wrong_id_answers = 1);
    match wrpc.submit(&tx).await {
        Err(Refusal::Refused(reason)) => {
            assert!(reason.contains("answered with transaction"), "{reason}")
        }
        got => panic!("{got:?}"),
    }
    // A node that never answers a submission: a refusal naming the silence, within the timeout.
    node.with(|c| c.hangs.push("submit_transaction"));
    let started = Instant::now();
    match within(wrpc.submit(&tx)).await {
        Err(Refusal::Refused(reason)) => {
            assert!(reason.contains("no answer in 500 ms"), "{reason}")
        }
        got => panic!("{got:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(20));
    node.with(|c| c.hangs.clear());
    wrpc.disconnect().await;
    // Control: a fresh connection works again.
    let wrpc = connect().await;
    assert_eq!(wrpc.submit(&tx).await, Ok(()));

    // The node's own clock, and a node that does not answer it.
    assert_eq!(wrpc.virtual_daa_score().await, Ok(100));
    let silent = connect().await;
    node.with(|c| c.hangs.push("get_block_dag_info"));
    let clock = within(silent.virtual_daa_score()).await.unwrap_err();
    assert!(clock.contains("no answer in 500 ms"), "{clock}");
    node.with(|c| c.hangs.clear());
    silent.disconnect().await;
    // A walk that never comes is a failed call, not a stalled watcher.
    let silent = connect().await;
    node.with(|c| c.hangs.push("get_virtual_chain_from_block_v2"));
    let walk = within(silent.get_virtual_chain_from(h(0)))
        .await
        .unwrap_err();
    assert!(walk.0.contains("no answer in 500 ms"), "{}", walk.0);
    node.with(|c| c.hangs.clear());
    silent.disconnect().await;
    assert!(wrpc.get_virtual_chain_from(h(0)).await.is_ok());
    wrpc.disconnect().await;
}

/// A link that goes silent without closing (the proxy swallows everything and keeps both sockets
/// open): the call that finds it ends with the timeout, and the adapter drops the link, so the
/// next call goes through a new one. Without the drop the client stays connected to the dead
/// socket, no disconnect is ever signalled, and every later call times out until the operating
/// system gives up on the socket, which takes minutes (review round 5).
#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_goes_silent_is_dropped_by_the_timeout_and_made_again() {
    let node = FakeNode::start_proxied().await;
    node.with(|c| c.extend(1, 100, vec![]));
    let wrpc =
        WrpcNode::connect_with_timeout(&node.url, Network::Mainnet, Duration::from_millis(500))
            .await
            .unwrap();
    // Control: the link answers.
    assert!(within(wrpc.get_virtual_chain_from(h(0))).await.is_ok());
    let walks = node.walks();

    node.proxy.as_ref().unwrap().blackhole();
    // The links notice at their next look, every 10 ms.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let silent = within(wrpc.get_virtual_chain_from(h(0))).await.unwrap_err();
    assert!(silent.0.contains("no answer in 500 ms"), "{}", silent.0);
    assert_eq!(
        node.walks(),
        walks,
        "the dead link carried nothing to the node"
    );

    // The next call is not made on the dead link.
    assert!(within(wrpc.get_virtual_chain_from(h(0))).await.is_ok());
    assert_eq!(node.walks(), walks + 1);
    assert!(within(wrpc.get_virtual_chain_from(h(0))).await.is_ok());
    wrpc.disconnect().await;
}

/// The adapter's own timeout on making a link again: a node that takes the connection and then
/// never answers the server-info check is a failed call within the timeout, not a stalled
/// watcher, and the link is tried again by the next call (review round 5).
#[tokio::test(flavor = "multi_thread")]
async fn a_link_made_again_to_a_node_that_never_answers_is_a_failed_call_and_is_tried_again() {
    let node = FakeNode::start_proxied().await;
    node.with(|c| c.extend(1, 100, vec![]));
    let wrpc =
        WrpcNode::connect_with_timeout(&node.url, Network::Mainnet, Duration::from_millis(500))
            .await
            .unwrap();
    assert!(within(wrpc.get_virtual_chain_from(h(0))).await.is_ok());
    let walks = node.walks();

    // The link is cut and comes back, and the node on it never answers the check.
    let proxy = node.proxy.as_ref().unwrap();
    proxy.cut();
    proxy.accept_again();
    tokio::time::sleep(Duration::from_millis(300)).await;
    node.with(|c| c.hangs.push("get_server_info"));
    let failed = within(wrpc.get_virtual_chain_from(h(0))).await.unwrap_err();
    assert!(
        failed.0.contains("could not be made again") && failed.0.contains("no answer in 500 ms"),
        "{}",
        failed.0
    );
    assert_eq!(
        node.walks(),
        walks,
        "nothing is read from an unchecked link"
    );

    // Control: once the node answers, the next call makes the link again and is answered.
    node.with(|c| c.hangs.clear());
    assert!(within(wrpc.get_virtual_chain_from(h(0))).await.is_ok());
    assert_eq!(node.walks(), walks + 1);
    wrpc.disconnect().await;
}

/// The submission made and the process dead before the state was saved: the restart submits the
/// same transaction again, and the node's "already in the mempool" is the answer a rebroadcast
/// wants, so it is reported as submitted, the same event as the first run's. The node's other
/// duplicate answer, only a record of an acceptance, is a wait that costs no attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_rebroadcast_made_and_not_saved_is_made_again_after_a_restart() {
    let (node, f) = started().await;
    let settle_id = f.trade.settle.0.id();
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| {
        c.extend(2, 101, vec![wire(&f.trade.funding)]);
        c.extend(3, 102, vec![wire(&f.trade.settle)]);
    });
    assert_ok(&run(&node, &f, 5, &[]).await);
    let before_reorg = std::fs::read_to_string(&f.state).unwrap();
    node.with(|c| {
        c.add(14, 2, 103, vec![]);
        c.set_sink(14);
    });

    let first = run(&node, &f, 5, &[]).await;
    assert_ok(&first);
    assert_eq!(
        first.kinds(),
        ["reorg settled", "reorg settled", "rebroadcast"]
    );
    assert_eq!(first.events()[2]["outcome"], "submitted");
    assert_eq!(first.events()[2]["attempt"], 1);
    assert_eq!(node.submitted().len(), 1);

    // Dead after the submission and before the save: the state file is the previous round's.
    std::fs::write(&f.state, &before_reorg).unwrap();
    node.with(|c| {
        c.refusals
            .push_back(format!("transaction {settle_id} is already in the mempool"))
    });
    let second = run(&node, &f, 5, &[]).await;
    assert_ok(&second);
    assert_eq!(second.kinds(), first.kinds());
    assert_eq!(second.events()[2]["outcome"], "submitted");
    assert_eq!(keys_of(&second.events()), keys_of(&first.events()));
    assert_eq!(node.submitted().len(), 2, "handed to the node again");
    assert!(state_of(&f)["pending"].as_array().unwrap().is_empty());

    // The node's other answer: it has only a record of the transaction as accepted. Not done:
    // waiting, no attempt used, pending in the file; and then the node takes it.
    std::fs::write(&f.state, &before_reorg).unwrap();
    node.with(|c| {
        c.refusals.push_back(format!(
            "transaction {settle_id} was already accepted by the consensus"
        ))
    });
    let third = run(&node, &f, 5, &[]).await;
    assert_ok(&third);
    let waiting = third.events()[2].clone();
    assert_eq!(waiting["outcome"], "refused");
    assert_eq!(waiting["attempt"], 0);
    assert_eq!(waiting["code"], "WATCH_REBROADCAST_FAILED");
    let pending = state_of(&f)["pending"].clone();
    assert_eq!(pending[0]["attempts"], 0);
    assert_eq!(pending[0]["due"], false);
    let fourth = run(&node, &f, 5, &[]).await;
    assert_ok(&fourth);
    assert_eq!(fourth.kinds(), ["rebroadcast"]);
    assert_eq!(fourth.events()[0]["outcome"], "submitted");
    assert_eq!(fourth.events()[0]["attempt"], 1);
    assert_eq!(node.with(|c| c.violations.clone()), Vec::<String>::new());
}

/// A watcher restarted behind the chain (the node's batch limit, or a long downtime) must not
/// take its stale cursor for the tip when it decides whether the depositor's refund may be open.
#[tokio::test(flavor = "multi_thread")]
async fn a_settle_is_held_back_by_the_nodes_clock_when_the_watcher_restarts_behind_the_chain() {
    let expiry = terms().terms().expiry_daa;
    // The chain after the settle's block, and where the sink stands when the watcher is back.
    let scenario = |sink_daa: u64| async move {
        let node = FakeNode::start().await;
        let f = Fixture::new();
        node.with(|c| c.extend(1, expiry - 9, vec![]));
        assert_ok(&run(&node, &f, 5, &["--init"]).await);
        node.with(|c| {
            c.extend(2, expiry - 8, vec![wire(&f.trade.funding)]);
            c.extend(3, expiry - 3, vec![wire(&f.trade.settle)]);
        });
        assert_ok(&run(&node, &f, 5, &[]).await);
        // While it was down a branch took the settle out, and the node serves one block a walk.
        node.with(|c| {
            c.add(14, 2, expiry - 2, vec![]);
            c.add(15, 14, sink_daa, vec![]);
            c.set_sink(15);
            c.added_limit = Some(1);
        });
        let r = run(&node, &f, 5, &[]).await;
        (node, r)
    };

    let (node, r) = scenario(expiry + 500).await;
    assert_ok(&r);
    assert_eq!(r.kinds(), ["reorg settled", "reorg settled", "rebroadcast"]);
    let skipped = &r.events()[2];
    assert_eq!(skipped["outcome"], "skipped_past_expiry");
    assert_eq!(skipped["code"], "WATCH_REBROADCAST_PAST_EXPIRY");
    assert_eq!(skipped["expiry_daa"], json!(expiry.to_string()));
    assert_eq!(skipped["tip_daa"], json!((expiry + 500).to_string()));
    assert!(node.submitted().is_empty());

    // Control: the same position with the node's clock before the expiry submits.
    let (node, r) = scenario(expiry - 1).await;
    assert_ok(&r);
    assert_eq!(r.events()[2]["outcome"], "submitted");
    assert_eq!(node.submitted().len(), 1);
}

/// The link cut while the watcher runs and refused for a while: the events before are not
/// repeated and the ones after arrive; a poll that fails meanwhile is reported as such and the
/// state file stays as the last good round left it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_link_is_survived_without_repeating_or_losing_an_event() {
    let node = FakeNode::start_proxied().await;
    node.with(|c| c.extend(1, 100, vec![]));
    let f = Fixture::new();
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let live = Live::spawn(&unbounded(&node, &f, 40));
    live.wait_until("the funding", |l| l.out().len() == 2).await;
    live.wait_until("the funding saved", |_| {
        state_of(&f)["accepted"]
            .as_array()
            .is_some_and(|a| a.len() == 1)
    })
    .await;
    let saved = std::fs::read_to_string(&f.state).unwrap();

    // The link goes and the node takes no connection; the settle is accepted meanwhile.
    let proxy = node.proxy.as_ref().unwrap();
    proxy.cut();
    node.with(|c| c.extend(3, 102, vec![wire(&f.trade.settle)]));
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(live.out().len(), 2, "nothing new while the link is down");
    assert_eq!(std::fs::read_to_string(&f.state).unwrap(), saved);

    // The link is back: polling resumes by itself and the settle comes through once.
    proxy.accept_again();
    live.wait_until("the settle after the link came back", |l| {
        l.out().len() == 4
    })
    .await;
    let walks = node.walks();
    live.wait_until("a few more polls", |_| node.walks() >= walks + 3)
        .await;
    let (events, err) = live.kill();
    let kinds: Vec<_> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["authorizer_seen", "funded", "settled", "settled"]);
    keys_of(&events);
    // The polls that failed while the link was down were reported as failed polls, and only
    // that, and the watcher made the link again by itself.
    assert!(!err.is_empty(), "the outage went unreported");
    assert!(
        err.iter()
            .all(|l| l.starts_with("impulse-watch: WATCH_SOURCE_FAILED")),
        "{err:?}"
    );
    assert!(
        err.iter()
            .any(|l| l.contains("the link to the node was lost")),
        "{err:?}"
    );
    let state = state_of(&f);
    assert_eq!(state["accepted"].as_array().unwrap().len(), 2);
    assert_eq!(state["cursor"]["block"], json!(h(3).to_string()));
    assert_eq!(node.with(|c| c.violations.clone()), Vec::<String>::new());
}

/// A node that comes back on another network, or not synced, is not followed: the link the
/// watcher makes again is checked as at start-up, and nothing it says is read until it passes.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_comes_back_on_another_network_is_not_followed() {
    let node = FakeNode::start_proxied().await;
    node.with(|c| c.extend(1, 100, vec![]));
    let f = Fixture::new();
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| c.extend(2, 101, vec![wire(&f.trade.funding)]));
    let live = Live::spawn(&unbounded(&node, &f, 40));
    live.wait_until("the funding", |l| l.out().len() == 2).await;

    // The link goes; the node that answers when it is back is a testnet node (or unsynced).
    let proxy = node.proxy.as_ref().unwrap();
    proxy.cut();
    node.with(|c| {
        c.extend(3, 102, vec![wire(&f.trade.settle)]);
        c.network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    });
    proxy.accept_again();
    live.wait_until("the refusal to follow it", |l| {
        l.err()
            .iter()
            .any(|e| e.contains("could not be made again"))
    })
    .await;
    let walks = node.walks();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        live.out().len(),
        2,
        "nothing is read from a node on another network"
    );
    assert_eq!(node.walks(), walks, "no walk was asked of it");
    let refusals = live.err();
    assert!(
        refusals.iter().any(|e| e.contains("testnet")),
        "{refusals:?}"
    );

    // Control: the right network again, and not synced first.
    node.with(|c| {
        c.network = NetworkId::new(NetworkType::Mainnet);
        c.synced = false;
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        live.out().len(),
        2,
        "nothing is read from a node that is not synced"
    );
    node.with(|c| c.synced = true);
    live.wait_until("the settle once the node is right", |l| l.out().len() == 4)
        .await;
    let (events, _) = live.kill();
    keys_of(&events);
}

/// A walk the node serves again verbatim (a notification delivered twice, a reconnect that
/// replays): nothing is reported, nothing is saved differently.
#[tokio::test(flavor = "multi_thread")]
async fn a_walk_delivered_again_changes_nothing() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    node.with(|c| {
        c.extend(2, 101, vec![wire(&f.trade.funding)]);
        c.extend(3, 102, vec![wire(&f.trade.settle)]);
    });
    let b = run(&node, &f, 5, &[]).await;
    assert_eq!(b.events().len(), 4);
    let saved = std::fs::read_to_string(&f.state).unwrap();
    let walks = node.walks();
    // The next two walks are the one that carried the funding and the settle, again.
    node.with(|c| c.replay_walks = 2);
    let r = run(&node, &f, 5, &["--max-polls", "3"]).await;
    assert_ok(&r);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    assert_eq!(node.walks(), walks + 3);
    assert_eq!(std::fs::read_to_string(&f.state).unwrap(), saved);
}

/// A node whose answers the watcher could not use, and a plain-text link to a remote host on
/// mainnet, are refused by the probe; a node that stops a walk short of its sink at its batch
/// limit is reported, not failed.
#[tokio::test(flavor = "multi_thread")]
async fn the_probe_refuses_what_the_watcher_could_not_use_and_reports_the_batch_limit() {
    let node = FakeNode::start().await;
    node.with(|c| {
        for n in 1..=14u64 {
            c.extend(n, 99 + n * 100, vec![]);
        }
    });
    let probe = |extra: &[&str]| {
        let mut a: Vec<String> = ["probe", "--network", "mainnet", "--node", &node.url]
            .map(String::from)
            .to_vec();
        a.extend(extra.iter().map(|x| x.to_string()));
        exec(a)
    };
    // Control: a node that reaches the sink in one walk.
    let ok = probe(&[]).await;
    assert_ok(&ok);
    assert!(
        ok.stdout.contains(
            "ok: the batch walk from the pruning point reached the sink in 14 added chain blocks"
        ),
        "{}",
        ok.stdout
    );
    assert!(
        ok.stdout.contains("ok: short walk: 10 added chain blocks"),
        "{}",
        ok.stdout
    );

    // A batch limit: the walk stops short, and the probe says so (and says the watcher goes on).
    node.with(|c| c.added_limit = Some(3));
    let limited = probe(&[]).await;
    assert_ok(&limited);
    assert!(
        limited.stdout.contains(
            "ok: the node stopped the batch walk at 3 added chain blocks, short of the sink: its added-block batch limit"
        ),
        "{}",
        limited.stdout
    );
    assert!(limited
        .stdout
        .contains("ok: short walk: 3 added chain blocks"));
    node.with(|c| c.added_limit = None);

    // A walk that adds nothing is no proof of anything.
    node.with(|c| c.empty_walks = true);
    let empty = probe(&[]).await;
    assert_refused(&empty, "WATCH_PROBE_FAILED");
    assert!(
        empty.stderr.contains("added no chain block"),
        "{}",
        empty.stderr
    );
    node.with(|c| c.empty_walks = false);

    // A walk from a block behind the sink that removes chain blocks.
    node.with(|c| c.forced_removed = vec![h(5)]);
    let removed = probe(&[]).await;
    assert_refused(&removed, "WATCH_PROBE_FAILED");
    assert!(
        removed.stderr.contains("removed chain blocks"),
        "{}",
        removed.stderr
    );
    node.with(|c| c.forced_removed.clear());
    assert_ok(&probe(&[]).await);

    // A plain-text link to a remote host on mainnet is refused before the node is contacted.
    let calls = node.calls().len();
    let insecure = exec(
        [
            "probe",
            "--network",
            "mainnet",
            "--node",
            "ws://192.0.2.1:17110",
        ]
        .map(String::from)
        .to_vec(),
    )
    .await;
    assert_refused(&insecure, "WATCH_NODE_INSECURE");
    assert_eq!(node.calls().len(), calls);
}

/// With `--retention-daa` the state file drops a final acceptance once it is that deep and
/// keeps a transaction marked for rebroadcast; without it nothing is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn the_retention_window_bounds_the_state_file_and_keeps_the_kept_transaction() {
    let accepted_txids = |f: &Fixture| -> Vec<String> {
        state_of(f)["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["txid"].as_str().unwrap().to_string())
            .collect()
    };
    for retention in [true, false] {
        let (node, f) = started().await;
        let (funding_id, settle_id) = (
            f.trade.funding.0.id().to_string(),
            f.trade.settle.0.id().to_string(),
        );
        let extra: Vec<&str> = if retention {
            vec!["--retention-daa", "20"]
        } else {
            vec![]
        };
        let mut first = vec!["--init"];
        first.extend(&extra);
        assert_ok(&run(&node, &f, 5, &first).await);
        node.with(|c| {
            c.extend(2, 101, vec![wire(&f.trade.funding)]);
            c.extend(3, 102, vec![wire(&f.trade.settle)]);
        });
        // Final (N = 5) but not 20 deep: both stay.
        node.with(|c| c.extend(4, 108, vec![]));
        let r = run(&node, &f, 5, &extra).await;
        assert_ok(&r);
        assert_eq!(accepted_txids(&f).len(), 2);
        // 24 deep: the funding goes with the window; the kept settle stays.
        node.with(|c| c.extend(5, 125, vec![]));
        assert_ok(&run(&node, &f, 5, &extra).await);
        let left = accepted_txids(&f);
        if retention {
            assert_eq!(left, std::slice::from_ref(&settle_id), "retained: {left:?}");
        } else {
            assert_eq!(left.len(), 2, "no window, nothing dropped");
            assert!(left.contains(&funding_id));
        }
        assert_eq!(state_of(&f)["kept"], json!([settle_id]));
    }
}

/// The owner script: a plain-text remote link on mainnet is refused through it too, the node's
/// credentials and path are never echoed, and the binary is found from cargo's own account of
/// what it built, wherever the target directory is.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_script_refuses_a_plain_link_hides_the_urls_secrets_and_finds_the_binary() {
    let node = FakeNode::start().await;
    node.with(|c| {
        for n in 1..=14u64 {
            c.extend(n, 99 + n, vec![]);
        }
        c.network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    });
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-vcc-v2.sh");
    let dir = TempDir::new();
    let stub_dir = dir.file("stub");
    std::fs::create_dir(&stub_dir).unwrap();
    // A cargo that reports, as cargo does with --message-format=json, where it put the binary.
    let stub = stub_dir.join("cargo");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\necho \"$@\" > '{args}'\n\
             echo '{{\"reason\":\"compiler-artifact\",\"target\":{{\"kind\":[\"lib\"],\"name\":\"impulse_watch\"}},\"executable\":null}}'\n\
             echo '{{\"reason\":\"compiler-artifact\",\"target\":{{\"kind\":[\"bin\"],\"name\":\"impulse-watch\"}},\"executable\":\"{bin}\"}}'\n\
             echo '{{\"reason\":\"build-finished\",\"success\":true}}'\n",
            args = dir.file("cargo-args").display(),
            bin = bin()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run_script = |args: Vec<String>, with_bin: bool| {
        let (script, stub_dir) = (script.clone(), stub_dir.clone());
        tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new("bash");
            cmd.arg(&script).args(&args).stdin(Stdio::null());
            if with_bin {
                cmd.env("IMPULSE_WATCH_BIN", bin());
            } else {
                let path = std::env::var("PATH").unwrap_or_default();
                cmd.env("PATH", format!("{}:{path}", stub_dir.display()));
                cmd.env_remove("IMPULSE_WATCH_BIN");
            }
            let out = cmd.output().unwrap();
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8(out.stdout).unwrap(),
                String::from_utf8(out.stderr).unwrap(),
            )
        })
    };

    // A plain-text link to a remote host on mainnet, through the script.
    let (code, out, err) = run_script(
        ["--network", "mainnet", "--node", "ws://192.0.2.1:17110"]
            .map(String::from)
            .to_vec(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(code, 1, "{out} {err}");
    assert!(err.contains("WATCH_NODE_INSECURE"), "{err}");
    assert!(err.contains("check-vcc-v2: FAILED"), "{err}");

    // A URL with credentials, a path and a query: the output shows host and port only.
    let secret_url =
        node.url.replacen("ws://", "ws://user:SECRETPW@", 1) + "/SECRETPATH?key=SECRETKEY";
    let (code, out, err) = run_script(
        [
            "--network",
            "testnet",
            "--node",
            &secret_url,
            "--expect-version",
            "2.1.0",
        ]
        .map(String::from)
        .to_vec(),
        true,
    )
    .await
    .unwrap();
    for text in [&out, &err] {
        for secret in ["SECRETPW", "SECRETPATH", "SECRETKEY"] {
            assert!(!text.contains(secret), "{secret} echoed:\n{out}\n{err}");
        }
    }
    assert!(
        out.contains("check-vcc-v2: network testnet, node ws://***@127.0.0.1:"),
        "{out} {err}"
    );
    // The same node without credentials in the URL passes (control for the redaction above).
    let (code2, out2, err2) = run_script(
        [
            "--network",
            "testnet",
            "--node",
            &node.url,
            "--expect-version",
            "2.1.0",
        ]
        .map(String::from)
        .to_vec(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(code2, 0, "{out2} {err2}");
    assert!(
        out2.contains("check-vcc-v2: network testnet, node ws://127.0.0.1:"),
        "{out2}"
    );
    let _ = code;

    // Without IMPULSE_WATCH_BIN the script builds, and runs the executable cargo names.
    let (code, out, err) = run_script(
        [
            "--network",
            "testnet",
            "--node",
            &node.url,
            "--expect-version",
            "2.1.0",
        ]
        .map(String::from)
        .to_vec(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("check-vcc-v2: all checks passed"), "{out}");
    let args = std::fs::read_to_string(dir.file("cargo-args")).unwrap();
    for part in [
        "build",
        "--locked",
        "--release",
        "-p impulse-watch",
        "--message-format=json",
    ] {
        assert!(args.contains(part), "{part} missing from: {args}");
    }
}

/// Operations (I14): a node that fails every walk ends a run with `--max-failed-polls` (exit 1)
/// before `--max-polls` is reached, and with `--log-format json` every stderr line is one JSON
/// object with a stable code: the failed polls at level warn, the end at level error.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_lost_for_k_polls_ends_the_run_with_json_logs() {
    let (node, f) = started().await;
    assert_ok(&run(&node, &f, 5, &["--init"]).await);
    let saved = std::fs::read_to_string(&f.state).unwrap();
    node.with(|c| c.failing_walks = 1_000);
    let r = run(
        &node,
        &f,
        5,
        &[
            "--max-polls",
            "50",
            "--max-failed-polls",
            "3",
            "--log-format",
            "json",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stdout.is_empty());
    let lines: Vec<serde_json::Value> = r
        .stderr
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON object per line"))
        .collect();
    assert_eq!(lines.len(), 4, "{}", r.stderr);
    for warn in &lines[..3] {
        assert_eq!(warn["level"], "warn");
        assert_eq!(warn["code"], "WATCH_SOURCE_FAILED");
    }
    assert_eq!(lines[3]["level"], "error");
    assert_eq!(lines[3]["code"], "WATCH_SOURCE_FAILED");
    assert!(lines[3]["message"]
        .as_str()
        .unwrap()
        .contains("3 polls in a row failed"));
    assert_eq!(std::fs::read_to_string(&f.state).unwrap(), saved);
}
