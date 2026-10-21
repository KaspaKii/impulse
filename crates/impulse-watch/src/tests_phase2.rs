// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Phase 2 tests: the node's walk converted, the transport checks, the strict file readers, the
//! state file, retiring and evicting, and the binary's logic (`prepare` and `drive`) over the
//! fake source. The process itself, against a fake wRPC node, is `tests/e2e.rs`. Each refusal
//! has an accepted control beside it. No test holds a key.

use super::*;
use crate::cli::{NetworkArg, RunArgs};
use crate::files::{hex, parse_signed_tx, parse_terms_file};
use crate::node::{
    check_server_info, check_transport, convert_transaction, convert_walk, node_has_in_mempool,
    node_recently_accepted,
};
use crate::persist::{self, FORMAT};
use crate::run::{drive, prepare, round};
use crate::tracker::{SourceError, VirtualChainSource};
use crate::watcher::{Refusal, Retention, WatchState};
use impulse_core::decode::encode_raw;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_wrpc_client::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---- helpers ----

pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "impulse-watch-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A terms file (`terms`, `canonical`, `terms_hash`) from golden vector `n`.
pub(super) fn write_terms_file(dir: &TempDir, name: &str, n: u8) -> PathBuf {
    let v: serde_json::Value = serde_json::from_str(vector_json(n)).unwrap();
    let file = json!({
        "terms": v["terms"],
        "canonical": v["canonical"],
        "terms_hash": v["terms_hash"],
    });
    let path = dir.file(name);
    std::fs::write(&path, file.to_string()).unwrap();
    path
}

pub(super) fn write_signed_tx(dir: &TempDir, name: &str, tx: &Transaction) -> PathBuf {
    let path = dir.file(name);
    std::fs::write(&path, format!("{}\n", hex(&encode_raw(tx)))).unwrap();
    path
}

/// The accepted control for `prepare`: a new mainnet state, trade 2, N = 10.
pub(super) fn run_args(dir: &TempDir) -> RunArgs {
    RunArgs {
        network: NetworkArg::Mainnet,
        node: "ws://127.0.0.1:17110".into(),
        finality_depth: 10,
        state: dir.file("state.json"),
        init: true,
        trades: vec![write_terms_file(dir, "trade2.json", 2)],
        linked: vec![],
        keep_signed: vec![],
        retire: vec![],
        retention_daa: None,
        poll_interval_ms: 0,
        max_polls: Some(1),
        max_failed_polls: None,
        log_format: crate::cli::LogFormat::Text,
    }
}

pub(super) fn code_of<T: std::fmt::Debug>(r: Result<T, WatchError>) -> &'static str {
    r.unwrap_err().code()
}

// ---- the node's walk converted ----

pub(super) fn rpc_tx(tx: &Transaction, spent: &[UtxoEntry]) -> RpcOptionalTransaction {
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

/// A version 0 transaction (sigop count) as the fake chain makes them.
pub(super) fn v0() -> (Transaction, Vec<UtxoEntry>) {
    let t = tx(
        5,
        vec![plain_in(), plain_in()],
        vec![(1_000, stranger()), (2_000, stranger())],
    );
    (t.tx().clone(), t.spent().to_vec())
}

/// A version 1 transaction (compute budget, mass commitment, a covenant-bound output).
fn v1() -> (Transaction, Vec<UtxoEntry>) {
    let prev = |n: u64| TransactionOutpoint::new(Hash::from_u64_word(n), 0);
    let inputs = vec![
        TransactionInput::new_with_compute_budget(prev(7), plain(), 0, 3),
        TransactionInput::new_with_compute_budget(prev(8), plain(), 0, 4),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(
            1_000,
            stranger(),
            Some(CovenantBinding::new(1, Hash::from_u64_word(0xc0de))),
        ),
        TransactionOutput::new(2_000, stranger()),
    ];
    let t = Transaction::new_with_mass(
        1,
        inputs,
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"payload".to_vec(),
        4_321,
    );
    (t, vec![utxo(10_000, stranger()), utxo(11_000, stranger())])
}

type Mutator = fn(&mut RpcOptionalTransaction);

#[test]
fn a_complete_v2_transaction_converts_with_its_id_and_spent_entries() {
    for (tx, spent) in [v0(), v1()] {
        let converted = convert_transaction(&rpc_tx(&tx, &spent)).unwrap();
        assert_eq!(converted.tx().id(), tx.id());
        assert_eq!(hashing::tx::id(converted.tx()), tx.id());
        assert_eq!(converted.tx().inputs, tx.inputs);
        assert_eq!(converted.tx().outputs, tx.outputs);
        assert_eq!(converted.tx().storage_mass(), tx.storage_mass());
        assert_eq!(converted.tx().payload, tx.payload);
        assert_eq!(converted.spent(), &spent[..]);
    }
}

#[test]
fn a_transaction_missing_a_field_the_watcher_needs_is_refused() {
    let both: [(&str, Mutator); 16] = [
        ("transaction version", |t| t.version = None),
        ("outpoint of input 0", |t| {
            t.inputs[0].previous_outpoint = None
        }),
        ("outpoint txid of input 0", |t| {
            t.inputs[0]
                .previous_outpoint
                .as_mut()
                .unwrap()
                .transaction_id = None
        }),
        ("outpoint index of input 0", |t| {
            t.inputs[0].previous_outpoint.as_mut().unwrap().index = None
        }),
        ("signature script of input 0", |t| {
            t.inputs[0].signature_script = None
        }),
        ("sequence of input 0", |t| t.inputs[0].sequence = None),
        ("spent UTXO entry of input 0", |t| {
            t.inputs[0].verbose_data = None
        }),
        ("spent UTXO entry of input 0", |t| {
            t.inputs[0].verbose_data.as_mut().unwrap().utxo_entry = None
        }),
        ("spent UTXO entry of input 0", |t| {
            t.inputs[0]
                .verbose_data
                .as_mut()
                .unwrap()
                .utxo_entry
                .as_mut()
                .unwrap()
                .amount = None
        }),
        ("value of output 0", |t| t.outputs[0].value = None),
        ("script of output 0", |t| {
            t.outputs[0].script_public_key = None
        }),
        ("lock time", |t| t.lock_time = None),
        ("subnetwork id", |t| t.subnetwork_id = None),
        ("gas", |t| t.gas = None),
        ("payload", |t| t.payload = None),
        ("storage mass", |t| t.storage_mass = None),
    ];
    for (tx, spent) in [v0(), v1()] {
        let complete = rpc_tx(&tx, &spent);
        assert!(convert_transaction(&complete).is_ok());
        for (what, mutate) in &both {
            let mut broken = complete.clone();
            mutate(&mut broken);
            let e = convert_transaction(&broken).unwrap_err();
            assert!(e.0.contains(what), "{what}: {e}");
        }
        let mut broken = complete.clone();
        broken.verbose_data = None;
        let e = convert_transaction(&broken).unwrap_err();
        assert!(e.0.contains("transaction id"), "{e}");
    }
    // The commitment each version carries, and only that one.
    let (tx, spent) = v0();
    let mut broken = rpc_tx(&tx, &spent);
    broken.inputs[1].sig_op_count = None;
    assert!(convert_transaction(&broken)
        .unwrap_err()
        .0
        .contains("sigop count of input 1"));
    let (tx, spent) = v1();
    let mut broken = rpc_tx(&tx, &spent);
    broken.inputs[1].compute_budget = None;
    assert!(convert_transaction(&broken)
        .unwrap_err()
        .0
        .contains("compute budget of input 1"));
    // A v0 transaction needs no compute budget, a v1 transaction no sigop count.
    let (tx, spent) = v0();
    let mut ok = rpc_tx(&tx, &spent);
    ok.inputs[0].compute_budget = None;
    assert!(convert_transaction(&ok).is_ok());
    let (tx, spent) = v1();
    let mut ok = rpc_tx(&tx, &spent);
    ok.inputs[0].sig_op_count = None;
    assert!(convert_transaction(&ok).is_ok());
}

#[test]
fn a_transaction_whose_rebuilt_id_differs_from_the_nodes_is_refused() {
    let (tx, spent) = v0();
    let control = rpc_tx(&tx, &spent);
    assert!(convert_transaction(&control).is_ok());
    // A value the ID covers, changed.
    let mut broken = control.clone();
    broken.outputs[0].value = Some(1_001);
    let e = convert_transaction(&broken).unwrap_err();
    assert!(e.0.contains("rebuilds to"), "{e}");
    // The node's ID is another one.
    let mut broken = control;
    broken.verbose_data.as_mut().unwrap().transaction_id = Some(Hash::from_u64_word(99));
    assert!(convert_transaction(&broken)
        .unwrap_err()
        .0
        .contains("rebuilds to"));
}

#[test]
fn a_covenant_binding_the_node_omits_fails_the_id_check() {
    // Version 1 IDs cover the output's covenant binding, so a node that dropped the binding
    // cannot pass an unbound output off as the transaction.
    let (tx, spent) = v1();
    let control = rpc_tx(&tx, &spent);
    let converted = convert_transaction(&control).unwrap();
    assert_eq!(converted.tx().outputs[0].covenant, tx.outputs[0].covenant);
    assert!(converted.tx().outputs[0].covenant.is_some());
    let mut broken = control;
    broken.outputs[0].covenant = None;
    assert!(convert_transaction(&broken)
        .unwrap_err()
        .0
        .contains("rebuilds to"));
}

pub(super) fn batch(
    hash: BlockHash,
    daa: Option<u64>,
    txs: Vec<RpcOptionalTransaction>,
) -> RpcChainBlockAcceptedTransactions {
    RpcChainBlockAcceptedTransactions {
        chain_block_header: RpcOptionalHeader {
            hash: Some(hash),
            daa_score: daa,
            ..Default::default()
        },
        accepted_transactions: txs,
    }
}

pub(super) fn response(
    removed: Vec<BlockHash>,
    added: Vec<BlockHash>,
    batches: Vec<RpcChainBlockAcceptedTransactions>,
) -> GetVirtualChainFromBlockV2Response {
    GetVirtualChainFromBlockV2Response {
        removed_chain_block_hashes: Arc::new(removed),
        added_chain_block_hashes: Arc::new(added),
        chain_block_accepted_transactions: Arc::new(batches),
    }
}

#[test]
fn a_v2_walk_converts_block_by_block_and_refuses_what_does_not_line_up() {
    let (t0, s0) = v0();
    let (t1, s1) = v1();
    let good = || {
        response(
            vec![block(9), block(8)],
            vec![block(1), block(2)],
            vec![
                batch(block(1), Some(100), vec![rpc_tx(&t0, &s0)]),
                batch(
                    block(2),
                    Some(101),
                    vec![rpc_tx(&t1, &s1), rpc_tx(&t0, &s0)],
                ),
            ],
        )
    };
    let update = convert_walk(&good()).unwrap();
    // Removed blocks keep the node's order (tip first); added blocks carry hash, DAA score and
    // their transactions in the node's order.
    assert_eq!(update.removed_chain_block_hashes, vec![block(9), block(8)]);
    let added: Vec<(BlockHash, u64, Vec<TransactionId>)> = update
        .added_chain_blocks
        .iter()
        .map(|b| {
            (
                b.hash,
                b.daa_score,
                b.accepted_transactions
                    .iter()
                    .map(|t| t.tx().id())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        added,
        vec![
            (block(1), 100, vec![t0.id()]),
            (block(2), 101, vec![t1.id(), t0.id()])
        ]
    );

    // Fewer batches than added blocks (or the reverse).
    let mut r = good();
    Arc::make_mut(&mut r.chain_block_accepted_transactions).pop();
    assert!(convert_walk(&r)
        .unwrap_err()
        .0
        .contains("2 added chain blocks, 1 accepted"));
    let mut r = good();
    Arc::make_mut(&mut r.added_chain_block_hashes).pop();
    assert!(convert_walk(&r)
        .unwrap_err()
        .0
        .contains("1 added chain blocks, 2 accepted"));
    // Batches in another order than the added blocks.
    let mut r = good();
    Arc::make_mut(&mut r.added_chain_block_hashes).swap(0, 1);
    assert!(convert_walk(&r).unwrap_err().0.contains("names"));
    // A header with no hash, or no DAA score.
    let mut r = good();
    Arc::make_mut(&mut r.chain_block_accepted_transactions)[0]
        .chain_block_header
        .hash = None;
    assert!(convert_walk(&r).unwrap_err().0.contains("names None"));
    let mut r = good();
    Arc::make_mut(&mut r.chain_block_accepted_transactions)[1]
        .chain_block_header
        .daa_score = None;
    assert!(convert_walk(&r)
        .unwrap_err()
        .0
        .contains("DAA score of chain block"));
    // A bad transaction fails the whole walk and names its chain block.
    let mut r = good();
    Arc::make_mut(&mut r.chain_block_accepted_transactions)[1].accepted_transactions[1].gas = None;
    let e = convert_walk(&r).unwrap_err();
    assert!(
        e.0.contains(&format!("chain block {}", block(2))) && e.0.contains("gas"),
        "{e}"
    );
    // An empty walk is a walk.
    let empty = convert_walk(&response(vec![], vec![], vec![])).unwrap();
    assert!(empty.added_chain_blocks.is_empty() && empty.removed_chain_block_hashes.is_empty());
}

// ---- the link and the node's identity ----

#[test]
fn mainnet_needs_a_private_link_and_testnet_does_not() {
    let ok = [
        "wss://node.example:443",
        "ws://127.0.0.1:17110",
        "ws://127.0.0.1",
        "ws://localhost:17110/path",
        "ws://[::1]:17110",
    ];
    for url in ok {
        assert!(check_transport(url, Network::Mainnet).is_ok(), "{url}");
    }
    let insecure = [
        "ws://10.0.0.5:17110",
        "ws://node.example",
        "ws://127.0.0.1.evil.example:17110",
        "ws://localhost:abc",
        "ws://localhost:",
        "ws://[::1]x:17110",
        "ws://user@127.0.0.1:17110",
    ];
    for url in insecure {
        assert_eq!(
            code_of(check_transport(url, Network::Mainnet)),
            "WATCH_NODE_INSECURE",
            "{url}"
        );
        // Control: the same URL on testnet.
        assert!(check_transport(url, Network::Testnet).is_ok(), "{url}");
    }
    for url in [
        "http://127.0.0.1:17110",
        "127.0.0.1:17110",
        "ws://",
        "wss://",
        "ws://a b",
        "",
    ] {
        for network in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                code_of(check_transport(url, network)),
                "WATCH_NODE_URL_INVALID",
                "{url}"
            );
        }
    }
}

fn server_info(network_id: NetworkId, synced: bool) -> GetServerInfoResponse {
    GetServerInfoResponse {
        rpc_api_version: 1,
        rpc_api_revision: 0,
        server_version: "2.1.0".into(),
        network_id,
        has_utxo_index: false,
        is_synced: synced,
        virtual_daa_score: 1,
    }
}

#[test]
fn the_node_must_be_on_the_watched_network_and_synced() {
    let mainnet = NetworkId::new(NetworkType::Mainnet);
    let tn10 = NetworkId::with_suffix(NetworkType::Testnet, 10);
    assert!(check_server_info(&server_info(mainnet, true), Network::Mainnet).is_ok());
    assert!(check_server_info(&server_info(tn10, true), Network::Testnet).is_ok());
    for (info, network) in [
        (server_info(tn10, true), Network::Mainnet),
        (server_info(mainnet, true), Network::Testnet),
        (
            server_info(NetworkId::new(NetworkType::Devnet), true),
            Network::Mainnet,
        ),
        (
            server_info(NetworkId::new(NetworkType::Simnet), true),
            Network::Testnet,
        ),
    ] {
        assert_eq!(
            code_of(check_server_info(&info, network)),
            "WATCH_NODE_NETWORK_MISMATCH"
        );
    }
    // Not synced, on the right network (and the network is checked first).
    assert_eq!(
        code_of(check_server_info(
            &server_info(mainnet, false),
            Network::Mainnet
        )),
        "WATCH_NODE_NOT_SYNCED"
    );
    assert_eq!(
        code_of(check_server_info(
            &server_info(tn10, false),
            Network::Mainnet
        )),
        "WATCH_NODE_NETWORK_MISMATCH"
    );
}

#[test]
fn a_node_that_has_the_transaction_in_its_mempool_has_done_what_a_rebroadcast_is_for() {
    let me = Hash::from_u64_word(1);
    let other = Hash::from_u64_word(2);
    let in_pool = format!("transaction {me} is already in the mempool");
    let accepted = format!("transaction {me} was already accepted by the consensus");
    assert!(node_has_in_mempool(&in_pool, &me));
    assert!(node_has_in_mempool(&format!("rejected: {in_pool}"), &me));
    // Another transaction's message, other refusals, and the other message: the node's record
    // of a block's transactions is not its mempool.
    assert!(!node_has_in_mempool(&in_pool, &other));
    assert!(!node_has_in_mempool(&accepted, &me));
    assert!(!node_has_in_mempool(
        "transaction is already in the mempool",
        &me
    ));
    assert!(!node_has_in_mempool(
        &format!("transaction {me} is an orphan"),
        &me
    ));
    assert!(!node_has_in_mempool(
        &format!("input of {me} already spent by transaction {other}"),
        &me
    ));
}

#[test]
fn a_node_that_only_remembers_the_transaction_as_accepted_is_told_apart() {
    let me = Hash::from_u64_word(1);
    let other = Hash::from_u64_word(2);
    let in_pool = format!("transaction {me} is already in the mempool");
    let accepted = format!("transaction {me} was already accepted by the consensus");
    assert!(node_recently_accepted(&accepted, &me));
    assert!(node_recently_accepted(
        &format!("rejected: {accepted}"),
        &me
    ));
    assert!(!node_recently_accepted(&accepted, &other));
    assert!(!node_recently_accepted(&in_pool, &me));
    assert!(!node_recently_accepted(
        "was already accepted by the consensus",
        &me
    ));
}

// ---- files ----

#[test]
fn a_terms_file_is_read_by_its_canonical_bytes_and_hash() {
    let v: serde_json::Value = serde_json::from_str(vector_json(2)).unwrap();
    let file = |canonical: &str, hash: &str| {
        json!({"terms": v["terms"], "canonical": canonical, "terms_hash": hash}).to_string()
    };
    let canonical = v["canonical"].as_str().unwrap();
    let hash = v["terms_hash"].as_str().unwrap();
    let t = parse_terms_file("f", &file(canonical, hash)).unwrap();
    assert_eq!(t.terms_hash().to_vec(), unhex(hash));

    let code = |text: &str| code_of(parse_terms_file("f", text));
    // Not a terms file: not JSON, a key twice, another key set, uppercase hex, canonical bytes
    // that are not terms.
    assert_eq!(code("not json"), "WATCH_TERMS_FILE_INVALID");
    assert_eq!(code("[]"), "WATCH_TERMS_FILE_INVALID");
    let twice =
        file(canonical, hash).replacen("\"canonical\"", "\"terms_hash\":\"00\",\"canonical\"", 1);
    assert_eq!(code(&twice), "WATCH_TERMS_FILE_INVALID");
    assert_eq!(
        code(&json!({"terms": v["terms"], "canonical": canonical}).to_string()),
        "WATCH_TERMS_FILE_INVALID"
    );
    assert_eq!(
        code(
            &json!({"terms": v["terms"], "canonical": canonical, "terms_hash": hash, "name": "x"})
                .to_string()
        ),
        "WATCH_TERMS_FILE_INVALID"
    );
    assert_eq!(
        code(&file(&canonical.to_uppercase(), hash)),
        "WATCH_TERMS_FILE_INVALID"
    );
    assert_eq!(
        code(&file(&canonical[..canonical.len() - 2], hash)),
        "WATCH_TERMS_FILE_INVALID"
    );
    assert_eq!(code(&file("", hash)), "WATCH_TERMS_FILE_INVALID");
    assert_eq!(
        code(&file(canonical, &hash[..62])),
        "WATCH_TERMS_FILE_INVALID"
    );
    // The hash is not the hash of the canonical bytes.
    let other = format!(
        "{}{}",
        if hash.starts_with('0') { "1" } else { "0" },
        &hash[1..]
    );
    assert_eq!(
        code(&file(canonical, &other)),
        "WATCH_TERMS_FILE_INCONSISTENT"
    );
}

#[test]
fn a_signed_transaction_file_is_the_raw_form_in_hex() {
    let (tx, _) = v0();
    let raw = hex(&encode_raw(&tx));
    assert_eq!(parse_signed_tx("f", &raw).unwrap().id(), tx.id());
    assert_eq!(
        parse_signed_tx("f", &format!("{raw}\n")).unwrap().id(),
        tx.id()
    );
    let code = |text: &str| code_of(parse_signed_tx("f", text));
    assert_eq!(code(""), "WATCH_SIGNED_TX_INVALID");
    assert_eq!(code(&raw.to_uppercase()), "WATCH_SIGNED_TX_INVALID");
    assert_eq!(code(&format!("{raw}\n\n")), "WATCH_SIGNED_TX_INVALID");
    assert_eq!(code(&format!("{raw} ")), "WATCH_SIGNED_TX_INVALID");
    assert_eq!(code(&raw[..raw.len() - 2]), "WATCH_SIGNED_TX_INVALID");
    // Bytes left over after the transaction.
    assert_eq!(code(&format!("{raw}00")), "WATCH_SIGNED_TX_INVALID");
    // A carried ID that is not the ID of the contents: the last 32 bytes.
    let mut bytes = encode_raw(&tx);
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    assert_eq!(code(&hex(&bytes)), "WATCH_SIGNED_TX_INVALID");
}

// ---- the state file ----

/// A watcher over trade 2 that has seen the funding and a settle (kept), with a node whose
/// chain can be reorged: `(watcher, node, source, funding, settle)`.
pub(super) struct Scenario {
    pub(super) w: Watcher,
    pub(super) source: FakeVirtualChainSource,
    pub(super) funding: AcceptedTransaction,
    pub(super) settle: AcceptedTransaction,
}

pub(super) async fn scenario(depth: u64) -> Scenario {
    let KasTrade {
        mut w,
        funding,
        settle,
        ..
    } = kas_trade(depth);
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle.clone()]);
    w.poll(&source).await.unwrap();
    Scenario {
        w,
        source,
        funding,
        settle,
    }
}

/// The state through its text and back, with the trade added again.
pub(super) fn through_text(w: Watcher, depth: u64) -> Watcher {
    let text = persist::encode(w.state(), Network::Mainnet);
    let state = persist::decode(&text, Network::Mainnet).unwrap();
    assert_eq!(
        persist::encode(&state, Network::Mainnet),
        text,
        "round trip"
    );
    let mut w = Watcher::with_state(Network::Mainnet, FinalityPolicy::new(depth).unwrap(), state);
    w.add_trade(terms(2)).unwrap();
    w
}

#[tokio::test]
async fn the_state_file_round_trips_and_a_restart_through_it_loses_nothing() {
    let Scenario {
        w,
        source,
        funding,
        settle,
    } = scenario(5).await;
    let (funding_id, settle_id) = (id(&funding), id(&settle));
    let text = persist::encode(w.state(), Network::Mainnet);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["format"], FORMAT);
    assert_eq!(v["network"], "mainnet");
    assert_eq!(v["accepted"].as_array().unwrap().len(), 2);
    assert_eq!(v["kept"], json!([settle_id.to_string()]));
    assert_eq!(v["pending"], json!([]));
    assert_eq!(
        v["cursor"],
        json!({"block": block(3).to_string(), "daa": "102"})
    );

    // Restart: the acceptances and the cursor come back, and finality is reported once, after.
    let mut w2 = through_text(
        Watcher::with_state(
            Network::Mainnet,
            FinalityPolicy::new(5).unwrap(),
            w.state().clone(),
        ),
        5,
    );
    assert_eq!(w2.tracker().accepting_block(&funding_id), at(2, 101));
    assert_eq!(w2.tracker().accepting_block(&settle_id), at(3, 102));
    source.extend(block(4), 108, vec![]);
    let e = w2.poll(&source).await.unwrap();
    assert_eq!(
        e.iter()
            .map(|e| e.to_json()["event"].clone())
            .collect::<Vec<_>>(),
        vec![json!("final"); 4]
    );
    let mut w3 = through_text(w2, 5);
    source.extend(block(5), 109, vec![]);
    assert!(
        w3.poll(&source).await.unwrap().is_empty(),
        "final is reported once"
    );

    // A reorg of the settle after a restart: the rebroadcast is pending in the file, refused
    // once, still pending in the file, and taken after another restart.
    source.add_block(block(14), block(2), 108, vec![]);
    source.set_sink(block(14));
    let e = w3.poll(&source).await.unwrap();
    assert!(e.iter().all(|e| matches!(
        e,
        Event::Reorg {
            was_final: true,
            ..
        }
    )));
    let mut w4 = through_text(w3, 5);
    assert_eq!(w4.pending_rebroadcasts(), vec![settle_id]);
    let node = FakeBroadcaster::refusing_first(&["busy"]);
    let r = drain(&mut w4, &node).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].to_json()["outcome"], "refused");
    let mut w5 = through_text(w4, 5);
    assert!(
        drain(&mut w5, &node).await.is_empty(),
        "one attempt per poll"
    );
    source.extend(block(15), 110, vec![]);
    w5.poll(&source).await.unwrap();
    let r = drain(&mut w5, &node).await;
    assert_eq!(r[0].to_json()["attempt"], 2);
    assert_eq!(r[0].to_json()["outcome"], "submitted");
    assert_eq!(node.handed().len(), 2);
    assert!(node.handed().iter().all(|t| *t == *settle.tx()));
}

pub(super) fn mutate_state(text: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut v: serde_json::Value = serde_json::from_str(text).unwrap();
    edit(&mut v);
    v.to_string()
}

#[tokio::test]
async fn a_state_file_that_is_not_exactly_the_accepted_form_is_refused() {
    let Scenario {
        mut w,
        source,
        funding,
        settle,
    } = scenario(5).await;
    let accepted_text = persist::encode(w.state(), Network::Mainnet);
    // A pending rebroadcast: the settle reorged out.
    source.add_block(block(14), block(2), 103, vec![]);
    source.set_sink(block(14));
    w.poll(&source).await.unwrap();
    let pending_text = persist::encode(w.state(), Network::Mainnet);
    assert!(persist::decode(&accepted_text, Network::Mainnet).is_ok());
    assert!(persist::decode(&pending_text, Network::Mainnet).is_ok());

    let bad = |text: &str| match persist::decode(text, Network::Mainnet) {
        Err(WatchError::StateInvalid(reason)) => reason,
        other => panic!("expected WATCH_STATE_INVALID, got {other:?}"),
    };
    let funding_raw = hex(&encode_raw(funding.tx()));
    let settle_id = id(&settle).to_string();
    let funding_id = id(&funding).to_string();

    // Shape.
    assert!(bad("").contains("not JSON"));
    assert!(bad("[]").contains("expected an object"));
    bad(&mutate_state(&accepted_text, |v| {
        v["extra"] = json!(1);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["format"] = json!("other");
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["version"] = json!(2);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["version"] = json!("1");
    }));
    // A key named twice (the last would win in a lenient reader).
    let twice = accepted_text.replacen("\"kept\"", "\"kept\": [], \"kept\"", 1);
    assert!(bad(&twice).contains("duplicate key"));
    // Hex and numbers in the one spelling.
    bad(&accepted_text.replace(&funding_id, &funding_id.to_uppercase()));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["daa"] = json!("0101");
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["daa"] = json!(101);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["effects"][0]["index"] = json!(-1);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["effects"][0]["leg"] = json!("both");
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["effects"][0]["kind"] = json!("rewarded");
    }));
    // Consistency: an effect of a trade the state does not hold; two trades or two txids listed
    // twice; accepted without a cursor.
    bad(&mutate_state(&accepted_text, |v| {
        v["trades"] = json!([]);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        let t = v["trades"][0].clone();
        v["trades"].as_array_mut().unwrap().push(t);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        let a = v["accepted"][0].clone();
        v["accepted"].as_array_mut().unwrap().push(a);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        let k = v["kept"][0].clone();
        v["kept"].as_array_mut().unwrap().push(k);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["cursor"] = json!(null);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][0]["effects"] = json!([]);
    }));
    // A transaction carries its accepted copy exactly when it settles or refunds, and the copy
    // is the transaction: the settle without its copy, the funding with one, the settle with
    // the funding's.
    let (spend, plain) = {
        let v: serde_json::Value = serde_json::from_str(&accepted_text).unwrap();
        let i = v["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .position(|a| a["txid"] == json!(settle_id))
            .unwrap();
        (i, 1 - i)
    };
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][spend]["tx"] = json!(null);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][plain]["tx"] = json!(funding_raw);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][spend]["tx"] = json!(funding_raw);
    }));
    bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][spend]["tx"] = json!("00");
    }));
    // The carried ID of the accepted copy (the last 32 bytes) is not the ID of its contents.
    let settle_raw = hex(&encode_raw(settle.tx()));
    let mut tampered = encode_raw(settle.tx());
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered_hex = hex(&tampered);
    assert_ne!(tampered_hex, settle_raw);
    assert!(bad(&mutate_state(&accepted_text, |v| {
        v["accepted"][spend]["tx"] = json!(tampered_hex);
    }))
    .contains("carried ID"));
    assert!(bad(&mutate_state(&pending_text, |v| {
        v["pending"][0]["tx"] = json!(tampered_hex);
    }))
    .contains("carried ID"));
    // A pending rebroadcast is a kept transaction that is not accepted, and is that transaction.
    bad(&mutate_state(&pending_text, |v| {
        v["kept"] = json!([]);
    }));
    bad(&mutate_state(&pending_text, |v| {
        v["pending"][0]["tx"] = json!(funding_raw);
    }));
    bad(&mutate_state(&pending_text, |v| {
        let p = v["pending"][0].clone();
        v["pending"].as_array_mut().unwrap().push(p);
    }));
    bad(&mutate_state(&pending_text, |v| {
        v["pending"][0]["attempts"] = json!(-1);
    }));
    bad(&mutate_state(&pending_text, |v| {
        let trade = v["trades"][0]["trade"].clone();
        v["accepted"].as_array_mut().unwrap().push(json!({
            "txid": settle_id,
            "block": block(3).to_string(),
            "daa": "102",
            "finalized": false,
            "settle_expiry": "5",
            "tx": hex(&encode_raw(settle.tx())),
            "effects": [{"kind": "settled", "trade": trade, "leg": "cash",
                "input": 1, "spent_txid": block(1).to_string(), "spent_index": 1, "spent_value": "1"}],
        }));
    }));

    // Another network is its own refusal.
    match persist::decode(&accepted_text, Network::Testnet) {
        Err(e @ WatchError::StateMismatch { .. }) => {
            assert_eq!(e.code(), "WATCH_STATE_MISMATCH");
            assert!(e.to_string().contains("mainnet") && e.to_string().contains("testnet"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_state_file_is_replaced_atomically_and_privately() {
    let dir = TempDir::new();
    let path = dir.file("state.json");
    persist::write_atomic(&path, "first, and longer than the second\n").unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "first, and longer than the second\n"
    );
    persist::write_atomic(&path, "second\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["state.json"], "no temporary file is left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// Failures that hold for every user, root included (a permission check is no failure under
/// root, which is who CI runs as): a name too long for the temporary file, a parent that is a
/// file, and a directory in the state file's place. Each is asserted unconditionally.
#[test]
fn a_state_file_that_cannot_be_written_leaves_the_previous_one_untouched() {
    let dir = TempDir::new();
    // The state file's own name just fits; the temporary file's, which adds to it, does not
    // (ENAMETOOLONG), so the previous file is there and the temporary file cannot be made.
    let long = dir.file(&"s".repeat(230));
    std::fs::write(&long, "previous\n").unwrap();
    let e = persist::write_atomic(&long, "next\n").unwrap_err();
    assert_eq!(e.code(), "WATCH_STATE_WRITE_FAILED");
    assert_eq!(std::fs::read_to_string(&long).unwrap(), "previous\n");

    // The parent of the state file is a file.
    std::fs::write(dir.file("a-file"), "x").unwrap();
    let e = persist::write_atomic(&dir.file("a-file").join("state.json"), "next\n").unwrap_err();
    assert_eq!(e.code(), "WATCH_STATE_WRITE_FAILED");
    assert_eq!(std::fs::read_to_string(dir.file("a-file")).unwrap(), "x");

    // A path that is a directory: the rename fails, the directory is as it was and the
    // temporary file is removed.
    let as_dir = dir.file("as-dir");
    std::fs::create_dir(&as_dir).unwrap();
    std::fs::write(as_dir.join("keep"), "x").unwrap();
    let e = persist::write_atomic(&as_dir, "next\n").unwrap_err();
    assert_eq!(e.code(), "WATCH_STATE_WRITE_FAILED");
    assert!(as_dir.is_dir());
    assert_eq!(std::fs::read_to_string(as_dir.join("keep")).unwrap(), "x");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // Control: the same write to a file path succeeds.
    let path = dir.file("state.json");
    persist::write_atomic(&path, "previous\n").unwrap();
    persist::write_atomic(&path, "next\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "next\n");
}

/// The write replaces the file by a rename of a complete new one: the file at the path is a
/// different file afterwards (a write in place would keep the inode), and a reader holding the
/// old file keeps reading the old text.
#[cfg(unix)]
#[test]
fn a_state_file_is_replaced_by_a_new_file_and_not_written_in_place() {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let dir = TempDir::new();
    let path = dir.file("state.json");
    persist::write_atomic(&path, "first\n").unwrap();
    let before = std::fs::metadata(&path).unwrap().ino();
    let mut reader = std::fs::File::open(&path).unwrap();
    persist::write_atomic(&path, "second\n").unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
    let mut old = String::new();
    reader.read_to_string(&mut old).unwrap();
    assert_eq!(old, "first\n", "the old file was never written to");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
}

/// The temporary file is created exclusively: a name already taken, by a symlink planted there
/// included, is never opened and the write goes to the next name.
#[cfg(unix)]
#[test]
fn the_temporary_file_is_created_exclusively_and_a_planted_name_is_skipped() {
    let dir = TempDir::new();
    let path = dir.file("state.json");
    let victim = dir.file("victim");
    std::fs::write(&victim, "victim\n").unwrap();
    let planted = dir.file(".state.json.tmp.planted");
    std::os::unix::fs::symlink(&victim, &planted).unwrap();
    let mut names = vec![dir.file(".state.json.tmp.fresh"), planted.clone()];
    persist::write_atomic_named(&path, "state\n", || names.pop().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim\n");
    assert!(planted.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "state\n");
    assert!(!dir.file(".state.json.tmp.fresh").exists());
}

/// A crash between the write and the rename leaves a temporary file, a full copy of an earlier
/// state; the next start removes it (and a planted link as a link), and nothing else.
#[cfg(unix)]
#[test]
fn leftover_temporary_files_are_removed_and_nothing_else() {
    let dir = TempDir::new();
    let path = dir.file("state.json");
    let victim = dir.file("victim");
    std::fs::write(&victim, "victim\n").unwrap();
    std::fs::write(dir.file(".state.json.tmp.1.2.3"), "copy").unwrap();
    std::os::unix::fs::symlink(&victim, dir.file(".state.json.tmp.link")).unwrap();
    for keep in [
        ".other.json.tmp.1",
        "state.json.tmp.1",
        ".state.json",
        ".state.json.lock",
        "state.json",
    ] {
        std::fs::write(dir.file(keep), "x").unwrap();
    }
    std::fs::create_dir(dir.file(".state.json.tmp.dir")).unwrap();
    assert_eq!(
        persist::remove_leftover_temp_files(&path),
        [".state.json.tmp.1.2.3", ".state.json.tmp.link"]
    );
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim\n");
    assert!(dir.file(".state.json.tmp.dir").is_dir());
    for kept in [
        ".other.json.tmp.1",
        "state.json.tmp.1",
        ".state.json",
        ".state.json.lock",
        "state.json",
    ] {
        assert!(dir.file(kept).exists(), "{kept}");
    }
    // Control: nothing to remove the second time.
    assert!(persist::remove_leftover_temp_files(&path).is_empty());
}

#[test]
fn a_state_file_is_held_by_one_watcher_at_a_time() {
    let dir = TempDir::new();
    let path = dir.file("state.json");
    let first = persist::lock(&path).unwrap();
    assert_eq!(code_of(persist::lock(&path)), "WATCH_STATE_LOCKED");
    // Another state file is another lock.
    let other = persist::lock(&dir.file("other.json")).unwrap();
    drop(first);
    let again = persist::lock(&path).unwrap();
    drop((other, again));
}

// ---- retiring a trade ----

#[tokio::test]
async fn a_retired_trade_leaves_the_state_and_its_events_stop() {
    let Scenario {
        mut w,
        source,
        funding,
        settle,
    } = scenario(5).await;
    let trade = TradeId(terms(2).terms_hash());
    // Control: before retiring, a reorg of the settle is reported.
    let mut control = through_text(
        Watcher::with_state(
            Network::Mainnet,
            FinalityPolicy::new(5).unwrap(),
            w.state().clone(),
        ),
        5,
    );
    source.add_block(block(14), block(2), 103, vec![]);
    source.set_sink(block(14));
    assert!(!control.poll(&source).await.unwrap().is_empty());

    assert_eq!(
        code_of(w.retire_trade(TradeId([9; 32]))),
        "WATCH_TRADE_UNKNOWN"
    );
    w.retire_trade(trade).unwrap();
    assert_eq!(w.accepted_len(), 0);
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(!w.is_kept(&id(&settle)));
    assert_eq!(w.tracker().accepting_block(&id(&funding)), None);
    assert_eq!(w.tracker().accepting_block(&id(&settle)), None);
    assert!(w.state().trades.is_empty());
    // Retired twice is unknown the second time.
    assert_eq!(code_of(w.retire_trade(trade)), "WATCH_TRADE_UNKNOWN");
    // The reorg that control reported is not reported, and nothing is rebroadcast.
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert!(drain(&mut w, &FakeBroadcaster::default()).await.is_empty());
    // A funding of the retired trade is no longer reported.
    let KasTrade { funding: late, .. } = kas_trade(5);
    source.extend(block(15), 110, vec![late]);
    assert!(w.poll(&source).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_trade_of_a_resumed_state_is_retired_without_its_terms() {
    let Scenario { w, source, .. } = scenario(5).await;
    let trade = TradeId(terms(2).terms_hash());
    // Control: resumed and not added again, a poll is refused.
    let state = w.into_state();
    let mut stuck = Watcher::with_state(
        Network::Mainnet,
        FinalityPolicy::new(5).unwrap(),
        state.clone(),
    );
    assert_eq!(
        code_of(stuck.poll(&source).await),
        "WATCH_TRADE_NOT_RESUMED"
    );
    assert_eq!(stuck.unresumed_trades(), vec![trade]);
    // Retired without adding it, the poll goes ahead.
    let mut w = Watcher::with_state(Network::Mainnet, FinalityPolicy::new(5).unwrap(), state);
    w.retire_trade(trade).unwrap();
    assert!(w.unresumed_trades().is_empty());
    assert!(w.poll(&source).await.is_ok());
}

#[tokio::test]
async fn retiring_one_trade_keeps_the_other_trades_effects_of_a_mixed_settle() {
    let node = Node::new();
    let (mut w, ida, idb, [a_asset, _, _, b_cash], names) = two_trades();
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
    let mixed_id = id(&mixed);
    let e = accept_one(&mut w, &node, mixed.clone()).await;
    assert_eq!(
        brief(&e, &names),
        ["accepted settled A/asset", "accepted settled B/cash"]
    );
    w.keep_signed(mixed.tx().clone()).unwrap();

    w.retire_trade(ida).unwrap();
    // The transaction stays accepted for B only: a reorg reports B's effect alone and the
    // kept settle (B's) is still rebroadcast.
    assert_eq!(w.accepted_len(), 1);
    assert!(w.is_kept(&mixed_id));
    node.chain.add_block(block(11), block(0), 100, vec![]);
    node.chain.set_sink(block(11));
    let e = w.poll(&node.chain).await.unwrap();
    assert_eq!(brief(&e, &names), ["reorg settled B/cash"]);
    assert_eq!(w.pending_rebroadcasts(), vec![mixed_id]);
    // Retiring the other as well drops the pending rebroadcast: it settles no watched vault.
    w.retire_trade(idb).unwrap();
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(!w.is_kept(&mixed_id));

    // A rebroadcast already pending when one of the two trades is retired stays pending while
    // the other trade is watched, and goes when the other is retired too.
    let node = Node::new();
    let (mut w, ida, idb, _, _) = two_trades();
    accept_one(&mut w, &node, mixed.clone()).await;
    w.keep_signed(mixed.tx().clone()).unwrap();
    node.chain.add_block(block(11), block(0), 100, vec![]);
    node.chain.set_sink(block(11));
    w.poll(&node.chain).await.unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![mixed_id]);
    w.retire_trade(ida).unwrap();
    assert_eq!(w.pending_rebroadcasts(), vec![mixed_id]);
    assert!(w.is_kept(&mixed_id));
    w.retire_trade(idb).unwrap();
    assert!(w.pending_rebroadcasts().is_empty());
    assert!(!w.is_kept(&mixed_id));
}

// ---- evicting final acceptances ----

#[test]
fn the_retention_window_is_above_the_finality_depth() {
    let n = FinalityPolicy::new(10).unwrap();
    assert_eq!(code_of(Retention::new(10, n)), "WATCH_RETENTION_TOO_SHORT");
    assert_eq!(code_of(Retention::new(0, n)), "WATCH_RETENTION_TOO_SHORT");
    assert_eq!(code_of(Retention::new(9, n)), "WATCH_RETENTION_TOO_SHORT");
    assert_eq!(Retention::new(11, n).unwrap().retain_daa(), 11);
}

/// Trade 2 with its funding accepted at DAA 100, retention `retain` and N = 10.
async fn retained(retain: u64) -> (Watcher, FakeVirtualChainSource, AcceptedTransaction) {
    let KasTrade { mut w, funding, .. } = kas_trade(10);
    w.set_retention(Retention::new(retain, FinalityPolicy::new(10).unwrap()).unwrap());
    let source = started(&mut w).await;
    source.extend(block(2), 100, vec![funding.clone()]);
    w.poll(&source).await.unwrap();
    (w, source, funding)
}

#[tokio::test]
async fn a_final_acceptance_is_evicted_once_it_is_older_than_the_retention_window() {
    let (mut w, source, funding) = retained(15).await;
    assert_eq!(w.accepted_len(), 1);
    // Final at depth 10 and reported, and still held.
    source.extend(block(3), 110, vec![]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(e.len(), 2);
    assert!(e.iter().all(|e| matches!(e, Event::Final { .. })));
    assert_eq!(w.accepted_len(), 1);
    // One short of the window: held. At the window: evicted, after its final was reported.
    source.extend(block(4), 114, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert_eq!(w.accepted_len(), 1);
    source.extend(block(5), 115, vec![]);
    assert!(w.poll(&source).await.unwrap().is_empty());
    assert_eq!(w.accepted_len(), 0);
    assert_eq!(w.tracker().accepting_block(&id(&funding)), None);
    // A reorg deeper than the window is not reported (the price of eviction)...
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 116, vec![]);
    source.set_sink(block(13));
    assert!(w.poll(&source).await.unwrap().is_empty());
}

#[tokio::test]
async fn without_a_retention_window_nothing_is_evicted_and_the_deep_reorg_is_reported() {
    let KasTrade { mut w, funding, .. } = kas_trade(10);
    let source = started(&mut w).await;
    source.extend(block(2), 100, vec![funding.clone()]);
    source.extend(block(3), 130, vec![]);
    w.poll(&source).await.unwrap();
    assert_eq!(w.accepted_len(), 1);
    source.add_block(block(12), block(1), 101, vec![]);
    source.add_block(block(13), block(12), 140, vec![]);
    source.set_sink(block(13));
    let e = w.poll(&source).await.unwrap();
    assert!(e.iter().all(|e| matches!(
        e,
        Event::Reorg {
            was_final: true,
            ..
        }
    )));
    assert_eq!(e.len(), 2);
}

#[tokio::test]
async fn a_kept_transaction_is_never_evicted() {
    let KasTrade {
        mut w,
        funding,
        settle,
        ..
    } = kas_trade(10);
    w.set_retention(Retention::new(15, FinalityPolicy::new(10).unwrap()).unwrap());
    let source = started(&mut w).await;
    w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 100, vec![funding.clone(), settle.clone()]);
    source.extend(block(3), 130, vec![]);
    w.poll(&source).await.unwrap();
    // The funding is evicted, the kept settle stays and is still rebroadcast after a reorg.
    assert_eq!(w.accepted_len(), 1);
    assert_eq!(w.tracker().accepting_block(&id(&funding)), None);
    assert!(w.tracker().accepting_block(&id(&settle)).is_some());
    source.add_block(block(12), block(1), 101, vec![]);
    source.set_sink(block(12));
    let e = w.poll(&source).await.unwrap();
    assert!(e.iter().all(|e| matches!(
        e,
        Event::Reorg {
            was_final: true,
            ..
        }
    )));
    assert_eq!(w.pending_rebroadcasts(), vec![id(&settle)]);
}

// ---- the binary's logic: prepare ----

#[test]
fn prepare_refuses_in_order_and_accepts_the_control() {
    let dir = TempDir::new();
    let control = run_args(&dir);
    {
        let prepared = prepare(&control).unwrap();
        assert!(prepared.notes.is_empty());
        assert_eq!(prepared.watcher.trades().len(), 1);
    }

    let refused = |edit: &dyn Fn(&mut RunArgs, &TempDir)| {
        let dir = TempDir::new();
        let mut a = run_args(&dir);
        edit(&mut a, &dir);
        code_of(prepare(&a).map(|_| ()))
    };
    assert_eq!(
        refused(&|a, _| a.finality_depth = 0),
        "WATCH_FINALITY_DEPTH_ZERO"
    );
    assert_eq!(
        refused(&|a, _| a.retention_daa = Some(10)),
        "WATCH_RETENTION_TOO_SHORT"
    );
    assert_eq!(
        refused(&|a, _| a.node = "http://127.0.0.1:17110".into()),
        "WATCH_NODE_URL_INVALID"
    );
    assert_eq!(
        refused(&|a, _| a.node = "ws://10.0.0.5:17110".into()),
        "WATCH_NODE_INSECURE"
    );
    assert_eq!(
        refused(&|a, _| a.trades.push("/nonexistent/terms.json".into())),
        "WATCH_FILE_READ"
    );
    assert_eq!(
        refused(&|a, _| a.keep_signed.push("/nonexistent/tx.hex".into())),
        "WATCH_FILE_READ"
    );
    assert_eq!(
        refused(&|a, _| a.network = NetworkArg::Testnet),
        "WATCH_NETWORK_MISMATCH"
    );
    // The same trade twice.
    assert_eq!(
        refused(&|a, _| a.trades.push(a.trades[0].clone())),
        "WATCH_TRADE_DUPLICATE"
    );
    // Retired and watched in one run.
    assert_eq!(
        refused(&|a, _| a.retire.push(TradeId(terms(2).terms_hash()))),
        "WATCH_RETIRE_WATCHED"
    );
    // A new state file that exists; a state file that does not exist.
    assert_eq!(
        refused(&|a, _| std::fs::write(&a.state, "x").unwrap()),
        "WATCH_STATE_EXISTS"
    );
    assert_eq!(refused(&|a, _| a.init = false), "WATCH_STATE_MISSING");
    // Direct terms have no vault to watch.
    assert_eq!(
        refused(&|a, dir| a.trades = vec![write_terms_file(dir, "direct.json", 7)]),
        "TEMPLATE_NO_VAULT"
    );
}

#[test]
fn prepare_refuses_a_bad_terms_file_a_bad_signed_file_and_an_untracked_transaction() {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    // Control: a settle of the watched trade is kept.
    let KasTrade { settle, .. } = kas_trade(10);
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];
    assert!(prepare(&a).is_ok());

    let dir = TempDir::new();
    let mut a = run_args(&dir);
    std::fs::write(dir.file("bad-terms.json"), "{}").unwrap();
    a.trades.push(dir.file("bad-terms.json"));
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_TERMS_FILE_INVALID");

    let dir = TempDir::new();
    let mut a = run_args(&dir);
    std::fs::write(dir.file("bad-tx.hex"), "zz").unwrap();
    a.keep_signed = vec![dir.file("bad-tx.hex")];
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_SIGNED_TX_INVALID");

    // A well-formed transaction that settles no watched vault.
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    let (stranger_tx, _) = v0();
    a.keep_signed = vec![write_signed_tx(&dir, "other.hex", &stranger_tx)];
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_TX_NOT_TRACKED");
}

#[test]
fn prepare_resumes_a_state_and_refuses_what_would_drop_a_trade_silently() {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    persist::write_atomic(
        &a.state,
        &persist::encode(prepare(&a).unwrap().watcher.state(), Network::Mainnet),
    )
    .unwrap();
    a.init = false;
    // Control: the same command line again resumes, the trade added again and nothing noted.
    {
        let again = prepare(&a).unwrap();
        assert!(again.notes.is_empty());
    }
    // The terms file is not given again: refused before any node is contacted.
    let mut missing = run_args(&dir);
    missing.init = false;
    missing.trades = vec![];
    let e = prepare(&missing).map(|_| ()).unwrap_err();
    assert_eq!(e.code(), "WATCH_TRADE_NOT_RESUMED");
    assert!(e
        .to_string()
        .contains(&TradeId(terms(2).terms_hash()).to_string()));
    // ... unless it is retired by hash, which is the explicit way to drop it.
    missing.retire = vec![TradeId(terms(2).terms_hash())];
    let retired = prepare(&missing).unwrap();
    assert_eq!(retired.notes.len(), 1);
    assert!(retired.notes[0].starts_with("retired trade"));
    drop(retired);
    // Retiring a hash the state does not hold.
    let mut unknown = run_args(&dir);
    unknown.init = false;
    unknown.retire = vec![TradeId([9; 32])];
    assert_eq!(
        code_of(prepare(&unknown).map(|_| ())),
        "WATCH_TRADE_UNKNOWN"
    );
    // A state file that is not a state, and one of another network.
    std::fs::write(&a.state, "{}").unwrap();
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_INVALID");
    std::fs::write(
        &a.state,
        persist::encode(&WatchState::default(), Network::Testnet),
    )
    .unwrap();
    assert_eq!(code_of(prepare(&a).map(|_| ())), "WATCH_STATE_MISMATCH");
}

#[test]
fn prepare_holds_the_state_file_and_a_second_watcher_is_refused() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let first = prepare(&a).unwrap();
    let mut b = run_args(&dir);
    b.init = true;
    assert_eq!(code_of(prepare(&b).map(|_| ())), "WATCH_STATE_LOCKED");
    drop(first);
    assert!(prepare(&b).is_ok());
}

#[tokio::test]
async fn a_kept_transaction_named_again_on_restart_is_not_an_error() {
    let dir = TempDir::new();
    let KasTrade { settle, .. } = kas_trade(10);
    let mut a = run_args(&dir);
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];
    let mut first = prepare(&a).unwrap();
    assert!(first.watcher.is_kept(&id(&settle)));
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    drive(
        &mut first,
        &node,
        Duration::ZERO,
        Some(1),
        &mut out,
        &mut err,
    )
    .await
    .unwrap();
    drop(first);
    a.init = false;
    let again = prepare(&a).unwrap();
    assert!(again.watcher.is_kept(&id(&settle)));
}

// ---- the binary's logic: drive ----

/// One value that is both the chain and the node's submit, as the wRPC client is.
pub(super) struct Both<'a> {
    pub(super) chain: &'a FakeVirtualChainSource,
    pub(super) submit: &'a FakeBroadcaster,
}

impl<'a> Both<'a> {
    pub(super) fn new(chain: &'a FakeVirtualChainSource, submit: &'a FakeBroadcaster) -> Self {
        Self { chain, submit }
    }
}

impl VirtualChainSource for Both<'_> {
    async fn get_virtual_chain_from(
        &self,
        start_hash: BlockHash,
    ) -> Result<VirtualChainUpdate, SourceError> {
        self.chain.get_virtual_chain_from(start_hash).await
    }

    async fn sink_hash(&self) -> Result<BlockHash, SourceError> {
        self.chain.sink_hash().await
    }

    async fn selected_parent_hash(&self, block_hash: BlockHash) -> Result<BlockHash, SourceError> {
        self.chain.selected_parent_hash(block_hash).await
    }
}

impl Broadcaster for Both<'_> {
    async fn submit(&self, tx: &Transaction) -> Result<(), Refusal> {
        self.submit.submit(tx).await
    }

    async fn virtual_daa_score(&self) -> Result<u64, String> {
        self.submit.virtual_daa_score().await
    }
}

pub(super) fn lines(out: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(out.to_vec())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn a_round_polls_then_rebroadcasts_and_drive_prints_then_saves() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let KasTrade {
        funding, settle, ..
    } = kas_trade(10);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);

    // Round 1 (--init): the bootstrap walk reports nothing and the state file is written.
    let mut p = prepare(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let o = drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(
        o,
        crate::run::Outcome {
            polls: 1,
            failed_polls: 0
        }
    );
    assert!(out.is_empty() && err.is_empty());
    let first = std::fs::read_to_string(&a.state).unwrap();
    assert!(persist::decode(&first, Network::Mainnet).is_ok());

    // Funding accepted, then the kept settle accepted and reorged out in one run of two polls:
    // the events of both polls, the rebroadcast after the second poll's reorg, one state write
    // per round that changed it.
    p.watcher.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle.clone()]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    let kinds: Vec<_> = lines(&out)
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["authorizer_seen", "funded", "settled", "settled"]);
    let second = std::fs::read_to_string(&a.state).unwrap();
    assert_ne!(second, first);
    source.add_block(block(14), block(2), 103, vec![]);
    source.set_sink(block(14));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    let kinds: Vec<_> = lines(&out)
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["reorg", "reorg", "rebroadcast"]);
    assert_eq!(bcast.submitted(), vec![id(&settle)]);
    // An idle round writes nothing: the file is as the last change left it.
    let third = std::fs::read_to_string(&a.state).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(2), &mut out, &mut err)
        .await
        .unwrap();
    assert!(out.is_empty());
    assert_eq!(std::fs::read_to_string(&a.state).unwrap(), third);
}

#[tokio::test]
async fn a_failed_poll_is_reported_counted_and_survived_but_a_refusal_ends_the_run() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    // The first poll fails (bootstrap call), the second goes through.
    source.fail_next(Call::Sink, "node restarting\u{1b}[31m");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let o = drive(&mut p, &node, Duration::ZERO, Some(2), &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(
        o,
        crate::run::Outcome {
            polls: 2,
            failed_polls: 1
        }
    );
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.starts_with("impulse-watch: WATCH_SOURCE_FAILED"),
        "{err}"
    );
    assert_eq!(err.lines().count(), 1);
    assert!(persist::decode(
        &std::fs::read_to_string(&a.state).unwrap(),
        Network::Mainnet
    )
    .is_ok());

    // A state file that cannot be written ends the run, after the events were printed. A
    // directory in its place makes the rename fail whoever runs this.
    let KasTrade { funding, .. } = kas_trade(10);
    source.extend(block(2), 101, vec![funding]);
    std::fs::remove_file(&a.state).unwrap();
    std::fs::create_dir(&a.state).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err).await;
    assert_eq!(r.unwrap_err().code(), "WATCH_STATE_WRITE_FAILED");
    assert_eq!(
        lines(&out).len(),
        2,
        "the events were printed before the save"
    );
}

#[tokio::test]
async fn a_round_is_a_poll_and_its_due_rebroadcasts_and_a_refusal_before_the_node_is_asked() {
    // round() alone: the unresumed-trade refusal comes before any node call.
    let KasTrade { mut w, .. } = kas_trade(10);
    let source = started(&mut w).await;
    let state = w.into_state();
    let mut w = Watcher::with_state(Network::Mainnet, FinalityPolicy::new(10).unwrap(), state);
    let calls = source.start_hashes_seen().len();
    let bcast = FakeBroadcaster::default();
    let both = Both::new(&source, &bcast);
    assert_eq!(
        code_of(round(&mut w, &both).await),
        "WATCH_TRADE_NOT_RESUMED"
    );
    assert_eq!(
        source.start_hashes_seen().len(),
        calls,
        "no walk was asked for"
    );
}

/// One start of the binary's logic: prepare from the files, one poll, the events printed.
pub(super) async fn run_once(node: &Both<'_>, a: &RunArgs) -> Vec<serde_json::Value> {
    let mut p = prepare(a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    lines(&out)
}

#[tokio::test]
async fn the_binary_restarts_from_its_state_file_and_loses_neither_a_final_nor_a_rebroadcast() {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    let KasTrade {
        funding, settle, ..
    } = kas_trade(5);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::refusing_first(&["mempool full"]);
    let node = Both::new(&source, &bcast);
    a.finality_depth = 5;
    a.keep_signed = vec![write_signed_tx(&dir, "settle.hex", settle.tx())];

    run_once(&node, &a).await;
    a.init = false;

    // Accepted, then a restart.
    source.extend(block(2), 101, vec![funding.clone()]);
    source.extend(block(3), 102, vec![settle.clone()]);
    let e = run_once(&node, &a).await;
    assert_eq!(e.len(), 4);
    // Deep enough for finality while the process is down: reported on the next start, once.
    source.extend(block(4), 108, vec![]);
    let e = run_once(&node, &a).await;
    assert_eq!(e.iter().filter(|l| l["event"] == "final").count(), 4);
    assert!(run_once(&node, &a).await.is_empty());
    // Reorged out: the rebroadcast is refused once; the process restarts; it is taken.
    source.add_block(block(14), block(2), 109, vec![]);
    source.set_sink(block(14));
    let e = run_once(&node, &a).await;
    let kinds: Vec<_> = e
        .iter()
        .map(|l| l["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["reorg", "reorg", "rebroadcast"]);
    assert_eq!(e[2]["outcome"], "refused");
    assert_eq!(e[2]["code"], "WATCH_REBROADCAST_FAILED");
    let e = run_once(&node, &a).await;
    assert_eq!(e.len(), 1);
    assert_eq!(e[0]["outcome"], "submitted");
    assert_eq!(e[0]["attempt"], 2);
    assert_eq!(bcast.submitted(), vec![id(&settle), id(&settle)]);
}

#[tokio::test]
async fn a_settle_past_its_expiry_is_still_skipped_after_a_restart_through_the_state_file() {
    let KasTrade {
        mut w,
        names,
        settle,
        ..
    } = kas_trade(10);
    let expiry = terms(2).terms().expiry_daa;
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w.poll(&source).await.unwrap();
    let settle_id = w.keep_signed(settle.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![settle]);
    w.poll(&source).await.unwrap();
    // Restart before the reorg: the earliest expiry of the trades it settles is in the file.
    let mut w = through_text(w, 10);
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry, vec![]);
    source.set_sink(block(13));
    w.poll(&source).await.unwrap();
    // And again once the rebroadcast is pending: its expiry is in the file too.
    let mut w = through_text(w, 10);
    let node = FakeBroadcaster::default();
    let r = drain(&mut w, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast skipped_past_expiry"]);
    assert_eq!(r[0].to_json()["expiry_daa"], json!(expiry.to_string()));
    assert!(node.submitted().is_empty());
    // Control: the same reorg to a tip before the expiry is submitted.
    let KasTrade {
        w: w0, settle: s0, ..
    } = kas_trade(10);
    let mut w0 = w0;
    let source = FakeVirtualChainSource::new(block(0), expiry - 10);
    source.extend(block(1), expiry - 9, vec![]);
    w0.poll(&source).await.unwrap();
    w0.keep_signed(s0.tx().clone()).unwrap();
    source.extend(block(2), expiry - 3, vec![s0]);
    w0.poll(&source).await.unwrap();
    let mut w0 = through_text(w0, 10);
    source.add_block(block(12), block(1), expiry - 3, vec![]);
    source.add_block(block(13), block(12), expiry - 1, vec![]);
    source.set_sink(block(13));
    w0.poll(&source).await.unwrap();
    let mut w0 = through_text(w0, 10);
    let r = drain(&mut w0, &node).await;
    assert_eq!(brief(&r, &names), ["rebroadcast submitted"]);
    assert_eq!(node.submitted(), vec![settle_id]);
}

/// An output that fails after taking `ok` writes.
struct BrokenPipe;

impl Write for BrokenPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "pipe closed",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn an_output_that_fails_ends_the_run_without_saving_the_round() {
    let dir = TempDir::new();
    let a = run_args(&dir);
    let KasTrade { funding, .. } = kas_trade(10);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    let saved = std::fs::read_to_string(&a.state).unwrap();
    // A round with events and an output that fails: refused, and the state file is as it was,
    // so the next start repeats the round.
    source.extend(block(2), 101, vec![funding]);
    let e = drive(
        &mut p,
        &node,
        Duration::ZERO,
        Some(1),
        &mut BrokenPipe,
        &mut err,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code(), "WATCH_OUTPUT_FAILED");
    assert!(e.to_string().contains("pipe closed"));
    assert_eq!(std::fs::read_to_string(&a.state).unwrap(), saved);
    drop(p);
    // Control: the restart, with a working output, reports the round.
    let mut again = a.clone();
    again.init = false;
    let mut p = prepare(&again).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(1), &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(lines(&out).len(), 2);
}

#[test]
fn control_characters_are_written_escaped() {
    use crate::run::escape_control;
    assert_eq!(
        escape_control("plain: text, 'quotes' and unicode é"),
        "plain: text, 'quotes' and unicode é"
    );
    assert_eq!(escape_control("a\u{1b}[31mb"), "a\\u{1b}[31mb");
    assert_eq!(escape_control("one\ntwo\r\tthree"), "one\\ntwo\\r\\tthree");
    assert_eq!(escape_control("\u{7f}\u{0}"), "\\u{7f}\\u{0}");
}

// ---- operations (I14): --max-failed-polls and --log-format ----

#[tokio::test]
async fn max_failed_polls_ends_the_run_after_that_many_failures_in_a_row() {
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    a.max_failed_polls = Some(2);
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    // fail, pass, fail, pass: never two in a row (the count runs across calls of drive, as
    // across the polls of one run), so the bounded runs end by their count.
    source.fail_next(Call::Sink, "down");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let o = drive(&mut p, &node, Duration::ZERO, Some(2), &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(o.failed_polls, 1);
    source.fail_next(Call::Walk, "down");
    let o = drive(&mut p, &node, Duration::ZERO, Some(2), &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(o.failed_polls, 1);
    // Two in a row end the run with WATCH_SOURCE_FAILED naming the count, well before its
    // bound; the state file is the last good round's.
    let before = std::fs::read_to_string(&a.state).unwrap();
    source.fail_next(Call::Walk, "down one");
    source.fail_next(Call::Walk, "down two");
    let mut err = Vec::new();
    let e = drive(&mut p, &node, Duration::ZERO, Some(10), &mut out, &mut err)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "WATCH_SOURCE_FAILED");
    assert!(
        e.to_string()
            .contains("2 polls in a row failed (--max-failed-polls), the last: down two"),
        "{e}"
    );
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.lines().count(), 2, "{err}");
    assert_eq!(std::fs::read_to_string(&a.state).unwrap(), before);
}

#[tokio::test]
async fn json_logs_are_one_object_per_line_with_a_code_and_no_raw_control_characters() {
    use crate::cli::LogFormat;
    use crate::run::{error_log_line, fatal_line, fatal_line_in, log_line};
    let dir = TempDir::new();
    let mut a = run_args(&dir);
    a.log_format = LogFormat::Json;
    let source = FakeVirtualChainSource::new(block(0), 99);
    source.extend(block(1), 100, vec![]);
    let bcast = FakeBroadcaster::default();
    let node = Both::new(&source, &bcast);
    let mut p = prepare(&a).unwrap();
    source.fail_next(Call::Sink, "node restarting\u{1b}[31m\nsecond line");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    drive(&mut p, &node, Duration::ZERO, Some(2), &mut out, &mut err)
        .await
        .unwrap();
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(!err.contains('\u{1b}'));
    let line: serde_json::Value = serde_json::from_str(err.trim_end()).unwrap();
    let keys: Vec<_> = line.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["code", "level", "message", "ts_ms"]);
    assert_eq!(line["code"], "WATCH_SOURCE_FAILED");
    assert_eq!(line["level"], "warn");
    assert!(line["ts_ms"].as_u64().unwrap() > 1_700_000_000_000);
    let message = line["message"].as_str().unwrap();
    assert!(message.starts_with("node call failed: "), "{message}");
    assert!(message.contains("node restarting\u{1b}[31m\nsecond line"));

    // A note has no code; a refusal that ends the run is at level error. The text form is the
    // one the binary always printed.
    let note: serde_json::Value =
        serde_json::from_str(&log_line(LogFormat::Json, "info", None, "retired trade x")).unwrap();
    assert_eq!(note["code"], serde_json::Value::Null);
    assert_eq!(note["level"], "info");
    assert_eq!(
        log_line(LogFormat::Text, "info", None, "a\nb"),
        "impulse-watch: a\\nb"
    );
    let e = WatchError::NodeNotSynced;
    assert_eq!(fatal_line_in(LogFormat::Text, &e), fatal_line(&e));
    assert_eq!(
        error_log_line(LogFormat::Text, "warn", &e),
        "impulse-watch: WATCH_NODE_NOT_SYNCED: the node is not synced"
    );
    let fatal: serde_json::Value =
        serde_json::from_str(&fatal_line_in(LogFormat::Json, &e)).unwrap();
    assert_eq!(fatal["level"], "error");
    assert_eq!(fatal["code"], "WATCH_NODE_NOT_SYNCED");
    assert_eq!(fatal["message"], "the node is not synced");
}
