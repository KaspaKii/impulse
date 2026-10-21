// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Native tests of the node forms (`rpc.rs`) against the real RPC types of the pinned
//! rusty-kaspa (`kaspa-rpc-core`, through `kaspa-wrpc-client`, a native-only dev-dependency): the
//! requests the module writes are what those types serialise, the replies it reads are what those
//! types serialise, and the transaction it writes is one they read back to the same transaction.
//! None of this has run against a node on a network.

use crate::error::{Failure, Refusal, SdkError};
use crate::rpc::{self, METHODS};
use impulse_core::terms::Network;
use kaspa_consensus_core::constants::TX_VERSION_TOCCATA;
use kaspa_consensus_core::mass::ComputeBudget;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput,
};
use kaspa_consensus_core::Hash;
use kaspa_wrpc_client::prelude::{
    GetBlockDagInfoRequest, GetBlockDagInfoResponse, GetMempoolEntryRequest,
    GetMempoolEntryResponse, GetServerInfoRequest, GetServerInfoResponse,
    GetUtxosByAddressesRequest, GetUtxosByAddressesResponse, GetVirtualChainFromBlockV2Request,
    GetVirtualChainFromBlockV2Response, NetworkId, NetworkType, RpcChainBlockAcceptedTransactions,
    RpcDataVerbosityLevel, RpcHash, RpcMempoolEntry, RpcOptionalHeader, RpcOptionalTransaction,
    RpcOptionalTransactionInputVerboseData, RpcOptionalUtxoEntry, RpcTransaction,
    RpcTransactionOutpoint, RpcUtxoEntry, RpcUtxosByAddressesEntry, SubmitTransactionRequest,
    SubmitTransactionResponse,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn h(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn p2sh(n: u8) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, [&[0xaa, 0x20][..], &[n; 32], &[0x87]].concat())
}

fn p2pk(n: u8) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, [&[0x20][..], &[n; 32], &[0xac]].concat())
}

/// A transaction with every field the form carries set to something: version, two inputs with
/// compute budgets and signature scripts, a covenant-bound output, a lock time, a mass.
fn transaction() -> Transaction {
    let inputs = vec![
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(h(1), 0),
            vec![0x41, 1, 2, 3],
            u64::MAX - 1,
            20,
        ),
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(h(2), 7),
            vec![],
            0,
            ComputeBudget(10).into(),
        ),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(
            1_234_567_890_123_456,
            p2sh(3),
            Some(CovenantBinding::new(1, h(9))),
        ),
        TransactionOutput::new(50_000_000, p2pk(4)),
    ];
    Transaction::new_with_mass(
        TX_VERSION_TOCCATA,
        inputs,
        outputs,
        1_500_000,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
        33_664,
    )
}

fn test_address() -> kaspa_addresses::Address {
    kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Testnet,
        kaspa_addresses::Version::PubKey,
        &[0x11; 32],
    )
}

fn frame(id: u64, method: &str, params: Value) -> String {
    json!({ "id": id, "method": method, "params": params }).to_string()
}

fn code<T: std::fmt::Debug>(r: Result<T, impl Refusal>) -> &'static str {
    r.unwrap_err().code()
}

#[test]
fn the_transaction_form_is_the_one_rpc_core_writes_and_reads() {
    let tx = transaction();
    let ours = rpc::rpc_transaction_json(&tx);
    // What rpc-core writes for the same transaction, field for field.
    let theirs = serde_json::to_value(RpcTransaction::from(&tx)).unwrap();
    assert_eq!(ours, theirs);
    // And what it reads back is the transaction, mass included.
    let back: RpcTransaction = serde_json::from_value(ours).unwrap();
    let round = Transaction::try_from(back).unwrap();
    assert_eq!(round, tx);
    assert_eq!(round.storage_mass(), 33_664);
    assert_eq!(round.id(), tx.id());
    // A u64 past 2^53 is written as the number it is, not a rounded one.
    let text = rpc::submit_request(7, &tx);
    assert!(text.contains("1234567890123456"), "{text}");
    assert!(text.contains("18446744073709551614"), "{text}");
}

#[test]
fn the_requests_are_the_ones_rpc_core_writes() {
    let tx = transaction();
    let parse = |t: String| serde_json::from_str::<Value>(&t).unwrap();
    let a = parse(rpc::request(3, "getServerInfo", &Value::Null).unwrap());
    assert_eq!(a["id"], 3);
    assert_eq!(a["method"], "getServerInfo");
    assert_eq!(
        a["params"],
        serde_json::to_value(GetServerInfoRequest {}).unwrap()
    );
    let b = parse(rpc::request(4, "getBlockDagInfo", &Value::Null).unwrap());
    assert_eq!(
        b["params"],
        serde_json::to_value(GetBlockDagInfoRequest {}).unwrap()
    );
    let addr = test_address();
    let address = addr.to_string();
    let address = address.as_str();
    let c = parse(rpc::request(5, "getUtxosByAddresses", &json!([address])).unwrap());
    assert_eq!(
        c["params"],
        serde_json::to_value(GetUtxosByAddressesRequest::new(vec![addr])).unwrap()
    );
    let id = "ab".repeat(32);
    let d = parse(rpc::request(6, "getMempoolEntry", &json!(id)).unwrap());
    assert_eq!(
        d["params"],
        serde_json::to_value(GetMempoolEntryRequest::new(
            RpcHash::from_bytes([0xab; 32]),
            false,
            false
        ))
        .unwrap()
    );
    let e = parse(rpc::request(7, "getVirtualChainFromBlockV2", &json!(id)).unwrap());
    assert_eq!(
        e["params"],
        serde_json::to_value(GetVirtualChainFromBlockV2Request::new(
            RpcHash::from_bytes([0xab; 32]),
            Some(RpcDataVerbosityLevel::Full),
            None
        ))
        .unwrap()
    );
    let f = parse(rpc::submit_request(8, &tx));
    assert_eq!(f["method"], "submitTransaction");
    assert_eq!(
        f["params"],
        serde_json::to_value(SubmitTransactionRequest::new(
            RpcTransaction::from(&tx),
            false
        ))
        .unwrap()
    );
}

#[test]
fn requests_refuse_what_they_cannot_write_beside_the_accepted_forms() {
    let ok = test_address().to_string();
    let ok = ok.as_str();
    assert!(
        rpc::request(1, "getUtxosByAddresses", &json!([ok])).is_ok(),
        "control"
    );
    for (what, method, argument) in [
        ("an unknown method", "getBalance", Value::Null),
        ("submit by the plain call", "submitTransaction", Value::Null),
        ("an argument to getServerInfo", "getServerInfo", json!(1)),
        ("no addresses", "getUtxosByAddresses", json!([])),
        (
            "an address that is not one",
            "getUtxosByAddresses",
            json!(["kaspa:nope"]),
        ),
        ("a number as an address", "getUtxosByAddresses", json!([5])),
        (
            "addresses not as an array",
            "getUtxosByAddresses",
            json!(ok),
        ),
        ("a short transaction id", "getMempoolEntry", json!("ab")),
        (
            "an upper case transaction id",
            "getMempoolEntry",
            json!("AB".repeat(32)),
        ),
        (
            "a block hash that is a number",
            "getVirtualChainFromBlockV2",
            json!(5),
        ),
    ] {
        let err = rpc::request(1, method, &argument).unwrap_err();
        assert!(
            ["SDK_JSON_FORM"].contains(&err.code()),
            "{what}: {}",
            err.code()
        );
    }
    // Sixty-five addresses are one too many.
    let many: Vec<&str> = std::iter::repeat_n(ok, 65).collect();
    assert_eq!(
        rpc::request(1, "getUtxosByAddresses", &json!(many))
            .unwrap_err()
            .code(),
        "SDK_JSON_FORM"
    );
    assert_eq!(METHODS.len(), 6);
}

fn spk_hex(spk: &ScriptPublicKey) -> String {
    serde_json::to_value(spk)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn a_server_info_reply_is_read_and_the_node_is_checked() {
    let reply = |net: NetworkId, synced: bool| {
        frame(
            1,
            "getServerInfo",
            serde_json::to_value(GetServerInfoResponse {
                rpc_api_version: 1,
                rpc_api_revision: 0,
                server_version: "2.0.1".into(),
                network_id: net,
                has_utxo_index: true,
                is_synced: synced,
                virtual_daa_score: 400_000_123,
            })
            .unwrap(),
        )
    };
    let main = rpc::reply(
        &reply(NetworkId::new(NetworkType::Mainnet), true),
        1,
        "getServerInfo",
        None,
    )
    .unwrap();
    assert_eq!(main["network"], "mainnet");
    assert_eq!(main["network_id"], "mainnet");
    assert_eq!(main["virtual_daa_score"], "400000123");
    assert_eq!(main["is_synced"], true);
    assert_eq!(main["has_utxo_index"], true);
    let test = rpc::reply(
        &reply(NetworkId::with_suffix(NetworkType::Testnet, 10), true),
        1,
        "getServerInfo",
        None,
    )
    .unwrap();
    assert_eq!(test["network"], "testnet");
    assert_eq!(test["network_id"], "testnet-10");
    let dev = rpc::reply(
        &reply(NetworkId::new(NetworkType::Devnet), true),
        1,
        "getServerInfo",
        None,
    )
    .unwrap();
    assert_eq!(dev["network"], Value::Null);
    // The node check: the right network, synced, beside each refusal.
    assert!(rpc::check_node(&test, Network::Testnet).is_ok(), "control");
    assert_eq!(
        code(rpc::check_node(&test, Network::Mainnet)),
        "SDK_NODE_NETWORK_MISMATCH"
    );
    assert_eq!(
        code(rpc::check_node(&dev, Network::Testnet)),
        "SDK_NODE_NETWORK_MISMATCH"
    );
    assert_eq!(
        code(rpc::check_node(&main, Network::Testnet)),
        "SDK_NODE_NETWORK_MISMATCH"
    );
    let unsynced = rpc::reply(
        &reply(NetworkId::with_suffix(NetworkType::Testnet, 10), false),
        1,
        "getServerInfo",
        None,
    )
    .unwrap();
    assert_eq!(
        code(rpc::check_node(&unsynced, Network::Testnet)),
        "SDK_NODE_NOT_SYNCED"
    );
}

#[test]
fn a_dag_info_reply_gives_the_score_and_the_sink() {
    let info = GetBlockDagInfoResponse::new(
        NetworkId::new(NetworkType::Mainnet),
        11,
        12,
        vec![RpcHash::from_bytes([1; 32])],
        1.0,
        13,
        vec![RpcHash::from_bytes([2; 32])],
        RpcHash::from_bytes([3; 32]),
        9_007_199_254_740_993,
        RpcHash::from_bytes([4; 32]),
    );
    let got = rpc::reply(
        &frame(2, "getBlockDagInfo", serde_json::to_value(info).unwrap()),
        2,
        "getBlockDagInfo",
        None,
    )
    .unwrap();
    // A score past 2^53 survives, as a string.
    assert_eq!(got["virtual_daa_score"], "9007199254740993");
    assert_eq!(got["sink"], "04".repeat(32));
}

fn utxo_entry(
    n: u8,
    amount: u64,
    spk: ScriptPublicKey,
    covenant: Option<u8>,
) -> RpcUtxosByAddressesEntry {
    RpcUtxosByAddressesEntry {
        address: None,
        outpoint: RpcTransactionOutpoint {
            transaction_id: h(n),
            index: u32::from(n),
        },
        utxo_entry: RpcUtxoEntry::new(
            amount,
            spk,
            1_000 + u64::from(n),
            n.is_multiple_of(2),
            covenant.map(h),
        ),
    }
}

#[test]
fn a_utxo_reply_is_read_exactly() {
    let big = 2_u64.pow(60) + 1;
    let response = GetUtxosByAddressesResponse::new(vec![
        utxo_entry(1, big, p2pk(5), None),
        utxo_entry(2, 50_000_000, p2sh(6), Some(7)),
    ]);
    let text = frame(
        9,
        "getUtxosByAddresses",
        serde_json::to_value(response).unwrap(),
    );
    let got = rpc::reply(&text, 9, "getUtxosByAddresses", None).unwrap();
    let utxos = got["utxos"].as_array().unwrap();
    assert_eq!(utxos.len(), 2);
    assert_eq!(utxos[0]["amount"], big.to_string());
    assert_eq!(utxos[0]["transaction_id"], "01".repeat(32));
    assert_eq!(utxos[0]["index"], 1);
    assert_eq!(utxos[0]["script_public_key"]["version"], 0);
    assert_eq!(
        utxos[0]["script_public_key"]["script"],
        format!("20{}ac", "05".repeat(32))
    );
    assert_eq!(utxos[0]["block_daa_score"], "1001");
    assert_eq!(utxos[0]["is_coinbase"], false);
    assert_eq!(utxos[0]["covenant_id"], Value::Null);
    assert_eq!(utxos[1]["covenant_id"], "07".repeat(32));
    assert_eq!(utxos[1]["is_coinbase"], true);
    assert_eq!(
        got["total"],
        (u128::from(big) + 50_000_000)
            .to_string()
            .as_str()
            .to_string()
    );
    // The same reply, read for the plan builders.
    let pool = rpc::utxos_from_reply(&text).unwrap();
    assert_eq!(pool.len(), 2);
    assert_eq!(pool[0].entry.amount, big);
    assert_eq!(
        spk_hex(&pool[1].entry.script_public_key),
        format!("0000aa20{}87", "06".repeat(32))
    );
}

#[test]
fn a_reply_that_is_not_the_reply_is_refused_beside_the_accepted_one() {
    let params = serde_json::to_value(SubmitTransactionResponse::new(h(0xaa))).unwrap();
    let good = frame(5, "submitTransaction", params.clone());
    assert!(
        rpc::reply(&good, 5, "submitTransaction", None).is_ok(),
        "control"
    );
    for (what, text) in [
        (
            "another request's id",
            frame(6, "submitTransaction", params.clone()),
        ),
        (
            "another method",
            frame(5, "getBlockDagInfo", params.clone()),
        ),
        ("not JSON", "{".to_string()),
        ("a bare number", "5".to_string()),
        (
            "an error",
            json!({"id": 5, "error": {"code": 1, "message": "boom\u{1b}[2J"}}).to_string(),
        ),
        (
            "no params",
            json!({"id": 5, "method": "submitTransaction"}).to_string(),
        ),
        (
            "a transaction id that is not a hash",
            frame(5, "submitTransaction", json!({"transactionId": "zz"})),
        ),
    ] {
        assert_eq!(
            code(rpc::reply(&text, 5, "submitTransaction", None)),
            "SDK_RPC_REPLY",
            "{what}"
        );
    }
    // The node's words are escaped: a control sequence never reaches the page raw.
    let e = rpc::reply(
        &json!({"id": 5, "error": {"code": 1, "message": "boom\u{1b}[2J"}}).to_string(),
        5,
        "submitTransaction",
        None,
    )
    .unwrap_err();
    assert!(!e.to_string().chars().any(char::is_control), "{e}");
    assert!(e.to_string().contains("boom"), "{e}");
    // The submit reply must name the submitted transaction.
    let tx = transaction();
    let named = frame(
        5,
        "submitTransaction",
        serde_json::to_value(SubmitTransactionResponse::new(tx.id())).unwrap(),
    );
    assert!(
        rpc::submit_reply(&named, 5, tx.id().as_bytes()).is_ok(),
        "control"
    );
    assert_eq!(
        code(rpc::submit_reply(&good, 5, tx.id().as_bytes())),
        "SDK_TXID_MISMATCH"
    );
}

/// Whether the node itself sent the error (`Refusal::is_node_error`), which a page that has sent a
/// transaction needs to tell "the node refused it" from "the answer cannot be read".
fn is_node_error<T: std::fmt::Debug>(r: Result<T, impl Refusal>) -> bool {
    r.unwrap_err().is_node_error()
}

#[test]
fn only_an_error_the_node_sent_to_the_request_is_marked_as_the_nodes_beside_every_unreadable_answer(
) {
    let tx = transaction();
    let submitted = tx.id().as_bytes();
    let named = frame(
        5,
        "submitTransaction",
        serde_json::to_value(SubmitTransactionResponse::new(tx.id())).unwrap(),
    );
    // Control: the node took it, and said so. There is no error to mark.
    assert!(rpc::submit_reply(&named, 5, submitted).is_ok());
    // The node answered this request with an error: it did not act on it. Marked, with the code a
    // refusal of the reply always had.
    for message in [
        json!({"id": 5, "error": {"code": 1, "message": "the mempool is full"}}),
        json!({"id": 5, "method": "submitTransaction", "error": {"message": "orphan"}}),
        json!({"id": 5, "error": "a bare string"}),
    ] {
        let text = message.to_string();
        let e = rpc::submit_reply(&text, 5, submitted).unwrap_err();
        assert_eq!(e.code(), "SDK_RPC_REPLY", "{text}");
        assert!(e.is_node_error(), "{text}");
    }
    // The same words in an answer to another request, or to none: they say nothing about this
    // request, which may have been taken.
    for (what, text) in [
        (
            "another request's id",
            json!({"id": 6, "error": {"message": "the mempool is full"}}).to_string(),
        ),
        (
            "no id",
            json!({"error": {"message": "the mempool is full"}}).to_string(),
        ),
        (
            "an id that is not a number",
            json!({"id": "5", "error": {"message": "the mempool is full"}}).to_string(),
        ),
        ("not JSON", "{".to_string()),
        ("a bare number", "5".to_string()),
        ("an array", "[]".to_string()),
        (
            "success for another request",
            frame(
                6,
                "submitTransaction",
                json!({"transactionId": crate::json::hex(&submitted)}),
            ),
        ),
        (
            "no params",
            json!({"id": 5, "method": "submitTransaction"}).to_string(),
        ),
        (
            "a method that is not the one asked",
            frame(
                5,
                "getBlockDagInfo",
                json!({"transactionId": crate::json::hex(&submitted)}),
            ),
        ),
        (
            "a transaction id that is not a hash",
            frame(5, "submitTransaction", json!({"transactionId": "zz"})),
        ),
        (
            "a reply longer than the page reads",
            format!(
                "{{\"id\": 5, \"pad\": \"{}\"}}",
                "x".repeat(rpc::MAX_REPLY_TEXT as usize)
            ),
        ),
    ] {
        let e = rpc::submit_reply(&text, 5, submitted).unwrap_err();
        assert_eq!(e.code(), "SDK_RPC_REPLY", "{what}");
        assert!(!e.is_node_error(), "{what}");
    }
    // The node said it took another transaction: not an error of the node's, and not a refusal.
    let other = frame(
        5,
        "submitTransaction",
        json!({"transactionId": crate::json::hex(&[0x42; 32])}),
    );
    let e = rpc::submit_reply(&other, 5, submitted).unwrap_err();
    assert_eq!(e.code(), "SDK_TXID_MISMATCH");
    assert!(!e.is_node_error());
    // `rpc::reply` and the other calls: the same rule.
    let refused = json!({"id": 3, "error": {"message": "boom"}}).to_string();
    assert!(is_node_error(rpc::reply(
        &refused,
        3,
        "getServerInfo",
        None
    )));
    assert!(!is_node_error(rpc::reply(
        &refused,
        4,
        "getServerInfo",
        None
    )));
    // The one error that is an answer, kaspad's "not found" to getMempoolEntry, is the node's own.
    let not_found = json!({"id": 3, "error": {"message": format!("Transaction {} not found", crate::json::hex(&submitted))}}).to_string();
    let e = rpc::reply(&not_found, 3, "getMempoolEntry", Some(submitted)).unwrap_err();
    assert_eq!(e.code(), "SDK_RPC_NOT_FOUND");
    assert!(e.is_node_error());
    // And the same words to another request are not.
    assert!(!is_node_error(rpc::reply(
        &not_found,
        4,
        "getMempoolEntry",
        Some(submitted)
    )));
    // The reader of a UTXO list takes no request id: an error in it says nothing of any request.
    let listed = json!({"error": {"message": "boom"}}).to_string();
    assert!(!is_node_error(rpc::utxos_from_reply(&listed)));
    // No other refusal of the SDK carries the mark.
    assert!(!SdkError::NodeNotSynced.is_node_error());
    assert!(!SdkError::WalletWiped.is_node_error());
}

#[test]
fn a_mempool_entry_is_read_into_a_fetched_transaction_and_must_be_the_one_asked_for() {
    let tx = transaction();
    let entry = RpcMempoolEntry::new(1_683_200, RpcTransaction::from(&tx), false);
    let text = frame(
        3,
        "getMempoolEntry",
        serde_json::to_value(GetMempoolEntryResponse::new(entry)).unwrap(),
    );
    let got = rpc::reply(&text, 3, "getMempoolEntry", Some(tx.id().as_bytes())).unwrap();
    assert_eq!(got["fee"], "1683200");
    assert_eq!(got["is_orphan"], false);
    assert_eq!(
        got["transaction"]["txid"],
        crate::json::hex(&tx.id().as_bytes())
    );
    assert_eq!(got["transaction"]["spent"], json!([null, null]));
    // Another transaction than the one asked for is refused.
    assert_eq!(
        code(rpc::reply(&text, 3, "getMempoolEntry", Some([0x42; 32]))),
        "SDK_TXID_MISMATCH"
    );
}

#[test]
fn an_accepted_transaction_is_found_in_the_chain_reply_with_the_scripts_it_spends() {
    let tx = transaction();
    let other = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![],
        vec![TransactionOutput::new(1, p2pk(8))],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let optional = |t: &Transaction, with_spent: bool| {
        let mut o = RpcOptionalTransaction::from(t);
        if with_spent {
            for (i, input) in o.inputs.iter_mut().enumerate() {
                input.verbose_data = Some(RpcOptionalTransactionInputVerboseData {
                    utxo_entry: Some(RpcOptionalUtxoEntry::new(
                        Some(1),
                        Some(p2sh(10 + i as u8)),
                        None,
                        None,
                        None,
                        None,
                    )),
                });
            }
        }
        o
    };
    let response = |txs: Vec<RpcOptionalTransaction>| GetVirtualChainFromBlockV2Response {
        removed_chain_block_hashes: Arc::new(vec![]),
        added_chain_block_hashes: Arc::new(vec![RpcHash::from_bytes([5; 32])]),
        chain_block_accepted_transactions: Arc::new(vec![RpcChainBlockAcceptedTransactions {
            chain_block_header: RpcOptionalHeader {
                hash: Some(RpcHash::from_bytes([6; 32])),
                daa_score: Some(9_007_199_254_740_993),
                ..RpcOptionalHeader::default()
            },
            accepted_transactions: txs,
        }]),
    };
    let text = |txs| {
        frame(
            4,
            "getVirtualChainFromBlockV2",
            serde_json::to_value(response(txs)).unwrap(),
        )
    };
    let want = tx.id().as_bytes();
    let got = rpc::reply(
        &text(vec![optional(&other, false), optional(&tx, true)]),
        4,
        "getVirtualChainFromBlockV2",
        Some(want),
    )
    .unwrap();
    assert_eq!(got["added"], json!(["05".repeat(32)]));
    assert_eq!(got["removed"], json!([]));
    assert_eq!(got["transaction"]["txid"], crate::json::hex(&want));
    assert_eq!(
        got["transaction"]["spent"][1]["script"],
        format!("aa20{}87", "0b".repeat(32))
    );
    // The chain block that accepted it, as its header says, a score past 2^53 kept exact.
    assert_eq!(
        got["accepting_block"],
        json!({ "hash": "06".repeat(32), "daa_score": "9007199254740993" })
    );
    // Not among the accepted transactions: null, not a guess.
    let none = rpc::reply(
        &text(vec![optional(&other, false)]),
        4,
        "getVirtualChainFromBlockV2",
        Some(want),
    )
    .unwrap();
    assert_eq!(none["transaction"], Value::Null);
    assert_eq!(none["accepting_block"], Value::Null);
    // A node that puts another transaction under the ID asked for is refused.
    let mut forged = optional(&other, false);
    forged.verbose_data = Some(
        kaspa_wrpc_client::prelude::RpcOptionalTransactionVerboseData {
            transaction_id: Some(tx.id()),
            hash: None,
            compute_mass: None,
            block_hash: None,
            block_time: None,
        },
    );
    assert_eq!(
        code(rpc::reply(
            &text(vec![forged]),
            4,
            "getVirtualChainFromBlockV2",
            Some(want)
        )),
        "SDK_TXID_MISMATCH"
    );
    // A transaction the node left fields out of is refused, not completed.
    let mut thin = optional(&tx, false);
    thin.lock_time = None;
    assert_eq!(
        code(rpc::reply(
            &text(vec![thin]),
            4,
            "getVirtualChainFromBlockV2",
            Some(want)
        )),
        "SDK_RPC_REPLY"
    );
}

#[test]
fn node_urls_follow_the_command_line_rules() {
    for good in ["ws://127.0.0.1:17210", "wss://node.example:443/path"] {
        assert!(
            rpc::check_node_url(good, Network::Testnet).is_ok(),
            "{good}"
        );
    }
    for bad in [
        "",
        "ws://",
        "http://127.0.0.1:16110",
        "127.0.0.1:17110",
        "ws://host name",
        "WS://127.0.0.1:17110",
    ] {
        assert_eq!(
            code(rpc::check_node_url(bad, Network::Testnet)),
            "SDK_NODE_URL_INVALID",
            "{bad}"
        );
    }
    for good in [
        "wss://node.example:443/path",
        "ws://127.0.0.1:17110",
        "ws://127.0.0.1",
        "ws://localhost:17110",
        "ws://127.0.0.1:17110/",
    ] {
        assert!(
            rpc::check_node_url(good, Network::Mainnet).is_ok(),
            "{good}"
        );
    }
    for bad in [
        "ws://203.0.113.9:17110",
        "ws://node.example:17110",
        "ws://127.0.0.1.example:17110",
        "ws://127.0.0.1@203.0.113.9:17110",
        "ws://localhost.example",
        "ws://127.0.0.2:17110",
        // Owner decision 2026-10-11: no IPv6 literal, not even loopback (the page's policy cannot
        // name one); the accepted controls above are `127.0.0.1` and `localhost`.
        "ws://[::1]:17110",
        "ws://[::1]",
        "ws://[::2]:17110",
        "ws://127.0.0.1:x",
        "ws://127.0.0.1:",
    ] {
        assert_eq!(
            code(rpc::check_node_url(bad, Network::Mainnet)),
            "SDK_NODE_INSECURE",
            "{bad}"
        );
        assert!(
            rpc::check_node_url(bad, Network::Testnet).is_ok(),
            "testnet takes {bad}"
        );
    }
    // The same on the command line's own function.
    for url in [
        "ws://203.0.113.9:17110",
        "ws://127.0.0.1:17110",
        "wss://x.example",
    ] {
        for net in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                rpc::check_node_url(url, net).is_ok(),
                impulse_cli::node::check_transport(url, net).is_ok(),
                "{url} on {net:?}"
            );
        }
    }
    // The one difference: the command line still takes `[::1]` on mainnet, the SDK does not.
    assert!(impulse_cli::node::check_transport("ws://[::1]:17110", Network::Mainnet).is_ok());
    assert_eq!(
        code(rpc::check_node_url("ws://[::1]:17110", Network::Mainnet)),
        "SDK_NODE_INSECURE"
    );
}

#[test]
fn a_fetched_transaction_decodes_only_as_the_one_asked_for() {
    // The signed vault transactions are decoded in the TypeScript suite; here the refusals.
    let tx = transaction();
    let fetched = json!({
        "txid": crate::json::hex(&tx.id().as_bytes()),
        "raw": crate::json::hex(&impulse_core::decode::encode_raw(&tx)),
        "spent": [null, null],
    });
    // The transaction asked for decodes as far as the decoder goes: it spends no vault.
    assert_eq!(
        rpc::decode_fetched(&fetched, tx.id().as_bytes(), Network::Mainnet)
            .unwrap_err()
            .code(),
        "DECODE_NO_VAULT_INPUT"
    );
    let wrong: Failure = rpc::decode_fetched(&fetched, [0x42; 32], Network::Mainnet).unwrap_err();
    assert_eq!(wrong.code(), "SDK_TXID_MISMATCH");
    let mut bad = fetched.clone();
    bad["raw"] = json!("zz");
    assert_eq!(
        rpc::decode_fetched(&bad, tx.id().as_bytes(), Network::Mainnet)
            .unwrap_err()
            .code(),
        "SDK_JSON_FORM"
    );
    // The list of spent scripts is bounded: the most is read (and, null, decodes as far as the
    // decoder goes), one more is refused as a form.
    let with_spent = |n: usize| {
        let mut f = fetched.clone();
        f["spent"] = json!(vec![Value::Null; n]);
        rpc::decode_fetched(&f, tx.id().as_bytes(), Network::Mainnet)
            .unwrap_err()
            .code()
    };
    assert_eq!(with_spent(crate::forms::MAX_ARRAY), "DECODE_NO_VAULT_INPUT");
    assert_eq!(with_spent(crate::forms::MAX_ARRAY + 1), "SDK_JSON_FORM");
    // A page that states the right ID over the raw form of another transaction is caught by the
    // ID of what is decoded.
    let other = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![],
        vec![TransactionOutput::new(1, p2pk(8))],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut swapped = fetched.clone();
    swapped["raw"] = json!(crate::json::hex(&impulse_core::decode::encode_raw(&other)));
    assert_eq!(
        rpc::decode_fetched(&swapped, tx.id().as_bytes(), Network::Mainnet)
            .unwrap_err()
            .code(),
        "DECODE_NO_VAULT_INPUT",
        "decoding fails first for a transaction without a vault input"
    );
}

/// The network a node's `networkId` text names: `mainnet`, or `testnet-` and digits, and nothing
/// that only starts like one.
#[test]
fn a_network_id_names_a_network_only_in_the_forms_kaspad_writes() {
    let network_of = |id: &str| {
        let text = json!({
            "id": 1, "method": "getServerInfo",
            "params": {
                "rpcApiVersion": 1, "rpcApiRevision": 0, "serverVersion": "x", "networkId": id,
                "hasUtxoIndex": true, "isSynced": true, "virtualDaaScore": 5
            }
        })
        .to_string();
        rpc::reply(&text, 1, "getServerInfo", None).unwrap()["network"].clone()
    };
    for (id, want) in [
        ("mainnet", json!("mainnet")),
        ("testnet-10", json!("testnet")),
        ("testnet-11", json!("testnet")),
        ("testnet-0", json!("testnet")),
        ("testnet-", Value::Null),
        ("testnet-abc", Value::Null),
        ("testnet-1a", Value::Null),
        ("testnet-+1", Value::Null),
        ("testnet", Value::Null),
        ("mainnet2", Value::Null),
        ("mainnet-1", Value::Null),
        ("Mainnet", Value::Null),
        ("devnet", Value::Null),
        ("simnet", Value::Null),
        ("", Value::Null),
    ] {
        assert_eq!(network_of(id), want, "{id:?}");
    }
}

/// Each bound is exact: the largest accepted beside the first refused.
#[test]
fn the_bounds_of_the_forms_are_exact_beside_the_accepted_forms() {
    use crate::forms::MAX_ARRAY;
    // Addresses of one request.
    let address = test_address().to_string();
    let request =
        |n: usize| rpc::request(1, "getUtxosByAddresses", &json!(vec![address.clone(); n]));
    assert!(
        request(rpc::MAX_ADDRESSES).is_ok(),
        "control: the most addresses"
    );
    assert_eq!(code(request(rpc::MAX_ADDRESSES + 1)), "SDK_JSON_FORM");
    assert_eq!(code(request(0)), "SDK_JSON_FORM");
    assert!(request(1).is_ok());

    // UTXOs of one reply, read by the reply reader and by the plan builders' reader.
    let entries = |n: usize| {
        let one = serde_json::to_value(utxo_entry(1, 50_000_000, p2pk(5), None)).unwrap();
        frame(3, "getUtxosByAddresses", json!({ "entries": vec![one; n] }))
    };
    let full = entries(rpc::MAX_UTXOS);
    assert_eq!(
        rpc::reply(&full, 3, "getUtxosByAddresses", None).unwrap()["utxos"]
            .as_array()
            .unwrap()
            .len(),
        rpc::MAX_UTXOS
    );
    assert_eq!(rpc::utxos_from_reply(&full).unwrap().len(), rpc::MAX_UTXOS);
    let over = entries(rpc::MAX_UTXOS + 1);
    assert_eq!(
        code(rpc::reply(&over, 3, "getUtxosByAddresses", None)),
        "SDK_RPC_REPLY"
    );
    assert_eq!(code(rpc::utxos_from_reply(&over)), "SDK_RPC_REPLY");

    // The inputs and the outputs of a transaction in a reply.
    let tx = rpc::rpc_transaction_json(&transaction());
    let mempool = |inputs: usize, outputs: usize| {
        let mut t = tx.clone();
        let input = t["inputs"][0].clone();
        let output = t["outputs"][0].clone();
        t["inputs"] = json!(vec![input; inputs]);
        t["outputs"] = json!(vec![output; outputs]);
        frame(
            4,
            "getMempoolEntry",
            json!({ "mempoolEntry": { "fee": 1, "transaction": t, "isOrphan": false } }),
        )
    };
    let read = |inputs, outputs| rpc::reply(&mempool(inputs, outputs), 4, "getMempoolEntry", None);
    assert!(
        read(MAX_ARRAY, MAX_ARRAY).is_ok(),
        "control: the most inputs and outputs"
    );
    assert_eq!(code(read(MAX_ARRAY + 1, 1)), "SDK_RPC_REPLY");
    assert_eq!(code(read(1, MAX_ARRAY + 1)), "SDK_RPC_REPLY");
    assert!(read(1, 1).is_ok());

    // The text of a reply, counted in UTF-16 code units as JavaScript counts a string: padded to
    // exactly the bound with characters of two units, then one unit over.
    let padded = |units: usize| {
        let base = json!({
            "id": 2, "method": "getBlockDagInfo",
            "params": { "virtualDaaScore": 5, "sink": "ab".repeat(32) },
            "pad": ""
        })
        .to_string();
        let room = units - base.encode_utf16().count();
        let astral = "\u{1F600}".repeat(room / 2);
        let odd = "x".repeat(room % 2);
        base.replace("\"pad\":\"\"", &format!("\"pad\":\"{astral}{odd}\""))
    };
    let at = padded(rpc::MAX_REPLY_TEXT as usize);
    assert_eq!(at.encode_utf16().count(), rpc::MAX_REPLY_TEXT as usize);
    assert!(
        at.len() > rpc::MAX_REPLY_TEXT as usize,
        "more bytes than units"
    );
    assert!(
        rpc::reply(&at, 2, "getBlockDagInfo", None).is_ok(),
        "control: exactly the bound"
    );
    let over = padded(rpc::MAX_REPLY_TEXT as usize + 1);
    assert_eq!(
        code(rpc::reply(&over, 2, "getBlockDagInfo", None)),
        "SDK_RPC_REPLY"
    );
}
