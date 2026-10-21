// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The node's wRPC JSON forms (I11 phase 2): the requests the demo page sends, the replies it
//! reads, and the checks on the node it is connected to. A kaspad started with `--rpclisten-json`
//! speaks this protocol over a WebSocket: a request is `{ "id", "method", "params" }`, a reply is
//! `{ "id", "method", "params" }` or `{ "id", "error" }`, and the `params` of each are the
//! serde JSON of the request and response types of rusty-kaspa's `kaspa-rpc-core` at the pinned
//! revision (camelCase field names, u64 values as JSON numbers). The page does no parsing of its
//! own: a reply is handed to [`reply`] as text, because `JSON.parse` reads a number past 2^53
//! inexactly and a sompi amount may be one; what comes back has every u64 as a decimal string.
//!
//! The forms are written from the pinned source, and `cargo test -p impulse-wasm` builds the
//! requests and replies with the real `kaspa-rpc-core` types (through `kaspa-wrpc-client`, a
//! native-only dev-dependency) and checks that this module reads what those types write and
//! writes what they read. Nothing here has been run against a node on a network.
//!
//! The node is a trust anchor for what it reports (the DAA score, the UTXOs, the transactions) and
//! nothing else. Every reply is checked for being the reply to the request, for the network the
//! page acts on and for being synced before the page acts on it; a transaction fetched from a node
//! is hashed here and refused unless it is the one asked for.

use crate::error::{node_words, shown, SdkError};
use crate::forms::MAX_ARRAY;
use crate::funding::kas;
use crate::json::{hex, hex_decode, network_name};
use impulse_core::decode;
use impulse_core::terms::Network;
use impulse_core::tx::Utxo;
use kaspa_addresses::Address;
use kaspa_consensus_core::mass::{ComputeBudget, SigopCount};
use kaspa_consensus_core::subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE};
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use serde_json::{json, Map, Value};

/// The node calls the page makes, by the name `RpcApiOps` serialises to.
pub(crate) const METHODS: [&str; 6] = [
    "getServerInfo",
    "getBlockDagInfo",
    "getUtxosByAddresses",
    "submitTransaction",
    "getMempoolEntry",
    "getVirtualChainFromBlockV2",
];

/// The longest reply text read, in UTF-16 code units. A reply of every UTXO of a few addresses is
/// far smaller; the bound keeps a hostile node from making the page copy and parse without end.
pub(crate) const MAX_REPLY_TEXT: u32 = 1 << 23;

/// At most this many UTXOs are read from one reply.
pub(crate) const MAX_UTXOS: usize = 20_000;

/// At most this many addresses in one `getUtxosByAddresses` request.
pub(crate) const MAX_ADDRESSES: usize = 64;

fn reply_error(method: &'static str, reason: impl Into<String>) -> SdkError {
    SdkError::RpcReply {
        method,
        reason: reason.into(),
        from_node: false,
    }
}

fn method_name(method: &str) -> Result<&'static str, SdkError> {
    METHODS
        .iter()
        .find(|m| **m == method)
        .copied()
        .ok_or_else(|| {
            SdkError::json(
                "method",
                format!("{} is not one of {}", shown(method), METHODS.join(", ")),
            )
        })
}

fn envelope(id: u64, method: &str, params: Value) -> String {
    json!({ "id": id, "method": method, "params": params }).to_string()
}

// Requests.

/// The request text for `method`. `argument` is `null` for `getServerInfo` and `getBlockDagInfo`;
/// an array of addresses for `getUtxosByAddresses`; a transaction ID (64 lowercase hex digits)
/// for `getMempoolEntry`; and the hash of a chain block to start from for
/// `getVirtualChainFromBlockV2`. `submitTransaction` has [`submit_request`].
pub(crate) fn request(id: u64, method: &str, argument: &Value) -> Result<String, SdkError> {
    let name = method_name(method)?;
    let hash = |what: &str| -> Result<String, SdkError> {
        match argument
            .as_str()
            .and_then(hex_decode)
            .map(<[u8; 32]>::try_from)
        {
            Some(Ok(b)) => Ok(hex(&b)),
            _ => Err(SdkError::json(
                "argument",
                format!("{what} is 64 lowercase hex digits"),
            )),
        }
    };
    let params = match name {
        "getServerInfo" | "getBlockDagInfo" => {
            if !argument.is_null() {
                return Err(SdkError::json(
                    "argument",
                    format!("{name} takes no argument"),
                ));
            }
            json!({})
        }
        "getUtxosByAddresses" => {
            let Value::Array(items) = argument else {
                return Err(SdkError::json("argument", "expected an array of addresses"));
            };
            if items.is_empty() || items.len() > MAX_ADDRESSES {
                return Err(SdkError::json(
                    "argument",
                    format!("from 1 to {MAX_ADDRESSES} addresses"),
                ));
            }
            let mut addresses = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let text = item.as_str().unwrap_or_default();
                let canonical = Address::try_from(text)
                    .ok()
                    .filter(|a| a.to_string() == text);
                match canonical {
                    Some(_) => addresses.push(text.to_string()),
                    None => {
                        return Err(SdkError::json(
                            format!("argument[{i}]"),
                            format!("{} is not a Kaspa address in canonical form", shown(text)),
                        ))
                    }
                }
            }
            json!({ "addresses": addresses })
        }
        "getMempoolEntry" => json!({
            "transactionId": hash("a transaction id")?,
            // The ordinary pool only: orphans are not transactions the page asks about.
            "includeOrphanPool": false,
            "filterTransactionPool": false,
        }),
        "getVirtualChainFromBlockV2" => json!({
            "startHash": hash("a block hash")?,
            "dataVerbosityLevel": "Full",
            "minConfirmationCount": null,
        }),
        "submitTransaction" => {
            return Err(SdkError::json(
                "method",
                "submitTransaction takes a signed transaction: use the submit request",
            ))
        }
        _ => unreachable!("method_name returns a method of the list"),
    };
    Ok(envelope(id, name, params))
}

/// The scriptPublicKey in the node's JSON: the version as four hex digits, then the script.
fn spk_hex(spk: &ScriptPublicKey) -> String {
    format!("{:04x}{}", spk.version(), hex(spk.script()))
}

fn spk_from_hex(text: &str, method: &'static str, what: &str) -> Result<ScriptPublicKey, SdkError> {
    let bytes = hex_decode(text)
        .filter(|b| b.len() >= 2)
        .ok_or_else(|| reply_error(method, format!("{what}: not a scriptPublicKey in hex")))?;
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    Ok(ScriptPublicKey::from_vec(version, bytes[2..].to_vec()))
}

/// A transaction as `RpcTransaction` serialises it (the node's `submitTransaction` takes this).
/// The `mass` and `storageMass` fields are the transaction's own, 0 for one Impulse builds: a node
/// sets the storage mass itself when it admits a transaction to its mempool (rusty-kaspa a41a333,
/// `validate_mempool_transaction_in_utxo_context`). Not run against a node.
pub(crate) fn rpc_transaction_json(tx: &Transaction) -> Value {
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .map(|i| {
            json!({
                "previousOutpoint": {
                    "transactionId": hex(&i.previous_outpoint.transaction_id.as_bytes()),
                    "index": i.previous_outpoint.index,
                },
                "signatureScript": hex(&i.signature_script),
                "sequence": i.sequence,
                "sigOpCount": i.compute_commit.sig_op_count().unwrap_or(0),
                "computeBudget": i.compute_commit.compute_budget().unwrap_or(0),
                "verboseData": null,
            })
        })
        .collect();
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .map(|o| {
            json!({
                "value": o.value,
                "scriptPublicKey": spk_hex(&o.script_public_key),
                "verboseData": null,
                "covenant": o.covenant.map(|c| json!({
                    "authorizingInput": c.authorizing_input,
                    "covenantId": hex(&c.covenant_id.as_bytes()),
                })),
            })
        })
        .collect();
    json!({
        "version": tx.version,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": tx.lock_time,
        "subnetworkId": hex(tx.subnetwork_id.as_ref()),
        "gas": tx.gas,
        "payload": hex(&tx.payload),
        "storageMass": tx.storage_mass(),
        "mass": tx.storage_mass(),
        "verboseData": null,
    })
}

/// The `submitTransaction` request for a signed transaction.
pub(crate) fn submit_request(id: u64, tx: &Transaction) -> String {
    envelope(
        id,
        "submitTransaction",
        json!({ "transaction": rpc_transaction_json(tx), "allowOrphan": false }),
    )
}

// Replies.

fn hash32(v: &Value, method: &'static str, what: &str) -> Result<[u8; 32], SdkError> {
    v.as_str()
        .and_then(hex_decode)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| reply_error(method, format!("{what}: not 64 hex digits")))
}

fn num(v: &Value, method: &'static str, what: &str) -> Result<u64, SdkError> {
    v.as_u64()
        .ok_or_else(|| reply_error(method, format!("{what}: not an unsigned integer")))
}

fn field<'a>(
    o: &'a Map<String, Value>,
    key: &str,
    method: &'static str,
    what: &str,
) -> Result<&'a Value, SdkError> {
    o.get(key)
        .ok_or_else(|| reply_error(method, format!("{what}: no {key}")))
}

fn object<'a>(
    v: &'a Value,
    method: &'static str,
    what: &str,
) -> Result<&'a Map<String, Value>, SdkError> {
    v.as_object()
        .ok_or_else(|| reply_error(method, format!("{what}: not an object")))
}

/// The node's network from its network ID: `mainnet`, or `testnet-<suffix>`.
fn network_of(id: &str) -> Option<Network> {
    if id == "mainnet" {
        return Some(Network::Mainnet);
    }
    let suffix = id.strip_prefix("testnet-")?;
    (!suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())).then_some(Network::Testnet)
}

fn utxo_json(
    entry: &Value,
    method: &'static str,
    at: &str,
) -> Result<(Utxo, Option<String>), SdkError> {
    let o = object(entry, method, at)?;
    let outpoint = object(field(o, "outpoint", method, at)?, method, at)?;
    let e = object(field(o, "utxoEntry", method, at)?, method, at)?;
    let transaction_id = hash32(field(outpoint, "transactionId", method, at)?, method, at)?;
    let index = u32::try_from(num(field(outpoint, "index", method, at)?, method, at)?)
        .map_err(|_| reply_error(method, format!("{at}: index out of range")))?;
    let amount = num(field(e, "amount", method, at)?, method, at)?;
    let spk = spk_from_hex(
        field(e, "scriptPublicKey", method, at)?
            .as_str()
            .unwrap_or_default(),
        method,
        at,
    )?;
    let block_daa_score = num(field(e, "blockDaaScore", method, at)?, method, at)?;
    let is_coinbase = field(e, "isCoinbase", method, at)?
        .as_bool()
        .ok_or_else(|| reply_error(method, format!("{at}: isCoinbase is not true or false")))?;
    let covenant_id = match e.get("covenantId") {
        None | Some(Value::Null) => None,
        Some(v) => Some(Hash::from_bytes(hash32(v, method, at)?)),
    };
    let address = o.get("address").and_then(Value::as_str).map(str::to_string);
    Ok((
        Utxo {
            outpoint: TransactionOutpoint::new(Hash::from_bytes(transaction_id), index),
            entry: UtxoEntry::new(amount, spk, block_daa_score, is_coinbase, covenant_id),
        },
        address,
    ))
}

/// The UTXOs of a `getUtxosByAddresses` reply text, read with the checks of [`reply`] for the
/// envelope. The plan builders (`plan.rs`) take the reply text, not objects, so that a long list
/// never passes through JavaScript.
pub(crate) fn utxos_from_reply(text: &str) -> Result<Vec<Utxo>, SdkError> {
    const METHOD: &str = "getUtxosByAddresses";
    let params = params_of(text, None, METHOD, None)?;
    let entries = field(
        object(&params, METHOD, "reply")?,
        "entries",
        METHOD,
        "reply",
    )?
    .as_array()
    .ok_or_else(|| reply_error(METHOD, "entries: not an array"))?
    .clone();
    if entries.len() > MAX_UTXOS {
        return Err(reply_error(
            METHOD,
            format!("{} UTXOs; at most {MAX_UTXOS} are read", entries.len()),
        ));
    }
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| utxo_json(e, METHOD, &format!("entries[{i}]")).map(|(u, _)| u))
        .collect()
}

/// A transaction from the node's JSON: `RpcTransaction`, or `RpcOptionalTransaction` at a
/// verbosity that names every field. Returns the transaction and, per input, the
/// scriptPublicKey of the UTXO it spends if the node gave it.
fn transaction_from_rpc(
    v: &Value,
    method: &'static str,
) -> Result<(Transaction, Vec<Option<ScriptPublicKey>>), SdkError> {
    let o = object(v, method, "transaction")?;
    let need = |key: &str| field(o, key, method, "transaction");
    let version = u16::try_from(num(need("version")?, method, "version")?)
        .map_err(|_| reply_error(method, "version out of range"))?;
    let lock_time = num(need("lockTime")?, method, "lockTime")?;
    let gas = num(need("gas")?, method, "gas")?;
    let payload = hex_decode(need("payload")?.as_str().unwrap_or("x"))
        .ok_or_else(|| reply_error(method, "payload: not hex"))?;
    let subnetwork = hex_decode(need("subnetworkId")?.as_str().unwrap_or("x"))
        .and_then(|b| <[u8; 20]>::try_from(b).ok())
        .map(SubnetworkId::from_bytes)
        .ok_or_else(|| reply_error(method, "subnetworkId: not 40 hex digits"))?;
    if subnetwork != SUBNETWORK_ID_NATIVE {
        return Err(reply_error(method, "not a native transaction"));
    }
    let mass = match (o.get("storageMass"), o.get("mass")) {
        (Some(v), _) | (None, Some(v)) if !v.is_null() => num(v, method, "storageMass")?,
        _ => 0,
    };
    let raw_inputs = need("inputs")?
        .as_array()
        .ok_or_else(|| reply_error(method, "inputs: not an array"))?;
    let raw_outputs = need("outputs")?
        .as_array()
        .ok_or_else(|| reply_error(method, "outputs: not an array"))?;
    if raw_inputs.len() > MAX_ARRAY || raw_outputs.len() > MAX_ARRAY {
        return Err(reply_error(
            method,
            format!("more than {MAX_ARRAY} inputs or outputs"),
        ));
    }
    let (mut inputs, mut spent) = (Vec::new(), Vec::new());
    for (i, raw) in raw_inputs.iter().enumerate() {
        let at = format!("inputs[{i}]");
        let io = object(raw, method, &at)?;
        let outpoint = object(field(io, "previousOutpoint", method, &at)?, method, &at)?;
        let previous = TransactionOutpoint::new(
            Hash::from_bytes(hash32(
                field(outpoint, "transactionId", method, &at)?,
                method,
                &at,
            )?),
            u32::try_from(num(field(outpoint, "index", method, &at)?, method, &at)?)
                .map_err(|_| reply_error(method, format!("{at}: index out of range")))?,
        );
        let script = hex_decode(
            field(io, "signatureScript", method, &at)?
                .as_str()
                .unwrap_or("x"),
        )
        .ok_or_else(|| reply_error(method, format!("{at}: signatureScript is not hex")))?;
        let sequence = num(field(io, "sequence", method, &at)?, method, &at)?;
        let optional = |key: &str| -> Result<u64, SdkError> {
            match io.get(key) {
                None | Some(Value::Null) => Ok(0),
                Some(v) => num(v, method, key),
            }
        };
        let (sigops, budget) = (optional("sigOpCount")?, optional("computeBudget")?);
        let commit: ComputeCommit = if ComputeCommit::version_expects_compute_budget_field(version)
        {
            if sigops != 0 {
                return Err(reply_error(
                    method,
                    format!("{at}: sigOpCount is set in a version {version} transaction"),
                ));
            }
            ComputeBudget(
                u16::try_from(budget)
                    .map_err(|_| reply_error(method, format!("{at}: computeBudget too large")))?,
            )
            .into()
        } else {
            if budget != 0 {
                return Err(reply_error(
                    method,
                    format!("{at}: computeBudget is set in a version {version} transaction"),
                ));
            }
            SigopCount(
                u8::try_from(sigops)
                    .map_err(|_| reply_error(method, format!("{at}: sigOpCount too large")))?,
            )
            .into()
        };
        inputs.push(TransactionInput::new_with_mass(
            previous, script, sequence, commit,
        ));
        let spk = io
            .get("verboseData")
            .and_then(|d| d.get("utxoEntry"))
            .and_then(|u| u.get("scriptPublicKey"))
            .and_then(Value::as_str)
            .map(|s| spk_from_hex(s, method, &at))
            .transpose()?;
        spent.push(spk);
    }
    let mut outputs = Vec::new();
    for (i, raw) in raw_outputs.iter().enumerate() {
        let at = format!("outputs[{i}]");
        let oo = object(raw, method, &at)?;
        let value = num(field(oo, "value", method, &at)?, method, &at)?;
        let spk = spk_from_hex(
            field(oo, "scriptPublicKey", method, &at)?
                .as_str()
                .unwrap_or_default(),
            method,
            &at,
        )?;
        let covenant = match oo.get("covenant") {
            None | Some(Value::Null) => None,
            Some(c) => {
                let co = object(c, method, &at)?;
                Some(CovenantBinding::new(
                    u16::try_from(num(
                        field(co, "authorizingInput", method, &at)?,
                        method,
                        &at,
                    )?)
                    .map_err(|_| {
                        reply_error(method, format!("{at}: authorizingInput too large"))
                    })?,
                    Hash::from_bytes(hash32(field(co, "covenantId", method, &at)?, method, &at)?),
                ))
            }
        };
        outputs.push(TransactionOutput::with_covenant(value, spk, covenant));
    }
    let tx = Transaction::new_with_mass(
        version, inputs, outputs, lock_time, subnetwork, gas, payload, mass,
    );
    Ok((tx, spent))
}

/// A transaction as the page holds it between the node and the decoder: its ID, its raw form
/// (rusty-kaspa a41a333's borsh encoding) and the scriptPublicKey each input spends where the node
/// said. `decode_fetched` reads it back.
fn fetched_json(tx: &Transaction, spent: &[Option<ScriptPublicKey>]) -> Value {
    json!({
        "txid": hex(&tx.id().as_bytes()),
        "raw": hex(&decode::encode_raw(tx)),
        "spent": spent.iter().map(|s| s.as_ref().map(crate::ops::spk_json)).collect::<Vec<_>>(),
    })
}

/// Reads the envelope of a reply and returns its `params`: the reply to request `expected_id`
/// (any id when None), for `method`, without an error. `asked` is the transaction ID the request
/// named, for the one error that is an answer and not a failure: kaspad's `Transaction <id> not
/// found` to `getMempoolEntry` (`RpcError::TransactionNotFound`, rusty-kaspa rpc/core/src/error.rs)
/// is `SDK_RPC_NOT_FOUND`; every other error the node sends is `SDK_RPC_REPLY`.
fn params_of(
    text: &str,
    expected_id: Option<u64>,
    method: &'static str,
    asked: Option<[u8; 32]>,
) -> Result<Value, SdkError> {
    if text.encode_utf16().count() > MAX_REPLY_TEXT as usize {
        return Err(reply_error(
            method,
            "the reply is longer than the page reads",
        ));
    }
    let frame: Value =
        serde_json::from_str(text).map_err(|_| reply_error(method, "the reply is not JSON"))?;
    let o = object(&frame, method, "reply")?;
    if let Some(expected) = expected_id {
        match o.get("id").and_then(Value::as_u64) {
            Some(id) if id == expected => {}
            other => {
                return Err(reply_error(
                    method,
                    format!("reply to another request (id {other:?}, expected {expected})"),
                ))
            }
        }
    }
    if let Some(error) = o.get("error").filter(|e| !e.is_null()) {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .map_or_else(|| error.to_string(), str::to_string);
        if let (true, Some(asked)) = (method == "getMempoolEntry", asked) {
            if message == format!("Transaction {} not found", hex(&asked)) {
                return Err(SdkError::RpcNotFound {
                    method,
                    id: hex(&asked),
                });
            }
        }
        // The id is this request's (checked above when one was expected): the node itself refused.
        return Err(SdkError::RpcReply {
            method,
            reason: format!("the node answered with an error: {}", node_words(&message)),
            from_node: expected_id.is_some(),
        });
    }
    if let Some(named) = o.get("method").and_then(Value::as_str) {
        if named != method {
            return Err(reply_error(
                method,
                format!("the reply is for {}", shown(named)),
            ));
        }
    }
    o.get("params")
        .cloned()
        .ok_or_else(|| reply_error(method, "the reply has no params"))
}

/// The reply to request `expected_id` for `method`, in the SDK's forms (u64 as decimal strings).
///
/// - `getServerInfo`: `{ network_id, network, is_synced, has_utxo_index, virtual_daa_score }`
/// - `getBlockDagInfo`: `{ virtual_daa_score, sink }`
/// - `getUtxosByAddresses`: `{ utxos }`, each `UtxoJson` with the node's `address` beside it
/// - `submitTransaction`: `{ transaction_id }`
/// - `getMempoolEntry`: `{ fee, is_orphan, transaction }` with the transaction as `fetched_json`
/// - `getVirtualChainFromBlockV2`: `{ removed, added, transaction, accepting_block }`, the
///   transaction with `filter` as its ID or null, as `fetched_json`, and the chain block that
///   accepted it (`{ hash, daa_score }`, each null if the node's header omits it) or null
///
/// `filter` is the transaction ID the caller asked for; a transaction whose own hash is another is
/// `SDK_TXID_MISMATCH`.
pub(crate) fn reply(
    text: &str,
    expected_id: u64,
    method: &str,
    filter: Option<[u8; 32]>,
) -> Result<Value, SdkError> {
    let name = method_name(method)?;
    let params = params_of(text, Some(expected_id), name, filter)?;
    let p = object(&params, name, "params")?;
    match name {
        "getServerInfo" => {
            let id = field(p, "networkId", name, "params")?
                .as_str()
                .ok_or_else(|| reply_error(name, "networkId: not a string"))?;
            let flag = |key: &str| {
                field(p, key, name, "params")?
                    .as_bool()
                    .ok_or_else(|| reply_error(name, format!("{key}: not true or false")))
            };
            Ok(json!({
                "network_id": id,
                "network": network_of(id).map(network_name),
                "is_synced": flag("isSynced")?,
                "has_utxo_index": flag("hasUtxoIndex")?,
                "virtual_daa_score": num(field(p, "virtualDaaScore", name, "params")?, name, "virtualDaaScore")?.to_string(),
            }))
        }
        "getBlockDagInfo" => Ok(json!({
            "virtual_daa_score": num(field(p, "virtualDaaScore", name, "params")?, name, "virtualDaaScore")?.to_string(),
            "sink": hex(&hash32(field(p, "sink", name, "params")?, name, "sink")?),
        })),
        "getUtxosByAddresses" => {
            let entries = field(p, "entries", name, "params")?
                .as_array()
                .ok_or_else(|| reply_error(name, "entries: not an array"))?;
            if entries.len() > MAX_UTXOS {
                return Err(reply_error(
                    name,
                    format!("{} UTXOs; at most {MAX_UTXOS} are read", entries.len()),
                ));
            }
            let mut utxos = Vec::new();
            for (i, e) in entries.iter().enumerate() {
                let (u, address) = utxo_json(e, name, &format!("entries[{i}]"))?;
                utxos.push(json!({
                    "address": address,
                    "transaction_id": hex(&u.outpoint.transaction_id.as_bytes()),
                    "index": u.outpoint.index,
                    "amount": u.entry.amount.to_string(),
                    "script_public_key": crate::ops::spk_json(&u.entry.script_public_key),
                    "block_daa_score": u.entry.block_daa_score.to_string(),
                    "is_coinbase": u.entry.is_coinbase,
                    "covenant_id": u.entry.covenant_id.map(|c| hex(&c.as_bytes())),
                }));
            }
            let total = entries.iter().enumerate().try_fold(0u64, |sum, (i, e)| {
                utxo_json(e, name, &format!("entries[{i}]"))
                    .map(|(u, _)| sum.saturating_add(u.entry.amount))
            })?;
            Ok(json!({ "utxos": utxos, "total": total.to_string(), "total_kas": kas(total) }))
        }
        "submitTransaction" => Ok(json!({
            "transaction_id": hex(&hash32(field(p, "transactionId", name, "params")?, name, "transactionId")?),
        })),
        "getMempoolEntry" => {
            let entry = object(
                field(p, "mempoolEntry", name, "params")?,
                name,
                "mempoolEntry",
            )?;
            let (tx, spent) =
                transaction_from_rpc(field(entry, "transaction", name, "mempoolEntry")?, name)?;
            check_txid(&tx, filter)?;
            let orphan = entry
                .get("isOrphan")
                .or_else(|| entry.get("is_orphan"))
                .and_then(Value::as_bool)
                .ok_or_else(|| reply_error(name, "isOrphan: not true or false"))?;
            Ok(json!({
                "fee": num(field(entry, "fee", name, "mempoolEntry")?, name, "fee")?.to_string(),
                "is_orphan": orphan,
                "transaction": fetched_json(&tx, &spent),
            }))
        }
        "getVirtualChainFromBlockV2" => {
            let hashes = |key: &str| -> Result<Vec<Value>, SdkError> {
                field(p, key, name, "params")?
                    .as_array()
                    .ok_or_else(|| reply_error(name, format!("{key}: not an array")))?
                    .iter()
                    .map(|h| hash32(h, name, key).map(|b| json!(hex(&b))))
                    .collect()
            };
            let (removed, added) = (
                hashes("removedChainBlockHashes")?,
                hashes("addedChainBlockHashes")?,
            );
            let mut found = Value::Null;
            let mut accepting = Value::Null;
            let blocks = field(p, "chainBlockAcceptedTransactions", name, "params")?
                .as_array()
                .ok_or_else(|| reply_error(name, "chainBlockAcceptedTransactions: not an array"))?;
            if let Some(want) = filter {
                'blocks: for block in blocks {
                    let accepted = block
                        .get("acceptedTransactions")
                        .and_then(Value::as_array)
                        .ok_or_else(|| reply_error(name, "acceptedTransactions: not an array"))?;
                    for candidate in accepted {
                        // The transaction ID the node states is looked at first, so that only the
                        // transaction asked for is parsed; the hash of what is parsed decides.
                        let stated = candidate
                            .get("verboseData")
                            .and_then(|d| d.get("transactionId"))
                            .and_then(Value::as_str)
                            .and_then(hex_decode);
                        if stated.as_deref().is_some_and(|s| s != want) {
                            continue;
                        }
                        let (tx, spent) = transaction_from_rpc(candidate, name)?;
                        if tx.id().as_bytes() == want {
                            found = fetched_json(&tx, &spent);
                            // The chain block that accepted it, as far as the node's header says.
                            let header = block.get("chainBlockHeader");
                            accepting = json!({
                                "hash": header
                                    .and_then(|h| h.get("hash"))
                                    .and_then(Value::as_str)
                                    .and_then(hex_decode)
                                    .filter(|b| b.len() == 32)
                                    .map(|b| hex(&b)),
                                "daa_score": header
                                    .and_then(|h| h.get("daaScore"))
                                    .and_then(Value::as_u64)
                                    .map(|n| n.to_string()),
                            });
                            break 'blocks;
                        }
                        if stated.is_some() {
                            return Err(SdkError::TxidMismatch {
                                asked: hex(&want),
                                got: hex(&tx.id().as_bytes()),
                            });
                        }
                    }
                }
            }
            Ok(
                json!({ "removed": removed, "added": added, "transaction": found, "accepting_block": accepting }),
            )
        }
        _ => Err(SdkError::json(
            "method",
            "submitTransaction has no reply to read: use the submit reply",
        )),
    }
}

fn check_txid(tx: &Transaction, asked: Option<[u8; 32]>) -> Result<(), SdkError> {
    match asked {
        Some(want) if tx.id().as_bytes() != want => Err(SdkError::TxidMismatch {
            asked: hex(&want),
            got: hex(&tx.id().as_bytes()),
        }),
        _ => Ok(()),
    }
}

/// The transaction ID a `submitTransaction` reply names, which must be the submitted
/// transaction's (`SDK_TXID_MISMATCH`).
pub(crate) fn submit_reply(
    text: &str,
    expected_id: u64,
    submitted: [u8; 32],
) -> Result<String, SdkError> {
    let value = reply(text, expected_id, "submitTransaction", None)?;
    let got = value["transaction_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if got != hex(&submitted) {
        return Err(SdkError::TxidMismatch {
            asked: hex(&submitted),
            got,
        });
    }
    Ok(got)
}

// The node the user names.

/// Only `ws://` and `wss://` URLs with something after the scheme and no whitespace (the command
/// line's `check_url`).
fn check_url(url: &str) -> Result<(), SdkError> {
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"));
    match rest {
        Some(r) if !r.is_empty() && !r.chars().any(char::is_whitespace) => Ok(()),
        _ => Err(SdkError::NodeUrlInvalid { url: url.into() }),
    }
}

/// The URL check, and on mainnet a private link: `wss://`, or `ws://` to this machine
/// (`127.0.0.1` or `localhost`, optionally with a port). On mainnet the node is the trust anchor
/// for the creation DAA score and for what the page signs against, so plaintext to another host
/// is refused; reach a remote node through an SSH tunnel to a loopback port. The command line's
/// `check_transport`, except that `[::1]` is not allowed here (owner decision 2026-10-11): the
/// demo page's Content-Security-Policy cannot name an IPv6 literal, so a page that took `[::1]`
/// would have its socket blocked by the browser, and the SDK refuses it first and says why.
pub(crate) fn check_node_url(url: &str, network: Network) -> Result<(), SdkError> {
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
    if matches!(host, "127.0.0.1" | "localhost") && port_ok {
        return Ok(());
    }
    Err(SdkError::NodeInsecure { url: url.into() })
}

/// The node is on `network` and synced, from a `getServerInfo` reply as [`reply`] returns it.
pub(crate) fn check_node(info: &Value, network: Network) -> Result<(), SdkError> {
    let id = info["network_id"].as_str().unwrap_or("unknown");
    if info["network"].as_str() != Some(network_name(network)) {
        return Err(SdkError::NodeNetworkMismatch {
            node: id.into(),
            expected: network_name(network),
        });
    }
    if info["is_synced"].as_bool() != Some(true) {
        return Err(SdkError::NodeNotSynced);
    }
    Ok(())
}

/// What the page reads of a transaction fetched from the node, decoded: bound to the spent
/// scriptPublicKeys when the node gave one for every input, else not (`bound: false`, as
/// `decode_unbound`). The transaction's own hash must be `asked` (`SDK_TXID_MISMATCH`).
pub(crate) fn decode_fetched(
    fetched: &Value,
    asked: [u8; 32],
    network: Network,
) -> Result<Value, crate::error::Failure> {
    // The ID the fetched transaction states is checked first: cheap, and a refusal before any
    // decoding of a transaction that is not the one asked for.
    let stated = fetched["txid"].as_str().unwrap_or_default();
    if stated != hex(&asked) {
        return Err(SdkError::TxidMismatch {
            asked: hex(&asked),
            got: stated.into(),
        }
        .into());
    }
    let raw = fetched["raw"]
        .as_str()
        .and_then(hex_decode)
        .ok_or_else(|| SdkError::json("fetched.raw", "expected lowercase hex"))?;
    let spent: Vec<Option<ScriptPublicKey>> = match fetched["spent"].as_array() {
        Some(items) if items.len() <= MAX_ARRAY => items
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if v.is_null() {
                    return Ok(None);
                }
                let o = crate::json::Obj::new(v, &format!("fetched.spent[{i}]"))?;
                crate::forms::script_public_key(o).map(Some)
            })
            .collect::<Result<_, SdkError>>()?,
        _ => return Err(SdkError::json("fetched.spent", "expected an array").into()),
    };
    let decoded = if spent.iter().all(Option::is_some) && !spent.is_empty() {
        let value: Vec<Value> = spent.iter().flatten().map(crate::ops::spk_json).collect();
        crate::ops::decode_raw(&raw, &Value::Array(value), network)?
    } else {
        crate::ops::decode_raw_unbound(&raw, network)?
    };
    // And the ID of the transaction decoded is the one asked for, whatever the page says.
    let got = decoded["txid"].as_str().unwrap_or_default();
    if got != hex(&asked) {
        return Err(SdkError::TxidMismatch {
            asked: hex(&asked),
            got: got.into(),
        }
        .into());
    }
    Ok(decoded)
}
