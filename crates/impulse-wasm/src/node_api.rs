// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The bindings of the node forms (`rpc.rs`), the UTXO plans (`plan.rs`), the review and the
//! wallet, for the browser demo (I11 phase 2). Each reads its JavaScript arguments and calls the
//! operation of its module; nothing here decides anything. The wallet is the only binding that
//! holds a secret, and it hands out none.

use crate::api::{JsIpst, JsSignedTransaction};
use crate::error::{js, SdkError};
use crate::json::hex_decode;
use crate::wallet::{self, Wallet};
use crate::{
    index_arg, json_arg, json_arg_tx, leg_arg, network_arg, plan, review, rpc, text_arg, u64_arg,
    JsValidatedTerms,
};
use js_sys::{Array, Object, Reflect};
use serde_json::Value;
use wasm_bindgen::prelude::*;

fn to_js(value: &Value) -> Result<JsValue, JsValue> {
    js_sys::JSON::parse(&value.to_string())
}

/// A 32-byte key or hash argument as 64 lowercase hex digits.
fn hex32_arg(value: &JsValue, argument: &'static str) -> Result<[u8; 32], JsValue> {
    let text = text_arg(value, argument, 64)?;
    hex_decode(&text)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| js(SdkError::json(argument, "expected 64 lowercase hex digits")))
}

// The terms' plans: which addresses to ask the node about, and the builder from the answer.

#[wasm_bindgen(js_class = ValidatedTerms)]
impl JsValidatedTerms {
    /// The addresses to ask the node for UTXOs before `settleFromReply`: each escrowed leg's vault
    /// and token, and the fee payer's address. `payer` is the fee payer's x-only key.
    #[wasm_bindgen(js_name = settleAddresses, unchecked_return_type = "string[]")]
    pub fn settle_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Hex")] payer: JsValue,
    ) -> Result<JsValue, JsValue> {
        let artifacts = json_arg_tx(&artifacts, "artifacts")?;
        let payer = hex32_arg(&payer, "payer")?;
        let addresses = plan::settle_addresses(&self.inner, &artifacts, &payer).map_err(js)?;
        to_js(&Value::from(addresses))
    }

    /// `tx::settle` over the UTXOs of the text of a `getUtxosByAddresses` reply (`plan.rs` says
    /// which UTXO is which). `funding` is `{ payer, fee }`, the fee a u64 string or `"auto"`.
    #[wasm_bindgen(js_name = settleFromReply)]
    pub fn settle_from_reply(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] reply: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PlanFundingJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let reply = text_arg(&reply, "reply", rpc::MAX_REPLY_TEXT)?;
        let (artifacts, funding, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = plan::settle_from_reply(&self.inner, &artifacts, &reply, &funding, daa, &value)
            .map_err(js)?;
        Ok(JsIpst { inner: ipst })
    }

    /// The addresses to ask the node about before `refundFromReply`.
    #[wasm_bindgen(js_name = refundAddresses, unchecked_return_type = "string[]")]
    pub fn refund_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Hex")] payer: JsValue,
    ) -> Result<JsValue, JsValue> {
        let leg = leg_arg(&leg)?;
        let artifacts = json_arg_tx(&artifacts, "artifacts")?;
        let payer = hex32_arg(&payer, "payer")?;
        let addresses = plan::refund_addresses(&self.inner, leg, &artifacts, &payer).map_err(js)?;
        to_js(&Value::from(addresses))
    }

    /// `tx::refund` of `leg` by `signer` over the UTXOs of a reply text. `withToken` carries a
    /// KCC-20 leg's escrowed token home; without it the token stays escrowed.
    #[wasm_bindgen(js_name = refundFromReply)]
    #[allow(clippy::too_many_arguments)]
    pub fn refund_from_reply(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RefundSignerName")] signer: JsValue,
        #[wasm_bindgen(js_name = withToken)] with_token: bool,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] reply: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PlanFundingJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let leg = leg_arg(&leg)?;
        let signer = text_arg(&signer, "signer", 32)?;
        let reply = text_arg(&reply, "reply", rpc::MAX_REPLY_TEXT)?;
        let (artifacts, funding, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = plan::refund_from_reply(
            &self.inner,
            leg,
            &signer,
            with_token,
            &artifacts,
            &reply,
            &funding,
            &value,
        )
        .map_err(js)?;
        Ok(JsIpst { inner: ipst })
    }

    /// The addresses to ask the node about before `directFromReply`.
    #[wasm_bindgen(js_name = directAddresses, unchecked_return_type = "string[]")]
    pub fn direct_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Hex")] payer: JsValue,
    ) -> Result<JsValue, JsValue> {
        let artifacts = json_arg_tx(&artifacts, "artifacts")?;
        let payer = hex32_arg(&payer, "payer")?;
        let addresses = plan::direct_addresses(&self.inner, &artifacts, &payer).map_err(js)?;
        to_js(&Value::from(addresses))
    }

    /// `tx::direct` over the UTXOs of a reply text.
    #[wasm_bindgen(js_name = directFromReply)]
    pub fn direct_from_reply(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] reply: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PlanFundingJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let reply = text_arg(&reply, "reply", rpc::MAX_REPLY_TEXT)?;
        let (artifacts, funding, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = plan::direct_from_reply(&self.inner, &artifacts, &reply, &funding, daa, &value)
            .map_err(js)?;
        Ok(JsIpst { inner: ipst })
    }

    /// The addresses to ask the node about before `fundCashFromReply`: the cash vault, the asset
    /// vault with the token escrowed in it, and the payer's own. Refused like the builder is,
    /// before the node is asked: a native KAS cash leg below the minimum
    /// (`TX_BELOW_MIN_KAS`), only the buyer funds the cash leg (`SDK_FUND_NOT_YOUR_LEG`),
    /// Direct terms and external cash have no cash vault (`TEMPLATE_NO_VAULT`), a KCC-20 cash leg
    /// is not funded here (`TX_WRONG_MODE`), and a KCC-20 template that is not a pinned kcc20.sil
    /// build is never funded (`SDK_TEMPLATE_UNPINNED`).
    #[wasm_bindgen(js_name = fundCashAddresses, unchecked_return_type = "string[]")]
    pub fn fund_cash_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Hex")] payer: JsValue,
    ) -> Result<JsValue, JsValue> {
        let artifacts = json_arg_tx(&artifacts, "artifacts")?;
        let payer = hex32_arg(&payer, "payer")?;
        let addresses = plan::fund_cash_addresses(&self.inner, &artifacts, &payer).map_err(js)?;
        to_js(&Value::from(addresses))
    }

    /// `tx::fund_kas` over the UTXOs of the text of a `getUtxosByAddresses` reply: the buyer's
    /// funding of a KAS cash vault, one output of exactly the cash amount, paid by the payer's own
    /// UTXOs that also pay the fee. `funding` is `{ payer, fee, change? }` and `payer` must be the
    /// buyer's key. `currentDaa` is the node's DAA score: the creation checks run with it. The
    /// reply must show the seller's asset leg funded (the authorizer at the asset vault and the
    /// escrowed token in its exact state: `SDK_FUND_ASSET_NOT_FUNDED`) and no deposit of exactly
    /// the cash amount at the cash vault yet (`SDK_FUND_ALREADY_FUNDED`).
    #[wasm_bindgen(js_name = fundCashFromReply)]
    pub fn fund_cash_from_reply(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] reply: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PlanFundingJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let reply = text_arg(&reply, "reply", rpc::MAX_REPLY_TEXT)?;
        let (artifacts, funding, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst =
            plan::fund_cash_from_reply(&self.inner, &artifacts, &reply, &funding, daa, &value)
                .map_err(js)?;
        Ok(JsIpst { inner: ipst })
    }
}

// The review of an IPST.

#[wasm_bindgen(js_class = Ipst)]
impl JsIpst {
    /// Everything a signer reads before signing: each input and output with its amount,
    /// scriptPublicKey, address and what the terms say it is, the fee, the lock time, and the
    /// masses. Only for a document the builders make from its own inputs and within the value
    /// cap: it runs `verifyAgainstTerms` first, with the same arguments. `held` are the public
    /// keys that live only in wallets of the page: the review marks the outputs that pay them.
    #[wasm_bindgen(unchecked_return_type = "ReviewJson")]
    pub fn review(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
        held: Option<Vec<String>>,
    ) -> Result<JsValue, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (artifacts, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&value, "value")?,
        );
        let held = held.unwrap_or_default();
        if held.len() > crate::role::MAX_HELD {
            return Err(js(SdkError::json(
                "held",
                format!("at most {} keys", crate::role::MAX_HELD),
            )));
        }
        let held: Vec<[u8; 32]> = held
            .iter()
            .enumerate()
            .map(|(i, key)| {
                hex_decode(key)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| {
                        js(SdkError::json(
                            format!("held[{i}]"),
                            "expected 64 lowercase hex digits",
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        to_js(&review::review(&self.inner, &artifacts, daa, &value, &held).map_err(js)?)
    }
}

// The node.

/// The node calls the page makes, by name.
#[wasm_bindgen(js_name = rpcMethods)]
pub fn rpc_methods() -> Vec<String> {
    rpc::METHODS.iter().map(|m| m.to_string()).collect()
}

/// The request text for a node call. `argument` is null for `getServerInfo` and
/// `getBlockDagInfo`, an array of addresses for `getUtxosByAddresses`, a transaction ID for
/// `getMempoolEntry` and a chain block hash for `getVirtualChainFromBlockV2`.
#[wasm_bindgen(js_name = rpcRequest)]
pub fn rpc_request(
    #[wasm_bindgen(unchecked_param_type = "number")] id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RpcMethod")] method: JsValue,
    #[wasm_bindgen(unchecked_param_type = "unknown")] argument: JsValue,
) -> Result<String, JsValue> {
    let id = index_arg(&id, "id")? as u64;
    let method = text_arg(&method, "method", 64)?;
    let argument = if argument.is_undefined() {
        Value::Null
    } else {
        json_arg_tx(&argument, "argument")?
    };
    rpc::request(id, &method, &argument).map_err(js)
}

/// The `submitTransaction` request for a signed transaction.
#[wasm_bindgen(js_name = rpcSubmitRequest)]
pub fn rpc_submit_request(
    #[wasm_bindgen(unchecked_param_type = "number")] id: JsValue,
    transaction: &JsSignedTransaction,
) -> Result<String, JsValue> {
    let id = index_arg(&id, "id")? as u64;
    Ok(rpc::submit_request(id, transaction.transaction()))
}

/// The reply to request `id` for `method`, in the SDK's forms (see `rpc.rs`). For the two calls
/// that return a transaction, use `rpcTransactionReply`.
#[wasm_bindgen(js_name = rpcReply, unchecked_return_type = "RpcReplyJson")]
pub fn rpc_reply(
    #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RpcMethod")] method: JsValue,
) -> Result<JsValue, JsValue> {
    let text = text_arg(&text, "text", rpc::MAX_REPLY_TEXT)?;
    let id = index_arg(&id, "id")? as u64;
    let method = text_arg(&method, "method", 64)?;
    to_js(&rpc::reply(&text, id, &method, None).map_err(js)?)
}

/// The reply to `getMempoolEntry` or `getVirtualChainFromBlockV2` for the transaction `txid`: the
/// transaction as the page holds it (`FetchedTransactionJson`), which must hash to `txid`
/// (`SDK_TXID_MISMATCH`); from the chain call, null when the chain reply does not carry it.
#[wasm_bindgen(js_name = rpcTransactionReply, unchecked_return_type = "RpcReplyJson")]
pub fn rpc_transaction_reply(
    #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "RpcMethod")] method: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Hex")] txid: JsValue,
) -> Result<JsValue, JsValue> {
    let text = text_arg(&text, "text", rpc::MAX_REPLY_TEXT)?;
    let id = index_arg(&id, "id")? as u64;
    let method = text_arg(&method, "method", 64)?;
    let txid = hex32_arg(&txid, "txid")?;
    to_js(&rpc::reply(&text, id, &method, Some(txid)).map_err(js)?)
}

/// The reply to a submit request: the transaction ID the node accepted, which must be the
/// submitted transaction's (`SDK_TXID_MISMATCH`).
#[wasm_bindgen(js_name = rpcSubmitReply, unchecked_return_type = "Hex")]
pub fn rpc_submit_reply(
    #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] id: JsValue,
    transaction: &JsSignedTransaction,
) -> Result<String, JsValue> {
    let text = text_arg(&text, "text", rpc::MAX_REPLY_TEXT)?;
    let id = index_arg(&id, "id")? as u64;
    rpc::submit_reply(&text, id, transaction.txid_bytes()).map_err(js)
}

/// Refuses a node URL that is not `ws://` or `wss://`, and on mainnet one that is plaintext to
/// another machine.
#[wasm_bindgen(js_name = checkNodeUrl)]
pub fn check_node_url(
    #[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<(), JsValue> {
    let url = text_arg(&url, "url", 2048)?;
    rpc::check_node_url(&url, network_arg(&network)?).map_err(js)
}

/// Refuses a node that is on another network than `network`, or not synced; `info` is the reply
/// to `getServerInfo` as `rpcReply` returns it.
#[wasm_bindgen(js_name = checkNode)]
pub fn check_node(
    #[wasm_bindgen(unchecked_param_type = "ServerInfoJson")] info: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<(), JsValue> {
    let info = json_arg(&info, "info")?;
    rpc::check_node(&info, network_arg(&network)?).map_err(js)
}

/// Decodes a transaction fetched from the node (`rpcReply` of `getMempoolEntry` or
/// `getVirtualChainFromBlockV2`), bound to the scriptPublicKeys its inputs spend where the node
/// gave all of them, else not bound (`bound` false). The transaction's own hash must be `txid`.
#[wasm_bindgen(js_name = decodeFetched, unchecked_return_type = "DecodedTransactionJson")]
pub fn decode_fetched(
    #[wasm_bindgen(unchecked_param_type = "FetchedTransactionJson")] fetched: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Hex")] txid: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<JsValue, JsValue> {
    let txid = hex32_arg(&txid, "txid")?;
    let fetched = fetched_arg(&fetched)?;
    to_js(&rpc::decode_fetched(&fetched, txid, network_arg(&network)?).map_err(js)?)
}

/// A fetched transaction carries its raw form in hex, two digits a byte of at most twice the
/// transaction mass cap, so its `raw` is read with a text bound of its own. Only the three
/// members `decode_fetched` reads are taken.
fn fetched_arg(value: &JsValue) -> Result<Value, JsValue> {
    let wrong = || js(SdkError::json("fetched", "expected an object"));
    if !value.is_object() {
        return Err(wrong());
    }
    let member = |key: &str| Reflect::get(value, &key.into()).map_err(|_| wrong());
    let txid = text_arg(&member("txid")?, "fetched.txid", 64)?;
    let raw = text_arg(&member("raw")?, "fetched.raw", 2 * crate::TX_BYTES_LONGEST)?;
    let spent = json_arg_tx(&member("spent")?, "fetched.spent")?;
    Ok(serde_json::json!({ "txid": txid, "raw": raw, "spent": spent }))
}

// The wallet.

/// A wallet: a key drawn in the page from the browser's `crypto.getRandomValues`, held in wasm
/// memory and never handed out. See `wallet.rs` for what that does and does not promise.
#[wasm_bindgen(js_name = Wallet)]
pub struct JsWallet {
    inner: Wallet,
}

#[cfg(target_arch = "wasm32")]
fn fill_random(bytes: &mut [u8; 32]) -> Result<(), SdkError> {
    getrandom::fill(bytes).map_err(|e| SdkError::WalletRandom {
        reason: e.to_string(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn fill_random(bytes: &mut [u8; 32]) -> Result<(), SdkError> {
    use secp256k1::rand::RngCore;
    secp256k1::rand::thread_rng().fill_bytes(bytes);
    Ok(())
}

#[wasm_bindgen(js_class = Wallet)]
impl JsWallet {
    /// A new wallet with a key of its own.
    pub fn generate() -> Result<JsWallet, JsValue> {
        Ok(JsWallet {
            inner: Wallet::generate(fill_random).map_err(js)?,
        })
    }

    /// The x-only public key, 64 lowercase hex digits. Public; still known after a wipe.
    #[wasm_bindgen(js_name = publicKey, unchecked_return_type = "Hex")]
    pub fn public_key(&self) -> String {
        crate::json::hex(&self.inner.public_key())
    }

    /// The P2PK address of the key on `network`: where to send this wallet KAS.
    pub fn address(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
    ) -> Result<String, JsValue> {
        let network = network_arg(&network)?;
        Ok(
            review::address_of(network, &review::p2pk(&self.inner.public_key()))
                .expect("a P2PK script has an address"),
        )
    }

    /// Zeroes the key now. Every later `sign` is `SDK_WALLET_WIPED`.
    pub fn wipe(&mut self) {
        self.inner.wipe();
    }

    #[wasm_bindgen(js_name = isWiped)]
    pub fn is_wiped(&self) -> bool {
        self.inner.is_wiped()
    }

    /// Signs every input of `ipst` that names this wallet's key and lacks a signature, after the
    /// checks of `wallet.rs`. Returns `{ ipst, signed_inputs }`; the document passed in is not
    /// changed.
    #[wasm_bindgen(unchecked_return_type = "SignResult")]
    pub fn sign(
        &self,
        ipst: &JsIpst,
        #[wasm_bindgen(unchecked_param_type = "SignOptionsJson")] options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let options = json_arg_tx(&options, "options")?;
        let options = wallet::sign_options_from_json(&options).map_err(js)?;
        let (signed, inputs) = wallet::sign_ipst(&self.inner, &ipst.inner, &options).map_err(js)?;
        let out = Object::new();
        let list: Array = inputs
            .into_iter()
            .map(|i| JsValue::from_f64(i as f64))
            .collect();
        let _ = Reflect::set(
            &out,
            &"ipst".into(),
            &JsValue::from(JsIpst { inner: signed }),
        );
        let _ = Reflect::set(&out, &"signed_inputs".into(), &list);
        Ok(out.into())
    }
}
