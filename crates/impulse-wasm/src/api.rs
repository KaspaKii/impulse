// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The phase 2 bindings (I9): the transaction builders, the IPST, signatures and assembly, verify
//! and decode. Each reads its JavaScript arguments into JSON values (`lib.rs`) and calls the
//! operation of `ops.rs`; a result comes back as a class or a plain object. Nothing here signs,
//! generates or holds a private key: a signature arrives as 65 bytes a caller made elsewhere and
//! is verified before it is stored.

use crate::error::{js, Failure};
use crate::ops;
use crate::{
    bytes_arg, index_arg, json_arg_tx, leg_arg, network_arg, text_arg, u64_arg, JsValidatedTerms,
    SHORT_BYTES, TX_BYTES,
};
use impulse_core::decode::DECODE_ERROR_CODES;
use impulse_core::tx::{
    self, Ipst, TxError, IPST_VERSION, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT, STANDARD_MASS_CAP,
    TX_ERROR_CODES,
};
use impulse_core::verify::{PINNED_KCC20_TEMPLATES, TOKEN_WARNING_CODES, VERIFY_ERROR_CODES};
use js_sys::Array;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

/// At most this many UTF-16 code units in an IPST's JSON text. The longest legal IPST holds a few
/// hundred inputs, each with a token redeem script of at most about 14 KB, in hex; the text is
/// measured before it is copied into wasm memory, which never shrinks.
const MAX_IPST_TEXT: u32 = 1 << 23;

fn to_js(value: &Value) -> Result<JsValue, JsValue> {
    js_sys::JSON::parse(&value.to_string())
}

fn fail(e: Failure) -> JsValue {
    js(e)
}

fn tx_fail(e: TxError) -> JsValue {
    js(e)
}

// Builders: methods of ValidatedTerms, so that the terms a builder works from are the checked
// terms and nothing else.

#[wasm_bindgen(js_class = ValidatedTerms)]
impl JsValidatedTerms {
    /// `tx::fund_kas`: funds the KAS cash leg. `context` is the creation context; its
    /// `creation_daa` is the current DAA score. The value declaration is checked first.
    #[wasm_bindgen(js_name = fundKas)]
    pub fn fund_kas(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let (context, funding, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = ops::fund_kas(&self.inner, &context, &funding, &value).map_err(fail)?;
        Ok(JsIpst { inner: ipst })
    }

    /// `tx::fund_kcc20`: funds a KCC-20 leg (0 the asset leg, 1 the cash leg).
    #[wasm_bindgen(js_name = fundKcc20)]
    pub fn fund_kcc20(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Kcc20DepositJson")] deposit: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let leg = leg_arg(&leg)?;
        let (context, deposit, funding, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&deposit, "deposit")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = ops::fund_kcc20(&self.inner, leg, &context, &deposit, &funding, &value)
            .map_err(fail)?;
        Ok(JsIpst { inner: ipst })
    }

    /// `tx::settle`. `currentDaa` is the caller's current DAA score, a decimal string or a
    /// bigint.
    pub fn settle(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SettleLegsJson")] legs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (legs, funding, value) = (
            json_arg_tx(&legs, "legs")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = ops::settle(&self.inner, &legs, &funding, daa, &value).map_err(fail)?;
        Ok(JsIpst { inner: ipst })
    }

    /// `tx::refund`: `signer` is "depositor", "counterparty" or "authority"; `escrow` is null for
    /// a refund of the vault UTXO alone (the escrowed token then stays escrowed).
    pub fn refund(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RefundSignerName")] signer: JsValue,
        #[wasm_bindgen(js_name = vaultUtxo, unchecked_param_type = "UtxoJson")] vault_utxo: JsValue,
        #[wasm_bindgen(unchecked_param_type = "RefundEscrowJson | null")] escrow: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let leg = leg_arg(&leg)?;
        let signer = text_arg(&signer, "signer", 32)?;
        let vault_utxo = json_arg_tx(&vault_utxo, "vaultUtxo")?;
        let escrow = if escrow.is_null() {
            None
        } else {
            Some(json_arg_tx(&escrow, "escrow")?)
        };
        let (funding, value) = (
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = ops::refund(
            &self.inner,
            leg,
            &signer,
            &vault_utxo,
            escrow.as_ref(),
            &funding,
            &value,
        )
        .map_err(fail)?;
        Ok(JsIpst { inner: ipst })
    }

    /// `tx::direct`.
    pub fn direct(
        &self,
        #[wasm_bindgen(unchecked_param_type = "DirectLegsJson")] legs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "FeePaymentJson")] funding: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (legs, funding, value) = (
            json_arg_tx(&legs, "legs")?,
            json_arg_tx(&funding, "funding")?,
            json_arg_tx(&value, "value")?,
        );
        let ipst = ops::direct(&self.inner, &legs, &funding, daa, &value).map_err(fail)?;
        Ok(JsIpst { inner: ipst })
    }

    /// `verify::verify_addresses`: recomputes each leg's funding address and compares it with the
    /// one offered. The value cap holds (the last argument is the builders' declaration).
    #[wasm_bindgen(js_name = verifyAddresses, unchecked_return_type = "VerifiedAddressJson[]")]
    pub fn verify_addresses(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "OfferedAddressesJson")] offered: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsValue, JsValue> {
        let (context, offered, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&offered, "offered")?,
            json_arg_tx(&value, "value")?,
        );
        to_js(&ops::verify_addresses(&self.inner, &context, &offered, &value).map_err(fail)?)
    }

    /// `verify::before_funding`: the address check, then the token warnings. The value cap
    /// holds, as in `verifyAddresses`.
    #[wasm_bindgen(js_name = beforeFunding, unchecked_return_type = "FundingCheckJson")]
    pub fn before_funding(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "OfferedAddressesJson")] offered: JsValue,
        #[wasm_bindgen(unchecked_param_type = "TokenEvidencesJson")] evidence: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsValue, JsValue> {
        let (context, offered, evidence, value) = (
            json_arg_tx(&context, "context")?,
            json_arg_tx(&offered, "offered")?,
            json_arg_tx(&evidence, "evidence")?,
            json_arg_tx(&value, "value")?,
        );
        to_js(
            &ops::before_funding(&self.inner, &context, &offered, &evidence, &value)
                .map_err(fail)?,
        )
    }

    /// `verify::token_warnings`.
    #[wasm_bindgen(js_name = tokenWarnings, unchecked_return_type = "TokenWarningJson[]")]
    pub fn token_warnings(
        &self,
        #[wasm_bindgen(unchecked_param_type = "TokenEvidencesJson")] evidence: JsValue,
    ) -> Result<JsValue, JsValue> {
        let evidence = json_arg_tx(&evidence, "evidence")?;
        to_js(&ops::token_warnings(&self.inner, &evidence).map_err(fail)?)
    }

    /// `verify::verify_revealed_script`: a revealed redeem script against these terms and leg.
    #[wasm_bindgen(js_name = verifyRevealedScript)]
    pub fn verify_revealed_script(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(js_name = redeemScript, unchecked_param_type = "Uint8Array")]
        redeem_script: JsValue,
    ) -> Result<(), JsValue> {
        let leg = leg_arg(&leg)?;
        let script = bytes_arg(&redeem_script, "redeemScript", TX_BYTES)?;
        ops::verify_revealed_script(&self.inner, leg, &script).map_err(fail)
    }

    /// `verify::verify_spent_input`: the signature script of a spent input, bound to the
    /// scriptPublicKey of the UTXO it spends, as the node reports it.
    #[wasm_bindgen(js_name = verifySpentInput)]
    pub fn verify_spent_input(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(js_name = signatureScript, unchecked_param_type = "Uint8Array")]
        signature_script: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ScriptPublicKeyJson")] spent: JsValue,
    ) -> Result<(), JsValue> {
        let leg = leg_arg(&leg)?;
        let script = bytes_arg(&signature_script, "signatureScript", TX_BYTES)?;
        let spent = json_arg_tx(&spent, "spent")?;
        ops::verify_spent_input(&self.inner, leg, &script, &spent).map_err(fail)
    }
}

// The IPST.

/// impulse_core::tx::Ipst: a partially signed transaction (spec/IPST.md).
#[wasm_bindgen(js_name = Ipst)]
pub struct JsIpst {
    pub(crate) inner: Ipst,
}

#[wasm_bindgen(js_class = Ipst)]
impl JsIpst {
    /// `Ipst::from_json`: the strict reader of spec/IPST.md. Every sighash is recomputed and
    /// every signature verified. A text with more than 256 inputs or outputs is `SDK_JSON_FORM`,
    /// refused before any of that work.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let text = text_arg(&text, "ipst", MAX_IPST_TEXT)?;
        Ok(JsIpst {
            inner: ops::ipst_from_json(&text, "ipst").map_err(fail)?,
        })
    }

    /// The canonical JSON text (spec/IPST.md, "Canonical rendering").
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> String {
        self.inner.to_json()
    }

    pub fn terms(&self) -> JsValidatedTerms {
        JsValidatedTerms {
            inner: self.inner.terms().clone(),
        }
    }

    /// What the inputs hold less what the outputs pay, in sompi.
    #[wasm_bindgen(unchecked_return_type = "U64String")]
    pub fn fee(&self) -> String {
        self.inner.fee().to_string()
    }

    /// The masses of the signed transaction and the minimum relay fee for them.
    #[wasm_bindgen(unchecked_return_type = "MassesJson")]
    pub fn masses(&self) -> Result<JsValue, JsValue> {
        to_js(&ops::masses_json(&self.inner))
    }

    /// The signature slots, in input order.
    #[wasm_bindgen(unchecked_return_type = "IpstSlotJson[]")]
    pub fn slots(&self) -> Result<JsValue, JsValue> {
        to_js(&ops::slots_json(&self.inner))
    }

    /// The inputs whose slot needs a signature and has none.
    #[wasm_bindgen(unchecked_return_type = "number[]")]
    pub fn pending(&self) -> JsValue {
        self.inner
            .pending()
            .into_iter()
            .map(|i| JsValue::from_f64(i as f64))
            .collect::<Array>()
            .into()
    }

    #[wasm_bindgen(js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// `tx::sighash`: the SIG_HASH_ALL Schnorr sighash of input `input`.
    pub fn sighash(
        &self,
        #[wasm_bindgen(unchecked_param_type = "number")] input: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let input = index_arg(&input, "input")?;
        Ok(ops::sighash(&self.inner, input).map_err(fail)?.to_vec())
    }

    /// `Ipst::add_signature`: verifies a 65-byte signature against the slot's signer and
    /// sighash, then stores it.
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "number")] input: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] signature: JsValue,
    ) -> Result<(), JsValue> {
        let input = index_arg(&input, "input")?;
        let signature = bytes_arg(&signature, "signature", SHORT_BYTES)?;
        self.inner.add_signature(input, &signature).map_err(tx_fail)
    }

    /// `Ipst::combine` with another IPST given as its JSON text.
    pub fn combine(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] other: JsValue,
    ) -> Result<JsIpst, JsValue> {
        let other = text_arg(&other, "other", MAX_IPST_TEXT)?;
        Ok(JsIpst {
            inner: ops::combine(&self.inner, &other).map_err(fail)?,
        })
    }

    /// `Ipst::finalize`: the signed transaction; every slot with a signer must hold a signature.
    pub fn finalize(&self) -> Result<JsSignedTransaction, JsValue> {
        let tx = self.inner.finalize().map_err(tx_fail)?;
        Ok(JsSignedTransaction::new(&tx))
    }

    /// `Ipst::assemble`: stores each `{ input, signature }`, then finalizes.
    pub fn assemble(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignatureJson[]")] signatures: JsValue,
    ) -> Result<JsSignedTransaction, JsValue> {
        let signatures = json_arg_tx(&signatures, "signatures")?;
        let tx = ops::assemble(&self.inner, &signatures).map_err(fail)?;
        Ok(JsSignedTransaction::new(&tx))
    }

    /// `Ipst::verify_against_terms`: whether the builders make this transaction from its own
    /// inputs. `artifacts` holds the legs' KCC-20 templates; `currentDaa` the caller's DAA score.
    /// This is the check a signer runs before signing, so the value cap holds (the last argument
    /// is the builders' declaration).
    #[wasm_bindgen(js_name = verifyAgainstTerms, unchecked_return_type = "TermsMatchJson")]
    pub fn verify_against_terms(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ArtifactsJson")] artifacts: JsValue,
        #[wasm_bindgen(js_name = currentDaa, unchecked_param_type = "U64String | bigint")]
        current_daa: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsValue, JsValue> {
        let daa = u64_arg(&current_daa, "currentDaa")?;
        let (artifacts, value) = (
            json_arg_tx(&artifacts, "artifacts")?,
            json_arg_tx(&value, "value")?,
        );
        to_js(&ops::verify_against_terms(&self.inner, &artifacts, daa, &value).map_err(fail)?)
    }
}

/// A signed transaction: its ID and its raw form (rusty-kaspa a41a333's borsh encoding, which
/// `decodeRaw` reads).
#[wasm_bindgen(js_name = SignedTransaction)]
pub struct JsSignedTransaction {
    txid: [u8; 32],
    raw: Vec<u8>,
    tx: kaspa_consensus_core::tx::Transaction,
}

impl JsSignedTransaction {
    pub(crate) fn new(tx: &kaspa_consensus_core::tx::Transaction) -> Self {
        let (txid, raw) = ops::signed(tx);
        Self {
            txid,
            raw,
            tx: tx.clone(),
        }
    }

    /// The transaction, for the submit request.
    pub(crate) fn transaction(&self) -> &kaspa_consensus_core::tx::Transaction {
        &self.tx
    }

    pub(crate) fn txid_bytes(&self) -> [u8; 32] {
        self.txid
    }
}

#[wasm_bindgen(js_class = SignedTransaction)]
impl JsSignedTransaction {
    /// The transaction ID.
    pub fn txid(&self) -> Vec<u8> {
        self.txid.to_vec()
    }

    /// The raw form.
    pub fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }
}

// Signatures.

/// `tx::verify_schnorr_sig65`: a 65-byte signature (BIP-340 Schnorr and the sighash type byte,
/// which must be SIG_HASH_ALL) against a sighash and an x-only public key.
#[wasm_bindgen(js_name = verifySchnorrSig65)]
pub fn verify_schnorr_sig65(
    #[wasm_bindgen(js_name = pubkeyXonly, unchecked_param_type = "Uint8Array")] pubkey: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] sighash: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] signature: JsValue,
) -> Result<(), JsValue> {
    let (pubkey, sighash, signature) = (
        bytes_arg(&pubkey, "pubkeyXonly", SHORT_BYTES)?,
        bytes_arg(&sighash, "sighash", SHORT_BYTES)?,
        bytes_arg(&signature, "signature", SHORT_BYTES)?,
    );
    let refuse = |reason: &str| {
        tx_fail(TxError::Signature {
            input: None,
            reason: reason.into(),
        })
    };
    let pubkey: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| refuse("an x-only public key is 32 bytes"))?;
    let sighash: [u8; 32] = sighash
        .try_into()
        .map_err(|_| refuse("a sighash is 32 bytes"))?;
    tx::verify_schnorr_sig65(&pubkey, &sighash, &signature).map_err(tx_fail)
}

// KCC-20 templates.

/// The template triple (hash, prefix length, suffix length) a leg of terms names a token by,
/// from the token's silverscript ABI artifact text. Refuses an artifact that is not kcc20.sil's
/// layout (`TX_TOKEN_TEMPLATE`).
#[wasm_bindgen(js_name = kcc20Template, unchecked_return_type = "Kcc20TemplateJson")]
pub fn kcc20_template(
    #[wasm_bindgen(unchecked_param_type = "string")] artifact: JsValue,
) -> Result<JsValue, JsValue> {
    let artifact = text_arg(&artifact, "artifact", 1 << 17)?;
    to_js(&ops::kcc20_template(&artifact).map_err(fail)?)
}

/// The P2SH scriptPublicKey of a token UTXO in the given state, from the token's artifact text.
#[wasm_bindgen(js_name = kcc20ScriptPublicKey, unchecked_return_type = "ScriptPublicKeyJson")]
pub fn kcc20_script_public_key(
    #[wasm_bindgen(unchecked_param_type = "string")] artifact: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Kcc20StateJson")] state: JsValue,
) -> Result<JsValue, JsValue> {
    let artifact = text_arg(&artifact, "artifact", 1 << 17)?;
    let state = json_arg_tx(&state, "state")?;
    to_js(&ops::kcc20_script_public_key(&artifact, &state).map_err(fail)?)
}

// Decode.

/// `decode::decode_raw`: the vault inputs of a raw transaction, bound to the scriptPublicKey each
/// input spends (one per input, as the node reports them).
#[wasm_bindgen(js_name = decodeRaw, unchecked_return_type = "DecodedTransactionJson")]
pub fn decode_raw(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] raw: JsValue,
    #[wasm_bindgen(unchecked_param_type = "ScriptPublicKeyJson[]")] spent: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<JsValue, JsValue> {
    let raw = bytes_arg(&raw, "raw", TX_BYTES)?;
    let spent = json_arg_tx(&spent, "spent")?;
    let network = network_arg(&network)?;
    to_js(&ops::decode_raw(&raw, &spent, network).map_err(fail)?)
}

/// `decode::decode_raw_unbound`: as `decodeRaw` without the binding to the spent UTXOs. What it
/// reports is only as trustworthy as the source of the transaction; `bound` is false.
#[wasm_bindgen(js_name = decodeRawUnbound, unchecked_return_type = "DecodedTransactionJson")]
pub fn decode_raw_unbound(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] raw: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<JsValue, JsValue> {
    let raw = bytes_arg(&raw, "raw", TX_BYTES)?;
    let network = network_arg(&network)?;
    to_js(&ops::decode_raw_unbound(&raw, network).map_err(fail)?)
}

// Constants and code lists.

/// `tx::IPST_VERSION`.
#[wasm_bindgen(js_name = ipstVersion)]
pub fn ipst_version() -> u16 {
    IPST_VERSION
}

/// `tx::MIN_KAS_OUTPUT`, in sompi.
#[wasm_bindgen(js_name = minKasOutput, unchecked_return_type = "U64String")]
pub fn min_kas_output() -> String {
    MIN_KAS_OUTPUT.to_string()
}

/// `tx::MIN_KCC20_OUTPUT`, in sompi.
#[wasm_bindgen(js_name = minKcc20Output, unchecked_return_type = "U64String")]
pub fn min_kcc20_output() -> String {
    MIN_KCC20_OUTPUT.to_string()
}

/// `tx::STANDARD_MASS_CAP`.
#[wasm_bindgen(js_name = standardMassCap, unchecked_return_type = "U64String")]
pub fn standard_mass_cap() -> String {
    STANDARD_MASS_CAP.to_string()
}

/// The default per-trade value cap, in sompi (10 KAS).
#[wasm_bindgen(js_name = defaultMaxValueSompi, unchecked_return_type = "U64String")]
pub fn default_max_value_sompi() -> String {
    crate::value::DEFAULT_MAX_VALUE_SOMPI.to_string()
}

/// `tx::min_relay_fee` for a fee mass.
#[wasm_bindgen(js_name = minRelayFee, unchecked_return_type = "U64String")]
pub fn min_relay_fee(
    #[wasm_bindgen(js_name = feeMass, unchecked_param_type = "U64String | bigint")]
    fee_mass: JsValue,
) -> Result<String, JsValue> {
    Ok(tx::min_relay_fee(u64_arg(&fee_mass, "feeMass")?).to_string())
}

/// `tx::TX_ERROR_CODES`, in order.
#[wasm_bindgen(js_name = txErrorCodes)]
pub fn tx_error_codes() -> Vec<String> {
    TX_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}

/// `verify::VERIFY_ERROR_CODES`, in order.
#[wasm_bindgen(js_name = verifyErrorCodes)]
pub fn verify_error_codes() -> Vec<String> {
    VERIFY_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}

/// `decode::DECODE_ERROR_CODES`, in order.
#[wasm_bindgen(js_name = decodeErrorCodes)]
pub fn decode_error_codes() -> Vec<String> {
    DECODE_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}

/// `verify::TOKEN_WARNING_CODES`, in order. Warnings are data, not refusals.
#[wasm_bindgen(js_name = tokenWarningCodes)]
pub fn token_warning_codes() -> Vec<String> {
    TOKEN_WARNING_CODES.iter().map(|c| c.to_string()).collect()
}

/// `verify::PINNED_KCC20_TEMPLATES`, in order: the kcc20.sil builds (silverscript v1.0.0, compiled
/// with the pinned silverc for every `maxCovIns` and `maxCovOuts` from 1 to 4) that a funding
/// accepts. A KCC-20 leg whose template is none of them is refused by `fundingInstructions`,
/// `fundCashAddresses`, `fundCashFromReply` and the signing of a funding
/// (`SDK_TEMPLATE_UNPINNED`).
#[wasm_bindgen(js_name = pinnedKcc20Templates, unchecked_return_type = "PinnedKcc20Json[]")]
pub fn pinned_kcc20_templates() -> Result<JsValue, JsValue> {
    let list: Vec<Value> = PINNED_KCC20_TEMPLATES
        .iter()
        .map(|p| {
            json!({
                "max_cov_ins": p.max_cov_ins,
                "max_cov_outs": p.max_cov_outs,
                "template_hash": crate::json::hex(&p.triple.hash),
                "template_prefix_len": p.triple.prefix_len,
                "template_suffix_len": p.triple.suffix_len,
            })
        })
        .collect();
    to_js(&Value::from(list))
}
