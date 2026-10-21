// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Unsigned transaction builders (spec/TRANSACTIONS.md) and the split signing flow: build the
//! unsigned transaction, compute each input's sighash, verify each signature a signer returns,
//! assemble the signed transaction from signature bytes. The builders return an [`Ipst`]
//! (spec/IPST.md), which carries the unsigned transaction, the UTXOs it spends and one signature
//! slot per input.
//!
//! Keyless by rule (rule 1, docs/ENGINEERING-RULES.md): nothing in this module signs, holds or derives a private
//! key. Signatures arrive as 65-byte values and are verified before they are used.
//!
//! The split flow (unsigned build, sighash, `verify_schnorr_sig65`, assemble) is adapted from an
//! internal split-signing module by the owner (relicensed, see NOTICE), generalised from two
//! fixed inputs to the ImpulseVault layouts with any number of fee inputs; its key-holding
//! signer and its hashlock are not carried over.

pub(crate) mod build;
mod error;
pub(crate) mod ipst;
pub(crate) mod kcc20;
pub(crate) mod rules;

#[cfg(test)]
mod golden;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use build::{
    direct, fund_kas, fund_kcc20, refund, settle, DirectCash, DirectLegs, IpstKind, Kcc20Deposit,
    RefundEscrow, RefundSigner, SettleCash, SettleLegs, TermsMatch,
};
pub use error::{TxError, TX_ERROR_CODES};
pub use ipst::{Ipst, IPST_VERSION};
pub use kcc20::{Kcc20State, Kcc20Template};
pub use rules::{
    min_output_value, min_relay_fee, Masses, KCC20_KEY_OWNED_BUDGET, KCC20_VAULT_OWNED_BUDGET,
    MAX_OUTPUTS, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT, MIN_RELAY_FEE_PER_KILOGRAM, P2PK_BUDGET,
    SOMPI_PER_STORAGE_UNIT, STANDARD_MASS_CAP, VAULT_BUDGET,
};

use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::EngineFlags;
use secp256k1::{schnorr, Message, XOnlyPublicKey};

/// A UTXO a transaction spends: its outpoint and its entry (value, scriptPubKey, DAA score,
/// coinbase flag, covenant ID), as the node reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}

/// A KCC-20 UTXO with the state its script holds. A builder checks that the scriptPubKey is the
/// P2SH of the token template holding exactly this state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenUtxo {
    pub utxo: Utxo,
    pub state: Kcc20State,
}

/// The submitter's KAS: version-0 P2PK Schnorr UTXOs that pay the fee (and, when funding, the
/// deposit), the exact fee in sompi, and where the change goes. Change is the inputs less the
/// outputs and the fee; it is omitted when zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePayment {
    pub inputs: Vec<Utxo>,
    pub fee: u64,
    pub change: ScriptPublicKey,
}

/// The SIG_HASH_ALL Schnorr sighash of input `input`, over the transaction and the UTXO entries
/// it spends (signature scripts are not part of it). Refuses an input index out of range, or
/// entries that do not match the inputs one for one (`TX_SIGNATURE_SLOT`).
pub fn sighash(tx: &Transaction, entries: &[UtxoEntry], input: usize) -> Result<[u8; 32], TxError> {
    if entries.len() != tx.inputs.len() {
        return Err(TxError::SignatureSlot {
            input,
            reason: "the UTXO entries do not match the inputs one for one",
        });
    }
    if input >= tx.inputs.len() {
        return Err(TxError::SignatureSlot {
            input,
            reason: "no such input",
        });
    }
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    Ok(calc_schnorr_signature_hash(&populated, input, SIG_HASH_ALL, &reused).as_bytes())
}

/// Verifies a 65-byte signature (a 64-byte BIP-340 Schnorr signature and the sighash type byte)
/// against a sighash and an x-only public key. Every sighash Impulse computes is SIG_HASH_ALL, so
/// any other type byte is refused before the signature is checked. Refusals are `TX_SIGNATURE`.
pub fn verify_schnorr_sig65(
    pubkey_xonly: &[u8; 32],
    sighash: &[u8; 32],
    sig65: &[u8],
) -> Result<(), TxError> {
    let refuse = |reason: String| TxError::Signature {
        input: None,
        reason,
    };
    if sig65.len() != 65 {
        return Err(refuse(format!(
            "a signature is 65 bytes, got {}",
            sig65.len()
        )));
    }
    if sig65[64] != SIG_HASH_ALL.to_u8() {
        return Err(refuse(format!(
            "the sighash type byte must be SIG_HASH_ALL (0x{:02x}), got 0x{:02x}",
            SIG_HASH_ALL.to_u8(),
            sig65[64]
        )));
    }
    let sig = schnorr::Signature::from_slice(&sig65[..64])
        .map_err(|e| refuse(format!("malformed signature: {e}")))?;
    let pubkey = XOnlyPublicKey::from_slice(pubkey_xonly)
        .map_err(|e| refuse(format!("malformed public key: {e}")))?;
    sig.verify(&Message::from_digest(*sighash), &pubkey)
        .map_err(|e| refuse(format!("signature does not verify: {e}")))
}

/// The data of the last push of a push-only script: the redeem script a P2SH signature script
/// ends with. None if the script does not parse or does not end with a push.
pub(crate) fn last_push(script: &[u8]) -> Option<Vec<u8>> {
    let ops =
        kaspa_txscript::parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
    let last = ops.last()?;
    last.is_push_opcode().then(|| last.get_data().to_vec())
}

/// One data push, as the engine reads it (covenant-era limits, as silverscript-abi builds).
pub(crate) fn push_data(data: &[u8]) -> Result<Vec<u8>, TxError> {
    let mut builder = ScriptBuilder::with_flags(EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    });
    builder.add_data(data).map_err(|e| TxError::Encoding {
        reason: format!("push of {} bytes: {e}", data.len()),
    })?;
    Ok(builder.drain())
}

/// Version-0 Schnorr P2PK: OpData32 <x-only key> OpCheckSig.
pub(crate) fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    let mut script = Vec::with_capacity(34);
    script.push(OpData32);
    script.extend_from_slice(key);
    script.push(OpCheckSig);
    ScriptPublicKey::from_vec(0, script)
}

/// The key of a version-0 Schnorr P2PK scriptPubKey, if it is one.
pub(crate) fn p2pk_key(spk: &ScriptPublicKey) -> Option<[u8; 32]> {
    let s = spk.script();
    if spk.version() != 0 || s.len() != 34 || s[0] != OpData32 || s[33] != OpCheckSig {
        return None;
    }
    s[1..33].try_into().ok()
}

// I20 (spec/V3-ZK.md section 17): `impulse_core::zk` builds its transactions from the same parts
// as the v1 builders. These re-exports only widen visibility to this crate; no behaviour of a v1
// builder changes.
#[cfg(feature = "zk")]
pub(crate) use build::same_spend;
#[cfg(feature = "zk")]
pub(crate) use build::too_many_inputs;
#[cfg(any(feature = "zk", feature = "zk-hashed"))]
pub(crate) use build::{
    checked_sum, complete, escrow_at, kas_destination, kas_key, kcc20_owner, not_expired,
    own_tokens, p2pk_spend, planned, signed, template_bytes, token_output, token_state, topped_up,
    PlannedInput, Spend,
};
#[cfg(any(feature = "zk", feature = "zk-hashed"))]
pub(crate) use ipst::{hex as ipst_hex, write_json as write_ipst_json, Slot, J as IpstJson};
#[cfg(any(feature = "zk", feature = "zk-hashed"))]
pub(crate) use rules::{check_min, kcc20_delegate_budget, kcc20_leader_budget, vault_budget};
