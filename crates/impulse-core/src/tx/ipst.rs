// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The Impulse partially signed transaction (spec/IPST.md): the trade's terms, the unsigned
//! transaction, the UTXOs it spends and one signature slot per input. It holds no key and no
//! secret. Reading an IPST recomputes every sighash and verifies every signature it carries, so
//! nothing stated in a document is trusted.

use super::build::{rebuild, TermsMatch};
use super::kcc20::Kcc20Template;
use super::rules::{check_masses, compute_masses, min_relay_fee, Masses};
use super::{sighash, verify_schnorr_sig65, TxError};
use crate::terms::ValidatedTerms;
use kaspa_consensus_core::constants::{MAX_SOMPI, TX_VERSION_TOCCATA};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::OpData65;

/// The IPST format version this crate reads and writes.
pub const IPST_VERSION: u16 = 1;

/// One input's signature slot: who signs (if anyone), the sighash they sign, the signature once
/// given, and the signature-script bytes around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub(crate) signer: Option<[u8; 32]>,
    pub(crate) sighash: Option<[u8; 32]>,
    pub(crate) signature: Option<[u8; 65]>,
    pub(crate) before: Vec<u8>,
    pub(crate) after: Vec<u8>,
}

impl Slot {
    /// The x-only key whose signature fills this slot; None when the input needs none.
    pub fn signer(&self) -> Option<[u8; 32]> {
        self.signer
    }

    /// The SIG_HASH_ALL sighash the signer signs; present exactly when there is a signer.
    pub fn sighash(&self) -> Option<[u8; 32]> {
        self.sighash
    }

    /// The signature, once given and verified.
    pub fn signature(&self) -> Option<[u8; 65]> {
        self.signature
    }

    /// Signature-script bytes before the signature push (the whole script without a signer).
    pub fn script_before(&self) -> &[u8] {
        &self.before
    }

    /// Signature-script bytes after the signature push.
    pub fn script_after(&self) -> &[u8] {
        &self.after
    }

    /// The signature script with `sig` in the slot: `before || OpData65 || sig || after`, or
    /// `before` alone without a signer.
    pub(crate) fn script_with(&self, sig: &[u8; 65]) -> Vec<u8> {
        if self.signer.is_none() {
            return self.before.clone();
        }
        let mut script = Vec::with_capacity(self.before.len() + 66 + self.after.len());
        script.extend_from_slice(&self.before);
        script.push(OpData65);
        script.extend_from_slice(sig);
        script.extend_from_slice(&self.after);
        script
    }
}

/// An Impulse partially signed transaction. Built by the `tx` builders or read from JSON; signed
/// slot by slot with [`Ipst::add_signature`]; combined with [`Ipst::combine`]; turned into the
/// signed transaction with [`Ipst::finalize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipst {
    terms: ValidatedTerms,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    slots: Vec<Slot>,
}

impl Ipst {
    /// From a builder: the transaction is unsigned and every slot's sighash is computed.
    pub(crate) fn from_parts(
        terms: ValidatedTerms,
        tx: Transaction,
        entries: Vec<UtxoEntry>,
        slots: Vec<Slot>,
    ) -> Self {
        Self {
            terms,
            tx,
            entries,
            slots,
        }
    }

    pub fn terms(&self) -> &ValidatedTerms {
        &self.terms
    }

    /// The unsigned transaction (empty signature scripts).
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// The UTXO each input spends, in input order.
    pub fn entries(&self) -> &[UtxoEntry] {
        &self.entries
    }

    /// The signature slots, in input order.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The masses of the signed transaction (every signature is 65 bytes, so the size is known
    /// before signing), with the pinned calculator and the terms' network parameters.
    pub fn masses(&self) -> Masses {
        let mut sized = self.tx.clone();
        for (input, slot) in sized.inputs.iter_mut().zip(&self.slots) {
            input.signature_script = slot.script_with(&[0; 65]);
        }
        compute_masses(&sized, &self.entries, self.terms.terms().network)
    }

    /// The fee: what the inputs hold less what the outputs pay. The builders and the reader
    /// admit only inputs of at most `MAX_SOMPI` together and outputs paying no more than that,
    /// so neither sum overflows and the difference is never negative; the arithmetic is checked
    /// all the same.
    pub fn fee(&self) -> u64 {
        let held = self
            .entries
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(e.amount));
        let paid = self
            .tx
            .outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.value));
        match (held, paid) {
            (Some(held), Some(paid)) => held.saturating_sub(paid),
            _ => 0,
        }
    }

    /// Inputs whose slot needs a signature and has none yet.
    pub fn pending(&self) -> Vec<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.signer.is_some() && s.signature.is_none())
            .map(|(i, _)| i)
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.pending().is_empty()
    }

    /// Verifies a 65-byte signature against the slot's signer and sighash and stores it
    /// (`TX_SIGNATURE`). A slot that does not exist or takes no signature is `TX_SIGNATURE_SLOT`.
    pub fn add_signature(&mut self, input: usize, sig65: &[u8]) -> Result<(), TxError> {
        let slot = self.slots.get_mut(input).ok_or(TxError::SignatureSlot {
            input,
            reason: "no such input",
        })?;
        let (Some(signer), Some(sighash)) = (slot.signer, slot.sighash) else {
            return Err(TxError::SignatureSlot {
                input,
                reason: "this input takes no signature",
            });
        };
        verify_schnorr_sig65(&signer, &sighash, sig65).map_err(|e| at_input(e, input))?;
        slot.signature = Some(sig65.try_into().expect("verified as 65 bytes"));
        Ok(())
    }

    /// Combines two IPSTs of the same transaction, taking every signature either holds
    /// (spec/IPST.md, "Combine"). `IPST_CONFLICT` if the terms differ, the transactions or the
    /// UTXO entries differ, a slot differs in anything but its signature, or one slot holds two
    /// different signatures. Every signature copied from `other` is verified against this
    /// document's slot first (`TX_SIGNATURE`), so a combined document never holds a signature
    /// its own slot does not accept.
    pub fn combine(&self, other: &Ipst) -> Result<Ipst, TxError> {
        let conflict = |reason| Err(TxError::IpstConflict { reason });
        if self.terms != other.terms {
            return conflict("the IPSTs carry different terms");
        }
        if self.tx != other.tx || self.entries != other.entries {
            return conflict("the IPSTs describe different transactions");
        }
        if !same_slots(&self.slots, &other.slots) {
            return conflict("the IPSTs have different signature slots");
        }
        let mut combined = self.clone();
        for (input, (mine, theirs)) in combined.slots.iter_mut().zip(&other.slots).enumerate() {
            match (mine.signature, theirs.signature) {
                (Some(a), Some(b)) if a != b => {
                    return conflict("one slot holds two different signatures");
                }
                (None, Some(b)) => {
                    let (Some(signer), Some(hash)) = (mine.signer, mine.sighash) else {
                        return Err(TxError::SignatureSlot {
                            input,
                            reason: "this input takes no signature",
                        });
                    };
                    verify_schnorr_sig65(&signer, &hash, &b).map_err(|e| at_input(e, input))?;
                    mine.signature = Some(b);
                }
                _ => {}
            }
        }
        Ok(combined)
    }

    /// The signed transaction: every slot with a signer must hold a signature
    /// (`TX_SIGNATURE_SLOT`); each signature script is assembled around it. Then the masses
    /// (`TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`) are checked again on the result: no
    /// signature covers an input's compute budget, so a document whose budgets were raised
    /// after signing reads and verifies, and only these checks see the change (spec/IPST.md,
    /// "Trust model"). A lowered budget, or a changed one that stays within both, is not
    /// visible here; [`Ipst::verify_against_terms`] compares every budget.
    pub fn finalize(&self) -> Result<Transaction, TxError> {
        let mut tx = self.tx.clone();
        for (input, (slot, tx_input)) in self.slots.iter().zip(tx.inputs.iter_mut()).enumerate() {
            let sig = match (slot.signer, slot.signature) {
                (Some(_), Some(sig)) => sig,
                (Some(_), None) => {
                    return Err(TxError::SignatureSlot {
                        input,
                        reason: "the signature is missing",
                    })
                }
                (None, _) => [0; 65],
            };
            tx_input.signature_script = slot.script_with(&sig);
        }
        tx.finalize();
        // The assembled scripts have the size `masses` assumes (every signature is 65 bytes).
        let masses = self.masses();
        check_masses(&masses)?;
        let (fee, minimum) = (self.fee(), min_relay_fee(masses.fee_mass));
        if fee < minimum {
            return Err(TxError::FeeTooLow { fee, minimum });
        }
        Ok(tx)
    }

    /// Assembles the signed transaction from signature bytes, one `(input, signature)` pair per
    /// slot to fill: each is verified as [`Ipst::add_signature`] does, then [`Ipst::finalize`].
    pub fn assemble(&self, signatures: &[(usize, &[u8])]) -> Result<Transaction, TxError> {
        let mut ipst = self.clone();
        for (input, sig) in signatures {
            ipst.add_signature(*input, sig)?;
        }
        ipst.finalize()
    }

    /// The terms check (spec/IPST.md, "Terms check"): whether this is the transaction the
    /// builders make for its terms from its own inputs. Rebuilds it with the builders (the trade
    /// UTXOs where the layout puts them, token states from the redeem scripts the token inputs
    /// carry, the fee inputs after them, this document's fee and change destination) and
    /// compares everything but the signatures byte for byte: every output and its value, the
    /// lock time, every input's outpoint, sequence and compute budget, the UTXO entries, and
    /// every slot's signer, sighash and script parts. A signer runs it before signing, and a
    /// submitter before broadcast.
    ///
    /// `asset` and `cash` are the legs' KCC-20 templates (`cash` for KCC-20 cash only), and
    /// `current_daa` the caller's current DAA score, as the fund, settle and Direct builders take
    /// it. A builder's refusal of these inputs keeps its code (for example `TX_EXPIRED`,
    /// `TX_LEG_AMOUNT`, `TX_TOKEN_TEMPLATE`); any other difference, or inputs no builder lays
    /// out this way for these terms, is `IPST_TERMS_MISMATCH`.
    pub fn verify_against_terms(
        &self,
        asset: &Kcc20Template,
        cash: Option<&Kcc20Template>,
        current_daa: u64,
    ) -> Result<TermsMatch, TxError> {
        let (kind, trade_outputs, rebuilt) = rebuild(self, asset, cash, current_daa)?;
        if rebuilt.tx != self.tx
            || rebuilt.entries != self.entries
            || !same_slots(&rebuilt.slots, &self.slots)
        {
            return Err(TxError::IpstTermsMismatch {
                reason: "the document is not the transaction the builders make from its inputs",
            });
        }
        Ok(TermsMatch {
            kind,
            fee: self.fee(),
            change: self.tx.outputs.get(trade_outputs).cloned(),
        })
    }

    /// The canonical JSON rendering (spec/IPST.md, "Canonical rendering").
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        write_json(&self.to_value(), 0, &mut out);
        out.push('\n');
        out
    }

    pub(crate) fn to_value(&self) -> J {
        let (inputs, outputs) = body_values(&self.tx, &self.entries, &self.slots);
        J::Obj(vec![
            ("ipst", J::Int(IPST_VERSION.into())),
            ("terms", J::Str(hex(self.terms.canonical()))),
            ("lock_time", J::Str(self.tx.lock_time.to_string())),
            ("inputs", J::Arr(inputs)),
            ("outputs", J::Arr(outputs)),
        ])
    }

    /// Reads an IPST (spec/IPST.md, "Reading an IPST"): form, version, terms, slot consistency,
    /// then every sighash recomputed and every signature verified.
    pub fn from_json(text: &str) -> Result<Ipst, TxError> {
        let doc = Parser::parse(text).map_err(malformed)?;
        let top = doc.object().map_err(malformed)?;
        let version = match top.iter().find(|(k, _)| k == "ipst") {
            Some((_, Value::Int(v))) => *v,
            _ => return Err(malformed("no integer ipst key".into())),
        };
        if version != i128::from(IPST_VERSION) {
            return Err(TxError::IpstUnsupportedVersion {
                version: i64::try_from(version).unwrap_or(i64::MAX),
            });
        }
        let top = Fields::new(top, &["ipst", "terms", "lock_time", "inputs", "outputs"])
            .map_err(malformed)?;
        let terms_bytes = top.hex("terms").map_err(malformed)?;
        let lock_time = top.u64("lock_time").map_err(malformed)?;
        let raw_inputs = top.array("inputs").map_err(malformed)?;
        let raw_outputs = top.array("outputs").map_err(malformed)?;
        if raw_inputs.is_empty() || raw_outputs.is_empty() {
            return Err(malformed("inputs and outputs must not be empty".into()));
        }
        let mut tx_inputs = Vec::with_capacity(raw_inputs.len());
        let mut entries = Vec::with_capacity(raw_inputs.len());
        let mut slots = Vec::with_capacity(raw_inputs.len());
        for (n, raw) in raw_inputs.iter().enumerate() {
            let (input, entry, slot) =
                read_input(raw).map_err(|e| malformed(format!("input {n}: {e}")))?;
            tx_inputs.push(input);
            entries.push(entry);
            slots.push(slot);
        }
        let mut outputs = Vec::with_capacity(raw_outputs.len());
        for (n, raw) in raw_outputs.iter().enumerate() {
            let output = read_output(raw, raw_inputs.len())
                .map_err(|e| malformed(format!("output {n}: {e}")))?;
            outputs.push(output);
        }
        check_values(&entries, &outputs).map_err(malformed)?;
        let terms = ValidatedTerms::decode(&terms_bytes)?;
        for (n, slot) in slots.iter().enumerate() {
            slot_shape(slot).map_err(|e| malformed(format!("input {n}: {e}")))?;
        }
        let tx = Transaction::new(
            TX_VERSION_TOCCATA,
            tx_inputs,
            outputs,
            lock_time,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        for (input, slot) in slots.iter().enumerate() {
            if let Some(stated) = slot.sighash {
                if sighash(&tx, &entries, input)? != stated {
                    return Err(TxError::IpstSighashMismatch { input });
                }
            }
        }
        for (input, slot) in slots.iter().enumerate() {
            if let (Some(signer), Some(hash), Some(sig)) =
                (slot.signer, slot.sighash, slot.signature)
            {
                verify_schnorr_sig65(&signer, &hash, &sig).map_err(|e| at_input(e, input))?;
            }
        }
        Ok(Ipst {
            terms,
            tx,
            entries,
            slots,
        })
    }
}

/// The `inputs` and `outputs` arrays of the canonical rendering (spec/IPST.md), shared by the
/// version 1 and version 2 documents.
pub(crate) fn body_values(
    tx: &Transaction,
    entries: &[UtxoEntry],
    slots: &[Slot],
) -> (Vec<J>, Vec<J>) {
    let inputs = tx
        .inputs
        .iter()
        .zip(entries)
        .zip(slots)
        .map(|((input, entry), slot)| {
            J::Obj(vec![
                (
                    "transaction_id",
                    J::Str(hex(&input.previous_outpoint.transaction_id.as_bytes())),
                ),
                ("index", J::Int(input.previous_outpoint.index.into())),
                ("sequence", J::Str(input.sequence.to_string())),
                (
                    "compute_budget",
                    J::Int(input.compute_commit.compute_budget().unwrap_or(0).into()),
                ),
                (
                    "utxo",
                    J::Obj(vec![
                        ("amount", J::Str(entry.amount.to_string())),
                        ("script_public_key", spk_value(&entry.script_public_key)),
                        ("block_daa_score", J::Str(entry.block_daa_score.to_string())),
                        ("is_coinbase", J::Bool(entry.is_coinbase)),
                        (
                            "covenant_id",
                            entry
                                .covenant_id
                                .map_or(J::Null, |c| J::Str(hex(&c.as_bytes()))),
                        ),
                    ]),
                ),
                ("signer", slot.signer.map_or(J::Null, |k| J::Str(hex(&k)))),
                ("sighash", slot.sighash.map_or(J::Null, |h| J::Str(hex(&h)))),
                (
                    "signature",
                    slot.signature.map_or(J::Null, |s| J::Str(hex(&s))),
                ),
                ("script_before", J::Str(hex(&slot.before))),
                ("script_after", J::Str(hex(&slot.after))),
            ])
        })
        .collect();
    let outputs = tx
        .outputs
        .iter()
        .map(|o| {
            J::Obj(vec![
                ("value", J::Str(o.value.to_string())),
                ("script_public_key", spk_value(&o.script_public_key)),
                (
                    "covenant",
                    o.covenant.map_or(J::Null, |c| {
                        J::Obj(vec![
                            ("authorizing_input", J::Int(c.authorizing_input.into())),
                            ("covenant_id", J::Str(hex(&c.covenant_id.as_bytes()))),
                        ])
                    }),
                ),
            ])
        })
        .collect();
    (inputs, outputs)
}

/// The same slots, signatures aside: signer, sighash and the script parts, one for one.
pub(crate) fn same_slots(a: &[Slot], b: &[Slot]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.signer == b.signer
                && a.sighash == b.sighash
                && a.before == b.before
                && a.after == b.after
        })
}

pub(crate) fn malformed(reason: String) -> TxError {
    TxError::IpstMalformed { reason }
}

pub(crate) fn at_input(e: TxError, input: usize) -> TxError {
    match e {
        TxError::Signature { reason, .. } => TxError::Signature {
            input: Some(input),
            reason,
        },
        other => other,
    }
}

/// Step 3 of reading, for values: every UTXO amount and output value is above zero and at most
/// `MAX_SOMPI`, the UTXO amounts add up to at most `MAX_SOMPI`, and the outputs pay no more than
/// the inputs hold. The consensus rules refuse anything else, and the pinned mass calculator
/// divides by every value.
pub(crate) fn check_values(
    entries: &[UtxoEntry],
    outputs: &[TransactionOutput],
) -> Result<(), String> {
    let in_range = |v: u64| v > 0 && v <= MAX_SOMPI;
    // Each running total stays at most MAX_SOMPI, so neither addition overflows.
    let mut held: u64 = 0;
    for (n, entry) in entries.iter().enumerate() {
        if !in_range(entry.amount) {
            return Err(format!("input {n}: amount outside 1 to MAX_SOMPI"));
        }
        held += entry.amount;
        if held > MAX_SOMPI {
            return Err("the UTXO amounts add up past MAX_SOMPI".into());
        }
    }
    let mut paid: u64 = 0;
    for (n, output) in outputs.iter().enumerate() {
        if !in_range(output.value) {
            return Err(format!("output {n}: value outside 1 to MAX_SOMPI"));
        }
        paid += output.value;
        if paid > held {
            return Err("the outputs pay more than the inputs hold".into());
        }
    }
    Ok(())
}

/// Step 5 of reading: the three slot fields agree, and a signer is a valid x-only key.
pub(crate) fn slot_shape(slot: &Slot) -> Result<(), String> {
    match (slot.signer, slot.sighash) {
        (None, None) => {
            if slot.signature.is_some() {
                return Err("a signature without a signer".into());
            }
            if !slot.after.is_empty() {
                return Err("script_after is not empty without a signer".into());
            }
        }
        (Some(signer), Some(_)) => {
            if secp256k1::XOnlyPublicKey::from_slice(&signer).is_err() {
                return Err("the signer is not a valid x-only key".into());
            }
        }
        _ => return Err("signer and sighash must be present together".into()),
    }
    Ok(())
}

pub(crate) fn read_input(raw: &Value) -> Result<(TransactionInput, UtxoEntry, Slot), String> {
    let f = Fields::new(
        raw.object()?,
        &[
            "transaction_id",
            "index",
            "sequence",
            "compute_budget",
            "utxo",
            "signer",
            "sighash",
            "signature",
            "script_before",
            "script_after",
        ],
    )?;
    let outpoint = TransactionOutpoint::new(
        Hash::from_bytes(f.hex_n::<32>("transaction_id")?),
        f.int::<u32>("index")?,
    );
    let input = TransactionInput::new_with_compute_budget(
        outpoint,
        vec![],
        f.u64("sequence")?,
        f.int::<u16>("compute_budget")?,
    );
    let u = Fields::new(
        f.get("utxo").object()?,
        &[
            "amount",
            "script_public_key",
            "block_daa_score",
            "is_coinbase",
            "covenant_id",
        ],
    )?;
    let entry = UtxoEntry::new(
        u.u64("amount")?,
        read_spk(u.get("script_public_key"))?,
        u.u64("block_daa_score")?,
        u.bool("is_coinbase")?,
        u.opt(|v| hex_n::<32>(v).map(Hash::from_bytes), "covenant_id")?,
    );
    let slot = Slot {
        signer: f.opt(hex_n::<32>, "signer")?,
        sighash: f.opt(hex_n::<32>, "sighash")?,
        signature: f.opt(hex_n::<65>, "signature")?,
        before: f.hex("script_before")?,
        after: f.hex("script_after")?,
    };
    Ok((input, entry, slot))
}

pub(crate) fn read_output(raw: &Value, inputs: usize) -> Result<TransactionOutput, String> {
    let f = Fields::new(raw.object()?, &["value", "script_public_key", "covenant"])?;
    let covenant = f.opt(
        |v| {
            let c = Fields::new(v.object()?, &["authorizing_input", "covenant_id"])?;
            let authorizing_input = c.int::<u16>("authorizing_input")?;
            if usize::from(authorizing_input) >= inputs {
                return Err("authorizing_input names no input".to_string());
            }
            Ok(CovenantBinding::new(
                authorizing_input,
                Hash::from_bytes(c.hex_n::<32>("covenant_id")?),
            ))
        },
        "covenant",
    )?;
    Ok(TransactionOutput {
        value: f.u64("value")?,
        script_public_key: read_spk(f.get("script_public_key"))?,
        covenant,
    })
}

fn read_spk(raw: &Value) -> Result<ScriptPublicKey, String> {
    let f = Fields::new(raw.object()?, &["version", "script"])?;
    Ok(ScriptPublicKey::from_vec(
        f.int::<u16>("version")?,
        f.hex("script")?,
    ))
}

pub(crate) fn spk_value(spk: &ScriptPublicKey) -> J {
    J::Obj(vec![
        ("version", J::Int(spk.version().into())),
        ("script", J::Str(hex(spk.script()))),
    ])
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// =============================================================================================
// JSON: the canonical writer, and a strict reader for the IPST subset of JSON
// =============================================================================================

/// A value to render. Keys are static: the IPST layout fixes them.
pub(crate) enum J {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

pub(crate) fn write_json(j: &J, indent: usize, out: &mut String) {
    let pad = |n: usize, out: &mut String| out.push_str(&" ".repeat(n));
    match j {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(n) => out.push_str(&n.to_string()),
        J::Str(s) => {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\'),
                "rendered strings need no escaping"
            );
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        J::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                pad(indent + 2, out);
                write_json(item, indent + 2, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push(']');
        }
        J::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                pad(indent + 2, out);
                out.push('"');
                out.push_str(key);
                out.push_str("\": ");
                write_json(value, indent + 2, out);
                if i + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push('}');
        }
    }
}

/// A parsed JSON value. Integers keep their sign and magnitude; fractions and exponents are
/// refused by the reader, since no IPST value has one.
#[derive(Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub(crate) fn object(&self) -> Result<&[(String, Value)], String> {
        match self {
            Value::Obj(fields) => Ok(fields),
            _ => Err("expected an object".into()),
        }
    }
}

/// The members of one object, checked to be exactly `keys`.
pub(crate) struct Fields<'a> {
    fields: &'a [(String, Value)],
}

impl<'a> Fields<'a> {
    pub(crate) fn new(fields: &'a [(String, Value)], keys: &[&str]) -> Result<Self, String> {
        for (k, _) in fields {
            if !keys.contains(&k.as_str()) {
                return Err(format!("unknown key {k}"));
            }
        }
        for k in keys {
            if !fields.iter().any(|(f, _)| f == k) {
                return Err(format!("missing key {k}"));
            }
        }
        Ok(Self { fields })
    }

    fn get(&self, key: &str) -> &'a Value {
        &self
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .expect("checked in new")
            .1
    }

    fn str(&self, key: &str) -> Result<&'a str, String> {
        match self.get(key) {
            Value::Str(s) => Ok(s),
            _ => Err(format!("{key}: expected a string")),
        }
    }

    pub(crate) fn hex(&self, key: &str) -> Result<Vec<u8>, String> {
        unhex(self.str(key)?).map_err(|e| format!("{key}: {e}"))
    }

    fn hex_n<const N: usize>(&self, key: &str) -> Result<[u8; N], String> {
        hex_n::<N>(self.get(key)).map_err(|e| format!("{key}: {e}"))
    }

    pub(crate) fn u64(&self, key: &str) -> Result<u64, String> {
        decimal(self.str(key)?).map_err(|e| format!("{key}: {e}"))
    }

    fn int<T: TryFrom<i128>>(&self, key: &str) -> Result<T, String> {
        match self.get(key) {
            Value::Int(n) => T::try_from(*n).map_err(|_| format!("{key}: out of range")),
            _ => Err(format!("{key}: expected an integer")),
        }
    }

    fn bool(&self, key: &str) -> Result<bool, String> {
        match self.get(key) {
            Value::Bool(b) => Ok(*b),
            _ => Err(format!("{key}: expected true or false")),
        }
    }

    pub(crate) fn array(&self, key: &str) -> Result<&'a [Value], String> {
        match self.get(key) {
            Value::Arr(items) => Ok(items),
            _ => Err(format!("{key}: expected an array")),
        }
    }

    fn opt<T>(
        &self,
        read: impl Fn(&'a Value) -> Result<T, String>,
        key: &str,
    ) -> Result<Option<T>, String> {
        match self.get(key) {
            Value::Null => Ok(None),
            v => read(v).map(Some).map_err(|e| format!("{key}: {e}")),
        }
    }
}

fn hex_n<const N: usize>(v: &Value) -> Result<[u8; N], String> {
    let Value::Str(s) = v else {
        return Err("expected a string".into());
    };
    unhex(s)?
        .try_into()
        .map_err(|_| format!("expected {N} bytes of hex"))
}

/// Lowercase hex of even length, possibly empty.
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("expected lowercase hex of even length".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked hex"))
        .collect())
}

/// A u64 as a decimal string: digits only, no leading zero except "0" itself.
fn decimal(s: &str) -> Result<u64, String> {
    let canonical =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err("expected a decimal string without sign or leading zero".into());
    }
    s.parse::<u64>()
        .map_err(|_| "decimal value above u64".to_string())
}

/// A recursive-descent reader for the JSON an IPST uses: objects, arrays, strings without escape
/// sequences, integers, true, false, null. Duplicate keys, escapes, control characters,
/// fractions and exponents are refused, so every accepted text has one meaning.
pub(crate) struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 16;

impl<'a> Parser<'a> {
    pub(crate) fn parse(text: &'a str) -> Result<Value, String> {
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
            depth: 0,
        };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.s.len() {
            return Err(format!("unexpected text at byte {}", p.i));
        }
        Ok(v)
    }

    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", b as char, self.i))
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("unexpected text at byte {}", self.i))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.nested(Self::obj),
            Some(b'[') => self.nested(Self::arr),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("expected a value at byte {}", self.i)),
        }
    }

    fn nested(&mut self, f: fn(&mut Self) -> Result<Value, String>) -> Result<Value, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nested too deep".into());
        }
        let v = f(self);
        self.depth -= 1;
        v
    }

    fn obj(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut fields: Vec<(String, Value)> = vec![];
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(fields));
        }
        loop {
            self.ws();
            let key = self.string()?;
            if fields.iter().any(|(k, _)| *k == key) {
                return Err(format!("duplicate key {key}"));
            }
            self.ws();
            self.expect(b':')?;
            self.ws();
            let v = self.value()?;
            fields.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
    }

    fn arr(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = vec![];
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let start = self.i;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => return Err("escape sequences are not used in an IPST".into()),
                Some(c) if c < 0x20 => return Err("control character in a string".into()),
                Some(_) => self.i += 1,
                None => return Err("unterminated string".into()),
            }
        }
        let s = std::str::from_utf8(&self.s[start..self.i])
            .map_err(|_| "string is not UTF-8".to_string())?
            .to_string();
        self.i += 1;
        Ok(s)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let int = &self.s[digits..self.i];
        if int.is_empty() || (int.len() > 1 && int[0] == b'0') {
            return Err(format!("malformed number at byte {start}"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(format!("not an integer at byte {start}"));
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).expect("ASCII");
        text.parse::<i128>()
            .map(Value::Int)
            .map_err(|_| format!("integer out of range at byte {start}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_accepts_json_and_refuses_what_an_ipst_never_holds() {
        assert_eq!(
            Parser::parse(" {\"a\" : [1, -2, true, null, \"0f\"] }\n"),
            Ok(Value::Obj(vec![(
                "a".into(),
                Value::Arr(vec![
                    Value::Int(1),
                    Value::Int(-2),
                    Value::Bool(true),
                    Value::Null,
                    Value::Str("0f".into())
                ])
            )]))
        );
        for bad in [
            "{\"a\":1,\"a\":2}",
            "{\"a\":\"\\u0030\"}",
            "{\"a\":1.0}",
            "{\"a\":1e3}",
            "{\"a\":01}",
            "{\"a\":1,}",
            "[1 2]",
            "{} x",
            "",
            "{\"a\":tru}",
            "{\"a\":\"\u{1}\"}",
            &"[".repeat(MAX_DEPTH + 1),
        ] {
            assert!(Parser::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn decimals_and_hex_are_canonical() {
        assert_eq!(decimal("0"), Ok(0));
        assert_eq!(decimal("18446744073709551615"), Ok(u64::MAX));
        for bad in [
            "",
            "00",
            "01",
            "-1",
            "+1",
            "1 ",
            "18446744073709551616",
            "1.0",
        ] {
            assert!(decimal(bad).is_err(), "{bad}");
        }
        assert_eq!(unhex(""), Ok(vec![]));
        assert_eq!(unhex("00ff"), Ok(vec![0, 255]));
        for bad in ["0", "0F", "zz", "0x00"] {
            assert!(unhex(bad).is_err(), "{bad}");
        }
    }
}
