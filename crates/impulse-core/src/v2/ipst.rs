// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The partially signed transaction of version 2 (spec/V2.md section 6): spec/IPST.md's layout,
//! rendering and reading rules with `"ipst": 2` and the terms v2 bytes in `terms`. It holds no key
//! and no secret. Reading recomputes every sighash and verifies every signature it carries. A v1
//! reader refuses a version 2 document (`IPST_UNSUPPORTED_VERSION`); [`read_ipst`] reads either
//! version and refuses any other (`IPST_V2_VERSION`).

use super::terms::ValidatedTermsV2;
use super::tx::{check_masses, masses_of, rebuild, TermsMatchV2};
use super::V2Error;
use crate::tx::ipst::{
    at_input, body_values, check_values, hex, malformed, read_input, read_output, same_slots,
    slot_shape, write_json, Fields, Parser, Slot, Value, J,
};
use crate::tx::kcc20::Kcc20Template;
use crate::tx::rules::{min_relay_fee, Masses};
use crate::tx::{sighash, verify_schnorr_sig65, Ipst, TxError, IPST_VERSION};
use kaspa_consensus_core::constants::TX_VERSION_TOCCATA;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};

/// The IPST format version of v2 trades.
pub const IPST_V2_VERSION: u16 = 2;

/// A partially signed transaction of a v2 trade. Built by the v2 builders or read with
/// [`read_ipst`]; signed slot by slot; combined; finalized into the signed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpstV2 {
    terms: ValidatedTermsV2,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    slots: Vec<Slot>,
}

/// An IPST of either version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyIpst {
    V1(Box<Ipst>),
    V2(Box<IpstV2>),
}

/// Reads an IPST of version 1 (with the v1 reader, unchanged) or 2; any other `ipst` value is
/// `IPST_V2_VERSION`. A text without an integer `ipst` key is `IPST_MALFORMED`.
pub fn read_ipst(text: &str) -> Result<AnyIpst, V2Error> {
    let doc = Parser::parse(text).map_err(malformed)?;
    let top = doc.object().map_err(malformed)?;
    let version = match top.iter().find(|(k, _)| k == "ipst") {
        Some((_, Value::Int(v))) => *v,
        _ => return Err(malformed("no integer ipst key".into()).into()),
    };
    if version == i128::from(IPST_VERSION) {
        return Ok(AnyIpst::V1(Box::new(Ipst::from_json(text)?)));
    }
    if version != i128::from(IPST_V2_VERSION) {
        return Err(V2Error::IpstVersion {
            version: i64::try_from(version).unwrap_or(i64::MAX),
        });
    }
    Ok(AnyIpst::V2(Box::new(read_v2(top)?)))
}

/// spec/IPST.md "Reading an IPST", for version 2: form, terms, slot consistency, then every
/// sighash recomputed and every signature verified.
fn read_v2(top: &[(String, Value)]) -> Result<IpstV2, V2Error> {
    let top = Fields::new(top, &["ipst", "terms", "lock_time", "inputs", "outputs"])
        .map_err(malformed)?;
    let terms_bytes = top.hex("terms").map_err(malformed)?;
    let lock_time = top.u64("lock_time").map_err(malformed)?;
    let raw_inputs = top.array("inputs").map_err(malformed)?;
    let raw_outputs = top.array("outputs").map_err(malformed)?;
    if raw_inputs.is_empty() || raw_outputs.is_empty() {
        return Err(malformed("inputs and outputs must not be empty".into()).into());
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
        outputs.push(
            read_output(raw, raw_inputs.len())
                .map_err(|e| malformed(format!("output {n}: {e}")))?,
        );
    }
    check_values(&entries, &outputs).map_err(malformed)?;
    let terms = ValidatedTermsV2::decode(&terms_bytes)?;
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
                return Err(TxError::IpstSighashMismatch { input }.into());
            }
        }
    }
    for (input, slot) in slots.iter().enumerate() {
        if let (Some(signer), Some(hash), Some(sig)) = (slot.signer, slot.sighash, slot.signature) {
            verify_schnorr_sig65(&signer, &hash, &sig).map_err(|e| at_input(e, input))?;
        }
    }
    Ok(IpstV2 {
        terms,
        tx,
        entries,
        slots,
    })
}

impl IpstV2 {
    pub(crate) fn from_parts(
        terms: ValidatedTermsV2,
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

    pub fn terms(&self) -> &ValidatedTermsV2 {
        &self.terms
    }

    /// The unsigned transaction (empty signature scripts).
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    pub fn entries(&self) -> &[UtxoEntry] {
        &self.entries
    }

    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The masses of the signed transaction (every signature is 65 bytes).
    pub fn masses(&self) -> Masses {
        let mut sized = self.tx.clone();
        for (input, slot) in sized.inputs.iter_mut().zip(&self.slots) {
            input.signature_script = slot.script_with(&[0; 65]);
        }
        masses_of(&sized, &self.entries, self.terms.terms().network)
    }

    /// Whether any mass dimension is above the pre-Toccata 100,000 standardness cap: a node or
    /// wallet still applying it does not relay the transaction (spec/V2.md 6.2). A warning for
    /// the CLI and verify, never a refusal.
    pub fn above_pre_toccata_cap(&self) -> bool {
        let m = self.masses();
        [m.compute, m.transient, m.storage]
            .iter()
            .any(|x| *x > super::PRE_TOCCATA_MASS_CAP)
    }

    /// What the inputs hold less what the outputs pay.
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

    /// Verifies a 65-byte signature against the slot's signer and sighash and stores it.
    pub fn add_signature(&mut self, input: usize, sig65: &[u8]) -> Result<(), V2Error> {
        let slot = self.slots.get_mut(input).ok_or(TxError::SignatureSlot {
            input,
            reason: "no such input",
        })?;
        let (Some(signer), Some(sighash)) = (slot.signer, slot.sighash) else {
            return Err(TxError::SignatureSlot {
                input,
                reason: "this input takes no signature",
            }
            .into());
        };
        verify_schnorr_sig65(&signer, &sighash, sig65).map_err(|e| at_input(e, input))?;
        slot.signature = Some(sig65.try_into().expect("verified as 65 bytes"));
        Ok(())
    }

    /// Combines two documents of the same transaction, as spec/IPST.md "Combine".
    pub fn combine(&self, other: &IpstV2) -> Result<IpstV2, V2Error> {
        let conflict = |reason| Err(TxError::IpstConflict { reason }.into());
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
                        }
                        .into());
                    };
                    verify_schnorr_sig65(&signer, &hash, &b).map_err(|e| at_input(e, input))?;
                    mine.signature = Some(b);
                }
                _ => {}
            }
        }
        Ok(combined)
    }

    /// The signed transaction: every slot with a signer holds a signature
    /// (`TX_SIGNATURE_SLOT`); then the masses against CAP_V2 (`TX_V2_MASS`) and the relay fee
    /// (`TX_FEE_TOO_LOW`) are checked again on the result.
    pub fn finalize(&self) -> Result<Transaction, V2Error> {
        let mut tx = self.tx.clone();
        for (input, (slot, tx_input)) in self.slots.iter().zip(tx.inputs.iter_mut()).enumerate() {
            let sig = match (slot.signer, slot.signature) {
                (Some(_), Some(sig)) => sig,
                (Some(_), None) => {
                    return Err(TxError::SignatureSlot {
                        input,
                        reason: "the signature is missing",
                    }
                    .into())
                }
                (None, _) => [0; 65],
            };
            tx_input.signature_script = slot.script_with(&sig);
        }
        tx.finalize();
        let masses = self.masses();
        check_masses(&masses, self.terms.terms().network)?;
        let (fee, minimum) = (self.fee(), min_relay_fee(masses.fee_mass));
        if fee < minimum {
            return Err(TxError::FeeTooLow { fee, minimum }.into());
        }
        Ok(tx)
    }

    /// Verifies and adds each `(input, signature)`, then [`IpstV2::finalize`].
    pub fn assemble(&self, signatures: &[(usize, &[u8])]) -> Result<Transaction, V2Error> {
        let mut ipst = self.clone();
        for (input, sig) in signatures {
            ipst.add_signature(*input, sig)?;
        }
        ipst.finalize()
    }

    /// The terms check: whether this is the transaction the v2 builders make for its terms
    /// from its own inputs, compared byte for byte except the signatures (spec/IPST.md, "Terms
    /// check"). `templates[j]` is the token template of KCC-20 leg j. A builder's refusal keeps
    /// its code; any other difference is `IPST_TERMS_MISMATCH`.
    pub fn verify_against_terms(
        &self,
        templates: &[&Kcc20Template],
        current_daa: u64,
    ) -> Result<TermsMatchV2, V2Error> {
        let (kind, trade_outputs, rebuilt) = rebuild(self, templates, current_daa)?;
        if rebuilt.tx != self.tx
            || rebuilt.entries != self.entries
            || !same_slots(&rebuilt.slots, &self.slots)
        {
            return Err(TxError::IpstTermsMismatch {
                reason: "the document is not the transaction the builders make from its inputs",
            }
            .into());
        }
        Ok(TermsMatchV2 {
            kind,
            fee: self.fee(),
            change: self.tx.outputs.get(trade_outputs).cloned(),
        })
    }

    /// The canonical JSON rendering (spec/IPST.md, "Canonical rendering", with `"ipst": 2`).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        write_json(&self.to_value(), 0, &mut out);
        out.push('\n');
        out
    }

    pub(crate) fn to_value(&self) -> J {
        let (inputs, outputs) = body_values(&self.tx, &self.entries, &self.slots);
        J::Obj(vec![
            ("ipst", J::Int(IPST_V2_VERSION.into())),
            ("terms", J::Str(hex(self.terms.canonical()))),
            ("lock_time", J::Str(self.tx.lock_time.to_string())),
            ("inputs", J::Arr(inputs)),
            ("outputs", J::Arr(outputs)),
        ])
    }
}
