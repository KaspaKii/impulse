// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v4 partially signed transaction (spec/V3-ZK.md 22.8): IPST version 5. It is `IPST.md`'s
//! layout with the canonical terms v4 in `terms`. The proofs are not a separate key: each vault
//! input's 128-byte proof is in its signature script, where the engine reads it, so a document can
//! never disagree with itself about them. A proof of 128 zero bytes is the placeholder of a plan
//! that has no receipt yet; such a document can be signed, merged and read, but `finalize` refuses
//! it (`ZK_H_PROOF_MALFORMED`). A v1 reader refuses version 5 as `IPST_UNSUPPORTED_VERSION`; this
//! reader, given another version, refuses `ZK_H_IPST_VERSION`.
//!
//! The transaction, UTXO entries and signature slots are those of the v1 [`Ipst`], which this type
//! wraps, so reading verifies every sighash and every signature exactly as for version 1. What
//! differs is the terms (v4) and the mass caps: a v4 settle carries two verifications, so
//! `finalize` checks the caps of D63 (spec/V3-ZK.md section 10).
//!
//! Holds no key and no secret.

use super::build::{check_masses, check_statement, rebuild, run_in_engine};
use super::vterms::ValidatedTermsV4;
use super::{parse_spend_script, ZkhError};
use crate::tx::{
    ipst_hex, min_relay_fee, write_ipst_json, Ipst, IpstJson, IpstKind, Kcc20Template, Masses,
    Slot, TermsMatch, TxError,
};
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// The IPST format version of a v4 document.
pub const IPST_VERSION_V4: u16 = 5;

/// Length of a RISC Zero Groth16 proof as the engine reads it.
pub const PROOF_LEN: usize = 128;

/// A 128-byte Groth16 proof, as the vault's `proof` argument carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofV4([u8; PROOF_LEN]);

impl ProofV4 {
    /// Refuses anything but 128 bytes that are not all zero (`ZK_H_PROOF_MALFORMED`). Whether the
    /// bytes verify is the engine's to say (`ZK_H_PROOF_INVALID`, at finalize).
    pub fn parse(bytes: &[u8]) -> Result<Self, ZkhError> {
        let arr: [u8; PROOF_LEN] = bytes.try_into().map_err(|_| {
            ZkhError::new(
                "ZK_H_PROOF_MALFORMED",
                format!("a proof is {PROOF_LEN} bytes, this one is {}", bytes.len()),
            )
        })?;
        if arr.iter().all(|b| *b == 0) {
            return Err(ZkhError::new(
                "ZK_H_PROOF_MALFORMED",
                "the proof is all zero bytes",
            ));
        }
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }
}

/// An IPST for terms v4: the v1 partially signed transaction over the v1 fields of the terms, and
/// the terms v4 themselves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpstV4 {
    ipst: Ipst,
    terms: ValidatedTermsV4,
}

impl IpstV4 {
    pub(crate) fn from_parts(
        terms: ValidatedTermsV4,
        tx: Transaction,
        entries: Vec<UtxoEntry>,
        slots: Vec<Slot>,
    ) -> Self {
        Self {
            ipst: Ipst::from_parts(terms.v1_fields().clone(), tx, entries, slots),
            terms,
        }
    }

    pub fn terms(&self) -> &ValidatedTermsV4 {
        &self.terms
    }

    /// The unsigned transaction (empty signature scripts).
    pub fn transaction(&self) -> &Transaction {
        self.ipst.transaction()
    }

    pub fn entries(&self) -> &[UtxoEntry] {
        self.ipst.entries()
    }

    pub fn slots(&self) -> &[Slot] {
        self.ipst.slots()
    }

    /// The masses of the signed transaction.
    pub fn masses(&self) -> Masses {
        self.ipst.masses()
    }

    pub fn fee(&self) -> u64 {
        self.ipst.fee()
    }

    pub fn pending(&self) -> Vec<usize> {
        self.ipst.pending()
    }

    pub fn is_complete(&self) -> bool {
        self.ipst.is_complete()
    }

    /// The transaction with every signature script assembled around `sig`, where a slot takes a
    /// signature and has none yet.
    pub(crate) fn scripted(&self, placeholder: Option<[u8; 65]>) -> Result<Transaction, ZkhError> {
        let mut tx = self.ipst.transaction().clone();
        for (index, (slot, input)) in self
            .ipst
            .slots()
            .iter()
            .zip(tx.inputs.iter_mut())
            .enumerate()
        {
            let sig = match (slot.signer(), slot.signature(), placeholder) {
                (Some(_), Some(sig), _) => sig,
                (Some(_), None, Some(p)) => p,
                (Some(_), None, None) => {
                    return Err(TxError::SignatureSlot {
                        input: index,
                        reason: "the signature is missing",
                    }
                    .into())
                }
                (None, _, _) => [0; 65],
            };
            input.signature_script = slot.script_with(&sig);
        }
        Ok(tx)
    }

    /// The vault inputs of this document and the proof each carries: `None` while the script holds
    /// the placeholder of 128 zero bytes.
    pub fn proofs(&self) -> Result<Vec<(usize, Option<ProofV4>)>, ZkhError> {
        let tx = self.scripted(Some([0; 65]))?;
        let mut out = Vec::new();
        for (index, input) in tx.inputs.iter().enumerate() {
            if let Some(spend) = parse_spend_script(&input.signature_script)? {
                out.push((index, ProofV4::parse(&spend.proof).ok()));
            }
        }
        Ok(out)
    }

    /// True if every vault input carries a proof.
    pub fn has_all_proofs(&self) -> Result<bool, ZkhError> {
        Ok(self.proofs()?.iter().all(|(_, p)| p.is_some()))
    }

    /// Verifies a 65-byte signature against the slot's signer and sighash and stores it
    /// (`TX_SIGNATURE`, `TX_SIGNATURE_SLOT`).
    pub fn add_signature(&mut self, input: usize, sig65: &[u8]) -> Result<(), ZkhError> {
        Ok(self.ipst.add_signature(input, sig65)?)
    }

    /// Combines two IPSTs of the same transaction (`IPST_CONFLICT` if they differ in anything but
    /// signatures).
    pub fn combine(&self, other: &IpstV4) -> Result<IpstV4, ZkhError> {
        if self.terms != other.terms {
            return Err(TxError::IpstConflict {
                reason: "the IPSTs carry different terms",
            }
            .into());
        }
        Ok(Self {
            ipst: self.ipst.combine(&other.ipst)?,
            terms: self.terms.clone(),
        })
    }

    /// The signed transaction. Every vault input must hold a proof (`ZK_H_PROOF_MALFORMED`) and
    /// every slot with a signer a signature (`TX_SIGNATURE_SLOT`); then the statement of
    /// `terms-core` is run natively on each vault view (`ZK_H_STATEMENT_FALSE`), the masses (`ZK_TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`) are checked, and last every
    /// input is run in the pinned script engine: a vault input the engine refuses is
    /// `ZK_H_PROOF_INVALID` when the precompile refused the proof and carries the engine's reason
    /// otherwise.
    pub fn finalize(&self) -> Result<Transaction, ZkhError> {
        if !self.has_all_proofs()? {
            return Err(ZkhError::new(
                "ZK_H_PROOF_MALFORMED",
                "a vault input still holds the placeholder proof: make the receipt and build again with it",
            ));
        }
        let mut tx = self.scripted(None)?;
        tx.finalize();
        if !self.proofs()?.is_empty() {
            check_statement(self)?;
        }
        let masses = self.masses();
        check_masses(&masses)?;
        let (fee, minimum) = (self.fee(), min_relay_fee(masses.fee_mass));
        if fee < minimum {
            return Err(TxError::FeeTooLow { fee, minimum }.into());
        }
        run_in_engine(&tx, self.entries(), self.terms.fields().network)?;
        Ok(tx)
    }

    /// Assembles the signed transaction from signature bytes, one `(input, signature)` pair per
    /// slot to fill: each is verified as [`IpstV4::add_signature`] does, then finalized.
    pub fn assemble(&self, signatures: &[(usize, &[u8])]) -> Result<Transaction, ZkhError> {
        let mut ipst = self.clone();
        for (input, sig) in signatures {
            ipst.add_signature(*input, sig)?;
        }
        ipst.finalize()
    }

    /// The terms check (spec/IPST.md, "Terms check", for terms v4): whether this is the
    /// transaction the v4 builders make for its terms from its own inputs and proofs. A signer
    /// runs it before signing, and a submitter before broadcast.
    pub fn verify_against_terms(
        &self,
        asset: &Kcc20Template,
        cash: Option<&Kcc20Template>,
        current_daa: u64,
    ) -> Result<TermsMatch, ZkhError> {
        let (kind, trade_outputs, rebuilt): (IpstKind, usize, IpstV4) =
            rebuild(self, asset, cash, current_daa)?;
        if rebuilt.ipst.transaction() != self.ipst.transaction()
            || rebuilt.ipst.entries() != self.ipst.entries()
            || !same_slots(rebuilt.ipst.slots(), self.ipst.slots())
        {
            return Err(TxError::IpstTermsMismatch {
                reason: "the document is not the transaction the builders make from its inputs",
            }
            .into());
        }
        Ok(TermsMatch {
            kind,
            fee: self.fee(),
            change: self.ipst.transaction().outputs.get(trade_outputs).cloned(),
        })
    }

    /// The canonical JSON rendering: `IPST.md`'s with `"ipst": 5` and the terms v4 bytes.
    pub fn to_json(&self) -> String {
        let IpstJson::Obj(fields) = self.ipst.to_value() else {
            unreachable!("an IPST renders as an object")
        };
        let out_fields: Vec<(&'static str, IpstJson)> = fields
            .into_iter()
            .map(|(key, value)| match key {
                "ipst" => (key, IpstJson::Int(IPST_VERSION_V4.into())),
                "terms" => (key, IpstJson::Str(ipst_hex(self.terms.canonical()))),
                _ => (key, value),
            })
            .collect();
        let mut out = String::new();
        write_ipst_json(&IpstJson::Obj(out_fields), 0, &mut out);
        out.push('\n');
        out
    }

    /// The version a document names, without reading the rest (`None` if it is not JSON with an
    /// integer `ipst` key). The CLI routes a document to the reader of its version with this.
    pub fn version_of(text: &str) -> Option<u64> {
        let Ok(Value::Object(top)) = serde_json::from_str::<Value>(text) else {
            return None;
        };
        top.get("ipst")?.as_u64()
    }

    /// Reads a v4 IPST: form, version (`ZK_H_IPST_VERSION`), terms v4, then everything the v1
    /// reader checks: slot consistency, every sighash recomputed and every signature verified.
    pub fn from_json(text: &str) -> Result<IpstV4, ZkhError> {
        let malformed = |reason: String| ZkhError::from(TxError::IpstMalformed { reason });
        let doc = parse_unique(text).map_err(malformed)?;
        let Value::Object(mut top) = doc else {
            return Err(malformed("expected an object".into()));
        };
        match top.get("ipst") {
            Some(Value::Number(n)) if n.as_u64() == Some(IPST_VERSION_V4.into()) => {}
            Some(Value::Number(n)) => {
                return Err(ZkhError::new(
                    "ZK_H_IPST_VERSION",
                    format!("ipst is {n}, a v4 reader reads 5"),
                ))
            }
            _ => return Err(malformed("no integer ipst key".into())),
        }
        let terms_hex = match top.get("terms") {
            Some(Value::String(s)) => s.clone(),
            _ => return Err(malformed("terms: expected a string".into())),
        };
        let terms_bytes = unhex(&terms_hex).map_err(|e| malformed(format!("terms: {e}")))?;
        let terms = ValidatedTermsV4::decode(&terms_bytes)?;
        // The rest is a version 1 document over the v1 fields of the terms.
        top.insert("ipst".into(), Value::from(1));
        top.insert(
            "terms".into(),
            Value::String(ipst_hex(terms.v1_fields().canonical())),
        );
        let v1_text = serde_json::to_string(&Value::Object(top))
            .map_err(|e| malformed(format!("cannot re-render: {e}")))?;
        let ipst = Ipst::from_json(&v1_text)?;
        Ok(Self { ipst, terms })
    }

    /// The v1 document underneath (tests and the CLI's transaction view).
    pub fn as_v1(&self) -> &Ipst {
        &self.ipst
    }
}

/// The same slots, signatures aside: signer, sighash and the script parts, one for one.
fn same_slots(a: &[Slot], b: &[Slot]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.signer() == b.signer()
                && a.sighash() == b.sighash()
                && a.script_before() == b.script_before()
                && a.script_after() == b.script_after()
        })
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("expected lowercase hex of even length".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked hex"))
        .collect())
}

/// serde_json::Value, refusing an object that gives one key twice (the v1 reader refuses it too).
fn parse_unique(text: &str) -> Result<Value, String> {
    struct Unique(Value);
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
            Err(E::custom("fractions and exponents are not part of an IPST"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_string()))
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            let mut items = Vec::new();
            while let Some(Unique(v)) = seq.next_element()? {
                items.push(v);
            }
            Ok(Value::Array(items))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some((k, Unique(v))) = map.next_entry::<String, Unique>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(de::Error::custom(format!("key {k} is given twice")));
                }
            }
            Ok(Value::Object(out))
        }
    }
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_any(V).map(Unique)
        }
    }
    let mut de = serde_json::Deserializer::from_str(text);
    let Unique(v) = Unique::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}
