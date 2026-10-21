// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v3 partially signed transaction (spec/V3-ZK.md section 11): IPST version 4. It is
//! `IPST.md`'s layout with the terms v3 bytes in `terms` and one more key, `zk_proof`, the proof
//! as hex (null where the transaction carries none: funding and refunds). A v1 reader refuses it
//! as `IPST_UNSUPPORTED_VERSION`; this reader, given another version, refuses `ZK_IPST_VERSION`.
//!
//! The transaction, UTXO entries and signature slots are those of the v1 [`Ipst`], which this
//! type wraps, so reading verifies every sighash and every signature exactly as for version 1.
//! What differs is the terms (v3), the proof, and the mass caps: a v3 settle is heavier than the
//! standard cap of version 1, so `finalize` checks the v3 caps (spec/V3-ZK.md section 10).
//!
//! Holds no key and no secret.

use super::build::{check_v3_masses, rebuild};
use super::proof::ProofBytes;
use super::terms::ValidatedTermsV3;
use super::{hex, ZkError};
use crate::tx::{
    ipst_hex, min_relay_fee, write_ipst_json, Ipst, IpstJson, IpstKind, Kcc20Template, Masses,
    Slot, TermsMatch, TxError,
};
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// The IPST format version of a v3 document.
pub const IPST_VERSION_V3: u16 = 4;

/// An IPST for terms v3: the v1 partially signed transaction over the v1 fields of the terms, the
/// terms v3 themselves, and the proof the settle carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpstV3 {
    ipst: Ipst,
    terms: ValidatedTermsV3,
    proof: Option<ProofBytes>,
}

impl IpstV3 {
    pub(crate) fn from_parts(
        terms: ValidatedTermsV3,
        proof: Option<ProofBytes>,
        tx: Transaction,
        entries: Vec<UtxoEntry>,
        slots: Vec<Slot>,
    ) -> Self {
        Self {
            ipst: Ipst::from_parts(terms.v1_fields().clone(), tx, entries, slots),
            terms,
            proof,
        }
    }

    pub fn terms(&self) -> &ValidatedTermsV3 {
        &self.terms
    }

    /// The proof a settle carries; None for funding and refunds.
    pub fn proof(&self) -> Option<&ProofBytes> {
        self.proof.as_ref()
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

    /// Verifies a 65-byte signature against the slot's signer and sighash and stores it
    /// (`TX_SIGNATURE`, `TX_SIGNATURE_SLOT`).
    pub fn add_signature(&mut self, input: usize, sig65: &[u8]) -> Result<(), ZkError> {
        Ok(self.ipst.add_signature(input, sig65)?)
    }

    /// Combines two IPSTs of the same transaction (`IPST_CONFLICT` if they differ in anything but
    /// signatures, or in terms or proof).
    pub fn combine(&self, other: &IpstV3) -> Result<IpstV3, ZkError> {
        if self.terms != other.terms {
            return Err(TxError::IpstConflict {
                reason: "the IPSTs carry different terms",
            }
            .into());
        }
        if self.proof != other.proof {
            return Err(TxError::IpstConflict {
                reason: "the IPSTs carry different proofs",
            }
            .into());
        }
        Ok(Self {
            ipst: self.ipst.combine(&other.ipst)?,
            terms: self.terms.clone(),
            proof: self.proof.clone(),
        })
    }

    /// The signed transaction: every slot with a signer must hold a signature
    /// (`TX_SIGNATURE_SLOT`); each signature script is assembled around it. Then the v3 masses
    /// (`ZK_TX_MASS`) and the relay fee (`TX_FEE_TOO_LOW`) are checked on the result.
    pub fn finalize(&self) -> Result<Transaction, ZkError> {
        let mut tx = self.ipst.transaction().clone();
        for (input, (slot, tx_input)) in self
            .ipst
            .slots()
            .iter()
            .zip(tx.inputs.iter_mut())
            .enumerate()
        {
            let sig = match (slot.signer(), slot.signature()) {
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
        check_v3_masses(&masses)?;
        let (fee, minimum) = (self.fee(), min_relay_fee(masses.fee_mass));
        if fee < minimum {
            return Err(TxError::FeeTooLow { fee, minimum }.into());
        }
        Ok(tx)
    }

    /// Assembles the signed transaction from signature bytes, one `(input, signature)` pair per
    /// slot to fill: each is verified as [`IpstV3::add_signature`] does, then finalized.
    pub fn assemble(&self, signatures: &[(usize, &[u8])]) -> Result<Transaction, ZkError> {
        let mut ipst = self.clone();
        for (input, sig) in signatures {
            ipst.add_signature(*input, sig)?;
        }
        ipst.finalize()
    }

    /// The terms check (spec/IPST.md, "Terms check", for terms v3): whether this is the
    /// transaction the v3 builders make for its terms from its own inputs and proof. A signer
    /// runs it before signing, and a submitter before broadcast.
    pub fn verify_against_terms(
        &self,
        asset: &Kcc20Template,
        cash: Option<&Kcc20Template>,
        current_daa: u64,
    ) -> Result<TermsMatch, ZkError> {
        let (kind, trade_outputs, rebuilt): (IpstKind, usize, IpstV3) =
            rebuild(self, asset, cash, current_daa)?;
        if rebuilt.ipst.transaction() != self.ipst.transaction()
            || rebuilt.ipst.entries() != self.ipst.entries()
            || !same_slots(rebuilt.ipst.slots(), self.ipst.slots())
            || rebuilt.proof != self.proof
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

    /// The canonical JSON rendering: `IPST.md`'s with `"ipst": 4`, the terms v3 bytes and the
    /// `zk_proof` key last.
    pub fn to_json(&self) -> String {
        let IpstJson::Obj(fields) = self.ipst.to_value() else {
            unreachable!("an IPST renders as an object")
        };
        let mut out_fields: Vec<(&'static str, IpstJson)> = Vec::with_capacity(fields.len() + 1);
        for (key, value) in fields {
            out_fields.push(match key {
                "ipst" => (key, IpstJson::Int(IPST_VERSION_V3.into())),
                "terms" => (key, IpstJson::Str(ipst_hex(self.terms.canonical()))),
                _ => (key, value),
            });
        }
        out_fields.push((
            "zk_proof",
            self.proof
                .as_ref()
                .map_or(IpstJson::Null, |p| IpstJson::Str(hex(p.as_bytes()))),
        ));
        let mut out = String::new();
        write_ipst_json(&IpstJson::Obj(out_fields), 0, &mut out);
        out.push('\n');
        out
    }

    /// Reads a v3 IPST: form, version (`ZK_IPST_VERSION`), terms v3, the proof
    /// (`ZK_PROOF_MALFORMED`), then everything the v1 reader checks: slot consistency, every
    /// sighash recomputed and every signature verified.
    pub fn from_json(text: &str) -> Result<IpstV3, ZkError> {
        let malformed = |reason: String| ZkError::Tx(TxError::IpstMalformed { reason });
        let doc = parse_unique(text).map_err(malformed)?;
        let Value::Object(mut top) = doc else {
            return Err(malformed("expected an object".into()));
        };
        match top.get("ipst") {
            Some(Value::Number(n)) if n.as_u64() == Some(IPST_VERSION_V3.into()) => {}
            Some(Value::Number(n)) => {
                return Err(ZkError::IpstVersion {
                    found: n.to_string(),
                })
            }
            _ => return Err(malformed("no integer ipst key".into())),
        }
        let terms_hex = match top.get("terms") {
            Some(Value::String(s)) => s.clone(),
            _ => return Err(malformed("terms: expected a string".into())),
        };
        let proof_value = top
            .remove("zk_proof")
            .ok_or_else(|| malformed("missing key zk_proof".into()))?;
        let terms_bytes = unhex(&terms_hex).map_err(|e| malformed(format!("terms: {e}")))?;
        let terms = ValidatedTermsV3::decode(&terms_bytes)?;
        let proof = match proof_value {
            Value::Null => None,
            Value::String(s) => Some(ProofBytes::parse(&unhex(&s).map_err(|e| {
                ZkError::ProofMalformed {
                    reason: format!("zk_proof: {e}"),
                }
            })?)?),
            _ => {
                return Err(ZkError::ProofMalformed {
                    reason: "zk_proof is neither null nor a hex string".into(),
                })
            }
        };
        // The rest is a version 1 document over the v1 fields of the terms.
        top.insert("ipst".into(), Value::from(1));
        top.insert(
            "terms".into(),
            Value::String(ipst_hex(terms.v1_fields().canonical())),
        );
        let v1_text = serde_json::to_string(&Value::Object(top))
            .map_err(|e| malformed(format!("cannot re-render: {e}")))?;
        let ipst = Ipst::from_json(&v1_text)?;
        Ok(Self { ipst, terms, proof })
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
