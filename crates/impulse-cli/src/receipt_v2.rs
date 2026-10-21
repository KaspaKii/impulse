// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Receipts of version 2 (spec/CLI.md, "Settlement receipt, version 2"; spec/V2.md 4.6 and 4.8):
//! what `impulse v2 status` observed about a settle transaction of a v2 trade, with the quantity
//! the transaction moved, the cumulative quantity of the lineage against the terms total for every
//! leg, and the lineage itself (the outpoint each vault input spent, its covenant ID and the
//! covenant ID of the continuation). One receipt per transaction, so one per tranche. Signed by
//! whoever ran it through the signing module; this module only encodes, parses and verifies.
//!
//! Unlike version 1, the quantities and the lineage are re-derived from the transaction itself
//! (`impulse_core::v2::read_settle`), so a receipt binds its terms to its transaction.

use crate::error::CliError;
use crate::json::{hex, parse_strict, Json, Obj};
use crate::receipt::Observation;
use crate::signing::{self, SignRequest};
use crate::terms_file::network_name;
use impulse_core::terms::{LegKind, Network};
use impulse_core::v2::{quantities, SettleFacts, ValidatedTermsV2};
use kaspa_consensus_core::tx::TransactionOutpoint;
use secp256k1::{schnorr, Message, XOnlyPublicKey, SECP256K1};
use std::path::Path;

/// The receipt format version.
pub const RECEIPT_V2_VERSION: u8 = 2;

/// blake2b-256 key for the version 2 digest. Not the version 1 key, so a signature over one
/// version's bytes is never valid for the other's.
pub const RECEIPT_V2_DOMAIN: &[u8] = b"Impulse/receipt/v2";

/// The state this receipt names (spec/V2.md 4.8). A receipt never reports more than acceptance;
/// `final` is the watcher's word at its configured depth.
pub const RECEIPT_STATE: &str = "accepted";

const ZERO: [u8; 32] = [0; 32];

/// One leg of a transaction: what it moved and where its lineage went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegLine {
    /// The leg's units moved by this transaction (`lots * unit`).
    pub moved: u64,
    /// The leg's units moved by the lineage up to and including this transaction.
    pub cumulative: u64,
    /// The leg amount of the terms.
    pub total: u64,
    /// The outpoint the leg's vault input spent.
    pub spent: TransactionOutpoint,
    /// The covenant ID the vault input carried; zero for a plain vault UTXO.
    pub covenant: [u8; 32],
    /// The covenant ID of the continuation at output N + leg; zero when the vault did not
    /// continue.
    pub continuation: [u8; 32],
}

/// The quantity and lineage part of a version 2 receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quantity {
    pub lots: u64,
    pub cumulative_lots: u64,
    pub total_lots: u64,
    /// Digest of the receipt of the previous transaction of the lineage; zero for the first
    /// receipt of a chain (the signer asserts that the lineage starts at the genesis).
    pub prior: [u8; 32],
    pub legs: Vec<LegLine>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptV2 {
    pub observation: Observation,
    pub quantity: Quantity,
    /// x-only public key of the signer.
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

const KEYS: [&str; 15] = [
    "version",
    "network",
    "terms_hash",
    "txid",
    "accepting_block",
    "daa_score",
    "depth",
    "state",
    "lots",
    "cumulative_lots",
    "total_lots",
    "prior_receipt",
    "legs",
    "signer",
    "signature",
];
const QUANTITY_KEYS: [&str; 5] = [
    "lots",
    "cumulative_lots",
    "total_lots",
    "prior_receipt",
    "legs",
];
const LEG_KEYS: [&str; 7] = [
    "moved",
    "cumulative",
    "total",
    "spent_txid",
    "spent_index",
    "covenant",
    "continuation",
];

fn code(c: &'static str, why: impl Into<String>) -> CliError {
    CliError::new(c, why.into())
}

fn mismatch(why: impl Into<String>) -> CliError {
    code("RECEIPT_QUANTITY_MISMATCH", why)
}

fn lineage(why: impl Into<String>) -> CliError {
    code("RECEIPT_LINEAGE_MISMATCH", why)
}

impl Quantity {
    /// The quantity of a settle transaction read from the chain (`facts`), on top of the receipt
    /// of the previous transaction of the lineage, if any. `RECEIPT_LINEAGE_MISMATCH` when the
    /// previous receipt is for other terms, is not the transaction these vault inputs spent, or
    /// carries another covenant ID; `RECEIPT_QUANTITY_MISMATCH` when the cumulative lots pass the
    /// lot count of the terms.
    pub fn derive(
        terms: &ValidatedTermsV2,
        observation: &Observation,
        facts: &SettleFacts,
        previous: Option<&ReceiptV2>,
    ) -> Result<Self, CliError> {
        let n = terms.terms().legs.len();
        let (prior_lots, prior) = match previous {
            None => {
                // Without a previous receipt the lineage is asserted to start here. A KAS leg's
                // vault shows how many lots it still held: fewer than the terms' lot count means
                // earlier tranches, so the cumulative cannot be stated without them.
                let total = terms.terms().partial.map_or(1, |p| p.lot_count);
                for (i, (leg, f)) in terms.terms().legs.iter().zip(&facts.legs).enumerate() {
                    let unit = terms.terms().unit(i);
                    if leg.asset.kind == LegKind::Kas && unit > 0 && f.held / unit < total {
                        return Err(lineage(format!(
                            "leg {i}: the vault held {} of {total} lots, so earlier tranches exist: pass --previous with the receipt of the previous transaction",
                            f.held / unit
                        )));
                    }
                }
                (0, ZERO)
            }
            Some(p) => {
                // A previous receipt is trusted only as far as it verifies.
                p.verify_signature()?;
                p.check_quantities(terms)?;
                p.check_links(observation, facts, n)?;
                (p.quantity.cumulative_lots, p.digest())
            }
        };
        let (cumulative_lots, per_leg) =
            quantities(terms, facts.lots, prior_lots).map_err(|e| mismatch(format!("{e}")))?;
        let total_lots = terms.terms().partial.map_or(1, |p| p.lot_count);
        let legs = per_leg
            .iter()
            .zip(&facts.legs)
            .map(|(q, f)| LegLine {
                moved: q.settled,
                cumulative: q.cumulative,
                total: q.total,
                spent: f.spent,
                covenant: f.covenant.map_or(ZERO, |c| c.as_bytes()),
                continuation: f.continuation.map_or(ZERO, |c| c.as_bytes()),
            })
            .collect();
        Ok(Self {
            lots: facts.lots,
            cumulative_lots,
            total_lots,
            prior,
            legs,
        })
    }

    fn canonical(&self, out: &mut Vec<u8>) {
        for v in [self.lots, self.cumulative_lots, self.total_lots] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.prior);
        out.extend_from_slice(&(self.legs.len() as u32).to_le_bytes());
        for l in &self.legs {
            for v in [l.moved, l.cumulative, l.total] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&l.spent.transaction_id.as_bytes());
            out.extend_from_slice(&l.spent.index.to_le_bytes());
            out.extend_from_slice(&l.covenant);
            out.extend_from_slice(&l.continuation);
        }
    }
}

/// The 32 bytes the signer signs, from the observation and the quantity part.
fn digest_of(o: &Observation, q: &Quantity) -> [u8; 32] {
    let mut bytes = o.canonical();
    bytes[0] = RECEIPT_V2_VERSION;
    q.canonical(&mut bytes);
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(RECEIPT_V2_DOMAIN)
        .hash(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn leg_json(l: &LegLine) -> Json {
    let opt = |h: &[u8; 32]| {
        if *h == ZERO {
            Json::Null
        } else {
            Json::Str(hex(h))
        }
    };
    Json::Obj(vec![
        ("moved", Json::Str(l.moved.to_string())),
        ("cumulative", Json::Str(l.cumulative.to_string())),
        ("total", Json::Str(l.total.to_string())),
        (
            "spent_txid",
            Json::Str(hex(&l.spent.transaction_id.as_bytes())),
        ),
        ("spent_index", Json::Num(l.spent.index.into())),
        ("covenant", opt(&l.covenant)),
        ("continuation", opt(&l.continuation)),
    ])
}

impl ReceiptV2 {
    /// Signs `observation` and `quantity` with the key file the user named, through the signing
    /// module.
    pub fn sign(
        observation: Observation,
        quantity: Quantity,
        key_file: &Path,
        mainnet_explicit: bool,
    ) -> Result<Self, CliError> {
        let signed = signing::sign(&SignRequest {
            key_file,
            network: observation.network,
            mainnet_explicit,
            expected_signer: None,
            digest: digest_of(&observation, &quantity),
        })?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&signed.signature[..64]);
        Ok(Self {
            observation,
            quantity,
            signer: signed.signer,
            signature,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        digest_of(&self.observation, &self.quantity)
    }

    pub fn render(&self) -> String {
        let o = &self.observation;
        let q = &self.quantity;
        Json::Obj(vec![
            ("version", Json::Num(RECEIPT_V2_VERSION.into())),
            ("network", Json::Str(network_name(o.network).into())),
            ("terms_hash", Json::Str(hex(&o.terms_hash))),
            ("txid", Json::Str(hex(&o.txid))),
            ("accepting_block", Json::Str(hex(&o.accepting_block))),
            ("daa_score", Json::Str(o.daa_score.to_string())),
            ("depth", Json::Str(o.depth.to_string())),
            ("state", Json::Str(RECEIPT_STATE.into())),
            ("lots", Json::Str(q.lots.to_string())),
            ("cumulative_lots", Json::Str(q.cumulative_lots.to_string())),
            ("total_lots", Json::Str(q.total_lots.to_string())),
            ("prior_receipt", Json::Str(hex(&q.prior))),
            ("legs", Json::Arr(q.legs.iter().map(leg_json).collect())),
            ("signer", Json::Str(hex(&self.signer))),
            ("signature", Json::Str(hex(&self.signature))),
        ])
        .render()
    }

    /// The JSON form, nothing more (`RECEIPT_MALFORMED`). A version 2 receipt without its
    /// quantity fields is `RECEIPT_QUANTITY_MISSING`: a receipt of a partial trade that does not
    /// state the quantity moved and the cumulative quantity is not read (spec/V2.md 4.6). The
    /// signature is not checked here.
    pub fn parse(text: &str) -> Result<Self, CliError> {
        let malformed = |why: String| code("RECEIPT_MALFORMED", why);
        let value = parse_strict(text).map_err(malformed)?;
        let o = Obj::new("receipt", &value).map_err(malformed)?;
        let version = o.num("version", u8::MAX.into()).map_err(malformed)?;
        if version != u64::from(RECEIPT_V2_VERSION) {
            return Err(malformed(
                "receipt.version: this reads version 2 only; a version 1 receipt states no quantity (impulse receipt verify reads it)".into(),
            ));
        }
        if let Some(missing) = QUANTITY_KEYS.iter().find(|k| o.opt(k).is_none()) {
            return Err(code(
                "RECEIPT_QUANTITY_MISSING",
                format!("receipt.{missing}: a version 2 receipt states the quantity moved, the cumulative quantity and the total"),
            ));
        }
        o.keys(&KEYS, &[]).map_err(malformed)?;
        let network = [Network::Mainnet, Network::Testnet][o
            .choice("network", &["mainnet", "testnet"])
            .map_err(malformed)?];
        o.choice("state", &[RECEIPT_STATE]).map_err(malformed)?;
        let signature: [u8; 64] = o
            .hex("signature")
            .map_err(malformed)?
            .try_into()
            .map_err(|_| malformed("receipt.signature: expected 64 bytes".into()))?;
        let legs = value["legs"]
            .as_array()
            .ok_or_else(|| malformed("receipt.legs: expected an array".into()))?;
        if legs.is_empty() || legs.len() > 64 {
            return Err(malformed("receipt.legs: expected 1 to 64 legs".into()));
        }
        let mut lines = Vec::with_capacity(legs.len());
        for (i, leg) in legs.iter().enumerate() {
            let path = format!("receipt.legs[{i}]");
            let l = Obj::new(&path, leg).map_err(malformed)?;
            if let Some(missing) = ["moved", "cumulative", "total"]
                .iter()
                .find(|k| l.opt(k).is_none())
            {
                return Err(code(
                    "RECEIPT_QUANTITY_MISSING",
                    format!("{path}.{missing}: every leg states what it moved, its cumulative and its total"),
                ));
            }
            l.keys(&LEG_KEYS, &[]).map_err(malformed)?;
            let opt = |key: &str| -> Result<[u8; 32], String> {
                if l.is_null(key)? {
                    Ok(ZERO)
                } else {
                    l.hex32(key)
                }
            };
            lines.push(LegLine {
                moved: l.dec("moved").map_err(malformed)?,
                cumulative: l.dec("cumulative").map_err(malformed)?,
                total: l.dec("total").map_err(malformed)?,
                spent: TransactionOutpoint::new(
                    kaspa_consensus_core::Hash::from_bytes(
                        l.hex32("spent_txid").map_err(malformed)?,
                    ),
                    l.num("spent_index", u32::MAX.into()).map_err(malformed)? as u32,
                ),
                covenant: opt("covenant").map_err(malformed)?,
                continuation: opt("continuation").map_err(malformed)?,
            });
        }
        Ok(Self {
            observation: Observation {
                network,
                terms_hash: o.hex32("terms_hash").map_err(malformed)?,
                txid: o.hex32("txid").map_err(malformed)?,
                accepting_block: o.hex32("accepting_block").map_err(malformed)?,
                daa_score: o.dec("daa_score").map_err(malformed)?,
                depth: o.dec("depth").map_err(malformed)?,
            },
            quantity: Quantity {
                lots: o.dec("lots").map_err(malformed)?,
                cumulative_lots: o.dec("cumulative_lots").map_err(malformed)?,
                total_lots: o.dec("total_lots").map_err(malformed)?,
                prior: o.hex32("prior_receipt").map_err(malformed)?,
                legs: lines,
            },
            signer: o.hex32("signer").map_err(malformed)?,
            signature,
        })
    }

    /// The signature verifies over the digest for `signer`.
    pub fn verify_signature(&self) -> Result<(), CliError> {
        let invalid = |why: &str| code("RECEIPT_SIGNATURE_INVALID", why);
        let key = XOnlyPublicKey::from_slice(&self.signer)
            .map_err(|_| invalid("signer is not a valid x-only public key"))?;
        let sig = schnorr::Signature::from_slice(&self.signature)
            .map_err(|_| invalid("signature is malformed"))?;
        SECP256K1
            .verify_schnorr(&sig, &Message::from_digest(self.digest()), &key)
            .map_err(|_| invalid("the signature does not verify for signer"))
    }

    pub fn check_signer(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.signer != expected {
            return Err(code(
                "RECEIPT_SIGNER_MISMATCH",
                format!(
                    "signed by {}, expected {}",
                    hex(&self.signer),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }

    pub fn check_terms_hash(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.observation.terms_hash != expected {
            return Err(code(
                "RECEIPT_TERMS_MISMATCH",
                format!(
                    "the receipt is for terms {}, not your terms {}",
                    hex(&self.observation.terms_hash),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }

    pub fn check_txid(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.observation.txid != expected {
            return Err(code(
                "RECEIPT_TXID_MISMATCH",
                format!(
                    "the receipt is for transaction {}, not {}",
                    hex(&self.observation.txid),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }

    /// The quantities against the terms (`RECEIPT_QUANTITY_MISMATCH`): the receipt's lots and
    /// cumulative lots are within the lot count, `total_lots` is the terms' lot count, and for
    /// every leg `moved = lots * unit`, `cumulative = cumulative_lots * unit` and `total` is the
    /// leg amount. Without a previous receipt (`prior_receipt` zero) the cumulative is the lots.
    pub fn check_quantities(&self, terms: &ValidatedTermsV2) -> Result<(), CliError> {
        let t = terms.terms();
        let q = &self.quantity;
        let total_lots = t.partial.map_or(1, |p| p.lot_count);
        if q.total_lots != total_lots {
            return Err(mismatch(format!(
                "total_lots is {}, the terms have {total_lots}",
                q.total_lots
            )));
        }
        if q.lots == 0 || q.lots > q.cumulative_lots || q.cumulative_lots > total_lots {
            return Err(mismatch(
                "lots and cumulative_lots are not within the lot count of the terms",
            ));
        }
        if q.prior == ZERO && q.cumulative_lots != q.lots {
            return Err(mismatch(
                "a receipt without a previous receipt states a cumulative equal to its lots",
            ));
        }
        if q.legs.len() != t.legs.len() {
            return Err(mismatch(
                "the receipt does not state every leg of the terms",
            ));
        }
        for (i, l) in q.legs.iter().enumerate() {
            let unit = t.unit(i);
            if l.moved != q.lots * unit
                || l.cumulative != q.cumulative_lots * unit
                || l.total != t.legs[i].asset.amount
            {
                return Err(mismatch(format!(
                    "leg {i}: moved, cumulative and total do not follow from the lots and the terms"
                )));
            }
        }
        Ok(())
    }

    /// `previous` is the receipt of the transaction this one continues: its digest is
    /// `prior_receipt`, and it covers the same terms; for each leg the vault input spent an
    /// output of its transaction (output N + leg) and carries the covenant ID it continued with;
    /// and the cumulative adds up (`RECEIPT_LINEAGE_MISMATCH`, `RECEIPT_QUANTITY_MISMATCH`).
    pub fn check_previous(&self, previous: &ReceiptV2) -> Result<(), CliError> {
        let q = &self.quantity;
        if q.prior != previous.digest() {
            return Err(lineage(
                "prior_receipt is not the digest of the previous receipt",
            ));
        }
        previous.check_chain_of(self)?;
        if previous.quantity.cumulative_lots.checked_add(q.lots) != Some(q.cumulative_lots) {
            return Err(mismatch(
                "cumulative_lots is not the previous cumulative plus the lots",
            ));
        }
        Ok(())
    }

    fn check_chain_of(&self, next: &ReceiptV2) -> Result<(), CliError> {
        if next.observation.terms_hash != self.observation.terms_hash
            || next.observation.network != self.observation.network
        {
            return Err(lineage("the previous receipt is for other terms"));
        }
        let n = self.quantity.legs.len();
        if next.quantity.legs.len() != n {
            return Err(lineage("the receipts state different numbers of legs"));
        }
        for (i, (prev, now)) in self
            .quantity
            .legs
            .iter()
            .zip(&next.quantity.legs)
            .enumerate()
        {
            if prev.continuation == ZERO {
                return Err(lineage(format!(
                    "leg {i}: the previous transaction did not continue the vault"
                )));
            }
            let expected = TransactionOutpoint::new(
                kaspa_consensus_core::Hash::from_bytes(self.observation.txid),
                (n + i) as u32,
            );
            if now.spent != expected || now.covenant != prev.continuation {
                return Err(lineage(format!(
                    "leg {i}: the vault input did not spend the previous transaction's continuation of the same covenant"
                )));
            }
        }
        Ok(())
    }

    /// While deriving: the previous receipt against the transaction facts.
    fn check_links(
        &self,
        observation: &Observation,
        facts: &SettleFacts,
        n: usize,
    ) -> Result<(), CliError> {
        if self.observation.terms_hash != observation.terms_hash
            || self.observation.network != observation.network
        {
            return Err(lineage("the previous receipt is for other terms"));
        }
        if self.quantity.legs.len() != n || facts.legs.len() != n {
            return Err(lineage("the receipts state different numbers of legs"));
        }
        for (i, (prev, now)) in self.quantity.legs.iter().zip(&facts.legs).enumerate() {
            if prev.continuation == ZERO {
                return Err(lineage(format!(
                    "leg {i}: the previous transaction did not continue the vault"
                )));
            }
            let expected = TransactionOutpoint::new(
                kaspa_consensus_core::Hash::from_bytes(self.observation.txid),
                (n + i) as u32,
            );
            if now.spent != expected
                || now.covenant.map(|c| c.as_bytes()) != Some(prev.continuation)
            {
                return Err(lineage(format!(
                    "leg {i}: the vault input did not spend the previous transaction's continuation of the same covenant"
                )));
            }
        }
        Ok(())
    }

    /// The receipt against the transaction as the chain has it: the same lots and, per leg, the
    /// same spent outpoint, covenant ID and continuation (`RECEIPT_QUANTITY_MISMATCH`,
    /// `RECEIPT_LINEAGE_MISMATCH`).
    pub fn check_facts(&self, facts: &SettleFacts) -> Result<(), CliError> {
        let q = &self.quantity;
        if q.lots != facts.lots {
            return Err(mismatch(format!(
                "the transaction moves {} lots, the receipt says {}",
                facts.lots, q.lots
            )));
        }
        if q.legs.len() != facts.legs.len() {
            return Err(mismatch(
                "the receipt does not state every leg of the transaction",
            ));
        }
        for (i, (l, f)) in q.legs.iter().zip(&facts.legs).enumerate() {
            let cov = |c: Option<kaspa_consensus_core::Hash>| c.map_or(ZERO, |h| h.as_bytes());
            if l.spent != f.spent
                || l.covenant != cov(f.covenant)
                || l.continuation != cov(f.continuation)
            {
                return Err(lineage(format!(
                    "leg {i}: the spent outpoint, covenant ID or continuation differs from the transaction's"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::throwaway::key_file;
    use impulse_core::terms::{FundingMode, IdentifierType, Leg};
    use impulse_core::v2::{DestinationV2, LegV2, Partial, TermsV2};
    use kaspa_consensus_core::Hash;
    use serde_json::Value;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn observation() -> Observation {
        Observation {
            network: Network::Testnet,
            terms_hash: h(0x11),
            txid: h(0x22),
            accepting_block: h(0x33),
            daa_score: 1000,
            depth: 10,
        }
    }

    fn outpoint(b: u8, i: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash::from_bytes(h(b)), i)
    }

    fn quantity() -> Quantity {
        Quantity {
            lots: 1,
            cumulative_lots: 3,
            total_lots: 4,
            prior: h(0x44),
            legs: vec![
                LegLine {
                    moved: 250,
                    cumulative: 750,
                    total: 1000,
                    spent: outpoint(0xaa, 2),
                    covenant: h(0xbb),
                    continuation: h(0xcc),
                },
                LegLine {
                    moved: 25,
                    cumulative: 75,
                    total: 100,
                    spent: outpoint(0xdd, 3),
                    covenant: h(0xee),
                    continuation: [0; 32],
                },
            ],
        }
    }

    /// Two KAS legs of 1000 and 100 over four lots, min_lot 1.
    fn terms() -> ValidatedTermsV2 {
        let leg = |from: u8, to: u8, amount: u64| LegV2 {
            depositor_key: h(from),
            asset: Leg {
                kind: LegKind::Kas,
                amount,
            },
            delivery: DestinationV2 {
                identifier_type: IdentifierType::PubKey,
                identifier: h(to),
            },
            refund: DestinationV2 {
                identifier_type: IdentifierType::PubKey,
                identifier: h(from),
            },
        };
        TermsV2 {
            version: 2,
            network: Network::Testnet,
            nonce: 1,
            authority_key: None,
            legs: vec![leg(1, 2, 1000), leg(2, 1, 100)],
            earliest_daa: None,
            expiry_daa: 5_000_000,
            funding_mode: FundingMode::Revocable,
            partial: Some(Partial {
                lot_count: 4,
                min_lot: 1,
            }),
            trade_ref: h(7),
        }
        .validate_structure()
        .unwrap()
    }

    #[test]
    fn digest_known_answer() {
        // Computed independently with Python's hashlib.blake2b(key=b"Impulse/receipt/v2") over the
        // 422 canonical bytes: version 2, network, terms_hash, txid, accepting_block, daa_score,
        // depth, lots, cumulative_lots, total_lots, prior, leg count, then per leg moved,
        // cumulative, total, spent txid, spent index, covenant, continuation (zero when none).
        let mut bytes = observation().canonical();
        bytes[0] = RECEIPT_V2_VERSION;
        quantity().canonical(&mut bytes);
        assert_eq!(bytes.len(), 422);
        assert_eq!(
            hex(&digest_of(&observation(), &quantity())),
            "eaee3a7a4107769994249ad50b029cb1c16f31a6f8483e3a278235fa8fada500"
        );
    }

    #[test]
    fn sign_render_parse_verify() {
        let k = key_file();
        let r = ReceiptV2::sign(observation(), quantity(), &k.path, false).unwrap();
        assert_eq!(r.signer, k.signer);
        let text = r.render();
        assert!(!text.contains(k.content.trim_end()), "no key material");
        let back = ReceiptV2::parse(&text).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.verify_signature(), Ok(()));
        assert_eq!(back.check_signer(&k.signer), Ok(()));
        assert_eq!(
            back.check_signer(&key_file().signer).unwrap_err().code(),
            "RECEIPT_SIGNER_MISMATCH"
        );
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("  \""))
            .filter_map(|l| l.split('"').next())
            .collect();
        assert_eq!(keys, KEYS, "keys in spec order");
        assert!(text.contains("\"state\": \"accepted\""));
        assert!(!text.contains("settled"), "wording of spec/V2.md 4.8");
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let k = key_file();
        let r = ReceiptV2::sign(observation(), quantity(), &k.path, false).unwrap();
        let edits: [fn(&mut ReceiptV2); 18] = [
            |r| r.observation.network = Network::Mainnet,
            |r| r.observation.terms_hash[0] ^= 1,
            |r| r.observation.txid[0] ^= 1,
            |r| r.observation.accepting_block[0] ^= 1,
            |r| r.observation.daa_score += 1,
            |r| r.observation.depth += 1,
            |r| r.quantity.lots += 1,
            |r| r.quantity.cumulative_lots += 1,
            |r| r.quantity.total_lots += 1,
            |r| r.quantity.prior[0] ^= 1,
            |r| r.quantity.legs[0].moved += 1,
            |r| r.quantity.legs[0].cumulative += 1,
            |r| r.quantity.legs[0].total += 1,
            |r| r.quantity.legs[0].spent = outpoint(0xaa, 3),
            |r| r.quantity.legs[0].covenant[0] ^= 1,
            |r| r.quantity.legs[1].continuation = h(1),
            |r| {
                r.quantity.legs.pop();
            },
            |r| r.signature[0] ^= 1,
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut bad = r.clone();
            edit(&mut bad);
            assert_eq!(
                bad.verify_signature().unwrap_err().code(),
                "RECEIPT_SIGNATURE_INVALID",
                "edit {i}"
            );
        }
        // A version 1 digest key is another key: the same observation signs differently.
        assert_ne!(r.digest(), Observation::digest(&observation()));
    }

    #[test]
    fn malformed_and_incomplete_receipts_are_told_apart() {
        let k = key_file();
        let good = ReceiptV2::sign(observation(), quantity(), &k.path, false)
            .unwrap()
            .render();
        assert!(ReceiptV2::parse(&good).is_ok(), "control");
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut v: Value = serde_json::from_str(&good).unwrap();
            f(&mut v);
            v.to_string()
        };
        let malformed = [
            edit(&|v| v["extra"] = 1.into()),
            edit(&|v| v["version"] = 1.into()),
            edit(&|v| v["state"] = "final".into()),
            edit(&|v| v["network"] = "devnet".into()),
            edit(&|v| v["lots"] = 1.into()),
            edit(&|v| v["legs"] = Value::Array(vec![])),
            edit(&|v| v["legs"][0]["spent_index"] = "2".into()),
            edit(&|v| v["legs"][0]["extra"] = 1.into()),
            edit(&|v| v["prior_receipt"] = "00".into()),
            "[]".to_string(),
            "not json".to_string(),
            good.replacen(
                "  \"txid\": ",
                &format!("  \"txid\": \"{}\",\n  \"txid\": ", "99".repeat(32)),
                1,
            ),
        ];
        for (i, text) in malformed.iter().enumerate() {
            assert_eq!(
                ReceiptV2::parse(text).unwrap_err().code(),
                "RECEIPT_MALFORMED",
                "case {i}"
            );
        }
        for key in [
            "lots",
            "cumulative_lots",
            "total_lots",
            "prior_receipt",
            "legs",
        ] {
            let text = edit(&|v| {
                v.as_object_mut().unwrap().remove(key);
            });
            assert_eq!(
                ReceiptV2::parse(&text).unwrap_err().code(),
                "RECEIPT_QUANTITY_MISSING",
                "{key}"
            );
        }
        for key in ["moved", "cumulative", "total"] {
            let text = edit(&|v| {
                v["legs"][1].as_object_mut().unwrap().remove(key);
            });
            assert_eq!(
                ReceiptV2::parse(&text).unwrap_err().code(),
                "RECEIPT_QUANTITY_MISSING",
                "leg {key}"
            );
        }
    }

    #[test]
    fn quantities_must_follow_from_the_terms() {
        let t = terms();
        let k = key_file();
        let mut q = quantity();
        q.legs[0].spent = outpoint(1, 0);
        // lots 1 of 4 after 2 earlier: cumulative 3; units 250 and 25.
        let ok = ReceiptV2::sign(observation(), q.clone(), &k.path, false).unwrap();
        assert_eq!(ok.check_quantities(&t), Ok(()), "control");
        let edits: [fn(&mut Quantity); 9] = [
            |q| q.total_lots = 5,
            |q| q.lots = 0,
            |q| q.cumulative_lots = 5,
            |q| q.lots = 4,
            |q| q.legs[0].moved = 251,
            |q| q.legs[1].cumulative = 76,
            |q| q.legs[1].total = 101,
            |q| {
                q.legs.pop();
            },
            |q| q.prior = [0; 32],
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut bad = q.clone();
            edit(&mut bad);
            let r = ReceiptV2::sign(observation(), bad, &k.path, false).unwrap();
            assert_eq!(
                r.check_quantities(&t).unwrap_err().code(),
                "RECEIPT_QUANTITY_MISMATCH",
                "edit {i}"
            );
        }
        // Lots above the cumulative, every other figure consistent with them.
        let mut over = q.clone();
        over.lots = 4;
        over.legs[0].moved = 1000;
        over.legs[1].moved = 100;
        let r = ReceiptV2::sign(observation(), over, &k.path, false).unwrap();
        assert_eq!(
            r.check_quantities(&t).unwrap_err().code(),
            "RECEIPT_QUANTITY_MISMATCH"
        );
    }

    #[test]
    fn a_chain_adds_up_and_each_link_is_the_continuation() {
        let k = key_file();
        let mut first_q = quantity();
        first_q.lots = 1;
        first_q.cumulative_lots = 1;
        first_q.prior = [0; 32];
        first_q.legs[0].continuation = h(0xcc);
        first_q.legs[1].continuation = h(0xc1);
        // One lot of the terms: 250 of 1000 and 25 of 100.
        for (l, v) in first_q.legs.iter_mut().zip([250, 25]) {
            l.moved = v;
            l.cumulative = v;
        }
        let first = ReceiptV2::sign(observation(), first_q, &k.path, false).unwrap();
        let n = 2u32;
        let mut second_obs = observation();
        second_obs.txid = h(0x55);
        let second_q = Quantity {
            lots: 2,
            cumulative_lots: 3,
            total_lots: 4,
            prior: first.digest(),
            legs: vec![
                LegLine {
                    moved: 500,
                    cumulative: 750,
                    total: 1000,
                    spent: TransactionOutpoint::new(Hash::from_bytes(first.observation.txid), n),
                    covenant: h(0xcc),
                    continuation: h(0xcc),
                },
                LegLine {
                    moved: 50,
                    cumulative: 75,
                    total: 100,
                    spent: TransactionOutpoint::new(
                        Hash::from_bytes(first.observation.txid),
                        n + 1,
                    ),
                    covenant: h(0xc1),
                    continuation: h(0xc1),
                },
            ],
        };
        let second = ReceiptV2::sign(second_obs, second_q.clone(), &k.path, false).unwrap();
        assert_eq!(second.check_previous(&first), Ok(()), "control");
        type Edit = fn(&mut Quantity);
        let edits: [(Edit, &str); 6] = [
            (|q| q.prior[0] ^= 1, "RECEIPT_LINEAGE_MISMATCH"),
            (
                |q| q.legs[0].spent = outpoint(9, 2),
                "RECEIPT_LINEAGE_MISMATCH",
            ),
            (|q| q.legs[1].spent.index = 0, "RECEIPT_LINEAGE_MISMATCH"),
            (|q| q.legs[0].covenant = h(1), "RECEIPT_LINEAGE_MISMATCH"),
            (|q| q.cumulative_lots = 4, "RECEIPT_QUANTITY_MISMATCH"),
            (|q| q.lots = 1, "RECEIPT_QUANTITY_MISMATCH"),
        ];
        for (i, (edit, expected)) in edits.iter().enumerate() {
            let mut q = second_q.clone();
            edit(&mut q);
            // The prior digest edit must be the one that fails; the others keep the digest.
            let r = ReceiptV2::sign(second.observation, q, &k.path, false).unwrap();
            assert_eq!(
                r.check_previous(&first).unwrap_err().code(),
                *expected,
                "edit {i}"
            );
        }
        // Another trade's receipt, and a previous receipt whose vault did not continue.
        let mut other = first.clone();
        other.observation.terms_hash[0] ^= 1;
        assert_eq!(
            second.check_previous(&other).unwrap_err().code(),
            "RECEIPT_LINEAGE_MISMATCH"
        );
        let mut ended = first.quantity.clone();
        ended.legs[1].continuation = [0; 32];
        let ended = ReceiptV2::sign(first.observation, ended, &k.path, false).unwrap();
        let mut linked = second_q;
        linked.prior = ended.digest();
        let linked = ReceiptV2::sign(second.observation, linked, &k.path, false).unwrap();
        assert_eq!(
            linked.check_previous(&ended).unwrap_err().code(),
            "RECEIPT_LINEAGE_MISMATCH"
        );
        // The same, where the next transaction's vault carries no covenant either.
        let mut plain = second_q_plain(&linked);
        plain.legs[1].covenant = [0; 32];
        let plain = ReceiptV2::sign(second.observation, plain, &k.path, false).unwrap();
        assert_eq!(
            plain.check_previous(&ended).unwrap_err().code(),
            "RECEIPT_LINEAGE_MISMATCH"
        );
        // derive checks the previous receipt against the transaction's facts.
        let facts = |txid: [u8; 32], idx: u32| impulse_core::v2::SettleFacts {
            lots: 2,
            tranche: false,
            legs: (0..2)
                .map(|i| impulse_core::v2::LegSettle {
                    leg: i,
                    settled: 0,
                    spent: TransactionOutpoint::new(Hash::from_bytes(txid), idx + i as u32),
                    held: 0,
                    covenant: Some(Hash::from_bytes(if i == 0 { h(0xcc) } else { h(0xc1) })),
                    continuation: None,
                })
                .collect(),
        };
        let t = terms();
        let good = Quantity::derive(
            &t,
            &second.observation,
            &facts(first.observation.txid, 2),
            Some(&first),
        );
        assert!(good.is_ok(), "control: {good:?}");
        let bad = Quantity::derive(&t, &second.observation, &facts(h(0x99), 2), Some(&first));
        assert_eq!(bad.unwrap_err().code(), "RECEIPT_LINEAGE_MISMATCH");
    }

    fn chain_facts(prev_txid: [u8; 32], held: [u64; 2]) -> impulse_core::v2::SettleFacts {
        impulse_core::v2::SettleFacts {
            lots: 1,
            tranche: true,
            legs: (0..2)
                .map(|i| impulse_core::v2::LegSettle {
                    leg: i,
                    settled: 0,
                    spent: TransactionOutpoint::new(Hash::from_bytes(prev_txid), 2 + i as u32),
                    held: held[i],
                    covenant: Some(Hash::from_bytes(if i == 0 { h(0xcc) } else { h(0xc1) })),
                    continuation: None,
                })
                .collect(),
        }
    }

    #[test]
    fn a_receipt_without_previous_needs_a_vault_that_held_every_lot() {
        let t = terms();
        let mut next = observation();
        next.txid = h(0x55);
        // Control: the vaults held all four lots, so the lineage starts here.
        let ok = Quantity::derive(&t, &next, &chain_facts(h(0x22), [1000, 100]), None).unwrap();
        assert_eq!((ok.lots, ok.cumulative_lots, ok.prior), (1, 1, ZERO));
        // Tranche two or later: the vault held three lots, so a cumulative of 1 would understate.
        let e = Quantity::derive(&t, &next, &chain_facts(h(0x22), [750, 75]), None).unwrap_err();
        assert_eq!(e.code(), "RECEIPT_LINEAGE_MISMATCH");
        let e = Quantity::derive(&t, &next, &chain_facts(h(0x22), [1000, 75]), None).unwrap_err();
        assert_eq!(e.code(), "RECEIPT_LINEAGE_MISMATCH");
    }

    #[test]
    fn a_previous_receipt_is_verified_before_it_is_chained() {
        let k = key_file();
        let t = terms();
        let mut next = observation();
        next.txid = h(0x55);
        let mut first_q = quantity();
        first_q.prior = ZERO;
        first_q.cumulative_lots = 1;
        first_q.lots = 1;
        first_q.legs[0].cumulative = 250;
        first_q.legs[0].moved = 250;
        first_q.legs[1].cumulative = 25;
        first_q.legs[1].moved = 25;
        first_q.legs[1].continuation = h(0xc1);
        let first = ReceiptV2::sign(observation(), first_q.clone(), &k.path, false).unwrap();
        let facts = chain_facts(h(0x22), [750, 75]);
        let good = Quantity::derive(&t, &next, &facts, Some(&first));
        assert!(good.is_ok(), "control: {good:?}");
        assert_eq!(good.unwrap().cumulative_lots, 2);
        // A flipped byte in the quantities breaks the signature.
        let mut forged = first.clone();
        forged.quantity.cumulative_lots = 3;
        let e = Quantity::derive(&t, &next, &facts, Some(&forged)).unwrap_err();
        assert_eq!(e.code(), "RECEIPT_SIGNATURE_INVALID");
        let mut flipped = first.clone();
        flipped.signature[0] ^= 1;
        let e = Quantity::derive(&t, &next, &facts, Some(&flipped)).unwrap_err();
        assert_eq!(e.code(), "RECEIPT_SIGNATURE_INVALID");
        // Validly signed, but its quantities disagree with the terms.
        let mut wrong = first_q;
        wrong.cumulative_lots = 3;
        let wrong = ReceiptV2::sign(observation(), wrong, &k.path, false).unwrap();
        let e = Quantity::derive(&t, &next, &facts, Some(&wrong)).unwrap_err();
        assert_eq!(e.code(), "RECEIPT_QUANTITY_MISMATCH");
    }

    fn second_q_plain(r: &ReceiptV2) -> Quantity {
        r.quantity.clone()
    }

    #[test]
    fn a_mainnet_receipt_needs_the_explicit_flag() {
        let k = key_file();
        let mut o = observation();
        o.network = Network::Mainnet;
        assert_eq!(
            ReceiptV2::sign(o, quantity(), &k.path, false)
                .unwrap_err()
                .code(),
            "SIGN_MAINNET_NOT_EXPLICIT"
        );
        assert!(
            ReceiptV2::sign(o, quantity(), &k.path, true).is_ok(),
            "control"
        );
    }
}
