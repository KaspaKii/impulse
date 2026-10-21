// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Decoding a transaction (spec/VERIFY.md, "Decoding a transaction"): find the inputs that spend
//! an Impulse vault, read each one's terms and leg index back from the redeem script it reveals,
//! name the entry it calls, and report the trade per leg. This is the engine behind the public
//! decoder page (I11) and `impulse decode` (I7, which fetches the transaction from a node).
//!
//! Decoding reads what a transaction reveals. It does not check that the transaction is valid
//! or accepted; a valid transaction's vault inputs ran the contract, so the outcomes reported
//! hold for it.
//!
//! The transaction ID does not commit to signature scripts (rusty-kaspa a41a333 hashes the
//! transaction with `EXCLUDE_SIGNATURE_SCRIPT`), and signature scripts are where a vault spend
//! reveals its terms. So the ID check catches a value or byte string edited elsewhere, never an
//! edited or forged signature script. [`decode_transaction`] and [`decode_raw`] therefore take
//! the scriptPublicKey of each spent UTXO and accept a vault input only when the UTXO it spends
//! is the version 0 P2SH of the script it reveals, the one case where consensus runs that
//! script. [`decode_unbound`] and [`decode_raw_unbound`] skip that check: what they report is
//! only as trustworthy as the source of the transaction.
//!
//! Adapted from an internal settlement-binding check by the owner (relicensed, see NOTICE):
//! the raw transaction as rusty-kaspa's borsh encoding, the redeem script as the last push of
//! each input's signature script, and the template hash of the revealed script. Changed: every
//! push is parsed, an input whose signature script is not push only is not a vault spend, the
//! carried transaction ID is checked against the recomputed one, and each vault input is bound
//! to the scriptPublicKey it spends. Keyless: nothing here signs or holds a private key.

mod error;
#[cfg(test)]
mod tests;

pub use error::{DecodeError, DECODE_ERROR_CODES};

use crate::template::{self, LegIndex, Vault};
use crate::terms::{Destination, Network, TermsError, ValidatedTerms};
use borsh::BorshDeserialize;
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionOutpoint};
use kaspa_txscript::pay_to_script_hash_script;

/// Decodes rusty-kaspa a41a333's borsh encoding of a `Transaction`, then decodes the
/// transaction as [`decode_transaction`] with the scriptPublicKey each input spends. Bytes that
/// do not parse, or leave bytes over, are `DECODE_TX_MALFORMED`.
pub fn decode_raw(
    bytes: &[u8],
    spent: &[ScriptPublicKey],
    network: Network,
) -> Result<DecodedTransaction, DecodeError> {
    decode_with(&parse(bytes)?, Some(spent), network)
}

/// [`decode_raw`] without the spent scriptPublicKeys: as [`decode_unbound`].
pub fn decode_raw_unbound(
    bytes: &[u8],
    network: Network,
) -> Result<DecodedTransaction, DecodeError> {
    decode_with(&parse(bytes)?, None, network)
}

fn parse(bytes: &[u8]) -> Result<Transaction, DecodeError> {
    Transaction::try_from_slice(bytes).map_err(|e| DecodeError::TxMalformed {
        reason: e.to_string(),
    })
}

/// The raw form [`decode_raw`] reads: rusty-kaspa a41a333's borsh encoding of the transaction.
pub fn encode_raw(tx: &Transaction) -> Vec<u8> {
    // Writing into a Vec has no I/O to fail, and every field of Transaction serializes.
    borsh::to_vec(tx).expect("borsh writes a transaction into memory")
}

/// Finds every input that spends an Impulse vault and reads its terms, leg and entry. `spent`
/// holds the scriptPublicKey of the UTXO each input spends, in input order (from the node, I7).
///
/// Whole-transaction refusals: the carried ID is not the ID of the contents
/// (`DECODE_TX_ID_MISMATCH`); `spent` does not have one entry per input (`DECODE_SPENT_COUNT`).
/// An input whose signature script is not push only, or whose last push is not a script of the
/// pinned template, is not a vault spend and is skipped. Each other input is a vault input, and
/// is refused on its own, in this order, without hiding the others: the UTXO it spends is not
/// the version 0 P2SH of the script it reveals (`DECODE_INPUT_NOT_VAULT`); the script does not
/// decode (`TEMPLATE_*`, `TERMS_*`); its terms name another network than `network`
/// (`TERMS_NETWORK_MISMATCH`); it calls no entry of the template (`DECODE_ENTRY_UNKNOWN`). When no
/// vault input decodes, the first refusal is returned, or `DECODE_NO_VAULT_INPUT` if there is
/// none; otherwise the decoded legs come back with the refusals beside them
/// ([`DecodedTransaction::strict`] turns any refusal into an error).
pub fn decode_transaction(
    tx: &Transaction,
    spent: &[ScriptPublicKey],
    network: Network,
) -> Result<DecodedTransaction, DecodeError> {
    decode_with(tx, Some(spent), network)
}

/// [`decode_transaction`] without the binding of each vault input to the UTXO it spends. The
/// transaction ID does not commit to signature scripts, so anyone can swap, forge or add a vault
/// input under an unchanged ID; and consensus does not run the signature script of an input
/// whose spent scriptPublicKey has a version above 0. Use only on a transaction from a source
/// trusted for its signature scripts; `bound` is false in the result.
pub fn decode_unbound(
    tx: &Transaction,
    network: Network,
) -> Result<DecodedTransaction, DecodeError> {
    decode_with(tx, None, network)
}

fn decode_with(
    tx: &Transaction,
    spent: Option<&[ScriptPublicKey]>,
    network: Network,
) -> Result<DecodedTransaction, DecodeError> {
    let computed = hashing::tx::id(tx);
    if tx.id() != computed {
        return Err(DecodeError::TxIdMismatch {
            carried: tx.id().as_bytes(),
            computed: computed.as_bytes(),
        });
    }
    if let Some(spent) = spent {
        if spent.len() != tx.inputs.len() {
            return Err(DecodeError::SpentCount {
                inputs: tx.inputs.len(),
                spent: spent.len(),
            });
        }
    }
    let template = template::check().map_err(DecodeError::Template)?;
    let tags = EntryTags::of(template)?;
    let mut legs = Vec::new();
    let mut refused = Vec::new();
    for (index, input) in tx.inputs.iter().enumerate() {
        // Not push only: consensus refuses it at a version 0 P2SH input, so it is no vault spend.
        let Some(pushes) = pushes(&input.signature_script) else {
            continue;
        };
        let Some(Some(script)) = pushes.last() else {
            continue; // reveals no script: not a P2SH spend
        };
        // Only a script running the published template is a vault spend.
        if template::template_hash_of_instance(script).ok() != Some(template.hash()) {
            continue;
        }
        let spent = spent.map(|s| &s[index]);
        let at = (index, input.previous_outpoint);
        match decode_input(at, &pushes, script, spent, network, &tags) {
            Ok(leg) => legs.push(leg),
            Err(e) => refused.push(e),
        }
    }
    if legs.is_empty() {
        return Err(refused
            .into_iter()
            .next()
            .unwrap_or(DecodeError::NoVaultInput));
    }
    Ok(DecodedTransaction {
        txid: computed.as_bytes(),
        bound: spent.is_some(),
        legs,
        refused,
    })
}

/// One vault input: bound to the UTXO it spends when `spent` is given, then decoded.
fn decode_input(
    (index, outpoint): (usize, TransactionOutpoint),
    pushes: &[Option<&[u8]>],
    script: &[u8],
    spent: Option<&ScriptPublicKey>,
    network: Network,
    tags: &EntryTags,
) -> Result<DecodedLeg, DecodeError> {
    // The version 0 P2SH of the revealed script: the only UTXO whose spend runs this script.
    if spent.is_some_and(|spk| *spk != pay_to_script_hash_script(script)) {
        return Err(DecodeError::InputNotVault { index });
    }
    let input_error = |error| DecodeError::Input { index, error };
    let (terms, leg) = template::decode(script).map_err(input_error)?;
    let named = terms.terms().network;
    if named != network {
        return Err(input_error(
            TermsError::NetworkMismatch {
                expected: network,
                found: named,
            }
            .into(),
        ));
    }
    let entry = tags
        .entry(pushes, &terms)
        .ok_or(DecodeError::EntryUnknown { index })?;
    let script_hash = Vault::instantiate_existing(&terms, leg)
        .map_err(input_error)?
        .script_hash();
    Ok(DecodedLeg {
        input_index: index,
        outpoint,
        leg,
        script_hash,
        terms,
        entry,
    })
}

/// The redeem script a signature script reveals: its last push, if the script is push only and
/// ends with a data push. Consensus runs every signature script push only, and a P2SH spend
/// carries its redeem script as the last push.
pub fn revealed_script(signature_script: &[u8]) -> Option<&[u8]> {
    match pushes(signature_script)?.last() {
        Some(Some(script)) => Some(script),
        _ => None,
    }
}

/// A decoded transaction: its ID, recomputed from its contents, its vault inputs in order, and
/// the vault inputs that were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTransaction {
    pub txid: [u8; 32],
    /// True when each vault input was bound to the scriptPublicKey of the UTXO it spends
    /// ([`decode_transaction`], [`decode_raw`]). False from [`decode_unbound`]: the legs are
    /// then only as trustworthy as the source of the transaction.
    pub bound: bool,
    pub legs: Vec<DecodedLeg>,
    /// The vault inputs refused, in input order, each error naming its input. A third party can
    /// add such an input to a transaction that settles a trade; the legs above still hold.
    pub refused: Vec<DecodeError>,
}

impl DecodedTransaction {
    /// The transaction only if no vault input was refused; else the first refusal. For callers
    /// that must treat a transaction carrying any unreadable vault input as unreadable.
    pub fn strict(self) -> Result<Self, DecodeError> {
        match self.refused.first() {
            Some(e) => Err(e.clone()),
            None => Ok(self),
        }
    }

    /// The trades the transaction touches, in order of first appearance, each with its legs.
    /// A canonical settle touches one trade. Two trades appear when the asset vault of one and
    /// the cash vault of another settle together (spec "Red team", cross-trade mixing).
    pub fn trades(&self) -> Vec<DecodedTrade<'_>> {
        let mut trades: Vec<DecodedTrade<'_>> = Vec::new();
        for leg in &self.legs {
            let hash = leg.terms.terms_hash();
            match trades.iter_mut().find(|t| t.terms.terms_hash() == hash) {
                Some(trade) => trade.legs.push(leg),
                None => trades.push(DecodedTrade {
                    terms: &leg.terms,
                    legs: vec![leg],
                }),
            }
        }
        trades
    }
}

/// One trade a transaction touches: its terms and the vault inputs that spend its legs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTrade<'a> {
    pub terms: &'a ValidatedTerms,
    pub legs: Vec<&'a DecodedLeg>,
}

/// One vault input: where it sits, which vault it spends and which entry it calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedLeg {
    pub input_index: usize,
    pub outpoint: TransactionOutpoint,
    pub leg: LegIndex,
    /// The vault's script hash, which the spent UTXO's P2SH scriptPubKey commits to.
    pub script_hash: [u8; 32],
    pub terms: ValidatedTerms,
    pub entry: Entry,
}

impl DecodedLeg {
    /// What the entry does with the leg, if the transaction is valid.
    pub fn outcome(&self) -> Outcome {
        let t = self.terms.terms();
        match (&self.entry, self.leg) {
            (Entry::Settle, LegIndex::Asset) => Outcome::Delivered {
                amount: t.asset_leg.amount,
                to: t.buyer_delivery.clone(),
            },
            (Entry::Settle, LegIndex::Cash) => Outcome::Delivered {
                amount: t.cash_leg.amount,
                to: t.seller_proceeds.clone(),
            },
            (Entry::Refund { .. }, LegIndex::Asset) => Outcome::Refunded {
                to: t.seller_refund.clone(),
            },
            (Entry::Refund { .. }, LegIndex::Cash) => Outcome::Refunded {
                to: t.buyer_refund.clone(),
            },
        }
    }
}

/// The vault entry an input calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Settle,
    /// `signer` is the key the refund names, when the argument is a 32-byte key; `party` is the
    /// role that key holds under the terms, if any.
    Refund {
        signer: Option<[u8; 32]>,
        party: Option<Party>,
    },
}

/// A role under the terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Party {
    Seller,
    Buyer,
    Authority,
}

/// What a valid transaction does with a leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Settled: the contract delivers exactly `amount` of the leg to `to` (buyer_delivery for the
    /// asset, seller_proceeds for the cash), and a KCC-20 leg's authorizer KAS to its depositor.
    Delivered { amount: u64, to: Destination },
    /// Refunded: what this vault UTXO holds goes home whole, an authorizer's KAS to the
    /// depositor's key. `to` (seller_refund or buyer_refund) is where the contract sends the
    /// escrowed token or KAS cash if the transaction carries it; decoding does not read the
    /// outputs, and a depositor may refund an authorizer without its token, so `to` may receive
    /// nothing from this transaction and no amount is stated.
    Refunded { to: Destination },
}

/// The dispatch tags of the template's two entries.
struct EntryTags {
    settle: [u8; 4],
    refund: [u8; 4],
}

impl EntryTags {
    fn of(template: &template::Template) -> Result<Self, DecodeError> {
        let tag = |name: &str| {
            template
                .abi()
                .contract(template::CONTRACT_NAME)
                .and_then(|c| c.entry(name))
                .map(|e| e.dispatch_tag.into_bytes())
                .ok_or_else(|| {
                    DecodeError::Template(template::TemplateError::ArtifactInvalid {
                        reason: format!("the template has no {name} entry"),
                    })
                })
        };
        Ok(Self {
            settle: tag("settle")?,
            refund: tag("refund")?,
        })
    }

    /// The entry a vault input's pushes call: the dispatch tag is the push before the redeem
    /// script, and a refund's `signer` argument the push before the tag.
    fn entry(&self, pushes: &[Option<&[u8]>], terms: &ValidatedTerms) -> Option<Entry> {
        let n = pushes.len();
        let tag: [u8; 4] = (*pushes.get(n.checked_sub(2)?)?)?.try_into().ok()?;
        if tag == self.settle {
            return Some(Entry::Settle);
        }
        if tag != self.refund {
            return None;
        }
        let signer: Option<[u8; 32]> = n
            .checked_sub(3)
            .and_then(|i| *pushes.get(i)?)
            .and_then(|s| s.try_into().ok());
        let t = terms.terms();
        let party = signer.and_then(|k| {
            if k == t.seller_key {
                Some(Party::Seller)
            } else if k == t.buyer_key {
                Some(Party::Buyer)
            } else if Some(k) == t.authority_key {
                Some(Party::Authority)
            } else {
                None
            }
        });
        Some(Entry::Refund { signer, party })
    }
}

/// Every push of a push-only script, in order: `Some(data)` for a data push, `None` for a
/// small-integer push (OP_1NEGATE, OP_1 to OP_16). None if the script holds any other opcode
/// or ends inside a push.
///
/// Kaspa's push-data grammar is Bitcoin's: `0x00` pushes empty data; `0x01..=0x4b` push that
/// many literal bytes; `0x4c`, `0x4d`, `0x4e` (OP_PUSHDATA1, 2, 4) push a 1, 2 or 4-byte
/// little-endian length, then that many bytes.
pub(crate) fn pushes(script: &[u8]) -> Option<Vec<Option<&[u8]>>> {
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let b = script.get(i..i + 2)?;
                i += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            0x4f | 0x51..=0x60 => {
                out.push(None);
                continue;
            }
            _ => return None,
        };
        let data = script.get(i..i.checked_add(len)?)?;
        i += len;
        out.push(Some(data));
    }
    Some(out)
}
