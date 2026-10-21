// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! What a v2 settle transaction says about itself (spec/V2.md 4.6 and 6.1): the lots it moved, per
//! leg the quantity and the covenant lineage, and whether a vault continued. Receipts of a partial
//! trade are made from these facts, so a receipt states the quantity settled by the transaction
//! and the cumulative quantity of the lineage against the terms total for every leg.
//!
//! Everything here reads public data of an accepted transaction and the UTXO entries it spent. It
//! holds no key and signs nothing.

use super::terms::ValidatedTermsV2;
use super::verify::verify_spent_input;
use super::{V2Error, VaultV2};
use crate::tx::TxError;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::tx::{Transaction, TransactionOutpoint, UtxoEntry};
use kaspa_consensus_core::Hash;

/// silverscript dispatch tag of `settle` in the ImpulseVault v2 artifact
/// (contracts/compiled/impulse_vault.v2.json; a test pins it to that file).
pub const SETTLE_TAG_V2: [u8; 4] = [0x8f, 0xb0, 0x4e, 0x80];

/// What one leg of a settle moved and where its lineage went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegSettle {
    pub leg: usize,
    /// Amount delivered by this transaction, in the leg's units (`lots * unit`).
    pub settled: u64,
    /// The outpoint the leg's vault input spent.
    pub spent: TransactionOutpoint,
    /// The value in sompi of the vault input (for a KAS leg, the amount the vault held).
    pub held: u64,
    /// The covenant ID the vault input carried (None for a plain vault UTXO).
    pub covenant: Option<Hash>,
    /// The covenant ID of the continuation at output N + leg, if the vault continued.
    pub continuation: Option<Hash>,
}

/// The facts of a v2 settle transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettleFacts {
    /// The `lots` witness, equal in every vault input.
    pub lots: u64,
    /// At least one vault continued (a tranche, or a mixed settle).
    pub tranche: bool,
    pub legs: Vec<LegSettle>,
}

fn mismatch(reason: &'static str) -> V2Error {
    TxError::IpstTermsMismatch { reason }.into()
}

/// The data pushes of a push-only script; small numbers as their value, OpFalse as empty.
fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
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
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        let end = i.checked_add(len)?;
        out.push(script.get(i..end)?.to_vec());
        i = end;
    }
    Some(out)
}

/// The `lots` argument of a signature script that calls `settle(sig authSig, int lots)`: pushes
/// are the 65-byte signature, the integer, the dispatch tag, then the redeem script. None for any
/// other shape, the refund entry included.
pub(crate) fn settle_lots(script: &[u8]) -> Option<u64> {
    let p = pushes(script)?;
    if p.len() != 4 || p[0].len() != 65 || p[2] != SETTLE_TAG_V2 {
        return None;
    }
    let n = &p[1];
    if n.len() > 8 || n.last().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..n.len()].copy_from_slice(n);
    Some(u64::from_le_bytes(buf))
}

/// Reads an accepted (or built) v2 settle transaction of `terms`. `spent[i]` is the UTXO entry
/// input i spent. Checks, in order: the transaction has the N vault inputs; each vault input
/// reveals the v2 vault script of its leg, bound to the entry it spent (`VERIFY_*`, `TEMPLATE_V2_*`);
/// each calls the settle entry with one `lots` (`IPST_TERMS_MISMATCH`); a continuation at output
/// N + i is the same script and carries the covenant ID of the input it continues (`TX_LINEAGE`).
pub fn read_settle(
    terms: &ValidatedTermsV2,
    tx: &Transaction,
    spent: &[UtxoEntry],
) -> Result<SettleFacts, V2Error> {
    let t = terms.terms();
    let n = t.legs.len();
    if tx.inputs.len() < n || spent.len() != tx.inputs.len() {
        return Err(mismatch("the transaction has no vault input for every leg"));
    }
    let mut lots = None;
    for (i, entry) in spent.iter().enumerate().take(n) {
        verify_spent_input(terms, i, &tx.inputs[i], &entry.script_public_key)?;
        let l = settle_lots(&tx.inputs[i].signature_script)
            .ok_or_else(|| mismatch("a vault input does not call the settle entry"))?;
        if lots.is_some_and(|prior| prior != l) {
            return Err(mismatch("the vault inputs name different lots"));
        }
        lots = Some(l);
    }
    let lots = lots.ok_or_else(|| mismatch("no legs"))?;
    if lots < 1 || (t.partial.is_none() && lots != 1) {
        return Err(mismatch("the lots are not those of these terms"));
    }
    let mut legs = Vec::with_capacity(n);
    let mut tranche = false;
    for (i, entry) in spent.iter().enumerate().take(n) {
        let vault_spk = VaultV2::instantiate_existing(terms, i)?.script_public_key();
        let continuation = match tx.outputs.get(n + i) {
            Some(o) if o.script_public_key == vault_spk => {
                let bound = o.covenant.map(|c| c.covenant_id);
                if bound.is_none() || bound != entry.covenant_id {
                    return Err(V2Error::Lineage {
                        reason: "a continuation does not carry the covenant ID of the vault input it continues",
                    });
                }
                tranche = true;
                bound
            }
            _ => None,
        };
        legs.push(LegSettle {
            leg: i,
            settled: lots * t.unit(i),
            spent: tx.inputs[i].previous_outpoint,
            held: entry.amount,
            covenant: entry.covenant_id,
            continuation,
        });
    }
    Ok(SettleFacts {
        lots,
        tranche,
        legs,
    })
}

/// The quantity of one leg after a settle: what the transaction moved, the lineage's cumulative
/// and the terms total, all in the leg's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegQuantity {
    pub leg: usize,
    pub settled: u64,
    pub cumulative: u64,
    pub total: u64,
}

/// The cumulative lots after a settle of `lots` lots on a lineage that had settled `prior_lots`,
/// with per leg the quantities against the terms total. `TX_TRANCHE` if the cumulative lots pass
/// the terms' lot count.
pub fn quantities(
    terms: &ValidatedTermsV2,
    lots: u64,
    prior_lots: u64,
) -> Result<(u64, Vec<LegQuantity>), V2Error> {
    let t = terms.terms();
    let total_lots = t.partial.map_or(1, |p| p.lot_count);
    let cumulative = prior_lots
        .checked_add(lots)
        .filter(|c| *c <= total_lots)
        .ok_or(V2Error::Tranche {
            leg: 0,
            reason: "the cumulative lots pass the lot count of the terms",
        })?;
    let legs = (0..t.legs.len())
        .map(|i| LegQuantity {
            leg: i,
            settled: lots * t.unit(i),
            cumulative: cumulative * t.unit(i),
            total: t.legs[i].asset.amount,
        })
        .collect();
    Ok((cumulative, legs))
}

/// Checks that the vault UTXO a funding transaction made at `output` is a genesis of its own
/// covenant (spec/V2.md 6.1): the output pays leg `leg`'s vault, is bound to a covenant ID, and
/// that ID is `covenant_id(outpoint of the authorizing input, [that output])`. An ID made over
/// several outputs (a shared genesis group) does not match (`TX_LINEAGE`). Returns the ID.
pub fn verify_genesis(
    terms: &ValidatedTermsV2,
    leg: usize,
    funding: &Transaction,
    output: usize,
) -> Result<Hash, V2Error> {
    let o = funding.outputs.get(output).ok_or(V2Error::Lineage {
        reason: "the funding transaction has no such output",
    })?;
    if o.script_public_key != VaultV2::instantiate_existing(terms, leg)?.script_public_key() {
        return Err(V2Error::NotAtVault { leg });
    }
    let binding = o.covenant.ok_or(V2Error::Lineage {
        reason: "the funded output carries no covenant ID",
    })?;
    let input = funding
        .inputs
        .get(binding.authorizing_input as usize)
        .ok_or(V2Error::Lineage {
            reason: "the authorizing input is not in the funding transaction",
        })?;
    let expected = covenant_id(input.previous_outpoint, std::iter::once((output as u32, o)));
    if expected != binding.covenant_id {
        return Err(V2Error::Lineage {
            reason: "the covenant ID does not match the funding outpoint and output",
        });
    }
    Ok(expected)
}
