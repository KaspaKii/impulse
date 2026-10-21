// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Lock time for Impulse transactions (spec/TRANSACTIONS.md, "Lock time"), and the two node
//! rules that decide when a transaction with a lock time or a sequence lock may enter a block.
//!
//! ImpulseVault's `require(tx.daa >= x)` compiles to `OpCheckLockTimeVerify`, a script check:
//! the transaction's lock time must be a DAA score of at least `x`, and the spending input's
//! sequence below the maximum. The node adds its own rule outside the script engine
//! (rusty-kaspa a41a333, `consensus/src/processes/transaction_validator/
//! tx_validation_in_header_context.rs`, `check_tx_is_finalized`): a transaction with a nonzero
//! DAA-score lock time is final in a block only if `lock_time < block DAA score`, unless every
//! input's sequence is the maximum. A transaction locked at `x` therefore enters a block from DAA
//! score `x + 1` on: the effective earliest settle is `earliest_daa + 1`, the effective opening of
//! the depositor's earmarked refund `expiry_daa + 1`.
//!
//! Both node rules live in the `kaspa-consensus` crate, which would bring the node's storage
//! engine into this crate, so they are ported here line for line from the pinned revision, with
//! the same constants from `kaspa_consensus_core::constants` and the same arithmetic.
//! [`check_sequence_lock`] is copied from an internal relative-lock helper by the owner
//! (relicensed, see NOTICE) and checked against a41a333. Impulse sets every input's sequence to
//! [`INPUT_SEQUENCE`], which keeps the lock time in force and imposes no relative lock.

use crate::terms::{FundingMode, Terms};
use kaspa_consensus_core::constants::{
    LOCK_TIME_THRESHOLD, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK,
};
use kaspa_consensus_core::tx::{Transaction, VerifiableTransaction};
use std::fmt;

/// The sequence of every input Impulse builds. Below `MAX_TX_IN_SEQUENCE_NUM`, so the lock time
/// holds and `OpCheckLockTimeVerify` accepts the input; the relative-lock bits are zero, so the
/// sequence lock asks for nothing (`utxo DAA - 1 < any later DAA`).
pub const INPUT_SEQUENCE: u64 = 0;

/// Lock time of a settle or Direct transaction: `earliest_daa`, or 0 (no lock) without one.
/// The node includes it from block DAA score `earliest_daa + 1`.
pub fn settle_lock_time(terms: &Terms) -> u64 {
    terms.earliest_daa.unwrap_or(0)
}

/// Lock time of a refund: `expiry_daa` for the depositor's own refund of an earmarked leg, else
/// 0. The node includes the earmarked depositor refund from block DAA score `expiry_daa + 1`.
pub fn refund_lock_time(terms: &Terms, signer_is_depositor: bool) -> u64 {
    if terms.funding_mode == FundingMode::Earmarked && signer_is_depositor {
        terms.expiry_daa
    } else {
        0
    }
}

/// The first block DAA score at which a transaction with DAA-score lock time `lock_time` (and
/// inputs below the maximum sequence) is final: `lock_time + 1`. None for lock time 0, which is
/// final in every block, and for a timestamp-domain lock time, which Impulse never sets.
pub fn first_block_daa(lock_time: u64) -> Option<u64> {
    if lock_time == 0 || lock_time >= LOCK_TIME_THRESHOLD {
        None
    } else {
        Some(lock_time + 1)
    }
}

/// The node refused a transaction whose lock time has not passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotFinalized {
    /// The first input whose sequence is below the maximum (consensus reports this index).
    pub input_index: usize,
    pub lock_time: u64,
    /// The block DAA score or block time the lock time was compared with.
    pub compared_with: u64,
}

impl fmt::Display for NotFinalized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not finalized: lock time {} is not below {} and input {} is not final",
            self.lock_time, self.compared_with, self.input_index
        )
    }
}

impl std::error::Error for NotFinalized {}

/// Port of rusty-kaspa a41a333 `TransactionValidator::check_tx_is_finalized` with the lock-time
/// type chosen as `get_lock_time_type` chooses it: lock time 0 is final; below
/// `LOCK_TIME_THRESHOLD` it is compared with the block's DAA score, otherwise with its time. The
/// transaction is final when `lock_time < compared value`, or when every input's sequence is
/// `MAX_TX_IN_SEQUENCE_NUM`.
pub fn check_tx_is_finalized(
    tx: &Transaction,
    block_daa_score: u64,
    block_time: u64,
) -> Result<(), NotFinalized> {
    let block_time_or_daa_score = match tx.lock_time {
        0 => return Ok(()),
        t if t < LOCK_TIME_THRESHOLD => block_daa_score,
        _ => block_time,
    };
    if tx.lock_time < block_time_or_daa_score {
        return Ok(());
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        // MAX_TX_IN_SEQUENCE_NUM, written as upstream writes it.
        if input.sequence != u64::MAX {
            return Err(NotFinalized {
                input_index: i,
                lock_time: tx.lock_time,
                compared_with: block_time_or_daa_score,
            });
        }
    }
    Ok(())
}

/// The node refused a transaction whose relative (sequence) lock has not matured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequenceLockError {
    pub input_index: usize,
    pub utxo_daa: u64,
    pub relative_lock: u64,
    pub pov_daa: u64,
}

impl fmt::Display for SequenceLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "input {}: relative lock not met (utxo DAA {} + lock {} - 1 >= point-of-view DAA {})",
            self.input_index, self.utxo_daa, self.relative_lock, self.pov_daa
        )
    }
}

impl std::error::Error for SequenceLockError {}

/// Port of rusty-kaspa a41a333 `TransactionValidator::check_sequence_lock`
/// (`tx_validation_in_utxo_context.rs`). For every input whose sequence does not have
/// `SEQUENCE_LOCK_TIME_DISABLED` set, the relative lock is `sequence & SEQUENCE_LOCK_TIME_MASK`
/// DAA scores counted from the spent UTXO's DAA score; the transaction is refused at
/// `pov_daa_score` while `utxo_daa + lock - 1 >= pov_daa_score`, in signed 64-bit arithmetic as
/// consensus does it. Consensus reports no index; this port reports the first failing input.
pub fn check_sequence_lock(
    tx: &impl VerifiableTransaction,
    pov_daa_score: u64,
) -> Result<(), SequenceLockError> {
    let pov_u64 = pov_daa_score;
    let pov_daa_score: i64 = pov_daa_score as i64;
    for (input_index, (input, entry)) in tx.populated_inputs().enumerate() {
        if input.sequence & SEQUENCE_LOCK_TIME_DISABLED == SEQUENCE_LOCK_TIME_DISABLED {
            continue;
        }
        let relative_lock = (input.sequence & SEQUENCE_LOCK_TIME_MASK) as i64;
        let lock_daa_score = entry.block_daa_score as i64 + relative_lock - 1;
        if lock_daa_score >= pov_daa_score {
            return Err(SequenceLockError {
                input_index,
                utxo_daa: entry.block_daa_score,
                relative_lock: relative_lock as u64,
                pov_daa: pov_u64,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::constants::MAX_TX_IN_SEQUENCE_NUM;

    // The port compares with u64::MAX, as upstream does.
    const _: () = assert!(MAX_TX_IN_SEQUENCE_NUM == u64::MAX);
    use kaspa_consensus_core::tx::{
        PopulatedTransaction, ScriptPublicKey, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    };

    fn tx(lock_time: u64, sequences: &[u64]) -> Transaction {
        let inputs = sequences
            .iter()
            .enumerate()
            .map(|(n, &s)| {
                TransactionInput::new_with_compute_budget(
                    TransactionOutpoint::new([n as u8 + 1; 32].into(), 0),
                    vec![],
                    s,
                    0,
                )
            })
            .collect();
        Transaction::new(
            1,
            inputs,
            vec![TransactionOutput::new(
                1,
                ScriptPublicKey::from_vec(0, vec![]),
            )],
            lock_time,
            Default::default(),
            0,
            vec![],
        )
    }

    #[test]
    fn lock_time_is_final_only_in_a_later_block() {
        let t = tx(1_000, &[INPUT_SEQUENCE, INPUT_SEQUENCE]);
        // lock_time < block DAA: the node rule, so the first block is lock_time + 1.
        assert_eq!(
            check_tx_is_finalized(&t, 1_000, 0),
            Err(NotFinalized {
                input_index: 0,
                lock_time: 1_000,
                compared_with: 1_000
            })
        );
        assert!(check_tx_is_finalized(&t, 999, 0).is_err());
        assert_eq!(check_tx_is_finalized(&t, 1_001, 0), Ok(()));
        assert_eq!(first_block_daa(1_000), Some(1_001));
    }

    #[test]
    fn lock_time_zero_is_always_final() {
        let t = tx(0, &[INPUT_SEQUENCE]);
        assert_eq!(check_tx_is_finalized(&t, 0, 0), Ok(()));
        assert_eq!(first_block_daa(0), None);
    }

    #[test]
    fn maximum_sequences_finalize_a_locked_transaction() {
        // Why Impulse never sets the maximum sequence: the lock time would stop counting at the
        // node, and OpCheckLockTimeVerify refuses such an input.
        let all_max = tx(1_000, &[MAX_TX_IN_SEQUENCE_NUM, MAX_TX_IN_SEQUENCE_NUM]);
        assert_eq!(check_tx_is_finalized(&all_max, 10, 0), Ok(()));
        let one_open = tx(1_000, &[MAX_TX_IN_SEQUENCE_NUM, INPUT_SEQUENCE]);
        assert_eq!(
            check_tx_is_finalized(&one_open, 10, 0)
                .unwrap_err()
                .input_index,
            1
        );
    }

    #[test]
    fn timestamp_domain_lock_time_compares_with_block_time() {
        let t = tx(LOCK_TIME_THRESHOLD + 5, &[INPUT_SEQUENCE]);
        assert!(check_tx_is_finalized(&t, u64::MAX, LOCK_TIME_THRESHOLD + 5).is_err());
        assert_eq!(
            check_tx_is_finalized(&t, 0, LOCK_TIME_THRESHOLD + 6),
            Ok(())
        );
        assert_eq!(first_block_daa(LOCK_TIME_THRESHOLD), None);
        // The threshold itself is a time: compared with the block time, not the DAA score.
        let at = tx(LOCK_TIME_THRESHOLD, &[INPUT_SEQUENCE]);
        assert!(check_tx_is_finalized(&at, u64::MAX, LOCK_TIME_THRESHOLD).is_err());
        assert_eq!(
            check_tx_is_finalized(&at, 0, LOCK_TIME_THRESHOLD + 1),
            Ok(())
        );
        assert_eq!(
            first_block_daa(LOCK_TIME_THRESHOLD - 1),
            Some(LOCK_TIME_THRESHOLD)
        );
    }

    #[test]
    fn impulse_sequence_imposes_no_relative_lock() {
        let t = tx(0, &[INPUT_SEQUENCE]);
        let entry = UtxoEntry::new(1, ScriptPublicKey::from_vec(0, vec![]), 5_000, false, None);
        let populated = PopulatedTransaction::new(&t, vec![entry]);
        // Spendable in the UTXO's own DAA score and after.
        assert_eq!(check_sequence_lock(&populated, 5_000), Ok(()));
        const { assert!(INPUT_SEQUENCE & SEQUENCE_LOCK_TIME_DISABLED == 0) };
        const { assert!(INPUT_SEQUENCE < MAX_TX_IN_SEQUENCE_NUM) };
    }

    #[test]
    fn relative_lock_matures_at_utxo_plus_lock() {
        // utxo + lock - 1 < pov  <=>  pov >= utxo + lock
        let t = tx(0, &[10]);
        let entry = UtxoEntry::new(1, ScriptPublicKey::from_vec(0, vec![]), 1_000, false, None);
        let populated = PopulatedTransaction::new(&t, vec![entry]);
        assert_eq!(
            check_sequence_lock(&populated, 1_009),
            Err(SequenceLockError {
                input_index: 0,
                utxo_daa: 1_000,
                relative_lock: 10,
                pov_daa: 1_009
            })
        );
        assert_eq!(check_sequence_lock(&populated, 1_010), Ok(()));
        // The disable bit skips the input.
        let disabled = tx(0, &[SEQUENCE_LOCK_TIME_DISABLED | 10]);
        let entry = UtxoEntry::new(1, ScriptPublicKey::from_vec(0, vec![]), 1_000, false, None);
        let populated = PopulatedTransaction::new(&disabled, vec![entry]);
        assert_eq!(check_sequence_lock(&populated, 0), Ok(()));
    }

    #[test]
    fn lock_times_follow_the_terms() {
        let mut t = crate::terms::golden::vectors()
            .into_iter()
            .find(|v| v.terms.funding_mode == FundingMode::Earmarked)
            .expect("an earmarked vector")
            .terms;
        t.earliest_daa = Some(7);
        t.expiry_daa = 9;
        assert_eq!(settle_lock_time(&t), 7);
        assert_eq!(refund_lock_time(&t, true), 9);
        assert_eq!(refund_lock_time(&t, false), 0);
        t.earliest_daa = None;
        assert_eq!(settle_lock_time(&t), 0);
        t.funding_mode = FundingMode::Revocable;
        assert_eq!(refund_lock_time(&t, true), 0);
    }
}
