// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Transaction-level rules every builder applies (spec/TRANSACTIONS.md, "Mass, minimum KAS and
//! fee", "Compute budgets"): the minimum KAS per output derived from KIP-9 storage mass, the
//! standard mass cap, the minimum relay fee, and the compute budget of each spend.
//!
//! Every figure here is derived from the pinned rusty-kaspa a41a333 rules, not measured on a
//! network. I7 confirms them on TN10.

use super::TxError;
use crate::terms::Network;
use kaspa_consensus_core::config::params::{Params, MAINNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::mass::{utxo_plurality, ComputeBudget, MassCalculator, ScriptUnits};
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, TransactionOutput, UtxoEntry};

/// The standard per-transaction cap on each mass dimension, in grams: kaspa-mining's
/// `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA` and kaspa-wallet-core's
/// `MAXIMUM_STANDARD_TRANSACTION_MASS` at a41a333. After Toccata the mempool's only per-transaction
/// cap is the block limit (500,000 grams); Impulse keeps the stricter figure.
pub const STANDARD_MASS_CAP: u64 = 100_000;

/// The most outputs an Impulse transaction has: a settle with KCC-20 cash (four trade outputs and
/// one change output).
pub const MAX_OUTPUTS: u64 = 5;

/// Sompi per squared storage unit: `C * MAX_OUTPUTS / STANDARD_MASS_CAP`, with the KIP-9 storage
/// mass parameter `C` = 10^12. An output of plurality `p` holding at least `p^2` times this adds at
/// most `STANDARD_MASS_CAP / MAX_OUTPUTS` to the storage mass.
pub const SOMPI_PER_STORAGE_UNIT: u64 = STORAGE_MASS_PARAMETER * MAX_OUTPUTS / STANDARD_MASS_CAP;

/// The minimum KAS of a plain KAS output (plurality 1): authorizer, KAS cash leg, change.
/// 50,000,000 sompi (0.5 KAS).
pub const MIN_KAS_OUTPUT: u64 = SOMPI_PER_STORAGE_UNIT;

/// The minimum KAS of a KCC-20 token output (P2SH plus covenant ID, plurality 2): the token's
/// carrier KAS. 200,000,000 sompi (2 KAS).
pub const MIN_KCC20_OUTPUT: u64 = 4 * SOMPI_PER_STORAGE_UNIT;

/// kaspa-mining's `DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE` at a41a333, in sompi per 1,000 grams.
pub const MIN_RELAY_FEE_PER_KILOGRAM: u64 = 100_000;

// Compute budgets. An input's budget lets it use 10,000 script units per unit on top of 9,999
// free units. The engine charges script units for signature checks (100,000 each), for bytes
// that operations other than literal pushes put on the stack (1 per byte) and for hashing
// (Blake2b, 2 per byte), so a spend that reads or rebuilds a KCC-20 token script costs units in
// proportion to the token template's length. The builders size each budget from the template
// lengths in the terms: the floors below (the budgets measured for the fixture tokens, kcc20.sil
// at 1,461 and 1,660 template bytes, with margin), raised by the per-byte rules when a template
// is longer. Measured in the engine (tests/engine/builders.rs, `budgets_cover_every_spend` and
// `budgets_follow_the_template_length`, the second with padded kcc20.sil templates of up to
// about 6,000 bytes); the per-byte figures fit every measurement exactly.

/// Floor of the compute budget of an ImpulseVault `settle` or `refund` input: at most 152,438
/// script units measured for the fixture tokens, covering budget 15.
pub const VAULT_BUDGET: u16 = 20;

/// Floor of the compute budget of a KCC-20 input owned by a vault's script hash (no signature
/// check): at most 12,392 script units measured for the fixture tokens, covering budget 1.
pub const KCC20_VAULT_OWNED_BUDGET: u16 = 3;

/// Floor of the compute budget of a KCC-20 input owned by a public key (one signature check):
/// at most 119,992 script units measured for the fixture tokens, covering budget 11.
pub const KCC20_KEY_OWNED_BUDGET: u16 = 14;

/// Compute budget of a P2PK Schnorr input (one signature check): 100,001 script units, covering
/// budget 10. The script is fixed, so the budget is exact.
pub const P2PK_BUDGET: u16 = 10;

/// Script units of one signature check: `mass_per_sig_op` (1,000 grams on mainnet and testnet)
/// at 100 script units per gram.
pub(crate) const SIGOP_SCRIPT_UNITS: u64 = 100_000;

/// ImpulseVault entry, per byte of a KCC-20 template it reads: measured 17 for the leg's own
/// escrow (read with `readInputStateWithTemplate`, 7, and its delivery validated, 10) and 10
/// for a delivery it only validates; 17 is used for every template.
const VAULT_UNITS_PER_TEMPLATE_BYTE: u64 = 17;

/// ImpulseVault entry, besides its signature check and the template bytes: at most 33,285
/// measured, most of it a settle's [S10] rebuilding and hashing the other vault's redeem script;
/// 45,000 leaves room for state and destination encodings of other lengths.
const VAULT_FIXED_UNITS: u64 = 45_000;

/// KCC-20 `transfer` (kcc20.sil): per template byte, 2 for the spend itself and 4 more for each
/// covenant output the leader validates (measured exactly 6 with one output, 10 with two, and 2
/// for a delegate).
const KCC20_UNITS_PER_TEMPLATE_BYTE: u64 = 2;
const KCC20_UNITS_PER_TEMPLATE_BYTE_PER_OUTPUT: u64 = 4;

/// KCC-20 `transfer`, besides its signature check and the template bytes: at most 4,299
/// measured (two covenant inputs, two outputs); 10,000 plus 1,000 per covenant input and output.
const KCC20_FIXED_UNITS: u64 = 10_000;
const KCC20_UNITS_PER_COVENANT_UTXO: u64 = 1_000;

/// The smallest budget whose allowance covers `units`; budgets do not go past `u16::MAX`, and
/// a budget that large is refused by the compute-mass check (`TX_MASS`), since every budget
/// unit adds 100 grams of compute mass.
fn covering(units: u64) -> u16 {
    ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map_or(u16::MAX, |b| b.value())
}

/// Budget of an ImpulseVault `settle` or `refund` input whose entry reads KCC-20 templates of
/// `template_bytes` bytes in all (prefix plus suffix): the asset template, and the cash template
/// too for KCC-20 cash, on settle; the leg's template on a refund that takes the token; none on
/// a refund without one.
pub(crate) fn vault_budget(template_bytes: u64) -> u16 {
    covering(
        (SIGOP_SCRIPT_UNITS + VAULT_FIXED_UNITS)
            .saturating_add(VAULT_UNITS_PER_TEMPLATE_BYTE.saturating_mul(template_bytes)),
    )
    .max(VAULT_BUDGET)
}

/// Budget of a KCC-20 `transfer` leader input: its template's length, whether its owner is a
/// public key (a signature check), and the covenant inputs and outputs of the transfer.
pub(crate) fn kcc20_leader_budget(
    key_owned: bool,
    template_bytes: u64,
    covenant_inputs: u64,
    covenant_outputs: u64,
) -> u16 {
    let per_byte = KCC20_UNITS_PER_TEMPLATE_BYTE
        .saturating_add(KCC20_UNITS_PER_TEMPLATE_BYTE_PER_OUTPUT.saturating_mul(covenant_outputs));
    let units = (if key_owned { SIGOP_SCRIPT_UNITS } else { 0 } + KCC20_FIXED_UNITS)
        .saturating_add(
            KCC20_UNITS_PER_COVENANT_UTXO
                .saturating_mul(covenant_inputs.saturating_add(covenant_outputs)),
        )
        .saturating_add(per_byte.saturating_mul(template_bytes));
    let floor = if key_owned {
        KCC20_KEY_OWNED_BUDGET
    } else {
        KCC20_VAULT_OWNED_BUDGET
    };
    covering(units).max(floor)
}

/// Budget of a KCC-20 `transfer` delegate input (always key-owned in Impulse: funding).
pub(crate) fn kcc20_delegate_budget(template_bytes: u64) -> u16 {
    covering(
        (SIGOP_SCRIPT_UNITS + KCC20_FIXED_UNITS)
            .saturating_add(KCC20_UNITS_PER_TEMPLATE_BYTE.saturating_mul(template_bytes)),
    )
    .max(KCC20_KEY_OWNED_BUDGET)
}

/// Consensus parameters of the terms' network: mainnet, or testnet (TN10).
pub(crate) fn params(network: Network) -> &'static Params {
    match network {
        Network::Mainnet => &MAINNET_PARAMS,
        Network::Testnet => &TESTNET_PARAMS,
    }
}

/// The minimum KAS an output of this scriptPubKey and covenant binding must hold: plurality
/// squared times [`SOMPI_PER_STORAGE_UNIT`].
pub fn min_output_value(output: &TransactionOutput) -> u64 {
    let p = utxo_plurality(&output.script_public_key, output.covenant.is_some());
    p.saturating_mul(p).saturating_mul(SOMPI_PER_STORAGE_UNIT)
}

/// Refuses an output below its minimum (`TX_BELOW_MIN_KAS`).
pub(crate) fn check_min(output: &TransactionOutput, index: usize) -> Result<(), TxError> {
    let minimum = min_output_value(output);
    if output.value < minimum {
        return Err(TxError::BelowMinKas {
            output: index,
            value: output.value,
            minimum,
        });
    }
    Ok(())
}

/// The masses of a finished transaction (signature scripts at their final size).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Masses {
    pub compute: u64,
    pub transient: u64,
    pub storage: u64,
    /// The mass the relay fee is charged on: compute, or transient normalized to the compute
    /// scale, whichever is larger (kaspa-mining, post-Toccata rule).
    pub fee_mass: u64,
}

/// The masses of `sized` (a transaction whose signature scripts have their final size) with the
/// pinned calculator and the network's parameters.
pub(crate) fn compute_masses(
    sized: &Transaction,
    entries: &[UtxoEntry],
    network: Network,
) -> Masses {
    let params = params(network);
    let calculator = MassCalculator::new_with_consensus_params(params);
    let non_contextual = calculator.calc_non_contextual_masses(sized);
    let populated = PopulatedTransaction::new(sized, entries.to_vec());
    let storage = calculator
        .calc_contextual_masses(&populated)
        .map_or(u64::MAX, |m| m.storage_mass);
    let cofactors = params.mempool_block_mass_cofactors().raw_post();
    let fee_mass = non_contextual
        .compute_mass
        .max(non_contextual.normalized_transient(&cofactors));
    Masses {
        compute: non_contextual.compute_mass,
        transient: non_contextual.transient_mass,
        storage,
        fee_mass,
    }
}

/// Refuses any mass dimension above [`STANDARD_MASS_CAP`] (`TX_MASS`), in the order compute,
/// transient, storage.
pub(crate) fn check_masses(masses: &Masses) -> Result<(), TxError> {
    for (dimension, mass) in [
        ("compute", masses.compute),
        ("transient", masses.transient),
        ("storage", masses.storage),
    ] {
        if mass > STANDARD_MASS_CAP {
            return Err(TxError::Mass {
                dimension,
                mass,
                cap: STANDARD_MASS_CAP,
            });
        }
    }
    Ok(())
}

/// The minimum relay fee for a fee mass, as kaspa-mining computes it: mass times the fee per
/// kilogram, over 1,000, and at least the fee per kilogram.
pub fn min_relay_fee(fee_mass: u64) -> u64 {
    let fee = fee_mass.saturating_mul(MIN_RELAY_FEE_PER_KILOGRAM) / 1000;
    if fee == 0 {
        MIN_RELAY_FEE_PER_KILOGRAM
    } else {
        fee
    }
}
