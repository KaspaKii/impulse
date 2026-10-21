// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! ImpulseHashlock measurements in the real engine (I18): script size, script units per vault
//! input, the exact covering compute budget (proven: accepted at it, ExceededCommittedScriptUnits
//! one unit below), the transaction's compute mass, and the signature-operation count of every
//! hashlock and escrow input under the pinned `post_toccata_p2sh_sig_scanner`, which must be at
//! most MAX_STANDARD_P2SH_SIG_OPS = 15 (spec/V2.md sections 3.1 and 11.3).
//!
//!     cargo test -p impulse-engine-tests --test htlc_measure -- --nocapture
//!
//! prints the table of script sizes and script units (spec/V2.md section 11.3).

mod harness;
mod htlc_harness;
use harness::*;
use htlc_harness::*;
use kaspa_txscript::post_toccata_p2sh_sig_scanner;
use kaspa_txscript_errors::TxScriptError;

/// `MAX_STANDARD_P2SH_SIG_OPS` in kaspa-mining (mining/src/mempool/check_transaction_standard.rs
/// at a41a333, crate-private there).
const MAX_STANDARD_P2SH_SIG_OPS: u64 = 15;

struct Row {
    label: String,
    redeem_bytes: usize,
    sigscript_bytes: usize,
    script_units: u64,
    budget: u16,
    sig_ops: u64,
}

/// Measures input `idx`, then proves it passes at exactly the covering budget and is refused
/// with ExceededCommittedScriptUnits one budget unit below.
fn prove(w: &HtlcWorld, spec: &HtlcTx, idx: usize, label: &str) -> Row {
    let (tx, entries) = spec.build(w);
    let unbounded = measure(&tx, &entries, idx);
    assert_accepted(&unbounded, label);
    let budget = covering_budget(unbounded.used);
    let sig_ops = post_toccata_p2sh_sig_scanner(
        &tx.inputs[idx].signature_script,
        &entries[idx].script_public_key,
    );

    let mut at = spec.clone();
    at.inputs[idx].budget = budget;
    let exact = at.run(w, idx);
    assert_accepted(&exact, label);
    assert_eq!(
        exact.used, unbounded.used,
        "{label}: units independent of the budget"
    );
    if budget > 0 {
        let mut below = spec.clone();
        below.inputs[idx].budget = budget - 1;
        let short = below.run(w, idx);
        assert!(
            matches!(
                short.result,
                Err(TxScriptError::ExceededCommittedScriptUnits { .. })
            ),
            "{label}: one budget unit below must exceed the meter, got {:?}",
            short.result
        );
    }
    Row {
        label: label.to_string(),
        redeem_bytes: spec.inputs[idx].redeem_len(),
        sigscript_bytes: tx.inputs[idx].signature_script.len(),
        script_units: unbounded.used.0,
        budget,
        sig_ops,
    }
}

/// Every input of `spec` at its exact covering budget; returns the budgets and compute mass.
fn tight_mass(w: &HtlcWorld, spec: &HtlcTx) -> (Vec<u16>, u64) {
    let (tx, entries) = spec.build(w);
    let mut tight = spec.clone();
    for (n, i) in tight.inputs.iter_mut().enumerate() {
        i.budget = covering_budget(measure(&tx, &entries, n).used);
    }
    tight.assert_all_accepted(w, "tight budgets");
    let (tx, _) = tight.build(w);
    (
        tight.inputs.iter().map(|i| i.budget).collect(),
        compute_mass(&tx),
    )
}

#[test]
fn hashlock_script_units_budgets_and_sig_ops() {
    let w = HtlcWorld::new();
    let (prefix, suffix) = w.vault.template_lens();
    eprintln!(
        "ImpulseHashlock: bytecode {} bytes (template prefix {prefix}, suffix {suffix}), template hash {}",
        w.vault.bytecode().len(),
        w.vault
            .template_hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    let claim = w.claim(&SECRET);
    let seller = w.refund(Role::Seller);
    let buyer = w.refund(Role::Buyer);
    let mut alone = w.refund(Role::Seller);
    alone.inputs.remove(1);
    alone.outputs.remove(1);

    let rows = [
        prove(&w, &claim, 0, "settleWithPreimage (vault, input 0)"),
        prove(
            &w,
            &claim,
            1,
            "claim: escrowed token, transfer leader (input 1)",
        ),
        prove(
            &w,
            &seller,
            0,
            "refund by the seller, with the token (vault, input 0)",
        ),
        prove(
            &w,
            &buyer,
            0,
            "refund by the buyer, with the token (vault, input 0)",
        ),
        prove(
            &w,
            &alone,
            0,
            "refund by the seller, authorizer alone (vault, input 0)",
        ),
        prove(
            &w,
            &buyer,
            1,
            "refund: escrowed token, transfer leader (input 1)",
        ),
    ];
    eprintln!("| Spend | Redeem script (bytes) | Sigscript (bytes) | Script units | Compute budget (units) | Budget mass (grams) | Sig ops |");
    eprintln!("| --- | --- | --- | --- | --- | --- | --- |");
    for r in &rows {
        eprintln!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            r.label,
            r.redeem_bytes,
            r.sigscript_bytes,
            r.script_units,
            r.budget,
            budget_grams(r.budget),
            r.sig_ops
        );
        assert!(
            r.sig_ops <= MAX_STANDARD_P2SH_SIG_OPS,
            "{}: {} sig ops over the standard limit",
            r.label,
            r.sig_ops
        );
    }
    for (label, spec) in [
        ("claim", &claim),
        ("seller refund", &seller),
        ("buyer refund", &buyer),
    ] {
        let (budgets, mass) = tight_mass(&w, spec);
        eprintln!(
            "{label}: budgets {budgets:?}, compute mass {mass} grams; mainnet block compute limit {} grams",
            block_compute_mass_limit()
        );
    }
}
