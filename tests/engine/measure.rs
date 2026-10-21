// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Script size, script units and compute mass per entry and mode, for the I3 Report.
//! Run with `cargo test -p impulse-engine-tests --test measure -- --nocapture`.
//!
//! Method: script units come from `used_script_units()` after an unbounded run. The compute
//! budget is the smallest whose allowance covers them (`ComputeBudget::checked_covering_script_units`);
//! each row is then re-run with exactly that budget committed (accepted, same units) and with one
//! budget unit less (refused, ExceededCommittedScriptUnits). Transaction compute mass is
//! `MassCalculator::calc_non_contextual_masses` under mainnet parameters, with every input at its
//! exact covering budget, printed against the pre-Toccata 100,000-gram standardness cap.

mod harness;
use harness::*;

fn kind(cash: u8) -> &'static str {
    match cash {
        CASH_KAS => "KAS cash",
        CASH_KCC20 => "KCC-20 cash",
        _ => "external cash",
    }
}

fn role(r: Role) -> &'static str {
    match r {
        Role::Seller => "depositor",
        Role::Buyer => "counterparty",
        Role::Authority => "authority",
        Role::Stranger => "stranger",
    }
}

fn funding(f: u8) -> &'static str {
    if f == REVOCABLE {
        "revocable"
    } else {
        "earmarked"
    }
}

/// Measures every vault and token input of `spec`, then the whole transaction at tight budgets.
fn measure_tx(
    w: &World,
    spec: &TxSpec,
    label: &str,
    rows: &mut Vec<Measure>,
    masses: &mut Vec<String>,
) {
    for (n, i) in spec.inputs.iter().enumerate() {
        let what = match i.spend {
            Spend::Plain => continue,
            Spend::Settle { .. } => format!("settle, input {n}"),
            Spend::Refund { .. } => format!("refund, input {n}"),
            Spend::SettleV4 { .. } => format!("settle (v4), input {n}"),
            Spend::RefundV4 { .. } => format!("refund (v4), input {n}"),
            Spend::Kcc20Leader { .. } | Spend::Kcc20Delegate { .. } => {
                format!("KCC-20 transfer, input {n}")
            }
        };
        rows.push(prove_budget(w, spec, n, &format!("{label}: {what}")));
    }
    let (_, budgets, mass) = tighten(w, spec);
    assert!(
        mass < PRE_TOCCATA_STANDARD_MASS_CAP,
        "{label}: compute mass {mass} reaches the pre-Toccata standard cap"
    );
    masses.push(format!(
        "| {label} | {} | {} | {budgets:?} | {mass} | {:.1}% |",
        spec.inputs.len(),
        spec.outputs.len(),
        100.0 * mass as f64 / PRE_TOCCATA_STANDARD_MASS_CAP as f64
    ));
}

#[test]
fn sizes_units_and_mass_per_entry_and_mode() {
    let mut rows = Vec::new();
    let mut masses = Vec::new();

    for authority in [true, false] {
        for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
            if cash == CASH_EXTERNAL && !authority {
                continue; // refused: external cash settles only through an authority ([S7])
            }
            let w = World::new(Mode::new(authority, cash, REVOCABLE));
            let who = if authority {
                "authority"
            } else {
                "self-settling"
            };
            let label = format!("Settle, {who}, {}", kind(cash));
            measure_tx(&w, &w.settle(), &label, &mut rows, &mut masses);
        }
    }

    for f in [REVOCABLE, EARMARKED] {
        let w = World::new(Mode::new(true, CASH_KCC20, f));
        for r in [Role::Seller, Role::Buyer, Role::Authority] {
            let label = format!("Refund asset leg, {}, {}", role(r), funding(f));
            measure_tx(&w, &w.refund(ASSET_LEG, r), &label, &mut rows, &mut masses);
        }
    }
    let w = World::new(Mode::new(true, CASH_KAS, EARMARKED));
    measure_tx(
        &w,
        &w.refund(CASH_LEG, Role::Buyer),
        "Refund KAS cash leg, depositor, earmarked",
        &mut rows,
        &mut masses,
    );
    let w = World::new(Mode::new(true, CASH_KCC20, EARMARKED));
    measure_tx(
        &w,
        &w.refund(CASH_LEG, Role::Seller),
        "Refund KCC-20 cash leg, counterparty, earmarked",
        &mut rows,
        &mut masses,
    );
    let mut alone = w.refund(ASSET_LEG, Role::Seller);
    alone.inputs.remove(1);
    alone.outputs.remove(1);
    measure_tx(
        &w,
        &alone,
        "Refund authorizer without token, depositor, earmarked",
        &mut rows,
        &mut masses,
    );

    eprintln!();
    print_rows(&rows);
    eprintln!();
    eprintln!(
        "| Transaction | Inputs | Outputs | Budgets per input | Compute mass (grams) | Of pre-Toccata cap {PRE_TOCCATA_STANDARD_MASS_CAP} |"
    );
    eprintln!("| --- | --- | --- | --- | --- | --- |");
    for m in &masses {
        eprintln!("{m}");
    }
    eprintln!(
        "Mainnet block compute mass limit: {} grams. Grams per compute budget unit: {}.",
        block_compute_mass_limit(),
        budget_grams(1)
    );
}

/// Script units of each settle vault input with one fee input and with fee inputs up to the
/// bound of 12 inputs, against the builders' rule (spec/TRANSACTIONS.md, "Compute budgets":
/// 100,000 + 45,000 + 17 per byte of each KCC-20 template the entry reads), I26. Run with
/// `cargo test -p impulse-engine-tests --test measure units_at_the_bound -- --nocapture`;
/// `IMPULSE_VAULT_SIL` points it at another source for a comparison.
#[test]
fn settle_units_at_the_bound_stay_within_the_builder_rule() {
    const MAX_INPUTS: usize = 12;
    let bytes = |t: Token, s: Kcc20State| {
        let (p, q) = t.compile(s).template_lens();
        (p + q) as u64
    };
    eprintln!("| Settle | Vault input | 1 fee input | {MAX_INPUTS} inputs | Units per extra input | Builder rule |");
    eprintln!("| --- | --- | --- | --- | --- | --- |");
    for authority in [true, false] {
        for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
            if cash == CASH_EXTERNAL && !authority {
                continue;
            }
            let w = World::new(Mode::new(authority, cash, REVOCABLE));
            let base = w.settle();
            let mut full = base.clone();
            while full.inputs.len() < MAX_INPUTS {
                full.inputs.push(In::plain(FEE_VALUE));
            }
            let extra = (full.inputs.len() - base.inputs.len()) as u64;
            let mut read = bytes(ASSET_TOKEN, w.asset_escrow_state());
            if cash == CASH_KCC20 {
                read += bytes(CASH_TOKEN, w.cash_escrow_state());
            }
            let rule = 100_000 + 45_000 + 17 * read;
            let vaults: &[usize] = if cash == CASH_EXTERNAL { &[0] } else { &[0, 1] };
            for &n in vaults {
                let units = |spec: &TxSpec| {
                    let (tx, entries) = spec.build(&w);
                    let run = measure(&tx, &entries, n);
                    assert_accepted(&run, &format!("{}: input {n}", spec.inputs.len()));
                    run.used.0
                };
                let (one, at_bound) = (units(&base), units(&full));
                assert!(at_bound <= rule, "authority {authority}, cash {cash}, input {n}: {at_bound} units over the rule {rule}");
                eprintln!(
                    "| {}, {} | {n} | {one} | {at_bound} | {} | {rule} |",
                    if authority {
                        "authority"
                    } else {
                        "self-settling"
                    },
                    kind(cash),
                    (at_bound - one) / extra
                );
            }
        }
    }
}
