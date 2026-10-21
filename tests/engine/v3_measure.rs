// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Script size, script units, sig-ops and mass of template v3, measured in the pinned engine
//! (spec/V3-ZK.md 10, 13.3). Run through scripts/measure-v3-units.sh, which commits the output as
//! docs/measurements/v3-zk-units.txt with the date, commit and command. Figures quoted anywhere
//! come from that file only.
//!
//! Method. Script units: `used_script_units()` after an unbounded run of the input. Compute
//! budget: the smallest whose allowance covers the units (`ComputeBudget::checked_covering_script_units`).
//! Every row is the same transaction shape on template v3 and on template v1 with identical
//! terms apart from the v3 fields, so the difference is what the gate costs. Masses:
//! `MassCalculator` under mainnet parameters, every input at its exact covering budget; storage
//! mass from `calc_contextual_masses` over the populated transaction. Sig-ops: the pinned
//! `post_toccata_p2sh_sig_scanner` over each vault input's signature script.

mod harness;
mod v3_common;
use harness::*;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::post_toccata_p2sh_sig_scanner;
use v3_common::*;

/// D63: the per-dimension caps of v3 (V2.md D37).
const CAP_COMPUTE: u64 = 450_000;
const CAP_STORAGE: u64 = 450_000;
const CAP_TRANSIENT: u64 = 900_000;
/// The verification: 14,000,000 + 250,000 * (5 public inputs + 1) script units (V3-ZK.md 3.4).
const VERIFY_UNITS: u64 = 15_500_000;

struct Out(Vec<String>);

impl Out {
    fn line(&mut self, s: impl Into<String>) {
        let s = s.into();
        eprintln!("{s}");
        self.0.push(s);
    }
}

fn v1_twin(w: &World) -> World {
    let mode = w.mode;
    let terms = w.terms.clone();
    World::with(mode, move |t, _| {
        *t = terms.clone();
        t.version = 1;
        t.zk = None;
    })
}

fn units_of(w: &World, spec: &TxSpec, idx: usize) -> u64 {
    let (tx, entries) = spec.build(w);
    let run = measure(&tx, &entries, idx);
    assert_accepted(&run, "measured input");
    run.used.0
}

fn sigops(w: &World, spec: &TxSpec, idx: usize) -> u64 {
    let (tx, entries) = spec.build(w);
    post_toccata_p2sh_sig_scanner(
        &tx.inputs[idx].signature_script,
        &entries[idx].script_public_key,
    )
}

struct Shape {
    label: &'static str,
    fixture: &'static str,
}

#[test]
fn v3_units_sizes_and_mass() {
    let mut o = Out(vec![]);
    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);

    o.line("Template sizes (bytes, with the fixture state):");
    let w0 = world_for("a_list1000");
    let v1_0 = v1_twin(&w0);
    o.line(format!(
        "  template v3 redeem script {} bytes (v1 {}); asset vault signature script {} bytes (v1 {})",
        w0.asset_vault.bytecode().len(),
        v1_0.asset_vault.bytecode().len(),
        {
            let s = w0.settle();
            let (tx, _) = s.build(&w0);
            tx.inputs[0].signature_script.len()
        },
        {
            let s = v1_0.settle();
            let (tx, _) = s.build(&v1_0);
            tx.inputs[0].signature_script.len()
        },
    ));
    o.line("");
    o.line("Settle: script units per vault input, template v3 against template v1 (same terms otherwise)");
    o.line("| Shape | v3 asset vault (with proof) | v1 asset vault | difference | difference minus 15,500,000 | v3 cash vault | v1 cash vault | v3 asset budget (units) | v3 sig-ops (asset, cash) | v1 sig-ops (asset, cash) |");
    o.line("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    let shapes = [
        Shape {
            label: "KAS cash, P2PK owner, list of 1",
            fixture: "a_list1",
        },
        Shape {
            label: "KAS cash, P2PK owner, list of 1,000",
            fixture: "a_list1000",
        },
        Shape {
            label: "KAS cash, P2SH owner, list of 1,000",
            fixture: "c_list1000_p2sh",
        },
        Shape {
            label: "KCC-20 cash, P2PK owner, list of 1,000",
            fixture: "a_list1000_kcc20",
        },
    ];
    let mut masses = vec![];
    let mass_row = |w: &World, label: &'static str, spec: &TxSpec| {
        let (tight, budgets, _) = tighten(w, spec);
        let (tx, entries) = tight.build(w);
        let non = calc.calc_non_contextual_masses(&tx);
        let storage = calc
            .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries))
            .map(|c| c.storage_mass);
        (
            label,
            budgets,
            non.compute_mass,
            non.transient_mass,
            storage,
            tx.inputs.len(),
            tx.outputs.len(),
        )
    };
    for s in &shapes {
        let w = world_for(s.fixture);
        let v1 = v1_twin(&w);
        let (spec3, spec1) = (w.settle(), v1.settle());
        let (a3, a1) = (units_of(&w, &spec3, 0), units_of(&v1, &spec1, 0));
        let (c3, c1) = (units_of(&w, &spec3, 1), units_of(&v1, &spec1, 1));
        let diff = a3 - a1;
        // the cash vault gains the empty-proof check, and its [S10] rebuilds and hashes the longer
        // v3 script (985 bytes more than v1's)
        assert!(
            c3 >= c1 && c3 - c1 < 10_000,
            "{}: cash vault units {c3} vs {c1}",
            s.label
        );
        assert!(
            diff >= VERIFY_UNITS,
            "{}: difference below the verification",
            s.label
        );
        o.line(format!(
            "| {} | {a3} | {a1} | {diff} | {} | {c3} | {c1} | {} | {}, {} | {}, {} |",
            s.label,
            diff - VERIFY_UNITS,
            covering_budget(kaspa_consensus_core::mass::ScriptUnits(a3)),
            sigops(&w, &spec3, 0),
            sigops(&w, &spec3, 1),
            sigops(&v1, &spec1, 0),
            sigops(&v1, &spec1, 1),
        ));
        assert_eq!(
            sigops(&w, &spec3, 0),
            sigops(&v1, &spec1, 0),
            "sig-ops unchanged"
        );
        masses.push(mass_row(&w, s.label, &spec3));
    }
    // Storage mass depends on the KAS values, and the fixtures use dust-sized ones (20,000 sompi
    // on an authorizer). Scale every KAS value of the KCC-20 shape, which holds no cash amount
    // in sompi, by 10,000 (an authorizer of 2 KAS) for a storage figure that says something.
    let w = world_for("a_list1000_kcc20");
    let mut scaled = w.settle();
    for i in scaled.inputs.iter_mut() {
        i.value *= 10_000;
    }
    for out in scaled.outputs.iter_mut() {
        out.value *= 10_000;
    }
    scaled.assert_all_accepted(&w, "KCC-20 settle with every KAS value x 10,000");
    masses.push(mass_row(
        &w,
        "KCC-20 cash, P2PK owner, list of 1,000, every KAS value x 10,000",
        &scaled,
    ));

    o.line("");
    o.line("Settle: transaction masses in grams at exact covering budgets (mainnet parameters)");
    o.line("Storage mass is driven by the KAS values: the fixture rows use dust-sized values (an authorizer holds 20,000 sompi), so their storage mass is not representative and is not asserted; the last row scales every KAS value by 10,000.");
    o.line("| Shape | Budgets per input (units) | Compute | Transient | Storage | Inputs | Outputs | Compute cap 450,000 | Transient cap 900,000 | Storage cap 450,000 | Pre-Toccata standard cap 100,000 |");
    o.line("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    let last = masses.len() - 1;
    for (n, (label, budgets, compute, transient, storage, ins, outs)) in masses.iter().enumerate() {
        let storage_text = storage
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into());
        let storage_cap = if n == last {
            if storage.unwrap_or(0) <= CAP_STORAGE {
                "within"
            } else {
                "OVER"
            }
        } else {
            "not asserted"
        };
        o.line(format!(
            "| {label} | {budgets:?} | {compute} | {transient} | {storage_text} | {ins} | {outs} | {} | {} | {storage_cap} | {} |",
            if *compute <= CAP_COMPUTE { "within" } else { "OVER" },
            if *transient <= CAP_TRANSIENT { "within" } else { "OVER" },
            if *compute < PRE_TOCCATA_STANDARD_MASS_CAP { "within" } else { "over" },
        ));
        assert!(
            *compute <= CAP_COMPUTE && *transient <= CAP_TRANSIENT,
            "{label} exceeds a D63 cap"
        );
        if n == last {
            assert!(
                storage.unwrap_or(0) <= CAP_STORAGE,
                "{label} exceeds the storage cap"
            );
        }
    }
    o.line(format!(
        "Mainnet block compute mass limit: {} grams. Grams per compute budget unit: {}.",
        block_compute_mass_limit(),
        budget_grams(1)
    ));

    o.line("");
    o.line("Refund: script units per vault input, template v3 against template v1 (random throwaway keys)");
    o.line("| Refund | v3 units | v1 units | difference |");
    o.line("| --- | --- | --- | --- |");
    let refund_world = |v3: bool| {
        World::with(Mode::new(true, CASH_KCC20, EARMARKED), move |t, _| {
            if !v3 {
                t.version = 1;
                t.zk = None;
            }
        })
    };
    let (r3, r1) = (refund_world(true), refund_world(false));
    for (label, leg, role) in [
        ("asset leg, depositor", ASSET_LEG, Role::Seller),
        ("asset leg, counterparty", ASSET_LEG, Role::Buyer),
        ("asset leg, authority", ASSET_LEG, Role::Authority),
        ("cash leg, depositor", CASH_LEG, Role::Buyer),
    ] {
        let (u3, u1) = (
            units_of(&r3, &r3.refund(leg, role), 0),
            units_of(&r1, &r1.refund(leg, role), 0),
        );
        o.line(format!(
            "| {label} | {u3} | {u1} | {} |",
            u3 as i64 - u1 as i64
        ));
    }
    o.line("");
    o.line("Proof gate: the precompile's fixed cost is 14,000,000 units; the fragment verifies with 5 public inputs, 6 gamma_abc points at 250,000 each (V3-ZK.md 3.2, 3.4).");

    if let Some(path) = std::env::var_os("IMPULSE_V3_UNITS_OUT") {
        std::fs::write(&path, o.0.join("\n") + "\n").expect("write measurements");
    }
}
