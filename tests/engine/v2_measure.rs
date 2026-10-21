// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Script units, sizes and masses of template v2 (spec/V2.md 9.2 and 9.3), measured in the real
//! engine (rusty-kaspa a41a333, covenants enabled, mainnet parameters). Run with
//! `cargo test -p impulse-engine-tests --test v2_measure -- --nocapture --test-threads 1`; the
//! raw output is committed as docs/measurements/v2-max-n.txt.
//!
//! Method. Units are `used_script_units()` after an unbounded run of each input. KCC-20 tokens are
//! the fixture kcc20.sil and the same source padded by 30 and 60 statements (template lengths
//! 1,461 / 3,771 / 6,081 bytes for maxCovOuts 2, and 199 bytes more for maxCovOuts 3), with
//! distinct covenant IDs. A budget is the smallest covering one
//! (`ComputeBudget::checked_covering_script_units`); `practical_max_n` sets every input to it and
//! runs every input again at that budget. Compute and transient masses are
//! `MassCalculator::calc_non_contextual_masses` of that transaction. Storage mass is
//! `calc_contextual_masses` of the same transaction with every output except the change, and
//! every input except the fee, valued at ceil(p^2 * C * O / cap) (spec/V2.md 6.2; p the UTXO's
//! plurality, O the output count, C the storage mass parameter) and a 10 KAS fee input, once for
//! cap = 100,000 and once for cap = CAP_V2_STORAGE (MIN_V2): the smallest values a builder
//! applying that cap allows, so the largest storage mass it can produce for that shape. Transactions are built by the engine
//! harness (tests/engine/v2_harness.rs) in the layout of spec/V2.md 4.3; the core v2 builders
//! are a later step of I16.

mod harness;
mod v2_harness;
use harness::*;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::mass::{utxo_plurality, ScriptUnits};
use kaspa_txscript::post_toccata_p2sh_sig_scanner;
use v2_harness::*;

/// Padding lines for the three token template lengths of spec/V2.md 9.2.
const PADS: [usize; 3] = [0, 30, 60];
const NS: [usize; 4] = [2, 3, 5, 10];
/// Pre-Toccata standardness cap per dimension (v1 keeps it).
const CAP_100K: u64 = 100_000;
/// MAX_STANDARD_P2SH_SIG_OPS (mining/src/mempool/check_transaction_standard.rs, crate-private).
const MAX_P2SH_SIG_OPS: u64 = 15;
/// NEW_MAX_SIGNATURE_SCRIPT_LEN (consensus/core/src/config/params.rs).
const MAX_SIGNATURE_SCRIPT: usize = 250_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Every leg KCC-20, final settle.
    Tokens,
    /// Every leg KCC-20 but the last, which is KAS; final settle.
    Mixed,
    /// Every leg KCC-20, partial terms (10 lots), a tranche of 3 lots.
    TokensTranche,
    /// As Mixed, tranche of 3 lots.
    MixedTranche,
    /// Every leg KAS (two parties alternating), final settle: the best case.
    Kas,
}

fn setup(shape: Shape, n: usize, auth: bool, pad: usize) -> (Setup, i64) {
    let mut s = Setup::all_tokens(n, auth, pad);
    let mut lots = 1;
    if matches!(shape, Shape::Mixed | Shape::MixedTranche) {
        s.legs[n - 1].asset = Asset::Kas;
        s.legs[n - 1].amount = KAS_AMOUNT * 10;
    }
    if shape == Shape::Kas {
        for leg in s.legs.iter_mut() {
            leg.asset = Asset::Kas;
            leg.amount = KAS_AMOUNT * 10;
        }
    }
    if matches!(shape, Shape::TokensTranche | Shape::MixedTranche) {
        s = s.partial(10, 1);
        lots = 3;
    }
    (s, lots)
}

fn tx_for(w: &WorldV2, shape: Shape, lots: i64) -> TxV2 {
    match shape {
        Shape::TokensTranche | Shape::MixedTranche => w.settle(lots),
        _ => w.settle_final(),
    }
}

// =============================================================================================
// Least squares
// =============================================================================================

/// Solves the normal equations of `rows` (features, value) by Gaussian elimination.
#[allow(clippy::needless_range_loop)] // row operations read two rows at one column
fn least_squares(rows: &[(Vec<f64>, f64)]) -> Vec<f64> {
    let m = rows[0].0.len();
    let mut a = vec![vec![0.0f64; m + 1]; m];
    for (x, y) in rows {
        for r in 0..m {
            for c in 0..m {
                a[r][c] += x[r] * x[c];
            }
            a[r][m] += x[r] * y;
        }
    }
    for col in 0..m {
        let pivot = (col..m)
            .max_by(|&p, &q| a[p][col].abs().total_cmp(&a[q][col].abs()))
            .expect("pivot");
        a.swap(col, pivot);
        assert!(a[col][col].abs() > 1e-9, "singular fit: feature {col}");
        for r in 0..m {
            if r != col {
                let f = a[r][col] / a[col][col];
                for c in col..=m {
                    a[r][c] -= f * a[col][c];
                }
            }
        }
    }
    (0..m).map(|r| a[r][m] / a[r][r]).collect()
}

fn within_tolerance(measured: f64, predicted: f64) -> bool {
    (measured - predicted).abs() <= (0.01 * measured).max(2_000.0)
}

// =============================================================================================
// spec/V2.md 9.2: the per-vault and per-transaction script-unit rules
// =============================================================================================

#[derive(Clone, Debug)]
struct Row {
    shape: Shape,
    pad: usize,
    n: usize,
    k: usize,
    auth: bool,
    tranche: bool,
    i: usize,
    tok_i: bool,
    t_i: usize,
    s: usize,
    units: u64,
}

/// Features of the settle rule (spec/V2.md 9.2, extended by the measured N^2 term of [S10] and
/// the per-kind constants):
///   units(vault i) = SIG * auth + A + B * N + C * N^2 + D * K + E * tok_i + r * T_i + v * S
///                    + F * tranche + G * tranche * tok_i + t * tranche * T_i + H * tranche * N
const SETTLE_TERMS: [&str; 12] = [
    "SIG (auth)",
    "A",
    "B (N)",
    "C (N^2)",
    "D (K)",
    "E (tok_i)",
    "r (T_i)",
    "v (S)",
    "F (tranche)",
    "G (tranche, tok_i)",
    "t (tranche, T_i)",
    "H (tranche, N)",
];

fn settle_features(r: &Row) -> Vec<f64> {
    let b = |x: bool| if x { 1.0 } else { 0.0 };
    let n = r.n as f64;
    vec![
        b(r.auth),
        1.0,
        n,
        n * n,
        r.k as f64,
        b(r.tok_i),
        r.t_i as f64,
        r.s as f64,
        b(r.tranche),
        b(r.tranche && r.tok_i),
        if r.tranche { r.t_i as f64 } else { 0.0 },
        if r.tranche { n } else { 0.0 },
    ]
}

/// The committed settle rule (integers, read from the fit printed by this test). The builders
/// budget every vault input from it plus a margin.
const SETTLE_RULE: [f64; 12] = [
    100_098.0, -13_579.0, 45_585.0, 1_311.0, 2_210.0, 1_380.0, 7.0, 10.0, 159.0, 770.0, 10.0, 7.0,
];

fn rows_for(shape: Shape, pad: usize, n: usize, auth: bool) -> Vec<Row> {
    let (s, lots) = setup(shape, n, auth, pad);
    let w = WorldV2::new(s);
    let tx = tx_for(&w, shape, lots);
    let (t, e) = tx.build(&w);
    let tl: Vec<usize> = (0..n)
        .map(|j| {
            if w.leg(j).is_token() {
                w.leg(j).token().template_len()
            } else {
                0
            }
        })
        .collect();
    let sum: usize = tl.iter().sum();
    (0..n)
        .map(|i| {
            let run = measure(&t, &e, i);
            assert_accepted(&run, &format!("{shape:?} pad {pad} N {n} vault {i}"));
            Row {
                shape,
                pad,
                n,
                k: w.k(),
                auth,
                tranche: matches!(shape, Shape::TokensTranche | Shape::MixedTranche),
                i,
                tok_i: w.leg(i).is_token(),
                t_i: tl[i],
                s: sum,
                units: run.used.0,
            }
        })
        .collect()
}

/// Runs `f` over `jobs` on 8 threads (each thread builds its own worlds).
fn parallel<J: Sync, R: Send>(jobs: &[J], f: impl Fn(&J) -> R + Sync) -> Vec<R> {
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = jobs
            .chunks(jobs.len().div_ceil(8))
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("measure thread"))
            .collect()
    })
}

#[test]
fn per_byte_and_per_leg_units_are_measured() {
    let mut jobs = Vec::new();
    for pad in PADS {
        for n in NS {
            for shape in [
                Shape::Tokens,
                Shape::Mixed,
                Shape::TokensTranche,
                Shape::MixedTranche,
            ] {
                for auth in [true, false] {
                    if auth || pad == 0 {
                        jobs.push((shape, pad, n, auth));
                    }
                }
            }
        }
    }
    let rows: Vec<Row> = parallel(&jobs, |&(shape, pad, n, auth)| {
        rows_for(shape, pad, n, auth)
    })
    .into_iter()
    .flatten()
    .collect();

    let fit = least_squares(
        &rows
            .iter()
            .map(|r| (settle_features(r), r.units as f64))
            .collect::<Vec<_>>(),
    );
    let predict = |coef: &[f64], r: &Row| -> f64 {
        settle_features(r)
            .iter()
            .zip(coef)
            .map(|(x, c)| x * c)
            .sum()
    };
    eprintln!(
        "Settle, script units per vault input ({} points)",
        rows.len()
    );
    eprintln!(
        "| Shape | Pad | N | K | Auth | Vault | Own leg | T_i | S | Units | Rule | Residual |"
    );
    eprintln!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    let mut worst = 0.0f64;
    for r in &rows {
        let p = predict(&SETTLE_RULE, r);
        worst = worst.max((r.units as f64 - p).abs());
        eprintln!(
            "| {:?} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.0} | {:.0} |",
            r.shape,
            r.pad,
            r.n,
            r.k,
            r.auth,
            r.i,
            if r.tok_i { "KCC-20" } else { "KAS" },
            r.t_i,
            r.s,
            r.units,
            p,
            r.units as f64 - p
        );
    }
    eprintln!();
    eprintln!("Least-squares fit of the settle rule (unrounded) and the committed rule:");
    for (name, (f, c)) in SETTLE_TERMS.iter().zip(fit.iter().zip(SETTLE_RULE)) {
        eprintln!("  {name}: fit {f:.3}, committed {c}");
    }
    let worst_fit = rows
        .iter()
        .map(|r| (r.units as f64 - predict(&fit, r)).abs())
        .fold(0.0f64, f64::max);
    eprintln!("  largest residual of the fit: {worst_fit:.0} units; of the committed rule: {worst:.0} units");

    // The transaction total: sum over the N vault inputs of one settle.
    eprintln!();
    eprintln!("Settle, script units of all vault inputs of one transaction:");
    eprintln!("| Shape | Pad | N | Auth | Measured | Rule | Residual |");
    eprintln!("| --- | --- | --- | --- | --- | --- | --- |");
    let mut groups: Vec<(Shape, usize, usize, bool)> =
        rows.iter().map(|r| (r.shape, r.pad, r.n, r.auth)).collect();
    groups.dedup();
    let mut totals = Vec::new();
    for g in groups {
        let members: Vec<&Row> = rows
            .iter()
            .filter(|r| (r.shape, r.pad, r.n, r.auth) == g)
            .collect();
        let measured: u64 = members.iter().map(|r| r.units).sum();
        let rule: f64 = members.iter().map(|r| predict(&SETTLE_RULE, r)).sum();
        eprintln!(
            "| {:?} | {} | {} | {} | {} | {:.0} | {:.0} |",
            g.0,
            g.1,
            g.2,
            g.3,
            measured,
            rule,
            measured as f64 - rule
        );
        totals.push((g, measured, rule));
    }

    for r in &rows {
        assert!(
            within_tolerance(r.units as f64, predict(&fit, r)),
            "the fitted form does not hold at {r:?}: fit {:.0}",
            predict(&fit, r)
        );
        assert!(
            within_tolerance(r.units as f64, predict(&SETTLE_RULE, r)),
            "the committed rule does not hold at {r:?}: rule {:.0}",
            predict(&SETTLE_RULE, r)
        );
    }
    for (g, measured, rule) in totals {
        assert!(
            within_tolerance(measured as f64, rule),
            "total rule at {g:?}"
        );
    }
}

/// Refund units per role and leg kind. The refund has no loop: units do not depend on N.
#[test]
fn refund_units_are_measured() {
    // Rule: units = R0 + RN * N + (a depositor signs) (RP + RPN * N)
    //               + (KCC-20 leg with its token) (RK + R_PER_BYTE * T_i).
    const R0: f64 = 120_004.0;
    const RN: f64 = 748.0;
    const RP: f64 = 663.0;
    const RPN: f64 = 187.0;
    const RK: f64 = 4_290.0;
    const R_PER_BYTE: f64 = 17.0;
    let mut rows = Vec::new();
    for pad in PADS {
        for n in [2usize, 10] {
            let (s, _) = setup(Shape::Mixed, n, true, pad);
            let w = WorldV2::new(s);
            let kas = n - 1;
            let cases: Vec<(usize, Who, i64, Option<i64>, &str)> = vec![
                (0, Who::Party(0), 0, Some(w.leg(0).amount()), "depositor"),
                (
                    0,
                    Who::Party(1),
                    1,
                    Some(w.leg(0).amount()),
                    "another depositor",
                ),
                (
                    0,
                    Who::Authority,
                    n as i64,
                    Some(w.leg(0).amount()),
                    "authority",
                ),
                (0, Who::Party(0), 0, None, "depositor, authorizer alone"),
                (
                    kas,
                    Who::Party(kas % 2),
                    kas as i64,
                    Some(w.leg(kas).amount()),
                    "depositor",
                ),
                (
                    kas,
                    Who::Party(1 - kas % 2),
                    0,
                    Some(w.leg(kas).amount()),
                    "another depositor",
                ),
                (
                    kas,
                    Who::Authority,
                    n as i64,
                    Some(w.leg(kas).amount()),
                    "authority",
                ),
            ];
            for (leg, who, named, held, label) in cases {
                let tx = w.refund_holding(leg, who, named, held);
                let (t, e) = tx.build(&w);
                let run = measure(&t, &e, 0);
                assert_accepted(&run, label);
                let tok = w.leg(leg).is_token();
                let t_i = if tok {
                    w.leg(leg).token().template_len()
                } else {
                    0
                };
                let party = who != Who::Authority;
                rows.push((
                    pad,
                    n,
                    tok,
                    held.is_some() && tok,
                    t_i,
                    label,
                    party,
                    run.used.0,
                ));
            }
        }
    }
    let fit = least_squares(
        &rows
            .iter()
            .map(|&(_, n, _, with_token, t_i, _, party, units)| {
                let w = if with_token { 1.0 } else { 0.0 };
                let p = if party { 1.0 } else { 0.0 };
                let n = n as f64;
                (vec![1.0, n, p, p * n, w, w * t_i as f64], units as f64)
            })
            .collect::<Vec<_>>(),
    );
    eprintln!("Refund, script units of the vault input:");
    eprintln!(
        "| Pad | N | Leg | T_i | Signer | Token in the transaction | Units | Rule | Residual |"
    );
    eprintln!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    let rule = |n: usize, party: bool, with_token: bool, t_i: usize| {
        R0 + RN * n as f64
            + if party { RP + RPN * n as f64 } else { 0.0 }
            + if with_token {
                RK + R_PER_BYTE * t_i as f64
            } else {
                0.0
            }
    };
    let mut worst = 0.0f64;
    for &(pad, n, tok, with_token, t_i, label, party, units) in &rows {
        let p = rule(n, party, with_token, t_i);
        worst = worst.max((units as f64 - p).abs());
        eprintln!(
            "| {pad} | {n} | {} | {t_i} | {label} | {with_token} | {units} | {p:.0} | {:.0} |",
            if tok { "KCC-20" } else { "KAS" },
            units as f64 - p
        );
    }
    eprintln!(
        "  fit: {:.3} + {:.3} * N + (a depositor signs) ({:.3} + {:.3} * N) + (with token) ({:.3} + {:.3} * T_i)",
        fit[0], fit[1], fit[2], fit[3], fit[4], fit[5]
    );
    eprintln!("  committed: {R0} + {RN} * N + (a depositor signs) ({RP} + {RPN} * N) + (with token) ({RK} + {R_PER_BYTE} * T_i); largest residual {worst:.0} units");
    for &(pad, n, _, with_token, t_i, label, party, units) in &rows {
        assert!(
            within_tolerance(units as f64, rule(n, party, with_token, t_i)),
            "refund rule at pad {pad}, N {n}, {label}: {units}"
        );
    }
}

// =============================================================================================
// spec/V2.md 9.3: the practical maximum N
// =============================================================================================

/// CAP_V2 per dimension: the pinned mainnet block limits after Toccata less the D37 reserve.
fn cap_v2() -> (u64, u64, u64) {
    let limits = MAINNET_PARAMS.block_mass_limits().after();
    let less = |x: u64| x - x / 10;
    (
        less(limits.compute),
        less(limits.storage),
        less(limits.transient),
    )
}

fn min_v2(p: u64, outputs: u64, cap_storage: u64) -> u64 {
    (p * p * MAINNET_PARAMS.storage_mass_parameter * outputs).div_ceil(cap_storage)
}

struct Point {
    n: usize,
    inputs: usize,
    outputs: usize,
    vault_bytes: usize,
    max_vault_sigscript: usize,
    max_escrow_sigscript: usize,
    max_vault_units: u64,
    max_vault_budget: u16,
    budgets_total: u64,
    compute: u64,
    transient: u64,
    /// Storage mass with values at the minimum for the 100,000 cap and for CAP_V2_STORAGE.
    storage_100k: u64,
    storage_v2: u64,
    max_sig_ops: u64,
}

/// Storage mass of `t` with every output but the change, and every input but the fee, at the
/// minimum value MIN(p, O) = ceil(p^2 * C * O / cap) for `cap`.
fn storage_at_min(
    t: &kaspa_consensus_core::tx::Transaction,
    e: &[kaspa_consensus_core::tx::UtxoEntry],
    cap: u64,
) -> u64 {
    let outputs = t.outputs.len() as u64;
    let mut st = t.clone();
    let mut se = e.to_vec();
    let last = st.outputs.len() - 1;
    for (o, out) in st.outputs.iter_mut().enumerate() {
        if o != last {
            let p = utxo_plurality(&out.script_public_key, out.covenant.is_some());
            out.value = min_v2(p, outputs, cap);
        }
    }
    st.outputs[last].value = 500_000_000;
    let fee = se.len() - 1;
    for (i, entry) in se.iter_mut().enumerate() {
        entry.amount = if i == fee {
            1_000_000_000
        } else {
            min_v2(
                utxo_plurality(&entry.script_public_key, entry.covenant_id.is_some()),
                outputs,
                cap,
            )
        };
    }
    masses(&st, &se).storage.expect("storage mass computable")
}

/// Builds the shape, sets every input to its covering budget, runs every input at that budget,
/// and returns the sizes and masses.
fn point(shape: Shape, pad: usize, n: usize) -> Point {
    let (s, lots) = setup(shape, n, true, pad);
    let w = WorldV2::new(s);
    let mut tx = tx_for(&w, shape, lots);
    let (t, e) = tx.build(&w);
    let used: Vec<ScriptUnits> = (0..tx.inputs.len())
        .map(|i| measure(&t, &e, i).used)
        .collect();
    for (i, u) in used.iter().enumerate() {
        tx.inputs[i].budget = covering_budget(*u);
    }
    let (t, e) = tx.build(&w);
    for i in 0..tx.inputs.len() {
        assert_accepted(
            &execute(&t, &e, i),
            &format!("{shape:?} pad {pad} N {n} input {i} at its covering budget"),
        );
    }
    let m = masses(&t, &e);

    let (_, cap_storage, _) = cap_v2();
    let storage_100k = storage_at_min(&t, &e, CAP_100K);
    let storage_v2 = storage_at_min(&t, &e, cap_storage);

    let mut max_sig_ops = 0;
    let mut max_vault_sigscript = 0;
    let mut max_escrow_sigscript = 0;
    let mut max_vault_units = 0;
    let mut max_vault_budget = 0;
    for (i, input) in tx.inputs.iter().enumerate() {
        let sig = &t.inputs[i].signature_script;
        if !input.is_plain() {
            let ops = post_toccata_p2sh_sig_scanner(sig, &e[i].script_public_key);
            max_sig_ops = max_sig_ops.max(ops);
            assert!(sig.len() < MAX_SIGNATURE_SCRIPT, "signature script length");
        }
        if input.is_vault() {
            max_vault_sigscript = max_vault_sigscript.max(sig.len());
            if used[i].0 > max_vault_units {
                max_vault_units = used[i].0;
                max_vault_budget = tx.inputs[i].budget;
            }
        } else if !input.is_plain() {
            max_escrow_sigscript = max_escrow_sigscript.max(sig.len());
        }
    }
    Point {
        n,
        inputs: t.inputs.len(),
        outputs: t.outputs.len(),
        vault_bytes: w.vaults[0].bytecode().len(),
        max_vault_sigscript,
        max_escrow_sigscript,
        max_vault_units,
        max_vault_budget,
        budgets_total: tx.inputs.iter().map(|i| i.budget as u64).sum(),
        compute: m.compute,
        transient: m.transient,
        storage_100k,
        storage_v2,
        max_sig_ops,
    }
}

/// A mass dimension: name, its value against 100,000, its value against CAP_V2, the CAP_V2 cap.
type Dim = (&'static str, fn(&Point) -> u64, fn(&Point) -> u64, u64);

#[test]
fn practical_max_n() {
    let (cap_compute, cap_storage, cap_transient) = cap_v2();
    assert_eq!(
        (cap_compute, cap_storage, cap_transient),
        (450_000, 450_000, 900_000),
        "CAP_V2 of spec/V2.md 6.2 (D37) from the pinned mainnet Params"
    );
    eprintln!("practical_max_n: rusty-kaspa a41a333, silverscript v1.0.0, mainnet parameters, authority present, final settle unless named.");
    eprintln!("Caps: 100,000 grams per dimension (pre-Toccata standard; v1 keeps it); CAP_V2 compute {cap_compute}, storage {cap_storage}, transient {cap_transient} (D37).");
    let shapes = [Shape::Tokens, Shape::TokensTranche, Shape::Kas];
    let mut jobs = Vec::new();
    for shape in shapes {
        for pad in PADS {
            if shape == Shape::Kas && pad != 0 {
                continue;
            }
            for n in 2..=MAX_LEGS {
                jobs.push((shape, pad, n));
            }
        }
    }
    let points: Vec<((Shape, usize, usize), Point)> =
        parallel(&jobs, |&(s, pad, n)| ((s, pad, n), point(s, pad, n)));

    // Each dimension against the 100,000 cap and against its CAP_V2 cap. Storage is measured at
    // the minimum values for the cap it is compared with (spec/V2.md 6.2).
    let dims: [Dim; 3] = [
        ("compute", |p| p.compute, |p| p.compute, cap_compute),
        ("storage", |p| p.storage_100k, |p| p.storage_v2, cap_storage),
        ("transient", |p| p.transient, |p| p.transient, cap_transient),
    ];
    let mut summary = Vec::new();
    for shape in shapes {
        for pad in PADS {
            let pts: Vec<&Point> = points
                .iter()
                .filter(|((s, p, _), _)| *s == shape && *p == pad)
                .map(|(_, pt)| pt)
                .collect();
            if pts.is_empty() {
                continue;
            }
            let what = if shape == Shape::Kas {
                "every leg KAS".to_string()
            } else {
                let tl = fixture_token(0).padded(pad).template_len();
                format!(
                    "every leg KCC-20, token templates {tl} and {} bytes",
                    fixture_token(1).padded(pad).template_len()
                )
            };
            eprintln!();
            eprintln!("{shape:?}, {what}:");
            eprintln!("| N | Inputs | Outputs | Vault script (bytes) | Vault sigscript (bytes) | Escrow sigscript (bytes) | Most units of a vault input | Its budget | Budgets, all inputs | Compute mass | Transient mass | Storage mass at the 100,000 minimum | Storage mass at MIN_V2 | Most sig ops of an input |");
            eprintln!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for p in &pts {
                eprintln!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                    p.n,
                    p.inputs,
                    p.outputs,
                    p.vault_bytes,
                    p.max_vault_sigscript,
                    p.max_escrow_sigscript,
                    p.max_vault_units,
                    p.max_vault_budget,
                    p.budgets_total,
                    p.compute,
                    p.transient,
                    p.storage_100k,
                    p.storage_v2,
                    p.max_sig_ops
                );
                assert!(
                    p.max_sig_ops <= MAX_P2SH_SIG_OPS,
                    "sig ops per input above the standard limit"
                );
            }
            let n_max = |f: fn(&Point) -> u64, cap: u64| -> usize {
                pts.iter()
                    .take_while(|p| f(p) <= cap)
                    .map(|p| p.n)
                    .last()
                    .unwrap_or(0)
            };
            let mut overall_100k = usize::MAX;
            let mut overall_v2 = usize::MAX;
            for (name, f100, fv2, cap) in dims {
                let a = n_max(f100, CAP_100K);
                let b = n_max(fv2, cap);
                overall_100k = overall_100k.min(a);
                overall_v2 = overall_v2.min(b);
                eprintln!("  N_max {name}: {a} under 100,000; {b} under CAP_V2 ({cap})");
            }
            eprintln!("  N_max overall: {overall_100k} under 100,000; {overall_v2} under CAP_V2 (measured up to MAX_LEGS = {MAX_LEGS}; 0 means not even N = 2)");
            summary.push((shape, pad, overall_100k, overall_v2));
        }
    }
    eprintln!();
    eprintln!(
        "Summary (shape, padding lines, N_max under 100,000, N_max under CAP_V2): {summary:?}"
    );
    // D38: MAX_LEGS stays 10 only if the worst case at the fixture template length fits CAP_V2
    // at N = 10. This pins the measured answer; if it changes, D38 lowers MAX_LEGS.
    let worst_fixture = summary
        .iter()
        .find(|(s, pad, _, _)| *s == Shape::Tokens && *pad == 0)
        .expect("worst case at the fixture length");
    assert_eq!(
        worst_fixture.3, MAX_LEGS,
        "N_max(CAP_V2) at the fixture length"
    );
}
