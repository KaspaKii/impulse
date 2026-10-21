// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Parity suite (I10): Impulse against the Solana Foundation DvP program, pinned in
//! `solana-dvp.json`. That file enumerates every Solana instruction, error code and README edge
//! case. Each item without a `pending` field is answered by exactly one test in
//! `instructions.rs`, `errors.rs` or `edges.rs`; an item with one names the later increment that
//! answers it, and may have one test tagged `partial` for the part merged code can express.
//! `scripts/gen-parity.sh` joins the mapping, the tags below and the test results into PARITY.md.
//!
//! Tag format, read by `tests/parity/gen_parity.py`. Every `#[test]` in the three item files is
//! preceded by exactly two doc lines:
//!
//! ```text
//! /// parity: <ID> <equivalent|impossible|divergent|uncovered|partial>
//! /// <one-line rationale: the Impulse behaviour, naming the check behind it>
//! ```
//!
//! - equivalent: Impulse has a behaviour that answers the Solana item; the test demonstrates it.
//! - impossible: the Solana case cannot arise in Impulse by construction; the test demonstrates
//!   the construction in Impulse's own code that rules it out.
//! - divergent: Impulse answers the item differently; the test pins the Impulse behaviour and the
//!   rationale states the difference.
//! - uncovered: Impulse has no check for the risk the item guards against; the test pins what
//!   Impulse does check and the rationale names the risk left.
//! - partial: the item is pending in a later increment; the test passes for the part merged code
//!   can express.
//!
//! A code of any family of spec/ERRORS.md (`TERMS_`, `TEMPLATE_`, `TX_`, `VERIFY_` and the rest)
//! in a rationale is a refusal or a report of off-chain software, which the contract does not
//! repeat: such a row is `equivalent` only if it also cites a contract tag that refuses on chain,
//! or its item is marked `client_side` in the mapping (Solana's own answer is a check its clients
//! run). Every cited tag must fail the row's test when its require is replaced by `require(true)`
//! (`tests/parity/mutation-run.json`, written by `--mutate-contract`). The builders run the
//! template embedded in impulse-core, which a mutant contract does not change,
//! so a row that cites a tag also checks it through the harness, against the source under test.
//!
//! Every refusal a test asserts stands beside an accepted control that differs only in the
//! fault (`assert_flips` for engine runs). Engine tests run ImpulseVault in the real Kaspa script
//! engine through the I3 harness, reused read-only; core tests run impulse-core's terms and
//! template code. Keys: the harness's throwaway keypairs only, erased on drop (rule 1, docs/ENGINEERING-RULES.md
//! exception); nothing here writes, prints or stores a private key.
//!
//! The tests in this file are not parity items: they check the mapping and spec/ERRORS.md.

#[path = "../engine/harness.rs"]
mod harness;

mod catalogue;
mod common;
mod edges;
mod errors;
mod htlc;
mod instructions;
mod linked;
#[path = "../engine/real_terms.rs"]
mod real_terms;
mod trade;
mod verify_world;

use harness::repo_path;
use std::collections::BTreeSet;

/// The verdicts a tag may carry (format above).
const VERDICTS: [&str; 5] = [
    "equivalent",
    "impossible",
    "divergent",
    "uncovered",
    "partial",
];

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn mapping() -> serde_json::Value {
    serde_json::from_str(&read("tests/parity/solana-dvp.json")).expect("solana-dvp.json parses")
}

/// The items of one kind, in file order.
fn items<'a>(m: &'a serde_json::Value, kind: &str) -> Vec<&'a serde_json::Value> {
    m["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|i| i["kind"] == kind)
        .collect()
}

/// `(id, verdict)` of every tagged test in the item files, with the count of `#[test]`s.
fn tags() -> (Vec<(String, String)>, usize) {
    let mut found = Vec::new();
    let mut tests = 0;
    for file in ["instructions.rs", "errors.rs", "edges.rs"] {
        let text = read(&format!("tests/parity/{file}"));
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            if *line != "#[test]" {
                continue;
            }
            tests += 1;
            let tag = n
                .checked_sub(2)
                .and_then(|t| lines[t].strip_prefix("/// parity: "))
                .unwrap_or_else(|| panic!("{file}:{}: #[test] without a parity tag", n + 1));
            let rationale = lines[n - 1].strip_prefix("/// ").unwrap_or("");
            assert!(
                !rationale.is_empty() && !rationale.starts_with("parity:"),
                "{file}:{}: the tag needs a one-line rationale",
                n + 1
            );
            let (id, verdict) = tag.split_once(' ').expect("<ID> <verdict>");
            found.push((id.to_string(), verdict.to_string()));
        }
    }
    (found, tests)
}

/// The mapping enumerates the six instructions and the 24 error codes of the pinned program,
/// one row each, in code order; edge cases are numbered without gaps; every row cites a pinned
/// file; every row without `pending` has exactly one tagged test, not partial; a pending row has
/// none, or one tagged partial.
#[test]
fn mapping_enumerates_every_instruction_error_and_edge_case() {
    let m = mapping();
    let commit = m["source"]["commit"].as_str().expect("commit");
    assert!(commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()));
    let pinned: BTreeSet<&str> = m["source"]["sha256"]
        .as_object()
        .expect("sha256 pins")
        .keys()
        .map(String::as_str)
        .collect();

    for (kind, prefix, count, width) in [
        ("instruction", "IX-", 6, 1),
        ("error", "ERR-", 24, 2),
        ("edge_case", "EDGE-", 0, 2),
    ] {
        let rows = items(&m, kind);
        if count > 0 {
            assert_eq!(rows.len(), count, "{kind} rows");
        } else {
            assert!(!rows.is_empty(), "{kind} rows");
        }
        for (n, row) in rows.iter().enumerate() {
            let number = if kind == "edge_case" { n + 1 } else { n };
            assert_eq!(row["id"], format!("{prefix}{number:0width$}"), "{kind} ids");
            if kind != "edge_case" {
                assert_eq!(row["code"], n, "{kind} codes in order");
            }
            for key in ["solana", "summary"] {
                assert!(row[key].as_str().is_some_and(|s| !s.is_empty()));
            }
            let cites = row["cite"].as_array().expect("cite");
            assert!(!cites.is_empty(), "{}: no citation", row["id"]);
            for cite in cites {
                let (file, line) = cite.as_str().unwrap().rsplit_once(':').unwrap();
                assert!(pinned.contains(file), "{}: {file} is not pinned", row["id"]);
                assert!(line.parse::<u32>().is_ok_and(|l| l > 0));
            }
        }
    }

    let (tags, tests) = tags();
    assert_eq!(tags.len(), tests, "every item test is tagged");
    let rows = m["items"].as_array().unwrap();
    for row in rows {
        let id = row["id"].as_str().unwrap();
        let verdicts: Vec<&str> = tags
            .iter()
            .filter(|(t, _)| t == id)
            .map(|(_, v)| v.as_str())
            .collect();
        match row.get("pending") {
            Some(_) => assert!(
                verdicts.is_empty() || verdicts == ["partial"],
                "{id}: pending, so no test or one partial test: {verdicts:?}"
            ),
            None => assert!(
                verdicts.len() == 1 && verdicts[0] != "partial",
                "{id}: one test, not partial: {verdicts:?}"
            ),
        }
    }
    for (id, verdict) in &tags {
        assert!(rows.iter().any(|r| r["id"] == id.as_str()), "{id}: no row");
        assert!(
            VERDICTS.contains(&verdict.as_str()),
            "{id}: verdict {verdict}"
        );
    }
}

/// The code column of the markdown table that follows `heading` (up to the next heading).
fn table_codes(doc: &str, heading: &str, column: usize) -> Vec<String> {
    let section = doc
        .split_once(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading}"))
        .1;
    let section = section.split("\n#").next().unwrap();
    section
        .lines()
        .filter(|l| l.starts_with('|'))
        .skip(2)
        .map(|l| {
            let cell = l.split('|').nth(column + 1).expect("column").trim();
            cell.trim_matches('`').to_string()
        })
        .collect()
}

/// The trailing parenthetical notes on which spec/ERRORS.md and a per-layer spec word a code's
/// meaning differently, frozen as (code, the note in ERRORS.md, the note in the spec), "" for
/// none. Everything else in a meaning is compared in full, so a changed meaning fails; so does a
/// changed note, a note not listed here, and an entry whose two texts now agree.
const NOTE_DIFFS: [(&str, &str, &str); 12] = [
    ("TERMS_PARTIES_NOT_DISTINCT", "(narrowed in I4, see below)", ""),
    ("TERMS_ASSET_KIND_UNSUPPORTED", "(decision D13)", ""),
    (
        "TERMS_AUTHORITY_IS_PARTY",
        "",
        "(added in I4; until I4, `TERMS_PARTIES_NOT_DISTINCT`)",
    ),
    ("TERMS_SAME_COVENANT", "", "(added in I4)"),
    (
        "CLI_URI_MALFORMED",
        "(the URI is not of the exact form: address, amount, impulse hash)",
        "",
    ),
    (
        "CLI_URI_TERMS_HASH_MISMATCH",
        "(the impulse parameter is not the terms hash)",
        "",
    ),
    (
        "CLI_URI_ADDRESS_MISMATCH",
        "(the address is neither of the terms' vault addresses)",
        "",
    ),
    (
        "CLI_URI_LEG_NOT_KAS",
        "(the vault's leg is not native KAS)",
        "",
    ),
    (
        "CLI_URI_AMOUNT_MISMATCH",
        "(the amount is not the leg amount exactly)",
        "",
    ),
    (
        "WATCH_STRAY_DEPOSIT",
        "(an output pays the cash-vault script of external-cash terms, which Impulse never instantiates; no recovery builder, decision D14)",
        "",
    ),
    (
        "WATCH_FUNDING_NOT_EXACT",
        "(a UTXO at the vault that is not the leg amount; only an exact UTXO can settle)",
        "",
    ),
    (
        "WATCH_SPEND_UNCLASSIFIED",
        "(a spend of a vault UTXO the watcher cannot read as a settle or refund; never reported as one)",
        "",
    ),
];

/// A meaning split into its text and its one trailing parenthetical note ("" if none).
fn split_note(meaning: &str) -> (&str, &str) {
    match meaning.rfind(" (") {
        Some(at) if meaning.ends_with(')') => (&meaning[..at], &meaning[at + 1..]),
        _ => (meaning, ""),
    }
}

/// The meaning of `code` in spec/ERRORS.md and in its per-layer spec is the same text, except
/// for a trailing note frozen in `NOTE_DIFFS`.
fn assert_same_meaning(code: &str, errors: &str, spec: &str) {
    let frozen = NOTE_DIFFS.iter().find(|(c, _, _)| *c == code);
    if errors == spec {
        assert!(
            frozen.is_none(),
            "{code}: the two meanings now agree, so drop it from NOTE_DIFFS"
        );
        return;
    }
    let Some((_, errors_note, spec_note)) = frozen else {
        panic!(
            "{code}: meaning in spec/ERRORS.md ({errors:?}) and in the per-layer spec ({spec:?}) differ; make them agree, or freeze a differing trailing note in NOTE_DIFFS"
        )
    };
    let ((errors_text, e), (spec_text, s)) = (split_note(errors), split_note(spec));
    assert_eq!(errors_text, spec_text, "{code}: meaning before the note");
    assert_eq!(
        (e, s),
        (*errors_note, *spec_note),
        "{code}: the trailing notes are not the frozen ones"
    );
}

/// (code, raised by, meaning) of every row of the table after `heading`, whose code column is
/// `code`, followed by the raised-by and meaning columns.
fn code_rows(doc: &str, heading: &str, code: usize) -> Vec<(String, String, String)> {
    let codes = table_codes(doc, heading, code);
    let raised = table_codes(doc, heading, code + 1);
    let meaning = table_codes(doc, heading, code + 2);
    codes
        .into_iter()
        .zip(raised)
        .zip(meaning)
        .map(|((c, r), m)| (c, r, m))
        .collect()
}

/// The two tables list the same codes in the same order, with the same raised-by and meaning.
fn assert_tables_agree(
    spec: &[(String, String, String)],
    errors: &[(String, String, String)],
    label: &str,
) {
    assert_eq!(spec.len(), errors.len(), "{label}: rows");
    for (s, e) in spec.iter().zip(errors) {
        assert_eq!(s.0, e.0, "{label}: code");
        assert_eq!(s.1, e.1, "{}: raised by", s.0);
        assert_same_meaning(&s.0, &e.2, &s.2);
    }
}

/// spec/ERRORS.md lists exactly the frozen code lists, in order, and the per-layer specs list
/// the same codes in the same order with the same raised-by and meaning text. A code retired
/// before main is listed as such and is not in the code.
#[test]
fn errors_md_lists_every_stable_code() {
    use impulse_core::template::TEMPLATE_ERROR_CODES;
    use impulse_core::terms::TERMS_ERROR_CODES;
    use impulse_core::v2::{TEMPLATE_V2_ERROR_CODES, TERMS_V2_ERROR_CODES};
    let errors = read("spec/ERRORS.md");
    let terms = table_codes(&errors, "## TERMS_ codes", 1);
    let template = table_codes(&errors, "## TEMPLATE_ codes", 1);
    // v0.2 appends its codes at the end of both families (spec/V2.md 8.1 and 8.2, I16).
    assert_eq!(
        terms,
        [&TERMS_ERROR_CODES[..], &TERMS_V2_ERROR_CODES[..]].concat(),
        "ERRORS.md TERMS_ codes"
    );
    assert_eq!(
        template,
        [&TEMPLATE_ERROR_CODES[..], &TEMPLATE_V2_ERROR_CODES[..]].concat(),
        "ERRORS.md TEMPLATE_ codes"
    );
    let numbers = table_codes(&errors, "## TERMS_ codes", 0);
    assert!(numbers
        .iter()
        .enumerate()
        .all(|(n, s)| *s == (n + 1).to_string()));
    let numbers = table_codes(&errors, "## TEMPLATE_ codes", 0);
    assert!(numbers
        .iter()
        .enumerate()
        .all(|(n, s)| *s == (n + 1).to_string()));

    let terms_rows = code_rows(&errors, "## TERMS_ codes", 1);
    let template_rows = code_rows(&errors, "## TEMPLATE_ codes", 1);
    let (terms_v1, terms_v2) = terms_rows.split_at(TERMS_ERROR_CODES.len());
    let (template_v1, template_v2) = template_rows.split_at(TEMPLATE_ERROR_CODES.len());
    let v2 = read("spec/V2.md");
    assert_tables_agree(
        &code_rows(&read("spec/ENCODING.md"), "## Error codes", 0),
        terms_v1,
        "ENCODING.md and ERRORS.md",
    );
    assert_tables_agree(
        &code_rows(&v2, "### 8.1 TERMS_", 1),
        terms_v2,
        "V2.md 8.1 and ERRORS.md",
    );
    assert_tables_agree(
        &code_rows(&read("spec/TEMPLATE.md"), "## Error codes", 0),
        template_v1,
        "TEMPLATE.md and ERRORS.md",
    );
    assert_tables_agree(
        &code_rows(&v2, "### 8.2 TEMPLATE_", 1),
        template_v2,
        "V2.md 8.2 and ERRORS.md",
    );

    let retired = table_codes(&errors, "## Retired and changed codes", 0);
    assert!(retired.contains(&"TEMPLATE_SAME_COVENANT".to_string()));
    assert!(retired.contains(&"TERMS_PARTIES_NOT_DISTINCT".to_string()));
    assert!(!TEMPLATE_ERROR_CODES.contains(&"TEMPLATE_SAME_COVENANT"));
}

/// spec/ERRORS.md lists exactly the tagged requires of contracts/impulse_vault.sil.
#[test]
fn errors_md_lists_every_contract_refusal() {
    let source = read("contracts/impulse_vault.sil");
    let in_contract: BTreeSet<String> = source
        .lines()
        .filter(|l| l.trim_start().starts_with("require("))
        .filter_map(|l| l.rsplit_once("// ["))
        .map(|(_, tag)| format!("[{}", tag.trim_end()))
        .collect();
    let errors = read("spec/ERRORS.md");
    let mut listed = table_codes(&errors, "### settle", 0);
    listed.extend(table_codes(&errors, "### refund", 0));
    let listed_set: BTreeSet<String> = listed.iter().cloned().collect();
    assert_eq!(listed.len(), listed_set.len(), "a tag listed twice");
    assert_eq!(in_contract.len(), 37, "tagged requires in the contract");
    assert_eq!(listed_set, in_contract);
}

/// spec/ERRORS.md lists exactly the tagged requires of contracts/impulse_vault_v2.sil, settle
/// tags under "### Template v2: settle" and refund tags under "### Template v2: refund"
/// (spec/V2.md 8.6).
#[test]
fn errors_md_lists_every_v2_contract_refusal() {
    let source = read("contracts/impulse_vault_v2.sil");
    let refund_at = source.find("entry refund(").expect("refund entry");
    let tags = |part: &str| -> BTreeSet<String> {
        part.lines()
            .filter(|l| l.trim_start().starts_with("require("))
            .filter_map(|l| l.rsplit_once("// ["))
            .map(|(_, tag)| format!("[{}", tag.trim_end()))
            .collect()
    };
    let settle = tags(&source[..refund_at]);
    let refund = tags(&source[refund_at..]);
    let errors = read("spec/ERRORS.md");
    let listed_settle = table_codes(&errors, "### Template v2: settle", 0);
    let listed_refund = table_codes(&errors, "### Template v2: refund", 0);
    let set = |v: &[String]| -> BTreeSet<String> { v.iter().cloned().collect() };
    assert_eq!(
        listed_settle.len(),
        set(&listed_settle).len(),
        "a settle tag listed twice"
    );
    assert_eq!(
        listed_refund.len(),
        set(&listed_refund).len(),
        "a refund tag listed twice"
    );
    assert_eq!(
        (settle.len(), refund.len()),
        (37, 25),
        "tagged requires in template v2"
    );
    assert_eq!(set(&listed_settle), settle);
    assert_eq!(set(&listed_refund), refund);
}
