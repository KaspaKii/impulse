// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! spec/ERRORS.md against the code that raises each code (phase 2). The families of impulse-core
//! that its default build exports are compared with the frozen lists themselves; the families of
//! the other crates, of the threshold feature (off by default, so not linked here), of the
//! command line's signing and receipt codes, and of the release dry run are compared with the
//! frozen lists or the code literals in their sources, read as text. Every family table is also
//! compared, code by code, with the per-layer spec that defines it. None of these tests is a
//! parity item.
//!
//! A new code in any of those places fails a test here until spec/ERRORS.md lists it, at the end
//! of its family; a code the file lists that the code no longer has fails too.

use crate::{assert_same_meaning, read, repo_path};
use std::collections::{BTreeMap, BTreeSet};

/// The Rust crates whose string literals are scanned for codes.
const CRATES: [&str; 4] = [
    "crates/impulse-core/src",
    "crates/impulse-cli/src",
    "crates/impulse-watch/src",
    "crates/impulse-wasm/src",
];

/// ALL_CAPS literals in the Rust sources that have an underscore and are not codes: environment
/// variables, an opcode name, a sighash type name and command-line value names (`TERMS_FILE`,
/// `TERMS_HASH`, `TX_FILE`, which have a family's prefix). A new one fails
/// `every_code_in_the_rust_sources_is_in_errors_md` until it is classified here, so a code under
/// a prefix no family lists cannot hide as one.
const NOT_CODES: [&str; 13] = [
    "CARGO_MANIFEST_DIR",
    "IMPULSE_E2E_OUT",
    "IMPULSE_MAX_VALUE",
    "IMPULSE_ORACLE_IN",
    "IMPULSE_ORACLE_OUT",
    "IMPULSE_V4_FIXTURE_WITNESS",
    "IMPULSE_V4_MASS_OUT",
    "IMPULSE_VECTORS_OUT",
    "OP_DUP",
    "SIG_HASH_ALL",
    "TERMS_FILE",
    "TERMS_HASH",
    "TX_FILE",
];

/// The 41 codes of the release dry run in the order I12 reported them, frozen here because the
/// script has no list of its own. A new code goes at the end, here and in ERRORS.md.
const RELEASE_CODES: [&str; 42] = [
    "RELEASE_USAGE",
    "RELEASE_PKG_LIST_FAILED",
    "RELEASE_PKG_METADATA",
    "RELEASE_PKG_UNPUBLISHABLE_DEP",
    "RELEASE_PKG_ESCAPES_CRATE",
    "RELEASE_PKG_FORBIDDEN_FILE",
    "RELEASE_NPM_PACK_FAILED",
    "RELEASE_NPM_FORBIDDEN_FILE",
    "RELEASE_CHECKLIST_MISSING",
    "RELEASE_CHECKLIST_DRIFT",
    "RELEASE_CHECKLIST_ROW",
    "RELEASE_CHECKLIST_ORDER",
    "RELEASE_CHECKLIST_PENDING",
    "RELEASE_NOTES_PLACEHOLDER_MISSING",
    "RELEASE_NOTES_STATUS",
    "RELEASE_NOTES_UNRESOLVED",
    "RELEASE_NOTES_HASH_MISMATCH",
    "RELEASE_NOTES_RISK",
    "RELEASE_NOTES_VALUE_CAP",
    "RELEASE_NOTES_MAINTAINER_SECTION",
    "RELEASE_NOTES_TXID_ROW",
    "RELEASE_NOTES_TXID_UNEVIDENCED",
    "RELEASE_PLACEHOLDER_URL",
    "RELEASE_INVENTED_VALUE",
    "RELEASE_DRAFT_MARKER",
    "RELEASE_DRAFT_UNRESOLVED",
    "RELEASE_BOUNTY_UNPUBLISHED",
    "RELEASE_KGPR_RECORD_MISSING",
    "RELEASE_KGPR_RECORD_FIELD",
    "RELEASE_KGPR_RECORD_NETWORK",
    "RELEASE_PLACEHOLDER",
    "RELEASE_SECURITY_NO_CONTACT",
    "RELEASE_EMDASH",
    "RELEASE_OWNERSHIP_WORDING",
    "RELEASE_VEHICLE_WORDING",
    "RELEASE_UNVERIFIED_CLAIM",
    "RELEASE_SPEC_WORDING",
    "RELEASE_DRAFT_HASH",
    "RELEASE_NOTES_TOOLCHAIN",
    "RELEASE_NOTES_TXID_TESTNET",
    "RELEASE_DRAFT_UNFILLED",
    "RELEASE_ZK_V4_LIVE_PENDING",
];

/// The receipt codes of spec/CLI.md in the order its prose lists them: the CLI raises them as
/// string literals and keeps no list.
const RECEIPT_CODES: [&str; 11] = [
    "RECEIPT_MALFORMED",
    "RECEIPT_SIGNATURE_INVALID",
    "RECEIPT_SIGNER_MISMATCH",
    "RECEIPT_DAA_MISMATCH",
    "RECEIPT_NOT_ACCEPTED",
    "RECEIPT_DEPTH_UNREACHED",
    "RECEIPT_TERMS_MISMATCH",
    "RECEIPT_TXID_MISMATCH",
    "RECEIPT_QUANTITY_MISSING",
    "RECEIPT_QUANTITY_MISMATCH",
    "RECEIPT_LINEAGE_MISMATCH",
];

/// The signing codes of spec/CLI.md in its table's order, likewise raised as literals.
const SIGN_CODES: [&str; 8] = [
    "SIGN_MAINNET_NOT_EXPLICIT",
    "SIGN_NETWORK_MISMATCH",
    "SIGN_KEY_FILE_UNREADABLE",
    "SIGN_KEY_FILE_PERMISSIONS",
    "SIGN_KEY_FILE_FORMAT",
    "SIGN_KEY_INVALID",
    "SIGN_KEY_NOT_EXPECTED",
    "SIGN_SELF_CHECK_FAILED",
];

/// The data rows of every markdown table in the section after `heading`, cells trimmed and
/// backticks dropped, header and separator rows removed.
fn tables(doc: &str, heading: &str) -> Vec<Vec<Vec<String>>> {
    let section = doc
        .split_once(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading}"))
        .1;
    let section = section.split("\n#").next().unwrap();
    let mut found: Vec<Vec<Vec<String>>> = Vec::new();
    let mut open = false;
    for line in section.lines() {
        if line.starts_with('|') {
            if !open {
                found.push(Vec::new());
                open = true;
            }
            let cells = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().replace('`', ""))
                .collect();
            found.last_mut().unwrap().push(cells);
        } else {
            open = false;
        }
    }
    found
        .into_iter()
        .map(|t| t.into_iter().skip(2).collect())
        .collect()
}

/// One row of a spec/ERRORS.md family table: `# | Code | Raised by | Meaning | Since`.
#[derive(Debug)]
struct Row {
    code: String,
    raised: String,
    meaning: String,
}

fn errors_rows(errors: &str, heading: &str) -> Vec<Row> {
    let all = tables(errors, heading);
    assert_eq!(all.len(), 1, "{heading}: one table");
    all[0]
        .iter()
        .enumerate()
        .map(|(n, cells)| {
            assert_eq!(cells.len(), 5, "{heading}: row {} has five cells", n + 1);
            assert_eq!(
                cells[0],
                (n + 1).to_string(),
                "{heading}: rows number from 1"
            );
            assert!(!cells[2].is_empty() && !cells[3].is_empty() && !cells[4].is_empty());
            Row {
                code: cells[1].clone(),
                raised: cells[2].clone(),
                meaning: cells[3].clone(),
            }
        })
        .collect()
}

/// The strings of `pub const NAME: [&str; N] = [...];` in a Rust source, read as text.
fn source_list(path: &str, name: &str) -> Vec<String> {
    let text = read(path);
    let head = format!("pub const {name}: [&str; ");
    let at = text
        .find(&head)
        .unwrap_or_else(|| panic!("{path}: no {name}"));
    let rest = &text[at + head.len()..];
    let (declared, rest) = rest.split_once(']').expect("length");
    let body = rest.split_once("= [").expect("= [").1;
    let body = body.split_once("];").expect("end of list").0;
    let listed: Vec<String> = body
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    assert_eq!(
        listed.len().to_string(),
        declared,
        "{path}: {name} declares {declared} codes and lists {}",
        listed.len()
    );
    listed
}

fn strs(codes: &[&str]) -> Vec<String> {
    codes.iter().map(|c| c.to_string()).collect()
}

/// ERRORS.md lists exactly `codes` under `heading`, in order, each with a raised-by and meaning.
fn assert_lists(errors: &str, heading: &str, codes: &[String]) -> Vec<Row> {
    let rows = errors_rows(errors, heading);
    let listed: Vec<String> = rows.iter().map(|r| r.code.clone()).collect();
    assert_eq!(
        &listed, codes,
        "{heading} in spec/ERRORS.md and the code disagree: append a new code at the end of its family"
    );
    rows
}

/// Where a per-layer spec states a family's codes: the file, the heading, which table of the
/// section, and the columns of the code, the raised-by text (if the table has it) and the
/// meaning.
struct SpecTable {
    path: &'static str,
    heading: &'static str,
    table: usize,
    code: usize,
    raised: Option<usize>,
    meaning: usize,
}

/// Every code of `spec` with its (raised by, meaning), read from the spec file.
fn spec_rows(spec: &SpecTable) -> BTreeMap<String, (Option<String>, String)> {
    let doc = read(spec.path);
    let table = tables(&doc, spec.heading)
        .into_iter()
        .nth(spec.table)
        .unwrap_or_else(|| {
            panic!(
                "{}: no table {} after {}",
                spec.path, spec.table, spec.heading
            )
        });
    table
        .into_iter()
        .map(|cells| {
            (
                cells[spec.code].clone(),
                (
                    spec.raised.map(|c| cells[c].clone()),
                    cells[spec.meaning].clone(),
                ),
            )
        })
        .collect()
}

/// Every row of the family agrees with the per-layer spec that defines it, and the specs define
/// no code of these prefixes that the family lacks.
fn assert_matches_specs(rows: &[Row], specs: &[SpecTable], prefixes: &[&str]) {
    let mut defined: BTreeMap<String, (Option<String>, String)> = BTreeMap::new();
    for spec in specs {
        for (code, row) in spec_rows(spec) {
            if prefixes.iter().any(|p| code.starts_with(p)) {
                defined.insert(code, row);
            }
        }
    }
    let listed: BTreeSet<&str> = rows.iter().map(|r| r.code.as_str()).collect();
    for row in rows {
        let (raised, meaning) = defined
            .get(&row.code)
            .unwrap_or_else(|| panic!("{}: not defined in its per-layer spec", row.code));
        assert_same_meaning(&row.code, &row.meaning, meaning);
        if let Some(raised) = raised {
            assert_eq!(&row.raised, raised, "{}: raised by", row.code);
        }
    }
    for code in defined.keys() {
        assert!(
            listed.contains(code.as_str()),
            "{code}: defined in a per-layer spec, missing from spec/ERRORS.md"
        );
    }
}

fn core_spec(path: &'static str, heading: &'static str, table: usize) -> SpecTable {
    SpecTable {
        path,
        heading,
        table,
        code: 0,
        raised: Some(1),
        meaning: 2,
    }
}

/// A code table of spec/V2.md section 8 (#, code, raised by, meaning).
fn v2_spec(heading: &'static str) -> SpecTable {
    SpecTable {
        path: "spec/V2.md",
        heading,
        table: 0,
        code: 1,
        raised: Some(2),
        meaning: 3,
    }
}

fn meaning_only(path: &'static str, heading: &'static str, table: usize) -> SpecTable {
    SpecTable {
        path,
        heading,
        table,
        code: 0,
        raised: None,
        meaning: 1,
    }
}

/// The families of impulse-core's default build: the builders and IPST, the verifier, the
/// decoder and the token warnings, each compared with the frozen list it exports and with the
/// specs that define it.
#[test]
fn errors_md_lists_every_code_of_the_core_builders_verifier_and_decoder() {
    use impulse_core::decode::DECODE_ERROR_CODES;
    use impulse_core::tx::TX_ERROR_CODES;
    use impulse_core::v2::{TX_V2_ERROR_CODES, VERIFY_V2_ERROR_CODES};
    use impulse_core::verify::{TOKEN_WARNING_CODES, VERIFY_ERROR_CODES};
    let errors = read("spec/ERRORS.md");

    // v0.2 appends its codes to the end of these families (spec/V2.md 8.3 and 8.4, I16).
    let tx_codes = [strs(&TX_ERROR_CODES), strs(&TX_V2_ERROR_CODES)].concat();
    let rows = assert_lists(&errors, "## TX_ and IPST_ codes", &tx_codes);
    assert_matches_specs(
        &rows,
        &[
            core_spec("spec/TRANSACTIONS.md", "## Error codes", 0),
            core_spec("spec/IPST.md", "## Error codes", 0),
            v2_spec("### 8.3 TX_ and IPST_"),
        ],
        &["TX_", "IPST_"],
    );
    let verify_codes = [strs(&VERIFY_ERROR_CODES), strs(&VERIFY_V2_ERROR_CODES)].concat();
    let rows = assert_lists(&errors, "## VERIFY_ codes", &verify_codes);
    assert_matches_specs(
        &rows,
        &[
            core_spec("spec/VERIFY.md", "## Error codes", 0),
            v2_spec("### 8.4 VERIFY_"),
        ],
        &["VERIFY_"],
    );
    let rows = assert_lists(&errors, "## DECODE_ codes", &strs(&DECODE_ERROR_CODES));
    assert_matches_specs(
        &rows,
        &[core_spec("spec/VERIFY.md", "## Error codes", 0)],
        &["DECODE_"],
    );
    let rows = assert_lists(&errors, "## TOKEN_ warnings", &strs(&TOKEN_WARNING_CODES));
    assert_matches_specs(
        &rows,
        &[meaning_only("spec/VERIFY.md", "## Error codes", 1)],
        &["TOKEN_"],
    );
}

/// The families of the other crates, whose frozen lists this crate reads as text so as to link
/// none of them: the command line (with its `impulse frost` commands), the watcher, the SDK and
/// the threshold feature.
#[test]
fn errors_md_lists_every_code_of_the_cli_watcher_sdk_and_threshold() {
    let errors = read("spec/ERRORS.md");
    let cli = source_list("crates/impulse-cli/src/error.rs", "CLI_ERROR_CODES");
    let rows = assert_lists(&errors, "## CLI_ codes", &cli);
    assert_matches_specs(
        &rows,
        &[meaning_only("spec/CLI.md", "## Error codes", 0)],
        &["CLI_"],
    );

    let rows = assert_lists(&errors, "## SIGN_ codes", &strs(&SIGN_CODES));
    assert_matches_specs(
        &rows,
        &[meaning_only(
            "spec/CLI.md",
            "## Key file and the signing module",
            0,
        )],
        &["SIGN_"],
    );
    // The receipt codes have no table in the spec, only a sentence that lists them.
    assert_lists(&errors, "## RECEIPT_ codes", &strs(&RECEIPT_CODES));
    let cli_spec = read("spec/CLI.md");
    for code in RECEIPT_CODES {
        assert!(
            cli_spec.contains(&format!("`{code}`")),
            "{code}: not in spec/CLI.md"
        );
    }

    let watch = source_list("crates/impulse-watch/src/error.rs", "WATCH_ERROR_CODES");
    let rows = assert_lists(&errors, "## WATCH_ codes", &watch);
    assert_matches_specs(
        &rows,
        &[meaning_only("spec/WATCH.md", "## Codes", 0)],
        &["WATCH_"],
    );
    let flags = source_list("crates/impulse-watch/src/error.rs", "WATCH_EVENT_CODES");
    let rows = assert_lists(&errors, "## WATCH_ event flags", &flags);
    assert_matches_specs(
        &rows,
        &[meaning_only("spec/WATCH.md", "## Codes", 1)],
        &["WATCH_"],
    );

    let sdk = source_list("crates/impulse-wasm/src/error.rs", "SDK_ERROR_CODES");
    assert_lists(&errors, "## SDK_ codes", &sdk);
    let readme = read("crates/impulse-wasm/npm/README.md");
    for code in &sdk {
        assert!(
            readme.contains(&format!("`{code}`")),
            "{code}: not in the package README"
        );
    }

    let threshold = source_list(
        "crates/impulse-core/src/threshold/error.rs",
        "THRESHOLD_ERROR_CODES",
    );
    let rows = assert_lists(&errors, "## THRESHOLD_ codes", &threshold);
    assert_matches_specs(
        &rows,
        &[core_spec("spec/THRESHOLD.md", "## Error codes", 0)],
        &["THRESHOLD_"],
    );

    // The `impulse frost` codes are the CLI's, in the second table of the same spec section.
    let frost = source_list("crates/impulse-cli/src/frost.rs", "FROST_ERROR_CODES");
    let rows = assert_lists(&errors, "## FROST_ codes", &frost);
    assert_matches_specs(
        &rows,
        &[meaning_only("spec/THRESHOLD.md", "## Error codes", 1)],
        &["FROST_"],
    );
}

/// The `ZK_` family (impulse_core::zk, cargo feature `zk`, off by default): ERRORS.md equals the
/// frozen list read from the source text and agrees row by row with spec/V3-ZK.md section 12,
/// whose table has a leading number column.
#[test]
fn errors_md_lists_every_zk_code() {
    let errors = read("spec/ERRORS.md");
    let zk = source_list("crates/impulse-core/src/zk/error.rs", "ZK_ERROR_CODES");
    let rows = assert_lists(&errors, "## ZK_ codes", &zk);
    let spec = SpecTable {
        path: "spec/V3-ZK.md",
        heading: "## 12. Error codes",
        table: 0,
        code: 1,
        raised: Some(2),
        meaning: 3,
    };
    assert_matches_specs(&rows, &[spec], &["ZK_"]);
}

/// The `ZK_H_` family (impulse_core::zkh, cargo feature `zk-hashed`, off by default): ERRORS.md
/// equals the frozen list read from the source text and agrees row by row with spec/V3-ZK.md
/// section 22.8.
#[test]
fn errors_md_lists_every_zk_h_code() {
    let errors = read("spec/ERRORS.md");
    let zkh = source_list("crates/impulse-core/src/zkh/mod.rs", "ZKH_ERROR_CODES");
    let rows = assert_lists(&errors, "## ZK_H_ codes", &zkh);
    let spec = SpecTable {
        path: "spec/V3-ZK.md",
        heading: "### 22.8 Error codes appended",
        table: 0,
        code: 1,
        raised: Some(2),
        meaning: 3,
    };
    assert_matches_specs(&rows, &[spec], &["ZK_H_"]);
}

/// The release dry run's finding codes: ERRORS.md lists the frozen 41, and the script raises
/// exactly those.
#[test]
fn errors_md_lists_every_release_dry_run_code() {
    let errors = read("spec/ERRORS.md");
    assert_lists(&errors, "## RELEASE_ codes", &strs(&RELEASE_CODES));
    // The release dry run is private-only: the public tree drops it with the owner documents it
    // checks, so the half of this test that reads it runs only where it exists. The name is built
    // from fragments because the public tree may not name the file.
    let script_path = concat!("scripts/release-dry", "run.sh");
    if !repo_path(script_path).exists() {
        eprintln!("skipped: the release dry run is not in this tree (private-only); ERRORS.md list checked");
        return;
    }
    let script = read(script_path);
    let mut raised = BTreeSet::new();
    for word in script.split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        if word.starts_with("RELEASE_") && word.len() > "RELEASE_".len() {
            raised.insert(word.to_string());
        }
    }
    let frozen: BTreeSet<String> = strs(&RELEASE_CODES).into_iter().collect();
    assert_eq!(raised, frozen, "the release dry run and the frozen list");
}

/// The code prefixes of the Families table of spec/ERRORS.md, without the trailing underscore.
fn family_prefixes(errors: &str) -> BTreeSet<String> {
    let all = tables(errors, "## Families");
    assert_eq!(all.len(), 1, "one Families table");
    all[0]
        .iter()
        .flat_map(|cells| cells[0].split(','))
        .map(|prefix| prefix.trim().trim_end_matches('_').to_string())
        .collect()
}

/// The code literals in the Rust sources: every one is a code a family table of spec/ERRORS.md
/// lists, none is a retired code (reserved, never reused), and an ALL_CAPS literal under a prefix
/// no family has is either listed in `NOT_CODES` or a failure. The signing and receipt codes,
/// which no constant lists, are exactly the literals found.
#[test]
fn every_code_in_the_rust_sources_is_in_errors_md() {
    let errors = read("spec/ERRORS.md");
    // Listed: the numbered rows of the family tables. Retired: the first cell of the retired
    // table, less the codes that are also live (a narrowed code is both).
    let mut listed = BTreeSet::new();
    for line in errors.lines().filter(|l| l.starts_with("| ")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.get(1).is_some_and(|n| n.parse::<u32>().is_ok()) {
            listed.insert(cells[2].trim_matches('`').to_string());
        }
    }
    let retired_table = tables(&errors, "## Retired and changed codes");
    assert_eq!(retired_table.len(), 1, "one retired table");
    let retired: BTreeSet<String> = retired_table[0]
        .iter()
        .map(|cells| cells[0].clone())
        .filter(|code| !listed.contains(code))
        .collect();
    assert!(
        retired.contains("TEMPLATE_SAME_COVENANT") && retired.len() >= 3,
        "{retired:?}"
    );
    // The Rust sources raise every family but the release dry run's, which is a script.
    let mut prefixes = family_prefixes(&errors);
    assert!(
        prefixes.remove("RELEASE"),
        "the Families table lists RELEASE"
    );
    assert!(prefixes.len() >= 14, "{prefixes:?}");

    let mut literals: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unclassified: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for dir in CRATES {
        let mut stack = vec![repo_path(dir)];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                for entry in std::fs::read_dir(&path).expect("read dir") {
                    stack.push(entry.expect("entry").path());
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                for quoted in text.split('"') {
                    let shaped = quoted.starts_with(|c: char| c.is_ascii_uppercase())
                        && quoted
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                        && quoted.split('_').count() >= 2
                        && quoted.split('_').all(|segment| !segment.is_empty());
                    if !shaped {
                        continue;
                    }
                    let family = quoted.split('_').next().unwrap_or("");
                    let found = if NOT_CODES.contains(&quoted) {
                        continue;
                    } else if prefixes.contains(family) {
                        &mut literals
                    } else {
                        &mut unclassified
                    };
                    found
                        .entry(quoted.to_string())
                        .or_default()
                        .insert(path.display().to_string());
                }
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "ALL_CAPS literals under a prefix no family of spec/ERRORS.md has: {unclassified:?}. If one is a code, add its family to spec/ERRORS.md; if not, list it in NOT_CODES"
    );
    for (code, files) in &literals {
        assert!(
            !retired.contains(code),
            "{code} is retired and reserved in spec/ERRORS.md, and {files:?} raises it again"
        );
        assert!(
            listed.contains(code),
            "{code} is raised in {files:?} and spec/ERRORS.md does not list it"
        );
    }
    for code in SIGN_CODES.iter().chain(RECEIPT_CODES.iter()) {
        assert!(
            literals.contains_key(*code),
            "{code}: no longer raised by the CLI"
        );
    }
    let signing_like: BTreeSet<&String> = literals
        .keys()
        .filter(|c| c.starts_with("SIGN_") || c.starts_with("RECEIPT_"))
        .collect();
    assert_eq!(
        signing_like.len(),
        SIGN_CODES.len() + RECEIPT_CODES.len(),
        "a signing or receipt code is raised that is not in the frozen lists: {signing_like:?}"
    );
}

/// No code is listed twice in the family tables of spec/ERRORS.md: a code is never reused.
#[test]
fn no_code_is_listed_twice_in_errors_md() {
    let errors = read("spec/ERRORS.md");
    let mut seen = BTreeSet::new();
    for line in errors.lines().filter(|l| l.starts_with("| ")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.get(1).is_some_and(|n| n.parse::<u32>().is_ok()) {
            let code = cells[2].trim_matches('`');
            assert!(seen.insert(code.to_string()), "{code} is listed twice");
        }
    }
    assert!(seen.len() >= 262, "{} codes listed", seen.len());
}

/// The tests spec/ERRORS.md names as keeping it in step are tests of this crate.
#[test]
fn errors_md_names_tests_that_exist() {
    let errors = read("spec/ERRORS.md");
    let mut sources = read("tests/parity/parity.rs");
    sources.push_str(&read("tests/parity/catalogue.rs"));
    let mut named = 0;
    for word in errors.split('`').skip(1).step_by(2) {
        let ours = ["errors_md_", "every_code_in_", "no_code_is_listed"]
            .iter()
            .any(|prefix| word.starts_with(prefix));
        if ours {
            named += 1;
            assert!(
                sources.contains(&format!("fn {word}()")),
                "spec/ERRORS.md names the test {word}, which does not exist"
            );
        }
    }
    assert!(named >= 7, "{named} tests named");
}
