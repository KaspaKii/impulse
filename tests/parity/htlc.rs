// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! spec/ERRORS.md against the hashlock code (I18, spec/V2.md section 8.5 and 8.6): the `HTLC_`
//! family equals impulse-core's frozen list and agrees row by row with spec/V2.md section 8.5,
//! and the hashlock contract's tag tables are exactly the tagged requires of
//! contracts/impulse_hashlock.sil, entry by entry. The `XCHAIN_` frozen list joins this file with
//! the command line's `xchain` commands. None of these tests is a parity item.

use crate::{assert_same_meaning, read};
use impulse_core::htlc::HTLC_ERROR_CODES;
use std::collections::BTreeSet;

/// The data rows of every markdown table in the section after `heading` (up to the next
/// heading), cells trimmed and backticks dropped, header and separator rows removed.
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

#[test]
fn errors_md_lists_every_htlc_code() {
    let errors = read("spec/ERRORS.md");
    let rows = tables(&errors, "## HTLC_ codes");
    assert_eq!(rows.len(), 1, "one HTLC_ table");
    let rows = &rows[0];
    let listed: Vec<&str> = rows.iter().map(|r| r[1].as_str()).collect();
    assert_eq!(
        listed, HTLC_ERROR_CODES,
        "## HTLC_ codes in spec/ERRORS.md and impulse_core::htlc::HTLC_ERROR_CODES disagree"
    );
    let v2 = read("spec/V2.md");
    let spec = tables(&v2, "### 8.5 HTLC_ and XCHAIN_ (new families)");
    let spec = &spec[0];
    assert_eq!(
        spec.len(),
        rows.len(),
        "spec/V2.md section 8.5 lists every code"
    );
    for (n, (e, s)) in rows.iter().zip(spec).enumerate() {
        assert_eq!(e.len(), 5, "row {}: five cells", n + 1);
        assert_eq!(e[0], (n + 1).to_string(), "rows number from 1");
        assert_eq!((&e[0], &e[1]), (&s[0], &s[1]), "row {}", n + 1);
        assert_eq!(e[2], s[2], "{}: raised by", e[1]);
        assert_same_meaning(&e[1], &e[3], &s[3]);
        assert_eq!(e[4], "I18", "{}: since", e[1]);
    }
}

/// The tags of the requires in `source` (each `require(...); // [TAG]`).
fn tags(source: &str) -> Vec<String> {
    source
        .lines()
        .filter(|l| l.trim_start().starts_with("require("))
        .filter_map(|l| l.rsplit_once("// ["))
        .map(|(_, tag)| format!("[{}", tag.trim_end()))
        .collect()
}

#[test]
fn errors_md_lists_every_hashlock_contract_refusal() {
    let source = read("contracts/impulse_hashlock.sil");
    let (settle, refund) = source
        .split_once("entry refund(")
        .expect("the refund entry follows settleWithPreimage");
    let errors = read("spec/ERRORS.md");
    let listed = |heading: &str| -> Vec<String> {
        let t = tables(&errors, heading);
        assert_eq!(t.len(), 1, "{heading}: one table");
        t[0].iter().map(|r| r[0].clone()).collect()
    };
    let as_set = |v: &[String]| -> BTreeSet<String> { v.iter().cloned().collect() };
    let (in_settle, in_refund) = (tags(settle), tags(refund));
    let (l_settle, l_refund) = (
        listed("### Hashlock: settleWithPreimage"),
        listed("### Hashlock: refund"),
    );
    assert_eq!(in_settle.len(), 15, "tagged requires of settleWithPreimage");
    assert_eq!(in_refund.len(), 15, "tagged requires of refund");
    assert_eq!(l_settle.len() + l_refund.len(), 30, "a tag listed twice");
    assert_eq!(as_set(&l_settle), as_set(&in_settle));
    assert_eq!(as_set(&l_refund), as_set(&in_refund));
    assert!(as_set(&l_settle).is_disjoint(&as_set(&l_refund)));
}

/// The codes of `XCHAIN_ERROR_CODES` in crates/impulse-cli/src/xchain.rs, read as text: the
/// parity crate does not link the command line.
fn xchain_source_codes() -> Vec<String> {
    let text = read("crates/impulse-cli/src/xchain.rs");
    let head = "pub const XCHAIN_ERROR_CODES: [&str; ";
    let at = text.find(head).expect("XCHAIN_ERROR_CODES");
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
    assert_eq!(listed.len().to_string(), declared, "declared length");
    listed
}

#[test]
fn errors_md_lists_every_xchain_code() {
    let errors = read("spec/ERRORS.md");
    let rows = tables(&errors, "## XCHAIN_ codes");
    assert_eq!(rows.len(), 1, "one XCHAIN_ table");
    let rows = &rows[0];
    let listed: Vec<String> = rows.iter().map(|r| r[1].clone()).collect();
    assert_eq!(
        listed,
        xchain_source_codes(),
        "## XCHAIN_ codes in spec/ERRORS.md and XCHAIN_ERROR_CODES disagree"
    );
    let v2 = read("spec/V2.md");
    let in_85 = tables(&v2, "### 8.5 HTLC_ and XCHAIN_ (new families)");
    let in_109 = tables(
        &v2,
        "### 10.9 Command line: `impulse xchain` (I18 CLI step)",
    );
    assert_eq!(
        in_85.len(),
        2,
        "section 8.5: the HTLC_ and the XCHAIN_ table"
    );
    assert_eq!(in_109.len(), 1, "section 10.9: the codes it adds");
    let spec: Vec<&Vec<String>> = in_85[1].iter().chain(in_109[0].iter()).collect();
    assert_eq!(spec.len(), rows.len(), "spec/V2.md lists every code");
    for (n, (e, s)) in rows.iter().zip(spec).enumerate() {
        assert_eq!(e.len(), 5, "row {}: five cells", n + 1);
        assert_eq!(e[0], (n + 1).to_string(), "rows number from 1");
        assert_eq!((&e[0], &e[1]), (&s[0], &s[1]), "row {}", n + 1);
        assert_eq!(e[2], s[2], "{}: raised by", e[1]);
        assert_same_meaning(&e[1], &e[3], &s[3]);
        assert_eq!(e[4], "I18", "{}: since", e[1]);
    }
}
