// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! spec/ERRORS.md against the linked-trade code (I22, spec/V2.md section 17.10): the `LINKED_`
//! family equals impulse-core's frozen list and agrees row by row with the table of spec/V2.md
//! section 17.10. None of these tests is a parity item.

use crate::{assert_same_meaning, read};
use impulse_core::linked::LINKED_ERROR_CODES;

/// The data rows of the first markdown table in the section after `heading`, cells trimmed and
/// backticks dropped, header and separator rows removed.
fn table(doc: &str, heading: &str) -> Vec<Vec<String>> {
    let section = doc
        .split_once(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading}"))
        .1;
    let section = section.split("\n#").next().unwrap();
    section
        .lines()
        .filter(|l| l.starts_with('|'))
        .skip(2)
        .take_while(|_| true)
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().replace('`', ""))
                .collect()
        })
        .collect()
}

#[test]
fn errors_md_lists_every_linked_code() {
    let errors = read("spec/ERRORS.md");
    let rows = table(&errors, "## LINKED_ codes");
    let listed: Vec<&str> = rows.iter().map(|r| r[1].as_str()).collect();
    assert_eq!(
        listed, LINKED_ERROR_CODES,
        "## LINKED_ codes in spec/ERRORS.md and impulse_core::linked::LINKED_ERROR_CODES disagree"
    );
    let v2 = read("spec/V2.md");
    let spec = table(&v2, "### 17.10 Codes appended");
    assert_eq!(
        spec.len(),
        rows.len(),
        "spec/V2.md section 17.10 lists every code"
    );
    for (n, (e, s)) in rows.iter().zip(&spec).enumerate() {
        assert_eq!(e.len(), 5, "row {}: five cells", n + 1);
        assert_eq!(e[0], (n + 1).to_string(), "rows number from 1");
        assert_eq!((&e[0], &e[1]), (&s[0], &s[1]), "row {}", n + 1);
        assert_eq!(e[2], s[2], "{}: raised by", e[1]);
        assert_same_meaning(&e[1], &e[3], &s[3]);
        assert_eq!(e[4], "I22", "{}: since", e[1]);
    }
}
