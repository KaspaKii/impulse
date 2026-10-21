// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The `impulse` binary end to end: exit statuses, the stderr refusal format, the
//! IMPULSE_MAX_VALUE wiring, and no default node. Offline: no command here reaches a node.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "impulse-cli-bin-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn impulse(args: &[&str], max_value: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_impulse"));
    cmd.args(args).env_remove("IMPULSE_MAX_VALUE");
    if let Some(v) = max_value {
        cmd.env("IMPULSE_MAX_VALUE", v);
    }
    cmd.output().unwrap()
}

/// The buyer of golden vector 08, whose delivery and refund pay the buyer key.
const BUYER: [&str; 4] = [
    "--role",
    "buyer",
    "--my-key",
    "67b2e7c8dfe143ccdad9cdd0929b9bfff2ed9039ef21a146a2caab1c2b542de3",
];

/// The buyer of vector 08, declaring the trade worth 1 KAS (every command here takes the cap).
fn with_buyer<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut v = args.to_vec();
    v.extend_from_slice(&BUYER);
    v.extend_from_slice(&["--kas-equivalent", "100000000"]);
    v
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// Writes the JSON form of golden vector 08 (testnet, 1 KAS cash) as a draft, its asset
/// template set to a pinned kcc20.sil build (`address` and `verify` refuse other templates).
fn draft(dir: &Path) -> PathBuf {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
    let text = std::fs::read_to_string(
        vectors.join("08-testnet-vault-authority-earmarked-kcc20-kas.json"),
    )
    .unwrap();
    let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let pin = &impulse_core::verify::PINNED_KCC20_TEMPLATES[0].triple;
    let leg = &mut doc["terms"]["asset_leg"];
    leg["template_hash"] = pin
        .hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into();
    leg["template_prefix_len"] = pin.prefix_len.into();
    leg["template_suffix_len"] = pin.suffix_len.into();
    let p = dir.join("draft.json");
    std::fs::write(&p, doc["terms"].to_string()).unwrap();
    p
}

#[test]
fn a_trade_from_draft_to_verified_uri() {
    let dir = TempDir::new();
    let draft = draft(&dir.0);
    let terms = dir.0.join("terms.json");
    let (d, t) = (draft.to_str().unwrap(), terms.to_str().unwrap());
    let made = impulse(
        &with_buyer(&[
            "terms",
            "new",
            "--draft",
            d,
            "--out",
            t,
            "--daa",
            "400000000",
        ]),
        None,
    );
    assert!(made.status.success(), "{}", stderr(&made));
    let shown = impulse(
        &with_buyer(&["address", "--terms", t, "--daa", "400000000", "--no-qr"]),
        None,
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    let text = String::from_utf8(shown.stdout).unwrap();
    let uri = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("funding URI: "))
        .unwrap();
    let checked = impulse(
        &with_buyer(&["verify", "--terms", t, "--uri", uri, "--daa", "400000000"]),
        None,
    );
    assert!(checked.status.success(), "{}", stderr(&checked));

    // The environment cap is read by the binary: 1 KAS is above a 0.5 KAS cap.
    let capped = impulse(
        &with_buyer(&["address", "--terms", t, "--daa", "400000000", "--no-qr"]),
        Some("50000000"),
    );
    assert_eq!(capped.status.code(), Some(1));
    assert!(stderr(&capped).starts_with("impulse: CLI_VALUE_CAP_EXCEEDED: "));
    assert!(capped.stdout.is_empty(), "nothing shown on refusal");
}

#[test]
fn a_refused_terms_new_prints_nothing_and_writes_nothing() {
    let dir = TempDir::new();
    let draft = draft(&dir.0);
    let terms = dir.0.join("terms.json");
    let (d, t) = (draft.to_str().unwrap(), terms.to_str().unwrap());
    // 1 KAS is above a 0.5 KAS cap: refused after both legs instantiate, before anything shows.
    let capped = impulse(
        &with_buyer(&[
            "terms",
            "new",
            "--draft",
            d,
            "--out",
            t,
            "--daa",
            "400000000",
        ]),
        Some("50000000"),
    );
    assert_eq!(capped.status.code(), Some(1));
    assert!(stderr(&capped).starts_with("impulse: CLI_VALUE_CAP_EXCEEDED: "));
    assert!(capped.stdout.is_empty(), "nothing shown on refusal");
    assert!(!terms.exists(), "nothing written");
    // Expired at the given creation DAA score: refused by the creation checks.
    let late = impulse(
        &with_buyer(&[
            "terms",
            "new",
            "--draft",
            d,
            "--out",
            t,
            "--daa",
            "425920000",
        ]),
        None,
    );
    assert_eq!(late.status.code(), Some(1));
    assert!(stderr(&late).starts_with("impulse: TERMS_EXPIRY_NOT_AFTER_CREATION: "));
    assert!(late.stdout.is_empty());
    assert!(!terms.exists());
}

#[test]
fn refusals_exit_1_with_the_code_on_stderr() {
    let o = impulse(
        &with_buyer(&[
            "address",
            "--terms",
            "/nonexistent/terms.json",
            "--daa",
            "1",
        ]),
        None,
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).starts_with("impulse: CLI_FILE_READ: "));
    assert!(o.stdout.is_empty());
}

#[test]
fn status_has_no_default_node() {
    let o = impulse(
        &["status", "--terms", "t", "--txid", "x", "--from-block", "y"],
        None,
    );
    assert_eq!(o.status.code(), Some(2), "usage error");
    assert!(stderr(&o).contains("--node"));
}

#[test]
fn help_lists_the_phase_1_commands() {
    let o = impulse(&["--help"], None);
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap();
    for cmd in ["terms", "address", "verify", "status", "receipt"] {
        assert!(text.contains(cmd), "{cmd}");
    }
}

#[test]
fn help_lists_the_phase_2_commands_and_hides_the_fake_node() {
    let o = impulse(&["--help"], None);
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap();
    for cmd in [
        "fund", "settle", "refund", "ipst", "submit", "decode", "tip", "key", "token",
    ] {
        assert!(text.contains(cmd), "{cmd}");
    }
    assert!(
        !text.contains("fake-node"),
        "hidden, and absent from release builds"
    );
}

/// A release build (no `offline-fake-node` feature) has no fake node: no `fake://` URL and no
/// `fake-node` command. Control: an ordinary URL gets past the URL check to the connection.
#[cfg(not(feature = "offline-fake-node"))]
#[test]
fn a_release_build_has_no_fake_node() {
    let o = impulse(&["fake-node", "init", "--state", "x", "--daa", "1"], None);
    assert_eq!(o.status.code(), Some(2), "unknown command");
    let o = impulse(&["tip", "--node", "fake:///tmp/impulse-no-state"], None);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).starts_with("impulse: CLI_NODE_URL_INVALID: "));
    let o = impulse(&["tip", "--node", "ws://127.0.0.1:1"], None);
    assert!(
        stderr(&o).starts_with("impulse: CLI_NODE_UNREACHABLE: "),
        "control"
    );
}

#[test]
fn help_carries_the_four_part_disclaimer() {
    let o = impulse(&["--help"], None);
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap().replace('\n', " ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for part in [
        "Non-custodial software",
        "financial, legal or tax advice, or an offer",
        "issues no asset or token",
        "Issuer terms, transfer restrictions and sanctions obligations",
    ] {
        assert!(text.contains(part), "missing: {part}");
    }
}
