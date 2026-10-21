// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The mainnet guard of the `impulse-htlc-demo` binary, offline. A tiny JSON-RPC server on
//! 127.0.0.1 answers `getGenesisHash` with the genesis hash a test names and nothing else, so
//! the binary can be shown to refuse or accept a "mainnet" cluster without touching any network.
//! No key file is made or read: every refusal tested here comes before a key is read.

use impulse_htlc_demo::{MAINNET_GENESIS, MAINNET_USDC_MINT, PLACEHOLDER_PROGRAM};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::Command,
    thread,
};

const TEST_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Starts the server and returns its URL.
fn mock(genesis: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    thread::spawn(move || {
        for conn in l.incoming().flatten() {
            thread::spawn(move || {
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut w = conn;
                loop {
                    let mut len = 0usize;
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let l = line.to_ascii_lowercase();
                        if let Some(v) = l.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap();
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let mut body = vec![0u8; len];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let body = String::from_utf8_lossy(&body).to_string();
                    let id: String = body
                        .split("\"id\":")
                        .nth(1)
                        .map(|t| t.chars().take_while(|c| c.is_ascii_digit()).collect())
                        .unwrap_or_else(|| "1".into());
                    let out = if body.contains("getGenesisHash") {
                        format!("{{\"jsonrpc\":\"2.0\",\"result\":\"{genesis}\",\"id\":{id}}}")
                    } else if body.contains("getAccountInfo") {
                        format!("{{\"jsonrpc\":\"2.0\",\"result\":{{\"context\":{{\"slot\":1}},\"value\":null}},\"id\":{id}}}")
                    } else {
                        format!("{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32601,\"message\":\"no\"}},\"id\":{id}}}")
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{out}",
                        out.len()
                    );
                    if w.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    url
}

struct Run {
    ok: bool,
    out: String,
    err: String,
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut c = Command::new(env!("CARGO_BIN_EXE_impulse-htlc-demo"));
    c.args(args).env_remove("IMPULSE_MAX_USDC");
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    Run {
        ok: o.status.success(),
        out: String::from_utf8_lossy(&o.stdout).to_string(),
        err: String::from_utf8_lossy(&o.stderr).to_string(),
    }
}

fn open_args<'a>(url: &'a str, amount: &'a str, mint: &'a str, program: &'a str) -> Vec<&'a str> {
    vec![
        "open",
        "--url",
        url,
        "--program",
        program,
        "--mint",
        mint,
        "--amount",
        amount,
        "--hash",
        HASH,
        "--timeout",
        "1",
        "--recipient",
        HASH,
        "--refund",
        HASH,
        "--funder-key",
        "/nonexistent",
    ]
}

const SOME_PROGRAM: &str = "11111111111111111111111111111112";

#[test]
fn mainnet_genesis_is_refused_without_network_mainnet() {
    let url = mock(MAINNET_GENESIS);
    for cmd in ["now", "ids"] {
        let r = run(&[cmd, "--url", &url], &[]);
        assert!(!r.ok);
        assert!(r.err.contains("pass --network mainnet"), "{}", r.err);
    }
    let r = run(&["now", "--url", &url, "--network", "devnet"], &[]);
    assert!(!r.ok && r.err.contains("names a test cluster"), "{}", r.err);
}

#[test]
fn network_mainnet_is_refused_on_another_genesis() {
    let url = mock(TEST_GENESIS);
    let r = run(&["now", "--url", &url, "--network", "mainnet"], &[]);
    assert!(
        !r.ok && r.err.contains("genesis hash is not mainnet-beta's"),
        "{}",
        r.err
    );
    // A test cluster without the flag is unchanged: it gets past the guard (and fails later, on
    // the mock's lack of a clock).
    let r = run(&["now", "--url", &url], &[]);
    assert!(
        !r.err.contains("genesis") && !r.err.contains("--network"),
        "{}",
        r.err
    );
}

#[test]
fn mainnet_prints_the_r2_notice_and_refuses_setup() {
    let url = mock(MAINNET_GENESIS);
    let r = run(&["setup", "--url", &url, "--network", "mainnet"], &[]);
    assert!(!r.ok);
    assert!(r.err.contains("Race R2"), "{}", r.err);
    assert!(r.err.contains("freeze authority"), "{}", r.err);
    assert!(r.err.contains("refused on mainnet"), "{}", r.err);
}

#[test]
fn open_above_the_cap_is_refused_before_any_key_is_read() {
    let url = mock(MAINNET_GENESIS);
    let a = open_args(&url, "10000001", MAINNET_USDC_MINT, SOME_PROGRAM);
    let mut args = a.clone();
    args.extend(["--network", "mainnet"]);
    let r = run(&args, &[]);
    assert!(!r.ok);
    assert!(r.err.contains("CLI_VALUE_CAP_EXCEEDED"), "{}", r.err);
    assert!(!r.err.contains("keypair"), "{}", r.err);
    // The environment can lower the cap.
    let a = open_args(&url, "2000000", MAINNET_USDC_MINT, SOME_PROGRAM);
    let mut args = a.clone();
    args.extend(["--network", "mainnet"]);
    let r = run(&args, &[("IMPULSE_MAX_USDC", "1000000")]);
    assert!(r.err.contains("CLI_VALUE_CAP_EXCEEDED"), "{}", r.err);
    // It cannot raise it.
    let r = run(&args, &[("IMPULSE_MAX_USDC", "20000000")]);
    assert!(!r.ok && r.err.contains("never raise it"), "{}", r.err);
}

#[test]
fn the_risk_flag_lifts_the_cap_and_a_value_within_it_passes_the_cap() {
    let url = mock(MAINNET_GENESIS);
    let mut args = open_args(&url, "20000000", MAINNET_USDC_MINT, SOME_PROGRAM);
    args.extend(["--network", "mainnet", "--i-accept-the-risk"]);
    let r = run(&args, &[]);
    assert!(r.out.contains("value cap: lifted"), "{}{}", r.out, r.err);
    let mut args = open_args(&url, "10000000", MAINNET_USDC_MINT, SOME_PROGRAM);
    args.extend(["--network", "mainnet"]);
    let r = run(&args, &[]);
    assert!(
        r.out.contains("within the cap of 10000000"),
        "{}{}",
        r.out,
        r.err
    );
    // Both then stop at the mock's empty mint account, before any key is read.
    assert!(
        !r.ok && r.err.contains("is not on this cluster"),
        "{}",
        r.err
    );
}

#[test]
fn only_the_pinned_mint_and_an_explicit_real_program_are_accepted() {
    let url = mock(MAINNET_GENESIS);
    let mut args = open_args(&url, "1000", SOME_PROGRAM, SOME_PROGRAM);
    args.extend(["--network", "mainnet"]);
    let r = run(&args, &[]);
    assert!(
        !r.ok && r.err.contains("the only mint accepted is USDC"),
        "{}",
        r.err
    );
    let mut args = open_args(&url, "1000", MAINNET_USDC_MINT, PLACEHOLDER_PROGRAM);
    args.extend(["--network", "mainnet"]);
    let r = run(&args, &[]);
    assert!(
        !r.ok && r.err.contains("placeholder program ID"),
        "{}",
        r.err
    );
    // No devnet default: the program must be named.
    let r = run(
        &[
            "open",
            "--url",
            &url,
            "--network",
            "mainnet",
            "--mint",
            MAINNET_USDC_MINT,
        ],
        &[],
    );
    assert!(
        !r.ok && r.err.contains("--program is required"),
        "{}",
        r.err
    );
    // claim and refund pin the mint too.
    let r = run(
        &[
            "refund",
            "--url",
            &url,
            "--network",
            "mainnet",
            "--program",
            SOME_PROGRAM,
            "--mint",
            SOME_PROGRAM,
        ],
        &[],
    );
    assert!(
        !r.ok && r.err.contains("the only mint accepted is USDC"),
        "{}",
        r.err
    );
}

/// Security review: on mainnet the claim needs the amount the HTLC must hold, refused before any
/// key file is read, and a negative lead is refused.
#[test]
fn a_mainnet_claim_needs_the_expected_amount_before_any_key_is_read() {
    let url = mock(MAINNET_GENESIS);
    let claim = |extra: &[&str]| {
        let mut a = vec![
            "claim",
            "--url",
            &url,
            "--network",
            "mainnet",
            "--program",
            SOME_PROGRAM,
            "--mint",
            MAINNET_USDC_MINT,
            "--payer-key",
            "/nonexistent",
        ];
        a.extend_from_slice(extra);
        run(&a, &[])
    };
    let r = claim(&[]);
    assert!(
        !r.ok && r.err.contains("--expect-amount is required on mainnet"),
        "{}",
        r.err
    );
    // With it, the claim gets past this check to the next one (the program is not on the mock).
    let r = claim(&["--expect-amount", "100000"]);
    assert!(
        !r.ok && !r.err.contains("--expect-amount") && !r.err.contains("keypair"),
        "{}",
        r.err
    );
    let r = claim(&["--expect-amount", "100000", "--min-lead", "-1"]);
    assert!(!r.ok && r.err.contains("--min-lead"), "{}", r.err);
}
