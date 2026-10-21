// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse zk terms reveal` and the v4 lines of `decode` (spec/V3-ZK.md 22.7), in process. The
//! decode of real transactions against terms runs in tests/engine/v4_verify.rs on the pinned
//! engine; here the file handling, the refusals and the fixed texts. Keys are the public
//! multiples of the secp256k1 generator, no private key exists.

use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, p2pk_address};
use crate::json::hex;
use crate::node::Node;
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::testutil::TempDir;
use crate::zkh_cmd::{DISCLOSURE_LINE, LOSS_LINE, SOUNDNESS_LINE};
use clap::Parser;
use impulse_core::terms::{IdentifierType, Kcc20Owner, Network};
use impulse_core::tx::{Kcc20State, Kcc20Template, MIN_KCC20_OUTPUT};
use impulse_core::zkh::IpstV4;
use std::path::{Path, PathBuf};
use terms_core::codec::{Dest, Leg, Terms, FUNDING_REVOCABLE, MODE_VAULT};

fn key(hexs: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&hexs[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn terms(network: u8, cash: Leg) -> Terms {
    let g = key("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let g2 = key("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    let g3 = key("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    let g4 = key("e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13");
    let p2pk = |k: [u8; 32]| {
        let mut s = vec![0x20];
        s.extend_from_slice(&k);
        s.push(0xac);
        Dest::Kas {
            version: 0,
            script: s,
        }
    };
    let external = matches!(cash, Leg::External { .. });
    Terms {
        network,
        mode: MODE_VAULT,
        nonce: 7,
        seller: g,
        buyer: g2,
        authority: Some(g3),
        asset: Leg::Kcc20 {
            cov: [0xA5; 32],
            template_hash: [0x11; 32],
            prefix_len: 100,
            suffix_len: 200,
            amount: 1,
        },
        cash,
        buyer_delivery: Dest::Owner { id_type: 0, id: g4 },
        seller_proceeds: if external { Dest::OffChain } else { p2pk(g) },
        seller_refund: Dest::Owner { id_type: 0, id: g },
        buyer_refund: if external { Dest::OffChain } else { p2pk(g2) },
        earliest: None,
        expiry: 2_000_000,
        funding: FUNDING_REVOCABLE,
        blind: [0xBD; 32],
        trade_ref: [0; 32],
    }
}

fn write(dir: &TempDir, t: &Terms) -> String {
    let path = dir.path().join("terms.v4");
    let text: String = t.encode().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

fn exec(network: Network, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut argv = vec!["impulse"];
    if network == Network::Mainnet {
        argv.extend_from_slice(&["--network", "mainnet"]);
    }
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("arguments parse");
    let connect = |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
        Err(CliError::new("TEST", "no node"))
    };
    let env = Env {
        max_value: None,
        connect: &connect,
    };
    let (mut out, mut notes) = (Vec::new(), Vec::new());
    let r = run(cli, &env, &mut out, &mut notes);
    (r, String::from_utf8(out).unwrap())
}

#[test]
fn reveal_prints_the_commitment_address_and_the_fixed_texts() {
    let dir = TempDir::new();
    let t = terms(0, Leg::Kas { amount: 50_000_000 });
    let f = write(&dir, &t);
    let (r0, o0) = exec(
        Network::Mainnet,
        &["zk", "terms", "reveal", "--terms", &f, "--leg", "0"],
    );
    r0.unwrap();
    let (r1, o1) = exec(
        Network::Mainnet,
        &["zk", "terms", "reveal", "--terms", &f, "--leg", "1"],
    );
    r1.unwrap();
    for o in [&o0, &o1] {
        assert!(o.contains("vault address: kaspa:"), "{o}");
        assert!(o.contains(DISCLOSURE_LINE) && o.contains(LOSS_LINE) && o.contains(SOUNDNESS_LINE));
        assert!(!o.contains('\u{2014}'));
    }
    let commit = |o: &str| {
        o.lines()
            .find(|l| l.starts_with("commitment: "))
            .unwrap()
            .to_string()
    };
    assert_ne!(commit(&o0), commit(&o1), "each leg has its own commitment");
}

#[test]
fn reveal_refuses_a_bad_leg_external_cash_a_wrong_network_and_a_bad_file() {
    let dir = TempDir::new();
    let f = write(&dir, &terms(0, Leg::Kas { amount: 50_000_000 }));
    let code = |net, args: &[&str]| exec(net, args).0.unwrap_err().code();
    assert_eq!(
        code(
            Network::Mainnet,
            &["zk", "terms", "reveal", "--terms", &f, "--leg", "2"]
        ),
        "ZK_H_SHAPE"
    );
    assert_eq!(
        code(
            Network::Testnet,
            &["zk", "terms", "reveal", "--terms", &f, "--leg", "0"]
        ),
        "ZK_H_TERMS_MISMATCH"
    );
    let ext = write(&dir, &terms(0, Leg::External { amount: 5 }));
    assert_eq!(
        code(
            Network::Mainnet,
            &["zk", "terms", "reveal", "--terms", &ext, "--leg", "1"]
        ),
        "ZK_H_SHAPE"
    );
    let bad = dir.path().join("bad.v4");
    std::fs::write(&bad, "0301").unwrap();
    assert_eq!(
        code(
            Network::Mainnet,
            &[
                "zk",
                "terms",
                "reveal",
                "--terms",
                bad.to_str().unwrap(),
                "--leg",
                "0"
            ]
        ),
        "ZK_H_TERMS_VERSION"
    );
    assert_eq!(
        code(
            Network::Mainnet,
            &[
                "zk",
                "terms",
                "reveal",
                "--terms",
                "/nonexistent/terms.v4",
                "--leg",
                "0"
            ]
        ),
        "ZK_H_TERMS_FILE"
    );
}

#[test]
fn the_fixed_texts_use_no_banned_word() {
    for line in [DISCLOSURE_LINE, LOSS_LINE, SOUNDNESS_LINE] {
        for w in [
            "hidden",
            "secret",
            "untraceable",
            "invisible",
            "shielded",
            "stealth",
            "mixer",
            concat!("aud", "it"),
        ] {
            assert!(!line.to_lowercase().contains(w), "{w} in {line}");
        }
    }
}

// =============================================================================================
// The builders and the IPST commands, against the fake node
// =============================================================================================
//
// Keys: the parties' key files are throwaways made at run time in a temporary directory that is
// removed (rule 1, docs/ENGINEERING-RULES.md, owner exceptions). Nothing here proves: a plan carries the zero
// placeholder, and the proof file checks run on files made by hand. The whole settle and refund
// with real receipts is `a_v4_trade_end_to_end_with_real_receipts` (ignored; ci-zk runs it).

const NODE: &str = "ws://127.0.0.1:17210";
const ASSET_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const ASSET_COV: [u8; 32] = [0xA5; 32];
const NOW: u64 = 1_500_000;
const KAS_CASH: u64 = 100_000_000;
const DECLARE: [&str; 2] = ["--kas-equivalent", "100000000"];

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A trade of terms v4 whose parties hold key files, on the fake node (testnet).
struct Keyed {
    dir: TempDir,
    sim: SimNode,
    seller: KeyFile,
    buyer: KeyFile,
    authority: KeyFile,
    terms_file: PathBuf,
    asset_template: PathBuf,
    seller_token: String,
    /// `IMPULSE_MAX_VALUE` for the next commands.
    max_value: std::cell::RefCell<Option<std::ffi::OsString>>,
    /// What the last command wrote to its notes (stderr).
    notes: std::cell::RefCell<String>,
}

impl Keyed {
    fn draft(&self, version: u8, authority: bool, mode: &str) -> serde_json::Value {
        let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let p2pk = |k: &KeyFile| format!("20{}ac", hex(&k.signer));
        let owner = |k: &KeyFile| serde_json::json!({"kind": "kcc20", "identifier_type": "pubkey", "identifier": hex(&k.signer)});
        serde_json::json!({
            "version": version, "network": "testnet", "settlement_mode": mode, "nonce": null,
            "seller_key": hex(&self.seller.signer), "buyer_key": hex(&self.buyer.signer),
            "authority_key": if authority { serde_json::json!(hex(&self.authority.signer)) } else { serde_json::Value::Null },
            "asset_leg": {"kind": "kcc20", "covenant_id": hex(&ASSET_COV),
                "template_hash": hex(&asset.template_hash()),
                "template_prefix_len": asset.prefix_len(), "template_suffix_len": asset.suffix_len(),
                "amount": "10"},
            "cash_leg": {"kind": "kas", "amount": KAS_CASH.to_string()},
            "buyer_delivery": owner(&self.buyer),
            "seller_proceeds": {"kind": "kas", "version": 0, "script": p2pk(&self.seller)},
            "seller_refund": owner(&self.seller),
            "buyer_refund": {"kind": "kas", "version": 0, "script": p2pk(&self.buyer)},
            "earliest_daa": null, "expiry_daa": (NOW + 864_000).to_string(),
            "funding_mode": "revocable", "trade_ref": hex(&[0x5E; 32]),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn exec(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse", "zk"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("arguments parse");
        let sim = self.sim.clone();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(Box::new(sim.clone()))
        };
        let max_value = self.max_value.borrow().clone();
        let env = Env {
            max_value: max_value.as_deref(),
            connect: &connect,
        };
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let r = run(cli, &env, &mut out, &mut notes);
        *self.notes.borrow_mut() = String::from_utf8(notes).unwrap();
        (r, String::from_utf8(out).unwrap())
    }

    fn run(&self, args: &[&str]) -> String {
        let (r, out) = self.exec(args);
        r.unwrap_or_else(|e| panic!("{args:?}: {e}"));
        out
    }

    fn refuse(&self, args: &[&str]) -> &'static str {
        let (r, out) = self.exec(args);
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }

    fn new() -> Self {
        let dir = TempDir::new();
        let (seller, buyer, authority) = (key_file(), key_file(), key_file());
        std::fs::write(dir.path().join("asset.json"), ASSET_JSON).unwrap();
        let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let sim = SimNode::memory(SimState::new(Network::Testnet, NOW, 0));
        let seller_token;
        {
            let mut state = sim.state.borrow_mut();
            for k in [&seller, &buyer, &authority] {
                for amount in [400_000_000_000, 300_000_000_000] {
                    state.add_utxo(
                        address_script(&p2pk_address(&k.signer, Network::Testnet)),
                        amount,
                        None,
                    );
                }
            }
            let held = Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::PubKey,
                    identifier: seller.signer,
                },
                1_000,
            );
            let o = state.add_utxo(
                asset.script_public_key(&held).unwrap(),
                MIN_KCC20_OUTPUT,
                Some(ASSET_COV),
            );
            seller_token = format!("{}:1000", crate::funds::outpoint_text(&o));
        }
        let mut t = Self {
            terms_file: dir.path().join("terms.v4"),
            asset_template: dir.path().join("asset.json"),
            dir,
            sim,
            seller,
            buyer,
            authority,
            seller_token,
            max_value: Default::default(),
            notes: Default::default(),
        };
        let draft = t.draft(4, true, "vault");
        let draft_file = t.path("draft.json");
        std::fs::write(&draft_file, draft.to_string()).unwrap();
        let out = t.terms_file.clone();
        t.run(&[
            "terms",
            "new-hashed",
            "--draft",
            s(&draft_file),
            "--daa",
            &NOW.to_string(),
            "--out",
            s(&out),
            "--role",
            "seller",
            "--my-key",
            &hex(&t.seller.signer),
            DECLARE[0],
            DECLARE[1],
        ]);
        t.terms_file = out;
        t
    }

    fn pay(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, Network::Testnet).to_string()
    }

    fn node_args(&self) -> Vec<String> {
        ["--node", NODE, "--asset-template", s(&self.asset_template)]
            .iter()
            .map(|x| x.to_string())
            .collect()
    }

    /// Builds with `build` (its own arguments), signs as `key` in `role`, submits.
    fn build_sign_submit(&self, name: &str, build: &[String], key: &KeyFile, role: &str) -> String {
        let unsigned = self.path(&format!("{name}.ipst"));
        let signed = self.path(&format!("{name}.signed"));
        let mut args: Vec<String> = build.to_vec();
        args.extend(self.node_args());
        args.extend(
            [
                "--terms",
                s(&self.terms_file),
                "--out",
                s(&unsigned),
                DECLARE[0],
                DECLARE[1],
            ]
            .iter()
            .map(|x| x.to_string()),
        );
        self.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
        let mut sign: Vec<String> = [
            "ipst",
            "sign",
            "--ipst",
            s(&unsigned),
            "--terms",
            s(&self.terms_file),
            "--key-file",
            s(&key.path),
            "--role",
            role,
            "--my-key",
            &hex(&key.signer),
            "--out",
            s(&signed),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        sign.extend(self.node_args());
        self.run(&sign.iter().map(String::as_str).collect::<Vec<_>>());
        let mut submit: Vec<String> = ["submit", "--ipst", s(&signed)]
            .iter()
            .map(|x| x.to_string())
            .collect();
        submit.extend(self.node_args());
        self.run(&submit.iter().map(String::as_str).collect::<Vec<_>>())
    }

    fn fund_both(&self) {
        let (sp, bp) = (self.pay(&self.seller), self.pay(&self.buyer));
        let sk = hex(&self.seller.signer);
        let a: Vec<String> = [
            "fund",
            "build",
            "--leg",
            "asset",
            "--role",
            "seller",
            "--my-key",
            &sk,
            "--pay-from",
            &sp,
            "--token",
            &self.seller_token,
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        let out = self.build_sign_submit("fund-asset", &a, &self.seller, "seller");
        assert!(out.contains("submitted: "), "{out}");
        let bk = hex(&self.buyer.signer);
        let a: Vec<String> = [
            "fund",
            "build",
            "--leg",
            "cash",
            "--role",
            "buyer",
            "--my-key",
            &bk,
            "--pay-from",
            &bp,
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        let out = self.build_sign_submit("fund-cash", &a, &self.buyer, "buyer");
        assert!(out.contains("submitted: "), "{out}");
    }

    fn settle_args(&self, out: &Path) -> Vec<String> {
        let mut v: Vec<String> = [
            "settle",
            "build",
            "--terms",
            s(&self.terms_file),
            "--pay-from",
            &self.pay(&self.authority),
            "--out",
            s(out),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        v.extend(self.node_args());
        v
    }
}

#[test]
fn terms_new_hashed_writes_the_hex_file_and_reads_it_back() {
    let t = Keyed::new();
    let text = std::fs::read_to_string(&t.terms_file).unwrap();
    assert!(text
        .trim()
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert!(text.starts_with("04"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&t.terms_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the blind is private");
    }
    // The file exists: not overwritten.
    let again = t.path("draft.json");
    let args = [
        "terms",
        "new-hashed",
        "--draft",
        s(&again),
        "--daa",
        "1500000",
        "--out",
        s(&t.terms_file),
        "--role",
        "seller",
        "--my-key",
        &hex(&t.seller.signer),
        DECLARE[0],
        DECLARE[1],
    ];
    assert_eq!(t.refuse(&args), "CLI_OUTPUT_EXISTS");
    // A second file for the same draft has another blind, so another terms hash and other vaults.
    let second = t.path("second.v4");
    let out1 = t.run(&[
        "terms",
        "new-hashed",
        "--draft",
        s(&again),
        "--daa",
        "1500000",
        "--out",
        s(&second),
        "--role",
        "seller",
        "--my-key",
        &hex(&t.seller.signer),
        DECLARE[0],
        DECLARE[1],
    ]);
    let second_text = std::fs::read_to_string(&second).unwrap();
    // The nonce is drawn too, so compare the blind position: the last 64 bytes are blind and
    // trade_ref.
    assert_ne!(text.trim(), second_text.trim());
    assert!(
        out1.contains(DISCLOSURE_LINE) && out1.contains(LOSS_LINE) && out1.contains(SOUNDNESS_LINE)
    );
    assert!(out1.contains("asset vault: kaspatest:"), "{out1}");
    assert!(out1.contains("cash vault: kaspatest:"), "{out1}");
}

#[test]
fn terms_new_hashed_refusals() {
    let t = Keyed::new();
    let try_draft = |name: &str, draft: serde_json::Value, extra: &[&str]| -> &'static str {
        let f = t.path(&format!("{name}.json"));
        std::fs::write(&f, draft.to_string()).unwrap();
        let out = t.path(&format!("{name}.v4"));
        let mut args = vec![
            "terms",
            "new-hashed",
            "--draft",
            s(&f),
            "--daa",
            "1500000",
            "--out",
            s(&out),
            "--role",
            "seller",
            "--my-key",
            "",
        ];
        let sk = hex(&t.seller.signer);
        args[11] = &sk;
        args.extend_from_slice(&DECLARE);
        args.extend_from_slice(extra);
        t.refuse(&args)
    };
    assert_eq!(
        try_draft("v3", t.draft(3, true, "vault"), &[]),
        "ZK_H_TERMS_VERSION"
    );
    assert_eq!(
        try_draft("noauth", t.draft(4, false, "vault"), &[]),
        "ZK_H_AUTHORITY_REQUIRED"
    );
    assert_eq!(
        try_draft("direct", t.draft(4, true, "direct"), &[]),
        "ZK_H_TERMS_DIRECT"
    );
    assert_eq!(
        try_draft("cap", t.draft(4, true, "vault"), &["--i-accept-the-risk"]),
        "ZK_H_CAP_OVERRIDE"
    );
    let mut same = t.draft(4, true, "vault");
    same["buyer_key"] = same["seller_key"].clone();
    assert_eq!(try_draft("same", same, &[]), "TERMS_PARTIES_NOT_DISTINCT");
}

#[test]
fn a_terms_file_that_is_not_exactly_canonical_hex_is_refused_and_no_command_lifts_the_cap() {
    let t = Keyed::new();
    let text = std::fs::read_to_string(&t.terms_file).unwrap();
    // A space inside the hex parses (whitespace is ignored) but is not the file terms new-hashed
    // writes: every command that reads the file refuses it by name.
    let spaced = t.path("spaced.v4");
    std::fs::write(&spaced, format!("{} {}", &text[..40], &text[40..])).unwrap();
    let plan = t.path("x.ipst");
    let bk = hex(&t.buyer.signer);
    let args: Vec<String> = [
        "fund",
        "build",
        "--terms",
        s(&spaced),
        "--leg",
        "cash",
        "--role",
        "buyer",
        "--my-key",
        &bk,
        "--pay-from",
        &t.pay(&t.buyer),
        "--out",
        s(&plan),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .chain(t.node_args())
    .collect();
    assert_eq!(
        t.refuse(&args.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_TERMS_FILE"
    );
    assert!(!plan.exists());
    // Upper case digits are not a terms file either.
    let upper = t.path("upper.v4");
    std::fs::write(&upper, text.to_uppercase()).unwrap();
    assert_eq!(
        t.refuse(&[
            "address",
            "--terms",
            s(&upper),
            "--daa",
            "1500000",
            "--role",
            "seller",
            "--my-key",
            &hex(&t.seller.signer),
            DECLARE[0],
            DECLARE[1]
        ]),
        "ZK_H_TERMS_VERSION"
    );
    // The cap has no override on the builders either.
    let mut with_flag = args.clone();
    with_flag[3] = s(&t.terms_file).to_string();
    with_flag.push("--i-accept-the-risk".into());
    assert_eq!(
        t.refuse(&with_flag.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_CAP_OVERRIDE"
    );
}

#[test]
fn address_and_verify_need_the_terms_and_both_addresses() {
    let t = Keyed::new();
    let addr = t.run(&[
        "address",
        "--terms",
        s(&t.terms_file),
        "--daa",
        "1500000",
        "--role",
        "seller",
        "--my-key",
        &hex(&t.seller.signer),
        DECLARE[0],
        DECLARE[1],
    ]);
    let line = |l: &str| {
        addr.lines()
            .find_map(|x| x.strip_prefix(l))
            .unwrap()
            .to_string()
    };
    let (asset, cash) = (line("asset vault: "), line("cash vault: "));
    let verify = |a: &str, c: Option<&str>| {
        let mut args = vec![
            "verify",
            "--terms",
            s(&t.terms_file),
            "--asset-address",
            a,
            "--daa",
            "1500000",
            "--role",
            "seller",
            "--my-key",
        ];
        let sk = hex(&t.seller.signer);
        args.push(&sk);
        args.extend_from_slice(&DECLARE);
        if let Some(c) = c {
            args.extend(["--cash-address", c]);
        }
        t.exec(&args)
    };
    let (r, out) = verify(&asset, Some(&cash));
    r.unwrap();
    assert!(
        out.contains("(verified)") && out.contains("ok: terms "),
        "{out}"
    );
    assert!(out.contains(DISCLOSURE_LINE));
    // Swapped, wrong, or missing addresses.
    for (a, c) in [(&cash, Some(&asset)), (&asset, None)] {
        let (r, out) = verify(a, c.map(String::as_str));
        assert_eq!(r.unwrap_err().code(), "ZK_H_VERIFY_ADDRESS_MISMATCH");
        assert_eq!(out, "");
    }
    // List options belong to terms v3.
    let m = t.path("m.json");
    let sk = hex(&t.seller.signer);
    let (r, _) = t.exec(&[
        "verify",
        "--terms",
        s(&t.terms_file),
        "--asset-address",
        &asset,
        "--cash-address",
        &cash,
        "--manifest",
        s(&m),
        "--daa",
        "1500000",
        "--role",
        "seller",
        "--my-key",
        &sk,
        DECLARE[0],
        DECLARE[1],
    ]);
    assert_eq!(r.unwrap_err().code(), "TX_WRONG_MODE");
    // prove-args has nothing to say about terms v4.
    let (r, _) = t.exec(&["prove-args", "--terms", s(&t.terms_file)]);
    assert_eq!(r.unwrap_err().code(), "TX_WRONG_MODE");
}

#[test]
fn a_funded_v4_trade_plans_signs_and_refuses_what_it_should() {
    let t = Keyed::new();
    t.fund_both();
    // The settle plan: no proofs yet.
    let plan = t.path("settle.ipst");
    let out = t.run(
        &t.settle_args(&plan)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert!(out.contains("has no proof yet"), "{out}");
    assert!(out.contains("a vault input has no proof yet"), "{out}");
    let ipst = IpstV4::from_json(&std::fs::read_to_string(&plan).unwrap()).unwrap();
    assert!(!ipst.has_all_proofs().unwrap());
    // The witness of each vault input.
    let wdir = t.path("witness");
    let out = t.run(&["witness", "--ipst", s(&plan), "--out-dir", s(&wdir)]);
    assert!(out.contains("impulse-zk-prove-terms --witness "), "{out}");
    assert!(
        out.contains("input 0 (asset vault)") && out.contains("input 1 (cash vault)"),
        "{out}"
    );
    assert_eq!(std::fs::read_dir(&wdir).unwrap().count(), 2);
    // Each witness file is what the prover reads: it parses, and the statement holds on it.
    for name in ["witness-input0-leg0.bin", "witness-input1-leg1.bin"] {
        let w = terms_core::Witness::from_bytes(&std::fs::read(wdir.join(name)).unwrap()).unwrap();
        terms_core::statement(&w, terms_core::StatementOptions { curve_checks: true }).unwrap();
        assert!(
            out.contains(&hex(&terms_core::hashes::sha256(&w.journal))),
            "{name}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(wdir.join("witness-input0-leg0.bin"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a witness holds the terms");
    }
    // Not twice into one directory.
    assert_eq!(
        t.refuse(&["witness", "--ipst", s(&plan), "--out-dir", s(&wdir)]),
        "CLI_OUTPUT_EXISTS"
    );
    // The authority signs the plan: its terms check passes (the transaction is what the v4
    // builders make from the document's inputs), then the vault inputs are signed.
    let signed = t.path("settle.signed");
    let mut sign: Vec<String> = [
        "ipst",
        "sign",
        "--ipst",
        s(&plan),
        "--terms",
        s(&t.terms_file),
        "--key-file",
        s(&t.authority.path),
        "--role",
        "authority",
        "--my-key",
        &hex(&t.authority.signer),
        "--out",
        s(&signed),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    sign.extend(t.node_args());
    t.run(&sign.iter().map(String::as_str).collect::<Vec<_>>());
    let after = IpstV4::from_json(&std::fs::read_to_string(&signed).unwrap()).unwrap();
    assert!(
        after.pending().is_empty(),
        "the authority pays the fee here, so every slot is signed"
    );
    // The cap has no override on v4.
    let mut capped = sign.clone();
    let blocked = t.path("blocked.signed");
    capped[sign.iter().position(|x| x == "--out").unwrap() + 1] = s(&blocked).to_string();
    capped.push("--i-accept-the-risk".into());
    assert_eq!(
        t.refuse(&capped.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_CAP_OVERRIDE"
    );
    // A plan cannot be finalized: the proofs are missing.
    let raw = t.path("raw.txt");
    assert_eq!(
        t.refuse(&["ipst", "raw", "--ipst", s(&signed), "--out", s(&raw)]),
        "ZK_H_PROOF_MALFORMED"
    );
    // A proof file for another transaction is refused, with nothing written.
    let bad = t.path("bad.proof.json");
    let journal = vec![7u8; 40];
    let proof = serde_json::json!({
        "format": "impulse-zk-proof/1",
        "proof": hex(&[3u8; 128]),
        "journal": hex(&journal),
        "journal_hash": hex(&terms_core::hashes::sha256(&journal)),
        "image_id": hex(&impulse_core::zkh::check().unwrap().image_id()),
        "risc0_zkvm": "3.0.4",
        "groth16_prover_image": "x",
    });
    std::fs::write(&bad, proof.to_string()).unwrap();
    let out2 = t.path("with-bad-proof.ipst");
    let mut args = t.settle_args(&out2);
    args.extend(["--proof".into(), s(&bad).to_string()]);
    assert_eq!(
        t.refuse(&args.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_PROOF_INVALID"
    );
    assert!(!out2.exists());
    // A malformed proof file.
    std::fs::write(&bad, "{}").unwrap();
    assert_eq!(
        t.refuse(&args.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_PROOF_MALFORMED"
    );
    // The refund plan of the cash leg by the depositor.
    let rplan = t.path("refund.ipst");
    let mut r: Vec<String> = [
        "refund",
        "build",
        "--terms",
        s(&t.terms_file),
        "--leg",
        "cash",
        "--signer",
        "depositor",
        "--pay-from",
        &t.pay(&t.buyer),
        "--out",
        s(&rplan),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    r.extend(t.node_args());
    let out = t.run(&r.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.contains("has no proof yet"), "{out}");
    let rp = IpstV4::from_json(&std::fs::read_to_string(&rplan).unwrap()).unwrap();
    assert_eq!(rp.proofs().unwrap().len(), 1);
}

#[test]
fn the_v4_value_cap_applies_to_funding_only() {
    let t = Keyed::new();
    // New value entering is capped: with the cap below the cash leg, funding is refused.
    *t.max_value.borrow_mut() = Some("50000000".into());
    let fund = |t: &Keyed, out: &Path| -> Vec<String> {
        let mut v: Vec<String> = [
            "fund",
            "build",
            "--leg",
            "cash",
            "--role",
            "buyer",
            "--my-key",
            &hex(&t.buyer.signer),
            "--pay-from",
            &t.pay(&t.buyer),
            "--terms",
            s(&t.terms_file),
            "--out",
            s(out),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        v.extend(t.node_args());
        v
    };
    let refused = t.path("refused.ipst");
    assert_eq!(
        t.refuse(
            &fund(&t, &refused)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        ),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    assert!(!refused.exists());
    // A vault funded under a higher cap (or by anyone at the address) is then above the cap.
    *t.max_value.borrow_mut() = None;
    t.fund_both();
    *t.max_value.borrow_mut() = Some("50000000".into());
    // Settle and refund plans are built with a warning.
    let plan = t.path("settle.ipst");
    let out = t.run(
        &t.settle_args(&plan)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert!(out.contains("has no proof yet"), "{out}");
    assert!(out.contains("above the cap, not blocked"), "{out}");
    assert!(
        t.notes.borrow().starts_with("warning: "),
        "{}",
        t.notes.borrow()
    );
    let rplan = t.path("refund.ipst");
    let mut r: Vec<String> = [
        "refund",
        "build",
        "--terms",
        s(&t.terms_file),
        "--leg",
        "cash",
        "--signer",
        "depositor",
        "--pay-from",
        &t.pay(&t.buyer),
        "--out",
        s(&rplan),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    r.extend(t.node_args());
    t.run(&r.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(
        t.notes.borrow().starts_with("warning: "),
        "{}",
        t.notes.borrow()
    );
    // Signing either plan proceeds, with the warning.
    for (ipst, key, role, name) in [
        (&plan, &t.authority, "authority", "s.signed"),
        (&rplan, &t.buyer, "buyer", "r.signed"),
    ] {
        let signed = t.path(name);
        let mut sign: Vec<String> = [
            "ipst",
            "sign",
            "--ipst",
            s(ipst),
            "--terms",
            s(&t.terms_file),
            "--key-file",
            s(&key.path),
            "--role",
            role,
            "--my-key",
            &hex(&key.signer),
            "--out",
            s(&signed),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        sign.extend(t.node_args());
        let out = t.run(&sign.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(signed.exists(), "{name}");
        assert!(out.contains("above the cap, not blocked"), "{out}");
        assert!(
            t.notes.borrow().starts_with("warning: "),
            "{}",
            t.notes.borrow()
        );
    }
    // Within the cap there is no warning.
    *t.max_value.borrow_mut() = None;
    let plan2 = t.path("settle2.ipst");
    t.run(
        &t.settle_args(&plan2)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(*t.notes.borrow(), "");
}

#[test]
fn an_ipst_of_another_version_is_routed_or_refused_by_version() {
    let t = Keyed::new();
    t.fund_both();
    let plan = t.path("settle.ipst");
    t.run(
        &t.settle_args(&plan)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let text = std::fs::read_to_string(&plan).unwrap();
    let as_v4 = t.path("as4.ipst");
    std::fs::write(&as_v4, text.replacen("\"ipst\": 5", "\"ipst\": 4", 1)).unwrap();
    let raw = t.path("raw.txt");
    // Version 4 goes to the v3 reader, which refuses these terms.
    let (r, _) = t.exec(&["ipst", "raw", "--ipst", s(&as_v4), "--out", s(&raw)]);
    assert!(r.is_err());
    assert!(!raw.exists());
}

// =============================================================================================
// Real receipts, end to end (ignored: minutes of proving each; scripts/ci-zk.sh runs them)
// =============================================================================================

/// Proves a witness file with impulse-zk-prove-terms, which must be built
/// (`cd circuits && cargo build --release --locked -p impulse-zk-prover --bin
/// impulse-zk-prove-terms`), and returns the proof file.
fn prove(witness: &Path, out: &Path) {
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/target/release/impulse-zk-prove-terms");
    assert!(bin.is_file(), "build the prover first: {}", bin.display());
    let status = std::process::Command::new(&bin)
        .args(["--witness", s(witness), "--out", s(out)])
        .status()
        .expect("run the prover");
    assert!(status.success(), "the prover refused {}", witness.display());
}

#[test]
#[ignore = "makes real Groth16 proofs (minutes each, Docker); run by scripts/ci-zk.sh"]
fn a_v4_trade_end_to_end_with_real_receipts() {
    let t = Keyed::new();
    t.fund_both();
    let authority_pay = t.pay(&t.authority);
    // Settle: plan, witnesses, one receipt per vault input, build with them, sign, submit.
    let plan = t.path("settle.ipst");
    t.run(
        &t.settle_args(&plan)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let wdir = t.path("witness");
    t.run(&["witness", "--ipst", s(&plan), "--out-dir", s(&wdir)]);
    let (p0, p1) = (t.path("proof0.json"), t.path("proof1.json"));
    prove(&wdir.join("witness-input0-leg0.bin"), &p0);
    prove(&wdir.join("witness-input1-leg1.bin"), &p1);
    let _ = authority_pay;
    let with = t.path("settle-proved.ipst");
    let mut args = t.settle_args(&with);
    args.extend([
        "--proof".into(),
        s(&p0).to_string(),
        "--proof-cash".into(),
        s(&p1).to_string(),
    ]);
    let out = t.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!out.contains("has no proof yet"), "{out}");
    // A proof of the other vault input is refused.
    let mut swapped = t.settle_args(&t.path("swapped.ipst"));
    swapped.extend([
        "--proof".into(),
        s(&p1).to_string(),
        "--proof-cash".into(),
        s(&p0).to_string(),
    ]);
    assert_eq!(
        t.refuse(&swapped.iter().map(String::as_str).collect::<Vec<_>>()),
        "ZK_H_PROOF_INVALID"
    );
    // The authority signs the vault inputs and pays the fee input; the engine runs every input,
    // the two receipts included, when the node is given the transaction.
    let signed = t.path("settle.signed");
    let mut sign: Vec<String> = [
        "ipst",
        "sign",
        "--ipst",
        s(&with),
        "--terms",
        s(&t.terms_file),
        "--key-file",
        s(&t.authority.path),
        "--role",
        "authority",
        "--my-key",
        &hex(&t.authority.signer),
        "--out",
        s(&signed),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    sign.extend(t.node_args());
    t.run(&sign.iter().map(String::as_str).collect::<Vec<_>>());
    // A proof with one flipped bit passes every check of the build (its journal and image ID are
    // right) and is refused by the pinned engine when the signed document is finalized.
    let mut flipped: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p0).unwrap()).unwrap();
    let mut bytes = crate::json::unhex(flipped["proof"].as_str().unwrap()).unwrap();
    bytes[5] ^= 1;
    flipped["proof"] = serde_json::Value::String(hex(&bytes));
    let p0_bad = t.path("proof0-flipped.json");
    std::fs::write(&p0_bad, flipped.to_string()).unwrap();
    let bad_plan = t.path("settle-flipped.ipst");
    let mut args = t.settle_args(&bad_plan);
    args.extend([
        "--proof".into(),
        s(&p0_bad).to_string(),
        "--proof-cash".into(),
        s(&p1).to_string(),
    ]);
    t.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let bad_signed = t.path("settle-flipped.signed");
    let mut sign_bad: Vec<String> = [
        "ipst",
        "sign",
        "--ipst",
        s(&bad_plan),
        "--terms",
        s(&t.terms_file),
        "--key-file",
        s(&t.authority.path),
        "--role",
        "authority",
        "--my-key",
        &hex(&t.authority.signer),
        "--out",
        s(&bad_signed),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    sign_bad.extend(t.node_args());
    t.run(&sign_bad.iter().map(String::as_str).collect::<Vec<_>>());
    let raw_bad = t.path("raw-flipped.txt");
    assert_eq!(
        t.refuse(&[
            "ipst",
            "raw",
            "--ipst",
            s(&bad_signed),
            "--out",
            s(&raw_bad)
        ]),
        "ZK_H_PROOF_INVALID"
    );
    assert!(!raw_bad.exists());
    // A flipped proof bit is refused by the engine before the node accepts anything.
    let ipst = IpstV4::from_json(&std::fs::read_to_string(&signed).unwrap()).unwrap();
    let tx = ipst
        .finalize()
        .expect("the real receipts verify in the engine");
    let mut bad = tx.clone();
    let at = bad.inputs[0]
        .signature_script
        .windows(128)
        .position(|w| w == ipst.proofs().unwrap()[0].1.unwrap().as_bytes())
        .unwrap();
    bad.inputs[0].signature_script[at] ^= 1;
    bad.finalize();
    let height = t.sim.state.borrow().height();
    assert!(t.sim.state.borrow_mut().submit(&bad).is_err());
    assert_eq!(t.sim.state.borrow().height(), height);
    let mut submit: Vec<String> = ["submit", "--ipst", s(&signed)]
        .iter()
        .map(|x| x.to_string())
        .collect();
    submit.extend(t.node_args());
    let out = t.run(&submit.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.contains("submitted: "), "{out}");

    // Refund: a second trade, the cash leg funded only; the buyer takes it back with a receipt.
    let r = Keyed::new();
    let bp = r.pay(&r.buyer);
    let bk = hex(&r.buyer.signer);
    let fund: Vec<String> = [
        "fund",
        "build",
        "--leg",
        "cash",
        "--role",
        "buyer",
        "--my-key",
        &bk,
        "--pay-from",
        &bp,
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    let out = r.build_sign_submit("fund-cash", &fund, &r.buyer, "buyer");
    assert!(out.contains("submitted: "), "{out}");
    let rplan = r.path("refund.ipst");
    let mut rb: Vec<String> = [
        "refund",
        "build",
        "--terms",
        s(&r.terms_file),
        "--leg",
        "cash",
        "--signer",
        "depositor",
        "--pay-from",
        &bp,
        "--out",
        s(&rplan),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    rb.extend(r.node_args());
    r.run(&rb.iter().map(String::as_str).collect::<Vec<_>>());
    let rw = r.path("rwitness");
    r.run(&["witness", "--ipst", s(&rplan), "--out-dir", s(&rw)]);
    let rproof = r.path("rproof.json");
    prove(&rw.join("witness-input0-leg1.bin"), &rproof);
    let rwith = r.path("refund-proved.ipst");
    let mut rb2: Vec<String> = rb.clone();
    let out_at = rb2.iter().position(|x| x == "--out").unwrap() + 1;
    rb2[out_at] = s(&rwith).to_string();
    rb2.extend(["--proof".into(), s(&rproof).to_string()]);
    r.run(&rb2.iter().map(String::as_str).collect::<Vec<_>>());
    let rsigned = r.path("refund.signed");
    let mut rs: Vec<String> = [
        "ipst",
        "sign",
        "--ipst",
        s(&rwith),
        "--terms",
        s(&r.terms_file),
        "--key-file",
        s(&r.buyer.path),
        "--role",
        "buyer",
        "--my-key",
        &bk,
        "--out",
        s(&rsigned),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    rs.extend(r.node_args());
    r.run(&rs.iter().map(String::as_str).collect::<Vec<_>>());
    let mut submit: Vec<String> = ["submit", "--ipst", s(&rsigned)]
        .iter()
        .map(|x| x.to_string())
        .collect();
    submit.extend(r.node_args());
    let out = r.run(&submit.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(out.contains("submitted: "), "{out}");
}

/// `TOKEN_FOREIGN_AT_VAULT` is retired (I26, spec/ERRORS.md "Retired and changed codes"): known
/// limitation L20 is closed in every template, so a token of the other leg's covenant owned by a
/// v4 vault's script hash cannot move. The v4 builders no longer look for it, as the v1 builders
/// do not, and build as they would without it.
#[test]
fn a_token_of_the_other_legs_covenant_at_a_v4_vault_is_not_warned_about() {
    let t = Keyed::new();
    t.fund_both();
    let text = std::fs::read_to_string(&t.terms_file).unwrap();
    let terms = impulse_core::zkh::ValidatedTermsV4::from_core(
        impulse_core::zkh::parse_terms_file(&text).unwrap(),
    )
    .expect("the terms file the CLI wrote is valid terms v4");
    let cash_vault =
        impulse_core::zkh::existing_vault(&terms, impulse_core::template::LegIndex::Cash)
            .expect("a KAS cash leg has a vault");
    let refund = |out: &str| -> Vec<String> {
        let mut v: Vec<String> = [
            "refund",
            "build",
            "--terms",
            s(&t.terms_file),
            "--leg",
            "cash",
            "--signer",
            "depositor",
            "--pay-from",
            &t.pay(&t.buyer),
            "--out",
            s(&t.path(out)),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        v.extend(t.node_args());
        v
    };
    let go = |args: Vec<String>| t.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    for args in [refund("r1"), t.settle_args(&t.path("s1"))] {
        let out = go(args);
        assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "control: {out}");
    }
    // The seller's asset token sent by mistake to the cash vault's script hash.
    let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
    let misdirected = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: cash_vault.script_hash(),
        },
        10,
    );
    t.sim.state.borrow_mut().add_utxo(
        asset.script_public_key(&misdirected).unwrap(),
        MIN_KCC20_OUTPUT,
        Some(ASSET_COV),
    );
    for args in [refund("r2"), t.settle_args(&t.path("s2"))] {
        let out = go(args);
        assert!(out.contains("wrote: "), "{out}");
        assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "{out}");
    }
    let fund: Vec<String> = [
        "fund",
        "build",
        "--leg",
        "cash",
        "--role",
        "buyer",
        "--my-key",
        &hex(&t.buyer.signer),
        "--pay-from",
        &t.pay(&t.buyer),
        "--terms",
        s(&t.terms_file),
        "--out",
        s(&t.path("f2")),
        DECLARE[0],
        DECLARE[1],
    ]
    .iter()
    .map(|x| x.to_string())
    .chain(t.node_args())
    .collect();
    let out = go(fund);
    assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "{out}");
}
