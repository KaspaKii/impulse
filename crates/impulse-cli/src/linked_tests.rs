// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse linked` end to end in process, against the in-memory fake node (`sim`), which runs
//! every submitted input in the pinned script engine: a repo shape of two KAS legs opens, settles,
//! returns and settles again, with the gate, the receipts and the pair check between. Each refusal
//! has a failing case beside an accepted control, and every refused command is checked to have
//! printed nothing. Keys are throwaway keys generated at run time into temporary directories that
//! are removed; no key literal exists.

use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, p2pk_address};
use crate::json::hex;
use crate::linked_cmd::{parse_receipt, parse_sheet_file, render_receipt};
use crate::node::Node;
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::testutil::TempDir;
use crate::v2_terms::terms_json;
use clap::Parser;
use impulse_core::linked::Role;
use impulse_core::terms::{FundingMode, IdentifierType, Leg, LegKind, Network};
use impulse_core::v2::{DestinationV2, LegV2, TermsV2, VaultV2};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const NODE: &str = "ws://127.0.0.1:17220";
const START_DAA: u64 = 1_000_000;
const OPENING_EXPIRY: u64 = START_DAA + 864_000;
const RETURN_EARLIEST: u64 = OPENING_EXPIRY + 36_000;
const RETURN_EXPIRY: u64 = RETURN_EARLIEST + 864_000;
const LEG_0: u64 = 40_000_000;
const LEG_1: u64 = 50_000_000;
const BACK_0: u64 = 40_400_000;
const BACK_1: u64 = 50_000_000;
const DECLARE: [&str; 2] = ["--kas-equivalent", "500000000"];

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn owned(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("no {key}: line in\n{out}"))
        .to_string()
}

struct World {
    dir: TempDir,
    sim: SimNode,
    parties: [KeyFile; 2],
    payer: KeyFile,
}

impl World {
    fn new() -> Self {
        let dir = TempDir::new();
        let mut state = SimState::new(Network::Testnet, START_DAA, 0);
        let parties = [key_file(), key_file()];
        let payer = key_file();
        for k in parties.iter().chain([&payer]) {
            let spk = address_script(&p2pk_address(&k.signer, Network::Testnet));
            for amount in [400_000_000_000, 300_000_000_000] {
                state.add_utxo(spk.clone(), amount, None);
            }
        }
        Self {
            dir,
            sim: SimNode::memory(state),
            parties,
            payer,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn addr(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, Network::Testnet).to_string()
    }

    fn set_daa(&self, daa: u64) {
        self.sim.state.borrow_mut().virtual_daa = daa;
    }

    fn sink(&self) -> String {
        hex(&self.sim.state.borrow().sink())
    }

    /// Two KAS legs: party 0 deposits LEG_0 for party 1, party 1 deposits LEG_1 for party 0.
    fn draft_terms(&self) -> TermsV2 {
        let pubkey = |k: [u8; 32]| DestinationV2 {
            identifier_type: IdentifierType::PubKey,
            identifier: k,
        };
        let leg = |from: usize, amount: u64| LegV2 {
            depositor_key: self.parties[from].signer,
            asset: Leg {
                kind: LegKind::Kas,
                amount,
            },
            delivery: pubkey(self.parties[1 - from].signer),
            refund: pubkey(self.parties[from].signer),
        };
        TermsV2 {
            version: 2,
            network: Network::Testnet,
            nonce: rand::random(),
            authority_key: None,
            legs: vec![leg(0, LEG_0), leg(1, LEG_1)],
            earliest_daa: None,
            expiry_daa: OPENING_EXPIRY,
            funding_mode: FundingMode::Revocable,
            partial: None,
            trade_ref: [0; 32],
        }
    }

    fn write_draft(&self, name: &str, t: &TermsV2) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, terms_json(t).render()).unwrap();
        p
    }

    fn exec_argv(&self, argv: Vec<&str>) -> (Result<(), CliError>, String) {
        let cli = Cli::try_parse_from(argv).expect("arguments parse");
        let sim = self.sim.clone();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(Box::new(sim.clone()))
        };
        let env = Env {
            max_value: None::<&OsStr>,
            connect: &connect,
        };
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let r = run(cli, &env, &mut out, &mut notes);
        (r, String::from_utf8(out).unwrap())
    }

    fn exec(&self, family: &str, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse", family];
        argv.extend_from_slice(args);
        self.exec_argv(argv)
    }

    fn go(&self, family: &str, args: &[String]) -> String {
        let (r, out) = self.exec(family, &strs(args));
        r.unwrap_or_else(|e| panic!("{family} {args:?}: {e}"));
        out
    }

    /// A refused command: its code, after checking it printed nothing.
    fn no(&self, family: &str, args: &[String]) -> &'static str {
        let (r, out) = self.exec(family, &strs(args));
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }

    /// Writes a sheet with the given return terms; returns its path.
    fn sheet(
        &self,
        name: &str,
        edit: impl FnOnce(&mut TermsV2),
        back: [u64; 2],
        earliest: u64,
        expiry: u64,
    ) -> Vec<String> {
        let mut t = self.draft_terms();
        edit(&mut t);
        let draft = self.write_draft(&format!("{name}.draft.json"), &t);
        let out = self.path(&format!("{name}.sheet.json"));
        owned(&[
            "new",
            "--draft",
            s(&draft),
            "--return-amount-0",
            &back[0].to_string(),
            "--return-amount-1",
            &back[1].to_string(),
            "--return-earliest-daa",
            &earliest.to_string(),
            "--return-expiry-daa",
            &expiry.to_string(),
            "--out",
            s(&out),
            "--daa",
            &START_DAA.to_string(),
        ])
    }

    fn standard_sheet(&self, name: &str) -> PathBuf {
        let args = self.sheet(
            name,
            |_| {},
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY,
        );
        self.go("linked", &args);
        self.path(&format!("{name}.sheet.json"))
    }

    /// Writes the derived terms file of a role.
    fn terms_file(&self, sheet: &Path, role: &str, name: &str) -> PathBuf {
        let out = self.path(name);
        self.go(
            "linked",
            &owned(&[
                "terms",
                "--sheet",
                s(sheet),
                "--role",
                role,
                "--out",
                s(&out),
            ]),
        );
        out
    }

    fn sign_args(&self, ipst: &Path, k: &KeyFile, out: &Path) -> Vec<String> {
        let text = std::fs::read_to_string(ipst).unwrap();
        let agreed = match impulse_core::v2::read_ipst(&text) {
            Ok(impulse_core::v2::AnyIpst::V2(i)) => hex(&i.terms().terms_hash()),
            _ => hex(&[0; 32]),
        };
        let role = if self.parties.iter().any(|p| p.signer == k.signer) {
            "depositor"
        } else {
            "payer"
        };
        let mut a = owned(&[
            "ipst",
            "sign",
            "--ipst",
            s(ipst),
            "--terms-hash",
            &agreed,
            "--key-file",
            s(&k.path),
            "--role",
            role,
            "--my-key",
            &hex(&k.signer),
            "--node",
            NODE,
            "--out",
            s(out),
        ]);
        a.extend(owned(&DECLARE));
        a
    }

    /// Signs with each key (one copy each, merged) and submits; returns (txid, from_block).
    fn sign_submit(&self, unsigned: &Path, keys: &[&KeyFile]) -> (String, String) {
        let name = unsigned.file_name().unwrap().to_str().unwrap().to_string();
        let from = self.sink();
        let mut copies = Vec::new();
        for (n, k) in keys.iter().enumerate() {
            let p = self.path(&format!("{name}.signed{n}"));
            self.go("v2", &self.sign_args(unsigned, k, &p));
            copies.push(p);
        }
        let complete = if copies.len() == 1 {
            copies.remove(0)
        } else {
            let m = self.path(&format!("{name}.merged"));
            let mut a = owned(&["ipst", "merge", "--ipst"]);
            a.extend(copies.iter().map(|p| s(p).to_string()));
            a.extend(owned(&["--node", NODE, "--out", s(&m)]));
            let merged = self.go("v2", &a);
            assert_eq!(field(&merged, "pending"), "complete", "{merged}");
            m
        };
        let out = self.go(
            "v2",
            &owned(&["submit", "--ipst", s(&complete), "--node", NODE]),
        );
        (field(&out, "submitted"), from)
    }

    fn fund_args(&self, extra_front: &[&str], terms: &Path, leg: usize, out: &Path) -> Vec<String> {
        // The depositor of leg i: party i in the opening, party 1 - i in the return.
        let k = &self.parties[self.depositor(terms, leg)];
        let mut a = owned(&["fund", "build"]);
        a.extend(owned(extra_front));
        a.extend(owned(&[
            "--terms",
            s(terms),
            "--leg",
            &leg.to_string(),
            "--node",
            NODE,
            "--my-key",
            &hex(&k.signer),
            "--pay-from",
            &self.addr(k),
            "--out",
            s(out),
        ]));
        a.extend(owned(&DECLARE));
        a
    }

    fn settle_args(&self, extra_front: &[&str], terms: &Path, out: &Path) -> Vec<String> {
        let mut a = owned(&["settle", "build"]);
        a.extend(owned(extra_front));
        a.extend(owned(&[
            "--terms",
            s(terms),
            "--node",
            NODE,
            "--pay-from",
            &self.addr(&self.payer),
            "--out",
            s(out),
        ]));
        a.extend(owned(&DECLARE));
        a
    }

    /// `--sheet <sheet> --role <role>`, then the gate arguments if any.
    fn front(sheet: &Path, role: &str, gate: &[String]) -> Vec<String> {
        let mut v = owned(&["--sheet", s(sheet), "--role", role]);
        v.extend(gate.iter().cloned());
        v
    }

    fn fund_via_linked(&self, sheet: &Path, role: &str, terms: &Path, gate: &[String]) {
        for leg in 0..2 {
            let unsigned = self.path(&format!("fund-{role}-{leg}-{}", self.sheet_tag(sheet)));
            let front = Self::front(sheet, role, gate);
            let front: Vec<&str> = strs(&front);
            self.go("linked", &self.fund_args(&front, terms, leg, &unsigned));
            self.sign_submit(&unsigned, &[&self.parties[self.depositor(terms, leg)]]);
        }
    }

    /// Which party deposits `leg` of the terms file `terms`.
    fn depositor(&self, terms: &Path, leg: usize) -> usize {
        let t =
            crate::v2_terms::parse_terms_file(&std::fs::read_to_string(terms).unwrap()).unwrap();
        let key = t.terms().legs[leg].depositor_key;
        self.parties.iter().position(|p| p.signer == key).unwrap()
    }

    fn sheet_tag(&self, sheet: &Path) -> String {
        sheet.file_name().unwrap().to_str().unwrap().to_string()
    }

    fn settle_via_linked(
        &self,
        sheet: &Path,
        role: &str,
        terms: &Path,
        gate: &[String],
    ) -> (String, String) {
        let unsigned = self.path(&format!("settle-{role}-{}", self.sheet_tag(sheet)));
        let front = Self::front(sheet, role, gate);
        let front: Vec<&str> = strs(&front);
        self.go("linked", &self.settle_args(&front, terms, &unsigned));
        // Without an authority the vault inputs take no signature: the payer signs the fee input.
        self.sign_submit(&unsigned, &[&self.payer])
    }

    fn gate_args(&self, txid: &str, from: &str, min_depth: u64) -> Vec<String> {
        owned(&[
            "--opening-txid",
            txid,
            "--opening-from-block",
            from,
            "--min-depth",
            &min_depth.to_string(),
        ])
    }

    fn unspent_at(&self, spk: &kaspa_consensus_core::tx::ScriptPublicKey) -> Vec<u64> {
        self.sim
            .state
            .borrow()
            .utxos_at(spk)
            .iter()
            .map(|u| u.entry.amount)
            .collect()
    }
}

fn with(args: &[String], extra: &[&str]) -> Vec<String> {
    let mut v = args.to_vec();
    v.extend(owned(extra));
    v
}

fn replace(args: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            v.push(value.to_string());
            continue;
        }
        v.push(a.clone());
        if a == flag {
            skip = true;
        }
    }
    v
}

// =============================================================================================
// The whole flow
// =============================================================================================

#[test]
fn an_open_and_a_return_settle_and_their_receipts_link_to_one_terms_hash() {
    let w = World::new();
    let sheet = w.standard_sheet("a");
    let open = w.terms_file(&sheet, "opening", "open.terms.json");
    let ret = w.terms_file(&sheet, "return", "return.terms.json");
    let linked = parse_sheet_file(&std::fs::read_to_string(&sheet).unwrap()).unwrap();

    // show prints both trades, what each party gets back, and the exposure sentences.
    let shown = w.go(
        "linked",
        &owned(&[
            "show",
            "--sheet",
            s(&sheet),
            "--my-key",
            &hex(&w.parties[0].signer),
        ]),
    );
    assert!(
        shown.contains(&format!("linked_hash: {}", hex(&linked.linked_hash()))),
        "{shown}"
    );
    assert!(
        shown.contains("asset 0: 40000000 at opening, 40400000 at return (400000 more)"),
        "{shown}"
    );
    assert!(shown.contains("you deposit opening leg 0"), "{shown}");
    assert!(shown.contains("you deposit return leg 1"), "{shown}");
    assert!(
        shown.contains("each party keeps what the opening delivered"),
        "{shown}"
    );
    assert!(w
        .go(
            "linked",
            &owned(&[
                "check",
                "--sheet",
                s(&sheet),
                "--role",
                "opening",
                "--terms",
                s(&open)
            ])
        )
        .starts_with("ok:"));
    assert!(w
        .go(
            "linked",
            &owned(&[
                "check",
                "--sheet",
                s(&sheet),
                "--role",
                "return",
                "--terms",
                s(&ret)
            ])
        )
        .starts_with("ok:"));

    // Open: fund both legs, settle.
    w.fund_via_linked(&sheet, "opening", &open, &[]);
    let (open_txid, open_from) = w.settle_via_linked(&sheet, "opening", &open, &[]);
    // Each party now holds the other's opening leg.
    let delivered = |to: &KeyFile, amount| {
        let spk = address_script(&p2pk_address(&to.signer, Network::Testnet));
        w.unspent_at(&spk).contains(&amount)
    };
    assert!(delivered(&w.parties[1], LEG_0));
    assert!(delivered(&w.parties[0], LEG_1));

    // The return cannot be built without the gate, or with a gate that is too shallow.
    let ret_fund = |gate: &[String]| {
        let unsigned = w.path(&format!("rf-{}", gate.len()));
        let front = World::front(&sheet, "return", gate);
        let front: Vec<&str> = strs(&front);
        w.fund_args(&front, &ret, 0, &unsigned)
    };
    assert_eq!(w.no("linked", &ret_fund(&[])), "LINKED_OPENING_NOT_SETTLED");
    let partial_gate = owned(&["--opening-txid", &open_txid]);
    assert_eq!(
        w.no("linked", &ret_fund(&partial_gate)),
        "LINKED_OPENING_NOT_SETTLED"
    );
    let shallow = w.gate_args(&open_txid, &open_from, 1_000);
    assert_eq!(
        w.no("linked", &ret_fund(&shallow)),
        "CLI_DEPTH_BELOW_MINIMUM"
    );
    let unknown = w.gate_args(&hex(&[9; 32]), &open_from, 0);
    assert_eq!(w.no("linked", &ret_fund(&unknown)), "CLI_TX_NOT_ACCEPTED");

    // The gate command reads the same node; the opening is accepted at depth 1 so far.
    let gate_cmd = |min_depth: u64| {
        owned(&[
            "return-gate",
            "--sheet",
            s(&sheet),
            "--node",
            NODE,
            "--opening-txid",
            &open_txid,
            "--opening-from-block",
            &open_from,
            "--min-depth",
            &min_depth.to_string(),
        ])
    };
    assert_eq!(w.no("linked", &gate_cmd(50)), "CLI_DEPTH_BELOW_MINIMUM");
    w.set_daa(START_DAA + 100);
    let gated = w.go("linked", &gate_cmd(50));
    assert!(gated.contains("opening settled: transaction"), "{gated}");
    assert!(gated.contains(&open_txid), "{gated}");

    // The return funds, with the gate, leg by leg; the funding is a v2 funding of the return.
    let gate = w.gate_args(&open_txid, &open_from, 50);
    let funded = w.go("linked", &ret_fund(&gate));
    assert!(
        funded.contains("linked: the return trade of sheet"),
        "{funded}"
    );
    assert!(funded.contains("opening settled: transaction"), "{funded}");
    // (the unsigned file written above is leg 0; fund both through the helper)
    w.fund_via_linked(&sheet, "return", &ret, &gate);
    w.set_daa(RETURN_EARLIEST + 100);
    let (ret_txid, ret_from) = w.settle_via_linked(&sheet, "return", &ret, &gate);
    // Party 0 got BACK_0 and party 1 got BACK_1 at the return.
    let delivered_to = |to: &KeyFile, amount| {
        let spk = address_script(&p2pk_address(&to.signer, Network::Testnet));
        w.unspent_at(&spk).contains(&amount)
    };
    assert!(delivered_to(&w.parties[0], BACK_0));
    assert!(delivered_to(&w.parties[1], BACK_1));

    // Receipts: one per trade, signed by a party, both naming one linked hash.
    w.set_daa(RETURN_EARLIEST + 500);
    let signer = &w.parties[0];
    let sign = |role: &str, txid: &str, from: &str, out: &str, min_depth: u64| {
        owned(&[
            "receipt",
            "sign",
            "--sheet",
            s(&sheet),
            "--role",
            role,
            "--node",
            NODE,
            "--txid",
            txid,
            "--from-block",
            from,
            "--min-depth",
            &min_depth.to_string(),
            "--key-file",
            s(&signer.path),
            "--out",
            s(&w.path(out)),
        ])
    };
    // Depth is checked before anything is signed or written; the transaction must be this trade's.
    assert_eq!(
        w.no(
            "linked",
            &sign("opening", &open_txid, &open_from, "r0", 10_000_000)
        ),
        "CLI_DEPTH_BELOW_MINIMUM"
    );
    assert!(!w.path("r0").exists());
    assert_eq!(
        w.no("linked", &sign("return", &open_txid, &open_from, "r1", 10)),
        "LINKED_SETTLE_EVIDENCE",
        "the opening's settle is not the return's"
    );
    assert!(!w.path("r1").exists());
    assert_eq!(
        w.no("linked", &sign("opening", &ret_txid, &ret_from, "r2", 10)),
        "LINKED_SETTLE_EVIDENCE"
    );
    let signed_open = w.go(
        "linked",
        &sign("opening", &open_txid, &open_from, "open.receipt", 10),
    );
    assert!(signed_open.contains("bound:"), "{signed_open}");
    w.go(
        "linked",
        &sign("return", &ret_txid, &ret_from, "return.receipt", 10),
    );
    let key_text: &str = &signer.content;
    assert!(!std::fs::read_to_string(w.path("open.receipt"))
        .unwrap()
        .contains(key_text.trim_end()));

    let verify = |file: &str, extra: &[&str]| {
        let mut v = owned(&[
            "receipt",
            "verify",
            "--receipt",
            s(&w.path(file)),
            "--sheet",
            s(&sheet),
        ]);
        v.extend(owned(extra));
        v
    };
    let ok = w.go(
        "linked",
        &verify(
            "open.receipt",
            &[
                "--signer",
                &hex(&signer.signer),
                "--txid",
                &open_txid,
                "--node",
                NODE,
            ],
        ),
    );
    assert!(ok.starts_with("ok:"), "{ok}");
    assert!(ok.contains("this is the opening trade"), "{ok}");
    assert!(ok.contains("chain: txid"), "{ok}");
    assert!(ok.contains("not established:"), "{ok}");
    let ok_ret = w.go("linked", &verify("return.receipt", &[]));
    assert!(ok_ret.contains("this is the return trade"), "{ok_ret}");
    assert!(ok_ret.contains("signer: not authenticated"), "{ok_ret}");
    // Both receipts name one terms hash: the sheet's.
    let opening = parse_receipt(&std::fs::read_to_string(w.path("open.receipt")).unwrap()).unwrap();
    let returned =
        parse_receipt(&std::fs::read_to_string(w.path("return.receipt")).unwrap()).unwrap();
    assert_eq!(opening.observation.linked_hash, linked.linked_hash());
    assert_eq!(returned.observation.linked_hash, linked.linked_hash());
    assert_eq!(
        opening.observation.leg_terms_hash,
        linked.terms_hash(Role::Opening)
    );
    assert_eq!(
        returned.observation.leg_terms_hash,
        linked.terms_hash(Role::Return)
    );
    assert_eq!(
        parse_receipt(&render_receipt(&opening)).unwrap(),
        opening,
        "render and parse agree"
    );

    // Verify refusals, each beside the controls above.
    assert_eq!(
        w.no(
            "linked",
            &verify("open.receipt", &["--signer", &hex(&w.parties[1].signer)])
        ),
        "RECEIPT_SIGNER_MISMATCH"
    );
    assert_eq!(
        w.no("linked", &verify("open.receipt", &["--txid", &ret_txid])),
        "RECEIPT_TXID_MISMATCH"
    );
    let text = std::fs::read_to_string(w.path("open.receipt")).unwrap();
    let tampered = text.replace("\"depth\": \"", "\"depth\": \"9");
    std::fs::write(w.path("tampered.receipt"), tampered).unwrap();
    assert_eq!(
        w.no("linked", &verify("tampered.receipt", &[])),
        "RECEIPT_SIGNATURE_INVALID"
    );
    std::fs::write(w.path("junk.receipt"), "{}").unwrap();
    assert_eq!(
        w.no("linked", &verify("junk.receipt", &[])),
        "RECEIPT_MALFORMED"
    );
    let other_sheet = w.standard_sheet("b");
    let mut other = owned(&[
        "receipt",
        "verify",
        "--receipt",
        s(&w.path("open.receipt")),
        "--sheet",
        s(&other_sheet),
    ]);
    assert_eq!(w.no("linked", &other), "LINKED_RECEIPT_TERMS");
    other.clear();

    // The pair.
    let pair = |a: &str, b: &str, extra: &[&str]| {
        let mut v = owned(&[
            "receipt",
            "pair",
            "--opening",
            s(&w.path(a)),
            "--return",
            s(&w.path(b)),
            "--sheet",
            s(&sheet),
        ]);
        v.extend(owned(extra));
        v
    };
    let paired = w.go(
        "linked",
        &pair(
            "open.receipt",
            "return.receipt",
            &["--signer", &hex(&signer.signer)],
        ),
    );
    assert!(
        paired.starts_with("ok: an opening receipt and a return receipt of one sheet"),
        "{paired}"
    );
    assert!(paired.contains(&hex(&linked.linked_hash())), "{paired}");
    assert_eq!(
        w.no("linked", &pair("return.receipt", "open.receipt", &[])),
        "LINKED_RECEIPT_PAIR"
    );
    assert_eq!(
        w.no("linked", &pair("open.receipt", "open.receipt", &[])),
        "LINKED_RECEIPT_PAIR"
    );
    assert_eq!(
        w.no(
            "linked",
            &pair(
                "open.receipt",
                "return.receipt",
                &["--signer", &hex(&w.parties[1].signer)]
            )
        ),
        "RECEIPT_SIGNER_MISMATCH"
    );
    assert_eq!(
        w.no("linked", &pair("tampered.receipt", "return.receipt", &[])),
        "RECEIPT_SIGNATURE_INVALID"
    );
}

// =============================================================================================
// Refusals
// =============================================================================================

#[test]
fn a_sheet_is_refused_for_each_check_and_written_only_when_all_pass() {
    let w = World::new();
    let good = w.sheet(
        "g",
        |_| {},
        [BACK_0, BACK_1],
        RETURN_EARLIEST,
        RETURN_EXPIRY,
    );
    w.go("linked", &good);
    let code = |name: &str, edit: &dyn Fn(&mut TermsV2), back: [u64; 2], e: u64, x: u64| {
        let args = w.sheet(name, |t| edit(t), back, e, x);
        let c = w.no("linked", &args);
        assert!(
            !w.path(&format!("{name}.sheet.json")).exists(),
            "{name}: nothing written"
        );
        c
    };
    let same = |_: &mut TermsV2| {};
    assert_eq!(
        code("c1", &same, [BACK_0, BACK_1], OPENING_EXPIRY, RETURN_EXPIRY),
        "LINKED_RETURN_NOT_LATER"
    );
    assert_eq!(
        code(
            "c2",
            &same,
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EARLIEST - 1
        ),
        "TERMS_EARLIEST_AFTER_EXPIRY"
    );
    assert_eq!(
        code("c3", &same, [0, BACK_1], RETURN_EARLIEST, RETURN_EXPIRY),
        "TERMS_AMOUNT_ZERO"
    );
    assert_eq!(
        code(
            "c4",
            &|t| t.trade_ref = [1; 32],
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ),
        "LINKED_TRADE_REF_SET"
    );
    assert_eq!(
        code(
            "c5",
            &|t| t.partial = Some(impulse_core::v2::Partial {
                lot_count: 2,
                min_lot: 1
            }),
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ),
        "LINKED_PARTIAL"
    );
    assert_eq!(
        code(
            "c6",
            &|t| {
                let extra = t.legs[0];
                t.legs.push(LegV2 {
                    depositor_key: t.legs[1].depositor_key,
                    ..extra
                });
            },
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ),
        "LINKED_LEG_COUNT"
    );
    assert_eq!(
        code(
            "c7",
            &|t| t.legs[1].depositor_key = t.legs[0].depositor_key,
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ),
        "TERMS_LEGS_ONE_PARTY"
    );
    assert_eq!(
        code(
            "c8",
            &|t| t.legs[0].asset.amount = 1_000,
            [BACK_0, BACK_1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ),
        "TX_BELOW_MIN_KAS"
    );
    assert_eq!(
        code(
            "c9",
            &|t| t.expiry_daa = START_DAA,
            [BACK_0, BACK_1],
            START_DAA + 1,
            RETURN_EXPIRY
        ),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    // The file is never overwritten.
    assert_eq!(w.no("linked", &good), "CLI_OUTPUT_EXISTS");
    // A sheet of another network is refused on this one.
    let mainnet = w.exec_argv(vec![
        "impulse",
        "--network",
        "mainnet",
        "linked",
        "show",
        "--sheet",
        s(&w.path("g.sheet.json")),
    ]);
    assert_eq!(mainnet.0.unwrap_err().code(), "CLI_NETWORK_MISMATCH");
}

#[test]
fn a_sheet_file_is_read_strictly() {
    let w = World::new();
    let sheet = w.standard_sheet("a");
    let text = std::fs::read_to_string(&sheet).unwrap();
    assert!(parse_sheet_file(&text).is_ok(), "control");
    let code = |t: String| parse_sheet_file(&t).unwrap_err().code();
    // Canonical bytes that are not the sheet's encoding, a hash that is not their hash, an extra
    // key, a key twice, and not JSON.
    let canonical = text
        .lines()
        .find(|l| l.contains("\"canonical\""))
        .unwrap()
        .to_string();
    let bytes = canonical.split('"').nth(3).unwrap().to_string();
    // The first byte is link_version 01: a different byte is not the encoding of the view.
    let edited = bytes.replacen("01", "02", 1);
    assert_eq!(
        code(text.replace(&bytes, &edited)),
        "CLI_TERMS_FILE_INCONSISTENT"
    );
    let hash_line = text
        .lines()
        .find(|l| l.contains("\"linked_hash\""))
        .unwrap();
    let hash = hash_line.split('"').nth(3).unwrap().to_string();
    assert_eq!(
        code(text.replace(&hash, &"00".repeat(32))),
        "CLI_TERMS_FILE_INCONSISTENT"
    );
    assert_eq!(
        code(text.replacen("{\n", "{\n  \"extra\": 1,\n", 1)),
        "CLI_TERMS_JSON"
    );
    assert_eq!(
        code(text.replacen(
            "  \"canonical\"",
            "  \"linked_hash\": \"00\",\n  \"canonical\"",
            1
        )),
        "CLI_TERMS_JSON"
    );
    assert_eq!(code("not json".into()), "CLI_TERMS_JSON");
    // A sheet whose view fails a sheet check (the opening carries a trade_ref) is refused by it.
    let bad = w.sheet(
        "t",
        |t| t.trade_ref = [3; 32],
        [BACK_0, BACK_1],
        RETURN_EARLIEST,
        RETURN_EXPIRY,
    );
    assert_eq!(w.no("linked", &bad), "LINKED_TRADE_REF_SET");
}

#[test]
fn a_terms_file_must_be_the_trade_of_the_role_the_command_names() {
    let w = World::new();
    let sheet = w.standard_sheet("a");
    let open = w.terms_file(&sheet, "opening", "open.terms.json");
    let ret = w.terms_file(&sheet, "return", "return.terms.json");
    let check = |role: &str, terms: &Path| {
        owned(&[
            "check",
            "--sheet",
            s(&sheet),
            "--role",
            role,
            "--terms",
            s(terms),
        ])
    };
    assert_eq!(
        w.no("linked", &check("return", &open)),
        "LINKED_ROLE_MISMATCH"
    );
    assert_eq!(
        w.no("linked", &check("opening", &ret)),
        "LINKED_ROLE_MISMATCH"
    );
    // Terms of a plain v2 trade (another trade_ref), and terms with one field changed.
    let plain = w.path("plain.terms.json");
    let draft = w.write_draft("plain.draft.json", &{
        let mut t = w.draft_terms();
        t.trade_ref = [5; 32];
        t
    });
    w.go(
        "v2",
        &owned(&[
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&plain),
            "--daa",
            &START_DAA.to_string(),
            "--my-key",
            &hex(&w.parties[0].signer),
        ]),
    );
    let other_sheet = w.standard_sheet("b");
    assert_eq!(
        w.no("linked", &check("opening", &plain)),
        "LINKED_NOT_A_LEG"
    );
    // The same trade as the sheet's opening but for trade_ref.
    let linked = parse_sheet_file(&std::fs::read_to_string(&sheet).unwrap()).unwrap();
    let mut t = linked.terms(Role::Opening).terms().clone();
    t.trade_ref = [8; 32];
    let wrong_ref = w.path("wrongref.terms.json");
    std::fs::write(
        &wrong_ref,
        crate::v2_terms::render_terms_file(&t.validate_structure().unwrap()),
    )
    .unwrap();
    assert_eq!(
        w.no("linked", &check("opening", &wrong_ref)),
        "LINKED_TRADE_REF"
    );
    // The opening of another sheet is not this sheet's.
    let other_open = w.terms_file(&other_sheet, "opening", "other.open.terms.json");
    assert_eq!(
        w.no("linked", &check("opening", &other_open)),
        "LINKED_NOT_A_LEG"
    );
    assert!(
        w.go("linked", &check("opening", &open)).starts_with("ok:"),
        "control"
    );

    // The builders run the same check before anything else.
    let unsigned = w.path("x.ipst");
    let front = World::front(&sheet, "opening", &[]);
    let front: Vec<&str> = strs(&front);
    assert_eq!(
        w.no("linked", &w.fund_args(&front, &ret, 0, &unsigned)),
        "LINKED_ROLE_MISMATCH"
    );
    assert!(!unsigned.exists());
}

#[test]
fn a_gate_for_another_trade_or_a_refund_is_no_evidence() {
    let w = World::new();
    let a = w.standard_sheet("a");
    let a_open = w.terms_file(&a, "opening", "a.open.json");
    let a_ret = w.terms_file(&a, "return", "a.return.json");
    // A second sheet with its own opening, funded and settled.
    let b = w.standard_sheet("b");
    let b_open = w.terms_file(&b, "opening", "b.open.json");
    w.fund_via_linked(&b, "opening", &b_open, &[]);
    let (b_txid, b_from) = w.settle_via_linked(&b, "opening", &b_open, &[]);
    w.set_daa(START_DAA + 100);
    // Sheet b's opening settle is no evidence for sheet a's return.
    let unsigned = w.path("y.ipst");
    let gate = w.gate_args(&b_txid, &b_from, 1);
    let front = World::front(&a, "return", &gate);
    let front: Vec<&str> = strs(&front);
    assert_eq!(
        w.no("linked", &w.fund_args(&front, &a_ret, 0, &unsigned)),
        "LINKED_SETTLE_EVIDENCE"
    );
    // A refund of an opening leg of sheet a is no evidence either: fund one leg, refund it.
    let unsigned_fund = w.path("a-fund-0");
    let front_open = World::front(&a, "opening", &[]);
    let front_open: Vec<&str> = strs(&front_open);
    w.go(
        "linked",
        &w.fund_args(&front_open, &a_open, 0, &unsigned_fund),
    );
    w.sign_submit(&unsigned_fund, &[&w.parties[0]]);
    let refund_ipst = w.path("a-refund-0");
    let mut refund = owned(&["refund", "build"]);
    refund.extend(owned(&["--sheet", s(&a), "--role", "opening"]));
    refund.extend(owned(&[
        "--terms",
        s(&a_open),
        "--leg",
        "0",
        "--signer",
        "0",
        "--node",
        NODE,
        "--pay-from",
        &w.addr(&w.payer),
        "--out",
        s(&refund_ipst),
    ]));
    refund.extend(owned(&DECLARE));
    w.go("linked", &refund);
    let (refund_txid, refund_from) = w.sign_submit(&refund_ipst, &[&w.parties[0], &w.payer]);
    w.set_daa(START_DAA + 200);
    let gate = w.gate_args(&refund_txid, &refund_from, 1);
    let front = World::front(&a, "return", &gate);
    let front: Vec<&str> = strs(&front);
    assert_eq!(
        w.no("linked", &w.fund_args(&front, &a_ret, 0, &w.path("z.ipst"))),
        "LINKED_SETTLE_EVIDENCE"
    );
    // The return's refund needs no gate: it takes a depositor's own leg home. Fund the return
    // leg 0 through a different, settled sheet is not needed: refund of an unfunded vault fails
    // for want of a UTXO, not for want of a gate.
    let mut r = owned(&["refund", "build"]);
    r.extend(owned(&["--sheet", s(&a), "--role", "return"]));
    r.extend(owned(&[
        "--terms",
        s(&a_ret),
        "--leg",
        "0",
        "--signer",
        "1",
        "--node",
        NODE,
        "--pay-from",
        &w.addr(&w.payer),
        "--out",
        s(&w.path("r.ipst")),
    ]));
    r.extend(owned(&DECLARE));
    let (res, _) = w.exec("linked", &strs(&r));
    assert_ne!(
        res.unwrap_err().code(),
        "LINKED_OPENING_NOT_SETTLED",
        "no gate on a refund"
    );
    // A bad gate argument is a hex error, not a gate pass.
    let bad = replace(&w.gate_args(&b_txid, &b_from, 1), "--opening-txid", "xyz");
    let front = World::front(&b, "return", &bad);
    let front: Vec<&str> = strs(&front);
    let b_ret = w.terms_file(&b, "return", "b.return.json");
    assert_eq!(
        w.no("linked", &w.fund_args(&front, &b_ret, 0, &w.path("q.ipst"))),
        "CLI_HEX"
    );
    let _ = with(&[], &[]);
    let _ = VaultV2::instantiate_existing;
}

#[test]
fn a_gate_whose_accepting_block_left_the_chain_or_lies_ahead_of_the_node_is_refused() {
    let w = World::new();
    let a = w.standard_sheet("a");
    let a_open = w.terms_file(&a, "opening", "a.open.json");
    let a_ret = w.terms_file(&a, "return", "a.return.json");
    w.fund_via_linked(&a, "opening", &a_open, &[]);
    let (txid, from) = w.settle_via_linked(&a, "opening", &a_open, &[]);
    w.set_daa(START_DAA + 100);
    let attempt = |w: &World| {
        let gate = w.gate_args(&txid, &from, 1);
        let front = World::front(&a, "return", &gate);
        let front: Vec<&str> = strs(&front);
        w.no("linked", &w.fund_args(&front, &a_ret, 0, &w.path("g.ipst")))
    };
    // Control: the chain block, deep enough, passes the gate (the build then needs no more).
    let gate = w.gate_args(&txid, &from, 1);
    let front = World::front(&a, "return", &gate);
    let front: Vec<&str> = strs(&front);
    w.go(
        "linked",
        &w.fund_args(&front, &a_ret, 0, &w.path("ok.ipst")),
    );
    // The depth is read from a refusal, then a minimum equal to it passes and one more fails.
    let probe = {
        let gate = w.gate_args(&txid, &from, 1_000_000);
        let front = World::front(&a, "return", &gate);
        let front: Vec<&str> = strs(&front);
        let (res, _) = w.exec(
            "linked",
            &strs(&w.fund_args(&front, &a_ret, 0, &w.path("d.ipst"))),
        );
        let msg = res.unwrap_err().to_string();
        let digits = msg.split("depth ").nth(1).expect("depth in message");
        digits.split(' ').next().unwrap().parse::<u64>().unwrap()
    };
    assert!(probe > 1);
    for (min, ok) in [(probe, true), (probe + 1, false)] {
        let gate = w.gate_args(&txid, &from, min);
        let front = World::front(&a, "return", &gate);
        let front: Vec<&str> = strs(&front);
        let (res, _) = w.exec(
            "linked",
            &strs(&w.fund_args(&front, &a_ret, 0, &w.path("e.ipst"))),
        );
        match (ok, res) {
            (true, Ok(())) => {}
            (false, Err(e)) => assert_eq!(e.code(), "CLI_DEPTH_BELOW_MINIMUM"),
            (_, other) => panic!("min {min}: unexpected {other:?}"),
        }
    }
    // The accepting block is no longer a chain block.
    w.sim.state.borrow_mut().off_chain = true;
    assert_eq!(attempt(&w), "CLI_TX_NOT_ACCEPTED");
    w.sim.state.borrow_mut().off_chain = false;
    // The node's virtual DAA score is below the accepting block's.
    w.set_daa(START_DAA.saturating_sub(1));
    assert_eq!(attempt(&w), "CLI_NODE_RPC");
}
