// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse v2` end to end in process, against the in-memory fake node (`sim`), which runs every
//! submitted input in the pinned script engine: 3-way trades fund leg by leg, settle in one
//! transaction and refund leg by leg. Each refusal has a failing case beside an accepted control,
//! and every refused command is checked to have printed nothing. Keys are throwaway keys generated
//! at runtime into temporary directories that are removed; no key literal exists.

use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, outpoint_text, p2pk_address};
use crate::json::hex;
use crate::node::Node;
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::testutil::TempDir;
use crate::v2_terms::{self, render_terms_file, terms_json};
use clap::Parser;
use impulse_core::terms::{
    FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
};
use impulse_core::tx::{Kcc20State, Kcc20Template, MIN_KCC20_OUTPUT};
use impulse_core::v2::{
    kas_destination, min_v2, DestinationV2, LegV2, Partial, TermsV2, ValidatedTermsV2, VaultV2,
};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const ASSET_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const CASH_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-cash.json");
const NODE: &str = "ws://127.0.0.1:17210";
const START_DAA: u64 = 1_000_000;
const EXPIRY_IN: u64 = 864_000;
const TOKENS: u64 = 1_000;
const AMOUNTS: [u64; 3] = [10, 7, 9];
const KAS_LEG: u64 = 100_000_000;
const DECLARE: [&str; 2] = ["--kas-equivalent", "500000000"];

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

fn owned(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The shape of a 3-way trade: two KCC-20 legs and a KAS leg, or three KCC-20 legs. Party i
/// deposits leg i and receives leg i - 1 (a ring).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    TwoTokensAndKas,
    ThreeTokens,
}

struct World {
    dir: TempDir,
    sim: SimNode,
    network: Network,
    parties: [KeyFile; 3],
    authority: KeyFile,
    payer: KeyFile,
    templates: [Kcc20Template; 2],
    covenants: [[u8; 32]; 3],
    /// Each party's token UTXO, `<txid>:<index>:<amount>`.
    tokens: RefCell<[String; 3]>,
    max_value: RefCell<Option<String>>,
    /// `--max-topup` for every `ipst sign`, when set.
    max_topup: RefCell<Option<String>>,
    explicit: std::cell::Cell<bool>,
}

impl World {
    fn new(network: Network) -> Self {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("a.json"), ASSET_JSON).unwrap();
        std::fs::write(dir.path().join("b.json"), CASH_JSON).unwrap();
        let mut state = SimState::new(network, START_DAA, 0);
        let parties = [key_file(), key_file(), key_file()];
        let (authority, payer) = (key_file(), key_file());
        for k in parties.iter().chain([&authority, &payer]) {
            let spk = address_script(&p2pk_address(&k.signer, network));
            for amount in [400_000_000_000, 300_000_000_000] {
                state.add_utxo(spk.clone(), amount, None);
            }
        }
        let templates = [
            Kcc20Template::from_json(ASSET_JSON).unwrap(),
            Kcc20Template::from_json(CASH_JSON).unwrap(),
        ];
        let covenants: [[u8; 32]; 3] = [rand::random(), rand::random(), rand::random()];
        let mut tokens: [String; 3] = Default::default();
        for i in 0..3 {
            let st = Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::PubKey,
                    identifier: parties[i].signer,
                },
                TOKENS,
            );
            let tpl = &templates[Self::template_of(i)];
            let o = state.add_utxo(
                tpl.script_public_key(&st).unwrap(),
                MIN_KCC20_OUTPUT,
                Some(covenants[i]),
            );
            tokens[i] = format!("{}:{TOKENS}", outpoint_text(&o));
        }
        Self {
            dir,
            sim: SimNode::memory(state),
            network,
            parties,
            authority,
            payer,
            templates,
            covenants,
            tokens: RefCell::new(tokens),
            max_value: RefCell::new(None),
            max_topup: RefCell::new(None),
            explicit: std::cell::Cell::new(network == Network::Mainnet),
        }
    }

    /// Legs 0 and 2 use the first token template, leg 1 the second.
    fn template_of(leg: usize) -> usize {
        leg % 2
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn template_args(&self) -> Vec<String> {
        owned(&[
            "--token-template",
            s(&self.path("a.json")),
            "--token-template",
            s(&self.path("b.json")),
        ])
    }

    fn addr(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, self.network).to_string()
    }

    fn token(&self, leg: usize) -> Kcc20Token {
        let t = &self.templates[Self::template_of(leg)];
        Kcc20Token {
            covenant_id: self.covenants[leg],
            template_hash: t.template_hash(),
            template_prefix_len: t.prefix_len() as u32,
            template_suffix_len: t.suffix_len() as u32,
        }
    }

    fn base_terms(&self, shape: Shape, authority: bool, funding: FundingMode) -> TermsV2 {
        let key = |i: usize| self.parties[i].signer;
        let pubkey = |k: [u8; 32]| DestinationV2 {
            identifier_type: IdentifierType::PubKey,
            identifier: k,
        };
        let legs = (0..3)
            .map(|i| {
                let kas = shape == Shape::TwoTokensAndKas && i == 2;
                LegV2 {
                    depositor_key: key(i),
                    asset: Leg {
                        kind: if kas {
                            LegKind::Kas
                        } else {
                            LegKind::Kcc20(self.token(i))
                        },
                        amount: if kas { KAS_LEG } else { AMOUNTS[i] },
                    },
                    delivery: pubkey(key((i + 1) % 3)),
                    refund: pubkey(key(i)),
                }
            })
            .collect();
        TermsV2 {
            version: 2,
            network: self.network,
            nonce: rand::random(),
            authority_key: authority.then_some(self.authority.signer),
            legs,
            earliest_daa: None,
            expiry_daa: START_DAA + EXPIRY_IN,
            funding_mode: funding,
            partial: None,
            trade_ref: [7; 32],
        }
    }

    /// Writes a terms file v2 for the shape, edited, and returns its path.
    fn terms(
        &self,
        name: &str,
        shape: Shape,
        authority: bool,
        edit: impl FnOnce(&mut TermsV2),
    ) -> PathBuf {
        let mut t = self.base_terms(shape, authority, FundingMode::Revocable);
        edit(&mut t);
        self.write_terms(name, t)
    }

    fn write_terms(&self, name: &str, t: TermsV2) -> PathBuf {
        let v = t.validate_structure().unwrap();
        let p = self.path(name);
        std::fs::write(&p, render_terms_file(&v)).unwrap();
        p
    }

    fn read(&self, terms: &Path) -> ValidatedTermsV2 {
        v2_terms::parse_terms_file(&std::fs::read_to_string(terms).unwrap()).unwrap()
    }

    fn exec_argv(&self, argv: Vec<&str>) -> (Result<(), CliError>, String) {
        let cli = Cli::try_parse_from(argv).expect("arguments parse");
        let sim = self.sim.clone();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(Box::new(sim.clone()))
        };
        let max = self.max_value.borrow().clone();
        let env = Env {
            max_value: max.as_deref().map(OsStr::new),
            connect: &connect,
        };
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let r = run(cli, &env, &mut out, &mut notes);
        (r, String::from_utf8(out).unwrap())
    }

    fn exec(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse"];
        if self.explicit.get() {
            argv.extend_from_slice(&["--network", "mainnet"]);
        }
        argv.push("v2");
        argv.extend_from_slice(args);
        self.exec_argv(argv)
    }

    /// A v1 command (no `v2`), for the cross-version refusals.
    fn exec_v1(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse"];
        argv.extend_from_slice(args);
        self.exec_argv(argv)
    }

    fn go(&self, args: &[String]) -> String {
        let (r, out) = self.exec(&strs(args));
        r.unwrap_or_else(|e| panic!("{args:?}: {e}"));
        out
    }

    /// A refused command: returns its code after checking it printed nothing.
    fn no(&self, args: &[String]) -> &'static str {
        let (r, out) = self.exec(&strs(args));
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }

    fn set_daa(&self, daa: u64) {
        self.sim.state.borrow_mut().virtual_daa = daa;
    }

    fn fund_args(&self, terms: &Path, leg: usize, out: &Path) -> Vec<String> {
        let k = &self.parties[leg];
        let mut a = owned(&[
            "fund",
            "build",
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
        ]);
        a.extend(owned(&DECLARE));
        if let LegKind::Kcc20(_) = self.read(terms).terms().legs[leg].asset.kind {
            a.extend(self.template_args());
            a.extend(["--token".into(), self.tokens.borrow()[leg].clone()]);
        }
        a
    }

    fn role_of(&self, k: &KeyFile) -> &'static str {
        if self.parties.iter().any(|p| p.signer == k.signer) {
            "depositor"
        } else if k.signer == self.authority.signer {
            "authority"
        } else {
            "payer"
        }
    }

    fn sign_args(&self, ipst: &Path, k: &KeyFile, out: &Path) -> Vec<String> {
        let text = std::fs::read_to_string(ipst).unwrap();
        let agreed = match impulse_core::v2::read_ipst(&text) {
            Ok(impulse_core::v2::AnyIpst::V2(i)) => hex(&i.terms().terms_hash()),
            _ => hex(&[0; 32]),
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
            self.role_of(k),
            "--my-key",
            &hex(&k.signer),
            "--node",
            NODE,
            "--out",
            s(out),
        ]);
        a.extend(self.template_args());
        a.extend(owned(&DECLARE));
        if let Some(m) = self.max_topup.borrow().as_deref() {
            a.extend(owned(&["--max-topup", m]));
        }
        a
    }

    fn submit_args(&self, ipst: &Path) -> Vec<String> {
        let mut a = owned(&["submit", "--ipst", s(ipst), "--node", NODE]);
        a.extend(self.template_args());
        a
    }

    /// Signs with each key in turn (one copy each, merged) and submits; returns the txid.
    fn sign_submit(&self, unsigned: &Path, keys: &[&KeyFile]) -> String {
        let name = unsigned.file_name().unwrap().to_str().unwrap().to_string();
        let mut copies = Vec::new();
        for (n, k) in keys.iter().enumerate() {
            let p = self.path(&format!("{name}.signed{n}"));
            self.go(&self.sign_args(unsigned, k, &p));
            copies.push(p);
        }
        let complete = if copies.len() == 1 {
            copies.remove(0)
        } else {
            let m = self.path(&format!("{name}.merged"));
            let mut a = owned(&["ipst", "merge", "--ipst"]);
            a.extend(copies.iter().map(|p| s(p).to_string()));
            a.extend(owned(&["--node", NODE, "--out", s(&m)]));
            a.extend(self.template_args());
            let merged = self.go(&a);
            assert_eq!(field(&merged, "pending"), "complete", "{merged}");
            m
        };
        field(&self.go(&self.submit_args(&complete)), "submitted")
    }

    /// Funds a leg as its depositor and returns the funding txid.
    fn fund(&self, terms: &Path, leg: usize) -> String {
        let name = format!(
            "fund-{}-{leg}",
            terms.file_name().unwrap().to_str().unwrap()
        );
        let unsigned = self.path(&name);
        let out = self.go(&self.fund_args(terms, leg, &unsigned));
        if let Some(change) = out.lines().find_map(|l| l.strip_prefix("token change: ")) {
            self.tokens.borrow_mut()[leg] = change.to_string();
        }
        self.sign_submit(&unsigned, &[&self.parties[leg]])
    }

    fn settle_args(&self, terms: &Path, payer: &KeyFile, out: &Path) -> Vec<String> {
        let mut a = owned(&[
            "settle",
            "build",
            "--terms",
            s(terms),
            "--node",
            NODE,
            "--pay-from",
            &self.addr(payer),
            "--out",
            s(out),
        ]);
        a.extend(self.template_args());
        a.extend(owned(&DECLARE));
        a
    }

    fn refund_args(
        &self,
        terms: &Path,
        leg: usize,
        signer: &str,
        payer: &KeyFile,
        out: &Path,
    ) -> Vec<String> {
        let mut a = owned(&[
            "refund",
            "build",
            "--terms",
            s(terms),
            "--leg",
            &leg.to_string(),
            "--signer",
            signer,
            "--node",
            NODE,
            "--pay-from",
            &self.addr(payer),
            "--out",
            s(out),
        ]);
        a.extend(self.template_args());
        a.extend(owned(&DECLARE));
        a
    }

    fn vault(&self, terms: &Path, leg: usize) -> VaultV2 {
        VaultV2::instantiate_existing(&self.read(terms), leg).unwrap()
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

    /// How many token UTXOs of `leg`'s token a key holds of exactly `amount` units.
    fn held(&self, leg: usize, key: [u8; 32], amount: u64) -> usize {
        let st = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: key,
            },
            amount,
        );
        let spk = self.templates[Self::template_of(leg)]
            .script_public_key(&st)
            .unwrap();
        self.sim.state.borrow().utxos_at(&spk).len()
    }
}

fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("no {key}: line in\n{out}"))
        .to_string()
}

fn with(args: &[String], extra: &[&str]) -> Vec<String> {
    let mut v = args.to_vec();
    v.extend(owned(extra));
    v
}

/// Removes `flag` and its value.
fn without(args: &[String], flag: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a == flag {
            skip = true;
            continue;
        }
        v.push(a.clone());
    }
    v
}

fn replace(args: &[String], flag: &str, value: &str) -> Vec<String> {
    with(&without(args, flag), &[flag, value])
}

/// Removes every `--token-template` and its value.
fn no_templates(args: &[String]) -> Vec<String> {
    let mut v = args.to_vec();
    while v.iter().any(|a| a == "--token-template") {
        v = without(&v, "--token-template");
    }
    v
}

// =============================================================================================
// Controls: 3-way trades fund, settle in one transaction and deliver every leg
// =============================================================================================

#[test]
fn a_three_way_trade_funds_settles_and_delivers_every_leg() {
    let w = World::new(Network::Testnet);
    for (shape, authority, name) in [
        (Shape::TwoTokensAndKas, false, "self"),
        (Shape::ThreeTokens, true, "auth"),
    ] {
        let terms = w.terms(name, shape, authority, |_| {});
        for leg in 0..3 {
            w.fund(&terms, leg);
        }
        let mut verify = owned(&[
            "verify",
            "--terms",
            s(&terms),
            "--node",
            NODE,
            "--my-key",
            &hex(&w.parties[0].signer),
        ]);
        verify.extend(w.template_args());
        let report = w.go(&verify);
        assert_eq!(field(&report, "ok"), "3 of 3 legs funded", "{report}");
        let unsigned = w.path(&format!("{name}-settle"));
        let payer = if authority { &w.authority } else { &w.payer };
        let built = w.go(&w.settle_args(&terms, payer, &unsigned));
        assert_eq!(field(&built, "ipst"), "v2 settle");
        let t = w.read(&terms);
        let before: Vec<usize> = (0..3)
            .map(|i| {
                w.held(
                    i,
                    w.parties[(i + 1) % 3].signer,
                    t.terms().legs[i].asset.amount,
                )
            })
            .collect();
        let from = hex(&w.sim.state.borrow().sink());
        let txid = w.sign_submit(&unsigned, &[payer]);
        let status = w.go(&owned(&[
            "status",
            "--terms",
            s(&terms),
            "--txid",
            &txid,
            "--from-block",
            &from,
            "--node",
            NODE,
        ]));
        assert!(field(&status, "state").starts_with("accepted"), "{status}");
        assert!(!status.contains("settled"), "{status}");
        // Every delivery arrived at its recipient, and every vault is spent.
        for (i, l) in t.terms().legs.iter().enumerate() {
            let recipient = w.parties[(i + 1) % 3].signer;
            match l.asset.kind {
                LegKind::Kas => {
                    assert!(w
                        .unspent_at(&kas_destination(&l.delivery))
                        .contains(&KAS_LEG))
                }
                _ => assert_eq!(
                    w.held(i, recipient, l.asset.amount),
                    before[i] + 1,
                    "leg {i}"
                ),
            }
            assert!(w
                .unspent_at(&w.vault(&terms, i).script_public_key())
                .is_empty());
        }
    }
}

#[test]
fn an_authority_settle_needs_the_authority_and_a_payer_merges_with_it() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, true, |_| {});
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let unsigned = w.path("settle");
    w.go(&w.settle_args(&terms, &w.payer, &unsigned));
    // The payer alone cannot complete it: the authority signs every vault input.
    let p = w.path("payer-only");
    let signed = w.go(&w.sign_args(&unsigned, &w.payer, &p));
    assert_eq!(
        field(&signed, "pending"),
        hex(&w.authority.signer),
        "{signed}"
    );
    assert_eq!(w.no(&w.submit_args(&p)), "TX_SIGNATURE_SLOT");
    let txid = w.sign_submit(&unsigned, &[&w.payer, &w.authority]);
    assert_eq!(txid.len(), 64);
}

#[test]
fn every_leg_refunds_home_in_each_role() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, true, |_| {});
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let t = w.read(&terms);
    // Leg 0 by its depositor with the token, leg 1 by the depositor of leg 2, leg 2 (KAS) by the
    // authority.
    for (leg, signer, key) in [
        (0, "0", &w.parties[0]),
        (1, "2", &w.parties[2]),
        (2, "authority", &w.authority),
    ] {
        let unsigned = w.path(&format!("refund-{leg}"));
        let built = w.go(&w.refund_args(&terms, leg, signer, key, &unsigned));
        assert!(field(&built, "ipst").starts_with(&format!("v2 refund leg {leg} by ")));
        w.sign_submit(&unsigned, &[key]);
        let l = &t.terms().legs[leg];
        match l.asset.kind {
            LegKind::Kas => assert!(w.unspent_at(&kas_destination(&l.refund)).contains(&KAS_LEG)),
            _ => assert_eq!(w.held(leg, w.parties[leg].signer, l.asset.amount), 1),
        }
    }
}

#[test]
fn an_earmarked_depositor_refund_waits_for_the_expiry() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |t| {
        t.funding_mode = FundingMode::Earmarked
    });
    w.fund(&terms, 2);
    let unsigned = w.path("refund");
    let built = w.go(&w.refund_args(&terms, 2, "2", &w.parties[2], &unsigned));
    assert!(field(&built, "lock_time").starts_with(&(START_DAA + EXPIRY_IN).to_string()));
    let signed = w.path("refund.signed");
    w.go(&w.sign_args(&unsigned, &w.parties[2], &signed));
    assert_eq!(w.no(&w.submit_args(&signed)), "CLI_TX_NOT_FINAL");
    w.set_daa(START_DAA + EXPIRY_IN + 1);
    assert!(w.go(&w.submit_args(&signed)).contains("submitted: "));
}

#[test]
fn submit_writes_the_signed_transaction_for_the_watcher() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let unsigned = w.path("settle");
    w.go(&w.settle_args(&terms, &w.payer, &unsigned));
    let signed = w.path("settle.signed");
    w.go(&w.sign_args(&unsigned, &w.payer, &signed));
    let file = w.path("settle.tx");
    let out = w.go(&with(
        &w.submit_args(&signed),
        &["--signed-tx-out", s(&file)],
    ));
    assert_eq!(field(&out, "signed_tx"), s(&file));
    let text = std::fs::read_to_string(&file).unwrap();
    let tx = impulse_watch::files::parse_signed_tx("settle.tx", &text).unwrap();
    assert_eq!(hex(&tx.id().as_bytes()), field(&out, "submitted"));
    // ipst raw writes the same file offline.
    let raw = w.path("raw.tx");
    w.go(&owned(&[
        "ipst",
        "raw",
        "--ipst",
        s(&signed),
        "--out",
        s(&raw),
    ]));
    assert_eq!(std::fs::read_to_string(&raw).unwrap(), text);
}

// =============================================================================================
// Terms new, the party check and the files
// =============================================================================================

fn draft_text(t: &TermsV2, drop: &[&str]) -> String {
    let mut v: serde_json::Value = serde_json::from_str(&terms_json(t).render()).unwrap();
    for k in drop {
        v.as_object_mut().unwrap().remove(*k);
    }
    v.to_string()
}

fn terms_new_args(w: &World, draft: &Path, out: &Path, me: usize) -> Vec<String> {
    let mut a = owned(&[
        "terms",
        "new",
        "--draft",
        s(draft),
        "--out",
        s(out),
        "--daa",
        &START_DAA.to_string(),
        "--my-key",
        &hex(&w.parties[me].signer),
    ]);
    a.extend(owned(&DECLARE));
    a
}

#[test]
fn terms_new_writes_a_terms_file_with_the_d46_defaults() {
    let w = World::new(Network::Testnet);
    let t = w.base_terms(Shape::TwoTokensAndKas, false, FundingMode::Earmarked);
    let draft = w.path("draft.json");
    std::fs::write(
        &draft,
        draft_text(&t, &["nonce", "expiry_daa", "funding_mode"]),
    )
    .unwrap();
    let out_path = w.path("terms.json");
    let out = w.go(&terms_new_args(&w, &draft, &out_path, 1));
    let written = w.read(&out_path);
    assert_eq!(written.terms().expiry_daa, START_DAA + 864_000);
    assert_eq!(written.terms().funding_mode, FundingMode::Revocable);
    assert_eq!(field(&out, "terms_hash"), hex(&written.terms_hash()));
    assert!(out.contains("you: depositor of leg 1, key "), "{out}");
    assert!(
        out.contains("you: leg 0 is delivered to you (pays --my-key)"),
        "{out}"
    );
    assert_eq!(
        field(&out, "funding deadline").split(',').next().unwrap(),
        format!("DAA score {}", START_DAA + 432_000)
    );
    for i in 0..3 {
        assert!(field(&out, &format!("leg {i} vault")).starts_with("kaspatest:"));
    }
    // Two legs name their funding mode (D46).
    let mut two = t.clone();
    two.legs.truncate(2);
    two.legs[1].delivery = two.legs[0].refund;
    let draft2 = w.path("draft2.json");
    std::fs::write(&draft2, draft_text(&two, &["funding_mode"])).unwrap();
    assert_eq!(
        w.no(&terms_new_args(&w, &draft2, &w.path("t2.json"), 0)),
        "CLI_TERMS_JSON"
    );
    // The file exists now: never overwritten.
    assert_eq!(
        w.no(&terms_new_args(&w, &draft, &out_path, 1)),
        "CLI_OUTPUT_EXISTS"
    );
}

fn terms_file_of(v: &serde_json::Value, terms: &serde_json::Value) -> String {
    serde_json::json!({
        "terms": terms,
        "canonical": v["canonical"],
        "terms_hash": v["terms_hash"],
    })
    .to_string()
}

#[test]
fn golden_terms_v2_read_back_as_terms_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms_v2");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let terms = v2_terms::parse_terms_file(&terms_file_of(&v, &v["terms"])).unwrap();
        assert_eq!(hex(&terms.terms_hash()), v["terms_hash"].as_str().unwrap());
        // The JSON form renders back to the vector's.
        let rendered: serde_json::Value =
            serde_json::from_str(&terms_json(terms.terms()).render()).unwrap();
        assert_eq!(rendered, v["terms"]);
        // An edit of the JSON view alone is inconsistent with canonical.
        let mut edited = v["terms"].clone();
        edited["trade_ref"] = serde_json::Value::String("00".repeat(32));
        assert_eq!(
            v2_terms::parse_terms_file(&terms_file_of(&v, &edited))
                .unwrap_err()
                .code(),
            "CLI_TERMS_FILE_INCONSISTENT"
        );
        n += 1;
    }
    assert_eq!(n, 8);
}

#[test]
fn each_version_refuses_the_others_files() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    // A v1 command reads a v2 terms file as not its JSON form.
    let (r, out) = w.exec_v1(&[
        "address",
        "--terms",
        s(&terms),
        "--daa",
        "1000000",
        "--role",
        "buyer",
        "--my-key",
        &hex(&w.parties[0].signer),
        "--kas-equivalent",
        "1",
    ]);
    assert_eq!(r.unwrap_err().code(), "CLI_TERMS_JSON");
    assert_eq!(out, "");
    // A v2 command reads a v1 terms file the same way.
    let v1 = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
    let mut v1_files: Vec<PathBuf> = std::fs::read_dir(v1)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v1_files.sort();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&v1_files[0]).unwrap()).unwrap();
    let file = w.path("v1.json");
    std::fs::write(&file, terms_file_of(&v, &v["terms"])).unwrap();
    let mut a = owned(&[
        "address",
        "--terms",
        s(&file),
        "--daa",
        "1000000",
        "--my-key",
        &hex(&w.parties[0].signer),
    ]);
    a.extend(owned(&DECLARE));
    assert_eq!(w.no(&a), "CLI_TERMS_JSON");
    // An IPST of version 1 is refused by v2 ipst sign.
    let ipst_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/ipst");
    let mut ipsts: Vec<PathBuf> = std::fs::read_dir(ipst_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    ipsts.sort();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ipsts[0]).unwrap()).unwrap();
    let doc = w.path("v1.ipst");
    std::fs::write(&doc, v["ipst"].to_string()).unwrap();
    let args = w.sign_args(&doc, &w.parties[0], &w.path("v1.signed"));
    assert_eq!(w.no(&args), "IPST_UNSUPPORTED_VERSION");
}

fn address_args(w: &World, terms: &Path, me: usize) -> Vec<String> {
    let mut a = owned(&[
        "address",
        "--terms",
        s(terms),
        "--daa",
        &START_DAA.to_string(),
        "--my-key",
        &hex(&w.parties[me].signer),
        "--no-qr",
    ]);
    a.extend(owned(&DECLARE));
    a
}

#[test]
fn the_party_check_refuses_terms_that_do_not_pay_you() {
    let w = World::new(Network::Testnet);
    let good = w.terms("good", Shape::TwoTokensAndKas, true, |_| {});
    let out = w.go(&address_args(&w, &good, 2));
    assert!(field(&out, "  funding URI").ends_with(&format!(
        "?amount={KAS_LEG}&impulse={}",
        hex(&w.read(&good).terms_hash())
    )));
    // A key that deposits nothing.
    let a = replace(
        &address_args(&w, &good, 0),
        "--my-key",
        &hex(&w.payer.signer),
    );
    assert_eq!(w.no(&a), "CLI_ROLE_KEY_MISMATCH");
    // My refund pays another depositor, or the authority: refused even with a pin.
    let to_other = w.terms("other", Shape::TwoTokensAndKas, true, |t| {
        t.legs[0].refund.identifier = w.parties[1].signer
    });
    let pinned = with(
        &address_args(&w, &to_other, 0),
        &[
            "--my-refund",
            &format!("kcc20:pubkey:{}", hex(&w.parties[1].signer)),
        ],
    );
    assert_eq!(w.no(&pinned), "CLI_DESTINATION_NOT_MINE");
    let to_authority = w.terms("auth", Shape::TwoTokensAndKas, true, |t| {
        t.legs[0].refund.identifier = w.authority.signer
    });
    assert_eq!(
        w.no(&address_args(&w, &to_authority, 0)),
        "CLI_DESTINATION_NOT_MINE"
    );
    let pinned = with(
        &address_args(&w, &to_authority, 0),
        &[
            "--my-refund",
            &format!("kcc20:pubkey:{}", hex(&w.authority.signer)),
        ],
    );
    assert_eq!(w.no(&pinned), "CLI_DESTINATION_NOT_MINE");
    // My refund pays a script: refused unless pinned.
    let script: [u8; 32] = rand::random();
    let to_script = w.terms("script", Shape::TwoTokensAndKas, true, |t| {
        t.legs[0].refund = DestinationV2 {
            identifier_type: IdentifierType::ScriptHash,
            identifier: script,
        }
    });
    assert_eq!(
        w.no(&address_args(&w, &to_script, 0)),
        "CLI_DESTINATION_NOT_MINE"
    );
    let out = w.go(&with(
        &address_args(&w, &to_script, 0),
        &[
            "--my-refund",
            &format!("kcc20:script_hash:{}", hex(&script)),
        ],
    ));
    assert!(out.contains("leg 0 refund equals --my-refund"), "{out}");
    // Nothing is delivered to me: refused; a pin of the delivery accepts it.
    let custodian: [u8; 32] = rand::random();
    let nothing = w.terms("nothing", Shape::TwoTokensAndKas, true, |t| {
        t.legs[2].delivery = DestinationV2 {
            identifier_type: IdentifierType::ScriptHash,
            identifier: custodian,
        }
    });
    assert_eq!(
        w.no(&address_args(&w, &nothing, 0)),
        "CLI_DESTINATION_NOT_MINE"
    );
    let custodian_address = kaspa_addresses::Address::new(
        impulse_core::address::prefix(Network::Testnet),
        kaspa_addresses::Version::ScriptHash,
        &custodian,
    )
    .to_string();
    let out = w.go(&with(
        &address_args(&w, &nothing, 0),
        &["--my-delivery", &custodian_address],
    ));
    assert!(
        out.contains("leg 2 is delivered to you (equals --my-delivery)"),
        "{out}"
    );
    // A pin that does not parse.
    assert_eq!(
        w.no(&with(
            &address_args(&w, &good, 0),
            &["--my-delivery", "nonsense"]
        )),
        "CLI_DESTINATION_PIN_INVALID"
    );
}

#[test]
fn terms_are_refused_before_funding_when_a_kas_leg_is_below_min_v2() {
    let w = World::new(Network::Testnet);
    let t = w.base_terms(Shape::TwoTokensAndKas, false, FundingMode::Revocable);
    let minimum = min_v2(&t, 1);
    let at = w.terms("at", Shape::TwoTokensAndKas, false, |t| {
        t.legs[2].asset.amount = minimum
    });
    w.go(&address_args(&w, &at, 2));
    let below = w.terms("below", Shape::TwoTokensAndKas, false, |t| {
        t.legs[2].asset.amount = minimum - 1
    });
    assert_eq!(w.no(&address_args(&w, &below, 2)), "TX_BELOW_MIN_KAS");
}

#[test]
fn mainnet_needs_the_explicit_flag_and_a_node() {
    let w = World::new(Network::Mainnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    assert_eq!(w.no(&address_args(&w, &terms, 0)), "CLI_MAINNET_NEEDS_NODE");
    let with_node = replace(
        &without(&address_args(&w, &terms, 0), "--daa"),
        "--node",
        NODE,
    );
    w.go(&with_node);
    // Without --network mainnet the command acts on testnet and refuses mainnet terms.
    w.explicit.set(false);
    assert_eq!(w.no(&with_node), "CLI_NETWORK_MISMATCH");
}

// =============================================================================================
// Builders
// =============================================================================================

#[test]
fn fund_build_funds_only_your_own_leg_with_its_own_arguments() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    let out_path = w.path("f");
    let control = w.fund_args(&terms, 0, &out_path);
    assert_eq!(
        w.no(&replace(&control, "--leg", "3")),
        "TEMPLATE_V2_LEG_INDEX"
    );
    assert_eq!(
        w.no(&replace(&control, "--leg", "1")),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    assert_eq!(
        w.no(&replace(&control, "--pay-from", &w.addr(&w.payer))),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    // A KCC-20 leg needs its template and a token; a KAS leg takes no token arguments.
    assert_eq!(w.no(&no_templates(&control)), "CLI_TEMPLATE_MISSING");
    assert_eq!(w.no(&without(&control, "--token")), "CLI_UTXO_NOT_FOUND");
    let kas = w.fund_args(&terms, 2, &out_path);
    assert_eq!(w.no(&with(&kas, &["--carrier", "1"])), "TX_WRONG_MODE");
    // The value cap: a KCC-20 leg needs the declaration.
    assert_eq!(
        w.no(&without(&control, "--kas-equivalent")),
        "CLI_VALUE_UNKNOWN"
    );
    assert_eq!(
        w.no(&replace(&control, "--kas-equivalent", "1000000001")),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    // Control: it builds, warns that the other legs are unfunded, and uses MIN_V2 carriers.
    let out = w.go(&control);
    assert_eq!(field(&out, "ipst"), "v2 fund_kcc20 leg 0");
    assert!(
        out.contains("warning: legs 1, 2 are not funded yet"),
        "{out}"
    );
    let t = w.read(&terms);
    assert!(field(&out, "output 0").starts_with(&format!("{} sompi", min_v2(t.terms(), 2))));
    assert!(field(&out, "output 1").starts_with(&format!("{} sompi", min_v2(t.terms(), 1))));
}

#[test]
fn the_v2_trade_value_is_the_sum_of_the_kas_legs_at_least() {
    let w = World::new(Network::Testnet);
    // Three KAS legs of 4 KAS each: 12 KAS together, above the 10 KAS cap, though each is below.
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |t| {
        for l in t.legs.iter_mut() {
            l.asset = Leg {
                kind: LegKind::Kas,
                amount: 400_000_000,
            };
        }
    });
    let a = without(&address_args(&w, &terms, 0), "--kas-equivalent");
    assert_eq!(w.no(&a), "CLI_VALUE_CAP_EXCEEDED");
    let out = w.go(&with(&a, &["--i-accept-the-risk"]));
    assert!(out.contains("value cap: lifted"), "{out}");
    *w.max_value.borrow_mut() = Some("2000000000".into());
    assert_eq!(w.no(&a), "CLI_VALUE_CAP_INVALID");
}

#[test]
fn settle_build_needs_every_leg_funded() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    w.fund(&terms, 0);
    w.fund(&terms, 2);
    let args = w.settle_args(&terms, &w.payer, &w.path("s"));
    assert_eq!(w.no(&args), "CLI_UTXO_NOT_FOUND");
    w.fund(&terms, 1);
    assert_eq!(w.no(&no_templates(&args)), "CLI_TEMPLATE_MISSING");
    w.go(&args);
}

#[test]
fn refund_build_checks_the_leg_the_signer_and_the_token_flags() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    let out = w.path("r");
    assert_eq!(
        w.no(&w.refund_args(&terms, 0, "0", &w.parties[0], &out)),
        "CLI_UTXO_NOT_FOUND"
    );
    w.fund(&terms, 0);
    w.fund(&terms, 2);
    assert_eq!(
        w.no(&w.refund_args(&terms, 3, "0", &w.parties[0], &out)),
        "TEMPLATE_V2_LEG_INDEX"
    );
    // No authority in these terms.
    assert_eq!(
        w.no(&w.refund_args(&terms, 0, "authority", &w.parties[0], &out)),
        "TX_REFUND_SIGNER"
    );
    // Only the depositor refunds a KCC-20 leg without its token.
    let bare = with(
        &w.refund_args(&terms, 0, "1", &w.parties[1], &out),
        &["--without-token"],
    );
    assert_eq!(w.no(&bare), "TX_REFUND_SIGNER");
    let kas = with(
        &w.refund_args(&terms, 2, "2", &w.parties[2], &out),
        &["--without-token"],
    );
    assert_eq!(w.no(&kas), "TX_WRONG_MODE");
    let own = w.go(&with(
        &w.refund_args(&terms, 0, "0", &w.parties[0], &out),
        &["--without-token"],
    ));
    assert!(own.contains("note: the escrowed token stays owned by the vault of leg 0"));
}

// =============================================================================================
// ipst sign
// =============================================================================================

#[test]
fn ipst_sign_holds_each_signer_to_its_own_part() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    let fund0 = w.path("fund0");
    w.go(&w.fund_args(&terms, 0, &fund0));
    let out = w.path("signed");
    let control = w.sign_args(&fund0, &w.parties[0], &out);
    // Another depositor cannot sign the funding of leg 0.
    assert_eq!(
        w.no(&replace(
            &replace(&control, "--my-key", &hex(&w.parties[1].signer)),
            "--key-file",
            s(&w.parties[1].path)
        )),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    // A depositor's key as a payer, or other terms.
    assert_eq!(
        w.no(&replace(&control, "--role", "payer")),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        w.no(&replace(&control, "--terms-hash", &hex(&[1; 32]))),
        "CLI_IPST_TERMS_NOT_AGREED"
    );
    // The deposit as the signer confirms it.
    assert_eq!(
        w.no(&with(&control, &["--carrier", "1"])),
        "CLI_IPST_DEPOSIT_MISMATCH"
    );
    // Change that is not mine, and a fee above the limit.
    assert_eq!(
        w.no(&with(&control, &["--change", &w.addr(&w.payer)])),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
    assert_eq!(
        w.no(&with(&control, &["--max-fee", "1"])),
        "CLI_IPST_FEE_TOO_HIGH"
    );
    let signed = w.go(&control);
    assert_eq!(field(&signed, "pending"), "complete");
    assert!(signed.contains("you commit: "), "{signed}");
    // Signed: nothing left to sign.
    assert_eq!(
        w.no(&w.sign_args(&out, &w.parties[0], &w.path("again"))),
        "CLI_IPST_NOTHING_TO_SIGN"
    );
    // No key file content appears in any output.
    for k in w.parties.iter().chain([&w.authority, &w.payer]) {
        assert!(!signed.contains(k.content.trim()));
    }
}

#[test]
fn a_settle_payer_accepts_no_top_up_by_default() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Shape::TwoTokensAndKas, false, |_| {});
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let unsigned = w.path("settle");
    let built = w.go(&w.settle_args(&terms, &w.payer, &unsigned));
    let topup: u64 = field(&built, "payer cost beyond the fee")
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let args = w.sign_args(&unsigned, &w.payer, &w.path("signed"));
    if topup > 0 {
        assert_eq!(w.no(&args), "CLI_IPST_TOPUP_TOO_HIGH");
        w.go(&with(&args, &["--max-topup", &topup.to_string()]));
    } else {
        w.go(&args);
    }
}

#[test]
fn partial_terms_are_shown_warned_and_fundable() {
    let w = World::new(Network::Testnet);
    let mut t = w.base_terms(Shape::TwoTokensAndKas, false, FundingMode::Revocable);
    t.legs[0].asset.amount = 10;
    t.legs[1].asset.amount = 20;
    t.legs[2].asset.amount = 200_000_000;
    t.partial = Some(Partial {
        lot_count: 2,
        min_lot: 1,
    });
    let terms = w.write_terms("partial", t);
    let out = w.go(&address_args(&w, &terms, 2));
    assert!(out.contains("partial: lot_count 2, min_lot 1"), "{out}");
    assert!(
        out.contains("warning: partial terms without an authority"),
        "{out}"
    );
    // Partial terms fund as a KIP-20 genesis (I17): the vault output is bound to a covenant ID.
    let built = w.go(&w.fund_args(&terms, 2, &w.path("f")));
    assert!(
        built
            .lines()
            .any(|l| l.starts_with("output 0: ") && l.contains("covenant")),
        "{built}"
    );
}

// =============================================================================================
// I17: a partial trade funds as KIP-20 genesis legs and settles in tranches
// =============================================================================================

/// Four lots: 40, 28 and 4 KAS of 1e8 sompi, so a lot of the KAS leg and each remainder hold the
/// MIN_V2 of a vault output (spec/V2.md 6.2).
fn partial_terms(w: &World, name: &str, authority: bool) -> PathBuf {
    w.terms(name, Shape::TwoTokensAndKas, authority, |t| {
        t.legs[0].asset.amount = 40;
        t.legs[1].asset.amount = 28;
        t.legs[2].asset.amount = 4 * KAS_LEG;
        t.partial = Some(Partial {
            lot_count: 4,
            min_lot: 1,
        });
    })
}

#[test]
fn a_partial_trade_funds_as_genesis_and_settles_in_tranches() {
    let w = World::new(Network::Testnet);
    let terms = partial_terms(&w, "t", true);
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let t = w.read(&terms);
    // Each tranche adds a carrier for every remainder token: 2 x MIN_V2(2, O) = 160,000,000.
    *w.max_topup.borrow_mut() = Some("160000000".into());
    // Every leg is its own genesis: the vault UTXOs carry distinct covenant IDs.
    let covenants: Vec<_> = (0..3)
        .map(|i| {
            let spk = w.vault(&terms, i).script_public_key();
            let utxos = w.sim.state.borrow().utxos_at(&spk);
            assert_eq!(utxos.len(), 1, "leg {i}");
            utxos[0].entry.covenant_id.expect("bound")
        })
        .collect();
    assert!(
        covenants[0] != covenants[1]
            && covenants[1] != covenants[2]
            && covenants[0] != covenants[2]
    );
    let mut verify = owned(&[
        "verify",
        "--terms",
        s(&terms),
        "--node",
        NODE,
        "--my-key",
        &hex(&w.parties[0].signer),
    ]);
    verify.extend(w.template_args());
    let verified = w.go(&verify);
    assert!(verified.contains("(4 of 4 lots)"), "{verified}");
    // Tranche 1 and 2, then the rest. The last transaction is the final layout.
    let kas_spk = kas_destination(&t.terms().legs[2].delivery);
    for (step, lots, kind, left) in [
        (0, Some("1"), "v2 settle tranche of 1 lots", 3),
        (1, Some("2"), "v2 settle tranche of 2 lots", 1),
        (2, None, "v2 settle", 0),
    ] {
        let unsigned = w.path(&format!("tranche-{step}"));
        let mut args = w.settle_args(&terms, &w.payer, &unsigned);
        if let Some(l) = lots {
            args.extend(owned(&["--tranche", l]));
        }
        let built = w.go(&args);
        assert_eq!(field(&built, "ipst"), kind, "{built}");
        w.sign_submit(&unsigned, &[&w.payer, &w.authority]);
        let kas_vault = w.vault(&terms, 2).script_public_key();
        let rest = w.unspent_at(&kas_vault);
        if left > 0 {
            assert_eq!(rest, vec![left * KAS_LEG], "step {step}");
            assert_eq!(
                w.unspent_at(&w.vault(&terms, 0).script_public_key()).len(),
                1
            );
        } else {
            assert!(rest.is_empty(), "the final settle leaves no vault UTXO");
        }
    }
    // The recipient of the KAS leg received 1, 2 and 1 lots of 1e8.
    let got = w.unspent_at(&kas_spk);
    for lot in [KAS_LEG, 2 * KAS_LEG, KAS_LEG] {
        assert!(got.contains(&lot), "{got:?}");
    }
}

#[test]
fn tranche_faults_are_refused_with_their_codes() {
    let w = World::new(Network::Testnet);
    let terms = partial_terms(&w, "t", true);
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let unsigned = w.path("tranche");
    let base = w.settle_args(&terms, &w.payer, &unsigned);
    // Controls first: 1 lot builds.
    w.go(&with(&base, &["--tranche", "1"]));
    std::fs::remove_file(&unsigned).unwrap();
    for lots in ["0", "5", "4294967296"] {
        assert_eq!(
            w.no(&with(&base, &["--tranche", lots])),
            "TX_TRANCHE",
            "{lots}"
        );
    }
    // A trade without partial names no tranche.
    let plain = w.terms("plain", Shape::TwoTokensAndKas, true, |_| {});
    for leg in 0..3 {
        w.fund(&plain, leg);
    }
    let plain_base = w.settle_args(&plain, &w.payer, &w.path("plain-settle"));
    assert_eq!(w.no(&with(&plain_base, &["--tranche", "1"])), "TX_TRANCHE");
}

#[test]
fn a_partly_filled_vault_refunds_home() {
    let w = World::new(Network::Testnet);
    let terms = partial_terms(&w, "t", true);
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let unsigned = w.path("tranche");
    *w.max_topup.borrow_mut() = Some("160000000".into());
    let built = w.go(&with(
        &w.settle_args(&terms, &w.payer, &unsigned),
        &["--tranche", "1"],
    ));
    assert!(
        field(&built, "settler cost").starts_with("160000000 sompi"),
        "{built}"
    );
    w.sign_submit(&unsigned, &[&w.payer, &w.authority]);
    let t = w.read(&terms);
    // Leg 2 (KAS) by the authority: the three remaining lots go to its refund destination.
    let r2 = w.path("refund-2");
    w.go(&w.refund_args(&terms, 2, "authority", &w.authority, &r2));
    w.sign_submit(&r2, &[&w.authority]);
    assert!(w
        .unspent_at(&kas_destination(&t.terms().legs[2].refund))
        .contains(&(3 * KAS_LEG)));
    // Leg 0 (KCC-20) by its depositor with the remaining 30 token units.
    let r0 = w.path("refund-0");
    w.go(&w.refund_args(&terms, 0, "0", &w.parties[0], &r0));
    w.sign_submit(&r0, &[&w.parties[0]]);
    assert_eq!(w.held(0, w.parties[0].signer, 30), 1);
}

/// Runs `status` for `txid` with a key file and returns the receipt path.
fn receipt_of(
    w: &World,
    terms: &Path,
    txid: &str,
    from: &str,
    name: &str,
    previous: Option<&Path>,
) -> PathBuf {
    let out = w.path(name);
    let mut a = owned(&[
        "status",
        "--terms",
        s(terms),
        "--txid",
        txid,
        "--from-block",
        from,
        "--node",
        NODE,
        "--key-file",
        s(&w.payer.path),
        "--out",
        s(&out),
        "--min-depth",
        "0",
    ]);
    if let Some(p) = previous {
        a.extend(owned(&["--previous", s(p)]));
    }
    w.go(&a);
    out
}

fn verify_receipt_args(
    w: &World,
    terms: &Path,
    receipt: &Path,
    previous: Option<&Path>,
) -> Vec<String> {
    let mut a = owned(&[
        "receipt",
        "verify",
        "--receipt",
        s(receipt),
        "--terms",
        s(terms),
        "--signer",
        &hex(&w.payer.signer),
        "--node",
        NODE,
    ]);
    if let Some(p) = previous {
        a.extend(owned(&["--previous", s(p)]));
    }
    a
}

#[test]
fn every_tranche_has_a_receipt_that_verifies_and_chains() {
    let w = World::new(Network::Testnet);
    let terms = partial_terms(&w, "t", true);
    *w.max_topup.borrow_mut() = Some("160000000".into());
    for leg in 0..3 {
        w.fund(&terms, leg);
    }
    let mut receipts: Vec<PathBuf> = Vec::new();
    for (step, lots) in [Some("1"), Some("2"), None].into_iter().enumerate() {
        let unsigned = w.path(&format!("tranche-{step}"));
        let mut args = w.settle_args(&terms, &w.payer, &unsigned);
        if let Some(l) = lots {
            args.extend(owned(&["--tranche", l]));
        }
        w.go(&args);
        let from = hex(&w.sim.state.borrow().sink());
        let txid = w.sign_submit(&unsigned, &[&w.payer, &w.authority]);
        let previous = receipts.last().cloned();
        let r = receipt_of(
            &w,
            &terms,
            &txid,
            &from,
            &format!("receipt-{step}"),
            previous.as_deref(),
        );
        let out = w.go(&verify_receipt_args(&w, &terms, &r, previous.as_deref()));
        assert!(out.contains("quantities: follow from the terms"), "{out}");
        assert!(out.contains("match the receipt"), "{out}");
        assert!(out.contains("(state: accepted)"), "{out}");
        let (this, cumulative) = [(1, 1), (2, 3), (1, 4)][step];
        assert!(
            out.contains(&format!(
                "lots: {this} in this transaction, {cumulative} of 4 in the lineage so far"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "leg 2: moved {}, cumulative {} of {}",
                this * KAS_LEG,
                cumulative * KAS_LEG,
                4 * KAS_LEG
            )),
            "{out}"
        );
        assert!(!out.contains("settled"), "{out}");
        if previous.is_some() {
            assert!(
                out.contains("lineage: checked against the previous receipt"),
                "{out}"
            );
        }
        receipts.push(r);
    }
    // A chain out of order, a receipt without its predecessor, a receipt of the wrong trade.
    let mut skip = verify_receipt_args(&w, &terms, &receipts[2], Some(&receipts[0]));
    assert_eq!(w.no(&skip), "RECEIPT_LINEAGE_MISMATCH");
    skip = verify_receipt_args(&w, &terms, &receipts[1], None);
    let out = w.go(&skip);
    assert!(
        out.contains("the previous receipt was not supplied"),
        "{out}"
    );
    // Fields the receipt must state.
    let text = std::fs::read_to_string(&receipts[1]).unwrap();
    for key in [
        "lots",
        "cumulative_lots",
        "total_lots",
        "prior_receipt",
        "legs",
    ] {
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v.as_object_mut().unwrap().remove(key);
        let bad = w.path(&format!("missing-{key}"));
        std::fs::write(&bad, v.to_string()).unwrap();
        assert_eq!(
            w.no(&verify_receipt_args(&w, &terms, &bad, None)),
            "RECEIPT_QUANTITY_MISSING",
            "{key}"
        );
    }
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["legs"][0].as_object_mut().unwrap().remove("cumulative");
    let bad = w.path("missing-leg-field");
    std::fs::write(&bad, v.to_string()).unwrap();
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &bad, None)),
        "RECEIPT_QUANTITY_MISSING"
    );
    // Any edit breaks the signature.
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["cumulative_lots"] = "4".into();
    let bad = w.path("edited");
    std::fs::write(&bad, v.to_string()).unwrap();
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &bad, None)),
        "RECEIPT_SIGNATURE_INVALID"
    );
    // A version 1 receipt states no quantity.
    let v1 = w.path("v1.json");
    std::fs::write(&v1, r#"{"version": 1}"#).unwrap();
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &v1, None)),
        "RECEIPT_QUANTITY_MISSING"
    );
    // A receipt signed with the right key but stating what the terms or the chain do not say.
    let genuine =
        crate::receipt_v2::ReceiptV2::parse(&std::fs::read_to_string(&receipts[0]).unwrap())
            .unwrap();
    let resign = |name: &str, edit: &dyn Fn(&mut crate::receipt_v2::Quantity)| {
        let mut q = genuine.quantity.clone();
        edit(&mut q);
        let r = crate::receipt_v2::ReceiptV2::sign(genuine.observation, q, &w.payer.path, false)
            .unwrap();
        let p = w.path(name);
        std::fs::write(&p, r.render()).unwrap();
        p
    };
    // Against the terms alone: two lots of a first receipt whose cumulative says one.
    let bad = resign("bad-terms", &|q| q.lots = 2);
    let mut offline = verify_receipt_args(&w, &terms, &bad, None);
    offline.truncate(offline.len() - 2);
    assert_eq!(
        w.no(&offline),
        "RECEIPT_QUANTITY_MISMATCH",
        "without --node"
    );
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &bad, None)),
        "RECEIPT_QUANTITY_MISMATCH"
    );
    // Consistent with the terms, but the chain moved one lot, not two.
    let two = resign("two-lots", &|q| {
        q.lots = 2;
        q.cumulative_lots = 2;
        for (i, l) in q.legs.iter_mut().enumerate() {
            l.moved = 2 * w.read(&terms).terms().unit(i);
            l.cumulative = l.moved;
        }
    });
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &two, None)),
        "RECEIPT_QUANTITY_MISMATCH"
    );
    // The lineage the chain shows: another covenant ID or another spent outpoint.
    let cov = resign("other-covenant", &|q| q.legs[0].covenant = [9; 32]);
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &cov, None)),
        "RECEIPT_LINEAGE_MISMATCH"
    );
    let spent = resign("other-outpoint", &|q| q.legs[1].spent.index += 1);
    assert_eq!(
        w.no(&verify_receipt_args(&w, &terms, &spent, None)),
        "RECEIPT_LINEAGE_MISMATCH"
    );
    // The other terms: a receipt for this trade is not another trade's.
    let other = partial_terms(&w, "other", true);
    assert_eq!(
        w.no(&verify_receipt_args(&w, &other, &receipts[0], None)),
        "RECEIPT_TERMS_MISMATCH"
    );
}

#[test]
fn status_states_a_quantity_only_for_a_v2_settle() {
    let w = World::new(Network::Testnet);
    let terms = partial_terms(&w, "t", true);
    for leg in 0..2 {
        w.fund(&terms, leg);
    }
    let from = hex(&w.sim.state.borrow().sink());
    let fund_id = w.fund(&terms, 2);
    let args = owned(&[
        "status",
        "--terms",
        s(&terms),
        "--txid",
        &fund_id,
        "--from-block",
        &from,
        "--node",
        NODE,
    ]);
    let out = w.go(&args);
    assert!(out.contains("not a v2 settle of these terms"), "{out}");
    let mut signed = args.clone();
    signed.extend(owned(&[
        "--key-file",
        s(&w.payer.path),
        "--out",
        s(&w.path("r")),
        "--min-depth",
        "0",
    ]));
    assert_eq!(w.no(&signed), "IPST_TERMS_MISMATCH");
}
