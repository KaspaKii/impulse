// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Phase 2 commands end to end in process, against the in-memory fake node (`sim`), which runs
//! every submitted input in the pinned script engine. Each refusal has a failing case beside an
//! accepted control, and every refused command is checked to have printed nothing. Keys are
//! throwaway keys generated at runtime into temporary directories that are removed; no key
//! literal exists.

use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, outpoint_text, p2pk_address};
use crate::json::hex;
use crate::node::Node;
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::terms_file::render_terms_file;
use crate::testutil::TempDir;
use clap::Parser;
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, TERMS_VERSION,
};
use impulse_core::tx::{
    fund_kas, fund_kcc20, min_relay_fee, FeePayment, Ipst, Kcc20Deposit, Kcc20State, Kcc20Template,
    TokenUtxo, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const ASSET_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const CASH_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-cash.json");
const NODE: &str = "ws://127.0.0.1:17210";
const START_DAA: u64 = 1_000_000;
const EXPIRY_IN: u64 = 864_000;
const ASSET_AMOUNT: u64 = 10;
const CASH_TOKENS: u64 = 7;
const KAS_CASH: u64 = 100_000_000;
const DECLARE: [&str; 2] = ["--kas-equivalent", "100000000"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Vault, authority, KAS cash, earmarked.
    Authority,
    /// Vault, no authority, KCC-20 cash, revocable.
    SelfSettling,
    /// Vault, authority, external cash, revocable.
    External,
    /// Direct, KAS cash.
    Direct,
    /// Direct, KCC-20 cash.
    DirectKcc20,
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn random32() -> [u8; 32] {
    rand::random()
}

struct World {
    dir: TempDir,
    sim: SimNode,
    network: Network,
    seller: KeyFile,
    buyer: KeyFile,
    authority: KeyFile,
    asset: Kcc20Template,
    cash: Kcc20Template,
    asset_cov: [u8; 32],
    cash_cov: [u8; 32],
    /// The seller's asset token and the buyer's cash token, `<txid>:<index>:<amount>`.
    seller_token: RefCell<String>,
    buyer_token: RefCell<String>,
    /// IMPULSE_MAX_VALUE for the next commands.
    max_value: RefCell<Option<String>>,
    /// Whether commands get `--network mainnet` (by default, exactly on a mainnet world).
    explicit: std::cell::Cell<bool>,
    /// When set, the node the commands reach lies (see [`Lying`]).
    lie: RefCell<Option<Lie>>,
}

/// How a scripted node lies: it rewrites every UTXO it reports, or the spent entries of every
/// accepted transaction it reports.
#[derive(Clone, Copy)]
enum Lie {
    Utxo(fn(&mut impulse_core::tx::Utxo)),
    Spent(fn(&mut Vec<kaspa_consensus_core::tx::UtxoEntry>)),
}

/// The fake node, answering through a [`Lie`]: a hostile node, for the checks that must not
/// trust what a node reports.
struct Lying {
    inner: SimNode,
    lie: Lie,
}

impl Node for Lying {
    fn server_info(&self) -> Result<crate::node::ServerInfo, CliError> {
        self.inner.server_info()
    }
    fn dag_info(&self) -> Result<crate::node::DagInfo, CliError> {
        self.inner.dag_info()
    }
    fn block(&self, hash: [u8; 32]) -> Result<crate::node::BlockInfo, CliError> {
        self.inner.block(hash)
    }
    fn virtual_chain_from(&self, start: [u8; 32]) -> Result<crate::node::ChainUpdate, CliError> {
        self.inner.virtual_chain_from(start)
    }
    fn submit(&self, tx: &kaspa_consensus_core::tx::Transaction) -> Result<[u8; 32], CliError> {
        self.inner.submit(tx)
    }
    fn utxos(
        &self,
        address: &kaspa_addresses::Address,
    ) -> Result<Vec<impulse_core::tx::Utxo>, CliError> {
        let mut all = self.inner.utxos(address)?;
        if let Lie::Utxo(f) = self.lie {
            all.iter_mut().for_each(f);
        }
        Ok(all)
    }
    fn accepted_from(&self, start: [u8; 32]) -> Result<crate::node::AcceptedUpdate, CliError> {
        let mut update = self.inner.accepted_from(start)?;
        if let Lie::Spent(f) = self.lie {
            for (_, txs) in &mut update.accepted {
                for a in txs {
                    f(&mut a.spent);
                }
            }
        }
        Ok(update)
    }
}

impl World {
    fn new(network: Network) -> Self {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("asset.json"), ASSET_JSON).unwrap();
        std::fs::write(dir.path().join("cash.json"), CASH_JSON).unwrap();
        let mut state = SimState::new(network, START_DAA, 0);
        let (seller, buyer, authority) = (key_file(), key_file(), key_file());
        for k in [&seller, &buyer, &authority] {
            let spk = address_script(&p2pk_address(&k.signer, network));
            for amount in [400_000_000_000, 300_000_000_000] {
                state.add_utxo(spk.clone(), amount, None);
            }
        }
        let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let cash = Kcc20Template::from_json(CASH_JSON).unwrap();
        let (asset_cov, cash_cov) = (random32(), random32());
        let held = |key: [u8; 32], amount| {
            Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::PubKey,
                    identifier: key,
                },
                amount,
            )
        };
        let st = held(seller.signer, 1_000);
        let o = state.add_utxo(
            asset.script_public_key(&st).unwrap(),
            MIN_KCC20_OUTPUT,
            Some(asset_cov),
        );
        let seller_token = format!("{}:1000", outpoint_text(&o));
        let bt = held(buyer.signer, 1_000);
        let o = state.add_utxo(
            cash.script_public_key(&bt).unwrap(),
            MIN_KCC20_OUTPUT,
            Some(cash_cov),
        );
        let buyer_token = format!("{}:1000", outpoint_text(&o));
        // Direct legs: the seller's exact asset (two trades), the buyer's exact KAS and exact
        // cash token.
        for _ in 0..2 {
            state.add_utxo(
                asset
                    .script_public_key(&held(seller.signer, ASSET_AMOUNT))
                    .unwrap(),
                MIN_KCC20_OUTPUT,
                Some(asset_cov),
            );
        }
        state.add_utxo(
            address_script(&p2pk_address(&buyer.signer, network)),
            KAS_CASH,
            None,
        );
        state.add_utxo(
            cash.script_public_key(&held(buyer.signer, CASH_TOKENS))
                .unwrap(),
            MIN_KCC20_OUTPUT,
            Some(cash_cov),
        );
        Self {
            dir,
            sim: SimNode::memory(state),
            network,
            seller,
            buyer,
            authority,
            asset,
            cash,
            asset_cov,
            cash_cov,
            seller_token: RefCell::new(seller_token),
            buyer_token: RefCell::new(buyer_token),
            max_value: RefCell::new(None),
            explicit: std::cell::Cell::new(network == Network::Mainnet),
            lie: RefCell::new(None),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn tpl(&self, leg: LegIndex) -> String {
        s(&self.path(match leg {
            LegIndex::Asset => "asset.json",
            LegIndex::Cash => "cash.json",
        }))
        .to_string()
    }

    fn addr(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, self.network).to_string()
    }

    fn token(&self, template: &Kcc20Template, covenant_id: [u8; 32]) -> Kcc20Token {
        Kcc20Token {
            covenant_id,
            template_hash: template.template_hash(),
            template_prefix_len: template.prefix_len() as u32,
            template_suffix_len: template.suffix_len() as u32,
        }
    }

    fn base_terms(&self, mode: Mode) -> Terms {
        let p2pk = |k: &KeyFile| {
            Destination::Kas(ScriptPublicKey::from_vec(
                0,
                [&[0x20][..], &k.signer, &[0xac]].concat(),
            ))
        };
        let owner = |k: &KeyFile| {
            Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: k.signer,
            })
        };
        let kcc20_cash = Leg {
            kind: LegKind::Kcc20(self.token(&self.cash, self.cash_cov)),
            amount: CASH_TOKENS,
        };
        let kas_cash = Leg {
            kind: LegKind::Kas,
            amount: KAS_CASH,
        };
        let (settlement_mode, authority, cash, funding) = match mode {
            Mode::Authority => (
                SettlementMode::Vault,
                true,
                kas_cash,
                FundingMode::Earmarked,
            ),
            Mode::SelfSettling => (
                SettlementMode::Vault,
                false,
                kcc20_cash,
                FundingMode::Revocable,
            ),
            Mode::External => (
                SettlementMode::Vault,
                true,
                Leg {
                    kind: LegKind::External,
                    amount: 1,
                },
                FundingMode::Revocable,
            ),
            Mode::Direct => (
                SettlementMode::Direct,
                false,
                kas_cash,
                FundingMode::Revocable,
            ),
            Mode::DirectKcc20 => (
                SettlementMode::Direct,
                false,
                kcc20_cash,
                FundingMode::Revocable,
            ),
        };
        let (proceeds, buyer_refund) = match cash.kind {
            LegKind::Kas => (p2pk(&self.seller), p2pk(&self.buyer)),
            LegKind::Kcc20(_) => (owner(&self.seller), owner(&self.buyer)),
            LegKind::External => (Destination::OffChain, Destination::OffChain),
        };
        Terms {
            version: TERMS_VERSION,
            network: self.network,
            settlement_mode,
            nonce: rand::random(),
            seller_key: self.seller.signer,
            buyer_key: self.buyer.signer,
            authority_key: authority.then_some(self.authority.signer),
            asset_leg: Leg {
                kind: LegKind::Kcc20(self.token(&self.asset, self.asset_cov)),
                amount: ASSET_AMOUNT,
            },
            cash_leg: cash,
            buyer_delivery: owner(&self.buyer),
            seller_proceeds: proceeds,
            seller_refund: owner(&self.seller),
            buyer_refund,
            earliest_daa: None,
            expiry_daa: START_DAA + EXPIRY_IN,
            funding_mode: funding,
            trade_ref: random32(),
        }
    }

    /// Writes a terms file for `mode`, edited, and returns its path.
    fn terms(&self, name: &str, mode: Mode, edit: impl FnOnce(&mut Terms)) -> PathBuf {
        let mut t = self.base_terms(mode);
        edit(&mut t);
        let v = t.validate_structure().unwrap();
        let p = self.path(name);
        std::fs::write(&p, render_terms_file(&v)).unwrap();
        p
    }

    fn exec(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse"];
        if self.explicit.get() {
            argv.extend_from_slice(&["--network", "mainnet"]);
        }
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("arguments parse");
        let sim = self.sim.clone();
        let lie = *self.lie.borrow();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(match lie {
                Some(lie) => Box::new(Lying {
                    inner: sim.clone(),
                    lie,
                }),
                None => Box::new(sim.clone()),
            })
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

    fn run(&self, args: &[&str]) -> String {
        let (r, out) = self.exec(args);
        r.unwrap_or_else(|e| panic!("{args:?}: {e}"));
        out
    }

    /// A refused command: returns its code after checking it printed nothing.
    fn refuse(&self, args: &[&str]) -> &'static str {
        let (r, out) = self.exec(args);
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }

    fn height(&self) -> usize {
        self.sim.state.borrow().height()
    }

    fn set_daa(&self, daa: u64) {
        self.sim.state.borrow_mut().virtual_daa = daa;
    }

    /// `fund build` arguments for a leg, as its depositor.
    fn fund_args(&self, terms: &Path, leg: LegIndex, out: &Path) -> Vec<String> {
        let (k, role) = match leg {
            LegIndex::Asset => (&self.seller, "seller"),
            LegIndex::Cash => (&self.buyer, "buyer"),
        };
        let mut a: Vec<String> = [
            "fund",
            "build",
            "--terms",
            s(terms),
            "--leg",
            match leg {
                LegIndex::Asset => "asset",
                LegIndex::Cash => "cash",
            },
            "--node",
            NODE,
            "--role",
            role,
            "--my-key",
            &hex(&k.signer),
            "--pay-from",
            &self.addr(k),
            "--out",
            s(out),
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        a.extend(DECLARE.iter().map(|x| x.to_string()));
        let t = crate::terms_file::read_terms_file(terms).unwrap();
        let kind = match leg {
            LegIndex::Asset => t.terms().asset_leg.kind,
            LegIndex::Cash => t.terms().cash_leg.kind,
        };
        if let LegKind::Kcc20(_) = kind {
            let (flag, token) = match leg {
                LegIndex::Asset => ("--asset-template", self.seller_token.borrow().clone()),
                LegIndex::Cash => ("--cash-template", self.buyer_token.borrow().clone()),
            };
            a.extend([flag.into(), self.tpl(leg), "--token".into(), token]);
        }
        a
    }

    /// The role a key signs as in this world.
    fn role_of(&self, k: &KeyFile) -> &'static str {
        if k.signer == self.seller.signer {
            "seller"
        } else if k.signer == self.buyer.signer {
            "buyer"
        } else if k.signer == self.authority.signer {
            "authority"
        } else {
            "payer"
        }
    }

    /// `ipst sign` arguments: `k` signs as its role, for the terms the IPST names (so the
    /// agreed-terms check passes; tests of that check replace `--terms-hash`).
    fn sign_args(&self, ipst: &Path, k: &KeyFile, out: &Path) -> Vec<String> {
        let agreed = std::fs::read_to_string(ipst)
            .ok()
            .and_then(|text| Ipst::from_json(&text).ok())
            .map_or_else(|| hex(&[0; 32]), |i| hex(&i.terms().terms_hash()));
        let mut a: Vec<String> = [
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
            "--asset-template",
            &self.tpl(LegIndex::Asset),
            "--cash-template",
            &self.tpl(LegIndex::Cash),
            "--out",
            s(out),
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        a.extend(DECLARE.iter().map(|x| x.to_string()));
        a
    }

    fn submit_args(&self, ipst: &Path) -> Vec<String> {
        [
            "submit",
            "--ipst",
            s(ipst),
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(LegIndex::Asset),
            "--cash-template",
            &self.tpl(LegIndex::Cash),
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
    }

    fn go(&self, args: &[String]) -> String {
        let v: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&v)
    }

    fn no(&self, args: &[String]) -> &'static str {
        let v: Vec<&str> = args.iter().map(String::as_str).collect();
        self.refuse(&v)
    }

    /// Builds, signs with `k` and submits; returns the submitted txid.
    fn sign_submit(&self, unsigned: &Path, k: &KeyFile) -> String {
        let signed = self.path(&format!(
            "{}.signed",
            unsigned.file_name().unwrap().to_str().unwrap()
        ));
        self.go(&self.sign_args(unsigned, k, &signed));
        let out = self.go(&self.submit_args(&signed));
        field(&out, "submitted")
    }

    /// Funds a leg as its depositor and returns the funding txid.
    fn fund(&self, terms: &Path, leg: LegIndex) -> String {
        let name = format!(
            "fund-{}-{}",
            terms.file_name().unwrap().to_str().unwrap(),
            leg as u8
        );
        let unsigned = self.path(&name);
        let out = self.go(&self.fund_args(terms, leg, &unsigned));
        if let Some(change) = out.lines().find_map(|l| l.strip_prefix("token change: ")) {
            if change.matches(':').count() == 2 {
                match leg {
                    LegIndex::Asset => *self.seller_token.borrow_mut() = change.to_string(),
                    LegIndex::Cash => *self.buyer_token.borrow_mut() = change.to_string(),
                }
            }
        }
        let k = match leg {
            LegIndex::Asset => &self.seller,
            LegIndex::Cash => &self.buyer,
        };
        self.sign_submit(&unsigned, k)
    }

    fn settle_args(&self, terms: &Path, payer: &KeyFile, out: &Path) -> Vec<String> {
        let mut a: Vec<String> = [
            "settle",
            "build",
            "--terms",
            s(terms),
            "--node",
            NODE,
            "--pay-from",
            &self.addr(payer),
            "--asset-template",
            &self.tpl(LegIndex::Asset),
            "--cash-template",
            &self.tpl(LegIndex::Cash),
            "--out",
            s(out),
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        a.extend(DECLARE.iter().map(|x| x.to_string()));
        a
    }

    fn refund_args(
        &self,
        terms: &Path,
        leg: &str,
        signer: &str,
        payer: &KeyFile,
        out: &Path,
    ) -> Vec<String> {
        let mut a: Vec<String> = [
            "refund",
            "build",
            "--terms",
            s(terms),
            "--leg",
            leg,
            "--signer",
            signer,
            "--node",
            NODE,
            "--pay-from",
            &self.addr(payer),
            "--asset-template",
            &self.tpl(LegIndex::Asset),
            "--cash-template",
            &self.tpl(LegIndex::Cash),
            "--out",
            s(out),
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        a.extend(DECLARE.iter().map(|x| x.to_string()));
        a
    }

    fn vault(&self, terms: &Path, leg: LegIndex) -> Vault {
        let t = crate::terms_file::read_terms_file(terms).unwrap();
        Vault::instantiate_existing(&t, leg).unwrap()
    }

    /// Terms of `mode`, edited, whose buyer is `key` with its own delivery and refund, and the
    /// `fund build` arguments of their cash leg as that buyer, paying from its P2PK address.
    fn buyer_funding(
        &self,
        name: &str,
        mode: Mode,
        key: [u8; 32],
        edit: impl FnOnce(&mut Terms),
    ) -> (PathBuf, Vec<String>) {
        let terms = self.terms(name, mode, |t| {
            t.buyer_key = key;
            t.buyer_delivery = Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: key,
            });
            t.buyer_refund = match t.buyer_refund.clone() {
                Destination::Kas(_) => Destination::Kas(ScriptPublicKey::from_vec(
                    0,
                    [&[0x20][..], &key, &[0xac]].concat(),
                )),
                Destination::Kcc20(_) => Destination::Kcc20(Kcc20Owner {
                    identifier_type: IdentifierType::PubKey,
                    identifier: key,
                }),
                other => other,
            };
            edit(t);
        });
        let args = self.fund_args(&terms, LegIndex::Cash, &self.path(&format!("{name}.fund")));
        let args = replace(&args, "--my-key", &hex(&key));
        let args = replace(
            &args,
            "--pay-from",
            &p2pk_address(&key, self.network).to_string(),
        );
        (terms, args)
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
    v.extend(extra.iter().map(|x| x.to_string()));
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
    let mut v = without(args, flag);
    v.extend([flag.to_string(), value.to_string()]);
    v
}

// =============================================================================================
// Controls: every mode settles, every refund role works, decode reads them back
// =============================================================================================

#[test]
fn every_mode_funds_settles_and_decodes() {
    let w = World::new(Network::Testnet);
    for (mode, name) in [
        (Mode::Authority, "authority"),
        (Mode::SelfSettling, "self"),
        (Mode::External, "external"),
    ] {
        let terms = w.terms(name, mode, |_| {});
        let from = hex(&w.sim.state.borrow().sink());
        w.fund(&terms, LegIndex::Asset);
        if mode != Mode::External {
            w.fund(&terms, LegIndex::Cash);
        }
        let unsigned = w.path(&format!("{name}-settle"));
        let payer = if mode == Mode::SelfSettling {
            &w.buyer
        } else {
            &w.authority
        };
        let built = w.go(&w.settle_args(&terms, payer, &unsigned));
        assert_eq!(field(&built, "ipst"), "settle");
        let txid = w.sign_submit(&unsigned, payer);
        let decoded = w.run(&["decode", &txid, "--node", NODE, "--from-block", &from]);
        assert!(decoded.contains("bound: yes"), "{decoded}");
        assert!(
            decoded.contains(&format!(
                "asset vault {}",
                hex(&w.vault(&terms, LegIndex::Asset).script_hash())
            )),
            "{decoded}"
        );
        assert!(decoded.contains("settle; delivers exactly 10"), "{decoded}");
        assert!(!decoded.contains("refused:"), "{decoded}");
    }
    for (mode, name) in [(Mode::Direct, "direct"), (Mode::DirectKcc20, "direct20")] {
        let terms = w.terms(name, mode, |_| {});
        let unsigned = w.path(&format!("{name}-tx"));
        let built = w.go(&w.settle_args(&terms, &w.buyer, &unsigned));
        assert_eq!(field(&built, "ipst"), "direct");
        // Each party signs its own copy; the copies are merged and submitted.
        let (a, b, m) = (
            w.path(&format!("{name}-s")),
            w.path(&format!("{name}-b")),
            w.path(&format!("{name}-m")),
        );
        w.go(&w.sign_args(&unsigned, &w.seller, &a));
        w.go(&w.sign_args(&unsigned, &w.buyer, &b));
        let merged = w.run(&[
            "ipst",
            "merge",
            "--ipst",
            s(&a),
            s(&b),
            "--node",
            NODE,
            "--asset-template",
            &w.tpl(LegIndex::Asset),
            "--cash-template",
            &w.tpl(LegIndex::Cash),
            "--out",
            s(&m),
        ]);
        assert_eq!(field(&merged, "pending"), "complete");
        let out = w.go(&w.submit_args(&m));
        assert!(out.contains("submitted: "));
    }
}

#[test]
fn every_refund_role_and_leg_kind_goes_home() {
    let w = World::new(Network::Testnet);
    // Authority mode, earmarked: the authority refunds the asset with its token, the
    // counterparty (seller) refunds the KAS cash.
    let terms = w.terms("a", Mode::Authority, |_| {});
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let r1 = w.path("r1");
    let out = w.go(&w.refund_args(&terms, "asset", "authority", &w.authority, &r1));
    assert_eq!(
        field(&out, "ipst"),
        "refund asset by authority, with the token"
    );
    w.sign_submit(&r1, &w.authority);
    let r2 = w.path("r2");
    w.go(&w.refund_args(&terms, "cash", "counterparty", &w.seller, &r2));
    w.sign_submit(&r2, &w.seller);
    // Self-settling, revocable: the buyer (depositor) refunds its KCC-20 cash with the token.
    let terms = w.terms("b", Mode::SelfSettling, |_| {});
    w.fund(&terms, LegIndex::Cash);
    let r3 = w.path("r3");
    let out = w.go(&w.refund_args(&terms, "cash", "depositor", &w.buyer, &r3));
    assert_eq!(
        field(&out, "ipst"),
        "refund cash by depositor, with the token"
    );
    w.sign_submit(&r3, &w.buyer);
    // The vaults are empty again.
    for (t, leg) in [
        ("a", LegIndex::Asset),
        ("a", LegIndex::Cash),
        ("b", LegIndex::Cash),
    ] {
        let v = w.vault(&w.path(t), leg);
        assert!(w
            .sim
            .state
            .borrow()
            .utxos_at(&v.script_public_key())
            .is_empty());
    }
}

// =============================================================================================
// Lock time: a depositor's earmarked refund before expiry is refused by submit
// =============================================================================================

#[test]
fn submit_refuses_a_transaction_the_node_would_not_yet_accept() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |t| t.expiry_daa = START_DAA + 1_000);
    w.fund(&terms, LegIndex::Cash);
    let r = w.path("r");
    let out = w.go(&w.refund_args(&terms, "cash", "depositor", &w.buyer, &r));
    assert!(
        out.contains(&format!("lock_time: {}", START_DAA + 1_000)),
        "{out}"
    );
    let signed = w.path("rs");
    w.go(&w.sign_args(&r, &w.buyer, &signed));
    let height = w.height();
    assert_eq!(w.no(&w.submit_args(&signed)), "CLI_TX_NOT_FINAL");
    assert_eq!(w.height(), height, "nothing submitted");
    // At the expiry the node still refuses it; one DAA score later it is accepted.
    w.set_daa(START_DAA + 1_000);
    assert_eq!(w.no(&w.submit_args(&signed)), "CLI_TX_NOT_FINAL");
    w.set_daa(START_DAA + 1_001);
    assert!(w.go(&w.submit_args(&signed)).contains("submitted: "));
}

// =============================================================================================
// Before funding: the KAS minimum and the pinned template
// =============================================================================================

#[test]
fn a_kas_cash_leg_below_the_minimum_is_refused_before_funding() {
    let w = World::new(Network::Testnet);
    let low = w.terms("low", Mode::Authority, |t| {
        t.cash_leg.amount = MIN_KAS_OUTPUT - 1
    });
    let ok = w.terms("ok", Mode::Authority, |t| {
        t.cash_leg.amount = MIN_KAS_OUTPUT
    });
    let party = |k: &KeyFile, role: &str| {
        vec![
            "--role".to_string(),
            role.into(),
            "--my-key".into(),
            hex(&k.signer),
            "--kas-equivalent".into(),
            "100000000".into(),
        ]
    };
    for (terms, refused) in [(&low, true), (&ok, false)] {
        let address = with(
            &["address", "--terms", s(terms), "--node", NODE, "--no-qr"].map(String::from),
            &[],
        );
        let address: Vec<String> = address
            .into_iter()
            .chain(party(&w.buyer, "buyer"))
            .collect();
        let fund_cash = w.fund_args(terms, LegIndex::Cash, &w.path(&format!("fc{refused}")));
        let fund_asset = w.fund_args(terms, LegIndex::Asset, &w.path(&format!("fa{refused}")));
        if refused {
            assert_eq!(w.no(&address), "CLI_KAS_LEG_BELOW_MIN");
            assert_eq!(w.no(&fund_cash), "CLI_KAS_LEG_BELOW_MIN");
            assert_eq!(w.no(&fund_asset), "CLI_KAS_LEG_BELOW_MIN", "whichever leg");
        } else {
            w.go(&address);
            w.go(&fund_cash);
            w.go(&fund_asset);
        }
    }
    // verify refuses it before reading the URI; the control verifies the URI address prints.
    let uri_of = |terms: &Path| {
        let mut a: Vec<String> = ["address", "--terms", s(terms), "--node", NODE, "--no-qr"]
            .map(String::from)
            .to_vec();
        a.extend(party(&w.buyer, "buyer"));
        let out = w.go(&a);
        field(&out, "  funding URI")
    };
    let ok_uri = uri_of(&ok);
    let verify = |terms: &Path| {
        let mut a: Vec<String> = [
            "verify",
            "--terms",
            s(terms),
            "--uri",
            &ok_uri,
            "--node",
            NODE,
        ]
        .map(String::from)
        .to_vec();
        a.extend(party(&w.buyer, "buyer"));
        a
    };
    assert_eq!(w.no(&verify(&low)), "CLI_KAS_LEG_BELOW_MIN");
    assert!(w.go(&verify(&ok)).contains("ok: funds the cash vault"));
    // terms new refuses it too.
    let draft = w.path("draft-low.json");
    let text = std::fs::read_to_string(&low).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    std::fs::write(&draft, v["terms"].to_string()).unwrap();
    let mut new: Vec<String> = [
        "terms",
        "new",
        "--draft",
        s(&draft),
        "--out",
        s(&w.path("new-low")),
        "--node",
        NODE,
    ]
    .map(String::from)
    .to_vec();
    new.extend(party(&w.seller, "seller"));
    assert_eq!(w.no(&new), "CLI_KAS_LEG_BELOW_MIN");
    assert!(!w.path("new-low").exists());
    let ok_text = std::fs::read_to_string(&ok).unwrap();
    let v: serde_json::Value = serde_json::from_str(&ok_text).unwrap();
    std::fs::write(&draft, v["terms"].to_string()).unwrap();
    w.go(&new);
    // ipst sign of a funding: the asset funding of the low terms, built directly by the core.
    let ipst = asset_funding(&w, &low);
    let p = w.path("low-fund.ipst");
    std::fs::write(&p, ipst.to_json()).unwrap();
    assert_eq!(
        w.no(&w.sign_args(&p, &w.seller, &w.path("low-fund-signed"))),
        "CLI_KAS_LEG_BELOW_MIN"
    );
    let ipst = asset_funding(&w, &ok);
    let p = w.path("ok-fund.ipst");
    std::fs::write(&p, ipst.to_json()).unwrap();
    w.go(&w.sign_args(&p, &w.seller, &w.path("ok-fund-signed")));
}

/// The seller's asset funding of `terms`, built by impulse-core directly (no CLI checks).
fn asset_funding(w: &World, terms: &Path) -> Ipst {
    let token = w.seller_token.borrow().clone();
    let change = address_script(&p2pk_address(&w.seller.signer, w.network));
    asset_funding_by(w, terms, &token, &w.seller, change)
}

/// The seller's asset funding of `terms` from its token UTXO `token` (`<txid>:<index>:<amount>`),
/// the fee paid from `payer`'s largest UTXO and the change to `change`, built by impulse-core
/// directly: anyone can build such an IPST, whatever `fund build` makes.
fn asset_funding_by(
    w: &World,
    terms: &Path,
    token: &str,
    payer: &KeyFile,
    change: ScriptPublicKey,
) -> Ipst {
    let t = crate::terms_file::read_terms_file(terms).unwrap();
    let ctx = impulse_core::terms::CreationContext::new(w.network, START_DAA);
    let vault = Vault::instantiate_for_creation(&t, LegIndex::Asset, &ctx).unwrap();
    let (outpoint, amount) = crate::funds::parse_token("t", token).unwrap();
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: w.seller.signer,
        },
        amount,
    );
    let spk = w.asset.script_public_key(&state).unwrap();
    let utxo = w
        .sim
        .state
        .borrow()
        .utxos_at(&spk)
        .into_iter()
        .find(|u| u.outpoint == outpoint)
        .unwrap();
    let pay = address_script(&p2pk_address(&payer.signer, w.network));
    let fee_in = w
        .sim
        .state
        .borrow()
        .utxos_at(&pay)
        .into_iter()
        .max_by_key(|u| u.entry.amount)
        .unwrap();
    fund_kcc20(
        &t,
        &vault,
        &w.asset,
        &Kcc20Deposit {
            tokens: vec![TokenUtxo { utxo, state }],
            carrier: MIN_KCC20_OUTPUT,
            authorizer: MIN_KAS_OUTPUT,
        },
        &FeePayment {
            inputs: vec![fee_in],
            fee: 1_000_000,
            change,
        },
        START_DAA,
    )
    .unwrap()
}

/// kcc20-asset.json with one suffix byte changed and its template hash recomputed: a KCC-20
/// artifact whose template is not a pinned kcc20.sil build.
fn unpinned_artifact() -> String {
    let mut v: serde_json::Value = serde_json::from_str(ASSET_JSON).unwrap();
    let c = v["contracts"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    let compiled = c["compiled"].as_object_mut().unwrap();
    let mut code: Vec<u8> = compiled["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let off = compiled["state_span"]["offset"].as_u64().unwrap() as usize;
    let len = compiled["state_span"]["len"].as_u64().unwrap() as usize;
    let last = code.len() - 1;
    code[last] ^= 0x01;
    let hash = silverscript_abi::template_hash(&code[..off], &code[off + len..]);
    compiled["bytecode"] = serde_json::json!(code);
    compiled["template_hash"] = serde_json::json!(hash.to_vec());
    v.to_string()
}

#[test]
fn an_unpinned_template_is_flagged_and_its_terms_are_not_funded() {
    let w = World::new(Network::Testnet);
    let art = unpinned_artifact();
    let unpinned_tpl = Kcc20Template::from_json(&art).unwrap();
    std::fs::write(w.path("unpinned.json"), &art).unwrap();
    let token = w.token(&unpinned_tpl, w.asset_cov);
    let unpinned = w.terms("unpinned", Mode::Authority, |t| {
        t.asset_leg.kind = LegKind::Kcc20(token)
    });
    let pinned = w.terms("pinned", Mode::Authority, |_| {});
    // address refuses it, as fund build does; the control shows the vaults.
    let address = |terms: &Path| -> Vec<String> {
        let mut a: Vec<String> = ["address", "--terms", s(terms), "--node", NODE, "--no-qr"]
            .map(String::from)
            .to_vec();
        a.extend(
            [
                "--role",
                "buyer",
                "--my-key",
                &hex(&w.buyer.signer),
                "--kas-equivalent",
                "100000000",
            ]
            .map(String::from),
        );
        a
    };
    assert_eq!(w.no(&address(&unpinned)), "CLI_TEMPLATE_UNPINNED");
    let shown = w.go(&address(&pinned));
    assert!(!shown.contains("warning:"), "control");
    // terms new flags it: one warning line, naming the leg and template, after the summary and
    // the role line; the pinned control prints none.
    let new = |terms: &Path, out: &str| -> Vec<String> {
        let draft = w.path(&format!("{out}.draft"));
        let text = std::fs::read_to_string(terms).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        std::fs::write(&draft, v["terms"].to_string()).unwrap();
        [
            "terms",
            "new",
            "--draft",
            s(&draft),
            "--out",
            s(&w.path(out)),
            "--node",
            NODE,
            "--role",
            "seller",
            "--my-key",
            &hex(&w.seller.signer),
            "--kas-equivalent",
            "100000000",
        ]
        .map(String::from)
        .to_vec()
    };
    let warned = w.go(&new(&unpinned, "new-unpinned"));
    let warnings: Vec<&str> = warned
        .lines()
        .filter(|l| l.starts_with("warning:"))
        .collect();
    assert_eq!(warnings.len(), 1, "{warned}");
    assert!(
        warnings[0].starts_with(&format!(
            "warning: the asset leg's KCC-20 template {} ",
            hex(&unpinned_tpl.template_hash())
        )),
        "{warned}"
    );
    let at = |p: &str| warned.lines().position(|l| l.starts_with(p)).unwrap();
    assert!(at("you: ") < at("warning:"), "{warned}");
    let clean = w.go(&new(&pinned, "new-pinned"));
    assert!(!clean.contains("warning:"), "control: {clean}");
    // verify gives no ok for such terms either, whatever the URI.
    let uri = field(&shown, "  funding URI");
    let verify = |terms: &Path| {
        let mut a = address(terms);
        a[0] = "verify".into();
        a.retain(|x| x != "--no-qr");
        with(&a, &["--uri", &uri])
    };
    assert_eq!(w.no(&verify(&unpinned)), "CLI_TEMPLATE_UNPINNED");
    assert!(w.go(&verify(&pinned)).contains("ok: "), "control");
    // fund build refuses any leg of such terms; the control funds.
    assert_eq!(
        w.no(&w.fund_args(&unpinned, LegIndex::Cash, &w.path("u1"))),
        "CLI_TEMPLATE_UNPINNED"
    );
    w.go(&w.fund_args(&pinned, LegIndex::Cash, &w.path("p1")));
    // ipst sign of a funding refuses it too: the cash funding of the unpinned terms, built by
    // the core, signed with the unpinned artifact as the asset template.
    let t = crate::terms_file::read_terms_file(&unpinned).unwrap();
    let ctx = impulse_core::terms::CreationContext::new(w.network, START_DAA);
    let vault = Vault::instantiate_for_creation(&t, LegIndex::Cash, &ctx).unwrap();
    let pay = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let fee_in = w.sim.state.borrow().utxos_at(&pay)[0].clone();
    let ipst = fund_kas(
        &t,
        &vault,
        &FeePayment {
            inputs: vec![fee_in],
            fee: 1_000_000,
            change: pay,
        },
        START_DAA,
    )
    .unwrap();
    let p = w.path("u.ipst");
    std::fs::write(&p, ipst.to_json()).unwrap();
    let args = replace(
        &w.sign_args(&p, &w.buyer, &w.path("u.signed")),
        "--asset-template",
        s(&w.path("unpinned.json")),
    );
    assert_eq!(w.no(&args), "CLI_TEMPLATE_UNPINNED");
    // Control: the same funding of the pinned terms is signed.
    let p1s = w.path("p1s");
    w.go(&w.sign_args(&w.path("p1"), &w.buyer, &p1s));
}

// =============================================================================================
// fund build
// =============================================================================================

#[test]
fn fund_build_funds_only_your_own_leg() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    // The seller asks to fund the cash leg.
    let wrong = replace(
        &replace(
            &w.fund_args(&terms, LegIndex::Cash, &w.path("x")),
            "--role",
            "seller",
        ),
        "--my-key",
        &hex(&w.seller.signer),
    );
    let wrong = replace(&wrong, "--pay-from", &w.addr(&w.seller));
    assert_eq!(w.no(&wrong), "CLI_FUND_NOT_YOUR_LEG");
    assert!(!w.path("x").exists());
    w.go(&w.fund_args(&terms, LegIndex::Cash, &w.path("y")));
    assert!(w.path("y").exists(), "control");
    // The seller funds its own leg from the buyer's address, the buyer from the authority's:
    // ipst sign lets no key but the depositor sign a funding, so nobody could complete it.
    let from_buyer = replace(
        &w.fund_args(&terms, LegIndex::Asset, &w.path("o1")),
        "--pay-from",
        &w.addr(&w.buyer),
    );
    assert_eq!(w.no(&from_buyer), "CLI_FUND_NOT_YOUR_LEG");
    assert!(!w.path("o1").exists());
    let from_authority = replace(
        &w.fund_args(&terms, LegIndex::Cash, &w.path("o2")),
        "--pay-from",
        &w.addr(&w.authority),
    );
    assert_eq!(w.no(&from_authority), "CLI_FUND_NOT_YOUR_LEG");
    assert!(!w.path("o2").exists());
    // Control: the seller's own address, and the IPST its key alone completes.
    w.go(&w.fund_args(&terms, LegIndex::Asset, &w.path("o3")));
    let signed = w.go(&w.sign_args(&w.path("o3"), &w.seller, &w.path("o4")));
    assert_eq!(field(&signed, "pending"), "complete");
    // External cash has no cash vault.
    let ext = w.terms("e", Mode::External, |_| {});
    assert_eq!(
        w.no(&w.fund_args(&ext, LegIndex::Cash, &w.path("z"))),
        "TEMPLATE_NO_VAULT"
    );
}

#[test]
fn fund_build_checks_its_arguments() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let asset = w.fund_args(&terms, LegIndex::Asset, &w.path("a"));
    let cash = w.fund_args(&terms, LegIndex::Cash, &w.path("c"));
    // Addresses.
    let p2sh = w.vault(&terms, LegIndex::Cash);
    let p2sh = kaspa_addresses::Address::new(
        impulse_core::address::prefix(w.network),
        kaspa_addresses::Version::ScriptHash,
        &p2sh.script_hash(),
    )
    .to_string();
    let mainnet = p2pk_address(&w.buyer.signer, Network::Mainnet).to_string();
    for bad in [p2sh.as_str(), mainnet.as_str(), "kaspatest:nonsense"] {
        assert_eq!(
            w.no(&replace(&cash, "--pay-from", bad)),
            "CLI_ADDRESS_INVALID",
            "{bad}"
        );
    }
    assert_eq!(
        w.no(&with(&cash, &["--change", &mainnet])),
        "CLI_ADDRESS_INVALID"
    );
    // Outpoints.
    for bad in ["nothing", "00:0:1", &format!("{}:x:1", "ab".repeat(32))] {
        assert_eq!(
            w.no(&replace(&asset, "--token", bad)),
            "CLI_OUTPOINT_INVALID",
            "{bad}"
        );
    }
    // A token that is not at the address its state gives: the right outpoint with another amount.
    let token = w.seller_token.borrow().clone();
    let other = token.replace(":1000", ":999");
    assert_eq!(
        w.no(&replace(&asset, "--token", &other)),
        "CLI_UTXO_NOT_FOUND"
    );
    // A KCC-20 leg needs a token and its template; a KAS leg takes neither.
    assert_eq!(w.no(&without(&asset, "--token")), "CLI_UTXO_NOT_FOUND");
    assert_eq!(
        w.no(&without(&asset, "--asset-template")),
        "CLI_TEMPLATE_MISSING"
    );
    assert_eq!(
        w.no(&replace(&asset, "--asset-template", &w.tpl(LegIndex::Cash))),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(w.no(&with(&cash, &["--token", &token])), "TX_WRONG_MODE");
    assert_eq!(
        w.no(&with(&cash, &["--carrier", "300000000"])),
        "TX_WRONG_MODE"
    );
    // A buyer without UTXOs.
    let (_, empty) = w.buyer_funding("e", Mode::Authority, random_xonly(), |_| {});
    assert_eq!(w.no(&empty), "CLI_UTXO_NOT_FOUND");
    // Controls.
    let a = w.go(&asset);
    let c = w.go(&with(&cash, &["--change", &w.addr(&w.authority)]));
    assert_eq!(field(&a, "ipst"), "fund_kcc20 asset");
    assert!(field(&a, "token change").ends_with(":2:990"), "{a}");
    assert!(c.contains(&w.addr(&w.authority)), "change to --change");
}

fn random_xonly() -> [u8; 32] {
    // An x-coordinate on the curve: hash until one parses.
    loop {
        let x = random32();
        if secp256k1::XOnlyPublicKey::from_slice(&x).is_ok() {
            return x;
        }
    }
}

#[test]
fn the_fee_defaults_to_the_minimum_and_inputs_are_added_until_they_cover_it() {
    let w = World::new(Network::Testnet);
    // A buyer with three small UTXOs: none alone covers 1 KAS plus fee and change.
    let payer = random_xonly();
    let addr = p2pk_address(&payer, w.network);
    for _ in 0..3 {
        w.sim
            .state
            .borrow_mut()
            .add_utxo(address_script(&addr), 80_000_000, None);
    }
    let (_, args) = w.buyer_funding("t", Mode::Authority, payer, |_| {});
    let args = replace(&args, "--out", s(&w.path("f")));
    let out = w.go(&args);
    let fee = field(&out, "fee");
    let (paid, minimum) = fee
        .strip_suffix(" sompi)")
        .unwrap()
        .split_once(" sompi (minimum relay fee ")
        .unwrap();
    assert_eq!(paid, minimum, "the default fee is the minimum relay fee");
    assert_eq!(out.lines().filter(|l| l.starts_with("input ")).count(), 2);
    // An explicit fee is used as given; one below the minimum is the builder's refusal.
    let given = w.go(&with(
        &replace(&args, "--out", s(&w.path("g"))),
        &["--fee", "900000"],
    ));
    assert!(given.contains("fee: 900000 sompi"));
    assert_eq!(
        w.no(&with(
            &replace(&args, "--out", s(&w.path("h"))),
            &["--fee", "1"]
        )),
        "TX_FEE_TOO_LOW"
    );
    // All three together cannot cover 3 KAS.
    let (_, args) = w.buyer_funding("big", Mode::Authority, payer, |t| {
        t.cash_leg.amount = 300_000_000
    });
    assert_eq!(w.no(&args), "TX_INSUFFICIENT_FUNDS");
}

// =============================================================================================
// settle build and refund build
// =============================================================================================

#[test]
fn settle_build_needs_funded_vaults_and_the_templates() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let args = w.settle_args(&terms, &w.authority, &w.path("s"));
    assert_eq!(w.no(&args), "CLI_UTXO_NOT_FOUND", "nothing funded");
    w.fund(&terms, LegIndex::Asset);
    assert_eq!(w.no(&args), "CLI_UTXO_NOT_FOUND", "cash not funded");
    w.fund(&terms, LegIndex::Cash);
    assert_eq!(
        w.no(&without(&args, "--asset-template")),
        "CLI_TEMPLATE_MISSING"
    );
    // A KAS cash vault UTXO of another amount is not the leg.
    let cash_vault = w.vault(&terms, LegIndex::Cash);
    w.go(&args);
    let other = w.terms("o", Mode::Authority, |_| {});
    w.fund(&other, LegIndex::Asset);
    let v = w.vault(&other, LegIndex::Cash);
    w.sim
        .state
        .borrow_mut()
        .add_utxo(v.script_public_key(), KAS_CASH + 1, None);
    assert_eq!(
        w.no(&w.settle_args(&other, &w.authority, &w.path("o-s"))),
        "CLI_UTXO_NOT_FOUND"
    );
    assert!(!w
        .sim
        .state
        .borrow()
        .utxos_at(&cash_vault.script_public_key())
        .is_empty());
}

#[test]
fn refund_build_finds_or_asks_for_the_vault_utxo() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let args = w.refund_args(&terms, "cash", "authority", &w.authority, &w.path("r"));
    assert_eq!(w.no(&args), "CLI_UTXO_NOT_FOUND", "empty vault");
    w.fund(&terms, LegIndex::Cash);
    // A stray deposit: two UTXOs at the vault.
    let v = w.vault(&terms, LegIndex::Cash);
    let stray = w
        .sim
        .state
        .borrow_mut()
        .add_utxo(v.script_public_key(), 70_000_000, None);
    assert_eq!(w.no(&args), "CLI_UTXO_AMBIGUOUS");
    assert_eq!(
        w.no(&with(&args, &["--vault-utxo", "nope"])),
        "CLI_OUTPOINT_INVALID"
    );
    let missing = format!("{}:7", hex(&[9u8; 32]));
    assert_eq!(
        w.no(&with(&args, &["--vault-utxo", &missing])),
        "CLI_UTXO_NOT_FOUND"
    );
    let out = w.go(&with(&args, &["--vault-utxo", &outpoint_text(&stray)]));
    assert!(
        out.contains(&format!("input 0: {}", outpoint_text(&stray))),
        "{out}"
    );
}

#[test]
fn refund_build_without_the_token_is_the_depositors_and_says_so() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::SelfSettling, |_| {});
    w.fund(&terms, LegIndex::Asset);
    let by = |signer: &str, payer: &KeyFile, name: &str| {
        with(
            &w.refund_args(&terms, "asset", signer, payer, &w.path(name)),
            &["--without-token"],
        )
    };
    assert_eq!(w.no(&by("counterparty", &w.buyer, "c")), "TX_REFUND_SIGNER");
    let out = w.go(&by("depositor", &w.seller, "d"));
    assert_eq!(
        field(&out, "ipst"),
        "refund asset by depositor, without the token"
    );
    assert!(out.contains("note: the escrowed token stays owned by the asset vault"));
    // A KAS leg takes no token flags.
    let kas = w.terms("k", Mode::Authority, |_| {});
    w.fund(&kas, LegIndex::Cash);
    let kas_args = w.refund_args(&kas, "cash", "authority", &w.authority, &w.path("k1"));
    assert_eq!(
        w.no(&with(&kas_args, &["--without-token"])),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        w.no(&with(&kas_args, &["--token-amount", "5"])),
        "TX_WRONG_MODE"
    );
    w.go(&kas_args);
    // External cash has no cash vault to refund (D14).
    let ext = w.terms("e", Mode::External, |_| {});
    assert_eq!(
        w.no(&w.refund_args(&ext, "cash", "authority", &w.authority, &w.path("e1"))),
        "TEMPLATE_NO_VAULT"
    );
}

// =============================================================================================
// The value cap in every builder and in ipst sign
// =============================================================================================

#[test]
fn the_value_cap_applies_to_every_builder_and_to_ipst_sign() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let fund = w.fund_args(&terms, LegIndex::Cash, &w.path("f"));
    let settle = w.settle_args(&terms, &w.authority, &w.path("s"));
    let refund = w.refund_args(&terms, "cash", "authority", &w.authority, &w.path("r"));
    w.go(&settle);
    let sign = w.sign_args(&w.path("s"), &w.authority, &w.path("ss"));
    for args in [&fund, &settle, &refund, &sign] {
        let args = replace(args, "--out", s(&w.path("cap-out")));
        assert_eq!(
            w.no(&without(&args, "--kas-equivalent")),
            "CLI_VALUE_UNKNOWN"
        );
        *w.max_value.borrow_mut() = Some("99999999".into());
        assert_eq!(w.no(&args), "CLI_VALUE_CAP_EXCEEDED");
        let lifted = with(
            &without(&args, "--kas-equivalent"),
            &["--i-accept-the-risk"],
        );
        *w.max_value.borrow_mut() = None;
        let out = w.go(&lifted);
        assert!(out.contains("value cap: lifted"), "{out}");
        std::fs::remove_file(w.path("cap-out")).unwrap();
    }
}

// =============================================================================================
// ipst sign
// =============================================================================================

#[test]
fn ipst_sign_signs_only_the_slots_of_my_key() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let f = w.path("f");
    w.go(&w.fund_args(&terms, LegIndex::Cash, &f));
    // The seller has no slot in the buyer's funding, and a funding is its depositor's to sign.
    assert_eq!(
        w.no(&w.sign_args(&f, &w.seller, &w.path("x"))),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    // A key file whose key is not --my-key: the signing module refuses it.
    let wrong = replace(
        &w.sign_args(&f, &w.buyer, &w.path("y")),
        "--key-file",
        s(&w.seller.path),
    );
    assert_eq!(w.no(&wrong), "SIGN_KEY_NOT_EXPECTED");
    let out = w.go(&w.sign_args(&f, &w.buyer, &w.path("z")));
    assert_eq!(field(&out, "signed"), "input 0");
    // Signing again finds nothing left.
    assert_eq!(
        w.no(&w.sign_args(&w.path("z"), &w.buyer, &w.path("zz"))),
        "CLI_IPST_NOTHING_TO_SIGN"
    );
    // No output reveals key material.
    for k in [&w.seller, &w.buyer] {
        assert!(!out.contains(k.content.trim_end()));
    }
}

#[test]
fn ipst_sign_checks_the_payers_change_and_fee() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let base = w.fund_args(&terms, LegIndex::Cash, &w.path("f"));
    // The change goes to the authority's address: the buyer signing its fee input is refused.
    w.go(&with(
        &replace(&base, "--out", s(&w.path("c"))),
        &["--change", &w.addr(&w.authority)],
    ));
    assert_eq!(
        w.no(&w.sign_args(&w.path("c"), &w.buyer, &w.path("c1"))),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
    let ok = with(
        &w.sign_args(&w.path("c"), &w.buyer, &w.path("c2")),
        &["--change", &w.addr(&w.authority)],
    );
    w.go(&ok);
    // A fee above twice the minimum is refused unless --max-fee accepts it.
    w.go(&with(
        &replace(&base, "--out", s(&w.path("h"))),
        &["--fee", "50000000"],
    ));
    assert_eq!(
        w.no(&w.sign_args(&w.path("h"), &w.buyer, &w.path("h1"))),
        "CLI_IPST_FEE_TOO_HIGH"
    );
    assert_eq!(
        w.no(&with(
            &w.sign_args(&w.path("h"), &w.buyer, &w.path("h1")),
            &["--max-fee", "49999999"]
        )),
        "CLI_IPST_FEE_TOO_HIGH"
    );
    w.go(&with(
        &w.sign_args(&w.path("h"), &w.buyer, &w.path("h2")),
        &["--max-fee", "50000000"],
    ));
    // The authority signs vault inputs of a settle it does not pay for: no payer check.
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let s1 = w.path("s");
    w.go(&with(
        &w.settle_args(&terms, &w.seller, &s1),
        &["--change", &w.addr(&w.buyer)],
    ));
    let out = w.go(&w.sign_args(&s1, &w.authority, &w.path("s1")));
    assert_eq!(field(&out, "signed"), "input 0, input 1");
    // The seller paying the fee is refused: its change goes to the buyer.
    assert_eq!(
        w.no(&w.sign_args(&w.path("s1"), &w.seller, &w.path("s2"))),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
}

#[test]
fn the_default_fee_limit_covers_at_most_three_of_the_signers_fee_inputs() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let pay = address_script(&p2pk_address(&w.buyer.signer, w.network));
    // Anyone can send the buyer small UTXOs; the buyer's largest pays a funding alone.
    for _ in 0..4 {
        w.sim
            .state
            .borrow_mut()
            .add_utxo(pay.clone(), 100_000_000, None);
    }
    let mut held = w.sim.state.borrow().utxos_at(&pay);
    held.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
    // The buyer's KAS funding with `inputs` as fee inputs and a fee of twice the document's own
    // minimum relay fee, built by impulse-core directly, as anyone can.
    let funding = |inputs: Vec<impulse_core::tx::Utxo>, name: &str| -> (PathBuf, u64) {
        let t = crate::terms_file::read_terms_file(&terms).unwrap();
        let ctx = impulse_core::terms::CreationContext::new(w.network, START_DAA);
        let vault = Vault::instantiate_for_creation(&t, LegIndex::Cash, &ctx).unwrap();
        let mut fee = 1_000_000;
        let ipst = loop {
            let ipst = fund_kas(
                &t,
                &vault,
                &FeePayment {
                    inputs: inputs.clone(),
                    fee,
                    change: pay.clone(),
                },
                START_DAA,
            )
            .unwrap();
            let twice = 2 * min_relay_fee(ipst.masses().fee_mass);
            if twice == fee {
                break ipst;
            }
            fee = twice;
        };
        let p = w.path(name);
        std::fs::write(&p, ipst.to_json()).unwrap();
        (p, fee)
    };
    let padded = |n: usize, name: &str| funding(held[..n].to_vec(), name);
    let sign = |p: &Path, out: &str| w.sign_args(p, &w.buyer, &w.path(out));
    let (one, honest) = padded(1, "one");
    let (three, _) = padded(3, "three");
    let (four, inflated) = padded(4, "four");
    // Padding raises a limit taken from the document: four inputs' default is above one's.
    assert!(inflated > honest, "{inflated} {honest}");
    // Refused at four fee inputs without --max-fee, whatever the fee.
    assert_eq!(w.no(&sign(&four, "four1")), "CLI_IPST_FEE_TOO_HIGH");
    // Controls: one and three fee inputs at the default limit, four with --max-fee.
    w.go(&sign(&one, "one1"));
    w.go(&sign(&three, "three1"));
    let out = w.go(&with(
        &sign(&four, "four2"),
        &["--max-fee", &inflated.to_string()],
    ));
    assert_eq!(field(&out, "signed"), "input 0, input 1, input 2, input 3");
    // Only the signer's own fee inputs count: one of the buyer's beside four of the
    // authority's is signed at the default limit.
    let theirs = address_script(&p2pk_address(&w.authority.signer, w.network));
    for _ in 0..2 {
        w.sim
            .state
            .borrow_mut()
            .add_utxo(theirs.clone(), 100_000_000, None);
    }
    let mut mixed = vec![held[0].clone()];
    mixed.extend(w.sim.state.borrow().utxos_at(&theirs));
    assert_eq!(mixed.len(), 5);
    let (mixed, _) = funding(mixed, "mixed");
    let out = w.go(&sign(&mixed, "mixed1"));
    assert_eq!(field(&out, "signed"), "input 0");
}

/// The IPST at `path` with input `i`'s compute budget raised: no sighash covers it, so the
/// document still reads, and only the terms check sees the change.
fn raise_budget(path: &Path, to: &Path, i: usize) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let b = v["inputs"][i]["compute_budget"].as_u64().unwrap();
    v["inputs"][i]["compute_budget"] = serde_json::json!(b + 1);
    let ipst = Ipst::from_json(&v.to_string()).expect("still reads");
    std::fs::write(to, ipst.to_json()).unwrap();
}

#[test]
fn every_ipst_the_cli_is_given_passes_the_terms_check() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Direct, |_| {});
    let unsigned = w.path("d");
    w.go(&w.settle_args(&terms, &w.buyer, &unsigned));
    let tampered = w.path("dt");
    raise_budget(&unsigned, &tampered, 0);
    // sign
    assert_eq!(
        w.no(&w.sign_args(&tampered, &w.seller, &w.path("x"))),
        "IPST_TERMS_MISMATCH"
    );
    let (a, b) = (w.path("a"), w.path("b"));
    w.go(&w.sign_args(&unsigned, &w.seller, &a));
    w.go(&w.sign_args(&unsigned, &w.buyer, &b));
    // merge: a signed copy with a raised budget, signatures still valid.
    let at = w.path("at");
    raise_budget(&a, &at, 1);
    let merge = |x: &Path, y: &Path, out: &str| -> Vec<String> {
        [
            "ipst",
            "merge",
            "--ipst",
            s(x),
            s(y),
            "--node",
            NODE,
            "--asset-template",
            &w.tpl(LegIndex::Asset),
            "--out",
            s(&w.path(out)),
        ]
        .map(String::from)
        .to_vec()
    };
    assert_eq!(w.no(&merge(&at, &at, "m0")), "IPST_TERMS_MISMATCH");
    assert_eq!(w.no(&merge(&a, &at, "m1")), "IPST_CONFLICT");
    w.go(&merge(&a, &b, "m"));
    // submit: the complete document with a raised budget.
    let mt = w.path("mt");
    raise_budget(&w.path("m"), &mt, 2);
    let height = w.height();
    assert_eq!(w.no(&w.submit_args(&mt)), "IPST_TERMS_MISMATCH");
    assert_eq!(w.height(), height);
    // An incomplete document is refused at finalization.
    assert_eq!(w.no(&w.submit_args(&a)), "TX_SIGNATURE_SLOT");
    w.go(&w.submit_args(&w.path("m")));
    assert_eq!(w.height(), height + 1);
}

#[test]
fn a_slot_signed_twice_does_not_merge_and_either_copy_does() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Direct, |_| {});
    let unsigned = w.path("d");
    w.go(&w.settle_args(&terms, &w.buyer, &unsigned));
    let (a, a2, b) = (w.path("a"), w.path("a2"), w.path("b"));
    w.go(&w.sign_args(&unsigned, &w.seller, &a));
    w.go(&w.sign_args(&unsigned, &w.seller, &a2));
    w.go(&w.sign_args(&unsigned, &w.buyer, &b));
    // BIP-340 auxiliary randomness: the seller's two signatures of one slot differ.
    assert_ne!(
        std::fs::read_to_string(&a).unwrap(),
        std::fs::read_to_string(&a2).unwrap()
    );
    let merge = |x: &Path, y: &Path, out: &str| -> Vec<String> {
        [
            "ipst",
            "merge",
            "--ipst",
            s(x),
            s(y),
            "--node",
            NODE,
            "--asset-template",
            &w.tpl(LegIndex::Asset),
            "--out",
            s(&w.path(out)),
        ]
        .map(String::from)
        .to_vec()
    };
    // spec/CLI.md, "ipst merge": the two copies do not combine; either one merges.
    assert_eq!(w.no(&merge(&a, &a2, "m0")), "IPST_CONFLICT");
    for (x, out) in [(&a, "m1"), (&a2, "m2")] {
        assert_eq!(field(&w.go(&merge(x, &b, out)), "pending"), "complete");
    }
}

#[test]
fn a_settle_past_expiry_is_not_signed_or_submitted() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let s1 = w.path("s");
    w.go(&w.settle_args(&terms, &w.authority, &s1));
    let signed = w.path("ss");
    w.go(&w.sign_args(&s1, &w.authority, &signed));
    w.set_daa(START_DAA + EXPIRY_IN);
    assert_eq!(
        w.no(&w.sign_args(&s1, &w.authority, &w.path("x"))),
        "TX_EXPIRED"
    );
    assert_eq!(w.no(&w.submit_args(&signed)), "TX_EXPIRED");
    assert_eq!(
        w.no(&w.settle_args(&terms, &w.authority, &w.path("y"))),
        "TX_EXPIRED"
    );
    w.set_daa(START_DAA + EXPIRY_IN - 1);
    w.go(&w.submit_args(&signed));
}

#[test]
fn ipst_commands_act_on_their_terms_network_only() {
    let w = World::new(Network::Mainnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let f = w.path("f");
    w.go(&w.fund_args(&terms, LegIndex::Cash, &f));
    // The same commands without --network mainnet: refused before anything is read further.
    let args = w.sign_args(&f, &w.buyer, &w.path("x"));
    w.explicit.set(false);
    assert_eq!(w.no(&args), "CLI_NETWORK_MISMATCH");
    assert_eq!(w.no(&w.submit_args(&f)), "CLI_NETWORK_MISMATCH");
    // A builder checks the node first: a mainnet node for a testnet command.
    assert_eq!(
        w.no(&w.fund_args(&terms, LegIndex::Cash, &w.path("y"))),
        "CLI_NODE_NETWORK_MISMATCH"
    );
    w.explicit.set(true);
    // On mainnet a typed DAA score is refused; the node supplies it.
    let typed = replace(&without(&args, "--node"), "--daa", "1000000");
    assert_eq!(w.no(&typed), "CLI_MAINNET_NEEDS_NODE");
    // Control: signed on mainnet with --network mainnet.
    w.go(&args);
}

// =============================================================================================
// decode, tip, key show, token info
// =============================================================================================

#[test]
fn decode_reports_a_refund_with_its_signer_and_refuses_an_unknown_txid() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let from = hex(&w.sim.state.borrow().sink());
    w.fund(&terms, LegIndex::Asset);
    let r = w.path("r");
    w.go(&w.refund_args(&terms, "asset", "counterparty", &w.buyer, &r));
    let txid = w.sign_submit(&r, &w.buyer);
    let out = w.run(&["decode", &txid, "--node", NODE, "--from-block", &from]);
    assert!(
        out.contains(&format!(
            "refund signed by {} (the buyer)",
            hex(&w.buyer.signer)
        )),
        "{out}"
    );
    let unknown = hex(&[7u8; 32]);
    assert_eq!(
        w.refuse(&["decode", &unknown, "--node", NODE, "--from-block", &from]),
        "CLI_TX_NOT_ACCEPTED"
    );
    // A funding spends no vault.
    let sink = hex(&w.sim.state.borrow().sink());
    let fund = w.fund(&terms, LegIndex::Cash);
    assert_eq!(
        w.refuse(&["decode", &fund, "--node", NODE, "--from-block", &sink]),
        "DECODE_NO_VAULT_INPUT"
    );
    assert_eq!(
        w.refuse(&["decode", "xyz", "--node", NODE, "--from-block", &from]),
        "CLI_HEX"
    );
}

#[test]
fn tip_key_show_and_token_info() {
    let w = World::new(Network::Testnet);
    let out = w.run(&["tip", "--node", NODE]);
    assert_eq!(field(&out, "virtual_daa_score"), START_DAA.to_string());
    assert_eq!(field(&out, "sink"), hex(&w.sim.state.borrow().sink()));
    let out = w.run(&["key", "show", "--key-file", s(&w.seller.path)]);
    assert_eq!(field(&out, "public_key"), hex(&w.seller.signer));
    assert_eq!(field(&out, "address"), w.addr(&w.seller));
    assert!(
        !out.contains(w.seller.content.trim_end()),
        "no key material"
    );
    // key show reads the key through the signing module, with its refusals.
    let missing = w.path("missing.key");
    assert_eq!(
        w.refuse(&["key", "show", "--key-file", s(&missing)]),
        "SIGN_KEY_FILE_UNREADABLE"
    );
    let out = w.run(&["token", "info", "--template", &w.tpl(LegIndex::Asset)]);
    assert!(field(&out, "pinned").starts_with("yes"), "{out}");
    assert_eq!(field(&out, "template_hash"), hex(&w.asset.template_hash()));
    std::fs::write(w.path("u.json"), unpinned_artifact()).unwrap();
    let out = w.run(&["token", "info", "--template", s(&w.path("u.json"))]);
    assert!(field(&out, "pinned").starts_with("no"), "{out}");
    std::fs::write(w.path("bad.json"), "{}").unwrap();
    assert_eq!(
        w.refuse(&["token", "info", "--template", s(&w.path("bad.json"))]),
        "TX_TOKEN_TEMPLATE"
    );
}

// =============================================================================================
// The fake node runs the engine and the node rules
// =============================================================================================

#[test]
fn the_fake_node_runs_every_input_in_the_engine() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let f = w.path("f");
    w.go(&w.fund_args(&terms, LegIndex::Cash, &f));
    let fs = w.path("fs");
    w.go(&w.sign_args(&f, &w.buyer, &fs));
    let ipst = Ipst::from_json(&std::fs::read_to_string(&fs).unwrap()).unwrap();
    let tx = ipst.finalize().unwrap();
    // A signature byte flipped after finalization: the engine refuses the input.
    let mut bad = tx.clone();
    bad.inputs[0].signature_script[5] ^= 1;
    let e = w.sim.submit(&bad).unwrap_err();
    assert!(
        e.to_string().contains("refused by the script engine"),
        "{e}"
    );
    // A lock time the virtual DAA score has not passed.
    let mut late = tx.clone();
    late.lock_time = START_DAA;
    late.finalize();
    assert!(w
        .sim
        .submit(&late)
        .unwrap_err()
        .to_string()
        .contains("not final"));
    // Outputs above the inputs, and one outpoint spent twice.
    let mut more = tx.clone();
    more.outputs[0].value += ipst.fee() + 1;
    more.finalize();
    assert!(w
        .sim
        .submit(&more)
        .unwrap_err()
        .to_string()
        .contains("the outputs pay more than the inputs hold"));
    let mut twice = tx.clone();
    twice.inputs.push(twice.inputs[0].clone());
    twice.finalize();
    assert!(w
        .sim
        .submit(&twice)
        .unwrap_err()
        .to_string()
        .contains("spends an outpoint twice"));
    w.sim.submit(&tx).unwrap();
    // Spent once only.
    assert!(w
        .sim
        .submit(&tx)
        .unwrap_err()
        .to_string()
        .contains("not in the UTXO set"));
}

// =============================================================================================
// Review round 1 (phase 2): what ipst sign checks before it signs
// =============================================================================================

fn held_state(key: [u8; 32], amount: u64) -> Kcc20State {
    Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: key,
        },
        amount,
    )
}

fn vault_owner(vault: &Vault) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

impl World {
    /// Adds a token UTXO of `leg`'s token held by `key`, carrying `kas`; returns it as
    /// `<txid>:<index>:<amount>`.
    fn add_token(&self, leg: LegIndex, key: [u8; 32], amount: u64, kas: u64) -> String {
        let (template, covenant) = match leg {
            LegIndex::Asset => (&self.asset, self.asset_cov),
            LegIndex::Cash => (&self.cash, self.cash_cov),
        };
        let o = self.sim.state.borrow_mut().add_utxo(
            template
                .script_public_key(&held_state(key, amount))
                .unwrap(),
            kas,
            Some(covenant),
        );
        format!("{}:{amount}", outpoint_text(&o))
    }

    fn terms_hash(&self, terms: &Path) -> String {
        hex(&crate::terms_file::read_terms_file(terms)
            .unwrap()
            .terms_hash())
    }

    /// The buyer's KAS funding of `terms`, built by impulse-core directly (no CLI checks) at
    /// creation DAA score `daa`, and written to `name`.
    fn kas_funding(&self, terms: &Path, daa: u64, name: &str) -> PathBuf {
        let t = crate::terms_file::read_terms_file(terms).unwrap();
        let ctx = impulse_core::terms::CreationContext::new(self.network, daa);
        let vault = Vault::instantiate_for_creation(&t, LegIndex::Cash, &ctx).unwrap();
        let pay = address_script(&p2pk_address(&self.buyer.signer, self.network));
        let fee_in = self.sim.state.borrow().utxos_at(&pay)[0].clone();
        let ipst = fund_kas(
            &t,
            &vault,
            &FeePayment {
                inputs: vec![fee_in],
                fee: 300_000,
                change: pay,
            },
            daa,
        )
        .unwrap();
        let p = self.path(name);
        std::fs::write(&p, ipst.to_json()).unwrap();
        p
    }
}

#[test]
fn ipst_sign_signs_only_for_the_trade_the_signer_agreed_to() {
    let w = World::new(Network::Testnet);
    let agreed = w.terms("agreed", Mode::Authority, |_| {});
    // The review's case: terms another party drafted, with its own authority and a worthless
    // asset covenant; the buyer's funding built on them pays the buyer's KAS to their vault.
    let other = w.terms("other", Mode::Authority, |t| {
        t.authority_key = Some(random_xonly());
        if let LegKind::Kcc20(token) = &mut t.asset_leg.kind {
            token.covenant_id = random32();
        }
    });
    let f = w.path("f");
    w.go(&w.fund_args(&other, LegIndex::Cash, &f));
    let sign = w.sign_args(&f, &w.buyer, &w.path("f1"));
    let by_file = |terms: &Path| with(&without(&sign, "--terms-hash"), &["--terms", s(terms)]);
    assert_eq!(w.no(&by_file(&agreed)), "CLI_IPST_TERMS_NOT_AGREED");
    assert_eq!(
        w.no(&replace(&sign, "--terms-hash", &w.terms_hash(&agreed))),
        "CLI_IPST_TERMS_NOT_AGREED"
    );
    assert_eq!(w.no(&replace(&sign, "--terms-hash", "xyz")), "CLI_HEX");
    w.go(&by_file(&other));
    // Settle and refund of the agreed trade, signed against other terms, and their controls.
    w.fund(&agreed, LegIndex::Asset);
    w.fund(&agreed, LegIndex::Cash);
    let settle = w.path("s");
    w.go(&w.settle_args(&agreed, &w.authority, &settle));
    let refund = w.path("r");
    w.go(&w.refund_args(&agreed, "cash", "authority", &w.authority, &refund));
    for (ipst, name) in [(&settle, "s"), (&refund, "r")] {
        let a = w.sign_args(ipst, &w.authority, &w.path(&format!("{name}1")));
        assert_eq!(
            w.no(&replace(&a, "--terms-hash", &w.terms_hash(&other))),
            "CLI_IPST_TERMS_NOT_AGREED",
            "{name}"
        );
        w.go(&with(
            &without(&a, "--terms-hash"),
            &["--terms", s(&agreed)],
        ));
    }
    // Direct: the buyer drafts the transaction; the seller signs only for its own terms.
    let d = w.terms("d", Mode::Direct, |_| {});
    let d2 = w.terms("d2", Mode::Direct, |_| {});
    let direct = w.path("direct");
    w.go(&w.settle_args(&d, &w.buyer, &direct));
    let a = w.sign_args(&direct, &w.seller, &w.path("d1"));
    assert_eq!(
        w.no(&replace(&a, "--terms-hash", &w.terms_hash(&d2))),
        "CLI_IPST_TERMS_NOT_AGREED"
    );
    w.go(&replace(&a, "--terms-hash", &w.terms_hash(&d)));
}

#[test]
fn ipst_sign_checks_the_signers_role_and_own_destinations() {
    let w = World::new(Network::Testnet);
    // The seller's refund pays a third key: terms new and fund build refuse such terms, and so
    // does ipst sign of a funding built elsewhere, unless the seller pinned that destination.
    let x = random_xonly();
    let third = w.terms("third", Mode::Authority, |t| {
        t.seller_refund = Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: x,
        })
    });
    assert_eq!(
        w.no(&w.fund_args(&third, LegIndex::Asset, &w.path("t0"))),
        "CLI_DESTINATION_NOT_MINE"
    );
    let p = w.path("t.ipst");
    std::fs::write(&p, asset_funding(&w, &third).to_json()).unwrap();
    let sign = w.sign_args(&p, &w.seller, &w.path("t1"));
    assert_eq!(w.no(&sign), "CLI_DESTINATION_NOT_MINE");
    let pinned = with(
        &sign,
        &["--my-refund", &format!("kcc20:pubkey:{}", hex(&x))],
    );
    // The role and its key.
    assert_eq!(
        w.no(&replace(&sign, "--role", "buyer")),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        w.no(&replace(&sign, "--role", "payer")),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        w.no(&replace(&sign, "--role", "authority")),
        "CLI_ROLE_KEY_MISMATCH"
    );
    let as_authority = replace(
        &replace(&sign, "--role", "authority"),
        "--key-file",
        s(&w.authority.path),
    );
    let as_authority = replace(&as_authority, "--my-key", &hex(&w.authority.signer));
    assert_eq!(
        w.no(&with(
            &as_authority,
            &["--my-refund", &w.addr(&w.authority)]
        )),
        "CLI_DESTINATION_PIN_INVALID"
    );
    // The authority has no slot in a funding, and a funding is its depositor's to sign.
    assert_eq!(w.no(&as_authority), "CLI_FUND_NOT_YOUR_LEG");
    w.go(&pinned);
    // A funding whose fee inputs another key pays: that key is not the depositor. fund build
    // does not make one (CLI_FUND_NOT_YOUR_LEG); anyone can build one with impulse-core.
    let terms = w.terms("t", Mode::Authority, |_| {});
    let f = w.path("f");
    let token = w.seller_token.borrow().clone();
    let buyer_pays = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let ipst = asset_funding_by(&w, &terms, &token, &w.buyer, buyer_pays);
    std::fs::write(&f, ipst.to_json()).unwrap();
    assert_eq!(
        w.no(&w.sign_args(&f, &w.buyer, &w.path("f1"))),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    w.go(&w.sign_args(&f, &w.seller, &w.path("f2")));
    // The creation checks at the current DAA score: an expiry beyond the horizon now, built
    // by the core at a later creation score.
    let horizon = impulse_core::terms::DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    let far = w.terms("far", Mode::Authority, |t| {
        t.expiry_daa = START_DAA + horizon + 1
    });
    let edge = w.terms("edge", Mode::Authority, |t| {
        t.expiry_daa = START_DAA + horizon
    });
    let p = w.kas_funding(&far, START_DAA + 10, "far.ipst");
    assert_eq!(
        w.no(&w.sign_args(&p, &w.buyer, &w.path("far1"))),
        "TERMS_EXPIRY_BEYOND_HORIZON"
    );
    let p = w.kas_funding(&edge, START_DAA, "edge.ipst");
    w.go(&w.sign_args(&p, &w.buyer, &w.path("edge1")));
    // A payer with no role in the terms settles a self-settling trade; a party's key cannot
    // sign as a payer, nor a payer's key as a party.
    let payer = key_file();
    w.sim.state.borrow_mut().add_utxo(
        address_script(&p2pk_address(&payer.signer, w.network)),
        10_000_000_000,
        None,
    );
    let ss = w.terms("ss", Mode::SelfSettling, |_| {});
    w.fund(&ss, LegIndex::Asset);
    w.fund(&ss, LegIndex::Cash);
    let st = w.path("st");
    w.go(&w.settle_args(&ss, &payer, &st));
    let by_payer = w.sign_args(&st, &payer, &w.path("st1"));
    assert_eq!(
        field(&w.go(&by_payer), "you"),
        format!(
            "payer, a key with no role in the terms, {}",
            hex(&payer.signer)
        )
    );
    assert_eq!(
        w.no(&replace(&by_payer, "--role", "buyer")),
        "CLI_ROLE_KEY_MISMATCH"
    );
    let buyer_as_payer = replace(
        &replace(
            &w.sign_args(&st, &w.buyer, &w.path("st2")),
            "--role",
            "payer",
        ),
        "--my-key",
        &hex(&w.buyer.signer),
    );
    assert_eq!(w.no(&buyer_as_payer), "CLI_ROLE_KEY_MISMATCH");
}

#[test]
fn ipst_sign_bounds_what_the_signer_commits() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let asset = w.fund_args(&terms, LegIndex::Asset, &w.path("a"));
    // Control: the default deposit.
    w.go(&asset);
    let out = w.go(&w.sign_args(&w.path("a"), &w.seller, &w.path("a1")));
    assert!(
        field(&out, "you commit").contains(" sompi of your KAS"),
        "{out}"
    );
    // A carrier of 5000 KAS: refused unless confirmed, and then by the cap unless lifted.
    w.go(&with(
        &replace(&asset, "--out", s(&w.path("c"))),
        &["--carrier", "500000000000"],
    ));
    let sc = w.sign_args(&w.path("c"), &w.seller, &w.path("c1"));
    assert_eq!(w.no(&sc), "CLI_IPST_DEPOSIT_MISMATCH");
    assert_eq!(
        w.no(&with(&sc, &["--carrier", "500000000000"])),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    w.go(&with(
        &without(&sc, "--kas-equivalent"),
        &["--carrier", "500000000000", "--i-accept-the-risk"],
    ));
    // An authorizer one sompi above the default.
    w.go(&with(
        &replace(&asset, "--out", s(&w.path("u"))),
        &["--authorizer", "50000001"],
    ));
    let su = w.sign_args(&w.path("u"), &w.seller, &w.path("u1"));
    assert_eq!(w.no(&su), "CLI_IPST_DEPOSIT_MISMATCH");
    assert_eq!(
        w.no(&with(&su, &["--authorizer", "50000000"])),
        "CLI_IPST_DEPOSIT_MISMATCH"
    );
    w.go(&with(&su, &["--authorizer", "50000001"]));
    // The seller signs only its token input, which carries 50 KAS; the buyer's key pays the
    // fee and the change goes to a third address: the seller's surplus KAS would go there.
    // fund build does not make such a funding; anyone can build one with impulse-core.
    let rich = w.add_token(LegIndex::Asset, w.seller.signer, 1_000, 5_000_000_000);
    let elsewhere = address_script(&p2pk_address(&w.authority.signer, w.network));
    let ipst = asset_funding_by(&w, &terms, &rich, &w.buyer, elsewhere);
    std::fs::write(w.path("h"), ipst.to_json()).unwrap();
    assert_eq!(
        w.no(&w.sign_args(&w.path("h"), &w.seller, &w.path("h1"))),
        "CLI_IPST_OUTFLOW_TOO_HIGH"
    );
    let home = address_script(&p2pk_address(&w.seller.signer, w.network));
    let ipst = asset_funding_by(&w, &terms, &rich, &w.buyer, home);
    std::fs::write(w.path("k"), ipst.to_json()).unwrap();
    w.go(&w.sign_args(&w.path("k"), &w.seller, &w.path("k1")));
    // Direct: the seller's token carries 5 KAS, all of which goes to the buyer with the asset.
    let d = w.terms("d", Mode::Direct, |t| t.asset_leg.amount = 11);
    w.add_token(LegIndex::Asset, w.seller.signer, 11, 500_000_000);
    w.go(&w.settle_args(&d, &w.buyer, &w.path("d0")));
    let sd = w.sign_args(&w.path("d0"), &w.seller, &w.path("d1"));
    assert_eq!(w.no(&sd), "CLI_IPST_OUTFLOW_TOO_HIGH");
    assert_eq!(
        w.no(&with(&sd, &["--carrier", "499999999"])),
        "CLI_IPST_OUTFLOW_TOO_HIGH"
    );
    w.go(&with(&sd, &["--carrier", "500000000"]));
    w.go(&w.sign_args(&w.path("d0"), &w.buyer, &w.path("d2")));
    // --authorizer is for a KCC-20 funding only.
    assert_eq!(
        w.no(&with(
            &w.sign_args(&w.path("d0"), &w.buyer, &w.path("d3")),
            &["--authorizer", "50000000"]
        )),
        "TX_WRONG_MODE"
    );
}

#[test]
fn carrier_is_refused_outside_a_kcc20_funding_or_a_direct_transaction() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let carrier = ["--carrier", "200000000"];
    // A KAS funding.
    w.go(&w.fund_args(&terms, LegIndex::Cash, &w.path("k")));
    let kas = w.sign_args(&w.path("k"), &w.buyer, &w.path("k1"));
    assert_eq!(w.no(&with(&kas, &carrier)), "TX_WRONG_MODE");
    w.go(&kas);
    // A settle and a refund.
    let funded = w.terms("f", Mode::Authority, |_| {});
    w.fund(&funded, LegIndex::Asset);
    w.fund(&funded, LegIndex::Cash);
    w.go(&w.settle_args(&funded, &w.authority, &w.path("s")));
    let settle = w.sign_args(&w.path("s"), &w.authority, &w.path("s1"));
    assert_eq!(w.no(&with(&settle, &carrier)), "TX_WRONG_MODE");
    w.go(&settle);
    w.go(&w.refund_args(&funded, "asset", "authority", &w.authority, &w.path("r")));
    let refund = w.sign_args(&w.path("r"), &w.authority, &w.path("r1"));
    assert_eq!(w.no(&with(&refund, &carrier)), "TX_WRONG_MODE");
    w.go(&refund);
    // Controls: a KCC-20 funding and a Direct transaction take it.
    w.go(&w.fund_args(&terms, LegIndex::Asset, &w.path("a")));
    w.go(&with(
        &w.sign_args(&w.path("a"), &w.seller, &w.path("a1")),
        &carrier,
    ));
    let d = w.terms("d", Mode::Direct, |_| {});
    w.go(&w.settle_args(&d, &w.buyer, &w.path("dx")));
    w.go(&with(
        &w.sign_args(&w.path("dx"), &w.seller, &w.path("dx1")),
        &carrier,
    ));
}

#[test]
fn the_top_up_of_a_settle_is_shown_and_bounded() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    let av = w.vault(&terms, LegIndex::Asset);
    let cv = w.vault(&terms, LegIndex::Cash);
    {
        // Vaults funded by hand: the escrowed asset carries 1000 sompi, under its minimum.
        let mut st = w.sim.state.borrow_mut();
        st.add_utxo(av.script_public_key(), MIN_KAS_OUTPUT, None);
        st.add_utxo(
            w.asset
                .script_public_key(&Kcc20State::new(vault_owner(&av), ASSET_AMOUNT))
                .unwrap(),
            1_000,
            Some(w.asset_cov),
        );
        st.add_utxo(cv.script_public_key(), KAS_CASH, None);
    }
    let topup = MIN_KCC20_OUTPUT - 1_000;
    let line = format!("{topup} sompi into trade outputs");
    let out = w.go(&w.settle_args(&terms, &w.authority, &w.path("s")));
    assert_eq!(field(&out, "payer cost beyond the fee"), line);
    let sign = w.sign_args(&w.path("s"), &w.authority, &w.path("s1"));
    assert_eq!(w.no(&sign), "CLI_IPST_TOPUP_TOO_HIGH");
    assert_eq!(
        w.no(&with(&sign, &["--max-topup", &(topup - 1).to_string()])),
        "CLI_IPST_TOPUP_TOO_HIGH"
    );
    let signed = w.go(&with(&sign, &["--max-topup", &topup.to_string()]));
    assert_eq!(field(&signed, "payer cost beyond the fee"), line);
    let out = w.go(&w.refund_args(&terms, "asset", "authority", &w.authority, &w.path("r")));
    assert_eq!(field(&out, "payer cost beyond the fee"), line);
    // Control: a trade funded by the builders tops up nothing.
    let ok = w.terms("ok", Mode::Authority, |_| {});
    w.fund(&ok, LegIndex::Asset);
    w.fund(&ok, LegIndex::Cash);
    let out = w.go(&w.settle_args(&ok, &w.authority, &w.path("o")));
    assert_eq!(
        field(&out, "payer cost beyond the fee"),
        "0 sompi into trade outputs"
    );
    w.go(&w.sign_args(&w.path("o"), &w.authority, &w.path("o1")));
}

#[test]
fn the_payers_checks_hold_for_every_layout() {
    let w = World::new(Network::Testnet);
    let elsewhere = p2pk_address(&random_xonly(), w.network).to_string();
    // Each layout built with its change going elsewhere: the payer is refused, and accepts
    // once it names that address as its change.
    let check = |name: &str, build: Vec<String>, payer: &KeyFile| {
        let p = w.path(name);
        let out = w.go(&with(
            &replace(&build, "--out", s(&p)),
            &["--change", &elsewhere],
        ));
        assert!(field(&out, "change").contains(&elsewhere), "{name}: {out}");
        assert_eq!(
            w.no(&w.sign_args(&p, payer, &w.path(&format!("{name}-x")))),
            "CLI_IPST_CHANGE_NOT_MINE",
            "{name}"
        );
        w.go(&with(
            &w.sign_args(&p, payer, &w.path(&format!("{name}-y"))),
            &["--change", &elsewhere],
        ));
    };
    let a = w.terms("a", Mode::Authority, |_| {});
    check(
        "fund_kcc20",
        w.fund_args(&a, LegIndex::Asset, &w.path("x")),
        &w.seller,
    );
    let ss = w.terms("ss", Mode::SelfSettling, |_| {});
    w.fund(&ss, LegIndex::Asset);
    w.fund(&ss, LegIndex::Cash);
    check(
        "settle_kcc20",
        w.settle_args(&ss, &w.buyer, &w.path("x")),
        &w.buyer,
    );
    let ext = w.terms("ext", Mode::External, |_| {});
    w.fund(&ext, LegIndex::Asset);
    check(
        "settle_external",
        w.settle_args(&ext, &w.authority, &w.path("x")),
        &w.authority,
    );
    check(
        "refund",
        w.refund_args(&ext, "asset", "authority", &w.authority, &w.path("x")),
        &w.authority,
    );
    let d = w.terms("d", Mode::Direct, |_| {});
    check(
        "direct",
        w.settle_args(&d, &w.buyer, &w.path("x")),
        &w.buyer,
    );
    let d20 = w.terms("d20", Mode::DirectKcc20, |_| {});
    check(
        "direct_kcc20",
        w.settle_args(&d20, &w.buyer, &w.path("x")),
        &w.buyer,
    );
    // The default fee limit is twice the minimum relay fee: accepted at it, refused one above.
    let t = w.terms("fee", Mode::Authority, |_| {});
    let base = w.fund_args(&t, LegIndex::Cash, &w.path("fee0"));
    let minimum = |out: &str| -> u64 {
        let f = field(out, "fee");
        f.split("minimum relay fee ").nth(1).unwrap()[..]
            .trim_end_matches(" sompi)")
            .parse()
            .unwrap()
    };
    let m = minimum(&w.go(&base));
    for (fee, accepted) in [(2 * m, true), (2 * m + 1, false)] {
        let p = w.path(&format!("fee-{fee}"));
        let built = w.go(&with(
            &replace(&base, "--out", s(&p)),
            &["--fee", &fee.to_string()],
        ));
        assert_eq!(minimum(&built), m, "the minimum does not move with the fee");
        let sign = w.sign_args(&p, &w.buyer, &w.path(&format!("fee-{fee}-s")));
        if accepted {
            w.go(&sign);
        } else {
            assert_eq!(w.no(&sign), "CLI_IPST_FEE_TOO_HIGH");
        }
    }
}

// =============================================================================================
// Review round 1 (phase 2): the spec's recovery and funding options are used as given
// =============================================================================================

#[test]
fn recovery_and_funding_options_are_used_as_given() {
    let w = World::new(Network::Testnet);
    // A refund by the depositor of an escrow of another amount, and of a minter.
    let terms = w.terms("t", Mode::SelfSettling, |_| {});
    w.fund(&terms, LegIndex::Asset);
    let av = w.vault(&terms, LegIndex::Asset);
    let other = w.sim.state.borrow_mut().add_utxo(
        w.asset
            .script_public_key(&Kcc20State::new(vault_owner(&av), 15))
            .unwrap(),
        MIN_KCC20_OUTPUT,
        Some(w.asset_cov),
    );
    let minter_state = Kcc20State {
        owner: vault_owner(&av),
        amount: 20,
        is_minter: true,
    };
    let minter = w.sim.state.borrow_mut().add_utxo(
        w.asset.script_public_key(&minter_state).unwrap(),
        MIN_KCC20_OUTPUT,
        Some(w.asset_cov),
    );
    let base = w.refund_args(&terms, "asset", "depositor", &w.seller, &w.path("r0"));
    let at = |name: &str, extra: &[&str]| with(&replace(&base, "--out", s(&w.path(name))), extra);
    let out = w.go(&at("r1", &["--token-amount", "15"]));
    assert!(
        out.contains(&format!("input 1: {}", outpoint_text(&other))),
        "{out}"
    );
    assert_eq!(
        w.no(&at("r2", &["--token-amount", "14"])),
        "CLI_UTXO_NOT_FOUND"
    );
    let out = w.go(&at("r3", &["--token-amount", "20", "--token-minter"]));
    assert!(
        out.contains(&format!("input 1: {}", outpoint_text(&minter))),
        "{out}"
    );
    assert_eq!(
        w.no(&at("r4", &["--token-amount", "20"])),
        "CLI_UTXO_NOT_FOUND"
    );
    let cp = w.refund_args(&terms, "asset", "counterparty", &w.buyer, &w.path("r5"));
    assert_eq!(w.no(&with(&cp, &["--token-amount", "15"])), "TX_LEG_AMOUNT");
    let out = w.go(&base);
    assert!(
        !out.contains(&outpoint_text(&other)),
        "the leg amount by default"
    );
    // A KAS leg takes no token or authorizer flags.
    let kas = w.terms("k", Mode::Authority, |_| {});
    w.fund(&kas, LegIndex::Cash);
    let kr = w.refund_args(&kas, "cash", "authority", &w.authority, &w.path("k1"));
    assert_eq!(w.no(&with(&kr, &["--token-minter"])), "TX_WRONG_MODE");
    let kf = w.fund_args(&kas, LegIndex::Cash, &w.path("k2"));
    assert_eq!(
        w.no(&with(&kf, &["--authorizer", "60000000"])),
        "TX_WRONG_MODE"
    );
    w.go(&kr);
    // A funding with a carrier and an authorizer above the minimum, and with two tokens.
    let f = w.terms("f", Mode::Authority, |_| {});
    let out = w.go(&with(
        &w.fund_args(&f, LegIndex::Asset, &w.path("f1")),
        &["--carrier", "300000000", "--authorizer", "60000000"],
    ));
    assert!(
        out.lines()
            .any(|l| l.starts_with("output 0: 300000000 sompi")),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with("output 1: 60000000 sompi")),
        "{out}"
    );
    let held: u64 = w
        .seller_token
        .borrow()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let second = w.add_token(LegIndex::Asset, w.seller.signer, 5, MIN_KCC20_OUTPUT);
    let out = w.go(&with(
        &w.fund_args(&f, LegIndex::Asset, &w.path("f2")),
        &["--token", &second],
    ));
    assert_eq!(
        out.lines()
            .filter(|l| l.starts_with("input ") && l.contains(", covenant "))
            .count(),
        2,
        "{out}"
    );
    assert!(
        field(&out, "token change").ends_with(&format!(":2:{}", held + 5 - ASSET_AMOUNT)),
        "{out}"
    );
    // The asset authorizer is the vault UTXO with the most KAS.
    let s2 = w.terms("s2", Mode::Authority, |_| {});
    w.fund(&s2, LegIndex::Asset);
    w.fund(&s2, LegIndex::Cash);
    let v2 = w.vault(&s2, LegIndex::Asset);
    let big = w
        .sim
        .state
        .borrow_mut()
        .add_utxo(v2.script_public_key(), 70_000_000, None);
    w.sim
        .state
        .borrow_mut()
        .add_utxo(v2.script_public_key(), 60_000_000, None);
    let out = w.go(&w.settle_args(&s2, &w.authority, &w.path("s2s")));
    assert!(
        out.contains(&format!("input 0: {}, 70000000 sompi", outpoint_text(&big))),
        "{out}"
    );
}

// =============================================================================================
// Review round 1 (phase 2): refusals at the command, and what the builders take from a node
// =============================================================================================

#[test]
fn phase_2_writers_refuse_an_existing_output_and_a_malformed_key() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |_| {});
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let s0 = w.path("s0");
    w.go(&w.settle_args(&terms, &w.authority, &s0));
    let taken = w.path("taken");
    std::fs::write(&taken, "keep").unwrap();
    let merge: Vec<String> = [
        "ipst",
        "merge",
        "--ipst",
        s(&s0),
        s(&s0),
        "--node",
        NODE,
        "--asset-template",
        &w.tpl(LegIndex::Asset),
        "--out",
        s(&taken),
    ]
    .map(String::from)
    .to_vec();
    let writers = [
        w.fund_args(&terms, LegIndex::Cash, &taken),
        w.settle_args(&terms, &w.authority, &taken),
        w.refund_args(&terms, "cash", "authority", &w.authority, &taken),
        w.sign_args(&s0, &w.authority, &taken),
        merge,
    ];
    for (i, args) in writers.iter().enumerate() {
        assert_eq!(w.no(args), "CLI_OUTPUT_EXISTS", "writer {i}");
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "keep");
        let fresh = w.path(&format!("fresh{i}"));
        w.go(&replace(args, "--out", s(&fresh)));
        assert!(fresh.exists());
    }
    // --my-key that is not 64 lowercase hex digits.
    for args in [
        w.fund_args(&terms, LegIndex::Cash, &w.path("h1")),
        w.sign_args(&s0, &w.authority, &w.path("h2")),
    ] {
        assert_eq!(w.no(&replace(&args, "--my-key", "XYZ")), "CLI_HEX");
    }
}

#[test]
fn phase_2_node_commands_refuse_an_insecure_or_unsynced_node() {
    let m = World::new(Network::Mainnet);
    let terms = m.terms("t", Mode::Authority, |_| {});
    let from = hex(&m.sim.state.borrow().sink());
    let f = m.path("f");
    m.go(&m.fund_args(&terms, LegIndex::Cash, &f));
    let signed = m.path("fs");
    let sign = m.sign_args(&f, &m.buyer, &signed);
    let commands = |txid: &str| -> Vec<Vec<String>> {
        vec![
            m.fund_args(&terms, LegIndex::Cash, &m.path("f2")),
            replace(&sign, "--out", s(&m.path("fs2"))),
            m.submit_args(&signed),
            ["decode", txid, "--node", NODE, "--from-block", &from]
                .map(String::from)
                .to_vec(),
        ]
    };
    let remote = "ws://203.0.113.9:17110";
    let height = m.height();
    for args in commands(&"ab".repeat(32)) {
        assert_eq!(
            m.no(&replace(&args, "--node", remote)),
            "CLI_NODE_INSECURE",
            "{args:?}"
        );
    }
    assert_eq!(m.height(), height, "nothing submitted");
    // Controls over the loopback link, then an unsynced node refused by each.
    m.go(&sign);
    let txid = field(&m.go(&m.submit_args(&signed)), "submitted");
    let controls = commands(&txid);
    m.go(&controls[0]);
    m.go(&controls[1]);
    assert_eq!(
        m.no(&controls[3]),
        "DECODE_NO_VAULT_INPUT",
        "past the node checks"
    );
    m.sim.state.borrow_mut().synced = false;
    for (i, args) in controls.iter().enumerate() {
        let args = replace(args, "--out", s(&m.path(&format!("u{i}"))));
        let args = if i >= 2 { controls[i].clone() } else { args };
        assert_eq!(m.no(&args), "CLI_NODE_NOT_SYNCED", "{args:?}");
    }
}

#[test]
fn builders_use_only_the_utxos_the_spec_names() {
    let w = World::new(Network::Testnet);
    // Several exact KAS cash UTXOs at the vault: the lowest outpoint.
    let t = w.terms("t", Mode::Authority, |_| {});
    w.fund(&t, LegIndex::Asset);
    let cv = w.vault(&t, LegIndex::Cash);
    let a = w
        .sim
        .state
        .borrow_mut()
        .add_utxo(cv.script_public_key(), KAS_CASH, None);
    let b = w
        .sim
        .state
        .borrow_mut()
        .add_utxo(cv.script_public_key(), KAS_CASH, None);
    let low = [a, b]
        .into_iter()
        .min_by_key(|o| (o.transaction_id.as_bytes(), o.index))
        .unwrap();
    let out = w.go(&w.settle_args(&t, &w.authority, &w.path("s")));
    assert!(
        out.contains(&format!("input 1: {}", outpoint_text(&low))),
        "{out}"
    );
    // The buyer's Direct cash is its largest UTXO and the buyer pays the fee: the cash UTXO is
    // a trade input only, never a fee input.
    let big = w.terms("big", Mode::Direct, |t| t.cash_leg.amount = 500_000_000_000);
    let cash = w.sim.state.borrow_mut().add_utxo(
        address_script(&p2pk_address(&w.buyer.signer, w.network)),
        500_000_000_000,
        None,
    );
    let out = w.go(&with(
        &without(
            &w.settle_args(&big, &w.buyer, &w.path("b")),
            "--kas-equivalent",
        ),
        &["--i-accept-the-risk"],
    ));
    assert_eq!(
        out.lines()
            .filter(|l| l.contains(&outpoint_text(&cash)))
            .count(),
        1,
        "{out}"
    );
    assert!(out.contains(&format!("input 1: {}", outpoint_text(&cash))));
    // A first fee input whose change would be below the minimum: one more input is taken.
    let payer = random_xonly();
    let addr = p2pk_address(&payer, w.network);
    for amount in [KAS_CASH + 20_000_000, 60_000_000] {
        w.sim
            .state
            .borrow_mut()
            .add_utxo(address_script(&addr), amount, None);
    }
    let (_, kp) = w.buyer_funding("kp", Mode::Authority, payer, |_| {});
    let out = w.go(&kp);
    assert_eq!(out.lines().filter(|l| l.starts_with("input ")).count(), 2);
    let k = w.terms("k", Mode::Authority, |_| {});
    // --pay-from: an ECDSA address is refused; outpoint indexes beyond u32 are refused.
    let ecdsa = kaspa_addresses::Address::new(
        impulse_core::address::prefix(w.network),
        kaspa_addresses::Version::PubKeyECDSA,
        &[[2u8].as_slice(), &random_xonly()].concat(),
    )
    .to_string();
    let fk = w.fund_args(&k, LegIndex::Cash, &w.path("k2"));
    assert_eq!(
        w.no(&replace(&fk, "--pay-from", &ecdsa)),
        "CLI_ADDRESS_INVALID"
    );
    let fa = w.fund_args(&k, LegIndex::Asset, &w.path("k3"));
    let wide = format!("{}:4294967296:1000", "ab".repeat(32));
    assert_eq!(
        w.no(&replace(&fa, "--token", &wide)),
        "CLI_OUTPOINT_INVALID"
    );
    // A node that reports the token without its covenant, or under another script version: the
    // UTXO is not the one looked for.
    let lies: [fn(&mut impulse_core::tx::Utxo); 2] = [
        |u| u.entry.covenant_id = None,
        |u| {
            u.entry.script_public_key =
                ScriptPublicKey::from_vec(1, u.entry.script_public_key.script().to_vec())
        },
    ];
    for lie in lies {
        *w.lie.borrow_mut() = Some(Lie::Utxo(lie));
        assert_eq!(w.no(&fa), "CLI_UTXO_NOT_FOUND");
    }
    *w.lie.borrow_mut() = None;
    w.go(&fa);
    // Terms of another network, for the existing-trade builders.
    let main = w.terms("main", Mode::Authority, |t| t.network = Network::Mainnet);
    assert_eq!(
        w.no(&w.settle_args(&main, &w.authority, &w.path("m1"))),
        "CLI_NETWORK_MISMATCH"
    );
    assert_eq!(
        w.no(&w.refund_args(&main, "cash", "authority", &w.authority, &w.path("m2"))),
        "CLI_NETWORK_MISMATCH"
    );
    // An unpinned KCC-20 cash leg is flagged like an unpinned asset leg.
    let art = unpinned_artifact();
    let unpinned_tpl = Kcc20Template::from_json(&art).unwrap();
    let token = w.token(&unpinned_tpl, w.cash_cov);
    let uc = w.terms("uc", Mode::SelfSettling, |t| {
        t.cash_leg.kind = LegKind::Kcc20(token)
    });
    assert_eq!(
        w.no(&w.fund_args(&uc, LegIndex::Asset, &w.path("uc1"))),
        "CLI_TEMPLATE_UNPINNED"
    );
}

#[test]
fn decode_and_the_transaction_lines_state_their_facts() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::Authority, |t| t.expiry_daa = START_DAA + 1_000);
    let t = crate::terms_file::read_terms_file(&terms)
        .unwrap()
        .into_terms();
    let from = hex(&w.sim.state.borrow().sink());
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let s0 = w.path("s0");
    w.go(&w.settle_args(&terms, &w.authority, &s0));
    let daa = w.sim.state.borrow().virtual_daa;
    let txid = w.sign_submit(&s0, &w.authority);
    let decode = ["decode", &txid, "--node", NODE, "--from-block", &from];
    let out = w.run(&decode);
    assert!(
        out.contains(&format!("at DAA score {}", daa + 1)),
        "the accepting block's DAA score: {out}"
    );
    for (amount, to) in [
        (ASSET_AMOUNT, &t.buyer_delivery),
        (KAS_CASH, &t.seller_proceeds),
    ] {
        assert!(
            out.contains(&format!(
                "delivers exactly {amount} to {}",
                crate::summary::describe(&t, to)
            )),
            "{out}"
        );
    }
    assert!(!out.contains("refused:"), "{out}");
    // A node that misreports the UTXO input 1 spent: that vault input is refused, by code,
    // and the other still decodes.
    *w.lie.borrow_mut() = Some(Lie::Spent(|spent| {
        if let Some(e) = spent.get_mut(1) {
            e.script_public_key = ScriptPublicKey::from_vec(0, vec![0x51])
        }
    }));
    let lied = w.run(&decode);
    *w.lie.borrow_mut() = None;
    assert!(
        lied.lines()
            .any(|l| l.starts_with("refused: DECODE_INPUT_NOT_VAULT")),
        "{lied}"
    );
    assert_eq!(lied.lines().filter(|l| l.starts_with("leg: ")).count(), 1);
    // Refunds: who signed, where the leg goes, the lock time hint and the change line.
    let r = w.terms("r", Mode::Authority, |t| {
        t.expiry_daa = START_DAA + 1_000_000
    });
    let rt = crate::terms_file::read_terms_file(&r).unwrap().into_terms();
    w.fund(&r, LegIndex::Asset);
    w.fund(&r, LegIndex::Cash);
    let from = hex(&w.sim.state.borrow().sink());
    let ra = w.path("ra");
    w.go(&w.refund_args(&r, "asset", "authority", &w.authority, &ra));
    let a = w.sign_submit(&ra, &w.authority);
    let rc = w.path("rc");
    let built = w.go(&w.refund_args(&r, "cash", "counterparty", &w.seller, &rc));
    // The change is the output after the refunded KAS: output 1, to the payer.
    assert_eq!(field(&built, "change"), field(&built, "output 1"));
    assert!(
        field(&built, "change").contains(&w.addr(&w.seller)),
        "{built}"
    );
    let c = w.sign_submit(&rc, &w.seller);
    for (txid, who, to) in [
        (&a, "the authority", &rt.seller_refund),
        (&c, "the seller", &rt.buyer_refund),
    ] {
        let out = w.run(&["decode", txid, "--node", NODE, "--from-block", &from]);
        assert!(out.contains(&format!("({who})")), "{out}");
        assert!(
            out.contains(&format!("goes to {}", crate::summary::describe(&rt, to))),
            "{out}"
        );
    }
    let lt = w.terms("lt", Mode::Authority, |t| t.expiry_daa = START_DAA + 5_000);
    w.fund(&lt, LegIndex::Cash);
    let out = w.go(&w.refund_args(&lt, "cash", "depositor", &w.buyer, &w.path("lt1")));
    assert_eq!(
        field(&out, "lock_time"),
        format!(
            "{} (a block can include it from DAA score {})",
            START_DAA + 5_000,
            START_DAA + 5_001
        )
    );
    // pending: names each signer once, in input order.
    let d = w.terms("d", Mode::Direct, |_| {});
    let out = w.go(&w.settle_args(&d, &w.buyer, &w.path("d1")));
    assert_eq!(
        field(&out, "pending"),
        format!("{}, {}", hex(&w.seller.signer), hex(&w.buyer.signer))
    );
    let f = w.terms("f", Mode::Authority, |_| {});
    let out = w.go(&w.fund_args(&f, LegIndex::Asset, &w.path("f1")));
    assert!(out.lines().filter(|l| l.contains(" pending")).count() >= 2);
    assert_eq!(field(&out, "pending"), hex(&w.seller.signer));
}

// =============================================================================================
// Integration follow-up (2026-10-11): the signed-transaction file and the Direct cancellation
// =============================================================================================

/// The watcher's own start-up path (`impulse-watch run`, everything before the node is
/// contacted) on `trades` and the signed-transaction files `kept`: the binary refuses exactly
/// when this does.
fn watcher_prepare(
    w: &World,
    trades: &[&Path],
    kept: &[&Path],
) -> Result<impulse_watch::run::Prepared, impulse_watch::WatchError> {
    let state = w.path(&format!("watch-{:016x}.json", rand::random::<u64>()));
    impulse_watch::run::prepare(&impulse_watch::cli::RunArgs {
        network: match w.network {
            Network::Mainnet => impulse_watch::cli::NetworkArg::Mainnet,
            Network::Testnet => impulse_watch::cli::NetworkArg::Testnet,
        },
        node: "ws://127.0.0.1:1".into(),
        finality_depth: 1,
        state,
        init: true,
        trades: trades.iter().map(|p| p.to_path_buf()).collect(),
        keep_signed: kept.iter().map(|p| p.to_path_buf()).collect(),
        retire: vec![],
        retention_daa: None,
        poll_interval_ms: 1000,
        max_polls: Some(1),
        max_failed_polls: None,
        log_format: impulse_watch::cli::LogFormat::Text,
        linked: vec![],
    })
}

fn txid_of(hex64: &str) -> kaspa_consensus_core::tx::TransactionId {
    kaspa_consensus_core::Hash::from_bytes(crate::json::unhex32(hex64).unwrap())
}

/// spec/CLI.md, "submit", "Signed-transaction file": the raw form of spec/VERIFY.md in hex, one
/// line feed, written only once the node took the transaction; the watcher keeps the settle it
/// names and refuses a funding.
#[test]
fn submit_writes_the_signed_transaction_the_watcher_keeps() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t.json", Mode::Authority, |_| {});
    w.fund(&terms, LegIndex::Asset);
    // The cash funding, submitted with its own file: the watcher refuses to keep a funding.
    let fund = w.path("fund-cash.ipst");
    w.go(&w.fund_args(&terms, LegIndex::Cash, &fund));
    let fund_signed = w.path("fund-cash.signed");
    w.go(&w.sign_args(&fund, &w.buyer, &fund_signed));
    let fund_tx = w.path("fund-cash.tx");
    let out = w.go(&with(
        &w.submit_args(&fund_signed),
        &["--signed-tx-out", s(&fund_tx)],
    ));
    assert_eq!(field(&out, "signed_tx"), s(&fund_tx));

    let unsigned = w.path("settle.ipst");
    w.go(&w.settle_args(&terms, &w.authority, &unsigned));
    let signed = w.path("settle.signed");
    w.go(&w.sign_args(&unsigned, &w.authority, &signed));
    let file = w.path("settle.tx");
    let submit = with(&w.submit_args(&signed), &["--signed-tx-out", s(&file)]);

    // Refused: a taken path, before anything is read or submitted; the file is left as it was.
    std::fs::write(&file, "taken").unwrap();
    let before = w.height();
    assert_eq!(w.no(&submit), "CLI_OUTPUT_EXISTS");
    assert_eq!(w.height(), before, "nothing submitted");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "taken");
    std::fs::remove_file(&file).unwrap();
    // Refused before the node sees anything (review round 1 of the integration follow-up): a
    // dangling symbolic link (never followed: its target is not created), a missing directory
    // and a read-only one.
    let target = w.path("link-target.tx");
    std::os::unix::fs::symlink(&target, &file).unwrap();
    assert_eq!(w.no(&submit), "CLI_OUTPUT_EXISTS");
    assert!(!target.exists());
    std::fs::remove_file(&file).unwrap();
    let missing = w.path("no-such-dir").join("x.tx");
    assert_eq!(
        w.no(&with(
            &w.submit_args(&signed),
            &["--signed-tx-out", s(&missing)]
        )),
        "CLI_FILE_WRITE"
    );
    assert_eq!(w.height(), before, "nothing submitted");
    let locked = w.path("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o555)).unwrap();
    // Root ignores the mode; the case applies only where the mode holds.
    if std::fs::write(locked.join("probe"), "").is_err() {
        assert_eq!(
            w.no(&with(
                &w.submit_args(&signed),
                &["--signed-tx-out", s(&locked.join("x.tx"))]
            )),
            "CLI_FILE_WRITE"
        );
        assert_eq!(w.height(), before, "nothing submitted");
    }
    // A refusal after the file is created removes it: an IPST still waiting for a signature,
    // and a write that fails (a test hook standing in for a full disk).
    assert_eq!(
        w.no(&with(
            &w.submit_args(&unsigned),
            &["--signed-tx-out", s(&file)]
        )),
        "TX_SIGNATURE_SLOT"
    );
    assert!(!file.exists(), "the refused submit's file is removed");
    crate::ipst_cmd::FAIL_SIGNED_TX_WRITE.with(|f| f.set(true));
    assert_eq!(w.no(&submit), "CLI_FILE_WRITE");
    assert!(!crate::ipst_cmd::FAIL_SIGNED_TX_WRITE.with(|f| f.get()));
    assert!(!file.exists(), "a failed write leaves no file");
    assert_eq!(w.height(), before, "nothing submitted");

    // Accepted control: submitted, then written, and the line names the file last.
    let out = w.go(&submit);
    assert_eq!(w.height(), before + 1);
    let txid = field(&out, "submitted");
    assert_eq!(
        out.lines().last().unwrap(),
        format!("signed_tx: {}", s(&file))
    );
    let tx = Ipst::from_json(&std::fs::read_to_string(&signed).unwrap())
        .unwrap()
        .finalize()
        .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        text,
        format!("{}\n", hex(&impulse_core::decode::encode_raw(&tx)))
    );
    assert_eq!(hex(&tx.id().as_bytes()), txid);
    // The raw form decodes as spec/VERIFY.md reads it: one transaction, the settle's ID.
    let bytes = (0..text.len() - 1)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    let decoded = impulse_core::decode::decode_raw_unbound(&bytes, Network::Testnet).unwrap();
    assert_eq!(hex(&decoded.txid), txid);

    // The watcher, on the binary's start-up path: the settle file is kept.
    let prepared = watcher_prepare(&w, &[&terms], &[&file]).expect("the watcher keeps the file");
    assert!(prepared.watcher.is_kept(&txid_of(&txid)));
    drop(prepared);
    // Refused by the watcher beside it: the funding's file (not a settle or refund), and the
    // settle's file with one hex digit changed.
    let e = watcher_prepare(&w, &[&terms], &[&fund_tx]).err().unwrap();
    assert_eq!(e.code(), "WATCH_TX_NOT_TRACKED");
    let tampered = w.path("tampered.tx");
    let mut t = text.clone().into_bytes();
    t[20] = if t[20] == b'0' { b'1' } else { b'0' };
    std::fs::write(&tampered, t).unwrap();
    let e = watcher_prepare(&w, &[&terms], &[&tampered]).err().unwrap();
    assert_eq!(e.code(), "WATCH_SIGNED_TX_INVALID");

    // A refused submission writes no file: the same settle again (its inputs are spent). The
    // refusal says how to write the file should the node have taken it after all.
    let again = w.path("again.tx");
    let before = w.height();
    let (r, printed) = w.exec(
        &with(&w.submit_args(&signed), &["--signed-tx-out", s(&again)])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let e = r.unwrap_err();
    assert_eq!((e.code(), printed.as_str()), ("CLI_NODE_RPC", ""));
    assert!(
        e.to_string().contains(&format!(
            "impulse status shows {txid} accepted: then write the file with impulse ipst raw"
        )),
        "{e}"
    );
    assert_eq!(w.height(), before);
    assert!(!again.exists(), "a refused submission leaves no file");

    // ipst raw writes the same file offline from the signed IPST, beside its refusals: a taken
    // path, an IPST still waiting for a signature, and the other network.
    let raw = |ipst: &Path, out: &Path| {
        vec![
            "ipst".to_string(),
            "raw".into(),
            "--ipst".into(),
            s(ipst).into(),
            "--out".into(),
            s(out).into(),
        ]
    };
    let rewritten = w.path("rewritten.tx");
    let out = w.go(&raw(&signed, &rewritten));
    assert_eq!(out, format!("txid: {txid}\nwrote: {}\n", s(&rewritten)));
    assert_eq!(std::fs::read_to_string(&rewritten).unwrap(), text);
    assert_eq!(w.no(&raw(&signed, &rewritten)), "CLI_OUTPUT_EXISTS");
    assert_eq!(std::fs::read_to_string(&rewritten).unwrap(), text);
    let o = w.path("raw-refused.tx");
    assert_eq!(w.no(&raw(&unsigned, &o)), "TX_SIGNATURE_SLOT");
    w.explicit.set(true);
    assert_eq!(w.no(&raw(&signed, &o)), "CLI_NETWORK_MISMATCH");
    w.explicit.set(false);
    assert!(!o.exists());
}

/// `direct cancel build` arguments for `k` as `role`.
fn cancel_args(terms: &Path, role: &str, k: &KeyFile, out: &Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "direct",
        "cancel",
        "build",
        "--terms",
        s(terms),
        "--node",
        NODE,
        "--role",
        role,
        "--my-key",
        &hex(&k.signer),
        "--out",
        s(out),
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    a.extend(DECLARE.iter().map(|x| x.to_string()));
    a
}

/// The outpoint an `input <i>:` line names.
fn input_outpoint(out: &str, i: usize) -> String {
    field(out, &format!("input {i}"))
        .split(',')
        .next()
        .unwrap()
        .to_string()
}

fn merge_args(w: &World, a: &Path, b: &Path, out: &Path) -> Vec<String> {
    [
        "ipst",
        "merge",
        "--ipst",
        s(a),
        s(b),
        "--node",
        NODE,
        "--asset-template",
        &w.tpl(LegIndex::Asset),
        "--cash-template",
        &w.tpl(LegIndex::Cash),
        "--out",
        s(out),
    ]
    .iter()
    .map(|x| x.to_string())
    .collect()
}

/// spec/CLI.md, "direct cancel build (the Direct refund)": the buyer's Direct cash goes home whole
/// under a lock time at the expiry, and the abandoned Direct transaction, signed by both parties,
/// no longer validates.
#[test]
fn the_direct_refund_sends_the_buyers_cash_home_after_the_expiry() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("d.json", Mode::Direct, |_| {});
    let expiry = START_DAA + EXPIRY_IN;
    let buyer_addr = w.addr(&w.buyer);
    // The abandoned Direct transaction: built, signed by both parties and merged, never sent.
    let direct = w.path("direct.ipst");
    let out = w.go(&w.settle_args(&terms, &w.seller, &direct));
    let direct_input = input_outpoint(&out, 1);
    let (by_seller, by_buyer, merged) = (w.path("d.s"), w.path("d.b"), w.path("d.m"));
    w.go(&w.sign_args(&direct, &w.seller, &by_seller));
    w.go(&w.sign_args(&direct, &w.buyer, &by_buyer));
    w.go(&merge_args(&w, &by_seller, &by_buyer, &merged));
    let abandoned = Ipst::from_json(&std::fs::read_to_string(&merged).unwrap())
        .unwrap()
        .finalize()
        .unwrap();
    // Control: until the cancellation, the node would take it.
    assert!(w.sim.state.borrow().clone().submit(&abandoned).is_ok());

    // Built before the expiry: lock time at the expiry, the Direct input settle build takes,
    // home whole to its own address, the fee from another input of the buyer.
    let cancel = w.path("cancel.ipst");
    let out = w.go(&cancel_args(&terms, "buyer", &w.buyer, &cancel));
    assert_eq!(field(&out, "ipst"), "direct cancel by buyer");
    assert_eq!(
        field(&out, "lock_time"),
        format!(
            "{expiry} (a block can include it from DAA score {})",
            expiry + 1
        )
    );
    assert_eq!(input_outpoint(&out, 0), direct_input);
    assert!(field(&out, "input 0").contains(&format!("{KAS_CASH} sompi at {buyer_addr}")));
    assert!(field(&out, "input 1").contains(&format!("at {buyer_addr}")));
    assert!(field(&out, "output 0").starts_with(&format!("{KAS_CASH} sompi to {buyer_addr} ")));
    assert!(field(&out, "change").contains(&format!(" sompi to {buyer_addr} ")));
    assert_eq!(
        field(&out, "payer cost beyond the fee"),
        "0 sompi into trade outputs"
    );
    assert_eq!(field(&out, "pending"), hex(&w.buyer.signer));
    let txid = field(&out, "txid");
    let fee = field(&out, "fee").split(' ').next().unwrap().to_string();
    // Naming the input gives the same transaction.
    let named = w.path("named.ipst");
    let out = w.go(&with(
        &cancel_args(&terms, "buyer", &w.buyer, &named),
        &["--direct-input", &direct_input],
    ));
    assert_eq!(field(&out, "txid"), txid);
    // So does naming the Direct transaction, and the line says which one it cancels.
    let out = w.go(&with(
        &cancel_args(&terms, "buyer", &w.buyer, &w.path("for.ipst")),
        &["--for-ipst", s(&merged)],
    ));
    assert_eq!(field(&out, "txid"), txid);
    assert_eq!(
        field(&out, "cancels"),
        format!(
            "Direct transaction {}, its input 1 {direct_input}",
            hex(&abandoned.id().as_bytes())
        )
    );

    // Signed by the buyer, who commits only the fee.
    let signed = w.path("cancel.signed");
    let out = w.go(&w.sign_args(&cancel, &w.buyer, &signed));
    assert_eq!(field(&out, "pending"), "complete");
    assert!(
        field(&out, "you commit").starts_with(&format!("{fee} sompi of your KAS")),
        "{out}"
    );
    // Refused by submit at the expiry, nothing sent; accepted one DAA score later.
    let before = w.height();
    w.set_daa(expiry);
    assert_eq!(w.no(&w.submit_args(&signed)), "CLI_TX_NOT_FINAL");
    assert_eq!(w.height(), before);
    w.set_daa(expiry + 1);
    let out = w.go(&w.submit_args(&signed));
    assert_eq!(field(&out, "submitted"), txid);
    let from = field(&out, "from_block");

    // The abandoned Direct transaction now spends an input that no longer exists.
    let e = w.sim.state.borrow().clone().submit(&abandoned).unwrap_err();
    assert!(
        e.contains("input 1: the outpoint is not in the UTXO set"),
        "{e}"
    );
    // Its input is gone, so there is nothing left to cancel for it.
    assert_eq!(
        w.no(&with(
            &cancel_args(&terms, "buyer", &w.buyer, &w.path("again.ipst")),
            &["--for-ipst", s(&merged)],
        )),
        "CLI_UTXO_NOT_FOUND"
    );
    // decode reads no vault input in it, as in a Direct transaction.
    assert_eq!(
        w.refuse(&["decode", &txid, "--node", NODE, "--from-block", &from]),
        "DECODE_NO_VAULT_INPUT"
    );
}

/// spec/CLI.md, "direct cancel build", checks 1 to 7: each refusal beside the accepted control,
/// with nothing printed and nothing written.
#[test]
fn direct_cancel_build_refuses_what_it_cannot_cancel() {
    let w = World::new(Network::Testnet);
    let direct = w.terms("d.json", Mode::Direct, |_| {});
    let o = w.path("refused.ipst");
    let args = |terms: &Path, role: &str, k: &KeyFile| cancel_args(terms, role, k, &o);
    let refused = |a: &[String]| {
        let code = w.no(a);
        assert!(!o.exists(), "{code}: wrote {}", o.display());
        code
    };
    // Check 1: Direct terms only.
    let vault = w.terms("v.json", Mode::Authority, |_| {});
    assert_eq!(
        refused(&args(&vault, "buyer", &w.buyer)),
        "CLI_CANCEL_NOT_DIRECT"
    );
    w.explicit.set(true);
    assert_eq!(
        refused(&args(&direct, "buyer", &w.buyer)),
        "CLI_NETWORK_MISMATCH"
    );
    w.explicit.set(false);
    // Check 2: the role's key.
    assert_eq!(
        refused(&args(&direct, "buyer", &w.seller)),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        refused(&replace(
            &args(&direct, "buyer", &w.buyer),
            "--my-key",
            "XYZ"
        )),
        "CLI_HEX"
    );
    // Check 3: only native KAS goes home this way.
    assert_eq!(
        refused(&args(&direct, "seller", &w.seller)),
        "CLI_CANCEL_INPUT_NOT_KAS"
    );
    let kcc20 = w.terms("k.json", Mode::DirectKcc20, |_| {});
    assert_eq!(
        refused(&args(&kcc20, "buyer", &w.buyer)),
        "CLI_CANCEL_INPUT_NOT_KAS"
    );
    // Check 4: the value cap.
    *w.max_value.borrow_mut() = Some("50000000".into());
    assert_eq!(
        refused(&args(&direct, "buyer", &w.buyer)),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    *w.max_value.borrow_mut() = None;
    // Checks 5 and 6: the Direct input. A named UTXO of the buyer that is not the cash amount,
    // a malformed outpoint, and terms for an amount the buyer holds no UTXO of.
    let other = w
        .sim
        .utxos(&p2pk_address(&w.buyer.signer, w.network))
        .unwrap()
        .into_iter()
        .find(|u| u.entry.amount != KAS_CASH && u.entry.covenant_id.is_none())
        .unwrap();
    assert_eq!(
        refused(&with(
            &args(&direct, "buyer", &w.buyer),
            &["--direct-input", &outpoint_text(&other.outpoint)]
        )),
        "CLI_UTXO_NOT_FOUND"
    );
    assert_eq!(
        refused(&with(
            &args(&direct, "buyer", &w.buyer),
            &["--direct-input", "nothex:0"]
        )),
        "CLI_OUTPOINT_INVALID"
    );
    let odd = w.terms("odd.json", Mode::Direct, |t| {
        t.cash_leg.amount = 3 * KAS_CASH / 2
    });
    assert_eq!(
        refused(&args(&odd, "buyer", &w.buyer)),
        "CLI_UTXO_NOT_FOUND"
    );
    // Check 7: a buyer whose only UTXO is the Direct input has nothing to pay the fee with;
    // then too little to pay it; then change below the minimum. The builders' rules: a fee below
    // the minimum relay fee.
    let lone = random_xonly();
    let lone_terms = w.terms("lone.json", Mode::Direct, |t| t.buyer_key = lone);
    let lone_spk = address_script(&p2pk_address(&lone, w.network));
    w.sim
        .state
        .borrow_mut()
        .add_utxo(lone_spk.clone(), KAS_CASH, None);
    let lone_args = replace(
        &args(&lone_terms, "buyer", &w.buyer),
        "--my-key",
        &hex(&lone),
    );
    assert_eq!(refused(&lone_args), "CLI_UTXO_NOT_FOUND");
    w.sim
        .state
        .borrow_mut()
        .add_utxo(lone_spk.clone(), 1_000, None);
    assert_eq!(refused(&lone_args), "TX_INSUFFICIENT_FUNDS");
    w.sim
        .state
        .borrow_mut()
        .add_utxo(lone_spk.clone(), 30_000_000, None);
    assert_eq!(refused(&lone_args), "TX_BELOW_MIN_KAS");
    assert_eq!(
        refused(&with(&args(&direct, "buyer", &w.buyer), &["--fee", "1"])),
        "TX_FEE_TOO_LOW"
    );
    assert_eq!(
        refused(&with(
            &args(&direct, "buyer", &w.buyer),
            &["--change", "kaspatest:nothing"]
        )),
        "CLI_ADDRESS_INVALID"
    );
    // A taken --out is kept.
    std::fs::write(&o, "taken").unwrap();
    assert_eq!(w.no(&args(&direct, "buyer", &w.buyer)), "CLI_OUTPUT_EXISTS");
    assert_eq!(std::fs::read_to_string(&o).unwrap(), "taken");
    // Controls: the buyer's cancellation of its Direct KAS cash, the lone buyer's once it has a
    // second UTXO, and the cap lifted.
    w.go(&cancel_args(
        &direct,
        "buyer",
        &w.buyer,
        &w.path("ok1.ipst"),
    ));
    w.sim
        .state
        .borrow_mut()
        .add_utxo(lone_spk.clone(), 5 * KAS_CASH, None);
    w.go(&replace(
        &cancel_args(&lone_terms, "buyer", &w.buyer, &w.path("ok2.ipst")),
        "--my-key",
        &hex(&lone),
    ));
    *w.max_value.borrow_mut() = Some("50000000".into());
    w.go(&with(
        &without(
            &cancel_args(&direct, "buyer", &w.buyer, &w.path("ok3.ipst")),
            "--kas-equivalent",
        ),
        &["--i-accept-the-risk"],
    ));
}

/// spec/CLI.md, "The cancellation check": a cancellation document that is not what `direct
/// cancel build` makes from its own parts is refused by `ipst sign`, `ipst merge` and `submit`,
/// beside the built document, which they accept.
#[test]
fn a_cancellation_is_held_to_what_direct_cancel_build_makes() {
    use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, UtxoEntry};
    let w = World::new(Network::Testnet);
    let terms = w.terms("d.json", Mode::Direct, |_| {});
    let built = w.path("cancel.ipst");
    w.go(&cancel_args(&terms, "buyer", &w.buyer, &built));
    let good = Ipst::from_json(&std::fs::read_to_string(&built).unwrap()).unwrap();
    let buyer = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let seller = address_script(&p2pk_address(&w.seller.signer, w.network));
    // A document from edited parts, rendered as direct cancel build renders one, so its
    // sighashes are consistent and only the cancellation check can refuse it.
    let doc = |name: &str, edit: &dyn Fn(&mut Transaction, &mut Vec<UtxoEntry>)| {
        let mut tx = good.transaction().clone();
        let mut entries = good.entries().to_vec();
        edit(&mut tx, &mut entries);
        tx.finalize();
        let v = crate::cancel::document(good.terms(), &tx, &entries, w.buyer.signer).unwrap();
        let ipst = Ipst::from_json(&v.to_string()).unwrap();
        let p = w.path(name);
        std::fs::write(&p, ipst.to_json()).unwrap();
        p
    };
    let same = doc("same.ipst", &|_, _| {});
    assert_eq!(
        std::fs::read_to_string(&same).unwrap(),
        std::fs::read_to_string(&built).unwrap()
    );
    // Every input of the built document is a P2PK spend at its exact budget.
    assert!(good
        .transaction()
        .inputs
        .iter()
        .all(|i| i.compute_commit.compute_budget() == Some(P2PK_BUDGET_TEST) && i.sequence == 0));
    let input = |tx: &Transaction, i: usize, sequence: u64, budget: u16| {
        TransactionInput::new_with_compute_budget(
            tx.inputs[i].previous_outpoint,
            vec![],
            sequence,
            budget,
        )
    };
    let cases = [
        (
            "output 0 pays the seller",
            doc("t1.ipst", &|tx, _| {
                tx.outputs[0].script_public_key = seller.clone()
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "the Direct input does not go home whole",
            doc("t2.ipst", &|tx, _| {
                tx.outputs[0].value -= 1;
                tx.outputs[1].value += 1;
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "no lock time",
            doc("t3.ipst", &|tx, _| tx.lock_time = 0),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "the lock time switched off by a final sequence",
            doc("t4.ipst", &|tx, _| {
                tx.inputs[0] = input(tx, 0, u64::MAX, P2PK_BUDGET_TEST)
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a raised compute budget",
            doc("t5.ipst", &|tx, _| {
                tx.inputs[1] = input(tx, 1, 0, P2PK_BUDGET_TEST + 5)
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            // Self-consistent: the larger UTXO goes home whole and the exact cash pays the fee,
            // so only the input 0 check refuses it.
            "input 0 is not the buyer's exact cash",
            doc("t6.ipst", &|tx, entries| {
                tx.inputs.swap(0, 1);
                entries.swap(0, 1);
                let total: u64 = entries.iter().map(|e| e.amount).sum();
                tx.outputs[0].value = entries[0].amount;
                tx.outputs[1].value = total - entries[0].amount - good.fee();
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a fee input of another key",
            doc("t8.ipst", &|_, entries| {
                entries[1].script_public_key = seller.clone()
            }),
            "TX_KAS_INPUT",
        ),
        (
            "the Direct input spent twice",
            doc("t9.ipst", &|tx, entries| {
                tx.inputs[1] = input(tx, 0, 0, P2PK_BUDGET_TEST);
                entries[1] = entries[0].clone();
                tx.outputs.truncate(1);
            }),
            "TX_DUPLICATE_INPUT",
        ),
        (
            "a non-standard change script",
            doc("t10.ipst", &|tx, _| {
                tx.outputs[1].script_public_key = ScriptPublicKey::from_vec(0, vec![0x51])
            }),
            "TX_NONSTANDARD_CHANGE",
        ),
        (
            "the fee taken from the Direct input",
            doc("t7.ipst", &|tx, entries| {
                tx.inputs.truncate(1);
                entries.truncate(1);
                tx.outputs = vec![TransactionOutput::new(KAS_CASH - 1_000_000, buyer.clone())];
            }),
            "TX_KAS_INPUT",
        ),
    ];
    for (what, path, code) in &cases {
        let out = w.path("refused.out");
        assert_eq!(
            w.no(&w.sign_args(path, &w.buyer, &out)),
            *code,
            "ipst sign: {what}"
        );
        assert_eq!(
            w.no(&merge_args(&w, path, path, &out)),
            *code,
            "ipst merge: {what}"
        );
        assert_eq!(w.no(&w.submit_args(path)), *code, "submit: {what}");
        assert!(!out.exists());
    }
    // The payer checks hold for the buyer's fee inputs: change elsewhere is refused.
    assert_eq!(
        w.no(&with(
            &w.sign_args(&same, &w.buyer, &w.path("c.signed")),
            &["--change", &w.addr(&w.seller)]
        )),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
    // Controls: the built document signs, merges and submits once the expiry has passed.
    let signed = w.path("same.signed");
    w.go(&w.sign_args(&same, &w.buyer, &signed));
    let merged = w.path("same.merged");
    w.go(&merge_args(&w, &signed, &same, &merged));
    w.set_daa(START_DAA + EXPIRY_IN + 1);
    let out = w.go(&w.submit_args(&merged));
    assert_eq!(
        field(&out, "submitted"),
        hex(&good.transaction().id().as_bytes())
    );
}

/// spec/CLI.md, "direct cancel build", checks 5 and 6 (review round 1 of the integration
/// follow-up): a cancellation stops only a Direct transaction that spends its input 0. With
/// several UTXOs of exactly the cash amount, the command names no input by itself
/// (`CLI_CANCEL_INPUT_AMBIGUOUS`); `--for-ipst` takes the named Direct transaction's input 1, so
/// the input `settle build` took and the input the cancellation spends move together, whichever
/// outpoint is lower; a document that is not such a transaction, and a `--direct-input` beside
/// it that names another UTXO, are `CLI_CANCEL_INPUT_MISMATCH`.
#[test]
fn direct_cancel_build_cancels_the_direct_transaction_it_names() {
    use kaspa_consensus_core::tx::TransactionOutpoint;
    let w = World::new(Network::Testnet);
    let terms = w.terms("d.json", Mode::Direct, |_| {});
    let buyer_spk = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let cancel = |name: &str, extra: &[&str]| {
        with(
            &cancel_args(&terms, "buyer", &w.buyer, &w.path(name)),
            extra,
        )
    };
    let refused = |name: &str, extra: &[&str]| {
        let code = w.no(&cancel(name, extra));
        assert!(!w.path(name).exists(), "{code}: wrote {name}");
        code
    };
    let direct = |name: &str| {
        let p = w.path(name);
        let out = w.go(&w.settle_args(&terms, &w.seller, &p));
        (p, field(&out, "txid"), input_outpoint(&out, 1))
    };
    // One UTXO of exactly the cash amount: it is the Direct input, named or not.
    let (d1, d1_txid, d1_input) = direct("d1.ipst");
    let out = w.go(&cancel("c0.ipst", &[]));
    assert_eq!(input_outpoint(&out, 0), d1_input);
    assert_eq!(
        field(&out, "cancels"),
        format!(
            "no Direct transaction named; only one that spends {d1_input} (name it with --for-ipst)"
        )
    );
    let out = w.go(&cancel("c1.ipst", &["--for-ipst", s(&d1)]));
    assert_eq!(input_outpoint(&out, 0), d1_input);
    assert_eq!(
        field(&out, "cancels"),
        format!("Direct transaction {d1_txid}, its input 1 {d1_input}")
    );

    // A second exact UTXO arrives with a lower outpoint: settle build now takes it.
    let low = outpoint_text(&w.sim.state.borrow_mut().add_utxo_at(
        TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([0; 32]), 0),
        buyer_spk.clone(),
        KAS_CASH,
    ));
    assert!(low < d1_input);
    let (d2, d2_txid, d2_input) = direct("d2.ipst");
    assert_eq!(d2_input, low);
    // Refused: no input named among several; nothing written.
    assert_eq!(refused("r1.ipst", &[]), "CLI_CANCEL_INPUT_AMBIGUOUS");
    // Each Direct transaction's own input is cancelled.
    let out = w.go(&cancel("c2.ipst", &["--for-ipst", s(&d1)]));
    assert_eq!(input_outpoint(&out, 0), d1_input);
    let out = w.go(&cancel("c3.ipst", &["--for-ipst", s(&d2)]));
    assert_eq!(input_outpoint(&out, 0), d2_input);
    assert_eq!(
        field(&out, "cancels"),
        format!("Direct transaction {d2_txid}, its input 1 {d2_input}")
    );
    // A third with a higher outpoint: settle build keeps the lowest, and each still moves with
    // its Direct transaction.
    let high = outpoint_text(&w.sim.state.borrow_mut().add_utxo_at(
        TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([0xff; 32]), 0),
        buyer_spk.clone(),
        KAS_CASH,
    ));
    let (d3, _, d3_input) = direct("d3.ipst");
    assert_eq!(d3_input, low);
    let out = w.go(&cancel("c4.ipst", &["--for-ipst", s(&d3)]));
    assert_eq!(input_outpoint(&out, 0), low);
    let out = w.go(&cancel("c5.ipst", &["--for-ipst", s(&d1)]));
    assert_eq!(input_outpoint(&out, 0), d1_input);
    assert_eq!(refused("r2.ipst", &[]), "CLI_CANCEL_INPUT_AMBIGUOUS");
    // --direct-input alone names any one of them, and says no transaction is named.
    let out = w.go(&cancel("c6.ipst", &["--direct-input", &high]));
    assert_eq!(input_outpoint(&out, 0), high);
    assert!(field(&out, "cancels").starts_with("no Direct transaction named"));
    // --direct-input beside --for-ipst: the same outpoint only.
    assert_eq!(
        refused("r3.ipst", &["--for-ipst", s(&d1), "--direct-input", &high]),
        "CLI_CANCEL_INPUT_MISMATCH"
    );
    w.go(&cancel(
        "c7.ipst",
        &["--for-ipst", s(&d1), "--direct-input", &d1_input],
    ));

    // --for-ipst that is not a Direct transaction of these terms whose input 1 is the buyer's
    // exact cash: another trade's Direct transaction, a cancellation, and a document of these
    // terms whose input 1 holds another amount (rendered with consistent sighashes, so only
    // this check refuses it).
    let other_terms = w.terms("d-other.json", Mode::Direct, |_| {});
    let other = w.path("other.ipst");
    w.go(&w.settle_args(&other_terms, &w.seller, &other));
    assert_eq!(
        refused("r4.ipst", &["--for-ipst", s(&other)]),
        "CLI_CANCEL_INPUT_MISMATCH"
    );
    let built = w.path("c1.ipst");
    let good = Ipst::from_json(&std::fs::read_to_string(&built).unwrap()).unwrap();
    // The cancellation itself, whose fee input is made exactly the cash amount, so that only
    // the "not a cancellation" rule refuses it.
    let mut tx = good.transaction().clone();
    let mut entries = good.entries().to_vec();
    entries[1].amount = KAS_CASH;
    tx.outputs[1].value = KAS_CASH - good.fee();
    tx.finalize();
    let as_cancel = w.path("as-cancel.ipst");
    let v = crate::cancel::document(good.terms(), &tx, &entries, w.buyer.signer).unwrap();
    std::fs::write(
        &as_cancel,
        Ipst::from_json(&v.to_string()).unwrap().to_json(),
    )
    .unwrap();
    assert_eq!(
        refused("r5.ipst", &["--for-ipst", s(&as_cancel)]),
        "CLI_CANCEL_INPUT_MISMATCH"
    );
    let d = Ipst::from_json(&std::fs::read_to_string(&d1).unwrap()).unwrap();
    let mut entries = d.entries().to_vec();
    entries[1].amount += 1;
    let mut v: serde_json::Value = serde_json::from_str(&d.to_json()).unwrap();
    v["inputs"][1]["utxo"]["amount"] = entries[1].amount.to_string().into();
    for (i, input) in v["inputs"].as_array_mut().unwrap().iter_mut().enumerate() {
        if !input["sighash"].is_null() {
            let h = impulse_core::tx::sighash(d.transaction(), &entries, i).unwrap();
            input["sighash"] = hex(&h).into();
        }
    }
    let odd = w.path("odd-direct.ipst");
    std::fs::write(&odd, Ipst::from_json(&v.to_string()).unwrap().to_json()).unwrap();
    assert_eq!(
        refused("r6.ipst", &["--for-ipst", s(&odd)]),
        "CLI_CANCEL_INPUT_MISMATCH"
    );
    // A malformed --for-ipst refuses as any IPST does.
    std::fs::write(w.path("bad.ipst"), "{}").unwrap();
    assert_eq!(
        refused("r7.ipst", &["--for-ipst", s(&w.path("bad.ipst"))]),
        "IPST_MALFORMED"
    );
}

/// spec/CLI.md, "The cancellation check" (review round 1 of the integration follow-up): each
/// clause of the input 0 gate refuses on its own, beside the built document. Input 0 and every
/// fee input under the seller's key at the exact cash amount (only the script clause sees it);
/// Direct terms with KCC-20 cash and a KAS input 0 of the cash number (only the kind clause);
/// an input 0 with a covenant ID (not a cancellation at all, so the core's terms check refuses
/// it).
#[test]
fn the_cancellation_check_refuses_each_clause_of_its_input_0_gate() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("d.json", Mode::Direct, |_| {});
    let built = w.path("cancel.ipst");
    w.go(&cancel_args(&terms, "buyer", &w.buyer, &built));
    let good = Ipst::from_json(&std::fs::read_to_string(&built).unwrap()).unwrap();
    let seller = address_script(&p2pk_address(&w.seller.signer, w.network));
    let render = |name: &str,
                  t: &impulse_core::terms::ValidatedTerms,
                  tx: &mut kaspa_consensus_core::tx::Transaction,
                  entries: &[kaspa_consensus_core::tx::UtxoEntry],
                  key: [u8; 32]| {
        tx.finalize();
        let v = crate::cancel::document(t, tx, entries, key).unwrap();
        let p = w.path(name);
        std::fs::write(&p, Ipst::from_json(&v.to_string()).unwrap().to_json()).unwrap();
        p
    };
    let refused_by_all = |path: &Path, k: &KeyFile, code: &str, what: &str| {
        let out = w.path("refused.out");
        assert_eq!(w.no(&w.sign_args(path, k, &out)), code, "ipst sign: {what}");
        assert_eq!(
            w.no(&merge_args(&w, path, path, &out)),
            code,
            "ipst merge: {what}"
        );
        assert_eq!(w.no(&w.submit_args(path)), code, "submit: {what}");
        assert!(!out.exists());
    };
    // Every input and output under the seller's key: a document build would make for the seller,
    // so only the script clause refuses it.
    let mut tx = good.transaction().clone();
    let mut entries = good.entries().to_vec();
    for e in &mut entries {
        e.script_public_key = seller.clone();
    }
    for o in &mut tx.outputs {
        o.script_public_key = seller.clone();
    }
    let by_seller = render(
        "seller.ipst",
        good.terms(),
        &mut tx,
        &entries,
        w.seller.signer,
    );
    refused_by_all(
        &by_seller,
        &w.seller,
        "IPST_TERMS_MISMATCH",
        "the seller's KAS",
    );
    // KCC-20 cash: a KAS input 0 holding as many sompi as the leg has token units.
    let kcc20 = w.terms("k.json", Mode::DirectKcc20, |_| {});
    let kterms = crate::terms_file::read_terms_file(&kcc20).unwrap();
    let mut tx = good.transaction().clone();
    let mut entries = good.entries().to_vec();
    entries[0].amount = CASH_TOKENS;
    tx.outputs[0].value = CASH_TOKENS;
    let kas_for_tokens = render("tokens.ipst", &kterms, &mut tx, &entries, w.buyer.signer);
    refused_by_all(
        &kas_for_tokens,
        &w.buyer,
        "IPST_TERMS_MISMATCH",
        "KCC-20 cash",
    );
    // An input 0 with a covenant ID is no cancellation: the core's terms check refuses it.
    let mut tx = good.transaction().clone();
    let mut entries = good.entries().to_vec();
    entries[0].covenant_id = Some(kaspa_consensus_core::Hash::from_bytes(random32()));
    let with_covenant = render(
        "covenant.ipst",
        good.terms(),
        &mut tx,
        &entries,
        w.buyer.signer,
    );
    refused_by_all(
        &with_covenant,
        &w.buyer,
        "IPST_TERMS_MISMATCH",
        "a covenant ID",
    );
    // Control: the built document signs, and --carrier, which no cancellation takes, is refused.
    let signed = w.path("cancel.signed");
    assert_eq!(
        w.no(&with(
            &w.sign_args(&built, &w.buyer, &signed),
            &["--carrier", "200000000"]
        )),
        "TX_WRONG_MODE"
    );
    let out = w.go(&w.sign_args(&built, &w.buyer, &signed));
    assert_eq!(field(&out, "pending"), "complete");
    // The fee inputs are the buyer's largest UTXOs first.
    assert!(
        field(&out, "input 1").contains(" 400000000000 sompi at "),
        "{out}"
    );
}

/// spec/CLI.md, "direct cancel build", the rules of the builders (review round 1 of the
/// integration follow-up): each refused by `build` with its code, beside the accepted control.
#[test]
fn direct_cancel_build_applies_each_rule_of_the_builders() {
    use impulse_core::tx::{TxError, Utxo};
    use kaspa_addresses::{Address, Version};
    use kaspa_consensus_core::constants::MAX_SOMPI;
    use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
    let w = World::new(Network::Testnet);
    let terms =
        crate::terms_file::read_terms_file(&w.terms("d.json", Mode::Direct, |_| {})).unwrap();
    let buyer = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let mut n = 0u32;
    let mut utxo = |amount: u64, spk: &ScriptPublicKey, covenant: Option<[u8; 32]>| {
        n += 1;
        Utxo {
            outpoint: TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([7; 32]), n),
            entry: UtxoEntry::new(
                amount,
                spk.clone(),
                START_DAA,
                false,
                covenant.map(kaspa_consensus_core::Hash::from_bytes),
            ),
        }
    };
    let input = utxo(KAS_CASH, &buyer, None);
    let ten = utxo(10 * KAS_CASH, &buyer, None);
    let pay = |inputs: Vec<Utxo>, change: &ScriptPublicKey| FeePayment {
        inputs,
        fee: 1_000_000,
        change: change.clone(),
    };
    let build = |input: &Utxo, p: &FeePayment| crate::cancel::build(&terms, input, p);
    // Controls: the change to the buyer, a P2SH and a P2PK-ECDSA change, as --change accepts.
    assert!(build(&input, &pay(vec![ten.clone()], &buyer)).is_ok());
    let p2sh = address_script(&Address::new(
        impulse_core::address::prefix(w.network),
        Version::ScriptHash,
        &[0x11; 32],
    ));
    let ecdsa = address_script(&Address::new(
        impulse_core::address::prefix(w.network),
        Version::PubKeyECDSA,
        &[[0x02].as_slice(), &[0x22; 32]].concat(),
    ));
    assert!(build(&input, &pay(vec![ten.clone()], &p2sh)).is_ok());
    assert!(build(&input, &pay(vec![ten.clone()], &ecdsa)).is_ok());
    // A version-1 change script of P2PK form is not standard.
    let v1 = ScriptPublicKey::new(1, buyer.script().into());
    assert!(matches!(
        build(&input, &pay(vec![ten.clone()], &v1)),
        Err(TxError::NonstandardChange)
    ));
    // TX_UTXO_VALUE: a fee input of zero, one above the supply, and inputs above it together.
    let zero = utxo(0, &buyer, None);
    assert!(matches!(
        build(&input, &pay(vec![zero, ten.clone()], &buyer)),
        Err(TxError::UtxoValue {
            input: Some(1),
            value: 0
        })
    ));
    let huge = utxo(MAX_SOMPI + 1, &buyer, None);
    assert!(matches!(
        build(&input, &pay(vec![huge], &buyer)),
        Err(TxError::UtxoValue { input: Some(1), .. })
    ));
    let all = utxo(MAX_SOMPI, &buyer, None);
    assert!(matches!(
        build(&input, &pay(vec![all], &buyer)),
        Err(TxError::UtxoValue { input: None, .. })
    ));
    // TX_MASS: three hundred fee inputs, with a fee that covers any relay minimum.
    let many: Vec<Utxo> = (0..300).map(|_| utxo(KAS_CASH, &buyer, None)).collect();
    let heavy = FeePayment {
        inputs: many,
        fee: 50 * KAS_CASH,
        change: buyer.clone(),
    };
    assert!(
        matches!(build(&input, &heavy), Err(TxError::Mass { .. })),
        "{:?}",
        build(&input, &heavy).err()
    );
    // TX_KAS_INPUT: a fee input with a covenant ID; a Direct input with one; a Direct input
    // under a version-1 script of P2PK form.
    let token_like = utxo(10 * KAS_CASH, &buyer, Some([9; 32]));
    assert!(matches!(
        build(&input, &pay(vec![token_like], &buyer)),
        Err(TxError::KasInput { index: 1, .. })
    ));
    let covenanted = utxo(KAS_CASH, &buyer, Some([9; 32]));
    assert!(matches!(
        build(&covenanted, &pay(vec![ten.clone()], &buyer)),
        Err(TxError::KasInput { index: 0, .. })
    ));
    let versioned = utxo(KAS_CASH, &v1, None);
    assert!(matches!(
        build(&versioned, &pay(vec![ten.clone()], &buyer)),
        Err(TxError::KasInput { index: 0, .. })
    ));
}

const P2PK_BUDGET_TEST: u16 = impulse_core::tx::P2PK_BUDGET;

/// The testnet token helper (spec/CLI.md, "Token helper (testnet only)"), on this world.
#[path = "token_tests.rs"]
mod token_tests;

/// `TOKEN_FOREIGN_AT_VAULT` is retired (I26, spec/ERRORS.md "Retired and changed codes"): a
/// token of the other leg's covenant owned by a vault's script hash cannot move, since every
/// settle spends the other leg's vault ([S10]) and every refund refuses it ([F3])
/// (spec/TRANSACTIONS.md, "A token of another covenant at a vault"). The builders no longer
/// look for it, and build as they would without it.
#[test]
fn a_token_of_the_other_legs_covenant_at_a_vault_is_not_warned_about() {
    let w = World::new(Network::Testnet);
    let terms = w.terms("t", Mode::SelfSettling, |_| {});
    w.fund(&terms, LegIndex::Asset);
    w.fund(&terms, LegIndex::Cash);
    let refund = w.refund_args(&terms, "asset", "depositor", &w.seller, &w.path("r1"));
    let settle = w.settle_args(&terms, &w.seller, &w.path("s1"));
    for args in [&refund, &settle] {
        let out = w.go(args);
        assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "control: {out}");
    }
    // The buyer's cash token sent by mistake to the asset vault's script hash.
    let asset_vault = w.vault(&terms, LegIndex::Asset);
    let misdirected = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: asset_vault.script_hash(),
        },
        CASH_TOKENS,
    );
    w.sim.state.borrow_mut().add_utxo(
        w.cash.script_public_key(&misdirected).unwrap(),
        MIN_KCC20_OUTPUT,
        Some(w.cash_cov),
    );
    for (args, name) in [
        (with(&refund, &[]), "r2"),
        (w.settle_args(&terms, &w.seller, &w.path("s2")), "s2"),
    ] {
        let args = replace(&args, "--out", s(&w.path(name)));
        let out = w.go(&args);
        assert!(out.contains("wrote: "), "{out}");
        assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "{out}");
    }
    let out = w.go(&w.fund_args(&terms, LegIndex::Cash, &w.path("f2")));
    assert!(!out.contains("TOKEN_FOREIGN_AT_VAULT"), "{out}");
}
