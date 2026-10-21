// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse xchain` end to end in process (spec/V2.md sections 10.9 and 11.3), against the
//! in-memory fake node, which runs every submitted input in the pinned script engine, and the
//! fake counterpart source. Each refusal has an accepted control beside it, and every refused
//! command is checked to have printed nothing. The secret and the revealed preimage are checked
//! never to appear in any command's output or notes.
//!
//! Keys: throwaway keys generated at runtime into temporary directories that are removed (docs/ENGINEERING-RULES.md
//! rule 1); the hashlock secret is drawn by `xchain new` itself and lives only in the test's
//! temporary directory.

use super::counterpart::fake::{finality_text, lock_json, state};
use super::counterpart::{Finality, Lock};
use super::doc;
use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, outpoint_text, p2pk_address};
use crate::json::hex;
use crate::node::{Node, ServerInfo};
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::testutil::TempDir;
use clap::Parser;
use impulse_core::htlc::{CounterpartChain, HtlcVault, ValidatedHtlcTerms, FINALITY_DEPTH_DAA};
use impulse_core::terms::{IdentifierType, Kcc20Owner, Network};
use impulse_core::tx::{Kcc20State, Kcc20Template, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{CovenantBinding, Transaction, TransactionOutput};
use kaspa_consensus_core::Hash;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::{Path, PathBuf};

const ASSET_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const NODE: &str = "ws://127.0.0.1:17210";
const START_DAA: u64 = 1_000_000;
const EXPIRY_IN: u64 = 864_000;
const AMOUNT: u64 = 10;
const FINAL_SECS: &str = "60";
const DECLARE: [&str; 2] = ["--kas-equivalent", "100000000"];
const HOURS: u64 = 3_600;

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn now() -> u64 {
    super::now_unix()
}

/// A node that reports another network ID than the fake node's, for the blocks-per-second check.
struct Renamed {
    inner: SimNode,
    name: &'static str,
}

impl Node for Renamed {
    fn server_info(&self) -> Result<ServerInfo, CliError> {
        let mut info = self.inner.server_info()?;
        info.network_name = self.name.into();
        Ok(info)
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
        self.inner.utxos(address)
    }
    fn accepted_from(&self, start: [u8; 32]) -> Result<crate::node::AcceptedUpdate, CliError> {
        self.inner.accepted_from(start)
    }
}

struct World {
    dir: TempDir,
    sim: SimNode,
    seller: KeyFile,
    buyer: KeyFile,
    payer: KeyFile,
    template: Kcc20Template,
    covenant: [u8; 32],
    seller_token: String,
    chain_id: [u8; 32],
    program: [u8; 32],
    usdc: [u8; 32],
    seller_account: [u8; 32],
    buyer_account: [u8; 32],
    /// Every line any command printed or noted, for the secret scan.
    seen: RefCell<String>,
    /// When set, the node reports this network ID.
    rename: RefCell<Option<&'static str>>,
    mainnet: std::cell::Cell<bool>,
}

impl World {
    fn new() -> Self {
        Self::on(Network::Testnet)
    }

    /// A world whose node, funds, drafts and command line are all on `net`.
    fn on(net: Network) -> Self {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("asset.json"), ASSET_JSON).unwrap();
        let mut st = SimState::new(net, START_DAA, 0);
        let (seller, buyer, payer) = (key_file(), key_file(), key_file());
        for k in [&seller, &buyer, &payer] {
            let spk = address_script(&p2pk_address(&k.signer, net));
            for amount in [400_000_000_000, 300_000_000_000] {
                st.add_utxo(spk.clone(), amount, None);
            }
        }
        let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let covenant: [u8; 32] = rand::random();
        let held = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: seller.signer,
            },
            1_000,
        );
        let o = st.add_utxo(
            template.script_public_key(&held).unwrap(),
            MIN_KCC20_OUTPUT,
            Some(covenant),
        );
        let w = Self {
            dir,
            sim: SimNode::memory(st),
            seller,
            buyer,
            payer,
            template,
            covenant,
            seller_token: format!("{}:1000", outpoint_text(&o)),
            chain_id: rand::random(),
            program: rand::random(),
            usdc: rand::random(),
            seller_account: rand::random(),
            buyer_account: rand::random(),
            seen: RefCell::new(String::new()),
            rename: RefCell::new(None),
            mainnet: std::cell::Cell::new(net == Network::Mainnet),
        };
        w.write_counterpart(state(CounterpartChain::Solana, &w.chain_id, None));
        w
    }

    fn net(&self) -> Network {
        if self.mainnet.get() {
            Network::Mainnet
        } else {
            Network::Testnet
        }
    }

    /// A mainnet DAA rate sample at 10 blocks per second, 8 days long, ending an hour ago.
    fn write_mainnet_sample(&self) -> String {
        let end = now() - HOURS;
        let start = end - 8 * 86_400;
        let mut text = String::from("impulse-daa-sample 1 mainnet bps 10\n");
        let mut t = start;
        while t <= end {
            text.push_str(&format!("{t} {}\n", 2_000_000_000 - (end - t) * 10));
            t += 300;
        }
        std::fs::write(self.path("main.sample"), text).unwrap();
        self.p("main.sample")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn p(&self, name: &str) -> String {
        s(&self.path(name)).to_string()
    }

    fn tpl(&self) -> String {
        self.p("asset.json")
    }

    fn cp(&self) -> String {
        format!("fake-counterpart://{}", self.p("counterpart.json"))
    }

    fn write_counterpart(&self, v: Value) {
        std::fs::write(
            self.path("counterpart.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
    }

    fn counterpart(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.path("counterpart.json")).unwrap())
            .unwrap()
    }

    fn edit_counterpart(&self, f: impl FnOnce(&mut Value)) {
        let mut v = self.counterpart();
        f(&mut v);
        self.write_counterpart(v);
    }

    fn addr(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, self.net()).to_string()
    }

    /// A draft, with the counterpart timeout `tc` and expiry `EXPIRY_IN` after the start.
    fn draft(&self, name: &str, tc: u64, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let mut v = json!({
            "version": 1,
            "network": if self.mainnet.get() { "mainnet" } else { "testnet" },
            "seller_key": hex(&self.seller.signer),
            "buyer_key": hex(&self.buyer.signer),
            "asset_leg": {
                "kind": "kcc20",
                "covenant_id": hex(&self.covenant),
                "template_hash": hex(&self.template.template_hash()),
                "template_prefix_len": self.template.prefix_len(),
                "template_suffix_len": self.template.suffix_len(),
                "amount": AMOUNT.to_string(),
            },
            "buyer_delivery": {"identifier_type": "pubkey", "identifier": hex(&self.buyer.signer)},
            "seller_refund": {"identifier_type": "pubkey", "identifier": hex(&self.seller.signer)},
            "expiry_daa": (START_DAA + EXPIRY_IN).to_string(),
            "counterpart": {
                "chain": "solana",
                "chain_id": hex(&self.chain_id),
                "htlc_program": hex(&self.program),
                "asset": hex(&self.usdc),
                "amount": "250000000",
                "recipient": hex(&self.seller_account),
                "refund": hex(&self.buyer_account),
                "timeout": tc.to_string(),
            },
            "trade_ref": hex(&[0x2a; 32]),
        });
        edit(&mut v);
        let p = self.path(name);
        std::fs::write(&p, v.to_string()).unwrap();
        p
    }

    fn exec(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse"];
        if self.mainnet.get() {
            argv.extend_from_slice(&["--network", "mainnet"]);
        }
        argv.push("xchain");
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        let sim = self.sim.clone();
        let rename = *self.rename.borrow();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(match rename {
                Some(name) => Box::new(Renamed {
                    inner: sim.clone(),
                    name,
                }),
                None => Box::new(sim.clone()),
            })
        };
        let env = Env {
            max_value: None,
            connect: &connect,
        };
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let r = run(cli, &env, &mut out, &mut notes);
        let (out, notes) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(notes).unwrap(),
        );
        let mut seen = self.seen.borrow_mut();
        seen.push_str(&out);
        seen.push_str(&notes);
        if let Err(e) = &r {
            seen.push_str(&e.to_string());
        }
        (r, out)
    }

    fn go(&self, args: &[&str]) -> String {
        let (r, out) = self.exec(args);
        r.unwrap_or_else(|e| panic!("{args:?}: {e}"));
        out
    }

    fn no(&self, args: &[&str]) -> &'static str {
        let (r, out) = self.exec(args);
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }

    /// `xchain new` arguments for draft `draft`, writing `<name>.terms` and `<name>.secret`.
    fn new_args(&self, draft: &Path, name: &str) -> Vec<String> {
        [
            "new",
            "--draft",
            s(draft),
            "--my-key",
            &hex(&self.seller.signer),
            "--my-counterpart-account",
            &hex(&self.seller_account),
            "--node",
            NODE,
            "--counterpart-final-secs",
            FINAL_SECS,
            "--known-hashes",
            &self.p("seller.known"),
            DECLARE[0],
            DECLARE[1],
            "--secret-out",
            &self.p(&format!("{name}.secret")),
            "--out",
            &self.p(&format!("{name}.terms")),
        ]
        .map(String::from)
        .to_vec()
    }

    fn verify_args(&self, terms: &str) -> Vec<String> {
        [
            "verify",
            "--terms",
            terms,
            "--my-key",
            &hex(&self.buyer.signer),
            "--my-counterpart-account",
            &hex(&self.buyer_account),
            "--node",
            NODE,
            "--counterpart-final-secs",
            FINAL_SECS,
            "--known-hashes",
            &self.p("buyer.known"),
            DECLARE[0],
            DECLARE[1],
        ]
        .map(String::from)
        .to_vec()
    }

    /// A trade created by the seller: its terms file path.
    fn create(&self, name: &str) -> String {
        let draft = self.draft(&format!("{name}.draft"), now() + 3 * HOURS, |_| {});
        let args = self.new_args(&draft, name);
        self.go(&strs(&args));
        self.p(&format!("{name}.terms"))
    }

    fn terms(&self, terms: &str) -> ValidatedHtlcTerms {
        doc::read_terms_file(Path::new(terms)).unwrap()
    }

    /// Funds the trade's vault: build, sign as the seller, submit. Returns what submit printed.
    fn fund(&self, terms: &str, name: &str) -> String {
        let unsigned = self.p(&format!("{name}.fund.ipst"));
        self.go(&[
            "fund",
            "build",
            "--terms",
            terms,
            "--node",
            NODE,
            "--my-key",
            &hex(&self.seller.signer),
            "--counterpart-final-secs",
            FINAL_SECS,
            "--pay-from",
            &self.addr(&self.seller),
            "--asset-template",
            &self.tpl(),
            "--token",
            &self.seller_token,
            DECLARE[0],
            DECLARE[1],
            "--out",
            &unsigned,
        ]);
        let signed = self.p(&format!("{name}.fund.signed"));
        self.go(&[
            "sign",
            "--ipst",
            &unsigned,
            "--terms",
            terms,
            "--key-file",
            s(&self.seller.path),
            "--role",
            "seller",
            "--my-key",
            &hex(&self.seller.signer),
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
            "--counterpart-final-secs",
            FINAL_SECS,
            DECLARE[0],
            DECLARE[1],
            "--out",
            &signed,
        ]);
        self.submit(&signed)
    }

    fn submit(&self, signed: &str) -> String {
        self.go(&[
            "submit",
            "--ipst",
            signed,
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
        ])
    }

    /// The buyer's lock on the fake counterpart chain, as the record says, at `finality`.
    fn lock(&self, terms: &str, finality: Finality, edit: impl FnOnce(&mut Lock)) -> Lock {
        let t = self.terms(terms);
        let c = &t.terms().counterpart;
        let mut l = Lock {
            id: rand::random(),
            htlc_program: c.htlc_program,
            asset: c.asset,
            amount: c.amount,
            recipient: c.recipient,
            refund: c.refund,
            hash_lock: t.terms().hash_lock,
            timeout: c.timeout,
            funded: true,
            finality,
            reference: None,
        };
        edit(&mut l);
        let entry = lock_json(&l);
        self.edit_counterpart(|v| v["locks"].as_array_mut().unwrap().push(entry));
        l
    }

    fn set_claims(&self, f: Finality) {
        self.edit_counterpart(|v| {
            for c in v["claims"].as_array_mut().unwrap() {
                c["finality"] = json!(finality_text(f));
            }
        });
    }

    fn claims(&self) -> usize {
        self.counterpart()["claims"].as_array().unwrap().len()
    }

    fn cp_claim_args(&self, terms: &str, secret: &str) -> Vec<String> {
        [
            "counterpart-claim",
            "--terms",
            terms,
            "--secret-file",
            secret,
            "--counterpart",
            &self.cp(),
            "--counterpart-final-secs",
            FINAL_SECS,
        ]
        .map(String::from)
        .to_vec()
    }

    /// `counterpart-claim` arguments against another counterpart URL than the fake one.
    fn cp_claim_args_for(&self, terms: &str, secret: &str, cp: &str) -> Vec<String> {
        let mut a = self.cp_claim_args(terms, secret);
        a[6] = cp.to_string();
        a
    }

    fn claim_args(&self, terms: &str, source: [&str; 2], out: &str) -> Vec<String> {
        [
            "claim",
            "--terms",
            terms,
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
            source[0],
            source[1],
            "--pay-from",
            &self.addr(&self.payer),
            DECLARE[0],
            DECLARE[1],
            "--out",
            out,
        ]
        .map(String::from)
        .to_vec()
    }

    fn sign_as(&self, ipst: &str, terms: &str, k: &KeyFile, role: &str, out: &str) -> String {
        self.go(&[
            "sign",
            "--ipst",
            ipst,
            "--terms",
            terms,
            "--key-file",
            s(&k.path),
            "--role",
            role,
            "--my-key",
            &hex(&k.signer),
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
            DECLARE[0],
            DECLARE[1],
            "--out",
            out,
        ])
    }

    fn status_args(&self, terms: &str, txid: &str, from: &str, counterpart: bool) -> Vec<String> {
        let mut v = [
            "status",
            "--terms",
            terms,
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
            "--txid",
            txid,
            "--from-block",
            from,
        ]
        .map(String::from)
        .to_vec();
        if counterpart {
            v.extend(["--counterpart".to_string(), self.cp()]);
        }
        v
    }

    fn verify_funding_args(&self, terms: &str, txid: &str, from: &str) -> Vec<String> {
        [
            "verify-funding",
            "--terms",
            terms,
            "--node",
            NODE,
            "--asset-template",
            &self.tpl(),
            "--txid",
            txid,
            "--from-block",
            from,
        ]
        .map(String::from)
        .to_vec()
    }

    /// A transaction with `outputs` and no inputs, accepted by the fake node as if another
    /// wallet had submitted it: its ID and the chain block before it, as submit prints them.
    fn accept(&self, outputs: Vec<TransactionOutput>) -> (String, String) {
        let tx = Transaction::new(0, vec![], outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let mut st = self.sim.state.borrow_mut();
        let from = st.sink();
        let id = st.accept_unchecked(&tx);
        (hex(&id), hex(&from))
    }

    fn set_daa(&self, daa: u64) {
        self.sim.state.borrow_mut().virtual_daa = daa;
    }

    fn daa(&self) -> u64 {
        self.sim.state.borrow().virtual_daa
    }
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

fn secret_hex(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .trim_end()
        .to_string()
}

#[cfg(unix)]
fn mode(path: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// =============================================================================================
// The whole flow
// =============================================================================================

#[test]
fn a_hashlock_trade_runs_end_to_end_and_completes_only_when_both_claims_are_final() {
    let w = World::new();
    let terms = w.create("t");
    let secret_path = w.p("t.secret");
    #[cfg(unix)]
    assert_eq!(mode(&secret_path), 0o600);
    let secret = secret_hex(&secret_path);
    assert_eq!(secret.len(), 64);
    let t = w.terms(&terms);
    assert_eq!(
        hex(&impulse_core::htlc::sha256(
            &crate::json::unhex(&secret).unwrap()
        )),
        hex(&t.terms().hash_lock),
        "hash_lock is sha256 of the secret written"
    );
    // The buyer checks the terms and records the hash lock.
    let out = w.go(&strs(&w.verify_args(&terms)));
    assert!(field(&out, "ok").starts_with("buyer"));
    assert!(field(&out, "funding").contains("xchain verify-funding"));
    // The seller funds the vault; the buyer verifies the funding at final depth before locking.
    let funded = w.fund(&terms, "t");
    let vf = w.verify_funding_args(
        &terms,
        &field(&funded, "submitted"),
        &field(&funded, "from_block"),
    );
    assert_eq!(w.no(&strs(&vf)), "XCHAIN_NOT_FINAL");
    w.set_daa(w.daa() + FINALITY_DEPTH_DAA);
    assert!(field(&w.go(&strs(&vf)), "ok").starts_with("funding verified and final"));
    // The buyer locks on the counterpart chain; the seller checks it and reveals.
    let lock = w.lock(&terms, Finality::Finalized, |_| {});
    let out = w.go(&[
        "verify-counterpart",
        "--terms",
        &terms,
        "--counterpart",
        &w.cp(),
        "--counterpart-final-secs",
        FINAL_SECS,
    ]);
    assert!(out.contains(&format!("counterpart lock: {}", hex(&lock.id))));
    // Reported done only at counterpart-final: submitted (seen), then confirmed, then final.
    let cc = w.cp_claim_args(&terms, &secret_path);
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    assert_eq!(w.claims(), 1);
    w.set_claims(Finality::Confirmed);
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    assert_eq!(w.claims(), 1, "a resubmission adds no second claim");
    w.set_claims(Finality::Finalized);
    let out = w.go(&strs(&cc));
    assert!(field(&out, "counterpart claim").contains("counterpart-final"));
    // The buyer reads the preimage at counterpart-final and claims the asset on Kaspa.
    let preimage_path = w.p("t.preimage");
    let out = w.go(&[
        "watch",
        "--terms",
        &terms,
        "--counterpart",
        &w.cp(),
        "--secret-out",
        &preimage_path,
    ]);
    assert!(field(&out, "preimage").contains("not shown"));
    #[cfg(unix)]
    assert_eq!(mode(&preimage_path), 0o600);
    assert_eq!(secret_hex(&preimage_path), secret);
    let unsigned = w.p("t.claim.ipst");
    let out = w.go(&strs(&w.claim_args(
        &terms,
        ["--secret-file", &preimage_path],
        &unsigned,
    )));
    assert_eq!(field(&out, "ipst"), "hashlock claim");
    let signed = w.p("t.claim.signed");
    w.sign_as(&unsigned, &terms, &w.payer, "payer", &signed);
    let out = w.submit(&signed);
    let txid = field(&out, "submitted");
    let from = field(&out, "from_block");
    // The delivery is at the buyer's key.
    let delivered = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: w.buyer.signer,
        },
        AMOUNT,
    );
    assert_eq!(
        w.sim
            .state
            .borrow()
            .utxos_at(&w.template.script_public_key(&delivered).unwrap())
            .len(),
        1
    );
    let status = |w: &World| w.go(&strs(&w.status_args(&terms, &txid, &from, true)));
    let out = status(&w);
    assert_eq!(
        field(&out, "transaction"),
        "claim (settleWithPreimage, delivery to buyer_delivery)"
    );
    assert!(field(&out, "kaspa").starts_with("accepted"));
    assert_eq!(field(&out, "trade"), "not complete");
    // D18 is 600 DAA: one score short is still only accepted, then it is final.
    assert_eq!(FINALITY_DEPTH_DAA, 600);
    let base = w.daa();
    w.set_daa(base + FINALITY_DEPTH_DAA - 1);
    assert!(field(&status(&w), "kaspa").starts_with("accepted"));
    w.set_daa(base + FINALITY_DEPTH_DAA);
    let out = status(&w);
    assert!(field(&out, "kaspa").starts_with("final"));
    assert!(field(&out, "trade").starts_with("complete"));
    // With the counterpart claim not final, the trade is not complete.
    w.set_claims(Finality::Confirmed);
    assert_eq!(field(&status(&w), "trade"), "not complete");
    // The secret and the preimage never appeared in any output, note or refusal.
    let seen = w.seen.borrow();
    assert!(!seen.contains(&secret), "the secret was printed");
    assert!(!seen.to_lowercase().contains(&secret));
}

#[test]
fn the_kaspa_claim_reads_the_preimage_from_the_counterpart_chain_in_any_finality_state() {
    let w = World::new();
    let terms = w.create("t");
    w.fund(&terms, "t");
    let out_path = w.p("c.ipst");
    let args = w.claim_args(&terms, ["--counterpart", &w.cp()], &out_path);
    // No lock yet, then a lock and no reveal.
    assert_eq!(w.no(&strs(&args)), "XCHAIN_COUNTERPART_MISMATCH");
    w.lock(&terms, Finality::Finalized, |_| {});
    assert_eq!(w.no(&strs(&args)), "XCHAIN_REVEAL_NOT_FOUND");
    // A claim with a wrong preimage is ignored.
    w.edit_counterpart(|v| {
        let lock = v["locks"][0]["id"].clone();
        v["claims"].as_array_mut().unwrap().push(json!({
            "id": hex(&[9; 32]), "lock": lock, "preimage": hex(&[7; 32]), "finality": "finalized"
        }));
    });
    assert_eq!(w.no(&strs(&args)), "XCHAIN_REVEAL_NOT_FOUND");
    w.no(&strs(&w.cp_claim_args(&terms, &w.p("t.secret"))));
    // The seller's reveal is seen only: the Kaspa claim still takes it.
    let out = w.go(&strs(&args));
    assert!(field(&out, "preimage").contains("(seen)"));
    let signed = w.p("c.signed");
    w.sign_as(&out_path, &terms, &w.payer, "payer", &signed);
    w.submit(&signed);
}

// =============================================================================================
// The funding, checked before the buyer locks; status bound to the trade
// =============================================================================================

const CASH_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-cash.json");

/// Outputs of a funding of trade `terms` with the escrow output holding `state` under
/// `template` and the asset's covenant, plus an authorizer at the vault when `authorizer`.
fn funding_outputs(
    w: &World,
    terms: &str,
    template: &Kcc20Template,
    state: Option<Kcc20State>,
    authorizer: bool,
) -> Vec<TransactionOutput> {
    let vault = HtlcVault::instantiate_existing(&w.terms(terms)).unwrap();
    let mut outputs = vec![];
    if let Some(state) = state {
        outputs.push(TransactionOutput {
            value: MIN_KCC20_OUTPUT,
            script_public_key: template.script_public_key(&state).unwrap(),
            covenant: Some(CovenantBinding::new(0, Hash::from_bytes(w.covenant))),
        });
    }
    if authorizer {
        outputs.push(TransactionOutput::new(
            MIN_KAS_OUTPUT,
            vault.script_public_key(),
        ));
    }
    outputs
}

fn vault_owned(w: &World, terms: &str, amount: u64) -> Kcc20State {
    let vault = HtlcVault::instantiate_existing(&w.terms(terms)).unwrap();
    Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        amount,
    )
}

/// spec/V2.md section 10.5, step 3: the buyer locks the counterpart amount only once `xchain
/// verify-funding` passes, which needs the vault's escrow (the asset's covenant and template,
/// owned by the vault's script hash, exactly the amount, not a minter) and an authorizer, both
/// created by the named transaction, unspent and at final depth. Every short or wrong funding
/// is refused even at final depth, so a seller cannot get the buyer to lock against an empty
/// or short vault.
#[test]
fn the_buyer_locks_only_after_verify_funding_passes_at_final_depth() {
    let w = World::new();
    let terms = w.create("t");
    let cash = Kcc20Template::from_json(CASH_JSON).unwrap();
    let key_owned = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: w.seller.signer,
        },
        AMOUNT,
    );
    let mut minter = vault_owned(&w, &terms, AMOUNT);
    minter.is_minter = true;
    let cases: Vec<(&str, Vec<TransactionOutput>)> = vec![
        (
            "no token",
            funding_outputs(&w, &terms, &w.template, None, true),
        ),
        (
            "amount - 1",
            funding_outputs(
                &w,
                &terms,
                &w.template,
                Some(vault_owned(&w, &terms, AMOUNT - 1)),
                true,
            ),
        ),
        (
            "amount + 1",
            funding_outputs(
                &w,
                &terms,
                &w.template,
                Some(vault_owned(&w, &terms, AMOUNT + 1)),
                true,
            ),
        ),
        (
            "key-owned token",
            funding_outputs(&w, &terms, &w.template, Some(key_owned), true),
        ),
        (
            "minter token",
            funding_outputs(&w, &terms, &w.template, Some(minter), true),
        ),
        (
            "token under another template",
            funding_outputs(
                &w,
                &terms,
                &cash,
                Some(vault_owned(&w, &terms, AMOUNT)),
                true,
            ),
        ),
        (
            "no authorizer",
            funding_outputs(
                &w,
                &terms,
                &w.template,
                Some(vault_owned(&w, &terms, AMOUNT)),
                false,
            ),
        ),
        (
            "an unrelated transaction",
            vec![TransactionOutput::new(
                MIN_KAS_OUTPUT,
                address_script(&p2pk_address(&w.payer.signer, Network::Testnet)),
            )],
        ),
    ];
    let mut injected = vec![];
    for (what, outputs) in cases {
        injected.push((what, w.accept(outputs)));
    }
    // A good funding of the same shape (no inputs) is accepted: the control.
    let good = w.accept(funding_outputs(
        &w,
        &terms,
        &w.template,
        Some(vault_owned(&w, &terms, AMOUNT)),
        true,
    ));
    w.set_daa(w.daa() + FINALITY_DEPTH_DAA);
    for (what, (txid, from)) in &injected {
        assert_eq!(
            w.no(&strs(&w.verify_funding_args(&terms, txid, from))),
            "HTLC_FUNDING",
            "{what}"
        );
    }
    let out = w.go(&strs(&w.verify_funding_args(&terms, &good.0, &good.1)));
    assert_eq!(
        field(&out, "escrow"),
        format!("{}:0 ({AMOUNT} units, owned by the vault, unspent)", good.0)
    );
    assert_eq!(field(&out, "authorizer"), format!("{}:1 (unspent)", good.0));
    assert!(field(&out, "kaspa").starts_with("final"));
    // A transaction the node never accepted, and another asset template given.
    assert_eq!(
        w.no(&strs(&w.verify_funding_args(
            &terms,
            &hex(&[7; 32]),
            &good.1
        ))),
        "CLI_TX_NOT_ACCEPTED"
    );
    let mut other_tpl = w.verify_funding_args(&terms, &good.0, &good.1);
    std::fs::write(w.path("cash.json"), CASH_JSON).unwrap();
    other_tpl[6] = w.p("cash.json");
    assert_eq!(w.no(&strs(&other_tpl)), "TX_TOKEN_TEMPLATE");
}

/// A funding whose escrow is spent no longer passes: the buyer would lock against nothing.
#[test]
fn verify_funding_refuses_a_spent_escrow() {
    let w = World::new();
    let terms = w.create("t");
    let funded = w.fund(&terms, "t");
    let vf = w.verify_funding_args(
        &terms,
        &field(&funded, "submitted"),
        &field(&funded, "from_block"),
    );
    w.set_daa(w.daa() + FINALITY_DEPTH_DAA);
    w.go(&strs(&vf));
    // The buyer sends the asset home (the buyer's refund, with the token).
    let unsigned = w.p("b.ipst");
    w.go(&[
        "refund",
        "--terms",
        &terms,
        "--node",
        NODE,
        "--signer",
        "buyer",
        "--asset-template",
        &w.tpl(),
        "--pay-from",
        &w.addr(&w.buyer),
        DECLARE[0],
        DECLARE[1],
        "--out",
        &unsigned,
    ]);
    let signed = w.p("b.signed");
    w.sign_as(&unsigned, &terms, &w.buyer, "buyer", &signed);
    let refunded = w.submit(&signed);
    assert_eq!(w.no(&strs(&vf)), "CLI_UTXO_NOT_FOUND");
    // status reads the same funding as spent, and the refund as a refund: never complete.
    let out = w.go(&strs(&w.status_args(
        &terms,
        &field(&funded, "submitted"),
        &field(&funded, "from_block"),
        false,
    )));
    assert_eq!(field(&out, "transaction"), "funding (escrow spent)");
    assert_eq!(field(&out, "trade"), "not complete");
    w.lock(&terms, Finality::Finalized, |_| {});
    w.no(&strs(&w.cp_claim_args(&terms, &w.p("t.secret"))));
    w.set_claims(Finality::Finalized);
    w.set_daa(w.daa() + FINALITY_DEPTH_DAA);
    let out = w.go(&strs(&w.status_args(
        &terms,
        &field(&refunded, "submitted"),
        &field(&refunded, "from_block"),
        true,
    )));
    assert_eq!(field(&out, "transaction"), "refund");
    assert!(field(&out, "kaspa").starts_with("final"));
    assert!(field(&out, "counterpart claim").starts_with("counterpart-final"));
    assert_eq!(field(&out, "trade"), "not complete");
}

/// status reports only a transaction of this trade: the funding of its vault or a spend of it.
/// An unrelated accepted transaction is refused, even with a final counterpart claim beside it,
/// so `trade: complete` never stands on another transaction.
#[test]
fn status_refuses_a_transaction_that_is_not_part_of_this_trade() {
    let w = World::new();
    let terms = w.create("t");
    let funded = w.fund(&terms, "t");
    w.lock(&terms, Finality::Finalized, |_| {});
    w.no(&strs(&w.cp_claim_args(&terms, &w.p("t.secret"))));
    w.set_claims(Finality::Finalized);
    let unrelated = w.accept(vec![TransactionOutput::new(
        MIN_KAS_OUTPUT,
        address_script(&p2pk_address(&w.payer.signer, Network::Testnet)),
    )]);
    // Another trade's vault, funded in the same shape: not this trade's either.
    let other = w.create("u");
    let other_funding = w.accept(funding_outputs(
        &w,
        &other,
        &w.template,
        Some(vault_owned(&w, &other, AMOUNT)),
        true,
    ));
    w.set_daa(w.daa() + FINALITY_DEPTH_DAA);
    for (txid, from) in [&unrelated, &other_funding] {
        for counterpart in [false, true] {
            assert_eq!(
                w.no(&strs(&w.status_args(&terms, txid, from, counterpart))),
                "XCHAIN_TX_UNRELATED"
            );
        }
    }
    // The control: the trade's own funding, final, with the counterpart claim final, is
    // reported as the funding and the trade is not complete (only the claim completes it).
    let out = w.go(&strs(&w.status_args(
        &terms,
        &field(&funded, "submitted"),
        &field(&funded, "from_block"),
        true,
    )));
    assert_eq!(field(&out, "transaction"), "funding (escrow unspent)");
    assert!(field(&out, "kaspa").starts_with("final"));
    assert_eq!(field(&out, "trade"), "not complete");
    // A short funding of this vault is refused by status as by verify-funding.
    let short = w.accept(funding_outputs(
        &w,
        &terms,
        &w.template,
        Some(vault_owned(&w, &terms, AMOUNT - 1)),
        true,
    ));
    assert_eq!(
        w.no(&strs(&w.status_args(&terms, &short.0, &short.1, true))),
        "HTLC_FUNDING"
    );
}

// =============================================================================================
// R13, R2 and the counterpart checks
// =============================================================================================

#[test]
fn the_seller_reveals_only_after_checking_the_buyers_lock() {
    let w = World::new();
    let terms = w.create("t");
    let cc = w.cp_claim_args(&terms, &w.p("t.secret"));
    // No lock with this hash lock.
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_COUNTERPART_MISMATCH");
    // A lock that differs in one field, or is not funded, is not the agreed lock.
    for (name, edit) in [
        (
            "htlc_program",
            Box::new(|l: &mut Lock| l.htlc_program[0] ^= 1) as Box<dyn Fn(&mut Lock)>,
        ),
        ("asset", Box::new(|l: &mut Lock| l.asset[0] ^= 1)),
        ("amount", Box::new(|l: &mut Lock| l.amount -= 1)),
        ("recipient", Box::new(|l: &mut Lock| l.recipient[0] ^= 1)),
        ("refund", Box::new(|l: &mut Lock| l.refund[0] ^= 1)),
        ("timeout", Box::new(|l: &mut Lock| l.timeout += 1)),
        ("funded", Box::new(|l: &mut Lock| l.funded = false)),
    ] {
        w.edit_counterpart(|v| v["locks"] = json!([]));
        w.lock(&terms, Finality::Finalized, |l| edit(l));
        let (r, out) = w.exec(&strs(&cc));
        let e = r.expect_err(name);
        assert_eq!(
            (e.code(), out.as_str()),
            ("XCHAIN_COUNTERPART_MISMATCH", "")
        );
        assert!(e.detail().contains(name), "{name}: {e}");
        assert_eq!(w.claims(), 0, "{name}: nothing revealed");
    }
    // Another chain ID.
    w.edit_counterpart(|v| v["locks"] = json!([]));
    w.lock(&terms, Finality::Finalized, |_| {});
    w.edit_counterpart(|v| v["chain_id"] = json!(hex(&[1; 32])));
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_COUNTERPART_MISMATCH");
    w.edit_counterpart(|v| v["chain_id"] = json!(hex(&w.chain_id)));
    // The agreed lock not yet counterpart-final.
    w.edit_counterpart(|v| v["locks"][0]["finality"] = json!("confirmed"));
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    let vc = [
        "verify-counterpart",
        "--terms",
        &terms,
        "--counterpart",
        &w.cp(),
        "--counterpart-final-secs",
        FINAL_SECS,
    ];
    assert_eq!(w.no(&vc), "XCHAIN_NOT_FINAL");
    assert_eq!(w.claims(), 0);
    // Control: counterpart-final, and the claim is submitted.
    w.edit_counterpart(|v| v["locks"][0]["finality"] = json!("finalized"));
    w.go(&vc);
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    assert_eq!(w.claims(), 1);
    // Another source than the fake one does not exist in this build.
    let mut other = cc.clone();
    other[6] = "https://counterpart.invalid".into();
    assert_eq!(w.no(&strs(&other)), "XCHAIN_CHAIN_UNSUPPORTED");
}

#[test]
fn the_first_reveal_is_refused_inside_the_claim_lead_r2() {
    let w = World::new();
    let terms = w.create("t");
    w.lock(&terms, Finality::Finalized, |_| {});
    let t = w.terms(&terms);
    let latest = t.terms().counterpart.timeout - super::delta_claim(60);
    let cc = w.cp_claim_args(&terms, &w.p("t.secret"));
    w.edit_counterpart(|v| v["now"] = json!((latest + 1).to_string()));
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_MARGIN_TOO_SHORT");
    assert_eq!(w.claims(), 0, "nothing revealed");
    // Control: exactly at the latest reveal time.
    w.edit_counterpart(|v| v["now"] = json!(latest.to_string()));
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    assert_eq!(w.claims(), 1);
    // A resubmission reveals nothing new, so it is not refused after the lead.
    w.edit_counterpart(|v| v["now"] = json!((latest + 100).to_string()));
    assert_eq!(w.no(&strs(&cc)), "XCHAIN_NOT_FINAL");
    // Δ_claim: two hours at least, else ten times the counterpart's finality.
    assert_eq!(super::delta_claim(60), 7_200);
    assert_eq!(super::delta_claim(721), 7_210);
}

#[test]
fn the_secret_file_is_read_only_from_a_private_file_of_the_right_form() {
    let w = World::new();
    let terms = w.create("t");
    w.lock(&terms, Finality::Finalized, |_| {});
    let secret = secret_hex(&w.p("t.secret"));
    let try_file = |name: &str, content: &str, mode: u32| {
        let p = w.path(name);
        crate::signing::throwaway::write_file(&p, content.as_bytes(), mode);
        let (r, out) = w.exec(&strs(&w.cp_claim_args(&terms, s(&p))));
        let e = r.expect_err(name);
        assert_eq!(out, "");
        assert!(
            !e.detail().contains(&secret),
            "{name}: content in the message"
        );
        e.code()
    };
    #[cfg(unix)]
    assert_eq!(try_file("open", &secret, 0o644), "XCHAIN_SECRET_FILE");
    assert_eq!(
        try_file("short", &secret[..62], 0o600),
        "XCHAIN_SECRET_FILE"
    );
    assert_eq!(
        try_file("upper", &secret.to_uppercase(), 0o600),
        "XCHAIN_SECRET_FILE"
    );
    assert_eq!(
        try_file("two", &format!("{secret}\n\n"), 0o600),
        "XCHAIN_SECRET_FILE"
    );
    assert_eq!(
        try_file("other", &hex(&[3; 32]), 0o600),
        "HTLC_SECRET_MISMATCH"
    );
    let dir = w.path("dir");
    std::fs::create_dir(&dir).unwrap();
    assert_eq!(
        w.no(&strs(&w.cp_claim_args(&terms, s(&dir)))),
        "XCHAIN_SECRET_FILE"
    );
    // Control: the same content without a final line feed is the secret.
    assert_eq!(try_file("bare", &secret, 0o600), "XCHAIN_NOT_FINAL");
}

#[test]
fn watch_reports_the_reveal_only_at_counterpart_final() {
    let w = World::new();
    let terms = w.create("t");
    let out_path = w.p("w.preimage");
    let args = [
        "watch",
        "--terms",
        &terms,
        "--counterpart",
        &w.cp(),
        "--secret-out",
        &out_path,
    ];
    assert_eq!(w.no(&args), "XCHAIN_COUNTERPART_MISMATCH");
    w.lock(&terms, Finality::Finalized, |_| {});
    assert_eq!(w.no(&args), "XCHAIN_REVEAL_NOT_FOUND");
    w.no(&strs(&w.cp_claim_args(&terms, &w.p("t.secret"))));
    assert_eq!(w.no(&args), "XCHAIN_NOT_FINAL");
    assert!(
        !Path::new(&out_path).exists(),
        "nothing written before final"
    );
    w.set_claims(Finality::Finalized);
    w.go(&args);
    assert_eq!(secret_hex(&out_path), secret_hex(&w.p("t.secret")));
    assert_eq!(w.no(&args), "CLI_OUTPUT_EXISTS");
}

// =============================================================================================
// R8, the node's blocks-per-second, the mainnet gate
// =============================================================================================

#[test]
fn a_hash_lock_serves_one_trade_r8() {
    let w = World::new();
    let a = w.create("a");
    let b = w.create("b");
    let (ta, tb) = (w.terms(&a), w.terms(&b));
    assert_ne!(
        ta.terms().hash_lock,
        tb.terms().hash_lock,
        "a fresh secret per trade"
    );
    let known = std::fs::read_to_string(w.path("seller.known")).unwrap();
    assert_eq!(known.lines().count(), 2);
    // The buyer verifies a trade twice: the same trade, accepted.
    w.go(&strs(&w.verify_args(&a)));
    w.go(&strs(&w.verify_args(&a)));
    assert_eq!(
        std::fs::read_to_string(w.path("buyer.known"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    // Other terms with a hash lock this installation knows: refused.
    let mut reused = ta.terms().clone();
    reused.nonce ^= 1;
    let reused = reused.validate_structure().unwrap();
    let p = w.path("reused.terms");
    std::fs::write(&p, doc::render_terms_file(&reused)).unwrap();
    assert_eq!(w.no(&strs(&w.verify_args(s(&p)))), "XCHAIN_HASH_REUSED");
    // xchain new checks the seller's own record the same way.
    assert!(doc::check_known(
        &w.path("seller.known"),
        &ta.terms().hash_lock,
        &ta.terms_hash()
    )
    .unwrap());
    assert_eq!(
        doc::check_known(
            &w.path("seller.known"),
            &ta.terms().hash_lock,
            &reused.terms_hash()
        )
        .unwrap_err()
        .code(),
        "XCHAIN_HASH_REUSED"
    );
    // A malformed record is refused, not ignored.
    std::fs::write(w.path("bad.known"), "nonsense\n").unwrap();
    let mut args = w.verify_args(&b);
    let at = args.iter().position(|x| x == "--known-hashes").unwrap();
    args[at + 1] = w.p("bad.known");
    assert_eq!(w.no(&strs(&args)), "CLI_FILE_READ");
}

#[test]
fn a_node_at_another_blocks_per_second_is_refused() {
    let info = |name: &str| ServerInfo {
        network: Some(Network::Testnet),
        network_name: name.into(),
        synced: true,
    };
    assert_eq!(super::node_bps(&info("testnet-10")), Some(10));
    assert_eq!(super::node_bps(&info("mainnet")), Some(10));
    assert_eq!(super::node_bps(&info("testnet-11")), None);
    assert_eq!(super::node_bps(&info("devnet")), None);
    assert_eq!(super::node_bps(&info("nonsense")), None);
    let w = World::new();
    let terms = w.create("t");
    let draft = w.draft("d2.draft", now() + 3 * HOURS, |_| {});
    *w.rename.borrow_mut() = Some("testnet-11");
    assert_eq!(w.no(&strs(&w.new_args(&draft, "d2"))), "XCHAIN_NODE_BPS");
    assert_eq!(w.no(&strs(&w.verify_args(&terms))), "XCHAIN_NODE_BPS");
    assert_eq!(
        w.no(&strs(&w.claim_args(
            &terms,
            ["--secret-file", &w.p("t.secret")],
            &w.p("x")
        ))),
        "XCHAIN_NODE_BPS"
    );
    assert_eq!(
        w.no(&["daa-sample", "--node", NODE, "--file", &w.p("sample")]),
        "XCHAIN_NODE_BPS"
    );
    // Control: a node reporting testnet-10.
    *w.rename.borrow_mut() = Some("testnet-10");
    w.go(&strs(&w.new_args(&draft, "d2")));
}

/// The hashlock mainnet gate is lifted (D39 b, D40): mainnet commands run under the value cap.
/// Above the cap without `--i-accept-the-risk` the trade is refused; within it the trade is made
/// and the race R2 notice is printed on stderr.
#[test]
fn mainnet_runs_under_the_value_cap() {
    let w = World::on(Network::Mainnet);
    let sample = w.write_mainnet_sample();
    let tc = now() + 3 * HOURS;
    let args_for = |name: &str, kas: &str| {
        let d = w.draft(&format!("{name}.draft"), tc, |_| {});
        let mut args = w.new_args(&d, name);
        let at = args.iter().position(|x| x == DECLARE[0]).unwrap();
        args[at + 1] = kas.into();
        args.extend(["--daa-sample".to_string(), sample.clone()]);
        args
    };
    // (a) Above the 10 KAS cap, no acceptance: refused, nothing written.
    assert_eq!(
        w.no(&strs(&args_for("big", "1000000001"))),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    assert!(!w.path("big.secret").exists());
    assert!(!w.path("big.terms").exists());
    // (b) Within the cap: accepted on mainnet.
    w.go(&strs(&args_for("ok", "1000000000")));
    assert!(w.path("ok.terms").exists());
    assert!(w.path("ok.secret").exists());
    assert!(
        w.seen.borrow().contains(super::MAINNET_R2_NOTICE),
        "the R2 notice is printed"
    );
    // The read-only sample too.
    let file = w.p("sample");
    let out = w.go(&["daa-sample", "--node", NODE, "--file", &file]);
    assert!(field(&out, "sample").contains("(mainnet, read only)"));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with("impulse-daa-sample 1 mainnet bps 10\n"));
}

// =============================================================================================
// xchain new and verify: their checks, in order, and nothing written on a refusal
// =============================================================================================

#[test]
fn new_checks_the_draft_the_role_and_the_margins_before_writing_anything() {
    let w = World::new();
    let tc = now() + 3 * HOURS;
    let refuse =
        |name: &str, tc: u64, edit: &dyn Fn(&mut Value), extra: &dyn Fn(&mut Vec<String>)| {
            let d = w.draft(&format!("{name}.draft"), tc, |v| edit(v));
            let mut args = w.new_args(&d, name);
            extra(&mut args);
            let code = w.no(&strs(&args));
            assert!(!w.path(&format!("{name}.secret")).exists(), "{name}");
            assert!(!w.path(&format!("{name}.terms")).exists(), "{name}");
            assert!(!w.path("seller.known").exists(), "{name}: nothing recorded");
            code
        };
    let none = |_: &mut Vec<String>| {};
    let set = |flag: &'static str, value: String| {
        move |a: &mut Vec<String>| {
            let at = a.iter().position(|x| x == flag).unwrap();
            a[at + 1] = value.clone();
        }
    };
    assert_eq!(
        refuse("h", tc, &|v| v["hash_lock"] = json!(hex(&[1; 32])), &none),
        "CLI_TERMS_JSON"
    );
    assert_eq!(
        refuse("k", tc, &|_| {}, &set("--my-key", hex(&w.buyer.signer))),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        refuse(
            "r",
            tc,
            &|v| v["seller_refund"]["identifier"] = json!(hex(&w.buyer.signer)),
            &none
        ),
        "CLI_DESTINATION_NOT_MINE"
    );
    assert_eq!(
        refuse(
            "a",
            tc,
            &|_| {},
            &set("--my-counterpart-account", hex(&[5; 32]))
        ),
        "CLI_DESTINATION_NOT_MINE"
    );
    assert_eq!(
        refuse("z", tc, &|v| v["counterpart"]["amount"] = json!("0"), &none),
        "HTLC_COUNTERPART"
    );
    // A pin does not make the counterparty's key the seller's own refund.
    let buyer_pin = format!("kcc20:pubkey:{}", hex(&w.buyer.signer));
    assert_eq!(
        refuse(
            "p",
            tc,
            &|v| v["seller_refund"]["identifier"] = json!(hex(&w.buyer.signer)),
            &|a: &mut Vec<String>| {
                a.push("--my-refund".into());
                a.push(buyer_pin.clone());
            }
        ),
        "CLI_DESTINATION_NOT_MINE"
    );
    // A pinned script-hash refund is the seller's when it equals the pin.
    let d =
        w.draft(
            "pin.draft",
            tc,
            |v| {
                v["seller_refund"] =
                    json!({"identifier_type": "script_hash", "identifier": hex(&[6; 32])})
            },
        );
    let mut a = w.new_args(&d, "pin");
    a.push("--my-refund".into());
    a.push(format!("kcc20:script_hash:{}", hex(&[6; 32])));
    let out = w.go(&strs(&a));
    assert!(out.contains("seller_refund: equals its pin --my-refund"));
    std::fs::remove_file(w.path("seller.known")).unwrap();
    // A KCC-20 template that is not a pinned kcc20.sil build.
    assert_eq!(
        refuse(
            "u",
            tc,
            &|v| v["asset_leg"]["template_hash"] = json!(hex(&[8; 32])),
            &none
        ),
        "CLI_TEMPLATE_UNPINNED"
    );
    // The counterpart timeout too close for the seller's reveal.
    assert_eq!(
        refuse("c", now() + HOURS, &|_| {}, &none),
        "XCHAIN_MARGIN_TOO_SHORT"
    );
    // expiry_daa too close to the counterpart timeout.
    assert_eq!(
        refuse(
            "e",
            tc,
            &|v| v["expiry_daa"] = json!((START_DAA + 200_000).to_string()),
            &none
        ),
        "HTLC_TIMEOUT_MARGIN"
    );
    // A declared 0 is no declaration.
    assert_eq!(
        refuse("v", tc, &|_| {}, &set(DECLARE[0], "0".into())),
        "CLI_VALUE_UNKNOWN"
    );
    assert_eq!(
        refuse("v2", tc, &|_| {}, &set(DECLARE[0], "1000000001".into())),
        "CLI_VALUE_CAP_EXCEEDED"
    );
    // An existing output: nothing else is written, and the hash lock is not recorded.
    std::fs::write(w.path("o.terms"), "x").unwrap();
    let d = w.draft("o.draft", tc, |_| {});
    assert_eq!(w.no(&strs(&w.new_args(&d, "o"))), "CLI_OUTPUT_EXISTS");
    assert!(!w.path("o.secret").exists());
    assert!(!w.path("seller.known").exists());
    // Control.
    let d = w.draft("ok.draft", tc, |_| {});
    let (r, out) = w.exec(&strs(&w.new_args(&d, "ok")));
    r.unwrap();
    assert!(field(&out, "secret").ends_with("(mode 0600); not shown"));
    assert!(field(&out, "exchange").contains("not atomic settlement"));
    assert!(out.contains("role check: seller, seller_refund: pays --my-key"));
    assert!(field(&out, "vault").starts_with("kaspatest:"));
    let notes = w.seen.borrow();
    assert!(notes.contains("R12"));
}

#[test]
fn verify_checks_the_buyers_side() {
    let w = World::new();
    let terms = w.create("t");
    let refuse = |edit: &dyn Fn(&mut Vec<String>)| {
        let mut a = w.verify_args(&terms);
        edit(&mut a);
        w.no(&strs(&a))
    };
    let set = |flag: &'static str, value: String| {
        move |a: &mut Vec<String>| {
            let at = a.iter().position(|x| x == flag).unwrap();
            a[at + 1] = value.clone();
        }
    };
    assert_eq!(
        refuse(&set("--my-key", hex(&w.seller.signer))),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        refuse(&set("--my-counterpart-account", hex(&w.seller_account))),
        "CLI_DESTINATION_NOT_MINE"
    );
    // A delivery pin that is not the terms' delivery.
    assert_eq!(
        refuse(&|a: &mut Vec<String>| {
            a.push("--my-delivery".into());
            a.push(format!("kcc20:script_hash:{}", hex(&[4; 32])));
        }),
        "CLI_DESTINATION_NOT_MINE"
    );
    // Past the creation window: the expiry is near.
    w.set_daa(START_DAA + EXPIRY_IN - 1_000);
    assert_eq!(refuse(&|_| {}), "HTLC_TIMEOUT_MARGIN");
    w.set_daa(START_DAA);
    // A terms file for mainnet on a testnet command, and a v1 terms file.
    let v1 = crate::terms_file::tests::vector_file("01");
    let p = w.path("v1.terms");
    std::fs::write(&p, v1).unwrap();
    let mut a = w.verify_args(s(&p));
    a.truncate(a.len());
    assert_eq!(w.no(&strs(&a)), "CLI_TERMS_JSON");
}

// =============================================================================================
// The Kaspa claim's time left, and refunds
// =============================================================================================

#[test]
fn the_kaspa_claim_needs_the_retry_window_unless_past_margin_is_given() {
    let w = World::new();
    let terms = w.create("t");
    w.fund(&terms, "t");
    let t = w.terms(&terms);
    // 1,000 DAA before expiry is 50 s at DAA_RATE_MAX (testnet, 20 per second).
    w.set_daa(t.terms().expiry_daa - 1_000);
    let out = w.p("late.ipst");
    let args = w.claim_args(&terms, ["--secret-file", &w.p("t.secret")], &out);
    assert_eq!(w.no(&strs(&args)), "XCHAIN_MARGIN_TOO_SHORT");
    let mut past = args.clone();
    past.push("--past-margin".into());
    let printed = w.go(&strs(&past));
    assert!(field(&printed, "warning").contains("R4"));
    // After expiry the claim is still valid (R4) and the node takes it.
    w.set_daa(t.terms().expiry_daa + 10);
    let signed = w.p("late.signed");
    w.sign_as(&out, &terms, &w.payer, "payer", &signed);
    w.submit(&signed);
    // Control: with time left, no warning.
    let w2 = World::new();
    let terms2 = w2.create("t");
    w2.fund(&terms2, "t");
    let o = w2.go(&strs(&w2.claim_args(
        &terms2,
        ["--secret-file", &w2.p("t.secret")],
        &w2.p("c.ipst"),
    )));
    assert!(!o.contains("warning:"));
}

/// A funded mainnet trade (sample-backed creation and funding), for the recovery tests below.
fn funded_mainnet(w: &World, sample: &str) -> String {
    let d = w.draft("m.draft", now() + 3 * HOURS, |_| {});
    let mut args = w.new_args(&d, "m");
    args.extend(["--daa-sample".to_string(), sample.to_string()]);
    w.go(&strs(&args));
    let terms = w.p("m.terms");
    let unsigned = w.p("m.fund.ipst");
    let mut fund: Vec<String> = [
        "fund",
        "build",
        "--terms",
        &terms,
        "--node",
        NODE,
        "--my-key",
        &hex(&w.seller.signer),
        "--counterpart-final-secs",
        FINAL_SECS,
        "--pay-from",
        &w.addr(&w.seller),
        "--asset-template",
        &w.tpl(),
        "--token",
        &w.seller_token,
        DECLARE[0],
        DECLARE[1],
        "--daa-sample",
        sample,
        "--out",
        &unsigned,
    ]
    .map(String::from)
    .to_vec();
    w.go(&strs(&fund));
    // Over the cap, funding is still refused: new value does not enter.
    let at = fund.iter().position(|x| x == DECLARE[0]).unwrap();
    fund[at + 1] = "1000000001".into();
    let last = fund.len() - 1;
    fund[last] = w.p("m.fund.big");
    assert_eq!(w.no(&strs(&fund)), "CLI_VALUE_CAP_EXCEEDED");
    let signed = w.p("m.fund.signed");
    w.go(&[
        "sign",
        "--ipst",
        &unsigned,
        "--terms",
        &terms,
        "--key-file",
        s(&w.seller.path),
        "--role",
        "seller",
        "--my-key",
        &hex(&w.seller.signer),
        "--node",
        NODE,
        "--asset-template",
        &w.tpl(),
        "--counterpart-final-secs",
        FINAL_SECS,
        "--daa-sample",
        sample,
        DECLARE[0],
        DECLARE[1],
        "--out",
        &signed,
    ]);
    w.submit(&signed);
    terms
}

/// R4: a mainnet claim after the seller revealed is never blocked by the DAA sample. The time left
/// is advice only; with no sample, a stale one or an unreadable one, the pinned worst case is used
/// and a warning is noted. Creation and verify keep the strict sample rule.
#[test]
fn a_mainnet_claim_never_blocks_on_the_daa_sample() {
    let w = World::on(Network::Mainnet);
    let sample = w.write_mainnet_sample();
    let terms = funded_mainnet(&w, &sample);
    // A sample that ended 40 days ago (older than 30 days), and one that is not a sample.
    let stale = {
        let end = now() - 40 * 86_400;
        let mut text = String::from("impulse-daa-sample 1 mainnet bps 10\n");
        let mut t = end - 8 * 86_400;
        while t <= end {
            text.push_str(&format!("{t} {}\n", 1_000_000_000 - (end - t) * 10));
            t += 300;
        }
        std::fs::write(w.path("stale.sample"), text).unwrap();
        w.p("stale.sample")
    };
    std::fs::write(w.path("bad.sample"), "not a sample\n").unwrap();
    let t = w.terms(&terms);
    let cases: [(&str, Option<&str>); 4] = [
        ("none", None),
        ("stale", Some(&stale)),
        ("bad", Some(&w.p("bad.sample"))),
        ("good", Some(&sample)),
    ];
    for past in [false, true] {
        for (name, file) in cases {
            let _ = std::fs::remove_file(w.path("c.ipst"));
            let mut args =
                w.claim_args(&terms, ["--secret-file", &w.p("m.secret")], &w.p("c.ipst"));
            if let Some(f) = file {
                args.extend(["--daa-sample".to_string(), f.to_string()]);
            }
            if past {
                args.push("--past-margin".into());
            }
            w.set_daa(t.terms().expiry_daa - 100_000);
            let before = w.seen.borrow().len();
            let printed = w.go(&strs(&args));
            assert_eq!(field(&printed, "ipst"), "hashlock claim", "{name} {past}");
            let new_text = w.seen.borrow()[before..].to_string();
            assert_eq!(
                new_text.contains("warning: the DAA rate sample"),
                file != Some(&sample),
                "{name} {past}: {new_text}"
            );
        }
    }
    // Close to expiry with no sample: the retry-window rule still applies, from the pinned rate.
    w.set_daa(t.terms().expiry_daa - 1_000);
    let mut args = w.claim_args(&terms, ["--secret-file", &w.p("m.secret")], &w.p("d.ipst"));
    assert_eq!(w.no(&strs(&args)), "XCHAIN_MARGIN_TOO_SHORT");
    args.push("--past-margin".into());
    w.go(&strs(&args));
    // Verification stays strict: verify without a sample is still refused on mainnet.
    assert_eq!(w.no(&strs(&w.verify_args(&terms))), "HTLC_DAA_SAMPLE");
}

/// The value cap guards new value only. Refund and claim of an already funded vault proceed over
/// the cap, without `--i-accept-the-risk`, and note a warning; funding over the cap is refused.
#[test]
fn recovery_is_not_value_capped_but_funding_is() {
    let w = World::on(Network::Mainnet);
    let sample = w.write_mainnet_sample();
    let terms = funded_mainnet(&w, &sample);
    let t = w.terms(&terms);
    let over = "1000000001";
    let mut claim = w.claim_args(&terms, ["--secret-file", &w.p("m.secret")], &w.p("oc.ipst"));
    let at = claim.iter().position(|x| x == DECLARE[0]).unwrap();
    claim[at + 1] = over.into();
    claim.extend(["--daa-sample".to_string(), sample.clone()]);
    w.set_daa(t.terms().expiry_daa - 100_000);
    let before = w.seen.borrow().len();
    let printed = w.go(&strs(&claim));
    assert_eq!(field(&printed, "ipst"), "hashlock claim");
    assert!(w.seen.borrow()[before..].contains("warning: the value cap"));
    let refund = |out: &str, extra: &[&str]| {
        let mut a: Vec<String> = [
            "refund",
            "--terms",
            &terms,
            "--node",
            NODE,
            "--signer",
            "buyer",
            "--asset-template",
            &w.tpl(),
            "--pay-from",
            &w.addr(&w.buyer),
            DECLARE[0],
            over,
            "--out",
            out,
        ]
        .map(String::from)
        .to_vec();
        a.extend(extra.iter().map(|x| x.to_string()));
        a
    };
    let before = w.seen.borrow().len();
    let printed = w.go(&strs(&refund(&w.p("or.ipst"), &[])));
    assert!(field(&printed, "ipst").starts_with("hashlock refund by buyer"));
    assert!(w.seen.borrow()[before..].contains("warning: the value cap"));
}

#[test]
fn refunds_seller_after_expiry_buyer_at_any_time() {
    let w = World::new();
    let terms = w.create("t");
    w.fund(&terms, "t");
    let t = w.terms(&terms);
    let refund = |w: &World, signer: &str, out: &str| {
        let k = if signer == "seller" {
            &w.seller
        } else {
            &w.buyer
        };
        let (tpl, addr) = (w.tpl(), w.addr(k));
        w.go(&[
            "refund",
            "--terms",
            &terms,
            "--node",
            NODE,
            "--signer",
            signer,
            "--asset-template",
            &tpl,
            "--pay-from",
            &addr,
            DECLARE[0],
            DECLARE[1],
            "--out",
            out,
        ])
    };
    // The buyer cannot refund without the token.
    let out = w.p("b0.ipst");
    let (r, _) = w.exec(&[
        "refund",
        "--terms",
        &terms,
        "--node",
        NODE,
        "--signer",
        "buyer",
        "--asset-template",
        &w.tpl(),
        "--without-token",
        "--pay-from",
        &w.addr(&w.buyer),
        DECLARE[0],
        DECLARE[1],
        "--out",
        &out,
    ]);
    assert_eq!(r.unwrap_err().code(), "TX_REFUND_SIGNER");
    // The seller's refund is built before expiry, and refused at submit until it.
    let seller_unsigned = w.p("s.ipst");
    let printed = refund(&w, "seller", &seller_unsigned);
    assert!(field(&printed, "ipst").starts_with("hashlock refund by seller, with the token"));
    let seller_signed = w.p("s.signed");
    w.sign_as(
        &seller_unsigned,
        &terms,
        &w.seller,
        "seller",
        &seller_signed,
    );
    assert_eq!(
        w.no(&[
            "submit",
            "--ipst",
            &seller_signed,
            "--node",
            NODE,
            "--asset-template",
            &w.tpl()
        ]),
        "CLI_TX_NOT_FINAL"
    );
    // The buyer sends the asset home at any time, with the token.
    let buyer_unsigned = w.p("b.ipst");
    refund(&w, "buyer", &buyer_unsigned);
    let buyer_signed = w.p("b.signed");
    w.sign_as(&buyer_unsigned, &terms, &w.buyer, "buyer", &buyer_signed);
    w.submit(&buyer_signed);
    // The seller's own refund now spends nothing that exists.
    w.set_daa(t.terms().expiry_daa + 1);
    let (r, _) = w.exec(&[
        "submit",
        "--ipst",
        &seller_signed,
        "--node",
        NODE,
        "--asset-template",
        &w.tpl(),
    ]);
    assert!(r.is_err());
    // A second trade: the seller refunds after expiry.
    let w2 = World::new();
    let terms2 = w2.create("t");
    w2.fund(&terms2, "t");
    let t2 = w2.terms(&terms2);
    let u = w2.p("s.ipst");
    let mut a = vec![
        "refund",
        "--terms",
        &terms2,
        "--node",
        NODE,
        "--signer",
        "seller",
        "--asset-template",
    ];
    let tpl = w2.tpl();
    let addr = w2.addr(&w2.seller);
    a.extend_from_slice(&[
        &tpl,
        "--pay-from",
        &addr,
        DECLARE[0],
        DECLARE[1],
        "--out",
        &u,
    ]);
    w2.go(&a);
    let sg = w2.p("s.signed");
    w2.sign_as(&u, &terms2, &w2.seller, "seller", &sg);
    w2.set_daa(t2.terms().expiry_daa + 1);
    w2.submit(&sg);
}

// =============================================================================================
// xchain sign
// =============================================================================================

#[test]
fn sign_checks_the_agreed_trade_the_role_and_what_the_signer_commits() {
    let w = World::new();
    let terms = w.create("t");
    let other = w.create("o");
    w.fund(&terms, "t");
    let unsigned = w.p("c.ipst");
    w.go(&strs(&w.claim_args(
        &terms,
        ["--secret-file", &w.p("t.secret")],
        &unsigned,
    )));
    let sign = |terms: &str, k: &KeyFile, role: &str, extra: &[&str]| {
        let out = w.p("x.signed");
        let _ = std::fs::remove_file(&out);
        let mut a = vec![
            "sign".to_string(),
            "--ipst".into(),
            unsigned.clone(),
            "--terms".into(),
            terms.into(),
            "--key-file".into(),
            s(&k.path).into(),
            "--role".into(),
            role.into(),
            "--my-key".into(),
            hex(&k.signer),
            "--node".into(),
            NODE.into(),
            "--asset-template".into(),
            w.tpl(),
            DECLARE[0].into(),
            DECLARE[1].into(),
            "--out".into(),
            out,
        ];
        a.extend(extra.iter().map(|x| x.to_string()));
        w.exec(&strs(&a))
    };
    let code = |r: (Result<(), CliError>, String)| {
        assert_eq!(r.1, "");
        r.0.unwrap_err().code()
    };
    assert_eq!(
        code(sign(&other, &w.payer, "payer", &[])),
        "CLI_IPST_TERMS_NOT_AGREED"
    );
    assert_eq!(
        code(sign(&terms, &w.payer, "seller", &[])),
        "CLI_ROLE_KEY_MISMATCH"
    );
    assert_eq!(
        code(sign(&terms, &w.seller, "payer", &[])),
        "CLI_ROLE_KEY_MISMATCH"
    );
    // The claim's only slots are the payer's fee inputs.
    assert_eq!(
        code(sign(&terms, &w.buyer, "buyer", &[])),
        "CLI_IPST_NOTHING_TO_SIGN"
    );
    assert_eq!(
        code(sign(
            &terms,
            &w.payer,
            "payer",
            &["--change", &w.addr(&w.buyer)]
        )),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
    assert_eq!(
        code(sign(&terms, &w.payer, "payer", &["--max-fee", "1"])),
        "CLI_IPST_FEE_TOO_HIGH"
    );
    // Control.
    let (r, out) = sign(&terms, &w.payer, "payer", &[]);
    r.unwrap();
    assert!(field(&out, "signed").starts_with("input 2"));
    assert_eq!(field(&out, "pending"), "complete");
    // A document of another version is refused by this reader, and this one by the v1 reader.
    let text = std::fs::read_to_string(&unsigned).unwrap();
    assert_eq!(
        doc::parse_ipst(&text.replacen("\"ipst\": 3", "\"ipst\": 1", 1))
            .unwrap_err()
            .code(),
        "IPST_UNSUPPORTED_VERSION"
    );
    assert_eq!(
        impulse_core::tx::Ipst::from_json(&text).unwrap_err().code(),
        "IPST_UNSUPPORTED_VERSION"
    );
    assert_eq!(
        doc::parse_ipst(&text.replacen("\"lock_time\"", "\"lock_time2\"", 1))
            .unwrap_err()
            .code(),
        "IPST_MALFORMED"
    );
    // The canonical form reads back to itself.
    let read = doc::parse_ipst(&text).unwrap();
    assert_eq!(doc::ipst_json(&read), text);
}

// =============================================================================================
// Files
// =============================================================================================

#[test]
fn the_terms_form_is_the_vectors_form() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/htlc");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let terms = doc::parse_terms_json(&v["terms"]).unwrap();
        let checked = terms.validate_structure().unwrap();
        assert_eq!(hex(checked.canonical()), v["canonical"].as_str().unwrap());
        assert_eq!(
            hex(&checked.terms_hash()),
            v["htlc_terms_hash"].as_str().unwrap()
        );
        // The JSON form written back is the vector's, key for key.
        let written: Value =
            serde_json::from_str(&doc::terms_json(checked.terms()).render()).unwrap();
        assert_eq!(written, v["terms"], "{}", path.display());
        let file = doc::render_terms_file(&checked);
        assert_eq!(doc::parse_terms_file(&file).unwrap(), checked);
        let tampered = file.replacen(
            &format!(
                "\"htlc_terms_hash\": \"{}",
                &hex(&checked.terms_hash())[..2]
            ),
            "\"htlc_terms_hash\": \"ff",
            1,
        );
        if tampered != file {
            assert_eq!(
                doc::parse_terms_file(&tampered).unwrap_err().code(),
                "CLI_TERMS_FILE_INCONSISTENT"
            );
        }
        n += 1;
    }
    assert_eq!(n, 5);
}

#[test]
fn the_daa_sample_file_grows_one_point_at_a_time() {
    let w = World::new();
    let file = w.p("sample");
    w.go(&["daa-sample", "--node", NODE, "--file", &file]);
    w.set_daa(START_DAA + 600);
    // The clock moves on by at least a second between two points.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    w.go(&["daa-sample", "--node", NODE, "--file", &file]);
    let sample = doc::read_sample(Path::new(&file), Network::Testnet).unwrap();
    assert_eq!(sample.bps, 10);
    assert_eq!(sample.points.len(), 2);
    assert_eq!(sample.points[1].1, START_DAA + 600);
    // A falling DAA score is refused; the file is unchanged.
    w.set_daa(START_DAA);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(
        w.no(&["daa-sample", "--node", NODE, "--file", &file]),
        "HTLC_DAA_SAMPLE"
    );
    assert_eq!(
        doc::read_sample(Path::new(&file), Network::Testnet)
            .unwrap()
            .points
            .len(),
        2
    );
    // A sample of another network.
    assert_eq!(
        doc::read_sample(Path::new(&file), Network::Mainnet)
            .unwrap_err()
            .code(),
        "HTLC_DAA_SAMPLE"
    );
    // A sample over its cap is refused, not read whole.
    let f = std::fs::File::create(w.path("big")).unwrap();
    f.set_len(doc::MAX_SAMPLE_FILE + 1).unwrap();
    let e = doc::read_sample(&w.path("big"), Network::Testnet).unwrap_err();
    assert_eq!(e.code(), "HTLC_DAA_SAMPLE");
    assert!(e.detail().contains("larger than"), "{e}");
    std::fs::write(w.path("bad"), "points\n1 2\n").unwrap();
    assert_eq!(
        doc::read_sample(&w.path("bad"), Network::Testnet)
            .unwrap_err()
            .code(),
        "HTLC_DAA_SAMPLE"
    );
}

#[test]
fn xchain_error_codes_are_frozen() {
    let v2 = include_str!("../../../spec/V2.md");
    let errors = include_str!("../../../spec/ERRORS.md");
    for code in super::XCHAIN_ERROR_CODES {
        assert!(
            v2.contains(&format!("`{code}`")),
            "{code} not in spec/V2.md"
        );
        assert!(
            errors.contains(&format!("`{code}`")),
            "{code} not in spec/ERRORS.md"
        );
    }
    let mut sorted = super::XCHAIN_ERROR_CODES.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), super::XCHAIN_ERROR_CODES.len());
}

#[test]
fn the_funding_is_the_sellers_and_is_signed_only_while_the_margin_holds() {
    let w = World::new();
    let terms = w.create("t");
    let out = w.p("f.ipst");
    let build = |pay_from: &str, key: &KeyFile| {
        w.exec(&[
            "fund",
            "build",
            "--terms",
            &terms,
            "--node",
            NODE,
            "--my-key",
            &hex(&key.signer),
            "--counterpart-final-secs",
            FINAL_SECS,
            "--pay-from",
            pay_from,
            "--asset-template",
            &w.tpl(),
            "--token",
            &w.seller_token,
            DECLARE[0],
            DECLARE[1],
            "--out",
            &out,
        ])
    };
    let code = |r: (Result<(), CliError>, String)| {
        assert_eq!(r.1, "");
        r.0.unwrap_err().code()
    };
    assert_eq!(
        code(build(&w.addr(&w.buyer), &w.buyer)),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    assert_eq!(
        code(build(&w.addr(&w.payer), &w.seller)),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    let (r, printed) = build(&w.addr(&w.seller), &w.seller);
    r.unwrap();
    assert_eq!(field(&printed, "ipst"), "hashlock fund");
    let sign = |k: &KeyFile, role: &str, extra: &[&str]| {
        let signed = w.p("f.signed");
        let _ = std::fs::remove_file(&signed);
        let mut a = vec![
            "sign".to_string(),
            "--ipst".into(),
            out.clone(),
            "--terms".into(),
            terms.clone(),
            "--key-file".into(),
            s(&k.path).into(),
            "--role".into(),
            role.into(),
            "--my-key".into(),
            hex(&k.signer),
            "--node".into(),
            NODE.into(),
            "--asset-template".into(),
            w.tpl(),
            DECLARE[0].into(),
            DECLARE[1].into(),
            "--out".into(),
            signed,
        ];
        a.extend(extra.iter().map(|x| x.to_string()));
        w.exec(&strs(&a))
    };
    let with_margin = ["--counterpart-final-secs", FINAL_SECS];
    assert_eq!(
        code(sign(&w.buyer, "buyer", &with_margin)),
        "CLI_FUND_NOT_YOUR_LEG"
    );
    // The margin rule runs again: without its input, and once the expiry is near.
    assert_eq!(code(sign(&w.seller, "seller", &[])), "HTLC_TIMEOUT_MARGIN");
    let t = w.terms(&terms);
    w.set_daa(t.terms().expiry_daa - 1_000);
    assert_eq!(
        code(sign(&w.seller, "seller", &with_margin)),
        "HTLC_TIMEOUT_MARGIN"
    );
    w.set_daa(START_DAA);
    // The deposit the seller expects.
    let mut other = with_margin.to_vec();
    other.extend_from_slice(&["--carrier", "300000000"]);
    assert_eq!(
        code(sign(&w.seller, "seller", &other)),
        "CLI_IPST_DEPOSIT_MISMATCH"
    );
    // Control.
    let (r, printed) = sign(&w.seller, "seller", &with_margin);
    r.unwrap();
    assert_eq!(field(&printed, "pending"), "complete");
}

// =============================================================================================
// The read-only Solana source, through the commands and the real HTTP transport (I11 live demo,
// I18). The cluster is the mock of xchain_solana_tests.rs behind a loopback socket.
// =============================================================================================

mod solana_source {
    use super::super::solana::b58;
    use super::super::solana::tests::{serve, Chain, Server, Spec};
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A mock cluster holding the buyer's HTLC for `terms`, as the record says (`tweak` edits it).
    fn cluster(
        w: &World,
        terms: &str,
        level: Finality,
        tweak: impl FnOnce(&mut Spec),
    ) -> (Spec, Chain) {
        let t = w.terms(terms);
        let c = &t.terms().counterpart;
        let mut spec = Spec {
            program: w.program,
            funder: w.buyer_account,
            mint: w.usdc,
            recipient: c.recipient,
            refund: c.refund,
            hash_lock: t.terms().hash_lock,
            amount: c.amount,
            timeout: c.timeout as i64,
            escrow_amount: c.amount,
            freeze_authority: None,
            frozen: false,
            level,
        };
        tweak(&mut spec);
        let chain = Chain {
            genesis: w.chain_id,
            time: now(),
            ..Chain::default()
        };
        (spec, chain)
    }

    fn url(server: &Server, w: &World, funder: bool) -> String {
        let f = if funder {
            format!("&funder={}", b58(&w.buyer_account))
        } else {
            String::new()
        };
        format!("solana+{}#program={}{f}", server.url, b58(&w.program))
    }

    fn vc(terms: &str, cp: &str) -> Vec<String> {
        [
            "verify-counterpart",
            "--terms",
            terms,
            "--counterpart",
            cp,
            "--counterpart-final-secs",
            FINAL_SECS,
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn verify_counterpart_reads_the_lock_and_stays_quiet_without_a_freeze_authority() {
        let w = World::new();
        let terms = w.create("t");
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |_| {});
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        let out = w.go(&strs(&vc(&terms, &url(&server, &w, false))));
        assert!(
            out.contains(&format!("counterpart lock: {}", b58(&spec.htlc()))),
            "{out}"
        );
        assert!(!out.contains("warning:"), "{out}");
        assert!(out.contains("ok: you may reveal"), "{out}");
    }

    #[test]
    fn verify_counterpart_warns_about_a_freeze_authority_before_the_ok() {
        let w = World::new();
        let terms = w.create("t");
        let fa: [u8; 32] = rand::random();
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |s| {
            s.freeze_authority = Some(fa)
        });
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        let out = w.go(&strs(&vc(&terms, &url(&server, &w, false))));
        let warning = format!(
            "warning: mint {} has a freeze authority, {}. It can freeze this HTLC's escrow so that neither claim nor refund moves it; you trust it not to.",
            b58(&w.usdc),
            b58(&fa)
        );
        let at = out.find(&warning).unwrap_or_else(|| panic!("{out}"));
        assert!(at < out.find("ok: you may reveal").unwrap(), "{out}");
    }

    #[test]
    fn a_frozen_escrow_is_refused_by_verify_counterpart_and_counterpart_claim() {
        let w = World::new();
        let terms = w.create("t");
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |s| {
            s.freeze_authority = Some(rand::random());
            s.frozen = true;
        });
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        let cp = url(&server, &w, false);
        assert_eq!(w.no(&strs(&vc(&terms, &cp))), "XCHAIN_COUNTERPART_MISMATCH");
        let cc = [
            "counterpart-claim",
            "--terms",
            &terms,
            "--secret-file",
            &w.p("t.secret"),
            "--counterpart",
            &cp,
            "--counterpart-final-secs",
            FINAL_SECS,
        ];
        assert_eq!(w.no(&cc), "XCHAIN_COUNTERPART_MISMATCH");
    }

    #[test]
    fn an_unfunded_or_unfinal_lock_is_refused() {
        let w = World::new();
        let terms = w.create("t");
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |s| s.escrow_amount -= 1);
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        assert_eq!(
            w.no(&strs(&vc(&terms, &url(&server, &w, false)))),
            "XCHAIN_COUNTERPART_MISMATCH"
        );
        let (spec, mut chain) = cluster(&w, &terms, Finality::Confirmed, |_| {});
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        assert_eq!(
            w.no(&strs(&vc(&terms, &url(&server, &w, false)))),
            "XCHAIN_NOT_FINAL"
        );
    }

    #[test]
    fn the_chain_must_be_the_one_in_the_record() {
        let w = World::new();
        let terms = w.create("t");
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |_| {});
        spec.install(&mut chain);
        chain.genesis = rand::random();
        let server = serve(Arc::new(Mutex::new(chain)));
        assert_eq!(
            w.no(&strs(&vc(&terms, &url(&server, &w, false)))),
            "XCHAIN_COUNTERPART_MISMATCH"
        );
    }

    #[test]
    fn the_buyer_reads_the_reveal_from_a_claimed_and_closed_lock() {
        let w = World::new();
        let terms = w.create("t");
        let secret_path = w.p("t.secret");
        let secret = crate::json::unhex(&secret_hex(&secret_path)).unwrap();
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |_| {});
        // The accounts are closed: only the buyer's open and the seller's claim remain.
        chain.txs.push(spec.open_tx(true, Finality::Finalized));
        let claim = spec.claim_tx(&secret, true, Finality::Confirmed);
        chain.txs.push(claim.clone());
        let chain = Arc::new(Mutex::new(chain));
        let server = serve(chain.clone());
        let preimage = w.p("t.preimage");
        let watch = |out: &str| -> Vec<String> {
            [
                "watch",
                "--terms",
                &terms,
                "--counterpart",
                &url(&server, &w, true),
                "--secret-out",
                out,
            ]
            .map(String::from)
            .to_vec()
        };
        // Without the funder the closed lock cannot be found.
        let mut blind = watch(&preimage);
        blind[4] = url(&server, &w, false);
        assert_eq!(w.no(&strs(&blind)), "XCHAIN_COUNTERPART_MISMATCH");
        // Confirmed is a reveal, not yet counterpart-final.
        assert_eq!(w.no(&strs(&watch(&preimage))), "XCHAIN_NOT_FINAL");
        assert!(!std::path::Path::new(&preimage).exists());
        // Counterpart-final: the preimage is written, never shown.
        chain.lock().unwrap().txs.last_mut().unwrap().level = Finality::Finalized;
        let out = w.go(&strs(&watch(&preimage)));
        assert!(
            out.contains(&format!(
                "reveal: claim {} counterpart-final",
                b58(&claim.signature)
            )),
            "{out}"
        );
        assert!(field(&out, "preimage").contains("not shown"));
        assert_eq!(secret_hex(&preimage), secret_hex(&secret_path));
        // The seller's own command reports it done, and cannot resubmit through this source.
        let out = w.go(&strs(&w.cp_claim_args_for(
            &terms,
            &secret_path,
            &url(&server, &w, true),
        )));
        assert!(
            field(&out, "counterpart claim").contains("counterpart-final"),
            "{out}"
        );
    }

    #[test]
    fn the_first_reveal_through_this_source_is_the_solana_tools_not_the_cli() {
        let w = World::new();
        let terms = w.create("t");
        let (spec, mut chain) = cluster(&w, &terms, Finality::Finalized, |_| {});
        spec.install(&mut chain);
        let server = serve(Arc::new(Mutex::new(chain)));
        let cc = w.cp_claim_args_for(&terms, &w.p("t.secret"), &url(&server, &w, false));
        // Nothing is revealed: the source is read-only.
        assert_eq!(w.no(&strs(&cc)), "XCHAIN_CHAIN_UNSUPPORTED");
    }
}
