// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse zk` in process. The offline commands run on the golden terms v3 vectors; the whole
//! list-gated settle (verify, settle build with a real proof, sign, submit) runs against the
//! in-memory fake node, which runs every submitted input in the pinned script engine. The proof
//! and the terms of that trade are those impulse-core commits beside its own end-to-end tests
//! (`impulse-core/src/zk/testdata`, made by `scripts/regen-zk-core-fixtures.sh`).
//!
//! Keys: the fee payer's key file is a throwaway made at run time in a temporary directory that
//! is removed; the parties of the proof-bound trade are label-derived public keys with no
//! private key anywhere, so that trade is self-settling. No key literal exists.

use crate::cli::{run, Cli, Env};
use crate::error::CliError;
use crate::funds::{address_script, p2pk_address};
use crate::json::hex;
use crate::node::Node;
use crate::signing::throwaway::{key_file, KeyFile};
use crate::sim::{SimNode, SimState};
use crate::testutil::TempDir;
use crate::zk_cmd::{parse_terms_v3_file, render_terms_v3_file, DISCLAIMER, GATE_LINE, SETUP_LINE};
use clap::Parser;
use impulse_core::template::LegIndex;
use impulse_core::terms::{IdentifierType, Kcc20Owner, Network};
use impulse_core::tx::{Kcc20State, Kcc20Template, MIN_KCC20_OUTPUT};
use impulse_core::zk::{IpstV3, TermsV3, ValidatedTermsV3, VaultV3};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const NODE: &str = "ws://127.0.0.1:17210";
const CORE_TESTDATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../impulse-core/src/zk/testdata"
);
const ASSET_JSON: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const ASSET_COV: [u8; 32] = [0xA5; 32];
/// The DAA score the proof-bound trade settles at: between its earliest and its expiry.
const NOW: u64 = 1_500_000;
const AUTHORIZER: u64 = 50_000_000;
const KAS_CASH: u64 = 100_000_000;
const DECLARE: [&str; 2] = ["--kas-equivalent", "100000000"];

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms_v3")
}

/// The terms v3 of a golden vector.
fn vector_terms(prefix: &str) -> (String, ValidatedTermsV3) {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vectors_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with(prefix))
        .collect();
    paths.sort();
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&paths[0]).unwrap()).unwrap();
    let file = serde_json::json!({
        "terms": doc["terms"],
        "canonical": doc["canonical"],
        "terms_hash": doc["terms_hash"],
    })
    .to_string();
    let terms = parse_terms_v3_file(&file).unwrap();
    (file, terms)
}

struct Sandbox {
    dir: TempDir,
    network: Network,
    sim: SimNode,
    max_value: Option<String>,
}

impl Sandbox {
    fn new(network: Network, daa: u64) -> Self {
        Self {
            dir: TempDir::new(),
            network,
            sim: SimNode::memory(SimState::new(network, daa, 0)),
            max_value: None,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    fn exec(&self, args: &[&str]) -> (Result<(), CliError>, String) {
        let mut argv = vec!["impulse"];
        if self.network == Network::Mainnet {
            argv.extend_from_slice(&["--network", "mainnet"]);
        }
        argv.push("zk");
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("arguments parse");
        let sim = self.sim.clone();
        let connect = move |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
            Ok(Box::new(sim.clone()))
        };
        let env = Env {
            max_value: self.max_value.as_deref().map(OsStr::new),
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

    /// A refused command: its code, after checking it printed nothing.
    fn refuse(&self, args: &[&str]) -> &'static str {
        let (r, out) = self.exec(args);
        let e = r.expect_err("refused");
        assert_eq!(out, "", "{} printed before refusing", e.code());
        e.code()
    }
}

// =============================================================================================
// Offline: lists, manifest
// =============================================================================================

fn pubkey_entry(label: u8) -> String {
    // The x coordinates of G, 2G and 3G: valid x-only keys with no private key anywhere.
    let xs = [
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    ];
    format!("pubkey:{}", xs[label as usize % 3])
}

#[test]
fn list_build_writes_a_root_and_one_path_file_per_entry() {
    let sb = Sandbox::new(Network::Testnet, 1);
    let list = sb.write(
        "list.txt",
        &format!(
            "# issuer list\n{}\n{}\nscripthash:{}\n",
            pubkey_entry(0),
            pubkey_entry(1),
            "22".repeat(32)
        ),
    );
    let dir = sb.path("paths");
    let out = sb.run(&["list", "build", "--list", s(&list), "--out-dir", s(&dir)]);
    assert!(out.contains("entries: 3"), "{out}");
    let root = out
        .lines()
        .find_map(|l| l.strip_prefix("list root: "))
        .unwrap()
        .to_string();
    assert_eq!(root.len(), 64);
    // One file per entry, mode 0600 in a directory of mode 0700; each leads to the root.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut roots = std::collections::BTreeSet::new();
    for i in 0..3 {
        let file = dir.join(format!("path-{i:07}.json"));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let path =
            crate::zk_cmd::parse_path_file(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(path.index, i);
        roots.insert(hex(&path.siblings[19]));
    }
    // Nothing the list or a salt holds is printed.
    assert!(!out.contains(&"22".repeat(32)));
    assert!(!out.contains("79be667e"));
    // The directory must not exist; a second run refuses and leaves the first alone.
    assert_eq!(
        sb.refuse(&["list", "build", "--list", s(&list), "--out-dir", s(&dir)]),
        "CLI_OUTPUT_EXISTS"
    );
}

#[test]
fn list_build_refuses_bad_lists() {
    let sb = Sandbox::new(Network::Testnet, 1);
    let bad = |name: &str, text: &str| {
        let list = sb.write(name, text);
        sb.refuse(&[
            "list",
            "build",
            "--list",
            s(&list),
            "--out-dir",
            s(&sb.path(&format!("out-{name}"))),
        ])
    };
    assert_eq!(bad("empty.txt", "# nothing\n"), "ZK_LIST_SIZE");
    assert_eq!(bad("junk.txt", "hello\n"), "ZK_LIST_ENTRY");
    assert_eq!(bad("short.txt", "pubkey:00\n"), "ZK_LIST_ENTRY");
    let mainnet = kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Mainnet,
        kaspa_addresses::Version::ScriptHash,
        &[3; 32],
    )
    .to_string();
    assert_eq!(
        bad("wrong-net.txt", &format!("{mainnet}\n")),
        "ZK_LIST_ENTRY"
    );
    // A refused list leaves no directory behind.
    assert!(!sb.path("out-junk.txt").exists());
}

#[test]
fn list_manifest_prints_the_digest_and_checks_a_signature() {
    let sb = Sandbox::new(Network::Testnet, 1);
    let root = "ab".repeat(32);
    let args = [
        "list",
        "manifest",
        "--root",
        root.as_str(),
        "--list-id",
        "fixture",
        "--list-version",
        "3",
        "--issued-at",
        "1760000000",
    ];
    let out = sb.run(&args);
    assert!(out.contains("issued: 2025-10-09"), "{out}");
    assert!(out.contains("digest: "), "{out}");
    let digest = out
        .lines()
        .find_map(|l| l.strip_prefix("digest: "))
        .unwrap();
    // The issuer signs with its own signer: here a throwaway key file, through the signing
    // module, the one place a key is read.
    let issuer_key = key_file();
    let issuer = hex(&issuer_key.signer);
    let signed = crate::signing::sign(&crate::signing::SignRequest {
        key_file: &issuer_key.path,
        network: Network::Testnet,
        mainnet_explicit: false,
        expected_signer: Some(issuer_key.signer),
        digest: crate::json::unhex32(digest).unwrap(),
    })
    .unwrap();
    let sig_hex = hex(&signed.signature[..64]);
    let file = sb.path("manifest.json");
    let mut signed: Vec<&str> = args.to_vec();
    signed.extend([
        "--list-issuer-key",
        &issuer,
        "--signature",
        &sig_hex,
        "--out",
        s(&file),
    ]);
    let out = sb.run(&signed);
    assert!(
        out.contains("signature: verifies under list issuer key"),
        "{out}"
    );
    assert!(file.exists());
    // A signature of another digest, and one under another key, are refused and write nothing.
    let other = sb.path("other.json");
    let mut wrong: Vec<&str> = args.to_vec();
    let at = wrong.iter().position(|a| *a == "--list-version").unwrap();
    wrong[at + 1] = "4";
    wrong.extend([
        "--list-issuer-key",
        &issuer,
        "--signature",
        &sig_hex,
        "--out",
        s(&other),
    ]);
    assert_eq!(sb.refuse(&wrong), "ZK_MANIFEST_INVALID");
    assert!(!other.exists());
}

// =============================================================================================
// Offline: terms new, address, verify, prove-args on the golden vectors
// =============================================================================================

/// A draft from a golden terms v3 vector: its terms object without the list keys.
fn draft_of(
    sb: &Sandbox,
    name: &str,
    prefix: &str,
    edit: impl FnOnce(&mut Value),
) -> (PathBuf, TermsV3) {
    let (file, terms) = vector_terms(prefix);
    let mut v: Value = serde_json::from_str(&file).unwrap();
    let t = v["terms"].as_object_mut().unwrap();
    t.remove("list_issuer_key");
    t.remove("list_root");
    let mut draft = v["terms"].clone();
    edit(&mut draft);
    (sb.write(name, &draft.to_string()), terms.terms().clone())
}

const CREATION_DAA: &str = "400000000";

/// A pin for a destination: a Kaspa address or kcc20:<type>:<hex>.
fn pin_of(network: Network, d: &impulse_core::terms::Destination) -> Option<String> {
    use impulse_core::terms::Destination;
    use kaspa_addresses::{Address, Version};
    match d {
        Destination::Kcc20(o) => Some(format!(
            "kcc20:{}:{}",
            match o.identifier_type {
                IdentifierType::PubKey => "pubkey",
                IdentifierType::ScriptHash => "script_hash",
                IdentifierType::CovenantId => "covenant_id",
            },
            hex(&o.identifier)
        )),
        Destination::Kas(spk) => {
            let prefix = impulse_core::address::prefix(network);
            match spk.script() {
                [0x20, key @ .., 0xac] => {
                    Some(Address::new(prefix, Version::PubKey, key).to_string())
                }
                [0xaa, 0x20, hash @ .., 0x87] => {
                    Some(Address::new(prefix, Version::ScriptHash, hash).to_string())
                }
                _ => None,
            }
        }
        Destination::OffChain => None,
    }
}

/// The seller of the terms, pinning the destinations that do not pay the seller key.
fn party_args(t: &TermsV3) -> Vec<String> {
    let network = t.fields.network;
    let mut args: Vec<String> = ["--role", "seller", "--my-key", &hex(&t.fields.seller_key)]
        .iter()
        .map(|x| x.to_string())
        .collect();
    if let Some(pin) = pin_of(network, &t.fields.seller_proceeds) {
        args.extend(["--my-proceeds".to_string(), pin]);
    }
    if let Some(pin) = pin_of(network, &t.fields.seller_refund) {
        args.extend(["--my-refund".to_string(), pin]);
    }
    args
}

#[test]
fn terms_new_writes_a_terms_file_and_prints_the_fixed_texts() {
    let sb = Sandbox::new(Network::Testnet, 1);
    let (draft, t) = draft_of(&sb, "draft.json", "07-", |_| {});
    let out_file = sb.path("terms.json");
    let issuer = hex(&t.list_issuer_key);
    let root = hex(&t.list_root);
    let party = party_args(&t);
    let mut args: Vec<&str> = vec![
        "terms",
        "new",
        "--draft",
        s(&draft),
        "--list-issuer-key",
        &issuer,
        "--list-root",
        &root,
        "--daa",
        CREATION_DAA,
        "--out",
        s(&out_file),
    ];
    args.extend(party.iter().map(String::as_str));
    args.extend(DECLARE);
    let out = sb.run(&args);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], DISCLAIMER);
    assert_eq!(lines[1], SETUP_LINE);
    assert_eq!(lines[2], GATE_LINE);
    assert!(out.contains("asset vault: kaspatest:p"), "{out}");
    assert!(out.contains("cash vault: kaspatest:p"), "{out}");
    assert!(out.contains("public on chain"), "{out}");
    assert!(out.contains(&format!("list_root: {root}")), "{out}");
    assert!(
        out.contains("A list cannot be revoked inside these terms."),
        "{out}"
    );
    // The file is the one the golden vector holds, hash for hash.
    let written = parse_terms_v3_file(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
    assert_eq!(written.terms(), &t);
    // Rendering and reading back is the identity.
    assert_eq!(
        render_terms_v3_file(&written),
        std::fs::read_to_string(&out_file).unwrap()
    );
}

#[test]
fn terms_new_refuses_what_the_spec_says() {
    let sb = Sandbox::new(Network::Testnet, 1);
    let (draft, t) = draft_of(&sb, "draft.json", "07-", |_| {});
    let issuer = hex(&t.list_issuer_key);
    let root = hex(&t.list_root);
    let party = party_args(&t);
    let try_with = |draft: &Path, issuer: &str, root: &str| {
        let out_file = sb.path("t.json");
        let _ = std::fs::remove_file(&out_file);
        let mut args: Vec<&str> = vec![
            "terms",
            "new",
            "--draft",
            s(draft),
            "--list-issuer-key",
            issuer,
            "--list-root",
            root,
            "--daa",
            CREATION_DAA,
            "--out",
            s(&out_file),
        ];
        args.extend(party.iter().map(String::as_str));
        args.extend(DECLARE);
        let code = sb.refuse(&args);
        assert!(!out_file.exists(), "{code}: a refused command wrote a file");
        code
    };
    // A version 1 draft, a root of zeros, an invalid issuer key, text that is not hex.
    let (v1, _) = draft_of(&sb, "draft-v1.json", "07-", |d| d["version"] = 1.into());
    assert_eq!(try_with(&v1, &issuer, &root), "ZK_TERMS_VERSION");
    assert_eq!(
        try_with(&draft, &issuer, &"00".repeat(32)),
        "ZK_ROOT_INVALID"
    );
    assert_eq!(try_with(&draft, &"ff".repeat(32), &root), "ZK_ISSUER_KEY");
    assert_eq!(try_with(&draft, "xyz", &root), "CLI_HEX");
}

#[test]
fn terms_new_requires_an_authority_unless_told_otherwise() {
    // Vector 04 is a mainnet trade without an authority; the creation DAA score is read from
    // the node, as on mainnet it must be.
    let sb = Sandbox::new(Network::Mainnet, 400_000_000);
    let (draft, t) = draft_of(&sb, "draft.json", "04-", |_| {});
    assert!(t.fields.authority_key.is_none());
    let (issuer, root) = (hex(&t.list_issuer_key), hex(&t.list_root));
    let out_file = sb.path("terms.json");
    let party = party_args(&t);
    let mut args: Vec<&str> = vec![
        "terms",
        "new",
        "--draft",
        s(&draft),
        "--list-issuer-key",
        &issuer,
        "--list-root",
        &root,
        "--node",
        NODE,
        "--out",
        s(&out_file),
    ];
    args.extend(party.iter().map(String::as_str));
    // The golden trade is far above the value cap; lift it here.
    args.push("--i-accept-the-risk");
    args.extend(DECLARE);
    assert_eq!(sb.refuse(&args), "ZK_AUTHORITY_ABSENT");
    assert!(!out_file.exists());
    args.push("--no-authority");
    let out = sb.run(&args);
    assert!(
        out.contains("No authority: removal from the list after these terms were made cannot stop the settle."),
        "{out}"
    );
    assert!(out_file.exists());
}

/// The self-settling KAS-cash trade impulse-core's end-to-end tests commit a proof for: pinned
/// KCC-20 asset, label-derived parties, mainnet.
fn proof_world() -> (Sandbox, ValidatedTermsV3, PathBuf, Vec<String>) {
    let sb = Sandbox::new(Network::Mainnet, NOW);
    let terms = core_terms("selfsettle");
    let file = sb.write("terms.json", &render_terms_v3_file(&terms));
    let party = party_args(terms.terms());
    (sb, terms, file, party)
}

#[test]
fn address_and_verify_agree_and_verify_refuses_a_swapped_address() {
    let (sb, terms, terms_file, party) = proof_world();
    let mut args: Vec<&str> = vec!["address", "--terms", s(&terms_file), "--node", NODE];
    args.extend(party.iter().map(String::as_str));
    args.extend(DECLARE);
    let out = sb.run(&args);
    let addr = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} vault: ")))
            .unwrap()
            .to_string()
    };
    let (asset, cash) = (addr("asset"), addr("cash"));
    let verify = |asset: &str, cash: &str| {
        let mut args: Vec<&str> = vec![
            "verify",
            "--terms",
            s(&terms_file),
            "--asset-address",
            asset,
            "--cash-address",
            cash,
            "--node",
            NODE,
        ];
        args.extend(party.iter().map(String::as_str));
        args.extend(DECLARE);
        sb.exec(&args)
    };
    let (r, out) = verify(&asset, &cash);
    r.unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], DISCLAIMER);
    assert_eq!(lines[1], SETUP_LINE);
    assert_eq!(lines[2], GATE_LINE);
    assert!(out.contains("list manifest: none supplied, nothing ties this root to the issuer key"));
    assert!(out.contains(
        "No path file: the buyer cannot settle without the list issuer's path for this owner."
    ));
    assert!(out.contains("A list cannot be revoked inside these terms."));
    // The order of the spec: root and issuer key before the delivery owner before the path.
    let at = |needle: &str| out.find(needle).unwrap_or_else(|| panic!("{needle}"));
    assert!(at("list_root:") < at("list_issuer_key:"));
    assert!(at("list_issuer_key:") < at("buyer delivery owner"));
    assert!(at("buyer delivery owner") < at("No path file"));
    // The terms have no authority: said so.
    assert!(out.contains("No authority:"), "{out}");
    // Swapped legs and a foreign address are refused, and print nothing.
    let (r, out) = verify(&cash, &asset);
    assert_eq!(r.unwrap_err().code(), "ZK_VERIFY_ADDRESS_MISMATCH");
    assert_eq!(out, "");
    let foreign = p2pk_address(&[7; 32], Network::Mainnet).to_string();
    let (r, out) = verify(&foreign, &cash);
    assert_eq!(r.unwrap_err().code(), "ZK_VERIFY_ADDRESS_MISMATCH");
    assert_eq!(out, "");
    drop(terms);
}

#[test]
fn prove_args_print_what_the_prover_takes() {
    let (sb, terms, terms_file, _) = proof_world();
    let out = sb.run(&["prove-args", "--terms", s(&terms_file)]);
    assert!(
        out.contains("impulse-zk-prove --path <PATH_FILE> --root "),
        "{out}"
    );
    assert!(out.contains(&hex(&terms.terms().list_root)));
    assert!(
        out.contains("journal: 496d70756c73652f7a6b2f776c2f7631"),
        "{out}"
    );
    let args = out
        .lines()
        .find(|l| l.starts_with("impulse-zk-prove"))
        .unwrap()
        .to_string();
    let vault_spk = args
        .split("--vault-spk ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    assert_eq!(vault_spk.len(), 74, "a 37-byte P2SH script in hex");
    // The journal the command prints is the one the committed proof carries.
    let proof: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(CORE_TESTDATA).join("e2e-selfsettle.proof.json"))
            .unwrap(),
    )
    .unwrap();
    let journal = out
        .lines()
        .find_map(|l| l.strip_prefix("journal: "))
        .unwrap();
    assert_eq!(journal, proof["journal"].as_str().unwrap());
}

#[test]
fn the_default_build_has_no_zk_text_outside_the_feature() {
    // The command exists only in this feature's tests; a plain parse of the top-level help
    // names it once.
    let help = Cli::try_parse_from(["impulse", "zk", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains(DISCLAIMER), "{help}");
    assert!(help.contains(SETUP_LINE), "{help}");
    assert!(help.contains(GATE_LINE), "{help}");
}

// =============================================================================================
// The proof-bound trade, end to end against the fake node
// =============================================================================================

struct Trade {
    sb: Sandbox,
    terms: ValidatedTermsV3,
    terms_file: PathBuf,
    payer: KeyFile,
    asset_template: PathBuf,
}

fn core_terms(name: &str) -> ValidatedTermsV3 {
    let path = Path::new(CORE_TESTDATA).join(format!("e2e-{name}.terms.hex"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run scripts/regen-zk-core-fixtures.sh",
            path.display()
        )
    });
    let bytes: Vec<u8> = (0..text.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text.trim()[i..i + 2], 16).unwrap())
        .collect();
    ValidatedTermsV3::decode(&bytes).expect("the committed terms decode")
}

impl Trade {
    /// The self-settling trade the committed proof is bound to, funded on a mainnet fake node.
    fn new() -> Self {
        let network = Network::Mainnet;
        let mut sb = Sandbox::new(network, NOW);
        sb.max_value = None;
        let terms = core_terms("selfsettle");
        let terms_file = sb.write("terms.json", &render_terms_v3_file(&terms));
        std::fs::write(sb.path("asset.json"), ASSET_JSON).unwrap();
        let payer = key_file();
        {
            let mut state = sb.sim.state.borrow_mut();
            state.add_utxo(
                address_script(&p2pk_address(&payer.signer, network)),
                400_000_000_000,
                None,
            );
            state.add_utxo(
                address_script(&p2pk_address(&payer.signer, network)),
                300_000_000_000,
                None,
            );
            let asset_vault = VaultV3::instantiate_existing(&terms, LegIndex::Asset).unwrap();
            let cash_vault = VaultV3::instantiate_existing(&terms, LegIndex::Cash).unwrap();
            let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
            let escrow = Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::ScriptHash,
                    identifier: asset_vault.script_hash(),
                },
                terms.terms().fields.asset_leg.amount,
            );
            state.add_utxo(asset_vault.script_public_key(), AUTHORIZER, None);
            state.add_utxo(
                asset.script_public_key(&escrow).unwrap(),
                MIN_KCC20_OUTPUT,
                Some(ASSET_COV),
            );
            state.add_utxo(cash_vault.script_public_key(), KAS_CASH, None);
        }
        Self {
            sb,
            terms,
            terms_file,
            payer,
            asset_template: PathBuf::new(),
        }
        .with_template()
    }

    fn with_template(mut self) -> Self {
        self.asset_template = self.sb.path("asset.json");
        self
    }

    fn payer_address(&self) -> String {
        p2pk_address(&self.payer.signer, self.sb.network).to_string()
    }

    fn proof_file(&self) -> PathBuf {
        Path::new(CORE_TESTDATA).join("e2e-selfsettle.proof.json")
    }

    fn settle_args(&self, proof: &Path, out: &Path) -> Vec<String> {
        [
            "settle",
            "build",
            "--terms",
            s(&self.terms_file),
            "--proof",
            s(proof),
            "--node",
            NODE,
            "--pay-from",
            &self.payer_address(),
            "--asset-template",
            s(&self.asset_template),
            "--out",
            s(out),
            DECLARE[0],
            DECLARE[1],
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
    }
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

impl Trade {
    /// Builds and signs the settle; returns the signed IPST's path.
    fn signed_settle(&self) -> PathBuf {
        let unsigned = self.sb.path("settle.json");
        self.sb
            .run(&strs(&self.settle_args(&self.proof_file(), &unsigned)));
        let signed = self.sb.path("signed.json");
        self.sb.run(&[
            "ipst",
            "sign",
            "--ipst",
            s(&unsigned),
            "--terms",
            s(&self.terms_file),
            "--key-file",
            s(&self.payer.path),
            "--role",
            "payer",
            "--my-key",
            &hex(&self.payer.signer),
            "--node",
            NODE,
            "--asset-template",
            s(&self.asset_template),
            "--out",
            s(&signed),
            DECLARE[0],
            DECLARE[1],
        ]);
        signed
    }
}

#[test]
fn a_settle_with_a_flipped_proof_bit_is_refused_by_the_node_and_only_on_testnet() {
    let t = Trade::new();
    let signed = t.signed_settle();
    let ipst = IpstV3::from_json(&std::fs::read_to_string(&signed).unwrap()).unwrap();
    let tx = ipst.finalize().unwrap();
    let mut out = Vec::new();
    let height = t.sb.sim.state.borrow().height();
    crate::zk_sign::flip_and_submit(&ipst, tx, &t.sb.sim, Network::Mainnet, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("refused by the node, as expected"), "{text}");
    assert_eq!(
        t.sb.sim.state.borrow().height(),
        height,
        "nothing was accepted"
    );
    // The command itself refuses outside testnet, before it reads or sends anything.
    assert_eq!(
        t.sb.refuse(&[
            "submit",
            "--ipst",
            s(&signed),
            "--node",
            NODE,
            "--asset-template",
            s(&t.asset_template),
            "--flip-proof-bit",
        ]),
        "CLI_NETWORK_MISMATCH"
    );
}

#[test]
fn a_gated_settle_goes_from_a_proof_file_to_an_accepted_transaction() {
    let t = Trade::new();
    let unsigned = t.sb.path("settle.json");
    let out = t.sb.run(&strs(&t.settle_args(&t.proof_file(), &unsigned)));
    assert!(out.starts_with(DISCLAIMER), "{out}");
    assert!(
        out.contains("This settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass."),
        "{out}"
    );
    assert!(out.contains("ipst: settle"), "{out}");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&unsigned).unwrap()).unwrap();
    assert_eq!(doc["ipst"], 4);
    assert!(doc["zk_proof"].as_str().unwrap().len() == 256);

    // The payer signs its fee input with its key file; the vault inputs take no signature.
    let signed = t.sb.path("signed.json");
    let out = t.sb.run(&[
        "ipst",
        "sign",
        "--ipst",
        s(&unsigned),
        "--terms",
        s(&t.terms_file),
        "--key-file",
        s(&t.payer.path),
        "--role",
        "payer",
        "--my-key",
        &hex(&t.payer.signer),
        "--node",
        NODE,
        "--asset-template",
        s(&t.asset_template),
        "--out",
        s(&signed),
        DECLARE[0],
        DECLARE[1],
    ]);
    assert!(out.contains("signed: input 3"), "{out}");
    assert!(
        !out.contains(t.payer.content.trim()),
        "a key never appears in output"
    );

    // Submit: the fake node runs every input, the asset vault's through the proof gate.
    let height_before = t.sb.sim.state.borrow().height();
    let out = t.sb.run(&[
        "submit",
        "--ipst",
        s(&signed),
        "--node",
        NODE,
        "--asset-template",
        s(&t.asset_template),
    ]);
    assert!(out.contains("submitted: "), "{out}");
    assert_eq!(
        t.sb.sim.state.borrow().height(),
        height_before + 1,
        "one block accepted the settle"
    );

    // Status and the receipt: the disclaimer, a finality state, a signature anyone can check.
    let field = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}: ")))
            .unwrap()
            .to_string()
    };
    let (txid, from_block) = (field("submitted"), field("from_block"));
    let receipt = t.sb.path("receipt.json");
    let status = t.sb.run(&[
        "status",
        "--node",
        NODE,
        "--terms",
        s(&t.terms_file),
        "--txid",
        &txid,
        "--from-block",
        &from_block,
        "--final-depth",
        "1000000",
        "--key-file",
        s(&t.payer.path),
        "--out",
        s(&receipt),
        "--min-depth",
        "0",
    ]);
    assert!(status.starts_with(DISCLAIMER), "{status}");
    assert!(status.contains("state: accepted: "), "{status}");
    assert!(!status.contains("state: final"), "{status}");
    let verified = t.sb.run(&[
        "receipt",
        "verify",
        "--receipt",
        s(&receipt),
        "--signer",
        &hex(&t.payer.signer),
        "--terms",
        s(&t.terms_file),
        "--txid",
        &txid,
        "--node",
        NODE,
    ]);
    assert!(verified.starts_with(DISCLAIMER), "{verified}");
    assert!(
        verified.contains("state when signed: accepted"),
        "{verified}"
    );
    assert!(verified.contains("signer: matches --signer"), "{verified}");
    // A receipt whose disclaimer was edited is refused.
    let text = std::fs::read_to_string(&receipt).unwrap();
    let edited = t.sb.write(
        "edited-receipt.json",
        &text.replace("Impulse checks", "Impulse approves"),
    );
    assert_eq!(
        t.sb.refuse(&["receipt", "verify", "--receipt", s(&edited)]),
        "RECEIPT_MALFORMED"
    );
    // With a final depth of zero the state is final.
    let final_status = t.sb.run(&[
        "status",
        "--node",
        NODE,
        "--terms",
        s(&t.terms_file),
        "--txid",
        &txid,
        "--from-block",
        &from_block,
        "--final-depth",
        "0",
    ]);
    assert!(final_status.contains("state: final: "), "{final_status}");
}

#[test]
fn a_proof_file_for_another_trade_is_refused_before_a_transaction_is_built() {
    let t = Trade::new();
    let unsigned = t.sb.path("settle.json");
    // The authority world's proof is a real proof of another vault.
    let other = Path::new(CORE_TESTDATA).join("e2e-authority.proof.json");
    if other.exists() {
        assert_eq!(
            t.sb.refuse(&strs(&t.settle_args(&other, &unsigned))),
            "ZK_PROOF_INVALID"
        );
    }
    assert!(!unsigned.exists());
    // A proof file that is not one.
    let junk = t.sb.write("junk.json", "{}");
    assert_eq!(
        t.sb.refuse(&strs(&t.settle_args(&junk, &unsigned))),
        "ZK_PROOF_MALFORMED"
    );
    // A proof with a bit flipped (journal intact): the point no longer parses or no longer
    // verifies, and either way nothing is built.
    let text = std::fs::read_to_string(t.proof_file()).unwrap();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    let proof = v["proof"].as_str().unwrap().to_string();
    let first = if proof.starts_with('a') { 'b' } else { 'a' };
    v["proof"] = format!("{first}{}", &proof[1..]).into();
    let flipped = t.sb.write("flipped.json", &v.to_string());
    let code = t.sb.refuse(&strs(&t.settle_args(&flipped, &unsigned)));
    assert!(
        code == "ZK_PROOF_MALFORMED" || code == "ZK_PROOF_INVALID",
        "{code}"
    );
    assert!(!unsigned.exists());
}

#[test]
fn a_signed_settle_is_refused_by_the_terms_check_when_the_proof_is_swapped() {
    let t = Trade::new();
    let unsigned = t.sb.path("settle.json");
    t.sb.run(&strs(&t.settle_args(&t.proof_file(), &unsigned)));
    // Hand-edit the document's proof: the rebuilt transaction differs, so nothing is signed.
    let text = std::fs::read_to_string(&unsigned).unwrap();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    let proof = v["zk_proof"].as_str().unwrap().to_string();
    let last = if proof.ends_with('0') { '1' } else { '0' };
    v["zk_proof"] = format!("{}{last}", &proof[..proof.len() - 1]).into();
    // The slot scripts still carry the original proof, so the document is not what the builder
    // makes for the stated proof (or the stated proof no longer parses).
    let edited = t.sb.write("edited.json", &v.to_string());
    let signed = t.sb.path("signed.json");
    let code = t.sb.refuse(&[
        "ipst",
        "sign",
        "--ipst",
        s(&edited),
        "--terms",
        s(&t.terms_file),
        "--key-file",
        s(&t.payer.path),
        "--role",
        "payer",
        "--my-key",
        &hex(&t.payer.signer),
        "--node",
        NODE,
        "--asset-template",
        s(&t.asset_template),
        "--out",
        s(&signed),
        DECLARE[0],
        DECLARE[1],
    ]);
    assert!(
        code == "ZK_PROOF_MALFORMED" || code == "IPST_TERMS_MISMATCH" || code == "ZK_PROOF_INVALID",
        "{code}"
    );
    assert!(!signed.exists());
    let _ = &t.terms;
}

// =============================================================================================
// A signed manifest and a path, and funding and refunds with key files, against the fake node
// =============================================================================================

/// The x coordinate of the public point G: a valid list entry with no private key anywhere.
const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn sign_digest(key: &KeyFile, network: Network, digest: [u8; 32]) -> String {
    let signed = crate::signing::sign(&crate::signing::SignRequest {
        key_file: &key.path,
        network,
        mainnet_explicit: false,
        expected_signer: Some(key.signer),
        digest,
    })
    .unwrap();
    hex(&signed.signature[..64])
}

#[test]
fn a_signed_manifest_and_a_members_path_verify_end_to_end() {
    let sb = Sandbox::new(Network::Testnet, NOW);
    let world = core_terms("selfsettle");
    let buyer = hex(&world.delivery_owner().identifier);
    let seller = hex(&world.terms().fields.seller_key);
    // The issuer's list holds G and the buyer's delivery owner (entry 1).
    let list = sb.write("list.txt", &format!("pubkey:{G_X}\npubkey:{buyer}\n"));
    let paths = sb.path("paths");
    let out = sb.run(&["list", "build", "--list", s(&list), "--out-dir", s(&paths)]);
    let root = out
        .lines()
        .find_map(|l| l.strip_prefix("list root: "))
        .unwrap()
        .to_string();
    // The issuer signs the manifest digest with its own key file.
    let issuer = key_file();
    let base = [
        "list",
        "manifest",
        "--root",
        &root,
        "--list-id",
        "fixture",
        "--list-version",
        "1",
        "--issued-at",
        "1760000000",
    ];
    let unsigned = sb.run(&base);
    let digest = unsigned
        .lines()
        .find_map(|l| l.strip_prefix("digest: "))
        .unwrap();
    let sig = sign_digest(
        &issuer,
        Network::Testnet,
        crate::json::unhex32(digest).unwrap(),
    );
    let manifest = sb.path("manifest.json");
    let issuer_hex = hex(&issuer.signer);
    let mut signed = base.to_vec();
    signed.extend([
        "--list-issuer-key",
        &issuer_hex,
        "--signature",
        &sig,
        "--out",
        s(&manifest),
    ]);
    sb.run(&signed);

    // Terms: the proof world's trade on testnet, the issuer key and the list root from above.
    let mut v: Value = serde_json::from_str(&render_terms_v3_file(&world)).unwrap();
    let t = v["terms"].as_object_mut().unwrap();
    t.remove("list_issuer_key");
    t.remove("list_root");
    t.insert("network".into(), "testnet".into());
    let draft = sb.write("draft.json", &v["terms"].to_string());
    let terms_file = sb.path("terms.json");
    let out = sb.run(&[
        "terms",
        "new",
        "--draft",
        s(&draft),
        "--list-issuer-key",
        &issuer_hex,
        "--list-root",
        &root,
        "--no-authority",
        "--daa",
        "1500000",
        "--out",
        s(&terms_file),
        "--role",
        "seller",
        "--my-key",
        &seller,
        DECLARE[0],
        DECLARE[1],
    ]);
    let vault = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} vault: ")))
            .unwrap()
            .to_string()
    };
    let (asset, cash) = (vault("asset"), vault("cash"));
    let verify = |path: &Path, manifest: Option<&Path>| {
        let mut args = vec![
            "verify",
            "--terms",
            s(&terms_file),
            "--asset-address",
            &asset,
            "--cash-address",
            &cash,
            "--daa",
            "1500000",
            "--path",
            s(path),
            "--role",
            "seller",
            "--my-key",
            &seller,
            DECLARE[0],
            DECLARE[1],
        ];
        if let Some(m) = manifest {
            args.extend(["--manifest", s(m)]);
        }
        sb.exec(&args)
    };
    let (r, out) = verify(&paths.join("path-0000001.json"), Some(&manifest));
    r.unwrap();
    assert!(
        out.contains("list manifest: signed by the list issuer key, list fixture version 1, issued 2025-10-09"),
        "{out}"
    );
    assert!(
        out.contains("path: leads from the buyer delivery owner's salted leaf"),
        "{out}"
    );
    // The other member's path does not lead from the buyer's owner.
    let (r, out) = verify(&paths.join("path-0000000.json"), Some(&manifest));
    assert_eq!(r.unwrap_err().code(), "ZK_PATH_INVALID");
    assert_eq!(out, "");
    // A manifest signed by another key, for the same root, is not the issuer's.
    let other_key = key_file();
    let sig2 = sign_digest(
        &other_key,
        Network::Testnet,
        crate::json::unhex32(digest).unwrap(),
    );
    let other = sb.path("other-manifest.json");
    let other_hex = hex(&other_key.signer);
    let mut forged = base.to_vec();
    forged.extend([
        "--list-issuer-key",
        &other_hex,
        "--signature",
        &sig2,
        "--out",
        s(&other),
    ]);
    sb.run(&forged);
    let (r, _) = verify(&paths.join("path-0000001.json"), Some(&other));
    assert_eq!(r.unwrap_err().code(), "ZK_MANIFEST_INVALID");
}

/// A trade whose parties hold key files, funded and refunded on the fake node.
struct Keyed {
    sb: Sandbox,
    seller: KeyFile,
    buyer: KeyFile,
    authority: KeyFile,
    terms_file: PathBuf,
    asset_template: PathBuf,
    seller_token: String,
}

impl Keyed {
    fn new() -> Self {
        use impulse_core::tx::Kcc20State;
        let sb = Sandbox::new(Network::Testnet, NOW);
        let (seller, buyer, authority) = (key_file(), key_file(), key_file());
        std::fs::write(sb.path("asset.json"), ASSET_JSON).unwrap();
        let asset = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let seller_token;
        {
            let mut state = sb.sim.state.borrow_mut();
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
        let list = sb.write(
            "list.txt",
            &format!("pubkey:{G_X}\npubkey:{}\n", hex(&buyer.signer)),
        );
        let out = sb.run(&[
            "list",
            "build",
            "--list",
            s(&list),
            "--out-dir",
            s(&sb.path("paths")),
        ]);
        let root = out
            .lines()
            .find_map(|l| l.strip_prefix("list root: "))
            .unwrap()
            .to_string();
        let p2pk = |k: &KeyFile| format!("20{}ac", hex(&k.signer));
        let owner = |k: &KeyFile| serde_json::json!({"kind": "kcc20", "identifier_type": "pubkey", "identifier": hex(&k.signer)});
        let draft = serde_json::json!({
            "version": 3, "network": "testnet", "settlement_mode": "vault", "nonce": null,
            "seller_key": hex(&seller.signer), "buyer_key": hex(&buyer.signer),
            "authority_key": hex(&authority.signer),
            "asset_leg": {"kind": "kcc20", "covenant_id": hex(&ASSET_COV),
                "template_hash": hex(&asset.template_hash()),
                "template_prefix_len": asset.prefix_len(), "template_suffix_len": asset.suffix_len(),
                "amount": "10"},
            "cash_leg": {"kind": "kas", "amount": KAS_CASH.to_string()},
            "buyer_delivery": owner(&buyer),
            "seller_proceeds": {"kind": "kas", "version": 0, "script": p2pk(&seller)},
            "seller_refund": owner(&seller),
            "buyer_refund": {"kind": "kas", "version": 0, "script": p2pk(&buyer)},
            "earliest_daa": null, "expiry_daa": (NOW + 864_000).to_string(),
            "funding_mode": "revocable", "trade_ref": hex(&[0x5E; 32]),
        });
        let draft_file = sb.write("draft.json", &draft.to_string());
        let terms_file = sb.path("terms.json");
        sb.run(&[
            "terms",
            "new",
            "--draft",
            s(&draft_file),
            "--list-issuer-key",
            &hex(&authority.signer),
            "--list-root",
            &root,
            "--daa",
            &NOW.to_string(),
            "--out",
            s(&terms_file),
            "--role",
            "seller",
            "--my-key",
            &hex(&seller.signer),
            DECLARE[0],
            DECLARE[1],
        ]);
        let asset_template = sb.path("asset.json");
        Self {
            sb,
            seller,
            buyer,
            authority,
            terms_file,
            asset_template,
            seller_token,
        }
    }

    fn pay(&self, k: &KeyFile) -> String {
        p2pk_address(&k.signer, Network::Testnet).to_string()
    }

    /// Builds with `build`, signs as `key` in `role`, submits; returns the submit output.
    fn build_sign_submit(&self, name: &str, build: &[&str], key: &KeyFile, role: &str) -> String {
        let unsigned = self.sb.path(&format!("{name}.ipst"));
        let signed = self.sb.path(&format!("{name}.signed"));
        let mut args: Vec<&str> = build.to_vec();
        args.extend([
            "--terms",
            s(&self.terms_file),
            "--out",
            s(&unsigned),
            DECLARE[0],
            DECLARE[1],
        ]);
        self.sb.run(&args);
        self.sb.run(&[
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
            "--node",
            NODE,
            "--asset-template",
            s(&self.asset_template),
            "--out",
            s(&signed),
            DECLARE[0],
            DECLARE[1],
        ]);
        self.sb.run(&[
            "submit",
            "--ipst",
            s(&signed),
            "--node",
            NODE,
            "--asset-template",
            s(&self.asset_template),
        ])
    }
}

#[test]
fn funding_and_refunds_of_a_v3_trade_run_in_the_engine_with_key_files() {
    let t = Keyed::new();
    let (sp, bp) = (t.pay(&t.seller), t.pay(&t.buyer));
    let tpl = s(&t.asset_template).to_string();
    let node_args = |extra: &[&str]| {
        let mut v: Vec<String> = ["--node", NODE, "--asset-template", &tpl]
            .iter()
            .map(|x| x.to_string())
            .collect();
        v.extend(extra.iter().map(|x| x.to_string()));
        v
    };
    // The seller funds the asset leg with its token, the buyer the cash leg.
    let mut a = vec![
        "fund", "build", "--leg", "asset", "--role", "seller", "--my-key",
    ];
    let sk = hex(&t.seller.signer);
    a.push(&sk);
    let extra = node_args(&["--pay-from", &sp, "--token", &t.seller_token]);
    a.extend(extra.iter().map(String::as_str));
    let out = t.build_sign_submit("fund-asset", &a, &t.seller, "seller");
    assert!(out.contains("submitted: "), "{out}");
    let bk = hex(&t.buyer.signer);
    let mut a = vec![
        "fund", "build", "--leg", "cash", "--role", "buyer", "--my-key", &bk,
    ];
    let extra = node_args(&["--pay-from", &bp]);
    a.extend(extra.iter().map(String::as_str));
    let out = t.build_sign_submit("fund-cash", &a, &t.buyer, "buyer");
    assert!(out.contains("submitted: "), "{out}");

    // The buyer, the cash leg's depositor, takes its cash back: the v3 vault's refund entry runs
    // in the engine with the buyer's real signature.
    let mut a = vec!["refund", "build", "--leg", "cash", "--signer", "depositor"];
    let extra = node_args(&["--pay-from", &bp]);
    a.extend(extra.iter().map(String::as_str));
    let out = t.build_sign_submit("refund-cash", &a, &t.buyer, "buyer");
    assert!(out.contains("submitted: "), "{out}");

    // The authority refunds the asset leg with its escrowed token.
    let ap = t.pay(&t.authority);
    let mut a = vec!["refund", "build", "--leg", "asset", "--signer", "authority"];
    let extra = node_args(&["--pay-from", &ap]);
    a.extend(extra.iter().map(String::as_str));
    let out = t.build_sign_submit("refund-asset", &a, &t.authority, "authority");
    assert!(out.contains("submitted: "), "{out}");
    // Both vaults are empty again: nothing left to refund.
    let unsigned = t.sb.path("again.ipst");
    let code = t.sb.refuse(&[
        "refund",
        "build",
        "--terms",
        s(&t.terms_file),
        "--leg",
        "cash",
        "--signer",
        "depositor",
        "--node",
        NODE,
        "--pay-from",
        &bp,
        "--out",
        s(&unsigned),
        DECLARE[0],
        DECLARE[1],
    ]);
    assert_eq!(code, "CLI_UTXO_NOT_FOUND");
}

#[test]
fn utc_dates_are_right() {
    use crate::zk_cmd::utc_date;
    assert_eq!(utc_date(0), "1970-01-01");
    assert_eq!(utc_date(951_782_400), "2000-02-29");
    assert_eq!(utc_date(1_760_000_000), "2025-10-09");
    assert_eq!(utc_date(4_102_444_800), "2100-01-01");
    assert_eq!(utc_date(1_709_164_800), "2024-02-29");
}
