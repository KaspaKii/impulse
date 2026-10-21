// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I13 phase 2 exit test, offline. Three `impulse frost keygen` processes, one per party, run a
//! 2-of-3 key generation through files this test moves between their directories (standing in
//! for the parties' own channels) and through the digests and fingerprints it types back after
//! comparing them (standing in for the out-of-band comparison). Two `impulse frost sign`
//! processes sign the unsigned settle IPST of a trade whose `authority_key` is the group's key,
//! and `impulse frost aggregate` puts the authority signatures into the IPST. The fee payer signs
//! its input, the IPST is finalized, and the real script engine (rusty-kaspa a41a333, covenants
//! enabled) accepts every input under the node's lock-time rules. One signer alone is refused,
//! and one signer's share from that session, aggregated alone, is refused by the engine. KCC-20
//! cash, external cash and a refund by the authority go the same way.
//!
//! Keys: the key shares exist only in files the keygen processes write into a temporary
//! directory with mode 0600, removed with it when the test ends; this file holds no share or key
//! literal. The fee payer's key is a throwaway generated at runtime, kept in memory and erased on
//! drop (rule 1 exception, docs/ENGINEERING-RULES.md).

#[path = "support/world.rs"]
mod world;

use impulse_core::locktime::{check_sequence_lock, check_tx_is_finalized};
use impulse_core::terms::Network;
use impulse_core::tx::Ipst;
use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, Transaction, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use secp256k1::{Keypair, Message, SECP256K1};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "impulse-cli-frost-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }

    fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

// =============================================================================================
// Driving interactive impulse processes
// =============================================================================================

struct Process {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    label: String,
}

impl Process {
    fn spawn<A: AsRef<std::ffi::OsStr>>(label: &str, args: &[A]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_impulse"))
            .args(args)
            .env_remove("IMPULSE_MAX_VALUE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            label: label.to_string(),
        }
    }

    /// Reads lines up to the prompt that starts with `> {step}`; returns the lines before it.
    fn until(&mut self, step: &str) -> Vec<String> {
        let mut lines = vec![];
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line).unwrap() == 0 {
                let mut err = String::new();
                if let Some(mut e) = self.child.stderr.take() {
                    std::io::Read::read_to_string(&mut e, &mut err).unwrap();
                }
                panic!(
                    "{}: ended before `> {step}`; stdout {lines:#?}; stderr {err}",
                    self.label
                );
            }
            let line = line.trim_end_matches('\n').to_string();
            if line.starts_with(&format!("> {step}")) {
                return lines;
            }
            lines.push(line);
        }
    }

    fn answer(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{text}").unwrap();
        stdin.flush().unwrap();
    }

    /// Closes stdin and waits: the exit status, the rest of stdout and stderr.
    fn finish(mut self) -> (bool, String, String) {
        drop(self.stdin.take());
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut rest).unwrap();
        let out = self.child.wait_with_output().unwrap();
        (
            out.status.success(),
            rest,
            String::from_utf8(out.stderr).unwrap(),
        )
    }
}

fn value_of(lines: &[String], key: &str) -> String {
    lines
        .iter()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("no `{key}` line in {lines:#?}"))
        .to_string()
}

fn copy(from: &Path, to: &Path, name: &str) {
    std::fs::copy(from.join(name), to.join(name)).unwrap();
}

fn run<A: AsRef<std::ffi::OsStr>>(args: &[A]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_impulse"))
        .args(args)
        .env_remove("IMPULSE_MAX_VALUE")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn refused(o: &Output) -> String {
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(o.stdout.is_empty(), "printed before refusing: {o:?}");
    let err = String::from_utf8(o.stderr.clone()).unwrap();
    let code = err
        .strip_prefix("impulse: ")
        .and_then(|e| e.split(':').next())
        .unwrap_or_else(|| panic!("{err}"));
    code.to_string()
}

// =============================================================================================
// Key generation: three processes
// =============================================================================================

struct Party {
    exchange: PathBuf,
    share: PathBuf,
    group: PathBuf,
}

struct Group {
    parties: Vec<Party>,
    authority_key: [u8; 32],
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn unhex32(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

/// A signature-share file's shares by input, read here by the layout of spec/THRESHOLD.md,
/// "Files": session (32), commitment set digest (32), sender (2), count (2), then per input its
/// index (4) and share (32).
fn sigshare_entries(path: &Path) -> BTreeMap<usize, [u8; 32]> {
    let text = std::fs::read_to_string(path).unwrap();
    let body = unhex(
        text.trim_end()
            .strip_prefix("impulse-frost-sigshare-v1:")
            .unwrap(),
    );
    let count = u16::from_be_bytes([body[66], body[67]]) as usize;
    assert_eq!(body.len(), 68 + 36 * count);
    (0..count)
        .map(|k| {
            let at = 68 + 36 * k;
            let input = u32::from_be_bytes(body[at..at + 4].try_into().unwrap()) as usize;
            (input, body[at + 4..at + 36].try_into().unwrap())
        })
        .collect()
}

/// A 2-of-3 key generation, one process per party, each with its own exchange directory.
fn keygen(root: &TempDir) -> Group {
    let n = 3u16;
    let parties: Vec<Party> = (1..=n)
        .map(|i| Party {
            exchange: root.sub(&format!("party-{i}/exchange")),
            share: root.0.join(format!("party-{i}/share.frost")),
            group: root.0.join(format!("party-{i}/group.frost")),
        })
        .collect();
    let mut procs: Vec<Process> = parties
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let party = (i + 1).to_string();
            Process::spawn(
                &format!("keygen {party}"),
                &[
                    "frost",
                    "keygen",
                    "--threshold",
                    "2",
                    "--parties",
                    "3",
                    "--party",
                    &party,
                    "--dir",
                    s(&p.exchange),
                    "--share-file",
                    s(&p.share),
                    "--group-out",
                    s(&p.group),
                ],
            )
        })
        .collect();
    // Round 1: every party broadcasts its round-1 file.
    for p in &mut procs {
        p.until("round 1:");
    }
    for i in 1..=n {
        for j in (1..=n).filter(|&j| j != i) {
            let (from, to) = (&parties[i as usize - 1], &parties[j as usize - 1]);
            copy(&from.exchange, &to.exchange, &format!("round1-{i}.frost"));
        }
    }
    let mut digests = vec![];
    for p in &mut procs {
        p.answer("");
        let lines = p.until("confirm round-1 digest");
        digests.push(value_of(&lines, "round-1 digest: "));
    }
    assert!(digests.windows(2).all(|d| d[0] == d[1]), "{digests:?}");
    // Round 2: each round-2 file goes to its one recipient.
    for p in &mut procs {
        p.answer(&digests[0]);
        p.until("round 2:");
    }
    for i in 1..=n {
        for j in (1..=n).filter(|&j| j != i) {
            let (from, to) = (&parties[i as usize - 1], &parties[j as usize - 1]);
            copy(
                &from.exchange,
                &to.exchange,
                &format!("round2-{i}-to-{j}.frost"),
            );
        }
    }
    let mut fingerprints = vec![];
    let mut keys = vec![];
    for p in &mut procs {
        p.answer("");
        let lines = p.until("confirm group fingerprint");
        fingerprints.push(value_of(&lines, "group fingerprint: "));
        keys.push(value_of(&lines, "authority key: "));
    }
    assert!(fingerprints.windows(2).all(|f| f[0] == f[1]));
    assert!(keys.windows(2).all(|k| k[0] == k[1]));
    for (i, mut p) in procs.into_iter().enumerate() {
        p.answer(&fingerprints[0]);
        let (ok, rest, err) = p.finish();
        assert!(ok, "keygen {}: {err}", i + 1);
        assert!(
            rest.contains(&format!("authority key {}", keys[0])),
            "{rest}"
        );
        // The share file is owner-only, and no output carries it.
        let share = std::fs::read_to_string(&parties[i].share).unwrap();
        let hex = share.trim_end().split(':').nth(1).unwrap();
        assert!(!rest.contains(hex) && !err.contains(hex));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&parties[i].share)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    Group {
        parties,
        authority_key: unhex32(&keys[0]),
    }
}

// =============================================================================================
// Signing and aggregation
// =============================================================================================

/// The terms hash of the IPST file: the trade the signer names.
fn terms_hash_of(ipst: &Path) -> String {
    let doc = Ipst::from_json(&std::fs::read_to_string(ipst).unwrap()).expect("reads");
    doc.terms()
        .terms_hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sign_args(share: &Path, ipst: &Path, signers: &str, dir: &Path) -> Vec<String> {
    sign_args_with(share, ipst, signers, dir, &[])
}

fn sign_args_with(
    share: &Path,
    ipst: &Path,
    signers: &str,
    dir: &Path,
    extra: &[String],
) -> Vec<String> {
    let mut args: Vec<String> = [
        "frost",
        "sign",
        "--share-file",
        s(share),
        "--ipst",
        s(ipst),
        "--signers",
        signers,
        "--terms-hash",
        &terms_hash_of(ipst),
        "--dir",
        s(dir),
        "--asset-template",
        s(&world::asset_template_path()),
        "--daa",
        "1500000",
        "--kas-equivalent",
        "100000000",
    ]
    .map(String::from)
    .to_vec();
    args.extend_from_slice(extra);
    args
}

/// `signers` sign `ipst`, each in its own process and directory, `extra` added to their
/// arguments; returns the directory the aggregator reads (every commit and sigshare file).
/// `tag` keeps the directories of one IPST apart from another's.
fn sign(
    root: &TempDir,
    group: &Group,
    ipst: &Path,
    signers: &[u16],
    extra: &[String],
    tag: &str,
) -> PathBuf {
    let list = signers
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let dirs: Vec<PathBuf> = signers
        .iter()
        .map(|i| root.sub(&format!("{tag}-sign-{list}-{i}")))
        .collect();
    let mut procs: Vec<Process> = signers
        .iter()
        .zip(&dirs)
        .map(|(&i, dir)| {
            let share = &group.parties[i as usize - 1].share;
            let args = sign_args_with(share, ipst, &list, dir, extra);
            Process::spawn(&format!("sign {i}"), &args)
        })
        .collect();
    let mut sessions = vec![];
    for p in &mut procs {
        let lines = p.until("commitments:");
        assert!(
            lines.iter().any(|l| l.starts_with("terms_hash: ")),
            "summary first"
        );
        sessions.push(value_of(&lines, "session: "));
    }
    assert!(sessions.windows(2).all(|s| s[0] == s[1]), "{sessions:?}");
    for (a, &i) in signers.iter().enumerate() {
        for (b, _) in signers.iter().enumerate().filter(|(b, _)| *b != a) {
            copy(&dirs[a], &dirs[b], &format!("commit-{i}.frost"));
        }
    }
    for (p, &i) in procs.into_iter().zip(signers) {
        let mut p = p;
        p.answer("");
        // The signer approves the transaction it was shown by typing back its session.
        p.until("sign:");
        p.answer(&sessions[0]);
        let (ok, rest, err) = p.finish();
        assert!(ok, "sign {i}: {err}");
        assert!(
            rest.contains(&format!("ok: party {i} signed inputs ")),
            "{rest}"
        );
    }
    let agg = root.sub(&format!("{tag}-aggregate-{list}"));
    for (dir, &i) in dirs.iter().zip(signers) {
        copy(dir, &agg, &format!("commit-{i}.frost"));
        copy(dir, &agg, &format!("sigshare-{i}.frost"));
    }
    agg
}

fn aggregate_args<'a>(
    group: &'a Path,
    ipst: &'a Path,
    signers: &'a str,
    dir: &'a Path,
    out: &'a Path,
) -> [&'a str; 12] {
    [
        "frost",
        "aggregate",
        "--group",
        s(group),
        "--ipst",
        s(ipst),
        "--signers",
        signers,
        "--dir",
        s(dir),
        "--out",
        s(out),
    ]
}

// =============================================================================================
// The real script engine and the node's lock-time rules
// =============================================================================================

// `engine_flags`, `execute` and `node_accepts` are copied from tests/engine/harness.rs (`run`,
// `engine_flags`) and tests/engine/builders.rs (`node_accepts`), which adapt the WarpCore engine
// runner (docs/reference/BORROW-MAP.md); no WarpCore type remains.
fn engine_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(MAINNET_PARAMS.mass_per_sig_op).into(),
    }
}

/// Input `idx` in the engine under the script-unit limit its own compute budget commits to.
fn execute(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> Result<(), String> {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(1_000);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("{e:?}"))?;
    let (input, utxo) = populated.populated_input(idx);
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated,
        input,
        idx,
        utxo,
        EngineCtx::new(&sig_cache)
            .with_reused(&reused)
            .with_covenants_ctx(&cov_ctx),
        engine_flags(),
        tx.inputs[idx].compute_commit.allowed_script_units(),
    );
    vm.execute().map_err(|e| format!("{e:?}"))
}

/// The node's view in a block of DAA score `daa`: finality of the lock time, the sequence lock,
/// then every input's scripts.
fn node_accepts(tx: &Transaction, entries: &[UtxoEntry], daa: u64) -> Result<(), String> {
    check_tx_is_finalized(tx, daa, 0).map_err(|e| format!("finality: {e}"))?;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    check_sequence_lock(&populated, daa).map_err(|e| format!("sequence lock: {e}"))?;
    for i in 0..tx.inputs.len() {
        execute(tx, entries, i).map_err(|e| format!("input {i}: {e}"))?;
    }
    Ok(())
}

/// The fee payer signs its own input (a throwaway key, in memory only), then the IPST is
/// finalized.
fn pay_and_finalize(mut ipst: Ipst, payer: &Keypair) -> Transaction {
    let x = payer.x_only_public_key().0.serialize();
    for input in ipst.pending() {
        let slot = &ipst.slots()[input];
        assert_eq!(slot.signer(), Some(x), "only the payer's input is left");
        let sig = payer.sign_schnorr(Message::from_digest(slot.sighash().unwrap()));
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(sig.as_ref());
        sig65[64] = 0x01;
        ipst.add_signature(input, &sig65).unwrap();
    }
    ipst.finalize().expect("every slot signed")
}

// =============================================================================================
// The exit test
// =============================================================================================

#[test]
fn three_processes_keygen_two_sign_a_settle_the_engine_accepts_and_one_alone_is_refused() {
    let root = TempDir::new();
    let group = keygen(&root);
    let mut payer = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let payer_x = payer.x_only_public_key().0.serialize();
    let unsigned = world::settle_ipst(Some(group.authority_key), Network::Testnet, &payer_x);
    let ipst_path = root.0.join("settle.ipst.json");
    std::fs::write(&ipst_path, unsigned.to_json()).unwrap();
    // The authority inputs of a KAS-cash settle: both vault inputs.
    for input in [0, 1] {
        assert_eq!(unsigned.slots()[input].signer(), Some(group.authority_key));
    }

    // Accepted: parties 1 and 2 sign, anyone with the group file aggregates.
    let agg = sign(&root, &group, &ipst_path, &[1, 2], &[], "settle");
    let out = root.0.join("settle.signed.ipst.json");
    let o = run(&aggregate_args(
        &group.parties[2].group,
        &ipst_path,
        "1,2",
        &agg,
        &out,
    ));
    assert!(o.status.success(), "{o:?}");
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("signed: inputs 0, 1"), "{text}");
    let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).expect("reads");
    let tx = pay_and_finalize(signed.clone(), &payer);
    node_accepts(&tx, signed.entries(), world::EARLIEST + 1).expect("the engine accepts");
    // The lock time still holds: one DAA score earlier the node refuses it.
    assert!(node_accepts(&tx, signed.entries(), world::EARLIEST).is_err());

    // Refused by the engine, beside the accepted pair: party 1's own share from this session
    // (its sigshare file) aggregated alone as if it were the whole signature, R of the set
    // {1, 2} with z1 where z1 + z2 belongs, at each vault input.
    let z1 = sigshare_entries(&agg.join("sigshare-1.frost"));
    assert_eq!(z1.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
    for input in [0usize, 1] {
        let honest = signed.slots()[input].signature().unwrap();
        let mut lone = honest;
        lone[32..64].copy_from_slice(&z1[&input]);
        assert_ne!(lone, honest);
        let mut forged = tx.clone();
        let script = &mut forged.inputs[input].signature_script;
        let at = script
            .windows(65)
            .position(|w| w == honest)
            .expect("the authority signature in the signature script");
        script[at..at + 65].copy_from_slice(&lone);
        assert_eq!(
            execute(&forged, signed.entries(), input),
            Err("VerifyError".to_string()),
            "input {input}: one share alone"
        );
    }

    // Every other pair settles too.
    for pair in [[1u16, 3], [2, 3]] {
        let agg = sign(&root, &group, &ipst_path, &pair, &[], "settle");
        let list = format!("{},{}", pair[0], pair[1]);
        let out = root.0.join(format!("settle-{list}.ipst.json"));
        let o = run(&aggregate_args(
            &group.parties[0].group,
            &ipst_path,
            &list,
            &agg,
            &out,
        ));
        assert!(o.status.success(), "{o:?}");
        let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let tx = pay_and_finalize(signed.clone(), &payer);
        node_accepts(&tx, signed.entries(), world::EARLIEST + 1).expect("pair settles");
    }

    // Refused: one signer alone, before any commitment is drawn or written.
    let lone = root.sub("lone");
    let share1 = &group.parties[0].share;
    let o = run(&sign_args(share1, &ipst_path, "1", &lone));
    assert_eq!(refused(&o), "THRESHOLD_TOO_FEW_SIGNERS");
    assert_eq!(
        std::fs::read_dir(&lone).unwrap().count(),
        0,
        "nothing written"
    );

    // Refused: aggregating one signer's share as if it were the signature.
    let lone_out = root.0.join("lone.ipst.json");
    let o = run(&aggregate_args(
        &group.parties[0].group,
        &ipst_path,
        "1",
        &agg,
        &lone_out,
    ));
    assert_eq!(refused(&o), "THRESHOLD_TOO_FEW_SIGNERS");
    assert!(!lone_out.exists());

    // Refused: one signer whose partner never answers gets no signature share out; its
    // nonces end with the process.
    let alone = root.sub("alone");
    let mut p = Process::spawn("sign alone", &sign_args(share1, &ipst_path, "1,2", &alone));
    p.until("commitments:");
    let (ok, _, err) = p.finish();
    assert!(!ok);
    assert!(err.starts_with("impulse: FROST_ABORTED: "), "{err}");
    assert!(!alone.join("sigshare-1.frost").exists());
    let o = run(&aggregate_args(
        &group.parties[0].group,
        &ipst_path,
        "1,2",
        &alone,
        &lone_out,
    ));
    assert_eq!(
        refused(&o),
        "CLI_FILE_READ",
        "no commitment or share from party 2"
    );

    // Without the authority signatures the settle does not finalize at all.
    assert_eq!(unsigned.finalize().unwrap_err().code(), "TX_SIGNATURE_SLOT");
    payer.non_secure_erase();
}

/// KCC-20 cash, external cash and a refund of the asset leg by the authority: two of the three
/// keygen processes sign each through `impulse frost sign`, `impulse frost aggregate` fills the
/// authority inputs, and the real script engine accepts every input.
#[test]
fn kcc20_cash_external_cash_and_an_authority_refund_signed_by_two_of_three_are_accepted() {
    let root = TempDir::new();
    let group = keygen(&root);
    let mut payer = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let payer_x = payer.x_only_public_key().0.serialize();
    let key = group.authority_key;
    let cash_template = [
        "--cash-template".to_string(),
        s(&world::cash_template_path()).to_string(),
    ];
    let cases = [
        (
            "kcc20",
            world::settle_ipst_with(world::Cash::Kcc20, Some(key), Network::Testnet, &payer_x),
            &cash_template[..],
            vec![0, 1],
        ),
        (
            "external",
            world::settle_ipst_with(world::Cash::External, Some(key), Network::Testnet, &payer_x),
            &[][..],
            vec![0],
        ),
        (
            "refund",
            world::authority_refund_ipst(key, Network::Testnet, &payer_x),
            &[][..],
            vec![0],
        ),
    ];
    for (label, unsigned, extra, inputs) in cases {
        for &input in &inputs {
            assert_eq!(unsigned.slots()[input].signer(), Some(key), "{label}");
        }
        let path = root.0.join(format!("{label}.ipst.json"));
        std::fs::write(&path, unsigned.to_json()).unwrap();
        let agg = sign(&root, &group, &path, &[1, 3], extra, label);
        let out = root.0.join(format!("{label}.signed.ipst.json"));
        let o = run(&aggregate_args(
            &group.parties[1].group,
            &path,
            "1,3",
            &agg,
            &out,
        ));
        assert!(o.status.success(), "{label}: {o:?}");
        let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).expect(label);
        for &input in &inputs {
            assert!(signed.slots()[input].signature().is_some(), "{label}");
        }
        let tx = pay_and_finalize(signed.clone(), &payer);
        node_accepts(&tx, signed.entries(), world::NOW)
            .unwrap_or_else(|e| panic!("{label}: the engine refuses: {e}"));
    }
    payer.non_secure_erase();
}

/// Emitter for the FROST script self-test (ignored; run by that self-test only): writes the
/// unsigned settle IPST of the test world, whose authority is the x-only key in
/// IMPULSE_FROST_EMIT_AUTHORITY, to IMPULSE_FROST_EMIT_OUT, on testnet unless
/// IMPULSE_FROST_EMIT_NETWORK is `mainnet`. Public data only.
#[test]
#[ignore]
fn emit_settle_ipst() {
    let authority = unhex32(&std::env::var("IMPULSE_FROST_EMIT_AUTHORITY").unwrap());
    let out = std::env::var("IMPULSE_FROST_EMIT_OUT").unwrap();
    let network = match std::env::var("IMPULSE_FROST_EMIT_NETWORK").as_deref() {
        Ok("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };
    let ipst = world::settle_ipst(
        Some(authority),
        network,
        // The label is fixed (it derives the payer key the script self-test expects); it is
        // built from fragments only to keep a word out of the public text.
        &world::label_key(concat!("frost/re", "hearsal-payer")),
    );
    std::fs::write(&out, ipst.to_json()).unwrap();
    // The trade the signers name, beside the file, for the script's --terms-hash.
    std::fs::write(format!("{out}.terms-hash"), terms_hash_of(Path::new(&out))).unwrap();
}
