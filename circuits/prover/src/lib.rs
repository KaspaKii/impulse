// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-zk-prover: proves the list statement of spec/V3-ZK.md section 5.4 on this machine and
//! writes the 128-byte compressed Groth16 proof that template v3 verifies with the Kaspa ZK
//! precompile (tag 0x20, through the kaspa-txscript-zk-sdk fragment at rusty-kaspa a41a333).
//!
//! Pipeline: native pre-check of the statement (no receipt is attempted for a refused input);
//! execution (cycles, segments); succinct receipt with the local prover; `identity_p254`; the
//! Groth16 step in RISC Zero's prover image, pinned by digest and run with no network; the
//! receipt is verified by risc0, then the compressed proof is verified in the pinned Kaspa script
//! engine before anything is written. Error codes are those of spec/V3-ZK.md section 12.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::opcodes::codes::{OpSHA256, OpSwap};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    pay_to_script_hash_script, EngineCtx, EngineFlags, SigCacheKey, TxScriptEngine,
};
use kaspa_txscript_errors::TxScriptError;
use list_core::Sha256 as _;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    local_executor, Digest, ExecutorEnv, ExitCode, Groth16Receipt,
    Groth16ReceiptVerifierParameters, InnerReceipt, LocalProver, Prover, ProverOpts, Receipt,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

pub use list_core;

pub mod fixtures;
pub mod terms;

/// risc0-zkvm version this prover links, pinned `=3.0.4` (circuits/Cargo.toml).
pub const RISC0_ZKVM_VERSION: &str = "3.0.4";
/// Format tag of a proof file.
pub const PROOF_FORMAT: &str = "impulse-zk-proof/1";
/// circuits/IMAGE_ID as committed: the list guest's image ID from the Docker build.
pub const COMMITTED_IMAGE_ID: &str = include_str!("../../IMAGE_ID");
/// circuits/GROTH16_PROVER_IMAGE as committed.
pub const PROVER_IMAGE_PIN: &str = include_str!("../../GROTH16_PROVER_IMAGE");

/// A refusal with its stable code (spec/V3-ZK.md section 12).
#[derive(Debug)]
pub struct ZkError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for ZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ZkError {}

pub(crate) fn err(code: &'static str, message: impl Into<String>) -> ZkError {
    ZkError {
        code,
        message: message.into(),
    }
}

/// SHA-256 on the host.
pub struct HostSha;

impl list_core::Sha256 for HostSha {
    fn hash(data: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(data).into()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    HostSha::hash(data)
}

/// The list guest's image ID as the 32 bytes the template and the zk-sdk fragment use.
pub fn list_guest_image_id() -> [u8; 32] {
    digest_bytes(Digest::from(impulse_zk_methods::LIST_GUEST_ID))
}

pub(crate) fn digest_bytes(d: Digest) -> [u8; 32] {
    d.as_bytes().try_into().expect("32-byte digest")
}

/// The test-only forging guest's image ID (spec/V3-ZK.md section 13.2).
pub fn forge_guest_image_id() -> [u8; 32] {
    digest_bytes(Digest::from(impulse_zk_methods::FORGE_GUEST_ID))
}

/// Refuses unless the embedded list guest is the one circuits/IMAGE_ID names
/// (`ZK_IMAGE_ID_MISMATCH`).
pub fn check_image_id() -> Result<[u8; 32], ZkError> {
    let built = list_guest_image_id();
    let committed = COMMITTED_IMAGE_ID.trim();
    if committed != hex::encode(built) {
        return Err(err(
            "ZK_IMAGE_ID_MISMATCH",
            format!(
                "the built list guest has image ID {}, circuits/IMAGE_ID says {committed}",
                hex::encode(built)
            ),
        ));
    }
    Ok(built)
}

/// A path file: the member's index, salt and the 20 siblings, hex encoded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PathFile {
    pub index: u32,
    pub salt: String,
    pub siblings: Vec<String>,
}

impl PathFile {
    pub fn from_path(p: &list_core::tree::Path) -> PathFile {
        PathFile {
            index: p.index,
            salt: hex::encode(p.salt),
            siblings: p.siblings.iter().map(hex::encode).collect(),
        }
    }
}

fn hex_n<const N: usize>(s: &str, what: &str, code: &'static str) -> Result<[u8; N], ZkError> {
    let v = hex::decode(s).map_err(|_| err(code, format!("{what} is not hex")))?;
    v.try_into()
        .map_err(|_| err(code, format!("{what} is not {N} bytes")))
}

/// Public values of one proof: the list root, the asset vault's scriptPubKey and the buyer
/// delivery owner's scriptPubKey, each in silverscript's form (spec/V3-ZK.md section 5.3).
#[derive(Clone, Debug)]
pub struct Public {
    pub root: [u8; 32],
    pub vault_spk: Vec<u8>,
    pub owner_spk: Vec<u8>,
}

/// Encodes the guest input from a path file and the public values, after checking natively that
/// the statement holds (`ZK_PATH_INVALID` otherwise, with the guest's reason). Returns the input
/// and J.
pub fn guest_input(path: &PathFile, public: &Public) -> Result<(Vec<u8>, Vec<u8>), ZkError> {
    let salt = hex_n::<32>(&path.salt, "salt", "ZK_PATH_INVALID")?;
    let mut sib = Vec::with_capacity(path.siblings.len());
    for s in &path.siblings {
        sib.push(hex_n::<32>(s, "sibling", "ZK_PATH_INVALID")?);
    }
    let input = list_core::tree::encode_input(
        path.index,
        &salt,
        &sib,
        &public.root,
        &public.vault_spk,
        &public.owner_spk,
    );
    let j = list_core::statement::<HostSha>(&input).map_err(|r| {
        err(
            "ZK_PATH_INVALID",
            format!("the list guest would refuse this input: {r:?}"),
        )
    })?;
    Ok((input, j.as_bytes().to_vec()))
}

/// The pinned Groth16 prover image (circuits/GROTH16_PROVER_IMAGE).
#[derive(Clone, Debug)]
pub struct ProverImage {
    pub name: String,
    pub tag: String,
    /// (platform, manifest digest)
    pub platforms: Vec<(String, String)>,
}

impl ProverImage {
    pub fn parse(s: &str) -> Result<ProverImage, ZkError> {
        let mut name = None;
        let mut tag = None;
        let mut platforms = Vec::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| err("ZK_PROVER_IMAGE", "malformed pin line"))?;
            match k.trim() {
                "image" => name = Some(v.trim().to_string()),
                "tag" => tag = Some(v.trim().to_string()),
                k if k.starts_with("linux/") => {
                    let d = v.trim();
                    if !(d.len() == 71
                        && d.starts_with("sha256:")
                        && d[7..].bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        return Err(err("ZK_PROVER_IMAGE", format!("malformed digest for {k}")));
                    }
                    platforms.push((k.to_string(), d.to_string()));
                }
                _ => {}
            }
        }
        Ok(ProverImage {
            name: name.ok_or_else(|| err("ZK_PROVER_IMAGE", "pin names no image"))?,
            tag: tag.ok_or_else(|| err("ZK_PROVER_IMAGE", "pin names no tag"))?,
            platforms,
        })
    }

    /// The platform of the Docker image this host runs natively.
    pub fn host_platform() -> Result<&'static str, ZkError> {
        match std::env::consts::ARCH {
            "aarch64" => Ok("linux/arm64"),
            "x86_64" => Ok("linux/amd64"),
            a => Err(err(
                "ZK_PROVER_IMAGE",
                format!("no pinned prover image for host architecture {a}"),
            )),
        }
    }

    /// `name@digest` for this host's platform.
    pub fn reference(&self) -> Result<(String, &'static str), ZkError> {
        let p = Self::host_platform()?;
        let d = self
            .platforms
            .iter()
            .find(|(k, _)| k == p)
            .ok_or_else(|| err("ZK_PROVER_IMAGE", format!("pin has no digest for {p}")))?;
        Ok((format!("{}@{}", self.name, d.1), p))
    }

    /// Refuses unless the image with the pinned digest is present locally (`ZK_PROVER_IMAGE`).
    /// Nothing is pulled here: the operator pulls by digest, so the content is the pinned one.
    pub fn check_local(&self) -> Result<String, ZkError> {
        let (r, _) = self.reference()?;
        let ok = Command::new("docker")
            .args(["image", "inspect", "--format", "{{.Id}}", &r])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(err(
                "ZK_PROVER_IMAGE",
                format!("the pinned Groth16 prover image is not present locally; pull it by digest: docker pull {r}"),
            ));
        }
        Ok(r)
    }
}

/// Runs the Groth16 step: the identity_p254 seal in, a risc0 Groth16 seal out. The container has
/// no network and sees only a fresh working directory.
pub fn shrink_wrap(
    identity_seal: &[u8],
    image: &ProverImage,
    container: &str,
) -> Result<Vec<u8>, ZkError> {
    // The seal is converted before the image is looked up, so a seal that is not a seal is
    // refused without Docker (ZK_PROVER).
    // `to_json` casts the bytes to words and panics on a length or alignment it cannot cast:
    // a refusal, not a crash.
    let json = std::panic::catch_unwind(|| risc0_groth16::prove::to_json(identity_seal))
        .map_err(|_| err("ZK_PROVER", "the identity seal is not a word-aligned seal"))?
        .map_err(|e| err("ZK_PROVER", format!("seal to json: {e}")))?;
    let r = image.check_local()?;
    let (_, platform) = image.reference()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("impulse-zk-g16-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| err("ZK_PROVER", format!("work dir: {e}")))?;
    let result = (|| {
        std::fs::write(dir.join("input.json"), json)
            .map_err(|e| err("ZK_PROVER", format!("write input: {e}")))?;
        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--platform",
                platform,
                "--name",
                container,
                "-v",
            ])
            .arg(format!("{}:/mnt", dir.display()))
            .arg(&r)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| err("ZK_PROVER", format!("docker: {e}")))?;
        if !out.status.success() {
            return Err(err(
                "ZK_PROVER",
                format!(
                    "the Groth16 prover container failed ({:?}): {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .last()
                        .unwrap_or("")
                ),
            ));
        }
        let pj = std::fs::read_to_string(dir.join("proof.json"))
            .map_err(|e| err("ZK_PROVER", format!("proof.json: {e}")))?;
        let pj: risc0_groth16::ProofJson =
            serde_json::from_str(&pj).map_err(|e| err("ZK_PROVER", format!("proof.json: {e}")))?;
        let seal: risc0_groth16::Seal = pj
            .try_into()
            .map_err(|e| err("ZK_PROVER", format!("proof.json: {e}")))?;
        Ok(seal.to_vec())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Measured figures of one proof, written by `--timings` (spec/V3-ZK.md section 14.2).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Timings {
    pub execute_ms: u128,
    pub total_cycles: u64,
    pub user_cycles: u64,
    pub segments: usize,
    pub succinct_ms: u128,
    pub succinct_receipt_bytes: usize,
    pub identity_p254_ms: u128,
    pub groth16_ms: u128,
    pub groth16_container: String,
    pub proof_bytes: usize,
    pub total_ms: u128,
}

/// A proof file (circuits/README.md, "Proof file").
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofFile {
    pub format: String,
    pub proof: String,
    pub journal: String,
    pub journal_hash: String,
    pub image_id: String,
    pub risc0_zkvm: String,
    pub groth16_prover_image: String,
}

impl ProofFile {
    pub fn proof_bytes(&self) -> Vec<u8> {
        hex::decode(&self.proof).expect("proof hex")
    }
    pub fn journal_bytes(&self) -> Vec<u8> {
        hex::decode(&self.journal).expect("journal hex")
    }
    pub fn image_id_bytes(&self) -> [u8; 32] {
        hex::decode(&self.image_id)
            .expect("image id hex")
            .try_into()
            .expect("32 bytes")
    }
}

/// Proves `elf` on `input` (a byte vector the guest reads with `env::read`), expecting journal
/// `expected_j`, and returns the proof file and the timings. `image_id` must be `elf`'s.
pub fn prove_elf(
    elf: &[u8],
    image_id: [u8; 32],
    input: &[u8],
    expected_j: &[u8],
    image: &ProverImage,
    container: &str,
) -> Result<(ProofFile, Timings), ZkError> {
    let image_ref = image.check_local()?;
    let total = Instant::now();
    let mut t = Timings {
        groth16_container: container.to_string(),
        ..Default::default()
    };
    let input = input.to_vec();
    let env = |input: &Vec<u8>| {
        ExecutorEnv::builder()
            .write(input)
            .and_then(|b| b.build())
            .map_err(|e| err("ZK_PROVER", format!("executor env: {e}")))
    };

    // (a) Execution: cycles and segments.
    let s = Instant::now();
    let info = local_executor()
        .execute(env(&input)?, elf)
        .map_err(|e| err("ZK_PROVER", format!("the guest refused: {e}")))?;
    t.execute_ms = s.elapsed().as_millis();
    if info.exit_code != ExitCode::Halted(0) {
        return Err(err(
            "ZK_PROVER",
            format!("the guest exited with {:?}", info.exit_code),
        ));
    }
    if info.journal.bytes != expected_j {
        return Err(err(
            "ZK_PROVER",
            "the guest committed another journal than expected",
        ));
    }

    // (b) Succinct receipt.
    let s = Instant::now();
    let pi = LocalProver::new("local")
        .prove_with_opts(env(&input)?, elf, &ProverOpts::succinct())
        .map_err(|e| err("ZK_PROVER", format!("succinct proving: {e}")))?;
    t.succinct_ms = s.elapsed().as_millis();
    t.total_cycles = pi.stats.total_cycles;
    t.user_cycles = pi.stats.user_cycles;
    t.segments = pi.stats.segments;
    pi.receipt.verify(image_id).map_err(|e| {
        err(
            "ZK_PROVER",
            format!("succinct receipt does not verify: {e}"),
        )
    })?;
    let succinct = pi
        .receipt
        .inner
        .succinct()
        .map_err(|e| err("ZK_PROVER", format!("not succinct: {e}")))?;
    t.succinct_receipt_bytes = succinct.get_seal_bytes().len();

    // (c) identity_p254, then the Groth16 step in Docker.
    let s = Instant::now();
    let ident = risc0_zkvm::recursion::identity_p254(succinct)
        .map_err(|e| err("ZK_PROVER", format!("identity_p254: {e}")))?;
    t.identity_p254_ms = s.elapsed().as_millis();
    let s = Instant::now();
    let seal = shrink_wrap(&ident.get_seal_bytes(), image, container)?;
    t.groth16_ms = s.elapsed().as_millis();

    let g16 = Groth16Receipt::new(
        seal,
        succinct.claim.clone(),
        Groth16ReceiptVerifierParameters::default().digest(),
    );
    let receipt = Receipt::new(InnerReceipt::Groth16(g16.clone()), expected_j.to_vec());
    receipt
        .verify(image_id)
        .map_err(|e| err("ZK_PROVER", format!("Groth16 receipt does not verify: {e}")))?;
    let proof = kaspa_txscript_zk_sdk::prepare_r0_groth16_proof(&g16)
        .map_err(|e| err("ZK_PROVER", format!("compressed proof: {e}")))?;
    if proof.len() != 128 {
        return Err(err(
            "ZK_PROVER",
            format!("compressed proof is {} bytes, not 128", proof.len()),
        ));
    }
    // The proof must verify in the pinned Kaspa script engine before it is written.
    engine_verify(&proof, expected_j, image_id).map_err(|e| {
        err(
            "ZK_PROVER",
            format!("the pinned Kaspa engine refuses the proof: {e}"),
        )
    })?;
    t.proof_bytes = proof.len();
    t.total_ms = total.elapsed().as_millis();

    let pf = ProofFile {
        format: PROOF_FORMAT.to_string(),
        proof: hex::encode(&proof),
        journal: hex::encode(expected_j),
        journal_hash: hex::encode(sha256(expected_j)),
        image_id: hex::encode(image_id),
        risc0_zkvm: RISC0_ZKVM_VERSION.to_string(),
        groth16_prover_image: image_ref,
    };
    Ok((pf, t))
}

/// Proves the list statement with the list guest.
pub fn prove_membership(
    path: &PathFile,
    public: &Public,
    image: &ProverImage,
    container: &str,
) -> Result<(ProofFile, Timings), ZkError> {
    let image_id = check_image_id()?;
    let (input, j) = guest_input(path, public)?;
    prove_elf(
        impulse_zk_methods::LIST_GUEST_ELF,
        image_id,
        &input,
        &j,
        image,
        container,
    )
}

/// Engine flags of the I20 tests: covenants enabled, as on mainnet after Toccata.
pub fn engine_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    }
}

/// The redeem script of the proof gate alone, as template v3 builds it: J is a script constant
/// here (template v3 builds it from its state), hashed in script with OpSHA256, then the zk-sdk
/// fragment with `image_id`. Stack in: `[proof]`; out: `[true]`.
pub fn gate_redeem_script(journal: &[u8], image_id: [u8; 32]) -> Vec<u8> {
    let mut b = ScriptBuilder::with_flags(engine_flags());
    b.add_data(journal).expect("push J");
    b.add_op(OpSHA256).expect("sha");
    b.add_op(OpSwap).expect("swap");
    kaspa_txscript_zk_sdk::append_r0_groth16_verifier(&mut b, image_id).expect("fragment");
    b.drain()
}

/// Runs a P2SH input whose redeem script is `redeem` and whose signature script pushes `proof`,
/// in the pinned kaspa-txscript engine.
pub fn engine_run(proof: &[u8], redeem: &[u8]) -> Result<(), TxScriptError> {
    let mut sb = ScriptBuilder::with_flags(engine_flags());
    sb.add_data(proof).expect("push proof");
    sb.add_data(redeem).expect("push redeem");
    let sig_script = sb.drain();
    let spk = pay_to_script_hash_script(redeem);
    let input = TransactionInput::new(
        TransactionOutpoint::new(Hash::from_u64_word(0), 0),
        sig_script,
        0,
        0,
    );
    let output = TransactionOutput::new(1_000_000, spk.clone());
    let mut tx = Transaction::new(
        0,
        vec![input],
        vec![output],
        0,
        SubnetworkId::default(),
        0,
        vec![],
    );
    tx.finalize();
    let entry = UtxoEntry::new(1_000_000, spk, 0, false, None);
    let cache: Cache<SigCacheKey, bool> = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(&tx, vec![entry]);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &tx.inputs[0],
        0,
        &populated.entries[0],
        EngineCtx::new(&cache).with_reused(&reused),
        engine_flags(),
    );
    vm.execute()
}

/// Verifies a compressed proof for journal J and an image ID in the pinned engine.
pub fn engine_verify(
    proof: &[u8],
    journal: &[u8],
    image_id: [u8; 32],
) -> Result<(), TxScriptError> {
    engine_run(proof, &gate_redeem_script(journal, image_id))
}

/// Reads a JSON file.
pub fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<T, String> {
    let s = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}
