// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Engine harness for the ImpulseVault tests (I3). Shared by every test target in this crate
//! through `mod harness;`, so silverscript-lang stays a dev-dependency.
//!
//! Compiles SilverScript in process with silverscript-lang at tag v1.0.0 (the same
//! `compile_to_sil_abi_artifact` call the pinned `silverc` binary makes) and executes single
//! transaction inputs through `kaspa_txscript::TxScriptEngine` at rusty-kaspa rev a41a333 with
//! covenants enabled. Engine flags and script-unit limits are built the way consensus builds them
//! in `check_scripts_sequential`: mainnet `mass_per_sig_op` for the sigop price, and the limit
//! each input commits through its compute budget plus the free per-input allowance.
//!
//! Engine pattern adapted from the WarpCore SettlementVault engine harness of the owner, via
//! the I1 spike. Keys: throwaway keypairs are generated from the OS RNG per run, held in memory
//! only, never written or printed, and erased on drop (rule 1 exception, docs/ENGINEERING-RULES.md).

#![allow(dead_code)] // each test target uses a different part of the harness

use std::path::PathBuf;

use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::{
    ComputeBudget, Gram, MassCalculator, ScriptUnits, GRAMS_PER_COMPUTE_BUDGET_UNIT,
};
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32, OpTrue};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
use rand::RngCore;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_abi::{
    encode_contract_covenant_decl_sig_script, encode_contract_entry_sig_script, ArtifactValue,
    SilAbiArtifact, SilContractArtifact,
};
use silverscript_lang::compiler::compile_to_sil_abi_artifact;

#[path = "v4_core.rs"]
pub mod v4_core;

// =============================================================================================
// Constants shared with contracts/impulse_vault.sil
// =============================================================================================

/// KCC-20 owner identifier types (kcc20.sil constants).
pub const IDENTIFIER_PUBKEY: u8 = 0x00;
pub const IDENTIFIER_SCRIPT_HASH: u8 = 0x01;
pub const IDENTIFIER_COVENANT_ID: u8 = 0x02;

/// Cash kinds and funding modes (impulse_vault.sil constants).
pub const CASH_KAS: u8 = 0x00;
pub const CASH_KCC20: u8 = 0x01;
pub const CASH_EXTERNAL: u8 = 0x02;
pub const REVOCABLE: u8 = 0x00;
pub const EARMARKED: u8 = 0x01;

pub const ASSET_LEG: i64 = 0;
pub const CASH_LEG: i64 = 1;

/// Pre-Toccata standardness cap on a transaction's compute mass, in grams:
/// `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA` in kaspa-mining
/// (mining/src/mempool/check_transaction_standard.rs at a41a333, crate-private there).
pub const PRE_TOCCATA_STANDARD_MASS_CAP: u64 = 100_000;

// =============================================================================================
// Sources and compilation
// =============================================================================================

pub fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_source(path: PathBuf) -> String {
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Pinned KCC-20 source, copied unchanged from silverscript v1.0.0.
pub fn kcc20_source() -> String {
    read_source(repo_path("tests/engine/fixtures/kcc20/kcc20.sil"))
}

/// The vault source under test. `IMPULSE_VAULT_SIL` overrides the path; the mutation run
/// (tests/engine/mutation.py) uses it to point every test at a mutant.
pub fn vault_source() -> String {
    match std::env::var_os("IMPULSE_VAULT_SIL") {
        Some(path) => read_source(PathBuf::from(path)),
        None => read_source(repo_path("contracts/impulse_vault.sil")),
    }
}

/// The template v3 source under test (contracts/impulse_vault_v3.sil). `IMPULSE_VAULT_V3_SIL`
/// overrides the path; tests/engine/mutation-v3.py uses it to point every v3 test at a mutant.
pub fn vault_v3_source() -> String {
    match std::env::var_os("IMPULSE_VAULT_V3_SIL") {
        Some(path) => read_source(PathBuf::from(path)),
        None => read_source(repo_path("contracts/impulse_vault_v3.sil")),
    }
}

/// True in a test binary whose name starts with `v3_`: such a binary runs the shared v1 test
/// files (`include!`d by v3_refund.rs) against template v3, so `World::new` builds v3 terms.
/// Any other binary runs template v1, unchanged.
pub fn v3_by_default() -> bool {
    exe_name().is_some_and(|n| n.starts_with("v3_") || n.starts_with("v3p_"))
}

/// True in a test binary whose name starts with `v3p_`: template v3 with its one
/// `r0.g16.verify` call replaced by `require(journalHash == byte[32](proof))`, and every settle
/// carrying sha256(J) as its proof. The shared v1 settle suites run against this probe, so
/// every v1 settle require is tested on the v3 code with a proof the gate accepts. The probe is
/// a different script from template v3 and says nothing about the gate itself.
pub fn v3_probe_by_default() -> bool {
    exe_name().is_some_and(|n| n.starts_with("v3p_"))
}

fn exe_name() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// The template v4 source under test (contracts/impulse_vault_v4.sil). `IMPULSE_VAULT_V4_SIL`
/// overrides the path; tests/engine/mutation-v4.py uses it to point every v4 test at a mutant.
pub fn vault_v4_source() -> String {
    match std::env::var_os("IMPULSE_VAULT_V4_SIL") {
        Some(path) => read_source(PathBuf::from(path)),
        None => read_source(repo_path("contracts/impulse_vault_v4.sil")),
    }
}

pub const VERIFY_LINE_V4: &str = "r0.g16.verify(sha256(head + items), proof, IMAGE_ID);";

fn probe_of(src: String) -> String {
    assert_eq!(src.matches(VERIFY_LINE_V4).count(), 2, "two verify calls");
    src.replace(
        VERIFY_LINE_V4,
        "require(sha256(head + items) == byte[32](proof));",
    )
}

/// The v4 source with both verify calls replaced by a comparison with the witness (probe mode):
/// a settle or refund then carries sha256(J) as its proof. The probe is a different script from
/// template v4 and says nothing about the gate itself; it lets every script require and the whole
/// of the transaction shapes run without a receipt.
pub fn v4_probe_source() -> String {
    probe_of(vault_v4_source())
}

pub const VERIFY_LINE: &str = "r0.g16.verify(journalHash, proof, IMAGE_ID);";

/// The v3 source with the verify call replaced by a comparison with the witness (probe mode).
/// The probe is another script, with another suffix length, so its `SUFFIX_LEN` (which [S10]
/// reads) is set to the probe's own fixed point; everything else is the source under test.
pub fn v3_probe_source() -> String {
    static PROBE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PROBE
        .get_or_init(|| {
            let src = vault_v3_source();
            assert_eq!(src.matches(VERIFY_LINE).count(), 1, "one verify call");
            let ctor =
                std::fs::read_to_string(repo_path("contracts/compiled/impulse_vault.v3.ctor.json"))
                    .expect("ctor args");
            let ctor: Vec<ArtifactValue> =
                serde_json::from_str(&ctor).expect("constructor args JSON");
            with_suffix_fixed_point(
                src.replace(VERIFY_LINE, "require(journalHash == byte[32](proof));"),
                &ctor,
            )
        })
        .clone()
}

const SUFFIX_LEN_DECL: &str = "int constant SUFFIX_LEN = ";

/// The `SUFFIX_LEN` constant written in a v1 or v3 source ([S10]'s layout).
pub fn suffix_len_constant(source: &str) -> usize {
    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with(SUFFIX_LEN_DECL))
        .expect("SUFFIX_LEN constant");
    line.trim_start()
        .trim_start_matches(SUFFIX_LEN_DECL)
        .trim_end_matches(';')
        .parse()
        .expect("SUFFIX_LEN value")
}

/// `source` with its `SUFFIX_LEN` set to the suffix length it compiles to (a fixed point).
pub fn with_suffix_fixed_point(mut source: String, ctor: &[ArtifactValue]) -> String {
    for _ in 0..8 {
        let actual = Compiled::new(&source, ctor).template_lens().1;
        let current = suffix_len_constant(&source);
        if actual == current {
            return source;
        }
        source = source.replacen(
            &format!("{SUFFIX_LEN_DECL}{current};"),
            &format!("{SUFFIX_LEN_DECL}{actual};"),
            1,
        );
    }
    panic!("SUFFIX_LEN did not converge");
}

/// J of a v3 asset vault: tag, list root, the vault's own scriptPubKey, the delivery owner's.
pub fn v3_journal(root: &[u8; 32], vault_spk: &[u8], owner: Owner) -> Vec<u8> {
    let mut j = b"Impulse/zk/wl/v1".to_vec();
    j.extend_from_slice(root);
    j.extend_from_slice(vault_spk);
    if owner.id_type == IDENTIFIER_PUBKEY {
        j.extend_from_slice(&[0, 0, 0x20]);
        j.extend_from_slice(&owner.id);
        j.push(0xac);
    } else {
        j.extend_from_slice(&[0, 0, 0xaa, 0x20]);
        j.extend_from_slice(&owner.id);
        j.push(0x87);
    }
    j
}

/// Terms-v3 fields (spec/V3-ZK.md 7.2): the list issuer key and the list root.
#[derive(Clone, Copy, Debug)]
pub struct ZkTerms {
    pub issuer_key: [u8; 32],
    pub list_root: [u8; 32],
}

/// Placeholder list values for worlds that never run the proof gate (refund tests).
pub const ZK_PLACEHOLDER: ZkTerms = ZkTerms {
    issuer_key: [0x1A; 32],
    list_root: [0x2B; 32],
};

/// One compiled single-contract artifact.
#[derive(Clone)]
pub struct Compiled {
    pub artifact: SilAbiArtifact,
    pub name: String,
    /// Probe mode only (see `v3_probe_by_default`): the proof an `In::settle` of this vault
    /// carries when none is given.
    pub default_proof: Option<Vec<u8>>,
}

impl Compiled {
    /// Compiles with the pinned compiler, exactly as `silverc` does.
    pub fn new(source: &str, ctor: &[ArtifactValue]) -> Self {
        let artifact = compile_to_sil_abi_artifact(source, ctor)
            .unwrap_or_else(|err| panic!("compile: {err}"));
        assert_eq!(artifact.contracts.len(), 1, "expected exactly one contract");
        let name = artifact
            .contracts
            .keys()
            .next()
            .expect("one contract")
            .clone();
        Self {
            artifact,
            name,
            default_proof: None,
        }
    }

    fn contract(&self) -> &SilContractArtifact {
        &self.artifact.contracts[&self.name]
    }

    pub fn bytecode(&self) -> &[u8] {
        &self.contract().compiled.bytecode
    }

    pub fn template_hash(&self) -> [u8; 32] {
        self.contract().compiled.template_hash
    }

    /// (prefix length, suffix length) around the runtime state span.
    pub fn template_lens(&self) -> (usize, usize) {
        let span = &self.contract().compiled.state_span;
        (span.offset, self.bytecode().len() - span.offset - span.len)
    }

    /// Template prefix and suffix bytes (everything outside the state span).
    pub fn template_parts(&self) -> (&[u8], &[u8]) {
        let span = &self.contract().compiled.state_span;
        let code = self.bytecode();
        (&code[..span.offset], &code[span.offset + span.len..])
    }

    pub fn p2sh(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(self.bytecode())
    }

    /// blake2b-256 of the redeem script, read back out of the P2SH scriptPubKey
    /// (OpBlake2b OpData32 <hash> OpEqual), so it is the hash consensus itself uses.
    pub fn script_hash(&self) -> [u8; 32] {
        p2sh_hash(&self.p2sh())
    }

    /// Entry call: KCC-01 encoded args and dispatch tag, then the redeem script push.
    pub fn entry_sigscript(&self, entry: &str, args: &[ArtifactValue]) -> Vec<u8> {
        let mut sigscript =
            encode_contract_entry_sig_script(&self.artifact, &self.name, entry, args)
                .unwrap_or_else(|err| panic!("encode {entry}: {err}"));
        sigscript.extend_from_slice(&push_data(self.bytecode()));
        sigscript
    }

    /// Covenant declaration call (leader or delegate), then the redeem script push.
    pub fn covenant_sigscript(
        &self,
        decl: &str,
        args: &[ArtifactValue],
        is_leader: bool,
    ) -> Vec<u8> {
        let mut sigscript = encode_contract_covenant_decl_sig_script(
            &self.artifact,
            &self.name,
            decl,
            is_leader,
            args,
        )
        .unwrap_or_else(|err| panic!("encode {decl}: {err}"));
        sigscript.extend_from_slice(&push_data(self.bytecode()));
        sigscript
    }
}

pub fn push_data(data: &[u8]) -> Vec<u8> {
    ScriptBuilder::with_flags(engine_flags())
        .add_data(data)
        .expect("push data")
        .drain()
}

/// The 32-byte hash inside a P2SH scriptPubKey.
pub fn p2sh_hash(spk: &ScriptPublicKey) -> [u8; 32] {
    let script = spk.script();
    assert_eq!(script.len(), 35, "P2SH scriptPubKey shape");
    script[2..34].try_into().expect("32-byte hash")
}

/// Schnorr pay-to-pubkey scriptPubKey (OpData32 <x-only key> OpCheckSig), version 0.
pub fn p2pk(key: [u8; 32]) -> ScriptPublicKey {
    let mut script = vec![OpData32];
    script.extend_from_slice(&key);
    script.push(OpCheckSig);
    ScriptPublicKey::new(0, script.into())
}

/// A scriptPubKey as script introspection returns it: version (u16 big-endian), then the script.
pub fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut bytes = spk.version().to_be_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    bytes
}

/// Redeem script of the plain stand-in inputs (fee inputs, foreign UTXOs): OpTrue.
pub fn plain_redeem() -> Vec<u8> {
    vec![OpTrue]
}

pub fn plain_spk() -> ScriptPublicKey {
    pay_to_script_hash_script(&plain_redeem())
}

// =============================================================================================
// KCC-20
// =============================================================================================

/// KCC-20 runtime state (kcc20.sil field order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc20State {
    pub owner: [u8; 32],
    pub id_type: u8,
    pub amount: i64,
    pub is_minter: bool,
}

impl Kcc20State {
    pub fn new(owner: Owner, amount: i64) -> Self {
        Self {
            owner: owner.id,
            id_type: owner.id_type,
            amount,
            is_minter: false,
        }
    }

    pub fn to_value(self) -> ArtifactValue {
        ArtifactValue::Object(
            [
                (
                    "ownerIdentifier".to_string(),
                    ArtifactValue::Bytes(self.owner.to_vec()),
                ),
                (
                    "identifierType".to_string(),
                    ArtifactValue::Byte(self.id_type),
                ),
                ("amount".to_string(), ArtifactValue::Int(self.amount)),
                ("isMinter".to_string(), ArtifactValue::Bool(self.is_minter)),
            ]
            .into_iter()
            .collect(),
        )
    }
}

/// A KCC-20 owner: identifier type and identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub id_type: u8,
    pub id: [u8; 32],
}

impl Owner {
    pub const fn pubkey(id: [u8; 32]) -> Self {
        Self {
            id_type: IDENTIFIER_PUBKEY,
            id,
        }
    }

    pub const fn script_hash(id: [u8; 32]) -> Self {
        Self {
            id_type: IDENTIFIER_SCRIPT_HASH,
            id,
        }
    }

    pub const ZERO: Owner = Owner {
        id_type: 0,
        id: [0; 32],
    };
}

/// One KCC-20 token: its covenant ID and the template constants maxCovIns and maxCovOuts
/// (which select the template, hence the template hash).
#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub cov: Hash,
    pub max_cov_ins: i64,
    pub max_cov_outs: i64,
}

impl Token {
    pub fn compile(&self, state: Kcc20State) -> Compiled {
        Compiled::new(
            &kcc20_source(),
            &[
                ArtifactValue::Bytes(state.owner.to_vec()),
                ArtifactValue::Int(state.amount),
                ArtifactValue::Byte(state.id_type),
                ArtifactValue::Bool(state.is_minter),
                ArtifactValue::Int(self.max_cov_ins),
                ArtifactValue::Int(self.max_cov_outs),
            ],
        )
    }

    /// (template hash, prefix length, suffix length), checked to be independent of the state.
    pub fn template(&self) -> TemplateRef {
        let a = self.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
        let b = self.compile(Kcc20State {
            owner: [7; 32],
            id_type: IDENTIFIER_SCRIPT_HASH,
            amount: 99,
            is_minter: true,
        });
        assert_eq!(a.template_hash(), b.template_hash());
        assert_eq!(a.template_lens(), b.template_lens());
        let (prefix_len, suffix_len) = a.template_lens();
        TemplateRef {
            cov: self.cov,
            hash: a.template_hash(),
            prefix_len: prefix_len as i64,
            suffix_len: suffix_len as i64,
        }
    }
}

/// A token leg as the terms carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateRef {
    pub cov: Hash,
    pub hash: [u8; 32],
    pub prefix_len: i64,
    pub suffix_len: i64,
}

impl TemplateRef {
    pub const ZERO: TemplateRef = TemplateRef {
        cov: Hash::from_bytes([0; 32]),
        hash: [0; 32],
        prefix_len: 0,
        suffix_len: 0,
    };
}

/// KCC-20 `transfer` leader arguments. `sig` is unused for SCRIPT_HASH owners (kcc20.sil
/// authorizes them by the witness input's scriptPubKey), so it is 65 zero bytes.
pub fn transfer_args(new_states: &[Kcc20State], witness: u8) -> Vec<ArtifactValue> {
    vec![
        ArtifactValue::Array(new_states.iter().map(|s| s.to_value()).collect()),
        ArtifactValue::Bytes(vec![0; 65]),
        ArtifactValue::Byte(witness),
    ]
}

// =============================================================================================
// Throwaway keys
// =============================================================================================

/// A throwaway keypair erased when it goes out of scope (rule 1 exception, docs/ENGINEERING-RULES.md).
pub struct TestKey(Keypair);

impl std::ops::Deref for TestKey {
    type Target = Keypair;
    fn deref(&self) -> &Keypair {
        &self.0
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

pub fn random_keypair() -> TestKey {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut bytes);
        if let Ok(mut secret) = SecretKey::from_slice(&bytes) {
            bytes.fill(0);
            let keypair = Keypair::from_secret_key(&secp, &secret);
            secret.non_secure_erase();
            return TestKey(keypair);
        }
    }
}

pub fn xonly(keypair: &Keypair) -> [u8; 32] {
    keypair.x_only_public_key().0.serialize()
}

/// Schnorr signature over the SIG_HASH_ALL sighash of input `idx`, with the sighash byte.
pub fn sign(tx: &Transaction, entries: &[UtxoEntry], idx: usize, keypair: &Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let hash = calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused);
    let msg = Message::from_digest_slice(hash.as_bytes().as_slice()).expect("32-byte sighash");
    let mut sig = keypair.sign_schnorr(msg).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    sig
}

// =============================================================================================
// Engine
// =============================================================================================

/// Engine flags as consensus sets them after Toccata on mainnet.
pub fn engine_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(MAINNET_PARAMS.mass_per_sig_op).into(),
    }
}

/// Result of running one input through the engine.
#[derive(Debug)]
pub struct Run {
    pub result: Result<(), TxScriptError>,
    pub used: ScriptUnits,
}

fn run(tx: &Transaction, entries: &[UtxoEntry], idx: usize, limit: ScriptUnits) -> Run {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(1_000);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(ctx) => ctx,
        Err(err) => {
            return Run {
                result: Err(TxScriptError::from(err)),
                used: ScriptUnits(0),
            }
        }
    };
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
        limit,
    );
    let result = vm.execute();
    Run {
        result,
        used: vm.used_script_units(),
    }
}

/// Runs input `idx` under the script-unit limit its own compute budget commits to, as consensus does.
pub fn execute(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> Run {
    run(
        tx,
        entries,
        idx,
        tx.inputs[idx].compute_commit.allowed_script_units(),
    )
}

/// Runs input `idx` with no script-unit limit, to measure what it consumes.
pub fn measure(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> Run {
    run(tx, entries, idx, ScriptUnits(u64::MAX))
}

/// Non-contextual compute mass of `tx` in grams under mainnet parameters.
pub fn compute_mass(tx: &Transaction) -> u64 {
    MassCalculator::new_with_consensus_params(&MAINNET_PARAMS)
        .calc_non_contextual_masses(tx)
        .compute_mass
}

/// Mainnet per-block compute mass limit in grams.
pub fn block_compute_mass_limit() -> u64 {
    MAINNET_PARAMS.prior_block_mass_limits.compute
}

/// Smallest compute budget whose allowance (budget units plus the free per-input allowance) covers `used`.
pub fn covering_budget(used: ScriptUnits) -> u16 {
    ComputeBudget::checked_covering_script_units(used)
        .expect("fits in u16")
        .value()
}

pub fn budget_grams(budget: u16) -> u64 {
    budget as u64 * GRAMS_PER_COMPUTE_BUDGET_UNIT
}

/// Asserts the refusal is a script verdict (a require or a builtin check failed), not a
/// malformed test transaction or a meter overrun.
pub fn assert_refused(run: &Run, label: &str) {
    assert!(
        matches!(
            run.result,
            Err(TxScriptError::VerifyError) | Err(TxScriptError::EvalFalse)
        ),
        "{label}: expected VerifyError or EvalFalse, got {:?}",
        run.result
    );
}

/// Asserts the refusal came from the lock-time check (OpCheckLockTimeVerify).
pub fn assert_locktime_refused(run: &Run, label: &str) {
    assert!(
        matches!(run.result, Err(TxScriptError::UnsatisfiedLockTime(_))),
        "{label}: expected UnsatisfiedLockTime, got {:?}",
        run.result
    );
}

pub fn assert_accepted(run: &Run, label: &str) {
    assert!(
        run.result.is_ok(),
        "{label}: expected accept, got {:?}",
        run.result
    );
}

// =============================================================================================
// Parties, terms and modes
// =============================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Seller,
    Buyer,
    Authority,
    Stranger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub authority: bool,
    pub cash: u8,
    pub funding: u8,
}

impl Mode {
    pub const fn new(authority: bool, cash: u8, funding: u8) -> Self {
        Self {
            authority,
            cash,
            funding,
        }
    }
}

/// The terms (spec "Terms") in the order and form of the ImpulseVault constructor.
#[derive(Clone, Debug)]
pub struct Terms {
    pub version: u8,
    pub network: u8,
    pub nonce: [u8; 8],
    pub seller_key: [u8; 32],
    pub buyer_key: [u8; 32],
    pub has_authority: bool,
    pub authority_key: [u8; 32],
    pub asset: TemplateRef,
    pub amount_a: i64,
    pub cash_kind: u8,
    pub cash: TemplateRef,
    pub amount_b: i64,
    pub buyer_delivery: Owner,
    pub seller_proceeds: Owner,
    pub seller_proceeds_spk: Vec<u8>,
    pub seller_refund: Owner,
    pub buyer_refund: Owner,
    pub buyer_refund_spk: Vec<u8>,
    pub has_earliest: bool,
    pub earliest_daa: i64,
    pub expiry_daa: i64,
    pub funding_mode: u8,
    pub trade_ref: [u8; 32],
    /// Some: template v3 (version 3, the two list fields after funding_mode).
    pub zk: Option<ZkTerms>,
}

impl Terms {
    pub fn ctor(&self, leg: i64) -> Vec<ArtifactValue> {
        use ArtifactValue::{Bool, Byte, Bytes, Int};
        let owner = |o: Owner| [Byte(o.id_type), Bytes(o.id.to_vec())];
        let tmpl = |t: TemplateRef| {
            [
                Bytes(t.cov.as_bytes().to_vec()),
                Bytes(t.hash.to_vec()),
                Int(t.prefix_len),
                Int(t.suffix_len),
            ]
        };
        let mut v = vec![
            Byte(self.version),
            Byte(self.network),
            Bytes(self.nonce.to_vec()),
            Bytes(self.seller_key.to_vec()),
            Bytes(self.buyer_key.to_vec()),
            Bool(self.has_authority),
            Bytes(self.authority_key.to_vec()),
        ];
        v.extend(tmpl(self.asset));
        v.push(Int(self.amount_a));
        v.push(Byte(self.cash_kind));
        v.extend(tmpl(self.cash));
        v.push(Int(self.amount_b));
        v.extend(owner(self.buyer_delivery));
        v.extend(owner(self.seller_proceeds));
        v.push(Bytes(self.seller_proceeds_spk.clone()));
        v.extend(owner(self.seller_refund));
        v.extend(owner(self.buyer_refund));
        v.push(Bytes(self.buyer_refund_spk.clone()));
        v.extend([
            Bool(self.has_earliest),
            Int(self.earliest_daa),
            Int(self.expiry_daa),
            Byte(self.funding_mode),
        ]);
        if let Some(zk) = self.zk {
            v.push(Bytes(zk.issuer_key.to_vec()));
            v.push(Bytes(zk.list_root.to_vec()));
        }
        v.extend([Bytes(self.trade_ref.to_vec()), Int(leg)]);
        v
    }

    pub fn vault(&self, leg: i64) -> Compiled {
        let Some(zk) = self.zk else {
            return Compiled::new(&vault_source(), &self.ctor(leg));
        };
        if !v3_probe_by_default() {
            return Compiled::new(&vault_v3_source(), &self.ctor(leg));
        }
        let mut c = Compiled::new(&v3_probe_source(), &self.ctor(leg));
        c.default_proof = Some(if leg == ASSET_LEG {
            let j = v3_journal(&zk.list_root, &spk_bytes(&c.p2sh()), self.buyer_delivery);
            sha256(&j).to_vec()
        } else {
            vec![]
        });
        c
    }
}

// Fixture values. Identifiers are placeholders; nothing in these tests spends to them.
pub const ASSET_COV: Hash = Hash::from_bytes([0xA5; 32]);
pub const CASH_COV: Hash = Hash::from_bytes([0xCA; 32]);
pub const DECOY_COV: Hash = Hash::from_bytes([0xD0; 32]);
/// Asset and cash tokens run different KCC-20 templates (different maxCovOuts), so a vault
/// that mixed up the two legs' templates would be caught.
pub const ASSET_TOKEN: Token = Token {
    cov: ASSET_COV,
    max_cov_ins: 2,
    max_cov_outs: 2,
};
pub const CASH_TOKEN: Token = Token {
    cov: CASH_COV,
    max_cov_ins: 2,
    max_cov_outs: 3,
};
pub const AMOUNT_A: i64 = 1_000;
/// KCC-20 cash amount, or sompi for KAS cash.
pub const AMOUNT_B: i64 = 250_000;
pub const EARLIEST_DAA: u64 = 1_000_000;
pub const EXPIRY_DAA: u64 = 2_000_000;
pub const NON_FINAL: u64 = 0;
/// KAS on an authorizer UTXO, on a token UTXO, on a fee input.
pub const AUTH_VALUE: u64 = 20_000;
pub const TOKEN_VALUE: u64 = 30_000;
pub const FEE_VALUE: u64 = 100_000;
/// Large enough that a refusal can only come from the script, never from the meter.
pub const GENEROUS_BUDGET: u16 = 1_000;
/// As `GENEROUS_BUDGET` for a template v3 settle, whose proof gate alone costs more than
/// 15,000,000 script units (V3-ZK.md 3.4): 3,000 budget units allow 30,000,000.
pub const GENEROUS_BUDGET_V3: u16 = 3_000;
pub const BUYER_DELIVERY: Owner = Owner::pubkey([0xB1; 32]);
pub const SELLER_PROCEEDS: Owner = Owner::pubkey([0x51; 32]);
pub const SELLER_REFUND: Owner = Owner::pubkey([0x52; 32]);
pub const BUYER_REFUND: Owner = Owner::script_hash([0xB2; 32]);
pub const STRANGER_OWNER: Owner = Owner::pubkey([0x5E; 32]);

pub fn seller_proceeds_kas_spk() -> ScriptPublicKey {
    p2pk([0x53; 32])
}

pub fn buyer_refund_kas_spk() -> ScriptPublicKey {
    pay_to_script_hash_script(&[0xB3; 40])
}

pub fn stranger_spk() -> ScriptPublicKey {
    p2pk([0x5F; 32])
}

/// Everything one test needs: the parties' throwaway keys, the terms for a mode, both vaults.
pub struct World {
    pub mode: Mode,
    pub terms: Terms,
    pub asset_vault: Compiled,
    /// None in external-cash mode (there is no cash vault).
    pub cash_vault: Option<Compiled>,
    /// Template v3: the proof the asset vault's settle carries (the cash vault carries none).
    pub proof: Vec<u8>,
    keys: [TestKey; 4],
}

impl World {
    pub fn new(mode: Mode) -> Self {
        let keys = [
            random_keypair(),
            random_keypair(),
            random_keypair(),
            random_keypair(),
        ];
        let terms = terms_for(mode, &keys);
        Self::with_terms(mode, terms, keys)
    }

    /// The world for `mode`, with the terms changed by `edit` before the vaults are compiled.
    pub fn with(mode: Mode, edit: impl FnOnce(&mut Terms, &Self)) -> Self {
        let base = Self::new(mode);
        let mut terms = base.terms.clone();
        edit(&mut terms, &base);
        let World { keys, .. } = base;
        Self::with_terms(mode, terms, keys)
    }

    /// The same parties (same keys) with the terms changed by `edit`.
    pub fn edit(self, edit: impl FnOnce(&mut Terms)) -> Self {
        let World {
            mode,
            mut terms,
            keys,
            ..
        } = self;
        edit(&mut terms);
        Self::with_terms(mode, terms, keys)
    }

    /// Another trade between the same parties (copies of the same throwaway keys, each copy
    /// erased on drop), with the terms changed by `edit`.
    pub fn sibling(&self, edit: impl FnOnce(&mut Terms)) -> Self {
        let keys = [0, 1, 2, 3].map(|i| TestKey(*self.keys[i]));
        let mut terms = self.terms.clone();
        edit(&mut terms);
        Self::with_terms(self.mode, terms, keys)
    }

    fn with_terms(mode: Mode, terms: Terms, keys: [TestKey; 4]) -> Self {
        let asset_vault = terms.vault(ASSET_LEG);
        let cash_vault = (mode.cash != CASH_EXTERNAL).then(|| terms.vault(CASH_LEG));
        Self {
            mode,
            terms,
            asset_vault,
            cash_vault,
            proof: vec![],
            keys,
        }
    }

    /// The same parties and tokens with other vaults (template v4): the escrow owners and the
    /// vault inputs of `settle()` and `refund()` follow the vaults given.
    pub fn with_vaults(mut self, asset: Compiled, cash: Option<Compiled>) -> Self {
        self.asset_vault = asset;
        self.cash_vault = cash;
        self
    }

    /// The same world, its asset vault's settle carrying `proof` (template v3).
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = proof;
        self
    }

    pub fn is_v3(&self) -> bool {
        self.terms.zk.is_some()
    }

    pub fn key(&self, role: Role) -> &Keypair {
        &self.keys[role as usize]
    }

    pub fn xonly(&self, role: Role) -> [u8; 32] {
        xonly(self.key(role))
    }

    pub fn cash_vault(&self) -> &Compiled {
        self.cash_vault
            .as_ref()
            .expect("this mode has a cash vault")
    }

    pub fn vault(&self, leg: i64) -> &Compiled {
        if leg == ASSET_LEG {
            &self.asset_vault
        } else {
            self.cash_vault()
        }
    }

    pub fn external(&self) -> bool {
        self.mode.cash == CASH_EXTERNAL
    }

    /// Canonical input index of the escrowed asset token.
    pub fn asset_escrow_idx(&self) -> usize {
        if self.external() {
            1
        } else {
            2
        }
    }

    pub const CASH_ESCROW_IDX: usize = 3;

    /// The escrowed asset token: owned by the asset vault's script hash, exactly amount_a.
    pub fn asset_escrow_state(&self) -> Kcc20State {
        Kcc20State::new(
            Owner::script_hash(self.asset_vault.script_hash()),
            self.terms.amount_a,
        )
    }

    pub fn cash_escrow_state(&self) -> Kcc20State {
        Kcc20State::new(
            Owner::script_hash(self.cash_vault().script_hash()),
            self.terms.amount_b,
        )
    }

    pub fn delivered_asset(&self) -> Kcc20State {
        Kcc20State::new(self.terms.buyer_delivery, self.terms.amount_a)
    }

    pub fn delivered_cash(&self) -> Kcc20State {
        Kcc20State::new(self.terms.seller_proceeds, self.terms.amount_b)
    }

    /// The canonical settle transaction for this world's mode (spec "Canonical settle
    /// transaction"), with a fee input and a change output after the trade positions.
    pub fn settle(&self) -> TxSpec {
        let signer = self.mode.authority.then_some(Role::Authority);
        let asset_escrow = self.asset_escrow_idx() as u16;
        let mut inputs = vec![if self.is_v3() && !v3_probe_by_default() {
            In::settle_v3(&self.asset_vault, signer, AUTH_VALUE, self.proof.clone())
        } else {
            In::settle(&self.asset_vault, signer, AUTH_VALUE)
        }];
        let mut outputs = vec![Out::token(
            ASSET_TOKEN.compile(self.delivered_asset()),
            ASSET_COV,
            asset_escrow,
        )];
        match self.mode.cash {
            CASH_KAS => {
                inputs.push(self.cash_settle_input(signer, self.terms.amount_b as u64));
                outputs.push(Out::kas(
                    self.terms.amount_b as u64,
                    seller_proceeds_kas_spk(),
                ));
            }
            CASH_KCC20 => {
                inputs.push(self.cash_settle_input(signer, AUTH_VALUE));
                outputs.push(Out::token(
                    CASH_TOKEN.compile(self.delivered_cash()),
                    CASH_COV,
                    Self::CASH_ESCROW_IDX as u16,
                ));
            }
            _ => {}
        }
        inputs.push(In::token(
            ASSET_TOKEN.compile(self.asset_escrow_state()),
            ASSET_COV,
            vec![self.delivered_asset()],
            0,
        ));
        outputs.push(Out::kas(AUTH_VALUE, p2pk(self.terms.seller_key)));
        if self.mode.cash == CASH_KCC20 {
            inputs.push(In::token(
                CASH_TOKEN.compile(self.cash_escrow_state()),
                CASH_COV,
                vec![self.delivered_cash()],
                1,
            ));
            outputs.push(Out::kas(AUTH_VALUE, p2pk(self.terms.buyer_key)));
        }
        inputs.push(In::plain(FEE_VALUE));
        outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
        TxSpec {
            inputs,
            outputs,
            lock_time: EARLIEST_DAA,
        }
    }

    /// The cash vault's settle input: under template v3 with an empty proof ([Z2]).
    fn cash_settle_input(&self, signer: Option<Role>, value: u64) -> In {
        if self.is_v3() && !v3_probe_by_default() {
            In::settle_v3(self.cash_vault(), signer, value, vec![])
        } else {
            In::settle(self.cash_vault(), signer, value)
        }
    }

    /// A refund of one vault UTXO of `leg`, signed by `signer` (named as itself). For a KCC-20
    /// leg the escrowed token rides at input 1 and returns home at output 1.
    pub fn refund(&self, leg: i64, signer: Role) -> TxSpec {
        let vault = self.vault(leg);
        let named = self.xonly(signer);
        let is_asset = leg == ASSET_LEG;
        let kas_cash = !is_asset && self.mode.cash == CASH_KAS;
        let value = if kas_cash {
            self.terms.amount_b as u64
        } else {
            AUTH_VALUE
        };
        let depositor = if is_asset { Role::Seller } else { Role::Buyer };
        let home_spk = if kas_cash {
            buyer_refund_kas_spk()
        } else {
            p2pk(self.xonly(depositor))
        };
        let mut inputs = vec![In::refund(vault, named, signer, value)];
        let mut outputs = vec![Out::kas(value, home_spk)];
        let token_leg = is_asset || self.mode.cash == CASH_KCC20;
        if token_leg {
            let (token, escrow, home) = if is_asset {
                (
                    ASSET_TOKEN,
                    self.asset_escrow_state(),
                    Kcc20State::new(self.terms.seller_refund, self.terms.amount_a),
                )
            } else {
                (
                    CASH_TOKEN,
                    self.cash_escrow_state(),
                    Kcc20State::new(self.terms.buyer_refund, self.terms.amount_b),
                )
            };
            inputs.push(In::token(token.compile(escrow), token.cov, vec![home], 0));
            outputs.push(Out::token(token.compile(home), token.cov, 1));
        }
        inputs.push(In::plain(FEE_VALUE));
        outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
        let lock_time = if self.mode.funding == EARMARKED && signer == depositor {
            EXPIRY_DAA
        } else {
            0
        };
        TxSpec {
            inputs,
            outputs,
            lock_time,
        }
    }
}

fn terms_for(mode: Mode, keys: &[TestKey; 4]) -> Terms {
    let kas = mode.cash == CASH_KAS;
    let kcc20 = mode.cash == CASH_KCC20;
    let v3 = v3_by_default();
    Terms {
        version: if v3 { 3 } else { 1 },
        network: 0,
        nonce: [0x4E; 8],
        seller_key: xonly(&keys[Role::Seller as usize]),
        buyer_key: xonly(&keys[Role::Buyer as usize]),
        has_authority: mode.authority,
        authority_key: if mode.authority {
            xonly(&keys[Role::Authority as usize])
        } else {
            [0; 32]
        },
        asset: ASSET_TOKEN.template(),
        amount_a: AMOUNT_A,
        cash_kind: mode.cash,
        cash: if kcc20 {
            CASH_TOKEN.template()
        } else {
            TemplateRef::ZERO
        },
        amount_b: AMOUNT_B,
        buyer_delivery: BUYER_DELIVERY,
        seller_proceeds: if kcc20 { SELLER_PROCEEDS } else { Owner::ZERO },
        seller_proceeds_spk: if kas {
            spk_bytes(&seller_proceeds_kas_spk())
        } else {
            vec![]
        },
        seller_refund: SELLER_REFUND,
        buyer_refund: if kcc20 { BUYER_REFUND } else { Owner::ZERO },
        buyer_refund_spk: if kas {
            spk_bytes(&buyer_refund_kas_spk())
        } else {
            vec![]
        },
        has_earliest: true,
        earliest_daa: EARLIEST_DAA as i64,
        expiry_daa: EXPIRY_DAA as i64,
        funding_mode: mode.funding,
        trade_ref: [0x7E; 32],
        zk: v3.then_some(ZK_PLACEHOLDER),
    }
}

// =============================================================================================
// Transactions as data: build a canonical one, change one thing, run every input
// =============================================================================================

#[derive(Clone)]
pub enum Spend {
    /// P2SH(OpTrue): fee inputs and foreign stand-ins.
    Plain,
    /// ImpulseVault `settle`; the signer's key makes authSig, else 65 zero bytes.
    Settle {
        vault: Compiled,
        signer: Option<Role>,
        /// Some: template v3, whose `settle` takes the proof as a second witness item.
        proof: Option<Vec<u8>>,
    },
    /// Template v4 `settle`: the authority's signature (or 65 zero bytes), the proof, the view
    /// sizes and the two covenant IDs the script hashes into J.
    SettleV4 {
        vault: Compiled,
        signer: Option<Role>,
        proof: Vec<u8>,
        n_in: i64,
        n_out: i64,
        cov_a: [u8; 32],
        cov_c: [u8; 32],
    },
    /// Template v4 `refund`: `named` is the signer pubkey argument, `signer` makes the signature.
    RefundV4 {
        vault: Compiled,
        named: [u8; 32],
        signer: Option<Role>,
        leg: u8,
        proof: Vec<u8>,
        n_in: i64,
        n_out: i64,
        cov: [u8; 32],
    },
    /// ImpulseVault `refund`: `named` is the pubkey argument, `signer` makes the signature.
    Refund {
        vault: Compiled,
        named: [u8; 32],
        signer: Role,
    },
    /// KCC-20 `transfer` as covenant leader.
    Kcc20Leader {
        redeem: Compiled,
        new_states: Vec<Kcc20State>,
        witness: u8,
    },
    /// KCC-20 `transfer` as covenant delegate.
    Kcc20Delegate { redeem: Compiled, witness: u8 },
}

#[derive(Clone)]
pub struct In {
    pub spend: Spend,
    pub value: u64,
    pub spk: ScriptPublicKey,
    pub cov: Option<Hash>,
    pub sequence: u64,
    pub budget: u16,
}

impl In {
    pub fn plain(value: u64) -> Self {
        Self {
            spend: Spend::Plain,
            value,
            spk: plain_spk(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn settle(vault: &Compiled, signer: Option<Role>, value: u64) -> Self {
        Self {
            spend: Spend::Settle {
                vault: vault.clone(),
                signer,
                proof: None,
            },
            value,
            spk: vault.p2sh(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// Template v3 `settle`: the proof rides as the second witness item (empty for a cash vault).
    pub fn settle_v3(vault: &Compiled, signer: Option<Role>, value: u64, proof: Vec<u8>) -> Self {
        let mut input = Self::settle(vault, signer, value);
        input.budget = GENEROUS_BUDGET_V3;
        input.spend = Spend::Settle {
            vault: vault.clone(),
            signer,
            proof: Some(proof),
        };
        input
    }

    /// Template v4 `settle` (see `Spend::SettleV4`).
    pub fn settle_v4(
        vault: &Compiled,
        signer: Option<Role>,
        value: u64,
        proof: Vec<u8>,
        (n_in, n_out): (i64, i64),
        (cov_a, cov_c): ([u8; 32], [u8; 32]),
    ) -> Self {
        let mut input = Self::settle(vault, signer, value);
        input.budget = GENEROUS_BUDGET_V3;
        input.spend = Spend::SettleV4 {
            vault: vault.clone(),
            signer,
            proof,
            n_in,
            n_out,
            cov_a,
            cov_c,
        };
        input
    }

    /// Template v4 `refund` (see `Spend::RefundV4`).
    #[allow(clippy::too_many_arguments)]
    pub fn refund_v4(
        vault: &Compiled,
        named: [u8; 32],
        signer: Option<Role>,
        value: u64,
        leg: u8,
        proof: Vec<u8>,
        (n_in, n_out): (i64, i64),
        cov: [u8; 32],
    ) -> Self {
        let mut input = Self::settle(vault, None, value);
        input.budget = GENEROUS_BUDGET_V3;
        input.spend = Spend::RefundV4 {
            vault: vault.clone(),
            named,
            signer,
            leg,
            proof,
            n_in,
            n_out,
            cov,
        };
        input
    }

    pub fn refund(vault: &Compiled, named: [u8; 32], signer: Role, value: u64) -> Self {
        Self {
            spend: Spend::Refund {
                vault: vault.clone(),
                named,
                signer,
            },
            value,
            spk: vault.p2sh(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// A KCC-20 UTXO of covenant `cov` spent as transfer leader, the witness at input `witness`.
    pub fn token(redeem: Compiled, cov: Hash, new_states: Vec<Kcc20State>, witness: u8) -> Self {
        Self {
            spk: redeem.p2sh(),
            spend: Spend::Kcc20Leader {
                redeem,
                new_states,
                witness,
            },
            value: TOKEN_VALUE,
            cov: Some(cov),
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// A KCC-20 UTXO of covenant `cov` spent as transfer delegate.
    pub fn token_delegate(redeem: Compiled, cov: Hash, witness: u8) -> Self {
        Self {
            spk: redeem.p2sh(),
            spend: Spend::Kcc20Delegate { redeem, witness },
            value: TOKEN_VALUE,
            cov: Some(cov),
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// The redeem script this input carries, if it is a vault or a token.
    pub fn redeem_len(&self) -> usize {
        match &self.spend {
            Spend::Plain => plain_redeem().len(),
            Spend::Settle { vault, .. }
            | Spend::Refund { vault, .. }
            | Spend::SettleV4 { vault, .. }
            | Spend::RefundV4 { vault, .. } => vault.bytecode().len(),
            Spend::Kcc20Leader { redeem, .. } | Spend::Kcc20Delegate { redeem, .. } => {
                redeem.bytecode().len()
            }
        }
    }
}

#[derive(Clone)]
pub struct Out {
    pub value: u64,
    pub spk: ScriptPublicKey,
    pub cov: Option<CovenantBinding>,
}

impl Out {
    pub fn kas(value: u64, spk: ScriptPublicKey) -> Self {
        Self {
            value,
            spk,
            cov: None,
        }
    }

    pub fn token(script: Compiled, cov: Hash, authorizing_input: u16) -> Self {
        Self {
            value: TOKEN_VALUE,
            spk: script.p2sh(),
            cov: Some(CovenantBinding {
                authorizing_input,
                covenant_id: cov,
            }),
        }
    }
}

#[derive(Clone)]
pub struct TxSpec {
    pub inputs: Vec<In>,
    pub outputs: Vec<Out>,
    pub lock_time: u64,
}

impl TxSpec {
    /// Materializes the transaction, then signs every vault input that needs a signature
    /// (sighashes do not commit to signature scripts, so signing after assembly is exact).
    pub fn build(&self, w: &World) -> (Transaction, Vec<UtxoEntry>) {
        let entries: Vec<UtxoEntry> = self
            .inputs
            .iter()
            .map(|i| UtxoEntry::new(i.value, i.spk.clone(), 0, false, i.cov))
            .collect();
        let inputs: Vec<TransactionInput> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(n, i)| {
                TransactionInput::new_with_compute_budget(
                    TransactionOutpoint {
                        transaction_id: TransactionId::from_bytes([n as u8 + 1; 32]),
                        index: 0,
                    },
                    vec![],
                    i.sequence,
                    i.budget,
                )
            })
            .collect();
        let outputs: Vec<TransactionOutput> = self
            .outputs
            .iter()
            .map(|o| TransactionOutput {
                value: o.value,
                script_public_key: o.spk.clone(),
                covenant: o.cov,
            })
            .collect();
        let mut tx = Transaction::new(
            1,
            inputs,
            outputs,
            self.lock_time,
            Default::default(),
            0,
            vec![],
        );
        let unsigned = tx.clone();
        for (n, i) in self.inputs.iter().enumerate() {
            tx.inputs[n].signature_script = match &i.spend {
                Spend::Plain => push_data(&plain_redeem()),
                Spend::Settle {
                    vault,
                    signer,
                    proof,
                } => {
                    let sig = match signer {
                        Some(role) => sign(&unsigned, &entries, n, w.key(*role)),
                        None => vec![0; 65],
                    };
                    let mut args = vec![ArtifactValue::Bytes(sig)];
                    if let Some(proof) = proof.as_ref().or(vault.default_proof.as_ref()) {
                        args.push(ArtifactValue::Bytes(proof.clone()));
                    }
                    vault.entry_sigscript("settle", &args)
                }
                Spend::SettleV4 {
                    vault,
                    signer,
                    proof,
                    n_in,
                    n_out,
                    cov_a,
                    cov_c,
                } => {
                    let sig = match signer {
                        Some(role) => sign(&unsigned, &entries, n, w.key(*role)),
                        None => vec![0; 65],
                    };
                    vault.entry_sigscript(
                        "settle",
                        &[
                            ArtifactValue::Bytes(sig),
                            ArtifactValue::Bytes(proof.clone()),
                            ArtifactValue::Int(*n_in),
                            ArtifactValue::Int(*n_out),
                            ArtifactValue::Bytes(cov_a.to_vec()),
                            ArtifactValue::Bytes(cov_c.to_vec()),
                        ],
                    )
                }
                Spend::RefundV4 {
                    vault,
                    named,
                    signer,
                    leg,
                    proof,
                    n_in,
                    n_out,
                    cov,
                } => {
                    let sig = match signer {
                        Some(role) => sign(&unsigned, &entries, n, w.key(*role)),
                        None => vec![0; 65],
                    };
                    vault.entry_sigscript(
                        "refund",
                        &[
                            ArtifactValue::Bytes(sig),
                            ArtifactValue::Bytes(named.to_vec()),
                            ArtifactValue::Byte(*leg),
                            ArtifactValue::Bytes(proof.clone()),
                            ArtifactValue::Int(*n_in),
                            ArtifactValue::Int(*n_out),
                            ArtifactValue::Bytes(cov.to_vec()),
                        ],
                    )
                }
                Spend::Refund {
                    vault,
                    named,
                    signer,
                } => {
                    let sig = sign(&unsigned, &entries, n, w.key(*signer));
                    vault.entry_sigscript(
                        "refund",
                        &[
                            ArtifactValue::Bytes(sig),
                            ArtifactValue::Bytes(named.to_vec()),
                        ],
                    )
                }
                Spend::Kcc20Leader {
                    redeem,
                    new_states,
                    witness,
                } => redeem.covenant_sigscript(
                    "transfer",
                    &transfer_args(new_states, *witness),
                    true,
                ),
                Spend::Kcc20Delegate { redeem, witness } => redeem.covenant_sigscript(
                    "transfer",
                    &[
                        ArtifactValue::Bytes(vec![0; 65]),
                        ArtifactValue::Byte(*witness),
                    ],
                    false,
                ),
            };
        }
        tx.finalize();
        (tx, entries)
    }

    pub fn run(&self, w: &World, idx: usize) -> Run {
        let (tx, entries) = self.build(w);
        let run = execute(&tx, &entries, idx);
        if v4_core::shadow_by_default() {
            v4_core::shadow_check(self, w, idx, run.result.is_ok());
        }
        run
    }

    /// Every input except the plain ones, accepted.
    pub fn assert_all_accepted(&self, w: &World, label: &str) {
        let (tx, entries) = self.build(w);
        for (n, i) in self.inputs.iter().enumerate() {
            if !matches!(i.spend, Spend::Plain) {
                let run = execute(&tx, &entries, n);
                if v4_core::shadow_by_default() {
                    v4_core::shadow_check(self, w, n, run.result.is_ok());
                }
                assert_accepted(&run, &format!("{label}: input {n}"));
            }
        }
    }
}

/// The control must be accepted at input `idx` and the faulty transaction refused there by
/// the script. Every refusal test goes through this, so each fault has an accepted twin.
pub fn assert_flips(w: &World, control: &TxSpec, faulty: &TxSpec, idx: usize, label: &str) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_refused(&faulty.run(w, idx), label);
}

/// As `assert_flips`, for a refusal by the lock-time check.
pub fn assert_flips_locktime(
    w: &World,
    control: &TxSpec,
    faulty: &TxSpec,
    idx: usize,
    label: &str,
) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_locktime_refused(&faulty.run(w, idx), label);
}

// =============================================================================================
// Measurement: exact covering compute budget, proven at the boundary
// =============================================================================================

pub struct Measure {
    pub label: String,
    pub redeem_bytes: usize,
    pub sigscript_bytes: usize,
    pub script_units: u64,
    pub budget: u16,
}

/// Measures input `idx` of `spec`, then proves it passes at exactly the covering compute budget
/// and is refused with ExceededCommittedScriptUnits one budget unit below.
pub fn prove_budget(w: &World, spec: &TxSpec, idx: usize, label: &str) -> Measure {
    let (tx, entries) = spec.build(w);
    let unbounded = measure(&tx, &entries, idx);
    assert_accepted(&unbounded, label);
    let budget = covering_budget(unbounded.used);

    let mut at = spec.clone();
    at.inputs[idx].budget = budget;
    let (tx, entries) = at.build(w);
    let exact = execute(&tx, &entries, idx);
    assert_accepted(&exact, label);
    assert_eq!(
        exact.used, unbounded.used,
        "{label}: units must not depend on the committed budget"
    );

    if budget > 0 {
        let mut below = spec.clone();
        below.inputs[idx].budget = budget - 1;
        let (btx, bentries) = below.build(w);
        let short = execute(&btx, &bentries, idx);
        assert!(
            matches!(
                short.result,
                Err(TxScriptError::ExceededCommittedScriptUnits { .. })
            ),
            "{label}: one budget unit below must exceed the meter, got {:?}",
            short.result
        );
    }
    Measure {
        label: label.to_string(),
        redeem_bytes: spec.inputs[idx].redeem_len(),
        sigscript_bytes: tx.inputs[idx].signature_script.len(),
        script_units: unbounded.used.0,
        budget,
    }
}

/// Sets every non-plain input of `spec` to its exact covering budget (plain inputs need none),
/// checks every input still passes, and returns the per-input budgets and the transaction's
/// compute mass in grams.
pub fn tighten(w: &World, spec: &TxSpec) -> (TxSpec, Vec<u16>, u64) {
    let (tx, entries) = spec.build(w);
    let mut tight = spec.clone();
    for (n, i) in tight.inputs.iter_mut().enumerate() {
        i.budget = covering_budget(measure(&tx, &entries, n).used);
    }
    let (tx, entries) = tight.build(w);
    for n in 0..tight.inputs.len() {
        assert_accepted(&execute(&tx, &entries, n), &format!("tight input {n}"));
    }
    let budgets = tight.inputs.iter().map(|i| i.budget).collect();
    let mass = compute_mass(&tx);
    (tight, budgets, mass)
}

pub fn print_rows(rows: &[Measure]) {
    eprintln!("| Spend | Redeem script (bytes) | Sigscript (bytes) | Script units | Compute budget (units) | Budget mass (grams) |");
    eprintln!("| --- | --- | --- | --- | --- | --- |");
    for m in rows {
        eprintln!(
            "| {} | {} | {} | {} | {} | {} |",
            m.label,
            m.redeem_bytes,
            m.sigscript_bytes,
            m.script_units,
            m.budget,
            budget_grams(m.budget)
        );
    }
}

pub fn print_tx_mass(label: &str, budgets: &[u16], mass: u64) {
    eprintln!(
        "{label}: budgets {budgets:?}, compute mass {mass} grams; pre-Toccata standard cap {} grams ({:.1}%); mainnet block compute limit {} grams",
        PRE_TOCCATA_STANDARD_MASS_CAP,
        100.0 * mass as f64 / PRE_TOCCATA_STANDARD_MASS_CAP as f64,
        block_compute_mass_limit()
    );
}

// =============================================================================================
// SHA-256 and hex, for the v3 journal
// =============================================================================================

/// A small self-contained SHA-256 (FIPS 180-4), so the harness takes no new dependency.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
