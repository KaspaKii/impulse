// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashed-terms vault, template v4 (spec/V3-ZK.md section 22), on the verifier side: the
//! embedded template and its startup check, the vault of a terms commitment, the state decode,
//! and `check_revealed`, which takes a revealed terms file and an accepted transaction and runs
//! the `terms-core` statement on the view the vault's script hashed (what the guest proves,
//! without a proof). Off by default (feature `zk-hashed`). Keyless: nothing here signs.

use crate::terms::Network;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{
    decode_runtime_state_script, encode_runtime_state_script, template_hash, ArtifactValue,
    SilAbiArtifact,
};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;
use terms_core::codec as tc;
use terms_core::hashes as th;
use terms_core::journal::{Item, Journal, Mode};

pub const CONTRACT_NAME_V4: &str = "ImpulseVaultV4";

const ARTIFACT_JSON: &str = include_str!("../../../../contracts/compiled/impulse_vault.v4.json");
const TEMPLATE_HASH_FILE: &str = include_str!("../../../../contracts/TEMPLATE_HASH_V4");
const IMAGE_ID_FILE: &str = include_str!("../../../../circuits/IMAGE_ID_V4");

/// Every `ZK_H_` code of spec/V3-ZK.md 22.8, in order (27 to 45). Frozen once merged.
pub const ZKH_ERROR_CODES: [&str; 19] = [
    "ZK_H_TERMS_VERSION",
    "ZK_H_TERMS_DIRECT",
    "ZK_H_AUTHORITY_REQUIRED",
    "ZK_H_BLIND_INVALID",
    "ZK_H_ARTIFACT_INVALID",
    "ZK_H_TEMPLATE_HASH_MISMATCH",
    "ZK_H_NOT_V4_VAULT",
    "ZK_H_STATE_MALFORMED",
    "ZK_H_NONCANONICAL",
    "ZK_H_TERMS_MISMATCH",
    "ZK_H_STATEMENT_FALSE",
    "ZK_H_WITNESS_INVALID",
    "ZK_H_SHAPE",
    "ZK_H_PROOF_MALFORMED",
    "ZK_H_PROOF_INVALID",
    "ZK_H_IPST_VERSION",
    "ZK_H_VERIFY_ADDRESS_MISMATCH",
    "ZK_H_TERMS_FILE",
    "ZK_H_CAP_OVERRIDE",
];

/// A refusal with its stable `ZK_H_` code (or the v1 `TERMS_` code the terms-core structure
/// check names) and a reason. Integrators match on `code()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkhError {
    code: &'static str,
    reason: String,
    min_fee: Option<u64>,
}

impl ZkhError {
    pub fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            min_fee: None,
        }
    }
    /// For `TX_FEE_TOO_LOW`: the minimum relay fee the transaction needs.
    pub fn min_fee(&self) -> Option<u64> {
        self.min_fee
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for ZkhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for ZkhError {}

impl From<crate::tx::TxError> for ZkhError {
    fn from(e: crate::tx::TxError) -> Self {
        let mut out = Self::new(e.code(), e.to_string());
        if let crate::tx::TxError::FeeTooLow { minimum, .. } = &e {
            out.min_fee = Some(*minimum);
        }
        out
    }
}

impl From<terms_core::Refusal> for ZkhError {
    fn from(r: terms_core::Refusal) -> Self {
        Self::new(r.code, format!("tag {}", r.tag))
    }
}

fn parse_hash(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_suffix('\n').unwrap_or(text);
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// The checked template v4: the bytes around the state span and their hash.
#[derive(Debug)]
pub struct TemplateV4 {
    abi: SilAbiArtifact,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    hash: [u8; 32],
    image_id: [u8; 32],
}

static TEMPLATE: LazyLock<Result<TemplateV4, ZkhError>> =
    LazyLock::new(|| TemplateV4::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE, IMAGE_ID_FILE));

/// The startup check; every instantiation and decode goes through it.
pub fn check() -> Result<&'static TemplateV4, ZkhError> {
    TEMPLATE.as_ref().map_err(Clone::clone)
}

impl TemplateV4 {
    pub(crate) fn load(
        artifact: &str,
        hash_file: &str,
        image_file: &str,
    ) -> Result<Self, ZkhError> {
        let bad = |r: String| ZkhError::new("ZK_H_ARTIFACT_INVALID", r);
        let abi: SilAbiArtifact =
            serde_json::from_str(artifact).map_err(|e| bad(format!("does not parse: {e}")))?;
        abi.check_schema_version().map_err(|e| bad(e.to_string()))?;
        if abi.contracts.len() != 1 || !abi.contracts.contains_key(CONTRACT_NAME_V4) {
            return Err(bad(format!(
                "artifact must hold exactly {CONTRACT_NAME_V4}"
            )));
        }
        let contract = &abi.contracts[CONTRACT_NAME_V4];
        let fields: Vec<&str> = contract
            .runtime_state
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        if fields != ["termsCommit", "authorityKey"] {
            return Err(bad(format!("state layout {fields:?} is not the v4 layout")));
        }
        let compiled = &contract.compiled;
        let (prefix, _state, suffix) = compiled
            .script_parts(&compiled.bytecode)
            .ok_or_else(|| bad("state span lies outside the bytecode".into()))?;
        if prefix.is_empty() || suffix.is_empty() {
            return Err(bad("template prefix or suffix is empty".into()));
        }
        let hash = template_hash(prefix, suffix);
        let mismatch = |expected: [u8; 32]| {
            ZkhError::new(
                "ZK_H_TEMPLATE_HASH_MISMATCH",
                format!(
                    "the template hash is {}, expected {}",
                    hex(&hash),
                    hex(&expected)
                ),
            )
        };
        if hash != compiled.template_hash {
            return Err(mismatch(compiled.template_hash));
        }
        let pinned =
            parse_hash(hash_file).ok_or_else(|| bad("TEMPLATE_HASH_V4 is malformed".into()))?;
        if hash != pinned {
            return Err(mismatch(pinned));
        }
        let image = parse_hash(image_file).ok_or_else(|| bad("IMAGE_ID_V4 is malformed".into()))?;
        let seen = [prefix, suffix]
            .iter()
            .map(|p| p.windows(32).filter(|w| *w == image).count())
            .sum::<usize>();
        if seen != 2 {
            return Err(bad(format!(
                "IMAGE_ID_V4 occurs {seen} times in template v4, it must occur once per entry (twice)"
            )));
        }
        abi.check_consistency().map_err(|e| bad(e.to_string()))?;
        let (prefix, suffix) = (prefix.to_vec(), suffix.to_vec());
        Ok(Self {
            abi,
            prefix,
            suffix,
            hash,
            image_id: image,
        })
    }

    /// `IMAGE_ID_V4`: the image ID of the terms guest the template pins.
    pub fn image_id(&self) -> [u8; 32] {
        self.image_id
    }
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    pub fn prefix_len(&self) -> usize {
        self.prefix.len()
    }
    pub fn suffix_len(&self) -> usize {
        self.suffix.len()
    }

    fn state_span<'a>(&self, script: &'a [u8]) -> Option<&'a [u8]> {
        let (p, s) = (self.prefix.len(), self.suffix.len());
        if script.len() < p + s
            || !script.starts_with(&self.prefix)
            || !script.ends_with(&self.suffix)
        {
            return None;
        }
        Some(&script[p..script.len() - s])
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One leg's vault: the redeem script of (commitment, authority key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultV4 {
    commit: [u8; 32],
    authority: [u8; 32],
    redeem_script: Vec<u8>,
}

impl VaultV4 {
    pub fn instantiate(commit: [u8; 32], authority: [u8; 32]) -> Result<Self, ZkhError> {
        let t = check()?;
        let mut values = BTreeMap::new();
        values.insert(
            "termsCommit".to_string(),
            ArtifactValue::Bytes(commit.to_vec()),
        );
        values.insert(
            "authorityKey".to_string(),
            ArtifactValue::Bytes(authority.to_vec()),
        );
        let state = encode_runtime_state_script(
            &t.abi,
            &t.abi.contracts[CONTRACT_NAME_V4].runtime_state,
            &values,
        )
        .map_err(|e| ZkhError::new("ZK_H_STATE_MALFORMED", e.to_string()))?;
        let mut redeem_script = Vec::with_capacity(t.prefix.len() + state.len() + t.suffix.len());
        redeem_script.extend_from_slice(&t.prefix);
        redeem_script.extend_from_slice(&state);
        redeem_script.extend_from_slice(&t.suffix);
        Ok(Self {
            commit,
            authority,
            redeem_script,
        })
    }

    /// The vault of `leg` (0 asset, 1 cash) of terms v4 bytes.
    pub fn of_terms(terms: &tc::Terms, leg: u8) -> Result<Self, ZkhError> {
        let authority = terms.authority.ok_or_else(|| {
            ZkhError::new("ZK_H_AUTHORITY_REQUIRED", "terms v4 name no authority")
        })?;
        let h = th::terms_hash(&terms.encode());
        Self::instantiate(th::commit(&h, leg), authority)
    }

    pub fn commit(&self) -> [u8; 32] {
        self.commit
    }
    pub fn authority(&self) -> [u8; 32] {
        self.authority
    }
    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }
    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_script_hash_script(&self.redeem_script)
    }
    /// The script hash of the vault's P2SH: the SCRIPT_HASH owner its escrowed token has.
    pub fn script_hash(&self) -> [u8; 32] {
        let spk = self.script_public_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&spk.script()[2..34]);
        out
    }
    pub fn address(&self, network: Network) -> String {
        let spk = self.script_public_key();
        kaspa_addresses::Address::new(
            crate::address::prefix(network),
            kaspa_addresses::Version::ScriptHash,
            &spk.script()[2..34],
        )
        .to_string()
    }
}

/// Decodes a revealed redeem script to (commitment, authority key). A script of another template
/// is `ZK_H_NOT_V4_VAULT`; one that is not the instantiation of its state is `ZK_H_NONCANONICAL`.
pub fn decode_vault(script: &[u8]) -> Result<([u8; 32], [u8; 32]), ZkhError> {
    let t = check()?;
    let span = t
        .state_span(script)
        .ok_or_else(|| ZkhError::new("ZK_H_NOT_V4_VAULT", "the script does not run template v4"))?;
    let bad = |r: &str| ZkhError::new("ZK_H_STATE_MALFORMED", r.to_string());
    let mut values = decode_runtime_state_script(
        &t.abi,
        &t.abi.contracts[CONTRACT_NAME_V4].runtime_state,
        span,
    )
    .map_err(|e| ZkhError::new("ZK_H_STATE_MALFORMED", e.to_string()))?;
    let mut take = |name: &str| -> Result<[u8; 32], ZkhError> {
        match values.remove(name) {
            Some(ArtifactValue::Bytes(b)) => b.try_into().map_err(|_| bad("field length")),
            _ => Err(bad("field missing")),
        }
    };
    let commit = take("termsCommit")?;
    let authority = take("authorityKey")?;
    if VaultV4::instantiate(commit, authority)?.redeem_script != script {
        return Err(ZkhError::new(
            "ZK_H_NONCANONICAL",
            "the script is not the v4 instantiation of its state",
        ));
    }
    Ok((commit, authority))
}

/// True if the script runs template v4 (its prefix and suffix are the template's).
pub fn is_v4_script(script: &[u8]) -> bool {
    check().is_ok_and(|t| t.state_span(script).is_some())
}

/// Decodes a terms file: lowercase hex of the canonical terms v4 bytes, whitespace ignored.
pub fn parse_terms_file(text: &str) -> Result<tc::Terms, ZkhError> {
    let digits: String = text.split_whitespace().collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ZkhError::new(
            "ZK_H_TERMS_VERSION",
            "a terms file is lowercase hex of the canonical terms v4",
        ));
    }
    let bytes: Vec<u8> = (0..digits.len() / 2)
        .map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).expect("hex checked"))
        .collect();
    let terms = tc::Terms::decode(&bytes)?;
    if terms.encode() != bytes {
        return Err(ZkhError::new(
            "ZK_H_TERMS_VERSION",
            "the terms are not canonical",
        ));
    }
    if terms.mode == tc::MODE_DIRECT {
        return Err(ZkhError::new(
            "ZK_H_TERMS_DIRECT",
            "terms v4 name Direct settlement",
        ));
    }
    terms_core::structure::validate(&terms, true)?;
    Ok(terms)
}

/// What a v4 vault input shows without the terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenInput {
    pub input_index: usize,
    pub commit: [u8; 32],
    pub authority: [u8; 32],
    pub entry: &'static str,
    pub proof_present: bool,
}

/// The pushes of a push-only script as script numbers or data: small-integer pushes become their
/// value as one byte (OP_0 is empty).
fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let b = script.get(i..i + 2)?;
                i += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            0x4f => {
                out.push(vec![0x81]);
                continue;
            }
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        out.push(script.get(i..i.checked_add(len)?)?.to_vec());
        i += len;
    }
    Some(out)
}

fn num(b: &[u8]) -> Option<usize> {
    match b {
        [] => Some(0),
        [v] if *v < 0x80 => Some(*v as usize),
        [v, 0] => Some(*v as usize),
        _ => None,
    }
}

/// A parsed v4 spend of one input.
pub(crate) struct Spend {
    pub(crate) script: Vec<u8>,
    pub(crate) commit: [u8; 32],
    pub(crate) authority: [u8; 32],
    pub(crate) settle: bool,
    pub(crate) proof: Vec<u8>,
    pub(crate) proof_present: bool,
    pub(crate) n_in: usize,
    pub(crate) n_out: usize,
    pub(crate) leg: Option<u8>,
    pub(crate) signer: [u8; 32],
    pub(crate) cov_a: [u8; 32],
    pub(crate) cov_c: [u8; 32],
}

fn arr32(b: &[u8]) -> Option<[u8; 32]> {
    b.try_into().ok()
}

/// The v4 spend an input makes, or `Ok(None)` if it reveals no v4 script. Dispatch tags are the
/// artifact's; arguments are pushed in declaration order before the tag and the redeem script.
pub(crate) fn parse_spend_script(sig_script: &[u8]) -> Result<Option<Spend>, ZkhError> {
    let Some(p) = pushes(sig_script) else {
        return Ok(None);
    };
    let Some(script) = p.last() else {
        return Ok(None);
    };
    if !is_v4_script(script) {
        return Ok(None);
    }
    let (commit, authority) = decode_vault(script)?;
    let t = check()?;
    let entries = &t.abi.contracts[CONTRACT_NAME_V4].entries;
    let tag_of = |name: &str| entries.get(name).map(|e| hex(e.dispatch_tag.as_bytes()));
    let n = p.len();
    let args = &p[..n.saturating_sub(2)];
    let tag = hex(p.get(n.wrapping_sub(2)).map_or(&[][..], |v| v));
    let shape = || {
        ZkhError::new(
            "ZK_H_SHAPE",
            "the entry call does not have the v4 arguments",
        )
    };
    if Some(tag.clone()) == tag_of("settle") {
        // authSig, proof, nIn, nOut, covA, covC
        if args.len() != 6 {
            return Err(shape());
        }
        return Ok(Some(Spend {
            script: script.clone(),
            commit,
            authority,
            settle: true,
            proof: args[1].clone(),
            proof_present: args[1].len() == 128,
            n_in: num(&args[2]).ok_or_else(shape)?,
            n_out: num(&args[3]).ok_or_else(shape)?,
            leg: None,
            signer: [0; 32],
            cov_a: arr32(&args[4]).ok_or_else(shape)?,
            cov_c: arr32(&args[5]).ok_or_else(shape)?,
        }));
    }
    if Some(tag) == tag_of("refund") {
        // s, signer, leg, proof, nIn, nOut, cov
        if args.len() != 7 {
            return Err(shape());
        }
        return Ok(Some(Spend {
            script: script.clone(),
            commit,
            authority,
            settle: false,
            proof: args[3].clone(),
            proof_present: args[3].len() == 128,
            n_in: num(&args[4]).ok_or_else(shape)?,
            n_out: num(&args[5]).ok_or_else(shape)?,
            leg: Some(num(&args[2]).ok_or_else(shape)? as u8),
            signer: arr32(&args[1]).ok_or_else(shape)?,
            cov_a: arr32(&args[6]).ok_or_else(shape)?,
            cov_c: [0; 32],
        }));
    }
    Err(ZkhError::new(
        "ZK_H_SHAPE",
        "the input calls no entry of template v4",
    ))
}

/// Every v4 vault input of a transaction as seen without the terms.
pub fn hidden_inputs(tx: &Transaction) -> Result<Vec<HiddenInput>, ZkhError> {
    let mut out = Vec::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        if let Some(s) = parse_spend_script(&input.signature_script)? {
            out.push(HiddenInput {
                input_index: i,
                commit: s.commit,
                authority: s.authority,
                entry: if s.settle { "settle" } else { "refund" },
                proof_present: s.proof_present,
            });
        }
    }
    Ok(out)
}

fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut b = spk.version().to_be_bytes().to_vec();
    b.extend_from_slice(spk.script());
    b
}

/// The result of checking one v4 vault input against revealed terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputCheck {
    pub input_index: usize,
    pub leg: u8,
    pub entry: &'static str,
    /// Ok, or the refusal naming the failing tag.
    pub verdict: Result<(), ZkhError>,
}

/// Runs the statement of terms-core on every v4 vault input of an accepted transaction, with the
/// revealed terms. Per input: `ZK_H_TERMS_MISMATCH` if neither leg's commitment is the vault's,
/// else the statement's verdict (`ZK_H_STATEMENT_FALSE` naming the tag).
pub fn check_revealed(
    tx: &Transaction,
    spent: &[UtxoEntry],
    terms: &tc::Terms,
) -> Result<Vec<InputCheck>, ZkhError> {
    if spent.len() != tx.inputs.len() {
        return Err(ZkhError::new(
            "ZK_H_SHAPE",
            "one spent entry per input is required",
        ));
    }
    let terms_bytes = terms.encode();
    let h = th::terms_hash(&terms_bytes);
    let mut out = Vec::new();
    for (idx, input) in tx.inputs.iter().enumerate() {
        let Some(s) = parse_spend_script(&input.signature_script)? else {
            continue;
        };
        let entry = if s.settle { "settle" } else { "refund" };
        // the vault must be the one the node says this input spent
        if spk_bytes(&spent[idx].script_public_key)
            != spk_bytes(&pay_to_script_hash_script(&s.script))
        {
            return Err(ZkhError::new(
                "ZK_H_NOT_V4_VAULT",
                format!("input {idx} does not spend the P2SH of the script it reveals"),
            ));
        }
        let Some(leg) = (0..=1u8)
            .find(|l| th::commit(&h, *l) == s.commit && terms.authority == Some(s.authority))
        else {
            out.push(InputCheck {
                input_index: idx,
                leg: 0,
                entry,
                verdict: Err(ZkhError::new(
                    "ZK_H_TERMS_MISMATCH",
                    "the commitment of neither leg of these terms is the vault's",
                )),
            });
            continue;
        };
        let verdict = statement_for(tx, spent, idx, &s, leg, &terms_bytes);
        out.push(InputCheck {
            input_index: idx,
            leg,
            entry,
            verdict,
        });
    }
    Ok(out)
}

fn statement_for(
    tx: &Transaction,
    spent: &[UtxoEntry],
    idx: usize,
    s: &Spend,
    leg: u8,
    terms_bytes: &[u8],
) -> Result<(), ZkhError> {
    let witness = witness_for(tx, spent, idx, s, leg, terms_bytes)?;
    terms_core::statement(
        &witness,
        terms_core::StatementOptions { curve_checks: true },
    )
    .map(|_| ())
    .map_err(ZkhError::from)
}

/// The witness the terms guest reads for vault input `idx` of a transaction whose signature
/// scripts are assembled: the terms, the journal the vault's script builds, and the redeem scripts
/// the view's inputs reveal: the token escrows' and the vaults' own (`[H5]`, spec/V3-ZK.md 22.16). `leg` is the leg whose commitment the input's vault holds.
pub(crate) fn witness_for(
    tx: &Transaction,
    spent: &[UtxoEntry],
    idx: usize,
    s: &Spend,
    leg: u8,
    terms_bytes: &[u8],
) -> Result<terms_core::Witness, ZkhError> {
    let (n_in, n_out) = (s.n_in, s.n_out);
    if n_in > spent.len() || n_out > tx.outputs.len() || n_in > 4 || n_out > 4 {
        return Err(ZkhError::new(
            "ZK_H_SHAPE",
            "the view is beyond the transaction",
        ));
    }
    let cov_of = |c: Option<kaspa_consensus_core::Hash>| c.map_or([0u8; 32], |h| h.as_bytes());
    let count = |cov: [u8; 32]| {
        spent
            .iter()
            .filter(|e| cov != [0; 32] && e.covenant_id.map(|h| h.as_bytes()) == Some(cov))
            .count() as u8
    };
    let inputs = (0..n_in)
        .map(|i| Item {
            value: spent[i].amount,
            spk_hash: th::sha256(&spk_bytes(&spent[i].script_public_key)),
            cov: cov_of(spent[i].covenant_id),
        })
        .collect();
    let outputs = (0..n_out)
        .map(|k| Item {
            value: tx.outputs[k].value,
            spk_hash: th::sha256(&spk_bytes(&tx.outputs[k].script_public_key)),
            cov: cov_of(tx.outputs[k].covenant.map(|c| c.covenant_id)),
        })
        .collect();
    let vault_spk: [u8; 37] = spk_bytes(&spent[idx].script_public_key)
        .try_into()
        .map_err(|_| ZkhError::new("ZK_H_NOT_V4_VAULT", "the vault scriptPubKey is not a P2SH"))?;
    let (leg_j, count_a, count_c) = if s.settle {
        (idx as u8, count(s.cov_a), count(s.cov_c))
    } else {
        (s.leg.unwrap_or(leg), count(s.cov_a), 0)
    };
    let journal = Journal {
        mode: if s.settle { Mode::Settle } else { Mode::Refund },
        vault_spk,
        commit: s.commit,
        authority: s.authority,
        leg: leg_j,
        input_index: idx as u8,
        locktime: tx.lock_time,
        signer: s.signer,
        cov_a: s.cov_a,
        cov_c: s.cov_c,
        count_a,
        count_c,
        inputs,
        outputs,
    };
    let redeems = (0..n_in)
        .filter_map(|i| {
            let p = pushes(&tx.inputs[i].signature_script)?;
            let r = p.last()?.clone();
            let spk = pay_to_script_hash_script(&r);
            (spk_bytes(&spk) == spk_bytes(&spent[i].script_public_key)).then_some((i as u8, r))
        })
        .collect();
    Ok(terms_core::Witness {
        terms: terms_bytes.to_vec(),
        journal: journal.to_bytes(),
        redeems,
    })
}

mod build;
mod ipst;
mod vterms;
pub use build::*;
pub use ipst::{IpstV4, ProofV4, IPST_VERSION_V4, PROOF_LEN};
pub use vterms::ValidatedTermsV4;

#[cfg(test)]
mod build_tests;
#[cfg(test)]
mod tests;
