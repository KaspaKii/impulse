// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse frost` (I13 phase 2, spec/THRESHOLD.md, "CLI"): `keygen` runs one party's FROST key
//! generation, `sign` one party's signature shares over the authority inputs of an IPST, and
//! `aggregate` turns the shares into the IPST's authority signatures.
//!
//! This module holds no FROST secret. Key generation lives in [`crate::keygen`] and signing in
//! [`crate::signing`], the two modules that touch a key share; here are the arguments, the checks
//! that need no secret, the public files, the signing session, and the console the interactive
//! commands ask through. Files move between parties by the parties' own channels (decision D16).

use crate::cli::{cap, creation, CapArgs, CreationArgs, Ctx};
use crate::error::CliError;
use crate::ipst_cmd::{check_agreed_as, AgreedArgs};
use crate::json::hex;
use crate::signing::{self, FrostSignRequest};
use crate::summary::{self, kas_address};
use crate::terms_file::{read_text, write_new};
use crate::trade::leg_name;
use clap::{Args, Subcommand};
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{Network, ValidatedTerms};
use impulse_core::threshold::{
    aggregate_input, Commitment, GroupKey, GroupShape, PartyId, SignatureShare, ThresholdError,
};
use impulse_core::tx::{self, Ipst, IpstKind, Kcc20Template, RefundSigner, TxError};
use kaspa_consensus_core::tx::ScriptPublicKey;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Every `impulse frost` refusal code of its own, in spec order (spec/THRESHOLD.md, "Error
/// codes"). Frozen once merged: a test pins this list, and it may only grow at the end.
pub const FROST_ERROR_CODES: [&str; 14] = [
    "FROST_SHARE_FILE_UNREADABLE",
    "FROST_SHARE_FILE_PERMISSIONS",
    "FROST_SHARE_FILE_FORMAT",
    "FROST_FILE_MALFORMED",
    "FROST_FILE_PERMISSIONS",
    "FROST_SESSION_MISMATCH",
    "FROST_NOT_CONFIRMED",
    "FROST_ABORTED",
    "FROST_SIGNERS_INVALID",
    "FROST_NO_AUTHORITY_INPUT",
    "FROST_KEY_NOT_AUTHORITY",
    "FROST_AUTHORITY_INPUT_NOT_VAULT",
    "FROST_ROUND2_NOT_REMOVED",
    "FROST_TERMS_NOT_AGREED",
];

#[derive(Subcommand, Debug)]
pub enum FrostCommand {
    /// Run this party's FROST key generation: three rounds, no dealer, files moved by the parties.
    Keygen(KeygenArgs),
    /// Sign the authority inputs of an IPST as one party of the group (two rounds, one process).
    Sign(SignArgs),
    /// Turn the signers' shares into the authority signatures of an IPST.
    Aggregate(AggregateArgs),
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// How many parties must sign together (t, at least 2).
    #[arg(long)]
    pub threshold: u16,
    /// How many parties the group has (n).
    #[arg(long)]
    pub parties: u16,
    /// Your party number, 1..=n, as the parties agreed it.
    #[arg(long)]
    pub party: u16,
    /// The directory this key generation exchanges files through; use a fresh one.
    #[arg(long, value_name = "DIR")]
    pub dir: PathBuf,
    /// Where to write your key share (secret, mode 0600); must not exist.
    #[arg(long, value_name = "FILE")]
    pub share_file: PathBuf,
    /// Where to write the group file (public); must not exist.
    #[arg(long, value_name = "FILE")]
    pub group_out: PathBuf,
}

/// Where the current DAA score comes from: exactly one of the two.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DaaArgs {
    /// The current DAA score, as you read it from your node. Testnet only: on mainnet the score
    /// is read from --node.
    #[arg(long, value_name = "SCORE")]
    pub daa: Option<u64>,
    /// wRPC URL of a synced node to read the DAA score from: ws:// or wss://, and on mainnet
    /// wss:// or ws:// to this machine.
    #[arg(long, value_name = "URL")]
    pub node: Option<String>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// Your key share file, as `impulse frost keygen` wrote it.
    #[arg(long, value_name = "FILE")]
    pub share_file: PathBuf,
    /// The IPST to sign.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// The signing set the signers agreed, your own number included: for example 1,2.
    #[arg(long, value_name = "LIST")]
    pub signers: String,
    #[command(flatten)]
    pub agreed: AgreedArgs,
    /// The directory this signing session exchanges files through; use a fresh one.
    #[arg(long, value_name = "DIR")]
    pub dir: PathBuf,
    /// The asset leg's KCC-20 token artifact (silverc JSON), for the terms check.
    #[arg(long, value_name = "FILE")]
    pub asset_template: PathBuf,
    /// The cash leg's KCC-20 token artifact, when the cash leg is a KCC-20 token.
    #[arg(long, value_name = "FILE")]
    pub cash_template: Option<PathBuf>,
    #[command(flatten)]
    pub daa: DaaArgs,
    #[command(flatten)]
    pub cap: CapArgs,
}

#[derive(Args, Debug)]
pub struct AggregateArgs {
    /// The group file, as `impulse frost keygen` wrote it.
    #[arg(long, value_name = "FILE")]
    pub group: PathBuf,
    /// The IPST the signers signed.
    #[arg(long, value_name = "FILE")]
    pub ipst: PathBuf,
    /// The signing set: for example 1,2.
    #[arg(long, value_name = "LIST")]
    pub signers: String,
    /// The directory holding every signer's commit and sigshare files.
    #[arg(long, value_name = "DIR")]
    pub dir: PathBuf,
    /// Where to write the IPST with the authority signatures; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Runs one `impulse frost` command. Results and prompts go to `out`; the interactive commands
/// read their answers from `input`.
pub(crate) fn run(
    ctx: &Ctx,
    command: FrostCommand,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let console = Terminal {
        input: RefCell::new(input),
        out: RefCell::new(out),
    };
    run_with(ctx, command, &console)
}

/// Runs one `impulse frost` command through `console`.
pub(crate) fn run_with(
    ctx: &Ctx,
    command: FrostCommand,
    console: &dyn Console,
) -> Result<(), CliError> {
    match command {
        FrostCommand::Keygen(a) => keygen(a, console),
        FrostCommand::Sign(a) => sign(ctx, a, console),
        FrostCommand::Aggregate(a) => aggregate(ctx, a, console),
    }
}

// =============================================================================================
// Console
// =============================================================================================

/// What the interactive commands print and ask.
pub trait Console {
    fn say(&self, line: &str) -> Result<(), CliError>;
    /// Prints `> ` and the prompt, then reads one line, returned without its line end. The end of
    /// input is `FROST_ABORTED`.
    fn ask(&self, prompt: &str) -> Result<String, CliError>;
}

struct Terminal<'a> {
    input: RefCell<&'a mut dyn BufRead>,
    out: RefCell<&'a mut dyn Write>,
}

fn stdout_error(e: std::io::Error) -> CliError {
    CliError::new("CLI_FILE_WRITE", format!("stdout: {e}"))
}

impl Console for Terminal<'_> {
    fn say(&self, line: &str) -> Result<(), CliError> {
        let mut out = self.out.borrow_mut();
        writeln!(out, "{line}").map_err(stdout_error)?;
        out.flush().map_err(stdout_error)
    }

    fn ask(&self, prompt: &str) -> Result<String, CliError> {
        self.say(&format!("> {prompt}"))?;
        let mut line = String::new();
        let n = self
            .input
            .borrow_mut()
            .read_line(&mut line)
            .map_err(|e| CliError::new("FROST_ABORTED", format!("stdin: {e}")))?;
        if n == 0 {
            return Err(CliError::new(
                "FROST_ABORTED",
                "the input ended before this step completed; nothing more is written",
            ));
        }
        let line = line.strip_suffix('\n').unwrap_or(&line);
        Ok(line.strip_suffix('\r').unwrap_or(line).to_string())
    }
}

/// Asks until every file in `names` is in `dir`, naming those still missing.
pub(crate) fn wait_for(
    console: &dyn Console,
    step: &str,
    dir: &Path,
    names: &[String],
) -> Result<(), CliError> {
    loop {
        console.ask(&format!(
            "{step}: put {} into {}, then press Enter",
            names.join(", "),
            dir.display()
        ))?;
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !dir.join(n).exists())
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        console.say(&format!("missing: {}", missing.join(", ")))?;
    }
}

/// Asks for the value every party reported out of band; anything but this party's own value is
/// `FROST_NOT_CONFIRMED`.
pub(crate) fn confirm(console: &dyn Console, what: &str, value: &[u8; 32]) -> Result<(), CliError> {
    let answer = console.ask(&format!(
        "confirm {what}: compare it with every other party out of band, then type the {what} they all reported (anything else stops)"
    ))?;
    if answer.trim() != hex(value) {
        return Err(CliError::new(
            "FROST_NOT_CONFIRMED",
            format!("the {what} typed back is not this party's; nothing more is written"),
        ));
    }
    Ok(())
}

// =============================================================================================
// Files: tag, ':', lowercase hex of the body, at most one line feed
// =============================================================================================

pub(crate) const ROUND1_TAG: &str = "impulse-frost-round1-v1";
pub(crate) const ROUND2_TAG: &str = "impulse-frost-round2-v1";
pub(crate) const SHARE_TAG: &str = "impulse-frost-share-v1";
pub(crate) const GROUP_TAG: &str = "impulse-frost-group-v1";
pub(crate) const COMMIT_TAG: &str = "impulse-frost-commit-v1";
pub(crate) const SIGSHARE_TAG: &str = "impulse-frost-sigshare-v1";

/// The largest file read. A group file is 98 + 66n bytes and a round-1 file 169 + 66t bytes
/// (hex doubles the body), so groups of up to 991 parties and thresholds up to 990 fit.
const MAX_FILE: usize = 1 << 16;

pub(crate) fn round1_name(party: PartyId) -> String {
    format!("round1-{party}.frost")
}

pub(crate) fn round2_name(from: PartyId, to: PartyId) -> String {
    format!("round2-{from}-to-{to}.frost")
}

pub(crate) fn commit_name(party: PartyId) -> String {
    format!("commit-{party}.frost")
}

pub(crate) fn sigshare_name(party: PartyId) -> String {
    format!("sigshare-{party}.frost")
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `tag:hex` and a line feed, in a buffer zeroed on drop (the body may be secret).
pub(crate) fn envelope(tag: &str, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(tag.len() + 2 + 2 * body.len()));
    out.extend_from_slice(tag.as_bytes());
    out.push(b':');
    for b in body {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out.push(b'\n');
    out
}

/// The text of a public file.
pub(crate) fn public_file(tag: &str, body: &[u8]) -> String {
    String::from_utf8(envelope(tag, body).to_vec()).expect("an envelope is ASCII")
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The body of `tag:hex` with at most one final line feed, in a buffer zeroed on drop; None for
/// anything else (another tag, uppercase or odd-length hex, other whitespace).
pub(crate) fn open_envelope(text: &[u8], tag: &str) -> Option<Zeroizing<Vec<u8>>> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let hex = text.strip_prefix(tag.as_bytes())?.strip_prefix(b":")?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut body = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    for pair in hex.chunks(2) {
        body.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(body)
}

/// Codes a file read refuses with.
pub(crate) struct ReadRules {
    /// The file cannot be opened or read, or is not a regular file.
    pub unreadable: &'static str,
    /// Group or others have access (Unix); None for public files.
    pub permissions: Option<&'static str>,
    /// The file is longer than `limit`.
    pub too_long: &'static str,
    /// The longest file accepted.
    pub limit: usize,
}

pub(crate) const PUBLIC_FILE: ReadRules = ReadRules {
    unreadable: "CLI_FILE_READ",
    permissions: None,
    too_long: "FROST_FILE_MALFORMED",
    limit: MAX_FILE,
};

/// Reads a whole file into a buffer zeroed on drop. The path must name a regular file before it
/// is opened (opening a FIFO would wait for a writer), and the file opened must be one too.
pub(crate) fn read_file(path: &Path, rules: &ReadRules) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let shown = path.display();
    let unreadable = |why: String| CliError::new(rules.unreadable, why);
    let named = std::fs::metadata(path).map_err(|e| unreadable(format!("{shown}: {e}")))?;
    if !named.is_file() {
        return Err(unreadable(format!("{shown}: not a regular file")));
    }
    let file = std::fs::File::open(path).map_err(|e| unreadable(format!("{shown}: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| unreadable(format!("{shown}: {e}")))?;
    if !meta.is_file() {
        return Err(unreadable(format!("{shown}: not a regular file")));
    }
    #[cfg(unix)]
    if let Some(code) = rules.permissions {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::new(
                code,
                format!(
                    "{shown}: mode {:o} lets group or others read a secret; run chmod 600 on it",
                    mode & 0o777
                ),
            ));
        }
    }
    // Allocated once at the limit, so reading never moves the content.
    let mut buf = Zeroizing::new(vec![0u8; rules.limit + 1]);
    let mut len = 0;
    let mut reader = file.take((rules.limit + 1) as u64);
    loop {
        let n = reader
            .read(&mut buf[len..])
            .map_err(|e| unreadable(format!("{shown}: {e}")))?;
        if n == 0 {
            break;
        }
        len += n;
        if len == buf.len() {
            return Err(CliError::new(
                rules.too_long,
                format!("{shown}: longer than {} bytes", rules.limit),
            ));
        }
    }
    buf.truncate(len);
    Ok(buf)
}

pub(crate) fn malformed(path: &Path, what: &str) -> CliError {
    CliError::new(
        "FROST_FILE_MALFORMED",
        format!("{}: not {what}", path.display()),
    )
}

pub(crate) fn session_mismatch(path: &Path, why: impl std::fmt::Display) -> CliError {
    CliError::new(
        "FROST_SESSION_MISMATCH",
        format!("{}: {why}", path.display()),
    )
}

/// A public FROST file's body.
pub(crate) fn read_public(path: &Path, tag: &str) -> Result<Vec<u8>, CliError> {
    let text = read_file(path, &PUBLIC_FILE)?;
    open_envelope(&text, tag)
        .map(|b| b.to_vec())
        .ok_or_else(|| malformed(path, &format!("a {tag} file")))
}

/// Reads fixed-size fields of a file body, front to back; any shortfall or excess is
/// `FROST_FILE_MALFORMED`.
pub(crate) struct Body<'a> {
    rest: &'a [u8],
    path: &'a Path,
    what: &'a str,
}

impl<'a> Body<'a> {
    pub(crate) fn new(bytes: &'a [u8], path: &'a Path, what: &'a str) -> Self {
        Self {
            rest: bytes,
            path,
            what,
        }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], CliError> {
        if self.rest.len() < n {
            return Err(malformed(self.path, self.what));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CliError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CliError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn array32(&mut self) -> Result<[u8; 32], CliError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// Everything left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }

    pub(crate) fn end(&self) -> Result<(), CliError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(malformed(self.path, self.what))
        }
    }
}

// =============================================================================================
// Shared checks
// =============================================================================================

/// A threshold refusal, keeping its `THRESHOLD_*` code.
pub(crate) fn threshold_error(e: ThresholdError) -> CliError {
    let code = e.code();
    let text = e.to_string();
    let detail = text
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(": "))
        .map(str::to_string)
        .unwrap_or(text);
    CliError::new(code, detail)
}

/// A transaction or IPST refusal, keeping its `TX_*` or `IPST_*` code.
pub(crate) fn tx_error(e: TxError) -> CliError {
    let code = e.code();
    let text = e.to_string();
    let detail = text
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(": "))
        .map(str::to_string)
        .unwrap_or(text);
    CliError::new(code, detail)
}

/// The terms' authority key and the authority inputs: the inputs whose slot names that key as
/// signer and holds no signature yet, ascending (`FROST_NO_AUTHORITY_INPUT` if none). Every slot
/// that names the authority, signed or not, must spend a UTXO at a vault of the terms
/// (`FROST_AUTHORITY_INPUT_NOT_VAULT`): the group signs vault inputs only, never a fee input
/// that happens to be locked to its key.
pub(crate) fn authority_inputs(ipst: &Ipst) -> Result<([u8; 32], Vec<usize>), CliError> {
    let none = |why: &str| CliError::new("FROST_NO_AUTHORITY_INPUT", why.to_string());
    let terms = ipst.terms();
    let authority = terms
        .terms()
        .authority_key
        .ok_or_else(|| none("the terms name no authority (self-settling)"))?;
    let vaults: Vec<ScriptPublicKey> = [LegIndex::Asset, LegIndex::Cash]
        .into_iter()
        .filter_map(|leg| Vault::instantiate_existing(terms, leg).ok())
        .map(|v| v.script_public_key())
        .collect();
    for (i, (slot, entry)) in ipst.slots().iter().zip(ipst.entries()).enumerate() {
        if slot.signer() == Some(authority) && !vaults.contains(&entry.script_public_key) {
            return Err(CliError::new(
                "FROST_AUTHORITY_INPUT_NOT_VAULT",
                format!(
                    "input {i} names the authority key as signer but spends {}, not a vault of these terms; the group signs vault inputs only",
                    address(terms.terms().network, &entry.script_public_key)
                ),
            ));
        }
    }
    let inputs: Vec<usize> = ipst
        .slots()
        .iter()
        .enumerate()
        .filter(|(_, s)| s.signer() == Some(authority) && s.signature().is_none())
        .map(|(i, _)| i)
        .collect();
    if inputs.is_empty() {
        return Err(none(
            "no input of the IPST waits for the authority's signature",
        ));
    }
    Ok((authority, inputs))
}

/// What the terms check found must be a transaction in which the authority signs vault inputs:
/// a settle, or a refund by the authority (`FROST_AUTHORITY_INPUT_NOT_VAULT`).
pub(crate) fn check_kind(kind: &IpstKind) -> Result<(), CliError> {
    match kind {
        IpstKind::Settle
        | IpstKind::Refund {
            signer: RefundSigner::Authority,
            ..
        } => Ok(()),
        other => Err(CliError::new(
            "FROST_AUTHORITY_INPUT_NOT_VAULT",
            format!(
                "the IPST is a {}, in which the authority signs no vault input",
                kind_line(other)
            ),
        )),
    }
}

fn address(network: Network, spk: &ScriptPublicKey) -> String {
    kas_address(network, spk.version(), spk.script())
}

/// `--signers`: a comma-separated list of distinct party numbers.
pub(crate) fn parse_signers(text: &str) -> Result<BTreeSet<PartyId>, CliError> {
    let invalid = || {
        CliError::new(
            "FROST_SIGNERS_INVALID",
            format!("--signers {text:?} is not a comma-separated list of distinct party numbers"),
        )
    };
    let mut set = BTreeSet::new();
    for part in text.split(',') {
        let decimal = !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'));
        let id: PartyId = part.parse().ok().filter(|_| decimal).ok_or_else(invalid)?;
        if !set.insert(id) {
            return Err(invalid());
        }
    }
    Ok(set)
}

/// The signing set fits the group: every signer in 1..=n (`THRESHOLD_PARTY`), at least t of them
/// (`THRESHOLD_TOO_FEW_SIGNERS`).
pub(crate) fn check_signers(
    shape: GroupShape,
    signers: &BTreeSet<PartyId>,
) -> Result<(), CliError> {
    for &id in signers {
        if id == 0 || id > shape.parties() {
            return Err(threshold_error(ThresholdError::Party {
                id,
                parties: shape.parties(),
            }));
        }
    }
    if signers.len() < shape.threshold() as usize {
        return Err(threshold_error(ThresholdError::TooFewSigners {
            signers: signers.len(),
            threshold: shape.threshold(),
        }));
    }
    Ok(())
}

fn read_ipst(ctx: &Ctx, path: &Path) -> Result<Ipst, CliError> {
    let ipst = Ipst::from_json(&read_text(path)?).map_err(tx_error)?;
    // A token genesis is testnet only, refused as soon as it is read (spec/CLI.md, "Token helper
    // (testnet only)").
    crate::token::refuse_mainnet_genesis(&ipst)?;
    let named = ipst.terms().terms().network;
    if named != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "{}: the terms are for {}, the command acts on {}",
                path.display(),
                crate::terms_file::network_name(named),
                crate::terms_file::network_name(ctx.network)
            ),
        ));
    }
    Ok(ipst)
}

fn read_template(path: &Path) -> Result<Kcc20Template, CliError> {
    Kcc20Template::from_json(&read_text(path)?).map_err(tx_error)
}

fn must_be_dir(dir: &Path) -> Result<(), CliError> {
    if !dir.is_dir() {
        return Err(CliError::new(
            "CLI_FILE_READ",
            format!("{}: not a directory", dir.display()),
        ));
    }
    Ok(())
}

fn must_not_exist(path: &Path) -> Result<(), CliError> {
    if path.symlink_metadata().is_ok() {
        return Err(CliError::new(
            "CLI_OUTPUT_EXISTS",
            format!("{} exists", path.display()),
        ));
    }
    Ok(())
}

/// The directory a file is to be created in exists.
fn parent_exists(path: &Path) -> Result<(), CliError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if !parent.is_dir() {
        return Err(CliError::new(
            "CLI_FILE_WRITE",
            format!("{}: no such directory", parent.display()),
        ));
    }
    Ok(())
}

fn list(ids: impl IntoIterator<Item = impl std::fmt::Display>) -> String {
    ids.into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// =============================================================================================
// Signing session (spec/THRESHOLD.md, "Files")
// =============================================================================================

/// blake2b-256 key of the signing session.
pub const SESSION_DOMAIN: &[u8] = b"Impulse/frostsession/v1";
/// blake2b-256 key of the commitment set digest.
pub const COMMITMENT_SET_DOMAIN: &[u8] = b"Impulse/frostcommitments/v1";

fn blake2b(key: &[u8]) -> blake2b_simd::State {
    blake2b_simd::Params::new()
        .hash_length(32)
        .key(key)
        .to_state()
}

fn digest(state: &blake2b_simd::State) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

fn input_u32(input: usize) -> u32 {
    u32::try_from(input).expect("a transaction has fewer than 2^32 inputs")
}

/// The signing session: the authority key, the signing set, and every authority input with the
/// `SIG_HASH_ALL` sighash this party computed for it from the IPST (the I5 sighash code).
pub(crate) fn session_id(
    ipst: &Ipst,
    authority: &[u8; 32],
    signers: &BTreeSet<PartyId>,
    inputs: &[usize],
) -> Result<[u8; 32], CliError> {
    let mut messages = Vec::with_capacity(inputs.len());
    for &input in inputs {
        let sighash = tx::sighash(ipst.transaction(), ipst.entries(), input).map_err(tx_error)?;
        messages.push((input, sighash));
    }
    Ok(session_digest(authority, signers, &messages))
}

/// The session digest of spec/THRESHOLD.md, "Files", over each authority input and its sighash.
pub(crate) fn session_digest(
    authority: &[u8; 32],
    signers: &BTreeSet<PartyId>,
    messages: &[(usize, [u8; 32])],
) -> [u8; 32] {
    let mut state = blake2b(SESSION_DOMAIN);
    state.update(authority);
    state.update(&(signers.len() as u16).to_be_bytes());
    for id in signers {
        state.update(&id.to_be_bytes());
    }
    state.update(&(messages.len() as u16).to_be_bytes());
    for (input, sighash) in messages {
        state.update(&input_u32(*input).to_be_bytes());
        state.update(sighash);
    }
    digest(&state)
}

/// The signer's approval, the last step before its share signs: the session shown with the
/// transaction, typed back. Anything else is `FROST_NOT_CONFIRMED`, and nothing is signed.
pub(crate) fn approve(
    console: &dyn Console,
    session: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<(), CliError> {
    let answer = console.ask(&format!(
        "sign: to sign the transaction printed above for terms {} with your share, type its session (anything else stops)",
        hex(terms_hash)
    ))?;
    if answer.trim() != hex(session) {
        return Err(CliError::new(
            "FROST_NOT_CONFIRMED",
            "the session typed back is not this signing session; nothing was signed",
        ));
    }
    Ok(())
}

/// Every signer's commitment for every authority input, keyed by signer then input.
pub type CommitmentSet = BTreeMap<PartyId, BTreeMap<usize, Commitment>>;

pub(crate) fn commitment_set_digest(
    session: &[u8; 32],
    set: &CommitmentSet,
) -> Result<[u8; 32], CliError> {
    let mut state = blake2b(COMMITMENT_SET_DOMAIN);
    state.update(session);
    for (id, by_input) in set {
        state.update(&id.to_be_bytes());
        for c in by_input.values() {
            state.update(&c.to_bytes().map_err(threshold_error)?);
        }
    }
    Ok(digest(&state))
}

pub(crate) fn commit_body(
    session: &[u8; 32],
    party: PartyId,
    commitments: &BTreeMap<usize, Commitment>,
) -> Result<Vec<u8>, CliError> {
    let mut body = session.to_vec();
    body.extend_from_slice(&party.to_be_bytes());
    body.extend_from_slice(&(commitments.len() as u16).to_be_bytes());
    for (&input, c) in commitments {
        body.extend_from_slice(&input_u32(input).to_be_bytes());
        body.extend_from_slice(&c.to_bytes().map_err(threshold_error)?);
    }
    Ok(body)
}

pub(crate) fn sigshare_body(
    session: &[u8; 32],
    set_digest: &[u8; 32],
    party: PartyId,
    shares: &BTreeMap<usize, SignatureShare>,
) -> Vec<u8> {
    let mut body = session.to_vec();
    body.extend_from_slice(set_digest);
    body.extend_from_slice(&party.to_be_bytes());
    body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    for (&input, s) in shares {
        body.extend_from_slice(&input_u32(input).to_be_bytes());
        body.extend_from_slice(&s.to_bytes());
    }
    body
}

/// A commitment file of `party` for this session and these authority inputs.
pub(crate) fn read_commit(
    path: &Path,
    session: &[u8; 32],
    party: PartyId,
    inputs: &[usize],
) -> Result<BTreeMap<usize, Commitment>, CliError> {
    let bytes = read_public(path, COMMIT_TAG)?;
    let what = "a commitment file";
    let mut b = Body::new(&bytes, path, what);
    let (file_session, sender, count) = (b.array32()?, b.u16()?, b.u16()?);
    let mut commitments = BTreeMap::new();
    for _ in 0..count {
        let input = b.u32()? as usize;
        let c = Commitment::from_bytes(b.take(66)?).map_err(|_| malformed(path, what))?;
        commitments.insert(input, c);
    }
    b.end()?;
    if file_session != *session {
        return Err(session_mismatch(
            path,
            "made for another signing session (another IPST, signing set or authority)",
        ));
    }
    if sender != party {
        return Err(session_mismatch(
            path,
            format_args!("from party {sender}, expected party {party}"),
        ));
    }
    if !commitments.keys().eq(inputs.iter()) || commitments.len() != count as usize {
        return Err(session_mismatch(path, "commits to other inputs"));
    }
    Ok(commitments)
}

/// A signature-share file of `party`: its commitment set digest and its share per input.
pub(crate) fn read_sigshare(
    path: &Path,
    session: &[u8; 32],
    party: PartyId,
    inputs: &[usize],
) -> Result<([u8; 32], BTreeMap<usize, SignatureShare>), CliError> {
    let bytes = read_public(path, SIGSHARE_TAG)?;
    let what = "a signature-share file";
    let mut b = Body::new(&bytes, path, what);
    let (file_session, set_digest, sender, count) =
        (b.array32()?, b.array32()?, b.u16()?, b.u16()?);
    let mut shares = BTreeMap::new();
    for _ in 0..count {
        let input = b.u32()? as usize;
        let s = SignatureShare::from_bytes(b.take(32)?).map_err(|_| malformed(path, what))?;
        shares.insert(input, s);
    }
    b.end()?;
    if file_session != *session {
        return Err(session_mismatch(
            path,
            "made for another signing session (another IPST, signing set or authority)",
        ));
    }
    if sender != party {
        return Err(session_mismatch(
            path,
            format_args!("from party {sender}, expected party {party}"),
        ));
    }
    if !shares.keys().eq(inputs.iter()) || shares.len() != count as usize {
        return Err(session_mismatch(path, "signs other inputs"));
    }
    Ok((set_digest, shares))
}

fn read_group(path: &Path) -> Result<GroupKey, CliError> {
    let bytes = read_public(path, GROUP_TAG)?;
    GroupKey::from_bytes(&bytes).map_err(|_| malformed(path, "a group file"))
}

// =============================================================================================
// impulse frost keygen
// =============================================================================================

fn keygen(a: KeygenArgs, console: &dyn Console) -> Result<(), CliError> {
    let shape = GroupShape::new(a.threshold, a.parties).map_err(threshold_error)?;
    if a.party == 0 || a.party > a.parties {
        return Err(threshold_error(ThresholdError::Party {
            id: a.party,
            parties: a.parties,
        }));
    }
    must_be_dir(&a.dir)?;
    for path in [&a.share_file, &a.group_out] {
        must_not_exist(path)?;
        parent_exists(path)?;
    }
    must_not_exist(&a.dir.join(round1_name(a.party)))?;
    console.say(&format!(
        "frost keygen: party {} of a {}-of-{} group, files in {}",
        a.party,
        a.threshold,
        a.parties,
        a.dir.display()
    ))?;
    let done = crate::keygen::run(&crate::keygen::KeygenRequest {
        shape,
        party: a.party,
        dir: &a.dir,
        share_file: &a.share_file,
        group_file: &a.group_out,
        console,
    })?;
    console.say(&format!(
        "wrote: {} (secret: your key share; keep it on this machine and never send it)",
        a.share_file.display()
    ))?;
    console.say(&format!("wrote: {} (public)", a.group_out.display()))?;
    for path in &done.removed {
        console.say(&format!("removed: {}", path.display()))?;
    }
    if !done.not_removed.is_empty() {
        for (path, why) in &done.not_removed {
            console.say(&format!(
                "could not remove: {}: {why} (it holds a secret share for you: delete it yourself)",
                path.display()
            ))?;
        }
        return Err(CliError::new(
            "FROST_ROUND2_NOT_REMOVED",
            format!(
                "the share and group files are written, but {} round-2 file(s) addressed to this party could not be removed; delete them yourself",
                done.not_removed.len()
            ),
        ));
    }
    console.say(&format!(
        "delete every copy of your round2-{}-to-*.frost files once each recipient has its file",
        a.party
    ))?;
    console.say(&format!(
        "ok: party {} of {}-of-{}, authority key {}, group fingerprint {}",
        a.party,
        a.threshold,
        a.parties,
        hex(&done.authority_key),
        hex(&done.fingerprint)
    ))
}

// =============================================================================================
// impulse frost sign
// =============================================================================================

fn kind_line(kind: &IpstKind) -> String {
    match kind {
        IpstKind::Settle => "settle".into(),
        IpstKind::Refund {
            leg,
            signer,
            with_token,
        } => format!(
            "refund of the {} leg, triggered by {signer:?}{}",
            leg_name(*leg),
            if *with_token {
                ", with the escrowed token"
            } else {
                ""
            }
        ),
        other => format!("{other:?}"),
    }
}

fn sign(ctx: &Ctx, a: SignArgs, console: &dyn Console) -> Result<(), CliError> {
    let ipst = read_ipst(ctx, &a.ipst)?;
    let (authority, inputs) = authority_inputs(&ipst)?;
    // The trade the signer named, before the share file is read or anything is written.
    check_agreed_as(
        &a.agreed,
        &ipst.terms().terms_hash(),
        "FROST_TERMS_NOT_AGREED",
    )?;
    let signers = parse_signers(&a.signers)?;
    let asset = read_template(&a.asset_template)?;
    let cash = a.cash_template.as_deref().map(read_template).transpose()?;
    let creation_args = CreationArgs {
        daa: a.daa.daa,
        node: a.daa.node.clone(),
    };
    let now = creation(ctx, &creation_args)?.creation_daa;
    let found = ipst
        .verify_against_terms(&asset, cash.as_ref(), now)
        .map_err(tx_error)?;
    check_kind(&found.kind)?;
    let terms: &ValidatedTerms = ipst.terms();
    let cap_line = cap(ctx, &a.cap, terms)?;
    must_be_dir(&a.dir)?;
    let session = session_id(&ipst, &authority, &signers, &inputs)?;
    let mut lines = summary::summary(&terms.terms_hash(), terms.terms(), now);
    lines.push(format!(
        "transaction: {} {}, fee {} sompi",
        kind_line(&found.kind),
        ipst.transaction().id(),
        found.fee
    ));
    let network = terms.terms().network;
    for (i, o) in ipst.transaction().outputs.iter().enumerate() {
        let covenant = o.covenant.map_or(String::new(), |c| {
            format!(", covenant {}", hex(&c.covenant_id.as_bytes()))
        });
        lines.push(format!(
            "output {i}: {} sompi to {}{covenant}",
            o.value,
            address(network, &o.script_public_key)
        ));
    }
    lines.push(match &found.change {
        Some(c) => format!(
            "change: {} sompi to {} (the fee payer's)",
            c.value,
            address(network, &c.script_public_key)
        ),
        None => "change: none".to_string(),
    });
    lines.push(format!(
        "authority inputs: {} (authority_key {})",
        list(&inputs),
        hex(&authority)
    ));
    lines.push(format!("signers: {}", list(&signers)));
    lines.push(format!("session: {}", hex(&session)));
    lines.push(cap_line);

    // Runs inside the signing module once the share is read and every check has passed: the
    // first point at which anything is printed or written.
    let exchange =
        |me: PartyId, mine: &BTreeMap<usize, Commitment>| -> Result<CommitmentSet, CliError> {
            let own = a.dir.join(commit_name(me));
            must_not_exist(&own)?;
            must_not_exist(&a.dir.join(sigshare_name(me)))?;
            for l in &lines {
                console.say(l)?;
            }
            console.say(&format!("you are party {me}"))?;
            write_new(
                &own,
                &public_file(COMMIT_TAG, &commit_body(&session, me, mine)?),
            )?;
            console.say(&format!(
                "wrote: {} (public: send it to every other signer)",
                own.display()
            ))?;
            let others: Vec<PartyId> = signers.iter().copied().filter(|&j| j != me).collect();
            let names: Vec<String> = others.iter().map(|&j| commit_name(j)).collect();
            wait_for(console, "commitments", &a.dir, &names)?;
            let mut set = CommitmentSet::new();
            for j in others {
                let path = a.dir.join(commit_name(j));
                set.insert(j, read_commit(&path, &session, j, &inputs)?);
            }
            approve(console, &session, &terms.terms_hash())?;
            Ok(set)
        };
    let signed = signing::sign(&FrostSignRequest {
        share_file: &a.share_file,
        mainnet_explicit: ctx.mainnet_explicit,
        ipst: &ipst,
        signers: &signers,
        exchange: &exchange,
    })?;
    let set_digest = commitment_set_digest(&session, &signed.commitments)?;
    let body = sigshare_body(&session, &set_digest, signed.party, &signed.shares);
    let path = a.dir.join(sigshare_name(signed.party));
    write_new(&path, &public_file(SIGSHARE_TAG, &body))?;
    console.say(&format!(
        "wrote: {} (public: send it, with every commit file, to whoever aggregates)",
        path.display()
    ))?;
    console.say(&format!(
        "ok: party {} signed inputs {} of session {}",
        signed.party,
        list(signed.shares.keys()),
        hex(&session)
    ))
}

// =============================================================================================
// impulse frost aggregate
// =============================================================================================

fn aggregate(ctx: &Ctx, a: AggregateArgs, console: &dyn Console) -> Result<(), CliError> {
    let mut ipst = read_ipst(ctx, &a.ipst)?;
    let (authority, inputs) = authority_inputs(&ipst)?;
    let signers = parse_signers(&a.signers)?;
    let group = read_group(&a.group)?;
    if group.authority_key() != authority {
        return Err(CliError::new(
            "FROST_KEY_NOT_AUTHORITY",
            format!(
                "{}: the group's authority key is {}, the terms' is {}",
                a.group.display(),
                hex(&group.authority_key()),
                hex(&authority)
            ),
        ));
    }
    check_signers(group.shape(), &signers)?;
    must_not_exist(&a.out)?;
    let session = session_id(&ipst, &authority, &signers, &inputs)?;
    let mut set = CommitmentSet::new();
    let mut shares = BTreeMap::new();
    for &j in &signers {
        let path = a.dir.join(commit_name(j));
        set.insert(j, read_commit(&path, &session, j, &inputs)?);
    }
    let set_digest = commitment_set_digest(&session, &set)?;
    for &j in &signers {
        let path = a.dir.join(sigshare_name(j));
        let (theirs, by_input) = read_sigshare(&path, &session, j, &inputs)?;
        if theirs != set_digest {
            return Err(session_mismatch(
                &path,
                "signed against other commitments than the commit files here",
            ));
        }
        shares.insert(j, by_input);
    }
    for &input in &inputs {
        let commitments: BTreeMap<PartyId, Commitment> =
            set.iter().map(|(&j, c)| (j, c[&input])).collect();
        let input_shares: BTreeMap<PartyId, SignatureShare> =
            shares.iter().map(|(&j, s)| (j, s[&input])).collect();
        let auth_sig = aggregate_input(
            &group,
            ipst.transaction(),
            ipst.entries(),
            input,
            &commitments,
            &input_shares,
        )
        .map_err(threshold_error)?;
        ipst.add_signature(input, &auth_sig).map_err(tx_error)?;
    }
    write_new(&a.out, &ipst.to_json())?;
    console.say(&format!("group fingerprint: {}", hex(&group.fingerprint())))?;
    console.say(&format!("session: {}", hex(&session)))?;
    console.say(&format!("signers: {}", list(&signers)))?;
    console.say(&format!(
        "signed: inputs {} with the authority key {}",
        list(&inputs),
        hex(&authority)
    ))?;
    console.say(&format!("wrote: {}", a.out.display()))?;
    console.say(&format!(
        "ok: {} authority signature(s) in the IPST; pending inputs: {}",
        inputs.len(),
        match ipst.pending() {
            p if p.is_empty() => "none".to_string(),
            p => list(p),
        }
    ))
}
