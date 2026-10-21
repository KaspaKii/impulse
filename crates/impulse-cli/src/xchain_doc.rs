// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The files of the `xchain` commands (spec/V2.md section 10.9): the hashlock draft and terms
//! file, the secret file, the known hash locks, the DAA rate sample, and the version 3 document
//! of a hashlock partially signed transaction (D52, D53).
//!
//! The secret file holds the seller's secret or a revealed preimage. It is written only as a new
//! file with mode 0600 and read only from a file nobody but its owner can access; its content is
//! held in buffers zeroed on drop and never appears in a message.

use crate::error::CliError;
use crate::json::{hex, parse_dec, parse_strict, unhex32, Json, Obj};
use impulse_core::htlc::{
    Counterpart, CounterpartChain, DaaRateSample, HtlcIpst, HtlcSlotParts, HtlcTerms,
    ValidatedHtlcTerms,
};
use impulse_core::terms::{IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network};
use kaspa_consensus_core::constants::MAX_SOMPI;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;
use serde_json::Value;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// The document version of a hashlock partially signed transaction (spec/V2.md section 10.9).
pub const HTLC_IPST_VERSION: u64 = 3;

const TERMS_KEYS: [&str; 12] = [
    "version",
    "network",
    "nonce",
    "seller_key",
    "buyer_key",
    "asset_leg",
    "buyer_delivery",
    "seller_refund",
    "hash_lock",
    "expiry_daa",
    "counterpart",
    "trade_ref",
];

fn json_err(reason: String) -> CliError {
    CliError::new("CLI_TERMS_JSON", reason)
}

pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

pub fn chain_name(c: CounterpartChain) -> &'static str {
    match c {
        CounterpartChain::Solana => "solana",
        CounterpartChain::OtherSha256 => "other_sha256",
    }
}

pub fn owner_text(o: &Kcc20Owner) -> String {
    let kind = match o.identifier_type {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    };
    format!("kcc20:{kind}:{}", hex(&o.identifier))
}

// =============================================================================================
// Draft and terms file
// =============================================================================================

/// A draft: the JSON form without `hash_lock`, `nonce` optional (drawn at random when absent).
/// The terms it returns carry an all-zero hash lock, which `xchain new` replaces with the hash of
/// a fresh secret before any check runs.
pub fn parse_draft(text: &str) -> Result<HtlcTerms, CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    if obj.get("hash_lock").is_ok() {
        return Err(json_err(
            "hash_lock: a draft never carries one; xchain new makes it from a fresh secret".into(),
        ));
    }
    let required: Vec<&str> = TERMS_KEYS
        .into_iter()
        .filter(|k| *k != "nonce" && *k != "hash_lock")
        .collect();
    obj.keys(&required, &["nonce"]).map_err(json_err)?;
    let nonce = match obj.opt("nonce") {
        Some(_) => obj.dec("nonce").map_err(json_err)?,
        None => rand::random::<u64>(),
    };
    fields(&obj, nonce, [0; 32]).map_err(json_err)
}

/// The JSON form, every key present and no other.
pub fn parse_terms_json(value: &Value) -> Result<HtlcTerms, CliError> {
    let obj = Obj::new("terms", value).map_err(json_err)?;
    obj.keys(&TERMS_KEYS, &[]).map_err(json_err)?;
    let nonce = obj.dec("nonce").map_err(json_err)?;
    let hash_lock = obj.hex32("hash_lock").map_err(json_err)?;
    fields(&obj, nonce, hash_lock).map_err(json_err)
}

fn fields(o: &Obj, nonce: u64, hash_lock: [u8; 32]) -> Result<HtlcTerms, String> {
    let leg = o.obj("asset_leg")?;
    leg.keys(
        &[
            "kind",
            "covenant_id",
            "template_hash",
            "template_prefix_len",
            "template_suffix_len",
            "amount",
        ],
        &[],
    )?;
    leg.choice("kind", &["kcc20"])?;
    let c = o.obj("counterpart")?;
    c.keys(
        &[
            "chain",
            "chain_id",
            "htlc_program",
            "asset",
            "amount",
            "recipient",
            "refund",
            "timeout",
        ],
        &[],
    )?;
    Ok(HtlcTerms {
        version: o.num("version", u8::MAX.into())? as u8,
        network: [Network::Mainnet, Network::Testnet]
            [o.choice("network", &["mainnet", "testnet"])?],
        nonce,
        seller_key: o.hex32("seller_key")?,
        buyer_key: o.hex32("buyer_key")?,
        asset_leg: Leg {
            kind: LegKind::Kcc20(Kcc20Token {
                covenant_id: leg.hex32("covenant_id")?,
                template_hash: leg.hex32("template_hash")?,
                template_prefix_len: leg.num("template_prefix_len", u32::MAX.into())? as u32,
                template_suffix_len: leg.num("template_suffix_len", u32::MAX.into())? as u32,
            }),
            amount: leg.dec("amount")?,
        },
        buyer_delivery: owner(&o.obj("buyer_delivery")?)?,
        seller_refund: owner(&o.obj("seller_refund")?)?,
        hash_lock,
        expiry_daa: o.dec("expiry_daa")?,
        counterpart: Counterpart {
            chain: [CounterpartChain::Solana, CounterpartChain::OtherSha256]
                [c.choice("chain", &["solana", "other_sha256"])?],
            chain_id: c.hex32("chain_id")?,
            htlc_program: c.hex32("htlc_program")?,
            asset: c.hex32("asset")?,
            amount: c.dec("amount")?,
            recipient: c.hex32("recipient")?,
            refund: c.hex32("refund")?,
            timeout: c.dec("timeout")?,
        },
        trade_ref: o.hex32("trade_ref")?,
    })
}

fn owner(o: &Obj) -> Result<Kcc20Owner, String> {
    o.keys(&["identifier_type", "identifier"], &[])?;
    Ok(Kcc20Owner {
        identifier_type: [
            IdentifierType::PubKey,
            IdentifierType::ScriptHash,
            IdentifierType::CovenantId,
        ][o.choice("identifier_type", &["pubkey", "script_hash", "covenant_id"])?],
        identifier: o.hex32("identifier")?,
    })
}

fn owner_json(o: &Kcc20Owner) -> Json {
    let text = owner_text(o);
    let kind = text.split(':').nth(1).unwrap_or_default().to_string();
    Json::Obj(vec![
        ("identifier_type", Json::Str(kind)),
        ("identifier", Json::Str(hex(&o.identifier))),
    ])
}

/// The JSON form of `t` in field order, as the vectors of spec/V2.md section 10.8 write it.
pub fn terms_json(t: &HtlcTerms) -> Json {
    let dec = |n: u64| Json::Str(n.to_string());
    let s = |b: &[u8]| Json::Str(hex(b));
    let asset = match t.asset_leg.kind {
        LegKind::Kcc20(token) => Json::Obj(vec![
            ("kind", Json::Str("kcc20".into())),
            ("covenant_id", s(&token.covenant_id)),
            ("template_hash", s(&token.template_hash)),
            (
                "template_prefix_len",
                Json::Num(token.template_prefix_len.into()),
            ),
            (
                "template_suffix_len",
                Json::Num(token.template_suffix_len.into()),
            ),
            ("amount", dec(t.asset_leg.amount)),
        ]),
        // The structure checks refuse any other kind before a terms file is written.
        _ => Json::Null,
    };
    let c = &t.counterpart;
    Json::Obj(vec![
        ("version", Json::Num(t.version.into())),
        ("network", Json::Str(network_name(t.network).into())),
        ("nonce", dec(t.nonce)),
        ("seller_key", s(&t.seller_key)),
        ("buyer_key", s(&t.buyer_key)),
        ("asset_leg", asset),
        ("buyer_delivery", owner_json(&t.buyer_delivery)),
        ("seller_refund", owner_json(&t.seller_refund)),
        ("hash_lock", s(&t.hash_lock)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "counterpart",
            Json::Obj(vec![
                ("chain", Json::Str(chain_name(c.chain).into())),
                ("chain_id", s(&c.chain_id)),
                ("htlc_program", s(&c.htlc_program)),
                ("asset", s(&c.asset)),
                ("amount", dec(c.amount)),
                ("recipient", s(&c.recipient)),
                ("refund", s(&c.refund)),
                ("timeout", dec(c.timeout)),
            ]),
        ),
        ("trade_ref", s(&t.trade_ref)),
    ])
}

/// The hashlock terms file: `terms`, `canonical`, `htlc_terms_hash`.
pub fn render_terms_file(terms: &ValidatedHtlcTerms) -> String {
    Json::Obj(vec![
        ("terms", terms_json(terms.terms())),
        ("canonical", Json::Str(hex(terms.canonical()))),
        ("htlc_terms_hash", Json::Str(hex(&terms.terms_hash()))),
    ])
    .render()
}

/// Reads a hashlock terms file and refuses it unless its three parts agree.
pub fn parse_terms_file(text: &str) -> Result<ValidatedHtlcTerms, CliError> {
    let value = parse_strict(text).map_err(json_err)?;
    let obj = Obj::new("", &value).map_err(json_err)?;
    obj.keys(&["terms", "canonical", "htlc_terms_hash"], &[])
        .map_err(json_err)?;
    let terms = parse_terms_json(obj.get("terms").map_err(json_err)?)?;
    let canonical = obj.hex("canonical").map_err(json_err)?;
    let hash = obj.hex32("htlc_terms_hash").map_err(json_err)?;
    let checked = terms.validate_structure().map_err(super::htlc_err)?;
    if checked.canonical() != canonical.as_slice() || checked.terms_hash() != hash {
        return Err(CliError::new(
            "CLI_TERMS_FILE_INCONSISTENT",
            "the terms file's terms, canonical bytes and htlc_terms_hash disagree",
        ));
    }
    Ok(checked)
}

pub fn read_terms_file(path: &Path) -> Result<ValidatedHtlcTerms, CliError> {
    parse_terms_file(&crate::terms_file::read_text(path)?)
}

// =============================================================================================
// Secret file
// =============================================================================================

fn secret_file_error(path: &Path, why: &str) -> CliError {
    CliError::new("XCHAIN_SECRET_FILE", format!("{}: {why}", path.display()))
}

/// Writes 32 bytes as a new secret file: 64 lowercase hex digits and a line feed, mode 0600.
pub fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::new("CLI_OUTPUT_EXISTS", format!("{} exists", path.display()))
        } else {
            CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display()))
        }
    })?;
    let mut text = Zeroizing::new(String::with_capacity(65));
    for b in bytes {
        text.push_str(&format!("{b:02x}"));
    }
    text.push('\n');
    file.write_all(text.as_bytes())
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))
}

/// Reads a secret file: a regular file only its owner can access, 64 lowercase hex digits and at
/// most one final line feed. The bytes it returns are zeroed on drop.
pub fn read_secret(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut file =
        std::fs::File::open(path).map_err(|_| secret_file_error(path, "cannot be opened"))?;
    let meta = file
        .metadata()
        .map_err(|_| secret_file_error(path, "cannot be read"))?;
    if !meta.is_file() {
        return Err(secret_file_error(path, "is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(secret_file_error(
                path,
                "group or others can access it; it must be mode 0600 or stricter",
            ));
        }
    }
    let mut buf = Zeroizing::new(vec![0u8; 66]);
    let mut n = 0;
    loop {
        let got = file
            .read(&mut buf[n..])
            .map_err(|_| secret_file_error(path, "cannot be read"))?;
        if got == 0 {
            break;
        }
        n += got;
        if n == buf.len() {
            break;
        }
    }
    let content = &buf[..n];
    let digits = match content {
        [d @ .., b'\n'] => d,
        d => d,
    };
    let form = "must hold 64 lowercase hex digits and at most one final line feed";
    if digits.len() != 64
        || !digits
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(secret_file_error(path, form));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(32));
    for pair in digits.chunks(2) {
        let v = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        };
        out.push(v(pair[0]) << 4 | v(pair[1]));
    }
    Ok(out)
}

// =============================================================================================
// Known hash locks
// =============================================================================================

/// One line of the known hash locks: (hash_lock, htlc_terms_hash).
type Known = ([u8; 32], [u8; 32]);

fn known_lines(path: &Path) -> Result<Vec<Known>, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => {
            return Err(CliError::new(
                "CLI_FILE_READ",
                format!("{}: {e}", path.display()),
            ))
        }
    };
    text.lines()
        .enumerate()
        .map(|(n, l)| {
            l.split_once(' ')
                .and_then(|(a, b)| Some((unhex32(a)?, unhex32(b)?)))
                .ok_or_else(|| {
                    CliError::new(
                        "CLI_FILE_READ",
                        format!(
                            "{} line {}: expected <hash_lock> <htlc_terms_hash> in lowercase hex",
                            path.display(),
                            n + 1
                        ),
                    )
                })
        })
        .collect()
}

/// Refuses a hash lock this installation knows under other terms (`XCHAIN_HASH_REUSED`, R8).
/// Returns whether the same trade is already recorded.
pub fn check_known(
    path: &Path,
    hash_lock: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<bool, CliError> {
    let mut same = false;
    for (h, t) in known_lines(path)? {
        if h == *hash_lock {
            if t != *terms_hash {
                return Err(CliError::new(
                    "XCHAIN_HASH_REUSED",
                    format!(
                        "hash_lock {} is already used by the trade with terms hash {} ({}): a hash lock serves one trade only",
                        hex(hash_lock),
                        hex(&t),
                        path.display()
                    ),
                ));
            }
            same = true;
        }
    }
    Ok(same)
}

/// Appends a trade to the known hash locks, creating the file with mode 0600.
pub fn record_known(
    path: &Path,
    hash_lock: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))?;
    writeln!(file, "{} {}", hex(hash_lock), hex(terms_hash))
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))
}

// =============================================================================================
// DAA rate sample
// =============================================================================================

fn sample_error(path: &Path, why: String) -> CliError {
    CliError::new("HTLC_DAA_SAMPLE", format!("{}: {why}", path.display()))
}

/// The header line of a sample file.
pub fn sample_header(network: Network, bps: u64) -> String {
    format!("impulse-daa-sample 1 {} bps {bps}", network_name(network))
}

/// The most bytes of a sample file read: a point a minute for the 30 days a sample may span is
/// about 1.4 MiB.
pub const MAX_SAMPLE_FILE: u64 = 4 << 20;

/// Reads a DAA rate sample file for `network`. The points are judged by `daa_rate_max`.
pub fn read_sample(path: &Path, network: Network) -> Result<DaaRateSample, CliError> {
    let bytes = crate::terms_file::read_bounded(path, MAX_SAMPLE_FILE)
        .map_err(|e| sample_error(path, format!("cannot be read: {e}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| sample_error(path, "cannot be read: not UTF-8".into()))?;
    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default();
    let words: Vec<&str> = header.split(' ').collect();
    let bps = match words.as_slice() {
        ["impulse-daa-sample", "1", net, "bps", bps] => {
            if *net != network_name(network) {
                return Err(sample_error(
                    path,
                    format!("the sample is for {net:?}, not {}", network_name(network)),
                ));
            }
            parse_dec(bps).ok_or_else(|| sample_error(path, "the header's bps".into()))?
        }
        _ => {
            return Err(sample_error(
                path,
                "line 1 is not `impulse-daa-sample 1 <network> bps <n>`".into(),
            ))
        }
    };
    let points = lines
        .enumerate()
        .map(|(n, l)| {
            l.split_once(' ')
                .and_then(|(a, b)| Some((parse_dec(a)?, parse_dec(b)?)))
                .ok_or_else(|| {
                    sample_error(
                        path,
                        format!("line {}: expected <unix seconds> <DAA score>", n + 2),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DaaRateSample { bps, points })
}

/// Appends one point, creating the file with its header. Refuses a file for another network or
/// blocks-per-second, and a point not after the file's last.
pub fn append_sample(
    path: &Path,
    network: Network,
    bps: u64,
    unix: u64,
    daa: u64,
) -> Result<(), CliError> {
    let write_err =
        |e: std::io::Error| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display()));
    if path.exists() {
        let sample = read_sample(path, network)?;
        if sample.bps != bps {
            return Err(sample_error(
                path,
                format!(
                    "the sample was taken at {} blocks per second; the node runs at {bps}",
                    sample.bps
                ),
            ));
        }
        if let Some((t, d)) = sample.points.last() {
            if *t >= unix || *d > daa {
                return Err(sample_error(
                    path,
                    format!("the last point ({t}, {d}) is not before ({unix}, {daa})"),
                ));
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(write_err)?;
        writeln!(file, "{unix} {daa}").map_err(write_err)
    } else {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(write_err)?;
        write!(file, "{}\n{unix} {daa}\n", sample_header(network, bps)).map_err(write_err)
    }
}

// =============================================================================================
// The version 3 document of a hashlock partially signed transaction
// =============================================================================================

/// A value of the canonical rendering of spec/IPST.md.
enum D {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Arr(Vec<D>),
    Obj(Vec<(&'static str, D)>),
}

fn render(d: &D, indent: usize, out: &mut String) {
    let pad = |n: usize, out: &mut String| out.push_str(&" ".repeat(n));
    match d {
        D::Null => out.push_str("null"),
        D::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        D::Int(n) => out.push_str(&n.to_string()),
        // Only hex and decimal strings are rendered: nothing needs escaping.
        D::Str(s) => {
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        D::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                pad(indent + 2, out);
                render(item, indent + 2, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push(']');
        }
        D::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                pad(indent + 2, out);
                out.push('"');
                out.push_str(key);
                out.push_str("\": ");
                render(value, indent + 2, out);
                if i + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(indent, out);
            out.push('}');
        }
    }
}

fn spk(s: &ScriptPublicKey) -> D {
    D::Obj(vec![
        ("version", D::Int(s.version().into())),
        ("script", D::Str(hex(s.script()))),
    ])
}

fn opt32(v: Option<[u8; 32]>) -> D {
    v.map_or(D::Null, |b| D::Str(hex(&b)))
}

/// The canonical text of a version 3 document.
pub fn ipst_json(ipst: &HtlcIpst) -> String {
    let tx = ipst.transaction();
    let inputs = tx
        .inputs
        .iter()
        .zip(ipst.entries())
        .zip(ipst.slots())
        .map(|((input, entry), slot)| {
            D::Obj(vec![
                (
                    "transaction_id",
                    D::Str(hex(&input.previous_outpoint.transaction_id.as_bytes())),
                ),
                ("index", D::Int(input.previous_outpoint.index.into())),
                ("sequence", D::Str(input.sequence.to_string())),
                (
                    "compute_budget",
                    D::Int(input.compute_commit.compute_budget().unwrap_or(0).into()),
                ),
                (
                    "utxo",
                    D::Obj(vec![
                        ("amount", D::Str(entry.amount.to_string())),
                        ("script_public_key", spk(&entry.script_public_key)),
                        ("block_daa_score", D::Str(entry.block_daa_score.to_string())),
                        ("is_coinbase", D::Bool(entry.is_coinbase)),
                        (
                            "covenant_id",
                            opt32(entry.covenant_id.map(|c| c.as_bytes())),
                        ),
                    ]),
                ),
                ("signer", opt32(slot.signer())),
                ("sighash", opt32(slot.sighash())),
                (
                    "signature",
                    slot.signature().map_or(D::Null, |s| D::Str(hex(&s))),
                ),
                ("script_before", D::Str(hex(slot.script_before()))),
                ("script_after", D::Str(hex(slot.script_after()))),
            ])
        })
        .collect();
    let outputs = tx
        .outputs
        .iter()
        .map(|o| {
            D::Obj(vec![
                ("value", D::Str(o.value.to_string())),
                ("script_public_key", spk(&o.script_public_key)),
                (
                    "covenant",
                    o.covenant.map_or(D::Null, |c| {
                        D::Obj(vec![
                            ("authorizing_input", D::Int(c.authorizing_input.into())),
                            ("covenant_id", D::Str(hex(&c.covenant_id.as_bytes()))),
                        ])
                    }),
                ),
            ])
        })
        .collect();
    let doc = D::Obj(vec![
        ("ipst", D::Int(HTLC_IPST_VERSION)),
        ("terms", D::Str(hex(ipst.terms().canonical()))),
        ("lock_time", D::Str(tx.lock_time.to_string())),
        ("inputs", D::Arr(inputs)),
        ("outputs", D::Arr(outputs)),
    ]);
    let mut out = String::new();
    render(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn malformed(reason: String) -> CliError {
    CliError::new("IPST_MALFORMED", reason)
}

fn array<'a>(o: &Obj<'a>, key: &str) -> Result<&'a Vec<Value>, String> {
    o.get(key)?
        .as_array()
        .ok_or_else(|| format!("{key}: expected an array"))
}

fn boolean(o: &Obj, key: &str) -> Result<bool, String> {
    o.get(key)?
        .as_bool()
        .ok_or_else(|| format!("{key}: expected true or false"))
}

fn opt<T>(o: &Obj, key: &str, f: impl Fn(&Obj) -> Result<T, String>) -> Result<Option<T>, String> {
    if o.is_null(key)? {
        Ok(None)
    } else {
        f(o).map(Some)
    }
}

fn read_spk(o: &Obj) -> Result<ScriptPublicKey, String> {
    o.keys(&["version", "script"], &[])?;
    Ok(ScriptPublicKey::from_vec(
        o.num("version", u16::MAX.into())? as u16,
        o.hex("script")?,
    ))
}

type InputParts = (TransactionInput, UtxoEntry, HtlcSlotParts);

fn read_input(v: &Value) -> Result<InputParts, String> {
    let f = Obj::new("input", v)?;
    f.keys(
        &[
            "transaction_id",
            "index",
            "sequence",
            "compute_budget",
            "utxo",
            "signer",
            "sighash",
            "signature",
            "script_before",
            "script_after",
        ],
        &[],
    )?;
    let outpoint = TransactionOutpoint::new(
        Hash::from_bytes(f.hex32("transaction_id")?),
        f.num("index", u32::MAX.into())? as u32,
    );
    let input = TransactionInput::new_with_compute_budget(
        outpoint,
        vec![],
        f.dec("sequence")?,
        f.num("compute_budget", u16::MAX.into())? as u16,
    );
    let u = f.obj("utxo")?;
    u.keys(
        &[
            "amount",
            "script_public_key",
            "block_daa_score",
            "is_coinbase",
            "covenant_id",
        ],
        &[],
    )?;
    let entry = UtxoEntry::new(
        u.dec("amount")?,
        read_spk(&u.obj("script_public_key")?)?,
        u.dec("block_daa_score")?,
        boolean(&u, "is_coinbase")?,
        opt(&u, "covenant_id", |u| u.hex32("covenant_id"))?.map(Hash::from_bytes),
    );
    let signature = opt(&f, "signature", |f| {
        f.hex("signature")?
            .try_into()
            .map_err(|_| "signature: expected 65 bytes of lowercase hex".to_string())
    })?;
    let parts = HtlcSlotParts {
        signer: opt(&f, "signer", |f| f.hex32("signer"))?,
        sighash: opt(&f, "sighash", |f| f.hex32("sighash"))?,
        signature,
        script_before: f.hex("script_before")?,
        script_after: f.hex("script_after")?,
    };
    Ok((input, entry, parts))
}

fn read_output(v: &Value, inputs: usize) -> Result<TransactionOutput, String> {
    let f = Obj::new("output", v)?;
    f.keys(&["value", "script_public_key", "covenant"], &[])?;
    let covenant = opt(&f, "covenant", |f| {
        let c = f.obj("covenant")?;
        c.keys(&["authorizing_input", "covenant_id"], &[])?;
        let authorizing_input = c.num("authorizing_input", u16::MAX.into())? as u16;
        if usize::from(authorizing_input) >= inputs {
            return Err("authorizing_input names no input".to_string());
        }
        Ok(CovenantBinding::new(
            authorizing_input,
            Hash::from_bytes(c.hex32("covenant_id")?),
        ))
    })?;
    Ok(TransactionOutput {
        value: f.dec("value")?,
        script_public_key: read_spk(&f.obj("script_public_key")?)?,
        covenant,
    })
}

/// Step 3 of reading, for values, before the terms are decoded (spec/IPST.md order).
fn check_values(inputs: &[InputParts], outputs: &[TransactionOutput]) -> Result<(), String> {
    let in_range = |v: u64| v > 0 && v <= MAX_SOMPI;
    let mut held: u64 = 0;
    for (n, (_, entry, _)) in inputs.iter().enumerate() {
        if !in_range(entry.amount) {
            return Err(format!("input {n}: amount outside 1 to MAX_SOMPI"));
        }
        held += entry.amount;
        if held > MAX_SOMPI {
            return Err("the UTXO amounts add up past MAX_SOMPI".into());
        }
    }
    let mut paid: u64 = 0;
    for (n, output) in outputs.iter().enumerate() {
        if !in_range(output.value) {
            return Err(format!("output {n}: value outside 1 to MAX_SOMPI"));
        }
        paid += output.value;
        if paid > held {
            return Err("the outputs pay more than the inputs hold".into());
        }
    }
    Ok(())
}

/// Reads a version 3 document (spec/V2.md section 10.9): the reading steps of spec/IPST.md with
/// version 3 and hashlock terms.
pub fn parse_ipst(text: &str) -> Result<HtlcIpst, CliError> {
    let value = parse_strict(text).map_err(malformed)?;
    let top = Obj::new("", &value).map_err(malformed)?;
    let version = match top.opt("ipst") {
        Some(v) if v.is_u64() || v.is_i64() => v.as_i64().unwrap_or(i64::MAX),
        _ => return Err(malformed("no integer ipst key".into())),
    };
    if version != HTLC_IPST_VERSION as i64 {
        return Err(CliError::new(
            "IPST_UNSUPPORTED_VERSION",
            format!("ipst {version}: a hashlock document is version {HTLC_IPST_VERSION}"),
        ));
    }
    top.keys(&["ipst", "terms", "lock_time", "inputs", "outputs"], &[])
        .map_err(malformed)?;
    let terms_bytes = top.hex("terms").map_err(malformed)?;
    let lock_time = top.dec("lock_time").map_err(malformed)?;
    let raw_inputs = array(&top, "inputs").map_err(malformed)?;
    let raw_outputs = array(&top, "outputs").map_err(malformed)?;
    if raw_inputs.is_empty() || raw_outputs.is_empty() {
        return Err(malformed("inputs and outputs must not be empty".into()));
    }
    let inputs = raw_inputs
        .iter()
        .enumerate()
        .map(|(n, v)| read_input(v).map_err(|e| malformed(format!("input {n}: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = raw_outputs
        .iter()
        .enumerate()
        .map(|(n, v)| {
            read_output(v, inputs.len()).map_err(|e| malformed(format!("output {n}: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_values(&inputs, &outputs).map_err(malformed)?;
    let terms = ValidatedHtlcTerms::decode(&terms_bytes).map_err(super::htlc_err)?;
    HtlcIpst::from_parts(terms, lock_time, inputs, outputs).map_err(super::htlc_err)
}

pub fn read_ipst(path: &Path) -> Result<HtlcIpst, CliError> {
    parse_ipst(&crate::terms_file::read_text(path)?)
}
