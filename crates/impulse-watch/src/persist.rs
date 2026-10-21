// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The local state file: [`WatchState`] as one JSON document, written whole after a round and
//! replaced atomically (a temporary file in the same directory, flushed, then renamed over the
//! old one), so a crash at any moment leaves the previous file or the new one, never half of
//! either. No database. The format is specified in spec/WATCH.md ("State file").
//!
//! The reader is strict and fails closed (`WATCH_STATE_INVALID`): exact key sets, no key twice,
//! lowercase hex, decimal u64 strings; a state is refused unless it is consistent with itself
//! (every effect names a trade of the state, a transaction's ID is its contents' ID, a spend
//! carries its accepted copy and only a spend does, a pending rebroadcast is a kept
//! transaction that is not accepted). A state of another network is `WATCH_STATE_MISMATCH`.
//! The acceptance index of the tracker is not stored: it is rebuilt from the accepted
//! transactions, so the two cannot disagree. Holds no key and no secret.

use crate::error::WatchError;
use crate::files::{hex, parse_strict, unhex32, Obj};
use crate::node::network_name;
use crate::tracker::{
    AcceptanceInfo, Cursor, InMemoryVirtualChainStore, VirtualChainStore, VirtualChainTracker,
};
use crate::trades::{Effect, Leg, TradeId};
use crate::watcher::{Accepted, Pending, WatchState};
use borsh::BorshDeserialize;
use impulse_core::decode::encode_raw;
use impulse_core::terms::Network;
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::{Transaction, TransactionId, TransactionOutpoint};
use kaspa_consensus_core::Hash;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The `format` value of a state file.
pub const FORMAT: &str = "impulse-watch-state";
/// The `version` value of a state file.
pub const VERSION: u64 = 1;

// ---- encoding ----

fn dec(n: u64) -> Value {
    Value::String(n.to_string())
}

fn opt_dec(n: Option<u64>) -> Value {
    n.map_or(Value::Null, dec)
}

fn leg_name(leg: Leg) -> Value {
    crate::event::leg_json(leg)
}

fn cursor_json(c: &Cursor) -> Value {
    json!({"block": c.block_hash.to_string(), "daa": opt_dec(c.daa_score)})
}

fn outpoint_fields(m: &mut Map<String, Value>, spent: &TransactionOutpoint, value: u64) {
    m.insert("spent_txid".into(), json!(spent.transaction_id.to_string()));
    m.insert("spent_index".into(), json!(spent.index));
    m.insert("spent_value".into(), dec(value));
}

fn effect_json(effect: &Effect) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), json!(effect.name()));
    m.insert("trade".into(), json!(effect.trade().to_string()));
    if let Some(leg) = effect.leg() {
        m.insert("leg".into(), leg_name(leg));
    }
    match effect {
        Effect::Funded {
            index,
            value,
            exact,
            ..
        } => {
            m.insert("index".into(), json!(index));
            m.insert("value".into(), dec(*value));
            m.insert("exact".into(), json!(exact));
        }
        Effect::AuthorizerSeen {
            index,
            value,
            covenant_output,
            ..
        } => {
            m.insert("index".into(), json!(index));
            m.insert("value".into(), dec(*value));
            m.insert("covenant_output".into(), json!(covenant_output));
        }
        Effect::Settled {
            input,
            spent,
            spent_value,
            ..
        }
        | Effect::Refunded {
            input,
            spent,
            spent_value,
            ..
        }
        | Effect::Unclassified {
            input,
            spent,
            spent_value,
            ..
        } => {
            m.insert("input".into(), json!(input));
            outpoint_fields(&mut m, spent, *spent_value);
        }
        Effect::StrayDeposit { index, value, .. } => {
            m.insert("index".into(), json!(index));
            m.insert("value".into(), dec(*value));
        }
        Effect::ForeignToken {
            input, covenant_id, ..
        } => {
            m.insert("input".into(), json!(input));
            m.insert("covenant_id".into(), json!(covenant_id.to_string()));
        }
    }
    Value::Object(m)
}

fn raw_hex(tx: &Transaction) -> String {
    hex(&encode_raw(tx))
}

/// The state as one JSON document: pretty, keys in a fixed order, lists sorted, so equal states
/// give equal text. `network` is the network the watcher watches.
pub fn encode(state: &WatchState, network: Network) -> String {
    let trades: Vec<Value> = state
        .trades
        .iter()
        .map(|(trade, from)| json!({"trade": trade.to_string(), "from": from.as_ref().map_or(Value::Null, cursor_json)}))
        .collect();
    let mut accepted: Vec<(&TransactionId, &Accepted)> = state.accepted.iter().collect();
    accepted.sort_by_key(|(txid, _)| **txid);
    let accepted: Vec<Value> = accepted
        .into_iter()
        .map(|(txid, a)| {
            json!({
                "txid": txid.to_string(),
                "block": a.at.accepting_block_hash.to_string(),
                "daa": dec(a.at.accepting_daa_score),
                "finalized": a.finalized,
                "settle_expiry": opt_dec(a.settle_expiry),
                "tx": a.tx.as_ref().map_or(Value::Null, |t| json!(raw_hex(t))),
                "effects": a.effects.iter().map(effect_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    let kept: Vec<Value> = state.kept.iter().map(|t| json!(t.to_string())).collect();
    let pending: Vec<Value> = state
        .pending
        .iter()
        .map(|(txid, p)| {
            json!({
                "txid": txid.to_string(),
                "tx": raw_hex(&p.tx),
                "settle_expiry": opt_dec(p.settle_expiry),
                "attempts": p.attempts,
                "due": p.due,
            })
        })
        .collect();
    let doc = json!({
        "format": FORMAT,
        "version": VERSION,
        "network": network_name(network),
        "trades": trades,
        "cursor": state.tracker.store().cursor().as_ref().map_or(Value::Null, cursor_json),
        "accepted": accepted,
        "kept": kept,
        "pending": pending,
        "round": dec(state.round),
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("a JSON value serialises");
    text.push('\n');
    text
}

// ---- decoding ----

fn invalid(reason: String) -> WatchError {
    WatchError::StateInvalid(reason)
}

fn cursor_from(o: &Obj) -> Result<Cursor, String> {
    o.keys(&["block", "daa"])?;
    Ok(Cursor {
        block_hash: Hash::from_bytes(o.hex32("block")?),
        daa_score: o.opt_dec("daa")?,
    })
}

fn opt_cursor(o: &Obj, key: &str) -> Result<Option<Cursor>, String> {
    if o.is_null(key)? {
        Ok(None)
    } else {
        cursor_from(&o.obj(key)?).map(Some)
    }
}

/// `asset` or `cash` (a v1 leg), or a v2 leg's index, a number below MAX_LEGS.
fn leg_from(o: &Obj) -> Result<Leg, String> {
    if let Some(i) = o.get("leg")?.as_u64() {
        return u8::try_from(i)
            .ok()
            .filter(|i| usize::from(*i) < impulse_core::v2::MAX_LEGS)
            .map(Leg::V2)
            .ok_or_else(|| format!("leg: {i} is not a v2 leg index"));
    }
    match o.str("leg")? {
        "asset" => Ok(Leg::Asset),
        "cash" => Ok(Leg::Cash),
        other => Err(format!("leg: {other:?} is not asset or cash")),
    }
}

fn spent_from(o: &Obj) -> Result<(TransactionOutpoint, u64), String> {
    Ok((
        TransactionOutpoint::new(
            Hash::from_bytes(o.hex32("spent_txid")?),
            o.u32("spent_index")?,
        ),
        o.dec("spent_value")?,
    ))
}

fn effect_from(o: &Obj) -> Result<Effect, String> {
    let trade = TradeId(o.hex32("trade")?);
    match o.str("kind")? {
        "funded" => {
            o.keys(&["kind", "trade", "leg", "index", "value", "exact"])?;
            Ok(Effect::Funded {
                trade,
                leg: leg_from(o)?,
                index: o.u32("index")?,
                value: o.dec("value")?,
                exact: o.bool("exact")?,
            })
        }
        "authorizer_seen" => {
            o.keys(&["kind", "trade", "leg", "index", "value", "covenant_output"])?;
            Ok(Effect::AuthorizerSeen {
                trade,
                leg: leg_from(o)?,
                index: o.u32("index")?,
                value: o.dec("value")?,
                covenant_output: o.bool("covenant_output")?,
            })
        }
        kind @ ("settled" | "refunded" | "unclassified_spend") => {
            o.keys(&[
                "kind",
                "trade",
                "leg",
                "input",
                "spent_txid",
                "spent_index",
                "spent_value",
            ])?;
            let (leg, input) = (leg_from(o)?, o.u32("input")?);
            let (spent, spent_value) = spent_from(o)?;
            Ok(match kind {
                "settled" => Effect::Settled {
                    trade,
                    leg,
                    input,
                    spent,
                    spent_value,
                },
                "refunded" => Effect::Refunded {
                    trade,
                    leg,
                    input,
                    spent,
                    spent_value,
                },
                _ => Effect::Unclassified {
                    trade,
                    leg,
                    input,
                    spent,
                    spent_value,
                },
            })
        }
        "foreign_token" => {
            o.keys(&["kind", "trade", "leg", "input", "covenant_id"])?;
            Ok(Effect::ForeignToken {
                trade,
                leg: leg_from(o)?,
                input: o.u32("input")?,
                covenant_id: Hash::from_bytes(o.hex32("covenant_id")?),
            })
        }
        "stray_deposit" => {
            o.keys(&["kind", "trade", "index", "value"])?;
            Ok(Effect::StrayDeposit {
                trade,
                index: o.u32("index")?,
                value: o.dec("value")?,
            })
        }
        other => Err(format!("kind: {other:?} is not an effect")),
    }
}

fn tx_from(o: &Obj, key: &str) -> Result<Transaction, String> {
    let tx = Transaction::try_from_slice(&o.hex(key)?)
        .map_err(|_| format!("{key}: not exactly one borsh-encoded transaction"))?;
    if tx.id() != hashing::tx::id(&tx) {
        return Err(format!(
            "{key}: the carried ID is not the ID of the contents"
        ));
    }
    Ok(tx)
}

fn txid_list(o: &Obj, key: &str) -> Result<BTreeSet<TransactionId>, String> {
    let mut out = BTreeSet::new();
    for (i, v) in o.array(key)?.iter().enumerate() {
        let id = v
            .as_str()
            .and_then(unhex32)
            .ok_or_else(|| format!("{key}[{i}]: expected 64 lowercase hex digits"))?;
        if !out.insert(Hash::from_bytes(id)) {
            return Err(format!("{key}[{i}]: listed twice"));
        }
    }
    Ok(out)
}

/// Reads a state document. `WATCH_STATE_INVALID` for anything not in the accepted form or not
/// consistent with itself; `WATCH_STATE_MISMATCH` for a state of another network.
pub fn decode(text: &str, network: Network) -> Result<WatchState, WatchError> {
    let value = parse_strict(text).map_err(invalid)?;
    let o = Obj::new("", &value).map_err(invalid)?;
    o.keys(&[
        "format", "version", "network", "trades", "cursor", "accepted", "kept", "pending", "round",
    ])
    .map_err(invalid)?;
    if o.str("format").map_err(invalid)? != FORMAT {
        return Err(invalid(format!("format: not {FORMAT:?}")));
    }
    if o.get("version").map_err(invalid)?.as_u64() != Some(VERSION) {
        return Err(invalid(format!("version: not {VERSION}")));
    }
    let file_network = o.str("network").map_err(invalid)?;
    if file_network != network_name(network) {
        return Err(WatchError::StateMismatch {
            state: file_network.to_string(),
            watching: network_name(network),
        });
    }

    let mut trades = BTreeMap::new();
    for (i, v) in o.array("trades").map_err(invalid)?.iter().enumerate() {
        let t = Obj::new(&format!("trades[{i}]"), v).map_err(invalid)?;
        t.keys(&["trade", "from"]).map_err(invalid)?;
        let trade = TradeId(t.hex32("trade").map_err(invalid)?);
        let from = opt_cursor(&t, "from").map_err(invalid)?;
        if trades.insert(trade, from).is_some() {
            return Err(invalid(format!("trades[{i}]: listed twice")));
        }
    }
    let cursor = opt_cursor(&o, "cursor").map_err(invalid)?;

    let mut accepted = HashMap::new();
    let mut store = InMemoryVirtualChainStore::new();
    if let Some(c) = cursor {
        store.set_cursor(c);
    }
    for (i, v) in o.array("accepted").map_err(invalid)?.iter().enumerate() {
        let path = format!("accepted[{i}]");
        let a = Obj::new(&path, v).map_err(invalid)?;
        let one = || -> Result<(TransactionId, Accepted), String> {
            a.keys(&[
                "txid",
                "block",
                "daa",
                "finalized",
                "settle_expiry",
                "tx",
                "effects",
            ])?;
            let txid = Hash::from_bytes(a.hex32("txid")?);
            let at = AcceptanceInfo {
                accepting_block_hash: Hash::from_bytes(a.hex32("block")?),
                accepting_daa_score: a.dec("daa")?,
            };
            let mut effects = Vec::new();
            for (j, e) in a.array("effects")?.iter().enumerate() {
                let e = effect_from(&Obj::new(&format!("{path}.effects[{j}]"), e)?)?;
                if !trades.contains_key(&e.trade()) {
                    return Err(format!(
                        "{path}.effects[{j}]: trade {} is not a trade of the state",
                        e.trade()
                    ));
                }
                effects.push(e);
            }
            if effects.is_empty() {
                return Err(format!("{path}: no effect"));
            }
            let spends = effects.iter().any(Effect::is_spend);
            let tx = if a.is_null("tx")? {
                None
            } else {
                Some(tx_from(&a, "tx")?)
            };
            if tx.is_some() != spends {
                return Err(format!(
                    "{path}: a transaction carries its accepted copy exactly when it settles or refunds"
                ));
            }
            if tx.as_ref().is_some_and(|t| t.id() != txid) {
                return Err(format!("{path}: tx is not the transaction txid"));
            }
            let settle_expiry = a.opt_dec("settle_expiry")?;
            let settles = effects.iter().any(|e| matches!(e, Effect::Settled { .. }));
            if settle_expiry.is_some() != settles {
                return Err(format!(
                    "{path}: a transaction carries a settle expiry exactly when it settles"
                ));
            }
            Ok((
                txid,
                Accepted {
                    at,
                    effects,
                    tx,
                    settle_expiry,
                    finalized: a.bool("finalized")?,
                },
            ))
        };
        let (txid, entry) = one().map_err(invalid)?;
        store.upsert_acceptance(txid, entry.at);
        if accepted.insert(txid, entry).is_some() {
            return Err(invalid(format!("{path}: txid listed twice")));
        }
    }
    if cursor.is_none() && !accepted.is_empty() {
        return Err(invalid("accepted transactions without a cursor".into()));
    }

    let kept = txid_list(&o, "kept").map_err(invalid)?;
    let mut pending = BTreeMap::new();
    for (i, v) in o.array("pending").map_err(invalid)?.iter().enumerate() {
        let path = format!("pending[{i}]");
        let p = Obj::new(&path, v).map_err(invalid)?;
        let one = || -> Result<(TransactionId, Pending), String> {
            p.keys(&["txid", "tx", "settle_expiry", "attempts", "due"])?;
            let txid = Hash::from_bytes(p.hex32("txid")?);
            let tx = tx_from(&p, "tx")?;
            if tx.id() != txid {
                return Err(format!("{path}: tx is not the transaction txid"));
            }
            Ok((
                txid,
                Pending {
                    tx,
                    settle_expiry: p.opt_dec("settle_expiry")?,
                    attempts: p.u32("attempts")?,
                    due: p.bool("due")?,
                },
            ))
        };
        let (txid, entry) = one().map_err(invalid)?;
        if !kept.contains(&txid) {
            return Err(invalid(format!("{path}: pending but not kept")));
        }
        if accepted.contains_key(&txid) {
            return Err(invalid(format!("{path}: pending but accepted")));
        }
        if pending.insert(txid, entry).is_some() {
            return Err(invalid(format!("{path}: txid listed twice")));
        }
    }

    Ok(WatchState {
        trades,
        tracker: VirtualChainTracker::new(store),
        accepted,
        kept,
        pending,
        round: o.dec("round").map_err(invalid)?,
    })
}

// ---- the file ----

fn write_failed(path: &Path, e: impl std::fmt::Display) -> WatchError {
    WatchError::StateWriteFailed {
        path: path.display().to_string(),
        reason: e.to_string(),
    }
}

/// A name for the temporary file next to `name`: the process, the clock and a counter, so two
/// attempts never share one. It need not be unguessable: the file is created exclusively
/// (`O_EXCL`), which also refuses a symlink planted at the name, and a taken name is retried.
fn temp_path(dir: &Path, name: &std::ffi::OsStr) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    dir.join(format!(
        ".{}{TEMP_INFIX}{}.{nanos}.{}",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Between a state file's name and the rest of its temporary file's name.
const TEMP_INFIX: &str = ".tmp.";

/// How many names are tried before a write gives up.
const TEMP_TRIES: u32 = 16;

/// Replaces `path` with `text` atomically: the text goes to a new file in the same directory,
/// created exclusively and never opened by name if the name is taken, is flushed to disk, and is
/// renamed over `path`. If anything fails the temporary file is removed and `path` is as it
/// was (`WATCH_STATE_WRITE_FAILED`). The file is private to the owner (mode 0600 on Unix): it
/// holds signed transactions. A crash between the write and the rename leaves a temporary file
/// behind; [`remove_leftover_temp_files`] clears it at the next start.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), WatchError> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| write_failed(path, "no file name"))?;
    write_atomic_named(path, text, || temp_path(dir, name))
}

/// [`write_atomic`] with the temporary file's names given by `next_name`, tried in turn: a name
/// already taken is skipped, never opened. Separate so a test can plant a name.
pub(crate) fn write_atomic_named(
    path: &Path,
    text: &str,
    mut next_name: impl FnMut() -> PathBuf,
) -> Result<(), WatchError> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut created = None;
    for _ in 0..TEMP_TRIES {
        let tmp = next_name();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&tmp) {
            Ok(file) => {
                created = Some((tmp, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(write_failed(path, e)),
        }
    }
    let Some((tmp, mut file)) = created else {
        return Err(write_failed(path, "no free temporary file name"));
    };
    let written = (|| -> std::io::Result<()> {
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(write_failed(path, e));
    }
    // Best effort: the rename is done either way; this only makes it durable sooner.
    let _ = File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

/// Removes the temporary files a crashed write left next to the state file at `path` (named
/// `.<state file name>.tmp.*`), each a full copy of an earlier state, signed transactions
/// included. Call it with the state file locked, so no writer of this state is running. Returns
/// the names removed. A symlink with such a name is removed as a link, never followed.
pub fn remove_leftover_temp_files(path: &Path) -> Vec<String> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Some(name) = path.file_name() else {
        return vec![];
    };
    let prefix = format!(".{}{TEMP_INFIX}", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry
            .file_type()
            .is_ok_and(|t| t.is_file() || t.is_symlink());
        if file_name.starts_with(&prefix) && is_file && std::fs::remove_file(entry.path()).is_ok() {
            removed.push(file_name);
        }
    }
    removed.sort();
    removed
}

/// Reads and decodes the state file at `path`. `WATCH_FILE_READ` if it cannot be read.
pub fn load(path: &Path, network: Network) -> Result<WatchState, WatchError> {
    decode(&crate::files::read_text(path)?, network)
}

/// An advisory lock on `<state>.lock`, held for the life of the value and released by the
/// operating system when the process exits, however it exits. A second watcher on the same
/// state file would overwrite this one's rounds. A lock file this value created is removed
/// again when it is dropped while the state file does not exist, so a run that never started a
/// state leaves nothing behind.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
    lock_path: PathBuf,
    state_path: PathBuf,
    created: bool,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        if self.created && !self.state_path.exists() {
            let _ = std::fs::remove_file(&self.lock_path);
        }
    }
}

/// Takes the lock for the state file at `path` (`WATCH_STATE_LOCKED` if another holds it).
pub fn lock(path: &Path) -> Result<StateLock, WatchError> {
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let open = |create_new: bool| {
        let mut options = OpenOptions::new();
        options.write(true);
        if create_new {
            options.create_new(true);
        } else {
            options.create(true).truncate(false);
        }
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&lock_path)
    };
    let (file, created) = match open(true) {
        Ok(file) => (file, true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            (open(false).map_err(|e| write_failed(&lock_path, e))?, false)
        }
        Err(e) => return Err(write_failed(&lock_path, e)),
    };
    match file.try_lock() {
        Ok(()) => Ok(StateLock {
            _file: file,
            lock_path,
            state_path: path.to_path_buf(),
            created,
        }),
        // The lock file stays: it is the holder's.
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(WatchError::StateLocked(path.display().to_string()))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(write_failed(&lock_path, e)),
    }
}
