// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! What the `impulse-watch` binary does, as library functions so it is testable without a
//! process: [`prepare`] (everything before the node is contacted), [`drive`] (poll, rebroadcast,
//! print, save, repeat; generic over the node) and [`run`] (prepare, connect, drive).
//!
//! Each round is: poll the chain and submit the due rebroadcasts; print the round's events, one
//! JSON object per line, and flush them; then replace the state file if the state changed. The
//! events go out before the state is saved, so a crash between the two repeats the round's events
//! after the restart (at least once) instead of losing them, and the state file is always either
//! the previous round's or this one's. The binary signs nothing and holds no key. It submits
//! only the transactions the user named with `--keep-signed`, after a reorg removed them, and
//! only the copy the node had accepted.

use crate::cli::{LogFormat, ProbeArgs, RunArgs};
use crate::error::WatchError;
use crate::event::Event;
use crate::files::{read_sheet_file, read_signed_tx, read_terms_file};
use crate::node::{check_transport, probe, WrpcNode};
use crate::persist::{self, StateLock};
use crate::tracker::{FinalityPolicy, VirtualChainSource};
use crate::trades::TradeId;
use crate::watcher::{Broadcaster, Retention, WatchState, Watcher};
use impulse_core::terms::Network;
use kaspa_consensus_core::hashing;
use std::io::Write;
use std::time::Duration;

/// A watcher ready to poll: its state loaded, its trades added, its kept transactions marked,
/// and the state file locked.
pub struct Prepared {
    pub watcher: Watcher,
    network: Network,
    state_path: std::path::PathBuf,
    _lock: StateLock,
    /// The text of the state file as last written (or read), to skip a write that changes
    /// nothing.
    saved: Option<String>,
    /// Things the operator should know, for stderr.
    pub notes: Vec<String>,
    /// End the run after this many polls in a row failed (`--max-failed-polls`).
    pub max_failed_polls: Option<u64>,
    /// The form of the lines on stderr (`--log-format`).
    pub log_format: LogFormat,
    /// Polls that failed in a row, across calls of [`drive`].
    failed_in_a_row: u64,
}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub polls: u64,
    /// Polls that failed with `WATCH_SOURCE_FAILED` (nothing was applied for them).
    pub failed_polls: u64,
}

/// Everything before the node is contacted. Refuses, in this order, each before anything
/// further is read: a finality depth of 0; a retention window not above the finality depth;
/// a node URL that is not `ws://` or `wss://`, or on mainnet is neither `wss://` nor `ws://` to
/// this machine; a terms file or signed transaction that cannot be read or is not one; a trade
/// both retired and watched; a state file that is missing without `--init`, or present with it
/// (nothing is created next to a mistyped path), or a new one in a directory that does not
/// exist; the state file locked by another watcher; a state file that is unreadable, invalid or
/// of another network; a trade that cannot be added; retiring a trade the state does not hold
/// (after the trades are added, so the trades that stay are known); a signed transaction that
/// cannot be kept; and a trade of the state with no terms file given.
pub fn prepare(args: &RunArgs) -> Result<Prepared, WatchError> {
    let network: Network = args.network.into();
    let finality = FinalityPolicy::new(args.finality_depth)?;
    let retention = args
        .retention_daa
        .map(|r| Retention::new(r, finality))
        .transpose()?;
    check_transport(&args.node, network)?;
    let terms = args
        .trades
        .iter()
        .map(|p| read_terms_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let sheets = args
        .linked
        .iter()
        .map(|p| read_sheet_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let signed = args
        .keep_signed
        .iter()
        .map(|p| read_signed_tx(p))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(trade) = terms
        .iter()
        .map(|t| TradeId(t.terms_hash()))
        .find(|t| args.retire.contains(t))
    {
        return Err(WatchError::RetireWatched(trade));
    }

    check_state_location(&args.state, args.init)?;
    let lock = persist::lock(&args.state)?;
    let mut notes: Vec<String> = persist::remove_leftover_temp_files(&args.state)
        .into_iter()
        .map(|name| {
            format!("removed the leftover temporary state file {name:?} of an earlier crash")
        })
        .collect();
    let (state, saved) = load_state(&args.state, args.init, network)?;

    let mut watcher = Watcher::with_state(network, finality, state);
    if let Some(retention) = retention {
        watcher.set_retention(retention);
    }
    for t in terms {
        let watching = watcher.add_trade(t)?;
        if let Some(from) = watching.from {
            notes.push(format!(
                "trade {} is watched from chain block {} (DAA {}) only: nothing accepted before it is reported",
                watching.trade,
                from.block_hash,
                from.daa_score.map_or("unknown".to_string(), |d| d.to_string())
            ));
        }
    }
    for sheet in &sheets {
        for watching in watcher.add_linked(sheet)? {
            if let Some(from) = watching.from {
                notes.push(format!(
                    "trade {} is watched from chain block {} (DAA {}) only: nothing accepted before it is reported",
                    watching.trade,
                    from.block_hash,
                    from.daa_score.map_or("unknown".to_string(), |d| d.to_string())
                ));
            }
        }
    }
    for trade in &args.retire {
        watcher.retire_trade(*trade)?;
        notes.push(format!("retired trade {trade}"));
    }
    for tx in signed {
        // The same command line restarts the watcher: a transaction already kept is not an error.
        if watcher.is_kept(&hashing::tx::id(&tx)) {
            continue;
        }
        watcher.keep_signed(tx)?;
    }
    let missing = watcher.unresumed_trades();
    if !missing.is_empty() {
        return Err(WatchError::TradeNotResumed(missing));
    }
    Ok(Prepared {
        watcher,
        network,
        state_path: args.state.clone(),
        _lock: lock,
        saved,
        notes,
        max_failed_polls: args.max_failed_polls,
        log_format: args.log_format,
        failed_in_a_row: 0,
    })
}

/// The state file's place, checked before the lock file is made next to it: it must exist
/// without `--init` (`WATCH_STATE_MISSING`, a missing directory included) and not with it
/// (`WATCH_STATE_EXISTS`), and a new one needs its directory (`WATCH_STATE_WRITE_FAILED`).
fn check_state_location(path: &std::path::Path, init: bool) -> Result<(), WatchError> {
    match (init, path.exists()) {
        (true, true) => Err(WatchError::StateExists(path.display().to_string())),
        (false, false) => Err(WatchError::StateMissing(path.display().to_string())),
        (true, false) => {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            if dir.is_dir() {
                Ok(())
            } else {
                Err(WatchError::StateWriteFailed {
                    path: dir.display().to_string(),
                    reason: "the directory for the new state file does not exist".into(),
                })
            }
        }
        (false, true) => Ok(()),
    }
}

/// With the state file locked: reads it, or starts a new state. The refusals of
/// [`check_state_location`] again, because the file may have appeared or gone while the lock was
/// waited for: a second `--init` on the same path that started a moment after the first one
/// ended would otherwise find the lock free and overwrite the state the first one wrote.
pub(crate) fn load_state(
    path: &std::path::Path,
    init: bool,
    network: Network,
) -> Result<(WatchState, Option<String>), WatchError> {
    match (init, path.exists()) {
        (true, true) => Err(WatchError::StateExists(path.display().to_string())),
        (true, false) => Ok((WatchState::default(), None)),
        (false, false) => Err(WatchError::StateMissing(path.display().to_string())),
        (false, true) => {
            let text = crate::files::read_text(path)?;
            Ok((persist::decode(&text, network)?, Some(text)))
        }
    }
}

/// One round: a poll, then every due rebroadcast. A failed poll returns its error and changes
/// nothing.
pub async fn round<N: VirtualChainSource + Broadcaster>(
    watcher: &mut Watcher,
    node: &N,
) -> Result<Vec<Event>, WatchError> {
    let mut events = watcher.poll(node).await?;
    while let Some(event) = watcher.rebroadcast_next(node).await {
        events.push(event);
        // Each pending transaction is tried once per poll, so this ends; the bound is a guard.
        if events.len() > 1_000_000 {
            break;
        }
    }
    Ok(events)
}

/// `text` with every control character (an escape, a line feed, a carriage return) written as
/// its escape sequence. Everything the binary writes to stderr passes through this, so text that
/// came from a node, a file or the operating system cannot write control sequences or extra
/// lines to the operator's terminal. Events on stdout are JSON, which escapes them itself.
pub fn escape_control(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// The line the binary prints for a refusal that ends it: `impulse-watch: CODE: detail`, with
/// every control character escaped, whatever the detail carries.
pub fn fatal_line(error: &WatchError) -> String {
    format!("impulse-watch: {}", escape_control(&error.to_string()))
}

/// [`fatal_line`] in the chosen form: in `json`, a [`log_line`] at level `error`.
pub fn fatal_line_in(format: LogFormat, error: &WatchError) -> String {
    match format {
        LogFormat::Text => fatal_line(error),
        LogFormat::Json => error_log_line(format, "error", error),
    }
}

/// One line for stderr. `text`: `impulse-watch: CODE: message`, or `impulse-watch: message`
/// with no code, every control character escaped. `json`: one object with `ts_ms` (the Unix
/// time in milliseconds), `level` (`info`, `warn` or `error`), `code` (a `WATCH_*` or other
/// stable code, or null for a note) and `message`, which JSON escapes itself. Nothing the
/// watcher logs holds key material: it has none. A node URL is shown redacted.
pub fn log_line(format: LogFormat, level: &str, code: Option<&str>, message: &str) -> String {
    match format {
        LogFormat::Text => match code {
            Some(code) => format!("impulse-watch: {code}: {}", escape_control(message)),
            None => format!("impulse-watch: {}", escape_control(message)),
        },
        LogFormat::Json => {
            let ts_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            serde_json::json!({
                "ts_ms": ts_ms,
                "level": level,
                "code": code,
                "message": message,
            })
            .to_string()
        }
    }
}

/// A refusal as a [`log_line`]: its code, and its text without the code in front.
pub fn error_log_line(format: LogFormat, level: &str, error: &WatchError) -> String {
    let code = error.code();
    let text = error.to_string();
    let message = text
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(": "))
        .unwrap_or(&text);
    log_line(format, level, Some(code), message)
}

fn print_events(out: &mut impl Write, round: u64, events: &[Event]) -> std::io::Result<()> {
    for event in events {
        writeln!(out, "{}", event.to_json_in_round(round))?;
    }
    out.flush()
}

impl Prepared {
    /// Replaces the state file with the current state if it differs from what was last saved.
    fn save(&mut self) -> Result<(), WatchError> {
        let text = persist::encode(self.watcher.state(), self.network);
        if self.saved.as_deref() != Some(text.as_str()) {
            persist::write_atomic(&self.state_path, &text)?;
            self.saved = Some(text);
        }
        Ok(())
    }
}

/// Polls until `max_polls`, or for ever. A poll that fails with `WATCH_SOURCE_FAILED` is
/// reported on `err` and the loop goes on after the interval; any other refusal ends the run.
/// A state file that cannot be written (`WATCH_STATE_WRITE_FAILED`) also ends it: the events
/// of that round were printed, and the next start repeats them. So does an output that cannot be
/// written (`WATCH_OUTPUT_FAILED`): the state of that round is not saved, so the next start
/// repeats the round. With `--max-failed-polls K`, the K-th failed poll in a row ends the run
/// with `WATCH_SOURCE_FAILED`, so that a supervisor restarts it or raises an alarm.
pub async fn drive<N: VirtualChainSource + Broadcaster>(
    prepared: &mut Prepared,
    node: &N,
    interval: Duration,
    max_polls: Option<u64>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<Outcome, WatchError> {
    let mut outcome = Outcome {
        polls: 0,
        failed_polls: 0,
    };
    loop {
        outcome.polls += 1;
        match round(&mut prepared.watcher, node).await {
            Ok(events) => {
                prepared.failed_in_a_row = 0;
                let number = prepared.watcher.close_round(&events);
                print_events(out, number, &events)
                    .map_err(|e| WatchError::OutputFailed(e.to_string()))?;
                prepared.save()?;
            }
            Err(e @ WatchError::SourceFailed(_)) => {
                outcome.failed_polls += 1;
                prepared.failed_in_a_row += 1;
                let _ = writeln!(err, "{}", error_log_line(prepared.log_format, "warn", &e));
                if let (Some(k), WatchError::SourceFailed(reason)) = (prepared.max_failed_polls, &e)
                {
                    if prepared.failed_in_a_row >= k {
                        return Err(WatchError::SourceFailed(format!(
                            "{k} polls in a row failed (--max-failed-polls), the last: {reason}"
                        )));
                    }
                }
            }
            Err(e) => return Err(e),
        }
        if max_polls.is_some_and(|k| outcome.polls >= k) {
            return Ok(outcome);
        }
        tokio::time::sleep(interval).await;
    }
}

/// `impulse-watch run`: prepare, connect to the node, drive, disconnect.
pub async fn run(
    args: &RunArgs,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<Outcome, WatchError> {
    let mut prepared = prepare(args)?;
    for note in &prepared.notes {
        let _ = writeln!(err, "{}", log_line(args.log_format, "info", None, note));
    }
    let node = WrpcNode::connect(&args.node, prepared.network).await?;
    let result = drive(
        &mut prepared,
        &node,
        Duration::from_millis(args.poll_interval_ms),
        args.max_polls,
        out,
        err,
    )
    .await;
    node.disconnect().await;
    result
}

/// `impulse-watch probe`: the read-only checks of [`crate::node::probe`], one line each.
pub async fn run_probe(args: &ProbeArgs, out: &mut impl Write) -> Result<(), WatchError> {
    let network: Network = args.network.into();
    let node = WrpcNode::connect(&args.node, network).await?;
    let result = probe(&node, network, args.expect_version.as_deref()).await;
    node.disconnect().await;
    for line in result?.lines {
        let _ = writeln!(out, "{line}");
    }
    Ok(())
}
