// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Watcher refusals and event flags, each with a stable code. A template or terms refusal met on
//! the way keeps its own `TEMPLATE_*` or `TERMS_*` code. Integrators match on `code()`, never on
//! the Display text.

use crate::trades::TradeId;
use impulse_core::template::TemplateError;
use impulse_core::terms::Network;
use kaspa_consensus_core::tx::TransactionId;
use std::fmt;

/// Why the watcher refused a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchError {
    /// The terms name another network than the one the watcher watches.
    NetworkMismatch { watcher: Network, terms: Network },
    /// These terms are already watched.
    TradeDuplicate(TradeId),
    /// A finality depth of 0.
    FinalityDepthZero,
    /// The cash-vault script of external-cash terms could not be derived and checked.
    StrayScriptUnderivable,
    /// A transaction offered for rebroadcast has an input with no signature script.
    TxUnsigned { input: usize },
    /// A transaction offered for rebroadcast settles or refunds no watched vault.
    TxNotTracked,
    /// A transaction with this id is already kept for rebroadcast.
    TxDuplicate(TransactionId),
    /// A node call failed; nothing was applied.
    SourceFailed(String),
    /// A poll while these trades of a resumed state have not been added again.
    TradeNotResumed(Vec<TradeId>),
    /// Phase 2. Retiring a trade the state does not hold.
    TradeUnknown(TradeId),
    /// A retention window that is not above the finality depth.
    RetentionTooShort { retain_daa: u64, finality_daa: u64 },
    /// The node URL is not `ws://` or `wss://`.
    NodeUrlInvalid(String),
    /// On mainnet, the node URL is neither `wss://` nor `ws://` to a loopback host.
    NodeInsecure(String),
    /// The connection to the node failed.
    NodeUnreachable(String),
    /// The node is on another network than the one watched.
    NodeNetworkMismatch {
        node: String,
        watching: &'static str,
    },
    /// The node is not synced.
    NodeNotSynced,
    /// A call made while starting (not a poll) failed, or returned something malformed.
    NodeRpc(String),
    /// A file cannot be read.
    FileRead { path: String, reason: String },
    /// A terms file is not a terms file.
    TermsFileInvalid { path: String, reason: String },
    /// A terms file's canonical bytes and terms hash disagree.
    TermsFileInconsistent { path: String },
    /// A signed transaction file is not the raw form of a transaction.
    SignedTxInvalid { path: String, reason: String },
    /// A state file is not in the accepted form, or is inconsistent.
    StateInvalid(String),
    /// A state file belongs to another network.
    StateMismatch {
        state: String,
        watching: &'static str,
    },
    /// The state file could not be written; a state file already there is untouched.
    StateWriteFailed { path: String, reason: String },
    /// Another watcher holds the state file.
    StateLocked(String),
    /// A trade is both retired and watched in one run.
    RetireWatched(TradeId),
    /// A check of `impulse-watch probe` failed.
    ProbeFailed(String),
    /// The state file does not exist and `--init` was not given.
    StateMissing(String),
    /// `--init` was given and the state file exists.
    StateExists(String),
    /// The events of a round could not be written to the output.
    OutputFailed(String),
    /// Instantiating a vault was refused; the code is the template or terms code.
    Template(TemplateError),
    /// A template v2 or terms v2 refusal met while adding a v2 trade; keeps its own code.
    V2(impulse_core::v2::V2Error),
}

/// Every watcher refusal code, in declaration order. Frozen once merged: a test pins this list,
/// and it may only grow at the end. Template and terms refusals keep their own codes.
pub const WATCH_ERROR_CODES: [&str; 30] = [
    "WATCH_NETWORK_MISMATCH",
    "WATCH_TRADE_DUPLICATE",
    "WATCH_FINALITY_DEPTH_ZERO",
    "WATCH_STRAY_SCRIPT_UNDERIVABLE",
    "WATCH_TX_UNSIGNED",
    "WATCH_TX_NOT_TRACKED",
    "WATCH_TX_DUPLICATE",
    "WATCH_SOURCE_FAILED",
    "WATCH_TRADE_NOT_RESUMED",
    "WATCH_TRADE_UNKNOWN",
    "WATCH_RETENTION_TOO_SHORT",
    "WATCH_NODE_URL_INVALID",
    "WATCH_NODE_INSECURE",
    "WATCH_NODE_UNREACHABLE",
    "WATCH_NODE_NETWORK_MISMATCH",
    "WATCH_NODE_NOT_SYNCED",
    "WATCH_NODE_RPC",
    "WATCH_FILE_READ",
    "WATCH_TERMS_FILE_INVALID",
    "WATCH_TERMS_FILE_INCONSISTENT",
    "WATCH_SIGNED_TX_INVALID",
    "WATCH_STATE_INVALID",
    "WATCH_STATE_MISMATCH",
    "WATCH_STATE_WRITE_FAILED",
    "WATCH_STATE_LOCKED",
    "WATCH_RETIRE_WATCHED",
    "WATCH_PROBE_FAILED",
    "WATCH_STATE_MISSING",
    "WATCH_STATE_EXISTS",
    "WATCH_OUTPUT_FAILED",
];

/// Every code an event can carry as a flag, frozen the same way. A flagged event reports
/// something the operator must look at; it is never reported as a plain funding or spend.
pub const WATCH_EVENT_CODES: [&str; 9] = [
    "WATCH_STRAY_DEPOSIT",
    "WATCH_FUNDING_NOT_EXACT",
    "WATCH_SPEND_UNCLASSIFIED",
    "WATCH_REBROADCAST_FAILED",
    "WATCH_REBROADCAST_ABANDONED",
    "WATCH_REBROADCAST_PAST_EXPIRY",
    "WATCH_FINAL_REORGED",
    "WATCH_LINK_RETURN_EARLY",
    "WATCH_FOREIGN_TOKEN",
];

impl WatchError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NetworkMismatch { .. } => "WATCH_NETWORK_MISMATCH",
            Self::TradeDuplicate(_) => "WATCH_TRADE_DUPLICATE",
            Self::FinalityDepthZero => "WATCH_FINALITY_DEPTH_ZERO",
            Self::StrayScriptUnderivable => "WATCH_STRAY_SCRIPT_UNDERIVABLE",
            Self::TxUnsigned { .. } => "WATCH_TX_UNSIGNED",
            Self::TxNotTracked => "WATCH_TX_NOT_TRACKED",
            Self::TxDuplicate(_) => "WATCH_TX_DUPLICATE",
            Self::SourceFailed(_) => "WATCH_SOURCE_FAILED",
            Self::TradeNotResumed(_) => "WATCH_TRADE_NOT_RESUMED",
            Self::TradeUnknown(_) => "WATCH_TRADE_UNKNOWN",
            Self::RetentionTooShort { .. } => "WATCH_RETENTION_TOO_SHORT",
            Self::NodeUrlInvalid(_) => "WATCH_NODE_URL_INVALID",
            Self::NodeInsecure(_) => "WATCH_NODE_INSECURE",
            Self::NodeUnreachable(_) => "WATCH_NODE_UNREACHABLE",
            Self::NodeNetworkMismatch { .. } => "WATCH_NODE_NETWORK_MISMATCH",
            Self::NodeNotSynced => "WATCH_NODE_NOT_SYNCED",
            Self::NodeRpc(_) => "WATCH_NODE_RPC",
            Self::FileRead { .. } => "WATCH_FILE_READ",
            Self::TermsFileInvalid { .. } => "WATCH_TERMS_FILE_INVALID",
            Self::TermsFileInconsistent { .. } => "WATCH_TERMS_FILE_INCONSISTENT",
            Self::SignedTxInvalid { .. } => "WATCH_SIGNED_TX_INVALID",
            Self::StateInvalid(_) => "WATCH_STATE_INVALID",
            Self::StateMismatch { .. } => "WATCH_STATE_MISMATCH",
            Self::StateWriteFailed { .. } => "WATCH_STATE_WRITE_FAILED",
            Self::StateLocked(_) => "WATCH_STATE_LOCKED",
            Self::RetireWatched(_) => "WATCH_RETIRE_WATCHED",
            Self::ProbeFailed(_) => "WATCH_PROBE_FAILED",
            Self::StateMissing(_) => "WATCH_STATE_MISSING",
            Self::StateExists(_) => "WATCH_STATE_EXISTS",
            Self::OutputFailed(_) => "WATCH_OUTPUT_FAILED",
            Self::Template(e) => e.code(),
            Self::V2(e) => e.code(),
        }
    }
}

impl From<impulse_core::v2::V2Error> for WatchError {
    fn from(e: impulse_core::v2::V2Error) -> Self {
        Self::V2(e)
    }
}

impl From<TemplateError> for WatchError {
    fn from(e: TemplateError) -> Self {
        Self::Template(e)
    }
}

impl fmt::Display for WatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::NetworkMismatch { watcher, terms } => write!(
                f,
                "{code}: the terms name {terms:?}, the watcher watches {watcher:?}"
            ),
            Self::TradeDuplicate(id) => write!(f, "{code}: trade {id} is already watched"),
            Self::FinalityDepthZero => write!(f, "{code}: the finality depth must be at least 1"),
            Self::StrayScriptUnderivable => write!(
                f,
                "{code}: the cash-vault script of these external-cash terms could not be derived"
            ),
            Self::TxUnsigned { input } => {
                write!(f, "{code}: input {input} has no signature script")
            }
            Self::TxNotTracked => write!(
                f,
                "{code}: the transaction settles or refunds no watched vault"
            ),
            Self::TxDuplicate(txid) => {
                write!(f, "{code}: transaction {txid} is already kept")
            }
            Self::SourceFailed(reason) => write!(f, "{code}: node call failed: {reason}"),
            Self::TradeNotResumed(trades) => {
                write!(f, "{code}: trades of the resumed state not added again:")?;
                trades.iter().try_for_each(|t| write!(f, " {t}"))
            }
            Self::TradeUnknown(trade) => write!(f, "{code}: trade {trade} is not in the state"),
            Self::RetentionTooShort {
                retain_daa,
                finality_daa,
            } => write!(
                f,
                "{code}: the retention window {retain_daa} must be above the finality depth {finality_daa}"
            ),
            // Text from a node, a file or the operating system is echoed escaped (Debug), so it
            // cannot write control sequences or extra lines to the operator's terminal.
            Self::NodeUrlInvalid(url) => {
                write!(f, "{code}: {url:?} is not a ws:// or wss:// wRPC URL")
            }
            Self::NodeInsecure(url) => write!(
                f,
                "{code}: {url:?}: on mainnet the node link must be wss://, or ws:// to 127.0.0.1, [::1] or localhost (an SSH tunnel reaches a remote node)"
            ),
            Self::NodeUnreachable(reason) => write!(f, "{code}: {reason}"),
            Self::NodeNetworkMismatch { node, watching } => {
                write!(f, "{code}: the node is on {node:?}, the watcher watches {watching}")
            }
            Self::NodeNotSynced => write!(f, "{code}: the node is not synced"),
            Self::NodeRpc(reason) => write!(f, "{code}: {reason}"),
            Self::FileRead { path, reason } => write!(f, "{code}: {path:?}: {reason:?}"),
            Self::TermsFileInvalid { path, reason } => {
                write!(f, "{code}: {path:?} is not a terms file: {reason}")
            }
            Self::TermsFileInconsistent { path } => write!(
                f,
                "{code}: {path:?}: the canonical bytes and the terms hash disagree"
            ),
            Self::SignedTxInvalid { path, reason } => write!(
                f,
                "{code}: {path:?} is not the raw form of a transaction: {reason}"
            ),
            Self::StateInvalid(reason) => write!(f, "{code}: {reason}"),
            Self::StateMismatch { state, watching } => write!(
                f,
                "{code}: the state file is for {state:?}, the watcher watches {watching}"
            ),
            Self::StateWriteFailed { path, reason } => {
                write!(f, "{code}: {path:?}: {reason:?}; a state file already there is untouched")
            }
            Self::StateLocked(path) => {
                write!(f, "{code}: another watcher holds the state file {path:?}")
            }
            Self::RetireWatched(trade) => write!(
                f,
                "{code}: trade {trade} is retired and watched in the same run"
            ),
            Self::ProbeFailed(reason) => write!(f, "{code}: {reason}"),
            Self::StateMissing(path) => write!(
                f,
                "{code}: the state file {path:?} does not exist; pass --init to start a new one"
            ),
            Self::StateExists(path) => write!(
                f,
                "{code}: --init was given and the state file {path:?} exists; it is never overwritten"
            ),
            Self::OutputFailed(reason) => write!(
                f,
                "{code}: {reason:?}; the round's state was not saved, so the next start repeats its events"
            ),
            Self::Template(e) => e.fmt(f),
            Self::V2(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for WatchError {}
