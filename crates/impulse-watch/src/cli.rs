// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The `impulse-watch` command line (spec/WATCH.md, "The binary"). No flag has a default that
//! chooses a network, a node, a finality depth or a state file: the user names each. A flag that
//! is missing is a usage error (exit 2) and nothing is read, contacted or written.

use crate::trades::TradeId;
use clap::{Args, Parser, Subcommand, ValueEnum};
use impulse_core::terms::Network;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "impulse-watch",
    version,
    about = "Watches Impulse trades on a Kaspa node and reports per-leg JSON events. Holds no key and signs nothing."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Follow the trades and print one JSON event per line on stdout.
    Run(RunArgs),
    /// Check, with read-only calls, what the watcher relies on in a node's answers.
    Probe(ProbeArgs),
}

/// The form of the lines on stderr. `text` is `impulse-watch: CODE: detail` (or
/// `impulse-watch: note` for a note); `json` is one object per line with `ts_ms`, `level`,
/// `code` and `message`. Events on stdout are JSON either way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// The network a command acts on. There is no default: mainnet is never implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
}

impl From<NetworkArg> for Network {
    fn from(n: NetworkArg) -> Self {
        match n {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
        }
    }
}

fn trade_id(s: &str) -> Result<TradeId, String> {
    crate::files::unhex32(s)
        .map(TradeId)
        .ok_or_else(|| "expected a terms hash: 64 lowercase hex digits".to_string())
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    /// The network watched; the node and every terms file must be on it.
    #[arg(long, value_enum)]
    pub network: NetworkArg,
    /// The node's wRPC (Borsh) URL, ws:// or wss://. On mainnet: wss://, or ws:// to this machine.
    #[arg(long)]
    pub node: String,
    /// Finality depth N in DAA scores. No default: it is a security choice.
    #[arg(long, value_name = "N")]
    pub finality_depth: u64,
    /// The local JSON state file. Replaced atomically after each round.
    #[arg(long, value_name = "FILE")]
    pub state: PathBuf,
    /// Start a new state file. Without it the file must exist; with it the file must not.
    #[arg(long)]
    pub init: bool,
    /// A terms file to watch (repeat for several trades).
    #[arg(long = "trade", value_name = "TERMS_FILE")]
    pub trades: Vec<PathBuf>,
    /// A sheet file of `impulse linked new` (repeat for several): both of its trades are watched
    /// as ordinary trades, and one `linked` event is reported when the pair's phase changes.
    #[arg(long = "linked", value_name = "SHEET")]
    pub linked: Vec<PathBuf>,
    /// A signed transaction (raw form, hex) to resubmit if a reorg removes it (repeat). The only
    /// transactions the watcher ever submits.
    #[arg(long = "keep-signed", value_name = "TX_FILE")]
    pub keep_signed: Vec<PathBuf>,
    /// Stop watching a trade of the state, by terms hash (repeat).
    #[arg(long = "retire", value_name = "TERMS_HASH", value_parser = trade_id)]
    pub retire: Vec<TradeId>,
    /// Evict final acceptances this many DAA scores deep (must be above the finality depth).
    /// Without it nothing is evicted.
    #[arg(long, value_name = "DAA")]
    pub retention_daa: Option<u64>,
    /// Milliseconds between polls.
    #[arg(long, value_name = "MS", default_value_t = 1000)]
    pub poll_interval_ms: u64,
    /// Stop after this many polls (exit 1 if one failed). Without it, run until killed.
    #[arg(long, value_name = "K", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_polls: Option<u64>,
    /// End the run (exit 1) after this many polls in a row failed, so that a supervisor sees a
    /// watcher that has lost its node. Without it a failed poll is reported and the run goes on.
    #[arg(long, value_name = "K", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_failed_polls: Option<u64>,
    /// The form of the lines on stderr.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

#[derive(Args, Debug)]
pub struct ProbeArgs {
    /// The network the node must be on.
    #[arg(long, value_enum)]
    pub network: NetworkArg,
    /// The node's wRPC (Borsh) URL, ws:// or wss://. On mainnet: wss://, or ws:// to this machine.
    #[arg(long)]
    pub node: String,
    /// Fail unless the node reports exactly this server version.
    #[arg(long, value_name = "VERSION")]
    pub expect_version: Option<String>,
    /// The form of the lines on stderr.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}
