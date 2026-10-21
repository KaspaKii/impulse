// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-watch: a single-node watcher for Impulse trades. It derives each trade's vaults from
//! its terms through impulse-core, follows the node's virtual selected parent chain, and reports
//! per-leg JSON events: funded (KAS legs), authorizer_seen (KCC-20 legs, escrow not verified),
//! settled, refunded, stray deposits to the cash-vault script of external-cash terms (decision
//! D14), reorgs, rebroadcasts and finality at depth N.
//!
//! Keyless by rule: it holds no key and signs nothing. When a reorg un-accepts a transaction the
//! operator marked for rebroadcast, it submits again the copy the node had accepted. State is in
//! memory, and the binary keeps it in one local JSON file (`persist`); no database.
//!
//! Events, attribution, rebroadcast policy and codes: spec/WATCH.md.
//!
//! I8 phase 1: the library, driven by a fake source in tests. Phase 2: the wRPC node (`node`),
//! the binary (`cli`, `run`, `files`) and the local state file (`persist`).

pub mod cli;
pub mod entry;
pub mod error;
pub mod event;
pub mod files;
pub mod linked;
pub mod node;
pub mod persist;
pub mod run;
pub mod tracker;
pub mod trades;
pub mod watcher;

#[cfg(test)]
mod tests;

pub use error::{WatchError, WATCH_ERROR_CODES, WATCH_EVENT_CODES};
pub use event::{Event, RebroadcastOutcome};
pub use tracker::FinalityPolicy;
pub use trades::{Effect, TradeId};
pub use watcher::{
    Broadcaster, Refusal, Retention, WatchState, Watcher, Watching, REBROADCAST_ATTEMPTS,
};
