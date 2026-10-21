// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Linked trades (spec/V2.md 17.9, spec/WATCH.md "Linked trades"): the two trades a sheet
//! derives are watched as ordinary trades, and this book follows them as one. After each poll the
//! phase of every link is read off the acceptances the watcher currently holds, so a reorg that
//! removes the opening's settle moves the phase back, and one `linked` event is reported for each
//! change. A return funded while the opening is not settled carries the flag
//! `WATCH_LINK_RETURN_EARLY`. Nothing here is saved: on a restart the phase is read again from
//! the loaded acceptances, and an event is reported only for a change after that.
//!
//! An acceptance that reached the finality depth is remembered by the book even after the
//! watcher evicts it (`--retention-daa`), so eviction never moves a phase back. A reorg of an
//! acceptance already reported final (`WATCH_FINAL_REORGED`) therefore does not move it back
//! either; that event is the report of such a reorg.

use crate::trades::{Effect, Leg, TradeId};
use crate::watcher::Accepted;
use kaspa_consensus_core::tx::TransactionId;
use std::collections::{BTreeSet, HashMap};

/// Where a link stands, from the acceptances currently held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The opening is not settled and none of its vaults was refunded.
    OpeningOpen,
    /// Both opening vaults settled; the return has not settled or refunded.
    OpeningSettled,
    /// A vault of the opening was refunded and the opening did not settle.
    OpeningRefunded,
    /// Both return vaults settled.
    ReturnSettled,
    /// A vault of the return was refunded and the return did not settle.
    ReturnRefunded,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::OpeningOpen => "opening_open",
            Self::OpeningSettled => "opening_settled",
            Self::OpeningRefunded => "opening_refunded",
            Self::ReturnSettled => "return_settled",
            Self::ReturnRefunded => "return_refunded",
        }
    }
}

/// The phase of a link and whether the return started before the opening settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkView {
    pub phase: Phase,
    /// `WATCH_LINK_RETURN_EARLY`: a return vault was funded (or settled) while the opening is
    /// not settled.
    pub early: bool,
}

/// One watched link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub linked_hash: [u8; 32],
    pub opening: TradeId,
    pub ret: TradeId,
}

/// What one trade of a link has done, from the held acceptances.
#[derive(Clone, Default)]
struct Side {
    settled: BTreeSet<u8>,
    refunded: BTreeSet<u8>,
    started: BTreeSet<u8>,
}

impl Side {
    fn settled(&self) -> bool {
        self.settled.len() == 2
    }

    fn refunded(&self) -> bool {
        !self.settled() && !self.refunded.is_empty()
    }

    fn started(&self) -> bool {
        !self.started.is_empty() || !self.settled.is_empty()
    }
}

impl Side {
    /// Adds what `a`'s effects did to `trade`.
    fn add(&mut self, a: &Accepted, trade: TradeId) {
        for effect in &a.effects {
            if effect.trade() != trade {
                continue;
            }
            let Some(Leg::V2(i)) = effect.leg() else {
                continue;
            };
            match effect {
                Effect::Settled { .. } => {
                    self.settled.insert(i);
                }
                Effect::Refunded { .. } => {
                    self.refunded.insert(i);
                }
                Effect::Funded { exact: true, .. } | Effect::AuthorizerSeen { .. } => {
                    self.started.insert(i);
                }
                _ => {}
            }
        }
    }
}

/// What the held acceptances (and the final ones remembered) did to `trade`.
fn side(
    accepted: &HashMap<TransactionId, Accepted>,
    remembered: &HashMap<TradeId, Side>,
    trade: TradeId,
) -> Side {
    let mut side = remembered.get(&trade).cloned().unwrap_or_default();
    for a in accepted.values() {
        side.add(a, trade);
    }
    side
}

impl Link {
    /// The link's phase from the acceptances held now.
    fn view(
        &self,
        accepted: &HashMap<TransactionId, Accepted>,
        remembered: &HashMap<TradeId, Side>,
    ) -> LinkView {
        let (opening, ret) = (
            side(accepted, remembered, self.opening),
            side(accepted, remembered, self.ret),
        );
        let phase = if ret.settled() {
            Phase::ReturnSettled
        } else if ret.refunded() {
            Phase::ReturnRefunded
        } else if opening.settled() {
            Phase::OpeningSettled
        } else if opening.refunded() {
            Phase::OpeningRefunded
        } else {
            Phase::OpeningOpen
        };
        LinkView {
            phase,
            early: ret.started() && !opening.settled(),
        }
    }
}

/// The links a watcher follows, each with the view last reported (or read when it was added).
#[derive(Default)]
pub(crate) struct LinkBook {
    links: Vec<(Link, LinkView)>,
    /// What final acceptances did to the trades of the links, kept past their eviction.
    remembered: HashMap<TradeId, Side>,
}

impl LinkBook {
    pub(crate) fn contains(&self, linked_hash: &[u8; 32]) -> bool {
        self.links
            .iter()
            .any(|(l, _)| &l.linked_hash == linked_hash)
    }

    /// Adds a link with its current view as the baseline: nothing is reported for it until it
    /// changes.
    pub(crate) fn add(&mut self, link: Link, accepted: &HashMap<TransactionId, Accepted>) {
        let view = link.view(accepted, &self.remembered);
        self.links.push((link, view));
    }

    /// Links whose view changed, with the new view; the baseline moves to it.
    pub(crate) fn changed(
        &mut self,
        accepted: &HashMap<TransactionId, Accepted>,
    ) -> Vec<(Link, LinkView)> {
        for (link, _) in &self.links {
            for trade in [link.opening, link.ret] {
                let entry = self.remembered.entry(trade).or_default();
                for a in accepted.values().filter(|a| a.finalized) {
                    entry.add(a, trade);
                }
            }
        }
        let mut out = Vec::new();
        for (link, last) in &mut self.links {
            let now = link.view(accepted, &self.remembered);
            if now != *last {
                *last = now;
                out.push((*link, now));
            }
        }
        out
    }
}
