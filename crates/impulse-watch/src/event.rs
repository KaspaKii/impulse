// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Watcher events, one JSON object each (schema and codes: spec/WATCH.md). Every event about a
//! vault names one trade and one leg; there is no trade-level settled or refunded event, because
//! one settle transaction can settle legs of two different trades. As in the JSON form of terms
//! (spec/ENCODING.md), u64 values are decimal strings, since JSON numbers above 2^53 lose
//! precision in JavaScript; u32 values are numbers.

use crate::linked::{Link, LinkView};
use crate::tracker::AcceptanceInfo;
use crate::trades::{Effect, Leg};
use kaspa_consensus_core::tx::TransactionId;
use serde_json::{json, Map, Value};

/// Something the watcher saw. Depths are DAA-score depths below the last chain block of the
/// poll's walk (the node's sink once the walk has caught up).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A transaction with this effect was accepted into the selected chain.
    Accepted {
        txid: TransactionId,
        effect: Effect,
        at: AcceptanceInfo,
        depth: u64,
    },
    /// The acceptance reached the finality depth N. Once per acceptance.
    Final {
        txid: TransactionId,
        effect: Effect,
        at: AcceptanceInfo,
        depth: u64,
    },
    /// A reorg removed the chain block that accepted the transaction; the effect is undone
    /// until the transaction is accepted again. `was_final` is whether that acceptance had
    /// already been reported final (`WATCH_FINAL_REORGED`): a reorg deeper than N, the one N is
    /// chosen to make unlikely.
    Reorg {
        txid: TransactionId,
        effect: Effect,
        at: AcceptanceInfo,
        was_final: bool,
    },
    /// A kept transaction that a reorg removed: the outcome of one attempt to submit the copy
    /// the node had accepted, or why it was not submitted.
    Rebroadcast {
        txid: TransactionId,
        outcome: RebroadcastOutcome,
    },
    /// A linked trade (spec/V2.md 17.9) moved to a new phase. `txid` is the transaction of the
    /// last event of the poll that touched either trade of the link. Reported after the events
    /// of the poll that caused it; carries `WATCH_LINK_RETURN_EARLY` when `view.early`.
    Linked {
        txid: TransactionId,
        link: Link,
        view: LinkView,
    },
}

/// The outcome of one rebroadcast attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebroadcastOutcome {
    /// The node took the transaction. Ends the rebroadcast after this reorg.
    Submitted { attempt: u32 },
    /// The node refused it (`WATCH_REBROADCAST_FAILED`); it is tried again after the next
    /// poll.
    Refused { attempt: u32, reason: String },
    /// The last allowed attempt was refused (`WATCH_REBROADCAST_ABANDONED`); it is not tried
    /// again.
    Abandoned { attempt: u32, reason: String },
    /// Not submitted: the tip is at or past the expiry of a trade the transaction settles
    /// (`WATCH_REBROADCAST_PAST_EXPIRY`). The decision is the operator's.
    PastExpiry { expiry_daa: u64, tip_daa: u64 },
}

impl RebroadcastOutcome {
    /// The JSON `outcome` value.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Submitted { .. } => "submitted",
            Self::Refused { .. } => "refused",
            Self::Abandoned { .. } => "abandoned",
            Self::PastExpiry { .. } => "skipped_past_expiry",
        }
    }

    /// The flag this outcome carries, if any.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Submitted { .. } => None,
            Self::Refused { .. } => Some("WATCH_REBROADCAST_FAILED"),
            Self::Abandoned { .. } => Some("WATCH_REBROADCAST_ABANDONED"),
            Self::PastExpiry { .. } => Some("WATCH_REBROADCAST_PAST_EXPIRY"),
        }
    }
}

impl Event {
    pub fn txid(&self) -> TransactionId {
        match self {
            Self::Accepted { txid, .. }
            | Self::Final { txid, .. }
            | Self::Reorg { txid, .. }
            | Self::Rebroadcast { txid, .. }
            | Self::Linked { txid, .. } => *txid,
        }
    }

    pub fn effect(&self) -> Option<&Effect> {
        match self {
            Self::Accepted { effect, .. }
            | Self::Final { effect, .. }
            | Self::Reorg { effect, .. } => Some(effect),
            Self::Rebroadcast { .. } | Self::Linked { .. } => None,
        }
    }

    /// The flag this event carries, if any.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Rebroadcast { outcome, .. } => outcome.code(),
            Self::Linked { view, .. } => view.early.then_some("WATCH_LINK_RETURN_EARLY"),
            Self::Reorg {
                was_final: true, ..
            } => Some("WATCH_FINAL_REORGED"),
            _ => self.effect().and_then(Effect::code),
        }
    }

    /// The event as one JSON object, with the number of the round that reported it
    /// ([`crate::watcher::Watcher::close_round`]): as the binary prints it. A u64, so a decimal
    /// string.
    pub fn to_json_in_round(&self, round: u64) -> Value {
        let mut json = self.to_json();
        if let Value::Object(m) = &mut json {
            m.insert("round".into(), json!(round.to_string()));
        }
        json
    }

    /// The event as one JSON object, without its round number.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::Accepted {
                effect, at, depth, ..
            } => {
                m.insert("event".into(), json!(effect.name()));
                effect_fields(effect, &mut m);
                acceptance_fields(at, &mut m);
                m.insert("depth".into(), json!(depth.to_string()));
            }
            Self::Final {
                effect, at, depth, ..
            } => {
                m.insert("event".into(), json!("final"));
                m.insert("of".into(), json!(effect.name()));
                effect_fields(effect, &mut m);
                acceptance_fields(at, &mut m);
                m.insert("depth".into(), json!(depth.to_string()));
            }
            Self::Reorg {
                effect,
                at,
                was_final,
                ..
            } => {
                m.insert("event".into(), json!("reorg"));
                m.insert("of".into(), json!(effect.name()));
                effect_fields(effect, &mut m);
                acceptance_fields(at, &mut m);
                m.insert("was_final".into(), json!(was_final));
            }
            Self::Linked { link, view, .. } => {
                m.insert("event".into(), json!("linked"));
                m.insert("linked".into(), json!(crate::files::hex(&link.linked_hash)));
                m.insert("opening".into(), json!(link.opening.to_string()));
                m.insert("return".into(), json!(link.ret.to_string()));
                m.insert("phase".into(), json!(view.phase.name()));
            }
            Self::Rebroadcast { outcome, .. } => {
                m.insert("event".into(), json!("rebroadcast"));
                m.insert("outcome".into(), json!(outcome.name()));
                match outcome {
                    RebroadcastOutcome::Submitted { attempt } => {
                        m.insert("attempt".into(), json!(attempt));
                    }
                    RebroadcastOutcome::Refused { attempt, reason }
                    | RebroadcastOutcome::Abandoned { attempt, reason } => {
                        m.insert("attempt".into(), json!(attempt));
                        m.insert("reason".into(), json!(reason));
                    }
                    RebroadcastOutcome::PastExpiry {
                        expiry_daa,
                        tip_daa,
                    } => {
                        m.insert("expiry_daa".into(), json!(expiry_daa.to_string()));
                        m.insert("tip_daa".into(), json!(tip_daa.to_string()));
                    }
                }
            }
        }
        m.insert("txid".into(), json!(self.txid().to_string()));
        if let Some(code) = self.code() {
            m.insert("code".into(), json!(code));
        }
        Value::Object(m)
    }
}

/// `asset` or `cash` for a v1 leg; the leg's index, a number, for a v2 leg (spec/V2.md 6.5).
pub(crate) fn leg_json(leg: Leg) -> Value {
    match leg {
        Leg::Asset => json!("asset"),
        Leg::Cash => json!("cash"),
        Leg::V2(i) => json!(i),
    }
}

fn effect_fields(effect: &Effect, m: &mut Map<String, Value>) {
    m.insert("trade".into(), json!(effect.trade().to_string()));
    if let Some(leg) = effect.leg() {
        m.insert("leg".into(), leg_json(leg));
    }
    match *effect {
        Effect::Funded {
            index,
            value,
            exact,
            ..
        } => {
            m.insert("output".into(), json!(index));
            m.insert("value".into(), json!(value.to_string()));
            m.insert("exact".into(), json!(exact));
        }
        Effect::AuthorizerSeen {
            index,
            value,
            covenant_output,
            ..
        } => {
            m.insert("output".into(), json!(index));
            m.insert("value".into(), json!(value.to_string()));
            m.insert("escrow".into(), json!("not_verified"));
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
            m.insert("spent_txid".into(), json!(spent.transaction_id.to_string()));
            m.insert("spent_index".into(), json!(spent.index));
            m.insert("spent_value".into(), json!(spent_value.to_string()));
        }
        Effect::StrayDeposit { index, value, .. } => {
            m.insert("output".into(), json!(index));
            m.insert("value".into(), json!(value.to_string()));
        }
        Effect::ForeignToken {
            input, covenant_id, ..
        } => {
            // The index of the token's input, not of a vault input.
            m.insert(String::from("input"), json!(input));
            m.insert("covenant_id".into(), json!(covenant_id.to_string()));
        }
    }
}

fn acceptance_fields(at: &AcceptanceInfo, m: &mut Map<String, Value>) {
    m.insert(
        "accepting_block".into(),
        json!(at.accepting_block_hash.to_string()),
    );
    m.insert(
        "accepting_daa".into(),
        json!(at.accepting_daa_score.to_string()),
    );
}
