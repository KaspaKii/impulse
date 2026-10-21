#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for crates/impulse-watch (I8, review rounds 1 to 5; template v2 trades, I16: V01 to V08).

Each mutant below is one hand-written fault in the watcher's source: a check removed or
weakened, an order reversed, a field dropped from the JSON. For each one, this script writes
the mutant into a scratch copy of the repository (the working tree is never touched), runs
`cargo test -p impulse-watch --lib` there (and `--test e2e` for a mutant in node.rs), and
records which tests fail. A mutant no test
catches is a survivor. Every pattern must occur exactly once in its file, so a mutant can never
silently stop applying.

    python3 scripts/watch-mutation.py            run and print
    python3 scripts/watch-mutation.py --record   also write crates/impulse-watch/mutation-run.txt
    python3 scripts/watch-mutation.py --check    check the record against the current source and
                                                 this script (scripts/ci-local.sh runs this)
    python3 scripts/watch-mutation.py --jobs=N   run N mutants at a time, each in its own copy of
                                                 the repository and of the cargo target directory
    python3 scripts/watch-mutation.py --only=T1,W5   run only these mutants (never recorded)

The record names the sha256 of the watcher's source files (src/, tests/e2e.rs and the golden
state file) and of this script; --check fails unless both match and every mutant was caught.
Any change to those files needs a new run with --record.
"""

import concurrent.futures
import hashlib
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRATE = os.path.join("crates", "impulse-watch")
SRC = os.path.join(CRATE, "src")
RECORD = os.path.join(ROOT, CRATE, "mutation-run.txt")
TARGET_DIR = os.path.join(ROOT, "target", "watch-mutation")
# A mutant in one of these files is also run against the end-to-end target (tests/e2e.rs), which
# is what exercises the wRPC client glue; the others run the library tests only.
E2E_FILES = {"node.rs"}
# Skipped in every run: the randomised restart check takes minutes under load and is a net, not
# the test that any mutant is credited to; the deterministic tests beside it name each fault.
SKIPPED = ["random_operations_leave_a_state_that_restarts_and_resumes_the_same"]
# Seconds one mutant's test run may take before it counts as a hang (and fails the run).
TEST_TIMEOUT = 1800

# (id, file in src/, what the fault does, pattern, replacement[, how many times the pattern
# occurs, all of which are replaced; default 1])
MUTANTS = [
    # Attribution and classification (trades.rs, entry.rs).
    ("T1", "trades.rs", "an over-funded KAS UTXO counts as exact",
     "exact: value == amount,", "exact: value >= amount,"),
    ("T2", "trades.rs", "an under-funded KAS UTXO counts as exact",
     "exact: value == amount,", "exact: value <= amount,"),
    ("T3", "trades.rs", "settle accepted at any input at or below the leg index",
     "Some(Entry::Settle) if input == leg.index() as u32 && exact",
     "Some(Entry::Settle) if input <= leg.index() as u32 && exact"),
    ("T4", "trades.rs", "settle accepted at any input at or above the leg index",
     "Some(Entry::Settle) if input == leg.index() as u32 && exact",
     "Some(Entry::Settle) if input >= leg.index() as u32 && exact"),
    ("T5", "trades.rs", "refund accepted at input 1",
     "Some(Entry::Refund) if input == 0 =>", "Some(Entry::Refund) if input < 2 =>"),
    ("T6", "trades.rs", "a KAS leg settled from an inexact UTXO is a settle ([S2] check dropped)",
     "let exact = v.kas_amount.is_none_or(|amount| amount == spent_value);", "let exact = true;"),
    ("T7", "trades.rs", "spends attributed by the signature script, not the spent UTXO (the round 1 HIGH)",
     "let Some(v) = self.by_spk.get(&entry.script_public_key) else {",
     "let Some(v) = pushes(&tx_input.signature_script).and_then(|p| p.last().map(|r| pay_to_script_hash_script(r))).and_then(|spk| self.by_spk.get(&spk)) else {"),
    ("T8", "trades.rs", "a vault spend need not reveal the vault's own script",
     ".is_some_and(|redeem| pay_to_script_hash_script(redeem) == entry.script_public_key)",
     ".is_some_and(|_| true)"),
    ("T9", "trades.rs", "an unclassified spend reported as settled",
     "        _ => Effect::Unclassified {\n            trade,",
     "        _ => Effect::Settled {\n            trade,"),
    ("T10", "trades.rs", "a settle reported as a refund",
     "Some(Entry::Settle) if input == leg.index() as u32 && exact => Effect::Settled {",
     "Some(Entry::Settle) if input == leg.index() as u32 && exact => Effect::Refunded {"),
    ("T11", "trades.rs", "deposits to the stray script are not flagged",
     "} else if let Some(trade) = self.stray_by_spk.get(&output.script_public_key) {",
     "} else if let Some(trade) = self.stray_by_spk.get(&output.script_public_key).filter(|_| false) {"),
    ("T12", "trades.rs", "a stray deposit's value dropped",
     "effects.push(Effect::StrayDeposit {\n                    trade: *trade,\n                    index,\n                    value,",
     "effects.push(Effect::StrayDeposit {\n                    trade: *trade,\n                    index,\n                    value: 0,"),
    ("T13", "trades.rs", "a funding output index off by one",
     "                    Some(amount) => Effect::Funded {\n                        trade,\n                        leg,\n                        index,",
     "                    Some(amount) => Effect::Funded {\n                        trade,\n                        leg,\n                        index: index + 1,"),
    ("T14", "trades.rs", "terms of another network accepted",
     "if network != self.network {", "if false && network != self.network {"),
    ("T15", "trades.rs", "a trade watched twice accepted",
     "if self.trades.contains_key(&id) {", "if false && self.trades.contains_key(&id) {"),
    ("T16", "trades.rs", "the stray script is not checked with impulse-core's decode",
     "        Err(TemplateError::NoVault {\n            leg: LegIndex::Cash,\n            ..\n        }) => Ok(script),\n        _ => Err(WatchError::StrayScriptUnderivable),",
     "        _ => Ok(script),"),
    ("T17", "trades.rs", "a KAS leg checked against the asset leg's amount",
     "LegKind::Kas => (Some(terms_leg.amount), None),", "LegKind::Kas => (Some(t.asset_leg.amount), None),"),
    ("T18", "trades.rs", "covenant_output never set",
     ".is_some_and(|c| Some(c.covenant_id) == v.covenant_id)", ".is_some_and(|_| false)"),
    ("T19", "trades.rs", "covenant_output set by an output of any covenant",
     ".is_some_and(|c| Some(c.covenant_id) == v.covenant_id)", ".is_some_and(|_| true)"),
    ("T20", "trades.rs", "a KCC-20 authorizer reported as funded",
     'Self::AuthorizerSeen { .. } => "authorizer_seen",', 'Self::AuthorizerSeen { .. } => "funded",'),
    ("T21", "trades.rs", "keep_signed accepts a settle claimed at any index",
     "Entry::Settle if input == v.leg.index() as usize =>", "Entry::Settle =>"),
    ("T22", "trades.rs", "keep_signed accepts a refund claimed at any index (review round 2)",
     "Entry::Refund if input == 0 =>", "Entry::Refund =>"),
    ("T23", "trades.rs", "keep_signed reads every settle claim at input 0, the asset leg's index (review round 2)",
     "Entry::Settle if input == v.leg.index() as usize =>", "Entry::Settle if input == 0 =>"),
    ("N1", "entry.rs", "the settle dispatch tag off by one bit",
     "[0xbd, 0x01, 0xfa, 0xf3]", "[0xbd, 0x01, 0xfa, 0xf2]"),
    ("N2", "entry.rs", "the entry tag read from the wrong push",
     "pushes.len().checked_sub(2)", "pushes.len().checked_sub(3)"),
    # Events and their JSON (event.rs).
    ("J1", "event.rs", "final renamed",
     'm.insert("event".into(), json!("final"));', 'm.insert("event".into(), json!("finalised"));'),
    ("J2", "event.rs", "reorg renamed",
     'm.insert("event".into(), json!("reorg"));', 'm.insert("event".into(), json!("reorged"));'),
    ("J3", "event.rs", "depth dropped from final",
     '                acceptance_fields(at, &mut m);\n                m.insert("depth".into(), json!(depth.to_string()));\n            }\n            Self::Reorg',
     '                acceptance_fields(at, &mut m);\n            }\n            Self::Reorg'),
    ("J4", "event.rs", "of dropped from reorg",
     'm.insert("event".into(), json!("reorg"));\n                m.insert("of".into(), json!(effect.name()));',
     'm.insert("event".into(), json!("reorg"));'),
    ("J5", "event.rs", "input dropped from spends",
     'm.insert("input".into(), json!(input));', ''),
    ("J6", "event.rs", "spent_value dropped from spends",
     'm.insert("spent_value".into(), json!(spent_value.to_string()));', ''),
    ("J7", "event.rs", "a stray deposit's value dropped from its JSON",
     'Effect::StrayDeposit { index, value, .. } => {\n            m.insert("output".into(), json!(index));\n            m.insert("value".into(), json!(value.to_string()));',
     'Effect::StrayDeposit { index, value, .. } => {\n            let _ = value;\n            m.insert("output".into(), json!(index));'),
    ("J8", "event.rs", "a funded value as a JSON number",
     '            m.insert("value".into(), json!(value.to_string()));\n            m.insert("exact".into(), json!(exact));',
     '            m.insert("value".into(), json!(value));\n            m.insert("exact".into(), json!(exact));'),
    ("J9", "event.rs", "accepting_daa as a JSON number",
     'json!(at.accepting_daa_score.to_string()),', 'json!(at.accepting_daa_score),'),
    ("J10", "event.rs", "escrow dropped from authorizer_seen",
     'm.insert("escrow".into(), json!("not_verified"));', ''),
    ("J11", "event.rs", "no code on a refused rebroadcast",
     'Self::Refused { .. } => Some("WATCH_REBROADCAST_FAILED"),', 'Self::Refused { .. } => None,'),
    ("J12", "event.rs", "an abandoned rebroadcast coded as a plain refusal",
     'Self::Abandoned { .. } => Some("WATCH_REBROADCAST_ABANDONED"),',
     'Self::Abandoned { .. } => Some("WATCH_REBROADCAST_FAILED"),'),
    ("J13", "event.rs", "no code on a rebroadcast skipped past expiry",
     'Self::PastExpiry { .. } => Some("WATCH_REBROADCAST_PAST_EXPIRY"),', 'Self::PastExpiry { .. } => None,'),
    ("J14", "event.rs", "no code on a reorg of a final acceptance",
     '} => Some("WATCH_FINAL_REORGED"),', '} => None,'),
    # The poll and rebroadcast (watcher.rs).
    ("W1", "watcher.rs", "an input with no signature script kept",
     "if let Some(input) = tx.inputs.iter().position(|i| i.signature_script.is_empty()) {",
     "if let Some(input) = tx.inputs.iter().position(|i| false && i.signature_script.is_empty()) {"),
    ("W2", "watcher.rs", "a transaction that claims no vault spend kept",
     "if !self.trades.claims_spend(&tx) {", "if false {"),
    ("W3", "watcher.rs", "a txid kept twice accepted",
     "if !self.state.kept.insert(txid) {", "if !{\n            self.state.kept.insert(txid);\n            true\n        } {"),
    ("W4", "watcher.rs", "the accepted copy not kept for spends",
     ".then(|| accepted.tx().clone());", ".then(|| accepted.tx().clone()).filter(|_| false);"),
    ("W5", "watcher.rs", "reorg events dropped",
     "events.extend(gone.effects.iter().map(|&effect| Event::Reorg {",
     "events.extend(gone.effects.iter().filter(|_| false).map(|&effect| Event::Reorg {"),
    ("W6", "watcher.rs", "was_final never set",
     "was_final: gone.finalized,", "was_final: false,"),
    ("W7", "watcher.rs", "transactions not kept are rebroadcast too",
     "if let (true, Some(tx)) = (self.state.kept.contains(txid), gone.tx) {",
     "if let (true, Some(tx)) = (true, gone.tx) {"),
    ("W8", "watcher.rs", "a pending rebroadcast accepted again is still submitted",
     "            // Accepted again, by whoever submitted it: nothing left to rebroadcast.\n            self.state.pending.remove(&txid);\n", ""),
    ("W9", "watcher.rs", "the settle expiry taken from refunds too",
     "Effect::Settled { trade, .. } => book.terms(trade),",
     "Effect::Settled { trade, .. } | Effect::Refunded { trade, .. } => book.terms(trade),"),
    ("W10", "watcher.rs", "a poll does not make pending rebroadcasts due",
     "            pending.due = true;\n", ""),
    ("W11", "watcher.rs", "finality one DAA score late",
     "self.finality.is_final(a.at.accepting_daa_score, tip)", "self.finality.is_final(a.at.accepting_daa_score + 1, tip)"),
    ("W12", "watcher.rs", "finals in reverse DAA order",
     ".map(|(txid, a)| (a.at.accepting_daa_score, *txid))", ".map(|(txid, a)| (u64::MAX - a.at.accepting_daa_score, *txid))"),
    ("W13", "watcher.rs", "a final depth reported as the tip",
     "            let depth = tip.saturating_sub(a.at.accepting_daa_score);\n            events.extend(a.effects.iter().map(|&effect| Event::Final {",
     "            let depth = tip;\n            events.extend(a.effects.iter().map(|&effect| Event::Final {"),
    ("W14", "watcher.rs", "final reported again on every poll",
     "            a.finalized = true;\n", ""),
    ("W15", "watcher.rs", "a settle at the expiry still submitted",
     "Ok(node_tip) if walk_tip.max(node_tip) >= expiry_daa => {", "Ok(node_tip) if walk_tip.max(node_tip) > expiry_daa => {"),
    ("W16", "watcher.rs", "an attempt does not wait for the next poll",
     "        pending.due = false;\n", ""),
    ("W17", "watcher.rs", "one attempt more than the cap",
     "if attempt >= REBROADCAST_ATTEMPTS {", "if attempt > REBROADCAST_ATTEMPTS {"),
    ("W18", "watcher.rs", "a submitted rebroadcast stays pending",
     "if !matches!(outcome, RebroadcastOutcome::Refused { .. }) {",
     "if matches!(outcome, RebroadcastOutcome::Abandoned { .. }) {"),
    ("W19", "watcher.rs", "an accepted effect's depth off by one",
     "            let depth = tip.saturating_sub(at.accepting_daa_score);\n            events.extend(effects.iter().map(|&effect| Event::Accepted {",
     "            let depth = tip.saturating_sub(at.accepting_daa_score) + 1;\n            events.extend(effects.iter().map(|&effect| Event::Accepted {"),
    ("W20", "watcher.rs", "a transaction accepted by two blocks of one walk: the first acceptance overwritten, never reported undone (review round 2)",
     "            self.unaccept(&txid, &mut events);\n", ""),
    ("W21", "watcher.rs", "a settle of two trades held back from the later expiry, not the earlier (review round 2)",
     ".map(TradeTerms::expiry_daa)\n        .min()\n}", ".map(TradeTerms::expiry_daa)\n        .max()\n}"),
    ("W22", "watcher.rs", "a poll runs while a trade of the resumed state is not added again (review round 3)",
     "if !missing.is_empty() {", "if false {"),
    ("W23", "watcher.rs", "a trade added again from a resumed state reports the cursor now, not its first (review round 3)",
     "let from = *self.state.trades.entry(trade).or_insert(cursor);",
     "self.state.trades.insert(trade, cursor);\n        let from = cursor;"),
    ("W24", "watcher.rs", "a trade added once polls have run reports no cursor (review round 3)",
     "let cursor = self.state.tracker.store().cursor();", "let cursor: Option<Cursor> = None;"),
    ("W25", "watcher.rs", "a refused trade recorded in the state (review round 3)",
     "let trade = self.trades.add(terms)?;",
     "let terms: TradeTerms = terms.into();\n        self.state.trades.entry(TradeId(terms.terms_hash())).or_insert(None);\n        let trade = self.trades.add(terms)?;"),
    # The tracker (tracker.rs).
    ("K1", "tracker.rs", "txid read from the transaction's cache",
     "let txid = hashing::tx::id(accepted.tx());", "let txid = accepted.tx().id();"),
    ("K2", "tracker.rs", "removed blocks applied oldest first",
     "for removed_hash in &update.removed_chain_block_hashes {",
     "for removed_hash in update.removed_chain_block_hashes.iter().rev() {"),
    ("K3", "tracker.rs", "only the first removed block honoured",
     "for removed_hash in &update.removed_chain_block_hashes {",
     "for removed_hash in update.removed_chain_block_hashes.iter().take(1) {"),
    ("K4", "tracker.rs", "only the last removed block honoured",
     "for removed_hash in &update.removed_chain_block_hashes {",
     "for removed_hash in update.removed_chain_block_hashes.iter().rev().take(1) {"),
    ("K5", "tracker.rs", "the cursor moved to the first added block",
     "if let Some(last) = update.added_chain_blocks.last() {", "if let Some(last) = update.added_chain_blocks.first() {"),
    ("K6", "tracker.rs", "only the first added block's acceptances indexed",
     "for block in &update.added_chain_blocks {", "for block in update.added_chain_blocks.iter().take(1) {"),
    ("K7", "tracker.rs", "a removed block's transactions stay accepted",
     "                self.store.unaccept(&txid);\n                removed_txids.push(txid);\n            }\n        }",
     "                removed_txids.push(txid);\n            }\n        }"),
    ("K8", "tracker.rs", "a walk delivered twice applied twice",
     "Some(known) if known == info => continue,", "Some(known) if known == info => {}"),
    ("K9", "tracker.rs", "a move without a removal not un-accepted",
     "                    Some(_) => {\n                        self.store.unaccept(&txid);\n                        removed_txids.push(txid);\n                    }",
     "                    Some(_) => {}"),
    ("K10", "tracker.rs", "the by-block index not moved with an acceptance",
     "        if let Some(old) = self.acceptances.insert(txid, info) {\n            self.unindex(&txid, &old.accepting_block_hash);\n        }",
     "        self.acceptances.insert(txid, info);"),
    ("K11", "tracker.rs", "bootstrap at the sink, skipping the sink's own acceptances",
     "block_hash: source.selected_parent_hash(sink).await?,", "block_hash: sink,"),
    ("K12", "tracker.rs", "spent entries not checked against the inputs",
     "if spent.len() != tx.inputs.len() {", "if false {"),
    ("K13", "tracker.rs", "finality with wrapping subtraction",
     "tip_daa.saturating_sub(accepting_daa) >= self.depth_daa", "tip_daa.wrapping_sub(accepting_daa) >= self.depth_daa"),
    ("K14", "tracker.rs", "depth zero accepted",
     "        if depth_daa == 0 {\n            return Err(crate::WatchError::FinalityDepthZero);",
     "        if depth_daa == u64::MAX {\n            return Err(crate::WatchError::FinalityDepthZero);"),
    # Phase 2 (I8): retiring and evicting (watcher.rs), the state file (persist.rs), the strict
    # readers (files.rs), the node's answers (node.rs) and the binary's logic (run.rs). The wRPC
    # client glue itself (connect, the calls, submit) and the process are covered by
    # tests/e2e.rs, which this run does not execute (--lib). Not listed, because it cannot be
    # told from the original: the `a.finalized` condition of the eviction filter (a retention
    # window above the finality depth makes it redundant) and the skip of a state write that
    # changes nothing (only the file's modification time shows it).
    ("W26", "watcher.rs", "a final acceptance one DAA short of the retention window is evicted",
     ">= retention.retain_daa", "> retention.retain_daa"),
    ("W27", "watcher.rs", "a kept transaction is evicted with the rest",
     "                        && !self.state.kept.contains(txid)\n", ""),
    ("W28", "watcher.rs", "an evicted acceptance stays in the tracker's index",
     "                self.state.accepted.remove(&txid);\n                self.state.tracker.forget(&txid);\n            }\n        }\n\n        Ok(events)",
     "                self.state.accepted.remove(&txid);\n            }\n        }\n\n        Ok(events)"),
    ("W29", "watcher.rs", "a retention window equal to the finality depth is accepted",
     "if retain_daa <= finality.depth_daa() {", "if retain_daa < finality.depth_daa() {"),
    ("W30", "watcher.rs", "retiring a trade keeps its effects on accepted transactions",
     "accepted.effects.retain(|e| e.trade() != trade);", "accepted.effects.retain(|_| true);"),
    ("W31", "watcher.rs", "retiring a trade leaves it in the state",
     "if self.state.trades.remove(&trade).is_none() {", "if self.state.trades.get(&trade).is_none() {"),
    ("W32", "watcher.rs", "retiring a trade leaves an emptied acceptance in the tracker's index",
     "            self.state.accepted.remove(&txid);\n            self.state.tracker.forget(&txid);\n            self.state.pending.remove(&txid);",
     "            self.state.accepted.remove(&txid);\n            self.state.pending.remove(&txid);"),
    ("W33", "watcher.rs", "retiring a trade keeps a pending rebroadcast that settles no watched vault",
     ".filter(|(_, p)| !book.claims_spend(&p.tx))", ".filter(|(_, _)| false)"),
    ("W34", "watcher.rs", "retiring a trade drops every pending rebroadcast",
     ".filter(|(_, p)| !book.claims_spend(&p.tx))", ".filter(|(_, _)| true)"),
    ("W35", "watcher.rs", "retiring a trade leaves its emptied transaction kept",
     "            self.state.pending.remove(&txid);\n            self.state.kept.remove(&txid);\n        }\n        // Nothing of it",
     "            self.state.pending.remove(&txid);\n        }\n        // Nothing of it"),
    ("W36", "watcher.rs", "a trade of a resumed state is never reported as missing",
     ".filter(|trade| self.trades.terms(trade).is_none())", ".filter(|_| false)"),
    ("P1", "persist.rs", "a state of another network is read",
     "if file_network != network_name(network) {", "if false {"),
    ("P2", "persist.rs", "a spend need not carry its accepted copy, nor a non-spend lack one",
     "if tx.is_some() != spends {", "if false {"),
    ("P3", "persist.rs", "an accepted copy of another transaction is read",
     "if tx.as_ref().is_some_and(|t| t.id() != txid) {", "if false {"),
    ("P4", "persist.rs", "a pending rebroadcast need not be kept",
     "if !kept.contains(&txid) {", "if false {"),
    ("P5", "persist.rs", "a transaction both pending and accepted is read",
     "if accepted.contains_key(&txid) {", "if false {"),
    ("P6", "persist.rs", "an effect of a trade the state does not hold is read",
     "if !trades.contains_key(&e.trade()) {", "if false {"),
    ("P7", "persist.rs", "a txid listed twice among the kept is read",
     "if !out.insert(Hash::from_bytes(id)) {", "if { out.insert(Hash::from_bytes(id)); false } {"),
    ("P8", "persist.rs", "the carried ID of a stored transaction is not checked",
     "if tx.id() != hashing::tx::id(&tx) {", "if false {"),
    ("P9", "persist.rs", "the final flag is not saved",
     "\"finalized\": a.finalized,", "\"finalized\": false,"),
    ("P10", "persist.rs", "the settle expiry of an accepted transaction is not saved",
     "\"settle_expiry\": opt_dec(a.settle_expiry),", "\"settle_expiry\": Value::Null,"),
    ("P11", "persist.rs", "the settle expiry of a pending rebroadcast is not saved",
     "\"settle_expiry\": opt_dec(p.settle_expiry),", "\"settle_expiry\": Value::Null,"),
    ("P12", "persist.rs", "the attempt count of a pending rebroadcast is not saved",
     "\"attempts\": p.attempts,", "\"attempts\": 0,"),
    ("P13", "persist.rs", "the due flag of a pending rebroadcast is not saved",
     "\"due\": p.due,", "\"due\": true,"),
    ("P14", "persist.rs", "the temporary file is left behind when a write fails",
     "let _ = std::fs::remove_file(&tmp);", "let _ = &tmp;"),
    ("P15", "persist.rs", "a second watcher on the state file is not refused",
     "match file.try_lock() {", "match Ok::<(), std::fs::TryLockError>(()) {"),
    ("P16", "persist.rs", "the state file is readable by others",
     "options.write(true).create_new(true);\n        #[cfg(unix)]\n        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);",
     "options.write(true).create_new(true);\n        #[cfg(unix)]\n        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);"),
    ("P17", "persist.rs", "the state file always says mainnet",
     "\"network\": network_name(network),", "\"network\": \"mainnet\","),
    ("F1", "files.rs", "a terms file's hash is not checked against its canonical bytes",
     "if terms.terms_hash() != hash {", "if false {"),
    ("F2", "files.rs", "a signed transaction's carried ID is not checked",
     "if tx.id() != hashing::tx::id(&tx) {", "if false {"),
    ("F3", "files.rs", "a key named twice is read",
     "if out.contains_key(&key) {", "if false {"),
    ("F4", "files.rs", "uppercase hex is read",
     "matches!(b, b'0'..=b'9' | b'a'..=b'f')", "matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')"),
    ("F5", "files.rs", "a decimal with a leading zero is read",
     "(s.len() > 1 && s.starts_with('0'))", "false"),
    ("F6", "files.rs", "an unexpected key is read",
     "if !keys.contains(&key.as_str()) {", "if false {"),
    ("C1", "node.rs", "a rebuilt transaction ID is not compared with the node's",
     "if computed != reported {", "if false {"),
    ("C2", "node.rs", "a batch need not name its chain block",
     "if header.hash != Some(*hash) {", "if false {"),
    ("C3", "node.rs", "added chain blocks and batches need not match in number",
     "if r.added_chain_block_hashes.len() != batches.len() {", "if false {"),
    ("C4", "node.rs", "a missing storage mass is taken as zero",
     "need(tx.storage_mass, \"storage mass\")?,", "tx.storage_mass.unwrap_or(0),"),
    ("C5", "node.rs", "a version 0 transaction is read for a compute budget and a later one for a sigop count",
     "inputs.push(if version == 0 {", "inputs.push(if version != 0 {"),
    ("C6", "node.rs", "mainnet accepts plaintext to any host",
     "if matches!(host, \"127.0.0.1\" | \"[::1]\" | \"localhost\") && port_ok {", "if port_ok {"),
    ("C7", "node.rs", "mainnet accepts any ws:// link",
     "if network == Network::Testnet || url.starts_with(\"wss://\") {", "if network == Network::Testnet || url.starts_with(\"ws\") {"),
    ("C8", "node.rs", "a node that is not synced is accepted",
     "if !info.is_synced {", "if false {"),
    ("C9", "node.rs", "a node on another network is accepted",
     "if impulse_network(info) != Some(expected) {", "if false {"),
    ("C10", "node.rs", "any transaction's 'already in the mempool' is taken for ours",
     "reason.contains(&format!(\"transaction {txid} is already in the mempool\"))", "reason.contains(\"is already in the mempool\")"),
    ("R1", "run.rs", "under the lock, a new state may replace an existing file",
     "(true, true) => Err(WatchError::StateExists(path.display().to_string())),\n        (true, false) => Ok((WatchState::default(), None)),",
     "(true, true) => Ok((WatchState::default(), None)),\n        (true, false) => Ok((WatchState::default(), None)),"),
    ("R2", "run.rs", "under the lock, a missing state file is silently a new one",
     "(false, false) => Err(WatchError::StateMissing(path.display().to_string())),\n        (false, true) => {\n            let text",
     "(false, false) => Ok((WatchState::default(), None)),\n        (false, true) => {\n            let text"),
    ("R3", "run.rs", "a trade both retired and watched is accepted",
     ".find(|t| args.retire.contains(t))", ".find(|t| args.retire.contains(t) && false)"),
    ("R4", "run.rs", "a kept transaction named again on restart is an error",
     "if watcher.is_kept(&hashing::tx::id(&tx)) {", "if false {"),
    ("R5", "run.rs", "a trade of the state with no terms file is not refused before the node is contacted",
     "if !missing.is_empty() {", "if false {"),
    ("R6", "run.rs", "a failed poll ends the run",
     "Err(e @ WatchError::SourceFailed(_)) => {", "Err(e @ WatchError::TxDuplicate(_)) => {"),
    ("R7", "run.rs", "failed polls are not counted",
     "outcome.failed_polls += 1;", "outcome.failed_polls += 0;"),
    ("R8", "run.rs", "the state is saved before the events are printed",
     "                print_events(out, number, &events)\n                    .map_err(|e| WatchError::OutputFailed(e.to_string()))?;\n                prepared.save()?;",
     "                prepared.save()?;\n                print_events(out, number, &events)\n                    .map_err(|e| WatchError::OutputFailed(e.to_string()))?;"),
    ("R9", "run.rs", "events are not written one per line",
     "writeln!(out, \"{}\", event.to_json_in_round(round))?;", "write!(out, \"{}\", event.to_json_in_round(round))?;"),
    ("R10", "run.rs", "a bounded run polls once too often",
     "if max_polls.is_some_and(|k| outcome.polls >= k) {", "if max_polls.is_some_and(|k| outcome.polls > k) {"),
    ("R11", "run.rs", "control characters are written to the terminal",
     "            if c.is_control() {", "            if false {"),
    # Operations (I14): --max-failed-polls and --log-format.
    ("R23", "run.rs", "a poll that goes through does not reset the failed-poll count (I14)",
     "                prepared.failed_in_a_row = 0;\n", ""),
    ("R24", "run.rs", "--max-failed-polls ends the run one failure late (I14)",
     "if prepared.failed_in_a_row >= k {", "if prepared.failed_in_a_row > k {"),
    ("R25", "run.rs", "a JSON log line carries no code (I14)",
     "                \"code\": code,\n", ""),
    ("R26", "run.rs", "a JSON log line is not escaped by JSON but written raw (I14)",
     "            .to_string()\n        }\n    }\n}", "            .to_string()\n            .replace(\"\\\\n\", \"\\n\")\n        }\n    }\n}"),
    # Review round 4: retiring, the expiry guard and the remembered acceptance (watcher.rs).
    ("W37", "watcher.rs", "retiring leaves the accepted copy of a transaction that no longer spends (review round 4)",
     "                accepted.tx = None;\n", ""),
    ("W38", "watcher.rs", "retiring leaves a transaction that no longer spends among the kept (review round 4)",
     "        for txid in no_longer_a_spend {\n            self.state.kept.remove(&txid);\n        }\n", ""),
    ("W39", "watcher.rs", "retiring does not recompute the settle expiry of what stays (review round 4)",
     "            accepted.settle_expiry = if all_known {\n                settle_expiry(book, &accepted.effects)\n            } else {\n                accepted.settle_expiry\n            };",
     "            let _ = all_known;"),
    ("W40", "watcher.rs", "retiring clears the expiry of a settle of a trade not added again (review round 4)",
     "            accepted.settle_expiry = if all_known {", "            accepted.settle_expiry = if true {"),
    ("W41", "watcher.rs", "retiring does not recompute the expiry of a pending settle (review round 4)",
     "            pending.settle_expiry = book.claimed_settle_expiry(&pending.tx);", "            let _ = &pending.tx;"),
    ("W42", "watcher.rs", "the expiry guard takes the walk's tip, not the node's clock (review round 4)",
     "Ok(node_tip) if walk_tip.max(node_tip) >= expiry_daa => {", "Ok(node_tip) if walk_tip >= expiry_daa => {"),
    ("W43", "watcher.rs", "a settle is submitted when the node's clock cannot be read (review round 4)",
     "                Err(reason) => Err(Refusal::Refused(format!(\n                    \"the node's virtual DAA score could not be read, so the settle's expiry could not be checked and it was not submitted: {reason}\"\n                ))),",
     "                Err(_) => broadcaster.submit(&tx).await,"),
    ("W44", "watcher.rs", "a remembered acceptance uses up an attempt (review round 4)",
     "            Err(Refusal::RecentlyAccepted(reason)) => RebroadcastOutcome::Refused {\n                attempt: pending.attempts,",
     "            Err(Refusal::RecentlyAccepted(reason)) => RebroadcastOutcome::Refused {\n                attempt: {\n                    pending.attempts += 1;\n                    pending.attempts\n                },"),
    ("W45", "watcher.rs", "a remembered acceptance ends the rebroadcast (review round 4)",
     "Err(Refusal::RecentlyAccepted(reason)) => RebroadcastOutcome::Refused {", "Err(Refusal::RecentlyAccepted(reason)) => RebroadcastOutcome::Abandoned {"),
    ("W46", "watcher.rs", "a skipped settle reports the walk's tip, not the one it was held back at (review round 4)",
     "tip_daa: walk_tip.max(node_tip),", "tip_daa: walk_tip,"),
    ("T31", "trades.rs", "a retired external-cash trade still flags deposits to its stray script (review round 4)",
     "        self.stray_by_spk.retain(|_, t| t != trade);\n", ""),
    ("T32", "trades.rs", "a pending refund inherits its trade's expiry as a settle expiry (review round 4)",
     ".filter(|(_, entry)| *entry == Entry::Settle)", ".filter(|_| true)"),
    # The adapter (node.rs; these also run the end-to-end target).
    ("C11", "node.rs", "an ID in the answer that is not the transaction's is taken for it (review round 4)",
     "Ok(id) if id == txid => Ok(()),", "Ok(_) => Ok(()),"),
    ("C12", "node.rs", "the node's record of an acceptance is not told apart from a refusal (review round 4)",
     "Err(e) if node_recently_accepted(&e.0, &txid) => Err(Refusal::RecentlyAccepted(e.0)),", "Err(e) if false => Err(Refusal::RecentlyAccepted(e.0)),"),
    ("C13", "node.rs", "'already in the mempool' is a refusal (review round 4)",
     "Err(e) if node_has_in_mempool(&e.0, &txid) => Ok(()),", "Err(e) if false => Ok(()),"),
    ("C14", "node.rs", "a node that never answers is waited for (review round 4)",
     "match tokio::time::timeout(self.call_timeout, call).await {", "match tokio::time::timeout(Duration::from_secs(30_000_000), call).await {"),
    ("C15", "node.rs", "the node's clock is read off by one (review round 4)",
     ".map(|p| p.2).map_err(|e| e.0)", ".map(|p| p.2 + 1).map_err(|e| e.0)"),
    ("C16", "node.rs", "chain blocks of a walk may repeat a DAA score (review round 4)",
     "added.last().filter(|b| b.daa_score >= daa_score)", "added.last().filter(|b| b.daa_score > daa_score)"),
    ("C17", "node.rs", "a link that is down is never made again (review round 4)",
     "        if self.client.is_connected() && !dropped {\n            return Ok(());\n        }", "        if true {\n            return Ok(());\n        }"),
    ("C18", "node.rs", "a link made again is not checked for network and sync (review round 4)",
     "check_server_info(&info, self.network).map_err(|e| e.to_string())", "Ok::<(), String>(()).map(|()| {\n                let _ = (&info, self.network);\n            })"),
    ("C19", "node.rs", "a link the client re-made by itself is not checked (review round 4)",
     "if self.client.is_connected() && !dropped {", "if self.client.is_connected() {"),
    ("C20", "node.rs", "text from the other end of a failed connection is echoed raw (review round 4)",
     "format!(\"{}: {:?}\", redact_url(url), error.to_string())", "format!(\"{}: {}\", redact_url(url), error)"),
    ("C21", "node.rs", "the user information of a node URL is echoed (review round 4)",
     "Some((_, host)) => (\"***@\", host),", "Some((_, host)) => (\"\", authority),"),
    ("C22", "node.rs", "the path and query of a node URL are echoed (review round 4)",
     "let more = if tail.is_empty() { \"\" } else { \"/...\" };", "let more = tail;"),
    ("C23", "node.rs", "the probe accepts a walk that adds nothing (review round 4)",
     "    if blocks == 0 {", "    if false {"),
    ("C24", "node.rs", "the probe accepts a walk from behind the sink that removes chain blocks (review round 4)",
     "if !near.removed_chain_block_hashes.is_empty() {", "if false {"),
    ("C25", "node.rs", "the probe never reports the node's batch limit (review round 4)",
     "report.lines.push(if last < virtual_daa.saturating_sub(100) {", "report.lines.push(if false {"),
    ("C26", "node.rs", "connect does not check the transport (review round 4)",
     "        check_transport(url, network)?;\n        let client = KaspaRpcClient::new", "        let client = KaspaRpcClient::new"),
    ("C27", "node.rs", "an invalid node URL is echoed in full (review round 4)",
     "_ => Err(WatchError::NodeUrlInvalid(redact_url(url))),", "_ => Err(WatchError::NodeUrlInvalid(url.to_string())),"),
    ("C28", "node.rs", "an insecure node URL is echoed in full (review round 4)",
     "Err(WatchError::NodeInsecure(redact_url(url)))", "Err(WatchError::NodeInsecure(url.to_string()))"),
    # The state file (persist.rs, files.rs).
    ("P18", "persist.rs", "the temporary file may be an existing one, a planted link included (review round 4)",
     "options.write(true).create_new(true);", "options.write(true).create(true).truncate(true);"),
    ("P19", "persist.rs", "the new state file is never moved over the old one (review round 4)",
     "        std::fs::rename(&tmp, path)\n    })();", "        Ok(())\n    })();"),
    ("P20", "persist.rs", "leftover temporary files are not removed (review round 4)",
     "std::fs::remove_file(entry.path()).is_ok()", "false"),
    ("P21", "persist.rs", "any file with .tmp. in its name is taken for a leftover (review round 4)",
     "file_name.starts_with(&prefix)", "file_name.contains(\".tmp.\")"),
    ("P22", "persist.rs", "a lock file beside a state file is removed (review round 4)",
     "if self.created && !self.state_path.exists() {", "if self.created {"),
    ("P23", "persist.rs", "a lock file the run did not make is removed (review round 4)",
     "if self.created && !self.state_path.exists() {", "if !self.state_path.exists() {"),
    ("P24", "persist.rs", "a settle expiry on a transaction that settles nothing is read (review round 4)",
     "if settle_expiry.is_some() != settles {", "if false {"),
    ("P25", "persist.rs", "settle_expiry renamed in the writer and the reader together (review round 4)",
     "\"settle_expiry\"", "\"settle_exp\"", 6),
    ("P26", "persist.rs", "spent_value renamed in the writer and the reader together (review round 4)",
     "\"spent_value\"", "\"spent_val\"", 3),
    ("P27", "persist.rs", "covenant_output renamed in the writer and the reader together (review round 4)",
     "\"covenant_output\"", "\"covenant_out\"", 3),
    ("P28", "persist.rs", "finalized renamed in the writer and the reader together (review round 4)",
     "\"finalized\"", "\"final\"", 3),
    ("P29", "persist.rs", "the state is written compact, not pretty (review round 4)",
     "serde_json::to_string_pretty(&doc)", "serde_json::to_string(&doc)"),
    ("P30", "persist.rs", "a trade's first cursor is never written (review round 4)",
     "\"from\": from.as_ref().map_or(Value::Null, cursor_json)", "\"from\": Value::Null"),
    ("P31", "persist.rs", "an extra key in a trade entry is read (review round 4)",
     "t.keys(&[\"trade\", \"from\"]).map_err(invalid)?;", "t.keys(&[\"trade\", \"from\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) }).map_err(invalid)?;"),
    ("P32", "persist.rs", "an extra key in a cursor is read (review round 4)",
     "o.keys(&[\"block\", \"daa\"])?;", "o.keys(&[\"block\", \"daa\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P33", "persist.rs", "an extra key in a funded effect is read (review round 4)",
     "o.keys(&[\"kind\", \"trade\", \"leg\", \"index\", \"value\", \"exact\"])?;", "o.keys(&[\"kind\", \"trade\", \"leg\", \"index\", \"value\", \"exact\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P34", "persist.rs", "an extra key in an authorizer_seen effect is read (review round 4)",
     "o.keys(&[\"kind\", \"trade\", \"leg\", \"index\", \"value\", \"covenant_output\"])?;", "o.keys(&[\"kind\", \"trade\", \"leg\", \"index\", \"value\", \"covenant_output\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P35", "persist.rs", "an extra key in a spend effect is read (review round 4)",
     "\"spent_value\",\n            ])?;", "\"spent_value\",\n            ]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P36", "persist.rs", "an extra key in a stray deposit effect is read (review round 4)",
     "o.keys(&[\"kind\", \"trade\", \"index\", \"value\"])?;", "o.keys(&[\"kind\", \"trade\", \"index\", \"value\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P37", "persist.rs", "an extra key in an accepted entry is read (review round 4)",
     "\"effects\",\n            ])?;", "\"effects\",\n            ]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("P38", "persist.rs", "an extra key in a pending entry is read (review round 4)",
     "p.keys(&[\"txid\", \"tx\", \"settle_expiry\", \"attempts\", \"due\"])?;", "p.keys(&[\"txid\", \"tx\", \"settle_expiry\", \"attempts\", \"due\"]).or_else(|e| if e.contains(\"unexpected key\") { Ok(()) } else { Err(e) })?;"),
    ("F7", "files.rs", "a u32 is truncated, not refused (review round 4)",
     ".and_then(|n| u32::try_from(n).ok())", ".map(|n| n as u32)"),
    ("F8", "files.rs", "odd-length hex is read (review round 4)",
     "if !s.len().is_multiple_of(2) || !s.bytes()", "if !s.bytes()"),
    ("F9", "files.rs", "a decimal with a plus sign is read (review round 4)",
     "!s.bytes().all(|b| b.is_ascii_digit())", "!s.bytes().all(|b| b.is_ascii_digit() || b == b'+')"),
    # The binary's logic (run.rs, cli.rs).
    ("R12", "run.rs", "the retention window is accepted and never set (review round 4)",
     "    if let Some(retention) = retention {", "    if let Some(retention) = retention.filter(|_| false) {"),
    ("R13", "run.rs", "a run does not wait between polls (review round 4)",
     "        tokio::time::sleep(interval).await;\n", ""),
    ("R14", "run.rs", "a run ignores the poll interval (review round 4)",
     "tokio::time::sleep(interval).await;", "tokio::time::sleep(Duration::ZERO).await;"),
    ("R15", "run.rs", "the state file's place is not checked before the lock file is made (review round 4)",
     "    check_state_location(&args.state, args.init)?;\n", ""),
    ("R16", "run.rs", "leftover temporary files are not cleared at start-up (review round 4)",
     "persist::remove_leftover_temp_files(&args.state)", "Vec::<String>::new()"),
    ("R17", "run.rs", "the transport is checked after the files are read (review round 4)",
     "    check_transport(&args.node, network)?;\n    let terms = args\n        .trades\n        .iter()\n        .map(|p| read_terms_file(p))\n        .collect::<Result<Vec<_>, _>>()?;",
     "    let terms = args\n        .trades\n        .iter()\n        .map(|p| read_terms_file(p))\n        .collect::<Result<Vec<_>, _>>()?;\n    check_transport(&args.node, network)?;"),
    ("R18", "run.rs", "the transport is checked before the retention window (review round 4)",
     "    let retention = args\n        .retention_daa\n        .map(|r| Retention::new(r, finality))\n        .transpose()?;\n    check_transport(&args.node, network)?;",
     "    check_transport(&args.node, network)?;\n    let retention = args\n        .retention_daa\n        .map(|r| Retention::new(r, finality))\n        .transpose()?;"),
    ("R19", "run.rs", "a refusal that ends the run is written with its control characters (review round 4)",
     "format!(\"impulse-watch: {}\", escape_control(&error.to_string()))", "format!(\"impulse-watch: {}\", error)"),
    ("R20", "run.rs", "a state file that cannot be written does not end the run (the reviewer's S1)",
     "                prepared.save()?;", "                let _ = prepared.save();"),
    ("A04", "cli.rs", "a bound of 0 polls is accepted (review round 4)",
     "range(1..))]\n    pub max_polls:", "range(0..))]\n    pub max_polls:"),
    ("A05", "cli.rs", "the poll interval defaults to 0 (review round 4)",
     "default_value_t = 1000", "default_value_t = 0"),
    # Review round 5: the round number in every event, and the link dropped after a silent call.
    ("W47", "watcher.rs", "a round that reported something is not counted (review round 5)",
     "        if !events.is_empty() {\n            self.state.round += 1;\n        }",
     "        if false {\n            self.state.round += 1;\n        }"),
    ("W48", "watcher.rs", "a round that reported nothing is counted too (review round 5)",
     "        if !events.is_empty() {\n            self.state.round += 1;", "        if true {\n            self.state.round += 1;"),
    ("W49", "watcher.rs", "the count of rounds restarts at 1 every round (review round 5)",
     "self.state.round += 1;", "self.state.round = 1;"),
    ("J15", "event.rs", "the round number is left out of the event (review round 5)",
     'm.insert("round".into(), json!(round.to_string()));', ''),
    ("J16", "event.rs", "the round number is a JSON number (review round 5)",
     'm.insert("round".into(), json!(round.to_string()));', 'm.insert("round".into(), json!(round));'),
    ("P39", "persist.rs", "the round count is never written to the state file (review round 5)",
     '"round": dec(state.round),', '"round": dec(0),'),
    ("P40", "persist.rs", "the round count is never read from the state file (review round 5)",
     'round: o.dec("round").map_err(invalid)?,', 'round: 0,'),
    ("P41", "persist.rs", "a state file without the round count is read (review round 5)",
     '"accepted", "kept", "pending", "round",\n    ])', '"accepted", "kept", "pending",\n    ])'),
    ("R21", "run.rs", "a round's events carry the previous round's number (review round 5)",
     "let number = prepared.watcher.close_round(&events);", "let number = prepared.watcher.state().round();"),
    ("R22", "run.rs", "the binary prints events without the round number (review round 5)",
     "event.to_json_in_round(round)", "event.to_json()"),
    ("C29", "node.rs", "a call that gets no answer leaves the link up (review round 5)",
     "                self.drop_silent_link().await;\n", ""),
    ("C30", "node.rs", "making the link again waits for a node that never answers the check (review round 5)",
     "        let outcome = match tokio::time::timeout(self.call_timeout, again).await {\n            Ok(outcome) => outcome,\n            Err(_) => Err(format!(\"no answer in {} ms\", self.call_timeout.as_millis())),\n        };",
     "        let outcome = again.await;"),
    # Template v2 trades (I16 CLI step, spec/V2.md 6.5).
    ("V01", "entry.rs", "the v2 settle tag is another tag",
     "[0x8f, 0xb0, 0x4e, 0x80]", "[0x8f, 0xb0, 0x4e, 0x81]"),
    ("V02", "trades.rs", "a v2 vault's spends read with the v1 tags",
     "    if v.v2 {\n        entry_of_v2(pushes)", "    if !v.v2 {\n        entry_of_v2(pushes)"),
    ("V03", "trades.rs", "every inexact KAS settle reported settled",
     "let exact = exact || !v.whole;", "let exact = exact || v.whole;"),
    ("V04", "trades.rs", "partial terms v2 held to the exact amount",
     "whole: t.partial.is_none(),", "whole: true,"),
    ("V05", "trades.rs", "every v2 vault reported as leg 0",
     "leg: Leg::V2(i as u8),", "leg: Leg::V2(0),"),
    ("V06", "files.rs", "a terms file v2 decoded as version 1",
     "if canonical.first() == Some(&TERMS_V2_VERSION) {", "if canonical.first() == Some(&0) {"),
    ("V07", "persist.rs", "a v2 leg index of MAX_LEGS read from the state file",
     ".filter(|i| usize::from(*i) < impulse_core::v2::MAX_LEGS)", ".filter(|i| usize::from(*i) <= impulse_core::v2::MAX_LEGS)"),
    ("V08", "event.rs", "a v2 leg reported as the asset leg",
     "        Leg::V2(i) => json!(i),", "        Leg::V2(_) => json!(\"asset\"),"),
    ("O1", "node.rs", "a walk of any number of added chain blocks is converted (I14 O1)",
     "r.added_chain_block_hashes.len() > MAX_ADDED_CHAIN_BLOCKS", "false"),
    ("O2", "node.rs", "the cap on added chain blocks is one too many (I14 O1)",
     "r.added_chain_block_hashes.len() > MAX_ADDED_CHAIN_BLOCKS", "r.added_chain_block_hashes.len() > MAX_ADDED_CHAIN_BLOCKS + 1"),
    ("O3", "node.rs", "a chain block at the virtual DAA score is refused (I14 O1)",
     "Some(b) if b.daa_score > virtual_daa =>", "Some(b) if b.daa_score >= virtual_daa =>"),
    ("O4", "node.rs", "a chain block above the virtual DAA score is taken (I14 O1)",
     "Some(b) if b.daa_score > virtual_daa =>", "Some(b) if b.daa_score > virtual_daa.saturating_add(1_000) =>"),
    ("O5", "node.rs", "the adapter never compares the walk with the virtual DAA score (I14 O1)",
     "            check_below_virtual(&update, self.dag_points().await?.2)?;\n", ""),
    # The linked-return watch (I22 review): phases and the early flag (linked.rs).
    ("LK1", "linked.rs", "a side with nothing refunded reads as refunded",
     "!self.settled() && !self.refunded.is_empty()", "!self.settled() || !self.refunded.is_empty()"),
    ("LK2", "linked.rs", "a refund is not recorded",
     "                    self.refunded.insert(i);", "                    let _ = i;"),
    ("LK3", "linked.rs", "the early flag ignores the opening settling",
     "early: ret.started() && !opening.settled(),", "early: ret.started(),"),
    ("LK4", "linked.rs", "the early flag is raised when the opening settled",
     "early: ret.started() && !opening.settled(),", "early: ret.started() && opening.settled(),"),
    ("LK5", "linked.rs", "the early flag is raised without a started return",
     "early: ret.started() && !opening.settled(),", "early: !opening.settled(),"),
    ("LK6", "linked.rs", "a settled leg does not count as a started return",
     "!self.started.is_empty() || !self.settled.is_empty()", "!self.started.is_empty()"),
    ("LK7", "linked.rs", "an exact funding does not start a side",
     "Effect::Funded { exact: true, .. } | Effect::AuthorizerSeen { .. } => {",
     "Effect::AuthorizerSeen { .. } => {"),
    # WATCH_FOREIGN_TOKEN, retired in I26: an earlier build's foreign_token effect still reads back.
    ("FT6", "persist.rs", "a foreign_token effect reads back without its covenant",
     "                covenant_id: Hash::from_bytes(o.hex32(\"covenant_id\")?),", "                covenant_id: Hash::from_bytes([0; 32]),"),
]


def source_files():
    """The files the record is for, relative to the repository: the watcher's source (its library
    tests included), the end-to-end test and the golden state file."""
    files = [os.path.join(SRC, f) for f in sorted(os.listdir(os.path.join(ROOT, SRC))) if f.endswith(".rs")]
    files.append(os.path.join(CRATE, "tests", "e2e.rs"))
    golden = os.path.join(CRATE, "tests", "golden")
    files += [os.path.join(golden, f) for f in sorted(os.listdir(os.path.join(ROOT, golden)))]
    return files


def source_digest():
    """sha256 over every file of source_files(), by path, in order."""
    h = hashlib.sha256()
    for rel in source_files():
        with open(os.path.join(ROOT, rel), "rb") as f:
            h.update(rel.encode() + b"\0" + f.read() + b"\0")
    return h.hexdigest()


def script_digest():
    with open(os.path.realpath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check():
    try:
        with open(RECORD) as f:
            record = f.read()
    except OSError:
        sys.exit("missing %s: run scripts/watch-mutation.py --record" % RECORD)
    result = re.search(r"^result: (\d+) of (\d+) mutants caught$", record, re.M)
    problems = []
    if not re.search(r"^source sha256 %s$" % source_digest(), record, re.M):
        problems.append("the record is for other watcher source")
    if not re.search(r"^script sha256 %s$" % script_digest(), record, re.M):
        problems.append("the record is for another mutant list")
    if not result or result.group(1) != result.group(2) or int(result.group(2)) != len(MUTANTS):
        problems.append("the record does not show every mutant caught")
    if problems:
        sys.exit("watch mutation record: " + "; ".join(problems) + "; rerun with --record")
    print("watch mutation record: %s of %s mutants caught, current" % (result.group(1), result.group(2)))


def copy_tree(dest):
    files = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.split(b"\0")
    for rel in filter(None, files):
        rel = rel.decode()
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            continue
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(src, "rb") as a, open(out, "wb") as b:
            b.write(a.read())


def run_tests(tree, target_dir, e2e):
    """Runs the watcher's tests in `tree`: the library tests, and the end-to-end target too for a
    mutant in a file only it exercises. Returns (failed test names, output); `None` for the first
    if the tree does not compile."""
    env = dict(os.environ, CARGO_TARGET_DIR=target_dir)
    cmd = ["cargo", "test", "--locked", "--offline", "--no-fail-fast", "-p", "impulse-watch", "--lib"]
    if e2e:
        cmd += ["--test", "e2e"]
    cmd += ["--"]
    for name in SKIPPED:
        cmd += ["--skip", name]
    try:
        out = subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True, timeout=TEST_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        text = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return ["<timed out after %d seconds>" % TEST_TIMEOUT], text
    text = out.stdout + out.stderr
    if "error[" in text or "could not compile" in text:
        return None, text
    failed = sorted(re.findall(r"^test (\S+) \.\.\. FAILED$", out.stdout, re.M))
    if out.returncode != 0 and not failed:
        return None, text
    return failed, text


def clone_target(index):
    """The cargo target directory of worker `index`: worker 0 uses the shared one, the others a
    copy of it (copy-on-write where the file system has it), so every worker starts warm."""
    if index == 0:
        return TARGET_DIR
    path = "%s-%d" % (TARGET_DIR, index)
    if not os.path.isdir(path) and os.path.isdir(TARGET_DIR):
        flags = ["-cR"] if sys.platform == "darwin" else ["-R", "--reflink=auto"]
        subprocess.run(["cp"] + flags + [TARGET_DIR, path], check=True)
    return path


def run_mutant(slot, mutant):
    mid, name, what, old, new = mutant[:5]
    count = mutant[5] if len(mutant) > 5 else 1
    path = os.path.join(slot["tree"], SRC, name)
    with open(path) as f:
        original = f.read()
    with open(path, "w") as f:
        f.write(original.replace(old, new, count))
    try:
        failed, text = run_tests(slot["tree"], slot["target"], name in E2E_FILES)
    finally:
        with open(path, "w") as f:
            f.write(original)
    if failed is None:
        sys.exit("[%s] mutant does not compile; fix the mutant:\n%s" % (mid, text[-3000:]))
    lines = ["[%s] %s: %s" % (mid, name, what)]
    if failed:
        lines.append("  caught by (%d): %s" % (len(failed), ", ".join(failed)))
    else:
        lines.append("  SURVIVED")
    return bool(failed), lines


def option(name, default):
    for arg in sys.argv[1:]:
        if arg.startswith(name + "="):
            return arg[len(name) + 1:]
    return default


def main():
    if "--check" in sys.argv[1:]:
        return check()
    record = "--record" in sys.argv[1:]
    jobs = int(option("--jobs", "1"))
    only = option("--only", "")
    mutants = MUTANTS
    if only:
        if record:
            sys.exit("--only runs part of the list; it cannot be recorded")
        wanted = only.split(",")
        mutants = [m for m in MUTANTS if m[0] in wanted]
    for mutant in MUTANTS:
        mid, name, _, old = mutant[:4]
        count = mutant[5] if len(mutant) > 5 else 1
        with open(os.path.join(ROOT, SRC, name)) as f:
            n = f.read().count(old)
        if n != count:
            sys.exit("[%s] pattern occurs %d times in %s; it must occur %d" % (mid, n, name, count))
    if len({m[0] for m in MUTANTS}) != len(MUTANTS):
        sys.exit("duplicate mutant ids")

    report = [
        "Mutation run, crates/impulse-watch/src (scripts/watch-mutation.py)",
        "source sha256 %s" % source_digest(),
        "script sha256 %s" % script_digest(),
        "mutants %d, test target impulse-watch --lib (and --test e2e for %s)" % (len(MUTANTS), ", ".join(sorted(E2E_FILES))),
        "skipped in every run (too slow to repeat for each mutant): %s" % ", ".join(SKIPPED),
        "",
    ]
    slots = []
    for index in range(jobs):
        tree = tempfile.mkdtemp(prefix="watch-mutation-")
        copy_tree(tree)
        slots.append({"tree": tree, "target": clone_target(index)})
    try:
        baseline = dict(slots[0])
        failed, text = run_tests(baseline["tree"], baseline["target"], True)
        if failed is None or failed:
            sys.exit("baseline is not green:\n%s" % text[-4000:])
        report += ["baseline: all tests pass", ""]
        print("\n".join(report), flush=True)

        free = queue.Queue()
        for slot in slots:
            free.put(slot)

        def work(mutant):
            slot = free.get()
            try:
                return run_mutant(slot, mutant)
            finally:
                free.put(slot)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(work, m) for m in mutants]
            for future in futures:
                ok, lines = future.result()
                results.append((ok, lines))
                print("\n".join(lines), flush=True)
    finally:
        for slot in slots:
            shutil.rmtree(slot["tree"], ignore_errors=True)
    caught = sum(1 for ok, _ in results if ok)
    for _, lines in results:
        report += lines
    result = "result: %d of %d mutants caught" % (caught, len(mutants))
    report += ["", result]
    print("\n" + result)
    if record:
        with open(RECORD, "w") as f:
            f.write("\n".join(report) + "\n")
        print("wrote %s" % RECORD)
    if caught != len(mutants):
        sys.exit(1)


if __name__ == "__main__":
    main()
