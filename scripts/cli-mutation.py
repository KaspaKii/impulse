#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for crates/impulse-cli (I7 phase 2, review rounds 1 and 2).

Each mutant below is one hand-written fault in the CLI's source: a check removed or weakened,
an order reversed, an argument ignored, a printed fact changed. For each one, this script writes
the mutant into a scratch copy of the repository (the working tree is never touched), runs
`cargo test -p impulse-cli --lib` there, and records which tests fail. A mutant no test catches
is a survivor. Every pattern must occur exactly once in its file, so a mutant can never silently
stop applying.

The list holds the mutants review round 1 of phase 2 reported as surviving (their review IDs:
FU, BC, TV, IC, ND, DC, SM, TR) and a mutant of each check that round added (AG, RL, FN, DP,
WM, TP, OF, CP, PC, AD); from review round 2 of phase 2, the two it reported as surviving (TW1,
Z1) and a mutant of each check that round added (FE, PF); from the integration follow-up of
2026-10-11, a mutant of each check it added (SX for submit --signed-tx-out, CN for the Direct
cancellation); from review round 1 of that follow-up, one mutant per clause of each condition
it named (the whole-condition CN18 split into CN18a to CN18c) and a mutant of each check that
round added (CN25 to CN44, SX04 to SX07, RW1); from the TN10 token helper of 2026-10-11, a
mutant of each check it added (TG01 to TG43; Z1 and CN37 follow the reshaped --carrier
condition); from review round 1 of the token helper, one mutant per mark of the genesis terms,
the reviewed defect, and one per line, field and branch the round pinned (TG44 to TG64; TG23
follows the reshaped predicate); from the I16 CLI step, a mutant of each check `impulse v2` added (VC01 to VC20); from the I18 CLI step (`impulse xchain`, spec/V2.md section
10.9), a mutant of each check it added (XC01 to XC40; XC41 to XC46 from I18 review round 4);
from the I17 CLI step, a mutant of each check the tranche and the version 2 receipt added (PT01 to
PT05, RV01 to RV17).
It is not every possible fault.
Mutants the review reported that are equivalent (no input can tell them apart) are not listed.

    python3 scripts/cli-mutation.py            run and print
    python3 scripts/cli-mutation.py --record   also write crates/impulse-cli/mutation-run.txt
    python3 scripts/cli-mutation.py --check    check the record against the current source and
                                               this script (scripts/ci-local.sh runs this)
    python3 scripts/cli-mutation.py --only=LG01,LG02   run only these mutants (never recorded)
    python3 scripts/cli-mutation.py --jobs N   (or --jobs=N) run N mutants at a time, each in its own copy of
                                               the repository and of the cargo target directory
                                               (I16; the port of scripts/watch-mutation.py's)

The record names the sha256 of the CLI's source files and of this script; --check fails unless
both match and every mutant was caught. Any change to crates/impulse-cli/src needs a new run
with --record.
"""

import concurrent.futures
import hashlib
import os
import queue
import shutil
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRATE = os.path.join("crates", "impulse-cli")
SRC = os.path.join(CRATE, "src")
RECORD = os.path.join(ROOT, CRATE, "mutation-run.txt")
TARGET_DIR = os.path.join(ROOT, "target", "cli-mutation")

# (id, file in src/, what the fault does, pattern, replacement)
MUTANTS = [
    # What the builders take from the user and the node (funds.rs).
    ("FU02", "funds.rs", "a UTXO a trade input spends is also a fee candidate",
     ".filter(|u| !exclude.contains(&u.outpoint))", ".filter(|_| true)"),
    ("FU03", "funds.rs", "a UTXO under another scriptPublicKey is used",
     "&u.entry.script_public_key == spk\n", "true\n"),
    ("FU04", "funds.rs", "a UTXO with another covenant ID is used",
     "                && u.entry.covenant_id.map(|c| c.as_bytes()) == covenant\n", ""),
    ("FU05", "funds.rs", "the highest outpoint first, not the lowest",
     "found.sort_by_key(|u| (u.outpoint.transaction_id.as_bytes(), u.outpoint.index));",
     "found.sort_by_key(|u| std::cmp::Reverse((u.outpoint.transaction_id.as_bytes(), u.outpoint.index)));"),
    ("FU06", "funds.rs", "change below the minimum does not take one more fee input",
     "Err(e @ (TxError::InsufficientFunds { .. } | TxError::BelowMinKas { .. })) => {",
     "Err(e @ TxError::InsufficientFunds { .. }) => {"),
    ("FU08", "funds.rs", "an ECDSA --pay-from accepted",
     "if address.version != Version::PubKey {", "if address.version == Version::ScriptHash {"),
    ("FU10", "funds.rs", "an outpoint index beyond u32 truncated",
     ".and_then(|i| u32::try_from(i).ok())", ".map(|i| i as u32)"),
    # The builders (build_cmd.rs).
    ("BC06", "build_cmd.rs", "the asset authorizer with the least KAS, not the most",
     "all.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));",
     "all.sort_by(|a, b| a.entry.amount.cmp(&b.entry.amount));"),
    ("BC08", "build_cmd.rs", "--token-minter not refused on a KAS leg",
     "if a.without_token || a.token_amount.is_some() || a.token_minter {",
     "if a.without_token || a.token_amount.is_some() {"),
    ("BC09", "build_cmd.rs", "refund --token-amount ignored",
     "let amount = a.token_amount.unwrap_or(leg_terms.amount);", "let amount = leg_terms.amount;"),
    ("BC10a", "build_cmd.rs", "--token-minter dropped from the escrow lookup",
     "                amount,\n                is_minter: a.token_minter,\n            };",
     "                amount,\n                is_minter: false,\n            };"),
    ("BC10b", "build_cmd.rs", "--token-minter dropped from the refunded escrow",
     "                amount,\n                is_minter: a.token_minter,\n                template,",
     "                amount,\n                is_minter: false,\n                template,"),
    ("BC11", "build_cmd.rs", "fund --carrier ignored",
     "carrier: a.carrier.unwrap_or(MIN_KCC20_OUTPUT),", "carrier: MIN_KCC20_OUTPUT,"),
    ("BC12", "build_cmd.rs", "fund --authorizer ignored",
     "authorizer: a.authorizer.unwrap_or(MIN_KAS_OUTPUT),", "authorizer: MIN_KAS_OUTPUT,"),
    ("BC13", "build_cmd.rs", "only the first --token used",
     "for text in &a.token {", "for text in a.token.iter().take(1) {"),
    ("BC15", "build_cmd.rs", "--authorizer not refused on a KAS leg",
     "if !a.token.is_empty() || a.carrier.is_some() || a.authorizer.is_some() {",
     "if !a.token.is_empty() || a.carrier.is_some() {"),
    ("BC18", "build_cmd.rs", "a Direct trade's cash UTXO is also a fee candidate",
     "let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;\n            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {\n                direct(",
     "let candidates = fee_candidates(node.as_ref(), &pay.from, net, &[])?;\n            let _ = &used;\n            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {\n                direct("),
    ("BC19", "build_cmd.rs", "settle and refund build take terms of another network",
     "    if terms.terms().network != ctx.network {\n        return Err(CliError::new(\n            \"CLI_NETWORK_MISMATCH\",\n            format!(\n                \"the terms are for {}; pass --network {0} to act on them\",",
     "    if false {\n        return Err(CliError::new(\n            \"CLI_NETWORK_MISMATCH\",\n            format!(\n                \"the terms are for {}; pass --network {0} to act on them\","),
    # The transaction lines (txview.rs).
    ("TV02", "txview.rs", "a KCC-20 funding's trade inputs miscounted",
     "            .take_while(|e| e.covenant_id.is_some())\n            .count(),\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,",
     "            .take_while(|e| e.covenant_id.is_some())\n            .count() + 10,\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,"),
    ("TV03a", "txview.rs", "a settle with KCC-20 cash: trade inputs miscounted",
     "            .count(),\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,\n            LegKind::Kcc20(_) => 4,",
     "            .count(),\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,\n            LegKind::Kcc20(_) => 14,"),
    ("TV03b", "txview.rs", "a settle with external cash: trade inputs miscounted",
     "            .count(),\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,\n            LegKind::Kcc20(_) => 4,\n            LegKind::External => 2,",
     "            .count(),\n        IpstKind::Settle => match t.cash_leg.kind {\n            LegKind::Kas => 3,\n            LegKind::Kcc20(_) => 4,\n            LegKind::External => 12,"),
    ("TV03c", "txview.rs", "a refund: trade inputs miscounted",
     "        IpstKind::Refund { with_token, .. } => 1 + usize::from(with_token),\n        IpstKind::Direct => 2,\n    }\n}\n\n/// How many outputs",
     "        IpstKind::Refund { with_token, .. } => 11 + usize::from(with_token),\n        IpstKind::Direct => 2,\n    }\n}\n\n/// How many outputs"),
    ("TV03d", "txview.rs", "a Direct transaction: trade inputs miscounted",
     "        IpstKind::Direct => 2,\n    }\n}\n\n/// How many outputs",
     "        IpstKind::Direct => 12,\n    }\n}\n\n/// How many outputs"),
    ("TV04", "txview.rs", "the lock time hint one DAA score early",
     "tx.lock_time.saturating_add(1)", "tx.lock_time"),
    ("TV05", "txview.rs", "the change line names the output after the change",
     "let n = trade_outputs(kind, ipst);", "let n = trade_outputs(kind, ipst) + 1;"),
    ("TV06", "txview.rs", "pending names a signer once per slot",
     "        signers.dedup();\n", ""),
    ("PC1", "txview.rs", "the payer cost beyond the fee shown as 0",
     "paid.saturating_sub(held)", "{ let _ = (paid, held); 0 }"),
    # ipst sign (ipst_cmd.rs).
    ("IC05", "ipst_cmd.rs", "the default fee limit ten times the minimum relay fee, not twice",
     "min_relay_fee(ipst.masses().fee_mass).saturating_mul(2),",
     "min_relay_fee(ipst.masses().fee_mass).saturating_mul(10),"),
    ("IC06", "ipst_cmd.rs", "the payer's change not checked",
     "if change.script_public_key != expected_change {", "if false {"),
    ("AG1", "ipst_cmd.rs", "an IPST for other terms than the agreed ones signed",
     "if agreed != *terms_hash {", "if false {"),
    ("RL1", "ipst_cmd.rs", "a party's own destinations not checked",
     "return summary::check_party(t, &party);",
     "let _ = party;\n        return Ok(String::new());"),
    ("RL2", "ipst_cmd.rs", "any key signs as the authority",
     "SignRole::Authority if t.authority_key == Some(my_key) => Ok(",
     "SignRole::Authority if true => Ok("),
    ("RL3", "ipst_cmd.rs", "a party's key signs as a payer",
     "match named.iter().find(|(_, k)| *k == Some(my_key)) {",
     "match named.iter().find(|_| false) {"),
    ("RL4", "ipst_cmd.rs", "pins accepted for the authority and a payer",
     "if a.my_delivery.is_some() || a.my_proceeds.is_some() || a.my_refund.is_some() {",
     "if false {"),
    ("FN1", "ipst_cmd.rs", "a funding signed by a key that is not its depositor",
     "if !role_matches {", "if false {"),
    ("FN2", "ipst_cmd.rs", "a funding signed without the creation checks",
     "    FundableTrade::new(\n        ipst.terms().clone(),\n        &CreationContext::new(ctx.network, daa),\n    )?;\n",
     "    let _ = FundableTrade::new;\n    let _ = CreationContext::new;\n"),
    ("DP1", "ipst_cmd.rs", "a KCC-20 deposit's carrier not confirmed",
     "if outputs[0].value != carrier || outputs[1].value != authorizer {",
     "if outputs[1].value != authorizer {"),
    ("DP2", "ipst_cmd.rs", "a KCC-20 deposit's authorizer not confirmed",
     "if outputs[0].value != carrier || outputs[1].value != authorizer {",
     "if outputs[0].value != carrier {"),
    ("WM1", "ipst_cmd.rs", "--authorizer taken outside a KCC-20 funding",
     "if a.authorizer.is_some() && !matches!(kind, Kind::Built(IpstKind::FundKcc20(_)))",
     "if false && a.authorizer.is_some() && !matches!(kind, Kind::Built(IpstKind::FundKcc20(_)))"),
    ("TP1", "ipst_cmd.rs", "the top-up not bounded",
     "if !is_funding(kind) && topup > max_topup {", "if false {"),
    ("TP2", "ipst_cmd.rs", "the default top-up limit unbounded",
     "let max_topup = a.max_topup.unwrap_or(0);", "let max_topup = a.max_topup.unwrap_or(u64::MAX);"),
    ("OF1", "ipst_cmd.rs", "the signer's outflow not bounded",
     "if outflow > limit {", "if false {"),
    ("OF2", "ipst_cmd.rs", "change to any address counts as coming back to the signer",
     ".filter(|o| o.script_public_key == *expected_change)", ".filter(|_| true)"),
    ("OF3", "ipst_cmd.rs", "vault inputs counted as the signer's own funds",
     "Kind::Built(IpstKind::Settle | IpstKind::Refund { .. }) => n_in,",
     "Kind::Built(IpstKind::Settle | IpstKind::Refund { .. }) => 0,"),
    ("OF4", "ipst_cmd.rs", "a Direct token's carrier allowance a hundred times --carrier",
     "                _ => carrier,", "                _ => carrier.saturating_mul(100),"),
    ("OF5", "ipst_cmd.rs", "a funding's token change not counted as coming back",
     "back = back.saturating_add(outputs[2].value);", "back = back.saturating_add(0);"),
    ("OF6", "ipst_cmd.rs", "a signer of no fee input allowed the fee limit too",
     "        } else {\n            expected\n        };",
     "        } else {\n            expected.saturating_add(max_fee)\n        };"),
    ("CP1", "ipst_cmd.rs", "the outflow not held to the value cap",
     "if outflow > cap {", "if false {"),
    ("Z1", "ipst_cmd.rs", "--carrier taken outside a KCC-20 funding or a Direct transaction",
     "|| a.carrier.is_some()\n            && !matches!(\n                kind,\n                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct) | Kind::Genesis\n            )",
     "|| false"),
    ("FE1", "ipst_cmd.rs", "the default fee limit covers any number of the signer's fee inputs",
     "if a.max_fee.is_none() && my_fee_inputs > DEFAULT_FEE_LIMIT_INPUTS {", "if false {"),
    ("FE2", "ipst_cmd.rs", "the default fee limit covers four fee inputs",
     "const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;", "const DEFAULT_FEE_LIMIT_INPUTS: usize = 4;"),
    ("FE3", "ipst_cmd.rs", "the default fee limit covers two fee inputs",
     "const DEFAULT_FEE_LIMIT_INPUTS: usize = 3;", "const DEFAULT_FEE_LIMIT_INPUTS: usize = 2;"),
    ("FE4", "ipst_cmd.rs", "--max-fee does not lift the fee input bound",
     "if a.max_fee.is_none() && my_fee_inputs > DEFAULT_FEE_LIMIT_INPUTS {",
     "if my_fee_inputs > DEFAULT_FEE_LIMIT_INPUTS {"),
    ("FE5", "ipst_cmd.rs", "every fee input counted, not only the signer's",
     "let my_fee_inputs = (first_fee_input..ipst.slots().len())\n        .filter(|&i| ipst.slots()[i].signer() == Some(my_key))",
     "let my_fee_inputs = (first_fee_input..ipst.slots().len())\n        .filter(|_| true)"),
    # fund build (build_cmd.rs).
    ("PF1", "build_cmd.rs", "fund build pays from an address that is not --my-key's",
     "if pay.from != mine {", "if false {"),
    # address and verify (cli.rs).
    ("AD1", "cli.rs", "address gives funding instructions for an unpinned template",
     "    check_pinned(trade.terms().terms())?;\n    let mut lines = reviewed(&trade, &creation, &a.party)?;\n    lines.push(cap(ctx, &a.cap, trade.terms())?);\n    for leg in LegIndex::ALL {",
     "    let mut lines = reviewed(&trade, &creation, &a.party)?;\n    lines.push(cap(ctx, &a.cap, trade.terms())?);\n    for leg in LegIndex::ALL {"),
    ("TW1", "cli.rs", "terms new prints no warning for an unpinned template",
     "    lines.extend(template_warnings(t.terms()));\n", ""),
    ("AD2", "cli.rs", "verify gives its ok for an unpinned template",
     "    check_pinned(trade.terms().terms())?;\n    let leg = uri::verify(&a.uri, &trade)?;",
     "    let leg = uri::verify(&a.uri, &trade)?;"),
    # The acceptance walk (node.rs).
    ("ND01", "node.rs", "an acceptance in a block the v2 answer does not add",
     "            if !update.added.contains(&block) {\n                return Err(rpc(\n                    \"get_virtual_chain_from_block_v2\",",
     "            if false {\n                return Err(rpc(\n                    \"get_virtual_chain_from_block_v2\","),
    # Operations (I14): redaction, the submit refusal, the call timeout (node.rs).
    ("ND02", "node.rs", "a mainnet transport refusal echoes the node URL's credential (I14)",
     "            redact_url(url)\n        ),", "            url\n        ),"),
    ("ND03", "node.rs", "a refused submission names the wrong block to walk from (I14)",
     "                hex(&from_block)\n", "                hex(&own)\n"),
    ("ND04", "node.rs", "a node call waits a thousand times the timeout (I14)",
     "tokio::time::timeout(timeout, call)", "tokio::time::timeout(timeout * 1000, call)"),
    ("ND05", "node.rs", "the redacted URL keeps the path and query (I14)",
     "    let more = if tail.is_empty() { \"\" } else { \"/...\" };", "    let more = tail;"),
    # decode (decode_cmd.rs).
    ("DC01", "decode_cmd.rs", "the accepting block's DAA score printed as 0",
     "let block_daa = node.block(block)?.daa_score;", "let block_daa = 0u64;"),
    ("DC02", "decode_cmd.rs", "refused vault inputs never printed",
     "lines.push(format!(\"refused: {}\", CliError::from(e.clone())));", "let _ = e;"),
    ("DC03", "decode_cmd.rs", "the seller named as the buyer",
     "Some(Party::Seller) => \"the seller\",", "Some(Party::Seller) => \"the buyer\","),
    ("DC04", "decode_cmd.rs", "the buyer named as the seller",
     "Some(Party::Buyer) => \"the buyer\",", "Some(Party::Buyer) => \"the seller\","),
    ("DC05", "decode_cmd.rs", "the authority named as the seller",
     "Some(Party::Authority) => \"the authority\",", "Some(Party::Authority) => \"the seller\","),
    ("DC07", "decode_cmd.rs", "a delivery printed to the buyer's delivery whatever the leg",
     "format!(\"delivers exactly {amount} to {}\", describe(t, &to))",
     "format!(\"delivers exactly {amount} to {}\", describe(t, &t.buyer_delivery))"),
    ("DC08", "decode_cmd.rs", "a refund printed to the seller's refund whatever the leg",
     "goes to {}\",\n                    describe(t, &to)",
     "goes to {}\",\n                    describe(t, &t.seller_refund)"),
    # The offline fake node (sim.rs).
    ("SM01", "sim.rs", "outputs above the inputs accepted",
     "if paid > held {", "if false && paid > held {"),
    ("SM02", "sim.rs", "an outpoint spent twice in one transaction not refused",
     ".any(|o| o.previous_outpoint == input.previous_outpoint)", ".any(|_| false)"),
    # Before funding (trade.rs).
    ("TR02", "trade.rs", "an unpinned KCC-20 cash leg not flagged",
     "        (LegIndex::Cash, &t.cash_leg),\n", ""),
    # Integration follow-up (2026-10-11): submit --signed-tx-out (ipst_cmd.rs).
    ("SX01", "ipst_cmd.rs", "a taken --signed-tx-out path overwritten, not refused before submitting",
     "            .create_new(true)\n", "            .create(true)\n            .truncate(true)\n"),
    ("SX02", "ipst_cmd.rs", "the signed-transaction file never written",
     "        f.write(&signed_tx_text(&tx))?;", "        let _ = &f;"),
    ("SX03", "ipst_cmd.rs", "the signed-transaction file without its line feed",
     "format!(\"{}\\n\", hex(&impulse_core::decode::encode_raw(tx)))",
     "format!(\"{}\", hex(&impulse_core::decode::encode_raw(tx)))"),
    # The Direct cancellation: direct cancel build (cancel.rs).
    ("CN01", "cancel.rs", "vault terms not refused",
     "    if t.settlement_mode != SettlementMode::Direct {", "    if false {"),
    ("CN02", "cancel.rs", "--my-key not checked against the role's key",
     "    if party != my_key {", "    if false {"),
    ("CN03", "cancel.rs", "a token Direct input not refused",
     "    if a.role != Role::Buyer || leg.kind != LegKind::Kas {", "    if false {"),
    ("CN04", "cancel.rs", "the value cap not applied",
     "    let cap_line = cap(ctx, &a.cap, terms)?;", "    let cap_line = String::new();"),
    ("CN05", "cancel.rs", "--direct-input of another amount accepted",
     "            if utxo.entry.amount != leg.amount {", "            if false {"),
    ("CN06", "cancel.rs", "the default Direct input not of the cash amount",
     "                .filter(|u| u.entry.amount == leg.amount)", "                .filter(|_| true)"),
    ("CN07", "cancel.rs", "the Direct input also taken as a fee input",
     "        .filter(|u| u.outpoint != input.outpoint)", "        .filter(|_| true)"),
    ("CN08", "cancel.rs", "no fee input not refused by the builder",
     "    if fee.inputs.is_empty() {\n        return Err(TxError::KasInput {",
     "    if false {\n        return Err(TxError::KasInput {"),
    ("CN09", "cancel.rs", "a fee input of another key accepted",
     "if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)",
     "if utxo.entry.covenant_id.is_some()"),
    ("CN10", "cancel.rs", "an outpoint spent twice accepted",
     "        if !seen.insert(utxo.outpoint) {", "        if !seen.insert(utxo.outpoint) && false {"),
    ("CN11", "cancel.rs", "a non-standard change script accepted",
     "    if !standard_change(&fee.change) {", "    if false {"),
    ("CN12", "cancel.rs", "too little to pay the fee not refused",
     "    if available < needed {\n        return Err(TxError::InsufficientFunds",
     "    if false {\n        return Err(TxError::InsufficientFunds"),
    ("CN13", "cancel.rs", "change below its minimum accepted",
     "        if change.value < minimum {", "        if false {"),
    ("CN14", "cancel.rs", "a fee below the minimum relay fee accepted",
     "    if fee.fee < minimum {\n        return Err(TxError::FeeTooLow {",
     "    if false {\n        return Err(TxError::FeeTooLow {"),
    ("CN15", "cancel.rs", "no lock time at the expiry",
     "        terms.terms().expiry_daa,\n", "        0,\n"),
    ("CN16", "cancel.rs", "a final sequence, so the lock time does not hold",
     "                    INPUT_SEQUENCE,\n", "                    u64::MAX,\n"),
    ("CN17", "cancel.rs", "the Direct input not sent home whole",
     "    let mut outputs = vec![TransactionOutput::new(\n        input.entry.amount,",
     "    let mut outputs = vec![TransactionOutput::new(\n        input.entry.amount - 1,"),
    ("CN18a", "cancel.rs", "the check takes a KAS input 0 under KCC-20 cash terms",
     "    if t.cash_leg.kind != LegKind::Kas\n        || entry.script_public_key",
     "    if false\n        || entry.script_public_key"),
    ("CN18b", "cancel.rs", "the check takes an input 0 under any key",
     "        || entry.script_public_key != buyer_cash\n", "        || false\n"),
    ("CN18c", "cancel.rs", "the check takes an input 0 of any amount",
     "        || entry.amount != t.cash_leg.amount\n    {", "        || false\n    {"),
    ("CN19", "cancel.rs", "the check does not compare the rebuilt document",
     "    if unsigned(&rebuilt) != unsigned(ipst) {", "    if false {"),
    ("CN20", "cancel.rs", "no document is taken as a cancellation",
     "    ipst.terms().terms().settlement_mode == SettlementMode::Direct\n        && ipst",
     "    false\n        && ipst"),
    # Review round 1 of the integration follow-up: the cancellation's builder rules, clause by
    # clause (cancel.rs).
    ("CN25", "cancel.rs", "an input 0 with a covenant ID taken as a cancellation",
     ".is_some_and(|e| e.covenant_id.is_none() && p2pk_key(&e.script_public_key).is_some())",
     ".is_some_and(|e| p2pk_key(&e.script_public_key).is_some())"),
    ("CN26", "cancel.rs", "a Direct input with a covenant ID built",
     "        Some(k) if input.entry.covenant_id.is_none() => k,", "        Some(k) => k,"),
    ("CN27", "cancel.rs", "a fee input with a covenant ID built",
     "if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)",
     "if p2pk_key(&utxo.entry.script_public_key) != Some(key)"),
    ("CN28", "cancel.rs", "a UTXO of zero sompi built",
     "        if value == 0 || value > MAX_SOMPI {", "        if value > MAX_SOMPI {"),
    ("CN29", "cancel.rs", "a UTXO above the supply not refused at its own index",
     "        if value == 0 || value > MAX_SOMPI {", "        if value == 0 {"),
    ("CN30", "cancel.rs", "UTXOs above the supply together built",
     "        if available > MAX_SOMPI {", "        if false {"),
    ("CN31", "cancel.rs", "a mass above the standard cap built",
     "        if mass > STANDARD_MASS_CAP {", "        if false {"),
    ("CN32", "cancel.rs", "a P2PK script of any version taken",
     "        (0, [0x20, key @ .., 0xac]) if key.len() == 32 => key.try_into().ok(),",
     "        (_, [0x20, key @ .., 0xac]) if key.len() == 32 => key.try_into().ok(),"),
    ("CN33", "cancel.rs", "a P2SH change refused",
     "            [0xaa, 0x20, hash @ .., 0x87] => hash.len() == 32,",
     "            [0xaa, 0x20, _hash @ .., 0x87] => false,"),
    ("CN34", "cancel.rs", "a P2PK-ECDSA change refused",
     "            [0x21, key @ .., 0xab] => key.len() == 33,", "            [0x21, _key @ .., 0xab] => false,"),
    ("CN35", "cancel.rs", "a change script of any version taken",
     "    spk.version() == 0\n        && match s {", "    true\n        && match s {"),
    ("CN36", "cancel.rs", "fee inputs smallest first",
     "    candidates.sort_by(|x, y| y.entry.amount.cmp(&x.entry.amount));",
     "    candidates.sort_by(|x, y| x.entry.amount.cmp(&y.entry.amount));"),
    ("CN37", "ipst_cmd.rs", "--carrier taken on a cancellation",
     "                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct) | Kind::Genesis\n",
     "                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct) | Kind::Genesis | Kind::Cancel(_)\n"),
    # The named Direct transaction and the ambiguous Direct input (cancel.rs).
    ("CN38", "cancel.rs", "the first of several exact UTXOs taken, as before the review",
     "            match exact.len() {", "            match exact.len().min(1) {"),
    ("CN39", "cancel.rs", "--for-ipst's input 0 taken, not its input 1",
     "    Ok((tx.id().as_bytes(), tx.inputs[1].previous_outpoint))",
     "    Ok((tx.id().as_bytes(), tx.inputs[0].previous_outpoint))"),
    ("CN40", "cancel.rs", "--for-ipst of other terms taken",
     "    if doc.terms().terms_hash() != terms.terms_hash() {", "    if false {"),
    ("CN41", "cancel.rs", "--for-ipst that is a cancellation taken",
     "    if is_candidate(&doc) {", "    if false {"),
    ("CN42", "cancel.rs", "--for-ipst whose input 1 is not the buyer's exact cash taken",
     "    if !is_cash {", "    if false {"),
    ("CN43", "cancel.rs", "--direct-input beside --for-ipst naming another UTXO taken",
     "        if of_ipst != named {", "        if false {"),
    ("CN44", "cancel.rs", "the cancels: line does not name the Direct transaction's input",
     "            \"cancels: Direct transaction {}, its input 1 {}\",",
     "            \"cancels: Direct transaction {}, input {}\","),
    # submit --signed-tx-out and ipst raw (ipst_cmd.rs).
    ("SX04", "ipst_cmd.rs", "a refused submission keeps its signed-transaction file",
     "        if !self.keep {", "        if false {"),
    ("SX05", "ipst_cmd.rs", "a submission the node took removes its signed-transaction file",
     "        f.keep = true;", "        f.keep = false;"),
    ("SX06", "ipst_cmd.rs", "a refused submission does not say how to write the file",
     "    let submitted = node::submit(node.as_ref(), &tx, ctx.network).map_err(|e| match &file {",
     "    let submitted = node::submit(node.as_ref(), &tx, ctx.network).map_err(|e| match &None::<SignedTxFile> {"),
    ("SX07", "ipst_cmd.rs", "a failed write of the signed-transaction file ignored",
     "        file.write_all(text.as_bytes()).map_err(fail)?;",
     "        let _ = file.write_all(text.as_bytes());"),
    ("RW1", "ipst_cmd.rs", "ipst raw writes an IPST that is not fully signed",
     "    let ipst = read_ipst(ctx, &a.ipst)?;\n    let tx = ipst.finalize()?;\n    write_new(&a.out",
     "    let ipst = read_ipst(ctx, &a.ipst)?;\n    let tx = ipst.transaction().clone();\n    write_new(&a.out"),
    # The cancellation in ipst sign, merge and submit (ipst_cmd.rs) and its lines (txview.rs).
    ("CN21", "ipst_cmd.rs", "the core terms check, not the cancellation check, for a cancellation",
     "    if crate::cancel::is_candidate(ipst) {", "    if false {"),
    ("CN22", "ipst_cmd.rs", "a cancellation's output 0 not counted as coming back to its signer",
     "                back = back.saturating_add(outputs[0].value);", "                let _ = back;"),
    ("CN23", "txview.rs", "a cancellation's fee inputs counted from input 2",
     "        Kind::Cancel(_) => return 1,\n    };\n    match kind {\n        IpstKind::FundKas => 0,",
     "        Kind::Cancel(_) => return 2,\n    };\n    match kind {\n        IpstKind::FundKas => 0,"),
    ("CN24", "txview.rs", "a cancellation named as a Direct transaction",
     "        Kind::Cancel(role) => return format!(\"direct cancel by {}\", role.name()),",
     "        Kind::Cancel(_) => return \"direct\".into(),"),
    # The testnet token helper (token.rs; the genesis in ipst_cmd.rs, txview.rs and cancel.rs).
    ("TG01", "token.rs", "token mint build and token list act on mainnet",
     "    if ctx.network == Network::Mainnet {\n        return Err(testnet_only(command));",
     "    if false {\n        return Err(testnet_only(command));"),
    ("TG02", "token.rs", "a mainnet genesis IPST is read",
     "if is_genesis(ipst) && ipst.terms().terms().network == Network::Mainnet {", "if false {"),
    ("TG03", "token.rs", "the genesis check takes mainnet terms",
     "    if t.network != Network::Testnet {", "    if false {"),
    ("TG04", "token.rs", "token mint build and token list take an unpinned template",
     "    let line = pinned_line(&template_triple(&template))?;",
     "    let line = pinned_line(&template_triple(&template)).unwrap_or_default();"),
    ("TG05", "token.rs", "the genesis check takes an unpinned template",
     "    pinned_line(&template_triple(template))?;", "    let _ = pinned_line(&template_triple(template));"),
    ("TG06", "token.rs", "an owner that is not an x-only key taken",
     "if secp256k1::XOnlyPublicKey::from_slice(&owner).is_err() {", "if false {"),
    ("TG07", "token.rs", "an amount of 0 taken",
     "if amount == 0 || amount > i64::MAX as u64 {", "if amount > i64::MAX as u64 {"),
    ("TG08", "token.rs", "an amount above i64::MAX taken",
     "if amount == 0 || amount > i64::MAX as u64 {", "if amount == 0 {"),
    ("TG09", "token.rs", "a genesis input of another key built",
     "if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)",
     "if utxo.entry.covenant_id.is_some()"),
    ("TG10", "token.rs", "a genesis input after input 0 with a covenant ID built",
     "if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)",
     "if p2pk_key(&utxo.entry.script_public_key) != Some(key)"),
    ("TG11", "token.rs", "a genesis input 0 with a covenant ID built",
     "        Some(k) if first.entry.covenant_id.is_none() => k,", "        Some(k) => k,"),
    ("TG12", "token.rs", "a genesis input spent twice built",
     "        if !seen.insert(utxo.outpoint) {", "        if !seen.insert(utxo.outpoint) && false {"),
    ("TG13", "token.rs", "a genesis input of 0 sompi not refused at its index",
     "        if value == 0 || value > MAX_SOMPI {", "        if value > MAX_SOMPI {"),
    ("TG14", "token.rs", "a genesis input above the supply not refused at its index",
     "        if value == 0 || value > MAX_SOMPI {", "        if value == 0 {"),
    ("TG15", "token.rs", "genesis inputs above the supply together built",
     "        if available > MAX_SOMPI {", "        if false {"),
    ("TG16", "token.rs", "a non-standard genesis change built",
     "    if !standard_change(&fee.change) {", "    if false {"),
    ("TG17", "token.rs", "a carrier below the minimum built",
     "    if carrier < minimum {", "    if false {"),
    ("TG18", "token.rs", "too little for the carrier and the fee not refused",
     "    if available < needed {", "    if false {"),
    ("TG19", "token.rs", "genesis change below its minimum built",
     "        if change.value < minimum {", "        if false {"),
    ("TG20", "token.rs", "a genesis above the standard mass cap built",
     "        if mass > STANDARD_MASS_CAP {", "        if false {"),
    ("TG21", "token.rs", "a genesis fee below the minimum relay fee built",
     "    if fee.fee < minimum {", "    if false {"),
    ("TG22", "token.rs", "the genesis check does not compare the rebuilt document",
     "    if unsigned(&rebuilt) != unsigned(ipst) {", "    if false {"),
    ("TG23", "token.rs", "no document is taken as a token genesis",
     "    t.trade_ref == GENESIS_TAG\n        && t.seller_key == party_key(\"seller\")\n",
     "    false\n        && t.seller_key == party_key(\"seller\")\n"),
    ("TG24", "token.rs", "the genesis carrier not confirmed against --carrier",
     "    if on_token != expected {", "    if false {"),
    ("TG25", "token.rs", "the token output without its genesis covenant binding",
     "    tx.populate_genesis_covenants(&[GenesisCovenantGroup::new(0, vec![0])])\n        .map_err(",
     "    Ok::<(), String>(())\n        .map_err("),
    ("TG26", "token.rs", "the token held by another key than --owner",
     "    let state = Kcc20State::new(pubkey_owner(owner), amount);",
     "    let state = Kcc20State::new(pubkey_owner(party_key(\"seller\")), amount);"),
    ("TG27", "token.rs", "genesis terms that have not expired",
     "        expiry_daa: 1,\n", "        expiry_daa: 499_999_999_999,\n"),
    ("TG31", "txview.rs", "a genesis input taken as a trade input, not the payer's",
     "        Kind::Genesis => return 0,", "        Kind::Genesis => return 1,"),
    ("TG32", "txview.rs", "the genesis change taken for a trade output",
     "        Kind::Genesis => return 1,\n        Kind::Cancel(_) => return 1,",
     "        Kind::Genesis => return 2,\n        Kind::Cancel(_) => return 1,"),
    ("TG33", "txview.rs", "a genesis named as a Direct transaction",
     "        Kind::Genesis => return \"token genesis\".into(),", "        Kind::Genesis => return \"direct\".into(),"),
    ("TG34", "txview.rs", "the token line names another output",
     "            \"token: {}:0:{}\",", "            \"token: {}:1:{}\","),
    ("TG35", "ipst_cmd.rs", "a mainnet genesis IPST read by every command",
     "    crate::token::refuse_mainnet_genesis(&ipst)?;\n", ""),
    ("TG36", "ipst_cmd.rs", "the terms check, not the genesis check, for a genesis",
     "    if crate::token::is_genesis(ipst) {", "    if false {"),
    ("TG37", "ipst_cmd.rs", "--carrier refused on a genesis",
     "                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct) | Kind::Genesis\n",
     "                Kind::Built(IpstKind::FundKcc20(_) | IpstKind::Direct)\n"),
    ("TG38", "ipst_cmd.rs", "a genesis signed without its carrier confirmed",
     "        crate::token::confirm_carrier(&ipst, a.carrier)?;", "        let _ = &ipst;"),
    ("TG39", "ipst_cmd.rs", "a genesis carrier held to the top-up limit",
     "        Kind::Built(IpstKind::FundKas | IpstKind::FundKcc20(_)) | Kind::Genesis\n",
     "        Kind::Built(IpstKind::FundKas | IpstKind::FundKcc20(_))\n"),
    ("TG40", "ipst_cmd.rs", "a genesis payer allowed a hundred carriers",
     "        Kind::Genesis => return Some((held.saturating_sub(back), carrier)),",
     "        Kind::Genesis => return Some((held.saturating_sub(back), carrier.saturating_mul(100))),"),
    ("TG41", "ipst_cmd.rs", "a genesis held to a trade value",
     "        crate::token::cap_line(&policy)\n", "        policy.check(&t, a.cap.kas_equivalent)?\n"),
    ("TG42", "ipst_cmd.rs", "a genesis signed under a trade's terms summary",
     "        crate::token::summary(ipst.terms())\n",
     "        summary::summary(&ipst.terms().terms_hash(), &t, daa)\n"),
    ("TG43", "cancel.rs", "an output's covenant ID rendered as another",
     "                    \"covenant_id\": hex(&c.covenant_id.as_bytes()),\n",
     "                    \"covenant_id\": hex(&[1u8; 32]),\n"),
    # Review round 1 of the token helper: one mutant per mark of the genesis terms, the
    # reviewed defect itself (the tag alone), and a mutant of each line, field and branch the
    # round pinned.
    ("TG44", "token.rs", "genesis terms without the tag",
     "    t.trade_ref == GENESIS_TAG\n        && ", "    "),
    ("TG45", "token.rs", "genesis terms with any seller_key",
     "        && t.seller_key == party_key(\"seller\")\n", ""),
    ("TG46", "token.rs", "genesis terms with any buyer_key",
     "        && t.buyer_key == party_key(\"buyer\")\n", ""),
    ("TG47", "token.rs", "genesis terms in vault mode",
     "        && t.settlement_mode == SettlementMode::Direct\n", ""),
    ("TG48", "token.rs", "genesis terms with any expiry",
     "        && t.expiry_daa == 1\n", ""),
    ("TG49", "token.rs", "the tag alone makes a token genesis (the reviewed defect)",
     "    is_genesis_terms(ipst.terms().terms())\n",
     "    ipst.terms().terms().trade_ref == GENESIS_TAG\n"),
    ("TG50", "frost.rs", "frost sign and frost aggregate read a mainnet genesis",
     "    crate::token::refuse_mainnet_genesis(&ipst)?;\n", ""),
    ("TG51", "token.rs", "token list without its template line",
     "        format!(\"template: {template_line}\"),\n", ""),
    ("TG52", "token.rs", "token list names mainnet",
     "\"network: testnet\".to_string(),", "\"network: mainnet\".to_string(),"),
    ("TG53", "token.rs", "token list prints the covenant as the owner",
     "        format!(\"owner: {}\", hex(&owner)),\n", "        format!(\"owner: {}\", hex(&covenant)),\n"),
    ("TG54", "token.rs", "the pinned line swaps maxCovIns and maxCovOuts",
     "        pin.max_cov_ins,\n        pin.max_cov_outs\n", "        pin.max_cov_outs,\n        pin.max_cov_ins\n"),
    ("TG55", "token.rs", "the default change of token mint build goes to the owner",
     "        None => address_script(&pay_from),\n",
     "        None => address_script(&p2pk_address(&owner, ctx.network)),\n"),
    ("TG56", "token.rs", "genesis seller_proceeds pay the buyer key",
     "        seller_proceeds: p2pk(&seller),\n", "        seller_proceeds: p2pk(&buyer),\n"),
    ("TG57", "token.rs", "genesis buyer_refund pays the seller key",
     "        buyer_refund: p2pk(&buyer),\n", "        buyer_refund: p2pk(&seller),\n"),
    ("TG58", "token.rs", "genesis seller_refund owned by the buyer key",
     "        seller_refund: Destination::Kcc20(pubkey_owner(seller)),\n",
     "        seller_refund: Destination::Kcc20(pubkey_owner(buyer)),\n"),
    ("TG59", "token.rs", "the carrier and the fee summed with wrap-around",
     "    let needed = carrier\n        .checked_add(fee.fee)\n",
     "    let needed = Some(carrier.wrapping_add(fee.fee))\n"),
    ("TG60", "token.rs", "genesis inputs at sequence 1",
     "                    INPUT_SEQUENCE,\n", "                    1,\n"),
    ("TG61", "token.rs", "the genesis binding authorizes the last input",
     "GenesisCovenantGroup::new(0, vec![0])",
     "GenesisCovenantGroup::new((fee.inputs.len() - 1) as u16, vec![0])"),
    ("TG62", "token.rs", "a token of one unit refused",
     "if amount == 0 || amount > i64::MAX as u64 {", "if amount <= 1 || amount > i64::MAX as u64 {"),
    ("TG63", "token.rs", "a genesis with a lock time",
     "        outputs,\n        0,\n        SUBNETWORK_ID_NATIVE,\n", "        outputs,\n        5,\n        SUBNETWORK_ID_NATIVE,\n"),
    ("TG64", "summary.rs", "the terms summary without trade_ref",
     "        format!(\"trade_ref: {}\", hex(&t.trade_ref)),\n", ""),
    # I16 CLI step: impulse v2 (spec/V2.md 6.5), one mutant per check it added.
    ("VC01", "v2_terms.rs", "a key that deposits no leg passes the party check",
     "    if own.is_empty() {", "    if false && own.is_empty() {"),
    ("VC02", "v2_terms.rs", "a refund to another depositor accepted when pinned",
     "            Some(k) if k != key && t.legs.iter().any(|o| o.depositor_key == k) => refused.push(",
     "            Some(k) if false && k != key && t.legs.iter().any(|o| o.depositor_key == k) => refused.push("),
    ("VC03", "v2_terms.rs", "a refund to the authority accepted when pinned",
     "            Some(k) if Some(k) == t.authority_key => refused.push(format!(",
     "            Some(k) if false && Some(k) == t.authority_key => refused.push(format!("),
    ("VC04", "v2_terms.rs", "terms that deliver nothing to the party accepted",
     "    if delivered.is_empty() {", "    if false && delivered.is_empty() {"),
    ("VC05", "v2_terms.rs", "the v2 trade value is the largest KAS leg, not the KAS legs together",
     ".fold(0u64, |s, l| s.saturating_add(l.asset.amount));", ".fold(0u64, |s, l| s.max(l.asset.amount));"),
    ("VC06", "v2_terms.rs", "a KAS leg at exactly MIN_V2 refused before funding",
     "        if l.asset.kind == LegKind::Kas && t.unit(i) < minimum {",
     "        if l.asset.kind == LegKind::Kas && t.unit(i) <= minimum {"),
    ("VC07", "v2_terms.rs", "a draft of two legs takes the revocable default",
     "        None if legs.len() >= 3 => FundingMode::Revocable,", "        None => FundingMode::Revocable,"),
    ("VC08", "v2_terms.rs", "the default expiry is 12 hours, not D46's 24",
     "            let e = creation_daa.saturating_add(DEFAULT_EXPIRY_IN);",
     "            let e = creation_daa.saturating_add(DEFAULT_EXPIRY_IN / 2);"),
    ("VC09", "v2_terms.rs", "terms v2 of another network acted on",
     "    if network != ctx.network {", "    if false && network != ctx.network {"),
    ("VC10", "v2_cmd.rs", "v2 fund build funds another party's leg",
     "    if !own.contains(&a.leg) {", "    if false && !own.contains(&a.leg) {"),
    ("VC11", "v2_cmd.rs", "a v2 funding paid from another address",
     "    if pay.from != mine {", "    if false && pay.from != mine {"),
    ("VC12", "v2_cmd.rs", "a KAS leg funding takes --carrier",
     "            if !a.token.is_empty() || a.carrier.is_some() || a.authorizer.is_some() {",
     "            if !a.token.is_empty() || a.authorizer.is_some() {"),
    ("VC13", "v2_cmd.rs", "another depositor signs a leg's funding",
     "    if a.role != SignRole::Depositor || depositor != my_key {", "    if a.role != SignRole::Depositor {"),
    ("VC14", "v2_cmd.rs", "the escrowed token's carrier not confirmed",
     "        if outputs[0].value != carrier || outputs[1].value != authorizer {",
     "        if outputs[1].value != authorizer {"),
    ("VC15", "v2_cmd.rs", "a depositor's key signs as a payer",
     "        _ if deposits => Err(CliError::new(", "        _ if false && deposits => Err(CliError::new("),
    ("VC16", "v2_cmd.rs", "a v2 fee input signed with the change going elsewhere",
     "            if change.script_public_key != expected_change {",
     "            if false && change.script_public_key != expected_change {"),
    ("VC17", "v2_cmd.rs", "a v2 fee above --max-fee signed",
     "        if checked.fee > max_fee {", "        if false && checked.fee > max_fee {"),
    ("VC18", "v2_cmd.rs", "v2 ipst sign with nothing to sign writes a copy",
     "    if mine.is_empty() {", "    if false && mine.is_empty() {"),
    ("VC19", "v2_cmd.rs", "a KAS leg refund takes --without-token",
     "            if a.without_token || a.token_amount.is_some() || a.token_minter {",
     "            if a.token_amount.is_some() || a.token_minter {"),
    ("VC20", "v2_cmd.rs", "a leg index equal to the leg count passes the CLI's check",
     "    if leg >= t.legs.len() {", "    if leg > t.legs.len() {"),
    # I18 CLI step: impulse xchain (xchain.rs, xchain_doc.rs, xchain_counterpart.rs).
    ("XC01", "xchain.rs", "the race R2 notice not printed on mainnet",
     "    if ctx.network == Network::Mainnet {\n        writeln!(notes, \"{MAINNET_R2_NOTICE}\")",
     "    if false {\n        writeln!(notes, \"{MAINNET_R2_NOTICE}\")"),
    ("XC02", "xchain.rs", "a network ID without pinned parameters read as 10 blocks per second",
     "        _ => None,\n    }\n}", "        _ => Some(10),\n    }\n}"),
    ("XC03", "xchain.rs", "the node's blocks-per-second not checked",
     "    check_bps(&info, ctx.network)?;\n", ""),
    ("XC04", "xchain_doc.rs", "a known hash lock under other terms accepted",
     "            if t != *terms_hash {", "            if false {"),
    ("XC05", "xchain.rs", "xchain verify does not record the trade",
     "    if !doc::check_known(", "    if false && !doc::check_known("),
    ("XC06", "xchain.rs", "xchain new for a key that is not the seller's",
     "    if draft.seller_key != my_key {", "    if false {"),
    ("XC07", "xchain.rs", "the counterpart account not compared with --my-counterpart-account",
     "    if mine != agreed {", "    if false {"),
    ("XC08", "xchain.rs", "a pin accepts the counterparty's key as the user's own destination",
     "    if *owner == key_owner(other_key) {", "    if false {"),
    ("XC09", "xchain.rs", "a counterpart timeout inside the claim lead accepted at creation",
     "    if now > latest || timeout < dc {", "    if false {"),
    ("XC10", "xchain.rs", "an unpinned KCC-20 template accepted",
     "        if pinned_kcc20(&TemplateTriple::from(&token)).is_none() {", "        if false {"),
    ("XC11", "xchain.rs", "a trade above the value cap accepted",
     "    if value > limit {", "    if false {"),
    ("XC12", "xchain_doc.rs", "a secret file others can read accepted",
     "        if meta.permissions().mode() & 0o077 != 0 {", "        if false {"),
    ("XC13", "xchain_doc.rs", "a short secret file accepted",
     "    if digits.len() != 64\n", "    if digits.len() > 64\n"),
    ("XC14", "xchain_doc.rs", "the secret file written readable by others",
     "        options.mode(0o600);\n    }\n    let mut file = options.open(path).map_err(|e| {",
     "        options.mode(0o644);\n    }\n    let mut file = options.open(path).map_err(|e| {"),
    ("XC15", "xchain.rs", "the seller reveals against a lock that is not counterpart-final (R13)",
     "    counterpart_final(&lock)?;\n    source.claim_check(&lock)?;\n    let mine = source", "    source.claim_check(&lock)?;\n    let mine = source"),
    ("XC16", "xchain_counterpart.rs", "an unfunded counterpart lock accepted",
     "        (\"funded\", lock.funded),\n", ""),
    ("XC17", "xchain.rs", "the first reveal accepted inside the claim lead (R2)",
     "    if now.saturating_add(dc) > timeout {", "    if false {"),
    ("XC18", "xchain.rs", "the counterpart claim reported done before counterpart-final",
     "        Some(c) if c.finality == Finality::Finalized => {", "        Some(c) if c.finality >= Finality::Seen => {"),
    ("XC19", "xchain.rs", "the watch writes the preimage before counterpart-final",
     "    if claim.finality != Finality::Finalized {", "    if false {"),
    ("XC20", "xchain.rs", "a claim with a wrong preimage taken as the reveal",
     "        .filter(|c| check_preimage(terms, &c.preimage).is_ok())", "        .filter(|_| true)"),
    ("XC21", "xchain.rs", "the Kaspa claim built with less than the retry window left",
     "    if left < u128::from(a.retry_secs) {", "    if false {"),
    ("XC22", "xchain.rs", "xchain sign signs for other terms than agreed",
     "    if agreed.terms_hash() != ipst.terms().terms_hash() {", "    if false {"),
    ("XC23", "xchain.rs", "xchain sign accepts change that is not the signer's",
     "        if m.change.is_some() && !change_mine {", "        if false {"),
    ("XC24", "xchain.rs", "xchain sign accepts a fee above --max-fee",
     "        if m.fee > max_fee {", "        if false {"),
    ("XC25", "xchain.rs", "the trade reported complete with the counterpart claim not final",
     "            counterpart_done = c.finality == Finality::Finalized;", "            counterpart_done = true;"),
    ("XC26", "xchain.rs", "the Kaspa transaction reported final at any depth",
     "    let kaspa_final = o.depth >= FINALITY_DEPTH_DAA;", "    let kaspa_final = true;"),
    ("XC27", "xchain_doc.rs", "a sample point with a falling DAA score appended",
     "            if *t >= unix || *d > daa {", "            if *t >= unix {"),
    ("XC28", "xchain_doc.rs", "a DAA sample of another network read",
     "            if *net != network_name(network) {", "            if false {"),
    ("XC29", "xchain_doc.rs", "a terms file's hash not checked",
     " || checked.terms_hash() != hash {", " {"),
    ("XC30", "xchain_doc.rs", "an older document version read as version 3",
     "    if version != HTLC_IPST_VERSION as i64 {", "    if version > HTLC_IPST_VERSION as i64 {"),
    ("XC31", "xchain.rs", "xchain submit ignores the lock time",
     "check_tx_is_finalized(&tx, daa, 0)", "check_tx_is_finalized(&tx, u64::MAX, 0)"),
    ("XC32", "xchain.rs", "the claim lead without its two-hour floor",
     "    final_secs.saturating_mul(10).max(MIN_DELTA_CLAIM_SECS)", "    final_secs.saturating_mul(10)"),
    ("XC33", "xchain.rs", "a refund built without the token by default",
     "    let escrow = if a.without_token {", "    let escrow = if true {"),
    ("XC34", "xchain.rs", "the funding paid from another address than the seller's",
     "    if pay.from != mine {", "    if false {"),
    ("XC35", "xchain.rs", "a funding signed without the margin rule run again",
     "        creation_checks(&agreed, daa, &margin, sample.as_ref(), now_unix())?;\n", ""),
    ("XC36", "xchain.rs", "a funding signed by the buyer",
     "        if my_key != t.seller_key || a.role != SignRole::Seller {", "        if false {"),
    ("XC37", "xchain.rs", "a funding's deposit not compared with --carrier and --authorizer",
     "        if tx.outputs[0].value != carrier || tx.outputs[1].value != authorizer {", "        if false {"),
    ("XC38", "xchain.rs", "xchain verify for a key that is not the buyer's",
     "    if t.buyer_key != my_key {", "    if false {"),
    ("XC39", "xchain.rs", "a source of another chain accepted",
     "    if chain != c.chain || id != c.chain_id {", "    if false {"),
    ("XC40", "xchain.rs", "a destination that differs from its pin accepted",
     "            if p != *owner {", "            if false {"),
    ("XC41", "xchain.rs", "verify-funding accepts a spent escrow or authorizer",
     "    funding_unspent(node.as_ref(), &terms, &template, &f)?;\n", ""),
    ("XC42", "xchain.rs", "verify-funding accepts a funding below final depth",
     "    if w.depth < FINALITY_DEPTH_DAA {", "    if false {"),
    ("XC43", "xchain.rs", "status takes an unrelated transaction for an attempted funding",
     "        .any(|o| o.script_public_key == vault_spk || o.script_public_key == escrow_spk)",
     "        .any(|_| true)"),
    ("XC44", "xchain.rs", "status completes the trade on a transaction that is not the claim",
     "        if role == TradeTx::Claim && kaspa_final && counterpart_done {",
     "        if kaspa_final && counterpart_done {"),
    ("XC45", "xchain.rs", "status takes a refund for the claim",
     "            o.script_public_key == delivery && o.covenant.map(|c| c.covenant_id) == covenant",
     "            true"),
    ("XC46", "xchain.rs", "status reports a spent funding as unspent",
     "        Err(e) if e.code() == \"CLI_UTXO_NOT_FOUND\" => false,", "        Err(_) => true,"),
    # I17 CLI step: the tranche and the version 2 receipt (PT01 to PT05, RV01 to RV17).
    ("PT01", "v2_cmd.rs", "a partial trade's vault UTXOs are looked up as plain ones",
     "    if !partial {\n        return utxos_with(", "    if true {\n        return utxos_with("),
    ("PT02", "v2_cmd.rs", "--tranche builds the final settle",
     "        Some(lots) => settle_tranche(&terms, &legs, lots, p, daa),", "        Some(_) => settle(&terms, &legs, p, daa),"),
    ("PT03", "v2_cmd.rs", "a tranche's kind is named as a final settle",
     "        Some(lots) if partial && lots < held_lots => IpstV2Kind::Tranche { lots },", "        Some(_) if false => IpstV2Kind::Tranche { lots: 0 },"),
    ("PT04", "v2_cmd.rs", "a tranche's trade outputs are counted as a final settle's",
     "        IpstV2Kind::Tranche { .. } => 2 * t.legs.len() + t.kcc20_legs(),", "        IpstV2Kind::Tranche { .. } => t.legs.len() + t.kcc20_legs(),"),
    ("PT05", "v2_cmd.rs", "the settler cost line is not printed for a tranche",
     "    if matches!(kind, IpstV2Kind::Tranche { .. }) {\n        lines.push(format!(\n            \"settler cost", "    if false {\n        lines.push(format!(\n            \"settler cost"),
    ("RV01", "receipt_v2.rs", "the digest does not carry the version 2 byte",
     "    let mut bytes = o.canonical();\n    bytes[0] = RECEIPT_V2_VERSION;\n", "    let mut bytes = o.canonical();\n"),
    ("RV02", "receipt_v2.rs", "a receipt missing a quantity field is malformed, not missing",
     "        if let Some(missing) = QUANTITY_KEYS.iter().find(|k| o.opt(k).is_none()) {", "        if let Some(missing) = QUANTITY_KEYS.iter().find(|_| false) {"),
    ("RV03", "receipt_v2.rs", "a leg missing a quantity field is read as present",
     "            if let Some(missing) = [\"moved\", \"cumulative\", \"total\"]", "            if let Some(missing) = [\"moved\", \"cumulative\"]"),
    ("RV04", "receipt_v2.rs", "total_lots is not compared with the terms",
     "        if q.total_lots != total_lots {", "        if false {"),
    ("RV05", "receipt_v2.rs", "lots above the cumulative pass",
     "        if q.lots == 0 || q.lots > q.cumulative_lots || q.cumulative_lots > total_lots {", "        if q.lots == 0 || q.cumulative_lots > total_lots {"),
    ("RV06", "receipt_v2.rs", "a first receipt may state a cumulative above its lots",
     "        if q.prior == ZERO && q.cumulative_lots != q.lots {", "        if false {"),
    ("RV07", "receipt_v2.rs", "a leg's total is not compared with the terms",
     "                || l.total != t.legs[i].asset.amount\n", "                || false\n"),
    ("RV08", "receipt_v2.rs", "the previous receipt's digest is not compared",
     "        if q.prior != previous.digest() {", "        if false {"),
    ("RV09", "receipt_v2.rs", "the cumulative does not have to add up",
     "        if previous.quantity.cumulative_lots.checked_add(q.lots) != Some(q.cumulative_lots) {", "        if false {"),
    ("RV10", "receipt_v2.rs", "a previous transaction that did not continue passes",
     "            if prev.continuation == ZERO {\n                return Err(lineage(format!(\n                    \"leg {i}: the previous transaction did not continue the vault\"\n                )));\n            }\n            let expected = TransactionOutpoint::new(\n                kaspa_consensus_core::Hash::from_bytes(self.observation.txid),\n                (n + i) as u32,\n            );\n            if now.spent != expected || now.covenant != prev.continuation {",
     "            let expected = TransactionOutpoint::new(\n                kaspa_consensus_core::Hash::from_bytes(self.observation.txid),\n                (n + i) as u32,\n            );\n            if now.spent != expected || now.covenant != prev.continuation {"),
    ("RV11", "receipt_v2.rs", "the spent outpoint or the covenant may differ from the continuation",
     "            if now.spent != expected || now.covenant != prev.continuation {", "            if now.spent != expected && now.covenant != prev.continuation {"),
    ("RV12", "receipt_v2.rs", "derive does not check the previous receipt against the transaction",
     "                p.check_links(observation, facts, n)?;", ""),
    ("RV13", "receipt_v2.rs", "the transaction's lots are not compared with the receipt's",
     "        if q.lots != facts.lots {", "        if false {"),
    ("RV14", "receipt_v2.rs", "the transaction's lineage is not compared with the receipt's",
     "            if l.spent != f.spent\n                || l.covenant != cov(f.covenant)\n                || l.continuation != cov(f.continuation)\n            {", "            if false {"),
    ("RV15", "v2_cmd.rs", "receipt verify does not compare the quantities with the terms",
     "    if let Some(t) = &terms {\n        receipt.check_quantities(t)?;\n    }", ""),
    ("RV16", "v2_cmd.rs", "receipt verify does not read the transaction again",
     "                    receipt.check_facts(&facts)?;", ""),
    ("RV17", "v2_cmd.rs", "status signs a receipt for a transaction that is not a settle of the terms",
     "        Err(e) if a.key_file.is_some() => return Err(e.clone().into()),", "        Err(e) if false => return Err(e.clone().into()),"),
    # I18 live-demo step: the read-only Solana counterpart source (xchain_solana.rs).
    ("XS01", "xchain_solana.rs", "a frozen escrow not refused",
     "        if t.frozen {", "        if false {"),
    ("XS02", "xchain_solana.rs", "the freeze-authority warning dropped",
     "        Ok(t.freeze_authority\n            .map(|a| {", "        Ok(None::<[u8; 32]>\n            .map(|a: [u8; 32]| {"),
    ("XS03", "xchain_solana.rs", "an escrow short of the amount read as funded",
     "&& read_u64(&data, 64) >= s.amount)", "&& true)"),
    ("XS04", "xchain_solana.rs", "an escrow held by another address read as funded",
     "&& key(&data, 32) == *htlc", "&& true"),
    ("XS05", "xchain_solana.rs", "an account off its own seeds taken as a lock",
     "        if pda(&[b\"htlc\", &s.funder, &s.hash_lock], s.bump, &self.program) != address",
     "        if false && pda(&[b\"htlc\", &s.funder, &s.hash_lock], s.bump, &self.program) != address"),
    ("XS06", "xchain_solana.rs", "a failed transaction read as a claim",
     "        if r.is_null() || !r[\"meta\"][\"err\"].is_null() {", "        if r.is_null() {"),
    ("XS07", "xchain_solana.rs", "a cleartext rpc url to a remote host accepted",
     "        \"http\" if loopback => Ok(()),", "        \"http\" => Ok(()),"),
    ("XS08", "xchain_solana.rs", "an open instruction for another hash lock taken as the lock",
     "                    || ix.data[9..41] != hash_lock[..]\n", "                    || false\n"),
    # Security fix: claims through a cross-program invocation, and paged histories.
    ("XS09", "xchain_solana.rs", "inner (CPI) instructions not read",
     "            .chain(inner)\n", "\n"),
    ("XS10", "xchain_solana.rs", "the history read as its newest page only",
     "                before = Some(sig.to_string());\n", "\n"),
    ("XS11", "xchain_solana.rs", "a history past the bound read as a miss",
     "        Err(rpc_err(format!(\n            \"the history of {}", "        if true {\n            return Ok(());\n        }\n        Err(rpc_err(format!(\n            \"the history of {}"),
    ("XS12", "xchain_solana.rs", "the claim search does not stop at the open",
     "            Ok(ixs.iter().any(|ix| self.is_open_of(ix, lock)))", "            Ok(false)"),
    ("XS13", "xchain_solana.rs", "the funder search does not stop at the open it found",
     "            Ok(!found.is_empty())", "            Ok(false)"),
    ("XS14", "xchain_solana.rs", "user information before the host accepted",
     "    if !u.username().is_empty() || u.password().is_some() {", "    if false {"),
    ("XS15", "xchain_solana.rs", "a password without a user name accepted",
     "    if !u.username().is_empty() || u.password().is_some() {", "    if !u.username().is_empty() {"),
    ("XS16", "xchain_solana.rs", "a transport error echoes the rpc url",
     "    e.without_url().to_string()", "    e.to_string()"),
    # Security fix: size caps on file reads and rpc replies.
    ("SZ01", "terms_file.rs", "a file over its cap read whole",
     "    if buf.len() as u64 > limit {", "    if false {"),
    ("SZ02", "terms_file.rs", "a document read under the owner list's cap",
     "    read_text_max(path, MAX_TEXT_FILE)", "    read_text_max(path, MAX_LIST_FILE)"),
    ("SZ03", "xchain_doc.rs", "a DAA sample read without its cap",
     "crate::terms_file::read_bounded(path, MAX_SAMPLE_FILE)", "crate::terms_file::read_bounded(path, u64::MAX)"),
    ("SZ04", "xchain_solana.rs", "an rpc reply over the cap buffered whole",
     "                    if body.len() + chunk.len() > MAX_RPC_BODY {", "                    if false {"),
    # The return gate (I22 review): core gate.rs and the CLI's gate functions (linked_cmd.rs).
    ("LG01", "core:gate.rs", "the settle tag read from the wrong push",
     "p.iter().rev().nth(1)", "p.iter().rev().nth(0)"),
    ("LG02", "core:gate.rs", "a transaction with one input passes the input-count guard",
     "tx.inputs.len() < 2 ||", "tx.inputs.len() < 1 ||"),
    ("LG03", "core:gate.rs", "missing spent scripts are tolerated",
     "spent.len() < tx.inputs.len()", "spent.len() < 2"),
    ("LG04", "core:gate.rs", "input 1 is checked against the vault of leg 0",
     "verify_spent_input(linked.terms(role), leg, input, &spent[leg])",
     "verify_spent_input(linked.terms(role), 0, input, &spent[leg])"),
    ("LG04b", "core:gate.rs", "input 1 is checked against the first spent script",
     "verify_spent_input(linked.terms(role), leg, input, &spent[leg])",
     "verify_spent_input(linked.terms(role), leg, input, &spent[0])"),
    ("LG04c", "core:gate.rs", "only input 0 is checked",
     "for leg in 0..2 {", "for leg in 0..1 {"),
    ("LG05", "core:gate.rs", "the settle tag is not compared",
     "if called.as_deref() != Some(&settle_tag()[..]) {", "if false {"),
    ("LG06", "core:gate.rs", "the evidence names no sheet",
     "if self.linked_hash == linked.linked_hash() {", "if true {"),
    ("LG07", "linked_cmd.rs", "the accepting block need not be a chain block",
     "    if !info.is_chain_block {\n        return Err(CliError::new(\n            \"CLI_TX_NOT_ACCEPTED\",\n            \"the accepting block left the selected chain during the walk\",",
     "    if false {\n        return Err(CliError::new(\n            \"CLI_TX_NOT_ACCEPTED\",\n            \"the accepting block left the selected chain during the walk\","),
    ("LG08", "linked_cmd.rs", "the depth is not compared with the minimum",
     "    if depth < min_depth {", "    if false {"),
    ("LG09", "linked_cmd.rs", "the depth compare is off by one",
     "    if depth < min_depth {", "    if depth <= min_depth {"),
    ("LG10", "linked_cmd.rs", "a virtual DAA score below the block's reads as depth zero",
     "        .checked_sub(info.daa_score)\n        .ok_or_else(|| {", "        .checked_sub(info.daa_score)\n        .or(Some(0)).ok_or_else(|| {"),
    # Recovery is never blocked or capped (xchain.rs, fix/xchain-claim): claim falls back to the pinned
    # DAA rate with a warning; the value cap on claim and refund is a warning.
    ("XR01", "xchain.rs", "a claim with an unusable DAA sample is refused again",
     "            pinned_daa_rate(t.network)\n", "            return Err(e);\n"),
    ("XR02", "xchain.rs", "the claim fallback uses the sample-only rate, not the pinned one",
     "            pinned_daa_rate(t.network)\n", "            daa_rate_max(t.network, None, now).map_err(htlc_err)?\n"),
    ("XR03", "xchain.rs", "the claim fallback warning goes nowhere",
     "                notes,\n                \"warning: the DAA rate sample", "                std::io::sink(),\n                \"warning: the DAA rate sample"),
    ("XR04", "xchain.rs", "recovery over the value cap is refused again",
     "            Ok(\"value cap: not applied to recovery\".into())", "            Err(CliError::new(\"CLI_VALUE_CAP_EXCEEDED\", \"refused\".to_string()))"),
    ("XR05", "xchain.rs", "the recovery cap warning goes nowhere",
     "                notes,\n                \"warning: the value cap is not applied", "                std::io::sink(),\n                \"warning: the value cap is not applied"),
]


CORE_GATE = os.path.join("crates", "impulse-core", "src", "linked", "gate.rs")


def mutant_path(root, name):
    """A mutant file is a name in the CLI's src/, or `core:gate.rs`, the return gate in core."""
    return os.path.join(root, CORE_GATE if name == "core:gate.rs" else os.path.join(SRC, name))


def source_files():
    return sorted(f for f in os.listdir(os.path.join(ROOT, SRC)) if f.endswith(".rs"))


def source_digest():
    """sha256 over every CLI source file, by name, in name order."""
    h = hashlib.sha256()
    for name in source_files():
        with open(os.path.join(ROOT, SRC, name), "rb") as f:
            h.update(name.encode() + b"\0" + f.read() + b"\0")
    with open(os.path.join(ROOT, CORE_GATE), "rb") as f:
        h.update(b"core:gate.rs\0" + f.read() + b"\0")
    return h.hexdigest()


def script_digest():
    with open(os.path.realpath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check():
    try:
        with open(RECORD) as f:
            record = f.read()
    except OSError:
        sys.exit("missing %s: run scripts/cli-mutation.py --record" % RECORD)
    result = re.search(r"^result: (\d+) of (\d+) mutants caught$", record, re.M)
    problems = []
    if not re.search(r"^source sha256 %s$" % source_digest(), record, re.M):
        problems.append("the record is for other CLI source")
    if not re.search(r"^script sha256 %s$" % script_digest(), record, re.M):
        problems.append("the record is for another mutant list")
    if not result or result.group(1) != result.group(2) or int(result.group(2)) != len(MUTANTS):
        problems.append("the record does not show every mutant caught")
    if problems:
        sys.exit("cli mutation record: " + "; ".join(problems) + "; rerun with --record")
    print("cli mutation record: %s of %s mutants caught, current" % (result.group(1), result.group(2)))


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


def run_tests(tree, target_dir=TARGET_DIR, core=False):
    env = dict(os.environ, CARGO_TARGET_DIR=target_dir)
    cmd = ["cargo", "test", "--locked", "--offline", "-p", "impulse-cli", "--lib"]
    if core:  # the gate also lives in core: its own linked tests count too
        cmd = ["cargo", "test", "--locked", "--offline", "-p", "impulse-cli", "-p", "impulse-core",
               "--lib", "--no-fail-fast"]
    out = subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True)
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
    mid, name, what, old, new = mutant
    path = mutant_path(slot["tree"], name)
    with open(path) as f:
        original = f.read()
    with open(path, "w") as f:
        f.write(original.replace(old, new, 1))
    try:
        failed, text = run_tests(slot["tree"], slot["target"], name.startswith("core:"))
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
    args = sys.argv[1:]
    for k, arg in enumerate(args):
        if arg == name and k + 1 < len(args):
            return args[k + 1]
    for arg in args:
        if arg.startswith(name + "="):
            return arg[len(name) + 1:]
    return default


def main():
    if "--check" in sys.argv[1:]:
        return check()
    record = "--record" in sys.argv[1:]
    only = option("--only", "")
    if only:  # a quick run of named mutants, never recorded
        global MUTANTS
        MUTANTS = [m for m in MUTANTS if m[0] in only.split(",")]
        record = False
    for mid, name, _, old, _ in MUTANTS:
        with open(mutant_path(ROOT, name)) as f:
            n = f.read().count(old)
        if n != 1:
            sys.exit("[%s] pattern occurs %d times in %s; it must occur once" % (mid, n, name))
    if len({m[0] for m in MUTANTS}) != len(MUTANTS):
        sys.exit("duplicate mutant ids")

    report = [
        "Mutation run, crates/impulse-cli/src (scripts/cli-mutation.py)",
        "source sha256 %s" % source_digest(),
        "script sha256 %s" % script_digest(),
        "mutants %d, test target impulse-cli --lib" % len(MUTANTS),
        "",
    ]
    jobs = int(option("--jobs", "1"))
    slots = []
    for index in range(jobs):
        tree = tempfile.mkdtemp(prefix="cli-mutation-")
        copy_tree(tree)
        slots.append({"tree": tree, "target": TARGET_DIR})
    try:
        failed, text = run_tests(slots[0]["tree"])
        if failed is None or failed:
            sys.exit("baseline is not green:\n%s" % text[-4000:])
        # The other workers start from a copy of the warm target directory.
        for index, slot in enumerate(slots):
            slot["target"] = clone_target(index)
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
            futures = [pool.submit(work, m) for m in MUTANTS]
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
    result = "result: %d of %d mutants caught" % (caught, len(MUTANTS))
    report += ["", result]
    print("\n" + result)
    if record:
        with open(RECORD, "w") as f:
            f.write("\n".join(report) + "\n")
        print("wrote %s" % RECORD)
    if caught != len(MUTANTS):
        sys.exit(1)


if __name__ == "__main__":
    main()
