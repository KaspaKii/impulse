// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Mutation run of the browser tests (I11, review round 1; phase 2 mutants added). Each mutant is
// one edit of one file of demo/dist, made in a private copy (the tests read it through
// IMPULSE_DIST); a mutant is caught when the browser suite fails on it, and the run on a mutant
// stops at the first failing test, so the record names the tests that failed by then. Run by hand after
// demo/ci.sh has built demo/dist:
//   node demo/mutation.mjs --record      writes demo/mutation-run.txt
//   node demo/mutation.mjs               prints the result, writes nothing
// The run is not a CI step: it takes about as long as the suite times the number of mutants that
// no test catches, plus a part of the suite for each that one does. Its record is checked in CI
// (--verify-record): it names the sources it was run against by hash. A survivor is a miss of the
// suite, or an edit that changes nothing observable; the record says which, in the brief's Review
// section.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");
const testFiles = readdirSync(join(here, "test"))
  .filter((f) => f.endsWith(".test.ts"))
  .sort();

// [id, file, from, to, what]. `from` must occur exactly once in the file.
const MUTANTS = [
  ["M1", "app.js", "cap: config.valueCapSompi,", "", "the configured cap is not passed to the SDK"],
  ["M2", "app.js", 'network: state.mainnet ? "mainnet" : "testnet", creation_daa', 'network: "testnet", creation_daa', "the mainnet switch is ignored by the creation checks"],
  ["M3", "app.js", "wallets.refreshAddresses();\n    if (state.touched) compute();", "wallets.refreshAddresses();", "the switch does not recompute: a testnet instruction stays on screen"],
  ["M4", "app.js", 'creation_daa_source: fromNode ? "node" : "typed",', 'creation_daa_source: "node",', "a typed creation DAA score is claimed to come from a node"],
  ["M5", "app.js", "qrSvg(doc, sdk.qrCode(leg.funding_uri))", "qrSvg(doc, sdk.qrCode(leg.vault.address))", "the QR shows the vault address, not the URI"],
  ["M6", "app.js", "const quiet = 4;", "const quiet = 0;", "no quiet zone around the QR"],
  ["M7", "app.js", "const quiet = 4;", "const quiet = 1;", "a quiet zone of one module"],
  ["M8", "app.js", 'form.querySelector(\'[data-path="cash_leg.amount"]\').value : ""', 'form.querySelector(\'[data-path="asset_leg.amount"]\').value : ""', "the KAS echo of the cash amount reads the asset amount"],
  ["M9", "app.js", "`${v.value_kas} KAS (${v.value} sompi;", "`${v.cap_kas} KAS (${v.value} sompi;", "the value row shows the cap as the value"],
  ["M10", "app.js", "(as you entered it, not read from a node)", "(read from a node)", "the creation score is described as read from a node"],
  ["M11", "app.js", "(${leg.amount_kas} KAS)`", "(${leg.amount_kas} sompi)`", "a KAS amount labelled as sompi"],
  ["M12", "app.js", " Confirm your wallet shows that amount before you send.", "", "the wallet confirmation sentence is dropped"],
  ["M13", "app.js", '$("decoded").hidden = false;', "", "the decoded terms are never shown"],
  ["M14", "app.js", '$("destinations").hidden = false;', "", "the four destinations are never shown"],
  ["M15", "app.js", '$("kas-equivalent").value = "";', "", "a KAS declaration survives loading other terms"],
  ["M16", "app.js", "back.requireSameAs(terms);", "", "the form read back is not compared with the terms loaded"],
  ["M17", "app.js", "sdk.Terms.fromFileText(text)", "sdk.Terms.fromJson(JSON.parse(text))", "pasted text goes through JSON.parse, not the SDK's reader"],
  ["M18", "app.js", "if (d.pays_counterparty_or_authority) {", "if (false) {", "no warning on a destination that pays the counterparty or the authority"],
  ["M19", "app.js", "for (const w of leg.token_warnings) {", "for (const w of []) {", "no token notice on a KCC-20 leg"],
  ["M20", "app.js", "send nothing to this address", "send it to this address", "the leg card no longer says to send nothing to the other vault"],
  ["M21", "app.js", "NOT checked: who controls a script destination you pinned", "All checks passed: who controls a script destination you pinned", "the status claims all checks passed"],
  ["M22", "app.js", 'status.dataset.state = "error";', 'status.dataset.state = "idle";', "a startup failure leaves the page idle"],
  ["M23", "main.js", "sdk.templateCheck();", "", "the startup template check is skipped"],
  ["M24", "app.js", '$("mainnet-notice").hidden = !state.mainnet;', '$("mainnet-notice").hidden = true;', "the mainnet notice never shows"],
  ["M25", "app.js", "loadError(`The golden vectors could not be listed: ${e.message}`);", 'loadError("");', "a vector list that cannot be fetched is not reported"],
  ["M26", "app.js", "if (!response.ok) throw new Error(`HTTP ${response.status}`);", "", "an HTTP error on a vector file is read as terms"],
  ["M27", "index.html", 'placeholder="the current virtual DAA score"', 'value="400000000"', "the creation score has a default again"],
  ["M28", "index.html", "connect-src 'self'", "connect-src *", "CSP: connections to anywhere"],
  ["M29", "index.html", "img-src 'self'", "img-src *", "CSP: images from anywhere"],
  ["M30", "index.html", "default-src 'none'", "default-src *", "CSP: default source anywhere"],
  ["M31", "index.html", "script-src 'self' 'wasm-unsafe-eval'", "script-src 'self' 'wasm-unsafe-eval' https:", "CSP: scripts from any https host"],
  ["M32", "index.html", "style-src 'self'", "style-src 'self' 'unsafe-inline'", "CSP: inline styles"],
  ["M33", "index.html", "; form-action 'none'", "", "CSP: forms may post anywhere"],
  ["M34", "index.html", "; base-uri 'none'", "", "CSP: a base element may redirect relative URLs"],
  ["M35", "index.html", "'wasm-unsafe-eval'", "'wasm-unsafe-eval' 'unsafe-eval'", "CSP: eval allowed"],
  ["M36", "decoder.html", "default-src 'none'", "default-src *", "decoder CSP: default source anywhere"],
  ["M37", "decoder.js", '$("decode").disabled = false;', "", "the decoder button is never enabled"],
  ["M38", "index.html", "This page refuses a trade whose declared KAS value, or whose native KAS leg, is above", "This page caps every trade at", "the banner says the page caps every trade"],
  ["M39", "app.js", 'const names = await (await fetch("examples/index.json")).json();', 'const names = await (await fetch("examples/index.json")).json(); fetch("https://example.com/");', "the page fetches a foreign URL at startup"],
  ["M40", "config.js", '"1000000000"', '"1000000001"', "the configured cap is above the SDK's default"],
  ["M41", "app.js", 'input.dataset.type === "nullable" && raw === ""', 'input.dataset.type === "nullable" && raw === "x"', "an empty nullable field is read as an empty string"],
  ["M42", "app.js", 'if (input.closest("[hidden]")) continue;', "", "fields of a hidden kind group are read"],
  // Phase 2.
  ["M43", "index.html", "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src 'self' wss: ws:", "CSP: plaintext sockets to any host"],
  ["M44", "decoder.html", "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src *", "decoder CSP: connections to anywhere"],
  ["M45", "node.js", "this.#sdk.checkNodeUrl(url, network);", "", "the node URL is not checked before a socket is opened"],
  ["M46", "node.js", "this.#sdk.checkNode(reply, this.network);", "", "the node is not checked for the network and for being synced"],
  ["M47", "actions.js", "if (!review.submit_ready) {", "if (false) {", "a transaction is submitted before its lock time has passed"],
  ["M48", "actions.js", "mainnet: ctx.mainnet(),", "mainnet: true,", "signing always claims the mainnet choice"],
  ["M49", "actions.js", '$("submit").disabled = !ipst.isComplete() || session.unknown !== undefined;', '$("submit").disabled = false;', "submit is offered before every input is signed"],
  ["M50", "actions.js", "if (w === null || w.isWiped()) continue;", "if (w === null) continue;", "a wiped wallet is offered for signing"],
  ["M51", "actions.js", "const reply = sdk.rpcSubmitReply(text, id, signed);", "const reply = txid;", "the page names the transaction it sent without checking the node's answer"],
  ["M52", "actions.js", 'entries($("review-outputs-body"), review.outputs, false);', "", "the outputs are not shown before signing"],
  ["M53", "actions.js", '"lock-time",', '"lock-time-hidden",', "the lock time row is not where a reader looks for it"],
  ["M54", "actions.js", "const info = await ctx.node.serverInfo();\n      const review = reviewOf(session.ipst, session.artifacts, info.virtual_daa_score, session.value);", "const info = { virtual_daa_score: session.daa };\n      const review = reviewOf(session.ipst, session.artifacts, info.virtual_daa_score, session.value);", "the node's score is not read again before submitting"],
  ["M55", "wallets.js", 'win.addEventListener("pagehide", wipeAll);', "", "the wallets are not wiped when the page is hidden"],
  ["M56", "wallets.js", 'event.preventDefault();\n    event.returnValue = "";', 'event.preventDefault();\n    event.returnValue = "";\n    wipeAll();', "the wallets are wiped by a beforeunload that the person may cancel"],
  ["M57", "wallets.js", "wallets[name]?.wipe();", "", "the wipe button does not wipe"],
  ["M58", "wallets.js", 'part(name, ".wallet-generate").disabled = w !== null && !wiped ? true : false;', 'part(name, ".wallet-generate").disabled = false;', "a wallet that holds a key can be asked for another"],
  ["M59", "app.js", 'const fromNode = state.nodeDaa !== null && $("creation-daa").value === state.nodeDaa;', "const fromNode = state.nodeDaa !== null;", "an edited score still counts as read from the node"],
  ["M60", "app.js", "actions.available(true);", "", "the actions are never offered"],
  ["M61", "app.js", "    actions.available(false);\n", "", "the actions stay offered when the terms stop passing"],
  ["M62", "app.js", "state.nodeDaa = null;\n    wallets.refreshAddresses();", "wallets.refreshAddresses();", "a score read on one network survives the switch to the other"],
  ["M63", "actions.js", "const pins = pinsFor(w);\n      if (pins !== undefined) options.pins = pins;", "", "the user's pins are not given to the wallet that signs"],
  ["M64", "actions.js", 'if ($("my-key").value === key) return pins("pin");', 'if (true) return pins("pin");', "the user's pins are given to every wallet"],
  ["M65", "actions.js", '$("refund-token").checked, arts, text, funding, value', "true, arts, text, funding, value", "the refund always carries the token"],
  ["M66", "decoder.js", 'if (describe(e).code !== "SDK_RPC_NOT_FOUND") throw e;', "", "every error of the mempool lookup is read as a miss"],
  ["M67", "decoder.js", '"data-bound": String(decoded.bound),', '"data-bound": "true",', "an unbound decoding is shown as bound"],
  [
    "M68",
    "decoder.js",
    "sdk.decodeFetched(found, txid, network)",
    "sdk.decodeFetched(found, found.txid, network)",
    "the decoder trusts the ID the node states",
    // The sixth member marks an edit no page can observe, with the reason. The check is not
    // unguarded: it is made twice, and the page reaches the second only through the first.
    "equivalent: rpcTransactionReply, called with the asked ID just before, already refuses a mempool entry or an accepted transaction whose own ID is not the asked one (SDK_TXID_MISMATCH, the 'swapped' case of the decoder test), so what reaches decodeFetched states the asked ID; decodeFetched's own refusal is tested in rpc_tests.rs and session.test.ts",
  ],
  ["M69", "node.js", 'if (typeof event.data !== "string") waiting.reject(new Error("The node sent something that is not text."));\n      else waiting.resolve(event.data);', "waiting.resolve(String(event.data));", "a binary frame from the node is read as text"],
  ["M70", "decoder.js", "if (reply.added.length === 0) {\n            reachedTip = true;\n            break;\n          }", "", "the chain walk never ends at the tip"],
  // Review round 2 of phase 2.
  ["M71", "actions.js", "`${review.fee_kas} KAS (${review.fee} sompi);", "`${review.min_relay_fee} KAS (${review.fee} sompi);", "the fee row shows the minimum relay fee as the KAS figure"],
  ["M72", "actions.js", 'row("Network", review.network, "network");', 'row("Network", "testnet", "network");', "a mainnet signer is told testnet"],
  ["M73", "actions.js", 'row("The node\'s DAA score", review.current_daa, "daa");', 'row("The node\'s DAA score", review.lock_time, "daa");', "the node's score row shows the lock time"],
  ["M74", "actions.js", "`compute ${review.masses.compute}, transient ${review.masses.transient}, storage ${review.masses.storage}`", "`compute ${review.masses.storage}, transient ${review.masses.transient}, storage ${review.masses.compute}`", "compute and storage mass swapped"],
  ["M75", "actions.js", "return `script version ${spk.version}: ${spk.script}`;", 'return "";', "an input or output without an address shows nothing"],
  ["M76", "actions.js", 'row("You pay beyond the fee", review.payer_cost_text, "payer-cost");', 'row("You pay beyond the fee", "none", "payer-cost");', "the cost beyond the fee is always none"],
  ["M77", "actions.js", "text: held ? `${item.what} [pays a key that lives only in this page]` : item.what,", "text: item.what,", "an output that pays a key held only in the page is not marked"],
  ["M78", "actions.js", "...review.notes.map((text)", "...[].map((text)", "the notes of the review are not shown"],
  ["M79", "actions.js", 'row("Terms hash", review.terms_hash, "terms-hash");', 'row("Terms hash", "", "terms-hash");', "the review does not show which trade it is for"],
  ["M80", "actions.js", "(${ROLE_TEXT[item.signer_role] ?? item.signer_role})", "()", "the review does not say whose key a signature is for"],
  ["M81", "decoder.js", 'if (seen !== null && reply.removed.includes(seen)) {', "if (false) {", "a block that left the chain still counts as accepting"],
  ["M82", "decoder.js", "cursor = reply.added[reply.added.length - 1];", "cursor = reply.added[0];", "the chain walk moves on by the first block of a page, not the last"],
  ["M83", "decoder.js", "const MAX_BATCHES = 200;", "const MAX_BATCHES = 1;", "the chain walk reads one page"],
  ["M84", "decoder.js", "sdk.decodeFetched(found, txid, network)", 'sdk.decodeFetched(found, txid, "testnet")', "every transaction is decoded as a testnet one"],
  ["M85", "decoder.js", 'if (from !== "" && !reachedTip) {', "if (false) {", "a walk that ran out of pages says the transaction is not there"],
  ["M86", "actions.js", "mainnet: ctx.mainnet(),", "mainnet: false,", "signing never makes the mainnet choice"],
  ["M87", "actions.js", 'return { asset: $("asset-artifact").value, cash: cash === "" ? null : cash };', 'return { asset: $("asset-artifact").value, cash: null };', "the cash token's artifact is never given to the SDK"],
  ["M88", "actions.js", 'const stale = () => started !== generation || $("actions").hidden;', "const stale = () => false;", "a build in flight is adopted whatever changed under it"],
  ["M89", "node.js", "this.close();\n      throw e;", "throw e;", "a node that fails the network or sync check is kept connected"],
  ["M90", "node.js", "const next = this.#queue.then(run, run);", "const next = run();", "requests are not made one at a time"],
  ["M91", "decoder.js", "} finally {\n      node.close();", "} finally {", "the decoder leaves its socket open"],
  ["M92", "wallets.js", 'event.preventDefault();\n    event.returnValue = "";', "", "the browser is not asked before the page leaves with keys in it"],
  ["M93", "wallets.js", "if (holding.length === 0) {", "if (true) {", "Wipe never asks, whatever the wallet held"],
  ["M94", "wallets.js", "balances[name] = live(name) ? BigInt(reply.total) : null;", "balances[name] = null;", "the balance read is forgotten at once"],
  ["M95", "actions.js", 'target: "_blank",\n      rel: "noopener",', "", "the decoder link opens in the tab that holds the keys"],
  ["M96", "actions.js", "if (left && !(e && e.nodeError === true)) {", "if (false) {", "a lost answer is reported as a refusal"],
  ["M97", "node.js", "if (e && typeof e === \"object\") e.afterSend = true;", "", "an error after a request was sent does not say so"],
  ["M98", "app.js", "held: wallets.heldKeys(),", "", "the role check is not told which keys live only in the page"],
  ["M99", "actions.js", "held: ctx.wallets.heldKeys(),", "", "a wallet is not told which keys live only in the page"],
  ["M100", "actions.js", "if (change !== null) options.change = change;", "", "a wallet is not told the change address the document pays"],
  ["M101", "actions.js", "if (change !== null) funding.change = change;", "", "the builder is not told the change address"],
  ["M102", "actions.js", "if (otherKey === key) {", "if (false) {", "the other party's pins are given to no wallet"],
  ["M103", "actions.js", "ipst.review(arts, daa, value, ctx.wallets.heldKeys())", "ipst.review(arts, daa, value)", "the review is not told which keys live only in the page"],
  ["M104", "actions.js", 'for (const [id, key] of [["max-fee", "max_fee"], ["max-topup", "max_topup"]]) {', 'for (const [id, key] of []) {', "the limits the person sets are not given to the wallet"],
  // Owner decisions 2026-10-11.
  ["M105", "config.js", '"1000000000"', '"100000000"', "the page's cap is lower than the default, too low for a Direct trade's token carrier"],
  ["M106", "index.html", "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:* ws://[::1]:*", "CSP: the IPv6 loopback literal is named"],
  ["M107", "index.html", "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src 'self' wss: ws://127.0.0.1:*", "CSP: localhost is not allowed over ws"],
  // Integration follow-up 2026-10-11: funding the buyer's cash leg from the page, and the export and
  // import of the partially signed transaction.
  ["M108", "actions.js", "addresses = terms.fundCashAddresses(arts, key);", "addresses = terms.settleAddresses(arts, key);", "the funding asks the node about the addresses of the settle, in the settle's order"],
  ["M109", "actions.js", '$("fund-options").hidden = !(mode === "vault" && role === "buyer" && cashKind === "kas");', '$("fund-options").hidden = false;', "the funding is offered to everyone, for every trade"],
  ["M110", "app.js", "actions.setMode(termsJson.settlement_mode, out.role.role, termsJson.cash_leg.kind);", "actions.setMode(termsJson.settlement_mode);", "the funding is never offered"],
  ["M111", "actions.js", "combined = session.ipst.combine(pasted);", "combined = sdk.Ipst.fromJson(pasted);", "the pasted document is taken in place of the one under review"],
  ["M112", "actions.js", "if (added === 0) {", "if (false) {", "a pasted document that adds no signature is accepted"],
  ["M113", "actions.js", "if (session === null) {\n        throw new Error(\"There is no document under review.", "if (false) {\n        throw new Error(\"There is no document under review.", "signatures are taken with no document under review"],
  ["M114", "actions.js", "adopt(combined, { daa });\n      combined = null;", "session.ipst = combined;\n      combined = null;", "the document with the added signatures is not reviewed again"],
  ["M115", "actions.js", "combined = null;\n      $(\"import-text\").value = \"\";", "combined = null;", "the pasted text stays in the box after it was taken"],
  ["M116", "actions.js", '$("import-text").value = "";\n    setImportStatus("idle", "");\n    $("submit").disabled = true;', '$("submit").disabled = true;', "a change under the review leaves the pasted text and its status behind"],
  ["M117", "actions.js", "await win.navigator.clipboard.writeText(text);", 'await win.navigator.clipboard.writeText("");', "the copy puts nothing on the clipboard and says it copied"],
  ["M118", "actions.js", "...(deposit !== null\n", "...(false\n", "a funding is not told to wait for the deposit to be listed"],
  ["M119", "actions.js", '$("fund-options").hidden = !(mode === "vault" && role === "buyer" && cashKind === "kas");', '$("fund-options").hidden = !(mode === "vault" && cashKind === "kas");', "the funding is offered to the seller"],
  ["M120", "actions.js", '$("fund-options").hidden = !(mode === "vault" && role === "buyer" && cashKind === "kas");', '$("fund-options").hidden = !(mode === "vault" && role === "buyer");', "the funding is offered for a cash leg that is not native KAS"],
  ["M121", "actions.js", '$("fund-options").hidden = !(mode === "vault" && role === "buyer" && cashKind === "kas");', '$("fund-options").hidden = !(role === "buyer" && cashKind === "kas");', "the funding is offered for a Direct trade"],
  ["M122", "actions.js", "if (kind === \"fund\") {\n        // The addresses are", "if (false) {\n        // The addresses are", "the funding button builds a settle"],
  ["M123", "actions.js", "...(deposit !== null\n", "...(session.kind === \"fund\"\n", "a submission the node accepted is reported as a failure when the terms were edited meanwhile"],
  // Review round 2 of the integration follow-up: the pinned template, the node's state, the node's
  // score, the way out of a funding, the copy of the signed text, and the import.
  ["M124", "actions.js", "built = terms.fundCashFromReply(arts, text, funding, daa, value);", 'built = terms.fundCashFromReply(arts, text, funding, "0", value);', "the funding is built at DAA score 0, not the node's"],
  ["M125", "actions.js", 'setCopyStatus("error", "The browser did not allow the copy. The text is open below: select it and copy it yourself.");', 'setCopyStatus("ok", "Copied.");', "a copy the browser refused is reported as made"],
  ["M126", "actions.js", '$("ipst-export").open = true;', "", "a refused copy points at text that stays closed"],
  ["M127", "actions.js", '$("ipst-export").open = false;\n    setCopyStatus("idle", "");', 'setCopyStatus("idle", "");', "a new build or an edit leaves the exported text open"],
  ["M128", "actions.js", '$("ipst-export").open = false;\n    setCopyStatus("idle", "");', '$("ipst-export").open = false;', "a new build or an edit leaves the status of the last copy behind"],
  ["M129", "actions.js", "daa = (await ctx.node.serverInfo()).virtual_daa_score;", "", "the review after an import is made at the score of the build"],
  ["M130", "actions.js", "if (deposit !== null) remembered = ctx.wallets.holdEscrow(deposit.wallet, { ...deposit, txid });", "", "a funding is not remembered as a deposit when its request is written"],
  ["M131", "actions.js", "if (session !== null) showUnknown(txid, before, message);\n        else showDetachedUnknown(txid, before, message);", "if (session !== null) showUnknown(txid, before, message);", "a submission whose document is gone while it is in flight says nothing of its unknown outcome"],
  ["M132", "actions.js", "if (closes) ctx.wallets.releaseEscrow(trade);", "ctx.wallets.releaseEscrow(trade);", "any submission ends the escrow of its trade"],
  ["M133", "actions.js", 'const closes = session.kind === "settle" || session.kind === "direct" || (session.kind === "refund" && session.refundLeg === 1);', "const closes = false;", "a settle does not end the escrow"],
  ["M134", "actions.js", '(session.kind === "refund" && session.refundLeg === 1)', '(session.kind === "refund")', "a refund of the asset leg ends the escrow of the cash leg"],
  ["M135", "actions.js", "kind, payerName, refundLeg: leg,", 'kind, payerName: "a", refundLeg: leg,', "the deposit is remembered for wallet A, whichever wallet funded it"],
  ["M136", "wallets.js", "(balances[n] !== null && balances[n] > 0n) || escrows[n].length > 0);", "(balances[n] !== null && balances[n] > 0n));", "Wipe does not ask about a wallet that funded a cash vault"],
  ["M137", "wallets.js", 'const notes = [...new Set(holding.flatMap((n) => escrows[n].map((e) => e.note)).filter((note) => typeof note === "string"))];', "const notes = [];", "the wipe question leaves out how the deposit comes back"],
  ["M138", "wallets.js", "// The key that was the way to refund a deposit is gone; nothing is left to protect.\n    escrows[name] = [];", "// The key that was the way to refund a deposit is gone; nothing is left to protect.", "a wiped wallet still says it holds a deposit"],
  ["M139", "index.html", "Fund it after the seller's asset leg has been accepted, not before.", "", "the page no longer says to fund after the seller's asset leg"],
  ["M140", "index.html", "After the funding is submitted, wait until the node lists the deposit before you build the settle; ", "", "the page no longer says to wait for the node to list the deposit"],
  ["M141", "actions.js", " (the page expects the node to list the UTXOs of accepted blocks; that has not been observed against a real node)", "", "the submit note states the node's behaviour as known"],
  ["M142", "index.html", "id=\"build-fund\">Build the funding of the cash leg<", "id=\"build-fund\">Build<", "the funding button no longer names what it builds"],
  ["M143", "index.html", "Auto is the minimum relay fee of the transaction and a tenth more. ", "", "the page no longer says what its automatic fee is"],
  ["M144", "index.html", "the page funds no token whose template is not a pinned kcc20.sil build (<code>SDK_TEMPLATE_UNPINNED</code>, no override)", "the page funds any token", "the page says it funds a token that is no pinned build"],
  ["M145", "index.html", "closing or reloading this page, or wiping the wallet, destroys that key, and the page asks before it wipes a wallet that funded a cash vault.", "", "the funding hint no longer says that closing the page destroys the refund key"],
  ["M146", "wallets.js", "const at = escrows[name].findIndex((e) => e.termsHash === termsHash);", "const at = escrows[name].length > 0 ? 0 : -1;", "any settle ends every wallet's escrow"],
  ["M147", "wallets.js", "escrow.hidden = held.length === 0;", "escrow.hidden = true;", "a wallet's card never says it holds a deposit"],
  ["M148", "wallets.js", "note: info.note });\n      show(name, false);", "note: info.note });\n      show(name);", "remembering a deposit offers the submit button again for the funding the node took"],
  ["M149", "wallets.js", "escrows[name].splice(at, 1);\n          show(name, false);", "escrows[name].splice(at, 1);\n          show(name);", "ending an escrow offers the submit button again for the settle the node took"],
  // Review round 3 of the integration follow-up: the unknown outcome of a funding the page cannot match to
  // its request or whose document is gone, the deposit list of a wallet, the guard of the import, and the
  // time the trade has left to settle.
  ["M150", "actions.js", '      if (session !== target || started !== generation) {\n        throw new Error("The terms, the role or the node changed while the node was being read. Nothing was added; paste the signed text again.");\n      }\n', "", "the import adds signatures to a document that is no longer the one under review"],
  ["M151", "actions.js", "if (session !== target || started !== generation) {", "if (false || started !== generation) {", "the import does not see another document under review, made by a signature meanwhile"],
  ["M152", "actions.js", "if (left && !(e && e.nodeError === true)) {", "if (left) {", "the node's own refusal is read as an unknown outcome"],
  ["M153", "actions.js", "const left = sentRequest && (answered || (e && e.afterSend === true));", "const left = sentRequest && (e && e.afterSend === true);", "an answer the page cannot read or match is read as a refusal"],
  ["M154", "actions.js", "if (remembered) ctx.wallets.dropEscrow(deposit.wallet, txid);", "", "a refusal by the node leaves the deposit remembered"],
  ["M155", "actions.js", "if (remembered) ctx.wallets.dropEscrow(deposit.wallet, txid);", "if (deposit !== null) ctx.wallets.dropEscrow(deposit.wallet, txid);", "a refusal of a second submission forgets the deposit the first one made"],
  ["M156", "wallets.js", "escrows[name].push({ termsHash: info.termsHash, amount: info.amount, txid: info.txid, note: info.note });", "escrows[name] = [{ termsHash: info.termsHash, amount: info.amount, txid: info.txid, note: info.note }];", "funding a second trade from the same wallet forgets the first deposit"],
  ["M157", "wallets.js", "if (escrows[name].some((e) => e.txid === info.txid)) return false;", "", "a transaction submitted again is remembered as a second deposit"],
  ["M158", "wallets.js", "escrows[name].splice(at, 1);\n          show(name, false);\n          return;", "escrows[name] = escrows[name].filter((e) => e.termsHash !== termsHash);\n          show(name, false);", "a settle ends every deposit of the trade, though it spends one"],
  ["M159", "wallets.js", "escrows[name] = escrows[name].filter((e) => e.txid !== txid);", "escrows[name] = [];", "the node's refusal of one funding forgets every deposit of the wallet"],
  ["M160", "index.html", " A settle is refused at or after the expiry, so fund with time to spare: the review of the funding says how long the trade has left to settle.", "", "the page no longer says that a settle is refused at the expiry"],
  // Security fix: the network switch during a connection still opening.
  ["M161", "node.js", "    if (pending) pending.abort();\n", "", "closing does not abandon a connection still opening"],
  ["M162", "node.js", "      if (page !== this.network) {", "      if (false) {", "a request goes out on a connection checked for the other network"],
  ["M163", "app.js", "    const had = node.connected || node.connecting;\n    node.close();", "    const had = node.connected || node.connecting;\n    if (node.connected) node.close();", "the switch closes only an open connection, not one still opening"],
];

const sha = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

// The files of demo/dist the record names by hash.
const DIST_FILES = ["app.js", "main.js", "dom.js", "node.js", "wallets.js", "actions.js", "decoder.js", "config.js", "index.html", "decoder.html"];

/**
 * Kills `pid` and everything that descends from it. Playwright starts each browser in a session of
 * its own, so killing the runner's process group leaves the browsers behind as orphans, hundreds of
 * them over a run, until new ones no longer start: the descendants are found first and killed one
 * by one.
 */
function killTree(pid) {
  let table = "";
  try {
    table = execFileSync("ps", ["-Ao", "pid=,ppid="], { encoding: "utf8" });
  } catch {
    // no process table: the group kill below is all there is
  }
  const children = new Map();
  for (const line of table.split("\n")) {
    const [child, parent] = line.trim().split(/\s+/).map(Number);
    if (Number.isFinite(child) && Number.isFinite(parent)) children.set(parent, [...(children.get(parent) ?? []), child]);
  }
  const all = [pid];
  for (let i = 0; i < all.length; i += 1) all.push(...(children.get(all[i]) ?? []));
  for (const target of all.reverse()) {
    try {
      process.kill(target, "SIGKILL");
    } catch {
      // already gone
    }
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    // the group is gone
  }
}

// A suite that has not finished by then is killed and run again (a browser killed from outside
// leaves a runner waiting for ever): an answer needs a suite that ran to its end, or one that failed.
const SUITE_TIMEOUT_MS = Number(process.env.MUTATION_TIMEOUT_MS ?? 15 * 60 * 1000);
const ATTEMPTS = 3;

/**
 * Runs the browser suite against `distDir`. With `stopAtFirstFailure` the run is killed (the whole
 * process group, browsers included) as soon as a test is reported as failing, which is all a mutant
 * needs to be caught: the failures it lists are the ones reported by then, not every failing test.
 * The baseline, and a mutant that no test catches, run to the end. The run is also killed after
 * SUITE_TIMEOUT_MS, and says so (`timedOut`).
 */
function runSuite(distDir, { stopAtFirstFailure = false } = {}) {
  return new Promise((done) => {
    const child = spawn("node", ["--test", "--test-reporter=tap", ...testFiles.map((f) => join(here, "test", f))], {
      env: { ...process.env, IMPULSE_DIST: distDir },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let out = "";
    let pending = "";
    let stopped = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child.pid);
    }, SUITE_TIMEOUT_MS);
    const live = [];
    const read = (d) => {
      out += d;
      if (!stopAtFirstFailure || stopped) return;
      pending += d;
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) {
        const found = /^not ok \d+ - (.*)$/.exec(line);
        if (found !== null) live.push(found[1]);
      }
      if (live.length > 0) {
        stopped = true;
        killTree(child.pid);
      }
    };
    child.stdout.on("data", read);
    child.stderr.on("data", read);
    child.on("close", (code) => {
      clearTimeout(timer);
      const failed = stopped ? live : [...out.matchAll(/^not ok \d+ - (.*)$/gm)].map((m) => m[1]);
      const tests = Number(/^# tests (\d+)$/m.exec(out)?.[1] ?? 0);
      const pass = Number(/^# pass (\d+)$/m.exec(out)?.[1] ?? 0);
      done({ code, failed, tests, pass, timedOut });
    });
  });
}

async function mutate(m) {
  const [id, file, from, to] = m;
  const dir = mkdtempSync(join(tmpdir(), "impulse-mutant-"));
  try {
    cpSync(dist, dir, { recursive: true });
    const text = readFileSync(join(dir, file), "utf8");
    const parts = text.split(from);
    if (parts.length !== 2) throw new Error(`${id}: the edit target occurs ${parts.length - 1} times in ${file}`);
    writeFileSync(join(dir, file), parts.join(to));
    // Caught: a test failed. Survived: the suite ran to its end and every test passed. Anything
    // else (a timeout, a crashed runner, a count that does not add up) says nothing about the
    // mutant, and the suite is run again rather than read as a survivor.
    for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
      const result = await runSuite(dir, { stopAtFirstFailure: true });
      if (result.failed.length > 0) return result;
      if (!result.timedOut && result.code === 0 && result.tests > 0 && result.pass === result.tests) return result;
      process.stderr.write(`${id}: the suite did not finish (attempt ${attempt} of ${ATTEMPTS}${result.timedOut ? ", timed out" : `, exit ${result.code}, ${result.pass} of ${result.tests} passed`})\n`);
    }
    throw new Error(`${id}: the suite did not run to an answer in ${ATTEMPTS} attempts`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const record = process.argv.includes("--record");
const jobs = Number(process.env.MUTATION_JOBS ?? 3);
// --only=M63,M64: run those mutants alone, to check a new test against the mutants it is for. Such
// a run never writes the record.
const onlyArg = process.argv.find((a) => a.startsWith("--only="));
const only = onlyArg === undefined ? null : onlyArg.slice("--only=".length).split(",");
if (only !== null && record) {
  console.error("--only does not write the record");
  process.exit(2);
}
if (only !== null && !only.every((id) => MUTANTS.some((m) => m[0] === id))) {
  console.error(`--only names a mutant that does not exist: ${only.join(",")}`);
  process.exit(2);
}
const run = only === null ? MUTANTS : MUTANTS.filter((m) => only.includes(m[0]));

// --check: only confirm that every edit target occurs exactly once in its file of demo/dist.
if (process.argv.includes("--check")) {
  let bad = 0;
  for (const [id, file, from] of MUTANTS) {
    const n = readFileSync(join(dist, file), "utf8").split(from).length - 1;
    if (n !== 1) {
      bad += 1;
      console.error(`${id}: the edit target occurs ${n} times in ${file}`);
    }
  }
  console.log(`${MUTANTS.length} mutants, ${bad} with an edit target that does not occur exactly once`);
  process.exit(bad === 0 ? 0 : 1);
}

// --verify-record: the record is of these sources. It names every page file, every test file and this
// file by hash; each must be what is on disk now. It names every mutant of the list, and each is
// caught by a named test or is one of the edits marked as one no page can observe. It runs no
// browser. scripts/ci-local.sh (through demo/ci.sh) fails if it does not hold, so a record goes
// stale the moment a source changes, and is made again with --record.
if (process.argv.includes("--verify-record")) {
  const record = readFileSync(join(here, "mutation-run.txt"), "utf8");
  const problems = [];
  const named = [
    ...DIST_FILES.map((f) => [f, join(dist, f)]),
    ...testFiles.map((f) => [`test/${f}`, join(here, "test", f)]),
    ["mutation.mjs", fileURLToPath(import.meta.url)],
  ];
  for (const [name, file] of named) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const found = new RegExp(`^${escaped} sha256 ([0-9a-f]{64})$`, "m").exec(record);
    if (found === null) problems.push(`${name}: the record has no hash for it`);
    else if (found[1] !== sha(file)) problems.push(`${name}: changed since the record was made`);
  }
  const header = /^mutants (\d+), test target demo\/test\/\*\.test\.ts \((\d+) tests\)$/m.exec(record);
  if (header === null || Number(header[1]) !== MUTANTS.length) {
    problems.push(`the record is of ${header?.[1] ?? "no"} mutants, the list has ${MUTANTS.length}`);
  }
  const baseline = /^baseline: (\d+) of (\d+) pass$/m.exec(record);
  if (baseline === null || baseline[1] !== baseline[2] || (header !== null && baseline[2] !== header[2])) {
    problems.push("the record's baseline did not pass every test");
  }
  for (const m of MUTANTS) {
    const at = record.indexOf(`\n[${m[0]}] `);
    const end = at < 0 ? -1 : record.indexOf("\n[M", at + 1);
    const block = at < 0 ? "" : record.slice(at, end < 0 ? record.indexOf("\nresult:", at) : end);
    if (at < 0) problems.push(`${m[0]}: not in the record`);
    else if (m[5] === undefined && !/\n {2}caught by \(\d+\): /.test(block)) problems.push(`${m[0]}: the record does not have it caught`);
    else if (m[5] !== undefined && !/\n {2}SURVIVED, equivalent: /.test(block)) problems.push(`${m[0]}: marked as an edit no page can observe, and the record does not say so`);
  }
  const survived = (record.match(/^ {2}SURVIVED/gm) ?? []).length;
  const equivalent = MUTANTS.filter((m) => m[5] !== undefined).length;
  if (survived !== equivalent) problems.push(`the record has ${survived} survivors, the list names ${equivalent} as equivalent`);
  if (problems.length > 0) {
    for (const p of problems) console.error(`mutation record: ${p}`);
    process.exit(1);
  }
  console.log(`mutation record matches: ${MUTANTS.length} mutants, ${named.length} sources`);
  process.exit(0);
}

// The baseline must pass whole. A test that fails on a machine under load and passes again is
// run again (ATTEMPTS times); the record is of the run that passed.
let baseline;
for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
  baseline = await runSuite(dist);
  if (!baseline.timedOut && baseline.code === 0 && baseline.failed.length === 0) break;
  console.error(`baseline attempt ${attempt} of ${ATTEMPTS}: ${baseline.timedOut ? "timed out" : baseline.failed.join("; ")}`);
}
if (baseline.timedOut || baseline.code !== 0 || baseline.failed.length > 0) {
  console.error(`baseline fails: ${baseline.failed.join("; ")}`);
  process.exit(1);
}
const results = new Array(run.length);
let next = 0;
await Promise.all(
  Array.from({ length: jobs }, async () => {
    while (next < run.length) {
      const i = next++;
      results[i] = await mutate(run[i]);
      process.stderr.write(`${run[i][0]} ${results[i].failed.length > 0 ? "caught" : "SURVIVED"}\n`);
    }
  }),
);

const lines = [
  "Mutation run, demo/dist (demo/mutation.mjs)",
  ...DIST_FILES.map((f) => `${f} sha256 ${sha(join(dist, f))}`),
  ...testFiles.map((f) => `test/${f} sha256 ${sha(join(here, "test", f))}`),
  `mutation.mjs sha256 ${sha(fileURLToPath(import.meta.url))}`,
  `mutants ${run.length}, test target demo/test/*.test.ts (${baseline.tests} tests)`,
  "",
  `baseline: ${baseline.pass} of ${baseline.tests} pass`,
  "",
];
let caught = 0;
let equivalent = 0;
run.forEach((m, i) => {
  const r = results[i];
  lines.push(`[${m[0]}] ${m[1]}: ${m[4]}`);
  if (r.failed.length > 0) {
    caught += 1;
    lines.push(`  caught by (${r.failed.length}): ${r.failed.join(" | ")}`);
  } else if (m[5] !== undefined) {
    equivalent += 1;
    lines.push(`  SURVIVED, ${m[5]}`);
  } else {
    lines.push("  SURVIVED");
  }
});
lines.push(
  "",
  `result: ${caught} of ${run.length} mutants caught by the browser tests` +
    (equivalent > 0 ? `, ${equivalent} survived as an edit no page can observe (named above)` : ""),
  "",
);
const text = lines.join("\n");
if (record) writeFileSync(join(here, "mutation-run.txt"), text);
process.stdout.write(text);
process.exit(caught + equivalent === run.length ? 0 : 3);
