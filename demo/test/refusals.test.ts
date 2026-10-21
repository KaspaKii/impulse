// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What the page refuses when it connects to a node, builds, signs and submits, each refusal beside
// the accepted control that differs from it in the one thing refused. The codes are the SDK's: the
// page shows them, it does not make them.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { FakeNode } from "../../crates/impulse-wasm/npm/test/fakenode.ts";
import { launch, open, termsVector, type NodeHandler } from "./harness.ts";
import { partyFor, type PartyTerms } from "./party.ts";
import {
  NODE_HREF,
  NODE_URL,
  actionStatus,
  build,
  connect,
  frames,
  prepare,
  rows,
  sdkOf,
  signWith,
  submitAndWait,
  text,
  withTrade,
} from "./session.ts";
import { ASSET_ARTIFACT, KAS_CASH, addressFor } from "./world.ts";
import type { Browser } from "playwright-core";

let browser: Browser;
before(async () => {
  browser = await launch();
});
after(async () => {
  await browser.close();
});

test("the page opens a socket only to a URL the SDK allows, and only a node on the network, synced, is used", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    // Refused before any socket is opened.
    for (const url of ["http://127.0.0.1:1", "127.0.0.1:1", "ws://", "ws://a b", ""]) {
      const r = await connect(page, url);
      assert.deepEqual([r.state, r.code], ["error", "SDK_NODE_URL_INVALID"], JSON.stringify(url));
    }
    assert.deepEqual(s.contacted, [], "no socket for any of them");
    // A node on another network, and one that is not synced: refused after it answers, and the
    // connection is not kept.
    fake.networkId = "mainnet";
    const wrong = await connect(page);
    assert.deepEqual([wrong.state, wrong.code], ["error", "SDK_NODE_NETWORK_MISMATCH"]);
    fake.networkId = "devnet";
    assert.equal((await connect(page)).code, "SDK_NODE_NETWORK_MISMATCH", "a devnet is no network of the page");
    fake.networkId = "testnet-10";
    fake.synced = false;
    const unsynced = await connect(page);
    assert.deepEqual([unsynced.state, unsynced.code], ["error", "SDK_NODE_NOT_SYNCED"]);
    fake.synced = true;
    // The control: the node typed, on the page's network, synced.
    const ok = await connect(page);
    assert.equal(ok.state, "connected", ok.text);
    assert.equal(ok.text, "Connected to ws://127.0.0.1:1: testnet-10, synced, at DAA score 1500000.");
    // A node that cannot list UTXOs says so.
    fake.hasUtxoIndex = false;
    assert.match((await connect(page)).text, /The node has no UTXO index/);
    fake.hasUtxoIndex = true;
    // Every socket the page opened went to the node typed.
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
    assert.equal(s.contacted.length, 5, "one socket for each of the five connections that got past the URL check");
  });
});

test("on mainnet the page opens a socket only over wss, or over ws to localhost or 127.0.0.1 (not the IPv6 literal)", async () => {
  await withTrade("vault", async (t) => {
    const { page, s } = t;
    await page.check("#mainnet-switch");
    const insecure = await connect(page, "ws://203.0.113.9:17110");
    assert.deepEqual([insecure.state, insecure.code], ["error", "SDK_NODE_INSECURE"]);
    assert.deepEqual(s.contacted, [], "no socket to a plaintext host on mainnet");
    // The IPv6 loopback literal is refused like any other plaintext host, before a socket (owner
    // decision 2026-10-11: the page's policy cannot name it); localhost below is the control.
    for (const url of ["ws://[::1]:17110", "ws://[::1]"]) {
      const v6 = await connect(page, url);
      assert.deepEqual([v6.state, v6.code], ["error", "SDK_NODE_INSECURE"], url);
    }
    assert.deepEqual(s.contacted, [], "no socket to the IPv6 loopback literal on mainnet");
    // A wss URL is allowed: a socket is opened to exactly that URL (the test node closes it).
    const secure = await connect(page, "wss://node.example:443/ws");
    assert.equal(secure.state, "error");
    assert.equal(secure.code, "");
    assert.deepEqual(s.contacted, [new URL("wss://node.example:443/ws").href]);
    // Control: localhost over ws:// passes the URL check, and a socket is opened to it.
    const localhost = await connect(page, "ws://localhost:17110");
    assert.deepEqual([localhost.state, localhost.code], ["error", ""]);
    assert.deepEqual(s.contacted, [new URL("wss://node.example:443/ws").href, new URL("ws://localhost:17110").href]);
    // To this machine over ws: the testnet node of the test answers as a testnet node, so the
    // mainnet check refuses it after the socket opened.
    const local = await connect(page, NODE_URL);
    assert.deepEqual([local.state, local.code], ["error", "SDK_NODE_NETWORK_MISMATCH"]);
  });
});

test("switching the network closes the connection, and the page then builds nothing until it connects again", async () => {
  await withTrade("vault", async (t) => {
    const { page } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok", "control: connected, built");
    await page.check("#mainnet-switch");
    assert.equal(await page.getAttribute("#node-status", "data-state"), "idle");
    assert.equal(await text(page, "#node-status"), "Disconnected: the network changed. Connect again.");
    await page.uncheck("#mainnet-switch");
    // Back on the network the terms name; the document built before is gone with the terms check.
    await page.fill("#kas-equivalent", KAS_CASH.toString());
    await page.waitForSelector("#status[data-state='ok']");
    const refused = await build(page);
    assert.equal(refused.state, "refused");
    assert.equal(refused.code, "");
    assert.match(refused.text, /^Not done: Connect to a node first/);
    assert.equal(await page.isVisible("#review-panel"), false);
    assert.equal((await connect(page)).state, "connected");
    assert.equal((await build(page)).state, "ok");
  });
});

test("building refuses what it cannot build, each beside the build that works", async () => {
  await withTrade("vault", async (t) => {
    const { page, keys } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok", "control");

    // No token artifact: nothing can be checked, so nothing is built.
    await page.fill("#asset-artifact", "");
    let r = await build(page);
    assert.deepEqual([r.state, r.code], ["refused", "TX_TOKEN_TEMPLATE"]);
    assert.equal(await page.isVisible("#review-panel"), false, "a refused build leaves no review");
    await page.fill("#asset-artifact", "{}");
    assert.equal((await build(page)).code, "TX_TOKEN_TEMPLATE");
    await page.fill("#asset-artifact", ASSET_ARTIFACT);
    assert.equal((await build(page)).state, "ok");

    // The fee: below the minimum, not a number, and the control "auto".
    await page.fill("#fee", "1");
    assert.deepEqual([(await build(page)).state, (await actionStatus(page)).code], ["refused", "TX_FEE_TOO_LOW"]);
    await page.fill("#fee", "abc");
    assert.equal((await build(page)).code, "SDK_JSON_FORM");
    await page.fill("#fee", "auto");
    assert.equal((await build(page)).state, "ok");

    // The native KAS a transaction moves counts toward the cap: a fee of exactly the cap builds, a
    // sompi more is refused before anything is built.
    await page.fill("#fee", "1000000000");
    assert.equal((await build(page)).state, "ok", "a fee at the cap of 10 KAS");
    await page.fill("#fee", "1000000001");
    r = await build(page);
    assert.deepEqual([r.state, r.code], ["refused", "SDK_VALUE_CAP_EXCEEDED"]);
    assert.equal(await page.isVisible("#review-panel"), false);
    await page.fill("#fee", "auto");
    assert.equal((await build(page)).state, "ok");

    // A fee payer that holds no UTXO of its own pays nothing.
    await page.selectOption("#fee-payer", { value: "a" });
    r = await build(page);
    assert.equal(r.state, "refused");
    assert.equal(r.code, "TX_KAS_INPUT");
    await page.selectOption("#fee-payer", { value: "b" });
    assert.equal((await build(page)).state, "ok");

    // A fee payer whose wallet is wiped.
    await page.click("#wallet-b .wallet-wipe");
    r = await build(page);
    assert.deepEqual([r.state, r.code], ["refused", ""]);
    assert.match(r.text, /^Not done: Choose a wallet that holds a key to pay the fee\.$/);
    await page.click("#wallet-b .wallet-generate");
    assert.notEqual(await text(page, "#wallet-b .wallet-key"), keys.b, "a new key, not the old one");

    // The new wallet B holds nothing on the node: it cannot pay a fee.
    r = await build(page);
    assert.equal(r.state, "refused");
    assert.equal(r.code, "TX_KAS_INPUT");
  });
});

test("a UTXO the node does not report is SDK_UTXO_NOT_FOUND, beside the same trade with it", async () => {
  await withTrade("direct", async (t) => {
    const { page, fake } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok", "control: the node holds the seller's token, the buyer's cash and the fee UTXO");
    const held = (fake as unknown as { held: Map<string, { utxo: { amount: string }; spent: boolean }> }).held;
    const cash = [...held.values()].find((h) => h.utxo.amount === KAS_CASH.toString());
    assert.ok(cash);
    cash.spent = true;
    const r = await build(page);
    assert.deepEqual([r.state, r.code], ["refused", "SDK_UTXO_NOT_FOUND"]);
    assert.match(r.text, /no UTXO of exactly 100000000 sompi at the buyer's key/);
    assert.equal(await page.isVisible("#review-panel"), false);
    cash.spent = false;
    assert.equal((await build(page)).state, "ok");
  });
});

test("nothing is offered until the user is known and the value is within the cap; a change of terms drops the review", async () => {
  await withTrade("vault", async (t) => {
    const { page, keys } = t;
    await prepare(t);
    assert.equal(await page.isVisible("#actions"), true, "control");
    assert.equal((await build(page)).state, "ok");
    assert.equal(await page.isVisible("#review-panel"), true);
    // A change of the terms drops the document: it is not the document of these terms any more.
    await page.fill('[data-path="nonce"]', "7");
    assert.equal(await page.isVisible("#review-panel"), false);
    assert.equal(await page.isVisible("#actions"), true, "the terms are still within the checks");
    await page.fill('[data-path="nonce"]', "1313131313");
    // Above the cap: refused by the SDK, and the actions are not offered.
    await page.fill("#kas-equivalent", "1000000001");
    await page.waitForSelector("#status[data-state='refused']");
    assert.equal(await page.getAttribute("#status", "data-code"), "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(await page.isVisible("#actions"), false);
    await page.fill("#kas-equivalent", "1000000000");
    await page.waitForSelector("#status[data-state='ok']");
    assert.equal(await page.isVisible("#actions"), true, "at the cap");
    // Not the key of the role: refused, and not offered.
    await page.fill("#my-key", keys.a);
    await page.waitForSelector("#status[data-state='refused']");
    assert.equal(await page.getAttribute("#status", "data-code"), "SDK_ROLE_KEY_MISMATCH");
    assert.equal(await page.isVisible("#actions"), false);
    await page.fill("#my-key", keys.b);
    await page.waitForSelector("#status[data-state='ok']");
    assert.equal(await page.isVisible("#actions"), true);
    // No role: the same.
    await page.selectOption("#role", { value: "" });
    assert.equal(await page.isVisible("#actions"), false);
    await page.selectOption("#role", { value: "buyer" });
    assert.equal(await page.isVisible("#actions"), true);
  });
});

test("a wallet wiped after the build can no longer sign; the document says whose key is missing", async () => {
  await withTrade("direct", async (t) => {
    const { page, keys, fake } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await page.locator('#sign-buttons button[data-wallet="a"]').count(), 1, "control: wallet A can sign");
    await page.click("#wallet-a .wallet-wipe");
    assert.equal(await page.locator('#sign-buttons button[data-wallet="a"]').count(), 0);
    await signWith(page, "b");
    assert.equal(await page.isDisabled("#submit"), true, "an input is still unsigned");
    assert.match(
      (await text(page, "#review-pending")) ?? "",
      new RegExp(`^Inputs still unsigned: 0\\. 1 of them needs a key this page does not hold \\(${keys.a}\\): hand the partially signed transaction to its holder \\(the copy button below puts it on your clipboard, impulse ipst sign signs it, and the signatures are added back under this review\\)\\.$`),
    );
    // The partially signed transaction is there to hand over, and it holds the buyer's signatures only.
    const ipst = JSON.parse((await text(page, "#ipst-text")) ?? "{}") as { inputs: { signature: string | null }[] };
    assert.deepEqual(ipst.inputs.map((i) => i.signature !== null), [false, true, true]);
    assert.equal(fake.accepted.length, 0);
  });
});

test("the node refusing the transaction, or naming another, is shown and nothing is claimed", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    await signWith(page, "b");
    // The node rejects it, in words that carry a control sequence.
    fake.rejectNext = "mempool is full\u001b[2J";
    const rejected = await submitAndWait(page);
    assert.deepEqual([rejected.state, rejected.code], ["refused", "SDK_RPC_REPLY"]);
    assert.match(rejected.text, /mempool is full/);
    assert.ok(!/[\u0000-\u001f]/.test(rejected.text), "the node's words arrive escaped");
    assert.equal(fake.accepted.length, 0);
    assert.equal(await page.isDisabled("#submit"), false, "the signed document is still there to send again");
    // The node takes it but names another transaction in its answer: the page does not call that a
    // success, and it does not call it a refusal either, because the node did take something. The
    // outcome is unknown, with the ID of the transaction the page signed, not the one the node named.
    t.handler.current = (request) => {
      const reply = fake.handle(request);
      const frame = JSON.parse(reply) as { method?: string; params?: { transactionId?: string } };
      if (frame.method === "submitTransaction") frame.params = { transactionId: "ab".repeat(32) };
      return JSON.stringify(frame);
    };
    await page.click("#submit");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
    const forged = (await text(page, "#submit-status")) ?? "";
    assert.ok(forged.startsWith("Outcome unknown: SDK_TXID_MISMATCH: the node returned "), forged);
    assert.ok(!forged.startsWith("Submitted"));
    assert.equal(fake.accepted.length, 1, "the node did take the document");
    const signedId = fake.accepted[0].txid;
    assert.ok(forged.includes(`Its ID is ${signedId}.`), forged);
    assert.equal(await page.getAttribute("#submit-status a", "href"), `decoder.html#txid=${signedId}&from=${fake.genesis}`, "the link names the transaction the page signed, not the one the node named");
    assert.ok(!forged.includes(`Its ID is ${"ab".repeat(32)}`));
    assert.equal(await page.isDisabled("#submit"), true, "submit stays off until the node is asked");
    // Asked, the node does not have it in its mempool (it is in a block), and a second submit is offered.
    t.handler.current = (request) => fake.handle(request);
    await page.click("#submit-check");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "wait");
    assert.equal(await page.isDisabled("#submit"), false);
    // A node that has the transaction already answers with an error for the second submit.
    const again = await submitAndWait(page);
    assert.deepEqual([again.state, again.code], ["refused", "SDK_RPC_REPLY"]);
    assert.equal(fake.accepted.length, 1, "the forged answer's request did reach the node once");
    assert.equal(frames(s).filter((f) => f.method === "submitTransaction").length, 3);
  });
});

test("the creation DAA score of mainnet terms is accepted only if the connected node gave it", async () => {
  const sdk = await sdkOf();
  const fake = new FakeNode(sdk as never, addressFor("mainnet"), "mainnet");
  fake.networkId = "mainnet";
  fake.virtualDaa = 400_000_001;
  const handler: NodeHandler = (request) => fake.handle(request);
  const s = await open(browser, "index.html", {}, undefined, { [NODE_URL]: handler });
  try {
    const { page } = s;
    const terms = structuredClone(termsVector("02").terms) as Record<string, any>;
    for (const leg of [terms.asset_leg, terms.cash_leg]) {
      if (leg.kind === "kas" && BigInt(leg.amount) > 1_000_000_000n) leg.amount = "100000000";
    }
    const party = partyFor("buyer", terms as unknown as PartyTerms);
    await page.check("#mainnet-switch");
    await page.selectOption("#role", { value: party.role });
    await page.fill("#my-key", party.key);
    await page.click("#you details > summary");
    await page.fill("#pin-receive", party.receive);
    await page.fill("#pin-refund", party.refund);
    await page.fill("#terms-json", JSON.stringify(terms));
    await page.click("#load-json");
    await page.fill("#kas-equivalent", "100000000");
    // Typed: refused on mainnet, whatever the score.
    await page.fill("#creation-daa", "400000000");
    await page.waitForSelector("#status[data-state='refused']");
    assert.equal(await page.getAttribute("#status", "data-code"), "SDK_MAINNET_NEEDS_NODE");
    assert.equal(await page.isVisible("#actions"), false);
    // Read from the node: accepted, and the page says where the score came from.
    assert.equal((await connect(page)).state, "connected");
    await page.click("#read-daa");
    await page.waitForSelector("#status[data-state='ok']");
    assert.equal(await page.inputValue("#creation-daa"), "400000001");
    assert.equal(await text(page, "#summary dd:nth-of-type(6)"), `400000001 (read from the node at ${NODE_URL})`);
    // Edited: typed again, refused again.
    await page.fill("#creation-daa", "400000002");
    await page.waitForSelector("#status[data-state='refused']");
    assert.equal(await page.getAttribute("#status", "data-code"), "SDK_MAINNET_NEEDS_NODE");
    // The switch off: the connection is closed and a score read before is not one any more.
    await page.click("#read-daa");
    await page.waitForSelector("#status[data-state='ok']");
    await page.uncheck("#mainnet-switch");
    assert.equal(await page.getAttribute("#node-status", "data-state"), "idle");
    await page.waitForSelector("#status[data-state='refused']");
    assert.equal(await page.getAttribute("#status", "data-code"), "TERMS_NETWORK_MISMATCH");
    // A node that is not on the network gives no score to read.
    await page.check("#mainnet-switch");
    fake.networkId = "testnet-10";
    const wrong = await connect(page);
    assert.equal(wrong.code, "SDK_NODE_NETWORK_MISMATCH");
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
  } finally {
    await s.close();
  }
});

test("the page reads a wallet's balance from the node, and says so when it cannot", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    const balance = "#wallet-b .wallet-balance";
    // Not connected: the page says it could not read, and shows no figure.
    await page.click("#wallet-b .wallet-refresh");
    await page.waitForFunction(() => (document.querySelector("#wallet-b .wallet-balance")?.textContent ?? "") !== "");
    assert.equal(await text(page, balance), "Not read: Not connected to a node.");
    assert.equal((await connect(page)).state, "connected");
    await page.click("#wallet-b .wallet-refresh");
    await page.waitForFunction(() => (document.querySelector("#wallet-b .wallet-balance")?.textContent ?? "").startsWith("11"));
    // The buyer holds the cash UTXO (1 KAS) and the fee UTXO (10 KAS).
    assert.equal(await text(page, balance), "11.00000000 KAS in 2 UTXOs, as the node reports");
    await page.click("#wallet-a .wallet-refresh");
    await page.waitForFunction(() => (document.querySelector("#wallet-a .wallet-balance")?.textContent ?? "") !== "");
    assert.equal(await text(page, "#wallet-a .wallet-balance"), "0.00000000 KAS in 0 UTXOs, as the node reports");
    // The rows of the review for a document that was never built are empty.
    assert.deepEqual(await rows(page, "#review-inputs-body"), []);
  });
});
