// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// A whole trade through the package and an offline node, with wallets of the SDK for every key:
// ask the node for the UTXOs, build, review, sign with the wallets, submit the signed transaction
// to the fake node (test/fakenode.ts), read what it accepted back from the node and decode it.
// This is the sequence the browser demo runs, without the page. The fake node runs no script and
// checks no signature (its header says what it does check); the signatures here are verified by
// the SDK as each wallet adds its own.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Ipst, SignOptionsJson, SignedTransaction, Wallet } from "../index.js";
import { FakeNode } from "./fakenode.ts";
import type { FakeUtxo } from "./fakenode.ts";
import { AMOUNT_A, ASSET_COV, KAS_CASH, NOW, VALUE, p2pk, utxo } from "./fixtures.ts";
import { hex, load, refusalError } from "./sdk.ts";
import { MODES, addressFor, freeAll, world } from "./world.ts";
import type { World } from "./world.ts";

const sdk = load();
const daa = NOW.toString();
/** The transaction ID of the cash vault UTXO the worlds hold (`utxo("cash-vault", ...)`). */
const cashVaultId = createHash("sha256").update("cash-vault").digest("hex");

/** A node holding the world's UTXOs, at the world's network and at the DAA score the tests use. */
function nodeFor(w: World): FakeNode {
  const node = new FakeNode(sdk, addressFor(w.network), w.network);
  node.networkId = w.network === "mainnet" ? "mainnet" : "testnet-10";
  node.virtualDaa = Number(NOW);
  for (const u of w.pool) node.add(u);
  return node;
}

let nextId = 100;
/** Sends one request and returns the node's answer text. */
function call(node: FakeNode, method: Parameters<typeof sdk.rpcRequest>[1], argument?: unknown) {
  const id = nextId++;
  return { id, text: node.handle(sdk.rpcRequest(id, method, argument)) };
}

function options(w: World, over: Partial<SignOptionsJson> = {}): SignOptionsJson {
  return { artifacts: w.artifacts, current_daa: daa, value: VALUE, mainnet: w.network === "mainnet", ...over };
}

/** The page's sequence up to a built document: the node's score, the addresses, the UTXOs, the build. */
function build(w: World, node: FakeNode, kind: "settle" | "direct", payer: Wallet = w.wallets.payer): Ipst {
  const info = call(node, "getServerInfo", null);
  const server = sdk.rpcReply(info.text, info.id, "getServerInfo") as { network: string; virtual_daa_score: string };
  sdk.checkNode(server as never, w.network);
  const key = payer.publicKey();
  const addresses = kind === "settle" ? w.terms.settleAddresses(w.artifacts, key) : w.terms.directAddresses(w.artifacts, key);
  const utxos = call(node, "getUtxosByAddresses", addresses);
  const funding = { payer: key, fee: "auto" };
  return kind === "settle"
    ? w.terms.settleFromReply(w.artifacts, utxos.text, funding, server.virtual_daa_score, VALUE)
    : w.terms.directFromReply(w.artifacts, utxos.text, funding, server.virtual_daa_score, VALUE);
}

/** Signs with every wallet that has something to sign, in the order given. */
function signAll(w: World, ipst: Ipst, order: Wallet[]): Ipst {
  return order.reduce((doc, wallet) => {
    return doc.pending().some((i) => doc.slots()[i].signer === wallet.publicKey()) ? wallet.sign(doc, options(w)).ipst : doc;
  }, ipst);
}

function submit(node: FakeNode, signed: SignedTransaction) {
  const id = nextId++;
  const text = node.handle(sdk.rpcSubmitRequest(id, signed));
  return { id, text };
}

test("a Direct trade: ask, build, review, sign with both wallets and the payer, submit, and the node holds the outputs", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const node = nodeFor(w);
    const ipst = build(w, node, "direct");
    const review = ipst.review(w.artifacts, daa, VALUE);
    assert.deepEqual(review.kind, { builder: "direct" });
    const signed = signAll(w, ipst, [w.wallets.seller, w.wallets.buyer, w.wallets.payer]);
    assert.equal(signed.isComplete(), true);
    const tx = signed.finalize();
    const sent = submit(node, tx);
    assert.equal(sdk.rpcSubmitReply(sent.text, sent.id, tx), hex(tx.txid()), "the node names the transaction submitted");
    // The node saw one submit, and no orphan was allowed.
    const received = node.received.filter((r) => r.method === "submitTransaction");
    assert.equal(received.length, 1);
    assert.equal((received[0].params as { allowOrphan: boolean }).allowOrphan, false);
    // What it holds now: the seller has the cash, the buyer the token, the inputs are gone.
    const accepted = node.accepted[0];
    assert.equal(accepted.txid, hex(tx.txid()));
    const proceeds = node.at(w.wallets.seller.address(w.network));
    assert.equal(proceeds.map((u) => u.amount).filter((a) => a === KAS_CASH.toString()).length, 1);
    assert.equal(node.at(w.wallets.buyer.address(w.network)).length, 0, "the buyer's cash UTXO is spent; the delivery is a token, not at its address");
    assert.equal(node.at(w.wallets.payer.address(w.network)).map((u) => u.amount).length, 1, "the payer's change");
    // Direct spends no vault, so there is nothing for the decoder to read.
    assert.equal(accepted.decoded, null);
    // The same transaction cannot be submitted twice: its inputs are spent.
    const again = submit(node, tx);
    assert.equal(refusalError(() => sdk.rpcSubmitReply(again.text, again.id, tx)).code, "SDK_RPC_REPLY");
  } finally {
    freeAll(w.wallets);
  }
});

test("a Vault trade: settle, sign with the authority and the payer, submit, and the decoder reads the trade back from the node", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    const ipst = build(w, node, "settle");
    const signed = signAll(w, ipst, [w.wallets.authority, w.wallets.payer]);
    const tx = signed.finalize();
    const sent = submit(node, tx);
    const txid = sdk.rpcSubmitReply(sent.text, sent.id, tx);
    // The node's own decoding at acceptance, bound to the scripts it spent.
    const accepted = node.accepted[0].decoded as { bound: boolean; legs: { leg: number; outcome: { kind: string; amount?: string } }[] };
    assert.equal(accepted.bound, true);
    assert.deepEqual(accepted.legs.map((l) => [l.leg, l.outcome.kind, l.outcome.amount]), [
      [0, "delivered", AMOUNT_A.toString()],
      [1, "delivered", KAS_CASH.toString()],
    ]);
    // The decoder page's path: the chain from the block before, filtered to the transaction asked for.
    const chain = call(node, "getVirtualChainFromBlockV2", node.genesis);
    const found = sdk.rpcTransactionReply(chain.text, chain.id, "getVirtualChainFromBlockV2", txid) as {
      added: string[];
      removed: string[];
      transaction: { txid: string; raw: string; spent: ({ version: number; script: string } | null)[] } | null;
      accepting_block: { hash: string | null; daa_score: string | null } | null;
    };
    assert.equal(found.added.length, 1);
    assert.deepEqual(found.accepting_block, { hash: node.blockHash(1), daa_score: daa });
    assert.deepEqual(found.removed, []);
    assert.ok(found.transaction !== null, "the accepted transaction is in the chain reply");
    assert.equal(found.transaction.txid, txid);
    assert.ok(found.transaction.spent.every((s) => s !== null), "the node gave every scriptPublicKey spent");
    const decoded = sdk.decodeFetched(found.transaction, txid, w.network);
    assert.equal(decoded.bound, true);
    assert.equal(decoded.txid, txid);
    assert.equal(decoded.legs.length, 2);
    assert.deepEqual(decoded.legs.map((l) => l.terms_hash), [hex(w.terms.termsHash()), hex(w.terms.termsHash())]);
    assert.deepEqual(decoded.refused, []);
    // Asked for a transaction that is not there: null, and a transaction the node swapped is refused.
    const absent = sdk.rpcTransactionReply(chain.text, chain.id, "getVirtualChainFromBlockV2", "ab".repeat(32)) as { transaction: unknown };
    assert.equal(absent.transaction, null);
    assert.equal(
      refusalError(() => sdk.decodeFetched(found.transaction as never, "ab".repeat(32), w.network)).code,
      "SDK_TXID_MISMATCH",
    );
    // A start block the node does not know is the node's error, passed on.
    const unknown = call(node, "getVirtualChainFromBlockV2", "cd".repeat(32));
    assert.equal(refusalError(() => sdk.rpcTransactionReply(unknown.text, unknown.id, "getVirtualChainFromBlockV2", txid)).code, "SDK_RPC_REPLY");
    // The vault UTXOs are spent and the trade's outputs are the node's.
    assert.deepEqual(node.at(w.terms.instantiateForCreation(0, { network: w.network, creation_daa: (NOW - 1n).toString() }, VALUE).address()), []);
    assert.equal(node.at(w.wallets.seller.address(w.network)).length >= 1, true);
  } finally {
    freeAll(w.wallets);
  }
});

test("a transaction pending in the mempool is read by its ID and decoded, not bound to what it spends", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    node.autoAccept = false;
    const tx = signAll(w, build(w, node, "settle"), [w.wallets.authority, w.wallets.payer]).finalize();
    const sent = submit(node, tx);
    const txid = sdk.rpcSubmitReply(sent.text, sent.id, tx);
    assert.equal(node.accepted.length, 0, "not accepted yet");
    const entry = call(node, "getMempoolEntry", txid);
    const got = sdk.rpcTransactionReply(entry.text, entry.id, "getMempoolEntry", txid) as {
      fee: string;
      is_orphan: boolean;
      transaction: { txid: string; raw: string; spent: unknown[] };
    };
    assert.equal(got.is_orphan, false);
    assert.equal(got.fee, signAll(w, build(w, nodeFor(w), "settle"), []).fee(), "the fee the node computes is the one built");
    assert.equal(got.transaction.txid, txid);
    assert.deepEqual(got.transaction.spent, [null, null, null, null]);
    const decoded = sdk.decodeFetched(got.transaction as never, txid, w.network);
    assert.equal(decoded.bound, false, "the mempool names no spent scripts, so the decoding is not bound");
    assert.equal(decoded.legs.length, 2);
    // Another ID than the one asked for is refused.
    assert.equal(refusalError(() => sdk.rpcTransactionReply(entry.text, entry.id, "getMempoolEntry", "ab".repeat(32))).code, "SDK_TXID_MISMATCH");
    // An ID the node does not hold is the node's "not found" and has its own code ...
    const missing = call(node, "getMempoolEntry", "ab".repeat(32));
    const absent = refusalError(() => sdk.rpcTransactionReply(missing.text, missing.id, "getMempoolEntry", "ab".repeat(32)));
    assert.equal(absent.code, "SDK_RPC_NOT_FOUND");
    assert.equal(absent.message, `SDK_RPC_NOT_FOUND: getMempoolEntry: the node does not have the transaction ${"ab".repeat(32)}`);
    // ... and nothing else is mistaken for it: another error of the node, the same words about
    // another transaction, a reply that cannot be read, and the same error to another call.
    const error = (message: string, id = missing.id) => JSON.stringify({ id, error: { code: -32000, message } });
    for (const [what, frame] of [
      ["another error", error("the mempool is busy")],
      ["not found for another transaction", error(`Transaction ${"cd".repeat(32)} not found`)],
      ["the words with more after them", error(`Transaction ${"ab".repeat(32)} not found.`)],
      ["not JSON", "{"],
      ["no params", JSON.stringify({ id: missing.id, method: "getMempoolEntry" })],
    ] as const) {
      assert.equal(refusalError(() => sdk.rpcTransactionReply(frame, missing.id, "getMempoolEntry", "ab".repeat(32))).code, "SDK_RPC_REPLY", what);
    }
    const sameWords = error(`Transaction ${"ab".repeat(32)} not found`);
    assert.equal(refusalError(() => sdk.rpcTransactionReply(sameWords, missing.id, "getMempoolEntry", "ab".repeat(32))).code, "SDK_RPC_NOT_FOUND", "control");
    assert.equal(refusalError(() => sdk.rpcReply(sameWords, missing.id, "getBlockDagInfo")).code, "SDK_RPC_REPLY", "the words answer getMempoolEntry only");
    // The node mines it; the chain now carries it, bound.
    node.mine(txid);
    assert.equal(node.accepted.length, 1);
  } finally {
    freeAll(w.wallets);
  }
});

test("a refund is submitted and decodes as refunded; a lock time in the future is the node's refusal until its score passes", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    const key = w.wallets.payer.publicKey();
    const refundOf = (signer: "depositor" | "counterparty") => {
      const addresses = w.terms.refundAddresses(1, w.artifacts, key);
      const utxos = call(node, "getUtxosByAddresses", addresses);
      return w.terms.refundFromReply(1, signer, false, w.artifacts, utxos.text, { payer: key, fee: "auto" }, VALUE);
    };
    // The depositor of an earmarked leg refunds from the expiry: the node refuses it before.
    const early = signAll(w, refundOf("depositor"), [w.wallets.buyer, w.wallets.payer]);
    const earlyTx = early.finalize();
    const refused = submit(node, earlyTx);
    const e = refusalError(() => sdk.rpcSubmitReply(refused.text, refused.id, earlyTx));
    assert.equal(e.code, "SDK_RPC_REPLY");
    assert.match(e.message, /is not final/);
    node.virtualDaa = 2_000_001;
    const ok = submit(node, earlyTx);
    assert.equal(sdk.rpcSubmitReply(ok.text, ok.id, earlyTx), hex(earlyTx.txid()));
    const decoded = node.accepted[0].decoded as { legs: { leg: number; outcome: { kind: string } }[] };
    assert.deepEqual(decoded.legs.map((l) => [l.leg, l.outcome.kind]), [[1, "refunded"]]);
    // A node that rejects says why, and the page is told in the node's words, escaped.
    const w2 = world(sdk, MODES.vaultKas);
    try {
      const node2 = nodeFor(w2);
      node2.rejectNext = "mempool is full\u001b[2J";
      const tx2 = signAll(w2, build(w2, node2, "settle"), [w2.wallets.authority, w2.wallets.payer]).finalize();
      const r = submit(node2, tx2);
      const err = refusalError(() => sdk.rpcSubmitReply(r.text, r.id, tx2));
      assert.equal(err.code, "SDK_RPC_REPLY");
      assert.ok(!/[\u0000-\u001f]/.test(err.message), "no control character reaches the page");
      assert.match(err.message, /mempool is full/);
      // The same transaction goes through afterwards: the rejection left nothing behind.
      const again = submit(node2, tx2);
      assert.equal(sdk.rpcSubmitReply(again.text, again.id, tx2), hex(tx2.txid()));
    } finally {
      freeAll(w2.wallets);
    }
  } finally {
    freeAll(w.wallets);
  }
});

test("the node is checked before anything is built on it, and a reply to another request or for another transaction is refused", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    const info = () => {
      const r = call(node, "getServerInfo", null);
      return sdk.rpcReply(r.text, r.id, "getServerInfo") as never;
    };
    sdk.checkNode(info(), w.network);
    node.synced = false;
    assert.equal(refusalError(() => sdk.checkNode(info(), w.network)).code, "SDK_NODE_NOT_SYNCED");
    node.synced = true;
    node.networkId = "testnet-10";
    assert.equal(refusalError(() => sdk.checkNode(info(), "mainnet")).code, "SDK_NODE_NETWORK_MISMATCH");
    sdk.checkNode(info(), "testnet");
    node.networkId = "devnet";
    assert.equal(refusalError(() => sdk.checkNode(info(), "testnet")).code, "SDK_NODE_NETWORK_MISMATCH");
    // A reply to another request.
    const r = call(node, "getBlockDagInfo", null);
    assert.equal(refusalError(() => sdk.rpcReply(r.text, r.id + 1, "getBlockDagInfo")).code, "SDK_RPC_REPLY");
    assert.equal(refusalError(() => sdk.rpcReply(r.text, r.id, "getServerInfo")).code, "SDK_RPC_REPLY");
    const dag = sdk.rpcReply(r.text, r.id, "getBlockDagInfo") as { virtual_daa_score: string; sink: string };
    assert.equal(dag.virtual_daa_score, daa);
    assert.equal(dag.sink, node.genesis);
    // A node without a UTXO index says so when asked for UTXOs.
    node.hasUtxoIndex = false;
    const noIndex = call(node, "getUtxosByAddresses", [w.wallets.payer.address(w.network)]);
    assert.equal(refusalError(() => sdk.rpcReply(noIndex.text, noIndex.id, "getUtxosByAddresses")).code, "SDK_RPC_REPLY");
    // The submit reply is the submitted transaction's.
    node.hasUtxoIndex = true;
    node.networkId = w.network === "mainnet" ? "mainnet" : "testnet-10";
    const tx = signAll(w, build(w, node, "settle"), [w.wallets.authority, w.wallets.payer]).finalize();
    const sent = submit(node, tx);
    const forged = JSON.stringify({ ...JSON.parse(sent.text), params: { transactionId: "ab".repeat(32) } });
    assert.equal(refusalError(() => sdk.rpcSubmitReply(forged, sent.id, tx)).code, "SDK_TXID_MISMATCH");
    assert.equal(sdk.rpcSubmitReply(sent.text, sent.id, tx), hex(tx.txid()), "control");
  } finally {
    freeAll(w.wallets);
  }
});

test("an error is marked nodeError only when the node itself sent it to the very request; an answer that cannot be read, or that is for another request, leaves the outcome unknown and is not marked", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    const tx = signAll(w, build(w, node, "settle"), [w.wallets.authority, w.wallets.payer]).finalize();
    // The node refuses the transaction: it did not act on it, and says so to this request.
    node.rejectNext = "the mempool is full";
    const refused = submit(node, tx);
    const said = refusalError(() => sdk.rpcSubmitReply(refused.text, refused.id, tx));
    assert.deepEqual([said.code, said.nodeError], ["SDK_RPC_REPLY", true]);
    assert.equal(node.accepted.length, 0, "the node took nothing");
    // The same words in a reply that is not to this request, and answers that cannot be read: the
    // request left the caller and the node may have taken it, so none of them is marked.
    const unreadable: [string, string, number][] = [
      ["the same words to another request", refused.text, refused.id + 1],
      ["no id", JSON.stringify({ error: { code: -32000, message: "the mempool is full" } }), refused.id],
      ["not JSON", "{", refused.id],
      ["a bare number", "5", refused.id],
      ["no params", JSON.stringify({ id: refused.id, method: "submitTransaction" }), refused.id],
      ["a transaction id that is not a hash", JSON.stringify({ id: refused.id, method: "submitTransaction", params: { transactionId: "zz" } }), refused.id],
    ];
    for (const [what, text, id] of unreadable) {
      const e = refusalError(() => sdk.rpcSubmitReply(text, id, tx));
      assert.equal(e.code, "SDK_RPC_REPLY", what);
      assert.equal(e.nodeError, undefined, what);
      assert.equal("nodeError" in e, false, what);
    }
    // The node says it took another transaction: not an error of the node's, and not a refusal.
    const sent = submit(node, tx);
    const forged = JSON.stringify({ ...JSON.parse(sent.text), params: { transactionId: "ab".repeat(32) } });
    const mismatch = refusalError(() => sdk.rpcSubmitReply(forged, sent.id, tx));
    assert.deepEqual([mismatch.code, mismatch.nodeError], ["SDK_TXID_MISMATCH", undefined]);
    // The reply to the request in flight, at last: no error at all.
    assert.equal(sdk.rpcSubmitReply(sent.text, sent.id, tx), hex(tx.txid()), "control");
    assert.equal(node.accepted.length, 1);
    // Another refusal of the SDK, nothing to do with a node, is not marked either.
    assert.equal(refusalError(() => sdk.checkNodeUrl("http://x", "testnet")).nodeError, undefined);
    // The node's "not found" to a mempool lookup is the node's own answer too.
    const missing = call(node, "getMempoolEntry", "ab".repeat(32));
    const absent = refusalError(() => sdk.rpcTransactionReply(missing.text, missing.id, "getMempoolEntry", "ab".repeat(32)));
    assert.deepEqual([absent.code, absent.nodeError], ["SDK_RPC_NOT_FOUND", true]);
    // The node's error to a call whose id is not the one read: not marked.
    assert.equal(refusalError(() => sdk.rpcTransactionReply(missing.text, missing.id + 1, "getMempoolEntry", "ab".repeat(32))).nodeError, undefined);
  } finally {
    freeAll(w.wallets);
  }
});

test("node URLs: ws and wss only; on mainnet only a private link (127.0.0.1 or localhost, no IPv6 literal)", () => {
  for (const url of ["ws://127.0.0.1:18210", "wss://node.example/ws", "ws://localhost:17110", "wss://[::1]:17110"]) {
    sdk.checkNodeUrl(url, "testnet");
    sdk.checkNodeUrl(url, "mainnet");
  }
  sdk.checkNodeUrl("ws://203.0.113.9:17110", "testnet");
  // Owner decision 2026-10-11: ws:// to [::1] is refused on mainnet like any other plaintext host
  // that is not 127.0.0.1 or localhost (the demo page's policy cannot name an IPv6 literal); the
  // controls are the two hosts that are accepted and wss:// to the same literal.
  for (const refused of ["ws://203.0.113.9:17110", "ws://[::1]:17110", "ws://[::1]", "ws://[::2]:17110"]) {
    assert.equal(refusalError(() => sdk.checkNodeUrl(refused, "mainnet")).code, "SDK_NODE_INSECURE", refused);
    sdk.checkNodeUrl(refused, "testnet");
  }
  for (const bad of ["", "http://127.0.0.1:16110", "127.0.0.1:17110", "ws://", "ws://a b"]) {
    assert.equal(refusalError(() => sdk.checkNodeUrl(bad, "testnet")).code, "SDK_NODE_URL_INVALID", JSON.stringify(bad));
  }
  assert.equal(refusalError(() => sdk.checkNodeUrl("ws://127.0.0.1", "devnet" as "mainnet")).code, "SDK_JSON_FORM");
  assert.deepEqual(sdk.rpcMethods(), [
    "getServerInfo",
    "getBlockDagInfo",
    "getUtxosByAddresses",
    "submitTransaction",
    "getMempoolEntry",
    "getVirtualChainFromBlockV2",
  ]);
});

test("a token of the asset covenant leaves the vault for the buyer's delivery, as the node holds it", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const node = nodeFor(w);
    const tx = signAll(w, build(w, node, "settle"), [w.wallets.authority, w.wallets.payer]).finalize();
    const sent = submit(node, tx);
    sdk.rpcSubmitReply(sent.text, sent.id, tx);
    const held: FakeUtxo[] = [...(node as unknown as { held: Map<string, { utxo: FakeUtxo; spent: boolean }> }).held.values()]
      .filter((h) => !h.spent && h.utxo.covenant_id === ASSET_COV)
      .map((h) => h.utxo);
    assert.equal(held.length, 1, "one asset token UTXO is left, the buyer's");
    assert.equal(held[0].transaction_id, hex(tx.txid()));
  } finally {
    freeAll(w.wallets);
  }
});

test("a fetched transaction's raw form is read up to the longest a transaction can be, and not a character more", () => {
  // Two hex digits a byte, and a transaction of at most twice the standard mass cap in bytes.
  const longest = 4 * Number(sdk.standardMassCap());
  const txid = "ab".repeat(32);
  const fetched = (raw: string) => ({ txid, raw, spent: [] as null[] });
  const atTheBound = refusalError(() => sdk.decodeFetched(fetched("00".repeat(longest / 2)), txid, "testnet"));
  assert.doesNotMatch(atTheBound.message, /a string of/, "the bound admits it to the decoder, which refuses what is not a transaction");
  assert.ok(atTheBound.code.startsWith("DECODE_"), atTheBound.code);
  const over = refusalError(() => sdk.decodeFetched(fetched("00".repeat(longest / 2) + "0"), txid, "testnet"));
  assert.equal(over.code, "SDK_JSON_FORM");
  assert.match(over.message, /^SDK_JSON_FORM: fetched\.raw: a string of \d+ characters; at most \d+ are read$/);
  assert.match(over.message, new RegExp(`at most ${longest} are read`));
});

test("a Vault trade where the buyer funds the cash leg from a wallet: ask, build the funding, review, sign, submit, and the settle then finds the exact deposit at the cash vault", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    // The node holds what the seller funded (the asset leg), the settler's fee coin and the buyer's
    // coins; the cash vault is empty until the buyer funds it.
    const node = new FakeNode(sdk, addressFor(w.network), w.network);
    node.networkId = "testnet-10";
    node.virtualDaa = Number(NOW);
    for (const u of w.pool.filter((u) => u.transaction_id !== cashVaultId)) node.add(u);
    const buyerKey = w.wallets.buyer.publicKey();
    node.add(utxo("buyer-coins", 130_000_000n, p2pk(buyerKey)) as FakeUtxo);
    node.add(utxo("buyer-more-coins", 40_000_000n, p2pk(buyerKey)) as FakeUtxo);
    // Before the funding there is no deposit for the settle to spend.
    assert.equal(refusalError(() => build(w, node, "settle")).code, "SDK_UTXO_NOT_FOUND");

    // The page's sequence: the node's score, the addresses the SDK names (the cash vault, the
    // asset vault and its token, the buyer), their UTXOs, the build.
    const info = call(node, "getServerInfo", null);
    const server = sdk.rpcReply(info.text, info.id, "getServerInfo") as { virtual_daa_score: string };
    const addresses = w.terms.fundCashAddresses(w.artifacts, buyerKey);
    const ask = () => call(node, "getUtxosByAddresses", addresses).text;
    const fundFrom = (text: string) =>
      w.terms.fundCashFromReply(w.artifacts, text, { payer: buyerKey, fee: "auto" }, server.virtual_daa_score, VALUE);
    // A node on which the seller has not funded the asset leg: the same question, a refusal.
    const bare = new FakeNode(sdk, addressFor(w.network), w.network);
    bare.networkId = "testnet-10";
    bare.virtualDaa = Number(NOW);
    for (const u of w.pool.filter((u) => u.transaction_id !== cashVaultId && !u.covenant_id && u.script_public_key.script.startsWith("20"))) bare.add(u);
    bare.add(utxo("buyer-coins", 130_000_000n, p2pk(buyerKey)) as FakeUtxo);
    assert.equal(
      refusalError(() => fundFrom(call(bare, "getUtxosByAddresses", addresses).text)).code,
      "SDK_FUND_ASSET_NOT_FUNDED",
      "the asset leg is not on that node",
    );
    const funding = fundFrom(ask());
    const review = funding.review(w.artifacts, daa, VALUE);
    assert.deepEqual(review.kind, { builder: "fund_kas" });
    assert.equal(review.outputs[0].what, "the cash vault");
    // Only the buyer's wallet has anything to sign, and it signs a document that is the builder's.
    assert.equal(refusalError(() => w.wallets.seller.sign(funding, options(w))).code, "SDK_SIGN_NOTHING_TO_SIGN");
    const signed = w.wallets.buyer.sign(funding, options(w)).ipst;
    assert.equal(signed.isComplete(), true);
    const tx = signed.finalize();
    const sent = submit(node, tx);
    assert.equal(sdk.rpcSubmitReply(sent.text, sent.id, tx), hex(tx.txid()));
    // The deposit is at the cash vault, exactly the cash amount; the buyer's coins are spent.
    const vaultAddress = w.terms.instantiateForCreation(1, { network: w.network, creation_daa: daa }, VALUE).address();
    assert.deepEqual(node.at(vaultAddress).map((u) => u.amount), [KAS_CASH.toString()]);
    assert.equal(node.at(w.wallets.buyer.address(w.network)).length, 1, "the buyer's change");
    // The node now lists the deposit: a second funding is refused, and the settle is what comes next.
    assert.equal(refusalError(() => fundFrom(ask())).code, "SDK_FUND_ALREADY_FUNDED");

    // And now the settle builds from it, the authority and the payer sign, the node takes it.
    const settle = signAll(w, build(w, node, "settle"), [w.wallets.authority, w.wallets.payer]).finalize();
    const done = submit(node, settle);
    assert.equal(sdk.rpcSubmitReply(done.text, done.id, settle), hex(settle.txid()));
    const decoded = node.accepted[1].decoded as { legs: { leg: number; outcome: { kind: string; amount?: string } }[] };
    assert.deepEqual(decoded.legs.map((l) => [l.leg, l.outcome.kind, l.outcome.amount]), [
      [0, "delivered", AMOUNT_A.toString()],
      [1, "delivered", KAS_CASH.toString()],
    ]);
    assert.deepEqual(node.at(vaultAddress), [], "the deposit is spent");
  } finally {
    freeAll(w.wallets);
  }
});
