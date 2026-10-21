// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The wallet of the browser demo (I11 phase 2): a key the SDK draws and never hands out, and a
// signing that does what the command line's `ipst sign` does, each refusal beside an accepted
// control.
//
// The key is a runtime throwaway, as the owner decision of 2026-10-10 allows for tests: it is drawn
// from the randomness of this process, held in the module's memory, never written to a file, a log
// or an assertion message. To look for it where it must not be, the test records the 32 bytes the
// module draws from `crypto.getRandomValues` and proves, with an independent implementation
// (@noble/curves, a dev dependency), that those bytes are the wallet's key. Assertions about the
// key are written as plain booleans, so that a failure never prints it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import { schnorr } from "@noble/curves/secp256k1.js";
import { createHash } from "node:crypto";
import type { Ipst, PlanFundingJson, SignOptionsJson, Wallet } from "../index.js";
import { utxosFrame } from "./fakenode.ts";
import { ASSET_ARTIFACT, ASSET_COV, AUTHORIZER, CARRIER, FEE_INPUT, KAS_CASH, LIFT, NOW, VALUE, ownToken, p2pk, utxo } from "./fixtures.ts";
import { hex, kaspaAddress, load, memory, refusalError } from "./sdk.ts";
import { MODES, addressFor, freeAll, pinsFor, world } from "./world.ts";
import type { World } from "./world.ts";
import type { FakeUtxo } from "./fakenode.ts";

const sdk = load();

// The 32 bytes of every draw the module makes from crypto.getRandomValues.
const drawn: Uint8Array[] = [];
{
  const crypto = globalThis.crypto;
  const real = crypto.getRandomValues.bind(crypto);
  Object.defineProperty(crypto, "getRandomValues", {
    configurable: true,
    writable: true,
    value: (array: ArrayBufferView) => {
      const out = real(array as never) as unknown;
      drawn.push(Uint8Array.from(new Uint8Array(array.buffer, array.byteOffset, array.byteLength)));
      return out;
    },
  });
}
/** The count of wasm calls to the randomness imports (rng-count.mjs, preloaded by ci.sh). */
const importCalls = (globalThis as { __rngCalls?: () => number }).__rngCalls;

/** Every way the test knows to write the 32 bytes as text. */
function spellings(secret: Uint8Array): string[] {
  const be = BigInt(`0x${hex(secret)}`).toString();
  const le = BigInt(`0x${hex(Uint8Array.from(secret).reverse())}`).toString();
  return [
    hex(secret),
    hex(secret).toUpperCase(),
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("base64url"),
    Buffer.from(secret).toString("base64").replace(/=+$/, ""),
    be,
    le,
    Array.from(secret).join(","),
    Array.from(secret).join(", "),
    hex(Uint8Array.from(secret).reverse()),
  ];
}

const leaks = (text: string, secret: Uint8Array) => spellings(secret).some((s) => text.includes(s));

/** The occurrences of `secret` as bytes in `bytes`. */
function occurrences(bytes: Uint8Array, secret: Uint8Array): number {
  let n = 0;
  for (let at = Buffer.from(bytes).indexOf(secret); at >= 0; at = Buffer.from(bytes).indexOf(secret, at + 1)) n += 1;
  return n;
}

test("a wallet draws its key once from the browser's randomness, and the bytes drawn are the key", () => {
  const draws = drawn.length;
  const calls = importCalls?.() ?? 0;
  const w = sdk.Wallet.generate();
  assert.equal(drawn.length - draws, 1, "one call to crypto.getRandomValues");
  assert.equal(drawn[drawn.length - 1].length, 32);
  if (importCalls) assert.equal(importCalls() - calls, 1, "one call across the wasm boundary");
  const secret = drawn[drawn.length - 1];
  const pub = w.publicKey();
  assert.match(pub, /^[0-9a-f]{64}$/);
  // Positive control for every scan below: an independent implementation derives this public key
  // from the bytes drawn, so those bytes are the wallet's key.
  assert.ok(hex(schnorr.getPublicKey(secret)) === pub, "the drawn bytes are the wallet's key");
  // The same call twice is two keys.
  const other = sdk.Wallet.generate();
  assert.notEqual(other.publicKey(), pub);
  assert.ok(!hex(drawn[drawn.length - 1]).includes(hex(secret)), "a second draw is another key");
  // Everything else the wallet does draws nothing.
  const quiet = importCalls?.() ?? 0;
  w.address("mainnet");
  w.address("testnet");
  w.publicKey();
  w.isWiped();
  if (importCalls) assert.equal(importCalls(), quiet, "no draw outside generate");
  w.free();
  other.free();
});

test("a wallet's address is its key as a P2PK address on the network asked for", () => {
  const w = sdk.Wallet.generate();
  try {
    const pk = Buffer.from(w.publicKey(), "hex");
    assert.equal(w.address("mainnet"), kaspaAddress("kaspa", 0, pk));
    assert.equal(w.address("testnet"), kaspaAddress("kaspatest", 0, pk));
    assert.equal(refusalError(() => w.address("devnet" as "mainnet")).code, "SDK_JSON_FORM");
    assert.equal(refusalError(() => w.address(1 as unknown as "mainnet")).code, "SDK_ARGUMENT_TYPE");
  } finally {
    w.free();
  }
});

test("no member of a wallet returns its key, in any spelling; the members are exactly the documented ones", () => {
  const w = sdk.Wallet.generate();
  const secret = drawn[drawn.length - 1];
  assert.ok(hex(schnorr.getPublicKey(secret)) === w.publicKey(), "control: the drawn bytes are the key");
  try {
    const proto = Object.getPrototypeOf(w) as object;
    // A new member would have to be added here, and with it a reason to believe it hands out no key.
    assert.deepEqual(
      Object.getOwnPropertyNames(proto)
        .filter((name) => !name.startsWith("__"))
        .sort(),
      ["address", "constructor", "free", "isWiped", "publicKey", "sign", "wipe"],
    );
    assert.deepEqual(Object.getOwnPropertySymbols(proto), []);
    const views = [
      JSON.stringify(w),
      String(w),
      inspect(w, { showHidden: true, depth: 8, getters: true }),
      Object.getOwnPropertyNames(w).join(),
      JSON.stringify(Object.getOwnPropertyDescriptors(w), (_, v) => (typeof v === "bigint" ? v.toString() : v)),
      JSON.stringify(Object.getOwnPropertyDescriptors(proto), (_, v) => (typeof v === "function" ? String(v) : v)),
      w.publicKey(),
      w.address("mainnet"),
      w.address("testnet"),
      String(w.isWiped()),
    ];
    for (const view of views) assert.ok(!leaks(view, secret), "a view of the wallet shows the key");
    // Control for the scan: the same views of a wallet-shaped object that does hold it.
    const careless = { secret: hex(secret) };
    assert.ok(leaks(JSON.stringify(careless), secret), "the scan sees a key that is there");
    assert.ok(leaks(inspect({ secret: Buffer.from(secret).toString("base64") }), secret), "and in base64");
  } finally {
    w.free();
  }
});

test("a wallet keeps its key in module memory while it holds it, and a wipe or a free leaves none", (t) => {
  const memoryBytes = () => new Uint8Array(memory().buffer);
  // The wallet signs first, so that the key pair the signing builds has been through the memory.
  const signed = (w: World, wallet: Wallet) => {
    wallet.sign(directIpst(w), options(w));
  };
  for (const how of ["wipe", "free"] as const) {
    const first = drawn.length;
    const w = world(sdk, MODES.directKas);
    try {
      const secret = drawn[first]; // the seller's: the first wallet of a world
      assert.ok(hex(schnorr.getPublicKey(secret)) === w.wallets.seller.publicKey(), "control: the drawn bytes are the key");
      signed(w, w.wallets.seller);
      const before = occurrences(memoryBytes(), secret);
      assert.ok(before >= 1, "the scan finds the key in the module memory while the wallet holds it");
      if (how === "wipe") w.wallets.seller.wipe();
      else w.wallets.seller.free();
      const after = occurrences(memoryBytes(), secret);
      // A measurement of this build in this engine, and a guard on it (wallet.rs says what a wipe
      // cannot promise): the secret sits in one boxed buffer, moved as a pointer, and the key
      // pair a signature builds is erased after it.
      t.diagnostic(`${how}: copies of the key in module memory: ${before} before, ${after} after`);
      assert.equal(after, 0, `${how} leaves no copy of the key in the module's memory`);
    } finally {
      for (const [name, wallet] of Object.entries(w.wallets)) {
        if (name !== "seller" || how === "wipe") wallet.free();
      }
    }
  }
});

// Signing.

function options(w: World, over: Partial<SignOptionsJson> = {}): SignOptionsJson {
  return {
    artifacts: w.artifacts,
    current_daa: NOW.toString(),
    value: VALUE,
    mainnet: w.network === "mainnet",
    ...over,
  };
}

/** The Direct trade of KAS cash against a KCC-20 asset, built over the UTXOs a node would report. */
function directIpst(w: World, fee: string | "auto" = "auto"): Ipst {
  const reply = utxosFrame(1, w.pool, addressFor(w.network));
  return w.terms.directFromReply(
    w.artifacts,
    reply,
    { payer: w.wallets.payer.publicKey(), fee },
    NOW.toString(),
    VALUE,
  );
}

function pending(ipst: Ipst): number[] {
  return ipst.pending();
}

test("each wallet signs its own inputs of a Direct trade, and only those; the document passed in is not changed", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const ipst = directIpst(w);
    // The seller's token, the buyer's cash, the payer's fee input.
    assert.deepEqual(pending(ipst), [0, 1, 2]);
    assert.deepEqual(
      ipst.slots().map((s) => s.signer),
      [w.wallets.seller.publicKey(), w.wallets.buyer.publicKey(), w.wallets.payer.publicKey()],
    );
    const bySeller = w.wallets.seller.sign(ipst, options(w));
    assert.deepEqual(bySeller.signed_inputs, [0]);
    assert.deepEqual(pending(bySeller.ipst), [1, 2]);
    assert.deepEqual(pending(ipst), [0, 1, 2], "the document passed in is unchanged");
    const byBuyer = w.wallets.buyer.sign(bySeller.ipst, options(w));
    assert.deepEqual(byBuyer.signed_inputs, [1]);
    const byPayer = w.wallets.payer.sign(byBuyer.ipst, options(w));
    assert.deepEqual(byPayer.signed_inputs, [2]);
    assert.equal(byPayer.ipst.isComplete(), true);
    // The signatures are the slots' own: each verifies under its signer and sighash.
    for (const slot of byPayer.ipst.slots()) {
      assert.ok(slot.signature !== null && slot.signer !== null && slot.sighash !== null);
      sdk.verifySchnorrSig65(Buffer.from(slot.signer, "hex"), Buffer.from(slot.sighash, "hex"), Buffer.from(slot.signature, "hex"));
    }
    // Signing in another order, and merging, gives the same document: signatures are deterministic.
    const reverse = w.wallets.seller.sign(
      w.wallets.buyer.sign(w.wallets.payer.sign(ipst, options(w)).ipst, options(w)).ipst,
      options(w),
    );
    assert.equal(reverse.ipst.toJson(), byPayer.ipst.toJson());
    assert.equal(Buffer.from(reverse.ipst.finalize().txid()).toString("hex"), Buffer.from(byPayer.ipst.finalize().txid()).toString("hex"));
  } finally {
    freeAll(w.wallets);
  }
});

test("the transaction the wallets sign is submitted in the node's form with a signature script on every input", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const signed = [w.wallets.seller, w.wallets.buyer, w.wallets.payer].reduce(
      (ipst, wallet) => wallet.sign(ipst, options(w)).ipst,
      directIpst(w),
    );
    const tx = signed.finalize();
    const request = JSON.parse(sdk.rpcSubmitRequest(7, tx)) as {
      id: number;
      method: string;
      params: { allowOrphan: boolean; transaction: { inputs: { signatureScript: string }[]; outputs: unknown[]; lockTime: number } };
    };
    assert.equal(request.id, 7);
    assert.equal(request.method, "submitTransaction");
    assert.equal(request.params.allowOrphan, false);
    assert.equal(request.params.transaction.inputs.length, 3);
    assert.ok(request.params.transaction.inputs.every((i) => /^[0-9a-f]+$/.test(i.signatureScript) && i.signatureScript.length > 0));
    assert.equal(request.params.transaction.outputs.length, 3);
    assert.equal(request.params.transaction.lockTime, Number(signed.review(w.artifacts, NOW.toString(), VALUE).lock_time));
  } finally {
    freeAll(w.wallets);
  }
});

test("a wallet refuses to sign in the order of the command line, each refusal beside an accepted control", () => {
  // Mainnet, where the destinations pay a cold key the seller pins (a key that lives only in a
  // wallet is refused there, see the strand tests below), and testnet.
  const w = world(sdk, MODES.directKas, "mainnet", true);
  const t = world(sdk, MODES.directKas, "testnet");
  try {
    const ipst = directIpst(w);
    const sellerPins = pinsFor(w, "seller");
    const sign = (who: Wallet, doc: Ipst = ipst, over: Partial<SignOptionsJson> = {}) =>
      who.sign(doc, options(w, who === w.wallets.seller ? { pins: sellerPins, ...over } : over));
    assert.deepEqual(sign(w.wallets.seller).signed_inputs, [0], "control");

    // The mainnet choice, both ways.
    assert.equal(refusalError(() => sign(w.wallets.seller, ipst, { mainnet: false })).code, "SDK_SIGN_MAINNET_NOT_EXPLICIT");
    const testnet = directIpst(t);
    assert.deepEqual(t.wallets.seller.sign(testnet, options(t)).signed_inputs, [0], "control: testnet, no mainnet choice");
    assert.equal(
      refusalError(() => t.wallets.seller.sign(testnet, options(t, { mainnet: true }))).code,
      "SDK_SIGN_NETWORK_MISMATCH",
    );

    // The key signs something that is not signed yet.
    const none = refusalError(() => sign(w.wallets.authority));
    assert.equal(none.code, "SDK_SIGN_NOTHING_TO_SIGN");
    assert.equal(none.message, "SDK_SIGN_NOTHING_TO_SIGN: this key signs no input of the document");
    const bySeller = sign(w.wallets.seller).ipst;
    const again = refusalError(() => sign(w.wallets.seller, bySeller));
    assert.equal(again.code, "SDK_SIGN_NOTHING_TO_SIGN");
    assert.equal(again.message, "SDK_SIGN_NOTHING_TO_SIGN: every input this key signs already has its signature");

    // The document is the builders', within the cap.
    assert.deepEqual(sign(w.wallets.seller, ipst, { value: { kas_equivalent: "1000000000" } }).signed_inputs, [0], "control: at the cap");
    assert.equal(
      refusalError(() => sign(w.wallets.seller, ipst, { value: { kas_equivalent: "1000000001" } })).code,
      "SDK_VALUE_CAP_EXCEEDED",
    );
    assert.equal(
      refusalError(() => sign(w.wallets.seller, ipst, { value: { kas_equivalent: "0" } })).code,
      "SDK_VALUE_UNKNOWN",
    );
    assert.deepEqual(sign(w.wallets.seller, ipst, { value: LIFT }).signed_inputs, [0], "the SDK's own lift, which the page never sets");
    const doc = JSON.parse(ipst.toJson()) as { inputs: { compute_budget: number }[] };
    doc.inputs[0].compute_budget += 1;
    const raised = sdk.Ipst.fromJson(JSON.stringify(doc, null, 2));
    assert.equal(refusalError(() => sign(w.wallets.seller, raised)).code, "IPST_TERMS_MISMATCH");
    assert.equal(refusalError(() => sign(w.wallets.seller, ipst, { current_daa: "99999999999" })).code, "TX_EXPIRED");
    assert.equal(
      refusalError(() => sign(w.wallets.seller, ipst, { artifacts: { asset: "{}", cash: null } })).code,
      "TX_TOKEN_TEMPLATE",
    );

    // The options are a strict form.
    for (const [what, bad] of [
      ["an unknown key", { ...options(w), secret: "x" }],
      ["no value", { ...options(w), value: undefined }],
      ["a DAA score as a number", { ...options(w), current_daa: 1_500_000 }],
      ["mainnet as text", { ...options(w), mainnet: "yes" }],
    ] as const) {
      assert.ok(
        ["SDK_JSON_FORM", "SDK_ARGUMENT_TYPE"].includes(refusalError(() => w.wallets.seller.sign(ipst, bad as unknown as SignOptionsJson)).code),
        what,
      );
    }

    // A wiped wallet signs nothing.
    const gone = world(sdk, MODES.directKas);
    try {
      const doc2 = directIpst(gone);
      assert.deepEqual(gone.wallets.seller.sign(doc2, options(gone)).signed_inputs, [0], "control");
      gone.wallets.seller.wipe();
      assert.equal(refusalError(() => gone.wallets.seller.sign(doc2, options(gone))).code, "SDK_WALLET_WIPED");
      assert.equal(gone.wallets.seller.isWiped(), true);
      assert.equal(gone.wallets.buyer.isWiped(), false);
    } finally {
      freeAll(gone.wallets);
    }
  } finally {
    freeAll(w.wallets);
    freeAll(t.wallets);
  }
});

test("a wallet whose key is a party's runs the role check before it signs; any other key does not", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const sellerKey = w.wallets.seller.publicKey();
    const evil = { ...w.json, buyer_refund: { kind: "kas", version: 0, script: `20${sellerKey}ac` } } as typeof w.json;
    const attacked: World = { ...w, json: evil, terms: sdk.Terms.fromJson(evil).validateStructure() };
    const ipst = directIpst(attacked);
    const sign = (who: Wallet, over: Partial<SignOptionsJson> = {}) => who.sign(ipst, options(w, over));
    // The seller is not the one attacked: its own destinations pay its key.
    assert.deepEqual(sign(w.wallets.seller).signed_inputs, [0], "control: the seller");
    // The buyer's refund pays the seller. Refused, unpinned and pinned to exactly that.
    const pin = kaspaAddress("kaspatest", 0, Buffer.from(sellerKey, "hex"));
    for (const pins of [undefined, { refund: pin }, { receive: null, refund: pin }]) {
      const e = refusalError(() => sign(w.wallets.buyer, pins === undefined ? {} : { pins }));
      assert.equal(e.code, "SDK_DESTINATION_NOT_MINE");
      assert.match(e.message, /buyer_refund pays .*the counterparty's key/);
    }
    // The fee payer is no party: it signs the same document.
    assert.deepEqual(sign(w.wallets.payer).signed_inputs, [2], "a key that is neither party's has no role to check");
    // The honest document, signed by the buyer, beside it.
    assert.deepEqual(w.wallets.buyer.sign(directIpst(w), options(w)).signed_inputs, [1], "control: the buyer of the honest terms");
    // A pin that does not parse is its own refusal.
    assert.equal(
      refusalError(() => sign(w.wallets.buyer, { pins: { refund: "not an address" } })).code,
      "SDK_DESTINATION_PIN_INVALID",
    );
  } finally {
    freeAll(w.wallets);
  }
});

test("the authority's wallet signs the vault inputs of a settle, and no other wallet has them", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const reply = utxosFrame(1, w.pool, addressFor(w.network));
    const ipst = w.terms.settleFromReply(w.artifacts, reply, { payer: w.wallets.payer.publicKey(), fee: "auto" }, NOW.toString(), VALUE);
    const slots = ipst.slots();
    const authority = w.wallets.authority.publicKey();
    const signers = slots.map((s) => s.signer);
    assert.equal(signers.filter((s) => s === authority).length, 2, "the authority signs both vault inputs");
    assert.equal(signers.filter((s) => s === w.wallets.payer.publicKey()).length, 1, "and the payer the fee input");
    const byAuthority = w.wallets.authority.sign(ipst, options(w));
    assert.equal(byAuthority.signed_inputs.length, 2);
    assert.equal(refusalError(() => w.wallets.seller.sign(ipst, options(w))).code, "SDK_SIGN_NOTHING_TO_SIGN");
    assert.equal(refusalError(() => w.wallets.buyer.sign(ipst, options(w))).code, "SDK_SIGN_NOTHING_TO_SIGN");
    const done = w.wallets.payer.sign(byAuthority.ipst, options(w)).ipst;
    assert.equal(done.isComplete(), true);
    assert.ok(done.finalize().txid().length === 32);
  } finally {
    freeAll(w.wallets);
  }
});

// The payer's side of signing (spec/CLI.md, "ipst sign", steps 9 and 10): what the signer commits
// beyond the fee, where the change goes, and what a key that lives only in a wallet may be paid.

const idOf = (label: string) => createHash("sha256").update(label).digest("hex");

/** A settle of the vault world over `pool`, the payer's fee from its own UTXO. */
function settleIpst(w: World, pool: FakeUtxo[] = w.pool, funding: Partial<PlanFundingJson> = {}): Ipst {
  return w.terms.settleFromReply(
    w.artifacts,
    utxosFrame(1, pool, addressFor(w.network)),
    { payer: w.wallets.payer.publicKey(), fee: "auto", ...funding },
    NOW.toString(),
    VALUE,
  );
}

/** The pool with the UTXO labelled `label` holding `amount` sompi instead. */
const holding = (pool: FakeUtxo[], label: string, amount: bigint): FakeUtxo[] =>
  pool.map((u) => (u.transaction_id === idOf(label) ? { ...u, amount: amount.toString() } : u));

test("a fee payer is not made to pay a counterparty's under-funded outputs: the top-up is shown, bounded, and the funded control signs", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    // The seller funded the asset vault's authorizer with 1 sompi. The builder tops the output that
    // passes it on to the seller up to the minimum, and the fee payer's inputs pay the difference.
    const topup = AUTHORIZER - 1n;
    const starved = settleIpst(w, holding(w.pool, "asset-authorizer", 1n));
    const review = starved.review(w.artifacts, NOW.toString(), VALUE);
    assert.equal(review.payer_cost, topup.toString());
    assert.match(review.payer_cost_text, new RegExp(`^${topup} sompi \\(0\\.49999999 KAS\\) into trade outputs`));
    const toSeller = review.outputs[2];
    assert.equal(toSeller.amount, AUTHORIZER.toString(), "the output the seller receives is topped up to the minimum");
    assert.equal(review.inputs[0].amount, "1");

    const payer = w.wallets.payer;
    const refused = refusalError(() => payer.sign(starved, options(w)));
    assert.equal(refused.code, "SDK_SIGN_TOPUP_TOO_HIGH");
    assert.match(refused.message, new RegExp(`${topup} sompi`));
    // The limit is exact: one sompi under it refuses, the amount itself signs.
    assert.equal(
      refusalError(() => payer.sign(starved, options(w, { max_topup: (topup - 1n).toString() }))).code,
      "SDK_SIGN_TOPUP_TOO_HIGH",
    );
    const accepted = payer.sign(starved, options(w, { max_topup: topup.toString() }));
    assert.deepEqual(accepted.signed_inputs, [3]);
    // What the payer paid: the fee and the top-up, nothing else (the change comes back).
    const done = accepted.ipst.review(w.artifacts, NOW.toString(), VALUE);
    const change = BigInt(done.outputs[3].amount);
    assert.equal(FEE_INPUT - change, BigInt(done.fee) + topup);

    // The control: the same settle over the funded vaults has no top-up, and signs with no options.
    const funded = settleIpst(w);
    assert.equal(funded.review(w.artifacts, NOW.toString(), VALUE).payer_cost, "0");
    assert.equal(funded.review(w.artifacts, NOW.toString(), VALUE).payer_cost_text, "none");
    assert.deepEqual(payer.sign(funded, options(w)).signed_inputs, [3]);
    // The authority, who signs the vault inputs and holds no fee input, is not asked for the top-up.
    assert.deepEqual(w.wallets.authority.sign(starved, options(w)).signed_inputs, [0, 1]);
  } finally {
    freeAll(w.wallets);
  }
});

test("the change must pay the address the signer accepts; a signer that names another address signs a document that pays it", () => {
  const w = world(sdk, MODES.vaultKas);
  const elsewhere = sdk.Wallet.generate();
  try {
    const address = elsewhere.address(w.network);
    const toElsewhere = settleIpst(w, w.pool, { change: address });
    const review = toElsewhere.review(w.artifacts, NOW.toString(), VALUE);
    assert.equal(review.outputs[3].address, address, "the builder paid the change to the address given");
    const payer = w.wallets.payer;
    const refused = refusalError(() => payer.sign(toElsewhere, options(w)));
    assert.equal(refused.code, "SDK_SIGN_CHANGE_NOT_MINE");
    assert.ok(refused.message.includes(address), "the refusal names where the change goes");
    assert.ok(refused.message.includes(payer.address(w.network)), "and where the signer expects it");
    // Naming that address, the signer signs it; naming another address, it does not.
    assert.deepEqual(payer.sign(toElsewhere, options(w, { change: address })).signed_inputs, [3]);
    const other = w.wallets.cold ?? w.wallets.authority;
    assert.equal(
      refusalError(() => payer.sign(toElsewhere, options(w, { change: other.address(w.network) }))).code,
      "SDK_SIGN_CHANGE_NOT_MINE",
    );
    // Control: change back to the payer's own key signs with no option, and the same address named
    // explicitly is the same thing.
    const own = settleIpst(w);
    assert.deepEqual(payer.sign(own, options(w)).signed_inputs, [3]);
    assert.deepEqual(payer.sign(own, options(w, { change: payer.address(w.network) })).signed_inputs, [3]);
    // The address is a strict form: a KCC-20 owner, an address of the other network and text that is not an address.
    for (const bad of [`kcc20:pubkey:${"ab".repeat(32)}`, elsewhere.address("mainnet"), "not an address", ""]) {
      assert.equal(refusalError(() => payer.sign(own, options(w, { change: bad }))).code, "SDK_JSON_FORM", bad);
      assert.equal(refusalError(() => settleIpst(w, w.pool, { change: bad })).code, "SDK_JSON_FORM", bad);
    }
  } finally {
    freeAll(w.wallets);
    elsewhere.free();
  }
});

test("the fee is bounded: twice the minimum relay fee by default, at most three fee inputs without a limit, and the limit the signer names", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const payer = w.wallets.payer;
    const auto = settleIpst(w);
    const fee = BigInt(auto.review(w.artifacts, NOW.toString(), VALUE).fee);
    const min = BigInt(auto.review(w.artifacts, NOW.toString(), VALUE).min_relay_fee);
    assert.ok(fee >= min && fee < 2n * min, "control: the automatic fee is within the default limit");
    assert.deepEqual(payer.sign(auto, options(w)).signed_inputs, [3]);
    // A fee of ten times the minimum: refused by default, signed under a limit that allows it.
    const dear = settleIpst(w, w.pool, { fee: (10n * min).toString() });
    assert.equal(refusalError(() => payer.sign(dear, options(w))).code, "SDK_SIGN_FEE_TOO_HIGH");
    const dearFee = BigInt(dear.review(w.artifacts, NOW.toString(), VALUE).fee);
    assert.equal(dearFee, 10n * min);
    assert.equal(refusalError(() => payer.sign(dear, options(w, { max_fee: (dearFee - 1n).toString() }))).code, "SDK_SIGN_FEE_TOO_HIGH");
    assert.deepEqual(payer.sign(dear, options(w, { max_fee: dearFee.toString() })).signed_inputs, [3]);
    // The default limit is exactly twice the minimum relay fee of the transaction as it is.
    const edge = settleIpst(w, w.pool, { fee: (2n * min).toString() });
    const edgeReview = edge.review(w.artifacts, NOW.toString(), VALUE);
    assert.equal(BigInt(edgeReview.fee), 2n * BigInt(edgeReview.min_relay_fee), "control: a fee of twice the minimum");
    assert.deepEqual(payer.sign(edge, options(w)).signed_inputs, [3], "twice the minimum is within the default");
    const over = settleIpst(w, w.pool, { fee: (2n * min + 1n).toString() });
    assert.equal(refusalError(() => payer.sign(over, options(w))).code, "SDK_SIGN_FEE_TOO_HIGH");
    // Four fee inputs: the default limit covers three. The minimum relay fee grows with every input
    // and the builder chose them, so without a limit of the signer's own the fourth is refused.
    const four = [1, 2, 3, 4].map((n) => ({ ...w.fee, transaction_id: idOf(`payer-fee-${n}`), amount: "1250000" }));
    const pool = [...w.pool.filter((u) => u !== w.fee), ...four];
    const many = settleIpst(w, pool, { fee: "5000000" });
    assert.equal(many.slots().filter((s) => s.signer === payer.publicKey()).length, 4, "control: four fee inputs");
    const tooMany = refusalError(() => payer.sign(many, options(w)));
    assert.equal(tooMany.code, "SDK_SIGN_FEE_TOO_HIGH");
    assert.match(tooMany.message, /you sign 4 fee inputs/);
    assert.deepEqual(payer.sign(many, options(w, { max_fee: "5000000" })).signed_inputs, [3, 4, 5, 6]);
  } finally {
    freeAll(w.wallets);
  }
});

test("the signer commits no KAS the trade does not take: a token that carries more than the carrier is refused, a confirmed carrier signs, and the cap holds on what is committed", () => {
  const w = world(sdk, MODES.directKas);
  try {
    // The seller's token UTXO carries 11 KAS where a Direct trade takes the carrier of 2 KAS: the
    // difference goes to the buyer with the token.
    const rich = (kas: bigint) => holding(w.pool, "seller-token", kas * 100_000_000n);
    const ipstFor = (pool: FakeUtxo[]) =>
      w.terms.directFromReply(
        w.artifacts,
        utxosFrame(1, pool, addressFor(w.network)),
        { payer: w.wallets.payer.publicKey(), fee: "auto" },
        NOW.toString(),
        VALUE,
      );
    const seller = w.wallets.seller;
    // Control: the token that carries the carrier signs with no option.
    assert.deepEqual(seller.sign(ipstFor(w.pool), options(w)).signed_inputs, [0]);
    const three = ipstFor(rich(3n));
    const refused = refusalError(() => seller.sign(three, options(w)));
    assert.equal(refused.code, "SDK_SIGN_OUTFLOW_TOO_HIGH");
    assert.match(refused.message, /300000000 sompi/);
    assert.equal(
      refusalError(() => seller.sign(three, options(w, { carrier: "299999999" }))).code,
      "SDK_SIGN_OUTFLOW_TOO_HIGH",
      "one sompi short of what the token carries",
    );
    assert.deepEqual(seller.sign(three, options(w, { carrier: "300000000" })).signed_inputs, [0]);
    // The value cap holds on what is committed: 11 KAS is above 10 KAS even when the signer confirms it.
    const eleven = ipstFor(rich(11n));
    assert.equal(
      refusalError(() => seller.sign(eleven, options(w, { carrier: "1100000000" }))).code,
      "SDK_VALUE_CAP_EXCEEDED",
    );
    assert.deepEqual(seller.sign(eleven, options(w, { carrier: "1100000000", value: LIFT })).signed_inputs, [0], "the SDK's own lift");
    // The buyer commits its KAS cash and its fee inputs less the change: the cash the trade takes.
    const buyer = w.wallets.buyer;
    assert.deepEqual(buyer.sign(ipstFor(w.pool), options(w)).signed_inputs, [1]);
  } finally {
    freeAll(w.wallets);
  }
});

test("on mainnet nothing is paid to a key that lives only in a wallet: the destinations of the role and the change are refused unless an address elsewhere is named", () => {
  // The wallets' own keys are the destinations here, as the page makes them by default.
  const direct = world(sdk, MODES.directKas, "mainnet");
  const vault = world(sdk, MODES.vaultKas, "mainnet");
  const testnet = world(sdk, MODES.directKas, "testnet");
  const elsewhere = sdk.Wallet.generate();
  try {
    const d = directIpst(direct);
    const refused = refusalError(() => direct.wallets.seller.sign(d, options(direct)));
    assert.equal(refused.code, "SDK_DESTINATION_IN_WALLET");
    assert.match(refused.message, /seller_proceeds pays .*a key that lives only in a wallet of this page/);
    assert.match(refused.message, /seller_refund pays /);
    // A pin that equals the destination does not help: it pays the same wallet key.
    assert.equal(
      refusalError(() => direct.wallets.seller.sign(d, options(direct, { pins: pinsFor(direct, "seller") }))).code,
      "SDK_DESTINATION_IN_WALLET",
    );
    assert.equal(refusalError(() => direct.wallets.buyer.sign(d, options(direct))).code, "SDK_DESTINATION_IN_WALLET");
    // Control: the same trade on testnet signs.
    assert.deepEqual(testnet.wallets.seller.sign(directIpst(testnet), options(testnet)).signed_inputs, [0]);

    // The change. The payer's own key is a wallet's, so mainnet refuses change back to it.
    const ipst = settleIpst(vault);
    const own = refusalError(() => vault.wallets.payer.sign(ipst, options(vault)));
    assert.equal(own.code, "SDK_DESTINATION_IN_WALLET");
    assert.match(own.message, /^SDK_DESTINATION_IN_WALLET: the change of \d+ sompi pays kaspa:/);
    // An address elsewhere signs. The SDK cannot know that an address is another wallet's, unless
    // the page says so (`held`): then that is refused too.
    const address = elsewhere.address("mainnet");
    const away = settleIpst(vault, vault.pool, { change: address });
    assert.deepEqual(vault.wallets.payer.sign(away, options(vault, { change: address })).signed_inputs, [3]);
    assert.equal(
      refusalError(() => vault.wallets.payer.sign(away, options(vault, { change: address, held: [elsewhere.publicKey()] }))).code,
      "SDK_DESTINATION_IN_WALLET",
    );
    // Every other output too: the vault's authorizer comes back to the seller's key, whatever the
    // terms say, so a seller whose key lives in a wallet of the page is paid there. Refused when the
    // page says the key is held; signed when it is not, beside it.
    const cold = world(sdk, MODES.vaultKas, "mainnet", true);
    try {
      const change = cold.wallets.cold?.address("mainnet") ?? "";
      const settle = settleIpst(cold, cold.pool, { change });
      const sellerKey = cold.wallets.seller.publicKey();
      assert.deepEqual(cold.wallets.payer.sign(settle, options(cold, { change })).signed_inputs, [3], "control: the seller's key is held in no wallet of the page");
      const stranded = refusalError(() => cold.wallets.payer.sign(settle, options(cold, { change, held: [sellerKey] })));
      assert.equal(stranded.code, "SDK_DESTINATION_IN_WALLET");
      assert.match(stranded.message, /^SDK_DESTINATION_IN_WALLET: output 2 of 50000000 sompi pays kaspa:[a-z0-9]+, a key that lives only in a wallet of this page\. /);
      assert.doesNotMatch(stranded.message, /output [013]/);
    } finally {
      freeAll(cold.wallets);
    }
    // Control: on testnet change back to the payer's own key signs.
    const vaultTestnet = world(sdk, MODES.vaultKas, "testnet");
    try {
      assert.deepEqual(vaultTestnet.wallets.payer.sign(settleIpst(vaultTestnet), options(vaultTestnet)).signed_inputs, [3]);
    } finally {
      freeAll(vaultTestnet.wallets);
    }
  } finally {
    freeAll(direct.wallets);
    freeAll(vault.wallets);
    freeAll(testnet.wallets);
    elsewhere.free();
  }
});

test("a wallet that funds a vault signs a funding that spends the deposit and the fee and brings the rest back to it, and refuses one whose change goes elsewhere or whose fee is above its limit", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer;
    const key = buyer.publicKey();
    const context = { network: w.network, creation_daa: (NOW - 1n).toString() } as const;
    const fund = (fee: bigint, change: string = key) =>
      w.terms.fundKas(
        context,
        { inputs: [utxo("buyer-funds", 3n * KAS_CASH, p2pk(key))], fee: fee.toString(), change: p2pk(change) },
        VALUE,
      );
    const min = BigInt(fund(5_000_000n).review(w.artifacts, NOW.toString(), VALUE).min_relay_fee);
    const fee = min + min / 10n;
    const ipst = fund(fee);
    assert.equal(ipst.review(w.artifacts, NOW.toString(), VALUE).kind.builder, "fund_kas");
    // The deposit is the cash leg; the rest of the input comes back as change.
    const done = buyer.sign(ipst, options(w));
    assert.deepEqual(done.signed_inputs, [0]);
    const outputs = done.ipst.review(w.artifacts, NOW.toString(), VALUE).outputs;
    assert.equal(outputs[0].amount, KAS_CASH.toString());
    assert.equal(outputs[1].amount, (3n * KAS_CASH - KAS_CASH - fee).toString());
    // Change that goes elsewhere is refused, and signed under a change address that names it.
    const seller = w.wallets.seller;
    const away = fund(fee, seller.publicKey());
    assert.equal(refusalError(() => buyer.sign(away, options(w))).code, "SDK_SIGN_CHANGE_NOT_MINE");
    assert.deepEqual(buyer.sign(away, options(w, { change: seller.address(w.network) })).signed_inputs, [0]);
    // A fee above twice the minimum is refused, and signed under a limit that allows it.
    const dear = fund(10n * min);
    assert.equal(refusalError(() => buyer.sign(dear, options(w))).code, "SDK_SIGN_FEE_TOO_HIGH");
    assert.deepEqual(buyer.sign(dear, options(w, { max_fee: (10n * min).toString() })).signed_inputs, [0]);
    // The topup limit does not apply to a funding: its payer cost is the deposit.
    const review = ipst.review(w.artifacts, NOW.toString(), VALUE);
    assert.equal(review.payer_cost, KAS_CASH.toString());
    assert.match(review.payer_cost_text, /, the deposit$/);
    assert.deepEqual(buyer.sign(ipst, options(w, { max_topup: "0" })).signed_inputs, [0]);

    // A KCC-20 funding: the seller's two tokens hold 1300 for a leg of 1000, the builder returns 300 as
    // token change, and the seller commits the deposit's carrier and authorizer, not the change.
    const tokens = [
      ownToken(sdk, "seller-token-1", ASSET_ARTIFACT, ASSET_COV, seller.publicKey(), 600n),
      ownToken(sdk, "seller-token-2", ASSET_ARTIFACT, ASSET_COV, seller.publicKey(), 700n),
    ];
    const deposit = { artifact: ASSET_ARTIFACT, tokens, carrier: CARRIER.toString(), authorizer: AUTHORIZER.toString() };
    const fundAsset = w.terms.fundKcc20(
      0,
      context,
      deposit,
      { inputs: [utxo("seller-fee", FEE_INPUT, p2pk(seller.publicKey()))], fee: "1000000", change: p2pk(seller.publicKey()) },
      VALUE,
    );
    const assetReview = fundAsset.review(w.artifacts, NOW.toString(), VALUE);
    assert.deepEqual(assetReview.kind, { builder: "fund_kcc20", leg: 0 });
    // The seller owns the tokens and the fee input here, so it signs all three inputs.
    assert.deepEqual(seller.sign(fundAsset, options(w)).signed_inputs, [0, 1, 2]);
    // The buyer's wallet has nothing to sign in the seller's funding.
    assert.equal(refusalError(() => buyer.sign(fundAsset, options(w))).code, "SDK_SIGN_NOTHING_TO_SIGN");
    // The deposit's carrier and authorizer are what the signer confirms, not what the document says:
    // a funding that puts 3 KAS on the escrowed token, or 0.6 KAS on the authorizer, is refused until
    // the signer confirms that amount, beside the funding at the defaults that signed above.
    const deposited = (carrier: bigint, authorizer: bigint) =>
      w.terms.fundKcc20(
        0,
        context,
        { ...deposit, carrier: carrier.toString(), authorizer: authorizer.toString() },
        { inputs: [utxo("seller-fee", FEE_INPUT, p2pk(seller.publicKey()))], fee: "1000000", change: p2pk(seller.publicKey()) },
        VALUE,
      );
    const heavy = deposited(300_000_000n, AUTHORIZER);
    const mismatch = refusalError(() => seller.sign(heavy, options(w)));
    assert.equal(mismatch.code, "SDK_SIGN_DEPOSIT_MISMATCH");
    assert.equal(
      mismatch.message,
      "SDK_SIGN_DEPOSIT_MISMATCH: the deposit puts 300000000 sompi on the escrowed token and 50000000 on the authorizer; you confirm 200000000 and 50000000 (pass carrier and authorizer to confirm other amounts)",
    );
    assert.deepEqual(seller.sign(heavy, options(w, { carrier: "300000000" })).signed_inputs, [0, 1, 2], "confirmed");
    assert.equal(refusalError(() => seller.sign(heavy, options(w, { carrier: "299999999" }))).code, "SDK_SIGN_DEPOSIT_MISMATCH", "one sompi off");
    const rich = deposited(CARRIER, 60_000_000n);
    assert.equal(refusalError(() => seller.sign(rich, options(w))).code, "SDK_SIGN_DEPOSIT_MISMATCH");
    assert.deepEqual(seller.sign(rich, options(w, { authorizer: "60000000" })).signed_inputs, [0, 1, 2], "confirmed");
    assert.equal(refusalError(() => seller.sign(rich, options(w, { authorizer: "60000001" }))).code, "SDK_SIGN_DEPOSIT_MISMATCH", "one sompi off");
    // `authorizer` confirms a KCC-20 funding and means nothing for any other document.
    assert.equal(refusalError(() => buyer.sign(ipst, options(w, { authorizer: "50000000" }))).code, "TX_WRONG_MODE");
    assert.deepEqual(buyer.sign(ipst, options(w)).signed_inputs, [0], "control: the KAS funding without it");
  } finally {
    freeAll(w.wallets);
  }
});
