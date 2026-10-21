// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What the page says when it cannot tell what happened, in a real browser: a submission whose answer
// is lost (the node may have taken the transaction), the sockets the decoder leaves open, a key that
// could not be drawn, and a scan for the wallets' keys through the Vault settle and the refund as
// well as the Direct trade. Each case sits beside the accepted one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { schnorr } from "../../crates/impulse-wasm/npm/node_modules/@noble/curves/secp256k1.js";
import {
  DROP,
  HANGUP,
  build,
  channelsOf,
  chooseRefund,
  connect,
  decode,
  drawnKeys,
  openDecoder,
  prepare,
  sdkOf,
  sentCount,
  signWith,
  submitAndWait,
  text,
  until,
  withTrade,
} from "./session.ts";
import { spellingsOf } from "./spellings.ts";
import type { Page } from "playwright-core";

const status = async (page: Page) => ({
  state: await page.getAttribute("#submit-status", "data-state"),
  text: (await text(page, "#submit-status")) ?? "",
});

/** The ID of the transaction the page has signed, from its partially signed form, by the SDK in Node. */
async function signedTxid(page: Page): Promise<string> {
  const sdk = await sdkOf();
  const ipst = sdk.Ipst.fromJson((await text(page, "#ipst-text")) ?? "");
  const signed = ipst.finalize();
  const id = Buffer.from(signed.txid()).toString("hex");
  signed.free();
  ipst.free();
  return id;
}

test("a submission whose answer never comes is not reported as refused: the page gives the ID, a link to look, and keeps submit off until the node is asked", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    fake.autoAccept = false;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
    const txid = await signedTxid(page);
    // The node takes the transaction into its mempool, and its answer is lost.
    t.handler.current = (request) => {
      const reply = fake.handle(request);
      return (JSON.parse(request) as { method: string }).method === "submitTransaction" ? DROP : reply;
    };
    await page.clock.install();
    await page.click("#submit");
    await until(() => sentCount(s, "submitTransaction") === 1, "the submission");
    await page.clock.fastForward(21_000);
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
    const said = await status(page);
    assert.ok(
      said.text.startsWith(
        `Outcome unknown: The node did not answer within 20 s. The transaction may have been accepted. Its ID is ${txid}. Do not submit again before you have checked: `,
      ),
      said.text,
    );
    assert.doesNotMatch(said.text, /Not submitted|Refused/);
    // The way to look: the decoder, in another tab, from the block before the submission.
    assert.equal(await page.getAttribute("#submit-status a", "href"), `decoder.html#txid=${txid}&from=${fake.genesis}`);
    assert.equal(await page.getAttribute("#submit-status a", "target"), "_blank");
    assert.equal(await page.getAttribute("#submit-status a", "rel"), "noopener");
    assert.equal(await page.isDisabled("#submit"), true, "submit stays off");
    assert.equal(sentCount(s, "submitTransaction"), 1);
    // Asking the node: it has the transaction in its mempool, and the page says it was accepted.
    await page.click("#submit-check");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "ok");
    assert.ok(((await status(page)).text).startsWith(`The node has the transaction ${txid} in its mempool: it was accepted. Do not submit it again. `));
    assert.equal(await page.isDisabled("#submit"), true, "and it is still not submitted twice");
    assert.equal(sentCount(s, "submitTransaction"), 1);
    // A new build is a new document, and its submission is not clouded by the last one's.
    t.handler.current = (request) => fake.handle(request);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await page.isDisabled("#submit"), true, "unsigned");
    assert.equal((await signWith(page, "b")).state, "ok");
    assert.equal(await page.isDisabled("#submit"), false);
    assert.equal(await page.locator("#submit-check").count(), 0);
  });
});

test("a node that hangs up on the submission is an unknown outcome too; once the page is connected again and the node says it does not have the transaction, submit is on and goes through", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
    const txid = await signedTxid(page);
    t.handler.current = (request) => ((JSON.parse(request) as { method: string }).method === "submitTransaction" ? HANGUP : fake.handle(request));
    await page.click("#submit");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
    assert.ok(((await status(page)).text).startsWith(`Outcome unknown: The connection to the node closed. The transaction may have been accepted. Its ID is ${txid}.`));
    assert.equal(await page.isDisabled("#submit"), true);
    assert.equal(fake.accepted.length, 0, "this node never saw it");
    // The connection is gone: the page cannot ask, and says so without turning it into an answer.
    await page.click("#submit-check");
    await page.waitForFunction(() => /^The node could not be asked: /.test(document.querySelector("#submit-status")?.textContent ?? ""));
    assert.equal((await status(page)).state, "unknown");
    assert.equal(await page.isDisabled("#submit"), true);
    // Connected again, the node does not have it: not in its mempool, and the page says it may be in a block.
    t.handler.current = (request) => fake.handle(request);
    assert.equal((await connect(page)).state, "connected");
    await page.click("#submit-check");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "wait");
    assert.match((await status(page)).text, new RegExp(`^The node's mempool does not have ${txid}\\. It may already be in a block`));
    assert.equal(await page.isDisabled("#submit"), false);
    const sent = await submitAndWait(page);
    assert.equal(sent.state, "ok", sent.text);
    assert.equal(fake.accepted.length, 1);
    assert.equal(sentCount(s, "submitTransaction"), 2, "the first never reached the node, the second did");
  });
});

test("a node that answers a submission with its refusal is a refusal, and the document can be sent again", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
    fake.rejectNext = "the mempool is full";
    const refused = await submitAndWait(page);
    assert.equal(refused.state, "refused");
    assert.match(refused.text, /^Refused: .*the mempool is full/);
    assert.equal(await page.locator("#submit-check").count(), 0, "a refusal is an answer: there is nothing to check");
    assert.equal(await page.isDisabled("#submit"), false);
    assert.equal((await submitAndWait(page)).state, "ok");
  });
});

test("the decoder closes the socket it opened when it is done, after a decode and after a refusal", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
    assert.equal((await submitAndWait(page)).state, "ok");
    const txid = fake.accepted[0].txid;
    assert.deepEqual(s.closed, [], "the trade page's own connection is still open");
    const decoder = await openDecoder(t);
    assert.equal((await decode(decoder, { txid, from: fake.genesis })).state, "ok");
    await until(() => s.closed.length === 1, "the decoder's socket to close");
    const refused = await decode(decoder, { txid: "ab".repeat(32), from: fake.genesis });
    assert.equal(refused.state, "refused");
    await until(() => s.closed.length === 2, "the decoder's second socket to close");
    assert.equal(s.contacted.length, 3, "one socket for the trade page, one for each decode");
    await decoder.close();
  });
});

test("a key that cannot be drawn is reported as no key made, the wallet holds nothing, and the next press makes one", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    await page.click("#wallet-a .wallet-wipe");
    assert.equal(await page.getAttribute("#wallet-a .wallet-state", "data-state"), "wiped");
    const oldKey = await text(page, "#wallet-a .wallet-key");
    // The browser gives no randomness.
    await page.evaluate(() => {
      const crypto = globalThis.crypto;
      (window as unknown as { __real: unknown }).__real = crypto.getRandomValues.bind(crypto);
      Object.defineProperty(crypto, "getRandomValues", {
        configurable: true,
        writable: true,
        value: () => {
          throw new Error("no randomness here");
        },
      });
    });
    await page.click("#wallet-a .wallet-generate");
    assert.equal(await page.getAttribute("#wallet-a .wallet-state", "data-state"), "error");
    const said = (await text(page, "#wallet-a .wallet-state")) ?? "";
    assert.match(said, /^No key was made: /);
    assert.ok(said.includes("SDK_WALLET_RANDOM"), said);
    assert.equal(await text(page, "#wallet-a .wallet-key"), oldKey, "the wiped wallet's public key is as it was: no new key");
    assert.equal(await page.isDisabled("#wallet-a .wallet-generate"), false, "it can be asked again");
    // Control: with randomness back, the same press makes a key.
    await page.evaluate(() => {
      Object.defineProperty(globalThis.crypto, "getRandomValues", {
        configurable: true,
        writable: true,
        value: (window as unknown as { __real: unknown }).__real,
      });
    });
    await page.click("#wallet-a .wallet-generate");
    assert.equal(await page.getAttribute("#wallet-a .wallet-state", "data-state"), "ready");
    assert.notEqual(await text(page, "#wallet-a .wallet-key"), oldKey);
  });
});

// The scan for a key in every channel of the page, through a whole trade of each kind.

test("no wallet's key appears in the page, its storage, its traffic or its console through a Vault settle with its decoding, or through a refund", async () => {
  for (const flow of ["settle", "refund"] as const) {
    await withTrade("vault", async (t) => {
      const { page, fake, keys } = t;
      // The two wallets' keys are the first two 32-byte draws of the page, before anything else
      // runs; an independent implementation derives each wallet's public key from its draw.
      const draws = (await drawnKeys(page)).slice(0, 2);
      assert.equal(draws.length, 2, "one draw for each wallet");
      assert.ok(Buffer.from(schnorr.getPublicKey(Uint8Array.from(Buffer.from(draws[0], "hex")))).toString("hex") === keys.a, "the first draw is wallet A's key");
      assert.ok(Buffer.from(schnorr.getPublicKey(Uint8Array.from(Buffer.from(draws[1], "hex")))).toString("hex") === keys.b, "the second draw is wallet B's key");
      await prepare(t);
      if (flow === "refund") await chooseRefund(page, 1, "counterparty");
      assert.equal((await build(page, flow === "settle" ? "#build-settle" : "#build-refund")).state, "ok");
      if (flow === "refund") await signWith(page, "a");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      const decoder = await openDecoder(t);
      assert.equal((await decode(decoder, { txid: fake.accepted[0].txid, from: fake.genesis })).state, "ok");
      await decoder.close();
      const seen = await channelsOf(t);
      assert.ok(seen.includes(keys.a) && seen.includes(keys.b), `${flow}: the scan reads real text with the public keys in it`);
      for (const [who, secret] of [["A", draws[0]], ["B", draws[1]]] as const) {
        assert.ok(!spellingsOf(secret).some((x) => seen.includes(x)), `${flow}: wallet ${who}'s key appears somewhere`);
      }
      // Control: a stand-in drawn here and put into the page is found by the same scan.
      const stand = randomBytes(32).toString("hex");
      await page.evaluate((v) => {
        const p = document.createElement("p");
        p.textContent = v;
        document.body.append(p);
      }, stand);
      assert.ok((await channelsOf(t)).includes(stand), `${flow}: the scan finds a stand-in key where one is planted`);
    });
  }
});
