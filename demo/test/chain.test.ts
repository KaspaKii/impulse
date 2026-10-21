// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The decoder's walk along the chain, in a real browser, against an offline node that pages its
// answers and can reorganise its chain: the transaction in a later page, the cursor that moves on
// by the last block of a page, the bound on the number of pages, and a block that leaves the chain
// after it accepted the transaction, with the transaction accepted again elsewhere or not at all.
// Each case sits beside the walk that finds the transaction where it was.
import { test } from "node:test";
import assert from "node:assert/strict";
import { build, decode, openDecoder, prepare, signWith, submitAndWait, text, withTrade, type Trade } from "./session.ts";
import { NOW } from "./world.ts";

/** Builds, signs and submits a settle that the node keeps in its mempool; returns its ID. */
async function pending(t: Trade): Promise<string> {
  t.fake.autoAccept = false;
  await prepare(t);
  assert.equal((await build(t.page)).state, "ok");
  assert.equal((await signWith(t.page, "b")).state, "ok");
  const sent = await submitAndWait(t.page);
  assert.equal(sent.state, "ok", sent.text);
  const txid = /transaction ([0-9a-f]{64})/.exec(sent.text)?.[1] ?? "";
  assert.match(txid, /^[0-9a-f]{64}$/);
  return txid;
}

const chainCalls = (t: Trade) =>
  t.fake.received.filter((r) => r.method === "getVirtualChainFromBlockV2").map((r) => r.params.startHash as string);

const receipt = (page: Awaited<ReturnType<typeof openDecoder>>) => text(page, "#out-receipt .receipt");

test("the walk follows the pages the node gives: each call starts from the last block of the page before, and the transaction in a later page is found", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { fake } = t;
      const txid = await pending(t);
      // Chain: b1, b2, b3 empty; b4 accepts the transaction; b5, b6 empty. Pages of two.
      const [b1, b2, b3] = [fake.mineEmpty(), fake.mineEmpty(), fake.mineEmpty()];
      fake.mine(txid);
      const b4 = fake.blockHash(4);
      const [b5, b6] = [fake.mineEmpty(), fake.mineEmpty()];
      assert.deepEqual([b1, b2, b3].length, 3);
      const decoder = await openDecoder(t);
      const done = await decode(decoder, { txid, from: fake.genesis });
      assert.equal(done.state, "ok", done.text);
      assert.match(done.text, /from the node's chain: 2 legs\.$/);
      // The page after the one with the transaction is read too, and then the tip: the cursor moved
      // on by the last block of each page, and by nothing else.
      assert.deepEqual(chainCalls(t), [fake.genesis, b2, b4, b6]);
      assert.equal(
        await receipt(decoder),
        `Accepted by chain block ${b4} at DAA score ${NOW}; the node is at DAA score ${NOW}, 0 DAA scores after that block.`,
      );
      void b5;
      await decoder.close();
    },
    { batchSize: 2 },
  );
});

test("the walk ends at the bound on pages: a transaction in the last page it reads is found, one in the page after is not, and the page says why", async () => {
  // 205 chain blocks, one to a page: the bound is 200 pages.
  const walk = async (block: number): Promise<{ state: string; text: string; receipt: string | null }> => {
    let result = { state: "", text: "", receipt: null as string | null };
    await withTrade(
      "vault",
      async (t) => {
        const { fake } = t;
        const txid = await pending(t);
        for (let i = 1; i < block; i += 1) fake.mineEmpty();
        fake.mine(txid);
        for (let i = block; i < 205; i += 1) fake.mineEmpty();
        const decoder = await openDecoder(t);
        const done = await decode(decoder, { txid, from: fake.genesis });
        result = { state: done.state, text: done.text, receipt: done.state === "ok" ? await receipt(decoder) : null };
        if (done.state === "ok") assert.equal(chainCalls(t).length, 200, "the walk read exactly the pages the bound allows");
        await decoder.close();
      },
      { batchSize: 1 },
    );
    return result;
  };
  const last = await walk(200);
  assert.equal(last.state, "ok", last.text);
  assert.match(last.receipt ?? "", /^Accepted by chain block [0-9a-f]{64} at DAA score /);
  const past = await walk(201);
  assert.equal(past.state, "refused");
  assert.equal(
    past.text,
    "Not decoded: Gave up after 200 batches of the chain without reaching the node's tip, and the transaction was not in them: give a chain block nearer the submission.",
  );
});

test("a walk that reaches the tip without the transaction says it is not on the chain from that block, and not that it gave up", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { fake } = t;
      const txid = await pending(t);
      for (let i = 0; i < 5; i += 1) fake.mineEmpty();
      const decoder = await openDecoder(t);
      const none = await decode(decoder, { txid: "ab".repeat(32), from: fake.genesis });
      assert.equal(none.state, "refused");
      assert.match(none.text, /^Not decoded: Not found in the node's mempool, nor accepted on the chain from the block given\.$/);
      assert.doesNotMatch(none.text, /Gave up/);
      // Control: the transaction mined at the end of that chain is found by the same walk.
      fake.mine(txid);
      const found = await decode(decoder, { txid, from: fake.genesis });
      assert.equal(found.state, "ok", found.text);
      await decoder.close();
    },
    { batchSize: 2 },
  );
});

test("a block that accepted the transaction and then left the chain no longer counts; the transaction accepted again elsewhere is read there, and one not accepted again is not found", async () => {
  for (const again of [true, false]) {
    await withTrade(
      "vault",
      async (t) => {
        const { fake } = t;
        const txid = await pending(t);
        fake.mineEmpty();
        fake.mine(txid);
        const old = fake.blockHash(2);
        // The walk has read the page with the old block when the node reorganises: the next call
        // names the old block, and is told it was removed and what the chain is now.
        let reorganised = false;
        t.handler.current = (request) => {
          const frame = JSON.parse(request) as { method: string; params: { startHash?: string } };
          if (frame.method === "getVirtualChainFromBlockV2" && frame.params.startHash === old && !reorganised) {
            reorganised = true;
            fake.reorg(old, again);
          }
          return fake.handle(request);
        };
        const decoder = await openDecoder(t);
        const done = await decode(decoder, { txid, from: fake.genesis });
        assert.ok(reorganised, "the node reorganised during the walk");
        if (again) {
          assert.equal(done.state, "ok", done.text);
          const now = fake.blockHash(2);
          assert.notEqual(now, old, "the transaction is in another block now");
          assert.equal(
            await receipt(decoder),
            `Accepted by chain block ${now} at DAA score ${NOW}; the node is at DAA score ${NOW}, 0 DAA scores after that block.`,
          );
          assert.ok(!(await receipt(decoder))?.includes(old), "and the old block is not named");
        } else {
          assert.equal(done.state, "refused", done.text);
          assert.match(done.text, /^Not decoded: Not found in the node's mempool, nor accepted on the chain from the block given\.$/);
          assert.equal(await decoder.locator("#out-trade .leg").count(), 0, "nothing of the removed acceptance is shown");
        }
        await decoder.close();
      },
      { batchSize: 1 },
    );
  }
  // Control: with no reorganisation the same chain gives the block it was accepted in.
  await withTrade(
    "vault",
    async (t) => {
      const { fake } = t;
      const txid = await pending(t);
      fake.mineEmpty();
      fake.mine(txid);
      const decoder = await openDecoder(t);
      const done = await decode(decoder, { txid, from: fake.genesis });
      assert.equal(done.state, "ok", done.text);
      assert.ok(((await receipt(decoder)) ?? "").includes(fake.blockHash(2)));
      await decoder.close();
    },
    { batchSize: 1 },
  );
});
