// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The wallets, settle, refund and Direct in a real browser (headless Chrome), against an offline
// node (crates/impulse-wasm/npm/test/fakenode.ts, stood in for a kaspad's wRPC JSON through
// Playwright's WebSocket routing): two wallets made in the page, a node URL typed in, the
// transaction built from the node's UTXOs, the review read, each wallet signing its own inputs,
// the signed transaction submitted. The expectations are written from the fixtures (the amounts the
// UTXOs hold, the addresses the page shows for the keys), not from the SDK. The fake node runs no
// script and checks no signature (its header says what it does check): these tests show that the
// page drives the SDK through the whole sequence and sends only what it should, not that a real
// node accepts the result.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  NODE_HREF,
  NODE_URL,
  build,
  chooseRefund,
  decode,
  fact,
  frames,
  hexOf,
  kasText,
  needs,
  openDecoder,
  prepare,
  rows,
  signWith,
  submitAndWait,
  text,
  withTrade,
} from "./session.ts";
import {
  AMOUNT_A,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  EXPIRY,
  FEE_INPUT,
  KAS_CASH,
  NOW,
  externalTermsFor,
  termsFor,
} from "./world.ts";
import { pinOf } from "./party.ts";

test("external cash with an authority: the page builds the settle that needs the authority's key and hands it over; the cash leg has no refund to build", async () => {
  let authority = "";
  await withTrade(
    "vault",
    async (t) => {
      const { page } = t;
      await prepare(t);
      const built = await build(page);
      assert.equal(built.state, "ok", built.text);
      // The cash is paid outside Kaspa: no cash input, no cash output, and the authority attests it.
      const inputs = await rows(page, "#review-inputs-body");
      assert.deepEqual(inputs.map((r) => r.what.replace(/ \(P2PK of the key .*$/, "")), [
        "the asset vault",
        "the asset token escrowed in the asset vault",
        "the buyer's key (P2PK)",
      ]);
      assert.equal(inputs[0].signer, needs(authority, "authority"), "the authority signs the vault input");
      // The wallets sign what they hold; the authority's input stays open and the page says whose it is.
      assert.deepEqual(
        await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)),
        ["Sign with wallet B (input 2)"],
      );
      await signWith(page, "b");
      assert.equal(await page.isDisabled("#submit"), true, "an input of the authority is unsigned");
      assert.match(
        (await text(page, "#review-pending")) ?? "",
        new RegExp(`^Inputs still unsigned: 0\\. 1 of them needs a key this page does not hold \\(${authority}\\)`),
      );
      const ipst = JSON.parse((await text(page, "#ipst-text")) ?? "{}") as { inputs: { signer: string | null; signature: string | null }[] };
      assert.equal(ipst.inputs[0].signer, authority);
      assert.equal(ipst.inputs[0].signature, null);
      // Owner decision D14: nothing recovers a stray deposit to the cash vault of external cash, and
      // the cash leg of external cash has no vault to refund.
      await chooseRefund(page, 1, "depositor", false);
      const refund = await build(page, "#build-refund");
      assert.deepEqual([refund.state, refund.code], ["refused", "TEMPLATE_NO_VAULT"]);
      assert.equal(await page.isVisible("#review-panel"), false);
      // The asset leg's refund, beside it, builds.
      await chooseRefund(page, 0, "depositor", true);
      assert.equal((await build(page, "#build-refund")).state, "ok");
    },
    {
      terms: (sdk, k) => {
        const w = sdk.Wallet.generate();
        authority = w.publicKey();
        w.free();
        return externalTermsFor(sdk, k.a, k.b, authority);
      },
    },
  );
});

test("a Direct trade in the page: build from the node's UTXOs, review, both wallets sign, submit", async () => {
  await withTrade("direct", async (t) => {
    const { page, fake, keys, addresses, s } = t;
    await prepare(t);
    assert.equal(await page.isVisible("#actions"), true);
    assert.equal(await text(page, "#build-settle"), "Build the Direct trade");
    assert.equal(await page.isVisible("#refund-options"), false, "a Direct trade has no refund");
    const built = await build(page);
    assert.equal(built.state, "ok", built.text);

    // The review: every input and output with its amount, address and name, from the fixtures.
    assert.match((await text(page, "#review-title")) ?? "", /^Direct trade/);
    const inputs = await rows(page, "#review-inputs-body");
    assert.equal(inputs.length, 3);
    assert.deepEqual(inputs.map((r) => r.amount), [kasText(CARRIER), kasText(KAS_CASH), kasText(FEE_INPUT)]);
    assert.match(inputs[0].what, /^the seller's asset token \(KCC-20, owner the seller's key\)$/);
    assert.equal(inputs[0].covenant, ASSET_COV);
    assert.equal(inputs[1].address, addresses.b);
    assert.equal(inputs[2].address, addresses.b);
    assert.deepEqual(inputs.map((r) => r.signer), [needs(keys.a, "seller"), needs(keys.b, "buyer"), needs(keys.b, "buyer")]);
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs.length, 3);
    assert.match(outputs[0].what, /^buyer_delivery \(the asset arrives here\), as a KCC-20 token \[pays a key that lives only in this page\]$/);
    assert.equal(outputs[0].amount, kasText(CARRIER));
    assert.equal(outputs[0].covenant, ASSET_COV);
    assert.equal(outputs[1].amount, kasText(KAS_CASH));
    assert.equal(outputs[1].address, addresses.a);
    assert.match(outputs[1].what, /^seller_proceeds \(the cash arrives here\)/);
    const fee = BigInt(/\((\d+) sompi\)/.exec((await fact(page, "fee")) ?? "")?.[1] ?? "x");
    assert.equal(outputs[2].amount, kasText(FEE_INPUT - fee), "the change is the fee input less the fee");
    assert.equal(outputs[2].address, addresses.b);
    assert.match((await fact(page, "lock-time")) ?? "", /^DAA score 1000000: final in a block from DAA score 1000001$/);
    assert.equal(await fact(page, "submit-ready"), "yes");
    assert.equal(await page.isDisabled("#submit"), true, "nothing is signed yet");

    // Both wallets sign their own inputs and no others.
    assert.deepEqual(
      await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)),
      ["Sign with wallet A (input 0)", "Sign with wallet B (inputs 1, 2)"],
    );
    const bySeller = await signWith(page, "a");
    assert.equal(bySeller.state, "ok", bySeller.text);
    assert.match(bySeller.text, /^Wallet A signed input 0\.$/);
    assert.deepEqual((await rows(page, "#review-inputs-body")).map((r) => r.signed), ["true", "false", "false"]);
    assert.equal(await page.isDisabled("#submit"), true, "the buyer's inputs are unsigned");
    assert.equal(await page.locator('#sign-buttons button[data-wallet="a"]').count(), 0);
    await signWith(page, "b");
    assert.deepEqual((await rows(page, "#review-inputs-body")).map((r) => r.signed), ["true", "true", "true"]);
    assert.equal(await page.isDisabled("#submit"), false);
    assert.equal(await page.locator("#sign-buttons button").count(), 0);
    // Nothing went to the node but questions: the transaction is held back until the click.
    assert.deepEqual(
      frames(s).map((f) => f.method),
      ["getServerInfo", "getServerInfo", "getServerInfo", "getUtxosByAddresses"],
      "connect, read the score, build: three questions about the node's state and one for the UTXOs",
    );
    assert.equal(fake.accepted.length, 0);

    const submitted = await submitAndWait(page);
    assert.equal(submitted.state, "ok", submitted.text);
    assert.equal(fake.accepted.length, 1);
    const accepted = fake.accepted[0];
    assert.ok(submitted.text.includes(accepted.txid), "the page names the transaction the node took");
    assert.equal(await page.isDisabled("#submit"), true, "a submitted document is not submitted twice");

    // What the node holds now: the seller has the cash, the buyer the token; the inputs are spent.
    assert.deepEqual(fake.at(addresses.a).map((u) => u.amount), [KAS_CASH.toString()]);
    const held = (fake as unknown as { held: Map<string, { utxo: { covenant_id: string | null; amount: string }; spent: boolean }> }).held;
    const delivered = [...held.values()].filter((h) => !h.spent && h.utxo.covenant_id === ASSET_COV).map((h) => h.utxo.amount);
    assert.deepEqual(delivered, [CARRIER.toString()], "one asset token UTXO, the buyer's");
    assert.equal(fake.at(addresses.b).length, 1, "the buyer's change");
    // The one submission carried the signed transaction: every input has its signature script, and
    // the outputs are the ones the review showed.
    const submits = frames(s).filter((f) => f.method === "submitTransaction");
    assert.equal(submits.length, 1);
    assert.equal(submits[0].params.allowOrphan, false);
    assert.ok(submits[0].params.transaction.inputs.every((i: { signatureScript: string }) => i.signatureScript.length > 0));
    assert.deepEqual(
      submits[0].params.transaction.outputs.map((o: { value: number }) => String(o.value)),
      outputs.map((r) => r.amount.replace(/^.*\((\d+) sompi\)$/, "$1")),
    );
    // The only node the page contacted is the one typed.
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
    assert.deepEqual(s.external, []);
    assert.deepEqual(s.errors, []);
  });
});

test("a custodian's destination: the pin the user typed goes to the user's own wallet and to no other, and the trade signs and submits", async () => {
  // The buyer's cash refund pays a custodian's script, which the buyer states as a pin.
  const custodian = { kind: "kas", version: 0, script: `aa20${"cc".repeat(32)}87` };
  await withTrade(
    "direct",
    async (t) => {
      const { page, fake } = t;
      await prepare(t, "buyer", { refund: pinOf("testnet", custodian) });
      assert.equal((await build(page)).state, "ok");
      // Wallet B holds the key the user gave, so the pin goes to it: its role check finds the
      // buyer's refund equal to the pin. Without the pin it would refuse the same document.
      const b = await signWith(page, "b");
      assert.deepEqual([b.state, b.code], ["ok", ""], b.text);
      assert.match(b.text, /^Wallet B signed inputs? /);
      // Wallet A is the seller's. Given the buyer's pin it would be held to it, and its own refund
      // does not equal that, so it would refuse; the page gives it none, and it signs.
      const a = await signWith(page, "a");
      assert.deepEqual([a.state, a.code], ["ok", ""], a.text);
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(fake.accepted.length, 1);
    },
    { terms: (sdk, k) => ({ ...termsFor(sdk, "direct", k.a, k.b), buyer_refund: custodian }) },
  );
});

test("a Vault trade in the page: settle from the vaults, the payer signs the fee, submit; the decoder page reads the trade back from the node", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, keys, addresses, s, sdk, terms } = t;
    await prepare(t);
    assert.equal(await text(page, "#build-settle"), "Build the settle");
    assert.equal(await page.isVisible("#refund-options"), true);
    const built = await build(page);
    assert.equal(built.state, "ok", built.text);
    assert.match((await text(page, "#review-title")) ?? "", /^Settle/);

    const inputs = await rows(page, "#review-inputs-body");
    assert.deepEqual(inputs.map((r) => r.amount), [kasText(AUTHORIZER), kasText(KAS_CASH), kasText(CARRIER), kasText(FEE_INPUT)]);
    assert.deepEqual(inputs.map((r) => r.what), [
      "the asset vault",
      "the cash vault",
      "the asset token escrowed in the asset vault",
      "the buyer's key (P2PK)",
    ]);
    assert.equal(inputs[2].covenant, ASSET_COV);
    // Self-settling: the vault inputs and the vault-owned token take no signature; only the fee input does.
    assert.deepEqual(inputs.map((r) => r.signer), ["no signature", "no signature", "no signature", needs(keys.b, "buyer")]);
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs.length, 4);
    assert.match(outputs[0].what, /^buyer_delivery \(the asset arrives here\), as a KCC-20 token \[pays a key that lives only in this page\]$/);
    assert.equal(outputs[1].amount, kasText(KAS_CASH));
    assert.equal(outputs[1].address, addresses.a);
    assert.match(outputs[1].what, /^seller_proceeds/);
    assert.equal(outputs[2].amount, kasText(AUTHORIZER), "the authorizer's KAS goes back to the seller");
    assert.equal(outputs[2].address, addresses.a);
    assert.equal(outputs[3].address, addresses.b);
    assert.deepEqual(
      await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)),
      ["Sign with wallet B (input 3)"],
    );
    assert.equal(await page.isDisabled("#submit"), true);
    await signWith(page, "b");
    assert.equal(await page.isDisabled("#submit"), false);
    const submitted = await submitAndWait(page);
    assert.equal(submitted.state, "ok", submitted.text);
    assert.equal(fake.accepted.length, 1);
    const txid = fake.accepted[0].txid;

    // The page links to the decoder with the transaction and the block before the submission.
    assert.equal(await page.getAttribute("#submit-status a", "href"), `decoder.html#txid=${txid}&from=${fake.genesis}`);

    // The decoder page, opened from that link, fetches it from the node and reads the trade back.
    const decoder = await openDecoder(t, `#txid=${txid}&from=${fake.genesis}`);
    assert.equal(await decoder.inputValue("#txid"), txid);
    assert.equal(await decoder.inputValue("#from-block"), fake.genesis);
    const done = await decode(decoder, {});
    assert.equal(done.state, "ok", done.text);
    assert.match(done.text, /^Decoded .* from the node's chain: 2 legs\.$/);
    assert.equal(await decoder.locator("#out-trade .leg").count(), 2);
    const termsHash = hexOf(sdk.Terms.fromJson(terms).termsHash());
    assert.deepEqual(await decoder.locator("#out-trade .terms-hash").evaluateAll((nodes) => nodes.map((n) => n.getAttribute("title"))), [termsHash, termsHash]);
    // Shown shortened in the middle, whole in the title.
    assert.deepEqual(await decoder.locator("#out-trade .terms-hash").allTextContents(), [`${termsHash.slice(0, 10)}...${termsHash.slice(-8)}`, `${termsHash.slice(0, 10)}...${termsHash.slice(-8)}`]);
    const outcomes = await decoder.locator("#out-trade .outcome").allTextContents();
    assert.equal(outcomes[0], `Delivered ${AMOUNT_A} to KCC-20 owner pubkey ${keys.b}`);
    assert.equal(outcomes[1], `Delivered ${KAS_CASH} to KAS scriptPublicKey (version 0) 20${keys.a}ac`);
    assert.match((await decoder.locator("#out-trade h3").first().textContent()) ?? "", /^Input 0 spends the vault of the asset leg: settle$/);
    assert.equal(await decoder.getAttribute("#out-template .template-hash", "title"), hexOf(sdk.templateCheck().hash()));
    assert.equal(await decoder.getAttribute("#out-template .binding", "data-bound"), "true");
    assert.match((await text(decoder, "#out-template .binding")) ?? "", /^Bound: the node gave the scriptPublicKey each input spends/);
    assert.equal(
      await text(decoder, "#out-receipt .receipt"),
      `Accepted by chain block ${fake.blockHash(1)} at DAA score ${NOW}; the node is at DAA score ${NOW}, 0 DAA scores after that block.`,
    );
    // The two pages contacted only the node typed.
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
    assert.deepEqual(s.external, []);
    assert.deepEqual(s.errors, []);
    await decoder.close();
  });
});

test("a refund in the page: the counterparty takes the cash leg home, both wallets sign, and the decoder reads it as refunded", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, keys, addresses, s } = t;
    await prepare(t);
    await chooseRefund(page, 1, "counterparty");
    const built = await build(page, "#build-refund");
    assert.equal(built.state, "ok", built.text);
    assert.equal(await text(page, "#review-title"), "Refund of the cash leg, signed by the counterparty");
    const inputs = await rows(page, "#review-inputs-body");
    assert.deepEqual(inputs.map((r) => r.amount), [kasText(KAS_CASH), kasText(FEE_INPUT)]);
    assert.equal(inputs[0].what, "the cash vault");
    // The counterparty of the cash leg is the seller: wallet A signs the vault input.
    assert.deepEqual(inputs.map((r) => r.signer), [needs(keys.a, "seller"), needs(keys.b, "buyer")]);
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs[0].amount, kasText(KAS_CASH));
    assert.equal(outputs[0].address, addresses.b);
    assert.match(outputs[0].what, /^buyer_refund \(the cash returns here\)/);
    assert.equal(await fact(page, "lock-time"), "none: a node admits it at once");
    await signWith(page, "a");
    await signWith(page, "b");
    const sent = await submitAndWait(page);
    assert.equal(sent.state, "ok", sent.text);
    const decoded = fake.accepted[0].decoded as { legs: { leg: number; outcome: { kind: string } }[] };
    assert.deepEqual(decoded.legs.map((l) => [l.leg, l.outcome.kind]), [[1, "refunded"]]);
    // The cash is the buyer's again, as a UTXO of exactly the leg amount.
    assert.ok(fake.at(addresses.b).some((u) => u.amount === KAS_CASH.toString()));

    const decoder = await openDecoder(t);
    const done = await decode(decoder, { txid: fake.accepted[0].txid, from: fake.genesis });
    assert.equal(done.state, "ok", done.text);
    assert.equal(
      await decoder.locator("#out-trade .outcome").first().textContent(),
      `Refunded to KAS scriptPublicKey (version 0) 20${keys.b}ac`,
    );
    assert.match((await decoder.locator("#out-trade h3").first().textContent()) ?? "", /^Input 0 spends the vault of the cash leg: refund signed by the seller/);
    await decoder.close();
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
  });
});

test("the depositor's refund of an earmarked leg waits for the expiry, with nothing sent until the node's score has passed it", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, keys, addresses, s } = t;
    await prepare(t);
    await chooseRefund(page, 0, "depositor", true);
    const built = await build(page, "#build-refund");
    assert.equal(built.state, "ok", built.text);
    assert.equal(await text(page, "#review-title"), "Refund of the asset leg, signed by the depositor, the escrowed token going home too");
    // The authorizer goes home to the seller, the token to its refund destination; the lock time is the expiry.
    const inputs = await rows(page, "#review-inputs-body");
    assert.deepEqual(inputs.map((r) => r.what.replace(/ \(P2PK of the key .*$/, "")), [
      "the asset vault",
      "the asset token escrowed in the asset vault",
      "the buyer's key (P2PK)",
    ]);
    assert.equal(inputs[0].signer, needs(keys.a, "seller"), "the seller is the depositor");
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs[0].amount, kasText(AUTHORIZER));
    assert.equal(outputs[0].address, addresses.a);
    assert.match(outputs[1].what, /^seller_refund \(the asset returns here\), as a KCC-20 token \[pays a key that lives only in this page\]$/);
    assert.equal(outputs[1].covenant, ASSET_COV);
    assert.equal(await fact(page, "lock-time"), `DAA score ${EXPIRY}: final in a block from DAA score ${EXPIRY + 1n}`);
    assert.match((await fact(page, "submit-ready")) ?? "", /^not yet: about \d+ hours to go, at the nominal 10 DAA scores a second$/);
    await signWith(page, "a");
    await signWith(page, "b");
    assert.equal(await page.isDisabled("#submit"), false, "signed; the lock time is checked at the submit");
    // Below the lock time nothing is sent; past it, the same document goes through.
    const early = await submitAndWait(page);
    assert.equal(early.state, "wait");
    assert.match(
      early.text,
      new RegExp(`^Not final yet: the lock time is DAA score ${EXPIRY} and the node is at ${NOW}; about \\d+ hours to go, at the nominal 10 DAA scores a second\\. Nothing was sent\\.$`),
    );
    assert.equal(frames(s).filter((f) => f.method === "submitTransaction").length, 0);
    assert.equal(fake.accepted.length, 0);
    fake.virtualDaa = Number(EXPIRY) + 1;
    const late = await submitAndWait(page);
    assert.equal(late.state, "ok", late.text);
    assert.equal(frames(s).filter((f) => f.method === "submitTransaction").length, 1);
    assert.equal(fake.accepted.length, 1);
  });
});

test("a refund without the token takes only the vault UTXO home and the page says the token stays escrowed", async () => {
  await withTrade("vault", async (t) => {
    const { page, addresses } = t;
    await prepare(t);
    await chooseRefund(page, 0, "depositor", true);
    assert.equal((await build(page, "#build-refund")).state, "ok");
    assert.equal((await rows(page, "#review-inputs-body")).length, 3, "control: with the token, three inputs");
    await chooseRefund(page, 0, "depositor", false);
    assert.equal((await build(page, "#build-refund")).state, "ok");
    assert.equal(await text(page, "#review-title"), "Refund of the asset leg, signed by the depositor");
    const inputs = await rows(page, "#review-inputs-body");
    assert.deepEqual(inputs.map((r) => r.what.replace(/ \(P2PK of the key .*$/, "")), ["the asset vault", "the buyer's key (P2PK)"]);
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs[0].amount, kasText(AUTHORIZER));
    assert.equal(outputs[0].address, addresses.a);
    assert.equal(outputs.length, 2, "the authorizer's KAS and the change; no token output");
  });
});

test("a transaction in the node's mempool is decoded without being bound; once mined, the chain path binds it", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, sdk } = t;
    fake.autoAccept = false;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    await signWith(page, "b");
    const sent = await submitAndWait(page);
    assert.equal(sent.state, "ok", sent.text);
    assert.equal(fake.accepted.length, 0, "pending");
    const txid = /transaction ([0-9a-f]{64})/.exec(sent.text)?.[1] ?? "";
    assert.match(txid, /^[0-9a-f]{64}$/);
    const decoder = await openDecoder(t);
    // No block given: found in the mempool, decoded, not bound, not accepted.
    const pending = await decode(decoder, { txid });
    assert.equal(pending.state, "ok", pending.text);
    assert.match(pending.text, /from the node's mempool: 2 legs\.$/);
    assert.equal(await decoder.getAttribute("#out-template .binding", "data-bound"), "false");
    assert.match((await text(decoder, "#out-template .binding")) ?? "", /^Not bound: the node did not give the scriptPublicKey of every spent output/);
    assert.equal(await text(decoder, "#out-receipt .receipt"), "Not accepted into a block yet: the transaction is in the node's mempool.");
    assert.equal(await decoder.locator("#out-trade .leg").count(), 2);
    // Mined: no longer in the mempool. Without a block to look from the page says where it looked;
    // with the block, the chain carries it and the decoding is bound.
    fake.mine(txid);
    const lost = await decode(decoder, { txid });
    assert.equal(lost.state, "refused");
    assert.equal(lost.code, "");
    assert.match(lost.text, /^Not decoded: Not found in the node's mempool\. Give a chain block at or before the submission/);
    assert.equal(await decoder.locator("#out-trade .leg").count(), 0, "the earlier trade is cleared");
    const bound = await decode(decoder, { txid, from: fake.genesis });
    assert.equal(bound.state, "ok", bound.text);
    assert.equal(await decoder.getAttribute("#out-template .binding", "data-bound"), "true");
    assert.equal(await decoder.getAttribute("#out-template .template-hash", "title"), hexOf(sdk.templateCheck().hash()));
    await decoder.close();
  });
});

test("the decoder refuses what it should, each beside the settlement it decodes", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    await signWith(page, "b");
    assert.equal((await submitAndWait(page)).state, "ok");
    const txid = fake.accepted[0].txid;
    const decoder = await openDecoder(t);
    const good = await decode(decoder, { txid, from: fake.genesis });
    assert.equal(good.state, "ok", good.text);

    // A node URL the SDK refuses, before any socket is opened.
    const before = s.contacted.length;
    const http = await decode(decoder, { url: "http://127.0.0.1:1" });
    assert.deepEqual([http.state, http.code], ["refused", "SDK_NODE_URL_INVALID"]);
    const insecure = await decode(decoder, { url: "ws://203.0.113.9:17110", network: "mainnet" });
    assert.deepEqual([insecure.state, insecure.code], ["refused", "SDK_NODE_INSECURE"]);
    const v6 = await decode(decoder, { url: "ws://[::1]:17110", network: "mainnet" });
    assert.deepEqual([v6.state, v6.code], ["refused", "SDK_NODE_INSECURE"], "the IPv6 loopback literal (owner decision 2026-10-11)");
    assert.equal(s.contacted.length, before, "no socket was opened for any of the three");
    assert.equal(await decoder.locator("#out-trade .leg").count(), 0, "a refusal clears the earlier trade");
    // A node on another network than the one asked for, and one that is not synced.
    fake.networkId = "mainnet";
    const wrong = await decode(decoder, { url: NODE_URL, network: "testnet" });
    assert.deepEqual([wrong.state, wrong.code], ["refused", "SDK_NODE_NETWORK_MISMATCH"]);
    fake.networkId = "testnet-10";
    fake.synced = false;
    const unsynced = await decode(decoder, {});
    assert.deepEqual([unsynced.state, unsynced.code], ["refused", "SDK_NODE_NOT_SYNCED"]);
    fake.synced = true;
    // A transaction ID that is not one, and one the node does not know.
    const bad = await decode(decoder, { txid: "ab" });
    assert.deepEqual([bad.state, bad.code], ["refused", "SDK_JSON_FORM"]);
    const unknown = await decode(decoder, { txid: "ab".repeat(32), from: fake.genesis });
    assert.deepEqual([unknown.state, unknown.code], ["refused", ""]);
    assert.match(unknown.text, /nor accepted on the chain from the block given\.$/);
    // A node that puts another transaction ID on the transaction than the one asked for.
    t.handler.current = (request) => {
      const reply = JSON.parse(fake.handle(request)) as {
        params?: { chainBlockAcceptedTransactions?: { acceptedTransactions: { verboseData: { transactionId: string } }[] }[] };
      };
      for (const block of reply.params?.chainBlockAcceptedTransactions ?? []) {
        for (const tx of block.acceptedTransactions) tx.verboseData.transactionId = "ab".repeat(32);
      }
      return JSON.stringify(reply);
    };
    const swapped = await decode(decoder, { txid: "ab".repeat(32), from: fake.genesis });
    assert.deepEqual([swapped.state, swapped.code], ["refused", "SDK_TXID_MISMATCH"], swapped.text);
    // A node that answers the mempool lookup with a binary frame: the page reads text only, says
    // so, and does not go on to look along the chain as if the node had said it holds nothing.
    t.handler.current = (request) =>
      (JSON.parse(request) as { method: string }).method === "getMempoolEntry" ? Buffer.from([0x7b, 0x7d]) : fake.handle(request);
    const binary = await decode(decoder, { txid, from: fake.genesis });
    assert.deepEqual([binary.state, binary.code], ["refused", ""]);
    assert.equal(binary.text, "Not decoded: The node sent something that is not text.");
    assert.equal(await decoder.locator("#out-trade .leg").count(), 0, "nothing is decoded from the chain after it");
    t.handler.current = (request) => fake.handle(request);
    // The control again, after all of that: the same settlement decodes.
    const again = await decode(decoder, { txid, from: fake.genesis });
    assert.equal(again.state, "ok", again.text);
    await decoder.close();
    // Only the node typed was ever opened a socket to.
    assert.deepEqual([...new Set(s.contacted)], [NODE_HREF]);
  });
});
