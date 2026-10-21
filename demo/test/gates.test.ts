// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The checks the page makes before the buyer's cash is funded, and what it says and does after:
// the funding is built from the node's state at the node's score (the seller's asset leg must be on
// the node, the cash vault must be empty, the creation checks run at the score the node reports
// now), a token that is no pinned kcc20.sil build is never funded, a funded wallet is not wiped
// without a question, and a trade whose funding wallet was wiped is still settled by another
// wallet. Also the hand-off of the partly signed transaction: what the page says when the browser
// refuses the copy, and the score the review is made at after signatures are added. Each refusal
// sits beside an accepted control. Offline, against the fake node of crates/impulse-wasm/npm/test.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Page } from "playwright-core";
import {
  HANGUP,
  NODE_URL,
  build,
  connect,
  fact,
  hexOf,
  prepare,
  rows,
  sdkOf,
  sentCount,
  signWith,
  submitAndWait,
  text,
  until,
  withTrade,
  type TestSdk,
  type Trade,
} from "./session.ts";
import type { NodeHandler } from "./harness.ts";
import { ASSET_ARTIFACT, AMOUNT_A, EXPIRY, KAS_CASH, NOW, addressFor, ownToken, p2pk, termsFor, utxo, vaultUtxos } from "./world.ts";
import { partyFor, pinOf } from "./party.ts";

const kasTo = (key: string) => ({ kind: "kas", version: 0, script: `20${key}ac` });
const ownerOf = (key: string) => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });

/** A public key held in no wallet of the page: an address elsewhere. */
function newKey(sdk: TestSdk): string {
  const w = sdk.Wallet.generate();
  const key = w.publicKey();
  w.free();
  return key;
}

/**
 * Mainnet terms whose buyer is wallet B, the seller a key outside the page, and whose four
 * destinations pay addresses elsewhere (on mainnet the SDK refuses a destination that pays a key
 * of the page).
 */
function mainnetTerms(sdk: TestSdk, mode: "vault" | "direct", seller: string, buyer: string, cold: string, sellerCold: string) {
  return {
    ...termsFor(sdk, mode, seller, buyer, "mainnet"),
    buyer_delivery: ownerOf(cold),
    buyer_refund: kasTo(cold),
    seller_proceeds: kasTo(sellerCold),
    seller_refund: ownerOf(sellerCold),
  };
}

/** The seller's funding of the asset leg, as it sits on the node: the authorizer and the escrowed token. */
function seedAssetLeg(t: Trade): void {
  const [assetAuthorizer, assetEscrow] = vaultUtxos(t.sdk, t.terms, t.keys.b);
  t.fake.add(assetAuthorizer);
  t.fake.add(assetEscrow);
}

function cashVaultAddress(sdk: TestSdk, terms: unknown, network: "mainnet" | "testnet"): string {
  const spk = sdk.Terms.fromJson(terms).validateStructure().instantiateExisting(1).scriptPublicKey();
  return addressFor(network)({ version: spk.version, script: hexOf(spk.script) });
}

// The pinned template.

test("terms whose token is no pinned kcc20.sil build offer no funding, and a funding forced through the page's build is refused by the SDK before the node is asked, beside the pinned control", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  const pinnedTerms = (_sdk: TestSdk, k: { a: string; b: string }) => mainnetTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold);
  // The same trade with the asset token's template one suffix byte longer than the pinned build it is made from.
  const unpinnedTerms = (_sdk: TestSdk, k: { a: string; b: string }) => {
    const t = pinnedTerms(_sdk, k) as Record<string, any>;
    return { ...t, asset_leg: { ...t.asset_leg, template_suffix_len: t.asset_leg.template_suffix_len + 1 } };
  };
  try {
    // Control: the pinned build is offered the funding, and it builds.
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        assert.equal(await page.isVisible("#fund-options"), true);
        assert.equal((await build(page, "#build-fund")).state, "ok");
      },
      { network: "mainnet", seed: "none", terms: pinnedTerms },
    );
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms, s } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
        // The page derives nothing, offers nothing, and says why.
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { expect: "SDK_TEMPLATE_UNPINNED" });
        assert.equal(await page.isVisible("#actions"), false);
        assert.equal(await page.isVisible("#fund-options"), false);
        assert.equal(await page.locator("#legs > *").count(), 0, "no vault address, URI or QR");
        assert.match(
          (await text(page, "#status")) ?? "",
          /^Refused: SDK_TEMPLATE_UNPINNED: the asset leg's KCC-20 template [0-9a-f]{64} \(1\+1461\) is not a pinned kcc20\.sil build /,
        );
        // Forced: the controls are unhidden and the build pressed, as a person with the developer tools could.
        // The score the page asked the node for has arrived (the page derives again when it does).
        await page.waitForFunction(() => (document.getElementById("creation-daa") as HTMLInputElement).value !== "");
        // The field the person typed last still has the focus; leaving it makes the page derive once more.
        await page.evaluate(() => (document.activeElement as HTMLElement).blur());
        await page.evaluate(() => {
          for (const id of ["actions", "fund-options"]) (document.getElementById(id) as HTMLElement).hidden = false;
        });
        await page.fill("#asset-artifact", ASSET_ARTIFACT);
        await page.selectOption("#fee-payer", { value: "b" });
        const forced = await build(page, "#build-fund");
        assert.deepEqual([forced.state, forced.code], ["refused", "SDK_TEMPLATE_UNPINNED"], forced.text);
        assert.equal(await page.isVisible("#review-panel"), false, "nothing to sign");
        assert.equal(sentCount(s, "getUtxosByAddresses"), 0, "the SDK refused before the node was asked for a UTXO");
        assert.equal(sentCount(s, "submitTransaction"), 0);
        assert.equal(fake.accepted.length, 0);
      },
      { network: "mainnet", seed: "none", terms: unpinnedTerms },
    );
  } finally {
    seller.free();
  }
});

// The network switch during a connection.

test("flipping the network while a connection is still opening leaves no node attached: the score is not read from it and nothing is built", async () => {
  const sdk = await sdkOf();
  const seller = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        seedAssetLeg(t);
        fake.add(utxo("buyer-coin", 200_000_000n, p2pk(keys.b)));
        // Control: on mainnet, with the mainnet node, the page reads the score and builds.
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        assert.equal((await build(page, "#build-fund")).state, "ok", "control: connected, built");
        // To testnet, where the node now answers as a testnet node (as a plaintext remote one
        // would pass the testnet check), and a connection whose open is held back.
        await page.uncheck("#mainnet-switch");
        fake.networkId = "testnet-10";
        await page.evaluate(() => {
          (window as unknown as { __holdOpen: boolean }).__holdOpen = true;
        });
        await page.fill("#node-url", NODE_URL);
        await page.click("#node-connect");
        await page.waitForFunction(() => (window as unknown as { __held: unknown[] }).__held.length === 1);
        // Back to mainnet before the socket opens; then it opens.
        await page.check("#mainnet-switch");
        await page.evaluate(() => {
          const w = window as unknown as { __holdOpen: boolean; __held: (() => void)[] };
          w.__holdOpen = false;
          for (const go of w.__held.splice(0)) go();
        });
        await page.waitForFunction(() => document.querySelector("#node-status")?.getAttribute("data-state") !== "working");
        await new Promise((done) => setTimeout(done, 200));
        assert.notEqual(await page.getAttribute("#node-status", "data-state"), "connected");
        // The switch abandoned the attempt itself; the socket that opened later was never used.
        assert.match((await text(page, "#node-status")) ?? "", /was closed before it opened: the page closed it\.$/);
        // Reading the score is refused, and the field keeps what it held: the page is still on a
        // typed score, which mainnet refuses.
        const before = await page.inputValue("#creation-daa");
        await page.click("#read-daa");
        await page.waitForFunction(() => document.querySelector("#node-status")?.getAttribute("data-state") === "error");
        assert.match((await text(page, "#node-status")) ?? "", /^Not read: /);
        assert.equal(await page.inputValue("#creation-daa"), before);
        assert.equal(await page.getAttribute("#status", "data-code"), "SDK_MAINNET_NEEDS_NODE");
        // Nothing is built: no funding is offered, and no review is shown.
        assert.equal(await page.isVisible("#fund-options"), false);
        assert.equal(await page.isVisible("#review-panel"), false);
        // Control: connecting again for mainnet, to the mainnet node, works.
        fake.networkId = "mainnet";
        assert.equal((await connect(page)).state, "connected");
      },
      { network: "mainnet", seed: "none", terms: (_sdk, k) => mainnetTerms(sdk, "vault", seller.publicKey(), k.b, cold, sellerCold), holdOpen: true },
    );
  } finally {
    seller.free();
  }
});

// The node's state.

test("the cash is not funded before the seller's asset leg is on the node, and not twice: each refusal beside the funding that builds", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, s } = t;
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      // The seller has funded nothing: the node lists no authorizer and no escrowed token.
      const early = await build(page, "#build-fund");
      assert.deepEqual([early.state, early.code], ["refused", "SDK_FUND_ASSET_NOT_FUNDED"], early.text);
      assert.match(early.text, /the seller's asset leg is not funded on this node: no plain UTXO at the asset vault \(the authorizer\)\./);
      assert.equal(await page.isVisible("#review-panel"), false, "nothing to sign");
      // Only the authorizer is there: still not funded, and the answer says what is missing.
      const [assetAuthorizer, assetEscrow] = vaultUtxos(t.sdk, t.terms, keys.b);
      fake.add(assetAuthorizer);
      const half = await build(page, "#build-fund");
      assert.deepEqual([half.state, half.code], ["refused", "SDK_FUND_ASSET_NOT_FUNDED"], half.text);
      assert.match(half.text, /no token UTXO of exactly 1000 units in the asset vault/);
      // Control: the whole asset leg, and the funding builds, is signed and goes.
      fake.add(assetEscrow);
      const funding = await build(page, "#build-fund");
      assert.deepEqual([funding.state, funding.code], ["ok", ""], funding.text);
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(sentCount(s, "submitTransaction"), 1);
      // The deposit is on the node: a second funding is refused, nothing is signed or sent, and the settle builds.
      const again = await build(page, "#build-fund");
      assert.deepEqual([again.state, again.code], ["refused", "SDK_FUND_ALREADY_FUNDED"], again.text);
      assert.match(again.text, /the cash vault already holds a deposit of exactly 100000000 sompi/);
      assert.equal(await page.isVisible("#review-panel"), false);
      assert.equal(sentCount(s, "submitTransaction"), 1, "nothing was sent for the second funding");
      await page.selectOption("#fee-payer", { value: "a" });
      assert.equal((await build(page)).state, "ok", "the settle is what comes next");
    },
    { seed: "none" },
  );
});

// The node's score.

test("the funding is built at the node's score: nothing is built at the expiry, and a funding signed in time is refused after the expiry with nothing sent", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, s } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      await prepare(t, "buyer");
      // The score the build reads is the node's now, not the one the page was prepared with.
      fake.virtualDaa = Number(EXPIRY) - 1;
      const inTime = await build(page, "#build-fund");
      assert.deepEqual([inTime.state, inTime.code], ["ok", ""], `one DAA score before the expiry: ${inTime.text}`);
      assert.equal(await fact(page, "daa"), (EXPIRY - 1n).toString());
      fake.virtualDaa = Number(EXPIRY);
      const atExpiry = await build(page, "#build-fund");
      assert.deepEqual([atExpiry.state, atExpiry.code], ["refused", "TERMS_EXPIRY_NOT_AFTER_CREATION"], `at the expiry: ${atExpiry.text}`);
      assert.equal(await page.isVisible("#review-panel"), false, "no review of a funding that cannot be made");
      // Built and signed in time, then the node passes the expiry before the person submits.
      fake.virtualDaa = NOW;
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      fake.virtualDaa = Number(EXPIRY) + 5;
      const late = await submitAndWait(page);
      assert.deepEqual([late.state, late.code], ["refused", "TX_EXPIRED"], late.text);
      assert.equal(sentCount(s, "submitTransaction"), 0, "nothing was sent");
      assert.equal(fake.accepted.length, 0);
      // Control: the same document, the node back at the score it was built at.
      fake.virtualDaa = NOW;
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(fake.accepted.length, 1);
    },
    { seed: "none" },
  );
});

// The way out.

test("wallet B can be wiped after it funded the cash vault, and wallet A settles the trade with no key of wallet B's", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, addresses, terms } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      // The person is asked, says yes, and the key of wallet B is gone.
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), true);
      await page.click("#wipe-confirm-yes");
      assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "wiped");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, "nothing left to protect");
      // The settle of a self-settling trade needs no depositor's key: wallet A pays the fee and signs it.
      await page.selectOption("#fee-payer", { value: "a" });
      const settle = await build(page, "#build-settle");
      assert.deepEqual([settle.state, settle.code], ["ok", ""], settle.text);
      assert.deepEqual(await page.locator("#sign-buttons button").evaluateAll((bs) => bs.map((b) => b.textContent)), ["Sign with wallet A (input 3)"]);
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(fake.accepted.length, 2);
      assert.ok(fake.at(addresses.a).some((u) => u.amount === KAS_CASH.toString()), "the cash reached the seller's proceeds");
      assert.deepEqual(fake.at(cashVaultAddress(t.sdk, terms, "testnet")), [], "the deposit is spent");
      assert.equal(fake.at(addresses.b).length, 1, "wallet B's change is where it was sent");
    },
    { seed: "none" },
  );
});

test("a wallet that funded a cash vault is asked about before a wipe until the trade is settled or its cash refunded from this page, then not", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      // Before the funding: nothing is asked, and nothing is said on the card.
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false);
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      // Built and signed is not funded: the document is not on the node, and the page asks nothing yet.
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false);
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(await page.isDisabled("#submit"), true, "a transaction the node took is not offered again");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true);
      // Leaving the page is not silent either: the browser is asked, and nothing is wiped by the event.
      const prevented = await page.evaluate(() => {
        const leave = new Event("beforeunload", { cancelable: true });
        window.dispatchEvent(leave);
        return leave.defaultPrevented;
      });
      assert.equal(prevented, true);
      assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "ready");
      // A refund of the cash leg from the page, signed by the counterparty (the seller), ends it.
      await page.selectOption("#fee-payer", { value: "a" });
      await page.selectOption("#refund-leg", { value: "1" });
      await page.selectOption("#refund-signer", { value: "counterparty" });
      assert.equal((await build(page, "#build-refund")).state, "ok");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "built, not yet sent");
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, "the cash is home");
      assert.equal(await page.isDisabled("#submit"), true, "a transaction the node took is not offered again");
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), false);
      assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "wiped");
    },
    { seed: "none" },
  );
  // A refund of the asset leg does not close the cash leg's escrow.
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      await page.selectOption("#fee-payer", { value: "a" });
      await page.selectOption("#refund-leg", { value: "0" });
      await page.selectOption("#refund-signer", { value: "counterparty" });
      assert.equal((await build(page, "#build-refund")).state, "ok");
      assert.deepEqual([(await signWith(page, "a")).state, (await signWith(page, "b")).state], ["ok", "ok"]);
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "the cash is still in its vault");
    },
    { seed: "none" },
  );
});

test("a funding whose outcome is unknown counts as a deposit: the wallet says so and Wipe asks, beside a funding the node refused, which does not", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      await prepare(t, "buyer");
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      const method = (request: string) => (JSON.parse(request) as { method: string; id: number });
      // The node refuses the transaction: nothing was deposited, and nothing is remembered.
      t.handler.current = (request) => {
        const call = method(request);
        return call.method === "submitTransaction"
          ? JSON.stringify({ id: call.id, error: { message: "refused for the test" } })
          : fake.handle(request);
      };
      const refused = await submitAndWait(page);
      assert.equal(refused.state, "refused", refused.text);
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, "a refusal is not a deposit");
      // The node hangs up after the request left the page: the outcome is unknown, and counts.
      t.handler.current = (request) => (method(request).method === "submitTransaction" ? HANGUP : fake.handle(request));
      await page.click("#submit");
      await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "it may have been taken");
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), true);
      assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "ready", "asked, not wiped");
    },
    { seed: "none" },
  );
});

/** What the page's submit status says, for a submission whose outcome is not known. */
const submitStatus = async (page: Page) => ({
  state: (await page.getAttribute("#submit-status", "data-state")) ?? "",
  text: (await text(page, "#submit-status")) ?? "",
});

/** The funding of the cash leg, built and signed by wallet B, ready to submit. */
async function signedFunding(t: Trade, more: { autoAccept?: boolean } = {}): Promise<void> {
  const { page, fake, keys } = t;
  seedAssetLeg(t);
  fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
  if (more.autoAccept === false) fake.autoAccept = false;
  await prepare(t, "buyer");
  assert.equal((await build(page, "#build-fund")).state, "ok");
  assert.equal((await signWith(page, "b")).state, "ok");
}

/** The node's own error to the submit request (the other calls are answered as usual). */
const refusesSubmit =
  (t: Trade, message: string): NodeHandler =>
  (request) => {
    const call = JSON.parse(request) as { method: string; id: number };
    return call.method === "submitTransaction" ? JSON.stringify({ id: call.id, error: { message } }) : t.fake.handle(request);
  };

/** The node takes the submitted transaction, and the page reads `garble` of the node's real answer. */
const takesSubmitButAnswers =
  (t: Trade, garble: (reply: string) => string): NodeHandler =>
  (request) => {
    const reply = t.fake.handle(request);
    return (JSON.parse(request) as { method: string }).method === "submitTransaction" ? garble(reply) : reply;
  };

// Answers the page cannot match to its request, which leave the outcome unknown.
const UNREADABLE: [string, string, (reply: string) => string][] = [
  [
    "a reply to another request, as a late answer to an earlier call is",
    "SDK_RPC_REPLY",
    (reply) => JSON.stringify({ ...JSON.parse(reply), id: JSON.parse(reply).id + 1000 }),
  ],
  [
    "a reply that names another transaction",
    "SDK_TXID_MISMATCH",
    (reply) => JSON.stringify({ ...JSON.parse(reply), params: { transactionId: "ab".repeat(32) } }),
  ],
  ["text that is not JSON", "SDK_RPC_REPLY", () => "this is not a reply"],
  [
    "an error of the node's that carries another request's id",
    "SDK_RPC_REPLY",
    (reply) => JSON.stringify({ id: JSON.parse(reply).id + 1000, error: { message: "the mempool is full" } }),
  ],
];

test("a funding the node took but whose answer the page cannot match to its request is a deposit with an unknown outcome and not a refusal, beside the node's own refusal, which is one", async () => {
  for (const [what, code, garble] of UNREADABLE) {
    await withTrade(
      "vault",
      async (t) => {
        const { page, s } = t;
        await signedFunding(t, { autoAccept: false });
        // Control: the node answers this very request with an error of its own. It took nothing, and
        // the page remembers no deposit and offers submit again.
        t.handler.current = refusesSubmit(t, "refused for the test");
        const refused = await submitAndWait(page);
        assert.deepEqual([refused.state, refused.code], ["refused", "SDK_RPC_REPLY"], `${what}: ${refused.text}`);
        assert.ok(refused.text.includes("refused for the test"), refused.text);
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, `${what}: a refusal is not a deposit`);
        assert.equal(await page.isDisabled("#submit"), false);
        assert.equal(await page.locator("#submit-check").count(), 0);
        // The node takes the same document, and the page reads an answer that is not the answer to
        // its request.
        t.handler.current = takesSubmitButAnswers(t, garble);
        await page.click("#submit");
        await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
        const said = await submitStatus(page);
        assert.ok(said.text.startsWith(`Outcome unknown: ${code}: `), `${what}: ${said.text}`);
        const txid = /Its ID is ([0-9a-f]{64})\. Do not submit again before you have checked: /.exec(said.text)?.[1];
        assert.ok(txid !== undefined, `${what}: ${said.text}`);
        assert.doesNotMatch(said.text, /^(Not submitted|Refused)/);
        assert.equal(await page.isDisabled("#submit"), true, `${what}: submit stays off`);
        assert.equal(sentCount(s, "submitTransaction"), 2);
        // The deposit counts: the card says so and Wipe asks, though the page was told nothing it can read.
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, `${what}: it may have been taken`);
        await page.click("#wallet-b .wallet-wipe");
        assert.equal(await page.isVisible("#wipe-confirm"), true, `${what}: Wipe asks`);
        assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "ready", "asked, not wiped");
        await page.click("#wipe-confirm-no");
        // Asking the node settles it: it has the transaction, by the ID the page gave.
        t.handler.current = (request) => t.fake.handle(request);
        await page.click("#submit-check");
        await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "ok");
        assert.ok((await submitStatus(page)).text.startsWith(`The node has the transaction ${txid} in its mempool: it was accepted. Do not submit it again. `));
        assert.equal(await page.isDisabled("#submit"), true);
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true);
      },
      { seed: "none" },
    );
  }
});

test("a node that hangs up on the funding while the terms are edited leaves the deposit remembered and the outcome unknown, with the transaction ID and a way to look, beside the same hang-up with the terms untouched", async () => {
  for (const edited of [false, true]) {
    await withTrade(
      "vault",
      async (t) => {
        const { page, fake, s } = t;
        await signedFunding(t);
        const trade = (await fact(page, "terms-hash")) ?? "";
        // The node takes the transaction, and hangs up instead of answering, after the terms are
        // edited (or not).
        let release: () => void = () => {};
        const gate = new Promise<void>((done) => (release = done));
        t.handler.current = async (request) => {
          const reply = fake.handle(request);
          if ((JSON.parse(request) as { method: string }).method !== "submitTransaction") return reply;
          await gate;
          return HANGUP;
        };
        await page.click("#submit");
        await until(() => sentCount(s, "submitTransaction") === 1, "the submission");
        // From the moment the request is written the deposit counts, before any answer.
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "remembered when the request is written");
        if (edited) {
          await page.fill('[data-path="nonce"]', "7");
          assert.equal(await page.isVisible("#review-panel"), false, "the edit dropped the document under review");
        }
        release();
        await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
        const said = await submitStatus(page);
        const txid = fake.accepted[0].txid;
        assert.ok(
          said.text.startsWith(`Outcome unknown: The connection to the node closed. The transaction may have been accepted. Its ID is ${txid}. `),
          said.text,
        );
        assert.doesNotMatch(said.text, /Not submitted|Refused/);
        assert.equal(await page.getAttribute("#submit-status a", "href"), `decoder.html#txid=${txid}&from=${fake.genesis}`);
        assert.equal(await page.getAttribute("#submit-status a", "target"), "_blank");
        assert.equal(await page.isDisabled("#submit"), true);
        // With the document still under review there is a question to put to the node; without it
        // the status says the document is gone and offers the decoder alone.
        assert.equal(await page.locator("#submit-check").count(), edited ? 0 : 1);
        assert.equal(
          said.text.includes("so this page no longer holds the document"),
          edited,
          "the status says the document is gone only when it is",
        );
        // The deposit is remembered either way, for the trade that was funded.
        assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "it may have been taken");
        assert.ok(((await text(page, "#wallet-b .wallet-escrow")) ?? "").includes(trade), "the card names the trade that was funded");
        await page.click("#wallet-b .wallet-wipe");
        assert.equal(await page.isVisible("#wipe-confirm"), true, "Wipe asks");
        assert.ok(((await text(page, "#wipe-confirm-text")) ?? "").includes(trade));
        assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "ready", "asked, not wiped");
      },
      { seed: "none" },
    );
  }
});

test("a deposit remembered after an unknown outcome is kept when a later submission of the same funding is refused by the node, which says it already has it", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake } = t;
      await signedFunding(t);
      // The node takes the transaction into a block and hangs up: the outcome is unknown.
      t.handler.current = (request) => {
        const reply = fake.handle(request);
        return (JSON.parse(request) as { method: string }).method === "submitTransaction" ? HANGUP : reply;
      };
      await page.click("#submit");
      await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "unknown");
      assert.equal(fake.accepted.length, 1);
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true);
      // Connected again, the mempool does not have it (it is in a block): submit is offered again.
      t.handler.current = (request) => fake.handle(request);
      assert.equal((await connect(page)).state, "connected");
      await page.click("#submit-check");
      await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "wait");
      assert.equal(await page.isDisabled("#submit"), false);
      // Submitting it again: the node says it already has it. That is an answer to this request,
      // and it does not say the earlier submission was refused: the deposit is still remembered.
      const again = await submitAndWait(page);
      assert.deepEqual([again.state, again.code], ["refused", "SDK_RPC_REPLY"], again.text);
      assert.match(again.text, /already in the mempool or accepted/);
      assert.equal(fake.accepted.length, 1, "nothing was taken twice");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true, "the refusal of a second submission forgets nothing");
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), true);
    },
    { seed: "none" },
  );
});

test("funding a second trade from the same wallet adds to the deposit it remembers and forgets nothing: the card and the question list both, a settle ends one, and Wipe asks until both are settled", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, sdk, terms } = t;
      seedAssetLeg(t);
      // The second trade: another nonce, its asset leg funded by the seller on the node.
      const otherTerms = { ...terms, nonce: "2222" };
      const [otherAuthorizer, otherEscrow] = vaultUtxos(sdk, otherTerms, keys.b, "other-");
      fake.add(otherAuthorizer);
      fake.add(otherEscrow);
      fake.add(utxo("buyer-coin", 400_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin-1", 100_000_000n, p2pk(keys.a)));
      fake.add(utxo("settle-fee-coin-2", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      const escrow = async () => (await text(page, "#wallet-b .wallet-escrow")) ?? "";
      const fundThisTrade = async () => {
        assert.equal((await build(page, "#build-fund")).state, "ok");
        const hash = (await fact(page, "terms-hash")) ?? "";
        assert.equal((await signWith(page, "b")).state, "ok");
        assert.equal((await submitAndWait(page)).state, "ok");
        return hash;
      };
      const first = await fundThisTrade();
      assert.ok((await escrow()).startsWith(`This wallet funded 1.00000000 KAS into the cash vault of the trade ${first} `));
      // Fund the second trade from the same wallet.
      await page.fill('[data-path="nonce"]', "2222");
      await page.waitForSelector("#status[data-state='ok']");
      assert.equal((await build(page, "#build-fund")).state, "ok");
      const second = (await fact(page, "terms-hash")) ?? "";
      assert.notEqual(second, first);
      assert.equal((await signWith(page, "b")).state, "ok");
      // The node refuses this funding: the first deposit is still remembered, and none of the second.
      t.handler.current = refusesSubmit(t, "refused for the test");
      assert.equal((await submitAndWait(page)).state, "refused");
      const afterRefusal = await escrow();
      assert.ok(afterRefusal.startsWith(`This wallet funded 1.00000000 KAS into the cash vault of the trade ${first} `), afterRefusal);
      assert.ok(!afterRefusal.includes(second) && !afterRefusal.includes(" It also funded "), afterRefusal);
      // Control: the same funding, taken.
      t.handler.current = (request) => fake.handle(request);
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(fake.accepted.length, 2);
      const card = await escrow();
      assert.ok(card.startsWith(`This wallet funded 1.00000000 KAS into the cash vault of the trade ${first} `), card);
      assert.ok(card.includes(` It also funded 1.00000000 KAS into the cash vault of the trade ${second} `), card);
      assert.ok(card.endsWith(" This key is your way to refund them: wiping the wallet or closing the page destroys it."), card);
      // The question to a Wipe names both deposits.
      await page.click("#wallet-b .wallet-wipe");
      const ask = (await text(page, "#wipe-confirm-text")) ?? "";
      assert.ok(ask.includes(first) && ask.includes(second), ask);
      await page.click("#wipe-confirm-no");
      // The settle of the second trade ends that deposit and leaves the first.
      await page.selectOption("#fee-payer", { value: "a" });
      assert.equal((await build(page)).state, "ok");
      assert.equal(await fact(page, "terms-hash"), second);
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      const left = await escrow();
      assert.ok(left.startsWith(`This wallet funded 1.00000000 KAS into the cash vault of the trade ${first} `), left);
      assert.ok(!left.includes(second), left);
      assert.ok(left.includes("This key is your way to refund it:"), left);
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), true, "the first deposit is still in its vault");
      assert.ok(((await text(page, "#wipe-confirm-text")) ?? "").includes(first));
      assert.ok(!((await text(page, "#wipe-confirm-text")) ?? "").includes(second));
      await page.click("#wipe-confirm-no");
      // Control: the settle of the first trade ends the last deposit, and Wipe asks nothing.
      await page.fill('[data-path="nonce"]', terms.nonce as string);
      await page.waitForSelector("#status[data-state='ok']");
      await page.selectOption("#fee-payer", { value: "a" });
      assert.equal((await build(page)).state, "ok");
      assert.equal(await fact(page, "terms-hash"), first);
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), false, "nothing left to protect");
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), false);
      assert.equal(await page.getAttribute("#wallet-b .wallet-state", "data-state"), "wiped");
    },
    { seed: "none" },
  );
});

test("two fundings of the same trade that the node took before it listed the first are two deposits: a settle spends one, and the other is still asked about", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      fake.autoAccept = false;
      await prepare(t, "buyer");
      const escrow = async () => (await text(page, "#wallet-b .wallet-escrow")) ?? "";
      const taken = async () => /accepted the transaction ([0-9a-f]{64})/.exec((await submitStatus(page)).text)?.[1] ?? "";
      // The first funding sits in the node's mempool: the node lists no deposit yet, so the page
      // builds a second funding from the same coin (a different fee, so another transaction).
      assert.equal((await build(page, "#build-fund")).state, "ok");
      const fee = BigInt(/\((\d+) sompi\)/.exec((await fact(page, "fee")) ?? "")?.[1] ?? "x");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      const first = await taken();
      assert.equal((await escrow()).split("This wallet funded").length - 1, 1);
      await page.fill("#fee", (fee + 1n).toString());
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      const second = await taken();
      assert.notEqual(second, first);
      const card = await escrow();
      assert.ok(card.includes(`(transaction ${first})`) && card.includes(`(transaction ${second})`), card);
      assert.ok(card.includes(" It also funded "), card);
      // A block accepts the first; the node now lists a deposit and the settle builds from it.
      fake.mine(first);
      await page.fill("#fee", "auto");
      await page.selectOption("#fee-payer", { value: "a" });
      const settle = await build(page);
      assert.deepEqual([settle.state, settle.code], ["ok", ""], settle.text);
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      // One settle spends one deposit: the card still says one is out, and Wipe asks.
      const left = await escrow();
      assert.equal(left.split("This wallet funded").length - 1, 1, left);
      assert.ok(!left.includes(" It also funded "), left);
      assert.ok(left.includes("This key is your way to refund it:"), left);
      await page.click("#wallet-b .wallet-wipe");
      assert.equal(await page.isVisible("#wipe-confirm"), true, "a deposit is still out");
    },
    { seed: "none" },
  );
});

test("settling another trade from the page does not end the escrow of this one", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, keys, sdk, terms } = t;
      seedAssetLeg(t);
      fake.add(utxo("buyer-coin", 300_000_000n, p2pk(keys.b)));
      fake.add(utxo("settle-fee-coin", 100_000_000n, p2pk(keys.a)));
      await prepare(t, "buyer");
      assert.equal((await build(page, "#build-fund")).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
      const thisTrade = (await fact(page, "terms-hash")) ?? "";
      assert.equal((await submitAndWait(page)).state, "ok");
      assert.ok(((await text(page, "#wallet-b .wallet-escrow")) ?? "").includes(thisTrade));
      // Another trade of the same parties (another nonce), both legs funded on the node: it settles.
      for (const u of vaultUtxos(sdk, { ...terms, nonce: "2222" }, keys.b, "other-")) fake.add(u);
      await page.fill('[data-path="nonce"]', "2222");
      await page.waitForSelector("#status[data-state='ok']");
      await page.selectOption("#fee-payer", { value: "a" });
      assert.equal((await build(page, "#build-settle")).state, "ok");
      assert.notEqual(await fact(page, "terms-hash"), thisTrade, "the settle is of the other trade");
      assert.equal((await signWith(page, "a")).state, "ok");
      assert.equal((await submitAndWait(page)).state, "ok");
      // The first trade's deposit is still in its vault, and its wallet still says so.
      assert.equal(await page.isVisible("#wallet-b .wallet-escrow"), true);
      assert.ok(((await text(page, "#wallet-b .wallet-escrow")) ?? "").includes(thisTrade));
    },
    { seed: "none" },
  );
});

// The hand-off of the partly signed transaction.

/**
 * A Direct trade on mainnet whose seller is a key outside the page, built by the page at the node's
 * score `daa` and signed by wallets A and B. `signedByHolder` is what the key holder's
 * `impulse ipst sign --role seller` makes of the page's text: the SDK's wallet, a runtime throwaway
 * key that is freed at the end and written nowhere.
 */
async function directTrade(
  f: (t: Trade, signedByHolder: () => Promise<string>) => Promise<void>,
  daa: number,
  /** The wallets that sign before `f` runs; wallet A and wallet B by default. */
  signers: ("a" | "b")[] = ["a", "b"],
): Promise<void> {
  const sdk = await sdkOf();
  const holder = sdk.Wallet.generate();
  const [cold, sellerCold] = [newKey(sdk), newKey(sdk)];
  try {
    await withTrade(
      "direct",
      async (t) => {
        const { page, fake, keys, terms } = t;
        const buyer = partyFor("buyer", terms as never);
        fake.add(ownToken(sdk, "seller-token", holder.publicKey(), AMOUNT_A));
        fake.add(utxo("buyer-cash", KAS_CASH, p2pk(keys.b)));
        fake.add(utxo("fee-coin", 100_000_000n, p2pk(keys.a)));
        fake.virtualDaa = daa;
        await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: pinOf("mainnet", kasTo(cold)) });
        await page.selectOption("#fee-payer", { value: "a" });
        assert.equal((await build(page)).state, "ok");
        for (const name of signers) assert.equal((await signWith(page, name)).state, "ok");
        const signedByHolder = async () => {
          const ipst = sdk.Ipst.fromJson((await text(page, "#ipst-text")) ?? "");
          const out = holder.sign(ipst, {
            artifacts: { asset: ASSET_ARTIFACT, cash: null },
            current_daa: NOW.toString(),
            value: { kas_equivalent: KAS_CASH.toString() },
            mainnet: true,
            pins: { receive: pinOf("mainnet", kasTo(sellerCold)), refund: `kcc20:pubkey:${sellerCold}` },
          });
          const signed = out.ipst.toJson() as string;
          out.ipst.free();
          ipst.free();
          return signed;
        };
        await f(t, signedByHolder);
      },
      {
        network: "mainnet",
        seed: "none",
        terms: (_sdk, k) => mainnetTerms(sdk, "direct", holder.publicKey(), k.b, cold, sellerCold),
      },
    );
  } finally {
    holder.free();
  }
}

const importState = async (page: Page) => ({
  state: (await page.getAttribute("#import-status", "data-state")) ?? "",
  code: (await page.getAttribute("#import-status", "data-code")) ?? "",
  text: (await text(page, "#import-status")) ?? "",
});

test("after signatures are added the review is made at the node's score as it is now: a lock time that has passed reads as final, an expiry that has passed refuses the import, and a node that cannot be asked is said", async () => {
  // Earliest settlement is DAA score 1,000,000: the page builds at 500,000, before it.
  await directTrade(async (t, signedByHolder) => {
    const { page, fake } = t;
    assert.match((await fact(page, "submit-ready")) ?? "", /^not yet: /, "built before the lock time passes");
    assert.equal(await fact(page, "daa"), "500000");
    const signed = await signedByHolder();
    // The node moves on, as it does in the hours the key holder takes.
    fake.virtualDaa = Number(NOW);
    await page.fill("#import-text", signed);
    await page.click("#import-apply");
    await page.waitForFunction(() => document.querySelector("#import-status")?.getAttribute("data-state") === "ok");
    assert.equal((await importState(page)).text, "Added 1 signature. The review above is of the result, at the node's DAA score 1500000.");
    assert.equal(await fact(page, "daa"), "1500000", "the review shows the score of now, not that of the build");
    assert.equal(await fact(page, "submit-ready"), "yes");
    assert.equal(await page.isDisabled("#submit"), false);
  }, 500_000);
  // The expiry passes before the signatures come back: the import is refused and the screen is as it was.
  await directTrade(async (t, signedByHolder) => {
    const { page, fake } = t;
    const signed = await signedByHolder();
    const flags = async () => (await rows(page, "#review-inputs-body")).map((r) => r.signed);
    assert.deepEqual(await flags(), ["false", "true", "true"]);
    fake.virtualDaa = Number(EXPIRY) + 5;
    await page.fill("#import-text", signed);
    await page.click("#import-apply");
    await page.waitForFunction(() => document.querySelector("#import-status")?.getAttribute("data-state") === "refused");
    const refused = await importState(page);
    assert.equal(refused.code, "TX_EXPIRED", refused.text);
    assert.deepEqual(await flags(), ["false", "true", "true"], "nothing was added");
    assert.equal(await fact(page, "daa"), "500000", "the review is the one that was there");
    assert.equal(await page.isDisabled("#submit"), true);
    // Control: the node back before the expiry, the same text is taken.
    fake.virtualDaa = Number(NOW);
    await page.click("#import-apply");
    await page.waitForFunction(() => document.querySelector("#import-status")?.getAttribute("data-state") === "ok");
    assert.deepEqual(await flags(), ["true", "true", "true"]);
  }, 500_000);
  // The node cannot be asked for its score: the signatures are added, and the status says the review is as of the build.
  await directTrade(async (t, signedByHolder) => {
    const { page } = t;
    const signed = await signedByHolder();
    t.handler.current = () => HANGUP;
    await page.fill("#import-text", signed);
    await page.click("#import-apply");
    await page.waitForFunction(() => document.querySelector("#import-status")?.getAttribute("data-state") === "ok");
    const done = await importState(page);
    assert.match(done.text, /^Added 1 signature\. The review above is of the result, at the node's DAA score 500000\. The node's DAA score could not be read, so the review still shows the score from the build \(500000\)\.$/);
    assert.equal(await fact(page, "daa"), "500000");
  }, 500_000);
});

test("signatures are added only to the document the node was asked about: if the terms are edited, or another signature is made, while the node's score is read, nothing is added; beside the same import with nothing changed", async () => {
  /** Holds the node's answer about its own score, which the import reads, until `release()`. */
  const hold = (t: Trade) => {
    let release: () => void = () => {};
    const gate = new Promise<void>((done) => (release = done));
    t.handler.current = async (request) => {
      const reply = t.fake.handle(request);
      if ((JSON.parse(request) as { method: string }).method === "getServerInfo") await gate;
      return reply;
    };
    return release;
  };
  const startImport = async (t: Trade, signed: string) => {
    const before = sentCount(t.s, "getServerInfo");
    await t.page.fill("#import-text", signed);
    await t.page.click("#import-apply");
    await until(() => sentCount(t.s, "getServerInfo") === before + 1, "the import to ask the node for its score");
  };
  const settled = (page: Page) =>
    page.waitForFunction(() => {
      const state = document.querySelector("#import-status")?.getAttribute("data-state");
      return state === "ok" || state === "refused";
    });
  const flags = async (page: Page) => (await rows(page, "#review-inputs-body")).map((r) => r.signed);
  const CHANGED =
    "Not added: The terms, the role or the node changed while the node was being read. Nothing was added; paste the signed text again.";
  // Control: the same import, held at the same place, with nothing changed meanwhile, is taken.
  await directTrade(async (t, signedByHolder) => {
    const { page } = t;
    const signed = await signedByHolder();
    const release = hold(t);
    await startImport(t, signed);
    release();
    await settled(page);
    const done = await importState(page);
    assert.deepEqual([done.state, done.code], ["ok", ""], done.text);
    assert.deepEqual(await flags(page), ["true", "true", "true"]);
    assert.equal(await page.isDisabled("#submit"), false);
  }, 500_000);
  // The terms are edited while the node is asked: the document under review is gone, and what was
  // pasted is not put in its place.
  await directTrade(async (t, signedByHolder) => {
    const { page } = t;
    const signed = await signedByHolder();
    const release = hold(t);
    await startImport(t, signed);
    await page.fill('[data-path="nonce"]', "7");
    assert.equal(await page.isVisible("#review-panel"), false, "the edit dropped the document under review");
    release();
    await settled(page);
    const refused = await importState(page);
    assert.deepEqual([refused.state, refused.code, refused.text], ["refused", "", CHANGED]);
    assert.equal(await page.isVisible("#review-panel"), false, "the pasted document is not put under review");
    assert.equal(await page.locator("#review-inputs-body tr").count(), 0);
    assert.equal(((await text(page, "#ipst-text")) ?? "").trim(), "", "no document");
    assert.equal(await page.locator("#sign-buttons button").count(), 0);
    assert.equal(await page.isDisabled("#submit"), true);
  }, 500_000);
  // Another signature is made while the node is asked: the document under review is a new one that
  // holds it, and the import (of a copy that does not) must not replace it and lose that signature.
  await directTrade(
    async (t, signedByHolder) => {
      const { page } = t;
      const signed = await signedByHolder();
      assert.deepEqual(await flags(page), ["false", "false", "true"], "wallet A has signed; the key holder's input and wallet B's wait");
      const release = hold(t);
      await startImport(t, signed);
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.deepEqual(await flags(page), ["false", "true", "true"], "wallet B signed meanwhile");
      release();
      await settled(page);
      const refused = await importState(page);
      assert.deepEqual([refused.state, refused.code, refused.text], ["refused", "", CHANGED]);
      assert.deepEqual(await flags(page), ["false", "true", "true"], "the signature made meanwhile is still in the document");
      assert.equal(await page.isDisabled("#submit"), true, "the key holder's input is still unsigned");
      // The pasted text stays in its box, and taken now, with nothing in flight, it adds the signature it carries.
      assert.equal(await page.inputValue("#import-text"), signed);
      await page.click("#import-apply");
      await settled(page);
      assert.equal((await importState(page)).state, "ok");
      assert.deepEqual(await flags(page), ["true", "true", "true"]);
    },
    500_000,
    ["a"],
  );
});

test("when the browser refuses the copy the page opens the text and says so, beside a copy that works; a new build or an edit of the terms closes it again", async () => {
  await directTrade(async (t) => {
    const { page, s } = t;
    const copyState = async () => ({
      state: (await page.getAttribute("#ipst-copy-status", "data-state")) ?? "",
      text: (await text(page, "#ipst-copy-status")) ?? "",
      open: await page.evaluate(() => (document.getElementById("ipst-export") as HTMLDetailsElement).open),
    });
    // Control: a clipboard that takes the text. The block stays closed, and the status says so.
    await s.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: s.site.origin });
    await page.click("#ipst-copy");
    await page.waitForFunction(() => document.querySelector("#ipst-copy-status")?.getAttribute("data-state") === "ok");
    assert.deepEqual(await copyState(), { state: "ok", text: "Copied.", open: false });
    // The browser refuses: a clipboard that rejects.
    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText: () => Promise.reject(new DOMException("denied", "NotAllowedError")) },
      });
    });
    await page.click("#ipst-copy");
    await page.waitForFunction(() => document.querySelector("#ipst-copy-status")?.getAttribute("data-state") === "error");
    const refused = await copyState();
    assert.deepEqual(refused, {
      state: "error",
      text: "The browser did not allow the copy. The text is open below: select it and copy it yourself.",
      open: true,
    });
    // The text is there to see and to select: visible, the whole document, and not marked unselectable.
    assert.equal(await page.isVisible("#ipst-text"), true);
    const shown = (await text(page, "#ipst-text")) ?? "";
    assert.ok(shown.startsWith("{") && shown.includes('"inputs"'), "the IPST text");
    assert.notEqual(await page.evaluate(() => getComputedStyle(document.getElementById("ipst-text") as HTMLElement).userSelect), "none");
    // No clipboard at all: the same.
    await page.evaluate(() => {
      document.getElementById("ipst-export")!.removeAttribute("open");
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    });
    await page.click("#ipst-copy");
    await page.waitForFunction(() => (document.getElementById("ipst-export") as HTMLDetailsElement).open);
    assert.equal((await copyState()).state, "error");
    // A change of the terms drops the document: the status is idle and the block is closed.
    await page.fill('[data-path="nonce"]', "7");
    await page.waitForFunction(() => document.querySelector("#review-panel")?.hasAttribute("hidden"));
    assert.deepEqual(await copyState(), { state: "idle", text: "", open: false });
  }, 500_000);
});
