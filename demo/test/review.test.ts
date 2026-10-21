// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What a person reads before signing, in a real browser: every fact of the review pinned to the
// fixtures (the network, the trade, the fee in KAS and sompi, the node's score, the masses, the
// script of an input or output that has no address), the cost beyond the fee that a counterparty
// can put on the fee wallet, the notes about the authority and about keys that live only in the
// page, and the guard that a build in flight is not adopted for terms that changed under it.
// Expectations come from the fixtures, the rows of the page itself and the SDK's own masses; each
// refusal sits beside the accepted control.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  NODE_URL,
  actionStatus,
  build,
  fact,
  frames,
  hexOf,
  kasText,
  needs,
  prepare,
  rows,
  sdkOf,
  sentCount,
  signWith,
  text,
  until,
  withTrade,
} from "./session.ts";
import {
  ASSET_ARTIFACT,
  AMOUNT_A,
  ASSET_COV,
  AUTHORIZER,
  CASH_AMOUNT,
  CASH_ARTIFACT,
  EXPIRY,
  FEE_INPUT,
  KAS_CASH,
  NOW,
  coldTermsFor,
  externalTermsFor,
  holding,
  kcc20CashTermsFor,
} from "./world.ts";
import { partyFor, pinOf } from "./party.ts";
import type { Page } from "playwright-core";

const sum = (items: { amount: string }[]) => items.reduce((total, i) => total + BigInt(/\((\d+) sompi\)$/.exec(i.amount)?.[1] ?? "x"), 0n);

/**
 * The address of the fixtures' own KCC-20 token owned by `state`, which the page prints for a token
 * (a token UTXO sits at a pay-to-script-hash of the template with its state): the P2SH address of the
 * script hash inside the script, written by the test's own encoder.
 */
async function tokenAddress(state: { identifier_type: string; identifier: string }, amount: bigint): Promise<string> {
  const sdk = await sdkOf();
  const spk = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, { ...state, amount: amount.toString(), is_minter: false });
  assert.match(spk.script, /^aa20[0-9a-f]{64}87$/, "a token's script is a pay-to-script-hash");
  return pinOf("testnet", { kind: "kas", version: spk.version, script: spk.script });
}

/** Opens the limits the fee wallet signs under, which sit in a closed details element. */
const openLimits = (page: Page) => page.evaluate(() => ((document.getElementById("limits") as HTMLDetailsElement).open = true));

test("every fact of the review of a Direct trade is the fixtures': network, trade, fee, node score, masses, and the script of a token that has no address", async () => {
  await withTrade("direct", async (t) => {
    const { page, keys, terms, addresses } = t;
    const sdk = await sdkOf();
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await fact(page, "network"), "testnet");
    assert.equal(await fact(page, "terms-hash"), hexOf(sdk.Terms.fromJson(terms).termsHash()));
    assert.equal(await fact(page, "nonce"), "1313131313");
    assert.equal(await fact(page, "daa"), String(NOW), "the node's DAA score is the node's, not the lock time");
    // The fee: inputs less outputs, in KAS and in sompi, with the minimum relay fee of the SDK's own masses.
    const inputs = await rows(page, "#review-inputs-body");
    const outputs = await rows(page, "#review-outputs-body");
    const fee = sum(inputs) - sum(outputs);
    assert.ok(fee > 0n);
    const ipst = sdk.Ipst.fromJson((await text(page, "#ipst-text")) ?? "");
    const masses = ipst.masses();
    const min = sdk.minRelayFee(masses.fee_mass);
    assert.equal(await fact(page, "fee"), `${kasText(fee)}; the minimum relay fee is ${min} sompi`);
    assert.ok(fee >= BigInt(min), "control: a fee at or above the minimum");
    assert.equal(await fact(page, "masses"), `compute ${masses.compute}, transient ${masses.transient}, storage ${masses.storage}`);
    assert.notEqual(masses.compute, masses.storage, "the order of the masses is visible");
    // A token sits at a pay-to-script-hash: the address cell is the address of the fixture token's
    // script with its owner's state, which is not the owner's own address.
    assert.equal(inputs[0].address, await tokenAddress({ identifier_type: "pubkey", identifier: keys.a }, AMOUNT_A), "the seller's token");
    assert.equal(outputs[0].address, await tokenAddress({ identifier_type: "pubkey", identifier: keys.b }, AMOUNT_A), "the token delivered to the buyer");
    assert.notEqual(outputs[0].address, addresses.b);
    assert.equal(inputs[0].covenant, ASSET_COV);
    // The rows with addresses carry the wallets' own addresses.
    assert.equal(inputs[1].address, addresses.b);
    assert.equal(outputs[1].address, addresses.a);
    // No other fact is hiding a different one under the same label.
    assert.equal(await fact(page, "payer-cost"), "none");
    ipst.free();
  });
});

test("the review of a Vault settle names the escrowed token by its address, and the fee payer's cost beyond the fee is none", async () => {
  await withTrade("vault", async (t) => {
    const { page, terms } = t;
    const sdk = await sdkOf();
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await fact(page, "payer-cost"), "none");
    assert.equal(await fact(page, "daa"), String(NOW));
    const inputs = await rows(page, "#review-inputs-body");
    const vault = sdk.Terms.fromJson(terms).validateStructure().instantiateExisting(0);
    const escrow = await tokenAddress({ identifier_type: "script_hash", identifier: hexOf(vault.scriptHash()) }, AMOUNT_A);
    assert.equal(inputs[2].address, escrow, "the escrowed token, by its address");
    assert.equal(inputs[2].covenant, ASSET_COV);
  });
});

test("a counterparty who funds the authorizer below its minimum cannot make the fee wallet pay for it unseen: the review shows the cost, the wallet refuses it, and a limit the person sets lets it through", async () => {
  const topup = AUTHORIZER - 1n;
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, s } = t;
      await prepare(t);
      assert.equal((await build(page)).state, "ok");
      // The review: one sompi in at the authorizer, a full minimum out to the seller, and the cost named.
      const inputs = await rows(page, "#review-inputs-body");
      const outputs = await rows(page, "#review-outputs-body");
      assert.equal(inputs[0].amount, kasText(1n));
      assert.equal(outputs[2].amount, kasText(AUTHORIZER), "the seller receives the minimum, topped up");
      assert.equal(
        await fact(page, "payer-cost"),
        `${topup} sompi (0.49999999 KAS) into trade outputs: the fee inputs top up under-funded pass-through outputs to their minimum, on top of the fee`,
      );
      // The wallet that pays the fee will not sign it.
      const refused = await signWith(page, "b");
      assert.deepEqual([refused.state, refused.code], ["refused", "SDK_SIGN_TOPUP_TOO_HIGH"], refused.text);
      assert.ok(refused.text.includes(`${topup} sompi`), refused.text);
      assert.equal((await rows(page, "#review-inputs-body"))[3].signed, "false");
      assert.equal(await page.isDisabled("#submit"), true);
      // The limit is exact: one sompi short refuses, the amount itself signs.
      await openLimits(page);
      await page.fill("#max-topup", (topup - 1n).toString());
      assert.equal((await signWith(page, "b")).code, "SDK_SIGN_TOPUP_TOO_HIGH");
      await page.fill("#max-topup", topup.toString());
      const signed = await signWith(page, "b");
      assert.deepEqual([signed.state, signed.code], ["ok", ""], signed.text);
      // What the wallet paid: the fee and the top-up, and the rest came back as change.
      const after = await rows(page, "#review-outputs-body");
      const fee = sum(await rows(page, "#review-inputs-body")) - sum(after);
      assert.equal(BigInt(/\((\d+) sompi\)$/.exec(after[3].amount)?.[1] ?? "x"), FEE_INPUT - fee - topup);
      assert.equal(await page.isDisabled("#submit"), false);
      assert.equal(sentCount(s, "submitTransaction"), 0);
      assert.equal(fake.accepted.length, 0);
    },
    { utxos: (u) => holding(u, "asset-authorizer", 1n) },
  );
  // The control: the vault funded in full costs the fee wallet nothing beyond the fee, and signs with no limit set.
  await withTrade("vault", async (t) => {
    const { page } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await fact(page, "payer-cost"), "none");
    assert.equal((await signWith(page, "b")).state, "ok");
  });
});

test("a fee above twice the minimum is refused by the wallet that pays it, and a limit the person sets allows exactly that much", async () => {
  await withTrade("vault", async (t) => {
    const { page } = t;
    await prepare(t);
    await page.fill("#fee", "20000000");
    assert.equal((await build(page)).state, "ok");
    const refused = await signWith(page, "b");
    assert.deepEqual([refused.state, refused.code], ["refused", "SDK_SIGN_FEE_TOO_HIGH"], refused.text);
    await openLimits(page);
    await page.fill("#max-fee", "19999999");
    assert.equal((await signWith(page, "b")).code, "SDK_SIGN_FEE_TOO_HIGH");
    await page.fill("#max-fee", "20000000");
    assert.equal((await signWith(page, "b")).state, "ok");
    // A limit that is not a number is the SDK's refusal, not the page's guess.
    await page.fill("#max-fee", "lots");
    await build(page);
    assert.equal((await signWith(page, "b")).code, "SDK_JSON_FORM");
  });
});

test("where the change goes: the builder pays it where the person says and the wallet signs only a document that pays that address", async () => {
  await withTrade("vault", async (t) => {
    const { page, addresses } = t;
    const sdk = await sdkOf();
    const away = sdk.Wallet.generate();
    const address = away.address("testnet");
    away.free();
    await prepare(t, "buyer", {}, { change: address });
    assert.equal((await build(page)).state, "ok");
    const outputs = await rows(page, "#review-outputs-body");
    assert.equal(outputs[3].address, address, "the change is paid to the address typed");
    assert.notEqual(outputs[3].address, addresses.b);
    assert.match(outputs[3].what, /^change, back to the fee payer/);
    assert.equal(outputs[3].held, null, "an address of a key held in no wallet of the page");
    assert.equal((await signWith(page, "b")).state, "ok", "the wallet is told the same address");
    // The address changes after the document was built: the wallet is told another and refuses.
    await page.fill("#change-address", addresses.a);
    await build(page);
    await page.fill("#change-address", address);
    const refused = await signWith(page, "b");
    assert.deepEqual([refused.state, refused.code], ["refused", "SDK_SIGN_CHANGE_NOT_MINE"], refused.text);
    assert.ok(refused.text.includes(addresses.a) && refused.text.includes(address), refused.text);
    // A change address that is not one is the SDK's refusal.
    await page.fill("#change-address", "not an address");
    const bad = await build(page);
    assert.deepEqual([bad.state, bad.code], ["refused", "SDK_JSON_FORM"], bad.text);
  });
});

test("on testnet a destination that pays a key held only in the page is allowed, and the result and the review say what that means", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    await prepare(t);
    const check = (await text(page, '#summary [data-field="role-check"]')) ?? "";
    assert.ok(
      check.includes("buyer_delivery pays your key: a key that lives only in a wallet of this page, so what is paid there cannot be spent from this page and is lost when it unloads"),
      check,
    );
    assert.ok(check.includes("buyer_refund pays your key: a key that lives only in a wallet of this page"), check);
    assert.equal((await build(page)).state, "ok");
    // Every output of a Direct trade between the two wallets pays a key of the page, the change too.
    const outputs = await rows(page, "#review-outputs-body");
    assert.deepEqual(outputs.map((r) => r.held), ["true", "true", "true"]);
    assert.ok(outputs.every((r) => r.what.endsWith("[pays a key that lives only in this page]")));
    const notes = await page.locator("#review-notes li").allTextContents();
    assert.equal(notes.length, 1);
    assert.match(
      notes[0],
      /^Outputs 0, 1, 2 \(\d+\.\d{8} KAS in all, and any token they carry\) pay a key that lives only in a wallet of this page\. Nothing in this page can spend it, and it is lost when the page unloads\. On mainnet signing refuses it\.$/,
    );
    assert.equal((await signWith(page, "a")).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
  });
  // The control: destinations that pay a key held in no wallet of the page carry no such note.
  await withTrade(
    "direct",
    async (t) => {
      const { page } = t;
      const cold = coldKey(t.terms);
      const party = partyFor("buyer", t.terms as never);
      await prepare(t, "buyer", { receive: party.receive, refund: party.refund }, { change: pinOf("testnet", { kind: "kas", version: 0, script: `20${cold}ac` }) });
      const check = (await text(page, '#summary [data-field="role-check"]')) ?? "";
      assert.ok(!check.includes("lives only in a wallet"), check);
      assert.equal((await build(page)).state, "ok");
      const outputs = await rows(page, "#review-outputs-body");
      assert.deepEqual(outputs.map((r) => r.held), [null, null, null]);
      assert.deepEqual(await page.locator("#review-notes li").allTextContents(), []);
    },
    { terms: (sdk, k) => coldTermsFor(sdk, "direct", k.a, k.b, newColdKey(sdk), "testnet") },
  );
});

/** A key that lives in no wallet of the page: drawn in Node and thrown away; only its public key is used. */
function newColdKey(sdk: Record<string, any>): string {
  const w = sdk.Wallet.generate();
  const key = w.publicKey();
  w.free();
  return key;
}

/** The key the four destinations of cold terms pay. */
function coldKey(terms: Record<string, any>): string {
  return terms.seller_proceeds.script.slice(2, 66);
}

test("on mainnet the page offers nothing while a destination of the role pays a key held only in its wallets, and a pin to an address elsewhere is what lets the trade through", async () => {
  // The default terms between the wallets: refused, whatever is pinned.
  await withTrade(
    "direct",
    async (t) => {
      const { page } = t;
      await prepare(t, "buyer", {}, { expect: "SDK_DESTINATION_IN_WALLET" });
      const said = (await text(page, "#status")) ?? "";
      assert.equal(await page.getAttribute("#status", "data-state"), "refused");
      assert.match(said, /buyer_delivery pays .*a key that lives only in a wallet of this page/);
      assert.match(said, /Pin an address you control elsewhere$/);
      assert.equal(await page.isVisible("#actions"), false, "nothing is offered");
      assert.equal(await page.isVisible("#review-panel"), false);
      // Pinning the destinations to themselves pays the same wallet key: still refused.
      const own = partyFor("buyer", t.terms as never);
      await page.click("#you details > summary");
      await page.fill("#pin-receive", pinOf("mainnet", { kind: "kcc20", identifier_type: "pubkey", identifier: own.key }));
      await page.fill("#pin-refund", pinOf("mainnet", { kind: "kas", version: 0, script: `20${own.key}ac` }));
      assert.equal(await page.getAttribute("#status", "data-code"), "SDK_DESTINATION_IN_WALLET");
    },
    { network: "mainnet" },
  );
});

test("a mainnet Vault trade settles through the page when the destinations and the change are addresses elsewhere, the decoder on mainnet reads it back, and every piece of it is mainnet", async () => {
  let cold = "";
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake, s, sdk, terms, keys } = t;
      const address = pinOf("mainnet", { kind: "kas", version: 0, script: `20${cold}ac` });
      const party = partyFor("buyer", terms as never);
      assert.deepEqual([party.receive, party.refund], [`kcc20:pubkey:${cold}`, address]);
      await prepare(t, "buyer", { receive: party.receive, refund: party.refund }, { change: address });
      assert.equal(await page.getAttribute("body", "data-network"), "mainnet");
      const built = await build(page);
      assert.equal(built.state, "ok", built.text);
      assert.equal(await fact(page, "network"), "mainnet");
      const outputs = await rows(page, "#review-outputs-body");
      assert.equal(outputs[1].address, address, "the cash goes to the address elsewhere");
      assert.ok(outputs.every((r) => r.held === null), "no output pays a key held in the page");
      assert.match(outputs[0].address, /^kaspa:p/, "the delivered token, at a mainnet pay-to-script-hash address");
      // The mainnet switch is on, so the wallet signs for mainnet (without it, it would refuse).
      const signed = await signWith(page, "b");
      assert.deepEqual([signed.state, signed.code], ["ok", ""], signed.text);
      const sent = await submitOk(page);
      assert.match(sent, /^Submitted\. /);
      assert.equal(fake.accepted.length, 1);
      // Every address in the traffic is a mainnet address.
      const asked = frames(s).filter((f) => f.method === "getUtxosByAddresses").flatMap((f) => f.params.addresses as string[]);
      assert.ok(asked.length > 0 && asked.every((a) => a.startsWith("kaspa:")), asked.join(","));
      // The decoder, on mainnet, over the same node: the trade is read back, bound, and for mainnet.
      const txid = fake.accepted[0].txid;
      const decoder = await t.s.context.newPage();
      await decoder.goto(`${s.site.origin}/decoder.html`);
      await decoder.selectOption("#decoder-network", { value: "mainnet" });
      await decoder.fill("#node-url", NODE_URL);
      await decoder.fill("#txid", txid);
      await decoder.fill("#from-block", fake.genesis);
      await decoder.click("#decode");
      await decoder.waitForFunction(() => ["ok", "refused"].includes(document.querySelector("#decoder-status")?.getAttribute("data-state") ?? ""));
      assert.equal(await decoder.getAttribute("#decoder-status", "data-state"), "ok", (await text(decoder, "#decoder-status")) ?? "");
      const outcomes = await decoder.locator("#out-trade .outcome").allTextContents();
      assert.equal(outcomes[0], `Delivered ${AMOUNT_A} to KCC-20 owner pubkey ${cold}`);
      assert.equal(outcomes[1], `Delivered ${KAS_CASH} to KAS scriptPublicKey (version 0) 20${cold}ac`);
      assert.equal(await decoder.getAttribute("#out-template .binding", "data-bound"), "true");
      // The decoder refuses the same transaction when asked as testnet: the node is on mainnet.
      await decoder.selectOption("#decoder-network", { value: "testnet" });
      await decoder.click("#decode");
      await decoder.waitForFunction(() => document.querySelector("#decoder-status")?.getAttribute("data-state") === "refused");
      assert.equal(await decoder.getAttribute("#decoder-status", "data-code"), "SDK_NODE_NETWORK_MISMATCH");
      await decoder.close();
      assert.deepEqual([...new Set(s.contacted)], [new URL(NODE_URL).href]);
      void keys;
    },
    {
      network: "mainnet",
      // The seller is a key held in no wallet of the page: the vault's authorizer comes back to the
      // seller's key whatever the terms say, and on mainnet a wallet's key is refused there.
      terms: (sdk, k) => {
        cold = newColdKey(sdk);
        return coldTermsFor(sdk, "vault", newColdKey(sdk), k.b, cold, "mainnet");
      },
    },
  );
});

/** Clicks submit and returns the status text once the page has answered. */
async function submitOk(page: Page): Promise<string> {
  await page.click("#submit");
  await page.waitForFunction(() => ["ok", "refused", "wait", "unknown"].includes(document.querySelector("#submit-status")?.getAttribute("data-state") ?? ""));
  return (await text(page, "#submit-status")) ?? "";
}

test("a Direct trade between two wallets of the page settles on mainnet when each party's pins and the change are addresses elsewhere", async () => {
  let cold = "";
  await withTrade(
    "direct",
    async (t) => {
      const { page, fake, terms } = t;
      const address = pinOf("mainnet", { kind: "kas", version: 0, script: `20${cold}ac` });
      const buyer = partyFor("buyer", terms as never);
      const seller = partyFor("seller", terms as never);
      await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: address, other: { receive: seller.receive, refund: seller.refund } });
      assert.equal((await build(page)).state, "ok");
      // Wallet B is the person, with the person's pins; wallet A is the other party, with its own.
      const bySeller = await signWith(page, "a");
      assert.deepEqual([bySeller.state, bySeller.code], ["ok", ""], bySeller.text);
      const byBuyer = await signWith(page, "b");
      assert.deepEqual([byBuyer.state, byBuyer.code], ["ok", ""], byBuyer.text);
      assert.match(await submitOk(page), /^Submitted\. /);
      assert.equal(fake.accepted.length, 1);
    },
    {
      network: "mainnet",
      terms: (sdk, k) => {
        cold = newColdKey(sdk);
        return coldTermsFor(sdk, "direct", k.a, k.b, cold, "mainnet");
      },
    },
  );
  // Without the other party's pins the wallet that is the other party is refused, as the role check
  // refuses a destination that does not pay its key: the pins of one party are never given to another.
  await withTrade(
    "direct",
    async (t) => {
      const { page, terms } = t;
      const address = pinOf("mainnet", { kind: "kas", version: 0, script: `20${cold}ac` });
      const buyer = partyFor("buyer", terms as never);
      await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: address });
      assert.equal((await build(page)).state, "ok");
      const refused = await signWith(page, "a");
      assert.deepEqual([refused.state, refused.code], ["refused", "SDK_DESTINATION_NOT_MINE"], refused.text);
      assert.equal((await signWith(page, "b")).state, "ok", "the person's own wallet signs under the person's pins");
    },
    {
      network: "mainnet",
      terms: (sdk, k) => {
        cold = newColdKey(sdk);
        return coldTermsFor(sdk, "direct", k.a, k.b, cold, "mainnet");
      },
    },
  );
});

test("on mainnet a wallet refuses a document that pays the other wallet of the page, which only the page can tell it of", async () => {
  let cold = "";
  await withTrade(
    "direct",
    async (t) => {
      const { page, terms, keys } = t;
      const address = pinOf("mainnet", { kind: "kas", version: 0, script: `20${cold}ac` });
      const buyer = partyFor("buyer", terms as never);
      // The buyer's destinations and the change are addresses elsewhere; the seller's proceeds pay wallet A.
      await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund }, { change: address });
      assert.equal((await build(page)).state, "ok");
      const outputs = await rows(page, "#review-outputs-body");
      assert.deepEqual(outputs.map((r) => r.held), [null, "true", null], "the review marks the proceeds");
      assert.equal(outputs[1].address, pinOf("mainnet", { kind: "kas", version: 0, script: `20${keys.a}ac` }));
      // Wallet B is not paid anything here. It is told of wallet A by the page, and refuses.
      const refused = await signWith(page, "b");
      assert.deepEqual([refused.state, refused.code], ["refused", "SDK_DESTINATION_IN_WALLET"], refused.text);
      assert.match(refused.text, /output 1 of 100000000 sompi pays kaspa:[a-z0-9]+, a key that lives only in a wallet of this page/);
      assert.doesNotMatch(refused.text, /output [02]/);
      assert.equal((await rows(page, "#review-inputs-body"))[1].signed, "false");
    },
    {
      network: "mainnet",
      terms: (sdk, k) => {
        cold = newColdKey(sdk);
        return { ...coldTermsFor(sdk, "direct", k.a, k.b, cold, "mainnet"), seller_proceeds: { kind: "kas", version: 0, script: `20${k.a}ac` } };
      },
    },
  );
});

test("on mainnet the fee wallet's change to its own key is refused at signing, and an address elsewhere signs", async () => {
  let cold = "";
  await withTrade(
    "vault",
    async (t) => {
      const { page, terms } = t;
      const buyer = partyFor("buyer", terms as never);
      await prepare(t, "buyer", { receive: buyer.receive, refund: buyer.refund });
      const built = await build(page);
      assert.equal(built.state, "ok", built.text);
      const outputs = await rows(page, "#review-outputs-body");
      assert.equal(outputs[3].held, "true", "the change pays wallet B's own key and the review says so");
      assert.match((await page.locator("#review-notes li").first().textContent()) ?? "", /^Output 3 \(\d+\.\d{8} KAS, and any token it carries\) pays a key that lives only in a wallet of this page/);
      const refused = await signWith(page, "b");
      assert.deepEqual([refused.state, refused.code], ["refused", "SDK_DESTINATION_IN_WALLET"], refused.text);
      assert.match(refused.text, /the change of \d+ sompi pays kaspa:/);
      // Control: the same document, once the person names an address elsewhere (and rebuilds).
      await page.fill("#change-address", pinOf("mainnet", { kind: "kas", version: 0, script: `20${cold}ac` }));
      assert.equal((await build(page)).state, "ok");
      assert.equal((await signWith(page, "b")).state, "ok");
    },
    {
      network: "mainnet",
      terms: (sdk, k) => {
        cold = newColdKey(sdk);
        return coldTermsFor(sdk, "vault", newColdKey(sdk), k.b, cold, "mainnet");
      },
    },
  );
});

test("a KCC-20 cash trade goes through the page with the cash artifact filled, and without it the page cannot check the document", async () => {
  await withTrade(
    "vault",
    async (t) => {
      const { page, fake } = t;
      // Without the cash artifact the SDK has nothing to check the cash token against.
      await prepare(t);
      const missing = await build(page);
      assert.equal(missing.state, "refused", missing.text);
      assert.ok(/artifacts\.cash|cash token/.test(missing.text), missing.text);
      // With it: a settle of four inputs and four outputs, both tokens by their scripts.
      await page.fill("#cash-artifact", CASH_ARTIFACT);
      const built = await build(page);
      assert.equal(built.state, "ok", built.text);
      assert.equal((await rows(page, "#review-inputs-body")).length, 5, "two authorizers, two escrowed tokens, the fee input");
      const inputs = await rows(page, "#review-inputs-body");
      assert.deepEqual(inputs.map((r) => r.what.replace(/ \(P2PK of the key .*$/, "")), [
        "the asset vault",
        "the cash vault",
        "the asset token escrowed in the asset vault",
        "the cash token escrowed in the cash vault",
        "the buyer's key (P2PK)",
      ]);
      assert.equal((await rows(page, "#review-outputs-body")).length, 5);
      assert.equal((await signWith(page, "b")).state, "ok");
      assert.match(await submitOk(page), /^Submitted\. /);
      assert.equal(fake.accepted.length, 1);
      const decoded = fake.accepted[0].decoded as { legs: { leg: number; outcome: { kind: string; amount: string } }[] };
      assert.deepEqual(decoded.legs.map((l) => [l.leg, l.outcome.kind, l.outcome.amount]), [
        [0, "delivered", AMOUNT_A.toString()],
        [1, "delivered", CASH_AMOUNT.toString()],
      ]);
    },
    { terms: (sdk, k) => kcc20CashTermsFor(sdk, "vault", k.a, k.b) },
  );
});

test("a settle that is built, signed and then submitted after the expiry is refused by the page with nothing sent, and goes through when the node's score is before it", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal((await signWith(page, "b")).state, "ok");
    fake.virtualDaa = Number(EXPIRY) + 5;
    await page.click("#submit");
    await page.waitForFunction(() => document.querySelector("#submit-status")?.getAttribute("data-state") === "refused");
    assert.equal(await page.getAttribute("#submit-status", "data-code"), "TX_EXPIRED");
    assert.equal(sentCount(s, "submitTransaction"), 0, "nothing was sent");
    assert.equal(fake.accepted.length, 0);
    // The signed document is still there: with the node's score before the expiry again it is sent.
    assert.equal(await page.isDisabled("#submit"), false);
    fake.virtualDaa = NOW;
    assert.match(await submitOk(page), /^Submitted\. /);
    assert.equal(sentCount(s, "submitTransaction"), 1);
    assert.equal(fake.accepted.length, 1);
  });
});

test("external cash: the title says the cash is paid outside Kaspa, the authority's input is named as the authority's, and the note says what its signature attests", async () => {
  let authority = "";
  await withTrade(
    "vault",
    async (t) => {
      const { page } = t;
      await prepare(t);
      assert.equal((await build(page)).state, "ok");
      assert.equal(
        await text(page, "#review-title"),
        "Settle: the asset to the buyer; the cash is paid outside Kaspa, and the authority's signature attests it",
      );
      const inputs = await rows(page, "#review-inputs-body");
      assert.equal(inputs[0].signer, needs(authority, "authority"));
      assert.match(inputs[2].signer ?? "", /^needs [0-9a-f]{64} \(the buyer\)$/, "the fee input is the buyer's key here");
      const notes = await page.locator("#review-notes li").allTextContents();
      assert.equal(notes.length, 2, "the authority's, and the keys of the page");
      assert.equal(
        notes[0],
        "Input 0 is signed by the authority. The cash leg is paid outside Kaspa and nothing on chain shows it: the authority's signature is the only thing that releases this transaction, and signing it attests that the cash was paid. Impulse does not check the payment.",
      );
    },
    {
      terms: (sdk, k) => {
        authority = newColdKey(sdk);
        return externalTermsFor(sdk, k.a, k.b, authority);
      },
    },
  );
  // The control: a trade whose cash is on Kaspa says so, and has no authority note.
  await withTrade("direct", async (t) => {
    const { page } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await text(page, "#review-title"), "Direct trade: the asset to the buyer, the cash to the seller");
    const notes = await page.locator("#review-notes li").allTextContents();
    assert.ok(notes.every((n) => !n.includes("authority")), notes.join(" | "));
  });
});

test("a build in flight when the terms, the role or the node change is thrown away, and nothing is offered for the form as it now stands", async () => {
  await withTrade("vault", async (t) => {
    const { page, fake, s } = t;
    await prepare(t);
    const hold = () => {
      let release = () => {};
      const gate = new Promise<void>((done) => (release = done));
      t.handler.current = async (request) => {
        if ((JSON.parse(request) as { method: string }).method === "getUtxosByAddresses") await gate;
        return fake.handle(request);
      };
      return release;
    };
    const waitForUtxoQuestion = async (before: number) => until(() => sentCount(s, "getUtxosByAddresses") > before, "the UTXO question");

    // 1. The terms change while the node is being read: the nonce.
    let release = hold();
    let asked = sentCount(s, "getUtxosByAddresses");
    await page.click("#build-settle");
    await waitForUtxoQuestion(asked);
    await page.fill('[data-path="nonce"]', "7");
    release();
    await page.waitForFunction(() => document.querySelector("#action-status")?.getAttribute("data-state") === "stale");
    assert.match((await actionStatus(page)).text, /^The terms, the role or the node changed while the node was being read\./);
    assert.equal(await page.isVisible("#review-panel"), false, "no review for terms that are not the form's");
    assert.equal(await page.locator("#sign-buttons button").count(), 0);
    assert.equal(await page.inputValue('[data-path="nonce"]'), "7");
    t.handler.current = (request) => fake.handle(request);

    // 2. The role changes while the node is being read: the first digit of the key. The role check
    //    refuses it, the actions are hidden, and the build in flight does not bring a review back.
    await page.fill('[data-path="nonce"]', "1313131313");
    await page.waitForSelector("#status[data-state='ok']");
    release = hold();
    asked = sentCount(s, "getUtxosByAddresses");
    await page.click("#build-settle");
    await waitForUtxoQuestion(asked);
    const key = await page.inputValue("#my-key");
    await page.fill("#my-key", `${key[0] === "a" ? "b" : "a"}${key.slice(1)}`);
    assert.equal(await page.getAttribute("#status", "data-code"), "SDK_ROLE_KEY_MISMATCH");
    release();
    await page.waitForFunction(() => document.querySelector("#action-status")?.getAttribute("data-state") === "stale");
    assert.equal(await page.isVisible("#actions"), false);
    assert.equal(await page.isVisible("#review-panel"), false);
    assert.equal(await page.locator("#sign-buttons button").count(), 0);
    t.handler.current = (request) => fake.handle(request);

    // 3. The control: nothing changes, the same build is adopted and offers its review.
    await page.fill("#my-key", key);
    await page.waitForSelector("#status[data-state='ok']");
    release = hold();
    asked = sentCount(s, "getUtxosByAddresses");
    await page.click("#build-settle");
    await waitForUtxoQuestion(asked);
    release();
    await page.waitForFunction(() => document.querySelector("#action-status")?.getAttribute("data-state") === "ok");
    assert.equal(await page.isVisible("#review-panel"), true);
    assert.equal(await page.locator("#sign-buttons button").count(), 1);
    assert.equal(await fact(page, "nonce"), "1313131313");
  });
});
