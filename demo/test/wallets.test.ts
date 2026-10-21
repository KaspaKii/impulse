// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The two wallets of the page: a key is made in the page, held in the SDK's memory and wiped on
// request and when the page is hidden or closed; and no key appears in the page's DOM, its
// storage, its network traffic or its console.
//
// The keys are runtime throwaways. To look for one where it must not be, the test records the
// bytes the page draws from crypto.getRandomValues (an init script wraps the call) and shows with
// an independent implementation (@noble/curves, a dev dependency of the SDK package) that the 32
// bytes drawn for a wallet are its key. Assertions about the key are written as plain booleans
// with messages that do not carry it, so a failure never prints it, and the bytes are never
// written to a file or a log.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { schnorr } from "../../crates/impulse-wasm/npm/node_modules/@noble/curves/secp256k1.js";
import type { Page } from "playwright-core";
import {
  build,
  connect,
  prepare,
  signWith,
  submitAndWait,
  text,
  withTrade,
  type Trade,
} from "./session.ts";
import { pinOf } from "./party.ts";
import { p2pk, utxo } from "./world.ts";

const hexToBytes = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const bytesToHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Every way the test knows to write the 32 bytes as text. */
function spellings(secretHex: string): string[] {
  const secret = hexToBytes(secretHex);
  const be = BigInt(`0x${secretHex}`).toString();
  const reversed = Uint8Array.from(secret).reverse();
  const le = BigInt(`0x${bytesToHex(reversed)}`).toString();
  return [
    secretHex,
    secretHex.toUpperCase(),
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("base64url"),
    Buffer.from(secret).toString("base64").replace(/=+$/, ""),
    be,
    le,
    Array.from(secret).join(","),
    Array.from(secret).join(", "),
    bytesToHex(reversed),
  ];
}

const leaks = (haystack: string, secretHex: string) => spellings(secretHex).some((s) => haystack.includes(s));

/** The 32-byte draws of the page, in order: the keys of the wallets that were made. */
async function drawn(page: Page): Promise<string[]> {
  const all = await page.evaluate(() => (window as unknown as { __drawn: string[] }).__drawn);
  return all.filter((h) => h.length === 64);
}

/** Everything in the page and about it that could hold a key, as text, by channel. */
async function channels(t: Trade): Promise<Record<string, string>> {
  const { page, s } = t;
  const inPage = await page.evaluate(async () => {
    const dom: string[] = [document.documentElement.outerHTML, document.title, location.href];
    for (const el of document.querySelectorAll("input, textarea, select")) dom.push((el as HTMLInputElement).value);
    for (const el of document.querySelectorAll("*")) for (const a of el.getAttributeNames()) dom.push(el.getAttribute(a) ?? "");
    const storage: string[] = [JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage }), document.cookie];
    storage.push(JSON.stringify((await indexedDB.databases?.()) ?? []));
    storage.push(JSON.stringify(await caches.keys()));
    // The page's own globals, the test's recorder (named __drawn, __csp) apart.
    const globals: string[] = [];
    for (const key of Object.getOwnPropertyNames(window)) {
      if (key.startsWith("__")) continue;
      try {
        const value = (window as unknown as Record<string, unknown>)[key];
        if (typeof value === "string" || typeof value === "number") globals.push(`${key}=${value}`);
      } catch {
        // a getter that throws holds nothing
      }
    }
    return { dom: dom.join("\n"), storage: storage.join("\n"), globals: globals.join("\n") };
  });
  return {
    ...inPage,
    network: [
      ...s.requests.map((r) => `${r.method} ${r.url}\n${JSON.stringify(r.headers)}\n${r.body ?? ""}`),
      ...s.sent.map((m) => `${m.url}\n${m.text}`),
      ...s.contacted,
    ].join("\n"),
    console: s.console.join("\n"),
  };
}

const state = (page: Page, wallet: "a" | "b") => page.getAttribute(`#wallet-${wallet} .wallet-state`, "data-state");

test("a wallet shows its public key and address and offers no way to see or export a key", async () => {
  await withTrade("direct", async (t) => {
    const { page, keys, addresses } = t;
    assert.equal(await state(page, "a"), "ready");
    assert.equal(await state(page, "b"), "ready");
    assert.notEqual(keys.a, keys.b);
    // The address is the key as a P2PK address on the page's network, written by the test's encoder.
    assert.equal(addresses.a, pinOf("testnet", { kind: "kas", version: 0, script: `20${keys.a}ac` }));
    assert.equal(addresses.b, pinOf("testnet", { kind: "kas", version: 0, script: `20${keys.b}ac` }));
    assert.match(addresses.a, /^kaspatest:/);
    await page.check("#mainnet-switch");
    assert.match((await text(page, "#wallet-a .wallet-address")) ?? "", /^kaspa:/, "the address follows the network");
    await page.uncheck("#mainnet-switch");
    assert.equal(await text(page, "#wallet-a .wallet-address"), addresses.a);
    // Nothing on a wallet card but the buttons of the list: no input, no export, no download, no link.
    const parts = await page.locator("#wallet-panel").evaluate((panel) => ({
      inputs: panel.querySelectorAll("input, textarea, select").length,
      links: panel.querySelectorAll("a").length,
      buttons: [...panel.querySelectorAll("button")].map((b) => b.textContent),
    }));
    assert.deepEqual(parts.inputs, 0);
    assert.deepEqual(parts.links, 0);
    assert.deepEqual(parts.buttons.slice(0, 6), ["Make a key", "Wipe", "Read balance", "I am this key", "Seller key", "Buyer key"]);
    assert.ok(parts.buttons.every((b) => !/export|show|copy|download|backup|reveal/i.test(b ?? "")), "no button that would hand out a key");
  });
});

test("the wallet buttons put public keys into the form, and wipe and regenerate replace a key", async () => {
  await withTrade("direct", async (t) => {
    const { page, keys } = t;
    await page.click("#wallet-a .wallet-use-seller");
    await page.click("#wallet-b .wallet-use-buyer");
    await page.click("#wallet-b .wallet-use-me");
    assert.equal(await page.inputValue('[data-path="seller_key"]'), keys.a);
    assert.equal(await page.inputValue('[data-path="buyer_key"]'), keys.b);
    assert.equal(await page.inputValue("#my-key"), keys.b);
    // Wipe: the key is gone from the page, the public key stays for reference, no more signing.
    assert.equal(await page.isDisabled("#wallet-a .wallet-wipe"), false);
    await page.click("#wallet-a .wallet-wipe");
    assert.equal(await state(page, "a"), "wiped");
    assert.match((await text(page, "#wallet-a .wallet-state")) ?? "", /^Wiped: the key is gone from this page and cannot be signed with\./);
    assert.equal(await text(page, "#wallet-a .wallet-key"), keys.a);
    assert.equal(await page.isDisabled("#wallet-a .wallet-wipe"), true);
    assert.equal(await page.isDisabled("#wallet-a .wallet-refresh"), true);
    assert.equal(await state(page, "b"), "ready", "the other wallet is untouched");
    // A new key replaces the wiped one, and is not the old one.
    assert.equal(await page.isDisabled("#wallet-a .wallet-generate"), false);
    await page.click("#wallet-a .wallet-generate");
    assert.equal(await state(page, "a"), "ready");
    const fresh = (await text(page, "#wallet-a .wallet-key")) ?? "";
    assert.match(fresh, /^[0-9a-f]{64}$/);
    assert.notEqual(fresh, keys.a);
    // A wallet that holds a key cannot be asked for another: the button is off until it is wiped.
    assert.equal(await page.isDisabled("#wallet-a .wallet-generate"), true);
    // Two draws of 32 bytes for the first two keys, a third for the replacement: all different.
    const draws = await drawn(page);
    assert.equal(draws.length, 3);
    assert.equal(new Set(draws).size, 3);
  });
});

test("the wallets are wiped when the page is hidden or unloaded, and by the button for both; a navigation that is only asked for wipes nothing", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    const states = async () => [await state(page, "a"), await state(page, "b")];
    // The page goes: the browser fires pagehide, and the wallets are wiped.
    assert.deepEqual(await states(), ["ready", "ready"], "control: both hold a key");
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    assert.deepEqual(await states(), ["wiped", "wiped"], "pagehide");
    await page.click("#wallet-a .wallet-generate");
    await page.click("#wallet-b .wallet-generate");
    // beforeunload fires before a navigation that may then be cancelled or fail, with the page
    // staying up: it asks the browser to confirm, and wipes nothing.
    const asked = () =>
      page.evaluate(() => {
        const event = new Event("beforeunload", { cancelable: true });
        window.dispatchEvent(event);
        return event.defaultPrevented;
      });
    assert.equal(await asked(), true, "the browser is asked to confirm while a wallet holds a key");
    assert.deepEqual(await states(), ["ready", "ready"], "and nothing is wiped by it");
    await page.click("#wallet-a .wallet-wipe");
    assert.equal(await asked(), true, "one wallet still holds a key");
    // The button for both.
    await page.click("#wipe-all");
    assert.deepEqual(await states(), ["wiped", "wiped"]);
    assert.equal(await asked(), false, "with no key held there is nothing to confirm");
    // With both wiped there is no signing button for anything.
    assert.equal(await page.locator("#sign-buttons button").count(), 0);
  });
});

test("a navigation the person cancels leaves the wallets where they are; one they confirm takes them", async () => {
  await withTrade("direct", async (t) => {
    const { page, s } = t;
    const dialogs: string[] = [];
    let answer: "dismiss" | "accept" = "dismiss";
    page.on("dialog", async (d) => {
      dialogs.push(d.type());
      await (answer === "dismiss" ? d.dismiss() : d.accept());
    });
    const here = page.url();
    // The page's own header link, with wallets that hold keys: the browser asks, the person says no.
    await page.click('nav a[href="decoder.html"]');
    assert.deepEqual(dialogs, ["beforeunload"], "the browser asked");
    assert.equal(page.url(), here, "the navigation was cancelled");
    assert.deepEqual([await state(page, "a"), await state(page, "b")], ["ready", "ready"], "and the keys are still here");
    // Control: yes, and the page that follows has none.
    answer = "accept";
    await Promise.all([page.waitForURL(/decoder\.html$/), page.click('nav a[href="decoder.html"]')]);
    assert.equal(dialogs.length, 2);
    assert.equal(new URL(page.url()).origin, s.site.origin);
    assert.equal(await page.locator("#wallet-a").count(), 0, "the decoder page has no wallets");
  });
});

test("Wipe asks first when the last balance read was above zero, and wipes at once when it was zero or never read", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    assert.equal((await connect(page)).state, "connected");
    const states = async () => [await state(page, "a"), await state(page, "b")];
    const confirm = () => page.isVisible("#wipe-confirm");
    const read = async (wallet: "a" | "b") => {
      await page.click(`#wallet-${wallet} .wallet-refresh`);
      await page.waitForFunction(
        (w) => document.querySelector(`#wallet-${w} .wallet-balance`)?.getAttribute("data-state") === "ok",
        wallet,
      );
      return text(page, `#wallet-${wallet} .wallet-balance`);
    };
    // Wallet A holds no KAS at its address (the seller's token sits at the token's script); wallet B
    // holds the buyer's cash and fee UTXOs: 1 KAS and 10 KAS.
    assert.equal(await read("a"), "0.00000000 KAS in 0 UTXOs, as the node reports");
    assert.equal(await read("b"), "11.00000000 KAS in 2 UTXOs, as the node reports");
    // Control: A was read as holding nothing, so Wipe wipes it at once.
    await page.click("#wallet-a .wallet-wipe");
    assert.equal(await state(page, "a"), "wiped");
    assert.equal(await confirm(), false, "nothing to confirm for a wallet that was read as empty");
    // B was read as holding KAS: the press of Wipe wipes nothing and asks.
    await page.click("#wallet-b .wallet-wipe");
    assert.equal(await state(page, "b"), "ready");
    assert.equal(await confirm(), true);
    const ask = (await text(page, "#wipe-confirm-text")) ?? "";
    assert.ok(ask.startsWith("Wallet B held 11.00000000 KAS when you last read its balance."), ask);
    assert.ok(ask.includes("nothing here can send it anywhere"), ask);
    assert.ok(!ask.includes("Wallet A"), "only the wallet that held KAS is named");
    // Keep it: the panel closes and the wallet stays.
    await page.click("#wipe-confirm-no");
    assert.equal(await confirm(), false);
    assert.equal(await state(page, "b"), "ready");
    // Both wallets, one holding KAS: the same question; yes wipes both.
    await page.click("#wallet-a .wallet-generate");
    await page.click("#wipe-all");
    assert.deepEqual(await states(), ["ready", "ready"], "asked, not wiped");
    assert.equal(await confirm(), true);
    await page.click("#wipe-confirm-yes");
    assert.deepEqual(await states(), ["wiped", "wiped"]);
    assert.equal(await confirm(), false);
    // Control: new wallets, never read, are wiped at once.
    await page.click("#wallet-a .wallet-generate");
    await page.click("#wallet-b .wallet-generate");
    await page.click("#wipe-all");
    assert.deepEqual(await states(), ["wiped", "wiped"]);
    assert.equal(await confirm(), false, "a wallet that was not read is not asked about");
  });
});

test("a document built before the page unloads cannot be signed after it", async () => {
  await withTrade("direct", async (t) => {
    const { page } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    assert.equal(await page.locator("#sign-buttons button").count(), 2, "control: both wallets can sign");
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    assert.equal(await page.locator("#sign-buttons button").count(), 0, "after the unload event neither can");
    assert.equal(await page.isDisabled("#submit"), true);
  });
});

test("a real navigation away destroys the wallets: the page that follows holds none", async () => {
  await withTrade("direct", async (t) => {
    const { page, s } = t;
    assert.equal(await state(page, "a"), "ready");
    // The browser asks before it leaves a page that holds keys; this person says yes.
    page.on("dialog", (d) => void d.accept());
    await page.goto(`${s.site.origin}/decoder.html`);
    await page.goBack();
    await page.waitForSelector("#status");
    // The browser may have kept the old page in its back/forward cache; if it did, the page was
    // told it was hidden and wiped. Either way no wallet of the old page signs.
    const states = [await state(page, "a"), await state(page, "b")];
    assert.ok(states.every((x) => x === "none" || x === "wiped"), `after a navigation: ${states.join(", ")}`);
  });
});

test("no key appears in the DOM, the storage, the network traffic, the console or the page's globals, through a whole trade; the scan sees a key where one is planted", async () => {
  await withTrade("direct", async (t) => {
    const { page, keys, fake } = t;
    // The draws of the page are the keys: an independent implementation derives the public key of
    // each wallet from the bytes drawn for it.
    const draws = await drawn(page);
    assert.equal(draws.length, 2, "one draw for each wallet");
    assert.ok(bytesToHex(schnorr.getPublicKey(hexToBytes(draws[0]))) === keys.a, "the first draw is wallet A's key");
    assert.ok(bytesToHex(schnorr.getPublicKey(hexToBytes(draws[1]))) === keys.b, "the second draw is wallet B's key");

    // A whole trade: connect, build, sign with both wallets, submit; and the balance read.
    await prepare(t);
    await page.click("#wallet-b .wallet-refresh");
    assert.equal((await build(page)).state, "ok");
    await signWith(page, "a");
    await signWith(page, "b");
    assert.equal((await submitAndWait(page)).state, "ok");
    assert.equal(fake.accepted.length, 1);

    // Nothing holds either key, in any spelling, in any channel.
    const seen = await channels(t);
    for (const [name, haystack] of Object.entries(seen)) {
      for (const [who, secret] of [["A", draws[0]], ["B", draws[1]]] as const) {
        assert.ok(!leaks(haystack, secret), `wallet ${who}'s key appears in the ${name}`);
      }
    }
    // The public keys do appear (the DOM and the traffic carry them), so the scan reads real text.
    assert.ok(seen.dom.includes(keys.a) && seen.dom.includes(keys.b), "the scan reads the DOM");
    assert.ok(seen.network.includes("getUtxosByAddresses"), "and the traffic");

    // Controls: plant a stand-in key in each channel and see the scan find it there. The stand-in
    // is 32 random bytes drawn here and used for nothing else: a wallet's own key is never moved
    // out of the page, not even to prove the scan.
    const planted = randomBytes(32).toString("hex");
    assert.ok(!draws.includes(planted), "the stand-in is not a wallet's key");
    await page.evaluate(async (key) => {
      const note = document.createElement("p");
      note.textContent = key;
      document.body.append(note);
      localStorage.setItem("planted", key);
      console.log(key);
      (window as unknown as { plantedGlobal: string }).plantedGlobal = key;
      await fetch(`/planted?k=${key}`).catch(() => {});
      const socket = new WebSocket("ws://127.0.0.1:1");
      await new Promise<void>((done) => {
        socket.onopen = () => {
          socket.send(key);
          done();
        };
        socket.onerror = () => done();
      });
    }, planted);
    await page.waitForTimeout(200);
    const after = await channels(t);
    for (const name of ["dom", "storage", "network", "console", "globals"]) {
      assert.ok(leaks(after[name], planted), `the scan finds a planted key in the ${name}`);
    }
    assert.ok(!leaks(after.dom, draws[0]) && !leaks(after.network, draws[0]), "and not wallet A's key, which was not planted");
    assert.ok(!leaks(after.dom, draws[1]) && !leaks(after.network, draws[1]), "and not the other wallet's key, which was not planted");
    await page.evaluate(() => localStorage.clear());
  });
});

test("the page reads and writes nothing of a key to a node: every frame sent to it is a request the page names", async () => {
  await withTrade("direct", async (t) => {
    const { page, s } = t;
    await prepare(t);
    assert.equal((await build(page)).state, "ok");
    await signWith(page, "a");
    await signWith(page, "b");
    assert.equal((await submitAndWait(page)).state, "ok");
    const allowed = new Set(["getServerInfo", "getUtxosByAddresses", "getBlockDagInfo", "submitTransaction"]);
    const methods = s.sent.map((m) => (JSON.parse(m.text) as { method: string }).method);
    assert.ok(methods.every((m) => allowed.has(m)), methods.join(", "));
    assert.deepEqual(methods.filter((m) => m === "submitTransaction"), ["submitTransaction"]);
    // The connection check is a connection, not a trade: the node is asked who it is before anything.
    assert.equal(methods[0], "getServerInfo");
  });
});
