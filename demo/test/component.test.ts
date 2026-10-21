// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The review renderer on its own, in a real browser, fed a review the SDK would not make. Every
// input and output of a document the builders make has an address (a token sits at a
// pay-to-script-hash address, and the terms admit only standard scripts), so the fallback to the
// script text cannot be reached through a trade. The page module (`actions.js`) is the real one,
// served from demo/dist; only its SDK, node and wallets are stand-ins, and the page's own script is
// swapped for this one so that the real application is not mounted beside it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { Browser } from "playwright-core";
import { dist, launch, open } from "./harness.ts";

let browser: Browser;
before(async () => {
  browser = await launch();
});
after(async () => {
  await browser.close();
});

const COMPONENT = `
import { mountActions } from "/actions.js";
const entry = (index, extra) => ({
  index, amount: "1", amount_kas: "0.00000001", script_public_key: { version: 1, script: "00ff" },
  address: null, covenant_id: null, what: "something", ...extra,
});
const review = {
  title: "A title", network: "testnet", terms_hash: "ab".repeat(32), nonce: "5", fee: "7", fee_kas: "0.00000007",
  min_relay_fee: "3", payer_cost_text: "none", lock_time: "0", final_from_daa: null, current_daa: "9",
  submit_ready: true, wait: null, masses: { compute: "1", transient: "2", storage: "3" }, notes: [],
  inputs: [entry(0, { signer: null, signer_role: null, signed: false })],
  outputs: [entry(0, { held_key: false }), entry(1, { address: "kaspatest:q", held_key: true })],
};
const wallet = { publicKey: () => "11".repeat(32), isWiped: () => false };
const ipst = { review: () => review, slots: () => [], toJson: () => "{}", isComplete: () => false, free() {} };
const terms = { settleAddresses: () => ["kaspatest:q"], settleFromReply: () => ipst, free() {} };
const ctx = {
  wallets: { names: ["a"], get: () => wallet, heldKeys: () => [] },
  node: { connected: true, serverInfo: async () => ({ virtual_daa_score: "9" }), call: async () => ({ text: "{}" }) },
  currentTerms: () => terms, termsMode: () => "vault", valueDeclaration: () => ({}), mainnet: () => false,
};
document.getElementById("actions").hidden = false;
mountActions(document, window, {}, ctx);
document.getElementById("build-settle").click();
setTimeout(() => { window.__done = true; }, 200);
`;

test("an input or output without an address is shown by its script, beside an output with an address", async () => {
  const index = readFileSync(new URL("index.html", dist), "utf8").replace(
    '<script type="module" src="main.js"></script>',
    '<script type="module" src="component.js"></script>',
  );
  assert.ok(index.includes('src="component.js"'), "the page's own script is swapped for the component's");
  const s = await open(browser, "component.html", { "/component.html": index, "/component.js": COMPONENT });
  try {
    await s.page.waitForFunction(() => (window as unknown as { __done?: boolean }).__done === true);
    assert.deepEqual(s.errors, []);
    const cells = (selector: string) => s.page.locator(selector).allTextContents();
    assert.deepEqual(await cells("#review-inputs-body td.address"), ["script version 1: 00ff"]);
    assert.deepEqual(await cells("#review-outputs-body td.address"), ["script version 1: 00ff", "kaspatest:q"]);
    // The same renderer marks the output that pays a key held only in the page, and not the other.
    assert.deepEqual(await cells("#review-outputs-body td.what"), ["something", "something [pays a key that lives only in this page]"]);
    assert.equal(await s.page.locator('#review-outputs-body tr[data-held="true"]').count(), 1);
    // And shows the facts it is given, label by label.
    assert.equal(await s.page.locator('#review-facts [data-field="terms-hash"]').textContent(), "ab".repeat(32));
    assert.equal(await s.page.locator('#review-facts [data-field="nonce"]').textContent(), "5");
    assert.equal(await s.page.locator("#review-title").textContent(), "A title");
  } finally {
    await s.close();
  }
});
