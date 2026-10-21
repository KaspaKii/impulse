// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Scaffolding for the browser tests of the wallets, settle, refund and the decoder: a page of the
// demo with an offline node behind a typed URL (crates/impulse-wasm/npm/test/fakenode.ts, reached
// through Playwright's WebSocket routing), two wallets made in the page, and the steps a person
// takes. Nothing here is page or SDK logic: the expectations come from the fixtures (world.ts) and
// the addresses the page shows for the keys.
import { after, before } from "node:test";
import assert from "node:assert/strict";
import type { Browser, Page } from "playwright-core";
import { FakeNode, type FakeUtxo } from "../../crates/impulse-wasm/npm/test/fakenode.ts";
import { DROP, HANGUP, launch, nodeSdk, open, type NodeHandler, type Session } from "./harness.ts";
export { DROP, HANGUP };
import {
  ASSET_ARTIFACT,
  KAS_CASH,
  NOW,
  addressFor,
  directUtxos,
  termsFor,
  vaultUtxos,
  type Mode,
  type WorldSdk,
} from "./world.ts";

// Not kaspad's default port (18210 is the TN10 wRPC JSON port, where a real node may be listening on
// this machine): every socket of the tests is intercepted, and a failure of the interception would
// reach a closed port, not a node.
export const NODE_URL = "ws://127.0.0.1:1";
/** The URL as the browser writes it. */
export const NODE_HREF = new URL(NODE_URL).href;

let browser: Browser;
before(async () => {
  browser = await launch();
});
after(async () => {
  await browser.close();
});

/** The SDK of demo/dist in Node, with the members the tests use. */
export type TestSdk = WorldSdk & Record<string, any>;
export const sdkOf = async () => (await nodeSdk()) as unknown as TestSdk;

/** Records the bytes of every crypto.getRandomValues call of the page, as hex, in window.__drawn. */
export function recordRandomness(): void {
  const w = window as unknown as { __drawn: string[] };
  w.__drawn = [];
  const real = crypto.getRandomValues.bind(crypto);
  Object.defineProperty(crypto, "getRandomValues", {
    configurable: true,
    writable: true,
    value: (array: ArrayBufferView) => {
      const out = real(array as never) as unknown;
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      w.__drawn.push(Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""));
      return out;
    },
  });
}

/**
 * Wraps the page's WebSocket class so that a test can hold back the open of a socket: while
 * window.__holdOpen is true, a socket made then reports "connecting" and its open event waits in
 * window.__held until the test releases it. Everything else passes through.
 */
export function holdableSockets(): void {
  const w = window as unknown as { __holdOpen: boolean; __held: (() => void)[]; WebSocket: unknown };
  const Base = window.WebSocket;
  w.__holdOpen = false;
  w.__held = [];
  class Held {
    #inner: WebSocket;
    #opened = false;
    onopen: ((e: Event) => void) | null = null;
    onerror: ((e: Event) => void) | null = null;
    onclose: ((e: Event) => void) | null = null;
    onmessage: ((e: MessageEvent) => void) | null = null;
    constructor(url: string) {
      this.#inner = new Base(url);
      const hold = w.__holdOpen;
      this.#inner.onopen = (e) => {
        const go = () => {
          this.#opened = true;
          this.onopen?.(e);
        };
        if (hold) w.__held.push(go);
        else go();
      };
      this.#inner.onerror = (e) => this.onerror?.(e);
      this.#inner.onclose = (e) => this.onclose?.(e);
      this.#inner.onmessage = (e) => this.onmessage?.(e);
    }
    get readyState() {
      const r = this.#inner.readyState;
      return r === 1 && !this.#opened ? 0 : r;
    }
    get url() {
      return this.#inner.url;
    }
    send(text: string) {
      this.#inner.send(text);
    }
    close() {
      this.#inner.close();
    }
  }
  w.WebSocket = Held;
}

/** What a test of a trade holds: the page, the node, the wallets' keys, the terms. */
export interface Trade {
  s: Session;
  page: Page;
  sdk: TestSdk;
  fake: FakeNode;
  /** Wallet A is the seller and wallet B the buyer. */
  keys: { a: string; b: string };
  addresses: { a: string; b: string };
  terms: Record<string, any>;
  /** Replace `current` to change what the node answers (a forged reply, an outage). */
  handler: { current: NodeHandler };
}

export const text = (page: Page, selector: string) => page.locator(selector).first().textContent();

const ROLE_WORDS = { seller: "the seller", buyer: "the buyer", authority: "the authority", other: "no party of the terms" };
/** The signature column of an unsigned input: the key and whose it is in the terms. */
export const needs = (key: string, role: keyof typeof ROLE_WORDS) => `needs ${key} (${ROLE_WORDS[role]})`;

/**
 * Opens the trade page with a node at NODE_URL, makes both wallets, and builds the terms of `mode`
 * between their keys. `seed` says what the node holds: the UTXOs of the trade (the default), or
 * nothing.
 */
export async function withTrade(
  mode: Mode,
  f: (t: Trade) => Promise<void>,
  options: {
    seed?: "funded" | "none";
    /** Other terms between the wallets' keys than the default ones of `mode`. */
    terms?: (sdk: TestSdk, keys: { a: string; b: string }) => Record<string, any>;
    /** The UTXOs the node holds, after the trade's own, changed (a vault funded below its amount). */
    utxos?: (utxos: FakeUtxo[]) => FakeUtxo[];
    /** The network of the node, the page's switch and the default terms; testnet if omitted. */
    network?: "mainnet" | "testnet";
    /** Where the node's pages of the chain end (see FakeNode.batchSize). */
    batchSize?: number;
    /** Lets the test hold back a socket's open (`holdableSockets`). */
    holdOpen?: boolean;
  } = {},
): Promise<void> {
  const sdk = await sdkOf();
  const network = options.network ?? "testnet";
  const fake = new FakeNode(sdk as never, addressFor(network), network);
  fake.networkId = network === "mainnet" ? "mainnet" : "testnet-10";
  if (options.batchSize !== undefined) fake.batchSize = options.batchSize;
  fake.virtualDaa = NOW;
  const handler = { current: ((t: string) => fake.handle(t)) as NodeHandler };
  const init = options.holdOpen ? [recordRandomness, holdableSockets] : recordRandomness;
  const s = await open(browser, "index.html", {}, init, { [NODE_URL]: (t) => handler.current(t) });
  try {
    const { page } = s;
    // The page's switch first: a wallet shows its address on the network the page is on.
    if (network === "mainnet") await page.check("#mainnet-switch");
    await page.click("#wallet-a .wallet-generate");
    await page.click("#wallet-b .wallet-generate");
    const keys = { a: (await text(page, "#wallet-a .wallet-key")) ?? "", b: (await text(page, "#wallet-b .wallet-key")) ?? "" };
    assert.match(keys.a, /^[0-9a-f]{64}$/);
    assert.match(keys.b, /^[0-9a-f]{64}$/);
    const addresses = {
      a: (await text(page, "#wallet-a .wallet-address")) ?? "",
      b: (await text(page, "#wallet-b .wallet-address")) ?? "",
    };
    const terms: Record<string, any> = options.terms ? options.terms(sdk, keys) : termsFor(sdk, mode, keys.a, keys.b, network);
    if (options.seed !== "none") {
      const kcc20Cash = (terms.cash_leg as { kind: string }).kind === "kcc20";
      const seeded = mode === "direct" ? directUtxos(sdk, keys.a, keys.b, kcc20Cash) : vaultUtxos(sdk, terms, keys.b);
      for (const u of options.utxos ? options.utxos(seeded) : seeded) fake.add(u);
    }
    await f({ s, page, sdk, fake, keys, addresses, terms, handler });
  } finally {
    await s.close();
  }
}

export interface Status {
  state: string;
  code: string;
  text: string;
}

const statusOf = async (page: Page, id: string): Promise<Status> => ({
  state: (await page.getAttribute(id, "data-state")) ?? "",
  code: (await page.getAttribute(id, "data-code")) ?? "",
  text: (await text(page, id)) ?? "",
});

/** Connects the page to the node at `url` and waits for its answer. */
export async function connect(page: Page, url = NODE_URL): Promise<Status> {
  await page.fill("#node-url", url);
  await page.click("#node-connect");
  await page.waitForFunction(() => {
    const state = document.querySelector("#node-status")?.getAttribute("data-state");
    return state === "connected" || state === "error";
  });
  return statusOf(page, "#node-status");
}

/**
 * The page up to the point where it offers to build: connected, the user the buyer with wallet B's
 * key (or the seller with wallet A's), the terms loaded, the creation score read from the node, a
 * value declared, the asset artifact pasted and wallet B chosen to pay the fee.
 */
export async function prepare(
  t: Trade,
  who: "buyer" | "seller" = "buyer",
  pins: { receive?: string; refund?: string } = {},
  more: {
    /** The pins of the other party, for a wallet of the page that is the other party. */
    other?: { receive?: string; refund?: string };
    /** Where the fee wallet's change goes. */
    change?: string;
    /**
     * What the role check is expected to say once the terms are loaded: "ok", or the code of the
     * refusal a test is after (nothing is then offered to build, and prepare stops there).
     */
    expect?: string;
    /** The cash token's artifact, for terms whose cash leg is a KCC-20 token. */
    cash?: string;
  } = {},
): Promise<void> {
  const { page } = t;
  assert.equal((await connect(page)).state, "connected");
  await page.selectOption("#role", { value: who });
  await page.click(who === "buyer" ? "#wallet-b .wallet-use-me" : "#wallet-a .wallet-use-me");
  // The pins of a user whose destination is a custodian's, given before the terms load.
  if (pins.receive !== undefined || pins.refund !== undefined) {
    if (!(await page.isVisible("#pin-receive"))) await page.click("#you details > summary");
    if (pins.receive !== undefined) await page.fill("#pin-receive", pins.receive);
    if (pins.refund !== undefined) await page.fill("#pin-refund", pins.refund);
  }
  const other = more.other;
  if (other !== undefined) {
    await page.evaluate(() => document.querySelectorAll("#you details").forEach((d) => ((d as HTMLDetailsElement).open = true)));
    if (other.receive !== undefined) await page.fill("#pin-other-receive", other.receive);
    if (other.refund !== undefined) await page.fill("#pin-other-refund", other.refund);
  }
  await page.fill("#terms-json", JSON.stringify(t.terms));
  await page.click("#load-json");
  await page.click("#read-daa");
  await page.fill("#kas-equivalent", KAS_CASH.toString());
  const expect = more.expect ?? "ok";
  await page.waitForSelector(expect === "ok" ? "#status[data-state='ok']" : `#status[data-state='refused'][data-code='${expect}']`);
  // A refused role check offers nothing to build.
  if (expect !== "ok") return;
  await page.fill("#asset-artifact", ASSET_ARTIFACT);
  await page.selectOption("#fee-payer", { value: "b" });
  if (more.change !== undefined) await page.fill("#change-address", more.change);
  if (more.cash !== undefined) await page.fill("#cash-artifact", more.cash);
}

export const actionStatus = (page: Page) => statusOf(page, "#action-status");

/** Clicks a build button and waits until the action leaves "working". */
export async function build(
  page: Page,
  which: "#build-settle" | "#build-refund" | "#build-fund" = "#build-settle",
): Promise<Status> {
  await page.click(which);
  await page.waitForFunction(() => {
    const state = document.querySelector("#action-status")?.getAttribute("data-state");
    return state === "ok" || state === "refused" || state === "stale";
  });
  return actionStatus(page);
}

export interface Row {
  index: string;
  amount: string;
  address: string;
  what: string;
  covenant: string;
  signer: string | null;
  signed: string | null;
  /** "true" on an output that pays a key held only in the page. */
  held: string | null;
}

export async function rows(page: Page, table: "#review-inputs-body" | "#review-outputs-body"): Promise<Row[]> {
  return page.locator(`${table} tr`).evaluateAll((trs) =>
    trs.map((tr) => ({
      index: tr.querySelector("td.index")?.textContent ?? "",
      amount: tr.querySelector("td.amount")?.textContent ?? "",
      address: tr.querySelector("td.address")?.textContent ?? "",
      what: tr.querySelector("td.what")?.textContent ?? "",
      covenant: tr.querySelector("td.covenant")?.textContent ?? "",
      signer: tr.querySelector("td.signer")?.textContent ?? null,
      signed: (tr as HTMLElement).dataset.signed ?? null,
      held: (tr as HTMLElement).dataset.held ?? null,
    })),
  );
}

export const fact = (page: Page, field: string) => text(page, `#review-facts [data-field="${field}"]`);

export const kasText = (sompi: bigint) =>
  `${sompi / 100_000_000n}.${(sompi % 100_000_000n).toString().padStart(8, "0")} KAS (${sompi} sompi)`;

/** Clicks the sign button of wallet `name` and returns the action status. */
export async function signWith(page: Page, name: "a" | "b"): Promise<Status> {
  await page.click(`#sign-buttons button[data-wallet="${name}"]`);
  return actionStatus(page);
}

/** The frames the page sent to the node, as parsed requests. */
export function frames(s: Session): { id: number; method: string; params: any }[] {
  return s.sent.map((m) => JSON.parse(m.text));
}

/** Refund options: the leg, who signs, and whether the token goes home. */
export async function chooseRefund(
  page: Page,
  leg: 0 | 1,
  signer: "depositor" | "counterparty" | "authority",
  withToken = true,
): Promise<void> {
  await page.selectOption("#refund-leg", { value: String(leg) });
  await page.selectOption("#refund-signer", { value: signer });
  await page.setChecked("#refund-token", withToken);
}

/** Clicks submit and waits for the page's answer. */
export async function submitAndWait(page: Page): Promise<Status> {
  await page.click("#submit");
  await page.waitForFunction(() => {
    const state = document.querySelector("#submit-status")?.getAttribute("data-state");
    return state === "ok" || state === "refused" || state === "wait";
  });
  return statusOf(page, "#submit-status");
}

/** The decoder page, opened in the session's browser context. */
export async function openDecoder(t: Trade, hash = ""): Promise<Page> {
  const page = await t.s.context.newPage();
  page.on("pageerror", (e) => t.s.errors.push(e.message));
  await page.goto(`${t.s.site.origin}/decoder.html${hash}`);
  await page.waitForSelector("#decoder-status[data-state='idle'], #decoder-status[data-state='error']");
  return page;
}

export async function decode(
  page: Page,
  fields: { url?: string; network?: "testnet" | "mainnet"; txid?: string; from?: string },
): Promise<Status> {
  if (fields.network !== undefined) await page.selectOption("#decoder-network", { value: fields.network });
  await page.fill("#node-url", fields.url ?? NODE_URL);
  if (fields.txid !== undefined) await page.fill("#txid", fields.txid);
  if (fields.from !== undefined) await page.fill("#from-block", fields.from);
  await page.click("#decode");
  await page.waitForFunction(() => {
    const state = document.querySelector("#decoder-status")?.getAttribute("data-state");
    return state === "ok" || state === "refused";
  });
  return statusOf(page, "#decoder-status");
}

export const hexOf = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

/** Polls `condition` until it holds, for a test that waits on something the page does on its own. */
export async function until(condition: () => boolean, what: string, ms = 5_000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((done) => setTimeout(done, 10));
  }
}

/** How many frames of `method` the page has sent to the node. */
export const sentCount = (s: Session, method: string) => frames(s).filter((f) => f.method === method).length;

// The scan for a key in every channel of the page, through a whole trade of each kind.

export async function channelsOf(t: Trade): Promise<string> {
  const { page, s } = t;
  const inPage = await page.evaluate(async () => {
    const parts: string[] = [document.documentElement.outerHTML, location.href];
    for (const el of document.querySelectorAll("input, textarea, select")) parts.push((el as HTMLInputElement).value);
    for (const el of document.querySelectorAll("*")) for (const a of el.getAttributeNames()) parts.push(el.getAttribute(a) ?? "");
    parts.push(JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage }), document.cookie);
    parts.push(JSON.stringify((await indexedDB.databases?.()) ?? []), JSON.stringify(await caches.keys()));
    for (const key of Object.getOwnPropertyNames(window)) {
      if (key.startsWith("__")) continue;
      try {
        const value = (window as unknown as Record<string, unknown>)[key];
        if (typeof value === "string" || typeof value === "number") parts.push(`${key}=${value}`);
      } catch {
        // a getter that throws holds nothing
      }
    }
    return parts.join("\n");
  });
  return [
    inPage,
    ...s.requests.map((r) => `${r.method} ${r.url}\n${JSON.stringify(r.headers)}\n${r.body ?? ""}`),
    ...s.sent.map((m) => `${m.url}\n${m.text}`),
    ...s.contacted,
    ...s.console,
  ].join("\n");
}

export const drawnKeys = async (page: Page): Promise<string[]> =>
  (await page.evaluate(() => (window as unknown as { __drawn: string[] }).__drawn)).filter((h) => h.length === 64);
