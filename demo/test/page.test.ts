// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The trade page in a real browser (headless Chrome), built from demo/dist: the page and the SDK
// bundled with it run under their Content-Security-Policy; the addresses, hashes and funding URIs
// they show equal what the SDK of demo/dist computes in Node for the same terms; the QR code on the
// page decodes to the URI; the value cap and the mainnet switch refuse. Every refusal test sits
// beside an accepted control. The golden vectors name a synthetic token that is no kcc20.sil build,
// which no funding accepts (SDK_TEMPLATE_UNPINNED), so the page's examples are the vectors with
// their tokens pinned (demo/pin-examples.mjs); the vectors as committed are refused by the page,
// and the SDK's own tests match the committed vault files byte for byte. The expectations come from
// the example files, from tests/vectors, and from the SDK of demo/dist run in Node.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import * as jsqrModule from "jsqr";
import type { Browser, Page } from "playwright-core";
import {
  committedVector,
  committedVectorText,
  committedVectors,
  dist,
  firstPinnedBuild,
  launch,
  nodeSdk,
  open,
  termsVector,
  termsVectors,
  vaultVector,
  vectorText,
  type Override,
  type Session,
} from "./harness.ts";
import { partyFor, type PageParty, type PartyTerms } from "./party.ts";

const jsQR = ((jsqrModule as unknown as { default?: unknown }).default ?? jsqrModule) as (
  data: Uint8ClampedArray,
  width: number,
  height: number,
) => { data: string } | null;

let browser: Browser;
before(async () => {
  browser = await launch();
});
after(async () => {
  await browser.close();
});

/** Runs `f` on a fresh page of the demo and closes it. */
async function withPage<T>(
  f: (s: Session) => Promise<T>,
  path = "index.html",
  overrides: Record<string, Override> = {},
  init?: () => void,
): Promise<T> {
  const s = await open(browser, path, overrides, init);
  try {
    return await f(s);
  } finally {
    await s.close();
  }
}

const exampleName = (prefix: string) => termsVector(prefix).name;
const distText = (name: string) => readFileSync(new URL(name, dist), "utf8");

/** `text` with the one place `from` stands replaced; the edit must apply exactly once. */
function edit(text: string, from: string, to: string): string {
  const parts = text.split(from);
  assert.equal(parts.length, 2, `the edit target occurs exactly once: ${from}`);
  return parts.join(to);
}

/** Types who the user is into the page: role, public key, and the pins ("" for none). */
async function iAm(page: Page, party: PageParty): Promise<void> {
  // A field already holding the value is left alone: typing it again would make the page derive
  // again, and a test of a refusal that leaves the form untouched must see the form untouched.
  const set = async (selector: string, value: string) => {
    if ((await page.inputValue(selector)) !== value) await page.fill(selector, value);
  };
  if ((await page.inputValue("#role")) !== party.role) await page.selectOption("#role", { value: party.role });
  await set("#my-key", party.key);
  // The pins sit in a closed section; a user opens it by clicking its summary.
  if (!(await page.isVisible("#pin-receive"))) await page.click("#you details > summary");
  await set("#pin-receive", party.receive);
  await set("#pin-refund", party.refund);
}

/** The party of `role` for the terms a vector holds (a vector as testnet terms differs only in network). */
const partyOf = (prefix: string, role: "buyer" | "seller" = "buyer") =>
  partyFor(role, termsVector(prefix).terms as unknown as PartyTerms);

/**
 * Loads a golden vector through the page's own control and waits for the page to answer. The
 * user is first made the buyer (or `role`) of that vector, so that loading the terms is the last
 * thing the page answers.
 */
async function loadExample(page: Page, prefix: string, role: "buyer" | "seller" = "buyer"): Promise<void> {
  const t = termsVector(prefix).terms;
  await iAm(page, partyOf(prefix, role));
  await page.selectOption("#example", { value: `${exampleName(prefix)}.json` });
  await page.click("#load-example");
  // The page fetches the file, fills the form and answers in one step; wait for the form to
  // hold this vector's nonce and trade reference.
  await page.waitForFunction(
    ([nonce, ref]) =>
      (document.querySelector('[data-path="nonce"]') as HTMLInputElement).value === nonce &&
      (document.querySelector('[data-path="trade_ref"]') as HTMLInputElement).value === ref,
    [String(t.nonce), String(t.trade_ref)],
  );
}

/**
 * Pastes terms text and loads it through the page's own control. When the text holds terms, the
 * user is first made the buyer of those terms (or `as`), with the pins their destinations call
 * for; text that is not terms leaves the role fields as they were.
 */
async function loadText(page: Page, text: string, as?: PageParty): Promise<void> {
  let party = as;
  if (party === undefined) {
    try {
      const doc = JSON.parse(text) as Record<string, any>;
      const terms = (doc.terms ?? doc) as PartyTerms;
      if (typeof terms.buyer_key === "string") party = partyFor("buyer", terms);
    } catch {
      // Not JSON: the page refuses it.
    }
  }
  if (party !== undefined) await iAm(page, party);
  await page.fill("#terms-json", text);
  await page.click("#load-json");
}

/** The two figures the user types: the KAS value of the larger leg, and the creation DAA score. */
async function declare(page: Page, kasEquivalent = "100000000", creationDaa = "400000000"): Promise<void> {
  await page.fill("#creation-daa", creationDaa);
  await page.fill("#kas-equivalent", kasEquivalent);
}

async function outcome(page: Page): Promise<{ state: string; code: string }> {
  return {
    state: (await page.getAttribute("#status", "data-state")) ?? "",
    code: (await page.getAttribute("#status", "data-code")) ?? "",
  };
}

/**
 * True when the page shows no summary, no destination, no leg, no address, no URI, no QR and no
 * decoded terms.
 */
async function showsNothing(page: Page): Promise<boolean> {
  const counts = await Promise.all(
    ["#summary > *", "#destination-list > *", "#legs > *", ".vault-address", ".funding-uri", ".token-owner", "svg.qr"].map((q) =>
      page.locator(q).count(),
    ),
  );
  return (
    counts.every((n) => n === 0) &&
    (await page.locator("#decoded").isHidden()) &&
    (await page.locator("#destinations").isHidden()) &&
    ((await text(page, "#terms-decoded")) ?? "") === ""
  );
}

const text = (page: Page, selector: string) => page.locator(selector).first().textContent();

/** The page's own answer for vector 08, which holds 1 KAS in its cash leg (within the cap). */
async function vector08(page: Page, kasEquivalent = "100000000"): Promise<void> {
  await loadExample(page, "08");
  await declare(page, kasEquivalent);
}

/** The terms of a vector as the page's network accepts them: testnet. */
function asTestnet(prefix: string): Record<string, any> {
  return { ...termsVector(prefix).terms, network: "testnet" };
}

// Static content.

test("dist holds exactly the pages, the bundled SDK, the licence and the eleven vectors", () => {
  const files: string[] = [];
  const walk = (dir: URL, prefix: string) => {
    for (const name of readdirSync(dir)) {
      const url = new URL(name, dir);
      if (statSync(url).isDirectory()) walk(new URL(`${name}/`, dir), `${prefix}${name}/`);
      else files.push(`${prefix}${name}`);
    }
  };
  walk(dist, "");
  const vectors = termsVectors.map((v) => `examples/${v.name}.json`);
  assert.deepEqual(
    files.sort(),
    [
      "LICENSE",
      "NOTICE",
      "actions.js",
      "app.js",
      "config.js",
      "decoder.html",
      "decoder.js",
      "dom.js",
      "examples/index.json",
      "favicon.svg",
      "index.html",
      "impulse-wordmark.svg",
      "main.js",
      "node.js",
      "sdk/index.js",
      "sdk/pkg/impulse_wasm.js",
      "sdk/pkg/impulse_wasm_bg.wasm",
      "style.css",
      "wallets.js",
      ...vectors,
    ].sort(),
  );
  assert.equal(vectors.length, 11);
  assert.deepEqual(JSON.parse(readFileSync(new URL("examples/index.json", dist), "utf8")), termsVectors.map((v) => `${v.name}.json`));
});

test("the page's examples are the golden vectors with only the token of each KCC-20 leg replaced by the first pinned build, and each is a consistent terms file", async () => {
  const pin = firstPinnedBuild();
  const sdk = await nodeSdk();
  assert.equal(termsVectors.length, 11);
  for (const committed of committedVectors) {
    const example = termsVectors.find((e) => e.name === committed.name);
    assert.ok(example, committed.name);
    // The example is the vector, and nothing else but the template triple of each KCC-20 leg.
    const expected = structuredClone(committed.terms) as Record<string, any>;
    let tokens = 0;
    for (const leg of [expected.asset_leg, expected.cash_leg]) {
      if (leg.kind === "kcc20") {
        tokens += 1;
        assert.equal(leg.template_hash.slice(0, 8), "a227fc3a", `${committed.name}: the vector's synthetic token`);
        [leg.template_hash, leg.template_prefix_len, leg.template_suffix_len] = [pin.hash, pin.prefix, pin.suffix];
      }
    }
    assert.ok(tokens >= 1, `${committed.name}: the asset leg is always a token`);
    assert.deepEqual(example.terms, expected, committed.name);
    // A different trade, with the hash and the canonical bytes of its own, which the SDK reads as consistent.
    assert.notEqual(example.terms_hash, committed.terms_hash, committed.name);
    assert.notEqual(example.canonical, committed.canonical, committed.name);
    const text = readFileSync(new URL(`examples/${example.name}.json`, dist), "utf8");
    assert.notEqual(text, committedVectorText(committed.name.slice(0, 2)), "not the committed file");
    const read = (sdk.Terms as unknown as { fromFileText(t: string): { termsHash(): Uint8Array } }).fromFileText(text);
    assert.equal(Buffer.from(read.termsHash()).toString("hex"), example.terms_hash, committed.name);
    assert.ok(
      example.description?.startsWith(`${(committed as { description?: string }).description} Page example: `) === true,
      `${committed.name}: the description says what was changed`,
    );
  }
});

test("the page's own files name no foreign host, hold no key code and fetch only the vectors", () => {
  const scripts: Record<string, string> = { "index.html": "main.js", "decoder.html": "decoder.js" };
  for (const name of [
    "index.html",
    "decoder.html",
    "main.js",
    "app.js",
    "dom.js",
    "node.js",
    "wallets.js",
    "actions.js",
    "decoder.js",
    "config.js",
    "style.css",
    "favicon.svg",
    "impulse-wordmark.svg",
  ]) {
    const source = readFileSync(new URL(name, dist), "utf8");
    // The SVG namespace is an identifier, not a request; it is the only URL-shaped text allowed.
    const urls = (source.match(/https?:\/\/[^\s"'`)]*/g) ?? []).filter((u) => u !== "http://www.w3.org/2000/svg");
    assert.deepEqual(urls, [], `${name}: URLs`);
    const own = scripts[name];
    if (own !== undefined) {
      const srcs = [...source.matchAll(/<script[^>]*\ssrc="([^"]*)"/g)].map((m) => m[1]);
      assert.deepEqual(srcs, [own], `${name}: scripts`);
    }
    assert.doesNotMatch(source, /<script(?![^>]*\ssrc=)/, `${name}: an inline script`);
    assert.doesNotMatch(source, /\b(XMLHttpRequest|sendBeacon|localStorage|sessionStorage|indexedDB|document\.cookie|importScripts)\b/, name);
    assert.doesNotMatch(source, /\beval\s*\(|new\s+Function\b/, `${name}: eval`);
    // A socket is opened in one place, node.js, from the class the page hands it; everything else
    // names the class only to pass it on.
    const sockets = source.match(/new\s+(?:this\.#)?WebSocket\b/g) ?? [];
    assert.deepEqual(sockets, name === "node.js" ? ["new this.#WebSocket"] : [], `${name}: new WebSocket`);
    assert.doesNotMatch(
      source,
      /\b(generateKey|importKey|exportKey|deriveKey|deriveBits|subtle|privateKey|secretKey|mnemonic|seed phrase|secp256k1)\b/i,
      `${name}: key handling`,
    );
    for (const call of source.matchAll(/\bfetch\(([^)]*)\)/g)) {
      assert.match(call[1], /^`?"?examples\//, `${name}: fetch(${call[1]})`);
    }
    // Text from the SDK, a node or a file is only ever set as text.
    assert.doesNotMatch(source, /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/, `${name}: markup from text`);
    // The page signs through the SDK: no curve library of its own (@noble/curves is a dev
    // dependency of the SDK's tests, and of these tests).
    assert.doesNotMatch(source, /noble|import\s+[^;]*from\s+"(?!\.\/)/i, `${name}: an import of a package`);
  }
  const app = readFileSync(new URL("app.js", dist), "utf8");
  // The page's own draw of randomness is the nonce button; a wallet's key is drawn inside the SDK,
  // and no other file asks the browser for randomness.
  assert.equal((app.match(/getRandomValues/g) ?? []).length, 1);
  assert.match(app, /new-nonce[\s\S]*getRandomValues/);
  for (const name of ["main.js", "dom.js", "node.js", "wallets.js", "actions.js", "decoder.js"]) {
    assert.doesNotMatch(readFileSync(new URL(name, dist), "utf8"), /getRandomValues|Math\.random/, name);
  }
  // The page never lifts the cap.
  for (const name of ["app.js", "actions.js", "wallets.js"]) {
    assert.doesNotMatch(readFileSync(new URL(name, dist), "utf8"), /accept_the_risk/, name);
  }
  // A creation DAA score is marked as read from a node only while the field holds what the
  // connected node gave (see the browser tests of the mainnet switch).
  assert.match(app, /creation_daa_source:\s*fromNode \? "node" : "typed"/);
  assert.match(app, /const fromNode = state\.nodeDaa !== null && \$\("creation-daa"\)\.value === state\.nodeDaa;/);
  assert.equal((app.match(/state\.nodeDaa = /g) ?? []).length, 2, "set once from the node, cleared once");
});

// The policy of each page, to the character. A widened directive is a different security
// posture, so a change here is deliberate.
// Both pages carry the same policy. It lets a script open a WebSocket to a host over wss://, and
// over ws:// to localhost and 127.0.0.1 only (owner decision 2026-10-11; a host-source cannot name
// an IPv6 literal, so `[::1]` is out), because the node is the URL the user types; it names no node.
const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*; img-src 'self'; base-uri 'none'; form-action 'none'";
const CONNECT_SRC = "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*";
const CSP_TRADE = CSP;
const CSP_DECODER = CSP;

test("each page carries exactly its Content-Security-Policy and no referrer", () => {
  for (const [name, csp] of [
    ["index.html", CSP_TRADE],
    ["decoder.html", CSP_DECODER],
  ]) {
    const html = distText(name);
    const tags = [...html.matchAll(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/g)].map((m) => m[1]);
    assert.deepEqual(tags, [csp], name);
    assert.match(html, /<meta name="referrer" content="no-referrer">/, name);
  }
});

// The page under its Content-Security-Policy.

const PROBE = `try { eval("1 + 1"); window.__evalError = "none"; } catch (e) { window.__evalError = e.name; }
try { new Function("return 1"); window.__functionError = "none"; } catch (e) { window.__functionError = e.name; }
`;

test("the trade page runs the bundled SDK under its CSP: no foreign request, no violation, no eval", async () => {
  await withPage(async ({ page, site, external, errors }) => {
    assert.deepEqual(await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp), [], "no violation so far");
    assert.equal((await outcome(page)).state, "idle");
    // The wasm module ran in the browser from this origin: the SDK answers.
    await vector08(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.deepEqual(external, [], "no request to any other origin");
    assert.deepEqual(errors, [], "no console error");
    for (const needed of ["/sdk/index.js", "/sdk/pkg/impulse_wasm.js", "/sdk/pkg/impulse_wasm_bg.wasm", "/examples/index.json"]) {
      assert.ok(site.requests.includes(needed), needed);
    }
    assert.ok(site.requests.every((p) => !p.startsWith("//")), "no scheme-relative path");
    // Control that the policy is enforced by this browser: a script the policy allows (same
    // origin) tries eval and Function, and an inline script is refused outright. Evaluating
    // through the test driver would bypass the policy, so the probe is a file the server serves.
    await page.evaluate(
      () =>
        new Promise<void>((done) => {
          const inline = document.createElement("script");
          inline.textContent = "window.__ran = 1";
          document.head.append(inline);
          const probe = document.createElement("script");
          probe.src = "/probe.js";
          probe.onload = () => done();
          document.head.append(probe);
        }),
    );
    const attempts = await page.evaluate(() => {
      const w = window as unknown as { __ran?: number; __evalError?: string; __functionError?: string };
      return { ran: w.__ran ?? 0, evalError: w.__evalError, functionError: w.__functionError };
    });
    assert.deepEqual(attempts, { ran: 0, evalError: "EvalError", functionError: "EvalError" });
    const violations = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
    assert.ok(violations.length >= 3, `violations: ${violations.join("; ")}`);
    assert.ok(violations.every((v) => v.startsWith("script-src")), violations.join("; "));
  }, "index.html", { "/probe.js": PROBE });
});

// What a script the policy allows (same origin) still cannot do. Each attempt is made from such
// a script, so the policy is the only thing in the way. Beside each, the same attempt under a
// policy with that one directive widened gets through to the network: that control shows the
// test would see a widened policy, and that the block is the policy's.
interface Attempt {
  name: string;
  /** The directive the browser names in the violation. */
  directive: RegExp;
  /** What the probe script does. */
  body: string;
  /** The one edit of the page's policy that lets the attempt through. */
  widen: [string, string];
  /** Whether the attempt reached the network layer (or, for base, took effect). */
  reached: (s: Session) => Promise<boolean>;
}
const evil = "http://evil.invalid";
const ATTEMPTS: Attempt[] = [
  {
    name: "fetch",
    directive: /^connect-src/,
    body: `fetch("${evil}/fetch").catch(() => {});`,
    widen: ["connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src *"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/fetch`)),
  },
  {
    name: "websocket (plaintext, another host)",
    directive: /^connect-src/,
    body: `try { new WebSocket("ws://evil.invalid/socket"); } catch (e) {}`,
    widen: ["connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*", "connect-src *"],
    reached: async (s) => s.sockets.some((u) => u.startsWith("ws://evil.invalid/socket")),
  },
  {
    name: "image",
    directive: /^img-src/,
    body: `new Image().src = "${evil}/image.png";`,
    widen: ["img-src 'self'", "img-src *"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/image.png`)),
  },
  {
    name: "stylesheet",
    directive: /^style-src/,
    body: `const l = document.createElement("link"); l.rel = "stylesheet"; l.href = "${evil}/style.css"; document.head.append(l);`,
    widen: ["style-src 'self'", "style-src *"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/style.css`)),
  },
  {
    name: "script",
    directive: /^script-src/,
    body: `const s = document.createElement("script"); s.src = "${evil}/script.js"; document.head.append(s);`,
    widen: ["script-src 'self' 'wasm-unsafe-eval'", "script-src 'self' 'wasm-unsafe-eval' http:"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/script.js`)),
  },
  {
    name: "frame",
    directive: /^(frame-src|child-src|default-src)/,
    body: `const f = document.createElement("iframe"); f.src = "${evil}/frame.html"; document.body.append(f);`,
    widen: ["default-src 'none'", "default-src *"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/frame.html`)),
  },
  {
    name: "form",
    directive: /^form-action/,
    body: `const f = document.createElement("form"); f.method = "post"; f.action = "${evil}/form"; document.body.append(f); f.submit();`,
    widen: ["form-action 'none'", "form-action *"],
    reached: async (s) => s.external.some((u) => u.startsWith(`${evil}/form`)),
  },
  {
    name: "base",
    directive: /^base-uri/,
    body: `const b = document.createElement("base"); b.href = "${evil}/"; document.head.append(b);`,
    widen: ["base-uri 'none'", "base-uri *"],
    // A base element that took effect changes where every relative URL points.
    reached: async (s) => (await s.page.evaluate(() => document.baseURI)).startsWith(evil),
  },
];

/** Runs a same-origin probe script that makes `attempt`, and waits for the browser to settle. */
async function attemptFrom(
  attempt: Attempt,
  html: string,
): Promise<{ violations: string[]; reached: boolean; external: string[]; sockets: string[] }> {
  const path = `/probe-${attempt.name.replace(/\W+/g, "-")}.js`;
  return withPage(
    async (s) => {
      await s.page.evaluate(
        (src) =>
          new Promise<void>((done) => {
            const probe = document.createElement("script");
            probe.src = src;
            probe.onload = () => done();
            probe.onerror = () => done();
            document.head.append(probe);
          }),
        path,
      );
      await s.page.waitForTimeout(400);
      const violations = await s.page
        .evaluate(() => (window as unknown as { __csp: string[] }).__csp)
        .catch(() => [] as string[]); // a form that navigated away took its page with it
      return { violations, reached: await attempt.reached(s).catch(() => attempt.name === "form" && s.external.length > 0), external: s.external, sockets: s.sockets };
    },
    "index.html",
    { "/index.html": html, [path]: attempt.body },
  );
}

test("from a script the policy allows, no connection, load, frame, form or base reaches beyond the page; widening the one directive lets it through", async () => {
  const real = distText("index.html");
  assert.ok(real.includes(CSP_TRADE));
  for (const attempt of ATTEMPTS) {
    const blocked = await attemptFrom(attempt, real);
    assert.ok(
      blocked.violations.some((v) => attempt.directive.test(v) && v.includes("evil.invalid")),
      `${attempt.name}: a violation of ${attempt.directive} naming the host; got ${blocked.violations.join("; ")}`,
    );
    assert.equal(blocked.reached, false, `${attempt.name}: reached the network`);
    assert.deepEqual(blocked.external, [], `${attempt.name}: foreign requests`);
    assert.deepEqual(blocked.sockets, [], `${attempt.name}: sockets`);
    // The control: the same page with the one directive widened.
    const widened = await attemptFrom(attempt, edit(real, attempt.widen[0], attempt.widen[1]));
    assert.equal(widened.reached, true, `${attempt.name}: a widened policy lets it through, and the test sees it`);
    assert.equal(
      widened.violations.some((v) => attempt.directive.test(v) && v.includes("evil.invalid")),
      false,
      `${attempt.name}: no violation once widened`,
    );
  }
});

test("plaintext sockets: the policy lets a script reach localhost and 127.0.0.1, and not the IPv6 loopback literal", async () => {
  const real = distText("index.html");
  const socketTo = (host: string): Attempt => ({
    name: `socket-${host.replace(/\W+/g, "-")}`,
    directive: /^connect-src/,
    body: `try { new WebSocket("ws://${host}/socket"); } catch (e) {}`,
    widen: [CONNECT_SRC, "connect-src *"],
    reached: async (s) => s.sockets.some((u) => u.startsWith(`ws://${host}/socket`)),
  });
  // The controls: allowed by the policy as it is.
  for (const host of ["localhost:17110", "127.0.0.1:17110"]) {
    const allowed = await attemptFrom(socketTo(host), real);
    assert.equal(allowed.reached, true, `${host}: a socket is opened`);
    assert.deepEqual(allowed.violations, [], `${host}: no violation`);
  }
  // Refused by the policy: the IPv6 loopback literal, with and without a port (another plaintext
  // host is the "websocket (plaintext, another host)" attempt above); the same page with the
  // directive widened lets each through.
  for (const host of ["[::1]:17110", "[::1]"]) {
    const blocked = await attemptFrom(socketTo(host), real);
    assert.equal(blocked.reached, false, `${host}: reached the network`);
    assert.deepEqual(blocked.sockets, [], `${host}: sockets`);
    assert.ok(
      blocked.violations.some((v) => /^connect-src/.test(v) && v.includes("::1")),
      `${host}: a connect-src violation naming the host; got ${blocked.violations.join("; ")}`,
    );
    const widened = await attemptFrom(socketTo(host), edit(real, CONNECT_SRC, "connect-src *"));
    assert.equal(widened.reached, true, `${host}: a widened policy lets it through, and the test sees it`);
  }
});

test("the decoder page runs the bundled SDK under its CSP: no foreign request, no violation, no eval, no inline script", async () => {
  await withPage(
    async ({ page, site, external, errors }) => {
      await page.waitForSelector("#decoder-status[data-state='idle'], #decoder-status[data-state='error']");
      assert.equal(await page.getAttribute("#decoder-status", "data-state"), "idle", "the SDK started");
      assert.equal(await page.isDisabled("#decode"), false);
      assert.deepEqual(await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp), [], "no violation so far");
      assert.deepEqual(external, [], "no request to any other origin");
      assert.deepEqual(errors, [], "no console error");
      for (const needed of ["/decoder.js", "/node.js", "/dom.js", "/sdk/index.js", "/sdk/pkg/impulse_wasm_bg.wasm"]) {
        assert.ok(site.requests.includes(needed), needed);
      }
      // Control that the policy is enforced by this browser: an inline script is refused, and
      // eval and Function are refused to the script the policy allows.
      await page.evaluate(
        () =>
          new Promise<void>((done) => {
            const inline = document.createElement("script");
            inline.textContent = "window.__ran = 1";
            document.head.append(inline);
            const probe = document.createElement("script");
            probe.src = "/probe.js";
            probe.onload = () => done();
            document.head.append(probe);
          }),
      );
      const attempts = await page.evaluate(() => {
        const w = window as unknown as { __ran?: number; __evalError?: string; __functionError?: string };
        return { ran: w.__ran ?? 0, evalError: w.__evalError, functionError: w.__functionError };
      });
      assert.deepEqual(attempts, { ran: 0, evalError: "EvalError", functionError: "EvalError" });
      const violations = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
      assert.ok(violations.length >= 3, `violations: ${violations.join("; ")}`);
      assert.ok(violations.every((v) => v.startsWith("script-src")), violations.join("; "));
    },
    "decoder.html",
    { "/probe.js": PROBE },
  );
  // The same page with the policy widened to allow inline scripts runs the inline probe: the
  // block above is the policy's.
  const real = distText("decoder.html");
  assert.ok(real.includes(CSP_DECODER));
  await withPage(
    async ({ page }) => {
      await page.waitForSelector("#decoder-status[data-state='idle']");
      await page.evaluate(() => {
        const inline = document.createElement("script");
        inline.textContent = "window.__ran = 1";
        document.head.append(inline);
      });
      assert.equal(await page.evaluate(() => (window as unknown as { __ran?: number }).__ran ?? 0), 1);
    },
    "decoder.html",
    { "/decoder.html": edit(real, "script-src 'self' 'wasm-unsafe-eval'", "script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'") },
  );
});

// The vectors as committed are refused: their token is no kcc20.sil build.

/** A committed vector's terms with the network rewritten to testnet, so that the creation checks pass for the page. */
function committedAsTestnet(prefix: string): Record<string, any> {
  return { ...committedVector(prefix).terms, network: "testnet" };
}

test("the golden vectors as committed are refused by the page for their synthetic token and show nothing, each beside the page's example of the same vector, which is not refused for it", async () => {
  await withPage(async ({ page }) => {
    for (const v of committedVectors) {
      const prefix = v.name.slice(0, 2);
      const terms = committedAsTestnet(prefix);
      await loadText(page, JSON.stringify(terms), partyFor("buyer", terms as unknown as PartyTerms));
      await declare(page);
      assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_TEMPLATE_UNPINNED" }, `${v.name}: as committed`);
      assert.ok(await showsNothing(page), `${v.name}: no address, URI or QR is shown for it`);
      assert.match((await text(page, "#status")) ?? "", /is not a pinned kcc20\.sil build/);
      assert.equal(await page.isVisible("#actions"), false, `${v.name}: nothing to build`);
      // The example of the same vector: its token is pinned, so this refusal is not what it meets.
      const example = { ...termsVector(prefix).terms, network: "testnet" };
      await loadText(page, JSON.stringify(example), partyFor("buyer", example as unknown as PartyTerms));
      await declare(page);
      assert.notEqual((await outcome(page)).code, "SDK_TEMPLATE_UNPINNED", `${v.name}: the example`);
    }
    // And the one example within the cap is accepted outright.
    await vector08(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" });
  });
});

// The sentences that keep a buyer from funding too early, twice, or into a token the page does not fund.

test("the funding's safety sentences are on the page: the order of the legs, what the SDK refuses, the way out and its loss, and what has not been observed", async () => {
  await withPage(async ({ page }) => {
    const textOf = async (selector: string) => ((await page.locator(selector).textContent()) ?? "").replace(/\s+/g, " ");
    const fund = await textOf("#fund-options");
    for (const sentence of [
      "Only the buyer funds a KAS cash vault, with one output of exactly the cash amount.",
      "the page funds no token whose template is not a pinned kcc20.sil build (SDK_TEMPLATE_UNPINNED, no override)",
      "Fund it after the seller's asset leg has been accepted, not before.",
      "refuses to build the funding while the seller's asset leg is not listed (SDK_FUND_ASSET_NOT_FUNDED)",
      "when the cash vault already holds a deposit of exactly the cash amount (SDK_FUND_ALREADY_FUNDED)",
      "Until the trade settles, your only way to take the deposit back yourself is a refund signed with this wallet's key, from the expiry in earmarked mode:",
      "closing or reloading this page, or wiping the wallet, destroys that key, and the page asks before it wipes a wallet that funded a cash vault.",
      "The seller or the authority can also trigger that refund, and nothing makes them.",
      "After the funding is submitted, wait until the node lists the deposit before you build the settle;",
      "the page expects the node to list the UTXOs of accepted blocks, which has not been observed against a real node.",
      "A settle is refused at or after the expiry, so fund with time to spare: the review of the funding says how long the trade has left to settle.",
    ]) {
      assert.ok(fund.includes(sentence), `${sentence}\n${fund}`);
    }
    // The behaviour of the node is not stated as fact.
    assert.ok(!fund.includes("(it lists UTXOs of accepted blocks)"), "the node's behaviour is expected, not known");
    // The fee: the page's automatic fee is not the command line's.
    assert.equal(
      await textOf("#fee-note"),
      "Auto is the minimum relay fee of the transaction and a tenth more. The command line's automatic fee is the minimum itself, so the same transaction built on both sides needs the same fee typed on both.",
    );
    // The wallets: what asks before a wipe, and the warning at the foot.
    const wallets = await textOf("#wallet-panel");
    assert.ok(
      wallets.includes(
        "Pressing Wipe asks first when the last balance you read was above zero, and when the wallet funded a cash vault and this page has not seen that trade settled or refunded: the wallet's key is then the buyer's own way to refund the deposit, and a wipe destroys it.",
      ),
      wallets,
    );
    const warnings = await textOf("#warnings");
    assert.ok(
      warnings.includes(
        "A deposit the buyer funds into a cash vault from a wallet can be taken back by the buyer only with a refund signed by that wallet's key (from the expiry, in earmarked mode), so closing the page or wiping that wallet before the trade settles leaves the refund to the seller's or the authority's goodwill.",
      ),
      warnings,
    );
    // The card of a wallet that funded nothing says nothing about escrow.
    assert.equal(await page.locator(".wallet-escrow:not([hidden])").count(), 0);
  });
});

// Addresses, hashes, URIs and the QR code against the golden vectors.

test("example 08 in the page (vector 08 with its token pinned): terms hash, template hash, both vault addresses and the funding URI equal the SDK's, and the URI is joined here as spec/CLI.md writes it", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" });
    const t = termsVector("08");
    const v = vaultVector("08");
    assert.equal(t.terms.network, "testnet");
    // The form took the vector's values.
    assert.equal(await page.inputValue('[data-path="seller_key"]'), t.terms.seller_key);
    assert.equal(await page.inputValue('[data-path="cash_leg.amount"]'), t.terms.cash_leg.amount);
    assert.equal(await text(page, '[data-field="terms-hash"]'), t.terms_hash);
    const summary = await page.locator("#summary").textContent();
    assert.ok(summary?.includes(v.template_hash), "template hash");
    assert.ok(summary?.includes("testnet"), "network");
    // The creation score is the one typed, and the page says so; the expiry follows from it:
    // 425,920,000 - 400,000,000 = 25,920,000 DAA scores at 10 per second is 30 days.
    assert.ok(summary?.includes("400000000 (as you entered it, not read from a node)"), summary ?? "");
    assert.ok(summary?.includes("DAA score 425920000, about 30 days after the creation score above"), summary ?? "");
    // The value: the cash leg (1 KAS) against a declaration of 1 KAS, below the cap of 10 KAS.
    assert.ok(
      summary?.includes("1.00000000 KAS (100000000 sompi; declared 100000000, largest native KAS leg 100000000), within the cap of 10.00000000 KAS"),
      summary ?? "",
    );
    // The user is the buyer: the asset vault is the seller's, shown by its address and as not
    // theirs, with no token owner, no URI and no QR code.
    assert.equal(await text(page, '[data-leg="asset"] .vault-address'), v.asset_vault.address);
    assert.equal(await page.locator('[data-leg="asset"] .token-owner').count(), 0);
    assert.equal(await page.locator('[data-leg="asset"] .funding-uri').count(), 0);
    assert.equal(await page.locator('[data-leg="asset"] svg.qr').count(), 0);
    assert.equal(await page.getAttribute('[data-leg="asset"]', "data-you-fund"), "false");
    assert.equal(await text(page, '[data-leg="asset"] .leg-kind'), "KCC-20 token, 1 units");
    assert.equal(await text(page, '[data-field="role"]'), `buyer, key ${t.terms.buyer_key}`);
    assert.equal(await text(page, '[data-field="role-check"]'), "buyer_delivery pays your key; buyer_refund pays your key");
    // Cash leg: native KAS, the URI of spec/CLI.md joined here from the vector files.
    assert.equal(await text(page, '[data-leg="cash"] .vault-address'), v.cash_vault.address);
    const uri = `${v.cash_vault.address}?amount=${t.terms.cash_leg.amount}&impulse=${t.terms_hash}`;
    assert.equal(await text(page, '[data-leg="cash"] .funding-uri'), uri);
    assert.equal(
      await text(page, '[data-leg="cash"] .uri-note'),
      "Send exactly 1.00000000 KAS (100000000 sompi). Confirm your wallet shows that amount before you send.",
    );
    assert.equal(await text(page, '[data-leg="cash"] .leg-kind'), "Native KAS, 100000000 sompi (1.00000000 KAS)");
    assert.equal(await page.getAttribute('[data-leg="cash"]', "data-you-fund"), "true");
    assert.equal(await text(page, "#cash-kas"), "1.00000000 KAS");
    assert.equal(await text(page, "#kas-equivalent-kas"), "1.00000000 KAS");
    // The decoded terms the user is told to read are the terms JSON of the vector.
    assert.deepEqual(JSON.parse((await text(page, "#terms-decoded")) ?? ""), t.terms);
  });
});

/** The QR on the page, drawn by the browser and read back by an independent decoder. */
async function decodeShownQr(s: Session, tamper = false): Promise<string | null> {
  const markup = await s.page.evaluate((t) => {
    const svg = document.querySelector('[data-leg="cash"] svg.qr');
    if (svg === null) return null;
    if (t) {
      // Flip 60 data modules: drop the last 60 dark-module strokes from the drawing.
      const path = svg.querySelector("path");
      const d = path?.getAttribute("d") ?? "";
      const strokes = d.split("z").filter((x) => x !== "");
      path?.setAttribute("d", `${strokes.slice(0, -60).join("z")}z`);
    }
    return new XMLSerializer().serializeToString(svg);
  }, tamper);
  assert.ok(markup, "the page draws a QR code");
  const view = /viewBox="0 0 (\d+) (\d+)"/.exec(markup);
  assert.ok(view);
  const size = Number(view[1]) * 6;
  // A second page without the demo's policy draws the SVG and returns its pixels.
  const reader = await s.context.newPage();
  try {
    await reader.goto("about:blank");
    const pixels = await reader.evaluate(
      async ({ svg, px }) => {
        const url = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg.replace("<svg ", `<svg width="${px}" height="${px}" `))}`;
        const img = new Image();
        img.src = url;
        await img.decode();
        const canvas = document.createElement("canvas");
        canvas.width = px;
        canvas.height = px;
        const g = canvas.getContext("2d") as CanvasRenderingContext2D;
        g.imageSmoothingEnabled = false;
        g.drawImage(img, 0, 0, px, px);
        return Array.from(g.getImageData(0, 0, px, px).data);
      },
      { svg: markup, px: size },
    );
    return jsQR(Uint8ClampedArray.from(pixels), size, size)?.data ?? null;
  } finally {
    await reader.close();
  }
}

test("the QR code on the page decodes to exactly the funding URI of the vector; a damaged one does not", async () => {
  await withPage(async (s) => {
    await vector08(s.page);
    const t = termsVector("08");
    const v = vaultVector("08");
    const uri = `${v.cash_vault.address}?amount=${t.terms.cash_leg.amount}&impulse=${t.terms_hash}`;
    assert.equal(await decodeShownQr(s), uri);
    assert.notEqual(await decodeShownQr(s, true), uri);
  });
});

/**
 * Whether the QR on the page keeps four light modules on every side: the viewBox is the code
 * plus four modules each side, and no dark module is drawn in that margin. Phone scanners need it,
 * and the decoder above reads the drawing edge to edge, so it cannot see it.
 */
async function quietZone(page: Page): Promise<{ width: number; viewBox: string; margin: boolean }> {
  return page.evaluate(() => {
    const svg = document.querySelector('[data-leg="cash"] svg.qr') as SVGElement;
    const width = Number(svg.dataset.width);
    const d = svg.querySelector("path")?.getAttribute("d") ?? "";
    const points = [...d.matchAll(/M(\d+) (\d+)h/g)].map((m) => [Number(m[1]), Number(m[2])]);
    const inside = points.every(([x, y]) => x >= 4 && y >= 4 && x < width + 4 && y < width + 4);
    return { width, viewBox: svg.getAttribute("viewBox") ?? "", margin: points.length > 0 && inside };
  });
}

test("the QR code has its quiet zone of four modules; a drawing with less is seen", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    const q = await quietZone(page);
    assert.equal(q.viewBox, `0 0 ${q.width + 8} ${q.width + 8}`);
    assert.equal(q.margin, true);
  });
  // The page edited to draw a quiet zone of 1 and of 0 modules: the same check refuses both.
  for (const quiet of ["1", "0"]) {
    await withPage(
      async ({ page }) => {
        await vector08(page);
        const q = await quietZone(page);
        assert.notEqual(q.viewBox, `0 0 ${q.width + 8} ${q.width + 8}`, `quiet ${quiet}`);
      },
      "index.html",
      { "/app.js": edit(distText("app.js"), "const quiet = 4;", `const quiet = ${quiet};`) },
    );
  }
});

test("the funding URI and QR follow the amount: another cash amount is another URI, and the QR follows it", async () => {
  await withPage(async (s) => {
    await vector08(s.page);
    const before = await text(s.page, '[data-leg="cash"] .funding-uri');
    await s.page.fill('[data-path="cash_leg.amount"]', "100000001");
    assert.equal((await outcome(s.page)).state, "ok");
    const after = await text(s.page, '[data-leg="cash"] .funding-uri');
    assert.notEqual(after, before);
    assert.ok(after?.includes("amount=100000001&impulse="));
    assert.equal(await decodeShownQr(s), after, "the QR shows the new URI");
    // The terms hash changed with the amount, and the URI names the new hash.
    assert.notEqual(await text(s.page, '[data-field="terms-hash"]'), termsVector("08").terms_hash);
    assert.ok(after?.endsWith(`impulse=${await text(s.page, '[data-field="terms-hash"]')}`));
    assert.equal(await text(s.page, "#cash-kas"), "1.00000001 KAS");
  });
});

// The four destinations, the legs and what the page says it did not check.

test("the four destinations come before the legs, open, decoded and marked by the SDK; the status says what did not run", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" });
    // Before the legs in the page, and not inside a closed element.
    assert.ok(await page.isVisible("#destinations"));
    assert.equal(await page.evaluate(() => document.querySelector("#destinations")?.closest("details") ?? null), null);
    const before = await page.evaluate(
      () => (document.querySelector("#destinations")!.compareDocumentPosition(document.querySelector("#legs")!) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0,
    );
    assert.equal(before, true);
    const rows = await page.locator("#destination-list > li").evaluateAll((els) =>
      els.map((e) => ({ name: e.getAttribute("data-destination"), pays: e.getAttribute("data-pays"), crosses: e.getAttribute("data-crosses") })),
    );
    // Vector 08: delivery and refund to the buyer's key (a KCC-20 pubkey owner, a P2PK-ECDSA
    // script), proceeds to a P2SH and the asset refund to a SCRIPT_HASH owner.
    assert.deepEqual(rows, [
      { name: "buyer_delivery", pays: "buyer_key", crosses: null },
      { name: "seller_proceeds", pays: "script", crosses: null },
      { name: "seller_refund", pays: "script", crosses: null },
      { name: "buyer_refund", pays: "buyer_key", crosses: null },
    ]);
    const t = termsVector("08").terms as Record<string, any>;
    const dest = (name: string) => text(page, `[data-destination="${name}"]`);
    assert.match((await dest("buyer_delivery")) ?? "", new RegExp(`KCC-20 owner pubkey ${t.buyer_key}pays buyer_key$`));
    assert.match((await dest("seller_refund")) ?? "", new RegExp(`KCC-20 owner script_hash ${t.seller_refund.identifier}script to check`));
    assert.match((await dest("seller_proceeds")) ?? "", /kaspatest:[a-z0-9]+ \(pay to script hash\)script to check/);
    assert.match((await dest("buyer_refund")) ?? "", /kaspatest:[a-z0-9]+ \(pay to ECDSA key\)pays buyer_key$/);
    assert.equal(await page.locator(".destination.warn").count(), 0);
    // The status says what ran and what did not, and no longer says that all checks passed.
    const status = (await text(page, "#status")) ?? "";
    assert.match(status, /^Terms structure, creation checks, the role check and the value cap passed\./);
    assert.match(status, /NOT checked: who controls a script destination you pinned, and the token\./);
    assert.match(status, /Read the four destinations below before you fund\.$/);
    assert.doesNotMatch(status, /All checks passed/);
    // The decoded terms are shown on success with their content.
    assert.ok(await page.isVisible("#decoded"));
    assert.ok(((await text(page, "#terms-decoded")) ?? "").includes(t.trade_ref));
  });
});

test("terms whose destinations pay the counterparty or the authority are refused for the party they attack; the other party sees them marked, beside the vector's own", async () => {
  await withPage(async ({ page }) => {
    const base = asTestnet("08") as Record<string, any>;
    const p2pk = (key: string) => ({ kind: "kas", version: 0, script: `20${key}ac` });
    const owner = (key: string) => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });
    const as = (role: "buyer" | "seller", terms: Record<string, any>) => partyFor(role, terms as PartyTerms);
    const load = async (terms: Record<string, any>, party: PageParty) => {
      await loadText(page, JSON.stringify(terms), party);
      await declare(page);
    };
    const crossing = () =>
      page.locator("#destination-list > li[data-crosses='true']").evaluateAll((els) =>
        els.map((e) => `${e.getAttribute("data-destination")} ${e.getAttribute("data-pays")}`),
      );
    // Control: the vector's own destinations, as the buyer.
    await load(base, as("buyer", base));
    assert.equal((await outcome(page)).state, "ok");
    assert.deepEqual(await crossing(), []);
    // The attack: the buyer's refund pays the seller's script, and the buyer's delivery is a
    // KCC-20 owner equal to the seller. The buyer is refused, with the pins of the honest terms
    // and with the attack pinned exactly, and nothing is shown.
    const evil = { ...base, buyer_refund: p2pk(base.seller_key), buyer_delivery: owner(base.seller_key) };
    for (const party of [as("buyer", base), as("buyer", evil)]) {
      await load(evil, party);
      assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_DESTINATION_NOT_MINE" });
      assert.ok(await showsNothing(page));
      const message = (await text(page, "#status")) ?? "";
      assert.match(message, /buyer_delivery pays .*: the counterparty's key/);
      assert.match(message, /buyer_refund pays .*: the counterparty's key/);
    }
    // The seller of the same terms is not attacked in its own destinations: it sees the buyer's
    // marked and flagged.
    await load(evil, as("seller", base));
    assert.equal((await outcome(page)).state, "ok");
    assert.deepEqual(await crossing(), ["buyer_delivery seller_key", "buyer_refund seller_key"]);
    const refund = page.locator('[data-destination="buyer_refund"]');
    assert.match((await refund.textContent()) ?? "", /pays seller_key/);
    assert.match((await refund.locator(".destination-warning").textContent()) ?? "", /If you are the buyer, do not fund these terms\./);
    assert.ok(await refund.isVisible());
    // The authority's key on a refund: refused for the buyer, marked for the seller.
    const authority = { ...base, buyer_refund: p2pk(base.authority_key) };
    await load(authority, as("buyer", base));
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_DESTINATION_NOT_MINE" });
    await load(authority, as("seller", base));
    assert.deepEqual(await crossing(), ["buyer_refund authority_key"]);
    assert.match((await text(page, '[data-destination="buyer_refund"]')) ?? "", /pays authority_key/);
    // The seller's destination paying the buyer: refused for the seller, marked for the buyer.
    const proceeds = { ...base, seller_proceeds: p2pk(base.buyer_key) };
    await load(proceeds, as("seller", base));
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_DESTINATION_NOT_MINE" });
    await load(proceeds, as("buyer", base));
    assert.deepEqual(await crossing(), ["seller_proceeds buyer_key"]);
    // Back to the vector: nothing flagged.
    await load(base, as("buyer", base));
    assert.deepEqual(await crossing(), []);
    assert.equal(await page.locator('[data-destination="seller_proceeds"][data-crosses]').count(), 0);
  });
});

test("the decoded terms show on success and are hidden, with nothing else, on refusal", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.ok(await page.isVisible("#decoded"));
    assert.notEqual(((await text(page, "#terms-decoded")) ?? "").trim(), "");
    assert.ok(await page.isVisible("#destinations"));
    await page.fill("#kas-equivalent", "");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_UNKNOWN" });
    assert.ok(await showsNothing(page));
    await page.fill("#kas-equivalent", "100000000");
    assert.ok(await page.isVisible("#decoded"));
    assert.ok(await page.isVisible("#destinations"));
  });
});

test("every KCC-20 leg carries TOKEN_UNASSESSED, every vault says who funds it, the warnings section says what is not checked", async () => {
  await withPage(async ({ page }) => {
    const warned = (leg: string) => page.locator(`[data-leg="${leg}"] .token-warning[data-code="TOKEN_UNASSESSED"]`).count();
    // Vector 08: a KCC-20 asset leg and a native KAS cash leg.
    await vector08(page);
    assert.equal(await warned("asset"), 1);
    assert.equal(await warned("cash"), 0, "the native KAS leg has no token notice");
    assert.match(
      (await text(page, '[data-leg="asset"] .token-warning')) ?? "",
      /^TOKEN_UNASSESSED: .*issuer powers not read\. Whether the token's issuer can create supply or move it was not examined: check the token yourself before you fund\.$/,
    );
    assert.equal(
      await text(page, '[data-leg="asset"] .depositor-note'),
      "Not yours. You are the buyer: send nothing to this address. Only the seller funds this vault, and funds sent to it are refunded to the seller's refund destination, not to you.",
    );
    assert.equal(
      await text(page, '[data-leg="cash"] .depositor-note'),
      "You fund this vault as the buyer. Check the address and the amount before you send.",
    );
    // Vector 01, as testnet terms: KCC-20 against KCC-20, both unassessed.
    await loadText(page, JSON.stringify(asTestnet("01")));
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await warned("asset"), 1);
    assert.equal(await warned("cash"), 1);
    // Direct terms (vector 07, KCC-20 against KCC-20): no vault, and the notice still shows.
    await loadText(page, JSON.stringify(asTestnet("07")));
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await page.locator(".no-vault").count(), 2);
    assert.equal(await warned("asset"), 1);
    assert.equal(await warned("cash"), 1);
    assert.equal(await page.locator(".depositor-note").count(), 0, "no vault, nothing to send");
    // The section under the result.
    const warnings = (await text(page, "#warnings")) ?? "";
    for (const sentence of [
      "The role check ran for the role and key you gave",
      "It does not say who controls a script you pinned, and it does not read the token.",
      "Only the depositor of a leg funds its vault",
      "The page gives a funding URI and a QR code only for your own leg.",
      "Send nothing to the other vault.",
      "confirm the wallet shows exactly the amount in KAS and sompi given here before you send",
      "A KCC-20 leg is funded with two outputs, the escrowed token and a little KAS",
      "This page funds one thing: the buyer's KAS cash leg, from a wallet of this page, with the wallet's own UTXOs. It does not fund a KCC-20 leg; the seller does that with the command line.",
      "The wallets in this page exist in this page's memory only.",
    ]) {
      assert.ok(warnings.includes(sentence), sentence);
    }
    assert.ok(await page.isVisible("#warnings"));
  });
});

// The role check: who the user is, before anything is shown.

test("nothing is shown until the user says who they are; a key that is not the role's is refused beside the right one", async () => {
  await withPage(async ({ page }) => {
    const t = termsVector("08").terms;
    await loadText(page, JSON.stringify(asTestnet("08")), partyOf("08")); // loads, as the buyer
    await declare(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" }, "control: the buyer of vector 08");
    // The role unset: terms read, and nothing derived.
    await page.selectOption("#role", { value: "" });
    assert.deepEqual(await outcome(page), { state: "role", code: "" });
    assert.ok(await showsNothing(page));
    assert.match((await text(page, "#status")) ?? "", /^Terms read\. Say which party you are/);
    // Each wrong key, with the role set: refused by the SDK, nothing shown.
    await page.selectOption("#role", { value: "buyer" });
    for (const key of [t.seller_key, t.authority_key, "ab".repeat(32), String(t.buyer_key).toUpperCase(), "", "not a key"]) {
      await page.fill("#my-key", String(key));
      const got = await outcome(page);
      assert.equal(got.state, "refused", String(key));
      assert.ok(["SDK_ROLE_KEY_MISMATCH", "SDK_JSON_FORM"].includes(got.code), `${got.code} for a wrong key`);
      assert.ok(await showsNothing(page), "nothing shown for a wrong key");
    }
    // The seller's key claimed as the buyer's names the key the terms hold.
    await page.fill("#my-key", String(t.seller_key));
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_ROLE_KEY_MISMATCH" });
    assert.ok(((await text(page, "#status")) ?? "").includes(String(t.buyer_key)));
    // The right key is accepted again.
    await page.fill("#my-key", String(t.buyer_key));
    assert.equal((await outcome(page)).state, "ok");
  });
});

test("a pin that is not a destination, or is of another network, is refused; the right pin is accepted (a custodian)", async () => {
  await withPage(async ({ page }) => {
    // Vector 08 as the seller: the proceeds and the refund are scripts, accepted only as pinned.
    const base = asTestnet("08");
    const seller = partyFor("seller", base as unknown as PartyTerms);
    await loadText(page, JSON.stringify(base), seller);
    await declare(page);
    assert.equal((await outcome(page)).state, "ok", "control: the seller with the pins its scripts call for");
    assert.ok(seller.receive !== "" && seller.refund !== "", "the seller's destinations are scripts, so pinned");
    // No pin: the scripts are not the seller's key, so the check refuses them.
    await page.fill("#pin-receive", "");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_DESTINATION_NOT_MINE" });
    assert.match((await text(page, "#status")) ?? "", /seller_proceeds pays /);
    assert.ok(await showsNothing(page));
    // A pin that is no destination, and a pin of another network.
    await page.fill("#pin-receive", "kaspa:not-an-address");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_DESTINATION_PIN_INVALID" });
    await page.fill("#pin-receive", "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    assert.equal((await outcome(page)).code, "SDK_DESTINATION_PIN_INVALID");
    // The right pin again.
    await page.fill("#pin-receive", seller.receive);
    assert.equal((await outcome(page)).state, "ok");
    // A different script than the terms name, pinned exactly: refused.
    await page.fill("#pin-refund", seller.refund.replace(/.$/, (c) => (c === "q" ? "p" : "q")));
    assert.equal((await outcome(page)).state, "refused");
    await page.fill("#pin-refund", seller.refund);
    assert.equal((await outcome(page)).state, "ok");
  });
});

test("the seller is shown its own leg to fund and the buyer's vault as not theirs, and the buyer the reverse", async () => {
  await withPage(async ({ page }) => {
    const base = asTestnet("08");
    const v = vaultVector("08");
    const t = termsVector("08");
    await loadText(page, JSON.stringify(base), partyFor("seller", base as unknown as PartyTerms));
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await text(page, '[data-field="role"]'), `seller, key ${t.terms.seller_key}`);
    // The seller funds the asset leg: its vault address and the token owner; the cash vault is
    // shown by address only, with no URI and no QR code.
    assert.equal(await page.getAttribute('[data-leg="asset"]', "data-you-fund"), "true");
    assert.equal(await page.getAttribute('[data-leg="cash"]', "data-you-fund"), "false");
    assert.equal(await text(page, '[data-leg="asset"] .token-owner'), v.asset_vault.script_hash);
    assert.equal(await text(page, '[data-leg="cash"] .vault-address'), v.cash_vault.address);
    assert.equal(await page.locator(".funding-uri, svg.qr").count(), 0, "no URI and no QR for the seller: its leg is a token");
    assert.match((await text(page, '[data-leg="cash"] .depositor-note')) ?? "", /^Not yours\. You are the seller: send nothing to this address\./);
    assert.equal(await page.locator('[data-leg="cash"] .token-owner').count(), 0);
    // The buyer of the same terms: the URI and the QR code are for the cash leg.
    await loadText(page, JSON.stringify(base), partyFor("buyer", base as unknown as PartyTerms));
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await page.locator(".funding-uri").count(), 1);
    assert.equal(await page.locator('[data-leg="cash"] svg.qr').count(), 1);
    assert.equal(await page.locator('[data-leg="asset"] .funding-uri, [data-leg="asset"] svg.qr, [data-leg="asset"] .token-owner').count(), 0);
  });
});

// The value cap.

test("the banner says what the cap checks and does not claim to cap every trade", async () => {
  await withPage(async ({ page }) => {
    const banner = ((await text(page, "#status-banner")) ?? "").replace(/\s+/g, " ");
    assert.equal(
      banner,
      "This page refuses a trade whose declared KAS value, or whose native KAS leg, is above 10.00000000 KAS. Non-custodial software, not advice or an offer.",
    );
    // The rest of the text is behind Details.
    const more = ((await text(page, "#banner-details")) ?? "").replace(/\s+/g, " ");
    assert.ok(more.includes("For a token leg the value is the figure you declare, and nothing checks it."), more);
    assert.ok(more.includes("Nothing here is advice or an offer. Impulse is non-custodial, issues no asset or token, and does not check issuer terms or sanctions obligations; those stay your own responsibility."), more);
    assert.doesNotMatch(banner, /caps every trade/);
    await page.check("#mainnet-switch");
    const notice = ((await text(page, "#mainnet-notice")) ?? "").replace(/\s+/g, " ");
    assert.match(notice, /a token leg's value is the figure you declare and nothing checks it/);
    assert.doesNotMatch(notice, /the cap is the only guard/);
  });
});

test("a declared value does not survive loading other terms: each trade needs a fresh declaration", async () => {
  await withPage(async ({ page }) => {
    await vector08(page, "1");
    assert.equal((await outcome(page)).state, "ok", "declared 1 sompi");
    assert.equal(await text(page, "#kas-equivalent-kas"), "0.00000001 KAS");
    // Other terms from pasted JSON: the declaration and its echo are gone, and the cap check
    // has nothing to measure until the value is typed again.
    await loadText(page, JSON.stringify(asTestnet("01")));
    assert.equal(await page.inputValue("#kas-equivalent"), "");
    assert.equal(await text(page, "#kas-equivalent-kas"), "");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_UNKNOWN" });
    assert.ok(await showsNothing(page));
    await page.fill("#kas-equivalent", "100000000");
    assert.equal((await outcome(page)).state, "ok", "retyped");
    // Again from an example.
    await loadExample(page, "08");
    assert.equal(await page.inputValue("#kas-equivalent"), "");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_UNKNOWN" });
    // The creation score, which belongs to the moment and not to the trade, is kept.
    assert.equal(await page.inputValue("#creation-daa"), "400000000");
  });
});

test("the value cap: at 10 KAS accepted, one sompi above refused with nothing shown", async () => {
  // The page's cap is the default one, the same as the command line's and the SDK's (D4): a Direct
  // trade needs the 2 KAS minimum carrier of its token, so a lower cap could not fund one.
  assert.match(distText("config.js"), /^export const VALUE_CAP_SOMPI = "1000000000";$/m);
  await withPage(async ({ page }) => {
    assert.equal(await text(page, "#cap-kas"), "10.00000000");
    await vector08(page, "1000000000");
    assert.deepEqual(await outcome(page), { state: "ok", code: "" }, "at the cap");
    assert.equal(await page.locator(".funding-uri").count(), 1);
    assert.ok(((await text(page, "#summary")) ?? "").includes("10.00000000 KAS"));
    await page.fill("#kas-equivalent", "1000000001");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_CAP_EXCEEDED" });
    assert.ok(await showsNothing(page), "no address, URI or QR above the cap");
    assert.ok(((await text(page, "#kas-equivalent-kas")) ?? "").startsWith("10.00000001 KAS"));
    await page.fill("#kas-equivalent", "1000000000");
    assert.equal((await outcome(page)).state, "ok", "back at the cap");
  });
});

test("a native KAS leg above the cap is refused even with a small declaration", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    await page.fill('[data-path="cash_leg.amount"]', "1000000000");
    assert.equal((await outcome(page)).state, "ok", "the cash leg at the cap");
    await page.fill('[data-path="cash_leg.amount"]', "1000000001");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_CAP_EXCEEDED" });
    assert.ok(await showsNothing(page));
  });
});

test("a v1 trade needs a declared value: none, or 0, is refused; 1 sompi is accepted", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    await page.fill("#kas-equivalent", "1");
    assert.equal((await outcome(page)).state, "ok", "declared 1 sompi");
    await page.fill("#kas-equivalent", "");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_UNKNOWN" });
    assert.ok(await showsNothing(page));
    await page.fill("#kas-equivalent", "0");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_UNKNOWN" });
    await page.fill("#kas-equivalent", "1");
    assert.equal((await outcome(page)).state, "ok");
  });
});

test("the value row shows the value, the declaration and the cap apart when the value is below the cap", async () => {
  await withPage(async ({ page }) => {
    await vector08(page, "50000000");
    assert.ok(
      ((await text(page, "#summary")) ?? "").includes(
        "1.00000000 KAS (100000000 sompi; declared 50000000, largest native KAS leg 100000000), within the cap of 10.00000000 KAS",
      ),
    );
    assert.equal(await text(page, "#kas-equivalent-kas"), "0.50000000 KAS");
  });
});

test("the configured cap can be lowered and binds; a cap above the default makes the page refuse every trade", async () => {
  const config = (cap: string) => ({ "/config.js": `export const VALUE_CAP_SOMPI = "${cap}";\n` });
  // Control: vector 08 is worth exactly 1 KAS, so a cap of 1 KAS accepts it.
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await text(page, "#cap-kas"), "1.00000000");
  }, "index.html", config("100000000"));
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_CAP_EXCEEDED" });
    assert.equal(await text(page, "#cap-kas"), "0.99999999");
    assert.ok(await showsNothing(page));
  }, "index.html", config("99999999"));
  // The cap the SDK knows as its default (10 KAS) is accepted as a configured cap; one sompi more is not.
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.equal((await outcome(page)).state, "ok");
  }, "index.html", config("1000000000"));
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_VALUE_CAP_INVALID" });
    assert.ok(await showsNothing(page));
  }, "index.html", config("1000000001"));
});

// The mainnet switch.

test("mainnet is off by default, behind a switch that shows the mainnet notice", async () => {
  await withPage(async ({ page }) => {
    assert.equal(await page.isChecked("#mainnet-switch"), false);
    assert.equal(await page.isVisible("#mainnet-notice"), false);
    assert.equal(await text(page, "#network-name"), "testnet");
    assert.ok(await page.isVisible("#status-banner"), "the banner is always shown");
    await page.check("#mainnet-switch");
    assert.equal(await page.isVisible("#mainnet-notice"), true);
    const notice = (await text(page, "#mainnet-notice")) ?? "";
    assert.match(notice, /Mainnet is on\. This page moves real funds, and it refuses a trade/);
    assert.ok(!/This page[^.]*\. This page/.test(notice), "no two sentences in a row begin with This page");
    assert.equal(await text(page, "#network-name"), "mainnet");
    assert.equal(await page.getAttribute("body", "data-network"), "mainnet");
    await page.uncheck("#mainnet-switch");
    assert.equal(await page.isVisible("#mainnet-notice"), false);
    assert.equal(await text(page, "#network-name"), "testnet");
  });
});

test("with the switch off every mainnet vector is refused and the testnet vector is accepted", async () => {
  await withPage(async ({ page }) => {
    let accepted = 0;
    for (const v of termsVectors) {
      await loadExample(page, v.name.slice(0, 2));
      await declare(page);
      const got = await outcome(page);
      if (v.terms.network === "testnet") {
        accepted += 1;
        assert.equal(got.state, "ok", v.name);
      } else {
        assert.deepEqual(got, { state: "refused", code: "TERMS_NETWORK_MISMATCH" }, v.name);
        assert.ok(await showsNothing(page), `${v.name}: nothing shown`);
      }
    }
    assert.equal(accepted, 1, "one testnet vector");
  });
});

test("with the switch on a typed creation DAA is refused for mainnet terms, whatever the cap, and testnet terms are refused", async () => {
  await withPage(async ({ page }) => {
    await page.check("#mainnet-switch");
    let refused = 0;
    for (const v of termsVectors) {
      await loadExample(page, v.name.slice(0, 2));
      await declare(page);
      const got = await outcome(page);
      const want = v.terms.network === "testnet" ? "TERMS_NETWORK_MISMATCH" : "SDK_MAINNET_NEEDS_NODE";
      assert.deepEqual(got, { state: "refused", code: want }, v.name);
      assert.ok(await showsNothing(page), `${v.name}: nothing shown`);
      refused += 1;
    }
    assert.equal(refused, 11);
    // Control: the same page with the switch off derives the testnet vector.
    await page.uncheck("#mainnet-switch");
    await loadExample(page, "08");
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
  });
});

test("ticking the switch after a derivation refuses at once and shows nothing; unticking restores it", async () => {
  await withPage(async ({ page }) => {
    // Testnet terms derived, then the switch: the network of the creation checks changes.
    await vector08(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await page.locator(".funding-uri").count(), 1);
    await page.check("#mainnet-switch");
    assert.deepEqual(await outcome(page), { state: "refused", code: "TERMS_NETWORK_MISMATCH" });
    assert.ok(await showsNothing(page), "the testnet instruction is gone");
    assert.equal(await text(page, "#network-name"), "mainnet");
    await page.uncheck("#mainnet-switch");
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await page.locator(".funding-uri").count(), 1);
    // Mainnet terms loaded with the switch off, then toggled: a typed score is what mainnet refuses.
    await loadExample(page, "02");
    await declare(page);
    assert.deepEqual(await outcome(page), { state: "refused", code: "TERMS_NETWORK_MISMATCH" });
    await page.check("#mainnet-switch");
    assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_MAINNET_NEEDS_NODE" });
    assert.ok(await showsNothing(page));
    await page.uncheck("#mainnet-switch");
    assert.deepEqual(await outcome(page), { state: "refused", code: "TERMS_NETWORK_MISMATCH" });
  });
});

// Form refusals carry the SDK's stable codes; nothing is shown beside them.

test("terms the SDK refuses show its code and nothing else, each beside the accepted vector", async () => {
  const t = termsVector("08").terms;
  const cases: [string, string, string][] = [
    ["seller_key", String(t.seller_key).toUpperCase(), "SDK_JSON_FORM"],
    ["buyer_key", String(t.seller_key), "TERMS_PARTIES_NOT_DISTINCT"],
    ["nonce", "abc", "SDK_JSON_FORM"],
    ["expiry_daa", "400000000", "TERMS_EARLIEST_AFTER_EXPIRY"],
    ["cash_leg.amount", "0", "TERMS_AMOUNT_ZERO"],
    ["asset_leg.template_prefix_len", "x", "SDK_JSON_FORM"],
  ];
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.equal((await outcome(page)).state, "ok", "control");
    for (const [path, bad, code] of cases) {
      const selector = `[data-path="${path}"]`;
      const good = await page.inputValue(selector);
      await page.fill(selector, bad);
      assert.deepEqual(await outcome(page), { state: "refused", code }, `${path} = ${bad}`);
      assert.ok(await showsNothing(page), `${path}: nothing shown`);
      assert.match((await text(page, "#status")) ?? "", new RegExp(`^Refused: ${code}: `));
      await page.fill(selector, good);
      assert.equal((await outcome(page)).state, "ok", `${path} restored`);
    }
    // A creation DAA the user types is checked by the SDK too.
    await page.fill("#creation-daa", "999999999999");
    assert.equal((await outcome(page)).code, "TERMS_EXPIRY_NOT_AFTER_CREATION");
    await page.fill("#creation-daa", "400000000");
    assert.equal((await outcome(page)).state, "ok");
  });
});

test("the creation DAA score has no default: nothing is derived until it is typed, and a stale one shows in the time left", async () => {
  await withPage(async ({ page }) => {
    assert.equal(await page.inputValue("#creation-daa"), "");
    assert.ok(((await page.getAttribute("#creation-daa", "placeholder")) ?? "").length > 0);
    await loadExample(page, "08");
    await page.fill("#kas-equivalent", "100000000");
    const refused = await outcome(page);
    assert.equal(refused.state, "refused");
    assert.equal(refused.code, "SDK_JSON_FORM");
    assert.match((await text(page, "#status")) ?? "", /creation_daa/);
    assert.ok(await showsNothing(page));
    await page.fill("#creation-daa", "400000000");
    assert.equal((await outcome(page)).state, "ok");
    assert.ok(((await text(page, "#summary")) ?? "").includes("about 30 days after the creation score"));
    // A stale score (lower than the chain's) makes the expiry look further away: the page shows
    // the time left it implies, here from score 200,000,000, in days.
    await page.fill("#creation-daa", "200000000");
    assert.equal((await outcome(page)).state, "ok");
    const days = Math.floor(Math.floor((425_920_000 - 200_000_000) / 10) / 86_400);
    assert.ok(((await text(page, "#summary")) ?? "").includes(`about ${days} days after the creation score`), `about ${days} days`);
  });
});

test("Direct terms and external cash show no vault and no URI; KAS cash shows both", async () => {
  await withPage(async ({ page }) => {
    // Vector 07 is Direct on mainnet; as testnet terms it is the same trade on the page's network.
    await loadText(page, JSON.stringify(asTestnet("07")));
    await declare(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" });
    assert.equal(await page.locator(".no-vault").count(), 2);
    assert.equal(await page.locator(".vault-address, .funding-uri, svg.qr").count(), 0);
    // Control: vector 08 has vaults and a URI.
    await loadExample(page, "08");
    await declare(page);
    assert.equal(await page.locator(".no-vault").count(), 0);
    assert.equal(await page.locator(".vault-address").count(), 2);
    assert.equal(await page.locator(".funding-uri").count(), 1);
    // External cash (vector 05) as testnet terms: the cash leg has no vault, the asset leg has one.
    await loadText(page, JSON.stringify(asTestnet("05")));
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
    assert.equal(await page.locator('[data-leg="cash"] .no-vault').count(), 1);
    assert.equal(await page.locator('[data-leg="asset"] .vault-address').count(), 1);
    assert.equal(await page.locator(".funding-uri").count(), 0);
  });
});

// Terms text: what the SDK reads, and what the page then holds.

test("terms text is read as a vector file, a terms file or a bare terms object, each equal to the vector", async () => {
  await withPage(async ({ page }) => {
    const t = termsVector("08");
    const shapes: [string, string][] = [
      ["bare terms object", JSON.stringify(t.terms)],
      ["terms file", JSON.stringify({ terms: t.terms, canonical: t.canonical, terms_hash: t.terms_hash })],
      ["vector file as committed", vectorText("08")],
    ];
    for (const [what, body] of shapes) {
      await loadText(page, body);
      await declare(page);
      assert.deepEqual(await outcome(page), { state: "ok", code: "" }, what);
      assert.equal(await text(page, '[data-field="terms-hash"]'), t.terms_hash, what);
      assert.deepEqual(JSON.parse((await text(page, "#terms-decoded")) ?? ""), t.terms, what);
      assert.equal(await page.isVisible("#load-error"), false, what);
    }
  });
});

test("pasted terms the SDK's reader refuses are refused whole: the form is untouched and nothing is derived, each beside the accepted file", async () => {
  const good = vectorText("08");
  const t = termsVector("08");
  const doc = () => JSON.parse(good) as Record<string, any>;
  const json = (f: (d: Record<string, any>) => void) => {
    const d = doc();
    f(d);
    return JSON.stringify(d);
  };
  const cases: [string, string, string][] = [
    ["a u64 as a JSON number", edit(good, '"amount": "100000000"', '"amount": 100000000'), "SDK_JSON_FORM"],
    ["a nonce past 2^53 as a JSON number", edit(good, '"7989634765647131680"', "7989634765647131680"), "SDK_JSON_FORM"],
    ["an asset amount of 2^53 + 1 as a JSON number", edit(good, '"amount": "1"', '"amount": 9007199254740993'), "SDK_JSON_FORM"],
    ["an unknown top-level key", json((d) => (d.memo = "x")), "SDK_JSON_FORM"],
    ["an unknown key in the terms", json((d) => (d.terms.memo = "x")), "SDK_JSON_FORM"],
    ["a stray key in a leg", json((d) => (d.terms.cash_leg.covenant_id = "00".repeat(32))), "SDK_JSON_FORM"],
    ["a key named twice", edit(good, '"name"', '"canonical": "00", "name"'), "SDK_JSON_FORM"],
    ["a terms_hash that is not the hash of the terms", json((d) => (d.terms_hash = "11".repeat(32))), "SDK_TERMS_INCONSISTENT"],
    ["a canonical that is not the encoding of the terms", json((d) => (d.canonical = "00")), "SDK_TERMS_INCONSISTENT"],
    ["terms changed under their own canonical and hash", json((d) => (d.terms.nonce = "7989634765647131681")), "SDK_TERMS_INCONSISTENT"],
    ["text that is not JSON", "{not json", "SDK_JSON_FORM"],
    ["an empty text", "", "SDK_JSON_FORM"],
    ["an empty object", "{}", "SDK_JSON_FORM"],
  ];
  await withPage(async ({ page }) => {
    await loadText(page, good);
    await declare(page);
    assert.deepEqual(await outcome(page), { state: "ok", code: "" }, "control: the vector file");
    assert.equal(await text(page, '[data-field="terms-hash"]'), t.terms_hash);
    const formBefore = await page.evaluate(() =>
      [...document.querySelectorAll("[data-path]")].map((e) => (e as HTMLInputElement).value),
    );
    for (const [what, body, code] of cases) {
      await loadText(page, body);
      assert.deepEqual(await outcome(page), { state: "refused", code }, what);
      assert.ok(await showsNothing(page), `${what}: nothing shown`);
      assert.match((await text(page, "#status")) ?? "", new RegExp(`^Refused: ${code}: `), what);
      // The refusal came before the form was filled.
      assert.deepEqual(
        await page.evaluate(() => [...document.querySelectorAll("[data-path]")].map((e) => (e as HTMLInputElement).value)),
        formBefore,
        `${what}: form untouched`,
      );
      // And the accepted file loads again beside it.
      await loadText(page, good);
      await declare(page);
      assert.deepEqual(await outcome(page), { state: "ok", code: "" }, `${what}: control again`);
      assert.equal(await text(page, '[data-field="terms-hash"]'), t.terms_hash, `${what}: control hash`);
    }
  });
});

test("an empty paste does not blank the hidden version: later hand-entered terms are accepted", async () => {
  await withPage(async ({ page }) => {
    await vector08(page);
    assert.equal(await page.inputValue('[data-path="version"]'), "1");
    await loadText(page, "{}");
    assert.equal((await outcome(page)).code, "SDK_JSON_FORM");
    assert.equal(await page.inputValue('[data-path="version"]'), "1");
    await page.fill('[data-path="nonce"]', "7");
    assert.deepEqual(await outcome(page), { state: "ok", code: "" });
  });
});

test("a form that changes a field while terms load is refused by the SDK's comparison; the page as built is accepted", async () => {
  const load = async (page: Page) => {
    // Who the user is comes first, so that loading the terms is the last thing the page answers.
    await iAm(page, partyOf("08"));
    await page.selectOption("#example", { value: `${exampleName("08")}.json` });
    await page.click("#load-example");
    // The page fetches the file, fills the form and answers in one step. With the mutated page the
    // form holds the loaded nonce all the same, so the wait is on the nonce and the trade reference.
    const t = termsVector("08").terms;
    await page.waitForFunction(
      ([nonce, ref]) =>
        (document.querySelector('[data-path="nonce"]') as HTMLInputElement).value === nonce &&
        (document.querySelector('[data-path="trade_ref"]') as HTMLInputElement).value === ref,
      [String(t.nonce), String(t.trade_ref)],
    );
  };
  // Control: the page as built derives vector 08 once the value is declared.
  await withPage(async ({ page }) => {
    await load(page);
    await declare(page);
    assert.equal((await outcome(page)).state, "ok");
  });
  // The page edited so that the form takes an expiry with a digit added: the form still holds
  // valid terms, but not the terms the SDK read, and nothing is derived.
  const app = edit(
    distText("app.js"),
    'input.value = v === undefined || v === null ? "" : String(v);',
    'input.value = (v === undefined || v === null ? "" : String(v)) + (input.dataset.path === "expiry_daa" ? "0" : "");',
  );
  await withPage(
    async ({ page }) => {
      await load(page);
      assert.deepEqual(await outcome(page), { state: "refused", code: "SDK_TERMS_INCONSISTENT" });
      assert.ok(await showsNothing(page));
    },
    "index.html",
    { "/app.js": app },
  );
});

// Startup and loading failures.

test("a template that does not match its pin stops the page at startup; a page whose module will not load derives nothing", async () => {
  const wasm = readFileSync(new URL("sdk/pkg/impulse_wasm_bg.wasm", dist));
  // The module embeds the compiled template as a JSON artifact whose bytecode is a list of
  // decimal byte values; it begins with 107. Make that 108: one byte of the template changes.
  // The module embeds more than one artifact (template v1, template v2); the page's startup
  // check is of template v1, whose bytecode begins 107, 1, 0 (the second number is the template
  // version). Take that one, wherever the linker placed it.
  const key = wasm.toString("latin1").search(/"bytecode":\s*\[\s*107,\s*1,\s*0,/);
  assert.ok(key > 0, "the embedded artifact");
  const at = wasm.indexOf(Buffer.from("107"), key);
  assert.ok(at > key && at - key < 64, "the first byte of the bytecode follows its key");
  const corrupt = Buffer.from(wasm);
  corrupt[at + 2] = 0x38; // "107" -> "108"
  const wasmPath = "/sdk/pkg/impulse_wasm_bg.wasm";
  const expectStopped = async ({ page }: Session, message: RegExp) => {
    assert.equal((await outcome(page)).state, "error");
    assert.match((await text(page, "#status")) ?? "", message);
    assert.equal(await page.locator("#example > option").count(), 0, "no examples listed");
    // The form is inert: an edit derives nothing.
    await page.fill('[data-path="nonce"]', "7");
    assert.equal((await outcome(page)).state, "error");
    assert.ok(await showsNothing(page));
  };
  // Control: the same module, byte for byte, starts the page.
  await withPage(async ({ page }) => {
    assert.equal((await outcome(page)).state, "idle");
    assert.equal(await page.locator("#example > option").count(), 11);
  }, "index.html", { [wasmPath]: wasm });
  await withPage((s) => expectStopped(s, /^The SDK did not start: TEMPLATE_HASH_MISMATCH/), "index.html", { [wasmPath]: corrupt });
  await withPage((s) => expectStopped(s, /^The SDK did not start: /), "index.html", { [wasmPath]: Buffer.from("this is not wasm") });
  await withPage((s) => expectStopped(s, /^The SDK did not start: /), "index.html", { [wasmPath]: 404 });
});

test("a golden vector list or file that cannot be fetched is reported; the page keeps working", async () => {
  // The list: the page mounts, says so, and lists nothing; typing still derives.
  await withPage(
    async ({ page }) => {
      // The page goes idle before it fetches the list, so the failure shows a moment later: wait
      // for the message itself, then check everything it must and must not have done.
      await page.waitForSelector("#load-error:not([hidden])");
      assert.equal((await outcome(page)).state, "idle");
      assert.equal(await page.locator("#example > option").count(), 0);
      assert.equal(await page.isVisible("#load-error"), true);
      assert.match((await text(page, "#load-error")) ?? "", /^The golden vectors could not be listed: /);
      await loadText(page, JSON.stringify(asTestnet("08")));
      await declare(page);
      assert.equal((await outcome(page)).state, "ok");
    },
    "index.html",
    { "/examples/index.json": 404 },
  );
  // One vector: reported, nothing derived from it, the status unchanged; the others load.
  const name = `${exampleName("08")}.json`;
  await withPage(
    async ({ page }) => {
      await page.selectOption("#example", { value: name });
      await page.click("#load-example");
      await page.waitForSelector("#load-error:not([hidden])");
      assert.equal(await text(page, "#load-error"), "The vector could not be loaded: HTTP 500");
      assert.equal((await outcome(page)).state, "idle");
      assert.ok(await showsNothing(page));
      await loadExample(page, "07");
      assert.equal(await page.isVisible("#load-error"), false, "cleared by the next load");
    },
    "index.html",
    { [`/examples/${name}`]: 500 },
  );
  // Control: with neither override the list has 11 entries and no error shows.
  await withPage(async ({ page }) => {
    // The list is fetched after the page goes idle: wait for it to arrive, then require all 11.
    await page.waitForSelector("#example > option", { state: "attached" });
    assert.equal(await page.locator("#example > option").count(), 11);
    assert.equal(await page.isVisible("#load-error"), false);
  });
});

// Every vector, in the page and in the SDK.

test("all 11 vectors, on the page's network: the page shows what the SDK returns for the same terms", async () => {
  const sdk = await nodeSdk();
  // Amounts above the cap are cut to 1 KAS so that every vector reaches the instructions; the
  // original terms are checked first, and must be refused for the cap alone.
  const clamp = (terms: Record<string, any>) => {
    const cut = structuredClone(terms);
    for (const leg of [cut.asset_leg, cut.cash_leg]) {
      if (leg.kind === "kas" && BigInt(leg.amount) > 1_000_000_000n) leg.amount = "100000000";
    }
    return cut;
  };
  // The buyer of the terms, as the SDK takes a party (no pin is the SDK's null).
  const oracleParty = (terms: Record<string, any>) => {
    const p = partyFor("buyer", terms as PartyTerms);
    return { role: p.role, key: p.key, pins: { receive: p.receive === "" ? null : p.receive, refund: p.refund === "" ? null : p.refund } };
  };
  const instructions = (terms: Record<string, any>) => {
    try {
      return {
        out: sdk.Terms.fromJson(terms)
          .validateStructure()
          .fundingInstructions({
            context: { network: "testnet", creation_daa: "400000000" },
            creation_daa_source: "typed",
            party: oracleParty(terms),
            kas_equivalent: "100000000",
            cap: "1000000000",
          }),
      };
    } catch (e) {
      return { code: (e as { code: string }).code };
    }
  };
  await withPage(async ({ page }) => {
    let derived = 0;
    let cut = 0;
    for (const v of termsVectors) {
      const original = asTestnet(v.name.slice(0, 2));
      for (const [which, terms] of [
        ["original", original],
        ["clamped", clamp(original)],
      ] as const) {
        if (which === "clamped" && JSON.stringify(terms) === JSON.stringify(original)) continue;
        await loadText(page, JSON.stringify(terms));
        await declare(page);
        const want = instructions(terms);
        const where = `${v.name} (${which})`;
        const got = await outcome(page);
        if (want.out === undefined) {
          assert.deepEqual(got, { state: "refused", code: want.code }, where);
          assert.ok(await showsNothing(page), `${where}: nothing shown`);
          if (which === "original") {
            assert.equal(want.code, "SDK_VALUE_CAP_EXCEEDED", `${where}: refused for the cap alone`);
            cut += 1;
          }
          continue;
        }
        const out = want.out;
        assert.deepEqual(got, { state: "ok", code: "" }, where);
        derived += 1;
        assert.equal(await text(page, '[data-field="terms-hash"]'), out.terms_hash, `${where}: terms hash`);
        assert.ok(((await text(page, "#summary")) ?? "").includes(out.template_hash), `${where}: template hash`);
        assert.deepEqual(JSON.parse((await text(page, "#terms-decoded")) ?? ""), terms, `${where}: decoded terms`);
        for (const [i, name] of ["asset", "cash"].entries()) {
          const leg = out.legs[i];
          const card = `[data-leg="${name}"]`;
          const shown = async (sel: string) => ((await page.locator(`${card} ${sel}`).count()) === 0 ? null : await text(page, `${card} ${sel}`));
          assert.equal(await shown(".vault-address"), leg.vault?.address ?? null, `${where}: ${name} address`);
          assert.equal(await shown(".funding-uri"), leg.funding_uri, `${where}: ${name} URI`);
          assert.equal(await shown(".token-owner"), leg.kind === "kcc20" && leg.vault && leg.you_fund ? leg.vault.script_hash : null, `${where}: ${name} token owner`);
          assert.equal(await shown(".no-vault"), leg.vault === null ? `No vault on this leg: ${leg.no_vault_reason}` : null, `${where}: ${name} no vault`);
          assert.equal(await page.locator(`${card} .token-warning`).count(), leg.token_warnings.length, `${where}: ${name} token notice`);
        }
        const rows = await page.locator("#destination-list > li").evaluateAll((els) =>
          els.map((e) => [e.getAttribute("data-destination"), e.getAttribute("data-pays"), e.querySelector(".destination-text")?.textContent]),
        );
        assert.deepEqual(rows, out.destinations.map((d: any) => [d.name, d.pays, d.destination]), `${where}: destinations`);
      }
    }
    assert.ok(derived >= 11, `every vector was derived at least once (${derived})`);
    assert.ok(cut >= 1, "some vector holds a KAS leg above the cap and is refused for it");
  });
});

// Keys and the network.

test("on load, and after a new nonce, the page holds no key and makes no WebCrypto key call, stores nothing and makes only GET requests for its own files", async () => {
  await withPage(
    async ({ page, site, external, sockets }) => {
      await vector08(page);
      await page.click("#new-nonce");
      const nonce = await page.inputValue('[data-path="nonce"]');
      assert.match(nonce, /^[0-9]+$/);
      assert.ok(BigInt(nonce) < 1n << 64n);
      await page.click("#new-nonce");
      assert.notEqual(await page.inputValue('[data-path="nonce"]'), nonce, "a new draw");
      const probe = await page.evaluate(() => {
        const w = window as unknown as { __subtle: string[] };
        return {
          local: localStorage.length,
          session: sessionStorage.length,
          cookie: document.cookie,
          subtleCalls: w.__subtle,
          keyInputs: document.querySelectorAll('input[type="password"], input[name*="private" i], input[name*="seed" i]').length,
        };
      });
      assert.deepEqual(probe, { local: 0, session: 0, cookie: "", subtleCalls: [], keyInputs: 0 });
      assert.deepEqual(external, []);
      assert.deepEqual(sockets, []);
      assert.ok(site.requests.length > 0);
      // Every request was a GET (the server records the method of each).
      assert.equal(site.methods.length, site.requests.length);
      assert.ok(site.methods.every((m) => m === "GET"), site.methods.join(","));
    },
    "index.html",
    {},
    () => {
      // Records any use of the WebCrypto key API; the page must not make one.
      const w = window as unknown as { __subtle: string[] };
      w.__subtle = [];
      const subtle = crypto.subtle as unknown as Record<string, unknown>;
      for (const name of ["generateKey", "importKey", "exportKey", "deriveKey", "deriveBits", "sign", "digest", "encrypt", "decrypt"]) {
        subtle[name] = () => {
          w.__subtle.push(name);
          throw new Error(`crypto.subtle.${name} is not for this page`);
        };
      }
    },
  );
});
