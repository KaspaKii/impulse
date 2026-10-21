// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Scaffolding for the browser tests: a static server for demo/dist that records every request, a
// Chrome or Chromium found on the machine (a test run fails if there is none; it never skips),
// and the golden vector files. Nothing here is page or SDK logic: the expectations come from
// tests/vectors, read from disk.
import { createServer, type Server } from "node:http";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";

// The site under test. IMPULSE_DIST names another directory (a copy with one edit, for the
// mutation record of mutation.mjs); by default it is the one demo/build.sh made.
export const dist = process.env.IMPULSE_DIST
  ? pathToFileURL(`${process.env.IMPULSE_DIST.replace(/\/+$/, "")}/`)
  : new URL("../dist/", import.meta.url);
export const repo = new URL("../../", import.meta.url);

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

/**
 * What a path serves instead of its file: a body (text or bytes), or a number, the status code
 * of an empty answer (a missing file, a failing server).
 */
export type Override = string | Buffer | number;

export interface Site {
  origin: string;
  /** Every request path the server saw, in order. */
  requests: string[];
  /** The method of each request, in the same order. */
  methods: string[];
  close(): Promise<void>;
}

/** Serves demo/dist on 127.0.0.1. `overrides` replaces the answer for a path, as a deployment would. */
export async function serve(overrides: Record<string, Override> = {}): Promise<Site> {
  const requests: string[] = [];
  const methods: string[] = [];
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    requests.push(path);
    methods.push(req.method ?? "");
    const name = path === "/" ? "/index.html" : path;
    const ext = name.slice(name.lastIndexOf("."));
    const override = overrides[name];
    if (typeof override === "number") {
      res.writeHead(override, { "content-type": "text/plain" }).end("");
      return;
    }
    let body: Buffer | string | undefined = override;
    if (body === undefined) {
      const file = new URL(`.${name}`, dist);
      if (file.href.startsWith(dist.href) && existsSync(file) && !name.endsWith("/")) body = readFileSync(file);
    }
    if (body === undefined) {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": MIME[ext] ?? "text/plain; charset=utf-8" }).end(body);
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    methods,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}

const CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  ...puppeteerChromes(),
];

/** Chrome for Testing builds installed by Puppeteer under ~/.cache/puppeteer, newest first. */
function puppeteerChromes(): string[] {
  const root = join(homedir(), ".cache", "puppeteer", "chrome");
  if (!existsSync(root)) return [];
  return readdirSync(root).sort().reverse().flatMap((v) => [
    join(root, v, "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
    join(root, v, "chrome-mac-x64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
    join(root, v, "chrome-linux64", "chrome"),
  ]);
}

/** $IMPULSE_BROWSER, else the first Chrome or Chromium at a usual path. Fails if there is none. */
export function browserPath(): string {
  const found = process.env.IMPULSE_BROWSER ?? CANDIDATES.find((p) => existsSync(p));
  if (found === undefined || !existsSync(found)) {
    throw new Error(`no Chrome or Chromium found (set IMPULSE_BROWSER to its path); looked at ${CANDIDATES.join(", ")}`);
  }
  return found;
}

export function launch(): Promise<Browser> {
  return chromium.launch({ executablePath: browserPath(), headless: true });
}

/** An open page of the demo, with everything a test needs to see what the page did. */
export interface Session {
  site: Site;
  context: BrowserContext;
  page: Page;
  /** Requests the browser tried to make to any origin but the page's own; all were aborted. */
  external: string[];
  /** WebSockets the browser created for the page, to any host. */
  sockets: string[];
  /** Console errors and uncaught page errors. */
  errors: string[];
  /** Every console message of every type, as text, and every uncaught page error. */
  console: string[];
  /** Every HTTP request the browser made for the page: URL, method, headers and body. */
  requests: { url: string; method: string; headers: Record<string, string>; body: string | null }[];
  /** Every WebSocket URL the page tried to open (when `nodes` was given), in the browser's normal form, in order. */
  contacted: string[];
  /** Every text the page sent over a WebSocket it opened, with the URL it was sent to. */
  sent: { url: string; text: string }[];
  /** The URL of every WebSocket the page closed (when `nodes` was given), in order. */
  closed: string[];
  close(): Promise<void>;
}

/** What a node of the test does with a frame instead of replying: say nothing, or hang up. */
export const DROP = Symbol("drop the frame: the node never answers");
export const HANGUP = Symbol("close the connection without an answer");

/**
 * A node the test stands for: the reply to each text the page sends (bytes make a binary frame).
 * The reply may be awaited, so that a test can hold an answer back while the page does something
 * else; `DROP` sends nothing and `HANGUP` closes the socket.
 */
export type NodeHandler = (
  text: string,
) => string | Buffer | typeof DROP | typeof HANGUP | Promise<string | Buffer | typeof DROP | typeof HANGUP>;

/**
 * Opens `path` of a fresh site. For a page that runs the SDK, resolves once the page has mounted
 * (its status leaves "loading").
 */
export async function open(
  browser: Browser,
  path: string,
  overrides: Record<string, Override> = {},
  init?: (() => void) | (() => void)[],
  nodes?: Record<string, NodeHandler>,
): Promise<Session> {
  const site = await serve(overrides);
  const context = await browser.newContext();
  const external: string[] = [];
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== site.origin) {
      external.push(url.href);
      return route.abort();
    }
    return route.continue();
  });
  const requests: Session["requests"] = [];
  context.on("request", (r) => requests.push({ url: r.url(), method: r.method(), headers: r.headers(), body: r.postData() }));
  // With `nodes`, every WebSocket the page opens is intercepted, whatever its URL: the URL is
  // recorded, a URL that names a node of the test is answered by its handler, and any other is
  // closed at once. The page's own connection to a real host never happens.
  const contacted: string[] = [];
  const sent: Session["sent"] = [];
  const closed: string[] = [];
  if (nodes !== undefined) {
    await context.routeWebSocket(/.*/, (ws) => {
      const url = ws.url();
      contacted.push(url);
      ws.onClose(() => closed.push(url));
      // The browser writes a URL in its normal form (a path of "/" after a bare host); the nodes of
      // the test are named as the user would type them.
      const named = Object.keys(nodes).find((k) => new URL(k).href === url);
      const handler = named === undefined ? undefined : nodes[named];
      if (handler === undefined) {
        ws.close({ code: 1008, reason: "no such node" });
        return;
      }
      ws.onMessage(async (message) => {
        const text = typeof message === "string" ? message : message.toString();
        sent.push({ url, text });
        // A handler that throws (the node of the test does not understand the frame) is a node
        // that hung up, not a crash of the test run.
        let reply: Awaited<ReturnType<NodeHandler>>;
        try {
          reply = await handler(text);
        } catch {
          ws.close({ code: 1011, reason: "the node of the test failed" });
          return;
        }
        if (reply === DROP) return;
        if (reply === HANGUP) {
          ws.close({ code: 1001, reason: "the node of the test hung up" });
          return;
        }
        ws.send(reply);
      });
    });
  }
  const page = await context.newPage();
  // context.route does not see WebSockets, and routeWebSocket replaces the page's WebSocket class
  // with a stand-in, so the page's policy would never be asked. The browser's own event fires for
  // a socket the browser creates, and not for one its policy blocks.
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));
  const errors: string[] = [];
  const consoleLog: string[] = [];
  page.on("console", (m) => {
    consoleLog.push(`${m.type()}: ${m.text()}`);
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => {
    errors.push(e.message);
    consoleLog.push(`pageerror: ${e.message}`);
  });
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: string[] };
    w.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => w.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  for (const f of init === undefined ? [] : [init].flat()) await page.addInitScript(f);
  await page.goto(`${site.origin}/${path}`);
  if (path === "index.html") await page.waitForSelector("#status[data-state='idle'], #status[data-state='error']");
  return {
    site,
    context,
    page,
    external,
    sockets,
    errors,
    console: consoleLog,
    requests,
    contacted,
    sent,
    closed,
    close: async () => {
      await context.close();
      await site.close();
    },
  };
}

// The golden vectors, read from disk, and the examples the page offers.
//
// The golden vectors name a synthetic token that is no kcc20.sil build, which no funding accepts
// (SDK_TEMPLATE_UNPINNED), so the page's examples are the vectors with the token of each KCC-20 leg
// pinned (demo/pin-examples.mjs, run by build.sh). `committedVectors` are the files of tests/vectors
// as committed; `termsVectors` are the examples the page loads, read from dist, and `vaultVector`
// gives their vault addresses as the SDK of dist computes them in Node (the committed vault files
// belong to the committed vectors, and are matched by the SDK's own tests).

export interface TermsVector {
  name: string;
  description?: string;
  canonical: string;
  terms: Record<string, unknown> & { network: string; cash_leg: { kind: string; amount: string }; asset_leg: { amount: string } };
  terms_hash: string;
}
export interface VaultVector {
  name: string;
  terms_hash: string;
  template_hash: string;
  asset_vault: { address?: string; script_hash?: string; refused?: string };
  cash_vault: { address?: string; script_hash?: string; refused?: string };
}

function readSet<T>(base: URL): T[] {
  return readdirSync(base)
    .filter((f) => f.endsWith(".json") && f !== "index.json")
    .sort()
    .map((f) => JSON.parse(readFileSync(new URL(f, base), "utf8")) as T);
}

/** The golden terms vectors as committed in tests/vectors/terms. */
export const committedVectors = readSet<TermsVector>(new URL("tests/vectors/terms/", repo));
/** The examples of the page (the vectors with their tokens pinned), read from dist. */
export const termsVectors = readSet<TermsVector>(new URL("examples/", dist));

export function termsVector(prefix: string): TermsVector {
  const found = termsVectors.filter((v) => v.name.startsWith(`${prefix}-`));
  if (found.length !== 1) throw new Error(`one terms vector ${prefix}`);
  return found[0];
}

export function committedVector(prefix: string): TermsVector {
  const found = committedVectors.filter((v) => v.name.startsWith(`${prefix}-`));
  if (found.length !== 1) throw new Error(`one committed terms vector ${prefix}`);
  return found[0];
}

/** The example file the page loads, as served: text and all. */
export function vectorText(prefix: string): string {
  return readFileSync(new URL(`examples/${termsVector(prefix).name}.json`, dist), "utf8");
}

/** The golden vector file as committed in tests/vectors/terms, text and all. */
export function committedVectorText(prefix: string): string {
  return readFileSync(new URL(`tests/vectors/terms/${committedVector(prefix).name}.json`, repo), "utf8");
}

/** What the tests use of the SDK that the page ships, run in Node (an oracle for the page). */
export interface NodeSdk {
  initSync(init: { module: Buffer }): unknown;
  Terms: {
    fromJson(terms: unknown): {
      validateStructure(): {
        fundingInstructions(options: unknown): any;
        instantiateForCreation(
          leg: 0 | 1,
          context: unknown,
          value: unknown,
        ): { address(): string; vault(): { scriptHash(): Uint8Array } };
      };
    };
  };
  templateCheck(): { prefix(): Uint8Array; hash(): Uint8Array };
}

/** The SDK of demo/dist, the very files the page loads, initialised in this process. */
export async function nodeSdk(): Promise<NodeSdk> {
  const sdk = (await import(new URL("sdk/index.js", dist).href)) as NodeSdk;
  sdk.initSync({ module: readFileSync(new URL("sdk/pkg/impulse_wasm_bg.wasm", dist)) });
  return sdk;
}

const sdkOfDist = await nodeSdk();

/**
 * The vault addresses, script hashes and template hash of an example of the page, as the SDK of
 * dist computes them in Node at the vectors' own creation score (a leg the terms do not escrow is
 * `refused: "TEMPLATE_NO_VAULT"`). The same code the page runs, in another process.
 */
export function vaultVector(prefix: string): VaultVector {
  const v = termsVector(prefix);
  const terms = sdkOfDist.Terms.fromJson(v.terms).validateStructure();
  const context = { network: v.terms.network, creation_daa: "400000000" };
  const leg = (i: 0 | 1) => {
    try {
      const f = terms.instantiateForCreation(i, context, { i_accept_the_risk: true });
      return { address: f.address(), script_hash: Buffer.from(f.vault().scriptHash()).toString("hex") };
    } catch (e) {
      return { refused: (e as { code?: string }).code ?? "?" };
    }
  };
  return {
    name: v.name,
    terms_hash: v.terms_hash,
    template_hash: Buffer.from(sdkOfDist.templateCheck().hash()).toString("hex"),
    asset_vault: leg(0),
    cash_vault: leg(1),
  };
}

/**
 * The first pinned kcc20.sil build, read from the Rust source that holds the list
 * (crates/impulse-core/src/verify/pins.rs), not from the SDK: what pin-examples.mjs must have
 * written into the page's examples.
 */
export function firstPinnedBuild(): { hash: string; prefix: number; suffix: number } {
  const source = readFileSync(new URL("crates/impulse-core/src/verify/pins.rs", repo), "utf8");
  const m = /pin\(\s*1,\s*1,\s*"([0-9a-f]{64})",\s*(\d+),\s*(\d+),?\s*\)/.exec(source);
  if (m === null) throw new Error("the first pinned build is not in pins.rs");
  return { hash: m[1], prefix: Number(m[2]), suffix: Number(m[3]) };
}
