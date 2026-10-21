// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The page's node client (`node.js`) on its own, in a real browser, against a scripted stand-in for
// the WebSocket class: the connection that is closed or fails before it opens, a node that does not
// answer, a node that hangs up with a request in flight, a frame that is not text, a node that
// fails the network or sync check (the connection is closed, not kept), and requests made at the
// same time (they go one at a time, in the order they were made). The client and the SDK are the
// real ones, served from demo/dist; the page's own script is swapped for this one.
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

const SCENARIOS = `
import init, * as sdk from "/sdk/index.js";
import { NodeClient } from "/node.js";
await init();

const info = (over = {}) => JSON.stringify({
  id: 1, method: "getServerInfo",
  params: { rpcApiVersion: 1, rpcApiRevision: 0, serverVersion: "x", networkId: "testnet-10", hasUtxoIndex: true, isSynced: true, virtualDaaScore: 5, ...over },
});

// A WebSocket the scenario drives by hand.
class Socket {
  static made = [];
  static plan = () => {};
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
    Socket.made.push(this);
    setTimeout(() => Socket.plan(this), 0);
  }
  send(text) { this.sent.push(text); }
  close() { if (this.readyState !== 3) { this.readyState = 3; this.closedByPage = true; } }
  open() { this.readyState = 1; this.onopen?.({}); }
  fail() { this.onerror?.({}); }
  hangup() { this.readyState = 3; this.onclose?.({}); }
  reply(data) { this.onmessage?.({ data }); }
  // The id the page used for the request it sent last, to answer it.
  lastId() { return JSON.parse(this.sent[this.sent.length - 1]).id; }
}

const settle = (promise) => promise.then(
  (value) => ({ ok: true, value }),
  (e) => ({ ok: false, code: e.code ?? "", message: e.message, afterSend: e.afterSend === true }),
);
const tick = (ms = 20) => new Promise((done) => setTimeout(done, ms));
const real = window.setTimeout.bind(window);
const quick = (on) => { window.setTimeout = on ? (f, ms, ...a) => real(f, ms >= 10000 ? 5 : ms, ...a) : real; };
const method = (text) => JSON.parse(text).method;

async function connected(url = "ws://127.0.0.1:1") {
  Socket.made = [];
  Socket.plan = (s) => {
    s.open();
    setTimeout(() => s.reply(info().replace('"id":1', '"id":' + s.lastId())), 0);
  };
  const client = new NodeClient(sdk, Socket);
  const result = await settle(client.connect(url, "testnet"));
  return { client, socket: Socket.made[0], result };
}

const out = {};

// The connection is closed by the far end before it opened, and fails before it opened.
Socket.made = [];
Socket.plan = (s) => s.hangup();
out.closedBeforeOpen = { ...(await settle(new NodeClient(sdk, Socket).connect("ws://127.0.0.1:1", "testnet"))), sockets: Socket.made.length };
Socket.made = [];
Socket.plan = (s) => s.fail();
out.failedBeforeOpen = await settle(new NodeClient(sdk, Socket).connect("ws://127.0.0.1:1", "testnet"));

// A node that never opens: the page gives up, and closes the socket it made.
Socket.made = [];
Socket.plan = () => {};
quick(true);
out.neverOpens = { ...(await settle(new NodeClient(sdk, Socket).connect("ws://127.0.0.1:1", "testnet"))), closedByPage: Socket.made[0].closedByPage === true };
quick(false);

// The control: a node that answers is connected, and says so.
{
  const { client, socket, result } = await connected();
  out.control = { result, connected: client.connected, network: client.network, url: client.url, sent: socket.sent.map(method) };
  client.close();
}

// A node on another network, and one that is not synced: refused, and the connection is not kept.
for (const [name, over] of [["otherNetwork", { networkId: "mainnet" }], ["notSynced", { isSynced: false }]]) {
  Socket.made = [];
  Socket.plan = (s) => {
    s.open();
    setTimeout(() => s.reply(info(over).replace('"id":1', '"id":' + s.lastId())), 0);
  };
  const client = new NodeClient(sdk, Socket);
  const result = await settle(client.connect("ws://127.0.0.1:1", "testnet"));
  out[name] = { result, connected: client.connected, url: client.url, closedByPage: Socket.made[0].closedByPage === true };
}

// A request in flight when the node hangs up, a frame that is not text, a reply that never comes.
{
  const { client, socket } = await connected();
  const pending = settle(client.exchange((i) => sdk.rpcRequest(i, "getBlockDagInfo")));
  await tick();
  socket.hangup();
  out.hangup = { ...(await pending), connected: client.connected };
}
{
  const { client, socket } = await connected();
  const pending = settle(client.exchange((i) => sdk.rpcRequest(i, "getBlockDagInfo")));
  await tick();
  socket.reply(new ArrayBuffer(2));
  out.binary = await pending;
  client.close();
}
{
  const { client } = await connected();
  quick(true);
  out.noAnswer = await settle(client.exchange((i) => sdk.rpcRequest(i, "getBlockDagInfo")));
  quick(false);
  client.close();
}
// Not connected: nothing is sent, so there is no "after send".
out.notConnected = await settle(new NodeClient(sdk, Socket).exchange((i) => sdk.rpcRequest(i, "getBlockDagInfo")));

// Two requests at once: the second is not sent until the first has its answer, and the answers
// go to the requests they answer.
{
  const { client, socket } = await connected();
  const first = settle(client.call("getBlockDagInfo"));
  const second = settle(client.call("getServerInfo"));
  await tick();
  const before = socket.sent.map(method);
  socket.reply(JSON.stringify({ id: socket.lastId(), method: "getBlockDagInfo", params: { virtualDaaScore: 7, sink: "ab".repeat(32) } }));
  await tick();
  const middle = socket.sent.map(method);
  socket.reply(info({ virtualDaaScore: 9 }).replace('"id":1', '"id":' + socket.lastId()));
  const [a, b] = await Promise.all([first, second]);
  out.serial = {
    before, middle, after: socket.sent.map(method),
    first: a.ok ? a.value.reply.virtual_daa_score : a,
    second: b.ok ? b.value.reply.virtual_daa_score : b,
  };
  client.close();
}
// Closed while still opening (the page's network switched): the attempt is refused, the socket is
// closed by the page, and an open that comes later attaches nothing.
{
  Socket.made = [];
  Socket.plan = () => {};
  const client = new NodeClient(sdk, Socket);
  const pending = settle(client.connect("ws://127.0.0.1:1", "testnet"));
  await tick();
  const connecting = client.connecting;
  client.close();
  const socket = Socket.made[0];
  socket.readyState = 1;
  socket.onopen?.({});
  out.closedWhileOpening = { ...(await pending), connecting, after: client.connecting, connected: client.connected, network: client.network, closedByPage: socket.closedByPage === true, sent: socket.sent.length };
}
// A connection checked for testnet while the page acts on mainnet: no request is sent.
{
  Socket.made = [];
  Socket.plan = (s) => {
    s.open();
    setTimeout(() => s.reply(info().replace('"id":1', '"id":' + s.lastId())), 0);
  };
  const page = { network: "testnet" };
  const client = new NodeClient(sdk, Socket, () => page.network);
  const connectedOk = (await settle(client.connect("ws://127.0.0.1:1", "testnet"))).ok;
  page.network = "mainnet";
  const refused = await settle(client.call("getBlockDagInfo"));
  out.otherPageNetwork = { connectedOk, ...refused, sent: Socket.made[0].sent.map(method) };
  client.close();
}
window.__results = out;
`;

interface Settled {
  ok: boolean;
  code?: string;
  message?: string;
  afterSend?: boolean;
  value?: unknown;
}

test("the node client: a connection that closes or fails before it opens, a node that never answers, one that hangs up or sends a frame that is not text, and one that fails the check", async () => {
  const index = readFileSync(new URL("index.html", dist), "utf8").replace(
    '<script type="module" src="main.js"></script>',
    '<script type="module" src="component.js"></script>',
  );
  const s = await open(browser, "component.html", { "/component.html": index, "/component.js": SCENARIOS });
  try {
    await s.page.waitForFunction(() => (window as unknown as { __results?: unknown }).__results !== undefined, undefined, { timeout: 30_000 });
    assert.deepEqual(s.errors, []);
    const r = (await s.page.evaluate(() => (window as unknown as { __results: unknown }).__results)) as Record<string, any>;

    // Before the connection opens.
    assert.deepEqual(r.closedBeforeOpen.ok, false);
    assert.equal(r.closedBeforeOpen.message, "The connection to ws://127.0.0.1:1 was closed before it opened.");
    assert.equal(r.closedBeforeOpen.afterSend, false);
    assert.equal(r.failedBeforeOpen.message, "The connection to ws://127.0.0.1:1 failed.");
    assert.equal(r.neverOpens.message, "The node at ws://127.0.0.1:1 did not answer within 10 s.");
    assert.equal(r.neverOpens.closedByPage, true, "the page closes the socket it gave up on");
    // Control: a node that answers.
    assert.equal((r.control.result as Settled).ok, true);
    assert.deepEqual(
      [r.control.connected, r.control.network, r.control.url, r.control.sent],
      [true, "testnet", "ws://127.0.0.1:1", ["getServerInfo"]],
    );

    // A node on the wrong network, or not synced: refused with the SDK's code, and not kept.
    for (const [name, code] of [
      ["otherNetwork", "SDK_NODE_NETWORK_MISMATCH"],
      ["notSynced", "SDK_NODE_NOT_SYNCED"],
    ] as const) {
      assert.equal(r[name].result.code, code, name);
      assert.equal(r[name].connected, false, `${name}: the connection is not kept`);
      assert.equal(r[name].url, null, name);
      assert.equal(r[name].closedByPage, true, `${name}: the page closed the socket`);
    }

    // After a request was sent, a failure says so (the node may have acted on it) ...
    assert.deepEqual([r.hangup.ok, r.hangup.message, r.hangup.afterSend, r.hangup.connected], [false, "The connection to the node closed.", true, false]);
    assert.deepEqual([r.binary.ok, r.binary.message, r.binary.afterSend], [false, "The node sent something that is not text.", true]);
    assert.deepEqual([r.noAnswer.ok, r.noAnswer.message, r.noAnswer.afterSend], [false, "The node did not answer within 20 s.", true]);
    // ... and before one was sent, it does not.
    assert.deepEqual([r.notConnected.ok, r.notConnected.message, r.notConnected.afterSend], [false, "Not connected to a node.", false]);

    // Requests at once go one at a time, in order, and each gets its own answer.
    assert.deepEqual(r.serial.before, ["getServerInfo", "getBlockDagInfo"], "the second request waits for the first");
    assert.deepEqual(r.serial.middle, ["getServerInfo", "getBlockDagInfo", "getServerInfo"], "and goes when the first is answered");
    assert.deepEqual([r.serial.first, r.serial.second], ["7", "9"]);

    // Closed while opening: refused, the socket closed, nothing attached when it opens later.
    assert.deepEqual(
      [r.closedWhileOpening.ok, r.closedWhileOpening.message, r.closedWhileOpening.afterSend],
      [false, "The connection to ws://127.0.0.1:1 was closed before it opened: the page closed it.", false],
    );
    assert.deepEqual(
      [r.closedWhileOpening.connecting, r.closedWhileOpening.after, r.closedWhileOpening.connected, r.closedWhileOpening.network],
      [true, false, false, null],
    );
    assert.equal(r.closedWhileOpening.closedByPage, true);
    assert.equal(r.closedWhileOpening.sent, 0, "nothing is sent on a socket the page abandoned");
    // A connection checked for another network than the page's: the request is refused unsent.
    assert.equal(r.otherPageNetwork.connectedOk, true);
    assert.deepEqual(
      [r.otherPageNetwork.ok, r.otherPageNetwork.message, r.otherPageNetwork.afterSend],
      [false, "The node was checked for testnet; the page acts on mainnet. Connect again.", false],
    );
    assert.deepEqual(r.otherPageNetwork.sent, ["getServerInfo"]);
  } finally {
    await s.close();
  }
});
