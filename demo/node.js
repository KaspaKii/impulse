// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The page's one connection: a WebSocket to the wRPC JSON address the user typed. Requests are
// written by the SDK (`rpcRequest`, `rpcSubmitRequest`) and replies are read by the SDK
// (`rpcReply`), as text, so that nothing here parses a number or decides what a reply means. The
// URL is checked by the SDK before a socket is opened (`checkNodeUrl`: ws or wss, and on mainnet a
// private link), and the node by the SDK once it answers (`checkNode`: the network the page acts on,
// synced). Requests go one at a time, in the order they were made; a reply that is not the reply
// to the request in flight is the SDK's refusal. An error after a request was sent carries
// `afterSend`: the node may have acted on it. Nothing is sent that the page did not write for a reason named in its UI: the
// calls of `sdk.rpcMethods()`, and the signed transaction the user submits.

const OPEN_TIMEOUT_MS = 10_000;
const REPLY_TIMEOUT_MS = 20_000;

export class NodeClient {
  #sdk;
  #WebSocket;
  #socket = null;
  /** The connection still opening: `{ socket, abort }`, else null. `close()` aborts it. */
  #pending = null;
  #pageNetwork;
  #waiting = null;
  #queue = Promise.resolve();
  #nextId = 1;
  /** The URL of the open connection, else null. */
  url = null;
  /** The network the connection was checked for ("mainnet" or "testnet"). */
  network = null;

  /**
   * `pageNetwork`, if given, returns the network the page acts on now: a request is refused, and
   * nothing sent, while it differs from the network the connection was checked for.
   */
  constructor(sdk, WebSocketClass = globalThis.WebSocket, pageNetwork = null) {
    this.#sdk = sdk;
    this.#WebSocket = WebSocketClass;
    this.#pageNetwork = pageNetwork;
  }

  get connected() {
    return this.#socket !== null && this.#socket.readyState === 1;
  }

  /** A connection is still opening. */
  get connecting() {
    return this.#pending !== null;
  }

  /**
   * Opens the connection to `url` for `network` and checks the node. Refuses before any socket is
   * opened if the URL is not allowed. Returns the checked reply to `getServerInfo`.
   */
  async connect(url, network) {
    this.close();
    this.#sdk.checkNodeUrl(url, network);
    const socket = new this.#WebSocket(url);
    await new Promise((resolve, reject) => {
      const settle = (f) => {
        clearTimeout(timer);
        if (this.#pending !== null && this.#pending.socket === socket) this.#pending = null;
        f();
      };
      const timer = setTimeout(() => {
        settle(() => reject(new Error(`The node at ${url} did not answer within ${OPEN_TIMEOUT_MS / 1000} s.`)));
        socket.close();
      }, OPEN_TIMEOUT_MS);
      socket.onopen = () => settle(resolve);
      socket.onerror = () => settle(() => reject(new Error(`The connection to ${url} failed.`)));
      // A socket that is closed before it opened (refused by the far end) says so by closing.
      socket.onclose = () => settle(() => reject(new Error(`The connection to ${url} was closed before it opened.`)));
      // `close()` while the socket is still opening (the network switched, another connect): the
      // socket is closed and never becomes the connection.
      this.#pending = {
        socket,
        abort: () => {
          socket.onopen = socket.onerror = socket.onclose = null;
          settle(() => reject(new Error(`The connection to ${url} was closed before it opened: the page closed it.`)));
          socket.close();
        },
      };
    });
    socket.onmessage = (event) => {
      const waiting = this.#waiting;
      this.#waiting = null;
      if (waiting === null) return;
      if (typeof event.data !== "string") waiting.reject(new Error("The node sent something that is not text."));
      else waiting.resolve(event.data);
    };
    socket.onclose = () => {
      this.#socket = null;
      this.url = null;
      const waiting = this.#waiting;
      this.#waiting = null;
      if (waiting) waiting.reject(new Error("The connection to the node closed."));
    };
    this.#socket = socket;
    this.url = url;
    this.network = network;
    try {
      return await this.serverInfo();
    } catch (e) {
      this.close();
      throw e;
    }
  }

  close() {
    const pending = this.#pending;
    this.#pending = null;
    if (pending) pending.abort();
    const socket = this.#socket;
    this.#socket = null;
    this.url = null;
    this.network = null;
    if (socket) {
      socket.onclose = null;
      socket.close();
    }
    const waiting = this.#waiting;
    this.#waiting = null;
    if (waiting) waiting.reject(new Error("The connection to the node was closed."));
  }

  /**
   * Sends the request that `write(id)` makes and returns `{ id, text }`, the text of the reply.
   * Requests are serialised: one is in flight at a time.
   */
  exchange(write) {
    const run = async () => {
      const socket = this.#socket;
      if (socket === null || socket.readyState !== 1) throw new Error("Not connected to a node.");
      const page = this.#pageNetwork === null ? this.network : this.#pageNetwork();
      if (page !== this.network) {
        throw new Error(`The node was checked for ${this.network}; the page acts on ${page}. Connect again.`);
      }
      const id = this.#nextId++;
      const request = write(id);
      const reply = new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          this.#waiting = null;
          reject(new Error(`The node did not answer within ${REPLY_TIMEOUT_MS / 1000} s.`));
        }, REPLY_TIMEOUT_MS);
        this.#waiting = {
          resolve: (text) => {
            clearTimeout(timer);
            resolve(text);
          },
          reject: (e) => {
            clearTimeout(timer);
            reject(e);
          },
        };
      });
      socket.send(request);
      try {
        return { id, text: await reply };
      } catch (e) {
        // The request has left this page: whatever went wrong now (no answer in time, a closed
        // connection, a frame that is not text), the node may have acted on it. The caller that
        // sent something that matters (the signed transaction) reads this.
        if (e && typeof e === "object") e.afterSend = true;
        throw e;
      }
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.catch(() => {});
    return next;
  }

  /** One of the node calls, read by the SDK: `{ id, text, reply }`. */
  async call(method, argument = null) {
    const { id, text } = await this.exchange((i) => this.#sdk.rpcRequest(i, method, argument));
    return { id, text, reply: this.#sdk.rpcReply(text, id, method) };
  }

  /** The node's answer about itself, checked for the network the connection was made for. */
  async serverInfo() {
    const { reply } = await this.call("getServerInfo");
    this.#sdk.checkNode(reply, this.network);
    return reply;
  }
}
