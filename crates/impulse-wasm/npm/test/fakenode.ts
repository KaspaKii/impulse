// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// An offline stand-in for a kaspad that speaks wRPC JSON, for the tests of the SDK and of the
// browser demo. It answers the six calls the demo makes (getServerInfo, getBlockDagInfo,
// getUtxosByAddresses, submitTransaction, getMempoolEntry, getVirtualChainFromBlockV2) from a
// UTXO set the test fills, and it accepts a submitted transaction into a chain block of its own.
//
// What it checks of a submitted transaction: that the JSON is a transaction (the SDK's reader
// hashes it), that every input spends a UTXO it holds that is not spent yet, that the inputs hold
// at least what the outputs pay, that the fee is at least `minFee`, and that the lock time is
// below its virtual DAA score (the node rule of spec/TRANSACTIONS.md). It records what it
// received. What it does NOT do: run any script, verify any signature, compute any mass or check
// the storage mass commitment. A transaction it accepts is not thereby valid on a real node; the
// engine tests of impulse-core run the scripts, and a run against a real node is the key
// holder's (the exit test of I11).
//
// It builds its replies by hand from the field names of the pinned rusty-kaspa types. The SDK's
// native tests (src/rpc_tests.rs) check that the SDK reads what those types write; this file
// shares no code with the SDK's readers, so the two can disagree and a test notices.
//
// Amounts are JSON numbers, as the node writes them, and so must stay below 2^53 here; the tests
// use small ones.
import { createHash } from "node:crypto";

/** The part of the SDK this file uses. */
export interface FakeNodeSdk {
  rpcReply(text: string, id: number, method: string, filter?: string | null): unknown;
  decodeFetched(
    fetched: { txid: string; raw: string; spent: ({ version: number; script: string } | null)[] },
    txid: string,
    network: "mainnet" | "testnet",
  ): unknown;
}

export interface ScriptPublicKey {
  version: number;
  script: string;
}

/** A UTXO as the test states it (the SDK's UtxoJson). */
export interface FakeUtxo {
  transaction_id: string;
  index: number;
  amount: string;
  script_public_key: ScriptPublicKey;
  block_daa_score: string;
  is_coinbase: boolean;
  covenant_id: string | null;
}

interface Held {
  utxo: FakeUtxo;
  address: string;
  spent: boolean;
}

/** A transaction the node accepted, with what it knew of the inputs it spent. */
export interface AcceptedTransaction {
  txid: string;
  block: string;
  daaScore: number;
  json: RpcTransactionJson;
  spent: Held[];
  /** The decoder's reading of it, bound to the spent scriptPublicKeys; null when it spends no vault. */
  decoded: unknown;
}

interface RpcInput {
  previousOutpoint: { transactionId: string; index: number };
  signatureScript: string;
  sequence: number;
  sigOpCount: number;
  computeBudget: number;
  verboseData: unknown;
}

interface RpcOutput {
  value: number;
  scriptPublicKey: string;
  verboseData: unknown;
  covenant: { authorizingInput: number; covenantId: string } | null;
}

export interface RpcTransactionJson {
  version: number;
  inputs: RpcInput[];
  outputs: RpcOutput[];
  lockTime: number;
  subnetworkId: string;
  gas: number;
  payload: string;
  storageMass: number;
  mass: number;
  verboseData: unknown;
}

const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const key = (txid: string, index: number) => `${txid}:${index}`;
const spkText = (s: ScriptPublicKey) => `${s.version.toString(16).padStart(4, "0")}${s.script}`;

export class FakeNode {
  networkId = "testnet-10";
  synced = true;
  hasUtxoIndex = true;
  virtualDaa = 1_500_000;
  minFee = 1;
  /** Every request received, in order. */
  readonly received: { id: number; method: string; params: Record<string, unknown> }[] = [];
  /** Every transaction accepted, in order. */
  readonly accepted: AcceptedTransaction[] = [];
  /** When set, the next submitTransaction is answered with this error and nothing is accepted. */
  rejectNext: string | null = null;
  /** When false a submitted transaction waits in the mempool instead of being accepted. */
  autoAccept = true;
  /** When set, getVirtualChainFromBlockV2 answers at most this many chain blocks a call, as a node pages a long walk. */
  batchSize: number | null = null;
  readonly genesis = sha("genesis");

  private readonly held = new Map<string, Held>();
  private readonly mempool = new Map<string, { json: RpcTransactionJson; fee: number; spent: Held[] }>();
  private readonly blocks: { hash: string; daaScore: number; txs: AcceptedTransaction[] }[] = [];
  /** Chain blocks a reorg took off the chain, with the length of the chain they were cut from. */
  private readonly stale: { hashes: string[]; fork: number }[] = [];

  private readonly sdk: FakeNodeSdk;
  private readonly addressOf: (spk: ScriptPublicKey) => string;
  private readonly network: "mainnet" | "testnet";

  /** `addressOf` turns a scriptPublicKey into the address the node reports for it. */
  constructor(sdk: FakeNodeSdk, addressOf: (spk: ScriptPublicKey) => string, network: "mainnet" | "testnet" = "testnet") {
    this.sdk = sdk;
    this.addressOf = addressOf;
    this.network = network;
  }

  /** Puts a UTXO into the set, as if a transaction long accepted had made it. */
  add(utxo: FakeUtxo): void {
    this.held.set(key(utxo.transaction_id, utxo.index), {
      utxo,
      address: this.addressOf(utxo.script_public_key),
      spent: false,
    });
  }

  /** The UTXOs at an address that are not spent. */
  at(address: string): FakeUtxo[] {
    return [...this.held.values()].filter((h) => !h.spent && h.address === address).map((h) => h.utxo);
  }

  /** The hash of the chain block after which `n` blocks have been added (0 is the genesis). */
  blockHash(n: number): string {
    return n === 0 ? this.genesis : this.blocks[n - 1].hash;
  }

  get sink(): string {
    return this.blockHash(this.blocks.length);
  }

  /** Answers one frame. A frame that is not a request is an error of the test. */
  handle(text: string): string {
    const frame = JSON.parse(text) as { id: number; method: string; params: Record<string, unknown> };
    this.received.push({ id: frame.id, method: frame.method, params: frame.params });
    try {
      return this.answer(frame.id, frame.method, frame.params);
    } catch (e) {
      if (e instanceof NodeError) return JSON.stringify({ id: frame.id, error: { code: -32000, message: e.message } });
      throw e;
    }
  }

  private ok(id: number, method: string, params: unknown): string {
    return JSON.stringify({ id, method, params });
  }

  private answer(id: number, method: string, params: Record<string, unknown>): string {
    switch (method) {
      case "getServerInfo":
        return this.ok(id, method, {
          rpcApiVersion: 1,
          rpcApiRevision: 0,
          serverVersion: "fake",
          networkId: this.networkId,
          hasUtxoIndex: this.hasUtxoIndex,
          isSynced: this.synced,
          virtualDaaScore: this.virtualDaa,
        });
      case "getBlockDagInfo":
        return this.ok(id, method, {
          network: this.networkId,
          blockCount: this.blocks.length,
          headerCount: this.blocks.length,
          tipHashes: [this.sink],
          difficulty: 1,
          pastMedianTime: 0,
          virtualParentHashes: [this.sink],
          pruningPointHash: "00".repeat(32),
          virtualDaaScore: this.virtualDaa,
          sink: this.sink,
        });
      case "getUtxosByAddresses": {
        if (!this.hasUtxoIndex) throw new NodeError("the node has no UTXO index");
        const addresses = params.addresses as string[];
        const entries = [...this.held.values()]
          .filter((h) => !h.spent && addresses.includes(h.address))
          .map((h) => ({
            address: h.address,
            outpoint: { transactionId: h.utxo.transaction_id, index: h.utxo.index },
            utxoEntry: {
              amount: Number(h.utxo.amount),
              scriptPublicKey: spkText(h.utxo.script_public_key),
              blockDaaScore: Number(h.utxo.block_daa_score),
              isCoinbase: h.utxo.is_coinbase,
              covenantId: h.utxo.covenant_id,
            },
          }));
        return this.ok(id, method, { entries });
      }
      case "submitTransaction":
        return this.submit(id, method, params);
      case "getMempoolEntry": {
        const entry = this.mempool.get(params.transactionId as string);
        // The words of kaspad's RpcError::TransactionNotFound (rusty-kaspa rpc/core/src/error.rs).
        if (!entry) throw new NodeError(`Transaction ${String(params.transactionId)} not found`);
        return this.ok(id, method, {
          mempoolEntry: { fee: entry.fee, transaction: entry.json, isOrphan: false },
        });
      }
      case "getVirtualChainFromBlockV2": {
        const start = params.startHash as string;
        const known = [this.genesis, ...this.blocks.map((b) => b.hash)];
        // A walk that began on blocks a reorg has since removed is told so: the removed blocks from
        // the one it named back to the fork, and the chain from the fork on (kaspad's answer).
        const cut = this.stale.find((s) => s.hashes.includes(start));
        const at = cut ? cut.fork : known.indexOf(start);
        if (at < 0) throw new NodeError(`Block ${start} not found`);
        const removed = cut ? cut.hashes.slice(0, cut.hashes.indexOf(start) + 1).reverse() : [];
        const rest = this.blocks.slice(at);
        const added = this.batchSize === null ? rest : rest.slice(0, this.batchSize);
        return this.ok(id, method, {
          removedChainBlockHashes: removed,
          addedChainBlockHashes: added.map((b) => b.hash),
          chainBlockAcceptedTransactions: added.map((b) => ({
            chainBlockHeader: { hash: b.hash, daaScore: b.daaScore },
            acceptedTransactions: b.txs.map((t) => this.optional(t)),
          })),
        });
      }
      default:
        throw new NodeError(`the fake node does not answer ${method}`);
    }
  }

  /** The accepted transaction as `RpcOptionalTransaction` at full verbosity writes it. */
  private optional(t: AcceptedTransaction): unknown {
    return {
      ...t.json,
      inputs: t.json.inputs.map((input, i) => ({
        ...input,
        verboseData: {
          utxoEntry: {
            amount: Number(t.spent[i].utxo.amount),
            scriptPublicKey: spkText(t.spent[i].utxo.script_public_key),
            blockDaaScore: Number(t.spent[i].utxo.block_daa_score),
            isCoinbase: t.spent[i].utxo.is_coinbase,
            covenantId: t.spent[i].utxo.covenant_id,
          },
        },
      })),
      verboseData: { transactionId: t.txid, hash: t.txid, computeMass: 0, blockHash: t.block, blockTime: 0 },
    };
  }

  private submit(id: number, method: string, params: Record<string, unknown>): string {
    if (this.rejectNext !== null) {
      const why = this.rejectNext;
      this.rejectNext = null;
      throw new NodeError(why);
    }
    const tx = params.transaction as RpcTransactionJson;
    if (params.allowOrphan !== false) throw new NodeError("orphans are not accepted");
    // The transaction's ID, from the SDK's reader of the very JSON received.
    const probe = JSON.stringify({ id: 0, method: "getMempoolEntry", params: { mempoolEntry: { fee: 0, transaction: tx, isOrphan: false } } });
    let fetched: { txid: string; raw: string; spent: null[] };
    try {
      fetched = (this.sdk.rpcReply(probe, 0, "getMempoolEntry") as { transaction: typeof fetched }).transaction;
    } catch (e) {
      throw new NodeError(`not a transaction: ${(e as Error).message}`);
    }
    if (this.mempool.has(fetched.txid) || this.accepted.some((a) => a.txid === fetched.txid)) {
      throw new NodeError(`Transaction ${fetched.txid} is already in the mempool or accepted`);
    }
    const spent: Held[] = [];
    let inputs = 0;
    for (const input of tx.inputs) {
      const k = key(input.previousOutpoint.transactionId, input.previousOutpoint.index);
      const h = this.held.get(k);
      if (!h || h.spent) throw new NodeError(`Transaction ${fetched.txid} spends ${k}, which is missing or spent`);
      if (spent.includes(h)) throw new NodeError(`Transaction ${fetched.txid} spends ${k} twice`);
      spent.push(h);
      inputs += Number(h.utxo.amount);
    }
    const outputs = tx.outputs.reduce((sum, o) => sum + o.value, 0);
    const fee = inputs - outputs;
    if (fee < this.minFee) throw new NodeError(`Transaction ${fetched.txid} pays a fee of ${fee}, below ${this.minFee}`);
    if (tx.lockTime !== 0 && !(tx.lockTime < this.virtualDaa)) {
      throw new NodeError(`Transaction ${fetched.txid} is not final: lock time ${tx.lockTime}, virtual DAA score ${this.virtualDaa}`);
    }
    if (tx.inputs.some((input) => input.signatureScript === "")) {
      // An input that reveals nothing cannot be spent by a script: the transaction is unsigned.
      throw new NodeError(`Transaction ${fetched.txid} has an input with no signature script`);
    }
    if (!this.autoAccept) {
      this.mempool.set(fetched.txid, { json: tx, fee, spent });
      return this.ok(id, method, { transactionId: fetched.txid });
    }
    this.accept(fetched, tx, spent);
    return this.ok(id, method, { transactionId: fetched.txid });
  }

  /** Accepts a mempool transaction into a new chain block (for a test with `autoAccept` off). */
  mine(txid: string): void {
    const entry = this.mempool.get(txid);
    if (!entry) throw new Error(`${txid} is not in the mempool`);
    this.mempool.delete(txid);
    const probe = JSON.stringify({ id: 0, method: "getMempoolEntry", params: { mempoolEntry: { fee: 0, transaction: entry.json, isOrphan: false } } });
    const fetched = (this.sdk.rpcReply(probe, 0, "getMempoolEntry") as { transaction: { txid: string; raw: string; spent: null[] } }).transaction;
    this.accept(fetched, entry.json, entry.spent);
  }

  /** Adds a chain block that carries no transaction. Returns its hash. */
  mineEmpty(): string {
    const hash = sha(`block ${this.blocks.length + 1} empty`);
    this.blocks.push({ hash, daaScore: this.virtualDaa, txs: [] });
    return hash;
  }

  /**
   * A reorg: the chain block `hash` and every block after it leave the chain. The transactions they
   * accepted are accepted again in new chain blocks (`again`), or go back to the mempool.
   */
  reorg(hash: string, again = true): void {
    const at = this.blocks.findIndex((b) => b.hash === hash);
    if (at < 0) throw new Error(`${hash} is not a chain block`);
    const removed = this.blocks.splice(at);
    this.stale.push({ hashes: removed.map((b) => b.hash), fork: at });
    for (const block of removed) {
      for (const record of block.txs) {
        if (again) {
          const fresh = sha(`block ${this.blocks.length + 1} ${record.txid} again`);
          record.block = fresh;
          this.blocks.push({ hash: fresh, daaScore: this.virtualDaa, txs: [record] });
        } else {
          const index = this.accepted.indexOf(record);
          if (index >= 0) this.accepted.splice(index, 1);
          this.mempool.set(record.txid, { json: record.json, fee: 0, spent: record.spent });
        }
      }
    }
  }

  private accept(fetched: { txid: string; raw: string; spent: null[] }, tx: RpcTransactionJson, spent: Held[]): void {
    const block = sha(`block ${this.blocks.length + 1} ${fetched.txid}`);
    const daaScore = this.virtualDaa;
    let decoded: unknown = null;
    try {
      decoded = this.sdk.decodeFetched(
        { ...fetched, spent: spent.map((h) => h.utxo.script_public_key) },
        fetched.txid,
        this.network,
      );
    } catch {
      // Not a vault spend: nothing to decode.
    }
    for (const h of spent) h.spent = true;
    tx.outputs.forEach((o, index) => {
      const version = Number.parseInt(o.scriptPublicKey.slice(0, 4), 16);
      const spk = { version, script: o.scriptPublicKey.slice(4) };
      this.add({
        transaction_id: fetched.txid,
        index,
        amount: String(o.value),
        script_public_key: spk,
        block_daa_score: String(daaScore),
        is_coinbase: false,
        covenant_id: o.covenant?.covenantId ?? null,
      });
    });
    const record: AcceptedTransaction = { txid: fetched.txid, block, daaScore, json: tx, spent, decoded };
    this.accepted.push(record);
    this.blocks.push({ hash: block, daaScore, txs: [record] });
  }
}

class NodeError extends Error {}

/** A `getUtxosByAddresses` reply frame for these UTXOs, as a test hands it to the plan builders. */
export function utxosFrame(id: number, utxos: FakeUtxo[], addressOf: (spk: ScriptPublicKey) => string): string {
  return JSON.stringify({
    id,
    method: "getUtxosByAddresses",
    params: {
      entries: utxos.map((u) => ({
        address: addressOf(u.script_public_key),
        outpoint: { transactionId: u.transaction_id, index: u.index },
        utxoEntry: {
          amount: Number(u.amount),
          scriptPublicKey: spkText(u.script_public_key),
          blockDaaScore: Number(u.block_daa_score),
          isCoinbase: u.is_coinbase,
          covenantId: u.covenant_id,
        },
      })),
    },
  });
}
