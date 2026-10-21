// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Test scaffolding shared by the TypeScript tests: loads the package entry once per test
// process and reads the committed golden vectors. The SDK itself is index.js; nothing here is
// SDK logic.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import * as sdk from "../index.js";
import type { DestinationJson, ImpulseError, PartyJson, TermsJson } from "../index.js";

export type Sdk = typeof sdk;

/** The repository root. */
export const root = new URL("../../../../", import.meta.url);
/** The compiled module the package ships. */
export const wasmUrl = new URL("../pkg/impulse_wasm_bg.wasm", import.meta.url);

let counting = false;

/**
 * The package entry, initialised from the shipped wasm bytes. `Wallet.generate` is wrapped to
 * count the keys this process asks for in `globalThis.__rngExpected`, which rng-count.mjs reports
 * beside the draws it saw: ci.sh requires the two to be equal in every test process, so the only
 * randomness the module draws is for a key a test asked for.
 */
export function load(): Sdk {
  sdk.initSync({ module: readFileSync(wasmUrl) });
  if (!counting) {
    counting = true;
    const real = sdk.Wallet.generate;
    Object.defineProperty(sdk.Wallet, "generate", {
      configurable: true,
      writable: true,
      value: function generate(this: unknown): ReturnType<typeof real> {
        const g = globalThis as { __rngExpected?: number };
        g.__rngExpected = (g.__rngExpected ?? 0) + 1;
        return real.call(this);
      },
    });
  }
  return sdk;
}

export interface TermsVector {
  name: string;
  description: string;
  terms: TermsJson;
  canonical: string;
  terms_hash: string;
}

export interface VaultLeg {
  leg_index: number;
  redeem_script?: string;
  script_hash?: string;
  address?: string;
  refused?: string;
}

export interface VaultVector {
  name: string;
  terms_hash: string;
  template_hash: string;
  asset_vault: VaultLeg;
  cash_vault: VaultLeg;
}

/** The files of one vector set, in name order. */
export function vectorFiles(set: "terms" | "vaults" | "ipst"): string[] {
  return readdirSync(new URL(`tests/vectors/${set}/`, root)).sort();
}

function readSet<T>(set: "terms" | "vaults"): T[] {
  const dir = new URL(`tests/vectors/${set}/`, root);
  return vectorFiles(set)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(readFileSync(new URL(f, dir), "utf8")) as T);
}

/** Every committed terms vector, in file order. */
export const termsVectors: TermsVector[] = readSet<TermsVector>("terms");
/** Every committed vault vector, in file order. */
export const vaultVectors: VaultVector[] = readSet<VaultVector>("vaults");

/** The terms vector whose file name starts with `prefix` (for example "02"). */
export function termsVector(prefix: string): TermsVector {
  const found = termsVectors.filter((v) => v.name.startsWith(`${prefix}-`));
  assert.equal(found.length, 1, `one terms vector ${prefix}`);
  return found[0];
}

/** The vault vector whose file name starts with `prefix`. */
export function vaultVector(prefix: string): VaultVector {
  const found = vaultVectors.filter((v) => v.name.startsWith(`${prefix}-`));
  assert.equal(found.length, 1, `one vault vector ${prefix}`);
  return found[0];
}

/** One committed IPST vector (tests/vectors/ipst): the file's `ipst` object, parsed and as text. */
export interface IpstVectorFile {
  file: string;
  name: string;
  description: string;
  /** The `ipst` object of the file, parsed. */
  doc: IpstDoc;
  /** The `ipst` object as text, de-indented by the two spaces it sits at in the file: exactly what `Ipst.toJson()` writes. */
  text: string;
}

export interface IpstInputDoc {
  transaction_id: string;
  index: number;
  sequence: string;
  compute_budget: number;
  utxo: {
    amount: string;
    script_public_key: { version: number; script: string };
    block_daa_score: string;
    is_coinbase: boolean;
    covenant_id: string | null;
  };
  signer: string | null;
  sighash: string | null;
  signature: string | null;
}

export interface IpstDoc {
  ipst: number;
  terms: string;
  lock_time: string;
  inputs: IpstInputDoc[];
  outputs: { value: string; script_public_key: { version: number; script: string } }[];
}

/** Every committed IPST vector, in file order. */
export const ipstVectors: IpstVectorFile[] = vectorFiles("ipst").map((file) => {
  const full = readFileSync(new URL(`tests/vectors/ipst/${file}`, root), "utf8");
  const parsed = JSON.parse(full) as { name: string; description: string; ipst: IpstDoc };
  const start = full.indexOf('"ipst": {') + '"ipst": '.length;
  const body = full.slice(start, full.lastIndexOf("\n}"));
  const text = body.split("\n").map((line, i) => (i === 0 ? line : line.replace(/^ {2}/, ""))).join("\n") + "\n";
  return { file, name: parsed.name, description: parsed.description, doc: parsed.ipst, text };
});

/** The IPST vector whose file name starts with `prefix` (for example "02"). */
export function ipstVector(prefix: string): IpstVectorFile {
  const found = ipstVectors.filter((v) => v.file.startsWith(`${prefix}-`));
  assert.equal(found.length, 1, `one IPST vector ${prefix}`);
  return found[0];
}

export interface PinnedBuild {
  maxCovIns: number;
  maxCovOuts: number;
  hash: string;
  prefix: number;
  suffix: number;
}

/**
 * The pinned kcc20.sil builds, read from the Rust source that holds them
 * (crates/impulse-core/src/verify/pins.rs), not from the SDK: the expectation of every test of the
 * pinned-template check.
 */
export const pinnedBuilds: PinnedBuild[] = [
  ...readFileSync(new URL("crates/impulse-core/src/verify/pins.rs", root), "utf8").matchAll(
    /pin\(\s*(\d+),\s*(\d+),\s*"([0-9a-f]{64})",\s*(\d+),\s*(\d+),?\s*\)/g,
  ),
].map((m) => ({ maxCovIns: Number(m[1]), maxCovOuts: Number(m[2]), hash: m[3], prefix: Number(m[4]), suffix: Number(m[5]) }));

/**
 * The terms with every KCC-20 leg's template replaced by the first pinned build. The golden vectors
 * name a synthetic token (a227fc3a, 40+1420) that is no kcc20.sil build, so no funding instruction
 * or funding is given for them (`SDK_TEMPLATE_UNPINNED`, as `impulse address` refuses them); a test
 * of a funding runs on this copy. The copy is a different trade: its hash is not the vector's.
 */
export function pinTerms(terms: TermsJson): TermsJson {
  const out = structuredClone(terms);
  const pin = pinnedBuilds[0];
  for (const leg of [out.asset_leg, out.cash_leg]) {
    if (leg.kind === "kcc20") {
      leg.template_hash = pin.hash;
      leg.template_prefix_len = pin.prefix;
      leg.template_suffix_len = pin.suffix;
    }
  }
  return out;
}

/** contracts/TEMPLATE_HASH as committed (64 hex digits and a newline). */
export const templateHashFile: string = readFileSync(new URL("contracts/TEMPLATE_HASH", root), "utf8");

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Lowercase hex to bytes; refuses anything Buffer would silently truncate. */
export function unhex(text: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(text, "hex"));
  assert.equal(hex(bytes), text, "test input is lowercase hex");
  return bytes;
}

/** Runs `f`, which must throw an ImpulseError, and returns it. */
export function refusalError(f: () => unknown): ImpulseError {
  try {
    f();
  } catch (thrown) {
    assert.ok(thrown instanceof Error, "an Error is thrown");
    const e = thrown as ImpulseError;
    assert.equal(e.name, "ImpulseError");
    assert.equal(typeof e.code, "string");
    // A decode refusal of one vault input names the input first ("input 1: TEMPLATE_...").
    assert.ok(new RegExp(`^(input [0-9]+: )?${e.code}: `).test(e.message), e.message);
    return e;
  }
  assert.fail("expected a refusal, the call returned");
}

/** Runs `f`, which must throw an ImpulseError, and returns its code. */
export function refusal(f: () => unknown): string {
  return refusalError(f).code;
}

/** The linear memory of the loaded module (initSync returns the instance it already has). */
export function memory(): WebAssembly.Memory {
  return sdk.initSync({ module: readFileSync(wasmUrl) }).memory;
}

// Role-check helpers: a pin for a destination, written here from the vector file alone, so that
// the SDK's own address encoding is not what builds the expectation.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

function polymod(values: number[]): bigint {
  let c = 1n;
  for (const v of values) {
    const top = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(v);
    for (let i = 0; i < 5; i += 1) if ((top >> BigInt(i)) & 1n) c ^= GENERATORS[i];
  }
  return c ^ 1n;
}

/** A Kaspa address (cashaddr-style, 40-bit checksum): version 0 P2PK, 1 P2PK-ECDSA, 8 P2SH. */
export function kaspaAddress(prefix: "kaspa" | "kaspatest", version: number, payload: Uint8Array): string {
  const data = [version, ...payload];
  const groups: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      groups.push((acc >> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) groups.push((acc << (5 - bits)) & 31);
  const checksum = polymod([...[...prefix].map((c) => c.charCodeAt(0) & 31), 0, ...groups, 0, 0, 0, 0, 0, 0, 0, 0]);
  const check = [...Array(8).keys()].map((i) => Number((checksum >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:${[...groups, ...check].map((g) => CHARSET[g]).join("")}`;
}

/** A destination as a pin names it, or null for an off-chain destination (which has none). */
export function pinOf(network: "mainnet" | "testnet", d: DestinationJson): string | null {
  if (d.kind === "off_chain") return null;
  if (d.kind === "kcc20") return `kcc20:${d.identifier_type}:${d.identifier}`;
  const prefix = network === "mainnet" ? "kaspa" : "kaspatest";
  const script = unhex(d.script);
  if (d.version === 0 && script.length === 34 && script[0] === 0x20 && script[33] === 0xac) {
    return kaspaAddress(prefix, 0, script.slice(1, 33));
  }
  if (d.version === 0 && script.length === 35 && script[0] === 0x21 && script[34] === 0xab) {
    return kaspaAddress(prefix, 1, script.slice(1, 34));
  }
  if (d.version === 0 && script.length === 35 && script[0] === 0xaa && script[1] === 0x20 && script[34] === 0x87) {
    return kaspaAddress(prefix, 8, script.slice(2, 34));
  }
  assert.fail("a destination with no address");
}

/** Whether a destination pays the key as the role check reads it: P2PK, ECDSA of either parity, or a KCC-20 pubkey owner. */
function paysKey(d: DestinationJson, key: string): boolean {
  if (d.kind === "kcc20") return d.identifier_type === "pubkey" && d.identifier === key;
  if (d.kind !== "kas" || d.version !== 0) return false;
  const body = d.script;
  return body === `20${key}ac` || body === `2102${key}ab` || body === `2103${key}ab`;
}

/**
 * The party of `role` for `terms` that the role check accepts: the role's key, with a pin for each
 * of the role's own destinations that does not pay that key (a custodian, a script, a covenant).
 */
export function partyFor(role: "buyer" | "seller", terms: TermsJson): PartyJson {
  const key = role === "buyer" ? terms.buyer_key : terms.seller_key;
  const [receive, refund] =
    role === "buyer" ? [terms.buyer_delivery, terms.buyer_refund] : [terms.seller_proceeds, terms.seller_refund];
  const pin = (d: DestinationJson) => (d.kind === "off_chain" || paysKey(d, key) ? null : pinOf(terms.network, d));
  return { role, key, pins: { receive: pin(receive), refund: pin(refund) } };
}
