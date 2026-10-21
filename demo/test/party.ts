// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The party of a trade as the browser tests type it into the page: the role, the role's public
// key, and a pin for each of the role's destinations that does not pay that key. Written here
// from the terms alone, with its own Kaspa address encoder, so that the expectation does not come
// from the SDK it checks. (The SDK package tests hold the same encoder and compare it with the
// committed vault addresses: crates/impulse-wasm/npm/test/role.test.ts.)
import assert from "node:assert/strict";

export interface Dest {
  kind: string;
  version?: number;
  script?: string;
  identifier_type?: string;
  identifier?: string;
}
export interface PartyTerms {
  network: string;
  buyer_key: string;
  seller_key: string;
  buyer_delivery: Dest;
  buyer_refund: Dest;
  seller_proceeds: Dest;
  seller_refund: Dest;
}
export interface PageParty {
  role: "buyer" | "seller";
  key: string;
  receive: string;
  refund: string;
}

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

/** A Kaspa address: version 0 P2PK, 1 P2PK-ECDSA, 8 P2SH. */
export function kaspaAddress(prefix: string, version: number, payload: Buffer): string {
  const groups: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const byte of [version, ...payload]) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      groups.push((acc >> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) groups.push((acc << (5 - bits)) & 31);
  const sum = polymod([...[...prefix].map((c) => c.charCodeAt(0) & 31), 0, ...groups, 0, 0, 0, 0, 0, 0, 0, 0]);
  const check = [...Array(8).keys()].map((i) => Number((sum >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:${[...groups, ...check].map((g) => CHARSET[g]).join("")}`;
}

/** A destination as a pin names it. */
export function pinOf(network: string, d: Dest): string {
  if (d.kind === "kcc20") return `kcc20:${d.identifier_type}:${d.identifier}`;
  assert.equal(d.kind, "kas");
  const prefix = network === "mainnet" ? "kaspa" : "kaspatest";
  const script = Buffer.from(d.script ?? "", "hex");
  if (script.length === 34 && script[0] === 0x20 && script[33] === 0xac) return kaspaAddress(prefix, 0, script.subarray(1, 33));
  if (script.length === 35 && script[0] === 0x21 && script[34] === 0xab) return kaspaAddress(prefix, 1, script.subarray(1, 34));
  if (script.length === 35 && script[0] === 0xaa && script[1] === 0x20 && script[34] === 0x87) return kaspaAddress(prefix, 8, script.subarray(2, 34));
  return assert.fail("a destination with no address");
}

function paysKey(d: Dest, key: string): boolean {
  if (d.kind === "kcc20") return d.identifier_type === "pubkey" && d.identifier === key;
  if (d.kind !== "kas" || d.version !== 0) return false;
  return [`20${key}ac`, `2102${key}ab`, `2103${key}ab`].includes(d.script ?? "");
}

/** The role's party with the pins its destinations call for ("" for no pin). */
export function partyFor(role: "buyer" | "seller", terms: PartyTerms): PageParty {
  const key = role === "buyer" ? terms.buyer_key : terms.seller_key;
  const [receive, refund] =
    role === "buyer" ? [terms.buyer_delivery, terms.buyer_refund] : [terms.seller_proceeds, terms.seller_refund];
  const pin = (d: Dest) => (d.kind === "off_chain" || paysKey(d, key) ? "" : pinOf(terms.network, d));
  return { role, key, receive: pin(receive), refund: pin(refund) };
}
