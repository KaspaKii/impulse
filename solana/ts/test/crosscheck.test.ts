// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// I19 cross-check: one term sheet derives both the Kaspa vault addresses and the Solana escrow.
// The impulse-wasm SDK (impulse-core compiled to WebAssembly) computes the terms hash and the
// ImpulseVault funding addresses; @solana/kit derives the impulse-solana SwapDvp PDA from the
// Solana parameters and that same hash. Expectations come from solana/tests/fixtures/
// term-sheets.json, whose Kaspa side must equal the golden vectors under tests/vectors/ and
// whose Solana side impulse-solana-tests derives independently in Rust (solana-pubkey).
// No key is generated, read or printed here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { address, getAddressEncoder, getProgramDerivedAddress, type Address } from "@solana/kit";
import * as sdk from "../../../crates/impulse-wasm/npm/index.js";
import type { CreationContextJson, TermsJson, ValueJson } from "../../../crates/impulse-wasm/npm/index.js";

const repo = new URL("../../../", import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, repo), "utf8");

sdk.initSync({ module: readFileSync(new URL("crates/impulse-wasm/npm/pkg/impulse_wasm_bg.wasm", repo)) });

interface Sheet {
  name: string;
  terms_vector: string;
  solana: {
    program_id: string;
    settlement_authority: string;
    user_a: string;
    user_b: string;
    mint_a: string;
    mint_b: string;
    token_program_a: string;
    token_program_b: string;
    nonce: string;
  };
  expected: {
    terms_hash: string;
    kaspa: Record<"asset_vault" | "cash_vault", { address?: string; refused?: string }>;
    solana: { swap_dvp: string; bump: number; nonce_tombstone: string; dvp_ata_a: string; dvp_ata_b: string };
  };
}

/** A term sheet: the Impulse terms of the golden vector it names, and its Solana parameters. */
const sheets: (Sheet & { terms: TermsJson })[] = JSON.parse(read("solana/tests/fixtures/term-sheets.json")).term_sheets.map(
  (s: Sheet) => ({ ...s, terms: JSON.parse(read(`tests/vectors/terms/${s.terms_vector}.json`)).terms as TermsJson }),
);
const ATA_PROGRAM = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
// spec/ENCODING.md: every vector passes both validation stages at creation DAA score 400,000,000.
const CREATION_DAA = "400000000";
// The golden vectors hold more than the default 10 KAS cap; the explicit flag lifts it, as the
// SDK's own vector tests do.
const LIFT: ValueJson = { i_accept_the_risk: true };

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const enc = getAddressEncoder();
const u64le = (n: string): Uint8Array => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
};

/** Seeds as on-chain: [b"dvp", authority, user_a, user_b, mint_a, mint_b, terms_hash, nonce LE]. */
async function swapDvp(s: Sheet["solana"], termsHash: Uint8Array): Promise<readonly [Address, number]> {
  return getProgramDerivedAddress({
    programAddress: address(s.program_id),
    seeds: [
      "dvp",
      enc.encode(address(s.settlement_authority)),
      enc.encode(address(s.user_a)),
      enc.encode(address(s.user_b)),
      enc.encode(address(s.mint_a)),
      enc.encode(address(s.mint_b)),
      termsHash,
      u64le(s.nonce),
    ],
  });
}

async function ata(owner: Address, mint: string, tokenProgram: string): Promise<Address> {
  const [a] = await getProgramDerivedAddress({
    programAddress: ATA_PROGRAM,
    seeds: [enc.encode(owner), enc.encode(address(tokenProgram)), enc.encode(address(mint))],
  });
  return a;
}

/** The Kaspa side of a term sheet through the SDK: terms hash and per-leg vault outcome. */
function kaspa(terms: TermsJson): { termsHash: Uint8Array; legs: Record<string, { address?: string; refused?: string }> } {
  const checked = sdk.Terms.fromJson(terms).validateStructure();
  const ctx: CreationContextJson = { network: terms.network, creation_daa: CREATION_DAA };
  checked.validateCreation(ctx);
  const legs: Record<string, { address?: string; refused?: string }> = {};
  for (const [key, leg] of [["asset_vault", 0], ["cash_vault", 1]] as const) {
    try {
      legs[key] = { address: checked.instantiateForCreation(leg, ctx, LIFT).address() };
    } catch (e) {
      legs[key] = { refused: (e as { code: string }).code };
    }
  }
  return { termsHash: checked.termsHash(), legs };
}

test("the fixture's terms hashes and Kaspa addresses are the golden vectors", () => {
  assert.ok(sheets.length >= 2);
  for (const s of sheets) {
    const t = JSON.parse(read(`tests/vectors/terms/${s.terms_vector}.json`));
    const v = JSON.parse(read(`tests/vectors/vaults/${s.terms_vector}.json`));
    assert.equal(s.expected.terms_hash, t.terms_hash, `${s.name}: terms hash`);
    for (const k of ["asset_vault", "cash_vault"] as const) {
      const want = v[k].address !== undefined ? { address: v[k].address } : { refused: v[k].refused };
      assert.deepEqual(s.expected.kaspa[k], want, `${s.name}: ${k}`);
    }
  }
  // One sheet has two Kaspa vaults, one has a Kaspa asset vault and an external cash leg.
  const vaults = sheets.map((s) => Object.values(s.expected.kaspa).filter((x) => x.address).length).sort();
  assert.deepEqual(vaults, [1, 2]);
});

test("the fixture's program ID is the program's declare_id and IDL key", () => {
  const lib = read("solana/programs/impulse-solana/src/lib.rs");
  const declared = /declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\)/.exec(lib)?.[1];
  const idl = JSON.parse(read("solana/programs/impulse-solana/idl/impulse_solana.json"));
  for (const s of sheets) {
    assert.equal(s.solana.program_id, declared, s.name);
    assert.equal(s.solana.program_id, idl.program.publicKey, s.name);
  }
});

test("one term sheet derives the Kaspa vault addresses and the Solana escrow PDA", async () => {
  for (const s of sheets) {
    const k = kaspa(s.terms);
    assert.equal(hex(k.termsHash), s.expected.terms_hash, `${s.name}: SDK terms hash`);
    assert.deepEqual(k.legs, s.expected.kaspa, `${s.name}: SDK vault addresses`);

    const [pda, bump] = await swapDvp(s.solana, k.termsHash);
    assert.equal(pda, s.expected.solana.swap_dvp, `${s.name}: SwapDvp PDA`);
    assert.equal(bump, s.expected.solana.bump, `${s.name}: bump`);
    const [tombstone] = await getProgramDerivedAddress({
      programAddress: address(s.solana.program_id),
      seeds: ["nonce", enc.encode(pda)],
    });
    assert.equal(tombstone, s.expected.solana.nonce_tombstone, `${s.name}: nonce tombstone`);
    assert.equal(await ata(pda, s.solana.mint_a, s.solana.token_program_a), s.expected.solana.dvp_ata_a);
    assert.equal(await ata(pda, s.solana.mint_b, s.solana.token_program_b), s.expected.solana.dvp_ata_b);
  }
});

test("changing any term moves the terms hash, the Kaspa vault address and the Solana PDA together", async () => {
  for (const s of sheets) {
    const base = kaspa(s.terms);
    const [basePda] = await swapDvp(s.solana, base.termsHash);
    const flippedRef = s.terms.trade_ref.slice(0, -1) + (s.terms.trade_ref.endsWith("0") ? "1" : "0");
    const variants: TermsJson[] = [
      { ...s.terms, trade_ref: flippedRef },
      { ...s.terms, nonce: (BigInt(s.terms.nonce) ^ 1n).toString() },
      { ...s.terms, expiry_daa: (BigInt(s.terms.expiry_daa) + 1n).toString() },
    ];
    for (const t of variants) {
      const k = kaspa(t);
      assert.notEqual(hex(k.termsHash), hex(base.termsHash), s.name);
      assert.notEqual(k.legs.asset_vault?.address, base.legs.asset_vault?.address, `${s.name}: Kaspa vault`);
      const [pda] = await swapDvp(s.solana, k.termsHash);
      assert.notEqual(pda, basePda, `${s.name}: Solana PDA`);
    }
  }
});

test("the Solana PDA needs the terms hash: without it (the upstream seeds) the address differs", async () => {
  for (const s of sheets) {
    const [upstream] = await getProgramDerivedAddress({
      programAddress: address(s.solana.program_id),
      seeds: [
        "dvp",
        enc.encode(address(s.solana.settlement_authority)),
        enc.encode(address(s.solana.user_a)),
        enc.encode(address(s.solana.user_b)),
        enc.encode(address(s.solana.mint_a)),
        enc.encode(address(s.solana.mint_b)),
        u64le(s.solana.nonce),
      ],
    });
    assert.notEqual(upstream, s.expected.solana.swap_dvp, s.name);
  }
});
