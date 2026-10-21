// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Fixtures for the phase 2 tests: runtime throwaway signers, terms and UTXOs for every trade
// mode, and the signing helpers.
//
// Keys: a Signer draws a random secret key when the test runs and signs with it. `erase()`
// zero-fills the 32-byte secret buffer the Signer holds. JavaScript cannot do more: @noble/curves
// turns the key into an immutable BigInt when it signs (and derives further bytes from it), and
// those copies live in the heap until garbage collection. So the key is throwaway and short-lived,
// not erased everywhere. It is never written to a file, a log or an oracle request, and has no
// way to be serialised. No key literal appears anywhere in the tests. The SDK itself never sees a
// secret key: a signature reaches it as 65 bytes.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { schnorr } from "@noble/curves/secp256k1.js";
import { blake3 } from "@noble/hashes/blake3.js";
import type {
  CreationContextJson,
  DestinationJson,
  FeePaymentJson,
  Hex,
  Ipst,
  Kcc20StateJson,
  LegJson,
  ScriptPublicKeyJson,
  SettleLegsJson,
  TermsJson,
  TokenUtxoJson,
  U64String,
  UtxoJson,
  ValidatedTerms,
  ValueJson,
} from "../index.js";
import { hex, root, unhex } from "./sdk.ts";
import type { Sdk } from "./sdk.ts";

/** SIG_HASH_ALL, the sighash type byte every Impulse signature ends with. */
const SIG_HASH_ALL = 0x01;

/** A throwaway signer: a random key in memory; `erase()` zero-fills its buffer (see the note above on BigInt copies). */
export class Signer {
  readonly #secret: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly publicHex: Hex;

  constructor() {
    this.#secret = schnorr.utils.randomSecretKey();
    this.publicKey = schnorr.getPublicKey(this.#secret);
    this.publicHex = hex(this.publicKey);
  }

  /** A 65-byte signature over a 32-byte sighash: BIP-340 Schnorr and the SIG_HASH_ALL byte. */
  sign(sighash: Uint8Array): Uint8Array {
    assert.equal(sighash.length, 32);
    const sig = new Uint8Array(65);
    sig.set(schnorr.sign(sighash, this.#secret), 0);
    sig[64] = SIG_HASH_ALL;
    return sig;
  }

  erase(): void {
    this.#secret.fill(0);
  }

  // A key is never rendered: not by String(), JSON.stringify, console.log or util.inspect.
  toJSON(): never {
    throw new Error("a Signer is not serialisable");
  }
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "Signer";
  }
}

/** The four keys of a test trade. */
export interface Parties {
  seller: Signer;
  buyer: Signer;
  authority: Signer;
  payer: Signer;
}

export function newParties(): Parties {
  return {
    seller: new Signer(),
    buyer: new Signer(),
    authority: new Signer(),
    payer: new Signer(),
  };
}

export function erase(p: Parties): void {
  for (const s of Object.values(p)) s.erase();
}

/** The public keys to signers, for finding the signer of a slot. */
export function ring(p: Parties): Map<Hex, Signer> {
  return new Map(Object.values(p).map((s) => [s.publicHex, s]));
}

// The KCC-20 fixture tokens: the pinned kcc20.sil builds impulse-core's tests use.
const testdata = new URL("crates/impulse-core/src/tx/testdata/", root);
export const ASSET_ARTIFACT = readFileSync(new URL("kcc20-asset.json", testdata), "utf8");
export const CASH_ARTIFACT = readFileSync(new URL("kcc20-cash.json", testdata), "utf8");
export const ASSET_COV = "a5".repeat(32);
export const CASH_COV = "ca".repeat(32);

/**
 * The fixture asset token as an artifact outside the set of pinned kcc20.sil builds, for the
 * token warnings. One no-op byte (0x61) is appended to the bytecode, which makes the template
 * suffix one byte longer, and the declared template hash is recomputed as silverscript computes
 * it (blake3 over the 8-byte little-endian prefix length, the prefix, the suffix length and the
 * suffix). It is a well-formed artifact for the checks of `verify`, not a working token. Each
 * name in `entries` is declared as a further entry, with a dispatch tag of its own.
 */
export function unpinnedToken(entries: string[] = []): string {
  const artifact = JSON.parse(ASSET_ARTIFACT);
  const contract = artifact.contracts.KCC20;
  const { offset, len } = contract.compiled.state_span as { offset: number; len: number };
  contract.compiled.bytecode.push(0x61);
  const bytes = Uint8Array.from(contract.compiled.bytecode as number[]);
  const prefix = bytes.slice(0, offset);
  const suffix = bytes.slice(offset + len);
  const le8 = (n: number): Uint8Array => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(n), true);
    return b;
  };
  contract.compiled.template_hash = Array.from(
    blake3(Uint8Array.from([...le8(prefix.length), ...prefix, ...le8(suffix.length), ...suffix])),
  );
  entries.forEach((name, i) => {
    contract.entries[name] = {
      ...structuredClone(contract.entries.__delegate),
      dispatch_tag: (0x0badf00d + i).toString(16).padStart(8, "0"),
    };
  });
  return JSON.stringify(artifact);
}

export const AMOUNT_A = 1_000n;
export const KAS_CASH = 100_000_000n;
export const KCC20_CASH = 250_000n;
export const EXTERNAL_CASH = 5_000n;
export const EARLIEST = 1_000_000n;
export const EXPIRY = 2_000_000n;
/** The DAA score the builders are called at: between earliest and expiry. */
export const NOW = 1_500_000n;
/** KAS on vault UTXOs at the derived minimums (0.5 KAS an authorizer, 2 KAS a token carrier). */
export const AUTHORIZER = 50_000_000n;
export const CARRIER = 200_000_000n;
export const FEE_INPUT = 1_000_000_000n;
export const FEE = 5_000_000n;
/** A declared value inside the default cap of 10 KAS. */
export const VALUE: ValueJson = { kas_equivalent: "100000000" };
/** The explicit flag that lifts the cap, for tests of what the cap is not about (the golden vectors hold more than 10 KAS). */
export const LIFT: ValueJson = { i_accept_the_risk: true };

export function p2pk(key: Hex): ScriptPublicKeyJson {
  return { version: 0, script: `20${key}ac` };
}

/** A fabricated UTXO with an outpoint derived from its label. */
export function utxo(
  label: string,
  amount: bigint | U64String,
  spk: ScriptPublicKeyJson,
  covenant: Hex | null = null,
): UtxoJson {
  return {
    transaction_id: createHash("sha256").update(label).digest("hex"),
    index: 0,
    amount: amount.toString(),
    script_public_key: spk,
    block_daa_score: "100",
    is_coinbase: false,
    covenant_id: covenant,
  };
}

export function ctx(): CreationContextJson {
  return { network: "mainnet", creation_daa: (NOW - 1n).toString() };
}

export type Cash = "kas" | "kcc20" | "external";

export interface Mode {
  settlement: "vault" | "direct";
  authority: boolean;
  cash: Cash;
  funding: "revocable" | "earmarked";
}

export const MODES = {
  /** Authority settles, KAS cash, earmarked: terms vector 02's shape. */
  vaultKas: { settlement: "vault", authority: true, cash: "kas", funding: "earmarked" } as Mode,
  vaultKcc20: { settlement: "vault", authority: true, cash: "kcc20", funding: "earmarked" } as Mode,
  selfSettling: { settlement: "vault", authority: false, cash: "kcc20", funding: "revocable" } as Mode,
  external: { settlement: "vault", authority: true, cash: "external", funding: "earmarked" } as Mode,
  directKas: { settlement: "direct", authority: false, cash: "kas", funding: "revocable" } as Mode,
  directKcc20: { settlement: "direct", authority: false, cash: "kcc20", funding: "revocable" } as Mode,
};

function owner(key: Hex): DestinationJson {
  return { kind: "kcc20", identifier_type: "pubkey", identifier: key };
}

function kas(key: Hex): DestinationJson {
  return { kind: "kas", ...p2pk(key) };
}

/** The leg of a KCC-20 token, named by its template triple. */
export function tokenLeg(sdk: Sdk, artifact: string, cov: Hex, amount: bigint): LegJson {
  return { kind: "kcc20", covenant_id: cov, ...sdk.kcc20Template(artifact), amount: amount.toString() };
}

/** The JSON form of terms for a mode, the keys from `p`. */
export function termsJson(sdk: Sdk, p: Parties, mode: Mode): TermsJson {
  const [s, b] = [p.seller.publicHex, p.buyer.publicHex];
  const cash: [LegJson, DestinationJson, DestinationJson] =
    mode.cash === "kas"
      ? [{ kind: "kas", amount: KAS_CASH.toString() }, kas(s), kas(b)]
      : mode.cash === "kcc20"
        ? [tokenLeg(sdk, CASH_ARTIFACT, CASH_COV, KCC20_CASH), owner(s), owner(b)]
        : [{ kind: "external", amount: EXTERNAL_CASH.toString() }, { kind: "off_chain" }, { kind: "off_chain" }];
  return {
    version: 1,
    network: "mainnet",
    settlement_mode: mode.settlement,
    nonce: "1313131313",
    seller_key: s,
    buyer_key: b,
    authority_key: mode.authority ? p.authority.publicHex : null,
    asset_leg: tokenLeg(sdk, ASSET_ARTIFACT, ASSET_COV, AMOUNT_A),
    cash_leg: cash[0],
    buyer_delivery: owner(b),
    seller_proceeds: cash[1],
    seller_refund: owner(s),
    buyer_refund: cash[2],
    earliest_daa: EARLIEST.toString(),
    expiry_daa: EXPIRY.toString(),
    funding_mode: mode.funding,
    trade_ref: "7e".repeat(32),
  };
}

export function validated(sdk: Sdk, json: TermsJson): ValidatedTerms {
  return sdk.Terms.fromJson(json).validateStructure();
}

/** One P2PK input of `owner`, the standard fee, change back to the owner. */
export function feePayment(owner: Signer, label = "fee", amount: bigint = FEE_INPUT, fee: bigint = FEE): FeePaymentJson {
  return {
    inputs: [utxo(label, amount, p2pk(owner.publicHex))],
    fee: fee.toString(),
    change: p2pk(owner.publicHex),
  };
}

export function kcc20State(key: Hex, amount: bigint): Kcc20StateJson {
  return { identifier_type: "pubkey", identifier: key, amount: amount.toString(), is_minter: false };
}

/** A party's own token UTXO, owned by `key`, carrying CARRIER KAS. */
export function ownToken(
  sdk: Sdk,
  label: string,
  artifact: string,
  cov: Hex,
  key: Hex,
  amount: bigint,
): TokenUtxoJson {
  const state = kcc20State(key, amount);
  return { utxo: utxo(label, CARRIER, sdk.kcc20ScriptPublicKey(artifact, state), cov), state };
}

/** The signer's signatures for the slots that name it. */
export function signSlots(ipst: Ipst, signer: Signer): void {
  for (const slot of ipst.slots()) {
    if (slot.signer === signer.publicHex && slot.signature === null) {
      ipst.addSignature(slot.input, signer.sign(ipst.sighash(slot.input)));
    }
  }
}

/** The IPST text with only `signer`'s signatures added, as one party returns it. */
export function signedBy(sdk: Sdk, text: string, signer: Signer): string {
  const copy = sdk.Ipst.fromJson(text);
  signSlots(copy, signer);
  return copy.toJson();
}

/** Every signature of the ring added, input by input, as `{ input, signature }`. */
export function allSignatures(ipst: Ipst, signers: Map<Hex, Signer>): { input: number; signature: Hex }[] {
  const out: { input: number; signature: Hex }[] = [];
  for (const slot of ipst.slots()) {
    if (slot.signer === null) continue;
    const signer = signers.get(slot.signer);
    assert.ok(signer, `a signer for input ${slot.input}`);
    out.push({ input: slot.input, signature: hex(signer.sign(ipst.sighash(slot.input))) });
  }
  return out;
}

interface OutputJson {
  value: string;
  script_public_key: ScriptPublicKeyJson;
  covenant: { authorizing_input: number; covenant_id: Hex } | null;
}

/** The outputs of an IPST, as the UTXOs they become once the transaction `txid` is accepted. */
export function outputsAsUtxos(txid: Hex, ipstText: string, daa = NOW - 1n): UtxoJson[] {
  const doc = JSON.parse(ipstText) as { outputs: OutputJson[] };
  return doc.outputs.map((o, index) => ({
    transaction_id: txid,
    index,
    amount: o.value,
    script_public_key: o.script_public_key,
    block_daa_score: daa.toString(),
    is_coinbase: false,
    covenant_id: o.covenant?.covenant_id ?? null,
  }));
}

/** The scriptPublicKeys an IPST's inputs spend, in input order. */
export function spentScripts(ipstText: string): ScriptPublicKeyJson[] {
  const doc = JSON.parse(ipstText) as { inputs: { utxo: { script_public_key: ScriptPublicKeyJson } }[] };
  return doc.inputs.map((i) => i.utxo.script_public_key);
}

/** The funded vault UTXOs of a vault trade, as Impulse's fund builders make them. */
export interface Funded {
  assetAuthorizer: UtxoJson;
  assetEscrow: UtxoJson;
  cashVault?: UtxoJson;
  cashAuthorizer?: UtxoJson;
  cashEscrow?: UtxoJson;
}

function escrowSpk(sdk: Sdk, terms: ValidatedTerms, leg: 0 | 1, artifact: string, amount: bigint): ScriptPublicKeyJson {
  const state: Kcc20StateJson = {
    identifier_type: "script_hash",
    identifier: hex(terms.instantiateExisting(leg).scriptHash()),
    amount: amount.toString(),
    is_minter: false,
  };
  return sdk.kcc20ScriptPublicKey(artifact, state);
}

/** The vault UTXOs a fabricated funding of `mode` would leave: each at the exact amount. */
export function funded(sdk: Sdk, terms: ValidatedTerms, mode: Mode): Funded {
  const vaultSpk = (leg: 0 | 1) => {
    const spk = terms.instantiateExisting(leg).scriptPublicKey();
    return { version: spk.version, script: hex(spk.script) };
  };
  const f: Funded = {
    assetAuthorizer: utxo("asset-authorizer", AUTHORIZER, vaultSpk(0)),
    assetEscrow: utxo("asset-escrow", CARRIER, escrowSpk(sdk, terms, 0, ASSET_ARTIFACT, AMOUNT_A), ASSET_COV),
  };
  if (mode.cash === "kas") {
    f.cashVault = utxo("cash-vault", KAS_CASH, vaultSpk(1));
  } else if (mode.cash === "kcc20") {
    f.cashAuthorizer = utxo("cash-authorizer", AUTHORIZER, vaultSpk(1));
    f.cashEscrow = utxo("cash-escrow", CARRIER, escrowSpk(sdk, terms, 1, CASH_ARTIFACT, KCC20_CASH), CASH_COV);
  }
  return f;
}

/** The settle legs of a funded trade. */
export function settleLegs(f: Funded): SettleLegsJson {
  const cash: SettleLegsJson["cash"] = f.cashVault
    ? { kind: "kas", vault: f.cashVault }
    : f.cashAuthorizer && f.cashEscrow
      ? { kind: "kcc20", artifact: CASH_ARTIFACT, authorizer: f.cashAuthorizer, escrow: f.cashEscrow }
      : { kind: "external" };
  return { asset_artifact: ASSET_ARTIFACT, asset_authorizer: f.assetAuthorizer, asset_escrow: f.assetEscrow, cash };
}

export { unhex };
