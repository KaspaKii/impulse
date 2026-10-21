// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The trades the browser tests of the wallets run: terms between the public keys of the page's two
// wallets, and the UTXOs an offline node holds for them. Built in Node with the SDK of demo/dist
// (the very module the page loads), from the fixture tokens of impulse-core's tests. No key is
// here: the tests learn the wallets' public keys from the page.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { repo } from "./harness.ts";
import { pinOf } from "./party.ts";
import type { FakeUtxo, ScriptPublicKey } from "../../crates/impulse-wasm/npm/test/fakenode.ts";

/** The part of the SDK the world uses; everything is checked by the SDK, nothing here. */
export interface WorldSdk {
  kcc20Template(artifact: string): { template_hash: string; template_prefix_len: number; template_suffix_len: number };
  kcc20ScriptPublicKey(artifact: string, state: unknown): ScriptPublicKey;
  Terms: {
    fromJson(terms: unknown): {
      termsHash(): Uint8Array;
      validateStructure(): {
        instantiateExisting(leg: 0 | 1): { scriptPublicKey(): { version: number; script: Uint8Array }; scriptHash(): Uint8Array };
      };
    };
  };
}

const testdata = new URL("crates/impulse-core/src/tx/testdata/", repo);
export const ASSET_ARTIFACT = readFileSync(new URL("kcc20-asset.json", testdata), "utf8");
export const CASH_ARTIFACT = readFileSync(new URL("kcc20-cash.json", testdata), "utf8");
export const ASSET_COV = "a5".repeat(32);
export const CASH_COV = "ca".repeat(32);

export const AMOUNT_A = 1_000n;
export const KAS_CASH = 100_000_000n;
export const AUTHORIZER = 50_000_000n;
export const CARRIER = 200_000_000n;
export const FEE_INPUT = 1_000_000_000n;
export const EARLIEST = 1_000_000n;
export const EXPIRY = 2_000_000n;
/** The node's DAA score in the tests: after the earliest settlement, before the expiry. */
export const NOW = 1_500_000;

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
export const p2pk = (key: string): ScriptPublicKey => ({ version: 0, script: `20${key}ac` });

/** A fabricated UTXO with an outpoint derived from its label. */
export function utxo(label: string, amount: bigint, spk: ScriptPublicKey, covenant: string | null = null): FakeUtxo {
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

/** The address a scriptPublicKey has on `network`, written by the tests' own encoder. */
export function addressFor(network: "mainnet" | "testnet") {
  return (spk: ScriptPublicKey): string => {
    const a = pinOf(network, { kind: "kas", version: spk.version, script: spk.script });
    if (a === "") throw new Error("a scriptPublicKey with no address");
    return a;
  };
}

export type Mode = "direct" | "vault";

const owner = (key: string) => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });
const kas = (key: string) => ({ kind: "kas", ...p2pk(key) });

/** The JSON form of terms between two wallets' keys: a KCC-20 asset against KAS cash. */
export function termsFor(sdk: WorldSdk, mode: Mode, seller: string, buyer: string, network: "mainnet" | "testnet" = "testnet") {
  const token = (artifact: string, cov: string, amount: bigint) => ({
    kind: "kcc20" as const,
    covenant_id: cov,
    ...sdk.kcc20Template(artifact),
    amount: amount.toString(),
  });
  return {
    version: 1,
    network,
    settlement_mode: mode,
    nonce: "1313131313",
    seller_key: seller,
    buyer_key: buyer,
    authority_key: null,
    asset_leg: token(ASSET_ARTIFACT, ASSET_COV, AMOUNT_A),
    cash_leg: { kind: "kas", amount: KAS_CASH.toString() },
    buyer_delivery: owner(buyer),
    seller_proceeds: kas(seller),
    seller_refund: owner(seller),
    buyer_refund: kas(buyer),
    earliest_daa: EARLIEST.toString(),
    expiry_daa: EXPIRY.toString(),
    funding_mode: mode === "direct" ? "revocable" : "earmarked",
    trade_ref: "7e".repeat(32),
  };
}

/**
 * The terms of `mode` whose four destinations pay `cold`, a key that lives in no wallet of the page
 * (a custodian's, or the person's own wallet elsewhere). On mainnet the page refuses the other
 * kind: a destination that pays a key held only in its wallets.
 */
export function coldTermsFor(
  sdk: WorldSdk,
  mode: Mode,
  seller: string,
  buyer: string,
  cold: string,
  network: "mainnet" | "testnet",
) {
  return {
    ...termsFor(sdk, mode, seller, buyer, network),
    buyer_delivery: owner(cold),
    seller_proceeds: kas(cold),
    seller_refund: owner(cold),
    buyer_refund: kas(cold),
  };
}

/** The KCC-20 cash of the tests that pay in a token: units. */
export const CASH_AMOUNT = 250_000n;

/** The terms of `mode` with the cash leg a KCC-20 token (the cash artifact is the one of the fixtures). */
export function kcc20CashTermsFor(sdk: WorldSdk, mode: Mode, seller: string, buyer: string, network: "mainnet" | "testnet" = "testnet") {
  return {
    ...termsFor(sdk, mode, seller, buyer, network),
    cash_leg: {
      kind: "kcc20" as const,
      covenant_id: CASH_COV,
      ...sdk.kcc20Template(CASH_ARTIFACT),
      amount: CASH_AMOUNT.toString(),
    },
    seller_proceeds: owner(seller),
    buyer_refund: owner(buyer),
  };
}

/**
 * The terms of a Vault trade whose cash is paid outside Kaspa (owner decision D13: the asset leg
 * is a KCC-20 token; the cash leg may be external), settled by an authority that attests it.
 */
export function externalTermsFor(sdk: WorldSdk, seller: string, buyer: string, authority: string) {
  return {
    ...termsFor(sdk, "vault", seller, buyer),
    authority_key: authority,
    cash_leg: { kind: "external", amount: "5000" },
    seller_proceeds: { kind: "off_chain" },
    buyer_refund: { kind: "off_chain" },
  };
}

/** The UTXOs with the one labelled `label` holding `amount` sompi instead (a vault funded short). */
export function holding(utxos: FakeUtxo[], label: string, amount: bigint): FakeUtxo[] {
  const id = createHash("sha256").update(label).digest("hex");
  return utxos.map((u) => (u.transaction_id === id ? { ...u, amount: amount.toString() } : u));
}

/** A token UTXO held by `key`, carrying CARRIER KAS. */
export function ownToken(sdk: WorldSdk, label: string, key: string, amount: bigint): FakeUtxo {
  const state = { identifier_type: "pubkey", identifier: key, amount: amount.toString(), is_minter: false };
  return utxo(label, CARRIER, sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, state), ASSET_COV);
}

/** The buyer's cash token of a Direct trade in a KCC-20 cash, carrying CARRIER KAS. */
export function ownCashToken(sdk: WorldSdk, label: string, key: string, amount: bigint): FakeUtxo {
  const state = { identifier_type: "pubkey", identifier: key, amount: amount.toString(), is_minter: false };
  return utxo(label, CARRIER, sdk.kcc20ScriptPublicKey(CASH_ARTIFACT, state), CASH_COV);
}

/**
 * What a Direct trade needs on the node: the seller's token, the buyer's exact cash (KAS, or a cash
 * token when `kcc20Cash`) and its fee UTXO.
 */
export function directUtxos(sdk: WorldSdk, seller: string, buyer: string, kcc20Cash = false): FakeUtxo[] {
  return [
    ownToken(sdk, "seller-token", seller, AMOUNT_A),
    kcc20Cash ? ownCashToken(sdk, "buyer-cash-token", buyer, CASH_AMOUNT) : utxo("buyer-cash", KAS_CASH, p2pk(buyer)),
    utxo("buyer-fee", FEE_INPUT, p2pk(buyer)),
  ];
}

/**
 * What a Vault trade needs once both legs are funded: the vaults' UTXOs, and the buyer's fee UTXO.
 * `prefix` is put before each label, for a second trade on the same node.
 */
export function vaultUtxos(sdk: WorldSdk, terms: unknown, buyer: string, prefix = ""): FakeUtxo[] {
  const validated = sdk.Terms.fromJson(terms).validateStructure();
  const assetVault = validated.instantiateExisting(0);
  // External cash has no vault: the cash is paid outside Kaspa.
  const kasCash = (terms as { cash_leg: { kind: string } }).cash_leg.kind === "kas";
  const spk = (v: typeof assetVault): ScriptPublicKey => {
    const s = v.scriptPublicKey();
    return { version: s.version, script: hex(s.script) };
  };
  const escrow = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
    identifier_type: "script_hash",
    identifier: hex(assetVault.scriptHash()),
    amount: AMOUNT_A.toString(),
    is_minter: false,
  });
  const cashLeg = (terms as { cash_leg: { kind: string } }).cash_leg.kind;
  const cashTokens: FakeUtxo[] = [];
  if (cashLeg === "kcc20") {
    const cashVault = validated.instantiateExisting(1);
    cashTokens.push(
      utxo(`${prefix}cash-authorizer`, AUTHORIZER, spk(cashVault)),
      utxo(
        "cash-escrow",
        CARRIER,
        sdk.kcc20ScriptPublicKey(CASH_ARTIFACT, {
          identifier_type: "script_hash",
          identifier: hex(cashVault.scriptHash()),
          amount: CASH_AMOUNT.toString(),
          is_minter: false,
        }),
        CASH_COV,
      ),
    );
  }
  return [
    utxo(`${prefix}asset-authorizer`, AUTHORIZER, spk(assetVault)),
    utxo(`${prefix}asset-escrow`, CARRIER, escrow, ASSET_COV),
    ...(kasCash ? [utxo(`${prefix}cash-vault`, KAS_CASH, spk(validated.instantiateExisting(1)))] : []),
    ...cashTokens,
    utxo(`${prefix}buyer-fee`, FEE_INPUT, p2pk(buyer)),
  ];
}
