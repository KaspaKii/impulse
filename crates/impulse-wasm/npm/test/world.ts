// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// A trade of every mode with its keys in wallets of the SDK (not throwaway noble signers), and the
// UTXOs a node would report for it: what the plan builders, the wallet and the review work on.
// The keys are drawn by `Wallet.generate` when a test calls it; this file holds none.
import { createHash } from "node:crypto";
import type {
  ArtifactsJson,
  DestinationJson,
  FeePaymentJson,
  Ipst,
  SettleLegsJson,
  TermsJson,
  ValidatedTerms,
  Wallet,
} from "../index.js";
import type { FakeUtxo } from "./fakenode.ts";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  CASH_ARTIFACT,
  CASH_COV,
  FEE_INPUT,
  KAS_CASH,
  KCC20_CASH,
  AMOUNT_A,
  MODES,
  funded,
  ownToken,
  p2pk,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import type { Mode, Parties } from "./fixtures.ts";
import { pinOf } from "./sdk.ts";
import type { Sdk } from "./sdk.ts";

export interface Wallets {
  seller: Wallet;
  buyer: Wallet;
  authority: Wallet;
  payer: Wallet;
  /** A fifth wallet, only in a world with `cold`: the key its destinations pay (see `world`). */
  cold?: Wallet;
}

export function newWallets(sdk: Sdk, cold = false): Wallets {
  return {
    seller: sdk.Wallet.generate(),
    buyer: sdk.Wallet.generate(),
    authority: sdk.Wallet.generate(),
    payer: sdk.Wallet.generate(),
    ...(cold ? { cold: sdk.Wallet.generate() } : {}),
  };
}

export function freeAll(w: Wallets): void {
  for (const wallet of Object.values(w)) wallet.free();
}

/** The wallets' public keys where the term fixtures want signers. */
function asParties(w: Wallets): Parties {
  const key = (wallet: Wallet) => ({ publicHex: wallet.publicKey() });
  return {
    seller: key(w.seller),
    buyer: key(w.buyer),
    authority: key(w.authority),
    payer: key(w.payer),
  } as unknown as Parties;
}

export interface World {
  wallets: Wallets;
  mode: Mode;
  network: "mainnet" | "testnet";
  json: TermsJson;
  terms: ValidatedTerms;
  artifacts: ArtifactsJson;
  /** Every UTXO the trade and the fee payer hold. */
  pool: FakeUtxo[];
  /** The fee payer's own UTXO. */
  fee: FakeUtxo;
}

/** The address a scriptPublicKey has on `network`, for the fake node. */
export function addressFor(network: "mainnet" | "testnet") {
  return (spk: { version: number; script: string }): string => {
    const a = pinOf(network, { kind: "kas", version: spk.version, script: spk.script });
    if (a === null) throw new Error("a scriptPublicKey with no address");
    return a;
  };
}

/**
 * A trade of `mode` between fresh wallets, and the UTXOs a node holds for it.
 *
 * The wallets' keys live only in the wallets, so on mainnet a destination that pays one of them is
 * refused (SDK_DESTINATION_IN_WALLET). A mainnet world therefore takes `cold`: its four destinations
 * pay a fifth key, `wallets.cold`, as a custodian's address the parties pin (`pinsFor`). A testnet
 * world pays the parties' own keys, as the page does by default.
 */
export function world(sdk: Sdk, mode: Mode, network: "mainnet" | "testnet" = "testnet", cold = false): World {
  const wallets = newWallets(sdk, cold);
  const base = termsJson(sdk, asParties(wallets), mode);
  const json = { ...base, network };
  if (wallets.cold !== undefined) {
    const key = wallets.cold.publicKey();
    const toCold = (d: DestinationJson): DestinationJson =>
      d.kind === "kas"
        ? { kind: "kas", version: 0, script: `20${key}ac` }
        : d.kind === "kcc20"
          ? { kind: "kcc20", identifier_type: "pubkey", identifier: key }
          : d;
    json.buyer_delivery = toCold(json.buyer_delivery);
    json.seller_proceeds = toCold(json.seller_proceeds);
    json.seller_refund = toCold(json.seller_refund);
    json.buyer_refund = toCold(json.buyer_refund);
  }
  const terms = validated(sdk, json);
  const fee = utxo("payer-fee", FEE_INPUT, p2pk(wallets.payer.publicKey())) as FakeUtxo;
  const artifacts: ArtifactsJson = { asset: ASSET_ARTIFACT, cash: mode.cash === "kcc20" ? CASH_ARTIFACT : null };
  let pool: FakeUtxo[];
  if (mode.settlement === "direct") {
    const seller = wallets.seller.publicKey();
    const buyer = wallets.buyer.publicKey();
    pool = [
      ownToken(sdk, "seller-token", ASSET_ARTIFACT, ASSET_COV, seller, AMOUNT_A).utxo,
      mode.cash === "kcc20"
        ? ownToken(sdk, "buyer-token", CASH_ARTIFACT, CASH_COV, buyer, KCC20_CASH).utxo
        : utxo("buyer-cash", KAS_CASH, p2pk(buyer)),
      fee,
    ];
  } else {
    const f = funded(sdk, terms, mode);
    pool = [f.assetAuthorizer, f.assetEscrow, ...[f.cashVault, f.cashAuthorizer, f.cashEscrow].filter((u) => u !== undefined), fee];
  }
  return { wallets, mode, network, json, terms, artifacts, pool, fee };
}

/** The pins a party of a cold world gives for its role: its two destinations, which pay the cold key. */
export function pinsFor(w: World, role: "buyer" | "seller"): { receive: string | null; refund: string | null } {
  const [receive, refund] =
    role === "buyer" ? [w.json.buyer_delivery, w.json.buyer_refund] : [w.json.seller_proceeds, w.json.seller_refund];
  return { receive: pinOf(w.network, receive), refund: pinOf(w.network, refund) };
}

export { MODES };

/** The inputs of an IPST, as text of its slots, for a quick look in a failing assertion. */
export function describeSlots(ipst: Ipst): string {
  return ipst
    .slots()
    .map((s) => `${s.input}:${s.signer === null ? "-" : s.signer.slice(0, 8)}:${s.signature === null ? "unsigned" : "signed"}`)
    .join(" ");
}

/** A fee payment from the world's payer: its own UTXO, the fee, change back to the payer. */
export function payment(w: World, fee: bigint, inputs: FakeUtxo[] = [w.fee]): FeePaymentJson {
  return { inputs, fee: fee.toString(), change: p2pk(w.wallets.payer.publicKey()) };
}

/** The settle legs of a world whose pool is the funded trade, as the builder takes them. */
export function legsOf(w: World): SettleLegsJson {
  const by = (label: string) => {
    const found = w.pool.find((u) => u.transaction_id === createHash("sha256").update(label).digest("hex"));
    if (found === undefined) throw new Error(`no UTXO ${label} in the pool`);
    return found;
  };
  const cash: SettleLegsJson["cash"] =
    w.mode.cash === "kas"
      ? { kind: "kas", vault: by("cash-vault") }
      : w.mode.cash === "kcc20"
        ? { kind: "kcc20", artifact: CASH_ARTIFACT, authorizer: by("cash-authorizer"), escrow: by("cash-escrow") }
        : { kind: "external" };
  return { asset_artifact: ASSET_ARTIFACT, asset_authorizer: by("asset-authorizer"), asset_escrow: by("asset-escrow"), cash };
}
