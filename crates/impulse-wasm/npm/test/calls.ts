// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The wasm calls the tests check against the native build, each recorded with its arguments (see
// oracle.ts). These wrappers add nothing to the SDK: they call the method and keep a record.
import type {
  ArtifactsJson,
  CreationContextJson,
  DecodedTransactionJson,
  DirectLegsJson,
  FeePaymentJson,
  FundingCheckJson,
  Ipst,
  Kcc20DepositJson,
  Network,
  OfferedAddressesJson,
  RefundEscrowJson,
  RefundSignerName,
  SettleLegsJson,
  SignatureJson,
  SignedTransaction,
  TermsMatchJson,
  TokenEvidencesJson,
  U64String,
  UtxoJson,
  ValidatedTerms,
  ValueJson,
  VerifiedAddressJson,
} from "../index.js";
import { VALUE } from "./fixtures.ts";
import { record } from "./oracle.ts";
import { hex } from "./sdk.ts";
import type { Sdk } from "./sdk.ts";

export const rec = {
  fundKas: (t: ValidatedTerms, c: CreationContextJson, f: FeePaymentJson, v: ValueJson): Ipst =>
    record("fundKas", t, [c, f, v], () => t.fundKas(c, f, v)),

  fundKcc20: (
    t: ValidatedTerms,
    leg: number,
    c: CreationContextJson,
    d: Kcc20DepositJson,
    f: FeePaymentJson,
    v: ValueJson,
  ): Ipst => record("fundKcc20", t, [leg, c, d, f, v], () => t.fundKcc20(leg, c, d, f, v)),

  settle: (t: ValidatedTerms, legs: SettleLegsJson, f: FeePaymentJson, daa: U64String, v: ValueJson): Ipst =>
    record("settle", t, [legs, f, daa, v], () => t.settle(legs, f, daa, v)),

  refund: (
    t: ValidatedTerms,
    leg: number,
    signer: RefundSignerName,
    vaultUtxo: UtxoJson,
    escrow: RefundEscrowJson | null,
    f: FeePaymentJson,
    v: ValueJson,
  ): Ipst => record("refund", t, [leg, signer, vaultUtxo, escrow, f, v], () => t.refund(leg, signer, vaultUtxo, escrow, f, v)),

  direct: (t: ValidatedTerms, legs: DirectLegsJson, f: FeePaymentJson, daa: U64String, v: ValueJson): Ipst =>
    record("direct", t, [legs, f, daa, v], () => t.direct(legs, f, daa, v)),

  combine: (a: Ipst, other: string): Ipst => record("combine", null, [a.toJson(), other], () => a.combine(other)),

  assemble: (a: Ipst, signatures: SignatureJson[]): SignedTransaction =>
    record("assemble", null, [a.toJson(), signatures], () => a.assemble(signatures)),

  verifyAgainstTerms: (a: Ipst, artifacts: ArtifactsJson, daa: U64String, v: ValueJson = VALUE): TermsMatchJson =>
    record("verifyAgainstTerms", null, [a.toJson(), artifacts, daa, v], () => a.verifyAgainstTerms(artifacts, daa, v)),

  verifyAddresses: (
    t: ValidatedTerms,
    c: CreationContextJson,
    offered: OfferedAddressesJson,
    v: ValueJson = VALUE,
  ): VerifiedAddressJson[] => record("verifyAddresses", t, [c, offered, v], () => t.verifyAddresses(c, offered, v)),

  beforeFunding: (
    t: ValidatedTerms,
    c: CreationContextJson,
    offered: OfferedAddressesJson,
    evidence: TokenEvidencesJson,
    v: ValueJson = VALUE,
  ): FundingCheckJson =>
    record("beforeFunding", t, [c, offered, evidence, v], () => t.beforeFunding(c, offered, evidence, v)),

  decodeRaw: (sdk: Sdk, raw: Uint8Array, spent: { version: number; script: string }[], network: Network): DecodedTransactionJson =>
    record("decodeRaw", null, [hex(raw), spent, network], () => sdk.decodeRaw(raw, spent, network)),
};
