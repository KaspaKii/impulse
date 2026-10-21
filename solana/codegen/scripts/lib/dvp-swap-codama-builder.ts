// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
import { Codama, createFromJson } from "codama";
import {
  setFixedAccountOptionFields,
  setInstructionAccountDefaultValues,
} from "./updates";

export class DvpSwapCodamaBuilder {
  private codama: Codama;

  constructor(dvpSwapIdl: unknown) {
    const idlJson =
      typeof dvpSwapIdl === "string" ? dvpSwapIdl : JSON.stringify(dvpSwapIdl);
    this.codama = createFromJson(idlJson);
  }

  setInstructionAccountDefaultValues(): this {
    this.codama = setInstructionAccountDefaultValues(this.codama);
    return this;
  }

  setFixedAccountOptionFields(): this {
    this.codama = setFixedAccountOptionFields(this.codama);
    return this;
  }

  build(): Codama {
    return this.codama;
  }
}

export function createDvpSwapCodamaBuilder(
  dvpSwapIdl: unknown,
): DvpSwapCodamaBuilder {
  return new DvpSwapCodamaBuilder(dvpSwapIdl);
}
