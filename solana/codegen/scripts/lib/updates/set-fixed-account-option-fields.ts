// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
import {
  assertIsNode,
  bottomUpTransformerVisitor,
  Codama,
  optionTypeNode,
  structFieldTypeNode,
} from "codama";

/**
 * The on-chain `SwapDvp.earliest_settlement_timestamp` is fixed-width (1 tag
 * byte + 8 payload bytes, even for `None`, whose payload is a sentinel), but
 * the IDL models it as a plain Borsh `Option<i64>`. Without this, the
 * generated codec accepts the 482-byte layout the program rejects
 * (`SwapDvp::LEN` is 490 in this fork, 458 upstream; the upstream comment says 394, the size without the two mint-authority fields).
 *
 * Marking the account field's option `fixed` makes the TS codec consume/emit
 * exactly 1 + 8 bytes, with the tag as source of truth. Instruction args are
 * left as variable-length Borsh. The Rust renderer ignores `fixed`, so the
 * Rust client's strict decoding lives in the handwritten `verify` module.
 */
export function setFixedAccountOptionFields(dvpSwapCodama: Codama): Codama {
  let matched = 0;
  dvpSwapCodama.update(
    bottomUpTransformerVisitor([
      {
        select:
          "[accountNode]swapDvp.[structFieldTypeNode]earliestSettlementTimestamp",
        transform: (node) => {
          assertIsNode(node, "structFieldTypeNode");
          assertIsNode(node.type, "optionTypeNode");
          matched += 1;
          return structFieldTypeNode({
            ...node,
            type: optionTypeNode(node.type.item, {
              prefix: node.type.prefix,
              fixed: true,
            }),
          });
        },
      },
    ]),
  );
  // Fail codegen if the selector stopped matching (e.g. a Codama or IDL
  // rename). A silent no-op would ship a SwapDvp codec that falls back to
  // variable-width Option and accepts the 386-byte forged layout the
  // on-chain program rejects.
  if (matched !== 1) {
    throw new Error(
      `setFixedAccountOptionFields: expected to patch exactly 1 SwapDvp ` +
        `option field, patched ${matched}. The generated codec would accept ` +
        `the forged short layout; refusing to render.`,
    );
  }
  return dvpSwapCodama;
}
