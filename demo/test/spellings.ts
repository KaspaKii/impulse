// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Every way the browser tests know to write 32 bytes as text, to look for a key where it must not
// be. The bytes passed in are a runtime throwaway (a wallet's key as the page drew it, or a stand-in
// drawn by the test); nothing here writes them anywhere.

/** The spellings of the 32 bytes given as 64 hex digits: hex, base64, decimal, byte lists, reversed. */
export function spellingsOf(secretHex: string): string[] {
  const secret = Uint8Array.from(Buffer.from(secretHex, "hex"));
  const reversed = Uint8Array.from(secret).reverse();
  const reversedHex = Buffer.from(reversed).toString("hex");
  return [
    secretHex,
    secretHex.toUpperCase(),
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("base64url"),
    Buffer.from(secret).toString("base64").replace(/=+$/, ""),
    BigInt(`0x${secretHex}`).toString(),
    BigInt(`0x${reversedHex}`).toString(),
    Array.from(secret).join(","),
    Array.from(secret).join(", "),
    reversedHex,
  ];
}
