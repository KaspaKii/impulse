// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Prints the list guest's image ID as 64 hex characters, the byte order of circuits/IMAGE_ID and
//! of the template constant (the risc0 Digest bytes: each u32 word little-endian).
fn main() {
    let hex: String = impulse_zk_methods::LIST_GUEST_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{hex}");
}
