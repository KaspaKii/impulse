// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
// Suppress warnings for generated code
#![allow(warnings)]

// Re-export generated code
pub mod generated;
pub use generated::*;

// Handwritten checked, verify-before-fund helpers (survive client
// regeneration; the generated readers do not check owner or exact size).
pub mod verify;

#[cfg(test)]
mod cpi_flag_regression;

// Re-export commonly used items
pub use generated::errors::*;
pub use generated::programs::*;
