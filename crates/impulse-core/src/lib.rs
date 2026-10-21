// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-core: terms, codec, template, transaction builders, verifier. The default build is
//! keyless. The `threshold` module exists only with the non-default cargo feature `threshold`; it
//! holds one FROST party's own share and nonces in memory and never writes, logs or transmits them
//! (spec/THRESHOLD.md, "Key material").

pub mod address;
pub mod bounds;
pub mod decode;
pub mod htlc;
pub mod linked;
pub mod locktime;
pub mod template;
pub mod terms;
#[cfg(feature = "threshold")]
pub mod threshold;
pub mod tx;
pub mod v2;
pub mod verify;
#[cfg(feature = "zk")]
pub mod zk;
#[cfg(feature = "zk-hashed")]
pub mod zkh;
