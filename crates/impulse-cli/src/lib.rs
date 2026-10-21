// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The `impulse` command line, as a library so its commands are testable without a process.
//! Formats and refusal codes: spec/CLI.md and, for `impulse frost`, spec/THRESHOLD.md. Only
//! `signing` reads a key or a FROST key share, and only from the file the user names; only
//! `keygen` generates a FROST key share, and writes it only to the file the user names. Only
//! `xchain new` makes a hashlock secret, and writes it only to the file the user names.

pub mod build_cmd;
pub mod cancel;
pub mod cli;
pub mod decode_cmd;
pub mod error;
pub mod frost;
pub mod funds;
pub mod ipst_cmd;
pub mod json;
pub mod keygen;
pub mod linked_cmd;
pub mod misc_cmd;
pub mod node;
#[cfg(test)]
mod phase2_tests;
pub mod qr;
pub mod receipt;
pub mod receipt_v2;
pub mod signing;
#[cfg(any(test, feature = "offline-fake-node"))]
pub mod sim;
pub mod summary;
pub mod terms_file;
pub mod token;
pub mod trade;
pub mod txview;
pub mod uri;
pub mod v2_cmd;
pub mod v2_terms;
pub mod value_cap;
pub mod xchain;
#[cfg(feature = "zk")]
pub mod zk_cmd;
#[cfg(feature = "zk")]
pub mod zk_receipt;
#[cfg(feature = "zk")]
pub mod zk_sign;
#[cfg(feature = "zk")]
pub mod zkh_cmd;
#[cfg(feature = "zk")]
pub mod zkh_sign;

#[cfg(test)]
mod frost_tests;
#[cfg(test)]
mod linked_tests;
#[cfg(test)]
mod testutil;
#[cfg(test)]
mod v2_tests;
#[cfg(test)]
#[path = "../tests/support/world.rs"]
mod world;
#[cfg(all(test, feature = "zk"))]
mod zk_tests;
#[cfg(all(test, feature = "zk"))]
mod zkh_tests;
