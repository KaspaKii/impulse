// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v1 refund suite (refund.rs, unchanged) run against template v3 (spec/V3-ZK.md 13.1): a
//! refund needs no proof and the refund entry is v1's, so every v1 refund test must pass on v3.
//! The binary name starts with v3_, which makes harness::World::new build v3 terms.

#[path = "refund.rs"]
mod suite;
