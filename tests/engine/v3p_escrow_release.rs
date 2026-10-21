// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v1 escrow_release suite (escrow_release.rs, unchanged) run against the template v3 probe: template v3 with its
//! one r0.g16.verify call replaced by a comparison of sha256(J) with the proof witness (see
//! harness::v3_probe_by_default). Every v1 settle require is thereby tested on the v3 code with a
//! proof the gate accepts, so the gate cannot mask a v1 refusal (spec/V3-ZK.md 13.1). The gate
//! itself is tested with real proofs in v3_proofs.rs and v3_settle.rs.

#[path = "escrow_release.rs"]
mod suite;
