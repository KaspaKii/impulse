// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The [S10] suite of foreign_covenant_residual.rs (unchanged) run against the template v3 probe
//! (harness::v3_probe_by_default): the other leg's vault is required in a settle of template v3,
//! tested with a proof the gate accepts, so the gate cannot mask a refusal. The shipped template
//! v3, with real proofs, is in v3_settle.rs (`v3_s10_*`).

#[path = "foreign_covenant_residual.rs"]
mod suite;
