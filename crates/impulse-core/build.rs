// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Tells the crate whether the committed template v3 artifacts exist (spec/V3-ZK.md section 6.1:
//! `contracts/compiled/impulse_vault.v3.json`, `contracts/TEMPLATE_HASH_V3` and
//! `circuits/IMAGE_ID`). `impulse_core::zk` embeds them with `include_str!` only when all three
//! are present, so the crate still builds while the contract step is unfinished; without them
//! every v3 operation refuses with `ZK_ARTIFACT_INVALID` (fail closed), and the test
//! `zk::template::tests::the_v3_template_is_embedded_and_passes_its_checks` fails.

use std::path::Path;

const FILES: [&str; 3] = [
    "contracts/compiled/impulse_vault.v3.json",
    "contracts/TEMPLATE_HASH_V3",
    "circuits/IMAGE_ID",
];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(impulse_v3_artifact)");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut all = true;
    for file in FILES {
        println!("cargo::rerun-if-changed=../../{file}");
        all &= root.join(file).is_file();
    }
    if all {
        println!("cargo::rustc-cfg=impulse_v3_artifact");
    }
}
