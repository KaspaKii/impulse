// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Builds the guests inside RISC Zero's guest-builder Docker image, pinned by digest, so the image
//! ID does not depend on the machine (spec/V3-ZK.md section 5.5; scripts/build-guest.sh rebuilds
//! and compares with circuits/IMAGE_ID). The tag names the RISC Zero Rust toolchain 1.91.1.
use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

/// risczero/risc0-guest-builder:r0.1.91.1, manifest digest read from the registry with
/// `docker buildx imagetools inspect` on 2026-10-12 (circuits/README.md, "Pins").
const GUEST_BUILDER: &str =
    "r0.1.91.1@sha256:fafb377a44e1cfca415577c48d2f7012bda99ed36f2fae27f9a663b9fe6048f0";

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let docker = DockerOptionsBuilder::default()
        .root_dir(root)
        .docker_container_tag(GUEST_BUILDER)
        .build()
        .expect("docker options");
    let opts = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .expect("guest options");
    let mut map = HashMap::new();
    map.insert("list-guest", opts.clone());
    map.insert("terms-guest", opts.clone());
    map.insert("forge-guest", opts);
    embed_methods_with_options(map);
}
