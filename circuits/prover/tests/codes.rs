// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The two prover refusals of spec/V3-ZK.md section 12 that no other test reaches:
//! `ZK_PROVER_IMAGE` (the pin, or the image it names, is wrong or absent) and `ZK_PROVER` (the
//! Groth16 step cannot run). No proving and no Docker daemon are needed.
use impulse_zk_prover::{shrink_wrap, ProverImage, PROVER_IMAGE_PIN};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn image_with(host: &str) -> ProverImage {
    ProverImage::parse(&format!(
        "image=example.invalid/prover\ntag=t\n{host}={DIGEST}\n"
    ))
    .unwrap()
}

#[test]
fn the_committed_pin_parses() {
    let i = ProverImage::parse(PROVER_IMAGE_PIN).unwrap();
    assert!(i.reference().is_ok());
}

#[test]
fn a_malformed_pin_is_prover_image() {
    for pin in [
        "image",
        "tag=t\nlinux/arm64=sha256:00",
        "image=x\nlinux/arm64=sha256:00",
        "image=x",
        "tag=t",
        "image=x\ntag=t\nlinux/arm64=sha256:zz00000000000000000000000000000000000000000000000000000000000000",
    ] {
        let e = ProverImage::parse(pin).unwrap_err();
        assert_eq!(e.code, "ZK_PROVER_IMAGE", "{pin}: {e}");
    }
}

#[test]
fn a_pin_without_this_hosts_platform_is_prover_image() {
    let other = match ProverImage::host_platform().unwrap() {
        "linux/arm64" => "linux/amd64",
        _ => "linux/arm64",
    };
    let e = image_with(other).reference().unwrap_err();
    assert_eq!(e.code, "ZK_PROVER_IMAGE");
}

#[test]
fn an_image_that_is_not_present_is_prover_image() {
    let image = image_with(ProverImage::host_platform().unwrap());
    assert_eq!(image.check_local().unwrap_err().code, "ZK_PROVER_IMAGE");
}

#[test]
fn a_seal_that_is_not_a_seal_is_prover() {
    let image = image_with(ProverImage::host_platform().unwrap());
    let e = shrink_wrap(&[1, 2, 3], &image, "impulse-zk-test").unwrap_err();
    assert_eq!(e.code, "ZK_PROVER", "{e}");
}
