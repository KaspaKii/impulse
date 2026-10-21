// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-zk-prove: proves that the buyer's delivery owner is in an issuer list, locally.
//!
//! impulse-zk-prove --path <path.json> --root <hex32> --vault-spk <hex37> --owner-spk <hex36|hex37>
//!                  --out <proof.json> [--timings <timings.json>] [--container <name>]
//! impulse-zk-prove --image-id      print the embedded list guest's image ID
//!
//! The path file and the salt in it stay on this machine; nothing is sent anywhere. Refusals print
//! `error: <CODE>: <reason>` and exit 1.
use std::path::PathBuf;

use impulse_zk_prover::{
    prove_membership, read_json, PathFile, ProverImage, Public, PROVER_IMAGE_PIN,
};

fn usage() -> ! {
    eprintln!(
        "usage: impulse-zk-prove --path <path.json> --root <hex> --vault-spk <hex> --owner-spk <hex> --out <proof.json> \
         [--timings <file>] [--container <name>]\n       impulse-zk-prove --image-id"
    );
    std::process::exit(2)
}

fn fail(code: &str, msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {code}: {msg}");
    std::process::exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--image-id"] {
        println!("{}", hex::encode(impulse_zk_prover::list_guest_image_id()));
        return;
    }
    let mut path = None;
    let mut root = None;
    let mut vault = None;
    let mut owner = None;
    let mut out = None;
    let mut timings = None;
    let mut container = format!("impulse-zk-groth16-{}", std::process::id());
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let v = it.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--path" => path = Some(PathBuf::from(v)),
            "--root" => root = Some(v),
            "--vault-spk" => vault = Some(v),
            "--owner-spk" => owner = Some(v),
            "--out" => out = Some(PathBuf::from(v)),
            "--timings" => timings = Some(PathBuf::from(v)),
            "--container" => container = v,
            _ => usage(),
        }
    }
    let (Some(path), Some(root), Some(vault), Some(owner), Some(out)) =
        (path, root, vault, owner, out)
    else {
        usage()
    };
    let pf: PathFile = read_json(&path).unwrap_or_else(|e| fail("ZK_PATH_INVALID", e));
    let root: [u8; 32] = hex::decode(&root)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| fail("ZK_PATH_INVALID", "--root is not 32 bytes of hex"));
    let vault_spk =
        hex::decode(&vault).unwrap_or_else(|_| fail("ZK_PATH_INVALID", "--vault-spk is not hex"));
    let owner_spk =
        hex::decode(&owner).unwrap_or_else(|_| fail("ZK_PATH_INVALID", "--owner-spk is not hex"));
    let image = ProverImage::parse(PROVER_IMAGE_PIN).unwrap_or_else(|e| fail(e.code, e.message));
    let public = Public {
        root,
        vault_spk,
        owner_spk,
    };
    let (proof, t) = prove_membership(&pf, &public, &image, &container)
        .unwrap_or_else(|e| fail(e.code, e.message));
    std::fs::write(
        &out,
        serde_json::to_string_pretty(&proof).expect("json") + "\n",
    )
    .unwrap_or_else(|e| fail("ZK_PROVER", format!("{}: {e}", out.display())));
    if let Some(tp) = timings {
        std::fs::write(&tp, serde_json::to_string_pretty(&t).expect("json") + "\n")
            .unwrap_or_else(|e| fail("ZK_PROVER", format!("{}: {e}", tp.display())));
    }
    println!(
        "proof written: {} (journal_hash {})",
        out.display(),
        proof.journal_hash
    );
}
