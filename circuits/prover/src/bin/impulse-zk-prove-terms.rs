// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-zk-prove-terms: proves the hashed-terms statement of spec/V3-ZK.md section 22.4, locally.
//!
//! impulse-zk-prove-terms --witness <file> --out <proof.json> [--timings <file>] [--container <name>]
//! impulse-zk-prove-terms --image-id       print the embedded terms guest's image ID
//! impulse-zk-prove-terms --check <file>   run the statement natively on the witness, print J
//! impulse-zk-prove-terms --verify <proof.json>   check a proof file in the pinned script engine
//!
//! The witness file is `terms_core::Witness::to_bytes` (the canonical terms, the journal, the
//! redeem scripts of the escrowed tokens). The terms stay on this machine; nothing is sent
//! anywhere. Refusals print `error: <CODE>: <reason>` and exit 1.
use std::path::PathBuf;

use impulse_zk_prover::terms::{precheck, prove_terms, terms_guest_image_id};
use impulse_zk_prover::{ProverImage, PROVER_IMAGE_PIN};

fn usage() -> ! {
    eprintln!(
        "usage: impulse-zk-prove-terms --witness <file> --out <proof.json> [--timings <file>] [--container <name>]\n       \
         impulse-zk-prove-terms --image-id\n       impulse-zk-prove-terms --check <file>\n       \
         impulse-zk-prove-terms --verify <proof.json>{}",
        if cfg!(feature = "fixtures") {
            "\n       impulse-zk-prove-terms --forge-journal <file> --out <proof.json>   (test only)"
        } else {
            ""
        }
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
        println!("{}", hex::encode(terms_guest_image_id()));
        return;
    }
    let mut witness = None;
    let mut out = None;
    let mut timings = None;
    let mut check = None;
    let mut verify = None;
    let mut forge = None;
    let mut container = format!("impulse-zk-groth16-{}", std::process::id());
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let v = it.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--witness" => witness = Some(PathBuf::from(v)),
            "--out" => out = Some(PathBuf::from(v)),
            "--timings" => timings = Some(PathBuf::from(v)),
            "--container" => container = v,
            "--check" => check = Some(PathBuf::from(v)),
            "--verify" => verify = Some(PathBuf::from(v)),
            "--forge-journal" if cfg!(feature = "fixtures") => forge = Some(PathBuf::from(v)),
            _ => usage(),
        }
    }
    let read = |p: &PathBuf| {
        std::fs::read(p)
            .unwrap_or_else(|e| fail("ZK_H_WITNESS_INVALID", format!("{}: {e}", p.display())))
    };
    if let Some(p) = check {
        let j = precheck(&read(&p)).unwrap_or_else(|e| fail(e.code, e.message));
        println!("{}", hex::encode(j));
        return;
    }
    if let Some(p) = verify {
        let pf: impulse_zk_prover::ProofFile =
            impulse_zk_prover::read_json(&p).unwrap_or_else(|e| fail("ZK_H_PROOF_MALFORMED", e));
        if pf.image_id_bytes() != terms_guest_image_id() {
            fail(
                "ZK_IMAGE_ID_MISMATCH",
                "the proof file was not made by the terms guest this build embeds",
            );
        }
        let journal = pf.journal_bytes();
        if hex::encode(impulse_zk_prover::sha256(&journal)) != pf.journal_hash {
            fail(
                "ZK_H_PROOF_MALFORMED",
                "journal_hash is not SHA-256 of the journal",
            );
        }
        impulse_zk_prover::engine_verify(&pf.proof_bytes(), &journal, pf.image_id_bytes())
            .unwrap_or_else(|e| fail("ZK_H_PROOF_INVALID", e));
        println!("verified: the proof is accepted by the pinned engine for this journal");
        return;
    }
    let Some(out) = out else { usage() };
    let image = ProverImage::parse(PROVER_IMAGE_PIN).unwrap_or_else(|e| fail(e.code, e.message));
    #[cfg(feature = "fixtures")]
    let forged = forge.map(|p| {
        impulse_zk_prover::terms::prove_forged(&read(&p), &image, &container)
            .unwrap_or_else(|e| fail(e.code, e.message))
    });
    #[cfg(not(feature = "fixtures"))]
    let forged: Option<(impulse_zk_prover::ProofFile, impulse_zk_prover::Timings)> = {
        let _ = forge;
        None
    };
    let (proof, t) = match forged {
        Some(x) => x,
        None => {
            let Some(w) = witness else { usage() };
            prove_terms(&read(&w), &image, &container).unwrap_or_else(|e| fail(e.code, e.message))
        }
    };
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
