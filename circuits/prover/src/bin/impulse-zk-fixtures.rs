// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! TEST FIXTURES ONLY. Makes and checks the committed proof fixtures of spec/V3-ZK.md 13.1, 13.2.
//!
//! impulse-zk-fixtures --out <dir> [--vaults <vaults.json>] [--only <name>[,<name>...]]
//! impulse-zk-fixtures --check <dir>
//!
//! `--out` proves every fixture (or the named ones) with the real list guest, and the forging
//! fixture with the test-only forging guest, and writes `<name>.inputs.json`,
//! `<name>.proof.json`, `cases.json`, `lists.json` and `vaults.json`. `--vaults` maps vault names
//! to real template v3 scriptPubKeys; without it every vault is a stand-in. `--check` recomputes
//! every deterministic file, compares, and runs every case in the pinned engine.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use impulse_zk_prover::fixtures::{
    cases, check_dir, compute, inputs, list, proof_defs, read_vaults,
};
use impulse_zk_prover::{list_core, prove_elf, HostSha, ProverImage, PROVER_IMAGE_PIN};

fn write_json<T: serde::Serialize>(dir: &Path, f: &str, v: &T) {
    std::fs::write(
        dir.join(f),
        serde_json::to_string_pretty(v).expect("json") + "\n",
    )
    .expect("write");
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--check" {
        match check_dir(Path::new(&args[1])) {
            Ok(lines) => {
                for l in lines {
                    println!("{l}");
                }
                println!("fixtures: ok");
            }
            Err(e) => die(e),
        }
        return;
    }
    make(&args);
}

fn make(args: &[String]) {
    let mut out = None;
    let mut vaults_file = None;
    let mut only: Option<Vec<String>> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next().cloned()) {
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            ("--vaults", Some(v)) => vaults_file = Some(PathBuf::from(v)),
            ("--only", Some(v)) => only = Some(v.split(',').map(String::from).collect()),
            _ => {
                eprintln!("usage: impulse-zk-fixtures --out <dir> [--vaults <file>] [--only <names>] | --check <dir>");
                std::process::exit(2)
            }
        }
    }
    let Some(dir) = out else {
        die("--out is required")
    };
    std::fs::create_dir_all(&dir).expect("out dir");
    let vaults = read_vaults(vaults_file.as_deref()).unwrap_or_else(|e| die(e));
    let image = ProverImage::parse(PROVER_IMAGE_PIN).unwrap_or_else(|e| die(e));
    impulse_zk_prover::check_image_id().unwrap_or_else(|e| die(e));

    let vm: BTreeMap<String, String> = vaults
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();
    write_json(&dir, "vaults.json", &vm);
    let mut lists = BTreeMap::new();
    for name in ["list1", "list1000"] {
        let t = list_core::tree::Tree::build::<HostSha>(&list(name)).expect("list");
        lists.insert(
            name,
            serde_json::json!({ "size": t.len(), "root": hex::encode(t.root()) }),
        );
    }
    write_json(&dir, "lists.json", &lists);
    for d in proof_defs() {
        let inp = inputs(&d, &vaults);
        write_json(&dir, &format!("{}.inputs.json", d.name), &inp);
        if let Some(o) = &only {
            if !o.iter().any(|n| n == d.name) {
                continue;
            }
        }
        let c = compute(&d, &vaults);
        let container = format!(
            "impulse-zk-fixture-{}-{}",
            d.name.replace('_', "-"),
            std::process::id()
        );
        let result = if d.guest == "forge" {
            // The forging guest reads J itself and commits it unchecked.
            prove_elf(
                impulse_zk_methods::FORGE_GUEST_ELF,
                impulse_zk_prover::forge_guest_image_id(),
                &c.journal,
                &c.journal,
                &image,
                &container,
            )
        } else {
            let public = impulse_zk_prover::Public {
                root: c.root,
                vault_spk: c.vault_spk,
                owner_spk: c.owner_spk,
            };
            impulse_zk_prover::prove_membership(&inp.path, &public, &image, &container)
        };
        let (pf, t) = result.unwrap_or_else(|e| die(format!("{}: {e}", d.name)));
        write_json(&dir, &format!("{}.proof.json", d.name), &pf);
        println!(
            "{}: proved in {} ms ({} cycles, {} segments)",
            d.name, t.total_ms, t.total_cycles, t.segments
        );
    }
    write_json(&dir, "cases.json", &cases(&vaults));
}
