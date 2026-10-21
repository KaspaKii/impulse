// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
use {
    codama::Codama,
    std::{env, fs, path::Path},
};

fn main() {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-env-changed=GENERATE_IDL");

    if let Err(e) = generate_idl() {
        println!("cargo:warning=Failed to generate IDL: {}", e)
    }
}

fn generate_idl() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_path = Path::new(&manifest_dir);
    let codama = Codama::load(crate_path)?;
    let idl_json = codama.get_json_idl()?;

    let parsed: serde_json::Value = serde_json::from_str(&idl_json)?;
    let mut formatted_json = serde_json::to_string_pretty(&parsed)?;
    formatted_json.push('\n');

    // Impulse: the IDL lives in this crate (solana/programs/impulse-solana/idl/).
    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join("impulse_solana.json");
    fs::write(&idl_path, formatted_json)?;

    Ok(())
}
