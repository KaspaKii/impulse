// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The terms guest of spec/V3-ZK.md section 22.4 on the I20 prover pipeline: the same local
//! succinct proof, `identity_p254` and pinned Groth16 step, with the terms guest's ELF and image ID
//! (circuits/IMAGE_ID_V4). The statement is checked natively first, so no receipt is attempted
//! for a witness the guest would refuse.

use crate::{digest_bytes, err, prove_elf, ProofFile, ProverImage, Timings, ZkError};
use risc0_zkvm::Digest;
use terms_core::{statement, StatementOptions, Witness};

/// circuits/IMAGE_ID_V4 as committed: the terms guest's image ID from the Docker build.
pub const COMMITTED_IMAGE_ID_V4: &str = include_str!("../../IMAGE_ID_V4");

/// The terms guest's image ID as the 32 bytes the v4 template and the zk-sdk fragment use.
pub fn terms_guest_image_id() -> [u8; 32] {
    digest_bytes(Digest::from(impulse_zk_methods::TERMS_GUEST_ID))
}

/// Refuses unless the embedded terms guest is the one circuits/IMAGE_ID_V4 names
/// (`ZK_IMAGE_ID_MISMATCH`).
pub fn check_image_id_v4() -> Result<[u8; 32], ZkError> {
    let built = terms_guest_image_id();
    let committed = COMMITTED_IMAGE_ID_V4.trim();
    if committed != hex::encode(built) {
        return Err(err(
            "ZK_IMAGE_ID_MISMATCH",
            format!(
                "the built terms guest has image ID {}, circuits/IMAGE_ID_V4 says {committed}",
                hex::encode(built)
            ),
        ));
    }
    Ok(built)
}

/// Runs the statement natively over an encoded witness and returns J, or the refusal
/// (`ZK_H_WITNESS_INVALID` for a witness that does not parse, else the statement's own code).
pub fn precheck(witness: &[u8]) -> Result<Vec<u8>, ZkError> {
    let w = Witness::from_bytes(witness).map_err(|r| err(r.code, r.to_string()))?;
    statement(&w, StatementOptions { curve_checks: true }).map_err(|r| err(r.code, r.to_string()))
}

/// Proves the terms statement for an encoded witness (`terms_core::Witness::to_bytes`).
pub fn prove_terms(
    witness: &[u8],
    image: &ProverImage,
    container: &str,
) -> Result<(ProofFile, Timings), ZkError> {
    let image_id = check_image_id_v4()?;
    let j = precheck(witness)?;
    prove_elf(
        impulse_zk_methods::TERMS_GUEST_ELF,
        image_id,
        witness,
        &j,
        image,
        container,
    )
}

/// TEST ONLY (feature `fixtures`): proves with the forging guest, which commits `journal` and
/// checks nothing, for the tests that show the gate refuses a receipt of another image ID.
#[cfg(feature = "fixtures")]
pub fn prove_forged(
    journal: &[u8],
    image: &ProverImage,
    container: &str,
) -> Result<(ProofFile, Timings), ZkError> {
    prove_elf(
        impulse_zk_methods::FORGE_GUEST_ELF,
        crate::forge_guest_image_id(),
        journal,
        journal,
        image,
        container,
    )
}
