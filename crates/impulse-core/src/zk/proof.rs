// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The proof as the settle carries it (spec/V3-ZK.md sections 3.2, 6.3, 11): 128 bytes, a
//! compressed BN254 Groth16 proof (G1 32 bytes, G2 64 bytes, G1 32 bytes). The builder checks the
//! length and that the bytes parse as curve points the way the Kaspa precompile reads them
//! (`ZK_PROOF_MALFORMED`); whether the proof verifies for a vault is the engine's question
//! (`ZK_PROOF_INVALID`).

use super::ZkError;
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

/// Length of a compressed Groth16 proof over BN254.
pub const PROOF_LEN: usize = 128;

/// A 128-byte proof that parses as a compressed Groth16 proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBytes([u8; PROOF_LEN]);

impl ProofBytes {
    /// Checks the length and parses the points, with subgroup checks (`ZK_PROOF_MALFORMED`).
    pub fn parse(bytes: &[u8]) -> Result<Self, ZkError> {
        let malformed = |reason: String| ZkError::ProofMalformed { reason };
        if bytes.len() != PROOF_LEN {
            return Err(malformed(format!(
                "a proof is {PROOF_LEN} bytes, found {}",
                bytes.len()
            )));
        }
        let mut reader = bytes;
        Proof::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|e| malformed(format!("not a compressed Groth16 proof: {e}")))?;
        if !reader.is_empty() {
            return Err(malformed("bytes remain after the proof".into()));
        }
        let mut out = [0u8; PROOF_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_checked_first() {
        for len in [0usize, 1, 127, 129, 256] {
            assert_eq!(
                ProofBytes::parse(&vec![0u8; len]).unwrap_err().code(),
                "ZK_PROOF_MALFORMED"
            );
        }
    }

    #[test]
    fn garbage_of_the_right_length_does_not_parse() {
        // 0xff... is not a valid compressed point encoding (x above the field prime).
        assert_eq!(
            ProofBytes::parse(&[0xff; PROOF_LEN]).unwrap_err().code(),
            "ZK_PROOF_MALFORMED"
        );
    }
}
