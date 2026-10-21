// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The journal of spec/V3-ZK.md section 5.2, the bytes the list guest commits and the asset
//! vault recomputes in script:
//!
//! ```text
//! J = "Impulse/zk/wl/v1" || list_root || vault_spk (37) || owner_spk (36 or 37)
//! journal_hash = SHA-256(J)
//! ```
//!
//! `owner_spk` is last and the only field of variable length, so J parses one way.

use super::list::{owner_spk, p2sh_spk, sha256};
use super::ZkError;
use crate::terms::Kcc20Owner;

/// Journal domain tag, 16 ASCII bytes.
pub const JOURNAL_TAG: &[u8; 16] = b"Impulse/zk/wl/v1";

/// J for a list root, the asset vault's script hash and the buyer delivery owner. A covenant ID
/// owner has no scriptPubKey (`ZK_DELIVERY_OWNER_TYPE`).
pub fn journal(
    list_root: &[u8; 32],
    asset_vault_script_hash: &[u8; 32],
    owner: &Kcc20Owner,
) -> Result<Vec<u8>, ZkError> {
    let owner = owner_spk(owner)?;
    let mut j = Vec::with_capacity(16 + 32 + 37 + owner.len());
    j.extend_from_slice(JOURNAL_TAG);
    j.extend_from_slice(list_root);
    j.extend_from_slice(&p2sh_spk(asset_vault_script_hash));
    j.extend_from_slice(&owner);
    Ok(j)
}

/// `SHA-256(J)`, the value the script passes to `r0.g16.verify` and the RISC Zero journal digest.
pub fn journal_hash(journal: &[u8]) -> [u8; 32] {
    sha256(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::IdentifierType;

    #[test]
    fn lengths_follow_the_owner_type() {
        let pk = Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: [3; 32],
        };
        let sh = Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: [3; 32],
        };
        let root = [1u8; 32];
        let vault = [2u8; 32];
        assert_eq!(journal(&root, &vault, &pk).unwrap().len(), 121);
        assert_eq!(journal(&root, &vault, &sh).unwrap().len(), 122);
        // A P2PK and a P2SH owner over the same 32 bytes give different journals.
        assert_ne!(
            journal(&root, &vault, &pk).unwrap(),
            journal(&root, &vault, &sh).unwrap()
        );
    }

    #[test]
    fn each_field_is_in_the_journal() {
        let owner = Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: [3; 32],
        };
        let base = journal(&[1; 32], &[2; 32], &owner).unwrap();
        assert_ne!(base, journal(&[9; 32], &[2; 32], &owner).unwrap());
        assert_ne!(base, journal(&[1; 32], &[9; 32], &owner).unwrap());
        let mut other = owner;
        other.identifier = [9; 32];
        assert_ne!(base, journal(&[1; 32], &[2; 32], &other).unwrap());
        assert_eq!(&base[..16], b"Impulse/zk/wl/v1");
    }

    #[test]
    fn covenant_owner_has_no_journal() {
        let cov = Kcc20Owner {
            identifier_type: IdentifierType::CovenantId,
            identifier: [3; 32],
        };
        assert_eq!(
            journal(&[1; 32], &[2; 32], &cov).unwrap_err().code(),
            "ZK_DELIVERY_OWNER_TYPE"
        );
    }
}
