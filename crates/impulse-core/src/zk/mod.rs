// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Proof-carrying settlement, the list-gated settle (spec/V3-ZK.md). Behind the non-default cargo
//! feature `zk`: the default build, which the WASM SDK and the watcher use, links none of it.
//!
//! Keyless by rule (rule 1, docs/ENGINEERING-RULES.md). Nothing here holds, derives or receives a private key. A
//! list's salts hide its entries; they are not keys, are drawn from the operating system's random
//! number generator, are erased on drop and are written only into each member's path file.
//!
//! Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not
//! check identity, eligibility, sanctions status or onward transfers. The delivery owner is
//! public on chain.

mod build;
#[cfg(all(test, impulse_v3_artifact))]
mod e2e_tests;
mod error;
#[cfg(test)]
mod golden;
mod ipst;
mod journal;
mod list;
mod manifest;
mod proof;
pub mod template;
mod terms;
mod verify;

pub use build::{
    fund_kas, fund_kcc20, refund, settle, GATE_FLOOR_UNITS, V3_COMPUTE_MASS_CAP,
    V3_STORAGE_MASS_CAP, V3_TRANSIENT_MASS_CAP, VERIFY_MARGIN_UNITS, VERIFY_UNITS,
};
pub use error::{ZkError, ZK_ERROR_CODES};
pub use ipst::{IpstV3, IPST_VERSION_V3};
pub use journal::{journal, journal_hash, JOURNAL_TAG};
pub use list::{
    leaf, node, owner_spk, p2sh_spk, parse_list, root_from_path, root_is_unusable, sha256,
    ListTree, MemberPath, DEPTH, EMPTY_ROOT, LEAF_TAG, MAX_ENTRIES, NODE_PREFIX,
};
pub use manifest::{Manifest, MANIFEST_DOMAIN, MANIFEST_VERSION, MAX_LIST_ID_LEN};
pub use proof::{ProofBytes, PROOF_LEN};
pub use template::{
    check as check_template, decode as decode_vault, template_hash_of_instance, vault_address_v3,
    FundableVaultV3, TemplateV3, VaultV3, CONTRACT_NAME_V3,
};
pub use terms::{
    is_empty_tree_root, TermsV3, ValidatedTermsV3, TERMS_V3_HASH_DOMAIN, TERMS_V3_VERSION,
};
pub use verify::{
    check_manifest, check_path, verify_addresses_v3, verify_revealed_script_v3, verify_v3,
    ManifestStatus, OfferedAddressesV3, PathStatus, VerifiedAddressV3, VerifyReportV3,
};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cross-checks against the real fixtures of the circuits workspace (`tests/engine/fixtures/v3/proofs`):
/// this crate's list rules, journal and proof parser against the guest's inputs and receipts.
#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::terms::{IdentifierType, Kcc20Owner};
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v3/proofs")
    }

    fn json(name: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(dir().join(name)).expect("fixture file");
        serde_json::from_str(&text).expect("fixture json")
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn b32(v: &serde_json::Value) -> [u8; 32] {
        unhex(v.as_str().unwrap()).try_into().unwrap()
    }

    #[test]
    fn guest_inputs_agree_with_this_crate() {
        for name in ["a_list1", "a_list1000", "b_list1000", "c_list1000_p2sh"] {
            let inputs = json(&format!("{name}.inputs.json"));
            let proof = json(&format!("{name}.proof.json"));
            let root = b32(&inputs["root"]);
            let owner_bytes = unhex(inputs["owner_spk"].as_str().unwrap());
            let vault_spk = unhex(inputs["vault_spk"].as_str().unwrap());
            let owner = Kcc20Owner {
                identifier_type: if owner_bytes.len() == 36 {
                    IdentifierType::PubKey
                } else {
                    IdentifierType::ScriptHash
                },
                identifier: if owner_bytes.len() == 36 {
                    owner_bytes[3..35].try_into().unwrap()
                } else {
                    owner_bytes[4..36].try_into().unwrap()
                },
            };
            assert_eq!(owner_spk(&owner).unwrap(), owner_bytes, "{name}");
            let siblings: Vec<[u8; 32]> = inputs["path"]["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(b32)
                .collect();
            let path = MemberPath::new(
                inputs["path"]["index"].as_u64().unwrap() as u32,
                b32(&inputs["path"]["salt"]),
                &siblings,
            )
            .unwrap();
            path.check(&owner, &root)
                .unwrap_or_else(|e| panic!("{name}: {e}"));

            let vault_hash: [u8; 32] = vault_spk[4..36].try_into().unwrap();
            let j = journal(&root, &vault_hash, &owner).unwrap();
            assert_eq!(hex(&j), proof["journal"].as_str().unwrap(), "{name}");
            assert_eq!(
                hex(&journal_hash(&j)),
                proof["journal_hash"].as_str().unwrap(),
                "{name}"
            );
            ProofBytes::parse(&unhex(proof["proof"].as_str().unwrap()))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn a_bit_flipped_proof_usually_does_not_parse_or_is_left_to_the_engine() {
        // A flipped bit may still be a curve point; then only the engine refuses it
        // (v3_proof_bit_flip_refused). Here: the parser never panics on any single-bit flip.
        let proof = json("a_list1.proof.json");
        let good = unhex(proof["proof"].as_str().unwrap());
        for bit in 0..good.len() * 8 {
            let mut p = good.clone();
            p[bit / 8] ^= 1 << (bit % 8);
            let _ = ProofBytes::parse(&p);
        }
    }
}
