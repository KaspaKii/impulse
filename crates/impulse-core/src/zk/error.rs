// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Refusals of `impulse_core::zk`. Every variant maps to one stable code (spec/V3-ZK.md section
//! 12, spec/ERRORS.md "ZK_ codes"). A terms refusal met on the way keeps its own `TERMS_*` code,
//! a template refusal its `TEMPLATE_*` code and a builder refusal its `TX_*` code, as section 12
//! says. Integrators match on `code()`, never on the Display text.

use crate::template::TemplateError;
use crate::terms::TermsError;
use crate::tx::TxError;
use std::fmt;

/// Why a v3 value was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkError {
    /// The terms v3 decoder was given a version byte other than 3.
    TermsVersion { version: u8 },
    /// Terms v3 name Direct settlement.
    TermsDirect,
    /// The buyer delivery owner is not of type PUBKEY or SCRIPT_HASH.
    DeliveryOwnerType,
    /// list_root is all zero or the root of the empty tree.
    RootInvalid,
    /// The embedded v3 artifact, `TEMPLATE_HASH_V3` or `IMAGE_ID` cannot be used.
    ArtifactInvalid { reason: String },
    /// The v3 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V3`.
    TemplateHashMismatch { expected: [u8; 32], found: [u8; 32] },
    /// The image ID in template v3 differs from `circuits/IMAGE_ID` or from the prover's guest.
    ImageIdMismatch { reason: String },
    /// The script does not run template v3.
    NotV3Vault,
    /// The state does not parse as the v3 state.
    StateMalformed { reason: String },
    /// A v3 state field holds a value no terms v3 value encodes to.
    StateInvalid { reason: String },
    /// The script is not the v3 instantiation of the terms it decodes to.
    Noncanonical,
    /// An entry is not a Schnorr P2PK or P2SH address or owner of the terms' network.
    ListEntry { line: usize, reason: String },
    /// The list is empty or has more than 1,048,576 entries.
    ListSize { count: usize },
    /// The delivery owner is not in the list.
    NotMember,
    /// The path file is malformed or does not lead from the owner's salted leaf to list_root.
    PathInvalid { reason: String },
    /// The proof is not 128 bytes or does not parse as a compressed Groth16 proof.
    ProofMalformed { reason: String },
    /// The proof does not verify for this vault's journal in the pinned engine.
    ProofInvalid { reason: String },
    /// No receipt was produced: r0vm or the Groth16 step is missing or of another version, or
    /// the guest refused. Raised by the prover; listed here so the frozen list is complete.
    Prover { reason: String },
    /// The compute, storage or transient mass exceeds its v3 cap.
    TxMass {
        dimension: &'static str,
        mass: u64,
        cap: u64,
    },
    /// `ipst` is not 4.
    IpstVersion { found: String },
    /// The offered address pays neither vault of these v3 terms.
    VerifyAddressMismatch,
    /// The revealed script does not run the pinned template v3.
    VerifyTemplateMismatch,
    /// list_issuer_key is not a valid BIP-340 x-only public key.
    IssuerKey,
    /// Terms v3 without an authority were requested without `--no-authority`.
    AuthorityAbsent,
    /// The manifest is malformed, names another root or network, or its signature does not
    /// verify under list_issuer_key.
    ManifestInvalid { reason: String },
    /// The local Groth16 prover image's digest differs from `circuits/GROTH16_PROVER_IMAGE`.
    /// Raised by the prover; listed here so the frozen list is complete.
    ProverImage { reason: String },

    /// A terms refusal with its own `TERMS_*` code (sections 7.2, 7.3).
    Terms(TermsError),
    /// A template refusal with its own `TEMPLATE_*` code.
    Template(TemplateError),
    /// A builder refusal with its own `TX_*` code (section 12).
    Tx(TxError),
}

/// Every `ZK_` code, in the order of spec/V3-ZK.md section 12. Frozen once merged: a test pins
/// this list and the parity suite compares it with spec/ERRORS.md; it may only grow at the end.
pub const ZK_ERROR_CODES: [&str; 26] = [
    "ZK_TERMS_VERSION",
    "ZK_TERMS_DIRECT",
    "ZK_DELIVERY_OWNER_TYPE",
    "ZK_ROOT_INVALID",
    "ZK_ARTIFACT_INVALID",
    "ZK_TEMPLATE_HASH_MISMATCH",
    "ZK_IMAGE_ID_MISMATCH",
    "ZK_NOT_V3_VAULT",
    "ZK_STATE_MALFORMED",
    "ZK_STATE_INVALID",
    "ZK_NONCANONICAL",
    "ZK_LIST_ENTRY",
    "ZK_LIST_SIZE",
    "ZK_NOT_MEMBER",
    "ZK_PATH_INVALID",
    "ZK_PROOF_MALFORMED",
    "ZK_PROOF_INVALID",
    "ZK_PROVER",
    "ZK_TX_MASS",
    "ZK_IPST_VERSION",
    "ZK_VERIFY_ADDRESS_MISMATCH",
    "ZK_VERIFY_TEMPLATE_MISMATCH",
    "ZK_ISSUER_KEY",
    "ZK_AUTHORITY_ABSENT",
    "ZK_MANIFEST_INVALID",
    "ZK_PROVER_IMAGE",
];

impl ZkError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TermsVersion { .. } => "ZK_TERMS_VERSION",
            Self::TermsDirect => "ZK_TERMS_DIRECT",
            Self::DeliveryOwnerType => "ZK_DELIVERY_OWNER_TYPE",
            Self::RootInvalid => "ZK_ROOT_INVALID",
            Self::ArtifactInvalid { .. } => "ZK_ARTIFACT_INVALID",
            Self::TemplateHashMismatch { .. } => "ZK_TEMPLATE_HASH_MISMATCH",
            Self::ImageIdMismatch { .. } => "ZK_IMAGE_ID_MISMATCH",
            Self::NotV3Vault => "ZK_NOT_V3_VAULT",
            Self::StateMalformed { .. } => "ZK_STATE_MALFORMED",
            Self::StateInvalid { .. } => "ZK_STATE_INVALID",
            Self::Noncanonical => "ZK_NONCANONICAL",
            Self::ListEntry { .. } => "ZK_LIST_ENTRY",
            Self::ListSize { .. } => "ZK_LIST_SIZE",
            Self::NotMember => "ZK_NOT_MEMBER",
            Self::PathInvalid { .. } => "ZK_PATH_INVALID",
            Self::ProofMalformed { .. } => "ZK_PROOF_MALFORMED",
            Self::ProofInvalid { .. } => "ZK_PROOF_INVALID",
            Self::Prover { .. } => "ZK_PROVER",
            Self::TxMass { .. } => "ZK_TX_MASS",
            Self::IpstVersion { .. } => "ZK_IPST_VERSION",
            Self::VerifyAddressMismatch => "ZK_VERIFY_ADDRESS_MISMATCH",
            Self::VerifyTemplateMismatch => "ZK_VERIFY_TEMPLATE_MISMATCH",
            Self::IssuerKey => "ZK_ISSUER_KEY",
            Self::AuthorityAbsent => "ZK_AUTHORITY_ABSENT",
            Self::ManifestInvalid { .. } => "ZK_MANIFEST_INVALID",
            Self::ProverImage { .. } => "ZK_PROVER_IMAGE",
            Self::Terms(e) => e.code(),
            Self::Template(e) => e.code(),
            Self::Tx(e) => e.code(),
        }
    }
}

impl fmt::Display for ZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::TermsVersion { version } => {
                write!(f, "{code}: terms v3 need version byte 3, found {version}")
            }
            Self::TermsDirect => write!(
                f,
                "{code}: terms v3 name Direct settlement, which has no contract to carry the gate"
            ),
            Self::DeliveryOwnerType => write!(
                f,
                "{code}: the buyer delivery owner must be a public key or a script hash"
            ),
            Self::RootInvalid => write!(
                f,
                "{code}: list_root is all zero or the root of the empty tree; nobody could settle"
            ),
            Self::ArtifactInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::TemplateHashMismatch { expected, found } => write!(
                f,
                "{code}: template hash {} where {} is pinned",
                hex(found),
                hex(expected)
            ),
            Self::ImageIdMismatch { reason } => write!(f, "{code}: {reason}"),
            Self::NotV3Vault => write!(f, "{code}: the script does not run template v3"),
            Self::StateMalformed { reason } => write!(f, "{code}: {reason}"),
            Self::StateInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::Noncanonical => write!(
                f,
                "{code}: the script is not the v3 instantiation of the terms it decodes to"
            ),
            Self::ListEntry { line, reason } => write!(f, "{code}: list line {line}: {reason}"),
            Self::ListSize { count } => write!(
                f,
                "{code}: a list holds 1 to 1048576 entries, found {count}"
            ),
            Self::NotMember => write!(f, "{code}: the delivery owner is not in the list"),
            Self::PathInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::ProofMalformed { reason } => write!(f, "{code}: {reason}"),
            Self::ProofInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::Prover { reason } => write!(f, "{code}: {reason}"),
            Self::TxMass {
                dimension,
                mass,
                cap,
            } => write!(f, "{code}: {dimension} mass {mass} exceeds the cap {cap}"),
            Self::IpstVersion { found } => {
                write!(f, "{code}: ipst version {found}, a v3 document is version 4")
            }
            Self::VerifyAddressMismatch => write!(
                f,
                "{code}: the address pays neither vault of these terms"
            ),
            Self::VerifyTemplateMismatch => write!(
                f,
                "{code}: the revealed script does not run the pinned template v3"
            ),
            Self::IssuerKey => write!(
                f,
                "{code}: list_issuer_key is not a valid BIP-340 x-only public key"
            ),
            Self::AuthorityAbsent => write!(
                f,
                "{code}: terms without an authority need --no-authority; the list issuer is the usual authority"
            ),
            Self::ManifestInvalid { reason } => write!(f, "{code}: {reason}"),
            Self::ProverImage { reason } => write!(f, "{code}: {reason}"),
            Self::Terms(e) => write!(f, "{e}"),
            Self::Template(e) => write!(f, "{e}"),
            Self::Tx(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ZkError {}

impl From<TermsError> for ZkError {
    fn from(e: TermsError) -> Self {
        Self::Terms(e)
    }
}

impl From<TemplateError> for ZkError {
    fn from(e: TemplateError) -> Self {
        Self::Template(e)
    }
}

impl From<TxError> for ZkError {
    fn from(e: TxError) -> Self {
        Self::Tx(e)
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frozen list: a code may be appended at the end, never renamed, reordered or removed.
    #[test]
    fn zk_error_codes_are_frozen() {
        let frozen = [
            "ZK_TERMS_VERSION",
            "ZK_TERMS_DIRECT",
            "ZK_DELIVERY_OWNER_TYPE",
            "ZK_ROOT_INVALID",
            "ZK_ARTIFACT_INVALID",
            "ZK_TEMPLATE_HASH_MISMATCH",
            "ZK_IMAGE_ID_MISMATCH",
            "ZK_NOT_V3_VAULT",
            "ZK_STATE_MALFORMED",
            "ZK_STATE_INVALID",
            "ZK_NONCANONICAL",
            "ZK_LIST_ENTRY",
            "ZK_LIST_SIZE",
            "ZK_NOT_MEMBER",
            "ZK_PATH_INVALID",
            "ZK_PROOF_MALFORMED",
            "ZK_PROOF_INVALID",
            "ZK_PROVER",
            "ZK_TX_MASS",
            "ZK_IPST_VERSION",
            "ZK_VERIFY_ADDRESS_MISMATCH",
            "ZK_VERIFY_TEMPLATE_MISMATCH",
            "ZK_ISSUER_KEY",
            "ZK_AUTHORITY_ABSENT",
            "ZK_MANIFEST_INVALID",
            "ZK_PROVER_IMAGE",
        ];
        assert_eq!(ZK_ERROR_CODES, frozen);
    }

    /// Every variant of the enum has a code in the list, and the list has no code without one.
    #[test]
    fn every_variant_has_a_listed_code() {
        let s = String::new;
        let h = [0u8; 32];
        let all = [
            ZkError::TermsVersion { version: 1 },
            ZkError::TermsDirect,
            ZkError::DeliveryOwnerType,
            ZkError::RootInvalid,
            ZkError::ArtifactInvalid { reason: s() },
            ZkError::TemplateHashMismatch {
                expected: h,
                found: h,
            },
            ZkError::ImageIdMismatch { reason: s() },
            ZkError::NotV3Vault,
            ZkError::StateMalformed { reason: s() },
            ZkError::StateInvalid { reason: s() },
            ZkError::Noncanonical,
            ZkError::ListEntry {
                line: 1,
                reason: s(),
            },
            ZkError::ListSize { count: 0 },
            ZkError::NotMember,
            ZkError::PathInvalid { reason: s() },
            ZkError::ProofMalformed { reason: s() },
            ZkError::ProofInvalid { reason: s() },
            ZkError::Prover { reason: s() },
            ZkError::TxMass {
                dimension: "compute",
                mass: 2,
                cap: 1,
            },
            ZkError::IpstVersion { found: s() },
            ZkError::VerifyAddressMismatch,
            ZkError::VerifyTemplateMismatch,
            ZkError::IssuerKey,
            ZkError::AuthorityAbsent,
            ZkError::ManifestInvalid { reason: s() },
            ZkError::ProverImage { reason: s() },
        ];
        let codes: Vec<&str> = all.iter().map(ZkError::code).collect();
        assert_eq!(codes, ZK_ERROR_CODES);
        for e in &all {
            assert!(e.to_string().starts_with(e.code()), "{e}");
        }
    }

    /// Every code in the list has a test that asserts it: its literal appears in test code
    /// outside this file (a `tests/` directory, a `*tests.rs` file, or after a `#[cfg(...test...)]` line),
    /// within six lines after an assertion macro opens. A new code without a test fails here.
    #[test]
    fn every_listed_code_is_asserted_by_a_test() {
        fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().into_owned();
                if p.is_dir() {
                    if name != "target" && name != "vendor" && !name.starts_with('.') {
                        rs_files(&p, out);
                    }
                } else if name.ends_with(".rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        rs_files(&root.join("crates"), &mut files);
        rs_files(&root.join("circuits"), &mut files);
        let this = std::path::Path::new(file!()).file_name().unwrap();
        let mut asserted = std::collections::BTreeSet::new();
        for f in files {
            if f.file_name() == Some(this) {
                continue;
            }
            let path = f.to_string_lossy().replace('\\', "/");
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let test_file = path.contains("/tests/") || path.ends_with("tests.rs");
            let lines: Vec<&str> = text.lines().collect();
            let mut in_tests = test_file;
            for (n, line) in lines.iter().enumerate() {
                if line.trim_start().starts_with("#[cfg(") && line.contains("test") {
                    in_tests = true;
                }
                if !in_tests {
                    continue;
                }
                for code in ZK_ERROR_CODES {
                    if line.contains(&format!("\"{code}\"")) {
                        let from = n.saturating_sub(6);
                        let near = lines[from..=n].iter().any(|l| l.contains("assert"));
                        if near {
                            asserted.insert(code);
                        }
                    }
                }
            }
        }
        let missing: Vec<&str> = ZK_ERROR_CODES
            .iter()
            .copied()
            .filter(|c| !asserted.contains(c))
            .collect();
        assert!(missing.is_empty(), "no test asserts: {missing:?}");
    }
}
