// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The list manifest of spec/V3-ZK.md section 5.6: a statement, signed by the list issuer, that
//! a root is version n of its list. The contract does not check it; `verify` does.
//!
//! ```text
//! M = 0x01 || network || list_id_len || list_id || list_version u32 BE || issued_at u64 BE
//!     || list_root
//! manifest_digest = BLAKE2b-256(key = "Impulse/zk/manifest/v1", message = M)
//! signature       = BIP-340 Schnorr signature of manifest_digest by list_issuer_key
//! ```
//!
//! Keyless: this module computes the digest the issuer signs and verifies a signature. The
//! issuer signs with its own signer; no Impulse component holds its key (rule 1, docs/ENGINEERING-RULES.md).

use super::ZkError;
use crate::terms::Network;
use secp256k1::{schnorr, Message, XOnlyPublicKey};

/// Manifest version byte.
pub const MANIFEST_VERSION: u8 = 0x01;
/// BLAKE2b key of the manifest digest, 22 ASCII bytes.
pub const MANIFEST_DOMAIN: &[u8] = b"Impulse/zk/manifest/v1";
/// Longest list id, in bytes.
pub const MAX_LIST_ID_LEN: usize = 64;

/// A list manifest. `list_id` is chosen by the issuer, 1 to 64 bytes of UTF-8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub network: Network,
    pub list_id: String,
    pub list_version: u32,
    /// Unix seconds.
    pub issued_at: u64,
    pub list_root: [u8; 32],
}

fn invalid(reason: &str) -> ZkError {
    ZkError::ManifestInvalid {
        reason: reason.into(),
    }
}

impl Manifest {
    /// A manifest; refuses a list id of 0 or more than 64 bytes (`ZK_MANIFEST_INVALID`).
    pub fn new(
        network: Network,
        list_id: &str,
        list_version: u32,
        issued_at: u64,
        list_root: [u8; 32],
    ) -> Result<Self, ZkError> {
        if list_id.is_empty() || list_id.len() > MAX_LIST_ID_LEN {
            return Err(invalid("list_id must be 1 to 64 bytes"));
        }
        if list_id.chars().any(char::is_control) {
            return Err(invalid("list_id holds a control character"));
        }
        Ok(Self {
            network,
            list_id: list_id.into(),
            list_version,
            issued_at,
            list_root,
        })
    }

    /// The canonical bytes M.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(1 + 1 + 1 + self.list_id.len() + 4 + 8 + 32);
        m.push(MANIFEST_VERSION);
        m.push(match self.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        });
        m.push(self.list_id.len() as u8);
        m.extend_from_slice(self.list_id.as_bytes());
        m.extend_from_slice(&self.list_version.to_be_bytes());
        m.extend_from_slice(&self.issued_at.to_be_bytes());
        m.extend_from_slice(&self.list_root);
        m
    }

    /// Parses M; any other byte string is refused (`ZK_MANIFEST_INVALID`).
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], ZkError> {
            if bytes.len() - pos < n {
                return Err(invalid("the manifest is truncated"));
            }
            let out = &bytes[pos..pos + n];
            pos += n;
            Ok(out)
        };
        if take(1)?[0] != MANIFEST_VERSION {
            return Err(invalid("unknown manifest version"));
        }
        let network = match take(1)?[0] {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            _ => return Err(invalid("unknown network byte")),
        };
        let len = take(1)?[0] as usize;
        if len == 0 || len > MAX_LIST_ID_LEN {
            return Err(invalid("list_id must be 1 to 64 bytes"));
        }
        let list_id = std::str::from_utf8(take(len)?)
            .map_err(|_| invalid("list_id is not UTF-8"))?
            .to_string();
        let list_version = u32::from_be_bytes(take(4)?.try_into().expect("4 bytes"));
        let issued_at = u64::from_be_bytes(take(8)?.try_into().expect("8 bytes"));
        let list_root: [u8; 32] = take(32)?.try_into().expect("32 bytes");
        if pos != bytes.len() {
            return Err(invalid("bytes remain after the manifest"));
        }
        // One encoding per value: the same refusals `new` makes.
        Self::new(network, &list_id, list_version, issued_at, list_root)
    }

    /// The digest the issuer signs.
    pub fn digest(&self) -> [u8; 32] {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .key(MANIFEST_DOMAIN)
            .hash(&self.encode());
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        out
    }

    /// Checks the issuer's BIP-340 signature over the digest (`ZK_MANIFEST_INVALID`).
    pub fn verify_signature(
        &self,
        issuer_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), ZkError> {
        let key = XOnlyPublicKey::from_slice(issuer_key).map_err(|_| ZkError::IssuerKey)?;
        let sig = schnorr::Signature::from_slice(signature)
            .map_err(|_| invalid("the signature is malformed"))?;
        sig.verify(&Message::from_digest(self.digest()), &key)
            .map_err(|_| invalid("the signature does not verify under the list issuer key"))
    }

    /// Checks that this manifest speaks about `root` on `network` (`ZK_MANIFEST_INVALID`).
    pub fn check_binding(&self, network: Network, root: &[u8; 32]) -> Result<(), ZkError> {
        if self.network != network {
            return Err(invalid("the manifest names another network"));
        }
        if self.list_root != *root {
            return Err(invalid("the manifest names another list root"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blake(m: &[u8]) -> String {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .key(MANIFEST_DOMAIN)
            .hash(m);
        super::super::hex(h.as_bytes())
    }

    #[test]
    fn keyed_hash_known_answers() {
        // spec/V3-ZK.md section 5.6 (Python hashlib.blake2b).
        assert_eq!(
            blake(b""),
            "6783cd7f7b56d97a8ecf7289e3835aac964a7be48fc668510f50bd763fbf39e6"
        );
        assert_eq!(
            blake(b"abc"),
            "41d7a32ff0778cd5986d942dc77220548918a6ef1aa0c1d5556afa353426224c"
        );
    }

    fn sample() -> Manifest {
        Manifest::new(Network::Mainnet, "issuer-list", 7, 1_760_000_000, [5; 32]).unwrap()
    }

    #[test]
    fn round_trip_and_layout() {
        let m = sample();
        let b = m.encode();
        assert_eq!(b[0], 1);
        assert_eq!(b[1], 0);
        assert_eq!(b[2] as usize, "issuer-list".len());
        assert_eq!(b.len(), 3 + 11 + 4 + 8 + 32);
        assert_eq!(Manifest::decode(&b).unwrap(), m);
    }

    #[test]
    fn decode_refuses_everything_else() {
        let good = sample().encode();
        for cut in 0..good.len() {
            assert_eq!(
                Manifest::decode(&good[..cut]).unwrap_err().code(),
                "ZK_MANIFEST_INVALID",
                "cut at {cut}"
            );
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(Manifest::decode(&extra).is_err());
        let mut bad = good.clone();
        bad[0] = 2;
        assert!(Manifest::decode(&bad).is_err());
        let mut bad = good.clone();
        bad[1] = 2;
        assert!(Manifest::decode(&bad).is_err());
        let mut bad = good.clone();
        bad[2] = 0;
        assert!(Manifest::decode(&bad).is_err());
        let mut bad = good;
        bad[3] = 0xff; // not UTF-8
        assert!(Manifest::decode(&bad).is_err());
    }

    #[test]
    fn list_id_bounds() {
        assert!(Manifest::new(Network::Mainnet, "", 1, 0, [1; 32]).is_err());
        assert!(Manifest::new(Network::Mainnet, &"x".repeat(65), 1, 0, [1; 32]).is_err());
        assert!(Manifest::new(Network::Mainnet, &"x".repeat(64), 1, 0, [1; 32]).is_ok());
        assert!(Manifest::new(Network::Mainnet, "a\nb", 1, 0, [1; 32]).is_err());
    }

    #[test]
    fn binding() {
        let m = sample();
        m.check_binding(Network::Mainnet, &[5; 32]).unwrap();
        assert!(m.check_binding(Network::Testnet, &[5; 32]).is_err());
        assert!(m.check_binding(Network::Mainnet, &[6; 32]).is_err());
    }

    #[test]
    fn signature_checks_refuse_what_is_not_a_signature_of_the_digest() {
        // No key exists here (rule 1, docs/ENGINEERING-RULES.md): a made-up signature does not verify, a bad key
        // is the issuer-key refusal, and the signature path that does verify is run in
        // impulse-cli/src/zk_tests.rs, where a key file signs the digest.
        let m = sample();
        let sig = [0x11u8; 64];
        let key = unhex_key("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(
            m.verify_signature(&key, &sig).unwrap_err().code(),
            "ZK_MANIFEST_INVALID"
        );
        assert_eq!(
            m.verify_signature(&[0xff; 32], &sig).unwrap_err().code(),
            "ZK_ISSUER_KEY"
        );
    }

    fn unhex_key(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
