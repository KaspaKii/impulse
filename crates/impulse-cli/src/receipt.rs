// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Settlement receipts (spec/CLI.md, "Settlement receipt"): what `impulse status` observed about
//! a transaction's acceptance, signed by whoever ran it, re-verifiable by anyone. The signature is
//! made by the signing module; this module only encodes, parses and verifies.

use crate::error::CliError;
use crate::json::{hex, parse_strict, Json, Obj};
use crate::signing::{self, SignRequest};
use crate::terms_file::network_name;
use impulse_core::terms::Network;
use secp256k1::{schnorr, Message, XOnlyPublicKey, SECP256K1};
use std::path::Path;

/// The receipt format version.
pub const RECEIPT_VERSION: u8 = 1;

/// blake2b-256 key for the receipt digest. Not the transaction sighash key, so a receipt
/// signature can never serve as a transaction signature.
pub const RECEIPT_DOMAIN: &[u8] = b"Impulse/receipt/v1";

/// What a node showed about one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub network: Network,
    pub terms_hash: [u8; 32],
    pub txid: [u8; 32],
    /// The chain block that accepted the transaction.
    pub accepting_block: [u8; 32],
    /// The accepting block's DAA score.
    pub daa_score: u64,
    /// The node's virtual DAA score at observation minus `daa_score`.
    pub depth: u64,
}

impl Observation {
    /// version, network, terms_hash, txid, accepting_block, daa_score LE, depth LE: 114 bytes.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(114);
        out.push(RECEIPT_VERSION);
        out.push(match self.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        });
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.accepting_block);
        out.extend_from_slice(&self.daa_score.to_le_bytes());
        out.extend_from_slice(&self.depth.to_le_bytes());
        out
    }

    /// The 32 bytes the signer signs.
    pub fn digest(&self) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .key(RECEIPT_DOMAIN)
            .hash(&self.canonical());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    fn fields(&self) -> Vec<(&'static str, Json)> {
        vec![
            ("version", Json::Num(RECEIPT_VERSION.into())),
            ("network", Json::Str(network_name(self.network).into())),
            ("terms_hash", Json::Str(hex(&self.terms_hash))),
            ("txid", Json::Str(hex(&self.txid))),
            ("accepting_block", Json::Str(hex(&self.accepting_block))),
            ("daa_score", Json::Str(self.daa_score.to_string())),
            ("depth", Json::Str(self.depth.to_string())),
        ]
    }

    /// The unsigned observation as JSON (status output without a key file).
    pub fn render(&self) -> String {
        Json::Obj(self.fields()).render()
    }
}

/// A signed observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub observation: Observation,
    /// x-only public key of the signer.
    pub signer: [u8; 32],
    /// BIP-340 signature over the observation's digest.
    pub signature: [u8; 64],
}

const KEYS: [&str; 9] = [
    "version",
    "network",
    "terms_hash",
    "txid",
    "accepting_block",
    "daa_score",
    "depth",
    "signer",
    "signature",
];

impl Receipt {
    /// Signs `observation` with the key file the user named, through the signing module.
    pub fn sign(
        observation: Observation,
        key_file: &Path,
        mainnet_explicit: bool,
    ) -> Result<Self, CliError> {
        let signed = signing::sign(&SignRequest {
            key_file,
            network: observation.network,
            mainnet_explicit,
            expected_signer: None,
            digest: observation.digest(),
        })?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&signed.signature[..64]);
        Ok(Self {
            observation,
            signer: signed.signer,
            signature,
        })
    }

    pub fn render(&self) -> String {
        self.to_json().render()
    }

    /// The receipt as a JSON value, for a document that embeds it.
    pub fn to_json(&self) -> Json {
        let mut fields = self.observation.fields();
        fields.push(("signer", Json::Str(hex(&self.signer))));
        fields.push(("signature", Json::Str(hex(&self.signature))));
        Json::Obj(fields)
    }

    /// The JSON form, nothing more (`RECEIPT_MALFORMED`). The signature is not checked here.
    pub fn parse(text: &str) -> Result<Self, CliError> {
        let malformed = |why: String| CliError::new("RECEIPT_MALFORMED", why);
        let value = parse_strict(text).map_err(malformed)?;
        let o = Obj::new("receipt", &value).map_err(malformed)?;
        o.keys(&KEYS, &[]).map_err(malformed)?;
        if o.num("version", u8::MAX.into()).map_err(malformed)? != u64::from(RECEIPT_VERSION) {
            return Err(malformed("receipt.version: only version 1 exists".into()));
        }
        let network = [Network::Mainnet, Network::Testnet][o
            .choice("network", &["mainnet", "testnet"])
            .map_err(malformed)?];
        let signature: [u8; 64] = o
            .hex("signature")
            .map_err(malformed)?
            .try_into()
            .map_err(|_| malformed("receipt.signature: expected 64 bytes".into()))?;
        Ok(Self {
            observation: Observation {
                network,
                terms_hash: o.hex32("terms_hash").map_err(malformed)?,
                txid: o.hex32("txid").map_err(malformed)?,
                accepting_block: o.hex32("accepting_block").map_err(malformed)?,
                daa_score: o.dec("daa_score").map_err(malformed)?,
                depth: o.dec("depth").map_err(malformed)?,
            },
            signer: o.hex32("signer").map_err(malformed)?,
            signature,
        })
    }

    /// The signature verifies over the digest for `signer`.
    pub fn verify_signature(&self) -> Result<(), CliError> {
        let invalid = |why: &str| CliError::new("RECEIPT_SIGNATURE_INVALID", why.to_string());
        let key = XOnlyPublicKey::from_slice(&self.signer)
            .map_err(|_| invalid("signer is not a valid x-only public key"))?;
        let sig = schnorr::Signature::from_slice(&self.signature)
            .map_err(|_| invalid("signature is malformed"))?;
        SECP256K1
            .verify_schnorr(&sig, &Message::from_digest(self.observation.digest()), &key)
            .map_err(|_| invalid("the signature does not verify for signer"))
    }

    /// With `--signer`, the receipt's signer must be that key.
    pub fn check_signer(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.signer != expected {
            return Err(CliError::new(
                "RECEIPT_SIGNER_MISMATCH",
                format!(
                    "signed by {}, expected {}",
                    hex(&self.signer),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }

    /// With `--terms` or `--terms-hash`, the receipt must be for that trade.
    pub fn check_terms_hash(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.observation.terms_hash != expected {
            return Err(CliError::new(
                "RECEIPT_TERMS_MISMATCH",
                format!(
                    "the receipt is for terms {}, not your terms {}",
                    hex(&self.observation.terms_hash),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }

    /// With `--txid`, the receipt must be for that transaction.
    pub fn check_txid(&self, expected: &[u8; 32]) -> Result<(), CliError> {
        if &self.observation.txid != expected {
            return Err(CliError::new(
                "RECEIPT_TXID_MISMATCH",
                format!(
                    "the receipt is for transaction {}, not {}",
                    hex(&self.observation.txid),
                    hex(expected)
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::signing::throwaway::key_file;
    use serde_json::Value;

    pub(crate) fn observation() -> Observation {
        Observation {
            network: Network::Testnet,
            terms_hash: [0x11; 32],
            txid: [0x22; 32],
            accepting_block: [0x33; 32],
            daa_score: 1000,
            depth: 10,
        }
    }

    #[test]
    fn digest_known_answer() {
        // Computed independently with Python's hashlib.blake2b(key=b"Impulse/receipt/v1").
        let o = observation();
        assert_eq!(o.canonical().len(), 114);
        assert_eq!(
            hex(&o.digest()),
            "b8683e8aaf6727cc2256bfc64dca118b03c7902993783cbb44e7e8abbeaaee36"
        );
    }

    #[test]
    fn sign_render_parse_verify() {
        let k = key_file();
        let r = Receipt::sign(observation(), &k.path, false).unwrap();
        assert_eq!(r.signer, k.signer);
        let text = r.render();
        assert!(!text.contains(k.content.trim_end()), "no key material");
        let back = Receipt::parse(&text).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.verify_signature(), Ok(()));
        assert_eq!(back.check_signer(&k.signer), Ok(()));
        assert_eq!(
            back.check_signer(&key_file().signer).unwrap_err().code(),
            "RECEIPT_SIGNER_MISMATCH"
        );
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"')?.split('"').next())
            .collect();
        assert_eq!(keys, KEYS, "keys in spec order");
    }

    #[test]
    fn a_receipt_is_checked_against_the_verifier_s_trade() {
        let k = key_file();
        let r = Receipt::sign(observation(), &k.path, false).unwrap();
        assert_eq!(r.check_terms_hash(&[0x11; 32]), Ok(()), "control");
        assert_eq!(r.check_txid(&[0x22; 32]), Ok(()), "control");
        assert_eq!(
            r.check_terms_hash(&[0x22; 32]).unwrap_err().code(),
            "RECEIPT_TERMS_MISMATCH"
        );
        assert_eq!(
            r.check_txid(&[0x11; 32]).unwrap_err().code(),
            "RECEIPT_TXID_MISMATCH"
        );
    }

    #[test]
    fn a_mainnet_receipt_needs_the_explicit_flag() {
        let k = key_file();
        let mut o = observation();
        o.network = Network::Mainnet;
        assert_eq!(
            Receipt::sign(o, &k.path, false).unwrap_err().code(),
            "SIGN_MAINNET_NOT_EXPLICIT"
        );
        assert!(Receipt::sign(o, &k.path, true).is_ok(), "control");
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let k = key_file();
        let r = Receipt::sign(observation(), &k.path, false).unwrap();
        let edits: [fn(&mut Receipt); 8] = [
            |r| r.observation.network = Network::Mainnet,
            |r| r.observation.terms_hash[0] ^= 1,
            |r| r.observation.txid[0] ^= 1,
            |r| r.observation.accepting_block[0] ^= 1,
            |r| r.observation.daa_score += 1,
            |r| r.observation.depth += 1,
            |r| r.signature[0] ^= 1,
            |r| r.signer = key_file().signer,
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut bad = r;
            edit(&mut bad);
            assert_eq!(
                bad.verify_signature().unwrap_err().code(),
                "RECEIPT_SIGNATURE_INVALID",
                "edit {i}"
            );
        }
    }

    #[test]
    fn malformed_receipts_are_refused() {
        let k = key_file();
        let good = Receipt::sign(observation(), &k.path, false)
            .unwrap()
            .render();
        assert!(Receipt::parse(&good).is_ok(), "control");
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut v: Value = serde_json::from_str(&good).unwrap();
            f(&mut v);
            v.to_string()
        };
        let cases = [
            edit(&|v| v["extra"] = 1.into()),
            edit(&|v| {
                v.as_object_mut().unwrap().remove("depth");
            }),
            edit(&|v| v["version"] = 2.into()),
            edit(&|v| v["network"] = "devnet".into()),
            edit(&|v| v["depth"] = 10.into()),
            edit(&|v| v["daa_score"] = "01000".into()),
            edit(&|v| v["signature"] = "00".into()),
            edit(&|v| v["txid"] = "22".repeat(31).into()),
            "[]".to_string(),
            "not json".to_string(),
            // A key given twice: a lax parser keeps the last, some keep the first.
            good.replacen(
                "  \"txid\": ",
                &format!("  \"txid\": \"{}\",\n  \"txid\": ", "99".repeat(32)),
                1,
            ),
        ];
        for (i, text) in cases.iter().enumerate() {
            assert_eq!(
                Receipt::parse(text).unwrap_err().code(),
                "RECEIPT_MALFORMED",
                "case {i}"
            );
        }
    }
}
