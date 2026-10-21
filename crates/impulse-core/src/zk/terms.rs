// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms v3 (spec/V3-ZK.md section 7): the v1 terms with two more fields, the list issuer key and
//! the list root. Version byte `0x03`, hash key `Impulse/terms/v3`, their own decoder. The v1
//! decoder refuses these bytes as `TERMS_UNSUPPORTED_VERSION`, and nothing here widens the meaning
//! of any v1 or v2 code: the v1 and v2 dispatchers are not taught version 3.
//!
//! Layout: the v1 layout (spec/ENCODING.md) with the version byte `0x03` and two fields inserted
//! after `funding_mode`, so `trade_ref` stays last:
//!
//! ```text
//! 0x03 || v1 fields 2 to 16 || list_issuer_key (32) || list_root (32) || trade_ref (32)
//! ```
//!
//! The v1 codec is reused through that fixed splice, so the v3 encoding of fields 2 to 16 and of
//! `trade_ref` is the v1 codec's, byte for byte, with the v1 decoding refusals and codes.

use super::list::{root_is_unusable, EMPTY_ROOT};
use super::ZkError;
use crate::terms::{
    CreationContext, Destination, IdentifierType, Kcc20Owner, SettlementMode, Terms, TermsError,
    ValidatedTerms, TERMS_VERSION,
};
use secp256k1::XOnlyPublicKey;

/// The terms v3 version byte.
pub const TERMS_V3_VERSION: u8 = 3;

/// blake2b-256 key for the terms v3 hash.
pub const TERMS_V3_HASH_DOMAIN: &[u8] = b"Impulse/terms/v3";

/// Terms v3: the v1 fields plus the list issuer key and the list root. A plain value; builders
/// take [`ValidatedTermsV3`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermsV3 {
    /// The v1 fields (2 to 16 and `trade_ref`). Its `version` is the v1 layout version, `1`,
    /// and is ignored by the encoder: the v3 wire version is always `0x03`.
    pub fields: Terms,
    /// x-only Schnorr key of the list issuer (section 5.6).
    pub list_issuer_key: [u8; 32],
    /// The root of the issuer list (section 5.1).
    pub list_root: [u8; 32],
}

impl TermsV3 {
    /// Terms v3 from v1 fields; the v1 `version` field is set to the layout version.
    pub fn new(mut fields: Terms, list_issuer_key: [u8; 32], list_root: [u8; 32]) -> Self {
        fields.version = TERMS_VERSION;
        Self {
            fields,
            list_issuer_key,
            list_root,
        }
    }

    /// Canonical bytes (section 7.2).
    pub fn encode(&self) -> Result<Vec<u8>, ZkError> {
        let mut base = self.fields.clone();
        base.version = TERMS_VERSION;
        let v1 = base.encode()?;
        // trade_ref is the last 32 bytes of the v1 encoding.
        let split = v1.len() - 32;
        let mut out = Vec::with_capacity(v1.len() + 64);
        out.push(TERMS_V3_VERSION);
        out.extend_from_slice(&v1[1..split]);
        out.extend_from_slice(&self.list_issuer_key);
        out.extend_from_slice(&self.list_root);
        out.extend_from_slice(&v1[split..]);
        Ok(out)
    }

    /// Parses canonical bytes: the version byte first (`ZK_TERMS_VERSION`), then the v1 decoding
    /// refusals with their v1 codes. The result may still fail validation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        let Some(&version) = bytes.first() else {
            return Err(TermsError::Truncated { field: "version" }.into());
        };
        if version != TERMS_V3_VERSION {
            return Err(ZkError::TermsVersion { version });
        }
        // Version, the two inserted fields and trade_ref are the shortest possible input.
        if bytes.len() < 1 + 64 + 32 {
            return Err(TermsError::Truncated { field: "list_root" }.into());
        }
        let split = bytes.len() - 32;
        let (list_issuer_key, list_root) = (
            bytes[split - 64..split - 32].try_into().expect("32 bytes"),
            bytes[split - 32..split].try_into().expect("32 bytes"),
        );
        let mut v1 = Vec::with_capacity(bytes.len() - 64);
        v1.push(TERMS_VERSION);
        v1.extend_from_slice(&bytes[1..split - 64]);
        v1.extend_from_slice(&bytes[split..]);
        let fields = Terms::decode(&v1)?;
        Ok(Self {
            fields,
            list_issuer_key,
            list_root,
        })
    }

    /// blake2b-256, keyed with `Impulse/terms/v3`, over the canonical bytes.
    pub fn terms_hash(&self) -> Result<[u8; 32], ZkError> {
        Ok(hash_canonical(&self.encode()?))
    }

    /// The buyer delivery owner, if the terms name a KCC-20 owner.
    pub fn delivery_owner(&self) -> Option<Kcc20Owner> {
        match &self.fields.buyer_delivery {
            Destination::Kcc20(owner) => Some(*owner),
            _ => None,
        }
    }

    /// `terms new` refuses terms without an authority unless `--no-authority` was given, because
    /// only the authority's `[S6]` signature can stop a settle for an owner removed from the list
    /// after the terms were made (`ZK_AUTHORITY_ABSENT`, section 7.3). The codec and
    /// [`TermsV3::validate_structure`] accept terms without one.
    pub fn require_authority(&self, no_authority: bool) -> Result<(), ZkError> {
        if self.fields.authority_key.is_none() && !no_authority {
            return Err(ZkError::AuthorityAbsent);
        }
        Ok(())
    }

    /// The time-independent checks (section 7.3), first failure returned: Direct settlement
    /// (`ZK_TERMS_DIRECT`); v1's structure checks in v1's order with v1's codes; the delivery
    /// owner type (`ZK_DELIVERY_OWNER_TYPE`); the issuer key (`ZK_ISSUER_KEY`); the root
    /// (`ZK_ROOT_INVALID`). The only way to obtain [`ValidatedTermsV3`].
    pub fn validate_structure(self) -> Result<ValidatedTermsV3, ZkError> {
        if self.fields.settlement_mode == SettlementMode::Direct {
            return Err(ZkError::TermsDirect);
        }
        let mut base = self.fields.clone();
        base.version = TERMS_VERSION;
        let v1 = base.validate_structure()?;
        match &self.fields.buyer_delivery {
            Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::PubKey | IdentifierType::ScriptHash,
                ..
            }) => {}
            _ => return Err(ZkError::DeliveryOwnerType),
        }
        if XOnlyPublicKey::from_slice(&self.list_issuer_key).is_err() {
            return Err(ZkError::IssuerKey);
        }
        if root_is_unusable(&self.list_root) {
            return Err(ZkError::RootInvalid);
        }
        let canonical = self.encode()?;
        let hash = hash_canonical(&canonical);
        Ok(ValidatedTermsV3 {
            terms: self,
            v1,
            canonical,
            hash,
        })
    }
}

/// Terms v3 that passed [`TermsV3::validate_structure`]. The fields are private, so a value of
/// this type always holds checked terms with their canonical bytes and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTermsV3 {
    terms: TermsV3,
    v1: ValidatedTerms,
    canonical: Vec<u8>,
    hash: [u8; 32],
}

impl ValidatedTermsV3 {
    /// Decodes canonical bytes and runs the structure checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZkError> {
        TermsV3::decode(bytes)?.validate_structure()
    }

    pub fn terms(&self) -> &TermsV3 {
        &self.terms
    }

    /// The v1 fields as structure-checked v1 terms (their own canonical bytes and hash are the
    /// v1 ones, not this version's).
    pub fn v1_fields(&self) -> &ValidatedTerms {
        &self.v1
    }

    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    pub fn terms_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The buyer delivery owner (a public key or a script hash, by the structure checks).
    pub fn delivery_owner(&self) -> Kcc20Owner {
        self.terms
            .delivery_owner()
            .expect("structure checks passed: the delivery is a KCC-20 owner")
    }

    /// The creation checks of v1 (spec/ENCODING.md): network, expiry after creation and within
    /// the horizon.
    pub fn validate_creation(&self, ctx: &CreationContext) -> Result<(), ZkError> {
        Ok(self.v1.validate_creation(ctx)?)
    }
}

fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(TERMS_V3_HASH_DOMAIN)
        .hash(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// True when `root` is the root of the empty tree.
pub fn is_empty_tree_root(root: &[u8; 32]) -> bool {
    *root == EMPTY_ROOT
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::terms::golden::vectors;
    use crate::terms::{FundingMode, LegKind};

    /// A structure-valid v3 terms value built on the v1 golden vector for a vault trade.
    pub(crate) fn sample() -> TermsV3 {
        let mut t = vectors()
            .into_iter()
            .find(|v| {
                v.terms.settlement_mode == SettlementMode::Vault
                    && matches!(v.terms.cash_leg.kind, LegKind::Kas)
                    && matches!(v.terms.buyer_delivery, Destination::Kcc20(_))
                    && v.terms.authority_key.is_some()
            })
            .expect("a golden vault vector with KAS cash and an authority")
            .terms;
        t.funding_mode = FundingMode::Earmarked;
        let mut owner = t.buyer_delivery.clone();
        if let Destination::Kcc20(o) = &mut owner {
            o.identifier_type = IdentifierType::ScriptHash;
        }
        t.buyer_delivery = owner;
        // A valid x-only key (the x coordinate of G) and a root that is neither zero nor empty.
        let mut issuer = [0u8; 32];
        for (i, b) in issuer.iter_mut().enumerate() {
            *b = u8::from_str_radix(
                &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    [2 * i..2 * i + 2],
                16,
            )
            .unwrap();
        }
        TermsV3::new(t, issuer, [0x42; 32])
    }

    #[test]
    fn round_trip_is_one_to_one() {
        let t = sample();
        let b = t.encode().unwrap();
        assert_eq!(b[0], 3);
        assert_eq!(TermsV3::decode(&b).unwrap(), t);
        assert_eq!(TermsV3::decode(&b).unwrap().encode().unwrap(), b);
        // The v1 encoding of the same fields is 64 bytes shorter and starts with 1.
        let v1 = t.fields.encode().unwrap();
        assert_eq!(v1.len() + 64, b.len());
        assert_eq!(
            &b[b.len() - 32..],
            &v1[v1.len() - 32..],
            "trade_ref stays last"
        );
        let n = b.len();
        assert_eq!(&b[n - 96..n - 64], &t.list_issuer_key);
        assert_eq!(&b[n - 64..n - 32], &t.list_root);
    }

    #[test]
    fn the_v1_decoder_refuses_version_3() {
        let b = sample().encode().unwrap();
        assert_eq!(
            Terms::decode(&b).unwrap_err().code(),
            "TERMS_UNSUPPORTED_VERSION"
        );
    }

    #[test]
    fn the_v3_decoder_refuses_other_versions_first() {
        let mut b = sample().encode().unwrap();
        for v in [0u8, 1, 2, 4, 255] {
            b[0] = v;
            assert_eq!(TermsV3::decode(&b).unwrap_err().code(), "ZK_TERMS_VERSION");
        }
        assert_eq!(TermsV3::decode(&[]).unwrap_err().code(), "TERMS_TRUNCATED");
    }

    #[test]
    fn truncation_and_trailing_bytes_use_v1_codes() {
        let good = sample().encode().unwrap();
        for cut in 1..good.len() {
            let code = TermsV3::decode(&good[..cut]).unwrap_err().code();
            assert!(code.starts_with("TERMS_"), "cut {cut}: {code}");
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(TermsV3::decode(&extra).is_err());
        // A tag byte no value encodes to.
        let mut bad = good;
        bad[1] = 9; // network
        assert_eq!(
            TermsV3::decode(&bad).unwrap_err().code(),
            "TERMS_INVALID_TAG"
        );
    }

    #[test]
    fn hash_key_is_the_v3_tag() {
        let h = |m: &[u8]| {
            let h = blake2b_simd::Params::new()
                .hash_length(32)
                .key(TERMS_V3_HASH_DOMAIN)
                .hash(m);
            super::super::hex(h.as_bytes())
        };
        // spec/V3-ZK.md section 7.1 (Python hashlib.blake2b).
        assert_eq!(
            h(b""),
            "175c483831717b966ff22e32bf1821b41ecb33c235c30b5c97ef3071a4c3a078"
        );
        assert_eq!(
            h(b"abc"),
            "033b06c4d13408373d9ea699b075c6d0621ba1f6740446026d920571c79b3e33"
        );
        let t = sample();
        assert_ne!(t.terms_hash().unwrap(), t.fields.terms_hash().unwrap());
    }

    #[test]
    fn validation_order() {
        let ok = sample().validate_structure().unwrap();
        assert_eq!(ok.terms_hash(), ok.terms().terms_hash().unwrap());
        ok.v1_fields();

        let code = |t: TermsV3| t.validate_structure().unwrap_err().code();

        let mut t = sample();
        t.fields.settlement_mode = SettlementMode::Direct;
        assert_eq!(code(t), "ZK_TERMS_DIRECT");

        // A v1 refusal keeps its v1 code (buyer equals seller).
        let mut t = sample();
        t.fields.buyer_key = t.fields.seller_key;
        assert_eq!(code(t), "TERMS_PARTIES_NOT_DISTINCT");

        let mut t = sample();
        if let Destination::Kcc20(o) = &mut t.fields.buyer_delivery {
            o.identifier_type = IdentifierType::CovenantId;
        }
        assert_eq!(code(t), "ZK_DELIVERY_OWNER_TYPE");

        let mut t = sample();
        t.list_issuer_key = [0xff; 32];
        assert_eq!(code(t), "ZK_ISSUER_KEY");

        let mut t = sample();
        t.list_root = [0; 32];
        assert_eq!(code(t), "ZK_ROOT_INVALID");
        let mut t = sample();
        t.list_root = EMPTY_ROOT;
        assert_eq!(code(t), "ZK_ROOT_INVALID");
        assert!(is_empty_tree_root(&EMPTY_ROOT));

        // Both a bad issuer key and a bad root: the key is reported first.
        let mut t = sample();
        t.list_issuer_key = [0xff; 32];
        t.list_root = [0; 32];
        assert_eq!(code(t), "ZK_ISSUER_KEY");
    }

    #[test]
    fn issuer_may_equal_a_party() {
        let mut t = sample();
        t.list_issuer_key = t.fields.seller_key;
        t.validate_structure().unwrap();
    }

    #[test]
    fn authority_is_required_by_terms_new_only() {
        let mut t = sample();
        t.require_authority(false).unwrap();
        t.fields.authority_key = None;
        // The codec and the structure checks accept it (a self-settling vault trade).
        let b = t.encode().unwrap();
        assert_eq!(TermsV3::decode(&b).unwrap(), t);
        assert_eq!(
            t.require_authority(false).unwrap_err().code(),
            "ZK_AUTHORITY_ABSENT"
        );
        t.require_authority(true).unwrap();
    }

    #[test]
    fn decode_validates() {
        let t = sample();
        let v = ValidatedTermsV3::decode(&t.encode().unwrap()).unwrap();
        assert_eq!(v.terms(), &t);
        assert_eq!(v.canonical(), t.encode().unwrap().as_slice());
        let mut bad = t;
        bad.list_root = [0; 32];
        assert_eq!(
            ValidatedTermsV3::decode(&bad.encode().unwrap())
                .unwrap_err()
                .code(),
            "ZK_ROOT_INVALID"
        );
    }
}
