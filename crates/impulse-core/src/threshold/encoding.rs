// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Byte encodings of the threshold values (spec/THRESHOLD.md, "Encodings"), built from the byte
//! forms FROST always exposes; FROST's `serialization` feature stays off (decision D20, option
//! (a)). Integers are big-endian, points 33-byte SEC1 compressed, scalars 32 bytes. Decoders are
//! fail closed: any other length, a point not on the curve, a scalar out of range or an
//! inconsistent value is `THRESHOLD_ENCODING`, and nothing partly decoded is returned. Encodings
//! of secret values come back in buffers zeroed on drop.

use super::*;
use zeroize::{Zeroize, Zeroizing};

const POINT: usize = 33;
const SCALAR: usize = 32;
const PROOF: usize = 64;

/// The bytes of a `KeyShare`: threshold, parties, party, signing share, public share, group key.
const KEY_SHARE_LEN: usize = 6 + SCALAR + POINT + POINT;

fn encoding(reason: impl Into<String>) -> ThresholdError {
    ThresholdError::Encoding {
        reason: reason.into(),
    }
}

/// Reads fixed-size fields from a byte string, front to back.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], ThresholdError> {
        if self.rest.len() < n {
            return Err(encoding(format!("too short for {what}")));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    /// A 33-byte SEC1 compressed point. The prefix must be 0x02 or 0x03: the FROST decoder
    /// accepts other prefix bytes and reads them as a parity, so one point would have several
    /// encodings (found by fuzzing, I14).
    fn sec1(&mut self, what: &str) -> Result<&'a [u8], ThresholdError> {
        let b = self.take(POINT, what)?;
        if !matches!(b[0], 2 | 3) {
            return Err(encoding(format!("{what} has an invalid point prefix")));
        }
        Ok(b)
    }

    fn u16(&mut self, what: &str) -> Result<u16, ThresholdError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn end(&self, what: &str) -> Result<(), ThresholdError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(encoding(format!("{} bytes after {what}", self.rest.len())))
        }
    }
}

fn shape_of(threshold: u16, parties: u16) -> Result<GroupShape, ThresholdError> {
    GroupShape::new(threshold, parties).map_err(|e| encoding(e.to_string()))
}

fn point(bytes: Vec<u8>, what: &str) -> Result<Vec<u8>, ThresholdError> {
    if bytes.len() != POINT {
        return Err(encoding(format!("{what} is not a 33-byte point")));
    }
    Ok(bytes)
}

impl DkgRound1Package {
    /// Coefficient count (u16), every commitment coefficient, then the 64-byte proof of
    /// knowledge.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        let coefficients = self.0.commitment().serialize().map_err(refused)?;
        let proof = self.0.proof_of_knowledge().serialize().map_err(refused)?;
        let count = u16::try_from(coefficients.len())
            .map_err(|_| encoding("more than 65535 coefficients"))?;
        let mut out = count.to_be_bytes().to_vec();
        for c in coefficients {
            out.extend_from_slice(&point(c, "a commitment coefficient")?);
        }
        if proof.len() != PROOF {
            return Err(encoding("the proof of knowledge is not 64 bytes"));
        }
        out.extend_from_slice(&proof);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        let mut r = Reader::new(bytes);
        let count = r.u16("the coefficient count")?;
        if count == 0 {
            return Err(encoding("a commitment has at least one coefficient"));
        }
        let mut coefficients = Vec::with_capacity(count as usize);
        for _ in 0..count {
            coefficients.push(r.sec1("a commitment coefficient")?);
        }
        let proof = r.take(PROOF, "the proof of knowledge")?;
        r.end("the proof of knowledge")?;
        let commitment = frost::keys::VerifiableSecretSharingCommitment::deserialize(coefficients)
            .map_err(|e| encoding(format!("a commitment coefficient: {e}")))?;
        let proof = frost::Signature::deserialize(proof)
            .map_err(|e| encoding(format!("the proof of knowledge: {e}")))?;
        Ok(Self(dkg::round1::Package::new(commitment, proof)))
    }
}

impl DkgRound2Package {
    /// The secret share for the package's recipient, 32 bytes. Secret: zeroed on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = self.0.signing_share().serialize();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&bytes);
        bytes.zeroize();
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != SCALAR {
            return Err(encoding("a round-2 package is a 32-byte scalar"));
        }
        let share = frost::keys::SigningShare::deserialize(bytes)
            .map_err(|e| encoding(format!("the secret share: {e}")))?;
        Ok(Self(dkg::round2::Package::new(share)))
    }
}

impl KeyShare {
    /// Threshold, parties and party (u16 each), the signing share, the party's public share and
    /// the group key. Secret: zeroed on drop.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ThresholdError> {
        let mut out = Zeroizing::new(Vec::with_capacity(KEY_SHARE_LEN));
        out.extend_from_slice(&self.shape.threshold.to_be_bytes());
        out.extend_from_slice(&self.shape.parties.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        let mut secret = self.inner.signing_share().serialize();
        out.extend_from_slice(&secret);
        secret.zeroize();
        let public = self.inner.verifying_share().serialize().map_err(refused)?;
        out.extend_from_slice(&point(public, "the public share")?);
        let group = self.inner.verifying_key().serialize().map_err(refused)?;
        out.extend_from_slice(&point(group, "the group key")?);
        Ok(out)
    }

    /// Checks the shape, the party, that the public share is the signing share times G, and
    /// that the group key has an x-only form (the authority key).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != KEY_SHARE_LEN {
            return Err(encoding(format!(
                "a key share is {KEY_SHARE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut r = Reader::new(bytes);
        let shape = shape_of(r.u16("the threshold")?, r.u16("the parties")?)?;
        let id = r.u16("the party")?;
        let identifier = shape.identifier(id).map_err(|e| encoding(e.to_string()))?;
        let signing = frost::keys::SigningShare::deserialize(r.take(SCALAR, "the signing share")?)
            .map_err(|e| encoding(format!("the signing share: {e}")))?;
        let public = frost::keys::VerifyingShare::deserialize(r.sec1("the public share")?)
            .map_err(|e| encoding(format!("the public share: {e}")))?;
        let group_sec1 = r.sec1("the group key")?;
        r.end("the group key")?;
        let group = frost::VerifyingKey::deserialize(group_sec1)
            .map_err(|e| encoding(format!("the group key: {e}")))?;
        if frost::keys::VerifyingShare::from(signing) != public {
            return Err(encoding(
                "the public share is not the signing share times G",
            ));
        }
        let authority_key = x_only(group_sec1).map_err(|e| encoding(e.to_string()))?;
        Ok(KeyShare {
            shape,
            id,
            authority_key,
            inner: frost::keys::KeyPackage::new(
                identifier,
                signing,
                public,
                group,
                shape.threshold,
            ),
        })
    }
}

impl GroupKey {
    /// Threshold and parties (u16 each), the group key, then every party's public share in party
    /// order.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut out = self.shape.threshold.to_be_bytes().to_vec();
        out.extend_from_slice(&self.shape.parties.to_be_bytes());
        let group = self.inner.verifying_key().serialize().map_err(refused)?;
        out.extend_from_slice(&point(group, "the group key")?);
        for id in 1..=self.shape.parties {
            let share = self
                .inner
                .verifying_shares()
                .get(&self.shape.identifier(id)?)
                .ok_or_else(|| encoding(format!("no public share for party {id}")))?;
            out.extend_from_slice(&point(
                share.serialize().map_err(refused)?,
                "a public share",
            )?);
        }
        Ok(out)
    }

    /// Checks the shape and every point, then recomputes the authority key and the fingerprint.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        let mut r = Reader::new(bytes);
        let shape = shape_of(r.u16("the threshold")?, r.u16("the parties")?)?;
        let group = frost::VerifyingKey::deserialize(r.sec1("the group key")?)
            .map_err(|e| encoding(format!("the group key: {e}")))?;
        let mut shares = BTreeMap::new();
        for id in 1..=shape.parties {
            let share = frost::keys::VerifyingShare::deserialize(r.sec1("a public share")?)
                .map_err(|e| encoding(format!("the public share of party {id}: {e}")))?;
            shares.insert(shape.identifier(id)?, share);
        }
        r.end("the public shares")?;
        let inner = frost::keys::PublicKeyPackage::new(shares, group, Some(shape.threshold));
        let (authority_key, fingerprint) =
            group_fingerprint(&shape, &inner).map_err(|e| encoding(e.to_string()))?;
        Ok(GroupKey {
            shape,
            authority_key,
            fingerprint,
            inner,
        })
    }
}

impl Commitment {
    /// The hiding then the binding nonce commitment.
    pub fn to_bytes(&self) -> Result<[u8; 66], ThresholdError> {
        let mut out = [0u8; 66];
        let hiding = point(self.0.hiding().serialize().map_err(refused)?, "a nonce")?;
        let binding = point(self.0.binding().serialize().map_err(refused)?, "a nonce")?;
        out[..POINT].copy_from_slice(&hiding);
        out[POINT..].copy_from_slice(&binding);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != 2 * POINT {
            return Err(encoding("a commitment is two 33-byte points"));
        }
        let nonce = |b: &[u8]| {
            if !matches!(b[0], 2 | 3) {
                return Err(encoding("a nonce commitment has an invalid point prefix"));
            }
            frost::round1::NonceCommitment::deserialize(b)
                .map_err(|e| encoding(format!("a nonce commitment: {e}")))
        };
        Ok(Self(frost::round1::SigningCommitments::new(
            nonce(&bytes[..POINT])?,
            nonce(&bytes[POINT..])?,
        )))
    }
}

impl SignatureShare {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() != SCALAR {
            return Err(encoding("a signature share is a 32-byte scalar"));
        }
        frost::round2::SignatureShare::deserialize(bytes)
            .map(Self)
            .map_err(|e| encoding(format!("the signature share: {e}")))
    }
}
