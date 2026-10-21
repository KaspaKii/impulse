// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Threshold settlement authority (I13): FROST t-of-n over secp256k1 whose aggregate signature is
//! a plain BIP-340 Schnorr signature, through frost-secp256k1-tr 3.0.0 (ZcashFoundation, crates.io,
//! pinned exactly). The group key is one x-only key, used as `authority_key` in the terms with no
//! contract change: the vault sees one key and one signature. Design, threat model and codes:
//! spec/THRESHOLD.md.
//!
//! Key generation is FROST's distributed key generation (three rounds, no dealer): no party, and
//! no coordinator, ever holds the group secret. Every party then confirms out of band that all
//! parties hold the same round-1 transcript ([`dkg_round1_digest`]) and the same group key
//! ([`GroupKey::fingerprint`]); the authority key alone does not show that. Signing is two rounds per message: every signer
//! commits to fresh nonces, then signs the message against the agreed signing set; anyone holding
//! the group key aggregates the shares. The message is the 32-byte Kaspa Schnorr sighash of one
//! vault input, computed by each signer from the transaction it approves.
//!
//! Key material: a party's share ([`KeyShare`]), its key generation secrets and its signing
//! nonces live in memory, inside FROST types that erase themselves on drop. This module never
//! writes, logs, prints or transmits them, and their `Debug` output names the party only. The byte
//! encodings of secret values (`KeyShare::to_bytes`, `DkgRound2Package::to_bytes`) return buffers
//! zeroed on drop; where those bytes go is the caller's rule (spec/THRESHOLD.md, "Key material").
//! It is compiled only with the non-default cargo feature `threshold`, so default impulse-core
//! holds no secret material. Nonces are consumed by [`sign`] and [`sign_input`], so one commitment
//! signs one message. Callers that sign a transaction use [`sign_input`] and [`aggregate_input`],
//! which compute the input's `SIG_HASH_ALL` sighash themselves.

mod encoding;
mod error;
#[cfg(test)]
mod tests;

pub use error::{ThresholdError, THRESHOLD_ERROR_CODES};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use frost::keys::dkg;
use frost::Identifier;
use frost_secp256k1_tr as frost;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use rand::rngs::OsRng;
use secp256k1::{schnorr, Message, XOnlyPublicKey, SECP256K1};

/// A party's identifier in its group: 1..=parties.
pub type PartyId = u16;

/// blake2b-256 key of [`GroupKey::fingerprint`].
pub const GROUP_FINGERPRINT_DOMAIN: &[u8] = b"Impulse/thresholdgroup/v1";

/// blake2b-256 key of [`dkg_round1_digest`].
pub const DKG_ROUND1_DIGEST_DOMAIN: &[u8] = b"Impulse/thresholdround1/v1";

// =============================================================================================
// Group shape and identifiers
// =============================================================================================

/// A t-of-n group: any `threshold` of the `parties` sign together; fewer cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupShape {
    threshold: u16,
    parties: u16,
}

impl GroupShape {
    /// Refuses a threshold below 2 (one share would settle alone) or above the party count
    /// (the group could never sign).
    pub fn new(threshold: u16, parties: u16) -> Result<Self, ThresholdError> {
        if threshold < 2 || threshold > parties {
            return Err(ThresholdError::Params { threshold, parties });
        }
        Ok(Self { threshold, parties })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn parties(&self) -> u16 {
        self.parties
    }

    fn identifier(&self, id: PartyId) -> Result<Identifier, ThresholdError> {
        if id == 0 || id > self.parties {
            return Err(ThresholdError::Party {
                id,
                parties: self.parties,
            });
        }
        Identifier::try_from(id).map_err(refused)
    }

    fn party_of(&self, identifier: &Identifier) -> Option<PartyId> {
        (1..=self.parties).find(|&id| Identifier::try_from(id).ok().as_ref() == Some(identifier))
    }

    /// Every party but `me`: the senders a key generation round must hear from, exactly.
    fn check_from_others<'a>(
        &self,
        me: PartyId,
        round: u8,
        received: impl Iterator<Item = &'a PartyId>,
    ) -> Result<(), ThresholdError> {
        self.check_senders(Some(me), round, received)
    }

    /// Exactly one package from every party, `except` excluded.
    fn check_senders<'a>(
        &self,
        except: Option<PartyId>,
        round: u8,
        received: impl Iterator<Item = &'a PartyId>,
    ) -> Result<(), ThresholdError> {
        let expected: BTreeSet<PartyId> = (1..=self.parties)
            .filter(|&id| Some(id) != except)
            .collect();
        let got: BTreeSet<PartyId> = received.copied().collect();
        if got != expected {
            return Err(ThresholdError::DkgPackages {
                round,
                missing: expected.difference(&got).copied().collect(),
                unexpected: got.difference(&expected).copied().collect(),
            });
        }
        Ok(())
    }

    /// A signing set: known parties only, at least the threshold of them.
    fn signing_package(
        &self,
        commitments: &BTreeMap<PartyId, Commitment>,
        sighash: &[u8; 32],
    ) -> Result<frost::SigningPackage, ThresholdError> {
        let mut map = BTreeMap::new();
        for (&id, c) in commitments {
            map.insert(self.identifier(id)?, c.0);
        }
        if map.len() < self.threshold as usize {
            return Err(ThresholdError::TooFewSigners {
                signers: map.len(),
                threshold: self.threshold,
            });
        }
        Ok(frost::SigningPackage::new(map, sighash))
    }
}

fn refused(e: frost::Error) -> ThresholdError {
    ThresholdError::Refused {
        reason: e.to_string(),
    }
}

/// The x-only form (BIP-340) of a group key in 33-byte SEC1 compressed form. Fail closed:
/// another length or prefix, or an x that is not on the curve, is `THRESHOLD_KEY_INVALID`.
fn x_only(sec1: &[u8]) -> Result<[u8; 32], ThresholdError> {
    let [0x02 | 0x03, x @ ..] = sec1 else {
        return Err(ThresholdError::KeyInvalid);
    };
    let x: [u8; 32] = x.try_into().map_err(|_| ThresholdError::KeyInvalid)?;
    XOnlyPublicKey::from_slice(&x).map_err(|_| ThresholdError::KeyInvalid)?;
    Ok(x)
}

/// Re-keys a FROST map by party. Fail closed: an identifier outside the group is refused.
fn by_party<T>(
    shape: &GroupShape,
    map: BTreeMap<Identifier, T>,
) -> Result<BTreeMap<PartyId, T>, ThresholdError> {
    map.into_iter()
        .map(|(identifier, value)| {
            let id = shape
                .party_of(&identifier)
                .ok_or_else(|| ThresholdError::Refused {
                    reason: "an identifier outside the group".into(),
                })?;
            Ok((id, value))
        })
        .collect()
}

// =============================================================================================
// Distributed key generation (FROST DKG, three rounds)
// =============================================================================================

/// What a party keeps in memory between key generation rounds 1 and 2. Secret; erased on drop.
pub struct DkgRound1Secret {
    shape: GroupShape,
    id: PartyId,
    inner: dkg::round1::SecretPackage,
}

/// A party's round-1 broadcast: its commitment and proof of knowledge. Public, but every party
/// must receive the same one from each sender (an authenticated broadcast).
#[derive(Clone, PartialEq, Eq)]
pub struct DkgRound1Package(dkg::round1::Package);

/// What a party keeps in memory between key generation rounds 2 and 3. Secret; erased on drop.
pub struct DkgRound2Secret {
    shape: GroupShape,
    id: PartyId,
    inner: dkg::round2::SecretPackage,
}

/// A round-2 package from one party to one other party. It carries a secret share for its
/// recipient alone: confidential and authenticated transport only. Erased on drop.
pub struct DkgRound2Package(dkg::round2::Package);

/// Round 1: party `me` of `shape` samples its secret polynomial and returns the secret it keeps
/// and the package it broadcasts to every other party.
pub fn dkg_round1(
    shape: GroupShape,
    me: PartyId,
) -> Result<(DkgRound1Secret, DkgRound1Package), ThresholdError> {
    let identifier = shape.identifier(me)?;
    let (inner, package) =
        dkg::part1(identifier, shape.parties, shape.threshold, OsRng).map_err(refused)?;
    Ok((
        DkgRound1Secret {
            shape,
            id: me,
            inner,
        },
        DkgRound1Package(package),
    ))
}

/// Round 2: given the round-1 package of every other party (keyed by sender), verifies each
/// proof of knowledge and returns the secret this party keeps and one package per recipient.
pub fn dkg_round2(
    secret: DkgRound1Secret,
    round1: &BTreeMap<PartyId, DkgRound1Package>,
) -> Result<(DkgRound2Secret, BTreeMap<PartyId, DkgRound2Package>), ThresholdError> {
    let DkgRound1Secret { shape, id, inner } = secret;
    shape.check_from_others(id, 2, round1.keys())?;
    let r1 = frost_round1(&shape, round1)?;
    let (inner, out) = dkg::part2(inner, &r1).map_err(|e| match e {
        frost::Error::InvalidProofOfKnowledge { culprit } => ThresholdError::DkgCulprit {
            round: 2,
            culprit: shape.party_of(&culprit),
        },
        e => refused(e),
    })?;
    let packages = by_party(&shape, out)?
        .into_iter()
        .map(|(to, package)| (to, DkgRound2Package(package)))
        .collect();
    Ok((DkgRound2Secret { shape, id, inner }, packages))
}

/// Round 3: given the same round-1 packages as round 2 and the round-2 package each other party
/// sent to this one, verifies every share and returns this party's key share and the group key.
/// Every party must then confirm out of band that every party holds the same
/// [`GroupKey::fingerprint`]; equal `authority_key`s alone do not show a consistent group.
pub fn dkg_round3(
    secret: DkgRound2Secret,
    round1: &BTreeMap<PartyId, DkgRound1Package>,
    round2: &BTreeMap<PartyId, DkgRound2Package>,
) -> Result<(KeyShare, GroupKey), ThresholdError> {
    let DkgRound2Secret { shape, id, inner } = secret;
    shape.check_from_others(id, 3, round1.keys())?;
    shape.check_from_others(id, 3, round2.keys())?;
    let r1 = frost_round1(&shape, round1)?;
    let mut r2 = BTreeMap::new();
    for (&from, package) in round2 {
        r2.insert(shape.identifier(from)?, package.0.clone());
    }
    // frost-core 3.0.0 checks proofs of knowledge in part 2 only; part 3 checks each share
    // against its sender's commitment.
    let (key_package, public) = dkg::part3(&inner, &r1, &r2).map_err(|e| match e {
        frost::Error::InvalidSecretShare { culprit } => ThresholdError::DkgCulprit {
            round: 3,
            culprit: culprit.and_then(|c| shape.party_of(&c)),
        },
        e => refused(e),
    })?;
    let (authority_key, fingerprint) = group_output(&shape, &key_package, &public)?;
    Ok((
        KeyShare {
            shape,
            id,
            authority_key,
            inner: key_package,
        },
        GroupKey {
            shape,
            authority_key,
            fingerprint,
            inner: public,
        },
    ))
}

/// Checks key generation output against the group shape (fail closed) and returns the x-only
/// authority key and the group fingerprint: keyed blake2b-256 ([`GROUP_FINGERPRINT_DOMAIN`]) over
/// threshold and parties (u16 big-endian each), the authority key, then every party's public
/// share (33-byte SEC1) in party order.
fn group_output(
    shape: &GroupShape,
    key_package: &frost::keys::KeyPackage,
    public: &frost::keys::PublicKeyPackage,
) -> Result<([u8; 32], [u8; 32]), ThresholdError> {
    let mismatch = || ThresholdError::Refused {
        reason: "key generation output does not match the group shape".into(),
    };
    let consistent = *key_package.min_signers() == shape.threshold
        && public.min_signers() == Some(shape.threshold)
        && public.verifying_shares().len() == shape.parties as usize
        && key_package.verifying_key() == public.verifying_key();
    if !consistent {
        return Err(mismatch());
    }
    group_fingerprint(shape, public)
}

/// The x-only authority key of a public key package and the group fingerprint over the shape,
/// that key and every party's public share. Fail closed: a party without a public share is
/// refused.
fn group_fingerprint(
    shape: &GroupShape,
    public: &frost::keys::PublicKeyPackage,
) -> Result<([u8; 32], [u8; 32]), ThresholdError> {
    let mismatch = || ThresholdError::Refused {
        reason: "key generation output does not match the group shape".into(),
    };
    let authority_key = x_only(&public.verifying_key().serialize().map_err(refused)?)?;
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(GROUP_FINGERPRINT_DOMAIN)
        .to_state();
    state
        .update(&shape.threshold.to_be_bytes())
        .update(&shape.parties.to_be_bytes())
        .update(&authority_key);
    for id in 1..=shape.parties {
        let share = public
            .verifying_shares()
            .get(&shape.identifier(id)?)
            .ok_or_else(mismatch)?;
        state.update(&share.serialize().map_err(refused)?);
    }
    Ok((authority_key, digest(state.finalize())))
}

fn digest(hash: blake2b_simd::Hash) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// The round-1 transcript digest a party compares with every other party, out of band, before it
/// sends any round-2 package: keyed blake2b-256 ([`DKG_ROUND1_DIGEST_DOMAIN`]) over threshold and
/// parties (u16 big-endian each), then, for every party in order, its identifier (u16
/// big-endian), its commitment (each coefficient 33-byte SEC1, the count first as u16
/// big-endian) and its proof of knowledge (64 bytes). `packages` holds the round-1 package of
/// every party, this party's own included; a party that equivocated in its broadcast shows up as
/// a differing digest.
pub fn dkg_round1_digest(
    shape: GroupShape,
    packages: &BTreeMap<PartyId, DkgRound1Package>,
) -> Result<[u8; 32], ThresholdError> {
    shape.check_senders(None, 1, packages.keys())?;
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(DKG_ROUND1_DIGEST_DOMAIN)
        .to_state();
    state
        .update(&shape.threshold.to_be_bytes())
        .update(&shape.parties.to_be_bytes());
    for (id, package) in packages {
        let coefficients = package.0.commitment().serialize().map_err(refused)?;
        let proof = package
            .0
            .proof_of_knowledge()
            .serialize()
            .map_err(refused)?;
        state
            .update(&id.to_be_bytes())
            .update(&(coefficients.len() as u16).to_be_bytes());
        for c in &coefficients {
            state.update(c);
        }
        state.update(&proof);
    }
    Ok(digest(state.finalize()))
}

fn frost_round1(
    shape: &GroupShape,
    round1: &BTreeMap<PartyId, DkgRound1Package>,
) -> Result<BTreeMap<Identifier, dkg::round1::Package>, ThresholdError> {
    let mut map = BTreeMap::new();
    for (&from, package) in round1 {
        map.insert(shape.identifier(from)?, package.0.clone());
    }
    Ok(map)
}

// =============================================================================================
// Key share and group key
// =============================================================================================

/// One party's long-lived share of the group secret. Secret: memory only, erased on drop, never
/// cloned by this module.
pub struct KeyShare {
    shape: GroupShape,
    id: PartyId,
    authority_key: [u8; 32],
    inner: frost::keys::KeyPackage,
}

impl KeyShare {
    pub fn id(&self) -> PartyId {
        self.id
    }

    pub fn shape(&self) -> GroupShape {
        self.shape
    }

    /// The group's x-only key, the `authority_key` of the terms.
    pub fn authority_key(&self) -> [u8; 32] {
        self.authority_key
    }
}

/// The group's public key material: the x-only authority key and every party's public share.
/// Public; the aggregator needs it to check each signature share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    shape: GroupShape,
    authority_key: [u8; 32],
    fingerprint: [u8; 32],
    inner: frost::keys::PublicKeyPackage,
}

impl GroupKey {
    pub fn shape(&self) -> GroupShape {
        self.shape
    }

    /// The x-only key that goes into the terms as `authority_key`.
    pub fn authority_key(&self) -> [u8; 32] {
        self.authority_key
    }

    /// The digest of the whole group key: shape, authority key and every party's public share
    /// (encoding in spec/THRESHOLD.md, "Key generation"). Every party compares it with every other party out of band before
    /// the authority key goes into terms. Equal fingerprints mean every party holds the same
    /// public shares, so any t of them can sign; an equivocation in key generation round 1 can
    /// leave the authority key equal everywhere while the fingerprints differ.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

// =============================================================================================
// Signing (two rounds) and aggregation
// =============================================================================================

/// A signer's nonces for one message. Secret; consumed by [`sign`], erased on drop.
pub struct SigningNonces {
    id: PartyId,
    inner: frost::round1::SigningNonces,
}

/// A signer's public commitment to its nonces, sent to the aggregator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(frost::round1::SigningCommitments);

/// A signer's share of one signature. Public: the aggregator verifies it against the signer's
/// public share before using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureShare(frost::round2::SignatureShare);

impl SignatureShare {
    /// The share's scalar, 32 bytes big-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.serialize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// Signing round 1: fresh nonces from the OS RNG for one message, and their commitment.
pub fn commit(share: &KeyShare) -> (SigningNonces, Commitment) {
    let (inner, commitment) = frost::round1::commit(share.inner.signing_share(), &mut OsRng);
    (
        SigningNonces {
            id: share.id,
            inner,
        },
        Commitment(commitment),
    )
}

/// Signing round 2: this party's share of the signature over `sighash` by the signing set
/// `commitments` (keyed by party, this party's own commitment included). Consumes the nonces.
/// `sighash` must be the `SIG_HASH_ALL` sighash the signer computed itself from the transaction
/// it approves; this function cannot tell how a digest was made (spec/THRESHOLD.md, "Signing").
pub fn sign(
    share: &KeyShare,
    nonces: SigningNonces,
    sighash: &[u8; 32],
    commitments: &BTreeMap<PartyId, Commitment>,
) -> Result<SignatureShare, ThresholdError> {
    let package = share.shape.signing_package(commitments, sighash)?;
    let own = commitments.get(&share.id).map(|c| &c.0);
    if nonces.id != share.id || own != Some(nonces.inner.commitments()) {
        return Err(ThresholdError::SignerNotInSet { id: share.id });
    }
    frost::round2::sign(&package, &nonces.inner, &share.inner)
        .map(SignatureShare)
        .map_err(refused)
}

/// Aggregates the signature shares of the signing set `commitments` into one BIP-340 signature
/// over `sighash`. FROST sums the shares and checks the sum under the group key first; only if
/// that fails does it check every share against its party's public share, and then every party
/// whose share fails is named (`THRESHOLD_SHARE_INVALID`). Shares that are individually invalid
/// but sum to a valid signature are not refused: the vault sees only the sum. The result is
/// verified under the authority key with libsecp256k1, the verifier the Kaspa engine uses, before
/// it is returned. Blame is reliable only once key generation was confirmed at every party
/// ([`GroupKey::fingerprint`]).
pub fn aggregate(
    group: &GroupKey,
    sighash: &[u8; 32],
    commitments: &BTreeMap<PartyId, Commitment>,
    shares: &BTreeMap<PartyId, SignatureShare>,
) -> Result<[u8; 64], ThresholdError> {
    let package = group.shape.signing_package(commitments, sighash)?;
    let set: BTreeSet<PartyId> = commitments.keys().copied().collect();
    let got: BTreeSet<PartyId> = shares.keys().copied().collect();
    if got != set {
        return Err(ThresholdError::SharesMismatch {
            missing: set.difference(&got).copied().collect(),
            unexpected: got.difference(&set).copied().collect(),
        });
    }
    let mut map = BTreeMap::new();
    for (&id, s) in shares {
        map.insert(group.shape.identifier(id)?, s.0);
    }
    let signature = frost_core::aggregate_custom(
        &package,
        &map,
        &group.inner,
        frost_core::CheaterDetection::AllCheaters,
    )
    .map_err(|e| match e {
        frost::Error::InvalidSignatureShare { culprits } => ThresholdError::ShareInvalid {
            culprits: culprits
                .iter()
                .filter_map(|c| group.shape.party_of(c))
                .collect(),
        },
        e => refused(e),
    })?;
    let bytes = signature.serialize().map_err(refused)?;
    let signature: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::SignatureInvalid)?;
    verify(&group.authority_key, sighash, &signature)?;
    Ok(signature)
}

/// The `SIG_HASH_ALL` Schnorr sighash of input `input` of `tx`, computed with the I5 code from the
/// transaction and the UTXO entries it spends.
fn input_sighash(
    tx: &Transaction,
    entries: &[UtxoEntry],
    input: usize,
) -> Result<[u8; 32], ThresholdError> {
    crate::tx::sighash(tx, entries, input).map_err(|_| ThresholdError::Input { input })
}

/// Signing round 2 for one transaction input: this party's share of the signature over the
/// `SIG_HASH_ALL` sighash of input `input` of `tx`, which this function computes itself from the
/// transaction and the UTXO entries it spends (`impulse_core::tx::sighash`). It takes no digest,
/// so a signer cannot be handed one; this is the signing entry point the CLI calls. Consumes the
/// nonces. `THRESHOLD_INPUT` if `input` is not an input of `tx` or the entries do not match its
/// inputs one for one; otherwise the refusals of [`sign`].
pub fn sign_input(
    share: &KeyShare,
    nonces: SigningNonces,
    tx: &Transaction,
    entries: &[UtxoEntry],
    input: usize,
    commitments: &BTreeMap<PartyId, Commitment>,
) -> Result<SignatureShare, ThresholdError> {
    let sighash = input_sighash(tx, entries, input)?;
    sign(share, nonces, &sighash, commitments)
}

/// Aggregates the signature shares of one transaction input into its 65-byte `authSig`: the
/// BIP-340 signature over the `SIG_HASH_ALL` sighash of input `input` of `tx`, computed here as
/// in [`sign_input`], followed by the sighash type `SIG_HASH_ALL` (0x01). The refusals of
/// [`aggregate`], and `THRESHOLD_INPUT` as in [`sign_input`].
pub fn aggregate_input(
    group: &GroupKey,
    tx: &Transaction,
    entries: &[UtxoEntry],
    input: usize,
    commitments: &BTreeMap<PartyId, Commitment>,
    shares: &BTreeMap<PartyId, SignatureShare>,
) -> Result<[u8; 65], ThresholdError> {
    let sighash = input_sighash(tx, entries, input)?;
    let signature = aggregate(group, &sighash, commitments, shares)?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature);
    out[64] = SIG_HASH_ALL.to_u8();
    Ok(out)
}

/// BIP-340 verification of `signature` over `sighash` under the x-only `authority_key`, with
/// libsecp256k1 (the check OpCheckSig makes for a Schnorr signature).
pub fn verify(
    authority_key: &[u8; 32],
    sighash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ThresholdError> {
    let key = XOnlyPublicKey::from_slice(authority_key).map_err(|_| ThresholdError::KeyInvalid)?;
    let signature =
        schnorr::Signature::from_slice(signature).map_err(|_| ThresholdError::SignatureInvalid)?;
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(*sighash), &key)
        .map_err(|_| ThresholdError::SignatureInvalid)
}

// =============================================================================================
// Debug output names the party only, never secret material
// =============================================================================================

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Debug for DkgRound1Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgRound1Secret")
            .field("shape", &self.shape)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DkgRound2Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgRound2Secret")
            .field("shape", &self.shape)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DkgRound1Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgRound1Package").finish_non_exhaustive()
    }
}

impl fmt::Debug for DkgRound2Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgRound2Package").finish_non_exhaustive()
    }
}

impl fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyShare")
            .field("shape", &self.shape)
            .field("id", &self.id)
            .field("authority_key", &hex(&self.authority_key))
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SigningNonces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningNonces")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
