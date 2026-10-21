// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! threshold:: tests. Every refusal is asserted by code beside an accepted control that differs
//! only in the one fault. Shares, key generation secrets and nonces are generated at runtime from
//! the OS RNG, held in memory only, never written or printed, and erased on drop. No key material
//! is stored in this file.

use super::*;

fn shape(t: u16, n: u16) -> GroupShape {
    GroupShape::new(t, n).expect("group shape")
}

fn assert_code<T: fmt::Debug>(result: Result<T, ThresholdError>, code: &str) -> ThresholdError {
    let err = result.expect_err(code);
    assert_eq!(err.code(), code, "{err}");
    err
}

/// One in-memory group: every party's share (index id - 1) and the group key.
struct Group {
    shares: Vec<KeyShare>,
    key: GroupKey,
}

impl Group {
    fn share(&self, id: PartyId) -> &KeyShare {
        &self.shares[id as usize - 1]
    }
}

type Sent = BTreeMap<PartyId, BTreeMap<PartyId, DkgRound2Package>>;

fn round1_all(shape: GroupShape) -> (Vec<DkgRound1Secret>, BTreeMap<PartyId, DkgRound1Package>) {
    let mut secrets = Vec::new();
    let mut packages = BTreeMap::new();
    for id in 1..=shape.parties() {
        let (secret, package) = dkg_round1(shape, id).expect("round 1");
        secrets.push(secret);
        packages.insert(id, package);
    }
    (secrets, packages)
}

/// The round-1 packages party `me` receives: everyone else's.
fn others(
    all: &BTreeMap<PartyId, DkgRound1Package>,
    me: PartyId,
) -> BTreeMap<PartyId, DkgRound1Package> {
    all.iter()
        .filter(|(&id, _)| id != me)
        .map(|(&id, p)| (id, p.clone()))
        .collect()
}

fn round2_all(
    secrets: Vec<DkgRound1Secret>,
    r1: &BTreeMap<PartyId, DkgRound1Package>,
) -> (Vec<DkgRound2Secret>, Sent) {
    let mut out = Vec::new();
    let mut sent = BTreeMap::new();
    for secret in secrets {
        let me = secret.id;
        let (secret, packages) = dkg_round2(secret, &others(r1, me)).expect("round 2");
        out.push(secret);
        sent.insert(me, packages);
    }
    (out, sent)
}

/// Moves the round-2 packages addressed to `me` out of `sent`, keyed by sender.
fn inbox(sent: &mut Sent, me: PartyId) -> BTreeMap<PartyId, DkgRound2Package> {
    sent.iter_mut()
        .filter_map(|(&from, to)| to.remove(&me).map(|p| (from, p)))
        .collect()
}

fn keygen(t: u16, n: u16) -> Group {
    let (secrets, r1) = round1_all(shape(t, n));
    let (secrets, mut sent) = round2_all(secrets, &r1);
    let mut shares = Vec::new();
    let mut keys = Vec::new();
    for secret in secrets {
        let me = secret.id;
        let received = inbox(&mut sent, me);
        let (share, key) = dkg_round3(secret, &others(&r1, me), &received).expect("round 3");
        shares.push(share);
        keys.push(key);
    }
    assert!(keys.windows(2).all(|k| k[0] == k[1]), "one group key");
    assert!(keys
        .windows(2)
        .all(|k| k[0].fingerprint() == k[1].fingerprint()));
    Group {
        shares,
        key: keys.remove(0),
    }
}

/// Both signing rounds for `signers`, then aggregation of every share.
fn sign_with(
    g: &Group,
    signers: &[PartyId],
    sighash: &[u8; 32],
) -> Result<[u8; 64], ThresholdError> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in signers {
        let (n, c) = commit(g.share(id));
        nonces.insert(id, n);
        commitments.insert(id, c);
    }
    let mut shares = BTreeMap::new();
    for &id in signers {
        let n = nonces.remove(&id).expect("nonces");
        shares.insert(id, sign(g.share(id), n, sighash, &commitments)?);
    }
    aggregate(&g.key, sighash, &commitments, &shares)
}

const SIGHASH: [u8; 32] = [0x5A; 32];
const OTHER_SIGHASH: [u8; 32] = [0xA5; 32];

// =============================================================================================
// Group shape and parties
// =============================================================================================

#[test]
fn group_shape_refuses_a_threshold_below_two_or_above_the_parties() {
    assert!(GroupShape::new(2, 3).is_ok());
    assert!(GroupShape::new(3, 3).is_ok());
    for (t, n) in [(1, 3), (0, 3), (4, 3), (1, 1), (0, 0)] {
        assert_code(GroupShape::new(t, n), "THRESHOLD_PARAMS");
    }
}

#[test]
fn dkg_round1_refuses_a_party_outside_the_group() {
    assert!(dkg_round1(shape(2, 3), 3).is_ok());
    assert_code(dkg_round1(shape(2, 3), 0), "THRESHOLD_PARTY");
    assert_code(dkg_round1(shape(2, 3), 4), "THRESHOLD_PARTY");
}

// =============================================================================================
// Key generation
// =============================================================================================

#[test]
fn dkg_2_of_3_gives_every_party_the_same_x_only_authority_key() {
    let g = keygen(2, 3);
    let key = g.key.authority_key();
    XOnlyPublicKey::from_slice(&key).expect("x-only point");
    for share in &g.shares {
        assert_eq!(share.authority_key(), key);
        assert_eq!(share.shape(), shape(2, 3));
    }
    assert_eq!(
        g.shares.iter().map(KeyShare::id).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    // A second run is a different group.
    assert_ne!(keygen(2, 3).key.authority_key(), key);
}

#[test]
fn dkg_round2_refuses_a_missing_own_or_unknown_package() {
    let s = shape(2, 3);
    let (mut secrets, r1) = round1_all(s);
    let control = secrets.remove(0);
    assert!(dkg_round2(control, &others(&r1, 1)).is_ok());

    let (mut secrets, r1) = round1_all(s);
    let mut missing = others(&r1, 1);
    missing.remove(&3);
    let err = assert_code(
        dkg_round2(secrets.remove(0), &missing),
        "THRESHOLD_DKG_PACKAGES",
    );
    assert_eq!(
        err,
        ThresholdError::DkgPackages {
            round: 2,
            missing: vec![3],
            unexpected: vec![]
        }
    );

    let (mut secrets, r1) = round1_all(s);
    let with_own = r1.clone();
    assert_code(
        dkg_round2(secrets.remove(0), &with_own),
        "THRESHOLD_DKG_PACKAGES",
    );

    let (mut secrets, r1) = round1_all(s);
    let mut unknown = others(&r1, 1);
    let p = unknown.remove(&3).expect("package");
    unknown.insert(4, p);
    let err = assert_code(
        dkg_round2(secrets.remove(0), &unknown),
        "THRESHOLD_DKG_PACKAGES",
    );
    assert_eq!(
        err,
        ThresholdError::DkgPackages {
            round: 2,
            missing: vec![3],
            unexpected: vec![4]
        }
    );
}

/// Party 1 of a 2-of-3 run receives the round-1 packages of a 3-of-3 run: their commitments have
/// three coefficients where two are expected. FROST refuses; no code of ours is more specific, so
/// it is THRESHOLD_REFUSED. Control: the packages of its own run.
#[test]
fn dkg_round2_refuses_packages_of_another_threshold() {
    let (mut secrets, r1) = round1_all(shape(2, 3));
    assert!(dkg_round2(secrets.remove(0), &others(&r1, 1)).is_ok());

    let (mut secrets, _) = round1_all(shape(2, 3));
    let (_, r1_3of3) = round1_all(shape(3, 3));
    let err = assert_code(
        dkg_round2(secrets.remove(0), &others(&r1_3of3, 1)),
        "THRESHOLD_REFUSED",
    );
    assert_eq!(
        err,
        ThresholdError::Refused {
            reason: "Incorrect number of commitments.".into()
        }
    );
}

/// Party 1 receives party 3's round-1 package as if from party 2: the proof of knowledge is bound
/// to its sender's identifier, so it fails, and party 2 is named. Control: party 2 of the same run
/// with the packages as sent.
#[test]
fn dkg_round2_names_the_sender_of_a_bad_proof_of_knowledge() {
    let s = shape(2, 3);
    let (mut secrets, r1) = round1_all(s);
    assert!(dkg_round2(secrets.remove(1), &others(&r1, 2)).is_ok());
    let mut received = others(&r1, 1);
    let p3 = received[&3].clone();
    received.insert(2, p3);
    let err = assert_code(
        dkg_round2(secrets.remove(0), &received),
        "THRESHOLD_DKG_CULPRIT",
    );
    assert_eq!(
        err,
        ThresholdError::DkgCulprit {
            round: 2,
            culprit: Some(2)
        }
    );
}

/// Control: party 2 of the same run with every package addressed to it.
#[test]
fn dkg_round3_refuses_a_missing_round2_package() {
    let (secrets, r1) = round1_all(shape(2, 3));
    let (mut secrets, mut sent) = round2_all(secrets, &r1);
    let complete = inbox(&mut sent, 2);
    assert!(dkg_round3(secrets.remove(1), &others(&r1, 2), &complete).is_ok());
    let mut received = inbox(&mut sent, 1);
    received.remove(&2);
    let err = assert_code(
        dkg_round3(secrets.remove(0), &others(&r1, 1), &received),
        "THRESHOLD_DKG_PACKAGES",
    );
    assert_eq!(
        err,
        ThresholdError::DkgPackages {
            round: 3,
            missing: vec![2],
            unexpected: vec![]
        }
    );
}

/// Round 3 needs the same complete set of round-1 packages as round 2. Control: party 2 of the
/// same run with every package.
#[test]
fn dkg_round3_refuses_a_missing_round1_package() {
    let (secrets, r1) = round1_all(shape(2, 3));
    let (mut secrets, mut sent) = round2_all(secrets, &r1);
    let complete = inbox(&mut sent, 2);
    assert!(dkg_round3(secrets.remove(1), &others(&r1, 2), &complete).is_ok());
    let mut round1 = others(&r1, 1);
    round1.remove(&3);
    let err = assert_code(
        dkg_round3(secrets.remove(0), &round1, &inbox(&mut sent, 1)),
        "THRESHOLD_DKG_PACKAGES",
    );
    assert_eq!(
        err,
        ThresholdError::DkgPackages {
            round: 3,
            missing: vec![3],
            unexpected: vec![]
        }
    );
}

/// At round 3, party 1 is given party 3's round-1 package as party 2's: party 2's share does not
/// match that commitment, and party 2 is named. Control: party 2 of the same run with the
/// packages as sent.
#[test]
fn dkg_round3_names_the_sender_of_a_tampered_round1_package() {
    let (secrets, r1) = round1_all(shape(2, 3));
    let (mut secrets, mut sent) = round2_all(secrets, &r1);
    let complete = inbox(&mut sent, 2);
    assert!(dkg_round3(secrets.remove(1), &others(&r1, 2), &complete).is_ok());
    let mut round1 = others(&r1, 1);
    round1.insert(2, r1[&3].clone());
    let err = assert_code(
        dkg_round3(secrets.remove(0), &round1, &inbox(&mut sent, 1)),
        "THRESHOLD_DKG_CULPRIT",
    );
    assert_eq!(
        err,
        ThresholdError::DkgCulprit {
            round: 3,
            culprit: Some(2)
        }
    );
}

/// Key generation output that does not match the group shape is refused, one clause at a time.
/// Control: the output of a real 2-of-3 run gives its authority key and fingerprint.
#[test]
fn group_output_refuses_output_that_does_not_match_the_shape() {
    let s = shape(2, 3);
    let g = keygen(2, 3);
    let h = keygen(2, 3);
    let kp = &g.share(1).inner;
    let pk = &g.key.inner;
    assert_eq!(
        group_output(&s, kp, pk).expect("control"),
        (g.key.authority_key(), g.key.fingerprint())
    );

    let id = |i: u16| Identifier::try_from(i).expect("id");
    let kp_min3 = frost::keys::KeyPackage::new(
        *kp.identifier(),
        *kp.signing_share(),
        *kp.verifying_share(),
        *kp.verifying_key(),
        3,
    );
    let shares = pk.verifying_shares().clone();
    let pk_min = |m| frost::keys::PublicKeyPackage::new(shares.clone(), *pk.verifying_key(), m);
    let mut two = shares.clone();
    two.remove(&id(3));
    let mut renumbered = two.clone();
    renumbered.insert(id(4), shares[&id(3)]);
    let mut four = shares.clone();
    four.insert(id(4), shares[&id(3)]);
    let pk_with = |sh| frost::keys::PublicKeyPackage::new(sh, *pk.verifying_key(), Some(2));
    let pk_other_key =
        frost::keys::PublicKeyPackage::new(shares.clone(), *h.key.inner.verifying_key(), Some(2));

    let refused = ThresholdError::Refused {
        reason: "key generation output does not match the group shape".into(),
    };
    for (label, kp, pk) in [
        ("key share threshold 3", &kp_min3, pk),
        ("group threshold 3", kp, &pk_min(Some(3))),
        ("group threshold absent", kp, &pk_min(None)),
        ("two public shares", kp, &pk_with(two)),
        (
            "public share of party 4, none of 3",
            kp,
            &pk_with(renumbered),
        ),
        ("a fourth public share", kp, &pk_with(four)),
        ("group key of another group", kp, &pk_other_key),
    ] {
        assert_eq!(
            group_output(&s, kp, pk).expect_err(label),
            refused,
            "{label}"
        );
    }
}

#[test]
fn x_only_refuses_anything_but_a_compressed_point() {
    let sec1 = g_sec1();
    assert_eq!(x_only(&sec1).expect("control")[..], sec1[1..]);
    let mut odd = sec1.clone();
    odd[0] = 0x03;
    assert!(x_only(&odd).is_ok(), "either parity");
    let mut uncompressed_prefix = sec1.clone();
    uncompressed_prefix[0] = 0x04;
    let mut not_on_curve = vec![0x02];
    not_on_curve.extend([0xFF; 32]);
    let mut long = sec1.clone();
    long.push(0);
    for bad in [
        &uncompressed_prefix,
        &not_on_curve,
        &sec1[..32].to_vec(),
        &long,
        &vec![],
    ] {
        assert_code(x_only(bad), "THRESHOLD_KEY_INVALID");
    }
}

/// The SEC1 form of a real group key.
fn g_sec1() -> Vec<u8> {
    keygen(2, 3)
        .key
        .inner
        .verifying_key()
        .serialize()
        .expect("sec1")
}

#[test]
fn by_party_refuses_an_identifier_outside_the_group() {
    let s = shape(2, 3);
    let id = |i: u16| Identifier::try_from(i).expect("id");
    let control = BTreeMap::from([(id(1), 'a'), (id(3), 'c')]);
    assert_eq!(
        by_party(&s, control).expect("control"),
        BTreeMap::from([(1, 'a'), (3, 'c')])
    );
    let outside = BTreeMap::from([(id(1), 'a'), (id(4), 'd')]);
    assert_eq!(
        by_party(&s, outside).expect_err("party 4"),
        ThresholdError::Refused {
            reason: "an identifier outside the group".into()
        }
    );
}

/// Party 1 receives, as party 2's share for it, the share party 2 made for party 3: it does not
/// match party 2's commitment at party 1's identifier, and party 2 is named. The control is the
/// same run with the right package.
#[test]
fn dkg_round3_names_the_sender_of_a_bad_secret_share() {
    let (secrets, r1) = round1_all(shape(2, 3));
    let (mut secrets, mut sent) = round2_all(secrets, &r1);
    let wrong = sent
        .get_mut(&2)
        .and_then(|to| to.remove(&3))
        .expect("2 -> 3");
    let mut received = inbox(&mut sent, 1);
    received.insert(2, wrong).expect("2 -> 1");
    let err = assert_code(
        dkg_round3(secrets.remove(0), &others(&r1, 1), &received),
        "THRESHOLD_DKG_CULPRIT",
    );
    assert_eq!(
        err,
        ThresholdError::DkgCulprit {
            round: 3,
            culprit: Some(2)
        }
    );

    // Control: a run where party 1 receives party 2's package for party 1.
    let (secrets, r1) = round1_all(shape(2, 3));
    let (mut secrets, mut sent) = round2_all(secrets, &r1);
    let received = inbox(&mut sent, 1);
    assert!(dkg_round3(secrets.remove(0), &others(&r1, 1), &received).is_ok());
}

// =============================================================================================
// Key generation: confirming the transcript and the group key
// =============================================================================================

type Suite = frost::Secp256K1Sha256TR;
type Curve = <Suite as frost::Ciphersuite>::Group;
type Scalars = <Curve as frost::Group>::Field;

/// Party 3's round-1 package as it equivocates towards one recipient: the same C0 and proof of
/// knowledge (which covers C0 only), with C1 replaced by C1 + G.
fn equivocated(p: &DkgRound1Package) -> DkgRound1Package {
    use frost::Group;
    let mut coefficients = p.0.commitment().serialize().expect("commitment");
    let c1 = <Curve as Group>::Serialization::try_from(coefficients[1].as_slice()).expect("C1");
    let c1 = Curve::deserialize(&c1).expect("C1") + Curve::generator();
    coefficients[1] = Curve::serialize(&c1).expect("C1 + G").as_ref().to_vec();
    let commitment =
        frost::keys::VerifiableSecretSharingCommitment::deserialize(coefficients).expect("C");
    DkgRound1Package(dkg::round1::Package::new(
        commitment,
        *p.0.proof_of_knowledge(),
    ))
}

/// Party 3's round-2 share for that recipient, matching the equivocated commitment:
/// f3(2) + 2 at party 2 (C1 + G adds x to the polynomial).
fn equivocated_share(p: &DkgRound2Package) -> DkgRound2Package {
    use frost::Field;
    let bytes = p.0.signing_share().serialize();
    let s = <Scalars as Field>::Serialization::try_from(bytes.as_slice()).expect("32 bytes");
    let s = Scalars::deserialize(&s).expect("scalar") + Scalars::one() + Scalars::one();
    let share = frost::keys::SigningShare::deserialize(Scalars::serialize(&s).as_ref())
        .expect("signing share");
    DkgRound2Package(dkg::round2::Package::new(share))
}

/// One 2-of-3 key generation in which party 3 equivocates towards party 2 (or not, for the
/// control). Returns every party's round-1 view (own package included), shares and group keys.
fn keygen_equivocating(
    equivocate: bool,
) -> (
    Vec<BTreeMap<PartyId, DkgRound1Package>>,
    Vec<KeyShare>,
    Vec<GroupKey>,
) {
    let (secrets, r1) = round1_all(shape(2, 3));
    let mut views = vec![r1.clone(), r1.clone(), r1.clone()];
    if equivocate {
        let bad = equivocated(&r1[&3]);
        views[1].insert(3, bad);
    }
    let mut r2_secrets = Vec::new();
    let mut sent: Sent = BTreeMap::new();
    for secret in secrets {
        let me = secret.id;
        let (secret, packages) =
            dkg_round2(secret, &others(&views[me as usize - 1], me)).expect("round 2");
        r2_secrets.push(secret);
        sent.insert(me, packages);
    }
    if equivocate {
        let to_2 = sent
            .get_mut(&3)
            .and_then(|to| to.get_mut(&2))
            .expect("3 -> 2");
        *to_2 = equivocated_share(to_2);
    }
    let mut shares = Vec::new();
    let mut keys = Vec::new();
    for secret in r2_secrets {
        let me = secret.id;
        let view = others(&views[me as usize - 1], me);
        let (share, key) = dkg_round3(secret, &view, &inbox(&mut sent, me)).expect("round 3");
        shares.push(share);
        keys.push(key);
    }
    (views, shares, keys)
}

/// Review round 1, item 1. Party 3 equivocates in round 1 towards party 2. Every round succeeds
/// and all three parties hold the same authority key, yet the honest pair {1, 2} can never sign.
/// The round-1 digests and the group fingerprints differ between parties 1 and 2, so the
/// confirmation step catches it before the key goes into terms. Control: the same run without
/// the equivocation, where both values agree at every party and every pair signs.
#[test]
fn round1_equivocation_keeps_the_authority_key_but_changes_digest_and_fingerprint() {
    let s = shape(2, 3);
    for equivocate in [false, true] {
        let (views, shares, keys) = keygen_equivocating(equivocate);
        let digests: Vec<[u8; 32]> = views
            .iter()
            .map(|v| dkg_round1_digest(s, v).expect("digest"))
            .collect();
        let prints: Vec<[u8; 32]> = keys.iter().map(GroupKey::fingerprint).collect();
        assert!(keys
            .windows(2)
            .all(|k| k[0].authority_key() == k[1].authority_key()));
        let g = Group {
            shares,
            key: keys[0].clone(),
        };
        let pair_12 = sign_with(&g, &[1, 2], &SIGHASH);
        if equivocate {
            assert_ne!(digests[0], digests[1], "round-1 views of parties 1 and 2");
            assert_eq!(digests[0], digests[2]);
            assert_ne!(prints[0], prints[1], "group keys of parties 1 and 2");
            assert_ne!(prints[1], prints[2], "group keys of parties 2 and 3");
            assert_eq!(prints[0], prints[2]);
            // What the confirmation prevents: the honest pair cannot sign, and the
            // aggregator's blame falls on an honest party.
            assert_eq!(
                pair_12.expect_err("{1, 2}"),
                ThresholdError::ShareInvalid { culprits: vec![2] }
            );
            assert!(sign_with(&g, &[1, 3], &SIGHASH).is_ok());
        } else {
            assert!(digests.windows(2).all(|d| d[0] == d[1]), "control digests");
            assert!(
                prints.windows(2).all(|p| p[0] == p[1]),
                "control fingerprints"
            );
            assert!(pair_12.is_ok(), "control {{1, 2}}");
            assert!(sign_with(&g, &[2, 3], &SIGHASH).is_ok(), "control {{2, 3}}");
        }
    }
}

#[test]
fn dkg_round1_digest_needs_every_partys_package_own_included() {
    let s = shape(2, 3);
    let (_, r1) = round1_all(s);
    let control = dkg_round1_digest(s, &r1).expect("control");
    let (_, r1b) = round1_all(s);
    assert_ne!(dkg_round1_digest(s, &r1b).expect("another run"), control);

    let err = assert_code(
        dkg_round1_digest(s, &others(&r1, 2)),
        "THRESHOLD_DKG_PACKAGES",
    );
    assert_eq!(
        err,
        ThresholdError::DkgPackages {
            round: 1,
            missing: vec![2],
            unexpected: vec![]
        }
    );
    let mut extra = r1.clone();
    extra.insert(4, r1[&1].clone());
    assert_code(dkg_round1_digest(s, &extra), "THRESHOLD_DKG_PACKAGES");
}

/// The fingerprint is the documented keyed blake2b-256 over the shape, the authority key and
/// every public share in party order (spec/THRESHOLD.md, "Key generation").
#[test]
fn group_fingerprint_encoding() {
    let g = keygen(2, 3);
    let mut bytes = vec![0, 2, 0, 3];
    bytes.extend_from_slice(&g.key.authority_key());
    for id in 1..=3u16 {
        let identifier = Identifier::try_from(id).expect("id");
        bytes.extend(
            g.key.inner.verifying_shares()[&identifier]
                .serialize()
                .expect("share"),
        );
    }
    assert_eq!(bytes.len(), 4 + 32 + 3 * 33);
    let expected = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/thresholdgroup/v1")
        .hash(&bytes);
    assert_eq!(g.key.fingerprint(), expected.as_bytes());
}

// =============================================================================================
// Signing: t of n sign, fewer cannot
// =============================================================================================

#[test]
fn every_2_of_3_signing_set_produces_a_bip340_signature() {
    let g = keygen(2, 3);
    for signers in [&[1, 2][..], &[1, 3], &[2, 3], &[1, 2, 3]] {
        let sig = sign_with(&g, signers, &SIGHASH).expect("signature");
        verify(&g.key.authority_key(), &SIGHASH, &sig).expect("verifies");
        // Independently of `verify`: libsecp256k1's BIP-340 check under the x-only key.
        let key = XOnlyPublicKey::from_slice(&g.key.authority_key()).expect("key");
        let sig = schnorr::Signature::from_slice(&sig).expect("64 bytes");
        SECP256K1
            .verify_schnorr(&sig, &Message::from_digest(SIGHASH), &key)
            .expect("BIP-340");
    }
}

#[test]
fn one_of_three_is_refused_at_sign_and_at_aggregate() {
    let g = keygen(2, 3);
    assert!(sign_with(&g, &[1, 2], &SIGHASH).is_ok());

    let (nonces, c1) = commit(g.share(1));
    let alone = BTreeMap::from([(1, c1)]);
    let err = assert_code(
        sign(g.share(1), nonces, &SIGHASH, &alone),
        "THRESHOLD_TOO_FEW_SIGNERS",
    );
    assert_eq!(
        err,
        ThresholdError::TooFewSigners {
            signers: 1,
            threshold: 2
        }
    );

    // A share made inside a 2-party set, aggregated as if it were the whole set.
    let (n1, c1) = commit(g.share(1));
    let (_n2, c2) = commit(g.share(2));
    let pair = BTreeMap::from([(1, c1), (2, c2)]);
    let s1 = sign(g.share(1), n1, &SIGHASH, &pair).expect("share 1");
    assert_code(
        aggregate(&g.key, &SIGHASH, &alone, &BTreeMap::from([(1, s1)])),
        "THRESHOLD_TOO_FEW_SIGNERS",
    );
}

#[test]
fn three_of_five_needs_three() {
    let g = keygen(3, 5);
    let sig = sign_with(&g, &[2, 4, 5], &SIGHASH).expect("3 of 5");
    verify(&g.key.authority_key(), &SIGHASH, &sig).expect("verifies");
    let err = assert_code(
        sign_with(&g, &[2, 4], &SIGHASH),
        "THRESHOLD_TOO_FEW_SIGNERS",
    );
    assert_eq!(
        err,
        ThresholdError::TooFewSigners {
            signers: 2,
            threshold: 3
        }
    );
}

/// A lone signer's share aggregated as if it were the whole signature of a 2-party set: the
/// set's group commitment R (computable from the public commitments; taken here from the honest
/// aggregate of the same session) with z1 in place of z1 + z2. Not a signature under the group key.
#[test]
fn a_lone_share_is_not_a_signature() {
    let g = keygen(2, 3);
    let (n1, c1) = commit(g.share(1));
    let (n2, c2) = commit(g.share(2));
    let set = BTreeMap::from([(1, c1), (2, c2)]);
    let s1 = sign(g.share(1), n1, &SIGHASH, &set).expect("share 1");
    let s2 = sign(g.share(2), n2, &SIGHASH, &set).expect("share 2");
    let full =
        aggregate(&g.key, &SIGHASH, &set, &BTreeMap::from([(1, s1), (2, s2)])).expect("2 of 3");
    verify(&g.key.authority_key(), &SIGHASH, &full).expect("control verifies");

    let mut lone = full;
    lone[32..].copy_from_slice(&s1.to_bytes());
    assert_code(
        verify(&g.key.authority_key(), &SIGHASH, &lone),
        "THRESHOLD_SIGNATURE_INVALID",
    );
}

/// `SignatureShare::to_bytes` is the share's scalar z_i, 32 bytes big-endian: z1 + z2 mod n,
/// added by libsecp256k1, is the s half of the aggregate of the same session, so the value the
/// lone-share tests refuse is exactly the partial share. FROST reads the bytes back as the same
/// share.
#[test]
fn signature_share_bytes_are_the_big_endian_partial_scalar() {
    let g = keygen(2, 3);
    let s = session(&g, &[1, 2], |_| SIGHASH);
    let full = aggregate(&g.key, &SIGHASH, &s.set, &s.shares).expect("2 of 3");
    let z1 = s.shares[&1].to_bytes();
    let z2 = s.shares[&2].to_bytes();
    let z2 = secp256k1::Scalar::from_be_bytes(z2).expect("z2 below n");
    let sum = secp256k1::SecretKey::from_slice(&z1)
        .expect("z1 a nonzero scalar below n")
        .add_tweak(&z2)
        .expect("z1 + z2 nonzero")
        .secret_bytes();
    assert_eq!(sum[..], full[32..]);
    assert_eq!(
        frost::round2::SignatureShare::deserialize(&z1).expect("share"),
        s.shares[&1].0
    );
}

#[test]
fn sign_refuses_a_party_outside_the_group() {
    let g = keygen(2, 3);
    let (n1, c1) = commit(g.share(1));
    let (_n2, c2) = commit(g.share(2));
    let control = BTreeMap::from([(1, c1), (2, c2)]);
    let mut faulty = control.clone();
    let c = faulty.remove(&2).expect("c2");
    faulty.insert(4, c);
    let err = assert_code(sign(g.share(1), n1, &SIGHASH, &faulty), "THRESHOLD_PARTY");
    assert_eq!(err, ThresholdError::Party { id: 4, parties: 3 });
    let (n1, c1) = commit(g.share(1));
    let control = BTreeMap::from([(1, c1), (2, c2)]);
    assert!(sign(g.share(1), n1, &SIGHASH, &control).is_ok());
}

#[test]
fn sign_refuses_when_its_commitment_is_absent_or_not_from_its_nonces() {
    let g = keygen(2, 3);
    let (_n2, c2) = commit(g.share(2));
    let (_n3, c3) = commit(g.share(3));

    // Control.
    let (n1, c1) = commit(g.share(1));
    assert!(sign(
        g.share(1),
        n1,
        &SIGHASH,
        &BTreeMap::from([(1, c1), (2, c2)])
    )
    .is_ok());

    // Its commitment is not in the set.
    let (n1, _c1) = commit(g.share(1));
    let without = BTreeMap::from([(2, c2), (3, c3)]);
    assert_code(
        sign(g.share(1), n1, &SIGHASH, &without),
        "THRESHOLD_SIGNER_NOT_IN_SET",
    );

    // The set holds another commitment of party 1, not the one of these nonces.
    let (old, _) = commit(g.share(1));
    let (_new, c_new) = commit(g.share(1));
    let set = BTreeMap::from([(1, c_new), (2, c2)]);
    assert_code(
        sign(g.share(1), old, &SIGHASH, &set),
        "THRESHOLD_SIGNER_NOT_IN_SET",
    );

    // Nonces of party 2 used with party 1's share.
    let (n2, c2b) = commit(g.share(2));
    let (_n1, c1) = commit(g.share(1));
    let set = BTreeMap::from([(1, c1), (2, c2b)]);
    assert_code(
        sign(g.share(1), n2, &SIGHASH, &set),
        "THRESHOLD_SIGNER_NOT_IN_SET",
    );
}

// =============================================================================================
// Aggregation
// =============================================================================================

struct Session {
    set: BTreeMap<PartyId, Commitment>,
    shares: BTreeMap<PartyId, SignatureShare>,
}

fn session(g: &Group, signers: &[PartyId], sighash_of: impl Fn(PartyId) -> [u8; 32]) -> Session {
    let mut nonces = BTreeMap::new();
    let mut set = BTreeMap::new();
    for &id in signers {
        let (n, c) = commit(g.share(id));
        nonces.insert(id, n);
        set.insert(id, c);
    }
    let mut shares = BTreeMap::new();
    for &id in signers {
        let n = nonces.remove(&id).expect("nonces");
        let share = sign(g.share(id), n, &sighash_of(id), &set).expect("share");
        shares.insert(id, share);
    }
    Session { set, shares }
}

#[test]
fn aggregate_refuses_shares_that_are_not_exactly_the_signing_set() {
    let g = keygen(2, 3);
    let s = session(&g, &[1, 2], |_| SIGHASH);
    assert!(aggregate(&g.key, &SIGHASH, &s.set, &s.shares).is_ok());

    let mut missing = s.shares.clone();
    missing.remove(&2);
    let err = assert_code(
        aggregate(&g.key, &SIGHASH, &s.set, &missing),
        "THRESHOLD_SHARES_MISMATCH",
    );
    assert_eq!(
        err,
        ThresholdError::SharesMismatch {
            missing: vec![2],
            unexpected: vec![]
        }
    );

    let other = session(&g, &[1, 3], |_| SIGHASH);
    let mut extra = s.shares.clone();
    extra.insert(3, other.shares[&3]);
    let err = assert_code(
        aggregate(&g.key, &SIGHASH, &s.set, &extra),
        "THRESHOLD_SHARES_MISMATCH",
    );
    assert_eq!(
        err,
        ThresholdError::SharesMismatch {
            missing: vec![],
            unexpected: vec![3]
        }
    );
}

#[test]
fn aggregate_names_a_share_over_another_message() {
    let g = keygen(2, 3);
    let control = session(&g, &[1, 2], |_| SIGHASH);
    assert!(aggregate(&g.key, &SIGHASH, &control.set, &control.shares).is_ok());

    let s = session(
        &g,
        &[1, 2],
        |id| if id == 2 { OTHER_SIGHASH } else { SIGHASH },
    );
    let err = assert_code(
        aggregate(&g.key, &SIGHASH, &s.set, &s.shares),
        "THRESHOLD_SHARE_INVALID",
    );
    assert_eq!(err, ThresholdError::ShareInvalid { culprits: vec![2] });
}

/// aggregate checks its result under the authority key with libsecp256k1 before returning it: a
/// group key whose authority key is not the key the shares were made under is refused, although
/// every share verifies. Control: the group's own key.
#[test]
fn aggregate_verifies_the_result_under_the_authority_key() {
    let g = keygen(2, 3);
    let h = keygen(2, 3);
    let s = session(&g, &[1, 2], |_| SIGHASH);
    assert!(aggregate(&g.key, &SIGHASH, &s.set, &s.shares).is_ok());
    let mismatched = GroupKey {
        authority_key: h.key.authority_key(),
        ..g.key.clone()
    };
    assert_code(
        aggregate(&mismatched, &SIGHASH, &s.set, &s.shares),
        "THRESHOLD_SIGNATURE_INVALID",
    );
}

/// Every party whose share fails is named, not only the first. Control: the same three-party
/// set over one message.
#[test]
fn aggregate_names_every_invalid_share() {
    let g = keygen(2, 3);
    let control = session(&g, &[1, 2, 3], |_| SIGHASH);
    assert!(aggregate(&g.key, &SIGHASH, &control.set, &control.shares).is_ok());
    let s = session(&g, &[1, 2, 3], |id| {
        if id == 1 {
            SIGHASH
        } else {
            OTHER_SIGHASH
        }
    });
    let err = assert_code(
        aggregate(&g.key, &SIGHASH, &s.set, &s.shares),
        "THRESHOLD_SHARE_INVALID",
    );
    assert_eq!(
        err,
        ThresholdError::ShareInvalid {
            culprits: vec![2, 3]
        }
    );
}

#[test]
fn aggregate_refuses_shares_of_another_group() {
    let g = keygen(2, 3);
    let h = keygen(2, 3);
    let s = session(&h, &[1, 2], |_| SIGHASH);
    assert!(aggregate(&h.key, &SIGHASH, &s.set, &s.shares).is_ok());
    assert_code(
        aggregate(&g.key, &SIGHASH, &s.set, &s.shares),
        "THRESHOLD_SHARE_INVALID",
    );
}

// =============================================================================================
// Verification
// =============================================================================================

#[test]
fn verify_refuses_another_key_message_or_signature() {
    let g = keygen(2, 3);
    let h = keygen(2, 3);
    let sig = sign_with(&g, &[1, 3], &SIGHASH).expect("signature");
    let key = g.key.authority_key();
    verify(&key, &SIGHASH, &sig).expect("control");

    assert_code(
        verify(&h.key.authority_key(), &SIGHASH, &sig),
        "THRESHOLD_SIGNATURE_INVALID",
    );
    assert_code(
        verify(&key, &OTHER_SIGHASH, &sig),
        "THRESHOLD_SIGNATURE_INVALID",
    );
    for byte in [0, 31, 32, 63] {
        let mut bad = sig;
        bad[byte] ^= 0x01;
        assert_code(verify(&key, &SIGHASH, &bad), "THRESHOLD_SIGNATURE_INVALID");
    }
    // An x coordinate at or above the field prime is no point.
    assert_code(verify(&[0xFF; 32], &SIGHASH, &sig), "THRESHOLD_KEY_INVALID");
}

// =============================================================================================
// Byte encodings (spec/THRESHOLD.md, "Encodings")
// =============================================================================================

/// FROST distributed key generation in which every package crosses the byte encoding before it
/// is used, as it does between CLI processes.
fn keygen_through_bytes(t: u16, n: u16) -> Group {
    let (secrets, r1) = round1_all(shape(t, n));
    let r1: BTreeMap<PartyId, DkgRound1Package> = r1
        .iter()
        .map(|(&id, p)| {
            let bytes = p.to_bytes().expect("encodes");
            let back = DkgRound1Package::from_bytes(&bytes).expect("decodes");
            assert_eq!(&back, p, "round-1 package of party {id} round-trips");
            (id, back)
        })
        .collect();
    let (secrets, sent) = round2_all(secrets, &r1);
    let mut sent: Sent = sent
        .into_iter()
        .map(|(from, to)| {
            let to = to
                .into_iter()
                .map(|(id, p)| {
                    let back = DkgRound2Package::from_bytes(&p.to_bytes()[..]).expect("decodes");
                    assert_eq!(back.to_bytes(), p.to_bytes());
                    (id, back)
                })
                .collect();
            (from, to)
        })
        .collect();
    let mut shares = Vec::new();
    let mut keys = Vec::new();
    for secret in secrets {
        let me = secret.id;
        let (share, key) =
            dkg_round3(secret, &others(&r1, me), &inbox(&mut sent, me)).expect("round 3");
        let bytes = share.to_bytes().expect("encodes");
        let back = KeyShare::from_bytes(&bytes).expect("decodes");
        assert_eq!(back.to_bytes().expect("encodes")[..], bytes[..]);
        assert_eq!(
            (back.id(), back.shape(), back.authority_key()),
            (me, share.shape(), share.authority_key())
        );
        let key_back = GroupKey::from_bytes(&key.to_bytes().expect("encodes")).expect("decodes");
        assert_eq!(key_back, key, "group key round-trips, fingerprint included");
        shares.push(back);
        keys.push(key_back);
    }
    Group {
        shares,
        key: keys.remove(0),
    }
}

#[test]
fn every_value_round_trips_and_a_group_from_bytes_signs() {
    for (t, n) in [(2, 3), (3, 5)] {
        let g = keygen_through_bytes(t, n);
        let signers: Vec<PartyId> = (1..=t).collect();
        let sig = sign_with(&g, &signers, &SIGHASH).expect("signs");
        verify(&g.key.authority_key(), &SIGHASH, &sig).expect("BIP-340");
        // Commitments and signature shares cross the encoding too.
        let (nonces, c) = commit(g.share(1));
        let c_back = Commitment::from_bytes(&c.to_bytes().expect("encodes")).expect("decodes");
        assert_eq!(c_back, c);
        let (n2, c2) = commit(g.share(2));
        let mut set = BTreeMap::from([(1, c_back), (2, c2)]);
        if t == 3 {
            let (_, c3) = commit(g.share(3));
            set.insert(3, c3);
        }
        let s1 = sign(g.share(1), nonces, &SIGHASH, &set).expect("signs");
        let s1_back = SignatureShare::from_bytes(&s1.to_bytes()).expect("decodes");
        assert_eq!(s1_back, s1);
        drop(n2);
    }
}

#[test]
fn the_encodings_have_the_specified_layout() {
    let g = keygen(2, 3);
    let share = g.share(2).to_bytes().expect("encodes");
    assert_eq!(share.len(), 6 + 32 + 33 + 33);
    assert_eq!(
        &share[..6],
        &[0, 2, 0, 3, 0, 2],
        "threshold, parties, party"
    );
    let key = g.key.to_bytes().expect("encodes");
    assert_eq!(key.len(), 4 + 33 + 3 * 33);
    assert_eq!(&key[..4], &[0, 2, 0, 3]);
    assert_eq!(key[5..37], g.key.authority_key(), "x of the group key");
    assert_eq!(&share[71..], &key[4..37], "the share carries the group key");
    let (secrets, r1) = round1_all(shape(2, 3));
    drop(secrets);
    let p = r1[&1].to_bytes().expect("encodes");
    assert_eq!(p.len(), 2 + 2 * 33 + 64);
    assert_eq!(&p[..2], &[0, 2], "two coefficients");
    let (_, c) = commit(g.share(1));
    assert_eq!(c.to_bytes().expect("encodes").len(), 66);
}

/// Every decoder refuses with THRESHOLD_ENCODING, each case beside the decoding control.
#[test]
fn decoders_refuse_what_is_not_an_encoding() {
    const BAD_POINT: [u8; 33] = [0xFF; 33];
    const BAD_SCALAR: [u8; 32] = [0xFF; 32];
    let g = keygen(2, 3);

    // Round-1 package.
    let (secrets, r1) = round1_all(shape(2, 3));
    drop(secrets);
    let good = r1[&1].to_bytes().expect("encodes");
    assert!(DkgRound1Package::from_bytes(&good).is_ok(), "control");
    let mut zero_count = good.clone();
    zero_count[..2].copy_from_slice(&[0, 0]);
    let mut bad_point = good.clone();
    bad_point[2..35].copy_from_slice(&BAD_POINT);
    let mut bad_proof = good.clone();
    let end = bad_proof.len();
    bad_proof[end - 32..].copy_from_slice(&BAD_SCALAR);
    let mut extra = good.clone();
    extra.push(0);
    for (label, bytes) in [
        ("empty", vec![]),
        ("truncated", good[..good.len() - 1].to_vec()),
        ("extra byte", extra),
        ("no coefficient", zero_count),
        ("coefficient off the curve", bad_point),
        ("proof scalar out of range", bad_proof),
    ] {
        let e = DkgRound1Package::from_bytes(&bytes).expect_err(label);
        assert_eq!(e.code(), "THRESHOLD_ENCODING", "{label}: {e}");
    }

    // Round-2 package.
    let (secrets, r1) = round1_all(shape(2, 3));
    let (_, sent) = round2_all(secrets, &r1);
    let good = sent[&1][&2].to_bytes();
    assert!(DkgRound2Package::from_bytes(&good[..]).is_ok(), "control");
    assert_code(
        DkgRound2Package::from_bytes(&good[..31]),
        "THRESHOLD_ENCODING",
    );
    assert_code(
        DkgRound2Package::from_bytes(&BAD_SCALAR),
        "THRESHOLD_ENCODING",
    );

    // Key share.
    let good = g.share(1).to_bytes().expect("encodes");
    assert!(KeyShare::from_bytes(&good).is_ok(), "control");
    let other = g.share(2).to_bytes().expect("encodes");
    let edit = |at: usize, with: &[u8]| {
        let mut b = good.to_vec();
        b[at..at + with.len()].copy_from_slice(with);
        b
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", good[..good.len() - 1].to_vec()),
        ("threshold 1", edit(0, &[0, 1])),
        ("threshold above the parties", edit(0, &[0, 4])),
        ("party 0", edit(4, &[0, 0])),
        ("party outside the group", edit(4, &[0, 4])),
        ("signing share out of range", edit(6, &BAD_SCALAR)),
        ("public share of another party", edit(38, &other[38..71])),
        ("public share off the curve", edit(38, &BAD_POINT)),
        ("group key off the curve", edit(71, &BAD_POINT)),
    ];
    for (label, bytes) in cases {
        let e = KeyShare::from_bytes(&bytes).expect_err(label);
        assert_eq!(e.code(), "THRESHOLD_ENCODING", "{label}: {e}");
    }

    // Group key.
    let good = g.key.to_bytes().expect("encodes");
    assert!(GroupKey::from_bytes(&good).is_ok(), "control");
    let mut bad_share = good.clone();
    bad_share[37..70].copy_from_slice(&BAD_POINT);
    let mut extra = good.clone();
    extra.push(0);
    let mut one_of_three = good.clone();
    one_of_three[..2].copy_from_slice(&[0, 1]);
    for bytes in [
        good[..good.len() - 33].to_vec(),
        extra,
        one_of_three,
        bad_share,
    ] {
        assert_code(GroupKey::from_bytes(&bytes), "THRESHOLD_ENCODING");
    }

    // Commitment and signature share.
    let (_, c) = commit(g.share(1));
    let good = c.to_bytes().expect("encodes");
    assert!(Commitment::from_bytes(&good).is_ok(), "control");
    assert_code(Commitment::from_bytes(&good[..65]), "THRESHOLD_ENCODING");
    let mut off = good;
    off[33..].copy_from_slice(&BAD_POINT);
    assert_code(Commitment::from_bytes(&off), "THRESHOLD_ENCODING");
    assert!(SignatureShare::from_bytes(&[1; 32]).is_ok(), "control");
    assert_code(SignatureShare::from_bytes(&[1; 31]), "THRESHOLD_ENCODING");
    assert_code(
        SignatureShare::from_bytes(&BAD_SCALAR),
        "THRESHOLD_ENCODING",
    );
}

// =============================================================================================
// Signing a transaction input by its own SIG_HASH_ALL sighash
// =============================================================================================

/// The unsigned settle of golden vector 04 (authority settlement, KAS cash): its transaction and
/// the UTXO entries it spends.
fn settle_vector() -> crate::tx::Ipst {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/ipst/04-settle-authority-kas.json"
    ))
    .expect("vector JSON");
    crate::tx::Ipst::from_json(&file["ipst"].to_string()).expect("vector reads")
}

/// A signing set's commitments and its signature shares over one input.
type InputSession = (
    BTreeMap<PartyId, Commitment>,
    BTreeMap<PartyId, SignatureShare>,
);

/// One signing session of `signers` over input `input` through `sign_input`.
fn session_input(
    g: &Group,
    signers: &[PartyId],
    ipst: &crate::tx::Ipst,
    input: usize,
) -> Result<InputSession, ThresholdError> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in signers {
        let (n, c) = commit(g.share(id));
        nonces.insert(id, n);
        commitments.insert(id, c);
    }
    let mut shares = BTreeMap::new();
    for &id in signers {
        let n = nonces.remove(&id).expect("nonces");
        let s = sign_input(
            g.share(id),
            n,
            ipst.transaction(),
            ipst.entries(),
            input,
            &commitments,
        )?;
        shares.insert(id, s);
    }
    Ok((commitments, shares))
}

#[test]
fn sign_input_signs_the_inputs_own_sig_hash_all_sighash() {
    let g = keygen(2, 3);
    let ipst = settle_vector();
    let (tx, entries) = (ipst.transaction(), ipst.entries());
    for input in 0..tx.inputs.len() {
        let (commitments, shares) = session_input(&g, &[1, 3], &ipst, input).expect("signs");
        let auth_sig =
            aggregate_input(&g.key, tx, entries, input, &commitments, &shares).expect("aggregates");
        assert_eq!(auth_sig[64], 0x01, "SIG_HASH_ALL");
        let sighash = crate::tx::sighash(tx, entries, input).expect("sighash");
        crate::tx::verify_schnorr_sig65(&g.key.authority_key(), &sighash, &auth_sig)
            .expect("verifies over the input's SIG_HASH_ALL sighash");
        if let Some(stated) = ipst.slots()[input].sighash() {
            assert_eq!(stated, sighash, "the IPST states the same sighash");
        }
        // The shares are bound to this input: another input's sighash is refused.
        let other = (input + 1) % tx.inputs.len();
        assert_code(
            aggregate_input(&g.key, tx, entries, other, &commitments, &shares),
            "THRESHOLD_SHARE_INVALID",
        );
    }
}

/// Review round 1, item 6: a digest of a weaker sighash type cannot be signed through
/// `sign_input`, which computes the SIG_HASH_ALL sighash itself and takes no digest. Control: the
/// raw-digest `sign` (tests only) does sign that weaker digest.
#[test]
fn a_weaker_sighash_cannot_be_signed_through_sign_input() {
    use kaspa_consensus_core::hashing::sighash::{
        calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
    };
    use kaspa_consensus_core::hashing::sighash_type::{
        SigHashType, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE,
    };
    use kaspa_consensus_core::tx::PopulatedTransaction;

    let g = keygen(2, 3);
    let ipst = settle_vector();
    let (tx, entries) = (ipst.transaction(), ipst.entries());
    let weak_type =
        SigHashType::from_u8(SIG_HASH_NONE.to_u8() | SIG_HASH_ANY_ONE_CAN_PAY.to_u8()).unwrap();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let weak =
        calc_schnorr_signature_hash(&populated, 0, weak_type, &SigHashReusedValuesUnsync::new())
            .as_bytes();
    let all = crate::tx::sighash(tx, entries, 0).expect("sighash");
    assert_ne!(weak, all);

    // Control: the raw-digest path signs the weak digest.
    let raw = sign_with(&g, &[1, 2], &weak).expect("raw sign");
    verify(&g.key.authority_key(), &weak, &raw).expect("valid over the weak digest");

    // Through sign_input the shares are over SIG_HASH_ALL only.
    let (commitments, shares) = session_input(&g, &[1, 2], &ipst, 0).expect("signs");
    assert_code(
        aggregate(&g.key, &weak, &commitments, &shares),
        "THRESHOLD_SHARE_INVALID",
    );
    let auth_sig = aggregate_input(&g.key, tx, entries, 0, &commitments, &shares).expect("ALL");
    let sig64: [u8; 64] = auth_sig[..64].try_into().unwrap();
    verify(&g.key.authority_key(), &all, &sig64).expect("valid over SIG_HASH_ALL");
    assert_code(
        verify(&g.key.authority_key(), &weak, &sig64),
        "THRESHOLD_SIGNATURE_INVALID",
    );
}

#[test]
fn sign_input_and_aggregate_input_refuse_an_input_outside_the_transaction() {
    let g = keygen(2, 3);
    let ipst = settle_vector();
    let (tx, entries) = (ipst.transaction(), ipst.entries());
    let n = tx.inputs.len();
    let (commitments, shares) = session_input(&g, &[1, 2], &ipst, 0).expect("control");
    assert!(aggregate_input(&g.key, tx, entries, 0, &commitments, &shares).is_ok());
    assert_code(session_input(&g, &[1, 2], &ipst, n), "THRESHOLD_INPUT");
    assert_code(
        aggregate_input(&g.key, tx, entries, n, &commitments, &shares),
        "THRESHOLD_INPUT",
    );
    // Entries that do not match the inputs one for one.
    let short = &entries[..n - 1];
    let (n1, _) = commit(g.share(1));
    assert_code(
        sign_input(g.share(1), n1, tx, short, 0, &commitments),
        "THRESHOLD_INPUT",
    );
    assert_code(
        aggregate_input(&g.key, tx, short, 0, &commitments, &shares),
        "THRESHOLD_INPUT",
    );
}

// =============================================================================================
// Codes, Debug output, erasure
// =============================================================================================

#[test]
fn threshold_error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; this list may only grow at the end.
    assert_eq!(
        THRESHOLD_ERROR_CODES,
        [
            "THRESHOLD_PARAMS",
            "THRESHOLD_PARTY",
            "THRESHOLD_DKG_PACKAGES",
            "THRESHOLD_DKG_CULPRIT",
            "THRESHOLD_TOO_FEW_SIGNERS",
            "THRESHOLD_SIGNER_NOT_IN_SET",
            "THRESHOLD_SHARES_MISMATCH",
            "THRESHOLD_SHARE_INVALID",
            "THRESHOLD_KEY_INVALID",
            "THRESHOLD_SIGNATURE_INVALID",
            "THRESHOLD_REFUSED",
            "THRESHOLD_ENCODING",
            "THRESHOLD_INPUT",
        ]
    );
    let all = [
        ThresholdError::Params {
            threshold: 1,
            parties: 3,
        },
        ThresholdError::Party { id: 4, parties: 3 },
        ThresholdError::DkgPackages {
            round: 2,
            missing: vec![3],
            unexpected: vec![],
        },
        ThresholdError::DkgCulprit {
            round: 3,
            culprit: None,
        },
        ThresholdError::TooFewSigners {
            signers: 1,
            threshold: 2,
        },
        ThresholdError::SignerNotInSet { id: 1 },
        ThresholdError::SharesMismatch {
            missing: vec![],
            unexpected: vec![3],
        },
        ThresholdError::ShareInvalid { culprits: vec![2] },
        ThresholdError::KeyInvalid,
        ThresholdError::SignatureInvalid,
        ThresholdError::Refused { reason: "r".into() },
        ThresholdError::Encoding { reason: "e".into() },
        ThresholdError::Input { input: 9 },
    ];
    let codes: Vec<&str> = all.iter().map(ThresholdError::code).collect();
    assert_eq!(codes, THRESHOLD_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()));
    }
    for c in THRESHOLD_ERROR_CODES {
        assert!(!crate::terms::TERMS_ERROR_CODES.contains(&c));
        assert!(!crate::template::TEMPLATE_ERROR_CODES.contains(&c));
    }
}

#[test]
fn debug_output_names_the_party_only() {
    let s = shape(2, 3);
    let (secret, package) = dkg_round1(s, 1).expect("round 1");
    assert_eq!(
        format!("{secret:?}"),
        "DkgRound1Secret { shape: GroupShape { threshold: 2, parties: 3 }, id: 1, .. }"
    );
    assert_eq!(format!("{package:?}"), "DkgRound1Package { .. }");

    let g = keygen(2, 3);
    let share = g.share(2);
    assert_eq!(
        format!("{share:?}"),
        format!(
            "KeyShare {{ shape: GroupShape {{ threshold: 2, parties: 3 }}, id: 2, \
             authority_key: \"{}\", .. }}",
            hex(&g.key.authority_key())
        )
    );
    let (nonces, _) = commit(share);
    assert_eq!(format!("{nonces:?}"), "SigningNonces { id: 2, .. }");

    let (secrets, r1) = round1_all(s);
    let (secrets, mut sent) = round2_all(secrets, &r1);
    assert_eq!(
        format!("{:?}", secrets[0]),
        "DkgRound2Secret { shape: GroupShape { threshold: 2, parties: 3 }, id: 1, .. }"
    );
    let received = inbox(&mut sent, 1);
    assert_eq!(format!("{:?}", received[&2]), "DkgRound2Package { .. }");
}

/// Every FROST type that holds secret material inside this module's wrappers erases itself on
/// drop. Fails to compile if a FROST upgrade drops that guarantee.
#[test]
fn secret_types_erase_on_drop() {
    fn erased_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    erased_on_drop::<frost::keys::KeyPackage>();
    erased_on_drop::<frost::round1::SigningNonces>();
    erased_on_drop::<dkg::round1::SecretPackage>();
    erased_on_drop::<dkg::round2::SecretPackage>();
    erased_on_drop::<dkg::round2::Package>();
}

/// Regression, fuzz target threshold_public (I14): the FROST decoder reads a point prefix of 5
/// as a parity, so a round-1 package with that prefix decoded and re-encoded to different bytes.
/// Every public point decoder now refuses a prefix other than 2 or 3 as THRESHOLD_ENCODING.
#[test]
fn public_encodings_refuse_a_point_prefix_other_than_2_or_3() {
    let s = shape(2, 3);
    let (_secret, package) = dkg_round1(s, 1).expect("round 1");
    let good = package.to_bytes().expect("encodes");
    assert_eq!(
        DkgRound1Package::from_bytes(&good)
            .expect("control")
            .to_bytes()
            .expect("re-encodes"),
        good
    );
    for prefix in [0u8, 1, 4, 5, 6, 7, 0xff] {
        let mut bad = good.clone();
        bad[2] = prefix;
        assert_code(DkgRound1Package::from_bytes(&bad), "THRESHOLD_ENCODING");
    }
    let group = keygen(2, 3);
    let key = group.key.to_bytes().expect("encodes");
    assert!(GroupKey::from_bytes(&key).is_ok());
    for at in [4, 4 + 33] {
        let mut bad = key.clone();
        bad[at] = 5;
        assert_code(GroupKey::from_bytes(&bad), "THRESHOLD_ENCODING");
    }
    let (_nonces, commit) = commit(group.share(1));
    let c = commit.to_bytes().expect("encodes");
    assert!(Commitment::from_bytes(&c).is_ok());
    for at in [0, 33] {
        let mut bad = c;
        bad[at] = 5;
        assert_code(Commitment::from_bytes(&bad), "THRESHOLD_ENCODING");
    }
}
