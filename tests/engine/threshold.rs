// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I13: a settlement authority that is a FROST 2-of-3 group, in the real engine. The vault's
//! `authority_key` is the group's x-only aggregate key from `impulse_core::threshold`; the
//! canonical settle transaction comes from the harness unchanged, and each vault input's authSig
//! is replaced by a FROST signature over that input's SIG_HASH_ALL Schnorr sighash. No contract
//! change: the vault checks one key and one signature ([S6]).
//!
//! Every 2-of-3 signing set settles. Each lone party's share, aggregated as if it were the whole
//! signature, is refused by [S6] at every vault input; a 2-of-3 signature of another group is
//! refused by [S6]. Each engine refusal sits beside an accepted 2-of-3 settle on the same world,
//! and fails with VerifyError exactly (OpCheckSigVerify on a bad signature).
//!
//! Keys: every share, key generation secret and nonce comes from the OS RNG at runtime, lives in
//! memory only, is never written or printed, and is erased on drop. No key material is stored in
//! this file.

mod harness;
use harness::*;

use std::collections::BTreeMap;

use impulse_core::threshold::{
    aggregate, commit, dkg_round1, dkg_round2, dkg_round3, sign, verify, Commitment,
    DkgRound1Package, DkgRound2Package, GroupKey, GroupShape, KeyShare, PartyId, SignatureShare,
    ThresholdError,
};
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry};
use kaspa_txscript_errors::TxScriptError;
use silverscript_abi::ArtifactValue;

// =============================================================================================
// A FROST group, key generation run in process (each party's rounds kept apart)
// =============================================================================================

struct Group {
    shares: Vec<KeyShare>,
    key: GroupKey,
}

impl Group {
    fn share(&self, id: PartyId) -> &KeyShare {
        &self.shares[id as usize - 1]
    }
}

fn others(
    all: &BTreeMap<PartyId, DkgRound1Package>,
    me: PartyId,
) -> BTreeMap<PartyId, DkgRound1Package> {
    all.iter()
        .filter(|(&id, _)| id != me)
        .map(|(&id, p)| (id, p.clone()))
        .collect()
}

/// FROST distributed key generation for a 2-of-3 group: no dealer, each party keeps its own
/// secrets, the packages move between parties as they would as files.
fn keygen_2_of_3() -> Group {
    let shape = GroupShape::new(2, 3).expect("2 of 3");
    let mut r1_secrets = Vec::new();
    let mut r1 = BTreeMap::new();
    for id in 1..=3 {
        let (secret, package) = dkg_round1(shape, id).expect("round 1");
        r1_secrets.push((id, secret));
        r1.insert(id, package);
    }
    let mut r2_secrets = Vec::new();
    let mut sent: BTreeMap<PartyId, BTreeMap<PartyId, DkgRound2Package>> = BTreeMap::new();
    for (id, secret) in r1_secrets {
        let (secret, packages) = dkg_round2(secret, &others(&r1, id)).expect("round 2");
        r2_secrets.push((id, secret));
        sent.insert(id, packages);
    }
    let mut shares = Vec::new();
    let mut keys = Vec::new();
    for (id, secret) in r2_secrets {
        let inbox: BTreeMap<PartyId, DkgRound2Package> = sent
            .iter_mut()
            .filter_map(|(&from, to)| to.remove(&id).map(|p| (from, p)))
            .collect();
        let (share, key) = dkg_round3(secret, &others(&r1, id), &inbox).expect("round 3");
        shares.push(share);
        keys.push(key);
    }
    assert!(keys.windows(2).all(|k| k[0] == k[1]), "one group key");
    Group {
        shares,
        key: keys.remove(0),
    }
}

/// A signing set's commitments and its signature shares, keyed by party.
type Signed = (
    BTreeMap<PartyId, Commitment>,
    BTreeMap<PartyId, SignatureShare>,
);

/// One signing session of `signers` over `sighash`.
fn session(g: &Group, signers: &[PartyId], sighash: &[u8; 32]) -> Result<Signed, ThresholdError> {
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
        shares.insert(id, sign(g.share(id), n, sighash, &set)?);
    }
    Ok((set, shares))
}

/// The 65-byte authSig a FROST group of `signers` makes over `sighash`.
fn frost_auth_sig(
    g: &Group,
    signers: &[PartyId],
    sighash: &[u8; 32],
) -> Result<Vec<u8>, ThresholdError> {
    let (set, shares) = session(g, signers, sighash)?;
    let sig = aggregate(&g.key, sighash, &set, &shares)?;
    let mut out = sig.to_vec();
    out.push(SIG_HASH_ALL.to_u8());
    Ok(out)
}

/// Party `lone`'s share aggregated alone as if it were the whole signature of the set
/// {lone, partner}: the set's group commitment R (public, from the commitments; read here off the
/// honest aggregate of the same session) with z_lone where z_lone + z_partner belongs.
fn lone_share_auth_sig(g: &Group, lone: PartyId, partner: PartyId, sighash: &[u8; 32]) -> Vec<u8> {
    let (set, shares) = session(g, &[lone, partner], sighash).expect("session");
    let full = aggregate(&g.key, sighash, &set, &shares).expect("2 of 3");
    let mut out = full[..32].to_vec();
    out.extend_from_slice(&shares[&lone].to_bytes());
    out.push(SIG_HASH_ALL.to_u8());
    out
}

/// [S6] refuses a bad authority signature with OpCheckSigVerify: VerifyError, nothing else.
fn assert_verify_error(run: &Run, label: &str) {
    assert!(
        matches!(run.result, Err(TxScriptError::VerifyError)),
        "{label}: expected VerifyError, got {:?}",
        run.result
    );
}

// =============================================================================================
// The canonical settle with a FROST authority
// =============================================================================================

/// The world for `cash` with an authority, whose authority_key is the group's aggregate key.
fn frost_world(cash: u8, g: &Group) -> World {
    World::with(Mode::new(true, cash, REVOCABLE), |t, _| {
        t.authority_key = g.key.authority_key()
    })
}

fn sighash(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> [u8; 32] {
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused).as_bytes()
}

/// The canonical settle of `w`, every vault input's authSig made by `auth_sig` over that input's
/// sighash (sighashes do not commit to signature scripts, so replacing them after assembly is
/// exact). Returns the transaction, its UTXO entries and the vault input indexes.
fn settle_signed_by(
    w: &World,
    auth_sig: impl Fn(&[u8; 32]) -> Vec<u8>,
) -> (Transaction, Vec<UtxoEntry>, Vec<usize>) {
    let spec = w.settle();
    let (mut tx, entries) = spec.build(w);
    let unsigned = tx.clone();
    let mut vaults = Vec::new();
    for (n, input) in spec.inputs.iter().enumerate() {
        if let Spend::Settle { vault, .. } = &input.spend {
            let sig = auth_sig(&sighash(&unsigned, &entries, n));
            tx.inputs[n].signature_script =
                vault.entry_sigscript("settle", &[ArtifactValue::Bytes(sig)]);
            vaults.push(n);
        }
    }
    tx.finalize();
    (tx, entries, vaults)
}

fn assert_settles(w: &World, signers: &[PartyId], g: &Group, label: &str) {
    let (tx, entries, vaults) = settle_signed_by(w, |h| {
        frost_auth_sig(g, signers, h).expect("2-of-3 signature")
    });
    assert!(!vaults.is_empty());
    for n in 0..tx.inputs.len() {
        assert_accepted(&execute(&tx, &entries, n), &format!("{label}: input {n}"));
    }
}

// =============================================================================================
// 2 of 3 settles
// =============================================================================================

#[test]
fn frost_2_of_3_authority_settles_kas_cash() {
    let g = keygen_2_of_3();
    let w = frost_world(CASH_KAS, &g);
    for signers in [[1, 2], [1, 3], [2, 3]] {
        assert_settles(&w, &signers, &g, &format!("KAS cash, signers {signers:?}"));
    }
}

#[test]
fn frost_2_of_3_authority_settles_kcc20_cash() {
    let g = keygen_2_of_3();
    let w = frost_world(CASH_KCC20, &g);
    for signers in [[1, 2], [1, 3], [2, 3]] {
        assert_settles(
            &w,
            &signers,
            &g,
            &format!("KCC-20 cash, signers {signers:?}"),
        );
    }
}

#[test]
fn frost_2_of_3_authority_settles_external_cash() {
    let g = keygen_2_of_3();
    let w = frost_world(CASH_EXTERNAL, &g);
    for signers in [[1, 2], [1, 3], [2, 3]] {
        assert_settles(
            &w,
            &signers,
            &g,
            &format!("external cash, signers {signers:?}"),
        );
    }
}

// =============================================================================================
// 1 of 3 does not
// =============================================================================================

/// Library only, no engine run: a lone signer gets no signature from the library, its signing
/// round is refused with one commitment in the set (aggregating one is refused too, in
/// impulse-core's threshold tests). Control: two signers over the same sighash. The engine-level
/// 1-of-3 refusal is `s6_frost_lone_share_cannot_settle`.
#[test]
fn frost_library_gives_one_of_three_no_signature() {
    let g = keygen_2_of_3();
    let w = frost_world(CASH_KAS, &g);
    let (tx, entries, _) = settle_signed_by(&w, |_| vec![0; 65]);
    let h = sighash(&tx, &entries, 0);
    assert!(frost_auth_sig(&g, &[1, 2], &h).is_ok(), "control");
    for lone in 1..=3 {
        let err = frost_auth_sig(&g, &[lone], &h).expect_err("one of three");
        assert_eq!(err.code(), "THRESHOLD_TOO_FEW_SIGNERS", "{err}");
    }
}

/// 1 of 3 in the engine: each lone party's share (parties 1, 2 and 3, each taken from a session
/// with one partner) at every vault input of the settle, for KAS, KCC-20 and external cash, is
/// refused by [S6] with VerifyError. Control in the same test and world: the 2-of-3 signature of
/// that party and its partner settles.
#[test]
fn s6_frost_lone_share_cannot_settle() {
    let g = keygen_2_of_3();
    for cash in [CASH_KAS, CASH_KCC20, CASH_EXTERNAL] {
        let w = frost_world(cash, &g);
        for (lone, partner) in [(1, 2), (2, 3), (3, 1)] {
            let label = format!("cash kind {cash}, lone party {lone}");
            assert_settles(&w, &[lone, partner], &g, &format!("{label}: control"));
            let (tx, entries, vaults) = settle_signed_by(&w, |h| {
                let sig = lone_share_auth_sig(&g, lone, partner, h);
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(&sig[..64]);
                assert_eq!(
                    verify(&g.key.authority_key(), h, &bytes)
                        .expect_err("lone share")
                        .code(),
                    "THRESHOLD_SIGNATURE_INVALID"
                );
                sig
            });
            assert!(!vaults.is_empty());
            for n in vaults {
                assert_verify_error(
                    &execute(&tx, &entries, n),
                    &format!("{label}: lone share at vault input {n}"),
                );
            }
        }
    }
}

/// A valid 2-of-3 signature of another FROST group does not settle: the vault binds the
/// aggregate key in its terms, not the act of reaching a threshold.
#[test]
fn s6_frost_another_groups_signature_cannot_settle() {
    let g = keygen_2_of_3();
    let other = keygen_2_of_3();
    let w = frost_world(CASH_KAS, &g);
    assert_settles(&w, &[2, 3], &g, "control");
    let (tx, entries, vaults) = settle_signed_by(&w, |h| {
        frost_auth_sig(&other, &[2, 3], h).expect("the other group's 2-of-3 signature")
    });
    assert!(!vaults.is_empty());
    for n in vaults {
        assert_verify_error(
            &execute(&tx, &entries, n),
            &format!("another group's signature at vault input {n}"),
        );
    }
}
