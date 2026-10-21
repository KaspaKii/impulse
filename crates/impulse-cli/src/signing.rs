// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The only code in Impulse that reads a private key or a FROST key share. One entry point,
//! [`sign`], for two kinds of request:
//! - [`SignRequest`]: it reads the key file the user named, signs one 32-byte digest, overwrites
//!   the key pair and returns the 65-byte signature (64-byte BIP-340 Schnorr signature, then the
//!   `SIG_HASH_ALL` byte), the form the ImpulseVault `sig` argument takes (spec/CLI.md, "Key file
//!   and the signing module").
//! - [`FrostSignRequest`] (I13): it reads the FROST key share file the user named, draws fresh
//!   nonces for every authority input of an IPST, hands their public commitments to the caller's
//!   exchange and receives the other signers' back, then signs every authority input with
//!   `threshold::sign_input`, which computes the input's `SIG_HASH_ALL` sighash itself from the
//!   transaction (spec/THRESHOLD.md, "impulse frost sign"). The share and the nonces never leave
//!   this module's stack; the nonces are consumed by the signing or erased when it is refused.
//!
//! Rules this module keeps: the key file and share file paths are always passed explicitly (no
//! default, no environment variable); key bytes read from a file live only in buffers zeroed on
//! drop, and the key pair is overwritten after the one signature on a best-effort basis
//! (secp256k1 documents `non_secure_erase` as best effort: the compiler may leave copies, and no
//! test can observe it); FROST shares and nonces live in FROST types erased on drop; nothing here
//! prints, logs, writes or sends anything, and no error message carries file content; mainnet is
//! refused unless `--network mainnet` was passed.
//!
//! Follows the split flow of an internal settlement design by the owner (unsigned build,
//! sighash, local sign, verify, assemble): signing is the one step that runs where the key lives.

use crate::error::CliError;
use crate::frost::{
    authority_inputs, check_signers, open_envelope, read_file, threshold_error, CommitmentSet,
    ReadRules, SHARE_TAG,
};
use impulse_core::terms::Network;
use impulse_core::threshold::{
    commit, sign_input, Commitment, KeyShare, PartyId, SignatureShare, ThresholdError,
};
use impulse_core::tx::Ipst;
use secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey, SECP256K1};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// `SIG_HASH_ALL`, the only sighash type Impulse signs with.
pub const SIG_HASH_ALL: u8 = 0x01;

/// Longest valid key file: 64 hex digits and a line feed. One more byte is read to detect excess.
const MAX_KEY_FILE: usize = 65;

/// What to sign and with which key file.
#[derive(Clone, Copy, Debug)]
pub struct SignRequest<'a> {
    /// The key file the user named with `--key-file`.
    pub key_file: &'a Path,
    /// The network the signed transaction or receipt belongs to.
    pub network: Network,
    /// Whether the user passed `--network mainnet`.
    pub mainnet_explicit: bool,
    /// If set, the key's x-only public key must be this one.
    pub expected_signer: Option<[u8; 32]>,
    /// The 32-byte digest (a transaction sighash or a receipt digest).
    pub digest: [u8; 32],
}

/// A signature and the public key that made it. Neither is secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    /// x-only public key of the key file.
    pub signer: [u8; 32],
    /// 64-byte BIP-340 signature followed by `SIG_HASH_ALL`.
    pub signature: [u8; 65],
}

/// One party's FROST signature shares over every authority input of an IPST.
pub struct FrostSignRequest<'a> {
    /// The key share file the user named with `--share-file`.
    pub share_file: &'a Path,
    /// Whether the user passed `--network mainnet`. The network is the IPST terms'.
    pub mainnet_explicit: bool,
    /// The IPST, read (every sighash recomputed) and terms-checked by the caller.
    pub ipst: &'a Ipst,
    /// The signing set the signers agreed, this party included.
    pub signers: &'a BTreeSet<PartyId>,
    /// Called once the share is read and every check has passed, with this party's number and
    /// its commitment for each authority input: publishes them, and returns the commitments of
    /// every other signer of the set for the same inputs.
    pub exchange: &'a Exchange<'a>,
}

/// The exchange of signing round 1: this party's number and commitments out, every other
/// signer's commitments in.
pub type Exchange<'a> =
    dyn Fn(PartyId, &BTreeMap<usize, Commitment>) -> Result<CommitmentSet, CliError> + 'a;

/// This party's signature shares and the commitment set they were made against. Public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostSigned {
    /// This party's number in the group.
    pub party: PartyId,
    /// Every signer's commitment for every authority input, this party's included.
    pub commitments: CommitmentSet,
    /// This party's share of the signature of each authority input.
    pub shares: BTreeMap<usize, SignatureShare>,
}

/// A request the one entry point serves: [`SignRequest`] or [`FrostSignRequest`]. Sealed: only
/// this module implements it, and only [`sign`] runs it.
pub trait Request: sealed::Run {}

mod sealed {
    /// Runs a request. The module is private, so nothing outside `signing` can call it.
    pub trait Run {
        type Output;
        fn run(&self) -> Result<Self::Output, crate::error::CliError>;
    }
}

impl Request for SignRequest<'_> {}

impl sealed::Run for SignRequest<'_> {
    type Output = Signed;
    fn run(&self) -> Result<Signed, CliError> {
        sign_key_file(self)
    }
}

impl Request for FrostSignRequest<'_> {}

impl sealed::Run for FrostSignRequest<'_> {
    type Output = FrostSigned;
    fn run(&self) -> Result<FrostSigned, CliError> {
        sign_frost(self)
    }
}

/// The signing entry point. Checks run in the order of spec/CLI.md (a key file) or
/// spec/THRESHOLD.md (a FROST share); no file is opened unless the network checks pass.
pub fn sign<R: Request>(req: &R) -> Result<R::Output, CliError> {
    sealed::Run::run(req)
}

/// Mainnet only with `--network mainnet`, and that flag only for mainnet.
fn check_network(network: Network, mainnet_explicit: bool) -> Result<(), CliError> {
    match (network, mainnet_explicit) {
        (Network::Mainnet, false) => Err(CliError::new(
            "SIGN_MAINNET_NOT_EXPLICIT",
            "this signs for mainnet; pass --network mainnet to sign it",
        )),
        (Network::Testnet, true) => Err(CliError::new(
            "SIGN_NETWORK_MISMATCH",
            "--network mainnet was passed for a testnet signature",
        )),
        _ => Ok(()),
    }
}

fn sign_key_file(req: &SignRequest) -> Result<Signed, CliError> {
    check_network(req.network, req.mainnet_explicit)?;
    let secret = read_key_file(req.key_file)?;
    let mut keypair = Keypair::from_seckey_slice(SECP256K1, &secret[..]).map_err(|_| {
        CliError::new(
            "SIGN_KEY_INVALID",
            format!(
                "{}: not a valid secp256k1 secret key",
                req.key_file.display()
            ),
        )
    })?;
    drop(secret);
    let result = sign_with(&keypair, req);
    keypair.non_secure_erase();
    result
}

fn sign_with(keypair: &Keypair, req: &SignRequest) -> Result<Signed, CliError> {
    let (xonly, _) = keypair.x_only_public_key();
    let signer = xonly.serialize();
    if let Some(expected) = req.expected_signer {
        if expected != signer {
            return Err(CliError::new(
                "SIGN_KEY_NOT_EXPECTED",
                format!(
                    "{}: the key's public key is {}, the signature is expected from {}",
                    req.key_file.display(),
                    crate::json::hex(&signer),
                    crate::json::hex(&expected)
                ),
            ));
        }
    }
    let msg = Message::from_digest(req.digest);
    let sig = keypair.sign_schnorr(msg);
    let sig64: [u8; 64] = *sig.as_ref();
    #[cfg(test)]
    let sig64 = corrupt::apply(sig64);
    self_check(&signer, &req.digest, &sig64)?;
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig64);
    signature[64] = SIG_HASH_ALL;
    Ok(Signed { signer, signature })
}

/// The signature must verify before it leaves this module.
fn self_check(signer: &[u8; 32], digest: &[u8; 32], sig64: &[u8; 64]) -> Result<(), CliError> {
    let failed = || CliError::new("SIGN_SELF_CHECK_FAILED", "the signature does not verify");
    let key = XOnlyPublicKey::from_slice(signer).map_err(|_| failed())?;
    let sig = schnorr::Signature::from_slice(sig64).map_err(|_| failed())?;
    SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(*digest), &key)
        .map_err(|_| failed())
}

const SHARE_FILE: ReadRules = ReadRules {
    unreadable: "FROST_SHARE_FILE_UNREADABLE",
    permissions: Some("FROST_SHARE_FILE_PERMISSIONS"),
    too_long: "FROST_SHARE_FILE_FORMAT",
    limit: 512,
};

/// Reads a key share file: a regular file no group or other may access, `impulse-frost-share-v1:`
/// and the hex of a key share that decodes. The text and the bytes live in buffers zeroed on drop.
fn read_share_file(path: &Path) -> Result<KeyShare, CliError> {
    let text = read_file(path, &SHARE_FILE)?;
    let format = || {
        CliError::new(
            "FROST_SHARE_FILE_FORMAT",
            format!(
                "{}: expected {SHARE_TAG}: and the hex of a key share, with at most one final line feed",
                path.display()
            ),
        )
    };
    let bytes = open_envelope(&text, SHARE_TAG).ok_or_else(format)?;
    KeyShare::from_bytes(&bytes).map_err(|_| format())
}

/// One party's round of FROST signing over the IPST's authority inputs. Order: the network
/// rule, the authority inputs, the share file, the share is the terms' authority, the signing set;
/// then commitments out and in through the caller's exchange, then one share per input.
fn sign_frost(req: &FrostSignRequest) -> Result<FrostSigned, CliError> {
    check_network(req.ipst.terms().terms().network, req.mainnet_explicit)?;
    let (authority, inputs) = authority_inputs(req.ipst)?;
    let share = read_share_file(req.share_file)?;
    if share.authority_key() != authority {
        return Err(CliError::new(
            "FROST_KEY_NOT_AUTHORITY",
            format!(
                "{}: this share is of the group whose authority key is {}, the terms' is {}",
                req.share_file.display(),
                crate::json::hex(&share.authority_key()),
                crate::json::hex(&authority)
            ),
        ));
    }
    check_signers(share.shape(), req.signers)?;
    let me = share.id();
    if !req.signers.contains(&me) {
        return Err(threshold_error(ThresholdError::SignerNotInSet { id: me }));
    }
    let mut nonces = BTreeMap::new();
    let mut mine = BTreeMap::new();
    for &input in &inputs {
        let (n, c) = commit(&share);
        nonces.insert(input, n);
        mine.insert(input, c);
    }
    let mut commitments = (req.exchange)(me, &mine)?;
    let others: BTreeSet<PartyId> = req.signers.iter().copied().filter(|&j| j != me).collect();
    let complete = commitments.keys().copied().collect::<BTreeSet<_>>() == others
        && commitments.values().all(|c| c.keys().eq(inputs.iter()));
    if !complete {
        return Err(CliError::new(
            "FROST_SESSION_MISMATCH",
            "the commitments received are not one per authority input from every other signer",
        ));
    }
    commitments.insert(me, mine);
    let (tx, entries) = (req.ipst.transaction(), req.ipst.entries());
    let mut shares = BTreeMap::new();
    for &input in &inputs {
        let set: BTreeMap<PartyId, Commitment> =
            commitments.iter().map(|(&j, c)| (j, c[&input])).collect();
        let n = nonces.remove(&input).expect("one set of nonces per input");
        let s = sign_input(&share, n, tx, entries, input, &set).map_err(threshold_error)?;
        shares.insert(input, s);
    }
    Ok(FrostSigned {
        party: me,
        commitments,
        shares,
    })
}

/// Test hook: corrupts the next signature before the self-check, so the self-check refusal is
/// driven through [`sign`] itself. Compiled only into tests; per test thread.
#[cfg(test)]
mod corrupt {
    use std::cell::Cell;

    thread_local! {
        static NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn arm() {
        NEXT.with(|n| n.set(true));
    }

    pub(super) fn apply(mut sig: [u8; 64]) -> [u8; 64] {
        if NEXT.with(|n| n.replace(false)) {
            sig[10] ^= 1;
        }
        sig
    }
}

/// Reads the 32-byte secret from a key file into a buffer zeroed on drop.
fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let shown = path.display();
    let unreadable = |why: String| CliError::new("SIGN_KEY_FILE_UNREADABLE", why);
    let file = std::fs::File::open(path).map_err(|e| unreadable(format!("{shown}: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| unreadable(format!("{shown}: {e}")))?;
    if !meta.is_file() {
        return Err(unreadable(format!("{shown}: not a regular file")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::new(
                "SIGN_KEY_FILE_PERMISSIONS",
                format!(
                    "{shown}: mode {:o} lets group or others access the key; run chmod 600 on it",
                    mode & 0o777
                ),
            ));
        }
    }
    let mut buf = Zeroizing::new([0u8; MAX_KEY_FILE + 1]);
    let mut len = 0;
    let mut reader = file.take((MAX_KEY_FILE + 1) as u64);
    loop {
        let n = reader
            .read(&mut buf[len..])
            .map_err(|e| unreadable(format!("{shown}: {e}")))?;
        if n == 0 {
            break;
        }
        len += n;
        if len == buf.len() {
            break;
        }
    }
    let format = || {
        CliError::new(
            "SIGN_KEY_FILE_FORMAT",
            format!("{shown}: expected 64 hexadecimal digits and at most one final line feed"),
        )
    };
    let digits = match len {
        64 => &buf[..64],
        65 if buf[64] == b'\n' => &buf[..64],
        _ => return Err(format()),
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    for (i, out) in secret.iter_mut().enumerate() {
        let hi = nibble(digits[2 * i]).ok_or_else(format)?;
        let lo = nibble(digits[2 * i + 1]).ok_or_else(format)?;
        *out = (hi << 4) | lo;
    }
    Ok(secret)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Throwaway key files for tests: a fresh random key written at runtime into a temporary
/// directory, removed with it. No key literal exists anywhere in the source.
#[cfg(test)]
pub(crate) mod throwaway {
    use crate::testutil::TempDir;
    use secp256k1::{SecretKey, SECP256K1};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    pub(crate) struct KeyFile {
        pub(crate) path: PathBuf,
        pub(crate) signer: [u8; 32],
        /// The file content, for the tests that check it never appears in output.
        pub(crate) content: Zeroizing<String>,
        _dir: TempDir,
    }

    /// A random key written as lowercase hex with a final line feed, mode 0600.
    pub(crate) fn key_file() -> KeyFile {
        let mut sk = SecretKey::new(&mut rand::thread_rng());
        let content = Zeroizing::new(format!("{}\n", crate::json::hex(&sk.secret_bytes())));
        let signer = sk.x_only_public_key(SECP256K1).0.serialize();
        sk.non_secure_erase();
        let dir = TempDir::new();
        let path = dir.path().join("throwaway.key");
        write_file(&path, content.as_bytes(), 0o600);
        KeyFile {
            path,
            signer,
            content,
            _dir: dir,
        }
    }

    pub(crate) fn write_file(path: &std::path::Path, bytes: &[u8], mode: u32) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::throwaway::{key_file, write_file};
    use super::*;
    use crate::testutil::TempDir;

    fn req(path: &Path, network: Network, explicit: bool) -> SignRequest<'_> {
        SignRequest {
            key_file: path,
            network,
            mainnet_explicit: explicit,
            expected_signer: None,
            digest: [7u8; 32],
        }
    }

    fn verifies(s: &Signed, digest: &[u8; 32]) -> bool {
        let sig: [u8; 64] = s.signature[..64].try_into().unwrap();
        self_check(&s.signer, digest, &sig).is_ok()
    }

    #[test]
    fn signs_a_testnet_digest_with_a_throwaway_key() {
        let k = key_file();
        let s = sign(&req(&k.path, Network::Testnet, false)).unwrap();
        assert_eq!(s.signer, k.signer);
        assert_eq!(s.signature[64], 0x01, "SIG_HASH_ALL is 0x01");
        assert_eq!(SIG_HASH_ALL, 0x01);
        assert!(verifies(&s, &[7u8; 32]));
        assert!(!verifies(&s, &[8u8; 32]), "bound to the digest");
    }

    #[test]
    fn mainnet_needs_the_explicit_flag() {
        let k = key_file();
        assert_eq!(
            sign(&req(&k.path, Network::Mainnet, false))
                .unwrap_err()
                .code(),
            "SIGN_MAINNET_NOT_EXPLICIT"
        );
        let s = sign(&req(&k.path, Network::Mainnet, true)).unwrap();
        assert!(verifies(&s, &[7u8; 32]), "control");
        assert_eq!(
            sign(&req(&k.path, Network::Testnet, true))
                .unwrap_err()
                .code(),
            "SIGN_NETWORK_MISMATCH"
        );
    }

    #[test]
    fn the_network_is_checked_before_the_file_is_opened() {
        let missing = Path::new("/nonexistent/impulse/key");
        assert_eq!(
            sign(&req(missing, Network::Mainnet, false))
                .unwrap_err()
                .code(),
            "SIGN_MAINNET_NOT_EXPLICIT"
        );
        assert_eq!(
            sign(&req(missing, Network::Testnet, false))
                .unwrap_err()
                .code(),
            "SIGN_KEY_FILE_UNREADABLE"
        );
    }

    #[test]
    fn only_a_regular_file_is_a_key_file() {
        let k = key_file();
        assert!(
            sign(&req(&k.path, Network::Testnet, false)).is_ok(),
            "control"
        );
        // A directory, and a character device that reads as empty with mode 0666: without the
        // regular-file check the first fails on read and the second on its permissions.
        let dir = TempDir::new();
        for path in [dir.path(), Path::new("/dev/null")] {
            let e = sign(&req(path, Network::Testnet, false)).unwrap_err();
            assert_eq!(e.code(), "SIGN_KEY_FILE_UNREADABLE", "{}", path.display());
            assert!(e.to_string().ends_with(": not a regular file"), "{e}");
        }
    }

    #[test]
    fn group_or_other_access_is_refused() {
        let k = key_file();
        let content = k.content.as_bytes();
        let dir = TempDir::new();
        for (i, mode) in [0o640, 0o604, 0o610, 0o601, 0o660].into_iter().enumerate() {
            let p = dir.path().join(format!("k{i}"));
            write_file(&p, content, mode);
            // create_new honours the umask; set the mode exactly.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                sign(&req(&p, Network::Testnet, false)).unwrap_err().code(),
                "SIGN_KEY_FILE_PERMISSIONS",
                "{mode:o}"
            );
        }
        let p = dir.path().join("ok");
        write_file(&p, content, 0o400);
        assert!(
            sign(&req(&p, Network::Testnet, false)).is_ok(),
            "control 0400"
        );
    }

    #[test]
    fn only_64_hex_digits_and_one_line_feed_are_accepted() {
        let k = key_file();
        let hex64 = k.content.trim_end().to_string();
        let dir = TempDir::new();
        let accepted = [hex64.clone(), format!("{hex64}\n"), hex64.to_uppercase()];
        for (i, text) in accepted.iter().enumerate() {
            let p = dir.path().join(format!("good{i}"));
            write_file(&p, text.as_bytes(), 0o600);
            let s = sign(&req(&p, Network::Testnet, false)).unwrap();
            assert_eq!(s.signer, k.signer, "case {i}");
        }
        let refused = [
            String::new(),
            hex64[..63].to_string(),
            format!("{hex64}0"),
            format!("{hex64}\n\n"),
            format!("{hex64}\r\n"),
            format!("{hex64} "),
            format!(" {}", &hex64[..63]),
            format!("0x{}", &hex64[..62]),
            format!("{}g", &hex64[..63]),
            "a".repeat(10_000),
        ];
        for (i, text) in refused.iter().enumerate() {
            let p = dir.path().join(format!("bad{i}"));
            write_file(&p, text.as_bytes(), 0o600);
            let e = sign(&req(&p, Network::Testnet, false)).unwrap_err();
            assert_eq!(e.code(), "SIGN_KEY_FILE_FORMAT", "case {i}");
        }
    }

    #[test]
    fn a_value_outside_the_curve_order_is_refused() {
        let dir = TempDir::new();
        let p = dir.path().join("zero");
        write_file(&p, "0".repeat(64).as_bytes(), 0o600);
        assert_eq!(
            sign(&req(&p, Network::Testnet, false)).unwrap_err().code(),
            "SIGN_KEY_INVALID"
        );
        let p = dir.path().join("max");
        write_file(&p, "f".repeat(64).as_bytes(), 0o600);
        assert_eq!(
            sign(&req(&p, Network::Testnet, false)).unwrap_err().code(),
            "SIGN_KEY_INVALID"
        );
    }

    #[test]
    fn the_expected_signer_is_enforced() {
        let k = key_file();
        let mut r = req(&k.path, Network::Testnet, false);
        r.expected_signer = Some(k.signer);
        assert!(sign(&r).is_ok(), "control");
        let other = key_file();
        r.expected_signer = Some(other.signer);
        assert_eq!(sign(&r).unwrap_err().code(), "SIGN_KEY_NOT_EXPECTED");
    }

    #[test]
    fn sign_refuses_a_signature_that_does_not_verify() {
        let k = key_file();
        assert!(
            sign(&req(&k.path, Network::Testnet, false)).is_ok(),
            "control"
        );
        corrupt::arm();
        assert_eq!(
            sign(&req(&k.path, Network::Testnet, false))
                .unwrap_err()
                .code(),
            "SIGN_SELF_CHECK_FAILED"
        );
        assert!(
            sign(&req(&k.path, Network::Testnet, false)).is_ok(),
            "hook disarmed"
        );
    }

    #[test]
    fn the_self_check_refuses_a_bad_signature() {
        let k = key_file();
        let s = sign(&req(&k.path, Network::Testnet, false)).unwrap();
        let mut sig: [u8; 64] = s.signature[..64].try_into().unwrap();
        assert!(self_check(&s.signer, &[7u8; 32], &sig).is_ok(), "control");
        sig[10] ^= 1;
        assert_eq!(
            self_check(&s.signer, &[7u8; 32], &sig).unwrap_err().code(),
            "SIGN_SELF_CHECK_FAILED"
        );
    }

    #[test]
    fn no_error_message_carries_the_key() {
        let k = key_file();
        let hex64 = k.content.trim_end().to_string();
        let dir = TempDir::new();
        let loose = dir.path().join("loose");
        write_file(&loose, k.content.as_bytes(), 0o600);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        let long = dir.path().join("long");
        write_file(&long, format!("{hex64}{hex64}").as_bytes(), 0o600);
        let mut wrong_signer = req(&k.path, Network::Testnet, false);
        wrong_signer.expected_signer = Some([2u8; 32]);
        let errors = [
            sign(&req(&loose, Network::Testnet, false)).unwrap_err(),
            sign(&req(&long, Network::Testnet, false)).unwrap_err(),
            sign(&wrong_signer).unwrap_err(),
            sign(&req(&k.path, Network::Mainnet, false)).unwrap_err(),
        ];
        for e in errors {
            let text = format!("{e} {e:?}");
            assert!(!text.contains(&hex64), "{}", e.code());
            assert!(!text.to_uppercase().contains(&hex64.to_uppercase()));
        }
    }

    #[test]
    fn signing_has_one_entry_point_and_no_other_module_touches_keys() {
        let this = include_str!("signing.rs");
        assert_eq!(this.matches("\npub fn ").count(), 1, "one public function");
        assert!(this.contains("\npub fn sign<R: Request>("));
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(src).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap() == "signing.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for word in [
                "SecretKey",
                "Keypair",
                "from_seckey",
                "secret_bytes",
                "sign_schnorr",
            ] {
                assert!(!text.contains(word), "{} mentions {word}", path.display());
            }
        }
    }
}
