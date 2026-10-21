// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! `impulse frost` in process (I13 phase 2): key generation, signing and aggregation through the
//! commands and through `signing::sign`, every refusal asserted by code beside an accepted
//! control, and the source guards that keep FROST secrets in `keygen` and `signing`. The other
//! parties of a group are played here with `impulse_core::threshold` in memory.
//!
//! Test-only (compiled under `cfg(test)`), and the one file outside `keygen` and `signing` the
//! source guard lets name FROST secret types. Shares are generated at runtime; share files exist
//! only in temporary directories removed on drop; this file holds no share or key literal.

use crate::cli::{Cli, Command, Ctx, Env, NetworkArg};
use crate::error::CliError;
use crate::frost::{
    authority_inputs, check_kind, check_signers, commit_body, commitment_set_digest, envelope,
    open_envelope, parse_signers, public_file, read_commit, read_file, read_sigshare,
    session_digest, session_id, sigshare_body, CommitmentSet, Console, COMMITMENT_SET_DOMAIN,
    COMMIT_TAG, FROST_ERROR_CODES, GROUP_TAG, PUBLIC_FILE, ROUND1_TAG, ROUND2_TAG, SESSION_DOMAIN,
    SHARE_TAG, SIGSHARE_TAG,
};
use crate::json::hex;
use crate::node::fake::FakeNode;
use crate::node::Node;
use crate::signing::{self, FrostSignRequest};
use crate::summary::kas_address;
use crate::testutil::TempDir;
use crate::world;
use clap::Parser;
use impulse_core::template::LegIndex;
use impulse_core::terms::Network;
use impulse_core::threshold::{
    commit, dkg_round1, dkg_round1_digest, dkg_round2, dkg_round3, sign_input, verify, Commitment,
    DkgRound1Package, DkgRound1Secret, DkgRound2Package, DkgRound2Secret, GroupKey, GroupShape,
    KeyShare, PartyId, SignatureShare, SigningNonces,
};
use impulse_core::tx::{self, Ipst, IpstKind, RefundSigner};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

// =============================================================================================
// Harness: a scripted console, the command runner, groups played in memory
// =============================================================================================

type OnAsk<'a> = Box<dyn FnMut(&str, &[String]) -> Option<String> + 'a>;

/// A console whose answers come from a closure, given the prompt and every line said so far.
/// No answer is the end of input.
struct Script<'a> {
    said: RefCell<Vec<String>>,
    on_ask: RefCell<OnAsk<'a>>,
}

impl<'a> Script<'a> {
    fn new(f: impl FnMut(&str, &[String]) -> Option<String> + 'a) -> Self {
        Self {
            said: RefCell::new(vec![]),
            on_ask: RefCell::new(Box::new(f)),
        }
    }

    fn silent() -> Self {
        Self::new(|_, _| None)
    }

    fn said(&self) -> Vec<String> {
        self.said.borrow().clone()
    }
}

impl Console for Script<'_> {
    fn say(&self, line: &str) -> Result<(), CliError> {
        self.said.borrow_mut().push(line.to_string());
        Ok(())
    }

    fn ask(&self, prompt: &str) -> Result<String, CliError> {
        self.said.borrow_mut().push(format!("> {prompt}"));
        let said = self.said();
        (self.on_ask.borrow_mut())(prompt, &said).ok_or_else(|| {
            CliError::new(
                "FROST_ABORTED",
                "the script ended before this step completed",
            )
        })
    }
}

/// Runs `impulse <args>` (a frost command) through `console`, offline.
fn exec(args: &[&str], console: &dyn Console) -> Result<(), CliError> {
    exec_on(args, console, None)
}

/// A node that answers: `node` makes it. None: every connection fails (offline).
type MakeNode = Option<fn() -> FakeNode>;

/// A synced mainnet node at the world's DAA score.
fn mainnet_node() -> FakeNode {
    let mut n = FakeNode::mainnet();
    n.dag.virtual_daa = world::NOW;
    n
}

/// Runs `impulse <args>` (a frost command) through `console`, with the node `node` makes.
fn exec_on(args: &[&str], console: &dyn Console, node: MakeNode) -> Result<(), CliError> {
    let mut argv = vec!["impulse"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("arguments parse");
    let connect = |_: &str, _: Network| -> Result<Box<dyn Node>, CliError> {
        match node {
            Some(make) => Ok(Box::new(make())),
            None => Err(CliError::new("CLI_NODE_UNREACHABLE", "offline test")),
        }
    };
    let env = Env {
        max_value: None,
        connect: &connect,
    };
    let mainnet = cli.network == Some(NetworkArg::Mainnet);
    let ctx = Ctx {
        network: if mainnet {
            Network::Mainnet
        } else {
            Network::Testnet
        },
        mainnet_explicit: mainnet,
        env: &env,
    };
    match cli.command {
        Command::Frost(c) => crate::frost::run_with(&ctx, c, console),
        other => panic!("not a frost command: {other:?}"),
    }
}

/// A refused command: its code, after checking that it printed nothing.
fn refuse(args: &[&str]) -> &'static str {
    let console = Script::silent();
    let e = exec(args, &console).expect_err("refused");
    assert_eq!(console.said(), Vec::<String>::new(), "{} printed", e.code());
    e.code()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A group whose every party lives here, in memory.
struct LibGroup {
    shares: BTreeMap<PartyId, KeyShare>,
    key: GroupKey,
}

fn lib_keygen(t: u16, n: u16) -> LibGroup {
    let shape = GroupShape::new(t, n).unwrap();
    let mut secrets = BTreeMap::new();
    let mut r1 = BTreeMap::new();
    for id in 1..=n {
        let (secret, package) = dkg_round1(shape, id).unwrap();
        secrets.insert(id, secret);
        r1.insert(id, package);
    }
    let others = |me: PartyId| -> BTreeMap<PartyId, DkgRound1Package> {
        r1.iter()
            .filter(|(&id, _)| id != me)
            .map(|(&id, p)| (id, p.clone()))
            .collect()
    };
    let mut secrets2 = BTreeMap::new();
    let mut sent: BTreeMap<PartyId, BTreeMap<PartyId, DkgRound2Package>> = BTreeMap::new();
    for (id, secret) in secrets {
        let (secret, packages) = dkg_round2(secret, &others(id)).unwrap();
        secrets2.insert(id, secret);
        sent.insert(id, packages);
    }
    let mut shares = BTreeMap::new();
    let mut keys = vec![];
    for (id, secret) in secrets2 {
        let inbox: BTreeMap<PartyId, DkgRound2Package> = sent
            .iter_mut()
            .filter_map(|(&from, to)| to.remove(&id).map(|p| (from, p)))
            .collect();
        let (share, key) = dkg_round3(secret, &others(id), &inbox).unwrap();
        shares.insert(id, share);
        keys.push(key);
    }
    LibGroup {
        shares,
        key: keys.remove(0),
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write_share(path: &Path, share: &KeyShare) {
    write_mode(
        path,
        &envelope(SHARE_TAG, &share.to_bytes().unwrap()),
        0o600,
    );
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// =============================================================================================
// Codes, files, signers, session
// =============================================================================================

#[test]
fn frost_error_codes_are_frozen() {
    assert_eq!(
        FROST_ERROR_CODES,
        [
            "FROST_SHARE_FILE_UNREADABLE",
            "FROST_SHARE_FILE_PERMISSIONS",
            "FROST_SHARE_FILE_FORMAT",
            "FROST_FILE_MALFORMED",
            "FROST_FILE_PERMISSIONS",
            "FROST_SESSION_MISMATCH",
            "FROST_NOT_CONFIRMED",
            "FROST_ABORTED",
            "FROST_SIGNERS_INVALID",
            "FROST_NO_AUTHORITY_INPUT",
            "FROST_KEY_NOT_AUTHORITY",
            "FROST_AUTHORITY_INPUT_NOT_VAULT",
            "FROST_ROUND2_NOT_REMOVED",
            "FROST_TERMS_NOT_AGREED",
        ]
    );
    let spec = include_str!("../../../spec/THRESHOLD.md");
    for code in FROST_ERROR_CODES {
        assert!(
            spec.contains(&format!("| `{code}` |")),
            "{code} not in spec"
        );
        assert!(!crate::error::CLI_ERROR_CODES.contains(&code));
    }
    for code in ["THRESHOLD_ENCODING", "THRESHOLD_INPUT"] {
        assert!(
            spec.contains(&format!("| `{code}` |")),
            "{code} not in spec"
        );
    }
    let distinct: BTreeSet<&str> = FROST_ERROR_CODES.into_iter().collect();
    assert_eq!(distinct.len(), FROST_ERROR_CODES.len());
}

#[test]
fn files_are_their_tag_and_lowercase_hex_and_nothing_else() {
    let body = [0x00, 0x1f, 0xa0, 0xff];
    let text = envelope(COMMIT_TAG, &body);
    assert_eq!(&text[..], b"impulse-frost-commit-v1:001fa0ff\n");
    assert_eq!(public_file(COMMIT_TAG, &body).as_bytes(), &text[..]);
    let opened = |t: &[u8]| open_envelope(t, COMMIT_TAG).map(|b| b.to_vec());
    assert_eq!(opened(&text), Some(body.to_vec()), "control");
    assert_eq!(
        opened(b"impulse-frost-commit-v1:001fa0ff"),
        Some(body.to_vec())
    );
    assert_eq!(opened(b"impulse-frost-commit-v1:\n"), Some(vec![]));
    for bad in [
        &b"impulse-frost-commit-v1:001fa0ff\n\n"[..],
        b"impulse-frost-commit-v1:001fa0ff\r\n",
        b"impulse-frost-commit-v1:001FA0FF\n",
        b"impulse-frost-commit-v1:001fa0f\n",
        b"impulse-frost-commit-v1 001fa0ff\n",
        b"impulse-frost-commit-v1:001fa0ff \n",
        b" impulse-frost-commit-v1:001fa0ff\n",
        b"impulse-frost-sigshare-v1:001fa0ff\n",
        b"impulse-frost-commit-v2:001fa0ff\n",
        b"impulse-frost-commit-v1:0x1fa0ff\n",
    ] {
        assert_eq!(opened(bad), None, "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn signers_are_distinct_party_numbers() {
    assert_eq!(parse_signers("1,2").unwrap(), BTreeSet::from([1, 2]));
    assert_eq!(parse_signers("3,1").unwrap(), BTreeSet::from([1, 3]));
    assert_eq!(
        parse_signers("0").unwrap(),
        BTreeSet::from([0]),
        "range is checked later"
    );
    for bad in [
        "", "1,", ",1", "1,1", "01", "a", "1 ,2", "65536", "+1", "1;2", "1,,2",
    ] {
        assert_eq!(
            parse_signers(bad).unwrap_err().code(),
            "FROST_SIGNERS_INVALID",
            "{bad:?}"
        );
    }
    let shape = GroupShape::new(2, 3).unwrap();
    assert!(
        check_signers(shape, &BTreeSet::from([1, 2])).is_ok(),
        "control"
    );
    assert!(check_signers(shape, &BTreeSet::from([1, 2, 3])).is_ok());
    let code = |set: &[PartyId]| {
        check_signers(shape, &set.iter().copied().collect())
            .unwrap_err()
            .code()
    };
    assert_eq!(code(&[1]), "THRESHOLD_TOO_FEW_SIGNERS");
    assert_eq!(code(&[1, 4]), "THRESHOLD_PARTY");
    assert_eq!(code(&[0, 1]), "THRESHOLD_PARTY");
}

#[test]
fn the_session_is_the_specified_digest_and_changes_with_any_part() {
    let authority = world::label_key("frost/authority");
    let ipst = world::settle_ipst(
        Some(authority),
        Network::Testnet,
        &world::label_key("payer"),
    );
    let (key, inputs) = authority_inputs(&ipst).unwrap();
    assert_eq!((key, inputs.clone()), (authority, vec![0, 1]));
    let signers = BTreeSet::from([1, 2]);
    let session = session_id(&ipst, &authority, &signers, &inputs).unwrap();
    // The encoding of spec/THRESHOLD.md, "Files", written out here independently.
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/frostsession/v1")
        .to_state();
    state
        .update(&authority)
        .update(&[0, 2, 0, 1, 0, 2])
        .update(&[0, 2]);
    for input in [0usize, 1] {
        let sighash = ipst.slots()[input].sighash().unwrap();
        state.update(&(input as u32).to_be_bytes()).update(&sighash);
    }
    assert_eq!(session[..], state.finalize().as_bytes()[..]);
    assert_ne!(
        session,
        session_id(&ipst, &authority, &BTreeSet::from([1, 3]), &inputs).unwrap()
    );
    assert_ne!(
        session,
        session_id(&ipst, &authority, &signers, &[0]).unwrap()
    );
    let other = world::settle_ipst(Some(authority), Network::Testnet, &world::label_key("x"));
    assert_ne!(
        session,
        session_id(&other, &authority, &signers, &inputs).unwrap(),
        "another transaction"
    );
}

#[test]
fn the_authority_inputs_are_the_unsigned_slots_of_the_terms_authority() {
    let authority = world::label_key("frost/authority");
    let ipst = world::settle_ipst(
        Some(authority),
        Network::Testnet,
        &world::label_key("payer"),
    );
    assert_eq!(authority_inputs(&ipst).unwrap().1, vec![0, 1], "control");
    let self_settling = world::settle_ipst(None, Network::Testnet, &world::label_key("payer"));
    assert_eq!(
        authority_inputs(&self_settling).unwrap_err().code(),
        "FROST_NO_AUTHORITY_INPUT"
    );
    // The vault inputs of every kind the authority signs.
    let payer = world::label_key("payer");
    for (cash, expected) in [
        (world::Cash::Kcc20, vec![0, 1]),
        (world::Cash::External, vec![0]),
    ] {
        let ipst = world::settle_ipst_with(cash, Some(authority), Network::Testnet, &payer);
        assert_eq!(authority_inputs(&ipst).unwrap().1, expected, "{cash:?}");
    }
    let refund = world::authority_refund_ipst(authority, Network::Testnet, &payer);
    assert_eq!(authority_inputs(&refund).unwrap().1, vec![0], "refund");
    // A fee input locked to the authority key is not an authority input: refused, input named.
    let own_fee = world::settle_ipst(Some(authority), Network::Testnet, &authority);
    assert_eq!(own_fee.slots()[3].signer(), Some(authority));
    let e = authority_inputs(&own_fee).unwrap_err();
    assert_eq!(e.code(), "FROST_AUTHORITY_INPUT_NOT_VAULT");
    assert!(e.to_string().contains("input 3 "), "{e}");
}

#[test]
fn only_a_settle_or_a_refund_by_the_authority_is_signed() {
    let refund = |signer| IpstKind::Refund {
        leg: LegIndex::Cash,
        signer,
        with_token: false,
    };
    for kind in [IpstKind::Settle, refund(RefundSigner::Authority)] {
        assert_eq!(check_kind(&kind), Ok(()), "control: {kind:?}");
    }
    for kind in [
        IpstKind::FundKas,
        IpstKind::FundKcc20(LegIndex::Asset),
        IpstKind::Direct,
        refund(RefundSigner::Depositor),
        refund(RefundSigner::Counterparty),
    ] {
        assert_eq!(
            check_kind(&kind).unwrap_err().code(),
            "FROST_AUTHORITY_INPUT_NOT_VAULT",
            "{kind:?}"
        );
    }
}

// =============================================================================================
// Wire formats (spec/THRESHOLD.md, "Files"): literal tags, domains, layouts and digests
// =============================================================================================

/// SEC1 of the secp256k1 generator G and of 2G and 3G: public curve points, not keys of anyone.
const G1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn fixed_commitment(first: &str, second: &str) -> Commitment {
    Commitment::from_bytes(&unhex(&format!("{first}{second}"))).unwrap()
}

#[test]
fn wire_formats_are_pinned() {
    assert_eq!(ROUND1_TAG, "impulse-frost-round1-v1");
    assert_eq!(ROUND2_TAG, "impulse-frost-round2-v1");
    assert_eq!(SHARE_TAG, "impulse-frost-share-v1");
    assert_eq!(GROUP_TAG, "impulse-frost-group-v1");
    assert_eq!(COMMIT_TAG, "impulse-frost-commit-v1");
    assert_eq!(SIGSHARE_TAG, "impulse-frost-sigshare-v1");
    assert_eq!(SESSION_DOMAIN, b"Impulse/frostsession/v1");
    assert_eq!(COMMITMENT_SET_DOMAIN, b"Impulse/frostcommitments/v1");
    let dir = TempDir::new();
    let session = [0x5e; 32];
    let (ca, cb) = (fixed_commitment(G1, G2), fixed_commitment(G2, G1));

    // commit-<i>.frost: session, sender, count, then input index and commitment per input.
    let commit_text = format!(
        "impulse-frost-commit-v1:{}0002000200000000{G1}{G2}00000001{G2}{G1}\n",
        "5e".repeat(32)
    );
    let mine = BTreeMap::from([(0usize, ca), (1, cb)]);
    let body = commit_body(&session, 2, &mine).unwrap();
    assert_eq!(public_file(COMMIT_TAG, &body), commit_text);
    let path = dir.path().join("commit-2.frost");
    std::fs::write(&path, &commit_text).unwrap();
    assert_eq!(read_commit(&path, &session, 2, &[0, 1]).unwrap(), mine);

    // sigshare-<i>.frost: session, commitment set digest, sender, count, then per input.
    let share = |b: u8| SignatureShare::from_bytes(&[b; 32]).unwrap();
    let shares = BTreeMap::from([(0usize, share(0x11)), (1, share(0x22))]);
    let sigshare_text = format!(
        "impulse-frost-sigshare-v1:{}{}0002000200000000{}00000001{}\n",
        "5e".repeat(32),
        "d1".repeat(32),
        "11".repeat(32),
        "22".repeat(32)
    );
    let body = sigshare_body(&session, &[0xd1; 32], 2, &shares);
    assert_eq!(public_file(SIGSHARE_TAG, &body), sigshare_text);
    let path = dir.path().join("sigshare-2.frost");
    std::fs::write(&path, &sigshare_text).unwrap();
    assert_eq!(
        read_sigshare(&path, &session, 2, &[0, 1]).unwrap(),
        ([0xd1; 32], shares)
    );

    // The group file: threshold, parties, the group key, every public share.
    let group_text = format!("impulse-frost-group-v1:00020003{G1}{G1}{G2}{G3}\n");
    let key = GroupKey::from_bytes(&unhex(&format!("00020003{G1}{G1}{G2}{G3}"))).unwrap();
    assert_eq!(public_file(GROUP_TAG, &key.to_bytes().unwrap()), group_text);

    // The session digest, recomputed with the literal key, and frozen.
    let signers = BTreeSet::from([1, 2]);
    let messages = [(0usize, [0x01; 32]), (1, [0x02; 32])];
    let digest = session_digest(&[0xa7; 32], &signers, &messages);
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/frostsession/v1")
        .to_state();
    state
        .update(&[0xa7; 32])
        .update(&[0, 2, 0, 1, 0, 2, 0, 2])
        .update(&[0, 0, 0, 0])
        .update(&[0x01; 32])
        .update(&[0, 0, 0, 1])
        .update(&[0x02; 32]);
    assert_eq!(digest[..], state.finalize().as_bytes()[..]);
    assert_eq!(hex(&digest), SESSION_VECTOR);

    // The commitment set digest, recomputed with the literal key, and frozen.
    let set: CommitmentSet = BTreeMap::from([
        (1, BTreeMap::from([(0usize, ca), (1, cb)])),
        (2, BTreeMap::from([(0usize, cb), (1, ca)])),
    ]);
    let digest = commitment_set_digest(&session, &set).unwrap();
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/frostcommitments/v1")
        .to_state();
    state
        .update(&session)
        .update(&unhex(&format!("0001{G1}{G2}{G2}{G1}0002{G2}{G1}{G1}{G2}")));
    assert_eq!(digest[..], state.finalize().as_bytes()[..]);
    assert_eq!(hex(&digest), COMMITMENT_SET_VECTOR);
}

/// Frozen outputs of `wire_formats_are_pinned`.
const SESSION_VECTOR: &str = "a6fcdeb9f295f3ecfc7a164498c012458fd77d72c504635ad967ab1af1d8745e";
const COMMITMENT_SET_VECTOR: &str =
    "7e4141ddf012e332d36026d4e28eac76795514577849eeb5132201b48178c198";

/// Opening a FIFO waits for a writer: every file the commands read is checked to be a regular
/// file before it is opened.
#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer() {
    let dir = TempDir::new();
    let regular = dir.path().join("regular");
    std::fs::write(&regular, "x").unwrap();
    let fifo = dir.path().join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let within = |path: PathBuf| {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(read_file(&path, &PUBLIC_FILE).map(|b| b.to_vec()));
        });
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read returns instead of waiting for a writer")
    };
    assert_eq!(within(regular).unwrap(), b"x", "control");
    let e = within(fifo.clone()).unwrap_err();
    assert_eq!(e.code(), "CLI_FILE_READ");
    assert!(e.to_string().ends_with("not a regular file"), "{e}");
    // The share file goes through the same read.
    let w = sign_world();
    let answer = honest(&w);
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let (r, reached) = sign_direct(&w, &fifo, &[1, 2], false, &answer);
            let _ = send.send((r.map(|_| ()), reached));
        });
        let (r, reached) = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the share read returns instead of waiting for a writer");
        assert_eq!(r.unwrap_err().code(), "FROST_SHARE_FILE_UNREADABLE");
        assert!(!reached);
    });
}

// =============================================================================================
// impulse frost keygen: party 1 through the command, parties 2 and 3 played here
// =============================================================================================

/// What the played parties do wrong, one fault per run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    /// The first round-1 prompt is answered before any file is there.
    LateRound1,
    WrongDigest,
    WrongFingerprint,
    EndAtRound1,
    Round1Garbage,
    Round1OtherShape,
    Round1OtherSender,
    /// round1-2 carries party 3's package under party 2's header.
    Round1BadProof,
    Round2Garbage,
    Round2Readable,
    Round2OtherTranscript,
    Round2OtherRecipient,
    /// round2-2-to-1 carries the share party 2 made for party 3.
    Round2BadShare,
    /// round2-1-to-2.frost appears in the directory while party 1 confirms the digest.
    Round2FileAppears,
    /// The share file appears while party 1 confirms the fingerprint.
    ShareFileAppears,
    /// The group file appears while party 1 confirms the fingerprint.
    GroupFileAppears,
    /// The exchange directory becomes read-only while party 1 confirms the fingerprint.
    Round2Unremovable,
}

/// What a file that appears during a run holds; it must still hold it afterwards.
const PLACEHOLDER: &str = "placeholder, not a frost file\n";

struct Played {
    shape: GroupShape,
    round1_secrets: BTreeMap<PartyId, DkgRound1Secret>,
    round1: BTreeMap<PartyId, DkgRound1Package>,
    round2_secrets: BTreeMap<PartyId, DkgRound2Secret>,
    sent: BTreeMap<PartyId, BTreeMap<PartyId, DkgRound2Package>>,
    shares: BTreeMap<PartyId, KeyShare>,
    keys: BTreeMap<PartyId, GroupKey>,
}

impl Played {
    /// The round-1 packages party `me` receives.
    fn others(&self, me: PartyId) -> BTreeMap<PartyId, DkgRound1Package> {
        self.round1
            .iter()
            .filter(|(&id, _)| id != me)
            .map(|(&id, p)| (id, p.clone()))
            .collect()
    }
}

fn header(t: u16, n: u16, from: PartyId) -> Vec<u8> {
    [t.to_be_bytes(), n.to_be_bytes(), from.to_be_bytes()].concat()
}

fn read_round1_file(path: &Path) -> DkgRound1Package {
    let text = std::fs::read(path).unwrap();
    let body = open_envelope(&text, ROUND1_TAG).unwrap();
    DkgRound1Package::from_bytes(&body[6..]).unwrap()
}

fn read_round2_file(path: &Path) -> DkgRound2Package {
    let text = std::fs::read(path).unwrap();
    let body = open_envelope(&text, ROUND2_TAG).unwrap();
    DkgRound2Package::from_bytes(&body[40..]).unwrap()
}

struct KeygenRun {
    dir: TempDir,
    exchange: PathBuf,
    share: PathBuf,
    group: PathBuf,
    result: Result<(), CliError>,
    said: Vec<String>,
    played: Played,
}

/// Party 1 of a 2-of-3 group runs `impulse frost keygen`; parties 2 and 3 are played here and
/// answer every prompt as honest parties would, except for `fault`.
fn keygen_party1(fault: Fault) -> KeygenRun {
    let dir = TempDir::new();
    let exchange = dir.path().join("exchange");
    std::fs::create_dir(&exchange).unwrap();
    let (share, group) = (
        dir.path().join("share.frost"),
        dir.path().join("group.frost"),
    );
    let shape = GroupShape::new(2, 3).unwrap();
    let played = RefCell::new(Played {
        shape,
        round1_secrets: BTreeMap::new(),
        round1: BTreeMap::new(),
        round2_secrets: BTreeMap::new(),
        sent: BTreeMap::new(),
        shares: BTreeMap::new(),
        keys: BTreeMap::new(),
    });
    let mut asked_round1 = 0;
    let console = Script::new(|prompt, said| {
        let mut p = played.borrow_mut();
        let last = |key: &str| {
            said.iter()
                .rev()
                .find_map(|l| l.strip_prefix(key))
                .unwrap()
                .to_string()
        };
        if prompt.starts_with("round 1:") {
            asked_round1 += 1;
            if fault == Fault::EndAtRound1 {
                return None;
            }
            if fault == Fault::LateRound1 && asked_round1 == 1 {
                return Some(String::new());
            }
            for j in [2u16, 3] {
                let (secret, package) = dkg_round1(shape, j).unwrap();
                p.round1_secrets.insert(j, secret);
                p.round1.insert(j, package);
            }
            for j in [2u16, 3] {
                let (header_from, package, t_n) = match (fault, j) {
                    (Fault::Round1OtherSender, 2) => (3, &p.round1[&3], (2, 3)),
                    (Fault::Round1BadProof, 2) => (2, &p.round1[&3], (2, 3)),
                    (Fault::Round1OtherShape, 2) => (2, &p.round1[&2], (2, 4)),
                    _ => (j, &p.round1[&j], (2, 3)),
                };
                let mut body = header(t_n.0, t_n.1, header_from);
                body.extend_from_slice(&package.to_bytes().unwrap());
                let text = if fault == Fault::Round1Garbage && j == 2 {
                    "impulse-frost-round1-v1:00\n".to_string()
                } else {
                    public_file(ROUND1_TAG, &body)
                };
                std::fs::write(exchange.join(format!("round1-{j}.frost")), text).unwrap();
            }
            return Some(String::new());
        }
        if prompt.starts_with("confirm round-1 digest") {
            if fault == Fault::Round2FileAppears {
                std::fs::write(exchange.join("round2-1-to-2.frost"), PLACEHOLDER).unwrap();
            }
            let digest = last("round-1 digest: ");
            return Some(if fault == Fault::WrongDigest {
                "00".repeat(32)
            } else {
                digest
            });
        }
        if prompt.starts_with("round 2:") {
            let own1 = read_round1_file(&exchange.join("round1-1.frost"));
            p.round1.insert(1, own1);
            let digest = dkg_round1_digest(shape, &p.round1).unwrap();
            for j in [2u16, 3] {
                let others = p.others(j);
                let secret = p.round1_secrets.remove(&j).unwrap();
                let (secret2, packages) = dkg_round2(secret, &others).unwrap();
                p.round2_secrets.insert(j, secret2);
                p.sent.insert(j, packages);
            }
            // Round-2 files to party 1.
            for j in [2u16, 3] {
                let (package, to, transcript): (_, PartyId, _) = match (fault, j) {
                    (Fault::Round2BadShare, 2) => (&p.sent[&2][&3], 1, digest),
                    (Fault::Round2OtherRecipient, 2) => (&p.sent[&2][&1], 3, digest),
                    (Fault::Round2OtherTranscript, 2) => (&p.sent[&2][&1], 1, [7u8; 32]),
                    _ => (&p.sent[&j][&1], 1, digest),
                };
                let mut body = header(2, 3, j);
                body.extend_from_slice(&to.to_be_bytes());
                body.extend_from_slice(&transcript);
                body.extend_from_slice(&package.to_bytes()[..]);
                let path = exchange.join(format!("round2-{j}-to-1.frost"));
                let text = if fault == Fault::Round2Garbage && j == 2 {
                    envelope(ROUND2_TAG, &body[..40])
                } else {
                    envelope(ROUND2_TAG, &body)
                };
                let mode = if fault == Fault::Round2Readable && j == 2 {
                    0o644
                } else {
                    0o600
                };
                write_mode(&path, &text, mode);
            }
            return Some(String::new());
        }
        if prompt.starts_with("confirm group fingerprint") {
            // Parties 2 and 3 finish with the round-2 files party 1 wrote for them, and must
            // reach the fingerprint party 1 shows.
            let shown = last("group fingerprint: ");
            for j in [2u16, 3] {
                let k = 5 - j;
                let from1 = read_round2_file(&exchange.join(format!("round2-1-to-{j}.frost")));
                let from_k = p.sent.get_mut(&k).unwrap().remove(&j).unwrap();
                let inbox = BTreeMap::from([(1, from1), (k, from_k)]);
                let secret2 = p.round2_secrets.remove(&j).unwrap();
                let others = p.others(j);
                let (share, key) = dkg_round3(secret2, &others, &inbox).unwrap();
                assert_eq!(hex(&key.fingerprint()), shown, "party {j} agrees");
                p.shares.insert(j, share);
                p.keys.insert(j, key);
            }
            match fault {
                Fault::ShareFileAppears => std::fs::write(&share, PLACEHOLDER).unwrap(),
                Fault::GroupFileAppears => std::fs::write(&group, PLACEHOLDER).unwrap(),
                Fault::Round2Unremovable => {
                    use std::os::unix::fs::PermissionsExt;
                    let read_only = std::fs::Permissions::from_mode(0o500);
                    std::fs::set_permissions(&exchange, read_only).unwrap();
                }
                _ => {}
            }
            return Some(if fault == Fault::WrongFingerprint {
                "11".repeat(32)
            } else {
                shown
            });
        }
        panic!("unexpected prompt {prompt}");
    });
    let result = exec(
        &[
            "frost",
            "keygen",
            "--threshold",
            "2",
            "--parties",
            "3",
            "--party",
            "1",
            "--dir",
            s(&exchange),
            "--share-file",
            s(&share),
            "--group-out",
            s(&group),
        ],
        &console,
    );
    let said = console.said();
    drop(console);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exchange, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    KeygenRun {
        dir,
        exchange,
        share,
        group,
        result,
        said,
        played: played.into_inner(),
    }
}

#[test]
fn keygen_writes_an_owner_only_share_after_both_confirmations() {
    let run = keygen_party1(Fault::None);
    run.result.as_ref().expect("keygen");
    let said = run.said.join("\n");
    // Outputs: the share file 0600, the group file, the outgoing round-2 files 0600.
    assert_eq!(mode_of(&run.share), 0o600);
    for j in [2, 3] {
        assert_eq!(
            mode_of(&run.exchange.join(format!("round2-1-to-{j}.frost"))),
            0o600
        );
        // The round-2 files addressed to party 1 are removed once the share is written.
        let incoming = run.exchange.join(format!("round2-{j}-to-1.frost"));
        assert!(!incoming.exists());
        assert!(said.contains(&format!("removed: {}", incoming.display())));
    }
    let text = std::fs::read(&run.share).unwrap();
    let share = KeyShare::from_bytes(&open_envelope(&text, SHARE_TAG).unwrap()).unwrap();
    let group_text = std::fs::read(&run.group).unwrap();
    let group = GroupKey::from_bytes(&open_envelope(&group_text, GROUP_TAG).unwrap()).unwrap();
    assert_eq!(group, run.played.keys[&2], "the group every party holds");
    assert_eq!((share.id(), share.shape()), (1, run.played.shape));
    assert_eq!(share.authority_key(), group.authority_key());
    assert!(said.contains(&format!("authority key: {}", hex(&group.authority_key()))));
    // The share file party 1 wrote signs with party 3's share.
    let (n1, c1) = commit(&share);
    let (n3, c3) = commit(&run.played.shares[&3]);
    let set = BTreeMap::from([(1, c1), (3, c3)]);
    let ipst = world::settle_ipst(
        Some(group.authority_key()),
        Network::Testnet,
        &world::label_key("frost/payer"),
    );
    let (tx_, entries) = (ipst.transaction(), ipst.entries());
    let s1 = sign_input(&share, n1, tx_, entries, 0, &set).unwrap();
    let s3 = sign_input(&run.played.shares[&3], n3, tx_, entries, 0, &set).unwrap();
    let sig = impulse_core::threshold::aggregate_input(
        &group,
        tx_,
        entries,
        0,
        &set,
        &BTreeMap::from([(1, s1), (3, s3)]),
    )
    .expect("party 1's share file signs with party 3");
    let sighash = tx::sighash(tx_, entries, 0).unwrap();
    verify(
        &group.authority_key(),
        &sighash,
        sig[..64].try_into().unwrap(),
    )
    .unwrap();
    // The share never appears in what the command said.
    let share_hex = String::from_utf8(text).unwrap();
    let share_hex = share_hex.trim_end().split(':').nth(1).unwrap();
    assert!(!said.contains(share_hex));
    assert!(
        !said.contains(&share_hex[12..76]),
        "nor the signing share alone"
    );
    // The digest was shown before any round-2 file was written, and the share written only
    // after the fingerprint was confirmed.
    // The files party 1 wrote, against the literal layouts of spec/THRESHOLD.md, "Files".
    let read = |p: PathBuf| String::from_utf8(std::fs::read(p).unwrap()).unwrap();
    let round1 = read(run.exchange.join("round1-1.frost"));
    assert!(
        round1.starts_with("impulse-frost-round1-v1:0002000300010002"),
        "{round1}"
    );
    assert_eq!(round1.len(), 24 + 2 * (6 + 2 + 2 * 33 + 64) + 1);
    let digest = run
        .said
        .iter()
        .find_map(|l| l.strip_prefix("round-1 digest: "))
        .unwrap();
    let round2 = read(run.exchange.join("round2-1-to-2.frost"));
    assert!(round2.starts_with(&format!("impulse-frost-round2-v1:0002000300010002{digest}")));
    assert_eq!(round2.len(), 24 + 2 * (8 + 32 + 32) + 1);
    let group_hex = read(run.group.clone());
    let group_hex = group_hex
        .strip_prefix("impulse-frost-group-v1:00020003")
        .unwrap()
        .strip_suffix('\n')
        .unwrap();
    assert_eq!(group_hex.len(), 2 * 33 * 4);
    let share_text = read(run.share.clone());
    let share_hex = share_text
        .strip_prefix("impulse-frost-share-v1:000200030001")
        .unwrap()
        .strip_suffix('\n')
        .unwrap();
    assert_eq!(share_hex.len(), 2 * (32 + 33 + 33));
    assert_eq!(
        &share_hex[64..130],
        &group_hex[66..132],
        "party 1's public share"
    );
    assert_eq!(&share_hex[130..], &group_hex[..66], "the group key");
    let pos = |needle: &str| run.said.iter().position(|l| l.contains(needle)).unwrap();
    assert!(pos("round-1 digest: ") < pos("round2-1-to-2.frost"));
    assert!(pos("> confirm round-1 digest") < pos("round2-1-to-2.frost"));
    assert!(pos("> confirm group fingerprint") < pos("share.frost (secret"));
    assert!(run.dir.path().exists());
}

#[test]
fn keygen_asks_again_while_files_are_missing() {
    let run = keygen_party1(Fault::LateRound1);
    run.result.as_ref().expect("keygen");
    assert!(run
        .said
        .contains(&"missing: round1-2.frost, round1-3.frost".to_string()));
}

#[test]
fn keygen_refuses_what_the_parties_did_not_confirm() {
    let control = keygen_party1(Fault::None);
    assert!(control.result.is_ok());
    let run = keygen_party1(Fault::WrongDigest);
    assert_eq!(
        run.result.as_ref().unwrap_err().code(),
        "FROST_NOT_CONFIRMED"
    );
    for j in [2, 3] {
        assert!(!run.exchange.join(format!("round2-1-to-{j}.frost")).exists());
    }
    let run = keygen_party1(Fault::WrongFingerprint);
    assert_eq!(
        run.result.as_ref().unwrap_err().code(),
        "FROST_NOT_CONFIRMED"
    );
    assert!(!run.share.exists() && !run.group.exists(), "nothing kept");
    assert!(
        run.exchange.join("round2-2-to-1.frost").exists(),
        "nothing removed"
    );
    let run = keygen_party1(Fault::EndAtRound1);
    assert_eq!(run.result.as_ref().unwrap_err().code(), "FROST_ABORTED");
    assert!(!run.share.exists());
}

#[test]
fn keygen_refuses_bad_round_files() {
    assert!(keygen_party1(Fault::None).result.is_ok(), "control");
    for (fault, code) in [
        (Fault::Round1Garbage, "FROST_FILE_MALFORMED"),
        (Fault::Round1OtherShape, "FROST_SESSION_MISMATCH"),
        (Fault::Round1OtherSender, "FROST_SESSION_MISMATCH"),
        (Fault::Round1BadProof, "THRESHOLD_DKG_CULPRIT"),
        (Fault::Round2Garbage, "FROST_FILE_MALFORMED"),
        (Fault::Round2Readable, "FROST_FILE_PERMISSIONS"),
        (Fault::Round2OtherTranscript, "FROST_SESSION_MISMATCH"),
        (Fault::Round2OtherRecipient, "FROST_SESSION_MISMATCH"),
        (Fault::Round2BadShare, "THRESHOLD_DKG_CULPRIT"),
    ] {
        let run = keygen_party1(fault);
        let e = run.result.as_ref().expect_err("refused");
        assert_eq!(e.code(), code, "{fault:?}: {e}");
        assert!(!run.share.exists() && !run.group.exists(), "{fault:?}");
        if code == "THRESHOLD_DKG_CULPRIT" {
            assert!(
                e.to_string().contains("party 2"),
                "{fault:?} names the sender: {e}"
            );
        }
    }
}

/// Every file keygen writes is created new: one that appears while it runs is never overwritten.
#[test]
fn keygen_never_overwrites_a_file_that_appears_while_it_runs() {
    assert!(keygen_party1(Fault::None).result.is_ok(), "control");
    let run = keygen_party1(Fault::Round2FileAppears);
    assert_eq!(run.result.unwrap_err().code(), "CLI_OUTPUT_EXISTS");
    let kept = std::fs::read_to_string(run.exchange.join("round2-1-to-2.frost")).unwrap();
    assert_eq!(kept, PLACEHOLDER);
    assert!(!run.exchange.join("round2-1-to-3.frost").exists());
    let run = keygen_party1(Fault::ShareFileAppears);
    assert_eq!(run.result.unwrap_err().code(), "CLI_OUTPUT_EXISTS");
    assert_eq!(std::fs::read_to_string(&run.share).unwrap(), PLACEHOLDER);
    assert!(!run.group.exists());
    let run = keygen_party1(Fault::GroupFileAppears);
    assert_eq!(run.result.unwrap_err().code(), "CLI_OUTPUT_EXISTS");
    assert_eq!(std::fs::read_to_string(&run.group).unwrap(), PLACEHOLDER);
}

/// Whether a file in a read-only (0500) directory really cannot be removed. Root ignores the
/// mode, so the probe tries it instead of checking who is running.
fn read_only_dir_blocks_removal() -> bool {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let file = dir.path().join("probe");
    std::fs::write(&file, "").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let blocked = std::fs::remove_file(&file).is_err();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    blocked
}

/// A round-2 file addressed to party 1 that cannot be removed is named, and the command fails.
#[test]
fn keygen_reports_round2_files_it_cannot_remove() {
    let control = keygen_party1(Fault::None);
    assert!(control.result.is_ok(), "control");
    if !read_only_dir_blocks_removal() {
        eprintln!(
            "skipped: a read-only directory does not stop file removal here (running as root), \
             so the unremovable round-2 file cannot be simulated"
        );
        return;
    }
    let run = keygen_party1(Fault::Round2Unremovable);
    assert_eq!(
        run.result.as_ref().unwrap_err().code(),
        "FROST_ROUND2_NOT_REMOVED"
    );
    assert!(run.share.exists() && run.group.exists(), "both written");
    for j in [2, 3] {
        let path = run.exchange.join(format!("round2-{j}-to-1.frost"));
        assert!(path.exists());
        let named = format!("could not remove: {}: ", path.display());
        assert!(run.said.iter().any(|l| l.starts_with(&named)), "{j}");
    }
    assert!(!run.said.iter().any(|l| l.starts_with("ok: ")));
}

#[test]
fn keygen_checks_its_arguments_before_anything() {
    let dir = TempDir::new();
    let ex = dir.path().join("ex");
    std::fs::create_dir(&ex).unwrap();
    let share = dir.path().join("share.frost");
    let group = dir.path().join("group.frost");
    let args = |t: &str, n: &str, i: &str, ex: &Path, share: &Path, group: &Path| -> Vec<String> {
        [
            "frost",
            "keygen",
            "--threshold",
            t,
            "--parties",
            n,
            "--party",
            i,
            "--dir",
            s(ex),
            "--share-file",
            s(share),
            "--group-out",
            s(group),
        ]
        .map(String::from)
        .to_vec()
    };
    let refuse_args = |a: Vec<String>| {
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        refuse(&refs)
    };
    // Control: valid arguments go on to round 1 (and stop at the end of input).
    let console = Script::silent();
    let a = args("2", "3", "1", &ex, &share, &group);
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    assert_eq!(exec(&refs, &console).unwrap_err().code(), "FROST_ABORTED");
    assert!(ex.join("round1-1.frost").exists());
    let ex2 = dir.path().join("ex2");
    std::fs::create_dir(&ex2).unwrap();
    for (a, code) in [
        (
            args("1", "3", "1", &ex2, &share, &group),
            "THRESHOLD_PARAMS",
        ),
        (
            args("4", "3", "1", &ex2, &share, &group),
            "THRESHOLD_PARAMS",
        ),
        (args("2", "3", "0", &ex2, &share, &group), "THRESHOLD_PARTY"),
        (args("2", "3", "4", &ex2, &share, &group), "THRESHOLD_PARTY"),
        (
            args("2", "3", "1", &dir.path().join("none"), &share, &group),
            "CLI_FILE_READ",
        ),
        (
            args("2", "3", "1", &ex, &share, &group),
            "CLI_OUTPUT_EXISTS",
        ),
        (
            args("2", "3", "1", &ex2, &ex.join("round1-1.frost"), &group),
            "CLI_OUTPUT_EXISTS",
        ),
        (
            args("2", "3", "1", &ex2, &share, &ex.join("round1-1.frost")),
            "CLI_OUTPUT_EXISTS",
        ),
        (
            args("2", "3", "1", &ex2, &dir.path().join("no/share"), &group),
            "CLI_FILE_WRITE",
        ),
        (
            args("2", "3", "1", &ex2, &share, &dir.path().join("no/group")),
            "CLI_FILE_WRITE",
        ),
    ] {
        assert_eq!(refuse_args(a.clone()), code, "{a:?}");
    }
    assert_eq!(
        std::fs::read_dir(&ex2).unwrap().count(),
        0,
        "nothing written"
    );
}

// =============================================================================================
// impulse frost sign and aggregate: party 1 through the command, party 2 played here
// =============================================================================================

struct SignWorld {
    dir: TempDir,
    group: LibGroup,
    ipst: Ipst,
    ipst_path: PathBuf,
    shares: BTreeMap<PartyId, PathBuf>,
    group_file: PathBuf,
    /// The terms check needs the cash leg's KCC-20 template.
    cash_template: bool,
}

fn sign_world_on(network: Network) -> SignWorld {
    sign_world_with(world::Cash::Kas, |authority| {
        world::settle_ipst(Some(authority), network, &world::label_key("frost/payer"))
    })
}

/// A group, and the IPST `make` builds for its authority key.
fn sign_world_with(cash: world::Cash, make: impl Fn([u8; 32]) -> Ipst) -> SignWorld {
    let dir = TempDir::new();
    let group = lib_keygen(2, 3);
    let ipst = make(group.key.authority_key());
    let ipst_path = dir.path().join("settle.json");
    std::fs::write(&ipst_path, ipst.to_json()).unwrap();
    let mut shares = BTreeMap::new();
    for (&id, share) in &group.shares {
        let path = dir.path().join(format!("share-{id}.frost"));
        write_share(&path, share);
        shares.insert(id, path);
    }
    let group_file = dir.path().join("group.frost");
    std::fs::write(
        &group_file,
        public_file(GROUP_TAG, &group.key.to_bytes().unwrap()),
    )
    .unwrap();
    SignWorld {
        dir,
        group,
        ipst,
        ipst_path,
        shares,
        group_file,
        cash_template: cash == world::Cash::Kcc20,
    }
}

fn sign_world() -> SignWorld {
    sign_world_on(Network::Testnet)
}

impl SignWorld {
    fn sub(&self, name: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sign_args(&self, me: PartyId, signers: &str, dir: &Path) -> Vec<String> {
        let mut args: Vec<String> = [
            "frost",
            "sign",
            "--share-file",
            s(&self.shares[&me]),
            "--ipst",
            s(&self.ipst_path),
            "--signers",
            signers,
            "--dir",
            s(dir),
            "--asset-template",
            s(&world::asset_template_path()),
            "--daa",
            "1500000",
            "--kas-equivalent",
            "100000000",
        ]
        .map(String::from)
        .to_vec();
        if self.cash_template {
            args.push("--cash-template".into());
            args.push(s(&world::cash_template_path()).into());
        }
        // Last, so the indexes of the flags above hold: the trade this signer agreed to.
        args.push("--terms-hash".into());
        args.push(hex(&self.ipst.terms().terms_hash()));
        args
    }

    /// The authority inputs of the IPST.
    fn inputs(&self) -> Vec<usize> {
        authority_inputs(&self.ipst).unwrap().1
    }

    fn session(&self, signers: &[PartyId]) -> [u8; 32] {
        let (authority, inputs) = authority_inputs(&self.ipst).unwrap();
        session_id(
            &self.ipst,
            &authority,
            &signers.iter().copied().collect(),
            &inputs,
        )
        .unwrap()
    }
}

/// How the played co-signer misbehaves in round 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoFault {
    None,
    Late,
    End,
    Garbage,
    OtherSession,
    OtherSender,
    /// Party 1 types back another session at the approval prompt.
    WrongApproval,
    /// The input ends at the approval prompt.
    EndAtApproval,
}

/// What party 1's signing run returns: its result, what it said, and the played party 2's
/// commitments and nonces.
type Party1Run = (
    Result<(), CliError>,
    Vec<String>,
    BTreeMap<usize, Commitment>,
    BTreeMap<usize, SigningNonces>,
);

/// An exchange's answer: the other signers' commitments.
type Answer<'a> = dyn Fn(PartyId, &BTreeMap<usize, Commitment>) -> CommitmentSet + 'a;

/// Party 1 signs through the command with `--signers 1,2` in `dir`; party 2 is played here and
/// writes its commitment file when asked. Returns the result, what was said, and party 2's
/// commitments and nonces.
fn party1_signs(w: &SignWorld, dir: &Path, fault: CoFault) -> Party1Run {
    party1_signs_with(w, dir, fault, w.sign_args(1, "1,2", dir), None)
}

/// [`party1_signs`] with these arguments and this node.
fn party1_signs_with(
    w: &SignWorld,
    dir: &Path,
    fault: CoFault,
    args: Vec<String>,
    node: MakeNode,
) -> Party1Run {
    let session = w.session(&[1, 2]);
    let share2 = &w.group.shares[&2];
    let mut nonces2 = BTreeMap::new();
    let mut commitments2 = BTreeMap::new();
    for input in w.inputs() {
        let (n, c) = commit(share2);
        nonces2.insert(input, n);
        commitments2.insert(input, c);
    }
    let mut asked = 0;
    let console = Script::new(|prompt, said| {
        if prompt.starts_with("sign:") {
            assert!(
                prompt.contains(&hex(&w.ipst.terms().terms_hash())),
                "the approval prompt names the terms"
            );
            let shown = said
                .iter()
                .rev()
                .find_map(|l| l.strip_prefix("session: "))
                .unwrap();
            assert_eq!(shown, hex(&session));
            return match fault {
                CoFault::EndAtApproval => None,
                CoFault::WrongApproval => Some(hex(&w.session(&[1, 3]))),
                _ => Some(shown.to_string()),
            };
        }
        assert!(prompt.starts_with("commitments:"), "{prompt}");
        asked += 1;
        match fault {
            CoFault::End => return None,
            CoFault::Late if asked == 1 => return Some(String::new()),
            _ => {}
        }
        let (session, sender) = match fault {
            CoFault::OtherSession => (w.session(&[1, 2, 3]), 2),
            CoFault::OtherSender => (session, 3),
            _ => (session, 2),
        };
        let text = if fault == CoFault::Garbage {
            "impulse-frost-commit-v1:0102\n".to_string()
        } else {
            public_file(
                COMMIT_TAG,
                &commit_body(&session, sender, &commitments2).unwrap(),
            )
        };
        std::fs::write(dir.join("commit-2.frost"), text).unwrap();
        Some(String::new())
    });
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = exec_on(&refs, &console, node);
    let said = console.said();
    drop(console);
    (result, said, commitments2, nonces2)
}

/// Party 2's signature-share file for the session party 1 ran in `dir`.
fn party2_signs(
    w: &SignWorld,
    dir: &Path,
    commitments2: &BTreeMap<usize, Commitment>,
    mut nonces2: BTreeMap<usize, SigningNonces>,
) {
    let session = w.session(&[1, 2]);
    let inputs = w.inputs();
    let c1 = read_commit(&dir.join("commit-1.frost"), &session, 1, &inputs).unwrap();
    let set: CommitmentSet = BTreeMap::from([(1, c1), (2, commitments2.clone())]);
    let mut shares = BTreeMap::new();
    for input in inputs {
        let by_party: BTreeMap<PartyId, Commitment> =
            set.iter().map(|(&j, c)| (j, c[&input])).collect();
        let share = sign_input(
            &w.group.shares[&2],
            nonces2.remove(&input).unwrap(),
            w.ipst.transaction(),
            w.ipst.entries(),
            input,
            &by_party,
        )
        .unwrap();
        shares.insert(input, share);
    }
    let digest = commitment_set_digest(&session, &set).unwrap();
    std::fs::write(
        dir.join("sigshare-2.frost"),
        public_file(SIGSHARE_TAG, &sigshare_body(&session, &digest, 2, &shares)),
    )
    .unwrap();
}

fn aggregate_args(w: &SignWorld, signers: &str, dir: &Path, out: &Path) -> Vec<String> {
    [
        "frost",
        "aggregate",
        "--group",
        s(&w.group_file),
        "--ipst",
        s(&w.ipst_path),
        "--signers",
        signers,
        "--dir",
        s(dir),
        "--out",
        s(out),
    ]
    .map(String::from)
    .to_vec()
}

fn run_args(args: &[String]) -> (Result<(), CliError>, Vec<String>) {
    let console = Script::silent();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = exec(&refs, &console);
    (r, console.said())
}

fn refuse_args(args: &[String]) -> &'static str {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    refuse(&refs)
}

/// A complete 2-of-3 session in `dir`: party 1 through the command, party 2 played.
fn complete_session(w: &SignWorld, dir: &Path) {
    let (result, _, c2, n2) = party1_signs(w, dir, CoFault::None);
    result.expect("party 1 signs");
    party2_signs(w, dir, &c2, n2);
}

#[test]
fn sign_and_aggregate_fill_the_authority_slots_of_the_ipst() {
    let w = sign_world();
    let dir = w.sub("session");
    let (result, said, c2, n2) = party1_signs(&w, &dir, CoFault::None);
    result.expect("signs");
    // Summary first, then the commitment file, then ok.
    assert!(said[0].starts_with("terms_hash: "), "{said:?}");
    let all = said.join("\n");
    let session = w.session(&[1, 2]);
    assert!(all.contains(&format!("session: {}", hex(&session))));
    assert!(all.contains("transaction: settle "));
    assert!(all.contains("authority inputs: 0, 1"));
    assert!(all.contains("ok: party 1 signed inputs 0, 1"));
    // Every output and the change are shown before the signer approves.
    let approval = said.iter().position(|l| l.starts_with("> sign: ")).unwrap();
    let shown = |line: &str| said.iter().position(|l| l.starts_with(line));
    let outputs = &w.ipst.transaction().outputs;
    for (i, o) in outputs.iter().enumerate() {
        let line = format!("output {i}: {} sompi to ", o.value);
        assert!(shown(&line).is_some_and(|at| at < approval), "{line}");
    }
    let change = outputs.last().unwrap();
    let payer = world::p2pk(&world::label_key("frost/payer"));
    assert_eq!(change.script_public_key, payer);
    let line = format!(
        "change: {} sompi to {} (the fee payer's)",
        change.value,
        kas_address(Network::Testnet, 0, payer.script())
    );
    assert!(shown(&line).is_some_and(|at| at < approval), "{line}");
    let (_, shares1) = read_sigshare(&dir.join("sigshare-1.frost"), &session, 1, &[0, 1]).unwrap();
    assert_eq!(shares1.len(), 2);
    party2_signs(&w, &dir, &c2, n2);
    let (_, shares2) = read_sigshare(&dir.join("sigshare-2.frost"), &session, 2, &[0, 1]).unwrap();
    assert_ne!(shares1, shares2);
    let out = w.dir.path().join("signed.json");
    let (r, said) = run_args(&aggregate_args(&w, "1,2", &dir, &out));
    r.expect("aggregates");
    let all = said.join("\n");
    assert!(all.contains(&format!(
        "group fingerprint: {}",
        hex(&w.group.key.fingerprint())
    )));
    assert!(
        all.contains("pending inputs: 3"),
        "the fee payer's input is left: {all}"
    );
    // Reading the IPST verifies every signature against its slot's signer and sighash.
    let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        signed.pending(),
        vec![3],
        "input 2 is the escrowed token, unsigned"
    );
    for input in [0usize, 1] {
        let sig = signed.slots()[input].signature().unwrap();
        assert_eq!(sig[64], 0x01);
        let sighash = tx::sighash(w.ipst.transaction(), w.ipst.entries(), input).unwrap();
        verify(
            &w.group.key.authority_key(),
            &sighash,
            sig[..64].try_into().unwrap(),
        )
        .expect("BIP-340 under the authority key");
    }
    // A signed IPST has no authority input left.
    let again = w.dir.path().join("again.json");
    std::fs::copy(&out, &again).unwrap();
    let mut args = aggregate_args(&w, "1,2", &dir, &w.dir.path().join("x.json"));
    args[5] = s(&again).to_string();
    assert_eq!(refuse_args(&args), "FROST_NO_AUTHORITY_INPUT");
}

#[test]
fn sign_refuses_before_printing_or_writing_anything() {
    let w = sign_world();
    let dir = w.sub("refusals");
    let garbage = w.dir.path().join("garbage.json");
    std::fs::write(&garbage, "{").unwrap();
    let mainnet = sign_world_on(Network::Mainnet);
    let self_settling = w.dir.path().join("self.json");
    std::fs::write(
        &self_settling,
        world::settle_ipst(None, Network::Testnet, &world::label_key("p")).to_json(),
    )
    .unwrap();
    let other = lib_keygen(2, 3);
    let other_share = w.dir.path().join("other-share.frost");
    write_share(&other_share, &other.shares[&1]);
    let base = w.sign_args(1, "1,2", &dir);
    let with = |at: usize, value: &str| {
        let mut a = base.clone();
        a[at] = value.to_string();
        a
    };
    let without = |flag: &str| {
        let mut a = base.clone();
        let i = a.iter().position(|x| x == flag).unwrap();
        a.drain(i..i + 2);
        a
    };
    // Indexes into sign_args: 3 share, 5 ipst, 7 signers, 9 dir, 11 template, 13 daa, 15 cap,
    // 17 terms hash.
    // An IPST of terms the signer never named: the authority is this group's key, the trade is
    // a token-cash trade the signer never named.
    let foreign = w.dir.path().join("foreign.json");
    std::fs::write(
        &foreign,
        world::settle_ipst_with(
            world::Cash::Kcc20,
            Some(w.group.key.authority_key()),
            Network::Testnet,
            &world::label_key("other"),
        )
        .to_json(),
    )
    .unwrap();
    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        // The trade the signer did not name: before the share file is read.
        (
            "terms not agreed",
            with(5, s(&foreign)),
            "FROST_TERMS_NOT_AGREED",
        ),
        (
            "terms not agreed, share missing",
            {
                let mut a = with(5, s(&foreign));
                a[3] = "/nonexistent/share".into();
                a
            },
            "FROST_TERMS_NOT_AGREED",
        ),
        (
            "IPST missing",
            with(5, "/nonexistent/ipst"),
            "CLI_FILE_READ",
        ),
        ("IPST not JSON", with(5, s(&garbage)), "IPST_MALFORMED"),
        (
            "IPST of mainnet",
            with(5, s(&mainnet.ipst_path)),
            "CLI_NETWORK_MISMATCH",
        ),
        (
            "no authority",
            with(5, s(&self_settling)),
            "FROST_NO_AUTHORITY_INPUT",
        ),
        ("signers repeated", with(7, "1,1"), "FROST_SIGNERS_INVALID"),
        (
            "template missing",
            with(11, "/nonexistent/t.json"),
            "CLI_FILE_READ",
        ),
        (
            "template not KCC-20",
            with(11, s(&garbage)),
            "TX_TOKEN_TEMPLATE",
        ),
        ("at expiry", with(13, "2000000"), "TX_EXPIRED"),
        (
            "value undeclared",
            without("--kas-equivalent"),
            "CLI_VALUE_UNKNOWN",
        ),
        (
            "value above the cap",
            with(15, "2000000000"),
            "CLI_VALUE_CAP_EXCEEDED",
        ),
        ("dir missing", with(9, "/nonexistent/dir"), "CLI_FILE_READ"),
        (
            "share missing",
            with(3, "/nonexistent/share"),
            "FROST_SHARE_FILE_UNREADABLE",
        ),
        (
            "another group's share",
            with(3, s(&other_share)),
            "FROST_KEY_NOT_AUTHORITY",
        ),
        ("one signer", with(7, "1"), "THRESHOLD_TOO_FEW_SIGNERS"),
        ("signer outside", with(7, "1,4"), "THRESHOLD_PARTY"),
        (
            "set without me",
            with(7, "2,3"),
            "THRESHOLD_SIGNER_NOT_IN_SET",
        ),
    ];
    for (label, args, code) in cases {
        assert_eq!(refuse_args(&args), code, "{label}");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "{label}: wrote"
        );
    }
    // Mainnet: a typed DAA score is refused, the node is the source.
    let mut args = mainnet.sign_args(1, "1,2", &dir);
    args.insert(0, "mainnet".into());
    args.insert(0, "--network".into());
    assert_eq!(refuse_args(&args), "CLI_MAINNET_NEEDS_NODE");
    // Own files already in the directory.
    std::fs::write(dir.join("commit-1.frost"), "x").unwrap();
    assert_eq!(refuse_args(&base), "CLI_OUTPUT_EXISTS");
    std::fs::remove_file(dir.join("commit-1.frost")).unwrap();
    std::fs::write(dir.join("sigshare-1.frost"), "x").unwrap();
    assert_eq!(refuse_args(&base), "CLI_OUTPUT_EXISTS");
    std::fs::remove_file(dir.join("sigshare-1.frost")).unwrap();
    // Control: the same arguments sign.
    let (result, _, _, _) = party1_signs(&w, &dir, CoFault::None);
    result.expect("control");
}

#[test]
fn sign_refuses_commitments_of_another_session_and_asks_while_missing() {
    let w = sign_world();
    let control = w.sub("control");
    let (result, said, _, _) = party1_signs(&w, &control, CoFault::Late);
    result.expect("control, after one more prompt");
    assert!(said.contains(&"missing: commit-2.frost".to_string()));
    for (fault, code) in [
        (CoFault::End, "FROST_ABORTED"),
        (CoFault::Garbage, "FROST_FILE_MALFORMED"),
        (CoFault::OtherSession, "FROST_SESSION_MISMATCH"),
        (CoFault::OtherSender, "FROST_SESSION_MISMATCH"),
    ] {
        let dir = w.sub(&format!("{fault:?}"));
        let (result, _, _, _) = party1_signs(&w, &dir, fault);
        assert_eq!(result.unwrap_err().code(), code, "{fault:?}");
        assert!(
            !dir.join("sigshare-1.frost").exists(),
            "{fault:?}: no share out"
        );
    }
}

#[test]
fn aggregate_refuses_before_writing_anything() {
    let w = sign_world();
    let dir = w.sub("session");
    complete_session(&w, &dir);
    let out = w.dir.path().join("out.json");
    let base = aggregate_args(&w, "1,2", &dir, &out);
    let with = |at: usize, value: &str| {
        let mut a = base.clone();
        a[at] = value.to_string();
        a
    };
    let garbage = w.dir.path().join("garbage.frost");
    std::fs::write(&garbage, "impulse-frost-group-v1:00\n").unwrap();
    let other = lib_keygen(2, 3);
    let other_group = w.dir.path().join("other-group.frost");
    std::fs::write(
        &other_group,
        public_file(GROUP_TAG, &other.key.to_bytes().unwrap()),
    )
    .unwrap();
    let mainnet = sign_world_on(Network::Mainnet);
    let exists = w.dir.path().join("exists.json");
    std::fs::write(&exists, "x").unwrap();
    // --out is checked before any signer file is read: with no signer file here, an existing
    // --out is still what is refused.
    let empty = w.sub("empty");
    assert_eq!(
        refuse_args(&aggregate_args(&w, "1,2", &empty, &exists)),
        "CLI_OUTPUT_EXISTS"
    );
    let partial = w.sub("partial");
    for name in ["commit-1.frost", "sigshare-1.frost"] {
        std::fs::copy(dir.join(name), partial.join(name)).unwrap();
    }
    // Indexes into aggregate_args: 3 group, 5 ipst, 7 signers, 9 dir, 11 out.
    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        (
            "IPST of mainnet",
            with(5, s(&mainnet.ipst_path)),
            "CLI_NETWORK_MISMATCH",
        ),
        ("signers malformed", with(7, "1,x"), "FROST_SIGNERS_INVALID"),
        (
            "group missing",
            with(3, "/nonexistent/group"),
            "CLI_FILE_READ",
        ),
        (
            "group malformed",
            with(3, s(&garbage)),
            "FROST_FILE_MALFORMED",
        ),
        (
            "another group",
            with(3, s(&other_group)),
            "FROST_KEY_NOT_AUTHORITY",
        ),
        ("one signer", with(7, "1"), "THRESHOLD_TOO_FEW_SIGNERS"),
        ("signer outside", with(7, "1,5"), "THRESHOLD_PARTY"),
        ("output exists", with(11, s(&exists)), "CLI_OUTPUT_EXISTS"),
        (
            "another signing set",
            with(7, "1,3"),
            "FROST_SESSION_MISMATCH",
        ),
        (
            "a signer's files missing",
            with(9, s(&partial)),
            "CLI_FILE_READ",
        ),
    ];
    for (label, args, code) in cases {
        assert_eq!(refuse_args(&args), code, "{label}");
        assert!(!out.exists(), "{label}");
    }
    // Control: the same session aggregates.
    let (r, _) = run_args(&base);
    r.expect("control");
}

#[test]
fn aggregate_refuses_tampered_session_files() {
    let w = sign_world();
    let control = w.sub("control");
    complete_session(&w, &control);
    let (r, _) = run_args(&aggregate_args(
        &w,
        "1,2",
        &control,
        &w.dir.path().join("ok.json"),
    ));
    r.expect("control");
    let session = w.session(&[1, 2]);

    // Party 2's share flipped: FROST names party 2.
    let dir = w.sub("flipped");
    complete_session(&w, &dir);
    let (digest, mut shares) =
        read_sigshare(&dir.join("sigshare-2.frost"), &session, 2, &[0, 1]).unwrap();
    let other = SignatureShare::from_bytes(&[3u8; 32]).unwrap();
    shares.insert(1, other);
    std::fs::write(
        dir.join("sigshare-2.frost"),
        public_file(SIGSHARE_TAG, &sigshare_body(&session, &digest, 2, &shares)),
    )
    .unwrap();
    let out = w.dir.path().join("flipped.json");
    let console = Script::silent();
    let args = aggregate_args(&w, "1,2", &dir, &out);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let e = exec(&refs, &console).unwrap_err();
    assert_eq!(e.code(), "THRESHOLD_SHARE_INVALID");
    assert!(e.to_string().contains("[2]"), "{e}");
    assert!(console.said().is_empty() && !out.exists());

    // Party 2's commitment replaced after signing: the commitment set digest differs.
    let dir = w.sub("recommitted");
    complete_session(&w, &dir);
    let fresh: BTreeMap<usize, Commitment> = [0usize, 1]
        .into_iter()
        .map(|i| (i, commit(&w.group.shares[&2]).1))
        .collect();
    std::fs::write(
        dir.join("commit-2.frost"),
        public_file(COMMIT_TAG, &commit_body(&session, 2, &fresh).unwrap()),
    )
    .unwrap();
    assert_eq!(
        refuse_args(&aggregate_args(&w, "1,2", &dir, &out)),
        "FROST_SESSION_MISMATCH"
    );

    // A signature-share file of another sender, and one that is not a file of its kind.
    let dir = w.sub("swapped");
    complete_session(&w, &dir);
    std::fs::copy(dir.join("sigshare-1.frost"), dir.join("sigshare-2.frost")).unwrap();
    assert_eq!(
        refuse_args(&aggregate_args(&w, "1,2", &dir, &out)),
        "FROST_SESSION_MISMATCH"
    );
    std::fs::write(dir.join("sigshare-2.frost"), "impulse-frost-sigshare-v1:00").unwrap();
    assert_eq!(
        refuse_args(&aggregate_args(&w, "1,2", &dir, &out)),
        "FROST_FILE_MALFORMED"
    );
    assert!(!out.exists());

    // Files of the right session and sender that carry another set of inputs: a subset, a
    // repeated input, an input that is not an authority input; and trailing bytes.
    let dir = w.sub("inputs");
    complete_session(&w, &dir);
    let c2 = read_commit(&dir.join("commit-2.frost"), &session, 2, &[0, 1]).unwrap();
    let (digest, z2) = read_sigshare(&dir.join("sigshare-2.frost"), &session, 2, &[0, 1]).unwrap();
    let (c0, c1) = (c2[&0], c2[&1]);
    let (z0, z1) = (z2[&0], z2[&1]);
    let commits: [InputSetCase<Commitment>; 4] = [
        ("subset", 1, vec![(0, c0)], &[], "FROST_SESSION_MISMATCH"),
        (
            "repeated",
            3,
            vec![(0, c0), (1, c1), (1, c1)],
            &[],
            "FROST_SESSION_MISMATCH",
        ),
        (
            "foreign",
            2,
            vec![(0, c0), (7, c1)],
            &[],
            "FROST_SESSION_MISMATCH",
        ),
        (
            "trailing",
            2,
            vec![(0, c0), (1, c1)],
            &[0],
            "FROST_FILE_MALFORMED",
        ),
    ];
    let honest_commit = std::fs::read(dir.join("commit-2.frost")).unwrap();
    for (label, count, entries, trailing, code) in commits {
        let mut body = session.to_vec();
        body.extend_from_slice(&[0, 2]);
        body.extend_from_slice(&count.to_be_bytes());
        for (input, c) in entries {
            body.extend_from_slice(&input.to_be_bytes());
            body.extend_from_slice(&c.to_bytes().unwrap());
        }
        body.extend_from_slice(trailing);
        std::fs::write(dir.join("commit-2.frost"), public_file(COMMIT_TAG, &body)).unwrap();
        let args = aggregate_args(&w, "1,2", &dir, &out);
        assert_eq!(refuse_args(&args), code, "commit file, {label}");
    }
    std::fs::write(dir.join("commit-2.frost"), honest_commit).unwrap();
    let sigshares: [InputSetCase<SignatureShare>; 4] = [
        ("subset", 1, vec![(0, z0)], &[], "FROST_SESSION_MISMATCH"),
        (
            "repeated",
            3,
            vec![(0, z0), (1, z1), (1, z1)],
            &[],
            "FROST_SESSION_MISMATCH",
        ),
        (
            "foreign",
            2,
            vec![(0, z0), (7, z1)],
            &[],
            "FROST_SESSION_MISMATCH",
        ),
        (
            "trailing",
            2,
            vec![(0, z0), (1, z1)],
            &[0],
            "FROST_FILE_MALFORMED",
        ),
    ];
    for (label, count, entries, trailing, code) in sigshares {
        let mut body = session.to_vec();
        body.extend_from_slice(&digest);
        body.extend_from_slice(&[0, 2]);
        body.extend_from_slice(&count.to_be_bytes());
        for (input, z) in entries {
            body.extend_from_slice(&input.to_be_bytes());
            body.extend_from_slice(&z.to_bytes());
        }
        body.extend_from_slice(trailing);
        std::fs::write(
            dir.join("sigshare-2.frost"),
            public_file(SIGSHARE_TAG, &body),
        )
        .unwrap();
        let args = aggregate_args(&w, "1,2", &dir, &out);
        assert_eq!(refuse_args(&args), code, "sigshare file, {label}");
    }
    // The session field alone changed: the digest and the shares are those of this session.
    let other_session = w.session(&[1, 2, 3]);
    std::fs::write(
        dir.join("sigshare-2.frost"),
        public_file(
            SIGSHARE_TAG,
            &sigshare_body(&other_session, &digest, 2, &z2),
        ),
    )
    .unwrap();
    let args = aggregate_args(&w, "1,2", &dir, &out);
    assert_eq!(
        refuse_args(&args),
        "FROST_SESSION_MISMATCH",
        "session field"
    );
    assert!(!out.exists());
}

/// A tampered session file: label, entry count, entries (input index and value), trailing
/// bytes, and the code that refuses it.
type InputSetCase<T> = (
    &'static str,
    u16,
    Vec<(u32, T)>,
    &'static [u8],
    &'static str,
);

/// A fee input locked to the authority key is not signed: sign, the signing module and
/// aggregate refuse the IPST before anything is printed, read or written.
#[test]
fn a_fee_input_locked_to_the_authority_key_is_never_signed() {
    let control = sign_world();
    let dir = control.sub("control");
    complete_session(&control, &dir);
    let out = control.dir.path().join("out.json");
    run_args(&aggregate_args(&control, "1,2", &dir, &out))
        .0
        .expect("control");
    let w = sign_world_with(world::Cash::Kas, |authority| {
        world::settle_ipst(Some(authority), Network::Testnet, &authority)
    });
    let dir = w.sub("own-fee");
    assert_eq!(
        refuse_args(&w.sign_args(1, "1,2", &dir)),
        "FROST_AUTHORITY_INPUT_NOT_VAULT"
    );
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing written"
    );
    let answer = honest(&w);
    let missing = Path::new("/nonexistent/share");
    let (r, reached) = sign_direct(&w, missing, &[1, 2], false, &answer);
    assert_eq!(
        r.unwrap_err().code(),
        "FROST_AUTHORITY_INPUT_NOT_VAULT",
        "before the share file is opened"
    );
    assert!(!reached);
    let out = w.dir.path().join("out.json");
    assert_eq!(
        refuse_args(&aggregate_args(&w, "1,2", &dir, &out)),
        "FROST_AUTHORITY_INPUT_NOT_VAULT"
    );
    assert!(!out.exists());
}

/// The last step before a share signs is the signer typing back the session shown with the
/// transaction.
#[test]
fn the_signer_types_the_session_back_before_its_share_signs() {
    let w = sign_world();
    let control = w.sub("control");
    party1_signs(&w, &control, CoFault::None)
        .0
        .expect("control");
    assert!(control.join("sigshare-1.frost").exists());
    for (fault, code) in [
        (CoFault::WrongApproval, "FROST_NOT_CONFIRMED"),
        (CoFault::EndAtApproval, "FROST_ABORTED"),
    ] {
        let dir = w.sub(&format!("{fault:?}"));
        let (r, said, _, _) = party1_signs(&w, &dir, fault);
        assert_eq!(r.unwrap_err().code(), code, "{fault:?}");
        assert!(said.iter().any(|l| l.starts_with("> sign: ")), "{fault:?}");
        assert!(
            !dir.join("sigshare-1.frost").exists(),
            "{fault:?}: no share out"
        );
    }
}

/// On mainnet the DAA score comes from the node: the same arguments that are refused with a typed
/// score sign with `--node`.
#[test]
fn mainnet_signing_reads_the_daa_score_from_the_node() {
    let w = sign_world_on(Network::Mainnet);
    let dir = w.sub("mainnet");
    let mainnet = |mut args: Vec<String>| {
        args.splice(0..0, ["--network".to_string(), "mainnet".to_string()]);
        args
    };
    let typed = mainnet(w.sign_args(1, "1,2", &dir));
    assert_eq!(refuse_args(&typed), "CLI_MAINNET_NEEDS_NODE");
    let mut args = w.sign_args(1, "1,2", &dir);
    assert_eq!(args[12], "--daa");
    args[12] = "--node".into();
    args[13] = "wss://node.example".into();
    let args = mainnet(args);
    let (r, said, c2, n2) = party1_signs_with(&w, &dir, CoFault::None, args, Some(mainnet_node));
    r.expect("mainnet signs with the score read from the node");
    assert!(said
        .iter()
        .any(|l| l.starts_with("ok: party 1 signed inputs 0, 1")));
    party2_signs(&w, &dir, &c2, n2);
    let out = w.dir.path().join("signed.json");
    let (r, _) = run_args(&mainnet(aggregate_args(&w, "1,2", &dir, &out)));
    r.expect("aggregates on mainnet");
    let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(signed.pending(), vec![3]);
}

/// KCC-20 cash, external cash and a refund by the authority sign and aggregate through the
/// commands as the KAS-cash settle does.
#[test]
fn kcc20_cash_external_cash_and_an_authority_refund_sign_through_the_commands() {
    let payer = world::label_key("frost/payer");
    let settle_with = |cash| {
        move |authority| world::settle_ipst_with(cash, Some(authority), Network::Testnet, &payer)
    };
    let kcc20 = sign_world_with(world::Cash::Kcc20, settle_with(world::Cash::Kcc20));
    let external = sign_world_with(world::Cash::External, settle_with(world::Cash::External));
    let refund = sign_world_with(world::Cash::Kas, |authority| {
        world::authority_refund_ipst(authority, Network::Testnet, &payer)
    });
    for (label, w, inputs, kind) in [
        ("KCC-20 cash", &kcc20, vec![0, 1], "transaction: settle "),
        ("external cash", &external, vec![0], "transaction: settle "),
        (
            "refund",
            &refund,
            vec![0],
            "transaction: refund of the asset leg, triggered by Authority",
        ),
    ] {
        assert_eq!(w.inputs(), inputs, "{label}");
        let dir = w.sub("session");
        let (r, said, c2, n2) = party1_signs(w, &dir, CoFault::None);
        r.unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(
            said.iter().any(|l| l.starts_with(kind)),
            "{label}: {said:?}"
        );
        party2_signs(w, &dir, &c2, n2);
        let out = w.dir.path().join("signed.json");
        let (r, _) = run_args(&aggregate_args(w, "1,2", &dir, &out));
        r.unwrap_or_else(|e| panic!("{label}: {e}"));
        let signed = Ipst::from_json(&std::fs::read_to_string(&out).unwrap()).unwrap();
        for &input in &inputs {
            let sig = signed.slots()[input].signature().expect("signed");
            let sighash = tx::sighash(w.ipst.transaction(), w.ipst.entries(), input).unwrap();
            verify(
                &w.group.key.authority_key(),
                &sighash,
                sig[..64].try_into().unwrap(),
            )
            .unwrap_or_else(|e| panic!("{label}, input {input}: {e}"));
        }
        let fee_input = w.ipst.slots().len() - 1;
        assert_eq!(signed.pending(), vec![fee_input], "{label}");
    }
    // KCC-20 cash without its template: the terms check cannot run, so nothing is signed.
    let dir = kcc20.sub("no-template");
    let mut args = kcc20.sign_args(1, "1,2", &dir);
    let at = args.iter().position(|x| x == "--cash-template").unwrap();
    args.drain(at..at + 2);
    assert_eq!(refuse_args(&args), "TX_TOKEN_TEMPLATE");
}

// =============================================================================================
// signing::sign with a FROST share: the module's own checks
// =============================================================================================

/// `signing::sign` for party `me` with `signers`; party 2 is played by the exchange (when the
/// set has it). Returns the result and whether the exchange was reached.
fn sign_direct(
    w: &SignWorld,
    share_file: &Path,
    signers: &[PartyId],
    mainnet_explicit: bool,
    answer: &Answer<'_>,
) -> (Result<signing::FrostSigned, CliError>, bool) {
    let reached = RefCell::new(false);
    let exchange = |me: PartyId, mine: &BTreeMap<usize, Commitment>| {
        *reached.borrow_mut() = true;
        Ok(answer(me, mine))
    };
    let signers: BTreeSet<PartyId> = signers.iter().copied().collect();
    let r = signing::sign(&FrostSignRequest {
        share_file,
        mainnet_explicit,
        ipst: &w.ipst,
        signers: &signers,
        exchange: &exchange,
    });
    (r, reached.into_inner())
}

/// Party 2's commitments for both authority inputs.
fn honest(w: &SignWorld) -> impl Fn(PartyId, &BTreeMap<usize, Commitment>) -> CommitmentSet + '_ {
    move |_, _| {
        let c: BTreeMap<usize, Commitment> = [0usize, 1]
            .into_iter()
            .map(|i| (i, commit(&w.group.shares[&2]).1))
            .collect();
        BTreeMap::from([(2, c)])
    }
}

#[test]
fn the_network_rule_comes_before_the_share_file_is_opened() {
    let w = sign_world_on(Network::Mainnet);
    let missing = Path::new("/nonexistent/share");
    let answer = honest(&w);
    let (r, reached) = sign_direct(&w, missing, &[1, 2], false, &answer);
    assert_eq!(r.unwrap_err().code(), "SIGN_MAINNET_NOT_EXPLICIT");
    assert!(!reached);
    let (r, _) = sign_direct(&w, &w.shares[&1], &[1, 2], true, &answer);
    let signed = r.expect("control: mainnet with --network mainnet");
    assert_eq!((signed.party, signed.shares.len()), (1, 2));
    let t = sign_world();
    let answer = honest(&t);
    let (r, reached) = sign_direct(&t, missing, &[1, 2], true, &answer);
    assert_eq!(r.unwrap_err().code(), "SIGN_NETWORK_MISMATCH");
    assert!(!reached);
}

#[test]
fn the_share_file_is_owner_only_and_exactly_its_encoding() {
    let w = sign_world();
    let answer = honest(&w);
    let (r, _) = sign_direct(&w, &w.shares[&1], &[1, 2], false, &answer);
    r.expect("control");
    let content = std::fs::read(&w.shares[&1]).unwrap();
    let dir = TempDir::new();
    for (i, mode) in [0o640, 0o604, 0o660, 0o601, 0o610].into_iter().enumerate() {
        let p = dir.path().join(format!("loose{i}"));
        write_mode(&p, &content, mode);
        let (r, reached) = sign_direct(&w, &p, &[1, 2], false, &answer);
        assert_eq!(
            r.unwrap_err().code(),
            "FROST_SHARE_FILE_PERMISSIONS",
            "{mode:o}"
        );
        assert!(!reached);
    }
    let p = dir.path().join("readonly");
    write_mode(&p, &content, 0o400);
    assert!(
        sign_direct(&w, &p, &[1, 2], false, &answer).0.is_ok(),
        "control 0400"
    );
    let text = String::from_utf8(content.clone()).unwrap();
    let hexpart = text.trim_end().split(':').nth(1).unwrap().to_string();
    let other = std::fs::read_to_string(&w.shares[&2]).unwrap();
    let other_hex = other.trim_end().split(':').nth(1).unwrap();
    // The public share of party 2 in party 1's share: 6 + 32 bytes in, 33 bytes long.
    let swapped = format!(
        "{}{}{}",
        &hexpart[..76],
        &other_hex[76..142],
        &hexpart[142..]
    );
    let refused = [
        format!("{SHARE_TAG}:{hexpart}\n\n"),
        format!("{SHARE_TAG}:{hexpart}\r\n"),
        format!("{SHARE_TAG}:{}\n", hexpart.to_uppercase()),
        format!("{SHARE_TAG}:{}\n", &hexpart[2..]),
        format!("{SHARE_TAG}:{hexpart}00\n"),
        format!("impulse-frost-group-v1:{hexpart}\n"),
        format!("{SHARE_TAG}:{swapped}\n"),
        "a".repeat(600),
        String::new(),
    ];
    for (i, bad) in refused.iter().enumerate() {
        let p = dir.path().join(format!("bad{i}"));
        write_mode(&p, bad.as_bytes(), 0o600);
        let (r, reached) = sign_direct(&w, &p, &[1, 2], false, &answer);
        let e = r.unwrap_err();
        assert_eq!(e.code(), "FROST_SHARE_FILE_FORMAT", "case {i}");
        assert!(!reached);
        // No refusal carries the share.
        assert!(!format!("{e} {e:?}").contains(&hexpart[12..76]), "case {i}");
    }
    let p = dir.path().join("no-final-line-feed");
    write_mode(&p, text.trim_end().as_bytes(), 0o600);
    assert!(
        sign_direct(&w, &p, &[1, 2], false, &answer).0.is_ok(),
        "control"
    );
    for path in [
        dir.path(),
        Path::new("/nonexistent/share"),
        Path::new("/dev/null"),
    ] {
        let (r, reached) = sign_direct(&w, path, &[1, 2], false, &answer);
        assert_eq!(
            r.unwrap_err().code(),
            "FROST_SHARE_FILE_UNREADABLE",
            "{path:?}"
        );
        assert!(!reached);
    }
}

#[test]
fn signing_checks_the_share_and_the_set_before_any_nonce_leaves() {
    let w = sign_world();
    let answer = honest(&w);
    assert!(
        sign_direct(&w, &w.shares[&1], &[1, 2], false, &answer)
            .0
            .is_ok(),
        "control"
    );
    let other = lib_keygen(2, 3);
    let dir = TempDir::new();
    let foreign = dir.path().join("foreign.frost");
    write_share(&foreign, &other.shares[&1]);
    for (share, set, code) in [
        (foreign.as_path(), &[1u16, 2][..], "FROST_KEY_NOT_AUTHORITY"),
        (
            w.shares[&1].as_path(),
            &[1][..],
            "THRESHOLD_TOO_FEW_SIGNERS",
        ),
        (w.shares[&1].as_path(), &[1, 4][..], "THRESHOLD_PARTY"),
        (
            w.shares[&1].as_path(),
            &[2, 3][..],
            "THRESHOLD_SIGNER_NOT_IN_SET",
        ),
    ] {
        let (r, reached) = sign_direct(&w, share, set, false, &answer);
        assert_eq!(r.unwrap_err().code(), code, "{set:?}");
        assert!(!reached, "{code}: the exchange was reached");
    }
}

#[test]
fn signing_refuses_an_incomplete_commitment_set() {
    let w = sign_world();
    let good = honest(&w);
    assert!(
        sign_direct(&w, &w.shares[&1], &[1, 2], false, &good)
            .0
            .is_ok(),
        "control"
    );
    let one_input = |me: PartyId, mine: &BTreeMap<usize, Commitment>| {
        let mut set = good(me, mine);
        set.get_mut(&2).unwrap().remove(&1);
        set
    };
    let another_party = |me: PartyId, mine: &BTreeMap<usize, Commitment>| {
        let c = good(me, mine).remove(&2).unwrap();
        BTreeMap::from([(3, c)])
    };
    let extra_party = |me: PartyId, mine: &BTreeMap<usize, Commitment>| {
        let mut set = good(me, mine);
        let c = set[&2].clone();
        set.insert(3, c);
        set
    };
    let nobody = |_: PartyId, _: &BTreeMap<usize, Commitment>| CommitmentSet::new();
    let faults: [&Answer<'_>; 4] = [&one_input, &another_party, &extra_party, &nobody];
    for (i, f) in faults.into_iter().enumerate() {
        let (r, _) = sign_direct(&w, &w.shares[&1], &[1, 2], false, f);
        assert_eq!(r.unwrap_err().code(), "FROST_SESSION_MISMATCH", "case {i}");
    }
}

// =============================================================================================
// Source guards
// =============================================================================================

fn sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = vec![];
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        out.push((name, std::fs::read_to_string(&path).unwrap()));
    }
    out
}

/// Only `keygen` and `signing` (and this test-only file) name a FROST secret or a FROST signing
/// call; `keygen` has one entry point; this file is compiled only under `cfg(test)`.
#[test]
fn frost_secrets_stay_in_keygen_and_signing() {
    let secret_words = [
        "KeyShare",
        "SigningNonces",
        "DkgRound1Secret",
        "DkgRound2Secret",
        "DkgRound2Package",
        "dkg_round",
        "sign_input",
        "read_share_file",
    ];
    let allowed = ["keygen.rs", "signing.rs", "frost_tests.rs"];
    for (name, text) in sources() {
        if allowed.contains(&name.as_str()) {
            continue;
        }
        for word in secret_words {
            assert!(!text.contains(word), "{name} names {word}");
        }
    }
    let lib = include_str!("lib.rs");
    assert!(lib.contains("#[cfg(test)]\nmod frost_tests;"));
    let keygen = include_str!("keygen.rs");
    assert_eq!(keygen.matches("\npub fn ").count(), 1, "one entry point");
    assert!(keygen.contains("\npub fn run(req: &KeygenRequest)"));
    let signing = include_str!("signing.rs");
    assert!(signing.contains("read_share_file(") && !keygen.contains("read_share_file("));
}

/// The CLI signs and aggregates only through the typed entry points, which compute each
/// input's SIG_HASH_ALL sighash themselves: no source calls or imports the raw-digest `sign`
/// or `aggregate` of `impulse_core::threshold`.
#[test]
fn the_cli_never_signs_or_aggregates_a_handed_digest() {
    for (name, text) in sources() {
        if name == "frost_tests.rs" {
            continue;
        }
        assert!(!text.contains("threshold::sign("), "{name}");
        assert!(!text.contains("threshold::aggregate("), "{name}");
        let mut rest = text.as_str();
        while let Some(at) = rest.find("impulse_core::threshold::") {
            let tail = &rest[at..];
            let end = tail.find(';').unwrap();
            let imported: Vec<&str> = tail[..end]
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .collect();
            assert!(
                !imported.contains(&"sign") && !imported.contains(&"aggregate"),
                "{name}: {}",
                &tail[..end]
            );
            rest = &tail[end..];
        }
    }
}
