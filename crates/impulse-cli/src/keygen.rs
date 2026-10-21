// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The only CLI code that generates a FROST key share (spec/THRESHOLD.md, "CLI", `impulse frost
//! keygen`). One entry point, [`run`]: one party's three rounds of FROST distributed key
//! generation, in one process, with no dealer.
//!
//! What it writes: this party's public round-1 file; one round-2 file per other party, each
//! carrying a secret share for that party alone, created new with mode 0600; and, only after the
//! party typed back the group fingerprint every party reported, the share file the party named
//! (created new, mode 0600) and the public group file. It removes the round-2 files addressed to
//! this party once the share file is written (an unlink, which does not overwrite the content on
//! disk), and reports any it cannot remove. The round-1 and round-2 secrets live in this
//! process's memory, inside FROST types erased on drop, and are never written. Nothing here
//! prints, logs or sends a secret: the console sees paths, digests, the authority key and the
//! fingerprint only.

use crate::error::CliError;
use crate::frost::{
    confirm, envelope, malformed, open_envelope, public_file, read_file, read_public, round1_name,
    round2_name, session_mismatch, threshold_error, wait_for, Body, Console, ReadRules, GROUP_TAG,
    ROUND1_TAG, ROUND2_TAG, SHARE_TAG,
};
use crate::json::hex;
use crate::terms_file::write_new;
use impulse_core::threshold::{
    dkg_round1, dkg_round1_digest, dkg_round2, dkg_round3, DkgRound1Package, DkgRound2Package,
    GroupShape, PartyId,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One party's key generation.
pub struct KeygenRequest<'a> {
    pub shape: GroupShape,
    pub party: PartyId,
    /// The directory the round files are exchanged through.
    pub dir: &'a Path,
    /// Where the key share goes; must not exist.
    pub share_file: &'a Path,
    /// Where the group file goes; must not exist.
    pub group_file: &'a Path,
    pub console: &'a dyn Console,
}

/// What a finished key generation reports. Public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeygenDone {
    pub authority_key: [u8; 32],
    pub fingerprint: [u8; 32],
    /// The round-2 files addressed to this party, removed after the share file was written.
    pub removed: Vec<PathBuf>,
    /// The round-2 files addressed to this party that could not be removed, and why.
    pub not_removed: Vec<(PathBuf, String)>,
}

const ROUND2_FILE: ReadRules = ReadRules {
    unreadable: "CLI_FILE_READ",
    permissions: Some("FROST_FILE_PERMISSIONS"),
    too_long: "FROST_FILE_MALFORMED",
    limit: 256,
};

/// The key generation entry point. The caller has checked the shape, the party, the directory
/// and that the outputs do not exist.
pub fn run(req: &KeygenRequest) -> Result<KeygenDone, CliError> {
    let (shape, me, dir, console) = (req.shape, req.party, req.dir, req.console);
    let others: Vec<PartyId> = (1..=shape.parties()).filter(|&j| j != me).collect();

    // Round 1: commit to this party's polynomial and broadcast it.
    let (secret1, own1) = dkg_round1(shape, me).map_err(threshold_error)?;
    let path = dir.join(round1_name(me));
    let mut body = header(shape, me);
    body.extend_from_slice(&own1.to_bytes().map_err(threshold_error)?);
    write_new(&path, &public_file(ROUND1_TAG, &body))?;
    console.say(&format!(
        "wrote: {} (public: send it to every other party over an authenticated channel; every party must receive the same file)",
        path.display()
    ))?;
    let names: Vec<String> = others.iter().map(|&j| round1_name(j)).collect();
    wait_for(console, "round 1", dir, &names)?;
    let mut round1 = BTreeMap::new();
    for &j in &others {
        round1.insert(j, read_round1(&dir.join(round1_name(j)), shape, j)?);
    }
    let mut transcript = round1.clone();
    transcript.insert(me, own1);
    let digest = dkg_round1_digest(shape, &transcript).map_err(threshold_error)?;
    console.say(&format!("round-1 digest: {}", hex(&digest)))?;
    confirm(console, "round-1 digest", &digest)?;

    // Round 2: one secret share per other party.
    let (secret2, outgoing) = dkg_round2(secret1, &round1).map_err(threshold_error)?;
    for (&j, package) in &outgoing {
        let path = dir.join(round2_name(me, j));
        let mut body = zeroize::Zeroizing::new(header(shape, me));
        body.extend_from_slice(&j.to_be_bytes());
        body.extend_from_slice(&digest);
        body.extend_from_slice(&package.to_bytes()[..]);
        write_secret(&path, &envelope(ROUND2_TAG, &body))?;
        console.say(&format!(
            "wrote: {} (secret: for party {j} only; move it over a confidential, authenticated channel, then delete every copy)",
            path.display()
        ))?;
    }
    drop(outgoing);
    let incoming: Vec<String> = others.iter().map(|&j| round2_name(j, me)).collect();
    wait_for(console, "round 2", dir, &incoming)?;
    let mut round2 = BTreeMap::new();
    for &j in &others {
        let path = dir.join(round2_name(j, me));
        round2.insert(j, read_round2(&path, shape, j, me, &digest)?);
    }

    // Round 3: this party's share and the group key, confirmed before anything is kept.
    let (share, group) = dkg_round3(secret2, &round1, &round2).map_err(threshold_error)?;
    drop(round2);
    console.say(&format!("authority key: {}", hex(&group.authority_key())))?;
    console.say(&format!("group fingerprint: {}", hex(&group.fingerprint())))?;
    confirm(console, "group fingerprint", &group.fingerprint())?;
    let share_bytes = share.to_bytes().map_err(threshold_error)?;
    drop(share);
    write_secret(req.share_file, &envelope(SHARE_TAG, &share_bytes))?;
    drop(share_bytes);
    let group_bytes = group.to_bytes().map_err(threshold_error)?;
    write_new(req.group_file, &public_file(GROUP_TAG, &group_bytes))?;
    let (mut removed, mut not_removed) = (Vec::new(), Vec::new());
    for name in incoming {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(e) => not_removed.push((path, e.to_string())),
        }
    }
    Ok(KeygenDone {
        authority_key: group.authority_key(),
        fingerprint: group.fingerprint(),
        removed,
        not_removed,
    })
}

fn header(shape: GroupShape, sender: PartyId) -> Vec<u8> {
    let mut out = shape.threshold().to_be_bytes().to_vec();
    out.extend_from_slice(&shape.parties().to_be_bytes());
    out.extend_from_slice(&sender.to_be_bytes());
    out
}

/// Creates `path` (it must not exist) with mode 0600 and writes `bytes`.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::new("CLI_OUTPUT_EXISTS", format!("{} exists", path.display()))
        } else {
            CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display()))
        }
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))
}

/// The round-1 file of party `from` for this group shape.
fn read_round1(
    path: &Path,
    shape: GroupShape,
    from: PartyId,
) -> Result<DkgRound1Package, CliError> {
    let bytes = read_public(path, ROUND1_TAG)?;
    let what = "a round-1 file";
    let mut b = Body::new(&bytes, path, what);
    let (t, n, sender) = (b.u16()?, b.u16()?, b.u16()?);
    let package = DkgRound1Package::from_bytes(b.rest()).map_err(|_| malformed(path, what))?;
    check_header(path, shape, (t, n, sender), from)?;
    Ok(package)
}

fn check_header(
    path: &Path,
    shape: GroupShape,
    (t, n, sender): (u16, u16, u16),
    from: PartyId,
) -> Result<(), CliError> {
    if (t, n) != (shape.threshold(), shape.parties()) {
        return Err(session_mismatch(
            path,
            format_args!(
                "made for a {t}-of-{n} group, this is {}-of-{}",
                shape.threshold(),
                shape.parties()
            ),
        ));
    }
    if sender != from {
        return Err(session_mismatch(
            path,
            format_args!("from party {sender}, expected party {from}"),
        ));
    }
    Ok(())
}

/// The round-2 file party `from` sent to party `to`, made for this round-1 transcript.
fn read_round2(
    path: &Path,
    shape: GroupShape,
    from: PartyId,
    to: PartyId,
    digest: &[u8; 32],
) -> Result<DkgRound2Package, CliError> {
    let text = read_file(path, &ROUND2_FILE)?;
    let what = "a round-2 file";
    let bytes = open_envelope(&text, ROUND2_TAG).ok_or_else(|| malformed(path, what))?;
    let mut b = Body::new(&bytes, path, what);
    let (t, n, sender, recipient) = (b.u16()?, b.u16()?, b.u16()?, b.u16()?);
    let transcript = b.array32()?;
    let package = DkgRound2Package::from_bytes(b.rest()).map_err(|_| malformed(path, what))?;
    check_header(path, shape, (t, n, sender), from)?;
    if recipient != to {
        return Err(session_mismatch(
            path,
            format_args!("addressed to party {recipient}, this is party {to}"),
        ));
    }
    if transcript != *digest {
        return Err(session_mismatch(
            path,
            "made for another round-1 transcript (its sender saw other round-1 files)",
        ));
    }
    Ok(package)
}
