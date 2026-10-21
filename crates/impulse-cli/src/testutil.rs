// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Test helpers: a private temporary directory, removed with everything in it when dropped, and a
//! non-canonical spelling of a Kaspa address.

use std::path::{Path, PathBuf};

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "impulse-cli-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `address` with the padding bit of its last payload character set and the checksum recomputed:
/// it decodes to the same address, but is not that address's canonical text.
pub(crate) fn noncanonical_address(address: &str) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let (prefix, rest) = address.split_once(':').unwrap();
    let mut data: Vec<u8> = rest
        .bytes()
        .map(|b| CHARSET.iter().position(|&c| c == b).unwrap() as u8)
        .collect();
    data.truncate(data.len() - 8);
    assert!(
        !(data.len() * 5).is_multiple_of(8),
        "the payload has a padding bit"
    );
    *data.last_mut().unwrap() |= 1;
    // The bech32 checksum of the Kaspa address format.
    let mut c = 1u64;
    let values = prefix.bytes().map(|b| b & 0x1f).chain([0]);
    for d in values.chain(data.iter().copied()).chain([0; 8]) {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(d);
        for (bit, g) in [
            0x98_f2bc_8e61u64,
            0x79_b76d_99e2,
            0xf3_3e5f_b3c4,
            0xae_2eab_e2a8,
            0x1e_4f43_e470,
        ]
        .into_iter()
        .enumerate()
        {
            if c0 >> bit & 1 != 0 {
                c ^= g;
            }
        }
    }
    let checksum = c ^ 1;
    data.extend((0..8).map(|i| ((checksum >> (5 * (7 - i))) & 0x1f) as u8));
    let text: String = data.iter().map(|&d| CHARSET[d as usize] as char).collect();
    format!("{prefix}:{text}")
}

#[test]
fn a_noncanonical_address_decodes_to_the_same_address() {
    let canonical = kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Testnet,
        kaspa_addresses::Version::ScriptHash,
        &[7; 32],
    )
    .to_string();
    let other = noncanonical_address(&canonical);
    assert_ne!(other, canonical);
    let decoded = kaspa_addresses::Address::try_from(other.as_str()).unwrap();
    assert_eq!(decoded.to_string(), canonical);
}

#[test]
fn temp_dirs_are_removed_on_drop() {
    let dir = TempDir::new();
    let path = dir.path().to_path_buf();
    std::fs::write(path.join("f"), "x").unwrap();
    drop(dir);
    assert!(!path.exists());
}
