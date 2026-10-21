// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The pinned KCC-20 templates (spec/VERIFY.md, "Token warnings"): kcc20.sil from silverscript
//! v1.0.0 (commit 3ed9733, tests/engine/fixtures/kcc20/kcc20.sil), compiled with the pinned
//! silverc for every `maxCovIns` and `maxCovOuts` from 1 to 4. The engine test
//! `the_pinned_kcc20_templates_are_kcc20_sil_built_with_the_pinned_compiler` recompiles each one
//! and fails on any difference.

use super::{PinnedKcc20, TemplateTriple};

/// (maxCovIns, maxCovOuts, template hash, prefix length, suffix length) of each build.
pub const PINNED_KCC20_TEMPLATES: [PinnedKcc20; 16] = [
    pin(
        1,
        1,
        "d7fe87e5cc7f41bf3f76ada9b8ef049fa65e53f98f96bdbf29655dca2964a0d1",
        1,
        982,
    ),
    pin(
        1,
        2,
        "22661f8f4a037171eabca9413960dbee2e976fa463a7d246105cd813f75c95d9",
        1,
        1181,
    ),
    pin(
        1,
        3,
        "17172653fb9891e28159fa59ef676b4c5876f8ad5b798beacad29bc870bd7201",
        1,
        1380,
    ),
    pin(
        1,
        4,
        "fdf42635d060d7448300b1e19660a5e0e9f064bc925b3874a56a85f8da1463e6",
        1,
        1579,
    ),
    pin(
        2,
        1,
        "e08f8f5bc26b818cb58cfe6cbdd26be0933c8a3e3ffe6b737179fe7dcbb0ac6d",
        1,
        1261,
    ),
    pin(
        2,
        2,
        "2a5713a61a2c350c9f76583746d95054ef6bb4160e1c338239249549929b9c9c",
        1,
        1460,
    ),
    pin(
        2,
        3,
        "410eff1477ed2e91e88e69422559c4351984d2474213148ef89e75a0a3668a34",
        1,
        1659,
    ),
    pin(
        2,
        4,
        "8bff7b5c26e088533841ddf527b5cb0ffd1e5e354b169a570348250047fbf512",
        1,
        1858,
    ),
    pin(
        3,
        1,
        "94abdcc0c338006f3d6b7f1cc64339413b955d33e8b655616e0db37d3d65b635",
        1,
        1540,
    ),
    pin(
        3,
        2,
        "7c57e2a9a33592a0b1fbdcd10c532593899f3dc52a50a851eb81f4981f12eeeb",
        1,
        1739,
    ),
    pin(
        3,
        3,
        "0fea2ae2be02d1309759bc67a418de02a1d5fedd9119dfb8cb8c2aed9fa45ec7",
        1,
        1938,
    ),
    pin(
        3,
        4,
        "0efb919b936424d3c795a8e8d64512e5a364a150059bb1859909614e739e43e8",
        1,
        2137,
    ),
    pin(
        4,
        1,
        "b7d14bad5d6a32bfbde87f93326f831e3767abba4b64afa4a5de59bbb62abae9",
        1,
        1819,
    ),
    pin(
        4,
        2,
        "2b9dd575aa7436ac02774f0f1dac2451bff49d667c663f5c7711079b105b344b",
        1,
        2018,
    ),
    pin(
        4,
        3,
        "13cf64b1a9a5a9e8b97c6dc3c046617ae0f601fd1a0452f27d772220a83cd0b4",
        1,
        2217,
    ),
    pin(
        4,
        4,
        "a61ae732e17795a6617a9b0cd0f6be7eb908a532022c1acd45e04e7caa5bfde1",
        1,
        2416,
    ),
];

const fn pin(ins: u8, outs: u8, hash: &str, prefix_len: u64, suffix_len: u64) -> PinnedKcc20 {
    PinnedKcc20 {
        max_cov_ins: ins,
        max_cov_outs: outs,
        triple: TemplateTriple {
            hash: hex32(hash),
            prefix_len,
            suffix_len,
        },
    }
}

/// 64 lowercase hex digits as 32 bytes, at compile time; anything else fails the build.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "not 32 bytes of hex");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
