// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Proof fixtures for the engine tests (spec/V3-ZK.md section 13.1, 13.2). Everything here except
//! the Groth16 proof bytes is deterministic: lists, salts, roots, paths, vault scriptPubKeys and
//! journals are computed from fixed labels, so `impulse-zk-fixtures --check` recomputes them and
//! compares with the committed files. Groth16 proofs carry the prover's random blinding, so a
//! regenerated proof differs in bytes and is checked by verification instead.
//!
//! Owners are fixture scriptPubKeys: P2PK owners use the x coordinates of the public points G, 2G
//! and 3G (no private key is held or written anywhere); the P2SH owner and the filler entries use
//! hashes of fixed labels. Salts are fixed fixture salts (a salt is not a key, rule 1).
//!
//! Vault scriptPubKeys are STAND-INS until template v3 exists: P2SH scripts whose hash is
//! SHA-256("Impulse/zk/fixture/standin-vault/" || name). They have the exact form the guest and
//! template require, so every proof here is a real receipt of the list guest, and the proof-only
//! engine cases (the gate of template v3 run on its own) are meaningful now. The v3 engine tests
//! that settle a real vault need proofs bound to the real vault addresses: the contract step
//! writes them to a vault map file and reruns `impulse-zk-fixtures --vaults <file>`.

use std::collections::BTreeMap;

use list_core::tree::{Path, Tree};
use serde::{Deserialize, Serialize};

use crate::{sha256, HostSha, PathFile};

/// x coordinate of the secp256k1 generator G.
pub const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// x coordinate of 2G.
pub const G2_X: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// x coordinate of 3G.
pub const G3_X: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

pub fn p2pk(x: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0, 0, 0x20];
    v.extend_from_slice(x);
    v.push(0xac);
    v
}

pub fn p2sh(h: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0, 0, 0xaa, 0x20];
    v.extend_from_slice(h);
    v.push(0x87);
    v
}

fn x(h: &str) -> [u8; 32] {
    hex::decode(h).expect("hex").try_into().expect("32")
}

fn label(s: &str) -> [u8; 32] {
    sha256(s.as_bytes())
}

/// Owner A (P2PK, G), B (P2PK, 2G), D (P2PK, 3G, never listed) and C (P2SH).
pub fn owner(name: &str) -> Vec<u8> {
    match name {
        "A" => p2pk(&x(G_X)),
        "B" => p2pk(&x(G2_X)),
        "D" => p2pk(&x(G3_X)),
        "C" => p2sh(&label("Impulse/zk/fixture/owner/C")),
        _ => panic!("unknown fixture owner {name}"),
    }
}

/// A fixture list: its entries, in order.
pub fn list(name: &str) -> Vec<([u8; 32], Vec<u8>)> {
    let salt = |i: u32| {
        let mut m = b"Impulse/zk/fixture/salt/v1/".to_vec();
        m.extend_from_slice(name.as_bytes());
        m.push(b'/');
        m.extend_from_slice(&i.to_be_bytes());
        sha256(&m)
    };
    match name {
        // One entry: owner A.
        "list1" => vec![(salt(0), owner("A"))],
        // 1,000 entries: B at 0, C at 500, A at 999 (the last position); the rest P2SH fillers.
        "list1000" => (0u32..1000)
            .map(|i| {
                let spk = match i {
                    0 => owner("B"),
                    500 => owner("C"),
                    999 => owner("A"),
                    _ => p2sh(&label(&format!("Impulse/zk/fixture/filler/{i}"))),
                };
                (salt(i), spk)
            })
            .collect(),
        _ => panic!("unknown fixture list {name}"),
    }
}

/// Stand-in vault scriptPubKey for a named vault (see the module documentation).
pub fn standin_vault(name: &str) -> Vec<u8> {
    p2sh(&label(&format!("Impulse/zk/fixture/standin-vault/{name}")))
}

/// One fixture proof to make.
#[derive(Clone, Debug)]
pub struct ProofDef {
    pub name: &'static str,
    /// "list" for the list guest; "forge" for the test-only forging guest.
    pub guest: &'static str,
    pub list: &'static str,
    pub owner: &'static str,
    /// Index of the owner in the list (ignored by the forging guest).
    pub index: usize,
    pub vault: &'static str,
    pub what: &'static str,
}

/// The fixture proofs.
pub fn proof_defs() -> Vec<ProofDef> {
    vec![
        ProofDef {
            name: "a_list1",
            guest: "list",
            list: "list1",
            owner: "A",
            index: 0,
            vault: "asset_list1",
            what: "P2PK owner A in a list of one entry",
        },
        ProofDef {
            name: "a_list1000",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000",
            what: "P2PK owner A at the last position of a list of 1,000 entries",
        },
        ProofDef {
            name: "c_list1000_p2sh",
            guest: "list",
            list: "list1000",
            owner: "C",
            index: 500,
            vault: "asset_list1000_p2sh",
            what: "P2SH owner C in the list of 1,000 entries",
        },
        ProofDef {
            name: "a_list1000_vault_b",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000_b",
            what: "owner A, same root, another vault (another nonce)",
        },
        ProofDef {
            name: "a_list1_at_vault1000",
            guest: "list",
            list: "list1",
            owner: "A",
            index: 0,
            vault: "asset_list1000",
            what: "owner A in list1, bound to the list1000 vault (valid for another root)",
        },
        ProofDef {
            name: "b_list1000",
            guest: "list",
            list: "list1000",
            owner: "B",
            index: 0,
            vault: "asset_list1000",
            what: "member B at the list1000 vault (another member)",
        },
        ProofDef {
            name: "a_list1000_cash_vault",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "cash_list1000",
            what: "owner A bound to the cash vault's scriptPubKey",
        },
        ProofDef {
            name: "a_list1000_kcc20",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000_kcc20",
            what: "owner A at the asset vault of a KCC-20 cash trade",
        },
        ProofDef {
            name: "a_list1000_auth",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000_auth",
            what: "owner A at the asset vault of a trade with an authority (KAS cash)",
        },
        ProofDef {
            name: "a_list1000_swap",
            guest: "list",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000_swap",
            what:
                "P2PK owner A bound to a vault whose terms name the same 32 bytes as a script hash",
        },
        ProofDef {
            name: "forge_a_list1000",
            guest: "forge",
            list: "list1000",
            owner: "A",
            index: 999,
            vault: "asset_list1000",
            what: "TEST ONLY forging guest: commits a_list1000's J without checking a path",
        },
    ]
}

/// Computed public values of a fixture: root, vault and owner scriptPubKeys, path and J.
pub struct Computed {
    pub root: [u8; 32],
    pub vault_spk: Vec<u8>,
    pub owner_spk: Vec<u8>,
    pub path: Path,
    pub journal: Vec<u8>,
}

pub fn compute(def: &ProofDef, vaults: &BTreeMap<String, Vec<u8>>) -> Computed {
    let entries = list(def.list);
    let tree = Tree::build::<HostSha>(&entries).expect("fixture list");
    let path = tree.path(def.index).expect("index");
    assert_eq!(
        entries[def.index].1,
        owner(def.owner),
        "fixture {} index",
        def.name
    );
    let vault_spk = vaults
        .get(def.vault)
        .cloned()
        .unwrap_or_else(|| standin_vault(def.vault));
    let owner_spk = owner(def.owner);
    let journal = list_core::journal(&tree.root(), &vault_spk, &owner_spk)
        .expect("journal")
        .as_bytes()
        .to_vec();
    Computed {
        root: tree.root(),
        vault_spk,
        owner_spk,
        path,
        journal,
    }
}

/// The deterministic part of a fixture, committed as `<name>.inputs.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub name: String,
    pub what: String,
    pub guest: String,
    pub list: String,
    pub list_size: usize,
    pub root: String,
    pub vault: String,
    pub vault_spk: String,
    pub vault_spk_is_standin: bool,
    pub owner: String,
    pub owner_spk: String,
    pub path: PathFile,
    pub journal: String,
    pub journal_hash: String,
}

pub fn inputs(def: &ProofDef, vaults: &BTreeMap<String, Vec<u8>>) -> Inputs {
    let c = compute(def, vaults);
    Inputs {
        name: def.name.into(),
        what: def.what.into(),
        guest: def.guest.into(),
        list: def.list.into(),
        list_size: list(def.list).len(),
        root: hex::encode(c.root),
        vault: def.vault.into(),
        vault_spk: hex::encode(&c.vault_spk),
        vault_spk_is_standin: !vaults.contains_key(def.vault),
        owner: def.owner.into(),
        owner_spk: hex::encode(&c.owner_spk),
        path: PathFile::from_path(&c.path),
        journal: hex::encode(&c.journal),
        journal_hash: hex::encode(sha256(&c.journal)),
    }
}

/// One engine case: a proof (a fixture, possibly altered) against the J and image ID a vault
/// would use. Committed as `cases.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    /// The section 13.2 test this case backs, or "accept".
    pub test: String,
    pub proof_fixture: String,
    /// How the proof bytes are altered: "none", "flip:<byte>:<bit>", "truncate:<len>", "append:<hex>".
    pub alter: String,
    /// J the verifying script computes.
    pub journal: String,
    /// "list" (circuits/IMAGE_ID), "forge" (the forging guest's) or "list-flipped" (one bit off).
    pub image: String,
    /// "accept" or "refuse".
    pub expect: String,
}

fn j_of(name: &str, vaults: &BTreeMap<String, Vec<u8>>) -> String {
    let d = proof_defs()
        .into_iter()
        .find(|d| d.name == name)
        .expect("def");
    hex::encode(compute(&d, vaults).journal)
}

/// J the swap vault computes: its root and scriptPubKey, but the owner named as a script hash
/// over A's 32 bytes (the proof a_list1000_swap commits A as a P2PK owner).
fn j_type_swap(vaults: &BTreeMap<String, Vec<u8>>) -> String {
    let d = proof_defs()
        .into_iter()
        .find(|d| d.name == "a_list1000_swap")
        .expect("def");
    let c = compute(&d, vaults);
    let swapped = p2sh(&x(G_X));
    hex::encode(
        list_core::journal(&c.root, &c.vault_spk, &swapped)
            .expect("j")
            .as_bytes(),
    )
}

pub fn cases(vaults: &BTreeMap<String, Vec<u8>>) -> Vec<Case> {
    let c = |name: &str,
             test: &str,
             fx: &str,
             alter: &str,
             journal: String,
             image: &str,
             expect: &str| Case {
        name: name.into(),
        test: test.into(),
        proof_fixture: fx.into(),
        alter: alter.into(),
        journal,
        image: image.into(),
        expect: expect.into(),
    };
    let j = |n: &str| j_of(n, vaults);
    let mut v = Vec::new();
    for d in proof_defs().iter().filter(|d| d.guest == "list") {
        v.push(c(
            &format!("valid_{}", d.name),
            "accept",
            d.name,
            "none",
            j(d.name),
            "list",
            "accept",
        ));
    }
    v.push(c(
        "forge_control_own_image",
        "accept",
        "forge_a_list1000",
        "none",
        j("a_list1000"),
        "forge",
        "accept",
    ));
    v.push(c(
        "bit_flip_first_byte",
        "v3_proof_bit_flip_refused",
        "a_list1000",
        "flip:0:0",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "bit_flip_middle_byte",
        "v3_proof_bit_flip_refused",
        "a_list1000",
        "flip:64:3",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "bit_flip_last_byte",
        "v3_proof_bit_flip_refused",
        "a_list1000",
        "flip:127:0",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "length_0",
        "v3_proof_length_refused",
        "a_list1000",
        "truncate:0",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "length_127",
        "v3_proof_length_refused",
        "a_list1000",
        "truncate:127",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "length_129",
        "v3_proof_length_refused",
        "a_list1000",
        "append:00",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "other_vault",
        "v3_proof_for_other_vault_refused",
        "a_list1000",
        "none",
        j("a_list1000_vault_b"),
        "list",
        "refuse",
    ));
    v.push(c(
        "other_root",
        "v3_proof_for_other_root_refused",
        "a_list1_at_vault1000",
        "none",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "other_owner",
        "v3_proof_for_other_owner_refused",
        "b_list1000",
        "none",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "owner_type_swap",
        "v3_proof_owner_type_swap_refused",
        "a_list1000_swap",
        "none",
        j_type_swap(vaults),
        "list",
        "refuse",
    ));
    v.push(c(
        "forging_guest",
        "v3_forging_guest_refused",
        "forge_a_list1000",
        "none",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "cash_vault_proof_at_asset_vault",
        "v3_proof_for_cash_vault_refused",
        "a_list1000_cash_vault",
        "none",
        j("a_list1000"),
        "list",
        "refuse",
    ));
    v.push(c(
        "wrong_image_id",
        "image_id_bound",
        "a_list1000",
        "none",
        j("a_list1000"),
        "list-flipped",
        "refuse",
    ));
    v
}

/// Applies a case's alteration to proof bytes.
pub fn alter(proof: &[u8], how: &str) -> Vec<u8> {
    let mut p = proof.to_vec();
    let parts: Vec<&str> = how.split(':').collect();
    match parts.as_slice() {
        ["none"] => {}
        ["flip", byte, bit] => {
            let (b, i): (usize, u8) = (byte.parse().expect("byte"), bit.parse().expect("bit"));
            p[b] ^= 1 << i;
        }
        ["truncate", n] => p.truncate(n.parse().expect("len")),
        ["append", h] => p.extend(hex::decode(h).expect("hex")),
        _ => panic!("unknown alteration {how}"),
    }
    p
}

/// Reads a vault map file: `{ "<vault name>": "<scriptPubKey hex>" }`.
pub fn read_vaults(path: Option<&std::path::Path>) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let Some(p) = path else {
        return Ok(BTreeMap::new());
    };
    let m: BTreeMap<String, String> = crate::read_json(p)?;
    let mut out = BTreeMap::new();
    for (k, v) in m {
        let b = hex::decode(&v).map_err(|_| format!("vault {k}: not hex"))?;
        if !list_core::is_p2sh(&b) {
            return Err(format!("vault {k}: not a P2SH scriptPubKey"));
        }
        out.insert(k, b);
    }
    Ok(out)
}

/// Image ID bytes for a case's `image` field.
pub fn case_image(image: &str) -> [u8; 32] {
    match image {
        "list" => crate::list_guest_image_id(),
        "forge" => crate::forge_guest_image_id(),
        "list-flipped" => {
            let mut i = crate::list_guest_image_id();
            i[31] ^= 1;
            i
        }
        _ => panic!("unknown image {image}"),
    }
}

fn read<T: for<'de> Deserialize<'de>>(dir: &std::path::Path, f: &str) -> Result<T, String> {
    crate::read_json(&dir.join(f))
}

/// Checks a committed fixture directory: every deterministic file equals what this code computes
/// from `vaults.json`, every proof file names the list guest's (or the forging guest's) image ID
/// and its own J, and every case of `cases.json` gives its expected result in the pinned engine.
/// Returns one line per case.
pub fn check_dir(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let vm: BTreeMap<String, String> = read(dir, "vaults.json")?;
    let mut vaults = BTreeMap::new();
    for (k, v) in vm {
        vaults.insert(
            k,
            hex::decode(v).map_err(|_| "vaults.json: hex".to_string())?,
        );
    }
    let mut proofs = BTreeMap::new();
    for d in proof_defs() {
        let committed: Inputs = read(dir, &format!("{}.inputs.json", d.name))?;
        if committed != inputs(&d, &vaults) {
            return Err(format!(
                "{}.inputs.json differs from the recomputed inputs",
                d.name
            ));
        }
        let pf: crate::ProofFile = read(dir, &format!("{}.proof.json", d.name))?;
        let want_image = if d.guest == "forge" {
            crate::forge_guest_image_id()
        } else {
            crate::list_guest_image_id()
        };
        if pf.format != crate::PROOF_FORMAT
            || pf.journal != committed.journal
            || pf.image_id_bytes() != want_image
        {
            return Err(format!(
                "{}.proof.json: format, journal or image ID differs",
                d.name
            ));
        }
        if pf.journal_hash != hex::encode(sha256(&pf.journal_bytes()))
            || pf.proof_bytes().len() != 128
        {
            return Err(format!(
                "{}.proof.json: journal hash or proof length",
                d.name
            ));
        }
        proofs.insert(d.name.to_string(), pf.proof_bytes());
    }
    let committed_cases: Vec<Case> = read(dir, "cases.json")?;
    if committed_cases != cases(&vaults) {
        return Err("cases.json differs from the recomputed cases".into());
    }
    let mut out = Vec::new();
    for c in committed_cases {
        let proof = alter(
            proofs
                .get(&c.proof_fixture)
                .ok_or("case names an unknown fixture")?,
            &c.alter,
        );
        let j = hex::decode(&c.journal).map_err(|_| "case journal hex".to_string())?;
        let r = crate::engine_verify(&proof, &j, case_image(&c.image));
        let got = if r.is_ok() { "accept" } else { "refuse" };
        if got != c.expect {
            return Err(format!(
                "case {}: expected {}, the engine gave {got} ({r:?})",
                c.name, c.expect
            ));
        }
        out.push(format!(
            "{} {} {} {}",
            c.name,
            c.test,
            got,
            r.err().map(|e| e.to_string()).unwrap_or_default()
        ));
    }
    Ok(out)
}
