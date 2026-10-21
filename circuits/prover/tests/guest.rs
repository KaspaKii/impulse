// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Guest host tests of spec/V3-ZK.md section 13.4. Each refusal runs the real list guest ELF (the
//! one circuits/IMAGE_ID names) in the RISC Zero executor: a refusal is a guest panic, so the
//! session fails and no receipt can exist. Execution only; no proving.
use impulse_zk_prover::fixtures::{list, owner, standin_vault};
use impulse_zk_prover::list_core::tree::{encode_input, Tree};
use impulse_zk_prover::list_core::{self, Refusal, DEPTH};
use impulse_zk_prover::{guest_input, HostSha, PathFile, Public};
use risc0_zkvm::{local_executor, ExecutorEnv, ExitCode};

/// Runs the list guest on `input`; Ok(journal) or Err(executor message).
fn run_guest(input: &[u8]) -> Result<Vec<u8>, String> {
    let env = ExecutorEnv::builder()
        .write(&input.to_vec())
        .unwrap()
        .build()
        .unwrap();
    let info = local_executor()
        .execute(env, impulse_zk_methods::LIST_GUEST_ELF)
        .map_err(|e| e.to_string())?;
    assert_eq!(info.exit_code, ExitCode::Halted(0));
    Ok(info.journal.bytes)
}

struct Fx {
    tree: Tree,
    salt: [u8; 32],
    siblings: [[u8; 32]; DEPTH],
    index: u32,
    vault: Vec<u8>,
    owner: Vec<u8>,
}

fn fx() -> Fx {
    let entries = list("list1000");
    let tree = Tree::build::<HostSha>(&entries).unwrap();
    let p = tree.path(999).unwrap();
    Fx {
        salt: p.salt,
        siblings: p.siblings,
        index: p.index,
        tree,
        vault: standin_vault("asset_list1000"),
        owner: owner("A"),
    }
}

fn refused(input: &[u8], want: Refusal) {
    // The shared statement code refuses with the expected reason, and the real guest refuses too.
    assert_eq!(list_core::statement::<HostSha>(input).err(), Some(want));
    let e = run_guest(input).expect_err("the guest must refuse");
    assert!(
        e.contains("impulse list guest refused") || e.to_lowercase().contains("panic"),
        "unexpected failure: {e}"
    );
}

#[test]
fn guest_accepts_member_and_commits_exactly_j() {
    let f = fx();
    let input = encode_input(
        f.index,
        &f.salt,
        &f.siblings,
        &f.tree.root(),
        &f.vault,
        &f.owner,
    );
    let j = run_guest(&input).unwrap();
    let want = list_core::journal(&f.tree.root(), &f.vault, &f.owner).unwrap();
    assert_eq!(j, want.as_bytes());
    assert_eq!(j.len(), 121, "P2PK owner: 16 + 32 + 37 + 36 bytes");
    assert_eq!(&j[..16], b"Impulse/zk/wl/v1");
}

#[test]
fn guest_accepts_p2sh_owner_journal_of_122_bytes() {
    let entries = list("list1000");
    let tree = Tree::build::<HostSha>(&entries).unwrap();
    let p = tree.path(500).unwrap();
    let input = encode_input(
        p.index,
        &p.salt,
        &p.siblings,
        &tree.root(),
        &standin_vault("v"),
        &owner("C"),
    );
    assert_eq!(run_guest(&input).unwrap().len(), 122);
}

#[test]
fn guest_refuses_wrong_depth() {
    let f = fx();
    let root = f.tree.root();
    refused(
        &encode_input(
            f.index,
            &f.salt,
            &f.siblings[..DEPTH - 1],
            &root,
            &f.vault,
            &f.owner,
        ),
        Refusal::Depth,
    );
    let mut more = f.siblings.to_vec();
    more.push([0u8; 32]);
    refused(
        &encode_input(f.index, &f.salt, &more, &root, &f.vault, &f.owner),
        Refusal::Depth,
    );
}

#[test]
fn guest_refuses_index_out_of_range() {
    let f = fx();
    // Bit 20 set: the low 20 bits still select the member's position, so only the range check
    // stops this input.
    let idx = f.index | (1 << DEPTH);
    refused(
        &encode_input(
            idx,
            &f.salt,
            &f.siblings,
            &f.tree.root(),
            &f.vault,
            &f.owner,
        ),
        Refusal::IndexOutOfRange,
    );
    refused(
        &encode_input(
            u32::MAX,
            &f.salt,
            &f.siblings,
            &f.tree.root(),
            &f.vault,
            &f.owner,
        ),
        Refusal::IndexOutOfRange,
    );
}

#[test]
fn guest_refuses_zero_leaf() {
    // Through the test hook of list-core (spec/V3-ZK.md 13.4): the guest binary has no hook, so a
    // zero leaf cannot be forced in the zkVM. The empty position 1 of a one-entry list has a valid
    // path from a zero leaf to the root; with the leaf forced to zero the statement must refuse.
    let entries = list("list1");
    let tree = Tree::build::<HostSha>(&entries).unwrap();
    let p0 = tree.path(0).unwrap();
    let mut sib = p0.siblings;
    sib[0] = list_core::leaf::<HostSha>(&p0.salt, &entries[0].1);
    assert_eq!(
        list_core::root_from_path::<HostSha>(&[0u8; 32], 1, &sib),
        tree.root()
    );
    let input = encode_input(
        1,
        &[0u8; 32],
        &sib,
        &tree.root(),
        &standin_vault("v"),
        &owner("D"),
    );
    assert_eq!(
        list_core::statement_with_forced_leaf::<HostSha>(&input, [0u8; 32]).err(),
        Some(Refusal::ZeroLeaf)
    );
    // Without the hook the real guest computes D's salted leaf, which is not on the path.
    refused(&input, Refusal::RootMismatch);
}

#[test]
fn guest_refuses_wrong_root() {
    let f = fx();
    let other = Tree::build::<HostSha>(&list("list1")).unwrap().root();
    refused(
        &encode_input(f.index, &f.salt, &f.siblings, &other, &f.vault, &f.owner),
        Refusal::RootMismatch,
    );
    let empty = list_core::empty_root::<HostSha>();
    refused(
        &encode_input(f.index, &f.salt, &f.siblings, &empty, &f.vault, &f.owner),
        Refusal::RootMismatch,
    );
}

#[test]
fn guest_refuses_malformed_vault_spk() {
    let f = fx();
    let root = f.tree.root();
    // P2PK form, a P2SH form with a wrong opcode, and one byte short.
    let mut bad = f.vault.clone();
    bad[36] = 0x88;
    for v in [owner("A"), bad, f.vault[..36].to_vec()] {
        refused(
            &encode_input(f.index, &f.salt, &f.siblings, &root, &v, &f.owner),
            Refusal::VaultSpk,
        );
    }
}

#[test]
fn guest_refuses_malformed_owner_spk() {
    let f = fx();
    let root = f.tree.root();
    let mut ecdsa = vec![0, 0, 0x21];
    ecdsa.extend([2u8; 33]);
    ecdsa.push(0xab); // ECDSA P2PK form
    let mut version1 = f.owner.clone();
    version1[1] = 1; // script version 1
    for o in [ecdsa, version1, f.owner[..35].to_vec(), vec![]] {
        refused(
            &encode_input(f.index, &f.salt, &f.siblings, &root, &f.vault, &o),
            Refusal::OwnerSpk,
        );
    }
}

#[test]
fn guest_refuses_non_member() {
    let f = fx();
    let root = f.tree.root();
    // D is in no list; B's own path does not make A a member; a wrong salt for A.
    refused(
        &encode_input(f.index, &f.salt, &f.siblings, &root, &f.vault, &owner("D")),
        Refusal::RootMismatch,
    );
    let pb = f.tree.path(0).unwrap();
    refused(
        &encode_input(pb.index, &pb.salt, &pb.siblings, &root, &f.vault, &f.owner),
        Refusal::RootMismatch,
    );
    refused(
        &encode_input(f.index, &[0x55; 32], &f.siblings, &root, &f.vault, &f.owner),
        Refusal::RootMismatch,
    );
    // Same path at another index.
    refused(
        &encode_input(998, &f.salt, &f.siblings, &root, &f.vault, &f.owner),
        Refusal::RootMismatch,
    );
}

#[test]
fn guest_refuses_malformed_input() {
    let f = fx();
    let ok = encode_input(
        f.index,
        &f.salt,
        &f.siblings,
        &f.tree.root(),
        &f.vault,
        &f.owner,
    );
    let mut trailing = ok.clone();
    trailing.push(0);
    let mut version = ok.clone();
    version[0] = 2;
    for i in [trailing, version, ok[..ok.len() - 1].to_vec(), vec![]] {
        refused(&i, Refusal::Malformed);
    }
}

#[test]
fn prover_refuses_non_member_before_proving() {
    // impulse-zk-prove checks the statement natively first: ZK_PATH_INVALID, no receipt attempted.
    let f = fx();
    let pf = PathFile::from_path(&f.tree.path(999).unwrap());
    let e = guest_input(
        &pf,
        &Public {
            root: f.tree.root(),
            vault_spk: f.vault.clone(),
            owner_spk: owner("D"),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, "ZK_PATH_INVALID");
    let e = guest_input(
        &pf,
        &Public {
            root: [7u8; 32],
            vault_spk: f.vault.clone(),
            owner_spk: f.owner.clone(),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, "ZK_PATH_INVALID");
    let mut bad = pf.clone();
    bad.salt = "zz".into();
    assert_eq!(
        guest_input(
            &bad,
            &Public {
                root: f.tree.root(),
                vault_spk: f.vault,
                owner_spk: f.owner
            }
        )
        .unwrap_err()
        .code,
        "ZK_PATH_INVALID"
    );
}

#[test]
fn committed_image_id_is_the_built_guest() {
    // circuits/IMAGE_ID equals the image ID of the list guest this crate embeds; scripts/build-guest.sh
    // also rebuilds the guest from scratch and compares (ZK_IMAGE_ID_MISMATCH otherwise).
    impulse_zk_prover::check_image_id().unwrap();
    assert_ne!(
        impulse_zk_prover::list_guest_image_id(),
        impulse_zk_prover::forge_guest_image_id()
    );
}

#[test]
fn guest_and_host_hash_agree() {
    // The guest uses the zkVM's SHA-256, the host sha2: the guest's committed J for a 1,000-entry
    // list proves the guest computed the same root as the host (the statement compares roots).
    let f = fx();
    let input = encode_input(
        f.index,
        &f.salt,
        &f.siblings,
        &f.tree.root(),
        &f.vault,
        &f.owner,
    );
    assert!(run_guest(&input).is_ok());
}
