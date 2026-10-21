// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! list-core: the issuer list rules of spec/V3-ZK.md sections 5.1, 5.2 and 5.4, shared by the
//! list guest (inside the zkVM) and the host prover. `no_std`; the tree builder needs the `std`
//! feature. The SHA-256 implementation is a parameter so the guest uses the zkVM's accelerated
//! one and the host uses `sha2`; `tests/vectors/zk/` pins both to the same bytes.
#![cfg_attr(not(feature = "std"), no_std)]

/// Fixed depth of every list tree (section 5.1).
pub const DEPTH: usize = 20;
/// Leaf domain tag, 18 ASCII bytes.
pub const LEAF_TAG: &[u8; 18] = b"Impulse/zk/leaf/v1";
/// Journal domain tag, 16 ASCII bytes.
pub const JOURNAL_TAG: &[u8; 16] = b"Impulse/zk/wl/v1";
/// Prefix byte of a node preimage.
pub const NODE_PREFIX: u8 = 0x01;
/// Version byte of the guest input encoding (circuits/README.md, "Guest input").
pub const INPUT_VERSION: u8 = 0x01;
/// Longest journal: tag, root, P2SH vault, P2SH owner.
pub const MAX_JOURNAL_LEN: usize = 16 + 32 + 37 + 37;

/// SHA-256, supplied by the caller.
pub trait Sha256 {
    fn hash(data: &[u8]) -> [u8; 32];
}

/// Why the statement does not hold. In the guest every refusal is a panic, so no receipt exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The input does not parse (version, lengths, trailing bytes).
    Malformed,
    /// The path does not hold exactly `DEPTH` siblings.
    Depth,
    /// `index` is not below 2^DEPTH.
    IndexOutOfRange,
    /// `vault_spk` is not 37 bytes of the P2SH form.
    VaultSpk,
    /// `owner_spk` is neither the Schnorr P2PK form (36 bytes) nor the P2SH form (37 bytes).
    OwnerSpk,
    /// The computed leaf is 32 zero bytes, the empty leaf.
    ZeroLeaf,
    /// The path from the owner's salted leaf does not lead to `root`.
    RootMismatch,
}

/// True for `0x0000 0x20 <32 bytes> 0xac`, a Schnorr P2PK scriptPubKey in silverscript's form.
pub fn is_p2pk(spk: &[u8]) -> bool {
    spk.len() == 36 && spk[0] == 0 && spk[1] == 0 && spk[2] == 0x20 && spk[35] == 0xac
}

/// True for `0x0000 0xaa 0x20 <32 bytes> 0x87`, a P2SH scriptPubKey in silverscript's form.
pub fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 37
        && spk[0] == 0
        && spk[1] == 0
        && spk[2] == 0xaa
        && spk[3] == 0x20
        && spk[36] == 0x87
}

/// LEAF(s, spk) = SHA-256("Impulse/zk/leaf/v1" || s || spk). `spk` must be 36 or 37 bytes.
pub fn leaf<H: Sha256>(salt: &[u8; 32], spk: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 18 + 32 + 37];
    buf[..18].copy_from_slice(LEAF_TAG);
    buf[18..50].copy_from_slice(salt);
    buf[50..50 + spk.len()].copy_from_slice(spk);
    H::hash(&buf[..50 + spk.len()])
}

/// NODE(l, r) = SHA-256(0x01 || l || r).
pub fn node<H: Sha256>(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(l);
    buf[33..65].copy_from_slice(r);
    H::hash(&buf)
}

/// Root from a leaf and its path: at level k, bit k of `index` 0 means the current hash is the
/// left child.
pub fn root_from_path<H: Sha256>(
    leaf: &[u8; 32],
    index: u32,
    siblings: &[[u8; 32]; DEPTH],
) -> [u8; 32] {
    let mut h = *leaf;
    for (k, s) in siblings.iter().enumerate() {
        h = if (index >> k) & 1 == 0 {
            node::<H>(&h, s)
        } else {
            node::<H>(s, &h)
        };
    }
    h
}

/// Root of the tree whose every leaf is empty (32 zero bytes).
pub fn empty_root<H: Sha256>() -> [u8; 32] {
    let mut h = [0u8; 32];
    for _ in 0..DEPTH {
        h = node::<H>(&h, &h);
    }
    h
}

/// The journal J of section 5.2: tag || root || vault_spk || owner_spk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    bytes: [u8; MAX_JOURNAL_LEN],
    len: usize,
}

impl Journal {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Builds J. Refuses a vault or owner scriptPubKey of the wrong form.
pub fn journal(root: &[u8; 32], vault_spk: &[u8], owner_spk: &[u8]) -> Result<Journal, Refusal> {
    if !is_p2sh(vault_spk) {
        return Err(Refusal::VaultSpk);
    }
    if !(is_p2pk(owner_spk) || is_p2sh(owner_spk)) {
        return Err(Refusal::OwnerSpk);
    }
    let mut bytes = [0u8; MAX_JOURNAL_LEN];
    bytes[..16].copy_from_slice(JOURNAL_TAG);
    bytes[16..48].copy_from_slice(root);
    bytes[48..85].copy_from_slice(vault_spk);
    bytes[85..85 + owner_spk.len()].copy_from_slice(owner_spk);
    Ok(Journal {
        bytes,
        len: 85 + owner_spk.len(),
    })
}

/// The guest input, parsed. Encoding (circuits/README.md, "Guest input"):
/// `0x01 || index u32 BE || salt 32 || count u32 BE || count * 32 sibling bytes || root 32 ||
/// vault_len u8 || vault_spk || owner_len u8 || owner_spk`, nothing after.
pub struct Input<'a> {
    pub index: u32,
    pub salt: [u8; 32],
    pub siblings: [[u8; 32]; DEPTH],
    pub root: [u8; 32],
    pub vault_spk: &'a [u8],
    pub owner_spk: &'a [u8],
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        if self.b.len() < n {
            return Err(Refusal::Malformed);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32, Refusal> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn b32(&mut self) -> Result<[u8; 32], Refusal> {
        let mut o = [0u8; 32];
        o.copy_from_slice(self.take(32)?);
        Ok(o)
    }
}

/// Parses the guest input. Step 1 of section 5.4: depth, index range and both scriptPubKey forms.
pub fn parse_input(b: &[u8]) -> Result<Input<'_>, Refusal> {
    let mut r = Reader { b };
    if r.take(1)?[0] != INPUT_VERSION {
        return Err(Refusal::Malformed);
    }
    let index = r.u32()?;
    let salt = r.b32()?;
    let count = r.u32()?;
    if count as usize != DEPTH {
        return Err(Refusal::Depth);
    }
    let mut siblings = [[0u8; 32]; DEPTH];
    for s in siblings.iter_mut() {
        *s = r.b32()?;
    }
    let root = r.b32()?;
    let vl = r.take(1)?[0] as usize;
    let vault_spk = r.take(vl)?;
    let ol = r.take(1)?[0] as usize;
    let owner_spk = r.take(ol)?;
    if !r.b.is_empty() {
        return Err(Refusal::Malformed);
    }
    if (index as u64) >= (1u64 << DEPTH) {
        return Err(Refusal::IndexOutOfRange);
    }
    if !is_p2sh(vault_spk) {
        return Err(Refusal::VaultSpk);
    }
    if !(is_p2pk(owner_spk) || is_p2sh(owner_spk)) {
        return Err(Refusal::OwnerSpk);
    }
    Ok(Input {
        index,
        salt,
        siblings,
        root,
        vault_spk,
        owner_spk,
    })
}

/// The statement of section 5.4: returns J when the owner's salted leaf lies under `root` along
/// the given path, and refuses otherwise. The list guest calls exactly this.
pub fn statement<H: Sha256>(input: &[u8]) -> Result<Journal, Refusal> {
    statement_inner::<H>(input, None)
}

/// Test hook of section 13.4 (`guest_refuses_zero_leaf`): replaces the computed leaf. Not in the
/// guest binary: the guest calls `statement`, which passes no override. A leaf cannot be forced in
/// a real proof, so the guard is only reachable through this hook or a SHA-256 preimage of zero.
#[cfg(feature = "test-hook")]
pub fn statement_with_forced_leaf<H: Sha256>(
    input: &[u8],
    forced: [u8; 32],
) -> Result<Journal, Refusal> {
    statement_inner::<H>(input, Some(forced))
}

fn statement_inner<H: Sha256>(input: &[u8], forced: Option<[u8; 32]>) -> Result<Journal, Refusal> {
    let i = parse_input(input)?;
    let lf = match forced {
        Some(f) => f,
        None => leaf::<H>(&i.salt, i.owner_spk),
    };
    if lf == [0u8; 32] {
        return Err(Refusal::ZeroLeaf);
    }
    if root_from_path::<H>(&lf, i.index, &i.siblings) != i.root {
        return Err(Refusal::RootMismatch);
    }
    journal(&i.root, i.vault_spk, i.owner_spk)
}

#[cfg(feature = "std")]
pub mod tree {
    //! Host-side list tree: roots and paths of a whole list (section 5.1).
    use super::{empty_root, leaf, node, Sha256, DEPTH, INPUT_VERSION};

    /// A path file's content: the owner's index, salt and the DEPTH siblings.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Path {
        pub index: u32,
        pub salt: [u8; 32],
        pub siblings: [[u8; 32]; DEPTH],
    }

    /// A list tree over salted entries. Positions from the list's length on are empty leaves.
    pub struct Tree {
        /// levels[0] are the leaves; levels[k] has the nodes at height k, without the empty tail.
        levels: Vec<Vec<[u8; 32]>>,
        zeros: [[u8; 32]; DEPTH + 1],
        salts: Vec<[u8; 32]>,
    }

    impl Tree {
        /// Builds the tree. `entries` are (salt, scriptPubKey) in list order; 1 to 2^DEPTH of them,
        /// each scriptPubKey of the P2PK or P2SH form.
        pub fn build<H: Sha256>(entries: &[([u8; 32], Vec<u8>)]) -> Result<Tree, &'static str> {
            if entries.is_empty() || entries.len() > (1usize << DEPTH) {
                return Err("list size");
            }
            let mut zeros = [[0u8; 32]; DEPTH + 1];
            for k in 1..=DEPTH {
                zeros[k] = node::<H>(&zeros[k - 1], &zeros[k - 1]);
            }
            debug_assert_eq!(zeros[DEPTH], empty_root::<H>());
            let mut leaves = Vec::with_capacity(entries.len());
            for (s, spk) in entries {
                if !(super::is_p2pk(spk) || super::is_p2sh(spk)) {
                    return Err("list entry");
                }
                leaves.push(leaf::<H>(s, spk));
            }
            let mut levels = vec![leaves];
            for k in 0..DEPTH {
                let cur = &levels[k];
                let mut next = Vec::with_capacity(cur.len().div_ceil(2));
                for pair in cur.chunks(2) {
                    let r = if pair.len() == 2 { pair[1] } else { zeros[k] };
                    next.push(node::<H>(&pair[0], &r));
                }
                levels.push(next);
            }
            Ok(Tree {
                levels,
                zeros,
                salts: entries.iter().map(|e| e.0).collect(),
            })
        }

        pub fn root(&self) -> [u8; 32] {
            self.levels[DEPTH][0]
        }

        pub fn len(&self) -> usize {
            self.levels[0].len()
        }

        pub fn is_empty(&self) -> bool {
            self.levels[0].is_empty()
        }

        /// The path of entry `i`.
        pub fn path(&self, i: usize) -> Option<Path> {
            if i >= self.len() {
                return None;
            }
            let mut siblings = [[0u8; 32]; DEPTH];
            let mut pos = i;
            for (k, s) in siblings.iter_mut().enumerate() {
                let sib = pos ^ 1;
                *s = self.levels[k].get(sib).copied().unwrap_or(self.zeros[k]);
                pos >>= 1;
            }
            Some(Path {
                index: i as u32,
                salt: self.salts[i],
                siblings,
            })
        }
    }

    /// Encodes the guest input of `super::parse_input`. Lengths are written as given, so tests
    /// can encode malformed inputs; `siblings` may hold any number of hashes.
    pub fn encode_input(
        index: u32,
        salt: &[u8; 32],
        siblings: &[[u8; 32]],
        root: &[u8; 32],
        vault_spk: &[u8],
        owner_spk: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 4 + 32 + 4 + 32 * siblings.len() + 32 + 2 + 74);
        v.push(INPUT_VERSION);
        v.extend_from_slice(&index.to_be_bytes());
        v.extend_from_slice(salt);
        v.extend_from_slice(&(siblings.len() as u32).to_be_bytes());
        for s in siblings {
            v.extend_from_slice(s);
        }
        v.extend_from_slice(root);
        v.push(vault_spk.len() as u8);
        v.extend_from_slice(vault_spk);
        v.push(owner_spk.len() as u8);
        v.extend_from_slice(owner_spk);
        v
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::tree::{encode_input, Tree};
    use super::*;
    use sha2::Digest;

    struct S;
    impl Sha256 for S {
        fn hash(d: &[u8]) -> [u8; 32] {
            sha2::Sha256::digest(d).into()
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn p2pk(b: u8) -> Vec<u8> {
        let mut v = vec![0, 0, 0x20];
        v.extend([b; 32]);
        v.push(0xac);
        v
    }
    fn p2sh(b: u8) -> Vec<u8> {
        let mut v = vec![0, 0, 0xaa, 0x20];
        v.extend([b; 32]);
        v.push(0x87);
        v
    }

    #[test]
    fn empty_root_matches_spec() {
        // spec/V3-ZK.md section 5.1.
        assert_eq!(
            empty_root::<S>(),
            hex32("51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503")
        );
    }

    #[test]
    fn preimage_forms() {
        assert!(is_p2pk(&p2pk(1)) && !is_p2sh(&p2pk(1)));
        assert!(is_p2sh(&p2sh(1)) && !is_p2pk(&p2sh(1)));
        let mut bad = p2pk(1);
        bad[35] = 0xab;
        assert!(!is_p2pk(&bad));
        let mut bad = p2sh(1);
        bad[2] = 0xab;
        assert!(!is_p2sh(&bad));
    }

    #[test]
    fn every_path_of_a_small_list_leads_to_the_root() {
        for n in [1usize, 2, 3, 5, 1000] {
            let entries: Vec<_> = (0..n)
                .map(|i| {
                    (
                        [i as u8; 32],
                        if i % 2 == 0 {
                            p2pk(i as u8)
                        } else {
                            p2sh(i as u8)
                        },
                    )
                })
                .collect();
            let t = Tree::build::<S>(&entries).unwrap();
            for i in [0, n / 2, n - 1] {
                let p = t.path(i).unwrap();
                let lf = leaf::<S>(&p.salt, &entries[i].1);
                assert_eq!(
                    root_from_path::<S>(&lf, p.index, &p.siblings),
                    t.root(),
                    "n {n} i {i}"
                );
                let inp = encode_input(
                    p.index,
                    &p.salt,
                    &p.siblings,
                    &t.root(),
                    &p2sh(0xee),
                    &entries[i].1,
                );
                let j = statement::<S>(&inp).unwrap();
                assert_eq!(j.as_bytes().len(), 85 + entries[i].1.len());
            }
            assert!(t.path(n).is_none());
        }
    }

    #[test]
    fn statement_refusals() {
        let entries = vec![([7u8; 32], p2pk(1)), ([8u8; 32], p2sh(2))];
        let t = Tree::build::<S>(&entries).unwrap();
        let p = t.path(0).unwrap();
        let v = p2sh(0xee);
        let ok = encode_input(p.index, &p.salt, &p.siblings, &t.root(), &v, &entries[0].1);
        assert!(statement::<S>(&ok).is_ok());
        // Depth.
        let e = encode_input(
            p.index,
            &p.salt,
            &p.siblings[..19],
            &t.root(),
            &v,
            &entries[0].1,
        );
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::Depth));
        // Index range.
        let e = encode_input(1 << 20, &p.salt, &p.siblings, &t.root(), &v, &entries[0].1);
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::IndexOutOfRange));
        // Wrong root.
        let e = encode_input(p.index, &p.salt, &p.siblings, &[9u8; 32], &v, &entries[0].1);
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::RootMismatch));
        // Wrong salt.
        let e = encode_input(
            p.index,
            &[0u8; 32],
            &p.siblings,
            &t.root(),
            &v,
            &entries[0].1,
        );
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::RootMismatch));
        // Non-member owner.
        let e = encode_input(p.index, &p.salt, &p.siblings, &t.root(), &v, &p2pk(3));
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::RootMismatch));
        // Malformed vault and owner forms.
        let e = encode_input(
            p.index,
            &p.salt,
            &p.siblings,
            &t.root(),
            &p2pk(0xee),
            &entries[0].1,
        );
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::VaultSpk));
        let mut o = entries[0].1.clone();
        o[35] = 0xad;
        let e = encode_input(p.index, &p.salt, &p.siblings, &t.root(), &v, &o);
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::OwnerSpk));
        // Trailing byte and wrong version.
        let mut e = ok.clone();
        e.push(0);
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::Malformed));
        let mut e = ok.clone();
        e[0] = 2;
        assert_eq!(statement::<S>(&e).err(), Some(Refusal::Malformed));
        assert_eq!(
            statement::<S>(&ok[..ok.len() - 1]).err(),
            Some(Refusal::Malformed)
        );
    }

    #[cfg(feature = "test-hook")]
    #[test]
    fn zero_leaf_refused_through_the_hook() {
        // An empty position's path: index 1 of a one-entry list has an empty leaf whose path leads
        // to the root. Forcing the zero leaf there must be refused before the root comparison.
        let entries = vec![([7u8; 32], p2pk(1))];
        let t = Tree::build::<S>(&entries).unwrap();
        let p0 = t.path(0).unwrap();
        let mut sib = [[0u8; 32]; DEPTH];
        sib[0] = leaf::<S>(&p0.salt, &entries[0].1);
        sib[1..DEPTH].copy_from_slice(&p0.siblings[1..DEPTH]);
        assert_eq!(root_from_path::<S>(&[0u8; 32], 1, &sib), t.root());
        let inp = encode_input(1, &[0u8; 32], &sib, &t.root(), &p2sh(0xee), &p2pk(5));
        assert_eq!(
            statement_with_forced_leaf::<S>(&inp, [0u8; 32]).err(),
            Some(Refusal::ZeroLeaf)
        );
    }
}
