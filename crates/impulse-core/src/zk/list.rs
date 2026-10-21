// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The issuer list tree (spec/V3-ZK.md section 5.1): salted leaves, SHA-256 nodes, fixed depth
//! 20. This is the host-side reimplementation of the rules `circuits/list-core` runs in the
//! guest; `tests/vectors/zk/` pins both to the same bytes.
//!
//! The list and its salts are sensitive (section 9.2, finding 16): nothing here prints, logs or
//! sends them. A salt is not a key and signs nothing; it hides its entry, so a [`MemberPath`]
//! erases its salt when dropped and [`ListTree`] erases every salt it holds.

use super::ZkError;
use crate::terms::{IdentifierType, Kcc20Owner, Network};
use kaspa_addresses::{Address, Prefix, Version};
use rand::RngCore;
use secp256k1::XOnlyPublicKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Fixed depth of every list tree.
pub const DEPTH: usize = 20;
/// Most entries a list holds: 2^20.
pub const MAX_ENTRIES: usize = 1 << DEPTH;
/// Leaf domain tag, 18 ASCII bytes.
pub const LEAF_TAG: &[u8; 18] = b"Impulse/zk/leaf/v1";
/// Prefix byte of a node preimage.
pub const NODE_PREFIX: u8 = 0x01;
/// The root of the tree whose every leaf is empty (32 zero bytes), at depth 20.
pub const EMPTY_ROOT: [u8; 32] = [
    0x51, 0xc2, 0x0d, 0x66, 0x00, 0x80, 0x24, 0xc0, 0x4c, 0xf1, 0x14, 0x56, 0x4a, 0x99, 0x8e, 0x49,
    0xef, 0x8f, 0x6e, 0x04, 0x4e, 0x2d, 0x13, 0xa0, 0x3a, 0x66, 0x52, 0x1d, 0x6e, 0x20, 0x05, 0x03,
];

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `LEAF(s, spk) = SHA-256("Impulse/zk/leaf/v1" || s || spk)`, `spk` the 36 or 37 bytes of
/// [`owner_spk`].
pub fn leaf(salt: &[u8; 32], spk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_TAG);
    h.update(salt);
    h.update(spk);
    h.finalize().into()
}

/// `NODE(l, r) = SHA-256(0x01 || l || r)`.
pub fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The empty subtree hashes: `zeros()[k]` is the root of an empty subtree of height k.
fn zeros() -> [[u8; 32]; DEPTH + 1] {
    let mut z = [[0u8; 32]; DEPTH + 1];
    for k in 1..=DEPTH {
        z[k] = node(&z[k - 1], &z[k - 1]);
    }
    z
}

/// Root from a leaf and its path: at level k, bit k of `index` 0 means the current hash is the
/// left child.
pub fn root_from_path(leaf: &[u8; 32], index: u32, siblings: &[[u8; 32]; DEPTH]) -> [u8; 32] {
    let mut h = *leaf;
    for (k, s) in siblings.iter().enumerate() {
        h = if (index >> k) & 1 == 0 {
            node(&h, s)
        } else {
            node(s, &h)
        };
    }
    h
}

/// A scriptPubKey in silverscript's form for a KCC-20 owner: version `0x0000` then the script.
/// A public key owner is the 36-byte Schnorr P2PK `0000 20 <key> ac`, a script hash owner the
/// 37-byte P2SH `0000 aa 20 <hash> 87`. A covenant ID has no scriptPubKey
/// (`ZK_DELIVERY_OWNER_TYPE`).
pub fn owner_spk(owner: &Kcc20Owner) -> Result<Vec<u8>, ZkError> {
    match owner.identifier_type {
        IdentifierType::PubKey => {
            let mut v = Vec::with_capacity(36);
            v.extend_from_slice(&[0x00, 0x00, 0x20]);
            v.extend_from_slice(&owner.identifier);
            v.push(0xac);
            Ok(v)
        }
        IdentifierType::ScriptHash => Ok(p2sh_spk(&owner.identifier).to_vec()),
        IdentifierType::CovenantId => Err(ZkError::DeliveryOwnerType),
    }
}

/// The 37-byte P2SH scriptPubKey `0000 aa 20 <script hash> 87` of a vault.
pub fn p2sh_spk(script_hash: &[u8; 32]) -> [u8; 37] {
    let mut v = [0u8; 37];
    v[2] = 0xaa;
    v[3] = 0x20;
    v[4..36].copy_from_slice(script_hash);
    v[36] = 0x87;
    v
}

/// The two list entry owners an address can be: Schnorr P2PK or P2SH.
fn owner_of_address(text: &str, network: Network, line: usize) -> Result<Kcc20Owner, ZkError> {
    let entry = |reason: String| ZkError::ListEntry { line, reason };
    let address = Address::try_from(text).map_err(|e| {
        entry(format!(
            "not a Kaspa address ({e}); write an address, pubkey:<hex> or scripthash:<hex>"
        ))
    })?;
    let expected = match network {
        Network::Mainnet => Prefix::Mainnet,
        Network::Testnet => Prefix::Testnet,
    };
    if address.prefix != expected {
        return Err(entry(format!(
            "address of another network (this list is for {})",
            match network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
            }
        )));
    }
    let identifier_type = match address.version {
        Version::PubKey => IdentifierType::PubKey,
        Version::ScriptHash => IdentifierType::ScriptHash,
        Version::PubKeyECDSA => {
            return Err(entry(
                "an ECDSA address is not accepted; only Schnorr P2PK and P2SH".into(),
            ))
        }
    };
    let identifier: [u8; 32] = address
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| entry("the address payload is not 32 bytes".into()))?;
    checked_owner(identifier_type, identifier, line)
}

fn checked_owner(
    identifier_type: IdentifierType,
    identifier: [u8; 32],
    line: usize,
) -> Result<Kcc20Owner, ZkError> {
    if identifier_type == IdentifierType::PubKey && XOnlyPublicKey::from_slice(&identifier).is_err()
    {
        return Err(ZkError::ListEntry {
            line,
            reason: "the public key is not a valid BIP-340 x-only key".into(),
        });
    }
    Ok(Kcc20Owner {
        identifier_type,
        identifier,
    })
}

fn parse_hex32(text: &str, line: usize) -> Result<[u8; 32], ZkError> {
    let bad = || ZkError::ListEntry {
        line,
        reason: "expected 64 lowercase hex digits".into(),
    };
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Reads a list file: one entry per line, in the order the issuer chooses (entry i is leaf i).
/// An entry is a Kaspa address of `network` (Schnorr P2PK or P2SH), `pubkey:<64 hex>` or
/// `scripthash:<64 hex>`. Blank lines and lines starting with `#` are skipped. Anything else is
/// `ZK_LIST_ENTRY` with its line number; an empty list or one over 1,048,576 entries is
/// `ZK_LIST_SIZE`. The text is not echoed in messages, so a list file cannot leak through them.
pub fn parse_list(text: &str, network: Network) -> Result<Vec<Kcc20Owner>, ZkError> {
    let mut owners = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let entry = raw.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let owner = if let Some(h) = entry.strip_prefix("pubkey:") {
            checked_owner(IdentifierType::PubKey, parse_hex32(h, line)?, line)?
        } else if let Some(h) = entry.strip_prefix("scripthash:") {
            checked_owner(IdentifierType::ScriptHash, parse_hex32(h, line)?, line)?
        } else {
            owner_of_address(entry, network, line)?
        };
        if owners.len() == MAX_ENTRIES {
            return Err(ZkError::ListSize {
                count: MAX_ENTRIES + 1,
            });
        }
        owners.push(owner);
    }
    if owners.is_empty() {
        return Err(ZkError::ListSize { count: 0 });
    }
    Ok(owners)
}

/// One member's path: the index, the entry's salt and the 20 sibling hashes (spec section 9.2:
/// the file reveals its own salt and which sibling subtrees are empty, nothing about others).
/// The salt is erased when the value is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct MemberPath {
    pub index: u32,
    pub salt: [u8; 32],
    pub siblings: [[u8; 32]; DEPTH],
}

impl std::fmt::Debug for MemberPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The salt hides its entry; it is never printed.
        f.debug_struct("MemberPath")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Drop for MemberPath {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

impl MemberPath {
    /// Builds a path value from parts a path file holds. `siblings` must be exactly 20 hashes
    /// and `index` below 2^20 (`ZK_PATH_INVALID`).
    pub fn new(index: u32, salt: [u8; 32], siblings: &[[u8; 32]]) -> Result<Self, ZkError> {
        if siblings.len() != DEPTH {
            return Err(ZkError::PathInvalid {
                reason: format!(
                    "a path holds exactly {DEPTH} siblings, found {}",
                    siblings.len()
                ),
            });
        }
        if index as usize >= MAX_ENTRIES {
            return Err(ZkError::PathInvalid {
                reason: "the index is not below 2^20".into(),
            });
        }
        let mut s = [[0u8; 32]; DEPTH];
        s.copy_from_slice(siblings);
        Ok(Self {
            index,
            salt,
            siblings: s,
        })
    }

    /// The root this path reaches from `owner`'s salted leaf.
    pub fn root_for(&self, owner: &Kcc20Owner) -> Result<[u8; 32], ZkError> {
        let spk = owner_spk(owner)?;
        let lf = leaf(&self.salt, &spk);
        // The guard of spec section 5.4 step 2: the empty leaf is not a member.
        if lf == [0u8; 32] {
            return Err(ZkError::PathInvalid {
                reason: "the salted leaf is the empty leaf".into(),
            });
        }
        Ok(root_from_path(&lf, self.index, &self.siblings))
    }

    /// Checks that the path leads from `owner`'s salted leaf to `root` (`ZK_PATH_INVALID`).
    pub fn check(&self, owner: &Kcc20Owner, root: &[u8; 32]) -> Result<(), ZkError> {
        if self.root_for(owner)? != *root {
            return Err(ZkError::PathInvalid {
                reason: "the path does not lead from the owner's salted leaf to the list root"
                    .into(),
            });
        }
        Ok(())
    }
}

/// A list tree over salted entries. Positions from the list's length on are empty leaves.
pub struct ListTree {
    owners: Vec<Kcc20Owner>,
    salts: Vec<[u8; 32]>,
    /// `levels[0]` are the leaves; `levels[k]` the nodes at height k, without the empty tail.
    levels: Vec<Vec<[u8; 32]>>,
    zeros: [[u8; 32]; DEPTH + 1],
}

impl Drop for ListTree {
    fn drop(&mut self) {
        for s in &mut self.salts {
            s.zeroize();
        }
    }
}

impl ListTree {
    /// Builds a tree with one fresh 32-byte salt per entry from the operating system's random
    /// number generator (spec section 5.1). Salts are drawn afresh for every build.
    pub fn build(owners: Vec<Kcc20Owner>) -> Result<Self, ZkError> {
        let mut salts = vec![[0u8; 32]; owners.len()];
        let mut rng = rand::rngs::OsRng;
        for s in &mut salts {
            rng.fill_bytes(s);
        }
        let tree = Self::build_with_salts(owners, &salts);
        for s in &mut salts {
            s.zeroize();
        }
        tree
    }

    /// Builds a tree with the given salts, one per entry (vectors and tests; a real list uses
    /// [`ListTree::build`]).
    pub fn build_with_salts(owners: Vec<Kcc20Owner>, salts: &[[u8; 32]]) -> Result<Self, ZkError> {
        if owners.is_empty() || owners.len() > MAX_ENTRIES {
            return Err(ZkError::ListSize {
                count: owners.len(),
            });
        }
        if salts.len() != owners.len() {
            return Err(ZkError::ListSize { count: salts.len() });
        }
        let zeros = zeros();
        let mut leaves = Vec::with_capacity(owners.len());
        for (owner, salt) in owners.iter().zip(salts) {
            let spk = owner_spk(owner).map_err(|_| ZkError::ListEntry {
                line: leaves.len() + 1,
                reason: "a covenant ID is not a list entry".into(),
            })?;
            leaves.push(leaf(salt, &spk));
        }
        let mut levels = vec![leaves];
        for k in 0..DEPTH {
            let cur = &levels[k];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            for pair in cur.chunks(2) {
                let right = if pair.len() == 2 { pair[1] } else { zeros[k] };
                next.push(node(&pair[0], &right));
            }
            levels.push(next);
        }
        Ok(Self {
            owners,
            salts: salts.to_vec(),
            levels,
            zeros,
        })
    }

    /// The root every trade under this list commits to as `list_root`.
    pub fn root(&self) -> [u8; 32] {
        self.levels[DEPTH][0]
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// The owner at position `i`.
    pub fn owner(&self, i: usize) -> Option<&Kcc20Owner> {
        self.owners.get(i)
    }

    /// The path of entry `i`.
    pub fn path(&self, i: usize) -> Option<MemberPath> {
        if i >= self.len() {
            return None;
        }
        let mut siblings = [[0u8; 32]; DEPTH];
        let mut pos = i;
        for (k, s) in siblings.iter_mut().enumerate() {
            *s = self.levels[k]
                .get(pos ^ 1)
                .copied()
                .unwrap_or(self.zeros[k]);
            pos >>= 1;
        }
        Some(MemberPath {
            index: i as u32,
            salt: self.salts[i],
            siblings,
        })
    }

    /// The path of the first entry equal to `owner`, or `ZK_NOT_MEMBER`.
    pub fn member_path(&self, owner: &Kcc20Owner) -> Result<MemberPath, ZkError> {
        let i = self
            .owners
            .iter()
            .position(|o| o == owner)
            .ok_or(ZkError::NotMember)?;
        Ok(self.path(i).expect("the position is in range"))
    }
}

/// True when `root` is a root a trade must not commit to: all zero or the empty tree's.
pub fn root_is_unusable(root: &[u8; 32]) -> bool {
    *root == [0u8; 32] || *root == EMPTY_ROOT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> Kcc20Owner {
        // The x coordinate of the public points G, 2G, 3G are valid x-only keys; for plain
        // structure tests any valid key works, so use the first three.
        let xs = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ];
        let mut id = [0u8; 32];
        for i in 0..32 {
            id[i] = u8::from_str_radix(&xs[(b as usize) % 3][2 * i..2 * i + 2], 16).unwrap();
        }
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: id,
        }
    }

    fn sh(b: u8) -> Kcc20Owner {
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: [b; 32],
        }
    }

    #[test]
    fn empty_root_is_the_spec_value() {
        let z = zeros();
        assert_eq!(z[DEPTH], EMPTY_ROOT);
        assert_eq!(
            super::super::hex(&EMPTY_ROOT),
            "51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503"
        );
    }

    #[test]
    fn owner_spk_forms() {
        let a = owner_spk(&pk(0)).unwrap();
        assert_eq!(a.len(), 36);
        assert_eq!(&a[..3], &[0, 0, 0x20]);
        assert_eq!(a[35], 0xac);
        let b = owner_spk(&sh(7)).unwrap();
        assert_eq!(b.len(), 37);
        assert_eq!(&b[..4], &[0, 0, 0xaa, 0x20]);
        assert_eq!(b[36], 0x87);
        let cov = Kcc20Owner {
            identifier_type: IdentifierType::CovenantId,
            identifier: [1; 32],
        };
        assert_eq!(
            owner_spk(&cov).unwrap_err().code(),
            "ZK_DELIVERY_OWNER_TYPE"
        );
    }

    #[test]
    fn every_path_leads_to_the_root() {
        for n in [1usize, 2, 3, 5, 8, 9] {
            let owners: Vec<_> = (0..n).map(|i| sh(i as u8 + 1)).collect();
            let salts: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 100; 32]).collect();
            let tree = ListTree::build_with_salts(owners.clone(), &salts).unwrap();
            for (i, owner) in owners.iter().enumerate() {
                let path = tree.member_path(owner).unwrap();
                assert_eq!(path.index as usize, i);
                path.check(owner, &tree.root()).unwrap();
                // Another owner at the same position does not lead to the root.
                assert_eq!(
                    path.check(&sh(200), &tree.root()).unwrap_err().code(),
                    "ZK_PATH_INVALID"
                );
            }
            assert_eq!(
                tree.member_path(&sh(250)).unwrap_err().code(),
                "ZK_NOT_MEMBER"
            );
        }
    }

    #[test]
    fn wrong_salt_or_index_or_root_is_refused() {
        let owners = vec![sh(1), sh(2), sh(3)];
        let salts = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tree = ListTree::build_with_salts(owners.clone(), &salts).unwrap();
        let good = tree.path(1).unwrap();
        good.check(&owners[1], &tree.root()).unwrap();
        let mut bad = good.clone();
        bad.salt[0] ^= 1;
        assert_eq!(
            bad.check(&owners[1], &tree.root()).unwrap_err().code(),
            "ZK_PATH_INVALID"
        );
        let mut bad = good.clone();
        bad.index = 0;
        assert_eq!(
            bad.check(&owners[1], &tree.root()).unwrap_err().code(),
            "ZK_PATH_INVALID"
        );
        let mut other = tree.root();
        other[0] ^= 1;
        assert_eq!(
            good.check(&owners[1], &other).unwrap_err().code(),
            "ZK_PATH_INVALID"
        );
    }

    #[test]
    fn fresh_salts_per_build() {
        let a = ListTree::build(vec![sh(1)]).unwrap();
        let b = ListTree::build(vec![sh(1)]).unwrap();
        assert_ne!(
            a.root(),
            b.root(),
            "the same address has unrelated leaves in two lists"
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(
            ListTree::build(vec![]).err().unwrap().code(),
            "ZK_LIST_SIZE"
        );
        assert_eq!(
            parse_list("# nothing\n\n", Network::Mainnet)
                .unwrap_err()
                .code(),
            "ZK_LIST_SIZE"
        );
        let one = ListTree::build_with_salts(vec![sh(1)], &[[9; 32]]).unwrap();
        assert!(one.path(1).is_none());
    }

    #[test]
    fn path_shape_is_checked() {
        assert_eq!(
            MemberPath::new(0, [0; 32], &[[0; 32]; 19])
                .unwrap_err()
                .code(),
            "ZK_PATH_INVALID"
        );
        assert_eq!(
            MemberPath::new(1 << 20, [0; 32], &[[0; 32]; 20])
                .unwrap_err()
                .code(),
            "ZK_PATH_INVALID"
        );
        MemberPath::new((1 << 20) - 1, [0; 32], &[[0; 32]; 20]).unwrap();
    }

    #[test]
    fn parse_list_entries() {
        let text = format!(
            "# issuer list\npubkey:{}\n  scripthash:{}  \n\n",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "11".repeat(32)
        );
        let owners = parse_list(&text, Network::Mainnet).unwrap();
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[0].identifier_type, IdentifierType::PubKey);
        assert_eq!(owners[1], sh(0x11));

        let code = |t: &str, n| parse_list(t, n).unwrap_err().code();
        assert_eq!(code("pubkey:00\n", Network::Mainnet), "ZK_LIST_ENTRY");
        assert_eq!(
            code(&format!("pubkey:{}\n", "00".repeat(32)), Network::Mainnet),
            "ZK_LIST_ENTRY"
        );
        assert_eq!(
            code(
                &format!("scripthash:{}\n", "AA".repeat(32)),
                Network::Mainnet
            ),
            "ZK_LIST_ENTRY"
        );
        assert_eq!(code("hello\n", Network::Mainnet), "ZK_LIST_ENTRY");
        // A script hash address of the other network.
        let testnet = Address::new(Prefix::Testnet, Version::ScriptHash, &[0x22; 32]).to_string();
        let mainnet = Address::new(Prefix::Mainnet, Version::ScriptHash, &[0x22; 32]).to_string();
        assert_eq!(
            code(&format!("{testnet}\n"), Network::Mainnet),
            "ZK_LIST_ENTRY"
        );
        assert_eq!(
            parse_list(&format!("{mainnet}\n"), Network::Mainnet).unwrap()[0],
            sh(0x22)
        );
        assert_eq!(
            parse_list(&format!("{testnet}\n"), Network::Testnet).unwrap()[0],
            sh(0x22)
        );
        // ECDSA addresses are refused.
        let ecdsa = Address::new(Prefix::Mainnet, Version::PubKeyECDSA, &[0x02; 33]).to_string();
        assert_eq!(
            code(&format!("{ecdsa}\n"), Network::Mainnet),
            "ZK_LIST_ENTRY"
        );
    }

    #[test]
    fn list_errors_do_not_echo_the_entry() {
        let e = parse_list("secret-looking-entry\n", Network::Mainnet).unwrap_err();
        assert!(!e.to_string().contains("secret-looking-entry"));
    }

    #[test]
    fn debug_hides_the_salt() {
        let t = ListTree::build_with_salts(vec![sh(1)], &[[0xab; 32]]).unwrap();
        let p = t.path(0).unwrap();
        assert!(!format!("{p:?}").contains("ab"));
    }
}
