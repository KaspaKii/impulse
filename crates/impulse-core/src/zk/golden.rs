// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden vectors of the v3 design: `tests/vectors/zk/` (leaves, empty root, list roots and paths,
//! manifests, journals, one real receipt's journal digest) and `tests/vectors/terms_v3/` (terms
//! v3 with canonical bytes and hash). The definitions below render to the committed files byte
//! for byte; the files are frozen, so a change fails `golden_files_match`. scripts/vectors.sh
//! regenerates them through `emit_vectors`, diffs the result, and checks every file again with
//! Python (`scripts/vectors-zk.py`) from spec/V3-ZK.md alone.
//!
//! Lists and salts are the fixed fixtures of the circuits workspace (`circuits/prover/src/fixtures.rs`),
//! reproduced here from the same labels, so the roots here equal the roots of the proof fixtures
//! under `tests/engine/fixtures/v3/proofs/`. Owners are the x coordinates of the public points G,
//! 2G and 3G and hashes of labels: no private key exists for any of them, and none is written
//! anywhere. Salts are fixed fixture salts (a salt is not a key).
//!
//! No manifest vector carries a signature: a signature by a fixed key needs that key's private
//! half in the repository, and the rules forbid it (rule 1, docs/ENGINEERING-RULES.md). The signature path is
//! tested in `manifest::tests` with a throwaway key made at run time.

use super::*;
use crate::terms::golden::{vectors as v1_vectors, xonly};
use crate::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, LegKind, Network, SettlementMode, Terms,
};
use std::path::{Path, PathBuf};

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2_X: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3_X: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

/// A JSON value in the subset the vectors use.
enum Json {
    Str(String),
    Num(u64),
    Null,
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

fn h(bytes: &[u8]) -> Json {
    Json::Str(hex(bytes))
}

fn write_json(j: &Json, indent: usize, out: &mut String) {
    match j {
        Json::Str(v) => {
            assert!(
                v.chars()
                    .all(|c| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\'),
                "vector strings need no escaping: {v}"
            );
            out.push('"');
            out.push_str(v);
            out.push('"');
        }
        Json::Num(n) => out.push_str(&n.to_string()),
        Json::Null => out.push_str("null"),
        Json::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                write_json(item, indent + 2, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        Json::Obj(fields) => {
            out.push_str("{\n");
            for (i, (key, value)) in fields.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push('"');
                out.push_str(key);
                out.push_str("\": ");
                write_json(value, indent + 2, out);
                if i + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

fn render(doc: &Json) -> String {
    let mut out = String::new();
    write_json(doc, 0, &mut out);
    out.push('\n');
    out
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

// Fixture owners and lists (circuits/prover/src/fixtures.rs).

fn label(text: &str) -> [u8; 32] {
    sha256(text.as_bytes())
}

fn pubkey_owner(x: &str) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: unhex(x).try_into().expect("32 bytes"),
    }
}

fn scripthash_owner(id: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: id,
    }
}

/// Owner A (P2PK, G), B (P2PK, 2G), C (P2SH) and D (P2PK, 3G, never listed).
fn fixture_owner(name: &str) -> Kcc20Owner {
    match name {
        "A" => pubkey_owner(G_X),
        "B" => pubkey_owner(G2_X),
        "D" => pubkey_owner(G3_X),
        "C" => scripthash_owner(label("Impulse/zk/fixture/owner/C")),
        _ => panic!("unknown fixture owner {name}"),
    }
}

fn fixture_salt(list: &str, i: u32) -> [u8; 32] {
    let mut m = b"Impulse/zk/fixture/salt/v1/".to_vec();
    m.extend_from_slice(list.as_bytes());
    m.push(b'/');
    m.extend_from_slice(&i.to_be_bytes());
    sha256(&m)
}

/// Entries of a fixture list: (owner, salt).
fn fixture_list(name: &str) -> Vec<(Kcc20Owner, [u8; 32])> {
    match name {
        "list1" => vec![(fixture_owner("A"), fixture_salt(name, 0))],
        "list2" => vec![
            (fixture_owner("A"), fixture_salt(name, 0)),
            (fixture_owner("B"), fixture_salt(name, 1)),
        ],
        "list3" => vec![
            (fixture_owner("A"), fixture_salt(name, 0)),
            (fixture_owner("B"), fixture_salt(name, 1)),
            (fixture_owner("C"), fixture_salt(name, 2)),
        ],
        // 1,000 entries: B at 0, C at 500, A at 999; the rest P2SH fillers.
        "list1000" => (0u32..1000)
            .map(|i| {
                let owner = match i {
                    0 => fixture_owner("B"),
                    500 => fixture_owner("C"),
                    999 => fixture_owner("A"),
                    _ => scripthash_owner(label(&format!("Impulse/zk/fixture/filler/{i}"))),
                };
                (owner, fixture_salt(name, i))
            })
            .collect(),
        _ => panic!("unknown fixture list {name}"),
    }
}

fn fixture_tree(name: &str) -> ListTree {
    let entries = fixture_list(name);
    let salts: Vec<[u8; 32]> = entries.iter().map(|e| e.1).collect();
    ListTree::build_with_salts(entries.into_iter().map(|e| e.0).collect(), &salts)
        .expect("fixture list builds")
}

/// Stand-in vault script hash for a named vault, as the proof fixtures use until the real
/// template v3 addresses replace them.
fn standin_vault_hash(name: &str) -> [u8; 32] {
    label(&format!("Impulse/zk/fixture/standin-vault/{name}"))
}

fn owner_type_name(owner: &Kcc20Owner) -> &'static str {
    match owner.identifier_type {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

fn owner_json(owner: &Kcc20Owner) -> Vec<(&'static str, Json)> {
    vec![
        ("owner_type", s(owner_type_name(owner))),
        ("owner_id", h(&owner.identifier)),
        (
            "owner_spk",
            h(&owner_spk(owner).expect("owner has a scriptPubKey")),
        ),
    ]
}

fn path_json(path: &MemberPath, owner: &Kcc20Owner) -> Json {
    let mut fields = vec![("index", Json::Num(path.index.into()))];
    fields.extend(owner_json(owner));
    fields.push(("salt", h(&path.salt)));
    fields.push((
        "siblings",
        Json::Arr(path.siblings.iter().map(|x| h(x)).collect()),
    ));
    Json::Obj(fields)
}

// The vector files.

type File = (&'static str, String, String);

fn leaf_vector(name: &'static str, description: &str, owner: Kcc20Owner, salt: [u8; 32]) -> File {
    let spk = owner_spk(&owner).unwrap();
    let mut fields = vec![
        ("name", s(name)),
        ("description", s(description)),
        ("leaf_tag", s("Impulse/zk/leaf/v1")),
        ("salt", h(&salt)),
    ];
    fields.extend(owner_json(&owner));
    fields.push(("leaf", h(&leaf(&salt, &spk))));
    ("zk", format!("{name}.json"), render(&Json::Obj(fields)))
}

fn list_vector(
    name: &'static str,
    list: &str,
    description: &str,
    positions: &[usize],
    explicit: bool,
) -> File {
    let entries = fixture_list(list);
    let tree = fixture_tree(list);
    let mut fields = vec![
        ("name", s(name)),
        ("description", s(description)),
        ("depth", Json::Num(DEPTH as u64)),
        ("entry_count", Json::Num(entries.len() as u64)),
    ];
    if explicit {
        fields.push((
            "entries",
            Json::Arr(
                entries
                    .iter()
                    .map(|(owner, salt)| {
                        let mut f = owner_json(owner);
                        f.push(("salt", h(salt)));
                        f.push(("leaf", h(&leaf(salt, &owner_spk(owner).unwrap()))));
                        Json::Obj(f)
                    })
                    .collect(),
            ),
        ));
    } else {
        // The entries are generated by this rule, which scripts/vectors-zk.py implements:
        // special positions hold the named owner; every other position i holds the P2SH owner
        // whose script hash is SHA-256(filler_label || decimal i); the salt of position i is
        // SHA-256(salt_label || i as u32 big-endian).
        fields.push((
            "entries_rule",
            Json::Obj(vec![
                ("filler_label", s("Impulse/zk/fixture/filler/")),
                (
                    "salt_label",
                    s(format!("Impulse/zk/fixture/salt/v1/{list}/")),
                ),
                (
                    "special",
                    Json::Arr(
                        [(0usize, "B"), (500, "C"), (999, "A")]
                            .iter()
                            .map(|(i, who)| {
                                let mut f = vec![("index", Json::Num(*i as u64))];
                                f.extend(owner_json(&fixture_owner(who)));
                                Json::Obj(f)
                            })
                            .collect(),
                    ),
                ),
            ]),
        ));
    }
    fields.push(("root", h(&tree.root())));
    fields.push((
        "paths",
        Json::Arr(
            positions
                .iter()
                .map(|&i| path_json(&tree.path(i).unwrap(), tree.owner(i).unwrap()))
                .collect(),
        ),
    ));
    ("zk", format!("{name}.json"), render(&Json::Obj(fields)))
}

fn empty_root_vector() -> File {
    let mut levels = vec![[0u8; 32]];
    for k in 0..DEPTH {
        levels.push(node(&levels[k], &levels[k]));
    }
    let doc = Json::Obj(vec![
        ("name", s("03-empty-root")),
        (
            "description",
            s("The root of the tree whose every leaf is empty (32 zero bytes), at depth 20; levels[k] is the root of an empty subtree of height k. Terms whose list_root is this value or all zero are refused."),
        ),
        ("depth", Json::Num(DEPTH as u64)),
        ("empty_leaf", h(&[0u8; 32])),
        ("levels", Json::Arr(levels.iter().map(|x| h(x)).collect())),
        ("root", h(&levels[DEPTH])),
    ]);
    ("zk", "03-empty-root.json".into(), render(&doc))
}

fn manifest_vector(name: &'static str, description: &str, m: &Manifest) -> File {
    let doc = Json::Obj(vec![
        ("name", s(name)),
        ("description", s(description)),
        (
            "network",
            s(match m.network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
            }),
        ),
        ("list_id", s(m.list_id.clone())),
        ("list_version", Json::Num(m.list_version.into())),
        ("issued_at", Json::Num(m.issued_at)),
        ("list_root", h(&m.list_root)),
        ("manifest", h(&m.encode())),
        ("digest_key", s("Impulse/zk/manifest/v1")),
        ("manifest_digest", h(&m.digest())),
    ]);
    ("zk", format!("{name}.json"), render(&doc))
}

fn journal_vector(
    name: &'static str,
    description: &str,
    list: &str,
    vault: &str,
    owner: &str,
) -> File {
    let root = fixture_tree(list).root();
    let vault_hash = standin_vault_hash(vault);
    let owner = fixture_owner(owner);
    let j = journal(&root, &vault_hash, &owner).unwrap();
    let mut fields = vec![
        ("name", s(name)),
        ("description", s(description)),
        ("list_root", h(&root)),
        ("vault_script_hash", h(&vault_hash)),
        ("vault_spk", h(&p2sh_spk(&vault_hash))),
    ];
    fields.extend(owner_json(&owner));
    fields.push(("journal", h(&j)));
    fields.push(("journal_hash", h(&journal_hash(&j))));
    ("zk", format!("{name}.json"), render(&Json::Obj(fields)))
}

/// The journal and journal digest of the real receipt `a_list1` of the proof fixtures
/// (`tests/engine/fixtures/v3/proofs/a_list1.proof.json`), copied here as constants. The digest in
/// the receipt is SHA-256 of J (spec section 5.2); `scripts/vectors-zk.py` checks it.
const RECEIPT_A_LIST1_JOURNAL: &str = "496d70756c73652f7a6b2f776c2f76319bcc938724ce3c153bb7c53dec8ca7a7a722b5e8161c66a61946363e2a5e09290000aa2034e024ea85d5a9fed72313b144f4e624f1db1f62c633006550ca3ab79457b68a8700002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac";
const RECEIPT_A_LIST1_JOURNAL_HASH: &str =
    "3c2c848feae97ad7e563b182c7a77c1d78ea9e33409f94073f25032e014941a1";

fn receipt_vector() -> File {
    let doc = Json::Obj(vec![
        ("name", s("14-receipt-journal-digest")),
        (
            "description",
            s("The journal and journal digest of a real RISC Zero receipt of the list guest (proof fixture a_list1, stand-in vault asset_list1). The digest is SHA-256 of the committed bytes, which is what the asset vault recomputes in script. Image id of the guest that made it is in circuits/IMAGE_ID."),
        ),
        ("fixture", s("a_list1")),
        ("journal", s(RECEIPT_A_LIST1_JOURNAL)),
        ("journal_hash", s(RECEIPT_A_LIST1_JOURNAL_HASH)),
    ]);
    ("zk", "14-receipt-journal-digest.json".into(), render(&doc))
}

fn manifests() -> [(&'static str, &'static str, Manifest); 2] {
    let root = fixture_tree("list3").root();
    [
        (
            "08-manifest-mainnet",
            "A list manifest for the three-entry fixture list, mainnet. M and its keyed BLAKE2b-256 digest; the issuer signs the digest with its own signer.",
            Manifest::new(Network::Mainnet, "fixture-list-3", 1, 1_760_000_000, root).unwrap(),
        ),
        (
            "09-manifest-testnet",
            "A list manifest for the three-entry fixture list, testnet, a later version.",
            Manifest::new(Network::Testnet, "fixture-list-3", 2, 1_760_086_400, root).unwrap(),
        ),
    ]
}

pub(super) fn zk_files() -> Vec<File> {
    let mut files = vec![
        leaf_vector(
            "01-leaf-p2pk",
            "The leaf of a Schnorr P2PK owner (the x coordinate of G) under a fixed salt.",
            fixture_owner("A"),
            fixture_salt("leaf-vectors", 1),
        ),
        leaf_vector(
            "02-leaf-p2sh",
            "The leaf of a P2SH owner under a fixed salt.",
            fixture_owner("C"),
            fixture_salt("leaf-vectors", 2),
        ),
        empty_root_vector(),
        list_vector(
            "04-list-1",
            "list1",
            "A list of one entry (owner A). The path of entry 0 has 20 siblings: the empty subtrees of height 0 to 19.",
            &[0],
            true,
        ),
        list_vector(
            "05-list-2",
            "list2",
            "A list of two entries (A, B): first and last position.",
            &[0, 1],
            true,
        ),
        list_vector(
            "06-list-3",
            "list3",
            "A list of three entries (A, B, C): first and last position; the last entry's sibling at height 0 is an empty leaf.",
            &[0, 2],
            true,
        ),
        list_vector(
            "07-list-1000",
            "list1000",
            "A list of 1,000 entries (B at 0, C at 500, A at 999, P2SH fillers elsewhere): first, a middle and the last position.",
            &[0, 500, 999],
            false,
        ),
    ];
    for (name, description, m) in manifests() {
        files.push(manifest_vector(name, description, &m));
    }
    files.push(journal_vector(
        "10-journal-p2pk-list1",
        "J and journal_hash for owner A (P2PK, 121 bytes) in list1 at the stand-in vault asset_list1.",
        "list1",
        "asset_list1",
        "A",
    ));
    files.push(journal_vector(
        "11-journal-p2pk-list1000",
        "J and journal_hash for owner A (P2PK) in list1000 at the stand-in vault asset_list1000.",
        "list1000",
        "asset_list1000",
        "A",
    ));
    files.push(journal_vector(
        "12-journal-p2sh-list1000",
        "J and journal_hash for owner C (P2SH, 122 bytes) in list1000 at the stand-in vault asset_list1000_p2sh.",
        "list1000",
        "asset_list1000_p2sh",
        "C",
    ));
    files.push(journal_vector(
        "13-journal-p2pk-b-list1000",
        "J and journal_hash for owner B (P2PK) in list1000 at the stand-in vault asset_list1000.",
        "list1000",
        "asset_list1000",
        "B",
    ));
    files.push(receipt_vector());
    files
}

// Terms v3.

struct TermsVector {
    name: &'static str,
    description: &'static str,
    terms: TermsV3,
}

fn destination_json(d: &Destination) -> Json {
    match d {
        Destination::Kas(spk) => Json::Obj(vec![
            ("kind", s("kas")),
            ("version", Json::Num(spk.version().into())),
            ("script", h(spk.script())),
        ]),
        Destination::Kcc20(o) => Json::Obj(vec![
            ("kind", s("kcc20")),
            ("identifier_type", s(owner_type_name(o).to_string())),
            ("identifier", h(&o.identifier)),
        ]),
        Destination::OffChain => Json::Obj(vec![("kind", s("off_chain"))]),
    }
}

fn leg_json(leg: &crate::terms::Leg) -> Json {
    let mut fields = Vec::new();
    match &leg.kind {
        LegKind::Kas => fields.push(("kind", s("kas"))),
        LegKind::Kcc20(t) => {
            fields.push(("kind", s("kcc20")));
            fields.push(("covenant_id", h(&t.covenant_id)));
            fields.push(("template_hash", h(&t.template_hash)));
            fields.push((
                "template_prefix_len",
                Json::Num(t.template_prefix_len.into()),
            ));
            fields.push((
                "template_suffix_len",
                Json::Num(t.template_suffix_len.into()),
            ));
        }
        LegKind::External => fields.push(("kind", s("external"))),
    }
    // u64 as a decimal string: JSON numbers above 2^53 lose precision in JavaScript.
    fields.push(("amount", s(leg.amount.to_string())));
    Json::Obj(fields)
}

fn terms_v3_json(t: &TermsV3) -> Json {
    let f: &Terms = &t.fields;
    let dec = |n: u64| s(n.to_string());
    Json::Obj(vec![
        ("version", Json::Num(TERMS_V3_VERSION.into())),
        (
            "network",
            s(match f.network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
            }),
        ),
        (
            "settlement_mode",
            s(match f.settlement_mode {
                SettlementMode::Direct => "direct",
                SettlementMode::Vault => "vault",
            }),
        ),
        ("nonce", dec(f.nonce)),
        ("seller_key", h(&f.seller_key)),
        ("buyer_key", h(&f.buyer_key)),
        (
            "authority_key",
            f.authority_key.map_or(Json::Null, |k| h(&k)),
        ),
        ("asset_leg", leg_json(&f.asset_leg)),
        ("cash_leg", leg_json(&f.cash_leg)),
        ("buyer_delivery", destination_json(&f.buyer_delivery)),
        ("seller_proceeds", destination_json(&f.seller_proceeds)),
        ("seller_refund", destination_json(&f.seller_refund)),
        ("buyer_refund", destination_json(&f.buyer_refund)),
        ("earliest_daa", f.earliest_daa.map_or(Json::Null, dec)),
        ("expiry_daa", dec(f.expiry_daa)),
        (
            "funding_mode",
            s(match f.funding_mode {
                FundingMode::Revocable => "revocable",
                FundingMode::Earmarked => "earmarked",
            }),
        ),
        ("list_issuer_key", h(&t.list_issuer_key)),
        ("list_root", h(&t.list_root)),
        ("trade_ref", h(&f.trade_ref)),
    ])
}

/// The v1 golden vector `name` as the base of a v3 vector.
/// A v1 delivery to a COVENANT_ID owner becomes a delivery to a SCRIPT_HASH owner with the same
/// 32 bytes: terms v3 refuse a covenant owner (`ZK_DELIVERY_OWNER_TYPE`).
fn base(name: &str) -> Terms {
    let mut terms = v1_vectors()
        .into_iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("no v1 golden vector {name}"))
        .terms;
    if let Destination::Kcc20(o) = &mut terms.buyer_delivery {
        if o.identifier_type == IdentifierType::CovenantId {
            o.identifier_type = IdentifierType::ScriptHash;
        }
    }
    terms
}

fn terms_vectors() -> Vec<TermsVector> {
    let issuer = xonly("impulse/vectors/key/list-issuer");
    let root1 = fixture_tree("list1").root();
    let root3 = fixture_tree("list3").root();
    let root1000 = fixture_tree("list1000").root();
    // The issuer key equal to the seller key (an issuer selling its own token), and to the
    // authority key (the usual arrangement: the issuer is the authority).
    let seller = crate::terms::golden::seller();
    let authority = crate::terms::golden::authority();
    vec![
        TermsVector {
            name: "01-v3-authority-kcc20-cash-pubkey-owner",
            description: "Terms v3 from v1 vector 01: authority present, KCC-20 cash, buyer delivery a PUBKEY owner, earmarked funding, mainnet. Issuer key distinct from every party.",
            terms: TermsV3::new(base("01-vault-authority-earmarked-kcc20-kcc20"), issuer, root3),
        },
        TermsVector {
            name: "02-v3-authority-kas-cash-scripthash-owner",
            description: "Terms v3 from v1 vector 02: authority present, KAS cash, buyer delivery a SCRIPT_HASH owner, revocable funding, mainnet. The issuer is the authority.",
            terms: TermsV3::new(base("02-vault-authority-revocable-kcc20-kas"), authority, root1000),
        },
        TermsVector {
            name: "03-v3-no-authority-kcc20-cash-pubkey-owner",
            description: "Terms v3 from v1 vector 03: no authority (a self-settling vault trade), KCC-20 cash, earmarked. The v1 covenant ID delivery owner is a SCRIPT_HASH owner here. The issuer key equals the seller key.",
            terms: TermsV3::new(base("03-vault-selfsettling-earmarked-kcc20-kcc20"), seller, root1),
        },
        TermsVector {
            name: "04-v3-no-authority-kas-cash-revocable",
            description: "Terms v3 from v1 vector 04: no authority, KAS cash, revocable funding, mainnet.",
            terms: TermsV3::new(base("04-vault-selfsettling-revocable-kcc20-kas"), issuer, root3),
        },
        TermsVector {
            name: "05-v3-external-cash-authority-earmarked",
            description: "Terms v3 from v1 vector 05: external cash settled off chain with an authority, earmarked funding, mainnet.",
            terms: TermsV3::new(base("05-vault-external-earmarked-kcc20"), issuer, root1000),
        },
        TermsVector {
            name: "06-v3-external-cash-authority-revocable",
            description: "Terms v3 from v1 vector 06: external cash with an authority, revocable funding, mainnet.",
            terms: TermsV3::new(base("06-vault-external-revocable-kcc20"), issuer, root1),
        },
        TermsVector {
            name: "07-v3-testnet-authority-kas-cash",
            description: "Terms v3 from v1 vector 08: testnet, authority present, KAS cash, earmarked funding.",
            terms: TermsV3::new(base("08-testnet-vault-authority-earmarked-kcc20-kas"), issuer, root3),
        },
        TermsVector {
            name: "08-v3-upper-bounds",
            description: "Terms v3 from v1 vector 09: the upper bounds of every v1 numeric field; the v1 covenant ID delivery owner is a SCRIPT_HASH owner here.",
            terms: TermsV3::new(base("09-vault-authority-earmarked-upper-bounds"), issuer, root1000),
        },
        TermsVector {
            name: "09-v3-lower-bounds",
            description: "Terms v3 from v1 vector 10: the lower bounds of every v1 numeric field, no authority.",
            terms: TermsV3::new(base("10-vault-selfsettling-earmarked-lower-bounds"), issuer, root1),
        },
    ]
}

fn terms_v3_files() -> Vec<File> {
    terms_vectors()
        .into_iter()
        .map(|v| {
            let canonical = v.terms.encode().expect("vector encodes");
            let hash = v.terms.terms_hash().expect("vector hashes");
            let doc = Json::Obj(vec![
                ("name", s(v.name)),
                ("description", s(v.description)),
                ("terms", terms_v3_json(&v.terms)),
                ("canonical", h(&canonical)),
                ("terms_hash", h(&hash)),
            ]);
            ("terms_v3", format!("{}.json", v.name), render(&doc))
        })
        .collect()
}

/// The two vault scripts of each terms v3 vector (spec/V3-ZK.md section 7.4): redeem script,
/// script hash and address, or the refusal of a leg with no vault. They depend on the template v3
/// hash, so they exist only in a build that embeds the artifact.
#[cfg(impulse_v3_artifact)]
fn vaults_v3_files() -> Vec<File> {
    use super::template::{check, vault_address_v3, VaultV3};
    use crate::template::LegIndex;
    use crate::terms::CreationContext;
    let template_hash = check().expect("template v3").hash();
    terms_vectors()
        .into_iter()
        .map(|v| {
            let terms = v.terms.clone().validate_structure().expect(v.name);
            let ctx =
                CreationContext::new(v.terms.fields.network, crate::terms::golden::CREATION_DAA);
            let vault = |leg: LegIndex| -> Json {
                match VaultV3::instantiate_for_creation(&terms, leg, &ctx) {
                    Ok(f) => Json::Obj(vec![
                        ("leg_index", Json::Num(leg.index().into())),
                        ("redeem_script", h(f.vault().redeem_script())),
                        ("script_hash", h(&f.vault().script_hash())),
                        ("address", s(vault_address_v3(&f))),
                    ]),
                    Err(e) => {
                        assert_eq!(e.code(), "TEMPLATE_NO_VAULT", "{}", v.name);
                        Json::Obj(vec![
                            ("leg_index", Json::Num(leg.index().into())),
                            ("refused", s("TEMPLATE_NO_VAULT")),
                        ])
                    }
                }
            };
            let doc = Json::Obj(vec![
                ("name", s(v.name)),
                ("terms_hash", h(&terms.terms_hash())),
                ("template_hash", h(&template_hash)),
                ("asset_vault", vault(LegIndex::Asset)),
                ("cash_vault", vault(LegIndex::Cash)),
            ]);
            ("vaults_v3", format!("{}.json", v.name), render(&doc))
        })
        .collect()
}

fn all_files() -> Vec<File> {
    let mut files = zk_files();
    files.extend(terms_v3_files());
    #[cfg(impulse_v3_artifact)]
    files.extend(vaults_v3_files());
    files
}

/// The directories of the golden set.
#[cfg(impulse_v3_artifact)]
const DIRS: [&str; 3] = ["zk", "terms_v3", "vaults_v3"];
#[cfg(not(impulse_v3_artifact))]
const DIRS: [&str; 2] = ["zk", "terms_v3"];

fn committed(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(dir)
}

#[test]
fn golden_files_match() {
    let files = all_files();
    for dir in DIRS {
        let mut expected: Vec<String> = files
            .iter()
            .filter(|f| f.0 == dir)
            .map(|f| f.1.clone())
            .collect();
        expected.sort();
        let mut found: Vec<String> = std::fs::read_dir(committed(dir))
            .unwrap_or_else(|e| panic!("read tests/vectors/{dir}: {e}"))
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| !name.starts_with('.'))
            .collect();
        found.sort();
        assert_eq!(
            found, expected,
            "tests/vectors/{dir} holds exactly the golden set"
        );
    }
    for (dir, name, content) in &files {
        let path = committed(dir).join(name);
        let on_disk = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            on_disk == *content,
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff). The vaults_v3 vectors follow contracts/compiled/impulse_vault.v3.json: while template v3 is unfrozen and unmerged they are regenerated with IMPULSE_VECTORS_OUT=$PWD/tests/vectors cargo test -p impulse-core --features zk --lib zk::golden::emit_vectors -- --ignored --exact",
            path.display()
        );
    }
}

#[test]
fn golden_terms_decode_validate_and_hash() {
    for v in terms_vectors() {
        let canonical = v.terms.encode().unwrap();
        assert_eq!(TermsV3::decode(&canonical).unwrap(), v.terms, "{}", v.name);
        let checked = v.terms.clone().validate_structure().expect(v.name);
        assert_eq!(checked.canonical(), canonical.as_slice());
        let ctx = crate::terms::CreationContext::new(
            v.terms.fields.network,
            crate::terms::golden::CREATION_DAA,
        );
        checked.validate_creation(&ctx).expect(v.name);
    }
    let hashes: std::collections::BTreeSet<_> = terms_vectors()
        .iter()
        .map(|v| v.terms.terms_hash().unwrap())
        .collect();
    assert_eq!(
        hashes.len(),
        terms_vectors().len(),
        "terms hashes are distinct"
    );
}

#[test]
fn golden_set_covers_what_the_spec_asks_for() {
    use crate::terms::{LegKind, SettlementMode};
    let v = terms_vectors();
    let any = |f: &dyn Fn(&TermsV3) -> bool| v.iter().any(|x| f(&x.terms));
    assert!(any(&|t| matches!(t.fields.cash_leg.kind, LegKind::Kas)));
    assert!(any(&|t| matches!(
        t.fields.cash_leg.kind,
        LegKind::Kcc20(_)
    )));
    assert!(any(&|t| matches!(
        t.fields.cash_leg.kind,
        LegKind::External
    ) && t.fields.authority_key.is_some()));
    assert!(any(&|t| t.fields.authority_key.is_some()));
    assert!(any(&|t| t.fields.authority_key.is_none()));
    assert!(any(&|t| t.fields.network == Network::Mainnet));
    assert!(any(&|t| t.fields.network == Network::Testnet));
    assert!(any(&|t| t.fields.funding_mode == FundingMode::Revocable));
    assert!(any(&|t| t.fields.funding_mode == FundingMode::Earmarked));
    assert!(any(
        &|t| t.delivery_owner().unwrap().identifier_type == IdentifierType::PubKey
    ));
    assert!(any(
        &|t| t.delivery_owner().unwrap().identifier_type == IdentifierType::ScriptHash
    ));
    assert!(any(&|t| t.list_issuer_key == t.fields.seller_key));
    assert!(any(&|t| t.list_issuer_key != t.fields.seller_key
        && t.list_issuer_key != t.fields.buyer_key
        && Some(t.list_issuer_key) != t.fields.authority_key));
    assert!(v
        .iter()
        .all(|x| x.terms.fields.settlement_mode == SettlementMode::Vault));
}

#[test]
fn golden_lists_agree_with_the_proof_fixtures() {
    // The roots of the proof fixtures (lists.json) are those of the same labels here.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v3/proofs");
    let lists: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("lists.json")).unwrap()).unwrap();
    for list in ["list1", "list1000"] {
        assert_eq!(
            lists[list]["root"].as_str().unwrap(),
            hex(&fixture_tree(list).root()),
            "{list}"
        );
    }
}

#[test]
fn golden_receipt_journal_is_the_fixture_receipt() {
    // While the fixture still uses the stand-in vault, its journal is the one pinned here.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/engine/fixtures/v3/proofs");
    let inputs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("a_list1.inputs.json")).unwrap())
            .unwrap();
    if inputs["vault_spk_is_standin"].as_bool() != Some(true) {
        return;
    }
    let proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("a_list1.proof.json")).unwrap())
            .unwrap();
    assert_eq!(proof["journal"].as_str().unwrap(), RECEIPT_A_LIST1_JOURNAL);
    assert_eq!(
        proof["journal_hash"].as_str().unwrap(),
        RECEIPT_A_LIST1_JOURNAL_HASH
    );
    let root = fixture_tree("list1").root();
    let j = journal(
        &root,
        &standin_vault_hash("asset_list1"),
        &fixture_owner("A"),
    )
    .unwrap();
    assert_eq!(hex(&j), RECEIPT_A_LIST1_JOURNAL);
    assert_eq!(hex(&journal_hash(&j)), RECEIPT_A_LIST1_JOURNAL_HASH);
}

/// Writes the golden set to $IMPULSE_VECTORS_OUT/zk/ and /terms_v3/. Run by scripts/vectors.sh
/// only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    for (dir, name, content) in all_files() {
        let dir = Path::new(&out).join(dir);
        std::fs::create_dir_all(&dir).expect("create output dir");
        std::fs::write(dir.join(name), content).expect("write vector");
    }
}
