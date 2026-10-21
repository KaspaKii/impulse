// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Unit tests and the golden vectors of the hashed-terms vault (spec/V3-ZK.md 22.9):
//! `tests/vectors/terms_v4/` (canonical terms v4, hash and the two commitments) and
//! `tests/vectors/vaults_v4/` (both legs' redeem scripts, hashes and addresses). The files are
//! frozen; `scripts/vectors.sh` regenerates them through `emit_vectors` and checks them again in
//! Python (`scripts/vectors-v4.py`). Keys are the public points G to 4G: no private key exists.

use super::*;
use std::path::{Path, PathBuf};
use terms_core::codec::{Dest, Leg, Terms, FUNDING_EARMARKED, FUNDING_REVOCABLE, MODE_VAULT};

const G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const G4: &str = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

fn key(h: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn p2pk(k: [u8; 32]) -> Dest {
    let mut s = vec![0x20];
    s.extend_from_slice(&k);
    s.push(0xac);
    Dest::Kas {
        version: 0,
        script: s,
    }
}

fn terms(network: u8, cash: Leg, funding: u8, blind: u8) -> Terms {
    let external = matches!(cash, Leg::External { .. });
    let kas = matches!(cash, Leg::Kas { .. });
    Terms {
        network,
        mode: MODE_VAULT,
        nonce: 7,
        seller: key(G),
        buyer: key(G2),
        authority: Some(key(G3)),
        asset: Leg::Kcc20 {
            cov: [0xA5; 32],
            template_hash: [0x11; 32],
            prefix_len: 100,
            suffix_len: 200,
            amount: 1,
        },
        cash,
        buyer_delivery: Dest::Owner {
            id_type: 0,
            id: key(G4),
        },
        seller_proceeds: if external {
            Dest::OffChain
        } else if kas {
            p2pk(key(G))
        } else {
            Dest::Owner {
                id_type: 0,
                id: key(G),
            }
        },
        seller_refund: Dest::Owner {
            id_type: 0,
            id: key(G),
        },
        buyer_refund: if external {
            Dest::OffChain
        } else if kas {
            p2pk(key(G2))
        } else {
            Dest::Owner {
                id_type: 0,
                id: key(G2),
            }
        },
        earliest: None,
        expiry: 2_000_000,
        funding,
        blind: [blind; 32],
        trade_ref: [0; 32],
    }
}

fn fixtures() -> Vec<(&'static str, Terms)> {
    let kcc20 = Leg::Kcc20 {
        cov: [0xC5; 32],
        template_hash: [0x22; 32],
        prefix_len: 90,
        suffix_len: 180,
        amount: 5,
    };
    vec![
        (
            "01-v4-kas-cash-revocable",
            terms(0, Leg::Kas { amount: 50_000_000 }, FUNDING_REVOCABLE, 0xB1),
        ),
        (
            "02-v4-kcc20-cash-earmarked",
            terms(1, kcc20, FUNDING_EARMARKED, 0xB2),
        ),
        (
            "03-v4-external-cash-revocable",
            terms(0, Leg::External { amount: 9 }, FUNDING_REVOCABLE, 0xB3),
        ),
    ]
}

fn terms_json(name: &str, t: &Terms) -> String {
    let h = th::terms_hash(&t.encode());
    format!(
        "{{\n  \"name\": \"{name}\",\n  \"canonical\": \"{}\",\n  \"terms_hash\": \"{}\",\n  \"commit_leg0\": \"{}\",\n  \"commit_leg1\": \"{}\"\n}}\n",
        hex(&t.encode()),
        hex(&h),
        hex(&th::commit(&h, 0)),
        hex(&th::commit(&h, 1))
    )
}

fn vault_json(t: &Terms, leg: u8) -> String {
    if leg == 1 && matches!(t.cash, Leg::External { .. }) {
        return "null".into();
    }
    let v = VaultV4::of_terms(t, leg).unwrap();
    let net = if t.network == 0 {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let spk = v.script_public_key();
    format!(
        "{{\n    \"leg_index\": {leg},\n    \"commit\": \"{}\",\n    \"redeem_script\": \"{}\",\n    \"script_hash\": \"{}\",\n    \"address\": \"{}\"\n  }}",
        hex(&v.commit()),
        hex(v.redeem_script()),
        hex(&spk.script()[2..34]),
        v.address(net)
    )
}

fn vaults_json(name: &str, t: &Terms) -> String {
    format!(
        "{{\n  \"name\": \"{name}\",\n  \"terms_hash\": \"{}\",\n  \"template_hash\": \"{}\",\n  \"authority\": \"{}\",\n  \"asset_vault\": {},\n  \"cash_vault\": {}\n}}\n",
        hex(&th::terms_hash(&t.encode())),
        hex(&check().unwrap().hash()),
        hex(&t.authority.unwrap()),
        vault_json(t, 0),
        vault_json(t, 1)
    )
}

fn all_files() -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    for (name, t) in fixtures() {
        out.push(("terms_v4", format!("{name}.json"), terms_json(name, &t)));
        out.push(("vaults_v4", format!("{name}.json"), vaults_json(name, &t)));
    }
    out.extend(super::build_tests::vector_files());
    out
}

fn committed(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(dir)
}

#[test]
fn golden_files_match() {
    let files = all_files();
    for dir in ["terms_v4", "vaults_v4", "journal_v4", "ipst_v5"] {
        let mut expected: Vec<String> = files
            .iter()
            .filter(|f| f.0 == dir)
            .map(|f| f.1.clone())
            .collect();
        expected.sort();
        let mut found: Vec<String> = std::fs::read_dir(committed(dir))
            .unwrap_or_else(|e| panic!("read tests/vectors/{dir}: {e}"))
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.starts_with('.'))
            .collect();
        found.sort();
        assert_eq!(found, expected, "tests/vectors/{dir} holds the golden set");
    }
    for (dir, name, content) in &files {
        let on_disk = std::fs::read_to_string(committed(dir).join(name)).expect("read vector");
        assert!(
            on_disk == *content,
            "{dir}/{name} differs from its definition"
        );
    }
}

/// Regenerates the vectors into $IMPULSE_VECTORS_OUT. Used by scripts/vectors.sh.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    for (dir, name, content) in all_files() {
        let dir = Path::new(&out).join(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), content).unwrap();
    }
}

#[test]
fn every_fixture_parses_as_a_terms_file_and_roundtrips_its_vaults() {
    for (name, t) in fixtures() {
        let parsed = parse_terms_file(&hex(&t.encode())).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(parsed, t, "{name}");
        for leg in 0..2u8 {
            if leg == 1 && matches!(t.cash, Leg::External { .. }) {
                continue;
            }
            let v = VaultV4::of_terms(&t, leg).unwrap();
            let (c, a) = decode_vault(v.redeem_script()).unwrap();
            assert_eq!((c, a), (v.commit(), v.authority()), "{name} leg {leg}");
        }
    }
}

#[test]
fn the_two_legs_and_two_blinds_commit_differently() {
    let a = terms(0, Leg::Kas { amount: 5 }, FUNDING_REVOCABLE, 1);
    let b = terms(0, Leg::Kas { amount: 5 }, FUNDING_REVOCABLE, 2);
    let (ha, hb) = (th::terms_hash(&a.encode()), th::terms_hash(&b.encode()));
    assert_ne!(ha, hb);
    assert_ne!(th::commit(&ha, 0), th::commit(&ha, 1));
}

#[test]
fn terms_file_refusals() {
    let ok = terms(0, Leg::Kas { amount: 5 }, FUNDING_REVOCABLE, 1);
    let code = |t: &Terms| parse_terms_file(&hex(&t.encode())).unwrap_err().code();
    let mut direct = ok.clone();
    direct.mode = terms_core::codec::MODE_DIRECT;
    assert_eq!(code(&direct), "ZK_H_TERMS_DIRECT");
    let mut no_auth = ok.clone();
    no_auth.authority = None;
    assert_eq!(code(&no_auth), "ZK_H_AUTHORITY_REQUIRED");
    let mut zero = ok.clone();
    zero.blind = [0; 32];
    assert_eq!(code(&zero), "ZK_H_BLIND_INVALID");
    let mut bytes = ok.encode();
    bytes[0] = 3;
    assert_eq!(
        parse_terms_file(&hex(&bytes)).unwrap_err().code(),
        "ZK_H_TERMS_VERSION"
    );
}

#[test]
fn the_frozen_code_list_has_nineteen_codes_in_spec_order() {
    assert_eq!(ZKH_ERROR_CODES.len(), 19);
    assert_eq!(ZKH_ERROR_CODES[0], "ZK_H_TERMS_VERSION");
    assert_eq!(ZKH_ERROR_CODES[18], "ZK_H_CAP_OVERRIDE");
}

#[test]
fn a_template_with_the_wrong_hash_or_image_id_is_refused() {
    let bad_hash = "00".repeat(32);
    let e = TemplateV4::load(ARTIFACT_JSON, &bad_hash, IMAGE_ID_FILE).unwrap_err();
    assert_eq!(e.code(), "ZK_H_TEMPLATE_HASH_MISMATCH");
    let e = TemplateV4::load(ARTIFACT_JSON, TEMPLATE_HASH_FILE, &bad_hash).unwrap_err();
    assert_eq!(e.code(), "ZK_H_ARTIFACT_INVALID");
    let e = TemplateV4::load("{}", TEMPLATE_HASH_FILE, IMAGE_ID_FILE).unwrap_err();
    assert_eq!(e.code(), "ZK_H_ARTIFACT_INVALID");
}
