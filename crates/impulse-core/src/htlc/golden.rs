// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden hashlock vectors (tests/vectors/htlc/), one file per vector: the terms in JSON form,
//! their canonical bytes, the counterpart record and its hash, the terms hash, and the vault's
//! redeem script, script hash and address. The definitions below render to the committed files
//! byte for byte; the files are frozen once on main, so a change to the codec, the hashes, the
//! template or the state mapping fails `golden_files_match`. scripts/vectors.sh regenerates them
//! through `emit_vectors`, diffs the result, and checks every file again in Python from
//! spec/V2.md section 10.2 alone.
//!
//! Every key, identifier and hash lock is derived from a public label with blake2b, so no
//! private key and no preimage exists for any of them. The counterpart identifiers are synthetic
//! labels too: no real chain, program, mint or account is named.

use super::*;
use crate::terms::golden::{hex, label32, unhex, write_json, xonly, Json, CREATION_DAA};
use crate::terms::{
    CreationContext, IdentifierType, Kcc20Token, LegKind, DEFAULT_MAX_EXPIRY_HORIZON_DAA,
};
use std::path::{Path, PathBuf};

/// Wall-clock time the vectors are created at (synthetic, unix seconds).
pub(crate) const NOW_UNIX: u64 = 1_790_000_000;
/// The time the buyer needs to see the reveal at counterpart-final, in the vectors' context
/// (synthetic). 60 s until I18 review round 5; with the D18 finality depth at 600 DAA (changed on
/// 2026-10-12) a 60 s figure would put every vector's Δ on the one-hour floor, so the vectors would
/// no longer exercise the sum of section 10.5. 1,830 s keeps Δ above the floor and vector 05
/// exactly on the margin boundary, so the frozen vectors stay byte-identical.
pub(crate) const COUNTERPART_FINAL_SECS: u64 = 1_830;
pub(crate) const HOUR_SECS: u64 = 3_600;
/// One day of DAA at the 10 blocks per second target.
pub(crate) const DAY_DAA: u64 = 864_000;

pub(crate) struct Vector {
    pub name: &'static str,
    pub description: &'static str,
    pub terms: HtlcTerms,
}

/// A synthetic mainnet DAA rate sample: 7 days and 5 minutes of points every 5 minutes, ending
/// one hour before `NOW_UNIX`, rising 3,000 DAA per point (10 per second). `DAA_RATE_MAX` is 15
/// per second.
pub(crate) fn mainnet_sample() -> DaaRateSample {
    let end = NOW_UNIX - HOUR_SECS;
    let steps = MIN_SAMPLE_SECS / 300 + 1;
    let start = end - steps * 300;
    DaaRateSample {
        bps: 10,
        points: (0..=steps)
            .map(|i| (start + i * 300, CREATION_DAA - (steps - i) * 3_000))
            .collect(),
    }
}

/// The creation context every vector validates against: the vectors' creation DAA score and
/// clock, the synthetic sample on mainnet, none on testnet.
pub(crate) fn context(network: Network, sample: &DaaRateSample) -> HtlcCreationContext<'_> {
    HtlcCreationContext {
        creation: CreationContext::new(network, CREATION_DAA),
        margin: MarginContext {
            now_unix: NOW_UNIX,
            counterpart_final_secs: COUNTERPART_FINAL_SECS,
            retry_secs: DEFAULT_RETRY_SECS,
            sample: (network == Network::Mainnet).then_some(sample),
        },
    }
}

fn nonce(label: &str) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&label32(label)[..8]);
    u64::from_le_bytes(b)
}

pub(crate) fn seller() -> [u8; 32] {
    xonly("impulse/vectors/htlc/key/seller")
}

pub(crate) fn buyer() -> [u8; 32] {
    xonly("impulse/vectors/htlc/key/buyer")
}

fn owner(identifier_type: IdentifierType, identifier: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type,
        identifier,
    }
}

fn token() -> Kcc20Token {
    Kcc20Token {
        covenant_id: label32("impulse/vectors/htlc/token/asset/covenant-id"),
        template_hash: label32("impulse/vectors/template/kcc20"),
        template_prefix_len: 40,
        template_suffix_len: 1_420,
    }
}

fn kcc20(amount: u64) -> Leg {
    Leg {
        kind: LegKind::Kcc20(token()),
        amount,
    }
}

fn counterpart(n: &str, chain: CounterpartChain, amount: u64, timeout: u64) -> Counterpart {
    let l = |field: &str| label32(&format!("impulse/vectors/htlc/{n}/counterpart/{field}"));
    Counterpart {
        chain,
        chain_id: l("chain-id"),
        htlc_program: l("htlc-program"),
        asset: l("asset"),
        amount,
        recipient: l("recipient"),
        refund: l("refund"),
        timeout,
    }
}

pub(crate) fn vectors() -> Vec<Vector> {
    use IdentifierType::{CovenantId, PubKey, ScriptHash};
    let (s, b) = (seller(), buyer());
    let custodian = label32("impulse/vectors/htlc/script-hash/custodian");
    let book = label32("impulse/vectors/htlc/covenant-id/book");
    vec![
        Vector {
            name: "01-mainnet-chain1-pubkey-owners",
            description: "Mainnet hashlock terms, counterpart chain kind 1. The asset is delivered to the buyer's key and goes home to the seller's key. Expiry two days of DAA after creation, counterpart timeout six hours after creation. Synthetic identifiers throughout.",
            terms: HtlcTerms {
                version: HTLC_TERMS_VERSION,
                network: Network::Mainnet,
                nonce: nonce("impulse/vectors/htlc/01/nonce"),
                seller_key: s,
                buyer_key: b,
                asset_leg: kcc20(500),
                buyer_delivery: owner(PubKey, b),
                seller_refund: owner(PubKey, s),
                hash_lock: label32("impulse/vectors/htlc/01/hash-lock"),
                expiry_daa: CREATION_DAA + 2 * DAY_DAA,
                counterpart: counterpart(
                    "01",
                    CounterpartChain::Solana,
                    250_000_000,
                    NOW_UNIX + 6 * HOUR_SECS,
                ),
                trade_ref: label32("impulse/vectors/htlc/01/trade-ref"),
            },
        },
        Vector {
            name: "02-testnet-chain1-script-hash-delivery",
            description: "Testnet hashlock terms, counterpart chain kind 1. The asset is delivered to a SCRIPT_HASH owner and goes home to a COVENANT_ID owner. Without a DAA rate sample the testnet rate of 2 times the target applies. Synthetic identifiers throughout.",
            terms: HtlcTerms {
                version: HTLC_TERMS_VERSION,
                network: Network::Testnet,
                nonce: nonce("impulse/vectors/htlc/02/nonce"),
                seller_key: s,
                buyer_key: b,
                asset_leg: kcc20(1_000_000),
                buyer_delivery: owner(ScriptHash, custodian),
                seller_refund: owner(CovenantId, book),
                hash_lock: label32("impulse/vectors/htlc/02/hash-lock"),
                expiry_daa: CREATION_DAA + DAY_DAA,
                counterpart: counterpart(
                    "02",
                    CounterpartChain::Solana,
                    1_000_000,
                    NOW_UNIX + 4 * HOUR_SECS,
                ),
                trade_ref: label32("impulse/vectors/htlc/02/trade-ref"),
            },
        },
        Vector {
            name: "03-mainnet-chain2-covenant-delivery",
            description: "Mainnet hashlock terms against another chain with sha256 hashlocks (counterpart chain kind 2). The asset is delivered to a COVENANT_ID owner and goes home to a SCRIPT_HASH owner. Synthetic identifiers throughout.",
            terms: HtlcTerms {
                version: HTLC_TERMS_VERSION,
                network: Network::Mainnet,
                nonce: nonce("impulse/vectors/htlc/03/nonce"),
                seller_key: s,
                buyer_key: b,
                asset_leg: kcc20(42),
                buyer_delivery: owner(CovenantId, book),
                seller_refund: owner(ScriptHash, custodian),
                hash_lock: label32("impulse/vectors/htlc/03/hash-lock"),
                expiry_daa: CREATION_DAA + 3 * DAY_DAA,
                counterpart: counterpart(
                    "03",
                    CounterpartChain::OtherSha256,
                    7,
                    NOW_UNIX + 24 * HOUR_SECS,
                ),
                trade_ref: label32("impulse/vectors/htlc/03/trade-ref"),
            },
        },
        Vector {
            name: "04-mainnet-upper-bounds",
            description: "Mainnet hashlock terms at the upper bounds: nonce and counterpart amount at u64::MAX, asset amount at i64::MAX, template lengths summing to the post-Toccata script size limit, expiry at the end of the default horizon. Synthetic identifiers throughout.",
            terms: HtlcTerms {
                version: HTLC_TERMS_VERSION,
                network: Network::Mainnet,
                nonce: u64::MAX,
                seller_key: s,
                buyer_key: b,
                asset_leg: Leg {
                    kind: LegKind::Kcc20(Kcc20Token {
                        template_prefix_len: 400_000,
                        template_suffix_len: 600_000,
                        ..token()
                    }),
                    amount: i64::MAX as u64,
                },
                buyer_delivery: owner(PubKey, b),
                seller_refund: owner(PubKey, s),
                hash_lock: label32("impulse/vectors/htlc/04/hash-lock"),
                expiry_daa: CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA,
                counterpart: counterpart(
                    "04",
                    CounterpartChain::Solana,
                    u64::MAX,
                    NOW_UNIX + 30 * 24 * HOUR_SECS,
                ),
                trade_ref: label32("impulse/vectors/htlc/04/trade-ref"),
            },
        },
        Vector {
            name: "05-testnet-lower-bounds",
            description: "Testnet hashlock terms at the lower bounds: nonce 0, asset and counterpart amounts of 1, template lengths of 1, and an expiry whose estimated arrival equals the counterpart timeout plus the margin exactly. Synthetic identifiers throughout.",
            terms: HtlcTerms {
                version: HTLC_TERMS_VERSION,
                network: Network::Testnet,
                nonce: 0,
                seller_key: s,
                buyer_key: b,
                asset_leg: Leg {
                    kind: LegKind::Kcc20(Kcc20Token {
                        template_prefix_len: 1,
                        template_suffix_len: 1,
                        ..token()
                    }),
                    amount: 1,
                },
                buyer_delivery: owner(ScriptHash, custodian),
                seller_refund: owner(PubKey, s),
                hash_lock: label32("impulse/vectors/htlc/05/hash-lock"),
                // Δ = max(1 h, 600 / 20 + 1,830 + 1,800) = 3,660 s, and T_C is one hour ahead, so
                // expiry must arrive 7,260 s ahead: 145,200 DAA at 20 per second.
                expiry_daa: CREATION_DAA + 145_200,
                counterpart: counterpart(
                    "05",
                    CounterpartChain::OtherSha256,
                    1,
                    NOW_UNIX + HOUR_SECS,
                ),
                trade_ref: label32("impulse/vectors/htlc/05/trade-ref"),
            },
        },
    ]
}

fn dec(n: u64) -> Json {
    Json::Str(n.to_string())
}

fn owner_json(o: &Kcc20Owner) -> Json {
    let kind = match o.identifier_type {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    };
    Json::Obj(vec![
        ("identifier_type", Json::Str(kind.into())),
        ("identifier", Json::Str(hex(&o.identifier))),
    ])
}

fn terms_json(t: &HtlcTerms) -> Json {
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        panic!("vector asset legs are KCC-20");
    };
    let c = &t.counterpart;
    let network = match t.network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };
    let chain = match c.chain {
        CounterpartChain::Solana => "solana",
        CounterpartChain::OtherSha256 => "other_sha256",
    };
    Json::Obj(vec![
        ("version", Json::Num(t.version.into())),
        ("network", Json::Str(network.into())),
        ("nonce", dec(t.nonce)),
        ("seller_key", Json::Str(hex(&t.seller_key))),
        ("buyer_key", Json::Str(hex(&t.buyer_key))),
        (
            "asset_leg",
            Json::Obj(vec![
                ("kind", Json::Str("kcc20".into())),
                ("covenant_id", Json::Str(hex(&token.covenant_id))),
                ("template_hash", Json::Str(hex(&token.template_hash))),
                (
                    "template_prefix_len",
                    Json::Num(token.template_prefix_len.into()),
                ),
                (
                    "template_suffix_len",
                    Json::Num(token.template_suffix_len.into()),
                ),
                ("amount", dec(t.asset_leg.amount)),
            ]),
        ),
        ("buyer_delivery", owner_json(&t.buyer_delivery)),
        ("seller_refund", owner_json(&t.seller_refund)),
        ("hash_lock", Json::Str(hex(&t.hash_lock))),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "counterpart",
            Json::Obj(vec![
                ("chain", Json::Str(chain.into())),
                ("chain_id", Json::Str(hex(&c.chain_id))),
                ("htlc_program", Json::Str(hex(&c.htlc_program))),
                ("asset", Json::Str(hex(&c.asset))),
                ("amount", dec(c.amount)),
                ("recipient", Json::Str(hex(&c.recipient))),
                ("refund", Json::Str(hex(&c.refund))),
                ("timeout", dec(c.timeout)),
            ]),
        ),
        ("trade_ref", Json::Str(hex(&t.trade_ref))),
    ])
}

/// The vector's vault as its creator would see it: creation-checked in the vectors' context.
/// The creation checks run here in the vectors' context.
pub(crate) fn fundable(v: &Vector) -> FundableHtlcVault {
    let checked = v.terms.clone().validate_structure().expect(v.name);
    let sample = mainnet_sample();
    checked
        .validate_creation(&context(v.terms.network, &sample))
        .unwrap_or_else(|e| panic!("{}: {e}", v.name));
    FundableHtlcVault::ungated_for_tests(HtlcVault::instantiate_existing(&checked).expect(v.name))
}

/// The exact file content for one vector.
pub(crate) fn render(v: &Vector) -> String {
    let canonical = v.terms.encode().expect("vector encodes");
    let fundable = fundable(v);
    let vault = fundable.vault();
    let doc = Json::Obj(vec![
        ("name", Json::Str(v.name.into())),
        ("description", Json::Str(v.description.into())),
        ("terms", terms_json(&v.terms)),
        ("canonical", Json::Str(hex(&canonical))),
        (
            "counterpart_record",
            Json::Str(hex(&v.terms.counterpart.encode())),
        ),
        (
            "counterpart_hash",
            Json::Str(hex(&v.terms.counterpart.hash())),
        ),
        (
            "htlc_terms_hash",
            Json::Str(hex(&v.terms.terms_hash().expect("vector hashes"))),
        ),
        (
            "template_hash",
            Json::Str(hex(&check_template().expect("startup check").hash())),
        ),
        (
            "vault",
            Json::Obj(vec![
                ("redeem_script", Json::Str(hex(vault.redeem_script()))),
                ("script_hash", Json::Str(hex(&vault.script_hash()))),
                ("address", Json::Str(fundable.address())),
            ]),
        ),
    ]);
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/htlc")
}

fn file_name(v: &Vector) -> String {
    format!("{}.json", v.name)
}

#[test]
fn golden_files_match() {
    let dir = committed_dir();
    let mut expected: Vec<String> = vectors().iter().map(file_name).collect();
    expected.sort();
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8")
        })
        // Hidden files (.DS_Store) are ignored by git; scripts/vectors.sh catches any other stray.
        .filter(|name| !name.starts_with('.'))
        .collect();
    found.sort();
    assert_eq!(
        found, expected,
        "tests/vectors/htlc holds exactly the golden set"
    );
    for v in vectors() {
        let path = dir.join(file_name(&v));
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == render(&v),
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

#[test]
fn golden_files_decode_hash_and_instantiate() {
    for v in vectors() {
        let path = committed_dir().join(file_name(&v));
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let field = |k: &str| {
            doc[k]
                .as_str()
                .unwrap_or_else(|| panic!("{}: {k}", v.name))
                .to_string()
        };
        let canonical = unhex(&field("canonical"));
        let decoded = HtlcTerms::decode(&canonical).expect("committed bytes decode");
        assert_eq!(decoded, v.terms, "{}", v.name);
        assert_eq!(decoded.encode().unwrap(), canonical, "{}", v.name);
        assert_eq!(
            hex(&decoded.terms_hash().unwrap()),
            field("htlc_terms_hash")
        );
        // The counterpart record is the canonical bytes' own slice before trade_ref.
        let record = unhex(&field("counterpart_record"));
        let end = canonical.len() - 32;
        assert_eq!(
            &canonical[end - COUNTERPART_RECORD_LEN..end],
            record.as_slice()
        );
        assert_eq!(
            hex(&keyed_hash(COUNTERPART_HASH_DOMAIN, &record)),
            field("counterpart_hash")
        );
        // The vault decodes back to the terms' state.
        let script = unhex(doc["vault"]["redeem_script"].as_str().expect("script"));
        assert_eq!(decode(&script).expect("vault decodes"), v.terms.state());
    }
}

#[test]
fn golden_hashes_distinct() {
    let mut hashes: Vec<[u8; 32]> = vectors()
        .iter()
        .map(|v| v.terms.terms_hash().unwrap())
        .collect();
    hashes.sort();
    hashes.dedup();
    assert_eq!(hashes.len(), vectors().len());
}

/// The set covers both networks, both counterpart chain kinds, every owner type in both owner
/// fields, and the margin boundary.
#[test]
fn golden_set_covers_every_form() {
    let vs = vectors();
    let ts: Vec<&HtlcTerms> = vs.iter().map(|v| &v.terms).collect();
    let any = |f: &dyn Fn(&HtlcTerms) -> bool| ts.iter().any(|t| f(t));
    assert!(any(&|t| t.network == Network::Mainnet));
    assert!(any(&|t| t.network == Network::Testnet));
    assert!(any(&|t| t.counterpart.chain == CounterpartChain::Solana));
    assert!(any(
        &|t| t.counterpart.chain == CounterpartChain::OtherSha256
    ));
    for id in [
        IdentifierType::PubKey,
        IdentifierType::ScriptHash,
        IdentifierType::CovenantId,
    ] {
        assert!(any(&|t| t.buyer_delivery.identifier_type == id), "{id:?}");
        assert!(any(&|t| t.seller_refund.identifier_type == id), "{id:?}");
    }
    // Vector 05 sits exactly on the margin: one DAA less is refused.
    let v = &vs[4];
    let sample = mainnet_sample();
    let ctx = context(v.terms.network, &sample);
    let e = margin_estimate(&v.terms, CREATION_DAA, &ctx.margin).unwrap();
    assert_eq!(e.expiry_estimate_unix, e.required_unix);
    let mut short = v.terms.clone();
    short.expiry_daa -= 1;
    let checked = short.validate_structure().unwrap();
    assert_eq!(
        checked.validate_creation(&ctx).unwrap_err().code(),
        "HTLC_TIMEOUT_MARGIN"
    );
}

/// Writes the golden set to $IMPULSE_VECTORS_OUT/htlc/. Run by scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    let dir = Path::new(&out).join("htlc");
    std::fs::create_dir_all(&dir).expect("create output dir");
    for v in vectors() {
        std::fs::write(dir.join(file_name(&v)), render(&v)).expect("write vector");
    }
}
