// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Unit tests of the hashlock module (spec/V2.md sections 8.5, 10 and 11.3): hashes and their
//! known answers, the codec and every decode refusal, the structure and creation checks in order,
//! the margin rule and the DAA rate sample, the template startup check and decoding, the builders'
//! layouts and refusals, the terms check, and the verifier.
//!
//! Keys: none. The parties are label-derived x-only public keys, for which nobody holds a private
//! key, and nothing here signs (rule 1, docs/ENGINEERING-RULES.md). Transactions that need a signature run in the
//! engine target (tests/engine/htlc_builders.rs). The preimage `PREIMAGE` is a fixed test value,
//! not a secret of any trade.

use super::golden::{self, context, mainnet_sample, vectors, HOUR_SECS, NOW_UNIX};
use super::*;
use crate::terms::golden::{hex, label32, CREATION_DAA};
use crate::terms::{CreationContext, IdentifierType, Kcc20Token, LegKind};
use crate::tx::testkit::{asset_template, own_token, utxo, ASSET_COV, CARRIER, FEE, FEE_INPUT};
use crate::tx::{
    p2pk, FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, Utxo, MIN_KAS_OUTPUT,
};
use kaspa_consensus_core::tx::{
    CovenantBinding, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_consensus_core::Hash;
use proptest::prelude::*;

const PREIMAGE: [u8; 32] = [0x5C; 32];

/// An edit of the terms, for the tables of faults below.
type Edit = Box<dyn Fn(&mut HtlcTerms)>;

fn code<T: std::fmt::Debug>(r: Result<T, HtlcError>) -> &'static str {
    r.expect_err("refused").code()
}

fn v1() -> HtlcTerms {
    vectors().remove(0).terms
}

fn sample() -> DaaRateSample {
    mainnet_sample()
}

// =============================================================================================
// Hashes
// =============================================================================================

/// spec/V2.md section 10.2 known answers, measured there with Python hashlib.
#[test]
fn hash_known_answers() {
    assert_eq!(HTLC_TERMS_HASH_DOMAIN.len(), 15);
    assert_eq!(COUNTERPART_HASH_DOMAIN.len(), 27);
    for (key, message, want) in [
        (
            HTLC_TERMS_HASH_DOMAIN,
            &b""[..],
            "9509729575406fcd715766393ef5279d60fada799fcc8456b54a4d9289013dbf",
        ),
        (
            HTLC_TERMS_HASH_DOMAIN,
            b"abc",
            "4d8a7f9ba1056cc853266401daaeec7cbc3931593731020df642088c2557dd9f",
        ),
        (
            COUNTERPART_HASH_DOMAIN,
            b"",
            "30c7bea0acb5b9a2de3aa57015947326a1dd21a649b4da0e6066016c04ea9eb9",
        ),
        (
            COUNTERPART_HASH_DOMAIN,
            b"abc",
            "b6901a3b7a2738e836156dda00334abc90fa8a9c74a21a9296e8c373dcef4794",
        ),
    ] {
        assert_eq!(hex(&keyed_hash(key, message)), want);
    }
    // The terms hash is over the canonical bytes, the counterpart hash over the record alone.
    let t = v1();
    assert_eq!(
        t.terms_hash().unwrap(),
        keyed_hash(HTLC_TERMS_HASH_DOMAIN, &t.encode().unwrap())
    );
    assert_eq!(
        t.counterpart.hash(),
        keyed_hash(COUNTERPART_HASH_DOMAIN, &t.counterpart.encode())
    );
    // sha256 known answer (FIPS 180-2, "abc").
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// =============================================================================================
// Codec
// =============================================================================================

#[test]
fn layout_lengths() {
    let t = v1();
    let bytes = t.encode().unwrap();
    assert_eq!(
        bytes.len(),
        1 + 1 + 8 + 32 + 32 + 81 + 33 + 33 + 32 + 8 + 177 + 32
    );
    assert_eq!(t.counterpart.encode().len(), COUNTERPART_RECORD_LEN);
    // Field positions: version, network, then the record before trade_ref.
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], 0);
    assert_eq!(&bytes[bytes.len() - 32..], &t.trade_ref);
    let record = &bytes[bytes.len() - 32 - COUNTERPART_RECORD_LEN..bytes.len() - 32];
    assert_eq!(record, t.counterpart.encode().as_slice());
    assert_eq!(record[0], 0x01);
}

#[test]
fn every_truncation_and_trailing_byte_is_refused() {
    let bytes = v1().encode().unwrap();
    for n in 0..bytes.len() {
        assert_eq!(
            code(HtlcTerms::decode(&bytes[..n])),
            "TERMS_TRUNCATED",
            "{n}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(code(HtlcTerms::decode(&long)), "TERMS_TRAILING_BYTES");
}

#[test]
fn decode_refuses_unknown_bytes() {
    let bytes = v1().encode().unwrap();
    let with = |at: usize, b: u8| {
        let mut x = bytes.clone();
        x[at] = b;
        x
    };
    for version in [0, 2, 0xFF] {
        assert_eq!(code(HtlcTerms::decode(&with(0, version))), "HTLC_VERSION");
    }
    assert_eq!(code(HtlcTerms::decode(&with(1, 2))), "TERMS_INVALID_TAG");
    let leg = 1 + 1 + 8 + 32 + 32;
    assert_eq!(code(HtlcTerms::decode(&with(leg, 3))), "TERMS_INVALID_TAG");
    let delivery = leg + 81;
    let refund = delivery + 33;
    for at in [delivery, refund] {
        assert_eq!(code(HtlcTerms::decode(&with(at, 3))), "TERMS_INVALID_TAG");
    }
    let chain = bytes.len() - 32 - COUNTERPART_RECORD_LEN;
    for b in [0, 3, 0xFF] {
        assert_eq!(code(HtlcTerms::decode(&with(chain, b))), "HTLC_COUNTERPART");
    }
    // Encoding refuses another version too.
    let mut t = v1();
    t.version = 2;
    assert_eq!(code(t.encode()), "HTLC_VERSION");
    assert_eq!(code(t.terms_hash()), "HTLC_VERSION");
}

/// A KAS or external asset leg decodes (v1's Leg encoding) and the structure checks refuse it.
#[test]
fn other_leg_kinds_decode_and_are_refused_by_structure() {
    for kind in [LegKind::Kas, LegKind::External] {
        let mut t = v1();
        t.asset_leg.kind = kind;
        let bytes = t.encode().unwrap();
        assert_eq!(bytes.len(), 470 - 72);
        let decoded = HtlcTerms::decode(&bytes).unwrap();
        assert_eq!(decoded, t);
        assert_eq!(code(decoded.validate_structure()), "HTLC_ASSET_KIND");
    }
}

fn arb_owner() -> impl Strategy<Value = Kcc20Owner> {
    (0u8..3, any::<[u8; 32]>()).prop_map(|(t, identifier)| Kcc20Owner {
        identifier_type: codec::id_type(t).unwrap(),
        identifier,
    })
}

fn arb_terms() -> impl Strategy<Value = HtlcTerms> {
    let leg = (
        0u8..3,
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
    )
        .prop_map(|(k, covenant_id, template_hash, p, s, amount)| Leg {
            kind: match k {
                0 => LegKind::Kas,
                1 => LegKind::Kcc20(Kcc20Token {
                    covenant_id,
                    template_hash,
                    template_prefix_len: p,
                    template_suffix_len: s,
                }),
                _ => LegKind::External,
            },
            amount,
        });
    let counterpart = (
        any::<bool>(),
        any::<[[u8; 32]; 5]>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(|(c, ids, amount, timeout)| Counterpart {
            chain: if c {
                CounterpartChain::Solana
            } else {
                CounterpartChain::OtherSha256
            },
            chain_id: ids[0],
            htlc_program: ids[1],
            asset: ids[2],
            amount,
            recipient: ids[3],
            refund: ids[4],
            timeout,
        });
    (
        any::<bool>(),
        any::<u64>(),
        any::<[[u8; 32]; 4]>(),
        leg,
        arb_owner(),
        arb_owner(),
        any::<u64>(),
        counterpart,
    )
        .prop_map(
            |(net, nonce, k, asset_leg, buyer_delivery, seller_refund, expiry_daa, counterpart)| {
                HtlcTerms {
                    version: 1,
                    network: if net {
                        Network::Mainnet
                    } else {
                        Network::Testnet
                    },
                    nonce,
                    seller_key: k[0],
                    buyer_key: k[1],
                    asset_leg,
                    buyer_delivery,
                    seller_refund,
                    hash_lock: k[2],
                    expiry_daa,
                    counterpart,
                    trade_ref: k[3],
                }
            },
        )
}

proptest! {
    #[test]
    fn encoding_round_trips(t in arb_terms()) {
        let bytes = t.encode().unwrap();
        prop_assert_eq!(HtlcTerms::decode(&bytes).unwrap(), t);
    }

    /// Any byte string either is refused or is the one encoding of what it decodes to.
    #[test]
    fn decoding_is_one_to_one(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Ok(t) = HtlcTerms::decode(&bytes) {
            prop_assert_eq!(t.encode().unwrap(), bytes);
        }
    }
}

// =============================================================================================
// Structure checks
// =============================================================================================

fn structure_code(edit: impl Fn(&mut HtlcTerms)) -> &'static str {
    let mut t = v1();
    edit(&mut t);
    code(t.validate_structure())
}

fn token_mut(t: &mut HtlcTerms) -> &mut Kcc20Token {
    match &mut t.asset_leg.kind {
        LegKind::Kcc20(token) => token,
        _ => unreachable!(),
    }
}

#[test]
fn structure_checks_each_code() {
    let off_curve = [0xFF; 32];
    let cases: Vec<(&str, Edit, &str)> = vec![
        ("version", Box::new(|t| t.version = 2), "HTLC_VERSION"),
        (
            "seller key",
            Box::new(move |t| t.seller_key = off_curve),
            "TERMS_INVALID_KEY",
        ),
        (
            "buyer key",
            Box::new(move |t| t.buyer_key = off_curve),
            "TERMS_INVALID_KEY",
        ),
        (
            "same parties",
            Box::new(|t| t.buyer_key = t.seller_key),
            "TERMS_PARTIES_NOT_DISTINCT",
        ),
        (
            "KAS asset",
            Box::new(|t| t.asset_leg.kind = LegKind::Kas),
            "HTLC_ASSET_KIND",
        ),
        (
            "external asset",
            Box::new(|t| t.asset_leg.kind = LegKind::External),
            "HTLC_ASSET_KIND",
        ),
        (
            "amount zero",
            Box::new(|t| t.asset_leg.amount = 0),
            "TERMS_AMOUNT_ZERO",
        ),
        (
            "amount above i64",
            Box::new(|t| t.asset_leg.amount = i64::MAX as u64 + 1),
            "TERMS_AMOUNT_OUT_OF_RANGE",
        ),
        (
            "covenant zero",
            Box::new(|t| token_mut(t).covenant_id = [0; 32]),
            "TERMS_ZERO_IDENTIFIER",
        ),
        (
            "template hash zero",
            Box::new(|t| token_mut(t).template_hash = [0; 32]),
            "TERMS_ZERO_IDENTIFIER",
        ),
        (
            "prefix zero",
            Box::new(|t| token_mut(t).template_prefix_len = 0),
            "TERMS_TEMPLATE_LENGTH",
        ),
        (
            "suffix zero",
            Box::new(|t| token_mut(t).template_suffix_len = 0),
            "TERMS_TEMPLATE_LENGTH",
        ),
        (
            "template too long",
            Box::new(|t| {
                token_mut(t).template_prefix_len = 500_000;
                token_mut(t).template_suffix_len = 500_001;
            }),
            "TERMS_TEMPLATE_LENGTH",
        ),
        (
            "delivery zero",
            Box::new(|t| t.buyer_delivery.identifier = [0; 32]),
            "TERMS_ZERO_IDENTIFIER",
        ),
        (
            "delivery key",
            Box::new(move |t| t.buyer_delivery.identifier = off_curve),
            "TERMS_INVALID_KEY",
        ),
        (
            "refund zero",
            Box::new(|t| t.seller_refund.identifier = [0; 32]),
            "TERMS_ZERO_IDENTIFIER",
        ),
        (
            "refund key",
            Box::new(move |t| t.seller_refund.identifier = off_curve),
            "TERMS_INVALID_KEY",
        ),
        (
            "hash lock zero",
            Box::new(|t| t.hash_lock = [0; 32]),
            "HTLC_HASH_ZERO",
        ),
        (
            "chain id zero",
            Box::new(|t| t.counterpart.chain_id = [0; 32]),
            "HTLC_COUNTERPART",
        ),
        (
            "program zero",
            Box::new(|t| t.counterpart.htlc_program = [0; 32]),
            "HTLC_COUNTERPART",
        ),
        (
            "asset zero",
            Box::new(|t| t.counterpart.asset = [0; 32]),
            "HTLC_COUNTERPART",
        ),
        (
            "counterpart amount zero",
            Box::new(|t| t.counterpart.amount = 0),
            "HTLC_COUNTERPART",
        ),
        (
            "recipient zero",
            Box::new(|t| t.counterpart.recipient = [0; 32]),
            "HTLC_COUNTERPART",
        ),
        (
            "refund account zero",
            Box::new(|t| t.counterpart.refund = [0; 32]),
            "HTLC_COUNTERPART",
        ),
        (
            "counterpart timeout zero",
            Box::new(|t| t.counterpart.timeout = 0),
            "HTLC_COUNTERPART",
        ),
        (
            "counterpart timeout beyond i64",
            Box::new(|t| t.counterpart.timeout = i64::MAX as u64 + 1),
            "HTLC_COUNTERPART",
        ),
        (
            "expiry not DAA",
            Box::new(|t| t.expiry_daa = kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD),
            "TERMS_EXPIRY_NOT_DAA",
        ),
    ];
    for (label, edit, want) in cases {
        assert_eq!(structure_code(edit), want, "{label}");
    }
    // A SCRIPT_HASH or COVENANT_ID owner need not be a key.
    let mut t = v1();
    t.buyer_delivery = Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: off_curve,
    };
    assert!(t.validate_structure().is_ok());
    // The upper bounds pass.
    let mut t = v1();
    t.asset_leg.amount = i64::MAX as u64;
    t.expiry_daa = kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD - 1;
    t.counterpart.timeout = i64::MAX as u64;
    assert!(t.validate_structure().is_ok());
    // The lower bound of the counterpart timeout passes the structure checks.
    let mut t = v1();
    t.counterpart.timeout = 1;
    assert!(t.validate_structure().is_ok());
}

/// The first failure in spec order is the one reported.
#[test]
fn structure_checks_run_in_order() {
    let off_curve = [0xFF; 32];
    let pairs: Vec<(Edit, &str)> = vec![
        (Box::new(|t| t.version = 9), "HTLC_VERSION"),
        (
            Box::new(move |t| t.seller_key = off_curve),
            "TERMS_INVALID_KEY",
        ),
        (
            Box::new(|t| t.buyer_key = t.seller_key),
            "TERMS_PARTIES_NOT_DISTINCT",
        ),
        (
            Box::new(|t| t.asset_leg.kind = LegKind::Kas),
            "HTLC_ASSET_KIND",
        ),
        (Box::new(|t| t.asset_leg.amount = 0), "TERMS_AMOUNT_ZERO"),
        (
            Box::new(|t| t.buyer_delivery.identifier = [0; 32]),
            "TERMS_ZERO_IDENTIFIER",
        ),
        (Box::new(|t| t.hash_lock = [0; 32]), "HTLC_HASH_ZERO"),
        (Box::new(|t| t.counterpart.amount = 0), "HTLC_COUNTERPART"),
        (
            Box::new(|t| t.expiry_daa = u64::MAX),
            "TERMS_EXPIRY_NOT_DAA",
        ),
    ];
    // Each fault together with every later one still reports itself.
    for i in 0..pairs.len() {
        let mut t = v1();
        for (edit, _) in &pairs[i..] {
            edit(&mut t);
        }
        assert_eq!(code(t.validate_structure()), pairs[i].1, "from {i}");
    }
}

// =============================================================================================
// Creation checks, the DAA rate and the margin rule
// =============================================================================================

#[test]
fn pinned_networks_run_at_ten_blocks_per_second() {
    assert_eq!(margin::params(Network::Mainnet).bps(), 10);
    assert_eq!(margin::params(Network::Testnet).bps(), 10);
}

#[test]
fn every_vector_passes_the_creation_checks() {
    let s = sample();
    for v in vectors() {
        let checked = v.terms.clone().validate_structure().unwrap();
        assert_eq!(
            checked.validate_creation(&context(v.terms.network, &s)),
            Ok(()),
            "{}",
            v.name
        );
    }
}

#[test]
fn creation_checks_v1_order() {
    let s = sample();
    let checked = v1().validate_structure().unwrap();
    let mut ctx = context(Network::Mainnet, &s);
    ctx.creation.network = Network::Testnet;
    assert_eq!(
        code(checked.validate_creation(&ctx)),
        "TERMS_NETWORK_MISMATCH"
    );
    let mut ctx = context(Network::Mainnet, &s);
    ctx.creation.creation_daa = checked.terms().expiry_daa;
    assert_eq!(
        code(checked.validate_creation(&ctx)),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    let mut ctx = context(Network::Mainnet, &s);
    ctx.creation.max_expiry_horizon_daa = 1;
    assert_eq!(
        code(checked.validate_creation(&ctx)),
        "TERMS_EXPIRY_BEYOND_HORIZON"
    );
    // The v1 checks come before the sample: a mis-networked trade without a sample is a network
    // mismatch.
    let mut ctx = context(Network::Mainnet, &s);
    ctx.margin.sample = None;
    ctx.creation.network = Network::Testnet;
    assert_eq!(
        code(checked.validate_creation(&ctx)),
        "TERMS_NETWORK_MISMATCH"
    );
}

/// Review round 2: a counterpart timeout at or before the time of the check is refused at
/// creation (`HTLC_COUNTERPART`), after v1's three and before the sample, so a library or WASM
/// caller cannot pass the margin rule with a timeout already gone.
#[test]
fn creation_refuses_a_past_counterpart_timeout() {
    let s = sample();
    let ctx = context(Network::Mainnet, &s);
    for (timeout, want) in [
        (NOW_UNIX - 1, Some("HTLC_COUNTERPART")),
        (NOW_UNIX, Some("HTLC_COUNTERPART")),
        (NOW_UNIX + 1, None),
    ] {
        let mut t = v1();
        t.counterpart.timeout = timeout;
        let checked = t.validate_structure().unwrap();
        let got = checked.validate_creation(&ctx);
        match want {
            Some(c) => assert_eq!(code(got), c, "timeout {timeout}"),
            None => assert_eq!(got, Ok(()), "timeout {timeout}"),
        }
    }
    // After v1's checks: a mis-networked trade with a past timeout is a network mismatch.
    let mut t = v1();
    t.counterpart.timeout = 1;
    let checked = t.validate_structure().unwrap();
    let mut wrong = context(Network::Mainnet, &s);
    wrong.creation.network = Network::Testnet;
    assert_eq!(
        code(checked.validate_creation(&wrong)),
        "TERMS_NETWORK_MISMATCH"
    );
    // Before the sample: a past timeout on mainnet without a sample is the timeout.
    let mut none = context(Network::Mainnet, &s);
    none.margin.sample = None;
    assert_eq!(code(checked.validate_creation(&none)), "HTLC_COUNTERPART");
}

/// spec/V2.md section 11.3: a fresh, a stale, a missing and a wrong-rate sample.
#[test]
fn daa_rate_sample_cases() {
    let checked = v1().validate_structure().unwrap();
    let fresh = sample();
    let run = |sample: Option<&DaaRateSample>, now: u64| {
        let mut ctx = context(Network::Mainnet, &fresh);
        ctx.margin.sample = sample;
        ctx.margin.now_unix = now;
        checked.validate_creation(&ctx)
    };
    assert_eq!(run(Some(&fresh), NOW_UNIX), Ok(()), "fresh");
    assert_eq!(
        code(run(None, NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "missing on mainnet"
    );
    let last = fresh.points.last().unwrap().0;
    // At most 30 days old: accepted at exactly 30 days, refused one second later. The vector's
    // timeout is in the past by then, so these two runs move it to one second after the check.
    let aged = last + MAX_SAMPLE_AGE_SECS;
    let mut later = v1();
    later.counterpart.timeout = aged + 2;
    let later = later.validate_structure().unwrap();
    let run = |sample: Option<&DaaRateSample>, now: u64| {
        let mut ctx = context(Network::Mainnet, &fresh);
        ctx.margin.sample = sample;
        ctx.margin.now_unix = now;
        if now >= aged {
            later.validate_creation(&ctx)
        } else {
            checked.validate_creation(&ctx)
        }
    };
    assert_eq!(run(Some(&fresh), aged), Ok(()), "30 days");
    assert_eq!(
        code(run(Some(&fresh), last + MAX_SAMPLE_AGE_SECS + 1)),
        "HTLC_DAA_SAMPLE",
        "stale"
    );
    let mut wrong_rate = fresh.clone();
    wrong_rate.bps = 1;
    assert_eq!(
        code(run(Some(&wrong_rate), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "another BPS"
    );
    let mut short = fresh.clone();
    short.points.truncate(short.points.len() - 2);
    assert_eq!(
        code(run(Some(&short), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "under 7 days"
    );
    let mut gap = fresh.clone();
    gap.points.remove(10);
    gap.points.remove(10);
    assert_eq!(
        code(run(Some(&gap), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "a gap over 10 minutes"
    );
    let mut disordered = fresh.clone();
    disordered.points.swap(3, 4);
    assert_eq!(
        code(run(Some(&disordered), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "order"
    );
    let mut falling = fresh.clone();
    falling.points[5].1 = 0;
    assert_eq!(
        code(run(Some(&falling), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "falling DAA"
    );
    assert_eq!(
        code(run(Some(&fresh), last - 1)),
        "HTLC_DAA_SAMPLE",
        "ends after now"
    );
    let flat = DaaRateSample {
        bps: 10,
        points: fresh.points.iter().map(|(t, _)| (*t, 7)).collect(),
    };
    assert_eq!(
        code(run(Some(&flat), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "no progress"
    );
    let single = DaaRateSample {
        bps: 10,
        points: vec![(NOW_UNIX - 10, 1)],
    };
    assert_eq!(
        code(run(Some(&single), NOW_UNIX)),
        "HTLC_DAA_SAMPLE",
        "one point"
    );
}

#[test]
fn daa_rate_max_values() {
    // Testnet without a sample: 2 times the target, 20 per second.
    assert_eq!(
        daa_rate_max(Network::Testnet, None, NOW_UNIX),
        Ok(DaaRate { daa: 20, secs: 1 })
    );
    // The synthetic sample: 10 per second at most, so 15 per second.
    let s = sample();
    let r = daa_rate_max(Network::Mainnet, Some(&s), NOW_UNIX).unwrap();
    assert_eq!(r.daa, 15 * r.secs);
    // A burst in one window raises the maximum to 1.5 times the burst.
    let mut burst = s.clone();
    for p in burst.points.iter_mut().skip(100) {
        p.1 += 12_000; // 12,000 more DAA between points 99 and 100, 300 s apart
    }
    let r = daa_rate_max(Network::Mainnet, Some(&burst), NOW_UNIX).unwrap();
    // The busiest window spans points 98 to 100 (or 99 to 101): 6,000 + 12,000 in 600 s.
    assert_eq!(r.daa * 600 * 2, 18_000 * 3 * r.secs);
    // A testnet sample is used, and checked, when given.
    assert_eq!(
        daa_rate_max(Network::Testnet, Some(&s), NOW_UNIX),
        Ok(r_of(&s))
    );
    let mut wrong = s.clone();
    wrong.bps = 11;
    assert_eq!(
        code(daa_rate_max(Network::Testnet, Some(&wrong), NOW_UNIX)),
        "HTLC_DAA_SAMPLE"
    );
}

/// Review round 2: a 10-minute burst inside gaps of nearly 10 minutes is measured over a fixed
/// 10-minute window, not averaged over the nearly 20 minutes to the next point at least 10
/// minutes on. Points 599 s apart at 10 per second, one interval at 30 per second.
#[test]
fn daa_rate_burst_between_long_gaps() {
    let end = NOW_UNIX - HOUR_SECS;
    let steps = MIN_SAMPLE_SECS / 599 + 2;
    let burst_at = steps / 2;
    let mut d = 1_000_000u64;
    let mut points = vec![(end - steps * 599, d)];
    for i in 1..=steps {
        d += if i == burst_at { 3 * 5_990 } else { 5_990 };
        points.push((end - (steps - i) * 599, d));
    }
    let s = DaaRateSample { bps: 10, points };
    let r = r_of(&s);
    // The busiest 600 s: the 599 s burst and 1 s of base rate, 17,980 DAA; times 1.5.
    assert_eq!(r.daa * 600 * 2, 17_980 * 3 * r.secs, "{r:?}");
    // At least 1.5 times 29 per second: the burst is not halved.
    assert!(r.daa * 2 >= 29 * 3 * r.secs, "{r:?}");
}

/// Windows run over fixed 10 minutes with the DAA score read linearly between points, so the
/// rate of a steady sample is the same whatever the spacing of its points.
#[test]
fn daa_rate_fixed_windows_are_spacing_independent() {
    for gap in [1u64, 7, 60, 240, 300, 599, 600] {
        let end = NOW_UNIX - HOUR_SECS;
        let steps = MIN_SAMPLE_SECS / gap + 1;
        let s = DaaRateSample {
            bps: 10,
            points: (0..=steps)
                .map(|i| (end - (steps - i) * gap, 1 + i * gap * 10))
                .collect(),
        };
        assert_eq!(r_of(&s), DaaRate { daa: 15, secs: 1 }, "gap {gap}");
    }
}

/// A steady sample of `per_10s` DAA every 10 seconds over 7 days, ending an hour before now.
fn steady(per_10s: u64) -> DaaRateSample {
    let end = NOW_UNIX - HOUR_SECS;
    let steps = MIN_SAMPLE_SECS / 300 + 1;
    DaaRateSample {
        bps: 10,
        points: (0..=steps)
            .map(|i| (end - (steps - i) * 300, 1 + i * 30 * per_10s))
            .collect(),
    }
}

/// Security review: a lying or forged sample that shows a slow rate would make `DAA_RATE_MAX`
/// low and the expiry estimate late, so the buyer could see expiry earlier than the margin
/// assumed. `DAA_RATE_MAX` is never below the target rate, and a sample whose mean rate is
/// below half the target is refused.
#[test]
fn a_slow_sample_never_lowers_the_rate_below_target() {
    // A mean rate of 6 per second: accepted, but 1.5 times 6 is 9, under the target of 10.
    assert_eq!(r_of(&steady(60)), DaaRate { daa: 10, secs: 1 });
    // Exactly half the target, 5 per second: accepted, at the target.
    assert_eq!(r_of(&steady(50)), DaaRate { daa: 10, secs: 1 });
    // Just under half the target is refused.
    assert_eq!(
        code(daa_rate_max(Network::Mainnet, Some(&steady(49)), NOW_UNIX)),
        "HTLC_DAA_SAMPLE"
    );
    // A burst that lifts one window does not hide a slow mean.
    let mut slow = steady(10);
    for p in slow.points.iter_mut().skip(100) {
        p.1 += 1_000_000;
    }
    assert_eq!(
        code(daa_rate_max(Network::Mainnet, Some(&slow), NOW_UNIX)),
        "HTLC_DAA_SAMPLE"
    );
    // Once 1.5 times the peak passes the target the sample decides: 7 per second gives 10.5.
    assert_eq!(r_of(&steady(70)), DaaRate { daa: 21, secs: 2 });
    assert_eq!(r_of(&steady(100)), DaaRate { daa: 15, secs: 1 });
    assert_eq!(MIN_SAMPLE_MEAN_OF_TARGET, (1, 2));
}

fn r_of(s: &DaaRateSample) -> DaaRate {
    daa_rate_max(Network::Mainnet, Some(s), NOW_UNIX).unwrap()
}

#[test]
fn margin_rule() {
    let s = sample();
    let ctx = context(Network::Mainnet, &s);
    let t = v1();
    let e = margin_estimate(&t, CREATION_DAA, &ctx.margin).unwrap();
    // 15 per second: 600 DAA is 40 s; Δ = 40 + 1,830 + 1,800.
    assert_eq!(e.delta_secs, 3_670);
    assert_eq!(e.required_unix, t.counterpart.timeout + 3_670);
    assert_eq!(e.expiry_estimate_unix, NOW_UNIX + 2 * 864_000 / 15);
    // The depth counts when the sum passes the floor: a 3,600 s retry window gives
    // 40 + 1,830 + 3,600 = 5,470 s.
    let mut slow = ctx.margin;
    slow.retry_secs = 3_600;
    assert_eq!(
        margin_estimate(&t, CREATION_DAA, &slow).unwrap().delta_secs,
        5_470
    );
    // Δ is never under an hour.
    let mut quick = ctx.margin;
    quick.counterpart_final_secs = 0;
    quick.retry_secs = 0;
    assert_eq!(
        margin_estimate(&t, CREATION_DAA, &quick)
            .unwrap()
            .delta_secs,
        MIN_DELTA_SECS
    );
    assert_eq!(FINALITY_DEPTH_DAA, 600);
    // A counterpart timeout too close to expiry is refused, one second past the boundary.
    let mut late = t.clone();
    late.counterpart.timeout = e.expiry_estimate_unix - e.delta_secs;
    let checked = late.clone().validate_structure().unwrap();
    assert_eq!(checked.validate_creation(&ctx), Ok(()));
    late.counterpart.timeout += 1;
    let checked = late.validate_structure().unwrap();
    assert_eq!(code(checked.validate_creation(&ctx)), "HTLC_TIMEOUT_MARGIN");
    // A slower counterpart chain widens Δ.
    let mut slow = ctx.margin;
    slow.counterpart_final_secs = 10 * HOUR_SECS;
    assert_eq!(
        margin_estimate(&t, CREATION_DAA, &slow).unwrap().delta_secs,
        40 + 10 * HOUR_SECS + 1_800
    );
}

// =============================================================================================
// Template
// =============================================================================================

const ARTIFACT: &str = include_str!("../../../../contracts/compiled/impulse_hashlock.v1.json");
const PIN: &str = include_str!("../../../../contracts/TEMPLATE_HASH_HASHLOCK");

#[test]
fn template_startup_check() {
    let t = check_template().unwrap();
    assert_eq!(hex(&t.hash()) + "\n", PIN);
    assert_eq!(
        hex(&t.hash()),
        "1e708d70c86ace8015778ccb693573b109dcd7135cf921366525a6f4aeef43d6"
    );
    assert_eq!((t.prefix().len(), t.suffix().len()), (1, 2020));
    let load = |a: &str, p: &str| HtlcTemplate::load(a, p);
    assert_eq!(code(load("{", PIN)), "HTLC_ARTIFACT_INVALID");
    assert_eq!(code(load(ARTIFACT, "not a hash")), "HTLC_ARTIFACT_INVALID");
    let v1_artifact = include_str!("../../../../contracts/compiled/impulse_vault.v1.json");
    assert_eq!(code(load(v1_artifact, PIN)), "HTLC_ARTIFACT_INVALID");
    let other_pin = format!("{}\n", "ab".repeat(32));
    assert_eq!(code(load(ARTIFACT, &other_pin)), "HTLC_HASH_MISMATCH");
    // A declared hash that is not the bytes' own.
    let mut doc: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();
    doc["contracts"]["ImpulseHashlock"]["compiled"]["template_hash"][0] = 0.into();
    assert_eq!(code(load(&doc.to_string(), PIN)), "HTLC_HASH_MISMATCH");
    // A renamed state field is another layout.
    let mut doc: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();
    doc["contracts"]["ImpulseHashlock"]["runtime_state"]["fields"][15]["name"] = "expiry".into();
    assert_eq!(code(load(&doc.to_string(), PIN)), "HTLC_ARTIFACT_INVALID");
}

fn vault_script(t: &HtlcTerms) -> Vec<u8> {
    let checked = t.clone().validate_structure().unwrap();
    HtlcVault::instantiate_existing(&checked)
        .unwrap()
        .redeem_script()
        .to_vec()
}

#[test]
fn instantiate_and_decode_round_trip() {
    for v in vectors() {
        let script = vault_script(&v.terms);
        assert_eq!(decode(&script), Ok(v.terms.state()), "{}", v.name);
        assert_eq!(
            template_hash_of_instance(&script),
            Ok(check_template().unwrap().hash())
        );
        // The state span is 350 bytes for every vector (fixed-width state).
        assert_eq!(script.len(), 1 + 350 + 2020, "{}", v.name);
    }
    // Every terms field is in the address: change any one and the script changes.
    let base = vault_script(&v1());
    let edits: Vec<Edit> = vec![
        Box::new(|t| t.network = Network::Testnet),
        Box::new(|t| t.nonce ^= 1),
        Box::new(|t| t.asset_leg.amount += 1),
        Box::new(|t| t.hash_lock[0] ^= 1),
        Box::new(|t| t.expiry_daa += 1),
        Box::new(|t| t.counterpart.timeout += 1),
        Box::new(|t| t.counterpart.chain = CounterpartChain::OtherSha256),
        Box::new(|t| t.trade_ref[0] ^= 1),
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut t = v1();
        edit(&mut t);
        assert_ne!(vault_script(&t), base, "edit {i}");
    }
}

fn splice(state: &[u8]) -> Vec<u8> {
    let t = check_template().unwrap();
    [t.prefix(), state, t.suffix()].concat()
}

fn state_of(script: &[u8]) -> &[u8] {
    &script[1..script.len() - 2020]
}

#[test]
fn decode_refusals() {
    let good = vault_script(&v1());
    let state = state_of(&good).to_vec();
    // Not the template: a v1 vault, garbage, a script shorter than the template.
    let v1_terms = crate::terms::golden::vectors().remove(0).terms;
    let v1_vault = crate::template::Vault::instantiate_existing(
        &v1_terms.validate_structure().unwrap(),
        crate::template::LegIndex::Asset,
    )
    .unwrap();
    assert_eq!(
        code(decode(v1_vault.redeem_script())),
        "HTLC_NOT_HASHLOCK_VAULT"
    );
    assert_eq!(code(decode(&[0x51; 100])), "HTLC_NOT_HASHLOCK_VAULT");
    assert_eq!(code(decode(&good[..1000])), "HTLC_NOT_HASHLOCK_VAULT");
    assert_eq!(
        code(template_hash_of_instance(&good[..100])),
        "HTLC_NOT_HASHLOCK_VAULT"
    );
    // And the v1 decoder refuses a hashlock vault (spec/V2.md section 2).
    assert_eq!(
        crate::template::decode(&good).unwrap_err().code(),
        "TEMPLATE_NOT_IMPULSE_VAULT"
    );
    // Malformed state: one byte short.
    assert_eq!(
        code(decode(&splice(&state[..state.len() - 1]))),
        "HTLC_STATE_MALFORMED"
    );
    // Field offsets: version 0, network 2, nonce 4, sellerKey 13, buyerKey 46, covenant 79,
    // template hash 112, prefix 145, suffix 154, amount 163, delivery type 172, delivery 174,
    // refund type 207, refund 209, hash lock 242, expiry 275, counterpart 284, trade ref 317.
    assert_eq!(&state[0..2], &[0x01, 0x01]);
    assert_eq!(&state[2..4], &[0x01, 0x00]);
    assert_eq!(&state[14..46], &v1().seller_key);
    assert_eq!(&state[243..275], &v1().hash_lock);
    let with = |at: usize, b: u8| {
        let mut s = state.clone();
        s[at] = b;
        splice(&s)
    };
    assert_eq!(code(decode(&with(3, 2))), "HTLC_STATE_INVALID", "network 2");
    assert_eq!(
        code(decode(&with(173, 3))),
        "HTLC_STATE_INVALID",
        "owner type 3"
    );
    assert_eq!(
        code(decode(&with(208, 3))),
        "HTLC_STATE_INVALID",
        "owner type 3"
    );
    assert_eq!(
        code(decode(&with(171, 0x80))),
        "HTLC_STATE_INVALID",
        "negative amount"
    );
    assert_eq!(
        code(decode(&with(283, 0x80))),
        "HTLC_STATE_INVALID",
        "negative expiry"
    );
    // Structure checks run on the decoded state.
    assert_eq!(code(decode(&with(1, 2))), "HTLC_VERSION");
    let mut zero_lock = state.clone();
    zero_lock[243..275].fill(0);
    assert_eq!(code(decode(&splice(&zero_lock))), "HTLC_HASH_ZERO");
    // Non-canonical: sellerKey as OpPushData1 32 instead of OpData32.
    assert_eq!(state[13], 0x20);
    let long_push = [&state[..13], &[0x4c, 0x20], &state[14..]].concat();
    assert_eq!(code(decode(&splice(&long_push))), "HTLC_NONCANONICAL");
}

#[test]
fn addresses_follow_the_network() {
    let s = sample();
    for v in vectors() {
        let a = golden::fundable(&v).address();
        let prefix = match v.terms.network {
            Network::Mainnet => "kaspa:p",
            Network::Testnet => "kaspatest:p",
        };
        assert!(a.starts_with(prefix), "{a}");
        let checked = v.terms.clone().validate_structure().unwrap();
        let ctx = context(v.terms.network, &s);
        let verified = verify_address(&checked, &ctx, Some(&a)).unwrap();
        assert_eq!(verified.address, a);
        assert_eq!(
            verified.script_hash,
            HtlcVault::instantiate_existing(&checked)
                .unwrap()
                .script_hash()
        );
    }
}

// =============================================================================================
// Builders
// =============================================================================================

const AMOUNT: u64 = 1_000;
const EXPIRY: u64 = 2_000_000;
const NOW_DAA: u64 = 1_500_000;

/// Terms over the fixture KCC-20 token, with hash_lock = sha256(PREIMAGE).
fn trade() -> (ValidatedHtlcTerms, Kcc20Template) {
    let template = asset_template();
    let mut t = v1();
    t.network = Network::Testnet;
    t.asset_leg = Leg {
        kind: LegKind::Kcc20(Kcc20Token {
            covenant_id: ASSET_COV,
            template_hash: template.template_hash(),
            template_prefix_len: template.prefix_len() as u32,
            template_suffix_len: template.suffix_len() as u32,
        }),
        amount: AMOUNT,
    };
    t.hash_lock = sha256(&PREIMAGE);
    t.expiry_daa = EXPIRY;
    // 500,000 DAA to expiry at 20 per second is 25,000 s; T_C plus Δ is 18,000 + 3,600.
    t.counterpart.timeout = NOW_UNIX + 5 * HOUR_SECS;
    (t.validate_structure().unwrap(), template)
}

fn payer() -> [u8; 32] {
    crate::terms::golden::xonly("impulse/tests/htlc/key/payer")
}

fn fee() -> FeePayment {
    FeePayment {
        inputs: vec![utxo("htlc-fee", FEE_INPUT, p2pk(&payer()), None)],
        fee: FEE,
        change: p2pk(&payer()),
    }
}

struct Funded {
    authorizer: Utxo,
    escrow: Utxo,
}

fn escrow_state(terms: &ValidatedHtlcTerms, amount: u64) -> Kcc20State {
    let vault = HtlcVault::instantiate_existing(terms).unwrap();
    Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        amount,
    )
}

fn funded(terms: &ValidatedHtlcTerms, template: &Kcc20Template) -> Funded {
    let vault = HtlcVault::instantiate_existing(terms).unwrap();
    Funded {
        authorizer: utxo(
            "htlc-authorizer",
            MIN_KAS_OUTPUT,
            vault.script_public_key(),
            None,
        ),
        escrow: utxo(
            "htlc-escrow",
            CARRIER,
            template
                .script_public_key(&escrow_state(terms, AMOUNT))
                .unwrap(),
            Some(ASSET_COV),
        ),
    }
}

fn testnet_ctx<'a>() -> HtlcCreationContext<'a> {
    HtlcCreationContext {
        creation: CreationContext::new(Network::Testnet, NOW_DAA),
        margin: MarginContext {
            now_unix: NOW_UNIX,
            counterpart_final_secs: 60,
            retry_secs: DEFAULT_RETRY_SECS,
            sample: None,
        },
    }
}

fn fundable(terms: &ValidatedHtlcTerms) -> FundableHtlcVault {
    HtlcVault::instantiate_for_creation(terms, &testnet_ctx()).unwrap()
}

fn deposit(template: &Kcc20Template, amounts: &[u64]) -> Kcc20Deposit {
    let seller = v1().seller_key;
    Kcc20Deposit {
        tokens: amounts
            .iter()
            .enumerate()
            .map(|(i, a)| own_token(&format!("htlc-token-{i}"), template, ASSET_COV, &seller, *a))
            .collect(),
        carrier: CARRIER,
        authorizer: MIN_KAS_OUTPUT,
    }
}

#[test]
fn fund_layout() {
    let (terms, template) = trade();
    let vault = fundable(&terms);
    let ipst = fund(
        &terms,
        &vault,
        &template,
        &deposit(&template, &[3 * AMOUNT]),
        &fee(),
        NOW_DAA,
    )
    .unwrap();
    let tx = ipst.transaction();
    assert_eq!(tx.lock_time, 0);
    assert_eq!(tx.outputs.len(), 4);
    assert_eq!(
        tx.outputs[0].script_public_key,
        template
            .script_public_key(&escrow_state(&terms, AMOUNT))
            .unwrap()
    );
    let binding = tx.outputs[0].covenant.unwrap();
    assert_eq!(
        (binding.authorizing_input, binding.covenant_id),
        (0, Hash::from_bytes(ASSET_COV))
    );
    assert_eq!(
        tx.outputs[1].script_public_key,
        vault.vault().script_public_key()
    );
    assert_eq!(tx.outputs[1].value, MIN_KAS_OUTPUT);
    assert!(tx.outputs[1].covenant.is_none());
    assert_eq!(tx.outputs[3].script_public_key, p2pk(&payer()));
    // The seller signs the token input, the payer the fee input.
    assert_eq!(ipst.slots()[0].signer(), Some(v1().seller_key));
    assert_eq!(ipst.slots()[1].signer(), Some(payer()));
    assert_eq!(ipst.pending(), vec![0, 1]);
    assert_eq!(ipst.fee(), FEE);
    let m = ipst.verify_against_terms(&template, NOW_DAA).unwrap();
    assert_eq!(m.kind, HtlcIpstKind::Fund);
    assert_eq!(m.change, Some(tx.outputs[3].clone()));
    // Exact tokens: no token change.
    let exact = fund(
        &terms,
        &vault,
        &template,
        &deposit(&template, &[AMOUNT]),
        &fee(),
        NOW_DAA,
    )
    .unwrap();
    assert_eq!(exact.transaction().outputs.len(), 3);
    // Two tokens: leader and delegate.
    let two = fund(
        &terms,
        &vault,
        &template,
        &deposit(&template, &[600, 700]),
        &fee(),
        NOW_DAA,
    )
    .unwrap();
    assert_eq!(two.pending(), vec![0, 1, 2]);
    assert_eq!(
        two.verify_against_terms(&template, NOW_DAA).unwrap().kind,
        HtlcIpstKind::Fund
    );
}

#[test]
fn fund_refusals() {
    let (terms, template) = trade();
    let vault = fundable(&terms);
    let d = deposit(&template, &[AMOUNT]);
    assert_eq!(
        code(fund(&terms, &vault, &template, &d, &fee(), EXPIRY)),
        "TX_EXPIRED"
    );
    // The vault of other terms.
    let mut other = terms.terms().clone();
    other.nonce ^= 1;
    let other = other.validate_structure().unwrap();
    assert_eq!(
        code(fund(
            &terms,
            &fundable(&other),
            &template,
            &d,
            &fee(),
            NOW_DAA
        )),
        "TX_VAULT_MISMATCH"
    );
    let wrong_template = crate::tx::testkit::cash_template();
    assert_eq!(
        code(fund(&terms, &vault, &wrong_template, &d, &fee(), NOW_DAA)),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(
        code(fund(
            &terms,
            &vault,
            &template,
            &deposit(&template, &[AMOUNT - 1]),
            &fee(),
            NOW_DAA
        )),
        "TX_TOKEN_INPUT"
    );
    let low = Kcc20Deposit {
        authorizer: MIN_KAS_OUTPUT - 1,
        ..d.clone()
    };
    assert_eq!(
        code(fund(&terms, &vault, &template, &low, &fee(), NOW_DAA)),
        "TX_BELOW_MIN_KAS"
    );
    let no_fee = FeePayment {
        inputs: vec![],
        ..fee()
    };
    assert_eq!(
        code(fund(&terms, &vault, &template, &d, &no_fee, NOW_DAA)),
        "TX_KAS_INPUT"
    );
    let cheap = FeePayment { fee: 1, ..fee() };
    assert_eq!(
        code(fund(&terms, &vault, &template, &d, &cheap, NOW_DAA)),
        "TX_FEE_TOO_LOW"
    );
    // The creation checks guard the funding vault: an expired trade has none.
    let mut ctx = testnet_ctx();
    ctx.creation.creation_daa = EXPIRY;
    assert_eq!(
        code(HtlcVault::instantiate_for_creation(&terms, &ctx)),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
}

#[test]
fn claim_layout() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let ipst = claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee(),
    )
    .unwrap();
    let tx = ipst.transaction();
    let t = terms.terms();
    assert_eq!(tx.lock_time, 0);
    assert_eq!(tx.inputs[0].previous_outpoint, f.authorizer.outpoint);
    assert_eq!(tx.inputs[1].previous_outpoint, f.escrow.outpoint);
    let delivered = Kcc20State::new(t.buyer_delivery, AMOUNT);
    assert_eq!(
        tx.outputs[0].script_public_key,
        template.script_public_key(&delivered).unwrap()
    );
    assert_eq!(tx.outputs[0].covenant.unwrap().authorizing_input, 1);
    assert_eq!(tx.outputs[0].value, CARRIER);
    assert_eq!(tx.outputs[1].script_public_key, p2pk(&t.seller_key));
    assert_eq!(tx.outputs[1].value, MIN_KAS_OUTPUT);
    // Only the fee payer signs; the preimage is the first push of the vault input's script.
    assert_eq!(ipst.slots()[0].signer(), None);
    assert_eq!(ipst.slots()[1].signer(), None);
    assert_eq!(ipst.pending(), vec![2]);
    assert_eq!(
        super::tx::first_push(ipst.slots()[0].script_before()),
        Some(PREIMAGE.to_vec())
    );
    // Budgets: the claim's vault input is unsigned, so below the refund's.
    let budget = |i: usize| tx.inputs[i].compute_commit.compute_budget().unwrap();
    assert!(budget(0) >= CLAIM_VAULT_BUDGET);
    let m = ipst.verify_against_terms(&template, NOW_DAA).unwrap();
    assert_eq!(m.kind, HtlcIpstKind::Claim);
    // The claim builds after expiry too (R4).
    assert!(claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee()
    )
    .is_ok());
    // The spent vault input verifies.
    let input = TransactionInput::new(
        tx.inputs[0].previous_outpoint,
        ipst.slots()[0].script_before().to_vec(),
        0,
        0,
    );
    assert_eq!(
        verify_spent_input(&terms, &input, &f.authorizer.entry.script_public_key),
        Ok(())
    );
}

#[test]
fn claim_refusals() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let run = |a: &Utxo, e: &Utxo, t: &Kcc20Template, p: &[u8]| claim(&terms, a, e, t, p, &fee());
    for len in [0, 31, 33, 64] {
        assert_eq!(
            code(run(&f.authorizer, &f.escrow, &template, &vec![0x5C; len])),
            "HTLC_SECRET_LENGTH",
            "{len}"
        );
    }
    let mut wrong = PREIMAGE;
    wrong[31] ^= 1;
    assert_eq!(
        code(run(&f.authorizer, &f.escrow, &template, &wrong)),
        "HTLC_SECRET_MISMATCH"
    );
    assert_eq!(
        code(run(
            &f.authorizer,
            &f.escrow,
            &template,
            &terms.terms().hash_lock
        )),
        "HTLC_SECRET_MISMATCH"
    );
    assert_eq!(
        code(run(
            &f.authorizer,
            &f.escrow,
            &crate::tx::testkit::cash_template(),
            &PREIMAGE
        )),
        "TX_TOKEN_TEMPLATE"
    );
    let mut stray = f.authorizer.clone();
    stray.entry.script_public_key = p2pk(&payer());
    assert_eq!(
        code(run(&stray, &f.escrow, &template, &PREIMAGE)),
        "TX_NOT_AT_VAULT"
    );
    let mut covenanted = f.authorizer.clone();
    covenanted.entry.covenant_id = Some(Hash::from_bytes(ASSET_COV));
    assert_eq!(
        code(run(&covenanted, &f.escrow, &template, &PREIMAGE)),
        "TX_NOT_AT_VAULT"
    );
    let short = utxo(
        "htlc-escrow-short",
        CARRIER,
        template
            .script_public_key(&escrow_state(&terms, AMOUNT - 1))
            .unwrap(),
        Some(ASSET_COV),
    );
    assert_eq!(
        code(run(&f.authorizer, &short, &template, &PREIMAGE)),
        "TX_ESCROW_MISMATCH"
    );
    let mut other_cov = f.escrow.clone();
    other_cov.entry.covenant_id = Some(Hash::from_bytes([0xCA; 32]));
    assert_eq!(
        code(run(&f.authorizer, &other_cov, &template, &PREIMAGE)),
        "TX_ESCROW_MISMATCH"
    );
    assert_eq!(
        code(claim(
            &terms,
            &f.authorizer,
            &f.escrow,
            &template,
            &PREIMAGE,
            &FeePayment {
                inputs: vec![],
                ..fee()
            }
        )),
        "TX_KAS_INPUT"
    );
    // A fee input that is not the payer's P2PK: the authorizer again.
    let dup = FeePayment {
        inputs: vec![f.authorizer.clone()],
        ..fee()
    };
    assert_eq!(
        code(claim(
            &terms,
            &f.authorizer,
            &f.escrow,
            &template,
            &PREIMAGE,
            &dup
        )),
        "TX_KAS_INPUT"
    );
}

#[test]
fn refund_layouts() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let t = terms.terms();
    let escrow = RefundEscrow {
        utxo: f.escrow.clone(),
        amount: AMOUNT,
        is_minter: false,
        template: &template,
    };
    // The seller, with the token: lock time expiry_daa, the token home to seller_refund.
    let ipst = refund(
        &terms,
        HtlcRefundSigner::Seller,
        &f.authorizer,
        Some(&escrow),
        &fee(),
    )
    .unwrap();
    let tx = ipst.transaction();
    assert_eq!(tx.lock_time, EXPIRY);
    assert_eq!(tx.outputs[0].script_public_key, p2pk(&t.seller_key));
    assert_eq!(tx.outputs[0].value, f.authorizer.entry.amount);
    let home = Kcc20State::new(t.seller_refund, AMOUNT);
    assert_eq!(
        tx.outputs[1].script_public_key,
        template.script_public_key(&home).unwrap()
    );
    assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert_eq!(ipst.slots()[0].signer(), Some(t.seller_key));
    assert_eq!(ipst.pending(), vec![0, 2]);
    assert!(tx.inputs[0].compute_commit.compute_budget().unwrap() >= REFUND_VAULT_BUDGET);
    assert_eq!(
        ipst.verify_against_terms(&template, NOW_DAA).unwrap().kind,
        HtlcIpstKind::Refund {
            signer: HtlcRefundSigner::Seller,
            with_token: true
        }
    );
    // The seller alone.
    let alone = refund(
        &terms,
        HtlcRefundSigner::Seller,
        &f.authorizer,
        None,
        &fee(),
    )
    .unwrap();
    assert_eq!(alone.transaction().outputs.len(), 2);
    assert_eq!(
        alone.verify_against_terms(&template, NOW_DAA).unwrap().kind,
        HtlcIpstKind::Refund {
            signer: HtlcRefundSigner::Seller,
            with_token: false
        }
    );
    // The buyer: lock time 0.
    let buyer = refund(
        &terms,
        HtlcRefundSigner::Buyer,
        &f.authorizer,
        Some(&escrow),
        &fee(),
    )
    .unwrap();
    assert_eq!(buyer.transaction().lock_time, 0);
    assert_eq!(buyer.slots()[0].signer(), Some(t.buyer_key));
    // The seller may take home a decoy of another amount; a minter goes home a minter.
    let decoy_state = Kcc20State {
        is_minter: true,
        ..escrow_state(&terms, 5)
    };
    let decoy = RefundEscrow {
        utxo: utxo(
            "htlc-decoy",
            CARRIER,
            template.script_public_key(&decoy_state).unwrap(),
            Some(ASSET_COV),
        ),
        amount: 5,
        is_minter: true,
        template: &template,
    };
    let ipst = refund(
        &terms,
        HtlcRefundSigner::Seller,
        &f.authorizer,
        Some(&decoy),
        &fee(),
    )
    .unwrap();
    let home = Kcc20State {
        owner: t.seller_refund,
        ..decoy_state
    };
    assert_eq!(
        ipst.transaction().outputs[1].script_public_key,
        template.script_public_key(&home).unwrap()
    );
}

#[test]
fn refund_refusals() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let escrow = |amount: u64| RefundEscrow {
        utxo: utxo(
            "htlc-escrow-n",
            CARRIER,
            template
                .script_public_key(&escrow_state(&terms, amount))
                .unwrap(),
            Some(ASSET_COV),
        ),
        amount,
        is_minter: false,
        template: &template,
    };
    assert_eq!(
        code(refund(
            &terms,
            HtlcRefundSigner::Buyer,
            &f.authorizer,
            None,
            &fee()
        )),
        "TX_REFUND_SIGNER"
    );
    assert_eq!(
        code(refund(
            &terms,
            HtlcRefundSigner::Buyer,
            &f.authorizer,
            Some(&escrow(AMOUNT - 1)),
            &fee()
        )),
        "TX_LEG_AMOUNT"
    );
    let mut stray = f.authorizer.clone();
    stray.entry.script_public_key = p2pk(&payer());
    assert_eq!(
        code(refund(
            &terms,
            HtlcRefundSigner::Seller,
            &stray,
            None,
            &fee()
        )),
        "TX_NOT_AT_VAULT"
    );
    // A stated amount the script does not hold.
    let lying = RefundEscrow {
        amount: AMOUNT + 1,
        ..escrow(AMOUNT)
    };
    assert_eq!(
        code(refund(
            &terms,
            HtlcRefundSigner::Seller,
            &f.authorizer,
            Some(&lying),
            &fee()
        )),
        "TX_ESCROW_MISMATCH"
    );
    let cash = crate::tx::testkit::cash_template();
    let wrong = RefundEscrow {
        template: &cash,
        ..escrow(AMOUNT)
    };
    assert_eq!(
        code(refund(
            &terms,
            HtlcRefundSigner::Seller,
            &f.authorizer,
            Some(&wrong),
            &fee()
        )),
        "TX_TOKEN_TEMPLATE"
    );
}

#[test]
fn the_terms_check_refuses_any_change() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let ipst = claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee(),
    )
    .unwrap();
    let tampered = |edit: &dyn Fn(&mut kaspa_consensus_core::tx::Transaction)| {
        let mut x = ipst.clone();
        edit(x.tx_mut_for_test());
        x.verify_against_terms(&template, NOW_DAA)
    };
    assert_eq!(
        code(tampered(&|tx| tx.lock_time = 1)),
        "IPST_TERMS_MISMATCH"
    );
    assert_eq!(
        code(tampered(&|tx| tx.outputs[2].value -= 1)),
        "IPST_TERMS_MISMATCH"
    );
    assert_eq!(
        code(tampered(
            &|tx| tx.outputs[1].script_public_key = p2pk(&payer())
        )),
        "IPST_TERMS_MISMATCH"
    );
    assert_eq!(
        code(tampered(&|tx| {
            tx.inputs[0] = TransactionInput::new_with_compute_budget(
                tx.inputs[0].previous_outpoint,
                vec![],
                0,
                60,
            )
        })),
        "IPST_TERMS_MISMATCH"
    );
    // A builder refusal keeps its code: the claim of another preimage.
    let mut x = ipst.clone();
    x.slots_mut_for_test()[0] = {
        let other = claim(
            &terms,
            &f.authorizer,
            &f.escrow,
            &template,
            &PREIMAGE,
            &fee(),
        )
        .unwrap();
        let mut s = other.slots()[0].clone();
        s.set_before_for_test([&[0x20][..], &[0x11; 32][..], &s.script_before()[33..]].concat());
        s
    };
    assert_eq!(
        code(x.verify_against_terms(&template, NOW_DAA)),
        "HTLC_SECRET_MISMATCH"
    );
}

#[test]
fn signature_slots() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let mut ipst = claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee(),
    )
    .unwrap();
    assert_eq!(code(ipst.add_signature(0, &[0; 65])), "TX_SIGNATURE_SLOT");
    assert_eq!(code(ipst.add_signature(9, &[0; 65])), "TX_SIGNATURE_SLOT");
    assert_eq!(code(ipst.add_signature(2, &[0; 64])), "TX_SIGNATURE");
    assert_eq!(code(ipst.add_signature(2, &[0; 65])), "TX_SIGNATURE");
    assert_eq!(code(ipst.finalize()), "TX_SIGNATURE_SLOT");
    assert!(!ipst.is_complete());
}

// =============================================================================================
// Verifier
// =============================================================================================

#[test]
fn verify_address_refusals() {
    let s = sample();
    // A testnet vector: mainnet terms stop at the gate (mainnet_creation_is_gated).
    let v = vectors().remove(1);
    assert_eq!(v.terms.network, Network::Testnet);
    let checked = v.terms.clone().validate_structure().unwrap();
    let ctx = context(Network::Testnet, &s);
    let good = golden::fundable(&v).address();
    let run = |a: Option<&str>| verify_address(&checked, &ctx, a);
    assert!(run(Some(&good)).is_ok());
    assert_eq!(code(run(None)), "VERIFY_ADDRESS_MISSING");
    assert_eq!(code(run(Some("kaspatest"))), "VERIFY_ADDRESS_MALFORMED");
    assert_eq!(code(run(Some("kaspatest:qqq"))), "VERIFY_ADDRESS_MALFORMED");
    let mut bad_checksum = good.clone();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'q' { 'p' } else { 'q' });
    assert_eq!(code(run(Some(&bad_checksum))), "VERIFY_ADDRESS_MALFORMED");
    // The same payload on mainnet.
    let hash = HtlcVault::instantiate_existing(&checked)
        .unwrap()
        .script_hash();
    let addr = |p, ver| kaspa_addresses::Address::new(p, ver, &hash).to_string();
    use kaspa_addresses::{Prefix, Version};
    assert_eq!(
        code(run(Some(&addr(Prefix::Mainnet, Version::ScriptHash)))),
        "VERIFY_ADDRESS_NETWORK"
    );
    assert_eq!(
        code(run(Some(&addr(Prefix::Testnet, Version::PubKey)))),
        "VERIFY_ADDRESS_MISMATCH"
    );
    // Another trade's vault.
    let other = golden::fundable(&vectors().remove(4)).address();
    assert!(other.starts_with("kaspatest:"));
    assert_eq!(code(run(Some(&other))), "VERIFY_ADDRESS_MISMATCH");
    // The creation checks first: a trade checked against another network has nothing to fund.
    let mut elsewhere = ctx;
    elsewhere.creation.network = Network::Mainnet;
    assert_eq!(
        code(verify_address(&checked, &elsewhere, Some(&good))),
        "TERMS_NETWORK_MISMATCH"
    );
    // The gate is lifted: mainnet terms without a sample reach the creation checks and are
    // refused for the missing sample.
    let main = vectors().remove(0);
    let main_checked = main.terms.clone().validate_structure().unwrap();
    let mut no_sample = context(Network::Mainnet, &s);
    no_sample.margin.sample = None;
    assert_eq!(
        code(verify_address(
            &main_checked,
            &no_sample,
            Some(&golden::fundable(&main).address())
        )),
        "HTLC_DAA_SAMPLE"
    );
}

#[test]
fn verify_revealed_scripts() {
    let checked = v1().validate_structure().unwrap();
    let good = vault_script(&v1());
    assert_eq!(verify_revealed_script(&checked, &good), Ok(()));
    let v1_vault = crate::template::Vault::instantiate_existing(
        &crate::terms::golden::vectors()
            .remove(0)
            .terms
            .validate_structure()
            .unwrap(),
        crate::template::LegIndex::Asset,
    )
    .unwrap();
    assert_eq!(
        code(verify_revealed_script(&checked, v1_vault.redeem_script())),
        "HTLC_NOT_HASHLOCK_VAULT"
    );
    let mismatch = |edit: &dyn Fn(&mut HtlcTerms)| {
        let mut t = v1();
        edit(&mut t);
        match verify_revealed_script(&checked, &vault_script(&t)) {
            Err(HtlcError::Verify(crate::verify::VerifyError::TermsMismatch { fields })) => fields,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        mismatch(&|t| t.hash_lock = label32("other")),
        vec!["hash_lock"]
    );
    assert_eq!(
        mismatch(&|t| t.counterpart.amount += 1),
        vec!["counterpart"]
    );
    assert_eq!(
        mismatch(&|t| {
            t.nonce += 1;
            t.expiry_daa += 1;
        }),
        vec!["nonce", "expiry_daa"]
    );
    // A spent input: the binding to the UTXO it spends.
    let input = |sig: Vec<u8>| {
        TransactionInput::new(
            kaspa_consensus_core::tx::TransactionOutpoint::new(Hash::from_bytes([1; 32]), 0),
            sig,
            0,
            0,
        )
    };
    let vault = HtlcVault::instantiate_existing(&checked).unwrap();
    let revealing = crate::tx::push_data(&good).unwrap();
    assert_eq!(
        verify_spent_input(
            &checked,
            &input(revealing.clone()),
            &vault.script_public_key()
        ),
        Ok(())
    );
    assert_eq!(
        code(verify_spent_input(
            &checked,
            &input(vec![0x51]),
            &vault.script_public_key()
        )),
        "VERIFY_NOTHING_REVEALED"
    );
    assert_eq!(
        code(verify_spent_input(
            &checked,
            &input(revealing),
            &p2pk(&payer())
        )),
        "VERIFY_INPUT_NOT_VAULT"
    );
}

// Funding verifier (spec/V2.md section 10.5, step 3)
// =============================================================================================

/// The fixture trade's funding as `fund` builds it: escrow at output 0, authorizer at output 1,
/// token change at output 2, KAS change at output 3.
fn funding_tx(terms: &ValidatedHtlcTerms, template: &Kcc20Template) -> Transaction {
    fund(
        terms,
        &fundable(terms),
        template,
        &deposit(template, &[3 * AMOUNT]),
        &fee(),
        NOW_DAA,
    )
    .unwrap()
    .transaction()
    .clone()
}

/// The funding with output 0 holding `state` under `template`, covenant binding unchanged.
fn escrow_as(
    terms: &ValidatedHtlcTerms,
    template: &Kcc20Template,
    under: &Kcc20Template,
    state: &Kcc20State,
) -> Transaction {
    let mut tx = funding_tx(terms, template);
    tx.outputs[0].script_public_key = under.script_public_key(state).unwrap();
    tx
}

/// The buyer's check of the seller's funding before locking on the counterpart chain: exactly
/// one output holds the escrowed token (the asset's covenant, the asset's template, owned by the
/// vault's script hash, exactly the amount, not a minter) and an authorizer sits at the vault.
/// Every way a seller could fund short or wrong is refused (`HTLC_FUNDING`), each beside the
/// accepted control.
#[test]
fn verify_funding_accepts_only_the_agreed_escrow_and_an_authorizer() {
    let (terms, template) = trade();
    let tx = funding_tx(&terms, &template);
    let f = verify_funding(&terms, &template, &tx).unwrap();
    assert_eq!(f.escrow, TransactionOutpoint::new(tx.id(), 0));
    assert_eq!(f.authorizer, TransactionOutpoint::new(tx.id(), 1));
    let vault = HtlcVault::instantiate_existing(&terms).unwrap();
    let seller_owner = Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: v1().seller_key,
    };
    let mut minter = escrow_state(&terms, AMOUNT);
    minter.is_minter = true;
    let refused: Vec<(&str, Transaction)> = vec![
        ("no token", {
            let mut t = funding_tx(&terms, &template);
            t.outputs.remove(0);
            t
        }),
        (
            "amount - 1",
            escrow_as(
                &terms,
                &template,
                &template,
                &escrow_state(&terms, AMOUNT - 1),
            ),
        ),
        (
            "amount + 1",
            escrow_as(
                &terms,
                &template,
                &template,
                &escrow_state(&terms, AMOUNT + 1),
            ),
        ),
        (
            "key-owned token",
            escrow_as(
                &terms,
                &template,
                &template,
                &Kcc20State::new(seller_owner, AMOUNT),
            ),
        ),
        (
            "token owned by another script hash",
            escrow_as(
                &terms,
                &template,
                &template,
                &Kcc20State::new(
                    Kcc20Owner {
                        identifier_type: IdentifierType::ScriptHash,
                        identifier: [0x77; 32],
                    },
                    AMOUNT,
                ),
            ),
        ),
        (
            "minter token",
            escrow_as(&terms, &template, &template, &minter),
        ),
        (
            "token under another template",
            escrow_as(
                &terms,
                &template,
                &crate::tx::testkit::cash_template(),
                &escrow_state(&terms, AMOUNT),
            ),
        ),
        ("escrow without a covenant", {
            let mut t = funding_tx(&terms, &template);
            t.outputs[0].covenant = None;
            t
        }),
        ("escrow of another covenant", {
            let mut t = funding_tx(&terms, &template);
            t.outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([0x11; 32])));
            t
        }),
        ("two escrows", {
            let mut t = funding_tx(&terms, &template);
            let again = t.outputs[0].clone();
            t.outputs.push(again);
            t
        }),
        ("no authorizer", {
            let mut t = funding_tx(&terms, &template);
            t.outputs.remove(1);
            t
        }),
        ("authorizer carrying a covenant", {
            let mut t = funding_tx(&terms, &template);
            t.outputs[1].covenant = Some(CovenantBinding::new(0, Hash::from_bytes(ASSET_COV)));
            t
        }),
        ("authorizer at another address", {
            let mut t = funding_tx(&terms, &template);
            t.outputs[1].script_public_key = p2pk(&payer());
            t
        }),
        ("an unrelated transaction", {
            let mut t = funding_tx(&terms, &template);
            t.outputs.drain(..2);
            t
        }),
    ];
    for (what, t) in &refused {
        assert_eq!(
            code(verify_funding(&terms, &template, t)),
            "HTLC_FUNDING",
            "{what}"
        );
    }
    // The funding of another trade (another trade_ref, so another vault) is not this one's.
    let mut other = terms.terms().clone();
    other.trade_ref = [0x99; 32];
    let other = other.validate_structure().unwrap();
    assert_eq!(
        code(verify_funding(
            &terms,
            &template,
            &funding_tx(&other, &template)
        )),
        "HTLC_FUNDING"
    );
    // The template given must be the one the terms name.
    assert_eq!(
        code(verify_funding(
            &terms,
            &crate::tx::testkit::cash_template(),
            &tx
        )),
        "TX_TOKEN_TEMPLATE"
    );
    // A second authorizer is harmless (anyone may add one): the lowest output is reported.
    let mut extra = funding_tx(&terms, &template);
    extra.outputs.push(TransactionOutput::new(
        MIN_KAS_OUTPUT,
        vault.script_public_key(),
    ));
    let f = verify_funding(&terms, &template, &extra).unwrap();
    assert_eq!(f.authorizer.index, 1);
}

/// The funding verifier only reads: it accepts mainnet terms, as the other verifiers of an
/// existing vault do, so a buyer can check a vault made by other software.
#[test]
fn verify_funding_reads_mainnet_vaults() {
    let (terms, template) = trade();
    let tx = funding_tx(&terms, &template);
    let (main, _) = mainnet_trade();
    let vault = HtlcVault::instantiate_existing(&main).unwrap();
    let mut t = tx.clone();
    t.outputs[0].script_public_key = template
        .script_public_key(&Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::ScriptHash,
                identifier: vault.script_hash(),
            },
            AMOUNT,
        ))
        .unwrap();
    t.outputs[1].script_public_key = vault.script_public_key();
    assert!(verify_funding(&main, &template, &t).is_ok());
}

// =============================================================================================
// Codes
// =============================================================================================

#[test]
fn htlc_error_codes_are_frozen() {
    assert_eq!(
        HTLC_ERROR_CODES,
        [
            "HTLC_VERSION",
            "HTLC_ASSET_KIND",
            "HTLC_HASH_ZERO",
            "HTLC_COUNTERPART",
            "HTLC_TIMEOUT_MARGIN",
            "HTLC_ARTIFACT_INVALID",
            "HTLC_HASH_MISMATCH",
            "HTLC_NOT_HASHLOCK_VAULT",
            "HTLC_STATE_MALFORMED",
            "HTLC_STATE_INVALID",
            "HTLC_NONCANONICAL",
            "HTLC_SECRET_LENGTH",
            "HTLC_SECRET_MISMATCH",
            "HTLC_DAA_SAMPLE",
            "HTLC_MAINNET_GATED",
            "HTLC_FUNDING",
        ]
    );
    let all = [
        HtlcError::Version { version: 2 },
        HtlcError::AssetKind,
        HtlcError::HashZero,
        HtlcError::Counterpart { field: "f" },
        HtlcError::TimeoutMargin {
            expiry_estimate_unix: 1,
            required_unix: 2,
        },
        HtlcError::ArtifactInvalid { reason: "r".into() },
        HtlcError::HashMismatch {
            expected: [1; 32],
            found: [2; 32],
        },
        HtlcError::NotHashlockVault,
        HtlcError::StateMalformed { reason: "r".into() },
        HtlcError::StateInvalid { field: "f" },
        HtlcError::NonCanonical,
        HtlcError::SecretLength { len: 3 },
        HtlcError::SecretMismatch,
        HtlcError::DaaSample { reason: "r" },
        HtlcError::MainnetGated,
        HtlcError::Funding { reason: "r" },
    ];
    let codes: Vec<&str> = all.iter().map(HtlcError::code).collect();
    assert_eq!(codes, HTLC_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()), "{e}");
    }
    // Reused v1 codes pass through with their own code and text.
    let terms = HtlcError::from(crate::terms::TermsError::EarliestZero);
    assert_eq!(terms.code(), "TERMS_EARLIEST_ZERO");
    assert_eq!(
        terms.to_string(),
        crate::terms::TermsError::EarliestZero.to_string()
    );
    for c in HTLC_ERROR_CODES {
        assert!(!crate::terms::TERMS_ERROR_CODES.contains(&c));
        assert!(!crate::tx::TX_ERROR_CODES.contains(&c));
    }
}

#[test]
fn check_preimage_rules() {
    let (terms, _) = trade();
    assert_eq!(check_preimage(&terms, &PREIMAGE), Ok(()));
    for len in [0, 31, 33, 64] {
        assert_eq!(
            code(check_preimage(&terms, &vec![0x5C; len])),
            "HTLC_SECRET_LENGTH"
        );
    }
    assert_eq!(
        code(check_preimage(&terms, &[0x5D; 32])),
        "HTLC_SECRET_MISMATCH"
    );
}

#[cfg(feature = "htlc-secret")]
#[test]
fn hashlock_secret() {
    let a = HashlockSecret::generate();
    let b = HashlockSecret::generate();
    assert_ne!(a.expose(), b.expose(), "fresh per trade");
    assert_eq!(a.hash_lock(), sha256(a.expose()));
    let shown = format!("{a:?}");
    assert_eq!(shown, "HashlockSecret(<redacted>)");
    assert!(!shown.contains(&hex(a.expose())));
    assert_eq!(
        code(HashlockSecret::from_bytes(&[1; 31])),
        "HTLC_SECRET_LENGTH"
    );
    let read_back = HashlockSecret::from_bytes(a.expose()).unwrap();
    assert_eq!(read_back.hash_lock(), a.hash_lock());
    // Terms made with the secret's hash lock accept it as the claim's preimage.
    let mut t = v1();
    t.hash_lock = a.hash_lock();
    let checked = t.validate_structure().unwrap();
    assert_eq!(check_preimage(&checked, a.expose()), Ok(()));
    assert_eq!(
        code(check_preimage(&checked, b.expose())),
        "HTLC_SECRET_MISMATCH"
    );
}

// =============================================================================================
// Reading a document back (spec/V2.md section 10.9, I18 CLI step)
// =============================================================================================

/// The parts of `ipst` as a document states them.
fn parts_of(
    ipst: &HtlcIpst,
) -> Vec<(
    TransactionInput,
    kaspa_consensus_core::tx::UtxoEntry,
    HtlcSlotParts,
)> {
    ipst.transaction()
        .inputs
        .iter()
        .zip(ipst.entries())
        .zip(ipst.slots())
        .map(|((i, e), s)| {
            (
                i.clone(),
                e.clone(),
                HtlcSlotParts {
                    signer: s.signer(),
                    sighash: s.sighash(),
                    signature: s.signature(),
                    script_before: s.script_before().to_vec(),
                    script_after: s.script_after().to_vec(),
                },
            )
        })
        .collect()
}

fn rebuilt(
    ipst: &HtlcIpst,
    edit: impl FnOnce(
        &mut Vec<(
            TransactionInput,
            kaspa_consensus_core::tx::UtxoEntry,
            HtlcSlotParts,
        )>,
        &mut Vec<kaspa_consensus_core::tx::TransactionOutput>,
    ),
) -> Result<HtlcIpst, HtlcError> {
    let mut inputs = parts_of(ipst);
    let mut outputs = ipst.transaction().outputs.clone();
    edit(&mut inputs, &mut outputs);
    HtlcIpst::from_parts(
        ipst.terms().clone(),
        ipst.transaction().lock_time,
        inputs,
        outputs,
    )
}

#[test]
fn from_parts_reads_back_and_refuses_what_does_not_hold() {
    let (terms, template) = trade();
    let f = funded(&terms, &template);
    let ipst = claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee(),
    )
    .unwrap();
    assert_eq!(rebuilt(&ipst, |_, _| {}).unwrap(), ipst);
    // Malformed: empty lists, values out of range, outputs above the inputs, an authorizing input
    // out of range, inconsistent slots.
    assert_eq!(code(rebuilt(&ipst, |i, _| i.clear())), "IPST_MALFORMED");
    assert_eq!(code(rebuilt(&ipst, |_, o| o.clear())), "IPST_MALFORMED");
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[2].1.amount = 0)),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |_, o| o[0].value = 0)),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |_, o| o[1].value = FEE_INPUT * 4)),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |_, o| {
            o[0].covenant = Some(kaspa_consensus_core::tx::CovenantBinding::new(
                9,
                Hash::from_bytes(ASSET_COV),
            ))
        })),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[0].2.signature = Some([1; 65]))),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[0].2.script_after = vec![1])),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[2].2.sighash = None)),
        "IPST_MALFORMED"
    );
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[2].2.signer = Some([0xff; 32]))),
        "IPST_MALFORMED"
    );
    // A stated sighash that is not the transaction's, and a signature that does not verify.
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[2].2.sighash = Some([7; 32]))),
        "IPST_SIGHASH_MISMATCH"
    );
    assert_eq!(
        code(rebuilt(&ipst, |_, o| o[0].value -= 1)),
        "IPST_SIGHASH_MISMATCH"
    );
    assert_eq!(
        code(rebuilt(&ipst, |i, _| i[2].2.signature = Some([1; 65]))),
        "TX_SIGNATURE"
    );
}

// =============================================================================================
// Mainnet gate (D39, D40, spec/V2.md sections 10.5 and 10.8)
// =============================================================================================

/// The fixture trade on mainnet, with a creation context that passes every creation check.
fn mainnet_trade() -> (ValidatedHtlcTerms, Kcc20Template) {
    let (terms, template) = trade();
    let mut t = terms.terms().clone();
    t.network = Network::Mainnet;
    (t.validate_structure().unwrap(), template)
}

/// The mainnet gate is lifted (D39 b, D40): the creation vault, the address verifier and the
/// funding builder accept mainnet terms, and `HTLC_MAINNET_GATED` is reserved and never returned.
#[test]
fn mainnet_creation_is_accepted() {
    let (terms, template) = mainnet_trade();
    let s = sample();
    let mut ctx = context(Network::Mainnet, &s);
    ctx.creation.creation_daa = NOW_DAA;
    assert_eq!(terms.validate_creation(&ctx), Ok(()), "control");
    let fundable = HtlcVault::instantiate_for_creation(&terms, &ctx).unwrap();
    let address = fundable.address();
    assert!(address.starts_with("kaspa:p"), "{address}");
    assert_eq!(
        verify_address(&terms, &ctx, Some(&address))
            .unwrap()
            .address,
        address
    );
    assert!(fund(
        &terms,
        &fundable,
        &template,
        &deposit(&template, &[AMOUNT]),
        &fee(),
        NOW_DAA,
    )
    .is_ok());
}

/// The gate covers creation only: a mainnet vault that exists (made by other software) can
/// still be claimed and refunded through the core, so no escrow is ever trapped by it.
#[test]
fn mainnet_exits_stay_open() {
    let (terms, template) = mainnet_trade();
    let f = funded(&terms, &template);
    assert!(claim(
        &terms,
        &f.authorizer,
        &f.escrow,
        &template,
        &PREIMAGE,
        &fee()
    )
    .is_ok());
    let escrow = RefundEscrow {
        utxo: f.escrow.clone(),
        amount: AMOUNT,
        is_minter: false,
        template: &template,
    };
    assert!(refund(
        &terms,
        HtlcRefundSigner::Seller,
        &f.authorizer,
        Some(&escrow),
        &fee()
    )
    .is_ok());
}

/// I18 review round 5: the finality depth is the owner's decision D18, changed by the owner on
/// 2026-10-12 to N = 600 DAA scores (about 60 s at 10 BPS, mainnet and TN10), with the D32
/// hashlock margin following it. This fails when the constant drifts from the decision again.
#[test]
fn finality_depth_is_the_d18_decision() {
    assert_eq!(
        FINALITY_DEPTH_DAA, 600,
        "D18 (changed 2026-10-12): N = 600 DAA"
    );
}

/// The documents that state the hashlock finality depth state the constant, and none still
/// states the withdrawn 36,000 DAA (I18 review round 5).
#[test]
fn documents_state_the_finality_depth_of_the_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stated = format!("D18: {} DAA", FINALITY_DEPTH_DAA);
    // The owner runbook is private-only: the public tree does not hold it, so it is read only
    // where it exists (the private checkout runs every document).
    let mut docs = vec!["spec/V2.md", "docs/XCHAIN-SOLANA-USDC.md"];
    // The name is built from fragments: the public tree may not name the file.
    let runbook = concat!("docs/RUNBOOK", "-OWNER.md");
    if root.join(runbook).exists() {
        docs.push(runbook);
    } else {
        eprintln!("skipped: the owner runbook is not in this tree (private-only document)");
    }
    for doc in docs {
        let text = std::fs::read_to_string(root.join(doc)).expect(doc);
        for withdrawn in ["36,000 DAA", "finality-depth 36000"] {
            assert!(!text.contains(withdrawn), "{doc} still states {withdrawn}");
        }
        if doc != runbook {
            assert!(text.contains(&stated), "{doc} does not state {stated}");
        }
    }
}
