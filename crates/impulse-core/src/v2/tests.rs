// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Unit tests of the v2 module: codes, terms v2 (codec, hash, every structure and creation
//! check), template v2 (instantiation, decode refusals, addresses), the builders (layouts and
//! every refusal they raise), the version 2 IPST and the verifier. Keyless: no test here signs;
//! the engine runs of the builders' transactions, with throwaway keys, are in
//! tests/engine/v2_builders.rs.

use super::testkit::*;
use super::*;
use crate::terms::{
    CreationContext, FundingMode, IdentifierType, Kcc20Owner, Leg, LegKind, Network, TermsError,
};
use crate::tx::testkit::cash_template;
use crate::tx::{p2pk, FeePayment, Kcc20Deposit, Kcc20State, TokenUtxo, TxError, Utxo};
use kaspa_consensus_core::constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI};
use kaspa_consensus_core::tx::UtxoEntry;
use kaspa_consensus_core::Hash;
use proptest::prelude::*;
use silverscript_abi::ArtifactValue;

const NS: &str = "tests";

fn code<T: std::fmt::Debug>(r: Result<T, V2Error>) -> &'static str {
    r.expect_err("refused").code()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// =============================================================================================
// Codes
// =============================================================================================

#[test]
fn v2_error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; each list may only grow at the end.
    assert_eq!(
        TERMS_V2_ERROR_CODES,
        [
            "TERMS_V2_VERSION",
            "TERMS_VERSION_UNKNOWN",
            "TERMS_LEG_COUNT",
            "TERMS_LEGS_ONE_PARTY",
            "TERMS_AUTHORITY_IS_DEPOSITOR",
            "TERMS_LEG_KIND",
            "TERMS_LEG_ORDER",
            "TERMS_LEGS_SAME_COVENANT",
            "TERMS_PARTIAL_LOTS",
            "TERMS_PARTIAL_INDIVISIBLE",
        ]
    );
    assert_eq!(
        TEMPLATE_V2_ERROR_CODES,
        [
            "TEMPLATE_V2_ARTIFACT_INVALID",
            "TEMPLATE_V2_HASH_MISMATCH",
            "TEMPLATE_V2_LEG_INDEX",
            "TEMPLATE_V2_NOT_VAULT",
            "TEMPLATE_V2_STATE_MALFORMED",
            "TEMPLATE_V2_STATE_INVALID",
            "TEMPLATE_V2_NONCANONICAL",
        ]
    );
    assert_eq!(
        TX_V2_ERROR_CODES,
        [
            "TX_V2_NOT_AT_VAULT",
            "TX_LEGS",
            "TX_TRANCHE",
            "TX_LINEAGE",
            "TX_LEGS_OUT_OF_STEP",
            "TX_V2_MASS",
            "IPST_V2_VERSION",
        ]
    );
    assert_eq!(
        VERIFY_V2_ERROR_CODES,
        [
            "VERIFY_V2_ADDRESS_MISMATCH",
            "VERIFY_V2_WRONG_LEG",
            "VERIFY_V2_TEMPLATE_MISMATCH",
        ]
    );
    // Appended codes never repeat a v1 code.
    let mut all: Vec<&str> = crate::terms::TERMS_ERROR_CODES.to_vec();
    all.extend(crate::template::TEMPLATE_ERROR_CODES);
    all.extend(crate::tx::TX_ERROR_CODES);
    all.extend(crate::verify::VERIFY_ERROR_CODES);
    all.extend(TERMS_V2_ERROR_CODES);
    all.extend(TEMPLATE_V2_ERROR_CODES);
    all.extend(TX_V2_ERROR_CODES);
    all.extend(VERIFY_V2_ERROR_CODES);
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), n, "codes are unique across v1 and v2");
}

#[test]
fn every_v2_variant_maps_to_its_listed_code() {
    let new = [
        V2Error::TermsV2Version { version: 1 },
        V2Error::TermsVersionUnknown { version: 3 },
        V2Error::LegCount { count: 1 },
        V2Error::LegsOneParty,
        V2Error::AuthorityIsDepositor { leg: 0 },
        V2Error::LegKind { leg: 0 },
        V2Error::LegOrder { leg: 1 },
        V2Error::LegsSameCovenant { leg: 1 },
        V2Error::PartialLots {
            lot_count: 1,
            min_lot: 1,
        },
        V2Error::PartialIndivisible { leg: 0 },
        V2Error::TemplateArtifactInvalid { reason: "x".into() },
        V2Error::TemplateHashMismatch {
            expected: [0; 32],
            found: [1; 32],
        },
        V2Error::TemplateLegIndex {
            value: 3,
            leg_count: 3,
        },
        V2Error::TemplateNotVault,
        V2Error::TemplateStateMalformed { reason: "x".into() },
        V2Error::TemplateStateInvalid { field: "legs" },
        V2Error::TemplateNonCanonical,
        V2Error::NotAtVault { leg: 0 },
        V2Error::Legs { reason: "x" },
        V2Error::Tranche {
            leg: 0,
            reason: "x",
        },
        V2Error::Lineage { reason: "x" },
        V2Error::LegsOutOfStep { leg: 1 },
        V2Error::Mass {
            dimension: "compute",
            mass: 2,
            cap: 1,
        },
        V2Error::IpstVersion { version: 3 },
        V2Error::AddressMismatch { leg: 0 },
        V2Error::WrongLeg { leg: 0, found: 1 },
        V2Error::TemplateMismatch {
            expected: [0; 32],
            found: None,
        },
    ];
    let mut listed: Vec<&str> = TERMS_V2_ERROR_CODES.to_vec();
    listed.extend(TEMPLATE_V2_ERROR_CODES);
    listed.extend(TX_V2_ERROR_CODES);
    listed.extend(VERIFY_V2_ERROR_CODES);
    assert_eq!(new.iter().map(V2Error::code).collect::<Vec<_>>(), listed);
    let reused = [
        (
            V2Error::AddressMalformed {
                leg: 0,
                reason: "x".into(),
            },
            "VERIFY_ADDRESS_MALFORMED",
        ),
        (
            V2Error::AddressNetwork {
                leg: 0,
                expected: Network::Mainnet,
                found: "kaspatest".into(),
            },
            "VERIFY_ADDRESS_NETWORK",
        ),
        (V2Error::AddressMissing { leg: 0 }, "VERIFY_ADDRESS_MISSING"),
        (V2Error::TermsMismatch, "VERIFY_TERMS_MISMATCH"),
        (V2Error::NothingRevealed, "VERIFY_NOTHING_REVEALED"),
        (V2Error::InputNotVault, "VERIFY_INPUT_NOT_VAULT"),
        (
            V2Error::Terms(TermsError::EarliestZero),
            "TERMS_EARLIEST_ZERO",
        ),
        (
            V2Error::Tx(TxError::NonstandardChange),
            "TX_NONSTANDARD_CHANGE",
        ),
    ];
    for (e, c) in &reused {
        assert_eq!(e.code(), *c);
        assert!(
            crate::verify::VERIFY_ERROR_CODES.contains(c)
                || crate::terms::TERMS_ERROR_CODES.contains(c)
                || crate::tx::TX_ERROR_CODES.contains(c)
        );
    }
    for e in new.iter().chain(reused.iter().map(|(e, _)| e)) {
        assert!(e.to_string().starts_with(e.code()), "{e}");
    }
}

// =============================================================================================
// Terms v2
// =============================================================================================

#[test]
fn hash_known_answers_of_spec_5_1() {
    assert_eq!(
        hex(&terms::hash_canonical(b"")),
        "2e88448b8dc977393c7b3d2f14da2d5747fc81409100edbe401bd9afa557009b"
    );
    assert_eq!(
        hex(&terms::hash_canonical(b"abc")),
        "f7638f8d16255576c53a0b850e3a1efb7e292ef0e4e1c0eef80e9044412c782d"
    );
    assert_eq!(TERMS_V2_HASH_DOMAIN.len(), 16);
}

fn fixtures() -> Vec<TermsV2> {
    vec![
        ring3(NS, true),
        ring3(NS, false),
        with_kas3(NS, true),
        bilateral10(NS, true),
        two_kas(NS, false),
        two_kcc20(NS, true),
    ]
}

#[test]
fn fixtures_round_trip_and_validate() {
    for t in fixtures() {
        let bytes = t.encode().unwrap();
        assert_eq!(TermsV2::decode(&bytes).unwrap(), t);
        let checked = t.clone().validate_structure().unwrap();
        assert_eq!(checked.canonical(), bytes.as_slice());
        assert_eq!(checked.terms_hash(), t.terms_hash().unwrap());
        assert_eq!(ValidatedTermsV2::decode(&bytes).unwrap(), checked);
        // Layout lengths of spec/V2.md 5.2: no authority, 1 + 1 + 8 + 1 + 1, legs, then the
        // optionals and fixed fields.
        let legs: usize = t
            .legs
            .iter()
            .map(|l| match l.asset.kind {
                LegKind::Kcc20(_) => 179,
                _ => 107,
            })
            .sum();
        let len = 11
            + if t.authority_key.is_some() { 33 } else { 1 }
            + legs
            + if t.earliest_daa.is_some() { 9 } else { 1 }
            + 8
            + 1
            + if t.partial.is_some() { 17 } else { 1 }
            + 32;
        assert_eq!(bytes.len(), len);
    }
}

#[test]
fn decode_refusals() {
    let t = two_kas(NS, false);
    let bytes = t.encode().unwrap();
    // The version byte first, before anything else.
    let mut v1 = bytes.clone();
    v1[0] = 1;
    assert_eq!(code(TermsV2::decode(&v1)), "TERMS_V2_VERSION");
    assert_eq!(code(TermsV2::decode(&[])), "TERMS_TRUNCATED");
    assert_eq!(code(TermsV2::decode(&[1])), "TERMS_V2_VERSION");
    for cut in 1..bytes.len() {
        assert_eq!(
            code(TermsV2::decode(&bytes[..cut])),
            "TERMS_TRUNCATED",
            "{cut}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(code(TermsV2::decode(&long)), "TERMS_TRAILING_BYTES");
    let set = |at: usize, v: u8| {
        let mut b = bytes.clone();
        b[at] = v;
        code(TermsV2::decode(&b))
    };
    // Offsets without authority: network 1, authority presence 10, leg_count 11, legs from 12.
    assert_eq!(set(1, 2), "TERMS_INVALID_TAG");
    assert_eq!(set(10, 2), "TERMS_INVALID_PRESENCE");
    assert_eq!(set(12 + 32, 3), "TERMS_INVALID_TAG");
    assert_eq!(set(12 + 32 + 81, 3), "TERMS_INVALID_TAG");
    assert_eq!(set(12 + 32 + 81 + 33, 3), "TERMS_INVALID_TAG");
    let tail = bytes.len();
    // ... earliest (9), expiry (8), funding (1), partial presence (1), trade_ref (32).
    assert_eq!(set(tail - 32 - 1 - 1 - 8 - 9, 2), "TERMS_INVALID_PRESENCE");
    assert_eq!(set(tail - 32 - 1 - 1, 2), "TERMS_INVALID_TAG");
    assert_eq!(set(tail - 32 - 1, 2), "TERMS_INVALID_PRESENCE");
    // A leg_count larger than the legs present reads the later fields as a leg and fails.
    let mut more = bytes.clone();
    more[11] = 3;
    assert!(TermsV2::decode(&more).is_err());
}

#[test]
fn decode_any_dispatches_on_the_version_byte() {
    let v1 = crate::terms::golden::vectors().remove(0).terms;
    let v1_bytes = v1.encode().unwrap();
    assert_eq!(decode_any(&v1_bytes).unwrap(), AnyTerms::V1(Box::new(v1)));
    let v2 = ring3(NS, true);
    assert_eq!(
        decode_any(&v2.encode().unwrap()).unwrap(),
        AnyTerms::V2(v2.clone())
    );
    assert_eq!(code(decode_any(&[])), "TERMS_TRUNCATED");
    for version in [0u8, 3, 255] {
        assert_eq!(code(decode_any(&[version, 0, 0])), "TERMS_VERSION_UNKNOWN");
    }
    // spec/V2.md section 2: the v1 decoder refuses terms v2 as an unsupported version.
    assert_eq!(
        crate::terms::Terms::decode(&v2.encode().unwrap())
            .unwrap_err()
            .code(),
        "TERMS_UNSUPPORTED_VERSION"
    );
}

#[test]
fn encode_refusals() {
    let mut t = two_kas(NS, false);
    t.version = 1;
    assert_eq!(code(t.encode()), "TERMS_V2_VERSION");
    let mut t = two_kas(NS, false);
    t.legs = vec![t.legs[0]; 256];
    assert_eq!(code(t.encode()), "TERMS_LEG_COUNT");
}

fn structure(edit: impl FnOnce(&mut TermsV2)) -> &'static str {
    let mut t = with_kas3(NS, true);
    edit(&mut t);
    code(t.validate_structure())
}

const BAD_KEY: [u8; 32] = [0xFF; 32];

#[test]
fn every_structure_check_in_spec_5_3_order() {
    // 1. Version.
    assert_eq!(structure(|t| t.version = 3), "TERMS_V2_VERSION");
    // 2. leg_count, before any key.
    assert_eq!(
        structure(|t| {
            t.legs.truncate(1);
            t.legs[0].depositor_key = BAD_KEY;
        }),
        "TERMS_LEG_COUNT"
    );
    assert_eq!(
        structure(|t| {
            let extra = t.legs[2];
            t.legs.extend(std::iter::repeat_n(extra, 8));
        }),
        "TERMS_LEG_COUNT"
    );
    // 3. Keys: depositors in leg order, then the authority.
    assert_eq!(
        structure(|t| t.legs[2].depositor_key = BAD_KEY),
        "TERMS_INVALID_KEY"
    );
    assert_eq!(
        structure(|t| t.authority_key = Some(BAD_KEY)),
        "TERMS_INVALID_KEY"
    );
    // 4. Parties.
    assert_eq!(
        structure(|t| {
            let k = t.legs[0].depositor_key;
            for l in t.legs.iter_mut() {
                l.depositor_key = k;
            }
        }),
        "TERMS_LEGS_ONE_PARTY"
    );
    assert_eq!(
        structure(|t| t.authority_key = Some(t.legs[1].depositor_key)),
        "TERMS_AUTHORITY_IS_DEPOSITOR"
    );
    // 5. Kinds, then order.
    assert_eq!(
        structure(|t| t.legs[0].asset.kind = LegKind::External),
        "TERMS_LEG_KIND"
    );
    assert_eq!(structure(|t| t.legs.swap(1, 2)), "TERMS_LEG_ORDER");
    // 6. Amounts and tokens, then distinct covenants.
    assert_eq!(
        structure(|t| t.legs[0].asset.amount = 0),
        "TERMS_AMOUNT_ZERO"
    );
    assert_eq!(
        structure(|t| t.legs[2].asset.amount = MAX_SOMPI + 1),
        "TERMS_AMOUNT_OUT_OF_RANGE"
    );
    assert_eq!(
        structure(|t| t.legs[0].asset.amount = i64::MAX as u64 + 1),
        "TERMS_AMOUNT_OUT_OF_RANGE"
    );
    let token = |edit: fn(&mut crate::terms::Kcc20Token)| {
        structure(move |t| {
            if let LegKind::Kcc20(tok) = &mut t.legs[1].asset.kind {
                edit(tok);
            }
        })
    };
    assert_eq!(token(|k| k.covenant_id = [0; 32]), "TERMS_ZERO_IDENTIFIER");
    assert_eq!(
        token(|k| k.template_hash = [0; 32]),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        token(|k| k.template_prefix_len = 0),
        "TERMS_TEMPLATE_LENGTH"
    );
    assert_eq!(
        token(|k| k.template_suffix_len = 1_000_000),
        "TERMS_TEMPLATE_LENGTH"
    );
    assert_eq!(
        token(|k| k.covenant_id = [0x10; 32]),
        "TERMS_LEGS_SAME_COVENANT"
    );
    // 7. Destinations.
    assert_eq!(
        structure(|t| t.legs[2].delivery.identifier_type = IdentifierType::CovenantId),
        "TERMS_DESTINATION_KIND"
    );
    assert_eq!(
        structure(|t| t.legs[1].refund.identifier = [0; 32]),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        structure(|t| t.legs[0].delivery.identifier = BAD_KEY),
        "TERMS_INVALID_KEY"
    );
    assert_eq!(
        structure(|t| t.legs[2].delivery.identifier = BAD_KEY),
        "TERMS_INVALID_KEY"
    );
    // A script hash or covenant identifier need not be a key.
    assert!(with_kas3(NS, true).validate_structure().is_ok());
    // 8. DAA scores.
    assert_eq!(
        structure(|t| t.expiry_daa = LOCK_TIME_THRESHOLD),
        "TERMS_EXPIRY_NOT_DAA"
    );
    assert_eq!(
        structure(|t| t.earliest_daa = Some(LOCK_TIME_THRESHOLD)),
        "TERMS_EARLIEST_NOT_DAA"
    );
    assert_eq!(
        structure(|t| t.earliest_daa = Some(0)),
        "TERMS_EARLIEST_ZERO"
    );
    assert_eq!(
        structure(|t| t.earliest_daa = Some(t.expiry_daa + 1)),
        "TERMS_EARLIEST_AFTER_EXPIRY"
    );
    // 9. Partial.
    let partial = |lot_count, min_lot| {
        structure(move |t| {
            t.partial = Some(Partial { lot_count, min_lot });
        })
    };
    assert_eq!(partial(1, 1), "TERMS_PARTIAL_LOTS");
    assert_eq!(partial(4, 0), "TERMS_PARTIAL_LOTS");
    assert_eq!(partial(4, 5), "TERMS_PARTIAL_LOTS");
    assert_eq!(partial(3, 1), "TERMS_PARTIAL_INDIVISIBLE");
    assert!(with_kas3(NS, true).validate_structure().is_ok());
    let mut ok = with_kas3(NS, true);
    ok.partial = Some(Partial {
        lot_count: 4,
        min_lot: 4,
    });
    assert!(ok.validate_structure().is_ok());
}

#[test]
fn creation_checks_are_v1s() {
    let t = validated(ring3(NS, true));
    let ctx = |network, daa| CreationContext::new(network, daa);
    assert_eq!(t.validate_creation(&ctx(Network::Mainnet, 1)), Ok(()));
    assert_eq!(
        code(t.validate_creation(&ctx(Network::Testnet, 1))),
        "TERMS_NETWORK_MISMATCH"
    );
    assert_eq!(
        code(t.validate_creation(&ctx(Network::Mainnet, EXPIRY))),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    let mut near = ctx(Network::Mainnet, 1);
    near.max_expiry_horizon_daa = 10;
    assert_eq!(
        code(t.validate_creation(&near)),
        "TERMS_EXPIRY_BEYOND_HORIZON"
    );
}

fn arb_leg() -> impl Strategy<Value = LegV2> {
    let kind = prop_oneof![
        Just(LegKind::Kas),
        Just(LegKind::External),
        (
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<u32>(),
            any::<u32>()
        )
            .prop_map(|(c, h, p, s)| LegKind::Kcc20(crate::terms::Kcc20Token {
                covenant_id: c,
                template_hash: h,
                template_prefix_len: p,
                template_suffix_len: s,
            })),
    ];
    let id = prop_oneof![
        Just(IdentifierType::PubKey),
        Just(IdentifierType::ScriptHash),
        Just(IdentifierType::CovenantId)
    ];
    (
        any::<[u8; 32]>(),
        kind,
        any::<u64>(),
        id.clone(),
        any::<[u8; 32]>(),
        id,
        any::<[u8; 32]>(),
    )
        .prop_map(|(d, kind, amount, dt, di, rt, ri)| LegV2 {
            depositor_key: d,
            asset: Leg { kind, amount },
            delivery: DestinationV2 {
                identifier_type: dt,
                identifier: di,
            },
            refund: DestinationV2 {
                identifier_type: rt,
                identifier: ri,
            },
        })
}

fn arb_terms() -> impl Strategy<Value = TermsV2> {
    (
        any::<bool>(),
        any::<u64>(),
        proptest::option::of(any::<[u8; 32]>()),
        proptest::collection::vec(arb_leg(), 0..12),
        proptest::option::of(any::<u64>()),
        any::<u64>(),
        any::<bool>(),
        proptest::option::of((any::<u64>(), any::<u64>())),
        any::<[u8; 32]>(),
    )
        .prop_map(
            |(net, nonce, auth, legs, earliest, expiry, ear, partial, tr)| TermsV2 {
                version: TERMS_V2_VERSION,
                network: if net {
                    Network::Mainnet
                } else {
                    Network::Testnet
                },
                nonce,
                authority_key: auth,
                legs,
                earliest_daa: earliest,
                expiry_daa: expiry,
                funding_mode: if ear {
                    FundingMode::Earmarked
                } else {
                    FundingMode::Revocable
                },
                partial: partial.map(|(lot_count, min_lot)| Partial { lot_count, min_lot }),
                trade_ref: tr,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// decode(encode(t)) = t over the whole structural domain.
    #[test]
    fn decode_inverts_encode(t in arb_terms()) {
        let bytes = t.encode().unwrap();
        prop_assert_eq!(TermsV2::decode(&bytes).unwrap(), t);
    }

    /// encode(decode(b)) = b for every byte string that decodes: one encoding per value.
    #[test]
    fn encode_inverts_decode(mut b in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Some(first) = b.first_mut() {
            *first = TERMS_V2_VERSION;
        }
        if let Ok(t) = TermsV2::decode(&b) {
            prop_assert_eq!(t.encode().unwrap(), b);
        }
    }
}

// =============================================================================================
// Template v2
// =============================================================================================

#[test]
fn template_load_refuses_tampered_inputs_v2() {
    use super::template::{TemplateV2, ARTIFACT_JSON, CONTRACT_NAME, TEMPLATE_HASH_FILE};
    let good: serde_json::Value = serde_json::from_str(ARTIFACT_JSON).unwrap();
    let load = |a: &serde_json::Value, h: &str| TemplateV2::load(&a.to_string(), h);
    assert!(load(&good, TEMPLATE_HASH_FILE).is_ok());

    // Pinned hash differing by one digit, and malformed pins.
    let pinned = TEMPLATE_HASH_FILE.trim().to_string();
    let first = if pinned.starts_with('0') { '1' } else { '0' };
    let off_by_one = format!("{first}{}\n", &pinned[1..]);
    assert_eq!(code(load(&good, &off_by_one)), "TEMPLATE_V2_HASH_MISMATCH");
    for bad in [
        pinned[..63].to_string(),
        pinned.to_uppercase(),
        format!("{pinned}0"),
        String::new(),
    ] {
        assert_eq!(
            code(load(&good, &bad)),
            "TEMPLATE_V2_ARTIFACT_INVALID",
            "{bad:?}"
        );
    }

    // A different state layout.
    let mut a = good.clone();
    a["contracts"][CONTRACT_NAME]["runtime_state"]["fields"][0]["name"] = "versionX".into();
    assert_eq!(
        code(load(&a, TEMPLATE_HASH_FILE)),
        "TEMPLATE_V2_ARTIFACT_INVALID"
    );

    // Two contracts.
    let mut a = good.clone();
    let c = a["contracts"].as_object_mut().unwrap();
    let v = c[CONTRACT_NAME].clone();
    c.insert("ZVault".into(), v);
    assert_eq!(
        code(load(&a, TEMPLATE_HASH_FILE)),
        "TEMPLATE_V2_ARTIFACT_INVALID"
    );

    // Not JSON.
    assert_eq!(
        code(TemplateV2::load("{}", TEMPLATE_HASH_FILE)),
        "TEMPLATE_V2_ARTIFACT_INVALID"
    );

    // The declared template_hash altered.
    let mut a = good.clone();
    let th = &mut a["contracts"][CONTRACT_NAME]["compiled"]["template_hash"];
    let mut bytes: Vec<u8> = th
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    bytes[0] ^= 1;
    *th = bytes.into();
    assert_eq!(
        code(load(&a, TEMPLATE_HASH_FILE)),
        "TEMPLATE_V2_HASH_MISMATCH"
    );
}

#[test]
fn startup_check_pins_template_hash_v2() {
    let t = check_template().unwrap();
    let pinned = include_str!("../../../../contracts/TEMPLATE_HASH_V2").trim();
    assert_eq!(hex(&t.hash()), pinned);
    assert_ne!(
        t.hash(),
        crate::template::check().unwrap().hash(),
        "v1 and v2 differ"
    );
    assert_eq!(t.prefix().len(), 1);
    assert_eq!(t.suffix().len(), 8_477);
}

#[test]
fn instantiation_layout_and_decode_round_trip() {
    for t in fixtures() {
        let checked = validated(t.clone());
        let n = t.legs.len();
        let scripts: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                VaultV2::instantiate_existing(&checked, i)
                    .unwrap()
                    .redeem_script()
                    .to_vec()
            })
            .collect();
        for (i, script) in scripts.iter().enumerate() {
            // 1 prefix byte, 142 fixed state bytes, 187 per leg, the 8,477-byte suffix.
            assert_eq!(script.len(), 1 + 142 + 187 * n + 8_477);
            let (decoded, leg) = decode_vault(script).unwrap();
            assert_eq!(decoded, checked);
            assert_eq!(leg, i);
            assert_eq!(
                template_hash_of_instance(script).unwrap(),
                check_template().unwrap().hash()
            );
            // [S10]: sibling scripts differ only in legIndex's 8-byte payload, the last state
            // bytes before the suffix.
            let at = script.len() - 8_477 - 8;
            assert_eq!(&script[at..at + 8], &(i as u64).to_le_bytes());
            assert_eq!(script[..at], scripts[0][..at]);
            assert_eq!(script[at + 8..], scripts[0][at + 8..]);
        }
        assert_eq!(
            code(VaultV2::instantiate_existing(&checked, n)),
            "TEMPLATE_V2_LEG_INDEX"
        );
    }
}

fn crafted(
    edit: impl FnOnce(&mut std::collections::BTreeMap<String, ArtifactValue>),
) -> &'static str {
    let t = ring3(NS, true);
    let mut values = template::values_of(&t, 1);
    edit(&mut values);
    code(decode_vault(&template::splice(&values)))
}

#[test]
fn decode_refusals_of_spec_8_2() {
    use ArtifactValue::{Byte, Bytes, Int};
    let checked = validated(ring3(NS, true));
    let good = VaultV2::instantiate_existing(&checked, 1).unwrap();
    let script = good.redeem_script().to_vec();
    // Not the v2 template: a v1 vault, a truncated script, another suffix.
    let v1_terms = crate::terms::golden::vectors().remove(0).terms;
    let v1 = crate::template::Vault::instantiate_existing(
        &v1_terms.validate_structure().unwrap(),
        crate::template::LegIndex::Asset,
    )
    .unwrap();
    assert_eq!(
        code(decode_vault(v1.redeem_script())),
        "TEMPLATE_V2_NOT_VAULT"
    );
    assert_eq!(code(decode_vault(&script[..100])), "TEMPLATE_V2_NOT_VAULT");
    let mut other = script.clone();
    *other.last_mut().unwrap() ^= 1;
    assert_eq!(code(decode_vault(&other)), "TEMPLATE_V2_NOT_VAULT");
    // spec/V2.md section 2: the v1 decoder refuses a v2 script.
    assert_eq!(
        crate::template::decode(&script).unwrap_err().code(),
        "TEMPLATE_NOT_IMPULSE_VAULT"
    );
    // A state that does not parse.
    let mut garbled = script.clone();
    garbled[1] = 0xff;
    assert_eq!(code(decode_vault(&garbled)), "TEMPLATE_V2_STATE_MALFORMED");
    // Fields no terms value holds.
    assert_eq!(
        crafted(|v| {
            v.insert("network".into(), Byte(2));
        }),
        "TEMPLATE_V2_STATE_INVALID"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("fundingMode".into(), Byte(2));
        }),
        "TEMPLATE_V2_STATE_INVALID"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("legCount".into(), Int(4));
        }),
        "TEMPLATE_V2_STATE_INVALID"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("legCount".into(), Int(-1));
        }),
        "TEMPLATE_V2_STATE_INVALID"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("expiryDaa".into(), Int(-1));
        }),
        "TEMPLATE_V2_STATE_INVALID"
    );
    let record_edit = |at: usize, byte: u8| {
        crafted(move |v| {
            if let Some(Bytes(legs)) = v.get_mut("legs") {
                legs[at] = byte;
            }
        })
    };
    assert_eq!(
        record_edit(32, 2),
        "TEMPLATE_V2_STATE_INVALID",
        "kind byte 2"
    );
    assert_eq!(
        record_edit(121, 3),
        "TEMPLATE_V2_STATE_INVALID",
        "delivery type 3"
    );
    assert_eq!(
        record_edit(113 + 7, 0x80),
        "TEMPLATE_V2_STATE_INVALID",
        "top bit of the amount"
    );
    // A leg index outside the list.
    assert_eq!(
        crafted(|v| {
            v.insert("legIndex".into(), Int(3));
        }),
        "TEMPLATE_V2_LEG_INDEX"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("legIndex".into(), Int(-1));
        }),
        "TEMPLATE_V2_LEG_INDEX"
    );
    // Terms that fail the structure checks keep the terms code.
    assert_eq!(
        crafted(|v| {
            v.insert("version".into(), Byte(1));
        }),
        "TERMS_V2_VERSION"
    );
    assert_eq!(
        crafted(|v| {
            v.insert("lotCount".into(), Int(1));
            v.insert("minLot".into(), Int(2));
        }),
        "TERMS_PARTIAL_LOTS"
    );
    // Not the canonical instantiation: an authority key under hasAuthority false.
    assert_eq!(
        crafted(|v| {
            v.insert("hasAuthority".into(), ArtifactValue::Bool(false));
        }),
        "TEMPLATE_V2_NONCANONICAL"
    );
    // A KAS leg whose record carries token fields.
    let t = with_kas3(NS, true);
    let mut values = template::values_of(&t, 0);
    if let Some(Bytes(legs)) = values.get_mut("legs") {
        legs[2 * 187 + 33] = 1;
    }
    assert_eq!(
        code(decode_vault(&template::splice(&values))),
        "TEMPLATE_V2_NONCANONICAL"
    );
}

#[test]
fn addresses_follow_the_network() {
    let mut t = ring3(NS, true);
    let ctx = CreationContext::new(Network::Mainnet, 1);
    let m =
        vault_address(&VaultV2::instantiate_for_creation(&validated(t.clone()), 0, &ctx).unwrap());
    assert!(m.starts_with("kaspa:p"), "{m}");
    t.network = Network::Testnet;
    let ctx = CreationContext::new(Network::Testnet, 1);
    let tn = vault_address(&VaultV2::instantiate_for_creation(&validated(t), 0, &ctx).unwrap());
    assert!(tn.starts_with("kaspatest:p"), "{tn}");
    assert_eq!(
        code(VaultV2::instantiate_for_creation(
            &validated(ring3(NS, true)),
            0,
            &CreationContext::new(Network::Testnet, 1)
        )),
        "TERMS_NETWORK_MISMATCH"
    );
}

// =============================================================================================
// Mass caps, minimum KAS, budgets
// =============================================================================================

#[test]
fn cap_v2_is_the_pinned_block_limits_less_the_d37_reserve() {
    for network in [Network::Mainnet, Network::Testnet] {
        assert_eq!(
            caps(network),
            MassCaps {
                compute: 450_000,
                storage: 450_000,
                transient: 900_000,
            }
        );
    }
}

#[test]
fn min_v2_follows_the_output_count() {
    // O = N + K + 1: 3-way ring 7, ten-leg list 20; with partial 2N + K + 1.
    let ring = ring3(NS, true);
    assert_eq!(
        min_v2(&ring, 1),
        (1_000_000_000_000u64 * 7).div_ceil(450_000)
    );
    assert_eq!(
        min_v2(&ring, 2),
        (4_000_000_000_000u64 * 7).div_ceil(450_000)
    );
    assert_eq!(
        min_v2(&bilateral10(NS, true), 1),
        (1_000_000_000_000u64 * 20).div_ceil(450_000)
    );
    let mut p = ring3(NS, true);
    p.partial = Some(Partial {
        lot_count: 2,
        min_lot: 1,
    });
    assert_eq!(min_v2(&p, 1), (1_000_000_000_000u64 * 10).div_ceil(450_000));
}

#[test]
fn min_vault_v2_floors_partial_terms_at_two_units_and_the_spec_says_so() {
    // D97: a vault output of partial terms carries a covenant ID and holds at least MIN_V2(2, O);
    // without partial it is MIN_V2(1, O). The CLI authorizer default is this same value.
    let plain = ring3(NS, true);
    assert_eq!(min_vault_v2(&plain), min_v2(&plain, 1));
    let mut p = ring3(NS, true);
    p.partial = Some(Partial {
        lot_count: 2,
        min_lot: 1,
    });
    assert_eq!(min_vault_v2(&p), min_v2(&p, 2));
    assert!(min_vault_v2(&p) > min_v2(&p, 1));
    // The spec text names the rule in 6.2 and in both CLI default texts.
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/V2.md"))
        .expect("spec/V2.md");
    assert!(spec.contains("D97: for partial terms a vault output holds at least MIN_V2(2, O)"));
    assert_eq!(
        spec.matches(
            "`--authorizer` defaults to MIN_V2(1, O), or MIN_V2(2, O) for partial terms (D97)"
        )
        .count(),
        2
    );
}

#[test]
fn budgets_follow_the_measured_rules() {
    // Fixture template 1,461 bytes. Ring, authority, N = K = 3, leg 0:
    // 100,098 - 13,579 + 136,755 + 11,799 + 6,630 + 1,380 + 10,227 + 43,830 = 297,140 units,
    // plus 107 for each of the 14 inputs after the vaults beyond the 3 escrows and one fee input.
    let t = ring3(NS, true);
    let tl = template().prefix_len() as i64 + template().suffix_len() as i64;
    assert_eq!(tl, 1_461);
    let units: u64 = 297_140 + 107 * 14;
    let with_margin = units + 10_000 + units / 50;
    assert_eq!(settle_budget(&t, 0), budget_of(with_margin));
    // Refund: depositor with token, N = 3: 120,004 + 2,244 + 663 + 561 + 4,290 + 24,837, plus
    // 168 for each of the 9 further inputs a refund may have.
    let r: u64 = 120_004 + 2_244 + 663 + 561 + 4_290 + 17 * 1_461 + 168 * 9;
    assert_eq!(
        refund_budget(&t, 0, true, true),
        budget_of(r + 10_000 + r / 50)
    );
    assert!(refund_budget(&t, 0, false, false) < refund_budget(&t, 0, true, true));
}

/// The smallest budget covering `units` (9,999 free units, then 10,000 per budget unit).
fn budget_of(units: u64) -> u16 {
    kaspa_consensus_core::mass::ComputeBudget::checked_covering_script_units(
        kaspa_consensus_core::mass::ScriptUnits(units),
    )
    .unwrap()
    .value()
}

// =============================================================================================
// Builders
// =============================================================================================

struct World {
    terms: ValidatedTermsV2,
    funded: Vec<Funded>,
}

fn world(t: TermsV2) -> World {
    let terms = validated(t);
    let funded = funded(&terms, NS);
    World { terms, funded }
}

impl World {
    fn settle(&self) -> Result<IpstV2, V2Error> {
        let tmpl = template();
        settle(
            &self.terms,
            &settle_legs(&self.funded, &tmpl),
            &fee_payment(NS),
            NOW,
        )
    }

    fn settle_with<'a>(
        &self,
        tmpl: &'a crate::tx::Kcc20Template,
        edit: impl FnOnce(&mut Vec<SettleLeg<'a>>),
    ) -> Result<IpstV2, V2Error> {
        let mut legs = settle_legs(&self.funded, tmpl);
        edit(&mut legs);
        settle(&self.terms, &legs, &fee_payment(NS), NOW)
    }

    fn refund(&self, leg: usize, signer: RefundSignerV2, token: bool) -> Result<IpstV2, V2Error> {
        let tmpl = template();
        let escrow = if token {
            refund_escrow(&self.funded[leg], &tmpl)
        } else {
            None
        };
        refund(
            &self.terms,
            leg,
            signer,
            &self.funded[leg].vault,
            escrow.as_ref(),
            &fee_payment(NS),
        )
    }
}

fn spk_of(t: &ValidatedTermsV2, leg: usize) -> kaspa_consensus_core::tx::ScriptPublicKey {
    VaultV2::instantiate_existing(t, leg)
        .unwrap()
        .script_public_key()
}

#[test]
fn settle_layout_of_spec_4_3() {
    for t in [
        ring3(NS, true),
        with_kas3(NS, false),
        bilateral10(NS, true),
        two_kas(NS, true),
        two_kcc20(NS, false),
    ] {
        let w = world(t);
        let tt = w.terms.terms();
        let (n, k) = (tt.legs.len(), tt.kcc20_legs());
        let ipst = w.settle().unwrap();
        let tx = ipst.transaction();
        assert_eq!(tx.inputs.len(), n + k + 1);
        assert_eq!(
            tx.outputs.len(),
            n + k + 1,
            "deliveries, authorizers, change"
        );
        assert_eq!(tx.lock_time, tt.earliest_daa.unwrap_or(0));
        for i in 0..n {
            assert_eq!(ipst.entries()[i].script_public_key, spk_of(&w.terms, i));
            assert_eq!(
                tx.inputs[i].compute_commit.compute_budget(),
                Some(settle_budget(tt, i))
            );
            assert_eq!(ipst.slots()[i].signer(), tt.authority_key);
        }
        for j in 0..k {
            assert_eq!(
                ipst.entries()[n + j].covenant_id,
                Some(Hash::from_bytes(token(j).covenant_id))
            );
            assert_eq!(ipst.slots()[n + j].signer(), None);
            // Delivery j is a token output authorized by its escrow at N + j.
            let binding = tx.outputs[j].covenant.expect("token delivery");
            assert_eq!(usize::from(binding.authorizing_input), n + j);
            assert_eq!(binding.covenant_id, Hash::from_bytes(token(j).covenant_id));
            // Authorizer j home to its depositor, at least in full.
            assert_eq!(
                tx.outputs[n + j].script_public_key,
                p2pk(&tt.legs[j].depositor_key)
            );
            assert!(tx.outputs[n + j].value >= ipst.entries()[j].amount);
        }
        for j in k..n {
            // A KAS delivery is exactly the leg amount, to its destination.
            assert_eq!(tx.outputs[j].value, tt.legs[j].asset.amount);
            assert_eq!(
                tx.outputs[j].script_public_key,
                tx::kas_destination(&tt.legs[j].delivery)
            );
            assert!(tx.outputs[j].covenant.is_none());
        }
        assert_eq!(ipst.slots()[n + k].signer(), Some(payer(NS)));
        let m = ipst.masses();
        let c = caps(Network::Mainnet);
        assert!(m.compute <= c.compute && m.transient <= c.transient && m.storage <= c.storage);
    }
}

#[test]
fn n2_settle_is_v1s_layout_position_for_position() {
    // v1 KAS cash: asset authorizer, KAS cash vault, asset escrow; asset delivery, KAS proceeds,
    // asset authorizer home, change.
    let w = world(two_kas(NS, true));
    let ipst = w.settle().unwrap();
    let tx = ipst.transaction();
    assert_eq!(ipst.entries()[1].amount, KAS_AMOUNT);
    assert!(ipst.entries()[2].covenant_id.is_some());
    assert!(tx.outputs[0].covenant.is_some());
    assert_eq!(tx.outputs[1].value, KAS_AMOUNT);
    assert_eq!(tx.outputs[2].script_public_key, p2pk(&party(NS, 0)));
    // v1 KCC-20 cash: two authorizers, two escrows; two deliveries, two authorizers home.
    let w = world(two_kcc20(NS, false));
    let tx = w.settle().unwrap().transaction().clone();
    assert_eq!(tx.outputs[0].covenant.unwrap().authorizing_input, 2);
    assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 3);
    assert_eq!(tx.outputs[2].script_public_key, p2pk(&party(NS, 0)));
    assert_eq!(tx.outputs[3].script_public_key, p2pk(&party(NS, 1)));
}

#[test]
fn ten_leg_settle_fits_cap_v2_and_warns_above_100000() {
    // The ten-leg list is above the pre-Toccata 100,000 grams (docs/measurements/v2-max-n.txt);
    // the builder builds it under CAP_V2 and only flags it.
    let ipst = world(bilateral10(NS, true)).settle().unwrap();
    assert!(ipst.above_pre_toccata_cap());
    let m = ipst.masses();
    let c = caps(Network::Mainnet);
    assert!(m.compute <= c.compute && m.transient <= c.transient && m.storage <= c.storage);
}

/// The pre-Toccata flag of every shape's builder-produced settle, measured with the pinned
/// MassCalculator (`IpstV2::masses`). The owner runbook states this per shape.
#[test]
fn above_pre_toccata_cap_is_asserted_per_shape() {
    // The mainnet demo's `token` shape: one KCC-20 leg and two KAS legs in a ring.
    let token_demo = {
        let p = |i| party(NS, i);
        terms(
            NS,
            vec![
                kcc20_leg(0, p(0), p(1), TOKEN_AMOUNT),
                kas_leg(p(1), p(2), KAS_AMOUNT),
                kas_leg(p(2), p(0), KAS_AMOUNT),
            ],
            true,
        )
    };
    let cases: [(&str, TermsV2, bool); 7] = [
        ("token demo (1 KCC-20, 2 KAS)", token_demo, true),
        ("ring3", ring3(NS, true), true),
        ("with_kas3", with_kas3(NS, false), true),
        ("bilateral10", bilateral10(NS, true), true),
        ("two_kas", two_kas(NS, true), true),
        ("kas_ring3 authority", kas_ring3(NS, true), true),
        ("kas_ring3 self-settling", kas_ring3(NS, false), true),
    ];
    for (label, terms, above) in cases {
        let ipst = world(terms).settle().unwrap();
        let m = ipst.masses();
        assert_eq!(
            ipst.above_pre_toccata_cap(),
            above,
            "{label}: {m:?} against {PRE_TOCCATA_MASS_CAP}"
        );
        let c = caps(Network::Mainnet);
        assert!(m.compute <= c.compute && m.transient <= c.transient && m.storage <= c.storage);
    }
}

#[test]
fn settle_refusals_in_order() {
    let w = world(with_kas3(NS, true));
    let tmpl = template();
    let other = cash_template();
    // TX_EXPIRED first.
    let legs = settle_legs(&w.funded, &tmpl);
    assert_eq!(
        code(settle(&w.terms, &legs, &fee_payment(NS), EXPIRY)),
        "TX_EXPIRED"
    );
    // TX_V2_NOT_AT_VAULT: a vault UTXO of another leg, or a covenant without partial.
    assert_eq!(
        code(w.settle_with(&tmpl, |l| l.swap(0, 1))),
        "TX_V2_NOT_AT_VAULT"
    );
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            if let SettleLeg::Kas { vault } = &mut l[2] {
                vault.entry.covenant_id = Some(Hash::from_bytes([7; 32]));
            }
        })),
        "TX_V2_NOT_AT_VAULT"
    );
    // TX_LEGS: a missing leg, or a leg of the wrong shape.
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            l.pop();
        })),
        "TX_LEGS"
    );
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            let SettleLeg::Kcc20 { authorizer, .. } = l[0].clone() else {
                unreachable!()
            };
            l[0] = SettleLeg::Kas { vault: authorizer };
        })),
        "TX_LEGS"
    );
    // TX_TOKEN_TEMPLATE: another template than the leg names.
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            if let SettleLeg::Kcc20 { escrow, .. } = &mut l[1] {
                escrow.template = &other;
            }
        })),
        "TX_TOKEN_TEMPLATE"
    );
    // TX_ESCROW_MISMATCH: another covenant.
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            if let SettleLeg::Kcc20 { escrow, .. } = &mut l[1] {
                escrow.utxo.entry.covenant_id = Some(Hash::from_bytes(token(0).covenant_id));
            }
        })),
        "TX_ESCROW_MISMATCH"
    );
    // TX_LEG_AMOUNT: an escrow of another amount (its script holding that amount), a KAS vault
    // UTXO of another value.
    let vault1 = VaultV2::instantiate_existing(&w.terms, 1).unwrap();
    let short = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault1.script_hash(),
        },
        TOKEN_AMOUNT * 2 - 1,
    );
    let short_spk = tmpl.script_public_key(&short).unwrap();
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            if let SettleLeg::Kcc20 { escrow, .. } = &mut l[1] {
                escrow.amount = TOKEN_AMOUNT * 2 - 1;
                escrow.utxo.entry.script_public_key = short_spk;
            }
        })),
        "TX_LEG_AMOUNT"
    );
    assert_eq!(
        code(w.settle_with(&tmpl, |l| {
            if let SettleLeg::Kas { vault } = &mut l[2] {
                vault.entry.amount += 1;
            }
        })),
        "TX_LEG_AMOUNT"
    );
    // The shared checks: no fee input, too little, a low fee.
    let legs = settle_legs(&w.funded, &tmpl);
    let mut fee = fee_payment(NS);
    fee.inputs.clear();
    assert_eq!(code(settle(&w.terms, &legs, &fee, NOW)), "TX_KAS_INPUT");
    let mut fee = fee_payment(NS);
    fee.fee = FEE_INPUT * 10;
    assert_eq!(
        code(settle(&w.terms, &legs, &fee, NOW)),
        "TX_INSUFFICIENT_FUNDS"
    );
    let mut fee = fee_payment(NS);
    fee.fee = 1;
    assert_eq!(code(settle(&w.terms, &legs, &fee, NOW)), "TX_FEE_TOO_LOW");
}

#[test]
fn settle_mass_above_cap_v2_is_refused() {
    // A KAS leg of 1,000 sompi: its exact delivery puts the storage mass above CAP_V2.
    let mut t = with_kas3(NS, true);
    t.legs[2].asset.amount = 1_000;
    let w = world(t);
    let e = w.settle().unwrap_err();
    assert_eq!(e.code(), "TX_V2_MASS");
    assert!(matches!(
        e,
        V2Error::Mass {
            dimension: "storage",
            ..
        }
    ));
}

/// Partial terms (I17's) settled in full: whole lots, the same number in every leg.
fn partial_world(lot_count: u64, min_lot: u64) -> World {
    let mut t = with_kas3(NS, true);
    t.partial = Some(Partial { lot_count, min_lot });
    let mut w = world(t);
    for (i, f) in w.funded.iter_mut().enumerate() {
        f.vault.entry.covenant_id = Some(Hash::from_bytes([0xC0 + i as u8; 32]));
    }
    w
}

fn holding(w: &World, leg: usize, amount: u64) -> World {
    let tmpl = template();
    let mut funded = w.funded.clone();
    match &mut funded[leg].escrow {
        Some((utxo, held)) => {
            let vault = VaultV2::instantiate_existing(&w.terms, leg).unwrap();
            let state = Kcc20State::new(
                Kcc20Owner {
                    identifier_type: IdentifierType::ScriptHash,
                    identifier: vault.script_hash(),
                },
                amount,
            );
            utxo.entry.script_public_key = tmpl.script_public_key(&state).unwrap();
            *held = amount;
        }
        None => funded[leg].vault.entry.amount = amount,
    }
    World {
        terms: w.terms.clone(),
        funded,
    }
}

#[test]
fn partial_terms_settle_in_full_and_refuse_tranche_faults() {
    let w = partial_world(4, 2);
    let ipst = w.settle().unwrap();
    assert_eq!(ipst.transaction().outputs[2].value, KAS_AMOUNT);
    // Three of four lots in every leg: still a final settle of what the escrows hold.
    let three = holding(
        &holding(&holding(&w, 0, 750), 1, 1_500),
        2,
        KAS_AMOUNT / 4 * 3,
    );
    assert_eq!(
        three.settle().unwrap().transaction().outputs[2].value,
        KAS_AMOUNT / 4 * 3
    );
    // TX_TRANCHE: not whole lots, more than the amount, fewer than min_lot.
    assert_eq!(code(holding(&w, 0, 700).settle()), "TX_TRANCHE");
    assert_eq!(code(holding(&w, 0, 1_250).settle()), "TX_TRANCHE");
    assert_eq!(
        code(holding(&holding(&holding(&w, 0, 250), 1, 500), 2, KAS_AMOUNT / 4).settle()),
        "TX_TRANCHE"
    );
    // TX_LINEAGE: two vault UTXOs with one covenant ID.
    let mut same = partial_world(4, 2);
    same.funded[1].vault.entry.covenant_id = same.funded[0].vault.entry.covenant_id;
    assert_eq!(code(same.settle()), "TX_LINEAGE");
    // TX_LEGS_OUT_OF_STEP: legs holding different numbers of lots.
    assert_eq!(code(holding(&w, 1, 1_500).settle()), "TX_LEGS_OUT_OF_STEP");
}

#[test]
fn refund_layouts_and_lock_times() {
    let mut t = with_kas3(NS, true);
    t.funding_mode = FundingMode::Earmarked;
    let w = world(t);
    let tt = w.terms.terms();
    // Depositor of a KCC-20 leg with its token: lock time expiry (earmarked).
    let r = w.refund(1, RefundSignerV2::Depositor(1), true).unwrap();
    let tx = r.transaction();
    assert_eq!(tx.lock_time, EXPIRY);
    assert_eq!(tx.outputs[0].value, r.entries()[0].amount);
    assert_eq!(
        tx.outputs[0].script_public_key,
        p2pk(&tt.legs[1].depositor_key)
    );
    assert_eq!(tx.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert_eq!(r.slots()[0].signer(), Some(party(NS, 1)));
    assert_eq!(
        tx.inputs[0].compute_commit.compute_budget(),
        Some(refund_budget(tt, 1, true, true))
    );
    // Another depositor: no lock, the token goes home all the same.
    let r = w.refund(1, RefundSignerV2::Depositor(2), true).unwrap();
    assert_eq!(r.transaction().lock_time, 0);
    assert_eq!(r.slots()[0].signer(), Some(party(NS, 2)));
    // The KAS leg by the authority: its refund destination, no lock.
    let r = w.refund(2, RefundSignerV2::Authority, false).unwrap();
    assert_eq!(r.transaction().lock_time, 0);
    assert_eq!(
        r.transaction().outputs[0].script_public_key,
        tx::kas_destination(&tt.legs[2].refund)
    );
    assert_eq!(r.slots()[0].signer(), tt.authority_key);
    // The depositor alone takes the authorizer home without the token.
    let r = w.refund(0, RefundSignerV2::Depositor(0), false).unwrap();
    assert_eq!(r.transaction().inputs.len(), 2);
}

#[test]
fn a_depositor_of_several_legs_is_each_legs_depositor() {
    // Party 0 deposits legs 0, 2, 4, 6, 8 of the ten-leg list: naming leg 2 when refunding leg 0
    // is still the depositor's own refund, so an earmarked lock applies.
    let mut t = bilateral10(NS, true);
    t.funding_mode = FundingMode::Earmarked;
    let w = world(t);
    let r = w.refund(0, RefundSignerV2::Depositor(2), false).unwrap();
    assert_eq!(r.transaction().lock_time, EXPIRY);
}

#[test]
fn refund_refusals() {
    let w = world(with_kas3(NS, false));
    let no_leg = refund(
        &w.terms,
        3,
        RefundSignerV2::Depositor(0),
        &w.funded[0].vault,
        None,
        &fee_payment(NS),
    );
    assert_eq!(code(no_leg), "TEMPLATE_V2_LEG_INDEX");
    assert_eq!(
        code(w.refund(0, RefundSignerV2::Depositor(3), true)),
        "TX_REFUND_SIGNER"
    );
    assert_eq!(
        code(w.refund(0, RefundSignerV2::Authority, true)),
        "TX_REFUND_SIGNER"
    );
    assert_eq!(
        code(w.refund(0, RefundSignerV2::Depositor(1), false)),
        "TX_REFUND_SIGNER"
    );
    let tmpl = template();
    let kas_with_token = refund(
        &w.terms,
        2,
        RefundSignerV2::Depositor(2),
        &w.funded[2].vault,
        refund_escrow(&w.funded[0], &tmpl).as_ref(),
        &fee_payment(NS),
    );
    assert_eq!(code(kas_with_token), "TX_WRONG_MODE");
    let not_vault = refund(
        &w.terms,
        0,
        RefundSignerV2::Depositor(0),
        &w.funded[1].vault,
        None,
        &fee_payment(NS),
    );
    assert_eq!(code(not_vault), "TX_V2_NOT_AT_VAULT");
    // Anyone but the depositor refunds only the whole leg amount.
    let short = holding(&w, 0, TOKEN_AMOUNT - 1);
    assert_eq!(
        code(short.refund(0, RefundSignerV2::Depositor(1), true)),
        "TX_LEG_AMOUNT"
    );
    assert!(short.refund(0, RefundSignerV2::Depositor(0), true).is_ok());
    let mut escrow = refund_escrow(&w.funded[0], &tmpl).unwrap();
    escrow.utxo.entry.covenant_id = Some(Hash::from_bytes([9; 32]));
    let wrong = refund(
        &w.terms,
        0,
        RefundSignerV2::Depositor(0),
        &w.funded[0].vault,
        Some(&escrow),
        &fee_payment(NS),
    );
    assert_eq!(code(wrong), "TX_ESCROW_MISMATCH");
}

fn fundable(t: &ValidatedTermsV2, leg: usize) -> FundableVaultV2 {
    VaultV2::instantiate_for_creation(t, leg, &CreationContext::new(t.terms().network, 1)).unwrap()
}

fn funding() -> FeePayment {
    FeePayment {
        inputs: vec![utxo(
            "tests/v2/funding",
            5 * FEE_INPUT,
            p2pk(&party(NS, 2)),
            None,
        )],
        fee: FEE,
        change: p2pk(&party(NS, 2)),
    }
}

fn deposit(t: &TermsV2, leg: usize, held: u64) -> Kcc20Deposit {
    let tmpl = template();
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: t.legs[leg].depositor_key,
        },
        held,
    );
    Kcc20Deposit {
        tokens: vec![TokenUtxo {
            utxo: utxo(
                "tests/v2/token",
                min_v2(t, 2),
                tmpl.script_public_key(&state).unwrap(),
                Some(token(leg).covenant_id),
            ),
            state,
        }],
        carrier: min_v2(t, 2),
        authorizer: min_vault_v2(t),
    }
}

#[test]
fn fund_builders() {
    let w = world(with_kas3(NS, true));
    let t = w.terms.terms();
    let tmpl = template();
    let kas = fund_kas(&w.terms, &fundable(&w.terms, 2), &funding(), NOW).unwrap();
    assert_eq!(kas.transaction().outputs[0].value, KAS_AMOUNT);
    assert_eq!(
        kas.transaction().outputs[0].script_public_key,
        spk_of(&w.terms, 2)
    );
    let token_fund = fund_kcc20(
        &w.terms,
        &fundable(&w.terms, 1),
        &tmpl,
        &deposit(t, 1, 5_000),
        &funding(),
        NOW,
    )
    .unwrap();
    let outs = &token_fund.transaction().outputs;
    assert_eq!(
        outs.len(),
        4,
        "escrow, authorizer, token change, KAS change"
    );
    assert_eq!(outs[1].script_public_key, spk_of(&w.terms, 1));
    // Refusals.
    assert_eq!(
        code(fund_kas(&w.terms, &fundable(&w.terms, 0), &funding(), NOW)),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        code(fund_kcc20(
            &w.terms,
            &fundable(&w.terms, 2),
            &tmpl,
            &deposit(t, 1, 5_000),
            &funding(),
            NOW
        )),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        code(fund_kas(
            &w.terms,
            &fundable(&w.terms, 2),
            &funding(),
            EXPIRY
        )),
        "TX_EXPIRED"
    );
    let other = validated(with_kas3(NS, false));
    assert_eq!(
        code(fund_kas(&w.terms, &fundable(&other, 2), &funding(), NOW)),
        "TX_VAULT_MISMATCH"
    );
    let mut partial = with_kas3(NS, true);
    partial.partial = Some(Partial {
        lot_count: 2,
        min_lot: 1,
    });
    let partial = validated(partial);
    // Partial terms are funded as a KIP-20 genesis (I17): the vault output is bound.
    let genesis = fund_kas(&partial, &fundable(&partial, 2), &funding(), NOW).unwrap();
    assert!(genesis.transaction().outputs[0].covenant.is_some());
    let mut tiny = with_kas3(NS, true);
    tiny.legs[2].asset.amount = 1_000;
    let tiny = validated(tiny);
    assert_eq!(
        code(fund_kas(&tiny, &fundable(&tiny, 2), &funding(), NOW)),
        "TX_BELOW_MIN_KAS"
    );
    let mut low = deposit(t, 1, 5_000);
    low.carrier -= 1;
    assert_eq!(
        code(fund_kcc20(
            &w.terms,
            &fundable(&w.terms, 1),
            &tmpl,
            &low,
            &funding(),
            NOW
        )),
        "TX_BELOW_MIN_KAS"
    );
    assert_eq!(
        code(fund_kcc20(
            &w.terms,
            &fundable(&w.terms, 1),
            &tmpl,
            &deposit(t, 1, 1_999),
            &funding(),
            NOW
        )),
        "TX_TOKEN_INPUT"
    );
}

// =============================================================================================
// IPST version 2
// =============================================================================================

fn every_kind() -> Vec<IpstV2> {
    let w = world(with_kas3(NS, true));
    let t = w.terms.terms().clone();
    let tmpl = template();
    vec![
        w.settle().unwrap(),
        w.refund(0, RefundSignerV2::Depositor(0), true).unwrap(),
        w.refund(0, RefundSignerV2::Depositor(0), false).unwrap(),
        w.refund(1, RefundSignerV2::Authority, true).unwrap(),
        w.refund(2, RefundSignerV2::Depositor(1), false).unwrap(),
        fund_kas(&w.terms, &fundable(&w.terms, 2), &funding(), NOW).unwrap(),
        fund_kcc20(
            &w.terms,
            &fundable(&w.terms, 0),
            &tmpl,
            &deposit(&t, 0, 1_000),
            &funding(),
            NOW,
        )
        .unwrap(),
        world(bilateral10(NS, false)).settle().unwrap(),
    ]
}

#[test]
fn ipst_round_trips_and_passes_the_terms_check() {
    let tmpl = template();
    for ipst in every_kind() {
        let text = ipst.to_json();
        assert!(text.starts_with("{\n  \"ipst\": 2,"));
        let AnyIpst::V2(read) = read_ipst(&text).unwrap() else {
            panic!("version 2")
        };
        assert_eq!(*read, ipst);
        let k = ipst.terms().terms().kcc20_legs();
        let m = read.verify_against_terms(&vec![&tmpl; k], NOW).unwrap();
        assert_eq!(m.fee, ipst.fee());
    }
}

#[test]
fn ipst_terms_check_names_the_builder() {
    let tmpl = template();
    let kinds: Vec<IpstV2Kind> = every_kind()
        .iter()
        .map(|i| {
            let k = i.terms().terms().kcc20_legs();
            i.verify_against_terms(&vec![&tmpl; k], NOW).unwrap().kind
        })
        .collect();
    assert_eq!(kinds[0], IpstV2Kind::Settle);
    assert_eq!(
        kinds[1],
        IpstV2Kind::Refund {
            leg: 0,
            signer: RefundSignerV2::Depositor(0),
            with_token: true
        }
    );
    assert_eq!(
        kinds[2],
        IpstV2Kind::Refund {
            leg: 0,
            signer: RefundSignerV2::Depositor(0),
            with_token: false
        }
    );
    assert_eq!(
        kinds[3],
        IpstV2Kind::Refund {
            leg: 1,
            signer: RefundSignerV2::Authority,
            with_token: true
        }
    );
    assert_eq!(
        kinds[4],
        IpstV2Kind::Refund {
            leg: 2,
            signer: RefundSignerV2::Depositor(1),
            with_token: false
        }
    );
    assert_eq!(kinds[5], IpstV2Kind::FundKas { leg: 2 });
    assert_eq!(kinds[6], IpstV2Kind::FundKcc20 { leg: 0 });
}

#[test]
fn ipst_refusals() {
    let tmpl = template();
    let ipst = world(ring3(NS, true)).settle().unwrap();
    let text = ipst.to_json();
    // Version: 1 reads with the v1 reader, 3 is IPST_V2_VERSION, none is IPST_MALFORMED.
    assert_eq!(
        code(read_ipst(&text.replacen("\"ipst\": 2", "\"ipst\": 3", 1))),
        "IPST_V2_VERSION"
    );
    assert_eq!(
        code(read_ipst(&text.replacen("\"ipst\": 2,", "", 1))),
        "IPST_MALFORMED"
    );
    let v1 = crate::tx::Ipst::from_json(&text).unwrap_err();
    assert_eq!(
        v1.code(),
        "IPST_UNSUPPORTED_VERSION",
        "a v1 reader refuses version 2"
    );
    let v1_doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors/ipst/04-settle-authority-kas.json"),
    )
    .unwrap();
    let v1_ipst: serde_json::Value = serde_json::from_str(&v1_doc).unwrap();
    assert!(matches!(
        read_ipst(&v1_ipst["ipst"].to_string()).unwrap(),
        AnyIpst::V1(_)
    ));
    // A stated sighash that is not the recomputed one.
    let sighash = hex(&ipst.slots()[0].sighash().unwrap());
    let wrong = format!("{:064x}", 7);
    assert_eq!(
        code(read_ipst(&text.replacen(&sighash, &wrong, 1))),
        "IPST_SIGHASH_MISMATCH"
    );
    // Terms check: a delivery carrier raised by one sompi (and the change lowered by one, so the
    // fee is unchanged) is not the builders' transaction, though its sighashes are consistent.
    let mut tx = ipst.transaction().clone();
    tx.outputs[0].value += 1;
    let last = tx.outputs.len() - 1;
    tx.outputs[last].value -= 1;
    let mut slots = ipst.slots().to_vec();
    for (i, slot) in slots.iter_mut().enumerate() {
        if slot.signer.is_some() {
            slot.sighash = Some(crate::tx::sighash(&tx, ipst.entries(), i).unwrap());
        }
    }
    let changed = IpstV2::from_parts(ipst.terms().clone(), tx, ipst.entries().to_vec(), slots);
    let AnyIpst::V2(changed) = read_ipst(&changed.to_json()).unwrap() else {
        panic!()
    };
    assert_eq!(
        code(changed.verify_against_terms(&[&tmpl, &tmpl, &tmpl], NOW)),
        "IPST_TERMS_MISMATCH"
    );
    // Signing: a missing signature at finalize, a bad one at add.
    assert_eq!(code(ipst.finalize()), "TX_SIGNATURE_SLOT");
    let mut s = ipst.clone();
    assert_eq!(code(s.add_signature(0, &[1; 65])), "TX_SIGNATURE");
    assert_eq!(code(s.add_signature(3, &[1; 65])), "TX_SIGNATURE_SLOT");
    assert_eq!(code(s.add_signature(99, &[1; 65])), "TX_SIGNATURE_SLOT");
    // Combine: other terms conflict.
    let other = world(ring3(NS, false)).settle().unwrap();
    assert_eq!(code(ipst.combine(&other)), "IPST_CONFLICT");
    assert_eq!(ipst.combine(&ipst).unwrap(), ipst);
}

// =============================================================================================
// Verifier
// =============================================================================================

fn offered<'a>(v: &[&'a str]) -> Vec<Option<&'a str>> {
    v.iter().map(|s| Some(*s)).collect()
}

fn addresses(t: &ValidatedTermsV2) -> Vec<String> {
    (0..t.terms().legs.len())
        .map(|i| vault_address(&fundable(t, i)))
        .collect()
}

#[test]
fn verify_addresses_of_every_leg() {
    let t = validated(ring3(NS, true));
    let ctx = CreationContext::new(Network::Mainnet, 1);
    let a = addresses(&t);
    let ok = verify_addresses(&t, &ctx, &offered(&[&a[0], &a[1], &a[2]])).unwrap();
    assert_eq!(ok.len(), 3);
    assert_eq!(ok[2].address, a[2]);
    assert_eq!(
        code(verify_addresses(&t, &ctx, &offered(&[&a[0], &a[1]]))),
        "VERIFY_ADDRESS_MISSING"
    );
    assert_eq!(
        code(verify_addresses(
            &t,
            &ctx,
            &offered(&[&a[0], "kaspa:qqq", &a[2]])
        )),
        "VERIFY_ADDRESS_MALFORMED"
    );
    let testnet = a[1].replacen("kaspa:", "kaspatest:", 1);
    assert_eq!(
        code(verify_addresses(
            &t,
            &ctx,
            &offered(&[&a[0], &testnet, &a[2]])
        )),
        "VERIFY_ADDRESS_MALFORMED"
    );
    let mut tn = ring3(NS, true);
    tn.network = Network::Testnet;
    let tn = validated(tn);
    let tn_a = addresses(&tn);
    assert_eq!(
        code(verify_addresses(
            &t,
            &ctx,
            &offered(&[&a[0], &tn_a[1], &a[2]])
        )),
        "VERIFY_ADDRESS_NETWORK"
    );
    let swapped = verify_addresses(&t, &ctx, &offered(&[&a[2], &a[1], &a[0]])).unwrap_err();
    assert_eq!(swapped, V2Error::WrongLeg { leg: 0, found: 2 });
    let other = addresses(&validated(ring3(NS, false)));
    assert_eq!(
        code(verify_addresses(
            &t,
            &ctx,
            &offered(&[&a[0], &other[1], &a[2]])
        )),
        "VERIFY_V2_ADDRESS_MISMATCH"
    );
    assert_eq!(
        code(verify_addresses(
            &t,
            &CreationContext::new(Network::Testnet, 1),
            &offered(&[&a[0], &a[1], &a[2]])
        )),
        "TERMS_NETWORK_MISMATCH"
    );
}

#[test]
fn verify_revealed_scripts_and_spent_inputs() {
    let t = validated(ring3(NS, true));
    let v1 = VaultV2::instantiate_existing(&t, 1).unwrap();
    assert_eq!(verify_revealed_script(&t, 1, v1.redeem_script()), Ok(()));
    assert_eq!(
        verify_revealed_script(&t, 0, v1.redeem_script()).unwrap_err(),
        V2Error::WrongLeg { leg: 0, found: 1 }
    );
    let other = validated(ring3(NS, false));
    let o = VaultV2::instantiate_existing(&other, 1).unwrap();
    assert_eq!(
        code(verify_revealed_script(&t, 1, o.redeem_script())),
        "VERIFY_TERMS_MISMATCH"
    );
    let v1_terms = crate::terms::golden::vectors()
        .remove(0)
        .terms
        .validate_structure()
        .unwrap();
    let old =
        crate::template::Vault::instantiate_existing(&v1_terms, crate::template::LegIndex::Asset)
            .unwrap();
    assert_eq!(
        code(verify_revealed_script(&t, 1, old.redeem_script())),
        "VERIFY_V2_TEMPLATE_MISMATCH"
    );
    assert_eq!(
        code(verify_revealed_script(&t, 1, &[0x51])),
        "VERIFY_V2_TEMPLATE_MISMATCH"
    );
    assert_eq!(
        code(verify_revealed_script(&t, 3, v1.redeem_script())),
        "TEMPLATE_V2_LEG_INDEX"
    );
    // A spent input of the settle reveals vault 1's script.
    let ipst = world(ring3(NS, true)).settle().unwrap();
    let signed = ipst.transaction().inputs[1].clone();
    let mut input = signed.clone();
    input.signature_script = ipst.slots()[1].script_with(&[0; 65]);
    assert_eq!(
        verify_spent_input(&t, 1, &input, &v1.script_public_key()),
        Ok(())
    );
    assert_eq!(
        code(verify_spent_input(&t, 1, &input, &o.script_public_key())),
        "VERIFY_INPUT_NOT_VAULT"
    );
    let mut nothing = signed;
    nothing.signature_script = vec![0x6a];
    assert_eq!(
        code(verify_spent_input(&t, 1, &nothing, &v1.script_public_key())),
        "VERIFY_NOTHING_REVEALED"
    );
}

#[test]
fn vault_utxo_checks_and_warnings() {
    let w = world(with_kas3(NS, true));
    let vaults: Vec<Vec<crate::tx::Utxo>> =
        w.funded.iter().map(|f| vec![f.vault.clone()]).collect();
    let tokens: Vec<Vec<(crate::tx::Utxo, u64)>> = w
        .funded
        .iter()
        .map(|f| f.escrow.clone().into_iter().collect())
        .collect();
    assert_eq!(
        check_vault_utxos(&w.terms, &vaults, &tokens).unwrap(),
        vec![]
    );
    let mut strays = tokens.clone();
    let extra = strays[0][0].clone();
    strays[0].push(extra);
    assert_eq!(
        check_vault_utxos(&w.terms, &vaults, &strays).unwrap(),
        vec![VaultUtxoWarning::StrayEscrows { leg: 0, count: 2 }]
    );
    let mut low = vaults.clone();
    low[2][0].entry.amount = 1_000;
    assert!(matches!(
        check_vault_utxos(&w.terms, &low, &tokens).unwrap()[..],
        [VaultUtxoWarning::BelowMinimum { leg: 2, .. }]
    ));
    let mut same = vaults.clone();
    same[0][0].entry.covenant_id = Some(Hash::from_bytes([1; 32]));
    same[1][0].entry.covenant_id = Some(Hash::from_bytes([1; 32]));
    assert_eq!(
        code(check_vault_utxos(&w.terms, &same, &tokens)),
        "TX_LINEAGE"
    );
    let mut p = with_kas3(NS, false);
    p.partial = Some(Partial {
        lot_count: 2,
        min_lot: 1,
    });
    let p = validated(p);
    assert_eq!(
        check_vault_utxos(&p, &[], &[]).unwrap(),
        vec![VaultUtxoWarning::PartialWithoutAuthority]
    );
}

// =============================================================================================
// I17: tranches, genesis funding, settle facts, quantities
// =============================================================================================

/// The transaction with every signature script filled in (65 zero bytes for each signature), so
/// the readers that look at signature scripts can run keyless.
fn scripted(ipst: &IpstV2) -> kaspa_consensus_core::tx::Transaction {
    let mut tx = ipst.transaction().clone();
    for (input, slot) in tx.inputs.iter_mut().zip(ipst.slots()) {
        input.signature_script = slot.script_with(&[0; 65]);
    }
    tx.finalize();
    tx
}

fn tranche_of(w: &World, lots: u64) -> Result<IpstV2, V2Error> {
    let tmpl = template();
    settle_tranche(
        &w.terms,
        &settle_legs(&w.funded, &tmpl),
        lots,
        &fee_payment(NS),
        NOW,
    )
}

/// A plain-terms world with lots of 250 / 500 / 25,000,000 and covenant IDs on the vaults.
fn lots_world(lot_count: u64, min_lot: u64) -> World {
    let mut t = with_kas3(NS, true);
    t.legs[2].asset.amount = BIG;
    t.partial = Some(Partial { lot_count, min_lot });
    let mut w = world(t);
    for (i, f) in w.funded.iter_mut().enumerate() {
        f.vault.entry.covenant_id = Some(Hash::from_bytes([0xC0 + i as u8; 32]));
    }
    w
}

/// The KAS leg of the I17 fixtures: a lot and a remainder must each hold MIN_V2 of the vault
/// output (0.8 KAS for nine outputs), which the 1 KAS of the I16 fixtures cannot.
const BIG: u64 = 10 * KAS_AMOUNT;

#[test]
fn tranche_layout_of_spec_4_3() {
    let w = lots_world(4, 1);
    let ipst = tranche_of(&w, 1).unwrap();
    let tx = ipst.transaction();
    let t = w.terms.terms();
    // N = 3, K = 2: deliveries 0..3, continuations 3..6, remainders 6..8, then change.
    assert_eq!(tx.outputs.len(), 3 + 3 + 2 + 1);
    assert_eq!(tx.outputs[2].value, BIG / 4);
    assert_eq!(
        tx.outputs[2].script_public_key,
        kas_destination(&t.legs[2].delivery)
    );
    for i in 0..3 {
        let o = &tx.outputs[3 + i];
        assert_eq!(o.script_public_key, spk_of(&w.terms, i), "continuation {i}");
        let b = o.covenant.expect("bound");
        assert_eq!(b.authorizing_input as usize, i);
        assert_eq!(Some(b.covenant_id), w.funded[i].vault.entry.covenant_id);
    }
    // The KAS leg continues with the remainder, exact; the authorizers in full.
    assert_eq!(tx.outputs[5].value, BIG / 4 * 3);
    assert_eq!(tx.outputs[3].value, w.funded[0].vault.entry.amount);
    // Remainder tokens carry the token covenants, authorized by the escrow inputs.
    for j in 0..2 {
        let b = tx.outputs[6 + j].covenant.expect("token");
        assert_eq!(b.authorizing_input as usize, 3 + j);
        assert_eq!(b.covenant_id.as_bytes(), token(j).covenant_id);
        assert!(tx.outputs[6 + j].value >= ipst.entries()[3 + j].amount);
    }
    // Lock time and the authority's slots as the final settle.
    assert_eq!(tx.lock_time, EARLIEST);
    assert_eq!(ipst.slots()[0].signer(), Some(authority(NS)));
    // The terms check rebuilds it, kind and all.
    let tmpl = template();
    let m = ipst.verify_against_terms(&[&tmpl, &tmpl], NOW).unwrap();
    assert_eq!(m.kind, IpstV2Kind::Tranche { lots: 1 });
    assert_eq!(m.change, tx.outputs.get(8).cloned());
    // A document round trip keeps every covenant binding.
    let AnyIpst::V2(back) = read_ipst(&ipst.to_json()).unwrap() else {
        panic!("a v2 document")
    };
    assert_eq!(back.transaction(), ipst.transaction());
    // Three of four lots leave a remainder of one: a tranche; all four: the final layout.
    let three = tranche_of(&w, 3).unwrap();
    assert_eq!(three.transaction().outputs[2].value, BIG / 4 * 3);
    assert_eq!(three.transaction().outputs[5].value, BIG / 4);
    let all = tranche_of(&w, 4).unwrap();
    let plain = w.settle().unwrap();
    assert_eq!(all.transaction(), plain.transaction());
    assert_eq!(
        all.verify_against_terms(&[&tmpl, &tmpl], NOW).unwrap().kind,
        IpstV2Kind::Settle
    );
}

#[test]
fn tranche_budgets_are_the_committed_rule() {
    let w = lots_world(4, 1);
    let t = w.terms.terms();
    for i in 0..3 {
        assert!(tranche_budget(t, i) >= settle_budget(t, i), "leg {i}");
    }
    assert!(
        tranche_budget(t, 0) > settle_budget(t, 0),
        "the token leg's rule adds 770"
    );
    let ipst = tranche_of(&w, 1).unwrap();
    for i in 0..3 {
        assert_eq!(
            ipst.transaction().inputs[i].compute_commit.compute_budget(),
            Some(tranche_budget(t, i))
        );
    }
}

#[test]
fn tranche_refusals_in_order() {
    let w = lots_world(10, 3);
    // Lots: 0, past what the escrows hold, below min_lot, leaving less than min_lot.
    for lots in [0, 11, 1, 2, 8, 9] {
        assert_eq!(code(tranche_of(&w, lots)), "TX_TRANCHE", "lots {lots}");
    }
    for lots in [3, 5, 7, 10] {
        assert!(tranche_of(&w, lots).is_ok(), "lots {lots}");
    }
    // Terms without partial name no tranche.
    let plain = world(with_kas3(NS, true));
    assert_eq!(code(tranche_of(&plain, 1)), "TX_TRANCHE");
    // A tranche from vault UTXOs without a covenant ID.
    let mut bare = lots_world(10, 3);
    bare.funded[1].vault.entry.covenant_id = None;
    assert_eq!(code(tranche_of(&bare, 5)), "TX_LINEAGE");
    // The final settle needs none.
    assert!(tranche_of(&bare, 10).is_ok());
    // Equal covenant IDs.
    let mut same = lots_world(10, 3);
    same.funded[1].vault.entry.covenant_id = same.funded[0].vault.entry.covenant_id;
    assert_eq!(code(tranche_of(&same, 5)), "TX_LINEAGE");
    // Legs at different remaining amounts.
    let off = holding(&lots_world(10, 3), 1, 1_400);
    assert_eq!(code(tranche_of(&off, 3)), "TX_LEGS_OUT_OF_STEP");
    // An escrow holding fewer than min_lot lots; a lot count the escrow cannot hold.
    let small = holding(&lots_world(10, 3), 0, 200);
    assert_eq!(code(tranche_of(&small, 3)), "TX_TRANCHE");
    // Expired.
    let tmpl = template();
    assert_eq!(
        code(settle_tranche(
            &w.terms,
            &settle_legs(&w.funded, &tmpl),
            5,
            &fee_payment(NS),
            EXPIRY
        )),
        "TX_EXPIRED"
    );
}

#[test]
fn tranche_chains_on_its_own_continuations() {
    // 8 lots, min 2: tranche 3, tranche 3, final 2; each spends the previous one's outputs.
    let mut w = lots_world(8, 2);
    let tmpl = template();
    for lots in [3u64, 3, 2] {
        let ipst = tranche_of(&w, lots).unwrap();
        let tx = ipst.transaction();
        let t = w.terms.terms();
        let n = t.legs.len();
        let id = tx.id();
        if lots == 2 {
            assert!(tx.outputs[n..].iter().all(|o| o.covenant.is_none()
                || o.covenant
                    .is_some_and(|c| c.authorizing_input as usize >= n)));
            break;
        }
        // The next tranche's UTXOs are this one's outputs.
        for (i, f) in w.funded.iter_mut().enumerate() {
            let vault_out = n + i;
            f.vault = Utxo {
                outpoint: kaspa_consensus_core::tx::TransactionOutpoint::new(id, vault_out as u32),
                entry: UtxoEntry::new(
                    tx.outputs[vault_out].value,
                    tx.outputs[vault_out].script_public_key.clone(),
                    100,
                    false,
                    tx.outputs[vault_out].covenant.map(|c| c.covenant_id),
                ),
            };
            if let Some((escrow, held)) = &mut f.escrow {
                let out = 2 * n + i;
                *held -= lots * t.unit(i);
                *escrow = Utxo {
                    outpoint: kaspa_consensus_core::tx::TransactionOutpoint::new(id, out as u32),
                    entry: UtxoEntry::new(
                        tx.outputs[out].value,
                        tx.outputs[out].script_public_key.clone(),
                        100,
                        false,
                        tx.outputs[out].covenant.map(|c| c.covenant_id),
                    ),
                };
            } else {
                f.vault.entry.amount = tx.outputs[vault_out].value;
            }
        }
        let _ = &tmpl;
    }
}

#[test]
fn partial_funding_makes_one_genesis_per_leg() {
    let mut t = with_kas3(NS, true);
    t.legs[2].asset.amount = BIG;
    t.partial = Some(Partial {
        lot_count: 4,
        min_lot: 1,
    });
    let terms = validated(t);
    // The KAS leg: output 0 is the genesis, authorized by the first payer input (input 0).
    let kas = fund_kas(&terms, &fundable(&terms, 2), &funding(), NOW).unwrap();
    let tx = scripted(&kas);
    let id = verify_genesis(&terms, 2, &tx, 0).unwrap();
    assert_eq!(tx.outputs[0].covenant.unwrap().authorizing_input, 0);
    assert_eq!(tx.outputs[0].covenant.unwrap().covenant_id, id);
    assert!(tx.outputs[1..].iter().all(|o| o.covenant.is_none()));
    // The terms check rebuilds a genesis funding.
    let tmpl = template();
    assert_eq!(
        kas.verify_against_terms(&[&tmpl, &tmpl], NOW).unwrap().kind,
        IpstV2Kind::FundKas { leg: 2 }
    );
    // A KCC-20 leg: output 1 (the authorizer) is the genesis, authorized by the first payer
    // input (input 1, after the token input); the escrow keeps the token's covenant.
    let dep = deposit(terms.terms(), 0, 1_000);
    let k = fund_kcc20(&terms, &fundable(&terms, 0), &tmpl, &dep, &funding(), NOW).unwrap();
    let ktx = scripted(&k);
    let kid = verify_genesis(&terms, 0, &ktx, 1).unwrap();
    assert_eq!(ktx.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert_eq!(
        ktx.outputs[0].covenant.unwrap().covenant_id.as_bytes(),
        token(0).covenant_id
    );
    assert_ne!(kid, id, "one genesis group per leg: distinct IDs");
    assert_eq!(
        k.verify_against_terms(&[&tmpl, &tmpl], NOW).unwrap().kind,
        IpstV2Kind::FundKcc20 { leg: 0 }
    );
    // The ID is bound to the output: the same transaction with another value fails.
    let mut forged = ktx.clone();
    forged.outputs[1].value += 1;
    assert_eq!(code(verify_genesis(&terms, 0, &forged, 1)), "TX_LINEAGE");
    // An output that is not bound, not at the vault, or not there.
    assert_eq!(
        code(verify_genesis(&terms, 0, &ktx, 0)),
        "TX_V2_NOT_AT_VAULT"
    );
    assert_eq!(code(verify_genesis(&terms, 0, &ktx, 9)), "TX_LINEAGE");
    let mut unbound = ktx.clone();
    unbound.outputs[1].covenant = None;
    assert_eq!(code(verify_genesis(&terms, 0, &unbound, 1)), "TX_LINEAGE");
    // Without partial the vault outputs are plain.
    let plain = validated(with_kas3(NS, true));
    let p = fund_kas(&plain, &fundable(&plain, 2), &funding(), NOW).unwrap();
    assert!(p.transaction().outputs[0].covenant.is_none());
    // A KAS lot below MIN_V2(1, O) is refused at funding (a delivery cannot be topped up).
    let mut thin = with_kas3(NS, true);
    thin.legs[2].asset.amount = 100_000_000;
    thin.partial = Some(Partial {
        lot_count: 8,
        min_lot: 1,
    });
    let thin = validated(thin);
    assert_eq!(
        code(fund_kas(&thin, &fundable(&thin, 2), &funding(), NOW)),
        "TX_BELOW_MIN_KAS"
    );
}

#[test]
fn a_settle_transaction_states_its_facts() {
    let w = lots_world(4, 1);
    let ipst = tranche_of(&w, 1).unwrap();
    let tx = scripted(&ipst);
    let facts = read_settle(&w.terms, &tx, ipst.entries()).unwrap();
    assert_eq!(facts.lots, 1);
    assert!(facts.tranche);
    let t = w.terms.terms();
    for (i, l) in facts.legs.iter().enumerate() {
        assert_eq!(l.leg, i);
        assert_eq!(l.settled, t.unit(i));
        assert_eq!(l.spent, w.funded[i].vault.outpoint);
        assert_eq!(l.covenant, w.funded[i].vault.entry.covenant_id);
        assert_eq!(l.continuation, l.covenant);
    }
    // The final settle has no continuation.
    let fin = w.settle().unwrap();
    let facts = read_settle(&w.terms, &scripted(&fin), fin.entries()).unwrap();
    assert_eq!((facts.lots, facts.tranche), (4, false));
    assert!(facts.legs.iter().all(|l| l.continuation.is_none()));
    assert_eq!(facts.legs[2].settled, BIG);
    // Refusals: a refund, other terms, a continuation of another covenant, a short entry list.
    let refund = w.refund(2, RefundSignerV2::Depositor(2), false).unwrap();
    assert_eq!(
        code(read_settle(&w.terms, &scripted(&refund), refund.entries())),
        "IPST_TERMS_MISMATCH"
    );
    let other = lots_world(4, 2);
    assert!(read_settle(&other.terms, &tx, ipst.entries()).is_err());
    let mut wrong = ipst.entries().to_vec();
    wrong[1].covenant_id = Some(Hash::from_bytes([9; 32]));
    assert_eq!(code(read_settle(&w.terms, &tx, &wrong)), "TX_LINEAGE");
    assert_eq!(
        code(read_settle(&w.terms, &tx, &ipst.entries()[..2])),
        "IPST_TERMS_MISMATCH"
    );
    // Different lots in two vault inputs.
    let mut mixed = tx.clone();
    mixed.inputs[1].signature_script = scripted(&tranche_of(&w, 2).unwrap()).inputs[1]
        .signature_script
        .clone();
    assert_eq!(
        code(read_settle(&w.terms, &mixed, ipst.entries())),
        "IPST_TERMS_MISMATCH"
    );
}

#[test]
fn quantities_state_settled_cumulative_and_total() {
    let w = lots_world(4, 1);
    let (cum, legs) = quantities(&w.terms, 1, 0).unwrap();
    assert_eq!(cum, 1);
    assert_eq!(
        legs[0],
        LegQuantity {
            leg: 0,
            settled: 250,
            cumulative: 250,
            total: 1_000
        }
    );
    let (cum, legs) = quantities(&w.terms, 3, 1).unwrap();
    assert_eq!(cum, 4);
    assert_eq!(
        (legs[2].settled, legs[2].cumulative, legs[2].total),
        (BIG / 4 * 3, BIG, BIG)
    );
    assert_eq!(code(quantities(&w.terms, 1, 4)), "TX_TRANCHE");
    assert_eq!(code(quantities(&w.terms, u64::MAX, 1)), "TX_TRANCHE");
    // Terms without partial: one lot, the whole amount.
    let plain = world(with_kas3(NS, true));
    let (cum, legs) = quantities(&plain.terms, 1, 0).unwrap();
    assert_eq!((cum, legs[0].settled, legs[0].total), (1, 1_000, 1_000));
}

#[test]
fn settle_lots_reads_only_the_settle_entry() {
    let w = lots_world(4, 1);
    let t = tranche_of(&w, 3).unwrap();
    for i in 0..3 {
        assert_eq!(
            receipt::settle_lots(&t.slots()[i].script_with(&[0; 65])),
            Some(3)
        );
    }
    let r = w.refund(2, RefundSignerV2::Depositor(2), false).unwrap();
    assert_eq!(
        receipt::settle_lots(&r.slots()[0].script_with(&[0; 65])),
        None
    );
    assert_eq!(receipt::settle_lots(&[]), None);
    assert_eq!(receipt::settle_lots(&[0x51]), None);
}

#[test]
fn the_settle_tag_is_the_artifact() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/compiled/impulse_vault.v2.json"
    ))
    .unwrap();
    let tag = artifact["contracts"]["ImpulseVaultV2"]["entries"]["settle"]["dispatch_tag"]
        .as_str()
        .unwrap();
    assert_eq!(tag, hex(&SETTLE_TAG_V2));
}
