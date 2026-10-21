// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms unit tests: layout, hash, and one accepting control plus one refusal per check.

use super::golden::{
    authority, buyer, hex, label32, owner, p2pk, p2pk_ecdsa, p2sh, seller, vectors, CREATION_DAA,
};
use super::*;
use kaspa_consensus_core::constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI};

/// A key that is not a valid x-only point: x must be below the field prime.
const OFF_CURVE: [u8; 32] = [0xff; 32];

/// Golden vector by number (1-based), with the context it validates under.
fn vector(n: usize) -> (Terms, CreationContext) {
    let t = vectors().remove(n - 1).terms;
    let ctx = CreationContext::new(t.network, CREATION_DAA);
    (t, ctx)
}

/// Both validation stages, as a creator runs them.
fn check(t: &Terms, ctx: &CreationContext) -> Result<(), TermsError> {
    t.clone().validate_structure()?.validate_creation(ctx)
}

fn refused(t: &Terms, ctx: &CreationContext) -> &'static str {
    check(t, ctx).expect_err("validation must refuse").code()
}

fn decode_code(bytes: &[u8]) -> &'static str {
    Terms::decode(bytes).expect_err("decode must refuse").code()
}

fn token() -> Kcc20Token {
    match vector(1).0.asset_leg.kind {
        LegKind::Kcc20(t) => t,
        _ => unreachable!("vector 1 has a KCC-20 asset"),
    }
}

fn token_mut(leg: &mut Leg) -> &mut Kcc20Token {
    match &mut leg.kind {
        LegKind::Kcc20(t) => t,
        _ => unreachable!("a KCC-20 leg"),
    }
}

// Error codes.

#[test]
fn error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; this list may only grow at the end.
    assert_eq!(
        TERMS_ERROR_CODES,
        [
            "TERMS_TRUNCATED",
            "TERMS_TRAILING_BYTES",
            "TERMS_INVALID_TAG",
            "TERMS_INVALID_PRESENCE",
            "TERMS_UNKNOWN_SETTLEMENT_MODE",
            "TERMS_FIELD_TOO_LONG",
            "TERMS_UNSUPPORTED_VERSION",
            "TERMS_INVALID_KEY",
            "TERMS_PARTIES_NOT_DISTINCT",
            "TERMS_ASSET_EXTERNAL",
            "TERMS_ASSET_KIND_UNSUPPORTED",
            "TERMS_EXTERNAL_WITHOUT_AUTHORITY",
            "TERMS_DIRECT_INCOMPATIBLE",
            "TERMS_AMOUNT_ZERO",
            "TERMS_AMOUNT_OUT_OF_RANGE",
            "TERMS_ZERO_IDENTIFIER",
            "TERMS_TEMPLATE_LENGTH",
            "TERMS_DESTINATION_KIND",
            "TERMS_NONSTANDARD_SCRIPT",
            "TERMS_EXPIRY_NOT_DAA",
            "TERMS_EARLIEST_NOT_DAA",
            "TERMS_EARLIEST_ZERO",
            "TERMS_EARLIEST_AFTER_EXPIRY",
            "TERMS_NETWORK_MISMATCH",
            "TERMS_EXPIRY_NOT_AFTER_CREATION",
            "TERMS_EXPIRY_BEYOND_HORIZON",
            "TERMS_AUTHORITY_IS_PARTY",
            "TERMS_SAME_COVENANT",
        ]
    );
    let mut sorted = TERMS_ERROR_CODES.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), TERMS_ERROR_CODES.len(), "codes are unique");
}

#[test]
fn every_variant_maps_to_its_listed_code() {
    let f = "field";
    let all = [
        TermsError::Truncated { field: f },
        TermsError::TrailingBytes { count: 1 },
        TermsError::InvalidTag { field: f, value: 9 },
        TermsError::InvalidPresence { field: f, value: 2 },
        TermsError::UnknownSettlementMode { value: 2 },
        TermsError::FieldTooLong { field: f, len: 1 },
        TermsError::UnsupportedVersion { version: 2 },
        TermsError::InvalidKey { field: f },
        TermsError::PartiesNotDistinct { field: f },
        TermsError::AssetExternal,
        TermsError::AssetKindUnsupported,
        TermsError::ExternalWithoutAuthority,
        TermsError::DirectIncompatible { field: f },
        TermsError::AmountZero { field: f },
        TermsError::AmountOutOfRange {
            field: f,
            amount: 2,
            max: 1,
        },
        TermsError::ZeroIdentifier { field: f },
        TermsError::TemplateLength {
            field: f,
            prefix_len: 0,
            suffix_len: 1,
        },
        TermsError::DestinationKind { field: f },
        TermsError::NonStandardScript { field: f },
        TermsError::ExpiryNotDaa { expiry_daa: 1 },
        TermsError::EarliestNotDaa { earliest_daa: 1 },
        TermsError::EarliestZero,
        TermsError::EarliestAfterExpiry {
            earliest_daa: 2,
            expiry_daa: 1,
        },
        TermsError::NetworkMismatch {
            expected: Network::Mainnet,
            found: Network::Testnet,
        },
        TermsError::ExpiryNotAfterCreation {
            expiry_daa: 1,
            creation_daa: 1,
        },
        TermsError::ExpiryBeyondHorizon {
            expiry_daa: 2,
            max_expiry_daa: 1,
        },
        TermsError::AuthorityIsParty { party: f },
        TermsError::SameCovenant,
    ];
    let codes: Vec<&str> = all.iter().map(TermsError::code).collect();
    assert_eq!(codes, TERMS_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()));
    }
}

#[test]
fn display_leads_with_the_code() {
    let err = TermsError::AmountZero {
        field: "asset_leg.amount",
    };
    assert_eq!(
        err.to_string(),
        "TERMS_AMOUNT_ZERO: asset_leg.amount is zero"
    );
}

// Hash.

#[test]
fn terms_hash_is_keyed_blake2b_256() {
    // Known answers from Python hashlib, an independent implementation:
    // hashlib.blake2b(m, digest_size=32, key=b"Impulse/terms/v1").hexdigest()
    assert_eq!(
        hex(&hash_canonical(b"")),
        "5d7790670ef4684cf722b07a37bfd3cf139175af62d4a34126327d713d895141"
    );
    assert_eq!(
        hex(&hash_canonical(b"abc")),
        "b5afc4eb7af8dde5dc9187962d434012b7c0559089e5502099ed3b59944a9dd9"
    );
    let (t, _) = vector(1);
    assert_eq!(
        t.terms_hash().unwrap(),
        hash_canonical(&t.encode().unwrap())
    );
}

// Layout.

#[test]
fn layout_fixed_order_little_endian() {
    let (mut t, _) = vector(2);
    t.nonce = 0x0807_0605_0403_0201;
    let b = t.encode().unwrap();
    assert_eq!(b[0], TERMS_VERSION);
    assert_eq!(b[1], 0, "mainnet");
    assert_eq!(b[2], 1, "vault");
    assert_eq!(&b[3..11], &[1, 2, 3, 4, 5, 6, 7, 8], "nonce little-endian");
    assert_eq!(&b[11..43], &t.seller_key);
    assert_eq!(&b[43..75], &t.buyer_key);
    assert_eq!(b[75], 1, "authority present");
    assert_eq!(&b[76..108], &authority());
    assert_eq!(b[108], 1, "asset leg KCC-20");
    let tok = token();
    assert_eq!(&b[109..141], &tok.covenant_id);
    assert_eq!(&b[141..173], &tok.template_hash);
    assert_eq!(&b[173..177], &40u32.to_le_bytes());
    assert_eq!(&b[177..181], &1_420u32.to_le_bytes());
    assert_eq!(&b[181..189], &500u64.to_le_bytes());
    assert_eq!(b[189], 0, "cash leg KAS");
    assert_eq!(&b[190..198], &2_500_000_000_000u64.to_le_bytes());
    // buyer_delivery: KCC-20 owner, SCRIPT_HASH.
    assert_eq!(&b[198..200], &[1, 1]);
    // seller_proceeds: KAS, version 0, 34-byte P2PK script.
    let at = 200 + 32;
    assert_eq!(b[at], 0);
    assert_eq!(&b[at + 1..at + 3], &[0, 0]);
    assert_eq!(&b[at + 3..at + 7], &34u32.to_le_bytes());
    // Tail: earliest absent, expiry, revocable, trade_ref.
    let n = b.len();
    assert_eq!(&b[n - 32..], &t.trade_ref);
    assert_eq!(b[n - 33], 0, "revocable");
    assert_eq!(&b[n - 41..n - 33], &t.expiry_daa.to_le_bytes());
    assert_eq!(b[n - 42], 0, "earliest absent");
    // Direct is 0x00 in the same position.
    t.settlement_mode = SettlementMode::Direct;
    assert_eq!(t.encode().unwrap()[2], 0, "direct");
}

#[test]
fn optional_absent_and_present_zero_differ() {
    // The encoding tells absent from present-and-zero; validation then refuses present-and-zero
    // (TERMS_EARLIEST_ZERO), so one rule has one spelling.
    let (mut t, _) = vector(7);
    t.earliest_daa = None;
    let absent = t.encode().unwrap();
    t.earliest_daa = Some(0);
    let zero = t.encode().unwrap();
    assert_eq!(zero.len(), absent.len() + 8);
    assert_ne!(
        Terms::decode(&absent).unwrap(),
        Terms::decode(&zero).unwrap()
    );
}

// Decoding refusals.

#[test]
fn decode_refuses_empty_and_truncated() {
    assert_eq!(decode_code(&[]), "TERMS_TRUNCATED");
    let b = vector(1).0.encode().unwrap();
    assert_eq!(decode_code(&b[..b.len() - 1]), "TERMS_TRUNCATED");
}

#[test]
fn decode_refuses_trailing_bytes() {
    let mut b = vector(1).0.encode().unwrap();
    b.push(0);
    assert_eq!(
        Terms::decode(&b),
        Err(TermsError::TrailingBytes { count: 1 })
    );
}

#[test]
fn version_other_than_1_refused_everywhere() {
    let (mut t, ctx) = vector(1);
    let mut b = t.encode().unwrap();
    b[0] = 2;
    assert_eq!(
        Terms::decode(&b),
        Err(TermsError::UnsupportedVersion { version: 2 })
    );
    b[0] = 0;
    assert_eq!(decode_code(&b), "TERMS_UNSUPPORTED_VERSION");
    t.version = 2;
    assert_eq!(t.encode().unwrap_err().code(), "TERMS_UNSUPPORTED_VERSION");
    assert_eq!(
        t.terms_hash().unwrap_err().code(),
        "TERMS_UNSUPPORTED_VERSION"
    );
    assert_eq!(refused(&t, &ctx), "TERMS_UNSUPPORTED_VERSION");
}

/// Overwrites one byte of a valid encoding and expects the given refusal for that field.
fn tag_refused(n: usize, offset: impl Fn(&[u8]) -> usize, value: u8, field: &str, code: &str) {
    let mut b = vector(n).0.encode().unwrap();
    let at = offset(&b);
    b[at] = value;
    let err = Terms::decode(&b).expect_err("refused");
    assert_eq!(err.code(), code, "{field}");
    match err {
        TermsError::InvalidTag { field: f, value: v }
        | TermsError::InvalidPresence { field: f, value: v } => {
            assert_eq!((f, v), (field, value))
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_refuses_unknown_tags() {
    tag_refused(1, |_| 1, 2, "network", "TERMS_INVALID_TAG");
    // Vector 1: authority present, so the asset leg kind sits at 108.
    tag_refused(1, |_| 108, 3, "asset_leg", "TERMS_INVALID_TAG");
    // Vector 1: asset KCC-20 leg is 1 + 32 + 32 + 4 + 4 + 8 = 81 bytes, so cash kind at 189.
    tag_refused(1, |_| 189, 9, "cash_leg", "TERMS_INVALID_TAG");
    // Vector 1: cash KCC-20 leg ends at 270; buyer_delivery kind, then identifier type.
    tag_refused(1, |_| 270, 3, "buyer_delivery", "TERMS_INVALID_TAG");
    tag_refused(1, |_| 271, 3, "buyer_delivery", "TERMS_INVALID_TAG");
    tag_refused(1, |b| b.len() - 33, 2, "funding_mode", "TERMS_INVALID_TAG");
}

#[test]
fn decode_refuses_unknown_settlement_mode() {
    let mut b = vector(1).0.encode().unwrap();
    for value in [2u8, 0xff] {
        b[2] = value;
        assert_eq!(
            Terms::decode(&b),
            Err(TermsError::UnknownSettlementMode { value })
        );
        assert_eq!(decode_code(&b), "TERMS_UNKNOWN_SETTLEMENT_MODE");
    }
}

#[test]
fn decode_refuses_bad_presence_bytes() {
    tag_refused(1, |_| 75, 2, "authority_key", "TERMS_INVALID_PRESENCE");
    // Vector 1 tail: earliest present (1 + 8), expiry 8, funding 1, trade_ref 32.
    tag_refused(
        1,
        |b| b.len() - 50,
        0xff,
        "earliest_daa",
        "TERMS_INVALID_PRESENCE",
    );
}

#[test]
fn script_length_bound_is_exact() {
    let (mut t, _) = vector(2);
    t.seller_proceeds = Destination::Kas(ScriptPublicKey::from_vec(0, vec![0x51; MAX_SCRIPT_LEN]));
    let b = t.encode().expect("MAX_SCRIPT_LEN encodes");
    assert_eq!(Terms::decode(&b).unwrap(), t);

    t.seller_proceeds =
        Destination::Kas(ScriptPublicKey::from_vec(0, vec![0x51; MAX_SCRIPT_LEN + 1]));
    assert_eq!(
        t.encode(),
        Err(TermsError::FieldTooLong {
            field: "seller_proceeds",
            len: MAX_SCRIPT_LEN + 1
        })
    );

    // A length prefix above the bound is refused before any truncation check.
    let (t, _) = vector(2);
    let mut b = t.encode().unwrap();
    let len_at = 200 + 32 + 3;
    b[len_at..len_at + 4].copy_from_slice(&((MAX_SCRIPT_LEN as u32) + 1).to_le_bytes());
    assert_eq!(decode_code(&b), "TERMS_FIELD_TOO_LONG");
    b[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_code(&b), "TERMS_FIELD_TOO_LONG");
}

// Validation: accepting controls.

#[test]
fn every_golden_vector_validates() {
    for v in vectors() {
        let ctx = CreationContext::new(v.terms.network, CREATION_DAA);
        assert_eq!(check(&v.terms, &ctx), Ok(()), "{}", v.name);
    }
}

// Validation: one refusal per check, each beside the control it differs from.

#[test]
fn network_must_match() {
    let (t, _) = vector(1);
    let ctx = CreationContext::new(Network::Testnet, CREATION_DAA);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::NetworkMismatch {
            expected: Network::Testnet,
            found: Network::Mainnet
        })
    );
    let (t, ctx) = vector(8);
    assert_eq!(t.network, Network::Testnet);
    assert_eq!(check(&t, &ctx), Ok(()));
    assert_eq!(
        refused(&t, &CreationContext::new(Network::Mainnet, CREATION_DAA)),
        "TERMS_NETWORK_MISMATCH"
    );
}

#[test]
fn party_keys_must_be_valid_xonly_points() {
    let (base, ctx) = vector(1);
    let mut t = base.clone();
    t.seller_key = OFF_CURVE;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey {
            field: "seller_key"
        })
    );
    let mut t = base.clone();
    t.buyer_key = OFF_CURVE;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey { field: "buyer_key" })
    );
    let mut t = base;
    t.authority_key = Some(OFF_CURVE);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey {
            field: "authority_key"
        })
    );
}

#[test]
fn parties_must_be_distinct() {
    let (base, ctx) = vector(1);
    let mut t = base.clone();
    t.buyer_key = seller();
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::PartiesNotDistinct { field: "buyer_key" })
    );
}

#[test]
fn authority_must_not_be_a_party() {
    // Control: vector 1 has an authority distinct from both parties.
    let (base, ctx) = vector(1);
    assert_eq!(check(&base, &ctx), Ok(()));
    for (same, party) in [(seller(), "seller_key"), (buyer(), "buyer_key")] {
        let mut t = base.clone();
        t.authority_key = Some(same);
        assert_eq!(check(&t, &ctx), Err(TermsError::AuthorityIsParty { party }));
        assert_eq!(refused(&t, &ctx), "TERMS_AUTHORITY_IS_PARTY");
    }
}

#[test]
fn buyer_cannot_be_the_authority_of_an_external_cash_trade() {
    // The case the I2 and I3 reviews named: a buyer-proposed external-cash trade naming the buyer
    // as authority would let the buyer release the asset without paying.
    let (base, ctx) = vector(5);
    assert_eq!(base.cash_leg.kind, LegKind::External);
    assert_eq!(check(&base, &ctx), Ok(()));
    let mut t = base;
    t.authority_key = Some(t.buyer_key);
    assert_eq!(refused(&t, &ctx), "TERMS_AUTHORITY_IS_PARTY");
}

#[test]
fn legs_must_be_different_tokens() {
    // Control: vector 1 trades two KCC-20 tokens with different covenant IDs.
    let (base, ctx) = vector(1);
    assert_eq!(check(&base, &ctx), Ok(()));
    let mut t = base.clone();
    let asset = token();
    token_mut(&mut t.cash_leg).covenant_id = asset.covenant_id;
    assert_eq!(check(&t, &ctx), Err(TermsError::SameCovenant));
    // Same template, other covenant: two tokens, accepted (the vectors' tokens share a template).
    let mut t = base.clone();
    token_mut(&mut t.cash_leg).template_hash = asset.template_hash;
    assert_eq!(check(&t, &ctx), Ok(()));
    // Direct mode too: one token for itself is no trade.
    let (base, ctx) = vector(7);
    let mut t = base.clone();
    assert_eq!(check(&t, &ctx), Ok(()));
    token_mut(&mut t.cash_leg).covenant_id = asset.covenant_id;
    assert_eq!(refused(&t, &ctx), "TERMS_SAME_COVENANT");
}

#[test]
fn asset_leg_cannot_be_external() {
    let (mut t, ctx) = vector(5);
    t.asset_leg.kind = LegKind::External;
    assert_eq!(check(&t, &ctx), Err(TermsError::AssetExternal));
}

#[test]
fn v1_asset_leg_must_be_kcc20() {
    // Vector 2 sells a KCC-20 token for KAS. The same trade the other way round, KAS as the
    // asset, is refused in v1 (D13); swapping buyer and seller expresses it instead.
    let (t, ctx) = vector(2);
    assert_eq!(check(&t, &ctx), Ok(()));
    let mut kas_asset = t.clone();
    kas_asset.asset_leg = t.cash_leg;
    kas_asset.cash_leg = t.asset_leg;
    kas_asset.buyer_delivery = p2pk(&buyer());
    kas_asset.seller_proceeds = owner(IdentifierType::PubKey, seller());
    kas_asset.seller_refund = p2pk(&seller());
    kas_asset.buyer_refund = owner(IdentifierType::PubKey, buyer());
    assert_eq!(
        check(&kas_asset, &ctx),
        Err(TermsError::AssetKindUnsupported)
    );
    // The KAS kind stays in the encoding for later versions: such terms still decode and hash.
    let bytes = kas_asset.encode().unwrap();
    assert_eq!(Terms::decode(&bytes).unwrap(), kas_asset);
    assert!(kas_asset.terms_hash().is_ok());
    // KAS against external cash has no v1 form at all.
    let (mut t, ctx) = vector(5);
    t.asset_leg = Leg {
        kind: LegKind::Kas,
        amount: 100_000_000,
    };
    assert_eq!(refused(&t, &ctx), "TERMS_ASSET_KIND_UNSUPPORTED");
}

#[test]
fn external_cash_needs_an_authority() {
    let (mut t, ctx) = vector(5);
    assert_eq!(check(&t, &ctx), Ok(()));
    t.authority_key = None;
    assert_eq!(check(&t, &ctx), Err(TermsError::ExternalWithoutAuthority));
}

#[test]
fn amounts_must_be_positive() {
    let (base, ctx) = vector(1);
    let mut t = base.clone();
    t.asset_leg.amount = 0;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::AmountZero {
            field: "asset_leg.amount"
        })
    );
    let mut t = base;
    t.cash_leg.amount = 0;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::AmountZero {
            field: "cash_leg.amount"
        })
    );
    // External amounts too.
    let (mut t, ctx) = vector(6);
    t.cash_leg.amount = 0;
    assert_eq!(refused(&t, &ctx), "TERMS_AMOUNT_ZERO");
}

#[test]
fn amounts_have_an_upper_bound_per_kind() {
    // Vector 9 sits at both maxima (KCC-20 asset at i64::MAX, KAS cash at MAX_SOMPI) and
    // validates.
    let (base, ctx) = vector(9);
    let mut t = base.clone();
    t.cash_leg.amount = MAX_SOMPI + 1;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::AmountOutOfRange {
            field: "cash_leg.amount",
            amount: MAX_SOMPI + 1,
            max: MAX_SOMPI
        })
    );
    let mut t = base;
    t.asset_leg.amount = i64::MAX as u64 + 1;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::AmountOutOfRange {
            field: "asset_leg.amount",
            amount: i64::MAX as u64 + 1,
            max: i64::MAX as u64
        })
    );
    let (mut t, ctx) = vector(6);
    t.cash_leg.amount = i64::MAX as u64;
    assert_eq!(check(&t, &ctx), Ok(()));
    t.cash_leg.amount = u64::MAX;
    assert_eq!(refused(&t, &ctx), "TERMS_AMOUNT_OUT_OF_RANGE");
}

#[test]
fn kcc20_identifiers_must_not_be_zero() {
    let (base, ctx) = vector(1);
    let mut t = base.clone();
    if let LegKind::Kcc20(tok) = &mut t.asset_leg.kind {
        tok.covenant_id = [0; 32];
    }
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ZeroIdentifier {
            field: "asset_leg.covenant_id"
        })
    );
    let mut t = base.clone();
    if let LegKind::Kcc20(tok) = &mut t.cash_leg.kind {
        tok.template_hash = [0; 32];
    }
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ZeroIdentifier {
            field: "cash_leg.template_hash"
        })
    );
    let mut t = base;
    t.buyer_delivery = owner(IdentifierType::ScriptHash, [0; 32]);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ZeroIdentifier {
            field: "buyer_delivery"
        })
    );
    // A P2SH destination with a zero script hash is refused the same way.
    let (mut t, ctx) = vector(4);
    t.seller_proceeds = p2sh(&[0; 32]);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ZeroIdentifier {
            field: "seller_proceeds"
        })
    );
}

fn slot<'a>(t: &'a mut Terms, field: &str) -> &'a mut Destination {
    match field {
        "buyer_delivery" => &mut t.buyer_delivery,
        "seller_proceeds" => &mut t.seller_proceeds,
        "seller_refund" => &mut t.seller_refund,
        "buyer_refund" => &mut t.buyer_refund,
        _ => unreachable!("not a destination: {field}"),
    }
}

#[test]
fn destination_kind_must_match_leg_kind() {
    let kas_dest = p2pk(&buyer());
    let kcc_dest = owner(IdentifierType::PubKey, buyer());
    // Vector 1: KCC-20 both legs. Vector 4: KAS cash. Vector 5: external cash.
    let cases = [
        (1, "buyer_delivery", kas_dest.clone()),
        (1, "seller_proceeds", kas_dest.clone()),
        (1, "seller_refund", Destination::OffChain),
        (1, "buyer_refund", kas_dest.clone()),
        (4, "seller_proceeds", kcc_dest.clone()),
        (4, "buyer_refund", Destination::OffChain),
        (5, "seller_proceeds", kcc_dest),
        (5, "buyer_refund", kas_dest),
    ];
    for (n, field, wrong) in cases {
        let (mut t, ctx) = vector(n);
        *slot(&mut t, field) = wrong;
        let err = check(&t, &ctx).expect_err("refused");
        assert_eq!(err.code(), "TERMS_DESTINATION_KIND", "vector {n} {field}");
        assert_eq!(
            err,
            TermsError::DestinationKind {
                field: slot_name(field)
            }
        );
    }
}

fn slot_name(field: &str) -> &'static str {
    [
        "buyer_delivery",
        "seller_proceeds",
        "seller_refund",
        "buyer_refund",
    ]
    .into_iter()
    .find(|f| *f == field)
    .expect("destination field")
}

#[test]
fn kas_destinations_must_be_standard() {
    let (base, ctx) = vector(2);
    let good = match &base.seller_proceeds {
        Destination::Kas(spk) => spk.script().to_vec(),
        _ => unreachable!("vector 2 pays KAS to a P2PK"),
    };
    let bad: Vec<ScriptPublicKey> = vec![
        ScriptPublicKey::from_vec(1, good.clone()), // version 1
        ScriptPublicKey::from_vec(0, vec![]),       // empty
        ScriptPublicKey::from_vec(0, good[..33].to_vec()), // truncated P2PK
        ScriptPublicKey::from_vec(0, vec![0x51]),   // OP_TRUE: anyone can spend
    ];
    for spk in bad {
        let mut t = base.clone();
        t.seller_proceeds = Destination::Kas(spk);
        assert_eq!(
            check(&t, &ctx),
            Err(TermsError::NonStandardScript {
                field: "seller_proceeds"
            })
        );
    }
}

#[test]
fn keys_inside_destinations_must_be_valid() {
    let (base, ctx) = vector(2);
    // P2PK with an off-curve key.
    let mut t = base.clone();
    t.seller_proceeds = p2pk(&OFF_CURVE);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey {
            field: "seller_proceeds"
        })
    );
    // P2PK-ECDSA with an off-curve key.
    let mut t = base.clone();
    t.buyer_refund = p2pk_ecdsa(&OFF_CURVE);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey {
            field: "buyer_refund"
        })
    );
    // KCC-20 PUBKEY owner with an off-curve key; the same bytes as SCRIPT_HASH are fine.
    let mut t = base;
    t.seller_refund = owner(IdentifierType::PubKey, OFF_CURVE);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::InvalidKey {
            field: "seller_refund"
        })
    );
    t.seller_refund = owner(IdentifierType::ScriptHash, OFF_CURVE);
    assert_eq!(check(&t, &ctx), Ok(()));
}

#[test]
fn expiry_must_lie_after_creation() {
    let (mut t, ctx) = vector(1);
    t.earliest_daa = None;
    t.expiry_daa = CREATION_DAA + 1;
    assert_eq!(check(&t, &ctx), Ok(()));
    t.expiry_daa = CREATION_DAA;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ExpiryNotAfterCreation {
            expiry_daa: CREATION_DAA,
            creation_daa: CREATION_DAA
        })
    );
}

#[test]
fn expiry_within_the_horizon() {
    let (mut t, ctx) = vector(1);
    let max = CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA;
    t.expiry_daa = max;
    assert_eq!(check(&t, &ctx), Ok(()));
    t.expiry_daa = max + 1;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ExpiryBeyondHorizon {
            expiry_daa: max + 1,
            max_expiry_daa: max
        })
    );
    // The horizon is a parameter.
    let short = CreationContext {
        max_expiry_horizon_daa: 10,
        ..ctx
    };
    t.expiry_daa = CREATION_DAA + 10;
    t.earliest_daa = None;
    assert_eq!(check(&t, &short), Ok(()));
    t.expiry_daa = CREATION_DAA + 11;
    assert_eq!(refused(&t, &short), "TERMS_EXPIRY_BEYOND_HORIZON");
}

#[test]
fn expiry_must_be_a_daa_score_lock_time() {
    let (mut t, _) = vector(1);
    t.earliest_daa = None;
    // A context wide enough that only the lock-time domain can refuse.
    let ctx = CreationContext {
        network: Network::Mainnet,
        creation_daa: 0,
        max_expiry_horizon_daa: u64::MAX,
    };
    t.expiry_daa = LOCK_TIME_THRESHOLD - 1;
    assert_eq!(check(&t, &ctx), Ok(()));
    t.expiry_daa = LOCK_TIME_THRESHOLD;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::ExpiryNotDaa {
            expiry_daa: LOCK_TIME_THRESHOLD
        })
    );
}

#[test]
fn earliest_must_be_a_daa_score_lock_time() {
    let (mut t, _) = vector(1);
    let ctx = CreationContext {
        network: Network::Mainnet,
        creation_daa: 0,
        max_expiry_horizon_daa: u64::MAX,
    };
    t.expiry_daa = LOCK_TIME_THRESHOLD - 1;
    t.earliest_daa = Some(LOCK_TIME_THRESHOLD - 1);
    assert_eq!(check(&t, &ctx), Ok(()));
    // At the threshold earliest_daa would read as a timestamp; refused for that, not ordering.
    t.earliest_daa = Some(LOCK_TIME_THRESHOLD);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::EarliestNotDaa {
            earliest_daa: LOCK_TIME_THRESHOLD
        })
    );
    t.earliest_daa = Some(u64::MAX);
    assert_eq!(refused(&t, &ctx), "TERMS_EARLIEST_NOT_DAA");
}

#[test]
fn earliest_present_means_nonzero() {
    let (mut t, ctx) = vector(1);
    t.earliest_daa = Some(1);
    assert_eq!(check(&t, &ctx), Ok(()));
    t.earliest_daa = None;
    assert_eq!(check(&t, &ctx), Ok(()));
    t.earliest_daa = Some(0);
    assert_eq!(check(&t, &ctx), Err(TermsError::EarliestZero));
}

#[test]
fn earliest_not_after_expiry() {
    let (mut t, ctx) = vector(1);
    t.earliest_daa = Some(t.expiry_daa);
    assert_eq!(check(&t, &ctx), Ok(()));
    t.earliest_daa = Some(t.expiry_daa + 1);
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::EarliestAfterExpiry {
            earliest_daa: t.expiry_daa + 1,
            expiry_daa: t.expiry_daa
        })
    );
}

#[test]
fn vector_labels_are_public_derivations() {
    // Party keys come from public labels, so no private key exists in this repository.
    assert_eq!(label32("x"), label32("x"));
    assert_ne!(seller(), buyer());
    assert_ne!(buyer(), authority());
}

// Direct mode.

#[test]
fn direct_refuses_external_cash_and_earmarked_funding() {
    // Controls: both Direct vectors validate.
    for n in [7, 11] {
        let (t, ctx) = vector(n);
        assert_eq!(t.settlement_mode, SettlementMode::Direct);
        assert_eq!(check(&t, &ctx), Ok(()), "vector {n}");
    }
    let (mut t, ctx) = vector(7);
    t.funding_mode = FundingMode::Earmarked;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::DirectIncompatible {
            field: "funding_mode"
        })
    );
    t.settlement_mode = SettlementMode::Vault;
    assert_eq!(check(&t, &ctx), Ok(()), "earmarked is a vault funding mode");

    let (mut t, ctx) = vector(5);
    assert_eq!(check(&t, &ctx), Ok(()), "external cash settles in a vault");
    t.settlement_mode = SettlementMode::Direct;
    assert_eq!(
        check(&t, &ctx),
        Err(TermsError::DirectIncompatible { field: "cash_leg" })
    );
}

// KCC-20 template lengths.

#[test]
fn template_lengths_in_range() {
    let max = MAX_TEMPLATE_LEN as u32;
    assert_eq!(max, 1_000_000);
    let cases = [
        (1, 1, true),
        (40, 1_420, true),
        (1, max - 1, true),
        (0, 1_420, false),
        (40, 0, false),
        (1, max, false),
        (u32::MAX, u32::MAX, false),
    ];
    for (prefix_len, suffix_len, ok) in cases {
        for (leg, field) in [
            ("asset", "asset_leg.template"),
            ("cash", "cash_leg.template"),
        ] {
            let (mut t, ctx) = vector(1);
            let tok = token_mut(if leg == "asset" {
                &mut t.asset_leg
            } else {
                &mut t.cash_leg
            });
            tok.template_prefix_len = prefix_len;
            tok.template_suffix_len = suffix_len;
            let expected = if ok {
                Ok(())
            } else {
                Err(TermsError::TemplateLength {
                    field,
                    prefix_len,
                    suffix_len,
                })
            };
            assert_eq!(check(&t, &ctx), expected, "{leg} {prefix_len}/{suffix_len}");
        }
    }
}

// Structure versus creation.

#[test]
fn expired_trade_passes_the_structure_check() {
    let (t, _) = vector(1);
    let long_after = CreationContext::new(Network::Mainnet, t.expiry_daa + 10 * 864_000);
    let checked = t
        .clone()
        .validate_structure()
        .expect("structure checks are time-independent");
    assert_eq!(
        checked.validate_creation(&long_after),
        Err(TermsError::ExpiryNotAfterCreation {
            expiry_daa: t.expiry_daa,
            creation_daa: long_after.creation_daa
        })
    );
    // Wrong network is a creation check too; the structure still holds.
    assert!(ValidatedTerms::decode(&t.encode().unwrap()).is_ok());
}

#[test]
fn validated_terms_carry_their_bytes_and_hash() {
    let (t, ctx) = vector(1);
    let bytes = t.encode().unwrap();
    let v = ValidatedTerms::decode(&bytes).unwrap();
    assert_eq!(v.terms(), &t);
    assert_eq!(v.canonical(), bytes.as_slice());
    assert_eq!(v.terms_hash(), t.terms_hash().unwrap());
    assert_eq!(v.validate_creation(&ctx), Ok(()));
    assert_eq!(v.clone().into_terms(), t);
    assert_eq!(t.clone().validate_structure().unwrap(), v);
    // Bytes that decode but fail the structure checks never become ValidatedTerms.
    let mut bad = t;
    bad.asset_leg.amount = 0;
    assert_eq!(
        ValidatedTerms::decode(&bad.encode().unwrap()),
        Err(TermsError::AmountZero {
            field: "asset_leg.amount"
        })
    );
}

// Check order, table driven.

type Fault = fn(&mut Terms, &mut CreationContext);

struct Row {
    code: &'static str,
    fault: Fault,
    /// Sets the same field as the previous row, so no terms value carries both faults.
    exclusive_with_previous: bool,
}

macro_rules! row {
    ($code:literal, |$t:ident| $body:expr) => {
        Row {
            code: $code,
            fault: |$t: &mut Terms, _: &mut CreationContext| {
                $body;
            },
            exclusive_with_previous: false,
        }
    };
    ($code:literal, context, |$c:ident| $body:expr) => {
        Row {
            code: $code,
            fault: |_: &mut Terms, $c: &mut CreationContext| {
                $body;
            },
            exclusive_with_previous: false,
        }
    };
}

/// One fault per check, in the order spec/ENCODING.md gives, applied to vector 2 (KCC-20 asset,
/// KAS cash, authority, vault, revocable, no earliest_daa).
fn order_rows() -> Vec<Row> {
    let mut rows = vec![
        row!("TERMS_UNSUPPORTED_VERSION", |t| t.version = 2),
        row!("TERMS_INVALID_KEY", |t| t.seller_key = OFF_CURVE),
        row!("TERMS_INVALID_KEY", |t| t.buyer_key = OFF_CURVE),
        row!("TERMS_INVALID_KEY", |t| t.authority_key = Some(OFF_CURVE)),
        row!("TERMS_PARTIES_NOT_DISTINCT", |t| t.buyer_key = t.seller_key),
        row!("TERMS_AUTHORITY_IS_PARTY", |t| t.authority_key =
            Some(t.seller_key)),
        row!("TERMS_ASSET_EXTERNAL", |t| t.asset_leg.kind =
            LegKind::External),
        row!("TERMS_ASSET_KIND_UNSUPPORTED", |t| t.asset_leg.kind =
            LegKind::Kas),
        row!("TERMS_EXTERNAL_WITHOUT_AUTHORITY", |t| {
            t.cash_leg.kind = LegKind::External;
            t.authority_key = None
        }),
        row!("TERMS_DIRECT_INCOMPATIBLE", |t| {
            t.settlement_mode = SettlementMode::Direct;
            t.cash_leg.kind = LegKind::External
        }),
        row!("TERMS_DIRECT_INCOMPATIBLE", |t| {
            t.settlement_mode = SettlementMode::Direct;
            t.funding_mode = FundingMode::Earmarked
        }),
        row!("TERMS_AMOUNT_ZERO", |t| t.asset_leg.amount = 0),
        row!("TERMS_ZERO_IDENTIFIER", |t| token_mut(&mut t.asset_leg)
            .covenant_id = [0; 32]),
        row!("TERMS_ZERO_IDENTIFIER", |t| token_mut(&mut t.asset_leg)
            .template_hash = [0; 32]),
        row!("TERMS_TEMPLATE_LENGTH", |t| token_mut(&mut t.asset_leg)
            .template_prefix_len = 0),
        row!("TERMS_AMOUNT_OUT_OF_RANGE", |t| t.cash_leg.amount =
            MAX_SOMPI + 1),
        row!("TERMS_SAME_COVENANT", |t| t.cash_leg.kind =
            t.asset_leg.kind),
        row!("TERMS_ZERO_IDENTIFIER", |t| t.buyer_delivery =
            owner(IdentifierType::ScriptHash, [0; 32])),
        row!("TERMS_NONSTANDARD_SCRIPT", |t| t.seller_proceeds =
            Destination::Kas(ScriptPublicKey::from_vec(0, vec![0x51]))),
        row!("TERMS_INVALID_KEY", |t| t.seller_refund =
            owner(IdentifierType::PubKey, OFF_CURVE)),
        row!("TERMS_DESTINATION_KIND", |t| t.buyer_refund =
            Destination::OffChain),
        row!("TERMS_EXPIRY_NOT_DAA", |t| t.expiry_daa =
            LOCK_TIME_THRESHOLD),
        row!("TERMS_EARLIEST_NOT_DAA", |t| t.earliest_daa =
            Some(LOCK_TIME_THRESHOLD)),
        row!("TERMS_EARLIEST_ZERO", |t| t.earliest_daa = Some(0)),
        row!("TERMS_EARLIEST_AFTER_EXPIRY", |t| t.earliest_daa =
            Some(t.expiry_daa + 1)),
        row!("TERMS_NETWORK_MISMATCH", context, |c| c.network =
            Network::Testnet),
        row!("TERMS_EXPIRY_NOT_AFTER_CREATION", context, |c| c
            .creation_daa =
            450_000_000),
        row!("TERMS_EXPIRY_BEYOND_HORIZON", context, |c| c
            .max_expiry_horizon_daa =
            1),
    ];
    // Rows that set the same field as the row before: asset_leg.kind (external, KAS), the cash
    // leg (amount above the KAS cap, then KCC-20 of the asset's token, where that amount is in
    // range) and earliest_daa (timestamp domain, zero, after expiry). No terms value carries
    // both faults of such a pair.
    for r in rows.iter_mut() {
        if matches!(
            r.code,
            "TERMS_ASSET_KIND_UNSUPPORTED"
                | "TERMS_SAME_COVENANT"
                | "TERMS_EARLIEST_ZERO"
                | "TERMS_EARLIEST_AFTER_EXPIRY"
        ) {
            r.exclusive_with_previous = true;
        }
    }
    rows
}

fn apply(rows: &[&Row]) -> (Terms, CreationContext) {
    let (mut t, mut ctx) = vector(2);
    for r in rows {
        (r.fault)(&mut t, &mut ctx);
    }
    (t, ctx)
}

#[test]
fn validation_order_two_faults_per_adjacent_pair() {
    let rows = order_rows();
    assert_eq!(rows.len(), 28);
    for r in &rows {
        let (t, ctx) = apply(&[r]);
        assert_eq!(refused(&t, &ctx), r.code, "single fault for {}", r.code);
    }
    for (i, pair) in rows.windows(2).enumerate() {
        let (first, second) = (&pair[0], &pair[1]);
        let (t1, c1) = apply(&[first]);
        let e1 = check(&t1, &c1).unwrap_err();
        let (t2, c2) = apply(&[second]);
        let e2 = check(&t2, &c2).unwrap_err();
        assert_ne!(e1, e2, "rows {i} and {} report the same refusal", i + 1);
        if second.exclusive_with_previous {
            continue;
        }
        // The later fault goes in first, so the earlier one wins any field they share.
        let (t, c) = apply(&[second, first]);
        assert!(
            (&t, &c) != (&t1, &c1),
            "rows {i} and {}: the second fault left no trace",
            i + 1
        );
        assert_eq!(check(&t, &c), Err(e1), "rows {i} and {}", i + 1);
    }
}

#[test]
fn invalid_terms_round_trip_and_hash() {
    // Decoding and hashing do not depend on validity: a verifier hashes what it is given.
    let (base, _) = vector(2);
    let base_hash = base.terms_hash().unwrap();
    for r in order_rows() {
        let (t, ctx) = apply(&[&r]);
        assert_eq!(refused(&t, &ctx), r.code);
        if t.version != TERMS_VERSION {
            assert_eq!(t.encode().unwrap_err().code(), "TERMS_UNSUPPORTED_VERSION");
            continue;
        }
        let bytes = t.encode().unwrap();
        let back = Terms::decode(&bytes).expect("invalid terms still decode");
        assert_eq!(back, t, "{}", r.code);
        assert_eq!(back.encode().unwrap(), bytes);
        let hash = t.terms_hash().unwrap();
        assert_eq!(back.terms_hash().unwrap(), hash);
        if t == base {
            // A creation-context fault leaves the terms, and so the hash, unchanged.
            assert_eq!(hash, base_hash);
        } else {
            assert_ne!(hash, base_hash, "{}", r.code);
        }
    }
}
