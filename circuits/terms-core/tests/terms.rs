// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Terms v4: known answers of the two hashes (spec/V3-ZK.md 22.2, measured with Python
//! `hashlib.blake2b`), the codec, and the structure checks with their codes.

mod common;
use common::*;
use terms_core::codec::*;
use terms_core::hashes::*;
use terms_core::structure::validate;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn known_answers() {
    assert_eq!(
        hex(&blake2b256_keyed(TERMS_KEY, b"")),
        "51c6e19b097e437b72bcee41372f358236d44511430de2fba6ba50ac62ee9893"
    );
    assert_eq!(
        hex(&blake2b256_keyed(TERMS_KEY, b"abc")),
        "b80e077a53e2bcf5ec633915e22bbb94525fb06ec5fe97853c6d2166d8d03ad5"
    );
    assert_eq!(
        hex(&commit(&[0; 32], 0)),
        "41aad3a9e889815bb8e7387397971eacfcbb5a59c119f5a19127e0b0e24e6cf7"
    );
    assert_eq!(
        hex(&commit(&[0; 32], 1)),
        "4b36a373a9e9b321e72777e8902560aeca913c7b86d2768251c7a197e719376e"
    );
}

#[test]
fn the_two_legs_commit_differently() {
    let t = terms(Cash::Kas, false).encode();
    let h = terms_hash(&t);
    assert_ne!(commit(&h, 0), commit(&h, 1));
}

#[test]
fn codec_round_trips_every_cash_kind() {
    for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
        for earmarked in [false, true] {
            let t = terms(cash, earmarked);
            let b = t.encode();
            assert_eq!(Terms::decode(&b).unwrap(), t);
            assert_eq!(Terms::decode(&b).unwrap().encode(), b);
            validate(&t, true).unwrap();
        }
    }
    let mut t = terms(Cash::Kas, false);
    t.earliest = None;
    assert_eq!(Terms::decode(&t.encode()).unwrap(), t);
}

#[test]
fn decode_refuses_with_the_codes() {
    let good = terms(Cash::Kcc20, false).encode();
    let code = |b: &[u8]| Terms::decode(b).unwrap_err().code;
    assert_eq!(code(&[]), "TERMS_TRUNCATED");
    let mut b = good.clone();
    b[0] = 1;
    assert_eq!(code(&b), "ZK_H_TERMS_VERSION", "a v1 file is not a v4 file");
    let mut b = good.clone();
    b[0] = 5;
    assert_eq!(code(&b), "ZK_H_TERMS_VERSION");
    let mut b = good.clone();
    b[1] = 2;
    assert_eq!(code(&b), "TERMS_INVALID_TAG");
    let mut b = good.clone();
    b[2] = 2;
    assert_eq!(code(&b), "TERMS_UNKNOWN_SETTLEMENT_MODE");
    assert_eq!(code(&good[..good.len() - 1]), "TERMS_TRUNCATED");
    assert_eq!(
        code(&[good.clone(), vec![0]].concat()),
        "TERMS_TRAILING_BYTES"
    );
    // the authority presence byte sits at offset 3 + 8 + 32 + 32 = 75
    let mut b = good.clone();
    b[75] = 2;
    assert_eq!(code(&b), "TERMS_INVALID_PRESENCE");
    // an unknown leg kind follows the authority key: offset 75 + 33
    let mut b = good.clone();
    b[108] = 3;
    assert_eq!(code(&b), "TERMS_INVALID_TAG");
    // a KAS destination script longer than 10,000 bytes is refused before it is read
    let mut t = terms(Cash::Kas, false);
    t.seller_proceeds = Dest::Kas {
        version: 0,
        script: vec![0; 10_001],
    };
    assert_eq!(code(&t.encode()), "TERMS_FIELD_TOO_LONG");
}

fn code_of(t: &Terms) -> &'static str {
    match validate(t, true) {
        Ok(()) => "ok",
        Err(r) => {
            assert_eq!(r.tag, "H2");
            r.code
        }
    }
}

fn with(cash: Cash, f: impl FnOnce(&mut Terms)) -> &'static str {
    let mut t = terms(cash, false);
    f(&mut t);
    code_of(&t)
}

#[test]
fn structure_refusals_by_code() {
    use Cash::*;
    assert_eq!(with(Kas, |t| t.seller = [0xFF; 32]), "TERMS_INVALID_KEY"); // not a point
    assert_eq!(with(Kas, |t| t.buyer = [0xFF; 32]), "TERMS_INVALID_KEY");
    assert_eq!(
        with(Kas, |t| t.authority = Some([0xFF; 32])),
        "TERMS_INVALID_KEY"
    );
    assert_eq!(
        with(Kas, |t| t.buyer = t.seller),
        "TERMS_PARTIES_NOT_DISTINCT"
    );
    assert_eq!(
        with(Kas, |t| t.authority = Some(t.seller)),
        "TERMS_AUTHORITY_IS_PARTY"
    );
    assert_eq!(
        with(Kas, |t| t.authority = Some(t.buyer)),
        "TERMS_AUTHORITY_IS_PARTY"
    );
    assert_eq!(
        with(Kas, |t| t.asset = Leg::External { amount: 1 }),
        "TERMS_ASSET_EXTERNAL"
    );
    assert_eq!(
        with(Kas, |t| t.asset = Leg::Kas { amount: 1 }),
        "TERMS_ASSET_KIND_UNSUPPORTED"
    );
    assert_eq!(
        with(External, |t| t.authority = None),
        "TERMS_EXTERNAL_WITHOUT_AUTHORITY"
    );
    assert_eq!(
        with(External, |t| t.mode = MODE_DIRECT),
        "TERMS_DIRECT_INCOMPATIBLE"
    );
    assert_eq!(
        with(Kas, |t| {
            t.mode = MODE_DIRECT;
            t.funding = FUNDING_EARMARKED
        }),
        "TERMS_DIRECT_INCOMPATIBLE"
    );
    assert_eq!(
        with(Kas, |t| t.cash = Leg::Kas { amount: 0 }),
        "TERMS_AMOUNT_ZERO"
    );
    assert_eq!(
        with(Kas, |t| t.cash = Leg::Kas {
            amount: 2_900_000_000_000_000_001
        }),
        "TERMS_AMOUNT_OUT_OF_RANGE"
    );
    assert_eq!(
        with(Kcc20, |t| if let Leg::Kcc20 { amount, .. } = &mut t.cash {
            *amount = i64::MAX as u64 + 1
        }),
        "TERMS_AMOUNT_OUT_OF_RANGE"
    );
    assert_eq!(
        with(Kcc20, |t| if let Leg::Kcc20 { cov, .. } = &mut t.cash {
            *cov = [0; 32]
        }),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        with(Kcc20, |t| {
            if let Leg::Kcc20 { template_hash, .. } = &mut t.cash {
                *template_hash = [0; 32]
            }
        }),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        with(Kcc20, |t| {
            if let Leg::Kcc20 { prefix_len, .. } = &mut t.cash {
                *prefix_len = 0
            }
        }),
        "TERMS_TEMPLATE_LENGTH"
    );
    assert_eq!(
        with(Kcc20, |t| {
            if let Leg::Kcc20 { suffix_len, .. } = &mut t.cash {
                *suffix_len = 1_000_000
            }
        }),
        "TERMS_TEMPLATE_LENGTH"
    );
    assert_eq!(
        with(Kcc20, |t| t.cash = t.asset.clone()),
        "TERMS_SAME_COVENANT"
    );
    assert_eq!(
        with(Kas, |t| t.buyer_delivery = Dest::OffChain),
        "TERMS_DESTINATION_KIND"
    );
    assert_eq!(
        with(Kas, |t| t.seller_proceeds = Dest::Owner {
            id_type: 0,
            id: [1; 32]
        }),
        "TERMS_DESTINATION_KIND"
    );
    assert_eq!(
        with(Kas, |t| t.seller_proceeds = Dest::Kas {
            version: 1,
            script: vec![0xaa, 0x20]
        }),
        "TERMS_NONSTANDARD_SCRIPT"
    );
    assert_eq!(
        with(Kas, |t| t.seller_proceeds = Dest::Kas {
            version: 0,
            script: vec![0x51]
        }),
        "TERMS_NONSTANDARD_SCRIPT"
    );
    assert_eq!(
        with(Kas, |t| t.buyer_refund = Dest::Kas {
            version: 0,
            script: [vec![0x20], vec![0xFF; 32], vec![0xac]].concat()
        }),
        "TERMS_INVALID_KEY"
    );
    assert_eq!(
        with(Kas, |t| t.buyer_refund = Dest::Kas {
            version: 0,
            script: [vec![0x21, 0x05], vec![0; 32], vec![0xab]].concat()
        }),
        "TERMS_INVALID_KEY"
    );
    assert_eq!(
        with(Kas, |t| t.buyer_refund = Dest::Kas {
            version: 0,
            script: [vec![0xaa, 0x20], vec![0; 32], vec![0x87]].concat()
        }),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        with(Kcc20, |t| t.buyer_delivery = Dest::Owner {
            id_type: 1,
            id: [0; 32]
        }),
        "TERMS_ZERO_IDENTIFIER"
    );
    assert_eq!(
        with(Kcc20, |t| t.buyer_delivery = Dest::Owner {
            id_type: 0,
            id: [0xFF; 32]
        }),
        "TERMS_INVALID_KEY"
    );
    // a script-hash owner needs no curve point
    assert_eq!(
        with(Kcc20, |t| t.buyer_delivery = Dest::Owner {
            id_type: 1,
            id: [0xFF; 32]
        }),
        "ok"
    );
    assert_eq!(
        with(Kas, |t| t.expiry = 500_000_000_000),
        "TERMS_EXPIRY_NOT_DAA"
    );
    assert_eq!(
        with(Kas, |t| t.earliest = Some(500_000_000_000)),
        "TERMS_EARLIEST_NOT_DAA"
    );
    assert_eq!(with(Kas, |t| t.earliest = Some(0)), "TERMS_EARLIEST_ZERO");
    assert_eq!(
        with(Kas, |t| t.earliest = Some(t.expiry + 1)),
        "TERMS_EARLIEST_AFTER_EXPIRY"
    );
}

#[test]
fn structure_refusals_of_v4() {
    assert_eq!(
        with(Cash::Kas, |t| t.mode = MODE_DIRECT),
        "ZK_H_TERMS_DIRECT"
    );
    assert_eq!(
        with(Cash::Kas, |t| t.authority = None),
        "ZK_H_AUTHORITY_REQUIRED"
    );
    assert_eq!(with(Cash::Kas, |t| t.blind = [0; 32]), "ZK_H_BLIND_INVALID");
}

#[test]
fn guest_refuses_h2_unvalid_terms_in_the_statement() {
    let mut sc = settle(Cash::Kas, 0);
    sc.terms.blind = [0; 32];
    sc.recommit();
    let r = sc.run().unwrap_err();
    assert_eq!((r.code, r.tag), ("ZK_H_BLIND_INVALID", "H2"));
    let mut sc = settle(Cash::Kas, 0);
    sc.terms.mode = MODE_DIRECT;
    sc.recommit();
    assert_eq!(sc.run().unwrap_err().tag, "H2");
}

#[test]
fn the_curve_check_is_skippable_only_by_option() {
    let mut t = terms(Cash::Kas, false);
    t.buyer_delivery = Dest::Owner {
        id_type: 0,
        id: [0xFF; 32],
    };
    t.asset = terms(Cash::Kas, false).asset;
    assert_eq!(validate(&t, true).unwrap_err().code, "TERMS_INVALID_KEY");
    validate(&t, false).unwrap();
}
