// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Property tests on the canonical encoding, 10,000 cases each. Terms are generated over the
//! whole structural domain (any bytes, any kinds, any lengths), not only valid trades.

use super::*;
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;

const CASES: u32 = 10_000;

/// The one configuration every property below runs under.
fn config() -> ProptestConfig {
    ProptestConfig::with_cases(CASES)
}

/// Measures, rather than assumes, that `config()` runs 10,000 cases.
#[test]
fn properties_run_10000_cases() {
    let mut runner = proptest::test_runner::TestRunner::new(config());
    let count = std::cell::Cell::new(0u32);
    runner
        .run(&arb_terms(), |_| {
            count.set(count.get() + 1);
            Ok(())
        })
        .expect("counting run");
    assert_eq!(count.get(), 10_000);
}

fn arb_token() -> impl Strategy<Value = Kcc20Token> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(covenant_id, template_hash, template_prefix_len, template_suffix_len)| Kcc20Token {
                covenant_id,
                template_hash,
                template_prefix_len,
                template_suffix_len,
            },
        )
}

fn arb_leg() -> impl Strategy<Value = Leg> {
    let kind = prop_oneof![
        Just(LegKind::Kas),
        arb_token().prop_map(LegKind::Kcc20),
        Just(LegKind::External),
    ];
    (kind, any::<u64>()).prop_map(|(kind, amount)| Leg { kind, amount })
}

fn arb_destination() -> impl Strategy<Value = Destination> {
    let id_type = prop_oneof![
        Just(IdentifierType::PubKey),
        Just(IdentifierType::ScriptHash),
        Just(IdentifierType::CovenantId),
    ];
    prop_oneof![
        (any::<u16>(), vec(any::<u8>(), 0..=40))
            .prop_map(|(v, s)| Destination::Kas(ScriptPublicKey::from_vec(v, s))),
        (id_type, any::<[u8; 32]>()).prop_map(|(identifier_type, identifier)| {
            Destination::Kcc20(Kcc20Owner {
                identifier_type,
                identifier,
            })
        }),
        Just(Destination::OffChain),
    ]
}

fn arb_terms() -> impl Strategy<Value = Terms> {
    let head = (
        prop_oneof![Just(Network::Mainnet), Just(Network::Testnet)],
        prop_oneof![Just(SettlementMode::Direct), Just(SettlementMode::Vault)],
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        option::of(any::<[u8; 32]>()),
        arb_leg(),
        arb_leg(),
    );
    let tail = (
        arb_destination(),
        arb_destination(),
        arb_destination(),
        arb_destination(),
        option::of(any::<u64>()),
        any::<u64>(),
        prop_oneof![Just(FundingMode::Revocable), Just(FundingMode::Earmarked)],
        any::<[u8; 32]>(),
    );
    (head, tail).prop_map(
        |(
            (
                network,
                settlement_mode,
                nonce,
                seller_key,
                buyer_key,
                authority_key,
                asset_leg,
                cash_leg,
            ),
            (
                buyer_delivery,
                seller_proceeds,
                seller_refund,
                buyer_refund,
                earliest_daa,
                expiry_daa,
                funding_mode,
                trade_ref,
            ),
        )| Terms {
            version: TERMS_VERSION,
            network,
            settlement_mode,
            nonce,
            seller_key,
            buyer_key,
            authority_key,
            asset_leg,
            cash_leg,
            buyer_delivery,
            seller_proceeds,
            seller_refund,
            buyer_refund,
            earliest_daa,
            expiry_daa,
            funding_mode,
            trade_ref,
        },
    )
}

/// Number of mutation sites `mutate` knows: every field, and every kind and content within.
const SITES: usize = 18;

/// Changes exactly one field of `t`. `salt` steers the change; `x` is a non-zero byte.
fn mutate(t: &Terms, site: usize, salt: u64, x: u8) -> Terms {
    let mut m = t.clone();
    let nz = salt | 1;
    let i = (salt as usize >> 8) % 32;
    match site {
        0 => {
            m.network = match m.network {
                Network::Mainnet => Network::Testnet,
                Network::Testnet => Network::Mainnet,
            }
        }
        1 => m.nonce ^= nz,
        2 => m.seller_key[i] ^= x,
        3 => m.buyer_key[i] ^= x,
        4 => {
            m.authority_key = match m.authority_key {
                None => Some([x; 32]),
                Some(_) if salt & 2 == 0 => None,
                Some(mut k) => {
                    k[i] ^= x;
                    Some(k)
                }
            }
        }
        5 => m.asset_leg.kind = next_leg_kind(&m.asset_leg.kind, x),
        6 => mutate_leg(&mut m.asset_leg, salt, x),
        7 => m.cash_leg.kind = next_leg_kind(&m.cash_leg.kind, x),
        8 => mutate_leg(&mut m.cash_leg, salt, x),
        9 => mutate_destination(&mut m.buyer_delivery, salt, x),
        10 => mutate_destination(&mut m.seller_proceeds, salt, x),
        11 => mutate_destination(&mut m.seller_refund, salt, x),
        12 => mutate_destination(&mut m.buyer_refund, salt, x),
        13 => {
            m.earliest_daa = match m.earliest_daa {
                None => Some(salt),
                Some(_) if salt & 2 == 0 => None,
                Some(d) => Some(d ^ nz),
            }
        }
        14 => m.expiry_daa ^= nz,
        15 => {
            m.funding_mode = match m.funding_mode {
                FundingMode::Revocable => FundingMode::Earmarked,
                FundingMode::Earmarked => FundingMode::Revocable,
            }
        }
        16 => m.trade_ref[i] ^= x,
        17 => {
            m.settlement_mode = match m.settlement_mode {
                SettlementMode::Direct => SettlementMode::Vault,
                SettlementMode::Vault => SettlementMode::Direct,
            }
        }
        _ => unreachable!("site out of range"),
    }
    m
}

fn next_leg_kind(kind: &LegKind, x: u8) -> LegKind {
    match kind {
        LegKind::Kas => LegKind::Kcc20(Kcc20Token {
            covenant_id: [x; 32],
            template_hash: [x; 32],
            template_prefix_len: x.into(),
            template_suffix_len: x.into(),
        }),
        LegKind::Kcc20(_) => LegKind::External,
        LegKind::External => LegKind::Kas,
    }
}

fn mutate_leg(leg: &mut Leg, salt: u64, x: u8) {
    let nz = salt | 1;
    let i = (salt as usize >> 8) % 32;
    match &mut leg.kind {
        LegKind::Kcc20(tok) => match salt % 5 {
            0 => tok.covenant_id[i] ^= x,
            1 => tok.template_hash[i] ^= x,
            2 => tok.template_prefix_len ^= nz as u32,
            3 => tok.template_suffix_len ^= nz as u32,
            _ => leg.amount ^= nz,
        },
        LegKind::Kas | LegKind::External => leg.amount ^= nz,
    }
}

fn mutate_destination(d: &mut Destination, salt: u64, x: u8) {
    let i = (salt as usize >> 8) % 32;
    if salt & 2 == 0 {
        *d = match d {
            Destination::Kas(_) => Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: [x; 32],
            }),
            Destination::Kcc20(_) => Destination::OffChain,
            Destination::OffChain => Destination::Kas(ScriptPublicKey::from_vec(0, vec![x])),
        };
        return;
    }
    match d {
        Destination::Kas(spk) => {
            let mut script = spk.script().to_vec();
            let mut version = spk.version();
            match (salt >> 2) % 3 {
                0 => version ^= (salt as u16) | 1,
                1 if !script.is_empty() => {
                    let at = i % script.len();
                    script[at] ^= x;
                }
                _ => script.push(x),
            }
            *spk = ScriptPublicKey::from_vec(version, script);
        }
        Destination::Kcc20(owner) => {
            if (salt >> 2) & 1 == 0 {
                owner.identifier[i] ^= x;
            } else {
                owner.identifier_type = match owner.identifier_type {
                    IdentifierType::PubKey => IdentifierType::ScriptHash,
                    IdentifierType::ScriptHash => IdentifierType::CovenantId,
                    IdentifierType::CovenantId => IdentifierType::PubKey,
                };
            }
        }
        Destination::OffChain => *d = Destination::Kas(ScriptPublicKey::from_vec(0, vec![])),
    }
}

proptest! {
    #![proptest_config(config())]

    /// decode(encode(t)) == t, and the bytes carry no slack: re-encoding gives them back.
    #[test]
    fn round_trip(t in arb_terms()) {
        let bytes = t.encode().expect("structural terms encode");
        let back = Terms::decode(&bytes).expect("own encoding decodes");
        prop_assert_eq!(&back, &t);
        prop_assert_eq!(back.encode().unwrap(), bytes);
    }

    /// The hash is a pure function of the terms: repeatable, equal through a round trip,
    /// and equal to keyed blake2b-256 of the canonical bytes.
    #[test]
    fn hash_stable(t in arb_terms()) {
        let h = t.terms_hash().unwrap();
        prop_assert_eq!(h, t.clone().terms_hash().unwrap());
        prop_assert_eq!(h, Terms::decode(&t.encode().unwrap()).unwrap().terms_hash().unwrap());
        prop_assert_eq!(h, hash_canonical(&t.encode().unwrap()));
    }

    /// Changing any one field changes the canonical bytes and the hash.
    #[test]
    fn any_field_change_changes_hash(
        t in arb_terms(),
        site in 0..SITES,
        salt in any::<u64>(),
        x in 1u8..=255,
    ) {
        let m = mutate(&t, site, salt, x);
        prop_assert_ne!(&m, &t, "mutation site {} changed nothing", site);
        prop_assert_ne!(m.encode().unwrap(), t.encode().unwrap());
        prop_assert_ne!(m.terms_hash().unwrap(), t.terms_hash().unwrap());
    }

    /// Every strict prefix of a valid encoding is refused as truncated.
    #[test]
    fn truncation_refused(t in arb_terms(), cut in any::<prop::sample::Index>()) {
        let bytes = t.encode().unwrap();
        let cut = cut.index(bytes.len());
        let err = Terms::decode(&bytes[..cut]).unwrap_err();
        prop_assert_eq!(err.code(), "TERMS_TRUNCATED");
    }

    /// Any bytes after a valid encoding are refused.
    #[test]
    fn trailing_bytes_refused(t in arb_terms(), extra in vec(any::<u8>(), 1..16)) {
        let mut bytes = t.encode().unwrap();
        bytes.extend_from_slice(&extra);
        prop_assert_eq!(
            Terms::decode(&bytes),
            Err(TermsError::TrailingBytes { count: extra.len() })
        );
    }

    /// One encoding per value: changing any byte of a valid encoding either is refused or
    /// decodes to different terms whose own encoding is exactly the changed bytes.
    #[test]
    fn byte_change_refused_or_canonical(
        t in arb_terms(),
        at in any::<prop::sample::Index>(),
        x in 1u8..=255,
    ) {
        let mut bytes = t.encode().unwrap();
        let at = at.index(bytes.len());
        bytes[at] ^= x;
        if let Ok(other) = Terms::decode(&bytes) {
            prop_assert_ne!(&other, &t);
            prop_assert_eq!(other.encode().unwrap(), bytes);
        }
    }

    /// Arbitrary input never panics, and anything accepted is in canonical form.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in vec(any::<u8>(), 0..600)) {
        if let Ok(t) = Terms::decode(&bytes) {
            prop_assert_eq!(t.encode().unwrap(), bytes);
        }
    }
}
