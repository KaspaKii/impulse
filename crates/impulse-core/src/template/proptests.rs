// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Property tests on instantiation and decoding. Terms are drawn over the whole valid vault
//! domain (every cash kind, destination form, optional field and range), not only the vectors.

use super::state::{Kind, LAYOUT};
use super::*;
use crate::terms::golden::xonly;
use crate::terms::{Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg};
use kaspa_consensus_core::constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI};
use kaspa_txscript::opcodes::codes::{
    OpBlake2b, OpCheckSig, OpCheckSigECDSA, OpData32, OpData33, OpEqual,
};
use proptest::prelude::*;
use silverscript_abi::ArtifactValue;

const CASES: u32 = 10_000;

fn config() -> ProptestConfig {
    ProptestConfig::with_cases(CASES)
}

/// Valid x-only keys, derived from public labels (nobody holds their private keys).
fn keys() -> Vec<[u8; 32]> {
    (0..6)
        .map(|n| xonly(&format!("impulse/proptest/key/{n}")))
        .collect()
}

fn nonzero32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("nonzero", |b| b.iter().any(|x| *x != 0))
}

fn token() -> impl Strategy<Value = Kcc20Token> {
    (nonzero32(), nonzero32(), 1u32..=500_000, 1u32..=500_000).prop_map(
        |(covenant_id, template_hash, prefix, suffix)| Kcc20Token {
            covenant_id,
            template_hash,
            template_prefix_len: prefix,
            template_suffix_len: suffix,
        },
    )
}

fn kcc20_owner() -> impl Strategy<Value = Destination> {
    let key = prop::sample::select(keys());
    prop_oneof![
        key.prop_map(|identifier| (IdentifierType::PubKey, identifier)),
        nonzero32().prop_map(|identifier| (IdentifierType::ScriptHash, identifier)),
        nonzero32().prop_map(|identifier| (IdentifierType::CovenantId, identifier)),
    ]
    .prop_map(|(identifier_type, identifier)| {
        Destination::Kcc20(Kcc20Owner {
            identifier_type,
            identifier,
        })
    })
}

fn kas_destination() -> impl Strategy<Value = Destination> {
    let key = prop::sample::select(keys());
    prop_oneof![
        key.clone()
            .prop_map(|k| [&[OpData32][..], &k, &[OpCheckSig]].concat()),
        // 0x02 and a valid x-coordinate: a valid compressed key.
        key.prop_map(|k| [&[OpData33, 0x02][..], &k, &[OpCheckSigECDSA]].concat()),
        nonzero32().prop_map(|h| [&[OpBlake2b, OpData32][..], &h, &[OpEqual]].concat()),
    ]
    .prop_map(|script| Destination::Kas(ScriptPublicKey::from_vec(0, script)))
}

/// (cash leg, seller_proceeds, buyer_refund) for each cash kind.
fn cash() -> impl Strategy<Value = (Leg, Destination, Destination)> {
    let kas = (1..=MAX_SOMPI, kas_destination(), kas_destination()).prop_map(|(amount, p, r)| {
        let kind = LegKind::Kas;
        (Leg { kind, amount }, p, r)
    });
    let kcc20 = (token(), 1..=i64::MAX as u64, kcc20_owner(), kcc20_owner()).prop_map(
        |(t, amount, p, r)| {
            let kind = LegKind::Kcc20(t);
            (Leg { kind, amount }, p, r)
        },
    );
    let external = (1..=i64::MAX as u64).prop_map(|amount| {
        let kind = LegKind::External;
        let off = Destination::OffChain;
        (Leg { kind, amount }, off.clone(), off)
    });
    prop_oneof![kas, kcc20, external]
}

type Parties = (Network, u64, Vec<[u8; 32]>, bool);
type Legs = (Kcc20Token, u64, (Leg, Destination, Destination));
type Timing = ((u64, Option<u64>, FundingMode), [u8; 32]);

fn build(
    (network, nonce, parties, has_authority): Parties,
    (asset, amount_a, (cash_leg, seller_proceeds, buyer_refund)): Legs,
    (buyer_delivery, seller_refund): (Destination, Destination),
    ((expiry_daa, earliest_daa, funding_mode), trade_ref): Timing,
) -> Option<ValidatedTerms> {
    let external = cash_leg.kind == LegKind::External;
    if let LegKind::Kcc20(c) = &cash_leg.kind {
        if c.covenant_id == asset.covenant_id {
            return None;
        }
    }
    let t = Terms {
        version: crate::terms::TERMS_VERSION,
        network,
        settlement_mode: SettlementMode::Vault,
        nonce,
        seller_key: parties[0],
        buyer_key: parties[1],
        authority_key: (has_authority || external).then_some(parties[2]),
        asset_leg: Leg {
            kind: LegKind::Kcc20(asset),
            amount: amount_a,
        },
        cash_leg,
        buyer_delivery,
        seller_proceeds,
        seller_refund,
        buyer_refund,
        earliest_daa,
        expiry_daa,
        funding_mode,
        trade_ref,
    };
    Some(t.validate_structure().expect("generated terms are valid"))
}

/// Any vault terms that pass the structure checks and have distinct leg tokens.
fn vault_terms() -> impl Strategy<Value = ValidatedTerms> {
    let parties = prop::sample::subsequence(keys(), 3).prop_shuffle();
    let timing = (1..LOCK_TIME_THRESHOLD).prop_flat_map(|expiry| {
        (
            Just(expiry),
            prop::option::of(1..=expiry),
            prop_oneof![Just(FundingMode::Revocable), Just(FundingMode::Earmarked)],
        )
    });
    (
        (
            prop_oneof![Just(Network::Mainnet), Just(Network::Testnet)],
            any::<u64>(),
            parties,
            any::<bool>(),
        ),
        (token(), 1..=i64::MAX as u64, cash()),
        (kcc20_owner(), kcc20_owner()),
        (timing, any::<[u8; 32]>()),
    )
        .prop_filter_map("distinct leg tokens", |(p, l, d, t)| build(p, l, d, t))
}

/// Measures, rather than assumes, that `config()` runs 10,000 cases.
#[test]
fn properties_run_10000_cases() {
    let mut runner = proptest::test_runner::TestRunner::new(config());
    let count = std::cell::Cell::new(0u32);
    runner
        .run(&vault_terms(), |_| {
            count.set(count.get() + 1);
            Ok(())
        })
        .expect("counting run");
    assert_eq!(count.get(), CASES);
}

/// The data of each push in a canonical state (every field is at most 75 bytes long).
fn canonical_pushes(state: &[u8]) -> Vec<Vec<u8>> {
    let (mut out, mut i) = (Vec::new(), 0);
    while i < state.len() {
        let len = state[i] as usize;
        assert!(len <= 75, "OP_0 or OpDataN");
        out.push(state[i + 1..i + 1 + len].to_vec());
        i += 1 + len;
    }
    out
}

/// The push opcode the encoder writes for `data`: OP_0 when empty, OpDataN otherwise.
fn canonical_push(data: &[u8]) -> [u8; 1] {
    [data.len() as u8]
}

/// A value of the field's type, biased to the defined values and the edges, so edits reach
/// every outcome: other valid terms, values outside the terms, terms refusals, non-canonical
/// states.
fn typed_value(kind: Kind) -> BoxedStrategy<ArtifactValue> {
    let threshold = LOCK_TIME_THRESHOLD as i64;
    match kind {
        Kind::Byte => prop_oneof![0u8..=3, any::<u8>()]
            .prop_map(ArtifactValue::Byte)
            .boxed(),
        Kind::Bool => any::<bool>().prop_map(ArtifactValue::Bool).boxed(),
        Kind::Int => prop_oneof![-2i64..=3, 1..threshold, Just(threshold), any::<i64>()]
            .prop_map(ArtifactValue::Int)
            .boxed(),
        Kind::Pubkey | Kind::Fixed(32) => prop_oneof![
            Just([0u8; 32]),
            prop::sample::select(keys()),
            any::<[u8; 32]>()
        ]
        .prop_map(|b| ArtifactValue::Bytes(b.to_vec()))
        .boxed(),
        Kind::Fixed(n) => prop::collection::vec(any::<u8>(), n)
            .prop_map(ArtifactValue::Bytes)
            .boxed(),
        Kind::Bytes => prop_oneof![
            Just(vec![]),
            kas_destination().prop_map(|d| match d {
                Destination::Kas(spk) => [&spk.version().to_be_bytes()[..], spk.script()].concat(),
                _ => unreachable!("a KAS destination"),
            }),
            prop::collection::vec(any::<u8>(), 0..40)
        ]
        .prop_map(ArtifactValue::Bytes)
        .boxed(),
    }
}

/// One state field and a new value of its type.
fn field_edit() -> impl Strategy<Value = (usize, ArtifactValue)> {
    (0..LAYOUT.len()).prop_flat_map(|i| (Just(i), typed_value(LAYOUT[i].1)))
}

/// What decoding made of an edited script.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    /// The edit wrote the value already there.
    Unchanged,
    /// Other terms (or the other leg), whose instantiation is exactly the edited script.
    OtherTerms,
    Refused(&'static str),
}

/// Re-encodes `terms`' asset vault with one field replaced, decodes it, and checks the result.
fn edit_and_decode(
    terms: &ValidatedTerms,
    field: usize,
    value: ArtifactValue,
) -> Result<Outcome, TestCaseError> {
    let t = check().unwrap();
    let vault = Vault::instantiate_existing(terms, LegIndex::Asset).unwrap();
    let span = t.state_span(vault.redeem_script()).unwrap();
    let mut values = decode_runtime_state_script(&t.abi, t.runtime_state(), span).unwrap();
    let name = LAYOUT[field].0;
    let unchanged = values[name] == value;
    values.insert(name.to_string(), value);
    let state = encode_runtime_state_script(&t.abi, t.runtime_state(), &values).unwrap();
    let script = [t.prefix(), &state, t.suffix()].concat();
    match decode(&script) {
        Ok((decoded, leg)) => {
            let again = Vault::instantiate_existing(&decoded, leg).unwrap();
            prop_assert_eq!(again.redeem_script(), &script[..]);
            prop_assert_eq!(unchanged, decoded == *terms && leg == LegIndex::Asset);
            Ok(if unchanged {
                Outcome::Unchanged
            } else {
                Outcome::OtherTerms
            })
        }
        Err(e) => {
            prop_assert!(!unchanged, "the unedited script decodes");
            // The edit is typed, so the template matches and the state parses.
            prop_assert!(!matches!(
                e.code(),
                "TEMPLATE_NOT_IMPULSE_VAULT" | "TEMPLATE_STATE_MALFORMED"
            ));
            Ok(Outcome::Refused(e.code()))
        }
    }
}

/// Every typed single-field edit of a real vault decodes to terms whose instantiation is exactly
/// the edited script, or is refused past the parse. The outcomes are counted, so the property is
/// shown to reach each of them.
#[test]
fn field_edits_decode_only_canonically() {
    let mut runner = proptest::test_runner::TestRunner::new(config());
    let outcomes = std::cell::RefCell::new(std::collections::BTreeMap::new());
    runner
        .run(&(vault_terms(), field_edit()), |(terms, (field, value))| {
            let outcome = edit_and_decode(&terms, field, value)?;
            *outcomes.borrow_mut().entry(outcome).or_insert(0u32) += 1;
            Ok(())
        })
        .unwrap();
    let outcomes = outcomes.into_inner();
    let count = |o: Outcome| outcomes.get(&o).copied().unwrap_or(0);
    assert_eq!(outcomes.values().sum::<u32>(), CASES);
    assert!(count(Outcome::OtherTerms) > 0, "{outcomes:?}");
    for code in [
        "TEMPLATE_STATE_INVALID",
        "TEMPLATE_LEG_INDEX",
        "TEMPLATE_NONCANONICAL",
    ] {
        assert!(count(Outcome::Refused(code)) > 0, "{code}: {outcomes:?}");
    }
    let terms_refusals: u32 = outcomes
        .iter()
        .filter(|(o, _)| matches!(o, Outcome::Refused(c) if c.starts_with("TERMS_")))
        .map(|(_, n)| n)
        .sum();
    assert!(terms_refusals > 0, "{outcomes:?}");
}

proptest! {
    #![proptest_config(config())]

    /// terms -> script -> decode -> terms, for every leg that has a vault. Decoding is a
    /// function, so this also proves instantiation one to one: every term moves the script.
    #[test]
    fn instantiate_then_decode_is_identity(terms in vault_terms()) {
        for leg in LegIndex::ALL {
            match Vault::instantiate_existing(&terms, leg) {
                Ok(vault) => {
                    let (decoded, decoded_leg) = decode(vault.redeem_script()).unwrap();
                    prop_assert_eq!(&decoded, &terms);
                    prop_assert_eq!(decoded_leg, leg);
                    prop_assert_eq!(
                        template_hash_of_instance(vault.redeem_script()).unwrap(),
                        check().unwrap().hash()
                    );
                }
                Err(e) => {
                    prop_assert_eq!(leg, LegIndex::Cash);
                    prop_assert_eq!(&terms.terms().cash_leg.kind, &LegKind::External);
                    prop_assert_eq!(e.code(), "TEMPLATE_NO_VAULT");
                }
            }
        }
    }

    /// Any field of a real vault's state pushed in a non-minimal form (OpPushData1 instead of
    /// OP_0 or OpDataN) parses, and is refused as non-canonical.
    #[test]
    fn non_minimal_push_of_any_field_is_non_canonical(
        terms in vault_terms(),
        field in 0..LAYOUT.len(),
    ) {
        let t = check().unwrap();
        let vault = Vault::instantiate_existing(&terms, LegIndex::Asset).unwrap();
        let pushes = canonical_pushes(t.state_span(vault.redeem_script()).unwrap());
        prop_assert_eq!(pushes.len(), LAYOUT.len());
        let mut state = Vec::new();
        for (n, data) in pushes.iter().enumerate() {
            if n == field {
                state.extend_from_slice(&[0x4c, data.len() as u8]); // OpPushData1
            } else {
                state.extend_from_slice(&canonical_push(data));
            }
            state.extend_from_slice(data);
        }
        let script = [t.prefix(), &state, t.suffix()].concat();
        prop_assert_eq!(decode(&script), Err(TemplateError::NonCanonical));
    }

    /// Changing any one state byte of a real vault is refused, or yields other terms that
    /// instantiate to exactly the changed script.
    #[test]
    fn single_byte_changes_decode_only_canonically(
        terms in vault_terms(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let vault = Vault::instantiate_existing(&terms, LegIndex::Asset).unwrap();
        let t = check().unwrap();
        let mut script = vault.redeem_script().to_vec();
        let span = script.len() - t.prefix().len() - t.suffix().len();
        let i = t.prefix().len() + at.index(span);
        script[i] ^= xor;
        if let Ok((decoded, leg)) = decode(&script) {
            prop_assert!(decoded != terms || leg != LegIndex::Asset);
            let again = Vault::instantiate_existing(&decoded, leg).unwrap();
            prop_assert_eq!(again.redeem_script(), &script[..]);
        }
    }
}
