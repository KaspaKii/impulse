// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Template unit tests: the startup check, the round trip for every golden vector, and one
//! refusal per check, each beside an accepted control that differs only in the one fault.

use super::*;
use crate::terms::golden::{authority, label32, seller, vectors, CREATION_DAA};
use crate::terms::{
    Destination, IdentifierType, Kcc20Owner, Leg, TermsError, DEFAULT_MAX_EXPIRY_HORIZON_DAA,
};
use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;

/// Golden vector by number (1-based).
fn vector(n: usize) -> Terms {
    vectors().remove(n - 1).terms
}

/// Structure checks, then instantiation, as a caller holding plain terms runs them.
fn vault(t: &Terms, leg: LegIndex) -> Result<Vault, TemplateError> {
    Vault::instantiate_existing(&t.clone().validate_structure()?, leg)
}

fn script(t: &Terms, leg: LegIndex) -> Vec<u8> {
    vault(t, leg)
        .expect("control instantiates")
        .redeem_script()
        .to_vec()
}

fn code<T: std::fmt::Debug>(r: Result<T, TemplateError>) -> &'static str {
    r.expect_err("must be refused").code()
}

fn template() -> &'static Template {
    check().expect("embedded template passes the startup check")
}

fn splice(state: &[u8]) -> Vec<u8> {
    let t = template();
    [t.prefix(), state, t.suffix()].concat()
}

fn state_of(script: &[u8]) -> &[u8] {
    template()
        .state_span(script)
        .expect("an ImpulseVault script")
}

fn values_of(script: &[u8]) -> BTreeMap<String, ArtifactValue> {
    let t = template();
    decode_runtime_state_script(&t.abi, t.runtime_state(), state_of(script)).expect("state")
}

/// `script` with its state values changed by `edit`, re-encoded canonically.
fn edit_state(script: &[u8], edit: impl FnOnce(&mut BTreeMap<String, ArtifactValue>)) -> Vec<u8> {
    let t = template();
    let mut values = values_of(script);
    edit(&mut values);
    let state =
        encode_runtime_state_script(&t.abi, t.runtime_state(), &values).expect("re-encode state");
    splice(&state)
}

fn set(values: &mut BTreeMap<String, ArtifactValue>, field: &str, value: ArtifactValue) {
    assert!(values.contains_key(field), "{field} is a state field");
    values.insert(field.to_string(), value);
}

fn committed_template_hash() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/TEMPLATE_HASH");
    std::fs::read_to_string(path)
        .expect("read TEMPLATE_HASH")
        .trim()
        .to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Startup check.

#[test]
fn embedded_template_passes_the_startup_check() {
    let t = template();
    assert_eq!(hex(&t.hash()), committed_template_hash());
    // The split: 1 prefix byte, a 508-byte example state, 3,437 suffix bytes.
    assert_eq!((t.prefix().len(), t.suffix().len()), (1, 3_437));
    let compiled = &t.abi.contracts[CONTRACT_NAME].compiled;
    assert_eq!(compiled.template_hash, t.hash());
    assert_eq!(state_of(&compiled.bytecode).len(), 508);
    assert_eq!(
        [t.prefix(), state_of(&compiled.bytecode), t.suffix()].concat(),
        compiled.bytecode
    );
    assert_eq!(template_hash(t.prefix(), t.suffix()), t.hash());
}

fn artifact_value() -> serde_json::Value {
    serde_json::from_str(ARTIFACT_JSON).expect("artifact JSON")
}

fn load(artifact: &serde_json::Value, hash_file: &str) -> Result<Template, TemplateError> {
    Template::load(&artifact.to_string(), hash_file)
}

fn bytecode_mut(a: &mut serde_json::Value) -> &mut Vec<serde_json::Value> {
    a["contracts"][CONTRACT_NAME]["compiled"]["bytecode"]
        .as_array_mut()
        .expect("bytecode array")
}

#[test]
fn startup_check_refuses_a_tampered_artifact() {
    let good = artifact_value();
    assert!(load(&good, TEMPLATE_HASH_FILE).is_ok(), "control");
    assert_eq!(
        code(Template::load("not json", TEMPLATE_HASH_FILE)),
        "TEMPLATE_ARTIFACT_INVALID"
    );

    type Edit = fn(&mut serde_json::Value);
    let invalid: Vec<(&str, Edit)> = vec![
        ("schema version", |a| a["schema_version"] = 2.into()),
        ("contract renamed", |a| {
            let c = a["contracts"].as_object_mut().unwrap();
            let v = c.remove(CONTRACT_NAME).unwrap();
            c.insert("OtherVault".into(), v);
        }),
        ("second contract", |a| {
            let c = a["contracts"].as_object_mut().unwrap();
            let v = c[CONTRACT_NAME].clone();
            c.insert("ZVault".into(), v);
        }),
        ("state field renamed", |a| {
            a["contracts"][CONTRACT_NAME]["runtime_state"]["fields"][33]["name"] = "leg".into()
        }),
        ("state field retyped", |a| {
            a["contracts"][CONTRACT_NAME]["runtime_state"]["fields"][11]["type"] =
                serde_json::json!({"kind": "byte"})
        }),
        ("state field dropped", |a| {
            a["contracts"][CONTRACT_NAME]["runtime_state"]["fields"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        ("state span past the end", |a| {
            a["contracts"][CONTRACT_NAME]["compiled"]["state_span"]["offset"] = 1_000_000.into()
        }),
        ("example state not canonical", |a| {
            // The first state push (OpData1, the version) becomes OpData2: the template bytes and
            // hash are unchanged, but the example state no longer parses.
            bytecode_mut(a)[1] = 2.into()
        }),
    ];
    for (label, edit) in invalid {
        let mut a = good.clone();
        edit(&mut a);
        assert_eq!(
            code(load(&a, TEMPLATE_HASH_FILE)),
            "TEMPLATE_ARTIFACT_INVALID",
            "{label}"
        );
    }

    // A changed suffix byte no longer matches the artifact's declared hash.
    let mut a = good.clone();
    let last = bytecode_mut(&mut a).len() - 1;
    bytecode_mut(&mut a)[last] = 0x00.into();
    assert_eq!(code(load(&a, TEMPLATE_HASH_FILE)), "TEMPLATE_HASH_MISMATCH");

    // The same change with the declared hash updated to match is caught by TEMPLATE_HASH.
    let bytes: Vec<u8> = bytecode_mut(&mut a)
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let (p, s) = (template().prefix().len(), template().suffix().len());
    let rehashed = template_hash(&bytes[..p], &bytes[bytes.len() - s..]);
    a["contracts"][CONTRACT_NAME]["compiled"]["template_hash"] = rehashed.to_vec().into();
    assert_eq!(
        load(&a, TEMPLATE_HASH_FILE).expect_err("pinned hash"),
        TemplateError::HashMismatch {
            expected: template().hash(),
            found: rehashed
        }
    );

    // The pin itself: another hash, or not a hash.
    let other = format!("{}\n", hex(&[0x11; 32]));
    assert_eq!(code(load(&good, &other)), "TEMPLATE_HASH_MISMATCH");
    let pinned = committed_template_hash();
    for bad in [
        String::new(),
        "1877".to_string(),
        pinned.to_uppercase(),
        format!("{pinned}0"),
        format!(" {pinned}"),
    ] {
        assert_eq!(
            code(load(&good, &bad)),
            "TEMPLATE_ARTIFACT_INVALID",
            "{bad:?}"
        );
    }
    // With or without the final newline the pin reads.
    assert!(load(&good, &pinned).is_ok());
    assert!(load(&good, &format!("{pinned}\n")).is_ok());
}

#[test]
fn a_template_that_fails_the_check_makes_and_accepts_nothing() {
    let terms = vector(1).validate_structure().unwrap();
    let good_script = script(&vector(1), LegIndex::Asset);
    // Controls: the embedded template, through the same inner functions.
    let embedded: &Checked = &TEMPLATE;
    assert!(instantiate_with(embedded, &terms, LegIndex::Asset).is_ok());
    assert!(decode_with(embedded, &good_script).is_ok());
    assert!(template_hash_of_instance_with(embedded, &good_script).is_ok());

    let mut changed_suffix = artifact_value();
    let last = bytecode_mut(&mut changed_suffix).len() - 1;
    bytecode_mut(&mut changed_suffix)[last] = 0x00.into();
    for (label, bad) in [
        ("changed suffix", load(&changed_suffix, TEMPLATE_HASH_FILE)),
        ("not JSON", Template::load("{}", TEMPLATE_HASH_FILE)),
    ] {
        let refusal = bad.as_ref().expect_err(label).clone();
        assert_eq!(
            instantiate_with(&bad, &terms, LegIndex::Asset),
            Err(refusal.clone()),
            "{label}"
        );
        assert_eq!(
            decode_with(&bad, &good_script),
            Err(refusal.clone()),
            "{label}"
        );
        assert_eq!(
            template_hash_of_instance_with(&bad, &good_script),
            Err(refusal),
            "{label}"
        );
    }
}

// Leg index.

#[test]
fn leg_index_outside_0_and_1_is_refused() {
    assert_eq!(LegIndex::from_index(0), Ok(LegIndex::Asset));
    assert_eq!(LegIndex::from_index(1), Ok(LegIndex::Cash));
    for leg in LegIndex::ALL {
        assert_eq!(LegIndex::try_from(i64::from(leg.index())), Ok(leg));
    }
    for value in [2, 3, 255, -1, i64::MIN, i64::MAX] {
        assert_eq!(
            LegIndex::from_index(value),
            Err(TemplateError::LegIndex { value })
        );
        assert_eq!(code(LegIndex::try_from(value)), "TEMPLATE_LEG_INDEX");
    }
    // In a script: the same terms with legIndex 2 or -1 do not decode.
    let control = script(&vector(1), LegIndex::Asset);
    assert!(decode(&control).is_ok());
    for value in [2, -1] {
        let s = edit_state(&control, |v| set(v, "legIndex", ArtifactValue::Int(value)));
        assert_eq!(decode(&s), Err(TemplateError::LegIndex { value }));
    }
}

// Round trip (the I4 exit test).

#[test]
fn every_vector_round_trips_through_its_redeem_scripts() {
    let mut vaults = 0;
    for v in vectors() {
        let checked = v.terms.clone().validate_structure().expect(v.name);
        for leg in LegIndex::ALL {
            let vault = match Vault::instantiate_existing(&checked, leg) {
                Ok(vault) => vault,
                Err(e) => {
                    let no_vault = v.terms.settlement_mode == SettlementMode::Direct
                        || (leg == LegIndex::Cash && v.terms.cash_leg.kind == LegKind::External);
                    assert!(no_vault, "{} {leg:?}: {e}", v.name);
                    assert_eq!(e.code(), "TEMPLATE_NO_VAULT");
                    continue;
                }
            };
            vaults += 1;
            assert_eq!(vault.leg(), leg);
            assert_eq!(vault.network(), v.terms.network);
            let (decoded, decoded_leg) = decode(vault.redeem_script()).expect(v.name);
            assert_eq!(decoded.terms(), &v.terms, "{} {leg:?}", v.name);
            assert_eq!(decoded_leg, leg);
            assert_eq!(decoded, checked);
            assert_eq!(decoded.terms_hash(), v.terms.terms_hash().unwrap());
        }
    }
    // Nine vault-mode vectors; the two external-cash ones have no cash vault.
    assert_eq!(vaults, 16);
}

#[test]
fn instantiation_is_deterministic_and_leg_specific() {
    for n in [1, 2, 8] {
        let t = vector(n);
        let asset = script(&t, LegIndex::Asset);
        assert_eq!(asset, script(&t, LegIndex::Asset));
        assert_ne!(asset, script(&t, LegIndex::Cash));
        let a = vault(&t, LegIndex::Asset).unwrap();
        let c = vault(&t, LegIndex::Cash).unwrap();
        assert_ne!(a.script_hash(), c.script_hash());
    }
}

#[test]
fn every_vault_runs_the_checked_template() {
    let t = template();
    let mut state_lens = Vec::new();
    for v in vectors() {
        for leg in LegIndex::ALL {
            let Ok(vault) = vault(&v.terms, leg) else {
                continue;
            };
            let s = vault.redeem_script();
            assert!(s.starts_with(t.prefix()) && s.ends_with(t.suffix()));
            assert_eq!(template_hash_of_instance(s), Ok(t.hash()), "{}", v.name);
            state_lens.push(state_of(s).len());
        }
    }
    // KAS cash puts two scriptPubKeys in the state, so the span is not of fixed length: the split
    // must come from the template's prefix and suffix lengths, never the example's span.
    state_lens.sort();
    state_lens.dedup();
    assert!(state_lens.len() > 1, "state lengths {state_lens:?}");
}

#[test]
fn script_hash_is_the_p2sh_hash_of_the_redeem_script() {
    let vault = vault(&vector(2), LegIndex::Cash).unwrap();
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(vault.redeem_script());
    assert_eq!(&vault.script_hash()[..], hash.as_bytes());
    let spk = vault.script_public_key();
    assert_eq!(spk.version(), 0);
    let mut expected = vec![0xaa, 0x20]; // OpBlake2b OpData32
    expected.extend_from_slice(hash.as_bytes());
    expected.push(0x87); // OpEqual
    assert_eq!(spk.script(), &expected[..]);
}

// Legs without a vault.

#[test]
fn direct_terms_have_no_vault() {
    for n in [7, 11] {
        let t = vector(n);
        assert_eq!(t.settlement_mode, SettlementMode::Direct);
        for leg in LegIndex::ALL {
            assert_eq!(code(vault(&t, leg)), "TEMPLATE_NO_VAULT", "{n} {leg:?}");
        }
        // Control: the same terms in Vault mode have both vaults.
        let mut t = t;
        t.settlement_mode = SettlementMode::Vault;
        for leg in LegIndex::ALL {
            assert!(vault(&t, leg).is_ok(), "{n} {leg:?}");
        }
    }
}

#[test]
fn external_cash_has_no_cash_vault() {
    for n in [5, 6] {
        let t = vector(n);
        assert_eq!(t.cash_leg.kind, LegKind::External);
        assert!(vault(&t, LegIndex::Asset).is_ok());
        assert_eq!(
            vault(&t, LegIndex::Cash),
            Err(TemplateError::NoVault {
                leg: LegIndex::Cash,
                reason: "external cash settles off chain"
            })
        );
    }
    // In a script: an asset vault of external-cash terms relabelled as leg 1 does not decode.
    let asset = script(&vector(5), LegIndex::Asset);
    let s = edit_state(&asset, |v| set(v, "legIndex", ArtifactValue::Int(1)));
    assert_eq!(code(decode(&s)), "TEMPLATE_NO_VAULT");
}

// The refusals carried forward from the I2 and I3 reviews.

#[test]
fn refuses_asset_and_cash_of_one_token() {
    let control = vector(1);
    let LegKind::Kcc20(asset) = control.asset_leg.kind else {
        unreachable!("vector 1 has a KCC-20 asset")
    };
    for leg in LegIndex::ALL {
        assert!(vault(&control, leg).is_ok());
    }
    let mut t = control.clone();
    let LegKind::Kcc20(cash) = &mut t.cash_leg.kind else {
        unreachable!("vector 1 has KCC-20 cash")
    };
    cash.covenant_id = asset.covenant_id;
    // Both vaults would fail [E1], so the structure checks refuse the terms: no ValidatedTerms,
    // hence no vault.
    for leg in LegIndex::ALL {
        assert_eq!(
            vault(&t, leg),
            Err(TemplateError::Terms(TermsError::SameCovenant))
        );
    }
    // In a script.
    let s = edit_state(&script(&control, LegIndex::Cash), |v| {
        set(
            v,
            "cashCovenantId",
            ArtifactValue::Bytes(asset.covenant_id.to_vec()),
        )
    });
    assert_eq!(code(decode(&s)), "TERMS_SAME_COVENANT");
}

#[test]
fn refuses_an_unknown_cash_kind() {
    // Instantiation writes only the three kinds the contract knows: the Rust type has no other.
    for (n, expected) in [(2, 0u8), (1, 1), (5, 2)] {
        let s = script(&vector(n), LegIndex::Asset);
        assert_eq!(values_of(&s)["cashKind"], ArtifactValue::Byte(expected));
        assert!(decode(&s).is_ok(), "control {n}");
    }
    // A script carrying any other kind, which the contract would treat as KCC-20, does not decode.
    let control = script(&vector(1), LegIndex::Asset);
    for kind in [3u8, 0x7f, 0xff] {
        let s = edit_state(&control, |v| set(v, "cashKind", ArtifactValue::Byte(kind)));
        assert_eq!(
            decode(&s),
            Err(TemplateError::StateInvalid { field: "cashKind" })
        );
    }
}

#[test]
fn refuses_zero_amounts() {
    // Control: the least amounts (vector 10, both 1) instantiate.
    let control = vector(10);
    assert_eq!((control.asset_leg.amount, control.cash_leg.amount), (1, 1));
    let s = script(&control, LegIndex::Asset);
    type Fault = fn(&mut Terms);
    let faults: [(&str, Fault); 2] = [
        ("asset_leg.amount", |t| t.asset_leg.amount = 0),
        ("cash_leg.amount", |t| t.cash_leg.amount = 0),
    ];
    for (field, fault) in faults {
        let mut t = control.clone();
        fault(&mut t);
        for leg in LegIndex::ALL {
            assert_eq!(
                vault(&t, leg),
                Err(TemplateError::Terms(TermsError::AmountZero { field }))
            );
        }
    }
    // In a script: zero is refused by the terms check, a negative amount by the state mapping.
    for (field, terms_field) in [
        ("amountA", "asset_leg.amount"),
        ("amountB", "cash_leg.amount"),
    ] {
        let zero = edit_state(&s, |v| set(v, field, ArtifactValue::Int(0)));
        assert_eq!(
            decode(&zero),
            Err(TemplateError::Terms(TermsError::AmountZero {
                field: terms_field
            }))
        );
        let negative = edit_state(&s, |v| set(v, field, ArtifactValue::Int(-1)));
        assert_eq!(
            decode(&negative),
            Err(TemplateError::StateInvalid { field })
        );
    }
}

#[test]
fn refuses_an_expiry_beyond_the_creation_horizon() {
    // Vector 9 expires exactly at the default horizon from its creation DAA score.
    let t = vector(9);
    assert_eq!(t.expiry_daa, CREATION_DAA + DEFAULT_MAX_EXPIRY_HORIZON_DAA);
    let checked = t.clone().validate_structure().unwrap();
    let ctx = CreationContext::new(t.network, CREATION_DAA);
    for leg in LegIndex::ALL {
        let created = Vault::instantiate_for_creation(&checked, leg, &ctx).expect("control");
        assert_eq!(
            created.into_vault(),
            Vault::instantiate_existing(&checked, leg).unwrap()
        );
    }
    let refusals = [
        (
            CreationContext::new(t.network, CREATION_DAA - 1),
            "TERMS_EXPIRY_BEYOND_HORIZON",
        ),
        (
            CreationContext {
                max_expiry_horizon_daa: DEFAULT_MAX_EXPIRY_HORIZON_DAA - 1,
                ..ctx
            },
            "TERMS_EXPIRY_BEYOND_HORIZON",
        ),
        (
            CreationContext::new(Network::Testnet, CREATION_DAA),
            "TERMS_NETWORK_MISMATCH",
        ),
        (
            CreationContext::new(t.network, t.expiry_daa),
            "TERMS_EXPIRY_NOT_AFTER_CREATION",
        ),
    ];
    for (ctx, expected) in refusals {
        for leg in LegIndex::ALL {
            assert_eq!(
                code(Vault::instantiate_for_creation(&checked, leg, &ctx)),
                expected
            );
        }
    }
    // An existing trade is not re-dated: past its expiry, its vaults still instantiate (refunds).
    assert!(Vault::instantiate_existing(&checked, LegIndex::Asset).is_ok());
}

#[test]
fn refuses_lock_times_in_the_timestamp_domain() {
    let mut t = vector(1);
    t.expiry_daa = LOCK_TIME_THRESHOLD - 1;
    t.earliest_daa = Some(LOCK_TIME_THRESHOLD - 1);
    assert!(vault(&t, LegIndex::Asset).is_ok(), "control at the bound");

    let mut expiry = t.clone();
    expiry.expiry_daa = LOCK_TIME_THRESHOLD;
    expiry.earliest_daa = None;
    let mut earliest = t.clone();
    earliest.earliest_daa = Some(LOCK_TIME_THRESHOLD);
    for leg in LegIndex::ALL {
        assert_eq!(code(vault(&expiry, leg)), "TERMS_EXPIRY_NOT_DAA");
        assert_eq!(code(vault(&earliest, leg)), "TERMS_EARLIEST_NOT_DAA");
    }
    // In a script.
    let s = script(&t, LegIndex::Asset);
    let threshold = LOCK_TIME_THRESHOLD as i64;
    let e = edit_state(&s, |v| {
        set(v, "expiryDaa", ArtifactValue::Int(threshold));
        set(v, "hasEarliest", ArtifactValue::Bool(false));
        set(v, "earliestDaa", ArtifactValue::Int(0));
    });
    assert_eq!(code(decode(&e)), "TERMS_EXPIRY_NOT_DAA");
    let e = edit_state(&s, |v| set(v, "earliestDaa", ArtifactValue::Int(threshold)));
    assert_eq!(code(decode(&e)), "TERMS_EARLIEST_NOT_DAA");
    let e = edit_state(&s, |v| set(v, "expiryDaa", ArtifactValue::Int(-1)));
    assert_eq!(
        decode(&e),
        Err(TemplateError::StateInvalid { field: "expiryDaa" })
    );
}

#[test]
fn refuses_an_authority_equal_to_a_party() {
    let control = script(&vector(1), LegIndex::Asset);
    assert!(decode(&control).is_ok());
    for key in ["sellerKey", "buyerKey"] {
        let party = values_of(&control)[key].clone();
        let s = edit_state(&control, |v| set(v, "authorityKey", party));
        assert_eq!(code(decode(&s)), "TERMS_AUTHORITY_IS_PARTY", "{key}");
    }
}

// Decoding refusals.

#[test]
fn decode_refuses_scripts_of_another_template() {
    let good = script(&vector(2), LegIndex::Asset);
    assert!(decode(&good).is_ok());
    let t = template();
    let mut prefix_changed = good.clone();
    prefix_changed[0] ^= 1;
    let mut suffix_changed = good.clone();
    let mid = good.len() - t.suffix().len() / 2;
    suffix_changed[mid] ^= 1;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one byte", vec![t.prefix()[0]]),
        ("last byte cut", good[..good.len() - 1].to_vec()),
        (
            "P2SH scriptPubKey",
            vault(&vector(2), LegIndex::Asset)
                .unwrap()
                .script_public_key()
                .script()
                .to_vec(),
        ),
        ("prefix byte changed", prefix_changed),
        ("suffix byte changed", suffix_changed),
    ];
    for (label, s) in cases {
        assert_eq!(decode(&s), Err(TemplateError::NotImpulseVault), "{label}");
    }
    assert_eq!(
        template_hash_of_instance(t.prefix()),
        Err(TemplateError::NotImpulseVault)
    );
}

#[test]
fn decode_refuses_a_malformed_state() {
    let good = script(&vector(1), LegIndex::Asset);
    let state = state_of(&good).to_vec();
    assert!(decode(&splice(&state)).is_ok(), "control");
    // The last push is legIndex: OpData8 and 8 bytes.
    assert_eq!(state[state.len() - 9], 0x08);
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty state", vec![]),
        ("last push dropped", state[..state.len() - 9].to_vec()),
        ("push appended", [&state[..], &[0x01, 0x00]].concat()),
        ("push cut short", state[..state.len() - 1].to_vec()),
        ("small-int opcode", [&state[..], &[0x51]].concat()),
    ];
    // hasAuthority (OpData1 01) sits at 2 + 2 + 9 + 33 + 33 = 79; a value of 2 is not a bool.
    let mut not_bool = state.clone();
    assert_eq!(&not_bool[79..81], &[0x01, 0x01]);
    not_bool[80] = 2;
    cases.push(("bool byte 2", not_bool));
    // The 8-byte nonce pushed as 7 bytes.
    let mut short_nonce = state.clone();
    assert_eq!(short_nonce[4], 0x08);
    short_nonce[4] = 0x07;
    short_nonce.remove(5);
    cases.push(("nonce of 7 bytes", short_nonce));
    for (label, s) in cases {
        assert_eq!(
            code(decode(&splice(&s))),
            "TEMPLATE_STATE_MALFORMED",
            "{label}"
        );
    }
}

#[test]
fn decode_refuses_state_values_outside_the_terms() {
    use ArtifactValue::{Byte, Bytes, Int};
    let kas = script(&vector(2), LegIndex::Cash);
    let kcc20 = script(&vector(1), LegIndex::Asset);
    assert!(decode(&kas).is_ok() && decode(&kcc20).is_ok(), "controls");
    let cases: Vec<(&Vec<u8>, &'static str, ArtifactValue)> = vec![
        (&kcc20, "network", Byte(2)),
        (&kcc20, "fundingMode", Byte(2)),
        (&kcc20, "buyerDeliveryType", Byte(3)),
        (&kcc20, "sellerRefundType", Byte(0xff)),
        (&kcc20, "sellerProceedsType", Byte(3)),
        (&kcc20, "assetPrefixLen", Int(-1)),
        (&kcc20, "assetSuffixLen", Int(1 << 32)),
        (&kcc20, "cashPrefixLen", Int(-1)),
        (&kcc20, "earliestDaa", Int(-5)),
        (&kas, "sellerProceedsSpk", Bytes(vec![0x00])),
        (&kas, "buyerRefundSpk", Bytes(vec![])),
    ];
    for (base, field, value) in cases {
        let s = edit_state(base, |v| set(v, field, value));
        assert_eq!(
            decode(&s),
            Err(TemplateError::StateInvalid { field }),
            "{field}"
        );
    }
    // Values the state carries but the terms refuse keep their terms code.
    let s = edit_state(&kcc20, |v| set(v, "version", Byte(2)));
    assert_eq!(code(decode(&s)), "TERMS_UNSUPPORTED_VERSION");
    // Version 0, OpTrue: not a standard scriptPubKey.
    let s = edit_state(&kas, |v| {
        set(v, "sellerProceedsSpk", Bytes(vec![0x00, 0x00, 0x51]))
    });
    assert_eq!(code(decode(&s)), "TERMS_NONSTANDARD_SCRIPT");
}

#[test]
fn decode_refuses_non_canonical_states() {
    use ArtifactValue::{Byte, Bytes, Int};
    // Vector 3 has no authority; vector 2 KAS cash and no earliest_daa; vector 1 KCC-20 cash.
    let no_authority = script(&vector(3), LegIndex::Asset);
    let kas = script(&vector(2), LegIndex::Asset);
    let kcc20 = script(&vector(1), LegIndex::Asset);
    for s in [&no_authority, &kas, &kcc20] {
        assert!(decode(s).is_ok(), "control");
    }
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "absent authority with a key",
            edit_state(&no_authority, |v| {
                set(v, "authorityKey", Bytes(authority().to_vec()))
            }),
        ),
        (
            "absent earliest_daa with a value",
            edit_state(&kas, |v| set(v, "earliestDaa", Int(1))),
        ),
        (
            "KAS cash with a covenant ID",
            edit_state(&kas, |v| {
                set(v, "cashCovenantId", Bytes(label32("x").to_vec()))
            }),
        ),
        (
            "KAS cash with a template length",
            edit_state(&kas, |v| set(v, "cashSuffixLen", Int(1))),
        ),
        (
            "KAS cash with an owner type",
            edit_state(&kas, |v| set(v, "sellerProceedsType", Byte(1))),
        ),
        (
            "KCC-20 cash with a scriptPubKey",
            edit_state(&kcc20, |v| set(v, "buyerRefundSpk", Bytes(vec![0, 0]))),
        ),
    ];
    for (label, s) in cases {
        assert_eq!(decode(&s), Err(TemplateError::NonCanonical), "{label}");
    }

    // Raw encodings the state parser accepts but the encoder never writes.
    let state = state_of(&kcc20).to_vec();
    // sellerKey: OpData32 at offset 13, written as OpPushData1 32 instead.
    assert_eq!(state[13], 0x20);
    assert_eq!(&state[14..46], &seller());
    let long_push = [&state[..13], &[0x4c, 0x20], &state[14..]].concat();
    // legIndex 0 written as negative zero (the sign bit set on its last byte).
    let mut negative_zero = state.clone();
    let n = negative_zero.len();
    assert_eq!(&negative_zero[n - 9..], &[0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
    negative_zero[n - 1] = 0x80;
    for (label, s) in [
        ("non-minimal push", long_push),
        ("negative zero", negative_zero),
    ] {
        assert_eq!(
            decode(&splice(&s)),
            Err(TemplateError::NonCanonical),
            "{label}"
        );
    }
}

#[test]
fn template_hash_of_instance_names_the_template() {
    let t = template();
    let good = script(&vector(4), LegIndex::Cash);
    assert_eq!(template_hash_of_instance(&good), Ok(t.hash()));
    let mut other = good.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    let hash = template_hash_of_instance(&other).unwrap();
    assert_ne!(hash, t.hash(), "another template, another hash");
}

#[test]
fn destinations_map_to_their_state_fields() {
    // A spot check beside the round trip: vector 2 (custodian SCRIPT_HASH delivery, KAS cash to
    // a P2PK scriptPubKey) as the contract reads it.
    let t = vector(2);
    let v = values_of(&script(&t, LegIndex::Asset));
    let Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier,
    }) = t.buyer_delivery
    else {
        unreachable!("vector 2 delivers to a SCRIPT_HASH owner")
    };
    assert_eq!(v["buyerDeliveryType"], ArtifactValue::Byte(1));
    assert_eq!(
        v["buyerDeliveryId"],
        ArtifactValue::Bytes(identifier.to_vec())
    );
    let Destination::Kas(spk) = &t.seller_proceeds else {
        unreachable!("vector 2 pays KAS")
    };
    let mut spk_bytes = vec![0, 0];
    spk_bytes.extend_from_slice(spk.script());
    assert_eq!(v["sellerProceedsSpk"], ArtifactValue::Bytes(spk_bytes));
    assert_eq!(v["sellerProceedsType"], ArtifactValue::Byte(0));
    assert_eq!(v["sellerProceedsId"], ArtifactValue::Bytes(vec![0; 32]));
    assert_eq!(v["cashKind"], ArtifactValue::Byte(0));
    assert_eq!(v["cashCovenantId"], ArtifactValue::Bytes(vec![0; 32]));
    assert_eq!(
        v["nonce"],
        ArtifactValue::Bytes(t.nonce.to_le_bytes().to_vec())
    );
    assert_eq!(v["hasEarliest"], ArtifactValue::Bool(false));
    assert_eq!(v["earliestDaa"], ArtifactValue::Int(0));
    assert_eq!(v["legIndex"], ArtifactValue::Int(0));
    let Leg {
        kind: LegKind::Kas,
        amount,
    } = t.cash_leg
    else {
        unreachable!("vector 2 has KAS cash")
    };
    assert_eq!(v["amountB"], ArtifactValue::Int(amount as i64));
}

// Error codes.

#[test]
fn template_error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; this list may only grow at the end.
    assert_eq!(
        TEMPLATE_ERROR_CODES,
        [
            "TEMPLATE_ARTIFACT_INVALID",
            "TEMPLATE_HASH_MISMATCH",
            "TEMPLATE_LEG_INDEX",
            "TEMPLATE_NO_VAULT",
            "TEMPLATE_NOT_IMPULSE_VAULT",
            "TEMPLATE_STATE_MALFORMED",
            "TEMPLATE_STATE_INVALID",
            "TEMPLATE_NONCANONICAL",
        ]
    );
    let all = [
        TemplateError::ArtifactInvalid { reason: "r".into() },
        TemplateError::HashMismatch {
            expected: [1; 32],
            found: [2; 32],
        },
        TemplateError::LegIndex { value: 2 },
        TemplateError::NoVault {
            leg: LegIndex::Cash,
            reason: "r",
        },
        TemplateError::NotImpulseVault,
        TemplateError::StateMalformed { reason: "r".into() },
        TemplateError::StateInvalid { field: "f" },
        TemplateError::NonCanonical,
    ];
    let codes: Vec<&str> = all.iter().map(TemplateError::code).collect();
    assert_eq!(codes, TEMPLATE_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()));
    }
    // Terms refusals pass through with their own code and text.
    let terms = TemplateError::from(TermsError::EarliestZero);
    assert_eq!(terms.code(), "TERMS_EARLIEST_ZERO");
    assert_eq!(terms.to_string(), TermsError::EarliestZero.to_string());
    for c in TEMPLATE_ERROR_CODES {
        assert!(!crate::terms::TERMS_ERROR_CODES.contains(&c));
    }
}
