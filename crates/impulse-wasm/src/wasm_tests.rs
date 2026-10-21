// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Tests that run inside the JavaScript engine (`wasm-pack test --node`): every impulse-core
//! refusal reaches JavaScript as an `ImpulseError` with its code unchanged, the argument checks
//! refuse with their own codes beside accepted controls, and a golden vector goes through the
//! exported bindings byte for byte. The TypeScript suite (crates/impulse-wasm/npm/test/) runs
//! every vector and every reachable refusal through the published package.

use super::*;
use impulse_core::decode::{DecodeError, DECODE_ERROR_CODES};
use impulse_core::template::TemplateError;
use impulse_core::terms::{Network, TermsError};
use impulse_core::tx::{TxError, TX_ERROR_CODES};
use impulse_core::verify::{TemplateTriple, VerifyError, VERIFY_ERROR_CODES};
use wasm_bindgen_test::wasm_bindgen_test;

const TERMS_02: &str =
    include_str!("../../../tests/vectors/terms/02-vault-authority-revocable-kcc20-kas.json");
const VAULTS_02: &str =
    include_str!("../../../tests/vectors/vaults/02-vault-authority-revocable-kcc20-kas.json");
const IPST_12: &str = include_str!("../../../tests/vectors/ipst/12-direct-kas.json");
const ASSET_ARTIFACT: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");

fn get(v: &JsValue, key: &str) -> JsValue {
    Reflect::get(v, &key.into()).expect("readable property")
}

/// The code a thrown value carries, after checking it is an `ImpulseError`.
fn code_of(thrown: &JsValue) -> String {
    assert!(
        thrown.is_instance_of::<js_sys::Error>(),
        "an Error is thrown"
    );
    assert_eq!(
        get(thrown, "name").as_string().as_deref(),
        Some("ImpulseError")
    );
    let code = get(thrown, "code").as_string().expect("a string code");
    let message = get(thrown, "message").as_string().expect("a message");
    assert!(message.starts_with(&format!("{code}: ")), "{message}");
    code
}

fn every_terms_error() -> Vec<TermsError> {
    use TermsError::*;
    let f = "field";
    vec![
        Truncated { field: f },
        TrailingBytes { count: 1 },
        InvalidTag { field: f, value: 9 },
        InvalidPresence { field: f, value: 2 },
        UnknownSettlementMode { value: 2 },
        FieldTooLong {
            field: f,
            len: 10_001,
        },
        UnsupportedVersion { version: 2 },
        InvalidKey { field: f },
        PartiesNotDistinct { field: f },
        AuthorityIsParty {
            party: "seller_key",
        },
        AssetExternal,
        AssetKindUnsupported,
        ExternalWithoutAuthority,
        DirectIncompatible { field: f },
        AmountZero { field: f },
        AmountOutOfRange {
            field: f,
            amount: 2,
            max: 1,
        },
        SameCovenant,
        ZeroIdentifier { field: f },
        TemplateLength {
            field: f,
            prefix_len: 0,
            suffix_len: 1,
        },
        DestinationKind { field: f },
        NonStandardScript { field: f },
        ExpiryNotDaa { expiry_daa: 1 },
        EarliestNotDaa { earliest_daa: 1 },
        EarliestZero,
        EarliestAfterExpiry {
            earliest_daa: 2,
            expiry_daa: 1,
        },
        NetworkMismatch {
            expected: Network::Mainnet,
            found: Network::Testnet,
        },
        ExpiryNotAfterCreation {
            expiry_daa: 1,
            creation_daa: 1,
        },
        ExpiryBeyondHorizon {
            expiry_daa: 2,
            max_expiry_daa: 1,
        },
    ]
}

fn every_template_error() -> Vec<TemplateError> {
    use TemplateError::*;
    vec![
        ArtifactInvalid {
            reason: "test".into(),
        },
        HashMismatch {
            expected: [1; 32],
            found: [2; 32],
        },
        LegIndex { value: 2 },
        NoVault {
            leg: impulse_core::template::LegIndex::Cash,
            reason: "test",
        },
        NotImpulseVault,
        StateMalformed {
            reason: "test".into(),
        },
        StateInvalid { field: "network" },
        NonCanonical,
        Terms(TermsError::SameCovenant),
    ]
}

#[wasm_bindgen_test]
fn every_core_and_sdk_code_reaches_javascript_unchanged() {
    let mut seen: Vec<String> = Vec::new();
    for e in every_terms_error() {
        let thrown = js(e.clone());
        assert_eq!(code_of(&thrown), e.code());
        assert_eq!(get(&thrown, "message").as_string(), Some(e.to_string()));
        seen.push(e.code().into());
    }
    for e in every_template_error() {
        let thrown = js(e.clone());
        assert_eq!(code_of(&thrown), e.code());
        assert_eq!(get(&thrown, "message").as_string(), Some(e.to_string()));
        seen.push(e.code().into());
    }
    for e in [
        SdkError::ArgumentType {
            argument: "bytes",
            expected: "a Uint8Array",
        },
        SdkError::json("terms", "expected an object"),
        SdkError::MainnetNeedsNode,
        SdkError::ValueCapInvalid {
            reason: "test".into(),
        },
        SdkError::ValueUnknown { reason: "test" },
        SdkError::ValueCapExceeded { value: 2, cap: 1 },
        SdkError::Qr {
            reason: "test".into(),
        },
        SdkError::TermsInconsistent {
            reason: "test".into(),
        },
        SdkError::RoleKeyMismatch {
            role: "buyer",
            expected: "x".into(),
            got: "y".into(),
        },
        SdkError::DestinationNotMine {
            reasons: vec!["test".into()],
        },
        SdkError::DestinationPinInvalid {
            pin: "test".into(),
            reason: "test".into(),
        },
        SdkError::WalletWiped,
        SdkError::WalletRandom {
            reason: "test".into(),
        },
        SdkError::SignMainnetNotExplicit,
        SdkError::SignNetworkMismatch,
        SdkError::SignNothing { reason: "test" },
        SdkError::SignSelfCheck,
        SdkError::NodeUrlInvalid { url: "test".into() },
        SdkError::NodeInsecure { url: "test".into() },
        SdkError::NodeNetworkMismatch {
            node: "test".into(),
            expected: "mainnet",
        },
        SdkError::NodeNotSynced,
        SdkError::RpcReply {
            method: "getServerInfo",
            reason: "test".into(),
            from_node: false,
        },
        SdkError::TxidMismatch {
            asked: "a".into(),
            got: "b".into(),
        },
        SdkError::UtxoNotFound {
            what: "test".into(),
        },
        SdkError::SignChangeNotMine {
            change: "x".into(),
            expected: "y".into(),
        },
        SdkError::SignFeeTooHigh {
            reason: "test".into(),
        },
        SdkError::SignTopupTooHigh {
            topup: 2,
            max_topup: 1,
        },
        SdkError::SignOutflowTooHigh {
            outflow: 2,
            limit: 1,
            expected: 0,
        },
        SdkError::DestinationInWallet {
            reasons: vec!["test".into()],
        },
        SdkError::RpcNotFound {
            method: "getMempoolEntry",
            id: "x".into(),
        },
        SdkError::FundNotYourLeg {
            reason: "test".into(),
        },
        SdkError::TemplateUnpinned {
            reason: "test".into(),
        },
        SdkError::FundAssetNotFunded {
            reason: "test".into(),
        },
        SdkError::FundAlreadyFunded {
            reason: "test".into(),
        },
        SdkError::SignDepositMismatch {
            carrier: 2,
            authorizer: 1,
            confirmed_carrier: 3,
            confirmed_authorizer: 4,
        },
    ] {
        let thrown = js(e.clone());
        assert_eq!(code_of(&thrown), e.code());
        // Only an error the node sent to the very request carries `nodeError`: of these, the
        // node's "not found" to getMempoolEntry.
        let mark = get(&thrown, "nodeError");
        if matches!(e, SdkError::RpcNotFound { .. }) {
            assert_eq!(mark.as_bool(), Some(true), "{}", e.code());
        } else {
            assert!(mark.is_undefined(), "{}", e.code());
        }
        seen.push(e.code().into());
    }
    // A reply the node sent to the request with an error in it is marked; the same code for a
    // reply that cannot be read is not.
    for (from_node, mark) in [(true, Some(true)), (false, None)] {
        let thrown = js(SdkError::RpcReply {
            method: "submitTransaction",
            reason: "test".into(),
            from_node,
        });
        assert_eq!(code_of(&thrown), "SDK_RPC_REPLY");
        assert_eq!(get(&thrown, "nodeError").as_bool(), mark);
    }
    seen.sort();
    seen.dedup();
    let mut all: Vec<String> = terms_error_codes();
    all.extend(template_error_codes());
    all.extend(sdk_error_codes());
    all.sort();
    assert_eq!(seen, all, "every stable code is exercised");
}

#[wasm_bindgen_test]
fn argument_checks_refuse_beside_accepted_controls() {
    let bytes: JsValue = Uint8Array::from(&[1u8, 2][..]).into();
    assert_eq!(bytes_arg(&bytes, "bytes", SHORT_BYTES).unwrap(), vec![1, 2]);
    let thrown = bytes_arg(&JsValue::from_str("0102"), "bytes", SHORT_BYTES).unwrap_err();
    assert_eq!(code_of(&thrown), "SDK_ARGUMENT_TYPE");
    // The bounds: a value at the bound is read, one byte over is refused, and the refusal names
    // the bound it says.
    for bound in [TX_BYTES, SHORT_BYTES] {
        assert!(
            bound.expected.contains(&bound.longest.to_string()),
            "{} says its bound",
            bound.expected
        );
        let at: JsValue = Uint8Array::new_with_length(bound.longest).into();
        assert_eq!(
            bytes_arg(&at, "bytes", bound).unwrap().len(),
            bound.longest as usize
        );
        let over: JsValue = Uint8Array::new_with_length(bound.longest + 1).into();
        let thrown = bytes_arg(&over, "bytes", bound).unwrap_err();
        assert_eq!(code_of(&thrown), "SDK_ARGUMENT_TYPE");
    }

    assert_eq!(leg_arg(&JsValue::from_f64(1.0)).unwrap(), LegIndex::Cash);
    assert_eq!(
        code_of(&leg_arg(&JsValue::from_f64(2.0)).unwrap_err()),
        "TEMPLATE_LEG_INDEX"
    );
    assert_eq!(
        code_of(&leg_arg(&JsValue::from_f64(-1.0)).unwrap_err()),
        "TEMPLATE_LEG_INDEX"
    );
    for wrong in [
        JsValue::from_f64(0.5),
        JsValue::from_f64(f64::NAN),
        JsValue::from_f64(f64::INFINITY),
        JsValue::from_str("0"),
        JsValue::UNDEFINED,
    ] {
        assert_eq!(code_of(&leg_arg(&wrong).unwrap_err()), "SDK_ARGUMENT_TYPE");
    }

    let object = js_sys::JSON::parse(r#"{"a":"1","b":null,"c":1,"d":true,"e":{"f":-2}}"#).unwrap();
    assert_eq!(
        json_arg(&object, "context").unwrap(),
        serde_json::json!({"a": "1", "b": null, "c": 1, "d": true, "e": {"f": -2}})
    );
    // JSON.stringify writes each of these as null or leaves it out; the reader refuses it, on
    // its own and as the value of a key whose control value, null, is read.
    let with_a = |v: &JsValue| {
        let o = Object::new();
        Reflect::set(&o, &"a".into(), v).unwrap();
        JsValue::from(o)
    };
    assert!(json_arg(&with_a(&JsValue::NULL), "context").is_ok());
    let wrong_values: [JsValue; 7] = [
        JsValue::UNDEFINED,
        js_sys::BigInt::from(1u64).into(),
        JsValue::from_f64(f64::NAN),
        JsValue::from_f64(f64::INFINITY),
        JsValue::from_f64(f64::NEG_INFINITY),
        js_sys::Date::new(&JsValue::from_f64(f64::NAN)).into(),
        js_sys::Array::new().into(),
    ];
    for wrong in &wrong_values {
        for value in [wrong.clone(), with_a(wrong)] {
            assert_eq!(
                code_of(&json_arg(&value, "context").unwrap_err()),
                "SDK_JSON_FORM"
            );
        }
    }
    // An own toJSON is a key like any other: read as data, never called.
    let to_json = js_sys::JSON::parse(r#"{"toJSON":null}"#).unwrap();
    assert_eq!(
        json_arg(&to_json, "context").unwrap(),
        serde_json::json!({"toJSON": null})
    );
    // -0 and 2^53 are read as serde_json reads their JSON text: floats, not integers.
    assert_eq!(json_number(0.0), Some(0u64.into()));
    assert!(json_number(-0.0).is_some_and(|n| n.is_f64()));
    assert_eq!(
        json_number(9_007_199_254_740_991.0),
        Some(9_007_199_254_740_991u64.into())
    );
    assert!(json_number(9_007_199_254_740_992.0).is_some_and(|n| n.is_f64()));
    assert_eq!(json_number(-1.0), Some((-1i64).into()));
    assert_eq!(json_number(f64::NAN), None);

    assert_eq!(
        address_prefix(JsValue::from_str("testnet")).unwrap(),
        "kaspatest"
    );
    assert_eq!(
        code_of(&address_prefix(JsValue::from_str("tn10")).unwrap_err()),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        code_of(&address_prefix(JsValue::from_f64(1.0)).unwrap_err()),
        "SDK_ARGUMENT_TYPE"
    );
}

#[wasm_bindgen_test]
fn a_golden_vector_through_the_bindings() {
    let terms_doc = js_sys::JSON::parse(TERMS_02).unwrap();
    let vaults_doc = js_sys::JSON::parse(VAULTS_02).unwrap();
    let hex_of = |v: JsValue| v.as_string().expect("hex string");

    let terms = JsTerms::from_json(get(&terms_doc, "terms")).unwrap();
    assert_eq!(
        json::hex(&terms.encode().unwrap()),
        hex_of(get(&terms_doc, "canonical"))
    );
    assert_eq!(
        json::hex(&terms.terms_hash().unwrap()),
        hex_of(get(&terms_doc, "terms_hash"))
    );
    let rendered = js_sys::JSON::stringify(&terms.to_json().unwrap()).unwrap();
    let committed = js_sys::JSON::stringify(&get(&terms_doc, "terms")).unwrap();
    assert_eq!(String::from(rendered), String::from(committed));

    let checked = terms.validate_structure().unwrap();
    let ctx = js_sys::JSON::parse(r#"{"network":"mainnet","creation_daa":"400000000"}"#).unwrap();
    // The vectors' terms are far above the cap; the explicit flag lifts it.
    let value = js_sys::JSON::parse(r#"{"i_accept_the_risk":true}"#).unwrap();
    checked.validate_creation(ctx.clone()).unwrap();
    for (key, leg) in [("asset_vault", 0.0), ("cash_vault", 1.0)] {
        let want = get(&vaults_doc, key);
        let fundable = checked
            .instantiate_for_creation(JsValue::from_f64(leg), ctx.clone(), value.clone())
            .unwrap();
        let vault = fundable.vault();
        assert_eq!(
            json::hex(&vault.redeem_script()),
            hex_of(get(&want, "redeem_script"))
        );
        assert_eq!(
            json::hex(&vault.script_hash()),
            hex_of(get(&want, "script_hash"))
        );
        assert_eq!(fundable.address(), hex_of(get(&want, "address")));
        let decoded = decode_vault(Uint8Array::from(&vault.redeem_script()[..]).into()).unwrap();
        assert_eq!(decoded.terms().canonical(), checked.canonical());
        assert_eq!(f64::from(decoded.leg()), leg);
    }
}

fn every_tx_error() -> Vec<TxError> {
    use TxError::*;
    vec![
        WrongMode { reason: "test" },
        VaultMismatch,
        Expired {
            current_daa: 2,
            expiry_daa: 1,
        },
        NotAtVault { input: "test" },
        EscrowMismatch { input: "test" },
        LegAmount {
            input: "test",
            expected: 1,
            found: 2,
        },
        TokenTemplate {
            reason: "test".into(),
        },
        TokenInput {
            index: 0,
            reason: "test",
        },
        KasInput {
            index: 0,
            reason: "test",
        },
        DuplicateInput { index: 1 },
        InsufficientFunds {
            available: 1,
            needed: 2,
        },
        BelowMinKas {
            output: 0,
            value: 1,
            minimum: 2,
        },
        Mass {
            dimension: "compute",
            mass: 2,
            cap: 1,
        },
        FeeTooLow { fee: 1, minimum: 2 },
        NonstandardChange,
        RefundSigner { reason: "test" },
        Signature {
            input: Some(1),
            reason: "test".into(),
        },
        SignatureSlot {
            input: 1,
            reason: "test",
        },
        Encoding {
            reason: "test".into(),
        },
        IpstMalformed {
            reason: "test".into(),
        },
        IpstUnsupportedVersion { version: 2 },
        IpstSighashMismatch { input: 1 },
        IpstConflict { reason: "test" },
        UtxoValue {
            input: None,
            value: 0,
        },
        IpstTermsMismatch { reason: "test" },
        Terms(TermsError::SameCovenant),
        Template(TemplateError::NotImpulseVault),
        TooManyInputs {
            inputs: 13,
            max: 12,
        },
    ]
}

fn every_verify_error() -> Vec<VerifyError> {
    use impulse_core::template::LegIndex::{Asset, Cash};
    use VerifyError::*;
    let triple = TemplateTriple {
        hash: [1; 32],
        prefix_len: 1,
        suffix_len: 2,
    };
    vec![
        AddressMalformed {
            leg: Asset,
            reason: "test".into(),
        },
        AddressNetwork {
            leg: Asset,
            expected: Network::Mainnet,
            found: "kaspatest".into(),
        },
        AddressMismatch { leg: Cash },
        AddressMissing { leg: Cash },
        AddressUnexpected { leg: Cash },
        LegsSwapped { leg: Asset },
        TemplateMismatch {
            expected: [1; 32],
            found: None,
        },
        TermsMismatch {
            fields: vec!["nonce"],
        },
        TokenLegKind { leg: Cash },
        TokenArtifactInvalid {
            leg: Asset,
            reason: "test".into(),
        },
        TokenTemplateMismatch {
            leg: Asset,
            expected: triple,
            found: triple,
        },
        TokenNotKcc20 {
            leg: Asset,
            reason: "test".into(),
        },
        NothingRevealed,
        TokenExtendedState {
            leg: Asset,
            fields: vec!["frozen".into()],
        },
        InputNotVault,
        Template(TemplateError::NonCanonical),
    ]
}

fn every_decode_error() -> Vec<DecodeError> {
    use DecodeError::*;
    vec![
        TxMalformed {
            reason: "test".into(),
        },
        TxIdMismatch {
            carried: [1; 32],
            computed: [2; 32],
        },
        EntryUnknown { index: 1 },
        NoVaultInput,
        SpentCount {
            inputs: 2,
            spent: 1,
        },
        InputNotVault { index: 1 },
        Input {
            index: 1,
            error: TemplateError::NonCanonical,
        },
        Template(TemplateError::NotImpulseVault),
    ]
}

#[wasm_bindgen_test]
fn every_phase_two_code_reaches_javascript_unchanged() {
    use crate::error::Refusal;
    fn check<E: Refusal + Clone>(errors: Vec<E>, seen: &mut Vec<String>) {
        for e in errors {
            let thrown = js(e.clone());
            // A decode refusal of one input names the input before the code ("input 1: ..."),
            // so the message is compared whole and not by its start.
            assert!(thrown.is_instance_of::<js_sys::Error>());
            assert_eq!(
                get(&thrown, "name").as_string().as_deref(),
                Some("ImpulseError")
            );
            assert_eq!(get(&thrown, "code").as_string().as_deref(), Some(e.code()));
            assert_eq!(get(&thrown, "message").as_string(), Some(e.to_string()));
            seen.push(e.code().into());
        }
    }
    let mut seen: Vec<String> = Vec::new();
    check(every_tx_error(), &mut seen);
    check(every_verify_error(), &mut seen);
    check(every_decode_error(), &mut seen);
    seen.sort();
    seen.dedup();
    // The terms and template codes met on the way are phase 1's.
    seen.retain(|c| !c.starts_with("TERMS_") && !c.starts_with("TEMPLATE_"));
    let mut all: Vec<String> = TX_ERROR_CODES.iter().map(|c| c.to_string()).collect();
    all.extend(VERIFY_ERROR_CODES.iter().map(|c| c.to_string()));
    all.extend(DECODE_ERROR_CODES.iter().map(|c| c.to_string()));
    all.sort();
    assert_eq!(seen, all, "every stable code is exercised");
}

#[wasm_bindgen_test]
fn phase_two_argument_readers_refuse_beside_accepted_controls() {
    // A u64: a canonical decimal string, or a bigint.
    assert_eq!(
        u64_arg(&JsValue::from_str("1500000"), "x").unwrap(),
        1_500_000
    );
    assert_eq!(
        u64_arg(&js_sys::BigInt::from(1_500_000u64).into(), "x").unwrap(),
        1_500_000
    );
    assert_eq!(
        u64_arg(&JsValue::from_str("18446744073709551615"), "x").unwrap(),
        u64::MAX
    );
    for wrong in [
        JsValue::from_f64(1.0),
        JsValue::from_str("01"),
        JsValue::from_str("-1"),
        JsValue::from_str("18446744073709551616"),
        js_sys::BigInt::from(-1i64).into(),
        JsValue::UNDEFINED,
    ] {
        assert_eq!(
            code_of(&u64_arg(&wrong, "x").unwrap_err()),
            "SDK_ARGUMENT_TYPE"
        );
    }

    // An input index: an integer number, -0 included.
    assert_eq!(index_arg(&JsValue::from_f64(2.0), "x").unwrap(), 2);
    assert_eq!(index_arg(&JsValue::from_f64(-0.0), "x").unwrap(), 0);
    for wrong in [
        JsValue::from_f64(-1.0),
        JsValue::from_f64(0.5),
        JsValue::from_f64(4_294_967_296.0),
        JsValue::from_str("0"),
    ] {
        assert_eq!(
            code_of(&index_arg(&wrong, "x").unwrap_err()),
            "SDK_ARGUMENT_TYPE"
        );
    }

    // Bounded text.
    assert_eq!(text_arg(&JsValue::from_str("abc"), "x", 3).unwrap(), "abc");
    assert_eq!(
        code_of(&text_arg(&JsValue::from_str("abcd"), "x", 3).unwrap_err()),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        code_of(&text_arg(&JsValue::from_f64(1.0), "x", 3).unwrap_err()),
        "SDK_ARGUMENT_TYPE"
    );

    // Arrays are read where the shape allows them, and only plain ones.
    let array = js_sys::JSON::parse(r#"{"a":[{"b":"1"},null,true]}"#).unwrap();
    assert_eq!(
        json_arg_tx(&array, "x").unwrap(),
        serde_json::json!({"a": [{"b": "1"}, null, true]})
    );
    assert_eq!(
        code_of(&json_arg(&array, "x").unwrap_err()),
        "SDK_JSON_FORM"
    );
    let sparse = js_sys::Array::new();
    sparse.set(1, JsValue::from_f64(1.0)); // a hole at index 0
    assert_eq!(
        code_of(&json_arg_tx(&sparse, "x").unwrap_err()),
        "SDK_JSON_FORM"
    );
    let with_extra = js_sys::Array::of1(&JsValue::from_f64(1.0));
    Reflect::set(&with_extra, &"note".into(), &JsValue::from_str("x")).unwrap();
    assert_eq!(
        code_of(&json_arg_tx(&with_extra, "x").unwrap_err()),
        "SDK_JSON_FORM"
    );
    // Dense arrays, so that only the bound refuses: one element over it, and the bound itself.
    let dense = |n: u32| {
        let a = js_sys::Array::new();
        for _ in 0..n {
            a.push(&JsValue::NULL);
        }
        a
    };
    assert_eq!(
        code_of(&json_arg_tx(&dense(MAX_JSON_ELEMENTS + 1), "x").unwrap_err()),
        "SDK_JSON_FORM"
    );
    // A length past the bound is refused before any element is read, however it is made.
    let huge = js_sys::Array::new_with_length(u32::MAX);
    assert_eq!(
        code_of(&json_arg_tx(&huge, "x").unwrap_err()),
        "SDK_JSON_FORM"
    );
    let at_bound = dense(MAX_JSON_ELEMENTS);
    assert!(
        json_arg_tx(&at_bound, "x").is_ok(),
        "the bound itself is read"
    );
}

#[wasm_bindgen_test]
fn a_direct_ipst_vector_through_the_bindings() {
    // The `ipst` object of the vector file, de-indented by the two spaces it sits at there.
    let start = IPST_12.find("\"ipst\": {").unwrap() + "\"ipst\": ".len();
    let body = &IPST_12[start..IPST_12.rfind("\n}").unwrap()];
    let text: String = body
        .lines()
        .enumerate()
        .map(|(i, l)| {
            format!(
                "{}\n",
                if i == 0 {
                    l
                } else {
                    l.strip_prefix("  ").unwrap_or(l)
                }
            )
        })
        .collect();
    let ipst = api::JsIpst::from_json(JsValue::from_str(&text)).unwrap();
    assert_eq!(ipst.to_json(), text, "read and rendered byte for byte");
    assert_eq!(ipst.fee(), "5000000");

    let artifacts = Object::new();
    Reflect::set(
        &artifacts,
        &"asset".into(),
        &JsValue::from_str(ASSET_ARTIFACT),
    )
    .unwrap();
    Reflect::set(&artifacts, &"cash".into(), &JsValue::NULL).unwrap();
    let declared = js_sys::JSON::parse(r#"{"kas_equivalent":"1"}"#).unwrap();
    let matched = ipst
        .verify_against_terms(
            artifacts.clone().into(),
            JsValue::from_str("1500000"),
            declared.clone(),
        )
        .unwrap();
    let kind = get(&matched, "kind");
    assert_eq!(get(&kind, "builder").as_string().as_deref(), Some("direct"));
    // Control beside a refusal: another DAA score past the expiry is the builder's TX_EXPIRED.
    let late = ipst.verify_against_terms(artifacts.into(), JsValue::from_str("2000000"), declared);
    assert_eq!(code_of(&late.unwrap_err()), "TX_EXPIRED");
}
