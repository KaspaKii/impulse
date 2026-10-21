// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Native tests of the template v2 surface (`v2.rs`): the terms v2 and IPST v2 golden vectors
//! read and render back, the four v2 builders called through the SDK's JSON forms rebuild the
//! golden IPSTs byte for byte from their own inputs, and every refusal beside an accepted
//! control. Keyless: no key, throwaway or other, appears here.

use crate::error::{Failure, Refusal};
use crate::v2::{self, Artifacts};
use impulse_core::terms::{LegKind, Network};
use impulse_core::v2::{ValidatedTermsV2, VaultV2};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const ARTIFACT: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");

/// The DAA score the golden IPST v2 vectors were built at (impulse-core `v2::testkit::NOW`).
const NOW: u64 = 1_500_000;

fn declared() -> Value {
    json!({ "kas_equivalent": "1" })
}

fn dir(set: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(set)
}

fn files(set: &str) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = std::fs::read_dir(dir(set))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                serde_json::from_str(&text).unwrap(),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn code<T>(r: Result<T, Failure>) -> &'static str {
    match r {
        Ok(_) => panic!("accepted"),
        Err(e) => e.code(),
    }
}

/// An IPST input as the SDK's `UtxoJson`.
fn utxo_of(input: &Value) -> Value {
    let u = &input["utxo"];
    json!({
        "transaction_id": input["transaction_id"],
        "index": input["index"],
        "amount": u["amount"],
        "script_public_key": u["script_public_key"],
        "block_daa_score": u["block_daa_score"],
        "is_coinbase": u["is_coinbase"],
        "covenant_id": u["covenant_id"],
    })
}

/// The fee payment of an IPST: its inputs from `first`, its fee, and the change destination
/// (output `trade_outputs`, or the first fee input's script when there is no change).
fn funding_of(doc: &Value, first: usize, trade_outputs: usize, fee: u64) -> Value {
    let inputs: Vec<Value> = doc["inputs"].as_array().unwrap()[first..]
        .iter()
        .map(utxo_of)
        .collect();
    let change = doc["outputs"]
        .as_array()
        .unwrap()
        .get(trade_outputs)
        .map_or_else(
            || inputs[0]["script_public_key"].clone(),
            |o| o["script_public_key"].clone(),
        );
    json!({ "inputs": inputs, "fee": fee.to_string(), "change": change })
}

fn read(doc: &Value) -> impulse_core::v2::IpstV2 {
    v2::ipst_from_json(&doc.to_string()).unwrap()
}

#[test]
fn terms_v2_vectors_read_and_render_back() {
    let all = files("terms_v2");
    assert_eq!(all.len(), 8);
    for (name, doc) in all {
        let t = v2::terms_from_json(&doc["terms"]).unwrap();
        let canonical = crate::json::hex(&t.encode().unwrap());
        assert_eq!(canonical, doc["canonical"].as_str().unwrap(), "{name}");
        let hash = crate::json::hex(&t.terms_hash().unwrap());
        assert_eq!(hash, doc["terms_hash"].as_str().unwrap(), "{name}");
        assert_eq!(v2::terms_to_json(&t), doc["terms"], "{name}");
        t.validate_structure().unwrap();
    }
}

#[test]
fn the_terms_v2_form_is_strict() {
    let doc = &files("terms_v2")[0].1;
    let mut extra = doc["terms"].clone();
    extra["settlement_mode"] = json!("vault");
    assert_eq!(
        v2::terms_from_json(&extra).unwrap_err().code(),
        "SDK_JSON_FORM"
    );
    let mut long = doc["terms"].clone();
    let leg = long["legs"][0].clone();
    long["legs"] = Value::Array(vec![leg; 11]);
    assert_eq!(
        v2::terms_from_json(&long).unwrap_err().code(),
        "SDK_JSON_FORM"
    );
    // Ten legs is the form's bound; the structure checks judge them.
    let mut ten = doc["terms"].clone();
    ten["legs"] = Value::Array(vec![doc["terms"]["legs"][0].clone(); 10]);
    v2::terms_from_json(&ten).unwrap();
}

#[test]
fn ipst_v2_vectors_read_render_and_pass_the_terms_check() {
    let all = files("ipst_v2");
    assert_eq!(all.len(), 15);
    for (name, doc) in &all {
        let ipst = read(&doc["ipst"]);
        let rendered: Value = serde_json::from_str(&ipst.to_json()).unwrap();
        assert_eq!(rendered, doc["ipst"], "{name}");
        let checked =
            v2::verify_against_terms(&ipst, &json!([ARTIFACT]), NOW, &declared()).unwrap();
        let builder = checked["kind"]["builder"].as_str().unwrap();
        assert!(
            name.contains(builder.split('_').next().unwrap()),
            "{name}: {builder}"
        );
        // Without the artifact a KCC-20 trade is not checked; without a value it is refused.
        if ipst.terms().terms().kcc20_legs() > 0 {
            assert_eq!(
                code(v2::verify_against_terms(
                    &ipst,
                    &json!([]),
                    NOW,
                    &declared()
                )),
                "TX_TOKEN_TEMPLATE"
            );
            assert_eq!(
                code(v2::verify_against_terms(
                    &ipst,
                    &json!([ARTIFACT]),
                    NOW,
                    &json!({})
                )),
                "SDK_VALUE_UNKNOWN"
            );
        }
    }
    // A version 1 document is refused here and read by Ipst.fromJson.
    let v1 = &files("ipst")[0].1;
    assert_eq!(
        code(v2::ipst_from_json(&v1["ipst"].to_string())),
        "IPST_UNSUPPORTED_VERSION"
    );
}

#[test]
fn a_tranche_states_its_quantity_and_refuses_its_faults_with_the_core_codes() {
    let (_, doc) = files("ipst_v2")
        .into_iter()
        .find(|(n, _)| n.starts_with("14-"))
        .unwrap();
    let ipst = read(&doc["ipst"]);
    let t = ipst.terms().terms().clone();
    let inputs = doc["ipst"]["inputs"].as_array().unwrap();
    let legs = json!([
        {
            "kind": "kcc20", "artifact": ARTIFACT,
            "authorizer": utxo_of(&inputs[0]), "escrow": utxo_of(&inputs[2]),
            "amount": t.legs[0].asset.amount.to_string(),
        },
        { "kind": "kas", "vault": utxo_of(&inputs[1]) },
    ]);
    let funding = funding_of(&doc["ipst"], 3, 5, ipst.fee());
    let build = |lots: u64| v2::settle(ipst.terms(), Some(lots), &legs, &funding, NOW, &declared());
    assert!(build(1).is_ok(), "control");
    assert_eq!(code(build(0)), "TX_TRANCHE");
    assert_eq!(code(build(5)), "TX_TRANCHE");
    // Every lot the escrows hold is the final layout, not a tranche.
    assert_eq!(build(4).unwrap().transaction().outputs.len(), 4);
}

#[test]
fn the_settle_builder_rebuilds_the_golden_settles_from_their_inputs() {
    for (name, doc) in files("ipst_v2")
        .into_iter()
        .filter(|(n, _)| n.contains("settle"))
    {
        let ipst = read(&doc["ipst"]);
        let t = ipst.terms().terms().clone();
        let (n, k) = (t.legs.len(), t.kcc20_legs());
        let inputs = doc["ipst"]["inputs"].as_array().unwrap();
        let legs: Vec<Value> = t
            .legs
            .iter()
            .enumerate()
            .map(|(i, l)| match l.asset.kind {
                LegKind::Kas => json!({ "kind": "kas", "vault": utxo_of(&inputs[i]) }),
                _ => json!({
                    "kind": "kcc20",
                    "artifact": ARTIFACT,
                    "authorizer": utxo_of(&inputs[i]),
                    "escrow": utxo_of(&inputs[n + i]),
                    // Vector 15 settles what vector 14's tranche of one lot left.
                    "amount": (l.asset.amount
                        - if name.contains("final") { t.unit(i) } else { 0 })
                    .to_string(),
                }),
            })
            .collect();
        // Vector 14 is a tranche of one lot (spec/V2.md 4.3: 2N + K outputs before the change).
        let lots = name.contains("tranche").then_some(1);
        let outputs = if lots.is_some() { 2 * n + k } else { n + k };
        let funding = funding_of(&doc["ipst"], n + k, outputs, ipst.fee());
        let built =
            v2::settle(ipst.terms(), lots, &json!(legs), &funding, NOW, &declared()).unwrap();
        assert_eq!(built.to_json(), ipst.to_json(), "{name}");
        // The value cap holds before the builder: one sompi under the fee as the cap.
        let fee = ipst.fee();
        assert_eq!(
            code(v2::settle(
                ipst.terms(),
                lots,
                &json!(legs),
                &funding,
                NOW,
                &json!({ "kas_equivalent": "1", "max_value": (fee - 1).to_string() }),
            )),
            "SDK_VALUE_CAP_EXCEEDED"
        );
    }
}

fn leg_of_output(terms: &ValidatedTermsV2, spk: &Value) -> usize {
    (0..terms.terms().legs.len())
        .find(|&i| {
            crate::ops::spk_json(
                &VaultV2::instantiate_existing(terms, i)
                    .unwrap()
                    .script_public_key(),
            ) == *spk
        })
        .expect("a leg's vault")
}

#[test]
fn the_fund_and_refund_builders_rebuild_the_golden_documents() {
    let all = files("ipst_v2");
    let get = |prefix: &str| {
        all.iter()
            .find(|(n, _)| n.starts_with(prefix))
            .unwrap()
            .1
            .clone()
    };
    // 08: a KAS leg funded.
    let doc = get("08-");
    let ipst = read(&doc["ipst"]);
    let terms = ipst.terms().clone();
    let leg = leg_of_output(&terms, &doc["ipst"]["outputs"][0]["script_public_key"]);
    let ctx = json!({ "network": "testnet", "creation_daa": NOW.to_string() });
    let ctx = if terms.terms().network == Network::Mainnet {
        json!({ "network": "mainnet", "creation_daa": NOW.to_string() })
    } else {
        ctx
    };
    let funding = funding_of(&doc["ipst"], 0, 1, ipst.fee());
    let built = v2::fund_kas(&terms, leg, &ctx, &funding, &declared()).unwrap();
    assert_eq!(built.to_json(), ipst.to_json());
    assert_eq!(
        code(v2::fund_kas(&terms, 10, &ctx, &funding, &declared())),
        "TEMPLATE_V2_LEG_INDEX"
    );
    // 05: a KAS leg refunded by the authority.
    let doc = get("05-");
    let ipst = read(&doc["ipst"]);
    let terms = ipst.terms().clone();
    let inputs = doc["ipst"]["inputs"].as_array().unwrap();
    let spk = &inputs[0]["utxo"]["script_public_key"];
    let leg = leg_of_output(&terms, spk);
    let funding = funding_of(&doc["ipst"], 1, 1, ipst.fee());
    let vault = utxo_of(&inputs[0]);
    let built = v2::refund(
        &terms,
        leg,
        &json!("authority"),
        &vault,
        None,
        &funding,
        &declared(),
    )
    .unwrap();
    assert_eq!(built.to_json(), ipst.to_json());
    // The signer form: a leg number or "authority", nothing else.
    for bad in [json!("depositor"), json!(-1), json!(10), json!(null)] {
        assert_eq!(v2::refund_signer(&bad).unwrap_err().code(), "SDK_JSON_FORM");
    }
    assert!(v2::refund_signer(&json!(0)).is_ok());
}

#[test]
fn the_v2_value_cap_counts_the_kas_legs_together() {
    let doc = &files("terms_v2")
        .into_iter()
        .find(|(n, _)| n.starts_with("02-"))
        .unwrap()
        .1;
    let mut t = v2::terms_from_json(&doc["terms"]).unwrap();
    // Every leg KAS, 4 KAS each: 12 KAS together, above the 10 KAS default.
    for l in t.legs.iter_mut() {
        l.asset = impulse_core::terms::Leg {
            kind: LegKind::Kas,
            amount: 400_000_000,
        };
    }
    let decl = |v: Value| crate::value::declaration_from_json(&v).unwrap();
    assert_eq!(
        crate::value::check_v2(&t, &decl(json!({})), 0)
            .unwrap_err()
            .code(),
        "SDK_VALUE_CAP_EXCEEDED"
    );
    crate::value::check_v2(&t, &decl(json!({ "i_accept_the_risk": true })), 0).unwrap();
    t.legs.truncate(2);
    crate::value::check_v2(&t, &decl(json!({})), 0).unwrap();
}

#[test]
fn the_v2_constants_are_the_cores() {
    assert_eq!(
        v2::caps_json(Network::Mainnet),
        json!({ "compute": "450000", "storage": "450000", "transient": "900000" })
    );
    let artifacts = Artifacts::from_json(&json!([ARTIFACT])).unwrap();
    let doc = &files("terms_v2")[0].1;
    let t = v2::terms_from_json(&doc["terms"]).unwrap();
    assert_eq!(artifacts.for_check(&t).unwrap().len(), t.kcc20_legs());
    assert_eq!(
        Artifacts::from_json(&json!(["{}"])).err().unwrap().code(),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(
        Artifacts::from_json(&json!({})).err().unwrap().code(),
        "SDK_JSON_FORM"
    );
}
