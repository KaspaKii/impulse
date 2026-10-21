// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Native tests of the phase 2 operations (`ops.rs`) and the driver of the TypeScript oracle test.
//!
//! The operations are impulse-core's, called with JSON values. These tests run them on the host:
//! every committed IPST vector is read, rendered, and rebuilt by the builders; the forms of the
//! builder inputs refuse what breaks them beside accepted controls. The oracle driver runs the
//! same operations on requests the TypeScript suite writes, so that what the wasm module computes
//! from runtime data is compared with what the host build computes from the same data.
//!
//! Keyless: no key, throwaway or other, appears here. A signature arrives in an oracle request,
//! made by the TypeScript test.

use crate::error::Failure;
use crate::forms;
use crate::json::{hex, hex_decode, Obj};
use crate::ops;
use impulse_core::template::LegIndex;
use impulse_core::terms::ValidatedTerms;
use impulse_core::tx::{Ipst, IPST_VERSION};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const ASSET_ARTIFACT: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-asset.json");
const CASH_ARTIFACT: &str = include_str!("../../impulse-core/src/tx/testdata/kcc20-cash.json");

/// The DAA score the golden IPST vectors were built at (impulse-core `tx::testkit::NOW`).
const NOW: u64 = 1_500_000;

/// A declared value within the cap, for the calls that take one.
fn declared() -> Value {
    json!({ "kas_equivalent": "1" })
}

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/ipst")
}

/// (file name, file text) of every committed IPST vector.
fn vector_files() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(vector_dir())
        .expect("read tests/vectors/ipst")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).expect("read vector"),
            )
        })
        .collect();
    out.sort();
    out
}

/// The `ipst` object of a vector file as text, de-indented by the two spaces it sits at in the
/// file, so that it equals `Ipst::to_json()` exactly.
fn embedded_ipst(file: &str) -> String {
    let start = file.find("\"ipst\": {").expect("ipst key") + "\"ipst\": ".len();
    let body = &file[start..];
    let end = body.rfind("\n}").expect("closing brace of the file");
    let mut out = String::new();
    for (i, line) in body[..end].lines().enumerate() {
        if i > 0 {
            out.push_str(line.strip_prefix("  ").unwrap_or(line));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_committed_ipst_vectors_read_render_and_rebuild_byte_for_byte() {
    let files = vector_files();
    assert_eq!(files.len(), 13, "the thirteen IPST vectors of I5");
    let artifacts = json!({ "asset": ASSET_ARTIFACT, "cash": CASH_ARTIFACT });
    for (name, file) in files {
        let text = embedded_ipst(&file);
        let ipst = Ipst::from_json(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(ipst.to_json(), text, "{name}: canonical rendering");
        // Reading recomputed every sighash. The terms check rebuilds the transaction with the
        // builders from the document's own inputs and compares all but the signatures.
        let matched = ops::verify_against_terms(&ipst, &artifacts, NOW, &declared())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let builder = matched["kind"]["builder"]
            .as_str()
            .unwrap()
            .replace('_', "-");
        assert!(
            name.contains(&builder),
            "{name}: the terms check names the builder {builder}"
        );
        assert_eq!(matched["fee"], "5000000", "{name}: the fee the vectors pay");
    }
}

#[test]
fn a_changed_ipst_vector_is_refused_where_it_is_read_or_checked() {
    let (name, file) = vector_files().into_iter().next().unwrap();
    let text = embedded_ipst(&file);
    let artifacts = json!({ "asset": ASSET_ARTIFACT, "cash": CASH_ARTIFACT });
    // Control: the vector as committed reads and is the builders' transaction.
    let ipst = Ipst::from_json(&text).unwrap();
    assert!(
        ops::verify_against_terms(&ipst, &artifacts, NOW, &declared()).is_ok(),
        "{name}"
    );
    // One sompi off an output: the stated sighash is no longer the transaction's.
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    let value = doc["outputs"][0]["value"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    doc["outputs"][0]["value"] = Value::String((value - 1).to_string());
    let err = Ipst::from_json(&doc.to_string()).unwrap_err();
    assert_eq!(err.code(), "IPST_SIGHASH_MISMATCH", "{err}");
    // A compute budget one unit higher: no sighash covers it, so the document reads, and only
    // the terms check sees that the builders do not make it.
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    let budget = doc["inputs"][0]["compute_budget"].as_u64().unwrap();
    doc["inputs"][0]["compute_budget"] = json!(budget + 1);
    let raised = Ipst::from_json(&doc.to_string()).expect("a well-formed document");
    let err = ops::verify_against_terms(&raised, &artifacts, NOW, &declared()).unwrap_err();
    assert_eq!(code(&err), "IPST_TERMS_MISMATCH", "{err}");
}

fn code(f: &Failure) -> &'static str {
    use crate::error::Refusal;
    f.code()
}

fn obj<'a>(v: &'a Value, path: &str) -> Obj<'a> {
    Obj::new(v, path).expect("an object")
}

fn utxo_json() -> Value {
    json!({
        "transaction_id": "11".repeat(32),
        "index": 3,
        "amount": "100000000",
        "script_public_key": { "version": 0, "script": format!("20{}ac", "22".repeat(32)) },
        "block_daa_score": "100",
        "is_coinbase": false,
        "covenant_id": null,
    })
}

#[test]
fn a_utxo_form_reads_and_every_break_of_it_is_refused() {
    let good = utxo_json();
    let utxo = forms::utxo(obj(&good, "utxo")).expect("control");
    assert_eq!(utxo.outpoint.index, 3);
    assert_eq!(utxo.entry.amount, 100_000_000);
    assert_eq!(utxo.entry.script_public_key.version(), 0);
    assert!(utxo.entry.covenant_id.is_none());

    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        edit(&mut v);
        forms::utxo(obj(&v, "utxo")).unwrap_err().code()
    };
    for key in [
        "transaction_id",
        "index",
        "amount",
        "script_public_key",
        "block_daa_score",
        "is_coinbase",
        "covenant_id",
    ] {
        assert_eq!(
            refused(&|v| {
                v.as_object_mut().unwrap().remove(key);
            }),
            "SDK_JSON_FORM",
            "missing {key}"
        );
    }
    assert_eq!(refused(&|v| v["extra"] = json!(1)), "SDK_JSON_FORM");
    assert_eq!(refused(&|v| v["amount"] = json!(5)), "SDK_JSON_FORM");
    assert_eq!(refused(&|v| v["amount"] = json!("05")), "SDK_JSON_FORM");
    assert_eq!(
        refused(&|v| v["index"] = json!(4294967296u64)),
        "SDK_JSON_FORM"
    );
    assert_eq!(refused(&|v| v["index"] = json!(-1)), "SDK_JSON_FORM");
    assert_eq!(
        refused(&|v| v["transaction_id"] = json!("AB".repeat(32))),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        refused(&|v| v["transaction_id"] = json!("11".repeat(31))),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        refused(&|v| v["is_coinbase"] = json!("false")),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        refused(&|v| v["covenant_id"] = json!("zz")),
        "SDK_JSON_FORM"
    );
    assert_eq!(
        refused(&|v| v["script_public_key"]["version"] = json!(65536)),
        "SDK_JSON_FORM"
    );
    // A covenant ID, spelled right, is read.
    let mut with = good.clone();
    with["covenant_id"] = json!("a5".repeat(32));
    assert!(forms::utxo(obj(&with, "utxo"))
        .unwrap()
        .entry
        .covenant_id
        .is_some());
}

#[test]
fn a_fee_payment_form_is_strict_and_bounded() {
    let good = json!({ "inputs": [utxo_json()], "fee": "5000000", "change": { "version": 0, "script": "ab" } });
    assert!(forms::fee_payment(&good).is_ok(), "control");
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        edit(&mut v);
        forms::fee_payment(&v).unwrap_err().code()
    };
    assert_eq!(refused(&|v| v["fee"] = json!(5)), "SDK_JSON_FORM");
    assert_eq!(refused(&|v| v["inputs"] = json!({})), "SDK_JSON_FORM");
    assert_eq!(refused(&|v| v["inputs"] = json!([5])), "SDK_JSON_FORM");
    assert_eq!(
        refused(&|v| v["change"]["extra"] = json!(1)),
        "SDK_JSON_FORM"
    );
    assert_eq!(refused(&|v| v["note"] = json!("x")), "SDK_JSON_FORM");
    // 256 inputs read; 257 do not.
    let many = |n: usize| {
        let mut v = good.clone();
        v["inputs"] = Value::Array(vec![utxo_json(); n]);
        forms::fee_payment(&v)
    };
    assert!(many(forms::MAX_ARRAY).is_ok(), "control: at the bound");
    assert_eq!(
        many(forms::MAX_ARRAY + 1).unwrap_err().code(),
        "SDK_JSON_FORM"
    );
}

#[test]
fn a_kcc20_artifact_longer_than_the_bound_is_refused_unparsed() {
    assert!(
        forms::template("artifact", ASSET_ARTIFACT).is_ok(),
        "control"
    );
    let long = " ".repeat(impulse_core::verify::MAX_TOKEN_ARTIFACT_LEN + 1);
    let err = forms::template("artifact", &long).unwrap_err();
    assert_eq!(code(&err), "SDK_JSON_FORM");
    let junk = forms::template("artifact", "{}").unwrap_err();
    assert_eq!(code(&junk), "TX_TOKEN_TEMPLATE");
}

#[test]
fn signature_and_refund_signer_forms() {
    let ok = json!([{ "input": 0, "signature": "ab" }, { "input": 2, "signature": "" }]);
    assert_eq!(
        forms::signatures(&ok).unwrap(),
        vec![(0, vec![0xab]), (2, vec![])]
    );
    for bad in [
        json!({}),
        json!([{ "input": -1, "signature": "ab" }]),
        json!([{ "input": 0, "signature": "AB" }]),
        json!([{ "input": 0, "signature": "ab", "x": 1 }]),
        json!([{ "signature": "ab" }]),
    ] {
        assert_eq!(forms::signatures(&bad).unwrap_err().code(), "SDK_JSON_FORM");
    }
    for name in ["depositor", "counterparty", "authority"] {
        assert!(forms::refund_signer(name).is_ok(), "{name}");
    }
    for name in ["Depositor", "seller", ""] {
        assert_eq!(
            forms::refund_signer(name).unwrap_err().code(),
            "SDK_JSON_FORM"
        );
    }
}

#[test]
fn the_template_functions_name_the_fixture_tokens() {
    let t = ops::kcc20_template(ASSET_ARTIFACT).unwrap();
    assert_eq!(t["template_hash"].as_str().unwrap().len(), 64);
    assert!(t["template_prefix_len"].as_u64().unwrap() > 0);
    let state = json!({
        "identifier_type": "pubkey",
        "identifier": "33".repeat(32),
        "amount": "1000",
        "is_minter": false,
    });
    let spk = ops::kcc20_script_public_key(ASSET_ARTIFACT, &state).unwrap();
    // A P2SH scriptPublicKey: version 0, OpBlake2b OpData32 <hash> OpEqual.
    assert_eq!(spk["version"], 0);
    let script = spk["script"].as_str().unwrap();
    assert!(script.starts_with("aa20") && script.ends_with("87") && script.len() == 70);
    // Another state is another script (control for the first).
    let mut other = state.clone();
    other["amount"] = json!("1001");
    assert_ne!(
        ops::kcc20_script_public_key(ASSET_ARTIFACT, &other).unwrap(),
        spk
    );
    // A different token is a different template.
    assert_ne!(ops::kcc20_template(CASH_ARTIFACT).unwrap(), t);
}

/// Vector 02's IPST with `inputs` inputs and `outputs` outputs, none of them signed, so that
/// reading it recomputes no sighash: the first input and output repeated under other outpoints,
/// each output holding 1 sompi.
fn ipst_with_counts(inputs: usize, outputs: usize) -> String {
    let file = vector_files()
        .into_iter()
        .find(|(name, _)| name.starts_with("02-"))
        .unwrap()
        .1;
    let mut doc: Value = serde_json::from_str(&embedded_ipst(&file)).unwrap();
    let mut input = doc["inputs"][0].clone();
    input["signer"] = Value::Null;
    input["sighash"] = Value::Null;
    let many: Vec<Value> = (0..inputs)
        .map(|n| {
            let mut i = input.clone();
            i["transaction_id"] = json!(hex(&[n as u8, (n >> 8) as u8, 7, 7].repeat(8)));
            i
        })
        .collect();
    doc["inputs"] = Value::Array(many);
    let mut output = doc["outputs"][0].clone();
    output["value"] = json!("1");
    doc["outputs"] = Value::Array(vec![output; outputs]);
    doc.to_string()
}

#[test]
fn an_ipst_text_is_bounded_in_inputs_and_outputs_before_it_is_read() {
    let at = ops::MAX_IPST_ENTRIES;
    // Control: at the bound, both counts at once, the reader is reached and accepts.
    for text in [ipst_with_counts(at, 1), ipst_with_counts(1, at)] {
        assert!(ops::ipst_from_json(&text, "ipst").is_ok(), "control");
    }
    // One over, in either count: refused with the SDK's code, naming the count.
    for (text, what) in [
        (ipst_with_counts(at + 1, 1), "inputs"),
        (ipst_with_counts(1, at + 1), "outputs"),
    ] {
        let err = ops::ipst_from_json(&text, "ipst").unwrap_err();
        assert_eq!(code(&err), "SDK_JSON_FORM", "{err}");
        assert!(err.to_string().contains(what), "{err}");
    }
    // Far over (the review's hostile document had 11,000 inputs): refused without the quadratic
    // work, which is the point of checking first.
    let started = std::time::Instant::now();
    let err = ops::ipst_from_json(&ipst_with_counts(11_000, 1), "ipst").unwrap_err();
    assert_eq!(code(&err), "SDK_JSON_FORM");
    assert!(
        started.elapsed().as_secs() < 60,
        "refused without doing work proportional to the input"
    );
    // A text the scan cannot read, and an object without the arrays, are impulse-core's to refuse.
    for text in ["{", "[]", "{\"inputs\": 5}", "{\"ipst\": 1}"] {
        let err = ops::ipst_from_json(text, "ipst").unwrap_err();
        assert_eq!(code(&err), "IPST_MALFORMED", "{text}: {err}");
    }
    // combine reads the other document through the same check.
    let ipst = ops::ipst_from_json(&ipst_with_counts(1, 1), "ipst").unwrap();
    let err = ops::combine(&ipst, &ipst_with_counts(at + 1, 1)).unwrap_err();
    assert_eq!(code(&err), "SDK_JSON_FORM", "{err}");
    let err = ops::combine(&ipst, &ipst_with_counts(at, 1)).unwrap_err();
    assert_ne!(
        code(&err),
        "SDK_JSON_FORM",
        "control: the other document is read: {err}"
    );
}

#[test]
fn ipst_version_is_the_cores() {
    assert_eq!(IPST_VERSION, 1);
}

// The oracle driver. The TypeScript suite writes a request file, runs this test with
// IMPULSE_ORACLE_IN and IMPULSE_ORACLE_OUT set, and compares the answers with the wasm module's.

fn terms_of(step: &Value) -> ValidatedTerms {
    let bytes = hex_decode(step["terms"].as_str().expect("terms hex")).expect("hex");
    ValidatedTerms::decode(&bytes).expect("the terms decode")
}

fn run(step: &Value) -> Result<Value, Failure> {
    let args = step["args"].as_array().expect("args");
    let arg = |i: usize| &args[i];
    let leg = |i: usize| LegIndex::from_index(args[i].as_i64().expect("leg")).expect("leg index");
    let daa = |i: usize| -> u64 { args[i].as_str().expect("daa").parse().expect("u64") };
    let ipst_json = |ipst: &Ipst| Value::String(ipst.to_json());
    let signed = |tx: &kaspa_consensus_core::tx::Transaction| {
        let (txid, raw) = ops::signed(tx);
        json!({ "txid": hex(&txid), "raw": hex(&raw) })
    };
    let op = step["op"].as_str().expect("op");
    match op {
        "fundKas" => ops::fund_kas(&terms_of(step), arg(0), arg(1), arg(2)).map(|i| ipst_json(&i)),
        "fundKcc20" => ops::fund_kcc20(&terms_of(step), leg(0), arg(1), arg(2), arg(3), arg(4))
            .map(|i| ipst_json(&i)),
        "settle" => {
            ops::settle(&terms_of(step), arg(0), arg(1), daa(2), arg(3)).map(|i| ipst_json(&i))
        }
        "refund" => ops::refund(
            &terms_of(step),
            leg(0),
            arg(1).as_str().expect("signer"),
            arg(2),
            (!arg(3).is_null()).then(|| arg(3)),
            arg(4),
            arg(5),
        )
        .map(|i| ipst_json(&i)),
        "direct" => {
            ops::direct(&terms_of(step), arg(0), arg(1), daa(2), arg(3)).map(|i| ipst_json(&i))
        }
        "combine" => {
            let ipst = Ipst::from_json(arg(0).as_str().expect("ipst")).map_err(Failure::from)?;
            ops::combine(&ipst, arg(1).as_str().expect("other")).map(|i| ipst_json(&i))
        }
        "assemble" => {
            let ipst = Ipst::from_json(arg(0).as_str().expect("ipst")).map_err(Failure::from)?;
            ops::assemble(&ipst, arg(1)).map(|tx| signed(&tx))
        }
        "verifyAgainstTerms" => {
            let ipst = Ipst::from_json(arg(0).as_str().expect("ipst")).map_err(Failure::from)?;
            ops::verify_against_terms(&ipst, arg(1), daa(2), arg(3))
        }
        "verifyAddresses" => ops::verify_addresses(&terms_of(step), arg(0), arg(1), arg(2)),
        "beforeFunding" => ops::before_funding(&terms_of(step), arg(0), arg(1), arg(2), arg(3)),
        "decodeRaw" => {
            let raw = hex_decode(arg(0).as_str().expect("raw")).expect("hex");
            let network = crate::json::network_from_json(arg(2).as_str().expect("network"))?;
            ops::decode_raw(&raw, arg(1), network)
        }
        other => panic!("the oracle has no operation {other}"),
    }
}

/// Runs every request and writes the answers: `{ id, ok }` or `{ id, err, message }`.
#[test]
#[ignore = "driver of the TypeScript oracle test (IMPULSE_ORACLE_IN, IMPULSE_ORACLE_OUT)"]
fn oracle() {
    use crate::error::Refusal;
    let input = std::env::var("IMPULSE_ORACLE_IN").expect("IMPULSE_ORACLE_IN is set");
    let output = std::env::var("IMPULSE_ORACLE_OUT").expect("IMPULSE_ORACLE_OUT is set");
    let steps: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(input).expect("read the requests"))
            .expect("the requests parse");
    let answers: Vec<Value> = steps
        .iter()
        .map(|step| match run(step) {
            Ok(ok) => json!({ "id": step["id"], "ok": ok }),
            Err(e) => json!({ "id": step["id"], "err": e.code(), "message": e.to_string() }),
        })
        .collect();
    std::fs::write(output, Value::Array(answers).to_string()).expect("write the answers");
}
