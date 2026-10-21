// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Decoder unit tests: a transaction spending the vaults of every golden vector decodes back to
//! its terms, legs and entries; every refusal sits beside an accepted control that differs only
//! in the one fault. The transactions here are shaped, not valid: decoding reads what a
//! transaction reveals and never runs it. tests/engine/verify.rs decodes transactions the real
//! engine accepts.

use super::*;
use crate::terms::golden::{label32, vectors};
use crate::terms::{SettlementMode, Terms};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_consensus_core::tx::{TransactionId, TransactionInput, TransactionOutput};
use proptest::prelude::*;
use silverscript_abi::{decode_runtime_state_script, encode_runtime_state_script, ArtifactValue};

fn checked(t: &Terms) -> ValidatedTerms {
    t.clone().validate_structure().expect("vector terms pass")
}

fn vector(n: usize) -> Terms {
    vectors().remove(n - 1).terms
}

fn script(t: &Terms, leg: LegIndex) -> Vec<u8> {
    Vault::instantiate_existing(&checked(t), leg)
        .expect("vault")
        .redeem_script()
        .to_vec()
}

/// Appends a minimal data push (OP_0, OP_DATA_n, OP_PUSHDATA1, 2 or 4).
fn push(out: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => out.push(0x00),
        n @ 1..=75 => out.push(n as u8),
        n @ 76..=255 => out.extend([0x4c, n as u8]),
        n @ 256..=65_535 => {
            out.push(0x4d);
            out.extend((n as u16).to_le_bytes());
        }
        n => {
            out.push(0x4e);
            out.extend((n as u32).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
}

fn tag(entry: &str) -> [u8; 4] {
    template::check().unwrap().abi().contracts[template::CONTRACT_NAME].entries[entry]
        .dispatch_tag
        .into_bytes()
}

fn sigscript(pushes: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in pushes {
        push(&mut out, p);
    }
    out
}

/// A `settle` call on the vault of `(t, leg)`: authSig, dispatch tag, redeem script.
fn settle_input(t: &Terms, leg: LegIndex) -> Vec<u8> {
    sigscript(&[&[0u8; 65], &tag("settle"), &script(t, leg)])
}

/// A `refund` call naming `signer`.
fn refund_input(t: &Terms, leg: LegIndex, signer: &[u8; 32]) -> Vec<u8> {
    sigscript(&[&[0u8; 65], signer, &tag("refund"), &script(t, leg)])
}

/// A plain P2PK spend: one signature push.
fn plain_input() -> Vec<u8> {
    sigscript(&[&[7u8; 65]])
}

fn tx(sigscripts: Vec<Vec<u8>>) -> Transaction {
    let inputs = sigscripts
        .into_iter()
        .enumerate()
        .map(|(n, s)| {
            let outpoint =
                TransactionOutpoint::new(TransactionId::from_bytes([n as u8 + 1; 32]), 0);
            TransactionInput::new_with_compute_budget(outpoint, s, 0, 100)
        })
        .collect();
    let outputs = vec![TransactionOutput::new(
        1_000,
        ScriptPublicKey::from_vec(0, vec![0x51]),
    )];
    Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![])
}

fn code<T: std::fmt::Debug>(r: Result<T, DecodeError>) -> &'static str {
    r.expect_err("must be refused").code()
}

/// What a node reports each input of a shaped transaction spends: the version 0 P2SH of the
/// script it reveals, else a stand-in P2PK. Honest by construction.
fn honest(tx: &Transaction) -> Vec<ScriptPublicKey> {
    tx.inputs
        .iter()
        .map(|i| match revealed_script(&i.signature_script) {
            Some(script) => pay_to_script_hash_script(script),
            None => ScriptPublicKey::from_vec(0, [&[0x20][..], &[7; 32], &[0xac]].concat()),
        })
        .collect()
}

/// Bound decode against the honest spent scriptPublicKeys.
fn decode(tx: &Transaction, network: Network) -> Result<DecodedTransaction, DecodeError> {
    decode_transaction(tx, &honest(tx), network)
}

/// A canonical settle of vector `t`: the asset vault at input 0, the cash vault (if any) at
/// input 1, then a plain fee input.
fn settle_tx(t: &Terms) -> Transaction {
    let mut inputs = vec![settle_input(t, LegIndex::Asset)];
    if Vault::instantiate_existing(&checked(t), LegIndex::Cash).is_ok() {
        inputs.push(settle_input(t, LegIndex::Cash));
    }
    inputs.push(plain_input());
    tx(inputs)
}

#[test]
fn a_settle_of_every_vault_vector_decodes_to_its_trade() {
    let mut decoded_legs = 0;
    for v in vectors() {
        if v.terms.settlement_mode == SettlementMode::Direct {
            continue;
        }
        let t = &v.terms;
        let tx = settle_tx(t);
        let decoded = decode_raw(&encode_raw(&tx), &honest(&tx), t.network)
            .unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(decoded.txid, tx.id().as_bytes());
        assert!(decoded.bound && decoded.refused.is_empty());
        assert_eq!(decoded, decode(&tx, t.network).unwrap());
        let unbound = decode_raw_unbound(&encode_raw(&tx), t.network).unwrap();
        assert_eq!((unbound.bound, &unbound.legs), (false, &decoded.legs));
        let trades = decoded.trades();
        assert_eq!(trades.len(), 1, "{}", v.name);
        assert_eq!(trades[0].terms, &checked(t));
        for (i, leg) in decoded.legs.iter().enumerate() {
            let expected_leg = [LegIndex::Asset, LegIndex::Cash][i];
            assert_eq!(leg.input_index, i);
            assert_eq!(leg.leg, expected_leg);
            assert_eq!(leg.entry, Entry::Settle);
            assert_eq!(leg.outpoint, tx.inputs[i].previous_outpoint);
            let vault = Vault::instantiate_existing(&checked(t), expected_leg).unwrap();
            assert_eq!(leg.script_hash, vault.script_hash());
            let expected = match expected_leg {
                LegIndex::Asset => Outcome::Delivered {
                    amount: t.asset_leg.amount,
                    to: t.buyer_delivery.clone(),
                },
                LegIndex::Cash => Outcome::Delivered {
                    amount: t.cash_leg.amount,
                    to: t.seller_proceeds.clone(),
                },
            };
            assert_eq!(leg.outcome(), expected);
            decoded_legs += 1;
        }
    }
    assert_eq!(decoded_legs, 16, "every vault of the vectors decoded");
}

#[test]
fn a_refund_names_its_signer_and_goes_home() {
    let t = vector(1);
    let terms = checked(&t);
    let stranger = label32("impulse/tests/decode/stranger");
    let cases = [
        (
            LegIndex::Asset,
            t.seller_key,
            Some(Party::Seller),
            &t.seller_refund,
        ),
        (
            LegIndex::Asset,
            t.authority_key.unwrap(),
            Some(Party::Authority),
            &t.seller_refund,
        ),
        (
            LegIndex::Cash,
            t.seller_key,
            Some(Party::Seller),
            &t.buyer_refund,
        ),
        (
            LegIndex::Cash,
            t.buyer_key,
            Some(Party::Buyer),
            &t.buyer_refund,
        ),
        (LegIndex::Cash, stranger, None, &t.buyer_refund),
    ];
    for (leg, signer, party, home) in cases {
        let tx = tx(vec![refund_input(&t, leg, &signer), plain_input()]);
        let decoded = decode(&tx, t.network).unwrap();
        assert_eq!(decoded.legs.len(), 1);
        let d = &decoded.legs[0];
        assert_eq!((d.leg, &d.terms), (leg, &terms));
        assert_eq!(
            d.entry,
            Entry::Refund {
                signer: Some(signer),
                party
            }
        );
        assert_eq!(d.outcome(), Outcome::Refunded { to: home.clone() });
    }
    // A signer argument that is not a 32-byte key is reported as such.
    let odd = sigscript(&[
        &[0u8; 65],
        &[1, 2, 3],
        &tag("refund"),
        &script(&t, LegIndex::Asset),
    ]);
    let decoded = decode(&tx(vec![odd]), t.network).unwrap();
    assert_eq!(
        decoded.legs[0].entry,
        Entry::Refund {
            signer: None,
            party: None
        }
    );
}

#[test]
fn two_trades_mixed_in_one_settle_are_reported_apart() {
    // The asset vault of vector 1 and the cash vault of vector 3 (spec red team, cross-trade
    // mixing): two trades, one leg each.
    let (a, b) = (vector(1), vector(3));
    let tx = tx(vec![
        settle_input(&a, LegIndex::Asset),
        settle_input(&b, LegIndex::Cash),
    ]);
    let decoded = decode(&tx, a.network).unwrap();
    let trades = decoded.trades();
    assert_eq!(trades.len(), 2);
    assert_eq!(trades[0].terms, &checked(&a));
    assert_eq!(trades[1].terms, &checked(&b));
    assert_eq!(trades[0].legs[0].leg, LegIndex::Asset);
    assert_eq!(trades[1].legs[0].leg, LegIndex::Cash);
}

#[test]
fn raw_bytes_that_are_not_one_transaction_are_refused() {
    let t = vector(1);
    let tx = settle_tx(&t);
    let raw = encode_raw(&tx);
    decode_raw(&raw, &honest(&tx), t.network).expect("control");
    let mut trailing = raw.clone();
    trailing.push(0);
    for bad in [
        &raw[..raw.len() - 1],
        &trailing[..],
        &[][..],
        b"not a transaction",
    ] {
        assert_eq!(
            code(decode_raw(bad, &honest(&tx), t.network)),
            "DECODE_TX_MALFORMED"
        );
        assert_eq!(
            code(decode_raw_unbound(bad, t.network)),
            "DECODE_TX_MALFORMED"
        );
    }
}

#[test]
fn a_transaction_whose_carried_id_is_not_its_own_is_refused() {
    let t = vector(1);
    let tx = settle_tx(&t);
    decode(&tx, t.network).expect("control");
    // The ID is the last field of the borsh encoding.
    let mut raw = encode_raw(&tx);
    let n = raw.len();
    assert_eq!(&raw[n - 32..], &tx.id().as_bytes());
    raw[n - 1] ^= 1;
    assert_eq!(
        code(decode_raw(&raw, &honest(&tx), t.network)),
        "DECODE_TX_ID_MISMATCH"
    );
    // Content changed after the ID was computed.
    let mut edited = tx.clone();
    edited.lock_time += 1;
    assert_eq!(
        decode(&edited, t.network),
        Err(DecodeError::TxIdMismatch {
            carried: tx.id().as_bytes(),
            computed: hashing::tx::id(&edited).as_bytes(),
        })
    );
    assert_eq!(
        code(decode_unbound(&edited, t.network)),
        "DECODE_TX_ID_MISMATCH"
    );
    edited.finalize();
    decode(&edited, t.network).expect("finalized again");
}

#[test]
fn an_input_that_is_not_push_only_is_not_a_vault_spend() {
    // Consensus runs a version 0 P2SH input's signature script push only, so such an input never
    // spends a vault; at an input of a higher script version it is never run at all.
    let t = vector(1);
    let mut inputs = vec![settle_input(&t, LegIndex::Asset), plain_input()];
    let control = decode(&tx(inputs.clone()), t.network).expect("control");
    for bad in [
        vec![0xac],
        vec![0x50],
        vec![0x4c],
        vec![0x4d, 0x01],
        vec![0x05, 1, 2],
    ] {
        inputs[1] = bad.clone();
        let decoded = decode(&tx(inputs.clone()), t.network).expect("skipped");
        assert_eq!(decoded.legs, control.legs, "{bad:02x?}");
        assert!(decoded.refused.is_empty(), "{bad:02x?}");
    }
    // A vault script behind a non-push opcode is not a vault spend either.
    let mut hidden = settle_input(&t, LegIndex::Asset);
    hidden.insert(0, 0xac);
    assert_eq!(
        code(decode(&tx(vec![hidden, plain_input()]), t.network)),
        "DECODE_NO_VAULT_INPUT"
    );
    // Small-integer pushes are pushes.
    inputs[1] = vec![0x51, 0x60, 0x4f];
    decode(&tx(inputs), t.network).expect("small integers");
}

#[test]
fn a_vault_input_must_call_an_entry() {
    let t = vector(1);
    let s = script(&t, LegIndex::Asset);
    decode(&tx(vec![settle_input(&t, LegIndex::Asset)]), t.network).expect("control");
    for bad in [
        sigscript(&[&[0u8; 65], &[0u8; 4], &s]),
        sigscript(&[&[0u8; 65], &tag("settle")[..3], &s]),
        sigscript(&[&s]),
        {
            let mut v = vec![0x51];
            push(&mut v, &s);
            v
        },
    ] {
        assert_eq!(
            decode(&tx(vec![plain_input(), bad]), t.network),
            Err(DecodeError::EntryUnknown { index: 1 })
        );
    }
}

#[test]
fn a_transaction_without_a_vault_input_is_refused() {
    let t = vector(1);
    decode(
        &tx(vec![plain_input(), settle_input(&t, LegIndex::Asset)]),
        t.network,
    )
    .expect("control");
    let not_impulse = sigscript(&[&[0u8; 65], &tag("settle"), &[0x51; 3000]]);
    for inputs in [
        vec![],
        vec![plain_input()],
        vec![vec![]],
        vec![plain_input(), not_impulse],
    ] {
        assert_eq!(
            code(decode(&tx(inputs), t.network)),
            "DECODE_NO_VAULT_INPUT"
        );
    }
}

#[test]
fn a_vault_of_another_network_is_refused() {
    for n in [1, 8] {
        let t = vector(n); // mainnet, then testnet
        let tx = settle_tx(&t);
        decode(&tx, t.network).expect("control");
        let other = match t.network {
            Network::Mainnet => Network::Testnet,
            Network::Testnet => Network::Mainnet,
        };
        let err = decode(&tx, other).unwrap_err();
        assert_eq!(err.code(), "TERMS_NETWORK_MISMATCH");
        assert!(matches!(err, DecodeError::Input { index: 0, .. }));
    }
}

#[test]
fn a_vault_script_impulse_refuses_keeps_its_code() {
    let t = vector(1);
    let good = script(&t, LegIndex::Asset);
    let call = |s: &[u8]| sigscript(&[&[0u8; 65], &tag("settle"), s]);
    decode(&tx(vec![plain_input(), call(&good)]), t.network).expect("control");
    let err = decode(&tx(vec![plain_input(), call(&version_2(&good))]), t.network).unwrap_err();
    assert_eq!(err.code(), "TERMS_UNSUPPORTED_VERSION");
    assert!(matches!(err, DecodeError::Input { index: 1, .. }));
}

#[test]
fn revealed_script_is_the_last_data_push() {
    let s = script(&vector(1), LegIndex::Asset);
    assert_eq!(
        revealed_script(&settle_input(&vector(1), LegIndex::Asset)),
        Some(&s[..])
    );
    assert_eq!(revealed_script(&[]), None);
    assert_eq!(revealed_script(&[0x51]), None); // a small integer is not a script
    assert_eq!(revealed_script(&[0xac, 0x01, 0x01]), None); // not push only
}

// The push parser, with the tests of the borrowed last-push helper.

#[test]
fn pushes_recovers_a_simple_push() {
    let script = [0x03, b'a', b'b', b'c'];
    assert_eq!(pushes(&script), Some(vec![Some(&b"abc"[..])]));
}

#[test]
fn pushes_recovers_the_final_of_several_pushes() {
    let mut script = vec![0x02, b'h', b'i'];
    script.extend_from_slice(&[0x03, b'a', b'b', b'c']);
    assert_eq!(revealed_script(&script), Some(&b"abc"[..]));
}

#[test]
fn pushes_handles_pushdata1_2_and_4() {
    let data76 = vec![0xAB; 76];
    let mut script = vec![0x4c, 76];
    script.extend_from_slice(&data76);
    assert_eq!(revealed_script(&script), Some(data76.as_slice()));

    let data300 = vec![0xCD; 300];
    let mut script2 = vec![0x4d, 44, 1]; // 300 = 0x012C, little-endian
    script2.extend_from_slice(&data300);
    assert_eq!(revealed_script(&script2), Some(data300.as_slice()));

    let mut script4 = vec![0x4e, 44, 1, 0, 0];
    script4.extend_from_slice(&data300);
    assert_eq!(revealed_script(&script4), Some(data300.as_slice()));
}

#[test]
fn pushes_none_for_truncated_or_non_push_scripts() {
    assert_eq!(pushes(&[]), Some(vec![]));
    assert_eq!(pushes(&[0x0a, 0x01, 0x02]), None); // claims 10 bytes, holds 2
    assert_eq!(pushes(&[0x4e, 0xff, 0xff, 0xff, 0xff]), None);
    assert_eq!(pushes(&[0x00, 0x76]), None); // OP_DUP
}

#[test]
fn decode_error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; this list may only grow at the end.
    assert_eq!(
        DECODE_ERROR_CODES,
        [
            "DECODE_TX_MALFORMED",
            "DECODE_TX_ID_MISMATCH",
            "DECODE_ENTRY_UNKNOWN",
            "DECODE_NO_VAULT_INPUT",
            "DECODE_SPENT_COUNT",
            "DECODE_INPUT_NOT_VAULT",
        ]
    );
    let all = [
        DecodeError::TxMalformed { reason: "r".into() },
        DecodeError::TxIdMismatch {
            carried: [0; 32],
            computed: [1; 32],
        },
        DecodeError::EntryUnknown { index: 0 },
        DecodeError::NoVaultInput,
        DecodeError::SpentCount {
            inputs: 2,
            spent: 1,
        },
        DecodeError::InputNotVault { index: 0 },
    ];
    let codes: Vec<&str> = all.iter().map(DecodeError::code).collect();
    assert_eq!(codes, DECODE_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()), "{e}");
    }
    let wrapped = DecodeError::Input {
        index: 2,
        error: template::TemplateError::NonCanonical,
    };
    assert_eq!(wrapped.code(), "TEMPLATE_NONCANONICAL");
}

// ---------------------------------------------------------------------------------------------
// Binding each vault input to the UTXO it spends (review round 1, HIGH 1)
// ---------------------------------------------------------------------------------------------

/// `script` with its version push set to 2 (state bytes 1 and 2): a script of the template that
/// Impulse refuses (`TERMS_UNSUPPORTED_VERSION`).
fn version_2(script: &[u8]) -> Vec<u8> {
    let mut v2 = script.to_vec();
    assert_eq!(&v2[1..3], &[0x01, 0x01]);
    v2[2] = 0x02;
    v2
}

#[test]
fn a_swapped_signature_script_keeps_the_id_and_is_refused_when_bound() {
    let (a, b) = (vector(1), vector(3));
    let honest_tx = settle_tx(&a);
    let spent = honest(&honest_tx);
    let control = decode_transaction(&honest_tx, &spent, a.network).expect("control");
    assert_eq!(control.legs.len(), 2);

    // Input 0 now reveals trade b's asset vault. The ID does not commit to signature scripts.
    let mut forged = honest_tx.clone();
    forged.inputs[0].signature_script = settle_input(&b, LegIndex::Asset);
    forged.finalize();
    assert_eq!(forged.id(), honest_tx.id());
    // Unbound, the forgery reads as trade b: what decode_unbound reports is only the source's.
    let unbound = decode_unbound(&forged, a.network).unwrap();
    assert_eq!(unbound.legs[0].terms, checked(&b));
    assert!(!unbound.bound);
    // Bound to what input 0 really spends (trade a's asset vault), it is refused; the honest
    // cash leg still decodes.
    let bound = decode_transaction(&forged, &spent, a.network).unwrap();
    assert_eq!(bound.refused, vec![DecodeError::InputNotVault { index: 0 }]);
    assert_eq!(bound.legs, control.legs[1..]);
    assert_eq!(code(bound.strict()), "DECODE_INPUT_NOT_VAULT");
}

#[test]
fn a_vault_script_on_an_input_consensus_does_not_run_is_refused() {
    // rusty-kaspa a41a333 accepts an input whose spent scriptPublicKey has a version above 0
    // without running its signature script (AcceptedUnknownVersion), so a vault script revealed
    // there proves nothing. Only the version 0 P2SH of the script itself binds it.
    let t = vector(1);
    let tx = tx(vec![settle_input(&t, LegIndex::Asset), plain_input()]);
    let mut spent = honest(&tx);
    let vault = Vault::instantiate_existing(&checked(&t), LegIndex::Asset).unwrap();
    assert_eq!(spent[0], vault.script_public_key());
    decode_transaction(&tx, &spent, t.network).expect("control: version 0 P2SH");
    let p2sh = spent[0].script().to_vec();
    let other_vault = Vault::instantiate_existing(&checked(&vector(3)), LegIndex::Asset).unwrap();
    for wrong in [
        ScriptPublicKey::from_vec(1, p2sh.clone()),
        ScriptPublicKey::from_vec(u16::MAX, p2sh),
        other_vault.script_public_key(),
        spent[1].clone(),
    ] {
        spent[0] = wrong.clone();
        assert_eq!(
            decode_transaction(&tx, &spent, t.network),
            Err(DecodeError::InputNotVault { index: 0 }),
            "{wrong:?}"
        );
    }
}

#[test]
fn the_spent_script_public_keys_must_be_one_per_input() {
    let t = vector(1);
    let tx = settle_tx(&t);
    let spent = honest(&tx);
    decode_transaction(&tx, &spent, t.network).expect("control");
    for n in [0, spent.len() - 1, spent.len() + 1] {
        let mut s = spent.clone();
        s.resize(n, spent[0].clone());
        assert_eq!(
            decode_transaction(&tx, &s, t.network),
            Err(DecodeError::SpentCount {
                inputs: spent.len(),
                spent: n
            })
        );
    }
}

// ---------------------------------------------------------------------------------------------
// One refused input does not hide the others (review round 1, MEDIUM 4)
// ---------------------------------------------------------------------------------------------

/// The cash-vault script of external-cash terms (vector 5): the asset vault relabelled as leg 1,
/// which Impulse never makes and refuses to decode (`TEMPLATE_NO_VAULT`).
fn external_cash_vault_script() -> Vec<u8> {
    let template = template::check().unwrap();
    let asset = script(&vector(5), LegIndex::Asset);
    let (p, s) = (template.prefix().len(), template.suffix().len());
    let abi = template.abi();
    let state_artifact = &abi.contracts[template::CONTRACT_NAME].runtime_state;
    let mut values =
        decode_runtime_state_script(abi, state_artifact, &asset[p..asset.len() - s]).unwrap();
    values.insert("legIndex".into(), ArtifactValue::Int(1));
    let state = encode_runtime_state_script(abi, state_artifact, &values).unwrap();
    [template.prefix(), &state, template.suffix()].concat()
}

#[test]
fn a_poison_vault_input_beside_a_real_settle_hides_nothing() {
    let t = vector(1);
    let settle = settle_tx(&t);
    let control = decode(&settle, t.network).expect("control");
    assert!(control.refused.is_empty());
    let testnet = vector(8);
    let call = |s: &[u8]| sigscript(&[&[0u8; 65], &tag("settle"), s]);
    let poisons = [
        (
            call(&version_2(&script(&t, LegIndex::Asset))),
            "TERMS_UNSUPPORTED_VERSION",
        ),
        (
            settle_input(&testnet, LegIndex::Asset),
            "TERMS_NETWORK_MISMATCH",
        ),
        (call(&external_cash_vault_script()), "TEMPLATE_NO_VAULT"),
        (
            sigscript(&[&[0u8; 65], &[0u8; 4], &script(&t, LegIndex::Asset)]),
            "DECODE_ENTRY_UNKNOWN",
        ),
    ];
    for (poison, expected) in poisons {
        let mut sigscripts: Vec<Vec<u8>> = settle
            .inputs
            .iter()
            .map(|i| i.signature_script.clone())
            .collect();
        sigscripts.push(poison);
        let poisoned = tx(sigscripts);
        let index = poisoned.inputs.len() - 1;
        for decoded in [
            decode(&poisoned, t.network).unwrap(),
            decode_unbound(&poisoned, t.network).unwrap(),
        ] {
            // The trade's legs are still reported, with the poison refused beside them.
            let legs: Vec<_> = decoded.legs.iter().map(|l| (l.leg, &l.terms)).collect();
            let expected_legs: Vec<_> = control.legs.iter().map(|l| (l.leg, &l.terms)).collect();
            assert_eq!(legs, expected_legs, "{expected}");
            assert_eq!(decoded.refused.len(), 1, "{expected}");
            assert_eq!(decoded.refused[0].code(), expected);
            assert_eq!(decoded.refused[0].input_index(), Some(index));
            assert_eq!(code(decoded.strict()), expected);
        }
    }
    // Alone, the poison is the refusal.
    let alone = tx(vec![call(&external_cash_vault_script())]);
    assert_eq!(code(decode(&alone, t.network)), "TEMPLATE_NO_VAULT");
}

// ---------------------------------------------------------------------------------------------
// Push boundaries (review round 1, MEDIUM 5)
// ---------------------------------------------------------------------------------------------

#[test]
fn pushes_at_every_length_boundary() {
    for (n, opcode) in [
        (0usize, 0x00u8),
        (1, 0x01),
        (75, 0x4b),
        (76, 0x4c),
        (255, 0x4c),
        (256, 0x4d),
        (65_535, 0x4d),
        (65_536, 0x4e),
    ] {
        let data = vec![0xAB; n];
        let mut script = Vec::new();
        push(&mut script, &data);
        assert_eq!(script[0], opcode, "{n}");
        assert_eq!(pushes(&script), Some(vec![Some(&data[..])]), "{n}");
        if n > 0 {
            // One byte short of the declared length.
            assert_eq!(pushes(&script[..script.len() - 1]), None, "{n}");
        }
        // The length field cut short.
        let header = script.len() - n;
        if header > 1 {
            assert_eq!(pushes(&script[..header - 1]), None, "{n}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A committed raw transaction (review round 1, MEDIUM 5)
// ---------------------------------------------------------------------------------------------

/// The canonical shaped settle of vector 1 in the raw form, committed: the bytes are fixed by
/// the vector and rusty-kaspa a41a333's borsh encoding, so a change to either fails here.
const SETTLE_01_HEX: &str = include_str!("fixtures/settle-vector-01.hex");

#[test]
fn the_committed_raw_settle_decodes_to_vector_1() {
    let t = vector(1);
    let tx = settle_tx(&t);
    let raw: Vec<u8> = (0..SETTLE_01_HEX.trim().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&SETTLE_01_HEX.trim()[i..i + 2], 16).unwrap())
        .collect();
    let hex: String = encode_raw(&tx).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, SETTLE_01_HEX.trim(), "the raw form changed");
    let decoded = decode_raw(&raw, &honest(&tx), Network::Mainnet).unwrap();
    assert_eq!(decoded.txid, tx.id().as_bytes());
    let terms = checked(&t);
    let got: Vec<_> = decoded
        .legs
        .iter()
        .map(|l| (l.input_index, l.leg, &l.terms, l.entry, l.script_hash))
        .collect();
    let vault = |leg| {
        Vault::instantiate_existing(&terms, leg)
            .unwrap()
            .script_hash()
    };
    assert_eq!(
        got,
        vec![
            (
                0,
                LegIndex::Asset,
                &terms,
                Entry::Settle,
                vault(LegIndex::Asset)
            ),
            (
                1,
                LegIndex::Cash,
                &terms,
                Entry::Settle,
                vault(LegIndex::Cash)
            ),
        ]
    );
    assert!(decoded.refused.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Properties (review round 1, MEDIUM 5)
// ---------------------------------------------------------------------------------------------

/// Every code a decode can return: the decode codes, and the template and terms codes a vault
/// input keeps.
fn known(code: &str) -> bool {
    DECODE_ERROR_CODES.contains(&code)
        || template::TEMPLATE_ERROR_CODES.contains(&code)
        || crate::terms::TERMS_ERROR_CODES.contains(&code)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn pushes_never_panic_and_round_trip(
        bytes in proptest::collection::vec(any::<u8>(), 0..400),
        data in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..6),
    ) {
        let _ = pushes(&bytes);
        let _ = revealed_script(&bytes);
        let mut script = Vec::new();
        for d in &data {
            push(&mut script, d);
        }
        let parsed = pushes(&script).expect("pushes parse");
        let expected: Vec<Option<&[u8]>> = data.iter().map(|d| Some(&d[..])).collect();
        prop_assert_eq!(parsed, expected);
    }

    #[test]
    fn arbitrary_bytes_decode_to_a_frozen_code(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Err(e) = decode_raw_unbound(&bytes, Network::Mainnet) {
            prop_assert!(known(e.code()), "{}", e.code());
        }
    }

    /// One byte of the raw settle changed: decode, bound to what the inputs really spend, either
    /// refuses with a frozen code or reports only vaults the inputs spend.
    #[test]
    fn a_changed_byte_never_decodes_to_a_vault_not_spent(position in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let t = vector(1);
        let tx = settle_tx(&t);
        let spent = honest(&tx);
        let control = decode(&tx, t.network).unwrap();
        let mut raw = encode_raw(&tx);
        let i = position.index(raw.len());
        raw[i] ^= mask;
        match decode_raw(&raw, &spent, t.network) {
            Err(e) => prop_assert!(known(e.code()), "{}", e.code()),
            Ok(d) => {
                for leg in &d.legs {
                    let honest_leg = control.legs.iter().find(|l| l.input_index == leg.input_index);
                    let honest_leg = honest_leg.expect("a vault input of the original");
                    prop_assert_eq!(
                        (leg.leg, &leg.terms, leg.script_hash),
                        (honest_leg.leg, &honest_leg.terms, honest_leg.script_hash)
                    );
                }
                for e in &d.refused {
                    prop_assert!(known(e.code()), "{}", e.code());
                }
            }
        }
    }
}
