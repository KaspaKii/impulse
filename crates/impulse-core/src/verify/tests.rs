// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Verifier unit tests. The `exit_*` tests are the I6 exit test: tampered amount, tampered
//! destination, swapped template, wrong network and reordered legs each fail closed with the
//! expected code, and every committed vault vector passes. Every other refusal sits beside an
//! accepted control that differs only in the one fault.

use super::*;
use crate::template::check;
use crate::terms::golden::{authority, buyer, label32, seller, unhex, vectors, CREATION_DAA};
use crate::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms,
};
use kaspa_addresses::Prefix;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput, TransactionOutpoint};
use kaspa_txscript::pay_to_script_hash_script;
use proptest::prelude::*;
use serde_json::json;
use serde_json::Value;
use silverscript_abi::{
    encode_runtime_state_script, template_hash, ArtifactValue, CompiledContractArtifact,
    RuntimeFieldArtifact, RuntimeStateArtifact, SilAbiArtifact, SilContractArtifact,
    SilEntryArtifact, StateSpanArtifact, TypeArtifact,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------------------------

/// Golden terms vector by number (1-based).
fn vector(n: usize) -> Terms {
    vectors().remove(n - 1).terms
}

fn checked(t: &Terms) -> ValidatedTerms {
    t.clone().validate_structure().expect("vector terms pass")
}

fn ctx(t: &Terms) -> CreationContext {
    CreationContext::new(t.network, CREATION_DAA)
}

/// The committed vault vector file for terms vector `name` (tests/vectors/vaults/).
fn committed(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/vaults")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).expect("committed vault vector");
    serde_json::from_str(&text).expect("vault vector parses")
}

fn leg_key(leg: LegIndex) -> &'static str {
    match leg {
        LegIndex::Asset => "asset_vault",
        LegIndex::Cash => "cash_vault",
    }
}

/// The committed address of a leg, if the leg has a vault.
fn committed_address(file: &Value, leg: LegIndex) -> Option<String> {
    file[leg_key(leg)]["address"].as_str().map(str::to_string)
}

fn committed_script(file: &Value, leg: LegIndex) -> Option<Vec<u8>> {
    file[leg_key(leg)]["redeem_script"].as_str().map(unhex)
}

/// Vector 1: vault, authority, earmarked, a KCC-20 asset against KCC-20 cash, mainnet.
fn agreed() -> Terms {
    vector(1)
}

fn agreed_file() -> Value {
    committed(vectors()[0].name)
}

fn script(t: &Terms, leg: LegIndex) -> Vec<u8> {
    Vault::instantiate_existing(&checked(t), leg)
        .expect("vault")
        .redeem_script()
        .to_vec()
}

fn address_of(t: &Terms, leg: LegIndex) -> String {
    let fundable =
        Vault::instantiate_for_creation(&checked(t), leg, &ctx(t)).expect("fundable vault");
    vault_address(&fundable)
}

fn code<T: std::fmt::Debug>(r: Result<T, VerifyError>) -> &'static str {
    r.expect_err("must be refused").code()
}

fn offered<'a>(asset: &'a Option<String>, cash: &'a Option<String>) -> OfferedAddresses<'a> {
    OfferedAddresses {
        asset: asset.as_deref(),
        cash: cash.as_deref(),
    }
}

/// The agreed addresses, as the counterparty sent them.
fn agreed_addresses() -> (Option<String>, Option<String>) {
    let file = agreed_file();
    (
        committed_address(&file, LegIndex::Asset),
        committed_address(&file, LegIndex::Cash),
    )
}

fn verify_agreed_addresses(t: &Terms) -> Result<Vec<VerifiedAddress>, VerifyError> {
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(t), &ctx(t), &offered(&a, &c))
}

// ---------------------------------------------------------------------------------------------
// Exit test
// ---------------------------------------------------------------------------------------------

#[test]
fn exit_every_committed_vault_vector_passes() {
    let mut legs = 0;
    for v in vectors() {
        let file = committed(v.name);
        let terms = checked(&v.terms);
        let (a, c) = (
            committed_address(&file, LegIndex::Asset),
            committed_address(&file, LegIndex::Cash),
        );
        let result = verify_addresses(&terms, &ctx(&v.terms), &offered(&a, &c));
        if a.is_none() {
            // Direct: nothing to fund.
            assert_eq!(code(result), "TEMPLATE_NO_VAULT", "{}", v.name);
            continue;
        }
        let verified = result.unwrap_or_else(|e| panic!("{}: {e}", v.name));
        for leg in LegIndex::ALL {
            let Some(script) = committed_script(&file, leg) else {
                assert!(verified.iter().all(|x| x.leg != leg), "{}", v.name);
                continue;
            };
            let got = verified.iter().find(|x| x.leg == leg).expect("verified");
            assert_eq!(Some(&got.address), committed_address(&file, leg).as_ref());
            let vault = Vault::instantiate_existing(&terms, leg).unwrap();
            assert_eq!(got.script_hash, vault.script_hash(), "{} {leg:?}", v.name);
            verify_revealed_script(&terms, leg, &script)
                .unwrap_or_else(|e| panic!("{} {leg:?}: {e}", v.name));
            legs += 1;
        }
    }
    assert_eq!(legs, 16, "every committed vault verified");
}

#[test]
fn exit_tampered_amount_fails_closed() {
    verify_agreed_addresses(&agreed()).expect("control");
    let agreed_terms = checked(&agreed());
    for leg in LegIndex::ALL {
        let mut t = agreed();
        match leg {
            LegIndex::Asset => t.asset_leg.amount += 1,
            LegIndex::Cash => t.cash_leg.amount -= 1,
        }
        // The agreed addresses do not pay the vaults of the tampered terms.
        assert_eq!(code(verify_agreed_addresses(&t)), "VERIFY_ADDRESS_MISMATCH");
        // A spend that reveals the tampered vault is not the agreed trade.
        let err = verify_revealed_script(&agreed_terms, leg, &script(&t, leg)).unwrap_err();
        let field = match leg {
            LegIndex::Asset => "asset_leg",
            LegIndex::Cash => "cash_leg",
        };
        assert_eq!(
            err,
            VerifyError::TermsMismatch {
                fields: vec![field]
            }
        );
        assert_eq!(err.code(), "VERIFY_TERMS_MISMATCH");
        verify_revealed_script(&agreed_terms, leg, &script(&agreed(), leg)).expect("control");
    }
}

#[test]
fn exit_tampered_destination_fails_closed() {
    let agreed_terms = checked(&agreed());
    let attacker = Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: label32("impulse/tests/verify/attacker"),
    });
    for (field, leg) in [
        ("buyer_delivery", LegIndex::Asset),
        ("seller_proceeds", LegIndex::Cash),
        ("seller_refund", LegIndex::Asset),
        ("buyer_refund", LegIndex::Cash),
    ] {
        let mut t = agreed();
        match field {
            "buyer_delivery" => t.buyer_delivery = attacker.clone(),
            "seller_proceeds" => t.seller_proceeds = attacker.clone(),
            "seller_refund" => t.seller_refund = attacker.clone(),
            _ => t.buyer_refund = attacker.clone(),
        }
        assert_eq!(
            code(verify_agreed_addresses(&t)),
            "VERIFY_ADDRESS_MISMATCH",
            "{field}"
        );
        assert_eq!(
            verify_revealed_script(&agreed_terms, leg, &script(&t, leg)),
            Err(VerifyError::TermsMismatch {
                fields: vec![field]
            })
        );
    }
}

#[test]
fn exit_swapped_template_fails_closed() {
    let agreed_terms = checked(&agreed());
    let control = committed_script(&agreed_file(), LegIndex::Asset).unwrap();
    verify_revealed_script(&agreed_terms, LegIndex::Asset, &control).expect("control");
    let template = check().unwrap();
    let pinned = template.hash();
    let (p, s) = (template.prefix().len(), template.suffix().len());

    // The same state under another template: one suffix byte changed.
    let mut other = control.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    let found = template_hash(&other[..p], &other[other.len() - s..]);
    assert_eq!(
        verify_revealed_script(&agreed_terms, LegIndex::Asset, &other),
        Err(VerifyError::TemplateMismatch {
            expected: pinned,
            found: Some(found),
        })
    );
    // Another prefix.
    let mut other = control.clone();
    other[0] ^= 0x01;
    assert_eq!(
        code(verify_revealed_script(
            &agreed_terms,
            LegIndex::Asset,
            &other
        )),
        "VERIFY_TEMPLATE_MISMATCH"
    );
    // Shorter than the template.
    assert_eq!(
        verify_revealed_script(&agreed_terms, LegIndex::Asset, &control[..100]),
        Err(VerifyError::TemplateMismatch {
            expected: pinned,
            found: None,
        })
    );

    // A token leg whose artifact runs another template than the terms name.
    let (t, spec) = token_terms(&Spec::standard());
    let terms = checked(&t);
    let good = spec.artifact_json();
    let control = TokenEvidence {
        artifact_json: &good,
        issuer_keys: &[],
    };
    token_warnings(&terms, Some(&control), None).expect("control");
    let swapped = Spec {
        suffix: vec![0x75, 0x51, 0x51],
        ..Spec::standard()
    }
    .artifact_json();
    let swapped = TokenEvidence {
        artifact_json: &swapped,
        issuer_keys: &[],
    };
    assert_eq!(
        code(token_warnings(&terms, Some(&swapped), None)),
        "VERIFY_TOKEN_TEMPLATE_MISMATCH"
    );
}

#[test]
fn exit_wrong_network_fails_closed() {
    let t = agreed();
    assert_eq!(t.network, Network::Mainnet);
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");

    // The verifier runs on testnet; the terms name mainnet.
    let testnet_ctx = CreationContext::new(Network::Testnet, CREATION_DAA);
    assert_eq!(
        code(verify_addresses(
            &checked(&t),
            &testnet_ctx,
            &offered(&a, &c)
        )),
        "TERMS_NETWORK_MISMATCH"
    );

    // The offered address carries another network's prefix over the right payload.
    let retag = |text: &str, p: Prefix| {
        let parsed = Address::try_from(text).unwrap();
        Address::new(p, parsed.version, &parsed.payload).to_string()
    };
    for p in [Prefix::Testnet, Prefix::Simnet, Prefix::Devnet] {
        let wrong = Some(retag(a.as_deref().unwrap(), p));
        assert_eq!(
            verify_addresses(&checked(&t), &ctx(&t), &offered(&wrong, &c)),
            Err(VerifyError::AddressNetwork {
                leg: LegIndex::Asset,
                expected: Network::Mainnet,
                found: p.to_string(),
            })
        );
    }

    // The same trade made for testnet is another vault.
    let mut testnet = t.clone();
    testnet.network = Network::Testnet;
    assert_eq!(
        verify_revealed_script(
            &checked(&t),
            LegIndex::Asset,
            &script(&testnet, LegIndex::Asset)
        ),
        Err(VerifyError::TermsMismatch {
            fields: vec!["network"]
        })
    );
    // And its addresses, offered for the mainnet terms, carry the wrong prefix.
    let tn = (
        Some(address_of(&testnet, LegIndex::Asset)),
        Some(address_of(&testnet, LegIndex::Cash)),
    );
    assert_eq!(
        code(verify_addresses(
            &checked(&t),
            &ctx(&t),
            &offered(&tn.0, &tn.1)
        )),
        "VERIFY_ADDRESS_NETWORK"
    );
}

#[test]
fn exit_reordered_legs_fail_closed() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");
    assert_eq!(
        verify_addresses(&checked(&t), &ctx(&t), &offered(&c, &a)),
        Err(VerifyError::LegsSwapped {
            leg: LegIndex::Asset
        })
    );
    // Only the cash slot holds the asset vault.
    assert_eq!(
        verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &a)),
        Err(VerifyError::LegsSwapped {
            leg: LegIndex::Cash
        })
    );
    // A spend of the cash vault checked as the asset leg, and the reverse.
    let terms = checked(&t);
    for (leg, other) in [
        (LegIndex::Asset, LegIndex::Cash),
        (LegIndex::Cash, LegIndex::Asset),
    ] {
        verify_revealed_script(&terms, leg, &script(&t, leg)).expect("control");
        assert_eq!(
            verify_revealed_script(&terms, leg, &script(&t, other)),
            Err(VerifyError::LegsSwapped { leg })
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Addresses: the other refusals
// ---------------------------------------------------------------------------------------------

#[test]
fn malformed_addresses_are_refused() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    let good = a.clone().unwrap();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");
    let mut bad_checksum = good.clone();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'q' { 'p' } else { 'q' });
    for bad in [
        bad_checksum,
        good.replace("kaspa:", ""),
        good.replace("kaspa:", "bitcoin:"),
        format!("{good}q"),
        String::new(),
    ] {
        let r = verify_addresses(&checked(&t), &ctx(&t), &offered(&Some(bad.clone()), &c));
        assert_eq!(code(r), "VERIFY_ADDRESS_MALFORMED", "{bad}");
    }
}

/// Address text with a valid checksum over any 5-bit payload symbols: the public BCH polymod
/// of rusty-kaspa a41a333 `crypto/addresses/src/bech32.rs`, so an attacker can compute it.
fn bech32_text(prefix: &str, symbols: &[u8]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut c = 1u64;
    let values = prefix.bytes().map(|b| b & 0x1f).chain([0]);
    for d in values.chain(symbols.iter().copied()).chain([0; 8]) {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ u64::from(d);
        for (bit, g) in [
            0x98_f2bc_8e61,
            0x79_b76d_99e2,
            0xf3_3e5f_b3c4,
            0xae_2eab_e2a8,
            0x1e_4f43_e470u64,
        ]
        .into_iter()
        .enumerate()
        {
            if c0 >> bit & 1 != 0 {
                c ^= g;
            }
        }
    }
    let checksum = c ^ 1;
    let mut out = format!("{prefix}:");
    out.extend(symbols.iter().map(|&s| char::from(CHARSET[usize::from(s)])));
    out.extend(
        (0..8)
            .rev()
            .map(|i| char::from(CHARSET[(checksum >> (5 * i) & 0x1f) as usize])),
    );
    out
}

/// `n` payload symbols whose first eight bits are the address version byte `version`.
fn versioned_symbols(version: u8, n: usize) -> Vec<u8> {
    let mut symbols = vec![version >> 3, (version & 7) << 2];
    symbols.resize(n.max(2), 0);
    symbols.truncate(n);
    symbols
}

#[test]
fn address_text_that_panics_the_address_parser_is_malformed() {
    // Review round 2, MEDIUM 2. rusty-kaspa a41a333 `Address::try_from` panics on text with a
    // valid checksum and 0 or 1 payload symbols (it indexes an empty payload), or whose payload
    // length is not its version's (`Address::new` asserts it). Both are refused unparsed.
    let t = agreed();
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");
    let refuse = |text: &str| {
        let r = verify_addresses(&checked(&t), &ctx(&t), &offered(&Some(text.into()), &c));
        code(r)
    };
    // The reviewer's strings, and the helper reproduces them.
    assert_eq!(bech32_text("kaspa", &[]), "kaspa:3xjng3c9");
    assert_eq!(bech32_text("kaspa", &[0]), "kaspa:qkgdh0z5s");
    assert_eq!(bech32_text("kaspatest", &[]), "kaspatest:29e8ll76");
    for text in ["kaspa:3xjng3c9", "kaspa:qkgdh0z5s", "kaspatest:29e8ll76"] {
        assert_eq!(refuse(text), "VERIFY_ADDRESS_MALFORMED", "{text}");
    }
    // The helper renders the agreed address exactly.
    let parsed = Address::try_from(a.as_deref().unwrap()).unwrap();
    let mut bits = vec![Version::ScriptHash as u8];
    bits.extend_from_slice(&parsed.payload);
    let symbols: Vec<u8> = (0..53)
        .map(|i| {
            let (byte, shift) = (i * 5 / 8, i * 5 % 8);
            let word = u16::from(bits[byte]) << 8 | u16::from(*bits.get(byte + 1).unwrap_or(&0));
            (word >> (11 - shift) & 0x1f) as u8
        })
        .collect();
    assert_eq!(bech32_text("kaspa", &symbols), a.clone().unwrap());
    // Every payload length for each address version: only a version's own length parses (32
    // bytes for PubKey and ScriptHash, 53 symbols; 33 for PubKeyECDSA, 55), and pays nothing
    // here. Every other length is malformed, where the parser would have panicked.
    for version in [Version::PubKey, Version::PubKeyECDSA, Version::ScriptHash] {
        for n in 0..=70 {
            let text = bech32_text("kaspa", &versioned_symbols(version as u8, n));
            let well_formed = n
                == if version == Version::PubKeyECDSA {
                    55
                } else {
                    53
                };
            let expected = if well_formed {
                "VERIFY_ADDRESS_MISMATCH"
            } else {
                "VERIFY_ADDRESS_MALFORMED"
            };
            assert_eq!(refuse(&text), expected, "{version:?}, {n} symbols: {text}");
        }
    }
}

#[test]
fn an_address_that_is_not_the_vault_p2sh_is_a_mismatch() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");
    let parsed = Address::try_from(a.as_deref().unwrap()).unwrap();
    // The same 32 bytes as a Schnorr P2PK address: not the vault.
    let p2pk = Some(Address::new(Prefix::Mainnet, Version::PubKey, &parsed.payload).to_string());
    assert_eq!(
        verify_addresses(&checked(&t), &ctx(&t), &offered(&p2pk, &c)),
        Err(VerifyError::AddressMismatch {
            leg: LegIndex::Asset
        })
    );
    // Another trade's vault.
    let stranger = Some(address_of(&vector(3), LegIndex::Asset));
    assert_eq!(
        code(verify_addresses(
            &checked(&t),
            &ctx(&t),
            &offered(&stranger, &c)
        )),
        "VERIFY_ADDRESS_MISMATCH"
    );
}

#[test]
fn every_leg_with_a_vault_needs_an_address() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &c)).expect("control");
    assert_eq!(
        verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &None)),
        Err(VerifyError::AddressMissing {
            leg: LegIndex::Cash
        })
    );
    assert_eq!(
        verify_addresses(&checked(&t), &ctx(&t), &offered(&None, &c)),
        Err(VerifyError::AddressMissing {
            leg: LegIndex::Asset
        })
    );
}

#[test]
fn external_cash_has_no_cash_address_to_fund() {
    // Vector 5: external cash. Its cash-vault script exists for anyone who compiles it, but it
    // must never be funded (spec/TEMPLATE.md), so an address offered for it is refused.
    let t = vector(5);
    let a = Some(address_of(&t, LegIndex::Asset));
    let verified = verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &None)).expect("control");
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].leg, LegIndex::Asset);
    for cash in [a.clone(), Some(address_of(&agreed(), LegIndex::Cash))] {
        assert_eq!(
            verify_addresses(&checked(&t), &ctx(&t), &offered(&a, &cash)),
            Err(VerifyError::AddressUnexpected {
                leg: LegIndex::Cash
            })
        );
    }
}

#[test]
fn direct_terms_have_nothing_to_fund() {
    let t = vector(7);
    // Control: the same terms in vault mode have both vaults to fund.
    let mut vault_mode = t.clone();
    vault_mode.settlement_mode = SettlementMode::Vault;
    let (a, c) = (
        Some(address_of(&vault_mode, LegIndex::Asset)),
        Some(address_of(&vault_mode, LegIndex::Cash)),
    );
    let verified = verify_addresses(&checked(&vault_mode), &ctx(&t), &offered(&a, &c));
    assert_eq!(verified.expect("control").len(), 2);
    assert_eq!(
        code(verify_addresses(
            &checked(&t),
            &ctx(&t),
            &OfferedAddresses::default()
        )),
        "TEMPLATE_NO_VAULT"
    );
}

#[test]
fn an_expired_trade_is_not_offered_for_funding_but_its_spends_verify() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    let late = CreationContext::new(t.network, t.expiry_daa);
    assert_eq!(
        code(verify_addresses(&checked(&t), &late, &offered(&a, &c))),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    // A refund after expiry still reveals the agreed vault.
    for leg in LegIndex::ALL {
        verify_revealed_script(&checked(&t), leg, &script(&t, leg)).expect("existing trade");
    }
}

#[test]
fn the_creation_checks_hold_at_their_boundaries() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    let check = |ctx: &CreationContext| verify_addresses(&checked(&t), ctx, &offered(&a, &c));
    // Created one DAA score before expiry: fundable. At expiry: not.
    check(&CreationContext::new(t.network, t.expiry_daa - 1)).expect("control");
    assert_eq!(
        code(check(&CreationContext::new(t.network, t.expiry_daa))),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    // The expiry exactly at the horizon: fundable. One score beyond it: not.
    let at_horizon = CreationContext {
        max_expiry_horizon_daa: t.expiry_daa - CREATION_DAA,
        ..ctx(&t)
    };
    check(&at_horizon).expect("control");
    let short = CreationContext {
        max_expiry_horizon_daa: t.expiry_daa - CREATION_DAA - 1,
        ..ctx(&t)
    };
    assert_eq!(code(check(&short)), "TERMS_EXPIRY_BEYOND_HORIZON");
}

// ---------------------------------------------------------------------------------------------
// Revealed scripts: the other refusals
// ---------------------------------------------------------------------------------------------

#[test]
fn a_leg_without_a_vault_reveals_nothing_to_verify() {
    let t = vector(5); // external cash
    let asset = script(&t, LegIndex::Asset);
    verify_revealed_script(&checked(&t), LegIndex::Asset, &asset).expect("control");
    assert_eq!(
        code(verify_revealed_script(&checked(&t), LegIndex::Cash, &asset)),
        "TEMPLATE_NO_VAULT"
    );
}

#[test]
fn a_script_of_the_template_that_does_not_decode_keeps_its_code() {
    let t = agreed();
    let terms = checked(&t);
    let good = script(&t, LegIndex::Asset);
    verify_revealed_script(&terms, LegIndex::Asset, &good).expect("control");
    // The version push (state bytes 1 and 2) says 2: the terms structure check refuses it.
    assert_eq!(&good[1..3], &[0x01, 0x01]);
    let mut v2 = good.clone();
    v2[2] = 0x02;
    assert_eq!(
        code(verify_revealed_script(&terms, LegIndex::Asset, &v2)),
        "TERMS_UNSUPPORTED_VERSION"
    );
    // A push that runs past the state: the state does not parse.
    let mut cut = good.clone();
    cut[1] = 0x4b;
    assert_eq!(
        code(verify_revealed_script(&terms, LegIndex::Asset, &cut)),
        "TEMPLATE_STATE_MALFORMED"
    );
}

#[test]
fn differing_fields_names_every_changed_field_in_order() {
    let a = agreed();
    let mut b = a.clone();
    b.nonce ^= 1;
    b.expiry_daa -= 1;
    b.trade_ref = [9; 32];
    assert_eq!(
        differing_fields(&a, &b),
        vec!["nonce", "expiry_daa", "trade_ref"]
    );
    assert!(differing_fields(&a, &a).is_empty());
}

#[test]
fn differing_fields_lists_every_field_in_field_order() {
    let a = agreed();
    let other = label32("impulse/tests/verify/other");
    let elsewhere = Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: other,
    });
    let b = Terms {
        version: a.version + 1,
        network: Network::Testnet,
        settlement_mode: SettlementMode::Direct,
        nonce: a.nonce ^ 1,
        seller_key: other,
        buyer_key: other,
        authority_key: None,
        asset_leg: Leg {
            amount: a.asset_leg.amount + 1,
            ..a.asset_leg
        },
        cash_leg: Leg {
            amount: a.cash_leg.amount + 1,
            ..a.cash_leg
        },
        buyer_delivery: elsewhere.clone(),
        seller_proceeds: elsewhere.clone(),
        seller_refund: elsewhere.clone(),
        buyer_refund: elsewhere,
        earliest_daa: None,
        expiry_daa: a.expiry_daa + 1,
        funding_mode: match a.funding_mode {
            FundingMode::Earmarked => FundingMode::Revocable,
            FundingMode::Revocable => FundingMode::Earmarked,
        },
        trade_ref: [9; 32],
    };
    let all = [
        "version",
        "network",
        "settlement_mode",
        "nonce",
        "seller_key",
        "buyer_key",
        "authority_key",
        "asset_leg",
        "cash_leg",
        "buyer_delivery",
        "seller_proceeds",
        "seller_refund",
        "buyer_refund",
        "earliest_daa",
        "expiry_daa",
        "funding_mode",
        "trade_ref",
    ];
    assert_eq!(differing_fields(&a, &b), all);
    assert_eq!(differing_fields(&b, &a), all);
    assert!(differing_fields(&b, &b).is_empty());
}

/// An input spending the vault: a refund call's arguments, the dispatch tag, the script.
fn spending_input(script: &[u8]) -> TransactionInput {
    let tag = check().unwrap().abi().contracts["ImpulseVault"].entries["refund"]
        .dispatch_tag
        .into_bytes();
    let mut sigscript = Vec::new();
    for data in [&[0u8; 65][..], &seller(), &tag, script] {
        push(&mut sigscript, data);
    }
    TransactionInput::new_with_compute_budget(TransactionOutpoint::default(), sigscript, 0, 1_000)
}

/// Appends a data push (OP_DATA_n, OP_PUSHDATA1 or OP_PUSHDATA2).
fn push(out: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        n @ 1..=75 => out.push(n as u8),
        n @ 76..=255 => out.extend([0x4c, n as u8]),
        n => {
            out.push(0x4d);
            out.extend((n as u16).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
}

#[test]
fn a_spent_input_reveals_its_script() {
    let t = agreed();
    let terms = checked(&t);
    let vault = script(&t, LegIndex::Asset);
    let input = spending_input(&vault);
    let spent = pay_to_script_hash_script(&vault);
    verify_spent_input(&terms, LegIndex::Asset, &input, &spent).expect("control");
    assert_eq!(
        code(verify_spent_input(&terms, LegIndex::Cash, &input, &spent)),
        "VERIFY_LEGS_SWAPPED"
    );
    // Not push only: an OP_CHECKSIG before the pushes.
    let mut not_push_only = input.clone();
    not_push_only.signature_script.insert(0, 0xac);
    assert_eq!(
        verify_spent_input(&terms, LegIndex::Asset, &not_push_only, &spent),
        Err(VerifyError::NothingRevealed)
    );
    let mut empty = input.clone();
    empty.signature_script.clear();
    assert_eq!(
        verify_spent_input(&terms, LegIndex::Asset, &empty, &spent),
        Err(VerifyError::NothingRevealed)
    );
}

#[test]
fn a_spent_input_verifies_only_against_the_utxo_whose_spend_runs_its_script() {
    // Review round 2, MEDIUM 1: the transaction ID does not commit to signature scripts, and
    // consensus runs a signature script only at a version 0 scriptPublicKey. The spent UTXO must
    // be the version 0 P2SH of the revealed script.
    let t = agreed();
    let terms = checked(&t);
    let vault = script(&t, LegIndex::Asset);
    let input = spending_input(&vault);
    let p2sh = pay_to_script_hash_script(&vault);
    verify_spent_input(&terms, LegIndex::Asset, &input, &p2sh).expect("control");

    // The same P2SH bytes at script version 1: accepted by consensus without running anything.
    let unrun = ScriptPublicKey::from_vec(1, p2sh.script().to_vec());
    assert_eq!(
        verify_spent_input(&terms, LegIndex::Asset, &input, &unrun),
        Err(VerifyError::InputNotVault)
    );
    // Another trade's vault script swapped into an input that spends this trade's vault, and
    // verified against that other trade: refused, while the same reveal at its own vault is
    // accepted.
    let other = vector(3);
    let other_vault = script(&other, LegIndex::Asset);
    let swapped = spending_input(&other_vault);
    let other_terms = checked(&other);
    verify_spent_input(
        &other_terms,
        LegIndex::Asset,
        &swapped,
        &pay_to_script_hash_script(&other_vault),
    )
    .expect("control: its own vault");
    assert_eq!(
        verify_spent_input(&other_terms, LegIndex::Asset, &swapped, &p2sh),
        Err(VerifyError::InputNotVault)
    );
    // A UTXO that is no P2SH at all: the agreed vault's script hash as a P2PK key.
    let mut p2pk = vec![0x20];
    p2pk.extend_from_slice(
        &Vault::instantiate_existing(&terms, LegIndex::Asset)
            .unwrap()
            .script_hash(),
    );
    p2pk.push(0xac);
    assert_eq!(
        verify_spent_input(
            &terms,
            LegIndex::Asset,
            &input,
            &ScriptPublicKey::from_vec(0, p2pk)
        ),
        Err(VerifyError::InputNotVault)
    );
}

// ---------------------------------------------------------------------------------------------
// Token warnings
// ---------------------------------------------------------------------------------------------

/// A synthetic compiled token template: KCC-20 state and entries by default, with knobs for
/// every way an artifact can differ. It passes silverscript's consistency check; its bytecode
/// is a placeholder, since the verifier reads the artifact and never runs it. The real
/// kcc20.sil artifact is checked in tests/engine/verify.rs.
#[derive(Clone)]
struct Spec {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    fields: Vec<(&'static str, TypeArtifact, ArtifactValue)>,
    entries: Vec<&'static str>,
    contracts: usize,
    break_hash: bool,
}

impl Spec {
    fn standard() -> Self {
        Self {
            prefix: vec![0x51],
            suffix: vec![0x75, 0x51],
            fields: vec![
                (
                    "ownerIdentifier",
                    TypeArtifact::FixedBytes { len: 32 },
                    ArtifactValue::Bytes(vec![0; 32]),
                ),
                ("identifierType", TypeArtifact::Byte, ArtifactValue::Byte(0)),
                ("amount", TypeArtifact::Int, ArtifactValue::Int(0)),
                ("isMinter", TypeArtifact::Bool, ArtifactValue::Bool(false)),
            ],
            entries: vec!["__delegate", "__leader_transfer"],
            contracts: 1,
            break_hash: false,
        }
    }

    fn with_field(mut self, name: &'static str, ty: TypeArtifact, v: ArtifactValue) -> Self {
        self.fields.push((name, ty, v));
        self
    }

    fn triple(&self) -> Kcc20Token {
        Kcc20Token {
            covenant_id: label32("impulse/tests/verify/token"),
            template_hash: template_hash(&self.prefix, &self.suffix),
            template_prefix_len: self.prefix.len() as u32,
            template_suffix_len: self.suffix.len() as u32,
        }
    }

    fn artifact_json(&self) -> String {
        let runtime_state = RuntimeStateArtifact {
            source: "State".into(),
            fields: self
                .fields
                .iter()
                .map(|(name, ty, _)| RuntimeFieldArtifact {
                    name: (*name).into(),
                    ty: ty.clone(),
                })
                .collect(),
        };
        let values: BTreeMap<String, ArtifactValue> = self
            .fields
            .iter()
            .map(|(name, _, v)| ((*name).into(), v.clone()))
            .collect();
        let mut abi = SilAbiArtifact {
            schema_version: 1,
            compiler_version: "synthetic".into(),
            structs: BTreeMap::new(),
            contracts: BTreeMap::new(),
        };
        let state = encode_runtime_state_script(&abi, &runtime_state, &values).unwrap();
        let mut bytecode = self.prefix.clone();
        bytecode.extend_from_slice(&state);
        bytecode.extend_from_slice(&self.suffix);
        let mut hash = template_hash(&self.prefix, &self.suffix);
        if self.break_hash {
            hash[0] ^= 1;
        }
        let entries = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let entry = SilEntryArtifact {
                    dispatch_tag: [i as u8 + 1, 0, 0, 0].into(),
                    params: vec![],
                };
                ((*name).into(), entry)
            })
            .collect();
        let contract = SilContractArtifact {
            source_path: "synthetic.sil".into(),
            runtime_state,
            entries,
            cov_decl_to_abi: BTreeMap::new(),
            delegate_entry_abi: None,
            compiled: CompiledContractArtifact {
                bytecode,
                template_hash: hash,
                state_span: StateSpanArtifact {
                    offset: self.prefix.len(),
                    len: state.len(),
                },
            },
        };
        for n in 0..self.contracts {
            abi.contracts.insert(format!("Token{n}"), contract.clone());
        }
        serde_json::to_string(&abi).unwrap()
    }
}

/// Vector 1 with its asset token running `spec`'s template, and that spec.
fn token_terms(spec: &Spec) -> (Terms, Spec) {
    let mut t = agreed();
    t.asset_leg = Leg {
        kind: LegKind::Kcc20(spec.triple()),
        amount: t.asset_leg.amount,
    };
    (t, spec.clone())
}

fn warnings_for(spec: &Spec, issuer_keys: &[[u8; 32]]) -> Result<Vec<TokenWarning>, VerifyError> {
    let (t, spec) = token_terms(spec);
    let json = spec.artifact_json();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys,
    };
    token_warnings(&checked(&t), Some(&evidence), None)
}

fn asset(kind: TokenWarningKind) -> TokenWarning {
    TokenWarning {
        leg: LegIndex::Asset,
        kind,
    }
}

fn cash_unassessed() -> TokenWarning {
    TokenWarning {
        leg: LegIndex::Cash,
        kind: TokenWarningKind::Unassessed,
    }
}

/// What every synthetic token reports: the minter branch, and a template outside the pinned
/// kcc20.sil builds (its declared state and entries are the artifact's own claim).
fn synthetic(rest: Vec<TokenWarningKind>) -> Vec<TokenWarning> {
    let mut out = vec![
        asset(TokenWarningKind::MinterBranch),
        asset(TokenWarningKind::TemplateUnpinned),
    ];
    out.extend(rest.into_iter().map(asset));
    out.push(cash_unassessed());
    out
}

#[test]
fn a_kcc20_token_reports_its_minter_branch_and_an_unread_leg_is_unassessed() {
    assert_eq!(
        warnings_for(&Spec::standard(), &[]).unwrap(),
        synthetic(vec![TokenWarningKind::IssuerUnknown])
    );
    // No evidence at all: both KCC-20 legs unassessed, never an empty list.
    let w = token_warnings(&checked(&agreed()), None, None).unwrap();
    let codes: Vec<&str> = w.iter().map(TokenWarning::code).collect();
    assert_eq!(codes, ["TOKEN_UNASSESSED", "TOKEN_UNASSESSED"]);
    // KAS cash has no token: only the asset leg is reported.
    let w = token_warnings(&checked(&vector(2)), None, None).unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].leg, LegIndex::Asset);
}

#[test]
fn a_token_with_extended_state_is_refused() {
    // The vault reads and rebuilds the four-field KCC-20 state, so it can neither settle nor
    // refund a token with more (tests/engine/verify.rs pins this in the engine).
    warnings_for(&Spec::standard(), &[]).expect("control");
    let spec = Spec::standard()
        .with_field("frozen", TypeArtifact::Bool, ArtifactValue::Bool(false))
        .with_field(
            "clawbackKey",
            TypeArtifact::Pubkey,
            ArtifactValue::Bytes(vec![2; 32]),
        );
    assert_eq!(
        warnings_for(&spec, &[]),
        Err(VerifyError::TokenExtendedState {
            leg: LegIndex::Asset,
            fields: vec!["frozen".into(), "clawbackKey".into()]
        })
    );
}

#[test]
fn extra_entries_are_reported_by_name() {
    assert_eq!(
        warnings_for(&Spec::standard(), &[]).unwrap(),
        synthetic(vec![TokenWarningKind::IssuerUnknown]),
        "control"
    );
    let mut spec = Spec::standard();
    spec.entries.push("clawback");
    assert_eq!(
        warnings_for(&spec, &[]).unwrap(),
        synthetic(vec![
            TokenWarningKind::ExtraEntries {
                entries: vec!["clawback".into()]
            },
            TokenWarningKind::IssuerUnknown,
        ])
    );
}

#[test]
fn entries_an_artifact_hides_under_the_same_template_are_flagged_unpinned() {
    // Review round 1, MEDIUM 3: the entry names are not covered by the template hash. Two
    // artifacts of one bytecode and triple, one declaring a clawback entry: both pass the
    // consistency check and the triple check, and neither is a pinned kcc20.sil build, so both
    // say their declared entries are unauthenticated.
    let honest = Spec::standard();
    let mut declared = Spec::standard();
    declared.entries.push("clawback");
    assert_eq!(honest.triple(), declared.triple());
    let triple = TemplateTriple::from(&honest.triple());
    assert_eq!(pinned_kcc20(&triple), None);
    for spec in [&honest, &declared] {
        let w = warnings_for(spec, &[]).unwrap();
        assert!(w.contains(&asset(TokenWarningKind::TemplateUnpinned)));
    }
    // Control: every pinned triple is found, and only the triple decides.
    for p in &PINNED_KCC20_TEMPLATES {
        assert_eq!(pinned_kcc20(&p.triple), Some(p));
        let mut near = p.triple;
        near.suffix_len += 1;
        assert_eq!(pinned_kcc20(&near), None);
    }
}

#[test]
fn no_issuer_keys_is_reported_as_issuers_unknown() {
    // Review round 1, LOW: an empty key list is not "keys supplied, none matched".
    let stranger = [label32("impulse/tests/verify/stranger")];
    let examined = warnings_for(&Spec::standard(), &stranger).unwrap();
    assert_eq!(examined, synthetic(vec![]), "control");
    assert_eq!(
        warnings_for(&Spec::standard(), &[]).unwrap(),
        synthetic(vec![TokenWarningKind::IssuerUnknown])
    );
}

#[test]
fn a_party_among_the_issuer_keys_is_reported_with_its_relation_to_the_leg() {
    // I3 residual: a counterparty or authority that issues the leg's token.
    let control = warnings_for(
        &Spec::standard(),
        &[label32("impulse/tests/verify/stranger")],
    );
    assert!(control
        .unwrap()
        .iter()
        .all(|w| w.code() != "TOKEN_PARTY_IS_ISSUER"));
    let issuer = |party, relation| asset(TokenWarningKind::PartyIsIssuer { party, relation });
    assert_eq!(
        warnings_for(&Spec::standard(), &[authority(), buyer(), seller()]).unwrap(),
        vec![
            asset(TokenWarningKind::MinterBranch),
            asset(TokenWarningKind::TemplateUnpinned),
            issuer(Party::Seller, Relation::Depositor),
            issuer(Party::Buyer, Relation::Counterparty),
            issuer(Party::Authority, Relation::Authority),
            cash_unassessed(),
        ]
    );
    // On the cash leg the buyer deposits and the seller is the counterparty.
    let spec = Spec::standard();
    let mut t = agreed();
    let LegKind::Kcc20(cash) = t.cash_leg.kind else {
        unreachable!("vector 1 has KCC-20 cash")
    };
    t.cash_leg.kind = LegKind::Kcc20(Kcc20Token {
        covenant_id: cash.covenant_id,
        ..spec.triple()
    });
    let json = spec.artifact_json();
    let keys = [seller(), buyer()];
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &keys,
    };
    let w = token_warnings(&checked(&t), None, Some(&evidence)).unwrap();
    let cash_issuer = |party, relation| TokenWarning {
        leg: LegIndex::Cash,
        kind: TokenWarningKind::PartyIsIssuer { party, relation },
    };
    assert!(w.contains(&cash_issuer(Party::Seller, Relation::Counterparty)));
    assert!(w.contains(&cash_issuer(Party::Buyer, Relation::Depositor)));
}

#[test]
fn token_evidence_refusals() {
    warnings_for(&Spec::standard(), &[]).expect("control");
    let (t, _) = token_terms(&Spec::standard());
    let not_json = TokenEvidence {
        artifact_json: "{",
        issuer_keys: &[],
    };
    assert_eq!(
        code(token_warnings(&checked(&t), Some(&not_json), None)),
        "VERIFY_TOKEN_ARTIFACT_INVALID"
    );
    let edited = |edit: fn(&mut Spec)| {
        let mut s = Spec::standard();
        edit(&mut s);
        s
    };
    let cases: [(&str, Spec, &str); 10] = [
        (
            "declared hash not the bytes' hash",
            edited(|s| s.break_hash = true),
            "VERIFY_TOKEN_ARTIFACT_INVALID",
        ),
        (
            "two contracts",
            edited(|s| s.contracts = 2),
            "VERIFY_TOKEN_ARTIFACT_INVALID",
        ),
        (
            "no contract",
            edited(|s| s.contracts = 0),
            "VERIFY_TOKEN_ARTIFACT_INVALID",
        ),
        (
            "amount is not an int",
            edited(|s| s.fields[2] = ("amount", TypeArtifact::Bool, ArtifactValue::Bool(false))),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "no isMinter field",
            edited(|s| {
                s.fields.pop();
            }),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "fields reordered",
            edited(|s| s.fields.swap(0, 1)),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "no delegate entry",
            edited(|s| s.entries = vec!["__leader_transfer"]),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "no transfer leader entry",
            edited(|s| s.entries = vec!["__delegate"]),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "fourth field of the right type, another name",
            edited(|s| s.fields[3] = ("isFrozen", TypeArtifact::Bool, ArtifactValue::Bool(false))),
            "VERIFY_TOKEN_NOT_KCC20",
        ),
        (
            "a fifth field",
            edited(|s| {
                s.fields
                    .push(("frozen", TypeArtifact::Bool, ArtifactValue::Bool(false)))
            }),
            "VERIFY_TOKEN_EXTENDED_STATE",
        ),
    ];
    for (label, spec, expected) in cases {
        assert_eq!(code(warnings_for(&spec, &[])), expected, "{label}");
    }
}

/// The standard synthetic artifact with structs `S0` to `S{depth}`, each but the last holding
/// two fields of the next, the last one int, and a state field of type `S0`: 2^depth leaves
/// from a few kilobytes of JSON.
fn struct_dag_artifact(depth: usize) -> String {
    let mut v: Value = serde_json::from_str(&Spec::standard().artifact_json()).unwrap();
    let structs = v["structs"].as_object_mut().unwrap();
    for i in 0..depth {
        let next = json!({"kind": "struct", "name": format!("S{}", i + 1)});
        let fields = json!([{"name": "a", "type": next}, {"name": "b", "type": next}]);
        structs.insert(format!("S{i}"), json!({ "fields": fields }));
    }
    let leaf = json!([{"name": "a", "type": {"kind": "int"}}]);
    structs.insert(format!("S{depth}"), json!({ "fields": leaf }));
    for contract in v["contracts"].as_object_mut().unwrap().values_mut() {
        let bomb = json!({"name": "bomb", "type": {"kind": "struct", "name": "S0"}});
        contract["runtime_state"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(bomb);
    }
    v.to_string()
}

#[test]
fn an_artifact_that_expands_without_bound_is_refused_quickly() {
    // Review round 2, MEDIUM 3: silverscript-abi's consistency check flattens struct types with
    // a cycle check only, so a DAG of structs doubles its cost per level. Measured before the
    // fix, debug build: depth 22, 3.5 KB, 11.7 s.
    warnings_for(&Spec::standard(), &[]).expect("control");
    let (t, _) = token_terms(&Spec::standard());
    for depth in [22, 40] {
        let json = struct_dag_artifact(depth);
        assert!(json.len() < 8 * 1024, "{}", json.len());
        let evidence = TokenEvidence {
            artifact_json: &json,
            issuer_keys: &[],
        };
        let start = Instant::now();
        let r = token_warnings(&checked(&t), Some(&evidence), None);
        let elapsed = start.elapsed();
        assert_eq!(code(r), "VERIFY_TOKEN_ARTIFACT_INVALID", "depth {depth}");
        assert!(
            elapsed < Duration::from_secs(1),
            "depth {depth}: {elapsed:?}"
        );
    }
    // A struct declared for other uses is not expanded and is read (control, as KCC20Minter's
    // KCC20State); a state field of a struct type, even one level deep or inside an array, is
    // refused.
    let read = |state_type: Option<Value>| {
        let mut v: Value = serde_json::from_str(&Spec::standard().artifact_json()).unwrap();
        v["structs"]["Pair"] = json!({"fields": [{"name": "a", "type": {"kind": "int"}}]});
        if let Some(ty) = state_type {
            for contract in v["contracts"].as_object_mut().unwrap().values_mut() {
                let field = json!({"name": "pair", "type": ty});
                contract["runtime_state"]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(field);
            }
        }
        let json = v.to_string();
        let evidence = TokenEvidence {
            artifact_json: &json,
            issuer_keys: &[],
        };
        token_warnings(&checked(&t), Some(&evidence), None)
    };
    read(None).expect("control: a struct no state field uses");
    let pair = json!({"kind": "struct", "name": "Pair"});
    for ty in [
        pair.clone(),
        json!({"kind": "dynamic_array", "item": pair}),
        json!({"kind": "fixed_array", "item": {"kind": "dynamic_array", "item": pair}, "len": 2}),
    ] {
        assert_eq!(
            code(read(Some(ty.clone()))),
            "VERIFY_TOKEN_ARTIFACT_INVALID",
            "{ty}"
        );
    }
}

#[test]
fn an_artifact_longer_than_the_cap_is_refused_unread() {
    let spec = Spec::standard();
    let (t, _) = token_terms(&spec);
    let json = spec.artifact_json();
    // Trailing whitespace keeps the JSON valid.
    let padded = |len: usize| format!("{json}{}", " ".repeat(len - json.len()));
    let at_cap = padded(MAX_TOKEN_ARTIFACT_LEN);
    let over = padded(MAX_TOKEN_ARTIFACT_LEN + 1);
    for (text, accepted) in [(&at_cap, true), (&over, false)] {
        let evidence = TokenEvidence {
            artifact_json: text,
            issuer_keys: &[],
        };
        let r = token_warnings(&checked(&t), Some(&evidence), None);
        if accepted {
            r.expect("control: at the cap");
        } else {
            assert_eq!(code(r), "VERIFY_TOKEN_ARTIFACT_INVALID");
        }
    }
}

/// Whether `text` is printable ASCII only: no terminal control sequence, no invisible or
/// bidirectional character.
fn printable_ascii(text: &str) -> bool {
    text.chars().all(|c| c == ' ' || c.is_ascii_graphic())
}

#[test]
fn counterparty_text_never_reaches_a_message_unescaped() {
    // Review round 2, LOW: artifact names, serde and upstream error text are the counterparty's,
    // and the CLI (I7) and decoder page (I11) print these messages.
    let leaked = |n: usize| -> &'static str { Box::leak("e".repeat(n).into_boxed_str()) };
    // Entry names: identifiers of 1 to 64 characters are reported (control), others refused.
    for (name, accepted) in [
        ("clawback", true),
        (leaked(64), true),
        (leaked(65), false),
        ("", false),
        ("evil\u{1b}[2J\u{1b}[Hmint", false),
        ("transfer\u{202e}", false),
        ("clawback()", false),
    ] {
        let mut spec = Spec::standard();
        spec.entries.push(name);
        let r = warnings_for(&spec, &[]);
        if accepted {
            let w = r.unwrap_or_else(|e| panic!("{name}: {e}"));
            let extra = TokenWarningKind::ExtraEntries {
                entries: vec![name.into()],
            };
            assert!(w.contains(&asset(extra)), "{name}");
        } else {
            let e = r.unwrap_err();
            assert_eq!(e.code(), "VERIFY_TOKEN_ARTIFACT_INVALID", "{name:?}");
            assert!(printable_ascii(&e.to_string()), "{e}");
        }
    }
    // State field names: an extended state is named (control), a hostile name refused.
    for (name, expected) in [
        ("frozen", "VERIFY_TOKEN_EXTENDED_STATE"),
        ("frozen\u{1b}[31m", "VERIFY_TOKEN_ARTIFACT_INVALID"),
    ] {
        let spec =
            Spec::standard().with_field(name, TypeArtifact::Bool, ArtifactValue::Bool(false));
        let e = warnings_for(&spec, &[]).unwrap_err();
        assert_eq!(e.code(), expected, "{name:?}");
        assert!(printable_ascii(&e.to_string()), "{e}");
    }
    // A serde error that echoes the text: a type kind with an escape sequence.
    let (t, _) = token_terms(&Spec::standard());
    let json = Spec::standard().artifact_json().replacen(
        "\"kind\":\"int\"",
        "\"kind\":\"\\u001b[31mpwn\"",
        1,
    );
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    let e = token_warnings(&checked(&t), Some(&evidence), None).unwrap_err();
    assert_eq!(e.code(), "VERIFY_TOKEN_ARTIFACT_INVALID");
    let shown = e.to_string();
    assert!(
        printable_ascii(&shown) && shown.contains("\\u{1b}[31mpwn"),
        "{shown}"
    );
    // An address the parser refuses for its prefix, which it echoes.
    let (a, c) = agreed_addresses();
    let hostile = Some(a.unwrap().replace("kaspa:", "\u{1b}[2Jkaspa:"));
    let e = verify_addresses(&checked(&t), &ctx(&t), &offered(&hostile, &c)).unwrap_err();
    assert_eq!(e.code(), "VERIFY_ADDRESS_MALFORMED");
    let shown = e.to_string();
    assert!(
        printable_ascii(&shown) && shown.contains("\\u{1b}[2Jkaspa"),
        "{shown}"
    );
}

#[test]
fn the_token_template_triple_must_be_the_legs() {
    let spec = Spec::standard();
    let (t, _) = token_terms(&spec);
    let json = spec.artifact_json();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    token_warnings(&checked(&t), Some(&evidence), None).expect("control");
    let edits: [fn(&mut Kcc20Token); 3] = [
        |k| k.template_hash[0] ^= 1,
        |k| k.template_prefix_len += 1,
        |k| k.template_suffix_len -= 1,
    ];
    for edit in edits {
        let mut t = t.clone();
        let LegKind::Kcc20(k) = &mut t.asset_leg.kind else {
            unreachable!("KCC-20 asset")
        };
        edit(k);
        let err = token_warnings(&checked(&t), Some(&evidence), None).unwrap_err();
        let VerifyError::TokenTemplateMismatch { found, .. } = &err else {
            panic!("{err}");
        };
        assert_eq!(*found, TemplateTriple::from(&spec.triple()));
    }
}

#[test]
fn evidence_for_a_leg_without_a_token_is_refused() {
    let t = vector(2); // KAS cash
    let spec = Spec::standard();
    let json = spec.artifact_json();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    token_warnings(&checked(&t), None, None).expect("control");
    assert_eq!(
        token_warnings(&checked(&t), None, Some(&evidence)),
        Err(VerifyError::TokenLegKind {
            leg: LegIndex::Cash
        })
    );
}

#[test]
fn before_funding_runs_both_checks() {
    let t = agreed();
    let (a, c) = agreed_addresses();
    let report = before_funding(&checked(&t), &ctx(&t), &offered(&a, &c), None, None).unwrap();
    assert_eq!(report.addresses.len(), 2);
    assert_eq!(report.warnings.len(), 2);
    assert!(!report.token_legs_assessed());
    assert_eq!(
        code(before_funding(
            &checked(&t),
            &ctx(&t),
            &offered(&c, &a),
            None,
            None
        )),
        "VERIFY_LEGS_SWAPPED"
    );
}

#[test]
fn a_funding_check_says_whether_every_token_leg_was_read() {
    // Vector 1's tokens replaced by the synthetic template, so evidence for both legs reads.
    let spec = Spec::standard();
    let mut t = agreed();
    for leg in [&mut t.asset_leg, &mut t.cash_leg] {
        let LegKind::Kcc20(k) = &mut leg.kind else {
            unreachable!("vector 1 has two KCC-20 legs")
        };
        *k = Kcc20Token {
            covenant_id: k.covenant_id,
            ..spec.triple()
        };
    }
    let (a, c) = (
        Some(address_of(&t, LegIndex::Asset)),
        Some(address_of(&t, LegIndex::Cash)),
    );
    let json = spec.artifact_json();
    let evidence = TokenEvidence {
        artifact_json: &json,
        issuer_keys: &[],
    };
    let run = |asset, cash| {
        before_funding(&checked(&t), &ctx(&t), &offered(&a, &c), asset, cash).unwrap()
    };
    assert!(run(Some(&evidence), Some(&evidence)).token_legs_assessed());
    assert!(!run(Some(&evidence), None).token_legs_assessed());
    assert!(!run(None, Some(&evidence)).token_legs_assessed());
}

// ---------------------------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------------------------

#[test]
fn verify_error_codes_are_frozen() {
    // Renaming or reordering a code breaks integrators; this list may only grow at the end.
    assert_eq!(
        VERIFY_ERROR_CODES,
        [
            "VERIFY_ADDRESS_MALFORMED",
            "VERIFY_ADDRESS_NETWORK",
            "VERIFY_ADDRESS_MISMATCH",
            "VERIFY_ADDRESS_MISSING",
            "VERIFY_ADDRESS_UNEXPECTED",
            "VERIFY_LEGS_SWAPPED",
            "VERIFY_TEMPLATE_MISMATCH",
            "VERIFY_TERMS_MISMATCH",
            "VERIFY_TOKEN_LEG_KIND",
            "VERIFY_TOKEN_ARTIFACT_INVALID",
            "VERIFY_TOKEN_TEMPLATE_MISMATCH",
            "VERIFY_TOKEN_NOT_KCC20",
            "VERIFY_NOTHING_REVEALED",
            "VERIFY_TOKEN_EXTENDED_STATE",
            "VERIFY_INPUT_NOT_VAULT",
        ]
    );
    let leg = LegIndex::Asset;
    let triple = TemplateTriple {
        hash: [0; 32],
        prefix_len: 1,
        suffix_len: 1,
    };
    let all = [
        VerifyError::AddressMalformed {
            leg,
            reason: "r".into(),
        },
        VerifyError::AddressNetwork {
            leg,
            expected: Network::Mainnet,
            found: "kaspatest".into(),
        },
        VerifyError::AddressMismatch { leg },
        VerifyError::AddressMissing { leg },
        VerifyError::AddressUnexpected { leg },
        VerifyError::LegsSwapped { leg },
        VerifyError::TemplateMismatch {
            expected: [0; 32],
            found: None,
        },
        VerifyError::TermsMismatch { fields: vec![] },
        VerifyError::TokenLegKind { leg },
        VerifyError::TokenArtifactInvalid {
            leg,
            reason: "r".into(),
        },
        VerifyError::TokenTemplateMismatch {
            leg,
            expected: triple,
            found: triple,
        },
        VerifyError::TokenNotKcc20 {
            leg,
            reason: "r".into(),
        },
        VerifyError::NothingRevealed,
        VerifyError::TokenExtendedState {
            leg,
            fields: vec!["f".into()],
        },
        VerifyError::InputNotVault,
    ];
    let codes: Vec<&str> = all.iter().map(VerifyError::code).collect();
    assert_eq!(codes, VERIFY_ERROR_CODES);
    for e in &all {
        assert!(e.to_string().starts_with(e.code()), "{e}");
    }
    // Wrapped refusals keep their own codes.
    let wrapped: VerifyError = TemplateError::NoVault { leg, reason: "r" }.into();
    assert_eq!(wrapped.code(), "TEMPLATE_NO_VAULT");
}

#[test]
fn token_warning_codes_are_frozen() {
    assert_eq!(
        TOKEN_WARNING_CODES,
        [
            "TOKEN_UNASSESSED",
            "TOKEN_MINTER_BRANCH",
            "TOKEN_EXTRA_ENTRIES",
            "TOKEN_PARTY_IS_ISSUER",
            "TOKEN_TEMPLATE_UNPINNED",
            "TOKEN_ISSUER_UNKNOWN",
            "TOKEN_FOREIGN_AT_VAULT",
        ]
    );
    let all = [
        TokenWarningKind::Unassessed,
        TokenWarningKind::MinterBranch,
        TokenWarningKind::ExtraEntries { entries: vec![] },
        TokenWarningKind::PartyIsIssuer {
            party: Party::Buyer,
            relation: Relation::Counterparty,
        },
        TokenWarningKind::TemplateUnpinned,
        TokenWarningKind::IssuerUnknown,
        TokenWarningKind::ForeignAtVault {
            covenant_id: [0xCA; 32],
        },
    ]
    .map(|kind| TokenWarning {
        leg: LegIndex::Asset,
        kind,
    });
    let codes: Vec<&str> = all.iter().map(TokenWarning::code).collect();
    assert_eq!(codes, TOKEN_WARNING_CODES);
    for w in &all {
        assert!(w.to_string().starts_with(w.code()), "{w}");
    }
}

// ---------------------------------------------------------------------------------------------
// Properties (review round 1, MEDIUM 5)
// ---------------------------------------------------------------------------------------------

fn known(code: &str) -> bool {
    VERIFY_ERROR_CODES.contains(&code)
        || crate::template::TEMPLATE_ERROR_CODES.contains(&code)
        || crate::terms::TERMS_ERROR_CODES.contains(&code)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any text as a token artifact: never a panic, a frozen code if refused.
    #[test]
    fn any_artifact_text_reads_or_refuses_with_a_frozen_code(text in ".{0,300}") {
        let (t, _) = token_terms(&Spec::standard());
        let evidence = TokenEvidence { artifact_json: &text, issuer_keys: &[] };
        if let Err(e) = token_warnings(&checked(&t), Some(&evidence), None) {
            prop_assert!(known(e.code()), "{}", e.code());
            prop_assert!(printable_ascii(&e.to_string()), "{}", e);
        }
    }

    /// One character of a valid artifact changed: never a panic, a frozen code if refused.
    #[test]
    fn a_changed_artifact_reads_or_refuses_with_a_frozen_code(
        position in any::<prop::sample::Index>(),
        c in proptest::char::range(' ', '~'),
    ) {
        let spec = Spec::standard();
        let (t, _) = token_terms(&spec);
        let mut json: Vec<char> = spec.artifact_json().chars().collect();
        let i = position.index(json.len());
        json[i] = c;
        let json: String = json.into_iter().collect();
        let evidence = TokenEvidence { artifact_json: &json, issuer_keys: &[] };
        match token_warnings(&checked(&t), Some(&evidence), None) {
            Ok(warnings) => for w in warnings {
                prop_assert!(printable_ascii(&w.to_string()), "{}", w);
            },
            Err(e) => {
                prop_assert!(known(e.code()), "{}", e.code());
                prop_assert!(printable_ascii(&e.to_string()), "{}", e);
            }
        }
    }

    /// Address text with a valid checksum, any prefix and any payload: never a panic, a frozen
    /// code if refused.
    #[test]
    fn any_checksummed_address_text_verifies_or_refuses_with_a_frozen_code(
        prefix in prop::sample::select(vec!["kaspa", "kaspatest", "kaspasim", "kaspadev", "bitcoin"]),
        symbols in proptest::collection::vec(0u8..32, 0..80),
        version in prop::sample::select(vec![None, Some(0u8), Some(1), Some(8)]),
    ) {
        let mut symbols = symbols;
        if let Some(v) = version {
            let n = symbols.len();
            symbols.splice(..n.min(2), versioned_symbols(v, n.min(2)));
        }
        let text = Some(bech32_text(prefix, &symbols));
        let t = agreed();
        let (_, c) = agreed_addresses();
        if let Err(e) = verify_addresses(&checked(&t), &ctx(&t), &offered(&text, &c)) {
            prop_assert!(known(e.code()), "{}", e.code());
            prop_assert!(printable_ascii(&e.to_string()), "{}", e);
        }
    }

    /// Any signature script on a spent input: never a panic, a frozen code if refused.
    #[test]
    fn any_spent_input_verifies_or_refuses_with_a_frozen_code(
        sigscript in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let input = TransactionInput::new_with_compute_budget(
            TransactionOutpoint::default(), sigscript, 0, 0);
        let t = agreed();
        let spent = pay_to_script_hash_script(&script(&t, LegIndex::Asset));
        if let Err(e) = verify_spent_input(&checked(&t), LegIndex::Asset, &input, &spent) {
            prop_assert!(known(e.code()), "{}", e.code());
        }
    }
}
