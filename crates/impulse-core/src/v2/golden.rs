// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Golden v2 vectors (spec/V2.md 5.4): terms v2 under tests/vectors/terms_v2/, each vector's N
//! vault scripts under tests/vectors/vaults_v2/, and unsigned IPSTs of version 2 under
//! tests/vectors/ipst_v2/. The definitions render to the committed files byte for byte; the files
//! are frozen once on main, so a codec, template or builder change fails `golden_files_match`.
//! scripts/vectors.sh regenerates them through `emit_vectors`, diffs them, and checks them again
//! in Python from spec/V2.md alone.
//!
//! Every key is label-derived (nobody holds its private key), every covenant ID and outpoint too.
//! KCC-20 legs name the pinned kcc20.sil template of the fixtures, so the vectors are also the
//! inputs of the engine runs of tests/engine/v2_builders.rs.

use super::testkit::*;
use super::*;
use crate::terms::golden::label32;
use crate::terms::Kcc20Owner;
use crate::terms::{CreationContext, FundingMode, IdentifierType, LegKind, Network};
use crate::tx::ipst::{hex, write_json, J};
use crate::tx::{p2pk, FeePayment, Kcc20Deposit, Kcc20State, TokenUtxo, Utxo};
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use std::path::{Path, PathBuf};

const NS: &str = "vectors";
/// DAA score the vectors' addresses are computed at (creation checks).
const CREATION_DAA: u64 = 900_000;

pub(crate) struct TermsVector {
    pub name: &'static str,
    pub description: &'static str,
    pub terms: TermsV2,
}

fn covenant_owner(label: &str) -> DestinationV2 {
    DestinationV2 {
        identifier_type: IdentifierType::CovenantId,
        identifier: label32(label),
    }
}

pub(crate) fn terms_vectors() -> Vec<TermsVector> {
    let ring = ring3(NS, true);
    let mut with_kas = with_kas3(NS, false);
    with_kas.network = Network::Testnet;
    with_kas.funding_mode = FundingMode::Earmarked;
    with_kas.legs[0].refund = script_hash(label32("impulse/vectors/v2/owner/party0-script"));
    with_kas.legs[1].delivery = covenant_owner("impulse/vectors/v2/owner/party2-covenant");
    let bilateral = bilateral10(NS, true);
    let mut two_kas_cash = two_kas(NS, true);
    two_kas_cash.funding_mode = FundingMode::Earmarked;
    two_kas_cash.legs[1].delivery = script_hash(label32("impulse/vectors/v2/kas/party0-script"));
    let mut two_token_cash = two_kcc20(NS, false);
    two_token_cash.network = Network::Testnet;
    let mut partial_one = two_kas(NS, true);
    partial_one.partial = Some(Partial {
        lot_count: 4,
        min_lot: 1,
    });
    let mut partial_all = ring3(NS, false);
    partial_all.network = Network::Testnet;
    partial_all.funding_mode = FundingMode::Earmarked;
    partial_all.earliest_daa = None;
    partial_all.partial = Some(Partial {
        lot_count: 5,
        min_lot: 5,
    });
    let kas_ring = kas_ring3(NS, true);
    vec![
        TermsVector {
            name: "01-three-way-ring-kcc20",
            description: "Three parties, three KCC-20 legs in a ring (party 0 pays party 1, 1 pays 2, 2 pays 0), with a settlement authority, revocable funding, earliest settlement set. Mainnet.",
            terms: ring,
        },
        TermsVector {
            name: "02-three-way-kcc20-kcc20-kas",
            description: "Three parties: two KCC-20 legs and a KAS leg last, self-settling, earmarked funding, no earliest bound. A SCRIPT_HASH refund owner, a COVENANT_ID delivery owner, a KAS P2PK delivery and a KAS P2SH refund. Testnet.",
            terms: {
                let mut t = with_kas;
                t.earliest_daa = None;
                t
            },
        },
        TermsVector {
            name: "03-ten-leg-bilateral",
            description: "The ten-leg bilateral list of the I16 brief: two parties, nine KCC-20 legs alternating between them and one KAS leg, with a settlement authority. The parties agreed the list; Impulse settles it and computes nothing from it. Mainnet.",
            terms: bilateral,
        },
        TermsVector {
            name: "04-two-leg-kcc20-kas",
            description: "N = 2 equivalent of v1's KAS-cash mode: a KCC-20 leg and a KAS leg, with a settlement authority, earmarked funding, the KAS delivered to a P2SH. Mainnet.",
            terms: two_kas_cash,
        },
        TermsVector {
            name: "05-two-leg-kcc20-kcc20",
            description: "N = 2 equivalent of v1's KCC-20-cash mode: two KCC-20 legs, self-settling, revocable funding. Testnet.",
            terms: two_token_cash,
        },
        TermsVector {
            name: "06-partial-min-lot-one",
            description: "Partial terms with lot_count 4 and min_lot 1 on a KCC-20 leg and a KAS leg, with a settlement authority. Mainnet.",
            terms: partial_one,
        },
        TermsVector {
            name: "07-partial-min-lot-all",
            description: "Partial terms with min_lot equal to lot_count (5) on the three-way ring, self-settling, earmarked funding, no earliest bound. Testnet.",
            terms: partial_all,
        },
        TermsVector {
            name: "08-three-way-ring-kas",
            description: "Three parties, three KAS legs in a ring (party 0 pays party 1, 1 pays 2, 2 pays 0), with a settlement authority, revocable funding, earliest settlement set. The shape of the mainnet demo, with no token. Mainnet.",
            terms: kas_ring,
        },
    ]
}

// =============================================================================================
// JSON
// =============================================================================================

fn dec(n: u64) -> J {
    J::Str(n.to_string())
}

fn id_name(t: IdentifierType) -> &'static str {
    match t {
        IdentifierType::PubKey => "pubkey",
        IdentifierType::ScriptHash => "script_hash",
        IdentifierType::CovenantId => "covenant_id",
    }
}

fn destination_json(d: &DestinationV2) -> J {
    J::Obj(vec![
        ("identifier_type", J::Str(id_name(d.identifier_type).into())),
        ("identifier", J::Str(hex(&d.identifier))),
    ])
}

fn leg_json(l: &LegV2) -> J {
    let mut asset = Vec::new();
    match &l.asset.kind {
        LegKind::Kas => asset.push(("kind", J::Str("kas".into()))),
        LegKind::Kcc20(t) => {
            asset.push(("kind", J::Str("kcc20".into())));
            asset.push(("covenant_id", J::Str(hex(&t.covenant_id))));
            asset.push(("template_hash", J::Str(hex(&t.template_hash))));
            asset.push(("template_prefix_len", J::Int(t.template_prefix_len.into())));
            asset.push(("template_suffix_len", J::Int(t.template_suffix_len.into())));
        }
        LegKind::External => asset.push(("kind", J::Str("external".into()))),
    }
    asset.push(("amount", dec(l.asset.amount)));
    J::Obj(vec![
        ("depositor_key", J::Str(hex(&l.depositor_key))),
        ("asset", J::Obj(asset)),
        ("delivery", destination_json(&l.delivery)),
        ("refund", destination_json(&l.refund)),
    ])
}

fn terms_json(t: &TermsV2) -> J {
    J::Obj(vec![
        ("version", J::Int(t.version.into())),
        (
            "network",
            J::Str(
                match t.network {
                    Network::Mainnet => "mainnet",
                    Network::Testnet => "testnet",
                }
                .into(),
            ),
        ),
        ("nonce", dec(t.nonce)),
        (
            "authority_key",
            t.authority_key.map_or(J::Null, |k| J::Str(hex(&k))),
        ),
        ("legs", J::Arr(t.legs.iter().map(leg_json).collect())),
        ("earliest_daa", t.earliest_daa.map_or(J::Null, dec)),
        ("expiry_daa", dec(t.expiry_daa)),
        (
            "funding_mode",
            J::Str(
                match t.funding_mode {
                    FundingMode::Revocable => "revocable",
                    FundingMode::Earmarked => "earmarked",
                }
                .into(),
            ),
        ),
        (
            "partial",
            t.partial.map_or(J::Null, |p| {
                J::Obj(vec![
                    ("lot_count", dec(p.lot_count)),
                    ("min_lot", dec(p.min_lot)),
                ])
            }),
        ),
        ("trade_ref", J::Str(hex(&t.trade_ref))),
    ])
}

fn rendered(doc: J) -> String {
    let mut out = String::new();
    write_json(&doc, 0, &mut out);
    out.push('\n');
    out
}

fn render_terms(v: &TermsVector) -> String {
    rendered(J::Obj(vec![
        ("name", J::Str(v.name.into())),
        ("description", J::Str(v.description.into())),
        ("terms", terms_json(&v.terms)),
        (
            "canonical",
            J::Str(hex(&v.terms.encode().expect("encodes"))),
        ),
        (
            "terms_hash",
            J::Str(hex(&v.terms.terms_hash().expect("hashes"))),
        ),
    ]))
}

fn render_vaults(v: &TermsVector) -> String {
    let terms = v.terms.clone().validate_structure().expect(v.name);
    let ctx = CreationContext::new(terms.terms().network, CREATION_DAA);
    let vaults = (0..terms.terms().legs.len())
        .map(|i| {
            let fundable = VaultV2::instantiate_for_creation(&terms, i, &ctx).expect("vault");
            let vault = fundable.vault();
            J::Obj(vec![
                ("leg_index", J::Int(i as u64)),
                ("redeem_script", J::Str(hex(vault.redeem_script()))),
                ("script_hash", J::Str(hex(&vault.script_hash()))),
                ("address", J::Str(vault_address(&fundable))),
            ])
        })
        .collect();
    rendered(J::Obj(vec![
        ("name", J::Str(v.name.into())),
        ("terms_hash", J::Str(hex(&terms.terms_hash()))),
        (
            "template_hash",
            J::Str(hex(&check_template().expect("template").hash())),
        ),
        ("vaults", J::Arr(vaults)),
    ]))
}

// =============================================================================================
// IPST vectors
// =============================================================================================

struct IpstVector {
    name: &'static str,
    description: &'static str,
    ipst: IpstV2,
}

fn terms_named(name: &str) -> ValidatedTermsV2 {
    terms_vectors()
        .into_iter()
        .find(|v| v.name == name)
        .expect("named terms vector")
        .terms
        .validate_structure()
        .expect("vector terms validate")
}

/// The UTXO output `index` of an IPST's transaction becomes (what a later transaction spends).
fn made(ipst: &IpstV2, index: usize) -> Utxo {
    let tx = ipst.transaction();
    let o = &tx.outputs[index];
    Utxo {
        outpoint: TransactionOutpoint::new(tx.id(), index as u32),
        entry: UtxoEntry::new(
            o.value,
            o.script_public_key.clone(),
            100,
            false,
            o.covenant.map(|c| c.covenant_id),
        ),
    }
}

/// The I17 chain of terms vector 06 (a KCC-20 leg against a KAS leg, four lots, min_lot 1, with an
/// authority): each leg funded as its own genesis, a tranche of 1 lot, the final 3 lots. Every transaction spends the outputs of the one before it.
fn partial_chain() -> Vec<(&'static str, &'static str, IpstV2)> {
    let tmpl = template();
    let terms = terms_named("06-partial-min-lot-one");
    let t = terms.terms();
    let fundable = |leg| {
        let ctx = CreationContext::new(t.network, CREATION_DAA);
        VaultV2::instantiate_for_creation(&terms, leg, &ctx).expect("fundable")
    };
    let funding = |label: &str| FeePayment {
        inputs: vec![utxo(
            &format!("vectors/v2/partial/{label}"),
            5 * FEE_INPUT,
            p2pk(&party(NS, 1)),
            None,
        )],
        fee: FEE,
        change: p2pk(&party(NS, 1)),
    };
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: party(NS, 0),
        },
        2 * TOKEN_AMOUNT,
    );
    let deposit = Kcc20Deposit {
        tokens: vec![TokenUtxo {
            utxo: utxo(
                "vectors/v2/partial/party0-token",
                min_v2(t, 2),
                tmpl.script_public_key(&state).expect("token script"),
                Some(token(0).covenant_id),
            ),
            state,
        }],
        carrier: min_v2(t, 2),
        authorizer: min_vault_v2(t),
    };
    let fund_token = fund_kcc20(
        &terms,
        &fundable(0),
        &tmpl,
        &deposit,
        &funding("fund-token"),
        NOW,
    )
    .expect("fund_kcc20 genesis");
    let fund_kas =
        fund_kas(&terms, &fundable(1), &funding("fund-kas"), NOW).expect("fund_kas genesis");
    // Leg 0: the authorizer at output 1 and the escrow at output 0; leg 1: the KAS at output 0.
    let mut funded = vec![
        Funded {
            vault: made(&fund_token, 1),
            escrow: Some((made(&fund_token, 0), t.legs[0].asset.amount)),
        },
        Funded {
            vault: made(&fund_kas, 0),
            escrow: None,
        },
    ];
    let mut out = vec![
        ("fund-kcc20-partial-genesis", "Funding of leg 0 of terms vector 06 as a KIP-20 genesis: the authorizer at output 1 is bound to a covenant ID made over the first payer input and that output alone; the escrow keeps the token's covenant. Token change and KAS change follow.", fund_token),
        ("fund-kas-partial-genesis", "Funding of the KAS leg (leg 1) of terms vector 06 as its own KIP-20 genesis: output 0 is bound to a covenant ID made over the first payer input and that output alone.", fund_kas),
    ];
    // A remainder of a KAS leg holds at least MIN_V2(2, O) (two storage units, a covenant ID),
    // 53,333,334 sompi for the five outputs of this trade, so only the first lot of this
    // 1 KAS leg can be a tranche.
    let steps: [(&str, &str, u64); 2] = [
        ("settle-tranche-one-lot", "Tranche of 1 lot of 4 on terms vector 06, spending the two genesis outputs of the funding vectors: deliveries at 0 and 1, the continuations (same script, bound to the covenant IDs) at 2 and 3, the remainder token at 4.", 1),
        ("settle-final-three-lots", "The remaining 3 lots, spending the continuations and the remainder token of the tranche: the final layout (deliveries, then the authorizer home), no continuation of the covenant.", 3),
    ];
    for (i, (name, description, lots)) in steps.into_iter().enumerate() {
        let ipst = settle_tranche(
            &terms,
            &settle_legs(&funded, &tmpl),
            lots,
            &fee_payment(&format!("{NS}/partial/step{i}")),
            NOW,
        )
        .expect("tranche");
        let n = t.legs.len();
        if i < 1 {
            funded = (0..n)
                .map(|j| Funded {
                    vault: made(&ipst, n + j),
                    escrow: funded[j]
                        .escrow
                        .as_ref()
                        .map(|(_, held)| (made(&ipst, 2 * n + j), held - lots * t.unit(j))),
                })
                .collect();
        }
        out.push((name, description, ipst));
    }
    out
}

fn ipst_vectors() -> Vec<IpstVector> {
    let tmpl = template();
    let fee = fee_payment(NS);
    let ring = terms_named("01-three-way-ring-kcc20");
    let with_kas = terms_named("02-three-way-kcc20-kcc20-kas");
    let ten = terms_named("03-ten-leg-bilateral");
    let kas_ring = terms_named("08-three-way-ring-kas");
    let settle_of = |t: &ValidatedTermsV2, label: &str| {
        let f = funded(t, &format!("{NS}/{label}"));
        settle(t, &settle_legs(&f, &tmpl), &fee, NOW).expect("settle")
    };
    let refund_of = |t: &ValidatedTermsV2, label: &str, leg, signer, token: bool| {
        let f = funded(t, &format!("{NS}/{label}"));
        let escrow = if token {
            refund_escrow(&f[leg], &tmpl)
        } else {
            None
        };
        refund(t, leg, signer, &f[leg].vault, escrow.as_ref(), &fee).expect("refund")
    };
    let fundable = |t: &ValidatedTermsV2, leg| {
        let ctx = CreationContext::new(t.terms().network, CREATION_DAA);
        VaultV2::instantiate_for_creation(t, leg, &ctx).expect("fundable")
    };
    let deposit = {
        let owner = party(NS, 0);
        let state = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: owner,
            },
            3 * TOKEN_AMOUNT,
        );
        Kcc20Deposit {
            tokens: vec![TokenUtxo {
                utxo: utxo(
                    "vectors/v2/party0-token",
                    min_v2(ring.terms(), 2),
                    tmpl.script_public_key(&state).expect("token script"),
                    Some(token(0).covenant_id),
                ),
                state,
            }],
            carrier: min_v2(ring.terms(), 2),
            authorizer: min_v2(ring.terms(), 1),
        }
    };
    let funding = FeePayment {
        inputs: vec![utxo(
            "vectors/v2/funding",
            5 * FEE_INPUT,
            p2pk(&party(NS, 1)),
            None,
        )],
        fee: FEE,
        change: p2pk(&party(NS, 1)),
    };
    let mut out = vec![
        IpstVector {
            name: "01-settle-three-way-ring",
            description: "Final settle of terms vector 01: three vault inputs signed by the authority, three escrows, three deliveries, three authorizers home.",
            ipst: settle_of(&ring, "ring"),
        },
        IpstVector {
            name: "02-settle-ten-leg-bilateral",
            description: "Final settle of terms vector 03: ten vault inputs signed by the authority, nine escrows, ten deliveries, nine authorizers home.",
            ipst: settle_of(&ten, "ten"),
        },
        IpstVector {
            name: "03-settle-three-way-with-kas-self-settling",
            description: "Final settle of terms vector 02, self-settling: no vault input takes a signature; the KAS leg's vault UTXO is the delivery's whole value. Lock time 0.",
            ipst: settle_of(&with_kas, "with-kas"),
        },
        IpstVector {
            name: "04-refund-kcc20-depositor-earmarked",
            description: "Refund of leg 0 of terms vector 02 by its depositor with the escrowed token: earmarked, so the lock time is expiry_daa.",
            ipst: refund_of(&with_kas, "with-kas", 0, RefundSignerV2::Depositor(0), true),
        },
        IpstVector {
            name: "05-refund-kas-authority",
            description: "Refund of the KAS leg (leg 9) of terms vector 03 by the authority (signerLeg 10) to the leg's P2SH refund destination.",
            ipst: refund_of(&ten, "ten", 9, RefundSignerV2::Authority, false),
        },
        IpstVector {
            name: "06-refund-kcc20-another-depositor",
            description: "Refund of leg 1 of terms vector 01 by party 2, the depositor of leg 2 (signerLeg 2), which takes the escrowed token home to leg 1's depositor.",
            ipst: refund_of(&ring, "ring", 1, RefundSignerV2::Depositor(2), true),
        },
        IpstVector {
            name: "07-refund-kcc20-authorizer-alone",
            description: "Refund of leg 0 of terms vector 01 by its depositor without the escrowed token: the authorizer goes home alone.",
            ipst: refund_of(&ring, "ring", 0, RefundSignerV2::Depositor(0), false),
        },
        IpstVector {
            name: "08-fund-kas",
            description: "Funding of the KAS leg (leg 9) of terms vector 03: exactly the leg amount at the leg's vault.",
            ipst: fund_kas(&ten, &fundable(&ten, 9), &funding, NOW).expect("fund_kas"),
        },
        IpstVector {
            name: "09-fund-kcc20-with-token-change",
            description: "Funding of leg 0 of terms vector 01 from a token UTXO of three times the leg amount: escrow, authorizer, token change, KAS change.",
            ipst: fund_kcc20(&ring, &fundable(&ring, 0), &tmpl, &deposit, &funding, NOW)
                .expect("fund_kcc20"),
        },
        IpstVector {
            name: "10-settle-three-way-ring-kas",
            description: "Final settle of terms vector 08: three KAS vault inputs signed by the authority, three deliveries, no escrow and no authorizer. Compute budgets of the K = 0 rule.",
            ipst: settle_of(&kas_ring, "kas-ring"),
        },
        IpstVector {
            name: "11-fund-kas-three-way-ring",
            description: "Funding of leg 2 of terms vector 08: exactly the leg amount at the leg's vault.",
            ipst: fund_kas(&kas_ring, &fundable(&kas_ring, 2), &funding, NOW).expect("fund_kas"),
        },
    ];
    let names = [
        "12-fund-kcc20-partial-genesis",
        "13-fund-kas-partial-genesis",
        "14-settle-tranche-one-lot",
        "15-settle-final-three-lots",
    ];
    for (name, (_, description, ipst)) in names.into_iter().zip(partial_chain()) {
        out.push(IpstVector {
            name,
            description,
            ipst,
        });
    }
    out
}

fn render_ipst(v: &IpstVector) -> String {
    rendered(J::Obj(vec![
        ("name", J::Str(v.name.into())),
        ("description", J::Str(v.description.into())),
        ("ipst", v.ipst.to_value()),
    ]))
}

// =============================================================================================
// Files
// =============================================================================================

fn dir(set: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(set)
}

/// Every (set, file name, content) the generator writes.
fn all_files() -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    for v in terms_vectors() {
        out.push(("terms_v2", format!("{}.json", v.name), render_terms(&v)));
        out.push(("vaults_v2", format!("{}.json", v.name), render_vaults(&v)));
    }
    for v in ipst_vectors() {
        out.push(("ipst_v2", format!("{}.json", v.name), render_ipst(&v)));
    }
    out
}

#[test]
fn golden_files_match() {
    let files = all_files();
    for set in ["terms_v2", "vaults_v2", "ipst_v2"] {
        let mut expected: Vec<&str> = files
            .iter()
            .filter(|(s, _, _)| *s == set)
            .map(|(_, n, _)| n.as_str())
            .collect();
        expected.sort();
        let d = dir(set);
        let mut found: Vec<String> = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("read {}: {e}", d.display()))
            .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
            .filter(|name| !name.starts_with('.'))
            .collect();
        found.sort();
        assert_eq!(
            found, expected,
            "tests/vectors/{set} holds exactly the golden set"
        );
    }
    for (set, name, content) in &files {
        let path = dir(set).join(name);
        let committed = std::fs::read_to_string(&path).expect("read vector");
        assert!(
            committed == *content,
            "{} differs from its definition; golden vectors are frozen (run scripts/vectors.sh for the diff)",
            path.display()
        );
    }
}

#[test]
fn golden_terms_decode_hash_and_validate() {
    for v in terms_vectors() {
        let text = std::fs::read_to_string(dir("terms_v2").join(format!("{}.json", v.name)))
            .expect("read");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
        let canonical =
            crate::tx::ipst::unhex(doc["canonical"].as_str().expect("canonical")).expect("hex");
        let decoded = TermsV2::decode(&canonical).expect("committed bytes decode");
        assert_eq!(decoded, v.terms, "{}", v.name);
        assert_eq!(decoded.encode().unwrap(), canonical);
        assert_eq!(
            hex(&decoded.terms_hash().unwrap()),
            doc["terms_hash"].as_str().unwrap()
        );
        let checked = decoded.validate_structure().expect(v.name);
        let ctx = CreationContext::new(v.terms.network, CREATION_DAA);
        assert_eq!(checked.validate_creation(&ctx), Ok(()), "{}", v.name);
    }
}

#[test]
fn golden_vaults_decode_to_their_terms() {
    for v in terms_vectors() {
        let text = std::fs::read_to_string(dir("vaults_v2").join(format!("{}.json", v.name)))
            .expect("read");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
        let vaults = doc["vaults"].as_array().expect("vaults");
        assert_eq!(vaults.len(), v.terms.legs.len());
        for (i, vault) in vaults.iter().enumerate() {
            let script = crate::tx::ipst::unhex(vault["redeem_script"].as_str().unwrap()).unwrap();
            let (terms, leg) = decode_vault(&script).expect("decodes");
            assert_eq!(terms.terms(), &v.terms, "{} leg {i}", v.name);
            assert_eq!(leg, i);
        }
    }
}

#[test]
fn golden_ipsts_read_back_and_pass_the_terms_check() {
    let tmpl = template();
    for v in ipst_vectors() {
        let text =
            std::fs::read_to_string(dir("ipst_v2").join(format!("{}.json", v.name))).expect("read");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
        let AnyIpst::V2(read) = read_ipst(&doc["ipst"].to_string()).expect("reads") else {
            panic!("{}: not version 2", v.name);
        };
        assert_eq!(*read, v.ipst, "{}", v.name);
        let k = read.terms().terms().kcc20_legs();
        let templates = vec![&tmpl; k];
        read.verify_against_terms(&templates, NOW)
            .unwrap_or_else(|e| panic!("{}: {e}", v.name));
    }
}

/// spec/V2.md 5.4: the set covers a 3-way swap, a 3-way swap with a KAS leg, the ten-leg list,
/// both N = 2 modes, partial with min_lot 1 and min_lot = lot_count, both networks, both funding
/// modes, authority present and absent, every destination type, and the bounds of leg_count.
#[test]
fn golden_set_covers_spec_5_4() {
    let vs = terms_vectors();
    let ts: Vec<&TermsV2> = vs.iter().map(|v| &v.terms).collect();
    let any = |f: &dyn Fn(&TermsV2) -> bool| ts.iter().any(|t| f(t));
    assert!(any(&|t| t.legs.len() == 2));
    assert!(any(&|t| t.legs.len() == MAX_LEGS));
    assert!(any(&|t| t.legs.len() == 3 && t.kcc20_legs() == 3));
    assert!(any(&|t| t.legs.len() == 3 && t.kcc20_legs() == 2));
    assert!(any(&|t| t.legs.len() == 10 && t.kcc20_legs() == 9));
    assert!(any(&|t| t.network == Network::Mainnet));
    assert!(any(&|t| t.network == Network::Testnet));
    assert!(any(&|t| t.funding_mode == FundingMode::Revocable));
    assert!(any(&|t| t.funding_mode == FundingMode::Earmarked));
    assert!(any(&|t| t.authority_key.is_some()));
    assert!(any(&|t| t.authority_key.is_none()));
    assert!(any(&|t| t.partial.is_some_and(|p| p.min_lot == 1)));
    assert!(any(&|t| t
        .partial
        .is_some_and(|p| p.min_lot == p.lot_count)));
    assert!(any(&|t| t.earliest_daa.is_none()));
    let dests = |kas: bool, ty: IdentifierType| {
        any(&|t| {
            t.legs.iter().any(|l| {
                (l.asset.kind == LegKind::Kas) == kas
                    && [l.delivery, l.refund]
                        .iter()
                        .any(|d| d.identifier_type == ty)
            })
        })
    };
    for ty in [
        IdentifierType::PubKey,
        IdentifierType::ScriptHash,
        IdentifierType::CovenantId,
    ] {
        assert!(dests(false, ty), "KCC-20 {ty:?}");
    }
    assert!(dests(true, IdentifierType::PubKey));
    assert!(dests(true, IdentifierType::ScriptHash));
    // spec/V2.md section 1: "net" stays out of vector names.
    assert!(vs.iter().all(|v| !v.name.contains("net")));
    assert!(ipst_vectors().iter().all(|v| !v.name.contains("net")));
}

/// Writes the v2 sets to $IMPULSE_VECTORS_OUT/{terms_v2,vaults_v2,ipst_v2}/. Run by
/// scripts/vectors.sh only.
#[test]
#[ignore = "generator for scripts/vectors.sh"]
fn emit_vectors() {
    let out = std::env::var("IMPULSE_VECTORS_OUT").expect("IMPULSE_VECTORS_OUT is set");
    for (set, name, content) in all_files() {
        let d = Path::new(&out).join(set);
        std::fs::create_dir_all(&d).expect("create output dir");
        std::fs::write(d.join(name), content).expect("write vector");
    }
}
