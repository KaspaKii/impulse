// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Test fixtures for terms v2 and the v2 builders: label-derived parties (x-only keys for which
//! nobody holds a private key, rule 1, docs/ENGINEERING-RULES.md), the fixture KCC-20 template of `crate::tx`'s
//! testdata (the pinned kcc20.sil) with one covenant ID per leg, the I16 trade shapes (3-way
//! ring, 3-way with a KAS leg, ten-leg bilateral list, N = 2 in v1's two modes), funded vault
//! UTXOs and fee payments. Tests that need a signature run in the engine target
//! (tests/engine/v2_builders.rs).

use super::*;
use crate::terms::golden::{label32, xonly};
use crate::terms::{FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network};
use crate::tx::testkit::{asset_template, outpoint};
use crate::tx::{p2pk, FeePayment, Kcc20State, Kcc20Template, RefundEscrow, Utxo};
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};
use kaspa_consensus_core::Hash;

pub(crate) const EARLIEST: u64 = 1_000_000;
pub(crate) const EXPIRY: u64 = 2_000_000;
/// The DAA score the builders are called at: between earliest and expiry.
pub(crate) const NOW: u64 = 1_500_000;
pub(crate) const TOKEN_AMOUNT: u64 = 1_000;
pub(crate) const KAS_AMOUNT: u64 = 100_000_000;
pub(crate) const FEE_INPUT: u64 = 1_000_000_000;
pub(crate) const FEE: u64 = 50_000_000;

/// Label-derived parties: party `i` of a namespace (`tests` or `vectors`).
pub(crate) fn party(ns: &str, i: usize) -> [u8; 32] {
    xonly(&format!("impulse/{ns}/v2/key/party{i}"))
}

pub(crate) fn authority(ns: &str) -> [u8; 32] {
    xonly(&format!("impulse/{ns}/v2/key/authority"))
}

pub(crate) fn payer(ns: &str) -> [u8; 32] {
    xonly(&format!("impulse/{ns}/v2/key/payer"))
}

pub(crate) fn template() -> Kcc20Template {
    asset_template()
}

/// The fixture token of leg `j`: the pinned kcc20.sil template with covenant ID 0x10 + j.
pub(crate) fn token(j: usize) -> Kcc20Token {
    let t = template();
    Kcc20Token {
        covenant_id: [0x10 + j as u8; 32],
        template_hash: t.template_hash(),
        template_prefix_len: t.prefix_len() as u32,
        template_suffix_len: t.suffix_len() as u32,
    }
}

pub(crate) fn pubkey(id: [u8; 32]) -> DestinationV2 {
    DestinationV2 {
        identifier_type: IdentifierType::PubKey,
        identifier: id,
    }
}

pub(crate) fn script_hash(id: [u8; 32]) -> DestinationV2 {
    DestinationV2 {
        identifier_type: IdentifierType::ScriptHash,
        identifier: id,
    }
}

/// A KCC-20 leg of token `j` from `from` to `to`, refunded to `from`'s key.
pub(crate) fn kcc20_leg(j: usize, from: [u8; 32], to: [u8; 32], amount: u64) -> LegV2 {
    LegV2 {
        depositor_key: from,
        asset: Leg {
            kind: LegKind::Kcc20(token(j)),
            amount,
        },
        delivery: pubkey(to),
        refund: pubkey(from),
    }
}

/// A KAS leg from `from` to `to` (P2PK), refunded to a P2SH derived from `from`.
pub(crate) fn kas_leg(from: [u8; 32], to: [u8; 32], amount: u64) -> LegV2 {
    let hex: String = from.iter().map(|b| format!("{b:02x}")).collect();
    LegV2 {
        depositor_key: from,
        asset: Leg {
            kind: LegKind::Kas,
            amount,
        },
        delivery: pubkey(to),
        refund: script_hash(label32(&format!("impulse/v2/kas-refund/{hex}"))),
    }
}

pub(crate) fn terms(ns: &str, legs: Vec<LegV2>, with_authority: bool) -> TermsV2 {
    TermsV2 {
        version: TERMS_V2_VERSION,
        network: Network::Mainnet,
        nonce: 0x4E4E_4E4E,
        authority_key: with_authority.then(|| authority(ns)),
        legs,
        earliest_daa: Some(EARLIEST),
        expiry_daa: EXPIRY,
        funding_mode: FundingMode::Revocable,
        partial: None,
        trade_ref: label32(&format!("impulse/{ns}/v2/trade-ref")),
    }
}

/// Three parties, three KCC-20 legs in a ring: 0 pays 1, 1 pays 2, 2 pays 0.
pub(crate) fn ring3(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    terms(
        ns,
        (0..3)
            .map(|i| kcc20_leg(i, p(i), p((i + 1) % 3), TOKEN_AMOUNT * (i as u64 + 1)))
            .collect(),
        with_authority,
    )
}

/// Three parties: two KCC-20 legs and a KAS leg (2 pays 0 in KAS).
pub(crate) fn with_kas3(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    terms(
        ns,
        vec![
            kcc20_leg(0, p(0), p(1), TOKEN_AMOUNT),
            kcc20_leg(1, p(1), p(2), TOKEN_AMOUNT * 2),
            kas_leg(p(2), p(0), KAS_AMOUNT),
        ],
        with_authority,
    )
}

/// Three parties, three KAS legs in a ring: 0 pays 1, 1 pays 2, 2 pays 0. The shape of the
/// mainnet 3-way preparation script (shape `kas`).
pub(crate) fn kas_ring3(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    terms(
        ns,
        (0..3)
            .map(|i| kas_leg(p(i), p((i + 1) % 3), KAS_AMOUNT * (i as u64 + 1)))
            .collect(),
        with_authority,
    )
}

/// The ten-leg bilateral list: two parties, nine KCC-20 legs alternating between them, then one
/// KAS leg from party 1 to party 0.
pub(crate) fn bilateral10(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    let mut legs: Vec<LegV2> = (0..9)
        .map(|j| {
            let (from, to) = if j % 2 == 0 { (0, 1) } else { (1, 0) };
            kcc20_leg(j, p(from), p(to), TOKEN_AMOUNT * (j as u64 + 1))
        })
        .collect();
    legs.push(kas_leg(p(1), p(0), KAS_AMOUNT * 3));
    terms(ns, legs, with_authority)
}

/// N = 2 in v1's KAS-cash mode: party 0's token to party 1, party 1's KAS to party 0.
pub(crate) fn two_kas(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    terms(
        ns,
        vec![
            kcc20_leg(0, p(0), p(1), TOKEN_AMOUNT),
            kas_leg(p(1), p(0), KAS_AMOUNT),
        ],
        with_authority,
    )
}

/// N = 2 in v1's KCC-20-cash mode.
pub(crate) fn two_kcc20(ns: &str, with_authority: bool) -> TermsV2 {
    let p = |i| party(ns, i);
    terms(
        ns,
        vec![
            kcc20_leg(0, p(0), p(1), TOKEN_AMOUNT),
            kcc20_leg(1, p(1), p(0), TOKEN_AMOUNT * 250),
        ],
        with_authority,
    )
}

pub(crate) fn validated(t: TermsV2) -> ValidatedTermsV2 {
    t.validate_structure()
        .expect("fixture terms pass the structure checks")
}

pub(crate) fn utxo(label: &str, amount: u64, spk: ScriptPublicKey, cov: Option<[u8; 32]>) -> Utxo {
    Utxo {
        outpoint: outpoint(label),
        entry: UtxoEntry::new(amount, spk, 100, false, cov.map(Hash::from_bytes)),
    }
}

pub(crate) fn fee_payment(ns: &str) -> FeePayment {
    FeePayment {
        inputs: vec![utxo(
            &format!("{ns}/fee"),
            FEE_INPUT,
            p2pk(&payer(ns)),
            None,
        )],
        fee: FEE,
        change: p2pk(&payer(ns)),
    }
}

/// One funded leg: the UTXO at the vault (the authorizer of a KCC-20 leg, the KAS of a KAS leg)
/// and, for a KCC-20 leg, the escrowed token UTXO and the amount it holds.
#[derive(Clone, Debug)]
pub(crate) struct Funded {
    pub vault: Utxo,
    pub escrow: Option<(Utxo, u64)>,
}

/// Every leg funded as the fund builders fund it: KAS legs with the exact amount, KCC-20 legs
/// with an authorizer of MIN_V2(1, O) and an escrow of exactly the amount carrying MIN_V2(2, O).
pub(crate) fn funded(terms: &ValidatedTermsV2, ns: &str) -> Vec<Funded> {
    let t = terms.terms();
    let tmpl = template();
    (0..t.legs.len())
        .map(|i| {
            let vault = VaultV2::instantiate_existing(terms, i).expect("vault");
            let l = &t.legs[i];
            match l.asset.kind {
                LegKind::Kas => Funded {
                    vault: utxo(
                        &format!("{ns}/vault/{i}"),
                        l.asset.amount,
                        vault.script_public_key(),
                        None,
                    ),
                    escrow: None,
                },
                _ => {
                    let state = Kcc20State::new(
                        Kcc20Owner {
                            identifier_type: IdentifierType::ScriptHash,
                            identifier: vault.script_hash(),
                        },
                        l.asset.amount,
                    );
                    Funded {
                        vault: utxo(
                            &format!("{ns}/authorizer/{i}"),
                            min_vault_v2(t),
                            vault.script_public_key(),
                            None,
                        ),
                        escrow: Some((
                            utxo(
                                &format!("{ns}/escrow/{i}"),
                                min_v2(t, 2),
                                tmpl.script_public_key(&state).expect("escrow script"),
                                Some(token(i).covenant_id),
                            ),
                            l.asset.amount,
                        )),
                    }
                }
            }
        })
        .collect()
}

pub(crate) fn settle_legs<'a>(funded: &[Funded], tmpl: &'a Kcc20Template) -> Vec<SettleLeg<'a>> {
    funded
        .iter()
        .map(|f| match &f.escrow {
            None => SettleLeg::Kas {
                vault: f.vault.clone(),
            },
            Some((utxo, amount)) => SettleLeg::Kcc20 {
                authorizer: f.vault.clone(),
                escrow: TokenEscrow {
                    utxo: utxo.clone(),
                    amount: *amount,
                    template: tmpl,
                },
            },
        })
        .collect()
}

pub(crate) fn refund_escrow<'a>(f: &Funded, tmpl: &'a Kcc20Template) -> Option<RefundEscrow<'a>> {
    f.escrow.as_ref().map(|(utxo, amount)| RefundEscrow {
        utxo: utxo.clone(),
        amount: *amount,
        is_minter: false,
        template: tmpl,
    })
}
