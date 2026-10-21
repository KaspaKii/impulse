// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Test fixtures for the builders: KCC-20 templates (the pinned kcc20.sil compiled by
//! silverscript v1.0.0, frozen in testdata/ under kcc20.sil's ISC licence, testdata/LICENSE, and
//! checked against the compiler by the engine tests), terms per mode, funded vault UTXOs and fee
//! payments.
//!
//! Keys: none. The parties are label-derived x-only public keys, for which nobody holds a
//! private key (rule 1, docs/ENGINEERING-RULES.md). Tests that need a signature run in the engine target
//! (tests/engine/builders.rs), under the owner's exception for engine tests.

use super::*;
use crate::template::{LegIndex, Vault};
use crate::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, ValidatedTerms,
};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry};
use kaspa_consensus_core::Hash;

pub(crate) const ASSET_ARTIFACT: &str = include_str!("testdata/kcc20-asset.json");
pub(crate) const CASH_ARTIFACT: &str = include_str!("testdata/kcc20-cash.json");

/// Covenant IDs of the fixture tokens (the engine harness uses the same).
pub(crate) const ASSET_COV: [u8; 32] = [0xA5; 32];
pub(crate) const CASH_COV: [u8; 32] = [0xCA; 32];

pub(crate) const AMOUNT_A: u64 = 1_000;
pub(crate) const KAS_CASH: u64 = 100_000_000;
pub(crate) const KCC20_CASH: u64 = 250_000;
pub(crate) const EXTERNAL_CASH: u64 = 5_000;
pub(crate) const EARLIEST: u64 = 1_000_000;
pub(crate) const EXPIRY: u64 = 2_000_000;
/// The DAA score the builders are called at: between earliest and expiry.
pub(crate) const NOW: u64 = 1_500_000;
/// KAS on vault UTXOs, at the derived minimums.
pub(crate) const AUTHORIZER: u64 = MIN_KAS_OUTPUT;
pub(crate) const CARRIER: u64 = MIN_KCC20_OUTPUT;
/// The fee payer's input and the fee.
pub(crate) const FEE_INPUT: u64 = 1_000_000_000;
pub(crate) const FEE: u64 = 5_000_000;

pub(crate) fn asset_template() -> Kcc20Template {
    Kcc20Template::from_json(ASSET_ARTIFACT).expect("fixture artifact")
}

pub(crate) fn cash_template() -> Kcc20Template {
    Kcc20Template::from_json(CASH_ARTIFACT).expect("fixture artifact")
}

pub(crate) fn token(template: &Kcc20Template, cov: [u8; 32]) -> Kcc20Token {
    Kcc20Token {
        covenant_id: cov,
        template_hash: template.template_hash(),
        template_prefix_len: template.prefix_len() as u32,
        template_suffix_len: template.suffix_len() as u32,
    }
}

/// The public keys of a trade's roles and of the fee payer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Parties {
    pub seller: [u8; 32],
    pub buyer: [u8; 32],
    pub authority: [u8; 32],
    pub payer: [u8; 32],
}

/// The unit tests' parties: label-derived x-only keys, for which nobody holds a private key.
pub(crate) fn parties() -> Parties {
    use crate::terms::golden::xonly;
    Parties {
        seller: xonly("impulse/tests/key/seller"),
        buyer: xonly("impulse/tests/key/buyer"),
        authority: xonly("impulse/tests/key/authority"),
        payer: xonly("impulse/tests/key/payer"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cash {
    Kas,
    Kcc20,
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mode {
    pub settlement: SettlementMode,
    pub authority: bool,
    pub cash: Cash,
    pub funding: FundingMode,
}

impl Mode {
    pub(crate) const fn vault(authority: bool, cash: Cash, funding: FundingMode) -> Self {
        Self {
            settlement: SettlementMode::Vault,
            authority,
            cash,
            funding,
        }
    }

    pub(crate) const fn direct(cash: Cash) -> Self {
        Self {
            settlement: SettlementMode::Direct,
            authority: false,
            cash,
            funding: FundingMode::Revocable,
        }
    }

    /// Every vault mode whose terms exist (self-settling external cash has none), then both
    /// Direct modes.
    pub(crate) fn all() -> Vec<Mode> {
        let mut modes = vec![];
        for authority in [true, false] {
            for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
                for funding in [FundingMode::Revocable, FundingMode::Earmarked] {
                    if cash == Cash::External && !authority {
                        continue;
                    }
                    modes.push(Mode::vault(authority, cash, funding));
                }
            }
        }
        modes.push(Mode::direct(Cash::Kas));
        modes.push(Mode::direct(Cash::Kcc20));
        modes
    }

    pub(crate) fn vaults() -> Vec<Mode> {
        Self::all()
            .into_iter()
            .filter(|m| m.settlement == SettlementMode::Vault)
            .collect()
    }
}

pub(crate) fn p2pk_dest(key: &[u8; 32]) -> Destination {
    Destination::Kas(p2pk(key))
}

pub(crate) fn owner(key: &[u8; 32]) -> Destination {
    Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: *key,
    })
}

pub(crate) fn terms(mode: Mode, p: &Parties) -> Terms {
    let (cash_kind, amount_b, proceeds, buyer_refund) = match mode.cash {
        Cash::Kas => (
            LegKind::Kas,
            KAS_CASH,
            p2pk_dest(&p.seller),
            p2pk_dest(&p.buyer),
        ),
        Cash::Kcc20 => (
            LegKind::Kcc20(token(&cash_template(), CASH_COV)),
            KCC20_CASH,
            owner(&p.seller),
            owner(&p.buyer),
        ),
        Cash::External => (
            LegKind::External,
            EXTERNAL_CASH,
            Destination::OffChain,
            Destination::OffChain,
        ),
    };
    Terms {
        version: 1,
        network: Network::Mainnet,
        settlement_mode: mode.settlement,
        nonce: 0x4E4E_4E4E,
        seller_key: p.seller,
        buyer_key: p.buyer,
        authority_key: mode.authority.then_some(p.authority),
        asset_leg: Leg {
            kind: LegKind::Kcc20(token(&asset_template(), ASSET_COV)),
            amount: AMOUNT_A,
        },
        cash_leg: Leg {
            kind: cash_kind,
            amount: amount_b,
        },
        buyer_delivery: owner(&p.buyer),
        seller_proceeds: proceeds,
        seller_refund: owner(&p.seller),
        buyer_refund,
        earliest_daa: Some(EARLIEST),
        expiry_daa: EXPIRY,
        funding_mode: mode.funding,
        trade_ref: [0x7E; 32],
    }
}

pub(crate) fn validated(mode: Mode, p: &Parties) -> ValidatedTerms {
    terms(mode, p)
        .validate_structure()
        .expect("fixture terms pass the structure checks")
}

pub(crate) fn outpoint(label: &str) -> TransactionOutpoint {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(label.as_bytes());
    let mut id = [0u8; 32];
    id.copy_from_slice(digest.as_bytes());
    TransactionOutpoint::new(Hash::from_bytes(id), 0)
}

pub(crate) fn utxo(label: &str, amount: u64, spk: ScriptPublicKey, cov: Option<[u8; 32]>) -> Utxo {
    Utxo {
        outpoint: outpoint(label),
        entry: UtxoEntry::new(amount, spk, 100, false, cov.map(Hash::from_bytes)),
    }
}

/// One P2PK input of the payer, the standard fee, change back to the payer.
pub(crate) fn fee_payment(p: &Parties) -> FeePayment {
    FeePayment {
        inputs: vec![utxo("fee", FEE_INPUT, p2pk(&p.payer), None)],
        fee: FEE,
        change: p2pk(&p.payer),
    }
}

pub(crate) fn vault(terms: &ValidatedTerms, leg: LegIndex) -> Vault {
    Vault::instantiate_existing(terms, leg).expect("the leg has a vault")
}

pub(crate) fn escrow_state(vault: &Vault, amount: u64) -> Kcc20State {
    Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: vault.script_hash(),
        },
        amount,
    )
}

/// The funded vault UTXOs of a vault trade, as Impulse's fund builders make them.
#[derive(Clone)]
pub(crate) struct Funded {
    pub asset_authorizer: Utxo,
    pub asset_escrow: Utxo,
    pub cash_vault: Option<Utxo>,
    pub cash_authorizer: Option<Utxo>,
    pub cash_escrow: Option<Utxo>,
}

pub(crate) fn funded(terms: &ValidatedTerms) -> Funded {
    let t = terms.terms();
    let asset = vault(terms, LegIndex::Asset);
    let asset_escrow_spk = asset_template()
        .script_public_key(&escrow_state(&asset, t.asset_leg.amount))
        .unwrap();
    let mut f = Funded {
        asset_authorizer: utxo(
            "asset-authorizer",
            AUTHORIZER,
            asset.script_public_key(),
            None,
        ),
        asset_escrow: utxo("asset-escrow", CARRIER, asset_escrow_spk, Some(ASSET_COV)),
        cash_vault: None,
        cash_authorizer: None,
        cash_escrow: None,
    };
    match t.cash_leg.kind {
        LegKind::Kas => {
            let cash = vault(terms, LegIndex::Cash);
            f.cash_vault = Some(utxo(
                "cash-vault",
                t.cash_leg.amount,
                cash.script_public_key(),
                None,
            ));
        }
        LegKind::Kcc20(_) => {
            let cash = vault(terms, LegIndex::Cash);
            let spk = cash_template()
                .script_public_key(&escrow_state(&cash, t.cash_leg.amount))
                .unwrap();
            f.cash_authorizer = Some(utxo(
                "cash-authorizer",
                AUTHORIZER,
                cash.script_public_key(),
                None,
            ));
            f.cash_escrow = Some(utxo("cash-escrow", CARRIER, spk, Some(CASH_COV)));
        }
        LegKind::External => {}
    }
    f
}

/// The settle legs of a funded trade.
pub(crate) fn settle_legs<'a>(
    f: &Funded,
    asset: &'a Kcc20Template,
    cash: &'a Kcc20Template,
) -> SettleLegs<'a> {
    SettleLegs {
        asset_authorizer: f.asset_authorizer.clone(),
        asset_escrow: f.asset_escrow.clone(),
        asset_token: asset,
        cash: match (&f.cash_vault, &f.cash_authorizer, &f.cash_escrow) {
            (Some(v), _, _) => SettleCash::Kas { vault: v.clone() },
            (_, Some(a), Some(e)) => SettleCash::Kcc20 {
                authorizer: a.clone(),
                escrow: e.clone(),
                token: cash,
            },
            _ => SettleCash::External,
        },
    }
}

/// A party's own token UTXO, owned by `key`, carrying `CARRIER` KAS.
pub(crate) fn own_token(
    label: &str,
    template: &Kcc20Template,
    cov: [u8; 32],
    key: &[u8; 32],
    amount: u64,
) -> TokenUtxo {
    let state = Kcc20State::new(
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: *key,
        },
        amount,
    );
    TokenUtxo {
        utxo: utxo(
            label,
            CARRIER,
            template.script_public_key(&state).unwrap(),
            Some(cov),
        ),
        state,
    }
}

/// The parties' Direct legs, each holding exactly its leg amount.
pub(crate) fn direct_legs<'a>(
    terms: &ValidatedTerms,
    p: &Parties,
    asset: &'a Kcc20Template,
    cash: &'a Kcc20Template,
) -> DirectLegs<'a> {
    let t = terms.terms();
    DirectLegs {
        asset: own_token(
            "seller-asset",
            asset,
            ASSET_COV,
            &p.seller,
            t.asset_leg.amount,
        ),
        asset_token: asset,
        cash: match t.cash_leg.kind {
            LegKind::Kas => {
                DirectCash::Kas(utxo("buyer-kas", t.cash_leg.amount, p2pk(&p.buyer), None))
            }
            _ => DirectCash::Kcc20 {
                token: own_token("buyer-cash", cash, CASH_COV, &p.buyer, t.cash_leg.amount),
                template: cash,
            },
        },
    }
}
