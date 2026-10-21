// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! A funded authority-settlement trade (KCC-20 asset; KAS, KCC-20 or external cash) and its
//! unsigned settle IPST, or the unsigned refund of its asset leg by the authority, built with
//! impulse-core's own builders and the pinned KCC-20 fixtures, for the `impulse frost` tests. Public APIs only: the CLI's unit tests include this file, and so does the end-to-end
//! test. Party keys are label-derived x-coordinates, for which nobody holds a private key; the
//! authority key and the fee payer's key are the caller's.

#![allow(dead_code)]

use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, ValidatedTerms,
};
use impulse_core::tx::{
    refund, settle, FeePayment, Ipst, Kcc20State, Kcc20Template, RefundEscrow, RefundSigner,
    SettleCash, SettleLegs, Utxo, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry};
use kaspa_consensus_core::Hash;
use std::path::PathBuf;

pub const ASSET_COV: [u8; 32] = [0xA5; 32];
pub const CASH_COV: [u8; 32] = [0xCA; 32];
pub const AMOUNT_A: u64 = 1_000;
/// 1 KAS: under the CLI's default value cap of 10 KAS.
pub const KAS_CASH: u64 = 100_000_000;
/// Token units of a KCC-20 cash leg.
pub const KCC20_CASH: u64 = 250_000;
/// The amount of an external cash leg, settled off chain.
pub const EXTERNAL_CASH: u64 = 5_000;
pub const EARLIEST: u64 = 1_000_000;
pub const EXPIRY: u64 = 2_000_000;
/// The DAA score the settle is built and signed at.
pub const NOW: u64 = 1_500_000;
/// DAA score of the blocks that created the vault and fee UTXOs.
pub const FUNDED_DAA: u64 = 900_000;
pub const FEE_INPUT: u64 = 1_000_000_000;
pub const FEE: u64 = 5_000_000;

/// The asset leg's KCC-20 artifact: the pinned kcc20.sil compiled by silverscript v1.0.0
/// (checked by tests/engine `kcc20_fixtures_are_the_pinned_compile`).
pub fn asset_template_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../impulse-core/src/tx/testdata/kcc20-asset.json")
}

pub fn asset_template() -> Kcc20Template {
    let text = std::fs::read_to_string(asset_template_path()).expect("fixture artifact");
    Kcc20Template::from_json(&text).expect("KCC-20 template")
}

/// The cash leg's KCC-20 artifact, for KCC-20 cash.
pub fn cash_template_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../impulse-core/src/tx/testdata/kcc20-cash.json")
}

pub fn cash_template() -> Kcc20Template {
    let text = std::fs::read_to_string(cash_template_path()).expect("fixture artifact");
    Kcc20Template::from_json(&text).expect("KCC-20 template")
}

/// The cash leg's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cash {
    Kas,
    Kcc20,
    External,
}

/// An x-only key nobody holds the secret of: the first valid x-coordinate hashed from `label`.
pub fn label_key(label: &str) -> [u8; 32] {
    for counter in 0u32.. {
        let digest = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(label.as_bytes())
            .update(&counter.to_be_bytes())
            .finalize();
        let mut x = [0u8; 32];
        x.copy_from_slice(digest.as_bytes());
        if secp256k1::XOnlyPublicKey::from_slice(&x).is_ok() {
            return x;
        }
    }
    unreachable!()
}

pub fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend_from_slice(key);
    s.push(0xac);
    ScriptPublicKey::from_vec(0, s)
}

fn owner(key: &[u8; 32]) -> Destination {
    Destination::Kcc20(Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: *key,
    })
}

fn outpoint(label: &str) -> TransactionOutpoint {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(label.as_bytes());
    let mut id = [0u8; 32];
    id.copy_from_slice(digest.as_bytes());
    TransactionOutpoint::new(Hash::from_bytes(id), 0)
}

fn utxo(label: &str, amount: u64, spk: ScriptPublicKey, cov: Option<[u8; 32]>) -> Utxo {
    Utxo {
        outpoint: outpoint(label),
        entry: UtxoEntry::new(amount, spk, FUNDED_DAA, false, cov.map(Hash::from_bytes)),
    }
}

/// Authority-settlement terms with a KCC-20 asset leg and a KAS cash leg.
pub fn terms(
    authority: Option<[u8; 32]>,
    network: Network,
    asset: &Kcc20Template,
) -> ValidatedTerms {
    terms_with(Cash::Kas, authority, network, asset)
}

/// Authority-settlement terms with a KCC-20 asset leg and a cash leg of kind `cash`.
pub fn terms_with(
    cash: Cash,
    authority: Option<[u8; 32]>,
    network: Network,
    asset: &Kcc20Template,
) -> ValidatedTerms {
    let (seller, buyer) = (label_key("frost/seller"), label_key("frost/buyer"));
    let (cash_leg, seller_proceeds, buyer_refund) = match cash {
        Cash::Kas => (
            Leg {
                kind: LegKind::Kas,
                amount: KAS_CASH,
            },
            Destination::Kas(p2pk(&seller)),
            Destination::Kas(p2pk(&buyer)),
        ),
        Cash::Kcc20 => {
            let token = cash_template();
            (
                Leg {
                    kind: LegKind::Kcc20(Kcc20Token {
                        covenant_id: CASH_COV,
                        template_hash: token.template_hash(),
                        template_prefix_len: token.prefix_len() as u32,
                        template_suffix_len: token.suffix_len() as u32,
                    }),
                    amount: KCC20_CASH,
                },
                owner(&seller),
                owner(&buyer),
            )
        }
        Cash::External => (
            Leg {
                kind: LegKind::External,
                amount: EXTERNAL_CASH,
            },
            Destination::OffChain,
            Destination::OffChain,
        ),
    };
    Terms {
        version: 1,
        network,
        settlement_mode: SettlementMode::Vault,
        nonce: 0x1313,
        seller_key: seller,
        buyer_key: buyer,
        authority_key: authority,
        asset_leg: Leg {
            kind: LegKind::Kcc20(Kcc20Token {
                covenant_id: ASSET_COV,
                template_hash: asset.template_hash(),
                template_prefix_len: asset.prefix_len() as u32,
                template_suffix_len: asset.suffix_len() as u32,
            }),
            amount: AMOUNT_A,
        },
        cash_leg,
        buyer_delivery: owner(&buyer),
        seller_proceeds,
        seller_refund: owner(&seller),
        buyer_refund,
        earliest_daa: Some(EARLIEST),
        expiry_daa: EXPIRY,
        funding_mode: FundingMode::Revocable,
        trade_ref: [0x13; 32],
    }
    .validate_structure()
    .expect("fixture terms pass the structure checks")
}

/// The unsigned settle of a funded trade whose authority is `authority`, with the fee paid from
/// one P2PK input of `payer`. The vault UTXOs are those the fund builders make.
pub fn settle_ipst(authority: Option<[u8; 32]>, network: Network, payer: &[u8; 32]) -> Ipst {
    settle_ipst_with(Cash::Kas, authority, network, payer)
}

/// The funded vault UTXOs: the asset authorizer and escrow, then the cash leg's.
struct Funded {
    asset_authorizer: Utxo,
    asset_escrow: Utxo,
    cash_vault: Option<Utxo>,
    cash_authorizer: Option<Utxo>,
    cash_escrow: Option<Utxo>,
}

fn escrow_owner(vault: &Vault) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::ScriptHash,
        identifier: vault.script_hash(),
    }
}

fn funded(terms: &ValidatedTerms, asset: &Kcc20Template, cash: Cash) -> Funded {
    let asset_vault = Vault::instantiate_existing(terms, LegIndex::Asset).expect("asset vault");
    let escrow_state = Kcc20State::new(escrow_owner(&asset_vault), AMOUNT_A);
    let mut f = Funded {
        asset_authorizer: utxo(
            "frost/asset-authorizer",
            MIN_KAS_OUTPUT,
            asset_vault.script_public_key(),
            None,
        ),
        asset_escrow: utxo(
            "frost/asset-escrow",
            MIN_KCC20_OUTPUT,
            asset
                .script_public_key(&escrow_state)
                .expect("escrow script"),
            Some(ASSET_COV),
        ),
        cash_vault: None,
        cash_authorizer: None,
        cash_escrow: None,
    };
    match cash {
        Cash::Kas => {
            let v = Vault::instantiate_existing(terms, LegIndex::Cash).expect("cash vault");
            f.cash_vault = Some(utxo(
                "frost/cash-vault",
                KAS_CASH,
                v.script_public_key(),
                None,
            ));
        }
        Cash::Kcc20 => {
            let v = Vault::instantiate_existing(terms, LegIndex::Cash).expect("cash vault");
            let state = Kcc20State::new(escrow_owner(&v), KCC20_CASH);
            f.cash_authorizer = Some(utxo(
                "frost/cash-authorizer",
                MIN_KAS_OUTPUT,
                v.script_public_key(),
                None,
            ));
            f.cash_escrow = Some(utxo(
                "frost/cash-escrow",
                MIN_KCC20_OUTPUT,
                cash_template()
                    .script_public_key(&state)
                    .expect("cash escrow script"),
                Some(CASH_COV),
            ));
        }
        Cash::External => {}
    }
    f
}

fn fee_payment(payer: &[u8; 32]) -> FeePayment {
    FeePayment {
        inputs: vec![utxo("frost/fee", FEE_INPUT, p2pk(payer), None)],
        fee: FEE,
        change: p2pk(payer),
    }
}

/// The unsigned settle of a funded trade with a cash leg of kind `cash`, whose authority is
/// `authority`, with the fee paid from one P2PK input of `payer`.
pub fn settle_ipst_with(
    cash: Cash,
    authority: Option<[u8; 32]>,
    network: Network,
    payer: &[u8; 32],
) -> Ipst {
    let asset = asset_template();
    let cash_token = cash_template();
    let terms = terms_with(cash, authority, network, &asset);
    let f = funded(&terms, &asset, cash);
    let legs = SettleLegs {
        asset_authorizer: f.asset_authorizer,
        asset_escrow: f.asset_escrow,
        asset_token: &asset,
        cash: match cash {
            Cash::Kas => SettleCash::Kas {
                vault: f.cash_vault.expect("KAS cash vault"),
            },
            Cash::Kcc20 => SettleCash::Kcc20 {
                authorizer: f.cash_authorizer.expect("cash authorizer"),
                escrow: f.cash_escrow.expect("cash escrow"),
                token: &cash_token,
            },
            Cash::External => SettleCash::External,
        },
    };
    settle(&terms, &legs, &fee_payment(payer), NOW).expect("settle builds")
}

/// The unsigned refund of the asset leg, with its escrowed token, by the authority of a funded
/// trade with KAS cash, with the fee paid from one P2PK input of `payer`.
pub fn authority_refund_ipst(authority: [u8; 32], network: Network, payer: &[u8; 32]) -> Ipst {
    let asset = asset_template();
    let terms = terms_with(Cash::Kas, Some(authority), network, &asset);
    let f = funded(&terms, &asset, Cash::Kas);
    let escrow = RefundEscrow {
        utxo: f.asset_escrow,
        amount: AMOUNT_A,
        is_minter: false,
        template: &asset,
    };
    refund(
        &terms,
        LegIndex::Asset,
        RefundSigner::Authority,
        &f.asset_authorizer,
        Some(&escrow),
        &fee_payment(payer),
    )
    .expect("refund builds")
}
