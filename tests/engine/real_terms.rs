// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Real impulse-core terms for the harness worlds, shared by the targets that check impulse-core
//! against the engine (instantiate, verify). Moved out of instantiate.rs in I6, unchanged.

#![allow(dead_code)] // each test target uses a different part

use crate::harness::*;
use impulse_core::template::{decode, LegIndex, Vault};
use impulse_core::terms::{
    self as core, CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner,
    Kcc20Token, Leg, LegKind, Network, SettlementMode, ValidatedTerms,
};
use kaspa_consensus_core::tx::ScriptPublicKey;

/// Creation DAA score for the real terms: below the harness's earliest (1,000,000) and expiry
/// (2,000,000) scores.
pub const CREATION_DAA: u64 = 500_000;

/// The harness world for `mode`, with the two fixture identifiers real terms refuse replaced.
/// [0xB1; 32] (the buyer's PUBKEY delivery owner) and [0x53; 32] (inside the KAS proceeds P2PK)
/// are not x-only keys, which the structure checks refuse (`TERMS_INVALID_KEY`). The asset goes
/// to a SCRIPT_HASH owner instead and KAS cash to the seller's own P2PK.
pub fn world(mode: Mode) -> World {
    World::with(mode, |t, w| {
        t.buyer_delivery = Owner::script_hash([0xB1; 32]);
        if mode.cash == CASH_KAS {
            t.seller_proceeds_spk = spk_bytes(&p2pk(w.xonly(Role::Seller)));
        }
    })
}

/// The harness's canonical settle, paying KAS cash to the proceeds scriptPubKey of `world`.
pub fn settle(w: &World) -> TxSpec {
    let mut spec = w.settle();
    if w.mode.cash == CASH_KAS {
        spec.outputs[1].spk = p2pk(w.xonly(Role::Seller));
    }
    spec
}

pub fn owner(o: Owner) -> Destination {
    let identifier_type = match o.id_type {
        IDENTIFIER_PUBKEY => IdentifierType::PubKey,
        IDENTIFIER_SCRIPT_HASH => IdentifierType::ScriptHash,
        IDENTIFIER_COVENANT_ID => IdentifierType::CovenantId,
        other => panic!("identifier type {other}"),
    };
    Destination::Kcc20(Kcc20Owner {
        identifier_type,
        identifier: o.id,
    })
}

pub fn token(t: TemplateRef) -> Kcc20Token {
    Kcc20Token {
        covenant_id: t.cov.as_bytes(),
        template_hash: t.hash,
        template_prefix_len: t.prefix_len.try_into().expect("u32"),
        template_suffix_len: t.suffix_len.try_into().expect("u32"),
    }
}

pub fn kas(spk: &[u8]) -> Destination {
    let version = u16::from_be_bytes([spk[0], spk[1]]);
    Destination::Kas(ScriptPublicKey::from_vec(version, spk[2..].to_vec()))
}

/// The harness terms as impulse-core terms: same parties, tokens, amounts, destinations and
/// lock times. A reading of the fixture, not of the contract state.
pub fn core_terms(t: &Terms) -> core::Terms {
    let cash_dest = |o: Owner, spk: &[u8]| match t.cash_kind {
        CASH_KAS => kas(spk),
        CASH_KCC20 => owner(o),
        _ => Destination::OffChain,
    };
    core::Terms {
        version: t.version,
        network: match t.network {
            0 => Network::Mainnet,
            _ => Network::Testnet,
        },
        settlement_mode: SettlementMode::Vault,
        nonce: u64::from_le_bytes(t.nonce),
        seller_key: t.seller_key,
        buyer_key: t.buyer_key,
        authority_key: t.has_authority.then_some(t.authority_key),
        asset_leg: Leg {
            kind: LegKind::Kcc20(token(t.asset)),
            amount: t.amount_a as u64,
        },
        cash_leg: Leg {
            kind: match t.cash_kind {
                CASH_KAS => LegKind::Kas,
                CASH_KCC20 => LegKind::Kcc20(token(t.cash)),
                _ => LegKind::External,
            },
            amount: t.amount_b as u64,
        },
        buyer_delivery: owner(t.buyer_delivery),
        seller_proceeds: cash_dest(t.seller_proceeds, &t.seller_proceeds_spk),
        seller_refund: owner(t.seller_refund),
        buyer_refund: cash_dest(t.buyer_refund, &t.buyer_refund_spk),
        earliest_daa: t.has_earliest.then_some(t.earliest_daa as u64),
        expiry_daa: t.expiry_daa as u64,
        funding_mode: if t.funding_mode == REVOCABLE {
            FundingMode::Revocable
        } else {
            FundingMode::Earmarked
        },
        trade_ref: t.trade_ref,
    }
}

/// `reference` with its bytecode replaced by `script`. The ABI (entries, dispatch tags) belongs
/// to the template and does not depend on the state.
pub fn from_core(reference: &Compiled, script: &[u8]) -> Compiled {
    let mut c = reference.clone();
    let name = c.name.clone();
    c.artifact
        .contracts
        .get_mut(&name)
        .expect("contract")
        .compiled
        .bytecode = script.to_vec();
    c
}

/// Real terms for `w`, checked as a creator checks them.
pub fn real_terms(w: &World) -> (ValidatedTerms, CreationContext) {
    let terms = core_terms(&w.terms)
        .validate_structure()
        .expect("real terms pass the structure checks");
    let ctx = CreationContext::new(terms.terms().network, CREATION_DAA);
    terms
        .validate_creation(&ctx)
        .expect("real terms pass the creation checks");
    (terms, ctx)
}

/// `w` with every vault replaced by impulse-core's instantiation of the real terms, after
/// checking that the two agree byte for byte and that impulse-core decodes the compiled vaults.
pub fn core_world(mode: Mode) -> World {
    let mut w = world(mode);
    let (terms, ctx) = real_terms(&w);
    for (leg, index) in [(LegIndex::Asset, ASSET_LEG), (LegIndex::Cash, CASH_LEG)] {
        assert_eq!(LegIndex::from_index(index), Ok(leg));
        let compiled = w.terms.vault(index);
        let decoded = decode(compiled.bytecode());
        let vault = match Vault::instantiate_for_creation(&terms, leg, &ctx) {
            Ok(fundable) => fundable.into_vault(),
            Err(e) => {
                // External cash has no cash vault: impulse-core neither makes nor accepts one.
                assert!(
                    w.external() && leg == LegIndex::Cash,
                    "{mode:?} {leg:?}: {e}"
                );
                assert_eq!(e.code(), "TEMPLATE_NO_VAULT");
                assert_eq!(decoded.unwrap_err().code(), "TEMPLATE_NO_VAULT");
                continue;
            }
        };
        assert_eq!(
            decoded.expect("impulse-core decodes the compiled vault"),
            (terms.clone(), leg),
            "{mode:?} {leg:?}: decoded terms"
        );
        assert_eq!(
            vault.redeem_script(),
            compiled.bytecode(),
            "{mode:?} {leg:?}: impulse-core and the compiler disagree"
        );
        assert_eq!(vault.script_public_key(), compiled.p2sh());
        assert_eq!(vault.script_hash(), compiled.script_hash());
        let swapped = from_core(&compiled, vault.redeem_script());
        match leg {
            LegIndex::Asset => w.asset_vault = swapped,
            LegIndex::Cash => w.cash_vault = Some(swapped),
        }
    }
    w
}
