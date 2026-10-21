// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I4 engine proof. A vault impulse-core instantiates from real terms (`impulse_core::terms`
//! values that pass the structure and creation checks) is byte for byte the vault the I3 engine
//! tests compile with silverscript and run, and the real engine accepts settle and refund spends
//! of it in every mode. The harness is reused unchanged; only the vault bytes come from
//! impulse-core. impulse-core also decodes the silverscript-compiled vault back to the terms.

mod harness;
mod real_terms;
use harness::*;
use impulse_core::template::{LegIndex, Vault};
use real_terms::*;

const AUTHORITY: [bool; 2] = [true, false];
const CASH: [u8; 3] = [CASH_KAS, CASH_KCC20, CASH_EXTERNAL];
const FUNDING: [u8; 2] = [REVOCABLE, EARMARKED];

#[test]
fn core_vaults_settle_in_the_engine_in_every_mode() {
    for authority in AUTHORITY {
        for cash in CASH {
            for funding in FUNDING {
                let mode = Mode::new(authority, cash, funding);
                if !authority && cash == CASH_EXTERNAL {
                    continue; // never settles ([S7]); real terms refuse it, see below
                }
                let w = core_world(mode);
                settle(&w).assert_all_accepted(&w, &format!("settle {mode:?}"));
            }
        }
    }
}

#[test]
fn core_vaults_refund_in_the_engine_for_every_signer() {
    for authority in AUTHORITY {
        for cash in CASH {
            for funding in FUNDING {
                let mode = Mode::new(authority, cash, funding);
                if !authority && cash == CASH_EXTERNAL {
                    continue;
                }
                let w = core_world(mode);
                let legs: &[i64] = if w.external() {
                    &[ASSET_LEG]
                } else {
                    &[ASSET_LEG, CASH_LEG]
                };
                for &leg in legs {
                    let mut signers = vec![Role::Seller, Role::Buyer];
                    if authority {
                        signers.push(Role::Authority);
                    }
                    for signer in signers {
                        w.refund(leg, signer).assert_all_accepted(
                            &w,
                            &format!("refund leg {leg} by {signer:?}, {mode:?}"),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn self_settling_external_cash_has_no_real_terms() {
    // The one harness mode that never settles ([S7]) cannot become real terms, so impulse-core
    // never instantiates a vault for it.
    let w = world(Mode::new(false, CASH_EXTERNAL, REVOCABLE));
    let refused = core_terms(&w.terms).validate_structure().unwrap_err();
    assert_eq!(refused.code(), "TERMS_EXTERNAL_WITHOUT_AUTHORITY");
}

#[test]
fn the_engine_judges_the_core_terms() {
    // Controls: the canonical settle with core vaults is accepted. Faults: the asset vault
    // instantiated from terms one unit off, or at the other leg index, is refused at input 0.
    let mode = Mode::new(true, CASH_KCC20, EARMARKED);
    let w = core_world(mode);
    let control = settle(&w);
    control.assert_all_accepted(&w, "control");
    let (terms, _) = real_terms(&w);

    let mut off = terms.terms().clone();
    off.asset_leg.amount += 1;
    let off = off.validate_structure().unwrap();
    let off_vault = Vault::instantiate_existing(&off, LegIndex::Asset).unwrap();
    let wrong_leg = Vault::instantiate_existing(&terms, LegIndex::Cash).unwrap();
    for (label, vault) in [("amount_a + 1", off_vault), ("cash leg index", wrong_leg)] {
        // The same parties and terms; only the asset vault's bytes differ. The escrow is owned
        // by that vault's script hash, so the vault's own terms are all the engine can object to.
        let mut faulty = w.sibling(|_| {});
        settle(&faulty).assert_all_accepted(&faulty, &format!("{label}: control"));
        let compiled = faulty.asset_vault.clone();
        faulty.asset_vault = from_core(&compiled, vault.redeem_script());
        assert_refused(&settle(&faulty).run(&faulty, 0), label);
    }
}

// The cash-leg script of external-cash terms. impulse-core never makes it (TEMPLATE_NO_VAULT),
// but anyone can compile it from the terms and fund its address. These tests pin, without
// changing, what the contract then does (spec/TEMPLATE.md, "The cash-vault script of
// external-cash terms").

/// An external-cash world with the cash-leg script compiled from its terms.
fn external_with_cash_script(funding: u8) -> World {
    let mut w = world(Mode::new(true, CASH_EXTERNAL, funding));
    w.cash_vault = Some(w.terms.vault(CASH_LEG));
    w
}

#[test]
fn external_cash_vault_refunds_only_by_the_buyer() {
    for funding in FUNDING {
        let w = external_with_cash_script(funding);
        let control = w.refund(CASH_LEG, Role::Buyer);
        for signer in [Role::Seller, Role::Authority] {
            assert_flips(
                &w,
                &control,
                &w.refund(CASH_LEG, signer),
                0,
                &format!("{signer:?} refund of the external-cash cash vault, funding {funding}"),
            );
        }
    }
}

#[test]
fn external_cash_vault_refunds_whole_as_kas_to_the_buyer_p2pk() {
    for funding in FUNDING {
        let w = external_with_cash_script(funding);
        let control = w.refund(CASH_LEG, Role::Buyer);
        assert_eq!(control.outputs[0].spk, p2pk(w.xonly(Role::Buyer)));
        let mut elsewhere = control.clone();
        elsewhere.outputs[0].spk = stranger_spk();
        let mut short = control.clone();
        short.outputs[0].value -= 1;
        for (label, faulty) in [("paid elsewhere", elsewhere), ("paid short", short)] {
            assert_flips(
                &w,
                &control,
                &faulty,
                0,
                &format!("buyer refund {label}, funding {funding}"),
            );
        }
    }
}
