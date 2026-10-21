// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The statement of spec/V3-ZK.md 22.4, one `guest_refuses_<tag>` per tag: each test changes the
//! view (or the terms) so that exactly that tag fails, and expects `ZK_H_STATEMENT_FALSE` naming
//! it. Every refusal has an accepted twin (the unchanged scenario). Worlds are in common.rs.

mod common;
use common::*;
use terms_core::codec::*;
use terms_core::hashes::*;
use terms_core::kcc20::{self, State};
use terms_core::Refusal;

const SF: &str = "ZK_H_STATEMENT_FALSE";

fn refused(sc: &Sc, tag: &str) {
    match sc.run() {
        Err(Refusal { code, tag: t }) => {
            assert_eq!((code, t), (SF, tag), "expected {SF} [{tag}]");
        }
        Ok(_) => panic!("expected a refusal at [{tag}], the statement held"),
    }
}

fn refused_code(sc: &Sc, code: &str, tag: &str) {
    match sc.run() {
        Err(r) => assert_eq!((r.code, r.tag), (code, tag)),
        Ok(_) => panic!("expected {code} [{tag}], the statement held"),
    }
}

// ---- accepted ----

#[test]
fn guest_accepts_every_settle_shape() {
    for (cash, legs) in [
        (Cash::Kas, vec![0u8, 1]),
        (Cash::Kcc20, vec![0, 1]),
        (Cash::External, vec![0]),
    ] {
        for leg in legs {
            let sc = settle(cash, leg);
            let j = sc
                .run()
                .unwrap_or_else(|e| panic!("{cash:?} leg {leg}: {e}"));
            assert_eq!(j, sc.j.to_bytes(), "the statement returns J unchanged");
        }
    }
}

#[test]
fn guest_accepts_every_refund_shape() {
    let (s, b, a) = (seller(), buyer(), authority());
    // asset leg: depositor revocable, with and without the token; counterparty; authority
    for signer in [s, b, a] {
        refund(Cash::Kas, 0, signer, false, true, 0).run().unwrap();
    }
    refund(Cash::Kas, 0, s, false, false, 0).run().unwrap();
    // earmarked: the depositor after expiry; the counterparty and the authority at any time
    refund(Cash::Kas, 0, s, true, true, EXPIRY).run().unwrap();
    refund(Cash::Kas, 0, b, true, true, 0).run().unwrap();
    refund(Cash::Kas, 0, a, true, true, 0).run().unwrap();
    // KAS cash leg, KCC-20 cash leg, external cash leg (no token possible)
    for signer in [b, s, a] {
        refund(Cash::Kas, 1, signer, false, false, 0).run().unwrap();
    }
    for signer in [b, s, a] {
        refund(Cash::Kcc20, 1, signer, false, true, 0)
            .run()
            .unwrap();
    }
    refund(Cash::Kcc20, 1, b, false, false, 0).run().unwrap();
    refund(Cash::External, 1, b, false, false, 0).run().unwrap();
}

// ---- commitment and layout: H1 to H4 ----

#[test]
fn guest_refuses_h1_commit() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.commit[0] ^= 1;
    refused(&sc, "H1");
    // the commitment of the other leg is not this leg's
    let mut sc = settle(Cash::Kas, 0);
    sc.j.commit = commit(&terms_hash(&sc.terms.encode()), 1);
    refused(&sc, "H1");
    // the leg byte must be a leg
    let mut sc = settle(Cash::Kas, 0);
    sc.j.leg = 2;
    refused(&sc, "H1");
    // changing any one term changes the commitment: a nonce one higher
    let mut sc = settle(Cash::Kas, 0);
    sc.terms.nonce += 1;
    refused(&sc, "H1");
}

#[test]
fn guest_refuses_h3_authority() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.authority = stranger();
    refused(&sc, "H3");
}

#[test]
fn guest_refuses_h4_covenant_ids_and_layout() {
    let mut sc = settle(Cash::Kcc20, 0);
    sc.j.cov_a = [0xEE; 32];
    refused(&sc, "H4");
    let mut sc = settle(Cash::Kcc20, 0);
    sc.j.cov_c = [0xEE; 32];
    refused(&sc, "H4");
    let mut sc = settle(Cash::Kas, 0);
    sc.j.cov_c = cash_cov(); // KAS cash: the cash covenant is zero
    refused(&sc, "H4");
    // ... for both legs, and for external cash: template v4's [T10] takes input 3's covenant
    // from cov_c, so no receipt may exist for a non-zero cov_c there (spec/V3-ZK.md 22.15)
    let mut sc = settle(Cash::Kas, 1);
    sc.j.cov_c = cash_cov();
    refused(&sc, "H4");
    let mut sc = settle(Cash::External, 0);
    sc.j.cov_c = cash_cov();
    refused(&sc, "H4");
    let mut sc = settle(Cash::Kas, 0);
    sc.j.signer = seller(); // a settle journal carries no signer
    refused(&sc, "H4");
    // a refund of an asset leg must name the asset covenant, and carries no cash covenant
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.cov_a = cash_cov();
    refused(&sc, "H4");
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.cov_c = cash_cov();
    refused(&sc, "H4");
}

#[test]
fn guest_refuses_wrong_layout() {
    // every cash kind has one layout: one view item too many or too few is ZK_H_SHAPE
    for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
        let mut sc = settle(cash, 0);
        let extra = sc.j.inputs[0];
        sc.j.inputs.push(extra);
        // a fifth item is outside the journal format itself (J1), else the layout (H4)
        let tag = if sc.j.inputs.len() > 4 { "J1" } else { "H4" };
        refused_code(&sc, "ZK_H_SHAPE", tag);
        let mut sc = settle(cash, 0);
        sc.j.outputs.pop();
        refused_code(&sc, "ZK_H_SHAPE", "H4");
        let mut sc = settle(cash, 0);
        sc.j.inputs.pop();
        refused_code(&sc, "ZK_H_SHAPE", "H4");
    }
    // KAS cash terms with the KCC-20 layout, and the reverse
    let mut sc = settle(Cash::Kas, 0);
    let (i, o) = (sc.j.inputs[2], sc.j.outputs[2]);
    sc.j.inputs.push(i);
    sc.j.outputs.push(o);
    refused_code(&sc, "ZK_H_SHAPE", "H4");
    // a refund is 1/1 without a token and 2/2 with one
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.inputs.pop();
    sc.j.outputs.pop();
    refused_code(&sc, "ZK_H_SHAPE", "H4");
    let mut sc = refund(Cash::Kas, 0, seller(), false, false, 0);
    let i = sc.j.inputs[0];
    sc.j.inputs.push(i);
    sc.j.outputs.push(i);
    refused_code(&sc, "ZK_H_SHAPE", "H4");
    // a KAS cash leg refund is 1/1 whatever the token count says
    let mut sc = refund(Cash::Kas, 1, buyer(), false, false, 0);
    let i = sc.j.inputs[0];
    sc.j.inputs.push(i);
    sc.j.outputs.push(i);
    refused_code(&sc, "ZK_H_SHAPE", "H4");
}

#[test]
fn guest_refuses_malformed_journal() {
    let sc = settle(Cash::Kas, 0);
    let good = sc.j.to_bytes();
    for bad in [
        good[..good.len() - 1].to_vec(),
        [good.clone(), vec![0]].concat(),
        good[..100].to_vec(),
        vec![],
    ] {
        let mut w = sc.witness();
        w.journal = bad;
        let r = terms_core::statement(&w, Default::default()).unwrap_err();
        assert_eq!((r.code, r.tag), ("ZK_H_SHAPE", "J1"));
    }
    for (at, v) in [(0usize, b'X'), (16, 0), (16, 3), (226, 5), (227, 9)] {
        let mut w = sc.witness();
        w.journal[at] = v;
        let r = terms_core::statement(&w, Default::default()).unwrap_err();
        assert_eq!((r.code, r.tag), ("ZK_H_SHAPE", "J1"), "byte {at}");
    }
}

// ---- settle tags ----

#[test]
fn guest_refuses_s1_position() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.input_index = 1; // the asset vault found at the cash position
    refused(&sc, "S1");
    let mut sc = settle(Cash::Kas, 1);
    sc.j.input_index = 0;
    refused(&sc, "S1");
}

#[test]
fn guest_refuses_s2_kas_cash_input() {
    for delta in [-1i64, 1] {
        let mut sc = settle(Cash::Kas, 1);
        sc.j.inputs[1].value = (AMOUNT_B as i64 + delta) as u64;
        refused(&sc, "S2");
    }
}

#[test]
fn guest_refuses_s3_locktime() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.locktime = EARLIEST - 1;
    refused(&sc, "S3");
    // a lock time in the timestamp domain is not a DAA score
    let mut sc = settle(Cash::Kas, 0);
    sc.j.locktime = terms_core::LOCK_TIME_THRESHOLD;
    refused(&sc, "S3");
    // above earliest is fine, and no earliest means no bound
    let mut sc = settle(Cash::Kas, 0);
    sc.j.locktime = EARLIEST + 1;
    sc.run().unwrap();
    let mut t = terms(Cash::Kas, false);
    t.earliest = None;
    let mut sc = settle_of(t, Cash::Kas, 0);
    sc.j.locktime = 0;
    sc.run().unwrap();
}

#[test]
fn guest_refuses_s4_proceeds_script() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.outputs[1].spk_hash = sha256(&p2pk_spk(&stranger()));
    refused(&sc, "S4");
}

#[test]
fn guest_refuses_s5_proceeds_amount() {
    for delta in [-1i64, 1] {
        let mut sc = settle(Cash::Kas, 0);
        sc.j.outputs[1].value = (AMOUNT_B as i64 + delta) as u64;
        refused(&sc, "S5");
    }
}

#[test]
fn guest_refuses_s8_s9_authorizer_return() {
    for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
        let slot = if cash == Cash::External { 1 } else { 2 };
        let mut sc = settle(cash, 0);
        sc.j.outputs[slot].spk_hash = sha256(&p2pk_spk(&stranger()));
        refused(&sc, "S8");
        let mut sc = settle(cash, 0);
        sc.j.outputs[slot].value = AUTH_VALUE - 1;
        refused(&sc, "S9");
        // a larger return is fine ("at least in full")
        let mut sc = settle(cash, 0);
        sc.j.outputs[slot].value = AUTH_VALUE + 1;
        sc.run().unwrap();
    }
    // the cash vault's return is the buyer's, at output 3
    let mut sc = settle(Cash::Kcc20, 1);
    sc.j.outputs[3].spk_hash = sha256(&p2pk_spk(&seller()));
    refused(&sc, "S8");
    let mut sc = settle(Cash::Kcc20, 1);
    sc.j.outputs[3].value = AUTH_VALUE - 1;
    refused(&sc, "S9");
}

#[test]
fn guest_refuses_e1_second_input_of_the_covenant() {
    for count in [0u8, 2] {
        let mut sc = settle(Cash::Kas, 0);
        sc.j.count_a = count;
        refused(&sc, "E1");
        let mut sc = settle(Cash::Kcc20, 1);
        sc.j.count_c = count;
        refused(&sc, "E1");
    }
    // external cash has no cash vault
    let mut sc = settle(Cash::External, 0);
    sc.j.leg = 1;
    sc.j.input_index = 1;
    sc.recommit();
    refused(&sc, "E1");
}

#[test]
fn guest_refuses_e2_escrow_at_the_slot() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.inputs[2].cov = [0; 32];
    refused(&sc, "E2");
    let mut sc = settle(Cash::Kcc20, 1);
    sc.j.inputs[3].cov = asset_cov();
    refused(&sc, "E2");
}

#[test]
fn guest_refuses_e3_template_and_owner_type() {
    // the escrow runs another template (a suffix byte changed)
    let mut sc = settle(Cash::Kas, 0);
    let mut r = sc.redeems[0].1.clone();
    let n = r.len();
    r[n - 1] ^= 1;
    sc.j.inputs[2].spk_hash = kcc20::input_spk_hash(&r);
    sc.redeems[0].1 = r;
    refused(&sc, "E3");
    // a pubkey owner, not a script hash
    let mut sc = settle(Cash::Kas, 0);
    let esc = State {
        owner: vault_hash(&sc.terms, 0),
        id_type: ID_PUBKEY,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    let (item, redeem) = token_item(&asset_template(), &esc, asset_cov());
    sc.j.inputs[2] = item;
    sc.redeems[0].1 = redeem;
    refused(&sc, "E3");
}

fn escrow_with(sc: &mut Sc, slot: usize, t: &Template, cov: [u8; 32], s: State) {
    let (item, redeem) = token_item(t, &s, cov);
    sc.j.inputs[slot] = item;
    sc.redeems
        .iter_mut()
        .find(|(i, _)| *i as usize == slot)
        .unwrap()
        .1 = redeem;
}

#[test]
fn guest_refuses_e4_owner() {
    let mut sc = settle(Cash::Kas, 0);
    let s = State {
        owner: vault_hash(&sc.terms, 1),
        id_type: ID_SCRIPT_HASH,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    escrow_with(&mut sc, 2, &asset_template(), asset_cov(), s);
    refused(&sc, "E4");
}

#[test]
fn guest_refuses_e5_escrow_amount() {
    for delta in [-1i64, 1] {
        let mut sc = settle(Cash::Kas, 0);
        let s = State {
            owner: vault_hash(&sc.terms, 0),
            id_type: ID_SCRIPT_HASH,
            amount: AMOUNT_A as i64 + delta,
            is_minter: false,
        };
        escrow_with(&mut sc, 2, &asset_template(), asset_cov(), s);
        refused(&sc, "E5");
        let mut sc = settle(Cash::Kcc20, 1);
        let s = State {
            owner: vault_hash(&sc.terms, 1),
            id_type: ID_SCRIPT_HASH,
            amount: AMOUNT_B as i64 + delta,
            is_minter: false,
        };
        escrow_with(&mut sc, 3, &cash_template(), cash_cov(), s);
        refused(&sc, "E5");
    }
}

#[test]
fn guest_refuses_e6_minter() {
    let mut sc = settle(Cash::Kas, 0);
    let s = State {
        owner: vault_hash(&sc.terms, 0),
        id_type: ID_SCRIPT_HASH,
        amount: AMOUNT_A as i64,
        is_minter: true,
    };
    escrow_with(&mut sc, 2, &asset_template(), asset_cov(), s);
    refused(&sc, "E6");
}

#[test]
fn guest_refuses_d1_d2_delivery_covenant_and_kas() {
    let mut sc = settle(Cash::Kas, 0);
    sc.j.outputs[0].cov = [0; 32];
    refused(&sc, "D1");
    let mut sc = settle(Cash::Kcc20, 0);
    sc.j.outputs[1].cov = asset_cov();
    refused(&sc, "D1");
    let mut sc = settle(Cash::Kas, 0);
    sc.j.outputs[0].value = TOKEN_VALUE - 1;
    refused(&sc, "D2");
    let mut sc = settle(Cash::Kcc20, 0);
    sc.j.outputs[1].value = TOKEN_VALUE - 1;
    refused(&sc, "D2");
    // more KAS than the escrow had is fine
    let mut sc = settle(Cash::Kas, 0);
    sc.j.outputs[0].value = TOKEN_VALUE + 1;
    sc.run().unwrap();
}

fn delivery_spk(sc: &Sc, t: &Template, s: State) -> [u8; 32] {
    let _ = sc;
    kcc20::output_spk_hash(&t.prefix, &t.suffix, &s)
}

#[test]
fn guest_refuses_db_delivery_state() {
    let at = asset_template();
    let base = State {
        owner: point_x(5),
        id_type: ID_PUBKEY,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    for bad in [
        State {
            amount: base.amount + 1,
            ..base
        },
        State {
            amount: base.amount - 1,
            ..base
        },
        State {
            owner: point_x(6),
            ..base
        },
        State {
            id_type: ID_SCRIPT_HASH,
            ..base
        },
        State {
            is_minter: true,
            ..base
        },
    ] {
        let mut sc = settle(Cash::Kas, 0);
        sc.j.outputs[0].spk_hash = delivery_spk(&sc, &at, bad);
        refused(&sc, "DB");
    }
    // the cash delivery
    let ct = cash_template();
    let cbase = State {
        owner: point_x(6),
        id_type: ID_PUBKEY,
        amount: AMOUNT_B as i64,
        is_minter: false,
    };
    for bad in [
        State {
            amount: cbase.amount + 1,
            ..cbase
        },
        State {
            is_minter: true,
            ..cbase
        },
    ] {
        let mut sc = settle(Cash::Kcc20, 0);
        sc.j.outputs[1].spk_hash = delivery_spk(&sc, &ct, bad);
        refused(&sc, "DB");
    }
    // a delivery to the right state under the other leg's template
    let mut sc = settle(Cash::Kcc20, 0);
    sc.j.outputs[1].spk_hash = delivery_spk(&sc, &at, cbase);
    refused(&sc, "DB");
}

// ---- refund tags ----

#[test]
fn guest_refuses_r1_signer() {
    let sc = refund(Cash::Kas, 0, stranger(), false, true, 0);
    refused(&sc, "R1");
    let sc = refund(Cash::Kas, 1, stranger(), false, false, 0);
    refused(&sc, "R1");
}

#[test]
fn guest_refuses_r3_earmarked_depositor_before_expiry() {
    let sc = refund(Cash::Kas, 0, seller(), true, true, EXPIRY - 1);
    refused(&sc, "R3");
    let sc = refund(Cash::Kas, 1, buyer(), true, false, 0);
    refused(&sc, "R3");
    let sc = refund(
        Cash::Kas,
        0,
        seller(),
        true,
        true,
        terms_core::LOCK_TIME_THRESHOLD,
    );
    refused(&sc, "R3");
    // the same refund by the counterparty has no such gate
    refund(Cash::Kas, 0, buyer(), true, true, 0).run().unwrap();
}

#[test]
fn guest_refuses_r4_vault_not_at_input_0() {
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.input_index = 1;
    refused(&sc, "R4");
}

#[test]
fn guest_refuses_r5_kas_whole() {
    for delta in [-1i64, 1] {
        let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
        sc.j.outputs[0].value = (AUTH_VALUE as i64 + delta) as u64;
        refused(&sc, "R5");
    }
}

#[test]
fn guest_refuses_r6_kas_cash_destination() {
    let mut sc = refund(Cash::Kas, 1, buyer(), false, false, 0);
    sc.j.outputs[0].spk_hash = sha256(&p2pk_spk(&stranger()));
    refused(&sc, "R6");
}

#[test]
fn guest_refuses_r7_depositor_destination() {
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.outputs[0].spk_hash = sha256(&p2pk_spk(&stranger()));
    refused(&sc, "R7");
    let mut sc = refund(Cash::Kcc20, 1, buyer(), false, true, 0);
    sc.j.outputs[0].spk_hash = sha256(&p2pk_spk(&seller()));
    refused(&sc, "R7");
}

#[test]
fn guest_refuses_r8_r9_r10_r11_r13_token_return() {
    // R11: the counterparty and the authority never separate the authorizer from the token
    for signer in [buyer(), authority()] {
        let mut sc = refund(Cash::Kas, 0, signer, false, false, 0);
        sc.j.count_a = 0;
        refused(&sc, "R11");
    }
    // R8: two tokens of the covenant in the transaction
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.count_a = 2;
    refused(&sc, "R8");
    // R9: the token of the covenant is not at input 1
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.inputs[1].cov = [0; 32];
    refused(&sc, "R9");
    // R10: the returned output is not of the covenant
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.outputs[1].cov = [0; 32];
    refused(&sc, "R10");
    // R13: the returned token output carries less KAS than the escrow
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    sc.j.outputs[1].value = TOKEN_VALUE - 1;
    refused(&sc, "R13");
}

#[test]
fn guest_refuses_r12_r14_escrow_owner_and_amount() {
    // R12: the escrow is owned by another vault
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    let s = State {
        owner: vault_hash(&sc.terms, 1),
        id_type: ID_SCRIPT_HASH,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    escrow_with(&mut sc, 1, &asset_template(), asset_cov(), s);
    refused(&sc, "R12");
    // R14: a decoy token of another amount refunded by the counterparty or the authority
    for signer in [buyer(), authority()] {
        let mut sc = refund(Cash::Kas, 0, signer, false, true, 0);
        let s = State {
            owner: vault_hash(&sc.terms, 0),
            id_type: ID_SCRIPT_HASH,
            amount: AMOUNT_A as i64 - 1,
            is_minter: false,
        };
        escrow_with(&mut sc, 1, &asset_template(), asset_cov(), s);
        refused(&sc, "R14");
    }
    // the depositor may refund a token of any amount, home whole
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    let s = State {
        owner: vault_hash(&sc.terms, 0),
        id_type: ID_SCRIPT_HASH,
        amount: 7,
        is_minter: false,
    };
    escrow_with(&mut sc, 1, &asset_template(), asset_cov(), s);
    let home = State {
        owner: point_x(7),
        id_type: ID_PUBKEY,
        amount: 7,
        is_minter: false,
    };
    sc.j.outputs[1].spk_hash =
        kcc20::output_spk_hash(&asset_template().prefix, &asset_template().suffix, &home);
    sc.run().unwrap();
}

#[test]
fn guest_refuses_rb_home_state() {
    let at = asset_template();
    let base = State {
        owner: point_x(7),
        id_type: ID_PUBKEY,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    for bad in [
        State {
            amount: base.amount + 1,
            ..base
        },
        State {
            owner: point_x(8),
            ..base
        },
        State {
            is_minter: true,
            ..base
        },
    ] {
        let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
        sc.j.outputs[1].spk_hash = kcc20::output_spk_hash(&at.prefix, &at.suffix, &bad);
        refused(&sc, "RB");
    }
    // a minter escrow goes home as a minter (v1 copies the flag)
    let mut sc = refund(Cash::Kas, 0, seller(), false, true, 0);
    let s = State {
        owner: vault_hash(&sc.terms, 0),
        id_type: ID_SCRIPT_HASH,
        amount: AMOUNT_A as i64,
        is_minter: true,
    };
    escrow_with(&mut sc, 1, &at, asset_cov(), s);
    let home = State {
        is_minter: true,
        ..base
    };
    sc.j.outputs[1].spk_hash = kcc20::output_spk_hash(&at.prefix, &at.suffix, &home);
    sc.run().unwrap();
}

// ---- the other leg's vault: H5 (spec/V3-ZK.md 22.16) ----

/// The settle views with a cash vault: (cash kind, leg).
const WITH_CASH_VAULT: [(Cash, u8); 4] = [
    (Cash::Kas, 0),
    (Cash::Kas, 1),
    (Cash::Kcc20, 0),
    (Cash::Kcc20, 1),
];

#[test]
fn guest_refuses_h5_other_vault() {
    for (cash, leg) in WITH_CASH_VAULT {
        let other = (1 - leg) as usize;
        // the control: the other leg's vault of these terms at its slot
        let sc = settle(cash, leg);
        assert_eq!(
            sc.j.inputs[other].spk_hash,
            sha256(&vault_spk(&sc.terms, 1 - leg))
        );
        sc.run().unwrap();
        // a plain input at the other vault's slot (the other vault omitted)
        let mut sc = settle(cash, leg);
        sc.j.inputs[other].spk_hash = sha256(&p2pk_spk(&stranger()));
        refused(&sc, "H5");
        // the other leg's vault of other terms (another trade: blind differs)
        let mut sc = settle(cash, leg);
        let mut t = sc.terms.clone();
        t.blind[0] ^= 1;
        sc.j.inputs[other].spk_hash = sha256(&vault_spk(&t, 1 - leg));
        refused(&sc, "H5");
        // a second UTXO of this vault at the other slot (a duplicate vault)
        let mut sc = settle(cash, leg);
        sc.j.inputs[other].spk_hash = sha256(&sc.j.vault_spk);
        refused(&sc, "H5");
        // the other leg's vault under another authority key
        let mut sc = settle(cash, leg);
        let c = commit(&terms_hash(&sc.terms.encode()), 1 - leg);
        sc.j.inputs[other].spk_hash =
            sha256(&p2sh_spk(&blake2b256(&vault_redeem_of(&c, &stranger()))));
        refused(&sc, "H5");
    }
}

/// This vault's own redeem script in the witness.
fn own(sc: &mut Sc) -> &mut Vec<u8> {
    let i = sc.j.input_index;
    &mut sc.redeems.iter_mut().find(|(k, _)| *k == i).unwrap().1
}

#[test]
fn guest_refuses_h5_witness() {
    for (cash, leg) in WITH_CASH_VAULT {
        // no redeem script of this vault
        let mut sc = settle(cash, leg);
        let i = sc.j.input_index;
        sc.redeems.retain(|(k, _)| *k != i);
        refused_code(&sc, "ZK_H_WITNESS_INVALID", "H5");
        // a script that does not open J.vault_spk (one byte after the state changed)
        let mut sc = settle(cash, leg);
        own(&mut sc)[70] ^= 1;
        refused_code(&sc, "ZK_H_WITNESS_INVALID", "H5");
        // the other leg's script, which opens another address
        let mut sc = settle(cash, leg);
        *own(&mut sc) = vault_redeem(&sc.terms.clone(), 1 - leg);
        refused_code(&sc, "ZK_H_WITNESS_INVALID", "H5");
        // a script that opens J.vault_spk but whose state is not J's: each state byte in turn
        for at in [1usize, 2, 33, 34, 35, 66] {
            let mut sc = settle(cash, leg);
            own(&mut sc)[at] ^= 1;
            let r = own(&mut sc).clone();
            sc.j.vault_spk = p2sh_spk(&blake2b256(&r));
            refused_code(&sc, "ZK_H_WITNESS_INVALID", "H5");
        }
        // a script too short to hold the state
        let mut sc = settle(cash, leg);
        let r = own(&mut sc)[..60].to_vec();
        *own(&mut sc) = r.clone();
        sc.j.vault_spk = p2sh_spk(&blake2b256(&r));
        refused_code(&sc, "ZK_H_WITNESS_INVALID", "H5");
    }
}

#[test]
fn h5_does_not_apply_to_external_cash_or_refunds() {
    // external cash has no cash vault: no redeem script of the asset vault is needed
    let mut sc = settle(Cash::External, 0);
    sc.redeems.retain(|(k, _)| *k != 0);
    sc.run().unwrap();
    // a refund reads no vault redeem script
    let b = buyer();
    let mut sc = refund(Cash::Kcc20, 1, b, false, true, 0);
    sc.redeems.retain(|(k, _)| *k != 0);
    sc.run().unwrap();
}

// ---- witness ----

#[test]
fn guest_refuses_a_redeem_that_does_not_open() {
    let mut sc = settle(Cash::Kas, 0);
    sc.redeems[0].1[5] ^= 1;
    refused_code(&sc, "ZK_H_WITNESS_INVALID", "E3");
    let mut sc = settle(Cash::Kas, 0);
    sc.redeems.retain(|(i, _)| *i == 0);
    refused_code(&sc, "ZK_H_WITNESS_INVALID", "E3");
    // the cash vault needs the asset slot's redeem for the delivery builtin
    let mut sc = settle(Cash::Kas, 1);
    sc.redeems.retain(|(i, _)| *i == 1);
    refused_code(&sc, "ZK_H_WITNESS_INVALID", "DB");
}

#[test]
fn witness_bytes_round_trip_and_refuse_garbage() {
    let sc = settle(Cash::Kcc20, 0);
    let w = sc.witness();
    let b = w.to_bytes();
    assert_eq!(terms_core::Witness::from_bytes(&b).unwrap(), w);
    assert!(terms_core::Witness::from_bytes(&b[..b.len() - 1]).is_err());
    assert!(terms_core::Witness::from_bytes(&[b.clone(), vec![0]].concat()).is_err());
}
