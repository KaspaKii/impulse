// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Unit tests of the linked module: codes, the sheet codec and hash, every sheet check, the
//! derivation of the two trades, terms verification, the return gate and its evidence, the
//! builders by role, and the linked receipt. Keyless: the receipt test signs with a random
//! throwaway key generated at run time (rule 1, docs/ENGINEERING-RULES.md, owner decisions 2026-10-06), never
//! printed or stored.

use super::*;
use crate::terms::{CreationContext, IdentifierType, LegKind, Network};
use crate::tx::FeePayment;
use crate::v2::testkit::*;
use crate::v2::{DestinationV2, IpstV2, RefundSignerV2, VaultV2};
use kaspa_consensus_core::constants::MAX_SOMPI;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction};

const NS: &str = "tests";
const RETURN_EARLIEST: u64 = 2_500_000;
const RETURN_EXPIRY: u64 = 3_500_000;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn code<T: std::fmt::Debug>(r: Result<T, LinkedError>) -> &'static str {
    r.expect_err("refused").code()
}

/// Token against KAS, authority present: the repo shape.
fn sheet() -> LinkedSheet {
    let mut opening = two_kas(NS, true);
    opening.trade_ref = [0; 32];
    LinkedSheet {
        version: LINKED_VERSION,
        opening,
        return_amounts: [TOKEN_AMOUNT, KAS_AMOUNT + 1_000_000],
        return_earliest_daa: RETURN_EARLIEST,
        return_expiry_daa: RETURN_EXPIRY,
    }
}

fn linked() -> ValidatedLinked {
    sheet().validate().expect("fixture sheet validates")
}

fn with(f: impl FnOnce(&mut LinkedSheet)) -> LinkedSheet {
    let mut s = sheet();
    f(&mut s);
    s
}

// =============================================================================================
// Codes
// =============================================================================================

#[test]
fn linked_error_codes_are_frozen() {
    assert_eq!(
        LINKED_ERROR_CODES,
        [
            "LINKED_VERSION",
            "LINKED_TRUNCATED",
            "LINKED_TRAILING_BYTES",
            "LINKED_LEG_COUNT",
            "LINKED_PARTIAL",
            "LINKED_TRADE_REF_SET",
            "LINKED_RETURN_NOT_LATER",
            "LINKED_NOT_A_LEG",
            "LINKED_ROLE_MISMATCH",
            "LINKED_TRADE_REF",
            "LINKED_OPENING_NOT_SETTLED",
            "LINKED_SETTLE_EVIDENCE",
            "LINKED_RECEIPT_TERMS",
            "LINKED_RECEIPT_PAIR",
        ]
    );
    // Every code has a variant that raises it.
    let raised = [
        LinkedError::Version { version: 0 },
        LinkedError::Truncated { field: "x" },
        LinkedError::TrailingBytes { count: 1 },
        LinkedError::LegCount { count: 3 },
        LinkedError::Partial,
        LinkedError::TradeRefSet,
        LinkedError::ReturnNotLater {
            return_earliest_daa: 1,
            opening_expiry_daa: 2,
        },
        LinkedError::NotALeg { role: Role::Return },
        LinkedError::RoleMismatch { role: Role::Return },
        LinkedError::TradeRef { role: Role::Return },
        LinkedError::OpeningNotSettled,
        LinkedError::SettleEvidence {
            role: Role::Opening,
            reason: "x",
        },
        LinkedError::ReceiptTerms { reason: "x" },
        LinkedError::ReceiptPair { reason: "x" },
    ];
    let codes: Vec<&str> = raised.iter().map(LinkedError::code).collect();
    assert_eq!(codes, LINKED_ERROR_CODES);
    for e in &raised {
        assert!(e.to_string().starts_with(e.code()), "{e}");
        assert!(!e.to_string().contains('\u{2014}'));
    }
}

// =============================================================================================
// Sheet codec and hash
// =============================================================================================

#[test]
fn the_hash_key_is_the_tag_and_matches_known_answers() {
    assert_eq!(LINKED_HASH_DOMAIN, b"Impulse/terms/v2/linked");
    assert_eq!(LINKED_HASH_DOMAIN.len(), 23);
    // Computed independently with Python's hashlib.blake2b(key=b"Impulse/terms/v2/linked").
    for (msg, want) in [
        (
            &b""[..],
            "f0f21f6c2445993189163dbd26ee39bd3a600642664bc886d8e13c394eaf4e20",
        ),
        (
            &b"abc"[..],
            "ce884529d5bc1a435dc5200c6f094b0d4ead1d747e57e478354b7260507b1241",
        ),
    ] {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .key(LINKED_HASH_DOMAIN)
            .hash(msg);
        assert_eq!(hex(h.as_bytes()), want);
    }
    let s = sheet();
    let canonical = s.encode().unwrap();
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .key(LINKED_HASH_DOMAIN)
        .hash(&canonical);
    assert_eq!(s.linked_hash().unwrap(), h.as_bytes());
}

#[test]
fn the_layout_is_the_spec_s() {
    let s = sheet();
    let opening = s.opening.encode().unwrap();
    let b = s.encode().unwrap();
    assert_eq!(b[0], 1, "link_version");
    assert_eq!(
        u16::from_le_bytes([b[1], b[2]]) as usize,
        opening.len(),
        "opening_len"
    );
    assert_eq!(&b[3..3 + opening.len()], &opening[..], "opening");
    let tail = &b[3 + opening.len()..];
    assert_eq!(tail.len(), 32);
    let u = |i: usize| u64::from_le_bytes(tail[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(
        [u(0), u(1), u(2), u(3)],
        [
            s.return_amounts[0],
            s.return_amounts[1],
            RETURN_EARLIEST,
            RETURN_EXPIRY
        ]
    );
    assert_eq!(b.len(), 3 + opening.len() + 32);
}

#[test]
fn a_sheet_round_trips_both_ways() {
    let s = sheet();
    let b = s.encode().unwrap();
    assert_eq!(LinkedSheet::decode(&b).unwrap(), s);
    assert_eq!(LinkedSheet::decode(&b).unwrap().encode().unwrap(), b);
    assert_eq!(ValidatedLinked::decode(&b).unwrap().canonical(), &b[..]);
}

#[test]
fn decoding_refuses_every_malformed_form() {
    let b = sheet().encode().unwrap();
    // The version comes first, before anything else.
    let mut bad = b.clone();
    bad[0] = 2;
    assert_eq!(code(LinkedSheet::decode(&bad)), "LINKED_VERSION");
    assert_eq!(code(LinkedSheet::decode(&[0u8; 3])), "LINKED_VERSION");
    assert_eq!(code(LinkedSheet::decode(&[])), "LINKED_TRUNCATED");
    // Every proper prefix is refused, none accepted by accident.
    for n in 1..b.len() {
        assert!(LinkedSheet::decode(&b[..n]).is_err(), "prefix {n}");
    }
    // A cut inside the length, the opening and the tail are all LINKED_TRUNCATED or a terms code.
    assert_eq!(code(LinkedSheet::decode(&b[..2])), "LINKED_TRUNCATED");
    assert_eq!(
        code(LinkedSheet::decode(&b[..b.len() - 1])),
        "LINKED_TRUNCATED"
    );
    // Bytes after the last field.
    let mut long = b.clone();
    long.push(0);
    assert_eq!(code(LinkedSheet::decode(&long)), "LINKED_TRAILING_BYTES");
    // A length that cuts the opening is the terms codec's refusal.
    let mut short = b.clone();
    let len = u16::from_le_bytes([short[1], short[2]]) - 1;
    short[1..3].copy_from_slice(&len.to_le_bytes());
    assert_eq!(code(LinkedSheet::decode(&short)), "TERMS_TRUNCATED");
    // A length that overruns it hands the terms codec trailing bytes.
    let mut over = b.clone();
    let len = u16::from_le_bytes([over[1], over[2]]) + 1;
    over[1..3].copy_from_slice(&len.to_le_bytes());
    assert_eq!(code(LinkedSheet::decode(&over)), "TERMS_TRAILING_BYTES");
    // The opening's own version byte.
    let mut v1 = b.clone();
    v1[3] = 1;
    assert_eq!(code(LinkedSheet::decode(&v1)), "TERMS_V2_VERSION");
    // Encoding refuses a version other than 1.
    assert_eq!(code(with(|s| s.version = 2).encode()), "LINKED_VERSION");
}

// =============================================================================================
// Sheet checks, in order
// =============================================================================================

#[test]
fn every_sheet_check_refuses_and_the_control_passes() {
    assert!(sheet().validate().is_ok(), "control");
    assert_eq!(code(with(|s| s.version = 2).validate()), "LINKED_VERSION");
    // 2. The opening's structure.
    assert_eq!(
        code(
            with(|s| s.opening.legs[1].depositor_key = s.opening.legs[0].depositor_key).validate()
        ),
        "TERMS_LEGS_ONE_PARTY"
    );
    assert_eq!(
        code(with(|s| s.opening.legs[0].asset.amount = 0).validate()),
        "TERMS_AMOUNT_ZERO"
    );
    // 3. Two legs.
    assert_eq!(
        code(with(|s| s.opening = ring3(NS, true)).validate()),
        "LINKED_LEG_COUNT"
    );
    // 4. No partial.
    assert_eq!(
        code(
            with(|s| {
                s.opening.partial = Some(crate::v2::Partial {
                    lot_count: 2,
                    min_lot: 1,
                })
            })
            .validate()
        ),
        "LINKED_PARTIAL"
    );
    // 5. A zero trade_ref.
    assert_eq!(
        code(with(|s| s.opening.trade_ref = [1; 32]).validate()),
        "LINKED_TRADE_REF_SET"
    );
    // 6. The return starts strictly after the opening's expiry.
    assert_eq!(
        code(with(|s| s.return_earliest_daa = s.opening.expiry_daa).validate()),
        "LINKED_RETURN_NOT_LATER"
    );
    assert_eq!(
        code(with(|s| s.return_earliest_daa = 1).validate()),
        "LINKED_RETURN_NOT_LATER"
    );
    assert!(with(|s| s.return_earliest_daa = s.opening.expiry_daa + 1)
        .validate()
        .is_ok());
    // 7. The derived return's structure checks.
    assert_eq!(
        code(with(|s| s.return_amounts[0] = 0).validate()),
        "TERMS_AMOUNT_ZERO"
    );
    assert_eq!(
        code(with(|s| s.return_amounts[1] = MAX_SOMPI + 1).validate()),
        "TERMS_AMOUNT_OUT_OF_RANGE"
    );
    assert_eq!(
        code(with(|s| s.return_expiry_daa = s.return_earliest_daa - 1).validate()),
        "TERMS_EARLIEST_AFTER_EXPIRY"
    );
    assert_eq!(
        code(with(|s| s.return_expiry_daa = 500_000_000_000).validate()),
        "TERMS_EXPIRY_NOT_DAA"
    );
    assert_eq!(
        code(
            with(|s| {
                s.return_earliest_daa = 500_000_000_000;
                s.return_expiry_daa = 1;
            })
            .validate()
        ),
        "TERMS_EARLIEST_NOT_DAA"
    );
}

#[test]
fn the_checks_run_in_the_specs_order() {
    // Version before the opening's structure.
    let both = with(|s| {
        s.version = 9;
        s.opening.legs[0].asset.amount = 0;
    });
    assert_eq!(code(both.validate()), "LINKED_VERSION");
    // The opening's structure before the leg count.
    let s = with(|s| {
        s.opening = ring3(NS, true);
        s.opening.legs[0].asset.amount = 0;
    });
    assert_eq!(code(s.validate()), "TERMS_AMOUNT_ZERO");
    // Partial before the trade_ref, the trade_ref before the timing, the timing before the
    // derived return.
    let s = with(|s| {
        s.opening.partial = Some(crate::v2::Partial {
            lot_count: 2,
            min_lot: 1,
        });
        s.opening.trade_ref = [1; 32];
    });
    assert_eq!(code(s.validate()), "LINKED_PARTIAL");
    let s = with(|s| {
        s.opening.trade_ref = [1; 32];
        s.return_earliest_daa = 0;
    });
    assert_eq!(code(s.validate()), "LINKED_TRADE_REF_SET");
    let s = with(|s| {
        s.return_earliest_daa = 0;
        s.return_amounts[0] = 0;
    });
    assert_eq!(code(s.validate()), "LINKED_RETURN_NOT_LATER");
}

// =============================================================================================
// Derivation
// =============================================================================================

#[test]
fn the_return_is_derived_by_the_specs_table() {
    let l = linked();
    let s = l.sheet();
    let (open, ret) = (
        l.terms(Role::Opening).terms(),
        l.terms(Role::Return).terms(),
    );
    assert_eq!(open.trade_ref, l.linked_hash());
    assert_eq!(ret.trade_ref, l.linked_hash());
    assert_ne!(l.linked_hash(), [0; 32]);
    // The opening is the sheet's opening with the hash written in.
    let mut expected = s.opening.clone();
    expected.trade_ref = l.linked_hash();
    assert_eq!(open, &expected);
    // Shared fields.
    assert_eq!(ret.version, 2);
    assert_eq!(ret.network, open.network);
    assert_eq!(ret.nonce, open.nonce, "shared nonce");
    assert_eq!(ret.authority_key, open.authority_key);
    assert_eq!(ret.funding_mode, open.funding_mode);
    assert_eq!(ret.partial, None);
    assert_eq!(ret.earliest_daa, Some(RETURN_EARLIEST));
    assert_eq!(ret.expiry_daa, RETURN_EXPIRY);
    assert!(ret.earliest_daa.unwrap() > open.expiry_daa);
    // Legs: swapped depositors, same kinds, agreed amounts, swapped destinations.
    assert_eq!(ret.legs.len(), 2);
    for i in 0..2 {
        let (o, r) = (&open.legs[i], &ret.legs[i]);
        assert_eq!(r.depositor_key, open.legs[1 - i].depositor_key, "leg {i}");
        assert_ne!(r.depositor_key, o.depositor_key);
        assert_eq!(r.asset.kind, o.asset.kind);
        assert_eq!(r.asset.amount, s.return_amounts[i]);
        assert_eq!(r.delivery, o.refund);
        assert_eq!(r.refund, o.delivery);
    }
    // Different trades with different hashes, so different vault addresses.
    assert_ne!(l.terms_hash(Role::Opening), l.terms_hash(Role::Return));
    let spk = |role, leg| l.vault(role, leg).unwrap().script_public_key();
    for (a, b) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        assert_ne!(spk(Role::Opening, a), spk(Role::Return, b));
    }
    // KCC-20 legs still come first.
    assert!(matches!(ret.legs[0].asset.kind, LegKind::Kcc20(_)));
    assert!(matches!(ret.legs[1].asset.kind, LegKind::Kas));
}

#[test]
fn every_sheet_field_reaches_the_hash_and_the_opening_address() {
    let base = linked();
    let edits: [fn(&mut LinkedSheet); 6] = [
        |s| s.return_amounts[0] += 1,
        |s| s.return_amounts[1] += 1,
        |s| s.return_earliest_daa += 1,
        |s| s.return_expiry_daa += 1,
        |s| s.opening.nonce += 1,
        |s| s.opening.legs[1].asset.amount += 1,
    ];
    for (i, edit) in edits.iter().enumerate() {
        let other = with(*edit).validate().unwrap();
        assert_ne!(other.linked_hash(), base.linked_hash(), "edit {i}");
        // The opening vault commits to the whole sheet through trade_ref: a funded opening
        // belongs to one return schedule only.
        for leg in 0..2 {
            assert_ne!(
                other.vault(Role::Opening, leg).unwrap().script_public_key(),
                base.vault(Role::Opening, leg).unwrap().script_public_key(),
                "edit {i} leg {leg}"
            );
        }
    }
}

#[test]
fn derived_trades_decode_from_their_vault_scripts() {
    let l = linked();
    for role in [Role::Opening, Role::Return] {
        for leg in 0..2 {
            let script = l.vault(role, leg).unwrap();
            let (terms, found) = crate::v2::decode_vault(script.redeem_script()).unwrap();
            assert_eq!(&terms, l.terms(role));
            assert_eq!(found, leg);
        }
    }
}

#[test]
fn creation_checks_run_per_trade_at_that_trades_own_moment() {
    let l = linked();
    let at = |daa| CreationContext::new(Network::Mainnet, daa);
    // The opening is created before its expiry, the return, later, before its own.
    assert!(l.validate_creation(Role::Opening, &at(1_500_000)).is_ok());
    assert_eq!(
        code(l.validate_creation(Role::Opening, &at(2_000_000))),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    assert!(l.validate_creation(Role::Return, &at(2_600_000)).is_ok());
    assert_eq!(
        code(l.validate_creation(Role::Return, &at(3_500_000))),
        "TERMS_EXPIRY_NOT_AFTER_CREATION"
    );
    assert_eq!(
        code(l.validate_creation(Role::Return, &CreationContext::new(Network::Testnet, 1))),
        "TERMS_NETWORK_MISMATCH"
    );
    let far = CreationContext {
        network: Network::Mainnet,
        creation_daa: 1,
        max_expiry_horizon_daa: 1_000_000,
    };
    assert_eq!(
        code(l.validate_creation(Role::Return, &far)),
        "TERMS_EXPIRY_BEYOND_HORIZON",
        "created long before its expiry"
    );
    assert_eq!(
        code(l.vault_for_creation(Role::Return, 0, &far)),
        "TERMS_EXPIRY_BEYOND_HORIZON"
    );
}

// =============================================================================================
// Verifying terms against the sheet
// =============================================================================================

#[test]
fn verify_terms_accepts_each_derived_trade_and_names_each_fault() {
    let l = linked();
    let open = l.terms(Role::Opening).terms().clone();
    let ret = l.terms(Role::Return).terms().clone();
    assert_eq!(l.verify_terms(Role::Opening, &open), Ok(()));
    assert_eq!(l.verify_terms(Role::Return, &ret), Ok(()));
    // The other role's trade.
    assert_eq!(
        code(l.verify_terms(Role::Return, &open)),
        "LINKED_ROLE_MISMATCH"
    );
    assert_eq!(
        code(l.verify_terms(Role::Opening, &ret)),
        "LINKED_ROLE_MISMATCH"
    );
    // Right terms, other trade_ref.
    let mut wrong_ref = open.clone();
    wrong_ref.trade_ref = [7; 32];
    assert_eq!(
        code(l.verify_terms(Role::Opening, &wrong_ref)),
        "LINKED_TRADE_REF"
    );
    let mut zero_ref = ret.clone();
    zero_ref.trade_ref = [0; 32];
    assert_eq!(
        code(l.verify_terms(Role::Return, &zero_ref)),
        "LINKED_TRADE_REF"
    );
    // Anything else.
    let mut edited = ret.clone();
    edited.legs[1].asset.amount += 1;
    assert_eq!(
        code(l.verify_terms(Role::Return, &edited)),
        "LINKED_NOT_A_LEG"
    );
    let mut later = open.clone();
    later.expiry_daa += 1;
    assert_eq!(
        code(l.verify_terms(Role::Opening, &later)),
        "LINKED_NOT_A_LEG"
    );
    let mut v = open;
    v.version = 3;
    assert_eq!(code(l.verify_terms(Role::Opening, &v)), "TERMS_V2_VERSION");
}

// =============================================================================================
// The return gate
// =============================================================================================

/// A settle of the opening: the builders' transaction with the dummy-signature script each slot
/// takes (nothing here is a signature), and the scriptPublicKeys the inputs spend.
fn opening_settle(l: &ValidatedLinked) -> (Transaction, Vec<ScriptPublicKey>) {
    let tmpl = template();
    let t = l.terms(Role::Opening);
    let f = funded(t, &format!("{NS}/open"));
    let ipst = l
        .settle(
            Role::Opening,
            None,
            &settle_legs(&f, &tmpl),
            &fee_payment(NS),
            NOW,
        )
        .expect("opening settle");
    signed_shape(&ipst)
}

fn signed_shape(ipst: &IpstV2) -> (Transaction, Vec<ScriptPublicKey>) {
    let mut tx = ipst.transaction().clone();
    for (input, slot) in tx.inputs.iter_mut().zip(ipst.slots()) {
        input.signature_script = slot.script_with(&[0; 65]);
    }
    let spent = ipst
        .entries()
        .iter()
        .map(|e| e.script_public_key.clone())
        .collect();
    (tx, spent)
}

#[test]
fn the_settle_tag_is_the_artifacts() {
    // The dispatch tag the watcher pins for the v2 artifact.
    assert_eq!(settle_tag(), [0x8f, 0xb0, 0x4e, 0x80]);
}

#[test]
fn an_opening_settle_is_evidence_and_nothing_else_is() {
    let l = linked();
    let (tx, spent) = opening_settle(&l);
    let e = check_opening_settled(&l, &tx, &spent).expect("a settle of both opening vaults");
    assert_eq!(e.linked_hash(), l.linked_hash());
    assert_eq!(
        e.txid(),
        kaspa_consensus_core::hashing::tx::id(&tx).as_bytes()
    );
    assert_eq!(e.check_for(&l), Ok(()));

    // A refund of an opening vault is not a settle.
    let tmpl = template();
    let f = funded(l.terms(Role::Opening), &format!("{NS}/open"));
    let refund = l
        .refund(
            Role::Opening,
            0,
            RefundSignerV2::Depositor(0),
            &f[0].vault,
            refund_escrow(&f[0], &tmpl).as_ref(),
            &fee_payment(NS),
        )
        .unwrap();
    let (rtx, rspent) = signed_shape(&refund);
    assert_eq!(
        code(check_opening_settled(&l, &rtx, &rspent)),
        "LINKED_SETTLE_EVIDENCE"
    );

    // A settle of the return trade, of another sheet's opening, a transaction with one input,
    // and a settle whose spent scripts are not the vaults are all refused.
    let ret_f = funded(l.terms(Role::Return), &format!("{NS}/ret"));
    let ret_settle = l
        .settle(
            Role::Return,
            Some(&e),
            &settle_legs(&ret_f, &tmpl),
            &fee_payment(NS),
            NOW,
        )
        .unwrap();
    let (ttx, tspent) = signed_shape(&ret_settle);
    assert_eq!(
        code(check_opening_settled(&l, &ttx, &tspent)),
        "LINKED_SETTLE_EVIDENCE",
        "the return settle is not the opening's"
    );
    // The same reading for the return's own settle, by role, and not across roles.
    assert_eq!(
        check_settled(&l, Role::Return, &ttx, &tspent),
        Ok(kaspa_consensus_core::hashing::tx::id(&ttx).as_bytes())
    );
    assert_eq!(
        code(check_settled(&l, Role::Return, &tx, &spent)),
        "LINKED_SETTLE_EVIDENCE"
    );
    assert_eq!(
        code(check_settled(&l, Role::Opening, &ttx, &tspent)),
        "LINKED_SETTLE_EVIDENCE"
    );
    let other = with(|s| s.return_amounts[0] += 1).validate().unwrap();
    assert_eq!(
        code(check_opening_settled(&other, &tx, &spent)),
        "LINKED_SETTLE_EVIDENCE",
        "the opening of another sheet"
    );
    let mut one = tx.clone();
    one.inputs.truncate(1);
    assert_eq!(
        code(check_opening_settled(&l, &one, &spent)),
        "LINKED_SETTLE_EVIDENCE"
    );
    assert_eq!(
        code(check_opening_settled(&l, &tx, &spent[..1])),
        "LINKED_SETTLE_EVIDENCE"
    );
    // A third input (the fee input) whose spent script is missing.
    assert!(tx.inputs.len() > 2, "the settle has a fee input");
    assert_eq!(
        code(check_opening_settled(&l, &tx, &spent[..2])),
        "LINKED_SETTLE_EVIDENCE"
    );
    let mut swapped = spent.clone();
    swapped.swap(0, 1);
    assert_eq!(
        code(check_opening_settled(&l, &tx, &swapped)),
        "LINKED_SETTLE_EVIDENCE"
    );
    let mut nothing = tx.clone();
    nothing.inputs[0].signature_script = vec![0x6a];
    assert_eq!(
        code(check_opening_settled(&l, &nothing, &spent)),
        "LINKED_SETTLE_EVIDENCE"
    );
    // Input 1 with a tag that is not settle.
    let mut wrong_tag = tx.clone();
    wrong_tag.inputs[1].signature_script = refund_script_of_leg(&l, 1);
    assert_eq!(
        code(check_opening_settled(&l, &wrong_tag, &spent)),
        "LINKED_SETTLE_EVIDENCE"
    );
    // Evidence for one sheet is not evidence for another.
    assert_eq!(
        e.check_for(&other).expect_err("other sheet").code(),
        "LINKED_OPENING_NOT_SETTLED"
    );
}

/// The signature script of a refund spend of the opening vault of `leg`.
fn refund_script_of_leg(l: &ValidatedLinked, leg: usize) -> Vec<u8> {
    let tmpl = template();
    let f = funded(l.terms(Role::Opening), &format!("{NS}/open"));
    let r = l
        .refund(
            Role::Opening,
            leg,
            RefundSignerV2::Depositor(leg),
            &f[leg].vault,
            refund_escrow(&f[leg], &tmpl).as_ref(),
            &fee_payment(NS),
        )
        .unwrap();
    r.slots()[0].script_with(&[0; 65])
}

// =============================================================================================
// Builders by role
// =============================================================================================

fn evidence(l: &ValidatedLinked) -> OpeningSettled {
    let (tx, spent) = opening_settle(l);
    check_opening_settled(l, &tx, &spent).unwrap()
}

fn kas_funding(ns: &str) -> FeePayment {
    fee_payment(ns)
}

#[test]
fn the_opening_builds_without_evidence_and_the_return_needs_it() {
    let l = linked();
    let tmpl = template();
    let ctx = |role| {
        let created = match role {
            Role::Opening => 1_000_000,
            Role::Return => 3_000_000,
        };
        CreationContext::new(Network::Mainnet, created)
    };
    // Fund the KAS leg (leg 1) of each trade.
    let fund = |role, ev: Option<&OpeningSettled>| {
        let vault = l.vault_for_creation(role, 1, &ctx(role)).unwrap();
        l.fund_kas(role, ev, &vault, &kas_funding(NS), ctx(role).creation_daa)
    };
    assert!(fund(Role::Opening, None).is_ok(), "the opening needs none");
    assert_eq!(code(fund(Role::Return, None)), "LINKED_OPENING_NOT_SETTLED");
    let ev = evidence(&l);
    assert!(fund(Role::Return, Some(&ev)).is_ok(), "control");
    // Evidence for another sheet.
    let other = with(|s| s.return_amounts[0] += 1).validate().unwrap();
    let other_ev = evidence(&other);
    assert_eq!(
        code(fund(Role::Return, Some(&other_ev))),
        "LINKED_OPENING_NOT_SETTLED"
    );
    // The opening does not mind which evidence it is given.
    assert!(fund(Role::Opening, Some(&other_ev)).is_ok());

    // Settle.
    let f = funded(l.terms(Role::Return), &format!("{NS}/ret"));
    let legs = settle_legs(&f, &tmpl);
    assert_eq!(
        code(l.settle(Role::Return, None, &legs, &fee_payment(NS), NOW)),
        "LINKED_OPENING_NOT_SETTLED"
    );
    assert_eq!(
        code(l.settle(Role::Return, Some(&other_ev), &legs, &fee_payment(NS), NOW)),
        "LINKED_OPENING_NOT_SETTLED"
    );
    assert!(l
        .settle(Role::Return, Some(&ev), &legs, &fee_payment(NS), NOW)
        .is_ok());

    // A refund of either trade needs no evidence.
    for role in [Role::Opening, Role::Return] {
        let f = funded(l.terms(role), &format!("{NS}/refund-{}", role.name()));
        assert!(l
            .refund(
                role,
                1,
                RefundSignerV2::Depositor(1),
                &f[1].vault,
                None,
                &fee_payment(NS)
            )
            .is_ok());
    }
}

#[test]
fn a_builder_is_given_the_vault_of_its_own_role() {
    // The vault of the opening cannot fund the return: the v2 builder's vault check.
    let l = linked();
    let ctx = CreationContext::new(Network::Mainnet, 3_000_000);
    let ev = evidence(&l);
    let opening_ctx = CreationContext::new(Network::Mainnet, 1_000_000);
    let opening_vault = l
        .vault_for_creation(Role::Opening, 1, &opening_ctx)
        .unwrap();
    assert_eq!(
        code(l.fund_kas(
            Role::Return,
            Some(&ev),
            &opening_vault,
            &fee_payment(NS),
            ctx.creation_daa
        )),
        "TX_VAULT_MISMATCH"
    );
}

#[test]
fn the_pair_of_trades_is_two_ordinary_v2_trades() {
    // Nothing is added to the contract: both vaults are instances of the pinned v2 template.
    let l = linked();
    let pinned = crate::v2::check_template().unwrap().hash();
    for role in [Role::Opening, Role::Return] {
        for leg in 0..2 {
            let v: VaultV2 = l.vault(role, leg).unwrap();
            assert_eq!(
                crate::v2::template_hash_of_instance(v.redeem_script()).unwrap(),
                pinned
            );
        }
    }
    assert_eq!(
        l.trade(Role::Return).terms_hash(),
        l.terms_hash(Role::Return)
    );
}

#[test]
fn nothing_of_the_leg_types_changes_on_the_way() {
    // A KAS leg's destinations swap as given, whatever their type.
    let mut s = sheet();
    s.opening.legs[1].delivery = DestinationV2 {
        identifier_type: IdentifierType::ScriptHash,
        identifier: [9; 32],
    };
    let l = s.validate().unwrap();
    let ret = l.terms(Role::Return).terms();
    assert_eq!(
        ret.legs[1].refund.identifier_type,
        IdentifierType::ScriptHash
    );
    assert_eq!(ret.legs[1].refund.identifier, [9; 32]);
}

// =============================================================================================
// Linked receipt
// =============================================================================================

fn observation(l: &ValidatedLinked, role: Role, txid: u8, daa: u64) -> LinkedObservation {
    LinkedObservation {
        network: Network::Mainnet,
        role,
        linked_hash: l.linked_hash(),
        leg_terms_hash: l.terms_hash(role),
        txid: [txid; 32],
        accepting_block: [0x44; 32],
        daa_score: daa,
        depth: 10,
    }
}

#[test]
fn the_receipt_digest_known_answer() {
    // Computed independently with Python's hashlib.blake2b(key=b"Impulse/receipt/linked/v1").
    let o = LinkedObservation {
        network: Network::Testnet,
        role: Role::Return,
        linked_hash: [0x11; 32],
        leg_terms_hash: [0x22; 32],
        txid: [0x33; 32],
        accepting_block: [0x44; 32],
        daa_score: 1000,
        depth: 10,
    };
    assert_eq!(LINKED_RECEIPT_DOMAIN.len(), 25);
    assert_eq!(o.canonical().len(), LINKED_RECEIPT_LEN);
    assert_eq!(
        hex(&o.digest()),
        "6b52dc4bc15abe858f1c83ec05eba532f6b9630e5c7f97b28e81cbb5eebcc018"
    );
}

#[test]
fn every_receipt_field_is_in_the_digest() {
    let l = linked();
    let base = observation(&l, Role::Opening, 0x33, 1000);
    let edits: [fn(&mut LinkedObservation); 8] = [
        |o| o.network = Network::Testnet,
        |o| o.role = Role::Return,
        |o| o.linked_hash[0] ^= 1,
        |o| o.leg_terms_hash[0] ^= 1,
        |o| o.txid[0] ^= 1,
        |o| o.accepting_block[0] ^= 1,
        |o| o.daa_score += 1,
        |o| o.depth += 1,
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut o = base;
        edit(&mut o);
        assert_ne!(o.digest(), base.digest(), "edit {i}");
    }
}

#[test]
fn a_receipt_is_checked_against_the_sheet() {
    let l = linked();
    for role in [Role::Opening, Role::Return] {
        assert_eq!(
            observation(&l, role, 1, 5).check_against(&l),
            Ok(()),
            "control"
        );
    }
    let mut o = observation(&l, Role::Opening, 1, 5);
    o.linked_hash[0] ^= 1;
    assert_eq!(code(o.check_against(&l)), "LINKED_RECEIPT_TERMS");
    // The return's terms hash under the opening role, and the reverse.
    let mut o = observation(&l, Role::Opening, 1, 5);
    o.leg_terms_hash = l.terms_hash(Role::Return);
    assert_eq!(code(o.check_against(&l)), "LINKED_RECEIPT_TERMS");
    let mut o = observation(&l, Role::Return, 1, 5);
    o.leg_terms_hash = l.terms_hash(Role::Opening);
    assert_eq!(code(o.check_against(&l)), "LINKED_RECEIPT_TERMS");
    let mut o = observation(&l, Role::Opening, 1, 5);
    o.network = Network::Testnet;
    assert_eq!(code(o.check_against(&l)), "LINKED_RECEIPT_TERMS");
    // Another sheet.
    let other = with(|s| s.return_amounts[1] += 1).validate().unwrap();
    assert_eq!(
        code(observation(&l, Role::Opening, 1, 5).check_against(&other)),
        "LINKED_RECEIPT_TERMS"
    );
}

#[test]
fn a_pair_is_an_opening_then_a_return_of_one_sheet() {
    let l = linked();
    let o = observation(&l, Role::Opening, 1, 100);
    let r = observation(&l, Role::Return, 2, 200);
    assert_eq!(check_pair(&o, &r), Ok(()), "control");
    // Both receipts link to one terms hash.
    assert_eq!(o.linked_hash, r.linked_hash);
    assert_ne!(o.leg_terms_hash, r.leg_terms_hash);
    let refused = |o: &LinkedObservation, r: &LinkedObservation| code(check_pair(o, r));
    assert_eq!(refused(&r, &o), "LINKED_RECEIPT_PAIR", "wrong order");
    assert_eq!(refused(&o, &o), "LINKED_RECEIPT_PAIR", "one role twice");
    assert_eq!(refused(&r, &r), "LINKED_RECEIPT_PAIR");
    let mut x = r;
    x.network = Network::Testnet;
    assert_eq!(refused(&o, &x), "LINKED_RECEIPT_PAIR");
    let mut x = r;
    x.linked_hash[0] ^= 1;
    assert_eq!(refused(&o, &x), "LINKED_RECEIPT_PAIR");
    let mut x = r;
    x.txid = o.txid;
    assert_eq!(refused(&o, &x), "LINKED_RECEIPT_PAIR");
    let mut x = r;
    x.daa_score = o.daa_score;
    assert_eq!(refused(&o, &x), "LINKED_RECEIPT_PAIR", "not later");
    x.daa_score = o.daa_score - 1;
    assert_eq!(refused(&o, &x), "LINKED_RECEIPT_PAIR", "earlier");
}

#[test]
fn a_signed_receipt_verifies_and_each_edit_breaks_it() {
    use secp256k1::{Keypair, Message, SECP256K1};
    let l = linked();
    // A random throwaway key, in memory only, dropped at the end of the test.
    let pair = Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
    let observation = observation(&l, Role::Return, 9, 77);
    let sig = SECP256K1.sign_schnorr(&Message::from_digest(observation.digest()), &pair);
    let receipt = LinkedReceipt {
        observation,
        signer: pair.x_only_public_key().0.serialize(),
        signature: *sig.as_ref(),
    };
    assert_eq!(receipt.verify_signature(), Ok(()));
    let mut bad = receipt;
    bad.observation.depth += 1;
    assert!(bad.verify_signature().is_err());
    let mut bad = receipt;
    bad.signature[0] ^= 1;
    assert!(bad.verify_signature().is_err());
    let mut bad = receipt;
    bad.signer = [0; 32];
    assert!(bad.verify_signature().is_err());
    // A version 1 receipt's digest is another message: the key separates them.
    assert_ne!(LINKED_RECEIPT_DOMAIN, b"Impulse/receipt/v1");
}
