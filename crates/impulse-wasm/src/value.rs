// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The per-trade value cap of the SDK (owner decision D4, default
//! 10 KAS; the rule of spec/CLI.md, "Value cap", with the differences listed below). This is the
//! one implementation in the SDK. Every builder, every call that hands out a funding address or
//! checks a counterparty's addresses (`instantiateForCreation`, `verifyAddresses`,
//! `beforeFunding`), the terms check a signer runs on a received IPST (`verifyAgainstTerms`) and
//! the funding instructions of the browser demo (`fundingInstructions`, I11) read a declaration
//! and refuse a trade above the cap before they do anything else of their own. The two entry
//! forms differ and meet in [`ValueDeclaration`]: the builders read `{ kas_equivalent?,
//! max_value?, i_accept_the_risk? }` ([`declaration_from_json`], a malformed value is
//! `SDK_JSON_FORM`), the funding instructions read `kas_equivalent`, `cap` (text, see
//! [`cap_from_text`]) and `accept_the_risk` from their options, and both call
//! [`measure`].
//!
//! The exposure is both escrowed legs, and in v1 the asset leg is always a KCC-20 token, whose
//! KAS value the SDK cannot know. So the value is unknown unless the caller declares it
//! (`kas_equivalent`, the KAS value of the larger leg in sompi, required nonzero for every trade
//! with a leg that is not native KAS). The value is the larger of the declaration, every native
//! KAS leg, and the native KAS the call itself moves (see [`measure`]), so a declaration can
//! raise the value but never lower it below a KAS amount. The declaration is the caller's word;
//! nothing on chain checks it.
//!
//! Only an explicit acceptance of the risk lifts the cap. A cap may lower it and never
//! raise it. The two together contradict each other and are refused (`SDK_VALUE_CAP_INVALID`);
//! spec/CLI.md says only that the flag lifts the cap, so the CLI tolerates the pair and the SDK
//! does not.
//!
//! Differences from spec/CLI.md, both stricter, for the owner under D4: the native KAS a call
//! moves besides the terms' legs is counted (the CLI counts the terms' legs and the declaration),
//! and a cap together with the lift flag is refused. The places the cap holds match the spec (the
//! funding address as `address`, the address checks as `verify`, the signer's check as `ipst
//! sign`, every builder). `cargo test` compares this rule with the command line's on every case
//! of the funding instructions (funding.rs).
//!
//! This is a second copy of the rule in impulse-cli (`value_cap.rs`): moving it into impulse-core
//! is outside the SDK crate.

use crate::error::SdkError;
use crate::json::{decimal_u64, Obj};
use impulse_core::terms::{LegKind, Terms};
use serde_json::Value;

/// 10 KAS in sompi.
pub const DEFAULT_MAX_VALUE_SOMPI: u64 = 1_000_000_000;

/// What a builder call declares about the trade's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValueDeclaration {
    kas_equivalent: Option<u64>,
    max_value: Option<u64>,
    accept_the_risk: bool,
}

impl ValueDeclaration {
    /// A declaration from its three parts: the KAS value of the larger leg in sompi, a cap that
    /// may only lower the default, and whether the caller accepts the risk.
    pub(crate) fn new(
        kas_equivalent: Option<u64>,
        max_value: Option<u64>,
        accept_the_risk: bool,
    ) -> Self {
        Self {
            kas_equivalent,
            max_value,
            accept_the_risk,
        }
    }
}

/// The cap as `fundingInstructions` takes it, as text: a decimal number of sompi, else
/// `SDK_VALUE_CAP_INVALID`. (The builders' `max_value` goes through the strict form reader and
/// is `SDK_JSON_FORM` when malformed.) A cap above the default is refused by [`measure`].
pub(crate) fn cap_from_text(text: &str) -> Result<u64, SdkError> {
    decimal_u64(text).ok_or_else(|| SdkError::ValueCapInvalid {
        reason: "the cap is not a decimal number of sompi".into(),
    })
}

/// Reads the declaration: `{ kas_equivalent?, max_value?, i_accept_the_risk? }`, every key
/// optional as a value, no other key. The object itself is required: a builder called without a
/// declaration is refused (`SDK_JSON_FORM`).
pub(crate) fn declaration_from_json(value: &Value) -> Result<ValueDeclaration, SdkError> {
    let mut o = Obj::new(value, "value")?;
    let kas_equivalent = o
        .optional("kas_equivalent")
        .map(|_| o.u64("kas_equivalent"))
        .transpose()?;
    let max_value = o
        .optional("max_value")
        .map(|_| o.u64("max_value"))
        .transpose()?;
    let accept_the_risk = o
        .optional("i_accept_the_risk")
        .map(|_| o.bool("i_accept_the_risk"))
        .transpose()?
        .unwrap_or(false);
    o.finish()?;
    Ok(ValueDeclaration {
        kas_equivalent,
        max_value,
        accept_the_risk,
    })
}

/// What the cap check measured, for a caller that shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValueCheck {
    pub value: u64,
    pub cap: u64,
    pub declared: u64,
    pub largest_kas_leg: u64,
}

/// Refuses a trade above the cap, in order: a contradictory or raised cap
/// (`SDK_VALUE_CAP_INVALID`), a value that is unknown (`SDK_VALUE_UNKNOWN`), a value above the
/// cap (`SDK_VALUE_CAP_EXCEEDED`). Returns what it measured, or `None` when the caller accepted
/// the risk and nothing was measured.
///
/// `native_kas` is the largest native KAS amount the call moves besides the terms' legs, in
/// sompi: for funding a KCC-20 leg the carrier and authorizer KAS that go into the vault with the
/// token (they go on to the receiving party on settle, spec/TRANSACTIONS.md), and for every call
/// that has one, the fee the submitter pays away. It counts as a native KAS leg does: the value
/// is the larger of it, the KAS legs and the declaration.
pub(crate) fn measure(
    terms: &Terms,
    declaration: &ValueDeclaration,
    native_kas: u64,
) -> Result<Option<ValueCheck>, SdkError> {
    let Some(cap) = cap_of(declaration)? else {
        return Ok(None);
    };
    let legs = [&terms.asset_leg, &terms.cash_leg];
    let all_kas = legs.iter().all(|l| l.kind == LegKind::Kas);
    let largest_kas_leg = legs
        .iter()
        .filter(|l| l.kind == LegKind::Kas)
        .map(|l| l.amount)
        .max()
        .unwrap_or(0);
    measure_legs(
        cap,
        declaration.kas_equivalent,
        all_kas,
        largest_kas_leg,
        native_kas,
    )
}

/// The cap in force, or none when the caller accepts the risk.
fn cap_of(declaration: &ValueDeclaration) -> Result<Option<u64>, SdkError> {
    let ValueDeclaration {
        max_value,
        accept_the_risk,
        ..
    } = *declaration;
    if accept_the_risk {
        if max_value.is_some() {
            return Err(SdkError::ValueCapInvalid {
                reason: "a lowered cap and the acceptance of the risk contradict each other: the cap is either lowered or lifted".into(),
            });
        }
        return Ok(None);
    }
    match max_value {
        Some(m) if m > DEFAULT_MAX_VALUE_SOMPI => Err(SdkError::ValueCapInvalid {
            reason: "the cap is above the default cap of 1000000000 sompi; a cap can only lower it, and only an explicit acceptance of the risk lifts it".into(),
        }),
        Some(m) => Ok(Some(m)),
        None => Ok(Some(DEFAULT_MAX_VALUE_SOMPI)),
    }
}

/// The value check of terms v2 (spec/V2.md 6.5, D57): the KAS legs count together, since a v2
/// trade escrows every leg at once, and the declaration is the KAS value of all legs together.
pub(crate) fn check_v2(
    terms: &impulse_core::v2::TermsV2,
    declaration: &ValueDeclaration,
    native_kas: u64,
) -> Result<(), SdkError> {
    let Some(cap) = cap_of(declaration)? else {
        return Ok(());
    };
    let all_kas = terms.legs.iter().all(|l| l.asset.kind == LegKind::Kas);
    let kas_legs = terms
        .legs
        .iter()
        .filter(|l| l.asset.kind == LegKind::Kas)
        .fold(0u64, |s, l| s.saturating_add(l.asset.amount));
    measure_legs(
        cap,
        declaration.kas_equivalent,
        all_kas,
        kas_legs,
        native_kas,
    )
    .map(|_| ())
}

fn measure_legs(
    cap: u64,
    kas_equivalent: Option<u64>,
    all_kas: bool,
    largest_kas_leg: u64,
    native_kas: u64,
) -> Result<Option<ValueCheck>, SdkError> {
    let declared = match kas_equivalent {
        Some(0) => {
            return Err(SdkError::ValueUnknown {
                reason: "a declared KAS equivalent of 0 declares no value; give the KAS value of the larger leg in sompi (kas_equivalent)",
            })
        }
        Some(v) => v,
        None if all_kas => 0,
        None => {
            return Err(SdkError::ValueUnknown {
                reason: "a leg is not native KAS, so the trade's value is unknown: declare the KAS value of the larger leg in sompi (kas_equivalent)",
            })
        }
    };
    let value = largest_kas_leg.max(declared).max(native_kas);
    if value > cap {
        return Err(SdkError::ValueCapExceeded { value, cap });
    }
    Ok(Some(ValueCheck {
        value,
        cap,
        declared,
        largest_kas_leg,
    }))
}

/// [`measure`] for a caller that needs only the refusal.
pub(crate) fn check(
    terms: &Terms,
    declaration: &ValueDeclaration,
    native_kas: u64,
) -> Result<(), SdkError> {
    measure(terms, declaration, native_kas).map(|_| ())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::json::terms_from_json;
    use serde_json::json;
    use std::path::Path;

    fn terms(file: &str) -> Terms {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
        let path = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(file))
            })
            .unwrap();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        terms_from_json(&doc["terms"]).unwrap()
    }

    fn decl(v: Value) -> ValueDeclaration {
        declaration_from_json(&v).unwrap()
    }

    /// `super::check` for a call that moves no native KAS beside the terms' legs.
    fn check(terms: &Terms, declaration: &ValueDeclaration) -> Result<(), SdkError> {
        super::check(terms, declaration, 0)
    }

    fn code(r: Result<(), SdkError>) -> &'static str {
        r.unwrap_err().code()
    }

    /// Vector 02: a KCC-20 asset against native KAS cash.
    fn kas_cash(amount: u64) -> Terms {
        let mut t = terms("02-");
        t.cash_leg.amount = amount;
        t
    }

    #[test]
    fn the_default_cap_is_ten_kas_and_a_declaration_is_required() {
        let t = kas_cash(1_000_000_000);
        // Control: a nonzero declaration within the cap, the KAS leg exactly at it.
        assert_eq!(check(&t, &decl(json!({ "kas_equivalent": "1" }))), Ok(()));
        // One sompi over the cap.
        let over = kas_cash(1_000_000_001);
        assert_eq!(
            code(check(&over, &decl(json!({ "kas_equivalent": "1" })))),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        // No declaration, and a declared 0, are no value: the asset leg is a token.
        assert_eq!(code(check(&t, &decl(json!({})))), "SDK_VALUE_UNKNOWN");
        assert_eq!(
            code(check(&t, &decl(json!({ "kas_equivalent": "0" })))),
            "SDK_VALUE_UNKNOWN"
        );
    }

    #[test]
    fn a_declaration_raises_the_value_and_never_lowers_a_kas_leg() {
        let small = kas_cash(1);
        let at_cap = decl(json!({ "kas_equivalent": "1000000000" }));
        let over = decl(json!({ "kas_equivalent": "1000000001" }));
        assert_eq!(check(&small, &at_cap), Ok(()));
        assert_eq!(code(check(&small, &over)), "SDK_VALUE_CAP_EXCEEDED");
        let big = kas_cash(1_000_000_001);
        assert_eq!(
            code(check(&big, &decl(json!({ "kas_equivalent": "1" })))),
            "SDK_VALUE_CAP_EXCEEDED"
        );
    }

    #[test]
    fn every_token_trade_needs_a_declaration() {
        // Vector 01: KCC-20 against KCC-20.
        let t = terms("01-");
        assert_eq!(code(check(&t, &decl(json!({})))), "SDK_VALUE_UNKNOWN");
        assert_eq!(
            check(&t, &decl(json!({ "kas_equivalent": "5" }))),
            Ok(()),
            "control"
        );
    }

    #[test]
    fn max_value_only_lowers_the_cap() {
        let t = kas_cash(100);
        let lowered = |m: &str| decl(json!({ "kas_equivalent": "1", "max_value": m }));
        assert_eq!(
            check(&t, &lowered("100")),
            Ok(()),
            "control: at the lowered cap"
        );
        assert_eq!(code(check(&t, &lowered("99"))), "SDK_VALUE_CAP_EXCEEDED");
        assert_eq!(
            check(&t, &lowered("1000000000")),
            Ok(()),
            "control: at the default"
        );
        assert_eq!(
            code(check(&t, &lowered("1000000001"))),
            "SDK_VALUE_CAP_INVALID"
        );
    }

    #[test]
    fn only_the_explicit_flag_lifts_the_cap() {
        let huge = kas_cash(5_000_000_000);
        assert_eq!(
            code(check(&huge, &decl(json!({ "kas_equivalent": "1" })))),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        assert_eq!(
            check(&huge, &decl(json!({ "i_accept_the_risk": true }))),
            Ok(())
        );
        // False is no lift.
        assert_eq!(
            code(check(
                &huge,
                &decl(json!({ "kas_equivalent": "1", "i_accept_the_risk": false }))
            )),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        // A lowered cap and the lift contradict each other.
        assert_eq!(
            code(check(
                &huge,
                &decl(json!({ "max_value": "1", "i_accept_the_risk": true }))
            )),
            "SDK_VALUE_CAP_INVALID"
        );
    }

    #[test]
    fn the_native_kas_a_call_moves_counts_as_a_kas_leg() {
        let t = kas_cash(1);
        let small = decl(json!({ "kas_equivalent": "1" }));
        let cap = DEFAULT_MAX_VALUE_SOMPI;
        // Control: exactly the cap passes; one sompi over is refused, whatever is declared.
        assert_eq!(super::check(&t, &small, cap), Ok(()));
        assert_eq!(
            code(super::check(&t, &small, cap + 1)),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        // It only raises the value: a small amount does not lower a larger declaration.
        let declared = decl(json!({ "kas_equivalent": "1000000001" }));
        assert_eq!(
            code(super::check(&t, &declared, 1)),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        // A lowered cap holds it to the lowered cap.
        let lowered = decl(json!({ "kas_equivalent": "1", "max_value": "100" }));
        assert_eq!(super::check(&t, &lowered, 100), Ok(()));
        assert_eq!(
            code(super::check(&t, &lowered, 101)),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        // The flag lifts it.
        let lifted = decl(json!({ "i_accept_the_risk": true }));
        assert_eq!(super::check(&t, &lifted, u64::MAX), Ok(()));
    }

    #[test]
    fn the_funding_instructions_and_the_builders_share_one_rule() {
        let t = kas_cash(100);
        // The funding instructions' parts: a cap as text, the value, the flag.
        let funding = |value: Option<u64>, cap: Option<&str>, accept: bool| {
            let cap = cap.map(cap_from_text).transpose()?;
            measure(&t, &ValueDeclaration::new(value, cap, accept), 0)
        };
        // Measured: the larger of the declaration and the KAS legs, and the cap in force.
        assert_eq!(
            funding(Some(7), Some("100"), false),
            Ok(Some(ValueCheck {
                value: 100,
                cap: 100,
                declared: 7,
                largest_kas_leg: 100
            }))
        );
        // Lifted: nothing measured.
        assert_eq!(funding(None, None, true), Ok(None));
        // The same refusals as the builders' declaration reads.
        for (declared, cap, accept, want) in [
            (Some(1), Some("99"), false, "SDK_VALUE_CAP_EXCEEDED"),
            (Some(1), Some("1000000001"), false, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some("1e9"), false, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some("01"), false, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some("-1"), false, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some(""), false, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some("100"), true, "SDK_VALUE_CAP_INVALID"),
            (Some(1), Some("x"), true, "SDK_VALUE_CAP_INVALID"),
            (Some(0), None, false, "SDK_VALUE_UNKNOWN"),
        ] {
            assert_eq!(
                funding(declared, cap, accept).unwrap_err().code(),
                want,
                "{declared:?} {cap:?} {accept}"
            );
        }
        assert!(funding(Some(1), Some("100"), false).is_ok(), "control");
        // A token trade with no declaration is unknown through either entry.
        let tokens = terms("01-");
        assert_eq!(
            measure(&tokens, &ValueDeclaration::new(None, None, false), 0)
                .unwrap_err()
                .code(),
            "SDK_VALUE_UNKNOWN"
        );
    }

    #[test]
    fn the_declaration_form_is_strict() {
        let refused = |v: Value| declaration_from_json(&v).unwrap_err().code();
        assert_eq!(refused(json!(null)), "SDK_JSON_FORM");
        assert_eq!(refused(json!({ "kas_equivalent": 5 })), "SDK_JSON_FORM");
        assert_eq!(refused(json!({ "kas_equivalent": "05" })), "SDK_JSON_FORM");
        assert_eq!(refused(json!({ "max_value": "-1" })), "SDK_JSON_FORM");
        assert_eq!(
            refused(json!({ "i_accept_the_risk": "yes" })),
            "SDK_JSON_FORM"
        );
        assert_eq!(refused(json!({ "cap": "1" })), "SDK_JSON_FORM");
        assert!(
            declaration_from_json(&json!({ "kas_equivalent": "5" })).is_ok(),
            "control"
        );
    }
}
