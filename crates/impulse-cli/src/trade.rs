// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The two ways the CLI holds a trade, and the only ways it shows a terms hash:
//! [`FundableTrade`] for a trade being created or funded (structure and creation checks, every
//! escrowed leg a [`FundableVault`]), and [`ExistingTrade`] for a trade already made, which may be
//! past its expiry (structure checks, every escrowed leg a [`Vault`]). spec/CLI.md, "Terms draft
//! and terms file".

use crate::error::CliError;
use crate::json::hex;
use impulse_core::template::{FundableVault, LegIndex, TemplateError, Vault};
use impulse_core::terms::{CreationContext, Kcc20Token, LegKind, Terms, ValidatedTerms};
use impulse_core::tx::MIN_KAS_OUTPUT;
use impulse_core::verify::{pinned_kcc20, TemplateTriple};

/// One leg's instantiation result: only `TEMPLATE_NO_VAULT` (the terms escrow nothing on that leg)
/// reads as no vault; any other refusal refuses the trade.
fn leg_or_none<T>(made: Result<T, TemplateError>) -> Result<Option<T>, CliError> {
    match made {
        Ok(v) => Ok(Some(v)),
        Err(TemplateError::NoVault { .. }) => Ok(None),
        Err(e) => Err(CliError::from(e)),
    }
}

/// Terms that passed the structure and creation checks, with the fundable vault of every leg the
/// terms escrow. A leg the terms do not escrow (Direct terms, external cash) has `None`.
#[derive(Debug)]
pub struct FundableTrade {
    terms: ValidatedTerms,
    asset: Option<FundableVault>,
    cash: Option<FundableVault>,
}

impl FundableTrade {
    /// Instantiates both legs through the creation path before returning anything. Only a
    /// `TEMPLATE_NO_VAULT` refusal (the terms escrow nothing on that leg) leaves a leg empty; any
    /// other refusal on either leg refuses the trade.
    pub fn new(terms: ValidatedTerms, ctx: &CreationContext) -> Result<Self, CliError> {
        // The creation checks run whatever the legs are, so Direct terms are checked too.
        terms.validate_creation(ctx)?;
        let leg = |leg| {
            leg_or_none(
                fail::injected(leg)
                    .map_or_else(|| Vault::instantiate_for_creation(&terms, leg, ctx), Err),
            )
        };
        let asset = leg(LegIndex::Asset)?;
        let cash = leg(LegIndex::Cash)?;
        Ok(Self { terms, asset, cash })
    }

    pub fn terms(&self) -> &ValidatedTerms {
        &self.terms
    }

    /// The fundable vault of `leg`, if the terms escrow it.
    pub fn vault(&self, leg: LegIndex) -> Option<&FundableVault> {
        match leg {
            LegIndex::Asset => self.asset.as_ref(),
            LegIndex::Cash => self.cash.as_ref(),
        }
    }
}

/// A trade already made: structure-checked terms whose escrowed legs all instantiate as vaults,
/// with no creation checks, so a trade past its expiry still qualifies (status, refunds). It has
/// no funding address.
#[derive(Debug)]
pub struct ExistingTrade {
    terms: ValidatedTerms,
    asset: Option<Vault>,
    cash: Option<Vault>,
}

impl ExistingTrade {
    /// Instantiates both legs before returning anything, with the same rule as
    /// [`FundableTrade::new`]: only `TEMPLATE_NO_VAULT` leaves a leg empty.
    pub fn new(terms: ValidatedTerms) -> Result<Self, CliError> {
        let leg = |leg| {
            leg_or_none(
                fail::injected(leg).map_or_else(|| Vault::instantiate_existing(&terms, leg), Err),
            )
        };
        let asset = leg(LegIndex::Asset)?;
        let cash = leg(LegIndex::Cash)?;
        Ok(Self { terms, asset, cash })
    }

    pub fn terms(&self) -> &ValidatedTerms {
        &self.terms
    }

    /// The vault of `leg`, if the terms escrow it.
    pub fn vault(&self, leg: LegIndex) -> Option<&Vault> {
        match leg {
            LegIndex::Asset => self.asset.as_ref(),
            LegIndex::Cash => self.cash.as_ref(),
        }
    }
}

/// Before funding (spec/CLI.md, "Before funding"): a KAS cash leg below `MIN_KAS_OUTPUT` has no
/// standard settle, so terms with one are refused before anyone funds (`CLI_KAS_LEG_BELOW_MIN`).
pub fn check_kas_minimum(t: &Terms) -> Result<(), CliError> {
    if t.cash_leg.kind == LegKind::Kas && t.cash_leg.amount < MIN_KAS_OUTPUT {
        return Err(CliError::new(
            "CLI_KAS_LEG_BELOW_MIN",
            format!(
                "the KAS cash leg is {} sompi, below the minimum of {MIN_KAS_OUTPUT} (spec/TRANSACTIONS.md, \"Minimum KAS per leg\"): a settle must pay exactly this amount in one output, which the minimum-KAS rule does not cover, and fund_kas refuses to fund it; do not fund these terms",
                t.cash_leg.amount
            ),
        ));
    }
    Ok(())
}

/// The KCC-20 legs whose template is not a pinned kcc20.sil build.
fn unpinned(t: &Terms) -> Vec<(LegIndex, Kcc20Token)> {
    [
        (LegIndex::Asset, &t.asset_leg),
        (LegIndex::Cash, &t.cash_leg),
    ]
    .into_iter()
    .filter_map(|(leg, l)| match l.kind {
        LegKind::Kcc20(token) if pinned_kcc20(&TemplateTriple::from(&token)).is_none() => {
            Some((leg, token))
        }
        _ => None,
    })
    .collect()
}

fn unpinned_text(leg: LegIndex, token: &Kcc20Token) -> String {
    format!(
        "the {} leg's KCC-20 template {} ({}+{}) is not a pinned kcc20.sil build (silverscript v1.0.0): the builders' compute budgets are measured for kcc20.sil only, so a settle or refund of this token may fail and leave it escrowed",
        leg_name(leg),
        hex(&token.template_hash),
        token.template_prefix_len,
        token.template_suffix_len
    )
}

/// The `warning:` lines `terms new` prints for unpinned templates; `address`, `verify`,
/// `fund build` and `ipst sign` of a funding refuse such terms (`check_pinned`).
pub fn template_warnings(t: &Terms) -> Vec<String> {
    unpinned(t)
        .iter()
        .map(|(leg, token)| format!("warning: {}", unpinned_text(*leg, token)))
        .collect()
}

/// `fund build` and `ipst sign` of a funding refuse terms with an unpinned KCC-20 template
/// (`CLI_TEMPLATE_UNPINNED`).
pub fn check_pinned(t: &Terms) -> Result<(), CliError> {
    match unpinned(t).first() {
        Some((leg, token)) => Err(CliError::new(
            "CLI_TEMPLATE_UNPINNED",
            format!("{}; such tokens are outside v1", unpinned_text(*leg, token)),
        )),
        None => Ok(()),
    }
}

/// "asset" or "cash".
pub fn leg_name(leg: LegIndex) -> &'static str {
    match leg {
        LegIndex::Asset => "asset",
        LegIndex::Cash => "cash",
    }
}

/// Test seam: makes one leg's instantiation fail with a chosen refusal, per test thread, so the
/// fail-closed rule is tested for refusals the golden terms cannot produce. Not compiled outside
/// tests.
pub(crate) mod fail {
    use impulse_core::template::{LegIndex, TemplateError};

    #[cfg(test)]
    thread_local! {
        static NEXT: std::cell::RefCell<Option<(LegIndex, TemplateError)>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Every instantiation of `leg` on this thread fails with `e` until [`clear`].
    #[cfg(test)]
    pub(crate) fn set(leg: LegIndex, e: TemplateError) {
        NEXT.with(|n| *n.borrow_mut() = Some((leg, e)));
    }

    #[cfg(test)]
    pub(crate) fn clear() {
        NEXT.with(|n| *n.borrow_mut() = None);
    }

    #[cfg(test)]
    pub(super) fn injected(leg: LegIndex) -> Option<TemplateError> {
        NEXT.with(|n| {
            n.borrow()
                .as_ref()
                .filter(|(l, _)| *l == leg)
                .map(|(_, e)| e.clone())
        })
    }

    #[cfg(not(test))]
    pub(super) fn injected(_leg: LegIndex) -> Option<TemplateError> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms_file::parse_terms_file;
    use crate::terms_file::tests::{vector_file, vector_terms_files};
    use impulse_core::terms::Network;

    pub(crate) const CREATION_DAA: u64 = 400_000_000;

    fn ctx(t: &ValidatedTerms) -> CreationContext {
        CreationContext::new(t.terms().network, CREATION_DAA)
    }

    #[test]
    fn every_vector_is_a_fundable_trade_with_the_expected_vaults() {
        for (name, text) in vector_terms_files() {
            let terms = parse_terms_file(&text).unwrap();
            let ctx = ctx(&terms);
            let trade = FundableTrade::new(terms, &ctx).unwrap_or_else(|e| panic!("{name}: {e}"));
            let direct = name.contains("direct");
            let external = name.contains("external");
            assert_eq!(trade.vault(LegIndex::Asset).is_some(), !direct, "{name}");
            assert_eq!(
                trade.vault(LegIndex::Cash).is_some(),
                !direct && !external,
                "{name}"
            );
        }
    }

    #[test]
    fn every_vector_is_an_existing_trade_with_the_same_vaults() {
        for (name, text) in vector_terms_files() {
            let terms = parse_terms_file(&text).unwrap();
            let fundable = FundableTrade::new(terms.clone(), &ctx(&terms)).unwrap();
            let existing = ExistingTrade::new(terms).unwrap();
            for leg in LegIndex::ALL {
                assert_eq!(
                    existing.vault(leg),
                    fundable.vault(leg).map(FundableVault::vault),
                    "{name} {leg:?}"
                );
            }
        }
    }

    #[test]
    fn creation_checks_refuse_before_any_vault() {
        let terms = parse_terms_file(&vector_file("02-")).unwrap();
        let control = CreationContext::new(Network::Mainnet, CREATION_DAA);
        assert!(
            FundableTrade::new(terms.clone(), &control).is_ok(),
            "control"
        );
        let wrong_net = CreationContext::new(Network::Testnet, CREATION_DAA);
        assert_eq!(
            FundableTrade::new(terms.clone(), &wrong_net)
                .unwrap_err()
                .code(),
            "TERMS_NETWORK_MISMATCH"
        );
        let expired = CreationContext::new(Network::Mainnet, terms.terms().expiry_daa);
        assert_eq!(
            FundableTrade::new(terms.clone(), &expired)
                .unwrap_err()
                .code(),
            "TERMS_EXPIRY_NOT_AFTER_CREATION"
        );
        // An existing trade has no creation checks: past its expiry it still has its vaults.
        let existing = ExistingTrade::new(terms).unwrap();
        assert!(existing.vault(LegIndex::Asset).is_some());
    }

    #[test]
    fn direct_terms_still_run_the_creation_checks() {
        let terms = parse_terms_file(&vector_file("07-")).unwrap();
        let control = ctx(&terms);
        assert!(
            FundableTrade::new(terms.clone(), &control).is_ok(),
            "control"
        );
        let late = CreationContext::new(terms.terms().network, terms.terms().expiry_daa);
        assert_eq!(
            FundableTrade::new(terms, &late).unwrap_err().code(),
            "TERMS_EXPIRY_NOT_AFTER_CREATION"
        );
    }

    /// The refusals the fail-closed rule must pass through, other than TEMPLATE_NO_VAULT.
    fn refusals() -> [TemplateError; 2] {
        [
            TemplateError::StateInvalid { field: "amount" },
            TemplateError::StateMalformed {
                reason: "injected".into(),
            },
        ]
    }

    #[test]
    fn any_other_refusal_on_either_leg_refuses_the_trade() {
        // Vector 02 escrows both legs.
        let terms = parse_terms_file(&vector_file("02-")).unwrap();
        let ctx = ctx(&terms);
        for leg in LegIndex::ALL {
            for e in refusals() {
                let code = e.code();
                fail::set(leg, e);
                let fundable = FundableTrade::new(terms.clone(), &ctx);
                let existing = ExistingTrade::new(terms.clone());
                fail::clear();
                assert_eq!(fundable.unwrap_err().code(), code, "fundable {leg:?}");
                assert_eq!(existing.unwrap_err().code(), code, "existing {leg:?}");
            }
            // TEMPLATE_NO_VAULT on that leg is no vault, not a refusal.
            fail::set(
                leg,
                TemplateError::NoVault {
                    leg,
                    reason: "injected",
                },
            );
            let fundable = FundableTrade::new(terms.clone(), &ctx).unwrap();
            let existing = ExistingTrade::new(terms.clone()).unwrap();
            fail::clear();
            assert!(fundable.vault(leg).is_none());
            assert!(existing.vault(leg).is_none());
        }
        assert!(FundableTrade::new(terms.clone(), &ctx).is_ok(), "control");
        assert!(ExistingTrade::new(terms).is_ok(), "control");
    }
}
