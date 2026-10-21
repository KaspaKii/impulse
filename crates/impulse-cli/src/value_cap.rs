// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The per-trade value cap (spec/CLI.md, "Value cap"). The
//! default is 10 KAS, the default until the owner decides it (decision D4).
//! `IMPULSE_MAX_VALUE` may lower it; only `--i-accept-the-risk` lifts it.

use crate::error::CliError;
use crate::json::parse_dec;
use impulse_core::terms::{LegKind, Terms};
use std::ffi::OsStr;

/// 10 KAS in sompi.
pub const DEFAULT_MAX_VALUE_SOMPI: u64 = 1_000_000_000;

/// The environment variable that lowers the cap, in sompi.
pub const MAX_VALUE_ENV: &str = "IMPULSE_MAX_VALUE";

/// The cap in force, or none when the user accepted the risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapPolicy {
    cap: Option<u64>,
}

impl CapPolicy {
    /// `env` is the value of `IMPULSE_MAX_VALUE`, if set.
    pub fn new(env: Option<&OsStr>, accept_the_risk: bool) -> Result<Self, CliError> {
        if accept_the_risk {
            return Ok(Self { cap: None });
        }
        let Some(raw) = env else {
            return Ok(Self {
                cap: Some(DEFAULT_MAX_VALUE_SOMPI),
            });
        };
        let invalid = |why: &str| CliError::new("CLI_VALUE_CAP_INVALID", why.to_string());
        let value = raw
            .to_str()
            .and_then(parse_dec)
            .ok_or_else(|| invalid("IMPULSE_MAX_VALUE is not a decimal number of sompi"))?;
        if value > DEFAULT_MAX_VALUE_SOMPI {
            return Err(invalid(
                "IMPULSE_MAX_VALUE is above the default cap of 1000000000 sompi; only --i-accept-the-risk lifts it",
            ));
        }
        Ok(Self { cap: Some(value) })
    }

    /// The cap in force, or none when it is lifted.
    pub fn limit(&self) -> Option<u64> {
        self.cap
    }

    /// Refuses a trade above the cap and returns the line that reports the cap used. The value
    /// is the larger of the native KAS legs and the user's declared KAS equivalent. A leg that is
    /// not native KAS (in v1 the asset leg is always a KCC-20 token) has no value the CLI can
    /// know, so the declaration is then required, and a declared 0 is no declaration.
    pub fn check(&self, terms: &Terms, kas_equivalent: Option<u64>) -> Result<String, CliError> {
        let Some(cap) = self.cap else {
            return Ok("value cap: lifted by --i-accept-the-risk".into());
        };
        let legs = [&terms.asset_leg, &terms.cash_leg];
        let all_kas = legs.iter().all(|l| l.kind == LegKind::Kas);
        let kas_max = legs
            .iter()
            .filter(|l| l.kind == LegKind::Kas)
            .map(|l| l.amount)
            .max()
            .unwrap_or(0);
        let declared = match kas_equivalent {
            Some(0) => {
                return Err(CliError::new(
                    "CLI_VALUE_UNKNOWN",
                    "--kas-equivalent 0 declares no value; give the KAS value of the larger leg in sompi",
                ))
            }
            Some(v) => v,
            None if all_kas => 0,
            None => {
                return Err(CliError::new(
                    "CLI_VALUE_UNKNOWN",
                    "a leg is not native KAS, so the trade's value is unknown: pass --kas-equivalent <sompi> (the KAS value of the larger leg) or --i-accept-the-risk",
                ))
            }
        };
        let value = kas_max.max(declared);
        if value > cap {
            return Err(CliError::new(
                "CLI_VALUE_CAP_EXCEEDED",
                format!(
                    "trade value {value} sompi is above the cap of {cap} sompi; pass --i-accept-the-risk to proceed"
                ),
            ));
        }
        Ok(format!(
            "value cap: trade value {value} sompi ({} KAS; declared {declared}, largest KAS leg {kas_max}) is within the cap of {cap} sompi",
            crate::summary::kas(value)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms_file::parse_terms_file;
    use crate::terms_file::tests::vector_file;

    fn terms_with_kas_cash(amount: u64) -> Terms {
        // Vector 02: KCC-20 asset against native KAS cash.
        let mut t = parse_terms_file(&vector_file("02-")).unwrap().into_terms();
        t.cash_leg.amount = amount;
        t
    }

    fn terms_with_token_cash() -> Terms {
        // Vector 01: KCC-20 against KCC-20.
        parse_terms_file(&vector_file("01-")).unwrap().into_terms()
    }

    fn default() -> CapPolicy {
        CapPolicy::new(None, false).unwrap()
    }

    #[test]
    fn the_default_cap_is_ten_kas() {
        let p = default();
        let at_cap = p
            .check(&terms_with_kas_cash(1_000_000_000), Some(1))
            .unwrap();
        assert!(at_cap.contains("trade value 1000000000 sompi"), "{at_cap}");
        assert!(at_cap.contains("cap of 1000000000 sompi"), "{at_cap}");
        assert_eq!(
            p.check(&terms_with_kas_cash(1_000_000_001), Some(1))
                .unwrap_err()
                .code(),
            "CLI_VALUE_CAP_EXCEEDED"
        );
    }

    #[test]
    fn a_declared_value_counts_when_larger() {
        let p = default();
        let t = terms_with_kas_cash(1);
        assert!(p.check(&t, Some(1_000_000_000)).is_ok());
        assert_eq!(
            p.check(&t, Some(1_000_000_001)).unwrap_err().code(),
            "CLI_VALUE_CAP_EXCEEDED"
        );
    }

    #[test]
    fn every_v1_trade_needs_a_declared_value() {
        let p = default();
        // KAS cash: the asset leg is a KCC-20 token whose value the CLI cannot know.
        let kas = terms_with_kas_cash(1);
        assert_eq!(p.check(&kas, None).unwrap_err().code(), "CLI_VALUE_UNKNOWN");
        assert_eq!(
            p.check(&kas, Some(0)).unwrap_err().code(),
            "CLI_VALUE_UNKNOWN"
        );
        assert!(p.check(&kas, Some(5)).is_ok(), "control");
        // Token cash.
        let t = terms_with_token_cash();
        assert_eq!(p.check(&t, None).unwrap_err().code(), "CLI_VALUE_UNKNOWN");
        assert!(p.check(&t, Some(5)).is_ok(), "control");
        assert_eq!(
            p.check(&t, Some(DEFAULT_MAX_VALUE_SOMPI + 1))
                .unwrap_err()
                .code(),
            "CLI_VALUE_CAP_EXCEEDED"
        );
    }

    #[test]
    fn a_declaration_cannot_lower_a_kas_leg() {
        let p = default();
        let t = terms_with_kas_cash(DEFAULT_MAX_VALUE_SOMPI + 1);
        assert_eq!(
            p.check(&t, Some(1)).unwrap_err().code(),
            "CLI_VALUE_CAP_EXCEEDED"
        );
    }

    #[test]
    fn the_env_variable_only_lowers_the_cap() {
        let lowered = CapPolicy::new(Some(OsStr::new("100")), false).unwrap();
        assert!(lowered.check(&terms_with_kas_cash(100), Some(1)).is_ok());
        assert_eq!(
            lowered
                .check(&terms_with_kas_cash(101), Some(1))
                .unwrap_err()
                .code(),
            "CLI_VALUE_CAP_EXCEEDED"
        );
        let at_default = OsStr::new("1000000000");
        assert!(CapPolicy::new(Some(at_default), false).is_ok(), "control");
        for bad in ["1000000001", "", "10 KAS", "-1", "01", "1e9"] {
            assert_eq!(
                CapPolicy::new(Some(OsStr::new(bad)), false)
                    .unwrap_err()
                    .code(),
                "CLI_VALUE_CAP_INVALID",
                "{bad}"
            );
        }
    }

    #[test]
    fn only_the_risk_flag_lifts_the_cap() {
        let lifted = CapPolicy::new(Some(OsStr::new("not a number")), true).unwrap();
        let line = lifted
            .check(&terms_with_kas_cash(u64::MAX >> 2), None)
            .unwrap();
        assert!(line.contains("lifted by --i-accept-the-risk"), "{line}");
        assert!(lifted.check(&terms_with_token_cash(), None).is_ok());
    }
}
