// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Funding URIs (spec/CLI.md, "Funding URI"): `<vault address>?amount=<sompi>&impulse=<terms
//! hash>`, for a leg whose vault holds native KAS. Built only from a [`FundableTrade`]; checked
//! against one in a fixed order.

use crate::error::CliError;
use crate::json::{hex, parse_dec, unhex32};
use crate::trade::{leg_name, FundableTrade};
use impulse_core::address::vault_address;
use impulse_core::template::LegIndex;
use impulse_core::terms::LegKind;
use kaspa_addresses::Address;

/// A funding URI split into its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingUri {
    pub address: String,
    pub amount: u64,
    pub terms_hash: [u8; 32],
}

/// The funding URI of `leg`, if the terms escrow it and it holds native KAS.
pub fn funding_uri(trade: &FundableTrade, leg: LegIndex) -> Option<String> {
    let vault = trade.vault(leg)?;
    let t = trade.terms().terms();
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    (leg_terms.kind == LegKind::Kas).then(|| {
        format!(
            "{}?amount={}&impulse={}",
            vault_address(vault),
            leg_terms.amount,
            hex(&trade.terms().terms_hash())
        )
    })
}

/// Parses the exact URI form; anything else is `CLI_URI_MALFORMED`.
pub fn parse(uri: &str) -> Result<FundingUri, CliError> {
    let malformed = |why: &str| CliError::new("CLI_URI_MALFORMED", why.to_string());
    let (address, query) = uri
        .split_once('?')
        .ok_or_else(|| malformed("no query part"))?;
    let parsed = Address::try_from(address).map_err(|_| malformed("the address does not parse"))?;
    if parsed.to_string() != address {
        return Err(malformed("the address is not in canonical form"));
    }
    let rest = query
        .strip_prefix("amount=")
        .ok_or_else(|| malformed("the query must start with amount="))?;
    let (amount, hash) = rest
        .split_once("&impulse=")
        .ok_or_else(|| malformed("the query must be amount=<sompi>&impulse=<terms hash>"))?;
    let amount =
        parse_dec(amount).ok_or_else(|| malformed("amount is not a decimal number of sompi"))?;
    let terms_hash =
        unhex32(hash).ok_or_else(|| malformed("impulse is not 64 lowercase hex digits"))?;
    Ok(FundingUri {
        address: address.to_string(),
        amount,
        terms_hash,
    })
}

/// Checks `uri` against the trade: form, terms hash, address, leg kind, amount. Returns the leg
/// it funds.
pub fn verify(uri: &str, trade: &FundableTrade) -> Result<LegIndex, CliError> {
    let parsed = parse(uri)?;
    let terms_hash = trade.terms().terms_hash();
    if parsed.terms_hash != terms_hash {
        return Err(CliError::new(
            "CLI_URI_TERMS_HASH_MISMATCH",
            format!(
                "the URI names terms {}, the terms file hashes to {}",
                hex(&parsed.terms_hash),
                hex(&terms_hash)
            ),
        ));
    }
    let leg = LegIndex::ALL
        .into_iter()
        .find(|leg| {
            trade
                .vault(*leg)
                .is_some_and(|v| vault_address(v) == parsed.address)
        })
        .ok_or_else(|| {
            CliError::new(
                "CLI_URI_ADDRESS_MISMATCH",
                format!("{} is not a vault of these terms", parsed.address),
            )
        })?;
    let t = trade.terms().terms();
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    if leg_terms.kind != LegKind::Kas {
        return Err(CliError::new(
            "CLI_URI_LEG_NOT_KAS",
            format!(
                "the {} vault escrows a KCC-20 token, which a funding URI cannot carry",
                leg_name(leg)
            ),
        ));
    }
    if parsed.amount != leg_terms.amount {
        return Err(CliError::new(
            "CLI_URI_AMOUNT_MISMATCH",
            format!(
                "the URI asks for {} sompi, the {} leg is exactly {} sompi",
                parsed.amount,
                leg_name(leg),
                leg_terms.amount
            ),
        ));
    }
    Ok(leg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms_file::parse_terms_file;
    use crate::terms_file::tests::{vector_file, vector_terms_files};
    use impulse_core::terms::CreationContext;

    fn trade(prefix: &str) -> FundableTrade {
        let terms = parse_terms_file(&vector_file(prefix)).unwrap();
        let ctx = CreationContext::new(terms.terms().network, 400_000_000);
        FundableTrade::new(terms, &ctx).unwrap()
    }

    #[test]
    fn uris_exist_exactly_for_kas_legs_and_verify() {
        let mut seen = 0;
        for (name, text) in vector_terms_files() {
            let terms = parse_terms_file(&text).unwrap();
            let ctx = CreationContext::new(terms.terms().network, 400_000_000);
            let trade = FundableTrade::new(terms, &ctx).unwrap();
            for leg in LegIndex::ALL {
                let kas = trade.vault(leg).is_some()
                    && leg == LegIndex::Cash
                    && trade.terms().terms().cash_leg.kind == LegKind::Kas;
                let uri = funding_uri(&trade, leg);
                assert_eq!(uri.is_some(), kas, "{name} {leg:?}");
                if let Some(uri) = uri {
                    assert_eq!(verify(&uri, &trade), Ok(leg), "{name}");
                    seen += 1;
                }
            }
        }
        assert!(seen >= 3, "mainnet and testnet KAS legs are covered");
    }

    #[test]
    fn the_uri_has_the_brief_form() {
        let t = trade("04-");
        let uri = funding_uri(&t, LegIndex::Cash).unwrap();
        let vault = vault_address(t.vault(LegIndex::Cash).unwrap());
        assert!(vault.starts_with("kaspa:p"));
        assert_eq!(
            uri,
            format!(
                "{vault}?amount={}&impulse={}",
                t.terms().terms().cash_leg.amount,
                hex(&t.terms().terms_hash())
            )
        );
        let testnet = trade("08-");
        assert!(funding_uri(&testnet, LegIndex::Cash)
            .unwrap()
            .starts_with("kaspatest:p"));
    }

    #[test]
    fn each_refusal_has_its_code() {
        let t = trade("04-");
        let good = funding_uri(&t, LegIndex::Cash).unwrap();
        assert_eq!(verify(&good, &t), Ok(LegIndex::Cash), "control");
        let (addr, _) = good.split_once('?').unwrap();
        let amount = t.terms().terms().cash_leg.amount;
        let hash = hex(&t.terms().terms_hash());
        let asset_addr = vault_address(t.vault(LegIndex::Asset).unwrap());
        let other = trade("02-");
        let other_addr = vault_address(other.vault(LegIndex::Cash).unwrap());
        let cases = [
            (addr.to_string(), "CLI_URI_MALFORMED"),
            (
                format!("{addr}?impulse={hash}&amount={amount}"),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{addr}?amount=0{amount}&impulse={hash}"),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{addr}?amount={amount}&impulse={}", hash.to_uppercase()),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{addr}?amount={amount}&impulse={hash}&x=1"),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{addr}?amount={amount}&impulse={hash}#f"),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{}?amount={amount}&impulse={hash}", addr.to_uppercase()),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("kaspa:nonsense?amount={amount}&impulse={hash}"),
                "CLI_URI_MALFORMED",
            ),
            (
                format!("{addr}?amount={amount}&impulse={}", "0".repeat(64)),
                "CLI_URI_TERMS_HASH_MISMATCH",
            ),
            (
                format!("{other_addr}?amount={amount}&impulse={hash}"),
                "CLI_URI_ADDRESS_MISMATCH",
            ),
            (
                format!("{asset_addr}?amount={amount}&impulse={hash}"),
                "CLI_URI_LEG_NOT_KAS",
            ),
            (
                format!("{addr}?amount={}&impulse={hash}", amount + 1),
                "CLI_URI_AMOUNT_MISMATCH",
            ),
            (
                format!("{addr}?amount={}&impulse={hash}", amount - 1),
                "CLI_URI_AMOUNT_MISMATCH",
            ),
        ];
        for (uri, code) in cases {
            assert_eq!(verify(&uri, &t).unwrap_err().code(), code, "{uri}");
        }
    }

    /// Review round 2: an address that decodes to the vault's but is not its canonical text.
    #[test]
    fn a_noncanonical_address_is_malformed() {
        let t = trade("04-");
        let good = funding_uri(&t, LegIndex::Cash).unwrap();
        let (addr, query) = good.split_once('?').unwrap();
        let other = crate::testutil::noncanonical_address(addr);
        assert_eq!(
            Address::try_from(other.as_str()).unwrap().to_string(),
            addr,
            "decodes to the vault address"
        );
        let e = verify(&format!("{other}?{query}"), &t).unwrap_err();
        assert_eq!(e.code(), "CLI_URI_MALFORMED");
        assert!(e.to_string().contains("canonical form"), "{e}");
        assert_eq!(verify(&good, &t), Ok(LegIndex::Cash), "control");
    }

    #[test]
    fn the_hash_is_checked_before_the_address() {
        // A URI for another trade fails on the terms hash, the first semantic check.
        let t = trade("04-");
        let other = trade("02-");
        let uri = funding_uri(&other, LegIndex::Cash).unwrap();
        assert_eq!(
            verify(&uri, &t).unwrap_err().code(),
            "CLI_URI_TERMS_HASH_MISMATCH"
        );
    }
}
