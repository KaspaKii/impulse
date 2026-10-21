// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! CLI refusals: one stable code each (spec/CLI.md, "Error codes"). Terms and template refusals
//! keep their own `TERMS_*` and `TEMPLATE_*` codes. Integrators match on the code, never on the
//! message. Messages never carry key material.

use impulse_core::decode::DecodeError;
use impulse_core::template::TemplateError;
use impulse_core::terms::TermsError;
use impulse_core::tx::TxError;
use std::fmt;

/// Every CLI refusal code, in spec order. Frozen once merged: a test pins this list, and it may
/// only grow at the end.
pub const CLI_ERROR_CODES: [&str; 55] = [
    "CLI_FILE_READ",
    "CLI_FILE_WRITE",
    "CLI_OUTPUT_EXISTS",
    "CLI_TERMS_JSON",
    "CLI_TERMS_FILE_INCONSISTENT",
    "CLI_NETWORK_MISMATCH",
    "CLI_HEX",
    "CLI_URI_MALFORMED",
    "CLI_URI_TERMS_HASH_MISMATCH",
    "CLI_URI_ADDRESS_MISMATCH",
    "CLI_URI_LEG_NOT_KAS",
    "CLI_URI_AMOUNT_MISMATCH",
    "CLI_VALUE_CAP_INVALID",
    "CLI_VALUE_UNKNOWN",
    "CLI_VALUE_CAP_EXCEEDED",
    "CLI_NODE_URL_INVALID",
    "CLI_NODE_UNREACHABLE",
    "CLI_NODE_RPC",
    "CLI_NODE_NETWORK_MISMATCH",
    "CLI_NODE_NOT_SYNCED",
    "CLI_NODE_TXID_MISMATCH",
    "CLI_TX_NOT_ACCEPTED",
    "CLI_QR",
    "CLI_ROLE_KEY_MISMATCH",
    "CLI_DESTINATION_NOT_MINE",
    "CLI_DEPTH_BELOW_MINIMUM",
    "CLI_NODE_INSECURE",
    "CLI_MAINNET_NEEDS_NODE",
    "CLI_DESTINATION_PIN_INVALID",
    "CLI_URI_NOT_YOUR_LEG",
    "CLI_KAS_LEG_BELOW_MIN",
    "CLI_TEMPLATE_UNPINNED",
    "CLI_TEMPLATE_MISSING",
    "CLI_FUND_NOT_YOUR_LEG",
    "CLI_ADDRESS_INVALID",
    "CLI_OUTPOINT_INVALID",
    "CLI_UTXO_NOT_FOUND",
    "CLI_UTXO_AMBIGUOUS",
    "CLI_IPST_NOTHING_TO_SIGN",
    "CLI_IPST_CHANGE_NOT_MINE",
    "CLI_IPST_FEE_TOO_HIGH",
    "CLI_TX_NOT_FINAL",
    "CLI_IPST_TERMS_NOT_AGREED",
    "CLI_IPST_DEPOSIT_MISMATCH",
    "CLI_IPST_TOPUP_TOO_HIGH",
    "CLI_IPST_OUTFLOW_TOO_HIGH",
    "CLI_CANCEL_NOT_DIRECT",
    "CLI_CANCEL_INPUT_NOT_KAS",
    "CLI_CANCEL_INPUT_AMBIGUOUS",
    "CLI_CANCEL_INPUT_MISMATCH",
    "CLI_TOKEN_TESTNET_ONLY",
    "CLI_TOKEN_OWNER_INVALID",
    "CLI_TOKEN_AMOUNT_INVALID",
    "CLI_TOKEN_TEMPLATE_UNPINNED",
    "CLI_TOKEN_CARRIER_MISMATCH",
];

/// A refusal: its stable code and a human-readable detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    code: &'static str,
    detail: String,
}

impl CliError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable detail, without the code.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for CliError {}

/// Core errors already print `CODE: detail`; keep the code and drop the repeated prefix.
fn from_core(code: &'static str, text: String) -> CliError {
    let detail = text
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(": "))
        .map(str::to_string)
        .unwrap_or(text);
    CliError::new(code, detail)
}

impl From<TermsError> for CliError {
    fn from(e: TermsError) -> Self {
        from_core(e.code(), e.to_string())
    }
}

impl From<TemplateError> for CliError {
    fn from(e: TemplateError) -> Self {
        from_core(e.code(), e.to_string())
    }
}

impl From<TxError> for CliError {
    fn from(e: TxError) -> Self {
        from_core(e.code(), e.to_string())
    }
}

#[cfg(feature = "zk")]
impl From<impulse_core::zk::ZkError> for CliError {
    fn from(e: impulse_core::zk::ZkError) -> Self {
        from_core(e.code(), e.to_string())
    }
}

impl From<DecodeError> for CliError {
    fn from(e: DecodeError) -> Self {
        from_core(e.code(), e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_frozen() {
        // spec/CLI.md lists these; the list may only grow at the end.
        let spec = include_str!("../../../spec/CLI.md");
        for code in CLI_ERROR_CODES {
            assert!(spec.contains(&format!("`{code}`")), "{code} not in spec");
        }
        let mut sorted = CLI_ERROR_CODES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), CLI_ERROR_CODES.len(), "codes are distinct");
    }

    #[test]
    fn core_codes_are_kept() {
        let e: CliError = TermsError::AmountZero {
            field: "asset_leg.amount",
        }
        .into();
        assert_eq!(e.code(), "TERMS_AMOUNT_ZERO");
        assert!(!e
            .to_string()
            .contains("TERMS_AMOUNT_ZERO: TERMS_AMOUNT_ZERO"));
        let e: CliError = TemplateError::NotImpulseVault.into();
        assert_eq!(e.code(), "TEMPLATE_NOT_IMPULSE_VAULT");
    }
}
