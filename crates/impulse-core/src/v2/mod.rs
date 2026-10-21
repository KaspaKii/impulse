// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Impulse v0.2 basket settlement (spec/V2.md sections 4 to 9): terms v2 (an ordered list of 2 to
//! `MAX_LEGS` legs, tag `Impulse/terms/v2`), the ImpulseVault v2 template (instantiation, decode,
//! addresses), the keyless N-leg builders (fund, final settle, per-leg refund) with their
//! partially signed transaction of version 2, and the v2 verifier.
//!
//! Version 1 is untouched: nothing here reads, re-encodes or migrates a v1 trade, and the v1
//! modules keep their codes, vectors and template (spec/V2.md section 2). v0.2 codes are appended
//! to the same families in spec/ERRORS.md and listed here in their own frozen lists, so the v1
//! lists (and the SDK that exposes them) do not change.
//!
//! Keyless by rule (rule 1, docs/ENGINEERING-RULES.md): nothing in this module signs, holds or derives a private
//! key. Builders return unsigned transactions with one sighash per signature slot; signatures
//! arrive as 65-byte values and are verified before they are used.
//!
//! Scope: I16 built the final settle; I17 adds the tranche settle ([`settle_tranche`]), the KIP-20
//! genesis funding of partial terms (one genesis group per leg) and the readers of a settle
//! transaction (`receipt`) that tranche receipts are made from.

mod error;
mod ipst;
mod receipt;
mod template;
mod terms;
mod tx;
mod verify;

#[cfg(test)]
mod golden;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use error::{
    V2Error, TEMPLATE_V2_ERROR_CODES, TERMS_V2_ERROR_CODES, TX_V2_ERROR_CODES,
    VERIFY_V2_ERROR_CODES,
};
pub use ipst::{read_ipst, AnyIpst, IpstV2, IPST_V2_VERSION};
pub use receipt::{
    quantities, read_settle, verify_genesis, LegQuantity, LegSettle, SettleFacts, SETTLE_TAG_V2,
};
pub use template::{
    check as check_template, decode as decode_vault, template_hash_of_instance, vault_address,
    FundableVaultV2, TemplateV2, VaultV2, CONTRACT_NAME,
};
pub use terms::{
    decode_any, AnyTerms, DestinationV2, LegV2, Partial, TermsV2, ValidatedTermsV2, LEG_RECORD,
    MAX_LEGS, TERMS_V2_HASH_DOMAIN, TERMS_V2_VERSION,
};
pub use tx::{
    caps, fund_kas, fund_kcc20, kas_destination, min_v2, min_vault_v2, refund, refund_budget,
    settle, settle_budget, settle_tranche, tranche_budget, IpstV2Kind, MassCaps, RefundSignerV2,
    SettleLeg, TermsMatchV2, TokenEscrow, CAP_V2_RESERVE_PERCENT, PRE_TOCCATA_MASS_CAP,
};
pub use verify::{
    check_vault_utxos, verify_addresses, verify_revealed_script, verify_spent_input,
    VaultUtxoWarning, VerifiedAddressV2,
};
