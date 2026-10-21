// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Linked trades, an opening and a return described by one sheet (I22, spec/V2.md section 17):
//! the sheet (terms v2 extension `linked`) with its canonical bytes and hash, the derivation of
//! the two ordinary terms v2 trades, the opening evidence the return builders need, the builders
//! by role, and the linked receipt.
//!
//! Nothing here touches terms v2, template v2 or their vectors. Keyless by rule (docs/ENGINEERING-RULES.md rule
//! 1): builders return unsigned transactions; a receipt's signature is made elsewhere and only
//! verified here.

mod error;
mod gate;
mod receipt;
mod sheet;
mod tx;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;

pub use error::{LinkedError, Role, LINKED_ERROR_CODES};
pub use gate::{check_opening_settled, check_settled, settle_tag, OpeningSettled};
pub use receipt::{
    check_pair, LinkedObservation, LinkedReceipt, LINKED_RECEIPT_DOMAIN, LINKED_RECEIPT_LEN,
    LINKED_RECEIPT_VERSION,
};
pub use sheet::{LinkedSheet, ValidatedLinked, LINKED_HASH_DOMAIN, LINKED_VERSION};
