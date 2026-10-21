// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The return gate (spec/V2.md 17.6): evidence that the opening settled, without which the
//! return builders refuse. The evidence is a transaction whose inputs 0 and 1 spend the two
//! opening vaults through the contract's `settle` entry. Whether the chain accepted it, and how
//! deep, is the caller's to read from a node; this module only reads the transaction.

use super::{LinkedError, Role, ValidatedLinked};
use crate::decode::pushes;
use crate::v2::verify_spent_input;
use kaspa_consensus_core::hashing;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction};
use std::sync::LazyLock;

/// The compiled ImpulseVault v2, read for the `settle` dispatch tag (the same file
/// `impulse_core::v2` embeds and checks against `TEMPLATE_HASH_V2`).
const ARTIFACT_JSON: &str = include_str!("../../../../contracts/compiled/impulse_vault.v2.json");

/// The dispatch tag of the `settle` entry of the pinned v2 artifact.
pub fn settle_tag() -> [u8; 4] {
    static TAG: LazyLock<[u8; 4]> = LazyLock::new(|| {
        let artifact: serde_json::Value =
            serde_json::from_str(ARTIFACT_JSON).expect("the embedded v2 artifact is JSON");
        let hex = artifact["contracts"]["ImpulseVaultV2"]["entries"]["settle"]["dispatch_tag"]
            .as_str()
            .expect("the v2 artifact names the settle dispatch tag");
        let mut tag = [0u8; 4];
        for (i, byte) in tag.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex tag");
        }
        tag
    });
    *TAG
}

/// Evidence that the opening of one sheet settled: made only by [`check_opening_settled`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpeningSettled {
    linked_hash: [u8; 32],
    txid: [u8; 32],
}

impl OpeningSettled {
    /// The sheet this evidence is for.
    pub fn linked_hash(&self) -> [u8; 32] {
        self.linked_hash
    }

    /// The transaction ID of the settle, recomputed from its contents.
    pub fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// The evidence is for `linked`'s sheet (`LINKED_OPENING_NOT_SETTLED` if not).
    pub fn check_for(&self, linked: &ValidatedLinked) -> Result<(), LinkedError> {
        if self.linked_hash == linked.linked_hash() {
            Ok(())
        } else {
            Err(LinkedError::OpeningNotSettled)
        }
    }
}

/// Reads `tx` as a settle of `role`'s trade of `linked`: input 0 and input 1 each reveal the
/// vault script of that trade's leg 0 and leg 1 (section 7's `verify_spent_input`, bound to the
/// UTXO the input spent, `spent[i]`, as the node reports it) and call `settle`. Returns the
/// transaction ID recomputed from the contents. Anything else is `LINKED_SETTLE_EVIDENCE`.
/// Whether the chain accepted the transaction is the caller's to read from a node.
pub fn check_settled(
    linked: &ValidatedLinked,
    role: Role,
    tx: &Transaction,
    spent: &[ScriptPublicKey],
) -> Result<[u8; 32], LinkedError> {
    const NOT_VAULT: [&str; 2] = [
        "input 0 does not spend the vault of leg 0 of this trade",
        "input 1 does not spend the vault of leg 1 of this trade",
    ];
    const NOT_SETTLE: [&str; 2] = [
        "input 0 does not call the settle entry",
        "input 1 does not call the settle entry",
    ];
    let evidence = |reason| LinkedError::SettleEvidence { role, reason };
    if tx.inputs.len() < 2 || spent.len() < tx.inputs.len() {
        return Err(evidence(
            "the transaction has fewer than two inputs, or the spent scripts are missing",
        ));
    }
    for leg in 0..2 {
        let input = &tx.inputs[leg];
        verify_spent_input(linked.terms(role), leg, input, &spent[leg])
            .map_err(|_| evidence(NOT_VAULT[leg]))?;
        let called = pushes(&input.signature_script)
            .and_then(|p| p.iter().rev().nth(1).copied().flatten().map(<[u8]>::to_vec));
        if called.as_deref() != Some(&settle_tag()[..]) {
            return Err(evidence(NOT_SETTLE[leg]));
        }
    }
    Ok(hashing::tx::id(tx).as_bytes())
}

/// [`check_settled`] for the opening: the evidence the return builders need.
pub fn check_opening_settled(
    linked: &ValidatedLinked,
    tx: &Transaction,
    spent: &[ScriptPublicKey],
) -> Result<OpeningSettled, LinkedError> {
    let txid = check_settled(linked, Role::Opening, tx, spent)?;
    Ok(OpeningSettled {
        linked_hash: linked.linked_hash(),
        txid,
    })
}
