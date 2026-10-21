// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! KCC-20 token evidence (spec/VERIFY.md, "Token warnings"): check that a token leg's compiled
//! template is the one the terms name, then report what the template declares about issuer
//! powers, and which parties the caller knows to hold them, as a structured warning list.
//!
//! The warnings are data read from the artifact and keys supplied, and an empty list is never a
//! statement that a token is safe. The artifact's template triple is checked against the terms,
//! and against a pinned set of kcc20.sil builds ([`PINNED_KCC20_TEMPLATES`]). Its state field
//! names and entry names are not covered by the template hash: for a pinned triple they are
//! known, for any other they are the artifact's own claim (`TOKEN_TEMPLATE_UNPINNED`).

pub use super::pins::PINNED_KCC20_TEMPLATES;
use super::{printable, Party, VerifyError};
use crate::template::LegIndex;
use crate::terms::{Kcc20Token, LegKind, Terms, ValidatedTerms};
use silverscript_abi::{template_hash, SilAbiArtifact, TypeArtifact};
use std::fmt;

/// The KCC-20 state the vault reads from an escrowed token, in order (kcc20.sil at silverscript
/// v1.0.0: `byte[32] ownerIdentifier`, `byte identifierType`, `int amount`, `bool isMinter`).
pub const KCC20_STATE: [&str; 4] = ["ownerIdentifier", "identifierType", "amount", "isMinter"];

/// The longest token artifact read, in bytes of JSON. Longer text is refused unread. The 16
/// pinned kcc20.sil builds are at most 13675 bytes as silverc writes them; tests/engine/verify.rs
/// checks each against this bound.
pub const MAX_TOKEN_ARTIFACT_LEN: usize = 64 * 1024;

/// The entries of the KCC-20 template as silverc v1.0.0 names them: the `transfer` covenant
/// leader and its delegate, through which a vault-owned token moves.
pub const KCC20_ENTRIES: [&str; 2] = ["__delegate", "__leader_transfer"];

fn kcc20_types() -> [TypeArtifact; 4] {
    [
        TypeArtifact::FixedBytes { len: 32 },
        TypeArtifact::Byte,
        TypeArtifact::Int,
        TypeArtifact::Bool,
    ]
}

/// What the caller knows about one token leg's token.
#[derive(Clone, Copy, Debug)]
pub struct TokenEvidence<'a> {
    /// The token template's compiled artifact: silverc JSON, schema 1, exactly one contract.
    /// It must come from the token publisher's reproducible build, never from the counterparty:
    /// its state field names and entry names are not covered by the template hash.
    pub artifact_json: &'a str,
    /// x-only keys the caller knows to hold issuer power over the token, for example the owner
    /// key of a PUBKEY-owned minter UTXO or of a minter controller such as KCC20Minter. Empty
    /// means the issuers are unknown (`TOKEN_ISSUER_UNKNOWN`), not that there are none.
    pub issuer_keys: &'a [[u8; 32]],
}

/// A KCC-20 template as the terms describe it: template hash, prefix and suffix lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateTriple {
    pub hash: [u8; 32],
    pub prefix_len: u64,
    pub suffix_len: u64,
}

impl From<&Kcc20Token> for TemplateTriple {
    fn from(t: &Kcc20Token) -> Self {
        Self {
            hash: t.template_hash,
            prefix_len: t.template_prefix_len.into(),
            suffix_len: t.template_suffix_len.into(),
        }
    }
}

/// A KCC-20 template Impulse recognises: kcc20.sil from silverscript v1.0.0 (commit 3ed9733),
/// compiled with the pinned silverc for one choice of the template constants `maxCovIns` and
/// `maxCovOuts`. tests/engine/verify.rs recompiles every entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedKcc20 {
    pub max_cov_ins: u8,
    pub max_cov_outs: u8,
    pub triple: TemplateTriple,
}

/// The pinned kcc20.sil build with this template triple, if any.
pub fn pinned_kcc20(triple: &TemplateTriple) -> Option<&'static PinnedKcc20> {
    PINNED_KCC20_TEMPLATES.iter().find(|p| p.triple == *triple)
}

impl fmt::Display for TemplateTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash: String = self.hash.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "{hash} ({}+{})", self.prefix_len, self.suffix_len)
    }
}

/// How a party relates to a leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Relation {
    /// Funds the leg: the seller for the asset, the buyer for the cash.
    Depositor,
    /// The other party.
    Counterparty,
    Authority,
}

fn relation(leg: LegIndex, party: Party) -> Relation {
    match (leg, party) {
        (_, Party::Authority) => Relation::Authority,
        (LegIndex::Asset, Party::Seller) | (LegIndex::Cash, Party::Buyer) => Relation::Depositor,
        _ => Relation::Counterparty,
    }
}

/// One warning about one token leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenWarning {
    pub leg: LegIndex,
    pub kind: TokenWarningKind,
}

/// What a warning reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenWarningKind {
    /// No evidence was supplied for this KCC-20 leg: nothing about its issuer powers was read.
    Unassessed,
    /// The state declares the KCC-20 `isMinter` flag. Under kcc20.sil a UTXO with the flag set
    /// is exempt from amount conservation and can create supply and further minters.
    MinterBranch,
    /// Entries other than the KCC-20 transfer leader and delegate, by name, as the artifact
    /// declares them. Only reported for a template outside the pinned set.
    ExtraEntries { entries: Vec<String> },
    /// `party` is among the issuer keys supplied. As counterparty or authority of a KCC-20 leg,
    /// an issuer can make the vault-owned decoy a non-depositor refund needs at no cost to
    /// itself (I3 residual, pinned by `r14_decoy_of_the_full_leg_amount_pays_the_depositor`).
    PartyIsIssuer { party: Party, relation: Relation },
    /// The template triple is not one of [`PINNED_KCC20_TEMPLATES`]. The artifact's state field
    /// names and entry names are then its own unauthenticated claim: they support no statement
    /// about the token, and an artifact can hide entries or state under the same triple.
    TemplateUnpinned,
    /// No issuer keys were supplied, so whether a party issues the token was not examined.
    IssuerUnknown,
    /// Retired (I26), never raised: `TOKEN_FOREIGN_AT_VAULT`, a token of covenant
    /// `covenant_id`, the other leg's own, owned by the script hash of this leg's vault. Every
    /// template now requires the other leg's vault in a settle, so such a token cannot move at
    /// all and there is nothing left to warn about (spec/TRANSACTIONS.md, "A token of another
    /// covenant at a vault"; spec/ERRORS.md, "Retired and changed codes"). The variant and its
    /// code stay, so the frozen list and this enum keep their shape; no Impulse caller builds it.
    ForeignAtVault { covenant_id: [u8; 32] },
}

/// Every token warning code, in declaration order. Frozen once merged: a test pins this list,
/// and it may only grow at the end.
pub const TOKEN_WARNING_CODES: [&str; 7] = [
    "TOKEN_UNASSESSED",
    "TOKEN_MINTER_BRANCH",
    "TOKEN_EXTRA_ENTRIES",
    "TOKEN_PARTY_IS_ISSUER",
    "TOKEN_TEMPLATE_UNPINNED",
    "TOKEN_ISSUER_UNKNOWN",
    "TOKEN_FOREIGN_AT_VAULT",
];

impl TokenWarning {
    /// The stable code for this warning.
    pub fn code(&self) -> &'static str {
        match self.kind {
            TokenWarningKind::Unassessed => "TOKEN_UNASSESSED",
            TokenWarningKind::MinterBranch => "TOKEN_MINTER_BRANCH",
            TokenWarningKind::ExtraEntries { .. } => "TOKEN_EXTRA_ENTRIES",
            TokenWarningKind::PartyIsIssuer { .. } => "TOKEN_PARTY_IS_ISSUER",
            TokenWarningKind::TemplateUnpinned => "TOKEN_TEMPLATE_UNPINNED",
            TokenWarningKind::IssuerUnknown => "TOKEN_ISSUER_UNKNOWN",
            TokenWarningKind::ForeignAtVault { .. } => "TOKEN_FOREIGN_AT_VAULT",
        }
    }
}

impl fmt::Display for TokenWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, leg) = (self.code(), self.leg);
        match &self.kind {
            TokenWarningKind::Unassessed => write!(
                f,
                "{code}: {leg:?} leg token: no evidence supplied, issuer powers not read"
            ),
            TokenWarningKind::MinterBranch => write!(
                f,
                "{code}: {leg:?} leg token state declares the KCC-20 isMinter flag"
            ),
            TokenWarningKind::ExtraEntries { entries } => write!(
                f,
                "{code}: {leg:?} leg token has entries beyond KCC-20 transfer: {}",
                entries.join(", ")
            ),
            TokenWarningKind::PartyIsIssuer { party, relation } => write!(
                f,
                "{code}: {leg:?} leg: the {party:?} ({relation:?}) is among the issuer keys supplied"
            ),
            TokenWarningKind::TemplateUnpinned => write!(
                f,
                "{code}: {leg:?} leg token template is not a pinned kcc20.sil build; its declared state and entries are unauthenticated"
            ),
            TokenWarningKind::IssuerUnknown => write!(
                f,
                "{code}: {leg:?} leg: no issuer keys supplied, so no party was checked as issuer"
            ),
            TokenWarningKind::ForeignAtVault { covenant_id } => write!(
                f,
                "{code}: {leg:?} leg vault: its script hash owns a token of covenant {}, the other leg's; a settle that leaves out the other leg's vault can use it as that leg's escrow, and what it holds above the leg amount goes wherever that settle sends it. Send each leg only to its own vault address",
                covenant_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
        }
    }
}

/// Reads the evidence for each KCC-20 leg, asset leg first.
///
/// A leg that is not KCC-20 takes no evidence (`VERIFY_TOKEN_LEG_KIND`). A KCC-20 leg without
/// evidence is `TOKEN_UNASSESSED`. With evidence, in order, first failure returned: the artifact
/// is at most [`MAX_TOKEN_ARTIFACT_LEN`] bytes, parses, holds exactly one contract, names every
/// state field and entry with 1 to 64 ASCII letters, digits and underscores, has no state field
/// of a type that is or holds a struct, and passes silverscript's consistency check
/// (`VERIFY_TOKEN_ARTIFACT_INVALID`); its template hash and prefix and suffix lengths are the
/// leg's (`VERIFY_TOKEN_TEMPLATE_MISMATCH`); its state begins with the four KCC-20 fields and it
/// has both KCC-20 entries (`VERIFY_TOKEN_NOT_KCC20`); its state has no further field, since the
/// vault reads and rebuilds the four-field state only and cannot move such a token
/// (`VERIFY_TOKEN_EXTENDED_STATE`); a pinned template's artifact declares no other entry
/// (`VERIFY_TOKEN_ARTIFACT_INVALID`). Then the warnings, in this order: `TOKEN_MINTER_BRANCH`;
/// for a template outside the pinned set, `TOKEN_TEMPLATE_UNPINNED` and then
/// `TOKEN_EXTRA_ENTRIES`; `TOKEN_ISSUER_UNKNOWN` when no issuer keys were supplied, else
/// `TOKEN_PARTY_IS_ISSUER` for the seller, the buyer and the authority in that order.
pub fn token_warnings(
    terms: &ValidatedTerms,
    asset: Option<&TokenEvidence<'_>>,
    cash: Option<&TokenEvidence<'_>>,
) -> Result<Vec<TokenWarning>, VerifyError> {
    let t = terms.terms();
    let mut out = Vec::new();
    for (leg, kind, evidence) in [
        (LegIndex::Asset, &t.asset_leg.kind, asset),
        (LegIndex::Cash, &t.cash_leg.kind, cash),
    ] {
        let LegKind::Kcc20(token) = kind else {
            if evidence.is_some() {
                return Err(VerifyError::TokenLegKind { leg });
            }
            continue;
        };
        match evidence {
            None => out.push(TokenWarning {
                leg,
                kind: TokenWarningKind::Unassessed,
            }),
            Some(evidence) => out.extend(
                read(t, leg, token, evidence)?
                    .into_iter()
                    .map(|kind| TokenWarning { leg, kind }),
            ),
        }
    }
    Ok(out)
}

/// Whether a type is a struct or an array that holds one, at any depth.
fn holds_struct(ty: &TypeArtifact) -> bool {
    match ty {
        TypeArtifact::Struct { .. } => true,
        TypeArtifact::FixedArray { item, .. } | TypeArtifact::DynamicArray { item } => {
            holds_struct(item)
        }
        _ => false,
    }
}

/// A name an artifact may declare for a state field or an entry: 1 to 64 ASCII letters, digits
/// and underscores, as silverc v1.0.0 writes them.
fn identifier(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn read(
    t: &Terms,
    leg: LegIndex,
    token: &Kcc20Token,
    evidence: &TokenEvidence<'_>,
) -> Result<Vec<TokenWarningKind>, VerifyError> {
    let invalid = |reason: String| VerifyError::TokenArtifactInvalid { leg, reason };
    // Bounded before silverscript's consistency check, which flattens the struct types of the
    // state fields with a cycle check only: a DAG of structs costs time and memory exponential in
    // its depth. KCC-20's state has no struct-typed field, and without one the check is linear in
    // the artifact.
    let len = evidence.artifact_json.len();
    if len > MAX_TOKEN_ARTIFACT_LEN {
        return Err(invalid(format!(
            "{len} bytes, more than {MAX_TOKEN_ARTIFACT_LEN}"
        )));
    }
    let abi: SilAbiArtifact = serde_json::from_str(evidence.artifact_json)
        .map_err(|e| invalid(format!("does not parse: {}", printable(&e.to_string()))))?;
    let mut contracts = abi.contracts.values();
    let (Some(contract), None) = (contracts.next(), contracts.next()) else {
        return Err(invalid(format!(
            "holds {} contracts, not one",
            abi.contracts.len()
        )));
    };
    // Names are reported in warnings and refusals, so they must be plain identifiers.
    let names = contract.runtime_state.fields.iter().map(|f| &f.name);
    if let Some(name) = names
        .chain(contract.entries.keys())
        .find(|n| !identifier(n))
    {
        return Err(invalid(format!(
            "declares the name \"{}\", not 1 to 64 ASCII letters, digits and underscores",
            printable(name)
        )));
    }
    let fields = &contract.runtime_state.fields;
    if let Some(field) = fields.iter().find(|f| holds_struct(&f.ty)) {
        return Err(invalid(format!(
            "its state field {} has a struct type; KCC-20 state has none",
            field.name
        )));
    }
    abi.check_consistency()
        .map_err(|e| invalid(printable(&e.to_string())))?;

    let compiled = &contract.compiled;
    let (prefix, _state, suffix) = compiled
        .script_parts(&compiled.bytecode)
        .ok_or_else(|| invalid("state span lies outside the bytecode".into()))?;
    let found = TemplateTriple {
        hash: template_hash(prefix, suffix),
        prefix_len: prefix.len() as u64,
        suffix_len: suffix.len() as u64,
    };
    let expected = TemplateTriple::from(token);
    if found != expected {
        return Err(VerifyError::TokenTemplateMismatch {
            leg,
            expected,
            found,
        });
    }

    let fields = &contract.runtime_state.fields;
    let kcc20_state = fields.len() >= KCC20_STATE.len()
        && fields
            .iter()
            .zip(KCC20_STATE.iter().zip(kcc20_types()))
            .all(|(f, (name, ty))| f.name == *name && f.ty == ty);
    if !kcc20_state {
        return Err(VerifyError::TokenNotKcc20 {
            leg,
            reason: format!(
                "its state does not begin with the KCC-20 fields {}",
                KCC20_STATE.join(", ")
            ),
        });
    }
    if let Some(missing) = KCC20_ENTRIES
        .iter()
        .find(|e| !contract.entries.contains_key(**e))
    {
        return Err(VerifyError::TokenNotKcc20 {
            leg,
            reason: format!("it has no {missing} entry"),
        });
    }
    // The vault reads and rebuilds the four-field KCC-20 state; a token with more cannot settle
    // or refund through it (tests/engine/verify.rs pins this in the engine).
    if fields.len() > KCC20_STATE.len() {
        return Err(VerifyError::TokenExtendedState {
            leg,
            fields: fields[KCC20_STATE.len()..]
                .iter()
                .map(|f| f.name.clone())
                .collect(),
        });
    }
    let extra: Vec<String> = contract
        .entries
        .keys()
        .filter(|e| !KCC20_ENTRIES.contains(&e.as_str()))
        .cloned()
        .collect();
    let pinned = pinned_kcc20(&found).is_some();
    if pinned && !extra.is_empty() {
        return Err(invalid(format!(
            "declares entries the pinned kcc20.sil template does not have: {}",
            extra.join(", ")
        )));
    }

    let mut warnings = vec![TokenWarningKind::MinterBranch];
    if !pinned {
        warnings.push(TokenWarningKind::TemplateUnpinned);
        if !extra.is_empty() {
            warnings.push(TokenWarningKind::ExtraEntries { entries: extra });
        }
    }
    if evidence.issuer_keys.is_empty() {
        warnings.push(TokenWarningKind::IssuerUnknown);
    }
    for (party, key) in [
        (Party::Seller, Some(t.seller_key)),
        (Party::Buyer, Some(t.buyer_key)),
        (Party::Authority, t.authority_key),
    ] {
        if key.is_some_and(|k| evidence.issuer_keys.contains(&k)) {
            warnings.push(TokenWarningKind::PartyIsIssuer {
                party,
                relation: relation(leg, party),
            });
        }
    }
    Ok(warnings)
}
