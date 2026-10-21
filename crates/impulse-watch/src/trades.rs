// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The watched trades and what an accepted transaction does to them. Every vault comes from
//! impulse-core (`Vault::instantiate_existing`); nothing here builds a vault script of its own,
//! except the one script Impulse never instantiates: the cash-vault script of external-cash
//! terms, derived only so a deposit to it can be flagged (decision D14) and checked with
//! impulse-core's `decode`. No address is ever produced for that script (spec/TEMPLATE.md).
//!
//! Attribution is per leg, never per trade. One settle transaction can spend the asset vault of
//! one trade and the cash vault of another (cross-trade mixing, accepted in the spec red team
//! and pinned by the engine test `cross_trade_mixing_is_accepted`), so each spent vault is
//! reported as its own (trade, leg) effect.
//!
//! A spend is attributed by the UTXO the input spent, never by its signature script alone. A
//! signature script that ends with a vault's redeem script proves nothing by itself: a block
//! producer can include an input that spends some other, non-standard UTXO (standardness is a
//! mempool rule, not a consensus rule) with exactly that signature script. Only when the spent
//! UTXO's scriptPubKey is the vault's P2SH has consensus run the vault script, so only then is
//! the input a vault spend.

use crate::entry::{entry_of, entry_of_v2, pushes, Entry};
use crate::error::WatchError;
use crate::tracker::AcceptedTransaction;
use impulse_core::template::{self, LegIndex, TemplateError, Vault};
use impulse_core::terms::{LegKind, Network, ValidatedTerms};
use impulse_core::v2::{ValidatedTermsV2, VaultV2};
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry};
use kaspa_consensus_core::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use std::collections::HashMap;
use std::fmt;

/// A trade, named by its terms hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TradeId(pub [u8; 32]);

impl fmt::Display for TradeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// A watched leg: the asset or cash leg of v1 terms, or leg i of terms v2 (spec/V2.md 6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Leg {
    Asset,
    Cash,
    /// Leg i of a v2 trade, 0 to MAX_LEGS - 1.
    V2(u8),
}

impl Leg {
    /// The leg's index: the input its vault settles at (`[S1]` in both templates).
    pub fn index(self) -> u8 {
        match self {
            Leg::Asset => 0,
            Leg::Cash => 1,
            Leg::V2(i) => i,
        }
    }
}

impl From<LegIndex> for Leg {
    fn from(leg: LegIndex) -> Self {
        match leg {
            LegIndex::Asset => Leg::Asset,
            LegIndex::Cash => Leg::Cash,
        }
    }
}

/// The terms of a watched trade: version 1, or terms v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TradeTerms {
    V1(Box<ValidatedTerms>),
    V2(ValidatedTermsV2),
}

impl TradeTerms {
    pub fn terms_hash(&self) -> [u8; 32] {
        match self {
            Self::V1(t) => t.terms_hash(),
            Self::V2(t) => t.terms_hash(),
        }
    }

    pub fn network(&self) -> Network {
        match self {
            Self::V1(t) => t.terms().network,
            Self::V2(t) => t.terms().network,
        }
    }

    pub fn expiry_daa(&self) -> u64 {
        match self {
            Self::V1(t) => t.terms().expiry_daa,
            Self::V2(t) => t.terms().expiry_daa,
        }
    }
}

impl From<ValidatedTerms> for TradeTerms {
    fn from(t: ValidatedTerms) -> Self {
        Self::V1(Box::new(t))
    }
}

impl From<ValidatedTermsV2> for TradeTerms {
    fn from(t: ValidatedTermsV2) -> Self {
        Self::V2(t)
    }
}

/// What one accepted transaction did to one watched leg, or to the cash-vault script of
/// external-cash terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Output `index` pays the vault of a KAS leg: the vault UTXO is the leg. `exact` is
    /// whether it holds exactly the leg amount; only such a UTXO can settle (spec principle 4).
    Funded {
        trade: TradeId,
        leg: Leg,
        index: u32,
        value: u64,
        exact: bool,
    },
    /// Output `index` pays the vault of a KCC-20 leg: an authorizer arrived. This is not a
    /// funding: the escrowed token is a separate KCC-20 output whose scriptPubKey hides its
    /// state, so the watcher cannot verify it, and anyone can pay a vault address. A vault
    /// without its escrowed token can never settle ([E1] to [E5]). `covenant_output` is
    /// whether the same transaction has an output bound to the leg's covenant ID, which shows
    /// only that it moved some token of that covenant (spec/WATCH.md).
    AuthorizerSeen {
        trade: TradeId,
        leg: Leg,
        index: u32,
        value: u64,
        covenant_output: bool,
    },
    /// Input `input` spends the leg's vault UTXO `spent`, holding `spent_value`, through
    /// `settle`, at the leg's canonical index.
    Settled {
        trade: TradeId,
        leg: Leg,
        input: u32,
        spent: TransactionOutpoint,
        spent_value: u64,
    },
    /// Input `input` spends the leg's vault UTXO `spent` through `refund`, at input 0.
    Refunded {
        trade: TradeId,
        leg: Leg,
        input: u32,
        spent: TransactionOutpoint,
        spent_value: u64,
    },
    /// Input `input` spends the leg's vault UTXO `spent`, but not as a settle or refund the
    /// watcher can read: another entry, an entry at an input index it never runs at, or a
    /// spend the vault's own checks would have refused (for example a KAS leg settled from a
    /// UTXO that is not the exact leg amount). Never reported as a settle or refund.
    Unclassified {
        trade: TradeId,
        leg: Leg,
        input: u32,
        spent: TransactionOutpoint,
        spent_value: u64,
    },
    /// Output `index` pays the cash-vault script of external-cash terms, which must never be
    /// funded and has no recovery builder (decision D14).
    StrayDeposit {
        trade: TradeId,
        index: u32,
        value: u64,
    },
    /// Retired (I26), never produced: `WATCH_FOREIGN_TOKEN`, a spend of the leg's vault that also
    /// spent, at input `input`, a token of covenant `covenant_id` the spend did not check. Every
    /// template now refuses every such spend (spec/TRANSACTIONS.md, "A token of another covenant
    /// at a vault"), so the watcher no longer looks for it. The variant stays so that a state file
    /// written by an earlier build, which may hold such an effect, still reads back.
    ForeignToken {
        trade: TradeId,
        leg: Leg,
        input: u32,
        covenant_id: Hash,
    },
}

impl Effect {
    /// The event name of this effect.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Funded { .. } => "funded",
            Self::AuthorizerSeen { .. } => "authorizer_seen",
            Self::Settled { .. } => "settled",
            Self::Refunded { .. } => "refunded",
            Self::Unclassified { .. } => "unclassified_spend",
            Self::StrayDeposit { .. } => "stray_deposit",
            Self::ForeignToken { .. } => "foreign_token",
        }
    }

    /// The flag this effect carries, if it needs the operator's attention.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Funded { exact: false, .. } => Some("WATCH_FUNDING_NOT_EXACT"),
            Self::Unclassified { .. } => Some("WATCH_SPEND_UNCLASSIFIED"),
            Self::StrayDeposit { .. } => Some("WATCH_STRAY_DEPOSIT"),
            Self::ForeignToken { .. } => Some("WATCH_FOREIGN_TOKEN"),
            _ => None,
        }
    }

    pub fn trade(&self) -> TradeId {
        match *self {
            Self::Funded { trade, .. }
            | Self::AuthorizerSeen { trade, .. }
            | Self::Settled { trade, .. }
            | Self::Refunded { trade, .. }
            | Self::Unclassified { trade, .. }
            | Self::StrayDeposit { trade, .. }
            | Self::ForeignToken { trade, .. } => trade,
        }
    }

    /// The leg, for every effect but a stray deposit, which belongs to no leg.
    pub fn leg(&self) -> Option<Leg> {
        match *self {
            Self::Funded { leg, .. }
            | Self::AuthorizerSeen { leg, .. }
            | Self::Settled { leg, .. }
            | Self::Refunded { leg, .. }
            | Self::Unclassified { leg, .. }
            | Self::ForeignToken { leg, .. } => Some(leg),
            Self::StrayDeposit { .. } => None,
        }
    }

    /// Whether this effect is a classified spend of a watched vault.
    pub fn is_spend(&self) -> bool {
        matches!(self, Self::Settled { .. } | Self::Refunded { .. })
    }
}

/// One watched vault.
#[derive(Clone, Debug)]
struct WatchedVault {
    trade: TradeId,
    leg: Leg,
    /// Whether the vault runs template v2 (its entries carry the v2 tags).
    v2: bool,
    /// Whether a settle spends exactly the leg amount of a KAS leg (`[S2]`; terms v2 without
    /// partial). False for partial terms, whose settles spend whole lots.
    whole: bool,
    /// The leg amount for a KAS leg; `None` for a KCC-20 leg (the vault holds the authorizer).
    kas_amount: Option<u64>,
    /// The covenant ID of a KCC-20 leg's token.
    covenant_id: Option<Hash>,
}

/// The watched trades, indexed for classification.
#[derive(Clone, Debug)]
pub struct TradeBook {
    network: Network,
    trades: HashMap<TradeId, TradeTerms>,
    /// Vault scriptPubKey to vault, for fundings and for spends (the spent UTXO's scriptPubKey).
    by_spk: HashMap<ScriptPublicKey, WatchedVault>,
    /// scriptPubKey of the cash-vault script of external-cash terms, for stray deposits.
    stray_by_spk: HashMap<ScriptPublicKey, TradeId>,
}

impl TradeBook {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            trades: HashMap::new(),
            by_spk: HashMap::new(),
            stray_by_spk: HashMap::new(),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn len(&self) -> usize {
        self.trades.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trades.is_empty()
    }

    pub fn terms(&self, trade: &TradeId) -> Option<&TradeTerms> {
        self.trades.get(trade)
    }

    /// Stops watching a trade: its vaults and its stray script leave the indexes. A no-op for
    /// a trade not watched.
    pub fn remove(&mut self, trade: &TradeId) {
        self.trades.remove(trade);
        self.by_spk.retain(|_, v| v.trade != *trade);
        self.stray_by_spk.retain(|_, t| t != trade);
    }

    /// Watches a trade. Refuses, in order: terms of another network (`WATCH_NETWORK_MISMATCH`),
    /// terms already watched (`WATCH_TRADE_DUPLICATE`), any instantiation refusal with its own
    /// code (Direct terms have no vault: `TEMPLATE_NO_VAULT`), and an underivable cash-vault
    /// script of external-cash terms (`WATCH_STRAY_SCRIPT_UNDERIVABLE`). Nothing is added
    /// unless every step passes.
    pub fn add(&mut self, terms: impl Into<TradeTerms>) -> Result<TradeId, WatchError> {
        let terms = terms.into();
        let network = terms.network();
        if network != self.network {
            return Err(WatchError::NetworkMismatch {
                watcher: self.network,
                terms: network,
            });
        }
        let id = TradeId(terms.terms_hash());
        if self.trades.contains_key(&id) {
            return Err(WatchError::TradeDuplicate(id));
        }
        let (vaults, stray) = match &terms {
            TradeTerms::V1(t) => v1_vaults(id, t)?,
            TradeTerms::V2(t) => (v2_vaults(id, t)?, None),
        };
        for (spk, watched) in vaults {
            self.by_spk.insert(spk, watched);
        }
        if let Some(spk) = stray {
            self.stray_by_spk.insert(spk, id);
        }
        self.trades.insert(id, terms);
        Ok(id)
    }

    /// What an accepted transaction does to the watched trades: fundings and stray deposits in
    /// output order, then vault spends in input order. An input is a vault spend only if the
    /// UTXO it spent pays a watched vault's scriptPubKey. Empty if it touches none.
    pub fn classify(&self, accepted: &AcceptedTransaction) -> Vec<Effect> {
        let tx = accepted.tx();
        let mut effects = Vec::new();
        for (index, output) in tx.outputs.iter().enumerate() {
            let index = index as u32;
            let value = output.value;
            if let Some(v) = self.by_spk.get(&output.script_public_key) {
                let (trade, leg) = (v.trade, v.leg);
                effects.push(match v.kas_amount {
                    Some(amount) => Effect::Funded {
                        trade,
                        leg,
                        index,
                        value,
                        exact: value == amount,
                    },
                    None => Effect::AuthorizerSeen {
                        trade,
                        leg,
                        index,
                        value,
                        covenant_output: tx.outputs.iter().any(|o| {
                            o.covenant
                                .is_some_and(|c| Some(c.covenant_id) == v.covenant_id)
                        }),
                    },
                });
            } else if let Some(trade) = self.stray_by_spk.get(&output.script_public_key) {
                effects.push(Effect::StrayDeposit {
                    trade: *trade,
                    index,
                    value,
                });
            }
        }
        let inputs = tx.inputs.iter().zip(accepted.spent());
        for (input, (tx_input, entry)) in inputs.enumerate() {
            let Some(v) = self.by_spk.get(&entry.script_public_key) else {
                continue;
            };
            let input = input as u32;
            let effect = spend_effect(
                v,
                input,
                tx_input.previous_outpoint,
                entry,
                &tx_input.signature_script,
            );
            effects.push(effect);
        }
        effects
    }

    /// The vault spends `tx` claims, by its signature scripts alone: each input that ends with
    /// a watched vault's redeem script and calls settle at that leg's index or refund at
    /// input 0.
    fn claims<'a>(
        &'a self,
        tx: &'a Transaction,
    ) -> impl Iterator<Item = (&'a WatchedVault, Entry)> + 'a {
        tx.inputs
            .iter()
            .enumerate()
            .filter_map(move |(input, tx_input)| {
                let pushes = pushes(&tx_input.signature_script)?;
                let v = pushes
                    .last()
                    .and_then(|redeem| self.by_spk.get(&pay_to_script_hash_script(redeem)))?;
                match entry_called(v, &pushes)? {
                    Entry::Settle if input == v.leg.index() as usize => Some((v, Entry::Settle)),
                    Entry::Refund if input == 0 => Some((v, Entry::Refund)),
                    _ => None,
                }
            })
    }

    /// Whether `tx` claims, by its signature scripts alone, to settle or refund a watched vault.
    /// A sanity check on a transaction offered for rebroadcast only; acceptance is always read
    /// through [`Self::classify`].
    pub fn claims_spend(&self, tx: &Transaction) -> bool {
        self.claims(tx).next().is_some()
    }

    /// The earliest expiry DAA score among the watched trades whose vault `tx` claims to settle;
    /// `None` if it claims no settle.
    pub fn claimed_settle_expiry(&self, tx: &Transaction) -> Option<u64> {
        self.claims(tx)
            .filter(|(_, entry)| *entry == Entry::Settle)
            .filter_map(|(v, _)| self.trades.get(&v.trade))
            .map(TradeTerms::expiry_daa)
            .min()
    }
}

/// The vaults of v1 terms, and the cash-vault script of external-cash terms (for stray
/// deposits).
#[allow(clippy::type_complexity)]
fn v1_vaults(
    id: TradeId,
    terms: &ValidatedTerms,
) -> Result<
    (
        Vec<(ScriptPublicKey, WatchedVault)>,
        Option<ScriptPublicKey>,
    ),
    WatchError,
> {
    let t = terms.terms();
    let watched = |leg: LegIndex| {
        let terms_leg = match leg {
            LegIndex::Asset => t.asset_leg,
            LegIndex::Cash => t.cash_leg,
        };
        let (kas_amount, covenant_id) = match terms_leg.kind {
            LegKind::Kas => (Some(terms_leg.amount), None),
            LegKind::Kcc20(token) => (None, Some(Hash::from_bytes(token.covenant_id))),
            LegKind::External => (None, None),
        };
        WatchedVault {
            trade: id,
            leg: leg.into(),
            v2: false,
            whole: true,
            kas_amount,
            covenant_id,
        }
    };
    // The asset leg always has a vault under vault terms; Direct terms are refused here.
    let asset = Vault::instantiate_existing(terms, LegIndex::Asset)?;
    let mut stray = None;
    let mut vaults = vec![];
    match Vault::instantiate_existing(terms, LegIndex::Cash) {
        Ok(cash) => vaults.push((cash.script_public_key(), watched(LegIndex::Cash))),
        Err(TemplateError::NoVault {
            leg: LegIndex::Cash,
            ..
        }) if t.cash_leg.kind == LegKind::External => {
            let script = stray_cash_script(asset.redeem_script())?;
            stray = Some(pay_to_script_hash_script(&script));
        }
        Err(e) => return Err(e.into()),
    }
    vaults.insert(0, (asset.script_public_key(), watched(LegIndex::Asset)));
    Ok((vaults, stray))
}

/// The vaults of terms v2: one per leg, every leg a KAS or KCC-20 leg (spec/V2.md 5.3).
fn v2_vaults(
    id: TradeId,
    terms: &ValidatedTermsV2,
) -> Result<Vec<(ScriptPublicKey, WatchedVault)>, WatchError> {
    let t = terms.terms();
    (0..t.legs.len())
        .map(|i| {
            let vault = VaultV2::instantiate_existing(terms, i)?;
            let leg = &t.legs[i];
            let (kas_amount, covenant_id) = match leg.asset.kind {
                LegKind::Kcc20(token) => (None, Some(Hash::from_bytes(token.covenant_id))),
                _ => (Some(leg.asset.amount), None),
            };
            let watched = WatchedVault {
                trade: id,
                leg: Leg::V2(i as u8),
                v2: true,
                whole: t.partial.is_none(),
                kas_amount,
                covenant_id,
            };
            Ok((vault.script_public_key(), watched))
        })
        .collect()
}

/// The entry a vault spend called, read with the tags of the vault's template.
fn entry_called(v: &WatchedVault, pushes: &[Vec<u8>]) -> Option<Entry> {
    if v.v2 {
        entry_of_v2(pushes)
    } else {
        entry_of(pushes)
    }
}

/// The effect of input `input`, which spent `entry` (a UTXO at vault `v`'s scriptPubKey) at
/// `spent` with `signature_script`. [S1]: settle runs at the leg's index. [R4]: refund runs at
/// input 0. [S2]: a KAS leg settles only from a UTXO of exactly the leg amount. Consensus has
/// already run the vault script, so a spend that breaks one of these, or whose signature script
/// does not end with the vault's redeem script, means the template is not the one the watcher
/// assumes: it is reported unclassified.
fn spend_effect(
    v: &WatchedVault,
    input: u32,
    spent: TransactionOutpoint,
    entry: &UtxoEntry,
    signature_script: &[u8],
) -> Effect {
    let (trade, leg, spent_value) = (v.trade, v.leg, entry.amount);
    let pushes = pushes(signature_script).filter(|p| {
        p.last()
            .is_some_and(|redeem| pay_to_script_hash_script(redeem) == entry.script_public_key)
    });
    let exact = v.kas_amount.is_none_or(|amount| amount == spent_value);
    // Partial terms v2 settle whole lots of a KAS leg; the vault script checked them.
    let exact = exact || !v.whole;
    match pushes.as_deref().and_then(|p| entry_called(v, p)) {
        Some(Entry::Settle) if input == leg.index() as u32 && exact => Effect::Settled {
            trade,
            leg,
            input,
            spent,
            spent_value,
        },
        Some(Entry::Refund) if input == 0 => Effect::Refunded {
            trade,
            leg,
            input,
            spent,
            spent_value,
        },
        _ => Effect::Unclassified {
            trade,
            leg,
            input,
            spent,
            spent_value,
        },
    }
}

/// legIndex is the last state field, just before the template suffix: an `int`, pushed as
/// OP_DATA_8 and an 8-byte script number (spec/TEMPLATE.md, "State").
const LEG_INDEX_ASSET: [u8; 9] = [0x08, 0, 0, 0, 0, 0, 0, 0, 0];
const LEG_INDEX_CASH: [u8; 9] = [0x08, 1, 0, 0, 0, 0, 0, 0, 0];

/// The asset vault's script with legIndex 1 in place of 0: what compiling the template with the
/// same terms and legIndex 1 gives. Refuses (`WATCH_STRAY_SCRIPT_UNDERIVABLE`) unless the
/// script ends with legIndex 0 and then the template suffix.
pub(crate) fn with_cash_leg_index(asset_redeem: &[u8]) -> Result<Vec<u8>, WatchError> {
    let suffix = template::check()?.suffix();
    let state_end = asset_redeem
        .strip_suffix(suffix)
        .and_then(|body| body.strip_suffix(&LEG_INDEX_ASSET))
        .ok_or(WatchError::StrayScriptUnderivable)?;
    let mut script = Vec::with_capacity(asset_redeem.len());
    script.extend_from_slice(state_end);
    script.extend_from_slice(&LEG_INDEX_CASH);
    script.extend_from_slice(suffix);
    Ok(script)
}

/// The cash-vault script of external-cash terms, from their asset vault's script. Checked with
/// impulse-core: it must decode as the cash leg and be refused for having no vault, which is how
/// spec/TEMPLATE.md says decoding treats this script and only this script. Refuses anything
/// else (`WATCH_STRAY_SCRIPT_UNDERIVABLE`), including the asset vault of terms whose cash leg
/// has a real vault.
pub(crate) fn stray_cash_script(asset_redeem: &[u8]) -> Result<Vec<u8>, WatchError> {
    let script = with_cash_leg_index(asset_redeem)?;
    match template::decode(&script) {
        Err(TemplateError::NoVault {
            leg: LegIndex::Cash,
            ..
        }) => Ok(script),
        _ => Err(WatchError::StrayScriptUnderivable),
    }
}
