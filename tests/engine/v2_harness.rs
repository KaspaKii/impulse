// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Engine harness for the ImpulseVault v2 tests (I16), on top of the v1 harness (compilation,
//! KCC-20 fixtures, throwaway keys, the engine run). Each v2 test target declares both modules:
//! `mod harness; mod v2_harness;`.
//!
//! A world is a v2 trade: parties with throwaway keys (generated from the OS RNG per run, held in
//! memory only, never written or printed, erased on drop; rule 1 exception, docs/ENGINEERING-RULES.md), the terms
//! v2 in the form of the ImpulseVaultV2 constructor, and one compiled vault per leg. Transactions
//! are data (`TxV2`): build the canonical one, change one thing, run every input in the engine.

#![allow(dead_code)] // each test target uses a different part of the harness

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript_errors::TxScriptError;
use secp256k1::Keypair;
use silverscript_abi::ArtifactValue;

use crate::harness::*;

// =============================================================================================
// Constants shared with contracts/impulse_vault_v2.sil
// =============================================================================================

pub const MAX_LEGS: usize = 10;
pub const LEG_RECORD: usize = 187;
pub const KIND_KAS: u8 = 0x00;
pub const KIND_KCC20: u8 = 0x01;
pub const DEST_P2PK: u8 = 0x00;
pub const DEST_P2SH: u8 = 0x01;
/// Template prefix and the fixed part of the state around the legs payload (contract constants
/// PREFIX_LEN and STATE_FIXED).
pub const PREFIX_LEN: usize = 1;
pub const STATE_FIXED: usize = 142;

/// The v2 vault source under test. `IMPULSE_VAULT_V2_SIL` overrides the path; the v2 mutation
/// run (tests/engine/v2_mutation.py) uses it to point every test at a mutant.
pub fn vault_v2_source() -> String {
    let path = match std::env::var_os("IMPULSE_VAULT_V2_SIL") {
        Some(path) => PathBuf::from(path),
        None => repo_path("contracts/impulse_vault_v2.sil"),
    };
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// The SUFFIX_LEN constant written in a v2 source.
pub fn suffix_constant(source: &str) -> usize {
    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with("int constant SUFFIX_LEN = "))
        .expect("SUFFIX_LEN constant");
    line.trim()
        .trim_start_matches("int constant SUFFIX_LEN = ")
        .trim_end_matches(';')
        .parse()
        .expect("SUFFIX_LEN value")
}

thread_local! {
    static COMPILED: RefCell<HashMap<String, Compiled>> = RefCell::new(HashMap::new());
}

/// Compiles once per (source, constructor) in this test thread.
fn compile_cached(source: &str, ctor: &[ArtifactValue]) -> Compiled {
    let key = format!("{}\n{:?}", source_digest(source.as_bytes()), ctor);
    if let Some(hit) = COMPILED.with(|c| c.borrow().get(&key).cloned()) {
        return hit;
    }
    let compiled = Compiled::new(source, ctor);
    COMPILED.with(|c| c.borrow_mut().insert(key, compiled.clone()));
    compiled
}

fn source_digest(data: &[u8]) -> String {
    // A cache key only; any stable digest will do.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as _, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}{}", h.finish(), data.len())
}

// =============================================================================================
// KCC-20 tokens, optionally padded to longer templates
// =============================================================================================

/// A KCC-20 token: covenant ID, the template constants maxCovIns and maxCovOuts, and `pad` extra
/// 32-byte-literal statements in the branch for owner types no Impulse token takes (a longer
/// template whose `transfer` does the same work; the padding of tests/engine/builders.rs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenV2 {
    pub cov: Hash,
    pub max_cov_ins: i64,
    pub max_cov_outs: i64,
    pub pad: usize,
}

impl TokenV2 {
    pub const fn new(cov_byte: u8, max_cov_outs: i64) -> Self {
        Self {
            cov: Hash::from_bytes([cov_byte; 32]),
            max_cov_ins: 2,
            max_cov_outs,
            pad: 0,
        }
    }

    pub fn padded(self, pad: usize) -> Self {
        Self { pad, ..self }
    }

    pub fn with_cov(self, cov: Hash) -> Self {
        Self { cov, ..self }
    }

    pub fn source(&self) -> String {
        let source = kcc20_source();
        if self.pad == 0 {
            return source;
        }
        let tail = "        } else {\n            require(false);\n        }";
        assert!(
            source.contains(tail),
            "kcc20.sil has the branch the padding goes in"
        );
        let padding: String = (0..self.pad)
            .map(|i| {
                format!(
                    "            require(ownerIdentifier != byte[32](0x{}));\n",
                    format!("{:02x}", i % 256).repeat(32)
                )
            })
            .collect();
        source.replacen(
            tail,
            &format!("        }} else {{\n{padding}            require(false);\n        }}"),
            1,
        )
    }

    pub fn compile(&self, state: Kcc20State) -> Compiled {
        compile_cached(
            &self.source(),
            &[
                ArtifactValue::Bytes(state.owner.to_vec()),
                ArtifactValue::Int(state.amount),
                ArtifactValue::Byte(state.id_type),
                ArtifactValue::Bool(state.is_minter),
                ArtifactValue::Int(self.max_cov_ins),
                ArtifactValue::Int(self.max_cov_outs),
            ],
        )
    }

    pub fn template(&self) -> TemplateRef {
        let a = self.compile(Kcc20State::new(Owner::pubkey([0; 32]), 0));
        let (prefix_len, suffix_len) = a.template_lens();
        TemplateRef {
            cov: self.cov,
            hash: a.template_hash(),
            prefix_len: prefix_len as i64,
            suffix_len: suffix_len as i64,
        }
    }

    /// Template length in bytes (prefix plus suffix).
    pub fn template_len(&self) -> usize {
        let t = self.template();
        (t.prefix_len + t.suffix_len) as usize
    }
}

/// Fixture tokens: distinct covenants, alternating templates (maxCovOuts 2 or 3), so a vault that
/// mixed up two legs' templates would be caught.
pub fn fixture_token(j: usize) -> TokenV2 {
    TokenV2::new(0xA0 + j as u8, 2 + (j as i64 % 2))
}

pub const DECOY_TOKEN_COV: Hash = Hash::from_bytes([0xD0; 32]);

// =============================================================================================
// Terms v2 in the constructor's form
// =============================================================================================

/// One leg record (spec/V2.md 4.2), field by field.
#[derive(Clone, Debug)]
pub struct LegV2 {
    pub depositor: [u8; 32],
    pub kind: u8,
    pub token: Option<TokenV2>,
    pub tmpl: TemplateRef,
    /// The 8 amount bytes as the record carries them (little-endian; a crafted record may set
    /// the top bit).
    pub amount_bytes: [u8; 8],
    pub delivery: Owner,
    pub refund: Owner,
}

impl LegV2 {
    pub fn amount(&self) -> i64 {
        let raw = u64::from_le_bytes(self.amount_bytes);
        // Script numbers are sign-magnitude: the top bit of byte 8 is the sign.
        let magnitude = (raw & !(1u64 << 63)) as i64;
        if raw >> 63 == 1 {
            -magnitude
        } else {
            magnitude
        }
    }

    pub fn set_amount(&mut self, amount: i64) {
        assert!(
            amount >= 0,
            "use amount_bytes for a crafted negative amount"
        );
        self.amount_bytes = amount.to_le_bytes();
    }

    pub fn record(&self) -> Vec<u8> {
        let mut r = Vec::with_capacity(LEG_RECORD);
        r.extend_from_slice(&self.depositor);
        r.push(self.kind);
        r.extend_from_slice(self.tmpl.cov.as_bytes().as_slice());
        r.extend_from_slice(&self.tmpl.hash);
        r.extend_from_slice(&self.tmpl.prefix_len.to_le_bytes());
        r.extend_from_slice(&self.tmpl.suffix_len.to_le_bytes());
        r.extend_from_slice(&self.amount_bytes);
        r.push(self.delivery.id_type);
        r.extend_from_slice(&self.delivery.id);
        r.push(self.refund.id_type);
        r.extend_from_slice(&self.refund.id);
        assert_eq!(r.len(), LEG_RECORD);
        r
    }

    pub fn is_token(&self) -> bool {
        self.kind != KIND_KAS
    }

    pub fn token(&self) -> TokenV2 {
        self.token.expect("a KCC-20 leg")
    }
}

#[derive(Clone, Debug)]
pub struct TermsV2 {
    pub version: u8,
    pub network: u8,
    pub nonce: [u8; 8],
    pub has_authority: bool,
    pub authority_key: [u8; 32],
    /// The legCount field; equals legs.len() unless a test crafts the state.
    pub leg_count: i64,
    pub legs: Vec<LegV2>,
    /// Bytes appended to the leg list (a crafted long list) and bytes cut from its end (short).
    pub legs_extra: Vec<u8>,
    pub legs_cut: usize,
    pub has_earliest: bool,
    pub earliest_daa: i64,
    pub expiry_daa: i64,
    pub funding_mode: u8,
    pub trade_ref: [u8; 32],
    pub lot_count: i64,
    pub min_lot: i64,
}

impl TermsV2 {
    pub fn legs_bytes(&self) -> Vec<u8> {
        let mut b: Vec<u8> = self.legs.iter().flat_map(|l| l.record()).collect();
        b.extend_from_slice(&self.legs_extra);
        b.truncate(b.len() - self.legs_cut);
        b
    }

    pub fn ctor(&self, leg_index: i64) -> Vec<ArtifactValue> {
        use ArtifactValue::{Bool, Byte, Bytes, Int};
        vec![
            Byte(self.version),
            Byte(self.network),
            Bytes(self.nonce.to_vec()),
            Bool(self.has_authority),
            Bytes(self.authority_key.to_vec()),
            Int(self.leg_count),
            Bytes(self.legs_bytes()),
            Bool(self.has_earliest),
            Int(self.earliest_daa),
            Int(self.expiry_daa),
            Byte(self.funding_mode),
            Bytes(self.trade_ref.to_vec()),
            Int(self.lot_count),
            Int(self.min_lot),
            Int(leg_index),
        ]
    }

    pub fn vault(&self, leg_index: i64) -> Compiled {
        compile_cached(&vault_v2_source(), &self.ctor(leg_index))
    }

    pub fn unit(&self, leg: usize) -> i64 {
        self.legs[leg].amount() / self.lot_count
    }
}

// =============================================================================================
// Parties and worlds
// =============================================================================================

/// Who signs: a party (by index), the authority, or a stranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    Party(usize),
    Authority,
    Stranger,
}

#[derive(Clone, Copy, Debug)]
pub enum Asset {
    Kas,
    Token(TokenV2),
}

/// One leg as a test describes it: who deposits what to whom.
#[derive(Clone, Copy, Debug)]
pub struct LegSpec {
    pub party: usize,
    pub asset: Asset,
    pub amount: i64,
    pub to: usize,
}

#[derive(Clone, Debug)]
pub struct Setup {
    pub parties: usize,
    pub legs: Vec<LegSpec>,
    pub authority: bool,
    pub funding: u8,
    /// None: no partial (lotCount 1, minLot 1). Some((lot_count, min_lot)): partial terms.
    pub partial: Option<(i64, i64)>,
}

pub const TOKEN_AMOUNT: i64 = 1_000;
pub const KAS_AMOUNT: i64 = 250_000;

impl Setup {
    /// v1's KAS-cash mode at N = 2: party 0 (seller) deposits a KCC-20 asset for party 1
    /// (buyer), party 1 deposits KAS for party 0.
    pub fn v1_kas_cash(authority: bool) -> Self {
        Self {
            parties: 2,
            legs: vec![
                LegSpec {
                    party: 0,
                    asset: Asset::Token(fixture_token(0)),
                    amount: TOKEN_AMOUNT,
                    to: 1,
                },
                LegSpec {
                    party: 1,
                    asset: Asset::Kas,
                    amount: KAS_AMOUNT,
                    to: 0,
                },
            ],
            authority,
            funding: REVOCABLE,
            partial: None,
        }
    }

    /// v1's KCC-20-cash mode at N = 2.
    pub fn v1_kcc20_cash(authority: bool) -> Self {
        Self {
            parties: 2,
            legs: vec![
                LegSpec {
                    party: 0,
                    asset: Asset::Token(fixture_token(0)),
                    amount: TOKEN_AMOUNT,
                    to: 1,
                },
                LegSpec {
                    party: 1,
                    asset: Asset::Token(fixture_token(1)),
                    amount: KAS_AMOUNT,
                    to: 0,
                },
            ],
            authority,
            funding: REVOCABLE,
            partial: None,
        }
    }

    /// A ring of n parties: party j delivers token j to party j + 1.
    pub fn ring(n: usize, authority: bool) -> Self {
        Self {
            parties: n,
            legs: (0..n)
                .map(|j| LegSpec {
                    party: j,
                    asset: Asset::Token(fixture_token(j)),
                    amount: TOKEN_AMOUNT * (j as i64 + 1),
                    to: (j + 1) % n,
                })
                .collect(),
            authority,
            funding: REVOCABLE,
            partial: None,
        }
    }

    /// Three parties, two KCC-20 legs and one KAS leg (the KCC-20 legs first).
    pub fn three_with_kas(authority: bool) -> Self {
        let mut s = Self::ring(3, authority);
        s.legs[2].asset = Asset::Kas;
        s.legs[2].amount = KAS_AMOUNT;
        s
    }

    /// Two parties exchanging a list of n legs: n - 1 KCC-20 legs alternating direction, then
    /// one KAS leg (the I16 ten-line bilateral case at n = 10).
    pub fn bilateral(n: usize, authority: bool) -> Self {
        let mut legs: Vec<LegSpec> = (0..n - 1)
            .map(|j| LegSpec {
                party: j % 2,
                asset: Asset::Token(fixture_token(j)),
                amount: TOKEN_AMOUNT * (j as i64 + 1),
                to: (j + 1) % 2,
            })
            .collect();
        legs.push(LegSpec {
            party: (n - 1) % 2,
            asset: Asset::Kas,
            amount: KAS_AMOUNT,
            to: n % 2,
        });
        Self {
            parties: 2,
            legs,
            authority,
            funding: REVOCABLE,
            partial: None,
        }
    }

    /// Every leg KCC-20 with distinct fixture tokens padded by `pad` lines (the worst case of
    /// spec/V2.md 9.3), parties alternating between two.
    pub fn all_tokens(n: usize, authority: bool, pad: usize) -> Self {
        Self {
            parties: 2,
            legs: (0..n)
                .map(|j| LegSpec {
                    party: j % 2,
                    asset: Asset::Token(fixture_token(j).padded(pad)),
                    amount: TOKEN_AMOUNT * 10,
                    to: (j + 1) % 2,
                })
                .collect(),
            authority,
            funding: REVOCABLE,
            partial: None,
        }
    }

    pub fn partial(mut self, lot_count: i64, min_lot: i64) -> Self {
        self.partial = Some((lot_count, min_lot));
        self
    }

    pub fn earmarked(mut self) -> Self {
        self.funding = EARMARKED;
        self
    }
}

/// Throwaway keys of one world: the parties, then the authority, then a stranger.
pub struct Keys(Vec<TestKey>);

impl Keys {
    fn new(parties: usize) -> Self {
        Keys((0..parties + 2).map(|_| random_keypair()).collect())
    }

    pub fn get(&self, who: Who) -> &Keypair {
        let n = self.0.len() - 2;
        match who {
            Who::Party(p) => &self.0[p],
            Who::Authority => &self.0[n],
            Who::Stranger => &self.0[n + 1],
        }
    }

    pub fn xonly(&self, who: Who) -> [u8; 32] {
        xonly(self.get(who))
    }
}

/// A P2SH script hash a KAS refund destination of party p uses (nothing spends it here).
pub fn kas_refund_hash(p: usize) -> [u8; 32] {
    [0xB3 ^ p as u8; 32]
}

/// Vault covenant IDs for partial terms (the funding genesis is not part of these tests; the
/// engine sees the vault UTXO with its covenant ID, as after a genesis).
pub fn vault_cov(i: usize) -> Hash {
    Hash::from_bytes([0xC0 + i as u8; 32])
}

pub const AUTH: u64 = AUTH_VALUE;

pub struct WorldV2 {
    pub setup: Setup,
    pub terms: TermsV2,
    pub vaults: Vec<Compiled>,
    /// The covenant ID each vault UTXO carries (Some for partial terms by default).
    pub vault_covs: Vec<Option<Hash>>,
    keys: Rc<Keys>,
}

impl WorldV2 {
    pub fn new(setup: Setup) -> Self {
        let keys = Rc::new(Keys::new(setup.parties));
        let terms = terms_for(&setup, &keys);
        Self::with_terms(setup, terms, keys)
    }

    /// The same parties (same keys) with the terms changed by `edit`.
    pub fn edit(&self, edit: impl FnOnce(&mut TermsV2)) -> Self {
        let mut terms = self.terms.clone();
        edit(&mut terms);
        let mut w = Self::with_terms(self.setup.clone(), terms, self.keys.clone());
        w.vault_covs = self.vault_covs.clone();
        w
    }

    fn with_terms(setup: Setup, terms: TermsV2, keys: Rc<Keys>) -> Self {
        let n = terms.legs.len();
        let vaults = (0..n).map(|i| terms.vault(i as i64)).collect();
        let vault_covs = (0..n)
            .map(|i| setup.partial.map(|_| vault_cov(i)))
            .collect();
        Self {
            setup,
            terms,
            vaults,
            vault_covs,
            keys,
        }
    }

    pub fn n(&self) -> usize {
        self.terms.legs.len()
    }

    pub fn k(&self) -> usize {
        self.terms.legs.iter().filter(|l| l.is_token()).count()
    }

    pub fn key(&self, who: Who) -> &Keypair {
        self.keys.get(who)
    }

    pub fn xonly(&self, who: Who) -> [u8; 32] {
        self.keys.xonly(who)
    }

    pub fn leg(&self, j: usize) -> &LegV2 {
        &self.terms.legs[j]
    }

    pub fn depositor(&self, j: usize) -> Who {
        Who::Party(self.setup.legs[j].party)
    }

    /// Value of vault UTXO i: the KAS of a KAS leg (`held`), or the authorizer's KAS.
    pub fn vault_value(&self, i: usize, held: i64) -> u64 {
        if self.leg(i).is_token() {
            AUTH
        } else {
            held as u64
        }
    }

    pub fn escrow_state(&self, j: usize, held: i64) -> Kcc20State {
        Kcc20State::new(Owner::script_hash(self.vaults[j].script_hash()), held)
    }

    pub fn delivered(&self, j: usize, amount: i64) -> Kcc20State {
        Kcc20State::new(self.leg(j).delivery, amount)
    }

    pub fn dest_spk(owner: Owner) -> ScriptPublicKey {
        if owner.id_type == DEST_P2PK {
            p2pk(owner.id)
        } else {
            ScriptPublicKey::new(0, {
                let mut s = vec![0xaa, 0x20];
                s.extend_from_slice(&owner.id);
                s.push(0x87);
                s.into()
            })
        }
    }

    /// The settle of `lots` lots with every escrow holding the full leg amount: final when lots
    /// is every lot, a tranche otherwise (spec/V2.md 4.3).
    pub fn settle(&self, lots: i64) -> TxV2 {
        let held: Vec<i64> = (0..self.n()).map(|j| self.leg(j).amount()).collect();
        self.settle_holding(lots, &held)
    }

    /// The full (final) settle without partial terms.
    pub fn settle_final(&self) -> TxV2 {
        self.settle(self.terms.lot_count)
    }

    /// The settle of `lots` lots with escrow (or KAS vault) j holding `held[j]`.
    #[allow(clippy::needless_range_loop)] // legs, inputs and outputs share the index
    pub fn settle_holding(&self, lots: i64, held: &[i64]) -> TxV2 {
        let n = self.n();
        let signer = self.terms.has_authority.then_some(Who::Authority);
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for i in 0..n {
            let mut input =
                InV2::settle(&self.vaults[i], signer, lots, self.vault_value(i, held[i]));
            input.cov = self.vault_covs[i];
            inputs.push(input);
        }
        let tranche: Vec<i64> = (0..n).map(|j| lots * self.terms.unit(j)).collect();
        let any_tranche = (0..n).any(|j| tranche[j] != held[j]);
        // Deliveries at 0 .. N-1.
        for j in 0..n {
            let leg = self.leg(j);
            outputs.push(if leg.is_token() {
                Out::token(
                    leg.token().compile(self.delivered(j, tranche[j])),
                    leg.tmpl.cov,
                    (n + j) as u16,
                )
            } else {
                Out::kas(tranche[j] as u64, Self::dest_spk(leg.delivery))
            });
        }
        // Escrows at N + j.
        for j in 0..n {
            let leg = self.leg(j);
            if !leg.is_token() {
                continue;
            }
            let mut new_states = vec![self.delivered(j, tranche[j])];
            if tranche[j] != held[j] {
                new_states.push(self.escrow_state(j, held[j] - tranche[j]));
            }
            let at = inputs.len();
            assert_eq!(at, n + j, "KCC-20 legs come first");
            inputs.push(InV2::token(
                leg.token().compile(self.escrow_state(j, held[j])),
                leg.tmpl.cov,
                new_states,
                j as u8,
            ));
        }
        if !any_tranche {
            // Final: authorizers home at N + i.
            for i in 0..n {
                if self.leg(i).is_token() {
                    outputs.push(Out::kas(AUTH, p2pk(self.leg(i).depositor)));
                }
            }
        } else {
            // Tranche: continuations at N + i, remainder tokens at 2N + j.
            for i in 0..n {
                let value = if self.leg(i).is_token() {
                    AUTH
                } else {
                    (held[i] - tranche[i]) as u64
                };
                outputs.push(Out {
                    value,
                    spk: self.vaults[i].p2sh(),
                    cov: self.vault_covs[i].map(|cov| CovenantBinding {
                        authorizing_input: i as u16,
                        covenant_id: cov,
                    }),
                });
            }
            for j in 0..n {
                let leg = self.leg(j);
                if leg.is_token() {
                    outputs.push(Out::token(
                        leg.token()
                            .compile(self.escrow_state(j, held[j] - tranche[j])),
                        leg.tmpl.cov,
                        (n + j) as u16,
                    ));
                }
            }
        }
        inputs.push(InV2::plain(FEE_VALUE));
        outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
        TxV2 {
            inputs,
            outputs,
            lock_time: if self.terms.has_earliest {
                self.terms.earliest_daa as u64
            } else {
                0
            },
        }
    }

    /// A refund of vault UTXO `leg`, signed by `signer`, who names leg `signer_leg` (or N for
    /// the authority). A KCC-20 leg's escrow (holding the full amount) rides at input 1 and goes
    /// home at output 1.
    pub fn refund(&self, leg: usize, signer: Who, signer_leg: i64) -> TxV2 {
        let held = self.leg(leg).amount();
        self.refund_holding(leg, signer, signer_leg, Some(held))
    }

    /// As `refund`, with the escrow holding `held` (None: no token in the transaction).
    pub fn refund_holding(
        &self,
        leg: usize,
        signer: Who,
        signer_leg: i64,
        held: Option<i64>,
    ) -> TxV2 {
        let l = self.leg(leg);
        let value = if l.is_token() {
            AUTH
        } else {
            held.expect("KAS") as u64
        };
        let mut vault_in = InV2::refund(&self.vaults[leg], signer, signer_leg, value);
        vault_in.cov = self.vault_covs[leg];
        let home_spk = if l.is_token() {
            p2pk(l.depositor)
        } else {
            Self::dest_spk(l.refund)
        };
        let mut inputs = vec![vault_in];
        let mut outputs = vec![Out::kas(value, home_spk)];
        if l.is_token() {
            if let Some(held) = held {
                let home = Kcc20State::new(l.refund, held);
                inputs.push(InV2::token(
                    l.token().compile(self.escrow_state(leg, held)),
                    l.tmpl.cov,
                    vec![home],
                    0,
                ));
                outputs.push(Out::token(l.token().compile(home), l.tmpl.cov, 1));
            }
        }
        inputs.push(InV2::plain(FEE_VALUE));
        outputs.push(Out::kas(FEE_VALUE / 2, plain_spk()));
        let signer_key = self.xonly(signer);
        let lock_time = if self.terms.funding_mode == EARMARKED && signer_key == l.depositor {
            self.terms.expiry_daa as u64
        } else {
            0
        };
        TxV2 {
            inputs,
            outputs,
            lock_time,
        }
    }
}

fn terms_for(setup: &Setup, keys: &Keys) -> TermsV2 {
    let legs = setup
        .legs
        .iter()
        .map(|spec| {
            let depositor = keys.xonly(Who::Party(spec.party));
            let recipient = keys.xonly(Who::Party(spec.to));
            match spec.asset {
                Asset::Token(token) => LegV2 {
                    depositor,
                    kind: KIND_KCC20,
                    token: Some(token),
                    tmpl: token.template(),
                    amount_bytes: spec.amount.to_le_bytes(),
                    delivery: Owner::pubkey(recipient),
                    refund: Owner::pubkey(depositor),
                },
                Asset::Kas => LegV2 {
                    depositor,
                    kind: KIND_KAS,
                    token: None,
                    tmpl: TemplateRef::ZERO,
                    amount_bytes: spec.amount.to_le_bytes(),
                    delivery: Owner {
                        id_type: DEST_P2PK,
                        id: recipient,
                    },
                    refund: Owner {
                        id_type: DEST_P2SH,
                        id: kas_refund_hash(spec.party),
                    },
                },
            }
        })
        .collect::<Vec<_>>();
    let (lot_count, min_lot) = setup.partial.unwrap_or((1, 1));
    TermsV2 {
        version: 2,
        network: 0,
        nonce: [0x4E; 8],
        has_authority: setup.authority,
        authority_key: if setup.authority {
            keys.xonly(Who::Authority)
        } else {
            [0; 32]
        },
        leg_count: legs.len() as i64,
        legs,
        legs_extra: vec![],
        legs_cut: 0,
        has_earliest: true,
        earliest_daa: EARLIEST_DAA as i64,
        expiry_daa: EXPIRY_DAA as i64,
        funding_mode: setup.funding,
        trade_ref: [0x7E; 32],
        lot_count,
        min_lot,
    }
}

// =============================================================================================
// Transactions as data
// =============================================================================================

#[derive(Clone)]
pub enum SpendV2 {
    /// P2SH(OpTrue): fee inputs and foreign stand-ins.
    Plain,
    /// ImpulseVaultV2 `settle(authSig, lots)`; the signer's key makes authSig, else 65 zero bytes.
    Settle {
        vault: Compiled,
        signer: Option<Who>,
        lots: i64,
    },
    /// ImpulseVaultV2 `refund(s, signerLeg)`, signed by `signer`.
    Refund {
        vault: Compiled,
        signer: Who,
        signer_leg: i64,
    },
    /// KCC-20 `transfer` as covenant leader.
    Kcc20Leader {
        redeem: Compiled,
        new_states: Vec<Kcc20State>,
        witness: u8,
    },
}

#[derive(Clone)]
pub struct InV2 {
    pub spend: SpendV2,
    pub value: u64,
    pub spk: ScriptPublicKey,
    pub cov: Option<Hash>,
    pub budget: u16,
}

impl InV2 {
    pub fn plain(value: u64) -> Self {
        Self {
            spend: SpendV2::Plain,
            value,
            spk: plain_spk(),
            cov: None,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn settle(vault: &Compiled, signer: Option<Who>, lots: i64, value: u64) -> Self {
        Self {
            spk: vault.p2sh(),
            spend: SpendV2::Settle {
                vault: vault.clone(),
                signer,
                lots,
            },
            value,
            cov: None,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn refund(vault: &Compiled, signer: Who, signer_leg: i64, value: u64) -> Self {
        Self {
            spk: vault.p2sh(),
            spend: SpendV2::Refund {
                vault: vault.clone(),
                signer,
                signer_leg,
            },
            value,
            cov: None,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn token(redeem: Compiled, cov: Hash, new_states: Vec<Kcc20State>, witness: u8) -> Self {
        Self {
            spk: redeem.p2sh(),
            spend: SpendV2::Kcc20Leader {
                redeem,
                new_states,
                witness,
            },
            value: TOKEN_VALUE,
            cov: Some(cov),
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn redeem_len(&self) -> usize {
        match &self.spend {
            SpendV2::Plain => plain_redeem().len(),
            SpendV2::Settle { vault, .. } | SpendV2::Refund { vault, .. } => vault.bytecode().len(),
            SpendV2::Kcc20Leader { redeem, .. } => redeem.bytecode().len(),
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self.spend, SpendV2::Plain)
    }

    pub fn is_vault(&self) -> bool {
        matches!(self.spend, SpendV2::Settle { .. } | SpendV2::Refund { .. })
    }

    pub fn lots_mut(&mut self) -> &mut i64 {
        match &mut self.spend {
            SpendV2::Settle { lots, .. } => lots,
            _ => panic!("not a settle input"),
        }
    }

    pub fn new_states_mut(&mut self) -> &mut Vec<Kcc20State> {
        match &mut self.spend {
            SpendV2::Kcc20Leader { new_states, .. } => new_states,
            _ => panic!("not a token leader"),
        }
    }
}

#[derive(Clone)]
pub struct TxV2 {
    pub inputs: Vec<InV2>,
    pub outputs: Vec<Out>,
    pub lock_time: u64,
}

impl TxV2 {
    /// Materializes the transaction, then signs every vault input that needs a signature
    /// (sighashes do not commit to signature scripts, so signing after assembly is exact).
    pub fn build(&self, w: &WorldV2) -> (Transaction, Vec<UtxoEntry>) {
        let entries: Vec<UtxoEntry> = self
            .inputs
            .iter()
            .map(|i| UtxoEntry::new(i.value, i.spk.clone(), 0, false, i.cov))
            .collect();
        let inputs: Vec<TransactionInput> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(n, i)| {
                TransactionInput::new_with_compute_budget(
                    TransactionOutpoint {
                        transaction_id: TransactionId::from_bytes([n as u8 + 1; 32]),
                        index: 0,
                    },
                    vec![],
                    NON_FINAL,
                    i.budget,
                )
            })
            .collect();
        let outputs: Vec<TransactionOutput> = self
            .outputs
            .iter()
            .map(|o| TransactionOutput {
                value: o.value,
                script_public_key: o.spk.clone(),
                covenant: o.cov,
            })
            .collect();
        let mut tx = Transaction::new(
            1,
            inputs,
            outputs,
            self.lock_time,
            Default::default(),
            0,
            vec![],
        );
        let unsigned = tx.clone();
        for (n, i) in self.inputs.iter().enumerate() {
            tx.inputs[n].signature_script = match &i.spend {
                SpendV2::Plain => push_data(&plain_redeem()),
                SpendV2::Settle {
                    vault,
                    signer,
                    lots,
                } => {
                    let sig = match signer {
                        Some(who) => sign(&unsigned, &entries, n, w.key(*who)),
                        None => vec![0; 65],
                    };
                    vault.entry_sigscript(
                        "settle",
                        &[ArtifactValue::Bytes(sig), ArtifactValue::Int(*lots)],
                    )
                }
                SpendV2::Refund {
                    vault,
                    signer,
                    signer_leg,
                } => {
                    let sig = sign(&unsigned, &entries, n, w.key(*signer));
                    vault.entry_sigscript(
                        "refund",
                        &[ArtifactValue::Bytes(sig), ArtifactValue::Int(*signer_leg)],
                    )
                }
                SpendV2::Kcc20Leader {
                    redeem,
                    new_states,
                    witness,
                } => redeem.covenant_sigscript(
                    "transfer",
                    &transfer_args(new_states, *witness),
                    true,
                ),
            };
        }
        tx.finalize();
        (tx, entries)
    }

    pub fn run(&self, w: &WorldV2, idx: usize) -> Run {
        let (tx, entries) = self.build(w);
        execute(&tx, &entries, idx)
    }

    /// Every non-plain input accepted.
    pub fn assert_all_accepted(&self, w: &WorldV2, label: &str) {
        let (tx, entries) = self.build(w);
        for (n, i) in self.inputs.iter().enumerate() {
            if !i.is_plain() {
                assert_accepted(&execute(&tx, &entries, n), &format!("{label}: input {n}"));
            }
        }
    }

    /// Every vault input refused by the script.
    pub fn assert_every_vault_refused(&self, w: &WorldV2, label: &str) {
        let (tx, entries) = self.build(w);
        for (n, i) in self.inputs.iter().enumerate() {
            if i.is_vault() {
                assert_refused(
                    &execute(&tx, &entries, n),
                    &format!("{label}: vault input {n}"),
                );
            }
        }
    }

    pub fn fee_idx(&self) -> usize {
        self.inputs.len() - 1
    }
}

/// The control must be accepted at every input and the faulty transaction refused by the script
/// at input `idx`. Every refusal test goes through this, so each fault has an accepted twin.
pub fn flips(w: &WorldV2, control: &TxV2, faulty: &TxV2, idx: usize, label: &str) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_refused(&faulty.run(w, idx), label);
}

/// As `flips`, with the control and the fault in two worlds (a crafted state against the honest
/// one).
pub fn flips_across(
    control_world: &WorldV2,
    control: &TxV2,
    faulty_world: &WorldV2,
    faulty: &TxV2,
    idx: usize,
    label: &str,
) {
    control.assert_all_accepted(control_world, &format!("{label} (control)"));
    assert_refused(&faulty.run(faulty_world, idx), label);
}

/// As `flips`, for a refusal by the lock-time check.
pub fn flips_locktime(w: &WorldV2, control: &TxV2, faulty: &TxV2, idx: usize, label: &str) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    let run = faulty.run(w, idx);
    assert!(
        matches!(run.result, Err(TxScriptError::UnsatisfiedLockTime(_))),
        "{label}: expected UnsatisfiedLockTime, got {:?}",
        run.result
    );
}

// =============================================================================================
// Masses
// =============================================================================================

pub struct Masses {
    pub compute: u64,
    pub transient: u64,
    pub storage: Option<u64>,
}

pub fn masses(tx: &Transaction, entries: &[UtxoEntry]) -> Masses {
    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let nc = calc.calc_non_contextual_masses(tx);
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    Masses {
        compute: nc.compute_mass,
        transient: nc.transient_mass,
        storage: calc
            .calc_contextual_masses(&populated)
            .map(|c| c.storage_mass),
    }
}

/// A P2SH scriptPubKey of an arbitrary redeem script (a stand-in owner that is not a vault).
pub fn p2sh_of(redeem: &[u8]) -> ScriptPublicKey {
    pay_to_script_hash_script(redeem)
}
