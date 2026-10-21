// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Shared by the v4_* test targets (spec/V3-ZK.md section 22.9): worlds for template v4 (the
//! hashed-terms vault), the host-side journal builder that mirrors the vault script, the witness
//! the terms guest reads, and loaders for the committed proof fixtures.
//!
//! Two kinds of world. A FIXED world has public keys only (the multiples G to 7G of the curve's
//! generator: no private key exists in this repository, rule 1, docs/ENGINEERING-RULES.md), so its vault
//! scriptPubKey and its journal are the same on every run and a Groth16 proof for it can be
//! committed. It cannot sign: its authority signature is impossible, which is why `[T4]` and `[T5]`
//! run after the proof gate. A LIVE world uses the harness's throwaway keys, generated at run time,
//! and its proofs are made at test time (v4_live.rs).
//!
//! A PROBE world compiles the v4 source with the verify call replaced by a comparison with
//! sha256(J) (harness::v4_probe_source), so every script require and every field of J run without
//! a receipt. It is a different script from template v4 and says nothing about the gate itself.

#![allow(dead_code)]

pub use crate::harness::v4_core::*;
use crate::harness::*;
use silverscript_abi::ArtifactValue;
use std::path::PathBuf;
use terms_core::codec as tc;
use terms_core::hashes as th;
use terms_core::journal::Journal;

pub const P1: [u8; 32] = hex32("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
pub const P2: [u8; 32] = hex32("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
pub const P3: [u8; 32] = hex32("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
pub const P4: [u8; 32] = hex32("e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13");
pub const P5: [u8; 32] = hex32("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4");
pub const P6: [u8; 32] = hex32("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556");
pub const P7: [u8; 32] = hex32("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc");

pub const SELLER_KEY: [u8; 32] = P2;
pub const BUYER_KEY: [u8; 32] = P4;
pub const AUTHORITY_KEY: [u8; 32] = P3;
const DELIVERY_KEY: [u8; 32] = P5;
const PROCEEDS_KEY: [u8; 32] = P6;
const SELLER_REFUND_KEY: [u8; 32] = P7;

/// Script units the gate alone costs at least: the Groth16 precompile's fixed cost (14,000,000).
pub const GATE_FLOOR_UNITS: u64 = 14_000_000;
pub const BLIND: [u8; 32] = [0xBD; 32];

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex digit"),
    }
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn proof_dir() -> PathBuf {
    repo_path("tests/engine/fixtures/v4/proofs")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The real template v4 (contracts/impulse_vault_v4.sil).
    Real,
    /// The probe: the verify call replaced by a comparison with sha256(J).
    Probe,
}

impl Kind {
    /// The real precompile runs (no probe comparison).
    pub fn is_real(self) -> bool {
        self == Kind::Real
    }
}

pub struct V4 {
    pub w: World,
    pub core: tc::Terms,
    pub kind: Kind,
    pub asset: Compiled,
    pub cash: Option<Compiled>,
    pub fixed: bool,
}

/// The v4 vault of `leg` for a commitment and an authority key.
pub fn compile_vault(kind: Kind, commit: [u8; 32], authority: [u8; 32]) -> Compiled {
    let src = match kind {
        Kind::Real => vault_v4_source(),
        Kind::Probe => v4_probe_source(),
    };
    Compiled::new(
        &src,
        &[
            ArtifactValue::Bytes(commit.to_vec()),
            ArtifactValue::Bytes(authority.to_vec()),
        ],
    )
}

impl V4 {
    /// A fixed (public keys only) world. `nonce` makes sibling trades.
    pub fn fixed(kind: Kind, cash: u8, funding: u8, nonce: u8) -> V4 {
        Self::build(kind, Mode::new(true, cash, funding), true, nonce)
    }

    /// A live world: the harness's throwaway keys, the authority included.
    pub fn live(kind: Kind, cash: u8, funding: u8) -> V4 {
        Self::build(kind, Mode::new(true, cash, funding), false, 0x4E)
    }

    fn build(kind: Kind, mode: Mode, fixed: bool, nonce: u8) -> V4 {
        let w = World::with(mode, |t, _| {
            t.version = 4;
            t.nonce = [nonce; 8];
            if fixed {
                t.seller_key = SELLER_KEY;
                t.buyer_key = BUYER_KEY;
                t.authority_key = AUTHORITY_KEY;
            }
            // owners and destinations that must be curve points (the guest checks them)
            t.buyer_delivery = Owner::pubkey(DELIVERY_KEY);
            t.seller_refund = Owner::pubkey(SELLER_REFUND_KEY);
            if mode.cash == CASH_KCC20 {
                t.seller_proceeds = Owner::pubkey(PROCEEDS_KEY);
            }
            if mode.cash == CASH_KAS {
                t.seller_proceeds_spk = spk_bytes(&p2pk(PROCEEDS_KEY));
            }
        });
        let core = core_terms(&w.terms, BLIND);
        terms_core::structure::validate(&core, true)
            .expect("the fixture terms pass the structure checks");
        let h = th::terms_hash(&core.encode());
        let auth = core.authority.expect("authority");
        let asset = compile_vault(kind, th::commit(&h, 0), auth);
        let cash =
            (mode.cash != CASH_EXTERNAL).then(|| compile_vault(kind, th::commit(&h, 1), auth));
        let w = w.with_vaults(asset.clone(), cash.clone());
        V4 {
            w,
            core,
            kind,
            asset,
            cash,
            fixed,
        }
    }

    pub fn commit(&self, leg: u8) -> [u8; 32] {
        th::commit(&th::terms_hash(&self.core.encode()), leg)
    }

    pub fn authority(&self) -> [u8; 32] {
        self.core.authority.expect("authority")
    }

    pub fn shape(&self) -> (usize, usize) {
        match self.w.mode.cash {
            CASH_KAS => (3, 3),
            CASH_KCC20 => (4, 4),
            _ => (2, 2),
        }
    }

    pub fn shape_i64(&self) -> (i64, i64) {
        let (a, b) = self.shape();
        (a as i64, b as i64)
    }

    pub fn cov_c(&self) -> [u8; 32] {
        if self.w.mode.cash == CASH_KCC20 {
            CASH_COV.as_bytes()
        } else {
            [0; 32]
        }
    }

    /// Fixes what the base world builds from constants rather than from the terms.
    fn patch(&self, spec: &mut TxSpec) {
        if self.w.mode.cash == CASH_KAS {
            let proceeds = p2pk(PROCEEDS_KEY);
            spec.outputs[1].spk = proceeds;
        }
    }

    /// The canonical settle with every vault input carrying `proof_of(idx)` and the authority's
    /// signature (a fixed world cannot sign, so its authority signature is the zero signature).
    pub fn settle(&self, proofs: &Proofs) -> TxSpec {
        let mut spec = self.w.settle();
        self.patch(&mut spec);
        let (n_in, n_out) = self.shape();
        let cov_a = ASSET_COV.as_bytes();
        let cov_c = self.cov_c();
        let signer = (!self.is_fixed()).then_some(Role::Authority);
        let vaults = if self.w.external() { 1 } else { 2 };
        for idx in 0..vaults {
            let vault = self.w.vault(idx as i64).clone();
            let value = spec.inputs[idx].value;
            spec.inputs[idx] = In::settle_v4(
                &vault,
                signer,
                value,
                vec![0; 128],
                (n_in as i64, n_out as i64),
                (cov_a, cov_c),
            );
        }
        self.fill(&mut spec, proofs);
        spec
    }

    /// A refund of the vault of `leg` named `named`, signed by `signer`'s throwaway key.
    pub fn refund(&self, leg: i64, named: Role, proofs: &Proofs) -> TxSpec {
        let mut spec = self.w.refund(leg, named);
        let named_key = self.w.xonly(named);
        let vault = self.w.vault(leg).clone();
        let value = spec.inputs[0].value;
        let n = spec.inputs.len() - 1; // the fee input is not in the view
        let is_asset = leg == ASSET_LEG;
        let kas_cash = !is_asset && self.w.mode.cash == CASH_KAS;
        let cov = if kas_cash || (!is_asset && self.w.mode.cash == CASH_EXTERNAL) {
            [0; 32]
        } else if is_asset {
            ASSET_COV.as_bytes()
        } else {
            CASH_COV.as_bytes()
        };
        spec.inputs[0] = In::refund_v4(
            &vault,
            named_key,
            (!self.is_fixed()).then_some(named),
            value,
            leg as u8,
            vec![0; 128],
            (n as i64, n as i64),
            cov,
        );
        self.fill(&mut spec, proofs);
        spec
    }

    pub fn is_fixed(&self) -> bool {
        self.fixed
    }

    /// The entry arguments of the vault input `idx` of `spec`.
    pub fn entry_of(&self, spec: &TxSpec, idx: usize) -> Entry {
        match &spec.inputs[idx].spend {
            Spend::SettleV4 {
                n_in,
                n_out,
                cov_a,
                cov_c,
                ..
            } => Entry::Settle {
                n_in: *n_in as usize,
                n_out: *n_out as usize,
                cov_a: *cov_a,
                cov_c: *cov_c,
            },
            Spend::RefundV4 {
                named,
                leg,
                n_in,
                n_out,
                cov,
                ..
            } => Entry::Refund {
                leg: *leg,
                signer: *named,
                n_in: *n_in as usize,
                n_out: *n_out as usize,
                cov: *cov,
            },
            _ => panic!("input {idx} is not a v4 vault input"),
        }
    }

    /// The journal the vault at input `idx` of `spec` computes for itself.
    pub fn journal(&self, spec: &TxSpec, idx: usize) -> Journal {
        let (tx, entries) = spec.build(&self.w);
        let leg = match &spec.inputs[idx].spend {
            Spend::SettleV4 { .. } => idx as u8,
            Spend::RefundV4 { leg, .. } => *leg,
            _ => panic!("not a v4 vault input"),
        };
        journal_of(
            &tx,
            &entries,
            idx,
            self.entry_of(spec, idx),
            self.commit(leg),
            self.authority(),
        )
    }

    /// The witness the terms guest reads for input `idx` of `spec`.
    pub fn witness(&self, spec: &TxSpec, idx: usize) -> terms_core::Witness {
        let j = self.journal(spec, idx);
        let n_in = j.inputs.len();
        let redeems = (0..n_in)
            .filter_map(|i| match &spec.inputs[i].spend {
                Spend::Kcc20Leader { redeem, .. } | Spend::Kcc20Delegate { redeem, .. } => {
                    Some((i as u8, redeem.bytecode().to_vec()))
                }
                // a vault's own redeem script ([H5], spec/V3-ZK.md 22.16)
                Spend::SettleV4 { vault, .. } | Spend::RefundV4 { vault, .. } => {
                    Some((i as u8, vault.bytecode().to_vec()))
                }
                _ => None,
            })
            .collect();
        terms_core::Witness {
            terms: self.core.encode(),
            journal: j.to_bytes(),
            redeems,
        }
    }

    fn vault_inputs(&self, spec: &TxSpec) -> Vec<usize> {
        (0..spec.inputs.len())
            .filter(|i| {
                matches!(
                    spec.inputs[*i].spend,
                    Spend::SettleV4 { .. } | Spend::RefundV4 { .. }
                )
            })
            .collect()
    }

    /// Sets the proofs of the vault inputs: probe proofs are sha256(J) of each; given proofs by index.
    fn fill(&self, spec: &mut TxSpec, proofs: &Proofs) {
        for idx in self.vault_inputs(spec) {
            let proof = match proofs {
                Proofs::Zeros => vec![0; 128],
                Proofs::Probe if self.kind.is_real() => vec![0; 128],
                Proofs::Probe => th::sha256(&self.journal(spec, idx).to_bytes()).to_vec(),
                Proofs::Given(v) => v
                    .iter()
                    .find(|(i, _)| *i == idx)
                    .map_or(vec![0; 128], |(_, p)| p.clone()),
            };
            set_proof(&mut spec.inputs[idx], proof);
        }
    }

    /// Recomputes the probe proof of every vault input from the transaction as it now is.
    pub fn reprobe(&self, spec: &mut TxSpec) {
        self.fill(spec, &Proofs::Probe);
    }

    /// Zero proofs at every vault input (for a spec whose journal cannot be built).
    pub fn fill_zeros(&self, spec: &mut TxSpec) {
        self.fill(spec, &Proofs::Zeros);
    }

    pub fn with_proof(&self, spec: &mut TxSpec, idx: usize, proof: Vec<u8>) {
        set_proof(&mut spec.inputs[idx], proof);
    }
}

/// A cash token owned by the asset vault (sent there by mistake), at input `at`, moved to a
/// stranger by an output before the change: the case of known limitation L20.
pub fn misdirected_cash_token(v: &V4, spec: &mut TxSpec, at: usize) {
    let held = Kcc20State::new(
        Owner::script_hash(v.w.asset_vault.script_hash()),
        v.w.terms.amount_b,
    );
    let taken = Kcc20State::new(STRANGER_OWNER, v.w.terms.amount_b);
    spec.inputs.insert(
        at,
        In::token(CASH_TOKEN.compile(held), CASH_COV, vec![taken], 0),
    );
    let out_at = spec.outputs.len() - 1;
    spec.outputs.insert(
        out_at,
        Out::token(CASH_TOKEN.compile(taken), CASH_COV, at as u16),
    );
}

pub enum Proofs {
    /// 128 zero bytes at every vault input.
    Zeros,
    /// sha256(J), for the probe.
    Probe,
    /// (input index, proof).
    Given(Vec<(usize, Vec<u8>)>),
}

pub fn set_proof(input: &mut In, new: Vec<u8>) {
    match &mut input.spend {
        Spend::SettleV4 { proof, .. } | Spend::RefundV4 { proof, .. } => *proof = new,
        _ => panic!("not a v4 vault input"),
    }
}

/// A proof fixture: the 128 proof bytes and the J it was made for.
pub struct Fixture {
    pub proof: Vec<u8>,
    pub journal: Vec<u8>,
    pub image_id: [u8; 32],
}

pub fn fixture(name: &str) -> Fixture {
    let path = proof_dir().join(format!("{name}.proof.json"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&text).expect("proof json");
    Fixture {
        proof: unhex(v["proof"].as_str().expect("proof")),
        journal: unhex(v["journal"].as_str().expect("journal")),
        image_id: unhex(v["image_id"].as_str().expect("image id"))
            .try_into()
            .expect("32 bytes"),
    }
}

use kaspa_txscript_errors::TxScriptError;

/// The proof gate refused: the precompile failed (ZkIntegrity), after its fixed cost was charged.
pub fn assert_gate_refused(run: &Run, label: &str) {
    assert!(
        matches!(run.result, Err(TxScriptError::ZkIntegrity(_))),
        "{label}: expected a ZkIntegrity refusal from the precompile, got {:?}",
        run.result
    );
    assert!(
        run.used.0 >= GATE_FLOOR_UNITS,
        "{label}: the precompile's cost was not charged ({} units)",
        run.used.0
    );
}

/// A script refusal that came before the proof gate: fewer units than the precompile's fixed cost.
pub fn assert_refused_before_gate(run: &Run, label: &str) {
    assert!(run.result.is_err(), "{label}: expected a refusal");
    assert!(
        !matches!(run.result, Err(TxScriptError::ZkIntegrity(_))),
        "{label}: the gate refused: {:?}",
        run.result
    );
    assert!(
        run.used.0 < GATE_FLOOR_UNITS,
        "{label}: refused after the gate ({} units): {:?}",
        run.used.0,
        run.result
    );
}

/// The run got past the gate (the precompile accepted) and a later check refused it.
pub fn assert_refused_after_gate(run: &Run, label: &str) {
    assert!(run.result.is_err(), "{label}: expected a refusal");
    assert!(
        !matches!(run.result, Err(TxScriptError::ZkIntegrity(_))),
        "{label}: the gate refused: {:?}",
        run.result
    );
    assert!(
        run.used.0 >= GATE_FLOOR_UNITS,
        "{label}: refused before the gate ({} units): {:?}",
        run.used.0,
        run.result
    );
}
