// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Engine harness for the ImpulseHashlock tests (I18, spec/V2.md section 10). Shared by the
//! `htlc_*` test targets through `mod harness; mod htlc_harness;`. It reuses the v1 harness for
//! compilation, KCC-20 tokens, throwaway keys and the engine, and adds the hashlock terms, the
//! canonical claim and refund transactions, and their builder.
//!
//! Keys: throwaway keypairs from the OS RNG per run, held in memory only, never written or
//! printed, erased on drop (rule 1 exception, docs/ENGINEERING-RULES.md). The secret is a fixed test value, not a
//! key, and nothing here is spendable.

#![allow(dead_code)] // each test target uses a different part of the harness

use crate::harness::*;
use kaspa_consensus_core::tx::{
    Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use secp256k1::Keypair;
use sha2::{Digest, Sha256};
use silverscript_abi::ArtifactValue;

/// The hashlock source under test. `IMPULSE_HASHLOCK_SIL` overrides the path; the mutation run
/// (tests/engine/htlc_mutation.py) uses it to point every test at a mutant.
pub fn hashlock_source() -> String {
    let path = match std::env::var_os("IMPULSE_HASHLOCK_SIL") {
        Some(path) => std::path::PathBuf::from(path),
        None => repo_path("contracts/impulse_hashlock.sil"),
    };
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The test secret (32 bytes, a fixed test value) and a wrong one of the same length.
pub const SECRET: [u8; 32] = [0x5C; 32];
pub const WRONG_SECRET: [u8; 32] = [0x5D; 32];
pub const COUNTERPART_HASH: [u8; 32] = [0xC7; 32];

/// The hashlock terms in the order and form of the ImpulseHashlock constructor (spec/V2.md
/// section 10.2, counterpart record replaced by its hash).
#[derive(Clone, Debug)]
pub struct HtlcTerms {
    pub version: u8,
    pub network: u8,
    pub nonce: [u8; 8],
    pub seller_key: [u8; 32],
    pub buyer_key: [u8; 32],
    pub asset: TemplateRef,
    pub amount: i64,
    pub buyer_delivery: Owner,
    pub seller_refund: Owner,
    pub hash_lock: [u8; 32],
    pub expiry_daa: i64,
    pub counterpart_hash: [u8; 32],
    pub trade_ref: [u8; 32],
}

impl HtlcTerms {
    pub fn ctor(&self) -> Vec<ArtifactValue> {
        use ArtifactValue::{Byte, Bytes, Int};
        vec![
            Byte(self.version),
            Byte(self.network),
            Bytes(self.nonce.to_vec()),
            Bytes(self.seller_key.to_vec()),
            Bytes(self.buyer_key.to_vec()),
            Bytes(self.asset.cov.as_bytes().to_vec()),
            Bytes(self.asset.hash.to_vec()),
            Int(self.asset.prefix_len),
            Int(self.asset.suffix_len),
            Int(self.amount),
            Byte(self.buyer_delivery.id_type),
            Bytes(self.buyer_delivery.id.to_vec()),
            Byte(self.seller_refund.id_type),
            Bytes(self.seller_refund.id.to_vec()),
            Bytes(self.hash_lock.to_vec()),
            Int(self.expiry_daa),
            Bytes(self.counterpart_hash.to_vec()),
            Bytes(self.trade_ref.to_vec()),
        ]
    }

    pub fn vault(&self) -> Compiled {
        Compiled::new(&hashlock_source(), &self.ctor())
    }
}

/// The parties' throwaway keys, the terms and the compiled vault.
pub struct HtlcWorld {
    pub terms: HtlcTerms,
    pub vault: Compiled,
    keys: [TestKey; 4],
}

impl HtlcWorld {
    pub fn new() -> Self {
        let keys = [
            random_keypair(),
            random_keypair(),
            random_keypair(),
            random_keypair(),
        ];
        let terms = HtlcTerms {
            version: 1,
            network: 1,
            nonce: [0x4E; 8],
            seller_key: xonly(&keys[Role::Seller as usize]),
            buyer_key: xonly(&keys[Role::Buyer as usize]),
            asset: ASSET_TOKEN.template(),
            amount: AMOUNT_A,
            buyer_delivery: BUYER_DELIVERY,
            seller_refund: SELLER_REFUND,
            hash_lock: sha256(&SECRET),
            expiry_daa: EXPIRY_DAA as i64,
            counterpart_hash: COUNTERPART_HASH,
            trade_ref: [0x7E; 32],
        };
        let vault = terms.vault();
        Self { terms, vault, keys }
    }

    /// The same parties (same keys) with the terms changed by `edit`.
    pub fn edit(self, edit: impl FnOnce(&mut HtlcTerms)) -> Self {
        let HtlcWorld {
            mut terms, keys, ..
        } = self;
        edit(&mut terms);
        let vault = terms.vault();
        Self { terms, vault, keys }
    }

    pub fn key(&self, role: Role) -> &Keypair {
        &self.keys[role as usize]
    }

    pub fn xonly(&self, role: Role) -> [u8; 32] {
        xonly(self.key(role))
    }

    /// The escrowed token: owned by the vault's script hash, exactly the amount.
    pub fn escrow_state(&self) -> Kcc20State {
        Kcc20State::new(
            Owner::script_hash(self.vault.script_hash()),
            self.terms.amount,
        )
    }

    pub fn delivered(&self) -> Kcc20State {
        Kcc20State::new(self.terms.buyer_delivery, self.terms.amount)
    }

    pub fn home(&self) -> Kcc20State {
        Kcc20State::new(self.terms.seller_refund, self.terms.amount)
    }

    /// The canonical claim (spec/V2.md section 10.4): vault at input 0, escrowed token at input 1
    /// (transfer leader, witness 0), then a fee input; output 0 the asset to the buyer, output 1
    /// the authorizer KAS to the seller, then change. Lock time 0.
    pub fn claim(&self, secret: &[u8]) -> HtlcTx {
        HtlcTx {
            inputs: vec![
                HIn::claim(&self.vault, secret, AUTH_VALUE),
                HIn::token(
                    ASSET_TOKEN.compile(self.escrow_state()),
                    ASSET_COV,
                    vec![self.delivered()],
                    0,
                ),
                HIn::plain(FEE_VALUE),
            ],
            outputs: vec![
                Out::token(ASSET_TOKEN.compile(self.delivered()), ASSET_COV, 1),
                Out::kas(AUTH_VALUE, p2pk(self.xonly(Role::Seller))),
                Out::kas(FEE_VALUE / 2, plain_spk()),
            ],
            lock_time: 0,
        }
    }

    /// A refund signed by `signer` (named as itself), the escrowed token riding at input 1 and
    /// returning home at output 1. Lock time expiry_daa for the seller, 0 for anyone else.
    pub fn refund(&self, signer: Role) -> HtlcTx {
        HtlcTx {
            inputs: vec![
                HIn::refund(&self.vault, self.xonly(signer), signer, AUTH_VALUE),
                HIn::token(
                    ASSET_TOKEN.compile(self.escrow_state()),
                    ASSET_COV,
                    vec![self.home()],
                    0,
                ),
                HIn::plain(FEE_VALUE),
            ],
            outputs: vec![
                Out::kas(AUTH_VALUE, p2pk(self.xonly(Role::Seller))),
                Out::token(ASSET_TOKEN.compile(self.home()), ASSET_COV, 1),
                Out::kas(FEE_VALUE / 2, plain_spk()),
            ],
            lock_time: if signer == Role::Seller {
                EXPIRY_DAA
            } else {
                0
            },
        }
    }
}

impl Default for HtlcWorld {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub enum HSpend {
    /// P2SH(OpTrue): fee inputs and foreign stand-ins.
    Plain,
    /// ImpulseHashlock `settleWithPreimage(secret)`.
    Claim { vault: Compiled, secret: Vec<u8> },
    /// ImpulseHashlock `refund`: `named` is the pubkey argument, `signer` makes the signature.
    Refund {
        vault: Compiled,
        named: [u8; 32],
        signer: Role,
    },
    /// KCC-20 `transfer` as covenant leader.
    Kcc20Leader {
        redeem: Compiled,
        new_states: Vec<Kcc20State>,
        witness: u8,
    },
    /// KCC-20 `transfer` as covenant delegate.
    Kcc20Delegate { redeem: Compiled, witness: u8 },
}

#[derive(Clone)]
pub struct HIn {
    pub spend: HSpend,
    pub value: u64,
    pub spk: kaspa_consensus_core::tx::ScriptPublicKey,
    pub cov: Option<Hash>,
    pub sequence: u64,
    pub budget: u16,
}

impl HIn {
    pub fn plain(value: u64) -> Self {
        Self {
            spend: HSpend::Plain,
            value,
            spk: plain_spk(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn claim(vault: &Compiled, secret: &[u8], value: u64) -> Self {
        Self {
            spend: HSpend::Claim {
                vault: vault.clone(),
                secret: secret.to_vec(),
            },
            value,
            spk: vault.p2sh(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn refund(vault: &Compiled, named: [u8; 32], signer: Role, value: u64) -> Self {
        Self {
            spend: HSpend::Refund {
                vault: vault.clone(),
                named,
                signer,
            },
            value,
            spk: vault.p2sh(),
            cov: None,
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// A KCC-20 UTXO of covenant `cov` spent as transfer leader, the witness at input `witness`.
    pub fn token(redeem: Compiled, cov: Hash, new_states: Vec<Kcc20State>, witness: u8) -> Self {
        Self {
            spk: redeem.p2sh(),
            spend: HSpend::Kcc20Leader {
                redeem,
                new_states,
                witness,
            },
            value: TOKEN_VALUE,
            cov: Some(cov),
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    /// A KCC-20 UTXO of covenant `cov` spent as transfer delegate.
    pub fn token_delegate(redeem: Compiled, cov: Hash, witness: u8) -> Self {
        Self {
            spk: redeem.p2sh(),
            spend: HSpend::Kcc20Delegate { redeem, witness },
            value: TOKEN_VALUE,
            cov: Some(cov),
            sequence: NON_FINAL,
            budget: GENEROUS_BUDGET,
        }
    }

    pub fn redeem_len(&self) -> usize {
        match &self.spend {
            HSpend::Plain => plain_redeem().len(),
            HSpend::Claim { vault, .. } | HSpend::Refund { vault, .. } => vault.bytecode().len(),
            HSpend::Kcc20Leader { redeem, .. } | HSpend::Kcc20Delegate { redeem, .. } => {
                redeem.bytecode().len()
            }
        }
    }

    /// The new states of a token leader input.
    pub fn leader_states(&mut self) -> &mut Vec<Kcc20State> {
        match &mut self.spend {
            HSpend::Kcc20Leader { new_states, .. } => new_states,
            _ => panic!("not a token leader"),
        }
    }
}

#[derive(Clone)]
pub struct HtlcTx {
    pub inputs: Vec<HIn>,
    pub outputs: Vec<Out>,
    pub lock_time: u64,
}

impl HtlcTx {
    /// Materializes the transaction, then signs every refund input (sighashes do not commit to
    /// signature scripts, so signing after assembly is exact).
    pub fn build(&self, w: &HtlcWorld) -> (Transaction, Vec<UtxoEntry>) {
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
                    i.sequence,
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
                HSpend::Plain => push_data(&plain_redeem()),
                HSpend::Claim { vault, secret } => vault.entry_sigscript(
                    "settleWithPreimage",
                    &[ArtifactValue::Bytes(secret.clone())],
                ),
                HSpend::Refund {
                    vault,
                    named,
                    signer,
                } => {
                    let sig = sign(&unsigned, &entries, n, w.key(*signer));
                    vault.entry_sigscript(
                        "refund",
                        &[
                            ArtifactValue::Bytes(sig),
                            ArtifactValue::Bytes(named.to_vec()),
                        ],
                    )
                }
                HSpend::Kcc20Leader {
                    redeem,
                    new_states,
                    witness,
                } => redeem.covenant_sigscript(
                    "transfer",
                    &transfer_args(new_states, *witness),
                    true,
                ),
                HSpend::Kcc20Delegate { redeem, witness } => redeem.covenant_sigscript(
                    "transfer",
                    &[
                        ArtifactValue::Bytes(vec![0; 65]),
                        ArtifactValue::Byte(*witness),
                    ],
                    false,
                ),
            };
        }
        tx.finalize();
        (tx, entries)
    }

    pub fn run(&self, w: &HtlcWorld, idx: usize) -> Run {
        let (tx, entries) = self.build(w);
        execute(&tx, &entries, idx)
    }

    /// Every input except the plain ones, accepted.
    pub fn assert_all_accepted(&self, w: &HtlcWorld, label: &str) {
        let (tx, entries) = self.build(w);
        for (n, i) in self.inputs.iter().enumerate() {
            if !matches!(i.spend, HSpend::Plain) {
                assert_accepted(&execute(&tx, &entries, n), &format!("{label}: input {n}"));
            }
        }
    }

    pub fn fee_idx(&self) -> usize {
        self.inputs.len() - 1
    }
}

/// The control must be accepted at every input and the faulty transaction refused by the
/// script at input `idx`. Every refusal test goes through this, so each fault has an accepted twin.
pub fn assert_htlc_flips(
    w: &HtlcWorld,
    control: &HtlcTx,
    faulty: &HtlcTx,
    idx: usize,
    label: &str,
) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_refused(&faulty.run(w, idx), label);
}

/// As `assert_htlc_flips`, for a refusal by the lock-time check.
pub fn assert_htlc_flips_locktime(
    w: &HtlcWorld,
    control: &HtlcTx,
    faulty: &HtlcTx,
    idx: usize,
    label: &str,
) {
    control.assert_all_accepted(w, &format!("{label} (control)"));
    assert_locktime_refused(&faulty.run(w, idx), label);
}

/// A token owner whose witness is any plain P2SH(OpTrue) input (the fee input here).
pub fn standin_owner() -> Owner {
    Owner::script_hash(p2sh_hash(&plain_spk()))
}

pub fn stranger(amount: i64) -> Kcc20State {
    Kcc20State::new(STRANGER_OWNER, amount)
}
