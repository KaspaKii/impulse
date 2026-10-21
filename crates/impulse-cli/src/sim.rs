// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The offline fake node (spec/CLI.md, "Offline fake node (tests only)"): a linear chain, a UTXO
//! set and a virtual DAA score, kept in memory for unit tests or in a state file for the scripts'
//! end-to-end test. It is compiled only into tests and into builds with the `offline-fake-node`
//! feature, which is off by default.
//!
//! On submit it applies the rules a test needs, in this order: every input unspent and spent
//! once, outputs no more than inputs, the lock time by the node rule ported in impulse-core
//! (`locktime::check_tx_is_finalized`, at the virtual DAA score as the mempool applies it), and
//! every input run in the pinned script engine at its committed budget with covenants enabled.
//! Then a new chain block accepts the transaction. It is not a node and proves nothing about one.

use crate::error::CliError;
use crate::funds::address_script;
use crate::node::{AcceptedTx, AcceptedUpdate, BlockInfo, ChainUpdate, DagInfo, Node, ServerInfo};
use borsh::{BorshDeserialize, BorshSerialize};
use impulse_core::locktime::check_tx_is_finalized;
use impulse_core::terms::Network;
use impulse_core::tx::Utxo;
use kaspa_addresses::Address;
use kaspa_consensus_core::config::params::{MAINNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
    VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// One chain block and the transactions it accepted, each with the UTXO entries it spent.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct SimBlock {
    hash: [u8; 32],
    daa: u64,
    txs: Vec<Transaction>,
    spent: Vec<Vec<UtxoEntry>>,
}

/// The whole state of a fake node.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SimState {
    mainnet: bool,
    pub synced: bool,
    pub virtual_daa: u64,
    /// DAA scores added to the virtual DAA score at every `get_block_dag_info` call.
    pub tick: u64,
    /// Every block reports `is_chain_block: false` (a reorg of the accepting block).
    pub off_chain: bool,
    counter: u64,
    chain: Vec<SimBlock>,
    utxos: Vec<(TransactionOutpoint, UtxoEntry)>,
}

fn tagged(tag: &[u8], n: u64) -> [u8; 32] {
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/fake-node")
        .to_state()
        .update(tag)
        .update(&n.to_le_bytes())
        .finalize();
    digest.as_bytes().try_into().expect("32 bytes")
}

fn network_of(mainnet: bool) -> Network {
    if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    }
}

impl SimState {
    /// A synced node on `network` with a genesis block at `daa`.
    pub fn new(network: Network, daa: u64, tick: u64) -> Self {
        Self {
            mainnet: network == Network::Mainnet,
            synced: true,
            virtual_daa: daa,
            tick,
            off_chain: false,
            counter: 0,
            chain: vec![SimBlock {
                hash: tagged(b"genesis", 0),
                daa,
                txs: vec![],
                spent: vec![],
            }],
            utxos: vec![],
        }
    }

    pub fn network(&self) -> Network {
        network_of(self.mainnet)
    }

    /// Adds a UTXO from nowhere (a test's starting balance) and returns its outpoint.
    pub fn add_utxo(
        &mut self,
        spk: ScriptPublicKey,
        amount: u64,
        covenant_id: Option<[u8; 32]>,
    ) -> TransactionOutpoint {
        self.counter += 1;
        let outpoint = TransactionOutpoint::new(Hash::from_bytes(tagged(b"utxo", self.counter)), 0);
        let entry = UtxoEntry::new(
            amount,
            spk,
            self.virtual_daa,
            false,
            covenant_id.map(Hash::from_bytes),
        );
        self.utxos.push((outpoint, entry));
        outpoint
    }

    /// Adds a UTXO from nowhere at a chosen outpoint: for a test that needs one below or above
    /// another.
    #[cfg(test)]
    pub fn add_utxo_at(
        &mut self,
        outpoint: TransactionOutpoint,
        spk: ScriptPublicKey,
        amount: u64,
    ) -> TransactionOutpoint {
        let entry = UtxoEntry::new(amount, spk, self.virtual_daa, false, None);
        self.utxos.push((outpoint, entry));
        outpoint
    }

    pub fn sink(&self) -> [u8; 32] {
        self.chain.last().expect("genesis").hash
    }

    /// Chain length, genesis included.
    pub fn height(&self) -> usize {
        self.chain.len()
    }

    fn position(&self, hash: &[u8; 32]) -> Option<usize> {
        self.chain.iter().position(|b| &b.hash == hash)
    }

    pub fn utxos_at(&self, spk: &ScriptPublicKey) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter(|(_, e)| &e.script_public_key == spk)
            .map(|(o, e)| Utxo {
                outpoint: *o,
                entry: e.clone(),
            })
            .collect()
    }

    /// Applies a transaction as described in the module documentation; returns its ID.
    pub fn submit(&mut self, tx: &Transaction) -> Result<[u8; 32], String> {
        let mut entries = Vec::with_capacity(tx.inputs.len());
        for (i, input) in tx.inputs.iter().enumerate() {
            if tx.inputs[..i]
                .iter()
                .any(|o| o.previous_outpoint == input.previous_outpoint)
            {
                return Err(format!("input {i} spends an outpoint twice"));
            }
            let entry = self
                .utxos
                .iter()
                .find(|(o, _)| *o == input.previous_outpoint)
                .map(|(_, e)| e.clone())
                .ok_or_else(|| format!("input {i}: the outpoint is not in the UTXO set"))?;
            entries.push(entry);
        }
        let held: u128 = entries.iter().map(|e| u128::from(e.amount)).sum();
        let paid: u128 = tx.outputs.iter().map(|o| u128::from(o.value)).sum();
        if paid > held {
            return Err("the outputs pay more than the inputs hold".into());
        }
        check_tx_is_finalized(tx, self.virtual_daa, 0)
            .map_err(|e| format!("not final at virtual DAA score {}: {e}", self.virtual_daa))?;
        run_engine(tx, &entries, self.network())?;
        Ok(self.apply(tx, entries))
    }

    /// Accepts a transaction with no inputs in a new chain block without any check: a test's
    /// stand-in for a transaction some other wallet had accepted, for the checks that read
    /// accepted transactions (`xchain verify-funding`, `xchain status`).
    #[cfg(test)]
    pub fn accept_unchecked(&mut self, tx: &Transaction) -> [u8; 32] {
        assert!(tx.inputs.is_empty(), "accept_unchecked takes no inputs");
        self.apply(tx, vec![])
    }

    /// Spends the inputs, adds the outputs and a chain block accepting `tx`; returns its ID.
    fn apply(&mut self, tx: &Transaction, entries: Vec<UtxoEntry>) -> [u8; 32] {
        let daa = self.virtual_daa + 1;
        self.utxos
            .retain(|(o, _)| !tx.inputs.iter().any(|i| i.previous_outpoint == *o));
        let id = tx.id();
        for (index, output) in tx.outputs.iter().enumerate() {
            let entry = UtxoEntry::new(
                output.value,
                output.script_public_key.clone(),
                daa,
                false,
                output.covenant.map(|c| c.covenant_id),
            );
            self.utxos
                .push((TransactionOutpoint::new(id, index as u32), entry));
        }
        let height = self.chain.len() as u64;
        self.chain.push(SimBlock {
            hash: tagged(b"block", height),
            daa,
            txs: vec![tx.clone()],
            spent: vec![entries],
        });
        self.virtual_daa = daa;
        id.as_bytes()
    }
}

/// Runs every input of `tx` in the pinned script engine at its committed budget, covenants
/// enabled, as consensus does after Toccata.
fn run_engine(tx: &Transaction, entries: &[UtxoEntry], network: Network) -> Result<(), String> {
    let params = match network {
        Network::Mainnet => &MAINNET_PARAMS,
        Network::Testnet => &TESTNET_PARAMS,
    };
    let flags = EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(params.mass_per_sig_op).into(),
    };
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants = CovenantsContext::from_tx(&populated).map_err(|e| format!("covenants: {e}"))?;
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(1_000);
    for i in 0..tx.inputs.len() {
        let (input, utxo) = populated.populated_input(i);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            i,
            utxo,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&covenants),
            flags,
            input.compute_commit.allowed_script_units(),
        );
        vm.execute()
            .map_err(|e| format!("input {i} refused by the script engine: {e}"))?;
    }
    Ok(())
}

/// A fake node over a shared state, saved to `path` after every change when it has one.
#[derive(Clone)]
pub struct SimNode {
    pub state: Rc<RefCell<SimState>>,
    path: Option<PathBuf>,
}

fn fake(what: &str, e: impl std::fmt::Display) -> CliError {
    CliError::new("CLI_NODE_RPC", format!("{what}: {:?}", e.to_string()))
}

impl SimNode {
    /// An in-memory fake node (tests).
    pub fn memory(state: SimState) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            path: None,
        }
    }

    /// A fake node kept in a state file.
    pub fn open(path: &Path) -> Result<Self, CliError> {
        let bytes = std::fs::read(path).map_err(|e| {
            CliError::new("CLI_NODE_UNREACHABLE", format!("{}: {e}", path.display()))
        })?;
        let state = SimState::try_from_slice(&bytes).map_err(|e| {
            CliError::new("CLI_NODE_UNREACHABLE", format!("{}: {e}", path.display()))
        })?;
        Ok(Self {
            state: Rc::new(RefCell::new(state)),
            path: Some(path.to_path_buf()),
        })
    }

    /// Writes a new state file; refuses to overwrite one.
    pub fn create(path: &Path, state: SimState) -> Result<(), CliError> {
        let bytes = borsh::to_vec(&state).expect("borsh writes into memory");
        crate::terms_file::write_new_bytes(path, &bytes)
    }

    pub fn save(&self) -> Result<(), CliError> {
        if let Some(path) = &self.path {
            let bytes = borsh::to_vec(&*self.state.borrow()).expect("borsh writes into memory");
            std::fs::write(path, bytes)
                .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("{}: {e}", path.display())))?;
        }
        Ok(())
    }
}

impl Node for SimNode {
    fn server_info(&self) -> Result<ServerInfo, CliError> {
        let s = self.state.borrow();
        Ok(ServerInfo {
            network: Some(s.network()),
            network_name: if s.mainnet {
                "fake-mainnet".into()
            } else {
                "fake-testnet".into()
            },
            synced: s.synced,
        })
    }

    fn dag_info(&self) -> Result<DagInfo, CliError> {
        let info = {
            let mut s = self.state.borrow_mut();
            s.virtual_daa += s.tick;
            DagInfo {
                sink: s.sink(),
                virtual_daa: s.virtual_daa,
            }
        };
        self.save()?;
        Ok(info)
    }

    fn block(&self, hash: [u8; 32]) -> Result<BlockInfo, CliError> {
        let s = self.state.borrow();
        let i = s
            .position(&hash)
            .ok_or_else(|| fake("get_block", "block not found"))?;
        Ok(BlockInfo {
            daa_score: s.chain[i].daa,
            selected_parent: i.checked_sub(1).map_or([0; 32], |p| s.chain[p].hash),
            is_chain_block: !s.off_chain,
        })
    }

    fn virtual_chain_from(&self, start: [u8; 32]) -> Result<ChainUpdate, CliError> {
        let s = self.state.borrow();
        let i = s
            .position(&start)
            .ok_or_else(|| fake("get_virtual_chain_from_block", "unknown start"))?;
        let added = &s.chain[i + 1..];
        Ok(ChainUpdate {
            removed: vec![],
            added: added.iter().map(|b| b.hash).collect(),
            accepted: added
                .iter()
                .map(|b| (b.hash, b.txs.iter().map(|t| t.id().as_bytes()).collect()))
                .collect(),
        })
    }

    fn submit(&self, tx: &Transaction) -> Result<[u8; 32], CliError> {
        let id = self
            .state
            .borrow_mut()
            .submit(tx)
            .map_err(|e| fake("submit_transaction", e))?;
        self.save()?;
        Ok(id)
    }

    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, CliError> {
        Ok(self.state.borrow().utxos_at(&address_script(address)))
    }

    fn accepted_from(&self, start: [u8; 32]) -> Result<AcceptedUpdate, CliError> {
        let s = self.state.borrow();
        let i = s
            .position(&start)
            .ok_or_else(|| fake("get_virtual_chain_from_block_v2", "unknown start"))?;
        let added = &s.chain[i + 1..];
        Ok(AcceptedUpdate {
            removed: vec![],
            added: added.iter().map(|b| b.hash).collect(),
            accepted: added
                .iter()
                .map(|b| {
                    let txs = b
                        .txs
                        .iter()
                        .zip(&b.spent)
                        .map(|(tx, spent)| AcceptedTx {
                            tx: tx.clone(),
                            spent: spent.clone(),
                        })
                        .collect();
                    (b.hash, txs)
                })
                .collect(),
        })
    }
}
