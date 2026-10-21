// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Helpers shared by the fuzz targets: a reader that turns fuzz bytes into values, and a node
//! whose every answer is drawn from those bytes, for the CLI's RPC answer handling.

use impulse_cli::error::CliError;
use impulse_cli::node::{
    AcceptedTx, AcceptedUpdate, BlockInfo, ChainUpdate, DagInfo, Node, ServerInfo,
};
use impulse_core::terms::Network;
use impulse_core::tx::Utxo;
use kaspa_addresses::Address;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;
use std::cell::RefCell;

/// Reads values off the front of the fuzz input; every read fails once it is used up.
pub struct Bytes<'a> {
    rest: &'a [u8],
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    pub fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.rest.split_first()?;
        self.rest = rest;
        Some(b)
    }

    pub fn bool(&mut self) -> Option<bool> {
        Some(self.u8()? & 1 == 1)
    }

    pub fn u64(&mut self) -> Option<u64> {
        if self.rest.len() < 8 {
            return None;
        }
        let (head, rest) = self.rest.split_at(8);
        self.rest = rest;
        Some(u64::from_le_bytes(head.try_into().expect("8 bytes")))
    }

    /// One of six hashes, so that answers name the same blocks and transactions often.
    pub fn hash(&mut self) -> Option<[u8; 32]> {
        Some([self.u8()? % 6; 32])
    }

    pub fn hashes(&mut self, max: u8) -> Option<Vec<[u8; 32]>> {
        let n = self.u8()? % (max + 1);
        (0..n).map(|_| self.hash()).collect()
    }
}

/// A transaction with `inputs` inputs, told apart by `tag`.
pub fn transaction(tag: u8, inputs: u8) -> Transaction {
    let inputs = (0..inputs)
        .map(|i| {
            TransactionInput::new(
                TransactionOutpoint::new(Hash::from_bytes([tag; 32]), i.into()),
                vec![],
                0,
                1,
            )
        })
        .collect();
    let outputs = vec![TransactionOutput::new(
        1_000,
        ScriptPublicKey::from_vec(0, vec![tag]),
    )];
    Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// A node whose answers come from the fuzz input. Once the input is used up every call fails,
/// as a node that went away does, so every walk ends.
pub struct FuzzNode<'a> {
    bytes: RefCell<Bytes<'a>>,
    /// Transactions an `accepted_from` answer may name; the first is the one asked about.
    pub pool: Vec<Transaction>,
}

fn gone() -> CliError {
    CliError::new("CLI_NODE_RPC", "fuzz input used up")
}

impl<'a> FuzzNode<'a> {
    pub fn new(bytes: Bytes<'a>, pool: Vec<Transaction>) -> Self {
        Self {
            bytes: RefCell::new(bytes),
            pool,
        }
    }

    fn read<T>(&self, f: impl FnOnce(&mut Bytes<'a>) -> Option<T>) -> Result<T, CliError> {
        f(&mut self.bytes.borrow_mut()).ok_or_else(gone)
    }

    fn chain(b: &mut Bytes<'_>) -> Option<ChainUpdate> {
        let removed = b.hashes(2)?;
        let added = b.hashes(3)?;
        let n = b.u8()? % 3;
        let accepted = (0..n)
            .map(|_| Some((b.hash()?, b.hashes(3)?)))
            .collect::<Option<_>>()?;
        Some(ChainUpdate {
            removed,
            added,
            accepted,
        })
    }
}

impl Node for FuzzNode<'_> {
    fn server_info(&self) -> Result<ServerInfo, CliError> {
        self.read(|b| {
            let network = match b.u8()? % 3 {
                0 => Some(Network::Mainnet),
                1 => Some(Network::Testnet),
                _ => None,
            };
            Some(ServerInfo {
                network,
                network_name: "fuzz".into(),
                synced: b.bool()?,
            })
        })
    }

    fn dag_info(&self) -> Result<DagInfo, CliError> {
        self.read(|b| {
            Some(DagInfo {
                sink: b.hash()?,
                virtual_daa: b.u64()?,
            })
        })
    }

    fn block(&self, _hash: [u8; 32]) -> Result<BlockInfo, CliError> {
        self.read(|b| {
            Some(BlockInfo {
                daa_score: b.u64()?,
                selected_parent: b.hash()?,
                is_chain_block: b.bool()?,
            })
        })
    }

    fn virtual_chain_from(&self, _start: [u8; 32]) -> Result<ChainUpdate, CliError> {
        self.read(Self::chain)
    }

    fn submit(&self, tx: &Transaction) -> Result<[u8; 32], CliError> {
        self.read(|b| {
            if b.bool()? {
                Some(tx.id().as_bytes())
            } else {
                b.hash()
            }
        })
    }

    fn utxos(&self, _address: &Address) -> Result<Vec<Utxo>, CliError> {
        Err(gone())
    }

    fn accepted_from(&self, _start: [u8; 32]) -> Result<AcceptedUpdate, CliError> {
        let pool = &self.pool;
        self.read(|b| {
            let shape = Self::chain(b)?;
            let accepted = shape
                .accepted
                .into_iter()
                .map(|(block, ids)| {
                    let txs = ids
                        .iter()
                        .map(|id| {
                            let tx = pool[usize::from(id[0]) % pool.len()].clone();
                            // Usually one spent entry per input; sometimes one too many.
                            let extra = usize::from(b.u8()? % 4 == 0);
                            let entry = UtxoEntry::new(
                                1_000,
                                ScriptPublicKey::from_vec(0, vec![]),
                                0,
                                false,
                                None,
                            );
                            let spent = vec![entry; tx.inputs.len() + extra];
                            Some(AcceptedTx { tx, spent })
                        })
                        .collect::<Option<Vec<_>>>()?;
                    Some((block, txs))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(AcceptedUpdate {
                removed: shape.removed,
                added: shape.added,
                accepted,
            })
        })
    }
}
