// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Node answers as they arrive on the wire: arbitrary bytes into the wRPC (Borsh) deserializers
//! of every response the CLI reads (kaspa-rpc-core at the pinned rusty-kaspa revision), then the
//! steps crates/impulse-cli/src/node.rs takes on each: the verbose-data presence check of
//! `map_block`, the UTXO mapping of `map_utxos`, and for `get_virtual_chain_from_block_v2` the
//! hash, spent-entry and transaction conversions of `map_chain_update_v2` followed by the
//! decoder `impulse decode` runs on the result. The CLI's mapping functions are crate-private, so
//! their steps are written out here call for call; the walk over mapped answers is fuzzed by
//! cli_rpc_walk. The first byte picks the response type.
//!
//! Known upstream defect (docs/evidence/fuzz-2026-10-12/README.md, finding F2): the Borsh
//! deserializers size `Vec::with_capacity` from an unchecked u64 length prefix, so a hostile node
//! can make the CLI abort with an allocation failure. This target turns an allocation above
//! 1 GiB into a caught panic (nightly alloc error hook) so the rest of the path stays fuzzable.
//! The same applies to F3: `Address::new` asserts on a payload length when the Borsh reader
//! builds an address, so a hostile node can panic the CLI; that one assert is swallowed here too.
//! The saved artifacts (oom-* and crash-* in the evidence directory) reproduce the defect on the
//! uncapped build.
#![no_main]
#![feature(alloc_error_hook)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Capped;
const CAP: usize = 1 << 30;
// SAFETY: forwards to the system allocator, refusing only oversized requests.
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() > CAP {
            return std::ptr::null_mut();
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if n > CAP {
            return std::ptr::null_mut();
        }
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static A: Capped = Capped;

thread_local! { static IN_OOM: Cell<bool> = const { Cell::new(false) }; }

fn oom_hook(_: Layout) {
    IN_OOM.with(|f| f.set(true));
    panic!("allocation refused");
}

use impulse_core::decode::decode_transaction;
use impulse_core::terms::Network;
use impulse_core::tx::Utxo;
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use kaspa_rpc_core::{
    GetBlockDagInfoResponse, GetBlockResponse, GetServerInfoResponse, GetUtxosByAddressesResponse,
    GetVirtualChainFromBlockResponse, GetVirtualChainFromBlockV2Response,
    SubmitTransactionResponse,
};
use libfuzzer_sys::fuzz_target;
use workflow_serializer::prelude::Deserializer;

fn v2(r: GetVirtualChainFromBlockV2Response) {
    for block in r.chain_block_accepted_transactions.iter() {
        if block.chain_block_header.hash.is_none() {
            return;
        }
        for rtx in &block.accepted_transactions {
            let spent: Option<Vec<UtxoEntry>> = rtx
                .inputs
                .iter()
                .map(|i| {
                    let entry = i.verbose_data.as_ref()?.utxo_entry.clone()?;
                    UtxoEntry::try_from(entry).ok()
                })
                .collect();
            let (Some(spent), Ok(tx)) = (spent, Transaction::try_from(rtx.clone())) else {
                return;
            };
            if spent.len() != tx.inputs.len() {
                continue;
            }
            let spks: Vec<_> = spent.iter().map(|e| e.script_public_key.clone()).collect();
            for network in [Network::Mainnet, Network::Testnet] {
                if let Ok(d) = decode_transaction(&tx, &spks, network) {
                    let _ = d.strict();
                }
            }
        }
    }
}

fuzz_target!(
    init: {
        std::alloc::set_alloc_error_hook(oom_hook);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.location().is_some_and(|l| l.file().ends_with("addresses/src/lib.rs")) {
                IN_OOM.with(|f| f.set(true));
            }
            if !IN_OOM.with(|f| f.get()) {
                previous(info);
            }
        }));
    },
    |data: &[u8]| {
    if let Err(payload) = std::panic::catch_unwind(|| run(data)) {
        // Only the capped allocation is swallowed; any other panic is a finding.
        if !IN_OOM.with(|f| f.get()) {
            std::panic::resume_unwind(payload);
        }
    }
    IN_OOM.with(|f| f.set(false));
});

fn run(data: &[u8]) {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    match which % 7 {
        0 => {
            if let Ok(r) = GetServerInfoResponse::try_from_slice(body) {
                let _ = r.network_id.to_string();
            }
        }
        1 => {
            let _ = GetBlockDagInfoResponse::try_from_slice(body);
        }
        2 => {
            if let Ok(r) = GetBlockResponse::try_from_slice(body) {
                let _ = r.block.verbose_data.as_ref().map(|v| v.is_chain_block);
            }
        }
        3 => {
            let _ = GetVirtualChainFromBlockResponse::try_from_slice(body);
        }
        4 => {
            if let Ok(r) = GetVirtualChainFromBlockV2Response::try_from_slice(body) {
                v2(r);
            }
        }
        5 => {
            if let Ok(r) = GetUtxosByAddressesResponse::try_from_slice(body) {
                let _: Vec<Utxo> = r
                    .entries
                    .into_iter()
                    .map(|e| Utxo {
                        outpoint: e.outpoint.into(),
                        entry: e.utxo_entry.into(),
                    })
                    .collect();
            }
        }
        _ => {
            let _ = SubmitTransactionResponse::try_from_slice(body);
        }
    }
}
