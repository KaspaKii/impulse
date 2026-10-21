// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The CLI's handling of node answers (crates/impulse-cli/src/node.rs): the network and sync
//! check, submit, the acceptance walks over `get_virtual_chain_from_block` (v1 and v2),
//! `impulse status` and receipt re-verification, against a node whose every answer is drawn from
//! the fuzz input. The first byte picks the operation. Oracles: an accepted submit carries the
//! transaction's own ID; a found acceptance names a block some answer added; an observation's
//! depth never underflows.
#![no_main]

use impulse_cli::node::{
    check_node, creation_daa, find_accepted_tx, find_acceptance, observe, submit, verify_receipt,
};
use impulse_cli::receipt::{Observation, Receipt};
use impulse_core::terms::Network;
use impulse_fuzz::{transaction, Bytes, FuzzNode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes::new(data);
    let (Some(op), Some(inputs)) = (b.u8(), b.u8()) else {
        return;
    };
    let network = if op & 0x80 == 0 {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let wanted = transaction(1, inputs % 4);
    let other = transaction(2, 1);
    let txid = wanted.id().as_bytes();
    let pool = vec![wanted.clone(), other];
    let node = FuzzNode::new(b, pool);
    match op & 0x7f {
        0 => {
            if let Ok(info) = check_node(&node, network) {
                assert_eq!(info.network, Some(network));
                assert!(info.synced);
            }
        }
        1 => {
            let _ = creation_daa(&node, network);
        }
        2 => {
            if let Ok(s) = submit(&node, &wanted, network) {
                assert_eq!(s.txid, txid);
            }
        }
        3 => {
            if let Ok(block) = find_acceptance(&node, txid, [0; 32]) {
                assert!(block[0] < 6);
            }
        }
        4 => {
            if let Ok((_, accepted)) = find_accepted_tx(&node, txid, [0; 32]) {
                assert_eq!(accepted.tx.id().as_bytes(), txid);
                assert_eq!(accepted.spent.len(), accepted.tx.inputs.len());
            }
        }
        5 => {
            let _ = observe(&node, network, [9; 32], txid, [0; 32]);
        }
        _ => {
            let receipt = Receipt {
                observation: Observation {
                    network,
                    terms_hash: [9; 32],
                    txid,
                    accepting_block: [u8::from(op & 1 == 1) + 3; 32],
                    daa_score: u64::from(op),
                    depth: u64::from(inputs),
                },
                signer: [0; 32],
                signature: [0; 64],
            };
            let _ = verify_receipt(&node, &receipt);
        }
    }
});
