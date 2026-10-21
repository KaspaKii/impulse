// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Transaction decode (spec/TRANSACTIONS.md, `impulse decode`): arbitrary bytes as the raw
//! (borsh) transaction into `decode_raw_unbound` on both networks, and into `decode_raw` with each
//! input bound to the P2SH of the script it reveals, so the vault path is reached as deep as the
//! input allows; then every view of a decoded result. The carried transaction ID is a hash the
//! fuzzer cannot match, so the parsed transaction is also re-finalized (its ID recomputed) and
//! decoded again through `decode_transaction` and `decode_unbound`, which reach the vault path.
#![no_main]

use borsh::BorshDeserialize;
use impulse_core::decode::{
    decode_raw, decode_raw_unbound, decode_transaction, decode_unbound, revealed_script,
    DecodedTransaction,
};
use impulse_core::terms::Network;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction};
use kaspa_txscript::pay_to_script_hash_script;
use libfuzzer_sys::fuzz_target;

fn views(d: DecodedTransaction) {
    for trade in d.trades() {
        let _ = format!("{trade:?}");
    }
    for leg in &d.legs {
        let _ = leg.outcome();
    }
    let _ = d.strict();
}

fuzz_target!(|data: &[u8]| {
    for network in [Network::Mainnet, Network::Testnet] {
        if let Ok(d) = decode_raw_unbound(data, network) {
            views(d);
        }
    }
    let Ok(mut tx) = Transaction::try_from_slice(data) else {
        return;
    };
    // The binding a node would report for a vault spend: the P2SH of the revealed script.
    let spent: Vec<ScriptPublicKey> = tx
        .inputs
        .iter()
        .map(|i| match revealed_script(&i.signature_script) {
            Some(s) => pay_to_script_hash_script(s),
            None => ScriptPublicKey::from_vec(0, Vec::new()),
        })
        .collect();
    for network in [Network::Mainnet, Network::Testnet] {
        if let Ok(d) = decode_raw(data, &spent, network) {
            views(d);
        }
        // One entry too few must be refused, never read past.
        if !spent.is_empty() {
            assert!(decode_raw(data, &spent[1..], network).is_err());
        }
    }
    tx.finalize();
    for network in [Network::Mainnet, Network::Testnet] {
        if let Ok(d) = decode_transaction(&tx, &spent, network) {
            assert!(d.bound);
            views(d);
        }
        if let Ok(d) = decode_unbound(&tx, network) {
            assert!(!d.bound);
            views(d);
        }
        if !spent.is_empty() {
            assert!(decode_transaction(&tx, &spent[1..], network).is_err());
        }
    }
});
