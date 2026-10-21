// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Writes the starting corpus of every fuzz target into `fuzz/corpus/<target>/seed-*`, from the
//! golden vectors under tests/vectors and from values impulse-core and impulse-cli build. Run by
//! scripts/fuzz.sh before fuzzing; the output is deterministic except the threshold seeds, which
//! come from a fresh throwaway DKG.
//!
//! Key material (rule 1, docs/ENGINEERING-RULES.md): nothing secret is written. The threshold seeds are the public
//! encodings of a 2-of-3 DKG run here in memory with random throwaway shares (round-1 packages,
//! the group key, a nonce commitment, a signature share); the shares and nonces are dropped,
//! zeroed, when this program ends. The threshold_secret target gets no seeds.

use impulse_cli::json::{hex, unhex};
use impulse_cli::funds::{outpoint_text, p2pk_address};
use impulse_cli::receipt::{Observation, Receipt};
use impulse_cli::terms_file::{render_terms_file, terms_json};
use impulse_core::template::Vault;
use impulse_core::template::LegIndex;
use impulse_core::terms::{Network, ValidatedTerms};
use impulse_core::threshold::{self, GroupShape};
use impulse_core::tx::Ipst;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use kaspa_consensus_core::Hash;
use kaspa_rpc_core::{
    GetServerInfoResponse, GetUtxosByAddressesResponse, GetVirtualChainFromBlockResponse,
    GetVirtualChainFromBlockV2Response, RpcAcceptedTransactionIds,
    RpcChainBlockAcceptedTransactions, RpcOptionalHeader, RpcOptionalTransaction,
    RpcOptionalTransactionInputVerboseData, RpcOptionalUtxoEntry, SubmitTransactionResponse,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use workflow_serializer::prelude::Serializer;

struct Out {
    root: PathBuf,
}

impl Out {
    fn put(&self, target: &str, name: &str, bytes: &[u8]) {
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("corpus directory");
        fs::write(dir.join(format!("seed-{name}")), bytes).expect("seed file");
    }
}

fn vectors(repo: &Path, kind: &str) -> Vec<(String, Value)> {
    let mut files: Vec<_> = fs::read_dir(repo.join("tests/vectors").join(kind))
        .expect("vector directory")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            (name, value)
        })
        .collect()
}

fn with(selector: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![selector];
    v.extend_from_slice(body);
    v
}

fn main() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let out = Out {
        root: std::env::args()
            .nth(1)
            .map(PathBuf::from)
            .unwrap_or_else(|| repo.join("fuzz/corpus")),
    };

    // Terms: canonical bytes, terms files, drafts; the vaults' redeem scripts and addresses.
    let mut all_terms = Vec::new();
    for (name, v) in vectors(&repo, "terms") {
        let canonical = unhex(v["canonical"].as_str().unwrap()).unwrap();
        out.put("terms_decode", &name, &canonical);
        let terms = ValidatedTerms::decode(&canonical).expect("golden terms");
        let file = render_terms_file(&terms);
        out.put("cli_terms_file", &name, file.as_bytes());
        out.put("cli_json", &name, file.as_bytes());
        let draft = terms_json(terms.terms()).render();
        out.put("cli_terms_file", &format!("{name}-draft"), draft.as_bytes());
        all_terms.push((name, terms));
    }
    for (name, v) in vectors(&repo, "vaults") {
        for leg in ["asset_vault", "cash_vault"] {
            if let Some(s) = v[leg]["redeem_script"].as_str() {
                out.put("template_decode", &format!("{name}-{leg}"), &unhex(s).unwrap());
            }
        }
    }

    // IPSTs and the transactions they hold.
    for (name, v) in vectors(&repo, "ipst") {
        let text = serde_json::to_string(&v["ipst"]).unwrap();
        let ipst = Ipst::from_json(&text).expect("golden IPST");
        let canonical = ipst.to_json();
        out.put("ipst_parse", &name, canonical.as_bytes());
        out.put("cli_json", &format!("ipst-{name}"), canonical.as_bytes());
        let tx = ipst.transaction();
        out.put("tx_decode", &name, &borsh::to_vec(tx).unwrap());
        if let Ok(signed) = ipst.finalize() {
            out.put("tx_decode", &format!("{name}-final"), &borsh::to_vec(&signed).unwrap());
        }
        if name == "04-settle-authority-kas" {
            wire_seeds(&out, tx);
        }
    }

    // KCC-20 templates.
    for side in ["asset", "cash"] {
        let path = repo.join(format!("crates/impulse-core/src/tx/testdata/kcc20-{side}.json"));
        out.put("kcc20_template", side, &fs::read(path).unwrap());
    }

    // Text arguments: selector byte (bit 7 testnet, low bits the parser), then the text.
    let key = [0x3c; 32];
    let txid = [0xab; 32];
    for (bit, network) in [(0u8, Network::Mainnet), (0x80, Network::Testnet)] {
        let address = p2pk_address(&key, network).to_string();
        out.put("cli_args", &format!("pay-from-{bit}"), &with(bit, address.as_bytes()));
        out.put("cli_args", &format!("change-{bit}"), &with(bit | 1, address.as_bytes()));
        out.put("cli_args", &format!("pin-{bit}"), &with(bit | 2, address.as_bytes()));
        let pin = format!("kcc20:script_hash:{}", hex(&key));
        out.put("cli_args", &format!("pin-kcc20-{bit}"), &with(bit | 2, pin.as_bytes()));
        for url in ["ws://127.0.0.1:17110", "wss://node.example:443/path", "ws://[::1]"] {
            out.put("cli_args", &format!("url-{bit}-{}", url.len()), &with(bit | 6, url.as_bytes()));
        }
    }
    for (name, terms) in all_terms.iter().take(3) {
        for leg in [LegIndex::Asset, LegIndex::Cash] {
            if let Ok(vault) = Vault::instantiate_existing(terms, leg) {
                let spk = vault.script_public_key();
                let address = impulse_cli::summary::kas_address(
                    terms.terms().network,
                    spk.version(),
                    spk.script(),
                );
                let uri = format!("{address}?amount=100000000&impulse={}", hex(&terms.terms_hash()));
                out.put("cli_args", &format!("uri-{name}-{}", leg.index()), &with(3, uri.as_bytes()));
            }
        }
    }
    let outpoint = outpoint_text(&TransactionOutpoint::new(Hash::from_bytes(txid), 7));
    out.put("cli_args", "outpoint", &with(4, outpoint.as_bytes()));
    out.put("cli_args", "token", &with(5, format!("{outpoint}:1000").as_bytes()));

    // A receipt (fields only: the signature is not a signature of anything).
    let receipt = Receipt {
        observation: Observation {
            network: Network::Testnet,
            terms_hash: [1; 32],
            txid,
            accepting_block: [3; 32],
            daa_score: 900,
            depth: 100,
        },
        signer: key,
        signature: [5; 64],
    };
    out.put("cli_receipt", "fields", receipt.render().as_bytes());
    out.put("cli_json", "receipt", receipt.render().as_bytes());

    // Node walks: op, input count, then answers. A synced testnet node, then a chain answer that
    // adds block 3 and accepts the wanted transaction there (hash class 1 is not its ID; the
    // fuzzer finds the rest), then an empty answer.
    for op in 0u8..7 {
        let mut s = vec![op | 0x80, 1, 1, 1];
        s.extend_from_slice(&[0, 1, 3, 1, 3, 1, 1, 0, 0, 0]);
        s.extend_from_slice(&1000u64.to_le_bytes());
        out.put("cli_rpc_walk", &format!("op{op}"), &s);
    }

    threshold_seeds(&out);
}

fn wire_seeds(out: &Out, tx: &kaspa_consensus_core::tx::Transaction) {
    let ser = |v: &dyn Fn(&mut Vec<u8>) -> std::io::Result<()>| {
        let mut b = Vec::new();
        v(&mut b).unwrap();
        b
    };
    let info = GetServerInfoResponse {
        rpc_api_version: 1,
        rpc_api_revision: 0,
        server_version: "fuzz".into(),
        network_id: NetworkId::with_suffix(NetworkType::Testnet, 10).into(),
        has_utxo_index: true,
        is_synced: true,
        virtual_daa_score: 1000,
    };
    out.put("cli_rpc_wire", "server-info", &with(0, &ser(&|w| info.serialize(w))));
    let chain = GetVirtualChainFromBlockResponse {
        removed_chain_block_hashes: vec![],
        added_chain_block_hashes: vec![Hash::from_bytes([3; 32])],
        accepted_transaction_ids: vec![RpcAcceptedTransactionIds {
            accepting_block_hash: Hash::from_bytes([3; 32]),
            accepted_transaction_ids: vec![tx.id()],
        }],
    };
    out.put("cli_rpc_wire", "chain", &with(3, &ser(&|w| chain.serialize(w))));
    let mut rtx = RpcOptionalTransaction::from(tx);
    for input in rtx.inputs.iter_mut() {
        input.verbose_data = Some(RpcOptionalTransactionInputVerboseData {
            utxo_entry: Some(RpcOptionalUtxoEntry {
                amount: Some(100_000_000),
                script_public_key: Some(ScriptPublicKey::from_vec(0, vec![0xaa; 35])),
                block_daa_score: Some(900),
                is_coinbase: Some(false),
                verbose_data: None,
                covenant_id: None,
            }),
        });
    }
    let v2 = GetVirtualChainFromBlockV2Response {
        removed_chain_block_hashes: Arc::new(vec![]),
        added_chain_block_hashes: Arc::new(vec![Hash::from_bytes([3; 32])]),
        chain_block_accepted_transactions: Arc::new(vec![RpcChainBlockAcceptedTransactions {
            chain_block_header: RpcOptionalHeader {
                hash: Some(Hash::from_bytes([3; 32])),
                ..Default::default()
            },
            accepted_transactions: vec![rtx],
        }]),
    };
    out.put("cli_rpc_wire", "chain-v2", &with(4, &ser(&|w| v2.serialize(w))));
    let utxos = GetUtxosByAddressesResponse { entries: vec![] };
    out.put("cli_rpc_wire", "utxos", &with(5, &ser(&|w| utxos.serialize(w))));
    let submitted = SubmitTransactionResponse {
        transaction_id: tx.id(),
    };
    out.put("cli_rpc_wire", "submit", &with(6, &ser(&|w| submitted.serialize(w))));
}

fn threshold_seeds(out: &Out) {
    let shape = GroupShape::new(2, 3).unwrap();
    let mut secrets1 = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for id in 1..=3u16 {
        let (secret, package) = threshold::dkg_round1(shape, id).unwrap();
        out.put("threshold_public", &format!("round1-{id}"), &with(0, &package.to_bytes().unwrap()));
        secrets1.insert(id, secret);
        round1.insert(id, package);
    }
    let others = |me: u16| -> BTreeMap<_, _> {
        round1
            .iter()
            .filter(|(id, _)| **id != me)
            .map(|(id, p)| (*id, p.clone()))
            .collect()
    };
    let mut secrets2 = BTreeMap::new();
    let mut sent = BTreeMap::new();
    for (id, secret) in secrets1 {
        let (secret, packages) = threshold::dkg_round2(secret, &others(id)).unwrap();
        secrets2.insert(id, secret);
        sent.insert(id, packages);
    }
    let mut shares = BTreeMap::new();
    for (id, secret) in secrets2 {
        let received: BTreeMap<_, _> = sent
            .iter_mut()
            .filter(|(from, _)| **from != id)
            .map(|(from, packages)| (*from, packages.remove(&id).expect("sent to every other")))
            .collect();
        let (share, group) = threshold::dkg_round3(secret, &others(id), &received).unwrap();
        if id == 1 {
            out.put("threshold_public", "group", &with(1, &group.to_bytes().unwrap()));
        }
        shares.insert(id, share);
    }
    let sighash = [0x42; 32];
    let (n1, c1) = threshold::commit(&shares[&1]);
    let (_n2, c2) = threshold::commit(&shares[&2]);
    out.put("threshold_public", "commitment", &with(2, &c1.to_bytes().unwrap()));
    let commitments = BTreeMap::from([(1, c1), (2, c2)]);
    let share = threshold::sign(&shares[&1], n1, &sighash, &commitments).unwrap();
    out.put("threshold_public", "sigshare", &with(3, &share.to_bytes()));
}
