// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Tests of the read-only Solana counterpart source, against a mock cluster that answers the
//! JSON-RPC methods the source uses from in-memory accounts and transactions. The mock is also
//! served over a loopback HTTP socket (`serve`), so the command-level tests in `xchain_tests.rs`
//! run the real HTTP transport. It is not a cluster and proves nothing about one: the live check
//! is the localnet and devnet run of `demo/xchain-demo.sh`.
//!
//! Keys: none. Every key and signature below is a random public value drawn at run time.

use super::*;
use crate::xchain::counterpart::mismatch;
use impulse_core::htlc::Counterpart;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const TOKEN_PROGRAM: [u8; 32] = [0x77; 32];

#[derive(Clone)]
pub(crate) struct Acct {
    pub address: [u8; 32],
    pub owner: [u8; 32],
    pub data: Vec<u8>,
    /// The account is visible at confirmed commitment only until this is Finalized.
    pub level: Finality,
}

#[derive(Clone)]
pub(crate) struct Tx {
    pub signature: [u8; 64],
    pub ok: bool,
    pub level: Finality,
    pub keys: Vec<[u8; 32]>,
    pub ixs: Vec<Ix>,
    /// Inner (CPI) instructions: (index of the outer instruction, its inner instructions).
    pub inner: Vec<(usize, Vec<Ix>)>,
}

/// (program key index, account key indexes, data)
pub(crate) type Ix = (usize, Vec<usize>, Vec<u8>);

/// The most signatures the mock returns in one `getSignaturesForAddress` page, whatever limit is
/// asked: a node may answer fewer than the limit, and a small page makes the tests page.
pub(crate) const MOCK_PAGE: usize = 10;

fn ix_json(ix: &Ix) -> Value {
    let (pi, accs, data) = ix;
    json!({"programIdIndex": pi, "accounts": accs, "data": b58(data)})
}

#[derive(Clone, Default)]
pub(crate) struct Chain {
    pub genesis: [u8; 32],
    pub time: u64,
    pub accounts: Vec<Acct>,
    /// Oldest first; the mock answers newest first.
    pub txs: Vec<Tx>,
}

fn level_ok(level: Finality, commitment: &str) -> bool {
    match commitment {
        "finalized" => level == Finality::Finalized,
        _ => level >= Finality::Confirmed,
    }
}

fn status(level: Finality) -> &'static str {
    match level {
        Finality::Seen => "processed",
        Finality::Confirmed => "confirmed",
        Finality::Finalized => "finalized",
    }
}

impl Chain {
    fn find(&self, address: &str, commitment: &str) -> Option<&Acct> {
        let a = unb58_32(address)?;
        self.accounts
            .iter()
            .find(|x| x.address == a && level_ok(x.level, commitment))
    }

    fn acct_json(a: &Acct) -> Value {
        json!({
            "data": [base64::engine::general_purpose::STANDARD.encode(&a.data), "base64"],
            "owner": b58(&a.owner),
            "lamports": 1,
            "executable": false,
        })
    }

    pub(crate) fn handle(&self, method: &str, p: &Value) -> Result<Value, String> {
        let commitment = |i: usize| {
            p[i]["commitment"]
                .as_str()
                .unwrap_or("finalized")
                .to_string()
        };
        Ok(match method {
            "getGenesisHash" => json!(b58(&self.genesis)),
            "getSlot" => json!(1000),
            "getBlockTime" => json!(self.time),
            "getAccountInfo" => {
                let a = self.find(p[0].as_str().unwrap(), &commitment(1));
                json!({"context": {"slot": 1}, "value": a.map(Self::acct_json)})
            }
            "getMultipleAccounts" => {
                let c = commitment(1);
                let v: Vec<Value> = p[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| match self.find(k.as_str().unwrap(), &c) {
                        Some(a) => Self::acct_json(a),
                        None => Value::Null,
                    })
                    .collect();
                json!({"context": {"slot": 1}, "value": v})
            }
            "getProgramAccounts" => {
                let program = unb58_32(p[0].as_str().unwrap()).unwrap();
                let c = commitment(1);
                let mut out = vec![];
                for a in &self.accounts {
                    if a.owner != program || !level_ok(a.level, &c) {
                        continue;
                    }
                    let mut keep = true;
                    for f in p[1]["filters"].as_array().unwrap() {
                        if let Some(n) = f["dataSize"].as_u64() {
                            keep &= a.data.len() as u64 == n;
                        }
                        if let Some(m) = f.get("memcmp") {
                            let off = m["offset"].as_u64().unwrap() as usize;
                            let want = unb58(m["bytes"].as_str().unwrap()).unwrap();
                            keep &= a.data.len() >= off + want.len()
                                && a.data[off..off + want.len()] == want[..];
                        }
                    }
                    if keep {
                        out.push(json!({"pubkey": b58(&a.address), "account": Self::acct_json(a)}));
                    }
                }
                json!(out)
            }
            "getSignaturesForAddress" => {
                let a = unb58_32(p[0].as_str().unwrap()).unwrap();
                let limit = (p[1]["limit"].as_u64().unwrap_or(1000) as usize).min(MOCK_PAGE);
                let before = p[1]["before"].as_str().map(|b| unb58(b).unwrap());
                let mut newest_first = self.txs.iter().rev().filter(|t| t.keys.contains(&a));
                if let Some(b) = before {
                    newest_first.find(|t| t.signature[..] == b[..]).unwrap();
                }
                let v: Vec<Value> = newest_first
                    .take(limit)
                    .map(|t| {
                        json!({
                            "signature": b58(&t.signature),
                            "err": if t.ok { Value::Null } else { json!({"InstructionError": [0, {"Custom": 14}]}) },
                            "confirmationStatus": status(t.level),
                            "slot": 1,
                        })
                    })
                    .collect();
                json!(v)
            }
            "getTransaction" => {
                let sig = unb58(p[0].as_str().unwrap()).unwrap();
                match self.txs.iter().find(|t| t.signature[..] == sig[..]) {
                    None => Value::Null,
                    Some(t) => json!({
                        "slot": 1,
                        "meta": {
                            "err": if t.ok { Value::Null } else { json!({"InstructionError": [0, {"Custom": 14}]}) },
                            "innerInstructions": t.inner.iter().map(|(index, ixs)| json!({
                                "index": index,
                                "instructions": ixs.iter().map(ix_json).collect::<Vec<_>>(),
                            })).collect::<Vec<_>>(),
                        },
                        "transaction": {"message": {
                            "accountKeys": t.keys.iter().map(|k| b58(k)).collect::<Vec<_>>(),
                            "instructions": t.ixs.iter().map(ix_json).collect::<Vec<_>>(),
                        }},
                    }),
                }
            }
            other => return Err(format!("mock: no method {other}")),
        })
    }
}

/// The mock cluster behind a loopback HTTP socket. Stops when dropped.
pub(crate) struct Server {
    pub url: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub(crate) fn serve(chain: Arc<Mutex<Chain>>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let Ok((mut sock, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            sock.set_nonblocking(false).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = vec![];
            let mut chunk = [0u8; 4096];
            let body = loop {
                let n = sock.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    break Some(buf[end + 4..end + 4 + len].to_vec());
                }
            };
            let Some(body) = body else { continue };
            let req: Value = serde_json::from_slice(&body).unwrap();
            let method = req["method"].as_str().unwrap().to_string();
            let reply = match chain.lock().unwrap().handle(&method, &req["params"]) {
                Ok(r) => json!({"jsonrpc": "2.0", "id": req["id"], "result": r}),
                Err(e) => json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": e}}),
            }
            .to_string();
            let _ = write!(
                sock,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.len(),
                reply
            );
        }
    });
    Server {
        url: format!("http://127.0.0.1:{port}"),
        stop,
        thread: Some(thread),
    }
}

/// Mock RPC for the in-process tests.
struct Direct(Arc<Mutex<Chain>>);

impl Rpc for Direct {
    fn call(&self, method: &str, params: Value) -> Result<Value, CliError> {
        self.0
            .lock()
            .unwrap()
            .handle(method, &params)
            .map_err(rpc_err)
    }
}

/// The parameters of one HTLC in the mock.
#[derive(Clone)]
pub(crate) struct Spec {
    pub program: [u8; 32],
    pub funder: [u8; 32],
    pub mint: [u8; 32],
    pub recipient: [u8; 32],
    pub refund: [u8; 32],
    pub hash_lock: [u8; 32],
    pub amount: u64,
    pub timeout: i64,
    pub escrow_amount: u64,
    pub freeze_authority: Option<[u8; 32]>,
    pub frozen: bool,
    pub level: Finality,
}

pub(crate) const BUMP: u8 = 255;
pub(crate) const ESCROW_BUMP: u8 = 254;

impl Spec {
    pub(crate) fn htlc(&self) -> [u8; 32] {
        pda(
            &[b"htlc", &self.funder, &self.hash_lock],
            BUMP,
            &self.program,
        )
    }

    pub(crate) fn escrow(&self) -> [u8; 32] {
        pda(&[b"escrow", &self.htlc()], ESCROW_BUMP, &self.program)
    }

    pub(crate) fn state_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; HTLC_LEN];
        b[0] = HTLC_TAG;
        b[1] = HTLC_VERSION;
        b[2] = BUMP;
        b[3] = ESCROW_BUMP;
        b[4..36].copy_from_slice(&self.funder);
        b[36..68].copy_from_slice(&TOKEN_PROGRAM);
        b[68..100].copy_from_slice(&self.mint);
        b[100..132].copy_from_slice(&self.escrow());
        b[132..164].copy_from_slice(&self.recipient);
        b[164..196].copy_from_slice(&self.refund);
        b[196..228].copy_from_slice(&self.hash_lock);
        b[228..236].copy_from_slice(&self.amount.to_le_bytes());
        b[236..244].copy_from_slice(&self.timeout.to_le_bytes());
        b[244] = 6;
        b
    }

    pub(crate) fn escrow_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; TOKEN_ACCOUNT_MIN];
        b[0..32].copy_from_slice(&self.mint);
        b[32..64].copy_from_slice(&self.htlc());
        b[64..72].copy_from_slice(&self.escrow_amount.to_le_bytes());
        b[108] = if self.frozen { 2 } else { 1 };
        b
    }

    pub(crate) fn mint_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; MINT_MIN];
        b[44] = 6;
        b[45] = 1;
        if let Some(a) = self.freeze_authority {
            b[46..50].copy_from_slice(&1u32.to_le_bytes());
            b[50..82].copy_from_slice(&a);
        }
        b
    }

    /// The HTLC, its escrow and its mint, all live.
    pub(crate) fn install(&self, chain: &mut Chain) {
        let acct = |address, owner, data| Acct {
            address,
            owner,
            data,
            level: self.level,
        };
        chain.accounts.retain(|a| a.address != self.mint);
        chain
            .accounts
            .push(acct(self.htlc(), self.program, self.state_bytes()));
        chain
            .accounts
            .push(acct(self.escrow(), TOKEN_PROGRAM, self.escrow_bytes()));
        chain
            .accounts
            .push(acct(self.mint, TOKEN_PROGRAM, self.mint_bytes()));
    }

    /// The `open` transaction of this HTLC, signed by the funder.
    pub(crate) fn open_tx(&self, ok: bool, level: Finality) -> Tx {
        let mut data = vec![TAG_OPEN];
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.hash_lock);
        data.extend_from_slice(&self.timeout.to_le_bytes());
        data.extend_from_slice(&self.recipient);
        data.extend_from_slice(&self.refund);
        Tx {
            signature: rand::random::<[u8; 32]>()
                .iter()
                .chain(rand::random::<[u8; 32]>().iter())
                .copied()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
            ok,
            level,
            // 0 funder, 1 htlc, 2 escrow, 3 mint, 4 program
            keys: vec![
                self.funder,
                self.htlc(),
                self.escrow(),
                self.mint,
                self.program,
            ],
            ixs: vec![(4, vec![0, 1, 2, 3], data)],
            inner: vec![],
        }
    }

    /// A claim transaction with `preimage`.
    pub(crate) fn claim_tx(&self, preimage: &[u8], ok: bool, level: Finality) -> Tx {
        let mut data = vec![TAG_CLAIM];
        data.extend_from_slice(preimage);
        let mut t = self.open_tx(ok, level);
        t.keys = vec![
            self.htlc(),
            self.escrow(),
            self.mint,
            self.funder,
            self.program,
        ];
        t.ixs = vec![(4, vec![0, 1, 2, 3], data)];
        t
    }

    /// A successful transaction that names `address` and calls some other program: noise in the
    /// address's history, as anyone can send for a few lamports.
    pub(crate) fn decoy_tx(&self, address: [u8; 32]) -> Tx {
        let mut t = self.open_tx(true, Finality::Finalized);
        t.keys = vec![address, rand32()];
        t.ixs = vec![(1, vec![0], vec![TAG_CLAIM])];
        t
    }
}

fn rand32() -> [u8; 32] {
    rand::random()
}

fn spec(level: Finality) -> Spec {
    Spec {
        program: rand32(),
        funder: rand32(),
        mint: rand32(),
        recipient: rand32(),
        refund: rand32(),
        hash_lock: rand32(),
        amount: 250_000,
        timeout: 1_900_000_000,
        escrow_amount: 250_000,
        freeze_authority: None,
        frozen: false,
        level,
    }
}

fn source(chain: &Chain, s: &Spec, funder: bool) -> SolanaSource {
    SolanaSource::new(
        Box::new(Direct(Arc::new(Mutex::new(chain.clone())))),
        s.program,
        funder.then_some(s.funder),
    )
}

fn record_of(s: &Spec) -> Counterpart {
    Counterpart {
        chain: CounterpartChain::Solana,
        chain_id: [0; 32],
        htlc_program: s.program,
        asset: s.mint,
        amount: s.amount,
        recipient: s.recipient,
        refund: s.refund,
        timeout: s.timeout as u64,
    }
}

#[test]
fn a_finalized_lock_is_found_and_equals_the_record() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let locks = source(&chain, &s, false).locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    let l = &locks[0];
    assert_eq!(l.id, s.htlc());
    assert_eq!(l.finality, Finality::Finalized);
    assert!(l.funded);
    assert_eq!(l.label(), b58(&s.htlc()));
    assert_eq!(mismatch(l, &record_of(&s), &s.hash_lock), None);
    // Another hash lock finds nothing.
    assert!(source(&chain, &s, false)
        .locks(&rand32())
        .unwrap()
        .is_empty());
}

#[test]
fn a_lock_seen_only_at_confirmed_is_confirmed_not_final() {
    let s = spec(Finality::Confirmed);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let locks = source(&chain, &s, false).locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].finality, Finality::Confirmed);
}

#[test]
fn an_escrow_short_of_the_amount_is_not_funded() {
    let mut s = spec(Finality::Finalized);
    s.escrow_amount = s.amount - 1;
    let mut chain = Chain::default();
    s.install(&mut chain);
    let l = source(&chain, &s, false)
        .locks(&s.hash_lock)
        .unwrap()
        .remove(0);
    assert!(!l.funded);
    assert_eq!(
        mismatch(&l, &record_of(&s), &s.hash_lock),
        Some("funded"),
        "the verifier refuses an unfunded lock"
    );
}

#[test]
fn a_differing_field_is_named() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let l = source(&chain, &s, false)
        .locks(&s.hash_lock)
        .unwrap()
        .remove(0);
    let mut rec = record_of(&s);
    rec.recipient = rand32();
    assert_eq!(mismatch(&l, &rec, &s.hash_lock), Some("recipient"));
}

#[test]
fn an_account_off_its_own_seeds_is_not_a_lock() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    s.install(&mut chain);
    // The state names another funder than the one the address derives from.
    let htlc = chain
        .accounts
        .iter_mut()
        .find(|a| a.address == s.htlc())
        .unwrap();
    htlc.data[4..36].copy_from_slice(&rand32());
    assert!(source(&chain, &s, false)
        .locks(&s.hash_lock)
        .unwrap()
        .is_empty());
}

#[test]
fn a_closed_lock_is_rebuilt_from_the_funders_history() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    // Only the open transaction remains (the accounts were closed by a claim or a refund), and a
    // failed open of the same hash that must not count.
    chain.txs.push(s.open_tx(false, Finality::Finalized));
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    assert!(source(&chain, &s, false)
        .locks(&s.hash_lock)
        .unwrap()
        .is_empty());
    let locks = source(&chain, &s, true).locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    let l = &locks[0];
    assert_eq!(l.id, s.htlc());
    assert_eq!(l.finality, Finality::Finalized);
    assert_eq!(mismatch(l, &record_of(&s), &s.hash_lock), None);
}

#[test]
fn claims_are_the_successful_claim_instructions_with_their_preimage() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    let preimage = rand32();
    let good = s.claim_tx(&preimage, true, Finality::Confirmed);
    chain.txs.push(s.open_tx(true, Finality::Finalized)); // not a claim
    chain
        .txs
        .push(s.claim_tx(&rand32(), false, Finality::Finalized)); // failed
    chain.txs.push(good.clone());
    let claims = source(&chain, &s, false).claims(&s.htlc()).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].preimage, preimage);
    assert_eq!(claims[0].finality, Finality::Confirmed);
    assert_eq!(claims[0].label(), b58(&good.signature));
    assert_eq!(claims[0].id[..], good.signature[..32]);
    // Another lock has none.
    assert!(source(&chain, &s, false)
        .claims(&rand32())
        .unwrap()
        .is_empty());
}

#[test]
fn a_claim_of_the_wrong_length_or_by_another_program_is_not_a_claim() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    let mut short = s.claim_tx(&rand32(), true, Finality::Finalized);
    short.ixs[0].2.pop();
    let mut other = s.claim_tx(&rand32(), true, Finality::Finalized);
    other.keys[4] = rand32();
    chain.txs.push(short);
    chain.txs.push(other);
    assert!(source(&chain, &s, false)
        .claims(&s.htlc())
        .unwrap()
        .is_empty());
}

#[test]
fn a_mint_with_a_freeze_authority_gets_the_documented_warning() {
    let mut s = spec(Finality::Finalized);
    let fa = rand32();
    s.freeze_authority = Some(fa);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let src = source(&chain, &s, false);
    let l = src.locks(&s.hash_lock).unwrap().remove(0);
    let w = src.claim_check(&l).unwrap();
    assert_eq!(
        w,
        vec![format!(
            "warning: mint {} has a freeze authority, {}. It can freeze this HTLC's escrow so that neither claim nor refund moves it; you trust it not to.",
            b58(&s.mint),
            b58(&fa)
        )]
    );
}

#[test]
fn a_mint_without_a_freeze_authority_gets_no_warning() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let src = source(&chain, &s, false);
    let l = src.locks(&s.hash_lock).unwrap().remove(0);
    assert!(src.claim_check(&l).unwrap().is_empty());
}

#[test]
fn a_frozen_escrow_is_refused() {
    let mut s = spec(Finality::Finalized);
    s.freeze_authority = Some(rand32());
    s.frozen = true;
    let mut chain = Chain::default();
    s.install(&mut chain);
    let src = source(&chain, &s, false);
    // Still found and still funded: the refusal is the claim check's, not the lock's.
    let l = src.locks(&s.hash_lock).unwrap().remove(0);
    assert!(l.funded);
    let e = src.claim_check(&l).unwrap_err();
    assert_eq!(e.code(), "XCHAIN_COUNTERPART_MISMATCH");
    assert!(e.detail().contains("frozen"), "{e}");
    assert!(e.detail().contains(&b58(&s.escrow())), "{e}");
}

#[test]
fn a_closed_lock_has_nothing_to_check() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    let src = source(&chain, &s, true);
    let l = src.locks(&s.hash_lock).unwrap().remove(0);
    assert!(src.claim_check(&l).unwrap().is_empty());
}

#[test]
fn the_source_cannot_claim() {
    let s = spec(Finality::Finalized);
    let src = source(&Chain::default(), &s, false);
    let e = src.submit_claim(&s.htlc(), &rand32()).unwrap_err();
    assert_eq!(e.code(), "XCHAIN_CHAIN_UNSUPPORTED");
}

#[test]
fn the_chain_is_the_genesis_hash_and_the_clock_the_block_time() {
    let s = spec(Finality::Finalized);
    let chain = Chain {
        genesis: rand32(),
        time: 1_800_000_123,
        ..Chain::default()
    };
    let src = source(&chain, &s, false);
    assert_eq!(
        src.chain().unwrap(),
        (CounterpartChain::Solana, chain.genesis)
    );
    assert_eq!(src.now_unix().unwrap(), 1_800_000_123);
}

#[test]
fn urls_name_a_program_and_refuse_cleartext_to_remote_hosts() {
    let p = b58(&rand32());
    let ok = |u: &str| open_url(u).map(|_| ()).map_err(|e| e.code());
    assert_eq!(
        ok(&format!("solana+https://api.devnet.solana.com#program={p}")),
        Ok(())
    );
    assert_eq!(
        ok(&format!("solana+http://127.0.0.1:8899#program={p}")),
        Ok(())
    );
    assert_eq!(
        ok(&format!(
            "solana+http://localhost:8899/x#program={p}&funder={p}"
        )),
        Ok(())
    );
    assert_eq!(ok(&format!("solana+http://[::1]:8899#program={p}")), Ok(()));
    assert_eq!(ok(&format!("solana+http://localhost#program={p}")), Ok(()));
    // A refusal never echoes a credential in the url.
    let e = open_url(&format!(
        "solana+http://user:secret@rpc.attacker.net/?token=t#program={p}"
    ))
    .map(|_| ())
    .unwrap_err();
    assert!(
        !e.to_string().contains("secret") && !e.to_string().contains("token"),
        "{e}"
    );
    for bad in [
        format!("solana+http://example.com#program={p}"),
        format!("solana+http://127.0.0.1.example.com#program={p}"),
        "solana+https://api.devnet.solana.com".to_string(),
        "solana+https://api.devnet.solana.com#program=notbase58!".to_string(),
        format!("solana+https://api.devnet.solana.com#program={p}&funder=short"),
        format!("solana+https://api.devnet.solana.com#program={p}&x=1"),
        format!("solana+ftp://x#program={p}"),
        // User information before the host: the host is the attacker's, not this machine.
        format!("solana+http://localhost:1@rpc.attacker.net/#program={p}"),
        format!("solana+http://127.0.0.1@203.0.113.9:8899#program={p}"),
        format!("solana+http://[::1]:1@rpc.attacker.net#program={p}"),
        format!("solana+http://:secret@localhost:8899#program={p}"),
        format!("solana+https://user:secret@api.devnet.solana.com#program={p}"),
        format!("solana+http://localhost.example#program={p}"),
        format!("solana+http://127.0.0.2:8899#program={p}"),
        format!("solana+http://[::2]:8899#program={p}"),
        format!("solana+http://127.0.0.1:x#program={p}"),
        format!("solana+https://#program={p}"),
        format!("solana+http://#program={p}"),
    ] {
        assert_eq!(ok(&bad), Err("XCHAIN_CHAIN_UNSUPPORTED"), "{bad}");
    }
}

#[test]
fn the_real_http_transport_reads_the_mock_cluster() {
    let mut s = spec(Finality::Finalized);
    s.freeze_authority = Some(rand32());
    let mut chain = Chain {
        genesis: rand32(),
        time: 1_800_000_000,
        ..Chain::default()
    };
    s.install(&mut chain);
    let genesis = chain.genesis;
    let server = serve(Arc::new(Mutex::new(chain)));
    let src = open_url(&format!(
        "solana+{}#program={}",
        server.url,
        b58(&s.program)
    ))
    .unwrap();
    assert_eq!(src.chain().unwrap(), (CounterpartChain::Solana, genesis));
    let l = src.locks(&s.hash_lock).unwrap().remove(0);
    assert_eq!(l.id, s.htlc());
    assert_eq!(src.claim_check(&l).unwrap().len(), 1);
    // An unknown method is a node error, not a panic.
    let e = HttpRpc::new(&server.url)
        .unwrap()
        .call("nope", json!([]))
        .unwrap_err();
    assert_eq!(e.code(), "CLI_NODE_RPC");
}

/// An escrow whose token account is held by another address is not funded.
#[test]
fn an_escrow_held_by_another_address_is_not_funded() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    s.install(&mut chain);
    let escrow = chain
        .accounts
        .iter_mut()
        .find(|a| a.address == s.escrow())
        .unwrap();
    escrow.data[32..64].copy_from_slice(&rand32());
    let l = source(&chain, &s, false)
        .locks(&s.hash_lock)
        .unwrap()
        .remove(0);
    assert!(!l.funded);
}

/// Answers like the mock, but lists every signature as successful, as a node can for a
/// transaction whose own record carries an error: the transaction read must refuse it.
struct ListsAllOk(Direct);

impl Rpc for ListsAllOk {
    fn call(&self, method: &str, params: Value) -> Result<Value, CliError> {
        let mut v = self.0.call(method, params)?;
        if method == "getSignaturesForAddress" {
            for e in v.as_array_mut().unwrap() {
                e["err"] = Value::Null;
            }
        }
        Ok(v)
    }
}

#[test]
fn a_failed_transaction_is_neither_a_claim_nor_an_open() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    chain
        .txs
        .push(s.claim_tx(&rand32(), false, Finality::Finalized));
    chain.txs.push(s.open_tx(false, Finality::Finalized));
    let src = SolanaSource::new(
        Box::new(ListsAllOk(Direct(Arc::new(Mutex::new(chain))))),
        s.program,
        Some(s.funder),
    );
    assert!(src.claims(&s.htlc()).unwrap().is_empty());
    assert!(src.locks(&s.hash_lock).unwrap().is_empty());
}

#[test]
fn an_open_for_another_hash_lock_is_not_the_lock() {
    let s = spec(Finality::Finalized);
    let mut other = s.clone();
    other.hash_lock = rand32();
    let mut chain = Chain::default();
    chain.txs.push(other.open_tx(true, Finality::Finalized));
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    let locks = source(&chain, &s, true).locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    let none = source(&chain, &s, true).locks(&rand32()).unwrap();
    assert!(none.is_empty());
}

/// A claim made by another program through a cross-program invocation: the program accepts it,
/// so the reveal is in the transaction's inner instructions, not its top-level ones.
#[test]
fn a_claim_made_through_a_cpi_is_found() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    let preimage = rand32();
    let mut t = s.claim_tx(&preimage, true, Finality::Finalized);
    // 0 htlc, 1 escrow, 2 mint, 3 funder, 4 program, 5 the wrapper program.
    t.keys.push(rand32());
    let mut claim = vec![TAG_CLAIM];
    claim.extend_from_slice(&preimage);
    t.ixs = vec![(5, vec![0, 1, 2, 3, 4], vec![7, 7, 7])];
    t.inner = vec![(0, vec![(4, vec![0, 1, 2, 3], claim.clone())])];
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    chain.txs.push(t);
    let claims = source(&chain, &s, false).claims(&s.htlc()).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].preimage, preimage);
    // An inner instruction of another program, or on another account, is not a claim.
    let mut chain = Chain::default();
    let mut t = s.claim_tx(&preimage, true, Finality::Finalized);
    t.keys.push(rand32());
    t.ixs = vec![(5, vec![0, 1, 2, 3, 4], vec![7])];
    t.inner = vec![(
        0,
        vec![
            (5, vec![0, 1, 2, 3], claim.clone()),
            (4, vec![1, 0, 2, 3], claim),
        ],
    )];
    chain.txs.push(t);
    assert!(source(&chain, &s, false)
        .claims(&s.htlc())
        .unwrap()
        .is_empty());
}

/// Anyone can send cheap transactions that name the HTLC or the funder; they must not push the
/// reveal or the open out of view.
#[test]
fn a_claim_and_an_open_behind_thirty_decoys_are_found() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    let preimage = rand32();
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    chain
        .txs
        .push(s.claim_tx(&preimage, true, Finality::Finalized));
    for _ in 0..30 {
        chain.txs.push(s.decoy_tx(s.htlc()));
        chain.txs.push(s.decoy_tx(s.funder));
    }
    let src = source(&chain, &s, true);
    let claims = src.claims(&s.htlc()).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].preimage, preimage);
    let locks = src.locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].id, s.htlc());
}

/// A history longer than the search bound is an error, never a quiet "no claim" or "no lock".
#[test]
fn a_history_past_the_bound_is_an_error_not_a_miss() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    chain
        .txs
        .push(s.claim_tx(&rand32(), true, Finality::Finalized));
    for _ in 0..HISTORY_MAX_PAGES * MOCK_PAGE {
        chain.txs.push(s.decoy_tx(s.htlc()));
        chain.txs.push(s.decoy_tx(s.funder));
    }
    let src = source(&chain, &s, true);
    let e = src.claims(&s.htlc()).unwrap_err();
    assert_eq!(e.code(), "CLI_NODE_RPC");
    assert!(e.detail().contains("not a miss"), "{e}");
    let e = src.locks(&s.hash_lock).unwrap_err();
    assert_eq!(e.code(), "CLI_NODE_RPC");
}

/// The search of an HTLC's history stops at its open, and the search of the funder's at the
/// newest open of the hash lock: transactions older than the open do not count against the bound.
#[test]
fn the_searches_stop_at_the_open() {
    let s = spec(Finality::Finalized);
    let mut chain = Chain::default();
    for _ in 0..HISTORY_MAX_PAGES * MOCK_PAGE + 1 {
        chain.txs.push(s.decoy_tx(s.htlc()));
        chain.txs.push(s.decoy_tx(s.funder));
    }
    let preimage = rand32();
    chain.txs.push(s.open_tx(true, Finality::Finalized));
    chain
        .txs
        .push(s.claim_tx(&preimage, true, Finality::Finalized));
    let src = source(&chain, &s, true);
    let claims = src.claims(&s.htlc()).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].preimage, preimage);
    let locks = src.locks(&s.hash_lock).unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].id, s.htlc());
}

/// An rpc url can carry an API key in its path or query: a transport error never echoes it.
#[test]
fn a_transport_error_never_echoes_the_rpc_url() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let url = format!("http://127.0.0.1:{port}/v2/apikeysecret?api-key=tokensecret");
    let rpc = HttpRpc::new(&url).unwrap();
    let e = rpc
        .rt
        .block_on(async { rpc.client.post(&url).body("{}").send().await })
        .unwrap_err();
    assert!(
        e.to_string().contains("apikeysecret"),
        "the probe must echo: {e}"
    );
    let shown = transport_err(e);
    assert!(
        !shown.contains("apikeysecret") && !shown.contains("tokensecret"),
        "{shown}"
    );
}

/// A reply body over the cap is refused while it is read, never buffered whole.
#[test]
fn a_reply_over_the_body_cap_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let _ = write!(
            sock,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
        );
        let chunk = vec![b' '; 1 << 16];
        let mut sent = 0usize;
        while sent <= MAX_RPC_BODY + chunk.len() {
            if sock.write_all(&chunk).is_err() {
                break;
            }
            sent += chunk.len();
        }
    });
    let e = HttpRpc::new(&format!("http://127.0.0.1:{port}"))
        .unwrap()
        .call("getSlot", json!([]))
        .unwrap_err();
    assert_eq!(e.code(), "CLI_NODE_RPC");
    assert!(e.detail().contains("larger than"), "{e}");
    server.join().unwrap();
}
