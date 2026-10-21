// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! A read-only Solana counterpart source for `impulse xchain` (I18, docs/xchain/SOLANA-HTLC.md
//! section 4): it reads the impulse-htlc program's accounts and transactions over JSON-RPC and
//! answers the questions of the [`CounterpartSource`] trait. It holds no key and sends no
//! transaction: `submit_claim` is refused, and the seller claims with the Solana tool.
//!
//! URL form: `solana+https://<rpc host>/<path>#program=<base58>[&funder=<base58>]`. The program
//! is the deployed impulse-htlc program ID. The funder (the buyer's wallet that opened the HTLC)
//! is optional: it lets the source find a lock that has already been claimed or refunded, whose
//! account is closed, from the funder's own transaction history. `http://` is accepted for
//! localhost and 127.0.0.1 only.
//!
//! What it reads, all through public JSON-RPC and nothing else:
//! - a live HTLC: `getProgramAccounts` filtered by size and by the hash lock at state offset 196,
//!   at finalized and then at confirmed commitment; the account must derive from its own seeds
//!   and bump, and its escrow and mint are read for the funded check;
//! - a closed HTLC: the funder's signatures, newest first, paged back to the open instruction;
//! - claims: the successful transactions that touch the HTLC account, paged back to its open,
//!   with an instruction of the program, top level or inner (a cross-program invocation), whose
//!   data is the claim tag and a 32-byte preimage.
//!
//! Anyone can send cheap transactions that name an address, so a history search pages with
//! `before` instead of reading only the newest page. It stops at `HISTORY_MAX_PAGES` pages with
//! an error, never with a quiet "not found".
//!
//! Finality is the commitment the cluster reports: processed is `Seen`, confirmed `Confirmed`,
//! finalized counterpart-final (spec/V2.md section 4.8).

use super::counterpart::{Claim, CounterpartSource, Finality, Lock};
use crate::error::CliError;
use base64::Engine;
use impulse_core::htlc::CounterpartChain;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Size of an HTLC state account (solana/programs/impulse-htlc/src/state.rs).
pub const HTLC_LEN: usize = 245;
const HTLC_TAG: u8 = 0x48;
const HTLC_VERSION: u8 = 1;
const OFFSET_HASH_LOCK: usize = 196;
/// Instruction tags and the length of the `open` data: tag, amount, hash, timeout, recipient,
/// refund.
const TAG_OPEN: u8 = 0;
const TAG_CLAIM: u8 = 1;
const OPEN_DATA_LEN: usize = 1 + 8 + 32 + 8 + 32 + 32;
const CLAIM_DATA_LEN: usize = 1 + 32;
/// The page size asked of `getSignaturesForAddress` (the most the RPC serves), and the most
/// pages one history search reads before it refuses.
const HISTORY_PAGE: usize = 1000;
const HISTORY_MAX_PAGES: usize = 20;
/// SPL token account layout: mint at 0, owner at 32, amount at 64, state at 108 (0 uninitialised,
/// 1 initialised, 2 frozen). Mint layout: is_initialized at 45, freeze authority option at 46.
const TOKEN_ACCOUNT_MIN: usize = 165;
/// The most bytes of one rpc reply read: a page of 1,000 signatures or a transaction is well
/// under 1 MiB, and `getProgramAccounts` is filtered to one hash lock.
pub(crate) const MAX_RPC_BODY: usize = 16 << 20;
const MINT_MIN: usize = 82;

fn rpc_err(what: impl std::fmt::Display) -> CliError {
    CliError::new("CLI_NODE_RPC", format!("solana rpc: {what}"))
}

/// A transport error without the url: an rpc url can carry an API key in its path or query, so no
/// message shows it (as `node::redact_url` does for a Kaspa node url).
fn transport_err(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

fn unsupported(what: impl std::fmt::Display) -> CliError {
    CliError::new("XCHAIN_CHAIN_UNSUPPORTED", format!("{what}"))
}

pub fn b58(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

fn unb58_32(s: &str) -> Option<[u8; 32]> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

fn unb58(s: &str) -> Option<Vec<u8>> {
    bs58::decode(s).into_vec().ok()
}

fn unb64(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_array()?.first()?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn read_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn key(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().expect("32 bytes")
}

/// A program derived address for seeds and a bump, without the off-curve test: the source only
/// checks that an account's address equals the address its own state names, so it needs the
/// hash, not the search.
fn pda(seeds: &[&[u8]], bump: u8, program: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.update([bump]);
    h.update(program);
    h.update(b"ProgramDerivedAddress");
    h.finalize().into()
}

/// The JSON-RPC transport. The real one is HTTP; tests supply their own.
pub trait Rpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, CliError>;
}

pub struct HttpRpc {
    url: String,
    client: reqwest::Client,
    rt: tokio::runtime::Runtime,
}

impl HttpRpc {
    fn new(url: &str) -> Result<Self, CliError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(rpc_err)?;
        let client = {
            let _guard = rt.enter();
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(20))
                .build()
                .map_err(rpc_err)?
        };
        Ok(Self {
            url: url.to_string(),
            client,
            rt,
        })
    }
}

impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, CliError> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let mut last = String::new();
        for attempt in 0..5u64 {
            if attempt > 0 {
                // A rate-limited public endpoint: wait, then ask again.
                std::thread::sleep(Duration::from_secs(2 * attempt));
            }
            let sent = self.rt.block_on(async {
                let r = self
                    .client
                    .post(&self.url)
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .send()
                    .await?;
                let status = r.status();
                // Read in chunks and stop past the cap: never buffer an unbounded reply.
                let mut r = r;
                let mut body = Vec::new();
                while let Some(chunk) = r.chunk().await? {
                    if body.len() + chunk.len() > MAX_RPC_BODY {
                        return Ok(Err(()));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok::<_, reqwest::Error>(Ok((status, body)))
            });
            let (status, body) = match sent {
                Ok(Ok(x)) => x,
                Ok(Err(())) => {
                    return Err(rpc_err(format!(
                        "{method}: the reply is larger than {MAX_RPC_BODY} bytes; refused"
                    )))
                }
                Err(e) => {
                    last = transport_err(e);
                    continue;
                }
            };
            if status.as_u16() == 429 || status.is_server_error() {
                last = format!("HTTP {status}");
                continue;
            }
            let v: Value = serde_json::from_slice(&body)
                .map_err(|_| rpc_err(format!("{method}: HTTP {status}, not JSON")))?;
            if let Some(e) = v.get("error") {
                return Err(rpc_err(format!("{method}: {e}")));
            }
            return v
                .get("result")
                .cloned()
                .ok_or_else(|| rpc_err(format!("{method}: no result")));
        }
        Err(CliError::new(
            "CLI_NODE_UNREACHABLE",
            format!("solana rpc {method}: {last}"),
        ))
    }
}

/// The HTLC state account, parsed (solana/programs/impulse-htlc/src/state.rs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub bump: u8,
    pub escrow_bump: u8,
    pub funder: [u8; 32],
    pub token_program: [u8; 32],
    pub mint: [u8; 32],
    pub escrow: [u8; 32],
    pub recipient: [u8; 32],
    pub refund: [u8; 32],
    pub hash_lock: [u8; 32],
    pub amount: u64,
    pub timeout: i64,
}

pub fn parse_state(b: &[u8]) -> Option<State> {
    if b.len() != HTLC_LEN || b[0] != HTLC_TAG || b[1] != HTLC_VERSION {
        return None;
    }
    Some(State {
        bump: b[2],
        escrow_bump: b[3],
        funder: key(b, 4),
        token_program: key(b, 36),
        mint: key(b, 68),
        escrow: key(b, 100),
        recipient: key(b, 132),
        refund: key(b, 164),
        hash_lock: key(b, 196),
        amount: read_u64(b, 228),
        timeout: i64::from_le_bytes(b[236..244].try_into().expect("8 bytes")),
    })
}

fn finality_of(status: Option<&str>) -> Finality {
    match status {
        Some("finalized") => Finality::Finalized,
        Some("confirmed") => Finality::Confirmed,
        _ => Finality::Seen,
    }
}

struct Instruction {
    program: [u8; 32],
    accounts: Vec<[u8; 32]>,
    data: Vec<u8>,
}

/// What the mint and the escrow of an HTLC say.
struct Token {
    freeze_authority: Option<[u8; 32]>,
    frozen: bool,
    escrow: [u8; 32],
    mint: [u8; 32],
}

pub struct SolanaSource {
    rpc: Box<dyn Rpc>,
    program: [u8; 32],
    funder: Option<[u8; 32]>,
}

/// The rpc url is `https://` to a host, or `http://` to exactly localhost, 127.0.0.1 or [::1],
/// and carries no user information: `http://localhost:1@rpc.example/` is a request to
/// rpc.example. Parsed as a URL, never by prefix. The refusal never echoes the url.
fn check_rpc_url(rpc_url: &str) -> Result<(), CliError> {
    use reqwest::Url;
    let refuse = || {
        unsupported(
            "the Solana rpc url must be https://, or http:// to localhost, 127.0.0.1 or [::1] only, with no user information",
        )
    };
    let u = Url::parse(rpc_url).map_err(|_| refuse())?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(refuse());
    }
    // The parser normalises the host: lower case, IPv4 in dotted decimal, IPv6 compressed.
    let host = u.host_str().unwrap_or("");
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match u.scheme() {
        "https" if !host.is_empty() => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(refuse()),
    }
}

/// Parses `solana+<rpc url>#program=<base58>[&funder=<base58>]` and opens the source.
pub fn open_url(url: &str) -> Result<Box<dyn CounterpartSource>, CliError> {
    let rest = url.strip_prefix("solana+").unwrap_or(url);
    let (rpc_url, frag) = rest.split_once('#').ok_or_else(|| {
        unsupported("a Solana source needs solana+<rpc url>#program=<base58 program id>")
    })?;
    check_rpc_url(rpc_url)?;
    let (mut program, mut funder) = (None, None);
    for part in frag.split('&') {
        match part.split_once('=') {
            Some(("program", v)) => program = Some(v),
            Some(("funder", v)) => funder = Some(v),
            _ => return Err(unsupported(format!("unknown source option {part:?}"))),
        }
    }
    let program = program.and_then(unb58_32).ok_or_else(|| {
        unsupported("program=<base58 program id> is missing or not a 32-byte key")
    })?;
    let funder = match funder {
        None => None,
        Some(f) => {
            Some(unb58_32(f).ok_or_else(|| unsupported("funder=<base58> is not a 32-byte key"))?)
        }
    };
    Ok(Box::new(SolanaSource::new(
        Box::new(HttpRpc::new(rpc_url)?),
        program,
        funder,
    )))
}

impl SolanaSource {
    pub fn new(rpc: Box<dyn Rpc>, program: [u8; 32], funder: Option<[u8; 32]>) -> Self {
        Self {
            rpc,
            program,
            funder,
        }
    }

    fn account(&self, address: &[u8; 32], commitment: &str) -> Result<Option<Vec<u8>>, CliError> {
        let r = self.rpc.call(
            "getAccountInfo",
            json!([b58(address), {"encoding": "base64", "commitment": commitment}]),
        )?;
        match r.get("value") {
            Some(Value::Null) | None => Ok(None),
            Some(v) => unb64(&v["data"])
                .map(Some)
                .ok_or_else(|| rpc_err("getAccountInfo: data is not base64")),
        }
    }

    /// The escrow token account and the mint of a state, at `commitment`.
    fn token(&self, s: &State, commitment: &str) -> Result<Option<Token>, CliError> {
        let r = self.rpc.call(
            "getMultipleAccounts",
            json!([[b58(&s.escrow), b58(&s.mint)], {"encoding": "base64", "commitment": commitment}]),
        )?;
        let v = r["value"]
            .as_array()
            .filter(|a| a.len() == 2)
            .ok_or_else(|| rpc_err("getMultipleAccounts: unexpected answer"))?;
        let (escrow, mint) = match (unb64(&v[0]["data"]), unb64(&v[1]["data"])) {
            (Some(e), Some(m)) => (e, m),
            _ => return Ok(None),
        };
        let owner_ok =
            |x: &Value| unb58_32(x["owner"].as_str().unwrap_or("")) == Some(s.token_program);
        if escrow.len() < TOKEN_ACCOUNT_MIN
            || mint.len() < MINT_MIN
            || !owner_ok(&v[0])
            || !owner_ok(&v[1])
            || key(&escrow, 0) != s.mint
            || mint[45] != 1
            || escrow[108] == 0
        {
            return Ok(None);
        }
        let freeze_authority = (u32::from_le_bytes(mint[46..50].try_into().expect("4 bytes")) == 1)
            .then(|| key(&mint, 50));
        Ok(Some(Token {
            freeze_authority,
            frozen: escrow[108] == 2,
            escrow: s.escrow,
            mint: s.mint,
        }))
    }

    /// Whether the escrow holds at least the amount, held by the HTLC address, of the mint.
    fn funded(&self, htlc: &[u8; 32], s: &State, commitment: &str) -> Result<bool, CliError> {
        let r = self.rpc.call(
            "getAccountInfo",
            json!([b58(&s.escrow), {"encoding": "base64", "commitment": commitment}]),
        )?;
        let Some(data) = r
            .get("value")
            .filter(|v| !v.is_null())
            .and_then(|v| unb64(&v["data"]))
        else {
            return Ok(false);
        };
        let owner = unb58_32(r["value"]["owner"].as_str().unwrap_or(""));
        Ok(owner == Some(s.token_program)
            && data.len() >= TOKEN_ACCOUNT_MIN
            && key(&data, 0) == s.mint
            && key(&data, 32) == *htlc
            && data[108] != 0
            && read_u64(&data, 64) >= s.amount)
    }

    fn live_lock(
        &self,
        address: [u8; 32],
        data: &[u8],
        finality: Finality,
        commitment: &str,
    ) -> Result<Option<Lock>, CliError> {
        let Some(s) = parse_state(data) else {
            return Ok(None);
        };
        // The account must be where its own state says the program put it.
        if pda(&[b"htlc", &s.funder, &s.hash_lock], s.bump, &self.program) != address
            || pda(&[b"escrow", &address], s.escrow_bump, &self.program) != s.escrow
            || s.timeout < 0
        {
            return Ok(None);
        }
        Ok(Some(Lock {
            id: address,
            htlc_program: self.program,
            asset: s.mint,
            amount: s.amount,
            recipient: s.recipient,
            refund: s.refund,
            hash_lock: s.hash_lock,
            timeout: s.timeout as u64,
            funded: self.funded(&address, &s, commitment)?,
            finality,
            reference: Some(b58(&address)),
        }))
    }

    fn live_locks(&self, hash_lock: &[u8; 32]) -> Result<Vec<Lock>, CliError> {
        let mut found: Vec<Lock> = vec![];
        for (commitment, finality) in [
            ("finalized", Finality::Finalized),
            ("confirmed", Finality::Confirmed),
        ] {
            let r = self.rpc.call(
                "getProgramAccounts",
                json!([b58(&self.program), {
                    "encoding": "base64",
                    "commitment": commitment,
                    "filters": [
                        {"dataSize": HTLC_LEN},
                        {"memcmp": {"offset": OFFSET_HASH_LOCK, "bytes": b58(hash_lock)}}
                    ]
                }]),
            )?;
            for a in r
                .as_array()
                .ok_or_else(|| rpc_err("getProgramAccounts: unexpected answer"))?
            {
                let (Some(address), Some(data)) = (
                    a["pubkey"].as_str().and_then(unb58_32),
                    unb64(&a["account"]["data"]),
                ) else {
                    continue;
                };
                if found.iter().any(|l| l.id == address) {
                    continue;
                }
                if let Some(l) = self.live_lock(address, &data, finality, commitment)? {
                    found.push(l);
                }
            }
        }
        Ok(found)
    }

    /// The instructions of a successful transaction, or None if it failed or is unknown.
    fn instructions(&self, signature: &str) -> Result<Option<Vec<Instruction>>, CliError> {
        let r = self.rpc.call(
            "getTransaction",
            json!([signature, {
                "encoding": "json",
                "commitment": "confirmed",
                "maxSupportedTransactionVersion": 0
            }]),
        )?;
        if r.is_null() || !r["meta"]["err"].is_null() {
            return Ok(None);
        }
        let mut keys: Vec<[u8; 32]> = vec![];
        let loaded = &r["meta"]["loadedAddresses"];
        for list in [
            &r["transaction"]["message"]["accountKeys"],
            &loaded["writable"],
            &loaded["readonly"],
        ] {
            for k in list.as_array().into_iter().flatten() {
                keys.push(
                    k.as_str()
                        .and_then(unb58_32)
                        .ok_or_else(|| rpc_err("getTransaction: bad account key"))?,
                );
            }
        }
        let mut out = vec![];
        // The top-level instructions, then those invoked by programs (cross-program invocations):
        // the HTLC program accepts a claim either way.
        let inner = r["meta"]["innerInstructions"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|i| i["instructions"].as_array().into_iter().flatten());
        for ix in r["transaction"]["message"]["instructions"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(inner)
        {
            let at = |i: &Value| i.as_u64().and_then(|i| keys.get(i as usize).copied());
            let (Some(program), Some(data)) = (
                at(&ix["programIdIndex"]),
                ix["data"].as_str().and_then(unb58),
            ) else {
                continue;
            };
            let accounts: Option<Vec<[u8; 32]>> = ix["accounts"]
                .as_array()
                .into_iter()
                .flatten()
                .map(at)
                .collect();
            if let Some(accounts) = accounts {
                out.push(Instruction {
                    program,
                    accounts,
                    data,
                });
            }
        }
        Ok(Some(out))
    }

    /// Visits the successful transactions of `address`, newest first, paging with `before` until
    /// `visit` returns true (found what it looks for) or the history ends. Past
    /// `HISTORY_MAX_PAGES` pages it refuses: a long history is not a miss.
    fn history(
        &self,
        address: &[u8; 32],
        mut visit: impl FnMut(&str, Finality) -> Result<bool, CliError>,
    ) -> Result<(), CliError> {
        let mut before: Option<String> = None;
        for _ in 0..HISTORY_MAX_PAGES {
            let mut opts = json!({"limit": HISTORY_PAGE, "commitment": "confirmed"});
            if let Some(b) = &before {
                opts["before"] = json!(b);
            }
            let r = self
                .rpc
                .call("getSignaturesForAddress", json!([b58(address), opts]))?;
            let page = r
                .as_array()
                .ok_or_else(|| rpc_err("getSignaturesForAddress: unexpected answer"))?;
            if page.is_empty() {
                return Ok(());
            }
            for e in page {
                let sig = e["signature"]
                    .as_str()
                    .ok_or_else(|| rpc_err("getSignaturesForAddress: entry without a signature"))?;
                before = Some(sig.to_string());
                if e["err"].is_null() && visit(sig, finality_of(e["confirmationStatus"].as_str()))?
                {
                    return Ok(());
                }
            }
        }
        Err(rpc_err(format!(
            "the history of {} is longer than the {HISTORY_MAX_PAGES} pages of {HISTORY_PAGE} signatures this source searches, and the search did not reach its end or the HTLC's open: this is not a miss, the reveal or the open may be further back; read the address's full history with another tool before relying on any answer",
            b58(address)
        )))
    }

    fn is_open_of(&self, ix: &Instruction, lock: &[u8; 32]) -> bool {
        ix.program == self.program
            && ix.data.len() == OPEN_DATA_LEN
            && ix.data[0] == TAG_OPEN
            && ix.accounts.get(1) == Some(lock)
    }

    /// A closed lock, rebuilt from the `open` instruction in the funder's recent history.
    fn closed_locks(&self, hash_lock: &[u8; 32]) -> Result<Vec<Lock>, CliError> {
        let Some(funder) = self.funder else {
            return Ok(vec![]);
        };
        let mut found = vec![];
        // The newest open of this hash lock by this funder is the lock (one address per funder
        // and hash lock): stop there.
        self.history(&funder, |sig, finality| {
            for ix in self.instructions(sig)?.unwrap_or_default() {
                if ix.program != self.program
                    || ix.data.len() != OPEN_DATA_LEN
                    || ix.data[0] != TAG_OPEN
                    || ix.accounts.len() < 4
                    || ix.accounts[0] != funder
                    || ix.data[9..41] != hash_lock[..]
                {
                    continue;
                }
                let timeout = i64::from_le_bytes(ix.data[41..49].try_into().expect("8 bytes"));
                if timeout < 0 {
                    continue;
                }
                found.push(Lock {
                    id: ix.accounts[1],
                    htlc_program: self.program,
                    asset: ix.accounts[3],
                    amount: read_u64(&ix.data, 1),
                    recipient: key(&ix.data, 49),
                    refund: key(&ix.data, 81),
                    hash_lock: *hash_lock,
                    timeout: timeout as u64,
                    // The open succeeded; the account is closed now (a claim or a refund).
                    funded: true,
                    finality,
                    reference: Some(b58(&ix.accounts[1])),
                });
            }
            Ok(!found.is_empty())
        })?;
        Ok(found)
    }
}

impl CounterpartSource for SolanaSource {
    fn chain(&self) -> Result<(CounterpartChain, [u8; 32]), CliError> {
        let r = self.rpc.call("getGenesisHash", json!([]))?;
        let id = r
            .as_str()
            .and_then(unb58_32)
            .ok_or_else(|| rpc_err("getGenesisHash: not a 32-byte hash"))?;
        Ok((CounterpartChain::Solana, id))
    }

    fn now_unix(&self) -> Result<u64, CliError> {
        let slot = self
            .rpc
            .call("getSlot", json!([{"commitment": "confirmed"}]))?
            .as_u64()
            .ok_or_else(|| rpc_err("getSlot: not a number"))?;
        // A skipped slot has no block time; step back to the last block.
        for back in 0..20u64 {
            let t = self
                .rpc
                .call("getBlockTime", json!([slot.saturating_sub(back)]));
            if let Ok(v) = t {
                if let Some(t) = v.as_u64() {
                    return Ok(t);
                }
            }
        }
        Err(rpc_err("no block time near the confirmed slot"))
    }

    fn locks(&self, hash_lock: &[u8; 32]) -> Result<Vec<Lock>, CliError> {
        let live = self.live_locks(hash_lock)?;
        if !live.is_empty() {
            return Ok(live);
        }
        self.closed_locks(hash_lock)
    }

    fn claims(&self, lock: &[u8; 32]) -> Result<Vec<Claim>, CliError> {
        let mut found = vec![];
        // Newest first, back to the HTLC's open: nothing before it can be a claim of this lock.
        self.history(lock, |sig, finality| {
            let Some(raw) = unb58(sig).and_then(|b| <[u8; 64]>::try_from(b).ok()) else {
                return Ok(false);
            };
            let ixs = self.instructions(sig)?.unwrap_or_default();
            for ix in &ixs {
                if ix.program == self.program
                    && ix.data.len() == CLAIM_DATA_LEN
                    && ix.data[0] == TAG_CLAIM
                    && ix.accounts.first() == Some(lock)
                {
                    found.push(Claim {
                        // The first half of the signature; the whole signature is `reference`.
                        id: key(&raw, 0),
                        lock: *lock,
                        preimage: ix.data[1..].to_vec(),
                        finality,
                        reference: Some(sig.to_string()),
                    });
                }
            }
            Ok(ixs.iter().any(|ix| self.is_open_of(ix, lock)))
        })?;
        Ok(found)
    }

    fn submit_claim(&self, _lock: &[u8; 32], _preimage: &[u8]) -> Result<(), CliError> {
        Err(unsupported(
            "the Solana source is read-only and holds no key: claim the HTLC with the Solana tool (impulse-htlc-demo claim), then run this command again",
        ))
    }

    fn claim_check(&self, lock: &Lock) -> Result<Vec<String>, CliError> {
        let Some(data) = self.account(&lock.id, "confirmed")? else {
            // Closed: claimed or refunded, nothing left to freeze.
            return Ok(vec![]);
        };
        let Some(s) = parse_state(&data) else {
            return Ok(vec![]);
        };
        let Some(t) = self.token(&s, "confirmed")? else {
            return Ok(vec![]);
        };
        if t.frozen {
            return Err(CliError::new(
                "XCHAIN_COUNTERPART_MISMATCH",
                format!(
                    "the escrow {} is frozen{}: a claim would fail and neither claim nor refund moves it; do not reveal",
                    b58(&t.escrow),
                    t.freeze_authority
                        .map(|a| format!(" (freeze authority {})", b58(&a)))
                        .unwrap_or_default()
                ),
            ));
        }
        Ok(t.freeze_authority
            .map(|a| {
                format!(
                    "warning: mint {} has a freeze authority, {}. It can freeze this HTLC's escrow so that neither claim nor refund moves it; you trust it not to.",
                    b58(&t.mint),
                    b58(&a)
                )
            })
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
#[path = "xchain_solana_tests.rs"]
pub(crate) mod tests;
