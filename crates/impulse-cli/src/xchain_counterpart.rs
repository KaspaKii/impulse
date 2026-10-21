// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The counterpart chain, as the `xchain` commands see it (spec/V2.md sections 10.7 and 10.9):
//! the `CounterpartSource` trait; a fake source in a JSON state file, compiled only into tests and
//! builds with the test-only feature `offline-fake-node`; and the read-only Solana JSON-RPC source
//! of `xchain_solana.rs` (`solana+<rpc url>#program=<id>`). Any other URL is
//! `XCHAIN_CHAIN_UNSUPPORTED`.

use crate::error::CliError;
use impulse_core::htlc::{Counterpart, CounterpartChain};

/// How final a lock or a claim is on its chain. `Finalized` is counterpart-final (spec/V2.md
/// section 4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finality {
    Seen,
    Confirmed,
    Finalized,
}

impl Finality {
    pub fn name(self) -> &'static str {
        match self {
            Self::Seen => "seen",
            Self::Confirmed => "confirmed",
            Self::Finalized => "counterpart-final",
        }
    }
}

/// A counterpart HTLC lock as its chain shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    /// The lock's identifier on its chain (an account or transaction), for messages.
    pub id: [u8; 32],
    pub htlc_program: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 32],
    pub refund: [u8; 32],
    pub hash_lock: [u8; 32],
    pub timeout: u64,
    pub funded: bool,
    pub finality: Finality,
    /// The lock's name on its own chain when that is not the hex of `id` (a Solana address in
    /// base58). For messages only.
    pub reference: Option<String>,
}

impl Lock {
    /// How messages name the lock.
    pub fn label(&self) -> String {
        self.reference
            .clone()
            .unwrap_or_else(|| crate::json::hex(&self.id))
    }
}

/// A claim of a lock, with the preimage it reveals. The preimage is public on its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: [u8; 32],
    pub lock: [u8; 32],
    pub preimage: Vec<u8>,
    pub finality: Finality,
    /// The claim's name on its own chain when that is not the hex of `id` (a Solana transaction
    /// signature in base58, of which `id` holds the first 32 bytes). For messages only.
    pub reference: Option<String>,
}

impl Claim {
    /// How messages name the claim.
    pub fn label(&self) -> String {
        self.reference
            .clone()
            .unwrap_or_else(|| crate::json::hex(&self.id))
    }
}

/// What the `xchain` commands read from, and submit to, the counterpart chain.
pub trait CounterpartSource {
    /// The chain kind and chain ID the source serves.
    fn chain(&self) -> Result<(CounterpartChain, [u8; 32]), CliError>;
    /// The chain's clock, unix seconds.
    fn now_unix(&self) -> Result<u64, CliError>;
    /// Every lock with this hash lock.
    fn locks(&self, hash_lock: &[u8; 32]) -> Result<Vec<Lock>, CliError>;
    /// Every claim of the lock `lock`.
    fn claims(&self, lock: &[u8; 32]) -> Result<Vec<Claim>, CliError>;
    /// Submits the seller's claim of `lock` with `preimage`; again if already submitted.
    fn submit_claim(&self, lock: &[u8; 32], preimage: &[u8]) -> Result<(), CliError>;
    /// What the seller must be told before revealing: warnings to print, or a refusal when the
    /// lock cannot be claimed (a frozen escrow). The default has nothing to add.
    fn claim_check(&self, _lock: &Lock) -> Result<Vec<String>, CliError> {
        Ok(vec![])
    }
}

/// The source a `--counterpart` URL names.
pub fn open(url: &str) -> Result<Box<dyn CounterpartSource>, CliError> {
    if url.starts_with("solana+") {
        return super::solana::open_url(url);
    }
    #[cfg(any(test, feature = "offline-fake-node"))]
    if let Some(path) = url
        .strip_prefix("fake-counterpart://")
        .filter(|p| !p.is_empty())
    {
        return Ok(Box::new(fake::FakeCounterpart::new(path)));
    }
    Err(CliError::new(
        "XCHAIN_CHAIN_UNSUPPORTED",
        format!(
            "{:?}: this build has no source for that counterpart chain (spec/V2.md section 10.9, D27)",
            url
        ),
    ))
}

/// The first field in which `lock` differs from the agreed record and hash lock, or that it is
/// not funded; None when it is the agreed lock.
pub fn mismatch(lock: &Lock, record: &Counterpart, hash_lock: &[u8; 32]) -> Option<&'static str> {
    [
        ("htlc_program", lock.htlc_program == record.htlc_program),
        ("asset", lock.asset == record.asset),
        ("amount", lock.amount == record.amount),
        ("recipient", lock.recipient == record.recipient),
        ("refund", lock.refund == record.refund),
        ("hash_lock", lock.hash_lock == *hash_lock),
        ("timeout", lock.timeout == record.timeout),
        ("funded", lock.funded),
    ]
    .into_iter()
    .find(|(_, ok)| !ok)
    .map(|(field, _)| field)
}

#[cfg(any(test, feature = "offline-fake-node"))]
pub mod fake {
    //! A fake counterpart chain in a JSON state file (tests only). It is not a chain and proves
    //! nothing about one. A submitted claim is added as `seen`; a test moves it on by editing the
    //! file.

    use super::{Claim, CounterpartSource, Finality, Lock};
    use crate::error::CliError;
    use crate::json::{hex, parse_dec, unhex, unhex32};
    use impulse_core::htlc::CounterpartChain;
    use serde_json::{json, Value};
    use std::path::PathBuf;

    pub struct FakeCounterpart {
        path: PathBuf,
    }

    fn bad(what: impl std::fmt::Display) -> CliError {
        CliError::new("CLI_FILE_READ", format!("fake counterpart state: {what}"))
    }

    fn h32(v: &Value, key: &str) -> Result<[u8; 32], CliError> {
        v[key].as_str().and_then(unhex32).ok_or_else(|| bad(key))
    }

    fn dec(v: &Value, key: &str) -> Result<u64, CliError> {
        v[key].as_str().and_then(parse_dec).ok_or_else(|| bad(key))
    }

    fn finality(v: &Value) -> Result<Finality, CliError> {
        match v["finality"].as_str() {
            Some("seen") => Ok(Finality::Seen),
            Some("confirmed") => Ok(Finality::Confirmed),
            Some("finalized") => Ok(Finality::Finalized),
            _ => Err(bad("finality")),
        }
    }

    impl FakeCounterpart {
        pub fn new(path: &str) -> Self {
            Self { path: path.into() }
        }

        fn state(&self) -> Result<Value, CliError> {
            let text = std::fs::read_to_string(&self.path).map_err(bad)?;
            serde_json::from_str(&text).map_err(bad)
        }

        fn save(&self, state: &Value) -> Result<(), CliError> {
            let text = serde_json::to_string_pretty(state).map_err(bad)?;
            std::fs::write(&self.path, text + "\n")
                .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("fake counterpart: {e}")))
        }
    }

    /// A fake state: the chain, an optional fixed clock, no lock and no claim.
    pub fn state(chain: CounterpartChain, chain_id: &[u8; 32], now: Option<u64>) -> Value {
        json!({
            "chain": super::super::doc::chain_name(chain),
            "chain_id": hex(chain_id),
            "now": now.map(|n| n.to_string()),
            "locks": [],
            "claims": [],
        })
    }

    /// A lock entry of the fake state.
    pub fn lock_json(l: &Lock) -> Value {
        json!({
            "id": hex(&l.id),
            "htlc_program": hex(&l.htlc_program),
            "asset": hex(&l.asset),
            "amount": l.amount.to_string(),
            "recipient": hex(&l.recipient),
            "refund": hex(&l.refund),
            "hash_lock": hex(&l.hash_lock),
            "timeout": l.timeout.to_string(),
            "funded": l.funded,
            "finality": finality_text(l.finality),
        })
    }

    pub fn finality_text(f: Finality) -> &'static str {
        match f {
            Finality::Seen => "seen",
            Finality::Confirmed => "confirmed",
            Finality::Finalized => "finalized",
        }
    }

    fn claim_id(lock: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
        let digest = blake2b_simd::Params::new()
            .hash_length(32)
            .key(b"Impulse/fake-counterpart")
            .to_state()
            .update(lock)
            .update(preimage)
            .finalize();
        digest.as_bytes().try_into().expect("32 bytes")
    }

    impl CounterpartSource for FakeCounterpart {
        fn chain(&self) -> Result<(CounterpartChain, [u8; 32]), CliError> {
            let s = self.state()?;
            let chain = match s["chain"].as_str() {
                Some("solana") => CounterpartChain::Solana,
                Some("other_sha256") => CounterpartChain::OtherSha256,
                _ => return Err(bad("chain")),
            };
            Ok((chain, h32(&s, "chain_id")?))
        }

        fn now_unix(&self) -> Result<u64, CliError> {
            let s = self.state()?;
            if s["now"].is_null() {
                return Ok(super::super::now_unix());
            }
            dec(&s, "now")
        }

        fn locks(&self, hash_lock: &[u8; 32]) -> Result<Vec<Lock>, CliError> {
            let s = self.state()?;
            let mut found = vec![];
            for l in s["locks"].as_array().ok_or_else(|| bad("locks"))? {
                let lock = Lock {
                    id: h32(l, "id")?,
                    htlc_program: h32(l, "htlc_program")?,
                    asset: h32(l, "asset")?,
                    amount: dec(l, "amount")?,
                    recipient: h32(l, "recipient")?,
                    refund: h32(l, "refund")?,
                    hash_lock: h32(l, "hash_lock")?,
                    timeout: dec(l, "timeout")?,
                    funded: l["funded"].as_bool().ok_or_else(|| bad("funded"))?,
                    finality: finality(l)?,
                    reference: None,
                };
                if lock.hash_lock == *hash_lock {
                    found.push(lock);
                }
            }
            Ok(found)
        }

        fn claims(&self, lock: &[u8; 32]) -> Result<Vec<Claim>, CliError> {
            let s = self.state()?;
            let mut found = vec![];
            for c in s["claims"].as_array().ok_or_else(|| bad("claims"))? {
                let claim = Claim {
                    id: h32(c, "id")?,
                    lock: h32(c, "lock")?,
                    preimage: c["preimage"]
                        .as_str()
                        .and_then(unhex)
                        .ok_or_else(|| bad("preimage"))?,
                    finality: finality(c)?,
                    reference: None,
                };
                if claim.lock == *lock {
                    found.push(claim);
                }
            }
            Ok(found)
        }

        fn submit_claim(&self, lock: &[u8; 32], preimage: &[u8]) -> Result<(), CliError> {
            let mut s = self.state()?;
            let id = hex(&claim_id(lock, preimage));
            let claims = s["claims"].as_array_mut().ok_or_else(|| bad("claims"))?;
            if !claims.iter().any(|c| c["id"].as_str() == Some(id.as_str())) {
                claims.push(json!({
                    "id": id,
                    "lock": hex(lock),
                    "preimage": hex(preimage),
                    "finality": "seen",
                }));
            }
            self.save(&s)
        }
    }
}
