// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Instruction builders and parsers for the impulse-htlc demo tool. No key handling lives here:
//! a keypair is read by `main.rs` from a file the caller names and used only to sign.

use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use std::str::FromStr;

pub const MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
/// The only mint the tool accepts on mainnet-beta: Circle's USDC (D47: the issuer is trusted, and
/// it holds a freeze authority). Confirm it against the issuer's own documentation before a run.
pub const MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// The placeholder ID compiled into impulse-htlc (`declare_id!`); no program lives there, so it
/// is never a mainnet program ID. The deploy replaces it with the key holder's own program ID.
pub const PLACEHOLDER_PROGRAM: &str = "3yJqvpGhqzN2mKtUGZ9MkLRFtcWPVJ5vD7QVtFkkucq3";
/// The per-trade cap on `open` on mainnet, in USDC base units (6 decimals): 10 USDC. The
/// environment variable `IMPULSE_MAX_USDC` (base units) may lower it, never raise it.
pub const DEFAULT_CAP_UNITS: u64 = 10_000_000;
/// Printed on stderr by every command on mainnet (the notice of `impulse xchain`, spec/V2.md
/// section 10.6).
pub const R2_NOTICE: &str = "notice: mainnet hashlock is a conditional exchange across two chains, not atomic settlement. Race R2 (spec/V2.md section 10.6): a buyer who controls or colludes with a counterpart block producer or relay can delay the seller's counterpart claim past its timeout. Claim early. The USDC mint has an issuer freeze authority (D47); the issuer can freeze the escrow. Opens are capped: lower than the cap by default, lifted only by --i-accept-the-risk.";
pub const IX_OPEN: u8 = 0;
pub const IX_CLAIM: u8 = 1;
pub const IX_REFUND: u8 = 2;
pub const HTLC_SEED: &[u8] = b"htlc";
pub const ESCROW_SEED: &[u8] = b"escrow";
pub const DECIMALS: u8 = 6;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 64 lowercase hex digits to 32 bytes.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A public key given as 64 hex digits (the form `impulse xchain` uses) or as base58.
pub fn parse_key(s: &str) -> Result<Pubkey, String> {
    if let Some(b) = unhex32(s) {
        return Ok(Pubkey::new_from_array(b));
    }
    Pubkey::from_str(s).map_err(|_| format!("{s:?} is neither 64 hex digits nor a base58 key"))
}

/// The secret file `impulse xchain new` writes: 64 lowercase hex digits and at most one final
/// line feed, readable by its owner only. The bytes are never printed.
pub fn read_secret_text(text: &str) -> Result<[u8; 32], String> {
    let t = text.strip_suffix('\n').unwrap_or(text);
    unhex32(t).ok_or_else(|| "the secret file is not 64 lowercase hex digits".to_string())
}

pub fn htlc_address(program: &Pubkey, funder: &Pubkey, hash: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[HTLC_SEED, funder.as_ref(), hash], program).0
}

pub fn escrow_address(program: &Pubkey, htlc: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_SEED, htlc.as_ref()], program).0
}

pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    get_associated_token_address_with_program_id(owner, mint, &spl_token::id())
}

/// What a cluster is, once its genesis hash and the caller's `--network` agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    /// Devnet, testnet or a local validator.
    Test,
    Mainnet,
}

/// Decides the network of a run. Mainnet needs `--network mainnet` and a cluster whose genesis
/// hash is mainnet-beta's, both: neither alone is enough. `--network devnet|testnet|localnet` is an
/// assertion that the cluster is not mainnet.
pub fn net_guard(genesis: &str, flag: Option<&str>) -> Result<Net, String> {
    let is_main = genesis == MAINNET_GENESIS;
    match (flag, is_main) {
        (Some("mainnet"), true) => Ok(Net::Mainnet),
        (Some("mainnet"), false) => Err(
            "--network mainnet was passed but the cluster's genesis hash is not mainnet-beta's"
                .into(),
        ),
        (Some("devnet" | "testnet" | "localnet") | None, false) => Ok(Net::Test),
        (Some("devnet" | "testnet" | "localnet"), true) => {
            Err("the cluster is Solana mainnet-beta but --network names a test cluster".into())
        }
        (None, true) => {
            Err("this cluster is Solana mainnet-beta: pass --network mainnet to act on it".into())
        }
        (Some(other), _) => Err(format!(
            "--network is mainnet, devnet, testnet or localnet, not {other:?}"
        )),
    }
}

/// The open cap in base units: the default, or `IMPULSE_MAX_USDC` if it is a smaller decimal.
pub fn cap_units(env: Option<&str>) -> Result<u64, String> {
    match env {
        None => Ok(DEFAULT_CAP_UNITS),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n > 0 && n <= DEFAULT_CAP_UNITS => Ok(n),
            _ => Err(format!(
                "IMPULSE_MAX_USDC must be a decimal from 1 to {DEFAULT_CAP_UNITS} (it can lower the cap, never raise it)"
            )),
        },
    }
}

/// The cap check of `open` on mainnet. Returns the line to print. `claim` and `refund` are never
/// capped: a recovery is never stuck behind the cap.
pub fn check_cap(amount: u64, cap: u64, accept_risk: bool) -> Result<String, String> {
    if amount == 0 {
        return Err("--amount must be above zero".into());
    }
    if accept_risk {
        return Ok(format!(
            "value cap: lifted by --i-accept-the-risk ({amount} base units, cap {cap})"
        ));
    }
    if amount > cap {
        return Err(format!(
            "CLI_VALUE_CAP_EXCEEDED: {amount} base units is above the cap of {cap} (10 USDC by default); pass --i-accept-the-risk to lift it"
        ));
    }
    Ok(format!(
        "value cap: {amount} base units within the cap of {cap}"
    ))
}

/// On mainnet the mint is the pinned USDC mint and nothing else.
pub fn mainnet_mint_ok(mint: &Pubkey) -> Result<(), String> {
    if mint.to_string() == MAINNET_USDC_MINT {
        Ok(())
    } else {
        Err(format!(
            "on mainnet the only mint accepted is USDC, {MAINNET_USDC_MINT}; got {mint}"
        ))
    }
}

/// On mainnet the program ID is the key holder's deployed one, passed explicitly; the placeholder
/// compiled into the source is refused.
pub fn mainnet_program_ok(program: &Pubkey) -> Result<(), String> {
    if program.to_string() == PLACEHOLDER_PROGRAM {
        Err("that is the placeholder program ID of the source, not a deployed program".into())
    } else {
        Ok(())
    }
}

/// The program-data account of an upgradeable-loader program account (enum tag 2, then the key).
pub fn programdata_address(program_account: &[u8]) -> Option<Pubkey> {
    if program_account.len() < 36 || program_account[..4] != 2u32.to_le_bytes() {
        return None;
    }
    Pubkey::try_from(&program_account[4..36]).ok()
}

/// The upgrade authority in a program-data account (enum tag 3, slot, optional key): `Some(None)`
/// when the program is final (no authority), `None` when the data is not a program-data account.
pub fn upgrade_authority(programdata: &[u8]) -> Option<Option<Pubkey>> {
    if programdata.len() < 13 || programdata[..4] != 3u32.to_le_bytes() {
        return None;
    }
    match programdata[12] {
        0 => Some(None),
        1 if programdata.len() >= 45 => Some(Some(Pubkey::try_from(&programdata[13..45]).ok()?)),
        _ => None,
    }
}

/// The least time, in seconds, that must remain before an HTLC's timeout for `claim` to reveal the
/// secret: the seller's claim lead Δ_claim is at least two hours (spec/V2.md section 10.5, D39).
pub const DEFAULT_MIN_LEAD_SECS: i64 = 7_200;

/// Size, tag and version of an HTLC state account (solana/programs/impulse-htlc/src/state.rs).
const HTLC_LEN: usize = 245;
const HTLC_TAG: u8 = 0x48;
const HTLC_VERSION: u8 = 1;

/// Checks the live state account `data` of `h` before a claim reveals the secret: it is the
/// HTLC of this funder, mint and hash lock; it pays `dest_owner`; it holds exactly
/// `expect_amount` when one is given; and its timeout is more than `min_lead` seconds after
/// `now`. A claim that fails any of these would reveal the secret for nothing, or too late.
pub fn claim_check(
    data: &[u8],
    h: &Htlc,
    expect_amount: Option<u64>,
    dest_owner: &Pubkey,
    now: i64,
    min_lead: i64,
) -> Result<(), String> {
    if data.len() != HTLC_LEN || data[0] != HTLC_TAG || data[1] != HTLC_VERSION {
        return Err(format!(
            "{} is not a live impulse-htlc state account",
            h.address()
        ));
    }
    let key = |at: usize| Pubkey::new_from_array(data[at..at + 32].try_into().expect("32 bytes"));
    if key(4) != h.funder || key(68) != h.mint || data[196..228] != h.hash {
        return Err("the HTLC state names another funder, mint or hash lock".into());
    }
    let recipient = key(132);
    if recipient != *dest_owner {
        return Err(format!(
            "the HTLC pays recipient {recipient}, not the destination owner {dest_owner}: not claiming"
        ));
    }
    let amount = u64::from_le_bytes(data[228..236].try_into().expect("8 bytes"));
    if let Some(want) = expect_amount {
        if amount != want {
            return Err(format!(
                "the HTLC holds amount {amount}, not --expect-amount {want}: not claiming"
            ));
        }
    }
    let timeout = i64::from_le_bytes(data[236..244].try_into().expect("8 bytes"));
    if timeout.saturating_sub(now) <= min_lead {
        return Err(format!(
            "the HTLC timeout {timeout} is not more than {min_lead} s after the cluster time {now}: not claiming; the buyer refunds after the timeout"
        ));
    }
    Ok(())
}

/// The parameters of one HTLC.
#[derive(Clone, Debug)]
pub struct Htlc {
    pub program: Pubkey,
    pub funder: Pubkey,
    pub mint: Pubkey,
    pub hash: [u8; 32],
}

impl Htlc {
    pub fn address(&self) -> Pubkey {
        htlc_address(&self.program, &self.funder, &self.hash)
    }

    pub fn escrow(&self) -> Pubkey {
        escrow_address(&self.program, &self.address())
    }

    /// `open`: the funder moves `amount` from `source` into the escrow.
    pub fn open(
        &self,
        source: &Pubkey,
        amount: u64,
        timeout: i64,
        recipient: &Pubkey,
        refund: &Pubkey,
    ) -> Instruction {
        let mut d = vec![IX_OPEN];
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(&self.hash);
        d.extend_from_slice(&timeout.to_le_bytes());
        d.extend_from_slice(recipient.as_ref());
        d.extend_from_slice(refund.as_ref());
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.funder, true),
                AccountMeta::new(self.address(), false),
                AccountMeta::new(self.escrow(), false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_system_interface::program::id(), false),
            ],
            data: d,
        }
    }

    /// `claim` (with the preimage) or `refund` (without): pays the escrow to `dest`, rent to the
    /// funder. Both are permissionless; the destination must be a token account of the mint owned
    /// by the recipient (claim) or the refund owner (refund).
    pub fn close(&self, dest: &Pubkey, preimage: Option<&[u8; 32]>) -> Instruction {
        let mut data = vec![if preimage.is_some() {
            IX_CLAIM
        } else {
            IX_REFUND
        }];
        if let Some(p) = preimage {
            data.extend_from_slice(p);
        }
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.address(), false),
                AccountMeta::new(self.escrow(), false),
                AccountMeta::new(*dest, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new(self.funder, false),
            ],
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

    #[test]
    fn mainnet_needs_the_flag_and_the_genesis_both() {
        assert_eq!(
            net_guard(MAINNET_GENESIS, Some("mainnet")),
            Ok(Net::Mainnet)
        );
        assert!(net_guard(MAINNET_GENESIS, None)
            .unwrap_err()
            .contains("--network mainnet"));
        assert!(net_guard(MAINNET_GENESIS, Some("devnet")).is_err());
        assert!(net_guard(OTHER_GENESIS, Some("mainnet")).is_err());
        assert_eq!(net_guard(OTHER_GENESIS, None), Ok(Net::Test));
        assert_eq!(net_guard(OTHER_GENESIS, Some("localnet")), Ok(Net::Test));
        assert!(net_guard(OTHER_GENESIS, Some("main")).is_err());
    }

    #[test]
    fn the_cap_is_10_usdc_lowered_only_by_the_environment() {
        assert_eq!(cap_units(None), Ok(10_000_000));
        assert_eq!(cap_units(Some("5000000")), Ok(5_000_000));
        assert!(cap_units(Some("10000001")).is_err());
        assert!(cap_units(Some("0")).is_err());
        assert!(cap_units(Some("ten")).is_err());
        assert!(check_cap(10_000_000, 10_000_000, false).is_ok());
        assert!(check_cap(10_000_001, 10_000_000, false)
            .unwrap_err()
            .starts_with("CLI_VALUE_CAP_EXCEEDED"));
        assert!(check_cap(10_000_001, 10_000_000, true)
            .unwrap()
            .contains("lifted"));
        assert!(check_cap(0, 10_000_000, true).is_err());
    }

    #[test]
    fn mainnet_pins_the_usdc_mint_and_refuses_the_placeholder_program() {
        assert!(mainnet_mint_ok(&Pubkey::from_str(MAINNET_USDC_MINT).unwrap()).is_ok());
        assert!(mainnet_mint_ok(&Pubkey::new_unique()).is_err());
        assert!(mainnet_program_ok(&Pubkey::from_str(PLACEHOLDER_PROGRAM).unwrap()).is_err());
        assert!(mainnet_program_ok(&Pubkey::new_unique()).is_ok());
    }

    #[test]
    fn the_loader_accounts_parse() {
        let pd = Pubkey::new_unique();
        let mut prog = 2u32.to_le_bytes().to_vec();
        prog.extend_from_slice(pd.as_ref());
        assert_eq!(programdata_address(&prog), Some(pd));
        assert_eq!(programdata_address(&prog[..35]), None);
        let auth = Pubkey::new_unique();
        let mut data = 3u32.to_le_bytes().to_vec();
        data.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(upgrade_authority(&data), None);
        let mut some = data.clone();
        some.push(1);
        some.extend_from_slice(auth.as_ref());
        assert_eq!(upgrade_authority(&some), Some(Some(auth)));
        let mut fin = data.clone();
        fin.push(0);
        assert_eq!(upgrade_authority(&fin), Some(None));
    }

    #[test]
    fn keys_are_hex_or_base58() {
        let k = Pubkey::new_unique();
        assert_eq!(parse_key(&k.to_string()).unwrap(), k);
        assert_eq!(parse_key(&hex(k.as_ref())).unwrap(), k);
        assert!(parse_key("nope").is_err());
        assert!(parse_key(&hex(k.as_ref()).to_uppercase()).is_err());
    }

    #[test]
    fn the_secret_file_is_64_lowercase_hex_with_at_most_one_line_feed() {
        let h = hex(&[0xab; 32]);
        assert_eq!(read_secret_text(&format!("{h}\n")).unwrap(), [0xab; 32]);
        assert_eq!(read_secret_text(&h).unwrap(), [0xab; 32]);
        assert!(read_secret_text(&format!("{h}\n\n")).is_err());
        assert!(read_secret_text(&h[2..]).is_err());
        assert!(read_secret_text(&h.to_uppercase()).is_err());
        assert!(read_secret_text("").is_err());
    }

    /// A state account as the program itself writes it.
    fn state_of(h: &Htlc, recipient: &Pubkey, amount: u64, timeout: i64) -> Vec<u8> {
        use impulse_htlc::state::{Htlc as State, HTLC_LEN};
        let a = |k: &Pubkey| pinocchio::address::Address::new_from_array(k.to_bytes());
        let mut out = vec![0u8; HTLC_LEN];
        State {
            bump: 255,
            escrow_bump: 254,
            funder: a(&h.funder),
            token_program: a(&spl_token::id()),
            mint: a(&h.mint),
            escrow: a(&h.escrow()),
            recipient: a(recipient),
            refund: a(&h.funder),
            hash_lock: h.hash,
            amount,
            timeout,
            decimals: DECIMALS,
        }
        .write(&mut out)
        .unwrap();
        out
    }

    /// Security review: the claim broadcasts the preimage, so before it signs it reads the live
    /// HTLC and refuses one that pays another owner, holds another amount, or times out too soon
    /// for the claim to land.
    #[test]
    fn the_claim_checks_the_live_htlc_before_revealing() {
        let h = Htlc {
            program: Pubkey::new_unique(),
            funder: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            hash: [7; 32],
        };
        let me = Pubkey::new_unique();
        let now = 1_900_000_000i64;
        let good = state_of(&h, &me, 250_000, now + 3 * 3600);
        let ok = |data: &[u8], expect: Option<u64>, owner: &Pubkey, lead: i64| {
            claim_check(data, &h, expect, owner, now, lead)
        };
        assert_eq!(ok(&good, Some(250_000), &me, DEFAULT_MIN_LEAD_SECS), Ok(()));
        assert_eq!(ok(&good, None, &me, DEFAULT_MIN_LEAD_SECS), Ok(()));
        // Another amount.
        assert!(ok(&good, Some(250_001), &me, DEFAULT_MIN_LEAD_SECS)
            .unwrap_err()
            .contains("amount"));
        // Another recipient.
        assert!(ok(
            &good,
            Some(250_000),
            &Pubkey::new_unique(),
            DEFAULT_MIN_LEAD_SECS
        )
        .unwrap_err()
        .contains("recipient"));
        // Too little time left: the lead must be more than --min-lead.
        let soon = state_of(&h, &me, 250_000, now + DEFAULT_MIN_LEAD_SECS);
        assert!(ok(&soon, None, &me, DEFAULT_MIN_LEAD_SECS)
            .unwrap_err()
            .contains("timeout"));
        let just = state_of(&h, &me, 250_000, now + DEFAULT_MIN_LEAD_SECS + 1);
        assert_eq!(ok(&just, None, &me, DEFAULT_MIN_LEAD_SECS), Ok(()));
        assert!(ok(&good, None, &me, 3 * 3600).is_err());
        // Another hash lock, mint or funder: not this HTLC.
        for other in [
            Htlc {
                hash: [8; 32],
                ..h.clone()
            },
            Htlc {
                mint: Pubkey::new_unique(),
                ..h.clone()
            },
            Htlc {
                funder: Pubkey::new_unique(),
                ..h.clone()
            },
        ] {
            assert!(ok(
                &state_of(&other, &me, 250_000, now + 3 * 3600),
                None,
                &me,
                60
            )
            .is_err());
        }
        // Not a state account.
        assert!(ok(&good[..244], None, &me, 60).is_err());
        let mut bad = good.clone();
        bad[0] = 0;
        assert!(ok(&bad, None, &me, 60).is_err());
        assert_eq!(DEFAULT_MIN_LEAD_SECS, 7_200);
    }

    #[test]
    fn instruction_layout_matches_the_program_documentation() {
        let h = Htlc {
            program: Pubkey::new_unique(),
            funder: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            hash: [7; 32],
        };
        let (r, f) = (Pubkey::new_unique(), Pubkey::new_unique());
        let o = h.open(&Pubkey::new_unique(), 100_000, 1_900_000_000, &r, &f);
        assert_eq!(o.data.len(), 1 + 8 + 32 + 8 + 32 + 32);
        assert_eq!(o.data[0], IX_OPEN);
        assert_eq!(o.accounts.len(), 7);
        assert!(o.accounts[0].is_signer && !o.accounts[1].is_signer);
        let c = h.close(&Pubkey::new_unique(), Some(&[9; 32]));
        assert_eq!(
            (c.data[0], c.data.len(), c.accounts.len()),
            (IX_CLAIM, 33, 6)
        );
        let rf = h.close(&Pubkey::new_unique(), None);
        assert_eq!((rf.data.clone(), rf.accounts.len()), (vec![IX_REFUND], 6));
        assert_eq!(c.accounts[0].pubkey, h.address());
        assert_eq!(c.accounts[1].pubkey, h.escrow());
    }
}
