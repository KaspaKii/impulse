// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I19 devnet run. Against a deployed copy of impulse-solana and impulse-htlc:
//!
//! 1. two test SPL mints (TEST-ASSET, and TEST-USDC standing in for USDC; neither is a real
//!    asset, both are created here with no freeze authority);
//! 2. one impulse-solana escrow whose PDA binds the terms hash of one Impulse term sheet
//!    (`solana/tests/fixtures/term-sheets.json`): CreateDvp, fund leg A, fund leg B, SettleDvp;
//! 3. one impulse-htlc open then claim with the preimage, and one open then refund at timeout.
//!
//! Every step checks exact balances afterwards and fails closed. Writes a JSON record of public
//! data (addresses, transaction signatures, balances) to `--out`. Reads the three keypair files
//! the caller names; never prints, logs or writes a key. Refuses mainnet (genesis hash check).

use std::{
    collections::BTreeMap,
    process::ExitCode,
    str::FromStr,
    thread::sleep,
    time::{Duration, Instant},
};

use impulse_solana_client::instructions::{CreateDvpBuilder, SettleDvpBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id,
    instruction::create_associated_token_account_idempotent,
};

const MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const DECIMALS: u8 = 6;
/// Leg A: 1.000000 TEST-ASSET from party A. Leg B: 2.500000 TEST-USDC from party B.
const AMOUNT_A: u64 = 1_000_000;
const AMOUNT_B: u64 = 2_500_000;
/// Each HTLC locks 0.100000 TEST-USDC.
const HTLC_AMOUNT: u64 = 100_000;
/// SOL the payer sends party A, which pays the rent of the two HTLC accounts it opens.
const PARTY_A_LAMPORTS: u64 = 20_000_000;
/// Seconds until the refund HTLC times out.
const REFUND_TIMEOUT_SECS: i64 = 20;
const HTLC_SEED: &[u8] = b"htlc";
const ESCROW_SEED: &[u8] = b"escrow";
const SWAP_DVP_SEED: &[u8] = b"dvp";
const NONCE_TOMBSTONE_SEED: &[u8] = b"nonce";

type Res<T> = Result<T, String>;

struct Args {
    url: String,
    cluster: String,
    payer: String,
    party_a: String,
    party_b: String,
    impulse_program: Pubkey,
    htlc_program: Pubkey,
    term_sheets: String,
    sheet: String,
    out: String,
}

fn parse_args() -> Res<Args> {
    let mut m = BTreeMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let k = k
            .strip_prefix("--")
            .ok_or(format!("unexpected argument {k}"))?
            .to_string();
        let v = it.next().ok_or(format!("--{k} needs a value"))?;
        m.insert(k, v);
    }
    let mut get = |k: &str| m.remove(k).ok_or(format!("--{k} is required"));
    let pk = |s: String| Pubkey::from_str(&s).map_err(|e| format!("bad program id {s}: {e}"));
    let a = Args {
        url: get("url")?,
        cluster: get("cluster")?,
        payer: get("payer")?,
        party_a: get("party-a")?,
        party_b: get("party-b")?,
        impulse_program: pk(get("impulse-program")?)?,
        htlc_program: pk(get("htlc-program")?)?,
        term_sheets: get("term-sheets")?,
        sheet: get("sheet")?,
        out: get("out")?,
    };
    if let Some(k) = m.keys().next() {
        return Err(format!("unknown argument --{k}"));
    }
    Ok(a)
}

fn keypair(path: &str, role: &str) -> Res<Keypair> {
    // The error names the role only, never the file contents.
    read_keypair_file(path).map_err(|_| format!("cannot read the {role} keypair file"))
}

struct Run {
    rpc: RpcClient,
    payer: Keypair,
    steps: Vec<Value>,
}

impl Run {
    fn send(&mut self, step: &str, ixs: &[Instruction], extra: &[&Keypair]) -> Res<String> {
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let bh = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| format!("{step}: blockhash: {e}"))?;
        let tx = Transaction::new_signed_with_payer(ixs, Some(&self.payer.pubkey()), &signers, bh);
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| format!("{step}: {e}"))?;
        println!("{step}: {sig}");
        self.steps
            .push(json!({"step": step, "signature": sig.to_string()}));
        Ok(sig.to_string())
    }

    fn token_balance(&self, ata: &Pubkey) -> Res<u64> {
        let b = self
            .rpc
            .get_token_account_balance(ata)
            .map_err(|e| format!("balance of {ata}: {e}"))?;
        b.amount
            .parse::<u64>()
            .map_err(|e| format!("balance of {ata}: {e}"))
    }

    fn gone(&self, key: &Pubkey) -> Res<bool> {
        let r = self
            .rpc
            .get_account_with_commitment(key, CommitmentConfig::confirmed())
            .map_err(|e| format!("account {key}: {e}"))?;
        Ok(r.value.is_none())
    }

    fn cluster_time(&self) -> Res<i64> {
        let slot = self.rpc.get_slot().map_err(|e| format!("slot: {e}"))?;
        self.rpc
            .get_block_time(slot)
            .map_err(|e| format!("block time: {e}"))
    }
}

fn expect_eq(what: &str, got: u64, want: u64) -> Res<()> {
    if got == want {
        println!("check: {what} = {got}");
        Ok(())
    } else {
        Err(format!("{what}: got {got}, want {want}"))
    }
}

fn expect(what: &str, cond: bool) -> Res<()> {
    if cond {
        println!("check: {what}");
        Ok(())
    } else {
        Err(format!("check failed: {what}"))
    }
}

fn create_mint(run: &mut Run, name: &str) -> Res<Pubkey> {
    let mint = Keypair::new();
    let rent = run
        .rpc
        .get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)
        .map_err(|e| format!("rent: {e}"))?;
    let payer = run.payer.pubkey();
    let ixs = [
        solana_system_interface::instruction::create_account(
            &payer,
            &mint.pubkey(),
            rent,
            spl_token::state::Mint::LEN as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_mint2(
            &spl_token::id(),
            &mint.pubkey(),
            &payer,
            None,
            DECIMALS,
        )
        .map_err(|e| e.to_string())?,
    ];
    run.send(&format!("create mint {name}"), &ixs, &[&mint])?;
    Ok(mint.pubkey())
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    get_associated_token_address_with_program_id(owner, mint, &spl_token::id())
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    create_associated_token_account_idempotent(payer, owner, mint, &spl_token::id())
}

fn mint_to(run: &mut Run, mint: &Pubkey, dest: &Pubkey, amount: u64, step: &str) -> Res<()> {
    let ix = spl_token::instruction::mint_to(
        &spl_token::id(),
        mint,
        dest,
        &run.payer.pubkey(),
        &[],
        amount,
    )
    .map_err(|e| e.to_string())?;
    run.send(step, &[ix], &[])?;
    Ok(())
}

fn transfer_checked(
    owner: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    dest: &Pubkey,
    amount: u64,
) -> Res<Instruction> {
    spl_token::instruction::transfer_checked(
        &spl_token::id(),
        source,
        mint,
        dest,
        owner,
        &[],
        amount,
        DECIMALS,
    )
    .map_err(|e| e.to_string())
}

fn hex32(s: &str) -> Res<[u8; 32]> {
    if s.len() != 64 {
        return Err("terms hash is not 32 bytes of hex".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| "terms hash is not hex".to_string())?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The terms hash and nonce of the named term sheet in the fixture.
fn term_sheet(path: &str, name: &str) -> Res<([u8; 32], u64, String)> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let sheet = v["term_sheets"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["name"] == name))
        .ok_or(format!("no term sheet named {name}"))?;
    let hash = hex32(
        sheet["expected"]["terms_hash"]
            .as_str()
            .ok_or("term sheet has no terms_hash")?,
    )?;
    let nonce = sheet["solana"]["nonce"]
        .as_str()
        .ok_or("term sheet has no nonce")?
        .parse::<u64>()
        .map_err(|e| format!("nonce: {e}"))?;
    let vector = sheet["terms_vector"].as_str().unwrap_or("").to_string();
    Ok((hash, nonce, vector))
}

fn settlement(run: &mut Run, a: &Args, pa: &Keypair, pb: &Keypair, rec: &mut Value) -> Res<()> {
    let (terms_hash, nonce, vector) = term_sheet(&a.term_sheets, &a.sheet)?;
    let payer = run.payer.pubkey();
    let (ua, ub) = (pa.pubkey(), pb.pubkey());
    let mint_a = create_mint(run, "TEST-ASSET (leg A)")?;
    let mint_b = create_mint(run, "TEST-USDC (leg B, stands in for USDC)")?;
    let (ua_a, ua_b, ub_a, ub_b) = (
        ata(&ua, &mint_a),
        ata(&ua, &mint_b),
        ata(&ub, &mint_a),
        ata(&ub, &mint_b),
    );
    run.send(
        "create party ATAs",
        &[
            create_ata_ix(&payer, &ua, &mint_a),
            create_ata_ix(&payer, &ua, &mint_b),
            create_ata_ix(&payer, &ub, &mint_a),
            create_ata_ix(&payer, &ub, &mint_b),
        ],
        &[],
    )?;
    mint_to(run, &mint_a, &ua_a, AMOUNT_A, "mint leg A to party A")?;
    mint_to(run, &mint_b, &ub_b, AMOUNT_B, "mint leg B to party B")?;

    let program = a.impulse_program;
    let nonce_le = nonce.to_le_bytes();
    let (swap_dvp, _) = Pubkey::find_program_address(
        &[
            SWAP_DVP_SEED,
            payer.as_ref(),
            ua.as_ref(),
            ub.as_ref(),
            mint_a.as_ref(),
            mint_b.as_ref(),
            &terms_hash,
            &nonce_le,
        ],
        &program,
    );
    let (tombstone, _) =
        Pubkey::find_program_address(&[NONCE_TOMBSTONE_SEED, swap_dvp.as_ref()], &program);
    let (dvp_a, dvp_b) = (ata(&swap_dvp, &mint_a), ata(&swap_dvp, &mint_b));
    let expiry = run.cluster_time()? + 3600;

    let mut create = CreateDvpBuilder::new()
        .terms_hash(terms_hash)
        .payer(payer)
        .swap_dvp(swap_dvp)
        .nonce_tombstone(tombstone)
        .mint_a(mint_a)
        .mint_b(mint_b)
        .dvp_ata_a(dvp_a)
        .dvp_ata_b(dvp_b)
        .token_program_a(spl_token::id())
        .token_program_b(spl_token::id())
        .user_a(ua)
        .user_b(ub)
        .settlement_authority(payer)
        .amount_a(AMOUNT_A)
        .amount_b(AMOUNT_B)
        .expiry_timestamp(expiry)
        .nonce(nonce)
        .instruction();
    // The generated client names the placeholder program ID; this run targets the deployed copy.
    create.program_id = program;
    run.send("CreateDvp", &[create], &[])?;
    expect(
        "SwapDvp exists at the term-sheet PDA",
        !run.gone(&swap_dvp)?,
    )?;

    let fund_a = transfer_checked(&ua, &ua_a, &mint_a, &dvp_a, AMOUNT_A)?;
    run.send("fund leg A (party A)", &[fund_a], &[pa])?;
    let fund_b = transfer_checked(&ub, &ub_b, &mint_b, &dvp_b, AMOUNT_B)?;
    run.send("fund leg B (party B)", &[fund_b], &[pb])?;
    expect_eq("escrow A", run.token_balance(&dvp_a)?, AMOUNT_A)?;
    expect_eq("escrow B", run.token_balance(&dvp_b)?, AMOUNT_B)?;

    let mut settle = SettleDvpBuilder::new()
        .terms_hash(terms_hash)
        .settlement_authority(payer)
        .swap_dvp(swap_dvp)
        .mint_a(mint_a)
        .mint_b(mint_b)
        .dvp_ata_a(dvp_a)
        .dvp_ata_b(dvp_b)
        .user_a_destination_ata_b(ua_b)
        .user_b_destination_ata_a(ub_a)
        .user_a_ata_a(ua_a)
        .user_b_ata_b(ub_b)
        .token_program_a(spl_token::id())
        .token_program_b(spl_token::id())
        .memo_program(Pubkey::from_str(MEMO_PROGRAM_ID).map_err(|e| e.to_string())?)
        .leg_a_extras_count(0)
        .instruction();
    settle.program_id = program;
    run.send("SettleDvp", &[settle], &[])?;
    expect_eq(
        "party A received leg B",
        run.token_balance(&ua_b)?,
        AMOUNT_B,
    )?;
    expect_eq(
        "party B received leg A",
        run.token_balance(&ub_a)?,
        AMOUNT_A,
    )?;
    expect_eq("party A leg A source", run.token_balance(&ua_a)?, 0)?;
    expect_eq("party B leg B source", run.token_balance(&ub_b)?, 0)?;
    let closed = run.gone(&swap_dvp)? && run.gone(&dvp_a)? && run.gone(&dvp_b)?;
    expect("SwapDvp and both escrows closed", closed)?;

    rec["settlement"] = json!({
        "term_sheet": a.sheet,
        "terms_vector": vector,
        "terms_hash": hex(&terms_hash),
        "nonce": nonce,
        "expiry_timestamp": expiry,
        "settlement_authority": payer.to_string(),
        "user_a": ua.to_string(),
        "user_b": ub.to_string(),
        "mint_a_test_asset": mint_a.to_string(),
        "mint_b_test_usdc_stand_in": mint_b.to_string(),
        "amount_a": AMOUNT_A,
        "amount_b": AMOUNT_B,
        "decimals": DECIMALS,
        "swap_dvp": swap_dvp.to_string(),
        "nonce_tombstone": tombstone.to_string(),
        "dvp_ata_a": dvp_a.to_string(),
        "dvp_ata_b": dvp_b.to_string(),
        "after": {
            "user_a_ata_b": AMOUNT_B, "user_b_ata_a": AMOUNT_A,
            "user_a_ata_a": 0, "user_b_ata_b": 0, "swap_dvp_and_escrows_closed": true
        }
    });
    rec["mint_b"] = json!(mint_b.to_string());
    Ok(())
}

struct Htlc {
    program: Pubkey,
    funder: Pubkey,
    mint: Pubkey,
    hash: [u8; 32],
}

impl Htlc {
    fn addr(&self) -> Pubkey {
        Pubkey::find_program_address(
            &[HTLC_SEED, self.funder.as_ref(), &self.hash],
            &self.program,
        )
        .0
    }
    fn escrow(&self) -> Pubkey {
        Pubkey::find_program_address(&[ESCROW_SEED, self.addr().as_ref()], &self.program).0
    }
    fn open(
        &self,
        source: &Pubkey,
        timeout: i64,
        recipient: &Pubkey,
        refund: &Pubkey,
    ) -> Instruction {
        let mut d = vec![0u8];
        d.extend_from_slice(&HTLC_AMOUNT.to_le_bytes());
        d.extend_from_slice(&self.hash);
        d.extend_from_slice(&timeout.to_le_bytes());
        d.extend_from_slice(recipient.as_ref());
        d.extend_from_slice(refund.as_ref());
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.funder, true),
                AccountMeta::new(self.addr(), false),
                AccountMeta::new(self.escrow(), false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_system_interface::program::id(), false),
            ],
            data: d,
        }
    }
    /// Claim (`preimage` given) or refund (`None`); rent goes back to the funder.
    fn close(&self, dest: &Pubkey, preimage: Option<&[u8; 32]>) -> Instruction {
        let mut data = vec![if preimage.is_some() { 1u8 } else { 2u8 }];
        if let Some(p) = preimage {
            data.extend_from_slice(p);
        }
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.addr(), false),
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

fn htlcs(run: &mut Run, a: &Args, pa: &Keypair, pb: &Keypair, rec: &mut Value) -> Res<()> {
    let mint: Pubkey = rec["mint_b"]
        .as_str()
        .and_then(|s| Pubkey::from_str(s).ok())
        .ok_or("no TEST-USDC mint from the settlement step")?;
    let (ua, ub) = (pa.pubkey(), pb.pubkey());
    let (ua_b, ub_b) = (ata(&ua, &mint), ata(&ub, &mint));
    // Party A funds both HTLCs from the TEST-USDC it received at settlement and pays their rent.
    let fee_ix =
        solana_system_interface::instruction::transfer(&run.payer.pubkey(), &ua, PARTY_A_LAMPORTS);
    run.send("send party A SOL for HTLC rent", &[fee_ix], &[])?;
    let mut out = Vec::new();

    for (kind, timeout_in) in [("claim", 3600i64), ("refund", REFUND_TIMEOUT_SECS)] {
        // A fresh random preimage per HTLC. It is not a key: claim publishes it on chain.
        let preimage: [u8; 32] = rand::random();
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let h = Htlc {
            program: a.htlc_program,
            funder: ua,
            mint,
            hash,
        };
        let a_before = run.token_balance(&ua_b)?;
        let b_before = run.token_balance(&ub_b)?;
        let timeout = run.cluster_time()? + timeout_in;
        let open_sig = run.send(
            &format!("HTLC open ({kind})"),
            &[h.open(&ua_b, timeout, &ub, &ua)],
            &[pa],
        )?;
        expect_eq("HTLC escrow", run.token_balance(&h.escrow())?, HTLC_AMOUNT)?;
        expect_eq(
            "party A after open",
            run.token_balance(&ua_b)?,
            a_before - HTLC_AMOUNT,
        )?;
        let close_sig = if kind == "claim" {
            // Submitted by the payer, a third party holding the preimage; pays party B.
            let s = run.send("HTLC claim", &[h.close(&ub_b, Some(&preimage))], &[])?;
            expect_eq(
                "party B after claim",
                run.token_balance(&ub_b)?,
                b_before + HTLC_AMOUNT,
            )?;
            s
        } else {
            let deadline = Instant::now() + Duration::from_secs(300);
            while run.cluster_time()? < timeout + 2 {
                if Instant::now() > deadline {
                    return Err("cluster clock did not pass the HTLC timeout".into());
                }
                sleep(Duration::from_secs(3));
            }
            let s = run.send("HTLC refund", &[h.close(&ua_b, None)], &[])?;
            expect_eq("party A after refund", run.token_balance(&ua_b)?, a_before)?;
            s
        };
        expect(
            "HTLC and its escrow closed",
            run.gone(&h.addr())? && run.gone(&h.escrow())?,
        )?;
        out.push(json!({
            "kind": kind,
            "htlc": h.addr().to_string(),
            "escrow": h.escrow().to_string(),
            "hash_lock": hex(&hash),
            "preimage_published_by_claim": if kind == "claim" { hex(&preimage) } else { String::new() },
            "amount": HTLC_AMOUNT,
            "timeout": timeout,
            "funder_and_refund_owner": ua.to_string(),
            "recipient": ub.to_string(),
            "open_signature": open_sig,
            "close_signature": close_sig,
        }));
    }
    rec["htlc"] = Value::Array(out);
    Ok(())
}

fn main_inner() -> Res<()> {
    let a = parse_args()?;
    let rpc = RpcClient::new_with_commitment(a.url.clone(), CommitmentConfig::confirmed());
    let genesis = rpc
        .get_genesis_hash()
        .map_err(|e| format!("genesis hash: {e}"))?
        .to_string();
    // Fail closed: never mainnet; "devnet" must really be devnet.
    if genesis == MAINNET_GENESIS {
        return Err("refused: the RPC endpoint is Solana mainnet".into());
    }
    match a.cluster.as_str() {
        "devnet" if genesis == DEVNET_GENESIS => {}
        "devnet" => return Err(format!("refused: genesis {genesis} is not devnet")),
        "localnet" if genesis != DEVNET_GENESIS => {}
        _ => {
            return Err(format!(
                "refused: cluster {} with genesis {genesis}",
                a.cluster
            ))
        }
    }
    let pa = keypair(&a.party_a, "party A")?;
    let pb = keypair(&a.party_b, "party B")?;
    let mut run = Run {
        rpc,
        payer: keypair(&a.payer, "payer")?,
        steps: Vec::new(),
    };
    for (name, id) in [
        ("impulse-solana", a.impulse_program),
        ("impulse-htlc", a.htlc_program),
    ] {
        let acc = run
            .rpc
            .get_account(&id)
            .map_err(|e| format!("{name} program {id}: {e}"))?;
        expect(
            &format!("{name} program {id} is executable"),
            acc.executable,
        )?;
    }
    let mut rec = json!({
        "cluster": a.cluster,
        "genesis_hash": genesis,
        "impulse_solana_program": a.impulse_program.to_string(),
        "impulse_htlc_program": a.htlc_program.to_string(),
        "payer_and_settlement_authority": run.payer.pubkey().to_string(),
        "party_a": pa.pubkey().to_string(),
        "party_b": pb.pubkey().to_string(),
        "note": "TEST-ASSET and TEST-USDC are test SPL mints created by this run; TEST-USDC stands in for USDC and is not USDC. All keys were throwaway keys generated for this run and deleted after it.",
    });
    let result = settlement(&mut run, &a, &pa, &pb, &mut rec)
        .and_then(|_| htlcs(&mut run, &a, &pa, &pb, &mut rec));
    rec["transactions"] = Value::Array(std::mem::take(&mut run.steps));
    rec["result"] = json!(match &result {
        Ok(()) => "pass".to_string(),
        Err(e) => format!("fail: {e}"),
    });
    if let Some(o) = rec.as_object_mut() {
        o.remove("mint_b");
    }
    let text = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&a.out, text).map_err(|e| format!("{}: {e}", a.out))?;
    result
}

fn main() -> ExitCode {
    match main_inner() {
        Ok(()) => {
            println!("impulse-solana-devnet: pass");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("impulse-solana-devnet: FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
