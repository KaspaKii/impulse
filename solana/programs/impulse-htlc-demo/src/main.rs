// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The Solana side of the hashlock exchange: demo/xchain-demo.sh on devnet, and the same flow
//! on mainnet-beta. (The name says "demo" for history; it is the
//! tool for both.) One command per call, flags as `--name value`:
//!
//! - `setup`: a test USDC mint (6 decimals, freeze authority set to the issuer key, like USDC),
//!   token accounts for the buyer and the seller, test USDC for the buyer, a little SOL for the
//!   seller. Idempotent through `--state`.
//! - `ids`: the identifiers `impulse xchain` wants, as 64 hex digits.
//! - `now`: the cluster clock, unix seconds.
//! - `open`: the buyer opens an impulse-htlc.
//! - `claim`: claim an impulse-htlc with the secret read from a file (never printed). Before it
//!   signs, it reads the live HTLC state and refuses unless the HTLC pays the destination owner,
//!   holds exactly `--expect-amount` (required on mainnet), and times out more than `--min-lead`
//!   seconds (default 7,200, the claim lead of spec/V2.md section 10.5) after the cluster time.
//! - `refund`: refund an impulse-htlc after its timeout.
//! - `balance`: the test USDC balance of an owner.
//! - `ata`: create the USDC token account of an owner (idempotent), paid by `--payer-key`.
//!
//! Mainnet-beta is acted on only with `--network mainnet` and a cluster whose genesis hash is
//! mainnet-beta's; either alone is refused. There the tool also needs `--program` (the key
//! holder's own deployed ID, never the placeholder), accepts only the pinned USDC mint, caps
//! `open` at 10 USDC (`IMPULSE_MAX_USDC` may lower it; `--i-accept-the-risk` lifts it; `claim` and
//! `refund` are never capped), refuses `setup` (it makes a test mint), prints the R2 notice on
//! stderr, and warns that the issuer holds a freeze authority (D47). `--priority-micro-lamports`
//! adds a compute-unit price to every transaction it sends.
//!
//! Keypair files are read from the paths the caller names and used only to sign; they are never
//! printed, logged or written. The secret is read from a file and never printed. Prints public
//! data only: addresses, amounts and signatures.

use impulse_htlc_demo::{
    ata, cap_units, check_cap, claim_check, hex, mainnet_mint_ok, mainnet_program_ok, net_guard,
    parse_key, programdata_address, read_secret_text, sha256, unhex32, upgrade_authority, Htlc,
    Net, DECIMALS, DEFAULT_MIN_LEAD_SECS, R2_NOTICE,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use std::{collections::BTreeMap, process::ExitCode, str::FromStr};

type Res<T> = Result<T, String>;

/// Test USDC the buyer is topped up to, in base units (5.000000).
const BUYER_TOKENS: u64 = 5_000_000;
/// SOL the seller keeps for transaction fees, in lamports.
const SELLER_LAMPORTS: u64 = 5_000_000;

struct Flags(BTreeMap<String, String>);

impl Flags {
    fn parse(args: impl Iterator<Item = String>) -> Res<Self> {
        let mut m = BTreeMap::new();
        let mut it = args;
        while let Some(k) = it.next() {
            let k = k
                .strip_prefix("--")
                .ok_or(format!("unexpected argument {k}"))?
                .to_string();
            // The one switch without a value, as in the Kaspa CLI.
            let v = if k == "i-accept-the-risk" {
                "yes".to_string()
            } else {
                it.next().ok_or(format!("--{k} needs a value"))?
            };
            if m.insert(k.clone(), v).is_some() {
                return Err(format!("--{k} given twice"));
            }
        }
        Ok(Self(m))
    }

    fn get(&mut self, k: &str) -> Res<String> {
        self.0.remove(k).ok_or(format!("--{k} is required"))
    }

    fn opt(&mut self, k: &str) -> Option<String> {
        self.0.remove(k)
    }

    fn done(&self) -> Res<()> {
        match self.0.keys().next() {
            Some(k) => Err(format!("unknown flag --{k}")),
            None => Ok(()),
        }
    }
}

fn keypair(path: &str, role: &str) -> Res<Keypair> {
    // The error names the role only, never the file contents.
    read_keypair_file(path).map_err(|_| format!("cannot read the {role} keypair file"))
}

fn pubkey(s: &str, what: &str) -> Res<Pubkey> {
    parse_key(s).map_err(|e| format!("{what}: {e}"))
}

fn num<T: FromStr>(s: &str, what: &str) -> Res<T> {
    s.parse().map_err(|_| format!("{what} is not a number"))
}

/// The cluster a command acts on, after the network guard.
struct Ctx {
    rpc: RpcClient,
    net: Net,
    accept_risk: bool,
    prio: Option<u64>,
}

/// The largest compute-unit price accepted, in micro-lamports (1,000,000 is 0.0002 SOL at 200,000
/// units).
const MAX_PRIORITY: u64 = 1_000_000;

fn connect(f: &mut Flags) -> Res<Ctx> {
    let url = f.get("url")?;
    let network = f.opt("network");
    let accept_risk = f.opt("i-accept-the-risk").is_some();
    let prio = f
        .opt("priority-micro-lamports")
        .map(|v| num::<u64>(&v, "--priority-micro-lamports"))
        .transpose()?;
    if prio.is_some_and(|p| p > MAX_PRIORITY) {
        return Err(format!(
            "--priority-micro-lamports is at most {MAX_PRIORITY}"
        ));
    }
    let rpc = RpcClient::new_with_commitment(url, CommitmentConfig::confirmed());
    let genesis = rpc
        .get_genesis_hash()
        .map_err(|e| format!("cannot reach the cluster: {e}"))?;
    let net = net_guard(&genesis.to_string(), network.as_deref())?;
    if net == Net::Mainnet {
        eprintln!("{R2_NOTICE}");
    }
    Ok(Ctx {
        rpc,
        net,
        accept_risk,
        prio,
    })
}

impl Ctx {
    fn mainnet(&self) -> bool {
        self.net == Net::Mainnet
    }

    /// The mainnet checks that need no key: the pinned mint, an explicit non-placeholder
    /// program that is deployed, and what is on chain about each. A no-op off mainnet.
    fn guard(&self, program: Option<&Pubkey>, mint: Option<&Pubkey>) -> Res<()> {
        if !self.mainnet() {
            return Ok(());
        }
        // The checks that need no network come first.
        if let Some(m) = mint {
            mainnet_mint_ok(m)?;
        }
        if let Some(p) = program {
            mainnet_program_ok(p)?;
        }
        if let Some(m) = mint {
            let acct = self
                .rpc
                .get_account(m)
                .map_err(|_| format!("mint {m} is not on this cluster"))?;
            let state = spl_token::state::Mint::unpack(&acct.data)
                .ok()
                .filter(|_| acct.owner == spl_token::id())
                .ok_or("the USDC mint is not an SPL Token mint")?;
            if state.decimals != DECIMALS {
                return Err(format!(
                    "the mint has {} decimals, not {DECIMALS}",
                    state.decimals
                ));
            }
            match Option::<Pubkey>::from(state.freeze_authority) {
                Some(a) => eprintln!(
                    "warning: mint {m} has a freeze authority, {a}. The issuer can freeze the escrow or either token account (D47: the issuer is trusted, not controlled)."
                ),
                None => eprintln!("note: mint {m} has no freeze authority."),
            }
        }
        if let Some(p) = program {
            let acct = self
                .rpc
                .get_account(p)
                .map_err(|_| format!("program {p} is not on this cluster"))?;
            if !acct.executable {
                return Err(format!("{p} is not an executable program"));
            }
            let pd = programdata_address(&acct.data)
                .ok_or("the program is not owned by the upgradeable loader; verify it by hand")?;
            let data = self
                .rpc
                .get_account(&pd)
                .map_err(|_| "cannot read the program-data account".to_string())?;
            match upgrade_authority(&data.data) {
                Some(Some(a)) => println!("program_upgrade_authority: {a}"),
                Some(None) => println!("program_upgrade_authority: none (final)"),
                None => return Err("the program-data account is not what the loader writes".into()),
            }
        }
        Ok(())
    }
}

fn send(
    ctx: &Ctx,
    what: &str,
    payer: &Keypair,
    ixs: &[Instruction],
    extra: &[&Keypair],
) -> Res<String> {
    let rpc = &ctx.rpc;
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let mut all: Vec<Instruction> = Vec::new();
    if let Some(p) = ctx.prio {
        all.push(ComputeBudgetInstruction::set_compute_unit_price(p));
    }
    all.extend_from_slice(ixs);
    let bh = rpc
        .get_latest_blockhash()
        .map_err(|e| format!("{what}: blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(&all, Some(&payer.pubkey()), &signers, bh);
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .map_err(|e| format!("{what}: {e}"))?;
    Ok(sig.to_string())
}

fn token_balance(rpc: &RpcClient, account: &Pubkey) -> Res<u64> {
    match rpc.get_token_account_balance(account) {
        Ok(b) => b
            .amount
            .parse()
            .map_err(|_| "balance is not a number".to_string()),
        Err(_) => Ok(0),
    }
}

fn lamports(rpc: &RpcClient, key: &Pubkey) -> Res<u64> {
    rpc.get_balance(key)
        .map_err(|e| format!("balance of {key}: {e}"))
}

fn cluster_time(rpc: &RpcClient) -> Res<i64> {
    let slot = rpc.get_slot().map_err(|e| format!("slot: {e}"))?;
    for back in 0..20 {
        if let Ok(t) = rpc.get_block_time(slot.saturating_sub(back)) {
            return Ok(t);
        }
    }
    Err("no block time near the current slot".into())
}

fn setup(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    if ctx.mainnet() {
        return Err("setup makes a test USDC mint and is refused on mainnet".into());
    }
    let rpc = &ctx.rpc;
    let buyer = keypair(&f.get("buyer-key")?, "buyer")?;
    let seller = keypair(&f.get("seller-key")?, "seller")?;
    let issuer = keypair(&f.get("issuer-key")?, "issuer")?;
    let state = f.get("state")?;
    let freeze = f
        .opt("freeze-authority")
        .map_or(Ok(true), |v| match v.as_str() {
            "yes" => Ok(true),
            "no" => Ok(false),
            _ => Err("--freeze-authority is yes or no".to_string()),
        })?;
    f.done()?;
    // The mint of an earlier run is reused while it exists on this cluster.
    let known = std::fs::read_to_string(&state)
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("mint: ").map(str::to_string))
        })
        .and_then(|m| Pubkey::from_str(&m).ok())
        .filter(|m| rpc.get_account(m).is_ok());
    let mint = match known {
        Some(m) => m,
        None => {
            let mint = Keypair::new();
            let rent = rpc
                .get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)
                .map_err(|e| format!("rent: {e}"))?;
            let ixs = [
                solana_system_interface::instruction::create_account(
                    &buyer.pubkey(),
                    &mint.pubkey(),
                    rent,
                    spl_token::state::Mint::LEN as u64,
                    &spl_token::id(),
                ),
                spl_token::instruction::initialize_mint2(
                    &spl_token::id(),
                    &mint.pubkey(),
                    &issuer.pubkey(),
                    freeze.then(|| issuer.pubkey()).as_ref(),
                    DECIMALS,
                )
                .map_err(|e| e.to_string())?,
            ];
            let sig = send(&ctx, "create mint", &buyer, &ixs, &[&mint])?;
            println!("create_mint_txid: {sig}");
            mint.pubkey()
        }
    };
    let (bata, sata) = (ata(&buyer.pubkey(), &mint), ata(&seller.pubkey(), &mint));
    let ixs = [
        create_associated_token_account_idempotent(
            &buyer.pubkey(),
            &buyer.pubkey(),
            &mint,
            &spl_token::id(),
        ),
        create_associated_token_account_idempotent(
            &buyer.pubkey(),
            &seller.pubkey(),
            &mint,
            &spl_token::id(),
        ),
    ];
    send(&ctx, "token accounts", &buyer, &ixs, &[])?;
    let have = token_balance(rpc, &bata)?;
    if have < BUYER_TOKENS {
        let ix = spl_token::instruction::mint_to(
            &spl_token::id(),
            &mint,
            &bata,
            &issuer.pubkey(),
            &[],
            BUYER_TOKENS - have,
        )
        .map_err(|e| e.to_string())?;
        let sig = send(&ctx, "mint test USDC", &buyer, &[ix], &[&issuer])?;
        println!("mint_txid: {sig}");
    }
    if lamports(rpc, &seller.pubkey())? < SELLER_LAMPORTS {
        let ix = solana_system_interface::instruction::transfer(
            &buyer.pubkey(),
            &seller.pubkey(),
            SELLER_LAMPORTS,
        );
        send(&ctx, "seller fee money", &buyer, &[ix], &[])?;
    }
    if token_balance(rpc, &bata)? < BUYER_TOKENS {
        return Err("the buyer's test USDC balance is below the target after the mint".into());
    }
    let text = format!(
        "mint: {mint}\nfreeze_authority: {}\n",
        if freeze {
            issuer.pubkey().to_string()
        } else {
            "none".into()
        }
    );
    std::fs::write(&state, text).map_err(|e| format!("{state}: {e}"))?;
    println!("mint: {mint}");
    println!("buyer_usdc: {}", token_balance(rpc, &bata)?);
    println!("seller_usdc: {}", token_balance(rpc, &sata)?);
    Ok(())
}

fn ids(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    let rpc = &ctx.rpc;
    let program = pubkey(&f.get("program")?, "--program")?;
    let mint = f.opt("mint").map(|m| pubkey(&m, "--mint")).transpose()?;
    ctx.guard(Some(&program), mint.as_ref())?;
    let buyer = keypair(&f.get("buyer-key")?, "buyer")?.pubkey();
    let seller = keypair(&f.get("seller-key")?, "seller")?.pubkey();
    f.done()?;
    let genesis = rpc.get_genesis_hash().map_err(|e| e.to_string())?;
    let exe = rpc
        .get_account(&program)
        .map_err(|_| format!("program {program} is not on this cluster"))?;
    if !exe.executable {
        return Err(format!("{program} is not an executable program"));
    }
    println!("chain_id: {}", hex(&genesis.to_bytes()));
    println!("program: {}", hex(program.as_ref()));
    if let Some(mint) = mint {
        println!("asset: {}", hex(mint.as_ref()));
    }
    println!("buyer_account: {}", hex(buyer.as_ref()));
    println!("seller_account: {}", hex(seller.as_ref()));
    println!("buyer_address: {buyer}");
    println!("seller_address: {seller}");
    Ok(())
}

fn now(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    f.done()?;
    println!("{}", cluster_time(&ctx.rpc)?);
    Ok(())
}

fn open(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    let rpc = &ctx.rpc;
    let program = pubkey(&f.get("program")?, "--program")?;
    let mint = pubkey(&f.get("mint")?, "--mint")?;
    let amount: u64 = num(&f.get("amount")?, "--amount")?;
    // The mainnet checks come before any key file is read.
    if ctx.mainnet() {
        let cap = cap_units(std::env::var("IMPULSE_MAX_USDC").ok().as_deref())?;
        println!("{}", check_cap(amount, cap, ctx.accept_risk)?);
        ctx.guard(Some(&program), Some(&mint))?;
    }
    let funder = keypair(&f.get("funder-key")?, "funder")?;
    let h = Htlc {
        program,
        funder: funder.pubkey(),
        mint,
        hash: unhex32(&f.get("hash")?).ok_or("--hash is not 64 lowercase hex digits")?,
    };
    let timeout: i64 = num(&f.get("timeout")?, "--timeout")?;
    let recipient = pubkey(&f.get("recipient")?, "--recipient")?;
    let refund = pubkey(&f.get("refund")?, "--refund")?;
    f.done()?;
    let source = ata(&funder.pubkey(), &h.mint);
    let ix = h.open(&source, amount, timeout, &recipient, &refund);
    let sig = send(&ctx, "open", &funder, &[ix], &[])?;
    let held = token_balance(rpc, &h.escrow())?;
    if held != amount {
        return Err(format!("the escrow holds {held}, not {amount}"));
    }
    println!("txid: {sig}");
    println!("htlc: {}", h.address());
    println!("escrow: {}", h.escrow());
    println!("escrow_holds: {held}");
    Ok(())
}

fn close(mut f: Flags, claim: bool) -> Res<()> {
    let ctx = connect(&mut f)?;
    let rpc = &ctx.rpc;
    let program = pubkey(&f.get("program")?, "--program")?;
    let mint = pubkey(&f.get("mint")?, "--mint")?;
    // What the claim checks in the live HTLC before it reveals the secret.
    let (expect, min_lead) = if claim {
        let expect = f
            .opt("expect-amount")
            .map(|v| num::<u64>(&v, "--expect-amount"))
            .transpose()?;
        let min_lead = f
            .opt("min-lead")
            .map(|v| num::<i64>(&v, "--min-lead"))
            .transpose()?
            .unwrap_or(DEFAULT_MIN_LEAD_SECS);
        if min_lead < 0 {
            return Err("--min-lead is a number of seconds, not negative".into());
        }
        if ctx.mainnet() && expect.is_none() {
            return Err("--expect-amount is required on mainnet: the amount, in base units, the HTLC must hold before the claim reveals the secret".into());
        }
        (expect, min_lead)
    } else {
        (None, 0)
    };
    ctx.guard(Some(&program), Some(&mint))?;
    let payer = keypair(&f.get("payer-key")?, "payer")?;
    let h = Htlc {
        program,
        funder: pubkey(&f.get("funder")?, "--funder")?,
        mint,
        hash: unhex32(&f.get("hash")?).ok_or("--hash is not 64 lowercase hex digits")?,
    };
    let secret = if claim {
        let path = f.get("secret-file")?;
        check_private(&path)?;
        let text = std::fs::read_to_string(&path)
            .map_err(|_| "cannot read the secret file".to_string())?;
        let s = read_secret_text(&text)?;
        if sha256(&s) != h.hash {
            return Err("sha256 of the secret file is not --hash: not claiming".into());
        }
        Some(s)
    } else {
        None
    };
    let owner = match f.opt("dest-owner") {
        Some(o) => pubkey(&o, "--dest-owner")?,
        None => payer.pubkey(),
    };
    f.done()?;
    let dest = ata(&owner, &h.mint);
    let escrow = token_balance(rpc, &h.escrow())?;
    if escrow == 0 {
        return Err(format!(
            "htlc {} has no escrow on this cluster",
            h.address()
        ));
    }
    if claim {
        // The claim publishes the secret: read the live HTLC first, and refuse one that pays
        // another owner, holds another amount, or times out too soon for the claim to land.
        let acct = rpc
            .get_account(&h.address())
            .map_err(|_| format!("htlc {} is not on this cluster", h.address()))?;
        if acct.owner != h.program {
            return Err(format!("htlc {} is not owned by the program", h.address()));
        }
        claim_check(&acct.data, &h, expect, &owner, cluster_time(rpc)?, min_lead)?;
    }
    let before = token_balance(rpc, &dest)?;
    let ix = h.close(&dest, secret.as_ref());
    let sig = send(
        &ctx,
        if claim { "claim" } else { "refund" },
        &payer,
        &[ix],
        &[],
    )?;
    let paid = token_balance(rpc, &dest)?.saturating_sub(before);
    if paid != escrow {
        return Err(format!("paid {paid}, the escrow held {escrow}"));
    }
    println!("txid: {sig}");
    println!("paid: {paid}");
    println!("to_owner: {owner}");
    Ok(())
}

/// The secret file must be a regular file only its owner can access.
fn check_private(path: &str) -> Res<()> {
    let meta = std::fs::metadata(path).map_err(|_| "cannot read the secret file".to_string())?;
    if !meta.is_file() {
        return Err("the secret file is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("group or others can access the secret file; it must be mode 0600".into());
        }
    }
    Ok(())
}

fn balance(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    let owner = pubkey(&f.get("owner")?, "--owner")?;
    let mint = pubkey(&f.get("mint")?, "--mint")?;
    f.done()?;
    if ctx.mainnet() {
        mainnet_mint_ok(&mint)?;
    }
    println!("{}", token_balance(&ctx.rpc, &ata(&owner, &mint))?);
    Ok(())
}

/// Creates the token account of `--owner` for `--mint`, paid by the payer (idempotent). A claim
/// and a refund pay into an existing token account, so both parties need theirs first.
fn make_ata(mut f: Flags) -> Res<()> {
    let ctx = connect(&mut f)?;
    let mint = pubkey(&f.get("mint")?, "--mint")?;
    ctx.guard(None, Some(&mint))?;
    let payer = keypair(&f.get("payer-key")?, "payer")?;
    let owner = pubkey(&f.get("owner")?, "--owner")?;
    f.done()?;
    let ix = create_associated_token_account_idempotent(
        &payer.pubkey(),
        &owner,
        &mint,
        &spl_token::id(),
    );
    let sig = send(&ctx, "token account", &payer, &[ix], &[])?;
    println!("txid: {sig}");
    println!("token_account: {}", ata(&owner, &mint));
    Ok(())
}

fn run() -> Res<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or(
        "usage: impulse-htlc-demo <setup|ids|now|open|claim|refund|balance|ata> --flag value ...",
    )?;
    let f = Flags::parse(args)?;
    match cmd.as_str() {
        "setup" => setup(f),
        "ids" => ids(f),
        "now" => now(f),
        "open" => open(f),
        "claim" => close(f, true),
        "refund" => close(f, false),
        "balance" => balance(f),
        "ata" => make_ata(f),
        other => Err(format!("unknown command {other}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("impulse-htlc-demo: {e}");
            ExitCode::FAILURE
        }
    }
}
