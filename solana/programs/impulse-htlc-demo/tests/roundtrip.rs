// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The demo tool's instructions against the real impulse-htlc program (the SBF build in
//! `solana/target/deploy/impulse_htlc.so`, built by scripts/ci-solana.sh first): open, claim with
//! the secret, and open, refund after the timeout, with exact balance checks. Keys are random
//! throwaway keypairs made in memory (rule 1 exception, docs/ENGINEERING-RULES.md); nothing is written or printed.

use impulse_htlc_demo::{ata, sha256, Htlc};
use litesvm::LiteSVM;
use solana_program::clock::Clock;
use solana_program_pack::Pack;
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    program_option::COption,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

const NOW: i64 = 1_800_000_000;
const AMOUNT: u64 = 100_000;

fn program_id() -> Pubkey {
    Pubkey::try_from(impulse_htlc::ID.as_ref()).unwrap()
}

fn put(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        key,
        Account {
            lamports,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_account(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    put(svm, key, spl_token::id(), data);
}

fn amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(key).unwrap().data[..TokenAccount::LEN])
        .unwrap()
        .amount
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<(), String> {
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?}", e.err))
}

struct World {
    svm: LiteSVM,
    buyer: Keypair,
    seller: Keypair,
    mint: Pubkey,
}

fn world() -> World {
    let mut svm = LiteSVM::new();
    svm.set_sysvar(&Clock {
        slot: 1,
        epoch_start_timestamp: NOW,
        epoch: 0,
        leader_schedule_epoch: 0,
        unix_timestamp: NOW,
    });
    svm.add_program(
        program_id(),
        include_bytes!("../../../target/deploy/impulse_htlc.so"),
    )
    .expect("load impulse_htlc.so");
    let (buyer, seller) = (Keypair::new(), Keypair::new());
    svm.airdrop(&buyer.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&seller.pubkey(), 10_000_000_000).unwrap();
    let mint = Pubkey::new_unique();
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 1_000_000_000,
            decimals: 6,
            is_initialized: true,
            // As the demo's test USDC: a freeze authority is set.
            freeze_authority: COption::Some(Pubkey::new_unique()),
        },
        &mut data,
    )
    .unwrap();
    put(&mut svm, mint, spl_token::id(), data);
    token_account(
        &mut svm,
        ata(&buyer.pubkey(), &mint),
        mint,
        buyer.pubkey(),
        5_000_000,
    );
    token_account(
        &mut svm,
        ata(&seller.pubkey(), &mint),
        mint,
        seller.pubkey(),
        0,
    );
    World {
        svm,
        buyer,
        seller,
        mint,
    }
}

fn htlc(w: &World, secret: &[u8; 32]) -> Htlc {
    Htlc {
        program: program_id(),
        funder: w.buyer.pubkey(),
        mint: w.mint,
        hash: sha256(secret),
    }
}

#[test]
fn open_then_claim_with_the_secret_pays_the_seller_exactly() {
    let mut w = world();
    let secret = [0x5a; 32];
    let h = htlc(&w, &secret);
    let (b, s) = (w.buyer.pubkey(), w.seller.pubkey());
    let buyer_ata = ata(&b, &w.mint);
    let seller_ata = ata(&s, &w.mint);
    let ix = h.open(&buyer_ata, AMOUNT, NOW + 3 * 3600, &s, &b);
    let buyer = Keypair::try_from(&w.buyer.to_bytes()[..]).unwrap();
    send(&mut w.svm, &buyer, ix).unwrap();
    assert_eq!(amount(&w.svm, &h.escrow()), AMOUNT);
    assert_eq!(amount(&w.svm, &buyer_ata), 5_000_000 - AMOUNT);
    // A wrong secret does not claim.
    let seller = Keypair::try_from(&w.seller.to_bytes()[..]).unwrap();
    let bad = send(&mut w.svm, &seller, h.close(&seller_ata, Some(&[1; 32])));
    assert!(bad.is_err());
    assert_eq!(amount(&w.svm, &seller_ata), 0);
    send(&mut w.svm, &seller, h.close(&seller_ata, Some(&secret))).unwrap();
    assert_eq!(amount(&w.svm, &seller_ata), AMOUNT);
    assert!(w
        .svm
        .get_account(&h.address())
        .is_none_or(|a| a.lamports == 0));
}

#[test]
fn open_then_refund_only_after_the_timeout_returns_the_buyers_tokens() {
    let mut w = world();
    let secret = [0x6b; 32];
    let h = htlc(&w, &secret);
    let (b, s) = (w.buyer.pubkey(), w.seller.pubkey());
    let buyer_ata = ata(&b, &w.mint);
    let timeout = NOW + 3600;
    let buyer = Keypair::try_from(&w.buyer.to_bytes()[..]).unwrap();
    send(
        &mut w.svm,
        &buyer,
        h.open(&buyer_ata, AMOUNT, timeout, &s, &b),
    )
    .unwrap();
    assert!(
        send(&mut w.svm, &buyer, h.close(&buyer_ata, None)).is_err(),
        "before the timeout"
    );
    w.svm.set_sysvar(&Clock {
        slot: 2,
        epoch_start_timestamp: NOW,
        epoch: 0,
        leader_schedule_epoch: 0,
        unix_timestamp: timeout,
    });
    send(&mut w.svm, &buyer, h.close(&buyer_ata, None)).unwrap();
    assert_eq!(amount(&w.svm, &buyer_ata), 5_000_000);
}
