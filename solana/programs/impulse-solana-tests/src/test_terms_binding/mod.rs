// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Impulse (I19): the SwapDvp address binds the impulse-core v1 terms hash.
//!
//! The term sheets in solana/tests/fixtures/term-sheets.json name Impulse terms in
//! tests/vectors/terms/ and hold the Solana escrow parameters. Their terms hashes are the golden
//! hashes; solana/ts checks them against the impulse-wasm SDK. Here: the pinned PDAs, a full
//! create, fund and settle under a term-sheet hash, and the refusals for a wrong or zero hash.
//! Every keypair is generated at runtime by the test (rule 1 exception, docs/ENGINEERING-RULES.md).
use impulse_solana_client::{
    accounts::SwapDvp,
    instructions::{CreateDvpBuilder, RecoverDvpBuilder, SettleDvpBuilder},
    verify::{find_swap_dvp_address, find_swap_dvp_escrow_ata},
    ImpulseSolanaError,
};
use serde_json::Value;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::str::FromStr;

use crate::{
    state_utils::{
        assert_create_dvp, assert_fund_a, assert_fund_b, assert_settle_dvp, setup_dvp, DvpFixture,
        AMOUNT_A, AMOUNT_B, INITIAL_BALANCE,
    },
    utils::{
        assert_instruction_error, assert_program_error, get_token_balance, nonce_tombstone_pda,
        swap_dvp_pda_for_terms, TestContext, MEMO_PROGRAM_ID, SWAP_PROGRAM_ID,
    },
};

const TERM_SHEETS: &str = include_str!("../../../../tests/fixtures/term-sheets.json");

const ZERO_TERMS_HASH: u32 = ImpulseSolanaError::ZeroTermsHash as u32;
const TERMS_HASH_MISMATCH: u32 = ImpulseSolanaError::TermsHashMismatch as u32;

fn sheets() -> Vec<Value> {
    let doc: Value = serde_json::from_str(TERM_SHEETS).expect("term-sheets.json parses");
    doc["term_sheets"].as_array().expect("term_sheets").clone()
}

fn hash32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "terms hash is 32 bytes of lowercase hex");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn key(v: &Value) -> Pubkey {
    Pubkey::from_str(v.as_str().expect("base58 string")).expect("base58 pubkey")
}

/// The terms hash of each term sheet: the external-cash sheet and the two-vault sheet.
fn sheet_hashes() -> ([u8; 32], [u8; 32]) {
    let s = sheets();
    (
        hash32(s[0]["expected"]["terms_hash"].as_str().unwrap()),
        hash32(s[1]["expected"]["terms_hash"].as_str().unwrap()),
    )
}

fn settle_ix(fixture: &DvpFixture, terms_hash: [u8; 32], swap_dvp: Pubkey) -> Instruction {
    SettleDvpBuilder::new()
        .terms_hash(terms_hash)
        .settlement_authority(fixture.settlement_authority.pubkey())
        .swap_dvp(swap_dvp)
        .mint_a(fixture.mint_a)
        .mint_b(fixture.mint_b)
        .dvp_ata_a(fixture.dvp_ata_a)
        .dvp_ata_b(fixture.dvp_ata_b)
        .user_a_destination_ata_b(fixture.user_a_ata_b)
        .user_b_destination_ata_a(fixture.user_b_ata_a)
        .user_a_ata_a(fixture.user_a_ata_a)
        .user_b_ata_b(fixture.user_b_ata_b)
        .token_program_a(fixture.token_program_a)
        .token_program_b(fixture.token_program_b)
        .memo_program(MEMO_PROGRAM_ID)
        .leg_a_extras_count(0)
        .instruction()
}

/// CreateDvp for `fixture`'s accounts (its swap_dvp, tombstone and escrows) but naming
/// `terms_hash` as the argument.
fn create_ix(context: &TestContext, fixture: &DvpFixture, terms_hash: [u8; 32]) -> Instruction {
    CreateDvpBuilder::new()
        .terms_hash(terms_hash)
        .payer(context.payer.pubkey())
        .swap_dvp(fixture.swap_dvp)
        .nonce_tombstone(fixture.nonce_tombstone)
        .mint_a(fixture.mint_a)
        .mint_b(fixture.mint_b)
        .dvp_ata_a(fixture.dvp_ata_a)
        .dvp_ata_b(fixture.dvp_ata_b)
        .token_program_a(fixture.token_program_a)
        .token_program_b(fixture.token_program_b)
        .user_a(fixture.user_a.pubkey())
        .user_b(fixture.user_b.pubkey())
        .settlement_authority(fixture.settlement_authority.pubkey())
        .amount_a(AMOUNT_A)
        .amount_b(AMOUNT_B)
        .expiry_timestamp(fixture.expiry)
        .nonce(fixture.nonce)
        .instruction()
}

fn stored(context: &TestContext, swap_dvp: &Pubkey) -> SwapDvp {
    let account = context.get_account(swap_dvp).expect("SwapDvp exists");
    SwapDvp::try_from_bytes(&account.data).expect("canonical SwapDvp")
}

/// The pinned PDAs of every term sheet, derived here with solana-pubkey and in solana/ts with
/// @solana/kit. The term sheet's program ID is this program's.
#[test]
fn term_sheet_pdas_match_the_fixture() {
    for sheet in sheets() {
        let name = sheet["name"].as_str().unwrap();
        let sol = &sheet["solana"];
        let want = &sheet["expected"]["solana"];
        assert_eq!(
            key(&sol["program_id"]),
            SWAP_PROGRAM_ID,
            "{name}: program id"
        );
        let terms_hash = hash32(sheet["expected"]["terms_hash"].as_str().unwrap());
        let nonce: u64 = sol["nonce"].as_str().unwrap().parse().unwrap();
        let (swap_dvp, bump) = swap_dvp_pda_for_terms(
            &key(&sol["settlement_authority"]),
            &key(&sol["user_a"]),
            &key(&sol["user_b"]),
            &key(&sol["mint_a"]),
            &key(&sol["mint_b"]),
            &terms_hash,
            nonce,
        );
        let tombstone = nonce_tombstone_pda(&swap_dvp).0;
        let ata_a = find_swap_dvp_escrow_ata(
            &swap_dvp,
            &key(&sol["mint_a"]),
            &key(&sol["token_program_a"]),
        );
        let ata_b = find_swap_dvp_escrow_ata(
            &swap_dvp,
            &key(&sol["mint_b"]),
            &key(&sol["token_program_b"]),
        );
        let computed = format!(
            "{name}: swap_dvp {swap_dvp} bump {bump} nonce_tombstone {tombstone} dvp_ata_a {ata_a} dvp_ata_b {ata_b}"
        );
        assert_eq!(
            want["swap_dvp"].as_str().unwrap(),
            swap_dvp.to_string(),
            "{computed}"
        );
        assert_eq!(want["bump"].as_u64().unwrap(), bump as u64, "{computed}");
        assert_eq!(
            want["nonce_tombstone"].as_str().unwrap(),
            tombstone.to_string(),
            "{computed}"
        );
        assert_eq!(
            want["dvp_ata_a"].as_str().unwrap(),
            ata_a.to_string(),
            "{computed}"
        );
        assert_eq!(
            want["dvp_ata_b"].as_str().unwrap(),
            ata_b.to_string(),
            "{computed}"
        );

        // The client's verify-before-fund derivation agrees.
        let (client, client_bump) = find_swap_dvp_address(
            &key(&sol["settlement_authority"]),
            &key(&sol["user_a"]),
            &key(&sol["user_b"]),
            &key(&sol["mint_a"]),
            &key(&sol["mint_b"]),
            &terms_hash,
            nonce,
        );
        assert_eq!(client.to_string(), swap_dvp.to_string(), "{name}: client");
        assert_eq!(client_bump, bump, "{name}: client bump");
    }
}

/// Different term sheets with identical Solana parameters give different escrow addresses,
/// so a SwapDvp address names exactly one terms hash.
#[test]
fn each_terms_hash_has_its_own_address() {
    let (h1, h2) = sheet_hashes();
    let mut context = TestContext::new();
    let base = setup_dvp(&mut context, 7);
    let upstream_style = base.swap_dvp;
    let a = base.with_terms_hash(h1);
    let (b, _) = swap_dvp_pda_for_terms(
        &a.settlement_authority.pubkey(),
        &a.user_a.pubkey(),
        &a.user_b.pubkey(),
        &a.mint_a,
        &a.mint_b,
        &h2,
        a.nonce,
    );
    assert_ne!(a.swap_dvp, b);
    assert_ne!(a.swap_dvp, upstream_style);
}

/// Create, fund and settle an escrow bound to a term-sheet terms hash; the stored hash is the
/// term sheet's.
#[test]
fn settles_under_a_term_sheet_hash() {
    let (h1, _) = sheet_hashes();
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash(h1);
    assert_create_dvp(&mut context, &fixture);
    assert_eq!(stored(&context, &fixture.swap_dvp).terms_hash, h1);
    assert_fund_a(&mut context, &fixture);
    assert_fund_b(&mut context, &fixture);
    assert_settle_dvp(&mut context, &fixture);
    assert_eq!(get_token_balance(&context, &fixture.user_b_ata_a), AMOUNT_A);
    assert_eq!(get_token_balance(&context, &fixture.user_a_ata_b), AMOUNT_B);
    assert!(context
        .get_account(&fixture.swap_dvp)
        .is_none_or(|a| a.lamports == 0));
}

/// Open: CreateDvp naming one terms hash cannot create the address of another.
#[test]
fn create_refuses_the_address_of_other_terms() {
    let (h1, h2) = sheet_hashes();
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash(h1);
    let ix = create_ix(&context, &fixture, h2);
    assert_instruction_error(context.send(ix, &[]), "InvalidSeeds");
    assert!(context
        .get_account(&fixture.swap_dvp)
        .is_none_or(|a| a.lamports == 0));
    // The same accounts with the matching hash open.
    let ix = create_ix(&context, &fixture, h1);
    context
        .send(ix, &[])
        .expect("CreateDvp with the matching terms hash");
}

/// Open: an all-zero terms hash is refused even at its own address.
#[test]
fn create_refuses_a_zero_terms_hash() {
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash([0u8; 32]);
    let ix = create_ix(&context, &fixture, [0u8; 32]);
    assert_program_error(context.send(ix, &[]), ZERO_TERMS_HASH);
}

/// Settle: the authority must name the terms hash the escrow was created with. A wrong hash
/// is refused and moves nothing; the right one then settles.
#[test]
fn settle_refuses_a_wrong_terms_hash() {
    let (h1, h2) = sheet_hashes();
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash(h1);
    assert_create_dvp(&mut context, &fixture);
    assert_fund_a(&mut context, &fixture);
    assert_fund_b(&mut context, &fixture);

    for wrong in [h2, [0u8; 32], {
        let mut flipped = h1;
        flipped[31] ^= 1;
        flipped
    }] {
        let ix = settle_ix(&fixture, wrong, fixture.swap_dvp);
        assert_program_error(
            context.send(ix, &[&fixture.settlement_authority]),
            TERMS_HASH_MISMATCH,
        );
    }
    assert_eq!(get_token_balance(&context, &fixture.dvp_ata_a), AMOUNT_A);
    assert_eq!(get_token_balance(&context, &fixture.dvp_ata_b), AMOUNT_B);
    assert_eq!(get_token_balance(&context, &fixture.user_b_ata_a), 0);
    assert_eq!(
        get_token_balance(&context, &fixture.user_a_ata_a),
        INITIAL_BALANCE - AMOUNT_A
    );

    let ix = settle_ix(&fixture, h1, fixture.swap_dvp);
    context
        .send(ix, &[&fixture.settlement_authority])
        .expect("SettleDvp with the matching terms hash");
    assert_eq!(get_token_balance(&context, &fixture.user_b_ata_a), AMOUNT_A);
}

/// Settle: a client that derives the escrow from the wrong term sheet reaches an address
/// with no SwapDvp, and nothing settles.
#[test]
fn settle_at_the_address_of_other_terms_fails() {
    let (h1, h2) = sheet_hashes();
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash(h1);
    assert_create_dvp(&mut context, &fixture);
    assert_fund_a(&mut context, &fixture);
    assert_fund_b(&mut context, &fixture);
    let (other, _) = swap_dvp_pda_for_terms(
        &fixture.settlement_authority.pubkey(),
        &fixture.user_a.pubkey(),
        &fixture.user_b.pubkey(),
        &fixture.mint_a,
        &fixture.mint_b,
        &h2,
        fixture.nonce,
    );
    let ix = settle_ix(&fixture, h2, other);
    assert_instruction_error(
        context.send(ix, &[&fixture.settlement_authority]),
        "InvalidAccountOwner",
    );
    assert_eq!(get_token_balance(&context, &fixture.dvp_ata_a), AMOUNT_A);
    assert_eq!(get_token_balance(&context, &fixture.dvp_ata_b), AMOUNT_B);
}

/// Recover re-derives the PDA from its seed arguments, the terms hash among them: a wrong
/// hash is InvalidSeeds; the right one reaches the next check (the DvP is still open).
#[test]
fn recover_refuses_a_wrong_terms_hash() {
    let (h1, h2) = sheet_hashes();
    let mut context = TestContext::new();
    let fixture = setup_dvp(&mut context, 7).with_terms_hash(h1);
    assert_create_dvp(&mut context, &fixture);
    let recover = |terms_hash: [u8; 32], signer: &Keypair| {
        RecoverDvpBuilder::new()
            .terms_hash(terms_hash)
            .signer(signer.pubkey())
            .swap_dvp(fixture.swap_dvp)
            .nonce_tombstone(fixture.nonce_tombstone)
            .mint(fixture.mint_a)
            .dvp_escrow_ata(fixture.dvp_ata_a)
            .signer_dest_ata(fixture.user_a_ata_a)
            .token_program(fixture.token_program_a)
            .memo_program(MEMO_PROGRAM_ID)
            .settlement_authority(fixture.settlement_authority.pubkey())
            .user_a(fixture.user_a.pubkey())
            .user_b(fixture.user_b.pubkey())
            .mint_a(fixture.mint_a)
            .mint_b(fixture.mint_b)
            .nonce(fixture.nonce)
            .instruction()
    };
    let ix = recover(h2, &fixture.user_a);
    assert_instruction_error(context.send(ix, &[&fixture.user_a]), "InvalidSeeds");
    let ix = recover(h1, &fixture.user_a);
    assert_program_error(
        context.send(ix, &[&fixture.user_a]),
        ImpulseSolanaError::DvpStillOpen as u32,
    );
}
