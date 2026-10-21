// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! LiteSVM tests of the Impulse HTLC program, run against the SBF build in
//! `solana/target/deploy/impulse_htlc.so` (scripts/ci-solana.sh builds it first).
//!
//! Every failure path has a test. Keys are random throwaway keypairs made in memory at run time
//! (rule 1 exception, docs/ENGINEERING-RULES.md); nothing is written to disk, printed or logged.

use impulse_htlc::{error::HtlcError, ESCROW_SEED, HTLC_SEED, IX_CLAIM, IX_OPEN, IX_REFUND};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_program::clock::Clock;
use solana_program_pack::Pack;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    program_option::COption,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0; 32]);
const NOW: i64 = 1_800_000_000;
const AMOUNT: u64 = 1_250_000; // 1.25 units of a 6-decimal token
const TIMEOUT_IN: i64 = 3_600;
const SECRET: [u8; 32] = [0x5a; 32];

fn program_id() -> Pubkey {
    Pubkey::try_from(impulse_htlc::ID.as_ref()).unwrap()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

struct Ctx {
    svm: LiteSVM,
    token_program: Pubkey,
    funder: Keypair,
    submitter: Keypair,
    mint: Pubkey,
    source: Pubkey,
    recipient: Pubkey,
    refund: Pubkey,
    recipient_ta: Pubkey,
    refund_ta: Pubkey,
    hash: [u8; 32],
    timeout: i64,
}

fn set_mint(svm: &mut LiteSVM, token_program: Pubkey) -> Pubkey {
    set_mint_with_freeze(svm, token_program, COption::None)
}

fn set_mint_with_freeze(
    svm: &mut LiteSVM,
    token_program: Pubkey,
    freeze_authority: COption<Pubkey>,
) -> Pubkey {
    let mint = Pubkey::new_unique();
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 1_000_000_000_000,
            decimals: 6,
            is_initialized: true,
            freeze_authority,
        },
        &mut data,
    )
    .unwrap();
    set_raw(svm, mint, token_program, data);
    mint
}

fn set_raw(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
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

fn set_token_account(
    svm: &mut LiteSVM,
    token_program: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
) -> Pubkey {
    let key = Pubkey::new_unique();
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
    set_raw(svm, key, token_program, data);
    key
}

fn balance(svm: &LiteSVM, key: &Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(key).unwrap().data[..TokenAccount::LEN])
        .unwrap()
        .amount
}

fn gone(svm: &LiteSVM, key: &Pubkey) -> bool {
    svm.get_account(key).is_none_or(|a| a.lamports == 0)
}

impl Ctx {
    fn new(token_program: Pubkey) -> Self {
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
        let funder = Keypair::new();
        let submitter = Keypair::new();
        svm.airdrop(&funder.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&submitter.pubkey(), 10_000_000_000).unwrap();
        let mint = set_mint(&mut svm, token_program);
        let source = set_token_account(&mut svm, token_program, mint, funder.pubkey(), 5_000_000);
        let recipient = Pubkey::new_unique();
        let refund = Pubkey::new_unique();
        let recipient_ta = set_token_account(&mut svm, token_program, mint, recipient, 0);
        let refund_ta = set_token_account(&mut svm, token_program, mint, refund, 0);
        Ctx {
            svm,
            token_program,
            funder,
            submitter,
            mint,
            source,
            recipient,
            refund,
            recipient_ta,
            refund_ta,
            hash: sha256(&SECRET),
            timeout: NOW + TIMEOUT_IN,
        }
    }

    fn htlc(&self) -> Pubkey {
        self.htlc_for(&self.funder.pubkey(), &self.hash)
    }

    fn htlc_for(&self, funder: &Pubkey, hash: &[u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&[HTLC_SEED, funder.as_ref(), hash], &program_id()).0
    }

    fn escrow_of(&self, htlc: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[ESCROW_SEED, htlc.as_ref()], &program_id()).0
    }

    fn open_data(
        &self,
        amount: u64,
        hash: [u8; 32],
        timeout: i64,
        rec: Pubkey,
        refd: Pubkey,
    ) -> Vec<u8> {
        let mut d = vec![IX_OPEN];
        d.extend_from_slice(&amount.to_le_bytes());
        d.extend_from_slice(&hash);
        d.extend_from_slice(&timeout.to_le_bytes());
        d.extend_from_slice(rec.as_ref());
        d.extend_from_slice(refd.as_ref());
        d
    }

    fn open_ix_with(
        &self,
        data: Vec<u8>,
        htlc: Pubkey,
        mint: Pubkey,
        token_program: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(self.funder.pubkey(), true),
                AccountMeta::new(htlc, false),
                AccountMeta::new(self.escrow_of(&htlc), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(self.source, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data,
        }
    }

    fn open_ix(&self) -> Instruction {
        let data = self.open_data(AMOUNT, self.hash, self.timeout, self.recipient, self.refund);
        self.open_ix_with(data, self.htlc(), self.mint, self.token_program)
    }

    fn claim_ix(
        &self,
        preimage: &[u8],
        dest: Pubkey,
        mint: Pubkey,
        extra: Option<Pubkey>,
    ) -> Instruction {
        let htlc = self.htlc();
        let mut accounts = vec![
            AccountMeta::new(htlc, false),
            AccountMeta::new(self.escrow_of(&htlc), false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(self.token_program, false),
            AccountMeta::new(self.funder.pubkey(), false),
        ];
        if let Some(e) = extra {
            accounts.push(AccountMeta::new(e, false));
        }
        let mut data = vec![IX_CLAIM];
        data.extend_from_slice(preimage);
        Instruction {
            program_id: program_id(),
            accounts,
            data,
        }
    }

    fn refund_ix(&self, dest: Pubkey, mint: Pubkey, rent_receiver: Pubkey) -> Instruction {
        let htlc = self.htlc();
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(htlc, false),
                AccountMeta::new(self.escrow_of(&htlc), false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(self.token_program, false),
                AccountMeta::new(rent_receiver, false),
            ],
            data: vec![IX_REFUND],
        }
    }

    /// Sends `ix` paid by the submitter (and signed by the funder when `funder_signs`).
    fn send(&mut self, ix: Instruction, funder_signs: bool) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let bh = self.svm.latest_blockhash();
        let tx = if funder_signs {
            Transaction::new_signed_with_payer(
                &[ix],
                Some(&self.submitter.pubkey()),
                &[&self.submitter, &self.funder],
                bh,
            )
        } else {
            Transaction::new_signed_with_payer(
                &[ix],
                Some(&self.submitter.pubkey()),
                &[&self.submitter],
                bh,
            )
        };
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn open(&mut self) {
        let ix = self.open_ix();
        self.send(ix, true).expect("open");
    }

    fn warp_to(&mut self, t: i64) {
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = t;
        self.svm.set_sysvar(&c);
    }
}

fn assert_code(r: Result<(), TransactionError>, e: HtlcError) {
    assert_eq!(
        r,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(e as u32)
        )),
        "expected {e:?}"
    );
}

fn both<F: Fn(Pubkey)>(f: F) {
    f(spl_token::ID);
    f(spl_token_2022::ID);
}

// ---------------------------------------------------------------- happy paths

#[test]
fn open_locks_exact_amount_and_claim_pays_recipient() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        let funder_lamports = c.svm.get_account(&c.funder.pubkey()).unwrap().lamports;
        c.open();
        let htlc = c.htlc();
        let escrow = c.escrow_of(&htlc);
        assert_eq!(balance(&c.svm, &escrow), AMOUNT);
        assert_eq!(balance(&c.svm, &c.source), 5_000_000 - AMOUNT);

        // Claim one second before the timeout, by a third party holding the preimage.
        c.warp_to(c.timeout - 1);
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        c.send(ix, false).expect("claim");
        assert_eq!(balance(&c.svm, &c.recipient_ta), AMOUNT);
        assert!(gone(&c.svm, &htlc) && gone(&c.svm, &escrow));
        // Rent of both accounts went back to the funder (who paid no fee: the submitter did).
        assert_eq!(
            c.svm.get_account(&c.funder.pubkey()).unwrap().lamports,
            funder_lamports
        );
    });
}

#[test]
fn refund_at_timeout_pays_refund_owner() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        c.warp_to(c.timeout);
        let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        c.send(ix, false).expect("refund");
        assert_eq!(balance(&c.svm, &c.refund_ta), AMOUNT);
        assert!(gone(&c.svm, &c.htlc()));
    });
}

fn donate(c: &mut Ctx, units: u64) {
    let escrow = c.escrow_of(&c.htlc());
    let mut acc = c.svm.get_account(&escrow).unwrap();
    let mut ta = TokenAccount::unpack(&acc.data[..TokenAccount::LEN]).unwrap();
    ta.amount += units;
    TokenAccount::pack(ta, &mut acc.data[..TokenAccount::LEN]).unwrap();
    c.svm.set_account(escrow, acc).unwrap();
}

#[test]
fn donated_excess_goes_to_recipient_with_the_amount() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        // Someone sends 7 extra base units straight to the escrow: a gift, paid on with the leg.
        donate(&mut c, 7);
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        c.send(ix, false).expect("claim");
        assert_eq!(balance(&c.svm, &c.recipient_ta), AMOUNT + 7);
        assert_eq!(balance(&c.svm, &c.refund_ta), 0);
        assert!(gone(&c.svm, &c.htlc()));
    });
}

/// Review round 1 (HIGH): a donation must not make claim depend on any account the funder or a
/// third party controls. Here the refund owner has no token account at all.
#[test]
fn donation_cannot_block_claim_when_refund_owner_has_no_token_account() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        donate(&mut c, 1);
        let refund_ta = c.refund_ta;
        c.svm.set_account(refund_ta, Account::default()).unwrap();
        c.warp_to(c.timeout - 1);
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        c.send(ix, false).expect("claim before the timeout");
        assert_eq!(balance(&c.svm, &c.recipient_ta), AMOUNT + 1);
        assert!(gone(&c.svm, &c.htlc()));
    });
}

#[test]
fn claim_with_an_extra_account_is_refused() {
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, Some(c.refund_ta));
    assert_eq!(
        c.send(ix, false),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::NotEnoughAccountKeys
        ))
    );
}

// ---------------------------------------------------------------- claim failures

#[test]
fn wrong_preimage_is_refused() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        let mut bad = SECRET;
        bad[31] ^= 1;
        let ix = c.claim_ix(&bad, c.recipient_ta, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::PreimageMismatch);
    });
}

#[test]
fn preimage_of_other_length_is_refused() {
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    for len in [0usize, 31, 33, 64] {
        let p = vec![0x5a; len];
        let ix = c.claim_ix(&p, c.recipient_ta, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::PreimageLength);
    }
}

#[test]
fn late_claim_is_refused_at_and_after_timeout() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        for t in [c.timeout, c.timeout + 1, c.timeout + 86_400] {
            c.warp_to(t);
            let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
            assert_code(c.send(ix, false), HtlcError::ClaimExpired);
        }
    });
}

#[test]
fn wrong_mint_is_refused() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        let other_mint = set_mint(&mut c.svm, tp);
        let other_ta = set_token_account(&mut c.svm, tp, other_mint, c.recipient, 0);
        let ix = c.claim_ix(&SECRET, other_ta, other_mint, None);
        assert_code(c.send(ix, false), HtlcError::MintMismatch);
        // The right mint account but a destination of another mint.
        let ix = c.claim_ix(&SECRET, other_ta, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::MintMismatch);
        // Refund side.
        c.warp_to(c.timeout);
        let other_refund_ta = set_token_account(&mut c.svm, tp, other_mint, c.refund, 0);
        let ix = c.refund_ix(other_refund_ta, c.mint, c.funder.pubkey());
        assert_code(c.send(ix, false), HtlcError::MintMismatch);
        let ix = c.refund_ix(other_refund_ta, other_mint, c.funder.pubkey());
        assert_code(c.send(ix, false), HtlcError::MintMismatch);
    });
}

#[test]
fn wrong_recipient_is_refused() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        let thief_ta = set_token_account(&mut c.svm, tp, c.mint, c.submitter.pubkey(), 0);
        let ix = c.claim_ix(&SECRET, thief_ta, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::RecipientMismatch);
        // The refund owner's account is not the recipient's either.
        let ix = c.claim_ix(&SECRET, c.refund_ta, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::RecipientMismatch);
        // An account not owned by the token program.
        let fake = Pubkey::new_unique();
        let mut data = vec![0u8; TokenAccount::LEN];
        data[..32].copy_from_slice(c.mint.as_ref());
        data[32..64].copy_from_slice(c.recipient.as_ref());
        set_raw(&mut c.svm, fake, SYSTEM_PROGRAM, data);
        let ix = c.claim_ix(&SECRET, fake, c.mint, None);
        assert_code(c.send(ix, false), HtlcError::RecipientMismatch);
    });
}

#[test]
fn double_claim_is_refused() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        c.send(ix.clone(), false).expect("first claim");
        assert_code(c.send(ix, false), HtlcError::NotHtlc);
        let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        c.warp_to(c.timeout);
        assert_code(c.send(ix, false), HtlcError::NotHtlc);
        assert_eq!(balance(&c.svm, &c.recipient_ta), AMOUNT);
        assert_eq!(balance(&c.svm, &c.refund_ta), 0);
    });
}

// ---------------------------------------------------------------- refund failures

#[test]
fn early_refund_is_refused() {
    both(|tp| {
        let mut c = Ctx::new(tp);
        c.open();
        for t in [NOW, c.timeout - 1] {
            c.warp_to(t);
            let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
            assert_code(c.send(ix, false), HtlcError::RefundTooEarly);
        }
    });
}

#[test]
fn refund_to_wrong_owner_or_rent_receiver_is_refused() {
    let tp = spl_token::ID;
    let mut c = Ctx::new(tp);
    c.open();
    c.warp_to(c.timeout);
    let ix = c.refund_ix(c.recipient_ta, c.mint, c.funder.pubkey());
    assert_code(c.send(ix, false), HtlcError::RefundAccountMismatch);
    let ix = c.refund_ix(c.refund_ta, c.mint, c.submitter.pubkey());
    assert_code(c.send(ix, false), HtlcError::RentReceiverMismatch);
}

#[test]
fn refund_after_refund_is_refused() {
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    c.warp_to(c.timeout);
    let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
    c.send(ix.clone(), false).expect("refund");
    assert_code(c.send(ix, false), HtlcError::NotHtlc);
    c.warp_to(c.timeout - 10);
    let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
    assert_code(c.send(ix, false), HtlcError::NotHtlc);
}

#[test]
fn claim_with_other_token_program_or_escrow_is_refused() {
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    let mut ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
    ix.accounts[4] = AccountMeta::new_readonly(spl_token_2022::ID, false);
    assert_code(c.send(ix, false), HtlcError::TokenProgramMismatch);
    let mut ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
    ix.accounts[1] = AccountMeta::new(c.source, false);
    assert_code(c.send(ix, false), HtlcError::EscrowAddressMismatch);
    let mut ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
    ix.accounts[0] = AccountMeta::new(c.source, false);
    assert_code(c.send(ix, false), HtlcError::NotHtlc);
}

// ---------------------------------------------------------------- open failures

#[test]
fn open_refuses_malformed_terms() {
    let mut c = Ctx::new(spl_token::ID);
    let (h, r, f) = (c.hash, c.recipient, c.refund);
    let t = c.timeout;
    let cases: Vec<(Vec<u8>, HtlcError)> = vec![
        (c.open_data(0, h, t, r, f), HtlcError::AmountZero),
        (c.open_data(AMOUNT, [0; 32], t, r, f), HtlcError::HashZero),
        (
            c.open_data(AMOUNT, h, t, Pubkey::default(), f),
            HtlcError::PartyZero,
        ),
        (
            c.open_data(AMOUNT, h, t, r, Pubkey::default()),
            HtlcError::PartyZero,
        ),
        (
            c.open_data(AMOUNT, h, t, r, r),
            HtlcError::PartiesNotDistinct,
        ),
        (
            c.open_data(AMOUNT, h, NOW, r, f),
            HtlcError::TimeoutNotInFuture,
        ),
        (
            c.open_data(AMOUNT, h, NOW - 1, r, f),
            HtlcError::TimeoutNotInFuture,
        ),
        (
            c.open_data(
                AMOUNT,
                h,
                NOW + impulse_htlc::MAX_HTLC_DURATION_SECS + 1,
                r,
                f,
            ),
            HtlcError::TimeoutTooFar,
        ),
    ];
    for (data, e) in cases {
        let htlc = if data[9..41] == [0u8; 32] {
            c.htlc_for(&c.funder.pubkey(), &[0; 32])
        } else {
            c.htlc()
        };
        let ix = c.open_ix_with(data, htlc, c.mint, c.token_program);
        assert_code(c.send(ix, true), e);
    }
    // The longest allowed lifetime opens.
    let data = c.open_data(AMOUNT, h, NOW + impulse_htlc::MAX_HTLC_DURATION_SECS, r, f);
    let ix = c.open_ix_with(data, c.htlc(), c.mint, c.token_program);
    c.send(ix, true).expect("open at max duration");
}

#[test]
fn open_refuses_bad_accounts() {
    let mut c = Ctx::new(spl_token::ID);
    let data = c.open_data(AMOUNT, c.hash, c.timeout, c.recipient, c.refund);
    // Unsupported token program.
    let ix = c.open_ix_with(data.clone(), c.htlc(), c.mint, SYSTEM_PROGRAM);
    assert_code(c.send(ix, true), HtlcError::UnsupportedTokenProgram);
    // Mint owned by the other token program.
    let ix = c.open_ix_with(data.clone(), c.htlc(), c.mint, spl_token_2022::ID);
    assert_code(c.send(ix, true), HtlcError::MintNotSupported);
    // HTLC address not the PDA of (funder, hash).
    let wrong = c.htlc_for(&c.submitter.pubkey(), &c.hash);
    let ix = c.open_ix_with(data.clone(), wrong, c.mint, c.token_program);
    assert_code(c.send(ix, true), HtlcError::HtlcAddressMismatch);
    // Escrow not the PDA of the htlc.
    let mut ix = c.open_ix_with(data.clone(), c.htlc(), c.mint, c.token_program);
    ix.accounts[2] = AccountMeta::new(Pubkey::new_unique(), false);
    assert_code(c.send(ix, true), HtlcError::EscrowAddressMismatch);
    // Funder not a signer.
    let mut ix = c.open_ix_with(data.clone(), c.htlc(), c.mint, c.token_program);
    ix.accounts[0] = AccountMeta::new(c.funder.pubkey(), false);
    assert_code(c.send(ix, false), HtlcError::MissingSigner);
    // Truncated data.
    let mut short = data.clone();
    short.pop();
    let ix = c.open_ix_with(short, c.htlc(), c.mint, c.token_program);
    assert_eq!(
        c.send(ix, true),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::InvalidInstructionData
        ))
    );
}

#[test]
fn open_refuses_token_2022_mint_with_extensions() {
    let mut c = Ctx::new(spl_token_2022::ID);
    // A Token-2022 mint padded to carry an extension area is refused before any transfer.
    let mut acc = c.svm.get_account(&c.mint).unwrap();
    acc.data.resize(Mint::LEN + 84, 0);
    acc.data[165] = 1; // AccountType::Mint
    c.svm.set_account(c.mint, acc).unwrap();
    let ix = c.open_ix();
    assert_code(c.send(ix, true), HtlcError::MintNotSupported);
}

// ------------------------------------------- mints with a freeze authority (D47)

/// A context whose mint has `issuer` as its freeze authority. Owner decision D47: `open` accepts
/// such a mint; the issuer is a documented trusted party.
fn ctx_with_freeze_authority(tp: Pubkey, issuer: &Pubkey) -> Ctx {
    let mut c = Ctx::new(tp);
    let m = set_mint_with_freeze(&mut c.svm, tp, COption::Some(*issuer));
    let acc = c.svm.get_account(&m).unwrap();
    c.svm.set_account(c.mint, acc).unwrap();
    c
}

/// The issuer's FreezeAccount (or ThawAccount when `thaw`) on the HTLC escrow.
fn freeze_escrow_ix(c: &Ctx, issuer: &Pubkey, thaw: bool) -> Instruction {
    let escrow = c.escrow_of(&c.htlc());
    let tp = c.token_program;
    if tp == spl_token::ID {
        let f = if thaw {
            spl_token::instruction::thaw_account
        } else {
            spl_token::instruction::freeze_account
        };
        f(&tp, &escrow, &c.mint, issuer, &[]).unwrap()
    } else {
        let f = if thaw {
            spl_token_2022::instruction::thaw_account
        } else {
            spl_token_2022::instruction::freeze_account
        };
        f(&tp, &escrow, &c.mint, issuer, &[]).unwrap()
    }
}

/// Sends `ix` paid by the submitter and signed by `signer`.
fn send_signed(c: &mut Ctx, ix: Instruction, signer: &Keypair) {
    c.svm.expire_blockhash();
    let bh = c.svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&c.submitter.pubkey()),
        &[&c.submitter, signer],
        bh,
    );
    c.svm.send_transaction(tx).expect("issuer instruction");
}

/// Sends `ix` paid by the submitter and asserts that the token program refused it because the
/// escrow is frozen (TokenError::AccountFrozen, raised inside the HTLC's transfer CPI).
fn assert_refused_frozen(c: &mut Ctx, ix: Instruction) {
    c.svm.expire_blockhash();
    let bh = c.svm.latest_blockhash();
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&c.submitter.pubkey()), &[&c.submitter], bh);
    let e = c
        .svm
        .send_transaction(tx)
        .expect_err("frozen escrow must refuse");
    assert_eq!(
        e.err,
        TransactionError::InstructionError(
            0,
            InstructionError::Custom(spl_token::error::TokenError::AccountFrozen as u32)
        )
    );
    assert!(
        e.meta.logs.iter().any(|l| l.contains("Account is frozen")),
        "the token program, not the HTLC, refused: {:?}",
        e.meta.logs
    );
}

#[test]
fn freeze_authority_mint_opens_and_claims() {
    both(|tp| {
        let issuer = Pubkey::new_unique();
        let mut c = ctx_with_freeze_authority(tp, &issuer);
        c.open();
        let htlc = c.htlc();
        let escrow = c.escrow_of(&htlc);
        assert_eq!(balance(&c.svm, &escrow), AMOUNT);
        c.warp_to(c.timeout - 1);
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        c.send(ix, false).expect("claim");
        assert_eq!(balance(&c.svm, &c.recipient_ta), AMOUNT);
        assert!(gone(&c.svm, &htlc) && gone(&c.svm, &escrow));
    });
}

#[test]
fn freeze_authority_mint_opens_and_refunds() {
    both(|tp| {
        let issuer = Pubkey::new_unique();
        let mut c = ctx_with_freeze_authority(tp, &issuer);
        c.open();
        c.warp_to(c.timeout);
        let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        c.send(ix, false).expect("refund");
        assert_eq!(balance(&c.svm, &c.refund_ta), AMOUNT);
        assert!(gone(&c.svm, &c.htlc()));
    });
}

/// The trust D47 documents: the freeze authority can freeze the escrow so that neither claim
/// (before the timeout) nor refund (at or after it) moves it. Only the authority can release it.
#[test]
fn frozen_escrow_blocks_claim_and_refund() {
    both(|tp| {
        let issuer = Keypair::new();
        let mut c = ctx_with_freeze_authority(tp, &issuer.pubkey());
        c.open();
        let htlc = c.htlc();
        let escrow = c.escrow_of(&htlc);
        let ix = freeze_escrow_ix(&c, &issuer.pubkey(), false);
        send_signed(&mut c, ix, &issuer);

        c.warp_to(c.timeout - 1);
        let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
        assert_refused_frozen(&mut c, ix);
        c.warp_to(c.timeout);
        let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        assert_refused_frozen(&mut c, ix);
        // Nothing moved and the HTLC is still live.
        assert_eq!(balance(&c.svm, &escrow), AMOUNT);
        assert_eq!(balance(&c.svm, &c.recipient_ta), 0);
        assert_eq!(balance(&c.svm, &c.refund_ta), 0);
        assert!(!gone(&c.svm, &htlc));

        // After the authority thaws it, the refund (now past the timeout) pays as usual.
        let ix = freeze_escrow_ix(&c, &issuer.pubkey(), true);
        send_signed(&mut c, ix, &issuer);
        let ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        c.send(ix, false).expect("refund after thaw");
        assert_eq!(balance(&c.svm, &c.refund_ta), AMOUNT);
        assert!(gone(&c.svm, &htlc) && gone(&c.svm, &escrow));
    });
}

#[test]
fn open_refuses_reuse_of_a_live_hash() {
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    let ix = c.open_ix();
    assert_code(c.send(ix, true), HtlcError::AccountNotEmpty);
}

#[test]
fn open_survives_prefunded_pdas() {
    let mut c = Ctx::new(spl_token::ID);
    let htlc = c.htlc();
    let escrow = c.escrow_of(&htlc);
    for k in [htlc, escrow] {
        c.svm
            .set_account(
                k,
                Account {
                    lamports: 1_000,
                    data: vec![],
                    owner: SYSTEM_PROGRAM,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
    c.open();
    assert_eq!(balance(&c.svm, &escrow), AMOUNT);
}

#[test]
fn unknown_instruction_is_refused() {
    let mut c = Ctx::new(spl_token::ID);
    for data in [vec![], vec![3u8], vec![IX_REFUND, 0]] {
        let mut ix = c.refund_ix(c.refund_ta, c.mint, c.funder.pubkey());
        ix.data = data;
        let r = c.send(ix, false);
        assert!(r.is_err());
    }
}

#[test]
fn short_escrow_is_refused() {
    // Unreachable through the token program (only the HTLC PDA can move escrow tokens); the state
    // is forced here to show the check holds.
    let mut c = Ctx::new(spl_token::ID);
    c.open();
    let escrow = c.escrow_of(&c.htlc());
    let mut acc = c.svm.get_account(&escrow).unwrap();
    let mut ta = TokenAccount::unpack(&acc.data[..TokenAccount::LEN]).unwrap();
    ta.amount -= 1;
    TokenAccount::pack(ta, &mut acc.data[..TokenAccount::LEN]).unwrap();
    c.svm.set_account(escrow, acc).unwrap();
    let ix = c.claim_ix(&SECRET, c.recipient_ta, c.mint, None);
    assert_code(c.send(ix, false), HtlcError::EscrowShort);
}
