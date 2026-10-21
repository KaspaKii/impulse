// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! open, claim and refund. Every check fails closed with a code from `error.rs`.

use pinocchio::{
    account::AccountView,
    address::Address,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use pinocchio_token_2022::instructions::{CloseAccount, InitializeAccount3, TransferChecked};

use crate::{
    error::HtlcError,
    state::{Htlc, HTLC_LEN},
    ESCROW_SEED, HTLC_SEED, MAX_HTLC_DURATION_SECS, PREIMAGE_LEN,
};

/// SPL Token and Token-2022, the only token programs accepted.
const SPL_TOKEN_ID: Address =
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022_ID: Address = pinocchio_token_2022::ID;
const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0; 32]);

/// Base mint length. A Token-2022 mint of any other length carries extensions and is refused
/// (a transfer fee would break the exact amount, a hook or a permanent delegate the escrow).
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

fn require(cond: bool, e: HtlcError) -> ProgramResult {
    if cond {
        Ok(())
    } else {
        Err(e.into())
    }
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

fn supported_token_program(id: &Address) -> bool {
    *id == SPL_TOKEN_ID || *id == TOKEN_2022_ID
}

/// Decimals of an extension-free, initialised mint owned by `token_program`. A mint with a freeze
/// authority is accepted (owner decision D47): its issuer is a documented trusted party that can
/// freeze the escrow so that neither claim nor refund moves it (docs/xchain/SOLANA-HTLC.md).
fn mint_decimals(mint: &AccountView, token_program: &Address) -> Result<u8, ProgramError> {
    require(mint.owned_by(token_program), HtlcError::MintNotSupported)?;
    let d = mint.try_borrow()?;
    require(
        d.len() == MINT_LEN && d[45] == 1,
        HtlcError::MintNotSupported,
    )?;
    Ok(d[44])
}

/// The (mint, owner, amount) of a token account owned by `token_program`.
fn token_account(
    acc: &AccountView,
    token_program: &Address,
    e: HtlcError,
) -> Result<(Address, Address, u64), ProgramError> {
    require(acc.owned_by(token_program), e)?;
    let d = acc.try_borrow()?;
    let ok_len = if *token_program == SPL_TOKEN_ID {
        d.len() == TOKEN_ACCOUNT_LEN
    } else {
        d.len() >= TOKEN_ACCOUNT_LEN
    };
    require(ok_len, e)?;
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&d[0..32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&d[32..64]);
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&d[64..72]);
    Ok((
        Address::new_from_array(mint),
        Address::new_from_array(owner),
        u64::from_le_bytes(amount),
    ))
}

/// Creates a PDA account, also when someone pre-funded its address with lamports.
fn create_pda(
    payer: &AccountView,
    account: &AccountView,
    space: usize,
    owner: &Address,
    seeds: &[Seed],
) -> ProgramResult {
    require(account.is_data_empty(), HtlcError::AccountNotEmpty)?;
    require(
        account.owned_by(&SYSTEM_PROGRAM_ID),
        HtlcError::AccountNotEmpty,
    )?;
    let signer = [Signer::from(seeds)];
    let needed = Rent::get()?.try_minimum_balance(space)?;
    let have = account.lamports();
    if have == 0 {
        return CreateAccount {
            from: payer,
            to: account,
            lamports: needed,
            space: space as u64,
            owner,
        }
        .invoke_signed(&signer);
    }
    if needed > have {
        Transfer {
            from: payer,
            to: account,
            lamports: needed - have,
        }
        .invoke()?;
    }
    Allocate {
        account,
        space: space as u64,
    }
    .invoke_signed(&signer)?;
    Assign { account, owner }.invoke_signed(&signer)
}

/// Moves all lamports of a program-owned account to `to` and closes it.
fn close_program_account(acc: &AccountView, to: &AccountView) -> ProgramResult {
    let total = to
        .lamports()
        .checked_add(acc.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    to.set_lamports(total);
    acc.set_lamports(0);
    acc.close()
}

/// Open data: amount u64, hash_lock 32, timeout i64, recipient 32, refund 32 (112 bytes).
pub const OPEN_DATA_LEN: usize = 112;

/// open: locks exactly `amount` of `mint` from the funder.
///
/// Accounts:
/// 0. `[signer, writable]` funder: pays rent, authority of the source token account
/// 1. `[writable]` htlc: PDA `["htlc", funder, hash_lock]`
/// 2. `[writable]` escrow: PDA `["escrow", htlc]`, created here as a token account owned by htlc
/// 3. `[]` mint
/// 4. `[writable]` source token account
/// 5. `[]` token program (SPL Token or Token-2022)
/// 6. `[]` system program
pub fn open(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [funder, htlc, escrow, mint, source, token_program, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != OPEN_DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut hash_lock = [0u8; 32];
    hash_lock.copy_from_slice(&data[8..40]);
    let timeout = i64::from_le_bytes(data[40..48].try_into().unwrap());
    let recipient = Address::new_from_array(data[48..80].try_into().unwrap());
    let refund = Address::new_from_array(data[80..112].try_into().unwrap());

    require(funder.is_signer(), HtlcError::MissingSigner)?;
    require(amount > 0, HtlcError::AmountZero)?;
    require(!is_zero(&hash_lock), HtlcError::HashZero)?;
    require(
        !is_zero(recipient.as_ref()) && !is_zero(refund.as_ref()),
        HtlcError::PartyZero,
    )?;
    require(recipient != refund, HtlcError::PartiesNotDistinct)?;
    let now = now()?;
    require(timeout > now, HtlcError::TimeoutNotInFuture)?;
    require(
        timeout - now <= MAX_HTLC_DURATION_SECS,
        HtlcError::TimeoutTooFar,
    )?;
    require(
        supported_token_program(token_program.address()),
        HtlcError::UnsupportedTokenProgram,
    )?;
    if *system_program.address() != SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let decimals = mint_decimals(mint, token_program.address())?;

    let (htlc_addr, bump) = Address::find_program_address(
        &[HTLC_SEED, funder.address().as_ref(), &hash_lock],
        program_id,
    );
    require(*htlc.address() == htlc_addr, HtlcError::HtlcAddressMismatch)?;
    let (escrow_addr, escrow_bump) =
        Address::find_program_address(&[ESCROW_SEED, htlc_addr.as_ref()], program_id);
    require(
        *escrow.address() == escrow_addr,
        HtlcError::EscrowAddressMismatch,
    )?;

    let bump_b = [bump];
    let htlc_seeds = [
        Seed::from(HTLC_SEED),
        Seed::from(funder.address().as_ref()),
        Seed::from(&hash_lock[..]),
        Seed::from(&bump_b[..]),
    ];
    create_pda(funder, htlc, HTLC_LEN, program_id, &htlc_seeds)?;
    let escrow_bump_b = [escrow_bump];
    let escrow_seeds = [
        Seed::from(ESCROW_SEED),
        Seed::from(htlc_addr.as_ref()),
        Seed::from(&escrow_bump_b[..]),
    ];
    create_pda(
        funder,
        escrow,
        TOKEN_ACCOUNT_LEN,
        token_program.address(),
        &escrow_seeds,
    )?;
    InitializeAccount3 {
        account: escrow,
        mint,
        owner: &htlc_addr,
        token_program: token_program.address(),
    }
    .invoke()?;

    TransferChecked {
        from: source,
        mint,
        to: escrow,
        authority: funder,
        amount,
        decimals,
        token_program: token_program.address(),
    }
    .invoke()?;
    // Exact amount: the escrow holds the leg amount and nothing else.
    let (_, _, held) = token_account(escrow, token_program.address(), HtlcError::ExactAmount)?;
    require(held == amount, HtlcError::ExactAmount)?;

    let state = Htlc {
        bump,
        escrow_bump,
        funder: *funder.address(),
        token_program: *token_program.address(),
        mint: *mint.address(),
        escrow: escrow_addr,
        recipient,
        refund,
        hash_lock,
        amount,
        timeout,
        decimals,
    };
    state.write(&mut htlc.try_borrow_mut()?)
}

/// Loads and checks the accounts common to claim and refund.
fn load(
    program_id: &Address,
    htlc: &AccountView,
    escrow: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
    rent_receiver: &AccountView,
) -> Result<(Htlc, u64), ProgramError> {
    require(htlc.owned_by(program_id), HtlcError::NotHtlc)?;
    let state = Htlc::read(&htlc.try_borrow()?)?;
    require(
        *escrow.address() == state.escrow,
        HtlcError::EscrowAddressMismatch,
    )?;
    require(*mint.address() == state.mint, HtlcError::MintMismatch)?;
    require(
        *token_program.address() == state.token_program,
        HtlcError::TokenProgramMismatch,
    )?;
    require(
        *rent_receiver.address() == state.funder,
        HtlcError::RentReceiverMismatch,
    )?;
    let (_, _, held) = token_account(
        escrow,
        token_program.address(),
        HtlcError::EscrowAddressMismatch,
    )?;
    require(held >= state.amount, HtlcError::EscrowShort)?;
    Ok((state, held))
}

/// Makes the payments from the escrow, then closes the escrow and the state account to the
/// funder.
#[allow(clippy::too_many_arguments)]
fn pay_and_close(
    state: &Htlc,
    htlc: &AccountView,
    escrow: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
    rent_receiver: &AccountView,
    payments: &[(&AccountView, u64)],
) -> ProgramResult {
    let bump_b = [state.bump];
    let seeds = [
        Seed::from(crate::HTLC_SEED),
        Seed::from(state.funder.as_ref()),
        Seed::from(&state.hash_lock[..]),
        Seed::from(&bump_b[..]),
    ];
    let signer = [Signer::from(&seeds)];
    for (to, amount) in payments {
        if *amount == 0 {
            continue;
        }
        TransferChecked {
            from: escrow,
            mint,
            to,
            authority: htlc,
            amount: *amount,
            decimals: state.decimals,
            token_program: token_program.address(),
        }
        .invoke_signed(&signer)?;
    }
    CloseAccount {
        account: escrow,
        destination: rent_receiver,
        authority: htlc,
        token_program: token_program.address(),
    }
    .invoke_signed(&signer)?;
    close_program_account(htlc, rent_receiver)
}

/// claim: data is the 32-byte preimage. Pays the whole escrow to a token account of `mint` owned by
/// the recipient, strictly before the timeout. Anyone holding the preimage may submit; the payee is
/// fixed. The escrow holds exactly `amount` unless someone donated tokens to it; a donation is paid
/// on to the recipient with the amount, so claim never depends on an account the recipient does
/// not control.
///
/// Accounts:
/// 0. `[writable]` htlc
/// 1. `[writable]` escrow
/// 2. `[writable]` recipient token account (mint = htlc mint, owner = recipient)
/// 3. `[]` mint
/// 4. `[]` token program
/// 5. `[writable]` rent receiver (= funder)
pub fn claim(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [htlc, escrow, dest, mint, token_program, rent_receiver] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == PREIMAGE_LEN, HtlcError::PreimageLength)?;
    let (state, held) = load(program_id, htlc, escrow, mint, token_program, rent_receiver)?;
    require(now()? < state.timeout, HtlcError::ClaimExpired)?;
    let digest = solana_sha256_hasher::hash(data).to_bytes();
    require(digest == state.hash_lock, HtlcError::PreimageMismatch)?;
    let (m, owner, _) = token_account(dest, token_program.address(), HtlcError::RecipientMismatch)?;
    require(m == state.mint, HtlcError::MintMismatch)?;
    require(owner == state.recipient, HtlcError::RecipientMismatch)?;
    pay_and_close(
        &state,
        htlc,
        escrow,
        mint,
        token_program,
        rent_receiver,
        &[(dest, held)],
    )
}

/// refund: no data. At or after the timeout, pays the whole escrow to a token account of `mint`
/// owned by the refund owner. Anyone may submit; the payee is fixed.
///
/// Accounts:
/// 0. `[writable]` htlc
/// 1. `[writable]` escrow
/// 2. `[writable]` refund token account (mint = htlc mint, owner = refund)
/// 3. `[]` mint
/// 4. `[]` token program
/// 5. `[writable]` rent receiver (= funder)
pub fn refund(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [htlc, escrow, dest, mint, token_program, rent_receiver] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (state, held) = load(program_id, htlc, escrow, mint, token_program, rent_receiver)?;
    require(now()? >= state.timeout, HtlcError::RefundTooEarly)?;
    let (m, owner, _) = token_account(
        dest,
        token_program.address(),
        HtlcError::RefundAccountMismatch,
    )?;
    require(m == state.mint, HtlcError::MintMismatch)?;
    require(owner == state.refund, HtlcError::RefundAccountMismatch)?;
    pay_and_close(
        &state,
        htlc,
        escrow,
        mint,
        token_program,
        rent_receiver,
        &[(dest, held)],
    )
}
