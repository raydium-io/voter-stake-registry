use crate::error::*;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};
use solana_program::program::invoke;
use solana_program::sysvar;

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub registrar: AccountLoader<'info, Registrar>,

    // checking the PDA address it just an extra precaution,
    // the other constraints must be exhaustive
    #[account(
        mut,
        seeds = [registrar.key().as_ref(), b"voter".as_ref(), voter.load()?.voter_authority.key().as_ref()],
        bump = voter.load()?.voter_bump,
        has_one = registrar)]
    pub voter: AccountLoader<'info, Voter>,

    #[account(
        mut,
        associated_token::authority = voter,
        associated_token::mint = deposit_token.mint,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = deposit_token.owner == deposit_authority.key(),
    )]
    pub deposit_token: Box<Account<'info, TokenAccount>>,
    pub deposit_authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    // remaining account
    // staker_info
    // staking_pool
    // voting_mint
    // voting_mint_authority
    // staking_program
    // instruction_program
}

impl<'info> Deposit<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.deposit_token.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.deposit_authority.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}

/// Adds tokens to a deposit entry.
///
/// Tokens will be transfered from deposit_token to vault using the deposit_authority.
///
/// The deposit entry must have been initialized with create_deposit_entry.
///
/// `deposit_entry_index`: Index of the deposit entry.
/// `amount`: Number of native tokens to transfer.
///
/// Note that adding tokens to a deposit entry with vesting, where some vesting
/// periods are already in the past is supported. What happens is that the tokens
/// get distributed over vesting points in the future.
///
/// Example: 20 tokens are deposited to a three-day vesting deposit entry
/// that started 36 hours ago. That means 10 extra tokens will vest in 12 hours
/// and another 10 in 36 hours.
pub fn deposit<'a, 'b, 'c, 'info>(
    ctx: Context<'a, 'b, 'c, 'info, Deposit<'info>>,
    deposit_entry_index: u8,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }

    if ctx.accounts.vault.mint == crate::restricted_id::voting_mint::id() {
        require_eq!(ctx.remaining_accounts.len(), 6);
        let remaining_accounts_iter = &mut ctx.remaining_accounts.iter();
        let staker_info = remaining_accounts_iter.next().unwrap();
        let staking_pool_info = remaining_accounts_iter.next().unwrap();
        let voting_mint_info = remaining_accounts_iter.next().unwrap();
        let voting_mint_authority_info = remaining_accounts_iter.next().unwrap();
        let staking_program = remaining_accounts_iter.next().unwrap();
        let instruction_program = remaining_accounts_iter.next().unwrap();

        require_keys_eq!(
            voting_mint_info.key(),
            crate::restricted_id::voting_mint::id()
        );
        require_keys_eq!(
            staking_program.key(),
            crate::restricted_id::staking_program::id()
        );
        require_keys_eq!(instruction_program.key(), sysvar::instructions::id());

        let user_vote_token_info = ctx.accounts.deposit_token.to_account_info();
        let voter_authority_info = ctx.accounts.deposit_authority.to_account_info();

        let mint_ix = raydium_staking::instruction::mint_vote_token(
            staking_program.key,
            voting_mint_authority_info.key,
            staking_pool_info.key,
            voting_mint_info.key,
            staker_info.key,
            user_vote_token_info.key,
            voter_authority_info.key,
            amount,
        )?;

        invoke(
            &mint_ix,
            &[
                voting_mint_authority_info.clone(),
                staking_pool_info.clone(),
                voting_mint_info.clone(),
                staker_info.clone(),
                user_vote_token_info.clone(),
                voter_authority_info.clone(),
                instruction_program.clone(),
            ],
        )?;
        ctx.accounts.deposit_token.reload()?;
    }

    let registrar = &ctx.accounts.registrar.load()?;
    let voter = &mut ctx.accounts.voter.load_mut()?;

    let d_entry = voter.active_deposit_mut(deposit_entry_index)?;

    // Get the exchange rate entry associated with this deposit.
    let mint_idx = registrar.voting_mint_config_index(ctx.accounts.deposit_token.mint)?;
    require_eq!(
        mint_idx,
        d_entry.voting_mint_config_idx as usize,
        VsrError::InvalidMint
    );

    // Adding funds to a lockup that is already in progress can be complicated
    // for linear vesting schedules because all added funds should be paid out
    // gradually over the remaining lockup duration.
    // The logic used is to:
    // - realize the vesting by reducing the locked amount and moving the start
    //   if the lockup forward by the number of expired vesting periods
    // - add the new funds to the locked up token count, so they will vest over
    //   the remaining periods.
    let curr_ts = registrar.clock_unix_timestamp();
    d_entry.resolve_vesting(curr_ts)?;

    // Deposit tokens into the vault and increase the lockup amount too.
    token::transfer(ctx.accounts.transfer_ctx(), amount)?;
    d_entry.amount_deposited_native = d_entry.amount_deposited_native.checked_add(amount).unwrap();
    d_entry.amount_initially_locked_native = d_entry
        .amount_initially_locked_native
        .checked_add(amount)
        .unwrap();

    msg!(
        "Deposited amount {} at deposit index {} with lockup kind {:?} and {} seconds left",
        amount,
        deposit_entry_index,
        d_entry.lockup.kind,
        d_entry.lockup.seconds_left(curr_ts),
    );

    Ok(())
}
