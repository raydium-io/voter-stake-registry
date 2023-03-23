use crate::error::*;
use crate::state::*;
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};
use solana_program::program::invoke;
use solana_program::sysvar;

use raydium_staking::*;
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub registrar: AccountLoader<'info, Registrar>,

    // checking the PDA address it just an extra precaution,
    // the other constraints must be exhaustive
    #[account(
        mut,
        seeds = [registrar.key().as_ref(), b"voter".as_ref(), voter_authority.key().as_ref()],
        bump = voter.load()?.voter_bump,
        has_one = registrar,
        has_one = voter_authority,
    )]
    pub voter: AccountLoader<'info, Voter>,
    pub voter_authority: Signer<'info>,

    /// The token_owner_record for the voter_authority. This is needed
    /// to be able to forbid withdraws while the voter is engaged with
    /// a vote or has an open proposal.
    ///
    /// CHECK: token_owner_record is validated in the instruction:
    /// - owned by registrar.governance_program_id
    /// - for the registrar.realm
    /// - for the registrar.realm_governing_token_mint
    /// - governing_token_owner is voter_authority
    pub token_owner_record: UncheckedAccount<'info>,

    /// Withdraws must update the voter weight record, to prevent a stale
    /// record being used to vote after the withdraw.
    #[account(
        mut,
        seeds = [registrar.key().as_ref(), b"voter-weight-record".as_ref(), voter_authority.key().as_ref()],
        bump = voter.load()?.voter_weight_record_bump,
        constraint = voter_weight_record.realm == registrar.load()?.realm,
        constraint = voter_weight_record.governing_token_owner == voter.load()?.voter_authority,
        constraint = voter_weight_record.governing_token_mint == registrar.load()?.realm_governing_token_mint,
    )]
    pub voter_weight_record: Account<'info, VoterWeightRecord>,

    #[account(
        mut,
        associated_token::authority = voter,
        associated_token::mint = destination.mint,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub destination: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    // remaining account
    // staker_info
    // staking_pool
    // voting_mint
    // voting_mint_authority
    // staking_program
    // instruction_program
}

impl<'info> Withdraw<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.vault.to_account_info(),
            to: self.destination.to_account_info(),
            authority: self.voter.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}

/// Withdraws tokens from a deposit entry, if they are unlocked according
/// to the deposit's vesting schedule.
///
/// `deposit_entry_index`: The deposit entry to withdraw from.
/// `amount` is in units of the native currency being withdrawn.
pub fn withdraw<'a, 'b, 'c, 'info>(
    ctx: Context<'a, 'b, 'c, 'info, Withdraw<'info>>,
    deposit_entry_index: u8,
    amount: u64,
) -> Result<()> {
    {
        // Transfer the tokens to withdraw.
        let voter = &mut ctx.accounts.voter.load()?;
        let voter_seeds = voter_seeds!(voter);
        token::transfer(
            ctx.accounts.transfer_ctx().with_signer(&[voter_seeds]),
            amount,
        )?;
    }

    if ctx.accounts.vault.mint == crate::restricted_id::voting_mint::id() {
        ctx.accounts.destination.reload()?;
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

        let user_vote_token_info = ctx.accounts.destination.to_account_info();
        let voter_authority_info = ctx.accounts.voter_authority.to_account_info();

        let burn_ix = raydium_staking::instruction::burn_vote_token(
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
            &burn_ix,
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
    }

    // Load the accounts.
    let registrar = &ctx.accounts.registrar.load()?;
    let voter = &mut ctx.accounts.voter.load_mut()?;

    // Get the exchange rate for the token being withdrawn.
    let mint_idx = registrar.voting_mint_config_index(ctx.accounts.destination.mint)?;

    // Governance may forbid withdraws, for example when engaged in a vote.
    // Not applicable for tokens that don't contribute to voting power.
    if registrar.voting_mints[mint_idx].grants_vote_weight() {
        let token_owner_record = voter.load_token_owner_record(
            &ctx.accounts.token_owner_record.to_account_info(),
            registrar,
        )?;
        token_owner_record.assert_can_withdraw_governing_tokens()?;
    }

    // Get the deposit being withdrawn from.
    let curr_ts = registrar.clock_unix_timestamp();
    let deposit_entry = voter.active_deposit_mut(deposit_entry_index)?;
    require_gte!(
        deposit_entry.amount_unlocked(curr_ts),
        amount,
        VsrError::InsufficientUnlockedTokens
    );
    require_eq!(
        mint_idx,
        deposit_entry.voting_mint_config_idx as usize,
        VsrError::InvalidMint
    );

    // Bookkeeping for withdrawn funds.
    require_gte!(
        deposit_entry.amount_deposited_native,
        amount,
        VsrError::InternalProgramError
    );
    deposit_entry.amount_deposited_native = deposit_entry
        .amount_deposited_native
        .checked_sub(amount)
        .unwrap();

    msg!(
        "Withdrew amount {} at deposit index {} with lockup kind {:?} and {} seconds left",
        amount,
        deposit_entry_index,
        deposit_entry.lockup.kind,
        deposit_entry.lockup.seconds_left(curr_ts),
    );

    // Update the voter weight record
    let record = &mut ctx.accounts.voter_weight_record;
    record.voter_weight = voter.weight(registrar)?;
    record.voter_weight_expiry = Some(Clock::get()?.slot);

    Ok(())
}
