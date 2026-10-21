// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The builders of a linked trade, by role (spec/V2.md 17.6). Each wraps the `impulse_core::v2`
//! builder on the terms the sheet derives for the role, so a caller names a sheet and a role and
//! cannot pass the terms of another trade. The return's fund and settle builders also need the
//! opening's [`OpeningSettled`] evidence; the opening's builders and every refund do not.
//!
//! Keyless like the builders they wrap: unsigned transactions with one sighash per signature
//! slot, nothing here signs or holds a key.

use super::{LinkedError, OpeningSettled, Role, ValidatedLinked};
use crate::terms::CreationContext;
use crate::tx::{FeePayment, Kcc20Deposit, Kcc20Template, RefundEscrow, Utxo};
use crate::v2::{
    self, FundableVaultV2, IpstV2, RefundSignerV2, SettleLeg, ValidatedTermsV2, VaultV2,
};

impl ValidatedLinked {
    /// The funding vault of `leg` of `role`'s trade: the creation checks of that trade, at the
    /// DAA score of this moment, then the vault. The only vault value an address is shown for.
    pub fn vault_for_creation(
        &self,
        role: Role,
        leg: usize,
        ctx: &CreationContext,
    ) -> Result<FundableVaultV2, LinkedError> {
        Ok(VaultV2::instantiate_for_creation(
            self.terms(role),
            leg,
            ctx,
        )?)
    }

    /// The vault of `leg` of `role`'s existing trade.
    pub fn vault(&self, role: Role, leg: usize) -> Result<VaultV2, LinkedError> {
        Ok(VaultV2::instantiate_existing(self.terms(role), leg)?)
    }

    /// The return needs the opening's evidence for this sheet; the opening needs none.
    fn gate(&self, role: Role, evidence: Option<&OpeningSettled>) -> Result<(), LinkedError> {
        match (role, evidence) {
            (Role::Opening, _) => Ok(()),
            (Role::Return, Some(e)) => e.check_for(self),
            (Role::Return, None) => Err(LinkedError::OpeningNotSettled),
        }
    }

    /// `v2::fund_kas` on `role`'s trade. The return needs `evidence`.
    pub fn fund_kas(
        &self,
        role: Role,
        evidence: Option<&OpeningSettled>,
        vault: &FundableVaultV2,
        funding: &FeePayment,
        current_daa: u64,
    ) -> Result<IpstV2, LinkedError> {
        self.gate(role, evidence)?;
        Ok(v2::fund_kas(self.terms(role), vault, funding, current_daa)?)
    }

    /// `v2::fund_kcc20` on `role`'s trade. The return needs `evidence`.
    // The wrapped builder takes seven arguments; the wrapper adds the role and the evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn fund_kcc20(
        &self,
        role: Role,
        evidence: Option<&OpeningSettled>,
        vault: &FundableVaultV2,
        template: &Kcc20Template,
        deposit: &Kcc20Deposit,
        funding: &FeePayment,
        current_daa: u64,
    ) -> Result<IpstV2, LinkedError> {
        self.gate(role, evidence)?;
        Ok(v2::fund_kcc20(
            self.terms(role),
            vault,
            template,
            deposit,
            funding,
            current_daa,
        )?)
    }

    /// `v2::settle` on `role`'s trade. The return needs `evidence`.
    pub fn settle(
        &self,
        role: Role,
        evidence: Option<&OpeningSettled>,
        legs: &[SettleLeg<'_>],
        fee: &FeePayment,
        current_daa: u64,
    ) -> Result<IpstV2, LinkedError> {
        self.gate(role, evidence)?;
        Ok(v2::settle(self.terms(role), legs, fee, current_daa)?)
    }

    /// `v2::refund` on `role`'s trade. Needs no evidence: a refund only takes a depositor's own
    /// leg home.
    pub fn refund(
        &self,
        role: Role,
        leg: usize,
        signer: RefundSignerV2,
        vault_utxo: &Utxo,
        escrow: Option<&RefundEscrow<'_>>,
        fee: &FeePayment,
    ) -> Result<IpstV2, LinkedError> {
        Ok(v2::refund(
            self.terms(role),
            leg,
            signer,
            vault_utxo,
            escrow,
            fee,
        )?)
    }

    /// The terms of `role`, for callers that go on with the `v2` verifier and decoder.
    pub fn trade(&self, role: Role) -> &ValidatedTermsV2 {
        self.terms(role)
    }
}
