// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The statement of spec/V3-ZK.md 22.4: the checks of the v1 vault (contracts/impulse_vault.sil,
//! tags in spec/TEMPLATE.md) run over the view in J against the committed terms. Each check keeps
//! the tag of the v1 require it replaces; the order is v1's. Only `[S6]`, `[R2]` (signatures) and
//! the lock-time finality of the spending input stay in the script (`[T4]`, `[T5]`, `[T8]`).

use crate::codec::*;
use crate::hashes;
use crate::journal::{Item, Journal, Mode};
use crate::kcc20::{self, Opened, State};
use crate::witness::Witness;
use crate::{
    refuse, require, Refusal, LOCK_TIME_THRESHOLD, SHAPE, STATEMENT_FALSE, WITNESS_INVALID,
};

#[derive(Clone, Copy, Debug)]
pub struct StatementOptions {
    /// Check that public keys are points on the curve (the guest always does).
    pub curve_checks: bool,
}

impl Default for StatementOptions {
    fn default() -> Self {
        Self { curve_checks: true }
    }
}

const ZERO: [u8; 32] = [0; 32];

/// Where silverc v1.0.0 puts the state of template v4 in its redeem script: one byte of prefix,
/// then `0x20 || termsCommit || 0x20 || authorityKey` (`contracts/compiled/impulse_vault.v4.json`,
/// `state_span`; pinned by `tests/engine/v4_template.rs`).
pub const VAULT_STATE_OFFSET: usize = 1;
pub const VAULT_STATE_LEN: usize = 66;

/// A token leg's template as the terms name it.
#[derive(Clone, Copy)]
struct Template {
    cov: [u8; 32],
    hash: [u8; 32],
    prefix_len: u32,
    suffix_len: u32,
    amount: i64,
}

fn template_of(l: &Leg) -> Option<Template> {
    match l {
        Leg::Kcc20 {
            cov,
            template_hash,
            prefix_len,
            suffix_len,
            amount,
        } => Some(Template {
            cov: *cov,
            hash: *template_hash,
            prefix_len: *prefix_len,
            suffix_len: *suffix_len,
            amount: *amount as i64,
        }),
        _ => None,
    }
}

struct Ctx<'a> {
    t: &'a Terms,
    j: &'a Journal,
    w: &'a Witness,
    vault_binding: bool,
}

impl Ctx<'_> {
    fn input(&self, i: usize) -> Item {
        self.j.inputs[i]
    }
    fn output(&self, i: usize) -> Item {
        self.j.outputs[i]
    }
    fn active_value(&self) -> u64 {
        self.j.inputs[self.j.input_index as usize].value
    }

    /// The token input at `idx`: its redeem script from the witness must be the one the input's
    /// P2SH hash names; then it is opened to the template. A redeem that does not open is a
    /// `ZK_H_WITNESS_INVALID`; a template mismatch is the statement being false at `tag`.
    fn open_token(
        &self,
        idx: usize,
        tm: &Template,
        tag: &'static str,
    ) -> Result<Opened<'_>, Refusal> {
        let Some(redeem) = self.w.redeem(idx) else {
            return refuse(WITNESS_INVALID, tag);
        };
        if kcc20::input_spk_hash(redeem) != self.input(idx).spk_hash {
            return refuse(WITNESS_INVALID, tag);
        }
        match kcc20::open_template(redeem, tm.prefix_len, tm.suffix_len, &tm.hash) {
            Some(o) => Ok(o),
            None => refuse(STATEMENT_FALSE, tag),
        }
    }

    /// `checkEscrow`: the escrow at `idx` is the only input of its covenant, runs the pinned
    /// template, is owned by this vault, holds exactly `amount` and is not a minter.
    fn check_escrow(
        &self,
        idx: usize,
        cov: &[u8; 32],
        count: u8,
        tm: &Template,
    ) -> Result<(), Refusal> {
        require(count == 1, "E1")?;
        require(self.input(idx).cov == *cov, "E2")?;
        let o = self.open_token(idx, tm, "E3")?;
        require(o.state.id_type == ID_SCRIPT_HASH, "E3")?;
        require(self.j.vault_spk == hashes::p2sh_spk(&o.state.owner), "E4")?;
        require(o.state.amount == tm.amount, "E5")?;
        require(!o.state.is_minter, "E6")
    }

    /// `checkAuthorizerReturn`: the authorizer's KAS goes back to its depositor at output `k`.
    fn check_return(&self, k: usize, depositor: &[u8; 32]) -> Result<(), Refusal> {
        require(
            self.output(k).spk_hash == hashes::sha256(&hashes::p2pk_spk(depositor)),
            "S8",
        )?;
        require(self.output(k).value >= self.active_value(), "S9")
    }

    /// `checkTokenDelivery`: output `k` carries `cov` and is the template of input `template_idx`
    /// around exactly (owner, amount, not a minter), with at least that input's KAS.
    fn check_delivery(
        &self,
        k: usize,
        cov: &[u8; 32],
        owner: &Dest,
        amount: i64,
        template_idx: usize,
        tm: &Template,
    ) -> Result<(), Refusal> {
        require(self.output(k).cov == *cov, "D1")?;
        require(self.output(k).value >= self.input(template_idx).value, "D2")?;
        let Dest::Owner { id_type, id } = owner else {
            return refuse(STATEMENT_FALSE, "DB");
        };
        let o = self.open_token(template_idx, tm, "DB")?;
        let expected = State {
            owner: *id,
            id_type: *id_type,
            amount,
            is_minter: false,
        };
        require(
            kcc20::output_spk_hash(o.prefix, o.suffix, &expected) == self.output(k).spk_hash,
            "DB",
        )
    }
}

/// Runs the statement over a witness. Returns the journal bytes (J) the guest commits.
pub fn statement(w: &Witness, opts: StatementOptions) -> Result<Vec<u8>, Refusal> {
    run(w, opts, true)
}

/// The statement without `[H5]`, for the differential test against template v1 only
/// (`tests/engine/v4_core.rs`): its views hold v1 vaults, which have no v4 redeem script, so that
/// test checks the same rule on the v1 vaults itself. The guest, the prover and the builders call
/// `statement`.
#[doc(hidden)]
pub fn statement_without_h5_for_v1_differential(
    w: &Witness,
    opts: StatementOptions,
) -> Result<Vec<u8>, Refusal> {
    run(w, opts, false)
}

fn run(w: &Witness, opts: StatementOptions, vault_binding: bool) -> Result<Vec<u8>, Refusal> {
    let j = Journal::parse(&w.journal)?;
    // [H2] the terms decode (version first) and pass the structure checks
    let t = Terms::decode(&w.terms)?;
    crate::structure::validate(&t, opts.curve_checks)?;
    // [H1] the committed terms are these terms, for this leg
    require(j.leg <= 1, "H1")?;
    let commit = hashes::commit(&hashes::terms_hash(&w.terms), j.leg);
    require(commit == j.commit, "H1")?;
    // [H3] the authority in the vault's state is the terms' authority
    require(t.authority == Some(j.authority), "H3")?;
    let ctx = Ctx {
        t: &t,
        j: &j,
        w,
        vault_binding,
    };
    match j.mode {
        Mode::Settle => settle(&ctx)?,
        Mode::Refund => refund(&ctx)?,
    }
    Ok(w.journal.clone())
}

fn settle(c: &Ctx) -> Result<(), Refusal> {
    let (t, j) = (c.t, c.j);
    let asset = template_of(&t.asset).expect("structure: the asset leg is KCC-20");
    let cash = template_of(&t.cash);
    let external = matches!(t.cash, Leg::External { .. });
    // [H4] the covenant IDs the script passed are the terms'; the layout is the cash kind's
    require(j.cov_a == asset.cov, "H4")?;
    require(j.cov_c == cash.map_or(ZERO, |m| m.cov), "H4")?;
    require(j.signer == ZERO, "H4")?;
    let (n_in, n_out) = match t.cash {
        Leg::Kas { .. } => (3, 3),
        Leg::Kcc20 { .. } => (4, 4),
        Leg::External { .. } => (2, 2),
    };
    if j.inputs.len() != n_in || j.outputs.len() != n_out {
        return refuse(SHAPE, "H4");
    }
    // [S1] the asset authorizer at input 0, the cash authorizer at input 1
    require(j.leg == j.input_index, "S1")?;
    // [H5] the other leg's vault of these terms at its slot, where the other leg has a vault
    if !external && c.vault_binding {
        other_vault(c)?;
    }
    // [S7] is vacuous: an authority is always present (structure).
    let asset_slot = if external { 1 } else { 2 };
    let cash_slot = 3;
    if j.leg == 0 {
        c.check_escrow(asset_slot, &asset.cov, j.count_a, &asset)?;
        c.check_return(asset_slot, &t.seller)?;
    } else {
        match (&t.cash, cash) {
            (Leg::Kas { amount }, _) => {
                require(c.active_value() == *amount, "S2")?;
            }
            (_, Some(cm)) => {
                c.check_escrow(cash_slot, &cm.cov, j.count_c, &cm)?;
                c.check_return(cash_slot, &t.buyer)?;
            }
            // External cash has no cash vault: v1's leg-1 vault finds no input of the (zero)
            // cash covenant and fails [E1].
            _ => return refuse(STATEMENT_FALSE, "E1"),
        }
    }
    // [S3] not before earliest_daa
    if let Some(e) = t.earliest {
        require(j.locktime >= e && j.locktime < LOCK_TIME_THRESHOLD, "S3")?;
    }
    // output 0 delivers amount_a of the asset to the buyer
    c.check_delivery(
        0,
        &asset.cov,
        &t.buyer_delivery,
        asset.amount,
        asset_slot,
        &asset,
    )?;
    // output 1 delivers amount_b of cash to the seller; skipped for external cash
    match (&t.cash, cash) {
        (Leg::Kas { amount }, _) => {
            let Dest::Kas { version, script } = &t.seller_proceeds else {
                return refuse(STATEMENT_FALSE, "S4");
            };
            require(c.output(1).spk_hash == kas_spk_hash(*version, script), "S4")?;
            require(c.output(1).value == *amount, "S5")?;
        }
        (_, Some(cm)) => {
            c.check_delivery(1, &cm.cov, &t.seller_proceeds, cm.amount, cash_slot, &cm)?;
        }
        _ => {}
    }
    Ok(())
}

/// `[H5]` (spec/V3-ZK.md 22.16): view input `1 - leg` is the template v4 vault of these terms for
/// the other leg. The guest cannot hold template v4 (it embeds this guest's image ID), so it takes
/// this vault's own redeem script from the witness, requires it to open `J.vault_spk` with J's
/// commitment and authority at the state span, swaps in the other leg's commitment and compares
/// the P2SH with the view.
fn other_vault(c: &Ctx) -> Result<(), Refusal> {
    let j = c.j;
    let Some(r) = c.w.redeem(j.input_index as usize) else {
        return refuse(WITNESS_INVALID, "H5");
    };
    let at = VAULT_STATE_OFFSET;
    if r.len() < at + VAULT_STATE_LEN
        || hashes::p2sh_spk(&hashes::blake2b256(r)) != j.vault_spk
        || r[at] != 0x20
        || r[at + 1..at + 33] != j.commit
        || r[at + 33] != 0x20
        || r[at + 34..at + 66] != j.authority
    {
        return refuse(WITNESS_INVALID, "H5");
    }
    let mut other = r.to_vec();
    let th = hashes::terms_hash(&c.w.terms);
    other[at + 1..at + 33].copy_from_slice(&hashes::commit(&th, 1 - j.leg));
    require(
        kcc20::input_spk_hash(&other) == c.input(1 - j.input_index as usize).spk_hash,
        "H5",
    )
}

fn kas_spk_hash(version: u16, script: &[u8]) -> [u8; 32] {
    let mut spk = Vec::with_capacity(2 + script.len());
    spk.extend_from_slice(&version.to_be_bytes());
    spk.extend_from_slice(script);
    hashes::sha256(&spk)
}

fn refund(c: &Ctx) -> Result<(), Refusal> {
    let (t, j) = (c.t, c.j);
    let is_asset = j.leg == 0;
    let depositor = if is_asset { &t.seller } else { &t.buyer };
    let counterparty = if is_asset { &t.buyer } else { &t.seller };
    let leg_tm = template_of(if is_asset { &t.asset } else { &t.cash });
    let kas_cash = !is_asset && matches!(t.cash, Leg::Kas { .. });
    // [H4] the covenant ID the script passed is the leg's token (zero for a leg without one)
    require(j.cov_a == leg_tm.map_or(ZERO, |m| m.cov), "H4")?;
    require(j.cov_c == ZERO && j.count_c == 0, "H4")?;
    let token_inputs = j.count_a;
    let (n_in, n_out) = if kas_cash || token_inputs == 0 {
        (1, 1)
    } else {
        (2, 2)
    };
    if j.inputs.len() != n_in || j.outputs.len() != n_out {
        return refuse(SHAPE, "H4");
    }
    // [R1] the depositor, the counterparty or the authority; [R2] is the signature, in script
    require(
        j.signer == *depositor || j.signer == *counterparty || Some(j.signer) == t.authority,
        "R1",
    )?;
    // [R3] an earmarked depositor refund opens at expiry
    if t.funding != FUNDING_REVOCABLE && j.signer == *depositor {
        require(
            j.locktime >= t.expiry && j.locktime < LOCK_TIME_THRESHOLD,
            "R3",
        )?;
    }
    // [R4], [R5] one vault UTXO per refund, at input 0, its KAS whole at output 0
    require(j.input_index == 0, "R4")?;
    require(c.output(0).value == c.input(0).value, "R5")?;
    if kas_cash {
        // [R6] a KAS cash leg goes to the buyer's refund scriptPubKey
        let Dest::Kas { version, script } = &t.buyer_refund else {
            return refuse(STATEMENT_FALSE, "R6");
        };
        require(c.output(0).spk_hash == kas_spk_hash(*version, script), "R6")?;
        return Ok(());
    }
    // [R7] the authorizer's KAS goes to the depositor
    require(
        c.output(0).spk_hash == hashes::sha256(&hashes::p2pk_spk(depositor)),
        "R7",
    )?;
    // [R11] only the depositor may refund the authorizer without the token
    if j.signer != *depositor {
        require(token_inputs == 1, "R11")?;
    }
    if token_inputs > 0 {
        // [R8], [R9] the leg's token is this vault's escrow at input 1
        require(token_inputs == 1, "R8")?;
        require(c.input(1).cov == j.cov_a, "R9")?;
        let Some(tm) = leg_tm else {
            return refuse(STATEMENT_FALSE, "R9");
        };
        let o = c.open_token(1, &tm, "R12")?;
        // [R12] it is owned by this vault
        require(j.vault_spk == hashes::p2sh_spk(&o.state.owner), "R12")?;
        // [R14] outside the depositor's own refund it holds the full leg amount
        if j.signer != *depositor {
            require(o.state.amount == tm.amount, "R14")?;
        }
        // [R10], [R13] it returns whole to the depositor's refund owner at output 1
        require(c.output(1).cov == j.cov_a, "R10")?;
        require(c.output(1).value >= c.input(1).value, "R13")?;
        let home_dest = if is_asset {
            &t.seller_refund
        } else {
            &t.buyer_refund
        };
        let Dest::Owner { id_type, id } = home_dest else {
            return refuse(STATEMENT_FALSE, "RB");
        };
        let home = State {
            owner: *id,
            id_type: *id_type,
            amount: o.state.amount,
            is_minter: o.state.is_minter,
        };
        require(
            kcc20::output_spk_hash(o.prefix, o.suffix, &home) == c.output(1).spk_hash,
            "RB",
        )?;
    }
    Ok(())
}
