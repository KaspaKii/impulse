// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The hashed-terms vault, template v4 (spec/V3-ZK.md section 22), in the CLI. The verifier side:
//! the lines `impulse decode` prints for a v4 vault input, with and without a revealed terms
//! file, `zk terms reveal`, `zk address` and `zk verify` for a terms v4 file. The builders: `zk
//! terms new-hashed`, `zk fund build`, `zk settle build`, `zk refund build` and `zk witness`,
//! routed here when the terms file is a terms v4 file (lowercase hex) and the IPST commands
//! (`zkh_sign`) when the document is version 5. The proof comes from `impulse-zk-prove-terms`
//! (circuits/), which reads the witness `zk witness` writes. Nothing here signs or holds a key
//! except through the signing module.

use crate::build_cmd::{node_now, PayArgs, Templates};
use crate::cli::{creation, party, print, CapArgs, Ctx};
use crate::error::CliError;
use crate::funds::{
    address_script, fee_candidates, p2pk_address, parse_change, parse_outpoint, parse_pay_from,
    parse_token, utxo_at, utxos_with,
};
use crate::json::hex;
use crate::node::{self, Node};
use crate::summary;
use crate::terms_file::{parse_draft, read_text, write_new};
use crate::trade::{check_kas_minimum, check_pinned, leg_name};
use crate::txview;
use crate::value_cap::CapPolicy;
use crate::zk_cmd::{
    ZkFundBuildArgs, ZkRefundBuildArgs, ZkSettleBuildArgs, ZkTermsNewHashedArgs, ZkWitnessArgs,
};
use clap::Args;
use impulse_core::template::LegIndex;
use impulse_core::terms::{
    CreationContext, IdentifierType, Kcc20Owner, Kcc20Token, LegKind, Network,
};
use impulse_core::tx::{
    min_relay_fee, FeePayment, IpstKind, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow,
    RefundSigner, SettleCash, SettleLegs, TokenUtxo, Utxo, MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use impulse_core::zkh::{self, IpstV4, ProofV4, ValidatedTermsV4, VaultV4, ZkhError};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry};
use rand::RngCore;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The fixed texts of spec/V3-ZK.md 22.11, each on its own line.
pub const DISCLOSURE_LINE: &str = "The chain shows only a commitment to the terms until a spend. Vault values, the escrowed token, the authority's key, the funders and the outputs of a settle or refund are public. Anyone holding the terms file can show the terms.";
pub const LOSS_LINE: &str =
    "Settle and refund both need the terms file. Keep a copy before funding.";
pub const SOUNDNESS_LINE: &str =
    "A flaw in the proof check could let funds leave a v4 vault. Keep value at or below the cap.";

impl From<ZkhError> for CliError {
    fn from(e: ZkhError) -> Self {
        CliError::new(e.code(), e.reason().to_string())
    }
}

#[derive(Args, Debug)]
pub struct ZkTermsRevealArgs {
    /// The terms file (lowercase hex of the canonical terms v4).
    #[arg(long, value_name = "FILE")]
    pub terms: PathBuf,
    /// The leg: 0 for the asset vault, 1 for the cash vault.
    #[arg(long, value_name = "0|1")]
    pub leg: u8,
}

pub(crate) fn read_terms(path: &Path) -> Result<terms_core::Terms, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::new(
            "ZK_H_TERMS_FILE",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    Ok(zkh::parse_terms_file(&text)?)
}

fn network_of(t: &terms_core::Terms) -> Network {
    if t.network == 0 {
        Network::Mainnet
    } else {
        Network::Testnet
    }
}

/// `impulse zk terms reveal`: the commitment and vault address of a leg.
pub(crate) fn terms_reveal(
    ctx: &Ctx,
    a: ZkTermsRevealArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    if a.leg > 1 {
        return Err(CliError::new("ZK_H_SHAPE", "leg is 0 or 1"));
    }
    let terms = read_terms(&a.terms)?;
    if network_of(&terms) != ctx.network {
        return Err(CliError::new(
            "ZK_H_TERMS_MISMATCH",
            "the terms name another network than the one acted on",
        ));
    }
    if a.leg == 1 && matches!(terms.cash, terms_core::Leg::External { .. }) {
        return Err(CliError::new(
            "ZK_H_SHAPE",
            "external cash settles off chain: there is no cash vault",
        ));
    }
    let vault = zkh::VaultV4::of_terms(&terms, a.leg)?;
    print(
        out,
        &[
            format!(
                "terms hash: {}",
                hex(&terms_core::hashes::terms_hash(&terms.encode()))
            ),
            format!("leg: {}", a.leg),
            format!("commitment: {}", hex(&vault.commit())),
            format!("authority key: {}", hex(&vault.authority())),
            format!("vault address: {}", vault.address(network_of(&terms))),
            DISCLOSURE_LINE.into(),
            LOSS_LINE.into(),
            SOUNDNESS_LINE.into(),
        ],
    )
}

/// True if any input of the transaction runs template v4.
pub(crate) fn has_v4(tx: &Transaction) -> bool {
    zkh::hidden_inputs(tx).is_ok_and(|h| !h.is_empty())
}

/// The lines for the v4 vault inputs of an accepted transaction. Without terms a v4 input is
/// reported as a vault with a commitment, with `terms not revealed`; that is not an error. With
/// terms every input is checked against the commitment and the statement, tag by tag.
pub(crate) fn lines(
    tx: &Transaction,
    spent: &[UtxoEntry],
    terms: Option<&terms_core::Terms>,
) -> Result<Vec<String>, CliError> {
    let mut out = Vec::new();
    match terms {
        None => {
            for h in zkh::hidden_inputs(tx)? {
                out.push(format!(
                    "v4 vault: input {}, template v4 vault, commitment {}, authority key {}, entry {}, proof {}, terms not revealed",
                    h.input_index,
                    hex(&h.commit),
                    hex(&h.authority),
                    h.entry,
                    if h.proof_present { "present" } else { "absent" },
                ));
            }
        }
        Some(t) => {
            let checks = zkh::check_revealed(tx, spent, t)?;
            for c in &checks {
                match &c.verdict {
                    Ok(()) => out.push(format!(
                        "v4 vault: input {}, {} of leg {} ({}): every tag of the statement holds on the reconstructed view",
                        c.input_index,
                        c.entry,
                        c.leg,
                        if c.leg == 0 { "asset" } else { "cash" }
                    )),
                    Err(e) => out.push(format!(
                        "v4 vault: input {}, {}: {e}",
                        c.input_index, c.entry
                    )),
                }
            }
            out.push("check: repeats what the proof states, natively and without a proof, bound to the scriptPublicKeys the node reports".into());
            if let Some(e) = checks.iter().find_map(|c| c.verdict.clone().err()) {
                out.push(DISCLOSURE_LINE.into());
                return Err(CliError::new(
                    e.code(),
                    format!("{}; {}", e.reason(), out.join(" | ")),
                ));
            }
        }
    }
    out.push(DISCLOSURE_LINE.into());
    Ok(out)
}

// =============================================================================================
// Terms files, the cap, shared helpers
// =============================================================================================

/// True if the file looks like a terms v4 file (lowercase hex) rather than a terms v3 file (JSON).
pub(crate) fn is_hashed_file(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| {
        t.trim_start()
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_hexdigit())
    })
}

/// Reads a terms v4 file on the command's network: lowercase hex of the canonical terms v4 and
/// nothing else (`ZK_H_TERMS_FILE`), then every structure check.
pub(crate) fn read_terms_v4(ctx: &Ctx, path: &Path) -> Result<ValidatedTermsV4, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::new(
            "ZK_H_TERMS_FILE",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let core = zkh::parse_terms_file(&text)?;
    if text.trim() != hex(&core.encode()) {
        return Err(CliError::new(
            "ZK_H_TERMS_FILE",
            "the terms file is not exactly the lowercase hex of the canonical terms v4",
        ));
    }
    let terms = ValidatedTermsV4::from_core(core)?;
    if terms.fields().network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the terms are for {}; pass --network {0} to act on them",
                crate::terms_file::network_name(terms.fields().network)
            ),
        ));
    }
    Ok(terms)
}

/// The value cap of v4: the trade's declared value against `IMPULSE_MAX_VALUE` or the default
/// cap. Template v4 has no override: the flag that lifts the cap is refused (`ZK_H_CAP_OVERRIDE`).
pub(crate) fn cap_policy(ctx: &Ctx, cap: &CapArgs) -> Result<CapPolicy, CliError> {
    if cap.i_accept_the_risk {
        return Err(CliError::new(
            "ZK_H_CAP_OVERRIDE",
            "template v4 never lifts the value cap: lower the trade to the cap",
        ));
    }
    CapPolicy::new(ctx.env.max_value, false)
}

/// The cap applies where new value enters: funding (and the other commands that are not a spend
/// of a funded vault). Above the cap it refuses.
fn cap_line(ctx: &Ctx, cap: &CapArgs, terms: &ValidatedTermsV4) -> Result<String, CliError> {
    cap_policy(ctx, cap)?.check(terms.fields(), cap.kas_equivalent)
}

/// The cap check of a spend of an already funded vault (settle, refund). Template v4 has no cap
/// override, so refusing here could lock funds that anyone can put at the P2SH address, or that
/// were funded before `IMPULSE_MAX_VALUE` was lowered. Above the cap the check does not refuse:
/// the note carries `warning:` and the output line says so. `funding` keeps the refusal.
pub(crate) fn cap_check(
    policy: &CapPolicy,
    t: &impulse_core::terms::Terms,
    kas_equivalent: Option<u64>,
    funding: bool,
    notes: &mut dyn Write,
) -> Result<String, CliError> {
    match policy.check(t, kas_equivalent) {
        Err(e) if !funding && e.code() == "CLI_VALUE_CAP_EXCEEDED" => {
            writeln!(
                notes,
                "warning: {}; this spends a vault that is already funded, so it is not blocked",
                e.detail().split("; pass").next().unwrap_or(e.detail())
            )
            .map_err(|e| CliError::new("CLI_FILE_WRITE", format!("stderr: {e}")))?;
            Ok("value cap: above the cap, not blocked (this spends a funded vault)".into())
        }
        r => r,
    }
}

fn spend_cap_line(
    ctx: &Ctx,
    cap: &CapArgs,
    terms: &ValidatedTermsV4,
    notes: &mut dyn Write,
) -> Result<String, CliError> {
    let policy = cap_policy(ctx, cap)?;
    cap_check(&policy, terms.fields(), cap.kas_equivalent, false, notes)
}

fn not_found(what: String) -> CliError {
    CliError::new("CLI_UTXO_NOT_FOUND", what)
}

fn no_vault(leg: LegIndex) -> CliError {
    CliError::new(
        "TEMPLATE_NO_VAULT",
        format!(
            "the {} leg has no vault: external cash has no vault (no builder recovers a stray deposit there, owner decision D14)",
            leg_name(leg)
        ),
    )
}

/// The lines every command that shows terms v4 prints first: the three fixed texts of 22.11 and
/// the decoded terms.
fn terms_lines(terms: &ValidatedTermsV4, now_daa: u64) -> Vec<String> {
    let mut lines = vec![
        DISCLOSURE_LINE.to_string(),
        LOSS_LINE.to_string(),
        SOUNDNESS_LINE.to_string(),
    ];
    lines.extend(summary::summary(
        &terms.terms_hash(),
        terms.fields(),
        now_daa,
    ));
    lines
}

/// Both legs' vaults of terms that exist; a leg without one (external cash) is None.
fn existing_vaults(terms: &ValidatedTermsV4) -> Result<[Option<VaultV4>; 2], CliError> {
    let mut out = [None, None];
    for leg in LegIndex::ALL {
        match zkh::existing_vault(terms, leg) {
            Ok(v) => out[usize::from(leg.index())] = Some(v),
            Err(e) if leg == LegIndex::Cash && e.code() == "TEMPLATE_NO_VAULT" => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

fn fundable_vaults(
    terms: &ValidatedTermsV4,
    creation: &CreationContext,
) -> Result<[Option<VaultV4>; 2], CliError> {
    let mut out = [None, None];
    for leg in LegIndex::ALL {
        match zkh::fundable_vault(terms, leg, creation) {
            Ok(v) => out[usize::from(leg.index())] = Some(v),
            Err(e) if leg == LegIndex::Cash && e.code() == "TEMPLATE_NO_VAULT" => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

fn vault_line(network: Network, leg: LegIndex, vault: &VaultV4) -> String {
    format!("{} vault: {}", leg_name(leg), vault.address(network))
}

/// The transaction lines of an IPST, less the `masses:` line (v4 user text states no mass
/// figure) and with a line per vault input saying whether it carries a proof.
pub(crate) fn tx_lines(ipst: &IpstV4, kind: IpstKind, token_change: Option<u64>) -> Vec<String> {
    let mut lines: Vec<String> = txview::lines(ipst.as_v1(), kind.into(), token_change)
        .into_iter()
        .filter(|l| !l.starts_with("masses: "))
        .collect();
    if let Ok(proofs) = ipst.proofs() {
        for (index, proof) in proofs {
            lines.push(format!(
                "proof: input {index} {}",
                if proof.is_some() {
                    "carries a proof"
                } else {
                    "has no proof yet (a plan for the prover: impulse zk witness)"
                }
            ));
        }
    }
    lines
}

fn finish(
    out: &mut dyn Write,
    mut lines: Vec<String>,
    ipst: &IpstV4,
    kind: IpstKind,
    token_change: Option<u64>,
    path: &Path,
) -> Result<(), CliError> {
    write_new(path, &ipst.to_json())?;
    lines.extend(tx_lines(ipst, kind, token_change));
    lines.push(format!("wrote: {}", path.display()));
    print(out, &lines)
}

struct Pay {
    from: Address,
    change: ScriptPublicKey,
    fee: Option<u64>,
}

fn pay(args: &PayArgs, network: Network) -> Result<Pay, CliError> {
    let from = parse_pay_from(&args.pay_from, network)?;
    let change = match &args.change {
        Some(c) => parse_change(c, network)?,
        None => address_script(&from),
    };
    Ok(Pay {
        from,
        change,
        fee: args.fee,
    })
}

fn owner(identifier_type: IdentifierType, identifier: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type,
        identifier,
    }
}

/// Builds with the first one, two, ... fee candidates until the builder accepts, and with the
/// minimum relay fee unless `fee` is given.
fn build_with_fee(
    candidates: &[Utxo],
    fee: Option<u64>,
    change: &ScriptPublicKey,
    build: impl Fn(&FeePayment) -> Result<IpstV4, ZkhError>,
) -> Result<IpstV4, CliError> {
    let mut last = None;
    for k in 1..=candidates.len() {
        let mut payment = FeePayment {
            inputs: candidates[..k].to_vec(),
            fee: fee.unwrap_or_else(|| min_relay_fee(0)),
            change: change.clone(),
        };
        let mut result = build(&payment);
        if fee.is_none() {
            if let Err(e) = &result {
                if let (Some(minimum), "TX_FEE_TOO_LOW") = (e.min_fee(), e.code()) {
                    payment.fee = minimum;
                    result = build(&payment);
                }
            }
        }
        match result {
            Ok(ipst) => return Ok(ipst),
            Err(e) if matches!(e.code(), "TX_INSUFFICIENT_FUNDS" | "TX_BELOW_MIN_KAS") => {
                last = Some(e)
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last.map_or_else(
        || CliError::new("CLI_UTXO_NOT_FOUND", "no fee input"),
        CliError::from,
    ))
}

/// The UTXO at a vault without a covenant ID holding the most KAS.
fn authorizer(
    node: &dyn Node,
    vault: &VaultV4,
    network: Network,
    what: &str,
) -> Result<Utxo, CliError> {
    let mut all = utxos_with(node, &vault.script_public_key(), None, network)?;
    all.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
    all.into_iter()
        .next()
        .ok_or_else(|| not_found(format!("no {what} at the vault: is the leg funded?")))
}

/// The escrowed token of a vault: owned by the vault's script hash, `amount`, not a minter.
fn escrow(
    node: &dyn Node,
    vault: &VaultV4,
    template: &Kcc20Template,
    token: &Kcc20Token,
    amount: u64,
    network: Network,
    what: &str,
) -> Result<Utxo, CliError> {
    let state = Kcc20State::new(
        owner(IdentifierType::ScriptHash, vault.script_hash()),
        amount,
    );
    utxos_with(
        node,
        &template.script_public_key(&state)?,
        Some(token.covenant_id),
        network,
    )?
    .into_iter()
    .next()
    .ok_or_else(|| {
        not_found(format!(
            "no {what} of {amount} token units owned by the vault: is the leg funded?"
        ))
    })
}

// =============================================================================================
// terms new-hashed, address, verify
// =============================================================================================

/// Writes a file that holds the blind: new, mode 0600 on unix.
fn write_new_private(path: &Path, text: &str) -> Result<(), CliError> {
    crate::zk_cmd::write_new_secret(path, text)
}

/// `impulse zk terms new-hashed`: checks a draft, draws the blind from the operating system's
/// random number generator, writes the terms v4 file and reads it back before printing anything
/// about the vaults (`ZK_H_TERMS_FILE`).
pub(crate) fn terms_new_hashed(
    ctx: &Ctx,
    a: ZkTermsNewHashedArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let mut draft = parse_draft(&read_text(&a.draft)?)?;
    if draft.version != terms_core::codec::TERMS_VERSION {
        return Err(CliError::new(
            "ZK_H_TERMS_VERSION",
            format!(
                "the draft is version {}, a terms v4 draft is version 4",
                draft.version
            ),
        ));
    }
    draft.version = impulse_core::terms::TERMS_VERSION;
    let mut blind = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut blind);
    let terms = ValidatedTermsV4::from_draft(&draft, blind)?;
    let creation = creation(ctx, &a.creation)?;
    terms.validate_creation(&creation)?;
    check_kas_minimum(terms.fields())?;
    let vaults = fundable_vaults(&terms, &creation)?;
    let you = summary::check_party(terms.fields(), &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&terms, creation.creation_daa);
    lines.push(you);
    lines.extend(crate::trade::template_warnings(terms.fields()));
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    let text = format!("{}\n", hex(terms.canonical()));
    write_new_private(&a.out, &text)?;
    let back = read_terms_v4(ctx, &a.out)?;
    if back != terms {
        return Err(CliError::new(
            "ZK_H_TERMS_FILE",
            format!(
                "{} did not read back to the terms written; do not fund",
                a.out.display()
            ),
        ));
    }
    for leg in LegIndex::ALL {
        lines.push(match &vaults[usize::from(leg.index())] {
            Some(v) => vault_line(ctx.network, leg, v),
            None => format!(
                "{}: no vault: external cash settles off chain",
                leg_name(leg)
            ),
        });
    }
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

/// `impulse zk address` for a terms v4 file.
pub(crate) fn address(
    ctx: &Ctx,
    a: crate::zk_cmd::AddressArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let terms = read_terms_v4(ctx, &a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    terms.validate_creation(&creation)?;
    check_kas_minimum(terms.fields())?;
    check_pinned(terms.fields())?;
    let vaults = fundable_vaults(&terms, &creation)?;
    let you = summary::check_party(terms.fields(), &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&terms, creation.creation_daa);
    lines.push(you);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    for leg in LegIndex::ALL {
        match &vaults[usize::from(leg.index())] {
            Some(v) => {
                lines.push(vault_line(ctx.network, leg, v));
                lines.push(format!("  commitment: {}", hex(&v.commit())));
                lines.push(format!(
                    "  funded by: the {}",
                    crate::cli::funder(leg).name()
                ));
                lines.push(format!(
                    "  escrowed token owner: script_hash {}",
                    hex(&v.script_hash())
                ));
            }
            None => lines.push(format!(
                "{}: no vault: external cash settles off chain",
                leg_name(leg)
            )),
        }
    }
    print(out, &lines)
}

/// `impulse zk verify` for a terms v4 file: the terms file and both vault addresses are required,
/// and each offered address must be the v4 vault of these terms for its leg
/// (`ZK_H_VERIFY_ADDRESS_MISMATCH`).
pub(crate) fn verify(
    ctx: &Ctx,
    a: crate::zk_cmd::VerifyArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    if a.manifest.is_some() || a.path.is_some() {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "--manifest and --path are for terms v3; terms v4 have no list",
        ));
    }
    let terms = read_terms_v4(ctx, &a.terms)?;
    let creation = creation(ctx, &a.creation)?;
    terms.validate_creation(&creation)?;
    check_kas_minimum(terms.fields())?;
    check_pinned(terms.fields())?;
    let vaults = existing_vaults(&terms)?;
    let offered = [Some(a.asset_address.as_str()), a.cash_address.as_deref()];
    let mut lines = terms_lines(&terms, creation.creation_daa);
    for leg in LegIndex::ALL {
        let i = usize::from(leg.index());
        match (&vaults[i], offered[i]) {
            (Some(v), Some(given)) => {
                let expected = v.address(ctx.network);
                if given != expected {
                    return Err(CliError::new(
                        "ZK_H_VERIFY_ADDRESS_MISMATCH",
                        format!(
                            "the offered {} address {given} is not the v4 vault of these terms for that leg ({expected})",
                            leg_name(leg)
                        ),
                    ));
                }
                lines.push(format!("{} vault: {expected} (verified)", leg_name(leg)));
            }
            (Some(_), None) => {
                return Err(CliError::new(
                    "ZK_H_VERIFY_ADDRESS_MISMATCH",
                    format!(
                        "no {} address offered: verify needs both vault addresses",
                        leg_name(leg)
                    ),
                ))
            }
            (None, Some(_)) => {
                return Err(CliError::new(
                    "ZK_H_VERIFY_ADDRESS_MISMATCH",
                    "an address was offered for external cash, which has no vault",
                ))
            }
            (None, None) => lines.push(format!(
                "{}: no vault: external cash settles off chain",
                leg_name(leg)
            )),
        }
    }
    let authority = terms
        .fields()
        .authority_key
        .map_or_else(String::new, |k| hex(&k));
    lines.push(format!("authority_key: {authority}"));
    lines.push(summary::check_party(
        terms.fields(),
        &party(ctx.network, &a.party)?,
    )?);
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    lines.push(format!("ok: terms {}", hex(&terms.terms_hash())));
    print(out, &lines)
}

// =============================================================================================
// fund build, settle build, refund build, witness
// =============================================================================================

/// `impulse zk fund build` for a terms v4 file.
pub(crate) fn fund_build(
    ctx: &Ctx,
    a: ZkFundBuildArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v4(ctx, &a.terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let creation = CreationContext::new(ctx.network, daa);
    terms.validate_creation(&creation)?;
    let t = terms.fields();
    check_kas_minimum(t)?;
    let vaults = fundable_vaults(&terms, &creation)?;
    let you = summary::check_party(t, &party(ctx.network, &a.party)?)?;
    let mut lines = terms_lines(&terms, daa);
    lines.push(you);
    let leg: LegIndex = a.leg.into();
    let by = crate::cli::funder(leg);
    if by != a.party.role {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "the {} leg is funded by the {}; you are the {}",
                leg_name(leg),
                by.name(),
                a.party.role.name()
            ),
        ));
    }
    let vault = vaults[usize::from(leg.index())]
        .as_ref()
        .ok_or_else(|| no_vault(leg))?;
    check_pinned(t)?;
    lines.push(cap_line(ctx, &a.cap, &terms)?);
    let pay = pay(&a.pay, ctx.network)?;
    let my_key = crate::cli::hash_arg("my-key", &a.party.my_key)?;
    let mine = p2pk_address(&my_key, ctx.network);
    if pay.from != mine {
        return Err(CliError::new(
            "CLI_FUND_NOT_YOUR_LEG",
            format!(
                "--pay-from {} is not the P2PK address of --my-key ({mine}): a funding is signed by its depositor only, so it is paid from your own address",
                pay.from
            ),
        ));
    }
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let templates = Templates::read(&a.templates)?;
    let (ipst, kind, token_change) = match leg_terms.kind {
        LegKind::Kcc20(token) => {
            let template = templates.of(leg, &token)?;
            if a.token.is_empty() {
                return Err(not_found(format!(
                    "a KCC-20 leg is funded with your token UTXOs: pass --token <txid>:<index>:<amount> (held by {})",
                    hex(&my_key)
                )));
            }
            let mut tokens = Vec::with_capacity(a.token.len());
            for text in &a.token {
                let (outpoint, amount) = parse_token("--token", text)?;
                let state = Kcc20State::new(owner(IdentifierType::PubKey, my_key), amount);
                let utxo = utxo_at(
                    node.as_ref(),
                    &outpoint,
                    &template.script_public_key(&state)?,
                    Some(token.covenant_id),
                    ctx.network,
                    "--token",
                )?;
                tokens.push(TokenUtxo { utxo, state });
            }
            let held: u64 = tokens
                .iter()
                .fold(0u64, |s, t| s.saturating_add(t.state.amount));
            let deposit = Kcc20Deposit {
                tokens,
                carrier: a.carrier.unwrap_or(MIN_KCC20_OUTPUT),
                authorizer: a.authorizer.unwrap_or(MIN_KAS_OUTPUT),
            };
            let exclude: Vec<TransactionOutpoint> =
                deposit.tokens.iter().map(|t| t.utxo.outpoint).collect();
            let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &exclude)?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                zkh::fund_kcc20(&terms, vault, leg, template, &deposit, p, daa)
            })?;
            let change = held.checked_sub(leg_terms.amount).filter(|c| *c > 0);
            (ipst, IpstKind::FundKcc20(leg), change)
        }
        LegKind::Kas => {
            if !a.token.is_empty() || a.carrier.is_some() || a.authorizer.is_some() {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS cash leg is funded with KAS alone: --token, --carrier and --authorizer are for KCC-20 legs",
                ));
            }
            let candidates = fee_candidates(node.as_ref(), &pay.from, ctx.network, &[])?;
            let ipst = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                zkh::fund_kas(&terms, vault, leg, p, daa)
            })?;
            (ipst, IpstKind::FundKas, None)
        }
        LegKind::External => return Err(no_vault(leg)),
    };
    finish(out, lines, &ipst, kind, token_change, &a.out)
}

/// The proof file `impulse-zk-prove-terms` writes: the proof, the journal it commits to and the
/// image ID of the guest that made it.
struct ProofFileV4 {
    proof: ProofV4,
    journal: Vec<u8>,
    image_id: [u8; 32],
}

fn read_proof_file(path: &Path) -> Result<ProofFileV4, CliError> {
    let malformed =
        |reason: String| CliError::new("ZK_H_PROOF_MALFORMED", format!("proof file: {reason}"));
    let text = read_text(path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| malformed(e.to_string()))?;
    if value["format"].as_str() != Some("impulse-zk-proof/1") {
        return Err(malformed("unknown format".into()));
    }
    let field = |name: &str| -> Result<Vec<u8>, CliError> {
        let s = value[name]
            .as_str()
            .ok_or_else(|| malformed(format!("{name} is missing")))?;
        crate::json::unhex(s).ok_or_else(|| malformed(format!("{name} is not lowercase hex")))
    };
    let proof = ProofV4::parse(&field("proof")?)?;
    let journal = field("journal")?;
    let journal_hash: [u8; 32] = field("journal_hash")?
        .try_into()
        .map_err(|_| malformed("journal_hash is not 32 bytes".into()))?;
    if journal_hash != terms_core::hashes::sha256(&journal) {
        return Err(malformed(
            "journal_hash is not SHA-256 of the journal".into(),
        ));
    }
    let image_id: [u8; 32] = field("image_id")?
        .try_into()
        .map_err(|_| malformed("image_id is not 32 bytes".into()))?;
    Ok(ProofFileV4 {
        proof,
        journal,
        image_id,
    })
}

/// Checks a proof file against the plan: its journal is the one the vault input at `input`
/// builds, and it was made by the guest the template pins.
fn checked_proof(plan: &IpstV4, input: usize, path: &Path) -> Result<ProofV4, CliError> {
    let file = read_proof_file(path)?;
    let witnesses = zkh::witnesses(plan)?;
    let (_, _, witness) = witnesses
        .iter()
        .find(|(i, _, _)| *i == input)
        .ok_or_else(|| {
            CliError::new(
                "ZK_H_SHAPE",
                format!("the transaction has no vault input {input}"),
            )
        })?;
    if file.journal != witness.journal {
        return Err(CliError::new(
            "ZK_H_PROOF_INVALID",
            format!(
                "the proof file's journal is not the one vault input {input} builds: it was made for another transaction, vault or lock time (impulse zk witness writes the witness to prove)"
            ),
        ));
    }
    let pinned = zkh::check()?.image_id();
    if file.image_id != pinned {
        return Err(CliError::new(
            "ZK_IMAGE_ID_MISMATCH",
            format!(
                "the proof file's image id {} is not the one template v4 pins ({})",
                hex(&file.image_id),
                hex(&pinned)
            ),
        ));
    }
    Ok(file.proof)
}

/// `impulse zk settle build` for a terms v4 file. Without proof files the result is a plan for
/// the prover; with them (`--proof` the asset vault's, `--proof-cash` the cash vault's) it is the
/// settle that carries them.
pub(crate) fn settle_build(
    ctx: &Ctx,
    a: ZkSettleBuildArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v4(ctx, &a.terms)?;
    let vaults = existing_vaults(&terms)?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let t = terms.fields();
    let mut lines = terms_lines(&terms, daa);
    lines.push(spend_cap_line(ctx, &a.cap, &terms, notes)?);
    let pay = pay(&a.pay, ctx.network)?;
    let templates = Templates::read(&a.templates)?;
    let net = ctx.network;
    let LegKind::Kcc20(asset) = t.asset_leg.kind else {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "the asset leg is not a KCC-20 token",
        ));
    };
    let asset_template = templates.of(LegIndex::Asset, &asset)?;
    let asset_vault = vaults[0]
        .as_ref()
        .ok_or_else(|| no_vault(LegIndex::Asset))?;
    let asset_authorizer = authorizer(node.as_ref(), asset_vault, net, "asset authorizer")?;
    let asset_escrow = escrow(
        node.as_ref(),
        asset_vault,
        asset_template,
        &asset,
        t.asset_leg.amount,
        net,
        "asset escrow",
    )?;
    let mut used = vec![asset_authorizer.outpoint, asset_escrow.outpoint];
    let cash = match t.cash_leg.kind {
        LegKind::Kas => {
            let cash_vault = vaults[1].as_ref().ok_or_else(|| no_vault(LegIndex::Cash))?;
            let vault = utxos_with(node.as_ref(), &cash_vault.script_public_key(), None, net)?
                .into_iter()
                .find(|u| u.entry.amount == t.cash_leg.amount)
                .ok_or_else(|| {
                    not_found(format!(
                        "no UTXO of exactly {} sompi at the cash vault: is the leg funded?",
                        t.cash_leg.amount
                    ))
                })?;
            used.push(vault.outpoint);
            SettleCash::Kas { vault }
        }
        LegKind::Kcc20(cash) => {
            let cash_template = templates.of(LegIndex::Cash, &cash)?;
            let cash_vault = vaults[1].as_ref().ok_or_else(|| no_vault(LegIndex::Cash))?;
            let authorizer = authorizer(node.as_ref(), cash_vault, net, "cash authorizer")?;
            let escrow = escrow(
                node.as_ref(),
                cash_vault,
                cash_template,
                &cash,
                t.cash_leg.amount,
                net,
                "cash escrow",
            )?;
            used.extend([authorizer.outpoint, escrow.outpoint]);
            SettleCash::Kcc20 {
                authorizer,
                escrow,
                token: cash_template,
            }
        }
        LegKind::External => SettleCash::External,
    };
    if matches!(cash, SettleCash::External) && a.proof_cash.is_some() {
        return Err(CliError::new(
            "TX_WRONG_MODE",
            "external cash has no cash vault: --proof-cash is for KAS and KCC-20 cash",
        ));
    }
    let legs = SettleLegs {
        asset_authorizer,
        asset_escrow,
        asset_token: asset_template,
        cash,
    };
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    // The plan first: the journal of each vault input does not depend on the fee inputs or the
    // proofs, so the proof files are checked against it.
    let plan = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        zkh::settle(&terms, &legs, &[None, None], p, daa)
    })?;
    let proofs = [
        a.proof
            .as_ref()
            .map(|p| checked_proof(&plan, 0, p))
            .transpose()?,
        a.proof_cash
            .as_ref()
            .map(|p| checked_proof(&plan, 1, p))
            .transpose()?,
    ];
    let ipst = if proofs.iter().any(Option::is_some) {
        build_with_fee(&candidates, pay.fee, &pay.change, |p| {
            zkh::settle(&terms, &legs, &proofs, p, daa)
        })?
    } else {
        plan
    };
    lines.push(MASS_NOTE.to_string());
    if !ipst.has_all_proofs()? {
        lines.push("a vault input has no proof yet: write its witness with impulse zk witness, prove it with impulse-zk-prove-terms, and build again with --proof (asset vault) and --proof-cash (cash vault)".to_string());
    }
    finish(out, lines, &ipst, IpstKind::Settle, None, &a.out)
}

/// `settle build` (spec section 10): in words, without figures.
const MASS_NOTE: &str = "This settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass.";

/// `impulse zk refund build` for a terms v4 file; `--proof` is the refund's proof (without it the
/// result is a plan for the prover).
pub(crate) fn refund_build(
    ctx: &Ctx,
    a: ZkRefundBuildArgs,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let terms = read_terms_v4(ctx, &a.terms)?;
    let vaults = existing_vaults(&terms)?;
    let t = terms.fields();
    let leg: LegIndex = a.leg.into();
    let vault = vaults[usize::from(leg.index())]
        .as_ref()
        .ok_or_else(|| no_vault(leg))?;
    let (node, daa) = node_now(ctx, &a.node)?;
    let mut lines = terms_lines(&terms, daa);
    lines.push(spend_cap_line(ctx, &a.cap, &terms, notes)?);
    let pay = pay(&a.pay, ctx.network)?;
    let net = ctx.network;
    let vault_utxo = match &a.vault_utxo {
        Some(text) => {
            let outpoint = parse_outpoint("--vault-utxo", text)?;
            utxo_at(
                node.as_ref(),
                &outpoint,
                &vault.script_public_key(),
                None,
                net,
                "--vault-utxo",
            )?
        }
        None => {
            let mut all = utxos_with(node.as_ref(), &vault.script_public_key(), None, net)?;
            match all.len() {
                0 => return Err(not_found(format!("no UTXO at the {} vault", leg_name(leg)))),
                1 => all.remove(0),
                _ => {
                    return Err(CliError::new(
                        "CLI_UTXO_AMBIGUOUS",
                        format!(
                            "the {} vault holds {} UTXOs; choose one with --vault-utxo: {}",
                            leg_name(leg),
                            all.len(),
                            all.iter()
                                .map(|u| format!(
                                    "{} ({} sompi)",
                                    crate::funds::outpoint_text(&u.outpoint),
                                    u.entry.amount
                                ))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ))
                }
            }
        }
    };
    let leg_terms = match leg {
        LegIndex::Asset => &t.asset_leg,
        LegIndex::Cash => &t.cash_leg,
    };
    let templates = Templates::read(&a.templates)?;
    let escrowed = match leg_terms.kind {
        LegKind::Kas => {
            if a.without_token || a.token_amount.is_some() || a.token_minter {
                return Err(CliError::new(
                    "TX_WRONG_MODE",
                    "a KAS cash leg has no escrowed token: --without-token, --token-amount and --token-minter are for KCC-20 legs",
                ));
            }
            None
        }
        LegKind::Kcc20(_) if a.without_token => None,
        LegKind::Kcc20(token) => {
            let template = templates.of(leg, &token)?;
            let amount = a.token_amount.unwrap_or(leg_terms.amount);
            let state = Kcc20State {
                owner: owner(IdentifierType::ScriptHash, vault.script_hash()),
                amount,
                is_minter: a.token_minter,
            };
            let utxo = utxos_with(
                node.as_ref(),
                &template.script_public_key(&state)?,
                Some(token.covenant_id),
                net,
            )?
            .into_iter()
            .next()
            .ok_or_else(|| {
                not_found(format!(
                    "no escrowed token of {amount} units{} owned by the {} vault",
                    if a.token_minter { ", a minter," } else { "" },
                    leg_name(leg)
                ))
            })?;
            Some(RefundEscrow {
                utxo,
                amount,
                is_minter: a.token_minter,
                template,
            })
        }
        LegKind::External => return Err(no_vault(leg)),
    };
    let mut used = vec![vault_utxo.outpoint];
    used.extend(escrowed.iter().map(|e| e.utxo.outpoint));
    let signer: RefundSigner = a.signer.into();
    let candidates = fee_candidates(node.as_ref(), &pay.from, net, &used)?;
    let plan = build_with_fee(&candidates, pay.fee, &pay.change, |p| {
        zkh::refund(&terms, leg, signer, &vault_utxo, escrowed.as_ref(), None, p)
    })?;
    let ipst = match &a.proof {
        Some(path) => {
            let proof = checked_proof(&plan, 0, path)?;
            build_with_fee(&candidates, pay.fee, &pay.change, |p| {
                zkh::refund(
                    &terms,
                    leg,
                    signer,
                    &vault_utxo,
                    escrowed.as_ref(),
                    Some(&proof),
                    p,
                )
            })?
        }
        None => plan,
    };
    if a.without_token {
        lines.push(format!(
            "note: the escrowed token stays owned by the {} vault; to get it back, fund a new authorizer (any KAS) at the vault's address and refund that one with the token",
            leg_name(leg)
        ));
    }
    if !ipst.has_all_proofs()? {
        lines.push("the vault input has no proof yet: write its witness with impulse zk witness, prove it with impulse-zk-prove-terms, and build again with --proof".to_string());
    }
    let kind = IpstKind::Refund {
        leg,
        signer,
        with_token: escrowed.is_some(),
    };
    finish(out, lines, &ipst, kind, None, &a.out)
}

/// `impulse zk witness`: writes the witness file of each vault input of an IPST (a plan or a
/// document that carries proofs), the file `impulse-zk-prove-terms --witness` reads, and prints
/// the proving command for each. The witness holds the terms: it stays on the machine that
/// proves, and is not a thing to send anywhere.
pub(crate) fn witness(ctx: &Ctx, a: ZkWitnessArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let text = read_text(&a.ipst)?;
    let ipst = IpstV4::from_json(&text)?;
    if ipst.terms().fields().network != ctx.network {
        return Err(CliError::new(
            "CLI_NETWORK_MISMATCH",
            format!(
                "the IPST is for {}; pass --network {0} to act on it",
                crate::terms_file::network_name(ipst.terms().fields().network)
            ),
        ));
    }
    zkh::check_statement(&ipst)?;
    let all = zkh::witnesses(&ipst)?;
    std::fs::create_dir(&a.out_dir).map_err(|e| {
        CliError::new(
            "CLI_OUTPUT_EXISTS",
            format!(
                "cannot create {} (it must not exist): {e}",
                a.out_dir.display()
            ),
        )
    })?;
    let mut lines = Vec::new();
    for (input, leg, w) in all {
        let name = format!("witness-input{input}-leg{leg}.bin");
        let path = a.out_dir.join(&name);
        crate::zk_cmd::write_new_bytes(&path, &w.to_bytes())?;
        lines.push(format!(
            "input {input} ({} vault): journal_hash {}",
            if leg == 0 { "asset" } else { "cash" },
            hex(&terms_core::hashes::sha256(&w.journal))
        ));
        lines.push(format!(
            "impulse-zk-prove-terms --witness {} --out {}",
            path.display(),
            a.out_dir.join(format!("proof-input{input}.json")).display()
        ));
    }
    lines.push(format!("image_id: {}", hex(&zkh::check()?.image_id())));
    lines.push(
        "Each witness holds the terms. Prove on a machine you control; the terms never leave it."
            .to_string(),
    );
    print(out, &lines)
}
