// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The testnet token helper (spec/CLI.md, "Token helper (testnet only)"): `token mint build`,
//! which builds the KIP-20 genesis of a fresh kcc20.sil token held by a public key, the token
//! genesis terms its IPST carries, the genesis check `ipst sign`, `ipst merge` and `submit` run in
//! place of the terms check, and `token list`, a read-only lookup of token UTXOs.
//!
//! Testnet only, with no flag that lifts it. Keyless: nothing here reads or holds a key; the
//! payer signs the genesis with `impulse ipst sign`, which signs through `signing::sign` only.

use crate::build_cmd::{node_now, TemplateArgs, Templates};
use crate::cancel::{document, p2pk_key, standard_change, unsigned};
use crate::cli::{hash_arg, print, Ctx};
use crate::error::CliError;
use crate::funds::{
    address_script, build_with_fee, fee_candidates, outpoint_text, p2pk_address, parse_change,
    parse_pay_from, script_address, utxos_with,
};
use crate::json::hex;
use crate::node;
use crate::summary::kas;
use crate::terms_file::read_text;
use crate::txview::{self, Kind};
use crate::value_cap::CapPolicy;
use clap::Args;
use impulse_core::locktime::INPUT_SEQUENCE;
use impulse_core::template::LegIndex;
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
    SettlementMode, Terms, TermsError, ValidatedTerms, TERMS_VERSION,
};
use impulse_core::tx::{
    min_output_value, min_relay_fee, FeePayment, Ipst, Kcc20State, Kcc20Template, TxError, Utxo,
    MIN_KCC20_OUTPUT, P2PK_BUDGET, STANDARD_MASS_CAP,
};
use impulse_core::verify::{pinned_kcc20, TemplateTriple};
use kaspa_consensus_core::constants::{MAX_SOMPI, TX_VERSION_TOCCATA};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, GenesisCovenantGroup, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry,
};
use kaspa_consensus_core::Hash;
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

/// The 24 ASCII bytes of the genesis tag, also the key of the party-key derivation.
const TAG_TEXT: &[u8; 24] = b"Impulse/token-genesis/v1";

/// The `trade_ref` of the token genesis terms: the tag text and eight zero bytes.
pub const GENESIS_TAG: [u8; 32] = {
    let mut tag = [0u8; 32];
    let mut i = 0;
    while i < TAG_TEXT.len() {
        tag[i] = TAG_TEXT[i];
        i += 1;
    }
    tag
};

/// Testnet only (spec/CLI.md, "Token helper (testnet only)"): mint a fresh KCC-20 token.
#[derive(Args, Debug)]
pub struct TokenMintBuildArgs {
    /// wRPC URL of a synced testnet node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// The token's silverc artifact: a pinned kcc20.sil build.
    #[arg(long, value_name = "FILE")]
    pub template: PathBuf,
    /// The x-only public key that will hold the whole supply, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub owner: String,
    /// P2PK address whose UTXOs pay the token output's KAS and the fee.
    #[arg(long, value_name = "ADDRESS")]
    pub pay_from: String,
    /// Token units to mint, the whole and fixed supply.
    #[arg(long, value_name = "UNITS")]
    pub amount: u64,
    /// KAS on the token output; default the minimum, 200000000.
    #[arg(long, value_name = "SOMPI")]
    pub carrier: Option<u64>,
    /// Where the change goes; default --pay-from.
    #[arg(long, value_name = "ADDRESS")]
    pub change: Option<String>,
    /// The exact fee in sompi; default the transaction's minimum relay fee.
    #[arg(long, value_name = "SOMPI")]
    pub fee: Option<u64>,
    /// The unsigned IPST to write; must not exist.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Testnet only: look up token UTXOs (spec/CLI.md, "token list").
#[derive(Args, Debug)]
pub struct TokenListArgs {
    /// wRPC URL of a synced testnet node with the UTXO index. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
    /// The token's silverc artifact: a pinned kcc20.sil build.
    #[arg(long, value_name = "FILE")]
    pub template: PathBuf,
    /// The x-only public key that holds the tokens, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub owner: String,
    /// The token's covenant ID, 64 lowercase hex digits.
    #[arg(long, value_name = "HEX")]
    pub covenant: String,
    /// The token units a UTXO holds: its script holds them, so the lookup needs them.
    #[arg(long, value_name = "UNITS")]
    pub amount: u64,
}

fn testnet_only(what: &str) -> CliError {
    CliError::new(
        "CLI_TOKEN_TESTNET_ONLY",
        format!(
            "{what}: the token helper acts on testnet only; a mainnet token comes from its issuer's own KCC-20 tooling"
        ),
    )
}

/// Refuses a mainnet command of the token helper (`CLI_TOKEN_TESTNET_ONLY`).
fn check_testnet(ctx: &Ctx, command: &str) -> Result<(), CliError> {
    if ctx.network == Network::Mainnet {
        return Err(testnet_only(command));
    }
    Ok(())
}

/// Whether terms are token genesis terms (spec/CLI.md, "The token genesis terms"): the genesis
/// tag as `trade_ref`, the two party keys nobody holds, Direct, expiry DAA 1. Whoever drafts a
/// trade chooses its `trade_ref`, so the tag alone never decides: a party to a trade holds its
/// own key, which is neither of the two.
pub(crate) fn is_genesis_terms(t: &Terms) -> bool {
    t.trade_ref == GENESIS_TAG
        && t.seller_key == party_key("seller")
        && t.buyer_key == party_key("buyer")
        && t.settlement_mode == SettlementMode::Direct
        && t.expiry_daa == 1
}

/// Whether an IPST is a token genesis IPST: its terms are token genesis terms.
pub(crate) fn is_genesis(ipst: &Ipst) -> bool {
    is_genesis_terms(ipst.terms().terms())
}

/// Refuses a token genesis IPST whose terms name mainnet, as soon as it is read
/// (`CLI_TOKEN_TESTNET_ONLY`).
pub(crate) fn refuse_mainnet_genesis(ipst: &Ipst) -> Result<(), CliError> {
    if is_genesis(ipst) && ipst.terms().terms().network == Network::Mainnet {
        return Err(testnet_only("this IPST is a token genesis on mainnet"));
    }
    Ok(())
}

/// One of the two party keys of the genesis terms: the first BLAKE2b-256 digest, keyed with the
/// tag text, over the label and a big-endian u32 counter from 0, that is a valid x-only key.
/// Nobody knows a secret key for it.
pub(crate) fn party_key(label: &str) -> [u8; 32] {
    (0u32..)
        .find_map(|counter| {
            let digest = blake2b_simd::Params::new()
                .hash_length(32)
                .key(TAG_TEXT)
                .to_state()
                .update(label.as_bytes())
                .update(&counter.to_be_bytes())
                .finalize();
            let x: [u8; 32] = digest.as_bytes().try_into().expect("32 bytes");
            secp256k1::XOnlyPublicKey::from_slice(&x)
                .is_ok()
                .then_some(x)
        })
        .expect("about half of all 32-byte values are x-coordinates on the curve")
}

fn pubkey_owner(identifier: [u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier,
    }
}

/// The token genesis terms (spec/CLI.md, "The token genesis terms"): derived from the token
/// alone, expired on any chain, with party keys nobody holds.
pub(crate) fn genesis_terms(
    network: Network,
    covenant_id: [u8; 32],
    template: &Kcc20Template,
    owner: [u8; 32],
    amount: u64,
    carrier: u64,
) -> Result<ValidatedTerms, TermsError> {
    let (seller, buyer) = (party_key("seller"), party_key("buyer"));
    let p2pk = |key: &[u8; 32]| Destination::Kas(address_script(&p2pk_address(key, network)));
    Terms {
        version: TERMS_VERSION,
        network,
        settlement_mode: SettlementMode::Direct,
        nonce: 0,
        seller_key: seller,
        buyer_key: buyer,
        authority_key: None,
        asset_leg: Leg {
            kind: LegKind::Kcc20(Kcc20Token {
                covenant_id,
                template_hash: template.template_hash(),
                template_prefix_len: template.prefix_len() as u32,
                template_suffix_len: template.suffix_len() as u32,
            }),
            amount,
        },
        cash_leg: Leg {
            kind: LegKind::Kas,
            amount: carrier,
        },
        buyer_delivery: Destination::Kcc20(pubkey_owner(owner)),
        seller_proceeds: p2pk(&seller),
        seller_refund: Destination::Kcc20(pubkey_owner(seller)),
        buyer_refund: p2pk(&buyer),
        earliest_daa: None,
        expiry_daa: 1,
        funding_mode: FundingMode::Revocable,
        trade_ref: GENESIS_TAG,
    }
    .validate_structure()
}

/// Builds the genesis of a token (spec/CLI.md, "token mint build"): the payer's inputs, every one
/// a version-0 P2PK UTXO of input 0's key without a covenant ID; output 0 the token, `carrier`
/// sompi to the template holding {`owner`, PUBKEY, `amount`, not a minter} with the genesis
/// binding of input 0; output 1 the change. Refusals keep the builders' codes.
pub(crate) fn build(
    network: Network,
    template: &Kcc20Template,
    owner: [u8; 32],
    amount: u64,
    carrier: u64,
    fee: &FeePayment,
) -> Result<Ipst, TxError> {
    let first = fee.inputs.first().ok_or(TxError::KasInput {
        index: 0,
        reason: "a token genesis spends at least one input of the payer",
    })?;
    let key = match p2pk_key(&first.entry.script_public_key) {
        Some(k) if first.entry.covenant_id.is_none() => k,
        _ => {
            return Err(TxError::KasInput {
                index: 0,
                reason: "input 0 of a token genesis is a version-0 P2PK UTXO of the payer without a covenant ID",
            })
        }
    };
    for (index, utxo) in fee.inputs.iter().enumerate().skip(1) {
        if utxo.entry.covenant_id.is_some() || p2pk_key(&utxo.entry.script_public_key) != Some(key)
        {
            return Err(TxError::KasInput {
                index,
                reason: "every input of a token genesis is a version-0 P2PK UTXO of input 0's key without a covenant ID",
            });
        }
    }
    let mut seen = HashSet::new();
    for (index, utxo) in fee.inputs.iter().enumerate() {
        if !seen.insert(utxo.outpoint) {
            return Err(TxError::DuplicateInput { index });
        }
    }
    let mut available: u64 = 0;
    for (index, utxo) in fee.inputs.iter().enumerate() {
        let value = utxo.entry.amount;
        if value == 0 || value > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: Some(index),
                value,
            });
        }
        // Each value is at most MAX_SOMPI and so is the running total: no overflow.
        available += value;
        if available > MAX_SOMPI {
            return Err(TxError::UtxoValue {
                input: None,
                value: available,
            });
        }
    }
    if !standard_change(&fee.change) {
        return Err(TxError::NonstandardChange);
    }
    let state = Kcc20State::new(pubkey_owner(owner), amount);
    let token_script = template.script_public_key(&state)?;
    // The minimum of a token output counts its covenant binding; the binding is set below.
    let minimum = min_output_value(&TransactionOutput::with_covenant(
        carrier,
        token_script.clone(),
        Some(CovenantBinding::new(0, Hash::default())),
    ));
    if carrier < minimum {
        return Err(TxError::BelowMinKas {
            output: 0,
            value: carrier,
            minimum,
        });
    }
    let needed = carrier
        .checked_add(fee.fee)
        .ok_or(TxError::InsufficientFunds {
            available,
            needed: u64::MAX,
        })?;
    if available < needed {
        return Err(TxError::InsufficientFunds { available, needed });
    }
    let mut outputs = vec![TransactionOutput::new(carrier, token_script)];
    if available > needed {
        let change = TransactionOutput::new(available - needed, fee.change.clone());
        let minimum = min_output_value(&change);
        if change.value < minimum {
            return Err(TxError::BelowMinKas {
                output: 1,
                value: change.value,
                minimum,
            });
        }
        outputs.push(change);
    }
    let mut tx = Transaction::new(
        TX_VERSION_TOCCATA,
        fee.inputs
            .iter()
            .map(|u| {
                TransactionInput::new_with_compute_budget(
                    u.outpoint,
                    vec![],
                    INPUT_SEQUENCE,
                    P2PK_BUDGET,
                )
            })
            .collect(),
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    // KIP-20: covenant_id(input 0's outpoint, [(0, output 0)]), bound to input 0.
    tx.populate_genesis_covenants(&[GenesisCovenantGroup::new(0, vec![0])])
        .map_err(|e| TxError::Encoding {
            reason: format!("token genesis binding: {e}"),
        })?;
    tx.finalize();
    let covenant_id = tx.outputs[0]
        .covenant
        .expect("the genesis binding was set")
        .covenant_id
        .as_bytes();
    // The arguments were checked before, so the terms pass their structure checks.
    let terms =
        genesis_terms(network, covenant_id, template, owner, amount, carrier).map_err(|e| {
            TxError::Encoding {
                reason: format!("token genesis terms: {e}"),
            }
        })?;
    let entries: Vec<UtxoEntry> = fee.inputs.iter().map(|u| u.entry.clone()).collect();
    let ipst = Ipst::from_json(&document(&terms, &tx, &entries, key)?.to_string())?;
    let masses = ipst.masses();
    for (dimension, mass) in [
        ("compute", masses.compute),
        ("transient", masses.transient),
        ("storage", masses.storage),
    ] {
        if mass > STANDARD_MASS_CAP {
            return Err(TxError::Mass {
                dimension,
                mass,
                cap: STANDARD_MASS_CAP,
            });
        }
    }
    let minimum = min_relay_fee(masses.fee_mass);
    if fee.fee < minimum {
        return Err(TxError::FeeTooLow {
            fee: fee.fee,
            minimum,
        });
    }
    Ok(ipst)
}

/// The template line, for a pinned kcc20.sil build only (`CLI_TOKEN_TEMPLATE_UNPINNED`).
fn pinned_line(triple: &TemplateTriple) -> Result<String, CliError> {
    let pin = pinned_kcc20(triple).ok_or_else(|| {
        CliError::new(
            "CLI_TOKEN_TEMPLATE_UNPINNED",
            format!(
                "template {} (prefix {}, suffix {}) is not a pinned kcc20.sil build; the builders' compute budgets are measured for those only",
                hex(&triple.hash),
                triple.prefix_len,
                triple.suffix_len
            ),
        )
    })?;
    Ok(format!(
        "{}, prefix {}, suffix {}; pinned: yes, kcc20.sil (silverscript v1.0.0) with maxCovIns {} and maxCovOuts {}",
        hex(&triple.hash),
        triple.prefix_len,
        triple.suffix_len,
        pin.max_cov_ins,
        pin.max_cov_outs
    ))
}

fn template_triple(template: &Kcc20Template) -> TemplateTriple {
    TemplateTriple {
        hash: template.template_hash(),
        prefix_len: template.prefix_len() as u64,
        suffix_len: template.suffix_len() as u64,
    }
}

/// `--template`: a KCC-20 artifact of a pinned kcc20.sil build, and its template line.
fn read_pinned(path: &std::path::Path) -> Result<(Kcc20Template, String), CliError> {
    let template = Kcc20Template::from_json(&read_text(path)?)?;
    let line = pinned_line(&template_triple(&template))?;
    Ok((template, line))
}

/// `--owner`: 64 lowercase hex digits (`CLI_HEX`), a valid x-only key
/// (`CLI_TOKEN_OWNER_INVALID`).
fn owner_arg(text: &str) -> Result<[u8; 32], CliError> {
    let owner = hash_arg("owner", text)?;
    if secp256k1::XOnlyPublicKey::from_slice(&owner).is_err() {
        return Err(CliError::new(
            "CLI_TOKEN_OWNER_INVALID",
            format!(
                "--owner {text} is not a valid x-only public key (an x-coordinate on secp256k1)"
            ),
        ));
    }
    Ok(owner)
}

/// `--amount`: above 0 and at most `i64::MAX`, the range of script integers
/// (`CLI_TOKEN_AMOUNT_INVALID`).
fn amount_arg(amount: u64) -> Result<u64, CliError> {
    if amount == 0 || amount > i64::MAX as u64 {
        return Err(CliError::new(
            "CLI_TOKEN_AMOUNT_INVALID",
            format!(
                "--amount {amount}: a token amount is above 0 and at most {}, the range of script integers",
                i64::MAX
            ),
        ));
    }
    Ok(amount)
}

/// The genesis check (spec/CLI.md, "The genesis check"), in place of the terms check: testnet,
/// the pinned template the terms name, then the document is the genesis `token mint build`
/// makes from its own parts, terms included, signatures aside (`IPST_TERMS_MISMATCH`; a rebuild
/// refusal keeps its code). Returns the fee and the change output.
pub(crate) fn check(
    ipst: &Ipst,
    templates: &TemplateArgs,
) -> Result<(u64, Option<TransactionOutput>), CliError> {
    let t = ipst.terms().terms();
    if t.network != Network::Testnet {
        return Err(testnet_only("this IPST is a token genesis on mainnet"));
    }
    let mismatch = |reason| CliError::from(TxError::IpstTermsMismatch { reason });
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        return Err(mismatch(
            "the asset leg of token genesis terms is the token",
        ));
    };
    let templates = Templates::read(templates)?;
    let template = templates.of(LegIndex::Asset, &token)?;
    pinned_line(&template_triple(template))?;
    // The structure checks make buyer_delivery a KCC-20 owner (the asset leg is KCC-20). Its type,
    // and the cash leg's kind, are held to the genesis terms by the comparison below.
    let Destination::Kcc20(Kcc20Owner {
        identifier: owner, ..
    }) = t.buyer_delivery
    else {
        return Err(mismatch(
            "buyer_delivery of token genesis terms is the token's owner",
        ));
    };
    let tx = ipst.transaction();
    let inputs: Vec<Utxo> = tx
        .inputs
        .iter()
        .zip(ipst.entries())
        .map(|(input, entry)| Utxo {
            outpoint: input.previous_outpoint,
            entry: entry.clone(),
        })
        .collect();
    let change = tx.outputs.get(1).cloned();
    let fee = FeePayment {
        inputs,
        fee: ipst.fee(),
        change: change.as_ref().map_or_else(
            || ipst.entries()[0].script_public_key.clone(),
            |o| o.script_public_key.clone(),
        ),
    };
    let rebuilt = build(
        t.network,
        template,
        owner,
        t.asset_leg.amount,
        t.cash_leg.amount,
        &fee,
    )?;
    if unsigned(&rebuilt) != unsigned(ipst) {
        return Err(mismatch(
            "the document is not the token genesis token mint build makes from its own parts",
        ));
    }
    Ok((ipst.fee(), change))
}

/// `ipst sign` of a genesis: the KAS on the token output is `--carrier`, default
/// `MIN_KCC20_OUTPUT` (`CLI_TOKEN_CARRIER_MISMATCH`). Returns the carrier.
pub(crate) fn confirm_carrier(ipst: &Ipst, carrier: Option<u64>) -> Result<u64, CliError> {
    let expected = carrier.unwrap_or(MIN_KCC20_OUTPUT);
    let on_token = ipst.transaction().outputs[0].value;
    if on_token != expected {
        return Err(CliError::new(
            "CLI_TOKEN_CARRIER_MISMATCH",
            format!(
                "the genesis puts {on_token} sompi on the token output; you confirm {expected} (pass --carrier to confirm another amount)"
            ),
        ));
    }
    Ok(expected)
}

/// `ipst sign` of a genesis: no trade value; the cap holds what the signer commits.
pub(crate) fn cap_line(policy: &CapPolicy) -> String {
    match policy.limit() {
        Some(cap) => format!(
            "value cap: a token genesis is not a trade; what you commit is held to the cap of {cap} sompi"
        ),
        None => "value cap: lifted by --i-accept-the-risk".into(),
    }
}

/// The genesis summary (spec/CLI.md, "token mint build").
pub(crate) fn summary(terms: &ValidatedTerms) -> Vec<String> {
    let t = terms.terms();
    let owner = match t.buyer_delivery {
        Destination::Kcc20(o) => hex(&o.identifier),
        _ => "none".into(),
    };
    let template = match t.asset_leg.kind {
        LegKind::Kcc20(token) => {
            let triple = TemplateTriple::from(&token);
            pinned_line(&triple).unwrap_or_else(|_| {
                format!(
                    "{}, prefix {}, suffix {}; pinned: no",
                    hex(&triple.hash),
                    triple.prefix_len,
                    triple.suffix_len
                )
            })
        }
        _ => "none".into(),
    };
    vec![
        "token_genesis: testnet; this transaction creates the KCC-20 token below, its whole supply held by its owner and fixed".into(),
        format!("terms_hash: {}", hex(&terms.terms_hash())),
        format!("owner: {owner}"),
        format!("amount: {} token units", t.asset_leg.amount),
        format!("template: {template}"),
        format!(
            "carrier: {} sompi ({} KAS) on the token output",
            t.cash_leg.amount,
            kas(t.cash_leg.amount)
        ),
    ]
}

/// `impulse token mint build` (spec/CLI.md, "token mint build").
pub(crate) fn mint_build(
    ctx: &Ctx,
    a: TokenMintBuildArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    check_testnet(ctx, "token mint build")?;
    node::check_transport(&a.node, ctx.network)?;
    let (template, _) = read_pinned(&a.template)?;
    let owner = owner_arg(&a.owner)?;
    let amount = amount_arg(a.amount)?;
    let pay_from = parse_pay_from(&a.pay_from, ctx.network)?;
    let change = match &a.change {
        Some(c) => parse_change(c, ctx.network)?,
        None => address_script(&pay_from),
    };
    let carrier = a.carrier.unwrap_or(MIN_KCC20_OUTPUT);
    let (node, _) = node_now(ctx, &a.node)?;
    let candidates = fee_candidates(node.as_ref(), &pay_from, ctx.network, &[])?;
    let ipst = build_with_fee(&candidates, a.fee, &change, |p| {
        build(ctx.network, &template, owner, amount, carrier, p)
    })?;
    crate::terms_file::write_new(&a.out, &ipst.to_json())?;
    let mut lines = summary(ipst.terms());
    lines.extend(txview::lines(&ipst, Kind::Genesis, None));
    lines.push(format!("wrote: {}", a.out.display()));
    print(out, &lines)
}

/// `impulse token list` (spec/CLI.md, "token list").
pub(crate) fn list(ctx: &Ctx, a: TokenListArgs, out: &mut dyn Write) -> Result<(), CliError> {
    check_testnet(ctx, "token list")?;
    node::check_transport(&a.node, ctx.network)?;
    let (template, template_line) = read_pinned(&a.template)?;
    let owner = owner_arg(&a.owner)?;
    let amount = amount_arg(a.amount)?;
    let covenant = hash_arg("covenant", &a.covenant)?;
    let (node, _) = node_now(ctx, &a.node)?;
    let spk = template.script_public_key(&Kcc20State::new(pubkey_owner(owner), amount))?;
    let found = utxos_with(node.as_ref(), &spk, Some(covenant), ctx.network)?;
    if found.is_empty() {
        return Err(CliError::new(
            "CLI_UTXO_NOT_FOUND",
            format!(
                "no token UTXO of exactly {amount} units held by {} with covenant ID {} at {}",
                hex(&owner),
                hex(&covenant),
                script_address(&spk, ctx.network).map_or_else(String::new, |a| a.to_string())
            ),
        ));
    }
    let mut lines = vec![
        "network: testnet".to_string(),
        format!("template: {template_line}"),
        format!("owner: {}", hex(&owner)),
        format!("covenant: {}", hex(&covenant)),
    ];
    for utxo in &found {
        lines.push(format!("token: {}:{amount}", outpoint_text(&utxo.outpoint)));
        lines.push(format!("token_kas: {}", utxo.entry.amount));
    }
    print(out, &lines)
}
