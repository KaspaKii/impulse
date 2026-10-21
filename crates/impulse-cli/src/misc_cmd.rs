// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The helpers of spec/CLI.md, "Helpers": `tip`, `key show`, `token info`; and, in test builds
//! with the `offline-fake-node` feature only, the hidden `fake-node` command.

use crate::cli::{connect, print, Ctx};
use crate::error::CliError;
use crate::funds::p2pk_address;
use crate::json::hex;
use crate::node;
use crate::signing::{self, SignRequest};
use crate::terms_file::{network_name, read_text};
use clap::Args;
use impulse_core::tx::Kcc20Template;
use impulse_core::verify::{pinned_kcc20, TemplateTriple};
use std::io::Write;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct TipArgs {
    /// wRPC URL of a synced node. There is no default.
    #[arg(long, value_name = "URL")]
    pub node: String,
}

#[derive(Args, Debug)]
pub struct KeyShowArgs {
    /// Your key file. Read by the signing module only.
    #[arg(long, value_name = "FILE")]
    pub key_file: PathBuf,
}

#[derive(Args, Debug)]
pub struct TokenInfoArgs {
    /// A KCC-20 token's silverc artifact.
    #[arg(long, value_name = "FILE")]
    pub template: PathBuf,
}

pub(crate) fn tip(ctx: &Ctx, a: TipArgs, out: &mut dyn Write) -> Result<(), CliError> {
    node::check_transport(&a.node, ctx.network)?;
    let node = connect(ctx, &a.node, ctx.network)?;
    let info = node::check_node(node.as_ref(), ctx.network)?;
    let dag = node.dag_info()?;
    print(
        out,
        &[
            format!(
                "network: {} ({:?})",
                network_name(ctx.network),
                info.network_name
            ),
            "synced: yes".into(),
            format!("virtual_daa_score: {}", dag.virtual_daa),
            format!("sink: {}", hex(&dag.sink)),
        ],
    )
}

/// The digest `key show` signs to learn the key's public key: BLAKE2b-256 keyed with
/// `Impulse/key-show/v1` over nothing, which is neither a transaction sighash nor a receipt
/// digest. The signature is discarded.
fn key_show_digest() -> [u8; 32] {
    let d = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"Impulse/key-show/v1")
        .hash(&[]);
    d.as_bytes().try_into().expect("32 bytes")
}

pub(crate) fn key_show(ctx: &Ctx, a: KeyShowArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let signed = signing::sign(&SignRequest {
        key_file: &a.key_file,
        network: ctx.network,
        mainnet_explicit: ctx.mainnet_explicit,
        expected_signer: None,
        digest: key_show_digest(),
    })?;
    print(
        out,
        &[
            format!("public_key: {}", hex(&signed.signer)),
            format!("address: {}", p2pk_address(&signed.signer, ctx.network)),
        ],
    )
}

pub(crate) fn token_info(a: TokenInfoArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let template = Kcc20Template::from_json(&read_text(&a.template)?)?;
    let triple = TemplateTriple {
        hash: template.template_hash(),
        prefix_len: template.prefix_len() as u64,
        suffix_len: template.suffix_len() as u64,
    };
    let pinned = match pinned_kcc20(&triple) {
        Some(p) => format!(
            "yes, kcc20.sil (silverscript v1.0.0) with maxCovIns {} and maxCovOuts {}",
            p.max_cov_ins, p.max_cov_outs
        ),
        None => "no: not a pinned kcc20.sil build; fund build refuses it".into(),
    };
    print(
        out,
        &[
            format!("template_hash: {}", hex(&triple.hash)),
            format!("template_prefix_len: {}", triple.prefix_len),
            format!("template_suffix_len: {}", triple.suffix_len),
            format!("pinned: {pinned}"),
        ],
    )
}

#[cfg(feature = "offline-fake-node")]
pub(crate) use fake::fake_node;
#[cfg(feature = "offline-fake-node")]
pub use fake::FakeNodeCommand;

#[cfg(feature = "offline-fake-node")]
mod fake {
    use super::*;
    use crate::cli::hash_arg;
    use crate::funds::{address_script, outpoint_text};
    use crate::sim::{SimNode, SimState};
    use clap::Subcommand;
    use impulse_core::terms::{IdentifierType, Kcc20Owner};
    use impulse_core::tx::{Kcc20State, MIN_KCC20_OUTPUT};
    use kaspa_addresses::Address;

    /// Test builds only: create and fill an offline fake node state file.
    #[derive(Subcommand, Debug)]
    pub enum FakeNodeCommand {
        /// Create a state file on the command's network.
        Init {
            #[arg(long)]
            state: PathBuf,
            #[arg(long)]
            daa: u64,
            /// DAA scores added at every get_block_dag_info call.
            #[arg(long, default_value_t = 0)]
            tick: u64,
        },
        /// Give an address a UTXO.
        Fund {
            #[arg(long)]
            state: PathBuf,
            #[arg(long)]
            address: String,
            #[arg(long)]
            amount: u64,
        },
        /// Add DAA scores to the virtual DAA score, so a test can pass an expiry without waiting.
        Advance {
            #[arg(long)]
            state: PathBuf,
            #[arg(long)]
            daa: u64,
        },
        /// Give a public key a KCC-20 token UTXO.
        Token {
            #[arg(long)]
            state: PathBuf,
            #[arg(long)]
            template: PathBuf,
            #[arg(long)]
            covenant_id: String,
            #[arg(long)]
            owner: String,
            #[arg(long)]
            amount: u64,
            #[arg(long, default_value_t = MIN_KCC20_OUTPUT)]
            kas: u64,
        },
    }

    pub(crate) fn fake_node(
        ctx: &Ctx,
        c: FakeNodeCommand,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        match c {
            FakeNodeCommand::Init { state, daa, tick } => {
                SimNode::create(&state, SimState::new(ctx.network, daa, tick))?;
                print(out, &[format!("state: {}", state.display())])
            }
            FakeNodeCommand::Fund {
                state,
                address,
                amount,
            } => {
                let node = SimNode::open(&state)?;
                let address = Address::try_from(address.as_str()).map_err(|e| {
                    CliError::new("CLI_ADDRESS_INVALID", format!("{address:?}: {e}"))
                })?;
                let o = node
                    .state
                    .borrow_mut()
                    .add_utxo(address_script(&address), amount, None);
                node.save()?;
                print(out, &[format!("utxo: {}:{amount}", outpoint_text(&o))])
            }
            FakeNodeCommand::Advance { state, daa } => {
                let node = SimNode::open(&state)?;
                let now = {
                    let mut s = node.state.borrow_mut();
                    s.virtual_daa = s.virtual_daa.saturating_add(daa);
                    s.virtual_daa
                };
                node.save()?;
                print(out, &[format!("daa: {now}")])
            }
            FakeNodeCommand::Token {
                state,
                template,
                covenant_id,
                owner,
                amount,
                kas,
            } => {
                let node = SimNode::open(&state)?;
                let template = Kcc20Template::from_json(&read_text(&template)?)?;
                let owner = Kcc20Owner {
                    identifier_type: IdentifierType::PubKey,
                    identifier: hash_arg("owner", &owner)?,
                };
                let spk = template.script_public_key(&Kcc20State::new(owner, amount))?;
                let covenant = hash_arg("covenant-id", &covenant_id)?;
                let o = node.state.borrow_mut().add_utxo(spk, kas, Some(covenant));
                node.save()?;
                print(out, &[format!("token: {}:{amount}", outpoint_text(&o))])
            }
        }
    }
}
