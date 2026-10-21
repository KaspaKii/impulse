// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! What the builders take from the user and the node (spec/CLI.md, "Common arguments of the
//! builders"): the payer's and change addresses, outpoint arguments, the UTXOs the CLI looks up,
//! and the fee inputs and fee. Holds no key.

use crate::error::CliError;
use crate::json::{parse_dec, unhex32};
use crate::node::Node;
use crate::terms_file::network_name;
use impulse_core::address::prefix;
use impulse_core::terms::Network;
use impulse_core::tx::{min_relay_fee, FeePayment, Ipst, TxError, Utxo};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint};
use kaspa_consensus_core::Hash;

fn invalid(flag: &str, text: &str, why: &str) -> CliError {
    CliError::new("CLI_ADDRESS_INVALID", format!("{flag} {text:?}: {why}"))
}

/// A Kaspa address of `network` in canonical form.
fn parse_address(flag: &str, text: &str, network: Network) -> Result<Address, CliError> {
    let address =
        Address::try_from(text).map_err(|_| invalid(flag, text, "not a Kaspa address"))?;
    if address.to_string() != text {
        return Err(invalid(flag, text, "the address is not in canonical form"));
    }
    if address.prefix != prefix(network) {
        return Err(invalid(
            flag,
            text,
            &format!("not a {} address", network_name(network)),
        ));
    }
    let len = address.payload.len();
    let ok = match address.version {
        Version::PubKey | Version::ScriptHash => len == 32,
        Version::PubKeyECDSA => len == 33,
    };
    if !ok {
        return Err(invalid(
            flag,
            text,
            "the address payload has the wrong length",
        ));
    }
    Ok(address)
}

/// The version-0 script an address stands for.
pub fn address_script(address: &Address) -> ScriptPublicKey {
    let p = address.payload.as_slice();
    let script = match address.version {
        Version::PubKey => [&[0x20][..], p, &[0xac]].concat(),
        Version::PubKeyECDSA => [&[0x21][..], p, &[0xab]].concat(),
        Version::ScriptHash => [&[0xaa, 0x20][..], p, &[0x87]].concat(),
    };
    ScriptPublicKey::from_vec(0, script)
}

/// The address of a version-0 P2PK or P2SH script, for a UTXO lookup.
pub fn script_address(spk: &ScriptPublicKey, network: Network) -> Option<Address> {
    let s = spk.script();
    if spk.version() != 0 {
        return None;
    }
    match s {
        [0x20, key @ .., 0xac] if key.len() == 32 => {
            Some(Address::new(prefix(network), Version::PubKey, key))
        }
        [0xaa, 0x20, hash @ .., 0x87] if hash.len() == 32 => {
            Some(Address::new(prefix(network), Version::ScriptHash, hash))
        }
        _ => None,
    }
}

/// The P2PK address of an x-only key.
pub fn p2pk_address(key: &[u8; 32], network: Network) -> Address {
    Address::new(prefix(network), Version::PubKey, key)
}

/// `--pay-from`: a P2PK (Schnorr) address of the network.
pub fn parse_pay_from(text: &str, network: Network) -> Result<Address, CliError> {
    let address = parse_address("--pay-from", text, network)?;
    if address.version != Version::PubKey {
        return Err(invalid(
            "--pay-from",
            text,
            "fee inputs are P2PK (Schnorr) UTXOs: give a P2PK address",
        ));
    }
    Ok(address)
}

/// `--change`: a P2PK, P2PK-ECDSA or P2SH address of the network.
pub fn parse_change(text: &str, network: Network) -> Result<ScriptPublicKey, CliError> {
    Ok(address_script(&parse_address("--change", text, network)?))
}

fn outpoint_error(flag: &str, text: &str, form: &str) -> CliError {
    CliError::new(
        "CLI_OUTPOINT_INVALID",
        format!("{flag} {text:?}: expected {form} (64 lowercase hex digits, decimal numbers)"),
    )
}

/// `<txid>:<index>`.
pub fn parse_outpoint(flag: &str, text: &str) -> Result<TransactionOutpoint, CliError> {
    let form = "<txid>:<index>";
    let (txid, index) = text
        .split_once(':')
        .ok_or_else(|| outpoint_error(flag, text, form))?;
    let txid = unhex32(txid).ok_or_else(|| outpoint_error(flag, text, form))?;
    let index = parse_dec(index)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(|| outpoint_error(flag, text, form))?;
    Ok(TransactionOutpoint::new(Hash::from_bytes(txid), index))
}

/// `<txid>:<index>:<amount>`.
pub fn parse_token(flag: &str, text: &str) -> Result<(TransactionOutpoint, u64), CliError> {
    let form = "<txid>:<index>:<amount>";
    let (head, amount) = text
        .rsplit_once(':')
        .ok_or_else(|| outpoint_error(flag, text, form))?;
    let outpoint = parse_outpoint(flag, head).map_err(|_| outpoint_error(flag, text, form))?;
    let amount = parse_dec(amount).ok_or_else(|| outpoint_error(flag, text, form))?;
    Ok((outpoint, amount))
}

/// `<txid>:<index>` as the CLI prints it.
pub fn outpoint_text(o: &TransactionOutpoint) -> String {
    format!(
        "{}:{}",
        crate::json::hex(&o.transaction_id.as_bytes()),
        o.index
    )
}

/// The UTXOs the node reports at the address of `spk` whose scriptPublicKey is exactly `spk`
/// and whose covenant ID is `covenant`, lowest outpoint first.
pub fn utxos_with(
    node: &dyn Node,
    spk: &ScriptPublicKey,
    covenant: Option<[u8; 32]>,
    network: Network,
) -> Result<Vec<Utxo>, CliError> {
    let address = script_address(spk, network).ok_or_else(|| {
        CliError::new("CLI_UTXO_NOT_FOUND", "the script has no address to look up")
    })?;
    let mut found: Vec<Utxo> = node
        .utxos(&address)?
        .into_iter()
        .filter(|u| {
            &u.entry.script_public_key == spk
                && u.entry.covenant_id.map(|c| c.as_bytes()) == covenant
        })
        .collect();
    found.sort_by_key(|u| (u.outpoint.transaction_id.as_bytes(), u.outpoint.index));
    Ok(found)
}

/// The UTXO at `outpoint`, if the node reports it at `spk` with `covenant`.
pub fn utxo_at(
    node: &dyn Node,
    outpoint: &TransactionOutpoint,
    spk: &ScriptPublicKey,
    covenant: Option<[u8; 32]>,
    network: Network,
    what: &str,
) -> Result<Utxo, CliError> {
    utxos_with(node, spk, covenant, network)?
        .into_iter()
        .find(|u| u.outpoint == *outpoint)
        .ok_or_else(|| {
            CliError::new(
                "CLI_UTXO_NOT_FOUND",
                format!(
                    "{what} {} is not in the node's UTXO set at {}",
                    outpoint_text(outpoint),
                    script_address(spk, network).map_or_else(String::new, |a| a.to_string())
                ),
            )
        })
}

/// The payer's fee inputs: UTXOs at `pay_from` without a covenant ID, none of them in `exclude`,
/// largest first, equal amounts by outpoint. None is `CLI_UTXO_NOT_FOUND`.
pub fn fee_candidates(
    node: &dyn Node,
    pay_from: &Address,
    network: Network,
    exclude: &[TransactionOutpoint],
) -> Result<Vec<Utxo>, CliError> {
    let mut found: Vec<Utxo> = utxos_with(node, &address_script(pay_from), None, network)?
        .into_iter()
        .filter(|u| !exclude.contains(&u.outpoint))
        .collect();
    found.sort_by(|a, b| b.entry.amount.cmp(&a.entry.amount));
    if found.is_empty() {
        return Err(CliError::new(
            "CLI_UTXO_NOT_FOUND",
            format!("no UTXO at --pay-from {pay_from} to pay the fee"),
        ));
    }
    Ok(found)
}

/// Builds with the first one, two, ... fee candidates until the builder accepts, and with the
/// minimum relay fee unless `fee` is given (spec/CLI.md, "Common arguments of the builders").
pub fn build_with_fee(
    candidates: &[Utxo],
    fee: Option<u64>,
    change: &ScriptPublicKey,
    build: impl Fn(&FeePayment) -> Result<Ipst, TxError>,
) -> Result<Ipst, CliError> {
    let mut last = None;
    for k in 1..=candidates.len() {
        let mut payment = FeePayment {
            inputs: candidates[..k].to_vec(),
            fee: fee.unwrap_or_else(|| min_relay_fee(0)),
            change: change.clone(),
        };
        let mut result = build(&payment);
        if fee.is_none() {
            if let Err(TxError::FeeTooLow { minimum, .. }) = result {
                payment.fee = minimum;
                result = build(&payment);
            }
        }
        match result {
            Ok(ipst) => return Ok(ipst),
            Err(e @ (TxError::InsufficientFunds { .. } | TxError::BelowMinKas { .. })) => {
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
