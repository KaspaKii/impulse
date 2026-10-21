// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! What a signer reads before signing (I11 phase 2): every input and output of an IPST with its
//! amount, scriptPublicKey and address, what each is as far as the terms say, the fee, the lock
//! time and when the transaction becomes final, and the masses. Nothing is shown for a document
//! the builders would not make: [`review`] runs `Ipst::verify_against_terms` first, with the value
//! cap, so a document that does not match its terms, or is above the cap, has no review.
//!
//! Round 2 added what a signer must also see: the payer cost beyond the fee (the top-up of
//! under-funded pass-through outputs), the party each signature is for, a note for the authority's
//! signature, and which outputs pay a key that lives only in a wallet of the page (`held`), where
//! nothing in the page can spend them.
//!
//! The labels are information on top of that check, not part of it. A label names what an
//! input or output is by matching its scriptPublicKey against the ones the terms determine: the
//! four destinations, the parties' keys, the vaults and the escrowed tokens. Matching is by exact
//! scriptPublicKey (and, for tokens, the exact state), so an output that pays the right amount to
//! some other address is "not named by the terms".

use crate::error::Failure;
use crate::forms;
use crate::funding::{approx_duration, destination_text, kas};
use crate::json::{hex, network_name};
use crate::ops;
use crate::payer;
use impulse_core::address;
use impulse_core::template::{LegIndex, Vault};
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, LegKind, Network, ValidatedTerms,
};
use impulse_core::tx::{Ipst, IpstKind, Kcc20State, Kcc20Template, RefundSigner};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde_json::{json, Value};

/// The Kaspa address of a version 0 P2PK, P2PK-ECDSA or P2SH scriptPublicKey of `network`.
pub(crate) fn address_of(network: Network, spk: &ScriptPublicKey) -> Option<String> {
    if spk.version() != 0 {
        return None;
    }
    let addr = |version, payload: &[u8]| {
        Some(Address::new(address::prefix(network), version, payload).to_string())
    };
    match spk.script() {
        [0x20, key @ .., 0xac] if key.len() == 32 => addr(Version::PubKey, key),
        [0x21, key @ .., 0xab] if key.len() == 33 => addr(Version::PubKeyECDSA, key),
        [0xaa, 0x20, hash @ .., 0x87] if hash.len() == 32 => addr(Version::ScriptHash, hash),
        _ => None,
    }
}

/// A scriptPublicKey the terms determine, and what to call it.
struct Known {
    spk: ScriptPublicKey,
    label: String,
}

/// The version 0 P2PK scriptPublicKey of an x-only key.
pub(crate) fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, [&[0x20][..], key, &[0xac]].concat())
}

pub(crate) fn token_spk(
    template: &Kcc20Template,
    owner: Kcc20Owner,
    amount: u64,
) -> Option<ScriptPublicKey> {
    template
        .script_public_key(&Kcc20State::new(owner, amount))
        .ok()
}

/// The scriptPublicKeys both an input and an output can have: the parties' keys, the vaults, and
/// the tokens escrowed in them.
fn common(vt: &ValidatedTerms, asset: &Kcc20Template, cash: Option<&Kcc20Template>) -> Vec<Known> {
    let t = vt.terms();
    let mut out = Vec::new();
    let mut push = |spk: Option<ScriptPublicKey>, label: String| {
        if let Some(spk) = spk {
            out.push(Known { spk, label });
        }
    };
    push(Some(p2pk(&t.seller_key)), "the seller's key (P2PK)".into());
    push(Some(p2pk(&t.buyer_key)), "the buyer's key (P2PK)".into());
    if let Some(authority) = t.authority_key {
        push(Some(p2pk(&authority)), "the authority's key (P2PK)".into());
    }
    for (leg, name, leg_terms, template) in [
        (LegIndex::Asset, "asset", &t.asset_leg, Some(asset)),
        (LegIndex::Cash, "cash", &t.cash_leg, cash),
    ] {
        let Ok(vault) = Vault::instantiate_existing(vt, leg) else {
            continue;
        };
        push(Some(vault.script_public_key()), format!("the {name} vault"));
        if matches!(leg_terms.kind, LegKind::Kcc20(_)) {
            let owner = Kcc20Owner {
                identifier_type: IdentifierType::ScriptHash,
                identifier: vault.script_hash(),
            };
            push(
                template.and_then(|tpl| token_spk(tpl, owner, leg_terms.amount)),
                format!("the {name} token escrowed in the {name} vault"),
            );
        }
    }
    out
}

/// What an output can be: one of the four destinations (a KCC-20 destination is the token of its
/// leg in that owner's state), or something `common` names.
fn known_outputs(
    vt: &ValidatedTerms,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
) -> Vec<Known> {
    let t = vt.terms();
    let mut out = Vec::new();
    let destinations: [(&str, &Destination, bool); 4] = [
        (
            "buyer_delivery (the asset arrives here)",
            &t.buyer_delivery,
            true,
        ),
        (
            "seller_proceeds (the cash arrives here)",
            &t.seller_proceeds,
            false,
        ),
        (
            "seller_refund (the asset returns here)",
            &t.seller_refund,
            true,
        ),
        (
            "buyer_refund (the cash returns here)",
            &t.buyer_refund,
            false,
        ),
    ];
    for (label, destination, is_asset) in destinations {
        match destination {
            Destination::Kas(spk) => out.push(Known {
                spk: spk.clone(),
                label: label.to_string(),
            }),
            Destination::Kcc20(owner) => {
                let (template, leg) = if is_asset {
                    (Some(asset), &t.asset_leg)
                } else {
                    (cash, &t.cash_leg)
                };
                if matches!(leg.kind, LegKind::Kcc20(_)) {
                    if let Some(spk) = template.and_then(|tpl| token_spk(tpl, *owner, leg.amount)) {
                        out.push(Known {
                            spk,
                            label: format!("{label}, as a KCC-20 token"),
                        });
                    }
                }
            }
            Destination::OffChain => {}
        }
    }
    out.extend(common(vt, asset, cash));
    out
}

/// What an input can be: a token a party holds in its own key (a Direct trade spends these), or
/// something `common` names.
fn known_inputs(
    vt: &ValidatedTerms,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
) -> Vec<Known> {
    let t = vt.terms();
    let mut out = Vec::new();
    for (who, key) in [("seller", t.seller_key), ("buyer", t.buyer_key)] {
        let owner = Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: key,
        };
        if matches!(t.asset_leg.kind, LegKind::Kcc20(_)) {
            if let Some(spk) = token_spk(asset, owner, t.asset_leg.amount) {
                out.push(Known {
                    spk,
                    label: format!("the {who}'s asset token (KCC-20, owner the {who}'s key)"),
                });
            }
        }
        if matches!(t.cash_leg.kind, LegKind::Kcc20(_)) {
            if let Some(spk) = cash.and_then(|tpl| token_spk(tpl, owner, t.cash_leg.amount)) {
                out.push(Known {
                    spk,
                    label: format!("the {who}'s cash token (KCC-20, owner the {who}'s key)"),
                });
            }
        }
    }
    out.extend(common(vt, asset, cash));
    out
}

fn label_of(known: &[Known], spk: &ScriptPublicKey) -> String {
    let names: Vec<&str> = known
        .iter()
        .filter(|k| &k.spk == spk)
        .map(|k| k.label.as_str())
        .collect();
    if names.is_empty() {
        "not named by the terms".into()
    } else {
        names.join("; or ")
    }
}

/// The label of an input: what the terms name, else a plain P2PK input is a fee input.
fn input_label(known: &[Known], spk: &ScriptPublicKey, signer: Option<[u8; 32]>) -> String {
    let named = label_of(known, spk);
    match signer {
        Some(key) if named.starts_with("not named") => {
            format!("a fee input (P2PK of the key {})", hex(&key))
        }
        _ => named,
    }
}

fn entry_json(
    network: Network,
    index: usize,
    amount: u64,
    spk: &ScriptPublicKey,
    covenant: Option<[u8; 32]>,
    what: String,
) -> Value {
    json!({
        "index": index,
        "amount": amount.to_string(),
        "amount_kas": kas(amount),
        "script_public_key": ops::spk_json(spk),
        "address": address_of(network, spk),
        "covenant_id": covenant.map(|c| hex(&c)),
        "what": what,
    })
}

/// The title of the document: what it does, in words.
fn title(ipst: &Ipst, kind: IpstKind) -> String {
    let t = ipst.terms().terms();
    match kind {
        IpstKind::FundKas => "Funding of the cash leg (native KAS)".into(),
        IpstKind::FundKcc20(leg) => format!(
            "Funding of the {} leg (a KCC-20 token)",
            if leg == LegIndex::Asset { "asset" } else { "cash" }
        ),
        IpstKind::Settle if matches!(t.cash_leg.kind, LegKind::External) => {
            "Settle: the asset to the buyer; the cash is paid outside Kaspa, and the authority's signature attests it"
                .into()
        }
        IpstKind::Settle => "Settle: the asset to the buyer, the cash to the seller".into(),
        IpstKind::Direct => "Direct trade: the asset to the buyer, the cash to the seller".into(),
        IpstKind::Refund {
            leg,
            signer,
            with_token,
        } => format!(
            "Refund of the {} leg, signed by the {}{}",
            if leg == LegIndex::Asset { "asset" } else { "cash" },
            match signer {
                RefundSigner::Depositor => "depositor",
                RefundSigner::Counterparty => "counterparty",
                RefundSigner::Authority => "authority",
            },
            if with_token {
                ", the escrowed token going home too"
            } else {
                ""
            }
        ),
    }
}

/// Which party a key is in the terms.
fn role_of(vt: &ValidatedTerms, key: [u8; 32]) -> &'static str {
    let t = vt.terms();
    if key == t.seller_key {
        "seller"
    } else if key == t.buyer_key {
        "buyer"
    } else if Some(key) == t.authority_key {
        "authority"
    } else {
        "other"
    }
}

/// The scriptPublicKeys that pay one of the `held` keys: its P2PK, and a KCC-20 token it owns on
/// either leg.
fn held_spks(
    vt: &ValidatedTerms,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
    held: &[[u8; 32]],
) -> Vec<ScriptPublicKey> {
    let t = vt.terms();
    let mut out = Vec::new();
    for key in held {
        out.push(p2pk(key));
        let owner = Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: *key,
        };
        for (leg, template) in [(&t.asset_leg, Some(asset)), (&t.cash_leg, cash)] {
            if matches!(leg.kind, LegKind::Kcc20(_)) {
                out.extend(template.and_then(|tpl| token_spk(tpl, owner, leg.amount)));
            }
        }
    }
    out
}

/// The outputs of `ipst` that pay one of the `held` keys (its P2PK, or a KCC-20 token it owns on
/// either leg): index, amount and where it pays. Wallets read it to refuse them on mainnet, and
/// the review to mark them.
pub(crate) fn held_outputs(
    ipst: &Ipst,
    asset: &Kcc20Template,
    cash: Option<&Kcc20Template>,
    held: &[[u8; 32]],
) -> Vec<(usize, u64, String)> {
    let spks = held_spks(ipst.terms(), asset, cash, held);
    let network = ipst.terms().terms().network;
    ipst.transaction()
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| spks.contains(&o.script_public_key))
        .map(|(i, o)| {
            let at = address_of(network, &o.script_public_key).unwrap_or_else(|| {
                format!(
                    "script version {}: {}",
                    o.script_public_key.version(),
                    hex(o.script_public_key.script())
                )
            });
            (i, o.value, at)
        })
        .collect()
}

/// What a funder reads before signing a funding: how the deposit comes back if the trade never
/// settles (spec/IMPULSE-SPEC.md, "refund"). A refund pays the leg's refund destination whoever
/// signs it. The depositor signs it with the key of the funding, from the expiry in earmarked
/// mode and at any time in revocable mode; the counterparty and the authority may sign it at any
/// time, and nothing makes them. When that key lives only in a wallet of the page (`held`),
/// closing or reloading the page, or wiping the wallet, takes the depositor's own way out with it.
fn funding_exit_note(vt: &ValidatedTerms, leg: LegIndex, held: &[[u8; 32]]) -> String {
    let t = vt.terms();
    let (name, role, counterparty, key, refund) = match leg {
        LegIndex::Asset => ("asset", "seller", "buyer", t.seller_key, &t.seller_refund),
        LegIndex::Cash => ("cash", "buyer", "seller", t.buyer_key, &t.buyer_refund),
    };
    let when = match t.funding_mode {
        FundingMode::Earmarked => format!(
            "from DAA score {} (earmarked funding: the depositor's refund opens after the expiry, DAA score {})",
            t.expiry_daa.saturating_add(1),
            t.expiry_daa
        ),
        FundingMode::Revocable => "at any time (revocable funding)".to_string(),
    };
    let keeping = if held.contains(&key) {
        "That key lives only in a wallet of this page: closing or reloading the page, or wiping the wallet, destroys it, and nothing in this page can bring it back."
    } else {
        "Keep that key until the trade has settled."
    };
    let others = if t.authority_key.is_some() {
        format!("The {counterparty} or the authority")
    } else {
        format!("The {counterparty}")
    };
    format!(
        "Until this trade settles, the only way you can take this deposit back yourself is a refund of the {name} leg signed with the {role}'s key {}, {when}. {keeping} {others} can also trigger that refund at any time, and it pays the {role}'s refund destination ({}) whoever signs it, but nothing makes them.",
        hex(&key),
        destination_text(t.network, refund)
    )
}

/// What a funder reads about the time the trade has left to settle. A settle is built only while
/// the node's score is below the expiry (`TX_EXPIRED` at or after it), so a deposit funded close to
/// the expiry can no longer be settled, and in earmarked mode waits for the depositor's refund from
/// the expiry plus one. This states the facts from the score the review is made at and chooses no
/// threshold: how short is too short is the funder's to judge, and the sentence gives the figures
/// to judge by.
fn funding_window_note(vt: &ValidatedTerms, current_daa: u64) -> String {
    let expiry = vt.terms().expiry_daa;
    let left = expiry.saturating_sub(current_daa);
    let unit = if left == 1 { "score" } else { "scores" };
    format!(
        "A settle of this trade can be built only before the expiry, DAA score {expiry}: at or after it the settle is refused (TX_EXPIRED). The node is at DAA score {current_daa}, so this funding, once accepted, has {left} DAA {unit} ({} at the nominal 10 DAA scores a second; the real rate varies) to be listed by the node and settled. A trade that is not settled by then can only be refunded.",
        approx_duration(left)
    )
}

fn list(indices: &[usize]) -> String {
    indices
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The review of `ipst` for a signer. `artifacts`, `current_daa` and `value` are those of
/// `Ipst::verify_against_terms`; `held` are the keys that live only in wallets of the page.
pub(crate) fn review(
    ipst: &Ipst,
    artifacts: &Value,
    current_daa: u64,
    value: &Value,
    held: &[[u8; 32]],
) -> Result<Value, Failure> {
    let matched = ops::terms_match(ipst, artifacts, current_daa, value)?;
    let kind = matched.kind;
    let (asset, cash) = forms::artifacts(artifacts)?;
    let network = ipst.terms().terms().network;
    let (outputs_known, inputs_known) = (
        known_outputs(ipst.terms(), &asset, cash.as_ref()),
        known_inputs(ipst.terms(), &asset, cash.as_ref()),
    );
    let held_outputs_found = held_outputs(ipst, &asset, cash.as_ref(), held);
    let tx = ipst.transaction();
    let has_change = matched.change.is_some();
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .zip(ipst.entries())
        .zip(ipst.slots())
        .enumerate()
        .map(|(i, ((input, entry), slot))| {
            let mut v = entry_json(
                network,
                i,
                entry.amount,
                &entry.script_public_key,
                entry.covenant_id.map(|c| c.as_bytes()),
                input_label(&inputs_known, &entry.script_public_key, slot.signer()),
            );
            v["outpoint"] = json!({
                "transaction_id": hex(&input.previous_outpoint.transaction_id.as_bytes()),
                "index": input.previous_outpoint.index,
            });
            v["signer"] = slot.signer().map_or(Value::Null, |k| json!(hex(&k)));
            v["signer_role"] = slot
                .signer()
                .map_or(Value::Null, |k| json!(role_of(ipst.terms(), k)));
            v["signed"] = json!(slot.signature().is_some());
            v
        })
        .collect();
    let last = tx.outputs.len().saturating_sub(1);
    let held_outputs: Vec<usize> = held_outputs_found.iter().map(|(i, _, _)| *i).collect();
    let held_amount = held_outputs_found
        .iter()
        .fold(0u64, |sum, (_, amount, _)| sum.saturating_add(*amount));
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let mut what = label_of(&outputs_known, &o.script_public_key);
            if has_change && i == last {
                what = format!("change, back to the fee payer ({what})");
            }
            let mut v = entry_json(
                network,
                i,
                o.value,
                &o.script_public_key,
                o.covenant.map(|c| c.covenant_id.as_bytes()),
                what,
            );
            v["held_key"] = json!(held_outputs.contains(&i));
            v
        })
        .collect();
    let fee = ipst.fee();
    let masses = ops::masses_json(ipst);
    let lock_time = tx.lock_time;
    // A transaction with a nonzero DAA-score lock time L is final in a block of DAA score d only
    // if L < d (spec/TRANSACTIONS.md, "Lock time"), and a node admits it when L is below its
    // virtual DAA score.
    let final_from = (lock_time != 0).then(|| lock_time.saturating_add(1));
    let submit_ready = lock_time == 0 || current_daa > lock_time;
    let wait = final_from
        .filter(|f| *f > current_daa)
        .map(|f| approx_duration(f - current_daa));
    let cost = payer::payer_cost(kind, ipst);
    let cost_text = match (payer::is_funding(kind), cost) {
        (false, 0) => "none".to_string(),
        (false, n) => format!(
            "{n} sompi ({} KAS) into trade outputs: the fee inputs top up under-funded pass-through outputs to their minimum, on top of the fee",
            kas(n)
        ),
        (true, n) => format!("{n} sompi ({} KAS), the deposit", kas(n)),
    };
    let mut notes: Vec<String> = Vec::new();
    let authority_inputs: Vec<usize> = ipst
        .slots()
        .iter()
        .enumerate()
        .filter(|(_, s)| s.signer().is_some() && s.signer() == ipst.terms().terms().authority_key)
        .map(|(i, _)| i)
        .collect();
    if !authority_inputs.is_empty() {
        notes.push(if matches!(ipst.terms().terms().cash_leg.kind, LegKind::External) {
            format!(
                "Input{} {} {} signed by the authority. The cash leg is paid outside Kaspa and nothing on chain shows it: the authority's signature is the only thing that releases this transaction, and signing it attests that the cash was paid. Impulse does not check the payment.",
                if authority_inputs.len() == 1 { "" } else { "s" },
                list(&authority_inputs),
                if authority_inputs.len() == 1 { "is" } else { "are" },
            )
        } else {
            format!(
                "Input{} {} {} signed by the authority_key of the terms. Sign it only if you are the authority.",
                if authority_inputs.len() == 1 { "" } else { "s" },
                list(&authority_inputs),
                if authority_inputs.len() == 1 { "is" } else { "are" },
            )
        });
    }
    // A funding: how the deposit comes back, and what happens to that way out with the page.
    let exit_note = match kind {
        IpstKind::FundKas => Some(funding_exit_note(ipst.terms(), LegIndex::Cash, held)),
        IpstKind::FundKcc20(leg) => Some(funding_exit_note(ipst.terms(), leg, held)),
        _ => None,
    };
    notes.extend(exit_note.clone());
    if exit_note.is_some() {
        notes.push(funding_window_note(ipst.terms(), current_daa));
    }
    if !held_outputs.is_empty() {
        let (what, in_all, carry, pays) = if held_outputs.len() == 1 {
            ("Output", "", "it carries", "pays")
        } else {
            ("Outputs", " in all", "they carry", "pay")
        };
        notes.push(format!(
            "{what} {} ({} KAS{in_all}, and any token {carry}) {pays} a key that lives only in a wallet of this page. Nothing in this page can spend it, and it is lost when the page unloads. On mainnet signing refuses it.",
            list(&held_outputs),
            kas(held_amount),
        ));
    }
    Ok(json!({
        "kind": ops::kind_json(kind),
        "title": title(ipst, kind),
        "network": network_name(network),
        "terms_hash": hex(&ipst.terms().terms_hash()),
        "nonce": ipst.terms().terms().nonce.to_string(),
        "inputs": inputs,
        "outputs": outputs,
        "fee": fee.to_string(),
        "fee_kas": kas(fee),
        "min_relay_fee": masses["min_relay_fee"],
        "masses": masses,
        "payer_cost": cost.to_string(),
        "payer_cost_kas": kas(cost),
        "payer_cost_text": cost_text,
        "held_outputs": held_outputs,
        "held_amount": held_amount.to_string(),
        "notes": notes,
        "exit_note": exit_note,
        "lock_time": lock_time.to_string(),
        "final_from_daa": final_from.map(|f| f.to_string()),
        "current_daa": current_daa.to_string(),
        "submit_ready": submit_ready,
        "wait": wait,
        "pending": ipst.pending(),
    }))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn spk(version: u16, script: Vec<u8>) -> ScriptPublicKey {
        ScriptPublicKey::from_vec(version, script)
    }

    /// An address is given for the three standard scripts at their exact lengths, and for nothing
    /// that only looks like one: a key of 31 or 33 bytes between the same opcodes, another script
    /// version, an empty script.
    #[test]
    fn an_address_is_given_for_a_standard_script_of_the_exact_length_and_for_nothing_else() {
        let key = |n: usize| vec![7u8; n];
        let p2pk = |n: usize| [&[0x20][..], &key(n), &[0xac]].concat();
        let ecdsa = |n: usize| [&[0x21][..], &key(n), &[0xab]].concat();
        let p2sh = |n: usize| [&[0xaa, 0x20][..], &key(n), &[0x87]].concat();
        for (what, script) in [("p2pk", p2pk(32)), ("ecdsa", ecdsa(33)), ("p2sh", p2sh(32))] {
            for network in [Network::Mainnet, Network::Testnet] {
                let address = address_of(network, &spk(0, script.clone())).expect(what);
                let prefix = if network == Network::Mainnet {
                    "kaspa:"
                } else {
                    "kaspatest:"
                };
                assert!(address.starts_with(prefix), "{what} {address}");
            }
            assert!(
                address_of(Network::Mainnet, &spk(1, script)).is_none(),
                "{what}: version 1"
            );
        }
        // The same opcodes around a key of another length have no address.
        for n in [0, 1, 31, 33, 34] {
            assert!(
                address_of(Network::Mainnet, &spk(0, p2pk(n))).is_none(),
                "p2pk of {n} bytes"
            );
        }
        for n in [0, 32, 34] {
            assert!(
                address_of(Network::Mainnet, &spk(0, ecdsa(n))).is_none(),
                "ecdsa of {n} bytes"
            );
        }
        for n in [0, 31, 33] {
            assert!(
                address_of(Network::Mainnet, &spk(0, p2sh(n))).is_none(),
                "p2sh of {n} bytes"
            );
        }
        assert!(address_of(Network::Mainnet, &spk(0, vec![])).is_none());
        // Two addresses of one key differ by network, and by the kind of script.
        let a = address_of(Network::Mainnet, &spk(0, p2pk(32))).unwrap();
        let b = address_of(Network::Testnet, &spk(0, p2pk(32))).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, address_of(Network::Mainnet, &spk(0, p2sh(32))).unwrap());
    }
}
