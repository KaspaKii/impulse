// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The role check of spec/CLI.md ("Terms summary and role check") in the SDK, so that no page has
//! to remember it: which party the user is, their public key, and whether the destinations of the
//! user's own role pay the user and not the counterparty or the authority.
//!
//! The contract lets the counterparty or the authority trigger a refund, and a refund returns a
//! leg to its depositor's refund destination as the terms name it. Terms that name the
//! counterparty's script as your refund, delivery or proceeds destination pay your leg to the
//! counterparty once you fund it, and the contract works as specified. Reading the terms is the
//! only defence. The funding instructions (`funding.rs`) and the signing of a wallet
//! (`wallet.rs`) both run this check first and refuse without it.
//!
//! The rules are those of `crates/impulse-cli/src/summary.rs` (`check_party`, `parse_pin`),
//! re-implemented here because impulse-cli does not build for wasm32; `cargo test` compares the two
//! on every vector for both roles, on the attack terms of the CLI's own tests, and on the pins.
//! Only the codes (`SDK_ROLE_KEY_MISMATCH`, `SDK_DESTINATION_NOT_MINE`,
//! `SDK_DESTINATION_PIN_INVALID`) and the words of the messages differ (a key and a pin, not
//! `--my-key` and `--my-refund`).
//!
//! 1. The key must be the role's party key in the terms.
//! 2. A destination of the role that pays the counterparty's party key or the authority key is
//!    refused, always: no pin accepts it.
//! 3. A destination the user pinned must equal the pin exactly. This is how a custodian or
//!    multisig destination is accepted.
//! 4. A destination without a pin must pay the user's key (P2PK, P2PK-ECDSA of either parity, or a
//!    KCC-20 owner of type `pubkey`). An off-chain destination without a pin is not checked.
//! 5. `held` names the keys that live only in wallets of the page (a wallet holds a key in memory
//!    and nothing the SDK or the page builds spends from it but the fee inputs and the tokens of
//!    its own transactions). A destination of the role that pays one of them, pinned or not, is
//!    refused on mainnet (`SDK_DESTINATION_IN_WALLET`): what is paid there is stranded, and lost
//!    when the page unloads. On testnet it passes, and the result says so.

use crate::error::SdkError;
use crate::funding::{destination_text, payee, Payee};
use crate::json::{hex, hex_decode, network_name, Obj};
use impulse_core::address::prefix;
use impulse_core::terms::{Destination, IdentifierType, Kcc20Owner, Network, Terms};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde_json::{json, Value};

/// The user's side of the trade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Pays the cash leg; receives the asset at `buyer_delivery`; refunded at `buyer_refund`.
    Buyer,
    /// Delivers the asset leg; paid at `seller_proceeds`; refunded at `seller_refund`.
    Seller,
}

impl Role {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Role::Buyer => "buyer",
            Role::Seller => "seller",
        }
    }

    /// The leg this role funds: the seller the asset leg, the buyer the cash leg.
    pub(crate) fn funds_leg(self) -> &'static str {
        match self {
            Role::Buyer => "cash",
            Role::Seller => "asset",
        }
    }

    /// The pin that names what the role is paid or delivered at.
    fn receive_pin(self) -> &'static str {
        match self {
            Role::Buyer => "receive pin (buyer delivery)",
            Role::Seller => "receive pin (seller proceeds)",
        }
    }
}

const REFUND_PIN: &str = "refund pin";

/// The party as the caller wrote it: the pins stay text until the terms' network is known, since a
/// Kaspa address pin must be of that network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Party {
    pub role: Role,
    pub key: [u8; 32],
    pub receive_pin: Option<String>,
    pub refund_pin: Option<String>,
    /// Keys that live only in wallets of the page (rule 5 above).
    pub held: Vec<[u8; 32]>,
}

/// At most this many held keys in one `held` list.
pub(crate) const MAX_HELD: usize = 8;

/// Reads the `held` member of `o` when it is present and not null: an array of x-only public
/// keys, 64 lowercase hex digits each.
pub(crate) fn held_from(o: &mut Obj) -> Result<Vec<[u8; 32]>, SdkError> {
    let Some(value) = o.optional("held").filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return o.fail("held", "expected an array of public keys");
    };
    if items.len() > MAX_HELD {
        return o.fail("held", format!("at most {MAX_HELD} keys"));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            item.as_str()
                .and_then(hex_decode)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    SdkError::json(
                        format!("{}[{i}]", o.at("held")),
                        "expected 64 lowercase hex digits",
                    )
                })
        })
        .collect()
}

/// The pins of a party as the caller wrote them: `{ receive?, refund? }`, each a pin text or null.
pub(crate) type Pins = (Option<String>, Option<String>);

/// Reads the `pins` member of `o` when it is present and not null.
pub(crate) fn pins_from(o: &mut Obj) -> Result<Pins, SdkError> {
    let (mut receive_pin, mut refund_pin) = (None, None);
    if o.optional("pins").is_some_and(|v| !v.is_null()) {
        let mut pins = o.object("pins")?;
        let mut read = |key: &'static str| match pins.optional(key) {
            None | Some(Value::Null) => Ok(None),
            Some(_) => pins.str(key).map(|s| Some(s.to_string())),
        };
        receive_pin = read("receive")?;
        refund_pin = read("refund")?;
        pins.finish()?;
    }
    Ok((receive_pin, refund_pin))
}

/// Reads `{ role, key, pins?, held? }` where `pins` is `{ receive?, refund? }`, each a pin text
/// or null, and `held` the keys that live only in wallets of the page.
pub(crate) fn party_from_json(value: &Value, path: &str) -> Result<Party, SdkError> {
    let mut o = Obj::new(value, path)?;
    let role = o.choice("role", &[("buyer", Role::Buyer), ("seller", Role::Seller)])?;
    let key = o.bytes32("key")?;
    let (receive_pin, refund_pin) = pins_from(&mut o)?;
    let held = held_from(&mut o)?;
    o.finish()?;
    Ok(Party {
        role,
        key,
        receive_pin,
        refund_pin,
        held,
    })
}

/// The party a key is in `t`, if it is the seller's or the buyer's. The authority and a fee payer
/// have no destination to check.
pub(crate) fn party_of_key(
    t: &Terms,
    key: &[u8; 32],
    pins: Pins,
    held: Vec<[u8; 32]>,
) -> Option<Party> {
    let role = if *key == t.seller_key {
        Role::Seller
    } else if *key == t.buyer_key {
        Role::Buyer
    } else {
        return None;
    };
    Some(Party {
        role,
        key: *key,
        receive_pin: pins.0,
        refund_pin: pins.1,
        held,
    })
}

/// A pin as the user wrote it: a Kaspa address of `network` in canonical form (the version-0
/// script of that address), or `kcc20:<pubkey|script_hash|covenant_id>:<64 hex digits>`.
pub(crate) fn parse_pin(pin: &str, text: &str, network: Network) -> Result<Destination, SdkError> {
    let invalid = |why: String| SdkError::DestinationPinInvalid {
        pin: pin.into(),
        reason: format!("{}: {why}", crate::error::shown(text)),
    };
    if let Some(rest) = text.strip_prefix("kcc20:") {
        let form =
            "a KCC-20 owner is kcc20:<pubkey|script_hash|covenant_id>:<64 lowercase hex digits>";
        let (kind, id) = rest.split_once(':').ok_or_else(|| invalid(form.into()))?;
        let identifier_type = match kind {
            "pubkey" => IdentifierType::PubKey,
            "script_hash" => IdentifierType::ScriptHash,
            "covenant_id" => IdentifierType::CovenantId,
            _ => return Err(invalid(form.into())),
        };
        let identifier = hex_decode(id)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| invalid(form.into()))?;
        return Ok(Destination::Kcc20(Kcc20Owner {
            identifier_type,
            identifier,
        }));
    }
    let address = Address::try_from(text)
        .map_err(|_| invalid("neither a Kaspa address nor kcc20:<type>:<hex>".into()))?;
    if address.to_string() != text {
        return Err(invalid("the address is not in canonical form".into()));
    }
    if address.prefix != prefix(network) {
        return Err(invalid(format!("not a {} address", network_name(network))));
    }
    let payload = address.payload.as_slice();
    let script = match (address.version, payload.len()) {
        (Version::PubKey, 32) => [&[0x20][..], payload, &[0xac]].concat(),
        (Version::PubKeyECDSA, 33) => [&[0x21][..], payload, &[0xab]].concat(),
        (Version::ScriptHash, 32) => [&[0xaa, 0x20][..], payload, &[0x87]].concat(),
        _ => return Err(invalid("the address payload has the wrong length".into())),
    };
    Ok(Destination::Kas(ScriptPublicKey::from_vec(0, script)))
}

/// A destination as the refusal messages write it: what it is, and whose key it pays.
fn describe(t: &Terms, d: &Destination) -> String {
    let whose = match payee(d) {
        Payee::Key(k) if k == t.seller_key => " = seller_key".to_string(),
        Payee::Key(k) if k == t.buyer_key => " = buyer_key".to_string(),
        Payee::Key(k) if Some(k) == t.authority_key => " = authority_key".to_string(),
        Payee::Key(_) => " (a key that is neither party's nor the authority's)".to_string(),
        Payee::Script => " (a script: check who controls it)".to_string(),
        Payee::OffChain => String::new(),
    };
    format!("{}{whose}", destination_text(t.network, d))
}

/// What a passed check reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleCheck {
    pub role: Role,
    pub key: [u8; 32],
    /// One line per own destination: pays the user's key, equals its pin, or is off chain.
    pub lines: Vec<String>,
    /// The own destinations that pay a key held only in a wallet of the page (testnet; on
    /// mainnet the check refuses instead).
    pub in_wallet: Vec<&'static str>,
}

impl RoleCheck {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "role": self.role.name(),
            "key": hex(&self.key),
            "funds_leg": self.role.funds_leg(),
            "lines": self.lines,
            "in_wallet": self.in_wallet,
        })
    }
}

/// The role check. Refuses terms in which `party.key` is not the role's party key
/// (`SDK_ROLE_KEY_MISMATCH`), a pin that does not parse (`SDK_DESTINATION_PIN_INVALID`), or in
/// which one of the role's own destinations pays the counterparty or the authority (always),
/// differs from its pin, or without a pin does not pay the user's key
/// (`SDK_DESTINATION_NOT_MINE`), and on mainnet one that pays a held key
/// (`SDK_DESTINATION_IN_WALLET`).
pub(crate) fn check(t: &Terms, party: &Party) -> Result<RoleCheck, SdkError> {
    let role = party.role.name();
    let (role_key, counterparty, own) = match party.role {
        Role::Buyer => (
            t.buyer_key,
            t.seller_key,
            [
                ("buyer_delivery", &t.buyer_delivery),
                ("buyer_refund", &t.buyer_refund),
            ],
        ),
        Role::Seller => (
            t.seller_key,
            t.buyer_key,
            [
                ("seller_proceeds", &t.seller_proceeds),
                ("seller_refund", &t.seller_refund),
            ],
        ),
    };
    if role_key != party.key {
        return Err(SdkError::RoleKeyMismatch {
            role,
            expected: hex(&role_key),
            got: hex(&party.key),
        });
    }
    let pin = |name: &str, text: &Option<String>| {
        text.as_deref()
            .map(|text| parse_pin(name, text, t.network))
            .transpose()
    };
    let receive_pin = pin(party.role.receive_pin(), &party.receive_pin)?;
    let refund_pin = pin(REFUND_PIN, &party.refund_pin)?;
    let checks = [
        (own[0], party.role.receive_pin(), receive_pin),
        (own[1], REFUND_PIN, refund_pin),
    ];
    let (mut ok, mut refused) = (vec![], vec![]);
    let (mut in_wallet, mut stranded) = (vec![], vec![]);
    for ((name, d), pin_name, pin) in checks {
        let verdict = match (payee(d), pin) {
            // Never the user's custodian, pinned or not.
            (Payee::Key(k), _) if k == counterparty => Err(format!(
                "{name} pays {}: the counterparty's key",
                describe(t, d)
            )),
            (Payee::Key(k), _) if Some(k) == t.authority_key => Err(format!(
                "{name} pays {}: the authority's key",
                describe(t, d)
            )),
            (_, Some(pin)) if &pin == d => Ok(format!("{name} equals the {pin_name}")),
            (_, Some(pin)) => Err(format!(
                "{name} pays {}, not the {pin_name} {}",
                describe(t, d),
                describe(t, &pin)
            )),
            (p, None) if p == Payee::Key(party.key) => Ok(format!("{name} pays your key")),
            (Payee::OffChain, None) => Ok(format!("{name} is off chain (not checked)")),
            (_, None) => Err(format!(
                "{name} pays {}, not your key (if your custodian or multisig controls it, state it exactly as the {pin_name})",
                describe(t, d)
            )),
        };
        match verdict {
            Ok(mut line) => {
                if let Payee::Key(k) = payee(d) {
                    if party.held.contains(&k) {
                        in_wallet.push(name);
                        if t.network == Network::Mainnet {
                            stranded.push(format!(
                                "{name} pays {}, a key that lives only in a wallet of this page",
                                describe(t, d)
                            ));
                        } else {
                            line.push_str(
                                ": a key that lives only in a wallet of this page, so what is paid there cannot be spent from this page and is lost when it unloads",
                            );
                        }
                    }
                }
                ok.push(line);
            }
            Err(line) => refused.push(line),
        }
    }
    if !refused.is_empty() {
        return Err(SdkError::DestinationNotMine { reasons: refused });
    }
    if !stranded.is_empty() {
        return Err(SdkError::DestinationInWallet { reasons: stranded });
    }
    Ok(RoleCheck {
        role: party.role,
        key: party.key,
        lines: ok,
        in_wallet,
    })
}

/// The address a change output pays, as the signer states it: a Kaspa address of `network` in
/// canonical form (P2PK, P2PK-ECDSA or P2SH). `path` names the argument in a refusal.
pub(crate) fn change_spk(
    path: &str,
    text: &str,
    network: Network,
) -> Result<ScriptPublicKey, SdkError> {
    match parse_pin(path, text, network) {
        Ok(Destination::Kas(spk)) => Ok(spk),
        Ok(_) => Err(SdkError::json(
            path,
            "a change address is a Kaspa address, not a KCC-20 owner",
        )),
        Err(e) => Err(SdkError::json(path, e.to_string())),
    }
}

/// A destination as a pin would name it (tests pin the vectors' destinations with it).
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn pin_text(network: Network, d: &Destination) -> String {
    match d {
        Destination::Kcc20(o) => format!(
            "kcc20:{}:{}",
            match o.identifier_type {
                IdentifierType::PubKey => "pubkey",
                IdentifierType::ScriptHash => "script_hash",
                IdentifierType::CovenantId => "covenant_id",
            },
            hex(&o.identifier)
        ),
        Destination::Kas(_) => destination_text(network, d)
            .split(' ')
            .next()
            .unwrap()
            .to_string(),
        Destination::OffChain => unreachable!("an off-chain destination has no pin"),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::testkit::{terms, vector, vectors};
    use impulse_cli::summary::{self as cli, Pins as CliPins};

    fn party(role: Role, t: &Terms) -> Party {
        Party {
            role,
            key: match role {
                Role::Buyer => t.buyer_key,
                Role::Seller => t.seller_key,
            },
            receive_pin: None,
            refund_pin: None,
            held: Vec::new(),
        }
    }

    fn cli_party(role: Role, t: &Terms, pins: CliPins) -> cli::Party {
        let p = party(role, t);
        cli::Party {
            role: match role {
                Role::Buyer => cli::Role::Buyer,
                Role::Seller => cli::Role::Seller,
            },
            key: p.key,
            pins,
        }
    }

    fn p2pk(key: &[u8; 32]) -> Destination {
        Destination::Kas(ScriptPublicKey::from_vec(
            0,
            [&[0x20][..], key, &[0xac]].concat(),
        ))
    }

    fn p2sh(hash: [u8; 32]) -> Destination {
        Destination::Kas(ScriptPublicKey::from_vec(
            0,
            [&[0xaa, 0x20][..], &hash, &[0x87]].concat(),
        ))
    }

    fn owner(key: [u8; 32]) -> Destination {
        Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: key,
        })
    }

    fn own_names(role: Role) -> [&'static str; 2] {
        match role {
            Role::Buyer => ["buyer_delivery", "buyer_refund"],
            Role::Seller => ["seller_proceeds", "seller_refund"],
        }
    }

    /// The SDK refuses and accepts exactly what the command line does, naming the same
    /// destinations, on every vector for both roles without a pin.
    #[test]
    fn the_role_check_agrees_with_the_command_line_on_every_vector_and_role() {
        let (mut accepted, mut refused) = (0, 0);
        for (name, doc) in vectors() {
            let t = terms(&doc);
            for role in [Role::Buyer, Role::Seller] {
                let ours = check(&t, &party(role, &t));
                let theirs = cli::check_party(&t, &cli_party(role, &t, CliPins::default()));
                match (ours, theirs) {
                    (Ok(ok), Ok(line)) => {
                        accepted += 1;
                        assert_eq!(ok.lines.len(), 2, "{name} {role:?}");
                        assert!(line.starts_with(&format!("you: {}", role.name())), "{line}");
                    }
                    (Err(e), Err(c)) => {
                        refused += 1;
                        assert_eq!(c.code(), "CLI_DESTINATION_NOT_MINE", "{name} {role:?}");
                        assert_eq!(e.code(), "SDK_DESTINATION_NOT_MINE", "{name} {role:?}");
                        for field in own_names(role) {
                            assert_eq!(
                                e.to_string().contains(&format!("{field} pays ")),
                                c.to_string().contains(&format!("{field} pays ")),
                                "{name} {role:?} {field}: {e} / {c}"
                            );
                        }
                    }
                    (ours, theirs) => {
                        panic!("{name} {role:?}: sdk {ours:?} but the command line {theirs:?}")
                    }
                }
            }
        }
        // Both outcomes occur among the vectors, so the comparison is not vacuous.
        assert!(accepted >= 8 && refused >= 2, "{accepted} / {refused}");
    }

    #[test]
    fn the_key_must_be_the_roles_party_key() {
        let t = terms(&vector("08-"));
        let mut p = party(Role::Buyer, &t);
        assert!(check(&t, &p).is_ok(), "control");
        p.key = t.seller_key;
        let e = check(&t, &p).unwrap_err();
        assert_eq!(e.code(), "SDK_ROLE_KEY_MISMATCH");
        assert!(e.to_string().contains(&hex(&t.buyer_key)), "{e}");
        let theirs = cli::check_party(&t, &cli_party(Role::Buyer, &t, CliPins::default()));
        assert!(
            theirs.is_ok(),
            "control: the command line accepts the buyer"
        );
        // The authority's key, and a key of nobody, are not a party's.
        for key in [t.authority_key.unwrap(), [9; 32]] {
            let mut p = party(Role::Seller, &t);
            p.key = key;
            assert_eq!(check(&t, &p).unwrap_err().code(), "SDK_ROLE_KEY_MISMATCH");
        }
    }

    /// Each own destination of each role pointed at the counterparty or the authority: refused,
    /// and refused as well when the user pins exactly that destination.
    #[test]
    fn a_destination_paying_the_counterparty_or_the_authority_is_refused_even_pinned() {
        type Edit = fn(&mut Terms);
        let cases: [(&str, &str, Role, &str, Edit); 8] = [
            ("08-", "buyer_refund", Role::Buyer, "counterparty", |t| {
                t.buyer_refund = p2pk(&t.seller_key)
            }),
            ("08-", "buyer_delivery", Role::Buyer, "counterparty", |t| {
                t.buyer_delivery = owner(t.seller_key)
            }),
            (
                "01-",
                "seller_proceeds",
                Role::Seller,
                "counterparty",
                |t| t.seller_proceeds = owner(t.buyer_key),
            ),
            ("01-", "seller_refund", Role::Seller, "counterparty", |t| {
                t.seller_refund = owner(t.buyer_key)
            }),
            ("08-", "buyer_refund", Role::Buyer, "authority", |t| {
                t.buyer_refund = p2pk(&t.authority_key.unwrap())
            }),
            ("08-", "buyer_delivery", Role::Buyer, "authority", |t| {
                t.buyer_delivery = owner(t.authority_key.unwrap())
            }),
            ("01-", "seller_proceeds", Role::Seller, "authority", |t| {
                t.seller_proceeds = owner(t.authority_key.unwrap())
            }),
            ("01-", "seller_refund", Role::Seller, "authority", |t| {
                t.seller_refund = owner(t.authority_key.unwrap())
            }),
        ];
        for (prefix, field, role, whose, edit) in cases {
            let base = terms(&vector(prefix));
            let control = party(role, &base);
            assert!(check(&base, &control).is_ok(), "control {field}");
            let mut evil = base.clone();
            edit(&mut evil);
            let e = check(&evil, &control).unwrap_err();
            assert_eq!(e.code(), "SDK_DESTINATION_NOT_MINE", "{field}");
            assert!(e.to_string().contains(&format!("{field} pays ")), "{e}");
            assert!(e.to_string().contains(&format!("the {whose}'s key")), "{e}");
            // Pinning exactly the evil destination does not help.
            let d = match field {
                "buyer_refund" => &evil.buyer_refund,
                "buyer_delivery" => &evil.buyer_delivery,
                "seller_proceeds" => &evil.seller_proceeds,
                _ => &evil.seller_refund,
            };
            let mut pinned = control.clone();
            let text = Some(pin_text(evil.network, d));
            if field.ends_with("refund") {
                pinned.refund_pin = text;
            } else {
                pinned.receive_pin = text;
            }
            let e = check(&evil, &pinned).unwrap_err();
            assert_eq!(e.code(), "SDK_DESTINATION_NOT_MINE", "pinned {field}");
            // The command line refuses the same terms.
            let theirs = cli::check_party(&evil, &cli_party(role, &evil, CliPins::default()));
            assert_eq!(theirs.unwrap_err().code(), "CLI_DESTINATION_NOT_MINE");
        }
    }

    /// Buyer delivery and refund both paying the seller (the round 2 draft of the command line's
    /// review): no pin a custodian could pass accepts it, the honest custodian's terms are
    /// accepted as pinned.
    #[test]
    fn the_round_2_evil_terms_are_refused_for_any_pins_and_a_custodian_is_accepted_as_pinned() {
        let base = terms(&vector("08-"));
        let mut evil = base.clone();
        evil.buyer_delivery = owner(base.seller_key);
        evil.buyer_refund = p2pk(&base.seller_key);
        let custodian = (
            "kcc20:script_hash:0505050505050505050505050505050505050505050505050505050505050505"
                .to_string(),
            pin_text(base.network, &p2sh([6; 32])),
        );
        let as_drafted = (
            pin_text(evil.network, &evil.buyer_delivery),
            pin_text(evil.network, &evil.buyer_refund),
        );
        for (receive, refund) in [
            (None, None),
            (Some(custodian.0.clone()), Some(custodian.1.clone())),
            (Some(as_drafted.0), Some(as_drafted.1)),
        ] {
            let mut p = party(Role::Buyer, &evil);
            p.receive_pin = receive;
            p.refund_pin = refund;
            let e = check(&evil, &p).unwrap_err();
            assert_eq!(e.code(), "SDK_DESTINATION_NOT_MINE");
            assert!(e.to_string().contains("buyer_delivery pays "), "{e}");
            assert!(e.to_string().contains("buyer_refund pays "), "{e}");
        }
        // Control: the custodian's own destinations, as pinned, are accepted; unpinned they are not.
        let mut honest = base.clone();
        honest.buyer_delivery = Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: [5; 32],
        });
        honest.buyer_refund = p2sh([6; 32]);
        let mut p = party(Role::Buyer, &honest);
        assert_eq!(
            check(&honest, &p).unwrap_err().code(),
            "SDK_DESTINATION_NOT_MINE"
        );
        p.receive_pin = Some(custodian.0);
        p.refund_pin = Some(custodian.1);
        let ok = check(&honest, &p).unwrap();
        assert_eq!(
            ok.lines,
            [
                "buyer_delivery equals the receive pin (buyer delivery)",
                "buyer_refund equals the refund pin"
            ]
        );
        // One destination pinned and the other not: the other is still refused.
        p.refund_pin = None;
        let e = check(&honest, &p).unwrap_err();
        assert!(!e.to_string().contains("buyer_delivery"), "{e}");
        assert!(e.to_string().contains("buyer_refund pays "), "{e}");
        // Another script than the one pinned.
        p.refund_pin = Some(pin_text(base.network, &p2sh([6; 32])));
        let mut other = honest.clone();
        other.buyer_refund = p2sh([7; 32]);
        let e = check(&other, &p).unwrap_err();
        assert_eq!(e.code(), "SDK_DESTINATION_NOT_MINE");
    }

    #[test]
    fn pins_parse_as_the_command_lines_do() {
        use impulse_core::terms::Network;
        let t = terms(&vector("08-"));
        // The addresses the vector's own destinations are written as, on the right network.
        let good: Vec<String> = [&t.buyer_refund, &t.seller_proceeds, &t.buyer_delivery]
            .iter()
            .map(|d| pin_text(t.network, d))
            .collect();
        let hash = "ab".repeat(32);
        let mut texts: Vec<String> = good.clone();
        texts.extend([
            format!("kcc20:pubkey:{hash}"),
            format!("kcc20:script_hash:{hash}"),
            format!("kcc20:covenant_id:{hash}"),
            // Refused by both.
            format!("kcc20:other:{hash}"),
            format!("kcc20:pubkey:{}", "AB".repeat(32)),
            format!("kcc20:pubkey:{}", "ab".repeat(31)),
            "kcc20:pubkey".to_string(),
            "not an address".to_string(),
            String::new(),
            good[0].to_uppercase(),
            format!("{} ", good[0]),
        ]);
        // A mainnet address on a testnet command.
        let m = terms(&vector("02-"));
        texts.push(pin_text(m.network, &m.seller_proceeds));
        for text in &texts {
            for network in [Network::Testnet, Network::Mainnet] {
                let ours = parse_pin("pin", text, network);
                let theirs = cli::parse_pin("--pin", text, network);
                match (ours, theirs) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b, "{text:?}"),
                    (Err(e), Err(_)) => {
                        assert_eq!(e.code(), "SDK_DESTINATION_PIN_INVALID", "{text:?}")
                    }
                    (a, b) => panic!("{text:?} on {network:?}: sdk {a:?}, command line {b:?}"),
                }
            }
        }
        // Control and refusal through the check: a pin of the wrong network is refused.
        let mut p = party(Role::Buyer, &t);
        p.refund_pin = Some(good[0].clone());
        assert!(check(&t, &p).is_ok(), "control");
        p.refund_pin = Some(pin_text(m.network, &m.seller_proceeds));
        assert_eq!(
            check(&t, &p).unwrap_err().code(),
            "SDK_DESTINATION_PIN_INVALID"
        );
    }

    #[test]
    fn the_party_form_is_strict() {
        use serde_json::json;
        let key = "ab".repeat(32);
        let ok = json!({"role": "buyer", "key": key});
        assert!(party_from_json(&ok, "party").is_ok(), "control");
        let with_pins =
            json!({"role": "seller", "key": key, "pins": {"receive": null, "refund": "x"}});
        let p = party_from_json(&with_pins, "party").unwrap();
        assert_eq!(p.refund_pin.as_deref(), Some("x"));
        assert!(p.receive_pin.is_none());
        let bad = [
            json!({"role": "authority", "key": key}),
            json!({"role": "Buyer", "key": key}),
            json!({"role": "buyer"}),
            json!({"role": "buyer", "key": "AB".repeat(32)}),
            json!({"role": "buyer", "key": "ab".repeat(31)}),
            json!({"role": "buyer", "key": key, "extra": 1}),
            json!({"role": "buyer", "key": key, "pins": {"receive": 5}}),
            json!({"role": "buyer", "key": key, "pins": {"other": "x"}}),
            json!({"role": "buyer", "key": key, "pins": "x"}),
            json!("buyer"),
        ];
        for b in bad {
            let e = party_from_json(&b, "party").unwrap_err();
            assert_eq!(e.code(), "SDK_JSON_FORM", "{b}");
        }
    }

    /// The refusal says what each offending destination is and whose key it pays: the words that
    /// let a person see the attack. One case for each kind of payee the check tells apart.
    #[test]
    fn a_refusal_names_the_offending_destination_and_whose_key_it_pays() {
        let base = terms(&vector("08-"));
        let buyer = party(Role::Buyer, &base);
        let refuse = |edit: &dyn Fn(&mut Terms)| {
            let mut t = base.clone();
            edit(&mut t);
            check(&t, &buyer).unwrap_err().to_string()
        };
        let stranger = [9u8; 32];
        let cases: [(&str, String, &str); 5] = [
            (
                "the counterparty's key",
                refuse(&|t| t.buyer_refund = p2pk(&t.seller_key)),
                " = seller_key",
            ),
            (
                "the authority's key",
                refuse(&|t| t.buyer_refund = p2pk(&t.authority_key.unwrap())),
                " = authority_key",
            ),
            (
                "some other key",
                refuse(&|t| t.buyer_refund = p2pk(&stranger)),
                " (a key that is neither party's nor the authority's)",
            ),
            (
                "a script",
                refuse(&|t| t.buyer_refund = p2sh([6; 32])),
                " (a script: check who controls it)",
            ),
            (
                "the buyer's own key, but not the one pinned",
                {
                    let mut p = buyer.clone();
                    p.refund_pin = Some(pin_text(base.network, &p2pk(&stranger)));
                    check(&base, &p).unwrap_err().to_string()
                },
                " = buyer_key",
            ),
        ];
        for (what, text, whose) in &cases {
            assert!(text.contains("buyer_refund pays "), "{what}: {text}");
            assert!(text.contains(whose), "{what}: {text}");
        }
        // Each is its own sentence: the key kinds do not borrow one another's words.
        assert!(!cases[0].1.contains("authority_key") && !cases[0].1.contains("neither party's"));
        assert!(!cases[2].1.contains(" = ") && !cases[2].1.contains("check who controls"));
        assert!(!cases[3].1.contains(" = ") && !cases[3].1.contains("neither party's"));
        // An off-chain destination has no payee to name, and a pin does not match it.
        let mut off = base.clone();
        off.buyer_refund = Destination::OffChain;
        let mut pinned = buyer.clone();
        pinned.refund_pin = Some(pin_text(base.network, &p2pk(&stranger)));
        let text = check(&off, &pinned).unwrap_err().to_string();
        assert!(
            text.contains(
                "buyer_refund pays off chain (outside Kaspa; Impulse does not check it), not the refund pin "
            ),
            "{text}"
        );
        assert!(
            !text.contains("off chain (outside Kaspa; Impulse does not check it) = "),
            "{text}"
        );
    }
}
