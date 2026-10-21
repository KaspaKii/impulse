// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! What a party reads before funding (spec/CLI.md, "Terms summary and role check"): the decoded
//! terms, and the check that the destinations of the user's own role pay the user's own key or
//! equal what the user pinned, and never the counterparty or the authority.
//!
//! The contract lets the counterparty trigger a refund, and a refund returns the leg to the
//! depositor's refund target as the terms name it (IMPULSE-SPEC.md, "Entries", refund rules 1 and
//! 3). Terms that name the counterparty's script as your refund target therefore hand your leg to
//! the counterparty as soon as you fund it. Only reading the terms protects against that, so the
//! CLI shows them decoded and checks your own destinations before it shows anything to fund.

use crate::error::CliError;
use crate::json::{hex, unhex32};
use crate::terms_file::network_name;
use clap::ValueEnum;
use impulse_core::address::prefix;
use impulse_core::terms::{
    Destination, FundingMode, IdentifierType, Kcc20Owner, Leg, LegKind, Network, SettlementMode,
    Terms,
};
use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;

/// DAA scores per second at Kaspa's nominal 10 blocks per second, the rate the terms' expiry
/// horizon also assumes.
pub const DAA_PER_SECOND: u64 = 10;

/// The user's side of the trade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Pays the cash leg; receives the asset at buyer_delivery; refunded at buyer_refund.
    Buyer,
    /// Delivers the asset leg; paid at seller_proceeds; refunded at seller_refund.
    Seller,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Buyer => "buyer",
            Role::Seller => "seller",
        }
    }

    /// The flag that pins what the role is paid or delivered at.
    pub fn receive_flag(self) -> &'static str {
        match self {
            Role::Buyer => "--my-delivery",
            Role::Seller => "--my-proceeds",
        }
    }
}

/// The flag that pins the role's refund destination.
pub const REFUND_FLAG: &str = "--my-refund";

/// Destinations the user expects instead of one paying `--my-key`: a custodian or multisig the
/// user controls, stated exactly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    /// `--my-delivery` (buyer) or `--my-proceeds` (seller).
    pub receive: Option<Destination>,
    /// `--my-refund`.
    pub refund: Option<Destination>,
}

/// The user's party: role, x-only public key, and pinned destinations.
#[derive(Clone, Debug)]
pub struct Party {
    pub role: Role,
    pub key: [u8; 32],
    pub pins: Pins,
}

/// A pin as the user wrote it: a Kaspa address of `network` in canonical form (the version-0
/// script of that address), or `kcc20:<pubkey|script_hash|covenant_id>:<64 hex digits>`.
/// Anything else is `CLI_DESTINATION_PIN_INVALID`.
pub fn parse_pin(flag: &str, text: &str, network: Network) -> Result<Destination, CliError> {
    let invalid = |why: String| {
        CliError::new(
            "CLI_DESTINATION_PIN_INVALID",
            format!("{flag} {text:?}: {why}"),
        )
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
        let identifier = unhex32(id).ok_or_else(|| invalid(form.into()))?;
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

/// Who a destination pays, as far as its script or owner shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Payee {
    /// A single x-only key: P2PK, P2PK-ECDSA of either parity of that x, or a KCC-20 pubkey owner.
    Key([u8; 32]),
    /// A script hash or covenant: whoever controls that script.
    Script,
    /// No on-chain destination (external cash).
    OffChain,
}

fn key32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn payee(d: &Destination) -> Payee {
    match d {
        Destination::OffChain => Payee::OffChain,
        Destination::Kcc20(o) => match o.identifier_type {
            IdentifierType::PubKey => Payee::Key(o.identifier),
            IdentifierType::ScriptHash | IdentifierType::CovenantId => Payee::Script,
        },
        Destination::Kas(spk) if spk.version() == 0 => match spk.script() {
            // OpData32 <x-only key> OpCheckSig
            [0x20, key @ .., 0xac] => key32(key).map_or(Payee::Script, Payee::Key),
            // OpData33 <02 or 03, x> OpCheckSigECDSA: the secret of x controls both parities.
            [0x21, 0x02 | 0x03, key @ .., 0xab] => key32(key).map_or(Payee::Script, Payee::Key),
            _ => Payee::Script,
        },
        Destination::Kas(_) => Payee::Script,
    }
}

/// A KAS destination as a Kaspa address where its script has one, else as hex.
pub fn kas_address(network: Network, version: u16, script: &[u8]) -> String {
    let addr = |v, payload: &[u8]| Address::new(prefix(network), v, payload).to_string();
    match (version, script) {
        (0, [0x20, key @ .., 0xac]) if key.len() == 32 => {
            format!("{} (pay to x-only key)", addr(Version::PubKey, key))
        }
        (0, [0x21, key @ .., 0xab]) if key.len() == 33 => {
            format!("{} (pay to ECDSA key)", addr(Version::PubKeyECDSA, key))
        }
        (0, [0xaa, 0x20, hash @ .., 0x87]) if hash.len() == 32 => {
            format!("{} (pay to script hash)", addr(Version::ScriptHash, hash))
        }
        _ => format!("script version {version} {}", hex(script)),
    }
}

pub fn describe(t: &Terms, d: &Destination) -> String {
    let what = match d {
        Destination::Kas(spk) => kas_address(t.network, spk.version(), spk.script()),
        Destination::Kcc20(o) => format!(
            "KCC-20 owner {} {}",
            match o.identifier_type {
                IdentifierType::PubKey => "pubkey",
                IdentifierType::ScriptHash => "script_hash",
                IdentifierType::CovenantId => "covenant_id",
            },
            hex(&o.identifier)
        ),
        Destination::OffChain => "off chain (outside Kaspa; Impulse does not check it)".into(),
    };
    let whose = match payee(d) {
        Payee::Key(k) if k == t.seller_key => " = seller_key".to_string(),
        Payee::Key(k) if k == t.buyer_key => " = buyer_key".to_string(),
        Payee::Key(k) if Some(k) == t.authority_key => " = authority_key".to_string(),
        Payee::Key(_) => " (a key that is neither party's nor the authority's)".to_string(),
        Payee::Script => " (a script: check who controls it)".to_string(),
        Payee::OffChain => String::new(),
    };
    format!("{what}{whose}")
}

/// `amount` sompi as a KAS decimal with eight places.
pub fn kas(amount: u64) -> String {
    format!("{}.{:08}", amount / 100_000_000, amount % 100_000_000)
}

fn leg_line(leg: &Leg) -> String {
    match &leg.kind {
        LegKind::Kas => format!("KAS, {} sompi ({} KAS)", leg.amount, kas(leg.amount)),
        LegKind::Kcc20(token) => format!(
            "KCC-20 token covenant_id {}, template_hash {}, {} token units",
            hex(&token.covenant_id),
            hex(&token.template_hash),
            leg.amount
        ),
        LegKind::External => format!(
            "external cash, amount {} (settled off chain; opaque to Impulse)",
            leg.amount
        ),
    }
}

/// `daa` DAA scores as an approximate duration at [`DAA_PER_SECOND`].
pub fn approx_duration(daa: u64) -> String {
    let secs = daa / DAA_PER_SECOND;
    let (hours, days) = (secs / 3_600, secs / 86_400);
    if days >= 2 {
        format!("about {days} days")
    } else if hours >= 2 {
        format!("about {hours} hours")
    } else {
        format!("about {} minutes", secs / 60)
    }
}

/// The decoded terms, one line per field a party must agree to. `now_daa` is the DAA score the
/// expiry is measured from (the creation DAA score of this run).
pub fn summary(terms_hash: &[u8; 32], t: &Terms, now_daa: u64) -> Vec<String> {
    let expiry = match t.expiry_daa.checked_sub(now_daa) {
        Some(left) => format!(
            "{}, {} after DAA score {now_daa} (at {DAA_PER_SECOND} DAA scores per second)",
            t.expiry_daa,
            approx_duration(left)
        ),
        None => format!("{}, passed at DAA score {now_daa}", t.expiry_daa),
    };
    let lock = match t.expiry_daa.checked_sub(now_daa) {
        Some(left) => format!(
            "a lock of {} from DAA score {now_daa}",
            approx_duration(left)
        ),
        None => format!("the lock has ended at DAA score {now_daa}"),
    };
    vec![
        format!("terms_hash: {}", hex(terms_hash)),
        format!("network: {}", network_name(t.network)),
        format!("trade_ref: {}", hex(&t.trade_ref)),
        format!(
            "settlement_mode: {}",
            match t.settlement_mode {
                SettlementMode::Direct => "direct (no escrow)",
                SettlementMode::Vault => "vault (each on-chain leg escrowed in its own vault)",
            }
        ),
        format!("seller_key: {}", hex(&t.seller_key)),
        format!("buyer_key: {}", hex(&t.buyer_key)),
        format!(
            "authority_key: {}",
            t.authority_key
                .map_or("none (self-settling)".to_string(), |k| hex(&k))
        ),
        format!("asset_leg (seller delivers): {}", leg_line(&t.asset_leg)),
        format!("cash_leg (buyer pays): {}", leg_line(&t.cash_leg)),
        format!("buyer_delivery: {}", describe(t, &t.buyer_delivery)),
        format!("seller_proceeds: {}", describe(t, &t.seller_proceeds)),
        format!("seller_refund: {}", describe(t, &t.seller_refund)),
        format!("buyer_refund: {}", describe(t, &t.buyer_refund)),
        format!(
            "earliest_daa: {}",
            t.earliest_daa.map_or("none".to_string(), |d| d.to_string())
        ),
        format!("expiry_daa: {expiry}"),
        format!(
            "funding_mode: {}",
            match t.funding_mode {
                FundingMode::Revocable => "revocable: a depositor may refund its own leg at any time".to_string(),
                FundingMode::Earmarked => format!(
                    "earmarked: a depositor may refund its own leg only from expiry_daa ({lock}); the counterparty or the authority can still cancel a leg at any time, so earmarking does not stop the other party cancelling the trade"
                ),
            }
        ),
        "refunds: the counterparty or the authority may also refund a leg at any time; a refund always goes to that leg's refund target above".to_string(),
    ]
}

/// The destinations a role receives at: what it is paid or delivered, and its refund.
fn own_destinations(t: &Terms, role: Role) -> [(&'static str, &Destination); 2] {
    match role {
        Role::Buyer => [
            ("buyer_delivery", &t.buyer_delivery),
            ("buyer_refund", &t.buyer_refund),
        ],
        Role::Seller => [
            ("seller_proceeds", &t.seller_proceeds),
            ("seller_refund", &t.seller_refund),
        ],
    }
}

/// Refuses terms in which `party` is not the role's party key (`CLI_ROLE_KEY_MISMATCH`), or in
/// which one of the role's own destinations (`CLI_DESTINATION_NOT_MINE`) pays the counterparty or
/// the authority (always), differs from its pin, or without a pin does not pay that key. Off-chain
/// destinations without a pin are not checked. Returns the line that reports the check.
pub fn check_party(t: &Terms, party: &Party) -> Result<String, CliError> {
    let role = party.role.name();
    let role_key = match party.role {
        Role::Buyer => t.buyer_key,
        Role::Seller => t.seller_key,
    };
    if role_key != party.key {
        return Err(CliError::new(
            "CLI_ROLE_KEY_MISMATCH",
            format!(
                "the terms name {role}_key {}, --my-key is {}; these terms are not yours as {role}",
                hex(&role_key),
                hex(&party.key)
            ),
        ));
    }
    let counterparty = match party.role {
        Role::Buyer => t.seller_key,
        Role::Seller => t.buyer_key,
    };
    let [(receive_name, receive), (refund_name, refund)] = own_destinations(t, party.role);
    let checks = [
        (
            receive_name,
            receive,
            party.role.receive_flag(),
            party.pins.receive.as_ref(),
        ),
        (refund_name, refund, REFUND_FLAG, party.pins.refund.as_ref()),
    ];
    let (mut ok, mut refused) = (vec![], vec![]);
    for (name, d, flag, pin) in checks {
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
            (_, Some(pin)) if pin == d => Ok(format!("{name} equals {flag}")),
            (_, Some(pin)) => Err(format!(
                "{name} pays {}, not {flag} {}",
                describe(t, d),
                describe(t, pin)
            )),
            (p, None) if p == Payee::Key(party.key) => Ok(format!("{name} pays --my-key")),
            (Payee::OffChain, None) => Ok(format!("{name} is off chain (not checked)")),
            (_, None) => Err(format!(
                "{name} pays {}, not --my-key (if your custodian or multisig controls it, pin it with {flag})",
                describe(t, d)
            )),
        };
        match verdict {
            Ok(line) => ok.push(line),
            Err(line) => refused.push(line),
        }
    }
    if !refused.is_empty() {
        return Err(CliError::new(
            "CLI_DESTINATION_NOT_MINE",
            format!("{}. Refuse these terms", refused.join("; ")),
        ));
    }
    Ok(format!(
        "you: {role}, {role}_key {}; {}",
        hex(&party.key),
        ok.join("; ")
    ))
}

/// A destination as a pin would name it (tests use it to pin the vectors' destinations).
#[cfg(test)]
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
        Destination::Kas(spk) => kas_address(network, spk.version(), spk.script())
            .split(' ')
            .next()
            .unwrap()
            .to_string(),
        Destination::OffChain => unreachable!("an off-chain destination has no pin"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms_file::parse_terms_file;
    use crate::terms_file::tests::vector_file;
    use crate::testutil::noncanonical_address;

    fn terms(prefix: &str) -> Terms {
        parse_terms_file(&vector_file(prefix)).unwrap().into_terms()
    }

    fn buyer(t: &Terms) -> Party {
        Party {
            role: Role::Buyer,
            key: t.buyer_key,
            pins: Pins::default(),
        }
    }

    fn seller(t: &Terms) -> Party {
        Party {
            role: Role::Seller,
            key: t.seller_key,
            pins: Pins::default(),
        }
    }

    fn p2sh(hash: [u8; 32]) -> Destination {
        let mut script = vec![0xaa, 0x20];
        script.extend_from_slice(&hash);
        script.push(0x87);
        Destination::Kas(ScriptPublicKey::from_vec(0, script))
    }

    /// `party` with `d` pinned as the destination `field` names.
    fn pinned(mut party: Party, field: &str, d: &Destination) -> Party {
        match field {
            "buyer_refund" | "seller_refund" => party.pins.refund = Some(d.clone()),
            _ => party.pins.receive = Some(d.clone()),
        }
        party
    }

    fn p2pk(key: &[u8; 32]) -> Destination {
        let mut script = vec![0x20];
        script.extend_from_slice(key);
        script.push(0xac);
        Destination::Kas(ScriptPublicKey::from_vec(0, script))
    }

    fn owner(key: [u8; 32]) -> Destination {
        Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: key,
        })
    }

    #[test]
    fn destinations_name_their_payee() {
        let t = terms("08-");
        let lines = summary(&[0xab; 32], &t, 400_000_000).join("\n");
        assert!(
            lines.contains(&format!(
                "buyer_delivery: KCC-20 owner pubkey {} = buyer_key",
                hex(&t.buyer_key)
            )),
            "{lines}"
        );
        assert!(lines.contains("buyer_refund: kaspatest:q"), "{lines}");
        assert!(lines.contains("(pay to ECDSA key) = buyer_key"), "{lines}");
        assert!(lines.contains("seller_proceeds: kaspatest:p"), "{lines}");
        assert!(lines.contains("(pay to script hash) (a script: check who controls it)"));
        assert!(lines.contains("seller_refund: KCC-20 owner script_hash "));
        assert!(lines.contains(&format!(
            "authority_key: {}",
            hex(&t.authority_key.unwrap())
        )));
        assert!(lines.contains("cash_leg (buyer pays): KAS, 100000000 sompi (1.00000000 KAS)"));
        assert!(lines.contains("asset_leg (seller delivers): KCC-20 token covenant_id "));
        assert!(
            lines.contains("expiry_daa: 425920000, about 30 days after DAA score 400000000"),
            "{lines}"
        );
        assert!(lines.contains("earliest_daa: 400036000"));
        assert!(lines.contains("funding_mode: earmarked"));
        assert!(lines.starts_with(&format!("terms_hash: {}", "ab".repeat(32))));
        // Mainnet P2PK and the off-chain destinations of external cash.
        let m = summary(&[0; 32], &terms("02-"), 400_000_000).join("\n");
        assert!(m.contains("seller_proceeds: kaspa:q"), "{m}");
        assert!(m.contains("(pay to x-only key) = seller_key"), "{m}");
        let x = summary(&[0; 32], &terms("05-"), 400_000_000).join("\n");
        assert!(x.contains("buyer_refund: off chain"), "{x}");
        assert!(x.contains("cash_leg (buyer pays): external cash"), "{x}");
    }

    /// Review round 2: the refund disclosure, the funding mode texts, the authority texts and
    /// the payee markers are pinned line by line.
    #[test]
    fn disclosure_and_mode_lines_are_exact() {
        let line = |t: &Terms, field: &str| -> String {
            summary(&[0; 32], t, 400_000_000)
                .into_iter()
                .find(|l| l.starts_with(&format!("{field}: ")))
                .unwrap_or_else(|| panic!("{field}"))
        };
        let t08 = terms("08-");
        let all = summary(&[0; 32], &t08, 400_000_000);
        assert_eq!(
            all.last().unwrap(),
            "refunds: the counterparty or the authority may also refund a leg at any time; a refund always goes to that leg's refund target above"
        );
        assert_eq!(
            line(&t08, "funding_mode"),
            "funding_mode: earmarked: a depositor may refund its own leg only from expiry_daa (a lock of about 30 days from DAA score 400000000); the counterparty or the authority can still cancel a leg at any time, so earmarking does not stop the other party cancelling the trade"
        );
        // After expiry the lock is over and the line says so.
        let late = summary(&[0; 32], &t08, t08.expiry_daa + 1);
        assert!(late.iter().any(|l| l.starts_with("funding_mode: earmarked")
            && l.contains("(the lock has ended at DAA score")));
        assert_eq!(
            line(&terms("04-"), "funding_mode"),
            "funding_mode: revocable: a depositor may refund its own leg at any time"
        );
        assert_eq!(
            line(&terms("04-"), "authority_key"),
            "authority_key: none (self-settling)"
        );
        assert_eq!(
            line(&t08, "settlement_mode"),
            "settlement_mode: vault (each on-chain leg escrowed in its own vault)"
        );
        assert_eq!(
            line(&terms("07-"), "settlement_mode"),
            "settlement_mode: direct (no escrow)"
        );
        let mut t = t08.clone();
        t.buyer_refund = p2pk(&t08.authority_key.unwrap());
        t.buyer_delivery = owner([9; 32]);
        assert!(
            line(&t, "buyer_refund").ends_with("(pay to x-only key) = authority_key"),
            "{}",
            line(&t, "buyer_refund")
        );
        assert_eq!(
            line(&t, "buyer_delivery"),
            format!(
                "buyer_delivery: KCC-20 owner pubkey {} (a key that is neither party's nor the authority's)",
                hex(&[9; 32])
            )
        );
    }

    /// Review round 1 of the token helper: the trade reference, which whoever drafts the terms
    /// chooses, is shown in hex right after the network, beside another value.
    #[test]
    fn the_trade_reference_is_shown() {
        for trade_ref in [[0x49; 32], [0; 32]] {
            let mut t = terms("08-");
            t.trade_ref = trade_ref;
            let all = summary(&[0; 32], &t, 400_000_000);
            assert_eq!(all[2], format!("trade_ref: {}", hex(&trade_ref)));
            assert!(all[1].starts_with("network: "));
        }
    }

    #[test]
    fn the_expiry_is_shown_with_the_time_left() {
        assert_eq!(approx_duration(10 * 86_400 * 3), "about 3 days");
        assert_eq!(approx_duration(10 * 3_600 * 5), "about 5 hours");
        assert_eq!(approx_duration(10 * 60 * 7), "about 7 minutes");
        let mut t = terms("08-");
        t.expiry_daa = 400_000_000 + 10 * 86_400 * 365;
        let lines = summary(&[0; 32], &t, 400_000_000).join("\n");
        assert!(
            lines.contains("about 365 days after DAA score 400000000"),
            "{lines}"
        );
        assert!(summary(&[0; 32], &t, t.expiry_daa + 1)
            .join("\n")
            .contains("passed at"));
    }

    #[test]
    fn the_buyer_check_accepts_its_own_destinations() {
        for prefix in ["01-", "04-", "05-", "07-", "08-"] {
            let t = terms(prefix);
            assert!(check_party(&t, &buyer(&t)).is_ok(), "{prefix}");
        }
        let t = terms("01-");
        assert!(
            check_party(&t, &seller(&t)).is_ok(),
            "control: vector 01 pays the seller key"
        );
    }

    #[test]
    fn the_party_key_must_be_the_role_key() {
        let t = terms("08-");
        let mut p = buyer(&t);
        p.key = t.seller_key;
        assert_eq!(
            check_party(&t, &p).unwrap_err().code(),
            "CLI_ROLE_KEY_MISMATCH"
        );
        let mut p = seller(&t);
        p.key = t.buyer_key;
        p.pins.receive = Some(t.seller_proceeds.clone());
        p.pins.refund = Some(t.seller_refund.clone());
        assert_eq!(
            check_party(&t, &p).unwrap_err().code(),
            "CLI_ROLE_KEY_MISMATCH"
        );
    }

    /// Each own destination of each role, pointed at the counterparty or the authority: refused,
    /// and refused as well when the user pins exactly that destination. Vector 08 pays both buyer
    /// destinations to the buyer key and vector 01 both seller destinations to the seller key, so
    /// each edit is the only defect.
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
            let base = terms(prefix);
            let party = match role {
                Role::Buyer => buyer(&base),
                Role::Seller => seller(&base),
            };
            assert!(check_party(&base, &party).is_ok(), "control {field}");
            let mut evil = base.clone();
            edit(&mut evil);
            let e = check_party(&evil, &party).unwrap_err();
            assert_eq!(e.code(), "CLI_DESTINATION_NOT_MINE", "{field}");
            assert!(e.to_string().contains(&format!("{field} pays ")), "{e}");
            assert!(e.to_string().contains(&format!("the {whose}'s key")), "{e}");
            let d = match field {
                "buyer_refund" => &evil.buyer_refund,
                "buyer_delivery" => &evil.buyer_delivery,
                "seller_proceeds" => &evil.seller_proceeds,
                _ => &evil.seller_refund,
            };
            let e = check_party(&evil, &pinned(party, field, &d.clone())).unwrap_err();
            assert_eq!(e.code(), "CLI_DESTINATION_NOT_MINE", "pinned {field}");
        }
    }

    /// The review round 2 draft: vector 08 with the buyer's delivery and refund both paying the
    /// seller key. No pin a custodian user could pass makes the buyer accept it.
    #[test]
    fn the_round_2_evil_terms_are_refused_for_any_pins() {
        let base = terms("08-");
        let mut evil = base.clone();
        evil.buyer_delivery = owner(base.seller_key);
        evil.buyer_refund = p2pk(&base.seller_key);
        let custodian = Pins {
            receive: Some(Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::ScriptHash,
                identifier: [5; 32],
            })),
            refund: Some(p2sh([6; 32])),
        };
        let as_drafted = Pins {
            receive: Some(evil.buyer_delivery.clone()),
            refund: Some(evil.buyer_refund.clone()),
        };
        for pins in [Pins::default(), custodian.clone(), as_drafted] {
            let mut p = buyer(&evil);
            p.pins = pins.clone();
            let e = check_party(&evil, &p).unwrap_err();
            assert_eq!(e.code(), "CLI_DESTINATION_NOT_MINE", "{pins:?}");
            assert!(e.to_string().contains("buyer_delivery pays "), "{e}");
            assert!(e.to_string().contains("buyer_refund pays "), "{e}");
        }
        // Control: the custodian's own destinations, as pinned, are accepted.
        let mut honest = base.clone();
        honest.buyer_delivery = custodian.receive.clone().unwrap();
        honest.buyer_refund = custodian.refund.clone().unwrap();
        let mut p = buyer(&honest);
        p.pins = custodian;
        let line = check_party(&honest, &p).unwrap();
        assert!(
            line.ends_with("buyer_delivery equals --my-delivery; buyer_refund equals --my-refund"),
            "{line}"
        );
    }

    #[test]
    fn a_custodian_destination_is_accepted_only_as_pinned() {
        // Vector 08: the seller is paid to a P2SH and refunded to a script-hash owner.
        let t = terms("08-");
        let e = check_party(&t, &seller(&t)).unwrap_err();
        assert_eq!(e.code(), "CLI_DESTINATION_NOT_MINE");
        assert!(
            e.to_string().contains("seller_proceeds pays kaspatest:p"),
            "{e}"
        );
        assert!(e.to_string().contains("pin it with --my-proceeds"), "{e}");
        assert!(
            e.to_string()
                .contains("seller_refund pays KCC-20 owner script_hash"),
            "{e}"
        );
        let half = pinned(seller(&t), "seller_proceeds", &t.seller_proceeds);
        let e = check_party(&t, &half).unwrap_err();
        assert!(!e.to_string().contains("seller_proceeds"), "{e}");
        assert!(e.to_string().contains("pin it with --my-refund"), "{e}");
        let both = pinned(half, "seller_refund", &t.seller_refund);
        assert_eq!(
            check_party(&t, &both).unwrap(),
            format!(
                "you: seller, seller_key {}; seller_proceeds equals --my-proceeds; seller_refund equals --my-refund",
                hex(&t.seller_key)
            )
        );
        // Another script than the one pinned: the attack a blanket override let through.
        for edit in [
            (|t: &mut Terms| t.seller_proceeds = p2sh([7; 32])) as fn(&mut Terms),
            |t| {
                t.seller_refund = Destination::Kcc20(Kcc20Owner {
                    identifier_type: IdentifierType::ScriptHash,
                    identifier: [7; 32],
                })
            },
        ] {
            let mut other = t.clone();
            edit(&mut other);
            let e = check_party(&other, &both).unwrap_err();
            assert_eq!(e.code(), "CLI_DESTINATION_NOT_MINE");
            assert!(e.to_string().contains(", not --my-"), "{e}");
        }
        // A key that is neither party's nor the authority's: only as pinned.
        let mut t = terms("08-");
        t.buyer_refund = p2pk(&[9; 32]);
        assert!(check_party(&t, &buyer(&t)).is_err());
        let refund = t.buyer_refund.clone();
        assert!(check_party(&t, &pinned(buyer(&t), "buyer_refund", &refund)).is_ok());
        // A pin is compared even where the destination pays --my-key.
        let t = terms("08-");
        let wrong = pinned(buyer(&t), "buyer_refund", &p2sh([8; 32]));
        assert_eq!(
            check_party(&t, &wrong).unwrap_err().code(),
            "CLI_DESTINATION_NOT_MINE"
        );
        // An off-chain destination is not checked, unless pinned: then it is not the pin.
        let x = terms("05-");
        assert!(check_party(&x, &buyer(&x))
            .unwrap()
            .contains("buyer_refund is off chain"));
        let pinned_off = pinned(buyer(&x), "buyer_refund", &p2sh([8; 32]));
        assert!(check_party(&x, &pinned_off).is_err());
        // Vector 02: the buyer takes delivery at a script-hash owner.
        let t = terms("02-");
        assert_eq!(
            check_party(&t, &buyer(&t)).unwrap_err().code(),
            "CLI_DESTINATION_NOT_MINE"
        );
        let delivery = t.buyer_delivery.clone();
        assert!(check_party(&t, &pinned(buyer(&t), "buyer_delivery", &delivery)).is_ok());
    }

    #[test]
    fn pins_parse_from_addresses_and_owners() {
        let t = terms("08-");
        let net = Network::Testnet;
        for d in [
            t.seller_proceeds.clone(),
            t.buyer_refund.clone(),
            p2pk(&t.buyer_key),
            t.seller_refund.clone(),
            owner(t.buyer_key),
            Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::CovenantId,
                identifier: [3; 32],
            }),
        ] {
            let text = pin_text(net, &d);
            assert_eq!(parse_pin("--my-refund", &text, net), Ok(d), "{text}");
        }
        let p2sh_text = pin_text(net, &t.seller_proceeds);
        assert!(p2sh_text.starts_with("kaspatest:p"), "{p2sh_text}");
        let hash = "ab".repeat(32);
        for bad in [
            String::new(),
            "nonsense".into(),
            p2sh_text.replace("kaspatest:", "kaspa:"),
            pin_text(Network::Mainnet, &t.seller_proceeds),
            noncanonical_address(&p2sh_text),
            p2sh_text.to_uppercase(),
            format!("kcc20:{hash}"),
            format!("kcc20:owner:{hash}"),
            format!("kcc20:pubkey:{}", hash.to_uppercase()),
            format!("kcc20:pubkey:{}", &hash[2..]),
            format!("kcc20:pubkey:{hash}00"),
        ] {
            let e = parse_pin("--my-refund", &bad, net).unwrap_err();
            assert_eq!(e.code(), "CLI_DESTINATION_PIN_INVALID", "{bad}");
            assert!(e.to_string().contains("--my-refund"), "{e}");
        }
        assert!(
            parse_pin("--my-refund", &noncanonical_address(&p2sh_text), net)
                .unwrap_err()
                .to_string()
                .contains("canonical form")
        );
        assert!(parse_pin(
            "--my-refund",
            &pin_text(Network::Mainnet, &t.seller_proceeds),
            net
        )
        .unwrap_err()
        .to_string()
        .contains("not a testnet address"));
    }

    #[test]
    fn an_ecdsa_destination_of_either_parity_pays_the_x_only_key() {
        let mut t = terms("02-");
        assert!(
            check_party(&t, &buyer(&t)).is_err(),
            "02 delivers to a script hash"
        );
        t.buyer_delivery = owner(t.buyer_key);
        for parity in [0x02u8, 0x03] {
            let mut script = vec![0x21, parity];
            script.extend_from_slice(&t.buyer_key);
            script.push(0xab);
            t.buyer_refund = Destination::Kas(ScriptPublicKey::from_vec(0, script));
            assert!(check_party(&t, &buyer(&t)).is_ok(), "{parity:#04x}");
        }
        let mut other = vec![0x21, 0x02];
        other.extend_from_slice(&t.seller_key);
        other.push(0xab);
        t.buyer_refund = Destination::Kas(ScriptPublicKey::from_vec(0, other));
        assert_eq!(
            check_party(&t, &buyer(&t)).unwrap_err().code(),
            "CLI_DESTINATION_NOT_MINE"
        );
    }
}
