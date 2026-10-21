// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Funding instructions for a trade, the SDK's counterpart of `impulse address` (spec/CLI.md,
//! "Funding URI" and "Value cap"), in Rust so that no SDK logic lives only in TypeScript.
//!
//! [`instructions`] returns nothing until every check has passed, in this order: the creation
//! checks of impulse-core (network, expiry), a mainnet creation DAA score that came from a node,
//! the two "Before funding" checks of spec/CLI.md ([`check_before_funding`]: a native KAS cash leg
//! below the minimum output, and a KCC-20 template that is no pinned kcc20.sil build, which no
//! funding instruction, funding or signature is ever given for), the role check (`role.rs`: which party the user is, their key, and that the destinations of
//! their role pay them), the per-trade value cap (`value::measure`, the one cap of the SDK, shared with the builders;
//! skipped only by `accept_the_risk`, the SDK's form of the CLI's
//! `--i-accept-the-risk`, which the demo never sets), then every leg the terms escrow
//! instantiated as a fundable vault (only `TEMPLATE_NO_VAULT` leaves a leg without one). The
//! funding URI of a native KAS leg is `<vault address>?amount=<sompi>&impulse=<terms hash>`, the
//! form of `crates/impulse-cli/src/uri.rs`; `cargo test` compares the two on every vector. Only the
//! leg the user's role funds gets a funding URI: the other vault is shown with the address and
//! `you_fund: false`, as `impulse address` shows the counterparty's vault. The cap
//! rules are those of `crates/impulse-cli/src/value_cap.rs`, compared the same way. Moving both
//! into impulse-core, so the CLI and the SDK share one implementation, is an open question of the
//! I11 Report.

use crate::error::{Failure, SdkError};
use crate::json::{hex, network_name, FundingOptions};
use crate::role;
use crate::value::{self, ValueDeclaration};
use impulse_core::address;
use impulse_core::template::{self, LegIndex, TemplateError, Vault};
use impulse_core::terms::{Destination, IdentifierType, LegKind, Network, Terms, ValidatedTerms};
use impulse_core::tx::{TxError, MIN_KAS_OUTPUT};
use impulse_core::verify::{self, pinned_kcc20, TemplateTriple};
use kaspa_addresses::{Address, Version};
use serde_json::{json, Value};

/// An amount of sompi as KAS with eight decimals.
pub(crate) fn kas(sompi: u64) -> String {
    format!("{}.{:08}", sompi / 100_000_000, sompi % 100_000_000)
}

/// A QR code: `modules` holds `width * width` bytes, row by row, 1 for a dark module. No quiet
/// zone: the drawing adds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Qr {
    pub width: usize,
    pub modules: Vec<u8>,
}

/// The QR code of `text` at the error correction level of the `qrcode` crate's default (M), the
/// level `impulse address` prints.
pub(crate) fn qr(text: &str) -> Result<Qr, SdkError> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| SdkError::Qr {
        reason: e.to_string(),
    })?;
    Ok(Qr {
        width: code.width(),
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| u8::from(c == qrcode::Color::Dark))
            .collect(),
    })
}

/// DAA scores per second at Kaspa's nominal 10 blocks per second, the rate the terms' expiry
/// horizon also assumes (the CLI's `summary::DAA_PER_SECOND`).
const DAA_PER_SECOND: u64 = 10;

/// `daa` DAA scores as an approximate duration at [`DAA_PER_SECOND`]; `cargo test` compares it
/// with the command line's `summary::approx_duration`.
pub(crate) fn approx_duration(daa: u64) -> String {
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

/// Who a destination pays, as far as its script or owner shows (the CLI's `summary::Payee`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Payee {
    /// A single x-only key: P2PK, P2PK-ECDSA of either parity of that x, or a KCC-20 pubkey owner.
    Key([u8; 32]),
    /// A script hash or covenant: whoever controls that script.
    Script,
    /// No on-chain destination (external cash).
    OffChain,
}

pub(crate) fn payee(d: &Destination) -> Payee {
    let key32 = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).ok();
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

/// A destination as the CLI's terms summary writes it before the mark: a Kaspa address where the
/// script has one, a KCC-20 owner, or the script in hex.
pub(crate) fn destination_text(network: Network, d: &Destination) -> String {
    let addr = |v, payload: &[u8]| Address::new(address::prefix(network), v, payload).to_string();
    match d {
        Destination::Kas(spk) => match (spk.version(), spk.script()) {
            (0, [0x20, key @ .., 0xac]) if key.len() == 32 => {
                format!("{} (pay to x-only key)", addr(Version::PubKey, key))
            }
            (0, [0x21, key @ .., 0xab]) if key.len() == 33 => {
                format!("{} (pay to ECDSA key)", addr(Version::PubKeyECDSA, key))
            }
            (0, [0xaa, 0x20, hash @ .., 0x87]) if hash.len() == 32 => {
                format!("{} (pay to script hash)", addr(Version::ScriptHash, hash))
            }
            (version, script) => format!("script version {version} {}", hex(script)),
        },
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
    }
}

/// The four destinations of the terms, in the order of the terms summary of spec/CLI.md: what
/// each is, which party's it is, and whom it pays as far as its script shows. `pays` is one of
/// `seller_key`, `buyer_key`, `authority_key`, `other_key`, `script` and `off_chain`.
/// `pays_counterparty_or_authority` is true when the destination pays the key of the party that
/// does not own it, or the authority's: the contract lets that party trigger a refund, so funding
/// terms with such a destination gives the leg away. The command line refuses it for the user's
/// own destinations, whatever the pin (`CLI_DESTINATION_NOT_MINE`); this page cannot know the
/// user's role and shows it.
fn destinations(t: &Terms) -> Vec<Value> {
    let rows = [
        ("buyer_delivery", "buyer", &t.buyer_delivery),
        ("seller_proceeds", "seller", &t.seller_proceeds),
        ("seller_refund", "seller", &t.seller_refund),
        ("buyer_refund", "buyer", &t.buyer_refund),
    ];
    rows.into_iter()
        .map(|(name, owner, d)| {
            let (pays, mark) = match payee(d) {
                Payee::Key(k) if k == t.seller_key => ("seller_key", "pays seller_key"),
                Payee::Key(k) if k == t.buyer_key => ("buyer_key", "pays buyer_key"),
                Payee::Key(k) if Some(k) == t.authority_key => {
                    ("authority_key", "pays authority_key")
                }
                Payee::Key(_) => (
                    "other_key",
                    "pays a key that is neither party's nor the authority's",
                ),
                Payee::Script => ("script", "script to check: find out who controls it"),
                Payee::OffChain => ("off_chain", "off chain: not checked"),
            };
            let other_party = if owner == "buyer" {
                "seller_key"
            } else {
                "buyer_key"
            };
            json!({
                "name": name,
                "owner": owner,
                "kind": match d {
                    Destination::Kas(_) => "kas",
                    Destination::Kcc20(_) => "kcc20",
                    Destination::OffChain => "off_chain",
                },
                "destination": destination_text(t.network, d),
                "pays": pays,
                "mark": mark,
                "pays_counterparty_or_authority": pays == other_party || pays == "authority_key",
            })
        })
        .collect()
}

/// "Before funding" (spec/CLI.md): a native KAS cash leg below `MIN_KAS_OUTPUT` has no standard
/// settle (the settle's cash output must equal the leg amount), and `fund_kas` refuses to fund
/// it. The command line's `CLI_KAS_LEG_BELOW_MIN`, under the builders' `TX_BELOW_MIN_KAS`.
pub(crate) fn check_kas_minimum(terms: &ValidatedTerms) -> Result<(), Failure> {
    let cash = &terms.terms().cash_leg;
    if cash.kind == LegKind::Kas && cash.amount < MIN_KAS_OUTPUT {
        return Err(TxError::BelowMinKas {
            output: 0,
            value: cash.amount,
            minimum: MIN_KAS_OUTPUT,
        }
        .into());
    }
    Ok(())
}

/// "Before funding" (spec/CLI.md): a KCC-20 leg whose template (hash, prefix length, suffix
/// length) is not one of the pinned kcc20.sil builds is refused, so that no funding instruction,
/// funding transaction or signature is given for a trade whose settle and refund the builders'
/// compute budgets do not cover (a token could be left escrowed with no spend path). There is no
/// override; such tokens are outside v1. The command line's `check_pinned`
/// (`CLI_TEMPLATE_UNPINNED`), under `SDK_TEMPLATE_UNPINNED`.
pub(crate) fn check_pinned(terms: &ValidatedTerms) -> Result<(), SdkError> {
    let t = terms.terms();
    for (name, leg) in [("asset", &t.asset_leg), ("cash", &t.cash_leg)] {
        if let LegKind::Kcc20(token) = leg.kind {
            if pinned_kcc20(&TemplateTriple::from(&token)).is_none() {
                return Err(SdkError::TemplateUnpinned {
                    reason: format!(
                        "the {name} leg's KCC-20 template {} ({}+{}) is not a pinned kcc20.sil build (silverscript v1.0.0): the builders' compute budgets are measured for kcc20.sil only, so a settle or refund of this token may fail and leave it escrowed; such tokens are outside v1",
                        hex(&token.template_hash),
                        token.template_prefix_len,
                        token.template_suffix_len
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Both "Before funding" checks, in the command line's order: the KAS minimum, then the template.
pub(crate) fn check_before_funding(terms: &ValidatedTerms) -> Result<(), Failure> {
    check_kas_minimum(terms)?;
    check_pinned(terms)?;
    Ok(())
}

/// The funding URI of a native KAS leg's vault.
fn funding_uri(address: &str, amount: u64, terms_hash: &str) -> String {
    format!("{address}?amount={amount}&impulse={terms_hash}")
}

/// The funding instructions of a trade, as a JSON value. See `FundingInstructions` in the type
/// declarations for its shape.
pub(crate) fn instructions(
    terms: &ValidatedTerms,
    options: &FundingOptions,
) -> Result<Value, Failure> {
    let ctx = &options.context;
    terms.validate_creation(ctx)?;
    if ctx.network == Network::Mainnet && !options.daa_from_node {
        return Err(SdkError::MainnetNeedsNode.into());
    }
    let t = terms.terms();
    // The "Before funding" checks come right after the creation checks, as `impulse address` runs
    // them: no instruction is given for a trade `fund build` would not fund.
    check_before_funding(terms)?;
    // The role check comes before any address, URI or amount is worked out.
    let role = role::check(t, &options.party)?;
    // The cap as text is read first, so a malformed cap is refused whether or not the risk is
    // accepted; a cap together with the acceptance is refused by the shared check.
    let cap = options
        .cap
        .as_deref()
        .map(value::cap_from_text)
        .transpose()?;
    let declaration = ValueDeclaration::new(options.kas_equivalent, cap, options.accept_the_risk);
    // This call moves no native KAS beside the terms' legs.
    let value = value::measure(t, &declaration, 0)?;
    let template_hash = hex(&template::check()?.hash());
    let terms_hash = hex(&terms.terms_hash());
    // No page of the SDK reads a token's artifact, so every KCC-20 leg is unassessed: nothing
    // about the token's issuer powers was read, and the caller must say so.
    let token_warnings = verify::token_warnings(terms, None, None)?;
    let mut legs = Vec::new();
    for leg in LegIndex::ALL {
        let (name, depositor, leg_terms) = match leg {
            LegIndex::Asset => ("asset", "seller", &t.asset_leg),
            LegIndex::Cash => ("cash", "buyer", &t.cash_leg),
        };
        let you_fund = depositor == role.role.name();
        let (kind, is_kas) = match leg_terms.kind {
            LegKind::Kas => ("kas", true),
            LegKind::Kcc20(_) => ("kcc20", false),
            LegKind::External => ("external", false),
        };
        let (vault, uri, no_vault_reason) = match Vault::instantiate_for_creation(terms, leg, ctx) {
            Ok(fundable) => {
                let address = address::vault_address(&fundable);
                // A URI only for the leg the user's role funds.
                let uri = (is_kas && you_fund)
                    .then(|| funding_uri(&address, leg_terms.amount, &terms_hash));
                let vault = json!({
                    "address": address,
                    "script_hash": hex(&fundable.vault().script_hash()),
                });
                (vault, uri, Value::Null)
            }
            Err(TemplateError::NoVault { reason, .. }) => (Value::Null, None, json!(reason)),
            Err(e) => return Err(e.into()),
        };
        legs.push(json!({
            "leg": leg.index(),
            "name": name,
            "depositor": depositor,
            "you_fund": you_fund,
            "kind": kind,
            "amount": leg_terms.amount.to_string(),
            "amount_kas": is_kas.then(|| kas(leg_terms.amount)),
            "vault": vault,
            "no_vault_reason": no_vault_reason,
            "funding_uri": uri,
            "token_warnings": token_warnings
                .iter()
                .filter(|w| w.leg == leg)
                .map(|w| json!({"code": w.code(), "message": w.to_string()}))
                .collect::<Vec<_>>(),
        }));
    }
    Ok(json!({
        "network": network_name(ctx.network),
        "terms_hash": terms_hash,
        "template_hash": template_hash,
        "creation_daa": ctx.creation_daa.to_string(),
        "creation_daa_source": if options.daa_from_node { "node" } else { "typed" },
        // validate_creation has refused an expiry that is not after the creation score.
        "expiry": {
            "expiry_daa": t.expiry_daa.to_string(),
            "time_left": approx_duration(t.expiry_daa.saturating_sub(ctx.creation_daa)),
        },
        "role": role.to_json(),
        "destinations": destinations(t),
        "value": match value {
            Some(v) => json!({
                "lifted": false,
                "value": v.value.to_string(),
                "value_kas": kas(v.value),
                "cap": v.cap.to_string(),
                "cap_kas": kas(v.cap),
                "declared": v.declared.to_string(),
                "largest_kas_leg": v.largest_kas_leg.to_string(),
            }),
            None => json!({
                "lifted": true,
                "value": null,
                "value_kas": null,
                "cap": null,
                "cap_kas": null,
                "declared": null,
                "largest_kas_leg": null,
            }),
        },
        "legs": legs,
    }))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::json::{funding_options_from_json, terms_from_json};
    use impulse_core::terms::CreationContext;
    use impulse_core::verify::PINNED_KCC20_TEMPLATES;
    use std::path::Path;

    /// (file name, parsed vector document) of every committed terms vector.
    fn vectors() -> Vec<(String, Value)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/terms");
        let mut out: Vec<(String, Value)> = std::fs::read_dir(&dir)
            .expect("read tests/vectors/terms")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .map(|p| {
                let text = std::fs::read_to_string(&p).expect("read vector");
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    serde_json::from_str(&text).expect("vector parses"),
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(out.len(), 11, "the eleven terms vectors");
        out
    }

    fn vector(prefix: &str) -> Value {
        let all = vectors();
        let found: Vec<_> = all.iter().filter(|(n, _)| n.starts_with(prefix)).collect();
        assert_eq!(found.len(), 1, "one vector {prefix}");
        found[0].1.clone()
    }

    fn validated(doc: &Value) -> ValidatedTerms {
        terms_from_json(&doc["terms"])
            .expect("form")
            .validate_structure()
            .expect("structure")
    }

    /// Options for a vector: its network, creation DAA 400,000,000 (the vectors' own), a
    /// declared KAS equivalent of 1 KAS, the default cap, the DAA marked as read from a node.
    fn options(network: &str) -> Value {
        json!({
            "context": {"network": network, "creation_daa": "400000000"},
            "creation_daa_source": "node",
            "kas_equivalent": "100000000",
        })
    }

    /// The same with the value checks skipped, for vectors whose amounts are above the cap.
    fn lifted(network: &str) -> Value {
        let mut o = options(network);
        o["accept_the_risk"] = json!(true);
        o
    }

    /// `role` of `t` as the role check wants it: the role's key, and a pin for each of the role's
    /// destinations that does not pay that key (a custodian or script destination).
    fn party_json(t: &Terms, role: &str) -> Value {
        let (key, receive, refund) = if role == "buyer" {
            (t.buyer_key, &t.buyer_delivery, &t.buyer_refund)
        } else {
            (t.seller_key, &t.seller_proceeds, &t.seller_refund)
        };
        let pin = |d: &Destination| match payee(d) {
            Payee::Key(k) if k == key => Value::Null,
            Payee::OffChain => Value::Null,
            _ => json!(crate::role::pin_text(t.network, d)),
        };
        json!({
            "role": role,
            "key": hex(&key),
            "pins": {"receive": pin(receive), "refund": pin(refund)},
        })
    }

    fn buyer_party(doc: &Value) -> Value {
        party_json(validated(doc).terms(), "buyer")
    }

    /// The vector with every KCC-20 leg's template replaced by the first pinned kcc20.sil build,
    /// and its terms hash recomputed. The golden vectors name a synthetic token (a227fc3a,
    /// 40+1420) that is no kcc20.sil build, so no funding instruction is given for them
    /// (`SDK_TEMPLATE_UNPINNED`, as `impulse address` refuses them). Pinning twice changes nothing.
    fn pin(doc: &Value) -> Value {
        let triple = &PINNED_KCC20_TEMPLATES[0].triple;
        let mut out = doc.clone();
        for leg in ["asset_leg", "cash_leg"] {
            if out["terms"][leg]["kind"] == "kcc20" {
                out["terms"][leg]["template_hash"] = json!(hex(&triple.hash));
                out["terms"][leg]["template_prefix_len"] = json!(triple.prefix_len);
                out["terms"][leg]["template_suffix_len"] = json!(triple.suffix_len);
            }
        }
        out["terms_hash"] = json!(hex(&validated(&out).terms_hash()));
        out
    }

    /// Runs the instructions for the buyer of the vector (with its tokens pinned, see `pin`),
    /// unless the options name a party.
    fn run(doc: &Value, options: &Value) -> Result<Value, Failure> {
        let doc = &pin(doc);
        let mut options = options.clone();
        if options.get("party").is_none() {
            options["party"] = buyer_party(doc);
        }
        instructions(
            &validated(doc),
            &funding_options_from_json(&options).expect("options"),
        )
    }

    /// Runs the instructions on the terms exactly as given (the buyer's role unless the options
    /// name a party): the vector as committed, with its synthetic token.
    fn run_as_is(doc: &Value, options: &Value) -> Result<Value, Failure> {
        let mut options = options.clone();
        if options.get("party").is_none() {
            options["party"] = buyer_party(doc);
        }
        instructions(
            &validated(doc),
            &funding_options_from_json(&options).expect("options"),
        )
    }

    fn code(r: Result<Value, Failure>) -> &'static str {
        use crate::error::Refusal;
        r.expect_err("a refusal").code()
    }

    fn vault_file(name: &str) -> Value {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/vaults");
        let text = std::fs::read_to_string(dir.join(name)).expect("vault vector");
        serde_json::from_str(&text).unwrap()
    }

    /// The golden vault files, byte for byte, from the SDK's own vault instantiation of the
    /// vectors as committed: the anchor that the funding instructions below cannot give, since
    /// they refuse these synthetic tokens.
    #[test]
    fn every_vector_gets_the_vault_addresses_of_the_golden_files() {
        for (name, doc) in vectors() {
            let terms = validated(&doc);
            let ctx = CreationContext::new(terms.terms().network, 400_000_000);
            let vaults = vault_file(&name);
            assert_eq!(
                hex(&template::check().unwrap().hash()),
                vaults["template_hash"],
                "{name}: template hash"
            );
            assert_eq!(
                hex(&terms.terms_hash()),
                doc["terms_hash"],
                "{name}: terms hash"
            );
            for (leg, key) in [
                (LegIndex::Asset, "asset_vault"),
                (LegIndex::Cash, "cash_vault"),
            ] {
                let want = &vaults[key];
                match Vault::instantiate_for_creation(&terms, leg, &ctx) {
                    Ok(fundable) => {
                        assert!(want["refused"].is_null(), "{name}: {key}");
                        assert_eq!(
                            address::vault_address(&fundable),
                            want["address"].as_str().unwrap(),
                            "{name}: {key}"
                        );
                        assert_eq!(
                            hex(&fundable.vault().script_hash()),
                            want["script_hash"].as_str().unwrap(),
                            "{name}: {key}"
                        );
                    }
                    Err(TemplateError::NoVault { .. }) => {
                        assert_eq!(want["refused"], "TEMPLATE_NO_VAULT", "{name}: {key}");
                    }
                    Err(e) => panic!("{name}: {key}: {e}"),
                }
            }
        }
    }

    /// The instructions of every vector, its tokens pinned: the terms hash, the template hash,
    /// every vault address and every URI are the ones the SDK's own vault instantiation of the
    /// same terms gives, and the URI is joined here from the address, the amount and the hash.
    #[test]
    fn every_vector_gets_the_vault_addresses_and_uris_of_its_terms() {
        let mut uris = 0;
        for (name, doc) in vectors() {
            let doc = pin(&doc);
            let network = doc["terms"]["network"].as_str().unwrap().to_string();
            let got = run(&doc, &lifted(&network)).unwrap_or_else(|e| panic!("{name}: {e}"));
            let terms = validated(&doc);
            let ctx = CreationContext::new(terms.terms().network, 400_000_000);
            assert_eq!(got["terms_hash"], doc["terms_hash"], "{name}: terms hash");
            assert_eq!(
                got["template_hash"],
                hex(&template::check().unwrap().hash()),
                "{name}: template hash"
            );
            for (i, leg) in LegIndex::ALL.into_iter().enumerate() {
                let leg_out = &got["legs"][i];
                let leg_terms = &doc["terms"][if i == 0 { "asset_leg" } else { "cash_leg" }];
                match Vault::instantiate_for_creation(&terms, leg, &ctx) {
                    Ok(fundable) => {
                        let address = address::vault_address(&fundable);
                        assert_eq!(leg_out["vault"]["address"], address, "{name}: leg {i}");
                        assert_eq!(
                            leg_out["vault"]["script_hash"],
                            hex(&fundable.vault().script_hash()),
                            "{name}: leg {i}"
                        );
                        assert!(leg_out["no_vault_reason"].is_null(), "{name}: leg {i}");
                        if leg_terms["kind"] == "kas" {
                            uris += 1;
                            let want = format!(
                                "{address}?amount={}&impulse={}",
                                leg_terms["amount"].as_str().unwrap(),
                                doc["terms_hash"].as_str().unwrap()
                            );
                            assert_eq!(leg_out["funding_uri"], want, "{name}: leg {i}");
                        } else {
                            assert!(
                                leg_out["funding_uri"].is_null(),
                                "{name}: leg {i} has no URI"
                            );
                        }
                    }
                    Err(TemplateError::NoVault { .. }) => {
                        assert!(leg_out["vault"].is_null(), "{name}: leg {i}");
                        assert!(leg_out["funding_uri"].is_null(), "{name}: leg {i}");
                        assert!(leg_out["no_vault_reason"].is_string(), "{name}: leg {i}");
                    }
                    Err(e) => panic!("{name}: leg {i}: {e}"),
                }
            }
        }
        assert!(uris >= 3, "the vectors hold KAS legs with vaults ({uris})");
    }

    #[test]
    fn funding_uris_equal_the_command_lines() {
        use impulse_cli::trade::FundableTrade;
        for (name, doc) in vectors() {
            let doc = pin(&doc);
            let terms = validated(&doc);
            let network = terms.terms().network;
            let ctx = CreationContext::new(network, 400_000_000);
            let trade = FundableTrade::new(terms.clone(), &ctx).unwrap();
            let got = run(&doc, &lifted(network_name(network))).unwrap();
            for (i, leg) in LegIndex::ALL.into_iter().enumerate() {
                let cli = impulse_cli::uri::funding_uri(&trade, leg);
                assert_eq!(
                    got["legs"][i]["funding_uri"].as_str().map(String::from),
                    cli,
                    "{name}: leg {i}"
                );
            }
        }
    }

    #[test]
    fn the_value_cap_matches_the_command_lines_on_every_case() {
        use impulse_cli::value_cap::CapPolicy;
        // Vector 02: KCC-20 asset against KAS cash; vector 01: KCC-20 against KCC-20.
        let policy = CapPolicy::new(None, false).unwrap();
        for prefix in ["01-", "02-"] {
            let base = validated(&vector(prefix));
            for cash in [
                1u64,
                999_999_999,
                1_000_000_000,
                1_000_000_001,
                2_500_000_000_000,
            ] {
                for declared in [
                    None,
                    Some(0),
                    Some(1),
                    Some(1_000_000_000),
                    Some(1_000_000_001),
                ] {
                    let mut t = base.terms().clone();
                    if t.cash_leg.kind == LegKind::Kas {
                        t.cash_leg.amount = cash;
                    }
                    let cli = policy.check(&t, declared);
                    let sdk = value::measure(&t, &ValueDeclaration::new(declared, None, false), 0)
                        .map(|v| v.expect("the risk is not accepted, so a value is measured"));
                    let cli_code = cli.as_ref().err().map(|e| e.code().replace("CLI_", "SDK_"));
                    let sdk_code = sdk.as_ref().err().map(|e| e.code().to_string());
                    assert_eq!(
                        sdk_code, cli_code,
                        "{prefix} cash {cash} declared {declared:?}"
                    );
                    if let Ok(v) = sdk {
                        assert!(cli
                            .unwrap()
                            .contains(&format!("trade value {} sompi", v.value)));
                    }
                }
            }
        }
    }

    #[test]
    fn a_refusal_returns_nothing_and_each_has_an_accepted_control() {
        let doc = vector("08-");
        assert_eq!(doc["terms"]["network"], "testnet");
        assert!(run(&doc, &options("testnet")).is_ok(), "control");
        // Network: the context must be the terms' network.
        assert_eq!(
            code(run(&doc, &options("mainnet"))),
            "TERMS_NETWORK_MISMATCH"
        );
        // Expiry in the past of the creation DAA score.
        let mut late = options("testnet");
        late["context"]["creation_daa"] = json!("999999999999");
        assert_eq!(code(run(&doc, &late)), "TERMS_EXPIRY_NOT_AFTER_CREATION");
        // A declaration is required for a v1 trade, and 0 is none.
        let mut none = options("testnet");
        none.as_object_mut().unwrap().remove("kas_equivalent");
        assert_eq!(code(run(&doc, &none)), "SDK_VALUE_UNKNOWN");
        let mut zero = options("testnet");
        zero["kas_equivalent"] = json!("0");
        assert_eq!(code(run(&doc, &zero)), "SDK_VALUE_UNKNOWN");
        // At the cap passes, one sompi above is refused.
        let mut at = options("testnet");
        at["kas_equivalent"] = json!("1000000000");
        assert!(run(&doc, &at).is_ok(), "at the cap");
        at["kas_equivalent"] = json!("1000000001");
        assert_eq!(code(run(&doc, &at)), "SDK_VALUE_CAP_EXCEEDED");
        // A lower cap binds; a cap above the default, or not a number, is invalid.
        let mut lower = options("testnet");
        lower["cap"] = json!("100000000");
        assert!(run(&doc, &lower).is_ok(), "value equals the lower cap");
        lower["cap"] = json!("99999999");
        assert_eq!(code(run(&doc, &lower)), "SDK_VALUE_CAP_EXCEEDED");
        for bad in ["1000000001", "10 KAS", "01", "-1", ""] {
            let mut o = options("testnet");
            o["cap"] = json!(bad);
            assert_eq!(code(run(&doc, &o)), "SDK_VALUE_CAP_INVALID", "cap {bad:?}");
        }
        // Mainnet needs a node-read DAA score.
        let main = vector("02-");
        let ok = run(&main, &lifted("mainnet"));
        assert!(ok.is_ok(), "control: node-read score: {:?}", ok.err());
        let mut typed = lifted("mainnet");
        typed["creation_daa_source"] = json!("typed");
        assert_eq!(code(run(&main, &typed)), "SDK_MAINNET_NEEDS_NODE");
        // A typed score is fine on testnet.
        let mut typed_test = options("testnet");
        typed_test["creation_daa_source"] = json!("typed");
        assert!(run(&doc, &typed_test).is_ok(), "typed score on testnet");
    }

    #[test]
    fn direct_terms_have_no_vault_and_a_kcc20_leg_has_a_vault_and_no_uri() {
        // Direct vector 11: KCC-20 asset against KAS cash, Direct mode, so no vault and no URI.
        let got = run(&vector("11-"), &lifted("mainnet")).unwrap();
        for leg in got["legs"].as_array().unwrap() {
            assert!(leg["vault"].is_null() && leg["funding_uri"].is_null());
        }
        // Vector 02 pays one URI, on the cash leg; the KCC-20 asset leg has a vault and none.
        let got = run(&vector("02-"), &lifted("mainnet")).unwrap();
        assert!(got["legs"][0]["vault"].is_object() && got["legs"][0]["funding_uri"].is_null());
        assert!(got["legs"][1]["funding_uri"].is_string());
    }

    #[test]
    fn the_lift_skips_the_value_checks_and_only_them() {
        let doc = vector("02-"); // 25,000 KAS cash leg
        assert_eq!(
            code(run(&doc, &options("mainnet"))),
            "SDK_VALUE_CAP_EXCEEDED"
        );
        let got = run(&doc, &lifted("mainnet")).unwrap();
        assert_eq!(got["value"]["lifted"], true);
        assert!(got["value"]["cap"].is_null());
        // The other checks still run when the cap is lifted.
        assert_eq!(
            code(run(&doc, &lifted("testnet"))),
            "TERMS_NETWORK_MISMATCH"
        );
        let mut typed = lifted("mainnet");
        typed["creation_daa_source"] = json!("typed");
        assert_eq!(code(run(&doc, &typed)), "SDK_MAINNET_NEEDS_NODE");
        // Not a boolean: a form refusal, not a lift.
        let mut text = options("mainnet");
        text["accept_the_risk"] = json!("true");
        assert!(funding_options_from_json(&text).is_err());
        // The cap of the builders (value.rs) holds here too: a cap lowered and the risk accepted
        // contradict each other, and a malformed cap is refused whether or not the risk is
        // accepted.
        let mut pair = lifted("mainnet");
        pair["cap"] = json!("100000000");
        assert_eq!(code(run(&doc, &pair)), "SDK_VALUE_CAP_INVALID");
        let mut bad = lifted("mainnet");
        bad["cap"] = json!("10 KAS");
        assert_eq!(code(run(&doc, &bad)), "SDK_VALUE_CAP_INVALID");
    }

    #[test]
    fn options_are_strict() {
        let mut ok = options("testnet");
        ok["party"] = buyer_party(&vector("08-"));
        assert!(funding_options_from_json(&ok).is_ok(), "control");
        let mut extra = ok.clone();
        extra["note"] = json!("x");
        assert!(funding_options_from_json(&extra).is_err(), "unknown key");
        let mut bad_source = ok.clone();
        bad_source["creation_daa_source"] = json!("node ");
        assert!(funding_options_from_json(&bad_source).is_err(), "source");
        let mut no_context = ok.clone();
        no_context.as_object_mut().unwrap().remove("context");
        assert!(funding_options_from_json(&no_context).is_err(), "context");
        let mut no_party = ok.clone();
        no_party.as_object_mut().unwrap().remove("party");
        assert!(funding_options_from_json(&no_party).is_err(), "party");
        let mut number = ok;
        number["kas_equivalent"] = json!(5);
        assert!(
            funding_options_from_json(&number).is_err(),
            "a number is not a u64 string"
        );
    }

    /// What the command line's terms summary appends to a destination for whom it pays.
    fn cli_whose(pays: &str) -> &'static str {
        match pays {
            "seller_key" => " = seller_key",
            "buyer_key" => " = buyer_key",
            "authority_key" => " = authority_key",
            "other_key" => " (a key that is neither party's nor the authority's)",
            "script" => " (a script: check who controls it)",
            "off_chain" => "",
            other => panic!("unknown pays {other}"),
        }
    }

    #[test]
    fn destinations_read_as_the_command_lines_terms_summary_reads_them_on_every_vector() {
        use impulse_cli::summary::summary;
        let mut marks = std::collections::BTreeSet::new();
        for (name, doc) in vectors() {
            let terms = validated(&doc);
            let network = terms.terms().network;
            let got = run(&doc, &lifted(network_name(network))).unwrap();
            let lines = summary(&terms.terms_hash(), terms.terms(), 400_000_000);
            let dests = got["destinations"].as_array().unwrap();
            let order = [
                "buyer_delivery",
                "seller_proceeds",
                "seller_refund",
                "buyer_refund",
            ];
            assert_eq!(dests.len(), 4, "{name}");
            for (d, field) in dests.iter().zip(order) {
                assert_eq!(d["name"], field, "{name}");
                let want = lines
                    .iter()
                    .find_map(|l| l.strip_prefix(&format!("{field}: ")))
                    .unwrap_or_else(|| panic!("{name}: no CLI line for {field}"));
                let pays = d["pays"].as_str().unwrap();
                marks.insert(pays.to_string());
                assert_eq!(
                    format!("{}{}", d["destination"].as_str().unwrap(), cli_whose(pays)),
                    want,
                    "{name}: {field}"
                );
                // Only the two parties' own keys on their own destinations are legitimate: none
                // of the golden vectors pays the counterparty or the authority.
                assert_eq!(
                    d["pays_counterparty_or_authority"], false,
                    "{name}: {field}"
                );
                assert!(d["mark"].as_str().unwrap().len() > 4, "{name}: {field}");
            }
        }
        // The vectors between them exercise every way a destination can pay.
        for pays in ["buyer_key", "seller_key", "script", "off_chain"] {
            assert!(marks.contains(pays), "no vector pays {pays}: {marks:?}");
        }
    }

    #[test]
    fn a_destination_that_pays_the_counterparty_or_the_authority_is_flagged_as_the_role_check_refuses_it(
    ) {
        use impulse_cli::summary::{check_party, Party, Pins, Role};
        use impulse_core::terms::{Kcc20Owner, Terms};
        use kaspa_consensus_core::tx::ScriptPublicKey;
        let base = validated(&vector("08-"));
        let p2pk = |key: [u8; 32]| {
            Destination::Kas(ScriptPublicKey::from_vec(
                0,
                [&[0x20][..], &key, &[0xac]].concat(),
            ))
        };
        let pubkey_owner = |key: [u8; 32]| {
            Destination::Kcc20(Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: key,
            })
        };
        // The instructions refuse the role whose own destination is the attack, so each case is
        // run as the other role: the flag is the page's warning to the party that is attacked.
        let flags = |t: &Terms, as_role: &str| -> Vec<bool> {
            let terms_json: Value = serde_json::from_str(&crate::json::terms_to_json(t)).unwrap();
            let doc = json!({ "terms": terms_json });
            let mut o = options("testnet");
            o["party"] = party_json(t, as_role);
            let got = run(&doc, &o).unwrap();
            got["destinations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["pays_counterparty_or_authority"].as_bool().unwrap())
                .collect()
        };
        let t = base.terms().clone();
        // Control: the vector's own destinations pay their owners or a script.
        assert_eq!(flags(&t, "buyer"), [false; 4]);
        let buyer = Party {
            role: Role::Buyer,
            key: t.buyer_key,
            pins: Pins::default(),
        };
        let seller = Party {
            role: Role::Seller,
            key: t.seller_key,
            pins: Pins::default(),
        };
        assert!(
            check_party(&t, &buyer).is_ok(),
            "control: the command line accepts the buyer's own"
        );
        // Order of the flags: buyer_delivery, seller_proceeds, seller_refund, buyer_refund.
        let cases: [(&str, Terms, usize, Party); 5] = [
            (
                "buyer_refund pays the seller",
                Terms {
                    buyer_refund: p2pk(t.seller_key),
                    ..t.clone()
                },
                3,
                buyer.clone(),
            ),
            (
                "buyer_delivery is a KCC-20 pubkey owner equal to the seller",
                Terms {
                    buyer_delivery: pubkey_owner(t.seller_key),
                    ..t.clone()
                },
                0,
                buyer.clone(),
            ),
            (
                "buyer_refund pays the authority",
                Terms {
                    buyer_refund: p2pk(t.authority_key.unwrap()),
                    ..t.clone()
                },
                3,
                buyer.clone(),
            ),
            (
                "seller_proceeds pays the buyer",
                Terms {
                    seller_proceeds: p2pk(t.buyer_key),
                    ..t.clone()
                },
                1,
                seller.clone(),
            ),
            (
                "seller_refund is a KCC-20 pubkey owner equal to the authority",
                Terms {
                    seller_refund: pubkey_owner(t.authority_key.unwrap()),
                    ..t.clone()
                },
                2,
                seller.clone(),
            ),
        ];
        for (what, terms, at, party) in cases {
            let got = flags(
                &terms,
                if party.role == Role::Buyer {
                    "seller"
                } else {
                    "buyer"
                },
            );
            assert!(got[at], "{what}: flagged ({got:?})");
            assert_eq!(
                got.iter().filter(|f| **f).count(),
                1,
                "{what}: only that one"
            );
            let refused = check_party(&terms, &party).unwrap_err();
            assert_eq!(refused.code(), "CLI_DESTINATION_NOT_MINE", "{what}");
        }
        // A destination that pays its own owner is not flagged, and the command line accepts it.
        let own = Terms {
            buyer_refund: p2pk(t.buyer_key),
            ..t.clone()
        };
        assert_eq!(flags(&own, "buyer"), [false; 4]);
        assert!(check_party(&own, &buyer).is_ok());
    }

    #[test]
    fn a_kcc20_leg_carries_the_unassessed_warning_of_impulse_core_and_other_legs_none() {
        for (name, doc) in vectors() {
            let doc = pin(&doc);
            let terms = validated(&doc);
            let network = terms.terms().network;
            let got = run(&doc, &lifted(network_name(network))).unwrap();
            let core = verify::token_warnings(&terms, None, None).unwrap();
            for (i, leg) in LegIndex::ALL.into_iter().enumerate() {
                let want: Vec<Value> = core
                    .iter()
                    .filter(|w| w.leg == leg)
                    .map(|w| json!({"code": w.code(), "message": w.to_string()}))
                    .collect();
                assert_eq!(
                    got["legs"][i]["token_warnings"],
                    json!(want),
                    "{name}: leg {i}"
                );
                let is_kcc20 = got["legs"][i]["kind"] == "kcc20";
                assert_eq!(want.len(), usize::from(is_kcc20), "{name}: leg {i}");
                if is_kcc20 {
                    assert_eq!(want[0]["code"], "TOKEN_UNASSESSED", "{name}: leg {i}");
                }
            }
        }
    }

    #[test]
    fn the_time_left_is_the_command_lines() {
        use impulse_cli::summary::approx_duration as cli;
        for daa in [
            0,
            1,
            599,
            600,
            36_000,
            71_999,
            72_000,
            863_999,
            1_728_000,
            4_000_000_000,
            u64::MAX,
        ] {
            assert_eq!(approx_duration(daa), cli(daa), "{daa}");
        }
        let got = run(&vector("08-"), &options("testnet")).unwrap();
        // Vector 08: expiry 425,920,000, creation 400,000,000.
        assert_eq!(got["expiry"]["expiry_daa"], "425920000");
        assert_eq!(got["expiry"]["time_left"], cli(25_920_000));
    }

    /// A copy of the vector's terms with the asset token's template triple replaced.
    fn with_asset_triple(doc: &Value, hash: [u8; 32], prefix: u64, suffix: u64) -> ValidatedTerms {
        let mut out = doc.clone();
        out["terms"]["asset_leg"]["template_hash"] = json!(hex(&hash));
        out["terms"]["asset_leg"]["template_prefix_len"] = json!(prefix);
        out["terms"]["asset_leg"]["template_suffix_len"] = json!(suffix);
        validated(&out)
    }

    #[test]
    fn the_pinned_template_check_is_the_command_lines_on_every_vector_and_on_near_misses() {
        use impulse_cli::trade::check_pinned as cli;
        let sdk_text = |t: &ValidatedTerms| check_pinned(t).err().map(|e| e.to_string());
        let cli_text = |t: &ValidatedTerms| cli(t.terms()).err().map(|e| e.to_string());
        let mut refused = 0;
        // The eleven vectors as committed: their synthetic token is no kcc20.sil build.
        for (name, doc) in vectors() {
            let t = validated(&doc);
            let (a, b) = (sdk_text(&t), cli_text(&t));
            assert!(a.is_some(), "{name}: the synthetic token is refused");
            refused += 1;
            assert_eq!(
                a.unwrap()
                    .replacen("SDK_TEMPLATE_UNPINNED", "CLI_TEMPLATE_UNPINNED", 1),
                b.unwrap(),
                "{name}: the same refusal, the same words"
            );
            // The same terms with their tokens pinned are accepted by both.
            let pinned = validated(&pin(&doc));
            assert_eq!(sdk_text(&pinned), None, "{name}: pinned control");
            assert_eq!(cli_text(&pinned), None, "{name}: pinned control (CLI)");
        }
        assert_eq!(refused, 11);
        // Every pinned build is accepted, and the same build one byte off in any of its three
        // parts is not, by both. A near miss on the cash leg is refused as the cash leg's.
        let base = vector("08-");
        for p in &PINNED_KCC20_TEMPLATES {
            let t = &p.triple;
            let exact = with_asset_triple(&base, t.hash, t.prefix_len, t.suffix_len);
            assert_eq!(sdk_text(&exact), None, "pinned {}", hex(&t.hash));
            assert_eq!(cli_text(&exact), None);
            let mut flipped = t.hash;
            flipped[31] ^= 1;
            for (what, near) in [
                (
                    "hash",
                    with_asset_triple(&base, flipped, t.prefix_len, t.suffix_len),
                ),
                (
                    "prefix",
                    with_asset_triple(&base, t.hash, t.prefix_len + 1, t.suffix_len),
                ),
                (
                    "suffix",
                    with_asset_triple(&base, t.hash, t.prefix_len, t.suffix_len + 1),
                ),
            ] {
                assert!(sdk_text(&near).is_some(), "{what} off by one is refused");
                assert_eq!(
                    sdk_text(&near).map(|m| m.replacen("SDK_", "CLI_", 1)),
                    cli_text(&near),
                    "{what}"
                );
            }
        }
        // The cash leg is checked too (vector 01 is KCC-20 against KCC-20), and named as the cash leg.
        let both = pin(&vector("01-"));
        assert_eq!(
            sdk_text(&validated(&both)),
            None,
            "control: both legs pinned"
        );
        let mut cash = both.clone();
        cash["terms"]["cash_leg"]["template_suffix_len"] = json!(7);
        let t = validated(&cash);
        assert!(sdk_text(&t)
            .unwrap()
            .contains("the cash leg's KCC-20 template"));
        assert_eq!(
            sdk_text(&t).map(|m| m.replacen("SDK_", "CLI_", 1)),
            cli_text(&t)
        );
    }

    #[test]
    fn the_kas_minimum_is_the_command_lines() {
        use crate::error::Refusal;
        use impulse_cli::trade::check_kas_minimum as cli;
        for amount in [
            1u64,
            MIN_KAS_OUTPUT - 1,
            MIN_KAS_OUTPUT,
            MIN_KAS_OUTPUT + 1,
            100_000_000,
        ] {
            let mut doc = vector("08-");
            doc["terms"]["cash_leg"]["amount"] = json!(amount.to_string());
            let t = validated(&doc);
            let (sdk, theirs) = (check_kas_minimum(&t), cli(t.terms()));
            assert_eq!(sdk.is_err(), theirs.is_err(), "cash {amount}");
            if let Err(e) = sdk {
                assert_eq!(e.code(), "TX_BELOW_MIN_KAS", "cash {amount}");
                assert!(e
                    .to_string()
                    .contains(&format!("would hold {amount} sompi")));
                assert_eq!(theirs.unwrap_err().code(), "CLI_KAS_LEG_BELOW_MIN");
            }
        }
        // A KCC-20 cash leg has no KAS minimum to meet (vector 01), by both.
        let t = validated(&vector("01-"));
        assert!(check_kas_minimum(&t).is_ok() && cli(t.terms()).is_ok());
    }

    #[test]
    fn no_instruction_is_given_for_an_unpinned_token_or_a_cash_leg_below_the_minimum() {
        let mut doc = vector("08-");
        // The vector as committed: refused, after the creation checks and before the role check.
        assert_eq!(
            code(run_as_is(&doc, &options("testnet"))),
            "SDK_TEMPLATE_UNPINNED"
        );
        assert!(
            run(&doc, &options("testnet")).is_ok(),
            "control: the same terms, token pinned"
        );
        assert_eq!(
            code(run_as_is(&doc, &options("mainnet"))),
            "TERMS_NETWORK_MISMATCH",
            "the creation checks come first"
        );
        let mut stranger = options("testnet");
        let mut party = buyer_party(&doc);
        party["key"] = json!("ab".repeat(32));
        stranger["party"] = party.clone();
        assert_eq!(
            code(run_as_is(&doc, &stranger)),
            "SDK_TEMPLATE_UNPINNED",
            "the template check comes before the role check"
        );
        assert_eq!(
            code(run(&doc, &stranger)),
            "SDK_ROLE_KEY_MISMATCH",
            "control: pinned"
        );
        // A cash leg below the minimum, token pinned: refused, and 0.5 KAS exactly accepted.
        doc["terms"]["cash_leg"]["amount"] = json!((MIN_KAS_OUTPUT - 1).to_string());
        assert_eq!(code(run(&doc, &options("testnet"))), "TX_BELOW_MIN_KAS");
        doc["terms"]["cash_leg"]["amount"] = json!(MIN_KAS_OUTPUT.to_string());
        assert!(
            run(&doc, &options("testnet")).is_ok(),
            "exactly the minimum"
        );
        // Both wrong: the minimum is told first, as the command line does.
        let mut both = vector("08-");
        both["terms"]["cash_leg"]["amount"] = json!("1");
        assert_eq!(
            code(run_as_is(&both, &options("testnet"))),
            "TX_BELOW_MIN_KAS"
        );
    }

    #[test]
    fn kas_has_eight_decimals() {
        assert_eq!(kas(0), "0.00000000");
        assert_eq!(kas(1), "0.00000001");
        assert_eq!(kas(1_000_000_000), "10.00000000");
        assert_eq!(kas(u64::MAX), "184467440737.09551615");
    }

    #[test]
    fn a_qr_code_is_square_deterministic_and_bound_to_its_text() {
        let a = qr("kaspa:abc?amount=1&impulse=00").unwrap();
        assert_eq!(a.modules.len(), a.width * a.width);
        assert!(a.modules.iter().all(|m| *m <= 1));
        assert_eq!(qr("kaspa:abc?amount=1&impulse=00").unwrap(), a);
        assert_ne!(qr("kaspa:abc?amount=2&impulse=00").unwrap(), a);
        // The three finder patterns: a dark 7 by 7 ring at three corners.
        let w = a.width;
        for (x, y) in [(0, 0), (w - 7, 0), (0, w - 7)] {
            assert_eq!(a.modules[y * w + x], 1);
            assert_eq!(a.modules[(y + 3) * w + x + 3], 1);
            assert_eq!(a.modules[(y + 1) * w + x + 1], 0);
        }
        // Control above, refusal here: more bytes than the largest code holds.
        let too_long = "x".repeat(3000);
        assert_eq!(qr(&too_long).unwrap_err().code(), "SDK_QR");
    }
}
