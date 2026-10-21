// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The in-page wallet of the browser demo (I11 phase 2), and with `signing.rs` of impulse-cli the
//! only code in Impulse that holds a private key. A [`Wallet`] draws its 32-byte key once, from
//! the browser's `crypto.getRandomValues` (the `wasm_js` backend of getrandom), and holds it in
//! wasm memory in a buffer that is zeroed on drop and on [`Wallet::wipe`]. JavaScript gets an
//! opaque handle: there is no call that returns the key, a string of it, or anything derived from
//! it but the public key and the signatures. The key is never written, sent or logged: this
//! module has no I/O, and no refusal message carries a byte of it.
//!
//! What it cannot promise: the 32 bytes cross once from the browser's `getRandomValues` into
//! wasm memory (the browser's copy is out of reach), the C library keeps no secret beyond the
//! call that uses it but the compiler and the allocator may leave copies of a stack or heap
//! buffer (the key pair is erased with secp256k1's `non_secure_erase`, which documents the same
//! limit), and wasm linear memory is not cleared when the page unloads. A page that is closed
//! loses the key with the tab; the wipe on unload narrows the window while the tab lives.
//!
//! Signing is a single call that does what the command line's `ipst sign` does, in the order
//! of spec/CLI.md: the mainnet choice, the key signs something, the document is what the
//! builders make from its inputs and is within the value cap (`Ipst::verify_against_terms`), for
//! a funding the checks of step 6 (the key is the leg's depositor, the terms are fundable at the
//! current DAA score, and the two "Before funding" checks: the KAS minimum and the pinned KCC-20
//! template), the role check when the key is a party's, the payer's checks and what the signer
//! commits (`payer.rs`: where the change goes, the fee, the top-up of under-funded outputs, the
//! outflow), then the signature, which is verified before it is stored. The signature is deterministic
//! BIP-340 (zero auxiliary randomness), so signing draws no randomness.
//!
//! The wallet's key lives only in the page. Anything paid to it (a delivered token, proceeds, a
//! refund, change) can be spent only as a fee input or a token input of a later Impulse
//! transaction built here, and is lost with the page. So on mainnet the role check and the change
//! check refuse a destination that pays a key of a wallet of the page (`SDK_DESTINATION_IN_WALLET`)
//! unless the user names an address elsewhere; on testnet the result says so.
//!
//! Adapted from `crates/impulse-cli/src/signing.rs` (same author): the key pair, the
//! `non_secure_erase`, the self-check and the 65-byte form, without the key file.

use crate::error::{Failure, SdkError};
use crate::forms;
use crate::funding;
use crate::json::Obj;
use crate::ops;
use crate::payer::{self, Accept};
use crate::review::{self, p2pk};
use crate::role::{self, Pins};
use crate::value;
use impulse_core::template::{LegIndex, TemplateError, Vault};
use impulse_core::terms::{CreationContext, Network};
use impulse_core::tx::{self, Ipst, IpstKind, TxError, MIN_KCC20_OUTPUT};
use secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey, SECP256K1};
use serde_json::Value;
use zeroize::Zeroizing;

/// `SIG_HASH_ALL`, the only sighash type Impulse signs with.
const SIG_HASH_ALL: u8 = 0x01;

/// A wallet: one key, held until it is wiped or dropped.
pub(crate) struct Wallet {
    /// Boxed, so that building and moving a wallet moves a pointer and copies no key bytes.
    secret: Option<Zeroizing<Box<[u8]>>>,
    public: [u8; 32],
}

impl Wallet {
    /// The wallet of a secret, or None if the 32 bytes are not a valid secp256k1 key (zero, or at
    /// or above the group order). The bytes are zeroed on every path.
    pub(crate) fn from_secret(secret: Zeroizing<Box<[u8]>>) -> Option<Wallet> {
        let mut keypair = Keypair::from_seckey_slice(SECP256K1, &secret[..]).ok()?;
        let public = keypair.x_only_public_key().0.serialize();
        keypair.non_secure_erase();
        Some(Wallet {
            secret: Some(secret),
            public,
        })
    }

    /// A new wallet from `fill`, which writes 32 random bytes. A draw that is not a valid key (one
    /// in 2^128) is drawn again, at most eight times.
    pub(crate) fn generate(
        mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), SdkError>,
    ) -> Result<Wallet, SdkError> {
        for _ in 0..8 {
            let mut bytes = Zeroizing::new(vec![0u8; 32].into_boxed_slice());
            let array: &mut [u8; 32] = (&mut bytes[..]).try_into().expect("32 bytes");
            fill(array)?;
            if let Some(wallet) = Wallet::from_secret(bytes) {
                return Ok(wallet);
            }
        }
        Err(SdkError::WalletRandom {
            reason: "eight draws in a row were not a valid key".into(),
        })
    }

    /// The x-only public key. Public, and still known after a wipe.
    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub(crate) fn is_wiped(&self) -> bool {
        self.secret.is_none()
    }

    /// Zeroes the key now. Every later signature is `SDK_WALLET_WIPED`.
    pub(crate) fn wipe(&mut self) {
        self.secret = None;
    }

    /// The 65-byte signature of a 32-byte digest: a BIP-340 Schnorr signature and `SIG_HASH_ALL`,
    /// checked against the wallet's public key before it is returned.
    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], SdkError> {
        let secret = self.secret.as_ref().ok_or(SdkError::WalletWiped)?;
        let mut keypair = Keypair::from_seckey_slice(SECP256K1, &secret[..])
            .map_err(|_| SdkError::WalletWiped)?;
        let message = Message::from_digest(*digest);
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair);
        keypair.non_secure_erase();
        let sig64: [u8; 64] = *sig.as_ref();
        #[cfg(all(test, not(target_arch = "wasm32")))]
        let sig64 = tests::corrupt::apply(sig64);
        let failed = || SdkError::SignSelfCheck;
        let key = XOnlyPublicKey::from_slice(&self.public).map_err(|_| failed())?;
        let checked = schnorr::Signature::from_slice(&sig64).map_err(|_| failed())?;
        SECP256K1
            .verify_schnorr(&checked, &message, &key)
            .map_err(|_| failed())?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig64);
        out[64] = SIG_HASH_ALL;
        Ok(out)
    }
}

/// What the page tells the wallet about the document it is asked to sign.
pub(crate) struct SignOptions {
    /// `{ asset, cash }`, the KCC-20 artifact texts, as for `verify_against_terms`.
    pub artifacts: Value,
    pub current_daa: u64,
    /// The value declaration of the builders (the cap holds at signing).
    pub value: Value,
    /// Whether the user chose mainnet explicitly.
    pub mainnet: bool,
    /// The user's pins, when the wallet's key is a party's.
    pub pins: Pins,
    /// The keys that live only in wallets of the page, besides this wallet's own.
    pub held: Vec<[u8; 32]>,
    /// Where the change of a fee input must pay: an address, else the wallet's own key.
    pub change: Option<String>,
    /// The most fee the signer accepts, else twice the minimum relay fee (three fee inputs).
    pub max_fee: Option<u64>,
    /// The most the fee inputs may add to the trade outputs, else none.
    pub max_topup: u64,
    /// The KAS each token input the signer gives carries in a Direct transaction, and the KAS a
    /// KCC-20 funding puts on the escrowed token, else the minimum of a KCC-20 output.
    pub carrier: Option<u64>,
    /// The KAS a KCC-20 funding puts on the authorizer, else the minimum of a KAS output. For a
    /// KCC-20 funding only (`TX_WRONG_MODE` for any other document).
    pub authorizer: Option<u64>,
}

/// `{ artifacts, current_daa, value, mainnet, pins?, held?, change?, max_fee?, max_topup?,
/// carrier?, authorizer? }`.
pub(crate) fn sign_options_from_json(value: &Value) -> Result<SignOptions, SdkError> {
    let mut o = Obj::new(value, "options")?;
    let artifacts = o.value("artifacts")?.clone();
    let current_daa = o.u64("current_daa")?;
    let value = o.value("value")?.clone();
    let mainnet = o.bool("mainnet")?;
    let pins = role::pins_from(&mut o)?;
    let held = role::held_from(&mut o)?;
    let change = match o.optional("change") {
        None | Some(Value::Null) => None,
        Some(_) => Some(o.str("change")?.to_string()),
    };
    let mut amount = |key: &'static str| match o.optional(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => o.u64(key).map(Some),
    };
    let max_fee = amount("max_fee")?;
    let max_topup = amount("max_topup")?.unwrap_or(0);
    let carrier = amount("carrier")?;
    let authorizer = amount("authorizer")?;
    o.finish()?;
    Ok(SignOptions {
        artifacts,
        current_daa,
        value,
        mainnet,
        pins,
        held,
        change,
        max_fee,
        max_topup,
        carrier,
        authorizer,
    })
}

/// Step 6 of `ipst sign` (spec/CLI.md) for a funding transaction, which the CLI's `check_funding`
/// runs: the signer is the leg's depositor (the seller for the asset leg, the buyer for the cash
/// leg: `SDK_FUND_NOT_YOUR_LEG`, because a funding whose fee inputs another key holds could never
/// be completed); the terms pass the creation checks at the current DAA score, with every
/// escrowed leg a fundable vault (`TERMS_*`, `TEMPLATE_*`); and the two "Before funding" checks,
/// the KAS minimum and the pinned KCC-20 template (`TX_BELOW_MIN_KAS`, `SDK_TEMPLATE_UNPINNED`).
/// And for a KCC-20 funding, the KAS on the escrowed token (output 0) and on the authorizer
/// (output 1) equal the signer's `carrier` and `authorizer`, by default the minimum of a KCC-20
/// output and of a KAS output (`SDK_SIGN_DEPOSIT_MISMATCH`, the command line's
/// `CLI_IPST_DEPOSIT_MISMATCH`): the terms check takes both amounts from the document, so only the
/// signer can confirm them.
fn check_funding(
    ipst: &Ipst,
    kind: IpstKind,
    me: &[u8; 32],
    options: &SignOptions,
) -> Result<(), Failure> {
    let leg = match kind {
        IpstKind::FundKcc20(leg) => leg,
        _ => LegIndex::Cash,
    };
    let terms = ipst.terms();
    let t = terms.terms();
    let (who, depositor, name) = match leg {
        LegIndex::Asset => ("seller", t.seller_key, "asset"),
        LegIndex::Cash => ("buyer", t.buyer_key, "cash"),
    };
    if *me != depositor {
        return Err(SdkError::FundNotYourLeg {
            reason: format!(
                "this document funds the {name} leg, which the {who} funds (key {}); this wallet's key is {}",
                crate::json::hex(&depositor),
                crate::json::hex(me)
            ),
        }
        .into());
    }
    let ctx = CreationContext::new(t.network, options.current_daa);
    terms.validate_creation(&ctx)?;
    for leg in LegIndex::ALL {
        match Vault::instantiate_for_creation(terms, leg, &ctx) {
            Ok(_) | Err(TemplateError::NoVault { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    funding::check_before_funding(terms)?;
    if let IpstKind::FundKcc20(_) = kind {
        let outputs = &ipst.transaction().outputs;
        let carrier = options.carrier.unwrap_or(MIN_KCC20_OUTPUT);
        let authorizer = options.authorizer.unwrap_or(tx::MIN_KAS_OUTPUT);
        if outputs[0].value != carrier || outputs[1].value != authorizer {
            return Err(SdkError::SignDepositMismatch {
                carrier: outputs[0].value,
                authorizer: outputs[1].value,
                confirmed_carrier: carrier,
                confirmed_authorizer: authorizer,
            }
            .into());
        }
    }
    Ok(())
}

/// Signs every input of `ipst` that names the wallet's key and lacks a signature, after the
/// checks in the order the module comment lists. Returns the document with the signatures added
/// and the inputs signed; the document passed in is not changed.
pub(crate) fn sign_ipst(
    wallet: &Wallet,
    ipst: &Ipst,
    options: &SignOptions,
) -> Result<(Ipst, Vec<usize>), Failure> {
    if wallet.is_wiped() {
        return Err(SdkError::WalletWiped.into());
    }
    let me = wallet.public_key();
    let terms = ipst.terms().terms();
    match (terms.network, options.mainnet) {
        (Network::Mainnet, false) => return Err(SdkError::SignMainnetNotExplicit.into()),
        (Network::Testnet, true) => return Err(SdkError::SignNetworkMismatch.into()),
        _ => {}
    }
    let slots = ipst.slots();
    let mine: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.signer() == Some(me) && s.signature().is_none())
        .map(|(i, _)| i)
        .collect();
    if mine.is_empty() {
        let signed_already = slots.iter().any(|s| s.signer() == Some(me));
        return Err(SdkError::SignNothing {
            reason: if signed_already {
                "every input this key signs already has its signature"
            } else {
                "this key signs no input of the document"
            },
        }
        .into());
    }
    // The document is the transaction the builders make from its own inputs, and within the cap.
    let matched = ops::terms_match(
        ipst,
        &options.artifacts,
        options.current_daa,
        &options.value,
    )?;
    // `authorizer` confirms a KCC-20 funding's deposit and means nothing for another document.
    if options.authorizer.is_some() && !matches!(matched.kind, IpstKind::FundKcc20(_)) {
        return Err(TxError::WrongMode {
            reason: "authorizer confirms a KCC-20 funding's deposit, and carrier the KAS your token carries in a KCC-20 funding or a Direct trade",
        }
        .into());
    }
    // A funding: its depositor signs it, the terms are fundable now, "Before funding" holds, and
    // a KCC-20 deposit is the one the signer confirms.
    if payer::is_funding(matched.kind) {
        check_funding(ipst, matched.kind, &me, options)?;
    }
    // This wallet's key lives only in the page, and so do the options' held keys.
    let mut held = options.held.clone();
    if !held.contains(&me) {
        held.push(me);
    }
    // The key is a party's: the destinations of its role pay it, or what it pinned.
    if let Some(party) = role::party_of_key(terms, &me, options.pins.clone(), held.clone()) {
        role::check(terms, &party)?;
    }
    // The payer's side: where the change goes, the fee, the top-up, and what the signer commits.
    let accept = Accept {
        change: match &options.change {
            None => p2pk(&me),
            Some(text) => role::change_spk("options.change", text, terms.network)?,
        },
        max_fee: options.max_fee,
        max_topup: options.max_topup,
        carrier: options.carrier.unwrap_or(MIN_KCC20_OUTPUT),
        held,
    };
    let declaration = value::declaration_from_json(&options.value)?;
    payer::check(ipst, &matched, me, &mine, &accept, &declaration)?;
    // On mainnet no output of the transaction pays a key that lives only in the page: the
    // destinations of the role and the change were checked above, and this is every other output
    // (the seller's authorizer comes back to the seller's key, whatever the terms say).
    if terms.network == Network::Mainnet {
        let (asset, cash) = forms::artifacts(&options.artifacts)?;
        let stranded = review::held_outputs(ipst, &asset, cash.as_ref(), &accept.held);
        if !stranded.is_empty() {
            return Err(SdkError::DestinationInWallet {
                reasons: stranded
                    .iter()
                    .map(|(i, amount, at)| {
                        format!(
                            "output {i} of {amount} sompi pays {at}, a key that lives only in a wallet of this page"
                        )
                    })
                    .collect(),
            }
            .into());
        }
    }
    let mut signed = ipst.clone();
    for &input in &mine {
        let digest = tx::sighash(ipst.transaction(), ipst.entries(), input)?;
        let signature = wallet.sign_digest(&digest)?;
        signed.add_signature(input, &signature)?;
    }
    Ok((signed, mine))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::json::hex;
    use secp256k1::rand::RngCore;

    /// A filler that draws from the host's generator and remembers what it drew, so that a test
    /// can look for the secret where it must not be. Test code only; the draw is thrown away with
    /// the test.
    fn drawing(
        drawn: &mut Vec<[u8; 32]>,
    ) -> impl FnMut(&mut [u8; 32]) -> Result<(), SdkError> + '_ {
        move |bytes| {
            secp256k1::rand::thread_rng().fill_bytes(bytes);
            drawn.push(*bytes);
            Ok(())
        }
    }

    /// Test hook: corrupts the next signature before the self-check, so the self-check refusal is
    /// driven through `sign_digest` itself, as in the command line's signing module. Compiled
    /// only into native tests; per test thread. The refusal has no case in the TypeScript suite
    /// for that reason.
    pub(super) mod corrupt {
        use std::cell::Cell;

        thread_local! {
            static NEXT: Cell<bool> = const { Cell::new(false) };
        }

        pub(crate) fn arm() {
            NEXT.with(|n| n.set(true));
        }

        pub(crate) fn apply(mut sig: [u8; 64]) -> [u8; 64] {
            if NEXT.with(|n| n.replace(false)) {
                sig[10] ^= 1;
            }
            sig
        }
    }

    // The order of the secp256k1 group: a public constant, not a key. A secret at or above it, and
    // zero, are not keys.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    #[test]
    fn a_wallet_signs_what_verifies_under_its_public_key_and_nothing_else() {
        let mut drawn = Vec::new();
        let wallet = Wallet::generate(drawing(&mut drawn)).unwrap();
        assert_eq!(drawn.len(), 1, "one draw makes one key");
        let (digest, other) = ([7u8; 32], [8u8; 32]);
        let sig = wallet.sign_digest(&digest).unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(sig[64], SIG_HASH_ALL);
        let me = wallet.public_key();
        assert!(
            tx::verify_schnorr_sig65(&me, &digest, &sig).is_ok(),
            "control"
        );
        assert!(
            tx::verify_schnorr_sig65(&me, &other, &sig).is_err(),
            "not for another digest"
        );
        let mut elsewhere = Vec::new();
        let stranger = Wallet::generate(drawing(&mut elsewhere)).unwrap();
        assert_ne!(stranger.public_key(), me);
        assert!(
            tx::verify_schnorr_sig65(&stranger.public_key(), &digest, &sig).is_err(),
            "not under another key"
        );
        // Deterministic: signing draws nothing, and the same digest gives the same signature.
        assert_eq!(wallet.sign_digest(&digest).unwrap(), sig);
        assert_ne!(wallet.sign_digest(&other).unwrap(), sig);
    }

    #[test]
    fn the_self_check_refuses_a_signature_that_does_not_verify() {
        let mut drawn = Vec::new();
        let wallet = Wallet::generate(drawing(&mut drawn)).unwrap();
        assert!(wallet.sign_digest(&[3; 32]).is_ok(), "control");
        corrupt::arm();
        assert_eq!(
            wallet.sign_digest(&[3; 32]).unwrap_err().code(),
            "SDK_SIGN_SELF_CHECK_FAILED"
        );
        assert!(wallet.sign_digest(&[3; 32]).is_ok(), "the hook fires once");
    }

    #[test]
    fn only_a_valid_secret_is_a_key() {
        let mut ok = Vec::new();
        let secret = {
            let w = Wallet::generate(drawing(&mut ok)).unwrap();
            assert!(!w.is_wiped());
            ok[0]
        };
        assert!(
            Wallet::from_secret(Zeroizing::new(Box::<[u8]>::from(secret))).is_some(),
            "control: a drawn secret"
        );
        let mut above = ORDER;
        above[31] += 1;
        for (what, bytes) in [
            ("zero", [0u8; 32]),
            ("the group order", ORDER),
            ("above the group order", above),
            ("all ones", [0xff; 32]),
        ] {
            assert!(
                Wallet::from_secret(Zeroizing::new(Box::<[u8]>::from(bytes))).is_none(),
                "{what}"
            );
        }
    }

    #[test]
    fn a_draw_that_is_not_a_key_is_drawn_again_and_a_failed_draw_is_a_refusal() {
        let mut calls = 0;
        let wallet = Wallet::generate(|bytes| {
            calls += 1;
            if calls <= 3 {
                *bytes = [0; 32];
            } else {
                secp256k1::rand::thread_rng().fill_bytes(bytes);
            }
            Ok(())
        });
        assert!(wallet.is_ok(), "control: the fourth draw is a key");
        assert_eq!(calls, 4);
        let always_zero = Wallet::generate(|bytes| {
            *bytes = [0; 32];
            Ok(())
        });
        assert_eq!(always_zero.err().unwrap().code(), "SDK_WALLET_RANDOM");
        let broken = Wallet::generate(|_| {
            Err(SdkError::WalletRandom {
                reason: "no crypto".into(),
            })
        });
        assert_eq!(broken.err().unwrap().code(), "SDK_WALLET_RANDOM");
    }

    #[test]
    fn a_wiped_wallet_signs_nothing_and_still_knows_its_public_key() {
        let mut drawn = Vec::new();
        let mut wallet = Wallet::generate(drawing(&mut drawn)).unwrap();
        let me = wallet.public_key();
        assert!(wallet.sign_digest(&[1; 32]).is_ok(), "control");
        wallet.wipe();
        assert!(wallet.is_wiped());
        assert_eq!(
            wallet.sign_digest(&[1; 32]).unwrap_err().code(),
            "SDK_WALLET_WIPED"
        );
        assert_eq!(wallet.public_key(), me);
        wallet.wipe();
        assert!(wallet.is_wiped(), "wiping twice is harmless");
    }

    #[test]
    fn no_refusal_carries_the_key() {
        let mut drawn = Vec::new();
        let mut wallet = Wallet::generate(drawing(&mut drawn)).unwrap();
        let secret = hex(&drawn[0]);
        let me = hex(&wallet.public_key());
        assert_ne!(secret, me);
        wallet.wipe();
        let refusals = [
            wallet.sign_digest(&[1; 32]).unwrap_err().to_string(),
            SdkError::SignSelfCheck.to_string(),
            SdkError::WalletWiped.to_string(),
        ];
        for text in refusals {
            assert!(!text.contains(&secret), "a refusal names the key");
        }
    }

    #[test]
    fn the_sign_options_form_is_strict() {
        use serde_json::json;
        let ok = json!({
            "artifacts": {"asset": "x", "cash": null},
            "current_daa": "1500000",
            "value": {"kas_equivalent": "1"},
            "mainnet": false,
        });
        assert!(sign_options_from_json(&ok).is_ok(), "control");
        let with_pins = {
            let mut v = ok.clone();
            v["pins"] = json!({"receive": null, "refund": "kaspatest:x"});
            v
        };
        let p = sign_options_from_json(&with_pins).unwrap();
        assert_eq!(p.pins.1.as_deref(), Some("kaspatest:x"));
        for key in ["artifacts", "current_daa", "value", "mainnet"] {
            let mut v = ok.clone();
            v.as_object_mut().unwrap().remove(key);
            assert_eq!(
                sign_options_from_json(&v).err().unwrap().code(),
                "SDK_JSON_FORM",
                "{key}"
            );
        }
        let mut extra = ok.clone();
        extra["secret"] = json!("x");
        assert_eq!(
            sign_options_from_json(&extra).err().unwrap().code(),
            "SDK_JSON_FORM"
        );
        let mut daa = ok.clone();
        daa["current_daa"] = json!(1_500_000);
        assert_eq!(
            sign_options_from_json(&daa).err().unwrap().code(),
            "SDK_JSON_FORM"
        );
        // The amounts the signer confirms: carrier and authorizer are u64 strings, or absent.
        let mut confirmed = ok.clone();
        confirmed["carrier"] = json!("300000000");
        confirmed["authorizer"] = json!("60000000");
        let c = sign_options_from_json(&confirmed).unwrap();
        assert_eq!(
            (c.carrier, c.authorizer),
            (Some(300_000_000), Some(60_000_000))
        );
        let none = sign_options_from_json(&ok).unwrap();
        assert_eq!(
            (none.carrier, none.authorizer),
            (None, None),
            "control: absent"
        );
        for key in ["carrier", "authorizer"] {
            let mut number = ok.clone();
            number[key] = json!(5);
            assert_eq!(
                sign_options_from_json(&number).err().unwrap().code(),
                "SDK_JSON_FORM",
                "{key} as a number"
            );
        }
        let mut flag = ok;
        flag["mainnet"] = json!("yes");
        assert_eq!(
            sign_options_from_json(&flag).err().unwrap().code(),
            "SDK_JSON_FORM"
        );
    }
}
