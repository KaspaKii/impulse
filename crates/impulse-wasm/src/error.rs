// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! SDK refusals and the JavaScript form of every refusal. impulse-core's refusals keep their
//! `TERMS_*` and `TEMPLATE_*` codes unchanged; the SDK adds codes only for what JavaScript can
//! pass that Rust types cannot: a value of the wrong JavaScript type, and a JSON-form value that
//! breaks the form. Integrators match on `code`, never on the message text.

use std::fmt;

/// Why the SDK refused an argument before impulse-core saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdkError {
    /// `argument` is not of the JavaScript type the API declares (`expected`).
    ArgumentType {
        argument: &'static str,
        expected: &'static str,
    },
    /// A JSON-form value (terms, creation context, network name) breaks the form of
    /// spec/ENCODING.md at `path`.
    JsonForm { path: String, reason: String },
    /// The mainnet creation DAA score was not read from a node (spec/CLI.md, "Terms draft and
    /// terms file": a typed score is refused on mainnet).
    MainnetNeedsNode,
    /// The value cap in force is unusable: a `max_value` or `cap` that is not a decimal number of
    /// sompi, or is above the default cap, or one given together with the flag that lifts the
    /// cap. Only `i_accept_the_risk` lifts the cap.
    ValueCapInvalid { reason: String },
    /// The trade's value is unknown: a leg is not native KAS and no KAS equivalent was declared,
    /// or a declared 0 stands for none.
    ValueUnknown { reason: &'static str },
    /// The trade's value is above the cap that holds in v0.1.
    ValueCapExceeded { value: u64, cap: u64 },
    /// The text does not fit a QR code.
    Qr { reason: String },
    /// A terms document disagrees with itself: its `canonical` or `terms_hash` is not that of its
    /// `terms` (spec/CLI.md, "Terms file"), or terms read back from a form are not the terms they
    /// were loaded from.
    TermsInconsistent { reason: String },
    /// The role check (spec/CLI.md, "Terms summary and role check"): the key the user gave is not
    /// the terms' party key for the role the user claims.
    RoleKeyMismatch {
        role: &'static str,
        expected: String,
        got: String,
    },
    /// The role check: a destination of the user's role pays the counterparty or the authority,
    /// differs from its pin, or without a pin does not pay the user's key.
    DestinationNotMine { reasons: Vec<String> },
    /// The role check: a pin does not parse, names another network, or is not a destination.
    DestinationPinInvalid { pin: String, reason: String },
    /// The wallet was wiped (or is being used after it was freed): its key is gone.
    WalletWiped,
    /// The wallet's key could not be drawn: the browser gave no randomness.
    WalletRandom { reason: String },
    /// A mainnet document is signed without the explicit mainnet choice (spec/CLI.md, "Key file
    /// and the signing module": `SIGN_MAINNET_NOT_EXPLICIT`).
    SignMainnetNotExplicit,
    /// A testnet document is signed with the mainnet choice made (`SIGN_NETWORK_MISMATCH`).
    SignNetworkMismatch,
    /// The wallet's key signs no input of the document that still lacks its signature.
    SignNothing { reason: &'static str },
    /// The signature the wallet made did not verify before it left the wallet
    /// (`SIGN_SELF_CHECK_FAILED`).
    SignSelfCheck,
    /// The node URL is not `ws://` or `wss://` with a host (`CLI_NODE_URL_INVALID`).
    NodeUrlInvalid { url: String },
    /// On mainnet the node link is neither `wss://` nor `ws://` to `127.0.0.1` or `localhost`
    /// (`CLI_NODE_INSECURE`; `[::1]` is refused here, unlike the command line).
    NodeInsecure { url: String },
    /// The node is on another network than the page acts on (`CLI_NODE_NETWORK_MISMATCH`).
    NodeNetworkMismatch {
        node: String,
        expected: &'static str,
    },
    /// The node says it is not synced (`CLI_NODE_NOT_SYNCED`).
    NodeNotSynced,
    /// A node's reply is not the reply to the request, or is malformed, or says it failed
    /// (`CLI_NODE_RPC`). The node's own words are echoed escaped and cut. `from_node` is true only
    /// when the node itself sent the error: a well-formed reply carrying the id of this very request
    /// and an `error` member. Every other reason (another request's id, text that is not JSON, a
    /// reply that has no params) leaves what the node did with the request unknown.
    RpcReply {
        method: &'static str,
        reason: String,
        from_node: bool,
    },
    /// The node returned another transaction than the one asked for or submitted
    /// (`CLI_NODE_TXID_MISMATCH`).
    TxidMismatch { asked: String, got: String },
    /// A UTXO a builder needs is not among those the node reported.
    UtxoNotFound { what: String },
    /// Signing a fee input: the change output does not pay the address the signer accepts
    /// (`CLI_IPST_CHANGE_NOT_MINE`).
    SignChangeNotMine { change: String, expected: String },
    /// Signing a fee input: the fee is above what the signer accepts, or the signer would pay
    /// more fee inputs than the default limit covers (`CLI_IPST_FEE_TOO_HIGH`).
    SignFeeTooHigh { reason: String },
    /// Signing a fee input of a settle, a refund or a Direct transaction: the fee inputs also put
    /// more KAS into the trade outputs than the signer accepts (`CLI_IPST_TOPUP_TOO_HIGH`).
    SignTopupTooHigh { topup: u64, max_topup: u64 },
    /// The inputs the signer signs hold more of its KAS, less what comes back to it, than the
    /// trade takes plus the fee and top-up it accepts (`CLI_IPST_OUTFLOW_TOO_HIGH`).
    SignOutflowTooHigh {
        outflow: u64,
        limit: u64,
        expected: u64,
    },
    /// On mainnet, a destination of the user's role, or the change of a transaction, pays a key
    /// that lives only in a wallet of the page. Nothing the SDK or the page builds can spend what
    /// is paid to it, and it is lost with the page: pin an address the user controls elsewhere.
    DestinationInWallet { reasons: Vec<String> },
    /// The node answered that the transaction asked for is not there (kaspad's
    /// `Transaction <id> not found`), as against a reply that cannot be read.
    RpcNotFound { method: &'static str, id: String },
    /// A funding is asked for by a key that is not the depositor of the leg: only the buyer funds
    /// the cash leg (`CLI_FUND_NOT_YOUR_LEG`).
    FundNotYourLeg { reason: String },
    /// A funding is asked for terms with a KCC-20 template that is not one of the pinned kcc20.sil
    /// builds: the builders' compute budgets are not measured for other code, so a settle or
    /// refund of such a token may not build and could leave it escrowed. No override
    /// (`CLI_TEMPLATE_UNPINNED`).
    TemplateUnpinned { reason: String },
    /// The cash leg is asked to be funded before the asset leg is: the node reports no authorizer
    /// at the asset vault, or no escrowed token in the exact state the leg needs. The buyer's
    /// cash would wait in its vault, and the buyer's only unilateral way out is a refund.
    FundAssetNotFunded { reason: String },
    /// The cash leg is asked to be funded again: the cash vault already holds a deposit of exactly
    /// the cash amount, which is the one a settle takes.
    FundAlreadyFunded { reason: String },
    /// Signing a KCC-20 funding: the KAS the deposit puts on the escrowed token (output 0) and on
    /// the authorizer (output 1) are not the amounts the signer confirms, the carrier and the
    /// authorizer it was told, by default the minimum of a KCC-20 output and of a KAS output
    /// (`CLI_IPST_DEPOSIT_MISMATCH`). The terms check takes both amounts from the document, so
    /// only the signer can confirm them.
    SignDepositMismatch {
        carrier: u64,
        authorizer: u64,
        confirmed_carrier: u64,
        confirmed_authorizer: u64,
    },
}

/// Every SDK refusal code, in declaration order. Frozen once merged: a test pins this list, and
/// it may only grow at the end. The value codes are one cap, `value.rs`, for the funding
/// instructions (I11) and the builders (I9).
pub const SDK_ERROR_CODES: [&str; 35] = [
    "SDK_ARGUMENT_TYPE",
    "SDK_JSON_FORM",
    "SDK_MAINNET_NEEDS_NODE",
    "SDK_VALUE_CAP_INVALID",
    "SDK_VALUE_UNKNOWN",
    "SDK_VALUE_CAP_EXCEEDED",
    "SDK_QR",
    "SDK_TERMS_INCONSISTENT",
    "SDK_ROLE_KEY_MISMATCH",
    "SDK_DESTINATION_NOT_MINE",
    "SDK_DESTINATION_PIN_INVALID",
    "SDK_WALLET_WIPED",
    "SDK_WALLET_RANDOM",
    "SDK_SIGN_MAINNET_NOT_EXPLICIT",
    "SDK_SIGN_NETWORK_MISMATCH",
    "SDK_SIGN_NOTHING_TO_SIGN",
    "SDK_SIGN_SELF_CHECK_FAILED",
    "SDK_NODE_URL_INVALID",
    "SDK_NODE_INSECURE",
    "SDK_NODE_NETWORK_MISMATCH",
    "SDK_NODE_NOT_SYNCED",
    "SDK_RPC_REPLY",
    "SDK_TXID_MISMATCH",
    "SDK_UTXO_NOT_FOUND",
    "SDK_SIGN_CHANGE_NOT_MINE",
    "SDK_SIGN_FEE_TOO_HIGH",
    "SDK_SIGN_TOPUP_TOO_HIGH",
    "SDK_SIGN_OUTFLOW_TOO_HIGH",
    "SDK_DESTINATION_IN_WALLET",
    "SDK_RPC_NOT_FOUND",
    "SDK_FUND_NOT_YOUR_LEG",
    "SDK_TEMPLATE_UNPINNED",
    "SDK_FUND_ASSET_NOT_FUNDED",
    "SDK_FUND_ALREADY_FUNDED",
    "SDK_SIGN_DEPOSIT_MISMATCH",
];

impl SdkError {
    /// The stable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ArgumentType { .. } => "SDK_ARGUMENT_TYPE",
            Self::JsonForm { .. } => "SDK_JSON_FORM",
            Self::MainnetNeedsNode => "SDK_MAINNET_NEEDS_NODE",
            Self::ValueCapInvalid { .. } => "SDK_VALUE_CAP_INVALID",
            Self::ValueUnknown { .. } => "SDK_VALUE_UNKNOWN",
            Self::ValueCapExceeded { .. } => "SDK_VALUE_CAP_EXCEEDED",
            Self::Qr { .. } => "SDK_QR",
            Self::TermsInconsistent { .. } => "SDK_TERMS_INCONSISTENT",
            Self::RoleKeyMismatch { .. } => "SDK_ROLE_KEY_MISMATCH",
            Self::DestinationNotMine { .. } => "SDK_DESTINATION_NOT_MINE",
            Self::DestinationPinInvalid { .. } => "SDK_DESTINATION_PIN_INVALID",
            Self::WalletWiped => "SDK_WALLET_WIPED",
            Self::WalletRandom { .. } => "SDK_WALLET_RANDOM",
            Self::SignMainnetNotExplicit => "SDK_SIGN_MAINNET_NOT_EXPLICIT",
            Self::SignNetworkMismatch => "SDK_SIGN_NETWORK_MISMATCH",
            Self::SignNothing { .. } => "SDK_SIGN_NOTHING_TO_SIGN",
            Self::SignSelfCheck => "SDK_SIGN_SELF_CHECK_FAILED",
            Self::NodeUrlInvalid { .. } => "SDK_NODE_URL_INVALID",
            Self::NodeInsecure { .. } => "SDK_NODE_INSECURE",
            Self::NodeNetworkMismatch { .. } => "SDK_NODE_NETWORK_MISMATCH",
            Self::NodeNotSynced => "SDK_NODE_NOT_SYNCED",
            Self::RpcReply { .. } => "SDK_RPC_REPLY",
            Self::TxidMismatch { .. } => "SDK_TXID_MISMATCH",
            Self::UtxoNotFound { .. } => "SDK_UTXO_NOT_FOUND",
            Self::SignChangeNotMine { .. } => "SDK_SIGN_CHANGE_NOT_MINE",
            Self::SignFeeTooHigh { .. } => "SDK_SIGN_FEE_TOO_HIGH",
            Self::SignTopupTooHigh { .. } => "SDK_SIGN_TOPUP_TOO_HIGH",
            Self::SignOutflowTooHigh { .. } => "SDK_SIGN_OUTFLOW_TOO_HIGH",
            Self::DestinationInWallet { .. } => "SDK_DESTINATION_IN_WALLET",
            Self::RpcNotFound { .. } => "SDK_RPC_NOT_FOUND",
            Self::FundNotYourLeg { .. } => "SDK_FUND_NOT_YOUR_LEG",
            Self::TemplateUnpinned { .. } => "SDK_TEMPLATE_UNPINNED",
            Self::FundAssetNotFunded { .. } => "SDK_FUND_ASSET_NOT_FUNDED",
            Self::FundAlreadyFunded { .. } => "SDK_FUND_ALREADY_FUNDED",
            Self::SignDepositMismatch { .. } => "SDK_SIGN_DEPOSIT_MISMATCH",
        }
    }

    pub(crate) fn json(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::JsonForm {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::ArgumentType { argument, expected } => {
                write!(f, "{argument} must be {expected}")
            }
            Self::JsonForm { path, reason } => write!(f, "{path}: {reason}"),
            Self::MainnetNeedsNode => write!(
                f,
                "on mainnet the creation DAA score must be read from a node; a typed score is refused"
            ),
            Self::ValueCapInvalid { reason } => f.write_str(reason),
            Self::ValueUnknown { reason } => f.write_str(reason),
            Self::ValueCapExceeded { value, cap } => write!(
                f,
                "trade value {value} sompi is above the cap of {cap} sompi; \
                 set i_accept_the_risk to proceed"
            ),
            Self::Qr { reason } => f.write_str(reason),
            Self::TermsInconsistent { reason } => f.write_str(reason),
            Self::RoleKeyMismatch {
                role,
                expected,
                got,
            } => write!(
                f,
                "the terms name {role}_key {expected}, you gave {got}; these terms are not yours as {role}"
            ),
            Self::DestinationNotMine { reasons } => {
                write!(f, "{}. Refuse these terms", reasons.join("; "))
            }
            Self::DestinationPinInvalid { pin, reason } => write!(f, "{pin} {reason}"),
            Self::WalletWiped => f.write_str("this wallet was wiped; its key is gone"),
            Self::WalletRandom { reason } => write!(f, "no randomness for a key: {reason}"),
            Self::SignMainnetNotExplicit => f.write_str(
                "this signs for mainnet; switch mainnet on explicitly to sign it",
            ),
            Self::SignNetworkMismatch => {
                f.write_str("the mainnet switch is on for a testnet document")
            }
            Self::SignNothing { reason } => f.write_str(reason),
            Self::SignSelfCheck => f.write_str("the signature does not verify"),
            Self::NodeUrlInvalid { url } => write!(
                f,
                "{} is not a ws:// or wss:// wRPC URL",
                shown(url)
            ),
            Self::NodeInsecure { url } => write!(
                f,
                "{}: on mainnet the node link must be wss://, or ws:// to 127.0.0.1 or localhost (an SSH tunnel reaches a remote node)",
                shown(url)
            ),
            Self::NodeNetworkMismatch { node, expected } => write!(
                f,
                "the node is on {}, this page acts on {expected}",
                shown(node)
            ),
            Self::NodeNotSynced => f.write_str("the node is not synced"),
            Self::RpcReply { method, reason, .. } => write!(f, "{method}: {reason}"),
            Self::TxidMismatch { asked, got } => write!(
                f,
                "the node returned {}, the transaction is {}",
                shown(got),
                shown(asked)
            ),
            Self::UtxoNotFound { what } => f.write_str(what),
            Self::SignChangeNotMine { change, expected } => write!(
                f,
                "you sign a fee input, and the change goes to {change}, not to {expected}; give the change address you accept, or build with change back to this key"
            ),
            Self::SignFeeTooHigh { reason } => f.write_str(reason),
            Self::SignTopupTooHigh { topup, max_topup } => write!(
                f,
                "you sign a fee input, and the fee inputs also put {topup} sompi into trade outputs (under-funded carriers or authorizers topped up), above the {max_topup} you accept; pass max_topup to accept more"
            ),
            Self::SignOutflowTooHigh {
                outflow,
                limit,
                expected,
            } => write!(
                f,
                "the inputs you sign hold {outflow} sompi of your KAS more than comes back to you, above the {limit} you accept ({expected} for the trade, and when you sign a fee input max_fee and max_topup); check where the change goes and what the inputs carry"
            ),
            Self::DestinationInWallet { reasons } => write!(
                f,
                "{}. These keys live only in wallets of this page: nothing can spend what is paid to them, and it is lost with the page. Pin an address you control elsewhere",
                reasons.join("; ")
            ),
            Self::RpcNotFound { method, id } => {
                write!(f, "{method}: the node does not have the transaction {id}")
            }
            Self::FundNotYourLeg { reason } => f.write_str(reason),
            Self::TemplateUnpinned { reason } => f.write_str(reason),
            Self::FundAssetNotFunded { reason } => f.write_str(reason),
            Self::FundAlreadyFunded { reason } => f.write_str(reason),
            Self::SignDepositMismatch {
                carrier,
                authorizer,
                confirmed_carrier,
                confirmed_authorizer,
            } => write!(
                f,
                "the deposit puts {carrier} sompi on the escrowed token and {authorizer} on the authorizer; you confirm {confirmed_carrier} and {confirmed_authorizer} (pass carrier and authorizer to confirm other amounts)"
            ),
        }
    }
}

impl std::error::Error for SdkError {}

/// At most this many characters of a caller's string appear in a refusal message.
const SHOWN_CHARS: usize = 32;

/// A caller's string as a refusal message shows it in a path: cut to `SHOWN_CHARS` characters,
/// with "..." after a cut, so that a message never echoes an unbounded input.
pub(crate) fn clipped(s: &str) -> String {
    match s.char_indices().nth(SHOWN_CHARS) {
        None => s.into(),
        Some((at, _)) => format!("{}...", &s[..at]),
    }
}

/// A caller's string as a refusal message quotes it: Rust-quoted and cut like `clipped`, with
/// "..." outside the quotes after a cut.
pub(crate) fn shown(s: &str) -> String {
    match s.char_indices().nth(SHOWN_CHARS) {
        None => format!("{s:?}"),
        Some((at, _)) => format!("{:?}...", &s[..at]),
    }
}

/// At most this many characters of a node's words appear in a refusal message.
const NODE_WORDS_CHARS: usize = 240;

/// A node's words as a refusal message quotes them: Rust-quoted, so that no control character
/// reaches the page raw, and cut at `NODE_WORDS_CHARS` characters, with "..." after a cut. Longer
/// than `shown`: the node's reason is what the user needs.
pub(crate) fn node_words(s: &str) -> String {
    match s.char_indices().nth(NODE_WORDS_CHARS) {
        None => format!("{s:?}"),
        Some((at, _)) => format!("{:?}...", &s[..at]),
    }
}

/// A refusal as JavaScript throws it: an `Error` named `ImpulseError` whose `code` is the stable
/// code and whose message is the Rust Display text (which starts with the code).
pub(crate) fn to_js(code: &str, message: &str) -> wasm_bindgen::JsValue {
    let error = js_sys::Error::new(message);
    error.set_name("ImpulseError");
    // Defining a data property on a fresh, extensible Error object cannot fail.
    let _ = js_sys::Reflect::set(&error, &"code".into(), &code.into());
    error.into()
}

/// A refusal of any layer, converted for JavaScript.
pub(crate) trait Refusal: fmt::Display {
    fn code(&self) -> &'static str;

    /// True when the node itself answered the request with an error: a well-formed reply to that
    /// very request that carries an `error` member (and so did not act on it). JavaScript sees it
    /// as `nodeError: true` on the thrown error, and on no other.
    fn is_node_error(&self) -> bool {
        false
    }
}

impl Refusal for SdkError {
    fn code(&self) -> &'static str {
        SdkError::code(self)
    }

    fn is_node_error(&self) -> bool {
        matches!(
            self,
            SdkError::RpcReply {
                from_node: true,
                ..
            } | SdkError::RpcNotFound { .. }
        )
    }
}

impl Refusal for impulse_core::terms::TermsError {
    fn code(&self) -> &'static str {
        impulse_core::terms::TermsError::code(self)
    }
}

impl Refusal for impulse_core::verify::VerifyError {
    fn code(&self) -> &'static str {
        impulse_core::verify::VerifyError::code(self)
    }
}

impl Refusal for impulse_core::template::TemplateError {
    fn code(&self) -> &'static str {
        impulse_core::template::TemplateError::code(self)
    }
}

impl Refusal for impulse_core::tx::TxError {
    fn code(&self) -> &'static str {
        impulse_core::tx::TxError::code(self)
    }
}

impl Refusal for impulse_core::decode::DecodeError {
    fn code(&self) -> &'static str {
        impulse_core::decode::DecodeError::code(self)
    }
}

impl Refusal for impulse_core::v2::V2Error {
    fn code(&self) -> &'static str {
        impulse_core::v2::V2Error::code(self)
    }
}

/// A refusal of any layer an operation can meet, so that one `?` carries it: the SDK's own, and
/// impulse-core's, each with its code unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Sdk(SdkError),
    Terms(impulse_core::terms::TermsError),
    Template(impulse_core::template::TemplateError),
    Tx(impulse_core::tx::TxError),
    Verify(impulse_core::verify::VerifyError),
    Decode(impulse_core::decode::DecodeError),
    V2(impulse_core::v2::V2Error),
}

macro_rules! failure_from {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        $(impl From<$ty> for Failure {
            fn from(e: $ty) -> Self {
                Self::$variant(e)
            }
        })*
        impl fmt::Display for Failure {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant(e) => e.fmt(f),)*
                }
            }
        }
        impl Refusal for Failure {
            fn code(&self) -> &'static str {
                match self {
                    $(Self::$variant(e) => Refusal::code(e),)*
                }
            }

            fn is_node_error(&self) -> bool {
                match self {
                    $(Self::$variant(e) => Refusal::is_node_error(e),)*
                }
            }
        }
    };
}

failure_from!(
    Sdk(SdkError),
    Terms(impulse_core::terms::TermsError),
    Template(impulse_core::template::TemplateError),
    Tx(impulse_core::tx::TxError),
    Verify(impulse_core::verify::VerifyError),
    Decode(impulse_core::decode::DecodeError),
    V2(impulse_core::v2::V2Error),
);

pub(crate) fn js<E: Refusal>(e: E) -> wasm_bindgen::JsValue {
    let error = to_js(e.code(), &e.to_string());
    if e.is_node_error() {
        // Only an error the node sent to this very request carries the mark; defining a data
        // property on a fresh, extensible Error object cannot fail.
        let _ = js_sys::Reflect::set(&error, &"nodeError".into(), &true.into());
    }
    error
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn sdk_error_codes_are_frozen() {
        assert_eq!(
            SDK_ERROR_CODES,
            [
                "SDK_ARGUMENT_TYPE",
                "SDK_JSON_FORM",
                "SDK_MAINNET_NEEDS_NODE",
                "SDK_VALUE_CAP_INVALID",
                "SDK_VALUE_UNKNOWN",
                "SDK_VALUE_CAP_EXCEEDED",
                "SDK_QR",
                "SDK_TERMS_INCONSISTENT",
                "SDK_ROLE_KEY_MISMATCH",
                "SDK_DESTINATION_NOT_MINE",
                "SDK_DESTINATION_PIN_INVALID",
                "SDK_WALLET_WIPED",
                "SDK_WALLET_RANDOM",
                "SDK_SIGN_MAINNET_NOT_EXPLICIT",
                "SDK_SIGN_NETWORK_MISMATCH",
                "SDK_SIGN_NOTHING_TO_SIGN",
                "SDK_SIGN_SELF_CHECK_FAILED",
                "SDK_NODE_URL_INVALID",
                "SDK_NODE_INSECURE",
                "SDK_NODE_NETWORK_MISMATCH",
                "SDK_NODE_NOT_SYNCED",
                "SDK_RPC_REPLY",
                "SDK_TXID_MISMATCH",
                "SDK_UTXO_NOT_FOUND",
                "SDK_SIGN_CHANGE_NOT_MINE",
                "SDK_SIGN_FEE_TOO_HIGH",
                "SDK_SIGN_TOPUP_TOO_HIGH",
                "SDK_SIGN_OUTFLOW_TOO_HIGH",
                "SDK_DESTINATION_IN_WALLET",
                "SDK_RPC_NOT_FOUND",
                "SDK_FUND_NOT_YOUR_LEG",
                "SDK_TEMPLATE_UNPINNED",
                "SDK_FUND_ASSET_NOT_FUNDED",
                "SDK_FUND_ALREADY_FUNDED",
                "SDK_SIGN_DEPOSIT_MISMATCH"
            ]
        );
        let all = [
            SdkError::ArgumentType {
                argument: "bytes",
                expected: "a Uint8Array",
            },
            SdkError::json("terms.nonce", "not a decimal string"),
            SdkError::MainnetNeedsNode,
            SdkError::ValueCapInvalid { reason: "x".into() },
            SdkError::ValueUnknown { reason: "x" },
            SdkError::ValueCapExceeded { value: 2, cap: 1 },
            SdkError::Qr { reason: "x".into() },
            SdkError::TermsInconsistent { reason: "x".into() },
            SdkError::RoleKeyMismatch {
                role: "buyer",
                expected: "x".into(),
                got: "y".into(),
            },
            SdkError::DestinationNotMine {
                reasons: vec!["x".into()],
            },
            SdkError::DestinationPinInvalid {
                pin: "x".into(),
                reason: "y".into(),
            },
            SdkError::WalletWiped,
            SdkError::WalletRandom { reason: "x".into() },
            SdkError::SignMainnetNotExplicit,
            SdkError::SignNetworkMismatch,
            SdkError::SignNothing { reason: "x" },
            SdkError::SignSelfCheck,
            SdkError::NodeUrlInvalid { url: "x".into() },
            SdkError::NodeInsecure { url: "x".into() },
            SdkError::NodeNetworkMismatch {
                node: "x".into(),
                expected: "mainnet",
            },
            SdkError::NodeNotSynced,
            SdkError::RpcReply {
                method: "getServerInfo",
                reason: "x".into(),
                from_node: false,
            },
            SdkError::TxidMismatch {
                asked: "x".into(),
                got: "y".into(),
            },
            SdkError::UtxoNotFound { what: "x".into() },
            SdkError::SignChangeNotMine {
                change: "x".into(),
                expected: "y".into(),
            },
            SdkError::SignFeeTooHigh { reason: "x".into() },
            SdkError::SignTopupTooHigh {
                topup: 2,
                max_topup: 1,
            },
            SdkError::SignOutflowTooHigh {
                outflow: 2,
                limit: 1,
                expected: 0,
            },
            SdkError::DestinationInWallet {
                reasons: vec!["x".into()],
            },
            SdkError::RpcNotFound {
                method: "getMempoolEntry",
                id: "x".into(),
            },
            SdkError::FundNotYourLeg { reason: "x".into() },
            SdkError::TemplateUnpinned { reason: "x".into() },
            SdkError::FundAssetNotFunded { reason: "x".into() },
            SdkError::FundAlreadyFunded { reason: "x".into() },
            SdkError::SignDepositMismatch {
                carrier: 2,
                authorizer: 1,
                confirmed_carrier: 3,
                confirmed_authorizer: 4,
            },
        ];
        let codes: Vec<&str> = all.iter().map(SdkError::code).collect();
        assert_eq!(codes, SDK_ERROR_CODES);
    }

    #[test]
    fn display_starts_with_the_code() {
        let e = SdkError::json("terms.network", "\"mainnet2\" is not a network");
        assert_eq!(
            e.to_string(),
            "SDK_JSON_FORM: terms.network: \"mainnet2\" is not a network"
        );
    }

    #[test]
    fn caller_strings_are_cut_in_messages() {
        let at_limit = "y".repeat(SHOWN_CHARS);
        assert_eq!(clipped(&at_limit), at_limit);
        assert_eq!(shown(&at_limit), format!("\"{at_limit}\""));
        let long = "é".repeat(1_000_000);
        let cut = "é".repeat(SHOWN_CHARS);
        assert_eq!(clipped(&long), format!("{cut}..."));
        assert_eq!(shown(&long), format!("\"{cut}\"..."));
        assert_eq!(shown("a\"b"), r#""a\"b""#);
    }
}
