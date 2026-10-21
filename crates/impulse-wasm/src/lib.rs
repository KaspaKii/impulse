// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! impulse-wasm: wasm-bindgen bindings over impulse-core, the engine of the npm SDK (I9).
//!
//! Every operation here is impulse-core's; this crate only converts JavaScript values to Rust
//! values and back, so no SDK logic lives in TypeScript. The JSON form of terms (spec/ENCODING.md)
//! is parsed and rendered here, in Rust. Phase 1 covers terms (JSON form, encode, decode, terms
//! hash, structure and creation checks), the template (startup check, instantiation of an
//! existing or a fundable vault, decode, template hash of an instance) and vault addresses.
//! Phase 2 (`api.rs`, `ops.rs`) covers the transaction builders, sighash, signature checks,
//! assembly, the IPST (read, write, combine, terms check), verify and decode.
//!
//! Refusals throw an `Error` named `ImpulseError` whose `code` is the stable code: impulse-core's
//! `TERMS_*`, `TEMPLATE_*`, `TX_*`, `IPST_*`, `VERIFY_*` and `DECODE_*` codes unchanged, and the
//! SDK's own `SDK_*` codes for arguments of the wrong JavaScript type, JSON-form values that
//! break the form, and a trade above the value cap.
//!
//! Keyless: nothing here signs, generates or holds a private key.
//!
//! Build setup (cdylib plus rlib, wasm-pack without wasm-opt) adapted from KTT-Core-v2 by
//! the owner; see docs/reference/BORROW-MAP.md. No KTT code is copied.

mod api;
mod error;
mod file;
mod forms;
mod funding;
mod json;
mod node_api;
mod ops;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod ops_tests;
mod payer;
mod plan;
mod review;
mod role;
mod rpc;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod rpc_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod testkit;
mod v2;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod v2_tests;
mod value;
mod wallet;
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests;

pub use error::{SdkError, SDK_ERROR_CODES};

use error::js;
use impulse_core::address;
use impulse_core::template::{self, FundableVault, LegIndex, Vault, TEMPLATE_ERROR_CODES};
use impulse_core::terms::{
    Network, Terms, ValidatedTerms, DEFAULT_MAX_EXPIRY_HORIZON_DAA, MAX_SCRIPT_LEN,
    MAX_TEMPLATE_LEN, TERMS_ERROR_CODES, TERMS_HASH_DOMAIN, TERMS_VERSION,
};
use js_sys::{ArrayBuffer, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
/** A Kaspa network as terms name it. Testnet covers every testnet suffix. */
export type Network = "mainnet" | "testnet";
/** A u64 as a decimal string: digits only, no sign, no leading zero. */
export type U64String = string;
/** Bytes as lowercase hex. */
export type Hex = string;
/** A leg index: 0 the asset leg, 1 the cash leg. */
export type LegIndexNumber = number;

export type LegJson =
  | { kind: "kas"; amount: U64String }
  | {
      kind: "kcc20";
      covenant_id: Hex;
      template_hash: Hex;
      template_prefix_len: number;
      template_suffix_len: number;
      amount: U64String;
    }
  | { kind: "external"; amount: U64String };

export type DestinationJson =
  | { kind: "kas"; version: number; script: Hex }
  | { kind: "kcc20"; identifier_type: "pubkey" | "script_hash" | "covenant_id"; identifier: Hex }
  | { kind: "off_chain" };

/** The JSON form of terms (spec/ENCODING.md, "Golden vectors"). Every key is required. */
export interface TermsJson {
  version: number;
  network: Network;
  settlement_mode: "direct" | "vault";
  nonce: U64String;
  seller_key: Hex;
  buyer_key: Hex;
  authority_key: Hex | null;
  asset_leg: LegJson;
  cash_leg: LegJson;
  buyer_delivery: DestinationJson;
  seller_proceeds: DestinationJson;
  seller_refund: DestinationJson;
  buyer_refund: DestinationJson;
  earliest_daa: U64String | null;
  expiry_daa: U64String;
  funding_mode: "revocable" | "earmarked";
  trade_ref: Hex;
}

/** impulse_core::terms::CreationContext. An absent horizon is the default horizon. */
export interface CreationContextJson {
  network: Network;
  creation_daa: U64String;
  max_expiry_horizon_daa?: U64String;
}

/**
 * The options of `ValidatedTerms.fundingInstructions`. `creation_daa_source` says where
 * `context.creation_daa` came from: `node` for a score the caller read from a node it trusts,
 * `typed` for one a person typed. Mainnet refuses `typed` (SDK_MAINNET_NEEDS_NODE).
 * `kas_equivalent` is the KAS value of the larger leg in sompi; every v1 trade needs it, because
 * the asset leg is a KCC-20 token. `cap` may only lower the default cap. `accept_the_risk`
 * skips every value check, as the command line's `--i-accept-the-risk` does, and excludes
 * `cap` (SDK_VALUE_CAP_INVALID); the browser demo never sets it. It is the cap of `ValueJson`,
 * under the names `cap` and `accept_the_risk`.
 */
export interface FundingOptionsJson {
  context: CreationContextJson;
  creation_daa_source: "typed" | "node";
  /** Which party the user is. The role check runs before anything is returned. */
  party: PartyJson;
  kas_equivalent?: U64String | null;
  cap?: U64String | null;
  accept_the_risk?: boolean | null;
}

/**
 * Which party the user is (spec/CLI.md, "Terms summary and role check"): the role, their x-only
 * public key, and optional pins. A pin names a destination the user controls that is not their own
 * key (a custodian or multisig): a Kaspa address of the terms' network in canonical form, or
 * `kcc20:<pubkey|script_hash|covenant_id>:<64 lowercase hex digits>`. `receive` pins the buyer's
 * delivery or the seller's proceeds, `refund` the role's refund destination.
 */
export interface PartyJson {
  role: "buyer" | "seller";
  key: Hex;
  pins?: { receive?: string | null; refund?: string | null } | null;
  /**
   * The public keys that live only in wallets of the page (at most 8). A destination of the role
   * that pays one of them is refused on mainnet (SDK_DESTINATION_IN_WALLET), pinned or not: what
   * is paid there cannot be spent from the page and is lost when it unloads. On testnet the check
   * passes and says so.
   */
  held?: Hex[] | null;
}

/** What a passed role check reports: one line per own destination, and the leg the role funds. */
export interface RoleCheckJson {
  role: "buyer" | "seller";
  key: Hex;
  funds_leg: "asset" | "cash";
  lines: string[];
  /** The own destinations that pay a key held only in a wallet of the page (testnet only). */
  in_wallet: ("buyer_delivery" | "buyer_refund" | "seller_proceeds" | "seller_refund")[];
}

/** One leg of the funding instructions. Asset leg: funded by the seller. Cash leg: the buyer. */
export interface FundingLeg {
  leg: LegIndexNumber;
  name: "asset" | "cash";
  depositor: "seller" | "buyer";
  /** True when the party's role is the depositor. Anyone else sends nothing to this leg's vault. */
  you_fund: boolean;
  kind: "kas" | "kcc20" | "external";
  amount: U64String;
  /** The amount in KAS with eight decimals, for a native KAS leg. */
  amount_kas: string | null;
  /** The vault the depositor funds; null when the terms escrow nothing on this leg. */
  vault: { address: string; script_hash: Hex } | null;
  /** Why there is no vault (TEMPLATE_NO_VAULT), else null. */
  no_vault_reason: string | null;
  /** `<vault address>?amount=<sompi>&impulse=<terms hash>`, for a native KAS leg with a vault that the party's role funds. */
  funding_uri: string | null;
  /**
   * The token warnings of impulse-core's `token_warnings` for this leg. This function reads no
   * token artifact, so a KCC-20 leg always carries `TOKEN_UNASSESSED`: nothing about the
   * token's issuer powers was read. Empty for a leg that is not KCC-20.
   */
  token_warnings: { code: string; message: string }[];
}

/**
 * One of the four destinations of the terms (the terms summary of spec/CLI.md). `destination`
 * is a Kaspa address (with how it pays), a KCC-20 owner, the script in hex, or off chain. `pays`
 * says whom it pays as far as its script or owner shows; `mark` is the same in words.
 * `pays_counterparty_or_authority` is true when it pays the key of the party that does not own
 * it, or the authority's: funding such terms gives the leg away, because the contract lets those
 * parties trigger a refund. It is not a role check: the SDK does not know which party the user is.
 */
export interface DestinationSummary {
  name: "buyer_delivery" | "seller_proceeds" | "seller_refund" | "buyer_refund";
  owner: "buyer" | "seller";
  kind: "kas" | "kcc20" | "off_chain";
  destination: string;
  pays: "seller_key" | "buyer_key" | "authority_key" | "other_key" | "script" | "off_chain";
  mark: string;
  pays_counterparty_or_authority: boolean;
}

/**
 * What the value cap measured. All amounts are sompi as decimal strings, except the KAS texts.
 * When `lifted` is true no check ran and every other field is null.
 */
export interface ValueCheck {
  lifted: boolean;
  value: U64String | null;
  value_kas: string | null;
  cap: U64String | null;
  cap_kas: string | null;
  declared: U64String | null;
  largest_kas_leg: U64String | null;
}

/** The funding instructions of a trade that passed every check; see `fundingInstructions`. */
export interface FundingInstructions {
  network: Network;
  terms_hash: Hex;
  template_hash: Hex;
  creation_daa: U64String;
  creation_daa_source: "typed" | "node";
  /** The expiry and the approximate time from the creation score to it, at 10 DAA scores per second. */
  expiry: { expiry_daa: U64String; time_left: string };
  /** buyer_delivery, seller_proceeds, seller_refund, buyer_refund, in that order. */
  destinations: [DestinationSummary, DestinationSummary, DestinationSummary, DestinationSummary];
  value: ValueCheck;
  /** The role check that passed. */
  role: RoleCheckJson;
  /** The asset leg, then the cash leg. */
  legs: [FundingLeg, FundingLeg];
}

/**
 * A kcc20.sil build (silverscript v1.0.0, the pinned silverc) for one choice of the template
 * constants: the only KCC-20 templates a funding accepts (`SDK_TEMPLATE_UNPINNED` otherwise).
 */
export interface PinnedKcc20Json {
  max_cov_ins: number;
  max_cov_outs: number;
  template_hash: Hex;
  template_prefix_len: number;
  template_suffix_len: number;
}

/** A QR code: `modules` holds `width * width` bytes, row by row, 1 for a dark module. */
export interface QrCodeValue {
  width: number;
  modules: Uint8Array;
}

/** A vault's P2SH scriptPubKey. */
export interface ScriptPublicKeyValue {
  version: number;
  script: Uint8Array;
}

/** A scriptPublicKey in the JSON form: the version and the script as hex. */
export interface ScriptPublicKeyJson {
  version: number;
  script: Hex;
}

/** A UTXO as a node reports it: the outpoint and the entry. */
export interface UtxoJson {
  transaction_id: Hex;
  index: number;
  amount: U64String;
  script_public_key: ScriptPublicKeyJson;
  block_daa_score: U64String;
  is_coinbase: boolean;
  covenant_id: Hex | null;
}

/** The state a KCC-20 UTXO's script holds. */
export interface Kcc20StateJson {
  identifier_type: "pubkey" | "script_hash" | "covenant_id";
  identifier: Hex;
  amount: U64String;
  is_minter: boolean;
}

/** A KCC-20 UTXO with the state its script holds. */
export interface TokenUtxoJson {
  utxo: UtxoJson;
  state: Kcc20StateJson;
}

/** The submitter's KAS: version 0 Schnorr P2PK UTXOs, the exact fee, and where the change goes. */
export interface FeePaymentJson {
  inputs: UtxoJson[];
  fee: U64String;
  change: ScriptPublicKeyJson;
}

/**
 * The KAS value of the trade, declared by the caller, checked against the per-trade cap that
 * holds in v0.1 (default 10 KAS). `kas_equivalent` (sompi, nonzero) is
 * required for every v1 trade, since the asset leg is a KCC-20 token. `max_value` can only lower
 * the cap. Only `i_accept_the_risk: true` lifts it, and it excludes `max_value`.
 */
export interface ValueJson {
  kas_equivalent?: U64String;
  max_value?: U64String;
  i_accept_the_risk?: boolean;
}

/** The depositor's side of a KCC-20 funding. `artifact` is the token's silverscript ABI artifact text. */
export interface Kcc20DepositJson {
  artifact: string;
  tokens: TokenUtxoJson[];
  carrier: U64String;
  authorizer: U64String;
}

export type SettleCashJson =
  | { kind: "kas"; vault: UtxoJson }
  | { kind: "kcc20"; artifact: string; authorizer: UtxoJson; escrow: UtxoJson }
  | { kind: "external" };

export interface SettleLegsJson {
  asset_artifact: string;
  asset_authorizer: UtxoJson;
  asset_escrow: UtxoJson;
  cash: SettleCashJson;
}

export type DirectCashJson =
  | { kind: "kas"; utxo: UtxoJson }
  | { kind: "kcc20"; artifact: string; token: TokenUtxoJson };

export interface DirectLegsJson {
  asset_artifact: string;
  asset: TokenUtxoJson;
  cash: DirectCashJson;
}

/** The escrowed token a refund carries home. */
export interface RefundEscrowJson {
  artifact: string;
  utxo: UtxoJson;
  amount: U64String;
  is_minter: boolean;
}

export type RefundSignerName = "depositor" | "counterparty" | "authority";

/** The legs' KCC-20 templates as artifact text; `cash` only for KCC-20 cash. */
export interface ArtifactsJson {
  asset: string;
  cash: string | null;
}

export interface SignatureJson {
  input: number;
  signature: Hex;
}

export interface IpstSlotJson {
  input: number;
  signer: Hex | null;
  sighash: Hex | null;
  signature: Hex | null;
}

export interface MassesJson {
  compute: U64String;
  transient: U64String;
  storage: U64String;
  fee_mass: U64String;
  min_relay_fee: U64String;
}

export type IpstKindJson =
  | { builder: "fund_kas" | "settle" | "direct" }
  | { builder: "fund_kcc20"; leg: LegIndexNumber }
  | { builder: "refund"; leg: LegIndexNumber; signer: RefundSignerName; with_token: boolean };

export interface TermsMatchJson {
  kind: IpstKindJson;
  fee: U64String;
  change: { value: U64String; script_public_key: ScriptPublicKeyJson } | null;
}

export interface Kcc20TemplateJson {
  template_hash: Hex;
  template_prefix_len: number;
  template_suffix_len: number;
}

export interface OfferedAddressesJson {
  asset: string | null;
  cash: string | null;
}

export interface VerifiedAddressJson {
  leg: LegIndexNumber;
  address: string;
  script_hash: Hex;
}

/** What the caller knows about one KCC-20 leg's token. `artifact` must come from the token publisher's reproducible build, never the counterparty. */
export interface TokenEvidenceJson {
  artifact: string;
  issuer_keys: Hex[];
}

export interface TokenEvidencesJson {
  asset: TokenEvidenceJson | null;
  cash: TokenEvidenceJson | null;
}

/** A warning is data, never a statement that a token is safe. */
export interface TokenWarningJson {
  leg: LegIndexNumber;
  code:
    | "TOKEN_UNASSESSED"
    | "TOKEN_MINTER_BRANCH"
    | "TOKEN_EXTRA_ENTRIES"
    | "TOKEN_PARTY_IS_ISSUER"
    | "TOKEN_TEMPLATE_UNPINNED"
    | "TOKEN_ISSUER_UNKNOWN"
    | "TOKEN_FOREIGN_AT_VAULT";
  entries?: string[];
  /** TOKEN_FOREIGN_AT_VAULT: the foreign token's covenant ID, hex. */
  covenant_id?: string;
  party?: "seller" | "buyer" | "authority";
  relation?: "depositor" | "counterparty" | "authority";
}

export interface FundingCheckJson {
  addresses: VerifiedAddressJson[];
  warnings: TokenWarningJson[];
  token_legs_assessed: boolean;
}

export interface DecodedLegJson {
  input_index: number;
  outpoint: { transaction_id: Hex; index: number };
  leg: LegIndexNumber;
  script_hash: Hex;
  terms: TermsJson;
  terms_hash: Hex;
  entry:
    | { kind: "settle" }
    | { kind: "refund"; signer: Hex | null; party: "seller" | "buyer" | "authority" | null };
  outcome:
    | { kind: "delivered"; amount: U64String; to: DestinationJson }
    | { kind: "refunded"; to: DestinationJson };
}

export interface DecodedTransactionJson {
  txid: Hex;
  /** False from decodeRawUnbound: the legs are then only as trustworthy as the source. */
  bound: boolean;
  legs: DecodedLegJson[];
  /** Vault inputs refused on their own, beside the legs. `message` may quote counterparty text. */
  refused: { code: string; input_index: number | null; message: string }[];
}

/**
 * What a signer reads before signing (`Ipst.review`): every input and output with its amount,
 * scriptPublicKey and address, and what the terms say it is (a label; "not named by the terms" when
 * nothing matches), the fee, the lock time and when the transaction becomes final, and the masses.
 */
export interface ReviewEntryJson {
  index: number;
  amount: U64String;
  amount_kas: string;
  script_public_key: ScriptPublicKeyJson;
  /** The Kaspa address of a standard scriptPublicKey, else null. */
  address: string | null;
  covenant_id: Hex | null;
  what: string;
}

export interface ReviewJson {
  kind: IpstKindJson;
  /** What the document does, in words (Settle, Direct trade, Refund of a leg, a funding). */
  title: string;
  network: Network;
  /** The hash and the nonce of the terms the document is for: the trade it belongs to. */
  terms_hash: Hex;
  nonce: U64String;
  inputs: (ReviewEntryJson & {
    outpoint: { transaction_id: Hex; index: number };
    signer: Hex | null;
    /** Which party the signer's key is in the terms; "other" for a key that is none of them. */
    signer_role: "seller" | "buyer" | "authority" | "other" | null;
    signed: boolean;
  })[];
  outputs: (ReviewEntryJson & {
    /** True when the output pays a key passed as `held`: a key that lives only in the page. */
    held_key: boolean;
  })[];
  fee: U64String;
  fee_kas: string;
  min_relay_fee: U64String;
  masses: MassesJson;
  /**
   * What the fee inputs put into the trade outputs beyond the fee: the top-up of under-funded
   * pass-through outputs in a settle, a refund or a Direct transaction (the deposit in a
   * funding). A counterparty who funds a vault's authorizer below the minimum makes the fee
   * payer pay the difference.
   */
  payer_cost: U64String;
  payer_cost_kas: string;
  payer_cost_text: string;
  /** The outputs that pay a held key, and the sompi on them. */
  held_outputs: number[];
  held_amount: U64String;
  /** Sentences a signer should read: the authority's signature, outputs paid to a held key, and for a funding how the deposit comes back and how long the trade has left to settle. */
  notes: string[];
  /**
   * For a funding: how the deposit comes back if the trade never settles, and what closing the
   * page or wiping the wallet does to that way out (also the first of the notes about a funding); null otherwise.
   */
  exit_note: string | null;
  /** The lock time as a DAA score; "0" for none. */
  lock_time: U64String;
  /** The first DAA score of a block the transaction can enter, null without a lock time. */
  final_from_daa: U64String | null;
  current_daa: U64String;
  /** False until the node's DAA score is past the lock time: a node refuses it before. */
  submit_ready: boolean;
  /** About how long until it is final, when it is not yet. */
  wait: string | null;
  pending: number[];
}

/** Where the fee comes from: the payer's x-only key, and the fee in sompi or "auto". */
export interface PlanFundingJson {
  payer: Hex;
  fee: U64String | "auto";
  /**
   * Where the payer's change goes, as a Kaspa address of the terms' network (the command line's
   * `--change`). Without it, back to the payer's own key. A payer whose key lives only in a
   * wallet of the page should name an address it controls elsewhere.
   */
  change?: string | null;
}

/** What the page tells a wallet about the document it is asked to sign. */
export interface SignOptionsJson {
  artifacts: ArtifactsJson;
  current_daa: U64String;
  value: ValueJson;
  /** True when the user chose mainnet explicitly. */
  mainnet: boolean;
  /** The user's pins, used when the wallet's key is a party's. */
  pins?: { receive?: string | null; refund?: string | null } | null;
  /** The public keys that live only in wallets of the page, besides this wallet's own (at most 8). */
  held?: Hex[] | null;
  /**
   * Where the change of a fee input must pay: a Kaspa address of the terms' network. Without it,
   * this wallet's own key (SDK_SIGN_CHANGE_NOT_MINE for any other). On mainnet a change that pays
   * a held key is SDK_DESTINATION_IN_WALLET.
   */
  change?: string | null;
  /** The most fee a signer of a fee input accepts, in sompi; else twice the minimum relay fee, for at most three fee inputs (SDK_SIGN_FEE_TOO_HIGH). */
  max_fee?: U64String | null;
  /** The most the fee inputs may add to the trade outputs beyond the fee; else none (SDK_SIGN_TOPUP_TOO_HIGH). */
  max_topup?: U64String | null;
  /**
   * The KAS each token input the signer gives carries in a Direct transaction, and the KAS a KCC-20
   * funding puts on the escrowed token (output 0); else the minimum of a KCC-20 output. A KCC-20
   * funding whose output 0 holds another amount is SDK_SIGN_DEPOSIT_MISMATCH.
   */
  carrier?: U64String | null;
  /**
   * The KAS a KCC-20 funding puts on the authorizer (output 1); else the minimum of a KAS output.
   * For a KCC-20 funding only (TX_WRONG_MODE for any other document); another amount in the
   * document is SDK_SIGN_DEPOSIT_MISMATCH.
   */
  authorizer?: U64String | null;
}

export interface SignResult {
  ipst: Ipst;
  signed_inputs: number[];
}

/** The node calls the page makes; see `rpcMethods()`. */
export type RpcMethod =
  | "getServerInfo"
  | "getBlockDagInfo"
  | "getUtxosByAddresses"
  | "submitTransaction"
  | "getMempoolEntry"
  | "getVirtualChainFromBlockV2";

export interface ServerInfoJson {
  network_id: string;
  network: Network | null;
  is_synced: boolean;
  has_utxo_index: boolean;
  virtual_daa_score: U64String;
}

/** A transaction as the page holds it between the node and the decoder. */
export interface FetchedTransactionJson {
  txid: Hex;
  /** rusty-kaspa a41a333's borsh encoding of the transaction, in hex. */
  raw: Hex;
  /** The scriptPublicKey each input spends where the node said, else null. */
  spent: (ScriptPublicKeyJson | null)[];
}

/** A node's reply in the SDK's forms; the members present depend on the method asked. */
export type RpcReplyJson =
  | ServerInfoJson
  | { virtual_daa_score: U64String; sink: Hex }
  | { utxos: (UtxoJson & { address: string | null })[]; total: U64String; total_kas: string }
  | { transaction_id: Hex }
  | { fee: U64String; is_orphan: boolean; transaction: FetchedTransactionJson }
  | {
      removed: Hex[];
      added: Hex[];
      transaction: FetchedTransactionJson | null;
      /** The chain block that accepted the transaction, as the node's header gives it. */
      accepting_block: { hash: Hex | null; daa_score: U64String | null } | null;
    };

/**
 * What every refusal throws. `code` is stable; match on it, never on the message. `nodeError` is
 * true only on an error the node itself sent in answer to the very request (a well-formed reply
 * with the request's id and an `error` member: `SDK_RPC_REPLY`, or `SDK_RPC_NOT_FOUND`), which is
 * how a caller tells "the node refused it" from "the answer cannot be read", where what the node
 * did with a request that left the caller is unknown. It is absent on every other error.
 */
export interface ImpulseError extends Error {
  name: "ImpulseError";
  code: string;
  nodeError?: true;
}

/**
 * Not part of the Impulse API. The rusty-kaspa crates linked into this module declare their own
 * wasm-bindgen types, which use HexString without declaring it; this keeps the generated
 * declarations type-checkable. The package entry (index.d.ts) does not export it.
 */
export type HexString = string;
"#;

// Arguments: JavaScript values are checked here before impulse-core sees them.

#[wasm_bindgen]
extern "C" {
    /// A Uint8Array made by `new Uint8Array(source)`.
    #[wasm_bindgen(js_name = Uint8Array)]
    type Uint8ArrayCopy;

    /// `new Uint8Array(source)`: a plain copy of a typed array, as long as the source's own
    /// length. Throws if the source's buffer is detached.
    #[wasm_bindgen(constructor, js_class = "Uint8Array", catch)]
    fn new(source: &Uint8Array) -> Result<Uint8ArrayCopy, JsValue>;
}

/// How many bytes a bytes argument may have, and how the refusal says so. Every legal value is far
/// below its bound; the bound only keeps a long value from being copied into wasm memory, which
/// never shrinks.
#[derive(Clone, Copy)]
struct Bound {
    longest: u32,
    expected: &'static str,
}

/// A raw transaction, and the scripts and canonical terms, which are parts of one. Every byte of
/// a transaction's size is a gram of compute mass (`mass_per_tx_byte` is 1 on mainnet and
/// testnet), and the builders refuse a transaction past `STANDARD_MASS_CAP` (100,000 grams, so
/// about 100,000 bytes); rusty-kaspa's borsh encoding adds some framing, so the bound is twice
/// the cap. The canonical terms (four destination scripts of at most `MAX_SCRIPT_LEN` bytes and a
/// few hundred bytes more) are far below it.
pub(crate) const TX_BYTES_LONGEST: u32 = (2 * impulse_core::tx::STANDARD_MASS_CAP) as u32;
const TX_BYTES: Bound = Bound {
    longest: (2 * impulse_core::tx::STANDARD_MASS_CAP) as u32,
    expected: "a Uint8Array of at most 200000 bytes",
};
/// A public key (32 bytes), a sighash (32) or a signature (65). impulse-core refuses any other
/// length with its own code; this keeps a long value from being copied first.
const SHORT_BYTES: Bound = Bound {
    longest: 1 << 10,
    expected: "a Uint8Array of at most 1024 bytes",
};

/// Bytes: a Uint8Array, or an instance of a subclass such as Node's Buffer, read through its own
/// length. `Uint8Array::to_vec` sizes its copy by the `length` getter, which a subclass can
/// override: a longer length would read stale wasm memory as input, a shorter one would write
/// past the copy. The constructor's copy has the source's own length, so `to_vec` reads that.
///
/// The length is measured against `bound` twice, and only then does the module's memory, which
/// never shrinks, take a byte: first the source's `length` before the copy, then the copy's own
/// length. The copy is made on the JavaScript side (a typed array of the source's real length),
/// so a value past the bound costs the module nothing; a subclass that overstates its `length`
/// is refused by the first check (it fails closed), one that understates it by the second.
fn bytes_arg(value: &JsValue, argument: &'static str, bound: Bound) -> Result<Vec<u8>, JsValue> {
    let wrong = |expected| js(SdkError::ArgumentType { argument, expected });
    let source = value
        .dyn_ref::<Uint8Array>()
        .filter(|_| ArrayBuffer::is_view(value))
        .ok_or_else(|| wrong("a Uint8Array"))?;
    if source.length() > bound.longest {
        return Err(wrong(bound.expected));
    }
    let copy: Uint8Array = Uint8ArrayCopy::new(source)
        .map_err(|_| wrong("a Uint8Array whose buffer is not detached"))?
        .unchecked_into();
    if copy.length() > bound.longest {
        return Err(wrong(bound.expected));
    }
    Ok(copy.to_vec())
}

/// A leg index must be an integer number; impulse-core then refuses anything but 0 and 1
/// (`TEMPLATE_LEG_INDEX`).
fn leg_arg(value: &JsValue) -> Result<LegIndex, JsValue> {
    const SAFE: f64 = 9_007_199_254_740_991.0; // Number.MAX_SAFE_INTEGER
    let wrong = || {
        js(SdkError::ArgumentType {
            argument: "leg",
            expected: "an integer number",
        })
    };
    let n = value.as_f64().ok_or_else(wrong)?;
    if n.fract() != 0.0 || n.abs() > SAFE {
        return Err(wrong());
    }
    LegIndex::from_index(n as i64).map_err(js)
}

/// Objects nest at most this deep in a terms or context value; terms nest two deep. The bound also
/// ends the walk of a cyclic object.
const MAX_JSON_DEPTH: usize = 4;
/// Objects and arrays nest at most this deep in a builder, verify or decode argument: a fee
/// payment with its inputs, their scriptPublicKeys; a Direct trade's cash token UTXO and its
/// state.
const MAX_TX_DEPTH: usize = 5;
/// At most this many keys in one object; the terms object has 17.
const MAX_JSON_KEYS: u32 = 64;
/// At most this many elements in one array of a builder, verify or decode argument. A
/// transaction with more inputs is far past the mass cap. The length is read before any element.
const MAX_JSON_ELEMENTS: u32 = 256;
/// At most this many UTF-16 code units in all the keys and strings of a JSON-form value
/// together, plus one per value. The longest legal terms hold four 10,000-byte scripts, 80,000
/// hex digits; a builder argument carries KCC-20 artifacts of at most 64 KiB each. Each string is
/// measured before it is copied into wasm memory, which never shrinks, so a value past the bound
/// costs the module nothing.
const MAX_JSON_TEXT: u32 = 1 << 18;

/// What a JSON-form argument may hold: the deepest nesting, and whether arrays are allowed.
#[derive(Clone, Copy)]
struct Shape {
    max_depth: usize,
    arrays: bool,
}

/// Terms, creation contexts and the other phase 1 forms: objects only.
const OBJECTS: Shape = Shape {
    max_depth: MAX_JSON_DEPTH,
    arrays: false,
};
/// The phase 2 forms: objects and arrays.
const OBJECTS_AND_ARRAYS: Shape = Shape {
    max_depth: MAX_TX_DEPTH,
    arrays: true,
};

fn json_arg(value: &JsValue, argument: &'static str) -> Result<serde_json::Value, JsValue> {
    let mut budget = MAX_JSON_TEXT;
    read_json(value, argument, 0, &mut budget, OBJECTS).map_err(js)
}

/// A builder, verify or decode argument: as `json_arg`, with arrays.
fn json_arg_tx(value: &JsValue, argument: &'static str) -> Result<serde_json::Value, JsValue> {
    let mut budget = MAX_JSON_TEXT;
    read_json(value, argument, 0, &mut budget, OBJECTS_AND_ARRAYS).map_err(js)
}

/// Spends `units` of the text budget of one JSON-form value.
fn charge(budget: &mut u32, units: u32, path: &str) -> Result<(), SdkError> {
    *budget = budget.checked_sub(units).ok_or_else(|| {
        SdkError::json(
            path,
            format!("more than {MAX_JSON_TEXT} characters in all; no argument is this long"),
        )
    })?;
    Ok(())
}

#[wasm_bindgen]
extern "C" {
    /// `Array.isArray`, caught: it throws on a revoked Proxy.
    #[wasm_bindgen(js_namespace = Array, js_name = isArray, catch)]
    fn is_array_checked(value: &JsValue) -> Result<bool, JsValue>;
}

/// Reads a JavaScript value as the JSON value it is, in Rust. `JSON.stringify` is not the
/// reader: it writes NaN, the infinities and an invalid Date as `null`, which the JSON form
/// reads as an absent optional, and it calls `toJSON` and drops `undefined`.
///
/// Read: null, booleans, finite numbers, strings, plain objects (prototype null or some realm's
/// `Object.prototype`) whose own properties are all enumerable data properties with string keys,
/// and, where the shape allows them, plain arrays (own `Array.prototype` of some realm, own
/// elements all enumerable data properties, no holes, no other property). A number is read as
/// serde_json reads its JSON text, so -0 and integers past 2^53 are not integers. Refused with
/// `SDK_JSON_FORM` at the path: undefined, NaN, the infinities, bigints, symbols, functions,
/// Dates, class instances, boxed primitives, getters and setters, symbol keys, non-enumerable
/// properties, and arrays where the shape has none, array subclasses, sparse arrays and arrays
/// with extra properties. The walk calls no getter and no `toJSON`; only a Proxy's traps run, and
/// what they throw is refused like any other value. So is a value past the bounds above.
fn read_json(
    value: &JsValue,
    path: &str,
    depth: usize,
    budget: &mut u32,
    shape: Shape,
) -> Result<serde_json::Value, SdkError> {
    use serde_json::Value;
    let refuse = |reason: &str| Err(SdkError::json(path, reason));
    charge(budget, 1, path)?;
    if value.is_null() {
        return Ok(Value::Null);
    }
    if let Some(b) = value.as_bool() {
        return Ok(Value::Bool(b));
    }
    if let Some(n) = value.as_f64() {
        return match json_number(n) {
            Some(n) => Ok(Value::Number(n)),
            None => refuse("NaN and the infinities are not JSON numbers"),
        };
    }
    if let Some(s) = value.dyn_ref::<JsString>() {
        charge(budget, s.length(), path)?;
        // A lone surrogate arrives as U+FFFD, which no JSON-form string admits.
        return Ok(Value::String(s.into()));
    }
    if value.is_undefined() {
        return refuse("undefined is not a JSON value; leave the key out");
    }
    if !value.is_object() {
        return refuse("a bigint, symbol or function is not a JSON value");
    }
    if depth == shape.max_depth {
        return refuse("objects nested too deeply");
    }
    let unreadable = |_| SdkError::json(path, "the object threw when read");
    let proto = Reflect::get_prototype_of(value).map_err(unreadable)?;
    let is_array = shape.arrays && is_array_checked(value).map_err(unreadable)?;
    // A plain object has no prototype, or one with none (some realm's Object.prototype). A plain
    // array has one more link: its own Array.prototype, then Object.prototype.
    let chain_ok = if is_array {
        let object_proto = if proto.is_null() {
            proto.clone()
        } else {
            Reflect::get_prototype_of(&proto).map_err(unreadable)?
        };
        !proto.is_null()
            && !object_proto.is_null()
            && Reflect::get_prototype_of(&object_proto)
                .map_err(unreadable)?
                .is_null()
    } else {
        proto.is_null()
            || Reflect::get_prototype_of(&proto)
                .map_err(unreadable)?
                .is_null()
    };
    if !chain_ok {
        return refuse(if shape.arrays {
            "expected a plain object or array, not a Date, class instance or boxed value"
        } else {
            "expected a plain object, not an array, Date, class instance or boxed value"
        });
    }
    let object: &Object = value.unchecked_ref();
    let keys = Reflect::own_keys(value).map_err(unreadable)?;
    if is_array {
        return read_array(object, &keys, path, depth, budget, shape);
    }
    let mut map = serde_json::Map::new();
    if keys.length() > MAX_JSON_KEYS {
        return refuse(&format!("more than {MAX_JSON_KEYS} keys"));
    }
    for key in keys.iter() {
        let Some(name) = key.dyn_ref::<JsString>() else {
            return refuse("a symbol key is not JSON");
        };
        charge(budget, name.length(), path)?;
        let name = String::from(name);
        let at = format!("{path}.{}", error::clipped(&name));
        let v = read_member(object, &key, &at, depth, budget, shape)?;
        map.insert(name, v);
    }
    Ok(Value::Object(map))
}

/// The value of an own enumerable data property, read through its descriptor.
fn read_member(
    object: &Object,
    key: &JsValue,
    at: &str,
    depth: usize,
    budget: &mut u32,
    shape: Shape,
) -> Result<serde_json::Value, SdkError> {
    let unreadable = |_| SdkError::json(at, "the object threw when read");
    let property = Reflect::get_own_property_descriptor(object, key).map_err(unreadable)?;
    if property.is_undefined() {
        return Err(SdkError::json(at, "a hole or a property that vanished"));
    }
    let field = |k: &str| Reflect::get(&property, &k.into()).map_err(unreadable);
    if field("enumerable")?.as_bool() != Some(true) {
        return Err(SdkError::json(at, "a non-enumerable property is not JSON"));
    }
    if !Reflect::has(&property, &"value".into()).map_err(unreadable)? {
        return Err(SdkError::json(at, "a getter or setter is not JSON"));
    }
    read_json(&field("value")?, at, depth + 1, budget, shape)
}

/// The elements of an array whose prototype chain `read_json` has checked. `keys` are its own
/// keys: the indices in order, then `length`.
fn read_array(
    object: &Object,
    keys: &js_sys::Array,
    path: &str,
    depth: usize,
    budget: &mut u32,
    shape: Shape,
) -> Result<serde_json::Value, SdkError> {
    let unreadable = |_| SdkError::json(path, "the array threw when read");
    let length = Reflect::get_own_property_descriptor(object, &"length".into())
        .map_err(unreadable)
        .and_then(|d| Reflect::get(&d, &"value".into()).map_err(unreadable))?
        .as_f64()
        .unwrap_or(f64::NAN);
    if !(length >= 0.0 && length.fract() == 0.0) {
        return Err(SdkError::json(path, "an array whose length is not a count"));
    }
    if length > f64::from(MAX_JSON_ELEMENTS) {
        return Err(SdkError::json(
            path,
            format!("more than {MAX_JSON_ELEMENTS} elements"),
        ));
    }
    let n = length as u32;
    // The indices in order, then `length`: no hole and no other property.
    let plain = keys.length() == n + 1
        && keys.get(n).as_string().as_deref() == Some("length")
        && (0..n).all(|i| keys.get(i).as_string() == Some(i.to_string()));
    if !plain {
        return Err(SdkError::json(
            path,
            "expected a plain array: no holes, no extra properties",
        ));
    }
    let mut items = Vec::with_capacity(n as usize);
    for i in 0..n {
        items.push(read_member(
            object,
            &keys.get(i),
            &format!("{path}[{i}]"),
            depth,
            budget,
            shape,
        )?);
    }
    Ok(serde_json::Value::Array(items))
}

/// A JavaScript number as serde_json reads its JSON text: an integer when it is one exactly
/// (at most 2^53 - 1 in magnitude, and not -0, which serde_json reads as a float), a float
/// otherwise, and nothing for NaN and the infinities.
fn json_number(n: f64) -> Option<serde_json::Number> {
    const SAFE: f64 = 9_007_199_254_740_991.0; // Number.MAX_SAFE_INTEGER
    let negative_zero = n == 0.0 && n.is_sign_negative();
    if n.fract() == 0.0 && n.abs() <= SAFE && !negative_zero {
        return Some(if n >= 0.0 {
            (n as u64).into()
        } else {
            (n as i64).into()
        });
    }
    serde_json::Number::from_f64(n)
}

/// A network name. A string longer than any name is refused before it is copied.
fn network_arg(value: &JsValue) -> Result<Network, JsValue> {
    const LONGEST: u32 = 64;
    let name = value.dyn_ref::<JsString>().ok_or_else(|| {
        js(SdkError::ArgumentType {
            argument: "network",
            expected: "a string",
        })
    })?;
    if name.length() > LONGEST {
        let reason = format!(
            "a string of {} characters is not one of mainnet, testnet",
            name.length()
        );
        return Err(js(SdkError::json("network", reason)));
    }
    json::network_from_json(&String::from(name)).map_err(js)
}

/// A u64 argument: a canonical decimal string, or a bigint that holds one.
fn u64_arg(value: &JsValue, argument: &'static str) -> Result<u64, JsValue> {
    // A u64 has at most 20 decimal digits.
    const LONGEST: u32 = 20;
    let wrong = || {
        js(SdkError::ArgumentType {
            argument,
            expected: "a decimal string or a bigint that holds a u64",
        })
    };
    let text = if let Some(s) = value.dyn_ref::<JsString>() {
        s.clone()
    } else if let Some(b) = value.dyn_ref::<js_sys::BigInt>() {
        b.to_string(10).map_err(|_| wrong())?
    } else {
        return Err(wrong());
    };
    if text.length() > LONGEST {
        return Err(wrong());
    }
    json::decimal_u64(&String::from(text)).ok_or_else(wrong)
}

/// An input index: an integer number from 0 to 2^32 - 1.
fn index_arg(value: &JsValue, argument: &'static str) -> Result<usize, JsValue> {
    let wrong = || {
        js(SdkError::ArgumentType {
            argument,
            expected: "an integer number from 0 to 4294967295",
        })
    };
    let n = value.as_f64().ok_or_else(wrong)?;
    // -0 is 0, as in a leg index.
    if n.fract() != 0.0 || !(0.0..=f64::from(u32::MAX)).contains(&n) {
        return Err(wrong());
    }
    Ok(n as usize)
}

/// A string argument of at most `longest` UTF-16 code units, measured before it is copied. Past
/// the bound is `SDK_JSON_FORM`, as for a network name.
fn text_arg(value: &JsValue, argument: &'static str, longest: u32) -> Result<String, JsValue> {
    let text = value.dyn_ref::<JsString>().ok_or_else(|| {
        js(SdkError::ArgumentType {
            argument,
            expected: "a string",
        })
    })?;
    if text.length() > longest {
        return Err(js(SdkError::json(
            argument,
            format!(
                "a string of {} characters; at most {longest} are read",
                text.length()
            ),
        )));
    }
    Ok(text.into())
}

// Terms.

/// impulse_core::terms::Terms: a plain terms value, anything that decodes. Run
/// `validateStructure` before using it for anything else.
#[wasm_bindgen(js_name = Terms)]
pub struct JsTerms {
    inner: Terms,
}

#[wasm_bindgen(js_class = Terms)]
impl JsTerms {
    /// Parses the JSON form (spec/ENCODING.md). Form only: refuses with `SDK_JSON_FORM`, and
    /// leaves the terms checks to `validateStructure`.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        #[wasm_bindgen(unchecked_param_type = "TermsJson")] json: JsValue,
    ) -> Result<JsTerms, JsValue> {
        let value = json_arg(&json, "terms")?;
        Ok(JsTerms {
            inner: json::terms_from_json(&value).map_err(js)?,
        })
    }

    /// Reads the text of a terms document: the JSON form of terms, a terms file (`terms`,
    /// `canonical`, `terms_hash`, spec/CLI.md) or a golden vector file (`name`, `description`
    /// and those three). Strict JSON that names no key twice; for the two file shapes the
    /// encoding of `terms` must equal `canonical` and its hash `terms_hash`
    /// (`SDK_TERMS_INCONSISTENT`). Form only otherwise, like `fromJson`: run `validateStructure`
    /// next. The text is the argument, not a parsed value, because `JSON.parse` keeps the last of
    /// two equal keys and reads a number past 2^53 inexactly.
    #[wasm_bindgen(js_name = fromFileText)]
    pub fn from_file_text(
        #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
    ) -> Result<JsTerms, JsValue> {
        let text = text.dyn_ref::<JsString>().ok_or_else(|| {
            js(SdkError::ArgumentType {
                argument: "text",
                expected: "a string",
            })
        })?;
        if text.length() > file::MAX_FILE_TEXT {
            return Err(js(SdkError::json(
                "file",
                format!(
                    "{} characters; no terms document is longer than {}",
                    text.length(),
                    file::MAX_FILE_TEXT
                ),
            )));
        }
        Ok(JsTerms {
            inner: file::terms_from_file_text(&String::from(text)).map_err(js)?,
        })
    }

    /// Refuses (`SDK_TERMS_INCONSISTENT`) unless `other` is the same terms: the same canonical
    /// bytes. For terms read back from a form that must be the terms they were loaded from.
    #[wasm_bindgen(js_name = requireSameAs)]
    pub fn require_same_as(&self, other: &JsTerms) -> Result<(), JsValue> {
        file::require_same(&self.inner, &other.inner).map_err(js)
    }

    /// The JSON form, keys in field order.
    #[wasm_bindgen(js_name = toJson, unchecked_return_type = "TermsJson")]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        js_sys::JSON::parse(&json::terms_to_json(&self.inner))
    }

    /// `Terms::decode`: canonical bytes only.
    pub fn decode(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: JsValue,
    ) -> Result<JsTerms, JsValue> {
        let bytes = bytes_arg(&bytes, "bytes", TX_BYTES)?;
        Ok(JsTerms {
            inner: Terms::decode(&bytes).map_err(js)?,
        })
    }

    /// `Terms::encode`: the canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.encode().map_err(js)
    }

    /// `Terms::terms_hash`: blake2b-256 keyed with `Impulse/terms/v1` over the canonical bytes.
    #[wasm_bindgen(js_name = termsHash)]
    pub fn terms_hash(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.terms_hash().map(|h| h.to_vec()).map_err(js)
    }

    /// `Terms::validate_structure`: the time-independent checks. This terms object stays usable.
    #[wasm_bindgen(js_name = validateStructure)]
    pub fn validate_structure(&self) -> Result<JsValidatedTerms, JsValue> {
        Ok(JsValidatedTerms {
            inner: self.inner.clone().validate_structure().map_err(js)?,
        })
    }
}

/// impulse_core::terms::ValidatedTerms: terms that passed the structure checks, with their
/// canonical bytes and hash. Only `Terms.validateStructure` and the decoders make one.
#[wasm_bindgen(js_name = ValidatedTerms)]
pub struct JsValidatedTerms {
    inner: ValidatedTerms,
}

#[wasm_bindgen(js_class = ValidatedTerms)]
impl JsValidatedTerms {
    /// `ValidatedTerms::decode`: canonical bytes, then the structure checks.
    pub fn decode(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] bytes: JsValue,
    ) -> Result<JsValidatedTerms, JsValue> {
        let bytes = bytes_arg(&bytes, "bytes", TX_BYTES)?;
        Ok(JsValidatedTerms {
            inner: ValidatedTerms::decode(&bytes).map_err(js)?,
        })
    }

    pub fn terms(&self) -> JsTerms {
        JsTerms {
            inner: self.inner.terms().clone(),
        }
    }

    pub fn canonical(&self) -> Vec<u8> {
        self.inner.canonical().to_vec()
    }

    #[wasm_bindgen(js_name = termsHash)]
    pub fn terms_hash(&self) -> Vec<u8> {
        self.inner.terms_hash().to_vec()
    }

    /// `ValidatedTerms::validate_creation`: network, expiry after the creation DAA score and
    /// within the horizon.
    #[wasm_bindgen(js_name = validateCreation)]
    pub fn validate_creation(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
    ) -> Result<(), JsValue> {
        let ctx = json::context_from_json(&json_arg(&context, "context")?).map_err(js)?;
        self.inner.validate_creation(&ctx).map_err(js)
    }

    /// The role check of spec/CLI.md ("Terms summary and role check"): `party` is `{ role, key,
    /// pins? }`. Throws `SDK_ROLE_KEY_MISMATCH`, `SDK_DESTINATION_PIN_INVALID` or
    /// `SDK_DESTINATION_NOT_MINE`; returns what passed. The funding instructions and a wallet's
    /// signing run it themselves, so a caller need not remember to.
    #[wasm_bindgen(js_name = roleCheck, unchecked_return_type = "RoleCheckJson")]
    pub fn role_check(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PartyJson")] party: JsValue,
    ) -> Result<JsValue, JsValue> {
        let party = role::party_from_json(&json_arg_tx(&party, "party")?, "party").map_err(js)?;
        let checked = role::check(self.inner.terms(), &party).map_err(js)?;
        js_sys::JSON::parse(&checked.to_json().to_string())
    }

    /// The funding instructions of a trade being created, the SDK's `impulse address`
    /// (spec/CLI.md, "Funding URI" and "Value cap"). Nothing is returned until every check has
    /// passed: the creation checks, a mainnet creation DAA score read from a node, the role check
    /// (`options.party`), the per-trade value cap, and every escrowed leg instantiated as a
    /// fundable vault. Only the leg the party's role funds gets a funding URI.
    #[wasm_bindgen(js_name = fundingInstructions, unchecked_return_type = "FundingInstructions")]
    pub fn funding_instructions(
        &self,
        #[wasm_bindgen(unchecked_param_type = "FundingOptionsJson")] options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let options =
            json::funding_options_from_json(&json_arg_tx(&options, "options")?).map_err(js)?;
        let out = funding::instructions(&self.inner, &options).map_err(js)?;
        js_sys::JSON::parse(&out.to_string())
    }

    /// `Vault::instantiate_existing(terms, leg)`: the vault of an existing trade (settle,
    /// refund, verify). It has no funding address.
    #[wasm_bindgen(js_name = instantiateExisting)]
    pub fn instantiate_existing(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
    ) -> Result<JsVault, JsValue> {
        let leg = leg_arg(&leg)?;
        Ok(JsVault {
            inner: Vault::instantiate_existing(&self.inner, leg).map_err(js)?,
        })
    }

    /// `Vault::instantiate_for_creation(terms, leg, ctx)`: the value cap (`value` is the
    /// declaration of the builders), the creation checks, then the vault. The only vault with a
    /// funding address, so no funding address is handed out for a trade above the cap.
    #[wasm_bindgen(js_name = instantiateForCreation)]
    pub fn instantiate_for_creation(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LegIndexNumber")] leg: JsValue,
        #[wasm_bindgen(unchecked_param_type = "CreationContextJson")] context: JsValue,
        #[wasm_bindgen(unchecked_param_type = "ValueJson")] value: JsValue,
    ) -> Result<JsFundableVault, JsValue> {
        let leg = leg_arg(&leg)?;
        let (context, value) = (json_arg(&context, "context")?, json_arg(&value, "value")?);
        Ok(JsFundableVault {
            inner: ops::instantiate_for_creation(&self.inner, leg, &context, &value).map_err(js)?,
        })
    }
}

// Template.

/// impulse_core::template::Vault: one leg's redeem script and its P2SH.
#[wasm_bindgen(js_name = Vault)]
pub struct JsVault {
    inner: Vault,
}

#[wasm_bindgen(js_class = Vault)]
impl JsVault {
    #[wasm_bindgen(unchecked_return_type = "Network")]
    pub fn network(&self) -> String {
        json::network_name(self.inner.network()).into()
    }

    #[wasm_bindgen(unchecked_return_type = "LegIndexNumber")]
    pub fn leg(&self) -> u8 {
        self.inner.leg().index()
    }

    /// The redeem script a spend of this vault reveals.
    #[wasm_bindgen(js_name = redeemScript)]
    pub fn redeem_script(&self) -> Vec<u8> {
        self.inner.redeem_script().to_vec()
    }

    /// The P2SH scriptPubKey: version 0, OpBlake2b OpData32 <script hash> OpEqual.
    #[wasm_bindgen(js_name = scriptPublicKey, unchecked_return_type = "ScriptPublicKeyValue")]
    pub fn script_public_key(&self) -> Result<JsValue, JsValue> {
        let spk = self.inner.script_public_key();
        let out = Object::new();
        Reflect::set(&out, &"version".into(), &spk.version().into())?;
        Reflect::set(
            &out,
            &"script".into(),
            &Uint8Array::from(spk.script()).into(),
        )?;
        Ok(out.into())
    }

    /// blake2b-256 of the redeem script; also the KCC-20 SCRIPT_HASH owner of the escrowed token.
    #[wasm_bindgen(js_name = scriptHash)]
    pub fn script_hash(&self) -> Vec<u8> {
        self.inner.script_hash().to_vec()
    }
}

/// impulse_core::template::FundableVault: a vault whose terms also passed the creation checks.
#[wasm_bindgen(js_name = FundableVault)]
pub struct JsFundableVault {
    inner: FundableVault,
}

#[wasm_bindgen(js_class = FundableVault)]
impl JsFundableVault {
    pub fn vault(&self) -> JsVault {
        JsVault {
            inner: self.inner.vault().clone(),
        }
    }

    /// `address::vault_address`: the address a depositor funds, prefix from the terms' network.
    pub fn address(&self) -> String {
        address::vault_address(&self.inner)
    }
}

/// The result of `decodeVault`: structure-checked terms and the leg index.
#[wasm_bindgen(js_name = DecodedVault)]
pub struct JsDecodedVault {
    terms: ValidatedTerms,
    leg: LegIndex,
}

#[wasm_bindgen(js_class = DecodedVault)]
impl JsDecodedVault {
    pub fn terms(&self) -> JsValidatedTerms {
        JsValidatedTerms {
            inner: self.terms.clone(),
        }
    }

    #[wasm_bindgen(unchecked_return_type = "LegIndexNumber")]
    pub fn leg(&self) -> u8 {
        self.leg.index()
    }
}

/// `template::decode`: a revealed redeem script back to its terms and leg index. Accepts only
/// a script that instantiation produces byte for byte.
#[wasm_bindgen(js_name = decodeVault)]
pub fn decode_vault(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] redeem_script: JsValue,
) -> Result<JsDecodedVault, JsValue> {
    let script = bytes_arg(&redeem_script, "redeemScript", TX_BYTES)?;
    let (terms, leg) = template::decode(&script).map_err(js)?;
    Ok(JsDecodedVault { terms, leg })
}

/// `template::template_hash_of_instance`: the template hash recomputed from a script's own
/// prefix and suffix bytes.
#[wasm_bindgen(js_name = templateHashOfInstance)]
pub fn template_hash_of_instance(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] script: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let script = bytes_arg(&script, "script", TX_BYTES)?;
    template::template_hash_of_instance(&script)
        .map(|h| h.to_vec())
        .map_err(js)
}

/// impulse_core::template::Template: the checked ImpulseVault template.
#[wasm_bindgen(js_name = Template)]
pub struct JsTemplate {
    hash: [u8; 32],
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

#[wasm_bindgen(js_class = Template)]
impl JsTemplate {
    pub fn hash(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    pub fn prefix(&self) -> Vec<u8> {
        self.prefix.clone()
    }

    pub fn suffix(&self) -> Vec<u8> {
        self.suffix.clone()
    }
}

/// `template::check`: the startup check of the embedded template. Every instantiation and
/// decode runs it; call it at startup to fail early.
#[wasm_bindgen(js_name = templateCheck)]
pub fn template_check() -> Result<JsTemplate, JsValue> {
    let t = template::check().map_err(js)?;
    Ok(JsTemplate {
        hash: t.hash(),
        prefix: t.prefix().to_vec(),
        suffix: t.suffix().to_vec(),
    })
}

// Addresses.

/// `address::prefix`: `kaspa` for mainnet, `kaspatest` for testnet.
#[wasm_bindgen(js_name = addressPrefix)]
pub fn address_prefix(
    #[wasm_bindgen(unchecked_param_type = "Network")] network: JsValue,
) -> Result<String, JsValue> {
    Ok(address::prefix(network_arg(&network)?).to_string())
}

// Funding helpers.

/// The QR code of a text, at the level `impulse address` prints. A text past the largest code
/// is `SDK_QR`; the length is measured before the text is copied into wasm memory.
#[wasm_bindgen(js_name = qrCode, unchecked_return_type = "QrCodeValue")]
pub fn qr_code(
    #[wasm_bindgen(unchecked_param_type = "string")] text: JsValue,
) -> Result<JsValue, JsValue> {
    /// A QR code holds at most 2,953 bytes (version 40, level L); a funding URI is under 200 (159 to 167 in the golden vectors).
    const LONGEST: u32 = 4096;
    let text = text.dyn_ref::<JsString>().ok_or_else(|| {
        js(SdkError::ArgumentType {
            argument: "text",
            expected: "a string",
        })
    })?;
    if text.length() > LONGEST {
        return Err(js(SdkError::Qr {
            reason: format!(
                "a text of {} characters does not fit a QR code",
                text.length()
            ),
        }));
    }
    let code = funding::qr(&String::from(text)).map_err(js)?;
    let out = Object::new();
    Reflect::set(&out, &"width".into(), &(code.width as f64).into())?;
    Reflect::set(
        &out,
        &"modules".into(),
        &Uint8Array::from(code.modules.as_slice()).into(),
    )?;
    Ok(out.into())
}

/// An amount of sompi as KAS with eight decimals, as `impulse address` prints it.
#[wasm_bindgen(js_name = kasFromSompi)]
pub fn kas_from_sompi(
    #[wasm_bindgen(unchecked_param_type = "U64String")] sompi: JsValue,
) -> Result<String, JsValue> {
    let wrong = || {
        js(SdkError::ArgumentType {
            argument: "sompi",
            expected: "a u64 as a decimal string",
        })
    };
    let text = sompi.dyn_ref::<JsString>().ok_or_else(wrong)?;
    // No u64 is longer than 20 digits; a longer string is refused before it is copied.
    if text.length() > 20 {
        return Err(wrong());
    }
    let sompi = json::decimal_u64(&String::from(text)).ok_or_else(wrong)?;
    Ok(funding::kas(sompi))
}

/// The default per-trade value cap in sompi, a u64 as a decimal string (10 KAS, decision D4).
#[wasm_bindgen(
    js_name = defaultValueCapSompi,
    unchecked_return_type = "U64String"
)]
pub fn default_value_cap_sompi() -> String {
    value::DEFAULT_MAX_VALUE_SOMPI.to_string()
}

// Constants and code lists.

/// `terms::TERMS_VERSION`.
#[wasm_bindgen(js_name = termsVersion)]
pub fn terms_version() -> u8 {
    TERMS_VERSION
}

/// `terms::TERMS_HASH_DOMAIN`, the blake2b key of the terms hash.
#[wasm_bindgen(js_name = termsHashDomain)]
pub fn terms_hash_domain() -> Vec<u8> {
    TERMS_HASH_DOMAIN.to_vec()
}

/// `terms::MAX_SCRIPT_LEN`.
#[wasm_bindgen(js_name = maxScriptLen)]
pub fn max_script_len() -> usize {
    MAX_SCRIPT_LEN
}

/// `terms::MAX_TEMPLATE_LEN`, a u64 as a decimal string.
#[wasm_bindgen(js_name = maxTemplateLen, unchecked_return_type = "U64String")]
pub fn max_template_len() -> String {
    MAX_TEMPLATE_LEN.to_string()
}

/// `terms::DEFAULT_MAX_EXPIRY_HORIZON_DAA`, a u64 as a decimal string.
#[wasm_bindgen(
    js_name = defaultMaxExpiryHorizonDaa,
    unchecked_return_type = "U64String"
)]
pub fn default_max_expiry_horizon_daa() -> String {
    DEFAULT_MAX_EXPIRY_HORIZON_DAA.to_string()
}

/// `template::CONTRACT_NAME`.
#[wasm_bindgen(js_name = contractName)]
pub fn contract_name() -> String {
    template::CONTRACT_NAME.into()
}

/// `terms::TERMS_ERROR_CODES`, in order.
#[wasm_bindgen(js_name = termsErrorCodes)]
pub fn terms_error_codes() -> Vec<String> {
    TERMS_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}

/// `template::TEMPLATE_ERROR_CODES`, in order.
#[wasm_bindgen(js_name = templateErrorCodes)]
pub fn template_error_codes() -> Vec<String> {
    TEMPLATE_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}

/// The SDK's own refusal codes, in order.
#[wasm_bindgen(js_name = sdkErrorCodes)]
pub fn sdk_error_codes() -> Vec<String> {
    SDK_ERROR_CODES.iter().map(|c| c.to_string()).collect()
}
