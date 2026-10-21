// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I18 engine proof for the hashlock builders (impulse_core::htlc, spec/V2.md section 10). Every
//! transaction the fund, claim and refund builders make, signed through the split flow (sighash
//! from the builder's slot, signature made here with a throwaway key, verified and assembled by
//! impulse-core), is run input by input through the real Kaspa script engine at the compute
//! budget the builder committed. The trade is chained: the vault is funded by the fund builder,
//! and the claim and the refunds spend those very outputs. The node's lock-time rule is composed
//! with the engine, one DAA score either side of expiry_daa.
//!
//! Also: the vault impulse-core instantiates from its embedded artifact is byte for byte the
//! contract the pinned compiler builds from contracts/impulse_hashlock.sil with the same state;
//! budgets follow the KCC-20 template length; every hashlock and escrow input stays within the
//! standard signature-operation limit.
//!
//! Keys: throwaway keypairs from the harness, erased on drop (rule 1 exception, docs/ENGINEERING-RULES.md). The
//! preimage is a fixed test value, not a secret of any trade.

mod harness;
mod htlc_harness;

use harness::{
    assert_accepted, execute, random_keypair, xonly, Compiled, Kcc20State as HState, Owner,
    TemplateRef, TestKey, Token, ASSET_TOKEN,
};
use impulse_core::htlc::{
    self, claim, fund, refund, verify_spent_input, Counterpart, CounterpartChain,
    HtlcCreationContext, HtlcIpst, HtlcRefundSigner, HtlcTerms, HtlcVault, MarginContext,
    ValidatedHtlcTerms, CLAIM_VAULT_BUDGET, DEFAULT_RETRY_SECS, REFUND_VAULT_BUDGET,
};
use impulse_core::locktime::{check_sequence_lock, check_tx_is_finalized};
use impulse_core::terms::{
    CreationContext, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
};
use impulse_core::tx::{
    FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, TokenUtxo, Utxo,
    MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32};
use kaspa_txscript::post_toccata_p2sh_sig_scanner;
use secp256k1::{Keypair, Message};
use silverscript_abi::ArtifactValue;

const AMOUNT: u64 = 1_000;
const TOKEN_HELD: u64 = 3 * AMOUNT;
const EXPIRY: u64 = 2_000_000;
/// The DAA score the builders are called at.
const NOW: u64 = 1_500_000;
const WALLET_DAA: u64 = 800_000;
const FUNDED_DAA: u64 = 900_000;
const FEE: u64 = 5_000_000;
const WALLET: u64 = 100_000_000_000;
const NOW_UNIX: u64 = 1_790_000_000;
/// The test preimage, and its hash lock in the terms.
const PREIMAGE: [u8; 32] = [0x5C; 32];
/// `MAX_STANDARD_P2SH_SIG_OPS` in kaspa-mining at a41a333 (crate-private there).
const MAX_STANDARD_P2SH_SIG_OPS: u64 = 15;

fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    let mut s = vec![OpData32];
    s.extend_from_slice(key);
    s.push(OpCheckSig);
    ScriptPublicKey::from_vec(0, s)
}

fn template_of(compiled: Compiled) -> Kcc20Template {
    Kcc20Template::from_artifact(compiled.artifact).expect("KCC-20 template")
}

fn fixture_template() -> Kcc20Template {
    template_of(ASSET_TOKEN.compile(HState::new(Owner::pubkey([0; 32]), 0)))
}

/// kcc20.sil with `lines` more requires in a branch no spend here takes: a longer template that
/// behaves the same (the padding of tests/engine/builders.rs).
fn padded_template(token: Token, lines: usize) -> Kcc20Template {
    let source = harness::kcc20_source();
    let tail = "        } else {\n            require(false);\n        }";
    assert!(
        source.contains(tail),
        "kcc20.sil has the branch the padding goes in"
    );
    let padding: String = (0..lines)
        .map(|i| {
            format!(
                "            require(ownerIdentifier != byte[32](0x{}));\n",
                format!("{:02x}", i % 256).repeat(32)
            )
        })
        .collect();
    let padded = source.replacen(
        tail,
        &format!("        }} else {{\n{padding}            require(false);\n        }}"),
        1,
    );
    template_of(Compiled::new(
        &padded,
        &[
            ArtifactValue::Bytes(vec![0; 32]),
            ArtifactValue::Int(0),
            ArtifactValue::Byte(0),
            ArtifactValue::Bool(false),
            ArtifactValue::Int(token.max_cov_ins),
            ArtifactValue::Int(token.max_cov_outs),
        ],
    ))
}

fn sign65(key: &Keypair, sighash: &[u8; 32]) -> [u8; 65] {
    let sig = key.sign_schnorr(Message::from_digest(*sighash));
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig.as_ref());
    out[64] = 0x01;
    out
}

/// A distinct outpoint per label (the pattern of tests/engine/builders.rs).
fn outpoint(label: &str) -> TransactionOutpoint {
    let mut id = [0u8; 32];
    for (i, b) in label.bytes().enumerate() {
        id[i % 32] ^= b.wrapping_add(i as u8);
    }
    id[31] ^= label.len() as u8;
    TransactionOutpoint::new(Hash::from_bytes(id), 0)
}

fn node_accepts(tx: &Transaction, entries: &[UtxoEntry], daa: u64) -> Result<(), String> {
    check_tx_is_finalized(tx, daa, 0).map_err(|e| format!("finality: {e}"))?;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    check_sequence_lock(&populated, daa).map_err(|e| format!("sequence lock: {e}"))?;
    for i in 0..tx.inputs.len() {
        execute(tx, entries, i)
            .result
            .map_err(|e| format!("input {i}: {e:?}"))?;
    }
    Ok(())
}

/// A hashlock trade between throwaway parties over a KCC-20 template.
struct Trade {
    seller: TestKey,
    buyer: TestKey,
    payer: TestKey,
    template: Kcc20Template,
    terms: ValidatedHtlcTerms,
}

impl Trade {
    fn new() -> Self {
        Self::with(fixture_template())
    }

    fn with(template: Kcc20Template) -> Self {
        let (seller, buyer, payer) = (random_keypair(), random_keypair(), random_keypair());
        let (s, b) = (xonly(&seller), xonly(&buyer));
        let owner = |key: [u8; 32]| Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: key,
        };
        let terms = HtlcTerms {
            version: 1,
            network: Network::Testnet,
            nonce: 77,
            seller_key: s,
            buyer_key: b,
            asset_leg: Leg {
                kind: LegKind::Kcc20(Kcc20Token {
                    covenant_id: ASSET_TOKEN.cov.as_bytes(),
                    template_hash: template.template_hash(),
                    template_prefix_len: template.prefix_len() as u32,
                    template_suffix_len: template.suffix_len() as u32,
                }),
                amount: AMOUNT,
            },
            buyer_delivery: owner(b),
            seller_refund: owner(s),
            hash_lock: htlc::sha256(&PREIMAGE),
            expiry_daa: EXPIRY,
            counterpart: Counterpart {
                chain: CounterpartChain::OtherSha256,
                chain_id: [0x01; 32],
                htlc_program: [0x02; 32],
                asset: [0x03; 32],
                amount: 5_000_000,
                recipient: [0x04; 32],
                refund: [0x05; 32],
                // 500,000 DAA to expiry at 20 per second is 25,000 s; T_C plus Δ is 21,660 s.
                timeout: NOW_UNIX + 5 * 3_600,
            },
            trade_ref: [0x7E; 32],
        }
        .validate_structure()
        .expect("real terms");
        Self {
            seller,
            buyer,
            payer,
            template,
            terms,
        }
    }

    fn token(&self) -> Kcc20Token {
        match self.terms.terms().asset_leg.kind {
            LegKind::Kcc20(t) => t,
            _ => unreachable!(),
        }
    }

    fn vault(&self) -> HtlcVault {
        HtlcVault::instantiate_existing(&self.terms).unwrap()
    }

    fn fee(&self, label: &str) -> FeePayment {
        let payer = xonly(&self.payer);
        FeePayment {
            inputs: vec![Utxo {
                outpoint: outpoint(label),
                entry: UtxoEntry::new(WALLET, p2pk(&payer), WALLET_DAA, false, None),
            }],
            fee: FEE,
            change: p2pk(&payer),
        }
    }

    /// Signs every pending slot with the key it names, through the slot's own sighash.
    fn sign(&self, mut ipst: HtlcIpst) -> Signed {
        let keys = [&self.seller, &self.buyer, &self.payer];
        for input in ipst.pending() {
            let slot = &ipst.slots()[input];
            let key = keys
                .iter()
                .find(|k| xonly(k) == slot.signer().unwrap())
                .expect("a party of the trade signs");
            let sig = sign65(key, &slot.sighash().unwrap());
            ipst.add_signature(input, &sig).expect("verified");
        }
        let tx = ipst.finalize().expect("every slot signed");
        Signed { ipst, tx }
    }

    fn fund(&self) -> Signed {
        let ctx = HtlcCreationContext {
            creation: CreationContext::new(Network::Testnet, NOW),
            margin: MarginContext {
                now_unix: NOW_UNIX,
                counterpart_final_secs: 60,
                retry_secs: DEFAULT_RETRY_SECS,
                sample: None,
            },
        };
        let vault = HtlcVault::instantiate_for_creation(&self.terms, &ctx).expect("fundable");
        let state = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::PubKey,
                identifier: xonly(&self.seller),
            },
            TOKEN_HELD,
        );
        let deposit = Kcc20Deposit {
            tokens: vec![TokenUtxo {
                utxo: Utxo {
                    outpoint: outpoint("seller-token"),
                    entry: UtxoEntry::new(
                        MIN_KCC20_OUTPUT,
                        self.template.script_public_key(&state).unwrap(),
                        WALLET_DAA,
                        false,
                        Some(ASSET_TOKEN.cov),
                    ),
                },
                state,
            }],
            carrier: MIN_KCC20_OUTPUT,
            authorizer: MIN_KAS_OUTPUT,
        };
        let ipst = fund(
            &self.terms,
            &vault,
            &self.template,
            &deposit,
            &self.fee("fund-fee"),
            NOW,
        )
        .expect("fund builds");
        self.sign(ipst)
    }

    fn claim(&self, funded: &Signed) -> Signed {
        let ipst = claim(
            &self.terms,
            &funded.utxo(1, FUNDED_DAA),
            &funded.utxo(0, FUNDED_DAA),
            &self.template,
            &PREIMAGE,
            &self.fee("claim-fee"),
        )
        .expect("claim builds");
        self.sign(ipst)
    }

    fn refund(&self, funded: &Signed, signer: HtlcRefundSigner, with_token: bool) -> Signed {
        let escrow = with_token.then(|| RefundEscrow {
            utxo: funded.utxo(0, FUNDED_DAA),
            amount: AMOUNT,
            is_minter: false,
            template: &self.template,
        });
        let ipst = refund(
            &self.terms,
            signer,
            &funded.utxo(1, FUNDED_DAA),
            escrow.as_ref(),
            &self.fee("refund-fee"),
        )
        .expect("refund builds");
        self.sign(ipst)
    }
}

struct Signed {
    ipst: HtlcIpst,
    tx: Transaction,
}

impl Signed {
    fn entries(&self) -> &[UtxoEntry] {
        self.ipst.entries()
    }

    /// Output `index` as the UTXO a later transaction spends, created at `daa`.
    fn utxo(&self, index: usize, daa: u64) -> Utxo {
        let o = &self.tx.outputs[index];
        Utxo {
            outpoint: TransactionOutpoint::new(self.tx.id(), index as u32),
            entry: UtxoEntry::new(
                o.value,
                o.script_public_key.clone(),
                daa,
                false,
                o.covenant.map(|c| c.covenant_id),
            ),
        }
    }

    fn assert_engine_accepts(&self, label: &str) {
        for i in 0..self.tx.inputs.len() {
            assert_accepted(
                &execute(&self.tx, self.entries(), i),
                &format!("{label}: input {i}"),
            );
        }
    }

    fn node(&self, daa: u64) -> Result<(), String> {
        node_accepts(&self.tx, self.entries(), daa)
    }

    /// The signature operations of input `i` under the pinned standardness scanner.
    fn sig_ops(&self, i: usize) -> u64 {
        post_toccata_p2sh_sig_scanner(
            &self.tx.inputs[i].signature_script,
            &self.entries()[i].script_public_key,
        )
    }
}

/// The vault impulse-core instantiates from its embedded artifact is the contract the pinned
/// compiler builds from the source with the same state, byte for byte.
#[test]
fn the_core_vault_is_the_compiled_contract() {
    let trade = Trade::new();
    let t = trade.terms.terms();
    let token = trade.token();
    let owner = |o: &Kcc20Owner| Owner {
        id_type: match o.identifier_type {
            IdentifierType::PubKey => 0,
            IdentifierType::ScriptHash => 1,
            IdentifierType::CovenantId => 2,
        },
        id: o.identifier,
    };
    let compiled = htlc_harness::HtlcTerms {
        version: t.version,
        network: 1,
        nonce: t.nonce.to_le_bytes(),
        seller_key: t.seller_key,
        buyer_key: t.buyer_key,
        asset: TemplateRef {
            cov: Hash::from_bytes(token.covenant_id),
            hash: token.template_hash,
            prefix_len: token.template_prefix_len.into(),
            suffix_len: token.template_suffix_len.into(),
        },
        amount: t.asset_leg.amount as i64,
        buyer_delivery: owner(&t.buyer_delivery),
        seller_refund: owner(&t.seller_refund),
        hash_lock: t.hash_lock,
        expiry_daa: t.expiry_daa as i64,
        counterpart_hash: t.counterpart.hash(),
        trade_ref: t.trade_ref,
    }
    .vault();
    assert_eq!(trade.vault().redeem_script(), compiled.bytecode());
}

#[test]
fn fund_then_claim() {
    let trade = Trade::new();
    let funded = trade.fund();
    funded.assert_engine_accepts("fund");
    assert_eq!(funded.node(FUNDED_DAA), Ok(()));
    let claimed = trade.claim(&funded);
    claimed.assert_engine_accepts("claim");
    assert_eq!(claimed.node(NOW), Ok(()), "claim before expiry");
    // R4: the claim stays valid at and after expiry_daa.
    assert_eq!(claimed.node(EXPIRY), Ok(()));
    assert_eq!(claimed.node(EXPIRY + 1_000), Ok(()));
    // The asset reaches the buyer, the authorizer's KAS the seller.
    let delivered = Kcc20State::new(trade.terms.terms().buyer_delivery, AMOUNT);
    assert_eq!(
        claimed.tx.outputs[0].script_public_key,
        trade.template.script_public_key(&delivered).unwrap()
    );
    assert_eq!(
        claimed.tx.outputs[1].script_public_key,
        p2pk(&xonly(&trade.seller))
    );
    // The claim's vault input verifies against the agreed terms and the UTXO it spends.
    assert_eq!(
        verify_spent_input(
            &trade.terms,
            &claimed.tx.inputs[0],
            &funded.tx.outputs[1].script_public_key
        ),
        Ok(())
    );
    // The committed budgets cover what the inputs use, and the claim budget's floor holds.
    let budget = |s: &Signed, i: usize| s.tx.inputs[i].compute_commit.compute_budget().unwrap();
    assert!(budget(&claimed, 0) >= CLAIM_VAULT_BUDGET);
    for i in 0..2 {
        assert!(claimed.sig_ops(i) <= MAX_STANDARD_P2SH_SIG_OPS, "input {i}");
    }
    // The terms check passes the signed document's transaction.
    assert!(claimed
        .ipst
        .verify_against_terms(&trade.template, NOW)
        .is_ok());
}

#[test]
fn refunds() {
    let trade = Trade::new();
    let funded = trade.fund();
    // The seller, with the token and alone: from expiry_daa + 1 (the node's lock-time rule).
    for with_token in [true, false] {
        let r = trade.refund(&funded, HtlcRefundSigner::Seller, with_token);
        let label = format!("seller refund, token {with_token}");
        r.assert_engine_accepts(&label);
        assert!(r.node(EXPIRY).is_err(), "{label}: not before expiry");
        assert_eq!(r.node(EXPIRY + 1), Ok(()), "{label}");
        assert!(
            r.tx.inputs[0].compute_commit.compute_budget().unwrap() >= REFUND_VAULT_BUDGET,
            "{label}"
        );
        for i in 0..r.tx.inputs.len() - 1 {
            assert!(
                r.sig_ops(i) <= MAX_STANDARD_P2SH_SIG_OPS,
                "{label}: input {i}"
            );
        }
    }
    // The buyer sends the asset home at any time.
    let r = trade.refund(&funded, HtlcRefundSigner::Buyer, true);
    r.assert_engine_accepts("buyer refund");
    assert_eq!(r.node(FUNDED_DAA + 1), Ok(()));
    let home = Kcc20State::new(trade.terms.terms().seller_refund, AMOUNT);
    assert_eq!(
        r.tx.outputs[1].script_public_key,
        trade.template.script_public_key(&home).unwrap()
    );
}

/// The budgets follow the KCC-20 template's length: every builder's transaction runs within its
/// committed budget for templates of 1,461, 3,771 and 6,081 bytes (measured by this test). The
/// lengths are pinned, so a change to the padding lines covered fails here and not silently.
#[test]
fn budgets_follow_the_template_length() {
    for (lines, expected_bytes) in [(0, 1_461), (30, 3_771), (60, 6_081)] {
        let template = if lines == 0 {
            fixture_template()
        } else {
            padded_template(ASSET_TOKEN, lines)
        };
        let bytes = template.prefix_len() + template.suffix_len();
        println!("htlc_builders: {lines} padding lines, {bytes} template bytes");
        assert_eq!(
            bytes, expected_bytes,
            "{lines} padding lines: template length differs from the length the I18 report states"
        );
        let trade = Trade::with(template);
        let funded = trade.fund();
        funded.assert_engine_accepts(&format!("{bytes} template bytes: fund"));
        trade
            .claim(&funded)
            .assert_engine_accepts(&format!("{bytes} template bytes: claim"));
        for (signer, with_token) in [
            (HtlcRefundSigner::Seller, true),
            (HtlcRefundSigner::Seller, false),
            (HtlcRefundSigner::Buyer, true),
        ] {
            trade
                .refund(&funded, signer, with_token)
                .assert_engine_accepts(&format!(
                    "{bytes} template bytes: refund {signer:?} token {with_token}"
                ));
        }
    }
}
