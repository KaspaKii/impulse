// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The builder world of the phase 2 parity rows (ERR-01, EDGE-01, EDGE-14): one real trade (a
//! KCC-20 asset against KAS cash, with a settlement authority) whose legs are funded by
//! impulse-core's fund builders and whose settle and refund are built by its settle and refund
//! builders from the funded outputs, then signed with throwaway keys and run in the real engine
//! at the budgets the builders committed. Written after tests/engine/builders.rs (the same
//! chain of builders, the same node rules), reduced to the one trade these rows need.
//!
//! Keys: throwaway keypairs from the harness, made at run time and erased on drop (docs/ENGINEERING-RULES.md
//! rule 1 exception). Nothing here writes, prints or stores a private key.

use crate::harness::{
    assert_accepted, execute, random_keypair, xonly, Kcc20State as HarnessState, Owner, TestKey,
    ASSET_TOKEN,
};
use impulse_core::locktime::{check_sequence_lock, check_tx_is_finalized};
use impulse_core::template::{FundableVault, LegIndex, Vault};
use impulse_core::terms::{
    CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg,
    LegKind, Network, SettlementMode, Terms, ValidatedTerms,
};
use impulse_core::tx::{
    fund_kas, fund_kcc20, refund, settle, FeePayment, Ipst, Kcc20Deposit, Kcc20State,
    Kcc20Template, RefundEscrow, RefundSigner, SettleCash, SettleLegs, TokenUtxo, TxError, Utxo,
    MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT,
};
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32};
use secp256k1::{Keypair, Message};

pub const LEG_AMOUNT: u64 = 1_000;
pub const KAS_CASH: u64 = 100_000_000;
pub const EARLIEST: u64 = 1_000_000;
pub const EXPIRY: u64 = 2_000_000;
/// The DAA score the builders are called at.
pub const NOW: u64 = 1_500_000;
/// DAA scores of the blocks that created the wallets' UTXOs and the vault UTXOs: before
/// earliest_daa, so the boundary rows can place a settle block at earliest_daa.
const WALLET_DAA: u64 = 800_000;
pub const FUNDED_DAA: u64 = 900_000;
const FEE: u64 = 5_000_000;
const WALLET: u64 = 100_000_000_000;
/// The seller holds more token than the leg needs, so funding makes token change.
pub const TOKEN_HELD: u64 = 3 * LEG_AMOUNT;

fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    let mut s = vec![OpData32];
    s.extend_from_slice(key);
    s.push(OpCheckSig);
    ScriptPublicKey::from_vec(0, s)
}

fn pubkey_owner(key: &[u8; 32]) -> Kcc20Owner {
    Kcc20Owner {
        identifier_type: IdentifierType::PubKey,
        identifier: *key,
    }
}

fn outpoint(label: &str) -> TransactionOutpoint {
    let mut id = [0u8; 32];
    for (i, b) in label.bytes().enumerate() {
        id[i % 32] ^= b.wrapping_add(i as u8);
    }
    id[31] ^= label.len() as u8;
    TransactionOutpoint::new(Hash::from_bytes(id), 0)
}

fn wallet_utxo(label: &str, key: &[u8; 32]) -> Utxo {
    Utxo {
        outpoint: outpoint(label),
        entry: UtxoEntry::new(WALLET, p2pk(key), WALLET_DAA, false, None),
    }
}

fn sign65(key: &Keypair, sighash: &[u8; 32]) -> [u8; 65] {
    let sig = key.sign_schnorr(Message::from_digest(*sighash));
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig.as_ref());
    out[64] = 0x01;
    out
}

/// A signed transaction and the IPST it came from.
pub struct Signed {
    pub ipst: Ipst,
    pub tx: Transaction,
}

impl Signed {
    pub fn entries(&self) -> &[UtxoEntry] {
        self.ipst.entries()
    }

    /// Output `index` as the UTXO a later transaction spends, created at `daa`.
    pub fn utxo(&self, index: usize, daa: u64) -> Utxo {
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

    /// Every input accepted by the engine at its committed budget.
    pub fn assert_engine_accepts(&self, label: &str) {
        for i in 0..self.tx.inputs.len() {
            assert_accepted(
                &execute(&self.tx, self.entries(), i),
                &format!("{label}: input {i}"),
            );
        }
    }

    /// The node's view in a block of DAA score `daa`: finality of the lock time, the sequence
    /// lock, then every input's scripts (the ports of rusty-kaspa a41a333, impulse-core's).
    pub fn node(&self, daa: u64) -> Result<(), String> {
        check_tx_is_finalized(&self.tx, daa, 0).map_err(|e| format!("finality: {e}"))?;
        let populated = PopulatedTransaction::new(&self.tx, self.entries().to_vec());
        check_sequence_lock(&populated, daa).map_err(|e| format!("sequence lock: {e}"))?;
        for i in 0..self.tx.inputs.len() {
            execute(&self.tx, self.entries(), i)
                .result
                .map_err(|e| format!("input {i}: {e:?}"))?;
        }
        Ok(())
    }
}

/// The vault UTXOs a funded trade holds.
pub struct Holdings {
    pub asset_escrow: Utxo,
    pub asset_authorizer: Utxo,
    pub cash_vault: Utxo,
}

/// A KCC-20 asset against KAS cash with a settlement authority, between throwaway parties.
pub struct Trade {
    seller: TestKey,
    buyer: TestKey,
    authority: TestKey,
    payer: TestKey,
    pub asset: Kcc20Template,
    pub terms: ValidatedTerms,
}

impl Trade {
    /// Terms with `funding`, `earliest` and `expiry`; they must pass the structure checks.
    pub fn new(funding: FundingMode, earliest: Option<u64>, expiry: u64) -> Self {
        let compiled = ASSET_TOKEN.compile(HarnessState::new(Owner::pubkey([0; 32]), 0));
        let asset = Kcc20Template::from_artifact(compiled.artifact).expect("KCC-20 template");
        let (seller, buyer, authority, payer) = (
            random_keypair(),
            random_keypair(),
            random_keypair(),
            random_keypair(),
        );
        let (s, b) = (xonly(&seller), xonly(&buyer));
        let terms = Terms {
            version: 1,
            network: Network::Mainnet,
            settlement_mode: SettlementMode::Vault,
            nonce: 77,
            seller_key: s,
            buyer_key: b,
            authority_key: Some(xonly(&authority)),
            asset_leg: Leg {
                kind: LegKind::Kcc20(Kcc20Token {
                    covenant_id: ASSET_TOKEN.cov.as_bytes(),
                    template_hash: asset.template_hash(),
                    template_prefix_len: asset.prefix_len() as u32,
                    template_suffix_len: asset.suffix_len() as u32,
                }),
                amount: LEG_AMOUNT,
            },
            cash_leg: Leg {
                kind: LegKind::Kas,
                amount: KAS_CASH,
            },
            buyer_delivery: Destination::Kcc20(pubkey_owner(&b)),
            seller_proceeds: Destination::Kas(p2pk(&s)),
            seller_refund: Destination::Kcc20(pubkey_owner(&s)),
            buyer_refund: Destination::Kas(p2pk(&b)),
            earliest_daa: earliest,
            expiry_daa: expiry,
            funding_mode: funding,
            trade_ref: [0x7E; 32],
        }
        .validate_structure()
        .expect("real terms");
        Self {
            seller,
            buyer,
            authority,
            payer,
            asset,
            terms,
        }
    }

    pub fn seller_key(&self) -> [u8; 32] {
        xonly(&self.seller)
    }

    pub fn fee(&self, label: &str) -> FeePayment {
        let payer = xonly(&self.payer);
        FeePayment {
            inputs: vec![wallet_utxo(label, &payer)],
            fee: FEE,
            change: p2pk(&payer),
        }
    }

    /// The vault of `leg`, as a funder gets it: the creation checks have run.
    pub fn fundable(&self, leg: LegIndex) -> FundableVault {
        let ctx = CreationContext::new(Network::Mainnet, FUNDED_DAA - 1);
        Vault::instantiate_for_creation(&self.terms, leg, &ctx).expect("fundable")
    }

    /// The seller's token UTXO holding `amount` of the asset.
    pub fn seller_token(&self, label: &str, amount: u64) -> TokenUtxo {
        let LegKind::Kcc20(token) = self.terms.terms().asset_leg.kind else {
            unreachable!("the asset leg is KCC-20")
        };
        let state = Kcc20State::new(pubkey_owner(&self.seller_key()), amount);
        TokenUtxo {
            utxo: Utxo {
                outpoint: outpoint(label),
                entry: UtxoEntry::new(
                    MIN_KCC20_OUTPUT,
                    self.asset.script_public_key(&state).expect("token script"),
                    WALLET_DAA,
                    false,
                    Some(Hash::from_bytes(token.covenant_id)),
                ),
            },
            state,
        }
    }

    /// The asset funding transaction, unsigned, for a deposit of `tokens`.
    pub fn fund_asset(&self, tokens: Vec<TokenUtxo>, now: u64) -> Result<Ipst, TxError> {
        let deposit = Kcc20Deposit {
            tokens,
            carrier: MIN_KCC20_OUTPUT,
            authorizer: MIN_KAS_OUTPUT,
        };
        fund_kcc20(
            &self.terms,
            &self.fundable(LegIndex::Asset),
            &self.asset,
            &deposit,
            &self.fee("fund-asset"),
            now,
        )
    }

    /// The cash funding transaction, unsigned, into `vault`.
    pub fn fund_cash_into(&self, vault: &FundableVault, now: u64) -> Result<Ipst, TxError> {
        fund_kas(&self.terms, vault, &self.fee("fund-cash"), now)
    }

    /// Signs every pending slot with the throwaway key it names, through the IPST's sighash.
    pub fn sign(&self, mut ipst: Ipst) -> Signed {
        for input in ipst.pending() {
            let signer = ipst.slots()[input].signer().expect("a signer");
            let sighash = ipst.slots()[input].sighash().expect("a sighash");
            let sig = sign65(self.key_of(&signer), &sighash);
            ipst.add_signature(input, &sig).expect("verified");
        }
        let tx = ipst.finalize().expect("every slot signed");
        Signed { ipst, tx }
    }

    fn key_of(&self, xonly_key: &[u8; 32]) -> &Keypair {
        [&self.seller, &self.buyer, &self.authority, &self.payer]
            .into_iter()
            .map(|k| &**k)
            .find(|k| xonly(k) == *xonly_key)
            .expect("a party of the trade signs")
    }

    /// Both legs funded by the fund builders at `NOW`, signed; the vault UTXOs are those
    /// transactions' outputs.
    pub fn holdings(&self) -> Holdings {
        let tokens = vec![self.seller_token("seller-token", TOKEN_HELD)];
        let asset = self.fund_asset(tokens, NOW).expect("asset fund builds");
        let cash = self
            .fund_cash_into(&self.fundable(LegIndex::Cash), NOW)
            .expect("cash fund builds");
        let (asset, cash) = (self.sign(asset), self.sign(cash));
        Holdings {
            asset_escrow: asset.utxo(0, FUNDED_DAA),
            asset_authorizer: asset.utxo(1, FUNDED_DAA),
            cash_vault: cash.utxo(0, FUNDED_DAA),
        }
    }

    /// The same vault UTXOs made by hand, as a depositor could make them with no builder: the
    /// escrowed token owned by the asset vault's script hash, the authorizer at the vault's
    /// address, the exact cash. For terms the fund builders refuse to fund.
    pub fn holdings_by_hand(&self) -> Holdings {
        let asset_vault = self.fundable(LegIndex::Asset);
        let LegKind::Kcc20(token) = self.terms.terms().asset_leg.kind else {
            unreachable!("the asset leg is KCC-20")
        };
        let state = Kcc20State::new(
            Kcc20Owner {
                identifier_type: IdentifierType::ScriptHash,
                identifier: asset_vault.vault().script_hash(),
            },
            LEG_AMOUNT,
        );
        let at = |label: &str, value: u64, spk: ScriptPublicKey, cov: Option<Hash>| Utxo {
            outpoint: outpoint(label),
            entry: UtxoEntry::new(value, spk, FUNDED_DAA, false, cov),
        };
        Holdings {
            asset_escrow: at(
                "hand-escrow",
                MIN_KCC20_OUTPUT,
                self.token_script(&state),
                Some(Hash::from_bytes(token.covenant_id)),
            ),
            asset_authorizer: at(
                "hand-authorizer",
                MIN_KAS_OUTPUT,
                asset_vault.vault().script_public_key(),
                None,
            ),
            cash_vault: at(
                "hand-cash",
                KAS_CASH,
                self.fundable(LegIndex::Cash).vault().script_public_key(),
                None,
            ),
        }
    }

    /// The settle of funded legs, unsigned, built as of the DAA score `now`.
    pub fn settle(&self, h: &Holdings, now: u64) -> Result<Ipst, TxError> {
        let legs = SettleLegs {
            asset_authorizer: h.asset_authorizer.clone(),
            asset_escrow: h.asset_escrow.clone(),
            asset_token: &self.asset,
            cash: SettleCash::Kas {
                vault: h.cash_vault.clone(),
            },
        };
        settle(&self.terms, &legs, &self.fee("settle-fee"), now)
    }

    /// The refund of the asset leg by `signer`, with the escrowed token, unsigned.
    pub fn refund_asset(&self, h: &Holdings, signer: RefundSigner) -> Result<Ipst, TxError> {
        let escrow = RefundEscrow {
            utxo: h.asset_escrow.clone(),
            amount: LEG_AMOUNT,
            is_minter: false,
            template: &self.asset,
        };
        refund(
            &self.terms,
            LegIndex::Asset,
            signer,
            &h.asset_authorizer,
            Some(&escrow),
            &self.fee("refund-fee"),
        )
    }

    /// `tx` (a copy of a built transaction with an edited field such as the lock time) signed
    /// again for the slots of `ipst`, so the engine judges the edit and not a stale signature.
    pub fn resign(&self, ipst: &Ipst, mut tx: Transaction) -> Transaction {
        for input in tx.inputs.iter_mut() {
            input.signature_script.clear();
        }
        let unsigned = tx.clone();
        for (i, slot) in ipst.slots().iter().enumerate() {
            let mut script = slot.script_before().to_vec();
            if let Some(signer) = slot.signer() {
                let hash =
                    impulse_core::tx::sighash(&unsigned, ipst.entries(), i).expect("sighash");
                script.push(0x41);
                script.extend_from_slice(&sign65(self.key_of(&signer), &hash));
                script.extend_from_slice(slot.script_after());
            }
            tx.inputs[i].signature_script = script;
        }
        tx.finalize();
        tx
    }

    /// The compiled asset token, for scripts the fund builder's outputs are checked against.
    pub fn token_script(&self, state: &Kcc20State) -> ScriptPublicKey {
        self.asset.script_public_key(state).expect("token script")
    }
}
