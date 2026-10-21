// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I16 core step: engine proof of the v2 builders (impulse_core::v2, spec/V2.md section 6).
//! Every transaction a v2 builder makes is signed through the split flow (sighash from the IPST,
//! signature made here with a throwaway key, verified and assembled by impulse-core) and run
//! input by input through the real Kaspa script engine (rusty-kaspa a41a333, covenants enabled)
//! with the compute budget the builder committed. Trades are chained: each leg is funded by the
//! v2 fund builders, and settle and refund spend those very outputs.
//!
//! Shapes: the 3-way ring, the 3-way with a KAS leg, the ten-leg bilateral list, and N = 2 in v1's
//! KAS-cash and KCC-20-cash modes, with and without an authority. Each vault script the core
//! instantiates is also compared with the pinned silverc's compile of contracts/impulse_vault_v2.sil
//! for the same constructor, built here from spec/V2.md 4.2.
//!
//! Keys: throwaway keypairs from the harness, erased on drop (rule 1 exception, docs/ENGINEERING-RULES.md).

mod harness;
use harness::{
    assert_accepted, execute, random_keypair, repo_path, xonly, Compiled,
    Kcc20State as HarnessState, Owner, TestKey, Token, ASSET_TOKEN,
};

use impulse_core::locktime::{check_sequence_lock, check_tx_is_finalized};
use impulse_core::terms::{
    CreationContext, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg, LegKind, Network,
};
use impulse_core::tx::{
    FeePayment, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, TokenUtxo, Utxo,
};
use impulse_core::v2::{
    fund_kas, fund_kcc20, min_v2, min_vault_v2, read_settle, refund, settle, settle_tranche,
    DestinationV2, IpstV2, LegV2, Partial, RefundSignerV2, SettleLeg, TermsV2, TokenEscrow,
    ValidatedTermsV2, VaultV2, TERMS_V2_VERSION,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32};
use secp256k1::{Keypair, Message};
use silverscript_abi::ArtifactValue;

const EARLIEST: u64 = 1_000_000;
const EXPIRY: u64 = 2_000_000;
const NOW: u64 = 1_500_000;
const WALLET_DAA: u64 = 800_000;
const FUNDED_DAA: u64 = 900_000;
const WALLET: u64 = 100_000_000_000;
const FEE: u64 = 50_000_000;
const TOKEN_AMOUNT: u64 = 1_000;
const KAS_AMOUNT: u64 = 100_000_000;

fn token_of(j: usize) -> Token {
    Token {
        cov: Hash::from_bytes([0x10 + j as u8; 32]),
        ..ASSET_TOKEN
    }
}

fn template() -> Kcc20Template {
    let compiled = ASSET_TOKEN.compile(HarnessState::new(Owner::pubkey([0; 32]), 0));
    Kcc20Template::from_artifact(compiled.artifact).expect("KCC-20 template")
}

fn token_terms(t: &Kcc20Template, j: usize) -> Kcc20Token {
    Kcc20Token {
        covenant_id: token_of(j).cov.as_bytes(),
        template_hash: t.template_hash(),
        template_prefix_len: t.prefix_len() as u32,
        template_suffix_len: t.suffix_len() as u32,
    }
}

fn p2pk(key: &[u8; 32]) -> ScriptPublicKey {
    let mut s = vec![OpData32];
    s.extend_from_slice(key);
    s.push(OpCheckSig);
    ScriptPublicKey::from_vec(0, s)
}

fn pubkey(id: [u8; 32]) -> DestinationV2 {
    DestinationV2 {
        identifier_type: IdentifierType::PubKey,
        identifier: id,
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

fn sign65(key: &Keypair, sighash: &[u8; 32]) -> [u8; 65] {
    let sig = key.sign_schnorr(Message::from_digest(*sighash));
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(sig.as_ref());
    out[64] = SIG_HASH_ALL.to_u8();
    out
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    Ring3,
    WithKas3,
    Bilateral10,
    TwoKas,
    TwoKcc20,
    /// Three KAS legs in a ring: the mainnet demo's `kas` shape.
    KasRing3,
}

struct Trade {
    parties: Vec<TestKey>,
    authority: TestKey,
    payer: TestKey,
    terms: ValidatedTermsV2,
    template: Kcc20Template,
}

impl Trade {
    fn new(shape: Shape, with_authority: bool, funding: FundingMode) -> Self {
        let template = template();
        let count = match shape {
            Shape::Ring3 | Shape::WithKas3 | Shape::KasRing3 => 3,
            _ => 2,
        };
        let parties: Vec<TestKey> = (0..count).map(|_| random_keypair()).collect();
        let authority = random_keypair();
        let payer = random_keypair();
        let p = |i: usize| xonly(&parties[i]);
        let kcc20 = |j: usize, from: usize, to: usize, amount: u64| LegV2 {
            depositor_key: p(from),
            asset: Leg {
                kind: LegKind::Kcc20(token_terms(&template, j)),
                amount,
            },
            delivery: pubkey(p(to)),
            refund: pubkey(p(from)),
        };
        let kas = |from: usize, to: usize, amount: u64| LegV2 {
            depositor_key: p(from),
            asset: Leg {
                kind: LegKind::Kas,
                amount,
            },
            delivery: pubkey(p(to)),
            refund: DestinationV2 {
                identifier_type: IdentifierType::ScriptHash,
                identifier: [0x5A + from as u8; 32],
            },
        };
        let legs = match shape {
            Shape::Ring3 => (0..3)
                .map(|i| kcc20(i, i, (i + 1) % 3, TOKEN_AMOUNT * (i as u64 + 1)))
                .collect(),
            Shape::WithKas3 => vec![
                kcc20(0, 0, 1, TOKEN_AMOUNT),
                kcc20(1, 1, 2, TOKEN_AMOUNT * 2),
                kas(2, 0, KAS_AMOUNT),
            ],
            Shape::Bilateral10 => {
                let mut legs: Vec<LegV2> = (0..9)
                    .map(|j| {
                        let (from, to) = if j % 2 == 0 { (0, 1) } else { (1, 0) };
                        kcc20(j, from, to, TOKEN_AMOUNT * (j as u64 + 1))
                    })
                    .collect();
                legs.push(kas(1, 0, KAS_AMOUNT * 3));
                legs
            }
            Shape::KasRing3 => (0..3)
                .map(|i| kas(i, (i + 1) % 3, KAS_AMOUNT * (i as u64 + 1)))
                .collect(),
            Shape::TwoKas => vec![kcc20(0, 0, 1, TOKEN_AMOUNT), kas(1, 0, KAS_AMOUNT)],
            Shape::TwoKcc20 => vec![
                kcc20(0, 0, 1, TOKEN_AMOUNT),
                kcc20(1, 1, 0, TOKEN_AMOUNT * 250),
            ],
        };
        let terms = TermsV2 {
            version: TERMS_V2_VERSION,
            network: Network::Mainnet,
            nonce: 77,
            authority_key: with_authority.then(|| xonly(&authority)),
            legs,
            earliest_daa: Some(EARLIEST),
            expiry_daa: EXPIRY,
            funding_mode: funding,
            partial: None,
            trade_ref: [0x7E; 32],
        }
        .validate_structure()
        .expect("terms validate");
        Self {
            parties,
            authority,
            payer,
            terms,
            template,
        }
    }

    /// The same shape as partial terms of `lot_count` lots (every amount a multiple of it, KAS
    /// legs four times as large so a lot and a remainder each hold MIN_V2 of a vault output).
    fn partial(shape: Shape, with_authority: bool, lot_count: u64, min_lot: u64) -> Self {
        let mut trade = Self::new(shape, with_authority, FundingMode::Revocable);
        let mut t = trade.terms.terms().clone();
        for l in &mut t.legs {
            if l.asset.kind == LegKind::Kas {
                l.asset.amount *= 4;
            }
            l.asset.amount *= lot_count;
        }
        t.partial = Some(Partial { lot_count, min_lot });
        trade.terms = t.validate_structure().expect("partial terms validate");
        trade
    }

    fn n(&self) -> usize {
        self.terms.terms().legs.len()
    }

    fn settle_legs<'a>(&'a self, funded: &[(Utxo, Option<(Utxo, u64)>)]) -> Vec<SettleLeg<'a>> {
        funded
            .iter()
            .map(|(vault, escrow)| match escrow {
                None => SettleLeg::Kas {
                    vault: vault.clone(),
                },
                Some((utxo, amount)) => SettleLeg::Kcc20 {
                    authorizer: vault.clone(),
                    escrow: TokenEscrow {
                        utxo: utxo.clone(),
                        amount: *amount,
                        template: &self.template,
                    },
                },
            })
            .collect()
    }

    fn tranche(&self, funded: &[(Utxo, Option<(Utxo, u64)>)], lots: u64, label: &str) -> Signed {
        self.sign(
            settle_tranche(
                &self.terms,
                &self.settle_legs(funded),
                lots,
                &self.fee(label),
                NOW,
            )
            .expect("tranche builds"),
        )
    }

    /// The vaults and escrows a tranche left, as the next transaction spends them.
    fn continued(
        &self,
        tranche: &Signed,
        funded: &[(Utxo, Option<(Utxo, u64)>)],
        lots: u64,
    ) -> Vec<(Utxo, Option<(Utxo, u64)>)> {
        let n = self.n();
        let t = self.terms.terms();
        (0..n)
            .map(|i| {
                let vault = tranche.utxo(n + i);
                let escrow = funded[i]
                    .1
                    .as_ref()
                    .map(|(_, held)| (tranche.utxo(2 * n + i), held - lots * t.unit(i)));
                (vault, escrow)
            })
            .collect()
    }

    fn keys(&self) -> Vec<&TestKey> {
        let mut keys: Vec<&TestKey> = self.parties.iter().collect();
        keys.push(&self.authority);
        keys.push(&self.payer);
        keys
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

    /// Signs every pending slot with the key it names, through the IPST's own sighash.
    fn sign(&self, mut ipst: IpstV2) -> Signed {
        for input in ipst.pending() {
            let slot = &ipst.slots()[input];
            let key = self
                .keys()
                .into_iter()
                .find(|k| xonly(k) == slot.signer().unwrap())
                .expect("a key of the trade signs");
            let sig = sign65(key, &slot.sighash().unwrap());
            ipst.add_signature(input, &sig).expect("verified");
        }
        let tx = ipst.finalize().expect("every slot signed");
        Signed { ipst, tx }
    }

    /// Funds every leg with the v2 fund builders; returns per leg (vault UTXO, escrow UTXO).
    fn fund(&self) -> Vec<(Utxo, Option<(Utxo, u64)>)> {
        let t = self.terms.terms();
        let ctx = CreationContext::new(Network::Mainnet, FUNDED_DAA - 1);
        (0..self.n())
            .map(|i| {
                let vault = VaultV2::instantiate_for_creation(&self.terms, i, &ctx).unwrap();
                let l = &t.legs[i];
                match l.asset.kind {
                    LegKind::Kas => {
                        let s = self.sign(
                            fund_kas(
                                &self.terms,
                                &vault,
                                &self.fee(&format!("fund-kas-{i}")),
                                NOW,
                            )
                            .expect("fund_kas"),
                        );
                        s.assert_engine_accepts(&format!("fund KAS leg {i}"));
                        (s.utxo(0), None)
                    }
                    LegKind::Kcc20(token) => {
                        let state = Kcc20State::new(
                            Kcc20Owner {
                                identifier_type: IdentifierType::PubKey,
                                identifier: l.depositor_key,
                            },
                            l.asset.amount * 3,
                        );
                        let wallet_token = TokenUtxo {
                            utxo: Utxo {
                                outpoint: outpoint(&format!("wallet-token-{i}")),
                                entry: UtxoEntry::new(
                                    min_v2(t, 2),
                                    self.template.script_public_key(&state).unwrap(),
                                    WALLET_DAA,
                                    false,
                                    Some(Hash::from_bytes(token.covenant_id)),
                                ),
                            },
                            state,
                        };
                        let deposit = Kcc20Deposit {
                            tokens: vec![wallet_token],
                            carrier: min_v2(t, 2),
                            authorizer: min_vault_v2(t),
                        };
                        let s = self.sign(
                            fund_kcc20(
                                &self.terms,
                                &vault,
                                &self.template,
                                &deposit,
                                &self.fee(&format!("fund-token-{i}")),
                                NOW,
                            )
                            .expect("fund_kcc20"),
                        );
                        s.assert_engine_accepts(&format!("fund KCC-20 leg {i}"));
                        (s.utxo(1), Some((s.utxo(0), l.asset.amount)))
                    }
                    LegKind::External => unreachable!("v2 legs are KAS or KCC-20"),
                }
            })
            .collect()
    }

    fn settle(&self, funded: &[(Utxo, Option<(Utxo, u64)>)]) -> Signed {
        let legs: Vec<SettleLeg<'_>> = funded
            .iter()
            .map(|(vault, escrow)| match escrow {
                None => SettleLeg::Kas {
                    vault: vault.clone(),
                },
                Some((utxo, amount)) => SettleLeg::Kcc20 {
                    authorizer: vault.clone(),
                    escrow: TokenEscrow {
                        utxo: utxo.clone(),
                        amount: *amount,
                        template: &self.template,
                    },
                },
            })
            .collect();
        self.sign(settle(&self.terms, &legs, &self.fee("settle"), NOW).expect("settle builds"))
    }

    fn refund(
        &self,
        funded: &[(Utxo, Option<(Utxo, u64)>)],
        leg: usize,
        signer: RefundSignerV2,
        with_token: bool,
    ) -> Signed {
        let (vault, escrow) = &funded[leg];
        let escrow = escrow
            .as_ref()
            .filter(|_| with_token)
            .map(|(utxo, amount)| RefundEscrow {
                utxo: utxo.clone(),
                amount: *amount,
                is_minter: false,
                template: &self.template,
            });
        self.sign(
            refund(
                &self.terms,
                leg,
                signer,
                vault,
                escrow.as_ref(),
                &self.fee("refund"),
            )
            .expect("refund builds"),
        )
    }

    /// The constructor of contracts/impulse_vault_v2.sil for leg `i`, from spec/V2.md 4.2 alone.
    fn ctor(&self, i: usize) -> Vec<ArtifactValue> {
        use ArtifactValue::{Bool, Byte, Bytes, Int};
        let t = self.terms.terms();
        let mut legs = Vec::new();
        for l in &t.legs {
            legs.extend_from_slice(&l.depositor_key);
            let (kind, cov, hash, p, s) = match l.asset.kind {
                LegKind::Kcc20(k) => (
                    1u8,
                    k.covenant_id,
                    k.template_hash,
                    u64::from(k.template_prefix_len),
                    u64::from(k.template_suffix_len),
                ),
                _ => (0, [0; 32], [0; 32], 0, 0),
            };
            legs.push(kind);
            legs.extend_from_slice(&cov);
            legs.extend_from_slice(&hash);
            legs.extend_from_slice(&p.to_le_bytes());
            legs.extend_from_slice(&s.to_le_bytes());
            legs.extend_from_slice(&l.asset.amount.to_le_bytes());
            for d in [l.delivery, l.refund] {
                legs.push(match d.identifier_type {
                    IdentifierType::PubKey => 0,
                    IdentifierType::ScriptHash => 1,
                    IdentifierType::CovenantId => 2,
                });
                legs.extend_from_slice(&d.identifier);
            }
        }
        vec![
            Byte(2),
            Byte(0),
            Bytes(t.nonce.to_le_bytes().to_vec()),
            Bool(t.authority_key.is_some()),
            Bytes(t.authority_key.unwrap_or([0; 32]).to_vec()),
            Int(t.legs.len() as i64),
            Bytes(legs),
            Bool(t.earliest_daa.is_some()),
            Int(t.earliest_daa.unwrap_or(0) as i64),
            Int(t.expiry_daa as i64),
            Byte(match t.funding_mode {
                FundingMode::Revocable => 0,
                FundingMode::Earmarked => 1,
            }),
            Bytes(t.trade_ref.to_vec()),
            Int(t.partial.map_or(1, |p| p.lot_count as i64)),
            Int(t.partial.map_or(1, |p| p.min_lot as i64)),
            Int(i as i64),
        ]
    }
}

struct Signed {
    ipst: IpstV2,
    tx: Transaction,
}

impl Signed {
    fn utxo(&self, index: usize) -> Utxo {
        let o = &self.tx.outputs[index];
        Utxo {
            outpoint: TransactionOutpoint::new(self.tx.id(), index as u32),
            entry: UtxoEntry::new(
                o.value,
                o.script_public_key.clone(),
                FUNDED_DAA,
                false,
                o.covenant.map(|c| c.covenant_id),
            ),
        }
    }

    fn assert_engine_accepts(&self, label: &str) {
        for i in 0..self.tx.inputs.len() {
            assert_accepted(
                &execute(&self.tx, self.ipst.entries(), i),
                &format!("{label}: input {i}"),
            );
        }
    }

    /// The node's view in a block of DAA score `daa`: finality of the lock time, the sequence
    /// lock, then every input's scripts at its committed budget.
    fn node(&self, daa: u64) -> Result<(), String> {
        check_tx_is_finalized(&self.tx, daa, 0).map_err(|e| format!("finality: {e}"))?;
        let populated = PopulatedTransaction::new(&self.tx, self.ipst.entries().to_vec());
        check_sequence_lock(&populated, daa).map_err(|e| format!("sequence lock: {e}"))?;
        for i in 0..self.tx.inputs.len() {
            execute(&self.tx, self.ipst.entries(), i)
                .result
                .map_err(|e| format!("input {i}: {e:?}"))?;
        }
        Ok(())
    }
}

const SHAPES: [Shape; 6] = [
    Shape::Ring3,
    Shape::WithKas3,
    Shape::Bilateral10,
    Shape::TwoKas,
    Shape::TwoKcc20,
    Shape::KasRing3,
];

/// The core's v2 vault scripts are the pinned silverc's compile of the v2 source for the
/// constructor spec/V2.md 4.2 gives, leg by leg.
#[test]
fn core_vault_scripts_are_the_compilers() {
    let source = std::fs::read_to_string(repo_path("contracts/impulse_vault_v2.sil")).unwrap();
    for shape in [
        Shape::Ring3,
        Shape::WithKas3,
        Shape::Bilateral10,
        Shape::KasRing3,
    ] {
        let trade = Trade::new(shape, true, FundingMode::Revocable);
        for i in 0..trade.n() {
            let core = VaultV2::instantiate_existing(&trade.terms, i).unwrap();
            let compiled = Compiled::new(&source, &trade.ctor(i));
            assert_eq!(
                core.redeem_script(),
                compiled.bytecode(),
                "{shape:?} leg {i}"
            );
        }
    }
}

/// Fund every leg, then settle all of them in one transaction: every input of every
/// transaction accepted at its committed budget, the settle not before earliest_daa.
#[test]
fn builders_fund_and_settle_every_shape_in_the_engine() {
    for shape in SHAPES {
        for with_authority in [true, false] {
            let trade = Trade::new(shape, with_authority, FundingMode::Revocable);
            let funded = trade.fund();
            let s = trade.settle(&funded);
            let label = format!("{shape:?} authority {with_authority}");
            s.assert_engine_accepts(&format!("settle {label}"));
            assert!(s.node(EARLIEST).is_err(), "{label}: settle before earliest");
            s.node(EARLIEST + 1)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            // Every delivery went where the terms say.
            let t = trade.terms.terms();
            for (j, l) in t.legs.iter().enumerate() {
                if l.asset.kind == LegKind::Kas {
                    assert_eq!(s.tx.outputs[j].value, l.asset.amount);
                }
            }
        }
    }
}

/// Refund every leg in each role the contract admits, with and without the escrowed token.
#[test]
fn builders_refund_every_leg_in_the_engine() {
    for shape in [Shape::WithKas3, Shape::Bilateral10, Shape::KasRing3] {
        for funding in [FundingMode::Revocable, FundingMode::Earmarked] {
            let trade = Trade::new(shape, true, funding);
            let funded = trade.fund();
            let n = trade.n();
            let t = trade.terms.terms().clone();
            for leg in 0..n {
                let depositor = t.legs[leg].depositor_key;
                let other = (0..n)
                    .find(|j| t.legs[*j].depositor_key != depositor)
                    .expect("another party");
                let is_token = t.legs[leg].asset.kind != LegKind::Kas;
                let mut cases = vec![
                    (RefundSignerV2::Depositor(leg), is_token),
                    (RefundSignerV2::Depositor(other), is_token),
                    (RefundSignerV2::Authority, is_token),
                ];
                if is_token {
                    cases.push((RefundSignerV2::Depositor(leg), false));
                }
                for (signer, with_token) in cases {
                    let s = trade.refund(&funded, leg, signer, with_token);
                    let label =
                        format!("{shape:?} {funding:?} leg {leg} {signer:?} token {with_token}");
                    s.assert_engine_accepts(&label);
                    let own = matches!(signer, RefundSignerV2::Depositor(j) if t.legs[j].depositor_key == depositor);
                    if funding == FundingMode::Earmarked && own {
                        assert!(s.node(EXPIRY).is_err(), "{label}: before expiry");
                        s.node(EXPIRY + 1)
                            .unwrap_or_else(|e| panic!("{label}: {e}"));
                    } else {
                        s.node(NOW).unwrap_or_else(|e| panic!("{label}: {e}"));
                    }
                }
            }
        }
    }
}

/// Every input of each shape's settle uses no more script units than its committed budget
/// allows (the budget rule of `impulse_core::v2::settle_budget`, measured here unbounded).
#[test]
fn committed_budgets_cover_the_measured_units() {
    let mut over = Vec::new();
    for shape in SHAPES {
        let trade = Trade::new(shape, true, FundingMode::Revocable);
        let funded = trade.fund();
        let s = trade.settle(&funded);
        for i in 0..s.tx.inputs.len() {
            let used = harness::measure(&s.tx, s.ipst.entries(), i).used;
            let allowed = s.tx.inputs[i].compute_commit.allowed_script_units();
            if used.0 > allowed.0 {
                over.push(format!("{shape:?} input {i}: {used:?} above {allowed:?}"));
            }
        }
    }
    // Every shape is checked, so a lowered rule names each shape it breaks (KasRing3 included).
    assert!(over.is_empty(), "{}", over.join("\n"));
}

/// Control: the engine runs above do refuse. A settle whose delivery to leg 0's recipient is
/// redirected fails at every vault input, since every vault checks every delivery.
#[test]
fn a_redirected_delivery_fails_every_vault() {
    let trade = Trade::new(Shape::WithKas3, false, FundingMode::Revocable);
    let funded = trade.fund();
    let s = trade.settle(&funded);
    let mut tx = s.tx.clone();
    tx.outputs[2].script_public_key = p2pk(&xonly(&trade.payer));
    for i in 0..trade.n() {
        let run = execute(&tx, s.ipst.entries(), i);
        assert!(
            run.result.is_err(),
            "vault input {i} accepted a redirected delivery"
        );
    }
}

/// I17: partial terms through the builders. Each leg is funded as its own KIP-20 genesis, then
/// tranches of 1, 2 and (the final) 1 lots of four, each spending the previous transaction's
/// continuations and remainders, every input accepted by the engine at its committed budget.
/// Each transaction reads back as what it is (`read_settle`) and the lineage keeps one covenant
/// ID per leg from the genesis to the final settle.
#[test]
fn partial_trades_fund_as_genesis_and_settle_in_tranches_in_the_engine() {
    for shape in [
        Shape::TwoKas,
        Shape::TwoKcc20,
        Shape::Ring3,
        Shape::KasRing3,
    ] {
        for with_authority in [true, false] {
            let trade = Trade::partial(shape, with_authority, 4, 1);
            let label = format!("{shape:?} authority {with_authority}");
            let mut funded = trade.fund();
            let genesis: Vec<_> = funded.iter().map(|(v, _)| v.entry.covenant_id).collect();
            let distinct: std::collections::HashSet<_> = genesis.iter().collect();
            assert!(genesis.iter().all(Option::is_some), "{label}: bound");
            assert_eq!(distinct.len(), genesis.len(), "{label}: one group per leg");
            let mut cumulative = 0;
            for (step, lots) in [1u64, 2, 1].into_iter().enumerate() {
                let s = if cumulative + lots == 4 {
                    trade.sign(
                        settle_tranche(
                            &trade.terms,
                            &trade.settle_legs(&funded),
                            lots,
                            &trade.fee(&format!("step-{step}")),
                            NOW,
                        )
                        .expect("final builds"),
                    )
                } else {
                    trade.tranche(&funded, lots, &format!("step-{step}"))
                };
                let label = format!("{label} step {step} lots {lots}");
                s.assert_engine_accepts(&label);
                s.node(EARLIEST + 1)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                let facts = read_settle(&trade.terms, &s.tx, s.ipst.entries()).unwrap();
                assert_eq!(facts.lots, lots, "{label}");
                assert_eq!(facts.tranche, cumulative + lots < 4, "{label}");
                for (i, l) in facts.legs.iter().enumerate() {
                    assert_eq!(l.covenant, genesis[i], "{label}: lineage of leg {i}");
                    assert_eq!(l.continuation.is_some(), facts.tranche, "{label}");
                }
                cumulative += lots;
                if facts.tranche {
                    funded = trade.continued(&s, &funded, lots);
                }
            }
            assert_eq!(cumulative, 4);
        }
    }
}

/// A tranche's budgets cover the measured units, and the vault outputs of a partial trade
/// meet the storage-mass cap the builder checked (the same transactions, run unbounded).
#[test]
fn tranche_budgets_cover_the_measured_units() {
    let mut over = Vec::new();
    for shape in [
        Shape::TwoKas,
        Shape::TwoKcc20,
        Shape::Ring3,
        Shape::KasRing3,
    ] {
        let trade = Trade::partial(shape, true, 4, 1);
        let funded = trade.fund();
        let s = trade.tranche(&funded, 1, "budget");
        for i in 0..s.tx.inputs.len() {
            let used = harness::measure(&s.tx, s.ipst.entries(), i).used;
            let allowed = s.tx.inputs[i].compute_commit.allowed_script_units();
            if used.0 > allowed.0 {
                over.push(format!("{shape:?} input {i}: {used:?} above {allowed:?}"));
            }
        }
    }
    assert!(over.is_empty(), "{}", over.join("\n"));
}

/// Controls: a tranche with the continuation redirected, short, or unbound is refused by the
/// vault of that leg in the engine (the builder never makes these; the contract refuses them).
#[test]
fn a_tampered_tranche_is_refused_by_the_engine() {
    let trade = Trade::partial(Shape::TwoKas, false, 4, 1);
    let funded = trade.fund();
    let s = trade.tranche(&funded, 1, "tamper");
    s.assert_engine_accepts("control");
    let n = trade.n();
    type Edit = fn(&mut Transaction, usize);
    let edits: [(&str, Edit); 3] = [
        ("continuation to a stranger", |tx, n| {
            tx.outputs[n + 1].script_public_key = p2pk(&[7; 32])
        }),
        ("KAS remainder short by one", |tx, n| {
            tx.outputs[n + 1].value -= 1
        }),
        ("continuation unbound", |tx, n| {
            tx.outputs[n + 1].covenant = None
        }),
    ];
    for (name, edit) in edits {
        let mut tx = s.tx.clone();
        edit(&mut tx, n);
        let refused = (0..n).any(|i| execute(&tx, s.ipst.entries(), i).result.is_err());
        assert!(refused, "{name}: accepted by every vault");
    }
}
