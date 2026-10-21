// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! I5 engine proof for the transaction builders (spec/TRANSACTIONS.md). Every transaction an
//! impulse-core builder makes, signed through the split flow (sighash from the IPST, signature
//! made here with a throwaway key, verified and assembled by impulse-core), is run input by
//! input through the real Kaspa script engine with the compute budget the builder committed:
//! the vault entries, the KCC-20 transfers and the P2PK fee inputs. Trades are chained: each
//! leg is funded by the fund builders, and settle and refund spend those very outputs.
//!
//! The boundary tests compose the two node rules impulse-core ports from rusty-kaspa a41a333
//! (finality of a lock time against the block DAA score, and the sequence lock) with the
//! script engine, one DAA score either side of earliest_daa and expiry_daa.
//!
//! The tests of the split flow that need a signature (slots, assembly, signed IPSTs, combine)
//! are here too, so impulse-core's own unit tests hold no key.
//!
//! Keys: throwaway keypairs from the harness, erased on drop (rule 1 exception, docs/ENGINEERING-RULES.md).

mod harness;
use harness::{
    assert_accepted, assert_locktime_refused, assert_refused, covering_budget, execute, measure,
    random_keypair, xonly, Compiled, Kcc20State as HarnessState, Owner, TestKey, Token,
    ASSET_TOKEN, CASH_TOKEN,
};

mod builders {
    use super::*;
    use impulse_core::locktime::{check_sequence_lock, check_tx_is_finalized, first_block_daa};
    use impulse_core::template::{LegIndex, Vault};
    use impulse_core::terms::{
        CreationContext, Destination, FundingMode, IdentifierType, Kcc20Owner, Kcc20Token, Leg,
        LegKind, Network, SettlementMode, Terms, ValidatedTerms,
    };
    use impulse_core::tx::{
        self, direct, fund_kas, fund_kcc20, refund, settle, DirectCash, DirectLegs, FeePayment,
        Ipst, Kcc20Deposit, Kcc20State, Kcc20Template, RefundEscrow, RefundSigner, SettleCash,
        SettleLegs, TokenUtxo, Utxo, KCC20_KEY_OWNED_BUDGET, KCC20_VAULT_OWNED_BUDGET,
        MIN_KAS_OUTPUT, MIN_KCC20_OUTPUT, P2PK_BUDGET, VAULT_BUDGET,
    };
    use kaspa_consensus_core::tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry,
    };
    use kaspa_consensus_core::Hash;
    use kaspa_txscript::opcodes::codes::{OpCheckSig, OpData32};
    use secp256k1::{Keypair, Message};

    const AMOUNT_A: u64 = 1_000;
    const KAS_CASH: u64 = 100_000_000;
    const KCC20_CASH: u64 = 250_000;
    const EXTERNAL_CASH: u64 = 5_000;
    const EARLIEST: u64 = 1_000_000;
    const EXPIRY: u64 = 2_000_000;
    /// The DAA score the builders are called at.
    const NOW: u64 = 1_500_000;
    /// DAA scores of the blocks that created the parties' wallet UTXOs and the vault UTXOs:
    /// before earliest_daa, so the boundary tests can place the settle block at earliest_daa.
    const WALLET_DAA: u64 = 800_000;
    const FUNDED_DAA: u64 = 900_000;
    const FEE: u64 = 5_000_000;
    /// The payer's and the depositors' KAS UTXOs.
    const WALLET: u64 = 100_000_000_000;
    /// The depositors hold more token than the leg needs, so funding makes token change.
    const TOKEN_HELD: u64 = 3 * AMOUNT_A;
    const CASH_HELD: u64 = 2 * KCC20_CASH;

    // =========================================================================================
    // Fixtures
    // =========================================================================================

    fn fixture_path(name: &str) -> std::path::PathBuf {
        harness::repo_path(&format!("crates/impulse-core/src/tx/testdata/{name}"))
    }

    fn compiled(token: Token) -> Compiled {
        token.compile(HarnessState::new(Owner::pubkey([0; 32]), 0))
    }

    fn template(token: Token) -> Kcc20Template {
        Kcc20Template::from_artifact(compiled(token).artifact).expect("KCC-20 template")
    }

    fn token_terms(t: &Kcc20Template, token: Token) -> Kcc20Token {
        Kcc20Token {
            covenant_id: token.cov.as_bytes(),
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

    fn pubkey_owner(key: &[u8; 32]) -> Kcc20Owner {
        Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: *key,
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Cash {
        Kas,
        Kcc20,
        External,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Mode {
        direct: bool,
        authority: bool,
        cash: Cash,
        funding: FundingMode,
    }

    fn vault_modes() -> Vec<Mode> {
        let mut modes = vec![];
        for authority in [true, false] {
            for cash in [Cash::Kas, Cash::Kcc20, Cash::External] {
                for funding in [FundingMode::Revocable, FundingMode::Earmarked] {
                    if cash == Cash::External && !authority {
                        continue; // no such terms (TERMS_EXTERNAL_WITHOUT_AUTHORITY)
                    }
                    modes.push(Mode {
                        direct: false,
                        authority,
                        cash,
                        funding,
                    });
                }
            }
        }
        modes
    }

    /// A trade between throwaway parties, with the harness's KCC-20 tokens.
    struct Trade {
        mode: Mode,
        seller: TestKey,
        buyer: TestKey,
        authority: TestKey,
        payer: TestKey,
        asset: Kcc20Template,
        cash: Kcc20Template,
        terms: ValidatedTerms,
    }

    impl Trade {
        fn new(mode: Mode) -> Self {
            Self::with(mode, template(ASSET_TOKEN), template(CASH_TOKEN))
        }

        /// A trade whose legs run the given KCC-20 templates.
        fn with(mode: Mode, asset: Kcc20Template, cash: Kcc20Template) -> Self {
            let (seller, buyer, authority, payer) = (
                random_keypair(),
                random_keypair(),
                random_keypair(),
                random_keypair(),
            );
            let (s, b) = (xonly(&seller), xonly(&buyer));
            let kcc20 = |key: &[u8; 32]| Destination::Kcc20(pubkey_owner(key));
            let (cash_kind, amount_b, proceeds, buyer_refund) = match mode.cash {
                Cash::Kas => (
                    LegKind::Kas,
                    KAS_CASH,
                    Destination::Kas(p2pk(&s)),
                    Destination::Kas(p2pk(&b)),
                ),
                Cash::Kcc20 => (
                    LegKind::Kcc20(token_terms(&cash, CASH_TOKEN)),
                    KCC20_CASH,
                    kcc20(&s),
                    kcc20(&b),
                ),
                Cash::External => (
                    LegKind::External,
                    EXTERNAL_CASH,
                    Destination::OffChain,
                    Destination::OffChain,
                ),
            };
            let terms = Terms {
                version: 1,
                network: Network::Mainnet,
                settlement_mode: if mode.direct {
                    SettlementMode::Direct
                } else {
                    SettlementMode::Vault
                },
                nonce: 77,
                seller_key: s,
                buyer_key: b,
                authority_key: mode.authority.then(|| xonly(&authority)),
                asset_leg: Leg {
                    kind: LegKind::Kcc20(token_terms(&asset, ASSET_TOKEN)),
                    amount: AMOUNT_A,
                },
                cash_leg: Leg {
                    kind: cash_kind,
                    amount: amount_b,
                },
                buyer_delivery: kcc20(&b),
                seller_proceeds: proceeds,
                seller_refund: kcc20(&s),
                buyer_refund,
                earliest_daa: Some(EARLIEST),
                expiry_daa: EXPIRY,
                funding_mode: mode.funding,
                trade_ref: [0x7E; 32],
            }
            .validate_structure()
            .expect("real terms");
            Self {
                mode,
                seller,
                buyer,
                authority,
                payer,
                asset,
                cash,
                terms,
            }
        }

        fn x(&self, key: &Keypair) -> [u8; 32] {
            xonly(key)
        }

        fn fee(&self, label: &str) -> FeePayment {
            let payer = self.x(&self.payer);
            FeePayment {
                inputs: vec![wallet_utxo(label, &payer)],
                fee: FEE,
                change: p2pk(&payer),
            }
        }

        /// Signs every pending slot with the key it names, through the IPST's own sighash.
        fn sign(&self, mut ipst: Ipst) -> Ipst {
            let keys = [&self.seller, &self.buyer, &self.authority, &self.payer];
            for input in ipst.pending() {
                let slot = &ipst.slots()[input];
                let key = keys
                    .iter()
                    .find(|k| xonly(k) == slot.signer().unwrap())
                    .expect("a party of the trade signs");
                let sig = sign65(key, &slot.sighash().unwrap());
                ipst.add_signature(input, &sig).expect("verified");
            }
            ipst
        }

        fn fundable(&self, leg: LegIndex) -> impulse_core::template::FundableVault {
            let ctx = CreationContext::new(Network::Mainnet, FUNDED_DAA - 1);
            Vault::instantiate_for_creation(&self.terms, leg, &ctx).expect("fundable")
        }

        /// Funds a leg with the builders; returns the signed funding transaction and its
        /// entries.
        fn fund(&self, leg: LegIndex) -> Option<Signed> {
            let t = self.terms.terms();
            let kind = match leg {
                LegIndex::Asset => t.asset_leg.kind,
                LegIndex::Cash => t.cash_leg.kind,
            };
            if kind == LegKind::External {
                return None;
            }
            let vault = self.fundable(leg);
            let ipst = match kind {
                LegKind::Kas => fund_kas(&self.terms, &vault, &self.fee("fund-kas"), NOW),
                LegKind::Kcc20(token) => {
                    let (tmpl, depositor, held, label) = match leg {
                        LegIndex::Asset => (&self.asset, &self.seller, TOKEN_HELD, "seller-token"),
                        LegIndex::Cash => (&self.cash, &self.buyer, CASH_HELD, "buyer-token"),
                    };
                    let deposit = Kcc20Deposit {
                        tokens: vec![own_token(label, tmpl, &token, &self.x(depositor), held)],
                        carrier: MIN_KCC20_OUTPUT,
                        authorizer: MIN_KAS_OUTPUT,
                    };
                    fund_kcc20(
                        &self.terms,
                        &vault,
                        tmpl,
                        &deposit,
                        &self.fee(&format!("fund-{label}")),
                        NOW,
                    )
                }
                LegKind::External => unreachable!("returned above"),
            }
            .expect("fund builds");
            Some(Signed::from(self.sign(ipst)))
        }
    }

    fn sign65(key: &Keypair, sighash: &[u8; 32]) -> [u8; 65] {
        let sig = key.sign_schnorr(Message::from_digest(*sighash));
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig.as_ref());
        out[64] = 0x01;
        out
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

    fn own_token(
        label: &str,
        tmpl: &Kcc20Template,
        token: &Kcc20Token,
        key: &[u8; 32],
        amount: u64,
    ) -> TokenUtxo {
        let state = Kcc20State::new(pubkey_owner(key), amount);
        TokenUtxo {
            utxo: Utxo {
                outpoint: outpoint(label),
                entry: UtxoEntry::new(
                    MIN_KCC20_OUTPUT,
                    tmpl.script_public_key(&state).unwrap(),
                    WALLET_DAA,
                    false,
                    Some(Hash::from_bytes(token.covenant_id)),
                ),
            },
            state,
        }
    }

    /// A signed transaction and the entries it spends.
    struct Signed {
        ipst: Ipst,
        tx: Transaction,
    }

    impl From<Ipst> for Signed {
        fn from(ipst: Ipst) -> Self {
            let tx = ipst.finalize().expect("every slot signed");
            Self { ipst, tx }
        }
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

        /// Every input accepted by the engine at its committed budget.
        fn assert_engine_accepts(&self, label: &str) {
            for i in 0..self.tx.inputs.len() {
                assert_accepted(
                    &execute(&self.tx, self.entries(), i),
                    &format!("{label}: input {i}"),
                );
            }
        }

        /// The node's view in a block of DAA score `daa`: finality of the lock time, the
        /// sequence lock, then every input's scripts.
        fn node(&self, daa: u64) -> Result<(), String> {
            node_accepts(&self.tx, self.entries(), daa)
        }
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

    /// The vault UTXOs a funded trade holds, taken from the funding transactions' outputs.
    struct Holdings {
        asset_fund: Signed,
        cash_fund: Option<Signed>,
    }

    impl Holdings {
        fn of(trade: &Trade) -> Self {
            Self {
                asset_fund: trade.fund(LegIndex::Asset).expect("asset leg"),
                cash_fund: trade.fund(LegIndex::Cash),
            }
        }

        fn settle_legs<'a>(&self, trade: &'a Trade) -> SettleLegs<'a> {
            let a = &self.asset_fund;
            SettleLegs {
                asset_authorizer: a.utxo(1, FUNDED_DAA),
                asset_escrow: a.utxo(0, FUNDED_DAA),
                asset_token: &trade.asset,
                cash: match (trade.mode.cash, &self.cash_fund) {
                    (Cash::Kas, Some(c)) => SettleCash::Kas {
                        vault: c.utxo(0, FUNDED_DAA),
                    },
                    (Cash::Kcc20, Some(c)) => SettleCash::Kcc20 {
                        authorizer: c.utxo(1, FUNDED_DAA),
                        escrow: c.utxo(0, FUNDED_DAA),
                        token: &trade.cash,
                    },
                    _ => SettleCash::External,
                },
            }
        }
    }

    fn settled(trade: &Trade, holdings: &Holdings) -> Signed {
        let ipst = settle(
            &trade.terms,
            &holdings.settle_legs(trade),
            &trade.fee("settle-fee"),
            NOW,
        )
        .unwrap_or_else(|e| panic!("{:?}: {e}", trade.mode));
        Signed::from(trade.sign(ipst))
    }

    fn refunded(
        trade: &Trade,
        holdings: &Holdings,
        leg: LegIndex,
        signer: RefundSigner,
        with_token: bool,
    ) -> Signed {
        let t = trade.terms.terms();
        let (fund, tmpl, amount) = match leg {
            LegIndex::Asset => (&holdings.asset_fund, &trade.asset, t.asset_leg.amount),
            LegIndex::Cash => (
                holdings.cash_fund.as_ref().expect("a cash vault"),
                &trade.cash,
                t.cash_leg.amount,
            ),
        };
        let kas_cash = leg == LegIndex::Cash && trade.mode.cash == Cash::Kas;
        let (vault_utxo, escrow) = if kas_cash {
            (fund.utxo(0, FUNDED_DAA), None)
        } else {
            (
                fund.utxo(1, FUNDED_DAA),
                with_token.then(|| RefundEscrow {
                    utxo: fund.utxo(0, FUNDED_DAA),
                    amount,
                    is_minter: false,
                    template: tmpl,
                }),
            )
        };
        let ipst = refund(
            &trade.terms,
            leg,
            signer,
            &vault_utxo,
            escrow.as_ref(),
            &trade.fee("refund-fee"),
        )
        .unwrap_or_else(|e| panic!("{:?} {leg:?} {signer:?}: {e}", trade.mode));
        Signed::from(trade.sign(ipst))
    }

    fn directed(trade: &Trade) -> Signed {
        let ipst = direct(
            &trade.terms,
            &direct_legs(trade),
            &trade.fee("direct-fee"),
            NOW,
        )
        .expect("direct");
        Signed::from(trade.sign(ipst))
    }

    /// The parties' own exact-amount UTXOs of a Direct trade.
    fn direct_legs(trade: &Trade) -> DirectLegs<'_> {
        let t = trade.terms.terms();
        let LegKind::Kcc20(asset) = t.asset_leg.kind else {
            unreachable!()
        };
        DirectLegs {
            asset: own_token(
                "direct-asset",
                &trade.asset,
                &asset,
                &trade.x(&trade.seller),
                AMOUNT_A,
            ),
            asset_token: &trade.asset,
            cash: match t.cash_leg.kind {
                LegKind::Kas => DirectCash::Kas(Utxo {
                    outpoint: outpoint("direct-kas"),
                    entry: UtxoEntry::new(
                        KAS_CASH,
                        p2pk(&trade.x(&trade.buyer)),
                        WALLET_DAA,
                        false,
                        None,
                    ),
                }),
                LegKind::Kcc20(cash) => DirectCash::Kcc20 {
                    token: own_token(
                        "direct-cash",
                        &trade.cash,
                        &cash,
                        &trade.x(&trade.buyer),
                        KCC20_CASH,
                    ),
                    template: &trade.cash,
                },
                LegKind::External => unreachable!(),
            },
        }
    }

    // =========================================================================================
    // Fixtures used by impulse-core's unit tests
    // =========================================================================================

    /// impulse-core's unit tests read KCC-20 artifacts from testdata/; they are the pinned
    /// kcc20.sil compiled in process by silverscript v1.0.0, field for field.
    #[test]
    fn kcc20_fixtures_are_the_pinned_compile() {
        for (name, token) in [
            ("kcc20-asset.json", ASSET_TOKEN),
            ("kcc20-cash.json", CASH_TOKEN),
        ] {
            let committed: silverscript_abi::SilAbiArtifact =
                serde_json::from_str(&std::fs::read_to_string(fixture_path(name)).unwrap())
                    .unwrap();
            assert_eq!(committed, compiled(token).artifact, "{name}");
            let t = template(token);
            let r = token.template();
            assert_eq!(t.template_hash(), r.hash);
            assert_eq!(
                (t.prefix_len() as i64, t.suffix_len() as i64),
                (r.prefix_len, r.suffix_len)
            );
        }
    }

    /// kcc20.sil with `lines` more statements, each a 32-byte literal, in the branch for owner
    /// types other than public key, script hash and covenant ID, which no Impulse token takes: a
    /// longer template whose `transfer` does the same work.
    fn padded_kcc20_source(lines: usize) -> String {
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
        source.replacen(
            tail,
            &format!("        }} else {{\n{padding}            require(false);\n        }}"),
            1,
        )
    }

    /// A token of `token`'s covenant and covenant limits, compiled from the padded source.
    fn padded_template(token: Token, lines: usize) -> Kcc20Template {
        let compiled = harness::Compiled::new(
            &padded_kcc20_source(lines),
            &[
                silverscript_abi::ArtifactValue::Bytes(vec![0; 32]),
                silverscript_abi::ArtifactValue::Int(0),
                silverscript_abi::ArtifactValue::Byte(0),
                silverscript_abi::ArtifactValue::Bool(false),
                silverscript_abi::ArtifactValue::Int(token.max_cov_ins),
                silverscript_abi::ArtifactValue::Int(token.max_cov_outs),
            ],
        );
        Kcc20Template::from_artifact(compiled.artifact).expect("padded KCC-20 template")
    }

    /// impulse-core encodes KCC-20 states as silverscript does: a token script it builds is the
    /// compiler's for the same state.
    #[test]
    fn kcc20_scripts_match_the_compiler() {
        let t = template(ASSET_TOKEN);
        let key = [0x42; 32];
        for (owner, amount, minter) in [
            (Owner::pubkey(key), 1, false),
            (Owner::script_hash(key), i64::MAX, false),
            (Owner::pubkey(key), 77, true),
        ] {
            let ours = Kcc20State {
                owner: Kcc20Owner {
                    identifier_type: if owner.id_type == 0 {
                        IdentifierType::PubKey
                    } else {
                        IdentifierType::ScriptHash
                    },
                    identifier: owner.id,
                },
                amount: amount as u64,
                is_minter: minter,
            };
            let theirs = ASSET_TOKEN.compile(HarnessState {
                owner: owner.id,
                id_type: owner.id_type,
                amount,
                is_minter: minter,
            });
            assert_eq!(t.redeem_script(&ours).unwrap(), theirs.bytecode());
        }
    }

    // =========================================================================================
    // Every builder in the engine
    // =========================================================================================

    #[test]
    fn fund_builders_validate_in_the_engine() {
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            h.asset_fund
                .assert_engine_accepts(&format!("{mode:?} fund asset"));
            assert_eq!(
                h.asset_fund.tx.outputs.len(),
                4,
                "escrow, authorizer, token change, change"
            );
            if let Some(c) = &h.cash_fund {
                c.assert_engine_accepts(&format!("{mode:?} fund cash"));
            }
        }
    }

    #[test]
    fn settle_validates_in_the_engine_in_every_mode() {
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            let s = settled(&trade, &h);
            s.assert_engine_accepts(&format!("{mode:?} settle"));
            assert_eq!(s.node(EARLIEST + 1), Ok(()), "{mode:?}");
        }
    }

    #[test]
    fn refund_validates_in_the_engine_for_every_leg_and_signer() {
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            let legs: &[LegIndex] = if mode.cash == Cash::External {
                &[LegIndex::Asset]
            } else {
                &[LegIndex::Asset, LegIndex::Cash]
            };
            for &leg in legs {
                let mut signers = vec![RefundSigner::Depositor, RefundSigner::Counterparty];
                if mode.authority {
                    signers.push(RefundSigner::Authority);
                }
                for signer in signers {
                    let label = format!("{mode:?} refund {leg:?} by {signer:?}");
                    let r = refunded(&trade, &h, leg, signer, true);
                    r.assert_engine_accepts(&label);
                    // Earmarked depositor refunds wait for expiry; the rest go at once.
                    let opens = first_block_daa(r.tx.lock_time).unwrap_or(NOW);
                    assert_eq!(r.node(opens), Ok(()), "{label}");
                }
                let kas_cash = leg == LegIndex::Cash && mode.cash == Cash::Kas;
                if !kas_cash {
                    // The depositor alone may send the authorizer home without its token.
                    refunded(&trade, &h, leg, RefundSigner::Depositor, false)
                        .assert_engine_accepts(&format!("{mode:?} {leg:?} authorizer alone"));
                }
            }
        }
    }

    #[test]
    fn direct_validates_in_the_engine() {
        for cash in [Cash::Kas, Cash::Kcc20] {
            let trade = Trade::new(Mode {
                direct: true,
                authority: false,
                cash,
                funding: FundingMode::Revocable,
            });
            let d = directed(&trade);
            d.assert_engine_accepts(&format!("direct {cash:?}"));
            // No vault enforces earliest_daa in Direct; the lock time makes the node do it.
            assert!(d.node(EARLIEST).is_err());
            assert_eq!(d.node(EARLIEST + 1), Ok(()));
        }
    }

    /// The engine judges the builder's outputs, not the builder: the same settle with the
    /// buyer's delivery one token short, or the seller's authorizer KAS one sompi short, is
    /// refused by the vault. Both are re-signed, so only the outputs differ.
    #[test]
    fn the_vault_refuses_what_the_builder_never_makes() {
        let trade = Trade::new(Mode {
            direct: false,
            authority: true,
            cash: Cash::Kcc20,
            funding: FundingMode::Earmarked,
        });
        let h = Holdings::of(&trade);
        let s = settled(&trade, &h);
        s.assert_engine_accepts("control");
        let t = trade.terms.terms();
        let Destination::Kcc20(buyer) = t.buyer_delivery else {
            unreachable!()
        };
        let mut short_delivery = s.tx.clone();
        short_delivery.outputs[0].script_public_key = trade
            .asset
            .script_public_key(&Kcc20State::new(buyer, AMOUNT_A - 1))
            .unwrap();
        let mut short_return = s.tx.clone();
        short_return.outputs[2].value -= 1;
        short_return.outputs[4].value += 1;
        for (label, faulty) in [
            ("delivery one short", short_delivery),
            ("authorizer return one short", short_return),
        ] {
            let resigned = resign(&trade, &s.ipst, faulty);
            assert_refused(
                &execute(&resigned, s.entries(), 0),
                &format!("{label}: the asset vault refuses"),
            );
        }
    }

    /// Funding from two token inputs runs the KCC-20 delegate entry (input 1) beside the leader;
    /// funding from exactly the leg amount makes no token change.
    #[test]
    fn fund_from_several_tokens_or_the_exact_amount_validates_in_the_engine() {
        let trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let two = Signed::from(trade.sign(fund_from(&trade, &[600, 700]).unwrap()));
        assert_eq!(
            two.tx.outputs.len(),
            4,
            "escrow, authorizer, token change, change"
        );
        two.assert_engine_accepts("two token inputs");
        let exact = Signed::from(trade.sign(fund_from(&trade, &[AMOUNT_A]).unwrap()));
        assert_eq!(exact.tx.outputs.len(), 3, "escrow, authorizer, change");
        exact.assert_engine_accepts("exactly the leg amount");
    }

    /// The fixture token's template allows two covenant inputs (`maxCovIns`). Its ABI artifact
    /// does not say so, so the builder cannot refuse a third token input; the token's own
    /// script does, at the leader. Pinned here so the limit is a known one
    /// (spec/TRANSACTIONS.md, "fund_kcc20").
    #[test]
    fn a_transfer_beyond_the_tokens_max_cov_ins_is_refused_by_the_token() {
        let trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let three = Signed::from(trade.sign(fund_from(&trade, &[600, 300, 100]).unwrap()));
        assert_refused(
            &execute(&three.tx, three.entries(), 0),
            "the leader of three token inputs",
        );
        for delegate in [1, 2] {
            assert_accepted(
                &execute(&three.tx, three.entries(), delegate),
                &format!("delegate {delegate}"),
            );
        }
    }

    /// A token owned by the vault's script hash that does not hold the leg amount, or is a
    /// minter, goes home with the depositor's refund; a minter escrow of exactly the leg amount
    /// goes home with anyone's refund ([R14] checks the amount only). The token keeps its
    /// amount and minter flag.
    #[test]
    fn refunds_of_stray_tokens_validate_in_the_engine() {
        let trade = Trade::new(mode(true, Cash::Kcc20, FundingMode::Revocable));
        let h = Holdings::of(&trade);
        let asset_vault = Vault::instantiate_existing(&trade.terms, LegIndex::Asset).unwrap();
        let LegKind::Kcc20(token) = trade.terms.terms().asset_leg.kind else {
            unreachable!()
        };
        let owner = Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: asset_vault.script_hash(),
        };
        let cases = [
            (7, false, RefundSigner::Depositor),
            (7, true, RefundSigner::Depositor),
            (AMOUNT_A, true, RefundSigner::Depositor),
            (AMOUNT_A, true, RefundSigner::Counterparty),
            (AMOUNT_A, true, RefundSigner::Authority),
        ];
        for (amount, is_minter, signer) in cases {
            let label = format!("amount {amount}, minter {is_minter}, by {signer:?}");
            let state = Kcc20State {
                owner,
                amount,
                is_minter,
            };
            let stray = Utxo {
                outpoint: outpoint(&format!("stray-{amount}-{is_minter}")),
                entry: UtxoEntry::new(
                    MIN_KCC20_OUTPUT,
                    trade.asset.script_public_key(&state).unwrap(),
                    FUNDED_DAA,
                    false,
                    Some(Hash::from_bytes(token.covenant_id)),
                ),
            };
            let ipst = refund(
                &trade.terms,
                LegIndex::Asset,
                signer,
                &h.asset_fund.utxo(1, FUNDED_DAA),
                Some(&RefundEscrow {
                    utxo: stray,
                    amount,
                    is_minter,
                    template: &trade.asset,
                }),
                &trade.fee("refund-fee"),
            )
            .unwrap_or_else(|e| panic!("{label}: {e}"));
            let home = Kcc20State {
                owner: pubkey_owner(&trade.x(&trade.seller)),
                amount,
                is_minter,
            };
            assert_eq!(
                ipst.transaction().outputs[1].script_public_key,
                trade.asset.script_public_key(&home).unwrap()
            );
            Signed::from(trade.sign(ipst)).assert_engine_accepts(&label);
        }
    }

    /// Terms without earliest_daa: the settle has no lock time and enters any block.
    #[test]
    fn settle_without_earliest_validates_in_the_engine() {
        let mut trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let mut t = trade.terms.terms().clone();
        t.earliest_daa = None;
        trade.terms = t.validate_structure().unwrap();
        let s = settled(&trade, &Holdings::of(&trade));
        assert_eq!(s.tx.lock_time, 0);
        s.assert_engine_accepts("no earliest_daa");
        assert_eq!(s.node(FUNDED_DAA + 1), Ok(()));
    }

    /// An authorizer or a token carrier below its minimum is topped up from the fee inputs;
    /// the vault accepts the larger output because it checks "at least" ([S9], [D2], [R13]).
    #[test]
    fn topped_up_outputs_validate_in_the_engine() {
        let trade = Trade::new(Mode {
            direct: false,
            authority: false,
            cash: Cash::Kcc20,
            funding: FundingMode::Earmarked,
        });
        let h = Holdings::of(&trade);
        let mut legs = h.settle_legs(&trade);
        legs.asset_authorizer.entry.amount = 1_000;
        if let SettleCash::Kcc20 { escrow, .. } = &mut legs.cash {
            escrow.entry.amount = 1_000;
        }
        let ipst = settle(&trade.terms, &legs, &trade.fee("settle-fee"), NOW).unwrap();
        assert_eq!(ipst.transaction().outputs[1].value, MIN_KCC20_OUTPUT);
        assert_eq!(ipst.transaction().outputs[2].value, MIN_KAS_OUTPUT);
        Signed::from(trade.sign(ipst)).assert_engine_accepts("topped-up settle");
        // A refund whose token carrier is thin: output 1 topped up, output 0 exact ([R5]).
        let mut thin = h.asset_fund.utxo(0, FUNDED_DAA);
        thin.entry.amount = 1_000;
        let ipst = refund(
            &trade.terms,
            LegIndex::Asset,
            RefundSigner::Counterparty,
            &h.asset_fund.utxo(1, FUNDED_DAA),
            Some(&RefundEscrow {
                utxo: thin,
                amount: AMOUNT_A,
                is_minter: false,
                template: &trade.asset,
            }),
            &trade.fee("refund-fee"),
        )
        .unwrap();
        assert_eq!(ipst.transaction().outputs[1].value, MIN_KCC20_OUTPUT);
        Signed::from(trade.sign(ipst)).assert_engine_accepts("topped-up refund");
    }

    /// Re-signs a changed transaction with the slots of `ipst` (the parts around each
    /// signature do not depend on the outputs).
    fn resign(trade: &Trade, ipst: &Ipst, mut tx: Transaction) -> Transaction {
        let keys = [&trade.seller, &trade.buyer, &trade.authority, &trade.payer];
        for input in tx.inputs.iter_mut() {
            input.signature_script.clear();
        }
        let unsigned = tx.clone();
        for (i, slot) in ipst.slots().iter().enumerate() {
            let mut script = slot.script_before().to_vec();
            if let Some(signer) = slot.signer() {
                let key = keys.iter().find(|k| xonly(k) == signer).unwrap();
                let hash = tx::sighash(&unsigned, ipst.entries(), i).unwrap();
                script.push(0x41);
                script.extend_from_slice(&sign65(key, &hash));
                script.extend_from_slice(slot.script_after());
            }
            tx.inputs[i].signature_script = script;
        }
        tx.finalize();
        tx
    }

    // =========================================================================================
    // The split flow and signed IPSTs. These need signatures, so they run here with the
    // harness's throwaway keys and not in impulse-core's unit tests: no private key enters
    // impulse-core (rule 1, docs/ENGINEERING-RULES.md).
    // =========================================================================================

    impl Trade {
        /// The throwaway key behind an x-only public key of this trade.
        fn key_of(&self, xonly_key: &[u8; 32]) -> &Keypair {
            [&self.seller, &self.buyer, &self.authority, &self.payer]
                .into_iter()
                .map(|k| &**k)
                .find(|k| xonly(k) == *xonly_key)
                .expect("a party of the trade")
        }

        /// The signature for slot `input` of `ipst`, by the key the slot names.
        fn signature(&self, ipst: &Ipst, input: usize) -> [u8; 65] {
            let slot = &ipst.slots()[input];
            sign65(
                self.key_of(&slot.signer().unwrap()),
                &slot.sighash().unwrap(),
            )
        }

        /// The unsigned settle of a funded trade.
        fn settle_ipst(&self, h: &Holdings) -> Ipst {
            settle(
                &self.terms,
                &h.settle_legs(self),
                &self.fee("settle-fee"),
                NOW,
            )
            .expect("settle builds")
        }
    }

    fn mode(authority: bool, cash: Cash, funding: FundingMode) -> Mode {
        Mode {
            direct: false,
            authority,
            cash,
            funding,
        }
    }

    fn direct_mode(cash: Cash) -> Mode {
        Mode {
            direct: true,
            authority: false,
            cash,
            funding: FundingMode::Revocable,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, tx::TxError>) -> &'static str {
        r.expect_err("expected a refusal").code()
    }

    /// Every slot of every settle and Direct transaction: the signature lands between the
    /// slot's parts and verifies against the slot's signer; a slot without a signer is the
    /// whole signature script; the sighash and the transaction ID do not depend on signature
    /// scripts.
    #[test]
    fn signatures_land_in_their_slots_and_verify() {
        let mut all = vec![];
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            all.push((format!("{mode:?}"), settled(&trade, &h)));
        }
        for cash in [Cash::Kas, Cash::Kcc20] {
            all.push((
                format!("direct {cash:?}"),
                directed(&Trade::new(direct_mode(cash))),
            ));
        }
        for (label, s) in all {
            let unsigned = s.ipst.transaction();
            assert_eq!(s.tx.id(), unsigned.id(), "{label}: id excludes signatures");
            for (i, slot) in s.ipst.slots().iter().enumerate() {
                let script = &s.tx.inputs[i].signature_script;
                let hash = tx::sighash(&s.tx, s.entries(), i).unwrap();
                match slot.signer() {
                    Some(key) => {
                        assert_eq!(slot.sighash(), Some(hash), "{label} {i}");
                        let b = slot.script_before().len();
                        assert_eq!(&script[..b], slot.script_before());
                        assert_eq!(script[b], 0x41, "OpData65");
                        assert_eq!(&script[b + 66..], slot.script_after());
                        tx::verify_schnorr_sig65(&key, &hash, &script[b + 1..b + 66]).unwrap();
                    }
                    None => {
                        assert_eq!(slot.sighash(), None);
                        assert_eq!(script, slot.script_before());
                    }
                }
            }
        }
    }

    #[test]
    fn assemble_from_signature_bytes() {
        let trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let ipst = trade.settle_ipst(&Holdings::of(&trade));
        let sigs: Vec<(usize, [u8; 65])> = ipst
            .pending()
            .into_iter()
            .map(|i| (i, trade.signature(&ipst, i)))
            .collect();
        assert_eq!(sigs.len(), 3, "authority twice, payer once");
        let refs: Vec<(usize, &[u8])> = sigs.iter().map(|(i, s)| (*i, s.as_slice())).collect();
        let mut one_by_one = ipst.clone();
        for (i, sig) in &refs {
            one_by_one.add_signature(*i, sig).unwrap();
        }
        assert_eq!(
            ipst.assemble(&refs).unwrap(),
            one_by_one.finalize().unwrap()
        );
        // One missing: TX_SIGNATURE_SLOT. One not verifying: TX_SIGNATURE.
        assert_eq!(code(ipst.assemble(&refs[1..])), "TX_SIGNATURE_SLOT");
        let swapped = [(refs[0].0, refs[2].1), refs[1], refs[2]];
        assert_eq!(code(ipst.assemble(&swapped)), "TX_SIGNATURE");
    }

    #[test]
    fn verify_schnorr_sig65_refuses_bad_signatures() {
        let (key, other) = (random_keypair(), random_keypair());
        let hash = [7u8; 32];
        let good = sign65(&key, &hash);
        assert_eq!(tx::verify_schnorr_sig65(&xonly(&key), &hash, &good), Ok(()));
        let mut wrong_type = good;
        wrong_type[64] = 0x02;
        let mut flipped = good;
        flipped[10] ^= 1;
        let longer = [good.as_slice(), &[1]].concat();
        for (label, pk, sig) in [
            ("64 bytes", xonly(&key), &good[..64]),
            ("66 bytes", xonly(&key), &longer[..]),
            ("sighash type", xonly(&key), &wrong_type[..]),
            ("flipped bit", xonly(&key), &flipped[..]),
            ("other key", xonly(&other), &good[..]),
            ("invalid key", [0u8; 32], &good[..]),
        ] {
            assert_eq!(
                code(tx::verify_schnorr_sig65(&pk, &hash, sig)),
                "TX_SIGNATURE",
                "{label}"
            );
        }
        assert_eq!(
            code(tx::verify_schnorr_sig65(&xonly(&key), &[8u8; 32], &good)),
            "TX_SIGNATURE"
        );
    }

    #[test]
    fn add_signature_checks_the_slot() {
        let trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let ipst = trade.settle_ipst(&Holdings::of(&trade));
        let hash0 = ipst.slots()[0].sighash().unwrap();
        let mut control = ipst.clone();
        assert_eq!(
            control.add_signature(0, &sign65(&trade.authority, &hash0)),
            Ok(())
        );
        // The seller's signature for the authority's slot.
        let mut wrong = ipst.clone();
        assert_eq!(
            code(wrong.add_signature(0, &sign65(&trade.seller, &hash0))),
            "TX_SIGNATURE"
        );
        // The authority's signature over input 1's sighash, offered for input 0.
        let hash1 = ipst.slots()[1].sighash().unwrap();
        assert_ne!(hash0, hash1);
        assert_eq!(
            code(wrong.add_signature(0, &sign65(&trade.authority, &hash1))),
            "TX_SIGNATURE"
        );
        // Input 2 is the escrowed token: no signature. Input 9 does not exist.
        let any = sign65(&trade.authority, &hash0);
        assert_eq!(code(wrong.add_signature(2, &any)), "TX_SIGNATURE_SLOT");
        assert_eq!(code(wrong.add_signature(9, &any)), "TX_SIGNATURE_SLOT");
        assert_eq!(code(ipst.finalize()), "TX_SIGNATURE_SLOT");
    }

    /// A signed IPST of every builder reads back as itself and finalizes to the same
    /// transaction.
    #[test]
    fn signed_ipsts_round_trip() {
        let trade = Trade::new(mode(true, Cash::Kcc20, FundingMode::Earmarked));
        let h = Holdings::of(&trade);
        let kas = Trade::new(mode(false, Cash::Kas, FundingMode::Revocable));
        let kas_h = Holdings::of(&kas);
        let all = [
            h.asset_fund.ipst.clone(),
            kas_h.cash_fund.as_ref().unwrap().ipst.clone(),
            settled(&trade, &h).ipst,
            refunded(&trade, &h, LegIndex::Cash, RefundSigner::Authority, true).ipst,
            refunded(&kas, &kas_h, LegIndex::Cash, RefundSigner::Depositor, false).ipst,
            directed(&Trade::new(direct_mode(Cash::Kcc20))).ipst,
        ];
        let (asset, cash) = (template(ASSET_TOKEN), template(CASH_TOKEN));
        for signed in all {
            assert!(signed.is_complete());
            let text = signed.to_json();
            let read = Ipst::from_json(&text).unwrap();
            assert_eq!(read, signed);
            assert_eq!(read.to_json(), text);
            assert_eq!(read.finalize(), signed.finalize());
            // Signatures aside, it is the builders' transaction for its terms.
            assert!(read.verify_against_terms(&asset, Some(&cash), NOW).is_ok());
        }
    }

    #[test]
    fn the_ipst_reader_refuses_a_signature_that_does_not_verify() {
        let trade = Trade::new(mode(true, Cash::Kas, FundingMode::Earmarked));
        let s = settled(&trade, &Holdings::of(&trade));
        let text = s.ipst.to_json();
        assert!(Ipst::from_json(&text).is_ok());
        let sig0 = hex(&s.ipst.slots()[0].signature().unwrap());
        let wrong = hex(&sign65(
            &trade.seller,
            &s.ipst.slots()[0].sighash().unwrap(),
        ));
        assert_eq!(
            code(Ipst::from_json(&text.replacen(&sig0, &wrong, 1))),
            "TX_SIGNATURE"
        );
    }

    #[test]
    fn ipst_combine() {
        let trade = Trade::new(direct_mode(Cash::Kas));
        let ipst = direct(
            &trade.terms,
            &direct_legs(&trade),
            &trade.fee("direct-fee"),
            NOW,
        )
        .unwrap();
        // The seller signs one copy, the buyer and the payer another.
        let seller_key = trade.x(&trade.seller);
        let (mut seller, mut rest) = (ipst.clone(), ipst.clone());
        for i in ipst.pending() {
            let sig = trade.signature(&ipst, i);
            if ipst.slots()[i].signer() == Some(seller_key) {
                seller.add_signature(i, &sig).unwrap();
            } else {
                rest.add_signature(i, &sig).unwrap();
            }
        }
        assert!(!seller.is_complete() && !rest.is_complete());
        let both = seller.combine(&rest).unwrap();
        assert!(both.is_complete());
        assert_eq!(rest.combine(&seller).unwrap().finalize(), both.finalize());
        // Same slot, two different signatures (BIP-340 signing draws fresh auxiliary
        // randomness, so a second signature over the same sighash differs).
        let mut again = ipst.clone();
        let sig = trade.signature(&ipst, 0);
        assert_ne!(Some(sig), seller.slots()[0].signature());
        again.add_signature(0, &sig).unwrap();
        assert_eq!(code(seller.combine(&again)), "IPST_CONFLICT");
        // Another transaction.
        let other = direct(
            &trade.terms,
            &direct_legs(&trade),
            &FeePayment {
                fee: FEE + 1,
                ..trade.fee("direct-fee")
            },
            NOW,
        )
        .unwrap();
        assert_eq!(code(ipst.combine(&other)), "IPST_CONFLICT");
    }

    /// No signature covers an input's compute budget, and neither does the transaction ID: a
    /// signed IPST whose budgets were raised afterwards reads, and its signatures verify.
    /// finalize re-checks the masses and the relay fee of the assembled transaction and refuses
    /// it once either fails.
    #[test]
    fn finalize_refuses_budgets_raised_after_signing() {
        let trade = Trade::new(mode(true, Cash::Kcc20, FundingMode::Earmarked));
        let s = settled(&trade, &Holdings::of(&trade));
        let text = s.ipst.to_json();
        assert!(Ipst::from_json(&text).unwrap().finalize().is_ok());
        let with_budget = |input: usize, budget: u16| -> Ipst {
            let mut d: serde_json::Value = serde_json::from_str(&text).unwrap();
            d["inputs"][input]["compute_budget"] = budget.into();
            Ipst::from_json(&d.to_string()).expect("a budget is not signed, so it still reads")
        };
        // A small change: same transaction ID, and finalize cannot tell; the terms check can.
        let check = |ipst: &Ipst| ipst.verify_against_terms(&trade.asset, Some(&trade.cash), NOW);
        assert!(check(&s.ipst).is_ok());
        let small = with_budget(0, VAULT_BUDGET + 10);
        assert_eq!(small.transaction().id(), s.tx.id());
        assert!(small.finalize().is_ok());
        assert_eq!(code(check(&small)), "IPST_TERMS_MISMATCH");
        // A lowered budget, which the node would refuse: only the terms check sees it.
        let lowered = with_budget(0, 1);
        assert!(lowered.finalize().is_ok());
        assert_eq!(code(check(&lowered)), "IPST_TERMS_MISMATCH");
        // Past the compute cap.
        assert_eq!(code(with_budget(0, 1_000).finalize()), "TX_MASS");
        // Within the cap, but the fee no longer covers the relay fee on the larger mass.
        let fee_input = s.tx.inputs.len() - 1;
        assert_eq!(
            code(with_budget(fee_input, 400).finalize()),
            "TX_FEE_TOO_LOW"
        );
    }

    // =========================================================================================
    // The four boundary tests: one DAA score either side of earliest_daa and expiry_daa, by the
    // script rule (OpCheckLockTimeVerify against the lock time) and by the node rule (the lock
    // time against the block DAA score)
    // =========================================================================================

    fn settle_trade() -> (Trade, Holdings) {
        let trade = Trade::new(Mode {
            direct: false,
            authority: true,
            cash: Cash::Kcc20,
            funding: FundingMode::Earmarked,
        });
        let h = Holdings::of(&trade);
        (trade, h)
    }

    #[test]
    fn boundary_settle_before_earliest_is_refused() {
        let (trade, h) = settle_trade();
        let s = settled(&trade, &h);
        assert_eq!(s.tx.lock_time, EARLIEST);
        // Script rule: a lock time one below earliest_daa fails [S3] in both vaults.
        let mut early = s.tx.clone();
        early.lock_time = EARLIEST - 1;
        let early = resign(&trade, &s.ipst, early);
        for vault_input in [0, 1] {
            assert_locktime_refused(
                &execute(&early, s.entries(), vault_input),
                &format!("lock time earliest - 1, input {vault_input}"),
            );
        }
        // Node rule: the builder's transaction (lock time earliest_daa) is not final in a block
        // at earliest_daa.
        let refused = s.node(EARLIEST).unwrap_err();
        assert!(refused.starts_with("finality"), "{refused}");
    }

    #[test]
    fn boundary_settle_from_earliest_is_accepted() {
        let (trade, h) = settle_trade();
        let s = settled(&trade, &h);
        // Script rule: lock time exactly earliest_daa passes [S3] (the builder's choice).
        s.assert_engine_accepts("lock time earliest");
        // Node rule: final from the next block, earliest_daa + 1, the effective earliest settle.
        assert_eq!(first_block_daa(s.tx.lock_time), Some(EARLIEST + 1));
        assert_eq!(s.node(EARLIEST + 1), Ok(()));
    }

    #[test]
    fn boundary_refund_before_expiry_is_refused() {
        let (trade, h) = settle_trade();
        let r = refunded(&trade, &h, LegIndex::Asset, RefundSigner::Depositor, true);
        assert_eq!(r.tx.lock_time, EXPIRY);
        // Script rule: the earmarked depositor's refund with lock time one below expiry_daa
        // fails [R3].
        let mut early = r.tx.clone();
        early.lock_time = EXPIRY - 1;
        let early = resign(&trade, &r.ipst, early);
        assert_locktime_refused(&execute(&early, r.entries(), 0), "lock time expiry - 1");
        // Node rule: not final in a block at expiry_daa.
        let refused = r.node(EXPIRY).unwrap_err();
        assert!(refused.starts_with("finality"), "{refused}");
        // The counterparty's refund needs no lock time and goes at once.
        let c = refunded(
            &trade,
            &h,
            LegIndex::Asset,
            RefundSigner::Counterparty,
            true,
        );
        assert_eq!(c.tx.lock_time, 0);
        assert_eq!(c.node(NOW), Ok(()));
    }

    #[test]
    fn boundary_refund_from_expiry_is_accepted() {
        let (trade, h) = settle_trade();
        let r = refunded(&trade, &h, LegIndex::Asset, RefundSigner::Depositor, true);
        // Script rule: lock time exactly expiry_daa passes [R3].
        r.assert_engine_accepts("lock time expiry");
        // Node rule: final from expiry_daa + 1, the effective opening of the earmarked refund.
        assert_eq!(first_block_daa(r.tx.lock_time), Some(EXPIRY + 1));
        assert_eq!(r.node(EXPIRY + 1), Ok(()));
    }

    /// The node-rule half of the boundary tests runs impulse-core's ports of rusty-kaspa's
    /// `check_tx_is_finalized` (with `get_lock_time_type`) and `check_sequence_lock`. This keeps
    /// the ports tied to the source at the pinned revision: it finds the pinned checkout through
    /// `cargo metadata`, and every load-bearing statement of the upstream functions must appear,
    /// whitespace and comments aside, in the upstream text and in the port.
    #[test]
    fn node_rule_ports_follow_the_pinned_source() {
        fn normalized(text: &str) -> String {
            text.lines()
                .map(|l| l.split("//").next().unwrap())
                .collect::<String>()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        }
        /// The text of `fn name` up to its closing brace.
        fn function(source: &str, name: &str) -> String {
            let start = source
                .find(&format!("fn {name}("))
                .unwrap_or_else(|| panic!("fn {name} not found"));
            let open = start + source[start..].find('{').unwrap();
            let mut depth = 0;
            for (i, c) in source[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return source[start..open + i + 1].to_string();
                        }
                    }
                    _ => {}
                }
            }
            panic!("fn {name} does not close");
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = std::process::Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--locked", "--offline"])
            .current_dir(harness::repo_path(""))
            .output()
            .expect("cargo metadata");
        assert!(out.status.success(), "cargo metadata failed");
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let core = meta["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "kaspa-consensus-core")
            .expect("kaspa-consensus-core in the build");
        let source = core["source"].as_str().unwrap();
        assert!(
            source.ends_with("#a41a333b08848f41bf737b72592e463a6011b8ac"),
            "{source}"
        );
        // .../consensus/core/Cargo.toml -> .../consensus/src/processes/transaction_validator
        let validator = std::path::Path::new(core["manifest_path"].as_str().unwrap())
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .join("src/processes/transaction_validator");
        let read = |file: &str| std::fs::read_to_string(validator.join(file)).unwrap();
        let header = read("tx_validation_in_header_context.rs");
        let utxo = read("tx_validation_in_utxo_context.rs");
        let port =
            std::fs::read_to_string(harness::repo_path("crates/impulse-core/src/locktime.rs"))
                .unwrap();
        let finalized = [
            "letblock_time_or_daa_score=match",
            "=>returnOk(()),",
            "iftx.lock_time<block_time_or_daa_score{returnOk(());}",
            "for(i,input)intx.inputs.iter().enumerate(){ifinput.sequence!=u64::MAX{",
        ];
        let lock_time_type = ["0=>", "tift<LOCK_TIME_THRESHOLD=>"];
        let sequence_lock = [
            "letpov_daa_score:i64=pov_daa_scoreasi64;",
            "input.sequence&SEQUENCE_LOCK_TIME_DISABLED",
            "SEQUENCE_LOCK_TIME_DISABLED",
            "letrelative_lock=(input.sequence&SEQUENCE_LOCK_TIME_MASK)asi64;",
            "letlock_daa_score=entry.block_daa_scoreasi64+relative_lock-1;",
            "lock_daa_score>=pov_daa_score",
        ];
        let port_finalized = normalized(&function(&port, "check_tx_is_finalized"));
        let port_sequence = normalized(&function(&port, "check_sequence_lock"));
        for (label, upstream, port, statements) in [
            (
                "check_tx_is_finalized",
                normalized(&function(&header, "check_tx_is_finalized")),
                &port_finalized,
                &finalized[..],
            ),
            (
                "get_lock_time_type",
                normalized(&function(&header, "get_lock_time_type")),
                &port_finalized,
                &lock_time_type[..],
            ),
            (
                "check_sequence_lock",
                normalized(&function(&utxo, "check_sequence_lock")),
                &port_sequence,
                &sequence_lock[..],
            ),
        ] {
            for statement in statements {
                assert!(
                    upstream.contains(statement),
                    "{label}: the pinned source no longer has {statement}"
                );
                assert!(
                    port.contains(statement),
                    "{label}: the port no longer has {statement}"
                );
            }
        }
    }

    // =========================================================================================
    // Compute budgets and mass
    // =========================================================================================    // =========================================================================================
    // Compute budgets and mass
    // =========================================================================================

    /// Every input of every builder's transaction runs within the budget the builder committed;
    /// prints the measured units and the covering budget per spend kind
    /// (`cargo test -p impulse-engine-tests --test builders budgets -- --nocapture`).
    #[test]
    fn budgets_cover_every_spend() {
        let mut worst: std::collections::BTreeMap<&str, (u64, u16)> = Default::default();
        let mut record = |kind: &'static str, used: u64, committed: u16, label: &str| {
            let cover = covering_budget(kaspa_consensus_core::mass::ScriptUnits(used));
            assert!(
                cover <= committed,
                "{label}: needs {cover}, commits {committed}"
            );
            let e = worst.entry(kind).or_insert((0, 0));
            if used > e.0 {
                *e = (used, cover);
            }
        };
        let mut txs: Vec<(String, Signed)> = vec![];
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            txs.push((format!("{mode:?} settle"), settled(&trade, &h)));
            let mut signers = vec![RefundSigner::Depositor, RefundSigner::Counterparty];
            if mode.authority {
                signers.push(RefundSigner::Authority);
            }
            for signer in signers {
                txs.push((
                    format!("{mode:?} refund {signer:?}"),
                    refunded(&trade, &h, LegIndex::Asset, signer, true),
                ));
            }
            if mode.cash == Cash::Kas {
                txs.push((
                    format!("{mode:?} refund KAS cash"),
                    refunded(&trade, &h, LegIndex::Cash, RefundSigner::Depositor, false),
                ));
            }
            txs.push((format!("{mode:?} fund asset"), h.asset_fund));
            if let Some(c) = h.cash_fund {
                txs.push((format!("{mode:?} fund cash"), c));
            }
        }
        for cash in [Cash::Kas, Cash::Kcc20] {
            let trade = Trade::new(Mode {
                direct: true,
                authority: false,
                cash,
                funding: FundingMode::Revocable,
            });
            txs.push((format!("direct {cash:?}"), directed(&trade)));
        }
        for (label, s) in &txs {
            for (i, input) in s.tx.inputs.iter().enumerate() {
                let used = measure(&s.tx, s.entries(), i).used.0;
                let committed = input.compute_commit.compute_budget().unwrap();
                let slot = &s.ipst.slots()[i];
                let kind = match committed {
                    b if b == VAULT_BUDGET => "vault settle or refund",
                    b if b == P2PK_BUDGET && slot.script_before().is_empty() => "P2PK",
                    b if b == KCC20_KEY_OWNED_BUDGET => "KCC-20, key owner",
                    b if b == KCC20_VAULT_OWNED_BUDGET => "KCC-20, vault owner",
                    other => panic!("{label}: unexpected budget {other}"),
                };
                record(kind, used, committed, &format!("{label} input {i}"));
            }
            // impulse-core's mass is the harness's (the same pinned calculator).
            assert_eq!(
                s.ipst.masses().compute,
                harness::compute_mass(&s.tx),
                "{label}"
            );
        }
        eprintln!("| Spend | Most script units measured | Covering budget | Committed budget |");
        eprintln!("| --- | --- | --- | --- |");
        for (kind, (used, cover)) in &worst {
            let committed = match *kind {
                "vault settle or refund" => VAULT_BUDGET,
                "P2PK" => P2PK_BUDGET,
                "KCC-20, key owner" => KCC20_KEY_OWNED_BUDGET,
                _ => KCC20_VAULT_OWNED_BUDGET,
            };
            eprintln!("| {kind} | {used} | {cover} | {committed} |");
        }
        assert_eq!(worst.len(), 4, "every spend kind measured");
    }

    /// Funds the asset leg from the seller's tokens of the given amounts (the first the leader,
    /// the others delegates).
    fn fund_from(trade: &Trade, amounts: &[u64]) -> Result<Ipst, tx::TxError> {
        let LegKind::Kcc20(token) = trade.terms.terms().asset_leg.kind else {
            unreachable!()
        };
        let tokens = amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| {
                own_token(
                    &format!("seller-token-{i}"),
                    &trade.asset,
                    &token,
                    &trade.x(&trade.seller),
                    amount,
                )
            })
            .collect();
        let deposit = Kcc20Deposit {
            tokens,
            carrier: MIN_KCC20_OUTPUT,
            authorizer: MIN_KAS_OUTPUT,
        };
        fund_kcc20(
            &trade.terms,
            &trade.fundable(LegIndex::Asset),
            &trade.asset,
            &deposit,
            &trade.fee("fund-fee"),
            NOW,
        )
    }

    /// Budgets follow the token templates' length. With kcc20.sil padded to about 3,800 and
    /// 6,100 template bytes (the fixture tokens have about 1,500), every input of every
    /// builder's transaction runs in the engine within the budget the builder committed, and the
    /// vault and token budgets rise above their floors, which the longer templates exceed. A
    /// template far longer still is refused when the transaction is built (`TX_MASS`), not left
    /// to fail at the node.
    #[test]
    fn budgets_follow_the_template_length() {
        let budget = |s: &Signed, i: usize| s.tx.inputs[i].compute_commit.compute_budget().unwrap();
        let allowance = |b: u16| u64::from(b) * 10_000 + 9_999;
        for lines in [30, 60] {
            let (asset, cash) = (
                padded_template(ASSET_TOKEN, lines),
                padded_template(CASH_TOKEN, lines),
            );
            let bytes = (asset.prefix_len() + asset.suffix_len()) as u64;
            for m in [
                mode(true, Cash::Kas, FundingMode::Earmarked),
                mode(true, Cash::Kcc20, FundingMode::Earmarked),
                mode(true, Cash::External, FundingMode::Revocable),
                mode(false, Cash::Kcc20, FundingMode::Revocable),
            ] {
                let label = format!("{bytes} template bytes, {m:?}");
                let trade = Trade::with(m, asset.clone(), cash.clone());
                let h = Holdings::of(&trade);
                h.asset_fund
                    .assert_engine_accepts(&format!("{label}: fund asset"));
                if let Some(c) = &h.cash_fund {
                    c.assert_engine_accepts(&format!("{label}: fund cash"));
                }
                let s = settled(&trade, &h);
                s.assert_engine_accepts(&format!("{label}: settle"));
                if lines == 60 && m.cash == Cash::Kcc20 && m.authority {
                    // The old fixed vault budget no longer covers this settle.
                    assert!(measure(&s.tx, s.entries(), 0).used.0 > allowance(VAULT_BUDGET));
                    assert!(budget(&s, 0) > VAULT_BUDGET, "{label}");
                }
                let mut signers = vec![RefundSigner::Depositor, RefundSigner::Counterparty];
                if m.authority {
                    signers.push(RefundSigner::Authority);
                }
                let legs: &[LegIndex] = if m.cash == Cash::External {
                    &[LegIndex::Asset]
                } else {
                    &[LegIndex::Asset, LegIndex::Cash]
                };
                for &leg in legs {
                    for &signer in &signers {
                        refunded(&trade, &h, leg, signer, true)
                            .assert_engine_accepts(&format!("{label}: refund {leg:?} {signer:?}"));
                    }
                }
            }
            // Funding from two tokens (leader and delegate), and Direct.
            let trade = Trade::with(
                mode(true, Cash::Kas, FundingMode::Earmarked),
                asset.clone(),
                cash.clone(),
            );
            let two = Signed::from(trade.sign(fund_from(&trade, &[600, 700]).unwrap()));
            two.assert_engine_accepts(&format!("{bytes} template bytes: fund from two tokens"));
            if lines == 60 {
                assert!(budget(&two, 0) > KCC20_KEY_OWNED_BUDGET);
            }
            for cash_kind in [Cash::Kas, Cash::Kcc20] {
                let trade = Trade::with(direct_mode(cash_kind), asset.clone(), cash.clone());
                directed(&trade).assert_engine_accepts(&format!(
                    "{bytes} template bytes: direct {cash_kind:?}"
                ));
            }
        }
        // About 10,700 template bytes: the settle's transient mass passes the standard cap, and
        // the builder says so.
        let trade = Trade::with(
            mode(true, Cash::Kcc20, FundingMode::Earmarked),
            padded_template(ASSET_TOKEN, 120),
            padded_template(CASH_TOKEN, 120),
        );
        let h = Holdings::of(&trade);
        let refused = settle(
            &trade.terms,
            &h.settle_legs(&trade),
            &trade.fee("settle-fee"),
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(
                refused,
                tx::TxError::Mass {
                    dimension: "transient",
                    ..
                }
            ),
            "{refused}"
        );
    }

    /// The per-byte rules behind the budgets, measured: with kcc20.sil padded by 0, 30 and 60
    /// statements (the asset template 1,461, 3,771 and 6,081 bytes, the cash template 199 bytes
    /// longer each), the script units of each spend grow exactly linearly in the template
    /// bytes: an ImpulseVault entry 17 per byte of its own leg's template and 10 per byte of a
    /// template it only validates, a `transfer` leader 2 per byte plus 4 per covenant output, a
    /// delegate 2 per byte. Prints the measurements
    /// (`cargo test -p impulse-engine-tests --test builders per_byte -- --nocapture`), and checks
    /// that the fixed parts stay within the rules' allowance.
    #[test]
    fn per_byte_script_units_are_measured() {
        let units = |s: &Signed, i: usize| measure(&s.tx, s.entries(), i).used.0;
        let mut rows: Vec<(&str, Vec<(u64, u64)>)> = vec![];
        let mut record = |name: &'static str, bytes: u64, used: u64| match rows
            .iter_mut()
            .find(|(n, _)| *n == name)
        {
            Some((_, v)) => v.push((bytes, used)),
            None => rows.push((name, vec![(bytes, used)])),
        };
        let mut kcc20_cash_fixed: Vec<(usize, u64)> = vec![];
        for lines in [0, 30, 60] {
            let (asset, cash) = (
                padded_template(ASSET_TOKEN, lines),
                padded_template(CASH_TOKEN, lines),
            );
            let la = (asset.prefix_len() + asset.suffix_len()) as u64;
            let kas = Trade::with(
                mode(true, Cash::Kas, FundingMode::Earmarked),
                asset.clone(),
                cash.clone(),
            );
            let kas_h = Holdings::of(&kas);
            let s = settled(&kas, &kas_h);
            record(
                "asset vault settle, KAS cash (own template)",
                la,
                units(&s, 0),
            );
            record(
                "KAS cash vault settle (validates the asset template)",
                la,
                units(&s, 1),
            );
            record(
                "asset escrow transfer, vault owner, 1 output",
                la,
                units(&s, 2),
            );
            let r = refunded(
                &kas,
                &kas_h,
                LegIndex::Asset,
                RefundSigner::Counterparty,
                true,
            );
            record("asset vault refund with its token", la, units(&r, 0));
            record(
                "asset fund leader, key owner, 1 input, 2 outputs",
                la,
                units(&kas_h.asset_fund, 0),
            );
            let two = Signed::from(kas.sign(fund_from(&kas, &[600, 700]).unwrap()));
            record(
                "asset fund leader, key owner, 2 inputs, 2 outputs",
                la,
                units(&two, 0),
            );
            record("asset fund delegate, key owner", la, units(&two, 1));
            // KCC-20 cash: each vault reads its own template (17 per byte) and validates the
            // other leg's delivery (10 per byte).
            let lc = (cash.prefix_len() + cash.suffix_len()) as u64;
            let kcc20 = Trade::with(
                mode(true, Cash::Kcc20, FundingMode::Earmarked),
                asset.clone(),
                cash.clone(),
            );
            let s = settled(&kcc20, &Holdings::of(&kcc20));
            for (input, own, other) in [(0, la, lc), (1, lc, la)] {
                let rest = units(&s, input) - 17 * own - 10 * other - 100_000;
                eprintln!(
                    "KCC-20 cash settle, vault input {input}, templates {la} and {lc} bytes: \
                     {} units, fixed part {rest} besides 1 signature check",
                    units(&s, input)
                );
                kcc20_cash_fixed.push((input, rest));
            }
        }
        for input in [0, 1] {
            let parts: Vec<u64> = kcc20_cash_fixed
                .iter()
                .filter(|(i, _)| *i == input)
                .map(|(_, rest)| *rest)
                .collect();
            assert!(
                parts.windows(2).all(|w| w[0] == w[1]),
                "KCC-20 cash settle input {input}: 17 per own and 10 per other template byte"
            );
            assert!(parts[0] <= 45_000);
        }
        let mut fixed = vec![];
        eprintln!("| Spend | Template bytes | Script units | Units per byte |");
        eprintln!("| --- | --- | --- | --- |");
        for (name, points) in &rows {
            let (b0, u0) = points[0];
            let slope = (points[1].1 - u0) / (points[1].0 - b0);
            for &(b, u) in points {
                assert_eq!(
                    u - u0,
                    slope * (b - b0),
                    "{name}: linear in the template bytes"
                );
                eprintln!("| {name} | {b} | {u} | {slope} |");
            }
            fixed.push((*name, u0 - slope * b0, slope));
        }
        let expect = |name: &str| fixed.iter().find(|(n, _, _)| *n == name).unwrap();
        // Signature checks: the vault entries with an authority and the key-owned transfers.
        let sigop = 100_000;
        for (name, slope, sigops, allowance) in [
            ("asset vault settle, KAS cash (own template)", 17, 1, 45_000),
            (
                "KAS cash vault settle (validates the asset template)",
                10,
                1,
                45_000,
            ),
            ("asset vault refund with its token", 17, 1, 45_000),
            ("asset escrow transfer, vault owner, 1 output", 6, 0, 12_000),
            (
                "asset fund leader, key owner, 1 input, 2 outputs",
                10,
                1,
                13_000,
            ),
            (
                "asset fund leader, key owner, 2 inputs, 2 outputs",
                10,
                1,
                14_000,
            ),
            ("asset fund delegate, key owner", 2, 1, 10_000),
        ] {
            let (_, base, measured) = expect(name);
            assert_eq!(*measured, slope, "{name}: units per template byte");
            let rest = base - sigops * sigop;
            assert!(
                rest <= allowance,
                "{name}: fixed part {rest} within {allowance}"
            );
            eprintln!("{name}: fixed part {rest} units besides {sigops} signature check(s)");
        }
    }

    /// The masses impulse-core reports for every settle, measured with its own calculator.    /// The masses impulse-core reports for every settle, measured with its own calculator.
    #[test]
    fn settle_masses() {
        eprintln!("| Settle | Inputs, outputs | Compute | Transient | Storage | Minimum relay fee (sompi) |");
        eprintln!("| --- | --- | --- | --- | --- | --- |");
        for mode in vault_modes() {
            let trade = Trade::new(mode);
            let h = Holdings::of(&trade);
            let s = settled(&trade, &h);
            let m = s.ipst.masses();
            assert!(m.compute <= tx::STANDARD_MASS_CAP && m.storage <= tx::STANDARD_MASS_CAP);
            assert!(s.ipst.fee() >= tx::min_relay_fee(m.fee_mass));
            eprintln!(
                "| {mode:?} | {}, {} | {} | {} | {} | {} |",
                s.tx.inputs.len(),
                s.tx.outputs.len(),
                m.compute,
                m.transient,
                m.storage,
                tx::min_relay_fee(m.fee_mass)
            );
        }
    }

    /// Writes the KCC-20 fixture artifacts for impulse-core's unit tests. Run by hand only; the
    /// committed files are checked by `kcc20_fixtures_are_the_pinned_compile`.
    #[test]
    #[ignore = "writes crates/impulse-core/src/tx/testdata/"]
    fn emit_kcc20_fixtures() {
        for (name, token) in [
            ("kcc20-asset.json", ASSET_TOKEN),
            ("kcc20-cash.json", CASH_TOKEN),
        ] {
            let json = silverscript_abi::to_pretty_json(&compiled(token).artifact).expect("json");
            std::fs::write(fixture_path(name), json + "\n").unwrap();
        }
    }
}
