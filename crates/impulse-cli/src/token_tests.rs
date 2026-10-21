// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The testnet token helper (spec/CLI.md, "Token helper (testnet only)") end to end in process,
//! against the in-memory fake node, which validates every genesis covenant ID with the pinned
//! consensus code (`CovenantsContext::from_tx`) and runs every submitted input in the pinned
//! script engine. A child of `phase2_tests`, whose world it uses. Each refusal has a failing case
//! beside an accepted control, and every refused command is checked to have printed nothing.
//! Keys are throwaway keys generated at runtime into temporary directories that are removed.

use super::*;
use crate::signing::throwaway::key_file;
use crate::token::{build, genesis_terms, party_key, GENESIS_TAG};
use crate::trade::FundableTrade;
use impulse_core::locktime::INPUT_SEQUENCE;
use impulse_core::terms::CreationContext;
use impulse_core::tx::{Utxo, P2PK_BUDGET};
use kaspa_consensus_core::constants::TX_VERSION_TOCCATA;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;

/// `token mint build` arguments: `payer` pays for a token of `template` held by `owner`.
fn mint_args(
    w: &World,
    leg: LegIndex,
    owner: &[u8; 32],
    payer: &KeyFile,
    amount: u64,
    out: &Path,
) -> Vec<String> {
    [
        "token",
        "mint",
        "build",
        "--node",
        NODE,
        "--template",
        &w.tpl(leg),
        "--owner",
        &hex(owner),
        "--pay-from",
        &w.addr(payer),
        "--amount",
        &amount.to_string(),
        "--out",
        s(out),
    ]
    .iter()
    .map(|x| x.to_string())
    .collect()
}

/// `ipst sign` of a genesis: `k` signs as the payer, for the genesis terms the IPST names.
fn genesis_sign_args(w: &World, ipst: &Path, k: &KeyFile, out: &Path) -> Vec<String> {
    replace(&w.sign_args(ipst, k, out), "--role", "payer")
}

/// `token list` arguments.
fn list_args(
    w: &World,
    leg: LegIndex,
    owner: &[u8; 32],
    covenant: &str,
    amount: u64,
) -> Vec<String> {
    [
        "token",
        "list",
        "--node",
        NODE,
        "--template",
        &w.tpl(leg),
        "--owner",
        &hex(owner),
        "--covenant",
        covenant,
        "--amount",
        &amount.to_string(),
    ]
    .iter()
    .map(|x| x.to_string())
    .collect()
}

/// Mints, signs as the owner, who pays, and submits; returns the build output, the `token:` and
/// `covenant:` lines.
fn mint(w: &World, leg: LegIndex, owner: &KeyFile, amount: u64) -> (String, String, String) {
    let name = format!("mint-{}-{amount}-{}", leg as u8, w.height());
    let unsigned = w.path(&name);
    let built = w.go(&mint_args(w, leg, &owner.signer, owner, amount, &unsigned));
    // A genesis IPST names its token as the genesis terms' asset leg (spec/CLI.md, "The
    // genesis check"), so the token's template goes in --asset-template.
    let signed = w.path(&format!("{name}.signed"));
    w.go(&replace(
        &genesis_sign_args(w, &unsigned, owner, &signed),
        "--asset-template",
        &w.tpl(leg),
    ));
    let out = w.go(&replace(
        &w.submit_args(&signed),
        "--asset-template",
        &w.tpl(leg),
    ));
    assert_eq!(field(&out, "submitted"), field(&built, "txid"));
    let (token, covenant) = (field(&built, "token"), field(&built, "covenant"));
    (built, token, covenant)
}

fn unhex(text: &str) -> [u8; 32] {
    crate::json::unhex32(text).unwrap()
}

/// The whole `token list` output for one token UTXO carrying the default 2 KAS, of a pinned
/// build with `max_cov` (maxCovIns, maxCovOuts).
fn list_text(
    template: &Kcc20Template,
    max_cov: (u8, u8),
    owner: &[u8; 32],
    covenant: &str,
    token: &str,
) -> String {
    format!(
        "network: testnet\n\
         template: {}, prefix {}, suffix {}; pinned: yes, kcc20.sil (silverscript v1.0.0) with maxCovIns {} and maxCovOuts {}\n\
         owner: {}\n\
         covenant: {covenant}\n\
         token: {token}\n\
         token_kas: {MIN_KCC20_OUTPUT}\n",
        hex(&template.template_hash()),
        template.prefix_len(),
        template.suffix_len(),
        max_cov.0,
        max_cov.1,
        hex(owner),
    )
}

/// spec/CLI.md, "The token genesis terms": the tag, the two party keys (known answers computed
/// in Python's hashlib), and terms that no trade can use.
#[test]
fn the_token_genesis_terms_are_fixed_and_never_a_live_trade() {
    assert_eq!(
        hex(&GENESIS_TAG),
        "496d70756c73652f746f6b656e2d67656e657369732f76310000000000000000"
    );
    assert_eq!(
        hex(&party_key("seller")),
        "6d755c66e18318a2ac4b2a3f0c0d517d1613dffa6ccfe5280efb000fab816b54"
    );
    assert_eq!(
        hex(&party_key("buyer")),
        "b2196ec23a3f518d771a97f3fd2fce494b3e8e1b0624c7ba226adafb5bd05965"
    );
    let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
    let owner = random_xonly();
    let v = genesis_terms(
        Network::Testnet,
        [7; 32],
        &template,
        owner,
        5,
        MIN_KCC20_OUTPUT,
    )
    .unwrap();
    let t = v.terms();
    assert_eq!(t.settlement_mode, SettlementMode::Direct);
    assert_eq!((t.nonce, t.expiry_daa, t.earliest_daa), (0, 1, None));
    assert_eq!(t.authority_key, None);
    assert_eq!(
        t.buyer_delivery,
        Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::PubKey,
            identifier: owner,
        })
    );
    assert_eq!(
        (t.asset_leg.amount, t.cash_leg.amount),
        (5, MIN_KCC20_OUTPUT)
    );
    // Expired on any chain: the creation checks refuse them at every DAA score from 1.
    for daa in [1, START_DAA] {
        let e = FundableTrade::new(v.clone(), &CreationContext::new(Network::Testnet, daa))
            .unwrap_err();
        assert_eq!(e.code(), "TERMS_EXPIRY_NOT_AFTER_CREATION");
    }
    // Their hash commits to the token: another owner, amount, carrier or covenant is another hash.
    let h = v.terms_hash();
    for other in [
        genesis_terms(
            Network::Testnet,
            [7; 32],
            &template,
            random_xonly(),
            5,
            MIN_KCC20_OUTPUT,
        ),
        genesis_terms(
            Network::Testnet,
            [7; 32],
            &template,
            owner,
            6,
            MIN_KCC20_OUTPUT,
        ),
        genesis_terms(
            Network::Testnet,
            [7; 32],
            &template,
            owner,
            5,
            MIN_KCC20_OUTPUT + 1,
        ),
        genesis_terms(
            Network::Testnet,
            [8; 32],
            &template,
            owner,
            5,
            MIN_KCC20_OUTPUT,
        ),
    ] {
        assert_ne!(other.unwrap().terms_hash(), h);
    }
}

/// The scope's exit items: the genesis and the minted UTXOs validate in the engine (the fake
/// node checks the genesis covenant ID with the pinned consensus code and runs every input), the
/// minted tokens pass the pinned-template check, `fund build` takes them as legs, and a whole
/// trade of two minted tokens settles.
#[test]
fn minted_tokens_validate_in_the_engine_and_settle_a_trade() {
    let w = World::new(Network::Testnet);
    let (built, asset_token, asset_cov) = mint(&w, LegIndex::Asset, &w.seller, 15);
    let (_, cash_token, cash_cov) = mint(&w, LegIndex::Cash, &w.buyer, 7);
    // What build prints: the genesis summary, the pinned template, the transaction lines.
    assert_eq!(field(&built, "ipst"), "token genesis");
    assert_eq!(field(&built, "owner"), hex(&w.seller.signer));
    assert_eq!(field(&built, "amount"), "15 token units");
    assert!(field(&built, "template").ends_with(
        "pinned: yes, kcc20.sil (silverscript v1.0.0) with maxCovIns 2 and maxCovOuts 2"
    ));
    assert_eq!(
        field(&built, "carrier"),
        "200000000 sompi (2.00000000 KAS) on the token output"
    );
    assert_eq!(asset_token, format!("{}:0:15", field(&built, "txid")));
    assert!(field(&built, "output 0").ends_with(&format!(
        "(pay to script hash), covenant {asset_cov} from input 0"
    )));
    // The token is on the node, held by the seller at the pinned template; token list prints
    // exactly its lines (review round 1 of the token helper: the network, template and owner
    // lines too, for a (2,2) and a (2,3) build).
    let listed = w.go(&list_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &asset_cov,
        15,
    ));
    assert_eq!(
        listed,
        list_text(&w.asset, (2, 2), &w.seller.signer, &asset_cov, &asset_token)
    );
    let listed = w.go(&list_args(
        &w,
        LegIndex::Cash,
        &w.buyer.signer,
        &cash_cov,
        7,
    ));
    assert_eq!(
        listed,
        list_text(&w.cash, (2, 3), &w.buyer.signer, &cash_cov, &cash_token)
    );
    // A trade of the two minted tokens: fund build takes them, the engine runs their transfers.
    *w.seller_token.borrow_mut() = asset_token;
    *w.buyer_token.borrow_mut() = cash_token;
    let terms = w.terms("minted.json", Mode::SelfSettling, |t| {
        t.asset_leg.kind = LegKind::Kcc20(w.token(&w.asset, unhex(&asset_cov)));
        t.cash_leg.kind = LegKind::Kcc20(w.token(&w.cash, unhex(&cash_cov)));
    });
    let address = w.go(&[
        "address".to_string(),
        "--terms".into(),
        s(&terms).into(),
        "--node".into(),
        NODE.into(),
        "--role".into(),
        "seller".into(),
        "--my-key".into(),
        hex(&w.seller.signer),
        "--no-qr".into(),
        DECLARE[0].into(),
        DECLARE[1].into(),
    ]);
    assert!(address.contains("asset vault: "), "{address}");
    w.fund(&terms, LegIndex::Asset);
    // 15 units less the 10 escrowed: the seller's token change is 5 units.
    assert!(w.seller_token.borrow().ends_with(":2:5"));
    w.fund(&terms, LegIndex::Cash);
    let unsigned = w.path("minted-settle");
    w.go(&w.settle_args(&terms, &w.buyer, &unsigned));
    w.sign_submit(&unsigned, &w.buyer);
    // The buyer now holds the 10 asset units, the seller the 7 cash units.
    w.go(&list_args(
        &w,
        LegIndex::Asset,
        &w.buyer.signer,
        &asset_cov,
        10,
    ));
    w.go(&list_args(
        &w,
        LegIndex::Cash,
        &w.seller.signer,
        &cash_cov,
        7,
    ));
}

/// The fake node refuses a genesis whose covenant ID is not the one the pinned consensus code
/// computes, beside the signed genesis itself, which it accepts.
#[test]
fn the_engine_refuses_a_genesis_with_another_covenant_id() {
    let w = World::new(Network::Testnet);
    let unsigned = w.path("g.ipst");
    w.go(&mint_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &w.seller,
        5,
        &unsigned,
    ));
    let signed = w.path("g.signed");
    w.go(&genesis_sign_args(&w, &unsigned, &w.seller, &signed));
    let tx = Ipst::from_json(&std::fs::read_to_string(&signed).unwrap())
        .unwrap()
        .finalize()
        .unwrap();
    for (what, edit) in [
        ("another covenant ID", [0xEE; 32]),
        ("the covenant ID of another output index", {
            let mut other = tx.outputs[0].clone();
            other.covenant = None;
            kaspa_consensus_core::hashing::covenant_id::covenant_id(
                tx.inputs[0].previous_outpoint,
                [(1u32, &other)].into_iter(),
            )
            .as_bytes()
        }),
    ] {
        let mut forged = tx.clone();
        forged.outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes(edit)));
        forged.finalize();
        let e = w.sim.state.borrow_mut().submit(&forged).unwrap_err();
        assert!(e.contains("covenants"), "{what}: {e}");
    }
    let height = w.height();
    w.sim.state.borrow_mut().submit(&tx).unwrap();
    assert_eq!(w.height(), height + 1);
}

/// spec/CLI.md, "token mint build", checks 1 to 8: each refusal beside the accepted control,
/// nothing printed or written.
#[test]
fn token_mint_build_checks_its_arguments() {
    let w = World::new(Network::Testnet);
    let out = w.path("m.ipst");
    let args = mint_args(&w, LegIndex::Asset, &w.seller.signer, &w.seller, 5, &out);
    let refused = |a: &[String]| {
        let code = w.no(a);
        assert!(!out.exists(), "{code} wrote the IPST");
        code
    };
    std::fs::write(w.path("u.json"), unpinned_artifact()).unwrap();
    std::fs::write(w.path("not-kcc20.json"), "{}").unwrap();
    // Mainnet: refused before anything is read or contacted.
    w.explicit.set(true);
    assert_eq!(refused(&args), "CLI_TOKEN_TESTNET_ONLY");
    assert_eq!(
        refused(&replace(&args, "--template", "/nonexistent")),
        "CLI_TOKEN_TESTNET_ONLY"
    );
    w.explicit.set(false);
    assert_eq!(
        refused(&replace(&args, "--node", "http://127.0.0.1:17210")),
        "CLI_NODE_URL_INVALID"
    );
    assert_eq!(
        refused(&replace(&args, "--template", s(&w.path("u.json")))),
        "CLI_TOKEN_TEMPLATE_UNPINNED"
    );
    assert_eq!(
        refused(&replace(&args, "--template", s(&w.path("not-kcc20.json")))),
        "TX_TOKEN_TEMPLATE"
    );
    assert_eq!(
        refused(&replace(&args, "--template", "/nonexistent")),
        "CLI_FILE_READ"
    );
    assert_eq!(refused(&replace(&args, "--owner", "abc")), "CLI_HEX");
    assert_eq!(
        refused(&replace(&args, "--owner", &"00".repeat(32))),
        "CLI_TOKEN_OWNER_INVALID"
    );
    assert_eq!(
        refused(&replace(&args, "--owner", &"ff".repeat(32))),
        "CLI_TOKEN_OWNER_INVALID"
    );
    assert_eq!(
        refused(&replace(&args, "--amount", "0")),
        "CLI_TOKEN_AMOUNT_INVALID"
    );
    assert_eq!(
        refused(&replace(
            &args,
            "--amount",
            &(i64::MAX as u64 + 1).to_string()
        )),
        "CLI_TOKEN_AMOUNT_INVALID"
    );
    let p2sh = kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Testnet,
        kaspa_addresses::Version::ScriptHash,
        &[9; 32],
    )
    .to_string();
    assert_eq!(
        refused(&replace(&args, "--pay-from", &p2sh)),
        "CLI_ADDRESS_INVALID"
    );
    assert_eq!(
        refused(&with(&args, &["--change", "kaspatest:nothing"])),
        "CLI_ADDRESS_INVALID"
    );
    let unfunded = p2pk_address(&random_xonly(), Network::Testnet).to_string();
    assert_eq!(
        refused(&replace(&args, "--pay-from", &unfunded)),
        "CLI_UTXO_NOT_FOUND"
    );
    assert_eq!(
        refused(&with(&args, &["--carrier", "199999999"])),
        "TX_BELOW_MIN_KAS"
    );
    // A carrier the fee pushes past u64::MAX (review round 1 of the token helper).
    assert_eq!(
        refused(&with(
            &args,
            &["--carrier", &u64::MAX.to_string(), "--fee", "1000000"]
        )),
        "TX_INSUFFICIENT_FUNDS"
    );
    assert_eq!(refused(&with(&args, &["--fee", "1"])), "TX_FEE_TOO_LOW");
    std::fs::write(&out, "taken").unwrap();
    assert_eq!(w.no(&args), "CLI_OUTPUT_EXISTS");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "taken");
    std::fs::remove_file(&out).unwrap();
    // Controls: the default build; the smallest and the largest amount; another carrier, change
    // and payer; the whole supply for a key that does not pay.
    let built = w.go(&args);
    assert_eq!(field(&built, "pending"), hex(&w.seller.signer));
    let one = w.path("one.ipst");
    let built = w.go(&replace(&replace(&args, "--amount", "1"), "--out", s(&one)));
    assert_eq!(field(&built, "amount"), "1 token units");
    let big = w.path("big.ipst");
    let max = (i64::MAX as u64).to_string();
    w.go(&replace(
        &replace(&args, "--amount", &max),
        "--out",
        s(&big),
    ));
    let other = w.path("other.ipst");
    let built = w.go(&with(
        &replace(
            &mint_args(&w, LegIndex::Cash, &w.buyer.signer, &w.authority, 2, &other),
            "--out",
            s(&other),
        ),
        &["--carrier", "300000000", "--change", &w.addr(&w.seller)],
    ));
    assert_eq!(field(&built, "owner"), hex(&w.buyer.signer));
    assert!(field(&built, "output 0").starts_with("300000000 sompi"));
    assert!(
        field(&built, "change").ends_with(&format!("{} (pay to x-only key)", w.addr(&w.seller)))
    );
    assert_eq!(field(&built, "pending"), hex(&w.authority.signer));
}

/// spec/CLI.md, "token list": the UTXOs of exactly the template, owner, amount and covenant
/// named, lowest outpoint first, beside each refusal.
#[test]
fn token_list_finds_only_the_token_it_names() {
    let w = World::new(Network::Testnet);
    let (_, token, cov) = mint(&w, LegIndex::Asset, &w.seller, 5);
    let args = list_args(&w, LegIndex::Asset, &w.seller.signer, &cov, 5);
    assert_eq!(field(&w.go(&args), "token"), token);
    // A second UTXO of the same token state: both listed, lowest outpoint first.
    let spk = w
        .asset
        .script_public_key(&held_state(w.seller.signer, 5))
        .unwrap();
    let second = w
        .sim
        .state
        .borrow_mut()
        .add_utxo(spk, 300_000_000, Some(unhex(&cov)));
    let listed = w.go(&args);
    let mut expected = vec![token.clone(), format!("{}:5", outpoint_text(&second))];
    expected.sort();
    let tokens: Vec<&str> = listed
        .lines()
        .filter_map(|l| l.strip_prefix("token: "))
        .collect();
    assert_eq!(tokens, expected);
    assert_eq!(
        listed
            .lines()
            .filter(|l| l.starts_with("token_kas: "))
            .count(),
        2
    );
    // Not there: another amount, owner, covenant or template.
    for other in [
        replace(&args, "--amount", "4"),
        replace(&args, "--owner", &hex(&w.buyer.signer)),
        replace(&args, "--covenant", &hex(&random32())),
        replace(&args, "--template", &w.tpl(LegIndex::Cash)),
    ] {
        assert_eq!(w.no(&other), "CLI_UTXO_NOT_FOUND");
    }
    std::fs::write(w.path("u.json"), unpinned_artifact()).unwrap();
    assert_eq!(
        w.no(&replace(&args, "--template", s(&w.path("u.json")))),
        "CLI_TOKEN_TEMPLATE_UNPINNED"
    );
    assert_eq!(
        w.no(&replace(&args, "--owner", &"00".repeat(32))),
        "CLI_TOKEN_OWNER_INVALID"
    );
    assert_eq!(
        w.no(&replace(&args, "--amount", "0")),
        "CLI_TOKEN_AMOUNT_INVALID"
    );
    assert_eq!(w.no(&replace(&args, "--covenant", "xyz")), "CLI_HEX");
    w.explicit.set(true);
    assert_eq!(w.no(&args), "CLI_TOKEN_TESTNET_ONLY");
    w.explicit.set(false);
    assert_eq!(field(&w.go(&args), "covenant"), cov);
}

/// A genesis document from edited parts, rendered as `token mint build` renders one, so its
/// sighashes are consistent and only the genesis check can refuse it.
fn genesis_doc(
    w: &World,
    good: &Ipst,
    name: &str,
    terms: Option<&impulse_core::terms::ValidatedTerms>,
    edit: &dyn Fn(&mut Transaction, &mut Vec<UtxoEntry>),
) -> PathBuf {
    let mut tx = good.transaction().clone();
    let mut entries = good.entries().to_vec();
    edit(&mut tx, &mut entries);
    tx.finalize();
    let key = good.slots()[0].signer().unwrap();
    let v = crate::cancel::document(terms.unwrap_or(good.terms()), &tx, &entries, key).unwrap();
    let ipst = Ipst::from_json(&v.to_string()).unwrap();
    let p = w.path(name);
    std::fs::write(&p, ipst.to_json()).unwrap();
    p
}

/// spec/CLI.md, "The genesis check": a genesis document that is not what `token mint build`
/// makes from its own parts is refused by `ipst sign`, `ipst merge` and `submit`, beside the
/// built document, which they accept.
#[test]
fn a_genesis_is_held_to_what_token_mint_build_makes() {
    let w = World::new(Network::Testnet);
    let built = w.path("g.ipst");
    w.go(&mint_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &w.seller,
        5,
        &built,
    ));
    let good = Ipst::from_json(&std::fs::read_to_string(&built).unwrap()).unwrap();
    assert_eq!(good.transaction().inputs.len(), 1);
    let same = genesis_doc(&w, &good, "same.ipst", None, &|_, _| {});
    assert_eq!(
        std::fs::read_to_string(&same).unwrap(),
        std::fs::read_to_string(&built).unwrap()
    );
    let buyer = address_script(&p2pk_address(&w.buyer.signer, w.network));
    let input = |tx: &Transaction, i: usize, sequence: u64, budget: u16| {
        TransactionInput::new_with_compute_budget(
            tx.inputs[i].previous_outpoint,
            vec![],
            sequence,
            budget,
        )
    };
    let t = good.terms().terms();
    let LegKind::Kcc20(token) = t.asset_leg.kind else {
        unreachable!()
    };
    let rebuilt_terms = |owner: [u8; 32], expiry: u64| {
        let mut t = genesis_terms(
            Network::Testnet,
            token.covenant_id,
            &w.asset,
            owner,
            5,
            MIN_KCC20_OUTPUT,
        )
        .unwrap()
        .into_terms();
        t.expiry_daa = expiry;
        t.validate_structure().unwrap()
    };
    let other_owner = rebuilt_terms(w.buyer.signer, 1);
    let script_hash_owner = {
        let mut t = rebuilt_terms(w.seller.signer, 1).into_terms();
        t.buyer_delivery = Destination::Kcc20(Kcc20Owner {
            identifier_type: IdentifierType::ScriptHash,
            identifier: w.seller.signer,
        });
        t.validate_structure().unwrap()
    };
    let later_expiry = rebuilt_terms(w.seller.signer, 2);
    let other_spk = w
        .asset
        .script_public_key(&held_state(w.buyer.signer, 5))
        .unwrap();
    let cases: Vec<(&str, PathBuf, &str)> = vec![
        (
            "the token output held by another key",
            genesis_doc(&w, &good, "t1", None, &|tx, _| {
                tx.outputs[0].script_public_key = other_spk.clone()
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "terms naming another owner than the token output",
            genesis_doc(&w, &good, "t2", Some(&other_owner), &|_, _| {}),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "the tag and party keys with another expiry: no genesis terms, so the cancellation check refuses it",
            genesis_doc(&w, &good, "t3", Some(&later_expiry), &|_, _| {}),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "terms naming the owner as a script hash",
            genesis_doc(&w, &good, "t3b", Some(&script_hash_owner), &|_, _| {}),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "another covenant ID",
            genesis_doc(&w, &good, "t4", None, &|tx, _| {
                tx.outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([0xEE; 32])))
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "no covenant binding",
            genesis_doc(&w, &good, "t5", None, &|tx, _| {
                tx.outputs[0].covenant = None
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "one sompi moved from the change to the token",
            genesis_doc(&w, &good, "t6", None, &|tx, _| {
                tx.outputs[0].value += 1;
                tx.outputs[1].value -= 1;
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a lock time",
            genesis_doc(&w, &good, "t7", None, &|tx, _| tx.lock_time = 5),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a final sequence",
            genesis_doc(&w, &good, "t8", None, &|tx, _| {
                tx.inputs[0] = input(tx, 0, u64::MAX, P2PK_BUDGET)
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a raised compute budget",
            genesis_doc(&w, &good, "t9", None, &|tx, _| {
                tx.inputs[0] = input(tx, 0, 0, P2PK_BUDGET + 5)
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "an output after the change",
            genesis_doc(&w, &good, "t10", None, &|tx, _| {
                tx.outputs[1].value -= 100_000_000;
                tx.outputs
                    .push(TransactionOutput::new(100_000_000, buyer.clone()));
            }),
            "IPST_TERMS_MISMATCH",
        ),
        (
            "a second input of another key",
            genesis_doc(&w, &good, "t11", None, &|tx, entries| {
                let extra = w.sim.state.borrow().utxos_at(&buyer)[0].clone();
                tx.inputs.push(TransactionInput::new_with_compute_budget(
                    extra.outpoint,
                    vec![],
                    0,
                    P2PK_BUDGET,
                ));
                tx.outputs[1].value += extra.entry.amount;
                entries.push(extra.entry);
            }),
            "TX_KAS_INPUT",
        ),
        (
            "an input with a covenant ID",
            genesis_doc(&w, &good, "t12", None, &|_, entries| {
                entries[0].covenant_id = Some(Hash::from_bytes([3; 32]))
            }),
            "TX_KAS_INPUT",
        ),
        (
            "a non-standard change script",
            genesis_doc(&w, &good, "t13", None, &|tx, _| {
                tx.outputs[1].script_public_key = ScriptPublicKey::from_vec(0, vec![0x51])
            }),
            "TX_NONSTANDARD_CHANGE",
        ),
        (
            "the payer's input spent twice",
            genesis_doc(&w, &good, "t14", None, &|tx, entries| {
                tx.inputs.push(tx.inputs[0].clone());
                entries.push(entries[0].clone());
            }),
            "TX_DUPLICATE_INPUT",
        ),
    ];
    for (what, path, code) in &cases {
        let out = w.path("refused.out");
        assert_eq!(
            w.no(&genesis_sign_args(&w, path, &w.seller, &out)),
            *code,
            "ipst sign: {what}"
        );
        assert_eq!(
            w.no(&merge_args(&w, path, path, &out)),
            *code,
            "ipst merge: {what}"
        );
        assert_eq!(w.no(&w.submit_args(path)), *code, "submit: {what}");
        assert!(!out.exists());
    }
    // Self-consistent and accepted by the check, with no change output and the rest as fee: the
    // payer's fee limit refuses it, and --max-fee accepts it.
    let all_fee = genesis_doc(&w, &good, "all-fee", None, &|tx, _| tx.outputs.truncate(1));
    assert_eq!(
        w.no(&genesis_sign_args(
            &w,
            &all_fee,
            &w.seller,
            &w.path("af.out")
        )),
        "CLI_IPST_FEE_TOO_HIGH"
    );
    w.go(&with(
        &genesis_sign_args(&w, &all_fee, &w.seller, &w.path("af.out")),
        &[
            "--max-fee",
            &good.entries()[0].amount.to_string(),
            "--i-accept-the-risk",
        ],
    ));
    // Controls: the built document signs, merges and submits.
    let signed = w.path("same.signed");
    let out = w.go(&genesis_sign_args(&w, &same, &w.seller, &signed));
    assert_eq!(
        field(&out, "you"),
        format!(
            "payer, a key with no role in the terms, {}",
            hex(&w.seller.signer)
        )
    );
    let merged = w.path("same.merged");
    let out = w.go(&merge_args(&w, &signed, &same, &merged));
    assert_eq!(field(&out, "ipst"), "token genesis");
    let out = w.go(&w.submit_args(&merged));
    assert_eq!(
        field(&out, "submitted"),
        hex(&good.transaction().id().as_bytes())
    );
}

/// spec/CLI.md, "The genesis check", how `ipst sign` signs a genesis: the payer only, the
/// agreed genesis terms, the carrier confirmed, the change, the template, and the value cap on
/// what the payer commits; each refusal beside its accepted control.
#[test]
fn ipst_sign_of_a_genesis_checks_the_payer() {
    let w = World::new(Network::Testnet);
    let built = w.path("g.ipst");
    let out_text = w.go(&mint_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &w.seller,
        5,
        &built,
    ));
    let o = w.path("s.out");
    let args = genesis_sign_args(&w, &built, &w.seller, &o);
    let refused = |a: &[String]| {
        let code = w.no(a);
        assert!(!o.exists(), "{code} wrote the signed IPST");
        code
    };
    assert_eq!(
        field(&out_text, "terms_hash"),
        field(&w.go(&args), "terms_hash")
    );
    std::fs::remove_file(&o).unwrap();
    for role in ["seller", "buyer", "authority"] {
        assert_eq!(
            refused(&replace(&args, "--role", role)),
            "CLI_ROLE_KEY_MISMATCH",
            "{role}"
        );
    }
    assert_eq!(
        refused(&replace(&args, "--terms-hash", &hex(&random32()))),
        "CLI_IPST_TERMS_NOT_AGREED"
    );
    assert_eq!(
        refused(&with(&args, &["--carrier", "300000000"])),
        "CLI_TOKEN_CARRIER_MISMATCH"
    );
    assert_eq!(
        refused(&with(&args, &["--authorizer", "50000000"])),
        "TX_WRONG_MODE"
    );
    assert_eq!(
        refused(&with(&args, &["--change", &w.addr(&w.buyer)])),
        "CLI_IPST_CHANGE_NOT_MINE"
    );
    assert_eq!(
        refused(&without(&args, "--asset-template")),
        "CLI_TEMPLATE_MISSING"
    );
    assert_eq!(
        refused(&replace(&args, "--asset-template", &w.tpl(LegIndex::Cash))),
        "TX_TOKEN_TEMPLATE"
    );
    // Another key has no slot here.
    let by_buyer = replace(
        &replace(&args, "--key-file", s(&w.buyer.path)),
        "--my-key",
        &hex(&w.buyer.signer),
    );
    assert_eq!(refused(&by_buyer), "CLI_IPST_NOTHING_TO_SIGN");
    // The cap holds what the payer commits (the 2 KAS carrier and the fee).
    *w.max_value.borrow_mut() = Some("200000000".into());
    assert_eq!(refused(&args), "CLI_VALUE_CAP_EXCEEDED");
    let lifted = w.go(&with(
        &without(&args, "--kas-equivalent"),
        &["--i-accept-the-risk"],
    ));
    assert_eq!(field(&lifted, "value cap"), "lifted by --i-accept-the-risk");
    std::fs::remove_file(&o).unwrap();
    *w.max_value.borrow_mut() = None;
    // Controls: no trade value is asked for; the default cap line; a carrier and change the
    // signer confirms.
    let signed = w.go(&without(&args, "--kas-equivalent"));
    assert_eq!(
        field(&signed, "value cap"),
        "a token genesis is not a trade; what you commit is held to the cap of 1000000000 sompi"
    );
    // The genesis summary, not a trade's; what the payer commits is the carrier and the fee,
    // within the carrier and the default fee limit (twice the minimum relay fee).
    assert_eq!(field(&signed, "owner"), hex(&w.seller.signer));
    assert!(field(&signed, "token_genesis").starts_with("testnet; "));
    let doc = Ipst::from_json(&std::fs::read_to_string(&built).unwrap()).unwrap();
    assert_eq!(
        field(&signed, "you commit"),
        format!(
            "{} sompi of your KAS (the inputs you sign less what comes back to you), within {}",
            MIN_KCC20_OUTPUT + doc.fee(),
            MIN_KCC20_OUTPUT + 2 * min_relay_fee(doc.masses().fee_mass)
        )
    );
    let other = w.path("o.ipst");
    w.go(&with(
        &mint_args(&w, LegIndex::Asset, &w.seller.signer, &w.seller, 5, &other),
        &["--carrier", "300000000", "--change", &w.addr(&w.buyer)],
    ));
    let other_args = genesis_sign_args(&w, &other, &w.seller, &w.path("o.out"));
    assert_eq!(
        w.no(&with(&other_args, &["--change", &w.addr(&w.buyer)])),
        "CLI_TOKEN_CARRIER_MISMATCH"
    );
    w.go(&with(
        &other_args,
        &["--carrier", "300000000", "--change", &w.addr(&w.buyer)],
    ));
}

/// spec/CLI.md, "Token helper (testnet only)": a genesis on mainnet is refused by every command
/// that reads an IPST, as soon as it is read (since review round 1 of the token helper, `frost
/// sign` and `frost aggregate` too), and by `token mint build` and `token list` on a mainnet
/// node; the same commands take the testnet genesis, and the frost commands refuse it for having
/// no authority input.
#[test]
fn a_token_genesis_is_testnet_only_everywhere() {
    let main = World::new(Network::Mainnet);
    let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
    let spk = address_script(&p2pk_address(&main.seller.signer, Network::Mainnet));
    let utxo: Utxo = main.sim.state.borrow().utxos_at(&spk)[0].clone();
    let fee = FeePayment {
        inputs: vec![utxo],
        fee: 1_000_000,
        change: spk,
    };
    let ipst = build(
        Network::Mainnet,
        &template,
        main.seller.signer,
        5,
        MIN_KCC20_OUTPUT,
        &fee,
    )
    .unwrap();
    let doc = main.path("mainnet-genesis.ipst");
    std::fs::write(&doc, ipst.to_json()).unwrap();
    let o = main.path("o");
    let reads = |w: &World, doc: &Path| -> Vec<Vec<String>> {
        vec![
            genesis_sign_args(w, doc, &w.seller, &o),
            merge_args(w, doc, doc, &o),
            w.submit_args(doc),
            vec![
                "ipst".into(),
                "raw".into(),
                "--ipst".into(),
                s(doc).into(),
                "--out".into(),
                s(&o).into(),
            ],
            frost_sign_args(w, doc),
            frost_aggregate_args(w, doc),
        ]
    };
    // The genesis check repeats the refusal for a document read by other means.
    let templates = crate::build_cmd::TemplateArgs {
        asset_template: Some(crate::world::asset_template_path()),
        cash_template: None,
    };
    assert_eq!(
        crate::token::check(&ipst, &templates).unwrap_err().code(),
        "CLI_TOKEN_TESTNET_ONLY"
    );
    for args in reads(&main, &doc) {
        assert_eq!(main.no(&args), "CLI_TOKEN_TESTNET_ONLY", "{args:?}");
        // Without --network mainnet too: the genesis is refused before the network check.
        main.explicit.set(false);
        assert_eq!(main.no(&args), "CLI_TOKEN_TESTNET_ONLY", "{args:?}");
        main.explicit.set(true);
    }
    let height = main.height();
    for args in [
        mint_args(
            &main,
            LegIndex::Asset,
            &main.seller.signer,
            &main.seller,
            5,
            &o,
        ),
        list_args(
            &main,
            LegIndex::Asset,
            &main.seller.signer,
            &hex(&random32()),
            5,
        ),
    ] {
        assert_eq!(main.no(&args), "CLI_TOKEN_TESTNET_ONLY");
    }
    assert!(!o.exists());
    assert_eq!(main.height(), height);
    // Controls on testnet: the same commands on a testnet genesis.
    let w = World::new(Network::Testnet);
    let doc = w.path("g.ipst");
    w.go(&mint_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &w.seller,
        5,
        &doc,
    ));
    let signed = w.path("g.signed");
    w.go(&genesis_sign_args(&w, &doc, &w.seller, &signed));
    let o = w.path("o");
    let reads = |w: &World, doc: &Path, o: &Path| -> Vec<Vec<String>> {
        vec![
            merge_args(w, doc, doc, o),
            vec![
                "ipst".into(),
                "raw".into(),
                "--ipst".into(),
                s(doc).into(),
                "--out".into(),
                s(o).into(),
            ],
            w.submit_args(doc),
        ]
    };
    for args in reads(&w, &signed, &o) {
        w.go(&args);
        let _ = std::fs::remove_file(&o);
    }
    // The frost commands read the testnet genesis, then refuse it for what it is not: a
    // transaction with an authority input.
    for args in [
        frost_sign_args(&w, &signed),
        frost_aggregate_args(&w, &signed),
    ] {
        assert_eq!(w.no(&args), "FROST_NO_AUTHORITY_INPUT", "{args:?}");
    }
}

/// `frost sign` arguments for `doc`; the share file and the directory are never reached here.
fn frost_sign_args(w: &World, doc: &Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "frost",
        "sign",
        "--share-file",
        s(&w.path("share.frost")),
        "--ipst",
        s(doc),
        "--signers",
        "1,2",
        "--terms-hash",
        &"00".repeat(32),
        "--dir",
        s(&w.path("frost")),
        "--asset-template",
        &w.tpl(LegIndex::Asset),
        "--node",
        NODE,
    ]
    .map(String::from)
    .to_vec();
    a.extend(DECLARE.iter().map(|x| x.to_string()));
    a
}

/// `frost aggregate` arguments for `doc`; the group file and the directory are never reached here.
fn frost_aggregate_args(w: &World, doc: &Path) -> Vec<String> {
    [
        "frost",
        "aggregate",
        "--group",
        s(&w.path("group.frost")),
        "--ipst",
        s(doc),
        "--signers",
        "1,2",
        "--dir",
        s(&w.path("frost")),
        "--out",
        s(&w.path("aggregated.ipst")),
    ]
    .map(String::from)
    .to_vec()
}

/// spec/CLI.md, "token mint build": the genesis builder keeps the builders' rules with their
/// codes, each refusal beside the accepted control, and binds the token output to the covenant
/// ID the pinned consensus code computes for input 0.
#[test]
fn the_genesis_builder_keeps_the_builders_rules() {
    use kaspa_consensus_core::constants::MAX_SOMPI;
    use kaspa_consensus_core::tx::TransactionOutpoint;
    let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
    let (payer, other) = (random_xonly(), random_xonly());
    let spk = |k: &[u8; 32]| address_script(&p2pk_address(k, Network::Testnet));
    let utxo = |n: u8, amount: u64, script: ScriptPublicKey, cov: Option<[u8; 32]>| Utxo {
        outpoint: TransactionOutpoint::new(Hash::from_bytes([n; 32]), 0),
        entry: UtxoEntry::new(amount, script, START_DAA, false, cov.map(Hash::from_bytes)),
    };
    let fee = 1_000_000;
    let pay = |inputs: Vec<Utxo>| FeePayment {
        inputs,
        fee,
        change: spk(&payer),
    };
    let code = |p: &FeePayment, carrier: u64| {
        build(Network::Testnet, &template, payer, 5, carrier, p)
            .map(|_| ())
            .map_err(|e| e.code())
    };
    let c = MIN_KCC20_OUTPUT;
    let ok = utxo(1, 10_000_000_000, spk(&payer), None);
    let p2sh = ScriptPublicKey::from_vec(0, [&[0xaa, 0x20][..], &[5; 32], &[0x87]].concat());
    for (what, p, carrier, expected) in [
        ("no input", pay(vec![]), c, "TX_KAS_INPUT"),
        (
            "input 0 not P2PK",
            pay(vec![utxo(1, 10_000_000_000, p2sh, None)]),
            c,
            "TX_KAS_INPUT",
        ),
        (
            "input 0 with a covenant ID",
            pay(vec![utxo(1, 10_000_000_000, spk(&payer), Some([3; 32]))]),
            c,
            "TX_KAS_INPUT",
        ),
        (
            "input 1 of another key",
            pay(vec![ok.clone(), utxo(2, 1_000_000_000, spk(&other), None)]),
            c,
            "TX_KAS_INPUT",
        ),
        (
            "input 1 with a covenant ID",
            pay(vec![
                ok.clone(),
                utxo(2, 1_000_000_000, spk(&payer), Some([3; 32])),
            ]),
            c,
            "TX_KAS_INPUT",
        ),
        (
            "an input twice",
            pay(vec![ok.clone(), ok.clone()]),
            c,
            "TX_DUPLICATE_INPUT",
        ),
        (
            "an input of 0 sompi",
            pay(vec![utxo(1, 0, spk(&payer), None)]),
            c,
            "TX_UTXO_VALUE",
        ),
        (
            "an input above the supply",
            pay(vec![utxo(1, MAX_SOMPI + 1, spk(&payer), None)]),
            c,
            "TX_UTXO_VALUE",
        ),
        (
            "inputs above the supply together",
            pay(vec![
                utxo(1, MAX_SOMPI, spk(&payer), None),
                utxo(2, 1, spk(&payer), None),
            ]),
            c,
            "TX_UTXO_VALUE",
        ),
        (
            "a non-standard change",
            FeePayment {
                change: ScriptPublicKey::from_vec(0, vec![0x51]),
                ..pay(vec![ok.clone()])
            },
            c,
            "TX_NONSTANDARD_CHANGE",
        ),
        (
            "a carrier below the minimum",
            pay(vec![ok.clone()]),
            c - 1,
            "TX_BELOW_MIN_KAS",
        ),
        (
            "too little for the carrier and the fee",
            pay(vec![utxo(1, c + fee - 1, spk(&payer), None)]),
            c,
            "TX_INSUFFICIENT_FUNDS",
        ),
        (
            "change below its minimum",
            pay(vec![utxo(1, c + fee + 1, spk(&payer), None)]),
            c,
            "TX_BELOW_MIN_KAS",
        ),
        (
            "a fee below the minimum relay fee",
            FeePayment {
                fee: 1,
                ..pay(vec![ok.clone()])
            },
            c,
            "TX_FEE_TOO_LOW",
        ),
        (
            "a mass above the standard cap",
            pay((0..300u16)
                .map(|i| Utxo {
                    outpoint: TransactionOutpoint::new(Hash::from_bytes([7; 32]), u32::from(i)),
                    entry: UtxoEntry::new(1_000_000_000, spk(&payer), START_DAA, false, None),
                })
                .collect()),
            c,
            "TX_MASS",
        ),
    ] {
        assert_eq!(code(&p, carrier), Err(expected), "{what}");
    }
    // The value refusals name the input, or the total.
    let err = |p: &FeePayment| build(Network::Testnet, &template, payer, 5, c, p).unwrap_err();
    use impulse_core::tx::TxError;
    // A carrier the fee pushes past u64::MAX is too little, not a wrapped sum (review round 1 of
    // the token helper), beside the carrier at the minimum, which the same input pays.
    assert_eq!(
        build(
            Network::Testnet,
            &template,
            payer,
            5,
            u64::MAX,
            &pay(vec![ok.clone()])
        )
        .unwrap_err(),
        TxError::InsufficientFunds {
            available: 10_000_000_000,
            needed: u64::MAX
        }
    );
    assert_eq!(
        err(&pay(vec![utxo(1, 0, spk(&payer), None)])),
        TxError::UtxoValue {
            input: Some(0),
            value: 0
        }
    );
    assert_eq!(
        err(&pay(vec![
            ok.clone(),
            utxo(2, MAX_SOMPI + 1, spk(&payer), None)
        ])),
        TxError::UtxoValue {
            input: Some(1),
            value: MAX_SOMPI + 1
        }
    );
    assert_eq!(
        err(&pay(vec![
            utxo(1, MAX_SOMPI, spk(&payer), None),
            utxo(2, 1, spk(&payer), None),
        ])),
        TxError::UtxoValue {
            input: None,
            value: MAX_SOMPI + 1
        }
    );
    // Controls: change of exactly its minimum; no change; a second input of the payer.
    assert_eq!(
        code(
            &pay(vec![utxo(1, c + fee + MIN_KAS_OUTPUT, spk(&payer), None)]),
            c
        ),
        Ok(())
    );
    assert_eq!(
        code(&pay(vec![utxo(1, c + fee, spk(&payer), None)]), c),
        Ok(())
    );
    assert_eq!(
        code(
            &pay(vec![ok.clone(), utxo(2, 1_000_000_000, spk(&payer), None)]),
            c
        ),
        Ok(())
    );
    // The token output: the template holding the owner, bound to covenant_id(input 0, output 0)
    // as the pinned consensus code computes it; the terms name that covenant.
    let ipst = build(
        Network::Testnet,
        &template,
        payer,
        5,
        c,
        &pay(vec![ok.clone()]),
    )
    .unwrap();
    let out0 = &ipst.transaction().outputs[0];
    assert_eq!(
        out0.script_public_key,
        template.script_public_key(&held_state(payer, 5)).unwrap()
    );
    // The fixed fields (spec/IPST.md, "Fixed transaction fields"; review round 1 of the token
    // helper), for one input and for two: every input at INPUT_SEQUENCE (0) with the P2PK
    // budget and no signature yet, lock time 0, the native subnetwork, no gas, no payload.
    let two = pay(vec![ok.clone(), utxo(2, 1_000_000_000, spk(&payer), None)]);
    for p in [pay(vec![ok.clone()]), two] {
        let built = build(Network::Testnet, &template, payer, 5, c, &p).unwrap();
        let tx = built.transaction();
        assert_eq!(INPUT_SEQUENCE, 0);
        assert_eq!(
            tx.inputs,
            p.inputs
                .iter()
                .map(|u| TransactionInput::new_with_compute_budget(
                    u.outpoint,
                    vec![],
                    INPUT_SEQUENCE,
                    P2PK_BUDGET
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            (tx.version, tx.lock_time, tx.gas, tx.payload.len()),
            (TX_VERSION_TOCCATA, 0, 0, 0)
        );
        assert_eq!(tx.subnetwork_id, SUBNETWORK_ID_NATIVE);
        // The binding names input 0, whatever the number of inputs.
        assert_eq!(tx.outputs[0].covenant.unwrap().authorizing_input, 0);
    }
    let mut unbound = out0.clone();
    unbound.covenant = None;
    let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        ok.outpoint,
        [(0u32, &unbound)].into_iter(),
    );
    assert_eq!(out0.covenant, Some(CovenantBinding::new(0, id)));
    let LegKind::Kcc20(token) = ipst.terms().terms().asset_leg.kind else {
        unreachable!()
    };
    assert_eq!(token.covenant_id, id.as_bytes());
    assert_eq!(ipst.terms().terms().trade_ref, GENESIS_TAG);
}

/// spec/CLI.md, "The genesis check", step 2: a genesis document that names an unpinned
/// template is refused by `ipst sign`, `ipst merge` and `submit`, beside the pinned control.
#[test]
fn the_genesis_check_refuses_an_unpinned_template() {
    let w = World::new(Network::Testnet);
    let art = unpinned_artifact();
    std::fs::write(w.path("u.json"), &art).unwrap();
    let unpinned = Kcc20Template::from_json(&art).unwrap();
    let spk = address_script(&p2pk_address(&w.seller.signer, w.network));
    let utxo = w.sim.state.borrow().utxos_at(&spk)[0].clone();
    let fee = FeePayment {
        inputs: vec![utxo],
        // Above the minimum relay fee and within the payer's default fee limit.
        fee: 300_000,
        change: spk,
    };
    let doc = |template: &Kcc20Template, name: &str| {
        let ipst = build(
            Network::Testnet,
            template,
            w.seller.signer,
            5,
            MIN_KCC20_OUTPUT,
            &fee,
        )
        .unwrap();
        let p = w.path(name);
        std::fs::write(&p, ipst.to_json()).unwrap();
        p
    };
    let bad = doc(&unpinned, "u.ipst");
    let o = w.path("o");
    let tpl = |args: Vec<String>| replace(&args, "--asset-template", s(&w.path("u.json")));
    for args in [
        tpl(genesis_sign_args(&w, &bad, &w.seller, &o)),
        tpl(merge_args(&w, &bad, &bad, &o)),
        tpl(w.submit_args(&bad)),
    ] {
        assert_eq!(w.no(&args), "CLI_TOKEN_TEMPLATE_UNPINNED", "{args:?}");
    }
    assert!(!o.exists());
    let good = doc(&w.asset, "p.ipst");
    w.go(&genesis_sign_args(&w, &good, &w.seller, &o));
}

/// `ipst raw` arguments.
fn raw_args(ipst: &Path, out: &Path) -> Vec<String> {
    ["ipst", "raw", "--ipst", s(ipst), "--out", s(out)]
        .map(String::from)
        .to_vec()
}

/// Review round 1 of the token helper (HIGH): terms are token genesis terms only with all four
/// marks (the tag, the two party keys nobody holds, Direct, expiry DAA 1); each mark changed
/// alone gives a trade's terms. The network is not a mark: a mainnet genesis stays a genesis,
/// which every command refuses.
#[test]
fn genesis_terms_need_all_four_marks() {
    use crate::token::is_genesis_terms;
    let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
    let genesis = genesis_terms(
        Network::Testnet,
        [7; 32],
        &template,
        random_xonly(),
        5,
        MIN_KCC20_OUTPUT,
    )
    .unwrap()
    .into_terms();
    assert!(is_genesis_terms(&genesis));
    let mut mainnet = genesis.clone();
    mainnet.network = Network::Mainnet;
    assert!(is_genesis_terms(&mainnet));
    type Edit = fn(&mut Terms);
    let edits: [(&str, Edit); 5] = [
        ("another trade_ref", |t| t.trade_ref[31] = 1),
        ("another seller_key", |t| t.seller_key = random_xonly()),
        ("another buyer_key", |t| t.buyer_key = random_xonly()),
        ("vault settlement", |t| {
            t.settlement_mode = SettlementMode::Vault
        }),
        ("another expiry", |t| t.expiry_daa = 2),
    ];
    for (what, edit) in edits {
        let mut t = genesis.clone();
        edit(&mut t);
        assert!(!is_genesis_terms(&t), "{what}");
    }
}

/// Review round 1 of the token helper (HIGH): whoever drafts a trade chooses its `trade_ref`, so
/// a trade whose terms carry the genesis tag beside the parties' own keys is an ordinary trade.
/// On testnet and on mainnet, a vault trade with the tag is funded, settled and refunded, and a
/// Direct trade with the tag is named by a cancellation and settled, through `fund build`,
/// `settle build`, `refund build`, `direct cancel build --for-ipst`, `ipst sign`, `ipst merge`,
/// `ipst raw` and `submit`, and the summary shows the tag. Beside them, the genesis controls: a
/// genesis is still a genesis to `ipst sign` on testnet and refused by it on mainnet.
#[test]
fn a_trade_carrying_the_genesis_tag_is_an_ordinary_trade() {
    for network in [Network::Testnet, Network::Mainnet] {
        let w = World::new(network);
        // Controls: a genesis of the seller's, built directly (token mint build is testnet only).
        let spk = address_script(&p2pk_address(&w.seller.signer, network));
        let utxo: Utxo = w.sim.state.borrow().utxos_at(&spk)[0].clone();
        let fee = FeePayment {
            inputs: vec![utxo],
            fee: 300_000,
            change: spk,
        };
        let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
        let genesis = build(
            network,
            &template,
            w.seller.signer,
            5,
            MIN_KCC20_OUTPUT,
            &fee,
        )
        .unwrap();
        let doc = w.path("genesis.ipst");
        std::fs::write(&doc, genesis.to_json()).unwrap();
        let sign = genesis_sign_args(&w, &doc, &w.seller, &w.path("genesis.signed"));
        if network == Network::Testnet {
            assert_eq!(field(&w.go(&sign), "ipst"), "token genesis");
        } else {
            assert_eq!(w.no(&sign), "CLI_TOKEN_TESTNET_ONLY");
        }
        let tagged = |t: &mut Terms| t.trade_ref = GENESIS_TAG;
        // Vault, authority, KAS cash: both fundings (fund build, ipst sign, submit), then the
        // settle, signed by the authority, merged with the unsigned copy, written raw, submitted.
        let vault = w.terms("vault.json", Mode::Authority, tagged);
        w.fund(&vault, LegIndex::Asset);
        w.fund(&vault, LegIndex::Cash);
        let settle = w.path("settle.ipst");
        w.go(&w.settle_args(&vault, &w.authority, &settle));
        let signed = w.path("settle.signed");
        let out = w.go(&w.sign_args(&settle, &w.authority, &signed));
        assert_eq!(field(&out, "ipst"), "settle", "{network:?}");
        assert_eq!(field(&out, "trade_ref"), hex(&GENESIS_TAG));
        let merged = w.path("settle.merged");
        w.go(&merge_args(&w, &signed, &settle, &merged));
        w.go(&raw_args(&merged, &w.path("settle.tx")));
        let out = w.go(&w.submit_args(&merged));
        assert_eq!(field(&out, "submitted"), field(&out, "txid"));
        // A tagged trade refunded: its KAS cash, by the authority.
        let refund = w.terms("refund.json", Mode::Authority, tagged);
        w.fund(&refund, LegIndex::Cash);
        let r = w.path("refund.ipst");
        let out = w.go(&w.refund_args(&refund, "cash", "authority", &w.authority, &r));
        assert!(field(&out, "ipst").starts_with("refund cash by authority"));
        w.sign_submit(&r, &w.authority);
        // Direct, KAS cash: a cancellation names the tagged Direct transaction; each party signs
        // its own copy, the copies are merged, written raw and submitted.
        let direct = w.terms("direct.json", Mode::Direct, tagged);
        let tx = w.path("direct.ipst");
        w.go(&w.settle_args(&direct, &w.buyer, &tx));
        let out = w.go(&with(
            &cancel_args(&direct, "buyer", &w.buyer, &w.path("cancel.ipst")),
            &["--for-ipst", s(&tx)],
        ));
        assert!(field(&out, "cancels").starts_with("Direct transaction "));
        let (a, b, m) = (w.path("d.s"), w.path("d.b"), w.path("d.m"));
        w.go(&w.sign_args(&tx, &w.seller, &a));
        let out = w.go(&w.sign_args(&tx, &w.buyer, &b));
        assert_eq!(field(&out, "ipst"), "direct");
        w.go(&merge_args(&w, &a, &b, &m));
        w.go(&raw_args(&m, &w.path("direct.tx")));
        let out = w.go(&w.submit_args(&m));
        assert_eq!(field(&out, "submitted"), field(&out, "txid"));
    }
}

/// Review round 1 of the token helper (LOW): the genesis terms of a fixed token, field by field
/// as the table of spec/CLI.md ("The token genesis terms") and the layout of spec/ENCODING.md
/// give them, and their terms hash, both computed independently with Python's hashlib. The owner
/// is the party-key derivation of spec/CLI.md for the label `owner`, also computed in Python: a
/// public key nobody holds a secret for. Every row of the table is pinned, so a change to any of
/// them, which would also strand the genesis IPSTs an earlier build wrote, fails here.
#[test]
fn the_genesis_terms_of_a_fixed_token_are_a_known_answer() {
    let template = Kcc20Template::from_json(ASSET_JSON).unwrap();
    assert_eq!(
        (
            hex(&template.template_hash()),
            template.prefix_len(),
            template.suffix_len()
        ),
        (
            "2a5713a61a2c350c9f76583746d95054ef6bb4160e1c338239249549929b9c9c".to_string(),
            1,
            1460
        )
    );
    let owner = unhex("76c01b325006e6ef9c8afe7bfc485383975a33579d904836e259b970dee368a9");
    let v = genesis_terms(
        Network::Testnet,
        [7; 32],
        &template,
        owner,
        5,
        MIN_KCC20_OUTPUT,
    )
    .unwrap();
    let expected = concat!(
        // version 1
        "01",
        // network: testnet
        "01",
        // settlement_mode: Direct
        "00",
        // nonce 0
        "0000000000000000",
        // seller_key
        "6d755c66e18318a2ac4b2a3f0c0d517d1613dffa6ccfe5280efb000fab816b54",
        // buyer_key
        "b2196ec23a3f518d771a97f3fd2fce494b3e8e1b0624c7ba226adafb5bd05965",
        // authority_key: none
        "00",
        // asset_leg: KCC-20, covenant ID
        "010707070707070707070707070707070707070707070707070707070707070707",
        // template hash
        "2a5713a61a2c350c9f76583746d95054ef6bb4160e1c338239249549929b9c9c",
        // prefix 1, suffix 1460, 5 units
        "01000000b40500000500000000000000",
        // cash_leg: KAS, the 2 KAS carrier
        "0000c2eb0b00000000",
        // buyer_delivery: KCC-20 owner, PUBKEY
        "0100",
        // the owner
        "76c01b325006e6ef9c8afe7bfc485383975a33579d904836e259b970dee368a9",
        // seller_proceeds: version 0, 34 bytes, P2PK
        "0000002200000020",
        // seller_key and OP_CHECKSIG
        "6d755c66e18318a2ac4b2a3f0c0d517d1613dffa6ccfe5280efb000fab816b54ac",
        // seller_refund: KCC-20 owner, PUBKEY
        "0100",
        // seller_key
        "6d755c66e18318a2ac4b2a3f0c0d517d1613dffa6ccfe5280efb000fab816b54",
        // buyer_refund: version 0, 34 bytes, P2PK
        "0000002200000020",
        // buyer_key and OP_CHECKSIG
        "b2196ec23a3f518d771a97f3fd2fce494b3e8e1b0624c7ba226adafb5bd05965ac",
        // earliest_daa: none
        "00",
        // expiry_daa 1
        "0100000000000000",
        // funding_mode: revocable
        "00",
        // trade_ref: the tag
        "496d70756c73652f746f6b656e2d67656e657369732f76310000000000000000",
    );
    assert_eq!(hex(v.canonical()), expected);
    assert_eq!(
        hex(&v.terms_hash()),
        "be7e38982a5b4a848f4e43e8fd2eae7fa8ad23f1de75ec1dd7e649ea1df28fa0"
    );
}

/// Review round 1 of the token helper (LOW): without `--change`, the change goes to `--pay-from`
/// (spec/CLI.md, "token mint build", check 6) even when the owner is another key. The payer
/// signs it with no `CLI_IPST_CHANGE_NOT_MINE`, and the token still goes to the owner.
#[test]
fn the_change_goes_to_the_payer_by_default() {
    let w = World::new(Network::Testnet);
    let unsigned = w.path("for-buyer.ipst");
    let built = w.go(&mint_args(
        &w,
        LegIndex::Cash,
        &w.buyer.signer,
        &w.authority,
        2,
        &unsigned,
    ));
    assert_eq!(field(&built, "owner"), hex(&w.buyer.signer));
    assert!(
        field(&built, "change").ends_with(&format!("{} (pay to x-only key)", w.addr(&w.authority))),
        "{built}"
    );
    let doc = Ipst::from_json(&std::fs::read_to_string(&unsigned).unwrap()).unwrap();
    let outputs = &doc.transaction().outputs;
    assert_eq!(
        outputs[0].script_public_key,
        w.cash
            .script_public_key(&held_state(w.buyer.signer, 2))
            .unwrap()
    );
    assert_eq!(
        outputs[1].script_public_key,
        address_script(&p2pk_address(&w.authority.signer, w.network))
    );
    // The payer signs with no --change, and the token reaches its owner.
    let signed = w.path("for-buyer.signed");
    let args = replace(
        &genesis_sign_args(&w, &unsigned, &w.authority, &signed),
        "--asset-template",
        &w.tpl(LegIndex::Cash),
    );
    assert_eq!(field(&w.go(&args), "pending"), "complete");
    let out = w.go(&replace(
        &w.submit_args(&signed),
        "--asset-template",
        &w.tpl(LegIndex::Cash),
    ));
    assert_eq!(field(&out, "submitted"), field(&built, "txid"));
    let listed = w.go(&list_args(
        &w,
        LegIndex::Cash,
        &w.buyer.signer,
        &field(&built, "covenant"),
        2,
    ));
    assert_eq!(field(&listed, "token"), field(&built, "token"));
}

/// Review round 1 of the token helper (LOW): a genesis of two payer inputs, minting exactly one
/// unit (the smallest amount), binds the token to input 0, with the covenant ID of input 0's
/// outpoint; the payer, a fresh throwaway key with no role, signs it alone, and the fake node's
/// consensus covenant check and script engine accept it.
#[test]
fn a_genesis_of_two_inputs_binds_input_0() {
    let w = World::new(Network::Testnet);
    let payer = key_file();
    let spk = address_script(&p2pk_address(&payer.signer, w.network));
    for _ in 0..2 {
        w.sim
            .state
            .borrow_mut()
            .add_utxo(spk.clone(), 130_000_000, None);
    }
    let unsigned = w.path("two.ipst");
    let built = w.go(&mint_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &payer,
        1,
        &unsigned,
    ));
    assert_eq!(field(&built, "amount"), "1 token units");
    let doc = Ipst::from_json(&std::fs::read_to_string(&unsigned).unwrap()).unwrap();
    let tx = doc.transaction();
    assert_eq!(tx.inputs.len(), 2);
    let mut unbound = tx.outputs[0].clone();
    unbound.covenant = None;
    let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        tx.inputs[0].previous_outpoint,
        [(0u32, &unbound)].into_iter(),
    );
    assert_eq!(tx.outputs[0].covenant, Some(CovenantBinding::new(0, id)));
    assert_eq!(field(&built, "covenant"), hex(&id.as_bytes()));
    let signed = w.path("two.signed");
    let out = w.go(&genesis_sign_args(&w, &unsigned, &payer, &signed));
    assert_eq!(field(&out, "signed"), "input 0, input 1");
    let out = w.go(&w.submit_args(&signed));
    assert_eq!(field(&out, "submitted"), field(&built, "txid"));
    let listed = w.go(&list_args(
        &w,
        LegIndex::Asset,
        &w.seller.signer,
        &hex(&id.as_bytes()),
        1,
    ));
    assert_eq!(
        field(&listed, "token"),
        format!("{}:0:1", field(&built, "txid"))
    );
}
