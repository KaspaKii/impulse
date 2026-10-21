// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Linked trades in the watcher (I22, spec/V2.md 17.9, spec/WATCH.md "Linked trades"): both
//! trades of a sheet watched as ordinary trades, one `linked` event for each change of the pair's
//! phase, the early-return flag, a reorg moving the phase back, restart and eviction not moving it,
//! and the sheet file. The pair comes from the frozen linked vector `03-kas-for-kas` (public keys
//! only). No test holds a key: a vault spend's signature push is stand-in bytes, and the fake
//! source plays consensus. Each refusal has an accepted control beside it.

use super::phase2::{code_of, run_args, TempDir};
use super::*;
use crate::entry::SETTLE_TAG_V2;
use crate::files::{hex, parse_sheet_file};
use crate::run::prepare;
use crate::watcher::Retention;
use impulse_core::linked::{Role, ValidatedLinked};
use impulse_core::v2::VaultV2;

const VECTOR: &str = include_str!("../../../tests/vectors/linked/03-kas-for-kas.json");

fn sheet() -> ValidatedLinked {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    ValidatedLinked::decode(&unhex(v["canonical"].as_str().unwrap())).unwrap()
}

fn sheet_file(hash: Option<&str>) -> String {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    json!({
        "sheet": v["sheet"],
        "canonical": v["canonical"],
        "linked_hash": hash.map_or(v["linked_hash"].clone(), |h| json!(h)),
    })
    .to_string()
}

struct Pair {
    linked: ValidatedLinked,
    open: [VaultV2; 2],
    ret: [VaultV2; 2],
    open_amounts: [u64; 2],
    ret_amounts: [u64; 2],
}

fn pair() -> Pair {
    let linked = sheet();
    let vault = |role, leg| VaultV2::instantiate_existing(linked.terms(role), leg).unwrap();
    let amounts = |role| {
        let t = linked.terms(role).terms();
        [t.legs[0].asset.amount, t.legs[1].asset.amount]
    };
    Pair {
        open: [vault(Role::Opening, 0), vault(Role::Opening, 1)],
        ret: [vault(Role::Return, 0), vault(Role::Return, 1)],
        open_amounts: amounts(Role::Opening),
        ret_amounts: amounts(Role::Return),
        linked,
    }
}

/// `settle(authSig, lots)` of a v2 vault.
fn settle_v2(v: &VaultV2, value: u64) -> In {
    In {
        sig: push_all(&[&SIG, &[1], &SETTLE_TAG_V2, v.redeem_script()]),
        spends: utxo(value, v.script_public_key()),
    }
}

/// `refund(s, signerLeg)` of a v2 vault.
fn refund_v2(v: &VaultV2, value: u64) -> In {
    In {
        sig: push_all(&[&SIG, &[0], &crate::entry::REFUND_TAG_V2, v.redeem_script()]),
        spends: utxo(value, v.script_public_key()),
    }
}

fn fund(salt: u64, vaults: &[VaultV2; 2], amounts: [u64; 2]) -> AcceptedTransaction {
    tx(
        salt,
        vec![plain_in()],
        vec![
            (amounts[0], vaults[0].script_public_key()),
            (amounts[1], vaults[1].script_public_key()),
        ],
    )
}

fn settle(salt: u64, vaults: &[VaultV2; 2], amounts: [u64; 2]) -> AcceptedTransaction {
    tx(
        salt,
        vec![
            settle_v2(&vaults[0], amounts[0]),
            settle_v2(&vaults[1], amounts[1]),
            plain_in(),
        ],
        vec![(1_000, stranger())],
    )
}

fn mainnet_watcher(depth: u64) -> Watcher {
    Watcher::new(Network::Mainnet, FinalityPolicy::new(depth).unwrap())
}

/// The `linked` events of `events`, as `<phase>` or `<phase> <code>`.
fn phases(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter(|e| matches!(e, Event::Linked { .. }))
        .map(|e| {
            let j = e.to_json();
            match j.get("code") {
                Some(c) => format!("{} {}", j["phase"].as_str().unwrap(), c.as_str().unwrap()),
                None => j["phase"].as_str().unwrap().to_string(),
            }
        })
        .collect()
}

#[tokio::test]
async fn an_open_and_a_return_move_the_pair_through_its_phases_one_event_each() {
    let p = pair();
    let mut w = mainnet_watcher(10);
    let [wo, wr] = w.add_linked(&p.linked).unwrap();
    assert_eq!(wo.trade, TradeId(p.linked.terms_hash(Role::Opening)));
    assert_eq!(wr.trade, TradeId(p.linked.terms_hash(Role::Return)));
    assert_ne!(wo.trade, wr.trade);
    let node = Node::new();

    // Funding the opening is a funding of each leg and no change of phase.
    let e = accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    assert_eq!(e.len(), 2, "two funded events");
    assert!(phases(&e).is_empty());

    // The opening settles: one linked event after the two settled events.
    let open_settle = settle(2, &p.open, p.open_amounts);
    let open_txid = id(&open_settle);
    let e = accept_one(&mut w, &node, open_settle).await;
    assert_eq!(e.len(), 3);
    assert_eq!(phases(&e), ["opening_settled"]);
    let j = e[2].to_json();
    assert_eq!(j["event"], json!("linked"));
    assert_eq!(j["linked"], json!(hex(&p.linked.linked_hash())));
    assert_eq!(j["opening"], json!(wo.trade.to_string()));
    assert_eq!(j["return"], json!(wr.trade.to_string()));
    assert_eq!(
        j["txid"],
        json!(open_txid.to_string()),
        "the transaction that moved it"
    );
    assert!(j.get("code").is_none());

    // The return funds after it: no early flag, no change of phase.
    let e = accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    assert!(phases(&e).is_empty());

    // The return settles.
    let ret_settle = settle(4, &p.ret, p.ret_amounts);
    let ret_txid = id(&ret_settle);
    let e = accept_one(&mut w, &node, ret_settle).await;
    assert_eq!(phases(&e), ["return_settled"]);
    assert_eq!(e[2].to_json()["txid"], json!(ret_txid.to_string()));
    // A poll with nothing new reports nothing.
    node.mine(vec![]);
    assert!(w.poll(&node.chain).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_return_funded_before_the_opening_settles_is_flagged() {
    let p = pair();
    let mut w = mainnet_watcher(10);
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    // Control: a return funding that is not exact (a stray amount) is not a start of the return.
    let e = accept_one(
        &mut w,
        &node,
        tx(2, vec![plain_in()], vec![(7, p.ret[0].script_public_key())]),
    )
    .await;
    assert!(phases(&e).is_empty());
    // An exact return funding while the opening is open.
    let e = accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    assert_eq!(phases(&e), ["opening_open WATCH_LINK_RETURN_EARLY"]);
    let flagged = e.last().unwrap();
    assert_eq!(flagged.code(), Some("WATCH_LINK_RETURN_EARLY"));
    // Settling the opening clears the flag.
    let e = accept_one(&mut w, &node, settle(4, &p.open, p.open_amounts)).await;
    assert_eq!(phases(&e), ["opening_settled"]);
    assert!(e.last().unwrap().code().is_none());
}

#[tokio::test]
async fn a_return_settle_seen_alone_while_the_opening_is_open_is_flagged() {
    let p = pair();
    let mut w = mainnet_watcher(10);
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    // Only the return's settle is seen (its funding never was): it still started the return.
    let e = accept_one(&mut w, &node, settle(1, &p.ret, p.ret_amounts)).await;
    assert_eq!(phases(&e), ["return_settled WATCH_LINK_RETURN_EARLY"]);
}

#[tokio::test]
async fn a_reorg_of_the_opening_settle_moves_the_phase_back() {
    let p = pair();
    let mut w = mainnet_watcher(1_000);
    w.add_linked(&p.linked).unwrap();
    let source = started(&mut w).await;
    source.extend(block(2), 101, vec![fund(1, &p.open, p.open_amounts)]);
    w.poll(&source).await.unwrap();
    source.extend(block(3), 102, vec![settle(2, &p.open, p.open_amounts)]);
    let e = w.poll(&source).await.unwrap();
    assert_eq!(phases(&e), ["opening_settled"]);
    // A competing branch from block 2 without the settle takes over.
    source.add_block(block(12), block(2), 102, vec![]);
    source.add_block(block(13), block(12), 103, vec![]);
    source.set_sink(block(13));
    let e = w.poll(&source).await.unwrap();
    assert_eq!(phases(&e), ["opening_open"]);
    assert!(
        e.iter().any(|x| matches!(x, Event::Reorg { .. })),
        "the reorg of each settled leg is reported too"
    );
}

#[tokio::test]
async fn a_refund_ends_either_trade_without_the_other_settling() {
    let p = pair();
    // The opening: one vault refunded.
    let mut w = mainnet_watcher(10);
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    let refund = tx(2, vec![refund_v2(&p.open[0], p.open_amounts[0])], vec![]);
    let e = accept_one(&mut w, &node, refund).await;
    assert_eq!(phases(&e), ["opening_refunded"]);
    // The return after a refunded opening is flagged when it funds.
    let e = accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    assert_eq!(phases(&e), ["opening_refunded WATCH_LINK_RETURN_EARLY"]);

    // The return: one vault refunded after the opening settled.
    let mut w = mainnet_watcher(10);
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    accept_one(&mut w, &node, settle(2, &p.open, p.open_amounts)).await;
    accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    let refund = tx(4, vec![refund_v2(&p.ret[1], p.ret_amounts[1])], vec![]);
    let e = accept_one(&mut w, &node, refund).await;
    assert_eq!(phases(&e), ["return_refunded"]);
}

#[tokio::test]
async fn a_restart_reads_the_phase_from_the_state_and_reports_only_what_changes_after() {
    let p = pair();
    let mut w = mainnet_watcher(1_000);
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    let e = accept_one(&mut w, &node, settle(2, &p.open, p.open_amounts)).await;
    assert_eq!(phases(&e), ["opening_settled"]);
    // Restart: the state goes into a new watcher, the sheet is added again.
    let state = w.into_state();
    let mut w = Watcher::with_state(Network::Mainnet, FinalityPolicy::new(1_000).unwrap(), state);
    w.add_linked(&p.linked).unwrap();
    node.mine(vec![]);
    assert!(
        phases(&w.poll(&node.chain).await.unwrap()).is_empty(),
        "no repeat of opening_settled"
    );
    accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    let e = accept_one(&mut w, &node, settle(4, &p.ret, p.ret_amounts)).await;
    assert_eq!(phases(&e), ["return_settled"]);
}

#[tokio::test]
async fn eviction_of_final_acceptances_does_not_move_the_phase_back() {
    let p = pair();
    let finality = FinalityPolicy::new(2).unwrap();
    let mut w = Watcher::new(Network::Mainnet, finality);
    w.set_retention(Retention::new(5, finality).unwrap());
    w.add_linked(&p.linked).unwrap();
    let node = Node::new();
    accept_one(&mut w, &node, fund(1, &p.open, p.open_amounts)).await;
    let e = accept_one(&mut w, &node, settle(2, &p.open, p.open_amounts)).await;
    assert_eq!(phases(&e), ["opening_settled"]);
    // Mine until the settle is final and evicted; the phase never moves.
    for _ in 0..12 {
        node.mine(vec![]);
        let e = w.poll(&node.chain).await.unwrap();
        assert!(phases(&e).is_empty(), "{e:?}");
    }
    assert!(w.accepted_len() <= 1, "the settle is gone from the state");
    // The return, funded after the eviction, is not flagged early.
    let e = accept_one(&mut w, &node, fund(3, &p.ret, p.ret_amounts)).await;
    assert!(phases(&e).is_empty(), "{e:?}");
}

#[test]
fn a_link_is_added_once_and_on_its_network() {
    let p = pair();
    let mut w = mainnet_watcher(10);
    w.add_linked(&p.linked).unwrap();
    assert_eq!(
        code_of(w.add_linked(&p.linked)),
        "WATCH_TRADE_DUPLICATE",
        "the same sheet twice"
    );
    // One trade already watched on its own: the link adds the other and follows both.
    let mut w = mainnet_watcher(10);
    w.add_trade(p.linked.terms(Role::Opening).clone()).unwrap();
    assert!(w.add_linked(&p.linked).is_ok());
    // The wrong network.
    let mut t = Watcher::new(Network::Testnet, FinalityPolicy::new(10).unwrap());
    assert_eq!(code_of(t.add_linked(&p.linked)), "WATCH_NETWORK_MISMATCH");
}

#[test]
fn a_sheet_file_is_read_as_a_terms_file_is() {
    let p = pair();
    let ok = parse_sheet_file("sheet", &sheet_file(None)).unwrap();
    assert_eq!(ok.linked_hash(), p.linked.linked_hash());
    assert_eq!(
        code_of(parse_sheet_file(
            "sheet",
            &sheet_file(Some(&"00".repeat(32)))
        )),
        "WATCH_TERMS_FILE_INCONSISTENT"
    );
    let bad = |text: String| code_of(parse_sheet_file("sheet", &text));
    assert_eq!(bad("not json".into()), "WATCH_TERMS_FILE_INVALID");
    assert_eq!(bad("{}".into()), "WATCH_TERMS_FILE_INVALID");
    let mut v: serde_json::Value = serde_json::from_str(&sheet_file(None)).unwrap();
    v["extra"] = json!(1);
    assert_eq!(bad(v.to_string()), "WATCH_TERMS_FILE_INVALID");
    // A terms file is not a sheet file.
    let mut v: serde_json::Value = serde_json::from_str(&sheet_file(None)).unwrap();
    v["canonical"] = json!("02");
    assert_eq!(bad(v.to_string()), "WATCH_TERMS_FILE_INVALID");
    // A canonical sheet that fails a sheet check: the opening carries a trade_ref.
    let mut s = p.linked.sheet().clone();
    s.opening.trade_ref = [1; 32];
    let mut v: serde_json::Value = serde_json::from_str(&sheet_file(None)).unwrap();
    v["canonical"] = json!(hex(&s.encode().unwrap()));
    v["linked_hash"] = json!(hex(&s.linked_hash().unwrap()));
    assert_eq!(bad(v.to_string()), "WATCH_TERMS_FILE_INVALID");
}

#[test]
fn the_binary_adds_both_trades_of_a_linked_sheet() {
    let dir = TempDir::new();
    let p = pair();
    let sheet = dir.file("sheet.json");
    std::fs::write(&sheet, sheet_file(None)).unwrap();
    let mut args = run_args(&dir);
    args.trades.clear();
    args.linked = vec![sheet.clone()];
    let prepared = prepare(&args).unwrap();
    for role in [Role::Opening, Role::Return] {
        assert!(prepared
            .watcher
            .trades()
            .terms(&TradeId(p.linked.terms_hash(role)))
            .is_some());
    }
    drop(prepared);
    // A bad sheet file refuses the run before the state file is made.
    let mut bad = run_args(&dir);
    bad.state = dir.file("other-state.json");
    bad.trades.clear();
    let broken = dir.file("broken.json");
    std::fs::write(&broken, "{}").unwrap();
    bad.linked = vec![broken];
    assert_eq!(
        prepare(&bad).err().unwrap().code(),
        "WATCH_TERMS_FILE_INVALID"
    );
    assert!(!bad.state.exists());
    // On the wrong network.
    let mut wrong = run_args(&dir);
    wrong.network = crate::cli::NetworkArg::Testnet;
    wrong.state = dir.file("wrong-state.json");
    wrong.trades.clear();
    wrong.linked = vec![sheet];
    assert_eq!(
        prepare(&wrong).err().unwrap().code(),
        "WATCH_NETWORK_MISMATCH"
    );
}
