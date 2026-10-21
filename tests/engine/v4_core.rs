// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The host side of the hashed-terms statement for the engine tests (spec/V3-ZK.md 22.9): the
//! journal the vault script builds, the harness terms as terms v4, and the shadow check of the
//! differential test (`shadow_check`): every run of a v1 vault input in the v4d_* binaries is also
//! put through the statement of terms-core, which must accept exactly when v1's script accepts.
//! The model of the v4 vault input is the statement plus the script requires that read the
//! transaction beyond the view: `[T2]`/`[T3]` against its length and the
//! covenant ID of every input (`[T10]`, `[T11]`, spec/V3-ZK.md 22.15, `covenant_rule`).

#![allow(dead_code)]

use super::*;
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};
use terms_core::codec as tc;
use terms_core::hashes as th;
use terms_core::journal::{Item, Journal, Mode as JMode};

/// The arguments of an entry call that enter J (the script hashes them in).
#[derive(Clone, Copy, Debug)]
pub enum Entry {
    Settle {
        n_in: usize,
        n_out: usize,
        cov_a: [u8; 32],
        cov_c: [u8; 32],
    },
    Refund {
        leg: u8,
        signer: [u8; 32],
        n_in: usize,
        n_out: usize,
        cov: [u8; 32],
    },
}

fn spk_hash(spk: &kaspa_consensus_core::tx::ScriptPublicKey) -> [u8; 32] {
    th::sha256(&spk_bytes(spk))
}

/// The journal the vault script builds (spec 22.3), from the transaction and its UTXO entries.
pub fn journal_of(
    tx: &Transaction,
    entries: &[UtxoEntry],
    idx: usize,
    entry: Entry,
    commit: [u8; 32],
    authority: [u8; 32],
) -> Journal {
    let (mode, n_in, n_out) = match entry {
        Entry::Settle { n_in, n_out, .. } | Entry::Refund { n_in, n_out, .. } => (
            if matches!(entry, Entry::Settle { .. }) {
                JMode::Settle
            } else {
                JMode::Refund
            },
            n_in,
            n_out,
        ),
    };
    let cov_of = |c: Option<kaspa_consensus_core::Hash>| c.map_or([0u8; 32], |h| h.as_bytes());
    let count = |cov: [u8; 32]| {
        entries
            .iter()
            .filter(|e| e.covenant_id.map(|h| h.as_bytes()) == Some(cov) && cov != [0; 32])
            .count() as u8
    };
    let inputs = (0..n_in)
        .map(|i| Item {
            value: entries[i].amount,
            spk_hash: spk_hash(&entries[i].script_public_key),
            cov: cov_of(entries[i].covenant_id),
        })
        .collect();
    let outputs = (0..n_out)
        .map(|k| Item {
            value: tx.outputs[k].value,
            spk_hash: spk_hash(&tx.outputs[k].script_public_key),
            cov: cov_of(tx.outputs[k].covenant.map(|c| c.covenant_id)),
        })
        .collect();
    let (leg, signer, cov_a, cov_c, count_a, count_c) = match entry {
        Entry::Settle { cov_a, cov_c, .. } => (
            idx as u8,
            [0u8; 32],
            cov_a,
            cov_c,
            count(cov_a),
            count(cov_c),
        ),
        Entry::Refund {
            leg, signer, cov, ..
        } => (leg, signer, cov, [0u8; 32], count(cov), 0),
    };
    Journal {
        mode,
        vault_spk: spk_bytes(&entries[idx].script_public_key)
            .try_into()
            .expect("37-byte vault scriptPubKey"),
        commit,
        authority,
        leg,
        input_index: idx as u8,
        locktime: tx.lock_time,
        signer,
        cov_a,
        cov_c,
        count_a,
        count_c,
        inputs,
        outputs,
    }
}

/// The harness terms as terms v4 (spec 22.2).
pub fn core_terms(t: &Terms, blind: [u8; 32]) -> tc::Terms {
    assert!(t.has_authority, "terms v4 always name an authority");
    let leg = |kind: u8, tr: TemplateRef, amount: i64| match kind {
        CASH_KAS => tc::Leg::Kas {
            amount: amount as u64,
        },
        CASH_EXTERNAL => tc::Leg::External {
            amount: amount as u64,
        },
        _ => tc::Leg::Kcc20 {
            cov: tr.cov.as_bytes(),
            template_hash: tr.hash,
            prefix_len: tr.prefix_len as u32,
            suffix_len: tr.suffix_len as u32,
            amount: amount as u64,
        },
    };
    let owner = |o: Owner| tc::Dest::Owner {
        id_type: o.id_type,
        id: o.id,
    };
    let kas = |spk: &[u8]| tc::Dest::Kas {
        version: u16::from_be_bytes([spk[0], spk[1]]),
        script: spk[2..].to_vec(),
    };
    let cash_dest = |o: Owner, spk: &[u8]| match t.cash_kind {
        CASH_KAS => kas(spk),
        CASH_EXTERNAL => tc::Dest::OffChain,
        _ => owner(o),
    };
    tc::Terms {
        network: t.network,
        mode: tc::MODE_VAULT,
        nonce: u64::from_le_bytes(t.nonce),
        seller: t.seller_key,
        buyer: t.buyer_key,
        authority: Some(t.authority_key),
        asset: leg(CASH_KCC20, t.asset, t.amount_a),
        cash: leg(t.cash_kind, t.cash, t.amount_b),
        buyer_delivery: owner(t.buyer_delivery),
        seller_proceeds: cash_dest(t.seller_proceeds, &t.seller_proceeds_spk),
        seller_refund: owner(t.seller_refund),
        buyer_refund: cash_dest(t.buyer_refund, &t.buyer_refund_spk),
        earliest: t.has_earliest.then_some(t.earliest_daa as u64),
        expiry: t.expiry_daa as u64,
        funding: t.funding_mode,
        blind,
        trade_ref: t.trade_ref,
    }
}

// =============================================================================================
// The differential: terms-core against the v1 script
// =============================================================================================

/// True in a test binary whose name starts with `v4d_`: the shared v1 suites (settle.rs,
/// refund.rs, ...) run unchanged, and every run of a v1 vault input is also put through the
/// statement of terms-core (spec/V3-ZK.md 22.9, `v4_differential_agrees_with_v1`).
pub fn shadow_by_default() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .is_some_and(|n| n.starts_with("v4d_"))
}

fn log(line: &str) {
    if let Some(path) = std::env::var_os("IMPULSE_V4_SHADOW_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// The `[T10]` (settle) and `[T11]` (refund), on the host: at most eight inputs, the
/// escrow slots carry the covenant the layout names, every other input none.
pub fn covenant_rule(entries: &[UtxoEntry], entry: Entry) -> Option<terms_core::Refusal> {
    let tag = match entry {
        Entry::Settle { .. } => "T10",
        Entry::Refund { .. } => "T11",
    };
    let refuse = Some(terms_core::Refusal {
        code: "ZK_H_SHAPE",
        tag,
    });
    if entries.len() > 8 {
        return refuse;
    }
    for (i, e) in entries.iter().enumerate() {
        let want = match entry {
            Entry::Settle {
                n_in, cov_a, cov_c, ..
            } => {
                let asset_slot = if n_in == 2 { 1 } else { 2 };
                if i == asset_slot {
                    cov_a
                } else if i == 3 {
                    cov_c
                } else {
                    [0; 32]
                }
            }
            Entry::Refund { n_in, cov, .. } if i == 1 && n_in == 2 => cov,
            Entry::Refund { .. } => [0; 32],
        };
        if e.covenant_id.map_or([0; 32], |h| h.as_bytes()) != want {
            return refuse;
        }
    }
    None
}

fn run_plain(spec: &TxSpec, w: &World, idx: usize) -> bool {
    let (tx, entries) = spec.build(w);
    execute(&tx, &entries, idx).result.is_ok()
}

/// The statement of terms-core for the v1 vault input `idx` of `spec`: `None` when the input is
/// not a v1 vault spend or the terms are outside the v4 domain (the reason is logged).
fn core_verdict(spec: &TxSpec, w: &World, idx: usize) -> Option<Result<(), terms_core::Refusal>> {
    let (vault, settle, named) = match &spec.inputs[idx].spend {
        Spend::Settle { vault, .. } => (vault, true, [0u8; 32]),
        Spend::Refund { vault, named, .. } => (vault, false, *named),
        _ => return None,
    };
    let skip = |why: &str| {
        log(&format!("skipped {why}"));
        None
    };
    if w.is_v3() {
        return skip("v3 terms");
    }
    if !w.terms.has_authority {
        return skip("no authority (terms v4 require one)");
    }
    let core = core_terms(&w.terms, [0xBD; 32]);
    if let Err(r) = terms_core::structure::validate(&core, false) {
        return skip(&format!("terms outside v4: {}", r.code));
    }
    // the canonical decoder of terms v4 is stricter than v1's structure checks (an unknown funding
    // mode is refused at decode): such terms are outside the v4 domain and cannot be committed
    if let Err(r) = tc::Terms::decode(&core.encode()) {
        return skip(&format!("terms v4 do not decode: {}", r.code));
    }
    let leg: u8 = if vault.script_hash() == w.asset_vault.script_hash() {
        0
    } else {
        1
    };
    let (tx, entries) = spec.build(w);
    let asset_cov = w.terms.asset.cov.as_bytes();
    let cash_cov = if w.terms.cash_kind == CASH_KCC20 {
        w.terms.cash.cov.as_bytes()
    } else {
        [0; 32]
    };
    let entry = if settle {
        let (n_in, n_out) = match w.terms.cash_kind {
            CASH_KAS => (3, 3),
            CASH_KCC20 => (4, 4),
            _ => (2, 2),
        };
        Entry::Settle {
            n_in,
            n_out,
            cov_a: asset_cov,
            cov_c: cash_cov,
        }
    } else {
        let kas_cash = leg == 1 && w.terms.cash_kind == CASH_KAS;
        let cov = if leg == 0 { asset_cov } else { cash_cov };
        let count = entries
            .iter()
            .filter(|e| cov != [0; 32] && e.covenant_id.map(|h| h.as_bytes()) == Some(cov))
            .count();
        let n = if kas_cash || count == 0 { 1 } else { 2 };
        Entry::Refund {
            leg,
            signer: named,
            n_in: n,
            n_out: n,
            cov,
        }
    };
    let (n_in, n_out) = match entry {
        Entry::Settle { n_in, n_out, .. } | Entry::Refund { n_in, n_out, .. } => (n_in, n_out),
    };
    if entries.len() < n_in || tx.outputs.len() < n_out {
        // the script's own [T2] / [T3] refuse a view beyond the transaction
        return Some(Err(terms_core::Refusal {
            code: "ZK_H_SHAPE",
            tag: "T2",
        }));
    }
    // the script's [T10] / [T11] run before the gate
    if let Some(r) = covenant_rule(&entries, entry) {
        return Some(Err(r));
    }
    // [H5] (spec/V3-ZK.md 22.16) on v1's vaults: the guest checks it from the v4 vault's own
    // redeem script, which a v1 view does not have, so the shadow asks the same of the v1 vaults:
    // in a settle with a cash vault, the input at the other leg's slot is this trade's other vault.
    // It runs after [S1] in the statement, so a vault off its slot is left to the statement.
    if settle && w.terms.cash_kind != CASH_EXTERNAL && idx == leg as usize {
        let other = if leg == 0 {
            w.cash_vault()
        } else {
            &w.asset_vault
        };
        if entries[1 - idx].script_public_key != other.p2sh() {
            return Some(Err(terms_core::Refusal {
                code: "ZK_H_STATEMENT_FALSE",
                tag: "H5",
            }));
        }
    }
    let terms_bytes = core.encode();
    let commit = th::commit(&th::terms_hash(&terms_bytes), leg);
    let j = journal_of(
        &tx,
        &entries,
        idx,
        entry,
        commit,
        core.authority.expect("authority"),
    );
    let redeems = (0..n_in)
        .filter_map(|i| match &spec.inputs[i].spend {
            Spend::Kcc20Leader { redeem, .. } | Spend::Kcc20Delegate { redeem, .. } => {
                Some((i as u8, redeem.bytecode().to_vec()))
            }
            _ => None,
        })
        .collect();
    let witness = terms_core::Witness {
        terms: terms_bytes,
        journal: j.to_bytes(),
        redeems,
    };
    Some(
        terms_core::statement::statement_without_h5_for_v1_differential(
            &witness,
            terms_core::StatementOptions {
                curve_checks: false,
            },
        )
        .map(|_| ()),
    )
}

/// A spec whose signatures and sequences are made right: the v4 script keeps `[S6]`, `[R2]` and
/// the lock-time finality of the spending input, so a v1 refusal for those is not one the
/// statement can share.
fn repaired(spec: &TxSpec, w: &World) -> TxSpec {
    let mut s = spec.clone();
    for i in s.inputs.iter_mut() {
        if !matches!(i.spend, Spend::Plain) {
            i.sequence = NON_FINAL;
        }
        match &mut i.spend {
            Spend::Settle { signer, .. } if w.mode.authority => *signer = Some(Role::Authority),
            Spend::Refund { named, signer, .. } => {
                for role in [Role::Seller, Role::Buyer, Role::Authority, Role::Stranger] {
                    if w.xonly(role) == *named {
                        *signer = role;
                    }
                }
            }
            _ => {}
        }
    }
    s
}

/// Called after v1 ran input `idx` of `spec`: the statement must hold exactly when v1's script
/// accepts, up to the checks the v4 script keeps. A divergence panics with both verdicts.
pub fn shadow_check(spec: &TxSpec, w: &World, idx: usize, v1_ok: bool) {
    let Some(core) = core_verdict(spec, w, idx) else {
        return;
    };
    let core_ok = core.is_ok();
    match (v1_ok, core_ok) {
        (true, true) => log("compared both accept"),
        (false, false) => log("compared both refuse"),
        (true, false) => {
            panic!(
                "differential: v1 accepts input {idx}, the statement refuses it: {}",
                core.unwrap_err()
            );
        }
        (false, true) => {
            // v1 refused. If the refusal was only a signature or a lock-time finality, the
            // repaired spec is accepted by v1; otherwise the statement is too lax.
            if run_plain(&repaired(spec, w), w, idx) {
                log("compared v1 refuses a signature or finality only, statement accepts");
            } else {
                panic!("differential: v1 refuses input {idx} for a reason beyond signatures and finality, the statement accepts it");
            }
        }
    }
}
