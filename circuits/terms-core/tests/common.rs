// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! Synthetic worlds for the statement tests: a settle or a refund view built by the same rules
//! the vault script uses, with a fake KCC-20 template (the statement only needs a template hash
//! over a prefix and a suffix). Keys are the public points nG, no signature is made anywhere.
#![allow(dead_code)]

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use terms_core::codec::*;
use terms_core::hashes::*;
use terms_core::journal::{Item, Journal, Mode};
use terms_core::kcc20::{self, State};
use terms_core::Witness;

pub const AMOUNT_A: u64 = 1_000;
pub const AMOUNT_B: u64 = 250_000;
pub const AUTH_VALUE: u64 = 20_000;
pub const TOKEN_VALUE: u64 = 30_000;
pub const EARLIEST: u64 = 1_000_000;
pub const EXPIRY: u64 = 2_000_000;

pub fn point_x(n: u64) -> [u8; 32] {
    let p = (ProjectivePoint::GENERATOR * Scalar::from(n))
        .to_affine()
        .to_encoded_point(true);
    p.as_bytes()[1..33].try_into().unwrap()
}

pub fn seller() -> [u8; 32] {
    point_x(2)
}
pub fn buyer() -> [u8; 32] {
    point_x(4)
}
pub fn authority() -> [u8; 32] {
    point_x(3)
}
pub fn stranger() -> [u8; 32] {
    point_x(9)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cash {
    Kas,
    Kcc20,
    External,
}

pub fn asset_cov() -> [u8; 32] {
    [0xA5; 32]
}
pub fn cash_cov() -> [u8; 32] {
    [0xCA; 32]
}

fn pattern(seed: u8, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| seed.wrapping_add(i as u8).wrapping_mul(7))
        .collect()
}

pub struct Template {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

impl Template {
    pub fn new(seed: u8) -> Self {
        Self {
            prefix: pattern(seed, 100),
            suffix: pattern(seed ^ 0x55, 60),
        }
    }
    pub fn hash(&self) -> [u8; 32] {
        template_hash(&self.prefix, &self.suffix)
    }
    pub fn redeem(&self, s: &State) -> Vec<u8> {
        let mut r = self.prefix.clone();
        r.extend_from_slice(&kcc20::encode(s));
        r.extend_from_slice(&self.suffix);
        r
    }
}

pub fn asset_template() -> Template {
    Template::new(1)
}
pub fn cash_template() -> Template {
    Template::new(2)
}

pub fn terms(cash: Cash, earmarked: bool) -> Terms {
    let at = asset_template();
    let ct = cash_template();
    let kcc = |cov, t: &Template, amount| Leg::Kcc20 {
        cov,
        template_hash: t.hash(),
        prefix_len: t.prefix.len() as u32,
        suffix_len: t.suffix.len() as u32,
        amount,
    };
    let kas_dest = |key: [u8; 32]| {
        let mut s = vec![0x20];
        s.extend_from_slice(&key);
        s.push(0xac);
        Dest::Kas {
            version: 0,
            script: s,
        }
    };
    Terms {
        network: 0,
        mode: MODE_VAULT,
        nonce: 0x4e4e_4e4e_4e4e_4e4e,
        seller: seller(),
        buyer: buyer(),
        authority: Some(authority()),
        asset: kcc(asset_cov(), &at, AMOUNT_A),
        cash: match cash {
            Cash::Kas => Leg::Kas { amount: AMOUNT_B },
            Cash::Kcc20 => kcc(cash_cov(), &ct, AMOUNT_B),
            Cash::External => Leg::External { amount: AMOUNT_B },
        },
        buyer_delivery: Dest::Owner {
            id_type: ID_PUBKEY,
            id: point_x(5),
        },
        seller_proceeds: match cash {
            Cash::Kas => kas_dest(point_x(6)),
            Cash::Kcc20 => Dest::Owner {
                id_type: ID_PUBKEY,
                id: point_x(6),
            },
            Cash::External => Dest::OffChain,
        },
        seller_refund: Dest::Owner {
            id_type: ID_PUBKEY,
            id: point_x(7),
        },
        buyer_refund: match cash {
            Cash::Kas => kas_dest(point_x(8)),
            Cash::Kcc20 => Dest::Owner {
                id_type: ID_SCRIPT_HASH,
                id: [0xB2; 32],
            },
            Cash::External => Dest::OffChain,
        },
        earliest: Some(EARLIEST),
        expiry: EXPIRY,
        funding: if earmarked {
            FUNDING_EARMARKED
        } else {
            FUNDING_REVOCABLE
        },
        blind: [0xBD; 32],
        trade_ref: [0x7E; 32],
    }
}

/// A template v4 vault's redeem script as the guest reads it (spec/V3-ZK.md 22.16): one byte, the
/// state `0x20 || commit || 0x20 || authority`, then a fake rest of the template.
pub fn vault_redeem_of(commit: &[u8; 32], authority: &[u8; 32]) -> Vec<u8> {
    let mut r = vec![0x6b, 0x20];
    r.extend_from_slice(commit);
    r.push(0x20);
    r.extend_from_slice(authority);
    r.extend_from_slice(&pattern(0x90, 300));
    r
}
/// The vault of `leg` of terms `t`.
pub fn vault_redeem(t: &Terms, leg: u8) -> Vec<u8> {
    vault_redeem_of(
        &commit(&terms_hash(&t.encode()), leg),
        &t.authority.expect("terms v4 name an authority"),
    )
}
pub fn vault_hash(t: &Terms, leg: u8) -> [u8; 32] {
    blake2b256(&vault_redeem(t, leg))
}
pub fn vault_spk(t: &Terms, leg: u8) -> [u8; 37] {
    p2sh_spk(&vault_hash(t, leg))
}

fn item(value: u64, spk: &[u8], cov: [u8; 32]) -> Item {
    Item {
        value,
        spk_hash: sha256(spk),
        cov,
    }
}

fn kas_spk(d: &Dest) -> Vec<u8> {
    match d {
        Dest::Kas { version, script } => {
            let mut v = version.to_be_bytes().to_vec();
            v.extend_from_slice(script);
            v
        }
        _ => panic!("not a KAS destination"),
    }
}

fn owner_of(d: &Dest) -> (u8, [u8; 32]) {
    match d {
        Dest::Owner { id_type, id } => (*id_type, *id),
        _ => panic!("not an owner"),
    }
}

pub fn token_item(t: &Template, s: &State, cov: [u8; 32]) -> (Item, Vec<u8>) {
    let redeem = t.redeem(s);
    (
        item(TOKEN_VALUE, &p2sh_spk(&blake2b256(&redeem)), cov),
        redeem,
    )
}

/// A view and its witness, the pieces a test can change.
#[derive(Clone)]
pub struct Sc {
    pub terms: Terms,
    pub j: Journal,
    pub redeems: Vec<(u8, Vec<u8>)>,
}

impl Sc {
    pub fn terms_bytes(&self) -> Vec<u8> {
        self.terms.encode()
    }

    /// Recommit the journal to the (changed) terms for its leg.
    pub fn recommit(&mut self) {
        self.j.commit = commit(&terms_hash(&self.terms.encode()), self.j.leg);
    }

    pub fn witness(&self) -> Witness {
        Witness {
            terms: self.terms.encode(),
            journal: self.j.to_bytes(),
            redeems: self.redeems.clone(),
        }
    }

    pub fn run(&self) -> Result<Vec<u8>, terms_core::Refusal> {
        terms_core::statement(&self.witness(), Default::default())
    }

    pub fn tag(&self) -> &'static str {
        match self.run() {
            Ok(_) => "ok",
            Err(r) => r.tag,
        }
    }

    pub fn code(&self) -> &'static str {
        match self.run() {
            Ok(_) => "ok",
            Err(r) => r.code,
        }
    }
}

/// The settle view of `leg` for `cash` terms, as the script builds it.
pub fn settle(cash: Cash, leg: u8) -> Sc {
    let t = terms(cash, false);
    settle_of(t, cash, leg)
}

pub fn settle_of(t: Terms, cash: Cash, leg: u8) -> Sc {
    let at = asset_template();
    let ct = cash_template();
    let (bd_type, bd) = owner_of(&t.buyer_delivery);
    let escrow_a = State {
        owner: vault_hash(&t, 0),
        id_type: ID_SCRIPT_HASH,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    let deliver_a = State {
        owner: bd,
        id_type: bd_type,
        amount: AMOUNT_A as i64,
        is_minter: false,
    };
    let (esc_a_item, esc_a_redeem) = token_item(&at, &escrow_a, asset_cov());
    let (del_a_item, _) = token_item(&at, &deliver_a, asset_cov());
    let p2pk = |k: &[u8; 32]| p2pk_spk(k).to_vec();
    let v0 = item(AUTH_VALUE, &vault_spk(&t, 0), [0; 32]);
    let mut redeems = vec![];
    let (inputs, outputs, count_c, cov_c);
    match cash {
        Cash::Kas => {
            let v1 = item(AMOUNT_B, &vault_spk(&t, 1), [0; 32]);
            inputs = vec![v0, v1, esc_a_item];
            redeems.push((2, esc_a_redeem));
            outputs = vec![
                del_a_item,
                item(AMOUNT_B, &kas_spk(&t.seller_proceeds), [0; 32]),
                item(AUTH_VALUE, &p2pk(&t.seller), [0; 32]),
            ];
            count_c = 0;
            cov_c = [0; 32];
        }
        Cash::Kcc20 => {
            let (sp_type, sp) = owner_of(&t.seller_proceeds);
            let escrow_c = State {
                owner: vault_hash(&t, 1),
                id_type: ID_SCRIPT_HASH,
                amount: AMOUNT_B as i64,
                is_minter: false,
            };
            let deliver_c = State {
                owner: sp,
                id_type: sp_type,
                amount: AMOUNT_B as i64,
                is_minter: false,
            };
            let (esc_c_item, esc_c_redeem) = token_item(&ct, &escrow_c, cash_cov());
            let (del_c_item, _) = token_item(&ct, &deliver_c, cash_cov());
            let v1 = item(AUTH_VALUE, &vault_spk(&t, 1), [0; 32]);
            inputs = vec![v0, v1, esc_a_item, esc_c_item];
            redeems.push((2, esc_a_redeem));
            redeems.push((3, esc_c_redeem));
            outputs = vec![
                del_a_item,
                del_c_item,
                item(AUTH_VALUE, &p2pk(&t.seller), [0; 32]),
                item(AUTH_VALUE, &p2pk(&t.buyer), [0; 32]),
            ];
            count_c = 1;
            cov_c = cash_cov();
        }
        Cash::External => {
            assert_eq!(leg, 0, "external cash has no cash vault");
            inputs = vec![v0, {
                let mut e = esc_a_item;
                e.value = TOKEN_VALUE;
                e
            }];
            redeems.push((1, esc_a_redeem));
            outputs = vec![del_a_item, item(AUTH_VALUE, &p2pk(&t.seller), [0; 32])];
            count_c = 0;
            cov_c = [0; 32];
        }
    }
    // this vault's own redeem script, after the escrows ([H5], spec/V3-ZK.md 22.16)
    redeems.push((leg, vault_redeem(&t, leg)));
    let mut sc = Sc {
        j: Journal {
            mode: Mode::Settle,
            vault_spk: vault_spk(&t, leg),
            commit: [0; 32],
            authority: authority(),
            leg,
            input_index: leg,
            locktime: EARLIEST,
            signer: [0; 32],
            cov_a: asset_cov(),
            cov_c,
            count_a: 1,
            count_c,
            inputs,
            outputs,
        },
        terms: t,
        redeems,
    };
    sc.recommit();
    sc
}

/// A refund view. `with_token`: the leg's escrow rides at input 1 and returns at output 1.
pub fn refund(
    cash: Cash,
    leg: u8,
    signer: [u8; 32],
    earmarked: bool,
    with_token: bool,
    locktime: u64,
) -> Sc {
    let t = terms(cash, earmarked);
    let at = asset_template();
    let ct = cash_template();
    let is_asset = leg == 0;
    let depositor = if is_asset { t.seller } else { t.buyer };
    let kas_cash = !is_asset && cash == Cash::Kas;
    let (value, home_spk): (u64, Vec<u8>) = if kas_cash {
        (AMOUNT_B, kas_spk(&t.buyer_refund))
    } else {
        (AUTH_VALUE, p2pk_spk(&depositor).to_vec())
    };
    let mut inputs = vec![item(value, &vault_spk(&t, leg), [0; 32])];
    let mut outputs = vec![item(value, &home_spk, [0; 32])];
    let mut redeems = vec![];
    let mut count_a = 0;
    let mut cov = [0u8; 32];
    if !kas_cash {
        let (tm, tcov, amount, home_dest) = if is_asset {
            (&at, asset_cov(), AMOUNT_A, &t.seller_refund)
        } else {
            (&ct, cash_cov(), AMOUNT_B, &t.buyer_refund)
        };
        if cash != Cash::External || is_asset {
            cov = tcov;
        }
        if with_token {
            assert!(cash != Cash::External || is_asset);
            let escrow = State {
                owner: vault_hash(&t, leg),
                id_type: ID_SCRIPT_HASH,
                amount: amount as i64,
                is_minter: false,
            };
            let (esc_item, esc_redeem) = token_item(tm, &escrow, tcov);
            let (hid_type, hid) = owner_of(home_dest);
            let home = State {
                owner: hid,
                id_type: hid_type,
                amount: amount as i64,
                is_minter: false,
            };
            let (home_item, _) = token_item(tm, &home, tcov);
            inputs.push(esc_item);
            outputs.push(home_item);
            redeems.push((1, esc_redeem));
            count_a = 1;
        }
    }
    let mut sc = Sc {
        j: Journal {
            mode: Mode::Refund,
            vault_spk: vault_spk(&t, leg),
            commit: [0; 32],
            authority: authority(),
            leg,
            input_index: 0,
            locktime,
            signer,
            cov_a: cov,
            cov_c: [0; 32],
            count_a,
            count_c: 0,
            inputs,
            outputs,
        },
        terms: t,
        redeems,
    };
    sc.recommit();
    sc
}
