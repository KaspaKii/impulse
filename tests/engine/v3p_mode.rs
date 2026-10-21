// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
//! The v3p_* binaries really run the template v3 probe (harness::v3_probe_by_default), so a
//! green v3p_settle, v3p_locktime or v3p_escrow_release means the v1 suites passed on v3 code.

mod harness;
use harness::*;

#[test]
fn v3p_worlds_are_template_v3_probes_carrying_sha256_of_j() {
    assert!(v3_by_default() && v3_probe_by_default());
    let w = World::new(Mode::new(false, CASH_KAS, REVOCABLE));
    assert_eq!(w.terms.version, 3);
    let zk = w.terms.zk.expect("v3 terms");
    assert!(w.asset_vault.default_proof.is_some());
    assert_eq!(w.cash_vault().default_proof, Some(vec![]));
    let j = v3_journal(
        &zk.list_root,
        &spk_bytes(&w.asset_vault.p2sh()),
        w.terms.buyer_delivery,
    );
    assert_eq!(
        w.asset_vault.default_proof.as_deref(),
        Some(&sha256(&j)[..])
    );
    // a probe is not template v3: its bytecode differs, because the verify call is replaced
    let real = Compiled::new(&vault_v3_source(), &w.terms.ctor(ASSET_LEG));
    assert_ne!(real.bytecode(), w.asset_vault.bytecode());
    assert_ne!(real.template_hash(), w.asset_vault.template_hash());
    // and the settle of such a world is accepted end to end
    w.settle().assert_all_accepted(&w, "probe settle");
}
