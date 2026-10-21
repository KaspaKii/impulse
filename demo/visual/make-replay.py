#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""demo/visual/make-replay.py: build an events file from a recorded run.log.

  demo/visual/make-replay.py docs/evidence/<run>/run.log > docs/evidence/<run>/events.jsonl

The output has the same shape as the live feed of `xchain-demo.sh --events`, with a pause event
where a live run with PAUSE=1 would wait for Enter, so the page plays it the same way. It reads
the public lines of the log only (the log has no secret: the demo never prints it).
"""
import json
import re
import sys

CLUSTER = "devnet"


def main(path):
    text = open(path, encoding="utf-8").read()
    lines = text.splitlines()

    def grab(pattern, flags=0, group=1):
        m = re.search(pattern, text, flags)
        if not m:
            sys.exit(f"make-replay: no match for {pattern!r} in {path}")
        return m.group(group)

    def sect(n):
        m = re.search(rf"^== Step {n}: .*?(?=^== Step |\Z)", text, re.S | re.M)
        if not m:
            sys.exit(f"make-replay: no step {n} in {path}")
        return m.group(0)

    hash_lock = grab(r"^hash_lock: ([0-9a-f]{64})$", re.M)
    vault = grab(r"^vault: (kaspatest:[a-z0-9]+)", re.M)
    s5 = sect(5)
    bal_before = re.search(r"balances before:\n\s+TN10\s+test KCC-20\s+seller (\d+)\s+buyer (\d+)\n\s+\w+\s+test USDC\s+seller (\d+) \(base units\)\s+buyer (\d+)", text)
    bal_after = re.search(r"balances after:\n\s+TN10\s+test KCC-20\s+seller (\d+)\s+buyer (\d+)\n\s+\w+\s+test USDC\s+seller (\d+) \(base units\)\s+buyer (\d+)", text)
    if not bal_before or not bal_after:
        sys.exit("make-replay: balances not found")

    def bal(m):
        ks, kb, us, ub = (int(x) for x in m.groups())
        return {"kaspa": {"seller": ks, "buyer": kb}, "solana": {"seller": us, "buyer": ub}}

    def txid_and_url(prefix, section):
        m = re.search(rf"^{prefix} txid: (\S+)\n\s+(https?://\S+)", section, re.M)
        if not m:
            sys.exit(f"make-replay: no {prefix} txid")
        return m.group(1), m.group(2)

    fund_tx, fund_url = txid_and_url("kaspa funding", sect(3))
    open_tx, open_url = txid_and_url("solana open", sect(4))
    claim_tx, claim_url = txid_and_url("solana claim", s5)
    kclaim_tx, kclaim_url = txid_and_url("kaspa claim", sect(6))
    htlc = grab(r"^htlc: (\S+)$", re.M)
    escrow = grab(r"^escrow: (\S+)$", re.M)
    freeze = re.search(r"^warning: mint \S+ has a freeze authority, ([1-9A-HJ-NP-Za-km-z]+)\.", text, re.M)

    out = []

    def ev(**kw):
        rec = {"seq": len(out) + 1, "source": "run.log"}
        rec.update(kw)
        out.append(rec)

    ev(phase="ready", step=0, chain="both", actor="both",
       text="Ready. A test asset on Kaspa TN10 against test USDC on Solana devnet, one shared hash lock.",
       cluster=CLUSTER, kaspa_network="TN10",
       solana_program=grab(r"^solana program (\S+)", re.M),
       usdc_mint=grab(r"^test USDC mint (\S+)", re.M),
       asset_covenant=grab(r"^kaspa test asset: covenant ([0-9a-f]{64})", re.M),
       kaspa_seller=grab(r"^kaspa seller\s+(kaspatest:\S+)", re.M),
       kaspa_buyer=grab(r"^kaspa buyer\s+(kaspatest:\S+)", re.M),
       solana_seller=grab(r"^solana seller\s+(\S+)", re.M),
       solana_buyer=grab(r"^solana buyer\s+(\S+)", re.M),
       asset_units=1, usdc_units=100000, bal=bal(bal_before))
    ev(phase="pause", step=0)

    ev(phase="started", step=1, chain="kaspa", actor="seller",
       text="The seller makes a secret and works out the vault address that only its hash can open.")
    ev(phase="done", step=1, chain="kaspa", actor="seller",
       text="The seller made a secret and the vault address that only its hash can open. The secret never leaves the seller's machine.",
       hash_lock=hash_lock, vault=vault)
    ev(phase="pause", step=1)

    ev(phase="started", step=2, chain="offchain", actor="buyer", text="The buyer checks the terms before locking anything.")
    ev(phase="done", step=2, chain="offchain", actor="buyer",
       text="The buyer checked that delivery goes to the buyer and the refund goes to the buyer's Solana account. Nothing was sent.",
       hash_lock=hash_lock)
    ev(phase="pause", step=2)

    ev(phase="started", step=3, chain="kaspa", actor="seller", text="The seller locks the asset in the Kaspa vault.")
    ev(phase="done", step=3, chain="kaspa", actor="seller",
       text="The seller locked 1 unit of the test asset in the vault on Kaspa TN10.",
       txid=fund_tx, url=fund_url, vault=vault, hash_lock=hash_lock, amount="1")
    ev(phase="pause", step=3)

    ev(phase="started", step=4, chain="solana", actor="buyer", text="The buyer locks test USDC on Solana under the same hash.")
    ev(phase="done", step=4, chain="solana", actor="buyer",
       text=f"The buyer locked 0.1 test USDC on Solana {CLUSTER}, under the same hash.",
       txid=open_tx, url=open_url, htlc=htlc, escrow=escrow, hash_lock=hash_lock, amount="100000")
    ev(phase="pause", step=4)

    ev(phase="started", step=5, chain="solana", actor="seller",
       text="The seller checks the Solana escrow against the terms, then claims it.")
    ev(phase="info", step=5, chain="solana", actor="seller",
       text="The seller checked that the escrow matches the terms and is final.", htlc=htlc)
    if freeze:
        ev(phase="warning", step=5, chain="solana", actor="seller",
           text="This test token has a freeze authority, as real USDC does. The issuer could freeze the escrow. The seller trusts it not to.",
           freeze_authority=freeze.group(1))
    ev(phase="done", step=5, chain="solana", actor="seller",
       text="The seller claimed the USDC. The claim carries the secret on a public chain, so now anyone can read it.",
       txid=claim_tx, url=claim_url, reveals_secret=True, hash_lock=hash_lock, htlc=htlc)
    ev(phase="pause", step=5)

    ev(phase="started", step=6, chain="kaspa", actor="buyer",
       text="The buyer reads the revealed secret from Solana and uses it on Kaspa.")
    ev(phase="done", step=6, chain="kaspa", actor="buyer",
       text="The buyer used the secret from Solana to take the asset out of the Kaspa vault.",
       txid=kclaim_tx, url=kclaim_url, vault=vault, hash_lock=hash_lock)

    ev(phase="started", step=7, chain="both", actor="both",
       text="Waiting for the Kaspa claim to be 600 score units deep, about a minute.")
    complete = "trade: complete" in text
    ev(phase="complete", step=7, chain="both", actor="both", complete=complete, hash_lock=hash_lock,
       text="Trade complete. Test networks, test tokens. A conditional exchange with residual risk, not atomic settlement.",
       fund_txid=fund_tx, fund_url=fund_url, open_txid=open_tx, open_url=open_url,
       claim_txid=claim_tx, claim_url=claim_url, kaspa_claim_txid=kclaim_tx, kaspa_claim_url=kclaim_url,
       bal=bal(bal_after))

    for rec in out:
        print(json.dumps(rec, separators=(",", ":")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make-replay.py <run.log>")
    main(sys.argv[1])
