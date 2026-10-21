#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# demo/kaspa-dvp-seller.sh: the seller's command-line side of Part A of the live demo, the Kaspa
# DvP on TN10 with the browser demo page (demo/README.md describes the page). The page holds the buyer's
# key (in-page wallet B) and pays the settle fee (wallet A); the seller's KCC-20 asset leg is
# funded here, because the page moves no token.
#
#   demo/kaspa-dvp-seller.sh terms  <wallet B public key, 64 hex> [expiry-in-DAA, default 864000]
#   demo/kaspa-dvp-seller.sh fund   <work dir printed by terms>
#   demo/kaspa-dvp-seller.sh status <work dir> <txid> <from_block>
#
# TN10 only. Keys: the existing $KEYS/tn10-seller.key and tn10-buyer.key, passed by path only.
# tn10-buyer's key is the buyer's delivery and refund destination: outside the page, so that
# nothing the trade pays is lost with the page. The test asset is the token Part B mints
# (demo/xchain-demo.sh prepare); this script reads its record, it never mints.
# Environment: KEYS (default ~/impulse-keys), NODE (default: asked from a public TN10 resolver),
# IMPULSE (default target/release/impulse), STATE_DIR (default ~/impulse-runs/xchain-demo-state).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
. "$repo/scripts/lib-impulse.sh"
KEYS=${KEYS:-$HOME/impulse-keys}
IMPULSE=${IMPULSE:-$repo/target/release/impulse}
STATE=${STATE_DIR:-$HOME/impulse-runs/xchain-demo-state}
ASSET_TPL=$repo/crates/impulse-core/src/tx/testdata/kcc20-asset.json
KAS_EQ=100000000
CASH=50000000 # 0.5 KAS, the minimum output
if [ -z "${NODE:-}" ] && "$IMPULSE" tip --node ws://127.0.0.1:17210 > /dev/null 2>&1; then
  NODE=ws://127.0.0.1:17210 # the local TN10 node, when one runs
fi
if [ -z "${NODE:-}" ]; then
  NODE=$(curl -s -m 15 https://eric.kaspa.stream/v2/kaspa/testnet-10/tls/wrpc/borsh | sed -n 's/.*"url":"\([^"]*\)".*/\1/p' || true)
fi
[ -n "$NODE" ] || die "no TN10 node: set NODE=wss://..."
k() { "$IMPULSE" key show --key-file "$KEYS/tn10-$1.key"; }
SP=$(field public_key "$(k seller)"); SA=$(field address "$(k seller)")
BP=$(field public_key "$(k buyer)"); BA=$(field address "$(k buyer)")

case "${1:-}" in
  terms)
    WB=${2:-}; hex32 "$WB" || die "give wallet B's public key (64 lowercase hex digits) from the page"
    expiry_in=${3:-864000}
    [ -f "$STATE/tn10-token.txt" ] || die "no test asset record: run demo/xchain-demo.sh prepare first"
    cov=$(field covenant "$(cat "$STATE/tn10-token.txt")")
    W=$HOME/impulse-runs/page-$(date -u +%Y%m%dT%H%M%SZ); mkdir -m 700 -p "$W"
    info=$("$IMPULSE" token info --template "$ASSET_TPL")
    leg=$(kcc20_leg "$cov" "$(field template_hash "$info")" "$(field template_prefix_len "$info")" "$(field template_suffix_len "$info")" 1)
    now=$(field virtual_daa_score "$("$IMPULSE" tip --node "$NODE")")
    draft "$W/draft.json" testnet vault "$SP" "$WB" null "$leg" "$(kas_leg $CASH)" \
      "$(owner_is "$BP")" "$(kas_to "$SP")" "$(owner_is "$SP")" "$(kas_to "$BP")" $((now + expiry_in)) earmarked
    "$IMPULSE" terms new --draft "$W/draft.json" --out "$W/terms.json" --node "$NODE" \
      --role seller --my-key "$SP" --kas-equivalent $KAS_EQ | tee "$W/terms.out"
    echo
    echo "work dir: $W"
    echo "paste into the page's \"Terms JSON\": pbcopy < $W/terms.json"
    echo "buyer delivery and refund: $BP / $BA (outside the page)"
    ;;
  fund)
    W=${2:-}; [ -f "$W/terms.json" ] || die "give the work dir printed by terms"
    cov=$(field covenant "$(cat "$STATE/tn10-token.txt")"); units=$(field units "$(cat "$STATE/tn10-token.txt")")
    tok=$("$IMPULSE" token list --node "$NODE" --template "$ASSET_TPL" --owner "$SP" --covenant "$cov" --amount "$units" | sed -n 's/^token: //p' | head -n 1)
    [ -n "$tok" ] || die "the node lists no seller token of $units units"
    "$IMPULSE" fund build --terms "$W/terms.json" --leg asset --node "$NODE" --role seller --my-key "$SP" \
      --pay-from "$SA" --asset-template "$ASSET_TPL" --token "$tok" --kas-equivalent $KAS_EQ \
      --out "$W/fund-asset.ipst" | tee "$W/fund-asset.log"
    "$IMPULSE" ipst sign --ipst "$W/fund-asset.ipst" --terms "$W/terms.json" --key-file "$KEYS/tn10-seller.key" \
      --role seller --my-key "$SP" --node "$NODE" --asset-template "$ASSET_TPL" --kas-equivalent $KAS_EQ \
      --out "$W/fund-asset.signed" > "$W/fund-asset.sign.out"
    "$IMPULSE" submit --ipst "$W/fund-asset.signed" --node "$NODE" --asset-template "$ASSET_TPL" | tee "$W/fund-asset.submit"
    # The funding sends 1 unit to the vault; record what the seller holds for Part B.
    printf 'covenant: %s\nunits: %s\n' "$cov" "$((units - 1))" > "$STATE/tn10-token.txt"
    ;;
  status)
    W=${2:-}; [ -f "$W/terms.json" ] && [ -n "${3:-}" ] && [ -n "${4:-}" ] || die "usage: status <work dir> <txid> <from_block>"
    "$IMPULSE" status --node "$NODE" --terms "$W/terms.json" --txid "$3" --from-block "$4"
    ;;
  *) die "usage: demo/kaspa-dvp-seller.sh terms <wallet B public key> | fund <work dir> | status <work dir> <txid> <from_block>" ;;
esac
