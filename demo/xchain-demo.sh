#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# demo/xchain-demo.sh: the cross-chain hashlock demo (I11 live demo, I18). A Kaspa KCC-20 asset on
# TN10 against a test USDC on Solana devnet, linked by one sha256 hash lock. Run by the key
# holder, on his own machine.
#
#   1  seller   makes the secret and the Kaspa hashlock vault        (impulse xchain new)
#   2  buyer    checks the terms                                      (impulse xchain verify)
#   3  seller   funds the vault with the asset                        (xchain fund build, sign, submit)
#   4  buyer    opens the Solana HTLC with the same hash              (impulse-htlc-demo open)
#   5  seller   checks that HTLC, then claims it, revealing the secret
#                                                (xchain verify-counterpart, impulse-htlc-demo claim)
#   6  buyer    reads the secret from Solana and claims the asset     (xchain watch, claim, sign, submit)
#   7  both     the summary: every txid with an explorer link
#
# Usage:  demo/xchain-demo.sh [run|refund|prepare|preflight] [--fast] [--events <file>]
#                                                          (default run; --fast = no pauses)
#   --events <file>   append one JSON object per line for each step (started, done, the pauses, the
#                     freeze-authority warning, the final balances): the feed of demo/visual/. Public
#                     data only. The secret and the preimage are never written to it.
#   refund      the fallback path: steps 1 to 4 (the seller funds the Kaspa vault, the buyer opens the Solana
#               HTLC), then nobody claims. The buyer refunds on Solana after the HTLC timeout
#               (impulse-htlc-demo refund); the seller refunds on Kaspa after expiry_daa (impulse xchain
#               refund --signer seller, sign, submit); the four balances are then checked to be back where
#               they were. The Solana HTLC of this mode is opened with a short timeout of its own
#               (SOL_REFUND_SECS, default 60 s) instead of the terms' T_C, which the margin rule keeps at
#               hours: it does not match the terms, and no command of this mode reads it against them.
#               Kaspa expiry_daa is at least about a day on TN10 (the margin rule), so on TN10 the Kaspa
#               half waits up to REFUND_WAIT_SECS (default 600) and then prints the commands to finish
#               later; against the offline stand-in node, ADVANCE_NODE_CMD moves its DAA score past it.
#   preflight   tools, keys, balances, node, program. Spends nothing (it may ask the devnet faucet).
#   prepare     preflight, then the one-time setup: the test USDC mint and token accounts on Solana, and
#               the test asset on TN10. Idempotent; run is the same and then the seven steps.
# Environment (all optional):
#   CLUSTER=devnet|localnet      the Solana cluster (default devnet)
#   KEYS=<dir>                   key directory (default ~/impulse-keys)
#   NODE=<ws(s)://...>           a synced TN10 node with the UTXO index (default: ws://127.0.0.1:17210 if it answers, else a public resolver)
#   SOLANA_RPC_URL=<url>         default https://api.devnet.solana.com, or http://127.0.0.1:8899 for localnet
#   HTLC_PROGRAM=<base58>        the impulse-htlc program (default: the final devnet deployment named in
#                                docs/evidence/solana-devnet-2026-10-11/README.md)
#   PAUSE=0|1                    1 (the default at a terminal) waits for Enter before each step; --fast sets 0
#   SOL_REFUND_SECS=<s>, REFUND_WAIT_SECS=<s>, ADVANCE_NODE_CMD=<command>   the refund mode, above (the
#                                command moves the offline stand-in node's DAA score; never set on TN10)
#   UNTIL=<n>                    stop after step n (1..6)
#   WORKDIR=<dir>                default ~/impulse-runs/xchain-demo-<utc time>
#   IMPULSE=<binary>, HTLC_TOOL=<binary>   default target/release/impulse and solana/target/release/impulse-htlc-demo
#
# Keys. Nothing here prints, logs or sends a key. TN10 keys are the existing files
# $KEYS/tn10-{seller,buyer,authority}.key, passed to the CLI by path only. The devnet keys
# $KEYS/devnet-{seller,buyer,issuer}.json are created on the first run if absent (solana-keygen,
# mode 0600, silent) and are passed by path only. The only account that needs devnet SOL is the
# buyer's: the script tops the seller up from it. The secret is made by `impulse xchain new` into
# $WORKDIR/seller.secret (mode 0600) and is never printed. Testnet and devnet only: the CLI
# refuses mainnet for every xchain command, and the Solana tool refuses the mainnet genesis hash.
#
# Not shown in this demo: the buyer's refund after the Solana timeout and the seller's refund after
# expiry_daa (both wait hours). They are the fallback evidence in docs/evidence/.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
. "$repo/scripts/lib-impulse.sh"

FAST=0
EVENTS=
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) FAST=1 ;;
    --events) [ $# -ge 2 ] || die "--events needs a file"; EVENTS=$2; shift ;;
    *) args+=("$1") ;;
  esac
  shift
done
[ -z "$EVENTS" ] || case "$EVENTS" in /*) ;; *) EVENTS=$PWD/$EVENTS ;; esac
mode=${args[0]:-run}
case "$mode" in run | refund | prepare | preflight) ;; *) die "usage: demo/xchain-demo.sh [run|refund|prepare|preflight]" ;; esac

CLUSTER=${CLUSTER:-devnet}
KEYS=${KEYS:-$HOME/impulse-keys}
IMPULSE=${IMPULSE:-$repo/target/release/impulse}
HTLC_TOOL=${HTLC_TOOL:-$repo/solana/target/release/impulse-htlc-demo}
# Each step waits for Enter when a person is at the terminal, unless --fast or PAUSE=0.
if [ "$FAST" = 1 ] || [ ! -t 0 ]; then PAUSE=${PAUSE:-0}; [ "$FAST" = 1 ] && PAUSE=0; else PAUSE=${PAUSE:-1}; fi
UNTIL=${UNTIL:-7}
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# The trade: 1 unit of the test KCC-20 asset against 0.1 test USDC (6 decimals). Test coins only.
ASSET_UNITS=1
USDC_UNITS=100000
KAS_EQUIVALENT=100000000 # the declared value of the larger leg, in sompi: 1 KAS, under the 10 KAS cap
FINAL_SECS=60            # the Solana cluster's time to finalized commitment, a generous bound
TIMEOUT_IN=10800         # the Solana timeout T_C: 3 hours (the claim lead is 2 hours)
ASSET_TPL=$repo/crates/impulse-core/src/tx/testdata/kcc20-asset.json
# 0.03 SOL covers the first run (mint, two token accounts, the seller's fee money and the HTLC's
# rent, which comes back). Modelled from rent figures, not measured.
NEED_LAMPORTS=30000000

case "$CLUSTER" in
  devnet)
    SOL_URL=${SOLANA_RPC_URL:-https://api.devnet.solana.com}
    SOL_EXPLORER_SUFFIX="?cluster=devnet"
    ;;
  localnet)
    SOL_URL=${SOLANA_RPC_URL:-http://127.0.0.1:8899}
    SOL_EXPLORER_SUFFIX="?cluster=custom&customUrl=$SOL_URL"
    ;;
  *) die "CLUSTER must be devnet or localnet" ;;
esac
KAS_EXPLORER=${KAS_EXPLORER:-https://explorer-tn10.kaspa.org/txs}
KAS_EXPLORER_ADDR=${KAS_EXPLORER_ADDR:-https://explorer-tn10.kaspa.org/addresses}

# The impulse-htlc build with D47 (freeze-authority mints accepted), deployed final to devnet on
# 2026-10-13 from solana/programs/impulse-htlc at e0e5f9a (sha256 895dc735...e8f4). The 2026-10-11
# deployment refuses such mints (code 25), so the demo uses this one.
HTLC_PROGRAM=${HTLC_PROGRAM:-B3uLzN2dSnd5tQcEofMDL1z7hSiZXcmFB5TVqGEd6w9z}
if [ -z "${HTLC_PROGRAM:-}" ]; then
  HTLC_PROGRAM=$(sed -n 's/^| impulse-htlc program | \([1-9A-HJ-NP-Za-km-z]*\) .*/\1/p' \
    "$repo/docs/evidence/solana-devnet-2026-10-11/README.md" | head -n 1)
fi
[ -n "$HTLC_PROGRAM" ] || die "no impulse-htlc program ID: set HTLC_PROGRAM"

# ---------------------------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------------------------
if [ -t 1 ]; then B=$(printf '\033[1m'); T=$(printf '\033[36m'); Y=$(printf '\033[33m'); N=$(printf '\033[0m'); else B= T= Y= N=; fi
CUR_STEP=0
step() { CUR_STEP=$1; printf '\n%s== Step %s: %s%s\n' "$B$T" "$1" "$2" "$N"; }
# ev key=value ...: one line of the events file (--events). A key with dots nests (bal.kaspa.seller=4).
# Only public data is ever passed: no call site has the secret or the preimage in scope.
ev() {
  [ -n "$EVENTS" ] || return 0
  python3 -I -c '
import json, os, sys, time
path = sys.argv[1]
n = 0
if os.path.exists(path):
    with open(path, "rb") as f:
        n = sum(1 for _ in f)
rec = {"seq": n + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
for a in sys.argv[2:]:
    k, _, v = a.partition("=")
    if k.startswith("bal.") or k in ("step", "code", "asset_units", "usdc_units"):
        try:
            v = int(v)
        except ValueError:
            v = None
    elif k in ("reveals_secret", "complete"):
        v = v == "true"
    d = rec
    parts = k.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = v
with open(path, "a") as f:
    f.write(json.dumps(rec, separators=(",", ":")) + "\n")
' "$EVENTS" "$@" || true
}
# The start and the end of a step: ev_start <chain> <actor> <text>; ev_done <chain> <actor> <text> [more]
ev_start() { local c=$1 a=$2 t=$3; shift 3; ev phase=started step="$CUR_STEP" chain="$c" actor="$a" text="$t" "$@"; }
ev_done() { local c=$1 a=$2 t=$3; shift 3; ev phase=done step="$CUR_STEP" chain="$c" actor="$a" text="$t" "$@"; }
note() { printf '%s\n' "$*"; }
warn() { printf '%s%s%s\n' "$Y" "$*" "$N"; }
pause() { if [ "$PAUSE" = 1 ]; then ev phase=pause step="$CUR_STEP"; printf '\n[Enter to continue] '; read -r _ || true; fi; }
stop_after() { if [ "$UNTIL" -le "$1" ]; then note "stopping after step $1 (UNTIL=$UNTIL)"; exit 0; fi; }
sol_link() { printf 'https://explorer.solana.com/tx/%s%s' "$1" "$SOL_EXPLORER_SUFFIX"; }
# The lines of a terms summary worth reading on a stage; the whole text is in the work directory.
show_terms() {
  sed -n -E 's/^(hashlock terms|hash_lock|asset|expiry_daa|latest reveal|vault|role check|ok): /\1: /p' |
    cut -c1-200
}
said() { printf '%s>> %s%s\n' "$B" "$*" "$N"; }
KCC_MAX=6
kcc_balance() { # <owner pub>: the test asset units the owner holds on TN10 (the node lists by exact amount)
  local total=0 n
  for n in $(seq "$KCC_MAX"); do
    if [ -n "$("$IMPULSE" token list --node "$NODE" --template "$ASSET_TPL" --owner "$1" --covenant "$ASSET_COV" --amount "$n" 2> /dev/null | sed -n 's/^token: //p' | head -n 1)" ]; then total=$((total + n)); fi
  done
  echo "$total"
}
usdc() { "$HTLC_TOOL" balance --url "$SOL_URL" --owner "$1" --mint "$MINT"; }
bal_vals() { # reads the four balances into BAL_KS BAL_KB BAL_US BAL_UB
  BAL_KS=$(kcc_balance "$SELLER_PUB"); BAL_KB=$(kcc_balance "$BUYER_PUB")
  BAL_US=$(usdc "$SOL_SELLER"); BAL_UB=$(usdc "$SOL_BUYER")
}
BAL_READY=
balances() { # <label>; "before" reuses the reading taken for the ready event
  if [ -z "$BAL_READY" ] || [ "$1" != before ]; then bal_vals; fi
  note "balances $1:"
  note "  TN10    test KCC-20   seller $BAL_KS   buyer $BAL_KB"
  note "  $CLUSTER  test USDC     seller $BAL_US (base units)   buyer $BAL_UB"
}
bal_args() { printf '%s\n' "bal.kaspa.seller=$BAL_KS" "bal.kaspa.buyer=$BAL_KB" "bal.solana.seller=$BAL_US" "bal.solana.buyer=$BAL_UB"; }
kas_link() { printf '%s/%s' "$KAS_EXPLORER" "$1"; }

# The permission bits of a file, in octal. GNU stat first: GNU `stat -f` is file system status
# and succeeds with other output, while BSD and macOS `stat -c` fails and falls through.
perm() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
private_file() { # <file> <what>
  [ -f "$1" ] || die "$2: $1 does not exist"
  case "$(perm "$1")" in 600 | 400) ;; *) die "$2: $1 must be mode 0600 (chmod 600 it)" ;; esac
}

# ---------------------------------------------------------------------------------------------
# Step 0: tools, keys, balances, node, program
# ---------------------------------------------------------------------------------------------
step 0 "preflight"
ev phase=boot step=0 chain=both actor=both text="Starting. Checking the tools, the keys, the balances and both networks."
for t in solana solana-keygen curl python3 od sed; do command -v "$t" > /dev/null || die "$t not on PATH"; done
[ -x "$IMPULSE" ] || die "$IMPULSE not built: cargo build --locked --release -p impulse-cli"
[ -x "$HTLC_TOOL" ] || die "$HTLC_TOOL not built: (cd solana && cargo build --locked --release -p impulse-htlc-demo)"

mkdir -p -m 700 "$KEYS"
for k in seller buyer authority; do private_file "$KEYS/tn10-$k.key" "TN10 $k key"; done
mkkey() { # create a devnet key file silently if absent; never print it
  if [ ! -e "$1" ]; then
    (umask 077; solana-keygen new --no-bip39-passphrase --silent -o "$1" > /dev/null 2>&1) \
      || die "could not create $1"
    chmod 600 "$1"
    note "created $1 (mode 0600, not shown)"
  fi
  private_file "$1" "devnet key"
}
for k in seller buyer issuer; do mkkey "$KEYS/devnet-$k.json"; done

kinfo() { "$IMPULSE" key show --key-file "$KEYS/tn10-$1.key"; }
SELLER_PUB=$(field public_key "$(kinfo seller)")
BUYER_PUB=$(field public_key "$(kinfo buyer)")
SELLER_ADDR=$(field address "$(kinfo seller)")
BUYER_ADDR=$(field address "$(kinfo buyer)")
AUTH_PUB=$(field public_key "$(kinfo authority)")
AUTH_ADDR=$(field address "$(kinfo authority)")
SOL_SELLER=$(solana-keygen pubkey "$KEYS/devnet-seller.json")
SOL_BUYER=$(solana-keygen pubkey "$KEYS/devnet-buyer.json")
note "kaspa seller   $SELLER_ADDR"
note "kaspa buyer    $BUYER_ADDR"
note "kaspa payer    $AUTH_ADDR   (the third key: pays the fee of the Kaspa claim, which anyone may submit)"
note "solana seller  $SOL_SELLER"
note "solana buyer   $SOL_BUYER   <- the one account that needs $CLUSTER SOL"

lamports() { solana balance "$1" --url "$SOL_URL" --lamports 2> /dev/null | awk '{print $1}'; }
bal=$(lamports "$SOL_BUYER" || true)
bal=${bal:-0}
if [ "$bal" -lt "$NEED_LAMPORTS" ] && [ "$CLUSTER" != devnet ]; then
  solana airdrop 2 "$SOL_BUYER" --url "$SOL_URL" > /dev/null 2>&1 || true
  bal=$(lamports "$SOL_BUYER" || echo 0)
fi
if [ "$bal" -lt "$NEED_LAMPORTS" ] && [ "$CLUSTER" = devnet ]; then
  solana airdrop 1 "$SOL_BUYER" --url "$SOL_URL" > /dev/null 2>&1 || true
  bal=$(lamports "$SOL_BUYER" || echo 0)
fi
note "solana buyer balance: $bal lamports (needs $NEED_LAMPORTS on $CLUSTER)"
if [ "$bal" -lt "$NEED_LAMPORTS" ]; then
  warn "FUND THIS ADDRESS on $CLUSTER with at least 0.03 SOL, 0.1 SOL for margin:"
  warn "  $SOL_BUYER"
  warn "  https://faucet.solana.com  (network: Devnet), or: solana airdrop 1 $SOL_BUYER --url devnet"
  exit 3
fi

if [ -z "${NODE:-}" ] && "$IMPULSE" tip --node ws://127.0.0.1:17210 > /dev/null 2>&1; then
  NODE=ws://127.0.0.1:17210 # the local TN10 node, when one runs
fi
if [ -z "${NODE:-}" ]; then
  NODE=$(curl -s -m 15 https://eric.kaspa.stream/v2/kaspa/testnet-10/tls/wrpc/borsh | sed -n 's/.*"url":"\([^"]*\)".*/\1/p' || true)
  [ -n "$NODE" ] || NODE=$(curl -s -m 15 https://john.kaspa.red/v2/kaspa/testnet-10/tls/wrpc/borsh | sed -n 's/.*"url":"\([^"]*\)".*/\1/p' || true)
fi
[ -n "${NODE:-}" ] || die "no TN10 node: set NODE=wss://... (a public resolver did not answer)"
tip=$("$IMPULSE" tip --node "$NODE") || die "the TN10 node $NODE did not answer"
note "kaspa node     $NODE"
note "$(printf '%s\n' "$tip" | sed -n 's/^network: /  network: /p;s/^synced: /  synced: /p;s/^virtual_daa_score: /  daa: /p' | tr '\n' ' ')"

W=${WORKDIR:-$HOME/impulse-runs/xchain-demo-$(date -u +%Y%m%dT%H%M%SZ)}
STATE=${STATE_DIR:-$HOME/impulse-runs/xchain-demo-state}
mkdir -p -m 700 "$STATE"
if [ "$mode" = run ] || [ "$mode" = refund ]; then [ ! -e "$W" ] || die "$W exists: one trade per work directory"; fi
LOG=${W}/log
SOL_ARGS="--url $SOL_URL"

ids=$("$HTLC_TOOL" ids --url "$SOL_URL" --program "$HTLC_PROGRAM" \
  --buyer-key "$KEYS/devnet-buyer.json" --seller-key "$KEYS/devnet-seller.json" 2>&1) \
  || die "the Solana cluster or program check failed: $ids"
CHAIN_ID=$(field chain_id "$ids")
PROGRAM_HEX=$(field program "$ids")
note "solana program $HTLC_PROGRAM (on $CLUSTER, executable)"
if [ "$mode" = preflight ]; then
  note ""
  note "preflight: ok. Nothing was spent."
  exit 0
fi

step 0b "one-time setup (idempotent): test USDC on Solana, test asset on TN10"
# The test USDC mint and the token accounts: created on the first run, reused after.
setup=$("$HTLC_TOOL" setup --url "$SOL_URL" --buyer-key "$KEYS/devnet-buyer.json" \
  --seller-key "$KEYS/devnet-seller.json" --issuer-key "$KEYS/devnet-issuer.json" \
  --state "$STATE/mint-$CLUSTER.txt") || die "test USDC setup failed"
MINT=$(field mint "$setup")
[ -n "$MINT" ] || die "no mint"
ids=$("$HTLC_TOOL" ids --url "$SOL_URL" --program "$HTLC_PROGRAM" --mint "$MINT" \
  --buyer-key "$KEYS/devnet-buyer.json" --seller-key "$KEYS/devnet-seller.json")
ASSET_HEX=$(field asset "$ids")
SELLER_ACCT=$(field seller_account "$ids")
BUYER_ACCT=$(field buyer_account "$ids")
note "test USDC mint $MINT (a test token, not Circle's USDC)"
note "test USDC: buyer $(field buyer_usdc "$setup"), seller $(field seller_usdc "$setup") base units"

# The seller's KCC-20 test asset on TN10: reuse the token recorded by an earlier run if the node
# still lists it, else mint a fresh one with the testnet token helper.
TOKFILE=$STATE/tn10-token.txt
ASSET_COV= TOKEN_UNITS=0
if [ -f "$TOKFILE" ]; then
  ASSET_COV=$(field covenant "$(cat "$TOKFILE")")
  TOKEN_UNITS=$(field units "$(cat "$TOKFILE")")
fi
find_token() { # <covenant> <units>: prints txid:index:units, or nothing
  "$IMPULSE" token list --node "$NODE" --template "$ASSET_TPL" --owner "$SELLER_PUB" \
    --covenant "$1" --amount "$2" 2> /dev/null | sed -n 's/^token: //p' | head -n 1
}
TOKEN=
if hex32 "$ASSET_COV" && [ "$TOKEN_UNITS" -ge "$ASSET_UNITS" ]; then
  TOKEN=$(find_token "$ASSET_COV" "$TOKEN_UNITS" || true)
fi
if [ -z "$TOKEN" ]; then
  note "the seller holds no test asset on TN10: minting 6 units with the testnet token helper"
  mintdir=$STATE/mint-$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -m 700 -p "$mintdir"
  "$IMPULSE" token mint build --node "$NODE" --template "$ASSET_TPL" --owner "$SELLER_PUB" \
    --pay-from "$SELLER_ADDR" --amount 6 --out "$mintdir/m.ipst" > "$mintdir/m.out" \
    || die "token mint build failed (does the seller address hold TN10 KAS? $SELLER_ADDR)"
  "$IMPULSE" ipst sign --ipst "$mintdir/m.ipst" --terms-hash "$(field terms_hash "$(cat "$mintdir/m.out")")" \
    --key-file "$KEYS/tn10-seller.key" --role payer --my-key "$SELLER_PUB" --node "$NODE" \
    --asset-template "$ASSET_TPL" --out "$mintdir/m.signed" >> "$mintdir/m.out" || die "token mint sign failed"
  "$IMPULSE" submit --ipst "$mintdir/m.signed" --node "$NODE" --asset-template "$ASSET_TPL" >> "$mintdir/m.out" \
    || die "token mint submit failed"
  ASSET_COV=$(sed -n 's/^covenant: //p' "$mintdir/m.out" | head -n 1)
  hex32 "$ASSET_COV" || die "no covenant ID in the mint output"
  TOKEN_UNITS=6
  for _ in $(seq 60); do
    TOKEN=$(find_token "$ASSET_COV" "$TOKEN_UNITS" || true)
    [ -n "$TOKEN" ] && break
    sleep 2
  done
  [ -n "$TOKEN" ] || die "the node did not list the new token in 120 s: run again"
  printf 'covenant: %s\nunits: %s\n' "$ASSET_COV" "$TOKEN_UNITS" > "$TOKFILE"
  note "minted: $(field submitted "$(cat "$mintdir/m.out")") (TN10)"
fi
note "kaspa test asset: covenant ${ASSET_COV}, $TOKEN_UNITS units at ${TOKEN%%:*}"

if [ "$mode" = prepare ]; then
  note ""
  note "prepare: ok. Spent on the first run only: the mint, two token accounts and the seller's fee money on Solana; 2 KAS carrier and the fee on TN10."
  exit 0
fi
mkdir -m 700 -p "$W"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then ev phase=error step="$CUR_STEP" text="The demo stopped with an error. Read the terminal." code="$rc"; fi' EXIT
exec > >(tee -a "$LOG") 2>&1
note "work directory $W (public data and the secret file only; the secret is never printed)"
if [ -n "$EVENTS" ]; then
  bal_vals
  BAL_READY=1
  ev phase=ready step=0 chain=both actor=both text="Ready. A test asset on Kaspa TN10 against test USDC on Solana $CLUSTER, one shared hash lock." \
    cluster="$CLUSTER" kaspa_network=TN10 solana_program="$HTLC_PROGRAM" usdc_mint="$MINT" asset_covenant="$ASSET_COV" \
    kaspa_seller="$SELLER_ADDR" kaspa_buyer="$BUYER_ADDR" solana_seller="$SOL_SELLER" solana_buyer="$SOL_BUYER" \
    asset_units="$ASSET_UNITS" usdc_units="$USDC_UNITS" $(bal_args)
fi
pause

# ---------------------------------------------------------------------------------------------
# Step 1: the seller makes the secret and the Kaspa hashlock vault
# ---------------------------------------------------------------------------------------------
step 1 "SELLER makes the secret and the Kaspa hashlock vault"
ev_start kaspa seller "The seller makes a secret and works out the vault address that only its hash can open."
balances "before"
KS_START=$BAL_KS KB_START=$BAL_KB US_START=$BAL_US UB_START=$BAL_UB
now=$("$HTLC_TOOL" now --url "$SOL_URL")
T_C=$((now + TIMEOUT_IN))
daa=$(field virtual_daa_score "$("$IMPULSE" tip --node "$NODE")")
info=$("$IMPULSE" token info --template "$ASSET_TPL")
EXPIRY_DAA=$((daa + 864000))
cat > "$W/hashlock.draft" << EOF
{"version":1,"network":"testnet","seller_key":"$SELLER_PUB","buyer_key":"$BUYER_PUB",
 "asset_leg":{"kind":"kcc20","covenant_id":"$ASSET_COV","template_hash":"$(field template_hash "$info")","template_prefix_len":$(field template_prefix_len "$info"),"template_suffix_len":$(field template_suffix_len "$info"),"amount":"$ASSET_UNITS"},
 "buyer_delivery":{"identifier_type":"pubkey","identifier":"$BUYER_PUB"},
 "seller_refund":{"identifier_type":"pubkey","identifier":"$SELLER_PUB"},
 "expiry_daa":"$EXPIRY_DAA",
 "counterpart":{"chain":"solana","chain_id":"$CHAIN_ID","htlc_program":"$PROGRAM_HEX","asset":"$ASSET_HEX","amount":"$USDC_UNITS","recipient":"$SELLER_ACCT","refund":"$BUYER_ACCT","timeout":"$T_C"},
 "trade_ref":"$(random_ref)"}
EOF
terms=$W/hashlock.terms
note "\$ impulse xchain new --draft hashlock.draft --secret-out seller.secret --out hashlock.terms ..."
new_out=$("$IMPULSE" xchain new --draft "$W/hashlock.draft" --my-key "$SELLER_PUB" \
  --my-counterpart-account "$SELLER_ACCT" --node "$NODE" --counterpart-final-secs "$FINAL_SECS" \
  --known-hashes "$W/seller.known" --kas-equivalent "$KAS_EQUIVALENT" \
  --secret-out "$W/seller.secret" --out "$terms") || die "xchain new failed"
printf '%s\n' "$new_out" > "$W/new.out"
printf '%s\n' "$new_out" | show_terms
HASH_LOCK=$(field hash_lock "$(printf '%s\n' "$new_out")")
if [ -z "$HASH_LOCK" ]; then
  # The summary names the hash lock on a line of its own in some builds; fall back to the file.
  HASH_LOCK=$(sed -n 's/.*"hash_lock" *: *"\([0-9a-f]\{64\}\)".*/\1/p' "$terms" | head -n 1)
fi
hex32 "$HASH_LOCK" || die "could not read the hash lock from the terms"
note ""
said "On Kaspa TN10 nothing is on chain yet: the seller made a secret (kept in a file, never shown) and the vault address that only its hash can open."
VAULT_ADDR=$(sed -n 's/^vault: \(kaspatest:[a-z0-9]*\).*/\1/p' "$W/new.out" | head -n 1)
note "vault explorer: $KAS_EXPLORER_ADDR/$VAULT_ADDR"
ev_done kaspa seller "The seller made a secret and the vault address that only its hash can open. The secret never leaves the seller's machine." \
  hash_lock="$HASH_LOCK" vault="$VAULT_ADDR" url="$KAS_EXPLORER_ADDR/$VAULT_ADDR" expiry_daa="$(field expiry_daa "$new_out" | cut -d' ' -f1)"
note "secret: written to seller.secret (mode $(perm "$W/seller.secret")), not shown"
note "hash_lock: $HASH_LOCK"
stop_after 1
pause

# ---------------------------------------------------------------------------------------------
# Step 2: the buyer checks the terms
# ---------------------------------------------------------------------------------------------
step 2 "BUYER checks the terms before locking anything"
ev_start offchain buyer "The buyer checks the terms before locking anything."
note "\$ impulse xchain verify --terms hashlock.terms ..."
verify_out=$("$IMPULSE" xchain verify --terms "$terms" --my-key "$BUYER_PUB" --my-counterpart-account "$BUYER_ACCT" \
  --node "$NODE" --counterpart-final-secs "$FINAL_SECS" --known-hashes "$W/buyer.known" \
  --kas-equivalent "$KAS_EQUIVALENT") || die "xchain verify failed"
printf '%s\n' "$verify_out" > "$W/verify.out"
printf '%s\n' "$verify_out" | show_terms
said "Off chain: the buyer checked the terms bind the delivery to the buyer's key and the refund to the buyer's Solana account. Nothing was sent."
ev_done offchain buyer "The buyer checked that delivery goes to the buyer and the refund goes to the buyer's Solana account. Nothing was sent." hash_lock="$HASH_LOCK"
stop_after 2
pause

# ---------------------------------------------------------------------------------------------
# Step 3: the seller funds the Kaspa vault
# ---------------------------------------------------------------------------------------------
step 3 "SELLER funds the Kaspa vault with the asset (TN10)"
ev_start kaspa seller "The seller locks the asset in the Kaspa vault."
note "\$ impulse xchain fund build / sign / submit ..."
"$IMPULSE" xchain fund build --terms "$terms" --node "$NODE" --my-key "$SELLER_PUB" \
  --counterpart-final-secs "$FINAL_SECS" --pay-from "$SELLER_ADDR" --asset-template "$ASSET_TPL" \
  --token "$TOKEN" --kas-equivalent "$KAS_EQUIVALENT" --out "$W/fund.ipst" > "$W/fund.build.out" \
  || die "xchain fund build failed"
"$IMPULSE" xchain sign --ipst "$W/fund.ipst" --terms "$terms" --key-file "$KEYS/tn10-seller.key" \
  --role seller --my-key "$SELLER_PUB" --node "$NODE" --asset-template "$ASSET_TPL" \
  --counterpart-final-secs "$FINAL_SECS" --kas-equivalent "$KAS_EQUIVALENT" \
  --out "$W/fund.signed" > "$W/fund.sign.out" || die "xchain sign (fund) failed"
"$IMPULSE" xchain submit --ipst "$W/fund.signed" --node "$NODE" --asset-template "$ASSET_TPL" > "$W/fund.out" \
  || die "xchain submit (fund) failed"
FUND_TX=$(field submitted "$(cat "$W/fund.out")")
FUND_BLOCK=$(field from_block "$(cat "$W/fund.out")")
said "On Kaspa TN10 the seller locked 1 unit of the test KCC-20 asset in the hashlock vault."
note "kaspa funding txid: $FUND_TX"
note "                    $(kas_link "$FUND_TX")"
ev_done kaspa seller "The seller locked 1 unit of the test asset in the vault on Kaspa TN10." txid="$FUND_TX" url="$(kas_link "$FUND_TX")" \
  vault="$VAULT_ADDR" hash_lock="$HASH_LOCK" amount="$ASSET_UNITS"
warn "production waits for this funding to reach the finality depth (D18: 600 DAA, about a minute) before the buyer locks. The demo waits only for the node to list it."
# Record the token left in the seller's hands for the next run.
printf 'covenant: %s\nunits: %s\n' "$ASSET_COV" "$((TOKEN_UNITS - ASSET_UNITS))" > "$TOKFILE"
stop_after 3
pause

# ---------------------------------------------------------------------------------------------
# Step 4: the buyer opens the Solana HTLC
# ---------------------------------------------------------------------------------------------
step 4 "BUYER opens the Solana HTLC with the same hash ($CLUSTER)"
ev_start solana buyer "The buyer locks test USDC on Solana under the same hash."
OPEN_TIMEOUT=$T_C
if [ "$mode" = refund ]; then OPEN_TIMEOUT=$(( $("$HTLC_TOOL" now --url "$SOL_URL") + ${SOL_REFUND_SECS:-60} )); fi
note "\$ impulse-htlc-demo open --hash $HASH_LOCK --amount $USDC_UNITS --timeout $OPEN_TIMEOUT ..."
open_out=$("$HTLC_TOOL" open --url "$SOL_URL" --funder-key "$KEYS/devnet-buyer.json" \
  --program "$HTLC_PROGRAM" --mint "$MINT" --hash "$HASH_LOCK" --amount "$USDC_UNITS" --timeout "$OPEN_TIMEOUT" \
  --recipient "$SELLER_ACCT" --refund "$BUYER_ACCT") || die "open failed"
OPEN_TX=$(field txid "$open_out")
HTLC_ADDR=$(field htlc "$open_out")
printf '%s\n' "$open_out"
said "On Solana $CLUSTER the buyer locked $USDC_UNITS base units (0.1) of test USDC in the HTLC, under the same hash."
note "solana open txid: $OPEN_TX"
note "                  $(sol_link "$OPEN_TX")"
ev_done solana buyer "The buyer locked 0.1 test USDC on Solana $CLUSTER, under the same hash." txid="$OPEN_TX" url="$(sol_link "$OPEN_TX")" \
  htlc="$HTLC_ADDR" escrow="$(field escrow "$open_out")" hash_lock="$HASH_LOCK" amount="$USDC_UNITS"
stop_after 4
pause

# ---------------------------------------------------------------------------------------------
# The refund path (mode refund): nobody claims; each side takes its own lock home after its expiry
# ---------------------------------------------------------------------------------------------
if [ "$mode" = refund ]; then
  step 5 "BUYER refunds the Solana HTLC after its timeout ($CLUSTER)"
  ev_start solana buyer "Nobody claims. The buyer waits for the HTLC timeout and takes the test USDC home."
  note "\$ impulse-htlc-demo refund --payer-key devnet-buyer.json ...   (refused before the timeout)"
  early=$("$HTLC_TOOL" refund --url "$SOL_URL" --payer-key "$KEYS/devnet-buyer.json" --program "$HTLC_PROGRAM" \
    --mint "$MINT" --funder "$SOL_BUYER" --hash "$HASH_LOCK" 2>&1) \
    && die "the Solana refund was accepted before the timeout: $early"
  note "before the timeout the program refuses the refund, as it should"
  refunded=
  for _ in $(seq "$(( ${SOL_REFUND_SECS:-60} + 120 ))"); do
    if ref_out=$("$HTLC_TOOL" refund --url "$SOL_URL" --payer-key "$KEYS/devnet-buyer.json" --program "$HTLC_PROGRAM" \
      --mint "$MINT" --funder "$SOL_BUYER" --hash "$HASH_LOCK" 2> /dev/null); then refunded=1; break; fi
    printf '.'
    sleep 2
  done
  echo
  [ -n "$refunded" ] || die "the Solana refund was not accepted after the timeout"
  SOL_REFUND_TX=$(field txid "$ref_out")
  printf '%s\n' "$ref_out"
  said "On Solana $CLUSTER the buyer took the test USDC home after the timeout."
  note "solana refund txid: $SOL_REFUND_TX"
  note "                    $(sol_link "$SOL_REFUND_TX")"
  ev_done solana buyer "The buyer took the test USDC home after the timeout." txid="$SOL_REFUND_TX" url="$(sol_link "$SOL_REFUND_TX")" \
    hash_lock="$HASH_LOCK" amount="$USDC_UNITS"

  step 6 "SELLER refunds the Kaspa vault after expiry_daa (TN10)"
  ev_start kaspa seller "The seller waits for expiry_daa and takes the asset home from the vault."
  note "\$ impulse xchain refund --signer seller / sign / submit ...   (valid from expiry_daa $EXPIRY_DAA)"
  waited=0
  while :; do
    cur=$(field virtual_daa_score "$("$IMPULSE" tip --node "$NODE")")
    [ "$cur" -ge "$EXPIRY_DAA" ] && break
    if [ -n "${ADVANCE_NODE_CMD:-}" ]; then eval "$ADVANCE_NODE_CMD" > /dev/null; continue; fi
    if [ "$waited" -ge "${REFUND_WAIT_SECS:-600}" ]; then
      warn "expiry_daa $EXPIRY_DAA is not reached (the node is at $cur) after ${REFUND_WAIT_SECS:-600} s."
      warn "Solana refund is done. Finish the Kaspa side from $W once the node passes expiry_daa:"
      warn "  impulse xchain refund --terms $terms --node $NODE --signer seller --asset-template $ASSET_TPL ... (spec/V2.md, xchain refund), then sign and submit"
      exit 4
    fi
    sleep 5
    waited=$((waited + 5))
  done
  "$IMPULSE" xchain refund --terms "$terms" --node "$NODE" --signer seller --asset-template "$ASSET_TPL" \
    --pay-from "$SELLER_ADDR" --kas-equivalent "$KAS_EQUIVALENT" --out "$W/refund.ipst" > "$W/refund.build.out" \
    || die "xchain refund failed"
  "$IMPULSE" xchain sign --ipst "$W/refund.ipst" --terms "$terms" --key-file "$KEYS/tn10-seller.key" \
    --role seller --my-key "$SELLER_PUB" --node "$NODE" --asset-template "$ASSET_TPL" \
    --kas-equivalent "$KAS_EQUIVALENT" --out "$W/refund.signed" > "$W/refund.sign.out" || die "xchain sign (refund) failed"
  "$IMPULSE" xchain submit --ipst "$W/refund.signed" --node "$NODE" --asset-template "$ASSET_TPL" > "$W/refund.out" \
    || die "xchain submit (refund) failed"
  KAS_REFUND_TX=$(field submitted "$(cat "$W/refund.out")")
  said "On Kaspa TN10 the seller took the test asset home from the vault after expiry_daa."
  note "kaspa refund txid: $KAS_REFUND_TX"
  note "                   $(kas_link "$KAS_REFUND_TX")"
  ev_done kaspa seller "The seller took the asset home from the vault after expiry_daa." txid="$KAS_REFUND_TX" \
    url="$(kas_link "$KAS_REFUND_TX")" vault="$VAULT_ADDR" hash_lock="$HASH_LOCK"

  step 7 "SUMMARY (refund path)"
  home=
  for _ in $(seq 40); do
    bal_vals
    if [ "$BAL_KS" = "$KS_START" ] && [ "$BAL_UB" = "$UB_START" ]; then home=1; break; fi
    sleep 1 # the node lists the refunded token once a block accepts the refund
  done
  balances "after"
  [ -n "$home" ] || die "the balances did not return: seller KCC-20 $KS_START -> $BAL_KS, buyer USDC $UB_START -> $BAL_UB"
  [ "$BAL_KB" = "$KB_START" ] && [ "$BAL_US" = "$US_START" ] || die "the counterparties' balances moved: buyer KCC-20 $KB_START -> $BAL_KB, seller USDC $US_START -> $BAL_US"
  note "balances are back where they were: seller KCC-20 $BAL_KS, buyer test USDC $BAL_UB (base units); the other two did not move"
  {
    echo "hash_lock $HASH_LOCK"
    echo "kaspa  fund    $FUND_TX   $(kas_link "$FUND_TX")"
    echo "solana open    $OPEN_TX   $(sol_link "$OPEN_TX")"
    echo "solana refund  $SOL_REFUND_TX   $(sol_link "$SOL_REFUND_TX")"
    echo "kaspa  refund  $KAS_REFUND_TX   $(kas_link "$KAS_REFUND_TX")"
  } | tee "$W/evidence.txt"
  note "refund path complete. Test coins only; nobody claimed, both sides took their own lock home."
  ev phase=complete step=7 chain=both actor=both complete=false hash_lock="$HASH_LOCK" text="Refund path complete: nobody claimed and both sides took their own lock home." $(bal_args)
  note "evidence: $W/evidence.txt"
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Step 5: the seller checks the HTLC and claims it
# ---------------------------------------------------------------------------------------------
step 5 "SELLER checks the Solana HTLC, then claims it and so reveals the secret"
ev_start solana seller "The seller checks the Solana escrow against the terms, then claims it."
SRC="solana+$SOL_URL#program=$HTLC_PROGRAM&funder=$SOL_BUYER"
note "\$ impulse xchain verify-counterpart --terms hashlock.terms --counterpart solana+<rpc>#program=... (waits for counterpart-final)"
vc=
for _ in $(seq 60); do
  if vc=$("$IMPULSE" xchain verify-counterpart --terms "$terms" --counterpart "$SRC" \
    --counterpart-final-secs "$FINAL_SECS" 2>&1); then
    break
  fi
  vc_failed=$vc
  vc=
  printf '.'
  sleep 3
done
echo
[ -n "$vc" ] || die "verify-counterpart did not pass: ${vc_failed:-no output}"
printf '%s\n' "$vc" | sed -n '/^counterpart lock:/p;/^warning:/p;/^ok:/p'
ev phase=info step=5 chain=solana actor=seller text="The seller checked that the escrow matches the terms and is final." htlc="$HTLC_ADDR"
case "$vc" in
  *"freeze authority"*)
    ev phase=warning step=5 chain=solana actor=seller \
      text="This test token has a freeze authority, as real USDC does. The issuer could freeze the escrow. The seller trusts it not to." \
      freeze_authority="$(printf '%s\n' "$vc" | sed -n 's/^warning: mint [^ ]* has a freeze authority, \([1-9A-HJ-NP-Za-km-z]*\)\..*/\1/p' | head -n 1)"
    ;;
esac
before=$("$HTLC_TOOL" balance --url "$SOL_URL" --owner "$SOL_SELLER" --mint "$MINT")
note ""
note "\$ impulse-htlc-demo claim --secret-file seller.secret ...   (the secret is read from the file, never printed)"
claim_out=$("$HTLC_TOOL" claim --url "$SOL_URL" --payer-key "$KEYS/devnet-seller.json" \
  --program "$HTLC_PROGRAM" --mint "$MINT" --funder "$SOL_BUYER" --hash "$HASH_LOCK" \
  --secret-file "$W/seller.secret" --expect-amount "$USDC_UNITS" --dest-owner "$SOL_SELLER") \
  || die "the Solana claim failed (it reads the live HTLC first and refuses another amount, another recipient or a timeout within its claim lead)"
CLAIM_TX=$(field txid "$claim_out")
said "On Solana $CLUSTER the seller claimed the test USDC. The claim transaction carries the secret in public."
note "solana claim txid: $CLAIM_TX"
note "                   $(sol_link "$CLAIM_TX")"
after=$("$HTLC_TOOL" balance --url "$SOL_URL" --owner "$SOL_SELLER" --mint "$MINT")
note "seller test USDC: $before -> $after base units"
ev_done solana seller "The seller claimed the USDC. The claim carries the secret on a public chain, so now anyone can read it." txid="$CLAIM_TX" \
  url="$(sol_link "$CLAIM_TX")" reveals_secret=true hash_lock="$HASH_LOCK" htlc="$HTLC_ADDR"
stop_after 5
pause

# ---------------------------------------------------------------------------------------------
# Step 6: the buyer reads the secret from Solana and claims on Kaspa
# ---------------------------------------------------------------------------------------------
step 6 "BUYER reads the secret from Solana and claims the asset on Kaspa (TN10)"
ev_start kaspa buyer "The buyer reads the revealed secret from Solana and uses it on Kaspa."
note "\$ impulse xchain watch --terms hashlock.terms --counterpart solana+<rpc>#program=... --secret-out buyer.preimage"
watch_out=$("$IMPULSE" xchain watch --terms "$terms" --counterpart "$SRC" --secret-out "$W/buyer.preimage" \
  --polls 40 --interval-secs 3) || die "watch found no counterpart-final reveal"
printf '%s\n' "$watch_out" | sed -n 's/^reveal: /reveal: /p;s/^preimage: .*\/\([a-z.]*\) (mode/preimage: written to \1 (mode/p'
note ""
note "\$ impulse xchain claim / sign / submit ..."
built=
for _ in $(seq 40); do
  if "$IMPULSE" xchain claim --terms "$terms" --node "$NODE" --asset-template "$ASSET_TPL" \
    --secret-file "$W/buyer.preimage" --pay-from "$AUTH_ADDR" --kas-equivalent "$KAS_EQUIVALENT" \
    --out "$W/claim.ipst" > "$W/claim.build.out" 2> "$W/claim.build.err"; then
    built=1
    break
  fi
  printf '.'
  sleep 3 # the node lists the vault once a block accepts the funding
done
echo
[ -n "$built" ] || die "xchain claim build failed: $(cat "$W/claim.build.err")"
"$IMPULSE" xchain sign --ipst "$W/claim.ipst" --terms "$terms" --key-file "$KEYS/tn10-authority.key" \
  --role payer --my-key "$AUTH_PUB" --node "$NODE" --asset-template "$ASSET_TPL" \
  --kas-equivalent "$KAS_EQUIVALENT" --out "$W/claim.signed" > "$W/claim.sign.out" || die "xchain sign (claim) failed"
"$IMPULSE" xchain submit --ipst "$W/claim.signed" --node "$NODE" --asset-template "$ASSET_TPL" > "$W/claim.out" \
  || die "xchain submit (claim) failed"
KAS_CLAIM_TX=$(field submitted "$(cat "$W/claim.out")")
KAS_CLAIM_BLOCK=$(field from_block "$(cat "$W/claim.out")")
said "On Kaspa TN10 the buyer used the secret from Solana to take the asset out of the vault."
note "kaspa claim txid: $KAS_CLAIM_TX"
note "                  $(kas_link "$KAS_CLAIM_TX")"
ev_done kaspa buyer "The buyer used the secret from Solana to take the asset out of the Kaspa vault." txid="$KAS_CLAIM_TX" \
  url="$(kas_link "$KAS_CLAIM_TX")" vault="$VAULT_ADDR" hash_lock="$HASH_LOCK"
stop_after 6

# ---------------------------------------------------------------------------------------------
# Step 7: the summary
# ---------------------------------------------------------------------------------------------
step 7 "SUMMARY"
# Demo depth (TN10 only): DEMO_DEPTH DAA scores after the claim is accepted, default 60 (about 6 s at
# 10 per second). Impulse's own policy (D18) is 600; `xchain status` below still reports against 600.
DEMO_DEPTH=${DEMO_DEPTH:-60}
ev_start both both "Waiting for the Kaspa claim to be $DEMO_DEPTH score units deep, a few seconds."
note "waiting for the Kaspa claim to be accepted and $DEMO_DEPTH DAA deep (demo depth on TN10; Impulse's policy D18 is 600)"
held=
for _ in $(seq 40); do
  held=$("$IMPULSE" token list --node "$NODE" --template "$ASSET_TPL" --owner "$BUYER_PUB" \
    --covenant "$ASSET_COV" --amount "$ASSET_UNITS" 2> /dev/null | sed -n 's/^token: //p' | head -n 1 || true)
  [ -n "$held" ] && break
  sleep 1 # the node lists the token once a block accepts the claim
done
accepted_daa=$(field virtual_daa_score "$("$IMPULSE" tip --node "$NODE")")
deep=false
for _ in $(seq 120); do
  now_daa=$(field virtual_daa_score "$("$IMPULSE" tip --node "$NODE")")
  if [ -n "$held" ] && [ $((now_daa - accepted_daa)) -ge "$DEMO_DEPTH" ]; then deep=true; break; fi
  sleep 1
done
if $deep; then
  note "kaspa: claim accepted and $((now_daa - accepted_daa)) DAA deep (demo depth $DEMO_DEPTH, in $(( (now_daa - accepted_daa) / 10 )) s or so)"
  status="trade: complete"
else
  note "kaspa: claim not yet $DEMO_DEPTH DAA deep"
  status="trade: not complete"
fi
note "counterpart claim: counterpart-final ($CLAIM_TX)"
note "$status (demo depth $DEMO_DEPTH on TN10)"
balances "after"
if [ -n "$held" ]; then note "buyer now holds the asset on TN10: $held" ; else note "buyer's token not listed yet by the node (it is listed once a block accepts the claim)"; fi
{
  echo "hash_lock $HASH_LOCK"
  echo "kaspa  fund   $FUND_TX   $(kas_link "$FUND_TX")"
  echo "solana open   $OPEN_TX   $(sol_link "$OPEN_TX")"
  echo "solana claim  $CLAIM_TX   $(sol_link "$CLAIM_TX")"
  echo "kaspa  claim  $KAS_CLAIM_TX   $(kas_link "$KAS_CLAIM_TX")"
} | tee "$W/evidence.txt"
note ""
note "Kaspa 'final' here means the claim is $DEMO_DEPTH DAA deep, a demo setting on TN10 (Impulse's production policy D18 is 600, about a minute); neither is a guarantee of the network."
note "Test coins only. Conditional exchange across two chains with residual risk, not atomic settlement."
case "$status" in
  *"trade: complete"*) COMPLETE=true; DONE_TEXT="Trade complete. Test networks, test tokens. A conditional exchange with residual risk, not atomic settlement." ;;
  *) COMPLETE=false; DONE_TEXT="Both claims are sent. The Kaspa claim is not yet $DEMO_DEPTH score units deep. Test networks, test tokens. A conditional exchange with residual risk, not atomic settlement." ;;
esac
ev phase=complete step=7 chain=both actor=both complete="$COMPLETE" hash_lock="$HASH_LOCK" \
  text="$DONE_TEXT" \
  fund_txid="$FUND_TX" fund_url="$(kas_link "$FUND_TX")" open_txid="$OPEN_TX" open_url="$(sol_link "$OPEN_TX")" \
  claim_txid="$CLAIM_TX" claim_url="$(sol_link "$CLAIM_TX")" kaspa_claim_txid="$KAS_CLAIM_TX" kaspa_claim_url="$(kas_link "$KAS_CLAIM_TX")" \
  $(bal_args)
note "evidence: $W/evidence.txt"
