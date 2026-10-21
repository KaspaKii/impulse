#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# I19 devnet run (the first half of the I19 exit test), repeatable by the owner.
#
#   scripts/solana-devnet.sh            devnet (default)
#   CLUSTER=localnet scripts/solana-devnet.sh
#                                       a local solana-test-validator, to try the run offline
#
# What it does, in a temporary directory removed on exit (trap):
#   1. generates throwaway keypairs with solana-keygen: a payer (also the settlement authority),
#      party A, party B, and one program keypair each for impulse-solana and impulse-htlc.
#      No key file is ever printed, logged or copied out of the temporary directory;
#   2. funds the payer: devnet airdrops (devnet only, spaced retries). If the faucet refuses, it
#      prints the payer's public address and waits FAUCET_WAIT seconds (default 0) for the owner
#      to fund it by hand (https://faucet.solana.com), then gives up with exit code 3;
#   3. builds both programs (cargo-build-sbf --tools-version v1.52) and deploys them with
#      --final (not upgradeable; the upgrade authority key is deleted at the end anyway);
#   4. runs solana/programs/impulse-solana-devnet: two test SPL mints (TEST-ASSET, and TEST-USDC,
#      which stands in for USDC and is not USDC), one settlement from the "external-cash" term
#      sheet (CreateDvp, fund A, fund B, SettleDvp), one HTLC open+claim and one open+refund,
#      with exact balance checks after every step;
#   5. writes public data only (program IDs, addresses, transaction signatures, versions,
#      program hashes, raw command output) to docs/evidence/solana-<cluster>-<date>/.
#
# Never mainnet: the URL is fixed per cluster and the runner refuses a mainnet genesis hash.
# Programs are deployed from the committed source; their declare_id! placeholder is not changed
# (neither program compares its own ID; both use the runtime program_id), so the deployed
# addresses are the throwaway program keypairs of this run.
#
# Needs: the Solana CLI (solana-cli 3.1.x with cargo-build-sbf, platform-tools v1.52), e.g.
#   export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

CLUSTER=${CLUSTER:-devnet}
FAUCET_WAIT=${FAUCET_WAIT:-0}
AIRDROP_SOL=${AIRDROP_SOL:-1}
AIRDROP_TRIES=${AIRDROP_TRIES:-6}
SBF_TOOLS_VERSION=v1.52
SHEET=external-cash
DATE=$(date -u +%Y-%m-%d)

fail() { echo "solana-devnet: FAIL: $1" >&2; exit 1; }
for t in solana solana-keygen cargo-build-sbf cargo python3; do
  command -v "$t" >/dev/null || fail "$t not on PATH (see the header of this script)"
done

case "$CLUSTER" in
  devnet) URL=${SOLANA_RPC_URL:-https://api.devnet.solana.com} ;;
  localnet) URL=http://127.0.0.1:8899 ;;
  *) fail "CLUSTER must be devnet or localnet" ;;
esac

ev=${EVIDENCE_DIR:-"$root/docs/evidence/solana-$CLUSTER-$DATE"}
mkdir -p "$ev"
log="$ev/run.log"
: >"$log"
say() { echo "$*" | tee -a "$log"; }
# Runs a command, echoing it and its output into the log. Key files are passed by path only.
# The temporary directory is shown as $TMPDIR_RUN in the log.
run() { say "\$ $(echo "$*" | sed "s|$tmp|\$TMPDIR_RUN|g")"; "$@" 2>&1 | tee -a "$log"; return "${PIPESTATUS[0]}"; }

tmp=$(mktemp -d)
validator_pid=""
# Removes the key files first, whatever happens next; then stops a local validator.
cleanup() {
  rm -rf "$tmp"
  if [ -n "$validator_pid" ]; then
    kill "$validator_pid" 2>/dev/null || true
    wait "$validator_pid" 2>/dev/null || true
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

say "# I19 Solana run, cluster $CLUSTER, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "# $(solana --version)"
say "# $(cargo-build-sbf --version | head -n 1), platform-tools $SBF_TOOLS_VERSION"
say "# git $(git rev-parse HEAD)"

if [ "$CLUSTER" = localnet ]; then
  # Never reuse a validator that is already running (its state and genesis are not this run's).
  solana cluster-version --url "$URL" >/dev/null 2>&1 && fail "something already answers on $URL"
  solana-test-validator --ledger "$tmp/ledger" --quiet --reset >/dev/null 2>&1 &
  validator_pid=$!
  for _ in $(seq 60); do solana cluster-version --url "$URL" >/dev/null 2>&1 && break; sleep 1; done
fi

for k in payer party-a party-b impulse-solana-program impulse-htlc-program; do
  solana-keygen new --no-bip39-passphrase --silent --force -o "$tmp/$k.json" >/dev/null 2>&1
  chmod 600 "$tmp/$k.json"
done
payer=$(solana-keygen pubkey "$tmp/payer.json")
say "# payer (settlement authority) $payer"
say "# party A $(solana-keygen pubkey "$tmp/party-a.json")"
say "# party B $(solana-keygen pubkey "$tmp/party-b.json")"

step() { say ""; say "== $1"; }

step "build programs"
for p in impulse-solana impulse-htlc; do
  (cd "solana/programs/$p" && cargo-build-sbf --tools-version "$SBF_TOOLS_VERSION" -- --locked) \
    >>"$log" 2>&1 || fail "cargo-build-sbf failed for $p (see $log)"
done
so_solana=solana/target/deploy/impulse_solana.so
so_htlc=solana/target/deploy/impulse_htlc.so
run shasum -a 256 "$so_solana" "$so_htlc"
run ls -l "$so_solana" "$so_htlc"

# Peak need: a buffer and the program data account per program (the buffer is refunded after
# each deploy), plus fees, mints, token accounts and the HTLC rent.
rent() { solana rent "$1" --lamports | awk '/Rent-exempt minimum/ {print $3}'; }
need=$(( 2 * $(rent $(( $(wc -c <"$so_solana") + 45 ))) + 2 * $(rent $(( $(wc -c <"$so_htlc") + 45 ))) + 200000000 ))
say "# payer needs at least $need lamports"

step "fund the payer"
balance() {
  local b i
  for i in 1 2 3 4 5; do
    b=$(solana balance "$payer" --url "$URL" --lamports 2>/dev/null | awk '{print $1}')
    [ -n "$b" ] && { echo "$b"; return; }
    sleep 5
  done
  echo 0
}
tries=0
while [ "$(balance)" -lt "$need" ] && [ "$tries" -lt "$AIRDROP_TRIES" ]; do
  tries=$((tries + 1))
  run solana airdrop "$AIRDROP_SOL" "$payer" --url "$URL" || true
  [ "$(balance)" -ge "$need" ] || sleep 20
done
if [ "$(balance)" -lt "$need" ] && [ "$FAUCET_WAIT" -gt 0 ]; then
  say "# faucet refused; fund $payer on $CLUSTER by hand (https://faucet.solana.com),"
  say "# waiting up to $FAUCET_WAIT s"
  end=$(( $(date +%s) + FAUCET_WAIT ))
  while [ "$(balance)" -lt "$need" ] && [ "$(date +%s)" -lt "$end" ]; do sleep 10; done
fi
if [ "$(balance)" -lt "$need" ]; then
  say "$CLUSTER: run pending, faucet rate-limited (payer balance $(balance) lamports, need $need)"
  exit 3
fi
say "# payer balance $(balance) lamports"

step "deploy (--final, not upgradeable)"
# The public devnet RPC rate-limits the buffer writes (429, "Max retries exceeded"). Each
# program gets its own buffer keypair, so a failed attempt is resumed, not paid for again; the
# writes go over TPU (no --use-rpc) and each attempt waits longer before the next.
deploy() {
  local buf="$tmp/buffer-$(basename "$1" .so).json" i
  [ -f "$buf" ] || { solana-keygen new --no-bip39-passphrase --silent --force -o "$buf" >/dev/null 2>&1; chmod 600 "$buf"; }
  for i in 1 2 3 4 5 6; do
    run solana program deploy "$1" --program-id "$2" --buffer "$buf" --keypair "$tmp/payer.json" \
      --url "$URL" --final --max-sign-attempts 50 && return 0
    say "# deploy attempt $i failed; resuming the same buffer after $((i * 20)) s"
    sleep $((i * 20))
  done
  return 1
}
deploy "$so_solana" "$tmp/impulse-solana-program.json" || fail "deploy impulse-solana"
deploy "$so_htlc" "$tmp/impulse-htlc-program.json" || fail "deploy impulse-htlc"
impulse_id=$(solana-keygen pubkey "$tmp/impulse-solana-program.json")
htlc_id=$(solana-keygen pubkey "$tmp/impulse-htlc-program.json")
run solana program show "$impulse_id" --url "$URL" --keypair "$tmp/payer.json"
run solana program show "$htlc_id" --url "$URL" --keypair "$tmp/payer.json"

step "settlement from one term sheet, HTLC claim and refund"
(cd solana && cargo build --locked --release -p impulse-solana-devnet) >>"$log" 2>&1 \
  || fail "build impulse-solana-devnet (see $log)"
run solana/target/release/impulse-solana-devnet \
  --url "$URL" --cluster "$CLUSTER" \
  --payer "$tmp/payer.json" --party-a "$tmp/party-a.json" --party-b "$tmp/party-b.json" \
  --impulse-program "$impulse_id" --htlc-program "$htlc_id" \
  --term-sheets solana/tests/fixtures/term-sheets.json --sheet "$SHEET" \
  --out "$ev/record.json" || fail "the run failed (see $log and $ev/record.json)"

say ""
say "# payer balance left $(balance) lamports (abandoned with the throwaway key)"
say "solana-$CLUSTER: pass"
