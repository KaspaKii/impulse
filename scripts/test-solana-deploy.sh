#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Self-test of scripts/solana-mainnet-deploy.sh against a LOCAL validator (solana-test-validator,
# throwaway ledger in a temporary directory, removed on exit). It builds, plans, then runs the
# commands the plan PRINTS (with the cluster URL swapped to the local one) with throwaway keypairs
# made at run time in that directory (rule 1 exception, docs/ENGINEERING-RULES.md: never real, never committed,
# never printed), so the printed deploy commands are proven to work as printed, and then runs
# `verify`, a tampered `verify`, a buffer close, and the authority commands. No mainnet, no
# network beyond 127.0.0.1. Needs the pinned Solana CLI (3.1.x) on PATH.
# shellcheck disable=SC2016,SC2034
# (the checks are single-quoted on purpose: `check` evaluates them after the run)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
work=$(mktemp -d)
chmod 700 "$work"
vpid=
cleanup() {
  [ -z "$vpid" ] || { kill "$vpid" 2> /dev/null; wait "$vpid" 2> /dev/null; }
  rm -rf "$work"
}
trap cleanup EXIT
fails=0 checks=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { checks=$((checks + 1)); }
check() { if eval "$2"; then pass; else fail "$1"; fi; }
# For state read back from a just-changed account: the validator may take a moment to show it.
settled() { local i; for i in 1 2 3 4 5 6 7 8 9 10; do eval "$1" && return 0; sleep 1; done; return 1; }
checks_settled() { if settled "$2"; then pass; else fail "$1"; fi; }

for t in solana solana-keygen solana-test-validator shellcheck; do
  command -v "$t" > /dev/null || { echo "test-solana-deploy: $t not on PATH" >&2; exit 1; }
done
D="$here/solana-mainnet-deploy.sh"
shellcheck -x -S warning "$D" "$0" || fail "shellcheck"
out=$work/out
so=$repo/solana/target/deploy/impulse_htlc.so

# --- the script refuses what it should --------------------------------------------------------
"$D" plan --out "$work/none" > /dev/null 2>&1; check "plan without a build record is refused" '[ $? -ne 0 ]'
"$D" bogus > /dev/null 2>&1; check "an unknown stage is a usage error" '[ $? -eq 2 ]'
"$D" verify --out "$out" > /dev/null 2>&1; check "verify needs --program-id" '[ $? -eq 2 ]'

# --- build ------------------------------------------------------------------------------------
if [ ! -f "$so" ]; then
  (cd "$repo/solana/programs/impulse-htlc" && cargo-build-sbf --tools-version v1.52 -- --locked) > /dev/null 2>&1
fi
[ -f "$so" ] || { echo "test-solana-deploy: no $so (cargo-build-sbf failed)" >&2; exit 1; }
rec=$("$D" build --so "$so" --out "$out" 2>&1); rc=$?
check "build records the sha256 and size (rc $rc)" \
  '[ $rc -eq 0 ] && printf "%s\n" "$rec" | grep -Eq "^so_sha256: [0-9a-f]{64}$" && printf "%s\n" "$rec" | grep -Eq "^so_bytes: [0-9]+$"'
want=$(shasum -a 256 "$so" | cut -d' ' -f1)
check "the recorded hash is the hash of the file" 'grep -qx "so_sha256: $want" "$out/build.record"'

# --- a local validator ------------------------------------------------------------------------
port=$((20000 + RANDOM % 20000))
url=http://127.0.0.1:$port
solana-test-validator --reset --quiet --ledger "$work/ledger" --rpc-port "$port" \
  --faucet-port $((port + 1)) --bind-address 127.0.0.1 \
  --gossip-port $((port + 2)) --dynamic-port-range "$((port + 10))-$((port + 60))" \
  > "$work/validator.log" 2>&1 &
vpid=$!
up=
for _ in $(seq 90); do
  if solana cluster-version --url "$url" > /dev/null 2>&1; then up=1; break; fi
  kill -0 "$vpid" 2> /dev/null || break
  sleep 1
done
[ -n "$up" ] || { echo "test-solana-deploy: the local validator did not start"; tail -n 5 "$work/validator.log"; exit 1; }

# --- throwaway keys (silent, in the temporary directory, never shown) ------------------------
for k in payer program authority offline buffer; do
  solana-keygen new --no-bip39-passphrase --silent --force -o "$work/$k.json" > /dev/null 2>&1
done
payer=$(solana-keygen pubkey "$work/payer.json")
pid=$(solana-keygen pubkey "$work/program.json")
offline=$(solana-keygen pubkey "$work/offline.json")
solana airdrop 50 "$payer" --url "$url" > /dev/null 2>&1 || fail "airdrop"

# --- plan -------------------------------------------------------------------------------------
plan=$("$D" plan --out "$out" --url "$url" --program-keypair "$work/program.json" \
  --authority-keypair "$work/authority.json" --payer-keypair "$work/payer.json" \
  --buffer-keypair "$work/buffer.json" --offline-authority "$offline" 2>&1); rc=$?
check "plan exits 0 (rc $rc): $(printf '%s' "$plan" | tail -n 2)" '[ $rc -eq 0 ]'
for f in so_bytes so_sha256 max_len rent_program_data_lamports rent_kept_lamports fees_lamports sol_needed_peak sol_needed_recommended; do
  check "plan prints $f" 'printf "%s\n" "$plan" | grep -q "^$f: "'
done
check "plan marks the fees as modelled" 'printf "%s\n" "$plan" | grep -q "^fees_lamports: .*modelled"'
check "plan prints the deploy, buffer-close, verify-from-repo and finalize commands" \
  'printf "%s\n" "$plan" | grep -q "solana program deploy --url mainnet-beta" && printf "%s\n" "$plan" | grep -q "solana program close --url mainnet-beta" && printf "%s\n" "$plan" | grep -q "solana-verify verify-from-repo" && printf "%s\n" "$plan" | grep -q -- "--final"'
check "the plan did not deploy anything" '! solana program show "$pid" --url "$url" -k "$work/payer.json" > /dev/null 2>&1'
check "plan leaks no key material (no keypair file content)" '! printf "%s\n" "$plan" | grep -q "\[[0-9]*,[0-9]*,"'
check "the plan's rent for the program-data account equals the cluster's" \
  'solana rent $((45 + $(wc -c < "$so" | tr -d " ") * 2)) --url "$url" --lamports | grep -q "$(printf "%s\n" "$plan" | sed -n "s/^rent_program_data_lamports: \([0-9]*\) .*/\1/p")"'

# --- run the printed commands, with the cluster swapped to the local one ----------------------
# Lines that start with "solana " (joined across trailing backslashes), minus the ones for later.
cmds=$(printf '%s\n' "$plan" | sed -e :a -e '/\\$/N; s/\\\n//; ta' | grep -E '^(solana |solana-keygen new )' \
  | sed -e "s#--url mainnet-beta#--url $url#")
runcmd() { # pattern
  local c
  c=$(printf '%s\n' "$cmds" | grep -E -- "$1" | head -n 1)
  [ -n "$c" ] || { fail "no printed command matches $1"; return 1; }
  c=${c//<program-id>/$pid}
  c=${c//<payer-address>/$payer}
  # shellcheck disable=SC2086
  eval "$c" > "$work/cmd.out" 2>&1
  local rc=$?
  [ $rc -eq 0 ] || { echo "--- failed: ${c%%--*}... (rc $rc)"; tail -n 6 "$work/cmd.out" | sed 's/^/    /'; }
  return $rc
}
runcmd '^solana-keygen new .*buffer.json' > /dev/null
check "the printed buffer keypair command refuses to overwrite a keypair (no --force)" '[ $? -ne 0 ]'
runcmd '^solana program write-buffer'
check "the printed write-buffer command works" '[ $? -eq 0 ]'
bufaddr=$(solana-keygen pubkey "$work/buffer.json")
dump=$work/buffer.dump
solana program dump "$bufaddr" "$dump" --url "$url" > /dev/null 2>&1
check "the buffer holds the recorded program" '[ "$(head -c $(wc -c < "$so" | tr -d " ") "$dump" | shasum -a 256 | cut -d" " -f1)" = "$want" ]'
runcmd '^solana program deploy'
check "the printed deploy command works" '[ $? -eq 0 ]'
checks_settled "the program is deployed to the program keypair's ID" 'solana program show "$pid" --url "$url" -k "$work/payer.json" 2>&1 | grep -q "Program Id: $pid"'
checks_settled "the upgrade authority is the authority keypair" \
  'solana program show "$pid" --url "$url" -k "$work/payer.json" | grep -q "Authority: $(solana-keygen pubkey "$work/authority.json")"'

# --- verify -----------------------------------------------------------------------------------
v=$("$D" verify --program-id "$pid" --out "$out" --url "$url" 2>&1); rc=$?
check "verify passes on the deployed build (rc $rc): $(printf '%s' "$v" | tail -n 2)" \
  '[ $rc -eq 0 ] && printf "%s\n" "$v" | grep -q "^ok: the deployed program equals the recorded build"'
cp "$out/build.record" "$work/build.record.good"
sed -i.bak 's/^so_sha256: ./so_sha256: 0/;' "$out/build.record"
v=$("$D" verify --program-id "$pid" --out "$out" --url "$url" 2>&1); rc=$?
check "verify fails on a different recorded hash" '[ $rc -ne 0 ] && printf "%s\n" "$v" | grep -q MISMATCH'
cp "$work/build.record.good" "$out/build.record"
"$D" verify --program-id 11111111111111111111111111111112 --out "$out" --url "$url" > /dev/null 2>&1
check "verify fails for a program that is not deployed" '[ $? -ne 0 ]'

# --- failure recovery: a second buffer is written, then closed with the printed command ------
solana-keygen new --no-bip39-passphrase --silent --force -o "$work/buffer.json" > /dev/null 2>&1
runcmd '^solana program write-buffer'
n=$(solana program show --buffers --url "$url" -k "$work/authority.json" 2>/dev/null | grep -c '^[1-9A-HJ-NP-Za-km-z]\{32,44\} ')
check "a buffer exists before the close (found $n)" '[ "$n" -ge 1 ]'
runcmd '^solana program close .*--buffers'
n=$(solana program show --buffers --url "$url" -k "$work/authority.json" 2>/dev/null | grep -c '^[1-9A-HJ-NP-Za-km-z]\{32,44\} ')
check "the printed close command removes the buffers (left $n)" '[ "$n" -eq 0 ]'

# --- the authority: move it, then make it final ---------------------------------------------
runcmd 'set-upgrade-authority .*--new-upgrade-authority'
check "the printed set-upgrade-authority command works" '[ $? -eq 0 ]'
checks_settled "the authority is now the offline key" 'solana program show "$pid" --url "$url" -k "$work/payer.json" | grep -q "Authority: $offline"'
cmds=$(printf '%s\n' "$cmds" | sed "s#<current-authority-keypair>#$work/offline.json#")
runcmd 'set-upgrade-authority .*--final'
check "the printed --final command works" '[ $? -eq 0 ]'
checks_settled "the program is final (no authority)" 'solana program show "$pid" --url "$url" -k "$work/payer.json" | grep -q "Authority: none"'
v=$("$D" verify --program-id "$pid" --out "$out" --url "$url" 2>&1); rc=$?
check "verify still passes on the final program" '[ $rc -eq 0 ]'

# --- the script never deploys or signs itself ------------------------------------------------
# A logging shim in front of the real `solana`: plan and verify may call only read-only commands,
# and plan must work with key paths that do not exist (it only prints them).
real=$(command -v solana)
mkdir "$work/shim"
printf '#!/bin/sh\necho "$*" >> "%s/solana.log"\nexec "%s" "$@"\n' "$work" "$real" > "$work/shim/solana"
chmod +x "$work/shim/solana"
PATH="$work/shim:$PATH" "$D" plan --out "$out" --url "$url" --program-keypair /nonexistent/a \
  --authority-keypair /nonexistent/b --payer-keypair /nonexistent/c > /dev/null 2>&1
check "plan works with key paths that do not exist" '[ $? -eq 0 ]'
PATH="$work/shim:$PATH" "$D" verify --program-id "$pid" --out "$out" --url "$url" > /dev/null 2>&1
check "the shim saw the read-only calls" '[ -s "$work/solana.log" ]'
check "plan and verify called only read-only solana commands (rent, account, program dump)" \
  '! grep -Ev "^(rent|account|program dump) " "$work/solana.log" | grep -q .'

echo "test-solana-deploy: $checks checks passed, $fails failed"
[ "$fails" -eq 0 ]
