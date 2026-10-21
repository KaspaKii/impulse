#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# scripts/solana-mainnet-deploy.sh: prepares, for the key holder, the deploy of the impulse-htlc
# program (solana/programs/impulse-htlc, pinocchio) to Solana mainnet-beta, and checks the result.
# Owner-run (the key holder deploys the program himself).
#
# This script NEVER deploys, signs, funds or submits, and never reads a key file. It builds the
# program, records the sha256 of the .so, reads rent figures from a Solana RPC (read-only), and
# PRINTS the commands the key holder runs on his own machine with his own keypair files. The
# program keypair, the upgrade authority and the fee payer are the key holder's; a path given here
# is only printed into those commands. After the deploy, `verify` reads the chain (read-only) and
# compares the deployed bytes with the recorded build.
#
# Stages:
#   build    verifiable build. With `solana-verify` on PATH: `solana-verify build` (Docker, the
#            reproducible path). Otherwise cargo-build-sbf with the pinned platform-tools v1.52 and
#            Rust 1.91.0 (solana/rust-toolchain.toml), which is repeatable on a machine with the
#            same toolchain but is not a cross-machine reproducible build. Records the sha256,
#            the size and the source commit in <out>/build.record.
#   plan     read <out>/build.record; read the rent from --url (read-only RPC); print the size,
#            the modelled SOL needed, and the deploy commands (printed, not run).
#   verify   read-only: dump the deployed program, compare its sha256 with build.record, print
#            the upgrade authority. Exit 1 on any difference.
#
# Usage:
#   scripts/solana-mainnet-deploy.sh build [--out <dir>] [--so <prebuilt .so>]
#   scripts/solana-mainnet-deploy.sh plan [--out <dir>] [--url <rpc, default mainnet-beta>]
#     [--max-len <bytes, default 2 x the .so size>] [--priority-micro-lamports <n, default 5000>]
#     [--program-keypair <path>] [--authority-keypair <path>] [--payer-keypair <path>]
#     [--buffer-keypair <path>] [--offline-authority <pubkey>]
#   scripts/solana-mainnet-deploy.sh verify --program-id <base58> [--out <dir>]
#     [--url <rpc, default mainnet-beta>]
#
# Default <out> is solana/target/mainnet-deploy. Every figure printed by `plan` other than the
# rent returned by the RPC is modelled (see the notes it prints), not measured.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
. "$here/lib-impulse.sh"

SBF_TOOLS_VERSION=v1.52
MAINNET_URL=https://api.mainnet-beta.solana.com

usage() {
  sed -n '/^# Usage:/,/^# Default <out>/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[ $# -ge 1 ] || usage
stage=$1
shift
out=$repo/solana/target/mainnet-deploy url=$MAINNET_URL prio=5000
so_in='' max_len='' program_id=''
program_kp='<program-keypair>' authority_kp='<authority-keypair>' payer_kp='<payer-keypair>'
buffer_kp='<buffer-keypair>' offline_auth='<offline-authority-pubkey>'
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --out) out=$2 ;;
    --url) url=$2 ;;
    --so) so_in=$2 ;;
    --max-len) max_len=$2 ;;
    --priority-micro-lamports) prio=$2 ;;
    --program-id) program_id=$2 ;;
    --program-keypair) program_kp=$2 ;;
    --authority-keypair) authority_kp=$2 ;;
    --payer-keypair) payer_kp=$2 ;;
    --buffer-keypair) buffer_kp=$2 ;;
    --offline-authority) offline_auth=$2 ;;
    *) usage ;;
  esac
  shift 2
done
record=$out/build.record

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
size() { wc -c < "$1" | tr -d ' '; }
need() { command -v "$1" > /dev/null || die "$1 not on PATH"; }
num() { case "$2" in '' | *[!0-9]*) die "$1 is a decimal number" ;; esac; }

case "$stage" in
  build)
    need shasum
    mkdir -p "$out"
    commit=$(git -C "$repo" rev-parse HEAD)
    dirty=clean
    [ -z "$(git -C "$repo" status --porcelain -- solana)" ] || dirty=DIRTY
    if [ -n "$so_in" ]; then
      [ -f "$so_in" ] || die "$so_in is not a file"
      cp "$so_in" "$out/impulse_htlc.so"
      method="prebuilt (--so)"
    elif command -v solana-verify > /dev/null; then
      need docker
      (cd "$repo/solana" && solana-verify build --library-name impulse_htlc)
      cp "$repo/solana/target/deploy/impulse_htlc.so" "$out/impulse_htlc.so"
      method="solana-verify build (docker)"
    else
      need cargo-build-sbf
      echo "note: solana-verify is not installed: building with cargo-build-sbf $SBF_TOOLS_VERSION; install solana-verify (cargo install solana-verify) and Docker for the reproducible build" >&2
      (cd "$repo/solana/programs/impulse-htlc" && cargo-build-sbf --tools-version "$SBF_TOOLS_VERSION" -- --locked)
      cp "$repo/solana/target/deploy/impulse_htlc.so" "$out/impulse_htlc.so"
      method="cargo-build-sbf $SBF_TOOLS_VERSION"
    fi
    {
      echo "source_commit: $commit"
      echo "source_tree: $dirty"
      echo "build_method: $method"
      echo "so_file: $out/impulse_htlc.so"
      echo "so_bytes: $(size "$out/impulse_htlc.so")"
      echo "so_sha256: $(sha "$out/impulse_htlc.so")"
    } > "$record"
    cat "$record"
    [ "$dirty" = clean ] || echo "warning: solana/ has uncommitted changes; do not publish this hash" >&2
    echo "next: scripts/solana-mainnet-deploy.sh plan"
    ;;

  plan)
    need solana
    [ -f "$record" ] || die "no $record: run the build stage first"
    so=$(field so_file "$(cat "$record")")
    bytes=$(field so_bytes "$(cat "$record")")
    want=$(field so_sha256 "$(cat "$record")")
    [ -f "$so" ] || die "$so is gone: run the build stage again"
    [ "$(sha "$so")" = "$want" ] || die "$so does not match build.record: run the build stage again"
    num "so_bytes" "$bytes"
    [ -n "$max_len" ] || max_len=$((bytes * 2))
    num "--max-len" "$max_len"
    [ "$max_len" -ge "$bytes" ] || die "--max-len is below the program size $bytes"
    num "--priority-micro-lamports" "$prio"
    # Rent, read from the cluster (read-only): the program-data account holds 45 bytes of header
    # and max_len bytes; the program account is 36 bytes; the buffer (37 bytes of header and the
    # program) is refunded when the deploy completes.
    rent() { solana rent "$1" --url "$url" --lamports | sed -n 's/^Rent-exempt minimum: \([0-9]*\) lamports.*/\1/p'; }
    r_pd=$(rent $((45 + max_len))) || die "cannot read the rent from $url"
    r_prog=$(rent 36)
    r_buf=$(rent $((37 + bytes)))
    [ -n "$r_pd" ] && [ -n "$r_prog" ] && [ -n "$r_buf" ] || die "the RPC gave no rent figure"
    # Modelled network fees: one write transaction per about 1,000 bytes of program (the CLI
    # packs less than one packet, 1,232 bytes, per write), each at 5,000 lamports per signature
    # (two signers) plus the priority fee at the CLI's default write limit of 200,000 units
    # per transaction; a deploy and a close transaction on top. Modelled, not measured.
    writes=$(((bytes + 999) / 1000))
    fee_each=$((10000 + prio * 200000 / 1000000))
    fees=$((writes * fee_each + 4 * fee_each))
    kept=$((r_pd + r_prog))
    peak=$((kept + r_buf + fees))
    sol() { awk -v l="$1" 'BEGIN{printf "%.6f", l/1000000000}'; }
    cat <<EOF
program: impulse-htlc
so_bytes: $bytes
so_sha256: $want
max_len: $max_len (program-data capacity; upgrades larger than this need an extend)
rpc: $url
rent_program_data_lamports: $r_pd (read from the cluster)
rent_program_lamports: $r_prog (read from the cluster)
rent_buffer_lamports: $r_buf (read from the cluster; refunded at deploy)
rent_kept_lamports: $kept = $(sol "$kept") SOL (stays locked in the program accounts while it exists)
fees_lamports: $fees = $(sol "$fees") SOL (modelled, not measured)
sol_needed_peak: $(sol "$peak") SOL on the fee payer while the buffer and the program-data account both exist (modelled)
sol_needed_recommended: $(sol $((peak + peak / 5 + 10000000))) SOL (peak plus 20 percent plus 0.01 SOL, modelled)

Nothing below is run by this script. Run it yourself, on your machine, one command at a time.

# 0. Keys (yours; never paste a key or a seed anywhere). Make the program keypair once, and
#    keep the dedicated upgrade authority offline (a hardware wallet path such as usb://ledger
#    works wherever a keypair path is asked for). The fee payer holds the SOL above. The buffer
#    authority must be the upgrade authority, which signs steps 1, 2 and 5.
solana-keygen new --no-bip39-passphrase -o $program_kp        # the program ID is its public key
solana-keygen pubkey $program_kp                             # prints the program ID: publish this
solana balance --url mainnet-beta -k $payer_kp                # at least the recommended SOL above

# 1. Write the program to a buffer (resumable: if it stops, run the same command again with the
#    same --buffer; it resumes the writes). The buffer keypair is a throwaway you may make now.
solana-keygen new --no-bip39-passphrase -o $buffer_kp
solana program write-buffer --url mainnet-beta -k $payer_kp --buffer $buffer_kp \\
  --buffer-authority $authority_kp --with-compute-unit-price $prio --max-sign-attempts 20 --use-rpc $out/impulse_htlc.so
solana program show --url mainnet-beta --buffers -k $authority_kp
#    The buffer's hash must be the recorded one before you deploy it:
solana program dump --url mainnet-beta <buffer-address> $out/buffer.dump
head -c $bytes $out/buffer.dump | shasum -a 256               # must equal $want

# 2. Deploy from the buffer to the program ID (the authority keypair signs):
solana program deploy --url mainnet-beta -k $payer_kp --program-id $program_kp \\
  --upgrade-authority $authority_kp --max-len $max_len \\
  --with-compute-unit-price $prio --buffer $buffer_kp

# 3. If a write or the deploy fails and you give up, recover the buffer rent (the buffer
#    authority is the upgrade authority, so it signs; the rent goes to the address given):
solana program close --url mainnet-beta -k $payer_kp --buffer-authority $authority_kp --buffers \\
  --recipient <payer-address>
#    or one: solana program close --url mainnet-beta -k $payer_kp --buffer-authority $authority_kp \\
#    <buffer-address> --recipient <payer-address> --bypass-warning

# 4. Verify (read-only; this script does it):
scripts/solana-mainnet-deploy.sh verify --program-id <program-id> --out $out --url $url
#    And, once the repository is public, against the source:
solana-verify verify-from-repo --url mainnet-beta --program-id <program-id> \\
  --library-name impulse_htlc --commit-hash $(field source_commit "$(cat "$record")") <public-repo-url>

# 5. Authority. Keep a dedicated authority key offline. While the program stays upgradeable a
#    defect can be fixed; making it final is irreversible:
#    The offline key cannot sign now, so the signer check is skipped: a mistyped public key
#    would give the upgrade right to nobody for ever. Compare it twice, character by character.
solana program set-upgrade-authority --url mainnet-beta -k $payer_kp <program-id> \\
  --upgrade-authority $authority_kp --new-upgrade-authority $offline_auth \\
  --skip-new-upgrade-authority-signer-check
#    Only if you accept that no fix is then possible:
solana program set-upgrade-authority --url mainnet-beta -k $payer_kp <program-id> \\
  --upgrade-authority <current-authority-keypair> --final

# 6. Record the program ID, the hash and the deploy transaction in docs/release/SOLANA-PROGRAM.md.
EOF
    ;;

  verify)
    need solana
    need shasum
    [ -n "$program_id" ] || usage
    [ -f "$record" ] || die "no $record: run the build stage first"
    want=$(field so_sha256 "$(cat "$record")")
    bytes=$(field so_bytes "$(cat "$record")")
    dump=$out/deployed.dump
    rm -f "$dump"
    solana program dump "$program_id" "$dump" --url "$url" > /dev/null 2>&1 \
      || die "no program $program_id on $url (or it is not an upgradeable-loader program)"
    # The upgrade authority, read from the program-data account (no default signer needed).
    acct() { solana account "$1" --url "$url" --output json-compact; }
    pd=$(acct "$program_id" | python3 -I -c '
import base64, json, sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
d = base64.b64decode(json.load(sys.stdin)["account"]["data"][0])
assert d[:4] == (2).to_bytes(4, "little"), "not an upgradeable program account"
print(b58(d[4:36]))') || die "cannot read the program account of $program_id"
    auth=$(acct "$pd" | python3 -I -c '
import base64, json, sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
d = base64.b64decode(json.load(sys.stdin)["account"]["data"][0])
assert d[:4] == (3).to_bytes(4, "little"), "not a program-data account"
print(b58(d[13:45]) if d[12] == 1 else "none (final)")') || die "cannot read the program-data account $pd"
    echo "program: $program_id"
    echo "program_data: $pd"
    echo "upgrade_authority: $auth"
    dsize=$(size "$dump")
    [ "$dsize" -ge "$bytes" ] || die "the deployed program is $dsize bytes, the build is $bytes"
    got=$(head -c "$bytes" "$dump" | shasum -a 256 | cut -d' ' -f1)
    # The program-data account may be larger than the program (max_len): the rest must be zeros.
    if [ "$dsize" -gt "$bytes" ]; then
      tail -c +$((bytes + 1)) "$dump" | tr -d '\0' | head -c 1 | od -An | grep -q . \
        && die "the deployed data after byte $bytes is not padding"
    fi
    echo "deployed_sha256: $got"
    echo "recorded_sha256: $want"
    [ "$got" = "$want" ] || die "MISMATCH: the deployed program is not the recorded build"
    echo "ok: the deployed program equals the recorded build (so_bytes $bytes)"
    ;;
  *) usage ;;
esac
