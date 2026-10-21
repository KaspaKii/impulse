#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Generates PARITY.md (I10) from tests/parity/solana-dvp.json, the tagged parity tests and their
# results. PARITY.md is never edited by hand.
#   scripts/gen-parity.sh                        run the parity tests, write PARITY.md
#   scripts/gen-parity.sh --check                run them, fail if PARITY.md differs (ci-local)
#   scripts/gen-parity.sh --mutate-contract      run them against each one-require mutant of the
#                                                contract, write tests/parity/mutation-run.json,
#                                                then PARITY.md (by hand; about 33 test runs)
#   scripts/gen-parity.sh --verify-source [DIR]  check the mapping against solana-foundation/dvp
#                                                at the pinned commit (DIR: a checkout; default:
#                                                clone into target/parity/, needs network)
set -euo pipefail
cd "$(dirname "$0")/.."
command -v python3 >/dev/null || { echo "gen-parity: FAIL: python3 not installed" >&2; exit 1; }
exec python3 tests/parity/gen_parity.py "$@"
