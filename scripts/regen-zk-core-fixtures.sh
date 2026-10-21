#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Regenerates the proofs under crates/impulse-core/src/zk/testdata/ that the end-to-end tests of
# impulse_core::zk (src/zk/e2e_tests.rs) run in the pinned script engine. A proof is bound to the
# asset vault's scriptPubKey, which commits to the template v3 hash and every term, so these must
# be remade whenever contracts/impulse_vault_v3.sil or circuits/IMAGE_ID changes.
#
#   scripts/regen-zk-core-fixtures.sh            prove the four worlds (selfsettle, authority, kcc20cash,
#                                                external; several minutes each)
#   scripts/regen-zk-core-fixtures.sh kcc20cash  prove one world
#
# Proving is local: the succinct receipt on this machine, the Groth16 step in the pinned Docker
# image with no network (circuits/README.md). Nothing here holds a key: the fixture parties are
# label-derived public keys.
set -euo pipefail
cd "$(dirname "$0")/.."
source circuits/scripts/env.sh
worlds=("$@")
[ ${#worlds[@]} -gt 0 ] || worlds=(selfsettle authority kcc20cash external)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
(cd circuits && cargo build --release --locked -p impulse-zk-prover --bin impulse-zk-prove)
IMPULSE_E2E_OUT="$out" cargo test --locked -q -p impulse-core --features zk --lib \
  zk::e2e_tests::emit_prover_inputs -- --ignored --exact >/dev/null
for w in "${worlds[@]}"; do
  python3 -I - "$out/$w.args.json" "$out/$w.path.json" > "$out/$w.cmd" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
json.dump(a["path"], open(sys.argv[2], "w"))
print(a["root"], a["vault_spk"], a["owner_spk"])
PY
  read -r root vault owner < "$out/$w.cmd"
  cp "$out/$w.terms.hex" "crates/impulse-core/src/zk/testdata/e2e-$w.terms.hex"
  circuits/target/release/impulse-zk-prove --path "$out/$w.path.json" --root "$root" \
    --vault-spk "$vault" --owner-spk "$owner" \
    --out "crates/impulse-core/src/zk/testdata/e2e-$w.proof.json"
done
