# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Sourced by the circuits scripts: puts the macOS Metal shim first on PATH (see xcrun-shim/xcrun).
# Run `source circuits/scripts/env.sh` before a manual cargo build in circuits/ on macOS.
_circuits_scripts="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ "$(uname -s)" = "Darwin" ]; then
  export PATH="$_circuits_scripts/xcrun-shim:$PATH"
fi
unset _circuits_scripts
