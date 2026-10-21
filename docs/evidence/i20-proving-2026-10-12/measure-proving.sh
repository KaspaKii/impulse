#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Proving measurement and go or no-go checkpoint of spec/V3-ZK.md section 14.2. Moves no value and
# touches no key. Writes raw data, this script and results.txt to
# docs/measurements/zk-proving/<date>/ (override with OUT=<dir>; RUNS=<n>, default 5).
#
# Input: the deterministic fixture a_list1000 (owner A at the last position of a list of 1,000
# entries, stand-in vault), read from tests/engine/fixtures/v3/proofs/a_list1000.inputs.json.
# Each run: impulse-zk-prove under /usr/bin/time -l (host peak resident memory; the Groth16 step
# runs inside Docker's VM and is not included), stage wall times from the prover's monotonic clock
# (--timings), the Groth16 container sampled with `docker stats --no-stream` about once a second,
# and the container's Docker events (die, oom, kill).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
runs="${RUNS:-5}"
day="$(date +%F)"
out="${OUT:-$repo/docs/measurements/zk-proving/$day}"
fx="$repo/tests/engine/fixtures/v3/proofs/a_list1000.inputs.json"
source "$here/env.sh"
docker info >/dev/null 2>&1 || { echo "measure-proving: Docker daemon not running" >&2; exit 1; }
[ -f "$fx" ] || { echo "measure-proving: missing $fx (run circuits/scripts/regen-fixtures.sh --inputs-only)" >&2; exit 1; }
mkdir -p "$out/raw"
cp "$0" "$out/measure-proving.sh"

(cd "$repo/circuits" && cargo build --release --locked -p impulse-zk-prover --bin impulse-zk-prove)
bin="$repo/circuits/target/release/impulse-zk-prove"
pin_ref="$(grep '^linux/arm64=' "$repo/circuits/GROTH16_PROVER_IMAGE" | cut -d= -f2)"
[ "$(uname -m)" = "x86_64" ] && pin_ref="$(grep '^linux/amd64=' "$repo/circuits/GROTH16_PROVER_IMAGE" | cut -d= -f2)"

{
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "commit: $(git -C "$repo" rev-parse HEAD) (working tree $(git -C "$repo" status --porcelain | wc -l | tr -d ' ') changed paths)"
  echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
  echo "hw.memsize: $(sysctl -n hw.memsize 2>/dev/null || echo n/a)"
  echo "hw.ncpu: $(sysctl -n hw.ncpu 2>/dev/null || nproc)"
  sw_vers 2>/dev/null || uname -a
  echo "--- docker version"; docker version
  echo "--- docker VM limits"
  docker info --format 'NCPU={{.NCPU}} MemTotal={{.MemTotal}} OperatingSystem={{.OperatingSystem}} Architecture={{.Architecture}}'
  echo "--- rzup show"; "$HOME/.risc0/bin/rzup" show 2>&1 || echo "rzup not found"
  echo "--- groth16 prover image"
  docker image inspect --format '{{.Id}} {{.RepoDigests}} {{.Architecture}}' "risczero/risc0-groth16-prover@$pin_ref"
  echo "--- impulse-zk-prove --image-id"; "$bin" --image-id
} > "$out/machine.txt" 2>&1

path_json="$out/raw/a_list1000.path.json"
python3 -I - "$fx" "$path_json" > "$out/raw/args.txt" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d["path"], open(sys.argv[2], "w"), indent=2)
print(d["root"], d["vault_spk"], d["owner_spk"])
PY
read -r root vault owner < "$out/raw/args.txt"

for i in $(seq 1 "$runs"); do
  name="impulse-zk-measure-$i-$$"
  echo "run $i of $runs (container $name)"
  # Machine load at the start of the run: other work on the laptop shares the CPU and Docker's VM.
  { uptime; ps -Ao pcpu,comm -r | head -8; docker ps -q | wc -l | sed 's/^ */running containers: /'; } \
    > "$out/raw/run$i-load-before.txt" 2>&1 || true  # ps | head can SIGPIPE under pipefail
  docker events --filter "container=$name" --format '{{.TimeNano}} {{.Action}} exitCode={{index .Actor.Attributes "exitCode"}}' \
    > "$out/raw/run$i-docker-events.txt" 2>/dev/null &
  ev=$!
  set +e
  /usr/bin/time -l "$bin" --path "$path_json" --root "$root" --vault-spk "$vault" --owner-spk "$owner" \
    --out "$out/raw/run$i-proof.json" --timings "$out/raw/run$i-timings.json" --container "$name" \
    > "$out/raw/run$i-stdout.txt" 2> "$out/raw/run$i-time.txt" &
  pid=$!
  echo "epoch_s,name,mem_usage,mem_perc,cpu_perc" > "$out/raw/run$i-docker-stats.csv"
  while kill -0 "$pid" 2>/dev/null; do
    docker stats --no-stream --format '{{.Name}},{{.MemUsage}},{{.MemPerc}},{{.CPUPerc}}' "$name" 2>/dev/null \
      | sed "s/^/$(date +%s),/" >> "$out/raw/run$i-docker-stats.csv"
    sleep 1
  done
  wait "$pid"; rc=$?
  set -e
  echo "$rc" > "$out/raw/run$i-exit.txt"
  sleep 1; kill "$ev" 2>/dev/null || true; wait "$ev" 2>/dev/null || true
done

python3 -I - "$out" "$runs" <<'PY'
import json, os, re, statistics, sys
out, runs = sys.argv[1], int(sys.argv[2])
raw = os.path.join(out, "raw")
def unit(s):
    m = re.match(r"([\d.]+)\s*([KMG]i?B|B)", s.strip())
    if not m: return None
    f = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "KB": 1e3, "MB": 1e6, "GB": 1e9}[m.group(2)]
    return float(m.group(1)) * f
machine = open(os.path.join(out, "machine.txt")).read()
vm_mem = int(re.search(r"MemTotal=(\d+)", machine).group(1))
rows, problems = [], []
for i in range(1, runs + 1):
    rc = int(open(os.path.join(raw, f"run{i}-exit.txt")).read().strip())
    r = {"run": i, "exit": rc}
    tf = os.path.join(raw, f"run{i}-timings.json")
    if rc == 0 and os.path.exists(tf):
        r.update(json.load(open(tf)))
    tm = open(os.path.join(raw, f"run{i}-time.txt")).read()
    m = re.search(r"(\d+)\s+maximum resident set size", tm)
    r["host_peak_rss_bytes"] = int(m.group(1)) if m else None
    peak = 0.0
    for line in open(os.path.join(raw, f"run{i}-docker-stats.csv")).read().splitlines()[1:]:
        parts = line.split(",")
        if len(parts) >= 3:
            v = unit(parts[2].split("/")[0])
            if v: peak = max(peak, v)
    r["docker_peak_mem_bytes"] = int(peak)
    ev = open(os.path.join(raw, f"run{i}-docker-events.txt")).read()
    r["docker_oom_or_kill"] = bool(re.search(r"\b(oom|kill)\b", ev))
    m = re.search(r"\bdie exitCode=(\d+)", ev)
    r["docker_exit"] = int(m.group(1)) if m else None
    lb = open(os.path.join(raw, f"run{i}-load-before.txt")).read()
    m = re.search(r"load averages?: ([\d.]+)", lb)
    r["load_avg_1m_before"] = float(m.group(1)) if m else None
    rows.append(r)
    if rc != 0: problems.append(f"run {i}: prover exited {rc}")
    if r["docker_oom_or_kill"]: problems.append(f"run {i}: container killed or out of memory")
    if r.get("groth16_ms", 0) > 60 * 60 * 1000: problems.append(f"run {i}: Groth16 stage over 60 minutes")
    if peak >= vm_mem: problems.append(f"run {i}: container reached the Docker VM memory limit")
    if r["docker_exit"] not in (0, None) : problems.append(f"run {i}: container exit {r['docker_exit']}")
ok = [r for r in rows if r["exit"] == 0]
def stat(k, scale=1.0, fmt="{:.1f}"):
    v = [r[k] / scale for r in ok if r.get(k) is not None]
    if not v: return "n/a"
    return " / ".join(fmt.format(x) for x in (min(v), statistics.median(v), max(v)))
L = []
L.append("I20 proving measurement (spec/V3-ZK.md section 14.2)")
L.append(f"directory: {out}")
L.append("method: circuits/scripts/measure-proving.sh (copied here); raw data in raw/; machine in machine.txt")
L.append("input: fixture a_list1000 (list of 1,000 entries, owner at the last position, stand-in vault)")
L.append(f"runs: {runs}, completed: {len(ok)}")
L.append(f"1-minute load average at run start: {stat('load_avg_1m_before', 1, '{:.2f}')} (other work shared the machine; see raw/run*-load-before.txt)")
L.append("")
L.append("figures for this laptop and these versions only; min / median / max over completed runs")
L.append(f"guest total cycles:               {stat('total_cycles', 1, '{:.0f}')}")
L.append(f"guest user cycles:                {stat('user_cycles', 1, '{:.0f}')}")
L.append(f"segments:                         {stat('segments', 1, '{:.0f}')}")
L.append(f"(a) execution, s:                 {stat('execute_ms', 1000, '{:.3f}')}")
L.append(f"(b) succinct receipt, s:          {stat('succinct_ms', 1000)}")
L.append(f"(c1) identity_p254, s:            {stat('identity_p254_ms', 1000)}")
L.append(f"(c2) Groth16 step in Docker, s:   {stat('groth16_ms', 1000)}")
L.append(f"total in the prover, s:           {stat('total_ms', 1000)}")
L.append(f"host peak resident memory, MiB:   {stat('host_peak_rss_bytes', 1024**2)}")
L.append(f"Groth16 container peak memory, MiB (sampled about once a second): {stat('docker_peak_mem_bytes', 1024**2)}")
L.append(f"Docker VM memory limit, MiB:      {vm_mem / 1024**2:.1f}")
L.append(f"succinct seal, bytes:             {stat('succinct_receipt_bytes', 1, '{:.0f}')}")
L.append(f"compressed Groth16 proof, bytes:  {stat('proof_bytes', 1, '{:.0f}')}")
L.append("")
for r in rows:
    L.append("run " + json.dumps(r, sort_keys=True))
L.append("")
L.append("go or no-go (section 14.2): " + ("GO" if not problems and len(ok) == runs and runs >= 5 else "NO-GO"))
for p in problems: L.append("  " + p)
if runs < 5: L.append("  fewer than five runs: not a checkpoint run")
open(os.path.join(out, "results.txt"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
PY
