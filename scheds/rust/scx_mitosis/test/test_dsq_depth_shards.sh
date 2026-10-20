#!/bin/bash
# Run only in an isolated sched_ext host/VM with no active scheduler.
# EXPECTED_WRITER_SHARDS=2 ./test_dsq_depth_shards.sh [scheduler arguments]
# For an 8-CPU, two-LLC VM, --virt-llc=2-2 expects four writer shards.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
EXPECTED_WRITER_SHARDS="${EXPECTED_WRITER_SHARDS:?Set the expected physical/virtual writer domain count}"
[[ "$EUID" -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
[[ -x "$SCHEDULER_BIN" ]] || { echo "Scheduler binary missing: $SCHEDULER_BIN" >&2; exit 1; }
[[ "$EXPECTED_WRITER_SHARDS" =~ ^([1-9]|1[0-6])$ ]] || {
    echo "EXPECTED_WRITER_SHARDS must be between 1 and 16" >&2
    exit 1
}
[[ -f /sys/kernel/sched_ext/state ]] || { echo "sched_ext unavailable" >&2; exit 1; }
[[ "$(cat /sys/kernel/sched_ext/state)" == disabled ]] || {
    echo "Refusing to replace an active scheduler; use an isolated host/VM" >&2
    exit 1
}
command -v bpftool >/dev/null
command -v python3 >/dev/null
NUM_CPUS=$(nproc)

ARTIFACT_DIR=$(mktemp -d /tmp/scx_mitosis_dsq_shards.XXXXXX)
CGROUP_PARENT="/sys/fs/cgroup/scx_dsq_shards_${$}_${RANDOM}"
WORKLOAD="$CGROUP_PARENT/workload"
WORKER_PIDS=()
SCHED_PID=""

cleanup() {
    if [[ -n "$SCHED_PID" ]]; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        for ((attempt = 0; attempt < 50; attempt++)); do
            kill -0 "$SCHED_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
    fi
    for pid in "${WORKER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${WORKER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rmdir "$WORKLOAD" "$CGROUP_PARENT" 2>/dev/null || true
    echo "Test logs:"
    printf '%s\n' "$ARTIFACT_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Capture existing map IDs so the test only inspects the scheduler it owns.
bpftool -j map show > "$ARTIFACT_DIR/maps.before.json"
mkdir "$CGROUP_PARENT" "$WORKLOAD"
# One oversubscribed cell, with inherited unrestricted affinity, generates
# shared DSQ observations from executing CPUs across the writer domains.
for ((worker = 0; worker < NUM_CPUS * 8; worker++)); do
    bash -ec 'echo "$$" > "$1/cgroup.procs"; while :; do :; done' _ "$WORKLOAD" &
    WORKER_PIDS+=("$!")
done

"$SCHEDULER_BIN" --cell-parent-cgroup "${CGROUP_PARENT#/sys/fs/cgroup}" \
    --enable-dsq-depth-stats "$@" > "$ARTIFACT_DIR/scheduler.log" 2>&1 &
SCHED_PID=$!
for ((attempt = 0; attempt < 150; attempt++)); do
    kill -0 "$SCHED_PID" 2>/dev/null || {
        cat "$ARTIFACT_DIR/scheduler.log" >&2
        exit 1
    }
    [[ "$(cat /sys/kernel/sched_ext/state)" == enabled ]] && break
    sleep 0.2
done
[[ "$(cat /sys/kernel/sched_ext/state)" == enabled ]] || {
    echo "Scheduler did not attach within 30 seconds" >&2
    exit 1
}

python3 - "$ARTIFACT_DIR" "$EXPECTED_WRITER_SHARDS" "$SCHED_PID" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import time

artifacts = Path(sys.argv[1])
expected = list(range(int(sys.argv[2])))
scheduler_pid = int(sys.argv[3])
deadline = time.monotonic() + 15


def read_json(command, filename):
    result = subprocess.run(command, capture_output=True, text=True, check=True,
                            timeout=max(0.1, deadline - time.monotonic()))
    (artifacts / filename).write_text(result.stdout)
    return json.loads(result.stdout)


before = {entry["id"] for entry in json.loads((artifacts / "maps.before.json").read_text())}
maps = read_json(["bpftool", "-j", "map", "show"], "maps.after.json")
# BPF_OBJ_NAME_LEN truncates the full shared_dsq_depth_hists map name.
matches = [entry for entry in maps
           if entry["id"] not in before and entry["name"] == "shared_dsq_dept"]
assert len(matches) == 1, f"Expected one new histogram map, found {matches}"
metadata = matches[0]
(artifacts / "histogram.map.json").write_text(json.dumps(metadata, indent=2))
assert metadata["type"] == "array", metadata
assert metadata["max_entries"] == 256, metadata
assert metadata["bytes_key"] == 4, metadata
flags = metadata["flags"]
if isinstance(flags, str):
    flags = int(flags, 0)
assert flags & (1 << 10), f"Histogram ARRAY must have BPF_F_MMAPABLE: {metadata}"
value_size = metadata["bytes_value"]
assert value_size % 16 == 0, f"Value must contain 16 equal shards: {metadata}"
stride = value_size // 16
# Each shard contains 16 u64 counters, followed by any cacheline padding.
assert stride >= 16 * 8 and stride % 8 == 0, f"Invalid 16-shard layout: {metadata}"
if os.uname().machine == "x86_64":
    assert value_size == 2048, f"x86 values must reserve exactly 16 shards: {metadata}"

active = []
cell_key = [f"{byte:02x}" for byte in (1).to_bytes(4, sys.byteorder)]
while time.monotonic() < deadline:
    os.kill(scheduler_pid, 0)
    result = read_json(["bpftool", "-j", "map", "lookup", "id", str(metadata["id"]),
                        "key", "hex", *cell_key], "cell1.raw.json")
    # bpftool may also supply formatted BTF; use the raw bytes for counters.
    raw = bytes(int(byte, 16) if isinstance(byte, str) else byte for byte in result["value"])
    assert len(raw) == value_size, f"Expected {value_size} value bytes, got {len(raw)}"
    formatted = result.get("formatted", {}).get("value", {})
    if isinstance(formatted, dict) and "shards" in formatted:
        assert len(formatted["shards"]) == 16, "BTF value must contain 16 shards"
    totals = [sum(int.from_bytes(raw[shard * stride + bucket * 8:
                                     shard * stride + (bucket + 1) * 8], sys.byteorder)
                  for bucket in range(16)) for shard in range(16)]
    active = [shard for shard, total in enumerate(totals) if total]
    (artifacts / "shard.totals.json").write_text(json.dumps(totals))
    assert set(active) <= set(expected), f"Unexpected writer shards: {active}; expected {expected}"
    if active == expected:
        print(f"PASS: ARRAY flags={flags:#x}, entries=256, shards=16, "
              f"value_size={value_size}, stride={stride}, active={active}, totals={totals}")
        break
    time.sleep(min(0.5, max(0, deadline - time.monotonic())))
else:
    raise AssertionError(f"Writer shards after 15 seconds: {active}; expected {expected}")
PY
