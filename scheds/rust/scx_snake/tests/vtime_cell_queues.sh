#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
layout=${SNAKE_QUEUE_LAYOUT:-cell}
duration=${SNAKE_QUEUE_DURATION:-8}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
dmesg_lines=0
snake_pid=
stress_pid=
pinned_pid=
mover_pid=

pid_done() {
    local pid=$1 state

    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

stop_pid() {
    local pid=$1 signal=${2:-TERM} attempt

    [[ -n ${pid} ]] || return 0
    kill "-${signal}" "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 30; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 10; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
}

cleanup() {
    kill "${stress_pid}" "${pinned_pid}" "${mover_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${stress_pid}"
    stop_pid "${pinned_pid}"
    stop_pid "${mover_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime cell queue test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for_enabled() {
    local deadline=$((SECONDS + 10))

    while (( SECONDS < deadline )); do
        scheduler_enabled && return 0
        sleep 0.05
    done
    return 1
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${layout} == cell || ${layout} == cell_llc ]] ||
    fail "SNAKE_QUEUE_LAYOUT must be cell or cell_llc"
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
command -v python3 >/dev/null || fail "python3 is required"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v taskset >/dev/null || fail "taskset is required"
command -v timeout >/dev/null || fail "timeout is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"

cpus=$(nproc)
(( cpus >= 4 )) || fail "requires at least four CPUs"
half=$((cpus / 2))
cell1_last=$((half - 1))
cell2_first=${half}
cell2_last=$((cpus - 1))
dmesg_lines=$(dmesg | wc -l)

printf '%s\n' \
    '[queues]' \
    "layout = \"${layout}\"" \
    '' \
    '[[cell]]' \
    'id = 1' \
    "cpus = \"0-${cell1_last}\"" \
    '' \
    '[[cell]]' \
    'id = 2' \
    "cpus = \"${cell2_first}-${cell2_last}\"" \
    '' \
    '[[rung]]' \
    'operation = "pick_idle"' \
    'scope = "task_cell"' \
    '' \
    '[[rung]]' \
    'operation = "pick_idle"' \
    'scope = "task_allowed"' >"${policy}"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.25 \
    --stats-format json >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for_enabled || fail "scheduler did not attach"

# Unannotated stress exercises cell 0's normal queue. The cell-2 task pinned
# outside cell 2's primary mask must use an affinity queue and is charged as
# borrowed service. The movable task exercises both a normal cell queue and a
# bounded translation between two per-cell clocks.
timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    stress-ng --cpu $((cpus * 2)) --cpu-method loop --timeout "${duration}s" \
    >/dev/null 2>&1 &
stress_pid=$!
taskset -c 0 yes >/dev/null &
pinned_pid=$!
"${snake_bin}" --set-thread-cell "${pinned_pid}:2" >/dev/null
yes >/dev/null &
mover_pid=$!
"${snake_bin}" --set-thread-cell "${mover_pid}:1" >/dev/null
sleep 2
"${snake_bin}" --set-thread-cell "${mover_pid}:2" >/dev/null

deadline=$((SECONDS + duration + 8))
while ! pid_done "${stress_pid}"; do
    scheduler_enabled || fail "scheduler exited during queue stress"
    ((SECONDS < deadline)) || fail "queue stress did not finish"
    sleep 0.1
done
stress_rc=0
wait "${stress_pid}" || stress_rc=$?
stress_pid=
((stress_rc == 0)) || fail "queue stress failed with status ${stress_rc}"
stop_pid "${pinned_pid}"
stop_pid "${mover_pid}"
pinned_pid=
mover_pid=
sleep 1
scheduler_enabled || fail "scheduler exited after queue stress"

python3 - "${snake_log}" <<'PY'
import json
import sys

records = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "cells" in record:
            records.append(record)

if not records:
    raise SystemExit("no cell statistics records were emitted")

totals = {
    "normal_enqueues": 0,
    "affinity_enqueues": 0,
    "clock_transitions": 0,
    "borrowed_runtime_ns": 0,
    "lent_runtime_ns": 0,
}
seen = set()
cell_runtime = {}
cell_primary = {}
cell_borrowed = {}
for record in records:
    if record.get("invalid_errors", 0):
        raise SystemExit("Snake reported invalid errors")
    if record.get("vtime_accounting_errors", 0):
        raise SystemExit("Snake reported VTIME accounting errors")
    for key, cell in record["cells"].items():
        cell_id = int(key)
        seen.add(cell_id)
        cell_runtime[cell_id] = cell_runtime.get(cell_id, 0) + cell["runtime_ns"]
        cell_primary[cell_id] = cell_primary.get(cell_id, 0) + cell["primary_runtime_ns"]
        cell_borrowed[cell_id] = cell_borrowed.get(cell_id, 0) + cell["borrowed_runtime_ns"]
        for name in totals:
            totals[name] += cell.get(name, 0)

if seen != {0, 1, 2}:
    raise SystemExit(f"unexpected cell IDs: {sorted(seen)}")
for cell_id in seen:
    accounted = cell_primary[cell_id] + cell_borrowed[cell_id]
    skew = abs(cell_runtime[cell_id] - accounted)
    tolerance = max(1_000_000, max(cell_runtime[cell_id], accounted) // 10_000)
    if skew > tolerance:
        raise SystemExit(
            f"cell {cell_id} runtime identity failed: {cell_runtime[cell_id]} != "
            f"{cell_primary[cell_id]} + {cell_borrowed[cell_id]} "
            f"(skew={skew} tolerance={tolerance})"
        )
resource_skew = abs(totals["borrowed_runtime_ns"] - totals["lent_runtime_ns"])
resource_tolerance = max(
    1_000_000,
    max(totals["borrowed_runtime_ns"], totals["lent_runtime_ns"]) // 10_000,
)
if resource_skew > resource_tolerance:
    raise SystemExit(
        "resource identity failed: borrowed "
        f"{totals['borrowed_runtime_ns']} != lent {totals['lent_runtime_ns']} "
        f"(skew={resource_skew} tolerance={resource_tolerance})"
    )
for name in ("normal_enqueues", "affinity_enqueues", "clock_transitions"):
    if totals[name] == 0:
        raise SystemExit(f"{name} was not exercised")
if totals["borrowed_runtime_ns"] == 0 or totals["lent_runtime_ns"] == 0:
    raise SystemExit("borrowed/lent runtime accounting was not exercised")
PY

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext error"
fi

echo "PASS: ${layout} VTIME queues survived mixed cell/affinity stress on ${cpus} CPUs"
