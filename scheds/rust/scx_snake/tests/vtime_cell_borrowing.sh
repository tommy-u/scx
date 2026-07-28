#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo=${SNAKE_REPO:-/home/tommyu/scx-snake}
snake_bin=${1:-${repo}/target/release/scx_snake}
layout=${SNAKE_QUEUE_LAYOUT:-cell}
duration=${SNAKE_BORROW_DURATION:-8}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
random_policy=${tmpdir}/random-policy.toml
snake_log=${tmpdir}/snake.ndjson
update_log=${tmpdir}/update.log
snake_pid=
cpu_pid=
pipe_pid=
cell1_pid=
cell2_pid=
pinned_pid=
rehome_pid=
dmesg_lines=0
verbose_args=()

if [[ ${SNAKE_VERBOSE:-0} == 1 ]]; then
    verbose_args+=(--verbose)
fi

cleanup() {
    for pid in "${cpu_pid}" "${pipe_pid}" "${rehome_pid}" \
        "${cell1_pid}" "${cell2_pid}" "${pinned_pid}"; do
        if [[ -n ${pid} ]]; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
    if [[ -n ${snake_pid} ]]; then
        kill -INT "${snake_pid}" 2>/dev/null || true
        wait "${snake_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
}

write_policy() {
    local path=$1 borrow_operation=$2 primary_operation=$3

    printf '%s\n' \
        '[queues]' \
        "layout = \"${layout}\"" \
        '' \
        '[[cell]]' \
        'id = 1' \
        "cpus = \"0-$((cpus - 1))\"" \
        '' \
        '[[cell]]' \
        'id = 2' \
        "cpus = \"0-$((cpus - 1))\"" \
        '' \
        '[[rung]]' \
        "operation = \"${borrow_operation}\"" \
        'scope = "task_cell_borrowable"' \
        '' \
        '[[rung]]' \
        "operation = \"${primary_operation}\"" \
        'scope = "task_cell"' \
        '' \
        '[[rung]]' \
        'operation = "pick_idle"' \
        'scope = "task_allowed"' >"${path}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime cell borrowing test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 || true
    cat "${update_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
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
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"

cpus=$(nproc)
(( cpus >= 4 )) || fail "requires at least four CPUs"
dmesg_lines=$(dmesg | wc -l)

write_policy "${policy}" pick_idle pick_idle
write_policy "${random_policy}" pick_random_idle_core pick_random_idle
cell1_primary_cpu=$("${snake_bin}" --policy "${policy}" --dump-compiled-policy | \
    python3 -c '
import re
import sys
match = re.search(r"cell 1 \(index [0-9]+\):.*primary=\[([0-9,]+)\]", sys.stdin.read())
if not match:
    raise SystemExit("cell 1 primary mask missing from compiled policy")
print(match.group(1).split(",")[0])
')
[[ ${cell1_primary_cpu} =~ ^[0-9]+$ ]] || fail "could not resolve cell 1 primary CPU"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.25 \
    --stats-format json "${verbose_args[@]}" >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

# Explicit-cell sleepers exercise direct borrowing before the machine is
# saturated. The pinned task must escape through its per-CPU affinity queue.
bash -c 'while :; do sleep 0.01; done' &
cell1_pid=$!
"${snake_bin}" --set-thread-cell "${cell1_pid}:1" >/dev/null
bash -c 'while :; do sleep 0.01; done' &
cell2_pid=$!
"${snake_bin}" --set-thread-cell "${cell2_pid}:2" >/dev/null
taskset -c "${cell1_primary_cpu}" bash -c 'while :; do sleep 0.01; done' &
pinned_pid=$!
"${snake_bin}" --set-thread-cell "${pinned_pid}:1" >/dev/null
sleep 1
scheduler_enabled || fail "scheduler exited under non-random borrowing policy"

"${snake_bin}" --update-policy "${random_policy}" >"${update_log}" 2>&1 ||
    fail "random/core borrowing policy update failed"
grep -q 'activated policy generation 2' "${update_log}" ||
    fail "borrowing policy update did not advance the generation"

# Repeated assignment changes race with wakeup placement. A cell change after
# the idle CPU claim must be handled by the selection snapshot, not ejection.
(
    for _ in $(seq 1 40); do
        "${snake_bin}" --set-thread-cell "${cell1_pid}:2" >/dev/null
        "${snake_bin}" --set-thread-cell "${cell1_pid}:1" >/dev/null
    done
) &
rehome_pid=$!
sleep 1
scheduler_enabled || fail "scheduler exited during cell reassignment race"

# CPU workers cover the requested oversubscription case. Pipe workers add
# repeated wakeups after the random/core policy is active.
stress-ng --cpu $((cpus * 2)) --cpu-method loop --timeout "${duration}s" \
    >/dev/null 2>&1 &
cpu_pid=$!
stress-ng --pipe "${cpus}" --timeout "${duration}s" >/dev/null 2>&1 &
pipe_pid=$!
while kill -0 "${cpu_pid}" 2>/dev/null || kill -0 "${pipe_pid}" 2>/dev/null; do
    scheduler_enabled || fail "scheduler exited during borrowing stress"
    sleep 0.1
done
wait "${cpu_pid}"
cpu_pid=
wait "${pipe_pid}"
pipe_pid=
wait "${rehome_pid}"
rehome_pid=
kill "${cell1_pid}" "${cell2_pid}" "${pinned_pid}" 2>/dev/null || true
wait "${cell1_pid}" 2>/dev/null || true
wait "${cell2_pid}" 2>/dev/null || true
wait "${pinned_pid}" 2>/dev/null || true
cell1_pid=
cell2_pid=
pinned_pid=
sleep 1
scheduler_enabled || fail "scheduler exited after borrowing stress"

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
    raise SystemExit("no statistics records were emitted")

direct = 0
direct_runtime = 0
borrow_hits = 0
borrowed = 0
lent = 0
active_cpus = set()
borrowed_by_cell = {}
random_borrow_hits = 0
plain_borrow_hits = 0
for record in records:
    if record.get("invalid_errors", 0) or record.get("vtime_accounting_errors", 0):
        raise SystemExit("Snake reported invalid or accounting errors")
    direct += record.get("direct_dispatches", 0)
    direct_runtime += record.get("vtime_direct_runtime_ns", 0)
    rung0 = record.get("rungs", {}).get("0", {})
    hits = rung0.get("hits", 0)
    borrow_hits += hits
    if rung0.get("operation") == "pick_random_idle_core":
        random_borrow_hits += hits
    elif rung0.get("operation") == "pick_idle":
        plain_borrow_hits += hits
    for key, cell in record["cells"].items():
        borrowed += cell["borrowed_runtime_ns"]
        lent += cell["lent_runtime_ns"]
        cell_id = int(key)
        borrowed_by_cell[cell_id] = (
            borrowed_by_cell.get(cell_id, 0) + cell["borrowed_runtime_ns"]
        )
    for key, cpu in record.get("cpus", {}).items():
        if cpu.get("runtime_ns", 0):
            active_cpus.add(int(key))

if direct == 0 or direct_runtime == 0 or borrow_hits == 0:
    raise SystemExit(
        f"borrowing was not exercised: direct={direct} runtime={direct_runtime} hits={borrow_hits}"
    )
# Per-cell percpu maps are sampled independently while system tasks continue
# running, so the observed halves of one charge can straddle two records.
skew = abs(borrowed - lent)
tolerance = max(1_000_000, max(borrowed, lent) // 10_000)
if borrowed == 0 or skew > tolerance:
    raise SystemExit(
        f"borrowed/lent accounting mismatch: borrowed={borrowed} lent={lent} "
        f"skew={skew} tolerance={tolerance}"
    )
for cell_id in (1, 2):
    if borrowed_by_cell.get(cell_id, 0) == 0:
        raise SystemExit(f"explicit cell {cell_id} did not borrow CPU time")
if plain_borrow_hits == 0 or random_borrow_hits == 0:
    raise SystemExit(
        f"borrowing variants were not exercised: plain={plain_borrow_hits} "
        f"random_core={random_borrow_hits}"
    )
if len(active_cpus) < 2:
    raise SystemExit(f"work ran on too few CPUs: {sorted(active_cpus)}")
PY

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext error"
fi

echo "PASS: ${layout} select-time borrowing survived CPU and wake-heavy stress on ${cpus} CPUs"
