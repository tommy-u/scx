#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
snake_pid=
worker_pid=
gate_pid=
gate_guard_pid=
dmesg_lines=0

pid_done() {
    local pid=$1
    local state

    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

stop_pid() {
    local pid=$1
    local signal=${2:-TERM}
    local attempt

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
    kill "${worker_pid}" "${gate_pid}" "${gate_guard_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${worker_pid}"
    stop_pid "${gate_pid}" KILL
    stop_pid "${gate_guard_pid}" KILL
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime queued-rehome test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

cell_counter() {
    local cell_id=$1
    local field=$2

    python3 - "${snake_log}" "${cell_id}" "${field}" <<'PY'
import json
import sys

value = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        value += record.get("cells", {}).get(sys.argv[2], {}).get(sys.argv[3], 0)
print(value)
PY
}

global_counter() {
    local field=$1

    python3 - "${snake_log}" "${field}" <<'PY'
import json
import sys

value = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        value += record.get(sys.argv[2], 0)
print(value)
PY
}

wait_counter_gt() {
    local cell_id=$1
    local field=$2
    local baseline=$3
    local attempt value

    for ((attempt = 0; attempt < 150; attempt++)); do
        value=$(cell_counter "${cell_id}" "${field}")
        ((value > baseline)) && return 0
        scheduler_enabled || return 1
        sleep 0.02
    done
    return 1
}

wait_global_counter_gt() {
    local field=$1
    local baseline=$2
    local attempt value

    for ((attempt = 0; attempt < 150; attempt++)); do
        value=$(global_counter "${field}")
        ((value > baseline)) && return 0
        scheduler_enabled || return 1
        sleep 0.02
    done
    return 1
}

wait_for_target_cpu() {
    local minimum=$1
    local maximum=$2
    local baseline_ticks=$3
    local attempt cpu ticks

    for ((attempt = 0; attempt < 25; attempt++)); do
        cpu=$(awk '{print $39}' "/proc/${worker_pid}/stat" 2>/dev/null || true)
        ticks=$(awk '{print $14 + $15}' "/proc/${worker_pid}/stat" 2>/dev/null || true)
        if [[ ${cpu} =~ ^[0-9]+$ && ${ticks} =~ ^[0-9]+$ ]] &&
            ((cpu >= minimum && cpu <= maximum && ticks > baseline_ticks)); then
            return 0
        fi
        scheduler_enabled || return 1
        sleep 0.02
    done
    return 1
}

start_stopped_worker() {
    local allowed=$1

    taskset -c "${allowed}" bash -c 'kill -STOP $$; exec yes' >/dev/null &
    worker_pid=$!
    for _ in $(seq 1 100); do
        [[ $(awk '{print $3}' "/proc/${worker_pid}/stat" 2>/dev/null || true) == T ]] &&
            return 0
        sleep 0.02
    done
    return 1
}

run_queued_rehome() {
    local action=$1
    local allowed=$2
    local target_min=$3
    local target_max=$4
    local target_cell transitions_before dispatches_before stale_before ticks_before
    local old_enqueues_before
    local clear_output gate_policy

    start_stopped_worker "${allowed}" || fail "worker did not stop for setup"
    "${snake_bin}" --set-thread-cell "${worker_pid}:1" >/dev/null
    if [[ ${action} == set ]]; then
        target_cell=2
    else
        target_cell=0
    fi
    stale_before=$(global_counter queue_stale_rehome_runs)
    transitions_before=$(cell_counter "${target_cell}" clock_transitions)
    dispatches_before=$(cell_counter "${target_cell}" normal_dispatches)
    old_enqueues_before=$(cell_counter 1 normal_enqueues)
    ticks_before=$(awk '{print $14 + $15}' "/proc/${worker_pid}/stat")

    # The RT gate holds cell 1's only CPU while SIGCONT synchronously enqueues
    # the target on the old normal DSQ. A separate guard bounds the gate even
    # if a later assertion fails before normal cleanup.
    taskset -c 0 chrt -f 1 yes >/dev/null &
    gate_pid=$!
    for _ in $(seq 1 100); do
        gate_policy=$(chrt -p "${gate_pid}" 2>/dev/null || true)
        grep -q 'SCHED_FIFO' <<<"${gate_policy}" && break
        sleep 0.01
    done
    grep -q 'SCHED_FIFO' <<<"${gate_policy}" || fail "queued-rehome RT gate did not start"
    (
        sleep 8
        kill -KILL "${gate_pid}" 2>/dev/null || true
    ) &
    gate_guard_pid=$!
    kill -CONT "${worker_pid}"
    wait_counter_gt 1 normal_enqueues "${old_enqueues_before}" ||
        fail "target did not enter the old cell's normal DSQ behind the RT gate"

    if [[ ${action} == set ]]; then
        "${snake_bin}" --set-thread-cell "${worker_pid}:2" >/dev/null
    else
        clear_output=$("${snake_bin}" --clear-thread-cell "${worker_pid}")
        grep -q 'placement update requested' <<<"${clear_output}" ||
            fail "queue-mode clear response did not acknowledge cell0 rehome"
    fi
    stop_pid "${gate_pid}" KILL
    gate_pid=
    stop_pid "${gate_guard_pid}" KILL
    gate_guard_pid=
    wait_global_counter_gt queue_stale_rehome_runs "${stale_before}" ||
        fail "queued ${action} reassignment skipped the old normal-DSQ execution"
    wait_for_target_cpu "${target_min}" "${target_max}" "${ticks_before}" ||
        fail "queued ${action} reassignment remained on old-cell CPU 0"
    wait_counter_gt "${target_cell}" clock_transitions "${transitions_before}" ||
        fail "queued ${action} reassignment did not translate clocks"
    wait_counter_gt "${target_cell}" normal_dispatches "${dispatches_before}" ||
        fail "queued ${action} reassignment did not execute in the target cell"
    stop_pid "${worker_pid}"
    worker_pid=
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
command -v python3 >/dev/null || fail "python3 is required"
command -v taskset >/dev/null || fail "taskset is required"
command -v chrt >/dev/null || fail "chrt is required"
(( $(nproc) >= 4 )) || fail "requires at least four CPUs"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
dmesg_lines=$(dmesg | wc -l)

cat >"${policy}" <<'EOF'
[queues]
layout = "cell"

[[queues.enqueue]]
target = "cell"

[[queues.enqueue]]
target = "affinity"

[[queues.dispatch]]
source = "affinity"

[[queues.dispatch]]
source = "cell"

[[cell]]
id = 1
cpus = "0"

[[cell]]
id = 2
cpus = "1"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
EOF

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.02 \
    --stats-format json >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

run_queued_rehome set 0,1 1 1
run_queued_rehome clear "0-$(($(nproc) - 1))" 2 "$(($(nproc) - 1))"

invalid=$(global_counter invalid_errors)
accounting=$(global_counter vtime_accounting_errors)
((invalid == 0 && accounting == 0)) ||
    fail "scheduler errors: invalid=${invalid} accounting=${accounting}"
scheduler_enabled || fail "scheduler exited during queued rehome cases"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall|watchdog)|snake.*(error|stall)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler or kernel error"
fi

echo "PASS: queued cell reassignment and clear-to-cell0 converged"
