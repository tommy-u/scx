#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
inspector_bin=${SNAKE_INSPECTOR_BIN:-}
failure_artifact=${SNAKE_REHOME_ARTIFACT:-}
timeout_s=${SNAKE_REHOME_TIMEOUT:-3}
rehome_polls=${SNAKE_REHOME_POLLS:-10}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
control_log=${tmpdir}/control.log
inspection_log=${tmpdir}/inspection.log
snake_pid=
inspector_pid=
worker_pid=
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
}

cleanup() {
    local rc=$? destination

    trap - EXIT INT TERM
    set +e
    kill "${worker_pid}" 2>/dev/null || true
    kill -INT "${inspector_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${worker_pid}"
    stop_pid "${inspector_pid}" INT
    stop_pid "${snake_pid}" INT
    if ((rc != 0)); then
        if [[ -n ${failure_artifact} ]]; then
            destination=${failure_artifact}
            mkdir -p "${destination}"
        else
            destination=$(mktemp -d /tmp/scx-snake-vtime-single-rehome.XXXXXX)
        fi
        cp -a "${tmpdir}/." "${destination}/"
        printf 'artifacts: %s\n' "${destination}" >&2
    fi
    rm -rf "${tmpdir}"
    exit "${rc}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime single-runner rehome test: $*" >&2
    capture_inspection "failure" || true
    cat "${control_log}" >&2 2>/dev/null || true
    cat "${inspection_log}" >&2 2>/dev/null || true
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 2>/dev/null || true
    exit 1
}

capture_inspection() {
    local label=$1

    [[ -n ${inspector_pid} ]] || return 0
    {
        printf '\n=== %s ===\n' "${label}"
        curl -fsS http://127.0.0.1:18787/api/inspection
        printf '\n'
    } >>"${inspection_log}"
}

set_cell() {
    local cell_id=$1
    local response

    response=$("${snake_bin}" --set-thread-cell "${worker_pid}:${cell_id}")
    printf 'cell=%s response=%s\n' "${cell_id}" "${response}" >>"${control_log}"
    capture_inspection "assigned-cell-${cell_id}" || true
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for_cpu() {
    local expected=$1
    local deadline=$((SECONDS + timeout_s))
    local cpu

    while ((SECONDS < deadline)); do
        scheduler_enabled || return 1
        cpu=$(awk '{print $39}' "/proc/${worker_pid}/stat" 2>/dev/null || true)
        [[ ${cpu} == "${expected}" ]] && return 0
        sleep 0.02
    done
    return 1
}

clock_transitions() {
    python3 - "${snake_log}" <<'PY'
import json
import sys

transitions = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        for cell in record.get("cells", {}).values():
            transitions += cell.get("clock_transitions", 0)
print(transitions)
PY
}

cell_runtime() {
    local cell_id=$1

    python3 - "${snake_log}" "${cell_id}" <<'PY'
import json
import sys

runtime = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        runtime += record.get("cells", {}).get(sys.argv[2], {}).get("runtime_ns", 0)
print(runtime)
PY
}

wait_for_cell_runtime() {
    local cell_id=$1
    local deadline=$((SECONDS + timeout_s))
    local runtime

    while ((SECONDS < deadline)); do
        runtime=$(cell_runtime "${cell_id}")
        ((runtime > 0)) && return 0
        sleep 0.05
    done
    return 1
}

wait_for_rehome_transition() {
    local expected=$1
    local attempt observed

    for ((attempt = 0; attempt < rehome_polls; attempt++)); do
        observed=$(clock_transitions)
        ((observed >= expected)) && return 0
        sleep 0.02
    done
    return 1
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${timeout_s} =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"
[[ ${rehome_polls} =~ ^[1-9][0-9]*$ ]] || fail "rehome polls must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
if [[ -n ${inspector_bin} ]]; then
    [[ -x ${inspector_bin} ]] || fail "inspector binary is not executable: ${inspector_bin}"
    command -v curl >/dev/null || fail "curl is required for inspector diagnostics"
fi
command -v taskset >/dev/null || fail "taskset is required"
command -v python3 >/dev/null || fail "python3 is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
(( $(nproc) >= 4 )) || fail "requires at least four CPUs"
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

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
EOF

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.02 \
    --stats-format json >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

if [[ -n ${inspector_bin} ]]; then
    "${inspector_bin}" --listen 127.0.0.1:18787 --window 2s --max-window 10s \
        >"${tmpdir}/inspector.log" 2>&1 &
    inspector_pid=$!
    for _ in $(seq 1 100); do
        curl -fsS http://127.0.0.1:18787/api/inspection >/dev/null 2>&1 && break
        kill -0 "${inspector_pid}" 2>/dev/null || fail "inspector exited during startup"
        sleep 0.05
    done
    curl -fsS http://127.0.0.1:18787/api/inspection >/dev/null 2>&1 ||
        fail "inspector diagnostics did not become ready"
fi

taskset -c 0,1 bash -c 'kill -STOP $$; exec yes' >/dev/null &
worker_pid=$!
for _ in $(seq 1 100); do
    [[ $(awk '{print $3}' "/proc/${worker_pid}/stat" 2>/dev/null || true) == T ]] && break
    sleep 0.02
done
[[ $(awk '{print $3}' "/proc/${worker_pid}/stat" 2>/dev/null || true) == T ]] ||
    fail "worker did not stop for initial assignment"
set_cell 1
kill -CONT "${worker_pid}"
wait_for_cpu 0 || fail "worker did not start in cell 1 on CPU 0"
wait_for_cell_runtime 1 || fail "worker did not execute under cell 1"
capture_inspection "running-cell-1-initial" || true
transition_baseline=$(clock_transitions)

# With no other cell-1 or cell-2 runnable work, the expired task is the only
# candidate. Reassignment must prevent keep-running replenishment so enqueue
# can translate its clock coordinate and route it to the new cell.
set_cell 2
wait_for_cpu 1 || fail "single runnable task remained in old cell after reassignment"
wait_for_cell_runtime 2 || fail "worker did not execute under cell 2"
wait_for_rehome_transition $((transition_baseline + 1)) ||
    fail "cell-2 rehome exceeded the bounded completion window"
capture_inspection "running-cell-2" || true
set_cell 1
wait_for_cpu 0 || fail "single runnable task did not return to cell 1"
wait_for_rehome_transition $((transition_baseline + 2)) ||
    fail "cell-1 rehome exceeded the bounded completion window"
capture_inspection "running-cell-1-final" || true

python3 - "${snake_log}" <<'PY'
import json
import sys

preemptions = 0
invalid_errors = 0
accounting_errors = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        preemptions += record.get("queue_rehome_preemptions", 0)
        invalid_errors += record.get("invalid_errors", 0)
        accounting_errors += record.get("vtime_accounting_errors", 0)
if preemptions == 0:
    raise SystemExit("dispatch never preempted keep-running for a pending rehome")
if invalid_errors or accounting_errors:
    raise SystemExit(
        f"scheduler errors: invalid={invalid_errors} accounting={accounting_errors}"
    )
PY

scheduler_enabled || fail "scheduler exited during live reassignment"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall|watchdog)|snake.*(error|stall)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler or kernel error"
fi

echo "PASS: a continuously runnable task followed two live cell reassignments"
