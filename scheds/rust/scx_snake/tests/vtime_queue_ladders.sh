#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
tmpdir=$(mktemp -d)
initial=${tmpdir}/initial.toml
replacement=${tmpdir}/replacement.toml
reordered=${tmpdir}/reordered.toml
min_vtime=${tmpdir}/min-vtime.toml
invalid=${tmpdir}/invalid.toml
snake_log=${tmpdir}/snake.log
update_log=${tmpdir}/update.log
snake_pid=
stress_pid=
pinned_pid=
order_normal_pid=
order_affinity_pid=
order_gate_pid=
order_guard_pid=
order_collector_pid=
dmesg_lines=0
order_result=${tmpdir}/dispatch-order
order_pipe=${tmpdir}/dispatch-order.pipe

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
    kill "${stress_pid}" "${pinned_pid}" "${order_normal_pid}" \
        "${order_affinity_pid}" "${order_gate_pid}" "${order_guard_pid}" \
        "${order_collector_pid}" \
        2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${stress_pid}"
    stop_pid "${pinned_pid}"
    stop_pid "${order_normal_pid}"
    stop_pid "${order_affinity_pid}"
    stop_pid "${order_gate_pid}" KILL
    stop_pid "${order_guard_pid}" KILL
    stop_pid "${order_collector_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime queue ladder test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 120 "${snake_log}" >&2 || true
    cat "${update_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_stopped() {
    local pid=$1 attempt state

    for ((attempt = 0; attempt < 100; attempt++)); do
        state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
        [[ ${state} == T ]] && return 0
        sleep 0.02
    done
    return 1
}

wait_order_workers() {
    local deadline=$((SECONDS + 3))

    while ! pid_done "${order_normal_pid}" || ! pid_done "${order_affinity_pid}"; do
        scheduler_enabled || return 1
        ((SECONDS < deadline)) || return 1
        sleep 0.02
    done
}

run_dispatch_ready_phase() {
    local policy=$1 generation=$2 gate_policy result

    rm -f "${order_pipe}"
    mkfifo "${order_pipe}"
    : >"${order_result}"
    taskset -c "${other_cell_cpu}" dd if="${order_pipe}" of="${order_result}" \
        bs=1 count=2 status=none &
    order_collector_pid=$!
    # shellcheck disable=SC2016 # The child expands its positional result path.
    taskset -c "${order_cpu}" bash -c \
        'exec 3>"$1"; kill -STOP $$; printf N >&3' _ "${order_pipe}" &
    order_normal_pid=$!
    wait_stopped "${order_normal_pid}" || fail "normal order worker did not stop"
    "${snake_bin}" --set-thread-cell "${order_normal_pid}:1" >/dev/null

    # shellcheck disable=SC2016 # The child expands its positional result path.
    taskset -c "${order_cpu}" bash -c \
        'exec 3>"$1"; kill -STOP $$; printf A >&3' _ "${order_pipe}" &
    order_affinity_pid=$!
    wait_stopped "${order_affinity_pid}" || fail "affinity order worker did not stop"
    "${snake_bin}" --set-thread-cell "${order_affinity_pid}:2" >/dev/null

    taskset -c "${order_cpu}" chrt -f 1 yes >/dev/null &
    order_gate_pid=$!
    for _ in $(seq 1 100); do
        gate_policy=$(chrt -p "${order_gate_pid}" 2>/dev/null || true)
        grep -q 'SCHED_FIFO' <<<"${gate_policy}" && break
        sleep 0.01
    done
    grep -q 'SCHED_FIFO' <<<"${gate_policy}" || fail "dispatch-order RT gate did not start"
    (
        sleep 3
        kill -KILL "${order_gate_pid}" 2>/dev/null || true
    ) &
    order_guard_pid=$!

    kill -CONT "${order_normal_pid}" "${order_affinity_pid}"
    "${snake_bin}" --update-policy "${policy}" >"${update_log}" 2>&1 ||
        fail "dispatch-order policy update failed"
    grep -q "activated policy generation ${generation}" "${update_log}" ||
        fail "dispatch-order policy did not activate generation ${generation}"
    stop_pid "${order_gate_pid}" KILL
    order_gate_pid=
    stop_pid "${order_guard_pid}" KILL
    order_guard_pid=
    wait_order_workers || fail "dispatch-order workers did not finish"
    wait "${order_normal_pid}" "${order_affinity_pid}"
    order_normal_pid=
    order_affinity_pid=
    wait "${order_collector_pid}" || fail "dispatch-order collector failed"
    order_collector_pid=
    # Source ladders are cyclic. Unrelated work may advance this CPU's cursor,
    # so userspace completion order cannot assert the generation's first rung.
    # Rust encoding tests verify exact rung order; this phase verifies liveness.
    result=$(cat "${order_result}")
    [[ ${result} == AN || ${result} == NA ]] ||
        fail "dispatch sources did not both drain: ${result}"
}

write_policy() {
    local path=$1 layout=$2 mode=$3

    {
        printf '[queues]\nlayout = "%s"\n\n' "${layout}"
        printf '[[cell]]\nid = 1\ncpus = "%s"\n\n' "${order_cpu}"
        printf '[[cell]]\nid = 2\ncpus = "%s"\n\n' "${other_cell_cpu}"
        if [[ ${mode} == affinity ]]; then
            printf '%s\n' \
                '[[queues.enqueue]]' \
                'target = "affinity"' \
                '[[queues.dispatch]]' \
                'source = "affinity"'
        else
            printf '%s\n' \
                '[[queues.enqueue]]' \
                'target = "cell"' \
                '[[queues.enqueue]]' \
                'target = "affinity"'
            if [[ ${mode} == min_vtime ]]; then
                printf '%s\n' \
                    '[[queues.dispatch]]' \
                    'operation = "min_vtime"'
            elif [[ ${mode} == full_affinity_first ]]; then
                printf '%s\n' \
                    '[[queues.dispatch]]' \
                    'source = "affinity"' \
                    '[[queues.dispatch]]' \
                    'source = "cell"'
            else
                printf '%s\n' \
                    '[[queues.dispatch]]' \
                    'source = "cell"' \
                    '[[queues.dispatch]]' \
                    'source = "affinity"'
            fi
        fi
        printf '%s\n' \
            '' \
            '[[rung]]' \
            'operation = "pick_idle"' \
            'scope = "task_allowed"'
    } >"${path}"
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
cpus=$(nproc)
(( cpus >= 4 )) || fail "requires at least four CPUs"
order_cpu=$((cpus - 1))
other_cell_cpu=$((cpus - 2))
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v timeout >/dev/null || fail "timeout is required"
command -v taskset >/dev/null || fail "taskset is required"
command -v chrt >/dev/null || fail "chrt is required"
command -v dd >/dev/null || fail "dd is required"
command -v mkfifo >/dev/null || fail "mkfifo is required"
command -v python3 >/dev/null || fail "python3 is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
dmesg_lines=$(dmesg | wc -l)

write_policy "${initial}" cell affinity
write_policy "${replacement}" cell full_cell_first
write_policy "${reordered}" cell full_affinity_first
write_policy "${min_vtime}" cell min_vtime
write_policy "${invalid}" cell_llc full_cell_first

"${snake_bin}" --policy "${initial}" --fairness vtime --stats 0.25 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

timeout --signal=TERM --kill-after=2s 15s \
    stress-ng --cpu $((cpus * 2)) --cpu-method loop --timeout 8s \
    >/dev/null 2>&1 &
stress_pid=$!
taskset -c 0 yes >/dev/null &
pinned_pid=$!
sleep 2
scheduler_enabled || fail "scheduler exited under affinity-only policy"
grep -Eq 'normal/affinity enqueues 0/[1-9][0-9]*' "${snake_log}" ||
    fail "affinity-only enqueue ladder was not observed"
grep -Eq 'dispatches 0/[1-9][0-9]*' "${snake_log}" ||
    fail "affinity-only dispatch source was not observed"

"${snake_bin}" --update-policy "${replacement}" >"${update_log}" 2>&1 ||
    fail "same-topology callback replacement failed"
grep -q 'activated policy generation 2' "${update_log}" ||
    fail "callback replacement did not advance the generation"
sleep 2
scheduler_enabled || fail "scheduler exited after callback replacement"
grep -Eq 'normal/affinity enqueues [1-9][0-9]*/[0-9]+' "${snake_log}" ||
    fail "cell enqueue rung was not observed after replacement"
grep -Eq 'dispatches [1-9][0-9]*/[0-9]+' "${snake_log}" ||
    fail "cell dispatch source was not observed after replacement"

"${snake_bin}" --update-policy "${reordered}" >"${update_log}" 2>&1 ||
    fail "callback dispatch reorder failed"
grep -q 'activated policy generation 3' "${update_log}" ||
    fail "dispatch reorder did not advance the generation"
sleep 1
python3 - "${snake_log}" <<'PY' || fail "reordered generation did not dispatch both sources"
import re
import sys

generation = None
normal = 0
affinity = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        match = re.search(r"policy generation (\d+) stats", line)
        if match:
            generation = int(match.group(1))
            continue
        if generation != 3:
            continue
        match = re.search(r"dispatches (\d+)/(\d+)", line)
        if match:
            normal += int(match.group(1))
            affinity += int(match.group(2))
if normal == 0 or affinity == 0:
    raise SystemExit(f"generation 3 dispatches normal={normal} affinity={affinity}")
PY
scheduler_enabled || fail "scheduler exited after callback dispatch reorder"

"${snake_bin}" --update-policy "${min_vtime}" >"${update_log}" 2>&1 ||
    fail "min_vtime callback replacement failed"
grep -q 'activated policy generation 4' "${update_log}" ||
    fail "min_vtime replacement did not advance the generation"
sleep 2
python3 - "${snake_log}" <<'PY' || fail "min_vtime did not dispatch both queue classes"
import re
import sys

generation = None
normal = 0
affinity = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        match = re.search(r"policy generation (\d+) stats", line)
        if match:
            generation = int(match.group(1))
            continue
        if generation != 4:
            continue
        match = re.search(r"dispatches (\d+)/(?P<affinity>\d+)", line)
        if match:
            normal += int(match.group(1))
            affinity += int(match.group("affinity"))
if normal == 0 or affinity == 0:
    raise SystemExit(f"generation 4 dispatches normal={normal} affinity={affinity}")
PY
scheduler_enabled || fail "scheduler exited after min_vtime replacement"

timeout --signal=TERM --kill-after=2s 8s \
    stress-ng --fork "${cpus}" --fork-max 4 --fork-vm --timeout 3s \
    >/dev/null 2>&1 || fail "min_vtime fork/exit churn failed"
scheduler_enabled || fail "scheduler exited during min_vtime fork/exit churn"

if "${snake_bin}" --update-policy "${initial}" >"${update_log}" 2>&1; then
    fail "source-removing callback replacement unexpectedly succeeded"
fi
# shellcheck disable=SC2016 # Backticks are literal policy diagnostic text.
grep -q 'cannot remove active queue enqueue target `cell`' "${update_log}" ||
    fail "source-removing replacement returned the wrong error"
scheduler_enabled || fail "rejected source removal disturbed the active scheduler"

deadline=$((SECONDS + 12))
while ! pid_done "${stress_pid}"; do
    scheduler_enabled || fail "scheduler exited during callback ladder stress"
    ((SECONDS < deadline)) || fail "callback ladder stress did not finish"
    sleep 0.1
done
stress_rc=0
wait "${stress_pid}" || stress_rc=$?
stress_pid=
((stress_rc == 0)) || fail "callback ladder stress failed with status ${stress_rc}"
stop_pid "${pinned_pid}"
pinned_pid=

run_dispatch_ready_phase "${reordered}" 5
run_dispatch_ready_phase "${replacement}" 6
echo "PASS: both cyclic dispatch sources drained after live reorder"

if "${snake_bin}" --update-policy "${invalid}" >"${update_log}" 2>&1; then
    fail "topology-changing callback replacement unexpectedly succeeded"
fi
grep -q 'changes the attachment-time queue topology' "${update_log}" ||
    fail "topology-changing replacement returned the wrong error"
scheduler_enabled || fail "rejected replacement disturbed the active scheduler"

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext error"
fi

echo "PASS: queue callback ladders replaced atomically without changing topology"
