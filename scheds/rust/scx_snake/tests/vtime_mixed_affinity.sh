#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
policy=${2:-${repo}/scheds/rust/scx_snake/examples/kernel-default-sim.toml}
duration=${VTIME_AFFINITY_DURATION:-10}
tmpdir=$(mktemp -d)
snake_log=${tmpdir}/snake.log
dmesg_lines=0
snake_pid=
hot_pid=
wide_pid=

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
    kill "${hot_pid}" "${wide_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${hot_pid}"
    stop_pid "${wide_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime mixed-affinity test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 200 "${snake_log}" >&2 || true
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
cpus=$(nproc)
(( cpus >= 4 )) || fail "requires at least four CPUs"
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v taskset >/dev/null || fail "taskset is required"
command -v timeout >/dev/null || fail "timeout is required"
dmesg_lines=$(dmesg | wc -l)

narrow_cpus=$((cpus / 16))
(( narrow_cpus < 2 )) && narrow_cpus=2
(( narrow_cpus > 16 )) && narrow_cpus=16
wide_first=${narrow_cpus}
hot_last=$((narrow_cpus - 1))
wide_last=$((cpus - 1))
hot_workers=$((narrow_cpus * 8))
wide_workers=$((cpus - narrow_cpus))

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 1 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

# Before per-CPU VTIME queues, wide CPUs repeatedly walked past every task in
# the narrow group and the sched_ext watchdog missed its five-second check-in.
timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    taskset -c "0-${hot_last}" stress-ng --cpu "${hot_workers}" \
    --cpu-method loop --timeout "${duration}s" >"${tmpdir}/hot.log" 2>&1 &
hot_pid=$!
timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    taskset -c "${wide_first}-${wide_last}" stress-ng --cpu "${wide_workers}" \
    --cpu-method loop --timeout "${duration}s" >"${tmpdir}/wide.log" 2>&1 &
wide_pid=$!

deadline=$((SECONDS + duration + 8))
while ! pid_done "${hot_pid}" || ! pid_done "${wide_pid}"; do
    scheduler_enabled || fail "scheduler exited during mixed-affinity load"
    ((SECONDS < deadline)) || fail "mixed-affinity workloads did not finish"
    sleep 0.1
done
hot_rc=0
wait "${hot_pid}" || hot_rc=$?
hot_pid=
wide_rc=0
wait "${wide_pid}" || wide_rc=$?
wide_pid=
((hot_rc == 0 && wide_rc == 0)) ||
    fail "mixed-affinity workloads failed: hot=${hot_rc} wide=${wide_rc}"
scheduler_enabled || fail "scheduler exited after mixed-affinity load"

grep -Eq 'VTIME enqueues: [0-9]+ \(per-CPU: [1-9][0-9]*\)' "${snake_log}" ||
    fail "per-CPU VTIME queues were not exercised"
grep -Eq 'invalid/errors: [1-9][0-9]*' "${snake_log}" &&
    fail "Snake reported invalid errors"
grep -Eq 'accounting errors: [1-9][0-9]*' "${snake_log}" &&
    fail "Snake reported accounting errors"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)'; then
    fail "kernel log contains a sched_ext error"
fi

echo "PASS: VTIME mixed-affinity load completed on ${cpus} CPUs"
