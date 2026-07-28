#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

snake_bin=${1:-target/debug/scx_snake}
policy=${2:-scheds/rust/scx_snake/examples/kernel-default-sim.toml}
duration=${VTIME_AFFINITY_DURATION:-10}
tmpdir=$(mktemp -d)
snake_log=${tmpdir}/snake.log
dmesg_lines=0
snake_pid=
hot_pid=
wide_pid=

cleanup() {
    for pid in "${hot_pid}" "${wide_pid}"; do
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
taskset -c "0-${hot_last}" stress-ng --cpu "${hot_workers}" \
    --cpu-method loop --timeout "${duration}s" >"${tmpdir}/hot.log" 2>&1 &
hot_pid=$!
taskset -c "${wide_first}-${wide_last}" stress-ng --cpu "${wide_workers}" \
    --cpu-method loop --timeout "${duration}s" >"${tmpdir}/wide.log" 2>&1 &
wide_pid=$!

while kill -0 "${hot_pid}" 2>/dev/null || kill -0 "${wide_pid}" 2>/dev/null; do
    scheduler_enabled || fail "scheduler exited during mixed-affinity load"
    sleep 0.1
done
wait "${hot_pid}"
hot_pid=
wait "${wide_pid}"
wide_pid=
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
