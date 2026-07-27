#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

snake_bin=${1:-target/debug/scx_snake}
policy=${2:-scheds/rust/scx_snake/examples/kernel-default-sim.toml}
tmpdir=$(mktemp -d)
snake_log=${tmpdir}/snake.log
cpu0_log=${tmpdir}/cpu0.log
dmesg_lines=0
snake_pid=
cpu0_stress=
cpu1_worker=

cleanup() {
    for pid in "${cpu0_stress}" "${cpu1_worker}"; do
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
    echo "eevdf affinity test: $*" >&2
    if [[ -s ${snake_log} ]]; then
        tail -n 200 "${snake_log}" >&2
    fi
    exit 1
}

ticks() {
    local pid=$1

    awk '{ line=$0; sub(/^[^(]*\([^)]*\) /, "", line); split(line, field, " "); print field[12] + field[13] }' \
        "/proc/${pid}/stat"
}

wait_for() {
    local description=$1 timeout=$2
    shift 2
    local deadline=$((SECONDS + timeout))

    while (( SECONDS < deadline )); do
        if "$@"; then
            return 0
        fi
        sleep 0.05
    done
    fail "timed out waiting for ${description}"
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

workers_ready() {
    local count

    count=$(pgrep -P "${cpu0_stress}" -c stress-ng-cpu 2>/dev/null || true)
    (( count >= 16 ))
}

cpu1_named() {
    [[ -r /proc/${cpu1_worker}/comm ]] &&
        [[ $(cat "/proc/${cpu1_worker}/comm") == yes ]]
}

forced_advance_seen() {
    grep -Eq 'forced advances: [1-9][0-9]*' "${snake_log}"
}

cpu1_progressed() {
    [[ -r /proc/${cpu1_worker}/stat ]] &&
        (( $(ticks "${cpu1_worker}") > cpu1_ticks ))
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
(( $(nproc) >= 2 )) || fail "requires at least two CPUs"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v taskset >/dev/null || fail "taskset is required"
dmesg_lines=$(dmesg | wc -l)

"${snake_bin}" --policy "${policy}" --fairness eevdf --stats 1 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for "Snake to attach" 10 scheduler_enabled

# These CPU-0-only workers keep the global eligible DSQ non-empty and slow the
# global virtual clock. Their service interval remains well below the 5-second
# watchdog, so they do not create an overload-induced stall.
taskset -c 0 nice -n -10 stress-ng --cpu 16 --cpu-method loop --timeout 15s \
    >"${cpu0_log}" 2>&1 &
cpu0_stress=$!
wait_for "CPU-0 stress workers" 10 workers_ready

# After its first request, this low-weight CPU-1-only task enters the future
# DSQ. CPU 1 must advance to it even though CPU-0 work remains eligible.
taskset -c 1 nice -n 19 yes >/dev/null &
cpu1_worker=$!
wait_for "CPU-1 worker exec" 2 cpu1_named
cpu1_ticks=$(ticks "${cpu1_worker}")
wait_for "an affinity-aware forced advance" 4 forced_advance_seen
wait_for "continued CPU-1 progress" 3 cpu1_progressed

# Remain healthy beyond one complete watchdog interval. This wait is testing
# the five-second watchdog behavior rather than waiting for asynchronous setup.
health_deadline=$((SECONDS + 6))
while (( SECONDS < health_deadline )); do
    scheduler_enabled || fail "scheduler exited during the watchdog window"
    sleep 0.1
done

grep -Eq 'accounting errors: [1-9][0-9]*' "${snake_log}" &&
    fail "EEVDF reported accounting errors"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)'; then
    fail "kernel log contains a sched_ext error"
fi
echo "PASS: affinity-constrained future task made progress without a watchdog exit"
