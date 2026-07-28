#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo=${SNAKE_REPO:-/home/tommyu/scx-snake}
snake_bin=${1:-${repo}/target/release/scx_snake}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.log
snake_pid=
dmesg_lines=0

cleanup() {
    if [[ -n ${snake_pid} ]]; then
        kill -INT "${snake_pid}" 2>/dev/null || true
        wait "${snake_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime cell fairness test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 || true
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
(( $(nproc) >= 4 )) || fail "requires at least four CPUs"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -x ${repo}/scheds/rust/scx_snake/interactive/fairness-demo.sh ]] ||
    fail "fairness demo is not executable"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
dmesg_lines=$(dmesg | wc -l)

printf '%s\n' \
    '[queues]' \
    'layout = "cell"' \
    '' \
    '[[rung]]' \
    'operation = "pick_idle"' \
    'scope = "task_allowed"' >"${policy}"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 1 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

# All demo workers are pinned to CPU 0. In queue mode this places them in the
# same per-CPU affinity DSQ and validates weighted ordering within that class.
FAIRNESS_CPU=0 FAIRNESS_DURATION=${SNAKE_FAIRNESS_DURATION:-5} \
    "${repo}/scheds/rust/scx_snake/interactive/fairness-demo.sh"
scheduler_enabled || fail "scheduler exited during fairness test"

grep -Eq 'invalid/errors: [1-9][0-9]*' "${snake_log}" &&
    fail "Snake reported invalid errors"
grep -Eq 'accounting errors: [1-9][0-9]*' "${snake_log}" &&
    fail "Snake reported accounting errors"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|snake.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext error"
fi

echo "PASS: queue-mode VTIME preserved nice-level weighted shares"
