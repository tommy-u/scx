#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo=${SNAKE_REPO:-/home/tommyu/scx-snake}
snake_bin=${1:-${repo}/target/release/scx_snake}
tmpdir=$(mktemp -d)
initial=${tmpdir}/initial.toml
replacement=${tmpdir}/replacement.toml
invalid=${tmpdir}/invalid.toml
snake_log=${tmpdir}/snake.log
update_log=${tmpdir}/update.log
snake_pid=
stress_pid=
dmesg_lines=0

cleanup() {
    if [[ -n ${stress_pid} ]]; then
        kill "${stress_pid}" 2>/dev/null || true
        wait "${stress_pid}" 2>/dev/null || true
    fi
    if [[ -n ${snake_pid} ]]; then
        kill -INT "${snake_pid}" 2>/dev/null || true
        wait "${snake_pid}" 2>/dev/null || true
    fi
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

write_policy() {
    local path=$1 layout=$2 mode=$3

    {
        printf '[queues]\nlayout = "%s"\n\n' "${layout}"
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
                'target = "affinity"' \
                '[[queues.dispatch]]' \
                'source = "cell"' \
                '[[queues.dispatch]]' \
                'source = "affinity"'
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
(( $(nproc) >= 4 )) || fail "requires at least four CPUs"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
command -v stress-ng >/dev/null || fail "stress-ng is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
dmesg_lines=$(dmesg | wc -l)

write_policy "${initial}" cell affinity
write_policy "${replacement}" cell full
write_policy "${invalid}" cell_llc full

"${snake_bin}" --policy "${initial}" --fairness vtime --stats 0.25 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

stress-ng --cpu $(( $(nproc) * 2 )) --cpu-method loop --timeout 8s >/dev/null 2>&1 &
stress_pid=$!
sleep 2
scheduler_enabled || fail "scheduler exited under affinity-only policy"
grep -Eq 'normal/affinity enqueues 0/[1-9][0-9]*' "${snake_log}" ||
    fail "affinity-only enqueue ladder was not observed"

"${snake_bin}" --update-policy "${replacement}" >"${update_log}" 2>&1 ||
    fail "same-topology callback replacement failed"
grep -q 'activated policy generation 2' "${update_log}" ||
    fail "callback replacement did not advance the generation"
sleep 2
scheduler_enabled || fail "scheduler exited after callback replacement"
grep -Eq 'normal/affinity enqueues [1-9][0-9]*/[0-9]+' "${snake_log}" ||
    fail "cell enqueue rung was not observed after replacement"

if "${snake_bin}" --update-policy "${initial}" >"${update_log}" 2>&1; then
    fail "source-removing callback replacement unexpectedly succeeded"
fi
grep -q 'cannot remove active queue enqueue target `cell`' "${update_log}" ||
    fail "source-removing replacement returned the wrong error"
scheduler_enabled || fail "rejected source removal disturbed the active scheduler"

wait "${stress_pid}"
stress_pid=

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
