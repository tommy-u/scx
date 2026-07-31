#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
policy=${2:-${repo}/scheds/rust/scx_snake/examples/llc.toml}
tmpdir=$(mktemp -d)
snake_log=${tmpdir}/snake.log
update_log=${tmpdir}/update.log
reduced_policy=${tmpdir}/reduced.toml
snake_pid=
stress_pid=
dmesg_lines=0

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
    for ((attempt = 0; attempt < 50; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    kill "${stress_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${stress_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime policy reader lifetime test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 160 "${snake_log}" >&2 || true
    cat "${update_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v timeout >/dev/null || fail "timeout is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"

cpus=$(nproc)
workers=$((cpus * 2))
fork_workers=$((cpus / 4))
((fork_workers < 1)) && fork_workers=1
dmesg_lines=$(dmesg | wc -l)

printf '%s\n' \
    'fallback = "previous_cpu"' \
    '' \
    '[[rung]]' \
    'operation = "claim_idle"' \
    'scope = "previous_cpu"' \
    '' \
    '[[rung]]' \
    'operation = "pick_idle"' \
    'scope = "task_allowed"' >"${reduced_policy}"

"${snake_bin}" --policy "${policy}" --fairness vtime \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    if scheduler_enabled &&
        grep -q 'attached scx_snake policy generation 1' "${snake_log}"; then
        break
    fi
    sleep 0.05
done
if ! scheduler_enabled ||
    ! grep -q 'attached scx_snake policy generation 1' "${snake_log}"; then
    fail "scheduler did not attach and open its control socket"
fi

timeout --signal=TERM --kill-after=3s 45s \
    stress-ng --cpu "${workers}" --cpu-method loop \
    --fork "${fork_workers}" --fork-max 4 \
    --futex "${fork_workers}" --yield "${fork_workers}" --timeout 35s \
    >"${tmpdir}/stress.log" 2>&1 &
stress_pid=$!

for generation in $(seq 2 21); do
    if ((generation % 2 == 0)); then
        candidate=${reduced_policy}
    else
        candidate=${policy}
    fi
    timeout --signal=TERM --kill-after=2s 8s \
        "${snake_bin}" --update-policy "${candidate}" \
        >"${update_log}" 2>&1 ||
        fail "policy update for generation ${generation} failed or timed out"
    grep -q "activated policy generation ${generation}" "${update_log}" ||
        fail "policy update did not activate generation ${generation}"
    scheduler_enabled || fail "scheduler exited after generation ${generation}"
done

deadline=$((SECONDS + 45))
while ! pid_done "${stress_pid}"; do
    scheduler_enabled || fail "scheduler exited during reader-lifetime stress"
    ((SECONDS < deadline)) || fail "reader-lifetime stress did not finish"
    sleep 0.1
done
stress_rc=0
wait "${stress_pid}" || stress_rc=$?
stress_pid=
((stress_rc == 0)) || fail "reader-lifetime stress failed with status ${stress_rc}"
scheduler_enabled || fail "scheduler exited after reader-lifetime stress"

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|BUG:|kernel panic'; then
    fail "kernel log contains a scheduler failure signature"
fi

echo "PASS: 20 live VTIME policy replacements completed under load on ${cpus} CPUs"
