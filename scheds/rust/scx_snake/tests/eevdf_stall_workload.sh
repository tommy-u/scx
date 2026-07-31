#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/debug/scx_snake}
policy=${2:-${repo}/scheds/rust/scx_snake/examples/basic.toml}
workload=${3:-mixed_affinity}
health_secs=${SNAKE_EEVDF_HEALTH_SECS:-60}
artifact=${SNAKE_EEVDF_STALL_ARTIFACT:-$(mktemp -d /tmp/scx-snake-eevdf-stall.XXXXXX)}
snake_log=${artifact}/scheduler.log
workload_log=${artifact}/workload.log
wakee_armed=${artifact}/wakee-armed
wakee_ran=${artifact}/wakee-ran
dmesg_lines=0
snake_pid=
workload_pid=

pid_done() {
    local pid=$1 state

    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

group_running() {
    local pgid=$1 state

    while read -r state; do
        [[ ${state} != Z* ]] && return 0
    done < <(ps -o stat= -g "${pgid}" 2>/dev/null || true)
    return 1
}

stop_group() {
    local pid=$1 signal=${2:-TERM} attempt

    [[ -n ${pid} ]] || return 0
    kill "-${signal}" -- "-${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 30; attempt++)); do
        if ! group_running "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    kill -KILL -- "-${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    stop_group "${workload_pid}"
    stop_group "${snake_pid}" INT
    dmesg | tail -n +$((dmesg_lines + 1)) >"${artifact}/dmesg-new.txt" 2>&1 || true
    printf '%s\n' "${rc}" >"${artifact}/test.rc"
    printf 'artifacts: %s\n' "${artifact}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "EEVDF ${workload} stall test: $*" >&2
    echo "sched_ext state: $(cat /sys/kernel/sched_ext/state 2>/dev/null || true)" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 200 "${snake_log}" >&2 || true
    exit 1
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
    local count fork_count minimum name parent

    case ${workload} in
        mixed_affinity)
            name=stress-ng-cpu
            minimum=$((workload_cpus * 2))
            ;;
        fork_yield)
            name=stress-ng-yield
            minimum=$((workload_cpus * 4))
            ;;
    esac
    count=$(pgrep -g "${workload_pid}" -c -x "${name}" 2>/dev/null || true)
    (( count >= minimum )) || return 1
    if [[ ${workload} == fork_yield ]]; then
        fork_count=0
        while read -r parent; do
            count=$(pgrep -P "${parent}" -c -x stress-ng-fork \
                2>/dev/null || true)
            fork_count=$((fork_count + count))
        done < <(pgrep -P "${workload_pid}" -x stress-ng 2>/dev/null || true)
        (( fork_count >= workload_cpus / 2 )) || return 1
        [[ -e ${wakee_armed} ]]
    fi
}

kernel_failure_seen() {
    dmesg | tail -n +$((dmesg_lines + 1)) | \
        grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)'
}

stats_failure_seen() {
    grep -Eq '"(invalid_errors|eevdf_accounting_errors)":[[:space:]]*[1-9]' \
        "${snake_log}"
}

run_lag_clamp_seen() {
    grep -Eq '"eevdf_run_lag_clamps":[[:space:]]*[1-9]' "${snake_log}"
}

wait_for_workers() {
    local deadline=$((SECONDS + 30)) last_log_check=-1

    while (( SECONDS < deadline )); do
        scheduler_enabled || fail "scheduler exited while starting ${workload}"
        group_running "${workload_pid}" || fail "${workload} exited during startup"
        if (( SECONDS != last_log_check )); then
            kernel_failure_seen && fail "kernel log contains a sched_ext failure"
            last_log_check=${SECONDS}
        fi
        workers_ready && return 0
        sleep 0.05
    done
    fail "timed out waiting for ${workload} workers"
}

mkdir -p "${artifact}"
rm -f -- "${wakee_armed}" "${wakee_ran}"
(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
cpus=$(nproc)
(( cpus >= 2 )) || fail "requires at least two CPUs"
# Eight CPUs reproduce the offending global-clock interactions without making
# this fixture scale its process count with large VM gauntlet guests.
workload_cpus=$((cpus < 8 ? cpus : 8))
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
[[ ${health_secs} =~ ^[1-9][0-9]*$ ]] || fail "health window must be positive"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
case ${workload} in
    mixed_affinity | fork_yield) ;;
    *) fail "unknown workload ${workload}" ;;
esac
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v taskset >/dev/null || fail "taskset is required"
dmesg_lines=$(dmesg | wc -l)

setsid "${snake_bin}" --policy "${policy}" --fairness eevdf --stats 1 \
    --stats-format json >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for "Snake to attach" 30 scheduler_enabled

case ${workload} in
    mixed_affinity)
        # The positional parameter and child PIDs belong to the inner shell.
        # shellcheck disable=SC2016
        setsid bash -c '
            taskset -c 0 stress-ng --cpu "$1" --cpu-method loop --aggressive &
            narrow=$!
            stress-ng --cpu "$1" --cpu-method loop --aggressive &
            wide=$!
            wait -n "${narrow}" "${wide}"
        ' bash "${workload_cpus}" >"${workload_log}" 2>&1 &
        ;;
    fork_yield)
        # Recreate the matrix's fork/yield churn while concentrating the yield
        # cohort on one CPU. The delayed wakee proves that the stale cohort
        # cannot monopolize that CPU after the global clock advances elsewhere.
        # shellcheck disable=SC2016
        setsid bash -c '
            armed=$1
            ran=$2
            cpus=$3
            taskset -c 0 bash -c '\''
                : >"$1"
                sleep 5
                : >"$2"
                exec stress-ng --yield 1 --yield-procs 1
            '\'' bash "${armed}" "${ran}" &
            wakee=$!
            while [[ ! -e ${armed} ]]; do sleep 0.01; done
            taskset -c 0 stress-ng --yield "${cpus}" --yield-procs 4 &
            yielders=$!
            taskset -c "1-$((cpus - 1))" stress-ng --fork "$((cpus / 2))" &
            forkers=$!
            wait -n "${wakee}" "${yielders}" "${forkers}"
        ' bash "${wakee_armed}" "${wakee_ran}" "${workload_cpus}" \
            >"${workload_log}" 2>&1 &
        ;;
esac
workload_pid=$!
wait_for_workers

# This is intentionally time based: it verifies health across the full
# 60-second matrix window after all workload workers exist.
SECONDS=0
# Bash exposes only whole seconds. The extra second guarantees that the
# measured interval cannot end on the short side of the requested window.
health_deadline=$((health_secs + 1))
last_log_check=-1
while (( SECONDS < health_deadline )); do
    scheduler_enabled || fail "scheduler exited during the watchdog window"
    pid_done "${workload_pid}" && fail "workload exited early"
    group_running "${workload_pid}" || fail "workload process group exited early"
    if (( SECONDS != last_log_check )); then
        kernel_failure_seen && fail "kernel log contains a sched_ext failure"
        stats_failure_seen && fail "Snake reported a fairness accounting error"
        workers_ready || fail "${workload} worker cohort degraded"
        last_log_check=${SECONDS}
    fi
    if [[ ${workload} == fork_yield && ${SECONDS} -ge 12 && ! -e ${wakee_ran} ]]; then
        fail "delayed CPU 0 wakee did not run within seven seconds of waking"
    fi
    sleep 0.1
done

kernel_failure_seen && fail "kernel log contains a sched_ext failure"
stats_failure_seen && fail "Snake reported a fairness accounting error"
if [[ ${workload} == fork_yield ]]; then
    [[ -e ${wakee_ran} ]] || fail "delayed CPU 0 wakee never ran"
fi
run_lag_clamp_seen || fail "run-start lag clamp was not exercised"

echo "PASS: EEVDF ${workload} stayed healthy for ${health_secs}s"
