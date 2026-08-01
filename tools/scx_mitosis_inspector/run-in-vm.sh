#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

repo=${MITOSIS_REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}
scheduler=${MITOSIS_BIN:-${repo}/target/release/scx_mitosis}
inspector=${MITOSIS_INSPECTOR_BIN:-${repo}/tools/scx_mitosis_inspector/target/release/scx_mitosis_inspector}
cell_parent_arg=/workload.slice/workload-tw.slice
cell_parent=/sys/fs/cgroup${cell_parent_arg}
cell_names=(inspector-a.service inspector-b.service)
workers_per_cell=${MITOSIS_WORKERS_PER_CELL:-4}
waker_interval=${MITOSIS_WAKER_INTERVAL_SECONDS:-0.02}
scheduler_log=/tmp/scx-mitosis.log
scheduler_pid=
workload_pids=()
waker_fifo=/tmp/scx-mitosis-waker-$$
waker_timer_fifo=/tmp/scx-mitosis-waker-timer-$$

scheduler_args=(
    --exit-dump-len 1048576
    --cell-parent-cgroup "${cell_parent_arg}"
    --cell-exclude systemd-workaround.service
    --cell0-min-cpus 4
)

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    if (( ${#workload_pids[@]} > 0 )); then
        kill "${workload_pids[@]}" 2>/dev/null || true
        wait "${workload_pids[@]}" 2>/dev/null || true
    fi
    rm -f "${waker_fifo}" "${waker_timer_fifo}"
    if [[ -n ${scheduler_pid} ]]; then
        kill -INT "${scheduler_pid}" 2>/dev/null || true
        wait "${scheduler_pid}" 2>/dev/null || true
    fi
    for cell in "${cell_names[@]}"; do
        rmdir "${cell_parent}/${cell}" 2>/dev/null || true
    done
    rmdir "${cell_parent}" 2>/dev/null || true
    rmdir /sys/fs/cgroup/workload.slice 2>/dev/null || true
    exit "${rc}"
}
trap cleanup EXIT INT TERM

[[ ${EUID} -eq 0 ]] || { echo "run-in-vm.sh must run as root" >&2; exit 1; }
[[ -x ${scheduler} ]] || { echo "scheduler not executable: ${scheduler}" >&2; exit 1; }
[[ -x ${inspector} ]] || { echo "inspector not executable: ${inspector}" >&2; exit 1; }
[[ $(nproc) -eq 16 ]] || { echo "expected 16 CPUs, found $(nproc)" >&2; exit 1; }
[[ ${workers_per_cell} =~ ^[1-9][0-9]*$ ]] || { echo "MITOSIS_WORKERS_PER_CELL must be positive" >&2; exit 1; }
command -v yes >/dev/null || { echo "yes is required for dummy workloads" >&2; exit 1; }

for cell in "${cell_names[@]}"; do
    path=${cell_parent}/${cell}
    mkdir -p "${path}"
    for ((worker = 0; worker < workers_per_cell; worker++)); do
        bash -c 'echo "$$" >"$1/cgroup.procs"; exec yes' _ "${path}" >/dev/null &
        workload_pids+=("$!")
    done
done

# Dynamic affinity, borrowing, rebalancing, slice shrinking, and LLC awareness
# are always enabled by this Mitosis version and no longer have CLI switches.
"${scheduler}" "${scheduler_args[@]}" >"${scheduler_log}" 2>&1 &
scheduler_pid=$!

deadline=$((SECONDS + 30))
until [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]]; do
    if ! kill -0 "${scheduler_pid}" 2>/dev/null; then
        cat "${scheduler_log}" >&2
        exit 1
    fi
    (( SECONDS < deadline )) || { echo "timed out waiting for mitosis" >&2; exit 1; }
    sleep 0.2
done

for cell in "${cell_names[@]}"; do
    path=${cell_parent}/${cell}
    actual_workers=$(wc -l <"${path}/cgroup.procs")
    [[ ${actual_workers} -eq ${workers_per_cell} ]] || {
        echo "expected ${workers_per_cell} workers in ${cell}, found ${actual_workers}" >&2
        exit 1
    }
    grep -q "Created cell .*${cell}" "${scheduler_log}" || {
        echo "Mitosis did not register ${cell} as a cell" >&2
        cat "${scheduler_log}" >&2
        exit 1
    }
done

mkfifo "${waker_fifo}" "${waker_timer_fifo}"
bash -c '
    echo "$$" >"$1/cgroup.procs"
    exec 3<>"$2"
    while IFS= read -r token <&3; do :; done
' _ "${cell_parent}/${cell_names[0]}" "${waker_fifo}" &
workload_pids+=("$!")
bash -c '
    echo "$$" >"$1/cgroup.procs"
    exec 3<>"$2" 4<>"$3"
    while :; do
        IFS= read -r -t "$4" token <&4 || true
        printf ".\n" >&3
    done
' _ "${cell_parent}/${cell_names[1]}" "${waker_fifo}" "${waker_timer_fifo}" "${waker_interval}" &
workload_pids+=("$!")

echo "scx_mitosis attached on $(nproc) CPUs with ${#cell_names[@]} workload cells"
echo "dummy workloads: ${workers_per_cell} workers each in ${cell_names[*]}"
echo "waker/wakee: one pipe handoff every ${waker_interval}s across ${cell_names[*]}"
"${inspector}" --listen 0.0.0.0:44105
