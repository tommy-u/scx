#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
policy_template=${2:-${repo}/scheds/rust/scx_snake/examples/mitosis-sim.toml}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.log
workload_log=${tmpdir}/workload.log
cgroup_root=/sys/fs/cgroup
parent_name=scx-snake-managed-churn-$$
parent=${cgroup_root}/${parent_name}
child=${parent}/workload
racy_child=${parent}/racy
snake_pid=
worker_pid=
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
        sleep 0.02
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

stop_workload() {
    local attempt

    if [[ -n ${worker_pid} ]]; then
        kill -TERM -- "-${worker_pid}" 2>/dev/null || true
        stop_pid "${worker_pid}"
        worker_pid=
    fi
    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -d ${child} ]] || return 0
        if [[ -z $(cat "${child}/cgroup.procs" 2>/dev/null) ]]; then
            rmdir "${child}" 2>/dev/null && return 0
        fi
        sleep 0.02
    done
    return 1
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    set +e
    stop_workload
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${snake_pid}" INT
    rmdir "${child}" 2>/dev/null || true
    rmdir "${racy_child}" 2>/dev/null || true
    rmdir "${parent}" 2>/dev/null || true
    rm -rf "${tmpdir}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "vtime managed-cell churn test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 160 "${snake_log}" >&2 2>/dev/null || true
    tail -n 40 "${workload_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for_enabled() {
    local attempt

    for ((attempt = 0; attempt < 200; attempt++)); do
        scheduler_enabled && return 0
        sleep 0.05
    done
    return 1
}

wait_for_cell_count_after() {
    local cells=$1 first_line=$2 attempt
    local pattern="activated managed cell topology generation [0-9]+ with ${cells} managed cells"

    for ((attempt = 0; attempt < 300; attempt++)); do
        tail -n +"${first_line}" "${snake_log}" | grep -Eq "${pattern}" && return 0
        scheduler_enabled || return 1
        sleep 0.05
    done
    return 1
}

soak_switch_workload() {
    local attempt

    for ((attempt = 0; attempt < 100; attempt++)); do
        scheduler_enabled || return 1
        kill -0 "${worker_pid}" 2>/dev/null || return 1
        sleep 0.02
    done
}

start_workload() {
    mkdir "${child}"
    printf '%s\n' "${cpuset_mems}" >"${child}/cpuset.mems"
    # Leave cpuset.cpus empty so this managed child exercises unpinned admission.
    [[ -z $(<"${child}/cpuset.cpus") ]] || fail "managed child cpuset.cpus is not empty"
    # shellcheck disable=SC2016 # The child expands its own PID and arguments.
    setsid bash -c '
        printf "%s\n" "$$" >"$1/cgroup.procs"
        exec stress-ng --switch 1 --switch-method pipe --metrics-brief
    ' _ "${child}" >"${workload_log}" 2>&1 &
    worker_pid=$!
}

((EUID == 0)) || fail "must run as root inside a VM"
if [[ ${SNAKE_TEST_ALLOW_BARE_METAL:-0} != 1 ]]; then
    if command -v systemd-detect-virt >/dev/null; then
        systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
    else
        grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
    fi
fi
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy_template} ]] || fail "policy template is not readable: ${policy_template}"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v setsid >/dev/null || fail "setsid is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
    fail "cgroup root does not provide the cpuset controller"
(( $(nproc) >= 2 )) || fail "requires at least two CPUs"

online_cpus=$(cat /sys/devices/system/cpu/online)
cpuset_mems=$(cat "${cgroup_root}/cpuset.mems.effective")
[[ -n ${cpuset_mems} ]] || fail "root cpuset has no effective memory nodes"
dmesg_lines=$(dmesg | wc -l)

grep -qw cpuset "${cgroup_root}/cgroup.subtree_control" ||
    printf '%s\n' +cpuset >"${cgroup_root}/cgroup.subtree_control"
mkdir "${parent}"
printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"
sed \
    -e "s|^parent = .*|parent = \"/${parent_name}\"|" \
    -e 's/^reconcile_ms = .*/reconcile_ms = 50/' \
    -e 's/^cell0_min_cpus = .*/cell0_min_cpus = 1/' \
    -e 's/^threshold_pct = .*/threshold_pct = 1000000.0/' \
    "${policy_template}" >"${policy}"
grep -Fq "parent = \"/${parent_name}\"" "${policy}" ||
    fail "managed-cell parent was not replaced in the test policy"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.1 \
    --stats-format json --exit-dump-len 1048576 >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for_enabled || fail "scheduler did not attach"

for _ in $(seq 1 100); do
    mkdir "${racy_child}"
    printf '%s\n' "${cpuset_mems}" >"${racy_child}/cpuset.mems"
    sleep 0.005
    rmdir "${racy_child}"
    sleep 0.005
    scheduler_enabled || fail "scheduler exited during rapid managed-cgroup churn"
done
sleep 0.1
scheduler_enabled || fail "scheduler exited after rapid managed-cgroup churn"

first_line=$(( $(wc -l <"${snake_log}") + 1 ))
start_workload
wait_for_cell_count_after 1 "${first_line}" || fail "first managed cell was not activated"
soak_switch_workload || fail "scheduler exited during the first switch workload"
first_line=$(( $(wc -l <"${snake_log}") + 1 ))
stop_workload || fail "first managed cgroup did not become removable"
wait_for_cell_count_after 0 "${first_line}" || fail "first managed cell was not removed"

first_line=$(( $(wc -l <"${snake_log}") + 1 ))
start_workload
wait_for_cell_count_after 1 "${first_line}" || fail "recreated managed cell was not activated"
soak_switch_workload || fail "scheduler exited during the recreated switch workload"
first_line=$(( $(wc -l <"${snake_log}") + 1 ))
stop_workload || fail "recreated managed cgroup did not become removable"
wait_for_cell_count_after 0 "${first_line}" || fail "recreated managed cell was not removed"
scheduler_enabled || fail "scheduler exited after managed-cell churn"

if grep -Eq 'invalid enq_flags|scx_bpf_error|Error: EXIT' "${snake_log}"; then
    fail "scheduler log contains a sched_ext failure"
fi
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext failure"
fi

kill -INT "${snake_pid}"
stop_pid "${snake_pid}" INT
snake_pid=
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "scheduler did not detach cleanly"

echo "PASS: unpinned managed cell create/delete/recreate survived a pipe-switch workload"
