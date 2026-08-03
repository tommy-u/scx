#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
policy_template=${2:-${repo}/scheds/rust/scx_snake/examples/mitosis-sim.toml}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
parent_name=scx-snake-managed-resize-$$
parent=/sys/fs/cgroup/${parent_name}
alpha=${parent}/alpha
beta=${parent}/beta
snake_pid=
alpha_pid=
beta_pid=
dmesg_lines=0

pid_done() {
    local pid=$1 state
    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

stop_pid() {
    local pid=$1 attempt
    [[ -n ${pid} ]] || return 0
    kill -TERM -- "-${pid}" 2>/dev/null || true
    kill -TERM "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 50; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.02
    done
    kill -KILL -- "-${pid}" 2>/dev/null || true
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    stop_pid "${alpha_pid}"
    stop_pid "${beta_pid}"
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${snake_pid}"
    rmdir "${alpha}" "${beta}" "${parent}" 2>/dev/null || true
    rm -rf "${tmpdir}"
    exit "${rc}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime managed-cell resizing test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    printf 'alpha procs: %s\n' "$(tr '\n' ' ' <"${alpha}/cgroup.procs" 2>/dev/null)" >&2
    printf 'beta procs: %s\n' "$(tr '\n' ' ' <"${beta}/cgroup.procs" 2>/dev/null)" >&2
    grep -E 'managed topology membership|activated managed' "${snake_log}" >&2 || true
    tail -n 160 "${snake_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for_cell_count() {
    local cells=$1 attempt
    local pattern="activated managed cell topology generation [0-9]+ with ${cells} managed cells"
    for ((attempt = 0; attempt < 300; attempt++)); do
        grep -Eq "${pattern}" "${snake_log}" && return 0
        scheduler_enabled || return 1
        sleep 0.05
    done
    return 1
}

latest_metric() {
    local cell_id=$1 field=$2
    python3 - "${snake_log}" "${cell_id}" "${field}" <<'PY'
import json
import sys

value = 0 if sys.argv[2:] == ["global", "managed_rebalance_count"] else ""
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if sys.argv[2] == "global":
            if sys.argv[3] in record:
                if sys.argv[3] == "managed_rebalance_count":
                    value += record[sys.argv[3]]
                else:
                    value = record[sys.argv[3]]
        else:
            cell = record.get("cells", {}).get(sys.argv[2], {})
            if sys.argv[3] in cell:
                value = cell[sys.argv[3]]
print(value)
PY
}

wait_for_metric() {
    local cell_id=$1 field=$2 operator=$3 expected=$4 attempt value
    for ((attempt = 0; attempt < 200; attempt++)); do
        value=$(latest_metric "${cell_id}" "${field}")
        if [[ ${value} =~ ^[0-9]+([.][0-9]+)?$ ]] &&
            python3 - "${value}" "${operator}" "${expected}" <<'PY'
import operator
import sys

ops = {"gt": operator.gt, "ge": operator.ge, "eq": operator.eq}
raise SystemExit(0 if ops[sys.argv[2]](float(sys.argv[1]), float(sys.argv[3])) else 1)
PY
        then
            return 0
        fi
        scheduler_enabled || return 1
        sleep 0.05
    done
    return 1
}

start_cell_process() {
    local cgroup=$1 mode=$2
    # shellcheck disable=SC2016 # Positional parameters expand in the child shell.
    setsid bash -c '
        printf "%s\n" "$$" >"$1/cgroup.procs"
        if [[ $2 == busy ]]; then
            while :; do :; done
        fi
        exec sleep infinity
    ' _ "${cgroup}" "${mode}" >/dev/null 2>&1 &
    printf '%s\n' "$!"
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
(( $(nproc) >= 6 )) || fail "requires at least six CPUs"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable"
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]] || fail "sched_ext is already enabled"

cpuset_mems=$(cat /sys/fs/cgroup/cpuset.mems.effective)
online_cpus=$(cat /sys/devices/system/cpu/online)
dmesg_lines=$(dmesg | wc -l)
grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control ||
    printf '%s\n' +cpuset >/sys/fs/cgroup/cgroup.subtree_control
mkdir "${parent}"
printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"

sed \
    -e "s|^parent = .*|parent = \"/${parent_name}\"|" \
    -e 's/^reconcile_ms = .*/reconcile_ms = 100/' \
    -e 's/^cell0_min_cpus = .*/cell0_min_cpus = 2/' \
    -e 's/^sample_ms = .*/sample_ms = 200/' \
    -e 's/^threshold_pct = .*/threshold_pct = 10.0/' \
    -e 's/^cooldown_ms = .*/cooldown_ms = 1000/' \
    -e 's/^ewma_alpha = .*/ewma_alpha = 1.0/' \
    "${policy_template}" >"${policy}"

verbose_args=()
[[ ${SNAKE_TEST_VERBOSE:-0} == 1 ]] && verbose_args=(-v)
"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.1 \
    "${verbose_args[@]}" \
    --stats-format json --exit-dump-len 1048576 >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

mkdir "${alpha}" "${beta}"
printf '%s\n' "${cpuset_mems}" >"${alpha}/cpuset.mems"
printf '%s\n' "${cpuset_mems}" >"${beta}/cpuset.mems"
alpha_pid=$(start_cell_process "${alpha}" idle)
beta_pid=$(start_cell_process "${beta}" idle)
wait_for_cell_count 2 || fail "two unpinned cells were not activated"
wait_for_metric 2 primary_cpu_count ge 1 || fail "cell 2 ownership was not reported"
initial_beta=$(latest_metric 2 primary_cpu_count)

stop_pid "${beta_pid}"
beta_pid=$(start_cell_process "${beta}" busy)
wait_for_metric global managed_rebalance_count ge 1 || fail "busy cell did not trigger a rebalance"
wait_for_metric 2 primary_cpu_count gt "${initial_beta}" || fail "busy cell did not gain CPUs"

stop_pid "${alpha_pid}"
stop_pid "${beta_pid}"
alpha_pid=$(start_cell_process "${alpha}" busy)
beta_pid=$(start_cell_process "${beta}" idle)
wait_for_metric global managed_rebalance_count ge 2 || fail "reversed load did not rebalance"
for _ in $(seq 1 200); do
    alpha_owned=$(latest_metric 1 primary_cpu_count)
    beta_owned=$(latest_metric 2 primary_cpu_count)
    if [[ ${alpha_owned} =~ ^[0-9]+$ && ${beta_owned} =~ ^[0-9]+$ ]] &&
        ((alpha_owned > beta_owned)); then
        break
    fi
    scheduler_enabled || fail "scheduler exited during reversed load"
    sleep 0.05
done
((alpha_owned > beta_owned)) || fail "CPU ownership did not follow reversed demand"

if grep -Eq 'invalid enq_flags|scx_bpf_error|Error: EXIT' "${snake_log}"; then
    fail "scheduler log contains a sched_ext failure"
fi
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall)|RCU.*stall|kernel panic'; then
    fail "kernel log contains a sched_ext failure"
fi

echo "PASS: EWMA demand moved CPUs to the busy managed cell in both directions"
