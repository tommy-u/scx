#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
inspector_bin=${2:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
listen=${SNAKE_TEST_INSPECTOR_LISTEN:-127.0.0.1:44108}
base_url=http://${listen}
rounds=${SNAKE_TEST_MUTATION_ROUNDS:-2}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
inspector_log=${tmpdir}/inspector.log
mutation_log=${tmpdir}/mutations.log
result_file=${tmpdir}/completions
cgroup_root=/sys/fs/cgroup
parent_name=scx-snake-queued-dequeue-$$
parent=${cgroup_root}/${parent_name}
alpha=${parent}/alpha
nested=${alpha}/nested
beta=${parent}/beta
snake_pid=
inspector_pid=
worker_pid=
normal_runtime_map_id=
dmesg_lines=0
target_queue_index=
target_dsq_id=
source_cpu=
alpha_id=
alpha_epoch=
declare -a gate_pids=()
declare -a alpha_cpus=()

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
    for ((attempt = 0; attempt < 60; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.02
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

stop_many() {
    local pid

    for pid in "$@"; do
        kill -CONT "${pid}" 2>/dev/null || true
        kill -TERM "${pid}" 2>/dev/null || true
    done
    for pid in "$@"; do
        stop_pid "${pid}"
    done
}

stop_gates() {
    stop_many "${gate_pids[@]}"
    gate_pids=()
}

stop_snake() {
    local attempt

    [[ -n ${snake_pid} ]] || return 0
    kill -INT "${snake_pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 150; attempt++)); do
        if pid_done "${snake_pid}" &&
            [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]]; then
            wait "${snake_pid}" 2>/dev/null || true
            snake_pid=
            return 0
        fi
        sleep 0.02
    done
    return 1
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    set +e
    stop_gates
    stop_pid "${worker_pid}"
    stop_snake || {
        kill -KILL "${snake_pid}" 2>/dev/null || true
        wait "${snake_pid}" 2>/dev/null || true
    }
    stop_pid "${inspector_pid}" INT
    rmdir "${beta}" "${nested}" "${alpha}" "${parent}" 2>/dev/null || true
    if [[ ${SNAKE_TEST_KEEP_TMP:-0} == 1 || ${rc} != 0 ]]; then
        chmod -R a+rX "${tmpdir}" 2>/dev/null || true
        printf 'vtime queued-dequeue artifacts: %s\n' "${tmpdir}" >&2
    else
        rm -rf "${tmpdir}"
    fi
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "vtime queued affinity/cpuset accounting test: $*" >&2
    printf 'sched_ext state: %s\n' \
        "$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)" >&2
    if [[ -n ${target_queue_index} && -n ${normal_runtime_map_id} ]]; then
        printf 'normal queue %s (DSQ %s) tracked depth: ' \
            "${target_queue_index}" "${target_dsq_id:-unknown}" >&2
        normal_queue_depth "${target_queue_index}" >&2 2>/dev/null || echo unknown >&2
    fi
    if ((dmesg_lines > 0)); then
        dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    fi
    tail -n 120 "${snake_log}" >&2 2>/dev/null || true
    tail -n 80 "${inspector_log}" >&2 2>/dev/null || true
    cat "${mutation_log}" >&2 2>/dev/null || true
    exit 1
}

inside_vm() {
    if command -v systemd-detect-virt >/dev/null; then
        systemd-detect-virt --vm --quiet
    else
        grep -qw hypervisor /proc/cpuinfo
    fi
}

scheduler_enabled() {
    [[ -n ${snake_pid} ]] &&
        [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for() {
    local description=$1 attempts=$2 interval=$3 attempt
    shift 3

    for ((attempt = 0; attempt < attempts; attempt++)); do
        "$@" && return 0
        if [[ ${description} != "Inspector API" && -n ${snake_pid} ]]; then
            pid_done "${snake_pid}" && return 1
            if [[ ${description} != "Snake attachment" ]] &&
                ! scheduler_enabled; then
                return 1
            fi
        fi
        sleep "${interval}"
    done
    echo "timed out waiting for ${description}" >&2
    return 1
}

wait_for_inspector() {
    [[ -n ${inspector_pid} ]] && kill -0 "${inspector_pid}" 2>/dev/null &&
        curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" \
            >/dev/null 2>&1
}

inspection_matches_attach() {
    local enable_seq=$1

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson enable_seq "${enable_seq}" '
            .error == null and .context.scheduler_active == true and
            .context.scheduler_attach_seq == $enable_seq and
            .snapshot.queue_topology.layout == "cell_llc" and
            ([.snapshot.cells[] | select(.name == "alpha")] | length) == 1
        ' >/dev/null
}

worker_stopped() {
    local pid=$1

    [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == T ]]
}

worker_runnable() {
    local pid=$1

    [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == R ]]
}

worker_mapped_to_alpha() {
    local pid=$1

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson pid "${pid}" --argjson cell "${alpha_id}" \
        --argjson epoch "${alpha_epoch}" '
            any(.snapshot.task_mappings[];
                .tid == $pid and .cell_id == $cell and
                .cell_epoch == $epoch and (.cgroup | endswith("/alpha/nested")))
        ' >/dev/null
}

result_has_pid() {
    local pid=$1

    [[ -f ${result_file} ]] && awk -v pid="${pid}" '$1 == pid { found = 1 }
        END { exit !found }' "${result_file}"
}

normal_queue_depth() {
    local index=$1 key0 key1 key2 key3

    [[ -n ${normal_runtime_map_id} ]] || return 1
    printf -v key0 '%02x' $((index & 0xff))
    printf -v key1 '%02x' $(((index >> 8) & 0xff))
    printf -v key2 '%02x' $(((index >> 16) & 0xff))
    printf -v key3 '%02x' $(((index >> 24) & 0xff))
    bpftool -j map lookup id "${normal_runtime_map_id}" \
        key hex "${key0}" "${key1}" "${key2}" "${key3}" |
        jq -er '.formatted.value.nr_queued'
}

normal_depth_ge() {
    local expected=$1 depth

    depth=$(normal_queue_depth "${target_queue_index}") || return 1
    ((depth >= expected))
}

normal_depth_eq() {
    local expected=$1 depth

    depth=$(normal_queue_depth "${target_queue_index}") || return 1
    ((depth == expected))
}

nested_mask_is() {
    local expected=$1 actual

    actual=$(awk '/^Cpus_allowed_list:/ { print $2 }' "/proc/${worker_pid}/status" \
        2>/dev/null || true)
    [[ ${actual} == "${expected}" ]]
}

start_gate() {
    local cpu=$1 pid policy

    taskset -c "${cpu}" chrt -f 1 yes >/dev/null 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        policy=$(chrt -p "${pid}" 2>/dev/null || true)
        if grep -q SCHED_FIFO <<<"${policy}"; then
            gate_pids+=("${pid}")
            return 0
        fi
        sleep 0.01
    done
    stop_pid "${pid}" KILL
    return 1
}

start_all_alpha_gates() {
    local cpu

    gate_pids=()
    for cpu in "${alpha_cpus[@]}"; do
        start_gate "${cpu}" || return 1
    done
}

start_stopped_worker() {
    local pid

    taskset -c "${source_cpu}" python3 -c '
import os
import signal
import sys
import time

os.kill(os.getpid(), signal.SIGSTOP)
deadline = time.monotonic() + 0.02
value = 1
while time.monotonic() < deadline:
    value = (value * 1664525 + 1013904223) & 0xffffffff
with open(sys.argv[1], "a", encoding="utf-8") as stream:
    stream.write(f"{os.getpid()} {value}\n")
' "${result_file}" &
    pid=$!
    wait_for "worker ${pid} stop" 100 0.02 worker_stopped "${pid}" || {
        stop_pid "${pid}" KILL
        return 1
    }
    printf '%s\n' "${pid}" >"${nested}/cgroup.procs"
    taskset -pc "${online_cpus}" "${pid}" >>"${mutation_log}"
    worker_pid=${pid}
}

reset_nested_cpuset() {
    printf '\n' >"${nested}/cpuset.cpus"
    [[ -z $(<"${nested}/cpuset.cpus") ]]
}

run_mutation_case() {
    local mutation=$1 round=$2 depth

    reset_nested_cpuset || fail "could not clear nested cpuset before ${mutation} round ${round}"
    wait_for "empty tracked normal queue" 100 0.01 normal_depth_eq 0 ||
        fail "normal queue was not empty before ${mutation} round ${round}"
    start_stopped_worker || fail "could not prepare ${mutation} worker in round ${round}"
    wait_for "worker ${worker_pid} alpha membership" 200 0.02 \
        worker_mapped_to_alpha "${worker_pid}" ||
        fail "${mutation} worker was not mapped through its nested cgroup"
    start_all_alpha_gates || fail "could not gate all alpha CPUs"
    kill -CONT "${worker_pid}"
    wait_for "queued ${mutation} worker" 150 0.01 worker_runnable "${worker_pid}" ||
        fail "${mutation} worker did not become runnable behind the gates"
    wait_for "normal DSQ ${target_dsq_id} population" 150 0.01 normal_depth_ge 1 ||
        fail "${mutation} worker did not enter normal DSQ ${target_dsq_id}"

    depth=$(normal_queue_depth "${target_queue_index}")
    printf '%s round %s: queued depth=%s dsq=%s\n' \
        "${mutation}" "${round}" "${depth}" "${target_dsq_id}" >>"${mutation_log}"
    case ${mutation} in
        affinity)
            taskset -pc "${source_cpu}" "${worker_pid}" >>"${mutation_log}"
            ;;
        cpuset)
            printf '%s\n' "${source_cpu}" >"${nested}/cpuset.cpus"
            wait_for "nested cpuset propagation" 100 0.01 \
                nested_mask_is "${source_cpu}" ||
                fail "nested cpuset did not restrict the queued worker"
            ;;
        *)
            fail "unknown mutation ${mutation}"
            ;;
    esac

    # A queued affinity or cpuset update physically removes the task from its
    # old normal DSQ before re-enqueueing it on an affinity DSQ. The task's
    # later completion corroborates that physical path; this map assertion is
    # the independent Snake accounting oracle for the old normal DSQ.
    wait_for "old normal DSQ accounting after ${mutation}" 150 0.01 \
        normal_depth_eq 0 ||
        fail "old normal DSQ depth stayed nonzero after queued ${mutation}"
    worker_runnable "${worker_pid}" ||
        fail "${mutation} worker stopped being runnable after its queued rehome"
    printf '%s round %s: rehomed depth=0\n' \
        "${mutation}" "${round}" >>"${mutation_log}"

    stop_gates
    wait_for "${mutation} worker completion" 200 0.01 \
        result_has_pid "${worker_pid}" ||
        fail "${mutation} worker did not complete after gate release"
    stop_pid "${worker_pid}"
    worker_pid=
    wait_for "post-completion normal depth" 100 0.01 normal_depth_eq 0 ||
        fail "normal queue depth changed after ${mutation} completion"
}

current_generation() {
    curl -fsS "${base_url}/api/inspection" |
        jq -er '.snapshot.topology_lifecycle.current_generation'
}

beta_added_after() {
    local baseline=$1

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson baseline "${baseline}" '
            .snapshot.topology_lifecycle.current_generation > $baseline and
            any(.snapshot.cells[]; .name == "beta") and
            any(.snapshot.topology_lifecycle.transitions[];
                .reason == "managed_cells_changed" and .outcome == "applied" and
                (.to_generation // 0) > $baseline and
                any(.stages[]; .stage == "drain" and .status == "complete") and
                any(.cell_changes[];
                    .kind == "added" and .after.name == "beta"))
        ' >/dev/null
}

beta_removed_after() {
    local baseline=$1

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson baseline "${baseline}" '
            .snapshot.topology_lifecycle.current_generation > $baseline and
            (all(.snapshot.cells[]; .name != "beta")) and
            any(.snapshot.topology_lifecycle.transitions[];
                .reason == "managed_cells_changed" and .outcome == "applied" and
                (.to_generation // 0) > $baseline and
                any(.stages[]; .stage == "drain" and .status == "complete") and
                any(.cell_changes[];
                    .kind == "removed" and .before.name == "beta"))
        ' >/dev/null
}

stats_sum() {
    local field=$1

    python3 - "${snake_log}" "${field}" <<'PY'
import json
import sys

value = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = record.get(sys.argv[2], 0)
        if isinstance(item, (int, float)):
            value += item
print(int(value))
PY
}

if [[ ${SNAKE_TEST_ALLOW_BARE_METAL:-0} != 1 ]]; then
    inside_vm || fail "refusing to run outside a VM"
fi
((EUID == 0)) || fail "must run as root inside a VM"
[[ ${rounds} =~ ^[1-5]$ ]] || fail "SNAKE_TEST_MUTATION_ROUNDS must be between 1 and 5"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
for command in bpftool chrt curl jq python3 taskset; do
    command -v "${command}" >/dev/null || fail "${command} is required"
done
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
(( $(nproc) >= 4 )) || fail "requires at least four CPUs"

online_cpus=$(cat /sys/devices/system/cpu/online)
cpuset_mems=$(cat "${cgroup_root}/cpuset.mems.effective")
[[ -n ${cpuset_mems} ]] || fail "root cpuset has no effective memory nodes"
dmesg_lines=$(dmesg | wc -l)
: >"${result_file}"
: >"${mutation_log}"

grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
    fail "cgroup root does not provide the cpuset controller"
grep -qw cpuset "${cgroup_root}/cgroup.subtree_control" ||
    printf '%s\n' +cpuset >"${cgroup_root}/cgroup.subtree_control"
mkdir "${parent}"
printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"
mkdir "${alpha}"
printf '%s\n' "${cpuset_mems}" >"${alpha}/cpuset.mems"
printf '%s\n' +cpuset >"${alpha}/cgroup.subtree_control"
mkdir "${nested}"
printf '%s\n' "${cpuset_mems}" >"${nested}/cpuset.mems"
[[ -z $(<"${alpha}/cpuset.cpus") && -z $(<"${nested}/cpuset.cpus") ]] ||
    fail "alpha and its nested cgroup must start unpinned"

cat >"${policy}" <<EOF
fallback = "previous_cpu"

[managed_cells]
parent = "/${parent_name}"
max_children = 2
reconcile_ms = 50
cell0_min_cpus = 1

[queues]
layout = "cell_llc"
cell0_cpu_weight = 1
direct_dispatch = false
enqueue = [
  { target = "cell" },
  { target = "affinity" },
]
dispatch = [
  { action = "drain", source = "cell_orphan" },
  { action = "peek", source = "cell" },
  { action = "peek", source = "cpu" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu"] },
  { action = "steal", source = "cell_sibling" },
]

[[rung]]
operation = "claim_idle_core"
scope = "task_cell"
[[rung]]
operation = "pick_idle_core"
scope = "task_cell"
[[rung]]
operation = "claim_idle"
scope = "task_cell"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
[[rung]]
operation = "claim_idle_core"
scope = "task_allowed_restricted"
[[rung]]
operation = "pick_idle_core"
scope = "task_allowed_restricted"
[[rung]]
operation = "claim_idle"
scope = "task_allowed_restricted"
[[rung]]
operation = "pick_idle"
scope = "task_allowed_restricted"
EOF

if curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" >/dev/null 2>&1; then
    fail "Inspector address ${listen} is already serving an API"
fi
"${inspector_bin}" --listen "${listen}" --snake-bin "${snake_bin}" \
    --policy-dir "${tmpdir}" >"${inspector_log}" 2>&1 &
inspector_pid=$!
wait_for "Inspector API" 200 0.05 wait_for_inspector || fail "Inspector API did not start"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.05 \
    --stats-format json --exit-dump-len 1048576 >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for "Snake attachment" 300 0.02 scheduler_enabled || fail "scheduler did not attach"
enable_seq=$(cat /sys/kernel/sched_ext/enable_seq)
wait_for "Inspector attachment" 300 0.02 inspection_matches_attach "${enable_seq}" ||
    fail "Inspector did not observe the scheduler attachment"

inspection=${tmpdir}/initial-inspection.json
curl -fsS "${base_url}/api/inspection" >"${inspection}"
alpha_id=$(jq -er '.snapshot.cells[] | select(.name == "alpha") | .id' "${inspection}")
alpha_epoch=$(jq -er --argjson id "${alpha_id}" '
    .snapshot.queue_topology.cells[] | select(.external_id == $id) | .slot_epoch
' "${inspection}")
mapfile -t alpha_cpus < <(jq -r --argjson id "${alpha_id}" '
    .snapshot.queue_topology.cells[] | select(.external_id == $id) | .primary_cpus[]
' "${inspection}")
((${#alpha_cpus[@]} > 0)) || fail "alpha received no primary CPUs"
target_queue_index=$(jq -er --argjson id "${alpha_id}" '
    [.snapshot.queue_topology.normal_queues[] |
        select(.cell_id == $id and (.consumer_cpus | length) > 0)] |
    max_by(.consumer_cpus | length) | .index
' "${inspection}")
target_dsq_id=$(jq -er --argjson index "${target_queue_index}" '
    .snapshot.queue_topology.normal_queues[] | select(.index == $index) | .dsq_id
' "${inspection}")
source_cpu=$(jq -er --argjson index "${target_queue_index}" '
    .snapshot.queue_topology.normal_queues[] |
    select(.index == $index) | .consumer_cpus[0]
' "${inspection}")
expected_dsq_id=$((0x20000000 + target_queue_index))
((target_dsq_id == expected_dsq_id)) ||
    fail "Inspector reported unexpected normal DSQ ID ${target_dsq_id} for queue ${target_queue_index}"
control_cpu=$(jq -er '
    .snapshot.queue_topology.cells[] | select(.external_id == 0) | .primary_cpus[0]
' "${inspection}")

normal_runtime_map_id=$(bpftool -j map show | jq -er '
    [.[] | select(.name == "normal_queue_ru")] | last | .id
') || fail "could not find the active normal_queue_runtime map"
wait_for "initial zero normal depth" 100 0.01 normal_depth_eq 0 ||
    fail "target normal queue did not start empty"

taskset -pc "${control_cpu}" "$$" >>"${mutation_log}"
for pid in "${snake_pid}" "${inspector_pid}"; do
    taskset -apc "${control_cpu}" "${pid}" >>"${mutation_log}" ||
        fail "could not pin control-plane process ${pid}"
done

for ((round = 1; round <= rounds; round++)); do
    run_mutation_case affinity "${round}"
    run_mutation_case cpuset "${round}"
done
reset_nested_cpuset || fail "could not restore the nested cpuset"

# Creating and removing a second direct child invokes Snake's supported
# queue_drain_ready path. Both transitions must apply well before its five-
# second timeout; a stale logical normal depth would leave them deferred.
generation=$(current_generation)
mkdir "${beta}"
printf '%s\n' "${cpuset_mems}" >"${beta}/cpuset.mems"
wait_for "beta add topology drain" 200 0.02 beta_added_after "${generation}" ||
    fail "beta addition did not apply after the queued-mask mutations"
wait_for "zero old depth after beta add" 100 0.01 normal_depth_eq 0 ||
    fail "old normal depth was nonzero after beta addition"

generation=$(current_generation)
rmdir "${beta}"
wait_for "beta remove topology drain" 200 0.02 beta_removed_after "${generation}" ||
    fail "beta removal did not apply after the queued-mask mutations"
wait_for "zero old depth after beta remove" 100 0.01 normal_depth_eq 0 ||
    fail "old normal depth was nonzero after beta removal"

invalid=$(stats_sum invalid_errors)
accounting=$(stats_sum vtime_accounting_errors)
((invalid == 0 && accounting == 0)) ||
    fail "scheduler correctness counters are nonzero: invalid=${invalid} accounting=${accounting}"
if grep -Eiq \
    'normal queue [0-9]+ depth underflow|depth underflow|invalid enq_flags|scx_bpf_error|Error: EXIT|runnable task stall' \
    "${snake_log}"; then
    fail "scheduler log contains a queue-accounting or stall failure"
fi
if dmesg | tail -n +$((dmesg_lines + 1)) | grep -Eiq \
    'depth underflow|runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler stall or kernel failure"
fi
scheduler_enabled || fail "scheduler detached during queued-mask mutations"
stop_snake || fail "scheduler did not detach cleanly"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext remained enabled after scheduler shutdown"

echo "PASS: queued affinity/cpuset changes balanced normal DSQ ${target_dsq_id} across ${rounds} rounds and two topology drains"
