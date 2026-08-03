#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
inspector_bin=${2:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
listen=${SNAKE_TEST_INSPECTOR_LISTEN:-127.0.0.1:44107}
base_url=http://${listen}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.ndjson
inspector_log=${tmpdir}/inspector.log
result_file=${tmpdir}/completions
worker_py=${tmpdir}/worker.py
cgroup_root=/sys/fs/cgroup
parent_name=scx-snake-managed-reuse-$$
parent=${cgroup_root}/${parent_name}
alpha=${parent}/alpha
beta=${parent}/beta
gamma=${parent}/gamma
snake_pid=
inspector_pid=
normal_runtime_map_id=
affinity_runtime_map_id=
cell_runtime_map_id=
cell_runtime_map_entries=
dmesg_lines=0
started_pid=
declare -a worker_pids=()
declare -a online_cpu_ids=()
declare -A cell_dirs=(
    [alpha]="${alpha}"
    [beta]="${beta}"
    [gamma]="${gamma}"
)
declare -A cell_ids=()
declare -A cell_epochs=()

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
    for ((attempt = 0; attempt < 75; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.02
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

stop_workers() {
    local pid

    for pid in "${worker_pids[@]}"; do
        kill -CONT "${pid}" 2>/dev/null || true
        kill -TERM "${pid}" 2>/dev/null || true
    done
    for pid in "${worker_pids[@]}"; do
        stop_pid "${pid}"
    done
    worker_pids=()
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
    stop_workers
    stop_snake || {
        kill -KILL "${snake_pid}" 2>/dev/null || true
        wait "${snake_pid}" 2>/dev/null || true
    }
    stop_pid "${inspector_pid}" INT
    rmdir "${beta}" "${gamma}" "${alpha}" "${parent}" 2>/dev/null || true
    if [[ ${SNAKE_TEST_KEEP_TMP:-0} == 1 || ${rc} != 0 ]]; then
        chmod -R a+rX "${tmpdir}" 2>/dev/null || true
        printf 'vtime managed-cell reuse artifacts: %s\n' "${tmpdir}" >&2
    else
        rm -rf "${tmpdir}"
    fi
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "vtime managed-cell reuse test: $*" >&2
    printf 'sched_ext state: %s\n' \
        "$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)" >&2
    if ((dmesg_lines > 0)); then
        dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    fi
    tail -n 180 "${snake_log}" >&2 2>/dev/null || true
    tail -n 100 "${inspector_log}" >&2 2>/dev/null || true
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
            if [[ ${description} != "Snake attachment" ]] && ! scheduler_enabled; then
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
            ([.snapshot.cells[] |
                select(.name == "alpha" or .name == "beta" or .name == "gamma")] |
                length) == 3
        ' >/dev/null
}

current_generation() {
    curl -fsS "${base_url}/api/inspection" |
        jq -er '.snapshot.topology_lifecycle.current_generation'
}

cell_llc_count_is() {
    local name=$1 expected=$2

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --arg name "${name}" --argjson expected "${expected}" '
            (.snapshot.cells[] | select(.name == $name) | .id) as $id |
            ([.snapshot.queue_topology.normal_queues[] |
                select(.cell_id == $id and (.consumer_cpus | length) > 0) |
                .llc_id] | unique | length) == $expected
        ' >/dev/null
}

transition_applied_after() {
    local baseline=$1 name=$2 kind=$3 epoch=$4

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson baseline "${baseline}" --arg name "${name}" \
        --arg kind "${kind}" --argjson epoch "${epoch}" '
            .snapshot.topology_lifecycle.current_generation > $baseline and
            any(.snapshot.topology_lifecycle.transitions[];
                .reason == "managed_cells_changed" and .outcome == "applied" and
                (.to_generation // 0) > $baseline and
                any(.stages[]; .stage == "drain" and .status == "complete") and
                any(.cell_changes[];
                    .kind == $kind and
                    (if $kind == "removed" then
                        .before.name == $name and .before.slot_epoch == $epoch
                    elif $kind == "added" then
                        .after.name == $name and .after.slot_epoch == $epoch
                    else
                        .before.name == $name and .after.name == $name and
                        .before.slot_epoch == $epoch and .after.slot_epoch == $epoch
                    end)))
        ' >/dev/null
}

cell_absent_after() {
    local baseline=$1 name=$2 epoch=$3

    transition_applied_after "${baseline}" "${name}" removed "${epoch}" &&
        curl -fsS "${base_url}/api/inspection" | jq -e --arg name "${name}" '
            all(.snapshot.cells[]; .name != $name)
        ' >/dev/null
}

cell_recreated_after() {
    local baseline=$1 name=$2 cell_id=$3 epoch=$4

    transition_applied_after "${baseline}" "${name}" added "${epoch}" &&
        curl -fsS "${base_url}/api/inspection" | jq -e \
            --arg name "${name}" --argjson id "${cell_id}" \
            --argjson epoch "${epoch}" '
                any(.snapshot.cells[];
                    .name == $name and .id == $id and .slot_epoch == $epoch)
            ' >/dev/null
}

worker_stopped() {
    local pid=$1

    [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == T ]]
}

worker_mapped() {
    local name=$1 pid=$2 cell_id=$3 epoch=$4

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --arg name "${name}" --argjson pid "${pid}" \
        --argjson cell "${cell_id}" --argjson epoch "${epoch}" '
            any(.snapshot.task_mappings[];
                .tid == $pid and .cell_id == $cell and .cell_epoch == $epoch and
                (.cgroup | endswith("/" + $name)))
        ' >/dev/null
}

result_has() {
    local token=$1

    [[ -f ${result_file} ]] && awk -v token="${token}" '
        $1 == token { found = 1 }
        END { exit !found }
    ' "${result_file}"
}

start_stopped_worker() {
    local name=$1 token=$2 seconds=$3
    local cgroup=${cell_dirs[${name}]}

    # shellcheck disable=SC2016 # The child shell expands its PID and arguments.
    setsid bash -c '
        printf "%s\n" "$$" >"$1/cgroup.procs"
        exec python3 "$2" "$3" "$4" "$5"
    ' _ "${cgroup}" "${worker_py}" "${result_file}" "${token}" "${seconds}" \
        >/dev/null 2>&1 &
    started_pid=$!
    worker_pids+=("${started_pid}")
    wait_for "worker ${started_pid} stop" 100 0.02 \
        worker_stopped "${started_pid}" ||
        fail "worker ${started_pid} did not stop for ${name} setup"
    wait_for "worker ${started_pid} ${name} membership" 200 0.02 \
        worker_mapped "${name}" "${started_pid}" \
            "${cell_ids[${name}]}" "${cell_epochs[${name}]}" ||
        fail "worker ${started_pid} was not mapped to ${name} cell ${cell_ids[${name}]}:${cell_epochs[${name}]}"
}

finish_workers() {
    local token pid

    for token in "$@"; do
        wait_for "worker ${token} completion" 300 0.02 result_has "${token}" ||
            fail "worker ${token} did not complete"
    done
    for pid in "${worker_pids[@]}"; do
        stop_pid "${pid}"
    done
    worker_pids=()
}

run_three_cell_round() {
    local prefix=$1 seconds=${2:-0.12}
    local -a tokens=("${prefix}-alpha" "${prefix}-beta" "${prefix}-gamma")
    local index

    for index in "${!tokens[@]}"; do
        start_stopped_worker \
            "${tokens[index]#${prefix}-}" "${tokens[index]}" "${seconds}"
    done
    for index in "${!worker_pids[@]}"; do
        kill -CONT "${worker_pids[index]}"
    done
    finish_workers "${tokens[@]}"
}

map_field() {
    local map_id=$1 index=$2 field=$3 key0 key1 key2 key3

    printf -v key0 '%02x' $((index & 0xff))
    printf -v key1 '%02x' $(((index >> 8) & 0xff))
    printf -v key2 '%02x' $(((index >> 16) & 0xff))
    printf -v key3 '%02x' $(((index >> 24) & 0xff))
    bpftool -j map lookup id "${map_id}" \
        key hex "${key0}" "${key1}" "${key2}" "${key3}" |
        jq -er --arg field "${field}" '.formatted.value[$field]'
}

queue_runtime_settled() {
    local snapshot=$1 index expected value

    while read -r index expected; do
        value=$(map_field "${normal_runtime_map_id}" "${index}" nr_queued) || return 1
        ((value == 0)) || return 1
        value=$(map_field "${normal_runtime_map_id}" "${index}" has_consumers) || return 1
        ((value == expected)) || return 1
    done < <(jq -r '
        .snapshot.queue_topology.normal_queues[] |
        [.index, (if (.consumer_cpus | length) > 0 then 1 else 0 end)] | @tsv
    ' "${snapshot}")
    while read -r index; do
        value=$(map_field "${affinity_runtime_map_id}" "${index}" nr_queued) || return 1
        ((value == 0)) || return 1
    done < <(jq -r '.snapshot.queue_topology.cpu_routes[].cpu' "${snapshot}")
    for ((index = 0; index < cell_runtime_map_entries; index++)); do
        value=$(map_field "${cell_runtime_map_id}" "${index}" llcs_to_drain) || return 1
        ((value == 0)) || return 1
    done
}

cell_id() {
    local snapshot=$1 name=$2

    jq -er --arg name "${name}" \
        '.snapshot.cells[] | select(.name == $name) | .id' "${snapshot}"
}

cell_epoch() {
    local snapshot=$1 id=$2

    jq -er --argjson id "${id}" '
        .snapshot.queue_topology.cells[] |
        select(.external_id == $id) | .slot_epoch
    ' "${snapshot}"
}

cell_identity() {
    local snapshot=$1 id=$2

    jq -cS --argjson id "${id}" '
        (.snapshot.queue_topology.cells[] | select(.external_id == $id)) as $cell |
        {
            external_id: $cell.external_id,
            index: $cell.index,
            slot_epoch: $cell.slot_epoch,
            queues: [.snapshot.queue_topology.normal_queues[] |
                select(.cell_id == $id) |
                {index, dsq_id, cell_index, clock_index, llc_id}]
        }
    ' "${snapshot}"
}

cell_bank_shape() {
    local snapshot=$1 id=$2

    jq -cS --argjson id "${id}" '
        (.snapshot.queue_topology.cells[] | select(.external_id == $id)) as $cell |
        {
            index: $cell.index,
            queues: [.snapshot.queue_topology.normal_queues[] |
                select(.cell_id == $id) |
                {index, dsq_id, cell_index, clock_index, llc_id}]
        }
    ' "${snapshot}"
}

stats_sum() {
    local field=$1

    python3 - "${snake_log}" "${field}" <<'PY'
import json
import sys

total = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = record.get(sys.argv[2], 0)
        if isinstance(value, (int, float)):
            total += value
print(int(total))
PY
}

inside_vm || fail "refusing to run outside a VM"
((EUID == 0)) || fail "must run as root inside a VM"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
for command in bpftool curl jq python3 setsid; do
    command -v "${command}" >/dev/null || fail "${command} is required"
done
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
(( $(nproc) >= 8 )) || fail "requires at least eight guest CPUs"

for cpu_path in /sys/devices/system/cpu/cpu[0-9]*; do
    cpu=${cpu_path##*cpu}
    [[ ${cpu} =~ ^[0-9]+$ ]] || continue
    if [[ ! -r ${cpu_path}/online || $(<"${cpu_path}/online") == 1 ]]; then
        online_cpu_ids+=("${cpu}")
    fi
done
((${#online_cpu_ids[@]} >= 8)) || fail "could not discover eight online CPUs"

declare -A llc_cpus=()
for cpu in "${online_cpu_ids[@]}"; do
    cache_id_file=/sys/devices/system/cpu/cpu${cpu}/cache/index3/id
    [[ -r ${cache_id_file} ]] ||
        fail "CPU ${cpu} has no LLC identity at ${cache_id_file}"
    llc=$(<"${cache_id_file}")
    llc_cpus[${llc}]="${llc_cpus[${llc}]:-} ${cpu}"
done
mapfile -t llc_ids < <(printf '%s\n' "${!llc_cpus[@]}" | sort -n)
((${#llc_ids[@]} == 2)) ||
    fail "requires exactly two guest LLCs, found ${#llc_ids[@]}"
read -r -a first_llc_cpus <<<"${llc_cpus[${llc_ids[0]}]}"
read -r -a second_llc_cpus <<<"${llc_cpus[${llc_ids[1]}]}"
((${#first_llc_cpus[@]} >= 2 && ${#second_llc_cpus[@]} >= 2)) ||
    fail "each guest LLC must contain at least two CPUs"
beta_shrink=${first_llc_cpus[0]},${first_llc_cpus[1]}
beta_span=${beta_shrink},${second_llc_cpus[0]},${second_llc_cpus[1]}

grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
    fail "cgroup root does not provide the cpuset controller"
grep -qw cpuset "${cgroup_root}/cgroup.subtree_control" ||
    printf '%s\n' +cpuset >"${cgroup_root}/cgroup.subtree_control"
cpuset_mems=$(cat "${cgroup_root}/cpuset.mems.effective")
online_cpus=$(cat /sys/devices/system/cpu/online)
[[ -n ${cpuset_mems} ]] || fail "root cpuset has no effective memory nodes"
dmesg_lines=$(dmesg | wc -l)
: >"${result_file}"

mkdir "${parent}"
printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"
mkdir "${alpha}" "${beta}" "${gamma}"
for child in "${alpha}" "${beta}" "${gamma}"; do
    printf '%s\n' "${cpuset_mems}" >"${child}/cpuset.mems"
done
printf '%s\n' "${beta_span}" >"${beta}/cpuset.cpus"
[[ -z $(<"${alpha}/cpuset.cpus") && -z $(<"${gamma}/cpuset.cpus") ]] ||
    fail "alpha and gamma must remain unpinned"

cat >"${worker_py}" <<'PY'
import os
import signal
import sys
import time

result, token, duration = sys.argv[1], sys.argv[2], float(sys.argv[3])
os.kill(os.getpid(), signal.SIGSTOP)
deadline = time.monotonic() + duration
value = 1
while time.monotonic() < deadline:
    value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
    time.sleep(0.0005)
with open(result, "a", encoding="utf-8") as stream:
    stream.write(f"{token} {os.getpid()} {value}\n")
PY

cat >"${policy}" <<EOF
fallback = "previous_cpu"

[managed_cells]
parent = "/${parent_name}"
max_children = 3
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
wait_for "Inspector API" 200 0.05 wait_for_inspector ||
    fail "Inspector API did not start"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.05 \
    --stats-format json --exit-dump-len 1048576 >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for "Snake attachment" 300 0.02 scheduler_enabled ||
    fail "scheduler did not attach"
enable_seq=$(cat /sys/kernel/sched_ext/enable_seq)
wait_for "Inspector attachment" 300 0.02 \
    inspection_matches_attach "${enable_seq}" ||
    fail "Inspector did not observe the three-cell attachment"

normal_runtime_map_id=$(bpftool -j map show | jq -er '
    [.[] | select(.name == "normal_queue_ru")] | last | .id
') || fail "could not find active normal_queue_runtime map"
affinity_runtime_map_id=$(bpftool -j map show | jq -er '
    [.[] | select(.name == "affinity_queue_")] | last | .id
') || fail "could not find active affinity_queue_runtime map"
cell_runtime_map_id=$(bpftool -j map show | jq -er '
    [.[] | select(.name == "cell_queue_runt")] | last | .id
') || fail "could not find active cell_queue_runtime map"
cell_runtime_map_entries=$(bpftool -j map show id "${cell_runtime_map_id}" |
    jq -er '.max_entries') || fail "could not read cell_queue_runtime capacity"
[[ ${cell_runtime_map_entries} =~ ^[1-9][0-9]*$ ]] ||
    fail "invalid cell_queue_runtime capacity: ${cell_runtime_map_entries}"

initial=${tmpdir}/initial.json
curl -fsS "${base_url}/api/inspection" >"${initial}"
for name in alpha beta gamma; do
    cell_ids[${name}]=$(cell_id "${initial}" "${name}")
    cell_epochs[${name}]=$(cell_epoch "${initial}" "${cell_ids[${name}]}")
done
[[ ${cell_ids[alpha]} == 1 && ${cell_ids[beta]} == 2 && ${cell_ids[gamma]} == 3 ]] ||
    fail "managed children did not receive deterministic IDs 1/2/3"
cell_llc_count_is beta 2 || fail "middle cell did not initially cover both LLCs"
alpha_initial=$(cell_identity "${initial}" "${cell_ids[alpha]}")
beta_initial_bank=$(cell_bank_shape "${initial}" "${cell_ids[beta]}")
gamma_initial=$(cell_identity "${initial}" "${cell_ids[gamma]}")
wait_for "initial queue settlement" 100 0.02 queue_runtime_settled "${initial}" ||
    fail "initial queue depths or drain masks were nonzero"

run_three_cell_round initial

# Constrain the middle cell to one LLC while a finite wakeup-heavy task runs.
# Its external identity and dense queue bank stay fixed while one cell/LLC DSQ
# becomes consumerless.
start_stopped_worker beta shrink-load 0.8
kill -CONT "${started_pid}"
generation=$(current_generation)
printf '%s\n' "${beta_shrink}" >"${beta}/cpuset.cpus"
wait_for "middle-cell LLC shrink" 300 0.02 \
    transition_applied_after "${generation}" beta changed "${cell_epochs[beta]}" ||
    fail "middle-cell shrink transition did not apply"
wait_for "one-LLC middle cell" 100 0.02 cell_llc_count_is beta 1 ||
    fail "middle cell did not shrink to one LLC"
finish_workers shrink-load
after_shrink=${tmpdir}/after-shrink.json
curl -fsS "${base_url}/api/inspection" >"${after_shrink}"
[[ $(cell_bank_shape "${after_shrink}" "${cell_ids[beta]}") == "${beta_initial_bank}" ]] ||
    fail "middle-cell DSQ bank changed during same-epoch LLC shrink"
wait_for "post-shrink queue settlement" 100 0.02 \
    queue_runtime_settled "${after_shrink}" ||
    fail "queue depths or drain masks did not settle after LLC shrink"

# Restore both LLCs under the same kind of light load. The previously orphaned
# logical queue must regain consumers without changing its index or DSQ ID.
start_stopped_worker beta regain-load 0.8
kill -CONT "${started_pid}"
generation=$(current_generation)
printf '%s\n' "${beta_span}" >"${beta}/cpuset.cpus"
wait_for "middle-cell LLC regain" 300 0.02 \
    transition_applied_after "${generation}" beta changed "${cell_epochs[beta]}" ||
    fail "middle-cell regain transition did not apply"
wait_for "two-LLC middle cell" 100 0.02 cell_llc_count_is beta 2 ||
    fail "middle cell did not regain both LLCs"
finish_workers regain-load
after_regain=${tmpdir}/after-regain.json
curl -fsS "${base_url}/api/inspection" >"${after_regain}"
[[ $(cell_bank_shape "${after_regain}" "${cell_ids[beta]}") == "${beta_initial_bank}" ]] ||
    fail "middle-cell DSQ bank changed while regaining LLC coverage"
wait_for "post-regain queue settlement" 100 0.02 \
    queue_runtime_settled "${after_regain}" ||
    fail "queue depths or drain masks did not settle after LLC regain"

# Delete the middle external ID. Gamma compacts into the retired dense bank
# only after the global topology drain, while alpha/gamma external epochs stay
# stable. This is the bank/index reuse boundary the test is intended to cover.
[[ -z $(<"${beta}/cgroup.procs") ]] || fail "middle cgroup still contains tasks"
generation=$(current_generation)
rmdir "${beta}"
wait_for "middle-cell removal" 300 0.02 \
    cell_absent_after "${generation}" beta "${cell_epochs[beta]}" ||
    fail "middle-cell removal transition did not apply"
after_delete=${tmpdir}/after-delete.json
curl -fsS "${base_url}/api/inspection" >"${after_delete}"
[[ $(cell_id "${after_delete}" alpha) == "${cell_ids[alpha]}" ]] ||
    fail "alpha external ID changed after middle-cell deletion"
[[ $(cell_id "${after_delete}" gamma) == "${cell_ids[gamma]}" ]] ||
    fail "gamma external ID changed after middle-cell deletion"
[[ $(cell_epoch "${after_delete}" "${cell_ids[alpha]}") == "${cell_epochs[alpha]}" ]] ||
    fail "alpha epoch changed after middle-cell deletion"
[[ $(cell_epoch "${after_delete}" "${cell_ids[gamma]}") == "${cell_epochs[gamma]}" ]] ||
    fail "gamma epoch changed after middle-cell deletion"
[[ $(cell_bank_shape "${after_delete}" "${cell_ids[gamma]}") == "${beta_initial_bank}" ]] ||
    fail "gamma did not safely reuse the retired middle dense queue bank"
wait_for "post-delete queue settlement" 100 0.02 \
    queue_runtime_settled "${after_delete}" ||
    fail "queue depths or drain masks did not settle after middle-cell deletion"

# Recreate the same child name. The external slot and physical DSQ bank are
# deliberately reused, but the epoch must advance so stale task annotations
# cannot alias the replacement cgroup.
generation=$(current_generation)
mkdir "${beta}"
printf '%s\n' "${cpuset_mems}" >"${beta}/cpuset.mems"
printf '%s\n' "${beta_span}" >"${beta}/cpuset.cpus"
recreated_epoch=$((cell_epochs[beta] + 1))
wait_for "middle-cell recreation" 300 0.02 \
    cell_recreated_after "${generation}" beta "${cell_ids[beta]}" "${recreated_epoch}" ||
    fail "recreated middle cell did not reuse its ID with an advanced epoch"
cell_epochs[beta]=${recreated_epoch}
final=${tmpdir}/final.json
curl -fsS "${base_url}/api/inspection" >"${final}"
[[ $(cell_identity "${final}" "${cell_ids[alpha]}") == "${alpha_initial}" ]] ||
    fail "alpha queue identity changed across middle-cell reuse"
[[ $(cell_identity "${final}" "${cell_ids[gamma]}") == "${gamma_initial}" ]] ||
    fail "gamma queue identity did not return after middle-cell recreation"
[[ $(cell_bank_shape "${final}" "${cell_ids[beta]}") == "${beta_initial_bank}" ]] ||
    fail "recreated middle cell did not reclaim its original DSQ bank"
cell_llc_count_is beta 2 || fail "recreated middle cell did not cover both LLCs"

run_three_cell_round recreated
curl -fsS "${base_url}/api/inspection" >"${final}"
wait_for "final queue settlement" 150 0.02 queue_runtime_settled "${final}" ||
    fail "logical normal/affinity depths or drain masks did not settle"
scheduler_enabled || fail "scheduler detached during managed-cell bank reuse"

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

stop_snake || fail "scheduler did not detach cleanly"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext remained enabled after scheduler shutdown"

echo "PASS: three managed cells survived LLC orphan/recovery and middle-slot ID/epoch/DSQ bank reuse"
