#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
inspector_bin=${2:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
listen=${SNAKE_TEST_INSPECTOR_LISTEN:-127.0.0.1:44109}
base_url=http://${listen}
tmpdir=$(mktemp -d)
phase1_policy=${tmpdir}/steal.toml
phase2_policy=${tmpdir}/drain.toml
phase1_log=${tmpdir}/snake-steal.ndjson
phase2_log=${tmpdir}/snake-drain.ndjson
inspector_log=${tmpdir}/inspector.log
phase1_result=${tmpdir}/steal-completions
phase1_poke_result=${tmpdir}/steal-poke-completions
phase2_result=${tmpdir}/drain-completions
inspection_json=${tmpdir}/inspection.json
cgroup_root=/sys/fs/cgroup
parent_name=scx-snake-mitosis-dispatch-$$
parent=${cgroup_root}/${parent_name}
alpha=${parent}/alpha
beta=${parent}/beta
snake_pid=
inspector_pid=
started_pid=
normal_runtime_map_id=
affinity_runtime_map_id=
last_attach_ms=
dmesg_lines=0
declare -a phase1_workers=()
declare -a phase2_workers=()
declare -a beta_workers=()
declare -a gate_pids=()
declare -a local_gate_pids=()
declare -a soft_gate_pids=()
declare -a spawned_pids=()
declare -A cpu_llc=()
declare -A local_idle_baseline=()

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
    stop_many "${gate_pids[@]}" "${soft_gate_pids[@]}"
    gate_pids=()
    local_gate_pids=()
    soft_gate_pids=()
}

stop_snake() {
    local attempt

    [[ -n ${snake_pid} ]] || return 0
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${snake_pid}" INT
    snake_pid=
    for ((attempt = 0; attempt < 200; attempt++)); do
        [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] &&
            return 0
        sleep 0.02
    done
    return 1
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    set +e
    stop_gates
    stop_many "${phase1_workers[@]}" "${phase2_workers[@]}" "${beta_workers[@]}"
    stop_many "${spawned_pids[@]}"
    stop_snake
    stop_pid "${inspector_pid}" INT
    rmdir "${alpha}" "${beta}" "${parent}" 2>/dev/null || true
    if [[ ${SNAKE_TEST_KEEP_TMP:-0} == 1 ]]; then
        chmod -R a+rX "${tmpdir}" 2>/dev/null || true
        echo "vtime Mitosis drain/steal artifacts: ${tmpdir}" >&2
    else
        rm -rf "${tmpdir}"
    fi
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "vtime Mitosis drain/steal test: $*" >&2
    printf 'sched_ext state: %s\n' "$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)" >&2
    if ((dmesg_lines > 0)); then
        dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    fi
    if [[ -s ${phase1_log} ]]; then
        printf '%s\n' '--- steal scheduler log ---' >&2
        grep -v '^{' "${phase1_log}" | tail -n 80 >&2 2>/dev/null || true
    fi
    if [[ -s ${phase2_log} ]]; then
        printf '%s\n' '--- drain scheduler log ---' >&2
        grep -v '^{' "${phase2_log}" | tail -n 100 >&2 2>/dev/null || true
    fi
    if [[ -s ${inspector_log} ]]; then
        printf '%s\n' '--- inspector log ---' >&2
        tail -n 80 "${inspector_log}" >&2 2>/dev/null || true
    fi
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

wait_for_before() {
    local description=$1 started_ms=$2 limit_ms=$3 interval=$4 now_ms
    shift 4

    while true; do
        "$@" && return 0
        if [[ -n ${snake_pid} ]]; then
            pid_done "${snake_pid}" && return 1
            scheduler_enabled || return 1
        fi
        now_ms=$(monotonic_ms)
        ((now_ms - started_ms < limit_ms)) || break
        sleep "${interval}"
    done
    echo "timed out waiting for ${description} within ${limit_ms}ms gate window" >&2
    return 1
}

wait_for_inspector() {
    [[ -n ${inspector_pid} ]] && kill -0 "${inspector_pid}" 2>/dev/null &&
        curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" \
            >/dev/null 2>&1
}

wait_for_stopped() {
    local pid=$1
    [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == T ]]
}

all_runnable() {
    local pid state

    for pid in "$@"; do
        [[ -r /proc/${pid}/stat ]] || return 1
        read -r _ _ state _ <"/proc/${pid}/stat" || return 1
        [[ ${state} == R ]] || return 1
    done
}

wait_for_detached() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]]
}

inspection_matches_attach() {
    local enable_seq=$1

    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson enable_seq "${enable_seq}" '
            .error == null and .context.scheduler_active == true and
            .context.scheduler_attach_seq == $enable_seq and
            .snapshot.queue_topology.layout == "cell_llc" and
            ([.snapshot.cells[] | select(.name == "alpha" or .name == "beta")] | length) == 2
        ' >/dev/null
}

stats_sum() {
    local log=$1 kind=$2 key=$3 field=$4

    python3 - "${log}" "${kind}" "${key}" "${field}" <<'PY'
import json
import sys

path, kind, key, field = sys.argv[1:]
total = 0
try:
    stream = open(path, encoding="utf-8")
except FileNotFoundError:
    print(0)
    raise SystemExit
with stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if kind == "dispatch":
            value = record.get("dispatch_rungs", {}).get(key, {}).get(field, 0)
        elif kind == "cell":
            value = record.get("cells", {}).get(key, {}).get(field, 0)
        else:
            value = record.get(field, 0)
        if isinstance(value, (int, float)):
            total += value
print(int(total))
PY
}

metric_gt() {
    local log=$1 kind=$2 key=$3 field=$4 baseline=$5 value

    value=$(stats_sum "${log}" "${kind}" "${key}" "${field}")
    ((value > baseline))
}

metric_ge() {
    local log=$1 kind=$2 key=$3 field=$4 expected=$5 value

    value=$(stats_sum "${log}" "${kind}" "${key}" "${field}")
    ((value >= expected))
}

result_count_is() {
    local path=$1 expected=$2 count=0

    [[ -f ${path} ]] && count=$(wc -l <"${path}")
    ((count == expected))
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

normal_queue_depth_ge() {
    local index=$1 expected=$2 depth

    depth=$(normal_queue_depth "${index}") || return 1
    ((depth >= expected))
}

affinity_queue_depth() {
    local cpu=$1 key0 key1 key2 key3

    [[ -n ${affinity_runtime_map_id} ]] || return 1
    printf -v key0 '%02x' $((cpu & 0xff))
    printf -v key1 '%02x' $(((cpu >> 8) & 0xff))
    printf -v key2 '%02x' $(((cpu >> 16) & 0xff))
    printf -v key3 '%02x' $(((cpu >> 24) & 0xff))
    bpftool -j map lookup id "${affinity_runtime_map_id}" \
        key hex "${key0}" "${key1}" "${key2}" "${key3}" |
        jq -er '.formatted.value.nr_queued'
}

cpu_idle_ticks() {
    local cpu=$1

    awk -v name="cpu${cpu}" '$1 == name { print $5 + $6; found = 1 }
        END { if (!found) exit 1 }' /proc/stat
}

monotonic_ms() {
    awk '{ printf "%.0f\n", $1 * 1000 }' /proc/uptime
}

cpu_idle_advanced() {
    local cpu=$1 baseline=$2 current

    current=$(cpu_idle_ticks "${cpu}") || return 1
    ((current > baseline))
}

local_dispatch_candidates_empty() {
    local cpu depth idle_seen=0

    depth=$(normal_queue_depth "${local_queue_index}") || return 1
    ((depth == 0)) || return 1
    for cpu in "${local_alpha_cpus[@]}"; do
        depth=$(affinity_queue_depth "${cpu}") || return 1
        ((depth == 0)) || return 1
        if cpu_idle_advanced "${cpu}" "${local_idle_baseline[${cpu}]}"; then
            idle_seen=1
        fi
    done
    ((idle_seen == 1))
}

local_candidate_depths() {
    local cpu depth output

    depth=$(normal_queue_depth "${local_queue_index}" 2>/dev/null || printf unknown)
    output="normal[${local_queue_index}]=${depth}"
    for cpu in "${local_alpha_cpus[@]}"; do
        depth=$(affinity_queue_depth "${cpu}" 2>/dev/null || printf unknown)
        output+=" affinity[${cpu}]=${depth}"
    done
    printf '%s\n' "${output}"
}

remote_affinity_depths_zero() {
    local cpu depth

    for cpu in "${remote_alpha_cpus[@]}"; do
        depth=$(affinity_queue_depth "${cpu}") || return 1
        ((depth == 0)) || return 1
    done
}

remote_affinity_depths() {
    local cpu depth output=

    for cpu in "${remote_alpha_cpus[@]}"; do
        depth=$(affinity_queue_depth "${cpu}" 2>/dev/null || printf unknown)
        output+=" affinity[${cpu}]=${depth}"
    done
    printf '%s\n' "${output# }"
}

all_mapped_to_cell() {
    local cell_id=$1 epoch=$2
    shift 2
    local tids_json

    tids_json=$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0) | tonumber)')
    curl -fsS "${base_url}/api/inspection" | jq -e \
        --argjson tids "${tids_json}" --argjson cell "${cell_id}" \
        --argjson epoch "${epoch}" '
            .snapshot.task_mappings as $mappings |
            all($tids[]; . as $tid |
                any($mappings[];
                    .tid == $tid and .cell_id == $cell and .cell_epoch == $epoch))
        ' >/dev/null
}

resize_removed_llc() {
    local cell_id=$1 epoch=$2 removed_cpus=$3

    curl -fsS --max-time 0.2 "${base_url}/api/inspection" | jq -e \
        --argjson cell "${cell_id}" --argjson epoch "${epoch}" \
        --argjson removed "${removed_cpus}" '
            .snapshot as $snapshot |
            ($snapshot.queue_topology.cells[] | select(.external_id == $cell)) as $cell_state |
            ($cell_state.slot_epoch == $epoch) and
            ($cell_state.primary_cpus | length > 0) and
            (all($cell_state.primary_cpus[]; . as $cpu | ($removed | index($cpu)) == null)) and
            any($snapshot.topology_lifecycle.transitions[];
                .reason == "managed_cells_rebalanced" and .outcome == "applied" and
                any(.cell_changes[];
                    .cell_id == $cell and .before.slot_epoch == $epoch and
                    .after.slot_epoch == $epoch and
                    (.primary_cpus_removed | any(. as $cpu | $removed | index($cpu) != null))))
        ' >/dev/null
}

wait_for_resize_bounded() {
    local cell_id=$1 epoch=$2 removed_cpus=$3 gate_started_ms=$4 limit_ms=$5
    local minimum_backlog=$6
    local elapsed_ms backlog_lost=0

    while true; do
        elapsed_ms=$(($(monotonic_ms) - gate_started_ms))
        if ((elapsed_ms >= limit_ms)); then
            ((backlog_lost == 0)) || return 3
            return 1
        fi
        resize_removed_llc "${cell_id}" "${epoch}" "${removed_cpus}" && return 0
        normal_queue_depth_ge "${remote_queue_index}" "${minimum_backlog}" ||
            backlog_lost=1
        sleep 0.01
    done
}

start_snake() {
    local policy=$1 log=$2 enable_seq
    local -a verbose_args=()

    [[ ${SNAKE_TEST_VERBOSE:-0} == 1 ]] && verbose_args=(-v)

    "${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.05 \
        --stats-format json --exit-dump-len 1048576 "${verbose_args[@]}" \
        >"${log}" 2>&1 &
    snake_pid=$!
    wait_for "Snake attachment" 3000 0.02 scheduler_enabled ||
        fail "scheduler did not attach with $(basename "${policy}")"
    last_attach_ms=$(monotonic_ms)
    enable_seq=$(cat /sys/kernel/sched_ext/enable_seq)
    wait_for "Inspector attachment ${enable_seq}" 200 0.05 \
        inspection_matches_attach "${enable_seq}" ||
        fail "Inspector did not observe scheduler attachment ${enable_seq}"
    normal_runtime_map_id=$(bpftool -j map show | jq -er \
        '[.[] | select(.name == "normal_queue_ru")] | last | .id') ||
        fail "could not find the active normal-queue runtime map"
    affinity_runtime_map_id=$(bpftool -j map show | jq -er \
        '[.[] | select(.name == "affinity_queue_")] | last | .id') ||
        fail "could not find the active affinity-queue runtime map"
    curl -fsS "${base_url}/api/inspection" >"${inspection_json}"
}

start_stopped_worker() {
    local cgroup=$1 initial_cpu=$2 allowed=$3 result=$4 busy_seconds=$5
    local pid last_cpu

    taskset -c "${initial_cpu}" python3 -c '
import os
import signal
import sys
import time

os.kill(os.getpid(), signal.SIGSTOP)
deadline = time.monotonic() + float(sys.argv[2])
value = 1
while time.monotonic() < deadline:
    value = (value * 1664525 + 1013904223) & 0xffffffff
with open(sys.argv[1], "a", encoding="utf-8") as stream:
    stream.write(f"{os.getpid()} {value}\n")
' "${result}" "${busy_seconds}" &
    pid=$!
    spawned_pids+=("${pid}")
    wait_for "worker ${pid} stop" 100 0.02 wait_for_stopped "${pid}" ||
        fail "worker ${pid} did not stop for setup"
    printf '%s\n' "${pid}" >"${cgroup}/cgroup.procs"
    taskset -pc "${allowed}" "${pid}" >/dev/null
    last_cpu=$(awk '{print $39}' "/proc/${pid}/stat")
    [[ ${cpu_llc[${last_cpu}]:-} == "${cpu_llc[${initial_cpu}]}" ]] ||
        fail "worker ${pid} moved LLCs during stopped setup (${initial_cpu} to ${last_cpu})"
    started_pid=${pid}
}

start_stopped_beta_worker() {
    local cpu=$1 pid

    taskset -c "${cpu}" python3 -c '
import os
import signal

os.kill(os.getpid(), signal.SIGSTOP)
value = 1
while True:
    value = (value * 1664525 + 1013904223) & 0xffffffff
' &
    pid=$!
    spawned_pids+=("${pid}")
    wait_for "beta worker ${pid} stop" 100 0.02 wait_for_stopped "${pid}" ||
        fail "beta worker ${pid} did not stop for setup"
    printf '%s\n' "${pid}" >"${beta}/cgroup.procs"
    started_pid=${pid}
}

start_gate() {
    local cpu=$1 pid policy

    taskset -c "${cpu}" chrt -f 1 yes >/dev/null 2>&1 &
    pid=$!
    spawned_pids+=("${pid}")
    for _ in $(seq 1 100); do
        policy=$(chrt -p "${pid}" 2>/dev/null || true)
        grep -q SCHED_FIFO <<<"${policy}" && {
            gate_pids+=("${pid}")
            started_pid=${pid}
            return 0
        }
        sleep 0.01
    done
    stop_pid "${pid}" KILL
    return 1
}

create_stopped_soft_gate() {
    local cpu=$1 nice_level=${2:-0} pid

    taskset -c "${cpu}" nice -n "${nice_level}" python3 -c '
import os
import signal

os.kill(os.getpid(), signal.SIGSTOP)
value = 1
while True:
    value = (value * 1664525 + 1013904223) & 0xffffffff
' &
    pid=$!
    spawned_pids+=("${pid}")
    wait_for "soft gate ${pid} stop" 100 0.01 wait_for_stopped "${pid}" || {
        stop_pid "${pid}" KILL
        return 1
    }
    printf '%s\n' "${pid}" >"${beta}/cgroup.procs"
    soft_gate_pids+=("${pid}")
    started_pid=${pid}
}

start_soft_gate() {
    local cpu=$1 nice_level=${2:-0} pid

    create_stopped_soft_gate "${cpu}" "${nice_level}" || return 1
    pid=${started_pid}
    wait_for "soft gate ${pid} beta membership" 100 0.01 \
        all_mapped_to_cell "${beta_id}" "${beta_epoch}" "${pid}" || {
        stop_pid "${pid}" KILL
        return 1
    }
    kill -CONT "${pid}"
    wait_for "soft gate ${pid} runnable" 100 0.01 all_runnable "${pid}" || {
        stop_pid "${pid}" KILL
        return 1
    }
}

pin_control_plane() {
    local cpu=$1 pid

    taskset -pc "${cpu}" "$$" >/dev/null
    for pid in "${snake_pid}" "${inspector_pid}"; do
        [[ -n ${pid} ]] || continue
        taskset -apc "${cpu}" "${pid}" >/dev/null ||
            fail "could not pin control-plane process ${pid} to CPU ${cpu}"
    done
}

write_policy() {
    local path=$1 resizing=$2
    local resize_cooldown_ms=4000

    cat >"${path}" <<EOF
fallback = "previous_cpu"

[managed_cells]
parent = "/${parent_name}"
max_children = 2
reconcile_ms = 50
cell0_min_cpus = 1
EOF
    if [[ ${resizing} == yes ]]; then
        cat >>"${path}" <<EOF

[managed_cells.resizing]
sample_ms = 2000
threshold_pct = 10.0
cooldown_ms = ${resize_cooldown_ms}
ewma_alpha = 1.0
EOF
    fi
    cat >>"${path}" <<'EOF'

[queues]
layout = "cell_llc"
cell0_cpu_weight = 1
direct_dispatch = true
enqueue = [
  { action = "try_direct", target = "cell" },
  { action = "try_insert", target = "cell" },
  { action = "insert", target = "cpu" },
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
scope = "task_cell_llc"

[[rung]]
operation = "pick_idle_core"
scope = "task_cell_llc"

[[rung]]
operation = "claim_idle"
scope = "task_cell_llc"

[[rung]]
operation = "pick_idle"
scope = "task_cell_llc"
EOF
    if [[ ${resizing} != yes ]]; then
        cat >>"${path}" <<'EOF'

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
scope = "task_cell_borrowable"

[[rung]]
operation = "pick_idle_core"
scope = "task_cell_borrowable"

[[rung]]
operation = "claim_idle"
scope = "task_cell_borrowable"

[[rung]]
operation = "pick_idle"
scope = "task_cell_borrowable"

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
    fi
}

capture_cell_topology() {
    local name=$1
    local topology_file=${tmpdir}/${name}-topology.json

    curl -fsS "${base_url}/api/inspection" >"${topology_file}"
    jq -e '
        .error == null and .snapshot.queue_topology.layout == "cell_llc" and
        ([.snapshot.cells[] | select(.name == "alpha")] | length) == 1 and
        ([.snapshot.cells[] | select(.name == "beta")] | length) == 1
    ' "${topology_file}" >/dev/null || fail "${name} topology is incomplete"
    alpha_id=$(jq -r '.snapshot.cells[] | select(.name == "alpha") | .id' "${topology_file}")
    beta_id=$(jq -r '.snapshot.cells[] | select(.name == "beta") | .id' "${topology_file}")
    alpha_epoch=$(jq -r --argjson id "${alpha_id}" \
        '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .slot_epoch' \
        "${topology_file}")
    beta_epoch=$(jq -r --argjson id "${beta_id}" \
        '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .slot_epoch' \
        "${topology_file}")
    mapfile -t alpha_cpus < <(jq -r --argjson id "${alpha_id}" \
        '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .primary_cpus[]' \
        "${topology_file}")
    mapfile -t alpha_borrowable_cpus < <(jq -r --argjson id "${alpha_id}" \
        '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .borrowable_cpus[]' \
        "${topology_file}")
    mapfile -t beta_cpus < <(jq -r --argjson id "${beta_id}" \
        '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .primary_cpus[]' \
        "${topology_file}")
    declare -A alpha_llcs=()
    local cpu llc selected_llc=-1 selected_min=-1
    for cpu in "${alpha_cpus[@]}"; do
        llc=${cpu_llc[${cpu}]}
        alpha_llcs[${llc}]=1
    done
    ((${#alpha_llcs[@]} == 2)) ||
        fail "${name} cell alpha does not initially span both LLCs: ${alpha_cpus[*]}"
    for llc in "${!alpha_llcs[@]}"; do
        for cpu in "${alpha_cpus[@]}"; do
            [[ ${cpu_llc[${cpu}]} == "${llc}" ]] || continue
            if ((cpu > selected_min)); then
                selected_min=${cpu}
                selected_llc=${llc}
            fi
        done
    done
    remote_llc=${selected_llc}
    remote_queue_index=$(jq -er --argjson id "${alpha_id}" \
        --argjson llc "${remote_llc}" '
            .snapshot.queue_topology.normal_queues[] |
            select(.cell_id == $id and .llc_id == $llc) | .index
        ' "${topology_file}") || fail "could not find alpha's remote normal queue"
    remote_alpha_cpus=()
    local_alpha_cpus=()
    for cpu in "${alpha_cpus[@]}"; do
        if [[ ${cpu_llc[${cpu}]} == "${remote_llc}" ]]; then
            remote_alpha_cpus+=("${cpu}")
        else
            local_alpha_cpus+=("${cpu}")
        fi
    done
    ((${#remote_alpha_cpus[@]} > 0 && ${#local_alpha_cpus[@]} > 0)) ||
        fail "could not split alpha CPUs by LLC"
    local_llc=${cpu_llc[${local_alpha_cpus[0]}]}
    local_queue_index=$(jq -er --argjson id "${alpha_id}" \
        --argjson llc "${local_llc}" '
            .snapshot.queue_topology.normal_queues[] |
            select(.cell_id == $id and .llc_id == $llc) | .index
        ' "${topology_file}") || fail "could not find alpha's local normal queue"
    remote_llc_cpus=()
    for cpu in "${online_cpu_ids[@]}"; do
        [[ ${cpu_llc[${cpu}]} == "${remote_llc}" ]] && remote_llc_cpus+=("${cpu}")
    done
    remote_llc_json=$(printf '%s\n' "${remote_llc_cpus[@]}" | jq -Rsc \
        'split("\n") | map(select(length > 0) | tonumber)')
}

if [[ ${SNAKE_TEST_ALLOW_BARE_METAL:-0} != 1 ]]; then
    inside_vm || fail "refusing to run outside a VM (set SNAKE_TEST_ALLOW_BARE_METAL=1 to override)"
fi
((EUID == 0)) || fail "must run as root inside a VM"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
for command in bpftool chrt curl jq python3 taskset; do
    command -v "${command}" >/dev/null || fail "${command} is required"
done
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
(( $(nproc) == 12 )) || fail "requires a 12-vCPU guest"

online_cpus=$(cat /sys/devices/system/cpu/online)
mapfile -t online_cpu_ids < <(seq 0 11)
declare -A observed_llcs=()
for cpu in "${online_cpu_ids[@]}"; do
    cache_id_file=/sys/devices/system/cpu/cpu${cpu}/cache/index3/id
    [[ -r ${cache_id_file} ]] || fail "CPU ${cpu} has no LLC identity at ${cache_id_file}"
    cpu_llc[${cpu}]=$(<"${cache_id_file}")
    observed_llcs[${cpu_llc[${cpu}]}]=1
done
((${#observed_llcs[@]} == 2)) || fail "requires exactly two guest LLCs"
for llc in "${!observed_llcs[@]}"; do
    count=0
    for cpu in "${online_cpu_ids[@]}"; do
        [[ ${cpu_llc[${cpu}]} == "${llc}" ]] && count=$((count + 1))
    done
    ((count == 6)) || fail "LLC ${llc} has ${count} CPUs; expected six"
done

grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
    fail "cgroup root does not provide the cpuset controller"
grep -qw cpuset "${cgroup_root}/cgroup.subtree_control" ||
    printf '%s\n' +cpuset >"${cgroup_root}/cgroup.subtree_control"
cpuset_mems=$(cat "${cgroup_root}/cpuset.mems.effective")
mkdir "${parent}"
printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"
mkdir "${alpha}" "${beta}"
printf '%s\n' "${cpuset_mems}" >"${alpha}/cpuset.mems"
printf '%s\n' "${cpuset_mems}" >"${beta}/cpuset.mems"
[[ -z $(<"${alpha}/cpuset.cpus") && -z $(<"${beta}/cpuset.cpus") ]] ||
    fail "managed children must remain unpinned"

write_policy "${phase1_policy}" no
write_policy "${phase2_policy}" yes
: >"${phase1_result}"
: >"${phase1_poke_result}"
: >"${phase2_result}"
dmesg_lines=$(dmesg | wc -l)

if curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" >/dev/null 2>&1; then
    fail "Inspector address ${listen} is already serving an API"
fi
"${inspector_bin}" --listen "${listen}" --snake-bin "${snake_bin}" \
    --policy-dir "${tmpdir}" >"${inspector_log}" 2>&1 &
inspector_pid=$!
wait_for "Inspector API" 200 0.05 wait_for_inspector || fail "Inspector API did not start"

# Phase 1 uses the full 16-rung Mitosis selector. Gate every alpha CPU so
# direct dispatch cannot bypass the queue, then release the sibling LLC and
# wake a local task to force same-cell stealing.
start_snake "${phase1_policy}" "${phase1_log}"
capture_cell_topology steal
control_cpu=${beta_cpus[0]}
pin_control_plane "${control_cpu}"
alpha_allowed=$(IFS=,; printf '%s' "${alpha_cpus[*]}")
load_beta_cpus=()
for cpu in "${beta_cpus[@]}"; do
    [[ ${cpu} == "${control_cpu}" ]] || load_beta_cpus+=("${cpu}")
done
((${#load_beta_cpus[@]} > 0)) || fail "beta has no CPU outside the control plane"
phase1_count=32
for ((index = 0; index < phase1_count; index++)); do
    source_cpu=${remote_alpha_cpus[index % ${#remote_alpha_cpus[@]}]}
    start_stopped_worker \
        "${alpha}" "${source_cpu}" "${online_cpus}" \
        "${phase1_result}" 0.01
    phase1_workers+=("${started_pid}")
done
start_stopped_worker \
    "${alpha}" "${local_alpha_cpus[0]}" "${alpha_allowed}" \
    "${phase1_poke_result}" 0.01
phase1_poke=${started_pid}
phase1_workers+=("${phase1_poke}")
wait_for "phase-1 managed membership" 200 0.05 \
    all_mapped_to_cell "${alpha_id}" "${alpha_epoch}" "${phase1_workers[@]}" ||
    fail "phase-1 workers were not assigned to alpha"
steal_hits_before=$(stats_sum "${phase1_log}" dispatch 4 hits)
alpha_enqueues_before=$(stats_sum "${phase1_log}" cell "${alpha_id}" normal_enqueues)
for cpu in "${alpha_borrowable_cpus[@]}"; do
    soft_nice=0
    [[ ${cpu} == "${control_cpu}" ]] && soft_nice=19
    start_soft_gate "${cpu}" "${soft_nice}" ||
        fail "could not load borrowable CPU ${cpu}"
done
phase1_gate_started_ms=$(monotonic_ms)
for cpu in "${alpha_cpus[@]}"; do
    start_gate "${cpu}" || fail "could not start phase-1 RT gate on CPU ${cpu}"
    [[ ${cpu_llc[${cpu}]} == "${remote_llc}" ]] ||
        local_gate_pids+=("${started_pid}")
done
kill -CONT "${phase1_workers[@]:0:${phase1_count}}"
expected_enqueues=$((alpha_enqueues_before + phase1_count))
wait_for_before "phase-1 workers runnable" \
    "${phase1_gate_started_ms}" 4000 0.005 \
    all_runnable "${phase1_workers[@]:0:${phase1_count}}" || {
    stop_gates
    fail "phase-1 workers did not become runnable behind the gates"
}
if ! wait_for_before "phase-1 remote normal enqueues" \
    "${phase1_gate_started_ms}" 4000 0.02 \
    metric_ge "${phase1_log}" cell "${alpha_id}" normal_enqueues \
        "${expected_enqueues}"; then
    phase1_enqueues=$(stats_sum \
        "${phase1_log}" cell "${alpha_id}" normal_enqueues)
    stop_gates
    fail "phase-1 alpha normal enqueues=${phase1_enqueues}; expected >=${expected_enqueues} before releasing the sibling LLC"
fi
wait_for_before "phase-1 remote normal queue depth" \
    "${phase1_gate_started_ms}" 4000 0.01 \
    normal_queue_depth_ge "${remote_queue_index}" 1 || {
    stop_gates
    fail "phase-1 remote normal queue ${remote_queue_index} never held backlog"
}
for cpu in "${local_alpha_cpus[@]}"; do
    local_idle_baseline[${cpu}]=$(cpu_idle_ticks "${cpu}") || {
        stop_gates
        fail "could not read idle time for local alpha CPU ${cpu}"
    }
done
stop_many "${local_gate_pids[@]}"
local_gate_pids=()
if ! wait_for_before "empty local dispatch candidates" \
    "${phase1_gate_started_ms}" 4000 0.01 \
    local_dispatch_candidates_empty; then
    local_depths=$(local_candidate_depths)
    stop_gates
    fail "local candidates did not settle before the steal poke: ${local_depths}"
fi
kill -CONT "${phase1_poke}"
wait_for_before "phase-1 local dispatch poke" \
    "${phase1_gate_started_ms}" 4000 0.01 \
    result_count_is "${phase1_poke_result}" 1 || {
    stop_gates
    fail "local dispatch poke did not complete"
}
if ! wait_for_before "same-cell sibling-steal completions" \
    "${phase1_gate_started_ms}" 4000 0.01 \
    result_count_is "${phase1_result}" "${phase1_count}"; then
    phase1_completed=$(wc -l <"${phase1_result}")
    phase1_enqueues=$(stats_sum \
        "${phase1_log}" cell "${alpha_id}" normal_enqueues)
    phase1_steal_hits=$(stats_sum "${phase1_log}" dispatch 4 hits)
    stop_gates
    fail "sibling LLC completed ${phase1_completed}/${phase1_count} queued tasks; alpha enqueues=${phase1_enqueues} (expected >=${expected_enqueues}), rung-4 hits=${phase1_steal_hits} (baseline ${steal_hits_before})"
fi
stop_gates
wait_for "dispatch rung 4 hit" 200 0.02 \
    metric_gt "${phase1_log}" dispatch 4 hits "${steal_hits_before}" ||
    fail "same-cell sibling stealing did not increment dispatch rung 4"
scheduler_enabled || fail "scheduler detached during sibling stealing"
stop_snake || fail "phase-1 scheduler did not detach"
wait_for "phase-1 sched_ext detach" 100 0.02 wait_for_detached ||
    fail "sched_ext remained enabled after phase 1"
phase1_workers=()

# Phase 2 intentionally narrows selection to the four task-cell/LLC rungs so
# borrowing and cell-wide escape cannot obscure the orphan-drain assertion.
# The enqueue and dispatch ladders remain unchanged. Preheat beta, queue alpha
# work shortly before the demand sample, and require the stable orphan queue to
# drain through dispatch rung 0 without changing alpha's ID or slot epoch.
phase2_count=128
((${#remote_alpha_cpus[@]} >= 2)) ||
    fail "phase 2 needs two former primary CPUs in the remote LLC"
for ((index = 0; index < phase2_count; index++)); do
    source_cpu=${remote_alpha_cpus[index % ${#remote_alpha_cpus[@]}]}
    start_stopped_worker \
        "${alpha}" "${source_cpu}" "${online_cpus}" \
        "${phase2_result}" 0.05
    phase2_workers+=("${started_pid}")
done
for ((index = 0; index < ${#load_beta_cpus[@]}; index++)); do
    source_cpu=${load_beta_cpus[index]}
    start_stopped_beta_worker "${source_cpu}"
    beta_workers+=("${started_pid}")
done
phase2_remote_expected=${remote_alpha_cpus[*]}
phase2_local_expected=${local_alpha_cpus[*]}
phase2_borrowable_expected=${alpha_borrowable_cpus[*]}
start_snake "${phase2_policy}" "${phase2_log}"
capture_cell_topology drain
[[ ${remote_alpha_cpus[*]} == "${phase2_remote_expected}" &&
    ${local_alpha_cpus[*]} == "${phase2_local_expected}" &&
    ${alpha_borrowable_cpus[*]} == "${phase2_borrowable_expected}" ]] ||
    fail "phase-2 initial CPU allocation changed before attachment"
wait_for "phase-2 alpha membership" 200 0.05 \
    all_mapped_to_cell "${alpha_id}" "${alpha_epoch}" "${phase2_workers[@]}" ||
    fail "phase-2 backlog workers were not assigned to alpha"
wait_for "phase-2 beta membership" 200 0.05 \
    all_mapped_to_cell "${beta_id}" "${beta_epoch}" \
        "${beta_workers[@]}" "${soft_gate_pids[@]}" ||
    fail "phase-2 load and gate workers were not assigned to beta"
alpha_enqueues_before=$(stats_sum "${phase2_log}" cell "${alpha_id}" normal_enqueues)
drain_hits_before=$(stats_sum "${phase2_log}" dispatch 0 hits)
wait_for "moving-CPU affinity queues empty before phase 2" 100 0.01 \
    remote_affinity_depths_zero ||
    fail "moving-CPU affinity queues were not empty before phase-2 workload start"
kill -CONT "${beta_workers[@]}"
phase2_work_target_ms=$((last_attach_ms + 3800))
phase2_work_delay_ms=$((phase2_work_target_ms - $(monotonic_ms)))
if ((phase2_work_delay_ms > 0)); then
    phase2_work_delay=$(awk -v ms="${phase2_work_delay_ms}" \
        'BEGIN { printf "%.3f", ms / 1000 }')
    sleep "${phase2_work_delay}"
fi
phase2_work_started_ms=$(monotonic_ms)
kill -CONT "${phase2_workers[@]:0:${phase2_count}}"
expected_enqueues=$((alpha_enqueues_before + phase2_count))
minimum_backlog=$((phase2_count / 4))
wait_for_before "phase-2 remote normal queue depth" \
    "${phase2_work_started_ms}" 1200 0.01 \
    normal_queue_depth_ge "${remote_queue_index}" "${minimum_backlog}" || {
    phase2_remote_depth=$(normal_queue_depth \
        "${remote_queue_index}" 2>/dev/null || printf unknown)
    stop_gates
    fail "phase-2 remote normal queue ${remote_queue_index} depth=${phase2_remote_depth}"
}
phase2_remote_depth=$(normal_queue_depth "${remote_queue_index}" || printf unknown)
phase2_depth_elapsed_ms=$(($(monotonic_ms) - phase2_work_started_ms))

resize_wait_rc=0
if wait_for_resize_bounded \
    "${alpha_id}" "${alpha_epoch}" "${remote_llc_json}" \
    "${phase2_work_started_ms}" 2000 "${minimum_backlog}"; then
    :
else
    resize_wait_rc=$?
    phase2_resize_elapsed_ms=$(($(monotonic_ms) - phase2_work_started_ms))
    phase2_affinity_depths=$(remote_affinity_depths)
    phase2_remaining_depth=$(normal_queue_depth \
        "${remote_queue_index}" 2>/dev/null || printf unknown)
    stop_gates
    fail "demand resize failed within 2000ms of phase-2 workload start (rc=${resize_wait_rc}, affinity=${phase2_affinity_depths}, remote_depth=${phase2_remaining_depth}, elapsed=${phase2_resize_elapsed_ms}ms)"
fi
phase2_resize_elapsed_ms=$(($(monotonic_ms) - phase2_work_started_ms))
printf 'phase-2 timing: remote-depth=%sms resize-published=%sms\n' \
    "${phase2_depth_elapsed_ms}" "${phase2_resize_elapsed_ms}" >&2
curl -fsS --max-time 0.5 "${base_url}/api/inspection" \
    >"${tmpdir}/inspection-after-resize.json" || {
    stop_gates
    fail "Inspector did not return the resized topology"
}
mapfile -t remaining_alpha_cpus < <(jq -r --argjson id "${alpha_id}" \
    '.snapshot.queue_topology.cells[] | select(.external_id == $id) | .primary_cpus[]' \
    "${tmpdir}/inspection-after-resize.json")
((${#remaining_alpha_cpus[@]} >= 1)) || {
    stop_gates
    fail "resize left alpha without a primary CPU for drain liveness"
}
idle_drain_cpu=${remaining_alpha_cpus[0]}
idle_ticks_before=$(cpu_idle_ticks "${idle_drain_cpu}") || {
    stop_gates
    fail "could not read idle time for drain CPU ${idle_drain_cpu}"
}
stop_gates
wait_for "orphan drain rung hit" 300 0.02 \
    metric_gt "${phase2_log}" dispatch 0 hits "${drain_hits_before}" ||
    fail "orphan backlog did not increment dispatch rung 0"
wait_for "orphan backlog completion" 500 0.02 \
    result_count_is "${phase2_result}" "${phase2_count}" ||
    fail "orphaned cell/LLC backlog did not complete"
wait_for "drain CPU ${idle_drain_cpu} idle" 300 0.01 \
    cpu_idle_advanced "${idle_drain_cpu}" "${idle_ticks_before}" ||
    fail "drain CPU ${idle_drain_cpu} did not become idle"
wait_for "phase-2 remote normal enqueues" 200 0.02 \
    metric_ge "${phase2_log}" cell "${alpha_id}" normal_enqueues "${expected_enqueues}" ||
    fail "phase-2 work did not enter alpha's remote normal queue"
stop_many "${beta_workers[@]}"
beta_workers=()
scheduler_enabled || fail "scheduler detached during orphan draining"
stop_snake || fail "phase-2 scheduler did not detach"
wait_for "phase-2 sched_ext detach" 100 0.02 wait_for_detached ||
    fail "sched_ext remained enabled after phase 2"

phase1_invalid=$(stats_sum "${phase1_log}" global ignored invalid_errors)
phase2_invalid=$(stats_sum "${phase2_log}" global ignored invalid_errors)
phase1_accounting=$(stats_sum "${phase1_log}" global ignored vtime_accounting_errors)
phase2_accounting=$(stats_sum "${phase2_log}" global ignored vtime_accounting_errors)
((phase1_invalid == 0 && phase2_invalid == 0 &&
    phase1_accounting == 0 && phase2_accounting == 0)) ||
    fail "scheduler correctness counters are nonzero: phase1 invalid=${phase1_invalid} accounting=${phase1_accounting}; phase2 invalid=${phase2_invalid} accounting=${phase2_accounting}"
failure_pattern='normal queue [0-9]+ depth underflow|depth underflow|invalid enq_flags|scx_bpf_error|Error: EXIT|runnable task stall'
if grep -Eiq "${failure_pattern}" "${phase1_log}" "${phase2_log}"; then
    fail "scheduler log contains a stall or queue-depth failure"
fi
if dmesg | tail -n +$((dmesg_lines + 1)) | grep -Eiq \
    'depth underflow|runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler stall or kernel failure"
fi

echo "PASS: sibling steal hit dispatch rung 4 and same-epoch orphan drain hit rung 0"
