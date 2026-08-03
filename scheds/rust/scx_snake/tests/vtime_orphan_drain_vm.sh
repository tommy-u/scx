#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
vng=${VNG:-vng}
guest_cpus=12,sockets=2,cores=6,threads=1
guest_memory=${SNAKE_TESTING_GUEST_MEMORY:-4G}
dry_run=${SNAKE_TESTING_DRY_RUN:-0}
listen=${SNAKE_ORPHAN_DRAIN_LISTEN:-127.0.0.1:44111}

fail() {
    echo "VTIME orphan-drain VM test: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
Usage:
  vtime_orphan_drain_vm.sh [RUN_DIR] [SNAKE_BIN] [INSPECTOR_BIN]
  vtime_orphan_drain_vm.sh --guest RUN_DIR SNAKE_BIN INSPECTOR_BIN LISTEN

Host mode snapshots its inputs and launches one two-LLC virtme guest. Guest
mode externally marks a populated cell/LLC queue as consumerless, proves that
the sched_ext watchdog kicks Snake with its drain bit clear, then proves the
same task finishes while Snake stays attached when the drain bit is present.
EOF
}

inside_vm() {
    if command -v systemd-detect-virt >/dev/null; then
        systemd-detect-virt --vm --quiet
    else
        grep -qw hypervisor /proc/cpuinfo
    fi
}

run_host() {
    local run_dir=${1:-/tmp/scx-snake-testing/vtime-orphan-drain-$(date +%Y%m%d-%H%M%S)}
    local snake_bin=${2:-${repo}/target/release/scx_snake}
    local inspector_bin=${3:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
    local input_dir snapshot_script snapshot_snake snapshot_inspector guest_script
    local -a guest_command vm_command

    inside_vm && fail "host mode must run outside a VM"
    command -v "${vng}" >/dev/null || fail "virtme-ng is required (set VNG to override)"
    command -v jq >/dev/null || fail "jq is required"
    command -v timeout >/dev/null || fail "timeout is required"
    [[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
    [[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
    [[ -n ${guest_memory} ]] || fail "SNAKE_TESTING_GUEST_MEMORY must not be empty"
    [[ ${dry_run} == 0 || ${dry_run} == 1 ]] ||
        fail "SNAKE_TESTING_DRY_RUN must be 0 or 1"

    run_dir=$(realpath -m "${run_dir}")
    input_dir=${run_dir}/inputs
    snapshot_script=${input_dir}/vtime_orphan_drain_vm.sh
    snapshot_snake=${input_dir}/scx_snake
    snapshot_inspector=${input_dir}/scx_snake_inspector
    guest_script=${run_dir}/guest.sh
    guest_command=(
        "${snapshot_script}" --guest "${run_dir}" "${snapshot_snake}"
        "${snapshot_inspector}" "${listen}"
    )
    vm_command=(
        "${vng}" --run
        --name snake-vtime-orphan-drain
        --cpus "${guest_cpus}"
        --memory "${guest_memory}"
        --user root
        --rwdir "${run_dir}"
        --exec "${guest_script}"
    )

    echo "Guest command:"
    printf '  '
    printf '%q ' "${guest_command[@]}"
    printf '\n'
    echo "VM command:"
    printf '  '
    printf '%q ' "${vm_command[@]}"
    printf '\n'
    [[ ${dry_run} == 0 ]] || return 0

    [[ -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is not usable"
    [[ ! -e ${run_dir} ]] || fail "run directory already exists: ${run_dir}"
    mkdir -p "${input_dir}"
    cp "$0" "${snapshot_script}"
    cp "${snake_bin}" "${snapshot_snake}"
    cp "${inspector_bin}" "${snapshot_inspector}"
    chmod 0555 "${snapshot_script}" "${snapshot_snake}" "${snapshot_inspector}"
    chmod -R a-w "${input_dir}"
    sha256sum "${snapshot_snake}" "${snapshot_inspector}" >"${run_dir}/binary-sha256.txt"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'exec '
        printf '%q ' "${guest_command[@]}"
        printf '\n'
    } >"${guest_script}"
    chmod 0555 "${guest_script}"

    if ! timeout --signal=TERM --kill-after=20s 240s \
        "${vm_command[@]}" >"${run_dir}/vm.log" 2>&1; then
        tail -n 240 "${run_dir}/vm.log" >&2 || true
        fail "virtme guest failed"
    fi
    [[ -s ${run_dir}/result.json ]] || fail "guest produced no result.json"
    jq -e '
        .status == "passed" and
        .topology.llc_count == 2 and
        .negative.completed == false and
        .negative.kickout_observed == true and
        .negative.depth_before >= 1 and
        .negative.stall_ms > 0 and .negative.stall_ms <= 120000 and
        .positive.completed == true and
        .positive.kickout_observed == false and
        .positive.depth_after == 0 and
        .positive.drain_hits_delta > 0
    ' "${run_dir}/result.json" >/dev/null || fail "guest result did not prove drain causality"
    echo "PASS: VTIME orphan-drain artifact: ${run_dir}"
}

run_guest() {
    local run_dir=$1 snake_bin=$2 inspector_bin=$3 guest_listen=$4
    local base_url=http://${guest_listen}
    local cgroup_root=/sys/fs/cgroup
    local parent_name=scx-snake-orphan-drain
    local parent=${cgroup_root}/${parent_name}
    local alpha=${parent}/alpha
    local beta=${parent}/beta
    local runtime_dir=${run_dir}/runtime
    local policy=${runtime_dir}/orphan-drain.toml
    local inspector_log=${run_dir}/inspector.log
    local inspector_pid='' snake_pid='' dmesg_lines fixture_created=0
    local normal_runtime_map_id='' cell_runtime_map_id='' cpu_queues_map_id=''
    local started_pid='' payload_pid='' poke_pid=''
    local alpha_id alpha_index alpha_epoch active_slot control_cpu target_llc
    local target_queue_index survivor_queue_index target_cell_offset
    local target_source_cpu survivor_cpu
    local workload_allowed cpuset_mems online_cpus
    local -a online_cpu_ids=() alpha_cpus=() target_cpus=() survivor_cpus=()
    local -a worker_pids=()
    local -A cpu_llc=() gate_pid_by_cpu=()

    stop_pid() {
        local pid=$1 signal=${2:-TERM} attempt

        [[ -n ${pid} ]] || return 0
        kill -CONT "${pid}" 2>/dev/null || true
        kill "-${signal}" "${pid}" 2>/dev/null || true
        for ((attempt = 0; attempt < 60; attempt++)); do
            if [[ ! -r /proc/${pid}/stat ]] ||
                [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == Z ]]; then
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
            stop_pid "${pid}"
        done
        worker_pids=()
        payload_pid=
        poke_pid=
    }

    stop_gates() {
        local cpu pid

        for cpu in "${!gate_pid_by_cpu[@]}"; do
            pid=${gate_pid_by_cpu[${cpu}]:-}
            stop_pid "${pid}"
            unset 'gate_pid_by_cpu[$cpu]'
        done
    }

    stop_snake() {
        local attempt

        [[ -n ${snake_pid} ]] || return 0
        kill -INT "${snake_pid}" 2>/dev/null || true
        for ((attempt = 0; attempt < 150; attempt++)); do
            if [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]]; then
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
        stop_gates
        stop_snake || {
            kill -KILL "${snake_pid}" 2>/dev/null || true
            wait "${snake_pid}" 2>/dev/null || true
        }
        stop_pid "${inspector_pid}" INT
        if ((fixture_created)); then
            rmdir "${alpha}" "${beta}" "${parent}" 2>/dev/null || true
        fi
        dmesg | tail -n +$((dmesg_lines + 1)) >"${run_dir}/dmesg-cleanup.txt" 2>/dev/null
        exit "${rc}"
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    guest_fail() {
        echo "VTIME orphan-drain guest: $*" >&2
        printf 'sched_ext state: %s\n' \
            "$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)" >&2
        dmesg | tail -n +$((dmesg_lines + 1)) >&2 2>/dev/null || true
        for log in "${runtime_dir}"/*.ndjson "${inspector_log}"; do
            [[ -s ${log} ]] || continue
            printf '%s\n' "--- ${log} ---" >&2
            tail -n 100 "${log}" >&2 || true
        done
        exit 1
    }

    scheduler_enabled() {
        [[ -n ${snake_pid} ]] && kill -0 "${snake_pid}" 2>/dev/null &&
            [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]]
    }

    wait_for() {
        local description=$1 attempts=$2 interval=$3 attempt
        shift 3

        for ((attempt = 0; attempt < attempts; attempt++)); do
            "$@" && return 0
            if [[ ${description} != "Inspector API" &&
                ${description} != "Snake attachment" && -n ${snake_pid} ]] &&
                ! scheduler_enabled; then
                return 1
            fi
            sleep "${interval}"
        done
        echo "timed out waiting for ${description}" >&2
        return 1
    }

    inspector_ready() {
        [[ -n ${inspector_pid} ]] && kill -0 "${inspector_pid}" 2>/dev/null &&
            curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" >/dev/null 2>&1
    }

    inspection_ready() {
        local enable_seq=$1 snapshot=$2

        curl -fsS --max-time 0.4 "${base_url}/api/inspection" >"${snapshot}.tmp" || return 1
        mv "${snapshot}.tmp" "${snapshot}"
        jq -e --argjson enable_seq "${enable_seq}" '
            .error == null and .context.scheduler_active == true and
            .context.scheduler_attach_seq == $enable_seq and
            .snapshot.queue_topology.layout == "cell_llc" and
            any(.snapshot.cells[]; .name == "alpha") and
            any(.snapshot.cells[]; .name == "beta")
        ' "${snapshot}" >/dev/null
    }

    worker_stopped() {
        local pid=$1
        [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == T ]]
    }

    worker_runnable() {
        local pid=$1
        [[ $(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true) == R ]]
    }

    result_has_token() {
        local path=$1 token=$2
        [[ -f ${path} ]] && grep -Fxq "${token}" "${path}"
    }

    start_stopped_worker() {
        local cgroup=$1 source_cpu=$2 allowed=$3 result=$4 token=$5 pid

        taskset -c "${source_cpu}" python3 - "${result}" "${token}" <<'PY' &
import os
import signal
import sys
import time

os.kill(os.getpid(), signal.SIGSTOP)
deadline = time.monotonic() + 0.03
value = 1
while time.monotonic() < deadline:
    value = (value * 1664525 + 1013904223) & 0xffffffff
with open(sys.argv[1], "a", encoding="utf-8") as stream:
    stream.write(sys.argv[2] + "\n")
PY
        pid=$!
        wait_for "worker ${pid} stop" 100 0.02 worker_stopped "${pid}" || {
            stop_pid "${pid}" KILL
            return 1
        }
        printf '%s\n' "${pid}" >"${cgroup}/cgroup.procs"
        taskset -pc "${allowed}" "${pid}" >/dev/null
        worker_pids+=("${pid}")
        started_pid=${pid}
    }

    worker_mapped_to_alpha() {
        local pid=$1

        curl -fsS --max-time 0.3 "${base_url}/api/inspection" | jq -e \
            --argjson pid "${pid}" --argjson cell "${alpha_id}" \
            --argjson epoch "${alpha_epoch}" '
                any(.snapshot.task_mappings[];
                    .tid == $pid and .cell_id == $cell and .cell_epoch == $epoch)
            ' >/dev/null
    }

    start_gate() {
        local cpu=$1 pid policy

        taskset -c "${cpu}" chrt -f 1 yes >/dev/null 2>&1 &
        pid=$!
        for _ in $(seq 1 100); do
            policy=$(chrt -p "${pid}" 2>/dev/null || true)
            if grep -q SCHED_FIFO <<<"${policy}"; then
                gate_pid_by_cpu[${cpu}]=${pid}
                return 0
            fi
            sleep 0.01
        done
        stop_pid "${pid}" KILL
        return 1
    }

    map_field() {
        local map_id=$1 index=$2 field=$3
        local -a key

        mapfile -t key < <(u32_bytes "${index}")
        bpftool -j map lookup id "${map_id}" key hex "${key[@]}" |
            jq -er --arg field "${field}" '.formatted.value[$field]'
    }

    u32_bytes() {
        local value=$1

        printf '%02x\n' \
            $((value & 0xff)) \
            $(((value >> 8) & 0xff)) \
            $(((value >> 16) & 0xff)) \
            $(((value >> 24) & 0xff))
    }

    write_normal_runtime() {
        local index=$1 has_consumers=$2 nr_queued cell_index cell_offset byte
        local -a key=() value=()

        nr_queued=$(map_field "${normal_runtime_map_id}" "${index}" nr_queued)
        cell_index=$(map_field "${normal_runtime_map_id}" "${index}" cell_index)
        cell_offset=$(map_field "${normal_runtime_map_id}" "${index}" cell_offset)
        mapfile -t key < <(u32_bytes "${index}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${nr_queued}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${has_consumers}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${cell_index}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${cell_offset}")
        for _ in $(seq 1 48); do value+=(00); done
        bpftool map update id "${normal_runtime_map_id}" \
            key hex "${key[@]}" value hex "${value[@]}" any
        target_cell_offset=${cell_offset}
    }

    write_cell_drain_mask() {
        local cell_index=$1 mask=$2 byte
        local -a key=() value=()

        mapfile -t key < <(u32_bytes "${cell_index}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${mask}")
        for _ in $(seq 1 60); do value+=(00); done
        bpftool map update id "${cell_runtime_map_id}" \
            key hex "${key[@]}" value hex "${value[@]}" any
    }

    write_cpu_route() {
        local cpu=$1 normal_queue_index=$2 map_index valid owner reserved byte
        local -a key=() value=()

        map_index=$((active_slot * 1024 + cpu))
        valid=$(map_field "${cpu_queues_map_id}" "${map_index}" valid)
        owner=$(map_field "${cpu_queues_map_id}" "${map_index}" owner_cell_index)
        reserved=$(map_field "${cpu_queues_map_id}" "${map_index}" reserved)
        ((valid == 1 && owner == alpha_index)) || return 1
        mapfile -t key < <(u32_bytes "${map_index}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${valid}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${owner}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${normal_queue_index}")
        while read -r byte; do value+=("${byte}"); done < <(u32_bytes "${reserved}")
        bpftool map update id "${cpu_queues_map_id}" \
            key hex "${key[@]}" value hex "${value[@]}" any
    }

    cpu_route_is() {
        local cpu=$1 expected=$2 map_index

        map_index=$((active_slot * 1024 + cpu))
        [[ $(map_field "${cpu_queues_map_id}" "${map_index}" normal_queue_index) == \
            "${expected}" ]]
    }

    normal_depth_is() {
        local expected=$1 actual
        actual=$(map_field "${normal_runtime_map_id}" "${target_queue_index}" nr_queued) || return 1
        ((actual == expected))
    }

    stats_sum() {
        local log=$1 kind=$2 field=$3

        python3 - "${log}" "${kind}" "${field}" <<'PY'
import json
import sys

path, kind, field = sys.argv[1:]
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
        if kind == "drain_hits":
            value = record.get("dispatch_rungs", {}).get("0", {}).get("hits", 0)
        else:
            value = record.get(field, 0)
        if isinstance(value, (int, float)):
            total += value
print(int(total))
PY
    }

    drain_hits_gt() {
        local log=$1 baseline=$2 value
        value=$(stats_sum "${log}" drain_hits ignored)
        ((value > baseline))
    }

    monotonic_ms() {
        awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime
    }

    wait_for_stall_kickout() {
        local dmesg_start=$1 output=$2 payload=$3 attempt

        for ((attempt = 0; attempt < 1200; attempt++)); do
            if [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]]; then
                for _ in $(seq 1 20); do
                    dmesg | tail -n +$((dmesg_start + 1)) >"${output}"
                    if grep -Eiq 'runnable task stall' "${output}" &&
                        grep -Eq "python3\\[${payload}\\] failed to run" "${output}"; then
                        return 0
                    fi
                    sleep 0.1
                done
                echo "scheduler detached without a watchdog stall for PID ${payload}" >&2
                return 1
            fi
            sleep 0.1
        done
        echo "timed out after 120 seconds waiting for the injected task stall" >&2
        return 1
    }

    capture_topology() {
        local snapshot=$1
        local -a llcs=()
        local cpu llc

        alpha_id=$(jq -er '.snapshot.cells[] | select(.name == "alpha") | .id' "${snapshot}")
        alpha_index=$(jq -er --argjson id "${alpha_id}" '
            .snapshot.queue_topology.cells[] | select(.external_id == $id) | .index
        ' "${snapshot}")
        alpha_epoch=$(jq -er --argjson id "${alpha_id}" '
            .snapshot.queue_topology.cells[] | select(.external_id == $id) | .slot_epoch
        ' "${snapshot}")
        active_slot=$(jq -er '.snapshot.active_slot' "${snapshot}")
        mapfile -t alpha_cpus < <(jq -r --argjson id "${alpha_id}" '
            .snapshot.queue_topology.cells[] | select(.external_id == $id) | .primary_cpus[]
        ' "${snapshot}")
        ((${#alpha_cpus[@]} >= 2)) || return 1
        mapfile -t llcs < <(
            for cpu in "${alpha_cpus[@]}"; do printf '%s\n' "${cpu_llc[${cpu}]}"; done |
                sort -nu
        )
        ((${#llcs[@]} == 2)) || return 1
        target_llc=${llcs[1]}
        target_cpus=()
        survivor_cpus=()
        for cpu in "${alpha_cpus[@]}"; do
            llc=${cpu_llc[${cpu}]}
            if [[ ${llc} == "${target_llc}" ]]; then
                target_cpus+=("${cpu}")
            else
                survivor_cpus+=("${cpu}")
            fi
        done
        ((${#target_cpus[@]} > 0 && ${#survivor_cpus[@]} > 0)) || return 1
        target_queue_index=$(jq -er --argjson id "${alpha_id}" --argjson llc "${target_llc}" '
            .snapshot.queue_topology.normal_queues[] |
            select(.cell_id == $id and .llc_id == $llc) | .index
        ' "${snapshot}")
        survivor_queue_index=$(jq -er --argjson id "${alpha_id}" \
            --argjson llc "${cpu_llc[${survivor_cpus[0]}]}" '
            .snapshot.queue_topology.normal_queues[] |
            select(.cell_id == $id and .llc_id == $llc) | .index
        ' "${snapshot}")
        control_cpu=$(jq -er '
            .snapshot.queue_topology.cells[] | select(.external_id == 0) | .primary_cpus[0]
        ' "${snapshot}")
        target_source_cpu=${target_cpus[0]}
        survivor_cpu=${survivor_cpus[0]}
        workload_allowed=${online_cpus}
    }

    run_case() {
        local mode=$1
        local log=${runtime_dir}/${mode}.ndjson
        local snapshot=${runtime_dir}/${mode}-topology.json
        local result=${runtime_dir}/${mode}-completions
        local case_result=${runtime_dir}/${mode}-result.json
        local case_dmesg=${runtime_dir}/${mode}-dmesg.txt
        local enable_seq payload_token=${mode}-payload poke_token=${mode}-poke
        local depth_before depth_after drain_before drain_after expected_mask
        local dmesg_start gate_started_ms gate_elapsed_ms injection_ms stall_ms=0 snake_rc=0
        local completed kickout_observed=false
        local cpu invalid accounting

        : >"${log}"
        : >"${result}"
        "${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.05 \
            --stats-format json --exit-dump-len 1048576 >"${log}" 2>&1 &
        snake_pid=$!
        wait_for "Snake attachment" 300 0.02 scheduler_enabled ||
            guest_fail "${mode} scheduler did not attach"
        enable_seq=$(cat /sys/kernel/sched_ext/enable_seq)
        wait_for "Inspector ${mode} attachment" 300 0.02 \
            inspection_ready "${enable_seq}" "${snapshot}" ||
            guest_fail "Inspector did not observe the ${mode} attachment"
        capture_topology "${snapshot}" ||
            guest_fail "${mode} alpha cell did not span both LLCs"

        normal_runtime_map_id=$(bpftool -j map show | jq -er '
            [.[] | select(.name == "normal_queue_ru")] | last | .id
        ') || guest_fail "could not find normal_queue_runtime map"
        cell_runtime_map_id=$(bpftool -j map show | jq -er '
            [.[] | select(.name == "cell_queue_runt")] | last | .id
        ') || guest_fail "could not find cell_queue_runtime map"
        cpu_queues_map_id=$(bpftool -j map show | jq -er '
            [.[] | select(.name == "cpu_queues")] | last | .id
        ') || guest_fail "could not find cpu_queues map"
        normal_depth_is 0 || guest_fail "${mode} target queue did not start empty"
        [[ $(map_field "${cell_runtime_map_id}" "${alpha_index}" llcs_to_drain) == 0 ]] ||
            guest_fail "${mode} alpha drain mask did not start clear"

        taskset -pc "${control_cpu}" "$$" >/dev/null
        taskset -apc "${control_cpu}" "${snake_pid}" >/dev/null ||
            guest_fail "could not pin Snake control plane"
        taskset -apc "${control_cpu}" "${inspector_pid}" >/dev/null ||
            guest_fail "could not pin Inspector control plane"

        start_stopped_worker "${alpha}" "${target_source_cpu}" "${workload_allowed}" \
            "${result}" "${payload_token}" || guest_fail "could not create ${mode} payload"
        payload_pid=${started_pid}
        start_stopped_worker "${alpha}" "${survivor_cpu}" "${workload_allowed}" \
            "${result}" "${poke_token}" || guest_fail "could not create ${mode} poke"
        poke_pid=${started_pid}
        wait_for "${mode} payload membership" 200 0.02 \
            worker_mapped_to_alpha "${payload_pid}" || guest_fail "payload was not mapped to alpha"
        wait_for "${mode} poke membership" 200 0.02 \
            worker_mapped_to_alpha "${poke_pid}" || guest_fail "poke was not mapped to alpha"

        gate_started_ms=$(monotonic_ms)
        for cpu in "${alpha_cpus[@]}"; do
            start_gate "${cpu}" || guest_fail "could not gate alpha CPU ${cpu}"
        done
        drain_before=$(stats_sum "${log}" drain_hits ignored)
        kill -CONT "${payload_pid}"
        wait_for "${mode} payload runnable" 150 0.01 worker_runnable "${payload_pid}" ||
            guest_fail "payload did not become runnable behind the gates"
        wait_for "${mode} target queue depth one" 150 0.01 normal_depth_is 1 ||
            guest_fail "payload did not enter normal queue ${target_queue_index}"
        gate_elapsed_ms=$(( $(monotonic_ms) - gate_started_ms ))
        ((gate_elapsed_ms < 4000)) ||
            guest_fail "queue setup held RT gates for ${gate_elapsed_ms} ms"
        depth_before=$(map_field "${normal_runtime_map_id}" "${target_queue_index}" nr_queued)

        for cpu in "${target_cpus[@]}"; do
            write_cpu_route "${cpu}" "${survivor_queue_index}" ||
                guest_fail "could not redirect CPU ${cpu} away from the target queue"
        done
        write_normal_runtime "${target_queue_index}" 0
        ((target_cell_offset < 31)) || guest_fail "invalid target cell offset ${target_cell_offset}"
        if [[ ${mode} == positive ]]; then
            expected_mask=$((1 << target_cell_offset))
        else
            expected_mask=0
        fi
        write_cell_drain_mask "${alpha_index}" "${expected_mask}"
        [[ $(map_field "${normal_runtime_map_id}" "${target_queue_index}" has_consumers) == 0 ]] ||
            guest_fail "${mode} fault injection did not remove consumers"
        [[ $(map_field "${cell_runtime_map_id}" "${alpha_index}" llcs_to_drain) == "${expected_mask}" ]] ||
            guest_fail "${mode} fault injection did not set drain mask ${expected_mask}"
        for cpu in "${target_cpus[@]}"; do
            cpu_route_is "${cpu}" "${survivor_queue_index}" ||
                guest_fail "${mode} CPU ${cpu} still routes to the orphan queue"
        done
        dmesg_start=$(dmesg | wc -l)
        injection_ms=$(monotonic_ms)

        stop_gates
        kill -CONT "${poke_pid}"
        wait_for "${mode} poke completion" 200 0.01 \
            result_has_token "${result}" "${poke_token}" || guest_fail "poke did not complete"

        if [[ ${mode} == negative ]]; then
            ! result_has_token "${result}" "${payload_token}" ||
                guest_fail "payload completed before the no-drain watchdog window"
            normal_depth_is 1 || guest_fail "orphan queue drained with its drain bit clear"
            wait_for_stall_kickout "${dmesg_start}" "${case_dmesg}" "${payload_pid}" ||
                guest_fail "no-drain case did not kick out on the injected task"
            stall_ms=$(( $(monotonic_ms) - injection_ms ))
            ((stall_ms > 0 && stall_ms <= 120000)) ||
                guest_fail "watchdog kickout took ${stall_ms} ms after injection"
            if wait "${snake_pid}"; then
                snake_rc=0
            else
                snake_rc=$?
            fi
            snake_pid=
            ((snake_rc != 0)) || guest_fail "no-drain Snake exited successfully after its stall"
            drain_after=$(stats_sum "${log}" drain_hits ignored)
            ((drain_after == drain_before)) ||
                guest_fail "drain rung hit with its runtime bit clear"
            depth_after=${depth_before}
            completed=false
            kickout_observed=true
        else
            wait_for "positive payload completion" 300 0.01 \
                result_has_token "${result}" "${payload_token}" ||
                guest_fail "orphan payload did not complete with drain enabled"
            wait_for "positive target queue empty" 200 0.01 normal_depth_is 0 ||
                guest_fail "orphan queue stayed populated with drain enabled"
            wait_for "positive drain rung hit" 200 0.02 \
                drain_hits_gt "${log}" "${drain_before}" ||
                guest_fail "dispatch rung 0 did not report an orphan drain"
            drain_after=$(stats_sum "${log}" drain_hits ignored)
            depth_after=$(map_field "${normal_runtime_map_id}" "${target_queue_index}" nr_queued)
            scheduler_enabled || guest_fail "drain-enabled Snake detached during the proof"
            for cpu in "${target_cpus[@]}"; do
                write_cpu_route "${cpu}" "${target_queue_index}" ||
                    guest_fail "could not restore CPU ${cpu} target queue route"
            done
            write_normal_runtime "${target_queue_index}" 1
            write_cell_drain_mask "${alpha_index}" 0
            completed=true
            kickout_observed=false
        fi

        jq -n \
            --arg mode "${mode}" \
            --argjson completed "${completed}" \
            --argjson kickout_observed "${kickout_observed}" \
            --argjson queue_index "${target_queue_index}" \
            --argjson cell_offset "${target_cell_offset}" \
            --argjson depth_before "${depth_before}" \
            --argjson depth_after "${depth_after}" \
            --argjson stall_ms "${stall_ms}" \
            --argjson drain_hits_delta "$((drain_after - drain_before))" \
            '{mode:$mode, completed:$completed, kickout_observed:$kickout_observed,
              queue_index:$queue_index,
              cell_offset:$cell_offset, depth_before:$depth_before,
              depth_after:$depth_after, stall_ms:$stall_ms,
              drain_hits_delta:$drain_hits_delta}' \
            >"${case_result}"

        stop_workers
        stop_gates
        stop_snake || guest_fail "${mode} scheduler did not detach"
        dmesg | tail -n +$((dmesg_start + 1)) >"${case_dmesg}"
        if [[ ${mode} == positive ]] && grep -Eiq \
            'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)' \
            "${case_dmesg}"; then
            guest_fail "drain-enabled case produced a sched_ext failure"
        fi
        invalid=$(stats_sum "${log}" global invalid_errors)
        accounting=$(stats_sum "${log}" global vtime_accounting_errors)
        ((invalid == 0 && accounting == 0)) ||
            guest_fail "${mode} correctness counters are nonzero: invalid=${invalid} accounting=${accounting}"
    }

    ((EUID == 0)) || fail "guest mode requires root"
    inside_vm || fail "guest mode refuses to run outside a VM"
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
        fail "guest sched_ext must be disabled"
    [[ $(nproc) == 12 ]] || fail "guest must expose exactly 12 CPUs"
    [[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
    [[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
    for command in bpftool chrt curl jq python3 taskset; do
        command -v "${command}" >/dev/null || fail "${command} is required"
    done
    [[ ! -e ${parent} ]] || fail "orphan-drain cgroup fixture already exists"

    dmesg_lines=$(dmesg | wc -l)
    mkdir -p "${runtime_dir}"
    online_cpus=$(cat /sys/devices/system/cpu/online)
    mapfile -t online_cpu_ids < <(seq 0 11)
    declare -A observed_llcs=()
    for cpu in "${online_cpu_ids[@]}"; do
        cache_id_file=/sys/devices/system/cpu/cpu${cpu}/cache/index3/id
        [[ -r ${cache_id_file} ]] || fail "CPU ${cpu} has no LLC identity"
        cpu_llc[${cpu}]=$(<"${cache_id_file}")
        observed_llcs[${cpu_llc[${cpu}]}]=1
    done
    ((${#observed_llcs[@]} == 2)) || fail "guest must expose exactly two LLCs"
    for llc in "${!observed_llcs[@]}"; do
        count=0
        for cpu in "${online_cpu_ids[@]}"; do
            [[ ${cpu_llc[${cpu}]} == "${llc}" ]] && count=$((count + 1))
        done
        ((count == 6)) || fail "LLC ${llc} has ${count} CPUs; expected six"
    done

    grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
        fail "guest cgroup root does not provide cpuset"
    grep -qw cpuset "${cgroup_root}/cgroup.subtree_control" ||
        printf '%s\n' +cpuset >"${cgroup_root}/cgroup.subtree_control"
    cpuset_mems=$(<"${cgroup_root}/cpuset.mems.effective")
    [[ -n ${cpuset_mems} ]] || fail "guest has no effective NUMA nodes"
    mkdir "${parent}"
    fixture_created=1
    printf '%s\n' "${cpuset_mems}" >"${parent}/cpuset.mems"
    printf '%s\n' "${online_cpus}" >"${parent}/cpuset.cpus"
    printf '%s\n' +cpuset >"${parent}/cgroup.subtree_control"
    mkdir "${alpha}" "${beta}"
    printf '%s\n' "${cpuset_mems}" >"${alpha}/cpuset.mems"
    printf '%s\n' "${cpuset_mems}" >"${beta}/cpuset.mems"

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

    if curl -fsS --max-time 0.2 "${base_url}/api/scheduler/control" >/dev/null 2>&1; then
        fail "Inspector address ${guest_listen} is already serving an API"
    fi
    "${inspector_bin}" --listen "${guest_listen}" --snake-bin "${snake_bin}" \
        --policy-dir "${runtime_dir}" >"${inspector_log}" 2>&1 &
    inspector_pid=$!
    wait_for "Inspector API" 200 0.05 inspector_ready || fail "Inspector API did not start"

    run_case negative
    run_case positive

    stop_pid "${inspector_pid}" INT
    inspector_pid=
    dmesg | tail -n +$((dmesg_lines + 1)) >"${run_dir}/dmesg-new.txt"
    if grep -Eiv 'runnable task stall' "${run_dir}/dmesg-new.txt" | grep -Eiq \
        'scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
        fail "kernel log contains a failure other than the expected no-drain stall"
    fi
    rmdir "${alpha}" "${beta}" "${parent}" || fail "cgroup fixture remained populated"
    fixture_created=0

    jq -n \
        --arg kernel "$(uname -r)" \
        --argjson llc_count "${#observed_llcs[@]}" \
        --slurpfile negative "${runtime_dir}/negative-result.json" \
        --slurpfile positive "${runtime_dir}/positive-result.json" \
        '{status:"passed", kernel:$kernel,
          topology:{cpus:12,llc_count:$llc_count,cpus_per_llc:6},
          negative:$negative[0], positive:$positive[0]}' >"${run_dir}/result.json"
    echo "PASS: orphan queue stayed stranded without drain and completed with drain"
}

if [[ ${1:-} == --guest ]]; then
    (($# == 5)) || { usage; exit 2; }
    run_guest "$2" "$3" "$4" "$5"
elif (($# <= 3)); then
    run_host "$@"
else
    usage
    exit 2
fi
