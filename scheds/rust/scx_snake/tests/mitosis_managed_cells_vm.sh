#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
vng=${VNG:-vng}
guest_cpus=${SNAKE_TESTING_GUEST_CPUS:-8}
guest_memory=${SNAKE_TESTING_GUEST_MEMORY:-4G}
duration_secs=${SNAKE_MANAGED_CELLS_DURATION_SECS:-20}
dry_run=${SNAKE_TESTING_DRY_RUN:-0}
listen=${SNAKE_MANAGED_CELLS_LISTEN:-127.0.0.1:18789}

fail() {
    echo "Mitosis managed-workload cells: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
Usage:
  mitosis_managed_cells_vm.sh [RUN_DIR] [SNAKE_BIN] [INSPECTOR_BIN]
  mitosis_managed_cells_vm.sh --guest RUN_DIR SNAKE_BIN INSPECTOR_BIN POLICY_DIR DURATION LISTEN

Host mode snapshots the inputs and launches one virtme guest. Guest mode creates
four managed workload cgroups, runs one matrix workload in each, and verifies
that Snake exposes four live managed cells through Inspector.
EOF
}

inside_vm() {
    if command -v systemd-detect-virt >/dev/null; then
        systemd-detect-virt --vm --quiet
    else
        grep -qw hypervisor /proc/cpuinfo
    fi
}

wait_for() {
    local description=$1 attempts=$2 delay=$3
    shift 3
    local attempt

    for ((attempt = 0; attempt < attempts; attempt++)); do
        if "$@"; then
            return 0
        fi
        sleep "${delay}"
    done
    fail "timed out waiting for ${description}"
}

pid_done() {
    local pid=$1 state

    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

stop_group() {
    local pid=$1 signal=${2:-TERM} attempt

    [[ -n ${pid} ]] || return 0
    kill "-${signal}" -- "-${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 30; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
        fi
        ! kill -0 -- "-${pid}" 2>/dev/null && return 0
        sleep 0.1
    done
    kill -KILL -- "-${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 10; attempt++)); do
        ! kill -0 -- "-${pid}" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

run_host() {
    local run_dir=${1:-/tmp/scx-snake-testing/mitosis-managed-cells-$(date +%Y%m%d-%H%M%S)}
    local snake_bin=${2:-${repo}/target/release/scx_snake}
    local inspector_bin=${3:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
    local source_policy=${repo}/scheds/rust/scx_snake/examples/mitosis-sim.toml
    local input_dir snapshot_script snapshot_snake snapshot_inspector policy_dir guest_script
    local vm_timeout_secs
    local -a guest_command vm_command

    inside_vm && fail "host mode must run outside a VM"
    command -v "${vng}" >/dev/null || fail "virtme-ng is required (set VNG to override)"
    command -v jq >/dev/null || fail "jq is required"
    command -v timeout >/dev/null || fail "timeout is required"
    [[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
    [[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
    [[ -f ${source_policy} ]] || fail "Mitosis policy does not exist: ${source_policy}"
    if [[ ! ${guest_cpus} =~ ^[0-9]+$ ]] || ((guest_cpus < 8)); then
        fail "SNAKE_TESTING_GUEST_CPUS must be at least 8"
    fi
    [[ -n ${guest_memory} ]] || fail "SNAKE_TESTING_GUEST_MEMORY must not be empty"
    [[ ${duration_secs} =~ ^[1-9][0-9]*$ ]] ||
        fail "SNAKE_MANAGED_CELLS_DURATION_SECS must be positive"
    [[ ${dry_run} == 0 || ${dry_run} == 1 ]] ||
        fail "SNAKE_TESTING_DRY_RUN must be 0 or 1"

    run_dir=$(realpath -m "${run_dir}")
    input_dir=${run_dir}/inputs
    snapshot_script=${input_dir}/mitosis_managed_cells_vm.sh
    snapshot_snake=${input_dir}/scx_snake
    snapshot_inspector=${input_dir}/scx_snake_inspector
    policy_dir=${input_dir}/policies
    guest_script=${run_dir}/guest.sh
    guest_command=(
        "${snapshot_script}" --guest "${run_dir}" "${snapshot_snake}"
        "${snapshot_inspector}" "${policy_dir}" "${duration_secs}" "${listen}"
    )
    vm_command=(
        "${vng}" --run
        --name snake-mitosis-managed-cells
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
    mkdir -p "${policy_dir}"
    cp "$0" "${snapshot_script}"
    cp "${snake_bin}" "${snapshot_snake}"
    cp "${inspector_bin}" "${snapshot_inspector}"
    cp "${source_policy}" "${policy_dir}/mitosis-sim.toml"
    chmod 0555 "${snapshot_script}" "${snapshot_snake}" "${snapshot_inspector}"
    chmod -R a-w "${input_dir}"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'exec '
        printf '%q ' "${guest_command[@]}"
        printf '\n'
    } >"${guest_script}"
    chmod 0555 "${guest_script}"

    vm_timeout_secs=$((duration_secs + 150))
    if ! timeout --signal=TERM --kill-after=30s "${vm_timeout_secs}s" \
        "${vm_command[@]}" >"${run_dir}/vm.log" 2>&1; then
        tail -n 200 "${run_dir}/vm.log" >&2 || true
        fail "virtme guest failed"
    fi
    [[ -s ${run_dir}/result.json ]] || fail "guest produced no result.json"
    jq -e '.status == "passed" and (.cells | length) == 4' \
        "${run_dir}/result.json" >/dev/null || fail "guest result did not pass"
    echo "PASS: managed-workload cell artifact: ${run_dir}"
}

run_guest() {
    local run_dir=$1 snake_bin=$2 inspector_bin=$3 policy_dir=$4
    local duration=$5 guest_listen=$6
    local base_url=http://${guest_listen}
    local cgroup_root=/sys/fs/cgroup
    local workload_slice=${cgroup_root}/workload.slice
    local managed_parent=${workload_slice}/workload-tw.slice
    local all_test_cpus=0-7
    local mems token snake_pid='' inspector_pid='' dmesg_lines fixture_created=0
    local active_inspection=${run_dir}/inspection-active.json
    local -a cell_names=(cpu-saturation waker-wakee mixed-affinity fork-yield)
    local -a cell_cpus=(0-1 2-3 4-5 6-7)
    local -a workload_pids=()
    local index pid

    ((EUID == 0)) || fail "guest mode requires root"
    inside_vm || fail "guest mode refuses to run outside a VM"
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
        fail "guest sched_ext must be disabled"
    (( $(nproc) >= 8 )) || fail "guest must expose at least 8 CPUs"
    [[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
    [[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
    [[ -f ${policy_dir}/mitosis-sim.toml ]] || fail "Mitosis policy is missing"
    [[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be positive"
    for command in awk curl jq setsid stress-ng taskset; do
        command -v "${command}" >/dev/null || fail "${command} is required"
    done
    for index in {0..7}; do
        [[ -d /sys/devices/system/cpu/cpu${index} ]] ||
            fail "guest CPU ${index} is not online"
    done
    [[ ! -e ${workload_slice} ]] || fail "managed workload fixture already exists"

    dmesg_lines=$(dmesg | wc -l)
    mkdir -p "${run_dir}/workloads"

    remove_fixture() {
        local remove_rc=0

        for index in "${!cell_names[@]}"; do
            if [[ -e ${managed_parent}/${cell_names[index]} ]] &&
                ! rmdir "${managed_parent}/${cell_names[index]}"; then
                remove_rc=1
            fi
        done
        if [[ -e ${managed_parent} ]] && ! rmdir "${managed_parent}"; then
            remove_rc=1
        fi
        if [[ -e ${workload_slice} ]] && ! rmdir "${workload_slice}"; then
            remove_rc=1
        fi
        return "${remove_rc}"
    }

    cleanup() {
        local cleanup_pid

        trap - EXIT INT TERM
        set +e
        for cleanup_pid in "${workload_pids[@]}"; do
            kill -TERM -- "-${cleanup_pid}" 2>/dev/null
        done
        for cleanup_pid in "${workload_pids[@]}"; do
            stop_group "${cleanup_pid}" || true
        done
        if [[ -n ${inspector_pid} ]]; then
            curl -fsS "${base_url}/api/inspection" \
                >"${run_dir}/inspection-cleanup.json" 2>/dev/null
            kill -INT "${inspector_pid}" 2>/dev/null
            wait "${inspector_pid}" 2>/dev/null
        fi
        if [[ -n ${snake_pid} ]]; then
            kill -INT "${snake_pid}" 2>/dev/null
            wait "${snake_pid}" 2>/dev/null
        fi
        ((fixture_created == 0)) || remove_fixture 2>/dev/null || true
        dmesg | tail -n +$((dmesg_lines + 1)) >"${run_dir}/dmesg-cleanup.txt" 2>/dev/null
    }
    trap cleanup EXIT INT TERM

    inspection_has_four_live_cells() {
        local temporary=${active_inspection}.tmp

        curl -fsS "${base_url}/api/inspection" >"${temporary}" || return 1
        mv "${temporary}" "${active_inspection}"
        jq -e '
            (.snapshot.cells // []) as $cells |
            ([ $cells[] | select(.source == "managed") ] | length) == 4 and
            any($cells[]; .name == "cpu-saturation" and .cpus == [0, 1] and .task_count > 0) and
            any($cells[]; .name == "waker-wakee" and .cpus == [2, 3] and .task_count > 0) and
            any($cells[]; .name == "mixed-affinity" and .cpus == [4, 5] and .task_count > 0) and
            any($cells[]; .name == "fork-yield" and .cpus == [6, 7] and .task_count > 0)
        ' "${active_inspection}" >/dev/null
    }

    inspection_has_four_cells() {
        local destination=${run_dir}/inspection-discovered.json
        local temporary=${destination}.tmp

        curl -fsS "${base_url}/api/inspection" >"${temporary}" || return 1
        mv "${temporary}" "${destination}"
        jq -e '
            (.snapshot.cells // []) as $cells |
            ([ $cells[] | select(.source == "managed") ] | length) == 4 and
            any($cells[]; .name == "cpu-saturation" and .cpus == [0, 1]) and
            any($cells[]; .name == "waker-wakee" and .cpus == [2, 3]) and
            any($cells[]; .name == "mixed-affinity" and .cpus == [4, 5]) and
            any($cells[]; .name == "fork-yield" and .cpus == [6, 7])
        ' "${destination}" >/dev/null
    }

    inspection_has_no_managed_cells() {
        local destination=${run_dir}/inspection-empty.json
        local temporary=${destination}.tmp

        curl -fsS "${base_url}/api/inspection" >"${temporary}" || return 1
        mv "${temporary}" "${destination}"
        jq -e '[.snapshot.cells[]? | select(.source == "managed")] | length == 0' \
            "${destination}" >/dev/null
    }

    scheduler_active() {
        curl -fsS "${base_url}/api/scheduler/control" 2>/dev/null |
            jq -e '.active == true and .last_exit == null' >/dev/null
    }

    scheduler_stopped() {
        [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] &&
            curl -fsS "${base_url}/api/scheduler/control" 2>/dev/null |
                jq -e '.active == false' >/dev/null
    }

    workloads_done() {
        local workload_pid

        for workload_pid in "${workload_pids[@]}"; do
            pid_done "${workload_pid}" || return 1
        done
        return 0
    }

    launch_workload() {
        local name=$1 cgroup=$2 minimum_duration
        shift 2

        minimum_duration=$((duration > 1 ? duration - 1 : duration))

        # shellcheck disable=SC2016
        setsid bash -c '
            cgroup=$1
            minimum_duration=$2
            shift 2
            echo $$ >"${cgroup}/cgroup.procs"
            started=$SECONDS
            "$@"
            rc=$?
            elapsed=$((SECONDS - started))
            ((rc == 0)) || exit "${rc}"
            if ((elapsed < minimum_duration)); then
                echo "workload exited after ${elapsed}s; expected at least ${minimum_duration}s" >&2
                exit 124
            fi
        ' _ "${cgroup}" "${minimum_duration}" "$@" \
            >"${run_dir}/workloads/${name}.log" 2>&1 &
        workload_pids+=("$!")
    }

    grep -qw cpuset "${cgroup_root}/cgroup.controllers" ||
        fail "guest cgroup root does not provide the cpuset controller"
    if ! grep -qw cpuset "${cgroup_root}/cgroup.subtree_control"; then
        echo +cpuset >"${cgroup_root}/cgroup.subtree_control"
    fi
    mems=$(<"${cgroup_root}/cpuset.mems.effective")
    [[ -n ${mems} ]] || fail "guest has no effective NUMA memory nodes"

    mkdir "${workload_slice}"
    fixture_created=1
    echo "${mems}" >"${workload_slice}/cpuset.mems"
    echo "${all_test_cpus}" >"${workload_slice}/cpuset.cpus"
    echo +cpuset >"${workload_slice}/cgroup.subtree_control"
    mkdir "${managed_parent}"
    echo "${mems}" >"${managed_parent}/cpuset.mems"
    echo "${all_test_cpus}" >"${managed_parent}/cpuset.cpus"
    echo +cpuset >"${managed_parent}/cgroup.subtree_control"

    "${inspector_bin}" \
        --listen "${guest_listen}" \
        --snake-bin "${snake_bin}" \
        --policy-dir "${policy_dir}" \
        >"${run_dir}/inspector.log" 2>&1 &
    inspector_pid=$!
    wait_for "Inspector API" 150 0.1 curl -fsS "${base_url}/api/scheduler/control"
    token=$(curl -fsS "${base_url}/" |
        sed -n 's/.*name="snake-session-token" content="\([^"]*\)".*/\1/p')
    [[ -n ${token} ]] || fail "could not read Inspector session token"

    curl -fsS -X POST "${base_url}/api/scheduler/start" \
        -H 'content-type: application/json' \
        -H "x-snake-token: ${token}" \
        --data '{"policy_id":"mitosis-sim.toml","fairness":"vtime","callback_timing_sample_rate":64,"exit_dump_len":1048576,"verbose":false}' \
        >"${run_dir}/scheduler-start.json"
    wait_for "Snake attachment" 150 0.1 scheduler_active
    snake_pid=$(curl -fsS "${base_url}/api/scheduler/control" | jq -r '.pid // empty')
    wait_for "empty managed-cell topology" 100 0.1 inspection_has_no_managed_cells

    for index in "${!cell_names[@]}"; do
        mkdir "${managed_parent}/${cell_names[index]}"
        echo "${mems}" >"${managed_parent}/${cell_names[index]}/cpuset.mems"
        echo "${cell_cpus[index]}" >"${managed_parent}/${cell_names[index]}/cpuset.cpus"
    done
    wait_for "four managed workload cells" 200 0.1 inspection_has_four_cells

    launch_workload cpu-saturation "${managed_parent}/cpu-saturation" \
        stress-ng --cpu 4 --cpu-method loop --aggressive \
        --timeout "${duration}s" --metrics-brief
    launch_workload waker-wakee "${managed_parent}/waker-wakee" \
        stress-ng --switch 2 --switch-method pipe --aggressive \
        --timeout "${duration}s" --metrics-brief
    # shellcheck disable=SC2016
    launch_workload mixed-affinity "${managed_parent}/mixed-affinity" \
        bash -c '
            taskset -c 4 stress-ng --cpu 2 --cpu-method loop --aggressive \
                --timeout "$1" --metrics-brief &
            narrow=$!
            taskset -c 4-5 stress-ng --cpu 2 --cpu-method loop --aggressive \
                --timeout "$1" --metrics-brief &
            wide=$!
            wait "$narrow" "$wide"
        ' _ "${duration}s"
    launch_workload fork-yield "${managed_parent}/fork-yield" \
        stress-ng --fork 1 --yield 2 --yield-procs 4 --aggressive \
        --timeout "${duration}s" --metrics-brief

    wait_for "four populated managed workload cells" 150 0.1 inspection_has_four_live_cells
    for pid in "${workload_pids[@]}"; do
        pid_done "${pid}" && fail "workload ${pid} exited before inspection"
    done

    for ((index = 0; index < (duration + 20) * 10; index++)); do
        scheduler_active || fail "Snake exited while workloads were running"
        workloads_done && break
        sleep 0.1
    done
    workloads_done || fail "workloads exceeded their completion deadline"
    for index in "${!workload_pids[@]}"; do
        pid=${workload_pids[index]}
        if ! wait "${pid}"; then
            fail "${cell_names[index]} workload exited unsuccessfully"
        fi
    done
    workload_pids=()

    curl -fsS "${base_url}/api/inspection" >"${run_dir}/inspection-final.json"
    curl -fsS "${base_url}/api/scheduler/control" >"${run_dir}/scheduler-control.json"
    jq -e '.active == true and .last_exit == null' \
        "${run_dir}/scheduler-control.json" >/dev/null || fail "Snake was not active after workloads"
    jq -e '
        [ .snapshot.cells[] | select(.source == "managed") | .name ] | sort ==
        ["cpu-saturation", "fork-yield", "mixed-affinity", "waker-wakee"]
    ' "${run_dir}/inspection-final.json" >/dev/null || fail "managed cells disappeared"
    jq -e '
        .snapshot.slots[] | select(.state == "active") | .metrics |
        .invalid_errors == 0 and .vtime_accounting_errors == 0 and
        .membership_invalid_runs == 0
    ' "${run_dir}/inspection-final.json" >/dev/null || fail "Snake reported correctness errors"

    curl -fsS -X POST "${base_url}/api/scheduler/stop" \
        -H 'content-type: application/json' \
        -H "x-snake-token: ${token}" \
        --data '{}' >"${run_dir}/scheduler-stop.json"
    wait_for "Snake detachment" 100 0.1 scheduler_stopped
    curl -fsS "${base_url}/api/scheduler/control" \
        >"${run_dir}/scheduler-control-stopped.json"
    snake_pid=
    kill -INT "${inspector_pid}" 2>/dev/null || true
    wait "${inspector_pid}" 2>/dev/null || true
    inspector_pid=

    dmesg | tail -n +$((dmesg_lines + 1)) >"${run_dir}/dmesg-new.txt"
    if grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic' \
        "${run_dir}/dmesg-new.txt"; then
        fail "kernel log contains a scheduler or kernel failure signature"
    fi
    remove_fixture || fail "managed workload cgroups remained populated after teardown"
    fixture_created=0

    jq -n \
        --arg kernel "$(uname -r)" \
        --argjson duration_secs "${duration}" \
        --slurpfile inspection "${active_inspection}" '
        {
          status: "passed",
          kernel: $kernel,
          duration_secs: $duration_secs,
          workloads: ["cpu_saturation", "waker_wakee", "mixed_affinity", "fork_yield"],
          cells: [
            $inspection[0].snapshot.cells[] |
            select(.source == "managed") |
            {id, name, cpus, task_count, slot_epoch}
          ]
        }
    ' >"${run_dir}/result.json"

    echo "PASS: four managed workload cgroups produced four Snake cells"
}

if [[ ${1:-} == --guest ]]; then
    (($# == 7)) || { usage; exit 2; }
    run_guest "$2" "$3" "$4" "$5" "$6" "$7"
elif (($# <= 3)); then
    run_host "$@"
else
    usage
    exit 2
fi
