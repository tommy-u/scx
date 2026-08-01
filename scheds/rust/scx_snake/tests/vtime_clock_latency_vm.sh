#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
sample_rate=${SNAKE_CLOCK_SAMPLE_RATE:-256}
warmup_secs=${SNAKE_CLOCK_WARMUP_SECS:-5}
measure_secs=${SNAKE_CLOCK_MEASURE_SECS:-20}
cpu_workers=${SNAKE_CLOCK_CPU_WORKERS:-4}
switch_workers=${SNAKE_CLOCK_SWITCH_WORKERS:-4}
pipe_workers=${SNAKE_CLOCK_PIPE_WORKERS:-4}
workload_cpus=4-7,12-15
workload_cpus_json='[4,5,6,7,12,13,14,15]'
listen=${SNAKE_CLOCK_LISTEN:-127.0.0.1:18787}
pin_cpus=${SNAKE_VM_PIN_CPUS:-32-39,48-55}

fail() {
    echo "VTIME clock latency: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  vtime_clock_latency_vm.sh LABEL ARTIFACT_ROOT [SNAKE_BIN] [INSPECTOR_BIN]
  vtime_clock_latency_vm.sh --guest LABEL RUN_DIR SNAKE_BIN INSPECTOR_BIN

The host mode snapshots both binaries and launches a 16-vCPU, two-LLC vng
guest. The guest mode runs one fixed wakeup-heavy capture and writes raw JSON
and a per-variant Markdown summary beneath RUN_DIR.
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

run_host() {
    local label=$1 artifact_root=$2
    local snake_bin=${3:-${repo}/target/release/scx_snake}
    local inspector_bin=${4:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
    local source_id=${SNAKE_CLOCK_SOURCE_ID:-unattributed}
    local run_dir=${artifact_root}/${label}
    local input_dir=${run_dir}/inputs
    local snapshot_script=${input_dir}/vtime_clock_latency_vm.sh
    local snapshot_snake=${input_dir}/scx_snake
    local snapshot_inspector=${input_dir}/scx_snake_inspector
    local guest_command host_state_before host_state_after

    inside_vm && fail "host mode must run outside a VM"
    command -v jq >/dev/null || fail "jq is required"
    command -v pgrep >/dev/null || fail "pgrep is required"
    command -v taskset >/dev/null || fail "taskset is required"
    command -v timeout >/dev/null || fail "timeout is required"
    command -v vng >/dev/null || fail "vng is required"
    [[ -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is not usable"
    [[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
    [[ -x ${inspector_bin} ]] || fail "Inspector binary is not executable: ${inspector_bin}"
    [[ ! -e ${run_dir} ]] || fail "run directory already exists: ${run_dir}"
    ! pgrep -f '[q]emu-system-x86_64.*-fsdev.*virtfs' >/dev/null ||
        fail "another virtme/QEMU guest is running; benchmark isolation is required"

    mkdir -p "${input_dir}"
    cp "${snake_bin}" "${snapshot_snake}"
    cp "${inspector_bin}" "${snapshot_inspector}"
    cp "$0" "${snapshot_script}"
    chmod a+rx "${snapshot_script}" "${snapshot_snake}" "${snapshot_inspector}"
    sha256sum "${snapshot_snake}" "${snapshot_inspector}" >"${run_dir}/binary-sha256.txt"
    jq -n \
        --arg source_id "${source_id}" \
        --arg snake_source_path "$(readlink -f "${snake_bin}")" \
        --arg inspector_source_path "$(readlink -f "${inspector_bin}")" \
        --arg note "repo state describes the harness invocation; binary hashes identify supplied artifacts" \
        '{source_id: $source_id, snake_source_path: $snake_source_path, inspector_source_path: $inspector_source_path, note: $note}' \
        >"${run_dir}/binary-provenance.json"
    git -C "${repo}" rev-parse HEAD >"${run_dir}/git-head.txt"
    git -C "${repo}" status --short >"${run_dir}/git-status.txt"
    git -C "${repo}" diff --binary >"${run_dir}/working-tree.patch"

    host_state_before=$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)
    printf '%s\n' "${host_state_before}" >"${run_dir}/host-sched-ext-before.txt"
    ps -eo pid,user,args | grep '[s]cx_snake' >"${run_dir}/host-snake-processes-before.txt" || true

    printf -v guest_command '%q --guest %q %q %q %q' \
        "${snapshot_script}" "${label}" "${run_dir}" \
        "${snapshot_snake}" "${snapshot_inspector}"
    timeout --signal=TERM --kill-after=15s 180s \
        taskset -c "${pin_cpus}" \
        vng --run "/boot/vmlinuz-$(uname -r)" \
        --name "snake-vtime-clock-${label}" \
        --cpus '16,sockets=2,cores=8,threads=1' \
        --memory 4G \
        --user root \
        --rwdir "${run_dir}" \
        --exec "${guest_command}" \
        >"${run_dir}/vm.log" 2>&1

    host_state_after=$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)
    printf '%s\n' "${host_state_after}" >"${run_dir}/host-sched-ext-after.txt"
    ps -eo pid,user,args | grep '[s]cx_snake' >"${run_dir}/host-snake-processes-after.txt" || true
    [[ ${host_state_before} == "${host_state_after}" ]] ||
        fail "host sched_ext state changed from ${host_state_before} to ${host_state_after}"
    [[ -s ${run_dir}/result.json ]] || fail "guest produced no result.json"
    [[ -s ${run_dir}/summary.md ]] || fail "guest produced no summary.md"
    echo "VTIME clock latency artifact: ${run_dir}"
}

run_guest() {
    local label=$1 run_dir=$2 snake_bin=$3 inspector_bin=$4
    local tmpdir policy cgroup_root workload_cgroup base_url token
    local snake_pid= inspector_pid= workload_pid= dmesg_lines
    local callback stage_count llc_count freeze_ns

    ((EUID == 0)) || fail "guest mode requires root"
    inside_vm || fail "guest mode refuses to run outside a VM"
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
        fail "guest sched_ext must be disabled"
    [[ $(nproc) == 16 ]] || fail "guest must expose exactly 16 CPUs"
    for command in curl jq stress-ng taskset sha256sum; do
        command -v "${command}" >/dev/null || fail "${command} is required"
    done
    ((cpu_workers > 0 && switch_workers > 0 && pipe_workers > 0)) ||
        fail "all stress-ng worker counts must be positive"

    tmpdir=$(mktemp -d /tmp/scx-snake-vtime-clock.XXXXXX)
    policy=${run_dir}/policy.toml
    cgroup_root=/sys/fs/cgroup/scx-snake-vtime-clock
    workload_cgroup=${cgroup_root}/workload
    base_url=http://${listen}
    dmesg_lines=$(dmesg | wc -l)

    cleanup() {
        set +e
        if [[ -n ${inspector_pid} ]]; then
            curl -sS "${base_url}/api/scheduler/control" \
                >"${run_dir}/failure-scheduler-control.json" 2>/dev/null
            curl -sS "${base_url}/api/inspection" \
                >"${run_dir}/failure-inspection.json" 2>/dev/null
            curl -sS "${base_url}/api/fine-timing" \
                >"${run_dir}/failure-fine-timing.json" 2>/dev/null
        fi
        [[ -n ${workload_pid} ]] && kill -CONT -- "-${workload_pid}" 2>/dev/null
        [[ -n ${workload_pid} ]] && kill -TERM -- "-${workload_pid}" 2>/dev/null
        [[ -n ${inspector_pid} ]] && kill -INT "${inspector_pid}" 2>/dev/null
        [[ -n ${snake_pid} ]] && kill -INT "${snake_pid}" 2>/dev/null
        [[ -n ${workload_pid} ]] && wait "${workload_pid}" 2>/dev/null
        [[ -n ${inspector_pid} ]] && wait "${inspector_pid}" 2>/dev/null
        [[ -n ${snake_pid} ]] && wait "${snake_pid}" 2>/dev/null
        rmdir "${workload_cgroup}" "${cgroup_root}" 2>/dev/null
        dmesg | tail -n +$((dmesg_lines + 1)) >"${run_dir}/dmesg-new.txt" 2>/dev/null
        rm -rf "${tmpdir}"
    }
    trap cleanup EXIT INT TERM

    lscpu -e=CPU,CORE,SOCKET,NODE,CACHE >"${run_dir}/guest-topology.txt"
    uname -a >"${run_dir}/guest-uname.txt"
    llc_count=$(find /sys/devices/system/cpu/cpu*/cache/index3 -name id -type f \
        -exec cat {} + | sort -nu | wc -l)
    [[ ${llc_count} == 2 ]] || fail "guest must expose two LLCs, found ${llc_count}"
    [[ $(cat /sys/devices/system/cpu/cpu0/cache/index3/id) == 0 ]] ||
        fail "guest CPU 0 must be in LLC 0"
    [[ $(cat /sys/devices/system/cpu/cpu8/cache/index3/id) == 1 ]] ||
        fail "guest CPU 8 must be in LLC 1"

    grep -qw cpuset /sys/fs/cgroup/cgroup.controllers ||
        fail "guest cgroup root does not provide the cpuset controller"
    echo +cpuset >/sys/fs/cgroup/cgroup.subtree_control
    mkdir "${cgroup_root}"
    echo 0 >"${cgroup_root}/cpuset.mems"
    echo 0-15 >"${cgroup_root}/cpuset.cpus"
    echo +cpuset >"${cgroup_root}/cgroup.subtree_control"
    mkdir "${workload_cgroup}"
    echo 0 >"${workload_cgroup}/cpuset.mems"
    echo "${workload_cpus}" >"${workload_cgroup}/cpuset.cpus"

    cat >"${policy}" <<'EOF'
fallback = "previous_cpu"

[managed_cells]
parent = "/scx-snake-vtime-clock"
max_children = 4
reconcile_ms = 50

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
  { action = "peek", source = "cell" },
  { action = "peek", source = "cpu" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu", "cell_sibling"] },
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

    taskset -c 0-3,8-11 "${inspector_bin}" \
        --listen "${listen}" \
        --snake-bin "${snake_bin}" \
        --policy-dir "${run_dir}" \
        >"${run_dir}/inspector.log" 2>&1 &
    inspector_pid=$!
    wait_for "Inspector API" 100 0.1 curl -fsS "${base_url}/api/scheduler/control"
    token=$(curl -fsS "${base_url}/" |
        sed -n 's/.*name="snake-session-token" content="\([^"]*\)".*/\1/p')
    [[ -n ${token} ]] || fail "could not read Inspector session token"

    curl -fsS -X POST "${base_url}/api/scheduler/start" \
        -H 'content-type: application/json' \
        -H "x-snake-token: ${token}" \
        --data "{\"policy_id\":\"policy.toml\",\"fairness\":\"vtime\",\"callback_timing_sample_rate\":${sample_rate},\"exit_dump_len\":1048576,\"verbose\":false}" \
        >"${run_dir}/scheduler-start.json"
    wait_for "Snake attachment" 150 0.1 sh -c \
        "curl -fsS '${base_url}/api/scheduler/control' | jq -e '.active == true' >/dev/null"
    snake_pid=$(curl -fsS "${base_url}/api/scheduler/control" | jq -r '.pid // empty')

    setsid bash -c '
        echo $$ >"$1/cgroup.procs"
        exec taskset -c "$6" stress-ng \
            --cpu "$3" --cpu-method loop \
            --switch "$4" --switch-method pipe \
            --pipe "$5" --aggressive \
            --timeout 40s --metrics-brief --yaml "$2"
    ' _ "${workload_cgroup}" "${run_dir}/stress.yaml" \
        "${cpu_workers}" "${switch_workers}" "${pipe_workers}" \
        "${workload_cpus}" \
        >"${run_dir}/workload.log" 2>&1 &
    workload_pid=$!
    wait_for "managed workload cell" 100 0.1 sh -c \
        "curl -fsS '${base_url}/api/inspection' | jq -e '.snapshot.cells? // [] | any(.name == \"workload\" and .task_count > 0 and .cpus == ${workload_cpus_json})' >/dev/null"
    sleep "${warmup_secs}"
    kill -0 "${workload_pid}" 2>/dev/null || fail "workload exited during warmup"

    for callback in select_cpu enqueue runnable running; do
        curl -fsS -X POST "${base_url}/api/fine-timing" \
            -H 'content-type: application/json' \
            -H "x-snake-token: ${token}" \
            --data "{\"callback\":\"${callback}\",\"enabled\":true}" \
            >"${run_dir}/fine-start-${callback}.json"
    done
    curl -fsS -X POST "${base_url}/api/stats/reset" \
        -H "x-snake-token: ${token}" >"${run_dir}/stats-reset.json"
    printf '%s\n' "$(date +%s%N)" >"${run_dir}/measurement-start-ns.txt"
    sleep "${measure_secs}"
    kill -STOP -- "-${workload_pid}"
    printf '%s\n' "$(date +%s%N)" >"${run_dir}/measurement-end-ns.txt"
    for callback in select_cpu enqueue runnable running; do
        curl -fsS -X POST "${base_url}/api/fine-timing" \
            -H 'content-type: application/json' \
            -H "x-snake-token: ${token}" \
            --data "{\"callback\":\"${callback}\",\"enabled\":false}" \
            >"${run_dir}/fine-stop-${callback}.json"
    done
    printf '%s\n' "$(date +%s%N)" >"${run_dir}/measurement-freeze-end-ns.txt"
    freeze_ns=$(($(<"${run_dir}/measurement-freeze-end-ns.txt") - $(<"${run_dir}/measurement-end-ns.txt")))
    ((freeze_ns <= 2000000000)) || fail "fine-timing shutdown froze the workload for ${freeze_ns}ns"
    kill -CONT -- "-${workload_pid}"
    kill -TERM -- "-${workload_pid}" 2>/dev/null || true
    wait "${workload_pid}" 2>/dev/null || true
    workload_pid=
    wait_for "historical fine-timing captures" 100 0.1 sh -c \
        "curl -fsS '${base_url}/api/fine-timing' | jq -e '(.captures | map(select(.callback == \"select_cpu\" or .callback == \"enqueue\" or .callback == \"runnable\" or .callback == \"running\"))) as \$captures | .status == \"ready\" and (\$captures | length) == 4 and (\$captures | all(.state == \"historical\"))' >/dev/null"

    curl -fsS "${base_url}/api/fine-timing" >"${run_dir}/fine-timing.json"
    curl -fsS "${base_url}/api/callback-timing?scope=lifetime" \
        >"${run_dir}/callback-timing.json"
    curl -fsS "${base_url}/api/inspection" >"${run_dir}/inspection.json"
    curl -fsS "${base_url}/api/snapshot?window_ms=${measure_secs}000" \
        >"${run_dir}/snapshot.json"
    curl -fsS "${base_url}/api/scheduler/control" >"${run_dir}/scheduler-control.json"

    jq -e '.active == true and .last_exit == null' "${run_dir}/scheduler-control.json" >/dev/null ||
        fail "Snake was not active at the end of the capture"
    jq -e '
        .snapshot.slots[] | select(.state == "active") | .metrics |
        .invalid_errors == 0 and .vtime_accounting_errors == 0 and
        .membership_invalid_runs == 0
    ' "${run_dir}/inspection.json" >/dev/null || fail "Snake reported correctness errors"
    stage_count=$(jq '[.captures[] | select(.callback == "select_cpu" or .callback == "enqueue" or .callback == "runnable" or .callback == "running") | .stages[] | select(.stage == "cell_clock_read" or (.stage | startswith("cell_clock_run_start_")) or (.stage | startswith("affinity_clock_"))) | .samples] | add // 0' "${run_dir}/fine-timing.json")
    ((stage_count >= 100)) || fail "clock wrappers produced only ${stage_count} samples"

    jq -n \
        --arg run_label "${label}" \
        --arg kernel "$(uname -r)" \
        --arg workload_cpus "${workload_cpus}" \
        --argjson duration_seconds "${measure_secs}" \
        --argjson cpu_workers "${cpu_workers}" \
        --argjson switch_workers "${switch_workers}" \
        --argjson pipe_workers "${pipe_workers}" \
        --slurpfile fine "${run_dir}/fine-timing.json" \
        --slurpfile callbacks "${run_dir}/callback-timing.json" \
        --slurpfile inspection "${run_dir}/inspection.json" '
        {
          label: $run_label,
          kernel: $kernel,
          duration_seconds: $duration_seconds,
          workload: {
            cpu_workers: $cpu_workers,
            switch_workers: $switch_workers,
            pipe_workers: $pipe_workers,
            cpus: $workload_cpus
          },
          context: $fine[0].context,
          callbacks: $callbacks[0].callbacks,
          clock_stages: [
            $fine[0].captures[] |
            select(.callback == "select_cpu" or .callback == "enqueue" or
                   .callback == "runnable" or .callback == "running") |
            .callback as $callback |
            .stages[] |
            select(.stage == "cell_clock_read" or
                   (.stage | startswith("cell_clock_run_start_")) or
                   (.stage | startswith("affinity_clock_"))) |
            {callback: $callback, stage, samples, mean_ns, p50_ns, p95_ns, p99_ns}
          ],
          metrics: [
            $inspection[0].snapshot.slots[] | select(.state == "active") | .metrics |
            {
              select_calls, enqueues, dispatch_calls, running,
              invalid_errors, vtime_accounting_errors, membership_invalid_runs,
              vtime_credit_clamps, vtime_direct_runtime_ns, vtime_queued_runtime_ns
            }
          ][0]
        }
    ' >"${run_dir}/result.json"

    {
        echo "# VTIME Clock Latency: ${label}"
        echo
        echo "Kernel: \`$(uname -r)\`  "
        echo "Measurement: ${measure_secs}s, sample rate 1/${sample_rate}  "
        echo "Guest: 16 vCPUs, two LLCs; workload cell CPUs ${workload_cpus}  "
        echo "Workload: ${cpu_workers} CPU, ${switch_workers} switch, ${pipe_workers} pipe workers"
        echo
        echo '| Callback | Clock operation | Samples | Mean ns | p50 ns | p95 ns | p99 ns |'
        echo '| --- | --- | ---: | ---: | ---: | ---: | ---: |'
        jq -r '.clock_stages[] | "| \(.callback) | \(.stage) | \(.samples) | \(.mean_ns // "-") | \(.p50_ns // "-") | \(.p95_ns // "-") | \(.p99_ns // "-") |"' \
            "${run_dir}/result.json"
    } >"${run_dir}/summary.md"

    curl -fsS -X POST "${base_url}/api/scheduler/stop" \
        -H 'content-type: application/json' \
        -H "x-snake-token: ${token}" \
        --data '{}' >"${run_dir}/scheduler-stop.json"
    snake_pid=
    kill -INT "${inspector_pid}" 2>/dev/null || true
    wait "${inspector_pid}" 2>/dev/null || true
    inspector_pid=
    trap - EXIT INT TERM
    cleanup
}

if [[ ${1:-} == --guest ]]; then
    (($# == 5)) || { usage >&2; exit 2; }
    run_guest "$2" "$3" "$4" "$5"
elif (($# >= 2 && $# <= 4)); then
    run_host "$@"
else
    usage >&2
    exit 2
fi
