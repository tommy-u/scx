#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
fairness=${1:-}
policy=${2:-}
inspector_bin=${3:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
snake_bin=${4:-${repo}/target/release/scx_snake}
run_root=${5:-/tmp/scx-snake-testing/focused-${fairness}-${policy%.toml}-$(date +%Y%m%d-%H%M%S)}
local_runner=${SNAKE_TESTING_LOCAL_RUNNER:-${script_dir}/vm_matrix_local.sh}
kernel_specs_text=${SNAKE_TESTING_KERNELS:-host=${VNG:-vng}}
vm_size_specs_text=${SNAKE_TESTING_VM_SIZES:-one=1:1G standard=8:4G}
max_parallel=${SNAKE_TESTING_MAX_PARALLEL:-4}
dry_run=${SNAKE_TESTING_DRY_RUN:-0}
policy_dir=${SNAKE_TESTING_POLICY_DIR:-${repo}/scheds/rust/scx_snake/examples}
declare -a pids=()
declare -a active_ids=()

fail() {
    echo "Snake focused VM matrix: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
Usage: vm_matrix_focus.sh FAIRNESS POLICY [INSPECTOR_BIN] [SNAKE_BIN] [RUN_ROOT]

Environment:
  SNAKE_TESTING_KERNELS   Space-separated LABEL=VNG launcher entries.
  SNAKE_TESTING_VM_SIZES  Space-separated LABEL=CPUS:MEMORY entries.
  SNAKE_TESTING_MAX_PARALLEL  Maximum simultaneous guests (default: 4).
  SNAKE_TESTING_DRY_RUN   Print expanded commands without running guests.
EOF
}

validate_label() {
    local kind=$1
    local value=$2

    [[ ${value} =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        fail "${kind} label must contain only letters, numbers, '.', '_', and '-': ${value}"
}

[[ -n ${fairness} && -n ${policy} ]] || {
    usage
    fail "fairness and policy are required"
}
case ${fairness} in
    fifo | vtime | eevdf) ;;
    *) fail "fairness must be fifo, vtime, or eevdf: ${fairness}" ;;
esac
[[ ${policy} =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.toml$ ]] ||
    fail "policy must be a direct TOML policy ID: ${policy}"
[[ ${max_parallel} =~ ^[1-9][0-9]*$ ]] ||
    fail "SNAKE_TESTING_MAX_PARALLEL must be positive"
[[ ${dry_run} == 0 || ${dry_run} == 1 ]] ||
    fail "SNAKE_TESTING_DRY_RUN must be 0 or 1"
[[ -x ${local_runner} ]] || fail "local VM runner is not executable: ${local_runner}"
[[ -x ${inspector_bin} ]] || fail "inspector binary is not executable: ${inspector_bin}"
[[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
[[ -f ${policy_dir}/${policy} && ! -L ${policy_dir}/${policy} ]] ||
    fail "policy is not a direct regular file in ${policy_dir}: ${policy}"

read -r -a raw_kernel_specs <<<"${kernel_specs_text}"
read -r -a raw_vm_size_specs <<<"${vm_size_specs_text}"
(( ${#raw_kernel_specs[@]} > 0 )) || fail "SNAKE_TESTING_KERNELS is empty"
(( ${#raw_vm_size_specs[@]} > 0 )) || fail "SNAKE_TESTING_VM_SIZES is empty"

declare -a kernel_labels=()
declare -a kernel_launchers=()
declare -A seen_kernel_labels=()
for spec in "${raw_kernel_specs[@]}"; do
    [[ ${spec} == *=* ]] || fail "kernel entries must use LABEL=VNG: ${spec}"
    label=${spec%%=*}
    launcher=${spec#*=}
    validate_label kernel "${label}"
    [[ -n ${launcher} ]] || fail "kernel launcher is empty for ${label}"
    [[ -z ${seen_kernel_labels[${label}]:-} ]] || fail "duplicate kernel label: ${label}"
    seen_kernel_labels[${label}]=1
    command -v "${launcher}" >/dev/null || fail "kernel launcher is not executable: ${launcher}"
    kernel_labels+=("${label}")
    kernel_launchers+=("${launcher}")
done

declare -a vm_size_labels=()
declare -a vm_size_cpus=()
declare -a vm_size_memory=()
declare -A seen_vm_size_labels=()
for spec in "${raw_vm_size_specs[@]}"; do
    [[ ${spec} == *=*:* ]] || fail "VM size entries must use LABEL=CPUS:MEMORY: ${spec}"
    label=${spec%%=*}
    shape=${spec#*=}
    cpus=${shape%%:*}
    memory=${shape#*:}
    validate_label "VM size" "${label}"
    [[ ${cpus} =~ ^[1-9][0-9]*$ && -n ${memory} && ${memory} != *:* ]] ||
        fail "VM size entries must use LABEL=CPUS:MEMORY: ${spec}"
    [[ -z ${seen_vm_size_labels[${label}]:-} ]] || fail "duplicate VM size label: ${label}"
    seen_vm_size_labels[${label}]=1
    vm_size_labels+=("${label}")
    vm_size_cpus+=("${cpus}")
    vm_size_memory+=("${memory}")
done

declare -a combo_ids=()
declare -a combo_kernel_labels=()
declare -a combo_launchers=()
declare -a combo_size_labels=()
declare -a combo_cpus=()
declare -a combo_memory=()
declare -a combo_campaigns=()
for kernel_index in "${!kernel_labels[@]}"; do
    for size_index in "${!vm_size_labels[@]}"; do
        id=${kernel_labels[kernel_index]}-${vm_size_labels[size_index]}
        combo_ids+=("${id}")
        combo_kernel_labels+=("${kernel_labels[kernel_index]}")
        combo_launchers+=("${kernel_launchers[kernel_index]}")
        combo_size_labels+=("${vm_size_labels[size_index]}")
        combo_cpus+=("${vm_size_cpus[size_index]}")
        combo_memory+=("${vm_size_memory[size_index]}")
        combo_campaigns+=("${run_root}/${id}")
    done
done

print_command() {
    local index=$1
    local -a command=(
        env
        "VNG=${combo_launchers[index]}"
        SNAKE_TESTING_SHARDS=1
        "SNAKE_TESTING_GUEST_CPUS=${combo_cpus[index]}"
        "SNAKE_TESTING_GUEST_MEMORY=${combo_memory[index]}"
        "SNAKE_TESTING_FAIRNESS=${fairness}"
        "SNAKE_TESTING_POLICY=${policy}"
        "${local_runner}"
        "${inspector_bin}"
        "${snake_bin}"
        "${combo_campaigns[index]}"
    )

    printf '%q ' "${command[@]}"
    printf '\n'
}

if [[ ${dry_run} == 1 ]]; then
    for index in "${!combo_ids[@]}"; do
        print_command "${index}"
    done
    exit 0
fi

if [[ -e ${run_root} ]]; then
    [[ -d ${run_root} ]] || fail "run root is not a directory: ${run_root}"
    [[ -z $(find "${run_root}" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
        fail "run root is not empty: ${run_root}"
else
    mkdir -p "${run_root}"
fi
run_root=$(realpath "${run_root}")
mkdir -p "${run_root}/logs"
for index in "${!combo_campaigns[@]}"; do
    combo_campaigns[index]=${run_root}/${combo_ids[index]}
done

declare -A result_rc=()
cleanup() {
    local rc=$?
    local pid

    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "${pid}" 2>/dev/null || true
    done
    exit "${rc}"
}
trap cleanup EXIT INT TERM

wait_one() {
    local pid=${pids[0]}
    local id=${active_ids[0]}
    local rc=0

    wait "${pid}" || rc=$?
    result_rc[${id}]=${rc}
    echo "Finished ${id} (status ${rc})"
    pids=("${pids[@]:1}")
    active_ids=("${active_ids[@]:1}")
}

echo "Focused target: ${fairness}/${policy}"
echo "Run root: ${run_root}"
for index in "${!combo_ids[@]}"; do
    while (( ${#pids[@]} >= max_parallel )); do
        wait_one
    done
    id=${combo_ids[index]}
    echo "Starting ${id}: ${combo_cpus[index]} CPUs, ${combo_memory[index]} memory"
    (
        env \
            VNG="${combo_launchers[index]}" \
            SNAKE_TESTING_SHARDS=1 \
            SNAKE_TESTING_GUEST_CPUS="${combo_cpus[index]}" \
            SNAKE_TESTING_GUEST_MEMORY="${combo_memory[index]}" \
            SNAKE_TESTING_FAIRNESS="${fairness}" \
            SNAKE_TESTING_POLICY="${policy}" \
            "${local_runner}" "${inspector_bin}" "${snake_bin}" \
            "${combo_campaigns[index]}"
    ) >"${run_root}/logs/${id}.log" 2>&1 &
    pids+=("$!")
    active_ids+=("${id}")
done
while (( ${#pids[@]} > 0 )); do
    wait_one
done

summary=${run_root}/summary.tsv
printf 'kernel\tvm_size\tcpus\tmemory\tstatus\tpassed\tskipped\tfailed\tkernel_release\tcampaign\n' >"${summary}"
failed_runs=0
for index in "${!combo_ids[@]}"; do
    id=${combo_ids[index]}
    result=${combo_campaigns[index]}/shard-0/run.json
    rc=${result_rc[${id}]:-125}
    status=launcher_failed
    passed=0
    skipped=0
    failed=0
    kernel_release=
    if [[ -f ${result} ]]; then
        passed=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "passed")] | length' "${result}")
        skipped=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "skipped")] | length' "${result}")
        failed=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and (.status == "failed" or .status == "aborted"))] | length' "${result}")
        kernel_release=$(jq -r '.environment.kernel_release // ""' "${result}")
        run_status=$(jq -r '.status' "${result}")
        if (( rc == 0 && failed == 0 )) && [[ ${run_status} == completed ]]; then
            status=passed
        else
            status=failed
        fi
    fi
    [[ ${status} == passed ]] || failed_runs=$((failed_runs + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${combo_kernel_labels[index]}" "${combo_size_labels[index]}" \
        "${combo_cpus[index]}" "${combo_memory[index]}" "${status}" \
        "${passed}" "${skipped}" "${failed}" "${kernel_release}" \
        "${combo_campaigns[index]}" >>"${summary}"
done

echo "Summary: ${summary}"
column -t -s $'\t' "${summary}" 2>/dev/null || cat "${summary}"
echo "Aggregate UI command:"
aggregate_command=(
    "${combo_campaigns[0]}/inputs/scx_snake_inspector"
    --listen 127.0.0.1:8788
    --snake-bin "${combo_campaigns[0]}/inputs/scx_snake"
    --policy-dir "${combo_campaigns[0]}/inputs/policies"
    --enable-testing
    --testing-isolated
    --testing-duration 60s
    --testing-shard-count 1
    --testing-fairness "${fairness}"
    --testing-policy "${policy}"
)
for campaign in "${combo_campaigns[@]}"; do
    aggregate_command+=(--testing-import-dir "${campaign}")
done
printf '  '
printf '%q ' "${aggregate_command[@]}"
printf '\n'

(( failed_runs == 0 )) || fail "${failed_runs}/${#combo_ids[@]} focused VM runs failed"
