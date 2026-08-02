#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
inspector_bin=${1:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
snake_bin=${2:-${repo}/target/release/scx_snake}
campaign_dir=${3:-/tmp/scx-snake-testing/campaign-$(date +%Y%m%d-%H%M%S)}
source_policy_dir=${SNAKE_TESTING_POLICY_DIR:-${repo}/scheds/rust/scx_snake/examples}
testing_profile=${SNAKE_TESTING_PROFILE:-default}
testing_fairness=${SNAKE_TESTING_FAIRNESS:-}
testing_policy=${SNAKE_TESTING_POLICY:-}
vm_timeout_secs=${SNAKE_TESTING_VM_TIMEOUT_SECS:-}
case_budget_secs=${SNAKE_TESTING_CASE_BUDGET_SECS:-105}
vng=${VNG:-vng}
pids=()

fail() {
    echo "Snake local VM matrix: $*" >&2
    exit 1
}

case ${testing_profile} in
    default)
        profile_shards=8
        profile_guest_cpus=8
        profile_guest_memory=4G
        ;;
    single-cpu)
        profile_shards=128
        profile_guest_cpus=1
        profile_guest_memory=1G
        ;;
    *)
        fail "unknown SNAKE_TESTING_PROFILE: ${testing_profile}"
        ;;
esac

shard_count=${SNAKE_TESTING_SHARDS:-${profile_shards}}
guest_cpus=${SNAKE_TESTING_GUEST_CPUS:-${profile_guest_cpus}}
guest_memory=${SNAKE_TESTING_GUEST_MEMORY:-${profile_guest_memory}}

cleanup() {
    local pid

    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "${pid}" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

command -v "${vng}" >/dev/null || fail "virtme-ng is required (set VNG to override)"
command -v jq >/dev/null || fail "jq is required"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v timeout >/dev/null || fail "timeout is required"
[[ -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is not usable"
[[ -r /sys/kernel/sched_ext/state ]] || fail "the host kernel does not expose sched_ext"
[[ ${shard_count} =~ ^[1-9][0-9]*$ ]] || fail "SNAKE_TESTING_SHARDS must be positive"
[[ ${guest_cpus} =~ ^[1-9][0-9]*$ ]] || fail "SNAKE_TESTING_GUEST_CPUS must be positive"
[[ ${case_budget_secs} =~ ^[1-9][0-9]*$ ]] || fail "SNAKE_TESTING_CASE_BUDGET_SECS must be positive"
[[ -z ${vm_timeout_secs} || ${vm_timeout_secs} =~ ^[1-9][0-9]*$ ]] ||
    fail "SNAKE_TESTING_VM_TIMEOUT_SECS must be positive"
if [[ -n ${testing_fairness} && -z ${testing_policy} ]] ||
    [[ -z ${testing_fairness} && -n ${testing_policy} ]]; then
    fail "SNAKE_TESTING_FAIRNESS and SNAKE_TESTING_POLICY must be used together"
fi
if [[ -n ${testing_fairness} ]]; then
    case ${testing_fairness} in
        fifo | vtime | eevdf) ;;
        *) fail "unknown SNAKE_TESTING_FAIRNESS: ${testing_fairness}" ;;
    esac
    [[ ${testing_policy} != */* ]] || fail "SNAKE_TESTING_POLICY must be a direct policy ID"
    [[ -f ${source_policy_dir}/${testing_policy} && ! -L ${source_policy_dir}/${testing_policy} ]] ||
        fail "testing policy does not exist: ${testing_policy}"
fi
[[ -x ${inspector_bin} ]] || fail "inspector binary is not executable: ${inspector_bin}"
[[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
[[ -d ${source_policy_dir} ]] || fail "policy directory does not exist: ${source_policy_dir}"

inspector_bin=$(realpath "${inspector_bin}")
snake_bin=$(realpath "${snake_bin}")
source_policy_dir=$(realpath "${source_policy_dir}")
if [[ -e ${campaign_dir} ]]; then
    [[ -d ${campaign_dir} ]] || fail "campaign path is not a directory: ${campaign_dir}"
    [[ -z $(find "${campaign_dir}" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
        fail "campaign directory is not empty: ${campaign_dir}"
else
    mkdir -p "${campaign_dir}"
fi
campaign_dir=$(realpath "${campaign_dir}")
inputs_dir=${campaign_dir}/inputs
snapshot_snake=${inputs_dir}/scx_snake
snapshot_inspector=${inputs_dir}/scx_snake_inspector
snapshot_policies=${inputs_dir}/policies
snapshot_shard=${inputs_dir}/vm_matrix_shard.sh
mkdir -p "${inputs_dir}"
cp "${snake_bin}" "${snapshot_snake}"
cp "${inspector_bin}" "${snapshot_inspector}"
cp "${script_dir}/vm_matrix_shard.sh" "${snapshot_shard}"
cp -a "${source_policy_dir}" "${snapshot_policies}"
chmod -R a-w "${inputs_dir}"

snake_bin=${snapshot_snake}
inspector_bin=${snapshot_inspector}
policy_dir=${snapshot_policies}
policy_count=$(find "${policy_dir}" -maxdepth 1 -type f -name '*.toml' | wc -l)
(( policy_count > 0 )) || fail "snapshot contains no TOML policies"
if [[ -n ${testing_fairness} ]]; then
    max_cases_per_shard=$(((4 + shard_count - 1) / shard_count))
else
    # Every policy can contribute at most three fairness modes by four workloads.
    max_cases_per_shard=$(((policy_count * 12 + shard_count - 1) / shard_count))
fi
if [[ -z ${vm_timeout_secs} ]]; then
    vm_timeout_secs=$((max_cases_per_shard * case_budget_secs + 180))
fi

echo "Campaign: ${campaign_dir}"
echo "Profile: ${testing_profile} (${shard_count} shards, ${guest_cpus} CPUs, ${guest_memory} memory each)"
echo "Aggregate UI command:"
aggregate_command=(
    "${inspector_bin}"
    --listen 127.0.0.1:8788
    --snake-bin "${snake_bin}"
    --policy-dir "${policy_dir}"
    --enable-testing
    --testing-isolated
    --testing-duration 60s
    --testing-shard-count "${shard_count}"
)
if [[ -n ${testing_fairness} ]]; then
    aggregate_command+=(--testing-fairness "${testing_fairness}" --testing-policy "${testing_policy}")
fi
aggregate_command+=(--testing-import-dir "${campaign_dir}")
printf '  '
printf '%q ' "${aggregate_command[@]}"
printf '\n'

declare -a shard_pids
for ((shard = 0; shard < shard_count; shard++)); do
    shard_dir=${campaign_dir}/shard-${shard}
    mkdir -p "${shard_dir}"
    shard_args=(
        "${snapshot_shard}"
        "${inspector_bin}"
        "${snake_bin}"
        "${shard}"
        "${shard_count}"
        "${shard_dir}"
        "${policy_dir}"
    )
    if [[ -n ${testing_fairness} ]]; then
        shard_args+=("${testing_fairness}" "${testing_policy}")
    fi
    printf -v shard_command '%q ' "${shard_args[@]}"
    shard_command=${shard_command% }
    guest_script=${campaign_dir}/shard-${shard}-guest.sh
    printf -v vm_boot_command '%q --run --name %q --cpus %q --memory %q --user root --rwdir %q --exec %q' \
        "${vng}" "snake-shard-${shard}" "${guest_cpus}" "${guest_memory}" \
        "${campaign_dir}" "${guest_script}"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'export SNAKE_TESTING_VM_BOOT_COMMAND=%q\n' "${vm_boot_command}"
        printf 'exec %s\n' "${shard_command}"
    } >"${guest_script}"
    chmod 0555 "${guest_script}"
    (
        rc=0
        marker=${campaign_dir}/shard-${shard}.exit
        write_marker() {
            printf '%s\n' "$1" >"${marker}.tmp"
            mv "${marker}.tmp" "${marker}"
        }
        # Invoked indirectly by the signal trap.
        # shellcheck disable=SC2317
        stop_vm() {
            trap - INT TERM
            kill -TERM "${vm_pid}" 2>/dev/null || true
            wait "${vm_pid}" 2>/dev/null || true
            write_marker 143
            exit 143
        }
        timeout --signal=TERM --kill-after=30s "${vm_timeout_secs}s" \
            "${vng}" --run \
            --name "snake-shard-${shard}" \
            --cpus "${guest_cpus}" \
            --memory "${guest_memory}" \
            --user root \
            --rwdir "${campaign_dir}" \
            --exec "${guest_script}" \
            </dev/null &
        vm_pid=$!
        trap stop_vm INT TERM
        wait "${vm_pid}" || rc=$?
        trap - INT TERM
        write_marker "${rc}"
        exit "${rc}"
    ) >"${campaign_dir}/shard-${shard}-vm.log" 2>&1 &
    pid=$!
    pids+=("${pid}")
    shard_pids[shard]=${pid}
done

failed_vms=0
for ((shard = 0; shard < shard_count; shard++)); do
    rc=0
    wait "${shard_pids[shard]}" || rc=$?
    (( rc == 0 )) || failed_vms=$((failed_vms + 1))
done
pids=()

passed=0
skipped=0
failed=0
completed=0
for ((shard = 0; shard < shard_count; shard++)); do
    result=${campaign_dir}/shard-${shard}/run.json
    [[ -f ${result} ]] || continue
    passed=$((passed + $(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "passed")] | length' "${result}")))
    skipped=$((skipped + $(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "skipped")] | length' "${result}")))
    failed=$((failed + $(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and (.status == "failed" or .status == "aborted"))] | length' "${result}")))
    [[ $(jq -r '.status' "${result}") == completed ]] && completed=$((completed + 1))
done

echo "Matrix complete: ${passed} passed, ${skipped} skipped, ${failed} failed, ${completed}/${shard_count} shards completed"
(( failed_vms == 0 )) || fail "${failed_vms} VM shards exited unsuccessfully"
(( failed == 0 )) || fail "${failed} scheduler/workload cases failed"
(( completed == shard_count )) || fail "only ${completed}/${shard_count} shards completed"
