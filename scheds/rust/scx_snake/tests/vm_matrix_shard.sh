#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
inspector_bin=${1:-${repo}/tools/scx_snake_inspector/target/release/scx_snake_inspector}
snake_bin=${2:-${repo}/target/release/scx_snake}
shard_index=${3:-0}
shard_count=${4:-8}
artifact_dir=${5:-${repo}/artifacts/snake-testing/shard-${shard_index}}
policy_dir=${6:-${repo}/scheds/rust/scx_snake/examples}
testing_fairness=${7:-}
testing_policy=${8:-}
listen=${SNAKE_TESTING_LISTEN:-127.0.0.1:8788}
base_url=http://${listen}
inspector_pid=

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    if [[ -n ${inspector_pid} ]]; then
        kill -INT "${inspector_pid}" 2>/dev/null || true
        wait "${inspector_pid}" 2>/dev/null || true
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "Snake VM matrix shard: $*" >&2
    exit 1
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${shard_count} =~ ^[1-9][0-9]*$ ]] || fail "shard count must be positive"
[[ ${shard_index} =~ ^[0-9]+$ ]] || fail "shard index must be non-negative"
(( shard_index < shard_count )) || fail "shard index must be less than shard count"
[[ -x ${inspector_bin} ]] || fail "inspector binary is not executable: ${inspector_bin}"
[[ -x ${snake_bin} ]] || fail "Snake binary is not executable: ${snake_bin}"
[[ -d ${policy_dir} ]] || fail "policy directory does not exist: ${policy_dir}"
if [[ -n ${testing_fairness} && -z ${testing_policy} ]] ||
    [[ -z ${testing_fairness} && -n ${testing_policy} ]]; then
    fail "testing fairness and policy must be used together"
fi
testing_args=()
if [[ -n ${testing_fairness} ]]; then
    case ${testing_fairness} in
        fifo | vtime | eevdf) ;;
        *) fail "unknown testing fairness: ${testing_fairness}" ;;
    esac
    [[ ${testing_policy} != */* ]] || fail "testing policy must be a direct policy ID"
    [[ -f ${policy_dir}/${testing_policy} && ! -L ${policy_dir}/${testing_policy} ]] ||
        fail "testing policy does not exist: ${testing_policy}"
    testing_args+=(--testing-fairness "${testing_fairness}" --testing-policy "${testing_policy}")
fi
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required"

mkdir -p "${artifact_dir}"
"${inspector_bin}" \
    --listen "${listen}" \
    --snake-bin "${snake_bin}" \
    --policy-dir "${policy_dir}" \
    --enable-testing \
    --testing-isolated \
    --testing-duration 60s \
    --testing-shard-index "${shard_index}" \
    --testing-shard-count "${shard_count}" \
    --testing-artifact-dir "${artifact_dir}" \
    "${testing_args[@]}" \
    >"${artifact_dir}/inspector.log" 2>&1 &
inspector_pid=$!

deadline=$((SECONDS + 30))
while ! curl --fail --silent "${base_url}/api/testing/matrix" \
    -H "host: ${listen}" >"${artifact_dir}/initial.json"; do
    kill -0 "${inspector_pid}" 2>/dev/null || fail "inspector exited during startup"
    (( SECONDS < deadline )) || fail "timed out waiting for the testing API"
    sleep 0.2
done

token=$(curl --fail --silent "${base_url}/" -H "host: ${listen}" |
    sed -n 's/.*name="snake-session-token" content="\([^"]*\)".*/\1/p')
[[ -n ${token} ]] || fail "could not read the inspector session token"

assigned_cases=$(jq -er '.matrix.assigned_cases' "${artifact_dir}/initial.json")
duration_secs=$(jq -er '.matrix.duration_secs' "${artifact_dir}/initial.json")
[[ ${assigned_cases} =~ ^[0-9]+$ ]] || fail "invalid assigned case count: ${assigned_cases}"
[[ ${duration_secs} =~ ^[1-9][0-9]*$ ]] || fail "invalid case duration: ${duration_secs}"
case_budget_secs=$((duration_secs + 45))
shard_timeout_secs=$((assigned_cases * case_budget_secs + 60))

curl --fail --silent --show-error \
    -X POST "${base_url}/api/testing/run" \
    -H "host: ${listen}" \
    -H "content-type: application/json" \
    -H "x-snake-token: ${token}" \
    -d '{}' >"${artifact_dir}/started.json"

deadline=$((SECONDS + shard_timeout_secs))
while :; do
    kill -0 "${inspector_pid}" 2>/dev/null || fail "inspector exited during the test run"
    curl --fail --silent "${base_url}/api/testing/matrix" \
        -H "host: ${listen}" >"${artifact_dir}/latest.json"
    status=$(jq -r '.status' "${artifact_dir}/latest.json")
    case ${status} in
        completed)
            break
            ;;
        stopped)
            fail "testing shard stopped before completion"
            ;;
        running)
            ;;
        *)
            fail "unexpected testing status: ${status}"
            ;;
    esac
    (( SECONDS < deadline )) ||
        fail "testing shard exceeded ${shard_timeout_secs}-second budget"
    sleep 1
done

cp "${artifact_dir}/latest.json" "${artifact_dir}/result.json"
failed=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "failed")] | length' \
    "${artifact_dir}/result.json")
passed=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "passed")] | length' \
    "${artifact_dir}/result.json")
skipped=$(jq '[.matrix.groups[].rows[].cases[] | select(.assigned and .status == "skipped")] | length' \
    "${artifact_dir}/result.json")
assigned=$(jq '.matrix.assigned_cases' "${artifact_dir}/result.json")
echo "Shard ${shard_index}/${shard_count}: ${passed} passed, ${skipped} skipped, ${failed} failed"
(( failed == 0 )) || fail "${failed} scheduler/workload cases failed"
(( passed + skipped == assigned )) ||
    fail "only $((passed + skipped)) of ${assigned} assigned cases completed"
