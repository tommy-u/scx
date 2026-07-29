#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
default_snake_bin=${repo}/target/release/scx_snake
default_policy=${repo}/scheds/rust/scx_snake/examples/cell-min-vtime.toml
[[ -x ${script_dir}/scx_snake ]] && default_snake_bin=${script_dir}/scx_snake
[[ -r ${script_dir}/policy.toml ]] && default_policy=${script_dir}/policy.toml
snake_bin=${1:-${default_snake_bin}}
policy=${2:-${default_policy}}
duration=${SNAKE_LOW_WEIGHT_DURATION:-8}
rounds=${SNAKE_LOW_WEIGHT_ROUNDS:-5}
rehome_timeout=${SNAKE_REHOME_TIMEOUT:-5}
artifact=${SNAKE_ARTIFACT:-$(mktemp -d /tmp/scx-snake-vtime-low-weight.XXXXXX)}
mkdir -p "${artifact}"
snake_log=${artifact}/snake.log
dmesg_lines=0
snake_pid=
stress_pid=
runner_pids=()

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
        sleep 0.1
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

capture_khugepaged() {
    local name=$1 pid

    pid=$(pgrep -o -x khugepaged 2>/dev/null || true)
    {
        printf 'pid=%s\n' "${pid}"
        if [[ -n ${pid} ]]; then
            cat "/proc/${pid}/status"
            cat "/proc/${pid}/sched"
            printf 'stat=' && cat "/proc/${pid}/stat"
        fi
    } >"${artifact}/${name}-khugepaged.txt" 2>&1 || true
}

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    set +e
    [[ -n ${stress_pid} ]] && kill -TERM -- "-${stress_pid}" 2>/dev/null
    stop_pid "${stress_pid}"
    [[ -n ${stress_pid} ]] && kill -KILL -- "-${stress_pid}" 2>/dev/null
    for pid in "${runner_pids[@]}"; do
        stop_pid "${pid}"
    done
    [[ -n ${snake_pid} ]] && kill -INT "${snake_pid}" 2>/dev/null
    stop_pid "${snake_pid}" INT
    capture_khugepaged exit
    dmesg >"${artifact}/dmesg-full.txt" 2>&1
    dmesg | tail -n +$((dmesg_lines + 1)) >"${artifact}/dmesg-new.txt" 2>&1
    printf '%s\n' "${rc}" >"${artifact}/test.rc"
    printf 'artifacts: %s\n' "${artifact}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "vtime low-weight yield test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 200 "${snake_log}" >&2 || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

clock_transitions() {
    python3 - "${snake_log}" <<'PY'
import json
import sys

transitions = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        transitions += sum(
            cell.get("clock_transitions", 0)
            for cell in record.get("cells", {}).values()
        )
print(transitions)
PY
}

cell_runtime() {
    local cell_id=$1

    python3 - "${snake_log}" "${cell_id}" <<'PY'
import json
import sys

runtime = 0
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        runtime += record.get("cells", {}).get(sys.argv[2], {}).get("runtime_ns", 0)
print(runtime)
PY
}

wait_task_runtime() {
    local pid=$1 deadline=$((SECONDS + rehome_timeout)) runtime

    while ((SECONDS < deadline)); do
        runtime=$(awk '{print $1}' "/proc/${pid}/schedstat" 2>/dev/null || true)
        [[ ${runtime:-0} =~ ^[0-9]+$ ]] && ((runtime > 0)) && return 0
        sleep 0.05
    done
    return 1
}

wait_cell_runtime_after() {
    local cell_id=$1 baseline=$2 deadline=$((SECONDS + rehome_timeout)) runtime

    while ((SECONDS < deadline)); do
        runtime=$(cell_runtime "${cell_id}")
        ((runtime > baseline)) && return 0
        sleep 0.1
    done
    return 1
}

wait_clock_transitions() {
    local expected=$1 deadline=$((SECONDS + rehome_timeout)) observed

    while ((SECONDS < deadline)); do
        observed=$(clock_transitions)
        ((observed >= expected)) && return 0
        sleep 0.1
    done
    return 1
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ ${rounds} =~ ^[1-9][0-9]*$ ]] || fail "rounds must be a positive integer"
[[ ${rehome_timeout} =~ ^[1-9][0-9]*$ ]] || fail "rehome timeout must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
for command in pgrep python3 setsid sha256sum stress-ng timeout yes; do
    command -v "${command}" >/dev/null || fail "${command} is required"
done

cpus=$(nproc)
(( cpus >= 128 )) || fail "requires at least 128 CPUs; 256 reproduces the original failure"
if [[ -n ${SNAKE_EXPECT_CPUS:-} && ${SNAKE_EXPECT_CPUS} != 0 &&
      ${cpus} -ne ${SNAKE_EXPECT_CPUS} ]]; then
    fail "expected ${SNAKE_EXPECT_CPUS} CPUs, found ${cpus}"
fi
khugepaged_pid=$(pgrep -o -x khugepaged 2>/dev/null || true)
[[ -n ${khugepaged_pid} ]] || fail "khugepaged is not running"
khugepaged_nice=$(awk '{print $19}' "/proc/${khugepaged_pid}/stat")
[[ ${khugepaged_nice} == 19 ]] || fail "expected khugepaged nice 19, found ${khugepaged_nice}"

sha256sum "${snake_bin}" >"${artifact}/snake.sha256"
[[ $(readlink -f "$0") == $(readlink -f "${artifact}/reproducer.sh" 2>/dev/null || true) ]] ||
    cp "$0" "${artifact}/reproducer.sh"
[[ $(readlink -f "${snake_bin}") == $(readlink -f "${artifact}/scx_snake" 2>/dev/null || true) ]] ||
    cp "${snake_bin}" "${artifact}/scx_snake"
[[ $(readlink -f "${policy}") == $(readlink -f "${artifact}/policy.toml" 2>/dev/null || true) ]] ||
    cp "${policy}" "${artifact}/policy.toml"
chmod +x "${artifact}/reproducer.sh" "${artifact}/scx_snake"
printf 'SNAKE_REPO=%q\nSNAKE_EXPECT_CPUS=%q\nSNAKE_LOW_WEIGHT_DURATION=%q\nSNAKE_LOW_WEIGHT_ROUNDS=%q\n' \
    "${repo}" "${cpus}" "${duration}" "${rounds}" \
    >"${artifact}/reproducer.env"
# These expressions belong in the generated script.
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)' \
    "exec env SNAKE_EXPECT_CPUS=${cpus} SNAKE_LOW_WEIGHT_DURATION=${duration} SNAKE_LOW_WEIGHT_ROUNDS=${rounds} \"\${dir}/reproducer.sh\" \"\${dir}/scx_snake\" \"\${dir}/policy.toml\"" \
    >"${artifact}/rerun.sh"
chmod +x "${artifact}/rerun.sh"
dmesg >"${artifact}/dmesg-before.txt"
dmesg_lines=$(dmesg | wc -l)
capture_khugepaged before

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.25 \
    --stats-format json --exit-dump-len 1048576 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"
khugepaged_runtime_before=$(awk '{print $1}' "/proc/${khugepaged_pid}/schedstat")
capture_khugepaged before-stress

# Keep old normal work runnable while the cell clocks advance, and force the
# same set/clear clock transition that exposed stale run-start credit.
transition_start=$(clock_transitions)
transition_baseline=${transition_start}
for cell in 1 2; do
    yes >/dev/null &
    runner_pid=$!
    runner_pids+=("${runner_pid}")
    wait_task_runtime "${runner_pid}" ||
        fail "persistent runner ${runner_pid} did not execute in cell 0"
    runtime_baseline=$(cell_runtime "${cell}")
    "${snake_bin}" --set-thread-cell "${runner_pid}:${cell}" >/dev/null
    wait_cell_runtime_after "${cell}" "${runtime_baseline}" ||
        fail "persistent runner ${runner_pid} did not execute in cell ${cell}"
    wait_clock_transitions $((transition_baseline + 1)) ||
        fail "persistent runner ${runner_pid} did not adopt cell ${cell} clock"
    transition_baseline=$(clock_transitions)
    "${snake_bin}" --clear-thread-cell "${runner_pid}" >/dev/null
    wait_clock_transitions $((transition_baseline + 1)) ||
        fail "persistent runner ${runner_pid} did not return to cell 0 clock"
    transition_baseline=$(clock_transitions)
done
((transition_baseline >= transition_start + 4)) ||
    fail "persistent runners did not complete four cell-clock transitions"
printf '%s\n' "${runner_pids[@]}" >"${artifact}/persistent-runners.txt"

cpu_workers=$((cpus * 2))
futex=$((cpus < 128 ? cpus : 128))
switch=$((cpus < 128 ? cpus : 128))
pipe=$((cpus < 64 ? cpus : 64))
yield_workers=$((cpus < 64 ? cpus : 64))
timer=$((cpus < 64 ? cpus : 64))
fork_workers=$((cpus / 8))
(( fork_workers > 32 )) && fork_workers=32
affinity=$((cpus < 64 ? cpus : 64))

for round in $(seq 1 "${rounds}"); do
    setsid timeout --signal=TERM --kill-after=5s "$((duration + 20))" \
        stress-ng --cpu "${cpu_workers}" --cpu-method loop \
        --futex "${futex}" --switch "${switch}" --pipe "${pipe}" \
        --yield "${yield_workers}" --timer "${timer}" --timer-rand \
        --fork "${fork_workers}" --fork-max 2 --fork-vm \
        --mmap "${fork_workers}" --mmap-bytes 8M --mmap-madvise \
        --madvise "${fork_workers}" --affinity "${affinity}" --affinity-rand \
        --timeout "${duration}s" --metrics-brief \
        >"${artifact}/stress-${round}.log" 2>&1 &
    stress_pid=$!
    deadline=$((SECONDS + duration + 25))
    while ! pid_done "${stress_pid}"; do
        scheduler_enabled || fail "scheduler exited during stress round ${round}"
        (( SECONDS < deadline )) || fail "stress round ${round} did not finish"
        sleep 0.1
    done
    stress_rc=0
    wait "${stress_pid}" || stress_rc=$?
    stress_pid=
    (( stress_rc == 0 )) || fail "stress round ${round} failed with status ${stress_rc}"
    scheduler_enabled || fail "scheduler exited after stress round ${round}"
    capture_khugepaged "round-${round}"
done

khugepaged_runtime_after=$(awk '{print $1}' "/proc/${khugepaged_pid}/schedstat")
printf 'before_ns=%s\nafter_ns=%s\n' \
    "${khugepaged_runtime_before}" "${khugepaged_runtime_after}" \
    >"${artifact}/khugepaged-runtime.txt"
(( khugepaged_runtime_after > khugepaged_runtime_before )) ||
    fail "khugepaged did not execute during the stress rounds"

dmesg | tail -n +$((dmesg_lines + 1)) >"${artifact}/dmesg-new.txt"
if grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)' \
    "${artifact}/dmesg-new.txt"; then
    fail "kernel log contains a scheduler failure signature"
fi
if grep -Eq '"(invalid_errors|vtime_accounting_errors|membership_invalid_runs)"[[:space:]]*:[[:space:]]*[1-9]' \
    "${snake_log}"; then
    fail "Snake reported a runtime error counter"
fi

touch "${artifact}/PASS"
echo "PASS: low-weight VTIME yield stress completed ${rounds} rounds on ${cpus} CPUs"
