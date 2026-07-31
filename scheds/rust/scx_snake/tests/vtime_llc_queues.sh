#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
policy=${2:-${repo}/scheds/rust/scx_snake/examples/kernel-default-sim.toml}
duration=${SNAKE_LLC_QUEUE_DURATION:-10}
fairness_duration=${SNAKE_LLC_FAIRNESS_DURATION:-5}
startup_timeout=${SNAKE_LLC_QUEUE_STARTUP_TIMEOUT:-60}
tmpdir=$(mktemp -d)
topology_dump=${tmpdir}/topology.dump
snake_log=${tmpdir}/snake.ndjson
wide_log=${tmpdir}/wide.log
pinned_log=${tmpdir}/pinned.log
fairness_log=${tmpdir}/fairness.log
pre_attach_log=${tmpdir}/pre-attach.ndjson
pre_attach_stress_log=${tmpdir}/pre-attach-stress.log
snake_pid=
wide_pid=
pinned_pid=
pre_attach_stress_pid=
pre_attach_pids=()
dmesg_lines=0
verbose_args=()

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

cleanup() {
    kill -INT "${snake_pid}" 2>/dev/null || true
    kill "${wide_pid}" "${pinned_pid}" "${pre_attach_stress_pid}" \
        2>/dev/null || true
    if ((${#pre_attach_pids[@]})); then
        kill -KILL "${pre_attach_pids[@]}" 2>/dev/null || true
    fi
    stop_pid "${wide_pid}"
    stop_pid "${pinned_pid}"
    stop_pid "${pre_attach_stress_pid}"
    stop_pid "${snake_pid}" INT
    if ((${#pre_attach_pids[@]})); then
        wait "${pre_attach_pids[@]}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime LLC queue test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    cat "${topology_dump}" >&2 2>/dev/null || true
    tail -n 200 "${pre_attach_log}" >&2 2>/dev/null || true
    tail -n 80 "${pre_attach_stress_log}" >&2 2>/dev/null || true
    tail -n 200 "${snake_log}" >&2 2>/dev/null || true
    tail -n 40 "${wide_log}" >&2 2>/dev/null || true
    tail -n 40 "${pinned_log}" >&2 2>/dev/null || true
    tail -n 80 "${fairness_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

sleepers_blocked() {
    local pid state

    for pid in "${pre_attach_pids[@]}"; do
        state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
        [[ ${state} == S ]] || return 1
    done
}

sleepers_done() {
    local pid

    for pid in "${pre_attach_pids[@]}"; do
        pid_done "${pid}" || return 1
    done
}

stats_record_count() {
    grep -c '^{' "${pre_attach_log}" 2>/dev/null || true
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
cpus=$(nproc)
((cpus >= 4)) || fail "requires at least four CPUs"
wide_workers=$((cpus * 4))
((wide_workers > 256)) && wide_workers=256
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ ${fairness_duration} =~ ^[1-9][0-9]*$ ]] ||
    fail "fairness duration must be a positive integer"
[[ ${startup_timeout} =~ ^[1-9][0-9]*$ ]] ||
    fail "startup timeout must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ -r ${policy} ]] || fail "policy is not readable: ${policy}"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"
command -v python3 >/dev/null || fail "python3 is required"
command -v pgrep >/dev/null || fail "pgrep is required"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v taskset >/dev/null || fail "taskset is required"
command -v timeout >/dev/null || fail "timeout is required"
[[ ${SNAKE_VERBOSE:-0} == 1 ]] && verbose_args=(-v)
dmesg_lines=$(dmesg | wc -l)

"${snake_bin}" --policy "${policy}" --dump-compiled-policy >"${topology_dump}" ||
    fail "could not resolve the LLC queue topology"
topology_values=$(python3 - "${topology_dump}" "${cpus}" <<'PY'
import re
import sys

path, expected_cpus = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as stream:
    text = stream.read()

header = re.search(
    r"^queue topology: layout=llc clocks=(\d+) cells=(\d+) "
    r"normal_queues=(\d+) affinity_queues=(\d+)$",
    text,
    re.MULTILINE,
)
if not header:
    raise SystemExit("missing global LLC queue topology header")
clocks, cells, normal_count, affinity_count = map(int, header.groups())
if clocks != 1 or cells != 0:
    raise SystemExit(f"expected one clock and no cells, got clocks={clocks} cells={cells}")
if normal_count < 1:
    raise SystemExit("expected at least one LLC queue")
if affinity_count != expected_cpus:
    raise SystemExit(
        f"expected {expected_cpus} per-CPU queues, found {affinity_count}"
    )

queues = []
pattern = re.compile(
    r"^  normal queue (\d+): cell_index=None clock_index=0 "
    r"llc=Some\((\d+)\) consumers=\[([0-9,]*)\]$",
    re.MULTILINE,
)
for match in pattern.finditer(text):
    consumers = {int(cpu) for cpu in match.group(3).split(",") if cpu}
    if not consumers:
        raise SystemExit(f"normal queue {match.group(1)} has no consumers")
    queues.append((int(match.group(1)), int(match.group(2)), consumers))
if len(queues) != normal_count:
    raise SystemExit(f"expected {normal_count} normal queue descriptors, found {len(queues)}")
if len({llc for _, llc, _ in queues}) != normal_count:
    raise SystemExit("normal queues are not one-to-one with discovered LLCs")

covered = set()
for index, _, consumers in queues:
    overlap = covered & consumers
    if overlap:
        raise SystemExit(f"normal queue {index} repeats consumers {sorted(overlap)}")
    covered.update(consumers)
if len(covered) != expected_cpus:
    raise SystemExit(f"normal queues cover {len(covered)} of {expected_cpus} CPUs")
print(min(covered), normal_count)
PY
) || fail "compiled topology validation failed"
read -r pinned_cpu normal_queue_count <<<"${topology_values}"
[[ ${pinned_cpu} =~ ^[0-9]+$ ]] || fail "invalid pinned CPU from topology"
[[ ${normal_queue_count} =~ ^[0-9]+$ ]] || fail "invalid LLC queue count from topology"

pre_attach_tasks=$((cpus * 4))
((pre_attach_tasks < 32)) && pre_attach_tasks=32
((pre_attach_tasks > 128)) && pre_attach_tasks=128
for _ in $(seq 1 "${pre_attach_tasks}"); do
    sleep 300 &
    pre_attach_pids+=("$!")
done
for _ in $(seq 1 200); do
    sleepers_blocked && break
    sleep 0.05
done
sleepers_blocked || fail "pre-attach tasks did not enter interruptible sleep"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.1 \
    --stats-format json "${verbose_args[@]}" >"${pre_attach_log}" 2>&1 &
snake_pid=$!
startup_deadline=$((SECONDS + startup_timeout))
while ! scheduler_enabled; do
    pid_done "${snake_pid}" && fail "scheduler exited while attaching"
    ((SECONDS < startup_deadline)) || fail "scheduler did not attach"
    sleep 0.05
done
stats_deadline=$((SECONDS + 10))
while (( $(stats_record_count) == 0 )); do
    scheduler_enabled || fail "scheduler exited before stats became available"
    ((SECONDS < stats_deadline)) || fail "pre-attach stats did not become available"
    sleep 0.05
done
records_before_stress=$(stats_record_count)

stress-ng --cpu "${cpus}" --cpu-method loop --timeout 15s \
    >"${pre_attach_stress_log}" 2>&1 &
pre_attach_stress_pid=$!
stress_workers=0
for _ in $(seq 1 200); do
    stress_workers=$(pgrep -P "${pre_attach_stress_pid}" -c stress-ng-cpu \
        2>/dev/null || true)
    ((stress_workers >= cpus)) && break
    sleep 0.05
done
((stress_workers >= cpus)) || fail "pre-attach stress workers did not start"
stats_deadline=$((SECONDS + 10))
while (( $(stats_record_count) <= records_before_stress )); do
    scheduler_enabled || fail "scheduler exited while saturating CPUs"
    ((SECONDS < stats_deadline)) || fail "stress activity was not sampled"
    sleep 0.05
done
records_before_signal=$(stats_record_count)

# Saturation forces each signal wake through the ladder exhaustion fallback.
kill -TERM "${pre_attach_pids[@]}"
signal_deadline=$((SECONDS + 10))
while ! sleepers_done; do
    scheduler_enabled || fail "scheduler exited during pre-attach sleeper termination"
    ((SECONDS < signal_deadline)) || fail "pre-attach sleepers did not exit"
    sleep 0.05
done
wait "${pre_attach_pids[@]}" 2>/dev/null || true
pre_attach_pids=()
scheduler_enabled || fail "scheduler exited during pre-attach sleeper termination"
stats_deadline=$((SECONDS + 10))
while (( $(stats_record_count) <= records_before_signal )); do
    scheduler_enabled || fail "scheduler exited before reporting signal wakeups"
    ((SECONDS < stats_deadline)) || fail "signal wakeups were not sampled"
    sleep 0.05
done
sleep 0.2
python3 - "${pre_attach_log}" "${records_before_signal}" \
    "${pre_attach_tasks}" <<'PY' || fail "pre-attach fallback validation failed"
import json
import sys

records = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
post_signal = records[int(sys.argv[2]):]
expected_tasks = int(sys.argv[3])
if not post_signal:
    raise SystemExit("missing post-signal scheduler statistics")
if sum(record.get("select_calls", 0) for record in post_signal) < expected_tasks:
    raise SystemExit("signal wakeups did not reach select_cpu")
if sum(record.get("ladder_exhaustions", 0) for record in post_signal) == 0:
    raise SystemExit("signal wakeups did not exercise ladder exhaustion")
if sum(record.get("invalid_errors", 0) for record in post_signal) != 0:
    raise SystemExit("pre-attach signal wakeups reported invalid errors")
if sum(record.get("vtime_accounting_errors", 0) for record in post_signal) != 0:
    raise SystemExit("pre-attach signal wakeups reported VTIME accounting errors")
PY
stop_pid "${pre_attach_stress_pid}"
pre_attach_stress_pid=
stop_pid "${snake_pid}" INT
snake_pid=
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "pre-attach regression phase left sched_ext enabled"

"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.25 \
    --stats-format json "${verbose_args[@]}" >"${snake_log}" 2>&1 &
snake_pid=$!
startup_deadline=$((SECONDS + startup_timeout))
while ! scheduler_enabled; do
    pid_done "${snake_pid}" && fail "scheduler exited while reattaching"
    ((SECONDS < startup_deadline)) || fail "scheduler did not reattach"
    sleep 0.05
done

timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    stress-ng --cpu "${wide_workers}" --cpu-method loop --timeout "${duration}s" \
    >"${wide_log}" 2>&1 &
wide_pid=$!
timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    taskset -c "${pinned_cpu}" stress-ng --cpu 8 --cpu-method loop \
    --timeout "${duration}s" >"${pinned_log}" 2>&1 &
pinned_pid=$!

deadline=$((SECONDS + duration + 8))
while ! pid_done "${wide_pid}" || ! pid_done "${pinned_pid}"; do
    scheduler_enabled || fail "scheduler exited during LLC queue load"
    ((SECONDS < deadline)) || fail "LLC queue workloads did not finish"
    sleep 0.1
done
wide_rc=0
wait "${wide_pid}" || wide_rc=$?
wide_pid=
pinned_rc=0
wait "${pinned_pid}" || pinned_rc=$?
pinned_pid=
((wide_rc == 0 && pinned_rc == 0)) ||
    fail "LLC queue workloads failed: wide=${wide_rc} pinned=${pinned_rc}"
scheduler_enabled || fail "scheduler exited after LLC queue load"
sleep 0.5

timeout --signal=TERM --kill-after=3s "$((fairness_duration * 3 + 15))s" \
    env FAIRNESS_CPU="${pinned_cpu}" FAIRNESS_DURATION="${fairness_duration}" \
    "${repo}/scheds/rust/scx_snake/interactive/fairness-demo.sh" \
    >"${fairness_log}" 2>&1 || fail "global-clock VTIME fairness demo failed"
scheduler_enabled || fail "scheduler exited during global-clock fairness test"
cat "${fairness_log}"

python3 - "${snake_log}" "${normal_queue_count}" <<'PY' || fail "queue-rung counter validation failed"
import json
import sys

normal_queue_count = int(sys.argv[2])
expected_enqueue = {
    "0": "try_insert(local)",
    "1": "insert(cpu)",
}
expected_dispatch = {
    "0": "peek(cpu)",
    "1": "peek(local)",
    "2": "peek(remote)",
    "3": "consume(min_vtime;fallback=cpu,local,remote)",
}
fields = (
    "attempts",
    "hits",
    "misses",
    "errors",
    "selected",
    "move_misses",
    "fallback_attempts",
    "fallback_hits",
    "fallback_misses",
)

records = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "enqueue_rungs" in record:
            records.append(record)
if not records:
    raise SystemExit("scheduler emitted no JSON statistics")

def aggregate(ladder, expected):
    totals = {index: {field: 0 for field in fields} for index in expected}
    operations = {}
    for record in records:
        for index, rung in record.get(ladder, {}).items():
            if index not in totals:
                continue
            if ladder == "dispatch_rungs" and "move_misses" not in rung:
                raise SystemExit("dispatch rung metrics omit move_misses")
            operations[index] = rung.get("operation")
            for field in fields:
                totals[index][field] += int(rung.get(field, 0))
    for index, operation in expected.items():
        if operations.get(index) != operation:
            raise SystemExit(
                f"{ladder} rung {index} operation {operations.get(index)!r}, expected {operation!r}"
            )
        rung = totals[index]
        if rung["attempts"] == 0:
            raise SystemExit(f"{ladder} rung {index} was never attempted")
        outcomes = rung["hits"] + rung["misses"] + rung["errors"]
        accounting_skew = abs(rung["attempts"] - outcomes)
        allowed_skew = max(8, max(rung["attempts"], outcomes) // 100)
        if accounting_skew > allowed_skew:
            raise SystemExit(
                f"{ladder} rung {index} attempt accounting skew "
                f"{accounting_skew} exceeds {allowed_skew}: {rung}"
            )
        fallback_outcomes = rung["fallback_hits"] + rung["fallback_misses"]
        fallback_skew = abs(rung["fallback_attempts"] - fallback_outcomes)
        allowed_fallback_skew = max(
            8,
            max(rung["fallback_attempts"], fallback_outcomes) // 100,
        )
        if fallback_skew > allowed_fallback_skew:
            raise SystemExit(
                f"{ladder} rung {index} fallback accounting skew "
                f"{fallback_skew} exceeds {allowed_fallback_skew}: {rung}"
            )
        if rung["errors"]:
            raise SystemExit(f"{ladder} rung {index} reported {rung['errors']} errors")
    return totals

enqueue = aggregate("enqueue_rungs", expected_enqueue)
dispatch = aggregate("dispatch_rungs", expected_dispatch)
if enqueue["0"]["hits"] == 0:
    raise SystemExit("wide work never entered an LLC-local normal queue")
if enqueue["0"]["misses"] == 0 or enqueue["1"]["hits"] == 0:
    raise SystemExit("pinned work never exercised the per-CPU enqueue escape")
for index, source in (("0", "CPU"), ("1", "local")):
    if dispatch[index]["selected"] == 0:
        raise SystemExit(f"{source} dispatch source never won arbitration")
if normal_queue_count >= 2 and dispatch["2"]["selected"] == 0:
    raise SystemExit("remote dispatch source never won arbitration")
if normal_queue_count == 1 and dispatch["2"]["selected"] != 0:
    raise SystemExit("remote dispatch source won with only one LLC queue")
if dispatch["3"]["hits"] == 0:
    raise SystemExit("min-vtime consume rung never dispatched work")

invalid_errors = sum(int(record.get("invalid_errors", 0)) for record in records)
accounting_errors = sum(int(record.get("vtime_accounting_errors", 0)) for record in records)
dispatch_calls = sum(int(record.get("dispatch_calls", 0)) for record in records)
if dispatch_calls == 0:
    raise SystemExit("dispatch callback counter never advanced")
if invalid_errors or accounting_errors:
    raise SystemExit(
        f"scheduler errors: invalid={invalid_errors} accounting={accounting_errors}"
    )
PY

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|BUG:|kernel panic'; then
    fail "kernel log contains a scheduler failure signature"
fi

if ((normal_queue_count >= 2)); then
    paths="local, CPU, and remote"
else
    paths="local and CPU (single LLC)"
fi
echo "PASS: global VTIME LLC queues preserved weighted shares and exercised ${paths} paths on ${cpus} CPUs"
