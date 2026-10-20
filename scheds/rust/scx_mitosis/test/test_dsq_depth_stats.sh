#!/bin/bash
# Run on an isolated sched_ext host/VM with no active scheduler.
# Verify shared enqueue backlog, completed-window caching and disabled output.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
[[ "$EUID" -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
[[ -x "$SCHEDULER_BIN" ]] || { echo "Scheduler binary missing: $SCHEDULER_BIN" >&2; exit 1; }
[[ -f /sys/kernel/sched_ext/state ]] || { echo "sched_ext unavailable" >&2; exit 1; }
[[ "$(cat /sys/kernel/sched_ext/state)" == disabled ]] || {
    echo "Refusing to replace an active scheduler; use an isolated host/VM" >&2
    exit 1
}
NUM_CPUS=$(nproc)
[[ "$NUM_CPUS" -ge 4 ]] || { echo "Need at least 4 CPUs" >&2; exit 1; }

ARTIFACT_DIR=$(mktemp -d /tmp/scx_mitosis_dsq_depth.XXXXXX)
CGROUP_PARENT="/sys/fs/cgroup/scx_dsq_depth_${$}_${RANDOM}"
WORKLOAD="$CGROUP_PARENT/workload"
SIBLING="$CGROUP_PARENT/empty_sibling"
WORKER_PIDS=()
SCHED_PID=""
MONITOR_PID=""
MONITOR_OUTPUT=""

stop_scheduler() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
    if [[ -n "$SCHED_PID" ]]; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        for ((attempt = 0; attempt < 50; attempt++)); do
            kill -0 "$SCHED_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
        SCHED_PID=""
    fi
}

cleanup() {
    stop_scheduler
    for pid in "${WORKER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${WORKER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rmdir "$SIBLING" "$WORKLOAD" "$CGROUP_PARENT" 2>/dev/null || true
    echo "Test logs: $ARTIFACT_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$CGROUP_PARENT" "$WORKLOAD"
# Cell-wide affinity and many more runnable workers than allocated CPUs force
# shared DSQ enqueues with a backlog, including after the sibling takes CPUs.
for ((worker = 0; worker < NUM_CPUS * 8; worker++)); do
    bash -c 'echo "$$" > "$1/cgroup.procs"; while :; do :; done' _ "$WORKLOAD" &
    WORKER_PIDS+=("$!")
done

start_scheduler() {
    local phase="$1"
    shift
    MONITOR_OUTPUT="$ARTIFACT_DIR/$phase.monitor.json"
    "$SCHEDULER_BIN" --cell-parent-cgroup "${CGROUP_PARENT#/sys/fs/cgroup}" "$@" \
        > "$ARTIFACT_DIR/$phase.scheduler.log" 2>&1 &
    SCHED_PID=$!
    for ((attempt = 0; attempt < 120; attempt++)); do
        kill -0 "$SCHED_PID" 2>/dev/null || {
            cat "$ARTIFACT_DIR/$phase.scheduler.log" >&2
            return 1
        }
        [[ "$(cat /sys/kernel/sched_ext/state)" == enabled ]] && break
        sleep 0.5
    done
    [[ "$(cat /sys/kernel/sched_ext/state)" == enabled ]] || {
        echo "Scheduler did not attach" >&2
        return 1
    }
    "$SCHEDULER_BIN" --monitor 0.5 > "$MONITOR_OUTPUT" 2> "$ARTIFACT_DIR/$phase.monitor.log" &
    MONITOR_PID=$!
}

# --monitor emits consecutive pretty-printed JSON objects. Ignore the last
# object if the writer has not finished it yet, as in test_cell_churn.sh.
latest_workload_metrics() {
    python3 - "$MONITOR_OUTPUT" "${WORKLOAD#/sys/fs/cgroup}" <<'PY'
import json
import sys

text = open(sys.argv[1]).read()
decoder = json.JSONDecoder()
latest = None
pos = 0
while pos < len(text):
    while pos < len(text) and text[pos].isspace():
        pos += 1
    try:
        latest, pos = decoder.raw_decode(text, pos)
    except json.JSONDecodeError:
        break
if latest is None:
    sys.exit(1)
for cell in latest.get("cells", {}).values():
    if cell.get("cgroup_path") == sys.argv[2]:
        print(cell["shared_dsq_enqueue_depth_p99"], latest["num_cells"], cell["num_cpus"])
        break
else:
    sys.exit(1)
PY
}

start_scheduler enabled --enable-dsq-depth-stats
deadline=$((SECONDS + 90))
p99=0
while ((SECONDS < deadline)); do
    kill -0 "$SCHED_PID" 2>/dev/null || { echo "Scheduler exited" >&2; exit 1; }
    if metrics=$(latest_workload_metrics 2>/dev/null); then
        read -r p99 cells cpus <<< "$metrics"
        [[ "$p99" -gt 0 && "$cells" -eq 2 && "$cpus" -gt 0 ]] && break
    fi
    sleep 0.5
done
[[ "$p99" -gt 0 ]] || { echo "No positive P99 within 90 seconds" >&2; exit 1; }
cached_p99="$p99"

# Several reports inside the next window must retain the completed result.
for ((report = 0; report < 4; report++)); do
    sleep 1
    read -r p99 cells cpus <<< "$(latest_workload_metrics)"
    [[ "$p99" -eq "$cached_p99" ]] || { echo "P99 cache changed between windows" >&2; exit 1; }
done

mkdir "$SIBLING"
deadline=$((SECONDS + 15))
while ((SECONDS < deadline)); do
    read -r p99 cells cpus <<< "$(latest_workload_metrics)"
    [[ "$p99" -eq "$cached_p99" ]] || { echo "Reconfiguration lost cached P99" >&2; exit 1; }
    [[ "$cells" -eq 3 ]] && break
    sleep 0.5
done
[[ "$cells" -eq 3 ]] || { echo "Empty sibling cell did not appear" >&2; exit 1; }
for ((report = 0; report < 4; report++)); do
    sleep 1
    read -r p99 cells cpus <<< "$(latest_workload_metrics)"
    [[ "$p99" -eq "$cached_p99" ]] || { echo "Sibling refresh lost cached P99" >&2; exit 1; }
done

stop_scheduler
rmdir "$SIBLING"
start_scheduler disabled
deadline=$((SECONDS + 15))
cells=0
while ((SECONDS < deadline)); do
    if metrics=$(latest_workload_metrics 2>/dev/null); then
        read -r p99 cells cpus <<< "$metrics"
        [[ "$cells" -eq 2 && "$cpus" -gt 0 ]] && break
    fi
    sleep 0.5
done
[[ "$cells" -eq 2 ]] || { echo "Disabled workload cell did not appear" >&2; exit 1; }
for ((report = 0; report < 4; report++)); do
    sleep 1
    read -r p99 cells cpus <<< "$(latest_workload_metrics)"
    [[ "$p99" -eq 0 ]] || { echo "Disabled metric was nonzero" >&2; exit 1; }
done

echo "PASS: positive shared DSQ depth P99=$cached_p99, cached across refresh; disabled output=0"
