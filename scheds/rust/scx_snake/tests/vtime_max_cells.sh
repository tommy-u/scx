#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
layout=${SNAKE_QUEUE_LAYOUT:-cell}
duration=${SNAKE_MAX_CELLS_DURATION:-10}
expected_cpus=${SNAKE_EXPECT_CPUS:-}
cell0_weight=${SNAKE_CELL0_WEIGHT:-32}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
invalid_policy=${tmpdir}/invalid-policy.toml
topology_dump=${tmpdir}/topology.dump
topology_env=${tmpdir}/topology.env
invalid_log=${tmpdir}/invalid.log
snake_log=${tmpdir}/snake.ndjson
snake_pid=
stress_pid=
pinned_pid=
worker_pid=
dmesg_lines=0
cell_pids=()

pid_done() {
    local pid=$1
    local state

    [[ -r /proc/${pid}/stat ]] || return 0
    state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null || true)
    [[ ${state} == Z || -z ${state} ]]
}

stop_pid() {
    local pid=$1
    local signal=${2:-TERM}
    local attempt

    [[ -n ${pid} ]] || return 0
    kill "-${signal}" "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 30; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "${pid}" 2>/dev/null || true
    for ((attempt = 0; attempt < 10; attempt++)); do
        if pid_done "${pid}"; then
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
}

cleanup() {
    local pid

    kill "${stress_pid}" "${pinned_pid}" "${worker_pid}" 2>/dev/null || true
    if ((${#cell_pids[@]})); then
        kill "${cell_pids[@]}" 2>/dev/null || true
    fi
    kill -CONT "${pinned_pid}" "${worker_pid}" 2>/dev/null || true
    if ((${#cell_pids[@]})); then
        kill -CONT "${cell_pids[@]}" 2>/dev/null || true
    fi
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${stress_pid}"
    stop_pid "${pinned_pid}"
    for pid in "${cell_pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    for pid in "${cell_pids[@]}"; do
        stop_pid "${pid}"
    done
    stop_pid "${worker_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "vtime max-cells test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    grep -E '^queue topology:|^  cell 0 ' "${topology_dump}" >&2 2>/dev/null || true
    if command -v python3 >/dev/null && [[ -s ${snake_log} ]]; then
        python3 - "${snake_log}" >&2 <<'PY' || true
import json
import sys

records = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "cells" in value:
            records.append(value)
if records:
    cell0 = {
        key: sum(record["cells"].get("0", {}).get(key, 0) for record in records)
        for key in (
            "runtime_ns",
            "primary_runtime_ns",
            "borrowed_runtime_ns",
            "normal_enqueues",
            "normal_dispatches",
            "affinity_enqueues",
            "affinity_dispatches",
        )
    }
    active = {
        int(cpu)
        for record in records
        for cpu, value in record.get("cpus", {}).items()
        if value.get("runtime_ns", 0)
    }
    print(
        "compact stats:",
        {
            "records": len(records),
            "enqueues": sum(record.get("vtime_enqueues", 0) for record in records),
            "dispatches": sum(record.get("vtime_dispatches", 0) for record in records),
            "direct": sum(record.get("direct_dispatches", 0) for record in records),
            "active_cpus": len(active),
            "cell0": cell0,
        },
    )
PY
    fi
    tail -n 20 "${snake_log}" 2>/dev/null | cut -c 1-2000 >&2 || true
    cat "${invalid_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

wait_for_enabled() {
    local deadline=$((SECONDS + 10))

    while (( SECONDS < deadline )); do
        scheduler_enabled && return 0
        sleep 0.05
    done
    return 1
}

wait_for_stopped() {
    local pid=$1 state
    local deadline=$((SECONDS + 5))

    while (( SECONDS < deadline )); do
        [[ -r /proc/${pid}/status ]] || return 1
        state=$(awk '$1 == "State:" { print $2 }' "/proc/${pid}/status")
        [[ ${state} == T || ${state} == t ]] && return 0
        sleep 0.02
    done
    return 1
}

start_stopped_worker() {
    local cpu=${1:-}

    if [[ -n ${cpu} ]]; then
        taskset -c "${cpu}" bash -c 'kill -STOP "$$"; exec yes >/dev/null' &
    else
        bash -c 'kill -STOP "$$"; exec yes >/dev/null' &
    fi
    worker_pid=$!
    wait_for_stopped "${worker_pid}" || fail "worker ${worker_pid} did not stop for setup"
}

write_policy() {
    local path=$1 declared=$2 id

    {
        printf '%s\n' \
            '[queues]' \
            "layout = \"${layout}\"" \
            "cell0_cpu_weight = ${cell0_weight}"
        for ((id = 1; id <= declared; id++)); do
            printf '%s\n' \
                '' \
                '[[cell]]' \
                "id = ${id}" \
                'cpu_weight = 1' \
                "cpus = \"${online_cpu_list}\""
        done
        printf '%s\n' \
            '' \
            '[[rung]]' \
            'operation = "pick_idle"' \
            'scope = "task_cell_borrowable"' \
            '' \
            '[[rung]]' \
            'operation = "pick_idle"' \
            'scope = "task_cell"' \
            '' \
            '[[rung]]' \
            'operation = "pick_idle"' \
            'scope = "task_allowed"'
    } >"${path}"
}

(( EUID == 0 )) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${layout} == cell || ${layout} == cell_llc ]] ||
    fail "SNAKE_QUEUE_LAYOUT must be cell or cell_llc"
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ ${cell0_weight} =~ ^[1-9][0-9]*$ ]] ||
    fail "SNAKE_CELL0_WEIGHT must be a positive integer"
if [[ -n ${expected_cpus} ]]; then
    [[ ${expected_cpus} =~ ^[0-9]+$ ]] ||
        fail "SNAKE_EXPECT_CPUS must be a non-negative integer"
fi
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
for command in awk python3 stress-ng taskset timeout yes; do
    command -v "${command}" >/dev/null || fail "${command} is required"
done
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"

cpus=$(nproc)
online_cpu_list=$(< /sys/devices/system/cpu/online)
(( cpus >= 256 )) || fail "requires at least 256 CPUs"
if [[ -n ${expected_cpus} && ${expected_cpus} -gt 0 && ${cpus} -ne ${expected_cpus} ]]; then
    fail "expected ${expected_cpus} CPUs, found ${cpus}"
fi

write_policy "${policy}" 255
write_policy "${invalid_policy}" 256

if "${snake_bin}" --policy "${invalid_policy}" --dump-compiled-policy \
    >"${invalid_log}" 2>&1; then
    fail "a queue policy with 256 declared cells unexpectedly compiled"
fi
grep -q 'at most 255 declared cells' "${invalid_log}" ||
    fail "256-cell rejection returned the wrong error"

"${snake_bin}" --policy "${policy}" --dump-compiled-policy >"${topology_dump}" ||
    fail "failed to dump the 255-cell queue topology"

if ! python3 - "${topology_dump}" "${layout}" "${cpus}" \
    "${online_cpu_list}" "${cell0_weight}" >"${topology_env}" <<'PY'
import glob
import os
import re
import sys


def cpuset(text):
    result = set()
    if not text:
        return result
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, last = (int(value) for value in part.split("-", 1))
            result.update(range(first, last + 1))
        else:
            result.add(int(part))
    return result


dump_path, expected_layout, cpu_count, online_list, cell0_weight = sys.argv[1:]
cpu_count = int(cpu_count)
cell0_weight = int(cell0_weight)
available = cpuset(online_list)
if len(available) != cpu_count:
    raise SystemExit(
        f"nproc/sysfs CPU mismatch: nproc={cpu_count} online={len(available)}"
    )


def cpu_llc_identity(cpu):
    base = f"/sys/devices/system/cpu/cpu{cpu}"
    nodes = sorted(glob.glob(f"{base}/node[0-9]*"))
    node = int(nodes[0].rsplit("node", 1)[1]) if nodes else 0
    with open(f"{base}/topology/physical_package_id", encoding="utf-8") as stream:
        package = int(stream.read().strip())
    cache_id = None
    for index in (3, 2):
        path = f"{base}/cache/index{index}/id"
        if os.path.exists(path):
            with open(path, encoding="utf-8") as stream:
                cache_id = int(stream.read().strip())
            break
    if cache_id is None:
        cache_id = 0
    return node, package, cache_id

with open(dump_path, encoding="utf-8") as stream:
    lines = [line.rstrip() for line in stream]
text = "\n".join(lines)

header = re.search(
    r"^queue topology: layout=(cell|cell_llc) clocks=(\d+) cells=(\d+) "
    r"normal_queues=(\d+) affinity_queues=(\d+)$",
    text,
    re.MULTILINE,
)
if not header:
    raise SystemExit("queue topology header is missing")
layout = header.group(1)
clock_count, cell_count, normal_count, affinity_count = map(int, header.groups()[1:])
if layout != expected_layout:
    raise SystemExit(f"layout mismatch: {layout} != {expected_layout}")
if cell_count != 256:
    raise SystemExit(f"expected 256 total cells, found {cell_count}")
if clock_count != cell_count:
    raise SystemExit(f"expected one clock per cell, found {clock_count} clocks")
if affinity_count != cpu_count:
    raise SystemExit(
        f"expected one affinity queue per CPU ({cpu_count}), found {affinity_count}"
    )

cell_pattern = re.compile(
    r"^\s*cell (\d+) \(index (\d+)\): cpu_weight=(\d+) "
    r"primary=\[([0-9,]*)\] borrowable=\[([0-9,]*)\] "
    r"normal_queues=\[([^]]*)\]$"
)
queue_pattern = re.compile(
    r"^\s*normal queue (\d+): cell_index=Some\((\d+)\) clock_index=(\d+) "
    r"llc=(None|Some\((\d+)\)) consumers=\[([0-9,]*)\]$"
)

cells = {}
for line in lines:
    match = cell_pattern.match(line)
    if not match:
        continue
    external_id, index, weight = map(int, match.groups()[:3])
    if index in cells:
        raise SystemExit(f"duplicate cell index in topology dump: {index}")
    normal_ids = [
        int(value.strip())
        for value in match.group(6).split(",")
        if value.strip()
    ]
    cells[index] = {
        "external_id": external_id,
        "weight": weight,
        "primary": cpuset(match.group(4)),
        "borrowable": cpuset(match.group(5)),
        "normal_ids": normal_ids,
    }

if set(cells) != set(range(256)):
    raise SystemExit(f"unexpected dense cell indices: {sorted(cells)}")
if {cell["external_id"] for cell in cells.values()} != set(range(256)):
    raise SystemExit("external cell IDs are not exactly 0 through 255")
expected_weights = {index: (cell0_weight if index == 0 else 1) for index in cells}
observed_weights = {index: cell["weight"] for index, cell in cells.items()}
if observed_weights != expected_weights:
    raise SystemExit(
        f"cell weights differ from policy: {observed_weights} != {expected_weights}"
    )

distributable = cpu_count - len(cells)
total_weight = sum(expected_weights.values())
targets = {}
remainders = []
assigned = len(cells)
for index, weight in expected_weights.items():
    numerator = distributable * weight
    extra, remainder = divmod(numerator, total_weight)
    targets[index] = 1 + extra
    assigned += extra
    remainders.append((-remainder, index))
for _, index in sorted(remainders)[: cpu_count - assigned]:
    targets[index] += 1

primary_union = set()
for index, cell in cells.items():
    primary = cell["primary"]
    overlap = primary_union & primary
    if overlap:
        raise SystemExit(
            f"primary allocation overlaps at cell index {index}: {sorted(overlap)}"
        )
    if not primary:
        raise SystemExit(f"cell index {index} has no primary CPU")
    primary_union.update(primary)
    if len(primary) != targets[index]:
        raise SystemExit(
            f"cell index {index} owns {len(primary)} CPUs, expected {targets[index]}"
        )
    expected_borrowable = available - primary
    if cell["borrowable"] != expected_borrowable:
        raise SystemExit(
            f"cell index {index} borrowable mask does not equal claimed-minus-primary"
        )
if primary_union != available:
    raise SystemExit("primary allocation does not cover every online CPU exactly once")

queues = {}
for line in lines:
    match = queue_pattern.match(line)
    if not match:
        continue
    index, cell_index, clock_index = map(int, match.groups()[:3])
    if index in queues:
        raise SystemExit(f"duplicate normal queue index in topology dump: {index}")
    llc_id = None if match.group(4) == "None" else int(match.group(5))
    queues[index] = {
        "cell_index": cell_index,
        "clock_index": clock_index,
        "llc_id": llc_id,
        "consumers": cpuset(match.group(6)),
    }

if set(queues) != set(range(normal_count)):
    raise SystemExit(
        f"normal queue IDs are not dense: expected 0..{normal_count - 1}, "
        f"found {sorted(queues)}"
    )
if normal_count > cpu_count:
    raise SystemExit(
        f"normal queue count scales past CPU count: {normal_count} > {cpu_count}"
    )
# A cell-by-CPU design would create 256 * cpu_count normal queues. The actual
# topology must instead be one queue per cell or per nonempty cell/LLC pair.
if normal_count >= cell_count * cpu_count:
    raise SystemExit("normal topology unexpectedly has a cell-by-CPU queue shape")

observed_pairs = set()
observed_identity_pairs = set()
advertised_queues = set()
for index, cell in cells.items():
    advertised = cell["normal_ids"]
    if not advertised:
        raise SystemExit(f"cell index {index} advertises no normal queues")
    if len(advertised) != len(set(advertised)):
        raise SystemExit(f"cell index {index} repeats a normal queue")
    consumers = set()
    for queue_id in advertised:
        if queue_id not in queues:
            raise SystemExit(f"cell index {index} references queue {queue_id} out of range")
        if queue_id in advertised_queues:
            raise SystemExit(f"normal queue {queue_id} is advertised by multiple cells")
        advertised_queues.add(queue_id)
        queue = queues[queue_id]
        if queue["cell_index"] != index:
            raise SystemExit(f"queue {queue_id} belongs to the wrong cell")
        if queue["clock_index"] != index:
            raise SystemExit(
                f"queue {queue_id} uses clock {queue['clock_index']} instead of cell {index}"
            )
        if not queue["consumers"]:
            raise SystemExit(f"queue {queue_id} has no consumers")
        overlap = consumers & queue["consumers"]
        if overlap:
            raise SystemExit(
                f"cell index {index} queue consumers overlap: {sorted(overlap)}"
            )
        consumers.update(queue["consumers"])
        pair = (index, queue["llc_id"])
        if pair in observed_pairs:
            raise SystemExit(f"duplicate normal queue for cell/LLC pair {pair}")
        observed_pairs.add(pair)
        if layout == "cell_llc":
            identities = {cpu_llc_identity(cpu) for cpu in queue["consumers"]}
            if len(identities) != 1:
                raise SystemExit(
                    f"queue {queue_id} crosses guest LLC identities: {sorted(identities)}"
                )
            identity_pair = (index, next(iter(identities)))
            if identity_pair in observed_identity_pairs:
                raise SystemExit(
                    f"cell index {index} repeats guest LLC identity {identity_pair[1]}"
                )
            observed_identity_pairs.add(identity_pair)
    if consumers != cell["primary"]:
        raise SystemExit(f"normal queues do not partition cell index {index}'s primary CPUs")
if advertised_queues != set(queues):
    raise SystemExit(
        f"orphan normal queues in topology: {sorted(set(queues) - advertised_queues)}"
    )

if layout == "cell":
    if normal_count != 256:
        raise SystemExit(f"cell layout expected 256 normal queues, found {normal_count}")
    if any(queue["llc_id"] is not None for queue in queues.values()):
        raise SystemExit("cell layout unexpectedly emitted LLC-sharded queues")
    if any(len(cell["normal_ids"]) != 1 for cell in cells.values()):
        raise SystemExit("cell layout did not emit exactly one normal queue per cell")
else:
    if any(queue["llc_id"] is None for queue in queues.values()):
        raise SystemExit("cell_llc layout emitted an unsharded normal queue")
    llcs = {queue["llc_id"] for queue in queues.values()}
    if any(len(cell["normal_ids"]) > len(llcs) for cell in cells.values()):
        raise SystemExit("a cell has more queues than the number of observed LLCs")
    expected_pairs = {
        (index, cpu_llc_identity(cpu))
        for index, cell in cells.items()
        for cpu in cell["primary"]
    }
    if observed_identity_pairs != expected_pairs:
        raise SystemExit(
            "cell_llc queues do not exactly cover occupied guest LLC identities"
        )

clock_indices = {queue["clock_index"] for queue in queues.values()}
if clock_indices != set(range(256)):
    raise SystemExit(
        f"normal queues do not use exactly one clock namespace per cell: {clock_indices}"
    )

cell1 = next(cell for cell in cells.values() if cell["external_id"] == 1)
outside = sorted(available - cell1["primary"])
if not outside:
    raise SystemExit("cell 1 has no outside CPU for affinity-queue coverage")
print(f"CELL1_OUTSIDE_CPU={outside[0]}")
print(f"NORMAL_QUEUE_COUNT={normal_count}")
PY
then
    fail "compiled topology validation failed"
fi
# The topology parser emits only numeric shell assignments.
# shellcheck disable=SC1090
source "${topology_env}"
[[ ${CELL1_OUTSIDE_CPU} =~ ^[0-9]+$ ]] || fail "invalid outside CPU from topology"

dmesg_lines=$(dmesg | wc -l)
"${snake_bin}" --policy "${policy}" --fairness vtime --stats 0.25 \
    --stats-format json >"${snake_log}" 2>&1 &
snake_pid=$!
wait_for_enabled || fail "scheduler did not attach"

# Each explicit cell gets a CPU-bound task. Stopping the task before assigning
# its cell makes its first runnable transition deterministic and gives the
# borrowable rung an idle-CPU opportunity before saturation.
for ((cell_id = 1; cell_id <= 255; cell_id++)); do
    start_stopped_worker
    cell_pids+=("${worker_pid}")
    "${snake_bin}" --set-thread-cell "${worker_pid}:${cell_id}" >/dev/null ||
        fail "failed to assign worker ${worker_pid} to cell ${cell_id}"
    kill -CONT "${worker_pid}"
done
sleep 1
scheduler_enabled || fail "scheduler exited while starting cell workers"

# Force an observed clock translation for every explicit cell. The workers are
# already CPU-bound, so one second is many scheduler slices between updates.
for ((cell_id = 1; cell_id <= 255; cell_id++)); do
    next_cell=$(((cell_id % 255) + 1))
    "${snake_bin}" --set-thread-cell "${cell_pids[cell_id - 1]}:${next_cell}" \
        >/dev/null || fail "failed to move worker from cell ${cell_id} to ${next_cell}"
done
sleep 1
scheduler_enabled || fail "scheduler exited during cross-cell transition"
for ((cell_id = 1; cell_id <= 255; cell_id++)); do
    "${snake_bin}" --set-thread-cell "${cell_pids[cell_id - 1]}:${cell_id}" \
        >/dev/null || fail "failed to return worker to cell ${cell_id}"
done
sleep 1
scheduler_enabled || fail "scheduler exited while restoring cell workers"

# Keep one cell-1 task outside cell 1's primary mask. It remains stopped until
# the nproc*2 load has removed idle-CPU opportunities, forcing affinity-queue
# enqueue and dispatch instead of select-time direct borrowing.
start_stopped_worker "${CELL1_OUTSIDE_CPU}"
pinned_pid=${worker_pid}
"${snake_bin}" --set-thread-cell "${pinned_pid}:1" >/dev/null ||
    fail "failed to assign the affinity-restricted worker"

timeout --signal=TERM --kill-after=5s "$((duration + 30))s" \
    stress-ng --cpu $((cpus * 2)) --cpu-method loop --timeout "${duration}s" \
    >/dev/null 2>&1 &
stress_pid=$!
sleep 1
kill -CONT "${pinned_pid}"

deadline=$((SECONDS + duration + 35))
while ! pid_done "${stress_pid}"; do
    scheduler_enabled || fail "scheduler exited during max-cell stress"
    ((SECONDS < deadline)) || fail "nproc*2 CPU stress did not finish"
    sleep 0.1
done
stress_rc=0
wait "${stress_pid}" || stress_rc=$?
stress_pid=
((stress_rc == 0)) || fail "nproc*2 CPU stress failed with status ${stress_rc}"

kill "${pinned_pid}" "${cell_pids[@]}" 2>/dev/null || true
stop_pid "${pinned_pid}"
pinned_pid=
for pid in "${cell_pids[@]}"; do
    stop_pid "${pid}"
done
cell_pids=()
sleep 1
scheduler_enabled || fail "scheduler exited after max-cell stress"

if ! python3 - "${snake_log}" "${cpus}" <<'PY'
import json
import sys


log_path, cpu_count = sys.argv[1:]
cpu_count = int(cpu_count)
records = []
with open(log_path, encoding="utf-8") as stream:
    for line in stream:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "cells" in record:
            records.append(record)
if not records:
    raise SystemExit("no cell statistics records were emitted")

expected_cells = set(range(256))
seen_cells = set()
runtime = {cell: 0 for cell in expected_cells}
primary = {cell: 0 for cell in expected_cells}
borrowed_by_cell = {cell: 0 for cell in expected_cells}
normal_enqueues = {cell: 0 for cell in expected_cells}
normal_dispatches = {cell: 0 for cell in expected_cells}
affinity_enqueues = {cell: 0 for cell in expected_cells}
affinity_dispatches = {cell: 0 for cell in expected_cells}
clock_transitions = {cell: 0 for cell in expected_cells}
lent = 0
direct_dispatches = 0
direct_runtime = 0
borrow_hits = 0
active_cpus = set()

for record in records:
    if record.get("invalid_errors", 0):
        raise SystemExit("Snake reported invalid errors")
    if record.get("vtime_accounting_errors", 0):
        raise SystemExit("Snake reported VTIME accounting errors")
    direct_dispatches += record.get("direct_dispatches", 0)
    direct_runtime += record.get("vtime_direct_runtime_ns", 0)
    borrow_hits += record.get("rungs", {}).get("0", {}).get("hits", 0)
    for rung in record.get("rungs", {}).values():
        if rung.get("errors", 0):
            raise SystemExit(f"placement rung reported errors: {rung}")
    for key, cell in record["cells"].items():
        cell_id = int(key)
        seen_cells.add(cell_id)
        if cell_id not in expected_cells:
            raise SystemExit(f"unexpected cell ID in statistics: {cell_id}")
        runtime[cell_id] += cell.get("runtime_ns", 0)
        primary[cell_id] += cell.get("primary_runtime_ns", 0)
        borrowed_by_cell[cell_id] += cell.get("borrowed_runtime_ns", 0)
        lent += cell.get("lent_runtime_ns", 0)
        normal_enqueues[cell_id] += cell.get("normal_enqueues", 0)
        normal_dispatches[cell_id] += cell.get("normal_dispatches", 0)
        affinity_enqueues[cell_id] += cell.get("affinity_enqueues", 0)
        affinity_dispatches[cell_id] += cell.get("affinity_dispatches", 0)
        clock_transitions[cell_id] += cell.get("clock_transitions", 0)
    for key, cpu in record.get("cpus", {}).items():
        if cpu.get("runtime_ns", 0):
            active_cpus.add(int(key))

if seen_cells != expected_cells:
    raise SystemExit(f"statistics omitted cells: {sorted(expected_cells - seen_cells)}")
for cell_id in sorted(expected_cells):
    if runtime[cell_id] == 0:
        raise SystemExit(f"cell {cell_id} received no runtime")
    if normal_enqueues[cell_id] == 0 or normal_dispatches[cell_id] == 0:
        raise SystemExit(
            f"cell {cell_id} did not exercise its normal queue: "
            f"enqueues={normal_enqueues[cell_id]} dispatches={normal_dispatches[cell_id]}"
        )
    identity_skew = abs(runtime[cell_id] - primary[cell_id] - borrowed_by_cell[cell_id])
    identity_tolerance = max(5_000_000, runtime[cell_id] // 200)
    if identity_skew > identity_tolerance:
        raise SystemExit(
            f"cell {cell_id} runtime identity mismatch: runtime={runtime[cell_id]} "
            f"primary={primary[cell_id]} borrowed={borrowed_by_cell[cell_id]} "
            f"skew={identity_skew} tolerance={identity_tolerance}"
        )

borrowed = sum(borrowed_by_cell.values())
resource_skew = abs(borrowed - lent)
# Cell entries are sampled sequentially while 256 CPUs may still be charging
# service. Allow endpoint skew without making a persistent accounting loss pass.
resource_tolerance = max(50_000_000, max(borrowed, lent) // 50)
if borrowed == 0 or resource_skew > resource_tolerance:
    raise SystemExit(
        f"borrowed/lent accounting mismatch: borrowed={borrowed} lent={lent} "
        f"skew={resource_skew} tolerance={resource_tolerance}"
    )
borrowed_cells = {cell for cell, value in borrowed_by_cell.items() if value}
if len(borrowed_cells) < 16:
    raise SystemExit(
        f"borrowing reached too few cells: {len(borrowed_cells)} {sorted(borrowed_cells)}"
    )
if direct_dispatches == 0 or direct_runtime == 0 or borrow_hits == 0:
    raise SystemExit(
        f"select-time borrowing was not exercised: direct={direct_dispatches} "
        f"runtime={direct_runtime} rung0_hits={borrow_hits}"
    )
if sum(affinity_enqueues.values()) == 0 or sum(affinity_dispatches.values()) == 0:
    raise SystemExit("the per-CPU affinity escape queues were not exercised")
if affinity_enqueues[1] == 0 or affinity_dispatches[1] == 0:
    raise SystemExit("the cell-1 restricted task did not traverse an affinity queue")
missing_transitions = [
    cell for cell in range(1, 256) if clock_transitions[cell] == 0
]
if missing_transitions:
    raise SystemExit(
        f"explicit cells without task clock transitions: {missing_transitions}"
    )
required_active = max(32, (cpu_count * 3) // 4)
if len(active_cpus) < required_active:
    raise SystemExit(
        f"work ran on too few CPUs: {len(active_cpus)} < {required_active}"
    )
PY
then
    fail "max-cell runtime/statistics validation failed"
fi

if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall|watchdog)|snake.*(error|stall)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler or kernel error"
fi

echo "PASS: ${layout} max-cell VTIME topology (${NORMAL_QUEUE_COUNT} normal queues) survived nproc*2 stress on ${cpus} CPUs"
