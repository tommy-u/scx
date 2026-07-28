#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
duration=${SNAKE_FIFO_DURATION:-8}
expected_cpus=${SNAKE_EXPECT_CPUS:-}
tmpdir=$(mktemp -d)
policy=${tmpdir}/policy.toml
snake_log=${tmpdir}/snake.log
stress_log=${tmpdir}/stress.log
burst_log=${tmpdir}/burst.log
snake_pid=
stress_pid=
burst_pid=
dmesg_lines=0

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
}

cleanup() {
    kill "${stress_pid}" "${burst_pid}" 2>/dev/null || true
    kill -INT "${snake_pid}" 2>/dev/null || true
    stop_pid "${stress_pid}"
    stop_pid "${burst_pid}"
    stop_pid "${snake_pid}" INT
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "fifo fallback test: $*" >&2
    dmesg | tail -n +$((dmesg_lines + 1)) >&2 || true
    tail -n 100 "${snake_log}" >&2 2>/dev/null || true
    tail -n 40 "${stress_log}" >&2 2>/dev/null || true
    tail -n 40 "${burst_log}" >&2 2>/dev/null || true
    exit 1
}

scheduler_enabled() {
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == enabled ]] &&
        kill -0 "${snake_pid}" 2>/dev/null
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ ${duration} =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
command -v stress-ng >/dev/null || fail "stress-ng is required"
command -v timeout >/dev/null || fail "timeout is required"
command -v python3 >/dev/null || fail "python3 is required"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the test"

cpus=$(nproc)
((cpus >= 2)) || fail "requires at least two CPUs"
[[ -z ${expected_cpus} || ${expected_cpus} =~ ^[0-9]+$ ]] ||
    fail "SNAKE_EXPECT_CPUS must be a non-negative integer"
if [[ -n ${expected_cpus} && ${expected_cpus} -gt 0 && ${cpus} -ne ${expected_cpus} ]]; then
    fail "expected ${expected_cpus} CPUs, found ${cpus}"
fi
dmesg_lines=$(dmesg | wc -l)

cat >"${policy}" <<EOF
[[cell]]
id = 1
cpus = "0-$((cpus - 1))"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
EOF

# No worker is annotated, so every selection exhausts the rung and exercises
# FIFO's non-direct enqueue path. This is the path that previously depended on
# the kernel's built-in global DSQ making forward progress on its own.
"${snake_bin}" --policy "${policy}" --fairness fifo --stats 0.25 \
    >"${snake_log}" 2>&1 &
snake_pid=$!
for _ in $(seq 1 200); do
    scheduler_enabled && break
    sleep 0.05
done
scheduler_enabled || fail "scheduler did not attach"

timeout --signal=TERM --kill-after=2s "$((duration + 5))s" \
    stress-ng --cpu $((cpus * 2)) --cpu-method loop --timeout "${duration}s" \
    >"${stress_log}" 2>&1 &
stress_pid=$!
deadline=$((SECONDS + duration + 8))
while ! pid_done "${stress_pid}"; do
    scheduler_enabled || fail "scheduler exited during fallback stress"
    ((SECONDS < deadline)) || fail "nproc*2 fallback stress did not finish"
    sleep 0.1
done
if ! wait "${stress_pid}"; then
    stress_pid=
    fail "nproc*2 fallback stress failed"
fi
stress_pid=
scheduler_enabled || fail "scheduler exited after fallback stress"

# Concentrate a mixed-affinity fork burst on CPU 0 before waking every child at
# once. With the default previous_cpu fallback, terminal local DSQs strand the
# burst on CPU 0; an explicitly consumed shared FIFO DSQ lets compatible CPUs
# drain it while narrow tasks remain affinity-safe.
timeout --signal=TERM --kill-after=2s 15s python3 - "${cpus}" \
    >"${burst_log}" 2>&1 <<'PY' &
import os
import sys
import time

cpus = int(sys.argv[1])
workers = min(1024, max(128, cpus * 64))
os.sched_setaffinity(0, {0})
ready_r, ready_w = os.pipe()
start_r, start_w = os.pipe()
result_r, result_w = os.pipe()
children = []

for index in range(workers):
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        os.close(start_w)
        os.close(result_r)
        os.sched_setaffinity(0, {0} if index % 8 == 0 else set(range(cpus)))
        os.write(ready_w, b"r")
        os.read(start_r, 1)
        deadline = time.process_time() + 0.02
        value = 1
        while time.process_time() < deadline:
            value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        with open("/proc/self/stat", encoding="utf-8") as stream:
            cpu = int(stream.read().split()[38])
        os.write(result_w, f"{cpu}\n".encode())
        os._exit(0)
    children.append(pid)

os.close(ready_w)
os.close(start_r)
os.close(result_w)
ready = b""
while len(ready) < workers:
    ready += os.read(ready_r, workers - len(ready))
os.write(start_w, b"s" * workers)
os.close(start_w)
failed = []
for pid in children:
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        failed.append((pid, status))
result = b""
while True:
    chunk = os.read(result_r, 4096)
    if not chunk:
        break
    result += chunk
records = result.splitlines()
if failed:
    raise SystemExit(f"FIFO burst children failed: {failed[:8]}")
if len(records) != workers:
    raise SystemExit(f"FIFO burst returned {len(records)} of {workers} CPU records")
active_cpus = {int(cpu) for cpu in records}
if len(active_cpus) < 2:
    raise SystemExit(f"shared FIFO burst used too few CPUs: {sorted(active_cpus)}")
print(f"active_cpus={len(active_cpus)}")
PY
burst_pid=$!
deadline=$((SECONDS + 18))
while ! pid_done "${burst_pid}"; do
    scheduler_enabled || fail "scheduler exited during concentrated fork burst"
    ((SECONDS < deadline)) || fail "concentrated fork burst did not finish"
    sleep 0.1
done
if ! wait "${burst_pid}"; then
    burst_pid=
    fail "concentrated fork burst failed"
fi
burst_pid=
scheduler_enabled || fail "scheduler exited after concentrated fork burst"

grep -Eq 'ladder exhausted: [1-9][0-9]*' "${snake_log}" ||
    fail "the fallback path was not exercised"
grep -Eq 'FIFO shared enqueues/dispatches: [1-9][0-9]*/[1-9][0-9]*' "${snake_log}" ||
    fail "fallback work did not traverse the explicit shared FIFO DSQ"
grep -Eq 'invalid/errors: [1-9][0-9]*' "${snake_log}" &&
    fail "Snake reported invalid errors"
if dmesg | tail -n +$((dmesg_lines + 1)) | \
    grep -Eiq 'scx_bpf_error|sched_ext:.*(error|stall|watchdog)|snake.*(error|stall)|RCU.*stall|soft lockup|hard LOCKUP|BUG:|Oops:|kernel panic'; then
    fail "kernel log contains a scheduler or kernel error"
fi

echo "PASS: FIFO ladder-exhaustion stress completed on ${cpus} CPUs"
