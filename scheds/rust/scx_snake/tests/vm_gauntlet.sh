#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${SNAKE_REPO:-$(cd -- "${script_dir}/../../../.." && pwd)}
snake_bin=${1:-${repo}/target/release/scx_snake}
artifact=${SNAKE_ARTIFACT:-$(mktemp -d /tmp/scx-snake-vm-gauntlet.XXXXXX)}
mkdir -p "${artifact}"
dmesg_lines=0

cleanup() {
    local rc=$?

    trap - EXIT INT TERM
    set +e
    dmesg >"${artifact}/dmesg-full.txt" 2>&1
    dmesg | tail -n +$((dmesg_lines + 1)) >"${artifact}/dmesg-new.txt" 2>&1
    printf '%s\n' "${rc}" >"${artifact}/gauntlet.rc"
    printf 'artifacts: %s\n' "${artifact}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "Snake VM gauntlet: $*" >&2
    exit 1
}

run_case() {
    local name=$1
    shift

    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
        fail "sched_ext is enabled before ${name}"
    printf 'START %s\n' "${name}" | tee -a "${artifact}/summary.log"
    if ! "$@" >"${artifact}/${name}.log" 2>&1; then
        printf 'FAIL %s\n' "${name}" | tee -a "${artifact}/summary.log"
        tail -n 200 "${artifact}/${name}.log" >&2 || true
        return 1
    fi
    [[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
        fail "${name} left sched_ext enabled"
    printf 'PASS %s\n' "${name}" | tee -a "${artifact}/summary.log"
}

((EUID == 0)) || fail "must run as root inside a VM"
if command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt --vm --quiet || fail "refusing to run outside a VM"
else
    grep -qw hypervisor /proc/cpuinfo || fail "refusing to run outside a VM"
fi
[[ -x ${snake_bin} ]] || fail "scheduler binary is not executable: ${snake_bin}"
[[ $(cat /sys/kernel/sched_ext/state 2>/dev/null || true) == disabled ]] ||
    fail "sched_ext must be disabled before the gauntlet"

cp "$0" "${artifact}/gauntlet.sh"
cp "${snake_bin}" "${artifact}/scx_snake"
chmod +x "${artifact}/scx_snake"
cp -a "${script_dir}" "${artifact}/tests"
sha256sum "${artifact}/scx_snake" >"${artifact}/snake.sha256"
git -c safe.directory="${repo}" -C "${repo}" rev-parse HEAD \
    >"${artifact}/git-head.txt"
git -c safe.directory="${repo}" -C "${repo}" status --short \
    >"${artifact}/git-status.txt"
git -c safe.directory="${repo}" -C "${repo}" diff --binary HEAD -- \
    >"${artifact}/worktree.patch"
printf 'SNAKE_REPO=%q %q %q\n' \
    "${repo}" "${artifact}/tests/vm_gauntlet.sh" "${artifact}/scx_snake" \
    >"${artifact}/rerun-command.txt"
nproc >"${artifact}/nproc.txt"
dmesg >"${artifact}/dmesg-before.txt"
dmesg_lines=$(dmesg | wc -l)

run_case fifo_fallback "${script_dir}/fifo_fallback.sh" "${snake_bin}"
run_case vtime_cell_fairness "${script_dir}/vtime_cell_fairness.sh" "${snake_bin}"
run_case vtime_cell_queues \
    env SNAKE_QUEUE_LAYOUT=cell "${script_dir}/vtime_cell_queues.sh" "${snake_bin}"
run_case vtime_cell_llc_queues \
    env SNAKE_QUEUE_LAYOUT=cell_llc "${script_dir}/vtime_cell_queues.sh" "${snake_bin}"
run_case vtime_cell_borrowing \
    env SNAKE_QUEUE_LAYOUT=cell "${script_dir}/vtime_cell_borrowing.sh" "${snake_bin}"
run_case vtime_cell_llc_borrowing \
    env SNAKE_QUEUE_LAYOUT=cell_llc "${script_dir}/vtime_cell_borrowing.sh" "${snake_bin}"
run_case vtime_mixed_affinity "${script_dir}/vtime_mixed_affinity.sh" "${snake_bin}"
llc_policy=${repo}/scheds/rust/scx_snake/examples/kernel-default-sim.toml
run_case vtime_llc_queues \
    "${script_dir}/vtime_llc_queues.sh" "${snake_bin}" "${llc_policy}"
run_case vtime_policy_reader_lifetime \
    "${script_dir}/vtime_policy_reader_lifetime.sh" "${snake_bin}"
run_case vtime_queue_ladders "${script_dir}/vtime_queue_ladders.sh" "${snake_bin}"
run_case vtime_queued_rehome "${script_dir}/vtime_queued_rehome.sh" "${snake_bin}"
run_case vtime_single_runner_rehome \
    env SNAKE_REHOME_ARTIFACT="${artifact}/vtime-single-runner-rehome" \
    "${script_dir}/vtime_single_runner_rehome.sh" "${snake_bin}"

if (( $(nproc) >= 2 )); then
    run_case vtime_managed_cell_churn \
        "${script_dir}/vtime_managed_cell_churn.sh" "${snake_bin}" \
        "${repo}/scheds/rust/scx_snake/examples/mitosis-sim.toml"
    run_case eevdf_mixed_affinity \
        env SNAKE_EEVDF_STALL_ARTIFACT="${artifact}/eevdf-mixed-affinity" \
        "${script_dir}/eevdf_stall_workload.sh" "${snake_bin}" \
        "${repo}/scheds/rust/scx_snake/examples/basic.toml" mixed_affinity
    run_case eevdf_fork_yield \
        env SNAKE_EEVDF_STALL_ARTIFACT="${artifact}/eevdf-fork-yield" \
        "${script_dir}/eevdf_stall_workload.sh" "${snake_bin}" \
        "${repo}/scheds/rust/scx_snake/examples/basic.toml" fork_yield
fi

if (( $(nproc) >= 6 )); then
    run_case vtime_managed_cell_resizing \
        "${script_dir}/vtime_managed_cell_resizing.sh" "${snake_bin}" \
        "${repo}/scheds/rust/scx_snake/examples/mitosis-sim.toml"
fi

if (( $(nproc) >= 32 )); then
    run_case vtime_max_cells \
        env SNAKE_QUEUE_LAYOUT=cell "${script_dir}/vtime_max_cells.sh" "${snake_bin}"
    run_case vtime_max_cells_llc \
        env SNAKE_QUEUE_LAYOUT=cell_llc "${script_dir}/vtime_max_cells.sh" "${snake_bin}"
fi
if (( $(nproc) >= 128 )); then
    run_case vtime_low_weight_yield \
        env SNAKE_ARTIFACT="${artifact}/vtime-low-weight" \
        SNAKE_EXPECT_CPUS="$(nproc)" \
        "${script_dir}/vtime_low_weight_yield.sh" "${snake_bin}"
fi

dmesg | tail -n +$((dmesg_lines + 1)) >"${artifact}/dmesg-new.txt"
if grep -Eiq 'runnable task stall|scx_bpf_error|sched_ext:.*(error|stall|watchdog)|RCU.*stall|BUG:|kernel panic' \
    "${artifact}/dmesg-new.txt"; then
    fail "kernel log contains a scheduler failure signature"
fi

touch "${artifact}/PASS"
echo "PASS: Snake FIFO/VTIME/EEVDF VM gauntlet completed on $(nproc) CPUs"
