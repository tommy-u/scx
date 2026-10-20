#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Compile the checkout's stopping/enqueue callbacks with userspace fixtures.
# No scheduler is loaded or replaced.
set -eu

usage() {
    cat <<'HELP'
Usage: weighted_debt_cap.sh [--source CHECKOUT]

Reproduce legitimate low-weight borrowing debt being truncated at enqueue.
Compile actual cap_vtime_debt(), mitosis_stopping(), and mitosis_enqueue()
C functions from a checkout and run them with a fixed userspace fixture.
This checks the accounting mechanism; it does not execute BPF in the kernel
or measure a live workload's CPU share.

The fixture gives a weight-1 task one full borrowed slice with LLC awareness
disabled, then queues it in its unchanged home domain. Borrowing skips the
domain clock update, so that slice legitimately owes 100 slice units.
A weight-100 task is the control.

--source accepts the repository root, scx_mitosis directory, or src/bpf.
MITOSIS_SOURCE supplies the same override. Otherwise search the current
directory's ancestors, then the script's ancestors. CC selects a compiler.
Requires Python 3 and a C compiler. Temporary files are removed on exit.

Exit: 0 = invariant holds, 1 = BUG reproduced, 2 = fixture/source error,
      77 = missing prerequisite.
HELP
}

repro_source=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --source)
            if [ "$#" -lt 2 ]; then
                printf '%s\n' 'ERROR: --source needs a path' >&2
                exit 2
            fi
            repro_source=$2
            shift 2
            ;;
        *)
            printf 'ERROR: unknown argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'SKIP: Python 3 is required' >&2
    exit 77
fi
repro_cc=cc
if [[ -v CC ]]; then repro_cc=$CC; fi
if ! command -v "$repro_cc" >/dev/null 2>&1; then
    printf 'SKIP: C compiler unavailable: %s\n' "$repro_cc" >&2
    exit 77
fi
if ! repro_tmp=$(mktemp -d); then
    printf '%s\n' 'ERROR: cannot create temporary directory' >&2
    exit 2
fi
trap 'rm -rf -- "$repro_tmp"' EXIT

if ! python3 - "$repro_source" "$0" "$repro_tmp/repro.c" <<'PY'
import os
from pathlib import Path
import re
import sys


def source_dir(override, script):
    override = override or os.environ.get("MITOSIS_SOURCE", "")
    starts = [Path(override).expanduser()] if override else [
        Path.cwd(), Path(script).resolve().parent
    ]
    for start in starts:
        locations = [start] if override else [start, *start.parents]
        for location in locations:
            for candidate in (
                location / "scheds/rust/scx_mitosis/src/bpf",
                location / "src/bpf",
                location,
            ):
                if (candidate / "mitosis.bpf.c").is_file():
                    return candidate.resolve()
    raise ValueError("cannot locate mitosis.bpf.c; use --source or MITOSIS_SOURCE")


def function(source, name):
    pattern = (
        r"(?m)^(?:static\b[^\n]*|void\b[^\n]*|s32\b[^\n]*|"
        r"int\b[^\n]*|bool\b[^\n]*|u64\b[^\n]*)\b"
        + re.escape(name) + r"(?:\s*\(|,)"
    )
    for match in re.finditer(pattern, source):
        brace = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        # Ignore braces in C comments and string/character literals.
        token = re.compile(r"/\*[\s\S]*?\*/|//[^\n]*|"
                           r'"(?:\\.|[^"\\])*"|'
                           r"'(?:\\.|[^'\\])*'|[{}]")
        depth = 0
        for item in token.finditer(source, brace):
            if item.group() == "{":
                depth += 1
            elif item.group() == "}":
                depth -= 1
                if not depth:
                    return source[match.start():item.end()]
    raise ValueError("cannot extract function: " + name)


try:
    bpf_dir = source_dir(sys.argv[1], sys.argv[2])
    source = (bpf_dir / "mitosis.bpf.c").read_text()
    dsq_source = (bpf_dir / "dsq.bpf.h").read_text()
    helper_sources = [source] + [
        path.read_text() for path in sorted(bpf_dir.glob("*.bpf.h"))
    ]

    def optional_helper(name):
        for helper_source in helper_sources:
            try:
                return function(helper_source, name)
            except ValueError:
                pass
        return None

    # Main accounts CPU-task time and demand separately from vtime. Older
    # checkouts charge CPU running time through charge_running() instead.
    # Import the real accounting implementation for the source under test.
    account_running = optional_helper("account_task_running")
    charge_running = optional_helper("charge_running")
    accounting_definitions = "#define FIXTURE_HAS_SUBCELL_ACCOUNTS 0\n"
    accounting_helpers = []
    if account_running is not None:
        intf_source = (bpf_dir / "intf.h").read_text()
        account_struct = re.search(
            r"(?ms)^struct\s+subcell_account\s*\{.*?^\};", intf_source
        )
        demand_shift = re.search(
            r"(?m)^\s*DEMAND_SHIFT\s*=\s*([0-9]+)\s*,", intf_source
        )
        if account_struct is None or demand_shift is None:
            raise ValueError("cannot extract subcell demand accounting declarations")
        accounting_definitions = (
            "#define FIXTURE_HAS_SUBCELL_ACCOUNTS 1\n"
            + account_struct.group() + "\n"
            + "#define DEMAND_SHIFT " + demand_shift.group(1) + "\n"
        )
        for name in ("DEMAND_TAU_NS", "DEMAND_MAX_WINDOW_NS"):
            match = re.search(
                r"(?m)^#define\s+" + name + r"\b[^\n]*", "\n".join(helper_sources)
            )
            if match is None:
                raise ValueError("missing demand accounting constant " + name)
            accounting_definitions += match.group() + "\n"
        update_demand = optional_helper("update_task_demand")
        if update_demand is None:
            raise ValueError("cannot extract update_task_demand")
        accounting_helpers = [update_demand, account_running]
    if charge_running is not None:
        accounting_helpers.append(charge_running)
    debt_constant = re.search(
        r"(?m)^#define VTIME_DEBT_CAP_SLICES[^\n]*$", source
    )
    if debt_constant is None:
        raise ValueError("VTIME_DEBT_CAP_SLICES is missing")

    has_rescue = bool(re.search(r"\btake_task_rescue\s*\(", source))
    rescue_definitions = ""
    rescue_helpers = []
    dsq_start = re.search(r"(?m)^#define\s+CPU_B\b", dsq_source)
    dsq_end = re.search(r"(?m)^static\s+inline\s+bool\s+dsq_is_invalid\s*\(", dsq_source)
    if dsq_start is None or dsq_end is None:
        raise ValueError("cannot extract DSQ declarations")
    dsq_definitions = dsq_source[dsq_start.start():dsq_end.start()]
    dsq_helpers = [
        function(dsq_source, name)
        for name in ("dsq_is_invalid", "is_user_dsq", "is_cpu_dsq",
                     "get_cpu_from_dsq", "get_cpu_dsq_id", "pack_subcell_id",
                     "get_subcell_llc_dsq_id")
    ]
    rescue_initial_state = "0"
    if has_rescue:
        header = (bpf_dir / "mitosis.bpf.h").read_text()
        llc_source = (bpf_dir / "llc_aware.bpf.h").read_text()
        rescue_enum = re.search(r"(?ms)^enum\s+task_rescue_phase\s*\{.*?^\};", header)
        if rescue_enum is None:
            raise ValueError("cannot extract enum task_rescue_phase")
        rescue_definitions += rescue_enum.group() + "\n"
        for name in ("TASK_RESCUE_PHASE_MASK", "TASK_RESCUE_GENERATION_STEP"):
            match = re.search(r"(?m)^#define\s+" + name + r"\b[^\n]*", source + "\n" + header)
            if match is None:
                raise ValueError("missing rescue constant " + name)
            rescue_definitions += match.group() + "\n"
        for pattern, description in (
            (r"(?m)^typedef\s+u32\s+llc_id_t\s*;", "llc_id_t"),
            (r"(?m)^#define\s+LLC_INVALID\b[^\n]*", "LLC_INVALID"),
        ):
            match = re.search(pattern, llc_source)
            if match is None:
                raise ValueError("cannot extract " + description)
            rescue_definitions += match.group() + "\n"
        rescue_initial_state = "TASK_RESCUE_NONE"
        rescue_helpers = [
            function(llc_source, "invalidate_task_llc_cpumask"),
            function(llc_source, "invalidate_task_llc"),
            function(source, "restore_task_rescue_vtime"),
            function(source, "repair_running_task_rescue"),
        ]
    rescue_definitions += "#define FIXTURE_TASK_RESCUE_NONE " + rescue_initial_state + "\n"

    preamble = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef long long s64;
#ifdef __always_inline
#undef __always_inline
#endif
#define __always_inline inline __attribute__((always_inline))
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value) = (next))
#define MEMBER_VPTR(container, member) (&((container) member))
#define barrier_var(value) ((void)(value))
#define unlikely(value) __builtin_expect(!!(value), 0)
#define MAX_CELLS 2
#define MAX_CPUS 2
#define MAX_SUBCELLS_PER_CELL 8
#define MAX_LLCS 2
#define FAKE_FLAT_SUBCELL_LLC 0
#define SCX_ENQ_LAST 2ULL
#define SCX_ENQ_WAKEUP 4ULL
#define FIXTURE_CPU_SELECTED 1ULL
#define SCX_KICK_IDLE 1
#define PF_IDLE 1

@FIXTURE_DSQ_DECLARATIONS@
@FIXTURE_ACCOUNT_DECLARATIONS@
struct cpumask { unsigned long bits; };
struct bpf_cpumask { unsigned long bits; };
struct scx_dispatch_q { u64 id; };
struct task_struct {
    int pid;
    unsigned int flags;
    const struct cpumask *cpus_ptr;
    struct { u64 dsq_vtime; u32 weight; u64 flags; struct scx_dispatch_q *dsq; } scx;
};
struct task_ctx {
    struct bpf_cpumask *cpumask, *llc_cpumask;
    u64 started_running_at, charged_at;
    u64 running_accounted_at, runnable_at, quiescent_at;
    u64 demand_window_at, window_run_ns, window_sleep_ns;
    u32 demand;
    u64 rescue_seq, rescue_vtime;
    u32 vtime_charge_subcell;
    u64 basis_vtime;
    u32 cell, subcell;
    dsq_id_t dsq;
    u32 configuration_seq;
    bool all_cell_cpus_allowed, borrowed;
    u64 cgid;
    s32 llc, llc_cpumask_id;
    u64 avg_runtime_ns;
};
struct subcell_llc { u64 vtime_now; u32 nr_queued; };
struct subcell { struct subcell_llc llcs[MAX_LLCS]; };
struct cpu_ctx {
    u64 pinned_waiting_since;
    u64 running_ns[MAX_CELLS], vtime_now;
    u32 cell, subcell, llc;
};
enum {
    CSTAT_CLAMP_USED, CSTAT_CPU_DSQ, CSTAT_CELL_DSQ
};
static const u64 slice_ns = 1000000ULL;
static const bool enable_llc_awareness = false;
static const bool dynamic_affinity_cpu_selection = false;
static const bool enable_slice_shrinking = false;
static struct task_ctx task;
static struct cpu_ctx execution_cpu;
static struct subcell domains[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
#if FIXTURE_HAS_SUBCELL_ACCOUNTS
static struct subcell_account accounts[MAX_CELLS * MAX_SUBCELLS_PER_CELL][MAX_CPUS];
static const int subcell_accounts;
#endif
static struct bpf_cpumask task_mask = { 1 };
static struct scx_dispatch_q home_dsq = { .id = 0x20000000ULL };
static u64 fixture_now, inserted_vtime;
static unsigned int errors, insertions;

/* Only kernel interfaces and inactive branches are fixtures. */
static bool time_before(u64 a, u64 b) { return (s64)(a - b) < 0; }
static bool time_after(u64 a, u64 b) { return (s64)(a - b) > 0; }
static u64 time_delta(u64 now, u64 before) {
    return now >= before ? now - before : 0;
}
static u64 scx_bpf_now(void) { return fixture_now; }
static u64 bpf_ktime_get_ns(void) { return fixture_now; }
static u64 scx_clock_task(s32 cpu) {
    if (cpu != 1)
        errors++;
    return fixture_now;
}
static void scx_bpf_error(const char *format, ...) {
    (void)format;
    errors++;
}
static bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 vtime) {
    p->scx.dsq_vtime = vtime;
    return true;
}
static s32 scx_bpf_task_cpu(struct task_struct *p) { (void)p; return 1; }
static struct task_ctx *lookup_task_ctx(struct task_struct *p) {
    (void)p;
    return &task;
}
static struct cpu_ctx *lookup_cpu_ctx(int cpu) {
    (void)cpu;
    return &execution_cpu;
}
#if FIXTURE_HAS_SUBCELL_ACCOUNTS
/* Model the kernel per-CPU map boundary; accounting logic is extracted below. */
static struct subcell_account *bpf_map_lookup_percpu_elem(
        const void *map, const u32 *key, s32 cpu) {
    if (map != &subcell_accounts || !key ||
        *key >= MAX_CELLS * MAX_SUBCELLS_PER_CELL || cpu < 0 || cpu >= MAX_CPUS) {
        errors++;
        return NULL;
    }
    return &accounts[*key][cpu];
}
#endif
static struct subcell *lookup_subcell(u32 cell, u32 subcell) {
    if (cell >= MAX_CELLS || subcell >= MAX_SUBCELLS_PER_CELL) {
        errors++;
        return NULL;
    }
    return &domains[cell][subcell];
}
static struct subcell_llc *lookup_subcell_llc(struct subcell *subcell, u32 llc) {
    if (!subcell || llc >= MAX_LLCS) {
        errors++;
        return NULL;
    }
    return &subcell->llcs[llc];
}
static bool llc_is_valid(u32 llc) { return llc < MAX_LLCS; }
static const u32 nr_llc = 1;
static void cstat_inc(int stat, u32 cell, struct cpu_ctx *cctx) {
    (void)stat; (void)cell; (void)cctx;
}
static int maybe_refresh_cell(struct task_struct *p, struct task_ctx *tctx) {
    (void)p; (void)tctx;
    return 0; /* The fixture's cell, affinity and config do not change. */
}
static bool __COMPAT_is_enq_cpu_selected(u64 flags) {
    return flags & FIXTURE_CPU_SELECTED;
}
static s32 enqueue_pinned_cpu(struct task_struct *p, struct task_ctx *tctx) {
    (void)p; (void)tctx; errors++; return -1;
}
static s32 try_pick_idle_cpu(struct task_struct *p, s32 cpu,
                            struct cpu_ctx *cctx, struct task_ctx *tctx,
                            bool kick) {
    (void)p; (void)cpu; (void)cctx; (void)tctx; (void)kick;
    errors++; return -1;
}
static u32 bpf_cpumask_any_distribute(const struct cpumask *mask) {
    (void)mask; errors++; return 0;
}
static int maybe_update_task_llc(struct task_struct *p, struct task_ctx *tctx,
                                 s32 cpu) {
    (void)p; (void)tctx; (void)cpu; errors++; return -EINVAL;
}
static int account_subcell_llc_enqueue(u32 cell, u32 subcell, u32 llc) {
    (void)cell; (void)subcell; (void)llc; errors++; return -EINVAL;
}
static struct task_struct *__COMPAT_scx_bpf_cpu_curr(s32 cpu) {
    (void)cpu; errors++; return NULL;
}
static void slice_shrink_on_enqueue(struct task_struct *p,
                                    struct task_ctx *tctx, u32 cell,
                                    struct cpu_ctx *cctx) {
    (void)p; (void)tctx; (void)cell; (void)cctx; errors++;
}
static void scx_bpf_kick_cpu(s32 cpu, u64 flags) {
    (void)cpu; (void)flags; errors++;
}
static void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq,
                                   u64 slice, u64 vtime, u64 flags) {
    (void)dsq; (void)slice; (void)flags;
    p->scx.dsq_vtime = vtime;
    p->scx.dsq = &home_dsq;
    inserted_vtime = vtime;
    insertions++;
}
'''
    preamble = preamble.replace("@FIXTURE_DSQ_DECLARATIONS@", dsq_definitions)
    preamble = preamble.replace("@FIXTURE_ACCOUNT_DECLARATIONS@", accounting_definitions)
    bodies = dsq_helpers
    if has_rescue:
        bodies.append(function(source, "take_task_rescue"))
    if re.search(r"\badvance_vtime\s*\(", source):
        bodies.append(function(source, "advance_vtime"))
    if re.search(r"\btask_shared_vtime\s*\(", source):
        bodies.append(function(source, "task_shared_vtime"))
    bodies += rescue_helpers
    bodies += [
        function(source, "set_vtime_charge_subcell"),
        function(source, "set_pinned_vtime_charge_cpu"),
        function(source, "cap_vtime_debt"),
        function(source, "advance_subcell_llc_vtime"),
        function(source, "update_task_runtime_ewma"),
    ]
    bodies += accounting_helpers
    bodies += [
        function(source, "mitosis_stopping"),
        function(source, "mitosis_enqueue"),
    ]
    main = r'''
static int run_slice(u32 weight, u64 runtime, u64 *charge, u64 *retained) {
    struct task_struct p = {
        .pid = 1001,
        .scx = { .dsq_vtime = 100000000ULL, .weight = weight },
    };
    const u64 basis = p.scx.dsq_vtime;
    memset(&task, 0, sizeof(task));
    task.rescue_seq = FIXTURE_TASK_RESCUE_NONE;
    memset(&execution_cpu, 0, sizeof(execution_cpu));
    memset(domains, 0, sizeof(domains));
#if FIXTURE_HAS_SUBCELL_ACCOUNTS
    memset(accounts, 0, sizeof(accounts));
#endif
    errors = insertions = 0;
    inserted_vtime = 0;
    /* A home-cell task has just run on an idle CPU borrowed from cell 1. */
    task.cell = task.subcell = 0;
    task.all_cell_cpus_allowed = true;
    task.borrowed = true;
    task.cpumask = &task_mask;
    task.dsq.raw = 0x20000000ULL;
    task.vtime_charge_subcell = pack_subcell_id(0, 0);
    task.started_running_at = task.charged_at = 1000000ULL;
    task.running_accounted_at = task.demand_window_at = task.started_running_at;
#if FIXTURE_HAS_SUBCELL_ACCOUNTS
    task.demand = 1024;
#endif
    fixture_now = task.started_running_at + runtime;
    execution_cpu.cell = 1;
    execution_cpu.vtime_now = basis;
    domains[0][0].llcs[0].vtime_now = basis;
    domains[1][0].llcs[0].vtime_now = basis;

    mitosis_stopping(&p, true);
    *charge = p.scx.dsq_vtime - basis;
    if (*charge != runtime * 100 / weight) {
        fputs("ERROR: stopping did not produce the expected weighted slice charge\n", stderr);
        return 2;
    }
    if (errors || task.borrowed || !*charge ||
        domains[0][0].llcs[0].vtime_now != basis ||
        domains[1][0].llcs[0].vtime_now != basis ||
        execution_cpu.vtime_now != basis) {
        fputs("ERROR: borrowed stopping fixture did not preserve clocks\n", stderr);
        return 2;
    }
    if (execution_cpu.running_ns[0] != runtime || execution_cpu.running_ns[1]) {
        fputs("ERROR: stopping did not account runtime to the task's home cell\n", stderr);
        return 2;
    }
#if FIXTURE_HAS_SUBCELL_ACCOUNTS
    if (accounts[0][1].running_ns != runtime || accounts[0][1].queued_ns ||
        accounts[0][1].demand_sum != 1024 * runtime ||
        accounts[0][0].running_ns || accounts[MAX_SUBCELLS_PER_CELL][1].running_ns ||
        task.running_accounted_at != fixture_now || task.runnable_at != fixture_now ||
        task.demand_window_at != fixture_now || task.demand != 1024 ||
        task.window_run_ns || task.window_sleep_ns) {
        fputs("ERROR: stopping did not retain per-subcell running and demand accounting\n", stderr);
        return 2;
    }
#endif
    /* Selected busy CPU: enqueue into the unchanged flat home DSQ. */
    mitosis_enqueue(&p, FIXTURE_CPU_SELECTED);
    if (errors || insertions != 1 || inserted_vtime < basis) {
        fputs("ERROR: enqueue did not produce the expected insertion\n", stderr);
        return 2;
    }
    *retained = inserted_vtime - basis;
    return 0;
}

int main(void) {
    u64 charge, retained, control_charge, control_retained;
    if (run_slice(1, slice_ns, &charge, &retained) ||
        run_slice(100, slice_ns, &control_charge, &control_retained))
        return 2;
    printf("Weight 1: charged debt=%llu ns (%llu slices), queued debt=%llu ns\n",
           charge, charge / slice_ns, retained);
    printf("Weight 100 control: charged debt=%llu ns, queued debt=%llu ns\n",
           control_charge, control_retained);
    if (control_charge != control_retained) {
        fputs("ERROR: the ordinary-weight control also lost debt\n", stderr);
        return 2;
    }
    if (retained < charge) {
        printf("BUG: enqueue discarded %llu ns of legitimate weighted debt\n",
               charge - retained);
        return 1;
    }
    if (retained != charge) {
        fputs("ERROR: enqueue increased the debt\n", stderr);
        return 2;
    }
    u64 excessive_charge, capped_debt;
    if (run_slice(200, 64 * slice_ns, &excessive_charge, &capped_debt))
        return 2;
    printf("Weight 200 cap control: charged=%llu ns, retained=%llu ns\n",
           excessive_charge, capped_debt);
    if (capped_debt != 8 * slice_ns) {
        fputs("ERROR: the weighted debt limit was not enforced\n", stderr);
        return 2;
    }
    struct task_struct invalid = { .pid = 1002, .scx = { .weight = 0 } };
    errors = insertions = 0;
    mitosis_enqueue(&invalid, FIXTURE_CPU_SELECTED);
    if (errors != 1 || insertions) {
        fputs("ERROR: zero weight was not rejected before insertion\n", stderr);
        return 2;
    }
    puts("Zero-weight control: rejected before division or insertion");
    puts("PASS: enqueue preserved the full weighted borrowed-slice charge");
    return 0;
}
'''
    Path(sys.argv[3]).write_text(
        preamble + "\n" + debt_constant.group() + "\n"
        + rescue_definitions
        + "\n\n".join(bodies) + "\n" + main
    )
    print(str(bpf_dir / "mitosis.bpf.c").replace("/home/tommyu/", "~/", 1), flush=True)
except (OSError, ValueError) as error:
    print("ERROR:", error, file=sys.stderr)
    sys.exit(2)
PY
then
    exit 2
fi

if ! "$repro_cc" -std=gnu11 -O0 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare \
    "$repro_tmp/repro.c" -o "$repro_tmp/repro"; then
    printf '%s\n' 'ERROR: cannot compile the extracted C fixture' >&2
    exit 2
fi

set +e
"$repro_tmp/repro"
repro_status=$?
set -e
case "$repro_status" in
    0|1|2|77) exit "$repro_status" ;;
    *) printf 'ERROR: fixture exited with status %s\n' "$repro_status" >&2; exit 2 ;;
esac
