#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Compile the checkout's LLC assignment and affinity callbacks in userspace.
# No scheduler is loaded or replaced.
set -eu

usage() {
    cat <<'HELP'
Usage: unchanged_llc_refresh.sh [--source CHECKOUT]

Reproduce a placement refresh erasing vtime although the LLC DSQ is unchanged.
Compile actual mitosis_set_cpumask(), update_task_cpumask(),
update_task_llc_assignment(), and set_task_llc() C functions from a checkout.
Run them with fixed userspace CPU masks and clocks. This checks the mechanism;
it does not execute BPF in the kernel or measure live fairness.

The task still covers its two-CPU cell after an affinity change removes a CPU
outside that cell. Its cell, LLC and DSQ stay identical. The script checks
both positive debt and credit, plus a non-reset assignment control.
Changing the cell, subcell, or LLC DSQ must instead reset to its new clock.

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
                if ((candidate / "mitosis.bpf.c").is_file()
                        and (candidate / "llc_aware.bpf.h").is_file()):
                    return candidate.resolve()
    raise ValueError("cannot locate Mitosis BPF sources; use --source or MITOSIS_SOURCE")


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
    llc_source = (bpf_dir / "llc_aware.bpf.h").read_text()
    dsq_source = (bpf_dir / "dsq.bpf.h").read_text()
    defs_source = (bpf_dir / "mitosis.bpf.h").read_text()
    dsq_type = re.search(
        r"typedef union \{[\s\S]*?\}\s*dsq_id_t;", dsq_source
    )
    dsq_enum = re.search(r"enum dsq_type \{[\s\S]*?\};", dsq_source)
    if dsq_type is None or dsq_enum is None:
        raise ValueError("cannot extract DSQ identifier definitions")
    widths = re.findall(
        r"(?m)^#define (?:CPU_B|LLC_B|SUBCELL_B|TYPE_B|DATA_B|RSVD_B)[^\n]*$",
        dsq_source,
    )
    if len(widths) != 6:
        raise ValueError("cannot extract DSQ bit widths")
    rescue_declarations = []
    rescue_phase = re.search(r"enum task_rescue_phase\s*\{[\s\S]*?\};", defs_source)
    if rescue_phase:
        rescue_declarations.append(rescue_phase.group())
        for macro in ("TASK_RESCUE_PHASE_MASK", "TASK_RESCUE_GENERATION_STEP"):
            match = re.search(rf"(?m)^#define[ \t]+{macro}[ \t]+[^\n]+", defs_source)
            if not match:
                raise ValueError("cannot extract " + macro)
            rescue_declarations.append(match.group())

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
typedef u32 llc_id_t;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value) = (next))
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#define barrier_var(value) ((void)(value))
#define MAX_CELLS 2
#define MAX_SUBCELLS_PER_CELL 8
#define MAX_LLCS 2
#define MAX_CPUS 4
#define MASK_WORDS 128
#define FAKE_FLAT_SUBCELL_LLC 0
#define LLC_INVALID ((llc_id_t)~0u)
static bool time_before(u64 a, u64 b) { return (s64)(a - b) < 0; }
'''
    fixture = r'''
#define DSQ_INVALID ((dsq_id_t){ 0 })
struct cpumask { unsigned long bits[MASK_WORDS]; };
struct bpf_cpumask { unsigned long bits[MASK_WORDS]; };
struct llc_cpumask { unsigned long bits[MASK_WORDS]; };
struct scx_dispatch_q { u64 id; };
struct task_struct {
    int pid, cpu;
    const struct cpumask *cpus_ptr;
    struct { u64 dsq_vtime; u32 weight; struct scx_dispatch_q *dsq; } scx;
};
struct task_ctx {
    struct bpf_cpumask *cpumask, *llc_cpumask;
    u64 started_running_at, charged_at;
    u32 vtime_charge_subcell;
    u64 basis_vtime;
    u32 cell, subcell;
    dsq_id_t dsq;
    u32 configuration_seq;
    bool all_cell_cpus_allowed, borrowed;
    u64 cgid;
    s32 llc, llc_cpumask_id;
    u64 avg_runtime_ns;
    u64 rescue_seq, rescue_vtime;
};
struct subcell_llc { u64 vtime_now; u32 nr_queued; };
struct subcell { struct subcell_llc llcs[MAX_LLCS]; };
struct cpu_ctx { u64 vtime_now; u32 cell, subcell, llc; };
enum { CSTAT_PIN_SKIP };
static const u32 nr_possible_cpus = 4, nr_llc = 2;
static const bool enable_llc_awareness = true;
static const bool enable_borrowing = false, reject_multicpu_pinning = false;
static const u32 cpuset_seq = 1, applied_cpuset_seq = 1;
static u32 cpu_to_llc[MAX_CPUS] = { 0, 0, 1, 1 };
static struct llc_cpumask llc_to_cpus[MAX_LLCS] = {
    { .bits = { 3 } }, { .bits = { 12 } },
};
static const struct cpumask old_affinity = { .bits = { 15 } };
static const struct cpumask new_affinity = { .bits = { 7 } };
static struct cpumask cell_masks[MAX_CELLS];
static struct cpumask subcell_masks[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
static struct bpf_cpumask task_mask, cached_llc_mask;
static struct task_ctx task;
static struct cpu_ctx cpus[MAX_CPUS];
static struct subcell domains[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
static unsigned int errors;
static unsigned int mask_refresh_calls;
static int mask_refresh_failure;

/* The only fixtures are kernel lookups, masks and the task-vtime setter. */
static void scx_bpf_error(const char *format, ...) {
    (void)format; errors++;
}
static const struct cpumask *cast_mask(const struct bpf_cpumask *mask) {
    return (const struct cpumask *)mask;
}
static bool bpf_cpumask_empty(const struct cpumask *mask) {
    for (u32 i = 0; i < MASK_WORDS; i++)
        if (mask->bits[i]) return false;
    return true;
}
static void bpf_cpumask_and(struct bpf_cpumask *out,
                            const struct cpumask *a, const struct cpumask *b) {
    for (u32 i = 0; i < MASK_WORDS; i++)
        out->bits[i] = a->bits[i] & b->bits[i];
}
static bool bpf_cpumask_subset(const struct cpumask *a,
                               const struct cpumask *b) {
    for (u32 i = 0; i < MASK_WORDS; i++)
        if (a->bits[i] & ~b->bits[i]) return false;
    return true;
}
static bool bpf_cpumask_test_cpu(u32 index, const struct cpumask *mask) {
    const u32 bits_per_word = sizeof(unsigned long) * 8;
    return index < MAX_CPUS &&
           (mask->bits[index / bits_per_word] & (1UL << (index % bits_per_word)));
}
static u32 bpf_cpumask_weight(const struct cpumask *mask) {
    u32 count = 0;
    for (u32 i = 0; i < MASK_WORDS; i++)
        count += __builtin_popcountl(mask->bits[i]);
    return count;
}
static u32 bpf_cpumask_any_distribute(const struct cpumask *mask) {
    for (u32 i = 0; i < MAX_CPUS; i++)
        if (bpf_cpumask_test_cpu(i, mask)) return i;
    return MAX_CPUS;
}
static const struct cpumask *lookup_cell_cpumask(u32 cell) {
    if (cell >= MAX_CELLS) { errors++; return NULL; }
    return &cell_masks[cell];
}
static const struct cpumask *lookup_subcell_cpumask(u32 cell, u32 subcell) {
    if (cell >= MAX_CELLS || subcell >= MAX_SUBCELLS_PER_CELL) {
        errors++; return NULL;
    }
    return &subcell_masks[cell][subcell];
}
static const struct cpumask *lookup_cell_borrowable_cpumask(u32 cell) {
    (void)cell; errors++; return NULL; /* Borrowing is disabled. */
}
static struct subcell *lookup_subcell(u32 cell, u32 subcell) {
    if (cell >= MAX_CELLS || subcell >= MAX_SUBCELLS_PER_CELL) {
        errors++; return NULL;
    }
    return &domains[cell][subcell];
}
static struct subcell_llc *lookup_subcell_llc(struct subcell *subcell, u32 llc) {
    if (!subcell || llc >= MAX_LLCS) { errors++; return NULL; }
    return &subcell->llcs[llc];
}
static struct cpu_ctx *lookup_cpu_ctx(int index) {
    if (index < 0) index = 0;
    if (index >= MAX_CPUS) { errors++; return NULL; }
    return &cpus[index];
}
static struct task_ctx *lookup_task_ctx(struct task_struct *p) {
    (void)p; return &task;
}
static void cstat_inc(int stat, u32 cell, struct cpu_ctx *cctx) {
    (void)stat; (void)cell; (void)cctx;
}
static s32 scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 vtime) {
    p->scx.dsq_vtime = vtime; return true;
}
'''
    bodies = [
        function(dsq_source, "dsq_is_invalid"),
        function(dsq_source, "is_user_dsq"),
        function(dsq_source, "is_cpu_dsq"),
        function(dsq_source, "get_cpu_from_dsq"),
        function(dsq_source, "get_cpu_dsq_id"),
        function(dsq_source, "pack_subcell_id"),
        function(dsq_source, "get_subcell_llc_dsq_id"),
        function(llc_source, "llc_is_valid"),
        function(llc_source, "lookup_llc_cpumask"),
        function(llc_source, "invalidate_task_llc_cpumask"),
        function(llc_source, "invalidate_task_llc"),
        function(llc_source, "llc_from_cpu"),
        function(llc_source, "choose_task_llc"),
        function(llc_source, "refresh_task_llc_cpumask"),
    ]
    for helper in ("take_task_rescue", "task_shared_vtime", "restore_task_rescue_vtime"):
        if re.search(r"(?m)^static\b[^\n]*\b" + helper + r"\s*\(", source):
            bodies.append(function(source, helper))
    bodies += [
        function(llc_source, "set_task_llc"),
        function(llc_source, "update_task_llc_assignment"),
        re.sub(r'\bupdate_task_cpumask(?=\s*\()',
               'recorded_update_task_cpumask',
               function(source, "update_task_cpumask"), count=1),
        r'''static int update_task_cpumask(struct task_struct *p, struct task_ctx *tctx) {
    int ret = recorded_update_task_cpumask(p, tctx);
    mask_refresh_calls++;
    if (ret)
        mask_refresh_failure = ret;
    return ret;
}''',
        function(source, "mitosis_set_cpumask"),
    ]
    main = r'''
static void seed(struct task_struct *p, s64 lag) {
    memset(&task, 0, sizeof(task));
    memset(cpus, 0, sizeof(cpus));
    memset(domains, 0, sizeof(domains));
    memset(cell_masks, 0, sizeof(cell_masks));
    memset(subcell_masks, 0, sizeof(subcell_masks));
    memset(&task_mask, 0, sizeof(task_mask));
    memset(&cached_llc_mask, 0, sizeof(cached_llc_mask));
    errors = 0;
    mask_refresh_calls = 0;
    mask_refresh_failure = 0;
    domains[0][0].llcs[0].vtime_now = 100000000ULL;
    cpus[0].vtime_now = 100000000ULL;
    cell_masks[0].bits[0] = subcell_masks[0][0].bits[0] = 3;
    task_mask.bits[0] = cached_llc_mask.bits[0] = 3;
    task.cpumask = &task_mask;
    task.llc_cpumask = &cached_llc_mask;
    task.all_cell_cpus_allowed = true;
    task.llc = task.llc_cpumask_id = 0;
    task.dsq = get_subcell_llc_dsq_id(0, 0, 0);
    *p = (struct task_struct) {
        .pid = 1001,
        .cpus_ptr = &old_affinity,
        .scx = { .dsq_vtime = 100000000ULL + lag, .weight = 100 },
    };
}

static int refresh(const char *label, s64 before, bool *changed) {
    struct task_struct p;
    seed(&p, before);
    dsq_id_t original_dsq = task.dsq;
    u64 original_vtime = p.scx.dsq_vtime;
    if (set_task_llc(&p, &task, 0, false) || errors ||
        p.scx.dsq_vtime != original_vtime || task.dsq.raw != original_dsq.raw) {
        fputs("ERROR: non-reset LLC assignment control did not preserve vtime\n",
              stderr);
        return 2;
    }
    /*
     * Remove CPU 3, outside the task's cell (CPUs 0,1). The kernel updates
     * p->cpus_ptr before calling set_cpumask. Both masks cover the cell.
     */
    p.cpus_ptr = &new_affinity;
    mitosis_set_cpumask(&p, &new_affinity);
    if (errors || !mask_refresh_calls || mask_refresh_failure ||
        task.dsq.raw != original_dsq.raw ||
        task.llc != 0 || !task.all_cell_cpus_allowed) {
        fputs("ERROR: the fixture unexpectedly changed placement\n", stderr);
        return 2;
    }
    s64 after = p.scx.dsq_vtime - domains[0][0].llcs[0].vtime_now;
    printf("%s: lag %lld -> %lld ns, unchanged DSQ=0x%llx\n",
           label, before, after, task.dsq.raw);
    *changed = p.scx.dsq_vtime != original_vtime;
    return 0;
}

struct domain_change {
    const char *label;
    u32 cell, subcell, llc, cpu;
    unsigned long cell_mask, subcell_mask;
    u64 vtime;
};

static int refresh_changed_domain(const struct domain_change *next) {
    struct task_struct p;
    seed(&p, 5000000LL);
    dsq_id_t original_dsq = task.dsq;
    /* Publish the destination configuration before refreshing this task. */
    cell_masks[next->cell].bits[0] = next->cell_mask;
    subcell_masks[next->cell][next->subcell].bits[0] = next->subcell_mask;
    domains[next->cell][next->subcell].llcs[next->llc].vtime_now = next->vtime;
    cpus[next->cpu].cell = next->cell;
    cpus[next->cpu].subcell = next->subcell;
    cpus[next->cpu].llc = next->llc;
    cpus[next->cpu].vtime_now = next->vtime;
    task.cell = next->cell;
    task.subcell = next->subcell;
    p.cpu = next->cpu;
    if (update_task_cpumask(&p, &task) || errors || mask_refresh_failure) {
        fprintf(stderr, "ERROR: %s could not refresh its destination configuration\n", next->label);
        return 2;
    }
    if (task.llc != next->llc || !task.all_cell_cpus_allowed ||
        task.dsq.raw == original_dsq.raw ||
        task.dsq.raw != get_subcell_llc_dsq_id(next->cell, next->subcell, next->llc).raw) {
        printf("BUG: %s did not reach its destination LLC DSQ\n", next->label);
        return 1;
    }
    if (p.scx.dsq_vtime != next->vtime) {
        printf("BUG: %s kept vtime %llu ns instead of new clock %llu ns\n",
               next->label, p.scx.dsq_vtime, next->vtime);
        return 1;
    }
    printf("%s control: reset to new clock %llu ns, DSQ=0x%llx\n",
           next->label, p.scx.dsq_vtime, task.dsq.raw);
    return 0;
}

int main(void) {
    static const struct domain_change changes[] = {
        { "Cell change", 1, 0, 0, 1, 2, 2, 200000000ULL },
        { "Subcell change", 0, 1, 0, 1, 3, 2, 300000000ULL },
        { "LLC change", 0, 0, 1, 2, 12, 12, 400000000ULL },
    };
    bool debt_changed, credit_changed;
    if (refresh("Debt", 5000000LL, &debt_changed) ||
        refresh("Credit", -500000LL, &credit_changed))
        return 2;
    puts("Non-reset assignment control: preserved both original vtimes");
    bool domain_control_failed = false;
    for (u32 i = 0; i < sizeof(changes) / sizeof(changes[0]); i++) {
        int ret = refresh_changed_domain(&changes[i]);
        if (ret == 2) return 2;
        if (ret) domain_control_failed = true;
    }
    if (debt_changed || credit_changed) {
        puts("BUG: affinity refresh erased fairness state in the same LLC DSQ");
        return 1;
    }
    if (domain_control_failed) return 1;
    puts("PASS: affinity refresh preserved debt and credit in the same LLC DSQ");
    return 0;
}
'''
    Path(sys.argv[3]).write_text(
        preamble + "\n" + "\n".join(widths)
        + "\n" + dsq_type.group() + "\n" + dsq_enum.group()
        + "\n" + "\n".join(rescue_declarations)
        + "\n" + fixture + "\n" + "\n\n".join(bodies) + "\n" + main
    )
    display_path = str(bpf_dir)
    if display_path.startswith("/home/tommyu/"):
        display_path = "~/" + display_path[len("/home/tommyu/"):]
    print(display_path, flush=True)
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
