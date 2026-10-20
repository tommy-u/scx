#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: cpu_shared_clock_gap.sh [--source ROOT]
Compile current Mitosis C callbacks and reproduce a cold CPU joining a hot
shared-clock domain with two continuously runnable pinned tasks.
This is a deterministic source harness, not a live scheduler reproduction.
The adapter uses 1ms slices, FIFO ties, and sequential callbacks.
Uses Python 3 and a C compiler; no root privileges or sched_ext kernel required.
--source ROOT or MITOSIS_SOURCE selects a checkout (or mitosis.bpf.c path).
Default source discovery walks script and current-directory ancestors.
Exit: 0=pass/bug absent in scenario, 1=bug reproduced, 2=error, 77=unsupported.
HELP
}

source_root=${MITOSIS_SOURCE:-}

while (($#)); do
    case "$1" in
        --source) (($# >= 2)) || { usage >&2; exit 2; }; source_root=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;

        *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
command -v python3 >/dev/null || { printf 'UNSUPPORTED: python3 required\n' >&2; exit 77; }
command -v "${CC:-cc}" >/dev/null || { printf 'UNSUPPORTED: C compiler required (CC or cc)\n' >&2; exit 77; }
repro_tmp=$(mktemp -d "${TMPDIR:-/tmp}/mitosis-vtime-01.XXXXXX") || exit 2
trap 'rm -rf -- "$repro_tmp"' EXIT

python3 - "$source_root" "${BASH_SOURCE[0]}" "$repro_tmp/repro.c" <<'PYTHON'
import pathlib
import re
import sys


def unsupported(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


def locate_source(explicit, script):
    if explicit:
        candidates = [pathlib.Path(explicit).expanduser()]
    else:
        candidates = list(pathlib.Path(script).resolve().parents)
        candidates += [pathlib.Path.cwd(), *pathlib.Path.cwd().parents]
    for root in candidates:
        if root.is_file() and root.name == "mitosis.bpf.c":
            return root.resolve()
        for relative in ("scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c", "mitosis.bpf.c"):
            path = root / relative
            if path.is_file():
                return path.resolve()
    unsupported("cannot find checkout; use --source ROOT or MITOSIS_SOURCE")


def mask_literals(text):
    # Keep positions and newlines; ignore braces in comments and literals.
    masked = list(text)
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                unsupported("unterminated source comment")
            end += 2
        elif text[i] in (chr(34), chr(39)):
            quote = text[i]
            end = i + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                unsupported("unterminated source literal")
        else:
            i += 1
            continue
        for j in range(i, min(end, len(text))):
            if text[j] != "\n":
                masked[j] = " "
        i = end
    return "".join(masked)


def extract_function(text, masked, name, source_path=None, required=True):
    pattern = re.compile(
        r"(?m)^(?:static\s+)?(?:(?:__always_inline|inline)\s+)?"
        r"(?:void|int|bool|u64|s32|dsq_id_t)\s+(?:BPF_STRUCT_OPS\(\s*"
        + re.escape(name) + r"\s*,|" + re.escape(name) + r"\s*\()"
    )
    matches = list(pattern.finditer(masked))
    if not matches and not required:
        return ""
    if len(matches) != 1:
        unsupported(f"expected one definition of {name}, found {len(matches)}")
    start = matches[0].start()
    opening = masked.find("{", matches[0].end())
    semicolon = masked.find(";", matches[0].end())
    if opening < 0 or (0 <= semicolon < opening):
        unsupported(f"cannot locate body of {name}")
    depth = 1
    end = opening + 1
    while end < len(masked) and depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    if depth:
        unsupported(f"unterminated body of {name}")
    line = text.count("\n", 0, start) + 1
    source_path = path if source_path is None else source_path
    return f'\n#line {line} "{source_path.as_posix()}"\n' + text[start:end] + "\n"


def read_header(name):
    header = path.with_name(name)
    try:
        header_text = header.read_text()
    except (OSError, UnicodeError) as exc:
        unsupported(f"cannot read required source header {header}: {exc}")
    return header, header_text, mask_literals(header_text)


def extract_declaration(header_text, header_masked, pattern, name):
    match = re.search(pattern, header_masked)
    if not match:
        unsupported(f"missing supported declaration {name}")
    return header_text[match.start():match.end()] + "\n"


def extract_define(header_text, name):
    match = re.search(r"(?m)^#define\s+" + re.escape(name) + r"\s+[^\n]+", header_text)
    if not match:
        unsupported(f"missing supported constant {name}")
    return match.group(0) + "\n"


path = locate_source(sys.argv[1], sys.argv[2])
try:
    text = path.read_text()
except (OSError, UnicodeError) as exc:
    print(f"ERROR: cannot read source: {exc}", file=sys.stderr)
    raise SystemExit(2)
masked = mask_literals(text)
constants = []
for name in ("VTIME_DEBT_CAP_SLICES", "PINNED_MAX_WAIT_SLICES"):
    match = re.search(r"(?m)^#define\s+" + name + r"\s+([0-9]+)\s*$", text)
    if not match:
        unsupported(f"missing supported integer constant {name}")
    constants.append(f"#define {name} {match.group(1)}\n")

print("MODE: source callback harness; sequential kernel/map adapters and 1ms slices")
print(str(path).replace("/home/tommyu/", "~/", 1))
prelude = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef long long s64;
typedef struct { u64 raw; } dsq_id_t;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define MEMBER_VPTR(base, member) (&((base) member))
#define barrier_var(x) ((void)(x))
#define unlikely(x) (x)
#define bpf_for(i, begin, end) for ((i) = (begin); (i) < (end); (i)++)
#define time_before(a, b) ((s64)((u64)(a) - (u64)(b)) < 0)
#define time_after(a, b) time_before(b, a)
#define FAKE_FLAT_SUBCELL_LLC 0
#define MAX_CPUS 4
#define MAX_CELLS 4
#define MAX_SUBCELLS_PER_CELL 2
#define MAX_LLCS 2
#define SCX_ENQ_WAKEUP 1ULL
#define SCX_ENQ_CPU_SELECTED (1ULL << 20)
#define SCX_ENQ_LAST (1ULL << 41)
#define SCX_TASK_QUEUED 1ULL
#define PF_IDLE 2U
#define SCX_KICK_IDLE 1
#define SCX_KICK_PREEMPT 2
#define SCX_DSQ_LOCAL (~0ULL - 1)
#define DSQ_INVALID ((dsq_id_t){~0ULL})
#define CSTAT_AFFN_VIOL 0
#define CSTAT_PIN_SKIP 0
#define CSTAT_CPU_DSQ 0
#define CSTAT_CELL_DSQ 0
#define CSTAT_DRAIN_CNT 0
#define CSTAT_STEAL 0
#define CSTAT_CLAMP_USED 0
struct cpumask { u64 bits; };
struct bpf_cpumask { u64 bits; };
struct subcell_llc { u64 vtime_now; u32 nr_queued; };
struct subcell { struct subcell_llc llcs[MAX_LLCS]; u64 llcs_to_drain; };
struct cpu_ctx {
    u64 pinned_waiting_since, vtime_now, vtime_bias, pending_vtime_owner, running_ns[MAX_CELLS];
    u32 cell, subcell, llc;
};
struct task_ctx {
    struct bpf_cpumask *cpumask;
    u64 started_running_at, charged_at, basis_vtime, avg_runtime_ns;
    u64 rescue_seq, rescue_vtime;
    u32 cell, subcell, configuration_seq, vtime_charge_subcell;
    dsq_id_t dsq;
    bool all_cell_cpus_allowed, borrowed;
    s32 llc, llc_cpumask_id;
};
struct scx_dispatch_q { u64 id; };
struct task_struct {
    struct { u64 dsq_vtime, flags, slice; u32 weight; struct scx_dispatch_q *dsq; } scx;
    struct task_ctx ctx;
    int pid, cpu;
    u32 flags;
    const struct cpumask *cpus_ptr;
    bool queued;
    u64 arrival;
};
static const u32 nr_possible_cpus = 3, nr_llc = 1;
static const u64 slice_ns = 1000000;
static const bool enable_llc_awareness = false, enable_borrowing = false;
static const bool dynamic_affinity_cpu_selection = false, enable_slice_shrinking = false;
static struct cpu_ctx cpus[MAX_CPUS];
static struct subcell subcells[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
static struct task_struct tasks[3], *local_task;
static struct scx_dispatch_q dsqs[3], local_dsq = {.id = SCX_DSQ_LOCAL};
static u64 now_ns = 1, arrival_seq;
static int errors;
static const struct cpumask task_affinity = {.bits = 1};
static const struct cpumask shared_affinity = {.bits = 3};
#define scx_bpf_error(...) do { errors++; fprintf(stderr, "callback error: "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
static struct cpu_ctx *lookup_cpu_ctx(int cpu) { return &cpus[cpu < 0 ? 0 : cpu]; }
static struct task_ctx *lookup_task_ctx(struct task_struct *p) { return &p->ctx; }
static struct subcell *lookup_subcell(u32 cell, u32 subcell) { return &subcells[cell][subcell]; }
static struct subcell_llc *lookup_subcell_llc(struct subcell *s, u32 llc) { return &s->llcs[llc]; }
static s32 pack_subcell_id(u32 cell, u32 subcell) { return (s32)(cell * MAX_SUBCELLS_PER_CELL + subcell); }
static dsq_id_t get_cpu_dsq_id(u32 cpu) { return (dsq_id_t){1 + cpu}; }
static dsq_id_t get_subcell_llc_dsq_id(u32 cell, u32 subcell, u32 llc) { return (dsq_id_t){100 + (cell * MAX_SUBCELLS_PER_CELL + subcell) * MAX_LLCS + llc}; }
static bool dsq_is_invalid(dsq_id_t dsq) { return dsq.raw == ~0ULL; }
static s32 get_cpu_from_dsq(dsq_id_t dsq) { return (s32)dsq.raw - 1; }
static bool llc_is_valid(s32 llc) { return llc >= 0 && llc < MAX_LLCS; }
static u64 scx_bpf_now(void) { return now_ns; }
static u64 bpf_ktime_get_ns(void) { return now_ns; }
static u64 time_delta(u64 a, u64 b) { return a >= b ? a - b : 0; }
static s32 scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 v) { p->scx.dsq_vtime = v; return true; }
static bool scx_bpf_task_set_slice(struct task_struct *p, u64 v) { p->scx.slice = v; return true; }
static int maybe_refresh_cell(struct task_struct *p, struct task_ctx *t) { (void)p; (void)t; return 0; }
static bool task_needs_refresh(struct task_struct *p, struct task_ctx *t) { (void)p; (void)t; return false; }
static bool __COMPAT_is_enq_cpu_selected(u64 flags) { return (flags & SCX_ENQ_CPU_SELECTED) != 0; }
static s32 enqueue_pinned_cpu(struct task_struct *p, struct task_ctx *t) { (void)p; return get_cpu_from_dsq(t->dsq); }
static s32 try_pick_idle_cpu(struct task_struct *p, s32 cpu, struct cpu_ctx *c, struct task_ctx *t, bool kick) { (void)p; (void)cpu; (void)c; (void)t; (void)kick; return -EBUSY; }
static int maybe_update_task_llc(struct task_struct *p, struct task_ctx *t, s32 cpu) { (void)p; (void)t; (void)cpu; return 0; }
static u32 bpf_cpumask_any_distribute(const struct cpumask *m) { (void)m; return 0; }
static void scx_bpf_kick_cpu(s32 cpu, int flags);
static void cstat_inc(int idx, u32 cell, struct cpu_ctx *c) { (void)idx; (void)cell; (void)c; }
static int account_subcell_llc_enqueue(u32 cell, u32 subcell, u32 llc) { (void)cell; (void)subcell; (void)llc; return 0; }
static void subcell_llc_nr_queued_dec(struct subcell *s, u32 llc) { (void)s; (void)llc; }
static int try_draining_work(u32 cell, u32 subcell, u32 llc, struct cpu_ctx *c) { (void)cell; (void)subcell; (void)llc; (void)c; return -ENOENT; }
static int try_stealing_work(u32 cell, u32 subcell, u32 llc) { (void)cell; (void)subcell; (void)llc; return -ENOENT; }
static struct task_struct *__COMPAT_scx_bpf_cpu_curr(s32 cpu) { (void)cpu; return local_task; }
static int slice_shrink_on_enqueue(struct task_struct *p, struct task_ctx *t, u32 cell, struct cpu_ctx *c) { (void)p; (void)t; (void)cell; (void)c; return 0; }
static int slice_shrink_on_running(struct task_struct *p, u32 cell, struct cpu_ctx *c) { (void)p; (void)cell; (void)c; return 0; }

/* Kernel DSQ adapter: priority by task vtime, FIFO for equal vtime.
 * Every insertion updates p->scx.dsq_vtime, as the kernel helper does.
 * All test tasks can execute on CPU 0; no concurrent dequeue is modeled.
 */
static struct scx_dispatch_q *dsq_for_id(u64 id) {
    for (unsigned i = 0; i < 3; i++)
        if (dsqs[i].id == id) return &dsqs[i];
    for (unsigned i = 0; i < 3; i++) {
        if (dsqs[i].id) continue;
        dsqs[i].id = id;
        return &dsqs[i];
    }
    errors++;
    return NULL;
}
static struct task_struct *dsq_peek(u64 dsq) {
    struct task_struct *head = NULL;
    for (unsigned i = 0; i < 3; i++) {
        struct task_struct *p = &tasks[i];
        if (!p->queued || !p->scx.dsq || p->scx.dsq->id != dsq) continue;
        if (!head || time_before(p->scx.dsq_vtime, head->scx.dsq_vtime) ||
            (p->scx.dsq_vtime == head->scx.dsq_vtime && p->arrival < head->arrival)) head = p;
    }
    return head;
}
static s32 scx_bpf_dsq_nr_queued(u64 dsq) {
    s32 count = 0;
    for (unsigned i = 0; i < 3; i++)
        count += tasks[i].queued && tasks[i].scx.dsq && tasks[i].scx.dsq->id == dsq;
    return count;
}
static bool scx_bpf_dsq_move_to_local(u64 dsq, u64 flags) {
    (void)flags;
    struct task_struct *p = dsq_peek(dsq);
    if (!p) return false;
    p->queued = false;
    p->scx.dsq = &local_dsq;
    local_task = p;
    return true;
}
static void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq, u64 slice, u64 vtime, u64 flags) {
    (void)flags;
    if (p->queued || dsq != p->ctx.dsq.raw) { errors++; return; }
    struct scx_dispatch_q *queue = dsq_for_id(dsq);
    if (!queue) return;
    p->scx.dsq_vtime = vtime;
    p->scx.slice = slice;
    p->scx.flags = SCX_TASK_QUEUED;
    p->scx.dsq = queue;
    p->arrival = ++arrival_seq;
    p->queued = true;
}
static void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    (void)p; (void)dsq; (void)slice; (void)flags;
    fprintf(stderr, "unexpected direct-local placement in fully busy scenario\n"); errors++;
}
"""
prelude += r"""
struct cell_cpumask_data { unsigned char mask[MAX_CPUS / 8 + 1]; };
struct cell_config { struct cell_cpumask_data cpumasks[MAX_CELLS], borrowable_cpumasks[MAX_CELLS]; };
struct cpumask_slot { int unused; };
struct cell_cpumask_wrapper { struct cpumask_slot primary, borrowable; };
static struct cell_cpumask_wrapper masks[MAX_CELLS];
static struct bpf_cpumask mask_scratch;
static int cpu_ctxs;
#define __free(x)
static struct cell_cpumask_wrapper *lookup_cell_cpumask_wrapper(u32 cell) { return &masks[cell]; }
static struct bpf_cpumask *get_tmp_cpumask(struct cpumask_slot *slot) { (void)slot; return &mask_scratch; }
static void bpf_cpumask_clear(struct bpf_cpumask *mask) { mask->bits = 0; }
static void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *mask) { mask->bits |= 1ULL << cpu; }
static int cell_cpumask_data_test_cpu(struct cell_cpumask_data *data, u32 cpu, bool *member) { *member = !!(data->mask[cpu / 8] & (1U << (cpu % 8))); return 0; }
static int publish_prepared_cpumask(struct cpumask_slot *slot, struct bpf_cpumask **mask) { (void)slot; (void)mask; return 0; }
static int set_cpumask_from_data(struct cpumask_slot *slot, struct cell_cpumask_data *data) { (void)slot; (void)data; return 0; }
"""
header_functions = ""
if path.with_name("dsq.bpf.h").is_file():
    dsq_path, dsq_text, dsq_masked = read_header("dsq.bpf.h")
    encoding = "".join(extract_define(dsq_text, name) for name in
                       ("CPU_B", "LLC_B", "SUBCELL_B", "TYPE_B", "DATA_B", "RSVD_B"))
    encoding += extract_declaration(dsq_text, dsq_masked,
                                    r"(?ms)^typedef union\s*\{.*?^\}\s*dsq_id_t;", "dsq_id_t")
    encoding += extract_declaration(dsq_text, dsq_masked,
                                    r"(?ms)^enum dsq_type\s*\{.*?^\};", "dsq_type")
    prelude = prelude.replace("typedef struct { u64 raw; } dsq_id_t;\n", encoding)
    prelude = prelude.replace("#define DSQ_INVALID ((dsq_id_t){~0ULL})\n",
                              extract_define(dsq_text, "DSQ_INVALID"))
    declarations = {
        "pack_subcell_id": "static inline s32 pack_subcell_id(u32 cell, u32 subcell);\n",
        "get_cpu_dsq_id": "static inline dsq_id_t get_cpu_dsq_id(u32 cpu);\n",
        "get_subcell_llc_dsq_id": "static inline dsq_id_t get_subcell_llc_dsq_id(u32 cell, u32 subcell, u32 llc);\n",
        "dsq_is_invalid": "static inline bool dsq_is_invalid(dsq_id_t dsq);\n",
        "get_cpu_from_dsq": "static inline s32 get_cpu_from_dsq(dsq_id_t dsq);\n",
    }
    for name, declaration in declarations.items():
        prelude, count = re.subn(r"(?m)^static [^\n;{]*\b" + name + r"\([^\n]*\n", declaration, prelude)
        if count != 1:
            unsupported(f"cannot replace adapter for {name}")
    header_functions += "".join(extract_function(dsq_text, dsq_masked, name, dsq_path) for name in
                                ("dsq_is_invalid", "is_user_dsq", "is_cpu_dsq", "get_cpu_from_dsq",
                                 "get_cpu_dsq_id", "pack_subcell_id", "get_subcell_llc_dsq_id"))

rescue_helpers = [name for name in ("begin_task_rescue", "take_task_rescue",
                                  "restore_task_rescue_vtime", "repair_running_task_rescue")
                 if re.search(r"\b" + name + r"\s*\(", masked)]
if rescue_helpers:
    rescue_path, rescue_text, rescue_masked = read_header("mitosis.bpf.h")
    constants += [extract_declaration(rescue_text, rescue_masked,
                                     r"(?ms)^enum task_rescue_phase\s*\{.*?^\};", "task_rescue_phase")]
    constants += [extract_define(text + "\n" + rescue_text, name) for name in
                  ("TASK_RESCUE_PHASE_MASK", "TASK_RESCUE_GENERATION_STEP")]
    llc_path, llc_text, llc_masked = read_header("llc_aware.bpf.h")
    constants += [extract_declaration(llc_text, llc_masked, r"(?m)^typedef u32 llc_id_t;", "llc_id_t"),
                  extract_define(llc_text, "LLC_INVALID")]
    header_functions += "".join(extract_function(llc_text, llc_masked, name, llc_path) for name in
                                ("invalidate_task_llc_cpumask", "invalidate_task_llc"))
constants.append("#define FIXTURE_TASK_RESCUE_NONE " +
                 ("TASK_RESCUE_NONE" if rescue_helpers else "0") + "\n")

# Import the real task state and new runtime/demand accounting. Only maps and
# CPU clocks are adapted; virtual-time charging remains in the real callbacks.
task_path, task_text, task_masked = read_header("mitosis.bpf.h")
task_declaration = extract_declaration(task_text, task_masked,
                                     r"(?ms)^struct task_ctx\s*\{.*?^\};", "task_ctx")
prelude, count = re.subn(r"(?ms)^struct task_ctx\s*\{.*?^\};\n",
                        task_declaration, prelude)
if count != 1:
    unsupported("cannot replace task-state adapter")
prelude = "#define __kptr\n" + prelude
constants.append("#define FIXTURE_INIT_RESCUE(ctx) " +
                 ("((ctx).rescue_seq = FIXTURE_TASK_RESCUE_NONE)" if rescue_helpers
                  else "((void)(ctx))") + "\n")
accounting_functions = ""
account_running = extract_function(text, masked, "account_task_running", required=False)
if account_running:
    intf_path, intf_text, intf_masked = read_header("intf.h")
    account_declaration = extract_declaration(intf_text, intf_masked,
                                            r"(?ms)^struct subcell_account\s*\{.*?^\};",
                                            "subcell_account")
    demand_shift = re.search(r"\bDEMAND_SHIFT\s*=\s*([0-9]+)\s*,", intf_masked)
    if not demand_shift:
        unsupported("cannot extract DEMAND_SHIFT")
    constants.append(f"#define DEMAND_SHIFT {demand_shift.group(1)}\n")
    constants += [extract_define(text, name) for name in ("DEMAND_TAU_NS", "DEMAND_MAX_WINDOW_NS")]
    prelude += account_declaration + r"""
static int subcell_accounts;
static struct subcell_account fixture_accounts[MAX_CPUS][MAX_CELLS * MAX_SUBCELLS_PER_CELL];
static u64 scx_clock_task(s32 cpu) { (void)cpu; return now_ns; }
static void *bpf_map_lookup_percpu_elem(void *map, u32 *key, u32 cpu) {
    if (cpu >= MAX_CPUS) return NULL;
    if (map == &cpu_ctxs) return &cpus[cpu];
    if (map == &subcell_accounts && *key < MAX_CELLS * MAX_SUBCELLS_PER_CELL)
        return &fixture_accounts[cpu][*key];
    return NULL;
}
static void *bpf_map_lookup_elem(void *map, u32 *key) {
    return bpf_map_lookup_percpu_elem(map, key, 0);
}
"""
    accounting_functions = extract_function(text, masked, "update_task_demand")
    accounting_functions += account_running
    accounting_functions += extract_function(text, masked, "account_task_queued")
else:
    prelude += "static struct cpu_ctx *bpf_map_lookup_percpu_elem(int *map, u32 *key, u32 cpu) { (void)map; (void)key; return cpu < MAX_CPUS ? &cpus[cpu] : NULL; }\n"

# Main can retag CPUs into nonzero subcells after applying the cell mask.
# Keep older sources supported, while exercising this additional real path.
subcell_configure = extract_function(text, masked, "apply_configured_cell_subcells", required=False)
has_subcell_retag = bool(subcell_configure)
subcell_control = "static int fixture_check_subcell_retag(void) { return 0; }\n"
if has_subcell_retag:
    intf_path, intf_text, intf_masked = read_header("intf.h")
    declarations = {}
    for name in ("cell_cpumask_data", "subcell_match", "subcell_match_and_group",
                 "subcell_config", "subcell", "cell", "cell_assignment", "cell_config"):
        declarations[name] = extract_declaration(intf_text, intf_masked,
                                                r"(?ms)^struct " + name + r"\s*\{.*?^\};", name)
    prelude = prelude.replace("struct cell_cpumask_data { unsigned char mask[MAX_CPUS / 8 + 1]; };\n", "")
    subcell_types = "#define MAX_CPUS_U8 ((MAX_CPUS + 7) / 8)\n"
    for name in ("MAX_COMM", "MAX_SUBCELL_MATCH_ORS", "MAX_SUBCELL_MATCH_ANDS"):
        match = re.search(r"\b" + name + r"\s*=\s*([0-9]+)\s*,", intf_masked)
        if not match:
            unsupported(f"cannot extract {name}")
        subcell_types += f"#define {name} {match.group(1)}\n"
    subcell_types += "".join(declarations[name] for name in
                            ("cell_cpumask_data", "subcell_match", "subcell_match_and_group",
                             "subcell_config", "subcell", "cell"))
    prelude = prelude.replace("struct subcell { struct subcell_llc llcs[MAX_LLCS]; u64 llcs_to_drain; };\n",
                              subcell_types)
    prelude = prelude.replace("struct cell_config { struct cell_cpumask_data cpumasks[MAX_CELLS], borrowable_cpumasks[MAX_CELLS]; };\n",
                              declarations["cell_assignment"] + declarations["cell_config"])
    prelude = prelude.replace("static struct subcell subcells[MAX_CELLS][MAX_SUBCELLS_PER_CELL];\n",
                              "static struct cell fixture_cells[MAX_CELLS];\n")
    prelude = prelude.replace("return &subcells[cell][subcell];", "return &fixture_cells[cell].subcells[subcell];")
    prelude = prelude.replace("struct cpumask_slot { int unused; };", "struct cpumask_slot { struct bpf_cpumask mask; };")
    prelude = prelude.replace("static int publish_prepared_cpumask(struct cpumask_slot *slot, struct bpf_cpumask **mask) { (void)slot; (void)mask; return 0; }",
                              "static int publish_prepared_cpumask(struct cpumask_slot *slot, struct bpf_cpumask **mask) { slot->mask = **mask; return 0; }")
    prelude = prelude.replace("static int set_cpumask_from_data(struct cpumask_slot *slot, struct cell_cpumask_data *data) { (void)slot; (void)data; return 0; }",
                              "static int set_cpumask_from_data(struct cpumask_slot *slot, struct cell_cpumask_data *data) { slot->mask.bits = data->mask[0]; return 0; }")
    prelude += r"""
#define scoped_guard(name) for (int fixture_guard = 0; fixture_guard < 1; fixture_guard++)
static struct cell_cpumask_wrapper subcell_masks[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
static struct cell *lookup_cell(u32 cell) { return cell < MAX_CELLS ? &fixture_cells[cell] : NULL; }
static struct cell_cpumask_wrapper *lookup_subcell_cpumask_wrapper(u32 cell, u32 subcell) {
    return cell < MAX_CELLS && subcell < MAX_SUBCELLS_PER_CELL ? &subcell_masks[cell][subcell] : NULL;
}
static int refresh_subcell_llc_draining(u32 cell, u32 subcell) {
    (void)cell; (void)subcell;
    /* The real helper returns immediately when LLC awareness is disabled. */
    if (enable_llc_awareness) { errors++; return -EINVAL; }
    return 0;
}
"""
    subcell_control = r"""
static int fixture_check_subcell_retag(void) {
    const u64 gap = 100000000000ULL;
    struct cell_config config = {0};
    config.cpumasks[1].mask[0] = 3;
    config.subcells[1][0].id = 0;
    config.subcells[1][0].in_use = 1;
    config.subcells[1][0].primary.mask[0] = 2;
    config.subcells[1][1].id = 1;
    config.subcells[1][1].in_use = 1;
    config.subcells[1][1].primary.mask[0] = 1;
    cpus[0].cell = cpus[1].cell = 1;
    cpus[1].subcell = 1;
    cpus[1].vtime_now = gap;
    lookup_subcell(1, 1)->llcs[0].vtime_now = gap;
    if (apply_configured_cell_subcells(1, &config) || errors) return 2;
    if (cpus[0].cell != 1 || cpus[0].subcell != 1 ||
        cpus[1].cell != 1 || cpus[1].subcell != 0 ||
        subcell_masks[1][1].primary.mask.bits != 1) {
        fprintf(stderr, "ERROR: subcell control did not perform the requested CPU swap\n");
        return 2;
    }
    printf("Nonzero subcell reassignment: CPU clock=%.3fs, destination shared clock=%.3fs\n",
           (cpus[0].vtime_now - cpus[0].vtime_bias) / 1e9, lookup_subcell(1, 1)->llcs[0].vtime_now / 1e9);
    int result = cpus[0].vtime_now - cpus[0].vtime_bias != gap || lookup_subcell(1, 1)->llcs[0].vtime_now != gap;
    if (result)
        puts("BUG 1: nonzero subcell reassignment leaves a cold CPU behind its hot shared clock.");
    else
        puts("PASS: nonzero subcell reassignment aligns both clock domains.");
    memset(cpus, 0, sizeof(cpus));
    memset(fixture_cells, 0, sizeof(fixture_cells));
    memset(subcell_masks, 0, sizeof(subcell_masks));
    return result;
}
"""

functions = ["set_pinned_vtime_charge_cpu", "set_vtime_charge_subcell"]
if re.search(r"\badvance_vtime\s*\(", masked):
    functions.append("advance_vtime")
if re.search(r"\btask_shared_vtime\s*\(", masked):
    functions.append("task_shared_vtime")
functions += [name for name in rescue_helpers if name != "repair_running_task_rescue"]
functions += ["cap_vtime_debt", "mitosis_enqueue", "pinned_dsq_overdue",
              "advance_subcell_llc_vtime"]
if re.search(r"\badvance_task_vtime\s*\(", masked):
    functions.append("advance_task_vtime")
if re.search(r"\bclear_pinned_wait\s*\(", masked):
    functions.append("clear_pinned_wait")
if "repair_running_task_rescue" in rescue_helpers:
    functions.append("repair_running_task_rescue")
functions += ["mitosis_dispatch", "mitosis_running", "update_task_runtime_ewma"]
if extract_function(text, masked, "charge_running", required=False):
    functions.append("charge_running")
functions += ["mitosis_stopping", "apply_configured_cell_cpumask"]
if has_subcell_retag:
    functions.append("apply_configured_cell_subcells")
code = prelude + "".join(constants)
code += header_functions
code += accounting_functions
code += extract_function(text, masked, "apply_cpu_vtime_assignment", required=False)
code += extract_function(text, masked, "configured_cpu_subcell", required=False)
code += extract_function(text, masked, "request_cpu_vtime_assignment", required=False)
code += "".join(extract_function(text, masked, name) for name in functions)
code += "static void scx_bpf_kick_cpu(s32 cpu, int flags) { (void)flags; "
if extract_function(text, masked, "apply_cpu_vtime_assignment", required=False):
    if "fixture_cpu" not in prelude:
        prelude = prelude.replace("static int errors;", "static int errors, fixture_cpu;")
        prelude = prelude.replace("cpus[cpu < 0 ? 0 : cpu]", "cpus[cpu < 0 ? fixture_cpu : cpu]")
        code = code.replace("static int errors;", "static int errors, fixture_cpu;")
        code = code.replace("cpus[cpu < 0 ? 0 : cpu]", "cpus[cpu < 0 ? fixture_cpu : cpu]")
    code += "if (flags == SCX_KICK_PREEMPT) { int saved = fixture_cpu; fixture_cpu = cpu; if (apply_cpu_vtime_assignment(&cpus[cpu])) errors++; fixture_cpu = saved; } "
else:
    code += "(void)cpu; "
code += "}\n"

code += subcell_control
code += r"""
int main(void) {
    int retag_status = fixture_check_subcell_retag();
    if (retag_status == 2) return 2;
    const u64 gap = 100000000000ULL;
    const u64 pinned_count = 2;
    struct cell_config config = {0};
    /* Reachable assignment: CPU 0 moves from a cold cell to a previously
     * active cell with retained shared-clock history. Pinned tasks belong to
     * cell 0, which has other CPUs, and retain their CPU 0 DSQ across the move.
     * A destination cell's own single-CPU tasks would use its shared DSQ.
     */
    cpus[0].cell = 2;
    cpus[1].cell = 1;
    cpus[1].vtime_now = gap;
    cpus[2].cell = 0;
    subcells[1][0].llcs[0].vtime_now = gap;
    config.cpumasks[0].mask[0] = 4;  /* root retains CPU 2 */
    config.cpumasks[1].mask[0] = 1;  /* hot cell gains cold CPU 0 */
    config.cpumasks[2].mask[0] = 2;  /* cold cell gains old hot CPU 1 */
    for (unsigned i = 0; i < 3; i++) {
        struct task_struct *p = &tasks[i];
        p->pid = (int)i + 1;
        p->cpus_ptr = i == 2 ? &shared_affinity : &task_affinity;
        p->scx.weight = 100;
        FIXTURE_INIT_RESCUE(p->ctx);
        p->cpu = 0;
        p->ctx.cell = i == 2 ? 1 : 0;
        p->ctx.all_cell_cpus_allowed = i == 2;
        p->ctx.dsq = i == 2 ? get_subcell_llc_dsq_id(1, 0, 0) : get_cpu_dsq_id(0);
        p->scx.dsq_vtime = i == 2 ? gap : 0;
        mitosis_enqueue(p, SCX_ENQ_CPU_SELECTED);  /* select_cpu has already found the CPU busy */
    }
    for (u32 cell = 0; cell < 3; cell++)
        if (apply_configured_cell_cpumask(cell, &config) || errors) return 2;
    printf("After real CPU reassignment: CPU clock=%.3fs, destination shared clock=%.3fs\n",
           (cpus[0].vtime_now - cpus[0].vtime_bias) / 1e9, subcells[1][0].llcs[0].vtime_now / 1e9);
    u64 slices = 0;
    u64 bound = pinned_count * (gap / slice_ns + 2) + 32;
    while (slices <= bound) {
        local_task = NULL;
        mitosis_dispatch(0, NULL);
        if (errors || !local_task) { fprintf(stderr, "ERROR: dispatch made no progress\n"); return 2; }
        if (local_task == &tasks[2]) {
            double delay = slices * slice_ns / 1e9;
            printf("First shared service after %.3fs simulated CPU runtime (%llu pinned slices).\n", delay, slices);
            if (slices > 8) {
                printf("Gap=100s; two equal pinned competitors give about 200s of delay.\n");
                printf("BUG 1 REPRODUCED: shared work waits beyond eight slices because its clock is ahead.\n");
                return 1;
            }
            printf("PASS: shared work received prompt service in this scenario.\n");
            return retag_status;
        }
        struct task_struct *p = local_task;
        p->scx.dsq = NULL;  /* The kernel dequeues the local task before running(). */
        mitosis_running(p);
        now_ns += slice_ns;
        mitosis_stopping(p, true);
        mitosis_enqueue(p, SCX_ENQ_CPU_SELECTED);
        if (errors) return 2;
        slices++;
    }
    fprintf(stderr, "BUG 1 REPRODUCED: shared work still unserved after the clock-gap bound.\n");
    return 1;
}
"""
if has_subcell_retag:
    code = re.sub(r"(?<![\w.>])subcells\[1\]\[0\]", "fixture_cells[1].subcells[0]", code)
try:
    pathlib.Path(sys.argv[3]).write_text(code)
except OSError as exc:
    print(f"ERROR: cannot write generated harness: {exc}", file=sys.stderr)
    raise SystemExit(2)
PYTHON
if ! "${CC:-cc}" -O2 -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -Wno-unused-const-variable -Wno-sign-compare -Wno-attributes "$repro_tmp/repro.c" -o "$repro_tmp/repro"; then
    printf 'ERROR: cannot compile callbacks with this harness; checkout may need new adapters\n' >&2
    exit 2
fi
"$repro_tmp/repro"
