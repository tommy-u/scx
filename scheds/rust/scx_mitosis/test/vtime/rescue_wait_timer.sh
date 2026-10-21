#!/usr/bin/env bash
# Compile the checkout's scheduling C against deterministic CPU/DSQ fixtures.
# This is a source-level reproducer; it does not load BPF or change host state.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: rescue_wait_timer.sh [--source CHECKOUT]

Check whether affinity rescue starts the target CPU DSQ wait timer.

Compiles the real scheduling functions from CHECKOUT with deterministic
clock, affinity, and DSQ primitives. Requires Python 3 and a C compiler.
It does not run scx_mitosis or measure behavior on a live kernel.

Source: --source, then MITOSIS_SOURCE, then this script's checkout or cwd.
Compiler: CC (default cc). Exit: 0 PASS/bug absent; 1 BUG reproduced;
2 error/unsupported source; 77 missing prerequisite.
HELP
}

source_root="${MITOSIS_SOURCE:-}"
while (( $# )); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --source)
            if (( $# < 2 )) || [[ -z "$2" ]]; then
                echo 'ERROR: --source requires a checkout path' >&2
                exit 2
            fi
            source_root="$2"; shift 2 ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$source_root" ]]; then
    source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    while [[ ! -f "$source_root/scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c" && "$source_root" != / ]]; do
        source_root="$(dirname -- "$source_root")"
    done
    if [[ "$source_root" == / ]]; then source_root="$PWD"; fi
fi
if [[ ! -f "$source_root/scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c" ]]; then
    echo "ERROR: no scx_mitosis source in $source_root; use --source CHECKOUT" >&2
    exit 2
fi
compiler="${CC:-cc}"
for dependency in python3 "$compiler"; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "SKIP: missing prerequisite: $dependency" >&2
        exit 77
    fi
done
repro_tmp="$(mktemp -d /tmp/mitosis-vtime-4.XXXXXX)" || exit 2
trap 'rm -rf -- "$repro_tmp"' EXIT
trap 'exit 2' INT TERM

if ! python3 - "$source_root" "$repro_tmp/repro.c" <<'PYTHON'
import re
import sys
from pathlib import Path

root, output = map(Path, sys.argv[1:])
bpf = root / "scheds/rust/scx_mitosis/src/bpf"


def syntax_only(text):
    """Mask comments and quoted text without changing offsets or newlines."""
    out = list(text)
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            if end < 0:
                end = len(text)
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated C comment")
            end += 2
        elif text[i] in "\"'":
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
                raise ValueError("unterminated C string/character literal")
        else:
            i += 1
            continue
        for j in range(i, min(end, len(text))):
            if out[j] != "\n":
                out[j] = " "
        i = end
    return "".join(out)


def braced(text, pattern, declaration=False):
    clean = syntax_only(text)
    matches = [m for m in re.finditer(pattern, clean, re.M)
               if clean[:m.start()].count("{") == clean[:m.start()].count("}")]
    if len(matches) != 1:
        raise ValueError(f"expected one declaration matching {pattern!r}, found {len(matches)}")
    start = matches[0].start()
    opening = clean.find("{", matches[0].start())
    if opening < 0 or ";" in clean[matches[0].start():opening]:
        raise ValueError(f"missing body for {pattern!r}")
    depth = 1
    end = opening + 1
    while depth and end < len(clean):
        depth += (clean[end] == "{") - (clean[end] == "}")
        end += 1
    if depth:
        raise ValueError(f"unterminated body for {pattern!r}")
    if declaration:
        semicolon = clean.find(";", end)
        if semicolon < 0:
            raise ValueError(f"missing declaration terminator for {pattern!r}")
        end = semicolon + 1
    return text[start:end]


def function(text, name):
    regular = rf"^[ \t]*(?:static[ \t]+)?[A-Za-z_][^\n;{{}}]*\b{re.escape(name)}[ \t]*\("
    callback = rf"^[ \t]*[A-Za-z_][^\n;{{}}]*\bBPF_STRUCT_OPS[ \t]*\([ \t]*{re.escape(name)}[ \t]*,"
    clean = syntax_only(text)
    return braced(text, callback if re.search(callback, clean, re.M) else regular)


def optional_function(text, name):
    pattern = rf"^[ \t]*(?:static[ \t]+)?[A-Za-z_][^\n;{{}}]*\b{re.escape(name)}[ \t]*\("
    clean = syntax_only(text)
    for match in re.finditer(pattern, clean, re.M):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        return braced(text[match.start():], pattern)
    return None


try:
    intf = (bpf / "intf.h").read_text()
    defs = (bpf / "mitosis.bpf.h").read_text()
    dsq = (bpf / "dsq.bpf.h").read_text()
    llc = (bpf / "llc_aware.bpf.h").read_text()
    mitosis = (bpf / "mitosis.bpf.c").read_text()
    declarations = [braced(intf, r"^enum consts\b", True),
                    braced(intf, r"^enum cell_stat_idx\b", True)]
    for macro in ("CPU_B", "LLC_B", "SUBCELL_B", "TYPE_B", "DATA_B", "RSVD_B"):
        match = re.search(rf"^#define[ \t]+{macro}[ \t]+[^\n]+", dsq, re.M)
        if not match:
            raise ValueError(f"missing {macro}")
        declarations.append(match.group())
    declarations += [braced(dsq, r"^typedef union\b", True),
                     braced(dsq, r"^enum dsq_type\b", True)]
    declarations.append(braced(intf, r"^struct cell_cpumask_data[ \t]*\{", True))
    declarations.append("typedef u32 llc_id_t;")
    invalid = re.search(r"^#define[ \t]+LLC_INVALID[ \t]+[^\n]+", llc, re.M)
    if not invalid:
        raise ValueError("missing LLC_INVALID")
    declarations.append(invalid.group())
    # Newer interfaces embed match groups and expose per-subcell demand data.
    for name in ("subcell_match", "subcell_match_and_group", "subcell_account"):
        pattern = rf"^struct {name}[ \t]*\{{"
        if re.search(pattern, syntax_only(intf), re.M):
            declarations.append(braced(intf, pattern, True))
    declarations += [braced(intf, rf"^struct {name}[ \t]*\{{", True)
                     for name in ("cpu_ctx", "subcell_llc", "subcell", "cell")]
    declarations.append(braced(defs, r"^struct task_ctx[ \t]*\{", True))
    if re.search(r"^enum task_rescue_phase\b", syntax_only(defs), re.M):
        declarations.append("#define HAS_TASK_RESCUE 1")
        declarations.append(braced(defs, r"^enum task_rescue_phase\b", True))
        for macro in ("TASK_RESCUE_PHASE_MASK", "TASK_RESCUE_GENERATION_STEP"):
            match = re.search(rf"^#define[ \t]+{macro}[ \t]+[^\n]+", defs, re.M)
            if not match:
                raise ValueError(f"missing {macro}")
            declarations.append(match.group())
    for macro in ("PINNED_MAX_WAIT_SLICES", "FAKE_FLAT_SUBCELL_LLC"):
        match = re.search(rf"^#define[ \t]+{macro}[ \t]+[^\n]+", mitosis, re.M)
        if not match:
            raise ValueError(f"missing {macro}")
        declarations.append(match.group())
    functions = [function(dsq, name) for name in
                 ("dsq_is_invalid", "is_user_dsq", "is_cpu_dsq", "get_cpu_from_dsq",
                  "get_cpu_dsq_id", "pack_subcell_id", "get_subcell_llc_dsq_id")]
    declarations += [body[:syntax_only(body).find("{")].rstrip() + ";"
                     for body in functions]
    functions.append(function(mitosis, "set_pinned_vtime_charge_cpu"))
    functions += [function(llc, name) for name in
                  ("llc_is_valid", "invalidate_task_llc_cpumask", "invalidate_task_llc",
                   "subcell_llc_drain_enable", "subcell_llc_drain_disable",
                   "subcell_llc_nr_queued_dec", "subcell_llc_has_cpus")]
    for helper in ("begin_task_rescue", "take_task_rescue", "task_shared_vtime",
                   "restore_task_rescue_vtime", "repair_running_task_rescue"):
        body = optional_function(mitosis, helper)
        if body:
            functions.append(body)
    functions.append(function(llc, "try_draining_work"))
    for helper in ("apply_cpu_vtime_assignment", "advance_vtime", "advance_subcell_llc_vtime", "advance_task_vtime"):
        declaration = rf"^[ \t]*(?:static|bool|int|u64)\b[^\n;{{}}]*\b{helper}[ \t]*\("
        if re.search(declaration, syntax_only(mitosis), re.M):
            functions.append(function(mitosis, helper))
    for helper in ("clear_pinned_wait", "consume_cpu_dsq"):
        body = optional_function(mitosis, helper)
        if body:
            functions.append(body)
    accounting = optional_function(mitosis, "account_task_running")
    if accounting:
        declarations.append("#define HAS_RUNNING_ACCOUNTING 1")
        for macro in ("DEMAND_TAU_NS", "DEMAND_MAX_WINDOW_NS"):
            match = re.search(rf"^#define[ \t]+{macro}[ \t]+[^\n]+", mitosis, re.M)
            if not match:
                raise ValueError(f"missing {macro}")
            declarations.append(match.group())
        functions += [function(mitosis, "update_task_demand"), accounting]
    functions += [function(mitosis, name) for name in
                  ("pinned_dsq_overdue", "mitosis_dispatch")]
except (OSError, ValueError) as error:
    print(f"ERROR: unsupported/incomplete source: {error}", file=sys.stderr)
    sys.exit(2)

preamble = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef signed long long s64;
typedef signed int s32;
#define __kptr
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define SCX_CACHELINE_SIZE 64
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, y) ((x) = (y))
#define MEMBER_VPTR(obj, member) (&((obj) member))
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#define barrier_var(x) ((void)(x))
#define unlikely(x) (x)
#define PF_IDLE 1
#define SCX_TASK_QUEUED 1
#define SCX_KICK_IDLE 1
#define SCX_KICK_PREEMPT 2
#define SCX_DSQ_GLOBAL ((1ULL << 63) | 1)
#define SCX_DSQ_LOCAL ((1ULL << 63) | 2)
#define DSQ_INVALID ((dsq_id_t){0})
#define scx_bpf_error(...) do { fprintf(stderr, "ERROR: "); \
    fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); exit(2); } while (0)
static bool time_before(u64 a, u64 b) { return (s64)(a - b) < 0; }
static bool time_after(u64 a, u64 b) { return (s64)(a - b) > 0; }
static u64 time_delta(u64 now, u64 before) { return now > before ? now - before : 0; }
"""

fixtures = r"""
/* Kernel primitives are fixtures; the scheduling functions below are intact. */
struct cpumask { u64 bits; };
struct bpf_cpumask { u64 bits; };
struct scx_dispatch_q { u64 id; };
struct task_struct {
    int pid, cpu;
    u64 flags;
    const struct cpumask *cpus_ptr;
    struct { u64 dsq_vtime, slice, flags; u32 weight; struct scx_dispatch_q *dsq; } scx;
    struct task_ctx *context;
};
enum { CONTINUE_DISPATCH = 1, FIXTURE_CPUS = 2, FIXTURE_CELLS = 3, QUEUE_CAPACITY = 32 };
static const u64 slice_ns = 20000000;
static const bool enable_llc_awareness = true;
static const u32 nr_llc = 2, nr_possible_cpus = FIXTURE_CPUS;
static struct cpu_ctx cpus[FIXTURE_CPUS];
static struct cell cells[FIXTURE_CELLS];
static u64 clock_now;
static int current_cpu;
static struct task_struct *local_task;
static bool fail_remote_move;
static struct task_struct *arrival_on_empty_cpu_peek;
static bool overlap_injected;
#ifdef HAS_RUNNING_ACCOUNTING
/* Model the kernel PERCPU_ARRAY, keeping the scheduler's accounting intact. */
struct fixture_account_map {
    struct subcell_account slots[FIXTURE_CELLS * MAX_SUBCELLS_PER_CELL][FIXTURE_CPUS];
};
static struct fixture_account_map subcell_accounts;
static u64 cpu_task_clock[FIXTURE_CPUS];
static struct subcell_account *bpf_map_lookup_percpu_elem(struct fixture_account_map *map,
                                                         const u32 *key, u32 cpu) {
    if (map != &subcell_accounts || !key ||
        *key >= FIXTURE_CELLS * MAX_SUBCELLS_PER_CELL || cpu >= FIXTURE_CPUS)
        return NULL;
    return &map->slots[*key][cpu];
}
static u64 scx_clock_task(s32 cpu) {
    if (cpu < 0 || cpu >= FIXTURE_CPUS) scx_bpf_error("fixture task-clock CPU out of range");
    return cpu_task_clock[cpu];
}
#endif
struct queue { struct scx_dispatch_q dsq; struct task_struct *tasks[QUEUE_CAPACITY]; u32 nr; };
static struct queue cpu_queues[FIXTURE_CPUS];
static struct queue llc_queues[FIXTURE_CELLS][MAX_SUBCELLS_PER_CELL][2];
struct dsq_iter { struct queue *queue; u64 vtime; bool once, has_vtime; };
#define BPF_FOR_EACH_ITER (&fixture_iter)
#define bpf_for_each(kind, p, dsq, flags) \
    for (struct dsq_iter fixture_iter = {.queue = queue_for(dsq)}; \
         !fixture_iter.once && ((p) = fixture_iter.queue->nr ? fixture_iter.queue->tasks[0] : NULL); \
         fixture_iter.once = true)
static struct cpu_ctx *lookup_cpu_ctx(int cpu) {
    if (cpu < 0) cpu = current_cpu;
    if (cpu >= FIXTURE_CPUS) scx_bpf_error("fixture CPU out of range");
    return &cpus[cpu];
}
static struct subcell *lookup_subcell(u32 cell, u32 subcell) {
    if (cell >= FIXTURE_CELLS || subcell >= MAX_SUBCELLS_PER_CELL)
        scx_bpf_error("fixture subcell out of range");
    return &cells[cell].subcells[subcell];
}
static struct subcell_llc *lookup_subcell_llc(struct subcell *subcell, u32 llc) {
    if (!subcell || llc >= 2) scx_bpf_error("fixture LLC out of range");
    return &subcell->llcs[llc];
}
static struct task_ctx *lookup_task_ctx(struct task_struct *p) { return p->context; }
static void cstat_inc(enum cell_stat_idx stat, u32 cell, struct cpu_ctx *cpu) { cpu->cstats[cell][stat]++; }
static void kick_subcell_idle_cpu(u32 cell, u32 subcell) { (void)cell; (void)subcell; }
static void scx_bpf_kick_cpu(int cpu, int flags) { (void)cpu; (void)flags; }
static u64 scx_bpf_now(void) { return clock_now; }
static u64 bpf_ktime_get_ns(void) { return clock_now; }
static int scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static bool scx_bpf_task_set_slice(struct task_struct *p, u64 slice) {
    p->scx.slice = slice; return true;
}
static bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 vtime) {
    p->scx.dsq_vtime = vtime; return true;
}
static u32 bpf_cpumask_any_distribute(const struct cpumask *mask) {
    return mask->bits ? (u32)__builtin_ctzll(mask->bits) : nr_possible_cpus;
}
static bool task_needs_refresh(struct task_struct *p, struct task_ctx *tctx) { (void)p; (void)tctx; return true; }
static int maybe_update_task_llc(struct task_struct *p, struct task_ctx *tctx, s32 cpu) {
    (void)p; (void)tctx; (void)cpu;
    scx_bpf_error("unexpected LLC retag: rescue must retain CPU DSQ for this slice");
    return -1;
}
static int slice_shrink_on_running(struct task_struct *p, u32 cell, struct cpu_ctx *cpu) {
    (void)p; (void)cell; (void)cpu; return 0;
}
static struct queue *queue_for(u64 raw) {
    dsq_id_t dsq = {.raw = raw};
    if (dsq.user_dsq.type == DSQ_TYPE_CPU && dsq.cpu_dsq.cpu < FIXTURE_CPUS)
        return &cpu_queues[dsq.cpu_dsq.cpu];
    if (dsq.user_dsq.type == DSQ_TYPE_SUBCELL_LLC) {
        u32 cell = dsq.subcell_llc_dsq.subcell / MAX_SUBCELLS_PER_CELL;
        u32 subcell = dsq.subcell_llc_dsq.subcell % MAX_SUBCELLS_PER_CELL;
        if (cell < FIXTURE_CELLS && dsq.subcell_llc_dsq.llc < 2)
            return &llc_queues[cell][subcell][dsq.subcell_llc_dsq.llc];
    }
    scx_bpf_error("invalid fixture DSQ %llx", raw);
    return NULL;
}
static void push(struct queue *q, struct task_struct *p) {
    if (q->nr == QUEUE_CAPACITY) scx_bpf_error("fixture queue overflow");
    u32 i = q->nr++;
    while (i && time_before(p->scx.dsq_vtime, q->tasks[i-1]->scx.dsq_vtime)) {
        q->tasks[i] = q->tasks[i-1]; i--;
    }
    q->tasks[i] = p;
    p->scx.dsq = &q->dsq;
}
static void remove_at(struct queue *q, u32 i) {
    q->tasks[i]->scx.dsq = NULL;
    memmove(q->tasks + i, q->tasks + i + 1, (q->nr - i - 1) * sizeof(q->tasks[0])); q->nr--;
}
static struct task_struct *dsq_peek(u64 raw) {
    struct queue *q = queue_for(raw);
    struct task_struct *head = q->nr ? q->tasks[0] : NULL;
    dsq_id_t dsq = {.raw = raw};
    if (!head && arrival_on_empty_cpu_peek && dsq.user_dsq.type == DSQ_TYPE_CPU) {
        /* Capture NULL first, then let a producer arrive before the caller clears. */
        push(q, arrival_on_empty_cpu_peek);
        __sync_val_compare_and_swap(&cpus[dsq.cpu_dsq.cpu].pinned_waiting_since, 0,
                                    bpf_ktime_get_ns());
        arrival_on_empty_cpu_peek = NULL;
        overlap_injected = true;
    }
    return head;
}
static s32 scx_bpf_dsq_nr_queued(u64 raw) {
    struct queue *q = queue_for(raw); return q ? (s32)q->nr : -ENOENT;
}
static bool scx_bpf_dsq_move_to_local(u64 raw, u64 flags) {
    (void)flags; struct queue *q = queue_for(raw);
    for (u32 i = 0; i < q->nr; i++) {
        struct task_struct *p = q->tasks[i];
        if (p->cpus_ptr->bits & (1ULL << current_cpu)) {
            remove_at(q, i); local_task = p; p->cpu = current_cpu; return true;
        }
    }
    return false;
}
static void scx_bpf_dsq_move_set_vtime(struct dsq_iter *iter, u64 vtime) {
    iter->vtime = vtime; iter->has_vtime = true;
}
static bool scx_bpf_dsq_move_vtime(struct dsq_iter *iter, struct task_struct *p, u64 raw, u64 flags) {
    (void)flags;
    if (fail_remote_move) return false;
    for (u32 i = 0; i < iter->queue->nr; i++) {
        if (iter->queue->tasks[i] == p) {
            remove_at(iter->queue, i);
            if (iter->has_vtime) p->scx.dsq_vtime = iter->vtime;
            push(queue_for(raw), p); return true;
        }
    }
    return false;
}
static int try_stealing_work(u32 cell, u32 subcell, s32 llc) {
    (void)cell; (void)subcell; (void)llc; return -ENOENT;
}
static void reset_fixture(void) {
    memset(cpus, 0, sizeof(cpus)); memset(cells, 0, sizeof(cells));
    memset(cpu_queues, 0, sizeof(cpu_queues)); memset(llc_queues, 0, sizeof(llc_queues));
#ifdef HAS_RUNNING_ACCOUNTING
    memset(&subcell_accounts, 0, sizeof(subcell_accounts));
#endif
    for (u32 cpu = 0; cpu < FIXTURE_CPUS; cpu++)
        cpu_queues[cpu].dsq.id = get_cpu_dsq_id(cpu).raw;
    for (u32 cell = 0; cell < FIXTURE_CELLS; cell++)
        for (u32 subcell = 0; subcell < MAX_SUBCELLS_PER_CELL; subcell++)
            for (u32 llc = 0; llc < 2; llc++)
                llc_queues[cell][subcell][llc].dsq.id = get_subcell_llc_dsq_id(cell, subcell, llc).raw;
    current_cpu = 0; clock_now = 1000000; local_task = NULL; fail_remote_move = false;
#ifdef HAS_RUNNING_ACCOUNTING
    for (u32 cpu = 0; cpu < FIXTURE_CPUS; cpu++) cpu_task_clock[cpu] = clock_now;
#endif
    arrival_on_empty_cpu_peek = NULL; overlap_injected = false;
    cpus[0].cell = 1; cpus[0].llc = 1;
    cpus[1].cell = 2; cpus[1].llc = 0;
    cells[1].subcells[0].llcs_with_cpus = 1ULL << 1;
    cells[2].subcells[0].llcs_with_cpus = 1ULL << 0;
}
static void require(bool ok, const char *message) {
    if (!ok) scx_bpf_error("fixture/source assumption failed: %s", message);
}
static bool failed_rescue_metadata_unchanged(const struct task_ctx *after,
                                             const struct task_ctx *before) {
    struct task_ctx result = *after;
#ifdef HAS_TASK_RESCUE
    if ((result.rescue_seq & TASK_RESCUE_PHASE_MASK) != TASK_RESCUE_NONE)
        return false;
    /* Idle generations and their inactive payload do not publish ownership. */
    result.rescue_seq = before->rescue_seq;
    result.rescue_vtime = before->rescue_vtime;
#endif
    return !memcmp(&result, before, sizeof(result));
}
"""

main = r"""
static bool clear_overlap_control(void) {
    struct cpumask target_mask = {.bits = 2};
    struct task_ctx pinned_ctx = {.cell = 2, .llc = -1, .vtime_charge_subcell = 16};
    struct task_struct pinned = {.pid = 201, .cpu = 1, .cpus_ptr = &target_mask,
                                 .context = &pinned_ctx,
                                 .scx = {.dsq_vtime = 500000000, .weight = 100}};
    struct task_ctx shared_ctx = {.cell = 2, .llc = 0, .all_cell_cpus_allowed = true};
    struct task_struct shared = {.pid = 202, .cpu = 1, .cpus_ptr = &target_mask,
                                 .context = &shared_ctx,
                                 .scx = {.dsq_vtime = 480000000, .weight = 100}};
    reset_fixture(); current_cpu = 1;
    cpus[1].vtime_now = 500000000;
    cells[2].subcells[0].llcs[0].vtime_now = 500000000;
    cells[2].subcells[0].llcs[0].nr_queued = 1;
    pinned_ctx.dsq = get_cpu_dsq_id(1);
    shared_ctx.dsq = get_subcell_llc_dsq_id(2, 0, 0);
    push(&llc_queues[2][0][0], &shared);
    arrival_on_empty_cpu_peek = &pinned;
    const u64 arrival_at = clock_now;
    mitosis_dispatch(1, NULL);
    require(overlap_injected, "dispatch must observe the injected empty CPU peek");
    require(local_task == &shared && cpu_queues[1].nr == 1,
            "new waiter must remain queued after the lower-vtime shared task is selected");
    printf("Clear overlap: producer start=%llu ns, timer after clear=%llu ns, queued waiter=%u.\n",
           arrival_at, cpus[1].pinned_waiting_since, cpu_queues[1].nr);
    if (!cpus[1].pinned_waiting_since) {
        puts("BUG 4: empty CPU peek cleared the timer of a racing pinned arrival.");
        return false;
    }
    return true;
}

static bool rescue_controls(void) {
    struct cpumask target_mask = {.bits = 2};
    struct task_ctx existing_ctx = {.cell = 2, .llc = -1};
    struct task_struct existing = {.pid = 101, .cpus_ptr = &target_mask, .context = &existing_ctx,
                                   .scx = {.dsq_vtime = 500000000, .weight = 100}};
    struct task_ctx victim_ctx = {.cell = 1, .llc = 0, .llc_cpumask_id = 0,
                                  .basis_vtime = 123456, .configuration_seq = 37,
                                  .all_cell_cpus_allowed = true, .vtime_charge_subcell = 8};
    struct task_struct victim = {.pid = 102, .cpus_ptr = &target_mask, .context = &victim_ctx,
                                 .scx = {.dsq_vtime = 60000000, .weight = 100}};
    reset_fixture();
    cpus[1].vtime_now = 500000000;
    cpus[1].pinned_waiting_since = 100000;
    existing_ctx.dsq = get_cpu_dsq_id(1);
    victim_ctx.dsq = get_subcell_llc_dsq_id(1, 0, 0);
    cells[1].subcells[0].llcs_to_drain = 1;
    cells[1].subcells[0].llcs[0].nr_queued = 1;
    push(&cpu_queues[1], &existing);
    push(&llc_queues[1][0][0], &victim);
    if (try_draining_work(1, 0, 1, &cpus[0]) != CONTINUE_DISPATCH ||
        cpu_queues[1].nr != 2 || cpus[1].pinned_waiting_since != 100000 ||
        victim.scx.dsq_vtime != 500000000) {
        puts("BUG 4: another rescue reset an existing CPU DSQ wait timer.");
        return false;
    }

    /* A failed move transfers no ownership, vtime, or waiting state. */
    reset_fixture();
    cpus[1].vtime_now = 500000000;
    victim_ctx = (struct task_ctx){.cell = 1, .llc = 0, .llc_cpumask_id = 0,
                                   .basis_vtime = 123456, .configuration_seq = 37,
                                   .all_cell_cpus_allowed = true, .vtime_charge_subcell = 8};
    victim_ctx.dsq = get_subcell_llc_dsq_id(1, 0, 0);
    victim.scx.dsq_vtime = 60000000;
    struct task_ctx before = victim_ctx;
    cells[1].subcells[0].llcs_to_drain = 1;
    cells[1].subcells[0].llcs[0].nr_queued = 1;
    push(&llc_queues[1][0][0], &victim);
    fail_remote_move = true;
    if (try_draining_work(1, 0, 1, &cpus[0]) != -ENOENT ||
        cpu_queues[1].nr != 0 || llc_queues[1][0][0].nr != 1 ||
        cpus[1].pinned_waiting_since != 0 || victim.scx.dsq_vtime != 60000000 ||
        victim_ctx.dsq.raw != before.dsq.raw || victim_ctx.basis_vtime != before.basis_vtime ||
        victim_ctx.vtime_charge_subcell != before.vtime_charge_subcell ||
        victim_ctx.cell != before.cell || victim_ctx.subcell != before.subcell ||
        victim_ctx.llc != before.llc || victim_ctx.llc_cpumask_id != before.llc_cpumask_id ||
        victim_ctx.configuration_seq != before.configuration_seq ||
        victim_ctx.all_cell_cpus_allowed != before.all_cell_cpus_allowed ||
        victim_ctx.borrowed != before.borrowed || cells[1].subcells[0].llcs[0].nr_queued != 1) {
        puts("BUG 4: failed remote rescue changed task metadata or the target wait timer.");
        return false;
    }
    puts("Rescue controls: preserve an existing wait timer and leave failed moves unchanged.");
    return true;
}

int main(void) {
    if (!rescue_controls()) return 1;
    bool clear_overlap_ok = clear_overlap_control();
    enum { BACKLOG = 16 };
    struct cpumask target_mask = {.bits = 2};
    struct task_ctx victim_ctx = { .cell = 1, .llc = 0, .all_cell_cpus_allowed = true };
    struct task_struct victim = { .pid = 1, .cpus_ptr = &target_mask, .context = &victim_ctx,
                                 .scx = { .dsq_vtime = 1000000, .weight = 100 } };
    struct task_struct shared[BACKLOG] = {0};
    reset_fixture();
    cpus[1].vtime_now = 500000000;
    cells[2].subcells[0].llcs[0].vtime_now = cpus[1].vtime_now;
    cells[1].subcells[0].llcs_to_drain = 1;
    cells[1].subcells[0].llcs[0].nr_queued = 1;
    victim_ctx.dsq = get_subcell_llc_dsq_id(1, 0, 0);
    victim_ctx.vtime_charge_subcell = pack_subcell_id(1, 0);
    push(&llc_queues[1][0][0], &victim);
    u64 rescued_at = clock_now;
    require(try_draining_work(1, 0, 1, &cpus[0]) == CONTINUE_DISPATCH, "remote rescue must succeed");
    require(cpu_queues[1].nr == 1 && cpu_queues[1].tasks[0] == &victim, "victim must reach target CPU DSQ");
    require(victim.scx.dsq_vtime == cpus[1].vtime_now, "rescue must rebase to target CPU clock");
    u64 recorded_start = cpus[1].pinned_waiting_since;
    for (u32 i = 0; i < BACKLOG; i++) {
        shared[i].pid = 2 + i; shared[i].cpus_ptr = &target_mask;
        shared[i].scx.dsq_vtime = cpus[1].vtime_now - slice_ns;
        push(&llc_queues[2][0][0], &shared[i]);
    }
    cells[2].subcells[0].llcs[0].nr_queued = BACKLOG;
    current_cpu = 1; clock_now = rescued_at + (PINNED_MAX_WAIT_SLICES + 1) * slice_ns;
    mitosis_dispatch(1, NULL);
    printf("Rescue wait: recorded start=%llu ns, rescue=%llu ns, dispatch delay=%llu ns, selected=%s.\n",
           recorded_start, rescued_at, clock_now - rescued_at,
           local_task == &victim ? "victim" : "shared");
    if (local_task == &victim) {
        if (recorded_start != rescued_at) {
            puts("BUG 4: rescue did not record the first wait's start time.");
            return 1;
        }
        if (!clear_overlap_ok) return 1;
        puts("PASS 4: rescued pinned task receives overdue protection on its first wait.");
        return 0;
    }
    require(local_task == &shared[0], "lower-vtime shared task must win without overdue protection");
    u64 missing_since = cpus[1].pinned_waiting_since;
    /* Falsifying control: initialize only the missing timer and dispatch again. */
    cpus[1].pinned_waiting_since = rescued_at;
    local_task = NULL; mitosis_dispatch(1, NULL);
    require(local_task == &victim, "starting timer alone must restore overdue service");
    printf("BUG 4: rescued CPU-DSQ waiter has timer=%llu; after %llums shared work still wins.\n",
           missing_since, (clock_now - rescued_at) / 1000000);
    return 1;
}
"""

output.write_text(preamble + "\n" + "\n".join(declarations) + "\n" + fixtures +
                  "\n" + "\n".join(functions) + "\n" + main)
display_path = str(bpf.resolve())
if display_path.startswith("/home/tommyu/"):
    display_path = "~/" + display_path[len("/home/tommyu/"):]
print(display_path, flush=True)
PYTHON
then
    exit 2
fi
if ! "$compiler" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
        -Wno-unused-parameter -Wno-sign-compare "$repro_tmp/repro.c" -o "$repro_tmp/repro"; then
    echo 'ERROR: C harness could not compile this source revision' >&2
    exit 2
fi
set +e
"$repro_tmp/repro"
result=$?
set -e
case "$result" in
    0|1|2) exit "$result" ;;
    *) echo "ERROR: harness terminated unexpectedly (status $result)" >&2; exit 2 ;;
esac
