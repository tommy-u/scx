/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * Soft preemption: cap the running task's time slice when CPU-pinned
 * waiters are queued, optionally scaling the cap proportionally to
 * the waiter's EWMA runtime.
 *
 * ── Problem ──────────────────────────────────────────────────────
 *
 * CPU-pinned tasks can only run on one CPU. When another task is
 * running on that CPU with a full slice (e.g. 20ms), the pinned
 * task must wait the entire slice. This creates long tail latencies
 * for latency-sensitive pinned tasks (kworkers, IRQ threads) that
 * may only need microseconds of CPU time.
 *
 * ── Approach ─────────────────────────────────────────────────────
 *
 * Trigger:  A CPU-pinned task (B) is waiting in a CPU DSQ.
 * Action:   Cap the slice of whatever task (A) is running on that CPU.
 *
 * A can be ANY task — pinned or unpinned, dispatched from a CPU DSQ
 * or a cell-LLC DSQ. There is no exemption by task type or DSQ
 * origin. If B is waiting, A gets capped.
 *
 * Two event-driven checks, no tick callback, no polling:
 *
 *   Case                                  Check         Rationale
 *   ─────────────────────────────────────  ────────────  ──────────────────────
 *   Pinned waiter arrives while A running  enqueue()     We ARE the waiter
 *   Task A starts while waiters queued     running()     dsq_nr_queued detects
 *   No waiters                             (nothing)     Zero overhead
 *
 * Both checks are idempotent: if (slice > cap) slice = cap.
 * Double-capping is a no-op.
 *
 * ── Cap calculation ──────────────────────────────────────────────
 *
 * Three zones determined by the waiter's EWMA runtime:
 *
 *   avg_runtime * K     vs thresholds      effective cap    result
 *   ─────────────────   ──────────────     ──────────────   ──────────
 *   < floor             (very short task)  0 (hard preempt) FLOOR
 *   floor..ceiling      (proportional)     avg_runtime * K  Proportional
 *   >= ceiling          (long task)        ceiling          CEIL
 *
 * With defaults ceiling=4ms, K=2, floor=50us:
 *
 *   Waiter avg_runtime   avg * K    Effective cap
 *   ──────────────────   ────────   ─────────────
 *   10us                 20us       0 (hard preempt, below floor)
 *   50us                 100us      100us (proportional)
 *   500us                1ms        1ms (proportional)
 *   2ms                  4ms        4ms (ceiling)
 *   5ms                  10ms       4ms (ceiling)
 *
 * Without --track-avg-runtime, the flat ceiling is always used.
 *
 * ── EWMA mechanics ──────────────────────────────────────────────
 *
 * Per-task avg_runtime_ns is updated in stopping() after each run:
 *
 *   Cold start (< 8 samples): simple cumulative average
 *     avg = (avg * nr_runs + used) / (nr_runs + 1)
 *
 *   Steady state (>= 8 samples): EWMA with alpha = 1/8
 *     avg = (avg * 7 + used) >> 3
 *
 * Cold start avoids the EWMA initialization problem: the first
 * EWMA update of (0 * 7 + used) >> 3 = used/8 would be 8x too low.
 *
 * ── Tuning parameters ───────────────────────────────────────────
 *
 *   Parameter                CLI flag                    Default
 *   ───────────────────────  ──────────────────────────  ───────
 *   pinned_slice_cap_ns      --pinned-slice-cap [MS]     4ms
 *   pinned_slice_multiplier  --pinned-slice-multiplier   2
 *   pinned_slice_min_ns      --pinned-slice-min-us       50us
 *
 * The multiplier K controls how much headroom the waiter gets:
 *
 *   K    50us task cap    500us task cap    Tradeoff
 *   ──   ─────────────    ──────────────    ───────────────────
 *   1    50us             500us             Tight, more preemptions
 *   2    100us            1ms               Balanced (default)
 *   4    200us            2ms               Loose, fewer preemptions
 *
 * The floor threshold determines when hard preempt (slice=0) kicks
 * in instead of proportional capping. Set based on context switch
 * cost (measured ~1.5us on target hardware, so floor=50us is ~33x).
 *
 * ── Known limitations ───────────────────────────────────────────
 *
 * Perma-waiter problem: A pinned task with high vtime sitting in a
 * CPU DSQ triggers capping on every task that runs on that CPU, but
 * never gets picked by dispatch() (which chooses lowest vtime across
 * CPU and cell-LLC DSQs). This causes context switch churn without
 * benefit. Mitigation: check if waiter's vtime is competitive before
 * capping (not yet implemented).
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

/* ── Config (populated by userspace rodata) ────────────────────────── */

/* Defaults are in main.rs; userspace always overwrites via rodata */
const volatile bool pinned_slice_cap;
const volatile u64 pinned_slice_cap_ns;
const volatile bool track_avg_runtime;
const volatile u64 pinned_slice_min_ns;
const volatile u32 pinned_slice_multiplier;

/* ── Map for userspace iteration at exit ───────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct avg_runtime_entry);
	__uint(max_entries, 65536);
} avg_runtime_map SEC(".maps");

/* ── Helpers ───────────────────────────────────────────────────────── */

enum soft_preempt_result {
	SPREEMPT_NONE = 0, /* no capping occurred */
	SPREEMPT_CEIL, /* flat ceiling used (no EWMA or prop >= ceil) */
	SPREEMPT_PROP, /* proportional cap between floor and ceiling */
	SPREEMPT_FLOOR, /* floor used (prop was below minimum) */
};

/*
 * Compute the effective slice cap given a waiter's EWMA stats.
 * Sets *result to indicate which category was used.
 */
static inline u64 soft_preempt_cap(u32 nr_runs, u64 avg_runtime_ns,
				   enum soft_preempt_result *result)
{
	u64 cap = pinned_slice_cap_ns;
	*result = SPREEMPT_CEIL;

	if (track_avg_runtime && nr_runs >= 8) {
		u64 prop = avg_runtime_ns * pinned_slice_multiplier;
		if (prop < pinned_slice_min_ns) {
			/* Very short task — hard preempt instead of capping */
			if (pinned_slice_min_ns < cap) {
				cap = 0;
				*result = SPREEMPT_FLOOR;
			}
		} else if (prop < cap) {
			cap = prop;
			*result = SPREEMPT_PROP;
		}
	}

	return cap;
}

/*
 * Called from enqueue() when a pinned waiter arrives.
 * Caps the currently running task's slice based on the waiter's
 * own EWMA runtime.
 */
static inline enum soft_preempt_result soft_preempt_on_enqueue(struct task_struct *curr,
							       struct task_ctx *waiter_tctx)
{
	if (!pinned_slice_cap || !curr)
		return SPREEMPT_NONE;

	enum soft_preempt_result result;
	u64 cap = soft_preempt_cap(waiter_tctx->nr_runs, waiter_tctx->avg_runtime_ns, &result);

	if (curr->scx.slice > cap) {
		curr->scx.slice = cap;
		return result;
	}
	return SPREEMPT_NONE;
}

/*
 * Called from running() to cap our own slice when waiters are
 * queued on our CPU DSQ. Peeks the head waiter for EWMA data.
 *
 * dsq_peek_fn: function pointer to the dsq_peek helper (avoids
 * circular dependency with mitosis.bpf.c's dsq_peek).
 */
static inline enum soft_preempt_result
soft_preempt_on_running(struct task_struct *p, dsq_id_t cpu_dsq,
			struct task_struct *(*dsq_peek_fn)(u64))
{
	if (!pinned_slice_cap)
		return SPREEMPT_NONE;

	if (scx_bpf_dsq_nr_queued(cpu_dsq.raw) == 0)
		return SPREEMPT_NONE;

	enum soft_preempt_result result = SPREEMPT_CEIL;
	u64 cap = pinned_slice_cap_ns;

	if (track_avg_runtime && dsq_peek_fn) {
		struct task_struct *waiter = dsq_peek_fn(cpu_dsq.raw);
		if (waiter) {
			struct task_ctx *wtctx = lookup_task_ctx(waiter);
			if (wtctx && wtctx->nr_runs >= 8)
				cap = soft_preempt_cap(wtctx->nr_runs, wtctx->avg_runtime_ns,
						       &result);
		}
	}

	if (p->scx.slice > cap) {
		p->scx.slice = cap;
		return result;
	}
	return SPREEMPT_NONE;
}

/*
 * Update per-task EWMA runtime and mirror to the hash map.
 * Called from stopping() with the task's actual runtime.
 */
static inline void soft_preempt_update_ewma(struct task_struct *p, struct task_ctx *tctx, u64 used)
{
	if (!track_avg_runtime)
		return;

	if (tctx->nr_runs < 8) {
		/* Cold start: simple moving average */
		tctx->avg_runtime_ns =
			(tctx->avg_runtime_ns * tctx->nr_runs + used) / (tctx->nr_runs + 1);
		tctx->nr_runs++;
	} else {
		/* Steady state: EWMA with decay factor 7/8 */
		tctx->avg_runtime_ns = (tctx->avg_runtime_ns * 7 + used) >> 3;
	}

	/* Mirror to hash map for userspace iteration at exit */
	struct avg_runtime_entry entry = {
		.tgid = p->tgid,
		.pid = p->pid,
		.avg_runtime_ns = tctx->avg_runtime_ns,
		.nr_runs = tctx->nr_runs,
	};
	__builtin_memcpy(entry.comm, p->comm, 16);
	u32 pid = p->pid;
	bpf_map_update_elem(&avg_runtime_map, &pid, &entry, BPF_ANY);
}

/*
 * Dump EWMA stats for a task (for scx_bpf_dump in dump_task).
 */
static inline void soft_preempt_dump_task(struct task_struct *p, struct task_ctx *tctx)
{
	if (!track_avg_runtime)
		return;

	scx_bpf_dump("Task[tgid=%d tid=%d/%s] avg_runtime=%lluus nr_runs=%u\n", p->tgid, p->pid,
		     p->comm, tctx->avg_runtime_ns / 1000, tctx->nr_runs);
}
