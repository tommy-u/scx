/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MAIN_H
#define __SCX_SNAKE_MAIN_H

#include <scx/common.bpf.h>

#include "intf.h"

static u32 nr_cpu_ids;

struct snake_ladder_ctx {
	u32				 slot;
	u32				 *readers;
	const struct snake_compiled_ladder *ladder;
};

struct snake_task_runtime {
	u64 started_exec_runtime;
	u32 valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_runtime);
} task_runtimes SEC(".maps");

/* Thread annotations are updated synchronously from the userspace control path. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_cell);
} task_cells SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_compiled_ladder);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
} compiled_ladders SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} active_ladder SEC(".maps");

/* Per-CPU readers let userspace safely rebuild the inactive ladder slot. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
} ladder_readers SEC(".maps");

/* Per-CPU counters avoid atomics in scheduler callbacks. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_NR_STATS);
} stats			    SEC(".maps");

static __always_inline s32 active_ladder_slot(void)
{
	u32  key = 0;
	u32 *slot;

	slot = bpf_map_lookup_elem(&active_ladder, &key);
	if (!slot)
		return -EINVAL;
	return READ_ONCE(*slot);
}

/* Pin one complete ladder slot for the duration of a scheduler callback. */
static __always_inline int acquire_active_ladder(struct snake_ladder_ctx *ctx)
{
	u32 attempt;

	bpf_for(attempt, 0, 4)
	{
		struct snake_compiled_ladder *ladder;
		u32			     *readers;
		s32			      slot;

		slot = active_ladder_slot();
		if (slot < 0 || slot >= SNAKE_LADDER_SLOTS)
			return -EINVAL;
		readers = bpf_map_lookup_elem(&ladder_readers, &slot);
		if (!readers)
			return -EINVAL;
		__sync_fetch_and_add(readers, 1);
		if (active_ladder_slot() != slot) {
			__sync_fetch_and_sub(readers, 1);
			continue;
		}

		ladder = bpf_map_lookup_elem(&compiled_ladders, &slot);
		if (!ladder) {
			__sync_fetch_and_sub(readers, 1);
			return -EINVAL;
		}
		ctx->slot    = slot;
		ctx->readers = readers;
		ctx->ladder  = ladder;
		return 0;
	}

	return -EAGAIN;
}

static __always_inline void release_active_ladder(struct snake_ladder_ctx *ctx)
{
	if (ctx->readers)
		__sync_fetch_and_sub(ctx->readers, 1);
	ctx->readers = NULL;
}

static __always_inline void stat_add(const struct snake_ladder_ctx *ctx, u32 idx,
				     u64 amount)
{
	u64 *value;
	u32  key;

	if (idx >= SNAKE_NR_STATS || ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	key   = ctx->slot * SNAKE_NR_STATS + idx;
	value = bpf_map_lookup_elem(&stats, &key);
	if (value)
		*value += amount;
}

static __always_inline void stat_inc(const struct snake_ladder_ctx *ctx, u32 idx)
{
	stat_add(ctx, idx, 1);
}

static __always_inline void stat_max(const struct snake_ladder_ctx *ctx, u32 idx,
				     u64 candidate)
{
	u64 *value;
	u32  key;

	if (idx >= SNAKE_NR_STATS || ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	key   = ctx->slot * SNAKE_NR_STATS + idx;
	value = bpf_map_lookup_elem(&stats, &key);
	if (value && candidate > *value)
		*value = candidate;
}

/* Record total and maximum latency for one select_cpu invocation. */
static __always_inline void finish_select(const struct snake_ladder_ctx *ctx,
					  u64 started_at)
{
	u64 elapsed = bpf_ktime_get_ns() - started_at;

	stat_add(ctx, SNAKE_STAT_SELECT_LATENCY_NS, elapsed);
	stat_max(ctx, SNAKE_STAT_SELECT_LATENCY_MAX_NS, elapsed);
}

/* Choose an affinity-safe CPU after every configured rung misses. */
static __always_inline s32 fallback_cpu(const struct snake_ladder_ctx *ctx,
					const struct task_struct *p, s32 prev_cpu)
{
	s32 cpu;

	if (ctx->ladder->fallback_mode == SNAKE_FALLBACK_PREVIOUS_CPU &&
	    prev_cpu >= 0 &&
	    prev_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_FALLBACK_PREV);
		return prev_cpu;
	}

	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_FALLBACK_ANY);
		return cpu;
	}

	stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
	scx_bpf_error("snake could not find an allowed fallback CPU for pid %d",
		      p->pid);
	return -1;
}

#endif /* __SCX_SNAKE_MAIN_H */
