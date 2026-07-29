/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MAIN_H
#define __SCX_SNAKE_MAIN_H

#include <scx/common.bpf.h>

#include "intf.h"

static u32 nr_cpu_ids;
extern u32 callback_timing_sample_rate;
extern u64 select_fine_timing_session_id;

struct snake_ladder_ctx {
	u32				 slot;
	u32				 *readers;
	const struct snake_compiled_ladder *ladder;
};

struct snake_fine_timing_ctx {
	u64 session_id;
	u32 callback;
	u32 active;
};

/* Userspace stores the resolved assignment and its independent policy layers. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_cell);
} task_cells SEC(".maps");

static __always_inline struct snake_task_cell *
snake_task_cell_annotation(struct task_struct *p)
{
	return bpf_task_storage_get(&task_cells, p, NULL, 0);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_header);
	__uint(max_entries, 1);
} queue_header SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_MAX_CPUS);
} queue_cell_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cells SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue);
	__uint(max_entries, SNAKE_MAX_NORMAL_QUEUES);
} normal_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_cpu_queue);
	__uint(max_entries, SNAKE_MAX_CPUS);
} cpu_queues SEC(".maps");

struct snake_queue_cell_masks {
	struct bpf_cpumask __kptr *primary;
	struct bpf_cpumask __kptr *borrowable;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell_masks);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cell_masks SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_callback_timing);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_NR_CALLBACKS);
} callback_timing SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_fine_timing_config);
	__uint(max_entries, 1);
} fine_timing_config SEC(".maps");

/* Userspace folds sampled stage events into fixed-size histograms. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} fine_timing_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_MAX_QUEUE_CELLS *
			    SNAKE_NR_CELL_STATS);
} cell_stats SEC(".maps");

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

static __always_inline u64 callback_timing_start(void)
{
	u32 rate = READ_ONCE(callback_timing_sample_rate);

	if (!rate)
		return 0;
	if (rate > 1 && (bpf_get_prandom_u32() & (rate - 1)))
		return 0;
	return bpf_ktime_get_ns();
}

static __always_inline void
callback_timing_finish(const struct snake_ladder_ctx *ctx, u32 callback,
		       u64 started_at)
{
	struct snake_callback_timing *timing;
	u64 elapsed;
	u32 bucket = 0, key;

	if (!started_at || callback >= SNAKE_NR_CALLBACKS ||
	    ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	elapsed = bpf_ktime_get_ns() - started_at;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= SNAKE_CALLBACK_TIMING_BUCKETS)
		bucket = SNAKE_CALLBACK_TIMING_BUCKETS - 1;
	key = ctx->slot * SNAKE_NR_CALLBACKS + callback;
	timing = bpf_map_lookup_elem(&callback_timing, &key);
	if (!timing)
		return;
	timing->total_ns += elapsed;
	timing->buckets[bucket]++;
}

static __noinline void
release_timed_callback(struct snake_ladder_ctx *ctx, u32 callback,
		       u64 started_at)
{
	callback_timing_finish(ctx, callback, started_at);
	release_active_ladder(ctx);
}

static __always_inline struct snake_fine_timing_ctx
fine_timing_begin(u32 callback, u64 callback_started_at)
{
	struct snake_fine_timing_ctx ctx = {};
	struct snake_fine_timing_config *config;
	u32 key = 0, mask;

	if (!callback_started_at || callback >= SNAKE_NR_FINE_TIMING_CALLBACKS)
		return ctx;
	config = bpf_map_lookup_elem(&fine_timing_config, &key);
	if (!config)
		return ctx;
	if (callback == SNAKE_FINE_TIMING_CALLBACK_SELECT_CPU)
		mask = SNAKE_FINE_TIMING_SELECT_CPU;
	else if (callback == SNAKE_FINE_TIMING_CALLBACK_ENQUEUE)
		mask = SNAKE_FINE_TIMING_ENQUEUE;
	else
		mask = SNAKE_FINE_TIMING_DISPATCH;
	if (!(READ_ONCE(config->enabled_mask) & mask))
		return ctx;
	ctx.session_id = READ_ONCE(config->session_ids[callback]);
	if (!ctx.session_id)
		return ctx;
	ctx.callback = callback;
	ctx.active = 1;
	return ctx;
}

static __always_inline u64
fine_timing_start(const struct snake_fine_timing_ctx *ctx)
{
	return ctx && ctx->active ? bpf_ktime_get_ns() : 0;
}

static __always_inline bool
fine_timing_stage_valid(const struct snake_fine_timing_ctx *ctx, u32 stage)
{
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_SELECT_CPU)
		return stage <= SNAKE_FINE_TIMING_SELECT_POLICY_LADDER;
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_ENQUEUE)
		return stage >= SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER &&
		       stage <= SNAKE_FINE_TIMING_ENQUEUE_FINISH;
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_DISPATCH)
		return stage >= SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER &&
		       stage <= SNAKE_FINE_TIMING_DISPATCH_FINISH;
	return false;
}

static __noinline void
fine_timing_finish_select(u64 started_at)
{
	struct snake_fine_timing_event event = {};
	u64 session_id = READ_ONCE(select_fine_timing_session_id);

	if (!started_at || !session_id)
		return;
	event.session_id = session_id;
	event.elapsed_ns = bpf_ktime_get_ns() - started_at;
	event.stage = SNAKE_FINE_TIMING_SELECT_POLICY_LADDER;
	bpf_ringbuf_output(&fine_timing_events, &event, sizeof(event), 0);
}

static __noinline void
fine_timing_finish(const struct snake_fine_timing_ctx *ctx, u32 stage,
		   u64 started_at)
{
	struct snake_fine_timing_config *config;
	struct snake_fine_timing_event event = {};
	u32 key = 0, mask;

	if (!started_at || !ctx || !ctx->active ||
	    !fine_timing_stage_valid(ctx, stage))
		return;
	config = bpf_map_lookup_elem(&fine_timing_config, &key);
	if (!config)
		return;
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_SELECT_CPU)
		mask = SNAKE_FINE_TIMING_SELECT_CPU;
	else if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_ENQUEUE)
		mask = SNAKE_FINE_TIMING_ENQUEUE;
	else
		mask = SNAKE_FINE_TIMING_DISPATCH;
	if (!(READ_ONCE(config->enabled_mask) & mask) ||
	    READ_ONCE(config->session_ids[ctx->callback]) != ctx->session_id)
		return;
	event.session_id = ctx->session_id;
	event.elapsed_ns = bpf_ktime_get_ns() - started_at;
	event.stage = stage;
	bpf_ringbuf_output(&fine_timing_events, &event, sizeof(event), 0);
}

static __always_inline void
cell_stat_add(const struct snake_ladder_ctx *ctx, u32 cell_index, u32 stat,
	      u64 amount)
{
	u64 *value;
	u32  key;

	if (ctx->slot >= SNAKE_LADDER_SLOTS ||
	    cell_index >= SNAKE_MAX_QUEUE_CELLS || stat >= SNAKE_NR_CELL_STATS)
		return;
	key = (ctx->slot * SNAKE_MAX_QUEUE_CELLS + cell_index) *
		      SNAKE_NR_CELL_STATS +
	      stat;
	value = bpf_map_lookup_elem(&cell_stats, &key);
	if (value)
		*value += amount;
}

static __always_inline void
cell_stat_inc(const struct snake_ladder_ctx *ctx, u32 cell_index, u32 stat)
{
	cell_stat_add(ctx, cell_index, stat, 1);
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
static __noinline void finish_select(const struct snake_ladder_ctx *ctx,
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
