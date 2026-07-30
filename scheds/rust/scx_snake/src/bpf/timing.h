/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_TIMING_H
#define __SCX_SNAKE_TIMING_H

#include "stats.h"

extern u32 callback_timing_sample_rate;
extern u64 select_fine_timing_session_id;

struct snake_fine_timing_ctx {
	u64 session_id;
	u32 callback;
	u32 active;
	u32 sampled;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_callback_timing);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_NR_CALLBACKS);
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

/* Sampled rung durations are histogrammed in userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rung_timing_events	   SEC(".maps");

static __always_inline u64 callback_timing_start(void)
{
	u32 rate = READ_ONCE(callback_timing_sample_rate);

	if (!rate)
		return 0;
	if (rate > 1 && (bpf_get_prandom_u32() & (rate - 1)))
		return 0;
	return bpf_ktime_get_ns();
}

static __always_inline u64 rung_timing_start(u64 callback_started_at)
{
	return callback_started_at ? bpf_ktime_get_ns() : 0;
}

static __noinline void rung_timing_finish(const struct snake_ladder_ctx *ctx,
					  u32 ladder, u32 rung, u64 started_at)
{
	struct snake_rung_timing_event event = {};

	if (!started_at || ctx->slot >= SNAKE_LADDER_SLOTS ||
	    ladder >= SNAKE_NR_RUNG_LADDERS || rung >= SNAKE_MAX_RUNGS)
		return;
	event.generation = ctx->ladder->generation;
	event.elapsed_ns = bpf_ktime_get_ns() - started_at;
	event.ladder	 = ladder;
	event.rung	 = rung;
	bpf_ringbuf_output(&rung_timing_events, &event, sizeof(event), 0);
}

static __always_inline void
callback_timing_finish(const struct snake_ladder_ctx *ctx, u32 callback,
		       u64 started_at)
{
	struct snake_callback_timing *timing;
	u64			      elapsed;
	u32			      bucket = 0, key;

	if (!started_at || callback >= SNAKE_NR_CALLBACKS ||
	    ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	elapsed = bpf_ktime_get_ns() - started_at;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= SNAKE_CALLBACK_TIMING_BUCKETS)
		bucket = SNAKE_CALLBACK_TIMING_BUCKETS - 1;
	key    = ctx->slot * SNAKE_NR_CALLBACKS + callback;
	timing = bpf_map_lookup_elem(&callback_timing, &key);
	if (!timing)
		return;
	timing->total_ns += elapsed;
	timing->buckets[bucket]++;
}

static __noinline void release_timed_callback(struct snake_ladder_ctx *ctx,
					      u32 callback, u64 started_at)
{
	callback_timing_finish(ctx, callback, started_at);
	release_active_ladder(ctx);
}

static __always_inline struct snake_fine_timing_ctx
fine_timing_begin(u32 callback, u64 callback_started_at)
{
	struct snake_fine_timing_ctx	 ctx = {};
	struct snake_fine_timing_config *config;
	u32				 key = 0, mask;

	ctx.sampled			     = callback_started_at != 0;
	if (!ctx.sampled || callback >= SNAKE_NR_FINE_TIMING_CALLBACKS)
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
	ctx.active   = 1;
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
		return stage >= SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER &&
		       stage <= SNAKE_FINE_TIMING_SELECT_FINISH;
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_ENQUEUE)
		return stage >= SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER &&
		       stage <= SNAKE_FINE_TIMING_ENQUEUE_FINISH;
	if (ctx->callback == SNAKE_FINE_TIMING_CALLBACK_DISPATCH)
		return stage >= SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER &&
		       stage <= SNAKE_FINE_TIMING_DISPATCH_FINISH;
	return false;
}

static __always_inline u64 fine_timing_select_start(u64 callback_started_at)
{
	return callback_started_at && READ_ONCE(select_fine_timing_session_id) ?
		       bpf_ktime_get_ns() :
		       0;
}

static __noinline void fine_timing_finish_select(u32 stage, u64 started_at)
{
	struct snake_fine_timing_event event = {};
	u64 session_id = READ_ONCE(select_fine_timing_session_id);

	if (!started_at || !session_id ||
	    stage < SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER ||
	    stage > SNAKE_FINE_TIMING_SELECT_FINISH)
		return;
	event.session_id = session_id;
	event.elapsed_ns = bpf_ktime_get_ns() - started_at;
	event.stage	 = stage;
	bpf_ringbuf_output(&fine_timing_events, &event, sizeof(event), 0);
}

static __noinline void
fine_timing_record_elapsed(const struct snake_fine_timing_ctx *ctx, u32 stage,
			   u64 elapsed_ns)
{
	struct snake_fine_timing_config *config;
	struct snake_fine_timing_event	 event = {};
	u32				 key   = 0, mask;

	if (!ctx || !ctx->active || !fine_timing_stage_valid(ctx, stage))
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
	event.elapsed_ns = elapsed_ns;
	event.stage	 = stage;
	bpf_ringbuf_output(&fine_timing_events, &event, sizeof(event), 0);
}

static __noinline void
fine_timing_record_dsq_operation(const struct snake_fine_timing_ctx   *ctx,
				 const struct snake_fine_timing_event *sample)
{
	struct snake_fine_timing_config *config;
	struct snake_fine_timing_event	 event;
	u32				 key = 0, mask;

	if (!ctx || !ctx->active || !sample ||
	    sample->operation == SNAKE_DSQ_OP_NONE ||
	    sample->outcome == SNAKE_DSQ_OUTCOME_NONE)
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
	event		 = *sample;
	event.session_id = ctx->session_id;
	bpf_ringbuf_output(&fine_timing_events, &event, sizeof(event), 0);
}

static __always_inline void
fine_timing_finish(const struct snake_fine_timing_ctx *ctx, u32 stage,
		   u64 started_at)
{
	if (!started_at)
		return;
	fine_timing_record_elapsed(ctx, stage, bpf_ktime_get_ns() - started_at);
}

/* Record total and maximum latency for one select_cpu invocation. */
static __noinline void finish_select(const struct snake_ladder_ctx *ctx,
				     u64 started_at, u64 callback_started_at)
{
	u64 fine_started_at = fine_timing_select_start(callback_started_at);
	u64 elapsed	    = bpf_ktime_get_ns() - started_at;

	stat_add(ctx, SNAKE_STAT_SELECT_LATENCY_NS, elapsed);
	stat_max(ctx, SNAKE_STAT_SELECT_LATENCY_MAX_NS, elapsed);
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_FINISH,
				  fine_started_at);
}

#endif /* __SCX_SNAKE_TIMING_H */
