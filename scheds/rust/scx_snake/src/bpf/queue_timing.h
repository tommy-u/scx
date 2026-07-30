/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_TIMING_H
#define __SCX_SNAKE_QUEUE_TIMING_H

#include "fairness_common.h"
#include "dsq.h"

extern u64				  queue_timing_session_id;
extern struct snake_queue_timing_counters queue_timing_counters;

/* Queue residence events are independent from fine timing stage events. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} queue_timing_events  SEC(".maps");

static __noinline void queue_timing_record_sample(struct snake_ladder_ctx *ctx,
						  struct task_struct	  *p,
						  dsq_id_t dsq, u32 cell_index,
						  u64 session_id)
{
	struct snake_task_runtime *runtime;
	u64			   enqueued_at_ns;
	s32			   depth;

	runtime = fairness_task(ctx, p, true);
	if (!runtime)
		return;
	enqueued_at_ns = bpf_ktime_get_ns();
	depth	       = dsq_nr_queued(dsq);
	if (depth < 0 || READ_ONCE(queue_timing_session_id) != session_id)
		return;
	runtime->queue_timing_dsq_id		 = dsq.raw;
	runtime->queue_timing_enqueued_at_ns	 = enqueued_at_ns;
	runtime->queue_timing_cell_index	 = cell_index;
	runtime->queue_timing_depth_after_insert = depth;
	runtime->queue_timing_queue_class	 = dsq_queue_class(dsq);
	runtime->queue_timing_session_id	 = session_id;
	__sync_fetch_and_add(&queue_timing_counters.started_samples, 1);
}

static __always_inline void
queue_timing_record_insert(struct snake_ladder_ctx *ctx, struct task_struct *p,
			   dsq_id_t dsq, u32 cell_index,
			   const struct snake_fine_timing_ctx *fine)
{
	u64 session_id;

	if (!fine || !fine->sampled)
		return;
	session_id = READ_ONCE(queue_timing_session_id);
	if (session_id)
		queue_timing_record_sample(ctx, p, dsq, cell_index, session_id);
}

static __always_inline void
queue_timing_cancel_runtime(struct snake_task_runtime *runtime)
{
	if (runtime)
		runtime->queue_timing_session_id = 0;
}

static __always_inline void queue_timing_cancel(struct snake_ladder_ctx *ctx,
						struct task_struct	*p)
{
	queue_timing_cancel_runtime(fairness_task(ctx, p, false));
}

static __noinline void queue_timing_complete(struct snake_task_runtime *runtime)
{
	struct snake_queue_timing_event event = {};
	u64				session_id, now;
	s32				depth;

	if (!runtime)
		return;
	session_id = runtime->queue_timing_session_id;
	if (!session_id)
		return;
	event.session_id	 = session_id;
	event.dsq_id		 = runtime->queue_timing_dsq_id;
	event.cell_index	 = runtime->queue_timing_cell_index;
	event.queue_class	 = runtime->queue_timing_queue_class;
	event.depth_after_insert = runtime->queue_timing_depth_after_insert;
	event.residence_ns	 = runtime->queue_timing_enqueued_at_ns;
	runtime->queue_timing_session_id = 0;
	if (session_id != READ_ONCE(queue_timing_session_id))
		return;
	now		   = bpf_ktime_get_ns();
	event.residence_ns = now - event.residence_ns;
	depth		   = dsq_nr_queued(dsq_from_raw(event.dsq_id));
	if (depth < 0)
		return;
	event.depth_after_dispatch = depth;
	if (bpf_ringbuf_output(&queue_timing_events, &event, sizeof(event), 0))
		__sync_fetch_and_add(&queue_timing_counters.dropped_samples, 1);
	else
		__sync_fetch_and_add(&queue_timing_counters.completed_samples,
				     1);
}

static __always_inline void
queue_timing_complete_pending(struct snake_task_runtime *runtime)
{
	if (runtime && runtime->queue_timing_session_id)
		queue_timing_complete(runtime);
}

#endif /* __SCX_SNAKE_QUEUE_TIMING_H */
