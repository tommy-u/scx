/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_SCHEDULER_MODE_H
#define __SCX_SNAKE_SCHEDULER_MODE_H

#include "fairness.h"
#include "ladder.h"
#include "queue.h"
#include "queue_fairness.h"
#include "queue_ladder.h"
#include "queue_timing.h"
#include "timing.h"

/* Route enqueue through the active queue topology or global fairness policy. */
static __noinline int
scheduler_mode_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		       u64 enq_flags, const struct snake_fine_timing_ctx *fine,
		       u64 callback_started_at)
{
	s32 cell_enqueued, ret;
	u64 slice, stage_started_at;

	if (queue_topology_enabled()) {
		ret = queue_ladder_enqueue(ctx, p, enq_flags, fine,
					   callback_started_at);
		if (ret)
			return ret;
		stage_started_at = fine_timing_start(fine);
		fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_FINISH,
				   stage_started_at);
		return 0;
	}

	slice	      = fairness_dispatch_slice(ctx, p, true);
	cell_enqueued = try_enqueue_task_cell(ctx, p, enq_flags, slice, fine,
					      callback_started_at);
	if (cell_enqueued < 0)
		return cell_enqueued;
	if (cell_enqueued > 0)
		return 0;
	return fairness_enqueue(ctx, p, enq_flags, fine);
}

/* Route dispatch and consume the caller's active-ladder reference. */
static __always_inline void scheduler_mode_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	s32 ret;
	u64 stage_started_at;

	if (queue_topology_enabled()) {
		ret		 = queue_ladder_dispatch(ctx, cpu, prev, fine,
							 callback_started_at);
		stage_started_at = fine_timing_start(fine);
		if (ret)
			scx_bpf_error("snake queue dispatch failed on CPU %d",
				      cpu);
		fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_FINISH,
				   stage_started_at);
		release_timed_callback(ctx, SNAKE_CALLBACK_DISPATCH,
				       callback_started_at);
		return;
	}

	ret = fairness_dispatch(ctx, cpu, prev, fine);
	release_timed_callback(ctx, SNAKE_CALLBACK_DISPATCH,
			       callback_started_at);
	if (ret)
		scx_bpf_error("snake fairness dispatch failed on CPU %d: %d",
			      cpu, ret);
}

static __always_inline int scheduler_mode_runnable(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	if (queue_cell_mode_enabled())
		return queue_fairness_prepare_runnable(ctx, p, NULL) ? 0 :
								       -EINVAL;
	if (queue_global_mode_enabled()) {
		fairness_vtime_runnable(ctx, p);
		return 0;
	}

	fairness_runnable(ctx, p);
	return 0;
}

static __always_inline int scheduler_mode_running(struct snake_ladder_ctx *ctx,
						  struct task_struct	  *p)
{
	stat_inc(ctx, SNAKE_STAT_RUNNING);
	if (queue_cell_mode_enabled()) {
		queue_account_task_membership(ctx, p);
		return queue_fairness_running(ctx, p);
	}
	if (queue_global_mode_enabled()) {
		fairness_vtime_running(ctx, p);
		return 0;
	}

	fairness_running(ctx, p);
	return 0;
}

static __always_inline int scheduler_mode_stopping(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p,
						   u64 *runtime_ns)
{
	stat_inc(ctx, SNAKE_STAT_STOPPING);
	if (queue_cell_mode_enabled())
		return queue_fairness_stopping(ctx, p, runtime_ns);
	if (queue_global_mode_enabled()) {
		*runtime_ns = fairness_vtime_stopping(ctx, p);
		return 0;
	}

	*runtime_ns = fairness_stopping(ctx, p);
	return 0;
}

static __always_inline void
scheduler_mode_quiescent(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u64 deq_flags)
{
	stat_inc(ctx, SNAKE_STAT_QUIESCENT);
	queue_timing_cancel(ctx, p);
	if (queue_cell_mode_enabled()) {
		queue_fairness_cancel_direct(ctx, p);
		return;
	}
	if (queue_global_mode_enabled()) {
		fairness_vtime_quiescent(ctx, p, deq_flags);
		return;
	}

	fairness_quiescent(ctx, p, deq_flags);
}

static __always_inline void
scheduler_mode_set_weight(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  u32 weight)
{
	fairness_set_weight(ctx, p, weight);
}

static __always_inline int scheduler_mode_init_task(struct task_struct *p)
{
	return queue_cell_mode_enabled() ? task_state_init_queue_mask(p) : 0;
}

#endif /* __SCX_SNAKE_SCHEDULER_MODE_H */
