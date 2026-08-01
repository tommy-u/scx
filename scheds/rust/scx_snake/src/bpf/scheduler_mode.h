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

static __always_inline int queue_try_direct_from_enqueue(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u64 enq_flags,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	struct snake_ladder_walk_args walk_args = {
		.prev_cpu = scx_bpf_task_cpu(p),
		.queue_cell_index = SNAKE_QUEUE_CELL_NONE,
		.wake_flags = 0,
		.dispatch_flags = 0,
		.callback_started_at = callback_started_at,
	};
	s32 cpu, ret;

	if (!queue_cell_mode_enabled() || !queue_direct_dispatch_enabled(ctx) ||
	    __COMPAT_is_enq_cpu_selected(enq_flags))
		return 0;
	cpu = walk_policy_ladder(ctx, p, &walk_args);
	if (cpu == -ENOENT)
		return 0;
	if (cpu < 0)
		return cpu;
	if (walk_args.dispatch_flags & SNAKE_SELECT_F_BORROWED)
		ret = queue_fairness_direct_borrow(
			ctx, p, cpu, walk_args.queue_cell_index, fine);
	else if (walk_args.dispatch_flags & SNAKE_SELECT_F_AFFINITY)
		ret = queue_fairness_direct_affinity(
			ctx, p, cpu, walk_args.queue_cell_index, fine);
	else
		ret = queue_fairness_direct_primary(
			ctx, p, cpu, walk_args.queue_cell_index, fine);
	if (ret)
		return ret;
	stat_inc(ctx, SNAKE_STAT_DIRECT_DISPATCHES);
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	return 1;
}

/* Route enqueue through the active queue topology or global fairness policy. */
static __noinline int
scheduler_mode_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		       u64 enq_flags, const struct snake_fine_timing_ctx *fine,
		       u64 callback_started_at)
{
	s32 cell_enqueued, ret;
	u64 slice, stage_started_at;

	if (queue_topology_enabled()) {
		if (queue_transition_active())
			return queue_transition_enqueue(ctx, p, enq_flags, fine);
		ret = queue_try_direct_from_enqueue(
			ctx, p, enq_flags, fine, callback_started_at);
		if (ret < 0)
			return ret;
		if (ret > 0)
			return 0;
		ret = queue_ladder_enqueue(ctx, p, enq_flags, fine,
					   callback_started_at);
		if (ret == -EAGAIN)
			return queue_transition_enqueue(ctx, p, enq_flags, fine);
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

static __always_inline int scheduler_mode_runnable(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	const struct snake_fine_timing_ctx *fine)
{
	u64  stage_started_at = fine_timing_start(fine);
	bool prepared;

	if (queue_cell_mode_enabled()) {
		prepared = queue_fairness_prepare_runnable(ctx, p, NULL);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_RUNNABLE_RUNNABLE_STATE,
				   stage_started_at);
		return prepared ? 0 : -EINVAL;
	}
	if (queue_global_mode_enabled()) {
		fairness_vtime_runnable(ctx, p);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_RUNNABLE_RUNNABLE_STATE,
				   stage_started_at);
		return 0;
	}

	fairness_runnable(ctx, p);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_RUNNABLE_RUNNABLE_STATE,
			   stage_started_at);
	return 0;
}

static __always_inline int scheduler_mode_running(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	const struct snake_fine_timing_ctx *fine)
{
	u64 stage_started_at;
	s32 ret = 0;

	stat_inc(ctx, SNAKE_STAT_RUNNING);
	if (queue_cell_mode_enabled()) {
		stage_started_at = fine_timing_start(fine);
		queue_account_task_membership(ctx, p);
		fine_timing_finish(
			fine, SNAKE_FINE_TIMING_RUNNING_MEMBERSHIP_ACCOUNT,
			stage_started_at);
	}
	stage_started_at = fine_timing_start(fine);
	if (queue_cell_mode_enabled())
		ret = queue_fairness_running(ctx, p);
	else if (queue_global_mode_enabled())
		fairness_vtime_running(ctx, p);
	else
		fairness_running(ctx, p);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_RUNNING_RUN_STATE,
			   stage_started_at);
	return ret;
}

static __always_inline int scheduler_mode_stopping(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u64 *runtime_ns,
	const struct snake_fine_timing_ctx *fine)
{
	u64 stage_started_at = fine_timing_start(fine);
	s32 ret		     = 0;

	stat_inc(ctx, SNAKE_STAT_STOPPING);
	if (queue_cell_mode_enabled())
		ret = queue_fairness_stopping(ctx, p, runtime_ns);
	else if (queue_global_mode_enabled())
		*runtime_ns = fairness_vtime_stopping(ctx, p);
	else
		*runtime_ns = fairness_stopping(ctx, p);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_STOPPING_RUN_STATE,
			   stage_started_at);
	return ret;
}

static __always_inline void
scheduler_mode_quiescent(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u64 deq_flags,
			 const struct snake_fine_timing_ctx *fine)
{
	u64 stage_started_at;

	stat_inc(ctx, SNAKE_STAT_QUIESCENT);
	stage_started_at = fine_timing_start(fine);
	queue_timing_cancel(ctx, p);
	fine_timing_finish(fine,
			   SNAKE_FINE_TIMING_QUIESCENT_QUEUE_TIMING_CANCEL,
			   stage_started_at);
	if (queue_cell_mode_enabled()) {
		stage_started_at = fine_timing_start(fine);
		queue_fairness_cancel_direct(ctx, p);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_QUIESCENT_DIRECT_CANCEL,
				   stage_started_at);
		return;
	}
	stage_started_at = fine_timing_start(fine);
	if (queue_global_mode_enabled())
		fairness_vtime_quiescent(ctx, p, deq_flags);
	else
		fairness_quiescent(ctx, p, deq_flags);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_QUIESCENT_FAIRNESS_STATE,
			   stage_started_at);
}

static __always_inline void
scheduler_mode_set_weight(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  u32 weight)
{
	fairness_set_weight(ctx, p, weight);
}

static __always_inline int scheduler_mode_init_task(struct task_struct *p)
{
	if (queue_cell_mode_enabled())
		return task_state_init_queue_mask(p);
	if (fairness_is_vtime())
		return task_state_init(p);
	return 0;
}

#endif /* __SCX_SNAKE_SCHEDULER_MODE_H */
