/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_FIFO_H
#define __SCX_SNAKE_FAIRNESS_FIFO_H

#include "fairness_common.h"
#include "queue_timing.h"
#include "queue.h"

static __always_inline struct snake_task_runtime *
fairness_fifo_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, true);

	if (!runtime || runtime->initialized)
		return runtime;
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	runtime->initialized	= 1;
	return runtime;
}

static __always_inline void fairness_fifo_runnable(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	(void)ctx;
	(void)p;
}

static __always_inline u64 fairness_fifo_dispatch_slice(
	struct snake_ladder_ctx *ctx, struct task_struct *p, bool direct)
{
	(void)ctx;
	(void)p;
	(void)direct;
	return SCX_SLICE_DFL;
}

static __always_inline int
fairness_fifo_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		      u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	u64 flags = enq_flags & ~SCX_ENQ_PREEMPT;
	s32 target_cpu;

	if (!dsq_insert(p, dsq_fifo(), SCX_SLICE_DFL, flags, fine)) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -EINVAL;
	}
	queue_timing_record_insert(ctx, p, dsq_fifo(), SNAKE_QUEUE_CELL_NONE,
				   fine);
	stat_inc(ctx, SNAKE_STAT_FIFO_SHARED_ENQUEUES);
	target_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (target_cpu < 0)
		target_cpu = scx_bpf_task_cpu(p);
	if (target_cpu >= 0 && target_cpu < nr_cpu_ids)
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline int
fairness_fifo_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
		       struct task_struct		  *prev,
		       const struct snake_fine_timing_ctx *fine)
{
	(void)prev;
	if (dsq_move_to_local(dsq_fifo(), cpu, fine))
		stat_inc(ctx, SNAKE_STAT_FIFO_SHARED_DISPATCHES);
	return 0;
}

static __always_inline void fairness_fifo_running(struct snake_ladder_ctx *ctx,
						  struct task_struct	  *p)
{
	struct snake_task_runtime *runtime = fairness_fifo_prepare_task(ctx, p);

	if (!runtime)
		return;
	queue_timing_complete_pending(runtime);
	fairness_runtime_begin(runtime, p);
}

static __always_inline u64 fairness_fifo_stopping(struct snake_ladder_ctx *ctx,
						  struct task_struct	  *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (!runtime || !runtime->runtime_valid)
		return 0;
	return fairness_runtime_delta(ctx, p, runtime);
}

static __always_inline void
fairness_fifo_quiescent(struct snake_ladder_ctx *ctx, struct task_struct *p,
			u64 deq_flags)
{
	(void)ctx;
	(void)p;
	(void)deq_flags;
}

static __always_inline void
fairness_fifo_set_weight(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u32 weight)
{
	(void)ctx;
	(void)p;
	(void)weight;
}

static __always_inline int fairness_fifo_init(void)
{
	return dsq_create(dsq_fifo(), -1);
}

#endif /* __SCX_SNAKE_FAIRNESS_FIFO_H */
