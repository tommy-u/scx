/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_ENQUEUE_H
#define __SCX_SNAKE_QUEUE_ENQUEUE_H

#include "queue_vtime.h"

static __always_inline int
queue_fairness_direct_borrow(struct snake_ladder_ctx *ctx,
			     struct task_struct *p, s32 cpu, u32 cell_index,
			     const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_queue_cell	  *cell;
	struct snake_cpu_queue	  *cpuq;

	runtime = queue_fairness_prepare_runnable_for_cell(ctx, p, cell_index,
							   false, NULL);
	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;
	cell = queue_cell(cell_index);
	cpuq = queue_cpu(cpu);
	if (!cell || !cpuq || !queue_mask_contains(&cell->borrowable, cpu) ||
	    cpuq->owner_cell_index == cell_index)
		return -EINVAL;
	task_route_clear_selected_cpu(runtime);
	runtime->queue_class	   = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct	   = 1;
	runtime->direct_cell_index = cell_index;
	runtime->direct_cell_valid = 1;
	if (!dsq_insert_local(p, cpu,
			      fairness_vtime_slice(runtime->active_weight), 0,
			      fine))
		return -EINVAL;
	queue_timing_record_insert(ctx, p, dsq_local_on(cpu), cell_index, fine);
	return 0;
}

static __always_inline int
queue_fairness_enqueue_cell(struct snake_ladder_ctx *ctx, struct task_struct *p,
			    struct snake_task_runtime *runtime,
			    s32 selected_cpu, u64 enq_flags,
			    const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	struct snake_cpu_queue	*cpuq = NULL;
	const struct cpumask	*primary;
	s32			 target_cpu = selected_cpu;
	s32			 ret	    = 0;
	u64			 flags	    = enq_flags & ~SCX_ENQ_PREEMPT;
	u64			 stage_started_at;
	dsq_id_t		 dsq;

	stage_started_at = fine_timing_start(fine);
	cell		 = queue_cell(runtime->cell_index);
	primary =
		queue_cell_mask(runtime->cell_index, SNAKE_QUEUE_MASK_PRIMARY);
	if (!cell || !primary)
		ret = -EINVAL;
	else if (!queue_primary_subset(primary, p))
		ret = -ENOENT;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_CELL_VALIDATE,
			   stage_started_at);
	if (ret)
		return ret;

	stage_started_at = fine_timing_start(fine);
	cpuq		 = target_cpu >= 0 ? queue_cpu(target_cpu) : NULL;
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		target_cpu = queue_pick_primary_cpu(
			primary, runtime->queue_cpumask, p, -1);
	if (target_cpu < 0)
		ret = target_cpu;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PICK_TARGET,
			   stage_started_at);
	if (ret)
		return ret;
	cpuq = queue_cpu(target_cpu);
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		return -EINVAL;

	runtime->queue_class	   = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct	   = 0;
	runtime->direct_cell_valid = 0;
	stage_started_at	   = fine_timing_start(fine);
	dsq			   = dsq_normal(cpuq->normal_queue_index);
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->vruntime, flags, fine)) {
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_ENQUEUE_NORMAL_DSQ_INSERT,
				   stage_started_at);
		return -EINVAL;
	}
	queue_timing_record_insert(ctx, p, dsq, runtime->cell_index, fine);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_NORMAL_DSQ_INSERT,
			   stage_started_at);
	stage_started_at = fine_timing_start(fine);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index,
		      SNAKE_CELL_STAT_NORMAL_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_NORMAL_ACCOUNT_KICK,
			   stage_started_at);
	return 0;
}

static __always_inline int queue_fairness_enqueue_affinity(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	struct snake_task_runtime *runtime, s32 selected_cpu, u64 enq_flags,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_cpu_queue *cpuq;
	s32	 target_cpu	  = queue_pick_allowed_cpu(p, selected_cpu);
	s32	 ret		  = 0;
	u64	 flags		  = enq_flags & ~SCX_ENQ_PREEMPT;
	u64	 stage_started_at = fine_timing_start(fine);
	u64	 insert_started_at;
	dsq_id_t dsq;

	if (target_cpu < 0) {
		ret = target_cpu;
		goto out;
	}
	cpuq = queue_cpu(target_cpu);
	if (!cpuq || queue_fairness_prepare_affinity(ctx, runtime,
						     cpuq->owner_cell_index)) {
		ret = -EINVAL;
		goto out;
	}
	runtime->queue_class	   = SNAKE_QUEUE_CLASS_AFFINITY;
	runtime->run_direct	   = 0;
	runtime->direct_cell_valid = 0;
	dsq			   = dsq_affinity(target_cpu);
	insert_started_at	   = fine_timing_start(fine);
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->affinity_vruntime, flags, fine)) {
		fine_timing_finish(
			fine, SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_DSQ_INSERT,
			insert_started_at);
		ret = -EINVAL;
		goto out;
	}
	queue_timing_record_insert(ctx, p, dsq, runtime->cell_index, fine);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_DSQ_INSERT,
			   insert_started_at);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index,
		      SNAKE_CELL_STAT_AFFINITY_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
out:
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_PATH,
			   stage_started_at);
	return ret;
}

static __always_inline int
queue_ladder_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		     u64 enq_flags, const struct snake_fine_timing_ctx *fine,
		     u64 callback_started_at)
{
	struct snake_task_runtime *runtime;
	s32			   selected_cpu = -1;
	u32			   i;
	u64			   stage_started_at;

	stage_started_at = fine_timing_start(fine);
	queue_fairness_cancel_direct(ctx, p);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_CANCEL_DIRECT,
			   stage_started_at);
	stage_started_at = fine_timing_start(fine);
	runtime		 = queue_fairness_prepare_runnable(ctx, p, fine);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_RUNNABLE,
			   stage_started_at);
	if (!runtime)
		return -EINVAL;
	selected_cpu = task_route_take_selected_cpu(runtime, p);

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;
		s32			       ret;
		u64			       rung_started_at;

		if (i >= ctx->ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ctx->ladder->enqueue_rungs, [i]);
		if (!rung)
			return -EINVAL;
		rung_started_at = rung_timing_start(callback_started_at);
		if (rung->opcode == SNAKE_ENQUEUE_OP_CELL)
			ret = queue_fairness_enqueue_cell(
				ctx, p, runtime, selected_cpu, enq_flags, fine);
		else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY)
			ret = queue_fairness_enqueue_affinity(
				ctx, p, runtime, selected_cpu, enq_flags, fine);
		else
			return -EINVAL;
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_ENQUEUE, i,
				   rung_started_at);
		if (!ret)
			return 0;
		if (ret != -ENOENT)
			return ret;
	}
	return -ENOENT;
}

#endif /* __SCX_SNAKE_QUEUE_ENQUEUE_H */
