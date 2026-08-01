/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_ENQUEUE_H
#define __SCX_SNAKE_QUEUE_ENQUEUE_H

#include "queue_vtime.h"

static __always_inline int
queue_global_enqueue_local(struct snake_ladder_ctx *ctx, struct task_struct *p,
			   struct snake_task_runtime *runtime, s32 selected_cpu,
			   u64 enq_flags,
			   const struct snake_fine_timing_ctx *fine)
{
	struct snake_cpu_queue *cpuq;
	const struct cpumask   *consumers;
	dsq_id_t		dsq;
	s32			target_cpu;
	u64			flags = enq_flags & ~SCX_ENQ_PREEMPT;

	target_cpu = queue_pick_allowed_cpu(ctx, p, selected_cpu);
	if (target_cpu < 0)
		return target_cpu;
	cpuq = queue_cpu(ctx, target_cpu);
	if (!cpuq)
		return -EINVAL;
	consumers = queue_normal_consumers(ctx, cpuq->normal_queue_index);
	if (!consumers)
		return -EINVAL;
	if (!bpf_cpumask_subset(consumers, p->cpus_ptr))
		return -ENOENT;
	dsq = dsq_normal(cpuq->normal_queue_index);
	runtime->run_direct = 0;
	if (queue_transition_active())
		return -EAGAIN;
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->vruntime, flags, fine))
		return -EINVAL;
	queue_timing_record_insert(ctx, p, dsq, SNAKE_QUEUE_CELL_NONE, fine);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline int
queue_global_enqueue_cpu(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 struct snake_task_runtime *runtime, s32 selected_cpu,
			 u64 enq_flags,
			 const struct snake_fine_timing_ctx *fine)
{
	s32 target_cpu = queue_pick_allowed_cpu(ctx, p, selected_cpu);
	u64 flags      = enq_flags & ~SCX_ENQ_PREEMPT;
	dsq_id_t dsq;

	if (target_cpu < 0)
		return target_cpu;
	dsq = dsq_affinity(target_cpu);
	runtime->run_direct = 0;
	if (queue_transition_active())
		return -EAGAIN;
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->vruntime, flags, fine))
		return -EINVAL;
	queue_timing_record_insert(ctx, p, dsq, SNAKE_QUEUE_CELL_NONE, fine);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline int queue_fairness_direct_insert(
	struct snake_ladder_ctx *ctx, struct task_struct *p, s32 cpu,
	u32 cell_index, u32 queue_class, u32 mask_kind,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_queue_cell	  *cell;
	struct snake_cpu_queue	  *cpuq;
	const struct cpumask	  *mask;

	runtime = queue_fairness_prepare_runnable_for_cell(ctx, p, cell_index,
							   false, NULL);
	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;
	cell = queue_cell(ctx, cell_index);
	cpuq = queue_cpu(ctx, cpu);
	if (!cell || !cpuq)
		return -EINVAL;
	if (queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (queue_fairness_prepare_affinity(ctx, runtime,
						    cpuq->owner_cell_index))
			return -EINVAL;
	} else {
		mask = queue_cell_mask(ctx, cell_index, mask_kind);
		if (!mask || !bpf_cpumask_test_cpu(cpu, mask))
			return -EINVAL;
		if ((mask_kind == SNAKE_QUEUE_MASK_PRIMARY &&
		     cpuq->owner_cell_index != cell_index) ||
		    (mask_kind == SNAKE_QUEUE_MASK_BORROWABLE &&
		     cpuq->owner_cell_index == cell_index))
			return -EINVAL;
	}
	task_route_clear_selected_cpu(runtime);
	runtime->queue_class	   = queue_class;
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

static __noinline int
queue_fairness_direct_primary(struct snake_ladder_ctx *ctx,
			      struct task_struct *p, s32 cpu, u32 cell_index,
			      const struct snake_fine_timing_ctx *fine)
{
	return queue_fairness_direct_insert(
		ctx, p, cpu, cell_index, SNAKE_QUEUE_CLASS_NORMAL,
		SNAKE_QUEUE_MASK_PRIMARY, fine);
}

static __noinline int
queue_fairness_direct_borrow(struct snake_ladder_ctx *ctx,
			     struct task_struct *p, s32 cpu, u32 cell_index,
			     const struct snake_fine_timing_ctx *fine)
{
	return queue_fairness_direct_insert(
		ctx, p, cpu, cell_index, SNAKE_QUEUE_CLASS_NORMAL,
		SNAKE_QUEUE_MASK_BORROWABLE, fine);
}

static __noinline int
queue_fairness_direct_affinity(struct snake_ladder_ctx *ctx,
			       struct task_struct *p, s32 cpu, u32 cell_index,
			       const struct snake_fine_timing_ctx *fine)
{
	return queue_fairness_direct_insert(
		ctx, p, cpu, cell_index, SNAKE_QUEUE_CLASS_AFFINITY,
		SNAKE_QUEUE_MASK_INVALID, fine);
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
	s32			 restricted;
	s32			 target_cpu = selected_cpu;
	s32			 ret	    = 0;
	u64			 flags	    = enq_flags & ~SCX_ENQ_PREEMPT;
	u64			 stage_started_at;
	dsq_id_t		 dsq;

	stage_started_at = fine_timing_start(fine);
	cell		 = queue_cell(ctx, runtime->cell_index);
	primary =
		queue_cell_mask(ctx, runtime->cell_index,
				SNAKE_QUEUE_MASK_PRIMARY);
	if (!cell || !primary)
		ret = -EINVAL;
	else {
		restricted = queue_task_cell_affinity_restricted(
			ctx, p, runtime->cell_index);
		if (restricted)
			ret = restricted < 0 ? restricted : -ENOENT;
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_CELL_VALIDATE,
			   stage_started_at);
	if (ret)
		return ret;

	stage_started_at = fine_timing_start(fine);
	cpuq		 = target_cpu >= 0 ? queue_cpu(ctx, target_cpu) : NULL;
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		target_cpu = queue_pick_primary_cpu(
			primary, runtime->queue_cpumask, p, -1);
	if (target_cpu < 0)
		ret = target_cpu;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PICK_TARGET,
			   stage_started_at);
	if (ret)
		return ret;
	cpuq = queue_cpu(ctx, target_cpu);
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		return -EINVAL;

	runtime->queue_class	   = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct	   = 0;
	runtime->direct_cell_valid = 0;
	stage_started_at	   = fine_timing_start(fine);
	dsq			   = dsq_normal(cpuq->normal_queue_index);
	if (queue_transition_active())
		return -EAGAIN;
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
	const struct snake_fine_timing_ctx *fine, bool distribute_if_queued)
{
	struct snake_cpu_queue *cpuq;
	s32	 target_cpu	  = queue_pick_allowed_cpu(ctx, p, selected_cpu);
	s32	 distributed, nr_queued;
	s32	 ret		  = 0;
	u64	 flags		  = enq_flags & ~SCX_ENQ_PREEMPT;
	u64	 stage_started_at = fine_timing_start(fine);
	u64	 insert_started_at;
	dsq_id_t dsq;

	if (target_cpu < 0) {
		ret = target_cpu;
		goto out;
	}
	if (distribute_if_queued) {
		nr_queued = dsq_nr_queued(dsq_affinity(target_cpu));
		if (nr_queued < 0) {
			ret = nr_queued;
			goto out;
		}
		if (nr_queued > 0) {
			distributed = bpf_cpumask_any_distribute(p->cpus_ptr);
			if (distributed >= 0 && distributed < nr_cpu_ids &&
			    queue_cpu(ctx, distributed))
				target_cpu = distributed;
		}
	}
	cpuq = queue_cpu(ctx, target_cpu);
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
	if (queue_transition_active()) {
		ret = -EAGAIN;
		goto out;
	}
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

static __always_inline int queue_transition_enqueue(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u64 enq_flags,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	dsq_id_t		   target;
	s32			   selected_cpu, target_cpu;
	u64			   slice;

	if (queue_global_mode_enabled()) {
		fairness_vtime_prepare_runnable(ctx, p);
		runtime = fairness_vtime_prepare_task(ctx, p);
		if (runtime) {
			runtime->active_weight = fairness_task_weight(p);
			runtime->pending_weight = runtime->active_weight;
		}
	} else {
		runtime = queue_fairness_prepare_runnable(ctx, p, fine);
	}
	if (!runtime)
		return -EINVAL;
	selected_cpu = task_route_take_selected_cpu(runtime, p);
	target_cpu = queue_pick_allowed_cpu(ctx, p, selected_cpu);
	if (target_cpu < 0)
		return target_cpu;
	runtime->queue_class	     = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct	     = 0;
	runtime->direct_cell_valid = 0;
	target = dsq_local_on(target_cpu);
	slice = fairness_vtime_slice(runtime->active_weight);
	if (!dsq_insert(p, target, slice, enq_flags & ~SCX_ENQ_PREEMPT, fine))
		return -EINVAL;
	queue_timing_record_insert(ctx, p, target, SNAKE_QUEUE_CELL_NONE, fine);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

struct snake_queue_enqueue_loop_ctx {
	struct snake_ladder_ctx	     ladder_ctx;
	struct task_struct	    *p;
	struct snake_task_runtime   *runtime;
	struct snake_fine_timing_ctx fine;
	s32			     selected_cpu;
	u64			     enq_flags;
	u64			     callback_started_at;
	s32			     result;
};

static __noinline int queue_cell_enqueue_normal_ctx(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	return queue_fairness_enqueue_cell(
		&loop_ctx->ladder_ctx, loop_ctx->p, loop_ctx->runtime,
		loop_ctx->selected_cpu, loop_ctx->enq_flags, &loop_ctx->fine);
}

static __noinline int queue_cell_enqueue_affinity_ctx(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	return queue_fairness_enqueue_affinity(
		&loop_ctx->ladder_ctx, loop_ctx->p, loop_ctx->runtime,
		loop_ctx->selected_cpu, loop_ctx->enq_flags, &loop_ctx->fine,
		false);
}

static __noinline int queue_cell_enqueue_cpu_ctx(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	return queue_fairness_enqueue_affinity(
		&loop_ctx->ladder_ctx, loop_ctx->p, loop_ctx->runtime,
		loop_ctx->selected_cpu, loop_ctx->enq_flags, &loop_ctx->fine, true);
}

static __noinline int queue_global_enqueue_local_ctx(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	return queue_global_enqueue_local(
		&loop_ctx->ladder_ctx, loop_ctx->p, loop_ctx->runtime,
		loop_ctx->selected_cpu, loop_ctx->enq_flags, &loop_ctx->fine);
}

static __noinline int queue_global_enqueue_cpu_ctx(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	return queue_global_enqueue_cpu(
		&loop_ctx->ladder_ctx, loop_ctx->p, loop_ctx->runtime,
		loop_ctx->selected_cpu, loop_ctx->enq_flags, &loop_ctx->fine);
}

static __noinline s32 queue_global_ladder_enqueue_rung(
	struct snake_queue_enqueue_loop_ctx *loop_ctx, u32 index)
{
	const struct snake_queue_rung *rung;
	s32 ret;
	u64 rung_started_at;

	if (index >= SNAKE_MAX_QUEUE_RUNGS ||
	    index >= loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs)
		return -EINVAL;
	rung = MEMBER_VPTR(loop_ctx->ladder_ctx.ladder->enqueue_rungs, [index]);
	if (!rung)
		return -EINVAL;
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE + index);
	if (rung->opcode == SNAKE_ENQUEUE_OP_TRY_INSERT &&
	    rung->input == SNAKE_QUEUE_INPUT_LOCAL)
		ret = queue_global_enqueue_local_ctx(loop_ctx);
	else if (rung->opcode == SNAKE_ENQUEUE_OP_INSERT &&
		 rung->input == SNAKE_QUEUE_INPUT_CPU)
		ret = queue_global_enqueue_cpu_ctx(loop_ctx);
	else
		ret = -EINVAL;
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_ENQUEUE,
			   index, rung_started_at);
	if (!ret) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE + index);
		return 1;
	}
	if (ret == -ENOENT &&
	    index + 1 < loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_MISS_BASE + index);
		return 0;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE + index);
	return ret;
}

static __noinline int queue_global_ladder_enqueue(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	s32 result;

	if (loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs != 2)
		return -EINVAL;
	result = queue_global_ladder_enqueue_rung(loop_ctx, 0);
	if (result < 0)
		return result;
	if (result > 0)
		return 0;
	result = queue_global_ladder_enqueue_rung(loop_ctx, 1);
	if (result < 0)
		return result;
	return result > 0 ? 0 : -ENOENT;
}

static long
queue_cell_ladder_enqueue_callback(u32				   i,
				   struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	const struct snake_queue_rung *rung;
	s32			       ret;
	u64			       rung_started_at;

	if (i >= SNAKE_MAX_QUEUE_RUNGS ||
	    i >= loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs)
		return 1;
	rung = MEMBER_VPTR(loop_ctx->ladder_ctx.ladder->enqueue_rungs, [i]);
	if (!rung) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE + i);
	if (rung->opcode == SNAKE_ENQUEUE_OP_CELL)
		ret = queue_cell_enqueue_normal_ctx(loop_ctx);
	else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY)
		ret = queue_cell_enqueue_affinity_ctx(loop_ctx);
	else {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE + i);
		loop_ctx->result = -EINVAL;
		return 1;
	}
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_ENQUEUE, i,
			   rung_started_at);
	if (!ret) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE + i);
		loop_ctx->result = 0;
		return 1;
	}
	if (ret == -ENOENT &&
	    i + 1 < loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_MISS_BASE + i);
		return 0;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE + i);
	loop_ctx->result = ret;
	return 1;
}

static __noinline int queue_mitosis_ladder_enqueue(
	struct snake_queue_enqueue_loop_ctx *loop_ctx)
{
	const struct snake_queue_rung *cell_rung, *cpu_rung;
	s32 ret;
	u64 rung_started_at;

	if (!loop_ctx || loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs != 3)
		return -EINVAL;
	cell_rung = MEMBER_VPTR(loop_ctx->ladder_ctx.ladder->enqueue_rungs, [1]);
	cpu_rung = MEMBER_VPTR(loop_ctx->ladder_ctx.ladder->enqueue_rungs, [2]);
	if (!cell_rung || !cpu_rung ||
	    cell_rung->opcode != SNAKE_ENQUEUE_OP_CELL ||
	    cell_rung->input != SNAKE_QUEUE_INPUT_CELL ||
	    cpu_rung->opcode != SNAKE_ENQUEUE_OP_INSERT_CPU ||
	    cpu_rung->input != SNAKE_QUEUE_INPUT_CPU)
		return -EINVAL;

	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE + 1);
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	ret = queue_cell_enqueue_normal_ctx(loop_ctx);
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_ENQUEUE, 1,
			   rung_started_at);
	if (!ret) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE + 1);
		return 0;
	}
	if (ret != -ENOENT) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE + 1);
		return ret;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_MISS_BASE + 1);

	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE + 2);
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	ret = queue_cell_enqueue_cpu_ctx(loop_ctx);
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_ENQUEUE, 2,
			   rung_started_at);
	stat_inc(&loop_ctx->ladder_ctx,
		 (!ret ? SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE :
			 SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE) +
			 2);
	return ret;
}

static __always_inline int
queue_ladder_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		     u64 enq_flags, const struct snake_fine_timing_ctx *fine,
		     u64 callback_started_at)
{
	struct snake_task_runtime	   *runtime;
	struct snake_queue_enqueue_loop_ctx loop_ctx;
	s32				    selected_cpu;
	u64				    stage_started_at;
	long				    nr_loops;

	stage_started_at = fine_timing_start(fine);
	queue_fairness_cancel_direct(ctx, p);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_CANCEL_DIRECT,
			   stage_started_at);
	stage_started_at = fine_timing_start(fine);
	if (queue_global_mode_enabled()) {
		fairness_vtime_prepare_runnable(ctx, p);
		runtime = fairness_vtime_prepare_task(ctx, p);
		if (runtime) {
			runtime->active_weight = fairness_task_weight(p);
			runtime->pending_weight = runtime->active_weight;
		}
	} else {
		runtime = queue_fairness_prepare_runnable(ctx, p, fine);
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_RUNNABLE,
			   stage_started_at);
	if (!runtime)
		return -EINVAL;
	selected_cpu = task_route_take_selected_cpu(runtime, p);
	loop_ctx     = (struct snake_queue_enqueue_loop_ctx){
		    .ladder_ctx	  = *ctx,
		    .p		  = p,
		    .runtime	  = runtime,
		    .fine	  = fine ? *fine : (struct snake_fine_timing_ctx){},
		    .selected_cpu = selected_cpu,
		    .enq_flags	  = enq_flags,
		    .callback_started_at = callback_started_at,
		    .result		 = -ENOENT,
	};
	if (queue_global_mode_enabled())
		return queue_global_ladder_enqueue(&loop_ctx);
	if (ctx->ladder->nr_enqueue_rungs == 3) {
		const struct snake_queue_rung *first =
			MEMBER_VPTR(ctx->ladder->enqueue_rungs, [0]);

		if (first && first->opcode == SNAKE_ENQUEUE_OP_TRY_DIRECT &&
		    first->input == SNAKE_QUEUE_INPUT_CELL)
			return queue_mitosis_ladder_enqueue(&loop_ctx);
	}
	nr_loops = bpf_loop(SNAKE_MAX_QUEUE_RUNGS,
			    queue_cell_ladder_enqueue_callback, &loop_ctx, 0);
	if (nr_loops < 0) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return nr_loops;
	}
	return loop_ctx.result;
}

#endif /* __SCX_SNAKE_QUEUE_ENQUEUE_H */
