/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_DISPATCH_H
#define __SCX_SNAKE_QUEUE_DISPATCH_H

#include "queue_vtime.h"

static __always_inline bool
queue_fairness_remote_normal(struct snake_queue_cell *cell, u32 local_queue,
			     u32 *queue_index, u64 *vtime)
{
	u32  offset;
	bool found = false;

	bpf_for(offset, 0, SNAKE_MAX_CELL_LLCS)
	{
		u32 index;
		u64 candidate;

		if (offset >= cell->nr_normal_queues)
			break;
		index = cell->first_normal_queue + offset;
		if (index == local_queue ||
		    !dsq_vtime_head(dsq_normal(index), &candidate))
			continue;
		if (!found || time_before(candidate, *vtime)) {
			*queue_index = index;
			*vtime	     = candidate;
			found	     = true;
		}
	}
	return found;
}

static __always_inline u32
queue_fairness_remote_scan_stage(const struct snake_queue_cell *cell)
{
	u32 nr_queues = READ_ONCE(cell->nr_normal_queues);

	if (nr_queues <= 1)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_1_QUEUE;
	if (nr_queues <= 4)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_2_4_QUEUES;
	if (nr_queues <= 8)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_5_8_QUEUES;
	return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_9_PLUS_QUEUES;
}

static __noinline s32
queue_fairness_move(struct snake_ladder_ctx *ctx, dsq_id_t dsq, s32 cpu,
			    u32 class, const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct task_struct *p;
	s32 ret = 0;
	bool moved = false;

	bpf_for_each(scx_dsq, p, dsq.raw, 0) {
		runtime = task_state_lookup(p);
		if (queue_cell_mode_enabled() && !runtime) {
			ret = -EINVAL;
			break;
		}
		moved = dsq_move(BPF_FOR_EACH_ITER, p, dsq, dsq_local_on(cpu), 0,
				 fine);
		if (moved && queue_cell_mode_enabled()) {
			ret = queue_custom_account_dequeue(runtime);
			if (ret < 0)
				stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		}
		break;
	}
	if (ret < 0)
		return ret;
	if (!moved)
		return 0;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return 1;
}

struct snake_queue_candidate {
	dsq_id_t dsq;
	u64	 vtime;
	u32 class;
	u32 valid;
};

static __always_inline int
queue_fairness_normal_candidate(struct snake_ladder_ctx		   *ctx,
				struct snake_cpu_queue		   *cpuq,
				struct snake_queue_candidate	   *candidate,
				const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	u32			 normal_index;
	u64			 stage_started_at;
	bool			 found;

	if (!cpuq || !candidate)
		return -EINVAL;
	candidate->valid = 0;
	cell		 = queue_cell(ctx, cpuq->owner_cell_index);
	if (!cell)
		return -EINVAL;
	normal_index	 = cpuq->normal_queue_index;
	candidate->dsq	 = dsq_normal(normal_index);
	stage_started_at = fine_timing_start(fine);
	found		 = dsq_vtime_head(candidate->dsq, &candidate->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
			   stage_started_at);
	if (!found) {
		stage_started_at = fine_timing_start(fine);
		found		 = queue_fairness_remote_normal(
			   cell, normal_index, &normal_index, &candidate->vtime);
		fine_timing_finish(fine, queue_fairness_remote_scan_stage(cell),
				   stage_started_at);
		if (!found)
			return 0;
		candidate->dsq = dsq_normal(normal_index);
	}
	candidate->class = SNAKE_QUEUE_CLASS_NORMAL;
	candidate->valid = 1;
	return 0;
}

static __always_inline int
queue_fairness_affinity_candidate(s32				cpu,
				  struct snake_queue_candidate *candidate)
{
	if (!candidate || cpu < 0 || cpu >= nr_cpu_ids ||
	    cpu >= SNAKE_MAX_CPUS)
		return -EINVAL;
	candidate->valid = 0;
	candidate->dsq	 = dsq_affinity(cpu);
	if (!dsq_vtime_head(candidate->dsq, &candidate->vtime))
		return 0;
	candidate->class = SNAKE_QUEUE_CLASS_AFFINITY;
	candidate->valid = 1;
	return 0;
}

static __noinline s32 queue_fairness_keep_running(struct snake_ladder_ctx *ctx,
						  struct snake_cpu_queue  *cpuq,
						  struct task_struct	  *prev,
						  u32 class,
						  u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64			   current, delta, projected, service, vruntime;
	u32			   weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid || !cpuq)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(ctx, prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	if (runtime->run_queue_class != class)
		return 0;
	if (runtime->run_owner_cell_index != cpuq->owner_cell_index)
		return 0;
	if (class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (!runtime->affinity_initialized)
			return -EINVAL;
		if (runtime->affinity_cell_index != cpuq->owner_cell_index)
			return 0;
	} else if (runtime->run_cell_index != cpuq->owner_cell_index) {
		return 0;
	}
	current = prev->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -ERANGE;
	}
	delta	  = current - runtime->started_exec_runtime;
	weight	  = runtime->active_weight ?: fairness_task_weight(prev);
	vruntime  = class == SNAKE_QUEUE_CLASS_AFFINITY ?
			    runtime->affinity_vruntime :
			    runtime->vruntime;
	service	  = fairness_vtime_service(delta, runtime->service_budget,
					   prev->scx.slice);
	projected = vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return 0;
	fairness_vtime_replenish(runtime, prev, weight);
	return 1;
}

static __always_inline s32 queue_fairness_keep_running_min(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq,
	struct task_struct *prev, u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64			   current, delta, projected, service, vruntime;
	u32			   weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid || !cpuq)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(ctx, prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	/* A core-retained prev from another cell clock cannot enter this order. */
	if (runtime->run_owner_cell_index != cpuq->owner_cell_index)
		return 0;
	if (runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (!runtime->affinity_initialized)
			return -EINVAL;
		if (runtime->affinity_cell_index != cpuq->owner_cell_index)
			return 0;
		vruntime = runtime->affinity_vruntime;
	} else {
		if (runtime->run_queue_class != SNAKE_QUEUE_CLASS_NORMAL)
			return -EINVAL;
		/* Borrowed normal work remains charged to its task cell clock. */
		if (runtime->run_cell_index != cpuq->owner_cell_index)
			return 0;
		vruntime = runtime->vruntime;
	}
	current = prev->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -ERANGE;
	}
	delta	  = current - runtime->started_exec_runtime;
	weight	  = runtime->active_weight ?: fairness_task_weight(prev);
	service	  = fairness_vtime_service(delta, runtime->service_budget,
					   prev->scx.slice);
	projected = vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return 0;
	fairness_vtime_replenish(runtime, prev, weight);
	return 1;
}

struct snake_queue_dispatch_min_args {
	const struct snake_fine_timing_ctx *fine;
	u32				   *equal_preference;
	s32				    cpu;
};

static __noinline s32 queue_fairness_dispatch_min(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq,
	struct task_struct			   *prev,
	const struct snake_queue_dispatch_min_args *args)
{
	struct snake_queue_candidate	    normal = {}, affinity = {};
	struct snake_queue_candidate	   *winner, *loser;
	const struct snake_fine_timing_ctx *fine = args->fine;
	u32 *equal_preference			 = args->equal_preference;
	s32  cpu				 = args->cpu;
	s32  keep, ret;
	u64  stage_started_at;

	if (!equal_preference)
		return -EINVAL;
	ret = queue_fairness_normal_candidate(ctx, cpuq, &normal, fine);
	if (ret)
		return ret;
	stage_started_at = fine_timing_start(fine);
	ret		 = queue_fairness_affinity_candidate(cpu, &affinity);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
			   stage_started_at);
	if (ret)
		return ret;
	stage_started_at = fine_timing_start(fine);
	if (!normal.valid && !affinity.valid) {
		fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
				   stage_started_at);
		return 0;
	}
	if (!affinity.valid ||
	    (normal.valid && time_before(normal.vtime, affinity.vtime))) {
		winner = &normal;
		loser  = affinity.valid ? &affinity : NULL;
	} else if (!normal.valid || time_before(affinity.vtime, normal.vtime)) {
		winner = &affinity;
		loser  = normal.valid ? &normal : NULL;
	} else {
		stat_inc(ctx, SNAKE_STAT_VTIME_EQUAL_HEAD_TIES);
		if (*equal_preference == SNAKE_QUEUE_CLASS_AFFINITY) {
			winner		  = &affinity;
			loser		  = &normal;
			*equal_preference = SNAKE_QUEUE_CLASS_NORMAL;
		} else {
			winner		  = &normal;
			loser		  = &affinity;
			*equal_preference = SNAKE_QUEUE_CLASS_AFFINITY;
		}
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
			   stage_started_at);

	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, winner->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	ret = queue_fairness_move(ctx, winner->dsq, cpu, winner->class, fine);
	if (ret < 0)
		return ret;
	if (ret > 0)
		return 1;
	if (!loser)
		return 0;
	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, loser->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	ret = queue_fairness_move(ctx, loser->dsq, cpu, loser->class, fine);
	return ret;
}

static __always_inline s32 queue_fairness_dispatch_source(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq, s32 cpu,
	struct task_struct *prev, u32 opcode,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	dsq_id_t		 dsq;
	u64			 candidate_vtime = 0;
	u64			 stage_started_at;
	u32 class, normal_index;
	s32  keep;
	bool found;

	if (!cpuq)
		return -EINVAL;
	if (opcode == SNAKE_DISPATCH_OP_CELL) {
		cell = queue_cell(ctx, cpuq->owner_cell_index);
		if (!cell)
			return -EINVAL;
		normal_index	 = cpuq->normal_queue_index;
		dsq		 = dsq_normal(normal_index);
		stage_started_at = fine_timing_start(fine);
		found		 = dsq_vtime_head(dsq, &candidate_vtime);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
				   stage_started_at);
		if (!found) {
			stage_started_at = fine_timing_start(fine);
			found = queue_fairness_remote_normal(cell, normal_index,
							     &normal_index,
							     &candidate_vtime);
			fine_timing_finish(
				fine, queue_fairness_remote_scan_stage(cell),
				stage_started_at);
			if (!found)
				return 0;
			dsq = dsq_normal(normal_index);
		}
		class = SNAKE_QUEUE_CLASS_NORMAL;
	} else if (opcode == SNAKE_DISPATCH_OP_AFFINITY) {
		dsq		 = dsq_affinity(cpu);
		stage_started_at = fine_timing_start(fine);
		found		 = dsq_vtime_head(dsq, &candidate_vtime);
		fine_timing_finish(
			fine, SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
			stage_started_at);
		if (!found)
			return 0;
		class = SNAKE_QUEUE_CLASS_AFFINITY;
	} else {
		return -EINVAL;
	}

	stage_started_at = fine_timing_start(fine);
	keep		 = queue_fairness_keep_running(ctx, cpuq, prev, class,
						       candidate_vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	keep = queue_fairness_move(ctx, dsq, cpu, class, fine);
	return keep;
}

static __always_inline int
queue_dispatch_peek_cpu(s32 cpu, struct snake_queue_candidate *candidate)
{
	if (!candidate || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	*candidate = (struct snake_queue_candidate){
		.dsq = dsq_affinity(cpu),
		.class = SNAKE_QUEUE_CLASS_AFFINITY,
	};
	candidate->valid = dsq_vtime_head(candidate->dsq, &candidate->vtime);
	return 0;
}

static __always_inline int
queue_dispatch_peek_local(struct snake_cpu_queue *cpuq,
			  struct snake_queue_candidate *candidate)
{
	if (!candidate || !cpuq)
		return -EINVAL;
	*candidate = (struct snake_queue_candidate){
		.dsq = dsq_normal(cpuq->normal_queue_index),
		.class = SNAKE_QUEUE_CLASS_NORMAL,
	};
	candidate->valid = dsq_vtime_head(candidate->dsq, &candidate->vtime);
	return 0;
}

static __noinline s32 queue_mitosis_steal_sibling(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq, s32 cpu,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	u32 local_offset, offset;

	if (!cpuq || cpu < 0 || cpu >= nr_cpu_ids || cpu >= SNAKE_MAX_CPUS)
		return -EINVAL;
	cell = queue_cell(ctx, cpuq->owner_cell_index);
	if (!cell || !cell->nr_normal_queues ||
	    cell->nr_normal_queues > SNAKE_MAX_CELL_LLCS)
		return -EINVAL;
	if (cpuq->normal_queue_index < cell->first_normal_queue)
		return -EINVAL;
	local_offset = cpuq->normal_queue_index - cell->first_normal_queue;
	if (local_offset >= cell->nr_normal_queues)
		return -EINVAL;
	bpf_for(offset, 0, SNAKE_MAX_CELL_LLCS)
	{
		dsq_id_t dsq;
		struct snake_normal_queue_runtime *runtime;
		u32 index;
		s32 nr_queued;

		if (offset >= cell->nr_normal_queues)
			break;
		index = cell->first_normal_queue +
			((local_offset + offset) % cell->nr_normal_queues);
		if (index >= SNAKE_MAX_NORMAL_QUEUES)
			return -EINVAL;
		if (index == cpuq->normal_queue_index)
			continue;
		runtime = queue_normal_runtime(index);
		if (!runtime || !READ_ONCE(runtime->has_consumers))
			continue;
		dsq = dsq_normal(index);
		nr_queued = dsq_nr_queued(dsq);
		if (nr_queued < 0)
			return nr_queued;
		if (nr_queued > 0) {
			s32 moved = queue_fairness_move(
				ctx, dsq, cpu, SNAKE_QUEUE_CLASS_NORMAL, fine);

			if (moved < 0)
				return moved;
			if (moved > 0)
				return 1;
		}
	}
	return 0;
}

static __noinline s32 queue_mitosis_ladder_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	const struct snake_queue_rung *cell_rung, *cpu_rung, *consume_rung;
	struct snake_cpu_queue *cpuq;
	struct snake_queue_candidate cell_candidate = {}, cpu_candidate = {};
	struct snake_queue_candidate *winner;
	u32 winner_rung;
	s32 keep, result = 0, ret;
	u64 rung_started_at, stage_started_at;

	if (!ctx || ctx->ladder->nr_dispatch_rungs != 3)
		return -EINVAL;
	cpuq = queue_cpu(ctx, cpu);
	if (!cpuq)
		return -EINVAL;
	cell_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);
	cpu_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [1]);
	consume_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [2]);
	if (!cell_rung || !cpu_rung || !consume_rung ||
	    cell_rung->opcode != SNAKE_DISPATCH_OP_PEEK ||
	    cell_rung->input != SNAKE_QUEUE_INPUT_CELL ||
	    cpu_rung->opcode != SNAKE_DISPATCH_OP_PEEK ||
	    cpu_rung->input != SNAKE_QUEUE_INPUT_CPU ||
	    consume_rung->opcode != SNAKE_DISPATCH_OP_CONSUME ||
	    consume_rung->input != SNAKE_QUEUE_INPUT_MIN_VTIME)
		return -EINVAL;

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE);
	rung_started_at = rung_timing_start(callback_started_at);
	stage_started_at = fine_timing_start(fine);
	ret = queue_dispatch_peek_local(cpuq, &cell_candidate);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
			   stage_started_at);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 0,
			   rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE);
		return ret;
	}
	stat_inc(ctx,
		 (cell_candidate.valid ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
					 SNAKE_STAT_DISPATCH_RUNG_MISS_BASE));

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 1);
	rung_started_at = rung_timing_start(callback_started_at);
	stage_started_at = fine_timing_start(fine);
	ret = queue_dispatch_peek_cpu(cpu, &cpu_candidate);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
			   stage_started_at);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 1,
			   rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 1);
		return ret;
	}
	stat_inc(ctx,
		 (cpu_candidate.valid ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
					SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
			 1);

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 2);
	rung_started_at = rung_timing_start(callback_started_at);
	if (!cell_candidate.valid && !cpu_candidate.valid) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE);
		ret = queue_mitosis_steal_sibling(ctx, cpuq, cpu, fine);
		if (ret < 0)
			goto consume_error;
		stat_inc(ctx,
			 (ret ? SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE :
				SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE));
		result = ret;
		goto consume_out;
	}

	stage_started_at = fine_timing_start(fine);
	if (cell_candidate.valid &&
	    (!cpu_candidate.valid ||
	     !time_before(cpu_candidate.vtime, cell_candidate.vtime))) {
		winner = &cell_candidate;
		winner_rung = 0;
		if (cpu_candidate.valid &&
		    cpu_candidate.vtime == cell_candidate.vtime)
			stat_inc(ctx, SNAKE_STAT_VTIME_EQUAL_HEAD_TIES);
	} else {
		winner = &cpu_candidate;
		winner_rung = 1;
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
			   stage_started_at);
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE + winner_rung);
	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, winner->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0) {
		ret = keep;
		goto consume_error;
	}
	if (keep) {
		result = 1;
		goto consume_out;
	}
	ret = queue_fairness_move(ctx, winner->dsq, cpu, winner->class, fine);
	if (ret < 0)
		goto consume_error;
	if (ret > 0) {
		result = 1;
		goto consume_out;
	}
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE + 2);
	if (winner == &cell_candidate && cpu_candidate.valid) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + 1);
		ret = queue_fairness_move(ctx, cpu_candidate.dsq, cpu,
					  SNAKE_QUEUE_CLASS_AFFINITY, fine);
		if (ret < 0)
			goto consume_error;
		if (ret > 0) {
			stat_inc(ctx,
				 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + 1);
			result = 1;
		} else {
			stat_inc(ctx,
				 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + 1);
		}
	}

consume_out:
	if (!result) {
		ret = queue_fairness_replenish(ctx, cpuq, prev);
		if (ret < 0)
			goto consume_error;
	}
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 2,
			   rung_started_at);
	stat_inc(ctx,
		 (result ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
			   SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
			 2);
	return 0;

consume_error:
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 2,
			   rung_started_at);
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 2);
	return ret;
}

static __noinline s32
queue_mitosis_drain_orphan(struct snake_ladder_ctx *ctx,
			    struct snake_cpu_queue *cpuq, s32 cpu,
			    const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	struct snake_cell_queue_runtime *cell_runtime;
	u32 drain_mask, local_offset, offset;

	if (!ctx || !cpuq || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	cell = queue_cell(ctx, cpuq->owner_cell_index);
	if (!cell || !cell->nr_normal_queues ||
	    cell->nr_normal_queues > SNAKE_MAX_CELL_LLCS)
		return -EINVAL;
	if (cpuq->normal_queue_index < cell->first_normal_queue)
		return -EINVAL;
	local_offset = cpuq->normal_queue_index - cell->first_normal_queue;
	if (local_offset >= cell->nr_normal_queues)
		return -EINVAL;
	cell_runtime = queue_cell_runtime(cpuq->owner_cell_index);
	if (!cell_runtime)
		return -EINVAL;
	drain_mask = READ_ONCE(cell_runtime->llcs_to_drain);
	if (!drain_mask)
		return 0;
	bpf_for(offset, 0, SNAKE_MAX_CELL_LLCS)
	{
		struct snake_normal_queue_runtime *runtime;
		u32 candidate_offset, index, pending;
		bool disabled = false;
		s32 moved;

		if (offset >= cell->nr_normal_queues)
			break;
		candidate_offset =
			(local_offset + offset) % cell->nr_normal_queues;
		if (!(drain_mask & (1U << candidate_offset)))
			continue;
		index = cell->first_normal_queue + candidate_offset;
		if (index >= SNAKE_MAX_NORMAL_QUEUES)
			return -EINVAL;
		runtime = queue_normal_runtime(index);
		if (!runtime)
			return -EINVAL;
		if (READ_ONCE(runtime->cell_index) != cpuq->owner_cell_index)
			continue;
		if (READ_ONCE(runtime->cell_offset) != candidate_offset)
			continue;
		if (READ_ONCE(runtime->has_consumers)) {
			if (queue_normal_drain_disable(runtime))
				return -EINVAL;
			pending = READ_ONCE(runtime->nr_queued);
			if (pending && !READ_ONCE(runtime->has_consumers)) {
				if (queue_normal_drain_enable(runtime))
					return -EINVAL;
				queue_kick_idle_cell_cpu(ctx->slot,
							 cpuq->owner_cell_index);
			}
			continue;
		}
		pending = READ_ONCE(runtime->nr_queued);
		if (!pending) {
			if (queue_normal_drain_disable(runtime))
				return -EINVAL;
			pending = READ_ONCE(runtime->nr_queued);
			if (pending && !READ_ONCE(runtime->has_consumers)) {
				if (queue_normal_drain_enable(runtime))
					return -EINVAL;
				queue_kick_idle_cell_cpu(ctx->slot,
							 cpuq->owner_cell_index);
			}
			continue;
		}
		if (pending <= 1) {
			if (queue_normal_drain_disable(runtime))
				return -EINVAL;
			disabled = true;
		}
		moved = queue_fairness_move(ctx, dsq_normal(index), cpu,
					    SNAKE_QUEUE_CLASS_NORMAL, fine);
		if (moved < 0)
			return moved;
		pending = READ_ONCE(runtime->nr_queued);
		if (disabled && pending && !READ_ONCE(runtime->has_consumers)) {
			if (queue_normal_drain_enable(runtime))
				return -EINVAL;
			queue_kick_idle_cell_cpu(ctx->slot,
						 cpuq->owner_cell_index);
		}
		if (moved > 0)
			return 1;
	}
	return 0;
}

static __noinline s32 queue_mitosis_expanded_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	const struct snake_queue_rung *drain_rung, *cell_rung, *cpu_rung,
		*consume_rung, *steal_rung;
	struct snake_cpu_queue *cpuq;
	struct snake_queue_candidate cell_candidate = {}, cpu_candidate = {};
	struct snake_queue_candidate *winner;
	u32 winner_rung;
	s32 keep, result = 0, ret;
	u64 rung_started_at, stage_started_at;

	if (!ctx || ctx->ladder->nr_dispatch_rungs != 5)
		return -EINVAL;
	cpuq = queue_cpu(ctx, cpu);
	if (!cpuq)
		return -EINVAL;
	drain_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);
	cell_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [1]);
	cpu_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [2]);
	consume_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [3]);
	steal_rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [4]);
	if (!drain_rung || !cell_rung || !cpu_rung || !consume_rung ||
	    !steal_rung || drain_rung->opcode != SNAKE_DISPATCH_OP_DRAIN ||
	    drain_rung->input != SNAKE_QUEUE_INPUT_CELL_ORPHAN ||
	    cell_rung->opcode != SNAKE_DISPATCH_OP_PEEK ||
	    cell_rung->input != SNAKE_QUEUE_INPUT_CELL ||
	    cpu_rung->opcode != SNAKE_DISPATCH_OP_PEEK ||
	    cpu_rung->input != SNAKE_QUEUE_INPUT_CPU ||
	    consume_rung->opcode != SNAKE_DISPATCH_OP_CONSUME ||
	    consume_rung->input != SNAKE_QUEUE_INPUT_MIN_VTIME ||
	    steal_rung->opcode != SNAKE_DISPATCH_OP_STEAL ||
	    steal_rung->input != SNAKE_QUEUE_INPUT_CELL_SIBLING)
		return -EINVAL;

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE);
	rung_started_at = rung_timing_start(callback_started_at);
	ret = queue_mitosis_drain_orphan(ctx, cpuq, cpu, fine);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 0, rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE);
		return ret;
	}
	stat_inc(ctx, (ret ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
			      SNAKE_STAT_DISPATCH_RUNG_MISS_BASE));
	if (ret)
		return 0;

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 1);
	rung_started_at = rung_timing_start(callback_started_at);
	stage_started_at = fine_timing_start(fine);
	ret = queue_dispatch_peek_local(cpuq, &cell_candidate);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
			   stage_started_at);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 1, rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 1);
		return ret;
	}
	stat_inc(ctx,
		 (cell_candidate.valid ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
					 SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
			 1);

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 2);
	rung_started_at = rung_timing_start(callback_started_at);
	stage_started_at = fine_timing_start(fine);
	ret = queue_dispatch_peek_cpu(cpu, &cpu_candidate);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
			   stage_started_at);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 2, rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 2);
		return ret;
	}
	stat_inc(ctx,
		 (cpu_candidate.valid ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
					SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
			 2);

	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 3);
	rung_started_at = rung_timing_start(callback_started_at);
	if (!cell_candidate.valid && !cpu_candidate.valid) {
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 3,
				   rung_started_at);
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_MISS_BASE + 3);

		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + 4);
		rung_started_at = rung_timing_start(callback_started_at);
		ret = queue_mitosis_steal_sibling(ctx, cpuq, cpu, fine);
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 4,
				   rung_started_at);
		if (ret < 0) {
			stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 4);
			return ret;
		}
		stat_inc(ctx,
			 (ret ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
				SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
				 4);
		if (ret)
			return 0;
		return queue_fairness_replenish(ctx, cpuq, prev);
	}

	stage_started_at = fine_timing_start(fine);
	if (cell_candidate.valid &&
	    (!cpu_candidate.valid ||
	     !time_before(cpu_candidate.vtime, cell_candidate.vtime))) {
		winner = &cell_candidate;
		winner_rung = 1;
		if (cpu_candidate.valid &&
		    cpu_candidate.vtime == cell_candidate.vtime)
			stat_inc(ctx, SNAKE_STAT_VTIME_EQUAL_HEAD_TIES);
	} else {
		winner = &cpu_candidate;
		winner_rung = 2;
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
			   stage_started_at);
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE + winner_rung);
	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, winner->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0) {
		ret = keep;
		goto consume_error;
	}
	if (keep) {
		result = 1;
		goto consume_out;
	}
	ret = queue_fairness_move(ctx, winner->dsq, cpu, winner->class, fine);
	if (ret < 0)
		goto consume_error;
	if (ret > 0) {
		result = 1;
		goto consume_out;
	}
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE + 3);
	if (winner == &cell_candidate && cpu_candidate.valid) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + 3);
		ret = queue_fairness_move(ctx, cpu_candidate.dsq, cpu,
					  SNAKE_QUEUE_CLASS_AFFINITY, fine);
		if (ret < 0)
			goto consume_error;
		if (ret > 0) {
			stat_inc(ctx,
				 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + 3);
			result = 1;
		} else {
			stat_inc(ctx,
				 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + 3);
		}
	}

consume_out:
	if (!result) {
		ret = queue_fairness_replenish(ctx, cpuq, prev);
		if (ret < 0)
			goto consume_error;
	}
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 3, rung_started_at);
	stat_inc(ctx,
		 (result ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
			   SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
			 3);
	return 0;

consume_error:
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 3, rung_started_at);
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + 3);
	return ret;
}

struct snake_remote_scan_loop_ctx {
	struct snake_queue_candidate candidate;
	u32 local_queue;
	u32 start;
	u32 nr_queues;
	u32 next_remote_queue;
	s32 cpu;
	s32 result;
};

static long queue_dispatch_remote_scan_callback(
	u32 offset, struct snake_remote_scan_loop_ctx *loop_ctx)
{
	struct task_struct *p, *task;
	dsq_id_t dsq;
	u32 index, nr_queues, start;
	s32 cpu;
	s32 nr_queued;
	bool eligible = false;

	nr_queues = loop_ctx->nr_queues;
	start = loop_ctx->start;
	cpu = loop_ctx->cpu;
	if (nr_queues <= 1 || nr_queues > SNAKE_MAX_NORMAL_QUEUES ||
	    start >= nr_queues || loop_ctx->local_queue >= nr_queues || cpu < 0 ||
	    cpu >= nr_cpu_ids || cpu >= SNAKE_MAX_CPUS || offset >= nr_queues)
		return 1;
	index = (start + offset) % nr_queues;
	if (index >= SNAKE_MAX_NORMAL_QUEUES)
		return 1;
	if (index == loop_ctx->local_queue)
		return 0;

	dsq = dsq_normal(index);
	loop_ctx->candidate.dsq = dsq;
	loop_ctx->next_remote_queue = index + 1;
	if (loop_ctx->next_remote_queue >= nr_queues)
		loop_ctx->next_remote_queue = 0;
	nr_queued = dsq_nr_queued(dsq);
	if (nr_queued < 0) {
		loop_ctx->result = nr_queued;
		return 1;
	}
	if (!nr_queued)
		return 0;
	/* Keep validity binary; a moved sentinel exhausts Linux 7.1 states. */
	bpf_rcu_read_lock();
	p = dsq_peek_vtime(dsq, &loop_ctx->candidate.vtime);
	if (p) {
		task = bpf_task_from_pid(p->pid);
		if (task) {
			eligible = bpf_cpumask_test_cpu(cpu, task->cpus_ptr);
			bpf_task_release(task);
		}
	}
	if (eligible) {
		loop_ctx->candidate.valid = 1;
		bpf_rcu_read_unlock();
		return 1;
	}
	bpf_rcu_read_unlock();
	return 0;
}

static __always_inline int
queue_dispatch_peek_remote(struct snake_ladder_ctx	*ctx,
			   struct snake_cpu_queue	*cpuq,
			   struct snake_queue_cpu_state *state, s32 cpu,
			   struct snake_queue_candidate *candidate)
{
	struct snake_queue_header	 *header = queue_config(ctx);
	struct snake_remote_scan_loop_ctx loop_ctx;
	u32				  nr_queues, start;
	long				  nr_loops;

	if (!candidate || !cpuq || !state || !header ||
	    header->mode != SNAKE_QUEUE_MODE_GLOBAL || cpu < 0 ||
	    cpu >= nr_cpu_ids || cpu >= SNAKE_MAX_CPUS)
		return -EINVAL;
	*candidate = (struct snake_queue_candidate){
		.dsq   = dsq_invalid(),
		.class = SNAKE_QUEUE_CLASS_NORMAL,
	};
	nr_queues = header->nr_normal_queues;
	if (nr_queues <= 1)
		return 0;
	if (nr_queues > SNAKE_MAX_NORMAL_QUEUES ||
	    cpuq->normal_queue_index >= nr_queues)
		return -EINVAL;
	start = state->next_remote_queue;
	if (start >= nr_queues)
		start = 0;
	loop_ctx = (struct snake_remote_scan_loop_ctx){
		.candidate	   = *candidate,
		.local_queue	   = cpuq->normal_queue_index,
		.start		   = start,
		.nr_queues	   = nr_queues,
		.next_remote_queue = start,
		.cpu		   = cpu,
	};
	nr_loops = bpf_loop(SNAKE_MAX_NORMAL_QUEUES,
			    queue_dispatch_remote_scan_callback, &loop_ctx, 0);
	if (nr_loops < 0)
		return nr_loops;
	if (loop_ctx.result < 0)
		return loop_ctx.result;
	state->next_remote_queue = loop_ctx.next_remote_queue;
	*candidate = loop_ctx.candidate;
	return 0;
}

static __always_inline bool
queue_global_move(struct snake_ladder_ctx *ctx, u64 source_dsq, u32 class)
{
	dsq_id_t source = { .raw = source_dsq };

	if (dsq_is_invalid(source) || !dsq_move_to_local_untimed(source))
		return false;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return true;
}

static __always_inline int queue_global_replenish(
	struct snake_ladder_ctx *ctx, struct task_struct *prev)
{
	struct snake_task_runtime *runtime;
	u32 weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	weight = runtime && runtime->runtime_valid ? runtime->active_weight :
						 fairness_task_weight(prev);
	fairness_vtime_replenish(runtime, prev, weight);
	return 0;
}

struct snake_global_consume_args {
	struct task_struct *prev;
	struct snake_queue_cpu_state *state;
	struct snake_queue_candidate *cpu_candidate;
	struct snake_queue_candidate *local_candidate;
	struct snake_queue_candidate *remote_candidate;
	u64 fallback;
	s32 cpu;
	u32 consume_rung;
};

enum snake_global_dispatch_result {
	SNAKE_GLOBAL_DISPATCH_MISS = 0,
	SNAKE_GLOBAL_DISPATCH_KEEP_RUNNING,
	SNAKE_GLOBAL_DISPATCH_TRANSFER_CPU,
	SNAKE_GLOBAL_DISPATCH_TRANSFER_LOCAL,
	SNAKE_GLOBAL_DISPATCH_TRANSFER_REMOTE,
};

static __noinline s32 queue_dispatch_try_selected(
	struct snake_ladder_ctx *ctx,
	const struct snake_global_consume_args *args, u32 source)
{
	struct snake_queue_candidate *candidate;
	u32 class, rung;
	s32 cpu;

	if (!ctx || !args)
		return -EINVAL;
	if (source == SNAKE_QUEUE_INPUT_CPU) {
		candidate = args->cpu_candidate;
		class = SNAKE_QUEUE_CLASS_AFFINITY;
		rung = 0;
	} else if (source == SNAKE_QUEUE_INPUT_LOCAL) {
		candidate = args->local_candidate;
		class = SNAKE_QUEUE_CLASS_NORMAL;
		rung = 1;
	} else if (source == SNAKE_QUEUE_INPUT_REMOTE) {
		candidate = args->remote_candidate;
		class = SNAKE_QUEUE_CLASS_NORMAL;
		rung = 2;
	} else {
		return -EINVAL;
	}
	cpu = args->cpu;
	if (!candidate || cpu < 0 || cpu >= nr_cpu_ids ||
	    cpu >= SNAKE_MAX_CPUS)
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE + rung);
	if (fairness_vtime_keep_running(ctx, args->prev, candidate->vtime))
		return SNAKE_GLOBAL_DISPATCH_KEEP_RUNNING;
	if (queue_global_move(ctx, candidate->dsq.raw, class))
		return source + SNAKE_GLOBAL_DISPATCH_KEEP_RUNNING;
	return SNAKE_GLOBAL_DISPATCH_MISS;
}

struct snake_global_fallback_candidate {
	u64 dsq;
	u32 rung;
};

struct snake_global_fallback_loop_ctx {
	struct snake_ladder_ctx ladder_ctx;
	struct snake_global_fallback_candidate cpu_candidate;
	struct snake_global_fallback_candidate local_candidate;
	struct snake_global_fallback_candidate remote_candidate;
	u64 fallback;
	s32 cpu;
	s32 result;
};

static __noinline long queue_dispatch_try_cpu_fallback(
	struct snake_global_fallback_loop_ctx *loop_ctx)
{
	struct snake_global_fallback_candidate *candidate =
		&loop_ctx->cpu_candidate;
	s32 cpu = loop_ctx->cpu;

	if (candidate->rung >= 3 || cpu < 0 || cpu >= nr_cpu_ids ||
	    cpu >= SNAKE_MAX_CPUS) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + candidate->rung);
	if (queue_global_move(&loop_ctx->ladder_ctx, candidate->dsq,
			      SNAKE_QUEUE_CLASS_AFFINITY)) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + candidate->rung);
		loop_ctx->result = SNAKE_GLOBAL_DISPATCH_TRANSFER_CPU;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + candidate->rung);
	return 0;
}

static __noinline long queue_dispatch_try_local_fallback(
	struct snake_global_fallback_loop_ctx *loop_ctx)
{
	struct snake_global_fallback_candidate *candidate =
		&loop_ctx->local_candidate;
	s32 cpu = loop_ctx->cpu;

	if (candidate->rung >= 3 || cpu < 0 || cpu >= nr_cpu_ids ||
	    cpu >= SNAKE_MAX_CPUS) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + candidate->rung);
	if (queue_global_move(&loop_ctx->ladder_ctx, candidate->dsq,
			      SNAKE_QUEUE_CLASS_NORMAL)) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + candidate->rung);
		loop_ctx->result = SNAKE_GLOBAL_DISPATCH_TRANSFER_LOCAL;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + candidate->rung);
	return 0;
}

static __noinline long queue_dispatch_try_remote_fallback(
	struct snake_global_fallback_loop_ctx *loop_ctx)
{
	struct snake_global_fallback_candidate *candidate =
		&loop_ctx->remote_candidate;
	s32 cpu = loop_ctx->cpu;

	if (candidate->rung >= 3 || cpu < 0 || cpu >= nr_cpu_ids ||
	    cpu >= SNAKE_MAX_CPUS) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + candidate->rung);
	if (queue_global_move(&loop_ctx->ladder_ctx, candidate->dsq,
			      SNAKE_QUEUE_CLASS_NORMAL)) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + candidate->rung);
		loop_ctx->result = SNAKE_GLOBAL_DISPATCH_TRANSFER_REMOTE;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + candidate->rung);
	return 0;
}

static long queue_dispatch_fallback_callback(
	u32 offset, struct snake_global_fallback_loop_ctx *loop_ctx)
{
	u32 source;

	if (offset >= SNAKE_DISPATCH_FALLBACK_MAX)
		return 1;
	source = (loop_ctx->fallback >>
		  (offset * SNAKE_DISPATCH_FALLBACK_BITS)) &
		 SNAKE_DISPATCH_FALLBACK_MASK;
	if (source == SNAKE_DISPATCH_FALLBACK_CPU)
		return queue_dispatch_try_cpu_fallback(loop_ctx);
	if (source == SNAKE_DISPATCH_FALLBACK_LOCAL)
		return queue_dispatch_try_local_fallback(loop_ctx);
	if (source == SNAKE_DISPATCH_FALLBACK_REMOTE)
		return queue_dispatch_try_remote_fallback(loop_ctx);
	loop_ctx->result = -EINVAL;
	return 1;
}

static __always_inline s32 queue_dispatch_try_fallbacks(
	struct snake_ladder_ctx *ctx,
	const struct snake_global_consume_args *args)
{
	struct snake_global_fallback_loop_ctx loop_ctx;
	long nr_loops;

	if (!args->cpu_candidate || !args->local_candidate ||
	    !args->remote_candidate)
		return -EINVAL;
	loop_ctx = (struct snake_global_fallback_loop_ctx){
		.ladder_ctx = *ctx,
		.cpu_candidate = {
			.dsq = args->cpu_candidate->dsq.raw,
			.rung = 0,
		},
		.local_candidate = {
			.dsq = args->local_candidate->dsq.raw,
			.rung = 1,
		},
		.remote_candidate = {
			.dsq = args->remote_candidate->dsq.raw,
			.rung = 2,
		},
		.fallback = args->fallback,
		.cpu = args->cpu,
	};
	nr_loops = bpf_loop(SNAKE_DISPATCH_FALLBACK_MAX,
			    queue_dispatch_fallback_callback, &loop_ctx, 0);
	if (nr_loops < 0)
		return nr_loops;
	return loop_ctx.result;
}

static __noinline s32 queue_dispatch_consume_min_vtime(
	struct snake_ladder_ctx *ctx,
	const struct snake_global_consume_args *args)
{
	u64  min_vtime = 0;
	u64  cpu_vtime = 0, local_vtime = 0, remote_vtime = 0;
	u32  preference, winner_source = SNAKE_QUEUE_INPUT_INVALID;
	u32  nr_min    = 0;
	bool cpu_valid = args->cpu_candidate && args->cpu_candidate->valid != 0;
	bool local_valid = args->local_candidate &&
			   args->local_candidate->valid != 0;
	bool remote_valid = args->remote_candidate &&
			    args->remote_candidate->valid != 0;
	bool found = false;

	if (cpu_valid) {
		cpu_vtime = args->cpu_candidate->vtime;
		min_vtime = cpu_vtime;
		found	  = true;
	}
	if (local_valid) {
		local_vtime = args->local_candidate->vtime;
	}
	if (local_valid && (!found || time_before(local_vtime, min_vtime))) {
		min_vtime = local_vtime;
		found = true;
	}
	if (remote_valid) {
		remote_vtime = args->remote_candidate->vtime;
	}
	if (remote_valid && (!found || time_before(remote_vtime, min_vtime))) {
		min_vtime = remote_vtime;
		found = true;
	}
	if (found) {
		if (cpu_valid && cpu_vtime == min_vtime)
			nr_min++;
		if (local_valid && local_vtime == min_vtime)
			nr_min++;
		if (remote_valid && remote_vtime == min_vtime)
			nr_min++;
		if (nr_min > 1)
			stat_inc(ctx, SNAKE_STAT_VTIME_EQUAL_HEAD_TIES);
		preference = args->state->next_equal_source;
		if (preference < SNAKE_QUEUE_INPUT_CPU ||
		    preference > SNAKE_QUEUE_INPUT_REMOTE)
			preference = SNAKE_QUEUE_INPUT_CPU;
		if (preference == SNAKE_QUEUE_INPUT_CPU) {
			if (cpu_valid && cpu_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_CPU;
			else if (local_valid && local_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_LOCAL;
			else
				winner_source = SNAKE_QUEUE_INPUT_REMOTE;
		} else if (preference == SNAKE_QUEUE_INPUT_LOCAL) {
			if (local_valid && local_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_LOCAL;
			else if (remote_valid && remote_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_REMOTE;
			else
				winner_source = SNAKE_QUEUE_INPUT_CPU;
		} else {
			if (remote_valid && remote_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_REMOTE;
			else if (cpu_valid && cpu_vtime == min_vtime)
				winner_source = SNAKE_QUEUE_INPUT_CPU;
			else
				winner_source = SNAKE_QUEUE_INPUT_LOCAL;
		}
		args->state->next_equal_source = winner_source + 1;
		if (args->state->next_equal_source > SNAKE_QUEUE_INPUT_REMOTE)
			args->state->next_equal_source = SNAKE_QUEUE_INPUT_CPU;
		{
			s32 ret = queue_dispatch_try_selected(ctx, args, winner_source);

			if (ret)
				return ret;
		}
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE +
				      args->consume_rung);
	}

	{
		s32 ret = queue_dispatch_try_fallbacks(ctx, args);

		if (ret)
			return ret;
	}
	queue_global_replenish(ctx, args->prev);
	return 0;
}

/* Keep shared ladder state and fixed rung metadata out of this stack frame. */
struct snake_global_dispatch_loop_ctx {
	struct task_struct *prev;
	struct snake_queue_cpu_state *state;
	struct snake_cpu_queue *cpuq;
	struct snake_queue_candidate cpu_candidate;
	struct snake_queue_candidate local_candidate;
	struct snake_queue_candidate remote_candidate;
	s32 cpu;
	u64 callback_started_at;
};

static __noinline s32 queue_global_dispatch_peek_rung(
	struct snake_ladder_ctx *ctx,
	struct snake_global_dispatch_loop_ctx *loop_ctx, u32 index)
{
	const struct snake_queue_rung *rung;
	bool hit = false;
	s32 ret;
	u64 rung_started_at;

	if (index >= 3 || index >= ctx->ladder->nr_dispatch_rungs)
		return -EINVAL;
	rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [index]);
	if (!rung)
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + index);
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	if (rung->opcode != SNAKE_DISPATCH_OP_PEEK) {
		ret = -EINVAL;
	} else if (index == 0) {
		if (rung->input != SNAKE_QUEUE_INPUT_CPU) {
			ret = -EINVAL;
		} else {
			ret = queue_dispatch_peek_cpu(loop_ctx->cpu,
						      &loop_ctx->cpu_candidate);
			hit = loop_ctx->cpu_candidate.valid;
		}
	} else if (index == 1) {
		if (rung->input != SNAKE_QUEUE_INPUT_LOCAL) {
			ret = -EINVAL;
		} else {
			ret = queue_dispatch_peek_local(
				loop_ctx->cpuq, &loop_ctx->local_candidate);
			hit = loop_ctx->local_candidate.valid;
		}
	} else if (index == 2) {
		if (rung->input != SNAKE_QUEUE_INPUT_REMOTE) {
			ret = -EINVAL;
		} else {
			ret = queue_dispatch_peek_remote(
				ctx, loop_ctx->cpuq, loop_ctx->state, loop_ctx->cpu,
				&loop_ctx->remote_candidate);
			hit = loop_ctx->remote_candidate.valid;
		}
	} else {
		ret = -EINVAL;
	}
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, index,
			   rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + index);
		return ret;
	}
	stat_inc(ctx,
		 (hit ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
			SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
		 index);
	return 0;
}

static __noinline s32 queue_global_dispatch_consume_rung(
	struct snake_ladder_ctx *ctx,
	struct snake_global_dispatch_loop_ctx *loop_ctx, u32 index)
{
	const struct snake_queue_rung *rung;
	struct snake_global_consume_args args;
	s32 ret;
	u64 rung_started_at;

	if (index != 3 || index >= ctx->ladder->nr_dispatch_rungs)
		return -EINVAL;
	rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [index]);
	if (!rung)
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + index);
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	if (rung->opcode != SNAKE_DISPATCH_OP_CONSUME ||
	    rung->input != SNAKE_QUEUE_INPUT_MIN_VTIME) {
		ret = -EINVAL;
	} else {
		args = (struct snake_global_consume_args){
			.prev = loop_ctx->prev,
			.state = loop_ctx->state,
			.cpu_candidate = &loop_ctx->cpu_candidate,
			.local_candidate = &loop_ctx->local_candidate,
			.remote_candidate = &loop_ctx->remote_candidate,
			.fallback = rung->data,
			.cpu = loop_ctx->cpu,
			.consume_rung = index,
		};
		ret = queue_dispatch_consume_min_vtime(ctx, &args);
	}
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, index,
			   rung_started_at);
	if (ret < 0) {
		stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + index);
		return ret;
	}
	stat_inc(ctx,
		 (ret ? SNAKE_STAT_DISPATCH_RUNG_HIT_BASE :
			SNAKE_STAT_DISPATCH_RUNG_MISS_BASE) +
		 index);
	return ret;
}

static __noinline int queue_global_ladder_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	struct snake_queue_cpu_state *state,
	u64 callback_started_at)
{
	struct snake_cpu_queue *cpuq = queue_cpu(ctx, cpu);
	struct snake_global_dispatch_loop_ctx loop_ctx = {
		.prev = prev,
		.state = state,
		.cpuq = cpuq,
		.cpu = cpu,
		.callback_started_at = callback_started_at,
	};
	s32 ret;

	if (!cpuq || ctx->ladder->nr_dispatch_rungs != 4)
		return -EINVAL;
	ret = queue_global_dispatch_peek_rung(ctx, &loop_ctx, 0);
	if (ret)
		return ret;
	ret = queue_global_dispatch_peek_rung(ctx, &loop_ctx, 1);
	if (ret)
		return ret;
	ret = queue_global_dispatch_peek_rung(ctx, &loop_ctx, 2);
	if (ret)
		return ret;
	ret = queue_global_dispatch_consume_rung(ctx, &loop_ctx, 3);
	if (ret == SNAKE_GLOBAL_DISPATCH_TRANSFER_CPU)
		fine_timing_record_dispatch_transfer(
			callback_started_at, loop_ctx.cpu_candidate.dsq.raw,
			dsq_local_on(cpu).raw, SNAKE_QUEUE_CLASS_AFFINITY);
	else if (ret == SNAKE_GLOBAL_DISPATCH_TRANSFER_LOCAL)
		fine_timing_record_dispatch_transfer(
			callback_started_at, loop_ctx.local_candidate.dsq.raw,
			dsq_local_on(cpu).raw, SNAKE_QUEUE_CLASS_NORMAL);
	else if (ret == SNAKE_GLOBAL_DISPATCH_TRANSFER_REMOTE)
		fine_timing_record_dispatch_transfer(
			callback_started_at, loop_ctx.remote_candidate.dsq.raw,
			dsq_local_on(cpu).raw, SNAKE_QUEUE_CLASS_NORMAL);
	return ret < 0 ? ret : 0;
}

struct snake_queue_dispatch_loop_ctx {
	struct snake_ladder_ctx	     ladder_ctx;
	struct task_struct	    *prev;
	struct snake_fine_timing_ctx fine;
	s32			     cpu;
	s32			     result;
	u64			     callback_started_at;
};

static long
queue_ladder_dispatch_callback(u32				     step,
			       struct snake_queue_dispatch_loop_ctx *loop_ctx)
{
	const struct snake_queue_rung *rung;
	struct snake_queue_cpu_state  *state;
	struct snake_cpu_queue	      *cpuq;
	u32			       key = 0;
	u32			       index;
	s32			       result;
	u64			       rung_started_at;

	if (step >= SNAKE_MAX_QUEUE_RUNGS ||
	    step >= loop_ctx->ladder_ctx.ladder->nr_dispatch_rungs)
		return 1;
	cpuq = queue_cpu(&loop_ctx->ladder_ctx, loop_ctx->cpu);
	if (!cpuq) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	state = bpf_map_lookup_elem(&queue_cpu_states, &key);
	if (!state) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	index = state->next_dispatch_rung + step;
	if (index >= loop_ctx->ladder_ctx.ladder->nr_dispatch_rungs)
		index -= loop_ctx->ladder_ctx.ladder->nr_dispatch_rungs;
	rung = MEMBER_VPTR(
		loop_ctx->ladder_ctx.ladder->dispatch_rungs, [index]);
	if (!rung) {
		loop_ctx->result = -EINVAL;
		return 1;
	}
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + index);
	result = queue_fairness_dispatch_source(&loop_ctx->ladder_ctx, cpuq,
						loop_ctx->cpu, loop_ctx->prev,
						rung->opcode, &loop_ctx->fine);
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_DISPATCH,
			   index, rung_started_at);
	if (result < 0) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + index);
		loop_ctx->result = result;
		return 1;
	}
	if (!result) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_DISPATCH_RUNG_MISS_BASE + index);
		return 0;
	}
	stat_inc(&loop_ctx->ladder_ctx,
		 SNAKE_STAT_DISPATCH_RUNG_HIT_BASE + index);
	index++;
	if (index >= loop_ctx->ladder_ctx.ladder->nr_dispatch_rungs)
		index = 0;
	state->next_dispatch_rung = index;
	loop_ctx->result	  = result;
	return 1;
}

static __always_inline int queue_ladder_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	struct snake_queue_cpu_state	    *state;
	struct snake_cpu_queue		    *cpuq;
	struct snake_queue_dispatch_loop_ctx loop_ctx;
	u32				     key = 0;
	s32				     local_queued;
	u64				     stage_started_at;
	long				     nr_loops;

	stage_started_at = fine_timing_start(fine);
	cpuq		 = queue_cpu(ctx, cpu);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ROUTE_LOOKUP,
			   stage_started_at);
	if (!cpuq)
		return -EINVAL;
	stage_started_at = fine_timing_start(fine);
	local_queued	 = dsq_nr_queued(dsq_local_on(cpu));
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_LOCAL_DSQ_CHECK,
			   stage_started_at);
	if (local_queued < 0)
		return local_queued;
	if (local_queued > 0)
		return 0;
	stage_started_at = fine_timing_start(fine);
	state		 = bpf_map_lookup_elem(&queue_cpu_states, &key);
	if (!state) {
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_DISPATCH_STATE_LOOKUP,
				   stage_started_at);
		return -EINVAL;
	}
	if (!state->initialized ||
	    state->generation != ctx->ladder->generation ||
	    state->next_dispatch_rung >= ctx->ladder->nr_dispatch_rungs) {
		state->generation	  = ctx->ladder->generation;
		state->next_dispatch_rung = 0;
		state->next_equal_class	  = SNAKE_QUEUE_CLASS_NORMAL;
		state->next_remote_queue  = cpuq->normal_queue_index + 1;
		state->next_equal_source  = SNAKE_QUEUE_INPUT_CPU;
		state->initialized	  = 1;
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_STATE_LOOKUP,
			   stage_started_at);
	if (queue_global_mode_enabled())
		return queue_global_ladder_dispatch(ctx, cpu, prev, state,
						    callback_started_at);
	if (ctx->ladder->nr_dispatch_rungs == 5) {
		const struct snake_queue_rung *first =
			MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);

		if (first && first->opcode == SNAKE_DISPATCH_OP_DRAIN &&
		    first->input == SNAKE_QUEUE_INPUT_CELL_ORPHAN)
			return queue_mitosis_expanded_dispatch(
				ctx, cpu, prev, fine, callback_started_at);
	}
	if (ctx->ladder->nr_dispatch_rungs == 3) {
		const struct snake_queue_rung *first =
			MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);

		if (first && first->opcode == SNAKE_DISPATCH_OP_PEEK &&
		    first->input == SNAKE_QUEUE_INPUT_CELL)
			return queue_mitosis_ladder_dispatch(
				ctx, cpu, prev, fine, callback_started_at);
	}
	if (ctx->ladder->nr_dispatch_rungs == 1) {
		const struct snake_queue_rung *only =
			MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);
		struct snake_queue_dispatch_min_args args;
		s32				     result;
		u64				     rung_started_at;

		if (!only)
			return -EINVAL;
		if (only->opcode == SNAKE_DISPATCH_OP_MIN_VTIME) {
			stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE);
			args = (struct snake_queue_dispatch_min_args){
				.fine		  = fine,
				.equal_preference = &state->next_equal_class,
				.cpu		  = cpu,
			};
			rung_started_at =
				rung_timing_start(callback_started_at);
			result = queue_fairness_dispatch_min(ctx, cpuq, prev,
							     &args);
			rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 0,
					   rung_started_at);
			if (result < 0)
				stat_inc(ctx,
					 SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE);
			if (result < 0)
				return result;
			if (result) {
				stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_HIT_BASE);
				return 0;
			}
			stat_inc(ctx, SNAKE_STAT_DISPATCH_RUNG_MISS_BASE);
			stage_started_at = fine_timing_start(fine);
			result = queue_fairness_replenish(ctx, cpuq, prev);
			fine_timing_finish(fine,
					   SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
					   stage_started_at);
			return result;
		}
	}
	loop_ctx = (struct snake_queue_dispatch_loop_ctx){
		.ladder_ctx = *ctx,
		.prev	    = prev,
		.fine	    = fine ? *fine : (struct snake_fine_timing_ctx){},
		.cpu	    = cpu,
		.result	    = 0,
		.callback_started_at = callback_started_at,
	};
	nr_loops = bpf_loop(SNAKE_MAX_QUEUE_RUNGS,
			    queue_ladder_dispatch_callback, &loop_ctx, 0);
	if (nr_loops < 0) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return nr_loops;
	}
	if (loop_ctx.result < 0)
		return loop_ctx.result;
	if (loop_ctx.result > 0)
		return 0;
	stage_started_at = fine_timing_start(fine);
	local_queued	 = queue_fairness_replenish(ctx, cpuq, prev);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
			   stage_started_at);
	return local_queued;
}

#endif /* __SCX_SNAKE_QUEUE_DISPATCH_H */
