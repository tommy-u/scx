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

	bpf_for(offset, 0, SNAKE_MAX_NORMAL_QUEUES)
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

static __always_inline bool
queue_fairness_move(struct snake_ladder_ctx *ctx, dsq_id_t dsq, s32 cpu,
		    u32 class, const struct snake_fine_timing_ctx *fine)
{
	bool moved = dsq_move_to_local(dsq, cpu, fine);

	if (!moved)
		return false;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return true;
}

struct snake_queue_candidate {
	dsq_id_t dsq;
	u64	 vtime;
	u32 class;
	u32 valid;
};

static __always_inline int
queue_fairness_normal_candidate(struct snake_cpu_queue		   *cpuq,
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
	cell		 = queue_cell(cpuq->owner_cell_index);
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
	if (!candidate || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	candidate->valid = 0;
	candidate->dsq	 = dsq_affinity(cpu);
	if (!dsq_vtime_head(candidate->dsq, &candidate->vtime))
		return 0;
	candidate->class = SNAKE_QUEUE_CLASS_AFFINITY;
	candidate->valid = 1;
	return 0;
}

static __always_inline s32 queue_fairness_keep_running(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq,
	struct task_struct *prev, u32 class, u64 candidate_vtime)
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
	if (queue_fairness_rehome_pending(prev, runtime)) {
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
	if (queue_fairness_rehome_pending(prev, runtime)) {
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

static __always_inline s32 queue_fairness_dispatch_min(
	struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq, s32 cpu,
	struct task_struct *prev, u32 *equal_preference,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_candidate  normal = {}, affinity = {};
	struct snake_queue_candidate *winner, *loser;
	s32			      keep, ret;
	u64			      stage_started_at;

	if (!equal_preference)
		return -EINVAL;
	ret = queue_fairness_normal_candidate(cpuq, &normal, fine);
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
	if (ret)
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
	return ret ? 1 : 0;
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
		cell = queue_cell(cpuq->owner_cell_index);
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
	return keep ? 1 : 0;
}

static __always_inline int queue_ladder_dispatch(
	struct snake_ladder_ctx *ctx, s32 cpu, struct task_struct *prev,
	const struct snake_fine_timing_ctx *fine, u64 callback_started_at)
{
	struct snake_queue_cpu_state *state;
	struct snake_cpu_queue	     *cpuq;
	u32			      key = 0, step, start;
	s32			      local_queued;
	u64			      stage_started_at;

	stage_started_at = fine_timing_start(fine);
	cpuq		 = queue_cpu(cpu);
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
		state->initialized	  = 1;
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_STATE_LOOKUP,
			   stage_started_at);
	if (ctx->ladder->nr_dispatch_rungs == 1) {
		const struct snake_queue_rung *only =
			MEMBER_VPTR(ctx->ladder->dispatch_rungs, [0]);
		s32 result;
		u64 rung_started_at;

		if (!only)
			return -EINVAL;
		if (only->opcode == SNAKE_DISPATCH_OP_MIN_VTIME) {
			rung_started_at =
				rung_timing_start(callback_started_at);
			result = queue_fairness_dispatch_min(
				ctx, cpuq, cpu, prev, &state->next_equal_class,
				fine);
			rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, 0,
					   rung_started_at);
			if (result < 0)
				return result;
			if (result)
				return 0;
			stage_started_at = fine_timing_start(fine);
			result = queue_fairness_replenish(ctx, cpuq, prev);
			fine_timing_finish(fine,
					   SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
					   stage_started_at);
			return result;
		}
	}
	start = state->next_dispatch_rung;

	bpf_for(step, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;
		u32			       index;
		s32			       result;
		u64			       rung_started_at;

		if (step >= ctx->ladder->nr_dispatch_rungs)
			break;
		index = start + step;
		if (index >= ctx->ladder->nr_dispatch_rungs)
			index -= ctx->ladder->nr_dispatch_rungs;
		rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [index]);
		if (!rung)
			return -EINVAL;
		rung_started_at = rung_timing_start(callback_started_at);
		result = queue_fairness_dispatch_source(ctx, cpuq, cpu, prev,
							rung->opcode, fine);
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_DISPATCH, index,
				   rung_started_at);
		if (result < 0)
			return result;
		if (!result)
			continue;
		index++;
		if (index >= ctx->ladder->nr_dispatch_rungs)
			index = 0;
		state->next_dispatch_rung = index;
		return 0;
	}
	stage_started_at = fine_timing_start(fine);
	local_queued	 = queue_fairness_replenish(ctx, cpuq, prev);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
			   stage_started_at);
	return local_queued;
}

#endif /* __SCX_SNAKE_QUEUE_DISPATCH_H */
