/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_LADDER_H
#define __SCX_SNAKE_QUEUE_LADDER_H

static __always_inline int
validate_queue_ladders(const struct snake_compiled_ladder *ladder)
{
	bool enqueue_cell = false, enqueue_affinity = false;
	bool dispatch_cell = false, dispatch_affinity = false, dispatch_min = false;
	u32  i;

	if (!queue_topology_enabled())
		return ladder->nr_enqueue_rungs || ladder->nr_dispatch_rungs ?
			       -EINVAL :
			       0;
	if (!ladder->nr_enqueue_rungs ||
	    ladder->nr_enqueue_rungs > SNAKE_MAX_QUEUE_RUNGS ||
	    !ladder->nr_dispatch_rungs ||
	    ladder->nr_dispatch_rungs > SNAKE_MAX_QUEUE_RUNGS)
		return -EINVAL;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;

		if (i >= ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ladder->enqueue_rungs, [i]);
		if (!rung || rung->flags)
			return -EINVAL;
		if (rung->opcode == SNAKE_ENQUEUE_OP_CELL) {
			if (enqueue_cell)
				return -EINVAL;
			enqueue_cell = true;
		} else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY) {
			if (enqueue_affinity || i + 1 != ladder->nr_enqueue_rungs)
				return -EINVAL;
			enqueue_affinity = true;
		} else {
			return -EINVAL;
		}
	}
	if (!enqueue_affinity)
		return -EINVAL;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;

		if (i >= ladder->nr_dispatch_rungs)
			break;
		rung = MEMBER_VPTR(ladder->dispatch_rungs, [i]);
		if (!rung || rung->flags)
			return -EINVAL;
		if (rung->opcode == SNAKE_DISPATCH_OP_CELL) {
			if (dispatch_cell || dispatch_min)
				return -EINVAL;
			dispatch_cell = true;
		} else if (rung->opcode == SNAKE_DISPATCH_OP_AFFINITY) {
			if (dispatch_affinity || dispatch_min)
				return -EINVAL;
			dispatch_affinity = true;
		} else if (rung->opcode == SNAKE_DISPATCH_OP_MIN_VTIME) {
			if (dispatch_cell || dispatch_affinity || dispatch_min ||
			    ladder->nr_dispatch_rungs != 1)
				return -EINVAL;
			dispatch_cell = true;
			dispatch_affinity = true;
			dispatch_min = true;
		} else {
			return -EINVAL;
		}
	}
	if (!dispatch_affinity || enqueue_cell != dispatch_cell)
		return -EINVAL;
	return 0;
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
	runtime = queue_fairness_prepare_runnable(ctx, p, fine);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_RUNNABLE,
			   stage_started_at);
	if (!runtime)
		return -EINVAL;
	selected_cpu = task_route_take_selected_cpu(runtime, p);

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;
		s32			      ret;
		u64			      rung_started_at;

		if (i >= ctx->ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ctx->ladder->enqueue_rungs, [i]);
		if (!rung)
			return -EINVAL;
		rung_started_at = rung_timing_start(callback_started_at);
		if (rung->opcode == SNAKE_ENQUEUE_OP_CELL)
			ret = queue_fairness_enqueue_cell(ctx, p, runtime,
						  selected_cpu, enq_flags, fine);
		else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY)
			ret = queue_fairness_enqueue_affinity(ctx, p, runtime,
						      selected_cpu, enq_flags,
						      fine);
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

static __always_inline int
queue_ladder_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
		      struct task_struct *prev,
		      const struct snake_fine_timing_ctx *fine,
		      u64 callback_started_at)
{
	struct snake_queue_cpu_state *state;
	struct snake_cpu_queue       *cpuq;
	u32			      key = 0, step, start;
	s32			      local_queued;
	u64			      stage_started_at;

	stage_started_at = fine_timing_start(fine);
	cpuq = queue_cpu(cpu);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ROUTE_LOOKUP,
			   stage_started_at);
	if (!cpuq)
		return -EINVAL;
	stage_started_at = fine_timing_start(fine);
	local_queued = dsq_nr_queued(dsq_local_on(cpu));
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_LOCAL_DSQ_CHECK,
			   stage_started_at);
	if (local_queued < 0)
		return local_queued;
	if (local_queued > 0)
		return 0;
	stage_started_at = fine_timing_start(fine);
	state = bpf_map_lookup_elem(&queue_cpu_states, &key);
	if (!state) {
		fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_STATE_LOOKUP,
				   stage_started_at);
		return -EINVAL;
	}
	if (!state->initialized || state->generation != ctx->ladder->generation ||
	    state->next_dispatch_rung >= ctx->ladder->nr_dispatch_rungs) {
		state->generation = ctx->ladder->generation;
		state->next_dispatch_rung = 0;
		state->next_equal_class = SNAKE_QUEUE_CLASS_NORMAL;
		state->initialized = 1;
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
			rung_started_at = rung_timing_start(callback_started_at);
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
		u32			      index;
		s32			      result;
		u64			      rung_started_at;

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
	local_queued = queue_fairness_replenish(ctx, cpuq, prev);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
			   stage_started_at);
	return local_queued;
}

#endif /* __SCX_SNAKE_QUEUE_LADDER_H */
