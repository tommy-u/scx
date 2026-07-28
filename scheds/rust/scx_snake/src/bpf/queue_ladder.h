/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_LADDER_H
#define __SCX_SNAKE_QUEUE_LADDER_H

static __always_inline int
validate_queue_ladders(const struct snake_compiled_ladder *ladder)
{
	bool enqueue_cell = false, enqueue_affinity = false;
	bool dispatch_cell = false, dispatch_affinity = false;
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
			if (dispatch_cell)
				return -EINVAL;
			dispatch_cell = true;
		} else if (rung->opcode == SNAKE_DISPATCH_OP_AFFINITY) {
			if (dispatch_affinity)
				return -EINVAL;
			dispatch_affinity = true;
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
		     u64 enq_flags)
{
	struct snake_task_runtime *runtime;
	s32			   selected_cpu = -1;
	u32			   i;

	runtime = queue_fairness_prepare_runnable(ctx, p);
	if (!runtime)
		return -EINVAL;
	if (runtime->selected_cpu_valid && runtime->selected_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(runtime->selected_cpu, p->cpus_ptr))
		selected_cpu = runtime->selected_cpu;
	runtime->selected_cpu_valid = 0;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;
		s32			      ret;

		if (i >= ctx->ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ctx->ladder->enqueue_rungs, [i]);
		if (!rung)
			return -EINVAL;
		if (rung->opcode == SNAKE_ENQUEUE_OP_CELL)
			ret = queue_fairness_enqueue_cell(ctx, p, runtime,
						  selected_cpu, enq_flags);
		else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY)
			ret = queue_fairness_enqueue_affinity(ctx, p, runtime,
						      selected_cpu, enq_flags);
		else
			return -EINVAL;
		if (!ret)
			return 0;
		if (ret != -ENOENT)
			return ret;
	}
	return -ENOENT;
}

static __always_inline int
queue_ladder_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
		      struct task_struct *prev)
{
	struct snake_queue_cpu_state *state;
	struct snake_cpu_queue       *cpuq;
	u32			      key = 0, step, start;
	s32			      local_queued;

	cpuq = queue_cpu(cpu);
	if (!cpuq)
		return -EINVAL;
	local_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
	if (local_queued < 0)
		return local_queued;
	if (local_queued > 0)
		return 0;
	state = bpf_map_lookup_elem(&queue_cpu_states, &key);
	if (!state)
		return -EINVAL;
	if (!state->initialized || state->generation != ctx->ladder->generation ||
	    state->next_dispatch_rung >= ctx->ladder->nr_dispatch_rungs) {
		state->generation = ctx->ladder->generation;
		state->next_dispatch_rung = 0;
		state->initialized = 1;
	}
	start = state->next_dispatch_rung;

	bpf_for(step, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;
		u32			      index;
		s32			      result;

		if (step >= ctx->ladder->nr_dispatch_rungs)
			break;
		index = start + step;
		if (index >= ctx->ladder->nr_dispatch_rungs)
			index -= ctx->ladder->nr_dispatch_rungs;
		rung = MEMBER_VPTR(ctx->ladder->dispatch_rungs, [index]);
		if (!rung)
			return -EINVAL;
		result = queue_fairness_dispatch_source(ctx, cpuq, cpu, prev,
							 rung->opcode);
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
	queue_fairness_replenish(prev);
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_LADDER_H */
