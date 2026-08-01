/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_FAIRNESS_H
#define __SCX_SNAKE_QUEUE_FAIRNESS_H

#include "cpu_pick.h"
#include "queue_vtime.h"
#include "queue_enqueue.h"
#include "queue_dispatch.h"

static __noinline s32
queue_pick_random_idle_cpu(const struct cpumask *candidates, bool whole_core)
{
	return cpu_pick_random_idle(candidates, whole_core);
}

static __always_inline s32 queue_pick_task_cell_cpu(
	const struct snake_ladder_ctx *ctx, struct task_struct *p, u32 kind,
	bool whole_core, bool random, u32 *cell_indexp)
{
	struct snake_task_runtime *runtime;
	struct bpf_cpumask	  *scratch;
	const struct cpumask	  *source;
	u32			   cell_index;
	s32			   selected;

	runtime	   = task_state_lookup(p);
	cell_index = queue_task_cell_index(ctx, p);
	source	   = queue_cell_mask(ctx, cell_index, kind);
	if (!runtime || !source)
		return -EINVAL;
	scratch = runtime->queue_cpumask;
	if (!scratch)
		return -EINVAL;
	if (!bpf_cpumask_and(scratch, source, p->cpus_ptr))
		return -ENOENT;
	if (!random) {
		selected = scx_bpf_pick_idle_cpu(
			(const struct cpumask *)scratch,
			whole_core ? SCX_PICK_IDLE_CORE : 0);
	} else {
		selected = queue_pick_random_idle_cpu(
			(const struct cpumask *)scratch, whole_core);
	}
	if (selected < 0)
		return selected == -EINVAL ? selected : -ENOENT;
	*cell_indexp = cell_index;
	return selected;
}

static __always_inline s32 queue_pick_task_cell_preferred_cpu(
	const struct snake_ladder_ctx *ctx, struct task_struct *p, u32 kind,
	s32 prev_cpu, u32 *cell_indexp)
{
	struct snake_task_runtime *runtime;
	struct snake_cpu_queue	  *cpuq;
	struct bpf_cpumask	  *scratch;
	const struct cpumask	  *primary, *source;
	u32 cell_index;
	s32 restricted, route_cpu;

	runtime = task_state_lookup(p);
	cell_index = queue_task_cell_index(ctx, p);
	primary = queue_cell_mask(ctx, cell_index, SNAKE_QUEUE_MASK_PRIMARY);
	if (!runtime || !primary)
		return -EINVAL;
	restricted = queue_task_cell_affinity_restricted(ctx, p, cell_index);
	if (restricted)
		return restricted < 0 ? restricted : -ENOENT;

	if (kind == SNAKE_QUEUE_MASK_LOCAL_LLC) {
		route_cpu = prev_cpu >= 0 && prev_cpu < nr_cpu_ids &&
				    bpf_cpumask_test_cpu(prev_cpu, primary) ?
				    prev_cpu :
				    bpf_cpumask_any_distribute(primary);
		if (route_cpu < 0 || route_cpu >= nr_cpu_ids)
			return -ENOENT;
		cpuq = queue_cpu(ctx, route_cpu);
		if (!cpuq || cpuq->owner_cell_index != cell_index)
			return -EINVAL;
		source = queue_normal_consumers(ctx, cpuq->normal_queue_index);
	} else {
		source = queue_cell_mask(ctx, cell_index, kind);
	}
	if (!source)
		return -EINVAL;
	scratch = runtime->queue_cpumask;
	if (!scratch)
		return -EINVAL;
	if (!bpf_cpumask_and(scratch, source, p->cpus_ptr))
		return -ENOENT;
	*cell_indexp = cell_index;
	return cpu_pick_idle_prefer_previous((const struct cpumask *)scratch,
					     prev_cpu);
}

static __always_inline s32 queue_pick_restricted_preferred_cpu(
	const struct snake_ladder_ctx *ctx, struct task_struct *p, s32 prev_cpu,
	u32 *cell_indexp)
{
	u32 cell_index = queue_task_cell_index(ctx, p);
	s32 restricted = queue_task_cell_affinity_restricted(ctx, p, cell_index);

	if (restricted <= 0)
		return restricted < 0 ? restricted : -ENOENT;
	*cell_indexp = cell_index;
	return cpu_pick_idle_prefer_previous(p->cpus_ptr, prev_cpu);
}

static __always_inline int
queue_fairness_select_cpu(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  s32 cpu)
{
	struct snake_task_runtime *runtime;

	if (queue_global_mode_enabled()) {
		fairness_vtime_prepare_runnable(ctx, p);
		runtime = fairness_vtime_prepare_task(ctx, p);
	} else {
		runtime = queue_fairness_prepare_task(ctx, p);
	}

	return task_route_record_selected_cpu(runtime, cpu);
}

#endif /* __SCX_SNAKE_QUEUE_FAIRNESS_H */
