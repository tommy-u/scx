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
