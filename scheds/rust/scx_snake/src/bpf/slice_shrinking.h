/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_SLICE_SHRINKING_H
#define __SCX_SNAKE_SLICE_SHRINKING_H

#include "dsq.h"
#include "stats.h"
#include "task_state.h"

extern u64 vtime_slice_ns;
extern u64 slice_shrink_min_ns;
extern u64 slice_shrink_max_ns;
extern u32 slice_shrink_multiplier;
extern u32 slice_shrinking_enabled;

enum snake_slice_shrink_result {
	SNAKE_SLICE_SHRINK_MIN,
	SNAKE_SLICE_SHRINK_PROPORTIONAL,
	SNAKE_SLICE_SHRINK_MAX,
};

static __always_inline void
slice_runtime_update(struct snake_task_runtime *runtime, u64 used)
{
	if (!runtime || !used)
		return;
	if (!runtime->avg_runtime_ns)
		runtime->avg_runtime_ns = used;
	else
		runtime->avg_runtime_ns =
			(runtime->avg_runtime_ns * 7 + used) / 8;
}

static __always_inline u64
slice_shrink_limit(u64 avg_runtime_ns, enum snake_slice_shrink_result *result)
{
	u64 min = READ_ONCE(slice_shrink_min_ns);
	u64 max = READ_ONCE(slice_shrink_max_ns);
	u32 multiplier = READ_ONCE(slice_shrink_multiplier);
	u64 proportional;

	if (!multiplier || avg_runtime_ns > max / multiplier) {
		*result = SNAKE_SLICE_SHRINK_MAX;
		return max;
	}
	proportional = avg_runtime_ns * multiplier;
	if (proportional < min) {
		*result = SNAKE_SLICE_SHRINK_MIN;
		return min;
	}
	if (proportional < max) {
		*result = SNAKE_SLICE_SHRINK_PROPORTIONAL;
		return proportional;
	}
	*result = SNAKE_SLICE_SHRINK_MAX;
	return max;
}

static __always_inline void
slice_shrink_apply(const struct snake_ladder_ctx *ctx, struct task_struct *p,
		   u64 avg_runtime_ns)
{
	enum snake_slice_shrink_result result;
	struct snake_task_runtime *runtime;
	u64 limit, old_slice, removed;

	if (!p || !READ_ONCE(slice_shrinking_enabled))
		return;
	limit = slice_shrink_limit(avg_runtime_ns, &result);
	old_slice = READ_ONCE(p->scx.slice);
	if (!limit || old_slice <= limit)
		return;
	removed = old_slice - limit;
	runtime = task_state_lookup(p);
	if (runtime && runtime->runtime_valid) {
		if (runtime->service_budget >= removed)
			runtime->service_budget -= removed;
		else
			runtime->service_budget = limit;
	}
	p->scx.slice = limit;
	if (result == SNAKE_SLICE_SHRINK_MIN)
		stat_inc(ctx, SNAKE_STAT_SLICE_SHRINK_MIN);
	else if (result == SNAKE_SLICE_SHRINK_PROPORTIONAL)
		stat_inc(ctx, SNAKE_STAT_SLICE_SHRINK_PROPORTIONAL);
	else
		stat_inc(ctx, SNAKE_STAT_SLICE_SHRINK_MAX);
}

static __always_inline void
slice_shrink_on_enqueue(const struct snake_ladder_ctx *ctx, s32 cpu,
			struct snake_task_runtime *waiter)
{
	struct task_struct *current;

	if (!READ_ONCE(slice_shrinking_enabled) || !waiter || cpu < 0 ||
	    cpu >= nr_cpu_ids)
		return;
	current = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (current && !(current->flags & PF_IDLE))
		slice_shrink_apply(ctx, current, waiter->avg_runtime_ns);
}

static __always_inline void
slice_shrink_on_running(const struct snake_ladder_ctx *ctx,
			struct task_struct *p)
{
	struct snake_task_runtime *waiter_runtime;
	struct task_struct *waiter;
	dsq_id_t dsq;
	s32 queued;
	u32 cpu;

	if (!READ_ONCE(slice_shrinking_enabled))
		return;
	cpu = bpf_get_smp_processor_id();
	dsq = dsq_affinity(cpu);
	queued = dsq_nr_queued(dsq);
	if (queued <= 0)
		return;
	waiter = dsq_peek(dsq);
	if (!waiter)
		return;
	waiter_runtime = task_state_lookup(waiter);
	if (waiter_runtime)
		slice_shrink_apply(ctx, p, waiter_runtime->avg_runtime_ns);
}

#endif /* __SCX_SNAKE_SLICE_SHRINKING_H */
