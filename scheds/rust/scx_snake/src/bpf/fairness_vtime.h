/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_VTIME_H
#define __SCX_SNAKE_FAIRNESS_VTIME_H

#include "fairness_common.h"
#include "queue_timing.h"
#include "queue.h"

struct snake_vtime_domain {
	struct bpf_spin_lock lock;
	u32		     pad;
	u64		     vtime_now;
	u64		     cacheline_pad[6];
};

_Static_assert(sizeof(struct snake_vtime_domain) == 64,
	       "VTIME domains must occupy one 64-byte cacheline stride");
_Static_assert(__builtin_offsetof(struct snake_vtime_domain, vtime_now) % 8 == 0,
	       "VTIME clock must remain aligned for 64-bit atomics");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_vtime_domain);
	__uint(max_entries, 1);
} vtime_domain		   SEC(".maps");

static __always_inline u64 fairness_vtime_slice(u32 weight)
{
	u64 slice;

	if (!weight)
		weight = SNAKE_BASE_WEIGHT;
	if (weight > SNAKE_BASE_WEIGHT)
		weight = SNAKE_BASE_WEIGHT;
	slice = (SNAKE_VTIME_SLICE_NS / SNAKE_BASE_WEIGHT) * weight;
	return slice < SNAKE_VTIME_MIN_SLICE_NS ? SNAKE_VTIME_MIN_SLICE_NS :
						  slice;
}

static __always_inline u64 fairness_vtime_run_start(u64 vruntime, u64 frontier)
{
	u64 minimum = frontier - SNAKE_VTIME_SLICE_NS;

	return time_before(vruntime, minimum) ? minimum : vruntime;
}

static __always_inline u64 fairness_vtime_service(u64 runtime,
						  u64 service_budget,
						  u64 remaining_slice)
{
	u64 consumed = 0;

	if (remaining_slice < service_budget)
		consumed = service_budget - remaining_slice;
	if (runtime < consumed)
		runtime = consumed;
	if (runtime > service_budget)
		runtime = service_budget;
	return runtime;
}

static __always_inline void
fairness_vtime_replenish(struct snake_task_runtime *runtime,
			 struct task_struct *p, u32 weight)
{
	u64 remaining = p->scx.slice;
	u64 slice     = fairness_vtime_slice(weight);
	u64 budget;

	if (runtime && runtime->runtime_valid) {
		budget = runtime->service_budget;
		if (remaining > budget)
			remaining = budget;
		budget -= remaining;
		if (budget > ~0ULL - slice)
			budget = ~0ULL;
		else
			budget += slice;
		runtime->service_budget = budget;
	}
	p->scx.slice = slice;
}

static __always_inline struct snake_vtime_domain *fairness_vtime_domain(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&vtime_domain, &key);
}

static __always_inline s32
fairness_vtime_distribute_cpu(const struct task_struct *p)
{
	s32 cpu = bpf_cpumask_any_distribute(p->cpus_ptr);

	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return cpu;
	return -ENOENT;
}

static __always_inline struct snake_task_runtime *
fairness_vtime_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_vtime_domain *domain;
	u64			   virtual_time;

	runtime = fairness_task(ctx, p, false);
	if (!runtime || runtime->initialized)
		return runtime;
	domain = fairness_vtime_domain();
	if (!domain) {
		fairness_accounting_error(ctx);
		return NULL;
	}
	bpf_spin_lock(&domain->lock);
	virtual_time = domain->vtime_now;
	bpf_spin_unlock(&domain->lock);
	runtime->vruntime	= virtual_time;
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	runtime->initialized	= 1;
	return runtime;
}

static __always_inline void
fairness_vtime_prepare_runnable(struct snake_ladder_ctx *ctx,
				struct task_struct	*p)
{
	struct snake_task_runtime *runtime;
	struct snake_vtime_domain *domain;
	u64			   minimum, vtime_now;

	runtime = fairness_vtime_prepare_task(ctx, p);
	domain	= fairness_vtime_domain();
	if (!runtime || !domain)
		return;
	bpf_spin_lock(&domain->lock);
	vtime_now = domain->vtime_now;
	bpf_spin_unlock(&domain->lock);
	minimum = vtime_now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->vruntime, minimum)) {
		runtime->vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
}

static __always_inline void
fairness_vtime_runnable(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	fairness_vtime_prepare_runnable(ctx, p);
}

static __always_inline u64 fairness_vtime_dispatch_slice(
	struct snake_ladder_ctx *ctx, struct task_struct *p, bool direct)
{
	struct snake_task_runtime *runtime;

	fairness_vtime_prepare_runnable(ctx, p);
	runtime = fairness_vtime_prepare_task(ctx, p);
	if (!runtime)
		return fairness_vtime_slice(fairness_task_weight(p));
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	runtime->run_direct	= direct;
	return fairness_vtime_slice(runtime->active_weight);
}

static __always_inline int
fairness_vtime_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		       u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	u64			   flags;
	s32			   target_cpu = -1;
	dsq_id_t		   dsq	      = dsq_vtime_global();

	fairness_vtime_prepare_runnable(ctx, p);
	runtime = fairness_vtime_prepare_task(ctx, p);
	if (!runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -EINVAL;
	}
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	runtime->run_direct	= 0;
	flags			= enq_flags & ~SCX_ENQ_PREEMPT;
	if (p->nr_cpus_allowed < nr_cpu_ids) {
		target_cpu = fairness_vtime_distribute_cpu(p);
		if (target_cpu < 0) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return target_cpu;
		}
		dsq = dsq_vtime_cpu(target_cpu);
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
	}
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->vruntime, flags, fine)) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -EINVAL;
	}
	queue_timing_record_insert(ctx, p, dsq, SNAKE_QUEUE_CELL_NONE, fine);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	if (target_cpu >= 0)
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline bool
fairness_vtime_keep_running(struct snake_ladder_ctx *ctx,
			    struct task_struct *prev, u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64			   current, delta, projected, service;
	u32			   weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return false;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid)
		return false;
	current = prev->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return false;
	}
	delta	  = current - runtime->started_exec_runtime;
	weight	  = runtime->active_weight ?: fairness_task_weight(prev);
	service	  = fairness_vtime_service(delta, runtime->service_budget,
					   prev->scx.slice);
	projected = runtime->vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return false;
	fairness_vtime_replenish(runtime, prev, weight);
	return true;
}

static __always_inline bool
fairness_vtime_move_local(struct snake_ladder_ctx *ctx, dsq_id_t dsq, s32 cpu,
			  const struct snake_fine_timing_ctx *fine)
{
	if (!dsq_move_to_local(dsq, cpu, fine))
		return false;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (dsq.raw != dsq_vtime_global().raw)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return true;
}

static __always_inline bool
fairness_vtime_dispatch_one(struct snake_ladder_ctx *ctx, s32 cpu,
			    struct task_struct		       *prev,
			    const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t cpu_dsq    = dsq_vtime_cpu(cpu);
	dsq_id_t global_dsq = dsq_vtime_global();
	dsq_id_t first_dsq, second_dsq = dsq_invalid();
	u64	 cpu_vtime = 0, global_vtime = 0, candidate_vtime;
	bool	 cpu_found, global_found;

	cpu_found    = dsq_vtime_head(cpu_dsq, &cpu_vtime);
	global_found = dsq_vtime_head(global_dsq, &global_vtime);
	if (!cpu_found && !global_found)
		goto keep_running;
	if (global_found &&
	    (!cpu_found || time_before(global_vtime, cpu_vtime))) {
		first_dsq	= global_dsq;
		candidate_vtime = global_vtime;
		if (cpu_found)
			second_dsq = cpu_dsq;
	} else {
		first_dsq	= cpu_dsq;
		candidate_vtime = cpu_vtime;
		if (global_found)
			second_dsq = global_dsq;
	}
	if (fairness_vtime_keep_running(ctx, prev, candidate_vtime))
		return false;
	if (fairness_vtime_move_local(ctx, first_dsq, cpu, fine))
		return true;
	if (!dsq_is_invalid(second_dsq) &&
	    fairness_vtime_move_local(ctx, second_dsq, cpu, fine))
		return true;

keep_running:
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct snake_task_runtime *runtime =
			fairness_task(ctx, prev, false);
		u32 weight = runtime && runtime->runtime_valid ?
				     runtime->active_weight :
				     fairness_task_weight(prev);

		fairness_vtime_replenish(runtime, prev, weight);
	}
	return false;
}

static __always_inline int
fairness_vtime_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
			struct task_struct		   *prev,
			const struct snake_fine_timing_ctx *fine)
{
	s32 local_queued = dsq_nr_queued(dsq_local_on(cpu));

	/* Local DSQs are FIFO; pre-filling one would discard VTIME order. */
	if (local_queued < 0)
		return local_queued;
	if (local_queued > 0)
		return 0;
	fairness_vtime_dispatch_one(ctx, cpu, prev, fine);
	return 0;
}

static __always_inline void fairness_vtime_running(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	struct snake_task_runtime *runtime =
		fairness_vtime_prepare_task(ctx, p);
	struct snake_vtime_domain *domain;

	if (!runtime)
		return;
	queue_timing_complete_pending(runtime);
	domain = fairness_vtime_domain();
	if (!domain) {
		fairness_accounting_error(ctx);
		return;
	}
	bpf_spin_lock(&domain->lock);
	runtime->vruntime =
		fairness_vtime_run_start(runtime->vruntime, domain->vtime_now);
	if (time_before(domain->vtime_now, runtime->vruntime))
		domain->vtime_now = runtime->vruntime;
	bpf_spin_unlock(&domain->lock);
	if (!runtime->active_weight) {
		runtime->active_weight	= fairness_task_weight(p);
		runtime->pending_weight = runtime->active_weight;
	}
	fairness_runtime_begin(runtime, p);
}

static __always_inline u64 fairness_vtime_stopping(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	u64			   delta, service;
	u32			   old_weight;

	if (!runtime || !runtime->runtime_valid) {
		fairness_accounting_error(ctx);
		return 0;
	}
	delta	   = fairness_runtime_delta(ctx, p, runtime);
	old_weight = runtime->active_weight ?: fairness_task_weight(p);
	service	   = fairness_vtime_service(delta, runtime->service_budget,
					    p->scx.slice);
	runtime->vruntime += fairness_scale_inverse(service, old_weight);
	stat_add(ctx,
		 runtime->run_direct ? SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS :
				       SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS,
		 delta);
	return delta;
}

static __always_inline void
fairness_vtime_quiescent(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u64 deq_flags)
{
	(void)ctx;
	(void)p;
	(void)deq_flags;
}

static __always_inline void
fairness_vtime_set_weight(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  u32 weight)
{
	(void)ctx;
	(void)p;
	(void)weight;
}

static __always_inline int fairness_vtime_init(void)
{
	u32 cpu;
	int ret;

	if (queue_topology_enabled())
		return 0;
	if (nr_cpu_ids > SNAKE_MAX_CPUS)
		return -E2BIG;
	ret = dsq_create(dsq_vtime_global(), -1);
	if (ret)
		return ret;
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		ret = dsq_create(dsq_vtime_cpu(cpu), -1);
		if (ret)
			return ret;
	}
	return 0;
}

#endif /* __SCX_SNAKE_FAIRNESS_VTIME_H */
