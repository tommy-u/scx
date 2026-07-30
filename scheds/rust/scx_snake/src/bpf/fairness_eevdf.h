/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_EEVDF_H
#define __SCX_SNAKE_FAIRNESS_EEVDF_H

#include "fairness_common.h"
#include "queue_timing.h"
#include "queue.h"

struct snake_eevdf_domain {
	struct bpf_spin_lock lock;
	u32		     pad;
	u64		     virtual_time;
	u64		     runnable_weight;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_eevdf_domain);
	__uint(max_entries, 1);
} eevdf_domain		    SEC(".maps");

static __always_inline bool fairness_eevdf_eligible(u64 vruntime,
						    u64 virtual_time)
{
	return (s64)(vruntime - virtual_time) <= 0;
}

static __always_inline struct snake_eevdf_domain *fairness_eevdf_domain(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&eevdf_domain, &key);
}

static __always_inline void
fairness_eevdf_set_request(struct snake_task_runtime *runtime, u32 weight)
{
	runtime->active_weight	      = weight ? weight : SNAKE_BASE_WEIGHT;
	runtime->request_remaining_ns = SNAKE_EEVDF_SLICE_NS;
	runtime->deadline = runtime->vruntime +
			    fairness_scale_inverse(SNAKE_EEVDF_SLICE_NS,
						   runtime->active_weight);
}

static __always_inline struct snake_task_runtime *
fairness_eevdf_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   virtual_time;

	runtime = fairness_task(ctx, p, true);
	if (!runtime || runtime->initialized)
		return runtime;
	domain = fairness_eevdf_domain();
	if (!domain) {
		fairness_accounting_error(ctx);
		return NULL;
	}
	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	runtime->vruntime	= virtual_time;
	runtime->pending_weight = fairness_task_weight(p);
	fairness_eevdf_set_request(runtime, runtime->pending_weight);
	runtime->initialized = 1;
	return runtime;
}

static __always_inline void
fairness_eevdf_runnable(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   lag_limit;

	runtime = fairness_eevdf_prepare_task(ctx, p);
	domain	= fairness_eevdf_domain();
	if (!runtime || !domain || runtime->runnable_accounted)
		return;
	lag_limit = fairness_scale_inverse(SNAKE_EEVDF_SLICE_NS,
					   runtime->active_weight);
	bpf_spin_lock(&domain->lock);
	if (runtime->has_sleep_lag) {
		s64 lag = runtime->sleep_lag;

		if (lag > (s64)lag_limit)
			lag = lag_limit;
		else if (lag < -(s64)lag_limit)
			lag = -(s64)lag_limit;
		runtime->vruntime = domain->virtual_time - lag;
		runtime->deadline =
			runtime->vruntime +
			fairness_scale_inverse(runtime->request_remaining_ns,
					       runtime->active_weight);
		runtime->has_sleep_lag = 0;
	}
	domain->runnable_weight += runtime->active_weight;
	runtime->runnable_accounted = 1;
	bpf_spin_unlock(&domain->lock);
}

static __always_inline u64 fairness_eevdf_dispatch_slice(
	struct snake_ladder_ctx *ctx, struct task_struct *p, bool direct)
{
	struct snake_task_runtime *runtime;

	fairness_eevdf_runnable(ctx, p);
	runtime = fairness_eevdf_prepare_task(ctx, p);
	if (!runtime)
		return SNAKE_EEVDF_SLICE_NS;
	runtime->run_direct = direct;
	return runtime->request_remaining_ns ? runtime->request_remaining_ns :
					       SNAKE_EEVDF_SLICE_NS;
}

static __always_inline int
fairness_eevdf_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		       u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   virtual_time, flags, slice;
	dsq_id_t		   dsq;

	fairness_eevdf_runnable(ctx, p);
	runtime = fairness_eevdf_prepare_task(ctx, p);
	domain	= fairness_eevdf_domain();
	if (!runtime || !domain) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -EINVAL;
	}
	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	runtime->run_direct = 0;
	flags		    = enq_flags & ~SCX_ENQ_PREEMPT;
	slice = runtime->request_remaining_ns ?: SNAKE_EEVDF_SLICE_NS;
	if (fairness_eevdf_eligible(runtime->vruntime, virtual_time)) {
		dsq = dsq_eevdf_eligible();
		if (!dsq_insert_vtime(p, dsq, slice, runtime->deadline, flags,
				      fine)) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		stat_inc(ctx, SNAKE_STAT_EEVDF_ELIGIBLE_ENQUEUES);
	} else {
		dsq = dsq_eevdf_future();
		if (!dsq_insert_vtime(p, dsq, slice, runtime->vruntime, flags,
				      fine)) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		stat_inc(ctx, SNAKE_STAT_EEVDF_FUTURE_ENQUEUES);
	}
	queue_timing_record_insert(ctx, p, dsq, SNAKE_QUEUE_CELL_NONE, fine);
	return 0;
}

static __always_inline u32
fairness_eevdf_promote(struct snake_ladder_ctx *ctx, u64 virtual_time,
		       const struct snake_fine_timing_ctx *fine)
{
	struct task_struct *p;
	u32		    moved = 0;

	bpf_for_each(scx_dsq, p, dsq_eevdf_future().raw, 0) {
		struct snake_task_runtime *runtime;
		u64			   slice;

		if (moved >= SNAKE_EEVDF_PROMOTE_BATCH)
			break;
		runtime = task_state_lookup(p);
		if (!runtime) {
			stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
			break;
		}
		if (!fairness_eevdf_eligible(runtime->vruntime, virtual_time))
			break;
		slice = runtime->request_remaining_ns ?: SNAKE_EEVDF_SLICE_NS;
		dsq_move_set_slice(BPF_FOR_EACH_ITER, slice);
		dsq_move_set_vtime(BPF_FOR_EACH_ITER, runtime->deadline);
		if (dsq_move_vtime(BPF_FOR_EACH_ITER, p, dsq_eevdf_future(),
				   dsq_eevdf_eligible(), 0, fine))
			moved++;
	}
	stat_add(ctx, SNAKE_STAT_EEVDF_PROMOTIONS, moved);
	return moved;
}

static __always_inline bool
fairness_eevdf_advance_to_cpu_future(struct snake_ladder_ctx *ctx, s32 cpu)
{
	struct snake_eevdf_domain *domain = fairness_eevdf_domain();
	struct task_struct	  *p;
	u64			   head	 = 0;
	bool			   found = false;

	if (!domain)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq_eevdf_future().raw, 0) {
		struct snake_task_runtime *runtime;
		struct task_struct	  *task;

		task = bpf_task_from_pid(p->pid);
		if (!task)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, task->cpus_ptr)) {
			bpf_task_release(task);
			continue;
		}
		bpf_task_release(task);
		runtime = task_state_lookup(p);
		if (runtime) {
			head  = runtime->vruntime;
			found = true;
		}
		break;
	}
	bpf_rcu_read_unlock();
	if (!found)
		return false;
	bpf_spin_lock(&domain->lock);
	if (!fairness_eevdf_eligible(head, domain->virtual_time))
		domain->virtual_time = head;
	bpf_spin_unlock(&domain->lock);
	stat_inc(ctx, SNAKE_STAT_EEVDF_FORCED_ADVANCES);
	return true;
}

static __always_inline bool
fairness_eevdf_dispatch_eligible(struct snake_ladder_ctx *ctx, s32 cpu,
				 const struct snake_fine_timing_ctx *fine)
{
	struct task_struct *p;
	bool		    dispatched = false;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq_eevdf_eligible().raw, 0) {
		/* Reacquire the iterator task for verifier-safe affinity access. */
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		dispatched = dsq_move(BPF_FOR_EACH_ITER, p,
				      dsq_eevdf_eligible(), dsq_local_on(cpu),
				      0, fine);
		bpf_task_release(p);
		if (dispatched) {
			stat_inc(ctx, SNAKE_STAT_EEVDF_DISPATCHES);
			break;
		}
	}
	bpf_rcu_read_unlock();
	return dispatched;
}

static __noinline int
fairness_eevdf_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
			struct task_struct		   *prev,
			const struct snake_fine_timing_ctx *fine)
{
	struct snake_eevdf_domain *domain = fairness_eevdf_domain();
	u64			   virtual_time;

	(void)prev;
	if (!domain)
		return -EINVAL;
	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	fairness_eevdf_promote(ctx, virtual_time, fine);
	if (fairness_eevdf_dispatch_eligible(ctx, cpu, fine))
		return 0;
	/* Advance to this CPU's first compatible future task if needed. */
	if (fairness_eevdf_advance_to_cpu_future(ctx, cpu)) {
		bpf_spin_lock(&domain->lock);
		virtual_time = domain->virtual_time;
		bpf_spin_unlock(&domain->lock);
		fairness_eevdf_promote(ctx, virtual_time, fine);
		fairness_eevdf_dispatch_eligible(ctx, cpu, fine);
	}
	return 0;
}

static __always_inline void fairness_eevdf_running(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	struct snake_task_runtime *runtime =
		fairness_eevdf_prepare_task(ctx, p);

	if (!runtime)
		return;
	queue_timing_complete_pending(runtime);
	fairness_runtime_begin(runtime, p);
}

static __always_inline u64 fairness_eevdf_stopping(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	struct snake_eevdf_domain *domain;
	u64			   delta;
	u32			   old_weight, new_weight;
	bool			   accounting_error = false;

	if (!runtime || !runtime->runtime_valid) {
		fairness_accounting_error(ctx);
		return 0;
	}
	delta = fairness_runtime_delta(ctx, p, runtime);
	if (!delta)
		return delta;
	domain = fairness_eevdf_domain();
	if (!domain)
		return delta;
	old_weight = runtime->active_weight ?: SNAKE_BASE_WEIGHT;
	runtime->vruntime += fairness_scale_inverse(delta, old_weight);
	bpf_spin_lock(&domain->lock);
	if (domain->runnable_weight)
		domain->virtual_time +=
			fairness_scale_inverse(delta, domain->runnable_weight);
	else
		accounting_error = true;
	if (delta >= runtime->request_remaining_ns) {
		new_weight = runtime->pending_weight ?: fairness_task_weight(p);
		if (runtime->runnable_accounted && new_weight != old_weight) {
			if (domain->runnable_weight >= old_weight)
				domain->runnable_weight =
					domain->runnable_weight - old_weight +
					new_weight;
			else
				accounting_error = true;
		}
		fairness_eevdf_set_request(runtime, new_weight);
	} else {
		runtime->request_remaining_ns -= delta;
	}
	bpf_spin_unlock(&domain->lock);
	if (accounting_error)
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
	stat_add(ctx,
		 runtime->run_direct ? SNAKE_STAT_EEVDF_DIRECT_RUNTIME_NS :
				       SNAKE_STAT_EEVDF_QUEUED_RUNTIME_NS,
		 delta);
	return delta;
}

static __always_inline void
fairness_eevdf_quiescent(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u64 deq_flags)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   lag_limit;
	s64			   lag = 0, clamped = 0;
	bool			   accounting_error = false;

	runtime = fairness_task(ctx, p, false);
	domain	= fairness_eevdf_domain();
	if (!runtime || !domain || !runtime->runnable_accounted)
		return;
	lag_limit = fairness_scale_inverse(SNAKE_EEVDF_SLICE_NS,
					   runtime->active_weight);
	bpf_spin_lock(&domain->lock);
	if (deq_flags & SCX_DEQ_SLEEP) {
		lag	= (s64)(domain->virtual_time - runtime->vruntime);
		clamped = lag;
		if (clamped > (s64)lag_limit)
			clamped = lag_limit;
		else if (clamped < -(s64)lag_limit)
			clamped = -(s64)lag_limit;
		runtime->sleep_lag     = clamped;
		runtime->has_sleep_lag = 1;
	} else {
		runtime->has_sleep_lag = 0;
	}
	if (domain->runnable_weight >= runtime->active_weight)
		domain->runnable_weight -= runtime->active_weight;
	else {
		domain->runnable_weight = 0;
		accounting_error	= true;
	}
	runtime->runnable_accounted = 0;
	bpf_spin_unlock(&domain->lock);
	if (lag != clamped)
		stat_inc(ctx, SNAKE_STAT_EEVDF_LAG_CLAMPS);
	if (accounting_error)
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
}

static __always_inline void
fairness_eevdf_set_weight(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  u32 weight)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, true);

	if (runtime)
		runtime->pending_weight = weight ? weight : SNAKE_BASE_WEIGHT;
}

static __always_inline int fairness_eevdf_init(void)
{
	int ret = dsq_create(dsq_eevdf_eligible(), -1);

	if (ret)
		return ret;
	ret = dsq_create(dsq_eevdf_future(), -1);
	if (ret)
		dsq_destroy(dsq_eevdf_eligible());
	return ret;
}

#endif /* __SCX_SNAKE_FAIRNESS_EEVDF_H */
