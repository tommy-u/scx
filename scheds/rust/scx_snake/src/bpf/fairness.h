/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_H
#define __SCX_SNAKE_FAIRNESS_H

const volatile u32 fairness_mode = SNAKE_FAIRNESS_FIFO;

struct snake_task_runtime {
	u64 started_exec_runtime;
	u64 vruntime;
	u64 deadline;
	u64 request_remaining_ns;
	s64 sleep_lag;
	u32 active_weight;
	u32 pending_weight;
	u8  runtime_valid;
	u8  initialized;
	u8  runnable_accounted;
	u8  has_sleep_lag;
	u8  run_direct;
};

struct snake_eevdf_domain {
	struct bpf_spin_lock lock;
	u32		     pad;
	u64		     virtual_time;
	u64		     runnable_weight;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_runtime);
} task_runtimes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_eevdf_domain);
	__uint(max_entries, 1);
} eevdf_domain		    SEC(".maps");

static __always_inline bool fairness_is_eevdf(void)
{
	return fairness_mode == SNAKE_FAIRNESS_EEVDF;
}

static __always_inline u32 fairness_task_weight(const struct task_struct *p)
{
	u32 weight = READ_ONCE(p->scx.weight);

	return weight ? weight : SNAKE_BASE_WEIGHT;
}

static __always_inline u64 fairness_scale_inverse(u64 delta, u64 weight)
{
	if (!weight)
		return delta;
	return (delta / weight) * SNAKE_BASE_WEIGHT +
	       ((delta % weight) * SNAKE_BASE_WEIGHT) / weight;
}

static __always_inline bool fairness_eligible(u64 vruntime, u64 virtual_time)
{
	return (s64)(vruntime - virtual_time) <= 0;
}

static __always_inline struct snake_eevdf_domain *fairness_domain(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&eevdf_domain, &key);
}

static __always_inline struct snake_task_runtime *
fairness_task(struct snake_ladder_ctx *ctx, struct task_struct *p, bool create)
{
	struct snake_task_runtime *runtime;

	runtime = bpf_task_storage_get(&task_runtimes, p, 0,
				       create ? BPF_LOCAL_STORAGE_GET_F_CREATE :
						0);
	if (!runtime && create) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
	}
	return runtime;
}

static __always_inline void
fairness_set_request(struct snake_task_runtime *runtime, u32 weight)
{
	runtime->active_weight	      = weight ? weight : SNAKE_BASE_WEIGHT;
	runtime->request_remaining_ns = SNAKE_EEVDF_SLICE_NS;
	runtime->deadline	      = runtime->vruntime +
			    fairness_scale_inverse(SNAKE_EEVDF_SLICE_NS,
						   runtime->active_weight);
}

static __always_inline struct snake_task_runtime *
fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   virtual_time;

	runtime = fairness_task(ctx, p, true);
	if (!runtime || runtime->initialized)
		return runtime;
	domain = fairness_domain();
	if (!domain) {
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
		return NULL;
	}

	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);

	runtime->vruntime	= virtual_time;
	runtime->pending_weight = fairness_task_weight(p);
	fairness_set_request(runtime, runtime->pending_weight);
	runtime->initialized = 1;
	return runtime;
}

static __always_inline void fairness_runnable(struct snake_ladder_ctx *ctx,
					      struct task_struct      *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   lag_limit;

	if (!fairness_is_eevdf())
		return;
	runtime = fairness_prepare_task(ctx, p);
	domain	= fairness_domain();
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

static __always_inline u64 fairness_dispatch_slice(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p,
						   bool direct)
{
	struct snake_task_runtime *runtime;

	if (!fairness_is_eevdf())
		return SCX_SLICE_DFL;
	fairness_runnable(ctx, p);
	runtime = fairness_prepare_task(ctx, p);
	if (!runtime)
		return SNAKE_EEVDF_SLICE_NS;
	runtime->run_direct = direct;
	return runtime->request_remaining_ns ? runtime->request_remaining_ns :
					       SNAKE_EEVDF_SLICE_NS;
}

static __always_inline void fairness_enqueue(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p,
					     u64		      enq_flags)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   virtual_time, flags, slice;

	if (!fairness_is_eevdf()) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
	fairness_runnable(ctx, p);
	runtime = fairness_prepare_task(ctx, p);
	domain	= fairness_domain();
	if (!runtime || !domain) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SNAKE_EEVDF_SLICE_NS,
				   enq_flags);
		return;
	}

	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	runtime->run_direct = 0;
	flags		    = enq_flags & ~SCX_ENQ_PREEMPT;
	slice = runtime->request_remaining_ns ?: SNAKE_EEVDF_SLICE_NS;
	if (fairness_eligible(runtime->vruntime, virtual_time)) {
		scx_bpf_dsq_insert_vtime(p, SNAKE_EEVDF_ELIGIBLE_DSQ, slice,
					 runtime->deadline, flags);
		stat_inc(ctx, SNAKE_STAT_EEVDF_ELIGIBLE_ENQUEUES);
	} else {
		scx_bpf_dsq_insert_vtime(p, SNAKE_EEVDF_FUTURE_DSQ, slice,
					 runtime->vruntime, flags);
		stat_inc(ctx, SNAKE_STAT_EEVDF_FUTURE_ENQUEUES);
	}
}

static __always_inline u32 fairness_promote(struct snake_ladder_ctx *ctx,
					    u64 virtual_time)
{
	struct task_struct *p;
	u32		    moved = 0;

	bpf_for_each(scx_dsq, p, SNAKE_EEVDF_FUTURE_DSQ, 0) {
		struct snake_task_runtime *runtime;
		u64			   slice;

		if (moved >= SNAKE_EEVDF_PROMOTE_BATCH)
			break;
		runtime = bpf_task_storage_get(&task_runtimes, p, 0, 0);
		if (!runtime) {
			stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
			break;
		}
		if (!fairness_eligible(runtime->vruntime, virtual_time))
			break;
		slice = runtime->request_remaining_ns ?: SNAKE_EEVDF_SLICE_NS;
		scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, slice);
		scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER,
					   runtime->deadline);
		if (scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, p,
					   SNAKE_EEVDF_ELIGIBLE_DSQ, 0))
			moved++;
	}
	stat_add(ctx, SNAKE_STAT_EEVDF_PROMOTIONS, moved);
	return moved;
}

static __always_inline bool
fairness_advance_to_cpu_future(struct snake_ladder_ctx *ctx, s32 cpu)
{
	struct snake_eevdf_domain *domain = fairness_domain();
	struct task_struct	  *p;
	u64			   head	 = 0;
	bool			   found = false;

	if (!domain)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, SNAKE_EEVDF_FUTURE_DSQ, 0) {
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

		runtime = bpf_task_storage_get(&task_runtimes, p, 0, 0);
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
	if (!fairness_eligible(head, domain->virtual_time))
		domain->virtual_time = head;
	bpf_spin_unlock(&domain->lock);
	stat_inc(ctx, SNAKE_STAT_EEVDF_FORCED_ADVANCES);
	return true;
}

static __always_inline bool
fairness_dispatch_eligible(struct snake_ladder_ctx *ctx, s32 cpu)
{
	struct task_struct *p;
	bool		    dispatched = false;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, SNAKE_EEVDF_ELIGIBLE_DSQ, 0) {
		/* Reacquire the iterator task for verifier-safe affinity access. */
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		dispatched = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
					      SCX_DSQ_LOCAL_ON | cpu, 0);
		bpf_task_release(p);
		if (dispatched) {
			stat_inc(ctx, SNAKE_STAT_EEVDF_DISPATCHES);
			break;
		}
	}
	bpf_rcu_read_unlock();
	return dispatched;
}

static __always_inline void fairness_dispatch(struct snake_ladder_ctx *ctx,
					      s32		       cpu)
{
	struct snake_eevdf_domain *domain;
	u64			   virtual_time;

	if (!fairness_is_eevdf())
		return;
	domain = fairness_domain();
	if (!domain)
		return;

	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	fairness_promote(ctx, virtual_time);
	if (fairness_dispatch_eligible(ctx, cpu))
		return;
	/*
	 * The global eligible DSQ may contain only tasks which cannot run on
	 * this CPU. Advance to this CPU's first compatible future task instead
	 * of leaving an otherwise usable CPU idle indefinitely.
	 */
	if (fairness_advance_to_cpu_future(ctx, cpu)) {
		bpf_spin_lock(&domain->lock);
		virtual_time = domain->virtual_time;
		bpf_spin_unlock(&domain->lock);
		fairness_promote(ctx, virtual_time);
		fairness_dispatch_eligible(ctx, cpu);
	}
}

static __always_inline void fairness_running(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	struct snake_task_runtime *runtime = fairness_prepare_task(ctx, p);

	if (!runtime)
		return;
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->runtime_valid	      = 1;
}

static __always_inline u64 fairness_stopping(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   current, delta = 0;
	u32			   old_weight, new_weight;
	bool			   accounting_error = false;

	runtime = fairness_task(ctx, p, false);
	if (!runtime || !runtime->runtime_valid)
		return 0;
	current = p->se.sum_exec_runtime;
	if (current >= runtime->started_exec_runtime)
		delta = current - runtime->started_exec_runtime;
	else
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
	runtime->runtime_valid = 0;
	if (!fairness_is_eevdf() || !delta)
		return delta;

	domain = fairness_domain();
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
		fairness_set_request(runtime, new_weight);
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

static __always_inline void fairness_quiescent(struct snake_ladder_ctx *ctx,
					       struct task_struct      *p,
					       u64 deq_flags)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   lag_limit;
	s64			   lag = 0, clamped = 0;
	bool			   accounting_error = false;

	if (!fairness_is_eevdf())
		return;
	runtime = fairness_task(ctx, p, false);
	domain	= fairness_domain();
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

static __always_inline void fairness_set_weight(struct snake_ladder_ctx *ctx,
						struct task_struct	*p,
						u32			 weight)
{
	struct snake_task_runtime *runtime;

	if (!fairness_is_eevdf())
		return;
	runtime = fairness_task(ctx, p, true);
	if (runtime)
		runtime->pending_weight = weight ? weight : SNAKE_BASE_WEIGHT;
}

static __always_inline int fairness_init(void)
{
	int ret;

	if (fairness_mode == SNAKE_FAIRNESS_FIFO)
		return 0;
	if (!fairness_is_eevdf())
		return -EINVAL;
	ret = scx_bpf_create_dsq(SNAKE_EEVDF_ELIGIBLE_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(SNAKE_EEVDF_FUTURE_DSQ, -1);
	if (ret)
		scx_bpf_destroy_dsq(SNAKE_EEVDF_ELIGIBLE_DSQ);
	return ret;
}

#endif /* __SCX_SNAKE_FAIRNESS_H */
