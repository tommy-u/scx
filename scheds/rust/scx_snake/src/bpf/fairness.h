/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_H
#define __SCX_SNAKE_FAIRNESS_H

const volatile u32 fairness_mode = SNAKE_FAIRNESS_FIFO;

struct snake_task_runtime {
	struct bpf_cpumask __kptr *queue_cpumask;
	u64 started_exec_runtime;
	u64 service_budget;
	u64 vruntime;
	u64 affinity_vruntime;
	u64 deadline;
	u64 request_remaining_ns;
	u64 queue_timing_session_id;
	u64 queue_timing_dsq_id;
	u64 queue_timing_enqueued_at_ns;
	s64 sleep_lag;
	u32 active_weight;
	u32 pending_weight;
	u32 cell_index;
	u32 affinity_cell_index;
	u32 run_cell_index;
	u32 run_owner_cell_index;
	u32 selected_cpu;
	u32 direct_cell_index;
	u32 queue_timing_cell_index;
	u32 queue_timing_depth_after_insert;
	u32 queue_timing_queue_class;
	u8  runtime_valid;
	u8  initialized;
	u8  runnable_accounted;
	u8  has_sleep_lag;
	u8  run_direct;
	u8  cell_initialized;
	u8  affinity_initialized;
	u8  selected_cpu_valid;
	u8  queue_class;
	u8  run_queue_class;
	u8  direct_cell_valid;
};

struct snake_eevdf_domain {
	struct bpf_spin_lock lock;
	u32		     pad;
	u64		     virtual_time;
	u64		     runnable_weight;
};

struct snake_vtime_domain {
	struct bpf_spin_lock lock;
	u32		     pad;
	u64		     vtime_now;
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
	__type(value, struct snake_vtime_domain);
	__uint(max_entries, 1);
} vtime_domain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_vtime_domain);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} cell_vtime_domains SEC(".maps");

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

static __always_inline bool fairness_is_vtime(void)
{
	return fairness_mode == SNAKE_FAIRNESS_VTIME;
}

static __always_inline bool fairness_is_ordered(void)
{
	return fairness_is_vtime() || fairness_is_eevdf();
}

static __always_inline void
fairness_accounting_error(struct snake_ladder_ctx *ctx)
{
	if (fairness_is_vtime())
		stat_inc(ctx, SNAKE_STAT_VTIME_ACCOUNTING_ERRORS);
	else if (fairness_is_eevdf())
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
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

static __always_inline u64 fairness_vtime_slice(u32 weight)
{
	u64 slice;

	if (!weight)
		weight = SNAKE_BASE_WEIGHT;
	if (weight > SNAKE_BASE_WEIGHT)
		weight = SNAKE_BASE_WEIGHT;
	slice = (SNAKE_VTIME_SLICE_NS / SNAKE_BASE_WEIGHT) * weight;
	return slice < SNAKE_VTIME_MIN_SLICE_NS ?
		       SNAKE_VTIME_MIN_SLICE_NS : slice;
}

static __always_inline u64 fairness_vtime_run_start(u64 vruntime, u64 frontier)
{
	u64 minimum = frontier - SNAKE_VTIME_SLICE_NS;

	return time_before(vruntime, minimum) ? minimum : vruntime;
}

static __always_inline u64
fairness_vtime_service(u64 runtime, u64 service_budget, u64 remaining_slice)
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
	u64 slice = fairness_vtime_slice(weight);
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

static __always_inline bool fairness_eligible(u64 vruntime, u64 virtual_time)
{
	return (s64)(vruntime - virtual_time) <= 0;
}

static __always_inline struct snake_eevdf_domain *fairness_domain(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&eevdf_domain, &key);
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
fairness_task(struct snake_ladder_ctx *ctx, struct task_struct *p, bool create)
{
	struct snake_task_runtime *runtime;

	runtime = bpf_task_storage_get(&task_runtimes, p, 0,
				       create ? BPF_LOCAL_STORAGE_GET_F_CREATE :
						0);
	if (!runtime && create) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		fairness_accounting_error(ctx);
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
fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p);

static __always_inline void
fairness_vtime_prepare_runnable(struct snake_ladder_ctx *ctx,
				struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_vtime_domain *domain;
	u64			   minimum, vtime_now;

	runtime = fairness_prepare_task(ctx, p);
	domain  = fairness_vtime_domain();
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

static __always_inline struct snake_task_runtime *
fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	struct snake_vtime_domain *vtime;
	u64			   virtual_time;

	runtime = fairness_task(ctx, p, true);
	if (!runtime || runtime->initialized)
		return runtime;
	if (fairness_mode == SNAKE_FAIRNESS_FIFO) {
		runtime->active_weight  = fairness_task_weight(p);
		runtime->pending_weight = runtime->active_weight;
		runtime->initialized    = 1;
		return runtime;
	}
	if (fairness_is_vtime()) {
		vtime = fairness_vtime_domain();
		if (!vtime) {
			fairness_accounting_error(ctx);
			return NULL;
		}

		bpf_spin_lock(&vtime->lock);
		virtual_time = vtime->vtime_now;
		bpf_spin_unlock(&vtime->lock);

		runtime->vruntime       = virtual_time;
		runtime->active_weight  = fairness_task_weight(p);
		runtime->pending_weight = runtime->active_weight;
		runtime->initialized    = 1;
		return runtime;
	}
	domain = fairness_domain();
	if (!domain) {
		fairness_accounting_error(ctx);
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

static __noinline void
queue_timing_record_sample(struct snake_ladder_ctx *ctx, struct task_struct *p,
			   dsq_id_t dsq, u32 cell_index, u64 session_id)
{
	struct snake_task_runtime *runtime;
	u64 enqueued_at_ns;
	s32 depth;

	runtime = fairness_task(ctx, p, true);
	if (!runtime)
		return;
	enqueued_at_ns = bpf_ktime_get_ns();
	depth = dsq_nr_queued(dsq);
	if (depth < 0 || READ_ONCE(queue_timing_session_id) != session_id)
		return;
	runtime->queue_timing_dsq_id = dsq.raw;
	runtime->queue_timing_enqueued_at_ns = enqueued_at_ns;
	runtime->queue_timing_cell_index = cell_index;
	runtime->queue_timing_depth_after_insert = depth;
	runtime->queue_timing_queue_class = dsq_queue_class(dsq);
	runtime->queue_timing_session_id = session_id;
	__sync_fetch_and_add(&queue_timing_counters.started_samples, 1);
}

static __always_inline void
queue_timing_record_insert(struct snake_ladder_ctx *ctx, struct task_struct *p,
			   dsq_id_t dsq, u32 cell_index,
			   const struct snake_fine_timing_ctx *fine)
{
	u64 session_id;

	if (!fine || !fine->sampled)
		return;
	session_id = READ_ONCE(queue_timing_session_id);
	if (session_id)
		queue_timing_record_sample(ctx, p, dsq, cell_index, session_id);
}

static __always_inline void
queue_timing_cancel(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (runtime)
		runtime->queue_timing_session_id = 0;
}

static __noinline void
queue_timing_complete(struct snake_task_runtime *runtime)
{
	struct snake_queue_timing_event event = {};
	u64 session_id, now;
	s32 depth;

	if (!runtime)
		return;
	session_id = runtime->queue_timing_session_id;
	if (!session_id)
		return;
	event.session_id = session_id;
	event.dsq_id = runtime->queue_timing_dsq_id;
	event.cell_index = runtime->queue_timing_cell_index;
	event.queue_class = runtime->queue_timing_queue_class;
	event.depth_after_insert = runtime->queue_timing_depth_after_insert;
	event.residence_ns = runtime->queue_timing_enqueued_at_ns;
	runtime->queue_timing_session_id = 0;
	if (session_id != READ_ONCE(queue_timing_session_id))
		return;
	now = bpf_ktime_get_ns();
	event.residence_ns = now - event.residence_ns;
	depth = dsq_nr_queued(dsq_from_raw(event.dsq_id));
	if (depth < 0)
		return;
	event.depth_after_dispatch = depth;
	if (bpf_ringbuf_output(&queue_timing_events, &event, sizeof(event), 0))
		__sync_fetch_and_add(&queue_timing_counters.dropped_samples, 1);
	else
		__sync_fetch_and_add(&queue_timing_counters.completed_samples, 1);
}

static __always_inline void fairness_runnable(struct snake_ladder_ctx *ctx,
					      struct task_struct      *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   lag_limit;

	if (fairness_is_vtime()) {
		fairness_vtime_prepare_runnable(ctx, p);
		return;
	}
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

static __noinline u64 fairness_dispatch_slice(struct snake_ladder_ctx *ctx,
					      struct task_struct *p, bool direct)
{
	struct snake_task_runtime *runtime;

	if (fairness_is_vtime()) {
		fairness_vtime_prepare_runnable(ctx, p);
		runtime = fairness_prepare_task(ctx, p);
		if (!runtime)
			return fairness_vtime_slice(fairness_task_weight(p));
		runtime->active_weight = fairness_task_weight(p);
		runtime->pending_weight = runtime->active_weight;
		runtime->run_direct = direct;
		return fairness_vtime_slice(runtime->active_weight);
	}
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

static __always_inline int fairness_enqueue(struct snake_ladder_ctx *ctx,
					    struct task_struct	    *p,
					    u64			     enq_flags,
					    const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   virtual_time, flags, slice;
	s32			   target_cpu;
	dsq_id_t		   dsq;

	if (fairness_mode == SNAKE_FAIRNESS_FIFO) {
		flags = enq_flags & ~SCX_ENQ_PREEMPT;
		if (!dsq_insert(p, dsq_fifo(), SCX_SLICE_DFL, flags, fine)) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		queue_timing_record_insert(ctx, p, dsq_fifo(), SNAKE_QUEUE_CELL_NONE,
					   fine);
		stat_inc(ctx, SNAKE_STAT_FIFO_SHARED_ENQUEUES);
		target_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (target_cpu < 0)
			target_cpu = scx_bpf_task_cpu(p);
		if (target_cpu >= 0 && target_cpu < nr_cpu_ids)
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		return 0;
	}
	if (fairness_is_vtime()) {
		target_cpu = -1;
		dsq = dsq_vtime_global();
		fairness_vtime_prepare_runnable(ctx, p);
		runtime = fairness_prepare_task(ctx, p);
		if (!runtime) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		runtime->active_weight = fairness_task_weight(p);
		runtime->pending_weight = runtime->active_weight;
		runtime->run_direct = 0;
		flags = enq_flags & ~SCX_ENQ_PREEMPT;
		if (p->nr_cpus_allowed < nr_cpu_ids) {
			target_cpu = fairness_vtime_distribute_cpu(p);
			if (target_cpu < 0) {
				stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
				return target_cpu;
			}
			dsq = dsq_vtime_cpu(target_cpu);
			stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
		}
		if (!dsq_insert_vtime(
			    p, dsq,
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
	fairness_runnable(ctx, p);
	runtime = fairness_prepare_task(ctx, p);
	domain	= fairness_domain();
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
	if (fairness_eligible(runtime->vruntime, virtual_time)) {
		dsq = dsq_eevdf_eligible();
		if (!dsq_insert_vtime(p, dsq, slice,
				      runtime->deadline, flags, fine)) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		stat_inc(ctx, SNAKE_STAT_EEVDF_ELIGIBLE_ENQUEUES);
	} else {
		dsq = dsq_eevdf_future();
		if (!dsq_insert_vtime(p, dsq, slice,
				      runtime->vruntime, flags, fine)) {
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			return -EINVAL;
		}
		stat_inc(ctx, SNAKE_STAT_EEVDF_FUTURE_ENQUEUES);
	}
	queue_timing_record_insert(ctx, p, dsq, SNAKE_QUEUE_CELL_NONE, fine);
	return 0;
}

static __always_inline u32
fairness_promote(struct snake_ladder_ctx *ctx, u64 virtual_time,
		 const struct snake_fine_timing_ctx *fine)
{
	struct task_struct *p;
	u32		    moved = 0;

	bpf_for_each(scx_dsq, p, dsq_eevdf_future().raw, 0) {
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
fairness_advance_to_cpu_future(struct snake_ladder_ctx *ctx, s32 cpu)
{
	struct snake_eevdf_domain *domain = fairness_domain();
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
fairness_dispatch_eligible(struct snake_ladder_ctx *ctx, s32 cpu,
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
	delta = current - runtime->started_exec_runtime;
	weight = runtime->active_weight ?: fairness_task_weight(prev);
	service = fairness_vtime_service(
		delta, runtime->service_budget, prev->scx.slice);
	projected = runtime->vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return false;
	fairness_vtime_replenish(runtime, prev, weight);
	return true;
}

static __always_inline bool fairness_vtime_head(dsq_id_t dsq, u64 *vtime)
{
	struct task_struct *p = dsq_peek(dsq);

	if (!p)
		return false;
	*vtime = READ_ONCE(p->scx.dsq_vtime);
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
fairness_dispatch_vtime(struct snake_ladder_ctx *ctx, s32 cpu,
			struct task_struct *prev,
			const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t cpu_dsq = dsq_vtime_cpu(cpu);
	dsq_id_t global_dsq = dsq_vtime_global();
	dsq_id_t first_dsq, second_dsq = dsq_invalid();
	u64  cpu_vtime = 0, global_vtime = 0, candidate_vtime;
	bool cpu_found, global_found;

	cpu_found = fairness_vtime_head(cpu_dsq, &cpu_vtime);
	global_found = fairness_vtime_head(global_dsq, &global_vtime);
	if (!cpu_found && !global_found)
		goto keep_running;
	if (global_found &&
	    (!cpu_found || time_before(global_vtime, cpu_vtime))) {
		first_dsq = global_dsq;
		candidate_vtime = global_vtime;
		if (cpu_found)
			second_dsq = cpu_dsq;
	} else {
		first_dsq = cpu_dsq;
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
		struct snake_task_runtime *runtime = fairness_task(ctx, prev, false);
		u32 weight = runtime && runtime->runtime_valid ?
				     runtime->active_weight :
				     fairness_task_weight(prev);

		fairness_vtime_replenish(runtime, prev, weight);
	}
	return false;
}

static __always_inline int fairness_dispatch(struct snake_ladder_ctx *ctx,
					     s32		      cpu,
					     struct task_struct *prev,
					     const struct snake_fine_timing_ctx *fine)
{
	struct snake_eevdf_domain *domain;
	u64			   virtual_time;
	s32			   local_queued;

	if (fairness_is_vtime()) {
		/* Local DSQs are FIFO; pre-filling one would discard VTIME order. */
		local_queued = dsq_nr_queued(dsq_local_on(cpu));
		if (local_queued < 0)
			return local_queued;
		if (local_queued > 0)
			return 0;
		fairness_dispatch_vtime(ctx, cpu, prev, fine);
		return 0;
	}
	if (fairness_mode == SNAKE_FAIRNESS_FIFO) {
		if (dsq_move_to_local(dsq_fifo(), cpu, fine))
			stat_inc(ctx, SNAKE_STAT_FIFO_SHARED_DISPATCHES);
		return 0;
	}
	if (!fairness_is_eevdf())
		return -EINVAL;
	domain = fairness_domain();
	if (!domain)
		return -EINVAL;

	bpf_spin_lock(&domain->lock);
	virtual_time = domain->virtual_time;
	bpf_spin_unlock(&domain->lock);
	fairness_promote(ctx, virtual_time, fine);
	if (fairness_dispatch_eligible(ctx, cpu, fine))
		return 0;
	/*
	 * The global eligible DSQ may contain only tasks which cannot run on
	 * this CPU. Advance to this CPU's first compatible future task instead
	 * of leaving an otherwise usable CPU idle indefinitely.
	 */
	if (fairness_advance_to_cpu_future(ctx, cpu)) {
		bpf_spin_lock(&domain->lock);
		virtual_time = domain->virtual_time;
		bpf_spin_unlock(&domain->lock);
		fairness_promote(ctx, virtual_time, fine);
		fairness_dispatch_eligible(ctx, cpu, fine);
	}
	return 0;
}

static __always_inline void fairness_running(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	struct snake_task_runtime *runtime = fairness_prepare_task(ctx, p);
	struct snake_vtime_domain *domain;

	if (!runtime)
		return;
	if (runtime->queue_timing_session_id)
		queue_timing_complete(runtime);
	if (fairness_is_vtime()) {
		domain = fairness_vtime_domain();
		if (!domain) {
			fairness_accounting_error(ctx);
			return;
		}
		bpf_spin_lock(&domain->lock);
		runtime->vruntime = fairness_vtime_run_start(
			runtime->vruntime, domain->vtime_now);
		if (time_before(domain->vtime_now, runtime->vruntime))
			domain->vtime_now = runtime->vruntime;
		bpf_spin_unlock(&domain->lock);
		if (!runtime->active_weight) {
			runtime->active_weight = fairness_task_weight(p);
			runtime->pending_weight = runtime->active_weight;
		}
	}
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->service_budget	      = p->scx.slice;
	runtime->runtime_valid	      = 1;
}

static __always_inline u64 fairness_stopping(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	struct snake_task_runtime *runtime;
	struct snake_eevdf_domain *domain;
	u64			   current, delta = 0, service;
	u32			   old_weight, new_weight;
	bool			   accounting_error = false;

	runtime = fairness_task(ctx, p, false);
	if (!runtime || !runtime->runtime_valid) {
		if (fairness_is_ordered())
			fairness_accounting_error(ctx);
		return 0;
	}
	current = p->se.sum_exec_runtime;
	if (current >= runtime->started_exec_runtime)
		delta = current - runtime->started_exec_runtime;
	else
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
	runtime->runtime_valid = 0;
	if (fairness_is_vtime()) {
		old_weight = runtime->active_weight ?: fairness_task_weight(p);
		service = fairness_vtime_service(
			delta, runtime->service_budget, p->scx.slice);
		runtime->vruntime += fairness_scale_inverse(service, old_weight);
		stat_add(ctx,
			 runtime->run_direct ? SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS :
					       SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS,
			 delta);
		return delta;
	}
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
	u32 cpu;
	int ret;

	if (fairness_mode == SNAKE_FAIRNESS_FIFO)
		return dsq_create(dsq_fifo(), -1);
	if (fairness_is_vtime()) {
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
	if (!fairness_is_eevdf())
		return -EINVAL;
	ret = dsq_create(dsq_eevdf_eligible(), -1);
	if (ret)
		return ret;
	ret = dsq_create(dsq_eevdf_future(), -1);
	if (ret)
		dsq_destroy(dsq_eevdf_eligible());
	return ret;
}

#endif /* __SCX_SNAKE_FAIRNESS_H */
