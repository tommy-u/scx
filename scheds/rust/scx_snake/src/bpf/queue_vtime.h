/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_VTIME_H
#define __SCX_SNAKE_QUEUE_VTIME_H

#include "queue.h"
#include "fairness.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_vtime_domain);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} cell_vtime_domains SEC(".maps");

static __always_inline struct snake_vtime_domain *
queue_cell_domain(u32 cell_index)
{
	if (cell_index >= SNAKE_MAX_QUEUE_CELLS)
		return NULL;
	return bpf_map_lookup_elem(&cell_vtime_domains, &cell_index);
}

static __always_inline u64 queue_domain_now(struct snake_vtime_domain *domain)
{
	u64 now;

	if (!domain)
		return 0;
	bpf_spin_lock(&domain->lock);
	now = domain->vtime_now;
	bpf_spin_unlock(&domain->lock);
	return now;
}

static __always_inline u64 queue_translate_vruntime(u64 vruntime, u64 old_now,
						    u64 new_now)
{
	s64 lag = (s64)(vruntime - old_now);

	if (lag > (s64)SNAKE_VTIME_SLICE_NS)
		lag = SNAKE_VTIME_SLICE_NS;
	else if (lag < -(s64)SNAKE_VTIME_SLICE_NS)
		lag = -(s64)SNAKE_VTIME_SLICE_NS;
	return new_now + lag;
}

static __noinline void queue_clear_rehome_if_cell(struct task_struct *p,
						  u32 cell_index)
{
	struct snake_queue_cell *cell;
	struct snake_task_cell	*annotation;
	u32			 external_id, slot_epoch;

	cell = queue_cell(cell_index);
	if (!cell)
		return;
	external_id = READ_ONCE(cell->external_id);
	slot_epoch  = READ_ONCE(cell->slot_epoch);
	annotation  = task_annotation(p);
	if (!annotation || READ_ONCE(annotation->cell_id) != external_id ||
	    READ_ONCE(annotation->cell_epoch) != slot_epoch)
		return;
	WRITE_ONCE(annotation->needs_rehome, 0);
	if (READ_ONCE(annotation->cell_id) != external_id ||
	    READ_ONCE(annotation->cell_epoch) != slot_epoch)
		WRITE_ONCE(annotation->needs_rehome, 1);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task_for_cell(struct snake_ladder_ctx *ctx,
				     struct task_struct *p, u32 cell_index,
				     bool clear_rehome,
				     const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_vtime_domain *old_domain, *new_domain;
	struct snake_task_cell	  *annotation;
	u64			   old_now, new_now, stage_started_at;

	stage_started_at = fine_timing_start(fine);
	runtime		 = fairness_task(ctx, p, false);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_TASK_STORAGE,
			   stage_started_at);
	if (!runtime)
		return NULL;
	stage_started_at = fine_timing_start(fine);
	new_domain	 = queue_cell_domain(cell_index);
	if (!new_domain) {
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
				   stage_started_at);
		fairness_accounting_error(ctx);
		return NULL;
	}
	if (!runtime->cell_initialized) {
		runtime->vruntime	  = queue_domain_now(new_domain);
		runtime->cell_index	  = cell_index;
		runtime->cell_initialized = 1;
	} else if (runtime->cell_index != cell_index) {
		old_domain = queue_cell_domain(runtime->cell_index);
		if (!old_domain) {
			fine_timing_finish(
				fine,
				SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
				stage_started_at);
			fairness_accounting_error(ctx);
			return NULL;
		}
		old_now		  = queue_domain_now(old_domain);
		new_now		  = queue_domain_now(new_domain);
		runtime->vruntime = queue_translate_vruntime(runtime->vruntime,
							     old_now, new_now);
		runtime->cell_index = cell_index;
		cell_stat_inc(ctx, cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
			   stage_started_at);
	annotation = task_annotation(p);
	if (clear_rehome && annotation)
		WRITE_ONCE(annotation->needs_rehome, 0);
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	return queue_fairness_prepare_task_for_cell(
		ctx, p, queue_task_cell_index(p), true, NULL);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable_for_cell(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u32 cell_index,
	bool clear_rehome, const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime =
		queue_fairness_prepare_task_for_cell(ctx, p, cell_index,
						     clear_rehome, fine);
	struct snake_vtime_domain *domain;
	u64			   minimum, now, stage_started_at;

	if (!runtime)
		return NULL;
	stage_started_at = fine_timing_start(fine);
	domain		 = queue_cell_domain(runtime->cell_index);
	if (!domain) {
		fine_timing_finish(
			fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CREDIT_CLAMP,
			stage_started_at);
		fairness_accounting_error(ctx);
		return NULL;
	}
	now	= queue_domain_now(domain);
	minimum = now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->vruntime, minimum)) {
		runtime->vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CREDIT_CLAMP,
			   stage_started_at);
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable(struct snake_ladder_ctx		   *ctx,
				struct task_struct		   *p,
				const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	u64			   stage_started_at = fine_timing_start(fine);

	runtime = fairness_task(ctx, p, false);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_ROUTE_LOOKUP,
			   stage_started_at);

	if (runtime && runtime->direct_cell_valid)
		return queue_fairness_prepare_runnable_for_cell(
			ctx, p, runtime->direct_cell_index, false, fine);
	return queue_fairness_prepare_runnable_for_cell(
		ctx, p, queue_task_cell_index(p), true, fine);
}

static __noinline void
queue_fairness_cancel_direct(struct snake_ladder_ctx *ctx,
			     struct task_struct	     *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (runtime) {
		runtime->direct_cell_valid = 0;
		queue_timing_cancel_runtime(runtime);
	}
}

static __always_inline int
queue_fairness_prepare_affinity(struct snake_ladder_ctx	  *ctx,
				struct snake_task_runtime *runtime,
				u32			   owner_cell_index)
{
	struct snake_vtime_domain *task_domain, *old_domain, *new_domain;
	u64			   minimum, task_now, old_now, new_now;

	if (!runtime)
		return -EINVAL;
	new_domain = queue_cell_domain(owner_cell_index);
	if (!new_domain)
		return -EINVAL;
	new_now = queue_domain_now(new_domain);
	if (!runtime->affinity_initialized) {
		task_domain = queue_cell_domain(runtime->cell_index);
		if (!task_domain)
			return -EINVAL;
		task_now		   = queue_domain_now(task_domain);
		runtime->affinity_vruntime = queue_translate_vruntime(
			runtime->vruntime, task_now, new_now);
		runtime->affinity_cell_index  = owner_cell_index;
		runtime->affinity_initialized = 1;
	} else if (runtime->affinity_cell_index != owner_cell_index) {
		old_domain = queue_cell_domain(runtime->affinity_cell_index);
		if (!old_domain)
			return -EINVAL;
		old_now			   = queue_domain_now(old_domain);
		runtime->affinity_vruntime = queue_translate_vruntime(
			runtime->affinity_vruntime, old_now, new_now);
		runtime->affinity_cell_index = owner_cell_index;
		cell_stat_inc(ctx, owner_cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	}
	minimum = new_now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->affinity_vruntime, minimum)) {
		runtime->affinity_vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	return 0;
}

static __always_inline bool
queue_fairness_rehome_pending(struct task_struct	*p,
			      struct snake_task_runtime *runtime)
{
	struct snake_task_cell *annotation;

	if (!runtime || !runtime->cell_initialized)
		return false;
	annotation = task_annotation(p);
	if (annotation && READ_ONCE(annotation->needs_rehome))
		return true;
	return queue_task_cell_index(p) != runtime->cell_index;
}

static __always_inline bool
queue_fairness_direct_borrowed(struct snake_task_runtime *runtime)
{
	return runtime && runtime->run_direct &&
	       runtime->run_cell_index != runtime->run_owner_cell_index;
}

static __always_inline int
queue_fairness_replenish(struct snake_ladder_ctx *ctx,
			 struct snake_cpu_queue *cpuq, struct task_struct *prev)
{
	struct snake_task_runtime *runtime;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !cpuq)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	if (runtime->run_owner_cell_index != cpuq->owner_cell_index)
		return 0;
	if (runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (!runtime->affinity_initialized)
			return -EINVAL;
		if (runtime->affinity_cell_index != cpuq->owner_cell_index)
			return 0;
	} else if (runtime->run_queue_class != SNAKE_QUEUE_CLASS_NORMAL ||
		   runtime->run_cell_index != cpuq->owner_cell_index) {
		return 0;
	}
	fairness_vtime_replenish(runtime, prev, runtime->active_weight);
	return 0;
}

static __always_inline int queue_fairness_running(struct snake_ladder_ctx *ctx,
						  struct task_struct	  *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	struct snake_vtime_domain *domain;
	struct snake_cpu_queue	  *cpuq;
	u32			   active_weight, cpu;

	active_weight = runtime && runtime->active_weight ?
				runtime->active_weight :
				fairness_task_weight(p);
	queue_timing_complete_pending(runtime);

	if (runtime && runtime->direct_cell_valid) {
		u32 direct_cell_index = runtime->direct_cell_index;

		runtime		      = queue_fairness_prepare_task_for_cell(
			ctx, p, direct_cell_index, false, NULL);
		if (!runtime)
			return -EINVAL;
		queue_clear_rehome_if_cell(p, direct_cell_index);
		runtime->direct_cell_valid = 0;
	} else if (runtime && runtime->cell_initialized &&
		   runtime->queue_class == SNAKE_QUEUE_CLASS_NORMAL &&
		   queue_task_cell_index(p) != runtime->cell_index) {
		/* Charge an already-queued execution to the cell which queued it. */
		stat_inc(ctx, SNAKE_STAT_QUEUE_STALE_REHOME_RUNS);
	} else {
		runtime = queue_fairness_prepare_task(ctx, p);
		if (!runtime)
			return -EINVAL;
	}
	cpu  = bpf_get_smp_processor_id();
	cpuq = queue_cpu(cpu);
	if (!cpuq)
		return -EINVAL;
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain)
		return -EINVAL;
	bpf_spin_lock(&domain->lock);
	runtime->vruntime =
		fairness_vtime_run_start(runtime->vruntime, domain->vtime_now);
	if (time_before(domain->vtime_now, runtime->vruntime))
		domain->vtime_now = runtime->vruntime;
	bpf_spin_unlock(&domain->lock);
	if (runtime->queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (queue_fairness_prepare_affinity(ctx, runtime,
						    cpuq->owner_cell_index))
			return -EINVAL;
		domain = queue_cell_domain(cpuq->owner_cell_index);
		if (!domain)
			return -EINVAL;
		bpf_spin_lock(&domain->lock);
		if (time_before(domain->vtime_now, runtime->affinity_vruntime))
			domain->vtime_now = runtime->affinity_vruntime;
		bpf_spin_unlock(&domain->lock);
	}
	/* select_cpu() may be followed directly by running() when prev is kept. */
	task_route_clear_selected_cpu(runtime);
	runtime->run_cell_index	      = runtime->cell_index;
	runtime->run_owner_cell_index = cpuq ? cpuq->owner_cell_index : 0;
	runtime->run_queue_class      = runtime->queue_class;
	runtime->active_weight	      = active_weight;
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->service_budget	      = p->scx.slice;
	runtime->runtime_valid	      = 1;
	cell_stat_inc(ctx, runtime->run_cell_index,
		      runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY ?
			      SNAKE_CELL_STAT_AFFINITY_DISPATCHES :
			      SNAKE_CELL_STAT_NORMAL_DISPATCHES);
	return 0;
}

static __always_inline int queue_fairness_stopping(struct snake_ladder_ctx *ctx,
						   struct task_struct	   *p,
						   u64 *runtime_ns)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	u64			   current, delta, scaled, service;
	u32			   weight;

	if (!runtime || !runtime->runtime_valid) {
		fairness_accounting_error(ctx);
		return -EINVAL;
	}
	current = p->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		runtime->runtime_valid = 0;
		return -ERANGE;
	}
	delta	= current - runtime->started_exec_runtime;
	weight	= runtime->active_weight ?: fairness_task_weight(p);
	service = fairness_vtime_service(delta, runtime->service_budget,
					 p->scx.slice);
	scaled	= fairness_scale_inverse(service, weight);
	runtime->vruntime += scaled;
	if (runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY)
		runtime->affinity_vruntime += scaled;
	runtime->runtime_valid = 0;
	cell_stat_add(ctx, runtime->run_cell_index, SNAKE_CELL_STAT_RUNTIME_NS,
		      delta);
	if (runtime->run_cell_index == runtime->run_owner_cell_index) {
		cell_stat_add(ctx, runtime->run_cell_index,
			      SNAKE_CELL_STAT_PRIMARY_RUNTIME_NS, delta);
	} else {
		cell_stat_add(ctx, runtime->run_cell_index,
			      SNAKE_CELL_STAT_BORROWED_RUNTIME_NS, delta);
		cell_stat_add(ctx, runtime->run_owner_cell_index,
			      SNAKE_CELL_STAT_LENT_RUNTIME_NS, delta);
	}
	stat_add(ctx,
		 runtime->run_direct ? SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS :
				       SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS,
		 delta);
	*runtime_ns = delta;
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_VTIME_H */
