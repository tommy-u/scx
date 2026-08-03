/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_VTIME_H
#define __SCX_SNAKE_QUEUE_VTIME_H

#include "queue.h"
#include "fairness.h"

#define SNAKE_VTIME_CAS_RETRIES 16

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

static __always_inline u32 queue_domain_read_stage(
	const struct snake_fine_timing_ctx *fine)
{
	if (!fine)
		return SNAKE_NR_FINE_TIMING_STAGES;
	if (fine->callback == SNAKE_FINE_TIMING_CALLBACK_SELECT_CPU)
		return SNAKE_FINE_TIMING_SELECT_CELL_CLOCK_READ;
	if (fine->callback == SNAKE_FINE_TIMING_CALLBACK_ENQUEUE)
		return SNAKE_FINE_TIMING_ENQUEUE_CELL_CLOCK_READ;
	if (fine->callback == SNAKE_FINE_TIMING_CALLBACK_RUNNABLE)
		return SNAKE_FINE_TIMING_RUNNABLE_CELL_CLOCK_READ;
	if (fine->callback == SNAKE_FINE_TIMING_CALLBACK_RUNNING)
		return SNAKE_FINE_TIMING_RUNNING_CELL_CLOCK_READ;
	return SNAKE_NR_FINE_TIMING_STAGES;
}

static __always_inline u64
queue_domain_now(struct snake_vtime_domain *domain,
		 const struct snake_fine_timing_ctx *fine)
{
	u64 now, started_at;
	u32 stage;

	if (!domain)
		return 0;
	started_at = fine_timing_start(fine);
	now = READ_ONCE(domain->vtime_now);
	stage = queue_domain_read_stage(fine);
	if (stage < SNAKE_NR_FINE_TIMING_STAGES)
		fine_timing_finish(fine, stage, started_at);
	return now;
}

static __always_inline int
queue_domain_run_start(const struct snake_ladder_ctx *ctx,
		       struct snake_vtime_domain *domain, u64 vruntime,
		       u64 *adjusted_vruntime,
		       const struct snake_fine_timing_ctx *fine)
{
	u64  adjusted, desired, observed, previous, started_at;
	u32  stage;
	int  attempt, ret = 0;
	bool advanced = false;

	if (!domain || !adjusted_vruntime)
		return -EINVAL;
	started_at = fine_timing_start(fine);
	observed = READ_ONCE(domain->vtime_now);
	bpf_for(attempt, 0, SNAKE_VTIME_CAS_RETRIES) {
		adjusted = fairness_vtime_run_start(vruntime, observed);
		desired  = observed;
		if (time_before(observed, adjusted))
			desired = adjusted;
		previous = __sync_val_compare_and_swap(&domain->vtime_now,
						   observed, desired);
		if (previous == observed) {
			advanced = desired != observed;
			*adjusted_vruntime = adjusted;
			goto out;
		}
		stat_inc(ctx, SNAKE_STAT_VTIME_CLOCK_CAS_RETRIES);
		observed = previous;
	}
	stat_inc(ctx, SNAKE_STAT_VTIME_CLOCK_CAS_EXHAUSTIONS);
	adjusted = fairness_vtime_run_start(vruntime, observed);
	if (time_before(observed, adjusted))
		ret = -EAGAIN;
	else
		*adjusted_vruntime = adjusted;
out:
	stage = advanced ? SNAKE_FINE_TIMING_RUNNING_CELL_CLOCK_RUN_START_ADVANCE :
			   SNAKE_FINE_TIMING_RUNNING_CELL_CLOCK_RUN_START_NOOP;
	fine_timing_finish(fine, stage, started_at);
	return ret;
}

static __always_inline int
queue_domain_advance(const struct snake_ladder_ctx *ctx,
		     struct snake_vtime_domain *domain, u64 candidate,
		     const struct snake_fine_timing_ctx *fine)
{
	u64  observed, previous, started_at;
	u32  stage;
	int  attempt, ret = 0;
	bool advanced = false;

	if (!domain)
		return -EINVAL;
	started_at = fine_timing_start(fine);
	observed = READ_ONCE(domain->vtime_now);
	bpf_for(attempt, 0, SNAKE_VTIME_CAS_RETRIES) {
		if (!time_before(observed, candidate))
			goto out;
		previous = __sync_val_compare_and_swap(&domain->vtime_now,
						   observed, candidate);
		if (previous == observed) {
			advanced = true;
			goto out;
		}
		stat_inc(ctx, SNAKE_STAT_VTIME_CLOCK_CAS_RETRIES);
		observed = previous;
	}
	stat_inc(ctx, SNAKE_STAT_VTIME_CLOCK_CAS_EXHAUSTIONS);
	if (time_before(observed, candidate))
		ret = -EAGAIN;
out:
	stage = advanced ? SNAKE_FINE_TIMING_RUNNING_AFFINITY_CLOCK_ADVANCE :
			   SNAKE_FINE_TIMING_RUNNING_AFFINITY_CLOCK_NOOP;
	fine_timing_finish(fine, stage, started_at);
	return ret;
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

static __noinline void queue_clear_rehome_if_cell(
	const struct snake_ladder_ctx *ctx, struct task_struct *p, u32 cell_index)
{
	struct snake_queue_cell *cell;
	struct snake_task_cell	*annotation;
	u32			 external_id, slot_epoch;

	cell = queue_cell(ctx, cell_index);
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

static __noinline u32 queue_fairness_resolve_runtime_cell(
	const struct snake_ladder_ctx *ctx, struct task_struct *p,
	struct snake_task_runtime *runtime)
{
	struct snake_queue_header *header = queue_config(ctx);
	struct snake_queue_cell   *cell;
	u32			 *encoded;
	u32 external_id, cell_epoch, cell_index, key;

	if (!ctx || !runtime || !runtime->cell_initialized || !header)
		goto fallback;
	external_id = READ_ONCE(runtime->cell_external_id);
	cell_epoch = READ_ONCE(runtime->cell_epoch);
	if (external_id >= SNAKE_MAX_CPUS)
		goto fallback;
	key = queue_slot_index(ctx->slot, SNAKE_MAX_CPUS, external_id);
	encoded = bpf_map_lookup_elem(&queue_cell_lookup, &key);
	if (!encoded || !READ_ONCE(*encoded))
		goto fallback;
	cell_index = READ_ONCE(*encoded) - 1;
	if (cell_index >= READ_ONCE(header->nr_cells))
		goto fallback;
	cell = queue_cell(ctx, cell_index);
	if (!cell || !READ_ONCE(cell->valid) ||
	    READ_ONCE(cell->external_id) != external_id ||
	    READ_ONCE(cell->slot_epoch) != cell_epoch)
		goto fallback;
	return cell_index;

fallback:
	return queue_task_cell_index(ctx, p);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task_for_cell(struct snake_ladder_ctx *ctx,
				     struct task_struct *p, u32 cell_index,
				     bool clear_rehome,
				     const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_queue_header *header;
	struct snake_queue_cell   *cell;
	struct snake_vtime_domain *old_domain, *new_domain;
	struct snake_task_cell	  *annotation;
	u64			   old_now, new_now, stage_started_at;
	u32			   external_id, slot_epoch;

	stage_started_at = fine_timing_start(fine);
	runtime		 = fairness_task(ctx, p, false);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_TASK_STORAGE,
			   stage_started_at);
	if (!runtime)
		return NULL;
	stage_started_at = fine_timing_start(fine);
	header		 = queue_config(ctx);
	cell		 = queue_cell(ctx, cell_index);
	new_domain	 = queue_cell_domain(cell_index);
	if (!header || !cell || !new_domain) {
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
				   stage_started_at);
		fairness_accounting_error(ctx);
		return NULL;
	}
	external_id = READ_ONCE(cell->external_id);
	slot_epoch  = READ_ONCE(cell->slot_epoch);
	new_now     = queue_domain_now(new_domain, fine);
	if (!runtime->cell_initialized) {
		runtime->vruntime	  = new_now;
		runtime->cell_index	  = cell_index;
		runtime->cell_initialized = 1;
	} else if (runtime->topology_generation !=
		   header->topology_generation) {
		if (runtime->cell_index != cell_index ||
		    runtime->cell_external_id != external_id ||
		    runtime->cell_epoch != slot_epoch) {
			runtime->vruntime = new_now;
			cell_stat_inc(ctx, cell_index,
				      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
		}
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
		old_now		  = queue_domain_now(old_domain, fine);
		runtime->vruntime = queue_translate_vruntime(runtime->vruntime,
							     old_now, new_now);
		runtime->cell_index = cell_index;
		cell_stat_inc(ctx, cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	} else if (runtime->cell_external_id != external_id ||
		   runtime->cell_epoch != slot_epoch) {
		runtime->vruntime = new_now;
		cell_stat_inc(ctx, cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	}
	runtime->cell_index		= cell_index;
	runtime->cell_external_id	= external_id;
	runtime->cell_epoch		= slot_epoch;
	runtime->topology_generation = header->topology_generation;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
			   stage_started_at);
	annotation = task_annotation(p);
	if (clear_rehome && annotation)
		WRITE_ONCE(annotation->needs_rehome, 0);
	runtime->active_weight	= fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	return runtime;
}

static __always_inline struct snake_task_runtime *queue_fairness_prepare_task(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	const struct snake_fine_timing_ctx *fine)
{
	return queue_fairness_prepare_task_for_cell(
		ctx, p, queue_task_cell_index(ctx, p), true, fine);
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
	now	= queue_domain_now(domain, fine);
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
	struct snake_queue_header *header;
	u64			   stage_started_at = fine_timing_start(fine);
	u32			   cell_index;

	runtime = fairness_task(ctx, p, false);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_ROUTE_LOOKUP,
			   stage_started_at);

	if (runtime && runtime->direct_cell_valid) {
		cell_index = runtime->direct_cell_index;
		header = queue_config(ctx);
		if (header && runtime->topology_generation !=
			      READ_ONCE(header->topology_generation)) {
			cell_index = queue_fairness_resolve_runtime_cell(ctx, p,
								  runtime);
			runtime->direct_cell_index = cell_index;
		}
		return queue_fairness_prepare_runnable_for_cell(
			ctx, p, cell_index, false, fine);
	}
	return queue_fairness_prepare_runnable_for_cell(
		ctx, p, queue_task_cell_index(ctx, p), true, fine);
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
					u32			   owner_cell_index,
					const struct snake_fine_timing_ctx *fine)
{
	struct snake_vtime_domain *task_domain, *old_domain, *new_domain;
	struct snake_queue_header *header;
	struct snake_queue_cell   *owner;
	u64			   minimum, task_now, old_now, new_now;
	u32			   external_id, slot_epoch;

	if (!runtime)
		return -EINVAL;
	header = queue_config(ctx);
	owner = queue_cell(ctx, owner_cell_index);
	new_domain = queue_cell_domain(owner_cell_index);
	if (!header || !owner || !new_domain)
		return -EINVAL;
	external_id = READ_ONCE(owner->external_id);
	slot_epoch = READ_ONCE(owner->slot_epoch);
	new_now = queue_domain_now(new_domain, fine);
	if (!runtime->affinity_initialized) {
		task_domain = queue_cell_domain(runtime->cell_index);
		if (!task_domain)
			return -EINVAL;
		task_now		   = queue_domain_now(task_domain, fine);
		runtime->affinity_vruntime = queue_translate_vruntime(
			runtime->vruntime, task_now, new_now);
		runtime->affinity_cell_index  = owner_cell_index;
		runtime->affinity_initialized = 1;
	} else if (runtime->affinity_topology_generation !=
		   header->topology_generation) {
		if (runtime->affinity_cell_index != owner_cell_index ||
		    runtime->affinity_cell_external_id != external_id ||
		    runtime->affinity_cell_epoch != slot_epoch) {
			runtime->affinity_vruntime = new_now;
			cell_stat_inc(ctx, owner_cell_index,
				      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
		}
	} else if (runtime->affinity_cell_index != owner_cell_index) {
		old_domain = queue_cell_domain(runtime->affinity_cell_index);
		if (!old_domain)
			return -EINVAL;
		old_now			   = queue_domain_now(old_domain, fine);
		runtime->affinity_vruntime = queue_translate_vruntime(
			runtime->affinity_vruntime, old_now, new_now);
		runtime->affinity_cell_index = owner_cell_index;
		cell_stat_inc(ctx, owner_cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	} else if (runtime->affinity_cell_external_id != external_id ||
		   runtime->affinity_cell_epoch != slot_epoch) {
		runtime->affinity_vruntime = new_now;
		cell_stat_inc(ctx, owner_cell_index,
			      SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	}
	runtime->affinity_cell_index = owner_cell_index;
	runtime->affinity_cell_external_id = external_id;
	runtime->affinity_cell_epoch = slot_epoch;
	runtime->affinity_topology_generation = header->topology_generation;
	minimum = new_now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->affinity_vruntime, minimum)) {
		runtime->affinity_vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	return 0;
}

static __noinline bool queue_fairness_rehome_pending(
	const struct snake_ladder_ctx *ctx, struct task_struct *p,
	struct snake_task_runtime *runtime)
{
	struct snake_task_cell *annotation;

	if (!runtime || !runtime->cell_initialized)
		return false;
	annotation = task_annotation(p);
	if (annotation && READ_ONCE(annotation->needs_rehome))
		return true;
	return queue_task_cell_index(ctx, p) != runtime->cell_index;
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
	if (queue_fairness_rehome_pending(ctx, prev, runtime)) {
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

static __always_inline int queue_fairness_running(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	struct snake_queue_header *header = queue_config(ctx);
	struct snake_vtime_domain *domain;
	struct snake_cpu_queue	  *cpuq;
	u64			   adjusted_vruntime;
	u32			   active_weight, cpu;
	int			   ret;

	active_weight = runtime && runtime->active_weight ?
				runtime->active_weight :
				fairness_task_weight(p);
	queue_timing_complete_pending(runtime);

	if (runtime && runtime->cell_initialized && header &&
	    runtime->topology_generation !=
		    READ_ONCE(header->topology_generation)) {
		u32 cell_index =
			queue_fairness_resolve_runtime_cell(ctx, p, runtime);
		bool direct = runtime->direct_cell_valid;

		runtime = queue_fairness_prepare_task_for_cell(
			ctx, p, cell_index, false, fine);
		if (!runtime)
			return -EINVAL;
		if (direct) {
			runtime->direct_cell_index = cell_index;
			queue_clear_rehome_if_cell(ctx, p, cell_index);
			runtime->direct_cell_valid = 0;
		} else {
			stat_inc(ctx, SNAKE_STAT_QUEUE_STALE_REHOME_RUNS);
		}
	} else if (runtime && runtime->direct_cell_valid) {
		u32 cell_index = runtime->direct_cell_index;

		runtime = queue_fairness_prepare_task_for_cell(
			ctx, p, cell_index, false, fine);
		if (!runtime)
			return -EINVAL;
		runtime->direct_cell_index = cell_index;
		queue_clear_rehome_if_cell(ctx, p, cell_index);
		runtime->direct_cell_valid = 0;
	} else if (runtime && runtime->cell_initialized &&
		   runtime->queue_class == SNAKE_QUEUE_CLASS_NORMAL &&
		   queue_task_cell_index(ctx, p) != runtime->cell_index) {
		/* Charge an already-queued execution to the cell which queued it. */
		stat_inc(ctx, SNAKE_STAT_QUEUE_STALE_REHOME_RUNS);
	} else {
		runtime = queue_fairness_prepare_task(ctx, p, fine);
		if (!runtime)
			return -EINVAL;
	}
	cpu  = bpf_get_smp_processor_id();
	cpuq = queue_cpu(ctx, cpu);
	if (!cpuq)
		return -EINVAL;
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain)
		return -EINVAL;
	ret = queue_domain_run_start(ctx, domain, runtime->vruntime,
				     &adjusted_vruntime, fine);
	if (ret)
		return ret;
	runtime->vruntime = adjusted_vruntime;
	if (runtime->queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (queue_fairness_prepare_affinity(ctx, runtime,
						    cpuq->owner_cell_index, fine))
			return -EINVAL;
		domain = queue_cell_domain(cpuq->owner_cell_index);
		if (!domain)
			return -EINVAL;
		ret = queue_domain_advance(ctx, domain,
				   runtime->affinity_vruntime, fine);
		if (ret)
			return ret;
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
	struct snake_queue_header *header = queue_config(ctx);
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
	stat_add(ctx,
		 runtime->run_direct ? SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS :
				       SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS,
		 delta);
	if (!header || runtime->topology_generation !=
		       READ_ONCE(header->topology_generation)) {
		*runtime_ns = delta;
		return 0;
	}
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
		if (runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY &&
		    p->nr_cpus_allowed < nr_cpu_ids)
			cell_stat_add(ctx, runtime->run_owner_cell_index,
				      SNAKE_CELL_STAT_FOREIGN_AFFINITY_RUNTIME_NS, delta);
	}
	*runtime_ns = delta;
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_VTIME_H */
