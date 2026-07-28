/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_FAIRNESS_H
#define __SCX_SNAKE_QUEUE_FAIRNESS_H

static __noinline s32
queue_pick_random_idle_cpu(const struct cpumask *candidates, bool whole_core)
{
	const struct cpumask *idle;
	u32 candidates_seen = 0, cpu;
	s32 selected = -1;
	bool claimed;

	idle = whole_core ? scx_bpf_get_idle_smtmask() :
			    scx_bpf_get_idle_cpumask();
	if (!idle)
		return -EINVAL;
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		if (bpf_cpumask_test_cpu(cpu, candidates) &&
		    bpf_cpumask_test_cpu(cpu, idle)) {
			candidates_seen++;
			if (bpf_get_prandom_u32() % candidates_seen == 0)
				selected = cpu;
		}
	}
	if (selected < 0) {
		scx_bpf_put_idle_cpumask(idle);
		return -ENOENT;
	}
	claimed = scx_bpf_test_and_clear_cpu_idle(selected);
	scx_bpf_put_idle_cpumask(idle);
	return claimed ? selected : -ENOENT;
}

static __always_inline s32
queue_pick_task_cell_cpu(struct task_struct *p, u32 kind, bool whole_core,
			 bool random, u32 *cell_indexp)
{
	struct snake_task_runtime *runtime;
	struct bpf_cpumask	 *scratch;
	const struct cpumask       *source;
	u32			    cell_index;
	s32			    selected;

	runtime = bpf_task_storage_get(&task_runtimes, p, NULL, 0);
	cell_index = queue_task_cell_index(p);
	source = queue_cell_mask(cell_index, kind);
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

static __always_inline u64
queue_translate_vruntime(u64 vruntime, u64 old_now, u64 new_now)
{
	s64 lag = (s64)(vruntime - old_now);

	if (lag > (s64)SNAKE_VTIME_SLICE_NS)
		lag = SNAKE_VTIME_SLICE_NS;
	else if (lag < -(s64)SNAKE_VTIME_SLICE_NS)
		lag = -(s64)SNAKE_VTIME_SLICE_NS;
	return new_now + lag;
}

static __noinline void
queue_clear_rehome_if_cell(struct task_struct *p, u32 cell_index)
{
	struct snake_queue_cell *cell;
	struct snake_task_cell  *annotation;
	u32			 external_id;

	cell = queue_cell(cell_index);
	if (!cell)
		return;
	external_id = READ_ONCE(cell->external_id);
	annotation = bpf_task_storage_get(&task_cells, p, NULL, 0);
	if (!annotation || READ_ONCE(annotation->cell_id) != external_id)
		return;
	WRITE_ONCE(annotation->needs_rehome, 0);
	if (READ_ONCE(annotation->cell_id) != external_id)
		WRITE_ONCE(annotation->needs_rehome, 1);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task_for_cell(struct snake_ladder_ctx *ctx,
				     struct task_struct *p, u32 cell_index,
				     bool clear_rehome)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, true);
	struct snake_vtime_domain *old_domain, *new_domain;
	struct snake_task_cell    *annotation;
	u64			    old_now, new_now;

	if (!runtime)
		return NULL;
	new_domain = queue_cell_domain(cell_index);
	if (!new_domain) {
		fairness_accounting_error(ctx);
		return NULL;
	}
	if (!runtime->cell_initialized) {
		runtime->vruntime = queue_domain_now(new_domain);
		runtime->cell_index = cell_index;
		runtime->cell_initialized = 1;
	} else if (runtime->cell_index != cell_index) {
		old_domain = queue_cell_domain(runtime->cell_index);
		if (!old_domain) {
			fairness_accounting_error(ctx);
			return NULL;
		}
		old_now = queue_domain_now(old_domain);
		new_now = queue_domain_now(new_domain);
		runtime->vruntime = queue_translate_vruntime(runtime->vruntime,
						      old_now, new_now);
		runtime->cell_index = cell_index;
		cell_stat_inc(ctx, cell_index, SNAKE_CELL_STAT_CLOCK_TRANSITIONS);
	}
	annotation = bpf_task_storage_get(&task_cells, p, NULL, 0);
	if (clear_rehome && annotation)
		WRITE_ONCE(annotation->needs_rehome, 0);
	runtime->active_weight  = fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	return queue_fairness_prepare_task_for_cell(
		ctx, p, queue_task_cell_index(p), true);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable_for_cell(struct snake_ladder_ctx *ctx,
					 struct task_struct *p, u32 cell_index,
					 bool clear_rehome)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task_for_cell(
		ctx, p, cell_index, clear_rehome);
	struct snake_vtime_domain *domain;
	u64			    minimum, now;

	if (!runtime)
		return NULL;
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain) {
		fairness_accounting_error(ctx);
		return NULL;
	}
	now = queue_domain_now(domain);
	minimum = now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->vruntime, minimum)) {
		runtime->vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable(struct snake_ladder_ctx *ctx,
				struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (runtime && runtime->direct_cell_valid)
		return queue_fairness_prepare_runnable_for_cell(
			ctx, p, runtime->direct_cell_index, false);
	return queue_fairness_prepare_runnable_for_cell(
		ctx, p, queue_task_cell_index(p), true);
}

static __noinline void
queue_fairness_cancel_direct(struct snake_ladder_ctx *ctx,
			     struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (runtime)
		runtime->direct_cell_valid = 0;
}

static __always_inline int
queue_fairness_prepare_affinity(struct snake_ladder_ctx *ctx,
				struct snake_task_runtime *runtime)
{
	struct snake_vtime_domain *domain = fairness_vtime_domain();
	u64			    minimum, now;

	if (!domain || !runtime)
		return -EINVAL;
	now = queue_domain_now(domain);
	if (!runtime->affinity_initialized) {
		runtime->affinity_vruntime = now;
		runtime->affinity_initialized = 1;
	}
	minimum = now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->affinity_vruntime, minimum)) {
		runtime->affinity_vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	return 0;
}

static __always_inline int
queue_fairness_select_cpu(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  s32 cpu)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task(ctx, p);

	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	runtime->selected_cpu = cpu;
	runtime->selected_cpu_valid = 1;
	return 0;
}

static __always_inline int
queue_fairness_direct_borrow(struct snake_ladder_ctx *ctx, struct task_struct *p,
			     s32 cpu, u32 cell_index)
{
	struct snake_task_runtime *runtime;
	struct snake_queue_cell    *cell;
	struct snake_cpu_queue     *cpuq;

	runtime = queue_fairness_prepare_runnable_for_cell(
		ctx, p, cell_index, false);
	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;
	cell = queue_cell(cell_index);
	cpuq = queue_cpu(cpu);
	if (!cell || !cpuq || !queue_mask_contains(&cell->borrowable, cpu) ||
	    cpuq->owner_cell_index == cell_index)
		return -EINVAL;
	runtime->selected_cpu_valid = 0;
	runtime->queue_class = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct = 1;
	runtime->direct_cell_index = cell_index;
	runtime->direct_cell_valid = 1;
	if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SNAKE_VTIME_SLICE_NS, 0))
		return -EINVAL;
	return 0;
}

static __always_inline int
queue_fairness_enqueue_cell(struct snake_ladder_ctx *ctx, struct task_struct *p,
			    struct snake_task_runtime *runtime,
			    s32 selected_cpu, u64 enq_flags)
{
	struct snake_queue_cell    *cell;
	struct snake_cpu_queue     *cpuq;
	s32			    target_cpu = selected_cpu;
	u64			    flags = enq_flags & ~SCX_ENQ_PREEMPT;

	cell = queue_cell(runtime->cell_index);
	if (!cell)
		return -EINVAL;
	if (!queue_primary_subset(cell, p))
		return -ENOENT;
	cpuq = target_cpu >= 0 ? queue_cpu(target_cpu) : NULL;
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index) {
		target_cpu = queue_pick_primary_cpu(cell, p, -1);
		if (target_cpu < 0)
			return target_cpu;
		cpuq = queue_cpu(target_cpu);
	}
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		return -EINVAL;
	runtime->queue_class = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct = 0;
	runtime->direct_cell_valid = 0;
	if (!scx_bpf_dsq_insert_vtime(p,
				       queue_normal_dsq(cpuq->normal_queue_index),
				       SNAKE_VTIME_SLICE_NS, runtime->vruntime,
				       flags))
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index, SNAKE_CELL_STAT_NORMAL_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline int
queue_fairness_enqueue_affinity(struct snake_ladder_ctx *ctx,
				struct task_struct *p,
				struct snake_task_runtime *runtime,
				s32 selected_cpu, u64 enq_flags)
{
	s32 target_cpu = queue_pick_allowed_cpu(p, selected_cpu);
	u64 flags = enq_flags & ~SCX_ENQ_PREEMPT;

	if (target_cpu < 0)
		return target_cpu;
	if (queue_fairness_prepare_affinity(ctx, runtime))
		return -EINVAL;
	runtime->queue_class = SNAKE_QUEUE_CLASS_AFFINITY;
	runtime->run_direct = 0;
	runtime->direct_cell_valid = 0;
	if (!scx_bpf_dsq_insert_vtime(p, queue_affinity_dsq(target_cpu),
				       SNAKE_VTIME_SLICE_NS,
				       runtime->affinity_vruntime, flags))
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index,
		      SNAKE_CELL_STAT_AFFINITY_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	return 0;
}

static __always_inline bool queue_fairness_head(u64 dsq_id, u64 *vtime)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	if (!p)
		return false;
	*vtime = READ_ONCE(p->scx.dsq_vtime);
	return true;
}

static __always_inline bool
queue_fairness_remote_normal(struct snake_queue_cell *cell, u32 local_queue,
			     u32 *queue_index, u64 *vtime)
{
	u32 offset;
	bool found = false;

	bpf_for(offset, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		u32 index;
		u64 candidate;

		if (offset >= cell->nr_normal_queues)
			break;
		index = cell->first_normal_queue + offset;
		if (index == local_queue ||
		    !queue_fairness_head(queue_normal_dsq(index), &candidate))
			continue;
		if (!found || time_before(candidate, *vtime)) {
			*queue_index = index;
			*vtime = candidate;
			found = true;
		}
	}
	return found;
}

static __always_inline bool
queue_fairness_move(struct snake_ladder_ctx *ctx, u64 dsq_id, u32 class)
{
	if (!scx_bpf_dsq_move_to_local(dsq_id, 0))
		return false;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return true;
}

static __always_inline bool
queue_fairness_rehome_pending(struct task_struct *p,
			      struct snake_task_runtime *runtime)
{
	struct snake_task_cell *annotation;

	if (!runtime || !runtime->cell_initialized)
		return false;
	annotation = bpf_task_storage_get(&task_cells, p, NULL, 0);
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

static __always_inline s32
queue_fairness_keep_running(struct snake_ladder_ctx *ctx,
			    struct task_struct *prev, u32 class,
			    u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64			   current, delta, projected, vruntime;
	u32			   weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	if (runtime->run_queue_class != class)
		return 0;
	current = prev->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -ERANGE;
	}
	delta = current - runtime->started_exec_runtime;
	weight = runtime->active_weight ?: fairness_task_weight(prev);
	vruntime = class == SNAKE_QUEUE_CLASS_AFFINITY ?
			 runtime->affinity_vruntime :
			 runtime->vruntime;
	projected = vruntime + fairness_scale_inverse(delta, weight);
	if (time_before(candidate_vtime, projected))
		return 0;
	prev->scx.slice = SNAKE_VTIME_SLICE_NS;
	return 1;
}

static __always_inline s32
queue_fairness_dispatch_source(struct snake_ladder_ctx *ctx,
			       struct snake_cpu_queue *cpuq, s32 cpu,
			       struct task_struct *prev, u32 opcode)
{
	struct snake_queue_cell *cell;
	u64 dsq_id, candidate_vtime = 0;
	u32 class, normal_index;
	s32 keep;

	if (!cpuq)
		return -EINVAL;
	if (opcode == SNAKE_DISPATCH_OP_CELL) {
		cell = queue_cell(cpuq->owner_cell_index);
		if (!cell)
			return -EINVAL;
		normal_index = cpuq->normal_queue_index;
		dsq_id = queue_normal_dsq(normal_index);
		if (!queue_fairness_head(dsq_id, &candidate_vtime)) {
			if (!queue_fairness_remote_normal(cell, normal_index,
						  &normal_index,
						  &candidate_vtime))
				return 0;
			dsq_id = queue_normal_dsq(normal_index);
		}
		class = SNAKE_QUEUE_CLASS_NORMAL;
	} else if (opcode == SNAKE_DISPATCH_OP_AFFINITY) {
		dsq_id = queue_affinity_dsq(cpu);
		if (!queue_fairness_head(dsq_id, &candidate_vtime))
			return 0;
		class = SNAKE_QUEUE_CLASS_AFFINITY;
	} else {
		return -EINVAL;
	}

	keep = queue_fairness_keep_running(ctx, prev, class, candidate_vtime);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	return queue_fairness_move(ctx, dsq_id, class) ? 1 : 0;
}

static __always_inline int
queue_fairness_replenish(struct snake_ladder_ctx *ctx, struct task_struct *prev)
{
	struct snake_task_runtime *runtime;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	prev->scx.slice = SNAKE_VTIME_SLICE_NS;
	return 0;
}

static __always_inline int
queue_fairness_running(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	struct snake_vtime_domain *domain;
	struct snake_cpu_queue    *cpuq;
	u32			    cpu;

	if (runtime && runtime->direct_cell_valid) {
		u32 direct_cell_index = runtime->direct_cell_index;

		runtime = queue_fairness_prepare_task_for_cell(
			ctx, p, direct_cell_index, false);
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
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain)
		return -EINVAL;
	bpf_spin_lock(&domain->lock);
	if (time_before(domain->vtime_now, runtime->vruntime))
		domain->vtime_now = runtime->vruntime;
	bpf_spin_unlock(&domain->lock);
	if (runtime->queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		domain = fairness_vtime_domain();
		if (!domain)
			return -EINVAL;
		bpf_spin_lock(&domain->lock);
		if (time_before(domain->vtime_now, runtime->affinity_vruntime))
			domain->vtime_now = runtime->affinity_vruntime;
		bpf_spin_unlock(&domain->lock);
	}
	cpu = bpf_get_smp_processor_id();
	cpuq = queue_cpu(cpu);
	if (!cpuq)
		return -EINVAL;
	runtime->run_cell_index = runtime->cell_index;
	runtime->run_owner_cell_index = cpuq ? cpuq->owner_cell_index : 0;
	runtime->run_queue_class = runtime->queue_class;
	runtime->active_weight = fairness_task_weight(p);
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->runtime_valid = 1;
	cell_stat_inc(ctx, runtime->run_cell_index,
		      runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY ?
			      SNAKE_CELL_STAT_AFFINITY_DISPATCHES :
				      SNAKE_CELL_STAT_NORMAL_DISPATCHES);
	return 0;
}

static __always_inline int
queue_fairness_stopping(struct snake_ladder_ctx *ctx, struct task_struct *p,
			 u64 *runtime_ns)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	u64 current, delta, scaled;
	u32 weight;

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
	delta = current - runtime->started_exec_runtime;
	weight = runtime->active_weight ?: fairness_task_weight(p);
	scaled = fairness_scale_inverse(delta, weight);
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

#endif /* __SCX_SNAKE_QUEUE_FAIRNESS_H */
