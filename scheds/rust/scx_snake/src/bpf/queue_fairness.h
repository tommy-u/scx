/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_FAIRNESS_H
#define __SCX_SNAKE_QUEUE_FAIRNESS_H

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

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_task(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, true);
	struct snake_vtime_domain *old_domain, *new_domain;
	struct snake_task_cell    *annotation;
	u32			    cell_index;
	u64			    old_now, new_now;

	if (!runtime)
		return NULL;
	cell_index = queue_task_cell_index(p);
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
	if (annotation)
		WRITE_ONCE(annotation->needs_rehome, 0);
	runtime->active_weight  = fairness_task_weight(p);
	runtime->pending_weight = runtime->active_weight;
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable(struct snake_ladder_ctx *ctx,
				struct task_struct *p)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task(ctx, p);
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
queue_fairness_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		       u64 enq_flags)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_runnable(ctx, p);
	struct snake_queue_cell    *cell;
	struct snake_cpu_queue     *cpuq;
	s32			    target_cpu = -1;
	u64			    dsq_id, vtime;
	u64			    flags = enq_flags & ~SCX_ENQ_PREEMPT;

	if (!runtime)
		return -EINVAL;
	cell = queue_cell(runtime->cell_index);
	if (!cell)
		return -EINVAL;
	if (runtime->selected_cpu_valid &&
	    runtime->selected_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(runtime->selected_cpu, p->cpus_ptr))
		target_cpu = runtime->selected_cpu;
	runtime->selected_cpu_valid = 0;

	if (queue_primary_subset(cell, p)) {
		cpuq = target_cpu >= 0 ? queue_cpu(target_cpu) : NULL;
		if (!cpuq || cpuq->owner_cell_index != runtime->cell_index) {
			target_cpu = queue_pick_primary_cpu(cell, p, -1);
			if (target_cpu < 0)
				return target_cpu;
			cpuq = queue_cpu(target_cpu);
		}
		if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
			return -EINVAL;
		dsq_id = queue_normal_dsq(cpuq->normal_queue_index);
		vtime = runtime->vruntime;
		runtime->queue_class = SNAKE_QUEUE_CLASS_NORMAL;
		cell_stat_inc(ctx, runtime->cell_index,
			      SNAKE_CELL_STAT_NORMAL_ENQUEUES);
	} else {
		target_cpu = queue_pick_allowed_cpu(p, target_cpu);
		if (target_cpu < 0)
			return target_cpu;
		if (queue_fairness_prepare_affinity(ctx, runtime))
			return -EINVAL;
		dsq_id = queue_affinity_dsq(target_cpu);
		vtime = runtime->affinity_vruntime;
		runtime->queue_class = SNAKE_QUEUE_CLASS_AFFINITY;
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
		cell_stat_inc(ctx, runtime->cell_index,
			      SNAKE_CELL_STAT_AFFINITY_ENQUEUES);
	}
	runtime->run_direct = 0;
	if (!scx_bpf_dsq_insert_vtime(p, dsq_id, SNAKE_VTIME_SLICE_NS,
				       vtime, flags))
		return -EINVAL;
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
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

static __always_inline int
queue_fairness_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
			struct task_struct *prev)
{
	struct snake_cpu_queue *cpuq = queue_cpu(cpu);
	struct snake_queue_cell *cell;
	struct snake_queue_cpu_state *state;
	u64 affinity_id = queue_affinity_dsq(cpu), normal_id;
	u64 affinity_vtime = 0, normal_vtime = 0;
	u32 key = 0, normal_index, first_class, second_class;
	s32 local_queued, keep;
	bool affinity_ready, normal_ready;

	if (!cpuq)
		return -EINVAL;
	local_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
	if (local_queued < 0)
		return local_queued;
	if (local_queued > 0)
		return 0;
	cell = queue_cell(cpuq->owner_cell_index);
	if (!cell)
		return -EINVAL;
	normal_index = cpuq->normal_queue_index;
	normal_id = queue_normal_dsq(normal_index);
	normal_ready = queue_fairness_head(normal_id, &normal_vtime);
	if (!normal_ready && queue_fairness_remote_normal(cell, normal_index,
							 &normal_index,
							 &normal_vtime)) {
		normal_id = queue_normal_dsq(normal_index);
		normal_ready = true;
	}
	affinity_ready = queue_fairness_head(affinity_id, &affinity_vtime);
	state = bpf_map_lookup_elem(&queue_cpu_states, &key);
	if (!state)
		return -EINVAL;
	if (!state->initialized) {
		state->next_class = SNAKE_QUEUE_CLASS_AFFINITY;
		state->initialized = 1;
	}
	if (!normal_ready && !affinity_ready)
		goto keep_running;
	if (!normal_ready)
		first_class = SNAKE_QUEUE_CLASS_AFFINITY;
	else if (!affinity_ready)
		first_class = SNAKE_QUEUE_CLASS_NORMAL;
	else
		first_class = state->next_class;
	second_class = first_class == SNAKE_QUEUE_CLASS_NORMAL ?
			       SNAKE_QUEUE_CLASS_AFFINITY :
			       SNAKE_QUEUE_CLASS_NORMAL;
	keep = first_class == SNAKE_QUEUE_CLASS_NORMAL ?
		       queue_fairness_keep_running(ctx, prev, first_class,
					   normal_vtime) :
		       queue_fairness_keep_running(ctx, prev, first_class,
					   affinity_vtime);
	if (keep < 0)
		return keep;
	if (keep)
		return 0;
	if ((first_class == SNAKE_QUEUE_CLASS_NORMAL &&
	     queue_fairness_move(ctx, normal_id, first_class)) ||
	    (first_class == SNAKE_QUEUE_CLASS_AFFINITY &&
	     queue_fairness_move(ctx, affinity_id, first_class))) {
		state->next_class = second_class;
		return 0;
	}
	keep = second_class == SNAKE_QUEUE_CLASS_NORMAL && normal_ready ?
		       queue_fairness_keep_running(ctx, prev, second_class,
					   normal_vtime) :
	       second_class == SNAKE_QUEUE_CLASS_AFFINITY && affinity_ready ?
		       queue_fairness_keep_running(ctx, prev, second_class,
					   affinity_vtime) :
		       0;
	if (keep < 0)
		return keep;
	if (keep)
		return 0;
	if ((second_class == SNAKE_QUEUE_CLASS_NORMAL && normal_ready &&
	     queue_fairness_move(ctx, normal_id, second_class)) ||
	    (second_class == SNAKE_QUEUE_CLASS_AFFINITY && affinity_ready &&
	     queue_fairness_move(ctx, affinity_id, second_class))) {
		state->next_class = first_class;
		return 0;
	}

keep_running:
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = SNAKE_VTIME_SLICE_NS;
	return 0;
}

static __always_inline int
queue_fairness_running(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task(ctx, p);
	struct snake_vtime_domain *domain;
	struct snake_cpu_queue    *cpuq;
	u32			    cpu;

	if (!runtime)
		return -EINVAL;
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
	stat_add(ctx, SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS, delta);
	*runtime_ns = delta;
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_FAIRNESS_H */
