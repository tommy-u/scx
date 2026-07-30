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

	runtime = task_state_lookup(p);
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
	annotation = task_annotation(p);
	if (!annotation || READ_ONCE(annotation->cell_id) != external_id)
		return;
	WRITE_ONCE(annotation->needs_rehome, 0);
	if (READ_ONCE(annotation->cell_id) != external_id)
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
	struct snake_task_cell    *annotation;
	u64			    old_now, new_now, stage_started_at;

	stage_started_at = fine_timing_start(fine);
	runtime = fairness_task(ctx, p, true);
	fine_timing_finish(fine,
			   SNAKE_FINE_TIMING_ENQUEUE_PREPARE_TASK_STORAGE,
			   stage_started_at);
	if (!runtime)
		return NULL;
	stage_started_at = fine_timing_start(fine);
	new_domain = queue_cell_domain(cell_index);
	if (!new_domain) {
		fine_timing_finish(fine,
			SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
			stage_started_at);
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
			fine_timing_finish(
				fine,
				SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
				stage_started_at);
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
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
			   stage_started_at);
	annotation = task_annotation(p);
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
		ctx, p, queue_task_cell_index(p), true, NULL);
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable_for_cell(struct snake_ladder_ctx *ctx,
					 struct task_struct *p, u32 cell_index,
					 bool clear_rehome,
					 const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task_for_cell(
		ctx, p, cell_index, clear_rehome, fine);
	struct snake_vtime_domain *domain;
	u64			    minimum, now, stage_started_at;

	if (!runtime)
		return NULL;
	stage_started_at = fine_timing_start(fine);
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain) {
		fine_timing_finish(fine,
			SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CREDIT_CLAMP,
			stage_started_at);
		fairness_accounting_error(ctx);
		return NULL;
	}
	now = queue_domain_now(domain);
	minimum = now - SNAKE_VTIME_SLICE_NS;
	if (time_before(runtime->vruntime, minimum)) {
		runtime->vruntime = minimum;
		stat_inc(ctx, SNAKE_STAT_VTIME_CREDIT_CLAMPS);
	}
	fine_timing_finish(fine,
			   SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CREDIT_CLAMP,
			   stage_started_at);
	return runtime;
}

static __always_inline struct snake_task_runtime *
queue_fairness_prepare_runnable(struct snake_ladder_ctx *ctx,
				struct task_struct *p,
				const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	u64 stage_started_at = fine_timing_start(fine);

	runtime = fairness_task(ctx, p, false);
	fine_timing_finish(fine,
			   SNAKE_FINE_TIMING_ENQUEUE_PREPARE_ROUTE_LOOKUP,
			   stage_started_at);

	if (runtime && runtime->direct_cell_valid)
		return queue_fairness_prepare_runnable_for_cell(
			ctx, p, runtime->direct_cell_index, false, fine);
	return queue_fairness_prepare_runnable_for_cell(
		ctx, p, queue_task_cell_index(p), true, fine);
}

static __noinline void
queue_fairness_cancel_direct(struct snake_ladder_ctx *ctx,
			     struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);

	if (runtime) {
		runtime->direct_cell_valid = 0;
		queue_timing_cancel_runtime(runtime);
	}
}

static __always_inline int
queue_fairness_prepare_affinity(struct snake_ladder_ctx *ctx,
				struct snake_task_runtime *runtime,
				u32 owner_cell_index)
{
	struct snake_vtime_domain *task_domain, *old_domain, *new_domain;
	u64			    minimum, task_now, old_now, new_now;

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
		task_now = queue_domain_now(task_domain);
		runtime->affinity_vruntime = queue_translate_vruntime(
			runtime->vruntime, task_now, new_now);
		runtime->affinity_cell_index = owner_cell_index;
		runtime->affinity_initialized = 1;
	} else if (runtime->affinity_cell_index != owner_cell_index) {
		old_domain = queue_cell_domain(runtime->affinity_cell_index);
		if (!old_domain)
			return -EINVAL;
		old_now = queue_domain_now(old_domain);
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

static __always_inline int
queue_fairness_select_cpu(struct snake_ladder_ctx *ctx, struct task_struct *p,
			  s32 cpu)
{
	struct snake_task_runtime *runtime = queue_fairness_prepare_task(ctx, p);

	return task_route_record_selected_cpu(runtime, cpu);
}

static __always_inline int
queue_fairness_direct_borrow(struct snake_ladder_ctx *ctx, struct task_struct *p,
				     s32 cpu, u32 cell_index,
				     const struct snake_fine_timing_ctx *fine)
{
	struct snake_task_runtime *runtime;
	struct snake_queue_cell    *cell;
	struct snake_cpu_queue     *cpuq;

	runtime = queue_fairness_prepare_runnable_for_cell(
		ctx, p, cell_index, false, NULL);
	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;
	cell = queue_cell(cell_index);
	cpuq = queue_cpu(cpu);
	if (!cell || !cpuq || !queue_mask_contains(&cell->borrowable, cpu) ||
	    cpuq->owner_cell_index == cell_index)
		return -EINVAL;
	task_route_clear_selected_cpu(runtime);
	runtime->queue_class = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct = 1;
	runtime->direct_cell_index = cell_index;
	runtime->direct_cell_valid = 1;
	if (!dsq_insert_local(p, cpu,
			      fairness_vtime_slice(runtime->active_weight), 0,
			      fine))
		return -EINVAL;
	queue_timing_record_insert(ctx, p, dsq_local_on(cpu), cell_index, fine);
	return 0;
}

static __always_inline int
queue_fairness_enqueue_cell(struct snake_ladder_ctx *ctx, struct task_struct *p,
			    struct snake_task_runtime *runtime,
			    s32 selected_cpu, u64 enq_flags,
			    const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell    *cell;
	struct snake_cpu_queue     *cpuq = NULL;
	const struct cpumask       *primary;
	s32			    target_cpu = selected_cpu;
	s32			    ret = 0;
	u64			    flags = enq_flags & ~SCX_ENQ_PREEMPT;
	u64			    stage_started_at;
	dsq_id_t		    dsq;

	stage_started_at = fine_timing_start(fine);
	cell = queue_cell(runtime->cell_index);
	primary = queue_cell_mask(runtime->cell_index, SNAKE_QUEUE_MASK_PRIMARY);
	if (!cell || !primary)
		ret = -EINVAL;
	else if (!queue_primary_subset(primary, p))
		ret = -ENOENT;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_CELL_VALIDATE,
			   stage_started_at);
	if (ret)
		return ret;

	stage_started_at = fine_timing_start(fine);
	cpuq = target_cpu >= 0 ? queue_cpu(target_cpu) : NULL;
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		target_cpu = queue_pick_primary_cpu(
			primary, runtime->queue_cpumask, p, -1);
	if (target_cpu < 0)
		ret = target_cpu;
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_PICK_TARGET,
			   stage_started_at);
	if (ret)
		return ret;
	cpuq = queue_cpu(target_cpu);
	if (!cpuq || cpuq->owner_cell_index != runtime->cell_index)
		return -EINVAL;

	runtime->queue_class = SNAKE_QUEUE_CLASS_NORMAL;
	runtime->run_direct = 0;
	runtime->direct_cell_valid = 0;
	stage_started_at = fine_timing_start(fine);
	dsq = dsq_normal(cpuq->normal_queue_index);
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->vruntime, flags, fine)) {
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_ENQUEUE_NORMAL_DSQ_INSERT,
				   stage_started_at);
		return -EINVAL;
	}
	queue_timing_record_insert(ctx, p, dsq, runtime->cell_index, fine);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_NORMAL_DSQ_INSERT,
			   stage_started_at);
	stage_started_at = fine_timing_start(fine);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index, SNAKE_CELL_STAT_NORMAL_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_NORMAL_ACCOUNT_KICK,
			   stage_started_at);
	return 0;
}

static __always_inline int
queue_fairness_enqueue_affinity(struct snake_ladder_ctx *ctx,
				struct task_struct *p,
				struct snake_task_runtime *runtime,
				s32 selected_cpu, u64 enq_flags,
				const struct snake_fine_timing_ctx *fine)
{
	struct snake_cpu_queue *cpuq;
	s32 target_cpu = queue_pick_allowed_cpu(p, selected_cpu);
	s32 ret = 0;
	u64 flags = enq_flags & ~SCX_ENQ_PREEMPT;
	u64 stage_started_at = fine_timing_start(fine);
	u64 insert_started_at;
	dsq_id_t dsq;

	if (target_cpu < 0) {
		ret = target_cpu;
		goto out;
	}
	cpuq = queue_cpu(target_cpu);
	if (!cpuq || queue_fairness_prepare_affinity(
			     ctx, runtime, cpuq->owner_cell_index)) {
		ret = -EINVAL;
		goto out;
	}
	runtime->queue_class = SNAKE_QUEUE_CLASS_AFFINITY;
	runtime->run_direct = 0;
	runtime->direct_cell_valid = 0;
	dsq = dsq_affinity(target_cpu);
	insert_started_at = fine_timing_start(fine);
	if (!dsq_insert_vtime(p, dsq,
			      fairness_vtime_slice(runtime->active_weight),
			      runtime->affinity_vruntime, flags, fine)) {
		fine_timing_finish(
			fine, SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_DSQ_INSERT,
			insert_started_at);
		ret = -EINVAL;
		goto out;
	}
	queue_timing_record_insert(ctx, p, dsq, runtime->cell_index, fine);
	fine_timing_finish(fine,
			   SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_DSQ_INSERT,
			   insert_started_at);
	stat_inc(ctx, SNAKE_STAT_VTIME_ENQUEUES);
	stat_inc(ctx, SNAKE_STAT_VTIME_CPU_ENQUEUES);
	cell_stat_inc(ctx, runtime->cell_index,
		      SNAKE_CELL_STAT_AFFINITY_ENQUEUES);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
out:
	fine_timing_finish(fine, SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_PATH,
			   stage_started_at);
	return ret;
}

static __always_inline bool queue_fairness_head(dsq_id_t dsq, u64 *vtime)
{
	struct task_struct *p = dsq_peek(dsq);

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
			    !queue_fairness_head(dsq_normal(index), &candidate))
			continue;
		if (!found || time_before(candidate, *vtime)) {
			*queue_index = index;
			*vtime = candidate;
			found = true;
		}
	}
	return found;
}

static __always_inline u32
queue_fairness_remote_scan_stage(const struct snake_queue_cell *cell)
{
	u32 nr_queues = READ_ONCE(cell->nr_normal_queues);

	if (nr_queues <= 1)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_1_QUEUE;
	if (nr_queues <= 4)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_2_4_QUEUES;
	if (nr_queues <= 8)
		return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_5_8_QUEUES;
	return SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_9_PLUS_QUEUES;
}

static __always_inline bool
queue_fairness_move(struct snake_ladder_ctx *ctx, dsq_id_t dsq, s32 cpu,
		    u32 class, const struct snake_fine_timing_ctx *fine)
{
	bool moved = dsq_move_to_local(dsq, cpu, fine);

	if (!moved)
		return false;
	stat_inc(ctx, SNAKE_STAT_VTIME_DISPATCHES);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		stat_inc(ctx, SNAKE_STAT_VTIME_CPU_DISPATCHES);
	return true;
}

struct snake_queue_candidate {
	dsq_id_t dsq;
	u64 vtime;
	u32 class;
	u32 valid;
};

static __always_inline int
queue_fairness_normal_candidate(struct snake_cpu_queue *cpuq,
				struct snake_queue_candidate *candidate,
				const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	u32 normal_index;
	u64 stage_started_at;
	bool found;

	if (!cpuq || !candidate)
		return -EINVAL;
	candidate->valid = 0;
	cell = queue_cell(cpuq->owner_cell_index);
	if (!cell)
		return -EINVAL;
	normal_index = cpuq->normal_queue_index;
	candidate->dsq = dsq_normal(normal_index);
	stage_started_at = fine_timing_start(fine);
	found = queue_fairness_head(candidate->dsq, &candidate->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
			   stage_started_at);
	if (!found) {
		stage_started_at = fine_timing_start(fine);
		found = queue_fairness_remote_normal(cell, normal_index,
					     &normal_index,
					     &candidate->vtime);
		fine_timing_finish(fine, queue_fairness_remote_scan_stage(cell),
				   stage_started_at);
		if (!found)
			return 0;
		candidate->dsq = dsq_normal(normal_index);
	}
	candidate->class = SNAKE_QUEUE_CLASS_NORMAL;
	candidate->valid = 1;
	return 0;
}

static __always_inline int
queue_fairness_affinity_candidate(s32 cpu,
				  struct snake_queue_candidate *candidate)
{
	if (!candidate || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	candidate->valid = 0;
	candidate->dsq = dsq_affinity(cpu);
	if (!queue_fairness_head(candidate->dsq, &candidate->vtime))
		return 0;
	candidate->class = SNAKE_QUEUE_CLASS_AFFINITY;
	candidate->valid = 1;
	return 0;
}

static __always_inline bool
queue_fairness_rehome_pending(struct task_struct *p,
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

static __always_inline s32
queue_fairness_keep_running(struct snake_ladder_ctx *ctx,
			    struct snake_cpu_queue *cpuq,
			    struct task_struct *prev, u32 class,
			    u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64			   current, delta, projected, service, vruntime;
	u32			   weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid || !cpuq)
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
	if (runtime->run_owner_cell_index != cpuq->owner_cell_index)
		return 0;
	if (class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (!runtime->affinity_initialized)
			return -EINVAL;
		if (runtime->affinity_cell_index != cpuq->owner_cell_index)
			return 0;
	} else if (runtime->run_cell_index != cpuq->owner_cell_index) {
		return 0;
	}
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
	service = fairness_vtime_service(
		delta, runtime->service_budget, prev->scx.slice);
	projected = vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return 0;
	fairness_vtime_replenish(runtime, prev, weight);
	return 1;
}

static __always_inline s32
queue_fairness_keep_running_min(struct snake_ladder_ctx *ctx,
				struct snake_cpu_queue *cpuq,
				struct task_struct *prev, u64 candidate_vtime)
{
	struct snake_task_runtime *runtime;
	u64 current, delta, projected, service, vruntime;
	u32 weight;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return 0;
	runtime = fairness_task(ctx, prev, false);
	if (!runtime || !runtime->runtime_valid || !cpuq)
		return -EINVAL;
	if (queue_fairness_direct_borrowed(runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_BORROW_YIELDS);
		return 0;
	}
	if (queue_fairness_rehome_pending(prev, runtime)) {
		stat_inc(ctx, SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS);
		return 0;
	}
	/* A core-retained prev from another cell clock cannot enter this order. */
	if (runtime->run_owner_cell_index != cpuq->owner_cell_index)
		return 0;
	if (runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY) {
		if (!runtime->affinity_initialized)
			return -EINVAL;
		if (runtime->affinity_cell_index != cpuq->owner_cell_index)
			return 0;
		vruntime = runtime->affinity_vruntime;
	} else {
		if (runtime->run_queue_class != SNAKE_QUEUE_CLASS_NORMAL)
			return -EINVAL;
		/* Borrowed normal work remains charged to its task cell clock. */
		if (runtime->run_cell_index != cpuq->owner_cell_index)
			return 0;
		vruntime = runtime->vruntime;
	}
	current = prev->se.sum_exec_runtime;
	if (current < runtime->started_exec_runtime) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return -ERANGE;
	}
	delta = current - runtime->started_exec_runtime;
	weight = runtime->active_weight ?: fairness_task_weight(prev);
	service = fairness_vtime_service(
		delta, runtime->service_budget, prev->scx.slice);
	projected = vruntime + fairness_scale_inverse(service, weight);
	if (time_before(candidate_vtime, projected))
		return 0;
	fairness_vtime_replenish(runtime, prev, weight);
	return 1;
}

static __always_inline s32
queue_fairness_dispatch_min(struct snake_ladder_ctx *ctx,
			    struct snake_cpu_queue *cpuq, s32 cpu,
			    struct task_struct *prev, u32 *equal_preference,
			    const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_candidate normal = {}, affinity = {};
	struct snake_queue_candidate *winner, *loser;
	s32 keep, ret;
	u64 stage_started_at;

	if (!equal_preference)
		return -EINVAL;
	ret = queue_fairness_normal_candidate(cpuq, &normal, fine);
	if (ret)
		return ret;
	stage_started_at = fine_timing_start(fine);
	ret = queue_fairness_affinity_candidate(cpu, &affinity);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
			   stage_started_at);
	if (ret)
		return ret;
	stage_started_at = fine_timing_start(fine);
	if (!normal.valid && !affinity.valid) {
		fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
				   stage_started_at);
		return 0;
	}
	if (!affinity.valid ||
	    (normal.valid && time_before(normal.vtime, affinity.vtime))) {
		winner = &normal;
		loser = affinity.valid ? &affinity : NULL;
	} else if (!normal.valid || time_before(affinity.vtime, normal.vtime)) {
		winner = &affinity;
		loser = normal.valid ? &normal : NULL;
	} else {
		stat_inc(ctx, SNAKE_STAT_VTIME_EQUAL_HEAD_TIES);
		if (*equal_preference == SNAKE_QUEUE_CLASS_AFFINITY) {
			winner = &affinity;
			loser = &normal;
			*equal_preference = SNAKE_QUEUE_CLASS_NORMAL;
		} else {
			winner = &normal;
			loser = &affinity;
			*equal_preference = SNAKE_QUEUE_CLASS_AFFINITY;
		}
	}
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
			   stage_started_at);

	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, winner->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	ret = queue_fairness_move(ctx, winner->dsq, cpu, winner->class, fine);
	if (ret)
		return 1;
	if (!loser)
		return 0;
	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running_min(ctx, cpuq, prev, loser->vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	ret = queue_fairness_move(ctx, loser->dsq, cpu, loser->class, fine);
	return ret ? 1 : 0;
}

static __always_inline s32
queue_fairness_dispatch_source(struct snake_ladder_ctx *ctx,
			       struct snake_cpu_queue *cpuq, s32 cpu,
			       struct task_struct *prev, u32 opcode,
			       const struct snake_fine_timing_ctx *fine)
{
	struct snake_queue_cell *cell;
	dsq_id_t dsq;
	u64 candidate_vtime = 0;
	u64 stage_started_at;
	u32 class, normal_index;
	s32 keep;
	bool found;

	if (!cpuq)
		return -EINVAL;
	if (opcode == SNAKE_DISPATCH_OP_CELL) {
		cell = queue_cell(cpuq->owner_cell_index);
		if (!cell)
			return -EINVAL;
		normal_index = cpuq->normal_queue_index;
		dsq = dsq_normal(normal_index);
		stage_started_at = fine_timing_start(fine);
		found = queue_fairness_head(dsq, &candidate_vtime);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
				   stage_started_at);
		if (!found) {
			stage_started_at = fine_timing_start(fine);
			found = queue_fairness_remote_normal(
				cell, normal_index, &normal_index, &candidate_vtime);
			fine_timing_finish(fine,
				queue_fairness_remote_scan_stage(cell),
				stage_started_at);
			if (!found)
				return 0;
			dsq = dsq_normal(normal_index);
		}
		class = SNAKE_QUEUE_CLASS_NORMAL;
	} else if (opcode == SNAKE_DISPATCH_OP_AFFINITY) {
		dsq = dsq_affinity(cpu);
		stage_started_at = fine_timing_start(fine);
		found = queue_fairness_head(dsq, &candidate_vtime);
		fine_timing_finish(fine,
				   SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
				   stage_started_at);
		if (!found)
			return 0;
		class = SNAKE_QUEUE_CLASS_AFFINITY;
	} else {
		return -EINVAL;
	}

	stage_started_at = fine_timing_start(fine);
	keep = queue_fairness_keep_running(ctx, cpuq, prev, class, candidate_vtime);
	fine_timing_finish(fine, SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
			   stage_started_at);
	if (keep < 0)
		return keep;
	if (keep)
		return 1;
	keep = queue_fairness_move(ctx, dsq, cpu, class, fine);
	return keep ? 1 : 0;
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

static __always_inline int
queue_fairness_running(struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_runtime *runtime = fairness_task(ctx, p, false);
	struct snake_vtime_domain *domain;
	struct snake_cpu_queue    *cpuq;
	u32			    active_weight, cpu;

	active_weight = runtime && runtime->active_weight ?
				runtime->active_weight : fairness_task_weight(p);
	queue_timing_complete_pending(runtime);

	if (runtime && runtime->direct_cell_valid) {
		u32 direct_cell_index = runtime->direct_cell_index;

		runtime = queue_fairness_prepare_task_for_cell(
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
	cpu = bpf_get_smp_processor_id();
	cpuq = queue_cpu(cpu);
	if (!cpuq)
		return -EINVAL;
	domain = queue_cell_domain(runtime->cell_index);
	if (!domain)
		return -EINVAL;
	bpf_spin_lock(&domain->lock);
	runtime->vruntime = fairness_vtime_run_start(
		runtime->vruntime, domain->vtime_now);
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
	runtime->run_cell_index = runtime->cell_index;
	runtime->run_owner_cell_index = cpuq ? cpuq->owner_cell_index : 0;
	runtime->run_queue_class = runtime->queue_class;
	runtime->active_weight = active_weight;
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->service_budget = p->scx.slice;
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
	u64 current, delta, scaled, service;
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
	service = fairness_vtime_service(
		delta, runtime->service_budget, p->scx.slice);
	scaled = fairness_scale_inverse(service, weight);
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
