/* SPDX-License-Identifier: GPL-2.0-only */
#include "main.h"
#include "queue.h"
#include "queue_init.h"
#include "mask_table_init.h"
#include "fairness.h"
#include "queue_fairness.h"
#include "queue_ladder.h"
#include "ladder.h"
#include "scheduler_mode.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

u32				   staging_ladder_slot;
u32				   staging_ladder_prepare_stage;
s32				   staging_ladder_prepare_error;
u32				   queue_topology_prepare_stage;
s32				   queue_topology_prepare_error;
u32				   queue_topology_prepare_detail;
u32				   queue_draining;
struct snake_mask_data		   queue_transition_cpus;
u32				   callback_timing_sample_rate;
u64				   select_fine_timing_session_id;
u64				   dispatch_fine_timing_session_id;
u64				   queue_timing_session_id;
struct snake_queue_timing_counters queue_timing_counters;
u64				   vtime_slice_ns;
u64				   slice_shrink_min_ns;
u64				   slice_shrink_max_ns;
u32				   slice_shrink_multiplier;
u32				   slice_shrinking_enabled;
const volatile u32		       expanded_mitosis_select = 0;

static __always_inline int
validate_compiled_ladder(const struct snake_compiled_ladder *ladder)
{
	u32 i;

	if (ladder->policy_abi_version != SNAKE_ABI_VERSION)
		return -EPROTO;
	if (!ladder->nr_rungs || ladder->nr_rungs > SNAKE_MAX_RUNGS)
		return -EINVAL;
	if (!!expanded_mitosis_select !=
	    (ladder->nr_rungs > SNAKE_MAX_GENERIC_RUNGS))
		return -EINVAL;
	if (ladder->nr_rungs > SNAKE_MAX_GENERIC_RUNGS &&
	    ladder->nr_rungs != SNAKE_MAX_RUNGS)
		return -EINVAL;
	if (ladder->nr_mask_tables > SNAKE_MAX_MASK_TABLES)
		return -EINVAL;
	if (ladder->fallback_mode != SNAKE_FALLBACK_PREVIOUS_CPU &&
	    ladder->fallback_mode != SNAKE_FALLBACK_ANY_ALLOWED)
		return -EINVAL;
	if (validate_queue_ladders(ladder))
		return -EINVAL;

	bpf_for(i, 0, SNAKE_MAX_RUNGS)
	{
		struct snake_rung rung;

		if (i >= ladder->nr_rungs)
			break;
		rung = ladder->rungs[i];
		if (ladder->nr_rungs > SNAKE_MAX_GENERIC_RUNGS) {
			if (!queue_atomic_rung_is_valid(&rung) ||
			    !expanded_mitosis_rung_matches(&rung, i))
				return -EINVAL;
		} else if (!rung_is_valid(&rung, ladder->nr_mask_tables)) {
			return -EINVAL;
		}
	}
	return 0;
}

/* Validate and materialize a fully staged, inactive ladder slot. */
SEC("syscall")
int prepare_ladder(void *ctx)
{
	struct snake_compiled_ladder *ladder;
	s32			      active;
	u32			      slot = READ_ONCE(staging_ladder_slot);
	int			      ret;

	(void)ctx;
	if (slot >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	active = active_ladder_slot();
	if (active >= 0 && active < SNAKE_LADDER_SLOTS && active == slot)
		return -EBUSY;

	ladder = bpf_map_lookup_elem(&compiled_ladders, &slot);
	if (!ladder)
		return -EINVAL;
	WRITE_ONCE(staging_ladder_prepare_stage, 1);
	ret = validate_compiled_ladder(ladder);
	if (ret) {
		WRITE_ONCE(staging_ladder_prepare_error, ret);
		return ret;
	}

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	WRITE_ONCE(staging_ladder_prepare_stage, 2);
	ret	   = prepare_queue_topology(slot);
	if (ret) {
		WRITE_ONCE(staging_ladder_prepare_error, ret);
		return ret;
	}
	if (queue_topology_enabled() && !fairness_is_vtime()) {
		WRITE_ONCE(staging_ladder_prepare_error, -EINVAL);
		return -EINVAL;
	}
	WRITE_ONCE(staging_ladder_prepare_stage, 3);
	ret = prepare_mask_tables(slot, ladder);
	WRITE_ONCE(staging_ladder_prepare_error, ret);
	if (!ret)
		WRITE_ONCE(staging_ladder_prepare_stage, 0);
	return ret;
}

static __always_inline s32
queue_affinity_drain_ready_slot(s32 active, bool changed_only)
{
	u32 i;

	bpf_for(i, 0, SNAKE_MAX_CPUS)
	{
		struct snake_affinity_queue_runtime *affinity_runtime;
		s32 queued;

		if (i >= nr_cpu_ids)
			break;
		if (!queue_cpu_slot(active, i))
			continue;
		if (changed_only &&
		    !queue_mask_contains(&queue_transition_cpus, i))
			continue;
		queued = dsq_nr_queued(dsq_affinity(i));
		if (queued < 0)
			return queued;
		if (queued > 0)
			return -EAGAIN;
		affinity_runtime = queue_affinity_runtime(i);
		if (!affinity_runtime)
			return -EINVAL;
		if (READ_ONCE(affinity_runtime->nr_queued))
			return -EAGAIN;
	}
	return 0;
}

/* Affinity DSQs cannot safely retain an old owner clock across CPU transfer. */
SEC("syscall")
int queue_affinity_drain_ready(void *ctx)
{
	struct snake_queue_header *header;
	s32			    active;

	(void)ctx;
	if (!queue_transition_active())
		return -EINVAL;
	active = active_ladder_slot();
	if (active < 0 || active >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	header = queue_config_slot(active);
	if (!header || header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	return queue_affinity_drain_ready_slot(active, true);
}

/* Report when every reusable custom DSQ is empty during a topology change. */
SEC("syscall")
int queue_drain_ready(void *ctx)
{
	struct snake_queue_header *header;
	s32			    active, ret;
	u32			    i;

	(void)ctx;
	if (!queue_transition_active())
		return -EINVAL;
	active = active_ladder_slot();
	if (active < 0 || active >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	header = queue_config_slot(active);
	if (!header || header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	ret = queue_affinity_drain_ready_slot(active, false);
	if (ret)
		return ret;
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_normal_queue_runtime *runtime;
		s32 queued;

		if (i >= header->nr_normal_queues)
			break;
		queued = dsq_nr_queued(dsq_normal(i));
		if (queued < 0)
			return queued;
		if (queued > 0)
			return -EAGAIN;
		runtime = queue_normal_runtime(i);
		if (!runtime)
			return -EINVAL;
		if (READ_ONCE(runtime->nr_queued))
			return -EAGAIN;
	}
	return 0;
}

/* Publish consumer presence before checking tracked depth, interlocking enqueue. */
SEC("syscall")
int queue_refresh_runtime(void *ctx)
{
	struct snake_queue_header *header;
	s32 active;
	u32 i;

	(void)ctx;
	active = active_ladder_slot();
	if (active < 0 || active >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	header = queue_config_slot(active);
	if (!header || header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_normal_queue_runtime *runtime;
		struct snake_normal_queue *queue;
		volatile unsigned long mb = 0;
		u32 cell_offset = 0;
		bool has_consumers;

		if (i >= header->nr_normal_queues)
			break;
		queue = queue_normal_slot(active, i);
		runtime = queue_normal_runtime(i);
		if (!queue || !runtime)
			return -EINVAL;
		has_consumers = queue->consumer_cpu != SNAKE_QUEUE_CPU_NONE;
		if (header->mode == SNAKE_QUEUE_MODE_CELL) {
			struct snake_queue_cell *cell =
				queue_cell_slot(active, queue->cell_index);

			if (!cell || i < cell->first_normal_queue)
				return -EINVAL;
			cell_offset = i - cell->first_normal_queue;
			if (cell_offset >= cell->nr_normal_queues ||
			    cell_offset >= SNAKE_MAX_CELL_LLCS)
				return -EINVAL;
		}
		WRITE_ONCE(runtime->cell_index, queue->cell_index);
		WRITE_ONCE(runtime->cell_offset, cell_offset);
		WRITE_ONCE(runtime->has_consumers, has_consumers);
		if (header->mode != SNAKE_QUEUE_MODE_CELL)
			continue;
		__sync_fetch_and_add(&mb, 0);
		if (has_consumers) {
			if (queue_normal_drain_disable(runtime))
				return -EINVAL;
			if (READ_ONCE(runtime->nr_queued))
				queue_kick_idle_cell_cpu(active,
						 queue->cell_index);
		} else if (READ_ONCE(runtime->nr_queued)) {
			if (queue_normal_drain_enable(runtime))
				return -EINVAL;
			queue_kick_idle_cell_cpu(active, queue->cell_index);
		}
	}
	return 0;
}

/* Run one selected placement engine, then use its exhaustion fallback. */
static __noinline s32 snake_select_cpu_impl(struct task_struct *p,
				     s32 prev_cpu, u64 wake_flags,
				     bool expanded_mitosis)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at			= callback_timing_start();
	struct snake_ladder_walk_args walk_args = {
		.prev_cpu	     = prev_cpu,
		.queue_cell_index    = SNAKE_QUEUE_CELL_NONE,
		.wake_flags	     = wake_flags,
		.enqueue_flags	     = 0,
		.select_flags	     = 0,
		.callback_started_at = callback_started_at,
		.scope_started_at    = bpf_ktime_get_ns(),
		.local_llc_route_cpu = SNAKE_QUEUE_CELL_NONE,
		.local_llc_cell_index = SNAKE_QUEUE_CELL_NONE,
	};
	u64 fine_stage_started_at =
		fine_timing_select_start(callback_started_at);
	s32 cpu, ret;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_SELECT_CPU,
					callback_started_at);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish_select(
			SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER,
			fine_stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in select_cpu");
		return -1;
	}
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER,
				  fine_stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_SELECT_CALLS);

	fine_stage_started_at = fine_timing_select_start(callback_started_at);
	cpu = expanded_mitosis ?
		      walk_expanded_mitosis_ladder(&ladder_ctx, p, &walk_args) :
		      walk_generic_policy_ladder(&ladder_ctx, p, &walk_args);
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_POLICY_LADDER,
				  fine_stage_started_at);
	if (cpu >= 0) {
		if (queue_topology_enabled()) {
			if (queue_transition_active())
				goto direct_dispatch;
			if (walk_args.select_flags & SNAKE_SELECT_F_BORROWED) {
				fine_stage_started_at =
					fine_timing_select_start(
						callback_started_at);
				ret = !queue_cell_mode_enabled() ? -EINVAL :
				      walk_args.queue_cell_index ==
						      SNAKE_QUEUE_CELL_NONE ?
					      -EINVAL :
					      queue_fairness_direct_borrow(
						      &ladder_ctx, p, cpu,
						      walk_args.queue_cell_index,
						      &fine_timing);
				fine_timing_finish_select(
					SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
					fine_stage_started_at);
				if (ret) {
					scx_bpf_error(
						"snake failed to direct-borrow CPU %d for pid %d",
						cpu, p->pid);
					cpu = -1;
					goto out;
				}
				stat_inc(&ladder_ctx,
					 SNAKE_STAT_DIRECT_DISPATCHES);
				goto out_success;
			}
			if (queue_direct_dispatch_enabled(&ladder_ctx) &&
			    !(walk_args.enqueue_flags & SCX_ENQ_PREEMPT)) {
				if (!queue_cell_mode_enabled())
					goto direct_dispatch;
				fine_stage_started_at = fine_timing_select_start(
					callback_started_at);
				ret = walk_args.select_flags &
						      SNAKE_SELECT_F_AFFINITY ?
					      queue_fairness_direct_affinity(
						      &ladder_ctx, p, cpu,
						      walk_args.queue_cell_index,
						      &fine_timing) :
					      queue_fairness_direct_primary(
						      &ladder_ctx, p, cpu,
						      walk_args.queue_cell_index,
						      &fine_timing);
				fine_timing_finish_select(
					SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
					fine_stage_started_at);
				if (ret) {
					scx_bpf_error(
						"snake failed to direct-dispatch CPU %d for pid %d",
						cpu, p->pid);
					cpu = -1;
					goto out;
				}
				stat_inc(&ladder_ctx,
					 SNAKE_STAT_DIRECT_DISPATCHES);
				goto out_success;
			}
			fine_stage_started_at =
				fine_timing_select_start(callback_started_at);
			ret = queue_fairness_select_cpu(&ladder_ctx, p, cpu,
						&fine_timing);
			fine_timing_finish_select(
				SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
				fine_stage_started_at);
			if (ret) {
				scx_bpf_error(
					"snake failed to record queue target for pid %d",
					p->pid);
				cpu = -1;
				goto out;
			}
			goto out_success;
		}
	direct_dispatch:
		if (fairness_is_ordered() &&
		    (walk_args.enqueue_flags & SCX_ENQ_PREEMPT)) {
			fine_stage_started_at =
				fine_timing_select_start(callback_started_at);
			stat_inc(
				&ladder_ctx,
				fairness_is_vtime() ?
					SNAKE_STAT_VTIME_STRICT_PREEMPT_QUEUES :
					SNAKE_STAT_EEVDF_STRICT_PREEMPT_QUEUES);
			fine_timing_finish_select(
				SNAKE_FINE_TIMING_SELECT_STRICT_PREEMPT,
				fine_stage_started_at);
			goto out_success;
		}
		fine_stage_started_at =
			fine_timing_select_start(callback_started_at);
		ret = dsq_insert_local_on(
			p, cpu, fairness_dispatch_slice(&ladder_ctx, p, true),
			walk_args.enqueue_flags, &fine_timing);
		fine_timing_finish_select(
			SNAKE_FINE_TIMING_SELECT_DIRECT_INSERT,
			fine_stage_started_at);
		if (!ret) {
			stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake failed to dispatch pid %d to CPU %d",
				p->pid, cpu);
			cpu = -1;
			goto out;
		}
		queue_timing_record_insert(&ladder_ctx, p, dsq_local_on(cpu),
					   SNAKE_QUEUE_CELL_NONE, &fine_timing);
		stat_inc(&ladder_ctx, SNAKE_STAT_DIRECT_DISPATCHES);
		goto out_success;
	}
	if (cpu != -ENOENT)
		goto out;

	fine_stage_started_at = fine_timing_select_start(callback_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_LADDER_EXHAUSTIONS);
	cpu = fallback_cpu(&ladder_ctx, p, prev_cpu);
	if (cpu < 0) {
		fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_FALLBACK,
					  fine_stage_started_at);
		goto out;
	}
	if (queue_topology_enabled() && queue_transition_active())
		goto direct_dispatch;
	ret = queue_topology_enabled() ?
		      queue_fairness_select_cpu(&ladder_ctx, p, cpu,
						&fine_timing) :
		      0;
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_FALLBACK,
				  fine_stage_started_at);
	if (ret) {
		scx_bpf_error(
			"snake failed to record fallback queue target for pid %d",
			p->pid);
		cpu = -1;
		goto out;
	}

out_success:
	finish_select(&ladder_ctx, walk_args.scope_started_at,
		      callback_started_at);
out:
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU,
			       callback_started_at);
	return cpu;
}

s32 BPF_STRUCT_OPS(snake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	return snake_select_cpu_impl(p, prev_cpu, wake_flags, false);
}

s32 BPF_STRUCT_OPS(snake_select_cpu_expanded, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	return snake_select_cpu_impl(p, prev_cpu, wake_flags, true);
}

static __noinline void
snake_enqueue_impl(struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	s32			     ret = 0;
	u64  callback_started_at = callback_timing_start();
	u64  stage_started_at;

	fine_timing	 = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_ENQUEUE,
					     callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in enqueue");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
			   stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	ret = scheduler_mode_enqueue_fairness(
		&ladder_ctx, p, enq_flags, &fine_timing, callback_started_at);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_ENQUEUE,
			       callback_started_at);
	if (ret)
		scx_bpf_error("snake fairness enqueue failed for pid %d: %d",
			      p->pid, ret);
}

static __noinline void snake_enqueue_expanded_impl(struct task_struct *p,
					   u64 enq_flags)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	s32			     ret = 0;
	s32			     gate;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;
	bool queue_tracked = false;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_ENQUEUE,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in enqueue");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
			   stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	gate = queue_enqueue_inflight_gate();
	if (gate < 0) {
		ret = gate;
	} else {
		queue_tracked = gate != SNAKE_QUEUE_ENQUEUE_CLOSED;
		ret = gate == SNAKE_QUEUE_ENQUEUE_OPEN ?
			      scheduler_mode_enqueue_expanded(
				      &ladder_ctx, p, enq_flags, &fine_timing,
				      callback_started_at) :
			      queue_transition_enqueue(
				      &ladder_ctx, p, enq_flags, &fine_timing);
	}
	if (ret) {
		stage_started_at = fine_timing_start(&fine_timing);
		scx_bpf_error("snake queue enqueue failed for pid %d", p->pid);
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_FINISH,
				   stage_started_at);
	}
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_ENQUEUE,
			       callback_started_at);
	if (queue_tracked && queue_enqueue_inflight_exit())
		scx_bpf_error("snake queue enqueue tracking underflow for pid %d",
			      p->pid);
}

static __noinline void snake_enqueue_no_direct_impl(struct task_struct *p,
					      u64 enq_flags)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	s32			     ret = 0;
	s32			     gate;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;
	bool queue_tracked = false;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_ENQUEUE,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in enqueue");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
			   stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	gate = queue_enqueue_inflight_gate();
	if (gate < 0) {
		ret = gate;
	} else {
		queue_tracked = gate != SNAKE_QUEUE_ENQUEUE_CLOSED;
		ret = gate == SNAKE_QUEUE_ENQUEUE_OPEN ?
			      scheduler_mode_enqueue_no_direct(
				      &ladder_ctx, p, enq_flags, &fine_timing,
				      callback_started_at) :
			      queue_transition_enqueue(
				      &ladder_ctx, p, enq_flags, &fine_timing);
	}
	if (ret) {
		stage_started_at = fine_timing_start(&fine_timing);
		scx_bpf_error("snake queue enqueue failed for pid %d", p->pid);
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_FINISH,
				   stage_started_at);
	}
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_ENQUEUE,
			       callback_started_at);
	if (queue_tracked && queue_enqueue_inflight_exit())
		scx_bpf_error("snake queue enqueue tracking underflow for pid %d",
			      p->pid);
}

void BPF_STRUCT_OPS(snake_enqueue, struct task_struct *p, u64 enq_flags)
{
	snake_enqueue_impl(p, enq_flags);
}

void BPF_STRUCT_OPS(snake_enqueue_expanded, struct task_struct *p,
		    u64 enq_flags)
{
	snake_enqueue_expanded_impl(p, enq_flags);
}

void BPF_STRUCT_OPS(snake_enqueue_no_direct, struct task_struct *p,
		    u64 enq_flags)
{
	snake_enqueue_no_direct_impl(p, enq_flags);
}

void BPF_STRUCT_OPS(snake_dispatch, s32 cpu, struct task_struct *prev)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_DISPATCH,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in dispatch");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER,
			   stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_DISPATCH_CALLS);
	scheduler_mode_dispatch(&ladder_ctx, cpu, prev, &fine_timing,
				callback_started_at);
}

void BPF_STRUCT_OPS(snake_runnable, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;
	s32 ret;

	(void)enq_flags;
	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_RUNNABLE,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_RUNNABLE_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in runnable");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_RUNNABLE_ACQUIRE_LADDER,
			   stage_started_at);
	ret = scheduler_mode_runnable(&ladder_ctx, p, &fine_timing);
	if (ret)
		scx_bpf_error(
			"snake runnable preparation failed for pid %d: %d",
			p->pid, ret);
	stage_started_at = fine_timing_start(&fine_timing);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNABLE,
			       callback_started_at);
	fine_timing_finish(&fine_timing, SNAKE_FINE_TIMING_RUNNABLE_FINISH,
			   stage_started_at);
}

void BPF_STRUCT_OPS(snake_running, struct task_struct *p)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;
	s32 ret;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_RUNNING,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_RUNNING_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in running");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_RUNNING_ACQUIRE_LADDER,
			   stage_started_at);
	ret = scheduler_mode_running(&ladder_ctx, p, &fine_timing);
	if (ret)
		scx_bpf_error("snake running accounting failed for pid %d: %d",
			      p->pid, ret);
	stage_started_at = fine_timing_start(&fine_timing);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNING,
			       callback_started_at);
	fine_timing_finish(&fine_timing, SNAKE_FINE_TIMING_RUNNING_FINISH,
			   stage_started_at);
}

void BPF_STRUCT_OPS(snake_stopping, struct task_struct *p, bool runnable)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;
	u64 runtime_ns;
	s32 ret;

	(void)runnable;
	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_STOPPING,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_STOPPING_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in stopping");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_STOPPING_ACQUIRE_LADDER,
			   stage_started_at);
	ret = scheduler_mode_stopping(&ladder_ctx, p, &runtime_ns,
				      &fine_timing);
	stage_started_at = fine_timing_start(&fine_timing);
	if (ret)
		scx_bpf_error("snake stopping accounting failed for pid %d: %d",
			      p->pid, ret);
	else
		stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns);
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_STOPPING_RUNTIME_STAT,
			   stage_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_STOPPING,
			       callback_started_at);
	fine_timing_finish(&fine_timing, SNAKE_FINE_TIMING_STOPPING_FINISH,
			   stage_started_at);
}

void BPF_STRUCT_OPS(snake_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct snake_ladder_ctx	     ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	u64 callback_started_at = callback_timing_start();
	u64 stage_started_at;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_QUIESCENT,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_QUIESCENT_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error(
			"snake failed to acquire active ladder in quiescent");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_QUIESCENT_ACQUIRE_LADDER,
			   stage_started_at);
	scheduler_mode_quiescent(&ladder_ctx, p, deq_flags, &fine_timing);
	stage_started_at = fine_timing_start(&fine_timing);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_QUIESCENT,
			       callback_started_at);
	fine_timing_finish(&fine_timing, SNAKE_FINE_TIMING_QUIESCENT_FINISH,
			   stage_started_at);
}

void BPF_STRUCT_OPS(snake_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct snake_task_runtime *runtime = task_state_lookup(p);
	s32 ret = queue_custom_account_dequeue(runtime);

	if (ret < 0)
		scx_bpf_error(
			"snake custom queue dequeue failed for pid %d flags %llu: %d",
			p->pid, deq_flags, ret);
}

void BPF_STRUCT_OPS(snake_set_weight, struct task_struct *p, u32 weight)
{
	struct snake_ladder_ctx ladder_ctx = {};

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error(
			"snake failed to acquire active ladder in set_weight");
		return;
	}
	scheduler_mode_set_weight(&ladder_ctx, p, weight);
	release_active_ladder(&ladder_ctx);
}

s32 BPF_STRUCT_OPS(snake_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	(void)args;
	return scheduler_mode_init_task(p);
}

/* Validate the published ladder before the scheduler can attach. */
s32 BPF_STRUCT_OPS_SLEEPABLE(snake_init)
{
	struct snake_ladder_ctx ladder_ctx = {};
	s32			active;
	int			ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	ret	   = init_mask_table_scratch();
	if (ret) {
		scx_bpf_error(
			"snake mask-table scratch initialization failed: %d",
			ret);
		return ret;
	}
	active = active_ladder_slot();
	if (active < 0 || active >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	ret = validate_queue_topology(active);
	if (ret) {
		scx_bpf_error("snake queue topology validation failed: %d",
			      ret);
		return ret;
	}
	if (queue_topology_enabled() && !fairness_is_vtime()) {
		scx_bpf_error("snake queue topology requires VTIME fairness");
		return -EINVAL;
	}
	ret = fairness_init();
	if (ret) {
		scx_bpf_error("snake fairness initialization failed: %d", ret);
		return ret;
	}
	ret = create_queue_topology_dsqs(active);
	if (ret) {
		scx_bpf_error("snake queue DSQ creation failed: %d", ret);
		return ret;
	}
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake has no prepared active ladder");
		return -EINVAL;
	}
	ret = validate_compiled_ladder(ladder_ctx.ladder);
	if (ret)
		stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
	release_active_ladder(&ladder_ctx);
	if (ret) {
		scx_bpf_error("snake active ladder validation failed: %d", ret);
		return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(snake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(
	snake_ops, .select_cpu = (void *)snake_select_cpu,
	.init_task = (void *)snake_init_task, .enqueue = (void *)snake_enqueue,
	.dequeue = (void *)snake_dequeue, .dispatch = (void *)snake_dispatch,
	.runnable = (void *)snake_runnable,
	.running = (void *)snake_running, .stopping = (void *)snake_stopping,
	.quiescent  = (void *)snake_quiescent,
	.set_weight = (void *)snake_set_weight, .init = (void *)snake_init,
	.exit = (void *)snake_exit, .timeout_ms = 5000, .name = "snake");
