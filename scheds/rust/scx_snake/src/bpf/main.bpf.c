/* SPDX-License-Identifier: GPL-2.0-only */
#include "main.h"
#include "queue.h"
#include "fairness.h"
#include "queue_fairness.h"
#include "queue_ladder.h"
#include "ladder.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

u32 staging_ladder_slot;
u32 callback_timing_sample_rate;
u64 select_fine_timing_session_id;
u64 queue_timing_session_id;
struct snake_queue_timing_counters queue_timing_counters;

static __always_inline int
validate_compiled_ladder(const struct snake_compiled_ladder *ladder)
{
	u32 i;

	if (ladder->policy_abi_version != SNAKE_ABI_VERSION)
		return -EPROTO;
	if (!ladder->nr_rungs || ladder->nr_rungs > SNAKE_MAX_RUNGS)
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
		if (!rung_is_valid(&rung, ladder->nr_mask_tables))
			return -EINVAL;
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
	ret = validate_compiled_ladder(ladder);
	if (ret)
		return ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	ret = validate_queue_topology();
	if (ret)
		return ret;
	if (queue_topology_enabled() && !fairness_is_vtime())
		return -EINVAL;
	return prepare_mask_tables(slot, ladder);
}

/* Run the policy ladder, then use its affinity-safe exhaustion fallback. */
s32 BPF_STRUCT_OPS(snake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 callback_started_at = callback_timing_start();
	u64 dispatch_flags = 0;
	u64 fine_stage_started_at =
		fine_timing_select_start(callback_started_at);
	u64 select_started_at = bpf_ktime_get_ns();
	u32 queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	s32 cpu, ret;

	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish_select(
			SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER,
			fine_stage_started_at);
		scx_bpf_error("snake failed to acquire active ladder in select_cpu");
		return -1;
	}
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER,
				  fine_stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_SELECT_CALLS);

	fine_stage_started_at = fine_timing_select_start(callback_started_at);
	cpu = walk_policy_ladder(&ladder_ctx, p, prev_cpu, wake_flags,
				 &dispatch_flags, &queue_cell_index,
				 callback_started_at);
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_POLICY_LADDER,
				  fine_stage_started_at);
	if (cpu >= 0) {
		if (queue_topology_enabled()) {
			if (dispatch_flags & SNAKE_SELECT_F_BORROWED) {
				fine_stage_started_at =
					fine_timing_select_start(callback_started_at);
				ret = queue_cell_index == SNAKE_QUEUE_CELL_NONE ?
					      -EINVAL :
					      queue_fairness_direct_borrow(
						      &ladder_ctx, p, cpu,
						      queue_cell_index);
				fine_timing_finish_select(
					SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
					fine_stage_started_at);
				if (ret) {
					scx_bpf_error(
						"snake failed to direct-borrow CPU %d for pid %d",
						cpu, p->pid);
					release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
					return -1;
				}
				stat_inc(&ladder_ctx, SNAKE_STAT_DIRECT_DISPATCHES);
				finish_select(&ladder_ctx, select_started_at,
					      callback_started_at);
				release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
				return cpu;
			}
			fine_stage_started_at =
				fine_timing_select_start(callback_started_at);
			ret = queue_fairness_select_cpu(&ladder_ctx, p, cpu);
			fine_timing_finish_select(
				SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
				fine_stage_started_at);
			if (ret) {
				scx_bpf_error("snake failed to record queue target for pid %d",
					      p->pid);
				release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
				return -1;
			}
			finish_select(&ladder_ctx, select_started_at,
				      callback_started_at);
			release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
			return cpu;
		}
		if (fairness_is_ordered() && (dispatch_flags & SCX_ENQ_PREEMPT)) {
			fine_stage_started_at =
				fine_timing_select_start(callback_started_at);
			stat_inc(&ladder_ctx,
				 fairness_is_vtime() ?
					 SNAKE_STAT_VTIME_STRICT_PREEMPT_QUEUES :
					 SNAKE_STAT_EEVDF_STRICT_PREEMPT_QUEUES);
			fine_timing_finish_select(
				SNAKE_FINE_TIMING_SELECT_STRICT_PREEMPT,
				fine_stage_started_at);
			finish_select(&ladder_ctx, select_started_at,
				      callback_started_at);
			release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
			return cpu;
		}
		fine_stage_started_at =
			fine_timing_select_start(callback_started_at);
		ret = scx_bpf_dsq_insert(
			p, SCX_DSQ_LOCAL,
			fairness_dispatch_slice(&ladder_ctx, p, true),
			dispatch_flags);
		fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_DIRECT_INSERT,
					  fine_stage_started_at);
		if (!ret) {
			stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake failed to dispatch pid %d to CPU %d",
				p->pid, cpu);
			release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
			return -1;
		}
		stat_inc(&ladder_ctx, SNAKE_STAT_DIRECT_DISPATCHES);
		finish_select(&ladder_ctx, select_started_at,
			      callback_started_at);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
		return cpu;
	}
	if (cpu != -ENOENT) {
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
		return cpu;
	}

	fine_stage_started_at = fine_timing_select_start(callback_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_LADDER_EXHAUSTIONS);
	cpu = fallback_cpu(&ladder_ctx, p, prev_cpu);
	if (cpu < 0) {
		fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_FALLBACK,
					  fine_stage_started_at);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
		return cpu;
	}
	ret = queue_topology_enabled() ?
		      queue_fairness_select_cpu(&ladder_ctx, p, cpu) :
		      0;
	fine_timing_finish_select(SNAKE_FINE_TIMING_SELECT_FALLBACK,
				  fine_stage_started_at);
	if (ret) {
		scx_bpf_error("snake failed to record fallback queue target for pid %d",
			      p->pid);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
		return -1;
	}
	finish_select(&ladder_ctx, select_started_at, callback_started_at);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_SELECT_CPU, callback_started_at);
	return cpu;
}

void BPF_STRUCT_OPS(snake_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	s32			 cell_enqueued, ret;
	u64			 callback_started_at = callback_timing_start();
	u64			 stage_started_at;
	u64			 slice;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_ENQUEUE,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error("snake failed to acquire active ladder in enqueue");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
			   stage_started_at);
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	if (queue_topology_enabled()) {
		ret = queue_ladder_enqueue(&ladder_ctx, p, enq_flags,
					   &fine_timing, callback_started_at);
		stage_started_at = fine_timing_start(&fine_timing);
		if (ret)
			scx_bpf_error("snake queue enqueue failed for pid %d", p->pid);
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_ENQUEUE_FINISH,
				   stage_started_at);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_ENQUEUE, callback_started_at);
		return;
	}
	slice = fairness_dispatch_slice(&ladder_ctx, p, true);
	cell_enqueued = try_enqueue_task_cell(&ladder_ctx, p, enq_flags, slice,
				      callback_started_at);
	if (cell_enqueued)
		goto out;
	ret = fairness_enqueue(&ladder_ctx, p, enq_flags);
out:
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_ENQUEUE, callback_started_at);
	if (cell_enqueued)
		return;
	if (ret)
		scx_bpf_error("snake fairness enqueue failed for pid %d: %d",
			      p->pid, ret);
}

void BPF_STRUCT_OPS(snake_dispatch, s32 cpu, struct task_struct *prev)
{
	struct snake_ladder_ctx ladder_ctx = {};
	struct snake_fine_timing_ctx fine_timing;
	s32			 ret;
	u64			 callback_started_at = callback_timing_start();
	u64			 stage_started_at;

	fine_timing = fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_DISPATCH,
					callback_started_at);
	stage_started_at = fine_timing_start(&fine_timing);
	if (acquire_active_ladder(&ladder_ctx)) {
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER,
				   stage_started_at);
		scx_bpf_error("snake failed to acquire active ladder in dispatch");
		return;
	}
	fine_timing_finish(&fine_timing,
			   SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER,
			   stage_started_at);
	if (queue_topology_enabled()) {
		ret = queue_ladder_dispatch(&ladder_ctx, cpu, prev, &fine_timing,
					    callback_started_at);
		stage_started_at = fine_timing_start(&fine_timing);
		if (ret)
			scx_bpf_error("snake queue dispatch failed on CPU %d", cpu);
		fine_timing_finish(&fine_timing,
				   SNAKE_FINE_TIMING_DISPATCH_FINISH,
				   stage_started_at);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_DISPATCH, callback_started_at);
		return;
	}
	ret = fairness_dispatch(&ladder_ctx, cpu, prev);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_DISPATCH, callback_started_at);
	if (ret)
		scx_bpf_error("snake fairness dispatch failed on CPU %d: %d", cpu,
			      ret);
}

void BPF_STRUCT_OPS(snake_runnable, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 callback_started_at = callback_timing_start();

	(void)enq_flags;
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in runnable");
		return;
	}
	if (queue_topology_enabled()) {
		if (!queue_fairness_prepare_runnable(&ladder_ctx, p, NULL))
			scx_bpf_error("snake queue runnable preparation failed for pid %d",
				      p->pid);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNABLE, callback_started_at);
		return;
	}
	fairness_runnable(&ladder_ctx, p);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNABLE, callback_started_at);
}

void BPF_STRUCT_OPS(snake_running, struct task_struct *p)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 callback_started_at = callback_timing_start();

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in running");
		return;
	}
	if (queue_topology_enabled()) {
		stat_inc(&ladder_ctx, SNAKE_STAT_RUNNING);
		queue_account_task_membership(&ladder_ctx, p);
		if (queue_fairness_running(&ladder_ctx, p))
			scx_bpf_error("snake queue running accounting failed for pid %d",
				      p->pid);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNING, callback_started_at);
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_RUNNING);
	fairness_running(&ladder_ctx, p);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_RUNNING, callback_started_at);
}

void BPF_STRUCT_OPS(snake_stopping, struct task_struct *p, bool runnable)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 callback_started_at = callback_timing_start();
	u64 runtime_ns;

	(void)runnable;
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in stopping");
		return;
	}
	if (queue_topology_enabled()) {
		stat_inc(&ladder_ctx, SNAKE_STAT_STOPPING);
		if (queue_fairness_stopping(&ladder_ctx, p, &runtime_ns)) {
			scx_bpf_error("snake queue stopping accounting failed for pid %d",
				      p->pid);
			release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_STOPPING, callback_started_at);
			return;
		}
		stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_STOPPING, callback_started_at);
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_STOPPING);
	runtime_ns = fairness_stopping(&ladder_ctx, p);
	stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_STOPPING, callback_started_at);
}

void BPF_STRUCT_OPS(snake_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 callback_started_at = callback_timing_start();

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in quiescent");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_QUIESCENT);
	if (queue_topology_enabled()) {
		queue_fairness_cancel_direct(&ladder_ctx, p);
		release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_QUIESCENT, callback_started_at);
		return;
	}
	fairness_quiescent(&ladder_ctx, p, deq_flags);
	release_timed_callback(&ladder_ctx, SNAKE_CALLBACK_QUIESCENT, callback_started_at);
}

void BPF_STRUCT_OPS(snake_set_weight, struct task_struct *p, u32 weight)
{
	struct snake_ladder_ctx ladder_ctx = {};

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in set_weight");
		return;
	}
	fairness_set_weight(&ladder_ctx, p, weight);
	release_active_ladder(&ladder_ctx);
}

s32 BPF_STRUCT_OPS(snake_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct snake_task_runtime *runtime;
	struct bpf_cpumask	 *mask, *stale;

	(void)args;
	if (!queue_topology_enabled())
		return 0;
	runtime = bpf_task_storage_get(&task_runtimes, p, NULL,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!runtime)
		return -ENOMEM;
	if (runtime->queue_cpumask)
		return 0;
	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;
	stale = bpf_kptr_xchg(&runtime->queue_cpumask, mask);
	if (stale) {
		bpf_cpumask_release(stale);
		return -EINVAL;
	}
	return 0;
}

/* Validate the published ladder before the scheduler can attach. */
s32 BPF_STRUCT_OPS_SLEEPABLE(snake_init)
{
	struct snake_ladder_ctx ladder_ctx = {};
	int			 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	ret = validate_queue_topology();
	if (ret) {
		scx_bpf_error("snake queue topology validation failed: %d", ret);
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
	ret = queue_init_cell_masks();
	if (ret) {
		scx_bpf_error("snake queue mask initialization failed: %d", ret);
		return ret;
	}
	ret = create_queue_topology_dsqs();
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

SCX_OPS_DEFINE(snake_ops, .select_cpu = (void *)snake_select_cpu,
	       .init_task  = (void *)snake_init_task,
	       .enqueue	  = (void *)snake_enqueue,
	       .dispatch  = (void *)snake_dispatch,
	       .runnable  = (void *)snake_runnable,
	       .running	  = (void *)snake_running,
	       .stopping  = (void *)snake_stopping,
	       .quiescent = (void *)snake_quiescent,
	       .set_weight = (void *)snake_set_weight, .init = (void *)snake_init,
	       .exit = (void *)snake_exit, .timeout_ms = 5000, .name = "snake");
