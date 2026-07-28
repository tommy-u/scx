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
	u64 dispatch_flags = 0;
	u64 started_at	   = bpf_ktime_get_ns();
	u32 queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	s32 cpu;

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in select_cpu");
		return -1;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_SELECT_CALLS);

	cpu = walk_policy_ladder(&ladder_ctx, p, prev_cpu, wake_flags,
				 &dispatch_flags, &queue_cell_index);
	if (cpu >= 0) {
		if (queue_topology_enabled()) {
			if (dispatch_flags & SNAKE_SELECT_F_BORROWED) {
				if (queue_cell_index == SNAKE_QUEUE_CELL_NONE ||
				    queue_fairness_direct_borrow(
					    &ladder_ctx, p, cpu, queue_cell_index)) {
					scx_bpf_error(
						"snake failed to direct-borrow CPU %d for pid %d",
						cpu, p->pid);
					release_active_ladder(&ladder_ctx);
					return -1;
				}
				stat_inc(&ladder_ctx, SNAKE_STAT_DIRECT_DISPATCHES);
				finish_select(&ladder_ctx, started_at);
				release_active_ladder(&ladder_ctx);
				return cpu;
			}
			if (queue_fairness_select_cpu(&ladder_ctx, p, cpu)) {
				scx_bpf_error("snake failed to record queue target for pid %d",
					      p->pid);
				release_active_ladder(&ladder_ctx);
				return -1;
			}
			finish_select(&ladder_ctx, started_at);
			release_active_ladder(&ladder_ctx);
			return cpu;
		}
		if (fairness_is_ordered() && (dispatch_flags & SCX_ENQ_PREEMPT)) {
			stat_inc(&ladder_ctx,
				 fairness_is_vtime() ?
					 SNAKE_STAT_VTIME_STRICT_PREEMPT_QUEUES :
					 SNAKE_STAT_EEVDF_STRICT_PREEMPT_QUEUES);
			finish_select(&ladder_ctx, started_at);
			release_active_ladder(&ladder_ctx);
			return cpu;
		}
		if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					fairness_dispatch_slice(&ladder_ctx, p, true),
					dispatch_flags)) {
			stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake failed to dispatch pid %d to CPU %d",
				p->pid, cpu);
			release_active_ladder(&ladder_ctx);
			return -1;
		}
		stat_inc(&ladder_ctx, SNAKE_STAT_DIRECT_DISPATCHES);
		finish_select(&ladder_ctx, started_at);
		release_active_ladder(&ladder_ctx);
		return cpu;
	}
	if (cpu != -ENOENT) {
		release_active_ladder(&ladder_ctx);
		return cpu;
	}

	stat_inc(&ladder_ctx, SNAKE_STAT_LADDER_EXHAUSTIONS);
	cpu = fallback_cpu(&ladder_ctx, p, prev_cpu);
	if (cpu < 0) {
		release_active_ladder(&ladder_ctx);
		return cpu;
	}
	if (queue_topology_enabled() &&
	    queue_fairness_select_cpu(&ladder_ctx, p, cpu)) {
		scx_bpf_error("snake failed to record fallback queue target for pid %d",
			      p->pid);
		release_active_ladder(&ladder_ctx);
		return -1;
	}
	finish_select(&ladder_ctx, started_at);
	release_active_ladder(&ladder_ctx);
	return cpu;
}

void BPF_STRUCT_OPS(snake_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	s32			 cell_enqueued, ret;
	u64			 slice;

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in enqueue");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	if (queue_topology_enabled()) {
		if (queue_ladder_enqueue(&ladder_ctx, p, enq_flags))
			scx_bpf_error("snake queue enqueue failed for pid %d", p->pid);
		release_active_ladder(&ladder_ctx);
		return;
	}
	slice = fairness_dispatch_slice(&ladder_ctx, p, true);
	cell_enqueued = try_enqueue_task_cell(&ladder_ctx, p, enq_flags, slice);
	if (cell_enqueued)
		goto out;
	ret = fairness_enqueue(&ladder_ctx, p, enq_flags);
out:
	release_active_ladder(&ladder_ctx);
	if (cell_enqueued)
		return;
	if (ret)
		scx_bpf_error("snake fairness enqueue failed for pid %d: %d",
			      p->pid, ret);
}

void BPF_STRUCT_OPS(snake_dispatch, s32 cpu, struct task_struct *prev)
{
	struct snake_ladder_ctx ladder_ctx = {};
	s32			 ret;

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in dispatch");
		return;
	}
	if (queue_topology_enabled()) {
		if (queue_ladder_dispatch(&ladder_ctx, cpu, prev))
			scx_bpf_error("snake queue dispatch failed on CPU %d", cpu);
		release_active_ladder(&ladder_ctx);
		return;
	}
	ret = fairness_dispatch(&ladder_ctx, cpu, prev);
	release_active_ladder(&ladder_ctx);
	if (ret)
		scx_bpf_error("snake fairness dispatch failed on CPU %d: %d", cpu,
			      ret);
}

void BPF_STRUCT_OPS(snake_runnable, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};

	(void)enq_flags;
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in runnable");
		return;
	}
	if (queue_topology_enabled()) {
		if (!queue_fairness_prepare_runnable(&ladder_ctx, p))
			scx_bpf_error("snake queue runnable preparation failed for pid %d",
				      p->pid);
		release_active_ladder(&ladder_ctx);
		return;
	}
	fairness_runnable(&ladder_ctx, p);
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_running, struct task_struct *p)
{
	struct snake_ladder_ctx ladder_ctx = {};

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
		release_active_ladder(&ladder_ctx);
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_RUNNING);
	fairness_running(&ladder_ctx, p);
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_stopping, struct task_struct *p, bool runnable)
{
	struct snake_ladder_ctx ladder_ctx = {};
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
			release_active_ladder(&ladder_ctx);
			return;
		}
		stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns);
		release_active_ladder(&ladder_ctx);
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_STOPPING);
	runtime_ns = fairness_stopping(&ladder_ctx, p);
	stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns);
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in quiescent");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_QUIESCENT);
	if (queue_topology_enabled()) {
		queue_fairness_cancel_direct(&ladder_ctx, p);
		release_active_ladder(&ladder_ctx);
		return;
	}
	fairness_quiescent(&ladder_ctx, p, deq_flags);
	release_active_ladder(&ladder_ctx);
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
