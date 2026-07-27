/* SPDX-License-Identifier: GPL-2.0-only */
#include "main.h"
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
	return prepare_mask_tables(slot, ladder);
}

/* Run the policy ladder, then use its affinity-safe exhaustion fallback. */
s32 BPF_STRUCT_OPS(snake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};
	u64 dispatch_flags = 0;
	u64 started_at	   = bpf_ktime_get_ns();
	s32 cpu;

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in select_cpu");
		return -1;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_SELECT_CALLS);

	cpu = walk_policy_ladder(&ladder_ctx, p, prev_cpu, wake_flags,
				 &dispatch_flags);
	if (cpu >= 0) {
		if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
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
	finish_select(&ladder_ctx, started_at);
	release_active_ladder(&ladder_ctx);
	return cpu;
}

void BPF_STRUCT_OPS(snake_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in enqueue");
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_ENQUEUES);
	release_active_ladder(&ladder_ctx);
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(snake_running, struct task_struct *p)
{
	struct snake_ladder_ctx ladder_ctx = {};
	struct snake_task_runtime *runtime;

	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in running");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_RUNNING);
	runtime = bpf_task_storage_get(&task_runtimes, p, 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!runtime) {
		stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
		release_active_ladder(&ladder_ctx);
		return;
	}
	runtime->started_exec_runtime = p->se.sum_exec_runtime;
	runtime->valid = 1;
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_stopping, struct task_struct *p, bool runnable)
{
	struct snake_ladder_ctx ladder_ctx = {};
	struct snake_task_runtime *runtime;
	u64 current_runtime;

	(void)runnable;
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in stopping");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_STOPPING);
	runtime = bpf_task_storage_get(&task_runtimes, p, 0, 0);
	if (runtime && runtime->valid) {
		current_runtime = p->se.sum_exec_runtime;
		if (current_runtime >= runtime->started_exec_runtime)
			stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS,
				 current_runtime - runtime->started_exec_runtime);
		else
			stat_inc(&ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
		runtime->valid = 0;
	}
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct snake_ladder_ctx ladder_ctx = {};

	(void)p;
	(void)deq_flags;
	if (acquire_active_ladder(&ladder_ctx)) {
		scx_bpf_error("snake failed to acquire active ladder in quiescent");
		return;
	}
	stat_inc(&ladder_ctx, SNAKE_STAT_QUIESCENT);
	release_active_ladder(&ladder_ctx);
}

/* Validate the published ladder before the scheduler can attach. */
s32 BPF_STRUCT_OPS_SLEEPABLE(snake_init)
{
	struct snake_ladder_ctx ladder_ctx = {};
	int			 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
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
	       .enqueue	  = (void *)snake_enqueue,
	       .running	  = (void *)snake_running,
	       .stopping  = (void *)snake_stopping,
	       .quiescent = (void *)snake_quiescent, .init = (void *)snake_init,
	       .exit = (void *)snake_exit, .timeout_ms = 5000, .name = "snake");
