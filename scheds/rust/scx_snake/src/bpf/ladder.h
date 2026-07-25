/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_LADDER_H
#define __SCX_SNAKE_LADDER_H

#include "mask_table.h"

/* Uniformly choose and claim one CPU from the task's allowed idle set. */
static __always_inline s32 pick_random_idle(const struct task_struct *p)
{
	const struct cpumask *idle;
	u32		      cpu, candidates = 0;
	s32		      selected = -1;
	bool		      claimed;

	idle = scx_bpf_get_idle_cpumask();
	if (!idle)
		return -EINVAL;

	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    bpf_cpumask_test_cpu(cpu, idle)) {
			candidates++;
			if (bpf_get_prandom_u32() % candidates == 0)
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

/* Apply the kernel-style synchronous wake-affine placement checks. */
static __always_inline s32 try_sync_wake_affine(
	const struct snake_ladder_ctx *ctx, struct task_struct *p, s32 prev_cpu,
	u64 wake_flags, u64 data, u64 *dispatch_flags)
{
	const struct cpumask *idle;
	struct task_struct   *waker;
	u32		      llc_table	 = data;
	u32		      node_table = data >> 32;
	s32		      waker_cpu, result;

	if (!(wake_flags & SCX_WAKE_SYNC))
		return -ENOENT;

	waker_cpu = bpf_get_smp_processor_id();
	result	  = mask_table_contains(ctx, llc_table, waker_cpu, prev_cpu);
	if (result < 0)
		return result;
	if (result && bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	waker = bpf_get_current_task_btf();
	if (!waker || !bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr) ||
	    (waker->flags & PF_EXITING) ||
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | waker_cpu) != 0)
		return -ENOENT;

	idle = scx_bpf_get_idle_cpumask();
	if (!idle)
		return -EINVAL;
	result = mask_table_intersects(ctx, node_table, waker_cpu, idle);
	scx_bpf_put_idle_cpumask(idle);
	if (result < 0)
		return result;

	if (result) {
		*dispatch_flags = SCX_ENQ_PREEMPT;
		return waker_cpu;
	}
	return -ENOENT;
}

/* Validate that a rung uses the supported mechanical ABI. */
static __always_inline bool rung_is_valid(const struct snake_rung *rung,
					  u32 nr_mask_tables)
{
	if (rung->reserved)
		return false;

	return (rung->opcode == SNAKE_OP_CLAIM_IDLE && !rung->flags &&
		rung->input == SNAKE_INPUT_CPU_PREV && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE &&
		(rung->flags == 0 ||
		 rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE) &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_RANDOM_IDLE && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_KERNEL_DEFAULT && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_SYNC_WAKE_AFFINE && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED &&
		(u32)rung->data < nr_mask_tables &&
		(u32)(rung->data >> 32) < nr_mask_tables) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE_MASK_TABLE &&
		rung->input == SNAKE_INPUT_CPU_PREV &&
		(rung->flags == SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED ||
		 rung->flags == (SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED |
				 SNAKE_RUNG_F_PICK_IDLE_CORE)) &&
		rung->data < nr_mask_tables);
}

/* Execute one validated rung and return an idle CPU or a miss. */
static __always_inline s32 execute_rung(const struct snake_ladder_ctx *ctx,
					struct task_struct *p,
					const struct snake_rung *rung, s32 prev_cpu,
					u64 wake_flags, u64 *dispatch_flags)
{
	switch (rung->opcode) {
	case SNAKE_OP_CLAIM_IDLE:
		/* Affinity is checked before the destructive idle claim. */
		if (prev_cpu >= 0 && prev_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		break;
	case SNAKE_OP_PICK_IDLE:
		prev_cpu = scx_bpf_pick_idle_cpu(
			p->cpus_ptr, rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE ?
					     SCX_PICK_IDLE_CORE :
					     0);
		return prev_cpu < 0 ? -ENOENT : prev_cpu;
	case SNAKE_OP_PICK_RANDOM_IDLE:
		return pick_random_idle(p);
	case SNAKE_OP_KERNEL_DEFAULT: {
		bool is_idle = false;
		s32  cpu;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return is_idle ? cpu : -ENOENT;
	}
	case SNAKE_OP_SYNC_WAKE_AFFINE:
		return try_sync_wake_affine(ctx, p, prev_cpu, wake_flags, rung->data,
					    dispatch_flags);
	case SNAKE_OP_PICK_IDLE_MASK_TABLE:
		if (rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE)
			return pick_idle_core_from_mask_table(ctx, p, rung->data,
							      prev_cpu);
		return pick_idle_from_mask_table(ctx, p, rung->data, prev_cpu,
						 p->cpus_ptr);
	default:
		break;
	}

	return -ENOENT;
}

/* Evaluate the configured rungs in order until one returns a valid hint. */
static __always_inline s32 walk_policy_ladder(struct snake_ladder_ctx *ctx,
					      struct task_struct *p, s32 prev_cpu,
					      u64 wake_flags, u64 *dispatch_flags)
{
	u32 i;

	bpf_for(i, 0, SNAKE_MAX_RUNGS)
	{
		struct snake_rung rung;
		s32		  cpu;

		if (i >= ctx->ladder->nr_rungs)
			break;

		rung = ctx->ladder->rungs[i];
		stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + i);

		if (!rung_is_valid(&rung, ctx->ladder->nr_mask_tables)) {
			stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + i);
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake invalid rung %u: opcode=%u input=%u", i,
				rung.opcode, rung.input);
			return -1;
		}

		*dispatch_flags = 0;
		cpu		= execute_rung(ctx, p, &rung, prev_cpu, wake_flags,
					       dispatch_flags);
		if (cpu < 0 && cpu != -ENOENT) {
			stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + i);
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error("snake rung %u execution failed: %d", i,
				      cpu);
			return cpu;
		}
		if (cpu >= 0 && cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			stat_inc(ctx, SNAKE_STAT_RUNG_HIT_BASE + i);
			return cpu;
		}

		stat_inc(ctx, SNAKE_STAT_RUNG_MISS_BASE + i);
	}

	return -ENOENT;
}

#endif /* __SCX_SNAKE_LADDER_H */
