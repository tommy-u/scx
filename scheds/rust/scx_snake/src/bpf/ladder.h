/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_LADDER_H
#define __SCX_SNAKE_LADDER_H

#include "mask_table.h"
#include "cpu_pick.h"
#include "queue_fairness.h"

/* Uniformly choose and claim one CPU from the task's allowed idle set. */
static __always_inline s32 pick_random_idle(const struct task_struct *p,
					    bool whole_core)
{
	return cpu_pick_random_idle(p->cpus_ptr, whole_core);
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
	    dsq_nr_queued(dsq_local_on(waker_cpu)) != 0)
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

	return (rung->opcode == SNAKE_OP_CLAIM_IDLE &&
		(rung->flags == 0 ||
		 rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE) &&
		rung->input == SNAKE_INPUT_CPU_PREV && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE &&
		(rung->flags == 0 ||
		 rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE) &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_RANDOM_IDLE &&
		(((rung->flags == 0 ||
		   rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE) &&
		  rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED &&
		  !rung->data) ||
		 ((rung->flags == SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED ||
		   rung->flags == (SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED |
				   SNAKE_RUNG_F_PICK_IDLE_CORE)) &&
		  (rung->input == SNAKE_INPUT_CPU_PREV ||
		   rung->input == SNAKE_INPUT_TASK_CELL) &&
		  rung->data < nr_mask_tables))) ||
	       (rung->opcode == SNAKE_OP_KERNEL_DEFAULT && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_SYNC_WAKE_AFFINE && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED &&
		(u32)rung->data < nr_mask_tables &&
		(u32)(rung->data >> 32) < nr_mask_tables) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE_MASK_TABLE &&
		(rung->input == SNAKE_INPUT_CPU_PREV ||
		 rung->input == SNAKE_INPUT_TASK_CELL) &&
		(rung->flags == SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED ||
		 rung->flags == (SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED |
				 SNAKE_RUNG_F_PICK_IDLE_CORE)) &&
		rung->data < nr_mask_tables) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE_QUEUE_MASK &&
		rung->input == SNAKE_INPUT_QUEUE_CELL &&
		(rung->flags == 0 ||
		 rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE ||
		 rung->flags == SNAKE_RUNG_F_PICK_RANDOM ||
		 rung->flags == (SNAKE_RUNG_F_PICK_RANDOM |
				 SNAKE_RUNG_F_PICK_IDLE_CORE)) &&
		(rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
		 rung->data == SNAKE_QUEUE_MASK_BORROWABLE));
}

struct snake_rung_exec_args {
	s32  prev_cpu;
	u64  wake_flags;
	u64 *dispatch_flags;
	u32 *queue_cell_index;
};

struct snake_ladder_walk_args {
	s32 prev_cpu;
	u32 queue_cell_index;
	u64 wake_flags;
	u64 dispatch_flags;
	u64 callback_started_at;
};

/* Execute one validated rung and return an idle CPU or a miss. */
static __noinline s32 execute_rung(const struct snake_ladder_ctx *ctx,
				   struct task_struct		 *p,
				   const struct snake_rung	 *rung,
				   struct snake_rung_exec_args	 *args)
{
	s32  prev_cpu	      = args->prev_cpu;
	u64  wake_flags	      = args->wake_flags;
	u64 *dispatch_flags   = args->dispatch_flags;
	u32 *queue_cell_index = args->queue_cell_index;

	switch (rung->opcode) {
	case SNAKE_OP_CLAIM_IDLE: {
		const struct cpumask *idle;
		bool whole_core_idle;

		/* Affinity is checked before the destructive idle claim. */
		if (prev_cpu < 0 || prev_cpu >= nr_cpu_ids ||
		    !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
			break;
		if (rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE) {
			idle = scx_bpf_get_idle_smtmask();
			if (!idle)
				return -EINVAL;
			whole_core_idle = bpf_cpumask_test_cpu(prev_cpu, idle);
			scx_bpf_put_idle_cpumask(idle);
			if (!whole_core_idle)
				break;
		}
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		break;
	}
	case SNAKE_OP_PICK_IDLE:
		prev_cpu = scx_bpf_pick_idle_cpu(
			p->cpus_ptr, rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE ?
					     SCX_PICK_IDLE_CORE :
					     0);
		return prev_cpu < 0 ? -ENOENT : prev_cpu;
	case SNAKE_OP_PICK_RANDOM_IDLE:
		if (rung->input == SNAKE_INPUT_TASK_CELL) {
			struct snake_task_cell *cell;
			s32			exists, cpu;

			cell = task_annotation(p);
			if (!cell)
				return -ENOENT;
			exists = mask_table_has_key(ctx, rung->data,
						    READ_ONCE(cell->cell_id));
			if (exists <= 0)
				return exists < 0 ? exists : -ENOENT;
			cpu = pick_random_idle_from_mask_table(
				ctx, p, rung->data, READ_ONCE(cell->cell_id),
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
			if (cpu >= 0) {
				if (READ_ONCE(cell->needs_rehome))
					stat_inc(ctx, SNAKE_STAT_CELL_REHOMES);
				WRITE_ONCE(cell->needs_rehome, 0);
			}
			return cpu;
		}
		if (rung->input == SNAKE_INPUT_CPU_PREV)
			return pick_random_idle_from_mask_table(
				ctx, p, rung->data, prev_cpu,
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
		return pick_random_idle(p, rung->flags &
						   SNAKE_RUNG_F_PICK_IDLE_CORE);
	case SNAKE_OP_KERNEL_DEFAULT: {
		bool is_idle = false;
		s32  cpu;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return is_idle ? cpu : -ENOENT;
	}
	case SNAKE_OP_SYNC_WAKE_AFFINE:
		return try_sync_wake_affine(ctx, p, prev_cpu, wake_flags,
					    rung->data, dispatch_flags);
	case SNAKE_OP_PICK_IDLE_MASK_TABLE:
		if (rung->input == SNAKE_INPUT_TASK_CELL) {
			struct snake_task_cell *cell;
			s32			exists, cpu;

			cell = task_annotation(p);
			if (!cell)
				return -ENOENT;
			exists = mask_table_has_key(ctx, rung->data,
						    READ_ONCE(cell->cell_id));
			if (exists <= 0)
				return exists < 0 ? exists : -ENOENT;
			cpu = pick_idle_from_mask_table(
				ctx, p, rung->data, READ_ONCE(cell->cell_id),
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
			if (cpu >= 0) {
				if (READ_ONCE(cell->needs_rehome))
					stat_inc(ctx, SNAKE_STAT_CELL_REHOMES);
				WRITE_ONCE(cell->needs_rehome, 0);
			}
			return cpu;
		}
		return pick_idle_from_mask_table(
			ctx, p, rung->data, prev_cpu,
			rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
	case SNAKE_OP_PICK_IDLE_QUEUE_MASK: {
		s32 cpu;

		cpu = queue_pick_task_cell_cpu(
			p, rung->data,
			rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE,
			rung->flags & SNAKE_RUNG_F_PICK_RANDOM,
			queue_cell_index);
		if (cpu >= 0 && rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
			*dispatch_flags |= SNAKE_SELECT_F_BORROWED;
		return cpu;
	}
	default:
		break;
	}

	return -ENOENT;
}

struct snake_task_cell_enqueue_loop_ctx {
	struct snake_ladder_ctx	     ladder_ctx;
	struct task_struct	    *p;
	struct snake_fine_timing_ctx fine;
	u64			     enq_flags;
	u64			     slice;
	u64			     callback_started_at;
	s32			     result;
};

static long try_enqueue_task_cell_callback(
	u32 i, struct snake_task_cell_enqueue_loop_ctx *loop_ctx)
{
	struct snake_rung	    rung;
	u64			    dispatch_flags   = 0;
	u32			    queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	struct snake_rung_exec_args args	     = {
			    .prev_cpu	      = -1,
			    .wake_flags	      = 0,
			    .dispatch_flags   = &dispatch_flags,
			    .queue_cell_index = &queue_cell_index,
	};
	s32 cpu;
	u64 rung_started_at;

	if (i >= SNAKE_MAX_RUNGS || i >= loop_ctx->ladder_ctx.ladder->nr_rungs)
		return 1;
	rung = loop_ctx->ladder_ctx.ladder->rungs[i];
	if (rung.input != SNAKE_INPUT_TASK_CELL)
		return 0;

	stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + i);
	rung_started_at = rung_timing_start(loop_ctx->callback_started_at);
	cpu = execute_rung(&loop_ctx->ladder_ctx, loop_ctx->p, &rung, &args);
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_IDLE, i,
			   rung_started_at);
	if (cpu >= 0 && cpu < nr_cpu_ids) {
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_HIT_BASE + i);
		if (!dsq_insert(loop_ctx->p, dsq_local_on(cpu), loop_ctx->slice,
				loop_ctx->enq_flags, &loop_ctx->fine)) {
			stat_inc(&loop_ctx->ladder_ctx,
				 SNAKE_STAT_INVALID_ERRORS);
			loop_ctx->result = -EINVAL;
			return 1;
		}
		queue_timing_record_insert(&loop_ctx->ladder_ctx, loop_ctx->p,
					   dsq_local_on(cpu),
					   SNAKE_QUEUE_CELL_NONE,
					   &loop_ctx->fine);
		loop_ctx->result = 1;
		return 1;
	}
	if (cpu < 0 && cpu != -ENOENT) {
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_ERROR_BASE + i);
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
		loop_ctx->result = cpu;
		return 1;
	}
	stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_MISS_BASE + i);
	return 0;
}

/* Keep annotated runnable tasks on CPUs selected by their task-cell rungs. */
static __always_inline s32 try_enqueue_task_cell(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u64 enq_flags,
	u64 slice, const struct snake_fine_timing_ctx *fine,
	u64 callback_started_at)
{
	struct snake_task_cell		       *cell;
	struct snake_task_cell_enqueue_loop_ctx loop_ctx = {
		.ladder_ctx = *ctx,
		.p	    = p,
		.fine	    = fine ? *fine : (struct snake_fine_timing_ctx){},
		.enq_flags  = enq_flags,
		.slice	    = slice,
		.callback_started_at = callback_started_at,
		.result		     = 0,
	};
	bool rehome_pending;
	long nr_loops;

	cell = task_annotation(p);
	if (!cell)
		return 0;
	rehome_pending = READ_ONCE(cell->needs_rehome);

	nr_loops = bpf_loop(SNAKE_MAX_RUNGS, try_enqueue_task_cell_callback,
			    &loop_ctx, 0);
	if (nr_loops < 0) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		return nr_loops;
	}
	if (!loop_ctx.result && rehome_pending)
		stat_inc(ctx, SNAKE_STAT_CELL_REHOME_MISSES);
	return loop_ctx.result;
}

static __noinline s32 walk_policy_rung(struct snake_ladder_ctx *ctx,
				       struct task_struct *p, u32 i,
				       struct snake_ladder_walk_args *walk_args)
{
	struct snake_rung	    rung;
	u64			    dispatch_flags   = 0;
	u32			    queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	struct snake_rung_exec_args args	     = {
			    .prev_cpu	      = walk_args->prev_cpu,
			    .wake_flags	      = walk_args->wake_flags,
			    .dispatch_flags   = &dispatch_flags,
			    .queue_cell_index = &queue_cell_index,
	};
	s32 cpu;
	u64 rung_started_at;

	rung = ctx->ladder->rungs[i];
	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + i);

	if (!rung_is_valid(&rung, ctx->ladder->nr_mask_tables)) {
		stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + i);
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake invalid rung %u: opcode=%u input=%u", i,
			      rung.opcode, rung.input);
		return -1;
	}

	rung_started_at = rung_timing_start(walk_args->callback_started_at);
	cpu		= execute_rung(ctx, p, &rung, &args);
	walk_args->dispatch_flags   = dispatch_flags;
	walk_args->queue_cell_index = queue_cell_index;
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_IDLE, i, rung_started_at);
	if (cpu < 0 && cpu != -ENOENT) {
		stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + i);
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake rung %u execution failed: %d", i, cpu);
		return cpu;
	}
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_RUNG_HIT_BASE + i);
		return cpu;
	}

	stat_inc(ctx, SNAKE_STAT_RUNG_MISS_BASE + i);
	return -ENOENT;
}

struct snake_ladder_walk_loop_ctx {
	struct snake_ladder_ctx	      ladder_ctx;
	struct task_struct	     *p;
	struct snake_ladder_walk_args walk_args;
	s32			      result;
};

static long
walk_policy_ladder_callback(u32 i, struct snake_ladder_walk_loop_ctx *loop_ctx)
{
	if (i >= SNAKE_MAX_RUNGS || i >= loop_ctx->ladder_ctx.ladder->nr_rungs)
		return 1;
	loop_ctx->result = walk_policy_rung(&loop_ctx->ladder_ctx, loop_ctx->p,
					    i, &loop_ctx->walk_args);
	return loop_ctx->result != -ENOENT;
}

/* Evaluate the configured rungs in order until one returns a valid hint. */
static __noinline s32
walk_policy_ladder(struct snake_ladder_ctx *ctx, struct task_struct *p,
		   struct snake_ladder_walk_args *walk_args)
{
	struct snake_ladder_walk_loop_ctx loop_ctx = {
		.ladder_ctx = *ctx,
		.p	    = p,
		.walk_args  = *walk_args,
		.result	    = -ENOENT,
	};
	long nr_loops;

	nr_loops   = bpf_loop(SNAKE_MAX_RUNGS, walk_policy_ladder_callback,
			      &loop_ctx, 0);
	*walk_args = loop_ctx.walk_args;
	if (nr_loops < 0) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake policy ladder loop failed: %ld", nr_loops);
		return nr_loops;
	}
	return loop_ctx.result;
}

#endif /* __SCX_SNAKE_LADDER_H */
