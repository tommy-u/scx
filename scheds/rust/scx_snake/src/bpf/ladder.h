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
	u64 wake_flags, u64 data, u64 *enqueue_flags)
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
		*enqueue_flags = SCX_ENQ_PREEMPT;
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
		((rung->input == SNAKE_INPUT_CPU_PREV && !rung->data) ||
		 (rung->input == SNAKE_INPUT_QUEUE_CELL &&
		  (rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
		   rung->data == SNAKE_QUEUE_MASK_BORROWABLE ||
		   rung->data == SNAKE_QUEUE_MASK_LOCAL_LLC)) ||
		 (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED &&
		  !rung->data))) ||
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
		(((rung->input == SNAKE_INPUT_QUEUE_CELL &&
		   (rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
		    rung->data == SNAKE_QUEUE_MASK_BORROWABLE)) &&
		  (rung->flags == 0 ||
		   rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE ||
		   rung->flags == SNAKE_RUNG_F_PICK_RANDOM ||
		   rung->flags == (SNAKE_RUNG_F_PICK_RANDOM |
				  SNAKE_RUNG_F_PICK_IDLE_CORE))) ||
		 (((rung->input == SNAKE_INPUT_QUEUE_CELL &&
		    rung->data == SNAKE_QUEUE_MASK_LOCAL_LLC) ||
		   (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED &&
		    !rung->data)) &&
		  (rung->flags == 0 ||
		   rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE)))) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS &&
		!rung->flags &&
		((rung->input == SNAKE_INPUT_QUEUE_CELL &&
		  (rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
		   rung->data == SNAKE_QUEUE_MASK_BORROWABLE ||
		   rung->data == SNAKE_QUEUE_MASK_LOCAL_LLC ||
		   rung->data == SNAKE_QUEUE_MASK_GROUP_LLC)) ||
		 (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED &&
		  !rung->data)));
}

static __always_inline bool
queue_atomic_rung_is_valid(const struct snake_rung *rung)
{
	if (rung->reserved)
		return false;
	if (rung->opcode == SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS)
		return !rung->flags && rung->input == SNAKE_INPUT_QUEUE_CELL &&
		       rung->data == SNAKE_QUEUE_MASK_GROUP_LLC;

	if (rung->opcode == SNAKE_OP_CLAIM_IDLE) {
		if (rung->flags != 0 &&
		    rung->flags != SNAKE_RUNG_F_PICK_IDLE_CORE)
			return false;
		return (rung->input == SNAKE_INPUT_QUEUE_CELL &&
			(rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
			 rung->data == SNAKE_QUEUE_MASK_BORROWABLE ||
			 rung->data == SNAKE_QUEUE_MASK_LOCAL_LLC)) ||
		       (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED &&
			!rung->data);
	}

	if (rung->opcode != SNAKE_OP_PICK_IDLE_QUEUE_MASK)
		return false;
	if (rung->input == SNAKE_INPUT_QUEUE_CELL &&
	    (rung->data == SNAKE_QUEUE_MASK_PRIMARY ||
	     rung->data == SNAKE_QUEUE_MASK_BORROWABLE))
		return rung->flags == 0 ||
		       rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE ||
		       rung->flags == SNAKE_RUNG_F_PICK_RANDOM ||
		       rung->flags == (SNAKE_RUNG_F_PICK_RANDOM |
				      SNAKE_RUNG_F_PICK_IDLE_CORE);
	return ((rung->input == SNAKE_INPUT_QUEUE_CELL &&
		 rung->data == SNAKE_QUEUE_MASK_LOCAL_LLC) ||
		(rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED &&
		 !rung->data)) &&
	       (rung->flags == 0 ||
		rung->flags == SNAKE_RUNG_F_PICK_IDLE_CORE);
}

static __always_inline bool expanded_mitosis_rung_matches(
	const struct snake_rung *rung, u32 index, u32 nr_rungs)
{
	u32 action, expected_flags, expected_input, expected_opcode;
	u64 expected_data;

	if (nr_rungs == SNAKE_MAX_RUNGS) {
		if (!index)
			return rung->opcode == SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS &&
			       rung->input == SNAKE_INPUT_QUEUE_CELL &&
			       !rung->flags && !rung->reserved &&
			       rung->data == SNAKE_QUEUE_MASK_GROUP_LLC;
		index--;
	} else if (nr_rungs != SNAKE_EXPANDED_MITOSIS_RUNGS) {
		return false;
	}
	if (index >= SNAKE_EXPANDED_MITOSIS_RUNGS)
		return false;
	action = index & 3;
	expected_opcode = action == 0 || action == 2 ?
				  SNAKE_OP_CLAIM_IDLE :
				  SNAKE_OP_PICK_IDLE_QUEUE_MASK;
	expected_flags = action < 2 ? SNAKE_RUNG_F_PICK_IDLE_CORE : 0;
	switch (index >> 2) {
	case 0:
		expected_input = SNAKE_INPUT_QUEUE_CELL;
		expected_data = SNAKE_QUEUE_MASK_LOCAL_LLC;
		break;
	case 1:
		expected_input = SNAKE_INPUT_QUEUE_CELL;
		expected_data = SNAKE_QUEUE_MASK_PRIMARY;
		break;
	case 2:
		expected_input = SNAKE_INPUT_QUEUE_CELL;
		expected_data = SNAKE_QUEUE_MASK_BORROWABLE;
		break;
	case 3:
		expected_input = SNAKE_INPUT_TASK_ALLOWED_RESTRICTED;
		expected_data = 0;
		break;
	default:
		return false;
	}
	return rung->opcode == expected_opcode &&
	       rung->input == expected_input &&
	       rung->flags == expected_flags && !rung->reserved &&
	       rung->data == expected_data;
}

struct snake_rung_exec_args {
	s32  prev_cpu;
	u64  wake_flags;
	u64 *enqueue_flags;
	u64 *select_flags;
	u32 *queue_cell_index;
	u32 *local_llc_route_cpu;
	u32 *local_llc_cell_index;
};

struct snake_ladder_walk_args {
	s32 prev_cpu;
	u32 queue_cell_index;
	u64 wake_flags;
	u64 enqueue_flags;
	u64 select_flags;
	u64 callback_started_at;
	u64 scope_started_at;
	u32 local_llc_route_cpu;
	u32 local_llc_cell_index;
};

/* Execute one validated rung and return an idle CPU or a miss. */
static __always_inline s32
execute_rung_impl(const struct snake_ladder_ctx *ctx, struct task_struct *p,
		  const struct snake_rung *rung,
		  struct snake_rung_exec_args *args)
{
	s32  prev_cpu	      = args->prev_cpu;
	u64  wake_flags	      = args->wake_flags;
	u64 *enqueue_flags    = args->enqueue_flags;
	u64 *select_flags     = args->select_flags;
	u32 *queue_cell_index = args->queue_cell_index;
	u32 *local_llc_route_cpu = args->local_llc_route_cpu;
	u32 *local_llc_cell_index = args->local_llc_cell_index;
	struct snake_queue_idle_args queue_args = {
		.prev_cpu = prev_cpu,
		.kind = 0,
		.whole_core = false,
		.random = false,
		.local_llc_route_cpu = local_llc_route_cpu,
		.local_llc_cell_index = local_llc_cell_index,
		.cell_index = queue_cell_index,
	};

	switch (rung->opcode) {
	case SNAKE_OP_CLAIM_IDLE: {
		const struct cpumask *idle;
		bool whole_core_idle;
		s32 cpu;

		if (rung->input == SNAKE_INPUT_QUEUE_CELL) {
			queue_args.kind = rung->data;
			queue_args.whole_core =
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE;
			cpu = queue_claim_task_cell_cpu(ctx, p, &queue_args);
			if (cpu >= 0 &&
			    rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
				*select_flags |= SNAKE_SELECT_F_BORROWED;
			return cpu;
		}
		if (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED) {
			cpu = queue_claim_restricted_cpu(
				ctx, p, prev_cpu,
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE,
				queue_cell_index);
			if (cpu >= 0)
				*select_flags |= SNAKE_SELECT_F_AFFINITY;
			return cpu;
		}

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
			u32			cell_id;
			s32			exists, cpu;

			exists = queue_task_cell_id(ctx, p, &cell_id);
			if (exists)
				return exists;
			exists = mask_table_has_key(ctx, rung->data, cell_id);
			if (exists <= 0)
				return exists < 0 ? exists : -ENOENT;
			cpu = pick_random_idle_from_mask_table(
				ctx, p, rung->data, cell_id,
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
			if (cpu >= 0) {
				if (task_cell_rehome_pending(p))
					stat_inc(ctx, SNAKE_STAT_CELL_REHOMES);
				task_cell_clear_rehome(p);
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
					    rung->data, enqueue_flags);
	case SNAKE_OP_PICK_IDLE_MASK_TABLE:
		if (rung->input == SNAKE_INPUT_TASK_CELL) {
			u32			cell_id;
			s32			exists, cpu;

			exists = queue_task_cell_id(ctx, p, &cell_id);
			if (exists)
				return exists;
			exists = mask_table_has_key(ctx, rung->data, cell_id);
			if (exists <= 0)
				return exists < 0 ? exists : -ENOENT;
			cpu = pick_idle_from_mask_table(
				ctx, p, rung->data, cell_id,
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
			if (cpu >= 0) {
				if (task_cell_rehome_pending(p))
					stat_inc(ctx, SNAKE_STAT_CELL_REHOMES);
				task_cell_clear_rehome(p);
			}
			return cpu;
		}
		return pick_idle_from_mask_table(
			ctx, p, rung->data, prev_cpu,
			rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE);
	case SNAKE_OP_PICK_IDLE_QUEUE_MASK: {
		s32 cpu;

		if (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED) {
			cpu = queue_pick_restricted_cpu(
				ctx, p,
				rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE,
				queue_cell_index);
			if (cpu >= 0)
				*select_flags |= SNAKE_SELECT_F_AFFINITY;
			return cpu;
		}
		queue_args.kind = rung->data;
		queue_args.whole_core =
			rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE;
		queue_args.random = rung->flags & SNAKE_RUNG_F_PICK_RANDOM;
		cpu = queue_pick_task_cell_cpu(ctx, p, &queue_args);
		if (cpu >= 0 && rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
			*select_flags |= SNAKE_SELECT_F_BORROWED;
		return cpu;
	}
	case SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS: {
		s32 cpu;

		if (rung->input == SNAKE_INPUT_QUEUE_CELL) {
			cpu = queue_pick_task_cell_preferred_cpu(
				ctx, p, rung->data, prev_cpu, queue_cell_index);
			if (cpu >= 0 &&
			    rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
				*select_flags |= SNAKE_SELECT_F_BORROWED;
			return cpu;
		}
		cpu = queue_pick_restricted_preferred_cpu(
			ctx, p, prev_cpu, queue_cell_index);
		if (cpu >= 0)
			*select_flags |= SNAKE_SELECT_F_AFFINITY;
		return cpu;
	}
	default:
		break;
	}

	return -ENOENT;
}

/* Enqueue keeps a call boundary to control verifier state growth. */
static __noinline s32 execute_rung(const struct snake_ladder_ctx *ctx,
				   struct task_struct *p,
				   const struct snake_rung *rung,
				   struct snake_rung_exec_args *args)
{
	return execute_rung_impl(ctx, p, rung, args);
}

/* Cell direct-dispatch policies accept only queue-routed placement rungs. */
static __always_inline s32 execute_direct_enqueue_rung(
	const struct snake_ladder_ctx *ctx, struct task_struct *p,
	const struct snake_rung *rung, struct snake_rung_exec_args *args)
{
	struct snake_queue_idle_args queue_args = {
		.prev_cpu = args->prev_cpu,
		.kind = rung->data,
		.whole_core = rung->flags & SNAKE_RUNG_F_PICK_IDLE_CORE,
		.random = rung->flags & SNAKE_RUNG_F_PICK_RANDOM,
		.local_llc_route_cpu = args->local_llc_route_cpu,
		.local_llc_cell_index = args->local_llc_cell_index,
		.cell_index = args->queue_cell_index,
	};
	s32 cpu;

	if (rung->input != SNAKE_INPUT_QUEUE_CELL &&
	    rung->input != SNAKE_INPUT_TASK_ALLOWED_RESTRICTED)
		return -EINVAL;

	switch (rung->opcode) {
	case SNAKE_OP_CLAIM_IDLE:
		if (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED) {
			cpu = queue_claim_restricted_cpu(
				ctx, p, args->prev_cpu, queue_args.whole_core,
				args->queue_cell_index);
			if (cpu >= 0)
				*args->select_flags |= SNAKE_SELECT_F_AFFINITY;
			return cpu;
		}
		cpu = queue_claim_task_cell_cpu(ctx, p, &queue_args);
		if (cpu >= 0 && rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
			*args->select_flags |= SNAKE_SELECT_F_BORROWED;
		return cpu;
	case SNAKE_OP_PICK_IDLE_QUEUE_MASK:
		if (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED) {
			cpu = queue_pick_restricted_cpu(
				ctx, p, queue_args.whole_core,
				args->queue_cell_index);
			if (cpu >= 0)
				*args->select_flags |= SNAKE_SELECT_F_AFFINITY;
			return cpu;
		}
		cpu = queue_pick_task_cell_cpu(ctx, p, &queue_args);
		if (cpu >= 0 && rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
			*args->select_flags |= SNAKE_SELECT_F_BORROWED;
		return cpu;
	case SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS:
		if (rung->input == SNAKE_INPUT_TASK_ALLOWED_RESTRICTED) {
			cpu = queue_pick_restricted_preferred_cpu(
				ctx, p, args->prev_cpu, args->queue_cell_index);
			if (cpu >= 0)
				*args->select_flags |= SNAKE_SELECT_F_AFFINITY;
			return cpu;
		}
		cpu = queue_pick_task_cell_preferred_cpu(
			ctx, p, rung->data, args->prev_cpu,
			args->queue_cell_index);
		if (cpu >= 0 && rung->data == SNAKE_QUEUE_MASK_BORROWABLE)
			*args->select_flags |= SNAKE_SELECT_F_BORROWED;
		return cpu;
	default:
		return -EINVAL;
	}
}

/* Select inlines the same mechanism to stay below the combined stack limit. */
static __always_inline s32
execute_select_rung(const struct snake_ladder_ctx *ctx, struct task_struct *p,
		    const struct snake_rung *rung,
		    struct snake_rung_exec_args *args)
{
	return execute_rung_impl(ctx, p, rung, args);
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
	u64			    enqueue_flags    = 0;
	u64			    select_flags     = 0;
	u32			    queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	u32			    local_llc_route_cpu = SNAKE_QUEUE_CELL_NONE;
	u32			    local_llc_cell_index = SNAKE_QUEUE_CELL_NONE;
	struct snake_rung_exec_args args	     = {
			    .prev_cpu	      = -1,
			    .wake_flags	      = 0,
			    .enqueue_flags    = &enqueue_flags,
			    .select_flags     = &select_flags,
			    .queue_cell_index = &queue_cell_index,
			    .local_llc_route_cpu = &local_llc_route_cpu,
			    .local_llc_cell_index = &local_llc_cell_index,
	};
	s32 cpu;
	u64 rung_started_at;

	if (i >= SNAKE_MAX_GENERIC_RUNGS ||
	    i >= loop_ctx->ladder_ctx.ladder->nr_rungs)
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

	if (queue_task_membership_kind(ctx, p) == SNAKE_MEMBERSHIP_NO_CELL)
		return 0;
	rehome_pending = task_cell_rehome_pending(p);

	nr_loops = bpf_loop(SNAKE_MAX_GENERIC_RUNGS,
			    try_enqueue_task_cell_callback,
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
	u64			    enqueue_flags    = 0;
	u64			    select_flags     = 0;
	u32			    queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	struct snake_rung_exec_args args	     = {
			    .prev_cpu	      = walk_args->prev_cpu,
			    .wake_flags	      = walk_args->wake_flags,
			    .enqueue_flags    = &enqueue_flags,
			    .select_flags     = &select_flags,
			    .queue_cell_index = &queue_cell_index,
			    .local_llc_route_cpu = &walk_args->local_llc_route_cpu,
			    .local_llc_cell_index = &walk_args->local_llc_cell_index,
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
	cpu		= execute_select_rung(ctx, p, &rung, &args);
	walk_args->enqueue_flags    = enqueue_flags;
	walk_args->select_flags     = select_flags;
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

static __noinline s32
walk_generic_policy_ladder(struct snake_ladder_ctx *ctx, struct task_struct *p,
			   struct snake_ladder_walk_args *walk_args)
{
	s32 result;

	if (!ctx->ladder->nr_rungs)
		return -ENOENT;
	result = walk_policy_rung(ctx, p, 0, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 1)
		return result;
	result = walk_policy_rung(ctx, p, 1, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 2)
		return result;
	result = walk_policy_rung(ctx, p, 2, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 3)
		return result;
	result = walk_policy_rung(ctx, p, 3, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 4)
		return result;
	result = walk_policy_rung(ctx, p, 4, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 5)
		return result;
	result = walk_policy_rung(ctx, p, 5, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 6)
		return result;
	result = walk_policy_rung(ctx, p, 6, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 7)
		return result;
	result = walk_policy_rung(ctx, p, 7, walk_args);
	if (result != -ENOENT || ctx->ladder->nr_rungs <= 8)
		return result;
	return walk_policy_rung(ctx, p, 8, walk_args);
}

struct snake_enqueue_ladder_loop_ctx {
	struct snake_ladder_ctx ladder_ctx;
	struct task_struct *p;
	struct snake_ladder_walk_args walk_args;
	s32 result;
};

static long walk_generic_enqueue_ladder_callback(
	u32 i, struct snake_enqueue_ladder_loop_ctx *loop_ctx)
{
	struct snake_rung rung;
	u64 enqueue_flags = 0;
	u64 select_flags = 0;
	u32 queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	struct snake_rung_exec_args args = {
		.prev_cpu = loop_ctx->walk_args.prev_cpu,
		.wake_flags = loop_ctx->walk_args.wake_flags,
		.enqueue_flags = &enqueue_flags,
		.select_flags = &select_flags,
		.queue_cell_index = &queue_cell_index,
		.local_llc_route_cpu =
			&loop_ctx->walk_args.local_llc_route_cpu,
		.local_llc_cell_index =
			&loop_ctx->walk_args.local_llc_cell_index,
	};
	s32 cpu;
	u64 rung_started_at;

	if (i >= SNAKE_MAX_GENERIC_RUNGS ||
	    i >= loop_ctx->ladder_ctx.ladder->nr_rungs)
		return 1;
	rung = loop_ctx->ladder_ctx.ladder->rungs[i];
	stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + i);

	if (!rung_is_valid(&rung,
			   loop_ctx->ladder_ctx.ladder->nr_mask_tables)) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_RUNG_ERROR_BASE + i);
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake invalid enqueue rung %u: opcode=%u input=%u",
			      i, rung.opcode, rung.input);
		loop_ctx->result = -EINVAL;
		return 1;
	}

	rung_started_at =
		rung_timing_start(loop_ctx->walk_args.callback_started_at);
	cpu = execute_direct_enqueue_rung(
		&loop_ctx->ladder_ctx, loop_ctx->p, &rung, &args);
	loop_ctx->walk_args.enqueue_flags = enqueue_flags;
	loop_ctx->walk_args.select_flags = select_flags;
	loop_ctx->walk_args.queue_cell_index = queue_cell_index;
	rung_timing_finish(&loop_ctx->ladder_ctx, SNAKE_RUNG_LADDER_IDLE, i,
			   rung_started_at);
	if (cpu < 0 && cpu != -ENOENT) {
		stat_inc(&loop_ctx->ladder_ctx,
			 SNAKE_STAT_RUNG_ERROR_BASE + i);
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake enqueue rung %u execution failed: %d", i,
			      cpu);
		loop_ctx->result = cpu;
		return 1;
	}
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, loop_ctx->p->cpus_ptr)) {
		stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_HIT_BASE + i);
		loop_ctx->result = cpu;
		return 1;
	}

	stat_inc(&loop_ctx->ladder_ctx, SNAKE_STAT_RUNG_MISS_BASE + i);
	return 0;
}

static __noinline s32 walk_generic_policy_ladder_from_enqueue(
	struct snake_ladder_ctx *ctx, struct task_struct *p,
	struct snake_ladder_walk_args *walk_args)
{
	struct snake_enqueue_ladder_loop_ctx loop_ctx = {
		.ladder_ctx = *ctx,
		.p = p,
		.walk_args = *walk_args,
		.result = -ENOENT,
	};
	long nr_loops;

	if (!ctx->ladder->nr_rungs)
		return -ENOENT;
	nr_loops = bpf_loop(SNAKE_MAX_GENERIC_RUNGS,
			    walk_generic_enqueue_ladder_callback, &loop_ctx, 0);
	if (nr_loops < 0)
		return nr_loops;
	*walk_args = loop_ctx.walk_args;
	return loop_ctx.result;
}

static __always_inline s32 expanded_mitosis_finish_stage(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u32 index,
	u64 started_at, s32 cpu)
{
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_IDLE, index, started_at);
	if (cpu < 0 && cpu != -ENOENT) {
		stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + index);
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake expanded Mitosis rung %u failed: %d",
			      index, cpu);
		return cpu;
	}
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_RUNG_HIT_BASE + index);
		return cpu;
	}
	stat_inc(ctx, SNAKE_STAT_RUNG_MISS_BASE + index);
	return -ENOENT;
}

static __always_inline void expanded_mitosis_record_unavailable_stage(
	struct snake_ladder_ctx *ctx, u32 index, u64 started_at)
{
	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + index);
	rung_timing_finish(ctx, SNAKE_RUNG_LADDER_IDLE, index, started_at);
	stat_inc(ctx, SNAKE_STAT_RUNG_MISS_BASE + index);
}

static __noinline s32 expanded_mitosis_unavailable_scope(
	struct snake_ladder_ctx *ctx, u32 base, s32 error,
	u64 callback_started_at, u64 scope_started_at)
{
	if (error != -ENOENT) {
		stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + base);
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_IDLE, base,
				   scope_started_at);
		stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE + base);
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake expanded Mitosis scope %u failed: %d",
			      base, error);
		return error;
	}
	expanded_mitosis_record_unavailable_stage(ctx, base, scope_started_at);
	expanded_mitosis_record_unavailable_stage(
		ctx, base + 1, rung_timing_start(callback_started_at));
	expanded_mitosis_record_unavailable_stage(
		ctx, base + 2, rung_timing_start(callback_started_at));
	expanded_mitosis_record_unavailable_stage(
		ctx, base + 3, rung_timing_start(callback_started_at));
	return -ENOENT;
}

static __noinline s32 walk_expanded_mitosis_candidates(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u32 base,
	const struct cpumask *candidates,
	struct snake_ladder_walk_args *walk_args)
{
	const struct cpumask *idle;
	s32 cpu, result;
	u64 started_at;
	bool prev_candidate, whole_core_idle = false;

	prev_candidate = walk_args->prev_cpu >= 0 &&
			 walk_args->prev_cpu < nr_cpu_ids &&
			 bpf_cpumask_test_cpu(walk_args->prev_cpu, candidates);

	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + base);
	started_at = walk_args->scope_started_at;
	cpu = -ENOENT;
	if (prev_candidate) {
		idle = scx_bpf_get_idle_smtmask();
		if (!idle) {
			cpu = -EINVAL;
		} else {
			whole_core_idle = bpf_cpumask_test_cpu(
				walk_args->prev_cpu, idle);
			scx_bpf_put_idle_cpumask(idle);
			if (whole_core_idle && scx_bpf_test_and_clear_cpu_idle(
						 walk_args->prev_cpu))
				cpu = walk_args->prev_cpu;
		}
	}
	result = expanded_mitosis_finish_stage(
		ctx, p, base, started_at, cpu);
	if (result != -ENOENT)
		return result;

	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + base + 1);
	started_at = rung_timing_start(walk_args->callback_started_at);
	cpu = scx_bpf_pick_idle_cpu(candidates, SCX_PICK_IDLE_CORE);
	if (cpu < 0 && cpu != -EINVAL)
		cpu = -ENOENT;
	result = expanded_mitosis_finish_stage(
		ctx, p, base + 1, started_at, cpu);
	if (result != -ENOENT)
		return result;

	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + base + 2);
	started_at = rung_timing_start(walk_args->callback_started_at);
	cpu = prev_candidate && scx_bpf_test_and_clear_cpu_idle(
					  walk_args->prev_cpu) ?
		      walk_args->prev_cpu :
		      -ENOENT;
	result = expanded_mitosis_finish_stage(
		ctx, p, base + 2, started_at, cpu);
	if (result != -ENOENT)
		return result;

	stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE + base + 3);
	started_at = rung_timing_start(walk_args->callback_started_at);
	cpu = scx_bpf_pick_idle_cpu(candidates, 0);
	if (cpu < 0 && cpu != -EINVAL)
		cpu = -ENOENT;
	return expanded_mitosis_finish_stage(
		ctx, p, base + 3, started_at, cpu);
}

static __noinline s32 walk_expanded_mitosis_cell_scope(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u32 base, u32 kind,
	struct snake_ladder_walk_args *walk_args)
{
	struct snake_task_runtime *runtime;
	struct bpf_cpumask *scratch;
	const struct cpumask *source;
	u32 cell_index;
	s32 error = 0, result;

	walk_args->enqueue_flags = 0;
	walk_args->select_flags = 0;
	walk_args->queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	walk_args->scope_started_at =
		rung_timing_start(walk_args->callback_started_at);
	runtime = task_state_lookup(p);
	cell_index = queue_task_cell_index(ctx, p);
	if (!runtime)
		return expanded_mitosis_unavailable_scope(
			ctx, base, -EINVAL, walk_args->callback_started_at,
			walk_args->scope_started_at);
	source = queue_task_cell_idle_source(
		ctx, p, cell_index, kind, walk_args->prev_cpu,
		&walk_args->local_llc_route_cpu,
		&walk_args->local_llc_cell_index, &error);
	if (!source)
		return expanded_mitosis_unavailable_scope(
			ctx, base, error, walk_args->callback_started_at,
			walk_args->scope_started_at);
	scratch = runtime->queue_cpumask;
	if (!scratch)
		return expanded_mitosis_unavailable_scope(
			ctx, base, -EINVAL, walk_args->callback_started_at,
			walk_args->scope_started_at);
	if (!bpf_cpumask_and(scratch, source, p->cpus_ptr))
		return expanded_mitosis_unavailable_scope(
			ctx, base, -ENOENT, walk_args->callback_started_at,
			walk_args->scope_started_at);
	result = walk_expanded_mitosis_candidates(
		ctx, p, base, (const struct cpumask *)scratch, walk_args);
	if (result >= 0) {
		walk_args->queue_cell_index = cell_index;
		if (kind == SNAKE_QUEUE_MASK_BORROWABLE)
			walk_args->select_flags = SNAKE_SELECT_F_BORROWED;
	}
	return result;
}

static __noinline s32 walk_expanded_mitosis_restricted_scope(
	struct snake_ladder_ctx *ctx, struct task_struct *p, u32 base,
	struct snake_ladder_walk_args *walk_args)
{
	u32 cell_index;
	s32 restricted, result;

	walk_args->enqueue_flags = 0;
	walk_args->select_flags = 0;
	walk_args->queue_cell_index = SNAKE_QUEUE_CELL_NONE;
	walk_args->scope_started_at =
		rung_timing_start(walk_args->callback_started_at);
	cell_index = queue_task_cell_index(ctx, p);
	restricted = queue_task_cell_affinity_restricted(ctx, p, cell_index);
	if (restricted <= 0)
		return expanded_mitosis_unavailable_scope(
			ctx, base, restricted < 0 ? restricted : -ENOENT,
			walk_args->callback_started_at,
			walk_args->scope_started_at);
	result = walk_expanded_mitosis_candidates(
		ctx, p, base, p->cpus_ptr, walk_args);
	if (result >= 0) {
		walk_args->queue_cell_index = cell_index;
		walk_args->select_flags = SNAKE_SELECT_F_AFFINITY;
	}
	return result;
}

static __noinline s32
walk_expanded_mitosis_ladder(struct snake_ladder_ctx *ctx,
			     struct task_struct *p,
			     struct snake_ladder_walk_args *walk_args)
{
	u64 select_started_at = walk_args->scope_started_at;
	u64 group_started_at;
	u32 base = 0;
	u32 group_cell_index = SNAKE_QUEUE_CELL_NONE;
	s32 result;

	if (ctx->ladder->nr_rungs == SNAKE_MAX_RUNGS) {
		stat_inc(ctx, SNAKE_STAT_RUNG_ATTEMPT_BASE);
		group_started_at =
			rung_timing_start(walk_args->callback_started_at);
		result = queue_pick_task_cell_preferred_cpu(
			ctx, p, SNAKE_QUEUE_MASK_GROUP_LLC,
			walk_args->prev_cpu, &group_cell_index);
		rung_timing_finish(ctx, SNAKE_RUNG_LADDER_IDLE, 0,
				   group_started_at);
		if (result < 0 && result != -ENOENT) {
			stat_inc(ctx, SNAKE_STAT_RUNG_ERROR_BASE);
			stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error("snake grouping rung execution failed: %d",
				      result);
			goto out;
		}
		if (result >= 0 && result < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(result, p->cpus_ptr)) {
			walk_args->enqueue_flags = 0;
			walk_args->select_flags = 0;
			walk_args->queue_cell_index = group_cell_index;
			stat_inc(ctx, SNAKE_STAT_RUNG_HIT_BASE);
			goto out;
		}
		stat_inc(ctx, SNAKE_STAT_RUNG_MISS_BASE);
		result = -ENOENT;
		base = 1;
	}
	result = walk_expanded_mitosis_cell_scope(
		ctx, p, base, SNAKE_QUEUE_MASK_LOCAL_LLC, walk_args);
	if (result != -ENOENT)
		goto out;
	result = walk_expanded_mitosis_cell_scope(
		ctx, p, base + 4, SNAKE_QUEUE_MASK_PRIMARY, walk_args);
	if (result != -ENOENT)
		goto out;
	result = walk_expanded_mitosis_cell_scope(
		ctx, p, base + 8, SNAKE_QUEUE_MASK_BORROWABLE, walk_args);
	if (result != -ENOENT)
		goto out;
	result = walk_expanded_mitosis_restricted_scope(
		ctx, p, base + 12, walk_args);
out:
	walk_args->scope_started_at = select_started_at;
	return result;
}

#endif /* __SCX_SNAKE_LADDER_H */
