/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_H
#define __SCX_SNAKE_QUEUE_H

#include "queue_state.h"
#include "task_state.h"
#include "stats.h"

#define SNAKE_SELECT_F_BORROWED (1ULL << 63)
enum snake_membership_kind {
	SNAKE_MEMBERSHIP_NO_CELL = 0,
	SNAKE_MEMBERSHIP_CELL,
	SNAKE_MEMBERSHIP_INVALID,
};

static __always_inline struct snake_queue_cell *
queue_task_cell(const struct snake_ladder_ctx *ctx, struct task_struct *p,
		u32 *indexp)
{
	struct snake_queue_header *header = queue_config(ctx);
	struct snake_queue_cell	  *cell;
	struct snake_task_cell	  *annotation;
	u32			  *encoded;
	u32			   cell_id, index, key;

	if (!header || !header->nr_cells || !indexp)
		return NULL;
	annotation = task_annotation(p);
	if (!annotation)
		return NULL;
	cell_id = READ_ONCE(annotation->cell_id);
	if (cell_id >= SNAKE_MAX_CPUS)
		return NULL;
	key = queue_slot_index(ctx->slot, SNAKE_MAX_CPUS, cell_id);
	encoded = bpf_map_lookup_elem(&queue_cell_lookup, &key);
	if (!encoded || !*encoded)
		return NULL;
	index = *encoded - 1;
	if (index >= header->nr_cells)
		return NULL;
	cell = queue_cell(ctx, index);
	if (!cell || !READ_ONCE(cell->valid) ||
	    READ_ONCE(cell->external_id) != cell_id ||
	    READ_ONCE(cell->slot_epoch) != READ_ONCE(annotation->cell_epoch))
		return NULL;
	*indexp = index;
	return cell;
}

static __always_inline u32
queue_task_cell_index(const struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	u32 index = 0;

	return queue_task_cell(ctx, p, &index) ? index : 0;
}

static __always_inline s32
queue_task_cell_id(const struct snake_ladder_ctx *ctx, struct task_struct *p,
		   u32 *cell_idp)
{
	struct snake_task_cell *annotation;
	u32			index;

	if (!cell_idp)
		return -EINVAL;
	annotation = task_annotation(p);
	if (!annotation)
		return -ENOENT;
	if (queue_cell_mode_enabled() && !queue_task_cell(ctx, p, &index))
		return -ENOENT;
	*cell_idp = READ_ONCE(annotation->cell_id);
	return 0;
}

static __always_inline u32 queue_task_membership_kind(
	const struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	struct snake_task_cell *annotation;
	u32			cell_id, index;

	annotation = task_annotation(p);
	if (!annotation)
		return SNAKE_MEMBERSHIP_NO_CELL;
	cell_id = READ_ONCE(annotation->cell_id);
	if (!cell_id)
		return SNAKE_MEMBERSHIP_NO_CELL;
	if (!queue_task_cell(ctx, p, &index))
		return SNAKE_MEMBERSHIP_INVALID;
	return SNAKE_MEMBERSHIP_CELL;
}

static __always_inline void
queue_account_task_membership(const struct snake_ladder_ctx *ctx,
			      struct task_struct	    *p)
{
	switch (queue_task_membership_kind(ctx, p)) {
	case SNAKE_MEMBERSHIP_NO_CELL:
		stat_inc(ctx, SNAKE_STAT_MEMBERSHIP_NO_CELL_RUNS);
		break;
	case SNAKE_MEMBERSHIP_INVALID:
		stat_inc(ctx, SNAKE_STAT_MEMBERSHIP_INVALID_RUNS);
		break;
	default:
		break;
	}
}

static __always_inline bool
queue_mask_contains(const struct snake_mask_data *mask, u32 cpu)
{
	u32 byte, bit;

	if (!mask || !mask->valid || cpu >= SNAKE_MAX_CPUS)
		return false;
	byte = cpu / 8;
	bit  = cpu % 8;
	return mask->bits[byte] & (1U << bit);
}

static __always_inline bool queue_primary_subset(const struct cpumask *primary,
						 const struct task_struct *p)
{
	return primary && bpf_cpumask_subset(primary, p->cpus_ptr);
}

static __always_inline s32 queue_pick_primary_cpu(const struct cpumask *primary,
						  struct bpf_cpumask   *scratch,
						  const struct task_struct *p,
						  s32 preferred)
{
	u32 cpu;

	if (!primary || !scratch)
		return -EINVAL;
	if (preferred >= 0 && preferred < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(preferred, primary) &&
	    bpf_cpumask_test_cpu(preferred, p->cpus_ptr))
		return preferred;
	if (!bpf_cpumask_and(scratch, primary, p->cpus_ptr))
		return -ENOENT;
	cpu = bpf_cpumask_any_distribute((const struct cpumask *)scratch);
	return cpu < nr_cpu_ids ? cpu : -ENOENT;
}

struct snake_queue_pick_allowed_loop_ctx {
	const struct task_struct *p;
	u32			  slot;
	u32			  start;
	s32			  result;
};

static long queue_pick_allowed_cpu_callback(
	u32 offset, struct snake_queue_pick_allowed_loop_ctx *loop_ctx)
{
	u32 cpu;

	if (offset >= SNAKE_MAX_CPUS || offset >= nr_cpu_ids)
		return 1;
	cpu = (loop_ctx->start + offset) % nr_cpu_ids;
	if (queue_cpu_slot(loop_ctx->slot, cpu) &&
	    bpf_cpumask_test_cpu(cpu, loop_ctx->p->cpus_ptr)) {
		loop_ctx->result = cpu;
		return 1;
	}
	return 0;
}

static __always_inline s32
queue_pick_allowed_cpu(const struct snake_ladder_ctx *ctx,
		       const struct task_struct *p, s32 preferred)
{
	struct snake_queue_pick_allowed_loop_ctx loop_ctx;
	s32					 current;
	long					 nr_loops;

	if (preferred >= 0 && preferred < nr_cpu_ids &&
	    queue_cpu(ctx, preferred) &&
	    bpf_cpumask_test_cpu(preferred, p->cpus_ptr))
		return preferred;
	current = scx_bpf_task_cpu(p);
	if (current >= 0 && current < nr_cpu_ids && queue_cpu(ctx, current) &&
	    bpf_cpumask_test_cpu(current, p->cpus_ptr))
		return current;
	loop_ctx = (struct snake_queue_pick_allowed_loop_ctx){
		.p	= p,
		.slot	= ctx->slot,
		.start	= bpf_get_prandom_u32() % nr_cpu_ids,
		.result = -ENOENT,
	};
	nr_loops = bpf_loop(SNAKE_MAX_CPUS, queue_pick_allowed_cpu_callback,
			    &loop_ctx, 0);
	return nr_loops < 0 ? nr_loops : loop_ctx.result;
}

#endif /* __SCX_SNAKE_QUEUE_H */
