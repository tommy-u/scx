/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_LADDER_H
#define __SCX_SNAKE_QUEUE_LADDER_H

#include "queue.h"
#include "queue_enqueue.h"
#include "queue_dispatch.h"

static __always_inline bool
queue_direct_dispatch_enabled(const struct snake_ladder_ctx *ctx)
{
	const struct snake_queue_rung *first;

	if (!ctx || !ctx->ladder || !ctx->ladder->nr_enqueue_rungs)
		return false;
	first = MEMBER_VPTR(ctx->ladder->enqueue_rungs, [0]);
	return first &&
	       first->flags == SNAKE_QUEUE_RUNG_F_DIRECT_DISPATCH;
}

static __always_inline int
validate_queue_ladders(const struct snake_compiled_ladder *ladder)
{
	bool enqueue_cell = false, enqueue_affinity = false;
	bool dispatch_cell = false, dispatch_affinity = false,
	     dispatch_min = false;
	u32  i;

	if (!queue_topology_enabled())
		return ladder->nr_enqueue_rungs || ladder->nr_dispatch_rungs ?
			       -EINVAL :
			       0;
	if (!ladder->nr_enqueue_rungs ||
	    ladder->nr_enqueue_rungs > SNAKE_MAX_QUEUE_RUNGS ||
	    !ladder->nr_dispatch_rungs ||
	    ladder->nr_dispatch_rungs > SNAKE_MAX_QUEUE_RUNGS)
		return -EINVAL;
	if (queue_global_mode_enabled()) {
		u32 enqueue_sources = 0, peek_sources = 0, fallback_sources = 0;

		bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
		{
			const struct snake_queue_rung *rung;

			if (i >= ladder->nr_enqueue_rungs)
				break;
			rung = MEMBER_VPTR(ladder->enqueue_rungs, [i]);
			if (!rung || rung->reserved || rung->data ||
			    (rung->flags &&
			     (i != 0 || rung->flags !=
					  SNAKE_QUEUE_RUNG_F_DIRECT_DISPATCH)))
				return -EINVAL;
			if (rung->opcode == SNAKE_ENQUEUE_OP_TRY_INSERT &&
			    rung->input == SNAKE_QUEUE_INPUT_LOCAL &&
			    i + 1 < ladder->nr_enqueue_rungs) {
				if (enqueue_sources & (1U << rung->input))
					return -EINVAL;
				enqueue_sources |= 1U << rung->input;
			} else if (rung->opcode == SNAKE_ENQUEUE_OP_INSERT &&
				   rung->input == SNAKE_QUEUE_INPUT_CPU &&
				   i + 1 == ladder->nr_enqueue_rungs) {
				if (enqueue_sources & (1U << rung->input))
					return -EINVAL;
				enqueue_sources |= 1U << rung->input;
			} else {
				return -EINVAL;
			}
		}
		if (!(enqueue_sources & (1U << SNAKE_QUEUE_INPUT_LOCAL)) ||
		    !(enqueue_sources & (1U << SNAKE_QUEUE_INPUT_CPU)))
			return -EINVAL;

		bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
		{
			const struct snake_queue_rung *rung;
			u32 offset;

			if (i >= ladder->nr_dispatch_rungs)
				break;
			rung = MEMBER_VPTR(ladder->dispatch_rungs, [i]);
			if (!rung || rung->flags || rung->reserved)
				return -EINVAL;
			if (rung->opcode == SNAKE_DISPATCH_OP_PEEK &&
			    rung->input >= SNAKE_QUEUE_INPUT_CPU &&
			    rung->input <= SNAKE_QUEUE_INPUT_REMOTE &&
			    !rung->data && i + 1 < ladder->nr_dispatch_rungs) {
				if (peek_sources & (1U << rung->input))
					return -EINVAL;
				peek_sources |= 1U << rung->input;
				continue;
			}
			if (rung->opcode != SNAKE_DISPATCH_OP_CONSUME ||
			    rung->input != SNAKE_QUEUE_INPUT_MIN_VTIME ||
			    i + 1 != ladder->nr_dispatch_rungs)
				return -EINVAL;
			bpf_for(offset, 0, SNAKE_DISPATCH_FALLBACK_MAX)
			{
				u32 source =
					(rung->data >>
					 (offset * SNAKE_DISPATCH_FALLBACK_BITS)) &
					SNAKE_DISPATCH_FALLBACK_MASK;

				if (source < SNAKE_DISPATCH_FALLBACK_CPU ||
				    source > SNAKE_DISPATCH_FALLBACK_REMOTE ||
				    fallback_sources & (1U << source))
					return -EINVAL;
				fallback_sources |= 1U << source;
			}
			if (rung->data >> (SNAKE_DISPATCH_FALLBACK_MAX *
					  SNAKE_DISPATCH_FALLBACK_BITS))
				return -EINVAL;
		}
		return peek_sources == fallback_sources ? 0 : -EINVAL;
	}

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;

		if (i >= ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ladder->enqueue_rungs, [i]);
		if (!rung ||
		    (rung->flags &&
		     (i != 0 || rung->flags !=
				  SNAKE_QUEUE_RUNG_F_DIRECT_DISPATCH)))
			return -EINVAL;
		if (rung->opcode == SNAKE_ENQUEUE_OP_CELL) {
			if (enqueue_cell)
				return -EINVAL;
			enqueue_cell = true;
		} else if (rung->opcode == SNAKE_ENQUEUE_OP_AFFINITY) {
			if (enqueue_affinity ||
			    i + 1 != ladder->nr_enqueue_rungs)
				return -EINVAL;
			enqueue_affinity = true;
		} else {
			return -EINVAL;
		}
	}
	if (!enqueue_affinity)
		return -EINVAL;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;

		if (i >= ladder->nr_dispatch_rungs)
			break;
		rung = MEMBER_VPTR(ladder->dispatch_rungs, [i]);
		if (!rung || rung->flags)
			return -EINVAL;
		if (rung->opcode == SNAKE_DISPATCH_OP_CELL) {
			if (dispatch_cell || dispatch_min)
				return -EINVAL;
			dispatch_cell = true;
		} else if (rung->opcode == SNAKE_DISPATCH_OP_AFFINITY) {
			if (dispatch_affinity || dispatch_min)
				return -EINVAL;
			dispatch_affinity = true;
		} else if (rung->opcode == SNAKE_DISPATCH_OP_MIN_VTIME) {
			if (dispatch_cell || dispatch_affinity ||
			    dispatch_min || ladder->nr_dispatch_rungs != 1)
				return -EINVAL;
			dispatch_cell	  = true;
			dispatch_affinity = true;
			dispatch_min	  = true;
		} else {
			return -EINVAL;
		}
	}
	if (!dispatch_affinity || enqueue_cell != dispatch_cell)
		return -EINVAL;
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_LADDER_H */
