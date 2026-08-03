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

static __always_inline bool queue_mitosis_callback_ladders(
	const struct snake_compiled_ladder *ladder)
{
	const struct snake_queue_rung *enqueue0, *enqueue1, *enqueue2;
	const struct snake_queue_rung *dispatch0, *dispatch1, *dispatch2;
	u64 fallback = SNAKE_DISPATCH_FALLBACK_CPU |
		       ((u64)SNAKE_DISPATCH_FALLBACK_CELL_SIBLING <<
			SNAKE_DISPATCH_FALLBACK_BITS);

	if (!ladder || ladder->nr_enqueue_rungs != 3 ||
	    ladder->nr_dispatch_rungs != 3)
		return false;
	enqueue0 = MEMBER_VPTR(ladder->enqueue_rungs, [0]);
	enqueue1 = MEMBER_VPTR(ladder->enqueue_rungs, [1]);
	enqueue2 = MEMBER_VPTR(ladder->enqueue_rungs, [2]);
	dispatch0 = MEMBER_VPTR(ladder->dispatch_rungs, [0]);
	dispatch1 = MEMBER_VPTR(ladder->dispatch_rungs, [1]);
	dispatch2 = MEMBER_VPTR(ladder->dispatch_rungs, [2]);
	if (!enqueue0 || !enqueue1 || !enqueue2 || !dispatch0 || !dispatch1 ||
	    !dispatch2)
		return false;
	return enqueue0->opcode == SNAKE_ENQUEUE_OP_TRY_DIRECT &&
	       enqueue0->input == SNAKE_QUEUE_INPUT_CELL &&
	       enqueue0->flags == SNAKE_QUEUE_RUNG_F_DIRECT_DISPATCH &&
	       !enqueue0->reserved && !enqueue0->data &&
	       enqueue1->opcode == SNAKE_ENQUEUE_OP_CELL &&
	       enqueue1->input == SNAKE_QUEUE_INPUT_CELL && !enqueue1->flags &&
	       !enqueue1->reserved && !enqueue1->data &&
	       enqueue2->opcode == SNAKE_ENQUEUE_OP_INSERT_CPU &&
	       enqueue2->input == SNAKE_QUEUE_INPUT_CPU && !enqueue2->flags &&
	       !enqueue2->reserved && !enqueue2->data &&
	       dispatch0->opcode == SNAKE_DISPATCH_OP_PEEK &&
	       dispatch0->input == SNAKE_QUEUE_INPUT_CELL && !dispatch0->flags &&
	       !dispatch0->reserved && !dispatch0->data &&
	       dispatch1->opcode == SNAKE_DISPATCH_OP_PEEK &&
	       dispatch1->input == SNAKE_QUEUE_INPUT_CPU && !dispatch1->flags &&
	       !dispatch1->reserved && !dispatch1->data &&
	       dispatch2->opcode == SNAKE_DISPATCH_OP_CONSUME &&
	       dispatch2->input == SNAKE_QUEUE_INPUT_MIN_VTIME &&
	       !dispatch2->flags && !dispatch2->reserved &&
	       dispatch2->data == fallback;
}

static __always_inline bool queue_mitosis_expanded_enqueue_ladder(
	const struct snake_compiled_ladder *ladder)
{
	const struct snake_queue_rung *enqueue0, *enqueue1, *enqueue2;

	if (!ladder || ladder->nr_enqueue_rungs != 3)
		return false;
	enqueue0 = MEMBER_VPTR(ladder->enqueue_rungs, [0]);
	enqueue1 = MEMBER_VPTR(ladder->enqueue_rungs, [1]);
	enqueue2 = MEMBER_VPTR(ladder->enqueue_rungs, [2]);
	if (!enqueue0 || !enqueue1 || !enqueue2)
		return false;
	return enqueue0->opcode == SNAKE_ENQUEUE_OP_TRY_DIRECT &&
	       enqueue0->input == SNAKE_QUEUE_INPUT_CELL &&
	       enqueue0->flags == SNAKE_QUEUE_RUNG_F_DIRECT_DISPATCH &&
	       !enqueue0->reserved && !enqueue0->data &&
	       enqueue1->opcode == SNAKE_ENQUEUE_OP_CELL &&
	       enqueue1->input == SNAKE_QUEUE_INPUT_CELL && !enqueue1->flags &&
	       !enqueue1->reserved && !enqueue1->data &&
	       enqueue2->opcode == SNAKE_ENQUEUE_OP_INSERT_CPU &&
	       enqueue2->input == SNAKE_QUEUE_INPUT_CPU && !enqueue2->flags &&
	       !enqueue2->reserved && !enqueue2->data;
}

static __always_inline bool queue_mitosis_expanded_dispatch_ladder(
	const struct snake_compiled_ladder *ladder)
{
	const struct snake_queue_rung *dispatch0, *dispatch1, *dispatch2,
		*dispatch3, *dispatch4;

	if (!ladder || ladder->nr_dispatch_rungs != 5)
		return false;
	dispatch0 = MEMBER_VPTR(ladder->dispatch_rungs, [0]);
	dispatch1 = MEMBER_VPTR(ladder->dispatch_rungs, [1]);
	dispatch2 = MEMBER_VPTR(ladder->dispatch_rungs, [2]);
	dispatch3 = MEMBER_VPTR(ladder->dispatch_rungs, [3]);
	dispatch4 = MEMBER_VPTR(ladder->dispatch_rungs, [4]);
	if (!dispatch0 || !dispatch1 || !dispatch2 || !dispatch3 ||
	    !dispatch4)
		return false;
	return dispatch0->opcode == SNAKE_DISPATCH_OP_DRAIN &&
	       dispatch0->input == SNAKE_QUEUE_INPUT_CELL_ORPHAN &&
	       !dispatch0->flags && !dispatch0->reserved && !dispatch0->data &&
	       dispatch1->opcode == SNAKE_DISPATCH_OP_PEEK &&
	       dispatch1->input == SNAKE_QUEUE_INPUT_CELL && !dispatch1->flags &&
	       !dispatch1->reserved && !dispatch1->data &&
	       dispatch2->opcode == SNAKE_DISPATCH_OP_PEEK &&
	       dispatch2->input == SNAKE_QUEUE_INPUT_CPU && !dispatch2->flags &&
	       !dispatch2->reserved && !dispatch2->data &&
	       dispatch3->opcode == SNAKE_DISPATCH_OP_CONSUME &&
	       dispatch3->input == SNAKE_QUEUE_INPUT_MIN_VTIME &&
	       !dispatch3->flags && !dispatch3->reserved &&
	       dispatch3->data == SNAKE_DISPATCH_FALLBACK_CPU &&
	       dispatch4->opcode == SNAKE_DISPATCH_OP_STEAL &&
	       dispatch4->input == SNAKE_QUEUE_INPUT_CELL_SIBLING &&
	       !dispatch4->flags && !dispatch4->reserved && !dispatch4->data;
}

static __always_inline bool queue_mitosis_expanded_callback_ladders(
	const struct snake_compiled_ladder *ladder)
{
	return queue_mitosis_expanded_enqueue_ladder(ladder) &&
	       queue_mitosis_expanded_dispatch_ladder(ladder);
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
	if (queue_mitosis_callback_ladders(ladder) ||
	    queue_mitosis_expanded_callback_ladders(ladder))
		return 0;

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
	if (queue_mitosis_expanded_dispatch_ladder(ladder))
		return enqueue_cell ? 0 : -EINVAL;

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
