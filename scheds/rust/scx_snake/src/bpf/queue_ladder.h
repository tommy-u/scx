/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_LADDER_H
#define __SCX_SNAKE_QUEUE_LADDER_H

#include "queue.h"
#include "queue_enqueue.h"
#include "queue_dispatch.h"

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

	bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)
	{
		const struct snake_queue_rung *rung;

		if (i >= ladder->nr_enqueue_rungs)
			break;
		rung = MEMBER_VPTR(ladder->enqueue_rungs, [i]);
		if (!rung || rung->flags)
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
