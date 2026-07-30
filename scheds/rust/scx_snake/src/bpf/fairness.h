/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_H
#define __SCX_SNAKE_FAIRNESS_H

#include "fairness_common.h"
#include "fairness_fifo.h"
#include "fairness_vtime.h"
#include "fairness_eevdf.h"

static __always_inline void fairness_runnable(struct snake_ladder_ctx *ctx,
					      struct task_struct      *p)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		fairness_fifo_runnable(ctx, p);
		break;
	case SNAKE_FAIRNESS_VTIME:
		fairness_vtime_runnable(ctx, p);
		break;
	case SNAKE_FAIRNESS_EEVDF:
		fairness_eevdf_runnable(ctx, p);
		break;
	default:
		break;
	}
}

static __noinline u64 fairness_dispatch_slice(struct snake_ladder_ctx *ctx,
					      struct task_struct      *p,
					      bool		       direct)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		return fairness_fifo_dispatch_slice(ctx, p, direct);
	case SNAKE_FAIRNESS_VTIME:
		return fairness_vtime_dispatch_slice(ctx, p, direct);
	case SNAKE_FAIRNESS_EEVDF:
		return fairness_eevdf_dispatch_slice(ctx, p, direct);
	default:
		return SCX_SLICE_DFL;
	}
}

static __always_inline int
fairness_enqueue(struct snake_ladder_ctx *ctx, struct task_struct *p,
		 u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		return fairness_fifo_enqueue(ctx, p, enq_flags, fine);
	case SNAKE_FAIRNESS_VTIME:
		return fairness_vtime_enqueue(ctx, p, enq_flags, fine);
	case SNAKE_FAIRNESS_EEVDF:
		return fairness_eevdf_enqueue(ctx, p, enq_flags, fine);
	default:
		return -EINVAL;
	}
}

static __always_inline int
fairness_dispatch(struct snake_ladder_ctx *ctx, s32 cpu,
		  struct task_struct		     *prev,
		  const struct snake_fine_timing_ctx *fine)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		return fairness_fifo_dispatch(ctx, cpu, prev, fine);
	case SNAKE_FAIRNESS_VTIME:
		return fairness_vtime_dispatch(ctx, cpu, prev, fine);
	case SNAKE_FAIRNESS_EEVDF:
		return fairness_eevdf_dispatch(ctx, cpu, prev, fine);
	default:
		return -EINVAL;
	}
}

static __always_inline void fairness_running(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		fairness_fifo_running(ctx, p);
		break;
	case SNAKE_FAIRNESS_VTIME:
		fairness_vtime_running(ctx, p);
		break;
	case SNAKE_FAIRNESS_EEVDF:
		fairness_eevdf_running(ctx, p);
		break;
	default:
		break;
	}
}

static __always_inline u64 fairness_stopping(struct snake_ladder_ctx *ctx,
					     struct task_struct	     *p)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		return fairness_fifo_stopping(ctx, p);
	case SNAKE_FAIRNESS_VTIME:
		return fairness_vtime_stopping(ctx, p);
	case SNAKE_FAIRNESS_EEVDF:
		return fairness_eevdf_stopping(ctx, p);
	default:
		return 0;
	}
}

static __always_inline void fairness_quiescent(struct snake_ladder_ctx *ctx,
					       struct task_struct      *p,
					       u64 deq_flags)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		fairness_fifo_quiescent(ctx, p, deq_flags);
		break;
	case SNAKE_FAIRNESS_VTIME:
		fairness_vtime_quiescent(ctx, p, deq_flags);
		break;
	case SNAKE_FAIRNESS_EEVDF:
		fairness_eevdf_quiescent(ctx, p, deq_flags);
		break;
	default:
		break;
	}
}

static __always_inline void fairness_set_weight(struct snake_ladder_ctx *ctx,
						struct task_struct	*p,
						u32			 weight)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		fairness_fifo_set_weight(ctx, p, weight);
		break;
	case SNAKE_FAIRNESS_VTIME:
		fairness_vtime_set_weight(ctx, p, weight);
		break;
	case SNAKE_FAIRNESS_EEVDF:
		fairness_eevdf_set_weight(ctx, p, weight);
		break;
	default:
		break;
	}
}

static __always_inline int fairness_init(void)
{
	switch (fairness_mode) {
	case SNAKE_FAIRNESS_FIFO:
		return fairness_fifo_init();
	case SNAKE_FAIRNESS_VTIME:
		return fairness_vtime_init();
	case SNAKE_FAIRNESS_EEVDF:
		return fairness_eevdf_init();
	default:
		return -EINVAL;
	}
}

#endif /* __SCX_SNAKE_FAIRNESS_H */
