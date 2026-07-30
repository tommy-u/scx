/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_FAIRNESS_COMMON_H
#define __SCX_SNAKE_FAIRNESS_COMMON_H

#include "stats.h"
#include "task_state.h"

const volatile u32	    fairness_mode = SNAKE_FAIRNESS_FIFO;

static __always_inline bool fairness_is_eevdf(void)
{
	return fairness_mode == SNAKE_FAIRNESS_EEVDF;
}

static __always_inline bool fairness_is_vtime(void)
{
	return fairness_mode == SNAKE_FAIRNESS_VTIME;
}

static __always_inline bool fairness_is_ordered(void)
{
	return fairness_is_vtime() || fairness_is_eevdf();
}

static __always_inline void
fairness_accounting_error(struct snake_ladder_ctx *ctx)
{
	if (fairness_is_vtime())
		stat_inc(ctx, SNAKE_STAT_VTIME_ACCOUNTING_ERRORS);
	else if (fairness_is_eevdf())
		stat_inc(ctx, SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS);
}

static __always_inline struct snake_task_runtime *
fairness_task(struct snake_ladder_ctx *ctx, struct task_struct *p, bool create)
{
	struct snake_task_runtime *runtime;

	runtime = create ? task_state_get_or_create(p) : task_state_lookup(p);
	if (!runtime && create) {
		stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
		fairness_accounting_error(ctx);
	}
	return runtime;
}

#endif /* __SCX_SNAKE_FAIRNESS_COMMON_H */
