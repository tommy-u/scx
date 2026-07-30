/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MAIN_H
#define __SCX_SNAKE_MAIN_H

#include "bpf_common.h"
#include "task_state.h"
#include "policy_bank.h"
#include "stats.h"
#include "timing.h"
#include "queue_timing.h"

/* Choose an affinity-safe CPU after every configured rung misses. */
static __always_inline s32 fallback_cpu(const struct snake_ladder_ctx *ctx,
					const struct task_struct      *p,
					s32			       prev_cpu)
{
	s32 cpu;

	if (ctx->ladder->fallback_mode == SNAKE_FALLBACK_PREVIOUS_CPU &&
	    prev_cpu >= 0 && prev_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_FALLBACK_PREV);
		return prev_cpu;
	}

	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		stat_inc(ctx, SNAKE_STAT_FALLBACK_ANY);
		return cpu;
	}

	stat_inc(ctx, SNAKE_STAT_INVALID_ERRORS);
	scx_bpf_error("snake could not find an allowed fallback CPU for pid %d",
		      p->pid);
	return -1;
}

#endif /* __SCX_SNAKE_MAIN_H */
