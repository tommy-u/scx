/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MAIN_H
#define __SCX_SNAKE_MAIN_H

#include <scx/common.bpf.h>

#include "intf.h"

extern const volatile u32		policy_abi_version;
extern const volatile u32		nr_rungs;
extern const volatile u32		nr_mask_tables;
extern const volatile u32		fallback_mode;
extern const volatile struct snake_rung rungs[SNAKE_MAX_RUNGS];

static u32				nr_cpu_ids;

/* Per-CPU counters avoid atomics in scheduler callbacks. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, SNAKE_NR_STATS);
} stats			    SEC(".maps");

static __always_inline void stat_add(u32 idx, u64 amount)
{
	u64 *value;

	value = bpf_map_lookup_elem(&stats, &idx);
	if (value)
		*value += amount;
}

static __always_inline void stat_inc(u32 idx)
{
	stat_add(idx, 1);
}

static __always_inline void stat_max(u32 idx, u64 candidate)
{
	u64 *value;

	value = bpf_map_lookup_elem(&stats, &idx);
	if (value && candidate > *value)
		*value = candidate;
}

/* Record total and maximum latency for one select_cpu invocation. */
static __always_inline void finish_select(u64 started_at)
{
	u64 elapsed = bpf_ktime_get_ns() - started_at;

	stat_add(SNAKE_STAT_SELECT_LATENCY_NS, elapsed);
	stat_max(SNAKE_STAT_SELECT_LATENCY_MAX_NS, elapsed);
}

/* Choose an affinity-safe CPU after every configured rung misses. */
static __always_inline s32 fallback_cpu(const struct task_struct *p,
					s32			  prev_cpu)
{
	s32 cpu;

	if (fallback_mode == SNAKE_FALLBACK_PREVIOUS_CPU && prev_cpu >= 0 &&
	    prev_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		stat_inc(SNAKE_STAT_FALLBACK_PREV);
		return prev_cpu;
	}

	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	if (cpu >= 0 && cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		stat_inc(SNAKE_STAT_FALLBACK_ANY);
		return cpu;
	}

	stat_inc(SNAKE_STAT_INVALID_ERRORS);
	scx_bpf_error("snake could not find an allowed fallback CPU for pid %d",
		      p->pid);
	return -1;
}

#endif /* __SCX_SNAKE_MAIN_H */
