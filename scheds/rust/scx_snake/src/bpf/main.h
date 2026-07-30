/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MAIN_H
#define __SCX_SNAKE_MAIN_H

#include "bpf_common.h"
#include "policy_bank.h"
#include "stats.h"
#include "timing.h"

extern u64				  queue_timing_session_id;
extern struct snake_queue_timing_counters queue_timing_counters;

/* Userspace stores the resolved assignment and its independent policy layers. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_cell);
} task_cells SEC(".maps");

static __always_inline struct snake_task_cell *
snake_task_cell_annotation(struct task_struct *p)
{
	return bpf_task_storage_get(&task_cells, p, NULL, 0);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_header);
	__uint(max_entries, 1);
} queue_header SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_MAX_CPUS);
} queue_cell_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cells SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue);
	__uint(max_entries, SNAKE_MAX_NORMAL_QUEUES);
} normal_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_cpu_queue);
	__uint(max_entries, SNAKE_MAX_CPUS);
} cpu_queues SEC(".maps");

struct snake_queue_cell_masks {
	struct bpf_cpumask __kptr *primary;
	struct bpf_cpumask __kptr *borrowable;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell_masks);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cell_masks SEC(".maps");

/* Queue residence events are independent from fine timing stage events. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} queue_timing_events SEC(".maps");

#include "dsq.h"

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
