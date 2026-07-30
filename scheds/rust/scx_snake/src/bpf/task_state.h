/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_TASK_STATE_H
#define __SCX_SNAKE_TASK_STATE_H

#include "bpf_common.h"

/* Flat layout is part of the generated BTF ABI consumed by userspace tests. */
struct snake_task_runtime {
	struct bpf_cpumask __kptr *queue_cpumask;
	u64			   started_exec_runtime;
	u64			   service_budget;
	u64			   vruntime;
	u64			   affinity_vruntime;
	u64			   deadline;
	u64			   request_remaining_ns;
	u64			   queue_timing_session_id;
	u64			   queue_timing_dsq_id;
	u64			   queue_timing_enqueued_at_ns;
	s64			   sleep_lag;
	u32			   active_weight;
	u32			   pending_weight;
	u32			   cell_index;
	u32			   affinity_cell_index;
	u32			   run_cell_index;
	u32			   run_owner_cell_index;
	u32			   selected_cpu;
	u32			   direct_cell_index;
	u32			   queue_timing_cell_index;
	u32			   queue_timing_depth_after_insert;
	u32			   queue_timing_queue_class;
	u8			   runtime_valid;
	u8			   initialized;
	u8			   runnable_accounted;
	u8			   has_sleep_lag;
	u8			   run_direct;
	u8			   cell_initialized;
	u8			   affinity_initialized;
	u8			   selected_cpu_valid;
	u8			   queue_class;
	u8			   run_queue_class;
	u8			   direct_cell_valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_runtime);
} task_runtimes SEC(".maps");

/* Userspace stores the resolved assignment and its independent policy layers. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_task_cell);
} task_cells SEC(".maps");

static __always_inline struct snake_task_runtime *
task_state_lookup(struct task_struct *p)
{
	return bpf_task_storage_get(&task_runtimes, p, NULL, 0);
}

static __always_inline struct snake_task_runtime *
task_state_get_or_create(struct task_struct *p)
{
	return bpf_task_storage_get(&task_runtimes, p, NULL,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct snake_task_cell *
task_annotation(struct task_struct *p)
{
	return bpf_task_storage_get(&task_cells, p, NULL, 0);
}

static __always_inline int task_state_init_queue_mask(struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct bpf_cpumask	  *mask, *stale;

	runtime = task_state_get_or_create(p);
	if (!runtime)
		return -ENOMEM;
	if (runtime->queue_cpumask)
		return 0;
	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;
	stale = bpf_kptr_xchg(&runtime->queue_cpumask, mask);
	if (stale) {
		bpf_cpumask_release(stale);
		return -EINVAL;
	}
	return 0;
}

static __always_inline int
task_route_record_selected_cpu(struct snake_task_runtime *runtime, s32 cpu)
{
	if (!runtime || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	runtime->selected_cpu	    = cpu;
	runtime->selected_cpu_valid = 1;
	return 0;
}

static __always_inline void
task_route_clear_selected_cpu(struct snake_task_runtime *runtime)
{
	if (runtime)
		runtime->selected_cpu_valid = 0;
}

static __always_inline s32 task_route_take_selected_cpu(
	struct snake_task_runtime *runtime, struct task_struct *p)
{
	s32 cpu = -1;

	if (!runtime || !runtime->selected_cpu_valid)
		return -1;
	if (runtime->selected_cpu < nr_cpu_ids &&
	    bpf_cpumask_test_cpu(runtime->selected_cpu, p->cpus_ptr))
		cpu = runtime->selected_cpu;
	task_route_clear_selected_cpu(runtime);
	return cpu;
}

#endif /* __SCX_SNAKE_TASK_STATE_H */
