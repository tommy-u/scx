/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_TASK_STATE_H
#define __SCX_SNAKE_TASK_STATE_H

#include "bpf_common.h"

/* Flat layout is part of the generated BTF ABI consumed by userspace tests. */
struct snake_task_runtime {
	struct bpf_cpumask __kptr *queue_cpumask;
	u64			   started_exec_runtime;
	u64			   service_budget;
	u64			   avg_runtime_ns;
	u64			   vruntime;
	u64			   affinity_vruntime;
	u64			   topology_generation;
	u64			   affinity_topology_generation;
	u64			   deadline;
	u64			   request_remaining_ns;
	u64			   queue_timing_session_id;
	u64			   queue_timing_dsq_id;
	u64			   queue_timing_enqueued_at_ns;
	u64			   llc_group_id;
	s64			   sleep_lag;
	u32			   active_weight;
	u32			   pending_weight;
	u32			   cell_index;
	u32			   cell_external_id;
	u32			   cell_epoch;
	u32			   affinity_cell_index;
	u32			   affinity_cell_external_id;
	u32			   affinity_cell_epoch;
	u32			   run_cell_index;
	u32			   run_owner_cell_index;
	u32			   selected_cpu;
	u32			   direct_cell_index;
	u32			   queue_timing_cell_index;
	u32			   queue_timing_depth_after_insert;
	u32			   queue_timing_queue_class;
	u32			   queued_dsq_index;
	u32			   llc_group_generation;
	u32			   run_group_normal_queue;
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
	u8			   queued_dsq_class;
	u8			   queued_dsq_accounted;
	u8			   run_grouped;
	u8			   run_group_preferred;
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

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct snake_managed_task_cell);
} managed_task_cells SEC(".maps");

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

static __always_inline int task_state_init(struct task_struct *p)
{
	return task_state_get_or_create(p) ? 0 : -ENOMEM;
}

static __always_inline struct snake_task_cell *
task_annotation(struct task_struct *p)
{
	return bpf_task_storage_get(&task_cells, p, NULL, 0);
}

static __always_inline struct snake_managed_task_cell *
managed_task_cell_lookup(struct task_struct *p)
{
	return bpf_task_storage_get(&managed_task_cells, p, NULL, 0);
}

static __always_inline struct snake_managed_task_cell *
managed_task_cell_get_or_create(struct task_struct *p)
{
	return bpf_task_storage_get(&managed_task_cells, p, NULL,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline bool task_effective_cell(struct task_struct *p,
					 u32 *cell_idp, u32 *cell_epochp)
{
	struct snake_managed_task_cell *managed;
	struct snake_task_cell *annotation;

	annotation = task_annotation(p);
	if (annotation &&
	    (READ_ONCE(annotation->flags) & SNAKE_TASK_CELL_F_MANUAL)) {
		*cell_idp = READ_ONCE(annotation->cell_id);
		*cell_epochp = READ_ONCE(annotation->cell_epoch);
		return true;
	}
	managed = managed_task_cell_lookup(p);
	if (managed && READ_ONCE(managed->status) ==
			       SNAKE_MANAGED_CGROUP_ASSIGNED) {
		*cell_idp = READ_ONCE(managed->cell_id);
		*cell_epochp = READ_ONCE(managed->cell_epoch);
		return true;
	}
	if (annotation &&
	    (READ_ONCE(annotation->flags) & SNAKE_TASK_CELL_F_MANAGED)) {
		*cell_idp = READ_ONCE(annotation->cell_id);
		*cell_epochp = READ_ONCE(annotation->cell_epoch);
		return true;
	}
	return false;
}

static __always_inline bool task_cell_rehome_pending(struct task_struct *p)
{
	struct snake_managed_task_cell *managed = managed_task_cell_lookup(p);
	struct snake_task_cell *annotation = task_annotation(p);

	return (annotation && READ_ONCE(annotation->needs_rehome)) ||
	       (managed && READ_ONCE(managed->needs_rehome));
}

static __always_inline void task_cell_clear_rehome(struct task_struct *p)
{
	struct snake_managed_task_cell *managed = managed_task_cell_lookup(p);
	struct snake_task_cell *annotation = task_annotation(p);

	if (annotation)
		WRITE_ONCE(annotation->needs_rehome, 0);
	if (managed)
		WRITE_ONCE(managed->needs_rehome, 0);
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

static __always_inline s32
task_route_take_selected_cpu(struct snake_task_runtime *runtime)
{
	s32 cpu = -1;

	if (!runtime || !runtime->selected_cpu_valid)
		return -1;
	if (runtime->selected_cpu < nr_cpu_ids)
		cpu = runtime->selected_cpu;
	task_route_clear_selected_cpu(runtime);
	return cpu;
}

#endif /* __SCX_SNAKE_TASK_STATE_H */
