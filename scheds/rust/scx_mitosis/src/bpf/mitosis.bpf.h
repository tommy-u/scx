#ifndef __MITOSIS_BPF_H
#define __MITOSIS_BPF_H

#include "common.bpf.h"

/* Structs */

/*
 * Store the cpumask for each cell (owned by BPF logic). We need this in an
 * explicit map to allow for these to be kptrs.
 */
struct cell_cpumask_wrapper {
	struct bpf_cpumask __kptr *cpumask;
	/*
	 * To avoid allocation on the reconfiguration path, have a second cpumask we
	 * can just do an xchg on.
	 */
	struct bpf_cpumask __kptr *tmp_cpumask;
};

struct cpumask_entry {
	unsigned long cpumask[CPUMASK_LONG_ENTRIES];
	u64 used;
};

/* Define types for cpumasks in-situ vs as a ptr in struct cpuset */
struct cpumask___local {};

typedef struct cpumask___local *cpumask_var_t___ptr;

struct cpuset___cpumask_ptr {
	cpumask_var_t___ptr cpus_allowed;
};

typedef struct cpumask___local cpumask_var_t___arr[1];

struct cpuset___cpumask_arr {
	cpumask_var_t___arr cpus_allowed;
};

/* MAPS */
struct function_counters_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NR_COUNTERS);
};

struct cgrp_ctx_map {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
};

struct task_ctx_map {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
};

struct cpu_ctx_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
};

struct cell_cpumask_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cell_cpumask_wrapper);
	__uint(max_entries, MAX_CELLS);
	__uint(map_flags, 0);
};

struct percpu_critical_section_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
};

struct cgrp_init_percpu_cpumask_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpumask_entry);
	__uint(max_entries, MAX_CPUMASK_ENTRIES);
};


/*
 * task_ctx is the per-task information kept by scx_mitosis
 */
struct task_ctx {
	/* cpumask is the set of valid cpus this task can schedule on */
	/* (tasks cpumask anded with its cell cpumask) */
	struct bpf_cpumask __kptr *cpumask;
	/* started_running_at for recording runtime */
	u64 started_running_at;
	u64 basis_vtime;
	/* For the sake of monitoring, each task is owned by a cell */
	u32 cell;
	/* For the sake of scheduling, a task is exclusively owned by either a cell
	 * or a cpu */
	u32 dsq;
	/* latest configuration that was applied for this task */
	/* (to know if it has to be re-applied) */
	u32 configuration_seq;
	/* Is this task allowed on all cores of its cell? */
	bool all_cell_cpus_allowed;
	// Which L3 this task is assigned to
	s32 l3;

#if MITOSIS_ENABLE_STEALING
	/* When a task is stolen, dispatch() marks the destination L3 here.
	 * running() applies the retag and recomputes cpumask (vtime preserved).
	*/
	s32 pending_l3;
	u32 steal_count; /* how many times this task has been stolen */
	u64 last_stolen_at; /* ns timestamp of the last steal (scx_bpf_now) */
#endif
};

#endif
