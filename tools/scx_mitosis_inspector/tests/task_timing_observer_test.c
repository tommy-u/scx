/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t	 s32;

struct task_observation;
struct linux_binprm;
struct task_struct {
	u32			 pid;
	u32			 policy;
	int			 on_cpu;
	struct task_observation *storage;
};
struct trace_event_raw_sched_migrate_task {
	int orig_cpu;
	int dest_cpu;
};

/* Only the kernel boundary is substituted; timing and switch logic is real. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define SEC(name)
#define __uint(name, value) int name
#define __type(name, type) type *name
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(task, field) ((task)->field)
#define READ_ONCE(value) (value)
#define BPF_MAP_TYPE_PERCPU_ARRAY 1
#define BPF_MAP_TYPE_TASK_STORAGE 2
#define BPF_MAP_TYPE_HASH 3
#define BPF_F_NO_PREALLOC 1
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#define BPF_NOEXIST 1

#define __SCX_MITOSIS_INSPECTOR_DSQ_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_SOFTIRQ_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_BLOCK_IO_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_HARDIRQ_OBSERVER_BPF_H

static u64 now_ns;
static u64 bpf_ktime_get_ns(void)
{
	return now_ns;
}
static u32 bpf_get_prandom_u32(void)
{
	return 0;
}
static u32 log2_u64(u64 value)
{
	/* Match SCX log2_u32(value) + 1, including its zero result. */
	return value ? 64 - __builtin_clzll(value) : 1;
}
static void *bpf_map_lookup_elem(const void *map, const void *key);
static void *bpf_task_storage_get(const void *map, struct task_struct *task,
				  const void *value, u64 flags);
static int   bpf_map_update_elem(const void *map, const void *key,
				 const void *value, int flags);

/* The loader sets these read-only BPF configuration values before loading. */
#define const
#include "../src/bpf/main.bpf.c"
#undef const

static struct task_observation	      storage[8];
static struct mitosis_callback_timing wakeup, slice, blocked;
static struct mitosis_cpu_runtime     runtime;
static struct scheduler_event_metrics events;

static void *bpf_map_lookup_elem(const void *map, const void *key)
{
	(void)key;
	if (map == &wakeup_latency)
		return &wakeup;
	if (map == &cpu_slice_duration)
		return &slice;
	if (map == &blocked_duration)
		return &blocked;
	if (map == &cpu_runtime)
		return &runtime;
	if (map == &scheduler_event_metrics)
		return &events;
	return NULL;
}

static void *bpf_task_storage_get(const void *map, struct task_struct *task,
				  const void *value, u64 flags)
{
	assert(map == &task_observations);
	(void)value;
	if (!task->storage && (flags & BPF_LOCAL_STORAGE_GET_F_CREATE)) {
		assert(task->pid < 8);
		task->storage = &storage[task->pid];
	}
	return task->storage;
}

static int bpf_map_update_elem(const void *map, const void *key,
			       const void *value, int flags)
{
	(void)map;
	(void)key;
	(void)value;
	(void)flags;
	return 0;
}

static void idle_is_excluded_from_task_slices(void)
{
	struct task_struct idle = {}, task = { .pid = 1 };

	now_ns = 10;
	on_sched_switch(false, NULL, &idle, 0);
	assert(idle.storage == NULL);
	now_ns = 100;
	on_sched_switch(false, &idle, &task, 0);
	now_ns = 120;
	on_sched_switch(false, &task, &idle, 0);
	assert(slice.total_ns == 20 && slice.buckets[4] == 1);
	now_ns = 220;
	on_sched_switch(false, &idle, &task, 0);
	assert(slice.total_ns == 20 && slice.buckets[4] == 1);
	assert(runtime.busy_ns == 20 && runtime.current_busy == 1);
}

static void running_wakeup_does_not_start_latency(void)
{
	struct task_struct task = { .pid = 1, .on_cpu = 1 };
	struct task_struct next = { .pid = 2 };

	now_ns			= 10;
	on_sched_wakeup(&task);
	assert(task.storage == NULL);
	now_ns = 20;
	on_sched_switch(true, &task, &next, 0);
	task.on_cpu = 0;
	now_ns	    = 100;
	on_sched_switch(false, &next, &task, 0);
	assert(wakeup.total_ns == 0);
}

static void preemption_does_not_start_blocked_timer(void)
{
	struct task_struct task = { .pid = 1 }, next = { .pid = 2 };

	now_ns = 100;
	on_sched_switch(false, NULL, &task, 0);
	now_ns = 150;
	on_sched_switch(true, &task, &next, 2);
	assert(task.storage && task.storage->blocked_at == 0);
	now_ns = 1000;
	on_sched_wakeup(&task);
	assert(blocked.total_ns == 0);
}

static void real_block_and_wakeup_keep_elapsed_samples(void)
{
	struct task_struct task = { .pid = 1 }, next = { .pid = 2 };

	now_ns = 100;
	on_sched_switch(false, NULL, &task, 0);
	now_ns = 150;
	on_sched_switch(false, &task, &next, 2);
	assert(task.storage && task.storage->blocked_at == 150);
	now_ns = 200;
	on_sched_wakeup(&task);
	assert(blocked.total_ns == 50 && blocked.buckets[5] == 1);
	assert(task.storage->blocked_at == 0);
	now_ns = 216;
	on_sched_switch(false, &next, &task, 0);
	assert(wakeup.total_ns == 16 && wakeup.buckets[4] == 1);
	assert(task.storage->wakeup_at == 0);
}

static void scheduler_switch_bins_are_exclusive(void)
{
	scheduler_event_switch(true, NULL, NULL, 2);
	scheduler_event_switch(false, NULL, NULL, 2);
	scheduler_event_switch(false, NULL, NULL, 0);
	assert(events.context_switches == 3);
	assert(events.preemptions == 1 && events.blocked_switches == 1 &&
	       events.voluntary_switches == 1);
}

static void disabled_timing_keeps_cpu_runtime(void)
{
	struct task_struct rt	    = { .pid = 1, .policy = 1 };
	struct task_struct deadline = { .pid = 2, .policy = 6 };
	struct task_struct idle	    = {};

	event_timing_sample_rate    = 0;
	now_ns			    = 100;
	on_sched_switch(false, NULL, &rt, 0);
	now_ns = 200;
	on_sched_switch(true, &rt, &deadline, 2);
	now_ns = 250;
	on_sched_switch(false, &deadline, &idle, 0);
	assert(runtime.busy_ns == 150);
	assert(runtime.rt_stop_ns == 100 && runtime.deadline_ns == 50);
	assert(rt.storage == NULL && deadline.storage == NULL &&
	       idle.storage == NULL);
	assert(slice.total_ns == 0 && blocked.total_ns == 0 &&
	       wakeup.total_ns == 0);
}

static void elapsed_histogram_uses_floor_log2_buckets(void)
{
	struct mitosis_callback_timing timing = {};

	record_elapsed(&timing, 1);
	record_elapsed(&timing, 2);
	record_elapsed(&timing, 16);
	record_elapsed(&timing, 20);
	record_elapsed(&timing, 50);
	assert(timing.total_ns == 89);
	assert(timing.buckets[0] == 1 && timing.buckets[1] == 1);
	assert(timing.buckets[4] == 2 && timing.buckets[5] == 1);
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	event_timing_sample_rate = 1;
	if (!strcmp(argv[1], "idle"))
		idle_is_excluded_from_task_slices();
	else if (!strcmp(argv[1], "wakeup"))
		running_wakeup_does_not_start_latency();
	else if (!strcmp(argv[1], "preempt"))
		preemption_does_not_start_blocked_timer();
	else if (!strcmp(argv[1], "blocked"))
		real_block_and_wakeup_keep_elapsed_samples();
	else if (!strcmp(argv[1], "switch_bins"))
		scheduler_switch_bins_are_exclusive();
	else if (!strcmp(argv[1], "runtime"))
		disabled_timing_keeps_cpu_runtime();
	else if (!strcmp(argv[1], "buckets"))
		elapsed_histogram_uses_floor_log2_buckets();
	else
		assert(false);
	return 0;
}
