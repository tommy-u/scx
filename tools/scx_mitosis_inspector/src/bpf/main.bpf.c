// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>
#include <bpf/bpf_tracing.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

const volatile u32 callback_timing_sample_rate;
const volatile u32 event_timing_sample_rate;

enum callback_index {
	CALLBACK_SELECT_CPU,
	CALLBACK_ENQUEUE,
	CALLBACK_DISPATCH,
	CALLBACK_RUNNING,
	CALLBACK_STOPPING,
	NR_CALLBACKS,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CALLBACKS);
	__type(key, u32);
	__type(value, u64);
} callback_counts	    SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CALLBACKS);
	__type(key, u32);
	__type(value, u64);
} callback_timing_starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CALLBACKS);
	__type(key, u32);
	__type(value, struct mitosis_callback_timing);
} callback_timings SEC(".maps");

struct task_observation {
	u64 wakeup_at;
	u64 running_at;
	u64 blocked_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_observation);
} task_observations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mitosis_callback_timing);
} wakeup_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mitosis_callback_timing);
} cpu_slice_duration SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mitosis_callback_timing);
} blocked_duration SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct mitosis_cpu_pair);
	__type(value, u64);
} migration_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mitosis_cpu_runtime);
} cpu_runtime SEC(".maps");

static __always_inline void count_callback(enum callback_index callback)
{
	u32  key = callback;
	u64 *count;

	count = bpf_map_lookup_elem(&callback_counts, &key);
	if (count)
		(*count)++;
}

static __always_inline void start_callback_timing(enum callback_index callback)
{
	u32  key = callback;
	u32  rate = READ_ONCE(callback_timing_sample_rate);
	u64 *started_at;

	started_at = bpf_map_lookup_elem(&callback_timing_starts, &key);
	if (!started_at)
		return;
	*started_at = 0;
	if (!rate)
		return;
	if (rate > 1 && (bpf_get_prandom_u32() & (rate - 1)))
		return;
	*started_at = bpf_ktime_get_ns();
}

static __always_inline bool should_sample(u32 rate)
{
	if (!rate)
		return false;
	return rate == 1 || !(bpf_get_prandom_u32() & (rate - 1));
}

static __always_inline void record_elapsed(struct mitosis_callback_timing *timing,
					   u64 elapsed)
{
	u32 bucket = 0;

	if (!timing)
		return;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= MITOSIS_CALLBACK_TIMING_BUCKETS)
		bucket = MITOSIS_CALLBACK_TIMING_BUCKETS - 1;
	timing->total_ns += elapsed;
	timing->buckets[bucket]++;
}

static __always_inline void finish_callback_timing(enum callback_index callback)
{
	struct mitosis_callback_timing *timing;
	u32 key = callback;
	u64 *started_at, elapsed;

	started_at = bpf_map_lookup_elem(&callback_timing_starts, &key);
	if (!started_at || !*started_at)
		return;
	elapsed = bpf_ktime_get_ns() - *started_at;
	*started_at = 0;
	timing = bpf_map_lookup_elem(&callback_timings, &key);
	record_elapsed(timing, elapsed);
}

static __always_inline void observe_callback(enum callback_index callback)
{
	count_callback(callback);
	start_callback_timing(callback);
}

SEC("fentry")
int BPF_PROG(observe_select_cpu, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags)
{
	observe_callback(CALLBACK_SELECT_CPU);
	return 0;
}

SEC("fentry")
int BPF_PROG(observe_enqueue, struct task_struct *p, u64 enq_flags)
{
	observe_callback(CALLBACK_ENQUEUE);
	return 0;
}

SEC("fentry")
int BPF_PROG(observe_dispatch, s32 cpu, struct task_struct *prev)
{
	observe_callback(CALLBACK_DISPATCH);
	return 0;
}

SEC("fentry")
int BPF_PROG(observe_running, struct task_struct *p)
{
	observe_callback(CALLBACK_RUNNING);
	return 0;
}

SEC("fentry")
int BPF_PROG(observe_stopping, struct task_struct *p, bool runnable)
{
	observe_callback(CALLBACK_STOPPING);
	return 0;
}

SEC("fexit")
int BPF_PROG(observe_select_cpu_exit, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags, s32 ret)
{
	finish_callback_timing(CALLBACK_SELECT_CPU);
	return 0;
}

SEC("fexit")
int BPF_PROG(observe_enqueue_exit, struct task_struct *p, u64 enq_flags)
{
	finish_callback_timing(CALLBACK_ENQUEUE);
	return 0;
}

SEC("fexit")
int BPF_PROG(observe_dispatch_exit, s32 cpu, struct task_struct *prev)
{
	finish_callback_timing(CALLBACK_DISPATCH);
	return 0;
}

SEC("fexit")
int BPF_PROG(observe_running_exit, struct task_struct *p)
{
	finish_callback_timing(CALLBACK_RUNNING);
	return 0;
}

SEC("fexit")
int BPF_PROG(observe_stopping_exit, struct task_struct *p, bool runnable)
{
	finish_callback_timing(CALLBACK_STOPPING);
	return 0;
}

static __always_inline int record_wakeup(struct task_struct *p)
{
	struct mitosis_callback_timing *timing;
	struct task_observation *observation;
	u32 key = 0;
	u64 now;

	if (!p)
		return 0;
	now = bpf_ktime_get_ns();
	observation = bpf_task_storage_get(&task_observations, p, 0, 0);
	if (observation && observation->blocked_at) {
		timing = bpf_map_lookup_elem(&blocked_duration, &key);
		record_elapsed(timing, now - observation->blocked_at);
		observation->blocked_at = 0;
	}
	if (!should_sample(READ_ONCE(event_timing_sample_rate)))
		return 0;
	if (!observation)
		observation = bpf_task_storage_get(
			&task_observations, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (observation)
		observation->wakeup_at = now;
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_sched_wakeup, struct task_struct *p)
{
	return record_wakeup(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_sched_wakeup_new, struct task_struct *p)
{
	return record_wakeup(p);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	struct mitosis_callback_timing *timing;
	struct mitosis_cpu_runtime *runtime;
	struct task_observation *observation;
	u32 key = 0;
	u64 now;

	if (!next)
		return 0;
	now = bpf_ktime_get_ns();
	runtime = bpf_map_lookup_elem(&cpu_runtime, &key);
	if (runtime) {
		if (runtime->last_switch_ns && runtime->current_busy)
			runtime->busy_ns += now - runtime->last_switch_ns;
		runtime->last_switch_ns = now;
		runtime->current_busy = BPF_CORE_READ(next, pid) != 0;
	}
	if (prev) {
		observation = bpf_task_storage_get(&task_observations, prev, 0, 0);
		if (observation && observation->running_at) {
			timing = bpf_map_lookup_elem(&cpu_slice_duration, &key);
			record_elapsed(timing, now - observation->running_at);
			observation->running_at = 0;
		}
		if (prev_state != 0 &&
		    should_sample(READ_ONCE(event_timing_sample_rate))) {
			if (!observation)
				observation = bpf_task_storage_get(
					&task_observations, prev, 0,
					BPF_LOCAL_STORAGE_GET_F_CREATE);
			if (observation)
				observation->blocked_at = now;
		}
	}
	observation = bpf_task_storage_get(&task_observations, next, 0, 0);
	if (observation && observation->wakeup_at) {
		timing = bpf_map_lookup_elem(&wakeup_latency, &key);
		record_elapsed(timing, now - observation->wakeup_at);
		observation->wakeup_at = 0;
	}
	if (should_sample(READ_ONCE(event_timing_sample_rate))) {
		if (!observation)
			observation = bpf_task_storage_get(
				&task_observations, next, 0,
				BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (observation)
			observation->running_at = now;
	}
	return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(on_sched_migrate_task, struct task_struct *p, int dest_cpu)
{
	struct mitosis_cpu_pair pair = {
		.from_cpu = bpf_get_smp_processor_id(),
		.to_cpu = dest_cpu,
	};
	u64 initial = 1, *count;

	if (pair.from_cpu == pair.to_cpu)
		return 0;
	count = bpf_map_lookup_elem(&migration_counts, &pair);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return 0;
	}
	bpf_map_update_elem(&migration_counts, &pair, &initial, BPF_NOEXIST);
	return 0;
}
