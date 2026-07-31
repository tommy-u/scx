// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>
#include <bpf/bpf_tracing.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

const volatile u32 callback_timing_sample_rate;

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

static __always_inline void finish_callback_timing(enum callback_index callback)
{
	struct mitosis_callback_timing *timing;
	u32 key = callback, bucket = 0;
	u64 *started_at, elapsed;

	started_at = bpf_map_lookup_elem(&callback_timing_starts, &key);
	if (!started_at || !*started_at)
		return;
	elapsed = bpf_ktime_get_ns() - *started_at;
	*started_at = 0;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= MITOSIS_CALLBACK_TIMING_BUCKETS)
		bucket = MITOSIS_CALLBACK_TIMING_BUCKETS - 1;
	timing = bpf_map_lookup_elem(&callback_timings, &key);
	if (!timing)
		return;
	timing->total_ns += elapsed;
	timing->buckets[bucket]++;
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
