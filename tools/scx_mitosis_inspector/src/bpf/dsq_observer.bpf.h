/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_DSQ_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_DSQ_OBSERVER_BPF_H

#include <bpf/bpf_core_read.h>

#define DSQ_OBSERVER_TIMING_BUCKETS 64

struct dsq_task_observation {
	u64 dsq_id;
	u64 inserted_at;
};

struct dsq_observer_metrics {
	u64 insert_count;
	u64 move_count;
	u64 residence_total_ns;
	u64 residence_buckets[DSQ_OBSERVER_TIMING_BUCKETS];
	u64 depth_samples;
	u64 depth_total;
	u64 depth_last;
	u64 depth_max;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, struct dsq_task_observation);
} dsq_task_observations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct dsq_observer_metrics);
} dsq_observer_metrics SEC(".maps");

static __always_inline struct dsq_observer_metrics *
dsq_observer_lookup_metrics(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&dsq_observer_metrics, &key);
}

static __always_inline void dsq_observer_record_insert(struct task_struct *p,
						       u64 dsq_id)
{
	struct dsq_task_observation observation = {};
	struct dsq_observer_metrics *metrics;
	u32 pid;

	metrics = dsq_observer_lookup_metrics();
	if (metrics)
		metrics->insert_count++;
	if (!p)
		return;
	pid = BPF_CORE_READ(p, pid);
	if (!pid)
		return;
	observation.dsq_id	 = dsq_id;
	observation.inserted_at = bpf_ktime_get_ns();
	bpf_map_update_elem(&dsq_task_observations, &pid, &observation, BPF_ANY);
}

static __always_inline void dsq_observer_record_move(struct task_struct *p,
						     u64		 dsq_id)
{
	struct dsq_task_observation observation = {};
	struct dsq_observer_metrics *metrics;
	u32 pid;

	metrics = dsq_observer_lookup_metrics();
	if (metrics)
		metrics->move_count++;
	if (!p)
		return;
	pid = BPF_CORE_READ(p, pid);
	if (!pid)
		return;
	observation.dsq_id	 = dsq_id;
	observation.inserted_at = bpf_ktime_get_ns();
	bpf_map_update_elem(&dsq_task_observations, &pid, &observation, BPF_ANY);
}

static __always_inline void dsq_observer_record_move_to_local(bool moved)
{
	struct dsq_observer_metrics *metrics;

	if (!moved)
		return;
	metrics = dsq_observer_lookup_metrics();
	if (metrics)
		metrics->move_count++;
}

static __always_inline void dsq_observer_record_residence(struct task_struct *p)
{
	struct dsq_task_observation *observation;
	struct dsq_observer_metrics *metrics;
	u64			     inserted_at, elapsed, dsq_id;
	s32			     depth;
	u32			     bucket = 0, pid;

	if (!p)
		return;
	pid = BPF_CORE_READ(p, pid);
	if (!pid)
		return;
	observation = bpf_map_lookup_elem(&dsq_task_observations, &pid);
	if (!observation || !observation->inserted_at)
		return;

	inserted_at		 = observation->inserted_at;
	dsq_id			 = observation->dsq_id;
	bpf_map_delete_elem(&dsq_task_observations, &pid);
	metrics			 = dsq_observer_lookup_metrics();
	if (!metrics)
		return;

	elapsed = bpf_ktime_get_ns() - inserted_at;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= DSQ_OBSERVER_TIMING_BUCKETS)
		bucket = DSQ_OBSERVER_TIMING_BUCKETS - 1;
	metrics->residence_total_ns += elapsed;
	metrics->residence_buckets[bucket]++;

	depth = scx_bpf_dsq_nr_queued(dsq_id);
	if (depth < 0)
		return;
	metrics->depth_samples++;
	metrics->depth_total += depth;
	metrics->depth_last = depth;
	if (depth > metrics->depth_max)
		metrics->depth_max = depth;
}

/* v6.13 and newer insert names. */
SEC("kprobe/scx_bpf_dsq_insert")
int BPF_KPROBE(dsqo_insert, struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_insert(p, dsq_id);
	return 0;
}

SEC("kprobe/scx_bpf_dsq_insert___v2")
int BPF_KPROBE(dsqo_insert_v2, struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_insert(p, dsq_id);
	return 0;
}

SEC("kprobe/scx_bpf_dsq_insert_vtime")
int BPF_KPROBE(dsqo_insert_vtime, struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_insert(p, dsq_id);
	return 0;
}

/* v6.19+ packs the vtime insert arguments into a struct. */
SEC("kprobe/__scx_bpf_dsq_insert_vtime")
int BPF_KPROBE(dsqo_insert_vtime_args, struct task_struct *p, void *args)
{
	u64 dsq_id = SCX_DSQ_INVALID;

	if (args && !bpf_probe_read_kernel(&dsq_id, sizeof(dsq_id), args))
		dsq_observer_record_insert(p, dsq_id);
	return 0;
}

/* Pre-v6.13 insert names. */
SEC("kprobe/scx_bpf_dispatch")
int BPF_KPROBE(dsqo_dispatch, struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_insert(p, dsq_id);
	return 0;
}

SEC("kprobe/scx_bpf_dispatch_vtime")
int BPF_KPROBE(dsqo_dispatch_vtime, struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_insert(p, dsq_id);
	return 0;
}

/* v6.13 and newer iterator move names. */
SEC("kprobe/scx_bpf_dsq_move")
int BPF_KPROBE(dsqo_move, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_move(p, dsq_id);
	return 0;
}

SEC("kprobe/scx_bpf_dsq_move_vtime")
int BPF_KPROBE(dsqo_move_vtime, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_move(p, dsq_id);
	return 0;
}

/* Pre-v6.13 iterator move names. */
SEC("kprobe/scx_bpf_dispatch_from_dsq")
int BPF_KPROBE(dsqo_dispatch_move, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_move(p, dsq_id);
	return 0;
}

SEC("kprobe/scx_bpf_dispatch_vtime_from_dsq")
int BPF_KPROBE(dsqo_dispatch_move_vtime, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id)
{
	dsq_observer_record_move(p, dsq_id);
	return 0;
}

/* Mitosis consumes queued work through this path. Count successful moves. */
SEC("kretprobe/scx_bpf_dsq_move_to_local")
int BPF_KRETPROBE(dsqo_move_local_ret, bool moved)
{
	dsq_observer_record_move_to_local(moved);
	return 0;
}

/* Pre-v6.13 name for scx_bpf_dsq_move_to_local(). */
SEC("kretprobe/scx_bpf_consume")
int BPF_KRETPROBE(dsqo_consume_ret, bool moved)
{
	dsq_observer_record_move_to_local(moved);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(dsqo_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	dsq_observer_record_residence(next);
	return 0;
}

#endif /* __SCX_MITOSIS_INSPECTOR_DSQ_OBSERVER_BPF_H */
