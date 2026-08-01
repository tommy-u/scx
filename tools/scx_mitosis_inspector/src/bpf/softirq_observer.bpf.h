/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_SOFTIRQ_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_SOFTIRQ_OBSERVER_BPF_H

#define SOFTIRQ_OBSERVER_VECTORS 10
#define SOFTIRQ_OBSERVER_TIMING_BUCKETS 64

struct softirq_observer_metrics {
	u64 count;
	u64 elapsed_total_ns;
	u64 elapsed_buckets[SOFTIRQ_OBSERVER_TIMING_BUCKETS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SOFTIRQ_OBSERVER_VECTORS);
	__type(key, u32);
	__type(value, u64);
} softirq_observer_starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SOFTIRQ_OBSERVER_VECTORS);
	__type(key, u32);
	__type(value, struct softirq_observer_metrics);
} softirq_observer_metrics SEC(".maps");

SEC("tp_btf/softirq_entry")
int BPF_PROG(sirqo_entry, unsigned int nr)
{
	struct softirq_observer_metrics *metrics;
	u64 *started_at;
	u32 key = nr;

	if (key >= SOFTIRQ_OBSERVER_VECTORS)
		return 0;
	metrics = bpf_map_lookup_elem(&softirq_observer_metrics, &key);
	if (metrics)
		metrics->count++;
	started_at = bpf_map_lookup_elem(&softirq_observer_starts, &key);
	if (started_at)
		*started_at = bpf_ktime_get_ns();
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(sirqo_exit, unsigned int nr)
{
	struct softirq_observer_metrics *metrics;
	u64 *started_at, started, elapsed;
	u32 bucket = 0;
	u32 key = nr;

	if (key >= SOFTIRQ_OBSERVER_VECTORS)
		return 0;
	started_at = bpf_map_lookup_elem(&softirq_observer_starts, &key);
	if (!started_at || !*started_at)
		return 0;
	started = *started_at;
	*started_at = 0;
	elapsed = bpf_ktime_get_ns() - started;

	metrics = bpf_map_lookup_elem(&softirq_observer_metrics, &key);
	if (!metrics)
		return 0;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= SOFTIRQ_OBSERVER_TIMING_BUCKETS)
		bucket = SOFTIRQ_OBSERVER_TIMING_BUCKETS - 1;
	metrics->elapsed_total_ns += elapsed;
	metrics->elapsed_buckets[bucket]++;
	return 0;
}

#endif /* __SCX_MITOSIS_INSPECTOR_SOFTIRQ_OBSERVER_BPF_H */
