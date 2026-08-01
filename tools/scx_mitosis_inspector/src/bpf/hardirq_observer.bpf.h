/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_HARDIRQ_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_HARDIRQ_OBSERVER_BPF_H

#define HARDIRQ_OBSERVER_MAX_IRQS 256
#define HARDIRQ_OBSERVER_TIMING_BUCKETS 64

struct hardirq_observer_metrics {
	u64 count;
	u64 elapsed_total_ns;
	u64 elapsed_buckets[HARDIRQ_OBSERVER_TIMING_BUCKETS];
};

struct hardirq_observer_health {
	u64 metrics_map_full;
	u64 starts_map_full;
	u64 unmatched_exits;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HARDIRQ_OBSERVER_MAX_IRQS);
	__type(key, u32);
	__type(value, u64);
} hardirq_observer_starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, HARDIRQ_OBSERVER_MAX_IRQS);
	__type(key, u32);
	__type(value, struct hardirq_observer_metrics);
} hardirq_observer_metrics SEC(".maps");

/* A map-backed zero value avoids placing the large histogram on BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hardirq_observer_metrics);
} hardirq_observer_zero_metrics SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hardirq_observer_health);
} hardirq_observer_health SEC(".maps");

static __always_inline struct hardirq_observer_health *
hardirq_observer_get_health(void)
{
	u32 zero = 0;

	return bpf_map_lookup_elem(&hardirq_observer_health, &zero);
}

static __always_inline struct hardirq_observer_metrics *
hardirq_observer_get_metrics(u32 irq)
{
	struct hardirq_observer_metrics *zero;
	struct hardirq_observer_metrics *metrics;
	u32 zero_key = 0;

	metrics = bpf_map_lookup_elem(&hardirq_observer_metrics, &irq);
	if (metrics)
		return metrics;

	zero = bpf_map_lookup_elem(&hardirq_observer_zero_metrics, &zero_key);
	if (!zero)
		return NULL;
	bpf_map_update_elem(&hardirq_observer_metrics, &irq, zero,
			    BPF_NOEXIST);
	return bpf_map_lookup_elem(&hardirq_observer_metrics, &irq);
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(hirqo_entry, int irq, struct irqaction *action)
{
	struct hardirq_observer_health *health;
	struct hardirq_observer_metrics *metrics;
	u64 started_at;
	u32 key;

	if (irq < 0)
		return 0;
	key = irq;
	metrics = hardirq_observer_get_metrics(key);
	if (!metrics) {
		health = hardirq_observer_get_health();
		if (health)
			health->metrics_map_full++;
		return 0;
	}

	metrics->count++;
	started_at = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&hardirq_observer_starts, &key, &started_at,
				BPF_ANY)) {
		health = hardirq_observer_get_health();
		if (health)
			health->starts_map_full++;
	}
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(hirqo_exit, int irq, struct irqaction *action, int ret)
{
	struct hardirq_observer_health *health;
	struct hardirq_observer_metrics *metrics;
	u64 *started_at, elapsed;
	u32 bucket = 0;
	u32 key;

	if (irq < 0)
		return 0;
	key = irq;
	started_at = bpf_map_lookup_elem(&hardirq_observer_starts, &key);
	if (!started_at || !*started_at) {
		health = hardirq_observer_get_health();
		if (health)
			health->unmatched_exits++;
		return 0;
	}
	elapsed = bpf_ktime_get_ns() - *started_at;
	*started_at = 0;

	metrics = bpf_map_lookup_elem(&hardirq_observer_metrics, &key);
	if (!metrics)
		return 0;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= HARDIRQ_OBSERVER_TIMING_BUCKETS)
		bucket = HARDIRQ_OBSERVER_TIMING_BUCKETS - 1;
	metrics->elapsed_total_ns += elapsed;
	metrics->elapsed_buckets[bucket]++;
	return 0;
}

#endif /* __SCX_MITOSIS_INSPECTOR_HARDIRQ_OBSERVER_BPF_H */
