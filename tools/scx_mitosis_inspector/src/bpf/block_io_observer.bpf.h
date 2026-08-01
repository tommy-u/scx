/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_BLOCK_IO_OBSERVER_BPF_H
#define __SCX_MITOSIS_INSPECTOR_BLOCK_IO_OBSERVER_BPF_H

#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define BLOCK_IO_OBSERVER_TIMING_BUCKETS 64
#define BLOCK_IO_OBSERVER_MAX_REQUESTS 16384

struct block_io_request_observation {
	u64 issued_at;
	u32 remaining_bytes;
};

struct block_io_observer_metrics {
	u64 issue_events;
	u64 completion_events;
	u64 completed_requests;
	u64 error_events;
	u64 issued_bytes;
	u64 completed_bytes;
	u64 unmatched_completions;
	u64 tracking_failures;
	u64 latency_total_ns;
	u64 latency_buckets[BLOCK_IO_OBSERVER_TIMING_BUCKETS];
};

/* Requests may be issued and completed on different CPUs. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, BLOCK_IO_OBSERVER_MAX_REQUESTS);
	__type(key, u64);
	__type(value, struct block_io_request_observation);
} block_io_request_observations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct block_io_observer_metrics);
} block_io_observer_metrics SEC(".maps");

static __always_inline struct block_io_observer_metrics *
block_io_observer_lookup_metrics(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&block_io_observer_metrics, &key);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_io_observer_issue, struct request *rq)
{
	struct block_io_request_observation observation = {};
	struct block_io_observer_metrics   *metrics;
	u64				    key;

	if (!rq)
		return 0;
	metrics = block_io_observer_lookup_metrics();
	if (!metrics)
		return 0;

	key			    = (u64)rq;
	observation.issued_at	    = bpf_ktime_get_ns();
	observation.remaining_bytes = BPF_CORE_READ(rq, __data_len);
	metrics->issue_events++;
	metrics->issued_bytes += observation.remaining_bytes;
	if (bpf_map_update_elem(&block_io_request_observations, &key,
				&observation, BPF_ANY))
		metrics->tracking_failures++;
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_io_observer_complete, struct request *rq, blk_status_t error,
	     unsigned int nr_bytes)
{
	struct block_io_request_observation *observation;
	struct block_io_observer_metrics    *metrics;
	u64				     issued_at, elapsed, key;
	u32				     bucket = 0;

	if (!rq)
		return 0;
	metrics = block_io_observer_lookup_metrics();
	if (!metrics)
		return 0;

	metrics->completion_events++;
	metrics->completed_bytes += nr_bytes;
	if (error)
		metrics->error_events++;

	key	    = (u64)rq;
	observation = bpf_map_lookup_elem(&block_io_request_observations, &key);
	if (!observation || !observation->issued_at) {
		metrics->unmatched_completions++;
		return 0;
	}

	/* block_rq_complete can report a request in multiple byte ranges. */
	if (nr_bytes && nr_bytes < observation->remaining_bytes) {
		observation->remaining_bytes -= nr_bytes;
		return 0;
	}

	issued_at = observation->issued_at;
	bpf_map_delete_elem(&block_io_request_observations, &key);
	elapsed = bpf_ktime_get_ns() - issued_at;
	if (elapsed > 1)
		bucket = log2_u64(elapsed) - 1;
	if (bucket >= BLOCK_IO_OBSERVER_TIMING_BUCKETS)
		bucket = BLOCK_IO_OBSERVER_TIMING_BUCKETS - 1;
	metrics->completed_requests++;
	metrics->latency_total_ns += elapsed;
	metrics->latency_buckets[bucket]++;
	return 0;
}

#endif /* __SCX_MITOSIS_INSPECTOR_BLOCK_IO_OBSERVER_BPF_H */
