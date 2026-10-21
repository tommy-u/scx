// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only
// Optional observers: no scheduler callbacks or scheduler-owned maps are changed.
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define EXPLORE_BUCKETS 64
#define EXPLORE_MAX_CPUS 4096
#define TASK_SAMPLE_RATE 16
#define EVENT_SAMPLE_RATE 64

struct explore_histogram {
	u64 total_ns;
	u64 max_ns;
	u64 max_update_failures;
	u64 buckets[EXPLORE_BUCKETS];
};

struct explore_task_key {
	u64 start_time_ns;
	u32 pid;
	u32 pad;
};

struct explore_dsq_metrics {
	u64 insert_events;
	u64 move_events;
	u64 depth_samples;
	u64 depth_total;
	u64 depth_last;
	u64 depth_max;
	u64 last_seen_ns;
	struct explore_histogram latency;
	struct explore_histogram run;
};

struct explore_task_metrics {
	u32 tgid;
	u32 cpu;
	char comm[16];
	u64 cgroup_id;
	u64 first_seen_ns;
	u64 last_seen_ns;
	u64 last_running_at_ns;
	u64 runtime_ns;
	u64 running_since_ns;
	u64 wakeups;
	u64 switches;
	struct explore_histogram delay;
	struct explore_histogram dsq_delay;
};

struct explore_pair_key {
	struct explore_task_key waker;
	struct explore_task_key wakee;
};

struct explore_waker_metrics {
	u32 waker_tgid;
	u32 wakee_tgid;
	char waker_comm[16];
	char wakee_comm[16];
	u32 waker_cpu;
	u32 wakee_cpu;
	u64 first_seen_ns;
	u64 last_seen_ns;
	u64 wakeups;
	u64 same_cpu;
	u64 same_llc;
	u64 cross_llc;
	u64 cross_numa;
	u64 unknown_locality;
	struct explore_histogram latency;
};

struct explore_dsq_state {
	u64 queued_dsq;
	u64 queued_at_ns;
	u64 run_dsq;
	u64 running_at_ns;
};

struct explore_task_state {
	u64 wakeup_at_ns;
	u64 queued_at_ns;
};

struct explore_waker_state {
	struct explore_pair_key pair;
	u64 wakeup_at_ns;
	u64 origin_at_ns;
	u32 waker_cpu;
	u32 pad;
	u32 waker_tgid;
	u32 wakee_tgid;
	char waker_comm[16];
	char wakee_comm[16];
};

struct explore_ipi_key { u32 source_cpu; u32 target_cpu; };
struct explore_pressure_value { u64 pressure; u64 updated_at_ns; };
struct explore_topology_value { u32 llc; u32 node; u32 available; u32 pad; };
struct explore_config_value { u32 cpu_limit; u32 pad; };
struct explore_health {
	u64 tracking_failures;
	u64 state_failures;
	u64 depth_failures;
	u64 ipi_send_cpu_events;
	u64 ipi_send_cpumask_events;
	u64 ipi_targets;
	u64 ipi_mask_read_failures;
	u64 ipi_mask_truncated;
	u64 waker_wakeups_seen;
	u64 waker_selected_wakeups;
	u64 waker_matched_samples;
	u64 waker_origins_seen;
	u64 waker_origins_selected;
	u64 waker_origins_missing;
	u64 waker_running_wakeups;
	u64 task_running_wakeups;
	u64 dsq_unverified_moves;
	u64 task_unverified_moves;
};

struct explore_scx_result {
	u64 supported_mask;
	u64 timestamp_ns;
	u64 counts[5];
};

#define HASH_MAP(name, key_t, value_t, capacity) \
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, capacity); \
	__type(key, key_t); __type(value, value_t); } name SEC(".maps")
#define ZERO_MAP(name, value_t) \
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); \
	__type(key, u32); __type(value, value_t); } name SEC(".maps")
#define LRU_HASH_MAP(name, key_t, value_t, capacity) \
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, capacity); \
	__type(key, key_t); __type(value, value_t); } name SEC(".maps")
#define HISTOGRAM_MAP(name) \
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); \
	__type(key, u32); __type(value, struct explore_histogram); } name SEC(".maps")

HASH_MAP(explore_dsqs, u64, struct explore_dsq_metrics, 256);
LRU_HASH_MAP(explore_tasks, struct explore_task_key, struct explore_task_metrics, 4096);
LRU_HASH_MAP(explore_wakers, struct explore_pair_key, struct explore_waker_metrics, 4096);
HASH_MAP(explore_ipis, struct explore_ipi_key, u64, 65536);
HASH_MAP(explore_pressure, u32, struct explore_pressure_value, EXPLORE_MAX_CPUS);
ZERO_MAP(explore_dsq_zero, struct explore_dsq_metrics);
ZERO_MAP(explore_task_zero, struct explore_task_metrics);
ZERO_MAP(explore_waker_zero, struct explore_waker_metrics);
ZERO_MAP(explore_config, struct explore_config_value);
// Kprobe task arguments are untrusted scalar addresses. Hash state uses CO-RE
// reads of PID + birth time and does not pass such addresses to task-storage helpers.
HASH_MAP(explore_dsq_states, struct explore_task_key, struct explore_dsq_state, 16384);
LRU_HASH_MAP(explore_task_states, struct explore_task_key, struct explore_task_state, 4096);
LRU_HASH_MAP(explore_waker_states, struct explore_task_key, struct explore_waker_state, 4096);
HISTOGRAM_MAP(explore_dsq_latency);
HISTOGRAM_MAP(explore_dsq_running);
HISTOGRAM_MAP(explore_task_delay);
HISTOGRAM_MAP(explore_waker_latency);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EXPLORE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct explore_topology_value);
} explore_topology SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct explore_health);
} explore_health SEC(".maps");

static __always_inline struct explore_health *health(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&explore_health, &zero);
}

static __always_inline void tracking_failure(void)
{
	struct explore_health *h = health();
	if (h)
		h->tracking_failures++;
}

static __always_inline void state_failure(void)
{
	struct explore_health *h = health();
	if (h)
		h->state_failures++;
}

static __always_inline void task_key(struct task_struct *p,
				    struct explore_task_key *key)
{
	key->pid = BPF_CORE_READ(p, pid);
	key->pad = 0;
	if (bpf_core_field_exists(p->start_boottime))
		key->start_time_ns = BPF_CORE_READ(p, start_boottime);
	else
		key->start_time_ns = BPF_CORE_READ(p, start_time);
}

static __always_inline bool task_sampled(struct task_struct *p)
{
	struct explore_task_key key = {};
	task_key(p, &key);
	// A stable cohort lets CPU runtime be counted continuously for each retained task.
	u32 hash = key.pid ^ (u32)key.start_time_ns ^ (u32)(key.start_time_ns >> 32);
	hash ^= hash >> 16;
	hash *= 0x7feb352d;
	hash ^= hash >> 15;
	return key.pid && !(hash & (TASK_SAMPLE_RATE - 1));
}

static __always_inline bool event_sampled(void)
{
	return !(bpf_get_prandom_u32() & (EVENT_SAMPLE_RATE - 1));
}

static __always_inline bool already_on_cpu(struct task_struct *p)
{
	if (bpf_core_field_exists(p->on_cpu))
		return BPF_CORE_READ(p, on_cpu) != 0;
	// Uniprocessor kernels need no on_cpu field; only the current task can execute.
	return p == (struct task_struct *)bpf_get_current_task_btf();
}

static __always_inline void record_histogram(struct explore_histogram *hist, u64 ns)
{
	// SCX log2_u64 returns a bit length; bucket indices use floor(log2(ns)).
	u32 bucket = ns > 1 ? log2_u64(ns) - 1 : 0;
	if (bucket >= EXPLORE_BUCKETS)
		bucket = EXPLORE_BUCKETS - 1;
	__sync_fetch_and_add(&hist->total_ns, ns);
	__sync_fetch_and_add(&hist->buckets[bucket], 1);
	// Retry racing max updates. A failed bounded retry is sticky quality loss:
	// userspace then refuses to present this maximum as exact or clip quantiles.
	for (u32 attempt = 0; attempt < 8; attempt++) {
		u64 previous = READ_ONCE(hist->max_ns);
		if (ns <= previous)
			return;
		if (__sync_val_compare_and_swap(&hist->max_ns, previous, ns) == previous)
			return;
	}
	__sync_fetch_and_add(&hist->max_update_failures, 1);
}

static __always_inline void record_aggregate_histogram(void *map, u64 ns)
{
	u32 zero = 0;
	struct explore_histogram *hist = bpf_map_lookup_elem(map, &zero);
	if (hist)
		record_histogram(hist, ns);
}

static __always_inline struct explore_dsq_metrics *dsq_metrics(u64 dsq_id)
{
	struct explore_dsq_metrics *result;
	u32 zero = 0;
	result = bpf_map_lookup_elem(&explore_dsqs, &dsq_id);
	if (!result) {
		struct explore_dsq_metrics *empty = bpf_map_lookup_elem(&explore_dsq_zero, &zero);
		if (empty)
			bpf_map_update_elem(&explore_dsqs, &dsq_id, empty, BPF_NOEXIST);
		result = bpf_map_lookup_elem(&explore_dsqs, &dsq_id);
	}
	if (!result)
		tracking_failure();
	return result;
}

static __always_inline void dsq_insert(struct task_struct *p, u64 dsq_id, bool moved)
{
	struct explore_dsq_metrics *metrics = dsq_metrics(dsq_id);
	if (metrics) {
		if (moved)
			__sync_fetch_and_add(&metrics->move_events, 1);
		else
			__sync_fetch_and_add(&metrics->insert_events, 1);
		metrics->last_seen_ns = bpf_ktime_get_ns();
	}
	if (!p)
		return;
	struct explore_task_key key = {};
	task_key(p, &key);
	if (!key.pid)
		return;
	if (moved) {
		// An iterator move can fail normally if another CPU consumed the task.
		// Without a verified return, never assign latency to its requested destination.
		struct explore_dsq_state *old = bpf_map_lookup_elem(&explore_dsq_states, &key);
		struct explore_health *h = health();
		if (h)
			h->dsq_unverified_moves++;
		if (old) {
			old->queued_at_ns = 0;
			if (!old->running_at_ns)
				bpf_map_delete_elem(&explore_dsq_states, &key);
		}
		return;
	}
	bool sampled = event_sampled();
	struct explore_dsq_state *state = bpf_map_lookup_elem(&explore_dsq_states, &key);
	if (!state && sampled) {
		struct explore_dsq_state empty = {};
		bpf_map_update_elem(&explore_dsq_states, &key, &empty, BPF_NOEXIST);
		state = bpf_map_lookup_elem(&explore_dsq_states, &key);
	}
	if (!state) {
		if (sampled)
			state_failure();
		return;
	}
	// Clear stale samples when a different insertion was not selected.
	state->queued_at_ns = 0;
	if (!sampled) {
		if (!state->running_at_ns)
			bpf_map_delete_elem(&explore_dsq_states, &key);
		return;
	}
	state->queued_dsq = dsq_id;
	state->queued_at_ns = bpf_ktime_get_ns();
}

static __always_inline struct explore_task_metrics *task_metrics(struct task_struct *p)
{
	struct explore_task_key key = {};
	struct explore_task_metrics *result;
	u32 zero = 0;
	if (!p || !task_sampled(p))
		return NULL;
	task_key(p, &key);
	result = bpf_map_lookup_elem(&explore_tasks, &key);
	if (!result) {
		struct explore_task_metrics *empty = bpf_map_lookup_elem(&explore_task_zero, &zero);
		if (empty)
			bpf_map_update_elem(&explore_tasks, &key, empty, BPF_NOEXIST);
		result = bpf_map_lookup_elem(&explore_tasks, &key);
	}
	if (!result) {
		tracking_failure();
		return NULL;
	}
	result->tgid = BPF_CORE_READ(p, tgid);
	bpf_probe_read_kernel_str(result->comm, sizeof(result->comm), p->comm);
	struct cgroup *cgroup = BPF_CORE_READ(p, cgroups, dfl_cgrp);
	if (cgroup)
		result->cgroup_id = BPF_CORE_READ(cgroup, kn, id);
	result->last_seen_ns = bpf_ktime_get_ns();
	if (!result->first_seen_ns)
		result->first_seen_ns = result->last_seen_ns;
	return result;
}

static __always_inline void task_insert(struct task_struct *p, u64 dsq_id, bool moved)
{
	if (!p || !task_sampled(p))
		return;
	struct explore_task_key key = {};
	task_key(p, &key);
	struct explore_task_state *state = bpf_map_lookup_elem(&explore_task_states, &key);
	if (moved) {
		struct explore_health *h = health();
		if (h)
			h->task_unverified_moves++;
		if (state) {
			state->queued_at_ns = 0;
			if (!state->wakeup_at_ns)
				bpf_map_delete_elem(&explore_task_states, &key);
		}
		return;
	}
	if (!state) {
		struct explore_task_state empty = {};
		bpf_map_update_elem(&explore_task_states, &key, &empty, BPF_NOEXIST);
		state = bpf_map_lookup_elem(&explore_task_states, &key);
	}
	if (!state) {
		state_failure();
		return;
	}
	state->queued_at_ns = bpf_ktime_get_ns();
}

#define INSERT_PROGRAM(name, symbol, handler) \
SEC("kprobe/" symbol) \
int BPF_KPROBE(name, struct task_struct *p, u64 dsq_id) \
{ handler(p, dsq_id, false); return 0; }
#define INSERT_ARGS_PROGRAM(name, handler) \
SEC("kprobe/__scx_bpf_dsq_insert_vtime") \
int BPF_KPROBE(name, struct task_struct *p, void *args) \
{ u64 dsq_id; if (args && !bpf_probe_read_kernel(&dsq_id, sizeof(dsq_id), args)) \
	handler(p, dsq_id, false); return 0; }
#define MOVE_PROGRAM(name, symbol, handler) \
SEC("kprobe/" symbol) \
int BPF_KPROBE(name, struct bpf_iter_scx_dsq *it, struct task_struct *p, u64 dsq_id) \
{ handler(p, dsq_id, true); return 0; }

INSERT_PROGRAM(ex_dsq_insert, "scx_bpf_dsq_insert", dsq_insert)
INSERT_PROGRAM(ex_dsq_insert_v2, "scx_bpf_dsq_insert___v2", dsq_insert)
INSERT_PROGRAM(ex_dsq_insert_vtime, "scx_bpf_dsq_insert_vtime", dsq_insert)
INSERT_ARGS_PROGRAM(ex_dsq_insert_args, dsq_insert)
INSERT_PROGRAM(ex_dsq_dispatch, "scx_bpf_dispatch", dsq_insert)
INSERT_PROGRAM(ex_dsq_dispatch_vtime, "scx_bpf_dispatch_vtime", dsq_insert)
MOVE_PROGRAM(ex_dsq_move, "scx_bpf_dsq_move", dsq_insert)
MOVE_PROGRAM(ex_dsq_move_vtime, "scx_bpf_dsq_move_vtime", dsq_insert)
MOVE_PROGRAM(ex_dsq_dispatch_move, "scx_bpf_dispatch_from_dsq", dsq_insert)
MOVE_PROGRAM(ex_dsq_dispatch_move_vtime, "scx_bpf_dispatch_vtime_from_dsq", dsq_insert)
INSERT_PROGRAM(ex_task_insert, "scx_bpf_dsq_insert", task_insert)
INSERT_PROGRAM(ex_task_insert_v2, "scx_bpf_dsq_insert___v2", task_insert)
INSERT_PROGRAM(ex_task_insert_vtime, "scx_bpf_dsq_insert_vtime", task_insert)
INSERT_ARGS_PROGRAM(ex_task_insert_args, task_insert)
INSERT_PROGRAM(ex_task_dispatch, "scx_bpf_dispatch", task_insert)
INSERT_PROGRAM(ex_task_dispatch_vtime, "scx_bpf_dispatch_vtime", task_insert)
MOVE_PROGRAM(ex_task_move, "scx_bpf_dsq_move", task_insert)
MOVE_PROGRAM(ex_task_move_vtime, "scx_bpf_dsq_move_vtime", task_insert)
MOVE_PROGRAM(ex_task_dispatch_move, "scx_bpf_dispatch_from_dsq", task_insert)
MOVE_PROGRAM(ex_task_dispatch_move_vtime, "scx_bpf_dispatch_vtime_from_dsq", task_insert)

SEC("tp_btf/sched_switch")
int BPF_PROG(ex_dsqs_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	u64 now = bpf_ktime_get_ns();
	struct explore_dsq_state *state;
	struct explore_task_key prev_key = {}, next_key = {};
	task_key(prev, &prev_key);
	task_key(next, &next_key);
	state = bpf_map_lookup_elem(&explore_dsq_states, &prev_key);
	if (state && state->running_at_ns) {
		struct explore_dsq_metrics *metrics = dsq_metrics(state->run_dsq);
		if (now >= state->running_at_ns)
			record_aggregate_histogram(&explore_dsq_running, now - state->running_at_ns);
		if (metrics && now >= state->running_at_ns)
			record_histogram(&metrics->run, now - state->running_at_ns);
		state->running_at_ns = 0;
		if (!state->queued_at_ns)
			bpf_map_delete_elem(&explore_dsq_states, &prev_key);
	}
	state = bpf_map_lookup_elem(&explore_dsq_states, &next_key);
	if (!state || !state->queued_at_ns)
		return 0;
	struct explore_dsq_metrics *metrics = dsq_metrics(state->queued_dsq);
	if (now >= state->queued_at_ns)
		record_aggregate_histogram(&explore_dsq_latency, now - state->queued_at_ns);
	if (metrics && now >= state->queued_at_ns) {
		record_histogram(&metrics->latency, now - state->queued_at_ns);
		s32 depth = scx_bpf_dsq_nr_queued(state->queued_dsq);
		if (depth >= 0) {
			__sync_fetch_and_add(&metrics->depth_samples, 1);
			__sync_fetch_and_add(&metrics->depth_total, depth);
			metrics->depth_last = depth;
			u64 previous = metrics->depth_max;
			if ((u64)depth > previous)
				__sync_val_compare_and_swap(&metrics->depth_max, previous, depth);
		} else {
			struct explore_health *h = health();
			if (h)
				h->depth_failures++;
		}
	}
	state->run_dsq = state->queued_dsq;
	state->running_at_ns = now;
	state->queued_at_ns = 0;
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(ex_tasks_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	u64 now = bpf_ktime_get_ns();
	struct explore_task_metrics *metrics = task_metrics(prev);
	if (metrics && metrics->running_since_ns) {
		if (now >= metrics->running_since_ns)
			__sync_fetch_and_add(&metrics->runtime_ns, now - metrics->running_since_ns);
		metrics->running_since_ns = 0;
	}
	metrics = task_metrics(next);
	if (!metrics)
		return 0;
	metrics->cpu = bpf_get_smp_processor_id();
	metrics->last_running_at_ns = now;
	metrics->running_since_ns = now;
	__sync_fetch_and_add(&metrics->switches, 1);
	struct explore_task_key key = {};
	task_key(next, &key);
	struct explore_task_state *state = bpf_map_lookup_elem(&explore_task_states, &key);
	if (state) {
		if (state->wakeup_at_ns && now >= state->wakeup_at_ns) {
			record_histogram(&metrics->delay, now - state->wakeup_at_ns);
			record_aggregate_histogram(&explore_task_delay, now - state->wakeup_at_ns);
		}
		if (state->queued_at_ns && now >= state->queued_at_ns)
			record_histogram(&metrics->dsq_delay, now - state->queued_at_ns);
		bpf_map_delete_elem(&explore_task_states, &key);
	}
	return 0;
}

static __always_inline void task_wakeup(struct task_struct *p)
{
	struct explore_task_metrics *metrics = task_metrics(p);
	if (!metrics)
		return;
	__sync_fetch_and_add(&metrics->wakeups, 1);
	struct explore_task_key key = {};
	task_key(p, &key);
	struct explore_task_state *state = bpf_map_lookup_elem(&explore_task_states, &key);
	if (already_on_cpu(p)) {
		struct explore_health *h = health();
		if (h)
			h->task_running_wakeups++;
		if (state) {
			state->wakeup_at_ns = 0;
			if (!state->queued_at_ns)
				bpf_map_delete_elem(&explore_task_states, &key);
		}
		return;
	}
	if (!state) {
		struct explore_task_state empty = {};
		bpf_map_update_elem(&explore_task_states, &key, &empty, BPF_NOEXIST);
		state = bpf_map_lookup_elem(&explore_task_states, &key);
	}
	if (!state) {
		state_failure();
		return;
	}
	// Preserve the first successful wakeup if a runnable task is notified again.
	if (!state->wakeup_at_ns)
		state->wakeup_at_ns = bpf_ktime_get_ns();
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(ex_tasks_wakeup, struct task_struct *p) { task_wakeup(p); return 0; }
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(ex_tasks_wakeup_new, struct task_struct *p) { task_wakeup(p); return 0; }

SEC("tp_btf/sched_process_exit")
int BPF_PROG(ex_dsqs_exit, struct task_struct *p)
{
	struct explore_task_key key = {};
	task_key(p, &key);
	bpf_map_delete_elem(&explore_dsq_states, &key);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(ex_tasks_exit, struct task_struct *p)
{
	struct explore_task_key key = {};
	task_key(p, &key);
	bpf_map_delete_elem(&explore_task_states, &key);
	return 0;
}

static __always_inline struct explore_waker_metrics *waker_metrics(struct explore_pair_key *pair)
{
	struct explore_waker_metrics *result = bpf_map_lookup_elem(&explore_wakers, pair);
	if (!result) {
		u32 zero = 0;
		struct explore_waker_metrics *empty = bpf_map_lookup_elem(&explore_waker_zero, &zero);
		if (empty)
			bpf_map_update_elem(&explore_wakers, pair, empty, BPF_NOEXIST);
		result = bpf_map_lookup_elem(&explore_wakers, pair);
	}
	if (!result)
		tracking_failure();
	else if (!result->first_seen_ns)
		result->first_seen_ns = bpf_ktime_get_ns();
	return result;
}

static __always_inline void waker_origin(struct task_struct *p)
{
	if (!p)
		return;
	struct explore_health *h = health();
	if (h)
		h->waker_origins_seen++;
	if (!event_sampled())
		return;
	if (h)
		h->waker_origins_selected++;
	struct task_struct *waker = (struct task_struct *)bpf_get_current_task_btf();
	if (!waker)
		return;
	struct explore_task_key key = {};
	task_key(p, &key);
	struct explore_waker_state *state = bpf_map_lookup_elem(&explore_waker_states, &key);
	if (!state) {
		struct explore_waker_state empty = {};
		bpf_map_update_elem(&explore_waker_states, &key, &empty, BPF_NOEXIST);
		state = bpf_map_lookup_elem(&explore_waker_states, &key);
	}
	if (!state) {
		state_failure();
		return;
	}
	if (state->wakeup_at_ns)
		return;
	task_key(waker, &state->pair.waker);
	task_key(p, &state->pair.wakee);
	state->origin_at_ns = bpf_ktime_get_ns();
	state->wakeup_at_ns = 0;
	state->waker_cpu = bpf_get_smp_processor_id();
	state->waker_tgid = BPF_CORE_READ(waker, tgid);
	state->wakee_tgid = BPF_CORE_READ(p, tgid);
	bpf_probe_read_kernel_str(state->waker_comm, sizeof(state->waker_comm), waker->comm);
	bpf_probe_read_kernel_str(state->wakee_comm, sizeof(state->wakee_comm), p->comm);
}

static __always_inline void waker_success(struct task_struct *p)
{
	if (!p)
		return;
	struct explore_health *h = health();
	if (h)
		h->waker_wakeups_seen++;
	struct explore_task_key key = {};
	task_key(p, &key);
	if (already_on_cpu(p)) {
		if (h)
			h->waker_running_wakeups++;
		bpf_map_delete_elem(&explore_waker_states, &key);
		return;
	}
	struct explore_waker_state *state = bpf_map_lookup_elem(&explore_waker_states, &key);
	if (!state || !state->origin_at_ns) {
		if (h)
			h->waker_origins_missing++;
		return;
	}
	if (state->wakeup_at_ns)
		return;
	state->wakeup_at_ns = bpf_ktime_get_ns();
	if (h)
		h->waker_selected_wakeups++;
	struct explore_waker_metrics *metrics = waker_metrics(&state->pair);
	if (metrics) {
		metrics->waker_tgid = state->waker_tgid;
		metrics->wakee_tgid = state->wakee_tgid;
		__builtin_memcpy(metrics->waker_comm, state->waker_comm, sizeof(metrics->waker_comm));
		__builtin_memcpy(metrics->wakee_comm, state->wakee_comm, sizeof(metrics->wakee_comm));
		metrics->waker_cpu = state->waker_cpu;
		metrics->last_seen_ns = state->wakeup_at_ns;
		if (!metrics->first_seen_ns)
			metrics->first_seen_ns = state->wakeup_at_ns;
		__sync_fetch_and_add(&metrics->wakeups, 1);
	}
}

SEC("tp_btf/sched_waking")
int BPF_PROG(ex_wakers_waking, struct task_struct *p) { waker_origin(p); return 0; }
SEC("tp_btf/sched_wakeup")
int BPF_PROG(ex_wakers_wakeup, struct task_struct *p) { waker_success(p); return 0; }
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(ex_wakers_wakeup_new, struct task_struct *p) { waker_origin(p); waker_success(p); return 0; }
SEC("tp_btf/sched_switch")
int BPF_PROG(ex_wakers_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	struct explore_task_key key = {};
	task_key(next, &key);
	struct explore_waker_state *state = bpf_map_lookup_elem(&explore_waker_states, &key);
	if (!state)
		return 0;
	if (!state->wakeup_at_ns) {
		bpf_map_delete_elem(&explore_waker_states, &key);
		return 0;
	}
	u64 now = bpf_ktime_get_ns();
	struct explore_waker_metrics *metrics = waker_metrics(&state->pair);
	if (metrics && now >= state->wakeup_at_ns) {
		u32 target_cpu = bpf_get_smp_processor_id();
		metrics->waker_tgid = state->waker_tgid;
		metrics->wakee_tgid = state->wakee_tgid;
		__builtin_memcpy(metrics->waker_comm, state->waker_comm, sizeof(metrics->waker_comm));
		__builtin_memcpy(metrics->wakee_comm, state->wakee_comm, sizeof(metrics->wakee_comm));
		metrics->waker_cpu = state->waker_cpu;
		record_histogram(&metrics->latency, now - state->wakeup_at_ns);
		record_aggregate_histogram(&explore_waker_latency, now - state->wakeup_at_ns);
		struct explore_health *h = health();
		if (h)
			h->waker_matched_samples++;
		metrics->wakee_cpu = target_cpu;
		metrics->last_seen_ns = now;
		struct explore_topology_value *source = bpf_map_lookup_elem(&explore_topology, &state->waker_cpu);
		struct explore_topology_value *target = bpf_map_lookup_elem(&explore_topology, &target_cpu);
		if (target_cpu == state->waker_cpu)
			__sync_fetch_and_add(&metrics->same_cpu, 1);
		else if (!source || !target || !source->available || !target->available)
			__sync_fetch_and_add(&metrics->unknown_locality, 1);
		else if (source->node != target->node)
			__sync_fetch_and_add(&metrics->cross_numa, 1);
		else if (source->llc == target->llc)
			__sync_fetch_and_add(&metrics->same_llc, 1);
		else
			__sync_fetch_and_add(&metrics->cross_llc, 1);
	}
	bpf_map_delete_elem(&explore_waker_states, &key);
	return 0;
}

static __always_inline void record_ipi_target(u32 target_cpu)
{
	struct explore_ipi_key key = { .source_cpu = bpf_get_smp_processor_id(), .target_cpu = target_cpu };
	u64 *count = bpf_map_lookup_elem(&explore_ipis, &key);
	struct explore_health *h = health();
	if (h)
		h->ipi_targets++;
	if (!count) {
		u64 zero = 0;
		bpf_map_update_elem(&explore_ipis, &key, &zero, BPF_NOEXIST);
		count = bpf_map_lookup_elem(&explore_ipis, &key);
	}
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		tracking_failure();
}

SEC("tp_btf/ipi_send_cpu")
int BPF_PROG(ex_ipi_send_cpu, u32 cpu, void *callsite, void *callback)
{
	struct explore_health *h = health();
	if (h)
		h->ipi_send_cpu_events++;
	record_ipi_target(cpu);
	return 0;
}

struct explore_ipi_loop_context {
	const struct cpumask *mask;
	u32 cpu_limit;
	u32 base;
	u64 bits;
};

static long explore_ipi_loop_target(u32 index, void *data)
{
	struct explore_ipi_loop_context *context = data;
	u64 bits = context->bits;
	if (!bits)
		return 1;
	u32 bit = log2_u64(bits) - 1;
	record_ipi_target(context->base + bit);
	context->bits = bits & ~(1ULL << bit);
	return !context->bits;
}

static long explore_ipi_loop_word(u32 word, void *data)
{
	struct explore_ipi_loop_context *context = data;
	u32 base = word << 6;
	if (word >= EXPLORE_MAX_CPUS / 64 || base >= context->cpu_limit)
		return 1;
	u64 bits = 0;
	if (bpf_probe_read_kernel(&bits, sizeof(bits), &context->mask->bits[word])) {
		struct explore_health *h = health();
		if (h)
			h->ipi_mask_read_failures++;
		return 1;
	}
	u32 remaining = context->cpu_limit - base;
	if (remaining < 64)
		bits &= (1ULL << remaining) - 1;
	// The kernel bounds both loops. A manual 64-iteration target loop expands
	// the verifier's state space around each map update and log2 branch.
	context->base = base;
	context->bits = bits;
	if (bits && bpf_loop(64, explore_ipi_loop_target, context, 0) < 0) {
		struct explore_health *h = health();
		if (h)
			h->ipi_mask_read_failures++;
		return 1;
	}
	return 0;
}

SEC("tp_btf/ipi_send_cpumask")
int BPF_PROG(ex_ipi_send_cpumask, const struct cpumask *mask, void *callsite, void *callback)
{
	struct explore_health *h = health();
	if (h)
		h->ipi_send_cpumask_events++;
	u32 zero = 0;
	struct explore_config_value *config = bpf_map_lookup_elem(&explore_config, &zero);
	u32 limit = config ? config->cpu_limit : 0;
	if (!limit || limit > EXPLORE_MAX_CPUS)
		return 0;
	struct explore_ipi_loop_context context = { .mask = mask, .cpu_limit = limit };
	if (bpf_loop((limit + 63) / 64, explore_ipi_loop_word, &context, 0) < 0 && h)
		h->ipi_mask_read_failures++;
	return 0;
}

SEC("tp_btf/hw_pressure_update")
int BPF_PROG(ex_pressure_update, u32 cpu, u64 pressure)
{
	struct explore_pressure_value value = {
		.pressure = pressure,
		.updated_at_ns = bpf_ktime_get_ns(),
	};
	if (bpf_map_update_elem(&explore_pressure, &cpu, &value, BPF_ANY))
		tracking_failure();
	return 0;
}

SEC("syscall")
int ex_collect_scx_events(struct explore_scx_result *result)
{
	struct scx_event_stats events = {};
	if (!bpf_ksym_exists(scx_bpf_events))
		return -95;
	scx_bpf_events(&events, sizeof(events));
	result->supported_mask = 0;
#define SCX_COUNTER(index, field) \
	if (bpf_core_field_exists(events.field)) { \
		result->supported_mask |= 1ULL << index; \
		result->counts[index] = scx_read_event(&events, field); \
	}
	SCX_COUNTER(0, SCX_EV_SELECT_CPU_FALLBACK)
	SCX_COUNTER(1, SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE)
	SCX_COUNTER(2, SCX_EV_DISPATCH_KEEP_LAST)
	SCX_COUNTER(3, SCX_EV_ENQ_SKIP_EXITING)
	SCX_COUNTER(4, SCX_EV_ENQ_SKIP_MIGRATION_DISABLED)
	result->timestamp_ns = bpf_ktime_get_ns();
	return 0;
}
