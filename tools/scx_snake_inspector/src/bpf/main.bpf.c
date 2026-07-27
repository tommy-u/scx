// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>

#include "intf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

const volatile u64 ext_sched_class_addr;

extern long bpf_task_under_cgroup(struct task_struct *task,
				  struct cgroup *ancestor) __weak __ksym;

struct task_cpu_state {
	u32 cpu;
	u32 generation;
	u32 valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_cpu_state);
} task_cpu_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct migration_key);
	__type(value, u64);
} migration_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u8);
} tracked_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct collector_config);
} collector_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_COLLECTOR_STATS);
	__type(key, u32);
	__type(value, u64);
} collector_stats SEC(".maps");

static __always_inline void stat_inc(enum collector_stat_id stat)
{
	u32 key = stat;
	u64 *value = bpf_map_lookup_elem(&collector_stats, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline void mark_untracked(struct task_struct *task)
{
	struct task_cpu_state *state;

	state = bpf_task_storage_get(&task_cpu_states, task, 0, 0);
	if (state)
		state->valid = 0;
}

static __always_inline bool task_matches_scope(
	struct task_struct *task, const struct collector_config *cfg)
{
	struct cgroup *ancestor;
	bool matches;
	u32 tgid;
	u8 *tracked;

	switch (cfg->scope_kind) {
	case TASK_SCOPE_ALL:
		return true;
	case TASK_SCOPE_TGID:
		tgid = BPF_CORE_READ(task, tgid);
		tracked = bpf_map_lookup_elem(&tracked_tgids, &tgid);
		return tracked != NULL;
	case TASK_SCOPE_CGROUP:
		if (!cfg->cgroup_id || !bpf_ksym_exists(bpf_task_under_cgroup))
			return false;
		ancestor = bpf_cgroup_from_id(cfg->cgroup_id);
		if (!ancestor)
			return false;
		matches = bpf_task_under_cgroup(task, ancestor) == 1;
		bpf_cgroup_release(ancestor);
		return matches;
	default:
		return false;
	}
}

static __always_inline void count_transition(u32 from_cpu, u32 to_cpu)
{
	struct migration_key key = {
		.from_cpu = from_cpu,
		.to_cpu = to_cpu,
	};
	u64 initial = 1;
	u64 *count;

	count = bpf_map_lookup_elem(&migration_counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return;
	}

	if (bpf_map_update_elem(&migration_counts, &key, &initial,
				BPF_NOEXIST) == 0)
		return;

	/* Another CPU may have inserted the pair between lookup and update. */
	count = bpf_map_lookup_elem(&migration_counts, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		stat_inc(COLLECTOR_STAT_PAIR_MAP_FAILURE);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	struct task_cpu_state *state;
	struct collector_config *cfg;
	const struct sched_class *sched_class;
	u32 key = 0;
	u32 cpu;

	(void)preempt;
	(void)prev;
	(void)prev_state;

	cfg = bpf_map_lookup_elem(&collector_cfg, &key);
	if (!cfg || !cfg->enabled || !next)
		return 0;

	sched_class = BPF_CORE_READ(next, sched_class);
	if (!ext_sched_class_addr || (u64)sched_class != ext_sched_class_addr) {
		mark_untracked(next);
		return 0;
	}

	if (!task_matches_scope(next, cfg)) {
		mark_untracked(next);
		return 0;
	}

	state = bpf_task_storage_get(&task_cpu_states, next, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!state) {
		stat_inc(COLLECTOR_STAT_TASK_STORAGE_FAILURE);
		return 0;
	}

	cpu = bpf_get_smp_processor_id();
	if (state->valid && state->generation == cfg->generation &&
	    state->cpu != cpu)
		count_transition(state->cpu, cpu);

	state->cpu = cpu;
	state->generation = cfg->generation;
	state->valid = 1;
	return 0;
}
