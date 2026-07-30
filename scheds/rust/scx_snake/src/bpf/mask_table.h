/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MASK_TABLE_H
#define __SCX_SNAKE_MASK_TABLE_H

#include "policy_bank.h"

struct snake_mask_slot {
	struct bpf_cpumask __kptr *mask;
};

struct snake_mask_scratch {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_mask_data);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_MAX_MASK_TABLES *SNAKE_MAX_CPUS);
} mask_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_mask_slot);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_MAX_MASK_TABLES *SNAKE_MAX_CPUS);
} mask_slots		   SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_mask_scratch);
	__uint(max_entries, 1);
} mask_scratch SEC(".maps");

static __always_inline struct bpf_cpumask *mask_table_scratch(void)
{
	struct snake_mask_scratch *scratch;
	u32			   zero = 0;

	scratch = bpf_map_lookup_elem(&mask_scratch, &zero);
	return scratch ? scratch->mask : NULL;
}

static __always_inline u32 mask_table_index(u32 slot, u32 table_id, u32 key)
{
	return slot * SNAKE_MAX_MASK_TABLES * SNAKE_MAX_CPUS +
	       table_id * SNAKE_MAX_CPUS + key;
}

/* Return whether a sparse mask table has a materialized entry for this key. */
static __always_inline s32
mask_table_has_key(const struct snake_ladder_ctx *ctx, u32 table_id, u32 key)
{
	struct snake_mask_slot *slot;
	u32			index;

	if (table_id >= ctx->ladder->nr_mask_tables || key >= SNAKE_MAX_CPUS)
		return -EINVAL;
	index = mask_table_index(ctx->slot, table_id, key);
	slot  = bpf_map_lookup_elem(&mask_slots, &index);
	if (!slot)
		return -EINVAL;
	return slot->mask != NULL;
}

/* Test whether one CPU belongs to a CPU-keyed policy mask. */
static __always_inline s32
mask_table_contains(const struct snake_ladder_ctx *ctx, u32 table_id, s32 key,
		    s32 cpu)
{
	struct bpf_cpumask     *table_mask;
	struct snake_mask_slot *slot;
	u32			index;

	if (table_id >= ctx->ladder->nr_mask_tables || key < 0 ||
	    key >= nr_cpu_ids ||
	    cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	index = mask_table_index(ctx->slot, table_id, key);
	slot  = bpf_map_lookup_elem(&mask_slots, &index);
	if (!slot)
		return -EINVAL;
	table_mask = slot->mask;
	if (!table_mask)
		return -EINVAL;

	return bpf_cpumask_test_cpu(cpu, (const struct cpumask *)table_mask);
}

/* Test whether a CPU-keyed policy mask intersects a live kernel mask. */
static __always_inline s32
mask_table_intersects(const struct snake_ladder_ctx *ctx, u32 table_id, s32 key,
		      const struct cpumask *candidate)
{
	struct bpf_cpumask     *table_mask;
	struct snake_mask_slot *slot;
	u32			index;

	if (table_id >= ctx->ladder->nr_mask_tables || key < 0 ||
	    key >= nr_cpu_ids || !candidate)
		return -EINVAL;

	index = mask_table_index(ctx->slot, table_id, key);
	slot  = bpf_map_lookup_elem(&mask_slots, &index);
	if (!slot)
		return -EINVAL;
	table_mask = slot->mask;
	if (!table_mask)
		return -EINVAL;

	return bpf_cpumask_intersects((const struct cpumask *)table_mask,
				      candidate);
}

/* Pick from a table mask intersected with the task's dynamic affinity mask. */
static __always_inline s32
pick_idle_from_mask_table(const struct snake_ladder_ctx *ctx,
			  const struct task_struct *p, u32 table_id, s32 key,
			  bool whole_core)
{
	struct bpf_cpumask     *scratch;
	struct bpf_cpumask     *table_mask;
	struct snake_mask_slot *slot;
	u32			index;
	s32			cpu;

	if (table_id >= ctx->ladder->nr_mask_tables || key < 0 ||
	    key >= SNAKE_MAX_CPUS)
		return -EINVAL;

	index = mask_table_index(ctx->slot, table_id, key);
	slot  = bpf_map_lookup_elem(&mask_slots, &index);
	if (!slot)
		return -EINVAL;

	table_mask = slot->mask;
	if (!table_mask)
		return -EINVAL;

	scratch = mask_table_scratch();
	if (!scratch)
		return -EINVAL;
	if (!bpf_cpumask_and(scratch, (const struct cpumask *)table_mask,
			     p->cpus_ptr))
		return -ENOENT;

	cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)scratch,
				     whole_core ? SCX_PICK_IDLE_CORE : 0);
	return cpu < 0 ? -ENOENT : cpu;
}

/* Uniformly choose and claim an allowed idle CPU from a CPU-keyed table mask. */
static __always_inline s32
pick_random_idle_from_mask_table(const struct snake_ladder_ctx *ctx,
				 const struct task_struct *p, u32 table_id, s32 key,
				 bool whole_core)
{
	const struct cpumask   *idle;
	struct bpf_cpumask     *table_mask;
	struct snake_mask_slot *slot;
	u32			    candidates = 0, cpu, index;
	s32			    selected = -1;
	bool			    claimed;

	if (table_id >= ctx->ladder->nr_mask_tables || key < 0 ||
	    key >= SNAKE_MAX_CPUS)
		return -EINVAL;

	index = mask_table_index(ctx->slot, table_id, key);
	slot  = bpf_map_lookup_elem(&mask_slots, &index);
	if (!slot)
		return -EINVAL;
	table_mask = slot->mask;
	if (!table_mask)
		return -EINVAL;

	idle = whole_core ? scx_bpf_get_idle_smtmask() :
			    scx_bpf_get_idle_cpumask();
	if (!idle)
		return -EINVAL;

	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		if (bpf_cpumask_test_cpu(cpu,
					  (const struct cpumask *)table_mask) &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    bpf_cpumask_test_cpu(cpu, idle)) {
			candidates++;
			if (bpf_get_prandom_u32() % candidates == 0)
				selected = cpu;
		}
	}
	if (selected < 0) {
		scx_bpf_put_idle_cpumask(idle);
		return -ENOENT;
	}

	claimed = scx_bpf_test_and_clear_cpu_idle(selected);
	scx_bpf_put_idle_cpumask(idle);
	return claimed ? selected : -ENOENT;
}

#endif /* __SCX_SNAKE_MASK_TABLE_H */
