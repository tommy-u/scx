/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MASK_TABLE_H
#define __SCX_SNAKE_MASK_TABLE_H

#include "main.h"

struct snake_mask_slot {
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

static __always_inline u32 mask_table_index(u32 slot, u32 table_id, u32 key)
{
	return slot * SNAKE_MAX_MASK_TABLES * SNAKE_MAX_CPUS +
	       table_id * SNAKE_MAX_CPUS + key;
}

static __always_inline int
mask_data_test_cpu(const struct snake_mask_data *data, u32 cpu, bool *set)
{
	u32	  byte_idx = cpu / 8;
	u32	  bit_idx  = cpu % 8;
	const u8 *byte;

	byte = MEMBER_VPTR(data->bits, [byte_idx]);
	if (!byte)
		return -EINVAL;

	*set = *byte & (1U << bit_idx);
	return 0;
}

static __always_inline int
build_mask_from_data(struct bpf_cpumask		  *mask,
		     const struct snake_mask_data *data)
{
	u32 cpu;

	bpf_cpumask_clear(mask);
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		bool set;

		if (mask_data_test_cpu(data, cpu, &set))
			return -EINVAL;
		if (!set)
			continue;
		if (cpu >= nr_cpu_ids)
			return -EINVAL;
		bpf_cpumask_set_cpu(cpu, mask);
	}

	return bpf_cpumask_empty((const struct cpumask *)mask) ? -EINVAL : 0;
}

/* Build every immutable cpumask needed by one fully staged ladder slot. */
static __always_inline int
prepare_mask_tables(u32 slot, const struct snake_compiled_ladder *ladder)
{
	u32 table_id, cpu;

	if (slot >= SNAKE_LADDER_SLOTS ||
	    ladder->nr_mask_tables > SNAKE_MAX_MASK_TABLES ||
	    nr_cpu_ids > SNAKE_MAX_CPUS)
		return -EINVAL;

	bpf_for(table_id, 0, SNAKE_MAX_MASK_TABLES)
	{
		if (table_id >= ladder->nr_mask_tables)
			break;

		bpf_for(cpu, 0, SNAKE_MAX_CPUS)
		{
			struct bpf_cpumask     *mask, *stale;
			struct snake_mask_data *data;
			struct snake_mask_slot *mask_slot;
			u32			index;

			index = mask_table_index(slot, table_id, cpu);
			data = bpf_map_lookup_elem(&mask_data, &index);
			mask_slot = bpf_map_lookup_elem(&mask_slots, &index);
			if (!data || !mask_slot)
				return -EINVAL;
			if (data->valid != 1) {
				stale = bpf_kptr_xchg(&mask_slot->mask, NULL);
				if (stale)
					bpf_cpumask_release(stale);
				continue;
			}

			mask = bpf_cpumask_create();
			if (!mask)
				return -ENOMEM;
			if (build_mask_from_data(mask, data)) {
				bpf_cpumask_release(mask);
				return -EINVAL;
			}

			stale = bpf_kptr_xchg(&mask_slot->mask, mask);
			if (stale)
				bpf_cpumask_release(stale);
		}
	}

	return 0;
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
			  const struct cpumask *eligible)
{
	struct bpf_cpumask     *table_mask;
	struct snake_mask_slot *slot;
	u32			index, offset, start;

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

	/* CPU-keyed tables rotate from the CPU; sparse cell IDs start at CPU zero. */
	start = key < nr_cpu_ids ? key : 0;
	bpf_for(offset, 0, SNAKE_MAX_CPUS)
	{
		u32 cpu;

		if (offset >= nr_cpu_ids)
			break;
		cpu = start + offset;
		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;
		if (!bpf_cpumask_test_cpu(cpu,
					  (const struct cpumask *)table_mask) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr) ||
		    !bpf_cpumask_test_cpu(cpu, eligible))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}

	return -ENOENT;
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

/* Pick from a table only when every SMT sibling of the CPU is idle. */
static __always_inline s32 pick_idle_core_from_mask_table(
	const struct snake_ladder_ctx *ctx, const struct task_struct *p, u32 table_id,
	s32 key)
{
	const struct cpumask *idle_smt;
	s32		      cpu;

	idle_smt = scx_bpf_get_idle_smtmask();
	if (!idle_smt)
		return -EINVAL;

	cpu = pick_idle_from_mask_table(ctx, p, table_id, key, idle_smt);
	scx_bpf_put_idle_cpumask(idle_smt);
	return cpu;
}

#endif /* __SCX_SNAKE_MASK_TABLE_H */
