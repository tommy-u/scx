/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MASK_TABLE_INIT_H
#define __SCX_SNAKE_MASK_TABLE_INIT_H

#include "mask_table.h"

static __always_inline int init_mask_table_scratch(void)
{
	u32 zero = 0, cpu;

	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		struct snake_mask_scratch *scratch;
		struct bpf_cpumask	  *mask, *stale;

		if (cpu >= nr_cpu_ids)
			break;
		scratch = bpf_map_lookup_percpu_elem(&mask_scratch, &zero, cpu);
		if (!scratch)
			return -EINVAL;
		mask = bpf_cpumask_create();
		if (!mask)
			return -ENOMEM;
		stale = bpf_kptr_xchg(&scratch->mask, mask);
		if (stale)
			bpf_cpumask_release(stale);
	}

	return 0;
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
		bpf_for(cpu, 0, SNAKE_MAX_CPUS)
		{
			struct bpf_cpumask     *mask, *stale;
			struct snake_mask_data *data;
			struct snake_mask_slot *mask_slot;
			u32			index;

			index	  = mask_table_index(slot, table_id, cpu);
			data	  = bpf_map_lookup_elem(&mask_data, &index);
			mask_slot = bpf_map_lookup_elem(&mask_slots, &index);
			if (!data || !mask_slot)
				return -EINVAL;
			if (table_id >= ladder->nr_mask_tables ||
			    data->valid != 1) {
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

#endif /* __SCX_SNAKE_MASK_TABLE_INIT_H */
