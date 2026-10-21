/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MITOSIS_MIGRATION_OBSERVER_BPF_H
#define __MITOSIS_MIGRATION_OBSERVER_BPF_H

/* Shared by the tracepoint and a native test of insertion races. */
static __always_inline void observe_migration(int orig_cpu, int dest_cpu)
{
	struct mitosis_cpu_pair pair;
	u64			initial = 1, *count;
	u32			zero	= 0;

	if (orig_cpu < 0 || dest_cpu < 0 || orig_cpu == dest_cpu)
		return;
	pair.from_cpu = orig_cpu;
	pair.to_cpu   = dest_cpu;
	count	      = bpf_map_lookup_elem(&migration_counts, &pair);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return;
	}
	if (!bpf_map_update_elem(&migration_counts, &pair, &initial,
				 BPF_NOEXIST))
		return;
	/* Another CPU may have inserted this pair after the first lookup. */
	count = bpf_map_lookup_elem(&migration_counts, &pair);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return;
	}
	count = bpf_map_lookup_elem(&migration_failures, &zero);
	if (count)
		(*count)++;
}

#endif
