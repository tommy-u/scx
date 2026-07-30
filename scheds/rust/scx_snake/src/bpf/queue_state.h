/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_STATE_H
#define __SCX_SNAKE_QUEUE_STATE_H

#include "bpf_common.h"

struct snake_queue_cpu_state {
	u64 generation;
	u32 next_dispatch_rung;
	u32 next_equal_class;
	u32 initialized;
};

struct snake_queue_cell_masks {
	struct bpf_cpumask __kptr *primary;
	struct bpf_cpumask __kptr *borrowable;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_header);
	__uint(max_entries, 1);
} queue_header SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_MAX_CPUS);
} queue_cell_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cells SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue);
	__uint(max_entries, SNAKE_MAX_NORMAL_QUEUES);
} normal_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_cpu_queue);
	__uint(max_entries, SNAKE_MAX_CPUS);
} cpu_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell_masks);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} queue_cell_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cpu_state);
	__uint(max_entries, 1);
} queue_cpu_states				  SEC(".maps");

static __always_inline struct snake_queue_header *queue_config(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&queue_header, &key);
}

static __always_inline bool queue_topology_enabled(void)
{
	struct snake_queue_header *header = queue_config();

	return header && READ_ONCE(header->layout) != SNAKE_QUEUE_LAYOUT_NONE;
}

static __always_inline struct snake_queue_cell *queue_cell(u32 cell_index)
{
	struct snake_queue_header *header = queue_config();

	if (!header || cell_index >= header->nr_cells)
		return NULL;
	return bpf_map_lookup_elem(&queue_cells, &cell_index);
}

static __always_inline struct snake_cpu_queue *queue_cpu(u32 cpu)
{
	struct snake_cpu_queue *cpuq;

	if (cpu >= nr_cpu_ids)
		return NULL;
	cpuq = bpf_map_lookup_elem(&cpu_queues, &cpu);
	return cpuq && READ_ONCE(cpuq->valid) ? cpuq : NULL;
}

static __always_inline const struct cpumask *queue_cell_mask(u32 index,
							     u32 kind)
{
	struct snake_queue_cell_masks *slot;

	slot = bpf_map_lookup_elem(&queue_cell_masks, &index);
	if (!slot)
		return NULL;
	if (kind == SNAKE_QUEUE_MASK_PRIMARY)
		return (const struct cpumask *)slot->primary;
	if (kind == SNAKE_QUEUE_MASK_BORROWABLE)
		return (const struct cpumask *)slot->borrowable;
	return NULL;
}

#endif /* __SCX_SNAKE_QUEUE_STATE_H */
