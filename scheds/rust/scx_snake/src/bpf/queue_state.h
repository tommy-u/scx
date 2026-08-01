/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_STATE_H
#define __SCX_SNAKE_QUEUE_STATE_H

#include "bpf_common.h"

const volatile u32 queue_mode = SNAKE_QUEUE_MODE_NONE;
extern u32 queue_draining;

static __always_inline bool queue_transition_active(void)
{
	return READ_ONCE(queue_draining) != 0;
}

struct snake_queue_cpu_state {
	u64 generation;
	u32 next_dispatch_rung;
	u32 next_equal_class;
	u32 next_remote_queue;
	u32 next_equal_source;
	u32 initialized;
};

struct snake_queue_cell_masks {
	struct bpf_cpumask __kptr *primary;
	struct bpf_cpumask __kptr *borrowable;
};

struct snake_normal_queue_masks {
	struct bpf_cpumask __kptr *consumers;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_header);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
} queue_header SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_CPUS);
} queue_cell_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS);
} queue_cells SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_NORMAL_QUEUES);
} normal_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_cpu_queue);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_CPUS);
} cpu_queues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cell_masks);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS);
} queue_cell_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue_masks);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_NORMAL_QUEUES);
} normal_queue_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cpu_state);
	__uint(max_entries, 1);
} queue_cpu_states				  SEC(".maps");

static __always_inline u32 queue_slot_index(u32 slot, u32 width, u32 index)
{
	return slot * width + index;
}

static __always_inline struct snake_queue_header *queue_config_slot(u32 slot)
{
	u32 key = slot;

	if (slot >= SNAKE_LADDER_SLOTS)
		return NULL;
	return bpf_map_lookup_elem(&queue_header, &key);
}

static __always_inline struct snake_queue_header *
queue_config(const struct snake_ladder_ctx *ctx)
{
	return ctx ? queue_config_slot(ctx->slot) : NULL;
}

static __always_inline bool queue_topology_enabled(void)
{
	return queue_mode != SNAKE_QUEUE_MODE_NONE;
}

static __always_inline bool queue_global_mode_enabled(void)
{
	return queue_mode == SNAKE_QUEUE_MODE_GLOBAL;
}

static __always_inline bool queue_cell_mode_enabled(void)
{
	return queue_mode == SNAKE_QUEUE_MODE_CELL;
}

static __always_inline struct snake_queue_cell *
queue_cell_slot(u32 slot, u32 cell_index)
{
	struct snake_queue_header *header = queue_config_slot(slot);
	u32 key;

	if (!header || cell_index >= header->nr_cells)
		return NULL;
	key = queue_slot_index(slot, SNAKE_MAX_QUEUE_CELLS, cell_index);
	return bpf_map_lookup_elem(&queue_cells, &key);
}

static __always_inline struct snake_queue_cell *
queue_cell(const struct snake_ladder_ctx *ctx, u32 cell_index)
{
	return ctx ? queue_cell_slot(ctx->slot, cell_index) : NULL;
}

static __always_inline struct snake_cpu_queue *queue_cpu_slot(u32 slot, u32 cpu)
{
	struct snake_cpu_queue *cpuq;
	u32 key;

	if (slot >= SNAKE_LADDER_SLOTS || cpu >= nr_cpu_ids)
		return NULL;
	key = queue_slot_index(slot, SNAKE_MAX_CPUS, cpu);
	cpuq = bpf_map_lookup_elem(&cpu_queues, &key);
	return cpuq && READ_ONCE(cpuq->valid) ? cpuq : NULL;
}

static __always_inline struct snake_cpu_queue *
queue_cpu(const struct snake_ladder_ctx *ctx, u32 cpu)
{
	return ctx ? queue_cpu_slot(ctx->slot, cpu) : NULL;
}

static __always_inline const struct cpumask *
queue_cell_mask(const struct snake_ladder_ctx *ctx, u32 index, u32 kind)
{
	struct snake_queue_cell_masks *slot;
	u32 key;

	if (!ctx || ctx->slot >= SNAKE_LADDER_SLOTS ||
	    index >= SNAKE_MAX_QUEUE_CELLS)
		return NULL;
	key = queue_slot_index(ctx->slot, SNAKE_MAX_QUEUE_CELLS, index);
	slot = bpf_map_lookup_elem(&queue_cell_masks, &key);
	if (!slot)
		return NULL;
	if (kind == SNAKE_QUEUE_MASK_PRIMARY)
		return (const struct cpumask *)slot->primary;
	if (kind == SNAKE_QUEUE_MASK_BORROWABLE)
		return (const struct cpumask *)slot->borrowable;
	return NULL;
}

static __always_inline const struct cpumask *
queue_normal_consumers(const struct snake_ladder_ctx *ctx, u32 index)
{
	struct snake_normal_queue_masks *slot;
	u32 key;

	if (!ctx || ctx->slot >= SNAKE_LADDER_SLOTS ||
	    index >= SNAKE_MAX_NORMAL_QUEUES)
		return NULL;
	key = queue_slot_index(ctx->slot, SNAKE_MAX_NORMAL_QUEUES, index);
	slot = bpf_map_lookup_elem(&normal_queue_masks, &key);
	return slot ? (const struct cpumask *)slot->consumers : NULL;
}

#endif /* __SCX_SNAKE_QUEUE_STATE_H */
