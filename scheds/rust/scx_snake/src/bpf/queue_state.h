/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_STATE_H
#define __SCX_SNAKE_QUEUE_STATE_H

#include "bpf_common.h"
#include "task_state.h"

const volatile u32 queue_mode = SNAKE_QUEUE_MODE_NONE;
extern u32 queue_draining;

static __always_inline bool queue_transition_active(void)
{
	return READ_ONCE(queue_draining) != 0;
}

enum snake_queue_enqueue_gate {
	SNAKE_QUEUE_ENQUEUE_CLOSED = 0,
	SNAKE_QUEUE_ENQUEUE_OPEN,
	SNAKE_QUEUE_ENQUEUE_CLOSED_TRACKED,
};

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

struct snake_normal_queue_runtime {
	u32 nr_queued;
	u32 has_consumers;
	u32 cell_index;
	u32 cell_offset;
	u32 reserved[12];
};

struct snake_cell_queue_runtime {
	u32 llcs_to_drain;
	u32 reserved[15];
};

struct snake_affinity_queue_runtime {
	u32 nr_queued;
	u32 reserved[15];
};

_Static_assert(sizeof(struct snake_normal_queue_runtime) == 64,
	       "normal queue runtime must occupy one cacheline");
_Static_assert(sizeof(struct snake_cell_queue_runtime) == 64,
	       "cell queue runtime must occupy one cacheline");
_Static_assert(sizeof(struct snake_affinity_queue_runtime) == 64,
	       "affinity queue runtime must occupy one cacheline");

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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_normal_queue_runtime);
	__uint(max_entries, SNAKE_MAX_NORMAL_QUEUES);
} normal_queue_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_cell_queue_runtime);
	__uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
} cell_queue_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_affinity_queue_runtime);
	__uint(max_entries, SNAKE_MAX_CPUS);
} affinity_queue_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} queue_enqueue_inflight SEC(".maps");

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

static __always_inline const struct cpumask *
queue_cell_mask_slot(u32 slot, u32 cell_index, u32 kind)
{
	struct snake_queue_cell_masks *masks;
	u32 key;

	if (slot >= SNAKE_LADDER_SLOTS || cell_index >= SNAKE_MAX_QUEUE_CELLS)
		return NULL;
	key = queue_slot_index(slot, SNAKE_MAX_QUEUE_CELLS, cell_index);
	masks = bpf_map_lookup_elem(&queue_cell_masks, &key);
	if (!masks)
		return NULL;
	if (kind == SNAKE_QUEUE_MASK_PRIMARY)
		return (const struct cpumask *)masks->primary;
	if (kind == SNAKE_QUEUE_MASK_BORROWABLE)
		return (const struct cpumask *)masks->borrowable;
	return NULL;
}

static __always_inline void queue_kick_idle_cell_cpu(u32 slot, u32 cell_index)
{
	const struct cpumask *primary;
	s32 cpu = -ENOENT;

	bpf_rcu_read_lock();
	primary = queue_cell_mask_slot(slot, cell_index,
				       SNAKE_QUEUE_MASK_PRIMARY);
	if (primary) {
		cpu = scx_bpf_pick_idle_cpu(primary, SCX_PICK_IDLE_CORE);
		if (cpu < 0)
			cpu = scx_bpf_pick_idle_cpu(primary, 0);
		if (cpu >= 0)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
	bpf_rcu_read_unlock();
}

static __always_inline s32 queue_enqueue_inflight_gate(void)
{
	u32 key = 0;
	u32 *inflight;

	if (queue_transition_active())
		return SNAKE_QUEUE_ENQUEUE_CLOSED;
	inflight = bpf_map_lookup_elem(&queue_enqueue_inflight, &key);
	if (!inflight)
		return -ENOENT;
	__sync_fetch_and_add(inflight, 1);
	return queue_transition_active() ? SNAKE_QUEUE_ENQUEUE_CLOSED_TRACKED :
					   SNAKE_QUEUE_ENQUEUE_OPEN;
}

static __always_inline s32 queue_enqueue_inflight_exit(void)
{
	u32 key = 0;
	u32 *inflight = bpf_map_lookup_elem(&queue_enqueue_inflight, &key);
	u32 value;

	if (!inflight)
		return -ENOENT;
	value = __sync_fetch_and_sub(inflight, 1);
	if (!value) {
		__sync_fetch_and_add(inflight, 1);
		return -ERANGE;
	}
	return 0;
}

static __always_inline struct snake_normal_queue_runtime *
queue_normal_runtime(u32 queue_index)
{
	if (queue_index >= SNAKE_MAX_NORMAL_QUEUES)
		return NULL;
	return bpf_map_lookup_elem(&normal_queue_runtime, &queue_index);
}

static __always_inline struct snake_cell_queue_runtime *
queue_cell_runtime(u32 cell_index)
{
	if (cell_index >= SNAKE_MAX_QUEUE_CELLS)
		return NULL;
	return bpf_map_lookup_elem(&cell_queue_runtime, &cell_index);
}

static __always_inline struct snake_affinity_queue_runtime *
queue_affinity_runtime(u32 cpu)
{
	if (cpu >= SNAKE_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&affinity_queue_runtime, &cpu);
}

static __always_inline s32
queue_normal_drain_enable(struct snake_normal_queue_runtime *runtime)
{
	struct snake_cell_queue_runtime *cell_runtime;
	u32 cell_index, cell_offset;

	if (!runtime)
		return -EINVAL;
	cell_index = READ_ONCE(runtime->cell_index);
	cell_offset = READ_ONCE(runtime->cell_offset);
	if (cell_offset >= SNAKE_MAX_CELL_LLCS)
		return -EINVAL;
	cell_runtime = queue_cell_runtime(cell_index);
	if (!cell_runtime)
		return -EINVAL;
	__sync_or_and_fetch(&cell_runtime->llcs_to_drain, 1U << cell_offset);
	return 0;
}

static __always_inline s32
queue_normal_drain_disable(struct snake_normal_queue_runtime *runtime)
{
	struct snake_cell_queue_runtime *cell_runtime;
	u32 cell_index, cell_offset;

	if (!runtime)
		return -EINVAL;
	cell_index = READ_ONCE(runtime->cell_index);
	cell_offset = READ_ONCE(runtime->cell_offset);
	if (cell_offset >= SNAKE_MAX_CELL_LLCS)
		return -EINVAL;
	cell_runtime = queue_cell_runtime(cell_index);
	if (!cell_runtime)
		return -EINVAL;
	__sync_and_and_fetch(&cell_runtime->llcs_to_drain,
			     ~(1U << cell_offset));
	return 0;
}

static __always_inline int
queue_normal_account_enqueue(const struct snake_ladder_ctx *ctx,
			     u32 queue_index)
{
	struct snake_normal_queue_runtime *runtime;
	u32 cell_index;

	if (!queue_cell_mode_enabled())
		return 0;
	if (!ctx)
		return -EINVAL;
	runtime = queue_normal_runtime(queue_index);
	if (!runtime)
		return -ENOENT;
	__sync_fetch_and_add(&runtime->nr_queued, 1);
	if (READ_ONCE(runtime->has_consumers))
		return 0;
	if (queue_normal_drain_enable(runtime)) {
		__sync_fetch_and_sub(&runtime->nr_queued, 1);
		return -EINVAL;
	}
	cell_index = READ_ONCE(runtime->cell_index);
	queue_kick_idle_cell_cpu(ctx->slot, cell_index);
	return 0;
}

static __always_inline s32 queue_normal_account_dequeue(u32 queue_index)
{
	struct snake_normal_queue_runtime *runtime;
	u32 previous;

	if (!queue_cell_mode_enabled())
		return 0;
	runtime = queue_normal_runtime(queue_index);
	if (!runtime)
		return -ENOENT;
	previous = __sync_fetch_and_sub(&runtime->nr_queued, 1);
	if (!previous) {
		__sync_fetch_and_add(&runtime->nr_queued, 1);
		return -ERANGE;
	}
	return previous - 1;
}

static __always_inline s32 queue_affinity_account_enqueue(u32 cpu)
{
	struct snake_affinity_queue_runtime *runtime =
		queue_affinity_runtime(cpu);

	if (!runtime)
		return -ENOENT;
	__sync_fetch_and_add(&runtime->nr_queued, 1);
	return 0;
}

static __always_inline s32 queue_affinity_account_dequeue(u32 cpu)
{
	struct snake_affinity_queue_runtime *runtime =
		queue_affinity_runtime(cpu);
	u32 previous;

	if (!runtime)
		return -ENOENT;
	previous = __sync_fetch_and_sub(&runtime->nr_queued, 1);
	if (!previous) {
		__sync_fetch_and_add(&runtime->nr_queued, 1);
		return -ERANGE;
	}
	return previous - 1;
}

static __always_inline s32 queue_custom_account_dequeue(
	struct snake_task_runtime *runtime)
{
	u32 index, class;

	if (!runtime || !READ_ONCE(runtime->queued_dsq_accounted))
		return 0;
	index = READ_ONCE(runtime->queued_dsq_index);
	class = READ_ONCE(runtime->queued_dsq_class);
	WRITE_ONCE(runtime->queued_dsq_accounted, 0);
	if (class == SNAKE_QUEUE_CLASS_NORMAL)
		return queue_normal_account_dequeue(index);
	if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		return queue_affinity_account_dequeue(index);
	return -EINVAL;
}

static __noinline s32 queue_custom_account_enqueue(
	const struct snake_ladder_ctx *ctx, struct snake_task_runtime *runtime,
	u32 class, u32 index)
{
	s32 ret;

	if (!queue_cell_mode_enabled())
		return 0;
	if (!ctx || !runtime)
		return -EINVAL;
	if (READ_ONCE(runtime->queued_dsq_accounted)) {
		if (READ_ONCE(runtime->queued_dsq_class) == class &&
		    READ_ONCE(runtime->queued_dsq_index) == index)
			return 0;
		ret = queue_custom_account_dequeue(runtime);
		if (ret < 0)
			return ret;
	}
	if (class == SNAKE_QUEUE_CLASS_NORMAL)
		ret = queue_normal_account_enqueue(ctx, index);
	else if (class == SNAKE_QUEUE_CLASS_AFFINITY)
		ret = queue_affinity_account_enqueue(index);
	else
		return -EINVAL;
	if (ret < 0)
		return ret;
	WRITE_ONCE(runtime->queued_dsq_index, index);
	WRITE_ONCE(runtime->queued_dsq_class, class);
	WRITE_ONCE(runtime->queued_dsq_accounted, 1);
	return 0;
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

static __always_inline struct snake_normal_queue *
queue_normal_slot(u32 slot, u32 queue_index)
{
	struct snake_normal_queue *queue;
	u32 key;

	if (slot >= SNAKE_LADDER_SLOTS ||
	    queue_index >= SNAKE_MAX_NORMAL_QUEUES)
		return NULL;
	key = queue_slot_index(slot, SNAKE_MAX_NORMAL_QUEUES, queue_index);
	queue = bpf_map_lookup_elem(&normal_queues, &key);
	return queue && READ_ONCE(queue->valid) ? queue : NULL;
}

static __always_inline struct snake_normal_queue *
queue_normal(const struct snake_ladder_ctx *ctx, u32 queue_index)
{
	return ctx ? queue_normal_slot(ctx->slot, queue_index) : NULL;
}

static __always_inline struct snake_cpu_queue *
queue_cpu(const struct snake_ladder_ctx *ctx, u32 cpu)
{
	return ctx ? queue_cpu_slot(ctx->slot, cpu) : NULL;
}

static __always_inline const struct cpumask *
queue_cell_mask(const struct snake_ladder_ctx *ctx, u32 index, u32 kind)
{
	if (!ctx)
		return NULL;
	return queue_cell_mask_slot(ctx->slot, index, kind);
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
