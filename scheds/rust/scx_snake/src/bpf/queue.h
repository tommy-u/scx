/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_H
#define __SCX_SNAKE_QUEUE_H

#define SNAKE_QUEUE_CLASS_NORMAL 0
#define SNAKE_QUEUE_CLASS_AFFINITY 1
#define SNAKE_SELECT_F_BORROWED (1ULL << 63)
#define SNAKE_QUEUE_CELL_NONE 0xffffffffU

struct snake_queue_cpu_state {
	u64 generation;
	u32 next_dispatch_rung;
	u32 initialized;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct snake_queue_cpu_state);
	__uint(max_entries, 1);
} queue_cpu_states SEC(".maps");

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

static __always_inline u64 queue_affinity_dsq(u32 cpu)
{
	return SNAKE_AFFINITY_DSQ_BASE + (u64)cpu;
}

static __always_inline u64 queue_normal_dsq(u32 queue_index)
{
	return SNAKE_NORMAL_DSQ_BASE + (u64)queue_index;
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

static __always_inline u32 queue_task_cell_index(struct task_struct *p)
{
	struct snake_queue_header *header = queue_config();
	struct snake_task_cell    *annotation;
	u32			   *encoded;
	u32			    cell_id, index;

	if (!header || !header->nr_cells)
		return 0;
	annotation = bpf_task_storage_get(&task_cells, p, NULL, 0);
	if (!annotation)
		return 0;
	cell_id = READ_ONCE(annotation->cell_id);
	if (cell_id >= SNAKE_MAX_CPUS)
		return 0;
	encoded = bpf_map_lookup_elem(&queue_cell_lookup, &cell_id);
	if (!encoded || !*encoded)
		return 0;
	index = *encoded - 1;
	return index < header->nr_cells ? index : 0;
}

static __always_inline bool
queue_mask_contains(const struct snake_mask_data *mask, u32 cpu)
{
	u32 byte, bit;

	if (!mask || !mask->valid || cpu >= SNAKE_MAX_CPUS)
		return false;
	byte = cpu / 8;
	bit  = cpu % 8;
	return mask->bits[byte] & (1U << bit);
}

static __always_inline bool
queue_primary_subset(const struct snake_queue_cell *cell,
		     const struct task_struct *p)
{
	u32 cpu;

	if (!cell || !cell->primary.valid)
		return false;
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		if (queue_mask_contains(&cell->primary, cpu) &&
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return false;
	}
	return true;
}

static __always_inline s32
queue_pick_primary_cpu(const struct snake_queue_cell *cell,
		       const struct task_struct *p, s32 preferred)
{
	u32 offset, start;

	if (preferred >= 0 && preferred < nr_cpu_ids &&
	    queue_mask_contains(&cell->primary, preferred) &&
	    bpf_cpumask_test_cpu(preferred, p->cpus_ptr))
		return preferred;
	start = bpf_get_prandom_u32() % nr_cpu_ids;
	bpf_for(offset, 0, SNAKE_MAX_CPUS)
	{
		u32 cpu;

		if (offset >= nr_cpu_ids)
			break;
		cpu = (start + offset) % nr_cpu_ids;
		if (queue_mask_contains(&cell->primary, cpu) &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}
	return -ENOENT;
}

static __always_inline s32
queue_pick_allowed_cpu(const struct task_struct *p, s32 preferred)
{
	u32 offset, start;

	if (preferred >= 0 && preferred < nr_cpu_ids && queue_cpu(preferred) &&
	    bpf_cpumask_test_cpu(preferred, p->cpus_ptr))
		return preferred;
	start = bpf_get_prandom_u32() % nr_cpu_ids;
	bpf_for(offset, 0, SNAKE_MAX_CPUS)
	{
		u32 cpu;

		if (offset >= nr_cpu_ids)
			break;
		cpu = (start + offset) % nr_cpu_ids;
		if (queue_cpu(cpu) && bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}
	return -ENOENT;
}

static __always_inline int
queue_build_cpumask(struct bpf_cpumask *mask,
		    const struct snake_mask_data *data)
{
	u32 cpu;

	if (!mask || !data || !data->valid)
		return -EINVAL;
	bpf_cpumask_clear(mask);
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		bool set;

		if (cpu >= nr_cpu_ids)
			break;
		set = queue_mask_contains(data, cpu);
		if (set)
			bpf_cpumask_set_cpu(cpu, mask);
	}
	return 0;
}

static __always_inline int queue_init_cell_masks(void)
{
	struct snake_queue_header *header = queue_config();
	u32 i;

	if (!header || header->layout == SNAKE_QUEUE_LAYOUT_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_queue_cell *cell;
		struct snake_queue_cell_masks *slot;
		struct bpf_cpumask *primary, *borrowable, *stale;

		if (i >= header->nr_cells)
			break;
		cell = queue_cell(i);
		slot = bpf_map_lookup_elem(&queue_cell_masks, &i);
		if (!cell || !slot)
			return -EINVAL;
		primary = bpf_cpumask_create();
		if (!primary)
			return -ENOMEM;
		if (queue_build_cpumask(primary, &cell->primary)) {
			bpf_cpumask_release(primary);
			return -EINVAL;
		}
		stale = bpf_kptr_xchg(&slot->primary, primary);
		if (stale) {
			bpf_cpumask_release(stale);
			return -EINVAL;
		}

		borrowable = bpf_cpumask_create();
		if (!borrowable)
			return -ENOMEM;
		if (queue_build_cpumask(borrowable, &cell->borrowable)) {
			bpf_cpumask_release(borrowable);
			return -EINVAL;
		}
		stale = bpf_kptr_xchg(&slot->borrowable, borrowable);
		if (stale) {
			bpf_cpumask_release(stale);
			return -EINVAL;
		}
	}
	return 0;
}

static __always_inline const struct cpumask *
queue_cell_mask(u32 index, u32 kind)
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

static __always_inline int validate_queue_topology(void)
{
	struct snake_queue_header *header = queue_config();
	u32			    i;

	if (!header)
		return -EINVAL;
	if (header->layout == SNAKE_QUEUE_LAYOUT_NONE)
		return 0;
	if (header->layout != SNAKE_QUEUE_LAYOUT_CELL &&
	    header->layout != SNAKE_QUEUE_LAYOUT_CELL_LLC)
		return -EINVAL;
	if (!header->nr_cells || header->nr_cells > SNAKE_MAX_QUEUE_CELLS ||
	    !header->nr_normal_queues ||
	    header->nr_normal_queues > SNAKE_MAX_NORMAL_QUEUES ||
	    !header->nr_cpus || header->nr_cpus > nr_cpu_ids ||
	    nr_cpu_ids > SNAKE_MAX_CPUS)
		return -EINVAL;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_queue_cell *cell;

		if (i >= header->nr_cells)
			break;
		cell = bpf_map_lookup_elem(&queue_cells, &i);
		if (!cell || !cell->valid || cell->clock_index != i ||
		    !cell->cpu_weight || !cell->primary.valid ||
		    !cell->nr_normal_queues ||
		    cell->first_normal_queue >= header->nr_normal_queues ||
		    cell->nr_normal_queues >
			    header->nr_normal_queues - cell->first_normal_queue)
			return -EINVAL;
	}
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_normal_queue *queue;

		if (i >= header->nr_normal_queues)
			break;
		queue = bpf_map_lookup_elem(&normal_queues, &i);
		if (!queue || !queue->valid ||
		    queue->cell_index >= header->nr_cells ||
		    queue->clock_index != queue->cell_index ||
		    queue->consumer_cpu >= nr_cpu_ids ||
		    !queue_cpu(queue->consumer_cpu))
			return -EINVAL;
		if (header->layout == SNAKE_QUEUE_LAYOUT_CELL &&
		    queue->llc_id != SNAKE_QUEUE_LLC_NONE)
			return -EINVAL;
		if (header->layout == SNAKE_QUEUE_LAYOUT_CELL_LLC &&
		    queue->llc_id == SNAKE_QUEUE_LLC_NONE)
			return -EINVAL;
	}
	{
		u32 configured = 0;

	bpf_for(i, 0, SNAKE_MAX_CPUS)
	{
		struct snake_cpu_queue *cpuq;
		struct snake_normal_queue *normal;

		if (i >= nr_cpu_ids)
			break;
		cpuq = bpf_map_lookup_elem(&cpu_queues, &i);
		if (!cpuq)
			return -EINVAL;
		if (!cpuq->valid)
			continue;
		configured++;
		if (cpuq->owner_cell_index >= header->nr_cells ||
		    cpuq->normal_queue_index >= header->nr_normal_queues)
			return -EINVAL;
		normal = bpf_map_lookup_elem(&normal_queues,
					     &cpuq->normal_queue_index);
		if (!normal || normal->cell_index != cpuq->owner_cell_index)
			return -EINVAL;
	}
	if (configured != header->nr_cpus)
		return -EINVAL;
	}
	return 0;
}

static __always_inline int create_queue_topology_dsqs(void)
{
	struct snake_queue_header *header = queue_config();
	u32			    i;
	int			    ret;

	if (!header || header->layout == SNAKE_QUEUE_LAYOUT_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_CPUS)
	{
		if (i >= nr_cpu_ids)
			break;
		if (!queue_cpu(i))
			continue;
		ret = scx_bpf_create_dsq(queue_affinity_dsq(i), -1);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		if (i >= header->nr_normal_queues)
			break;
		ret = scx_bpf_create_dsq(queue_normal_dsq(i), -1);
		if (ret)
			return ret;
	}
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_H */
