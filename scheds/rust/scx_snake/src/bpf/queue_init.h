/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_INIT_H
#define __SCX_SNAKE_QUEUE_INIT_H

#include "queue.h"
#include "dsq.h"

static __always_inline int
queue_build_cpumask(struct bpf_cpumask		 *mask,
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
	u32			   i;

	if (!header || header->layout == SNAKE_QUEUE_LAYOUT_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_queue_cell	      *cell;
		struct snake_queue_cell_masks *slot;
		struct bpf_cpumask	      *primary, *borrowable, *stale;

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

static __always_inline int validate_queue_topology(void)
{
	struct snake_queue_header *header = queue_config();
	u32			   i;

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
			struct snake_cpu_queue	  *cpuq;
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
			    cpuq->normal_queue_index >=
				    header->nr_normal_queues)
				return -EINVAL;
			normal = bpf_map_lookup_elem(&normal_queues,
						     &cpuq->normal_queue_index);
			if (!normal ||
			    normal->cell_index != cpuq->owner_cell_index)
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
	u32			   i;
	int			   ret;

	if (!header || header->layout == SNAKE_QUEUE_LAYOUT_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_CPUS)
	{
		if (i >= nr_cpu_ids)
			break;
		if (!queue_cpu(i))
			continue;
		ret = dsq_create(dsq_affinity(i), -1);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		if (i >= header->nr_normal_queues)
			break;
		ret = dsq_create(dsq_normal(i), -1);
		if (ret)
			return ret;
	}
	return 0;
}

#endif /* __SCX_SNAKE_QUEUE_INIT_H */
