/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_QUEUE_INIT_H
#define __SCX_SNAKE_QUEUE_INIT_H

#include "queue.h"
#include "dsq.h"

extern u32 queue_topology_prepare_stage;
extern s32 queue_topology_prepare_error;
extern u32 queue_topology_prepare_detail;

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

static __always_inline int queue_init_cell_masks(u32 bank)
{
	struct snake_queue_header *header = queue_config_slot(bank);
	u32			   i;

	if (!header || header->mode != SNAKE_QUEUE_MODE_CELL)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_queue_cell	      *cell;
		struct snake_queue_cell_masks *slot;
		struct bpf_cpumask	      *primary, *borrowable, *stale;
		u32			       key;

		if (i >= header->nr_cells)
			break;
		cell = queue_cell_slot(bank, i);
		key = queue_slot_index(bank, SNAKE_MAX_QUEUE_CELLS, i);
		slot = bpf_map_lookup_elem(&queue_cell_masks, &key);
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
		if (stale)
			bpf_cpumask_release(stale);

		borrowable = bpf_cpumask_create();
		if (!borrowable)
			return -ENOMEM;
		if (queue_build_cpumask(borrowable, &cell->borrowable)) {
			bpf_cpumask_release(borrowable);
			return -EINVAL;
		}
		stale = bpf_kptr_xchg(&slot->borrowable, borrowable);
		if (stale)
			bpf_cpumask_release(stale);
	}
	return 0;
}

static __always_inline int queue_init_normal_masks(u32 bank)
{
	struct snake_queue_header *header = queue_config_slot(bank);
	u32 i;

	if (!header || header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_normal_queue       *queue;
		struct snake_normal_queue_masks *slot;
		struct bpf_cpumask	       *consumers, *stale;
		u32				key;

		if (i >= header->nr_normal_queues)
			break;
		key = queue_slot_index(bank, SNAKE_MAX_NORMAL_QUEUES, i);
		queue = bpf_map_lookup_elem(&normal_queues, &key);
		slot = bpf_map_lookup_elem(&normal_queue_masks, &key);
		if (!queue || !slot)
			return -EINVAL;
		consumers = bpf_cpumask_create();
		if (!consumers)
			return -ENOMEM;
		if (queue_build_cpumask(consumers, &queue->consumers)) {
			bpf_cpumask_release(consumers);
			return -EINVAL;
		}
		stale = bpf_kptr_xchg(&slot->consumers, consumers);
		if (stale)
			bpf_cpumask_release(stale);
	}
	return 0;
}

static __always_inline int validate_queue_topology(u32 bank)
{
	struct snake_queue_header *header = queue_config_slot(bank);
	u32			   i;

	if (!header) {
		WRITE_ONCE(queue_topology_prepare_detail, 1);
		return -EINVAL;
	}
	if (header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	if (header->mode != SNAKE_QUEUE_MODE_GLOBAL &&
	    header->mode != SNAKE_QUEUE_MODE_CELL) {
		WRITE_ONCE(queue_topology_prepare_detail, 2);
		return -EINVAL;
	}
	if (header->nr_cells > SNAKE_MAX_QUEUE_CELLS) {
		WRITE_ONCE(queue_topology_prepare_detail, 3);
		return -EINVAL;
	}
	if (header->mode == SNAKE_QUEUE_MODE_CELL && !header->nr_cells) {
		WRITE_ONCE(queue_topology_prepare_detail, 4);
		return -EINVAL;
	}
	if (header->mode == SNAKE_QUEUE_MODE_GLOBAL && header->nr_cells) {
		WRITE_ONCE(queue_topology_prepare_detail, 5);
		return -EINVAL;
	}
	if (!header->nr_normal_queues ||
	    header->nr_normal_queues > SNAKE_MAX_NORMAL_QUEUES) {
		WRITE_ONCE(queue_topology_prepare_detail, 6);
		return -EINVAL;
	}
	if (!header->nr_cpus || header->nr_cpus > nr_cpu_ids ||
	    nr_cpu_ids > SNAKE_MAX_CPUS) {
		WRITE_ONCE(queue_topology_prepare_detail, 7);
		return -EINVAL;
	}

	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_queue_cell *cell;

		if (i >= header->nr_cells)
			break;
		cell = queue_cell_slot(bank, i);
		if (!cell) {
			WRITE_ONCE(queue_topology_prepare_detail, 10000 + i * 10);
			return -EINVAL;
		}
		if (!cell->valid || cell->clock_index != i ||
		    !cell->cpu_weight || !cell->primary.valid ||
		    !cell->nr_normal_queues ||
		    cell->first_normal_queue >= header->nr_normal_queues ||
		    cell->nr_normal_queues >
			    header->nr_normal_queues - cell->first_normal_queue) {
			WRITE_ONCE(queue_topology_prepare_detail, 10001 + i * 10);
			return -EINVAL;
		}
	}
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_normal_queue *queue;
		u32			  key;

		if (i >= header->nr_normal_queues)
			break;
		key = queue_slot_index(bank, SNAKE_MAX_NORMAL_QUEUES, i);
		queue = bpf_map_lookup_elem(&normal_queues, &key);
		if (!queue || !queue->valid || !queue->consumers.valid ||
		    queue->consumer_cpu >= nr_cpu_ids ||
		    !queue_cpu_slot(bank, queue->consumer_cpu)) {
			WRITE_ONCE(queue_topology_prepare_detail, 20001 + i * 10);
			return -EINVAL;
		}
		if (header->mode == SNAKE_QUEUE_MODE_CELL &&
		    (queue->cell_index >= header->nr_cells ||
		     queue->clock_index != queue->cell_index)) {
			WRITE_ONCE(queue_topology_prepare_detail, 20002 + i * 10);
			return -EINVAL;
		}
		if (header->mode == SNAKE_QUEUE_MODE_GLOBAL &&
		    (queue->cell_index != SNAKE_QUEUE_CELL_NONE ||
		     queue->clock_index != SNAKE_QUEUE_CELL_NONE)) {
			WRITE_ONCE(queue_topology_prepare_detail, 20003 + i * 10);
			return -EINVAL;
		}
	}
	{
		u32 configured = 0;

		bpf_for(i, 0, SNAKE_MAX_CPUS)
		{
			struct snake_cpu_queue	  *cpuq;
			struct snake_normal_queue *normal;
			u32			   cpu_key, normal_key;

			if (i >= nr_cpu_ids)
				break;
			cpu_key = queue_slot_index(bank, SNAKE_MAX_CPUS, i);
			cpuq = bpf_map_lookup_elem(&cpu_queues, &cpu_key);
			if (!cpuq) {
				WRITE_ONCE(queue_topology_prepare_detail,
					   30001 + i * 10);
				return -EINVAL;
			}
			if (!cpuq->valid)
				continue;
			configured++;
			if (cpuq->normal_queue_index >=
				    header->nr_normal_queues) {
				WRITE_ONCE(queue_topology_prepare_detail,
					   30002 + i * 10);
				return -EINVAL;
			}
			normal_key = queue_slot_index(
				bank, SNAKE_MAX_NORMAL_QUEUES,
				cpuq->normal_queue_index);
			normal = bpf_map_lookup_elem(&normal_queues, &normal_key);
			if (!normal ||
			    (header->mode == SNAKE_QUEUE_MODE_CELL &&
			     (cpuq->owner_cell_index >= header->nr_cells ||
			      normal->cell_index != cpuq->owner_cell_index)) ||
			    (header->mode == SNAKE_QUEUE_MODE_GLOBAL &&
			     cpuq->owner_cell_index != SNAKE_QUEUE_CELL_NONE)) {
				WRITE_ONCE(queue_topology_prepare_detail,
					   30003 + i * 10);
				return -EINVAL;
			}
		}
		if (configured != header->nr_cpus) {
			WRITE_ONCE(queue_topology_prepare_detail, 40000 + configured);
			return -EINVAL;
		}
	}
	WRITE_ONCE(queue_topology_prepare_detail, 0);
	return 0;
}

static __always_inline int create_queue_topology_dsqs(u32 bank)
{
	struct snake_queue_header *header = queue_config_slot(bank);
	u32			   i;
	int			   ret;

	if (!header || header->mode == SNAKE_QUEUE_MODE_NONE)
		return 0;
	bpf_for(i, 0, SNAKE_MAX_CPUS)
	{
		if (i >= nr_cpu_ids)
			break;
		if (!queue_cpu_slot(bank, i))
			continue;
		ret = dsq_create(dsq_affinity(i), -1);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		if (i >= header->nr_cpus)
			break;
		ret = dsq_create(dsq_normal(i), -1);
		if (ret)
			return ret;
	}
	return 0;
}

static __always_inline int prepare_queue_topology(u32 slot)
{
	int ret;

	WRITE_ONCE(queue_topology_prepare_stage, 1);
	ret = validate_queue_topology(slot);
	if (ret) {
		WRITE_ONCE(queue_topology_prepare_error, ret);
		return ret;
	}
	WRITE_ONCE(queue_topology_prepare_stage, 2);
	ret = queue_init_cell_masks(slot);
	if (ret) {
		WRITE_ONCE(queue_topology_prepare_error, ret);
		return ret;
	}
	WRITE_ONCE(queue_topology_prepare_stage, 3);
	ret = queue_init_normal_masks(slot);
	WRITE_ONCE(queue_topology_prepare_error, ret);
	if (!ret)
		WRITE_ONCE(queue_topology_prepare_stage, 0);
	return ret;
}

#endif /* __SCX_SNAKE_QUEUE_INIT_H */
