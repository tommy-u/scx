/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_DUMP_H
#define __SCX_SNAKE_DUMP_H

#include "dsq.h"
#include "queue_vtime.h"

extern u32 staging_ladder_slot;
extern u32 staging_ladder_prepare_stage;
extern s32 staging_ladder_prepare_error;
extern u32 queue_topology_prepare_stage;
extern s32 queue_topology_prepare_error;
extern u32 queue_topology_prepare_detail;
extern u32 queue_draining;
extern struct snake_mask_data queue_transition_cpus;
extern u32 slice_shrinking_enabled;
extern u64 slice_shrink_min_ns;
extern u64 slice_shrink_max_ns;
extern u32 slice_shrink_multiplier;

__hidden void snake_dump_cpumask_word(s32 word, const struct cpumask *cpumask)
{
	u32 bit, value = 0;

	bpf_for(bit, 0, 32)
	{
		s32 cpu = 32 * word + bit;

		if (cpu < nr_cpu_ids && bpf_cpumask_test_cpu(cpu, cpumask))
			value |= 1U << bit;
	}
	scx_bpf_dump("%08x", value);
}

static __noinline void snake_dump_cpumask(const struct cpumask *cpumask)
{
	u32 word, nr_words = (nr_cpu_ids + 31) / 32;

	bpf_for(word, 0, SNAKE_MAX_CPUS / 32)
	{
		if (word >= nr_words)
			break;
		if (word)
			scx_bpf_dump(",");
		snake_dump_cpumask_word(nr_words - word - 1, cpumask);
	}
}

__hidden void snake_dump_mask_word(s32 word, const struct snake_mask_data *mask)
{
	u32 bit, value = 0;

	bpf_for(bit, 0, 32)
	{
		u32 cpu = 32 * word + bit;

		if (cpu < nr_cpu_ids && queue_mask_contains(mask, cpu))
			value |= 1U << bit;
	}
	scx_bpf_dump("%08x", value);
}

static __noinline void snake_dump_mask(const struct snake_mask_data *mask)
{
	u32 word, nr_words = (nr_cpu_ids + 31) / 32;

	if (!mask || !READ_ONCE(mask->valid)) {
		scx_bpf_dump("-");
		return;
	}
	bpf_for(word, 0, SNAKE_MAX_CPUS / 32)
	{
		if (word >= nr_words)
			break;
		if (word)
			scx_bpf_dump(",");
		snake_dump_mask_word(nr_words - word - 1, mask);
	}
}

static __noinline void snake_dump_cells(const struct snake_ladder_ctx *ctx,
					const struct snake_queue_header *header)
{
	u32 i;

	bpf_for(i, 0, SNAKE_MAX_QUEUE_CELLS)
	{
		struct snake_cell_queue_runtime *cell_runtime;
		struct snake_vtime_domain *domain;
		struct snake_queue_cell *cell;
		u64 vtime = 0;
		u32 llcs_to_drain = 0;

		if (i >= header->nr_cells)
			break;
		cell = queue_cell(ctx, i);
		if (!cell)
			continue;
		domain = queue_cell_domain(READ_ONCE(cell->clock_index));
		if (domain)
			vtime = READ_ONCE(domain->vtime_now);
		cell_runtime = queue_cell_runtime(i);
		if (cell_runtime)
			llcs_to_drain = READ_ONCE(cell_runtime->llcs_to_drain);

		scx_bpf_dump(
			"CELL[%u] external=%u epoch=%u weight=%u clock=%u vtime=%llu llcs_to_drain=%x primary=",
			i, READ_ONCE(cell->external_id), READ_ONCE(cell->slot_epoch),
			READ_ONCE(cell->cpu_weight), READ_ONCE(cell->clock_index), vtime,
			llcs_to_drain);
		snake_dump_mask(&cell->primary);
		scx_bpf_dump(" borrowable=");
		snake_dump_mask(&cell->borrowable);
		scx_bpf_dump("\n");
	}
}

static __noinline void snake_dump_normal_queues(
	const struct snake_ladder_ctx *ctx, const struct snake_queue_header *header)
{
	u32 i;

	bpf_for(i, 0, SNAKE_MAX_NORMAL_QUEUES)
	{
		struct snake_cell_queue_runtime *cell_runtime;
		struct snake_normal_queue_runtime *runtime;
		struct snake_normal_queue *queue;
		u32 tracked_nr_queued, has_consumers, drain = 0;
		s32 nr_queued;

		if (i >= header->nr_normal_queues)
			break;
		queue = queue_normal(ctx, i);
		runtime = queue_normal_runtime(i);
		if (!queue || !runtime)
			continue;
		nr_queued = dsq_nr_queued(dsq_normal(i));
		tracked_nr_queued = READ_ONCE(runtime->nr_queued);
		has_consumers = READ_ONCE(runtime->has_consumers);
		cell_runtime = queue_cell_runtime(READ_ONCE(runtime->cell_index));
		if (cell_runtime && READ_ONCE(runtime->cell_offset) < 32)
			drain = !!(READ_ONCE(cell_runtime->llcs_to_drain) &
				    (1U << READ_ONCE(runtime->cell_offset)));
		if (!nr_queued && !tracked_nr_queued && !has_consumers && !drain)
			continue;

		scx_bpf_dump(
			"QUEUE[%u] cell=%u offset=%u clock=%u consumer_cpu=%u nr_queued=%d tracked_nr_queued=%u has_consumers=%u drain=%u\n",
			i, READ_ONCE(runtime->cell_index), READ_ONCE(runtime->cell_offset),
			READ_ONCE(queue->clock_index), READ_ONCE(queue->consumer_cpu),
			nr_queued, tracked_nr_queued, has_consumers, drain);
	}
}

static __noinline void snake_dump_cpus(const struct snake_ladder_ctx *ctx)
{
	u32 cpu;

	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		struct snake_affinity_queue_runtime *affinity_runtime;
		struct snake_queue_cell *cell;
		struct snake_cpu_queue *cpuq;
		u32 affinity_tracked_nr_queued = 0;
		u32 external_id = SNAKE_QUEUE_CELL_NONE;
		u32 slot_epoch = 0;
		s32 affinity_nr_queued;

		if (cpu >= nr_cpu_ids)
			break;
		cpuq = queue_cpu(ctx, cpu);
		if (!cpuq || !READ_ONCE(cpuq->valid))
			continue;
		cell = queue_cell(ctx, READ_ONCE(cpuq->owner_cell_index));
		if (cell) {
			external_id = READ_ONCE(cell->external_id);
			slot_epoch = READ_ONCE(cell->slot_epoch);
		}
		affinity_nr_queued = dsq_nr_queued(dsq_affinity(cpu));
		affinity_runtime = queue_affinity_runtime(cpu);
		if (affinity_runtime)
			affinity_tracked_nr_queued = READ_ONCE(affinity_runtime->nr_queued);

		scx_bpf_dump(
			"CPU[%u] owner=%u external=%u epoch=%u normal_queue=%u affinity_nr_queued=%d affinity_tracked_nr_queued=%u\n",
			cpu, READ_ONCE(cpuq->owner_cell_index), external_id, slot_epoch,
			READ_ONCE(cpuq->normal_queue_index), affinity_nr_queued,
			affinity_tracked_nr_queued);
	}
}

void BPF_STRUCT_OPS(snake_dump, struct scx_dump_ctx *dctx)
{
	struct snake_ladder_ctx ladder_ctx = {};
	struct snake_queue_header *header;
	s32 ret;

	(void)dctx;
	scx_bpf_dump_header();
	scx_bpf_dump(
		"SNAKE active_slot=%d staging_slot=%u ladder_stage=%u ladder_error=%d topology_stage=%u topology_error=%d topology_detail=%u draining=%u fairness=%u queue_mode=%u\n",
		active_ladder_slot(), READ_ONCE(staging_ladder_slot),
		READ_ONCE(staging_ladder_prepare_stage),
		READ_ONCE(staging_ladder_prepare_error),
		READ_ONCE(queue_topology_prepare_stage),
		READ_ONCE(queue_topology_prepare_error),
		READ_ONCE(queue_topology_prepare_detail), READ_ONCE(queue_draining),
		READ_ONCE(fairness_mode), READ_ONCE(queue_mode));
	scx_bpf_dump(
		"PARAM vtime_slice_ns=%llu slice_shrinking=%u min_ns=%llu max_ns=%llu multiplier=%u\n",
		READ_ONCE(vtime_slice_ns), READ_ONCE(slice_shrinking_enabled),
		READ_ONCE(slice_shrink_min_ns), READ_ONCE(slice_shrink_max_ns),
		READ_ONCE(slice_shrink_multiplier));
	if (READ_ONCE(queue_draining)) {
		scx_bpf_dump("TRANSITION_CPUS=");
		snake_dump_mask(&queue_transition_cpus);
		scx_bpf_dump("\n");
	}

	ret = acquire_active_ladder(&ladder_ctx);
	if (ret) {
		scx_bpf_dump("SNAKE active ladder unavailable error=%d\n", ret);
		return;
	}
	scx_bpf_dump("POLICY generation=%llu abi=%u rungs=%u enqueue_rungs=%u dispatch_rungs=%u\n",
		     READ_ONCE(ladder_ctx.ladder->generation),
		     READ_ONCE(ladder_ctx.ladder->policy_abi_version),
		     READ_ONCE(ladder_ctx.ladder->nr_rungs),
		     READ_ONCE(ladder_ctx.ladder->nr_enqueue_rungs),
		     READ_ONCE(ladder_ctx.ladder->nr_dispatch_rungs));
	header = queue_config(&ladder_ctx);
	if (!header || !queue_topology_enabled()) {
		scx_bpf_dump(
			"FAIRNESS fifo_nr_queued=%d vtime_nr_queued=%d eevdf_eligible_nr_queued=%d eevdf_future_nr_queued=%d\n",
			dsq_nr_queued(dsq_fifo()), dsq_nr_queued(dsq_vtime_global()),
			dsq_nr_queued(dsq_eevdf_eligible()),
			dsq_nr_queued(dsq_eevdf_future()));
		release_active_ladder(&ladder_ctx);
		return;
	}
	scx_bpf_dump(
		"TOPOLOGY topology_generation=%llu cells=%u normal_queues=%u normal_dsqs=%u cpus=%u\n",
		READ_ONCE(header->topology_generation), READ_ONCE(header->nr_cells),
		READ_ONCE(header->nr_normal_queues), READ_ONCE(header->nr_normal_dsqs),
		READ_ONCE(header->nr_cpus));
	snake_dump_cells(&ladder_ctx, header);
	snake_dump_normal_queues(&ladder_ctx, header);
	snake_dump_cpus(&ladder_ctx);
	release_active_ladder(&ladder_ctx);
}

void BPF_STRUCT_OPS(snake_dump_task, struct scx_dump_ctx *dctx,
			     struct task_struct *p)
{
	struct snake_task_runtime *runtime;
	struct snake_task_cell *annotation;

	(void)dctx;
	runtime = task_state_lookup(p);
	annotation = task_annotation(p);
	if (annotation)
		scx_bpf_dump(
			"TASK[%d] annotation_cell=%u annotation_epoch=%u managed_cell=%u managed_epoch=%u needs_rehome=%u flags=%x\n",
			p->pid, READ_ONCE(annotation->cell_id),
			READ_ONCE(annotation->cell_epoch),
			READ_ONCE(annotation->managed_cell_id),
			READ_ONCE(annotation->managed_cell_epoch),
			READ_ONCE(annotation->needs_rehome), READ_ONCE(annotation->flags));
	if (runtime) {
		scx_bpf_dump(
			"TASK[%d] cpu=%d slice=%llu dsq_vtime=%llu cell=%u external=%u epoch=%u topology_generation=%llu queue_class=%u queue_index=%u\n",
			p->pid, scx_bpf_task_cpu(p), p->scx.slice, dsq_task_vtime(p),
			READ_ONCE(runtime->cell_index),
			READ_ONCE(runtime->cell_external_id), READ_ONCE(runtime->cell_epoch),
			READ_ONCE(runtime->topology_generation),
			READ_ONCE(runtime->queued_dsq_class),
			READ_ONCE(runtime->queued_dsq_index));
		scx_bpf_dump(
			"TASK[%d] vruntime=%llu affinity_vruntime=%llu service_budget=%llu avg_runtime_ns=%llu run_cell=%u run_owner=%u run_class=%u selected_cpu=%u selected_valid=%u\n",
			p->pid, READ_ONCE(runtime->vruntime),
			READ_ONCE(runtime->affinity_vruntime),
			READ_ONCE(runtime->service_budget), READ_ONCE(runtime->avg_runtime_ns),
			READ_ONCE(runtime->run_cell_index),
			READ_ONCE(runtime->run_owner_cell_index),
			READ_ONCE(runtime->run_queue_class), READ_ONCE(runtime->selected_cpu),
			READ_ONCE(runtime->selected_cpu_valid));
	}
	scx_bpf_dump("TASK[%d] CPUS=", p->pid);
	snake_dump_cpumask(p->cpus_ptr);
	scx_bpf_dump("\n");
}

#endif /* __SCX_SNAKE_DUMP_H */
