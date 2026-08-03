/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_DSQ_H
#define __SCX_SNAKE_DSQ_H

#include "dsq_id.h"
#include "timing.h"

static __always_inline s32 dsq_nr_queued(dsq_id_t dsq)
{
	return scx_bpf_dsq_nr_queued(dsq.raw);
}

static __always_inline struct task_struct *dsq_peek(dsq_id_t dsq)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq.raw);
}

static __always_inline struct task_struct *
dsq_peek_vtime(dsq_id_t dsq, u64 *vtime)
{
	struct task_struct *p = dsq_peek(dsq);

	if (!p || !vtime)
		return NULL;
	*vtime = READ_ONCE(p->scx.dsq_vtime);
	return p;
}

static __always_inline bool dsq_vtime_head(dsq_id_t dsq, u64 *vtime)
{
	if (dsq_nr_queued(dsq) <= 0)
		return false;
	return dsq_peek_vtime(dsq, vtime) != NULL;
}

static __always_inline s32 dsq_create(dsq_id_t dsq, s32 node)
{
	return scx_bpf_create_dsq(dsq.raw, node);
}

static __always_inline void dsq_destroy(dsq_id_t dsq)
{
	scx_bpf_destroy_dsq(dsq.raw);
}

static __always_inline void
dsq_move_set_slice(struct bpf_iter_scx_dsq *iterator, u64 slice)
{
	scx_bpf_dsq_move_set_slice(iterator, slice);
}

static __always_inline void
dsq_move_set_vtime(struct bpf_iter_scx_dsq *iterator, u64 vtime)
{
	scx_bpf_dsq_move_set_vtime(iterator, vtime);
}

static __always_inline void
dsq_record_operation(const struct snake_fine_timing_ctx *fine, dsq_id_t source,
		     dsq_id_t target, u32 operation, u32 outcome,
		     u64 started_at)
{
	struct snake_fine_timing_event *event;

	if (!started_at)
		return;
	event = fine_timing_reserve_dsq_operation(fine, operation, outcome);
	if (!event)
		return;
	event->session_id    = fine->session_id;
	event->elapsed_ns    = bpf_ktime_get_ns() - started_at;
	event->source_dsq_id = source.raw;
	event->target_dsq_id = target.raw;
	event->stage	     = 0;
	event->operation     = operation;
	event->outcome	     = outcome;
	event->queue_class =
		dsq_queue_class(dsq_is_invalid(source) ? target : source);
	bpf_ringbuf_submit(event, 0);
}

static __always_inline bool dsq_insert(struct task_struct *p, dsq_id_t target,
				       u64 slice, u64 enq_flags,
				       const struct snake_fine_timing_ctx *fine)
{
	u64  started_at = fine_timing_start(fine);
	bool inserted	= scx_bpf_dsq_insert(p, target.raw, slice, enq_flags);

	dsq_record_operation(fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
			     inserted ? SNAKE_DSQ_OUTCOME_SUCCESS :
					SNAKE_DSQ_OUTCOME_ERROR,
			     started_at);
	return inserted;
}

/* Target the selected CPU explicitly; enqueue's contextual LOCAL is task_rq. */
static __always_inline bool
dsq_insert_local_on(struct task_struct *p, s32 cpu, u64 slice, u64 enq_flags,
		    const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t target	    = cpu < 0 ? dsq_invalid() : dsq_local_on(cpu);
	u64	 started_at = fine_timing_start(fine);
	bool inserted = scx_bpf_dsq_insert(p, target.raw, slice, enq_flags);

	dsq_record_operation(fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
			     inserted ? SNAKE_DSQ_OUTCOME_SUCCESS :
					SNAKE_DSQ_OUTCOME_ERROR,
			     started_at);
	return inserted;
}

static __always_inline bool
dsq_insert_vtime(struct task_struct *p, dsq_id_t target, u64 slice, u64 vtime,
		 u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	u64  started_at = fine_timing_start(fine);
	bool inserted	= scx_bpf_dsq_insert_vtime(p, target.raw, slice, vtime,
						   enq_flags);

	dsq_record_operation(fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
			     inserted ? SNAKE_DSQ_OUTCOME_SUCCESS :
					SNAKE_DSQ_OUTCOME_ERROR,
			     started_at);
	return inserted;
}

static __noinline bool
dsq_move_to_local(dsq_id_t source, s32 cpu,
		  const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t target	    = cpu < 0 ? dsq_invalid() : dsq_local_on(cpu);
	u64	 started_at = fine_timing_start(fine);
	bool	 moved	    = scx_bpf_dsq_move_to_local(source.raw, 0);

	dsq_record_operation(fine, source, target, SNAKE_DSQ_OP_MOVE_TO_LOCAL,
			     moved ? SNAKE_DSQ_OUTCOME_SUCCESS :
				     SNAKE_DSQ_OUTCOME_MISS,
			     started_at);
	return moved;
}

static __always_inline bool
dsq_move_to_local_untimed(dsq_id_t source)
{
	return scx_bpf_dsq_move_to_local(source.raw, 0);
}

static __always_inline bool dsq_move(struct bpf_iter_scx_dsq *iterator,
				     struct task_struct *p, dsq_id_t source,
				     dsq_id_t target, u64 enq_flags,
				     const struct snake_fine_timing_ctx *fine)
{
	u64  started_at = fine_timing_start(fine);
	bool moved	= scx_bpf_dsq_move(iterator, p, target.raw, enq_flags);

	dsq_record_operation(fine, source, target, SNAKE_DSQ_OP_MOVE,
			     moved ? SNAKE_DSQ_OUTCOME_SUCCESS :
				     SNAKE_DSQ_OUTCOME_MISS,
			     started_at);
	return moved;
}

static __noinline bool
dsq_move_vtime(struct bpf_iter_scx_dsq *iterator, struct task_struct *p,
	       dsq_id_t source, dsq_id_t target, u64 enq_flags,
	       const struct snake_fine_timing_ctx *fine)
{
	u64  started_at = fine_timing_start(fine);
	bool moved = scx_bpf_dsq_move_vtime(iterator, p, target.raw, enq_flags);

	dsq_record_operation(fine, source, target, SNAKE_DSQ_OP_MOVE,
			     moved ? SNAKE_DSQ_OUTCOME_SUCCESS :
				     SNAKE_DSQ_OUTCOME_MISS,
			     started_at);
	return moved;
}

#endif /* __SCX_SNAKE_DSQ_H */
