/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_DSQ_H
#define __SCX_SNAKE_DSQ_H

/*
 * Snake user DSQs retain their existing raw IDs. Bits 31..28 identify the
 * queue family and bits 27..0 carry a CPU or queue index. Type zero contains
 * the global EEVDF/VTIME queues and the per-CPU VTIME range.
 */
#define SNAKE_DSQ_DATA_BITS 28
#define SNAKE_DSQ_TYPE_BITS 4
#define SNAKE_DSQ_RESERVED_BITS 32

#ifndef __clang__
#error "Snake DSQ bitfields require Clang/LLVM"
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Snake DSQ bitfields require little-endian BPF"
#endif

enum snake_dsq_type {
	SNAKE_DSQ_TYPE_FAIRNESS = 0,
	SNAKE_DSQ_TYPE_AFFINITY = 1,
	SNAKE_DSQ_TYPE_NORMAL = 2,
	SNAKE_DSQ_TYPE_FIFO = 3,
};

typedef union {
	u64 raw;
	struct {
		u64 data : SNAKE_DSQ_DATA_BITS;
		u64 type : SNAKE_DSQ_TYPE_BITS;
		u64 reserved : SNAKE_DSQ_RESERVED_BITS;
	} user;
	struct {
		u64 value : 32;
		u64 reserved : 30;
		u64 local_on : 1;
		u64 builtin : 1;
	} builtin;
} dsq_id_t;

_Static_assert(sizeof(dsq_id_t) == sizeof(u64), "DSQ IDs must remain 64 bits");
_Static_assert(_Alignof(dsq_id_t) == sizeof(u64),
	       "DSQ IDs must remain 8-byte aligned");
_Static_assert(SNAKE_AFFINITY_DSQ_BASE ==
		       ((u64)SNAKE_DSQ_TYPE_AFFINITY << SNAKE_DSQ_DATA_BITS),
	       "affinity DSQ base must match its type encoding");
_Static_assert(SNAKE_NORMAL_DSQ_BASE ==
		       ((u64)SNAKE_DSQ_TYPE_NORMAL << SNAKE_DSQ_DATA_BITS),
	       "normal DSQ base must match its type encoding");
_Static_assert(SNAKE_FIFO_DSQ ==
		       ((u64)SNAKE_DSQ_TYPE_FIFO << SNAKE_DSQ_DATA_BITS),
	       "FIFO DSQ must match its type encoding");
_Static_assert(SNAKE_MAX_CPUS <= (1U << SNAKE_DSQ_DATA_BITS),
	       "CPU IDs must fit in a DSQ ID");
_Static_assert(SNAKE_MAX_NORMAL_QUEUES <= (1U << SNAKE_DSQ_DATA_BITS),
	       "normal queue IDs must fit in a DSQ ID");

static __always_inline dsq_id_t dsq_from_raw(u64 raw)
{
	return (dsq_id_t){ .raw = raw };
}

static __always_inline dsq_id_t dsq_invalid(void)
{
	return dsq_from_raw(SCX_DSQ_INVALID);
}

static __always_inline bool dsq_is_invalid(dsq_id_t dsq)
{
	return dsq.raw == SCX_DSQ_INVALID;
}

static __always_inline dsq_id_t dsq_eevdf_eligible(void)
{
	return dsq_from_raw(SNAKE_EEVDF_ELIGIBLE_DSQ);
}

static __always_inline dsq_id_t dsq_eevdf_future(void)
{
	return dsq_from_raw(SNAKE_EEVDF_FUTURE_DSQ);
}

static __always_inline dsq_id_t dsq_vtime_global(void)
{
	return dsq_from_raw(SNAKE_VTIME_GLOBAL_DSQ);
}

static __always_inline dsq_id_t dsq_vtime_cpu(u32 cpu)
{
	if (cpu >= SNAKE_MAX_CPUS)
		return dsq_invalid();
	return dsq_from_raw(SNAKE_VTIME_CPU_DSQ_BASE + (u64)cpu);
}

static __always_inline dsq_id_t dsq_affinity(u32 cpu)
{
	if (cpu >= SNAKE_MAX_CPUS)
		return dsq_invalid();
	return (dsq_id_t){ .user = {
		.data = cpu,
		.type = SNAKE_DSQ_TYPE_AFFINITY,
	} };
}

static __always_inline dsq_id_t dsq_normal(u32 queue_index)
{
	if (queue_index >= SNAKE_MAX_NORMAL_QUEUES)
		return dsq_invalid();
	return (dsq_id_t){ .user = {
		.data = queue_index,
		.type = SNAKE_DSQ_TYPE_NORMAL,
	} };
}

static __always_inline dsq_id_t dsq_fifo(void)
{
	return (dsq_id_t){ .user = { .type = SNAKE_DSQ_TYPE_FIFO } };
}

static __always_inline dsq_id_t dsq_local(void)
{
	return dsq_from_raw(SCX_DSQ_LOCAL);
}

static __always_inline dsq_id_t dsq_local_on(u32 cpu)
{
	if (cpu >= SNAKE_MAX_CPUS)
		return dsq_invalid();
	return dsq_from_raw(SCX_DSQ_LOCAL_ON | (u64)cpu);
}

static __always_inline u32 dsq_queue_class(dsq_id_t dsq)
{
	if (dsq.builtin.builtin)
		return SNAKE_QUEUE_CLASS_FAIRNESS;
	if (dsq.user.type == SNAKE_DSQ_TYPE_AFFINITY)
		return SNAKE_QUEUE_CLASS_AFFINITY;
	if (dsq.user.type == SNAKE_DSQ_TYPE_NORMAL)
		return SNAKE_QUEUE_CLASS_NORMAL;
	return SNAKE_QUEUE_CLASS_FAIRNESS;
}

static __always_inline s32 dsq_nr_queued(dsq_id_t dsq)
{
	return scx_bpf_dsq_nr_queued(dsq.raw);
}

static __always_inline struct task_struct *dsq_peek(dsq_id_t dsq)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq.raw);
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
dsq_record_operation(const struct snake_fine_timing_ctx *fine,
		     dsq_id_t source, dsq_id_t target, u32 operation,
		     u32 outcome, u64 started_at)
{
	if (!started_at)
		return;
	struct snake_fine_timing_event event = {};

	event.elapsed_ns = bpf_ktime_get_ns() - started_at;
	event.source_dsq_id = source.raw;
	event.target_dsq_id = target.raw;
	event.operation = operation;
	event.outcome = outcome;
	event.queue_class = dsq_queue_class(
		dsq_is_invalid(source) ? target : source);
	fine_timing_record_dsq_operation(fine, &event);
}

static __always_inline bool
dsq_insert(struct task_struct *p, dsq_id_t target, u64 slice, u64 enq_flags,
	   const struct snake_fine_timing_ctx *fine)
{
	u64 started_at = fine_timing_start(fine);
	bool inserted = scx_bpf_dsq_insert(p, target.raw, slice, enq_flags);

	dsq_record_operation(
		fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
		inserted ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_ERROR,
		started_at);
	return inserted;
}

/* SCX_DSQ_LOCAL is contextual; record the concrete CPU-local destination. */
static __always_inline bool
dsq_insert_local(struct task_struct *p, s32 cpu, u64 slice, u64 enq_flags,
		 const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t target = cpu < 0 ? dsq_invalid() : dsq_local_on(cpu);
	u64 started_at = fine_timing_start(fine);
	bool inserted = scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);

	dsq_record_operation(
		fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
		inserted ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_ERROR,
		started_at);
	return inserted;
}

static __always_inline bool
dsq_insert_vtime(struct task_struct *p, dsq_id_t target, u64 slice, u64 vtime,
		 u64 enq_flags, const struct snake_fine_timing_ctx *fine)
{
	u64 started_at = fine_timing_start(fine);
	bool inserted = scx_bpf_dsq_insert_vtime(p, target.raw, slice, vtime,
					       enq_flags);

	dsq_record_operation(
		fine, dsq_invalid(), target, SNAKE_DSQ_OP_INSERT,
		inserted ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_ERROR,
		started_at);
	return inserted;
}

static __noinline bool
dsq_move_to_local(dsq_id_t source, s32 cpu,
		  const struct snake_fine_timing_ctx *fine)
{
	dsq_id_t target = cpu < 0 ? dsq_invalid() : dsq_local_on(cpu);
	u64 started_at = fine_timing_start(fine);
	bool moved = scx_bpf_dsq_move_to_local(source.raw, 0);

	dsq_record_operation(
		fine, source, target, SNAKE_DSQ_OP_MOVE_TO_LOCAL,
		moved ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_MISS,
		started_at);
	return moved;
}

static __always_inline bool
dsq_move(struct bpf_iter_scx_dsq *iterator, struct task_struct *p,
	 dsq_id_t source, dsq_id_t target, u64 enq_flags,
	 const struct snake_fine_timing_ctx *fine)
{
	u64 started_at = fine_timing_start(fine);
	bool moved = scx_bpf_dsq_move(iterator, p, target.raw, enq_flags);

	dsq_record_operation(
		fine, source, target, SNAKE_DSQ_OP_MOVE,
		moved ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_MISS,
		started_at);
	return moved;
}

static __always_inline bool
dsq_move_vtime(struct bpf_iter_scx_dsq *iterator, struct task_struct *p,
	       dsq_id_t source, dsq_id_t target, u64 enq_flags,
	       const struct snake_fine_timing_ctx *fine)
{
	u64 started_at = fine_timing_start(fine);
	bool moved = scx_bpf_dsq_move_vtime(iterator, p, target.raw, enq_flags);

	dsq_record_operation(
		fine, source, target, SNAKE_DSQ_OP_MOVE,
		moved ? SNAKE_DSQ_OUTCOME_SUCCESS : SNAKE_DSQ_OUTCOME_MISS,
		started_at);
	return moved;
}

#endif /* __SCX_SNAKE_DSQ_H */
