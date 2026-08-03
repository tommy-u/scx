/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_DSQ_ID_H
#define __SCX_SNAKE_DSQ_ID_H

#include "bpf_common.h"

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
	SNAKE_DSQ_TYPE_NORMAL	= 2,
	SNAKE_DSQ_TYPE_FIFO	= 3,
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
_Static_assert(SNAKE_MAX_QUEUE_CELLS * SNAKE_MAX_CELL_LLCS <=
		       SNAKE_MAX_NORMAL_QUEUES,
	       "the stable cell/LLC DSQ pool must fit normal queue storage");

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

#endif /* __SCX_SNAKE_DSQ_ID_H */
