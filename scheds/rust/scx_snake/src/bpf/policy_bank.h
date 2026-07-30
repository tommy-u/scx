/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_POLICY_BANK_H
#define __SCX_SNAKE_POLICY_BANK_H

#include "bpf_common.h"

struct snake_ladder_ctx {
	u32				    slot;
	u32				   *readers;
	const struct snake_compiled_ladder *ladder;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct snake_compiled_ladder);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
} compiled_ladders SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} active_ladder SEC(".maps");

/* Per-CPU readers let userspace safely rebuild the inactive ladder slot. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
} ladder_readers	   SEC(".maps");

static __always_inline s32 active_ladder_slot(void)
{
	u32  key = 0;
	u32 *slot;

	slot = bpf_map_lookup_elem(&active_ladder, &key);
	if (!slot)
		return -EINVAL;
	return READ_ONCE(*slot);
}

/* Pin one complete ladder slot for the duration of a scheduler callback. */
static __always_inline int acquire_active_ladder(struct snake_ladder_ctx *ctx)
{
	u32 attempt;

	bpf_for(attempt, 0, 4)
	{
		struct snake_compiled_ladder *ladder;
		u32			     *readers;
		s32			      slot;

		slot = active_ladder_slot();
		if (slot < 0 || slot >= SNAKE_LADDER_SLOTS)
			return -EINVAL;
		readers = bpf_map_lookup_elem(&ladder_readers, &slot);
		if (!readers)
			return -EINVAL;
		__sync_fetch_and_add(readers, 1);
		if (active_ladder_slot() != slot) {
			__sync_fetch_and_sub(readers, 1);
			continue;
		}

		ladder = bpf_map_lookup_elem(&compiled_ladders, &slot);
		if (!ladder) {
			__sync_fetch_and_sub(readers, 1);
			return -EINVAL;
		}
		ctx->slot    = slot;
		ctx->readers = readers;
		ctx->ladder  = ladder;
		return 0;
	}

	return -EAGAIN;
}

static __always_inline void release_active_ladder(struct snake_ladder_ctx *ctx)
{
	if (ctx->readers)
		__sync_fetch_and_sub(ctx->readers, 1);
	ctx->readers = NULL;
}

#endif /* __SCX_SNAKE_POLICY_BANK_H */
