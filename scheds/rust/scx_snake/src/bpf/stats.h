/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_STATS_H
#define __SCX_SNAKE_STATS_H

#include "policy_bank.h"

/* Per-CPU counters avoid atomics in scheduler callbacks. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, SNAKE_LADDER_SLOTS *SNAKE_NR_STATS);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS *
				    SNAKE_NR_CELL_STATS);
} cell_stats		    SEC(".maps");

static __always_inline void stat_add(const struct snake_ladder_ctx *ctx,
				     u32 idx, u64 amount)
{
	u64 *value;
	u32  key;

	if (idx >= SNAKE_NR_STATS || ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	key   = ctx->slot * SNAKE_NR_STATS + idx;
	value = bpf_map_lookup_elem(&stats, &key);
	if (value)
		*value += amount;
}

static __always_inline void stat_inc(const struct snake_ladder_ctx *ctx,
				     u32			    idx)
{
	stat_add(ctx, idx, 1);
}

static __always_inline void cell_stat_add(const struct snake_ladder_ctx *ctx,
					  u32 cell_index, u32 stat, u64 amount)
{
	u64 *value;
	u32  key;

	if (ctx->slot >= SNAKE_LADDER_SLOTS ||
	    cell_index >= SNAKE_MAX_QUEUE_CELLS || stat >= SNAKE_NR_CELL_STATS)
		return;
	key = (ctx->slot * SNAKE_MAX_QUEUE_CELLS + cell_index) *
	      SNAKE_NR_CELL_STATS + stat;
	value = bpf_map_lookup_elem(&cell_stats, &key);
	if (value)
		*value += amount;
}

static __always_inline void cell_stat_inc(const struct snake_ladder_ctx *ctx,
					  u32 cell_index, u32 stat)
{
	cell_stat_add(ctx, cell_index, stat, 1);
}

static __always_inline void stat_max(const struct snake_ladder_ctx *ctx,
				     u32 idx, u64 candidate)
{
	u64 *value;
	u32  key;

	if (idx >= SNAKE_NR_STATS || ctx->slot >= SNAKE_LADDER_SLOTS)
		return;
	key   = ctx->slot * SNAKE_NR_STATS + idx;
	value = bpf_map_lookup_elem(&stats, &key);
	if (value && candidate > *value)
		*value = candidate;
}

#endif /* __SCX_SNAKE_STATS_H */
