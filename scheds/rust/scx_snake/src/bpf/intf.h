/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_INTF_H
#define __SCX_SNAKE_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned int	   u32;
typedef unsigned long long u64;
#endif

#define SNAKE_ABI_VERSION 1
#define SNAKE_MAX_RUNGS 8

/* Stable operation codes shared by the userspace compiler and BPF. */
enum snake_opcode {
	SNAKE_OP_INVALID    = 0,
	SNAKE_OP_CLAIM_IDLE = 1,
	SNAKE_OP_PICK_IDLE  = 2,
};

/* Topology-blind operand sources consumed by mechanical rung operations. */
enum snake_input_source {
	SNAKE_INPUT_INVALID	      = 0,
	SNAKE_INPUT_CPU_PREV	      = 1,
	SNAKE_INPUT_MASK_TASK_ALLOWED = 2,
};

/*
 * Mechanical instruction consumed by BPF. Semantic concepts such as LLCs or
 * NUMA nodes must be lowered by userspace into operand sources and data tables.
 */
struct snake_rung {
	u32 opcode;
	u32 input;
	u32 flags;
	u32 reserved;
	u64 data;
};

/* Fixed map-key layout for global and per-rung scheduler counters. */
enum snake_stat {
	SNAKE_STAT_SELECT_CALLS = 0,
	SNAKE_STAT_DIRECT_DISPATCHES,
	SNAKE_STAT_LADDER_EXHAUSTIONS,
	SNAKE_STAT_FALLBACK_PREV,
	SNAKE_STAT_FALLBACK_ANY,
	SNAKE_STAT_INVALID_ERRORS,
	SNAKE_STAT_ENQUEUES,
	SNAKE_STAT_RUNNING,
	SNAKE_STAT_STOPPING,
	SNAKE_STAT_QUIESCENT,
	SNAKE_STAT_SELECT_LATENCY_NS,
	SNAKE_STAT_SELECT_LATENCY_MAX_NS,
	SNAKE_STAT_GLOBAL_NR,
	SNAKE_STAT_RUNG_ATTEMPT_BASE = SNAKE_STAT_GLOBAL_NR,
	SNAKE_STAT_RUNG_HIT_BASE =
		SNAKE_STAT_RUNG_ATTEMPT_BASE + SNAKE_MAX_RUNGS,
	SNAKE_STAT_RUNG_MISS_BASE = SNAKE_STAT_RUNG_HIT_BASE + SNAKE_MAX_RUNGS,
	SNAKE_STAT_RUNG_ERROR_BASE =
		SNAKE_STAT_RUNG_MISS_BASE + SNAKE_MAX_RUNGS,
	SNAKE_NR_STATS = SNAKE_STAT_RUNG_ERROR_BASE + SNAKE_MAX_RUNGS,
};

#endif /* __SCX_SNAKE_INTF_H */
