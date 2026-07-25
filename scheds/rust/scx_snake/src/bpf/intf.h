/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_INTF_H
#define __SCX_SNAKE_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char	   u8;
typedef unsigned int	   u32;
typedef unsigned long long u64;
#endif

#define SNAKE_ABI_VERSION 4
#define SNAKE_MAX_RUNGS 8
#define SNAKE_MAX_CPUS 1024
#define SNAKE_MASK_BYTES (SNAKE_MAX_CPUS / 8)
#define SNAKE_MAX_MASK_TABLES 4
#define SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED (1U << 0)
#define SNAKE_RUNG_F_PICK_IDLE_CORE (1U << 1)

/* Stable operation codes shared by the userspace compiler and BPF. */
enum snake_opcode {
	SNAKE_OP_INVALID	      = 0,
	SNAKE_OP_CLAIM_IDLE	      = 1,
	SNAKE_OP_PICK_IDLE	      = 2,
	SNAKE_OP_PICK_IDLE_MASK_TABLE = 3,
	SNAKE_OP_PICK_RANDOM_IDLE     = 4,
};

/* Exhaustion behavior applied when every select rung misses. */
enum snake_fallback {
	SNAKE_FALLBACK_INVALID	    = 0,
	SNAKE_FALLBACK_PREVIOUS_CPU = 1,
	SNAKE_FALLBACK_ANY_ALLOWED  = 2,
};

/* Topology-blind operand sources consumed by mechanical rung operations. */
enum snake_input_source {
	SNAKE_INPUT_INVALID	      = 0,
	SNAKE_INPUT_CPU_PREV	      = 1,
	SNAKE_INPUT_MASK_TASK_ALLOWED = 2,
};

/*
 * Mechanical instruction consumed by BPF. Semantic topology concepts must be
 * lowered by userspace into operand sources and data tables.
 */
struct snake_rung {
	u32 opcode;
	u32 input;
	u32 flags;
	u32 reserved;
	u64 data;
};

/* Serialized userspace mask entry consumed when BPF initializes a table. */
struct snake_mask_data {
	u32 valid;
	u8  bits[SNAKE_MASK_BYTES];
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
