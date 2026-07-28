/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_INTF_H
#define __SCX_SNAKE_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char	   u8;
typedef unsigned int	   u32;
typedef unsigned long long u64;
#endif

#define SNAKE_ABI_VERSION 16
#define SNAKE_MAX_RUNGS 8
#define SNAKE_MAX_QUEUE_RUNGS 8
#define SNAKE_LADDER_SLOTS 2
#define SNAKE_LADDER_SLOT_INVALID SNAKE_LADDER_SLOTS
#define SNAKE_MAX_CPUS 1024
#define SNAKE_MASK_BYTES (SNAKE_MAX_CPUS / 8)
#define SNAKE_MAX_MASK_TABLES 4
#define SNAKE_MAX_QUEUE_CELLS 32
#define SNAKE_MAX_NORMAL_QUEUES SNAKE_MAX_CPUS
#define SNAKE_QUEUE_LAYOUT_NONE 0U
#define SNAKE_QUEUE_LAYOUT_CELL 1U
#define SNAKE_QUEUE_LAYOUT_CELL_LLC 2U
#define SNAKE_AFFINITY_DSQ_BASE 0x10000000ULL
#define SNAKE_NORMAL_DSQ_BASE 0x20000000ULL
#define SNAKE_QUEUE_LLC_NONE 0xffffffffU
#define SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED (1U << 0)
#define SNAKE_RUNG_F_PICK_IDLE_CORE (1U << 1)
#define SNAKE_RUNG_F_PICK_RANDOM (1U << 2)
#define SNAKE_EEVDF_SLICE_NS 5000000ULL
#define SNAKE_EEVDF_PROMOTE_BATCH 64
#define SNAKE_EEVDF_ELIGIBLE_DSQ 0
#define SNAKE_EEVDF_FUTURE_DSQ 1
#define SNAKE_VTIME_GLOBAL_DSQ 2ULL
#define SNAKE_VTIME_CPU_DSQ_BASE 3ULL
#define SNAKE_FIFO_DSQ 0x30000000ULL
#define SNAKE_VTIME_SLICE_NS 5000000ULL
#define SNAKE_BASE_WEIGHT 100

enum snake_fairness_mode {
	SNAKE_FAIRNESS_INVALID = 0,
	SNAKE_FAIRNESS_FIFO    = 1,
	SNAKE_FAIRNESS_EEVDF   = 2,
	SNAKE_FAIRNESS_VTIME   = 3,
};

/* Stable operation codes shared by the userspace compiler and BPF. */
enum snake_opcode {
	SNAKE_OP_INVALID	      = 0,
	SNAKE_OP_CLAIM_IDLE	      = 1,
	SNAKE_OP_PICK_IDLE	      = 2,
	SNAKE_OP_PICK_IDLE_MASK_TABLE = 3,
	SNAKE_OP_PICK_RANDOM_IDLE     = 4,
	SNAKE_OP_KERNEL_DEFAULT	      = 5,
	SNAKE_OP_SYNC_WAKE_AFFINE     = 6,
	SNAKE_OP_PICK_IDLE_QUEUE_MASK = 7,
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
	SNAKE_INPUT_TASK_CELL	      = 3,
	SNAKE_INPUT_QUEUE_CELL	      = 4,
};

enum snake_queue_mask_kind {
	SNAKE_QUEUE_MASK_INVALID    = 0,
	SNAKE_QUEUE_MASK_PRIMARY    = 1,
	SNAKE_QUEUE_MASK_BORROWABLE = 2,
};

enum snake_enqueue_opcode {
	SNAKE_ENQUEUE_OP_INVALID  = 0,
	SNAKE_ENQUEUE_OP_CELL     = 1,
	SNAKE_ENQUEUE_OP_AFFINITY = 2,
};

enum snake_dispatch_opcode {
	SNAKE_DISPATCH_OP_INVALID  = 0,
	SNAKE_DISPATCH_OP_CELL     = 1,
	SNAKE_DISPATCH_OP_AFFINITY = 2,
	SNAKE_DISPATCH_OP_MIN_VTIME = 3,
};

/* Userspace annotation attached to one thread through BPF task storage. */
struct snake_task_cell {
	u32 cell_id;
	u32 needs_rehome;
};

/* Serialized userspace CPU mask stored in immutable queue descriptors. */
struct snake_mask_data {
	u32 valid;
	u8  bits[SNAKE_MASK_BYTES];
};

struct snake_queue_header {
	u32 layout;
	u32 nr_cells;
	u32 nr_normal_queues;
	u32 nr_cpus;
};

struct snake_queue_cell {
	u32 valid;
	u32 external_id;
	u32 cpu_weight;
	u32 clock_index;
	u32 first_normal_queue;
	u32 nr_normal_queues;
	u32 reserved[2];
	struct snake_mask_data primary;
	struct snake_mask_data borrowable;
};

struct snake_normal_queue {
	u32 valid;
	u32 cell_index;
	u32 clock_index;
	u32 llc_id;
	u32 consumer_cpu;
	u32 reserved[3];
};

struct snake_cpu_queue {
	u32 valid;
	u32 owner_cell_index;
	u32 llc_id;
	u32 normal_queue_index;
};

enum snake_cell_stat {
	SNAKE_CELL_STAT_RUNTIME_NS = 0,
	SNAKE_CELL_STAT_PRIMARY_RUNTIME_NS,
	SNAKE_CELL_STAT_BORROWED_RUNTIME_NS,
	SNAKE_CELL_STAT_LENT_RUNTIME_NS,
	SNAKE_CELL_STAT_NORMAL_ENQUEUES,
	SNAKE_CELL_STAT_AFFINITY_ENQUEUES,
	SNAKE_CELL_STAT_NORMAL_DISPATCHES,
	SNAKE_CELL_STAT_AFFINITY_DISPATCHES,
	SNAKE_CELL_STAT_CLOCK_TRANSITIONS,
	SNAKE_NR_CELL_STATS,
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

struct snake_queue_rung {
	u32 opcode;
	u32 flags;
};

/* Complete userspace-compiled ladder installed as one runtime generation. */
struct snake_compiled_ladder {
	u64		  generation;
	u32		  policy_abi_version;
	u32		  nr_rungs;
	u32		  nr_mask_tables;
	u32		  fallback_mode;
	struct snake_rung rungs[SNAKE_MAX_RUNGS];
	u32		  nr_enqueue_rungs;
	u32		  nr_dispatch_rungs;
	struct snake_queue_rung enqueue_rungs[SNAKE_MAX_QUEUE_RUNGS];
	struct snake_queue_rung dispatch_rungs[SNAKE_MAX_QUEUE_RUNGS];
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
	SNAKE_STAT_FIFO_SHARED_ENQUEUES,
	SNAKE_STAT_FIFO_SHARED_DISPATCHES,
	SNAKE_STAT_RUNNING,
	SNAKE_STAT_STOPPING,
	SNAKE_STAT_QUIESCENT,
	SNAKE_STAT_RUNTIME_NS,
	SNAKE_STAT_SELECT_LATENCY_NS,
	SNAKE_STAT_SELECT_LATENCY_MAX_NS,
	SNAKE_STAT_CELL_REHOMES,
	SNAKE_STAT_CELL_REHOME_MISSES,
	SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS,
	SNAKE_STAT_QUEUE_STALE_REHOME_RUNS,
	SNAKE_STAT_QUEUE_BORROW_YIELDS,
	SNAKE_STAT_VTIME_ENQUEUES,
	SNAKE_STAT_VTIME_DISPATCHES,
	SNAKE_STAT_VTIME_CPU_ENQUEUES,
	SNAKE_STAT_VTIME_CPU_DISPATCHES,
	SNAKE_STAT_VTIME_STRICT_PREEMPT_QUEUES,
	SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS,
	SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS,
	SNAKE_STAT_VTIME_CREDIT_CLAMPS,
	SNAKE_STAT_VTIME_ACCOUNTING_ERRORS,
	SNAKE_STAT_VTIME_EQUAL_HEAD_TIES,
	SNAKE_STAT_EEVDF_ELIGIBLE_ENQUEUES,
	SNAKE_STAT_EEVDF_FUTURE_ENQUEUES,
	SNAKE_STAT_EEVDF_PROMOTIONS,
	SNAKE_STAT_EEVDF_FORCED_ADVANCES,
	SNAKE_STAT_EEVDF_DISPATCHES,
	SNAKE_STAT_EEVDF_STRICT_PREEMPT_QUEUES,
	SNAKE_STAT_EEVDF_DIRECT_RUNTIME_NS,
	SNAKE_STAT_EEVDF_QUEUED_RUNTIME_NS,
	SNAKE_STAT_EEVDF_LAG_CLAMPS,
	SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS,
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
