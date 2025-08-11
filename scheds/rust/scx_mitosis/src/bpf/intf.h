// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned long long u64;
typedef unsigned int u32;
typedef _Bool bool;
#endif

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/ravg.bpf.h"
#else
#include <scx/ravg.bpf.h>
#endif

enum consts {
	CACHELINE_SIZE = 64,
	MAX_CPUS_SHIFT = 9,
	MAX_CPUS = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8 = MAX_CPUS / 8,
	MAX_CELLS = 16,
	MAX_L3S = 16,
	USAGE_HALF_LIFE = 100000000, /* 100ms */
	DSQ_ERROR = 0xFFFFFFFF, /* Error value for DSQ functions */

	PCPU_BASE = 1 << 24,
};


/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_CPU_DSQ,
	CSTAT_CELL_DSQ,
	CSTAT_AFFN_VIOL,
	NR_CSTATS,
};

/* Function invocation counters */
enum counter_idx {
	COUNTER_SELECT_CPU,
	COUNTER_ENQUEUE,
	COUNTER_DISPATCH,
	COUNTER_UPDATE_TASK_CPUMASK,
	COUNTER_MAYBE_REFRESH_CELL,
	COUNTER_MAYBE_REFRESH_CELL_TRUE,
	COUNTER_UPDATE_TASK_CELL,
	COUNTER_MITOSIS_CGROUP_MOVE,
	NR_COUNTERS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u32 cell;
	u64 vtime_now;
};

struct cgrp_ctx {
	u32 cell;
	bool cell_owner;
};

/*
 * cell is the per-cell book-keeping
*/
struct cell {
	// current vtime of the cell
	u64 vtime_now;
	// Whether or not the cell is used or not
	u32 in_use;
	// Number of CPUs in this cell
	u32 cpu_cnt;
	// Number of CPUs from each L3 assigned to this cell
	u32 l3_cpu_cnt[MAX_L3S];
	// Number of L3s with at least one CPU in this cell
	u32 l3_present_cnt;
};

struct l3_ctx {
	u64 vtime_now;
};

// BPF DSQ IDs are 64 bits wide.
// Bits: [63] [62 ..  0]
//       [ B] [   ID   ]

// When B is 1, it is a built-in DSQ. And you interpret it like this:
// Bits: [63] [62] [61..32] [31 ..  0]
//       [ 1] [ L] [   R  ] [    V   ]
// Where L is the LOCAL_ON flag. When L is 1, V is the CPU number.

// When B is 0, it's a user defined DSQ. Mitosis only writes the botom 32 bits.
// Bits: [63] [62..32] [31 ..  0]
//       [ 0] [00..00] [   VAL  ]

// When B is 0, We consider it as follows:
// Bits: [31..24] [        23..0        ]
//       [Q-TYPE] [         DATA        ]

// Only 1 bit of Q-TYPE will be set:

// Q-TYPE = 0x1 = Per-CPU Q
// Bits: [ 31..24 ] [ 23..16 ] [15..8] [7..0]
//       [Q-TYPE:1] [ UNUSED ] [   CPU#     ]
//       [00000001] [00000000]

// Q-TYPE = 0x2 =
// Bits: [ 31..24 ] [ 23..16 ] [15..8] [7..0]
//       [Q-TYPE:2] [  CELL# ] [   L3 ID    ]
//       [00000010]

/* DSQ type enumeration */
enum dsq_type {
	DSQ_UNKNOWN,
	DSQ_TYPE_CPU,
	DSQ_TYPE_CELL_L3,
};

/* DSQ ID structure using unions for type-safe access */
struct dsq_cpu {
	u32 cpu : 16;
	u32 unused : 8;
	u32 type : 8;
} __attribute__((packed));

struct dsq_cell_l3 {
	u32 l3 : 16;
	u32 cell : 8;
	u32 type : 8;
} __attribute__((packed));

union dsq_id {
	u32 raw;
	struct dsq_cpu cpu;
	struct dsq_cell_l3 cell_l3;
	struct {
		u32 data : 24;
		u32 type : 8;
	} common;
} __attribute__((packed));

/* Static assertions to ensure correct sizes */
#ifdef __KERNEL__
/* In kernel/BPF context, use BUILD_BUG_ON */
#define STATIC_ASSERT(cond, msg) BUILD_BUG_ON(!(cond))
#else
/* In userspace, use _Static_assert (C11) */
#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* Verify that all DSQ structures are exactly 32 bits */
STATIC_ASSERT(sizeof(struct dsq_cpu) == 4, "dsq_cpu must be 32 bits");
STATIC_ASSERT(sizeof(struct dsq_cell_l3) == 4, "dsq_cell_l3 must be 32 bits");
STATIC_ASSERT(sizeof(union dsq_id) == 4, "dsq_id union must be 32 bits");

/* Inline helper functions for DSQ ID manipulation */

// Is this a per CPU DSQ?
static inline bool is_cpu_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	return id.common.type == DSQ_TYPE_CPU;
}

// Is this a per cell and per l3 dsq?
static inline bool is_cell_l3_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	return id.common.type == DSQ_TYPE_CELL_L3;
}

// Get the Queue type
static inline enum dsq_type queue_type(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type == DSQ_TYPE_CPU)
		return DSQ_TYPE_CPU;
	else if (id.common.type == DSQ_TYPE_CELL_L3)
		return DSQ_TYPE_CELL_L3;
	else
		return DSQ_UNKNOWN; /* Invalid/unknown type */
}

// If this is a per cpu dsq, return the cpu
static inline u32 get_cpu_from_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CPU)
		return DSQ_ERROR;
	return id.cpu.cpu;
}

static inline u32 get_cell(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CELL_L3)
		return DSQ_ERROR;
	return id.cell_l3.cell;
}

static inline u32 get_l3(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CELL_L3)
		return DSQ_ERROR;
	return id.cell_l3.l3;
}

/* Helper functions to construct DSQ IDs */

static inline u32 make_cpu_dsq(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return DSQ_ERROR;
	union dsq_id id = { .cpu = { .cpu = cpu, .unused = 0, .type = DSQ_TYPE_CPU } };
	return id.raw;
}

static inline u32 make_cell_l3_dsq(u32 cell, u32 l3)
{
	if (cell >= MAX_CELLS || l3 >= MAX_L3S)
		return DSQ_ERROR;
	union dsq_id id = { .cell_l3 = {.l3 = l3, .cell = cell, .type = DSQ_TYPE_CELL_L3 } };
	return id.raw;
}

#endif /* __INTF_H */
