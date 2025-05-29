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
	USAGE_HALF_LIFE = 100000000, /* 100ms */

	HI_FALLBACK_DSQ = MAX_CELLS,
	LO_FALLBACK_DSQ = MAX_CELLS + 1,
};

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_GLOBAL,
	CSTAT_AFFN_VIOL,
	NR_CSTATS,
};

enum cell_queue_idx {
	LO_FALLBACK_DSQ_IDX,
	HI_FALLBACK_DSQ_IDX,
	DEFAULT_DSQ_IDX,
};

struct cell_queue_counters {
	u64 lo_fallback_count;
	u64 hi_fallback_count;
	u64 default_count;
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	struct cell_queue_counters queue_counters[MAX_CELLS];
	u32 prev_cell;
	u32 cell;
};

struct cgrp_ctx {
	u32 cell;
	bool cell_owner;
};

#endif /* __INTF_H */
