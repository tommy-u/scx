#ifndef __MITOSIS_COMMON_BPF_H
#define __MITOSIS_COMMON_BPF_H

#include "intf.h"

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#endif

/*
 * A couple of tricky things about checking a cgroup's cpumask:
 *
 * First, we need an RCU pointer to pass to cpumask kfuncs. The only way to get
 * this right now is to copy the cpumask to a map entry. Given that cgroup init
 * could be re-entrant we have a few per-cpu entries in a map to make this
 * doable.
 *
 * Second, cpumask can sometimes be stored as an array in-situ or as a pointer
 * and with different lengths. Some bpf_core_type_matches finagling can make
 * this all work.
 */
#define MAX_CPUMASK_ENTRIES (4)

/*
 * We don't know how big struct cpumask is at compile time, so just allocate a
 * large space and check that it is big enough at runtime
 */
#define CPUMASK_LONG_ENTRIES (128)
#define CPUMASK_SIZE (sizeof(long) * CPUMASK_LONG_ENTRIES)

/* These are needed by l3_aware.c */
static inline struct cell *lookup_cell(int idx);
static inline const struct cpumask *lookup_cell_cpumask(int idx);

enum mitosis_constants {
	/* Default weight divisor for vtime calculation */
	DEFAULT_WEIGHT_MULTIPLIER = 100,

	/* Root cell index */
	ROOT_CELL_ID = 0,

	/* Root cgroup kernel ID */
	ROOT_CGROUP_ID = 1,

	/* Invalid/unset L3 value */
	INVALID_L3_ID = -1,

	/* Vtime validation multiplier (slice_ns * 8192) */
	VTIME_MAX_FUTURE_MULTIPLIER = 8192,

	/* Bits per u32 for cpumask operations */
	BITS_PER_U32 = 32,

	/* No NUMA constraint for DSQ creation */
	ANY_NUMA = -1,
};

#endif /* __MITOSIS_COMMON_BPF_H */
