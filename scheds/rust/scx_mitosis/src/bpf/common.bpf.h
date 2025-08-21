// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __MITOSIS_COMMON_BPF_H
#define __MITOSIS_COMMON_BPF_H

#include "intf.h"



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


#endif /* __MITOSIS_BPF_H */
