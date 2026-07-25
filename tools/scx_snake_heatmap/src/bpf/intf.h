// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __SCX_SNAKE_HEATMAP_INTF_H
#define __SCX_SNAKE_HEATMAP_INTF_H

#ifndef __KERNEL__
typedef unsigned char	   u8;
typedef unsigned int	   u32;
typedef unsigned long long u64;
#endif

enum task_scope_kind {
	TASK_SCOPE_ALL,
	TASK_SCOPE_TGID,
	TASK_SCOPE_CGROUP,
};

enum collector_stat_id {
	COLLECTOR_STAT_PAIR_MAP_FAILURE,
	COLLECTOR_STAT_TASK_STORAGE_FAILURE,
	NR_COLLECTOR_STATS,
};

struct migration_key {
	u32 from_cpu;
	u32 to_cpu;
};

struct collector_config {
	u32 enabled;
	u32 scope_kind;
	u32 generation;
	u32 reserved;
	u64 cgroup_id;
};

#endif /* __SCX_SNAKE_HEATMAP_INTF_H */
