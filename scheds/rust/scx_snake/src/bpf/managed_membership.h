/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_MANAGED_MEMBERSHIP_H
#define __SCX_SNAKE_MANAGED_MEMBERSHIP_H

#include "policy_bank.h"
#include "task_state.h"

#define SNAKE_MANAGED_CGROUP_MAX_DEPTH 64

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS);
	__type(key, struct snake_managed_cgroup_key);
	__type(value, struct snake_managed_cgroup_value);
} managed_cgroup_assignments SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SNAKE_LADDER_SLOTS);
	__type(key, u32);
	__type(value, struct snake_managed_cgroup_root);
} managed_cgroup_roots SEC(".maps");

static __always_inline int managed_membership_resolve(
	u32 slot, struct cgroup *cgrp, struct snake_managed_cgroup_root *root,
	struct snake_managed_task_cell *managed)
{
	struct snake_managed_cgroup_key key = { .slot = slot };
	u64 current_cgid;
	u32 depth, i;

	managed->cell_id = 0;
	managed->cell_epoch = 0;
	managed->status = SNAKE_MANAGED_CGROUP_NONE;
	if (!cgrp || !root || !READ_ONCE(root->enabled))
		return 0;
	current_cgid = READ_ONCE(cgrp->kn->id);
	depth = READ_ONCE(cgrp->level);
	bpf_for(i, 0, SNAKE_MANAGED_CGROUP_MAX_DEPTH)
	{
		struct snake_managed_cgroup_value *entry;
		struct cgroup *ancestor;
		u64 ancestor_cgid;
		u32 level;

		if (i > depth)
			break;
		level = depth - i;
		ancestor = bpf_cgroup_ancestor(cgrp, level);
		if (!ancestor)
			return -ENOENT;
		ancestor_cgid = READ_ONCE(ancestor->kn->id);
		key.cgid = ancestor_cgid;
		entry = bpf_map_lookup_elem(&managed_cgroup_assignments, &key);
		if (entry) {
			managed->cell_id = READ_ONCE(entry->cell_id);
			managed->cell_epoch = READ_ONCE(entry->cell_epoch);
			managed->status = READ_ONCE(entry->status);
			bpf_cgroup_release(ancestor);
			return 0;
		}
		bpf_cgroup_release(ancestor);
		if (ancestor_cgid == READ_ONCE(root->cgid)) {
			managed->status = current_cgid == ancestor_cgid ?
				SNAKE_MANAGED_CGROUP_ROOT :
				SNAKE_MANAGED_CGROUP_UNRESOLVED;
			return 0;
		}
	}
	return 0;
}

static __always_inline int
managed_membership_refresh_cgroup_slot(struct task_struct *p, u32 slot,
				       struct cgroup *cgrp)
{
	struct snake_managed_task_cell *managed;
	struct snake_managed_cgroup_root *root;
	u64 cgid;
	u32 old_cell_id, old_cell_epoch;
	int ret;

	if (slot >= SNAKE_LADDER_SLOTS)
		return -EINVAL;
	root = bpf_map_lookup_elem(&managed_cgroup_roots, &slot);
	if (!root)
		return -ENOENT;
	managed = managed_task_cell_lookup(p);
	if (!READ_ONCE(root->enabled)) {
		if (managed) {
			managed->cgid = 0;
			managed->generation = READ_ONCE(root->generation);
			managed->cell_id = 0;
			managed->cell_epoch = 0;
			managed->status = SNAKE_MANAGED_CGROUP_NONE;
		}
		return 0;
	}
	managed = managed_task_cell_get_or_create(p);
	if (!managed)
		return -ENOMEM;
	if (!cgrp)
		return -ENOENT;
	cgid = READ_ONCE(cgrp->kn->id);
	if (READ_ONCE(managed->cgid) == cgid &&
	    READ_ONCE(managed->generation) == READ_ONCE(root->generation))
		return 0;
	old_cell_id = READ_ONCE(managed->cell_id);
	old_cell_epoch = READ_ONCE(managed->cell_epoch);
	ret = managed_membership_resolve(slot, cgrp, root, managed);
	if (ret)
		return ret;
	managed->cgid = cgid;
	managed->generation = READ_ONCE(root->generation);
	managed->pending_since_ns = scx_bpf_now();
	managed->cell0_runtime_ns = 0;
	managed->cell0_timeslices = 0;
	managed->affected = 0;
	managed->uncorrected = 0;
	if (old_cell_id != READ_ONCE(managed->cell_id) ||
	    old_cell_epoch != READ_ONCE(managed->cell_epoch))
		managed->needs_rehome = 1;
	return 0;
}

static __always_inline int
managed_membership_refresh_slot(struct task_struct *p, u32 slot)
{
	struct cgroup *cgrp;
	int ret;

	bpf_rcu_read_lock();
	cgrp = p->cgroups->dfl_cgrp;
	ret = managed_membership_refresh_cgroup_slot(p, slot, cgrp);
	bpf_rcu_read_unlock();
	return ret;
}

static __always_inline int managed_membership_refresh(struct task_struct *p)
{
	s32 slot = active_ladder_slot();

	if (slot < 0)
		return slot;
	return managed_membership_refresh_slot(p, slot);
}

static __always_inline int managed_membership_refresh_current(
	const struct snake_ladder_ctx *ctx, struct task_struct *p)
{
	return managed_membership_refresh_slot(p, ctx->slot);
}

static __always_inline void
managed_membership_account_runtime(const struct snake_ladder_ctx *ctx,
				   struct task_struct *p, u64 runtime_ns)
{
	struct snake_managed_task_cell *managed = managed_task_cell_lookup(p);
	struct snake_task_runtime *runtime = task_state_lookup(p);
	struct snake_task_cell *annotation = task_annotation(p);
	struct snake_queue_cell *run_cell;
	u32 intended_cell_index = 0;
	u32 affected_stat, runtime_stat, timeslice_stat;
	bool mapped;

	if (!managed || !runtime ||
	    (annotation && (READ_ONCE(annotation->flags) &
			       SNAKE_TASK_CELL_F_MANUAL)))
		return;
	if (READ_ONCE(managed->status) != SNAKE_MANAGED_CGROUP_ASSIGNED &&
	    READ_ONCE(managed->status) != SNAKE_MANAGED_CGROUP_UNRESOLVED)
		return;
	run_cell = queue_cell(ctx, READ_ONCE(runtime->run_cell_index));
	if (!run_cell || READ_ONCE(run_cell->external_id) != 0) {
		managed->uncorrected = 0;
		return;
	}
	mapped = READ_ONCE(managed->status) == SNAKE_MANAGED_CGROUP_ASSIGNED;
	if (mapped) {
		runtime_stat = SNAKE_STAT_MANAGED_MAPPED_CELL0_RUNTIME_NS;
		timeslice_stat = SNAKE_STAT_MANAGED_MAPPED_CELL0_TIMESLICES;
		affected_stat = SNAKE_STAT_MANAGED_MAPPED_AFFECTED_TASKS;
	} else {
		runtime_stat = SNAKE_STAT_MANAGED_UNRESOLVED_CELL0_RUNTIME_NS;
		timeslice_stat = SNAKE_STAT_MANAGED_UNRESOLVED_CELL0_TIMESLICES;
		affected_stat = SNAKE_STAT_MANAGED_UNRESOLVED_AFFECTED_TASKS;
	}
	stat_add(ctx, runtime_stat, runtime_ns);
	stat_inc(ctx, timeslice_stat);
	if (mapped && queue_task_cell(ctx, p, &intended_cell_index)) {
		cell_stat_add(ctx, intended_cell_index,
			      SNAKE_CELL_STAT_MANAGED_CELL0_RUNTIME_NS,
			      runtime_ns);
		cell_stat_inc(ctx, intended_cell_index,
			      SNAKE_CELL_STAT_MANAGED_CELL0_TIMESLICES);
	}
	managed->cell0_runtime_ns += runtime_ns;
	managed->cell0_timeslices++;
	if (!READ_ONCE(managed->affected)) {
		stat_inc(ctx, affected_stat);
		if (mapped && queue_task_cell(ctx, p, &intended_cell_index))
			cell_stat_inc(ctx, intended_cell_index,
				      SNAKE_CELL_STAT_MANAGED_AFFECTED_TASKS);
		managed->affected = 1;
	}
	managed->uncorrected = 1;
}

static __always_inline void
managed_membership_exit_task(struct task_struct *p,
			     struct scx_exit_task_args *args)
{
	struct snake_ladder_ctx ctx = {};
	struct snake_managed_task_cell *managed;

	if (args->cancelled)
		return;
	managed = managed_task_cell_lookup(p);
	if (!managed || !READ_ONCE(managed->uncorrected))
		return;
	if (acquire_active_ladder(&ctx))
		return;
	if (READ_ONCE(managed->status) == SNAKE_MANAGED_CGROUP_ASSIGNED)
		stat_inc(&ctx, SNAKE_STAT_MANAGED_MAPPED_UNCORRECTED_EXITS);
	else if (READ_ONCE(managed->status) ==
		 SNAKE_MANAGED_CGROUP_UNRESOLVED)
		stat_inc(&ctx, SNAKE_STAT_MANAGED_UNRESOLVED_EXITS);
	release_active_ladder(&ctx);
}

#endif /* __SCX_SNAKE_MANAGED_MEMBERSHIP_H */
