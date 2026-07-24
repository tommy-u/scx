/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_LADDER_H
#define __SCX_SNAKE_LADDER_H

#include "mask_table.h"

/* Validate that a rung uses the supported mechanical ABI. */
static __always_inline bool rung_is_valid(const struct snake_rung *rung)
{
	if (rung->reserved)
		return false;

	return (rung->opcode == SNAKE_OP_CLAIM_IDLE && !rung->flags &&
		rung->input == SNAKE_INPUT_CPU_PREV && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE && !rung->flags &&
		rung->input == SNAKE_INPUT_MASK_TASK_ALLOWED && !rung->data) ||
	       (rung->opcode == SNAKE_OP_PICK_IDLE_MASK_TABLE &&
		rung->input == SNAKE_INPUT_CPU_PREV &&
		rung->flags == SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED &&
		rung->data < nr_mask_tables);
}

/* Execute one validated rung and return an idle CPU or a miss. */
static __always_inline s32 execute_rung(const struct task_struct *p,
					const struct snake_rung	 *rung,
					s32			  prev_cpu)
{
	switch (rung->opcode) {
	case SNAKE_OP_CLAIM_IDLE:
		/* Affinity is checked before the destructive idle claim. */
		if (prev_cpu >= 0 && prev_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		break;
	case SNAKE_OP_PICK_IDLE:
		prev_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		return prev_cpu < 0 ? -ENOENT : prev_cpu;
	case SNAKE_OP_PICK_IDLE_MASK_TABLE:
		return pick_idle_from_mask_table(p, rung->data, prev_cpu);
	default:
		break;
	}

	return -ENOENT;
}

/* Evaluate the configured rungs in order until one returns a valid hint. */
static __always_inline s32 walk_policy_ladder(const struct task_struct *p,
					      s32 prev_cpu)
{
	u32 i;

	bpf_for(i, 0, SNAKE_MAX_RUNGS)
	{
		struct snake_rung rung;
		s32		  cpu;

		if (i >= nr_rungs)
			break;

		rung = rungs[i];
		stat_inc(SNAKE_STAT_RUNG_ATTEMPT_BASE + i);

		if (!rung_is_valid(&rung)) {
			stat_inc(SNAKE_STAT_RUNG_ERROR_BASE + i);
			stat_inc(SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake invalid rung %u: opcode=%u input=%u", i,
				rung.opcode, rung.input);
			return -1;
		}

		cpu = execute_rung(p, &rung, prev_cpu);
		if (cpu < 0 && cpu != -ENOENT) {
			stat_inc(SNAKE_STAT_RUNG_ERROR_BASE + i);
			stat_inc(SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error("snake rung %u execution failed: %d", i,
				      cpu);
			return cpu;
		}
		if (cpu >= 0 && cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			stat_inc(SNAKE_STAT_RUNG_HIT_BASE + i);
			return cpu;
		}

		stat_inc(SNAKE_STAT_RUNG_MISS_BASE + i);
	}

	return -ENOENT;
}

#endif /* __SCX_SNAKE_LADDER_H */
