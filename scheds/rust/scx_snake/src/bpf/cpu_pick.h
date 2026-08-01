/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_SNAKE_CPU_PICK_H
#define __SCX_SNAKE_CPU_PICK_H

#include "bpf_common.h"

static __always_inline s32 cpu_pick_random_idle(const struct cpumask *allowed,
						bool whole_core)
{
	const struct cpumask *idle;
	u32		      candidates = 0, cpu;
	s32		      selected	 = -1;
	bool		      claimed;

	idle = whole_core ? scx_bpf_get_idle_smtmask() :
			    scx_bpf_get_idle_cpumask();
	if (!idle)
		return -EINVAL;
	bpf_for(cpu, 0, SNAKE_MAX_CPUS)
	{
		if (cpu >= nr_cpu_ids)
			break;
		if (bpf_cpumask_test_cpu(cpu, allowed) &&
		    bpf_cpumask_test_cpu(cpu, idle)) {
			candidates++;
			if (bpf_get_prandom_u32() % candidates == 0)
				selected = cpu;
		}
	}
	if (selected < 0) {
		scx_bpf_put_idle_cpumask(idle);
		return -ENOENT;
	}
	claimed = scx_bpf_test_and_clear_cpu_idle(selected);
	scx_bpf_put_idle_cpumask(idle);
	return claimed ? selected : -ENOENT;
}

static __always_inline s32
cpu_pick_idle_prefer_previous(const struct cpumask *candidates, s32 prev_cpu)
{
	const struct cpumask *idle_smtmask;
	bool prev_candidate, whole_core_idle = false;
	s32 cpu;

	if (!candidates)
		return -EINVAL;
	prev_candidate = prev_cpu >= 0 && prev_cpu < nr_cpu_ids &&
			 bpf_cpumask_test_cpu(prev_cpu, candidates);
	idle_smtmask = scx_bpf_get_idle_smtmask();
	if (!idle_smtmask)
		return -EINVAL;
	if (prev_candidate)
		whole_core_idle = bpf_cpumask_test_cpu(prev_cpu, idle_smtmask);
	scx_bpf_put_idle_cpumask(idle_smtmask);
	if (whole_core_idle && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_pick_idle_cpu(candidates, SCX_PICK_IDLE_CORE);
	if (cpu >= 0)
		return cpu;
	if (prev_candidate && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;
	cpu = scx_bpf_pick_idle_cpu(candidates, 0);
	return cpu < 0 ? -ENOENT : cpu;
}

#endif /* __SCX_SNAKE_CPU_PICK_H */
