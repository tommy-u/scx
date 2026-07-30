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

#endif /* __SCX_SNAKE_CPU_PICK_H */
