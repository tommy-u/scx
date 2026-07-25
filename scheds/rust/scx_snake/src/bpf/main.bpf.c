/* SPDX-License-Identifier: GPL-2.0-only */
#include "main.h"
#include "ladder.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u32		 policy_abi_version;
const volatile u32		 nr_rungs;
const volatile u32		 nr_mask_tables;
const volatile u32		 fallback_mode;
const volatile struct snake_rung rungs[SNAKE_MAX_RUNGS];

/* Run the policy ladder, then use its affinity-safe exhaustion fallback. */
s32 BPF_STRUCT_OPS(snake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	u64 started_at = bpf_ktime_get_ns();
	s32 cpu;

	(void)wake_flags;
	stat_inc(SNAKE_STAT_SELECT_CALLS);

	cpu = walk_policy_ladder(p, prev_cpu);
	if (cpu >= 0) {
		if (!scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0)) {
			stat_inc(SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake failed to dispatch pid %d to idle CPU %d",
				p->pid, cpu);
			return -1;
		}
		stat_inc(SNAKE_STAT_DIRECT_DISPATCHES);
		finish_select(started_at);
		return cpu;
	}
	if (cpu != -ENOENT)
		return cpu;

	stat_inc(SNAKE_STAT_LADDER_EXHAUSTIONS);
	cpu = fallback_cpu(p, prev_cpu);
	if (cpu < 0)
		return cpu;
	finish_select(started_at);
	return cpu;
}

void BPF_STRUCT_OPS(snake_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(SNAKE_STAT_ENQUEUES);
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(snake_running, struct task_struct *p)
{
	(void)p;
	stat_inc(SNAKE_STAT_RUNNING);
}

void BPF_STRUCT_OPS(snake_stopping, struct task_struct *p, bool runnable)
{
	(void)p;
	(void)runnable;
	stat_inc(SNAKE_STAT_STOPPING);
}

void BPF_STRUCT_OPS(snake_quiescent, struct task_struct *p, u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
	stat_inc(SNAKE_STAT_QUIESCENT);
}

/* Validate immutable policy state before the scheduler can attach. */
s32 BPF_STRUCT_OPS_SLEEPABLE(snake_init)
{
	u32 i;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (policy_abi_version != SNAKE_ABI_VERSION) {
		stat_inc(SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake policy ABI mismatch: got %u expected %u",
			      policy_abi_version, SNAKE_ABI_VERSION);
		return -EINVAL;
	}
	if (!nr_rungs || nr_rungs > SNAKE_MAX_RUNGS) {
		stat_inc(SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake invalid rung count %u", nr_rungs);
		return -EINVAL;
	}
	if (fallback_mode != SNAKE_FALLBACK_PREVIOUS_CPU &&
	    fallback_mode != SNAKE_FALLBACK_ANY_ALLOWED) {
		stat_inc(SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake invalid fallback mode %u", fallback_mode);
		return -EINVAL;
	}
	if (init_mask_tables()) {
		stat_inc(SNAKE_STAT_INVALID_ERRORS);
		scx_bpf_error("snake failed to initialize %u mask tables",
			      nr_mask_tables);
		return -EINVAL;
	}

	bpf_for(i, 0, SNAKE_MAX_RUNGS)
	{
		struct snake_rung rung;

		if (i >= nr_rungs)
			break;
		rung = rungs[i];
		if (!rung_is_valid(&rung)) {
			stat_inc(SNAKE_STAT_INVALID_ERRORS);
			scx_bpf_error(
				"snake invalid startup rung %u: opcode=%u input=%u",
				i, rung.opcode, rung.input);
			return -EINVAL;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(snake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(snake_ops, .select_cpu = (void *)snake_select_cpu,
	       .enqueue	  = (void *)snake_enqueue,
	       .running	  = (void *)snake_running,
	       .stopping  = (void *)snake_stopping,
	       .quiescent = (void *)snake_quiescent, .init = (void *)snake_init,
	       .exit = (void *)snake_exit, .timeout_ms = 5000, .name = "snake");
