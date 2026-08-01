/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_SCHEDULER_EVENTS_BPF_H
#define __SCX_MITOSIS_INSPECTOR_SCHEDULER_EVENTS_BPF_H

#include <scx/common.bpf.h>
#include <bpf/bpf_tracing.h>

struct scheduler_event_metrics {
	u64 context_switches;
	u64 preemptions;
	u64 blocked_switches;
	u64 voluntary_switches;
	u64 wakeups;
	u64 new_task_wakeups;
	u64 task_forks;
	u64 task_execs;
	u64 task_exits;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct scheduler_event_metrics);
} scheduler_event_metrics SEC(".maps");

static __always_inline struct scheduler_event_metrics *
scheduler_event_lookup_metrics(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&scheduler_event_metrics, &key);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(scheduler_event_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	struct scheduler_event_metrics *metrics;

	metrics = scheduler_event_lookup_metrics();
	if (!metrics)
		return 0;

	metrics->context_switches++;
	if (preempt)
		metrics->preemptions++;
	else if (prev_state)
		metrics->blocked_switches++;
	else
		metrics->voluntary_switches++;
	return 0;
}

static __always_inline int scheduler_event_record_wakeup(bool new_task)
{
	struct scheduler_event_metrics *metrics;

	metrics = scheduler_event_lookup_metrics();
	if (!metrics)
		return 0;
	metrics->wakeups++;
	if (new_task)
		metrics->new_task_wakeups++;
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(scheduler_event_wakeup, struct task_struct *p)
{
	return scheduler_event_record_wakeup(false);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(scheduler_event_wakeup_new, struct task_struct *p)
{
	return scheduler_event_record_wakeup(true);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(scheduler_event_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	struct scheduler_event_metrics *metrics;

	metrics = scheduler_event_lookup_metrics();
	if (metrics)
		metrics->task_forks++;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(scheduler_event_exec, struct task_struct *p, u32 old_pid,
	     struct linux_binprm *prm)
{
	struct scheduler_event_metrics *metrics;

	metrics = scheduler_event_lookup_metrics();
	if (metrics)
		metrics->task_execs++;
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(scheduler_event_exit, struct task_struct *task)
{
	struct scheduler_event_metrics *metrics;

	metrics = scheduler_event_lookup_metrics();
	if (metrics)
		metrics->task_exits++;
	return 0;
}

#endif /* __SCX_MITOSIS_INSPECTOR_SCHEDULER_EVENTS_BPF_H */
