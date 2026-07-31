/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_MITOSIS_INSPECTOR_INTF_H
#define __SCX_MITOSIS_INSPECTOR_INTF_H

#define MITOSIS_CALLBACK_TIMING_BUCKETS 64

struct mitosis_callback_timing {
	u64 total_ns;
	u64 buckets[MITOSIS_CALLBACK_TIMING_BUCKETS];
};

struct mitosis_cpu_pair {
	u32 from_cpu;
	u32 to_cpu;
};

#endif /* __SCX_MITOSIS_INSPECTOR_INTF_H */
