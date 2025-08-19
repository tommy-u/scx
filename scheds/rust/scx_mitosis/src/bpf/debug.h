static inline u32 get_l3(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CELL_L3)
		return DSQ_ERROR;
	return id.cell_l3.l3;
}

static inline u32 get_cell(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CELL_L3)
		return DSQ_ERROR;
	return id.cell_l3.cell;
}

// Get the Queue type
static inline enum dsq_type queue_type(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type == DSQ_TYPE_CPU)
		return DSQ_TYPE_CPU;
	else if (id.common.type == DSQ_TYPE_CELL_L3)
		return DSQ_TYPE_CELL_L3;
	else
		return DSQ_UNKNOWN; /* Invalid/unknown type */
}

// Is this a per cell and per l3 dsq?
static inline bool is_cell_l3_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	return id.common.type == DSQ_TYPE_CELL_L3;
}

/* Debug helper to decode and print DSQ components */
static void debug_print_dsq(u32 dsq_id, const char *action)
{
	if (is_cpu_dsq(dsq_id)) {
		u32 cpu = get_cpu_from_dsq(dsq_id);
		bpf_printk("%s CPU_DSQ(cpu=%u) raw=%u", action, cpu, dsq_id);
	} else if (is_cell_l3_dsq(dsq_id)) {
		u32 cell = get_cell(dsq_id);
		u32 l3 = get_l3(dsq_id);
		bpf_printk("%s CELL_L3_DSQ(cell=%u,l3=%u) raw=%u", action, cell,
			   l3, dsq_id);
	} else {
		bpf_printk("%s UNKNOWN_DSQ raw=%u", action, dsq_id);
	}
}

static inline u32 cell_dsq(u32 cell)
{
	return cell;
}

static inline u32 dsq_to_cell(u32 dsq)
{
	return dsq;
}

static inline bool is_pcpu(u32 dsq)
{
	return is_cpu_dsq(dsq);
}

PCPU_BASE = 1 << 24,
