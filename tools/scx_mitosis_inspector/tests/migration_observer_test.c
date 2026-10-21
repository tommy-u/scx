/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
#include "../src/bpf/intf.h"

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define BPF_NOEXIST 1

static int		       migration_counts, migration_failures;
static bool		       exists, race_insert, full;
static u64		       count, failures;
static struct mitosis_cpu_pair stored_pair;

static void *bpf_map_lookup_elem(const void *map, const void *key)
{
	if (map == &migration_failures)
		return &failures;
	assert(map == &migration_counts);
	return exists && !memcmp(key, &stored_pair, sizeof(stored_pair)) ?
		       &count :
		       NULL;
}

static int bpf_map_update_elem(const void *map, const void *key,
			       const void *value, int flags)
{
	assert(map == &migration_counts);
	assert(flags == BPF_NOEXIST);
	if (full)
		return -1;
	stored_pair = *(const struct mitosis_cpu_pair *)key;
	if (race_insert) {
		exists = true;
		count  = 1;
		return -1;
	}
	if (exists)
		return -1;
	exists = true;
	count  = *(const u64 *)value;
	return 0;
}

#include "../src/bpf/migration_observer.bpf.h"

int main(void)
{
	observe_migration(-1, 7);
	observe_migration(3, -1);
	observe_migration(3, 3);
	assert(!exists && failures == 0);
	observe_migration(3, 7);
	assert(exists && stored_pair.from_cpu == 3 && stored_pair.to_cpu == 7 &&
	       count == 1);
	observe_migration(3, 7);
	assert(count == 2 && failures == 0);
	exists	    = false;
	race_insert = true;
	observe_migration(8, 9);
	assert(count == 2 && failures == 0);
	exists	    = false;
	race_insert = false;
	full	    = true;
	observe_migration(10, 11);
	assert(!exists && failures == 1);
	return 0;
}
