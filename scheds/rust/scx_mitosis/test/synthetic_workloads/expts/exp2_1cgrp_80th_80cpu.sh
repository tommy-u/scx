#!/usr/bin/env bash
# Experiment 2: 1 cgroup, 80 threads, 80 cores — verify threads spread across all cores
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGROUP_CLI="$SCRIPT_DIR/../cgroup_cli.sh"

UNIT_NAME="${UNIT_NAME:-expt2}"
TARGET_CPU="${TARGET_CPU:-0-79}"   # override via env if desired, e.g. TARGET_CPU=0-63 ./exp2_1cgrp_80th80cores.sh

command -v mpstat >/dev/null || { echo "mpstat not found (install 'sysstat')"; exit 1; }

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "$CGROUP_CLI" stop "$UNIT_NAME" || true
}

trap cleanup EXIT

printf "=== Experiment 2: 1 cgroup, 80 threads, 80 cores — threads across CPUs %s ===\n" "$TARGET_CPU"
printf "Starting workload:\n"

# Start workload
"$CGROUP_CLI" start "$UNIT_NAME" "$TARGET_CPU" 80

printf "Monitoring. Expect CPUs %s to show distributed load. Press Ctrl+C to stop.\n\n" "$TARGET_CPU"

# Monitor
"$CGROUP_CLI" monitor
