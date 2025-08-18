#!/usr/bin/env bash
# Experiment 4: 1 cgroup, 1 thread, 16 CPUs — single thread can migrate across L3 cache boundaries
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGROUP_CLI="$SCRIPT_DIR/../cgroup_cli.sh"

UNIT_NAME="${UNIT_NAME:-expt4}"
TARGET_CPU="${TARGET_CPU:-0-16}"   # override via env if desired, e.g. TARGET_CPU=0-15 ./exp4_1cgrp_1th_16cpu_crossl3.sh

command -v mpstat >/dev/null || { echo "mpstat not found (install 'sysstat')"; exit 1; }

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "$CGROUP_CLI" stop "$UNIT_NAME" || true
}

trap cleanup EXIT

printf "=== Experiment 4: 1 cgroup, 1 thread, 16 CPUs — single thread on CPUs %s ===\n" "$TARGET_CPU"
printf "Starting workload:\n"

# Start workload
"$CGROUP_CLI" start "$UNIT_NAME" "$TARGET_CPU" 1

printf "Monitoring. Single thread can migrate across CPUs %s. Press Ctrl+C to stop.\n\n" "$TARGET_CPU"

# Monitor
"$CGROUP_CLI" monitor
