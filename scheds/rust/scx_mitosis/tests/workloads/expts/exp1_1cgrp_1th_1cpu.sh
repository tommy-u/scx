#!/usr/bin/env bash
# Experiment 1: 1 cgroup, 1 thread, 1 CPU — verify it stays put, log total busy (%) for that CPU.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGROUP_CLI="$SCRIPT_DIR/../cgroup_cli.sh"

UNIT_NAME="${UNIT_NAME:-expt1}"
TARGET_CPU="${TARGET_CPU:-8}"   # override via env if desired, e.g. TARGET_CPU=12 ./exp1_1cgrp_1th_1cpu.sh

command -v mpstat >/dev/null || { echo "mpstat not found (install 'sysstat')"; exit 1; }

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "$CGROUP_CLI" stop "$UNIT_NAME" || true
}

trap cleanup EXIT

printf "=== Experiment 1: 1 cgroup, 1 thread, 1 CPU — single thread on CPU %s ===\n" "$TARGET_CPU"
printf "Starting workload:\n"

# Start workload
"$CGROUP_CLI" start "$UNIT_NAME" "$TARGET_CPU" 1

printf "Monitoring. Expect CPU %s ≈ 100%% busy; others mostly idle. Press Ctrl+C to stop.\n\n" "$TARGET_CPU"

# Monitor
"$CGROUP_CLI" util
