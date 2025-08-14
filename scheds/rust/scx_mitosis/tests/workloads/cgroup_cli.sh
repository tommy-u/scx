#!/usr/bin/env bash
# cgroup_cli.sh — start/stop N busy loops in transient systemd units bound to CPU sets.
# Usage:
#   ./cgroup_cli.sh start <unit_name> <cpuspec> <nthreads>
#   ./cgroup_cli.sh stop  [unit_name|all]
#   ./cgroup_cli.sh status [unit_name|all]
#   ./cgroup_cli.sh list
#   ./cgroup_cli.sh util
# Notes:
# - cpuspec uses cpuset syntax: "0-7,16,18".
# - unit names are prefixed with "mito-spin-".
set -euo pipefail

UNIT_PREFIX="mito-spin"

ensure_cpuset() {
  # Require cpuset controller under cgroup v2
  local ctrls="/sys/fs/cgroup/cgroup.controllers"
  if [[ ! -r "$ctrls" ]] || ! grep -qw cpuset "$ctrls"; then
    echo "Error: cpuset controller not available (cgroup v2). Enable cpuset on your systemd hierarchy." >&2
    exit 2
  fi
}

unit_pat() {
  # Build a systemctl pattern like: mito-spin-<name>.service  (or mito-spin-*.service)
  local name="${1:-*}"
  [[ "$name" == "all" || -z "$name" ]] && name="*"
  printf '%s-%s.service' "$UNIT_PREFIX" "$name"
}

start_service() {
  local name=${1:?unit name required}
  local cpus=${2:?cpuspec required}
  local n=${3:?nthreads required}

  ensure_cpuset

  [[ "$name" == "all" ]] && { echo "Error: 'all' is not a valid unit name."; exit 2; }
  [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] || { echo "Error: nthreads must be a positive integer."; exit 2; }

  local unit; unit=$(unit_pat "$name")   # e.g., mito-spin-foo.service

  # Stop any stale instance quietly
  sudo systemctl stop "$unit" >/dev/null 2>&1 || true

  # Build properties
  local props=(-p "AllowedCPUs=$cpus" --collect)

  # Launch N busy loops and sleep forever
  sudo systemd-run \
    --unit="$unit" \
    "${props[@]}" \
    -E N="$n" \
    bash -lc '
      for i in $(seq 1 "$N"); do
        while :; do :; done &
      done
      exec sleep infinity
    '

  echo "Started $unit on CPUs [$cpus] with $n spinner(s)."
}

stop_service() {
  local pat; pat=$(unit_pat "${1:-all}")
  sudo systemctl stop "$pat" || true
}

status_service() {
  local pat; pat=$(unit_pat "${1:-all}")
  systemctl --no-pager status "$pat" || true
}

list_services() {
  local pat; pat=$(unit_pat '*')
  echo "Active:"
  systemctl --no-pager list-units --type=service --state=active --plain --no-legend "$pat" || echo "  (none)"
  echo "All:"
  systemctl --no-pager list-units --type=service --all --plain --no-legend "$pat" || echo "  (none)"
}

mpstat_util() {
  mpstat --dec=0 -P ALL 1
}

usage() {
  cat <<EOF
Usage:
  $0 start  <unit_name> <cpuspec> <nthreads>
  $0 stop   [unit_name|all]
  $0 status [unit_name|all]
  $0 list
  $0 util
Notes:
  - cpuspec like "0-7,16,18" (cpuset syntax).
  - unit name is prefixed with "$UNIT_PREFIX-".
EOF
}

case "${1:-}" in
  start)  start_service "${2:-}" "${3:-}" "${4:-}";;
  stop)   stop_service "${2:-all}";;
  status) status_service "${2:-all}";;
  list)   list_services;;
  util) mpstat_util;;
  *)      usage; exit 1;;
esac
