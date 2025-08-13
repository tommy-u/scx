#!/usr/bin/env bash
# cgroup_cli.sh — start/stop N busy loops in transient systemd units bound to CPU sets.
# Usage:
#   ./cgroup_cli.sh start <unit_name> <cpuspec> <nthreads> [memnodes]   # e.g. "group1" "24-31" 8 [0]
#   ./cgroup_cli.sh stop  [unit_name|all]                                # stop specific unit or all mito-spin-* units
#   ./cgroup_cli.sh status [unit_name|all]                               # show status of specific unit or all
#   ./cgroup_cli.sh list                                                 # list all running mito-spin-* units
# Notes:
# - cpuspec uses cpuset syntax: "0-7,16,18".
# - memnodes is optional (e.g. "0" or "0-1") and sets AllowedMemoryNodes.
# - unit names will be prefixed with "mito-spin-" to avoid conflicts
set -euo pipefail

UNIT_PREFIX="mito-spin"

start_service() {
    local unit_name=${1:?unit name required}
    local cpus=${2:?cpuspec required}
    local n=${3:?nthreads required}
    local mem=${4:-}

    local full_unit="$UNIT_PREFIX-$unit_name"

    # Build systemd-run args
    local args=(--unit="$full_unit" -p "AllowedCPUs=$cpus" -p "Environment=N=$n" --collect)
    [[ -n "$mem" ]] && args+=(-p "AllowedMemoryNodes=$mem")

    # If an old unit exists, stop it quietly
    sudo systemctl stop "$full_unit".service >/dev/null 2>&1 || true

    # Start a transient service that launches $N infinite busy loops and then sleeps forever
    sudo systemd-run "${args[@]}" bash -lc \
      'for i in $(seq 1 "$N"); do while :; do :; done & done; exec sleep infinity'

    echo "Started $full_unit.service on CPUs [$cpus] with $n spinner(s)${mem:+, memnodes [$mem]}."
    echo "Stop with: $0 stop $unit_name"
}

stop_service() {
    local unit_name=${1:-}

    if [[ "$unit_name" == "all" ]]; then
        # Stop all mito-spin-* units
        local units
        units=$(systemctl list-units --type=service --state=active --no-legend | grep "^$UNIT_PREFIX-" | awk '{print $1}' || true)
        if [[ -z "$units" ]]; then
            echo "No active $UNIT_PREFIX-* units found"
            return 0
        fi

        echo "Stopping all $UNIT_PREFIX-* units..."
        for unit in $units; do
            sudo systemctl stop "$unit"
            echo "Stopped $unit"
        done
    elif [[ -n "$unit_name" ]]; then
        # Stop specific unit
        local full_unit="$UNIT_PREFIX-$unit_name"
        sudo systemctl stop "$full_unit".service
        echo "Stopped $full_unit.service"
    else
        echo "Error: unit name required. Use 'all' to stop all $UNIT_PREFIX-* units"
        exit 1
    fi
}

show_status() {
    local unit_name=${1:-}

    if [[ "$unit_name" == "all" ]]; then
        # Show status of all mito-spin-* units
        local units
        units=$(systemctl list-units --type=service --no-legend | grep "^$UNIT_PREFIX-" | awk '{print $1}' || true)
        if [[ -z "$units" ]]; then
            echo "No $UNIT_PREFIX-* units found"
            return 0
        fi

        for unit in $units; do
            echo "=== Status of $unit ==="
            systemctl status "$unit" --no-pager || true
            echo
        done
    elif [[ -n "$unit_name" ]]; then
        # Show status of specific unit
        local full_unit="$UNIT_PREFIX-$unit_name"
        systemctl status "$full_unit".service --no-pager
    else
        echo "Error: unit name required. Use 'all' to show status of all $UNIT_PREFIX-* units"
        exit 1
    fi
}

list_services() {
    echo "Active $UNIT_PREFIX-* units:"
    systemctl list-units --type=service --state=active --no-legend | grep "^$UNIT_PREFIX-" || echo "No active $UNIT_PREFIX-* units found"
    echo
    echo "All $UNIT_PREFIX-* units (including inactive):"
    systemctl list-units --type=service --all --no-legend | grep "^$UNIT_PREFIX-" || echo "No $UNIT_PREFIX-* units found"
}

show_usage() {
    echo "Usage: $0 {start|stop|status|list} …"
    echo "  start <unit_name> <cpuspec> <nthreads> [memnodes]"
    echo "  stop  <unit_name|all>"
    echo "  status <unit_name|all>"
    echo "  list"
    echo ""
    echo "Examples:"
    echo "  $0 start group1 0-3 4        # Start group1 with 4 threads on CPUs 0-3"
    echo "  $0 start group2 4-7 2 0      # Start group2 with 2 threads on CPUs 4-7, memory node 0"
    echo "  $0 stop group1               # Stop group1"
    echo "  $0 stop all                  # Stop all mito-spin-* units"
    echo "  $0 status all                # Show status of all units"
    echo "  $0 list                      # List all units"
    exit 1
}

case "${1:-}" in
  start)
    start_service "${2:-}" "${3:-}" "${4:-}" "${5:-}"
    ;;
  stop)
    stop_service "${2:-}"
    ;;
  status)
    show_status "${2:-}"
    ;;
  list)
    list_services
    ;;
  *)
    show_usage
    ;;
esac
