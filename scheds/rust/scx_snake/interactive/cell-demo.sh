#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

SNAKE_BIN=${SNAKE_BIN:?SNAKE_BIN must point to scx_snake}
SUDO=${SUDO:-sudo}
STATE_DIR=${STATE_DIR:-${XDG_RUNTIME_DIR:-/tmp}/scx-snake-cell-demo-${UID}}
STATE_FILE=${STATE_DIR}/state
POLICY_FILE=${STATE_DIR}/cells.toml
DEMO_INTERVAL=${DEMO_INTERVAL:-2}

green='\033[1;32m'
yellow='\033[0;33m'
reset='\033[0m'

load_state() {
    if [[ ! -r "${STATE_FILE}" ]]; then
        echo "cell demo is not running; use make cell-demo-start" >&2
        exit 1
    fi
    # The state file is generated below and contains only integers and CPU lists.
    source "${STATE_FILE}"
}

cell_cpus() {
    case "$1" in
        0) printf '%s' "${CELL_0}" ;;
        1) printf '%s' "${CELL_1}" ;;
        2) printf '%s' "${CELL_2}" ;;
        *) echo "CELL must be 0, 1, or 2" >&2; exit 1 ;;
    esac
}

wait_for_cell() {
    local cell=$1
    local cpus tid cpu all_inside attempt
    cpus=$(cell_cpus "${cell}")

    for ((attempt = 0; attempt < 100; attempt++)); do
        all_inside=1
        for tid in ${PIDS}; do
            if [[ ! -r "/proc/${tid}/stat" ]]; then
                echo "demo TID ${tid} exited unexpectedly" >&2
                return 1
            fi
            cpu=$(awk '{ print $39 }' "/proc/${tid}/stat")
            if [[ ",${cpus}," != *",${cpu},"* ]]; then
                all_inside=0
                break
            fi
        done
        if (( all_inside )); then
            return 0
        fi
        sleep 0.05
    done

    echo "tasks did not converge to cell ${cell} [${cpus}] within five seconds" >&2
    return 1
}

write_policy() {
    local count half quarter overlap_start
    mapfile -t cpus < <(lscpu -p=CPU,ONLINE | awk -F, '$1 !~ /^#/ && $2 == "Y" { print $1 }' | head -16)
    if (( ${#cpus[@]} < 4 )); then
        echo "cell demo requires at least four online CPUs" >&2
        exit 1
    fi

    count=${#cpus[@]}
    (( count % 2 == 0 )) || ((count--))
    half=$((count / 2))
    quarter=$((half / 2))
    overlap_start=$((half - quarter))
    CELL_0=$(IFS=,; echo "${cpus[*]:0:half}")
    CELL_1=$(IFS=,; echo "${cpus[*]:half:half}")
    CELL_2=$(IFS=,; echo "${cpus[*]:overlap_start:$((quarter * 2))}")
    cat >"${POLICY_FILE}" <<EOF
fallback = "previous_cpu"

[[cell]]
id = 0
cpus = "${CELL_0}"

[[cell]]
id = 1
cpus = "${CELL_1}"

[[cell]]
id = 2
cpus = "${CELL_2}"

[[rung]]
operation = "pick_idle"
scope = "task_cell"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
EOF
}

set_cell() {
    local cell=$1 tid
    local cpus
    cpus=$(cell_cpus "${cell}")
    for tid in ${PIDS}; do
        "${SUDO}" "${SNAKE_BIN}" --set-thread-cell "${tid}:${cell}"
    done
    CURRENT_CELL=${cell}
    sed -i "s/^CURRENT_CELL=.*/CURRENT_CELL=${cell}/" "${STATE_FILE}"
    wait_for_cell "${cell}"
    printf "${green}Moved TIDs %s to cell %s [%s]${reset}\n" "${PIDS}" "${cell}" "${cpus}"
}

status() {
    load_state
    local cpus
    cpus=$(cell_cpus "${CURRENT_CELL}")
    printf "${green}Current cell %s permits CPUs [%s]${reset}\n" "${CURRENT_CELL}" "${cpus}"
    printf '%-10s %-8s %-8s %s\n' TID CPU STATE COMMAND
    ps -o pid=,psr=,stat=,comm= -p ${PIDS} | awk '{ printf "%-10s %-8s %-8s %s\n", $1, $2, $3, $4 }'
}

start() {
    mkdir -p -m 700 "${STATE_DIR}"
    chmod 700 "${STATE_DIR}"
    if [[ -r "${STATE_FILE}" ]]; then
        source "${STATE_FILE}"
        if kill -0 ${PIDS%% *} 2>/dev/null; then
            echo "cell demo is already running with TIDs ${PIDS}" >&2
            exit 1
        fi
    fi

    write_policy
    "${SUDO}" "${SNAKE_BIN}" --update-policy "${POLICY_FILE}"

    nohup bash -c 'while :; do for ((i = 0; i < 20000; i++)); do :; done; sleep 0.01; done' >/dev/null 2>&1 &
    local first=$!
    nohup bash -c 'while :; do for ((i = 0; i < 20000; i++)); do :; done; sleep 0.01; done' >/dev/null 2>&1 &
    local second=$!
    PIDS="${first} ${second}"
    CURRENT_CELL=0
    cat >"${STATE_FILE}" <<EOF
PIDS="${PIDS}"
CELL_0="${CELL_0}"
CELL_1="${CELL_1}"
CELL_2="${CELL_2}"
CURRENT_CELL=${CURRENT_CELL}
EOF
    set_cell 0
    status
}

stop() {
    if [[ ! -r "${STATE_FILE}" ]]; then
        printf "${yellow}Cell demo is not running${reset}\n"
        return
    fi
    load_state
    kill ${PIDS} 2>/dev/null || true
    rm -f "${STATE_FILE}" "${POLICY_FILE}"
    rmdir "${STATE_DIR}" 2>/dev/null || true
    printf "${green}Stopped cell demo tasks${reset}\n"
}

demo() {
    trap stop EXIT INT TERM
    start
    for cell in 1 2 0; do
        sleep "${DEMO_INTERVAL}"
        load_state
        set_cell "${cell}"
        status
    done
}

case "${1:-}" in
    start) start ;;
    move) load_state; set_cell "${CELL:-}" ;;
    status) status ;;
    stop) stop ;;
    demo) demo ;;
    *) echo "usage: $0 {start|move|status|stop|demo}" >&2; exit 2 ;;
esac
