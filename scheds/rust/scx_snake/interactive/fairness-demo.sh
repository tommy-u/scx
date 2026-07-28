#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

DURATION=${FAIRNESS_DURATION:-20}
CPU=${FAIRNESS_CPU:-}
WORKERS=()

cleanup() {
    if (( ${#WORKERS[@]} )); then
        kill "${WORKERS[@]}" 2>/dev/null || true
        wait "${WORKERS[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

die() {
    echo "fairness demo: $*" >&2
    exit 1
}

command -v taskset >/dev/null || die "taskset is required"
command -v nice >/dev/null || die "nice is required"
[[ ${DURATION} =~ ^[1-9][0-9]*$ ]] || die "FAIRNESS_DURATION must be a positive integer"

snake_pid=$(pgrep -o -x scx_snake || true)
[[ -n ${snake_pid} ]] || die "start Snake with 'make start FAIRNESS=vtime' first"
snake_args=$(tr '\0' ' ' <"/proc/${snake_pid}/cmdline" 2>/dev/null || true)
if [[ " ${snake_args} " == *" --fairness vtime "* ]]; then
    FAIRNESS_MODE=vtime
elif [[ " ${snake_args} " == *" --fairness eevdf "* ]]; then
    FAIRNESS_MODE=eevdf
else
    die "the running Snake instance must use --fairness vtime or eevdf"
fi

if [[ -z ${CPU} ]]; then
    CPU=$(lscpu -p=CPU,ONLINE | awk -F, '$1 !~ /^#/ && $2 == "Y" { print $1; exit }')
fi
[[ ${CPU} =~ ^[0-9]+$ ]] || die "FAIRNESS_CPU must be an online CPU number"
[[ -d /sys/devices/system/cpu/cpu${CPU} ]] || die "CPU ${CPU} does not exist"
if [[ -r /sys/devices/system/cpu/cpu${CPU}/online ]] &&
    [[ $(<"/sys/devices/system/cpu/cpu${CPU}/online") != 1 ]]; then
    die "CPU ${CPU} is offline"
fi

ticks() {
    local pid=$1
    awk '{ line=$0; sub(/^[^(]*\([^)]*\) /, "", line); split(line, field, " "); print field[12] + field[13] }' \
        "/proc/${pid}/stat"
}

start_worker() {
    local nice_level=$1
    taskset -c "${CPU}" nice -n "${nice_level}" yes >/dev/null &
    WORKERS+=("$!")
}

ratio() {
    awk -v numerator="$1" -v denominator="$2" 'BEGIN {
        if (denominator <= 0) exit 1;
        printf "%.4f", numerator / denominator;
    }'
}

within_fraction() {
    awk -v actual="$1" -v expected="$2" -v tolerance="$3" 'BEGIN {
        low = expected * (1 - tolerance);
        high = expected * (1 + tolerance);
        exit !(actual >= low && actual <= high);
    }'
}

run_case() {
    local label=$1
    shift
    local nice_levels=("$@") starts=() deltas=() pid start end i

    WORKERS=()
    for i in "${nice_levels[@]}"; do
        start_worker "${i}"
    done
    sleep 1
    for pid in "${WORKERS[@]}"; do
        starts+=("$(ticks "${pid}")")
    done
    sleep "${DURATION}"
    for i in "${!WORKERS[@]}"; do
        pid=${WORKERS[$i]}
        start=${starts[$i]}
        end=$(ticks "${pid}")
        deltas+=("$((end - start))")
    done
    cleanup
    WORKERS=()
    CASE_DELTAS=("${deltas[@]}")
    printf '%-28s nice=%-10s ticks=%s\n' "${label}" "${nice_levels[*]}" "${deltas[*]}"
}

printf 'Snake %s fairness demo: CPU %s, %ss measured per case\n' \
    "${FAIRNESS_MODE^^}" "${CPU}" "${DURATION}"

run_case "equal weights" 0 0
equal_ratio=$(ratio "${CASE_DELTAS[0]}" "${CASE_DELTAS[1]}") || die "equal-weight task made no progress"
within_fraction "${equal_ratio}" 1 0.15 ||
    die "equal-weight ratio ${equal_ratio} is outside 1.0 +/-15%"

run_case "nice 0 vs nice 5" 0 5
weighted_ratio=$(ratio "${CASE_DELTAS[0]}" "${CASE_DELTAS[1]}") || die "nice 5 task made no progress"
expected_ratio=$(awk 'BEGIN { printf "%.4f", 1024 / 335 }')
within_fraction "${weighted_ratio}" "${expected_ratio}" 0.20 ||
    die "nice 0:nice 5 ratio ${weighted_ratio} is outside ${expected_ratio} +/-20%"

run_case "third low-weight task" 0 5 19
three_ratio=$(ratio "${CASE_DELTAS[0]}" "${CASE_DELTAS[1]}") || die "nice 5 task made no progress"
(( CASE_DELTAS[2] > 0 )) || die "nice 19 task made no progress"
within_fraction "${three_ratio}" "${expected_ratio}" 0.25 ||
    die "nice 0:nice 5 ratio ${three_ratio} with a nice 19 peer is outside ${expected_ratio} +/-25%"

printf 'PASS equal=%s weighted=%s weighted-with-peer=%s expected-weighted=%s\n' \
    "${equal_ratio}" "${weighted_ratio}" "${three_ratio}" "${expected_ratio}"
