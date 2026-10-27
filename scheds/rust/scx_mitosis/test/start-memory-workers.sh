#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Launch one collection for Mitosis placement/profile experiments.
set -euo pipefail
export LC_ALL=C

usage() {
    cat <<'EOF'
Usage: start-memory-workers.sh [--pin-workers-to-llcs] [--double-workers] [DURATION]
       start-memory-workers.sh --help

Launch nine identical memory jobs, mem-a through mem-i, in one unique
experiment slice below /workload.slice/workload-tw.slice. Each job runs one
stress-ng randlist worker with a private 24 MiB list and memory bound to NUMA
node 0. The experiment slice is restricted to all online CPUs outside LLC 0.
Workers can move freely among those CPUs. LLC 0 remains available to cell 0.
With --pin-workers-to-llcs, each job is restricted to a different nonzero LLC,
in ascending LLC ID order. CPUs within that LLC remain interchangeable.
--double-workers runs two randlist workers per job (18 total), each with its
own 24 MiB list. In pinned mode, both workers share the job's assigned LLC.

DURATION is a positive integer, optionally followed by s, m, h, or d.
A bare integer means seconds. Default: 4h (four hours).

Run as your normal user with sudo access. The launcher stays in the foreground.
Ctrl+C stops this collection. Logs and manifest.tsv are retained in the printed
run directory; temporary executable aliases and working directories are removed.
Use the same launcher for parent-mode and learned-subcell Mitosis runs.

Examples:
  ./start-memory-workers.sh
  ./start-memory-workers.sh 4h
  ./start-memory-workers.sh 120s
  ./start-memory-workers.sh --pin-workers-to-llcs 120s
  ./start-memory-workers.sh --pin-workers-to-llcs --double-workers 120s
EOF
}

die() {
    printf 'start-memory-workers: %s\n' "$*" >&2
    exit 1
}

pin_workers_to_llcs=0
randlist_workers_per_job=1
duration=4h
duration_set=0
for argument in "$@"; do
    case $argument in
        --help) usage; exit 0 ;;
        --pin-workers-to-llcs) pin_workers_to_llcs=1 ;;
        --double-workers) randlist_workers_per_job=2 ;;
        --*) die "unknown argument: $argument; use --help" ;;
        *)
            (( duration_set == 0 )) || die 'expected at most one duration argument; use --help'
            duration=$argument
            duration_set=1
            ;;
    esac
done
[[ $duration =~ ^([0-9]+)([smhd]?)$ ]] || die "invalid duration: $duration"
amount=${BASH_REMATCH[1]}
suffix=${BASH_REMATCH[2]}
amount=${amount#"${amount%%[!0]*}"}
[[ -n $amount ]] || die 'duration must be greater than zero'
case $suffix in
    ''|s) multiplier=1 ;;
    m) multiplier=60 ;;
    h) multiplier=3600 ;;
    d) multiplier=86400 ;;
esac
# RuntimeMaxSec uses an unsigned 64-bit microsecond value. Reserve its 60s grace.
maximum=$(( (18446744073709 - 60) / multiplier ))
if (( ${#amount} > ${#maximum} )) ||
    { (( ${#amount} == ${#maximum} )) && (( 10#$amount > maximum )); }; then
    die 'duration is too large for the service runtime limit'
fi
duration_seconds=$(( 10#$amount * multiplier ))
runtime_max_seconds=$(( duration_seconds + 60 ))

(( BASH_VERSINFO[0] > 5 ||
   (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )) ||
    die 'Bash 5.1 or newer is required for concurrent worker supervision'
(( EUID != 0 )) || die 'run as your normal user; the launcher uses sudo as needed'

declare -A tools=()
for dependency in sudo systemd-run systemctl numactl stress-ng timeout mktemp \
    readlink mkdir ln rm sleep date id hostname kill; do
    tools[$dependency]=$(type -P "$dependency") || die "missing required command: $dependency"
done
[[ -d /run/systemd/system && -f /sys/fs/cgroup/cgroup.controllers ]] ||
    die 'a running system systemd manager and cgroup v2 are required'
[[ -d /sys/devices/system/node/node0 ]] || die 'NUMA memory node 0 is unavailable'
"${tools[sudo]}" -n true || die 'sudo access is required; run sudo -v before launching'
"${tools[numactl]}" --membind=0 "$BASH" -c ':' || die 'cannot bind memory to NUMA node 0'
stress_help=$("${tools[stress-ng]}" --help)
for option in --keep-name --randlist-compact --randlist-items --randlist-size \
    --seed --no-madvise --timeout --metrics; do
    [[ $stress_help == *"$option"* ]] || die "installed stress-ng lacks $option"
done
stress_binary=$("${tools[readlink]}" -f "${tools[stress-ng]}")
user_name=$("${tools[id]}" -un)

compact_cpus() {
    local first='' last='' cpu output=''
    for cpu in "$@"; do
        if [[ -z $first ]]; then
            first=$cpu last=$cpu
        elif (( cpu == last + 1 )); then
            last=$cpu
        else
            output+=${output:+,}$first
            [[ $first == "$last" ]] || output+=-$last
            first=$cpu last=$cpu
        fi
    done
    if [[ -n $first ]]; then
        output+=${output:+,}$first
        [[ $first == "$last" ]] || output+=-$last
    fi
    printf '%s\n' "$output"
}

online_cpus=$(< /sys/devices/system/cpu/online)
declare -a workload_cpu_ids=() cell0_cpu_ids=() online_ranges=()
declare -A llc_members=()
max_llc_id=0
IFS=, read -r -a online_ranges <<< "$online_cpus"
for range in "${online_ranges[@]}"; do
    first=${range%-*} last=${range##*-}
    for (( cpu=first; cpu<=last; cpu++ )); do
        cache=/sys/devices/system/cpu/cpu$cpu/cache/index3
        [[ -r $cache/id && $(< "$cache/level") == 3 ]] || die "cannot read LLC for CPU $cpu"
        llc_id=$(< "$cache/id")
        if (( llc_id > max_llc_id )); then max_llc_id=$llc_id; fi
        if [[ $llc_id == 0 ]]; then
            cell0_cpu_ids+=("$cpu")
        else
            workload_cpu_ids+=("$cpu")
            llc_members[$llc_id]="${llc_members[$llc_id]:-} $cpu"
        fi
    done
done
(( ${#cell0_cpu_ids[@]} > 0 && ${#workload_cpu_ids[@]} > 0 )) ||
    die 'need LLC 0 and at least one other LLC'
workload_cpus=$(compact_cpus "${workload_cpu_ids[@]}")
cell0_cpus=$(compact_cpus "${cell0_cpu_ids[@]}")

run_dir=
runtime_dir=
manifest=
slice=
owned_slice=
slice_cgroup=
requested_status=0
cleanup_done=0
slice_cpu_property_owned=0
declare -a aliases=(mem-a mem-b mem-c mem-d mem-e mem-f mem-g mem-h mem-i)
declare -a worker_llc_ids=() worker_cpu_masks=() members=()
if (( pin_workers_to_llcs )); then
    for (( llc_id=1; llc_id<=max_llc_id && ${#worker_llc_ids[@]}<${#aliases[@]}; llc_id++ )); do
        [[ -n ${llc_members[$llc_id]:-} ]] || continue
        read -r -a members <<< "${llc_members[$llc_id]}"
        worker_llc_ids+=("$llc_id")
        worker_cpu_masks+=("$(compact_cpus "${members[@]}")")
    done
    (( ${#worker_llc_ids[@]} == ${#aliases[@]} )) ||
        die '--pin-workers-to-llcs requires nine distinct LLCs outside LLC 0'
fi
declare -a units=() owned_units=() clients=()
declare -A client_alias=() client_unit=() client_done=() client_ack=() client_start=()

append_manifest() {
    [[ -n $manifest ]] || return 0
    printf '%s\n' "$*" >> "$manifest"
}

request_stop() {
    if (( requested_status == 0 )); then
        requested_status=$1
        printf 'Cancellation requested; stopping this collection.\n' >&2
    fi
}

check_stop() {
    (( requested_status == 0 )) || exit "$requested_status"
}

read_unit_state() {
    local output key value
    unit_load='' unit_active='' unit_fragment='' unit_transient=''
    # Collected/absent units can return nonzero while still reporting not-found.
    if output=$("${tools[timeout]}" --foreground 3s "${tools[systemctl]}" show \
        -p LoadState -p ActiveState -p FragmentPath -p Transient "$1" 2>/dev/null); then :; fi
    while IFS='=' read -r key value; do
        case $key in
            LoadState) unit_load=$value ;;
            ActiveState) unit_active=$value ;;
            FragmentPath) unit_fragment=$value ;;
            Transient) unit_transient=$value ;;
        esac
    done <<< "$output"
    [[ -n $unit_load ]]
}

process_start() {
    local stat
    local -a fields=()
    if { stat=$(< "/proc/$1/stat"); } 2>/dev/null; then
        read -r -a fields <<< "${stat##*) }"
        printf '%s\n' "${fields[19]}"
    else
        return 1
    fi
}

client_alive() {
    local current
    kill -0 "$1" 2>/dev/null || return 1
    current=$(process_start "$1") || return 1
    [[ -n ${client_start[$1]} && $current == "${client_start[$1]}" ]]
}

record_exit() {
    local pid=$1 status=$2
    client_done[$pid]=1
    # A normal command return acknowledges completion/rejection of its request.
    # A signal-killed client alone is NOT proof that PID 1 finished creation.
    if (( status < 128 )); then client_ack[$pid]=1; fi
    append_manifest $'exit\t'"${client_alias[$pid]}"$'\t'"$status"
    last_status=$status
}

reap_client() {
    local status
    if wait "$1"; then status=0; else status=$?; fi
    record_exit "$1" "$status"
}

check_completed_clients() {
    local pid
    for pid in "${clients[@]}"; do
        if [[ ${client_done[$pid]} == 0 ]] && ! client_alive "$pid"; then
            reap_client "$pid"
            check_stop
            if (( last_status != 0 )); then
                printf 'Worker %s failed (client status %s); see its retained log.\n' \
                    "${client_alias[$pid]}" "$last_status" >&2
                exit "$last_status"
            fi
        fi
    done
}

stop_units() {
    (( $# != 0 )) || return 0
    # Names were checked for collisions and registered before the first launch.
    # An absent unit or a collection race is harmless; verify the result below.
    if "${tools[timeout]}" --foreground 7s "${tools[sudo]}" -n \
        "${tools[systemctl]}" stop "$@" >> "$run_dir/cleanup.log" 2>&1; then :; fi
}

slice_command() {
    # Finish the synchronous manager request before acting on terminal signals.
    (
        trap '' INT TERM HUP
        exec "${tools[timeout]}" --foreground --kill-after=2s 7s \
            "${tools[sudo]}" -n "${tools[systemctl]}" "$@"
    )
}

kill_lingering_clients() {
    local pid child children start i
    local -a tree=() killable=()
    local -A identities=()
    for pid in "${clients[@]}"; do
        if [[ ${client_done[$pid]} == 0 ]] && client_alive "$pid"; then
            tree+=("$pid")
            identities[$pid]=${client_start[$pid]}
        fi
    done
    # Include sudo's systemd-run children, without searching unrelated processes.
    for (( i=0; i<${#tree[@]}; i++ )); do
        pid=${tree[$i]}
        if { children=$(< "/proc/$pid/task/$pid/children"); } 2>/dev/null; then
            for child in $children; do
                if start=$(process_start "$child"); then
                    tree+=("$child")
                    identities[$child]=$start
                fi
            done
        fi
    done
    for pid in "${tree[@]}"; do
        if start=$(process_start "$pid") && [[ $start == "${identities[$pid]}" ]]; then
            killable+=("$pid")
        fi
    done
    if (( ${#killable[@]} != 0 )); then
        printf 'Cleanup deadline reached; terminating exact launcher clients.\n' >&2
        if "${tools[timeout]}" --foreground 3s "${tools[sudo]}" -n \
            "${tools[kill]}" -KILL -- "${killable[@]}" >> "$run_dir/cleanup.log" 2>&1; then :; fi
        return 1
    fi
}

cleanup() {
    (( cleanup_done == 0 )) || return 0
    cleanup_done=1
    local deadline=$(( SECONDS + 30 )) pid unit pending unfinished failed=0
    local -a live_units=()
    if (( ${#owned_units[@]} != 0 )); then
        while :; do
            pending=0 unfinished=0 live_units=()
            for pid in "${clients[@]}"; do
                if [[ ${client_ack[$pid]} == 0 ]] &&
                    read_unit_state "${client_unit[$pid]}" && [[ $unit_load != not-found ]]; then
                    client_ack[$pid]=1
                fi
                if [[ ${client_done[$pid]} == 0 ]]; then
                    if client_alive "$pid"; then unfinished=1; else reap_client "$pid"; fi
                fi
                [[ ${client_ack[$pid]} == 1 ]] || pending=1
            done
            for unit in "${owned_units[@]}"; do
                if read_unit_state "$unit" && [[ $unit_load != not-found ]]; then
                    live_units+=("$unit")
                fi
                (( SECONDS < deadline )) || break
            done
            stop_units "${live_units[@]}"
            # Keep clients alive to settle creation, then repeat the stop: a
            # service may have appeared after the preceding stop attempt.
            if (( pending == 0 && unfinished == 0 )); then break; fi
            if (( SECONDS >= deadline )); then failed=1; break; fi
            "${tools[sleep]}" 0.1
        done
        if ! kill_lingering_clients; then failed=1; fi
        deadline=$(( SECONDS + 5 ))
        for pid in "${clients[@]}"; do
            while [[ ${client_done[$pid]} == 0 ]] && client_alive "$pid" &&
                (( SECONDS < deadline )); do "${tools[sleep]}" 0.1; done
            if [[ ${client_done[$pid]} == 0 ]]; then
                if client_alive "$pid"; then failed=1; else reap_client "$pid"; fi
            fi
            if [[ ${client_ack[$pid]} == 0 ]]; then
                printf 'Creation was not acknowledged for %s.\n' "${client_unit[$pid]}" >&2
                failed=1
            fi
        done
        stop_units "${owned_units[@]}"
        # Stop the slice only after services and creation clients have settled.
        stop_units "$owned_slice"
        if (( slice_cpu_property_owned )); then
            if ! slice_command revert "$owned_slice" >> "$run_dir/cleanup.log" 2>&1; then
                failed=1
            fi
        fi
        if "${tools[timeout]}" --foreground 3s "${tools[sudo]}" -n \
            "${tools[systemctl]}" reset-failed "${owned_units[@]}" "$owned_slice" \
            >> "$run_dir/cleanup.log" 2>&1; then :; fi
        deadline=$(( SECONDS + 5 ))
        while [[ -d $slice_cgroup ]] && (( SECONDS < deadline )); do
            "${tools[sleep]}" 0.1
        done
        [[ ! -d $slice_cgroup ]] || failed=1
        for unit in "${owned_units[@]}" "$owned_slice"; do
            if ! read_unit_state "$unit" ||
                [[ $unit_load != not-found && $unit_active != inactive ]]; then
                printf 'Could not verify removal of owned unit %s.\n' "$unit" >&2
                failed=1
            fi
        done
    fi
    if [[ -n $runtime_dir && $runtime_dir == "$run_dir/runtime" && -d $runtime_dir ]]; then
        "${tools[rm]}" -rf -- "$runtime_dir" || failed=1
    fi
    if (( failed == 0 )); then
        append_manifest $'cleanup\tcomplete'
        printf 'Cleanup complete; logs and manifest retained.\n'
    else
        append_manifest $'cleanup\tfailed'
        printf 'Cleanup could not verify every owned resource was removed.\n' >&2
    fi
    return "$failed"
}

finish() {
    local status=$1
    trap - EXIT
    trap '' INT TERM HUP
    (( requested_status == 0 )) || status=$requested_status
    if ! cleanup && (( status == 0 )); then status=1; fi
    append_manifest $'exit_status\t'"$status"
    if [[ -n $run_dir ]]; then printf 'Retained run directory:\n%s\n' "$run_dir"; fi
    exit "$status"
}

trap 'request_stop 130' INT
trap 'request_stop 143' TERM
trap 'request_stop 129' HUP
trap 'finish "$?"' EXIT

run_dir=$("${tools[mktemp]}" -d "${TMPDIR:-/tmp}/mitosis-memory-workers.XXXXXXXX")
runtime_dir=$run_dir/runtime
manifest=$run_dir/manifest.tsv
token=${run_dir##*.}
[[ $token =~ ^[A-Za-z0-9]+$ ]] || die 'mktemp did not produce an alphanumeric run token'
slice=workload-tw-cache${token}.slice
slice_cgroup=/sys/fs/cgroup/workload.slice/workload-tw.slice/$slice
for alias in "${aliases[@]}"; do units+=("mitosis-cache-$token-$alias.service"); done

# Check every name before taking ownership: cleanup must not stop a collision.
for unit in "${units[@]}"; do
    read_unit_state "$unit" || die "cannot query system manager for $unit"
    [[ $unit_load == not-found ]] || die "unit name already exists: $unit"
done
read_unit_state "$slice" || die "cannot query system manager for $slice"
# Merely querying a new .slice generates a loaded, inactive stub. It is safe
# only with no unit file, no transient definition, and no existing cgroup.
[[ $unit_load == not-found ||
    ( $unit_active == inactive && -z $unit_fragment && $unit_transient == no ) ]] ||
    die "slice name already exists: $slice"
[[ ! -d $slice_cgroup ]] || die 'experiment cgroup name already exists'
owned_units=("${units[@]}")
owned_slice=$slice

# Set the shared parent before creating any workers. systemd enables the cpuset
# controller through the slice hierarchy and all services inherit this mask.
slice_cpu_property_owned=1
slice_command set-property --runtime "$slice" "AllowedCPUs=$workload_cpus" ||
    die 'could not set the experiment slice CPU mask'
check_stop
slice_command start "$slice" || die 'could not start the experiment slice'
check_stop
[[ -r $slice_cgroup/cpuset.cpus && $(< "$slice_cgroup/cpuset.cpus") == "$workload_cpus" ]] ||
    die 'experiment cpuset does not match the requested LLC mask'

"${tools[mkdir]}" -p "$runtime_dir/bin" "$runtime_dir/work" "$run_dir/logs"
{
    printf 'run_dir\t%s\nruntime_dir\t%s\nslice\t%s\nslice_cgroup\t%s\n' \
        "$run_dir" "$runtime_dir" "$slice" "$slice_cgroup"
    printf 'duration_seconds\t%s\nruntime_max_seconds\t%s\nuid\t%s\nuser\t%s\n' \
        "$duration_seconds" "$runtime_max_seconds" "$EUID" "$user_name"
    printf 'started_at\t%s\nhost\t%s\nonline_cpus\t%s\n' \
        "$("${tools[date]}" --iso-8601=seconds)" "$("${tools[hostname]}")" "$online_cpus"
    printf 'stress_ng\t%s\nnumactl\t%s\n' "$stress_binary" "${tools[numactl]}"
    printf 'memory_node\t0\nrandlist_workers_per_job\t%s\nrandlist_items\t393216\n' \
        "$randlist_workers_per_job"
    printf 'worker_count\t%s\nworkload_cpus\t%s\ncell0_cpus\t%s\nexcluded_llc\t0\n' \
        "$(( ${#aliases[@]} * randlist_workers_per_job ))" "$workload_cpus" "$cell0_cpus"
    printf 'pin_workers_to_llcs\t%s\n' "$pin_workers_to_llcs"
    printf 'randlist_payload_bytes\t48\nrandlist_compact\ttrue\nseed\t1\nno_madvise\ttrue\n'
} > "$manifest"
printf 'Run directory:\n%s\nExperiment slice:\n%s\nExperiment cgroup:\n%s\n' \
    "$run_dir" "$slice" "$slice_cgroup"
printf 'Duration: %s seconds; online CPUs: %s\n' "$duration_seconds" "$online_cpus"
printf 'Workers: %s (%s per job)\n' "$(( ${#aliases[@]} * randlist_workers_per_job ))" \
    "$randlist_workers_per_job"
printf 'Workload CPUs: %s\nCell 0 reserved CPUs: %s\n' "$workload_cpus" "$cell0_cpus"

for i in "${!aliases[@]}"; do
    alias=${aliases[$i]}
    work=$runtime_dir/work/$alias
    log=$run_dir/logs/$alias.log
    "${tools[mkdir]}" -p "$work"
    "${tools[ln]}" -s "$stress_binary" "$runtime_dir/bin/$alias"
    printf 'job\t%s\t%s\t%s\t%s\t%s\n' "$alias" "${units[$i]}" \
        "$slice_cgroup/${units[$i]}" "$log" "$work" >> "$manifest"
    if (( pin_workers_to_llcs )); then
        printf 'worker_llc\t%s\t%s\t%s\n' "$alias" "${worker_llc_ids[$i]}" \
            "${worker_cpu_masks[$i]}" >> "$manifest"
        printf '%s: LLC %s, CPUs %s\n' "$alias" "${worker_llc_ids[$i]}" "${worker_cpu_masks[$i]}"
    fi
    printf '%s unit: %s\nLog:\n%s\n' "$alias" "${units[$i]}" "$log"
done
check_stop

for i in "${!aliases[@]}"; do
    alias=${aliases[$i]}
    worker_pin_args=()
    if (( pin_workers_to_llcs )); then
        worker_pin_args+=(--property="AllowedCPUs=${worker_cpu_masks[$i]}")
    fi
    command=("${tools[numactl]}" --membind=0 "$runtime_dir/bin/$alias" \
        --keep-name --randlist "$randlist_workers_per_job" --randlist-compact --randlist-items 393216 \
        --randlist-size 48 --seed 1 --no-madvise --timeout "${duration_seconds}s" --metrics)
    { printf 'command\t%s\t' "$alias"; printf '%q ' "${command[@]}"; printf '\n'; } >> "$manifest"
    (
        # Terminal/session cancellation must leave pending creation clients
        # available for the parent to drain and acknowledge before final stop.
        trap '' INT TERM HUP
        exec "${tools[sudo]}" -n "${tools[systemd-run]}" \
            --service-type=exec --wait --pipe --collect --slice="$slice" \
            --unit="${units[$i]}" --uid="$EUID" --working-directory="$runtime_dir/work/$alias" \
            --property=KillMode=control-group --property=TimeoutStopSec=5s \
            --property="RuntimeMaxSec=${runtime_max_seconds}s" \
            "${worker_pin_args[@]}" "${command[@]}"
    ) </dev/null > "$run_dir/logs/$alias.log" 2>&1 &
    pid=$!
    # Do not exit from a signal trap in the fork-to-bookkeeping window.
    clients+=("$pid")
    client_alias[$pid]=$alias client_unit[$pid]=${units[$i]}
    client_done[$pid]=0 client_ack[$pid]=0
    client_start[$pid]=$(process_start "$pid" || true)
    append_manifest $'client\t'"$alias"$'\t'"$pid"
    check_stop
done

# A short condition-based startup barrier; long supervision uses wait -n.
startup_deadline=$(( SECONDS + 30 ))
while :; do
    check_stop
    check_completed_clients
    ready=1
    for pid in "${clients[@]}"; do
        [[ ${client_done[$pid]} == 0 ]] || continue
        if read_unit_state "${client_unit[$pid]}" && [[ $unit_load != not-found ]]; then
            client_ack[$pid]=1
            [[ $unit_active == active ]] || ready=0
        else
            ready=0
        fi
    done
    (( ready == 0 )) || break
    (( SECONDS < startup_deadline )) || die 'timed out waiting for worker startup'
    "${tools[sleep]}" 0.1
done
printf 'All %s services started.\n' "${#aliases[@]}"

# Retain actual inherited affinity and PID identities while the jobs are present.
printf 'job\tpid\tname\tppid\tcpus_allowed_list\n' > "$run_dir/tasks.tsv"
for i in "${!aliases[@]}"; do
    procs=$slice_cgroup/${units[$i]}/cgroup.procs
    # --collect can remove this file at any point. Guard the actual open rather
    # than checking readability and then opening it in a separate operation.
    if { exec {task_procs_fd}< "$procs"; } 2>/dev/null; then
        while read -r task_pid; do
            [[ -n $task_pid ]] || continue
            if { status=$(< "/proc/$task_pid/status"); } 2>/dev/null; then
                task_name='' task_ppid='' task_affinity=''
                while IFS=: read -r key value; do
                    value=${value#"${value%%[![:space:]]*}"}
                    case $key in
                        Name) task_name=$value ;;
                        PPid) task_ppid=$value ;;
                        Cpus_allowed_list) task_affinity=$value ;;
                    esac
                done <<< "$status"
                printf '%s\t%s\t%s\t%s\t%s\n' "${aliases[$i]}" "$task_pid" \
                    "$task_name" "$task_ppid" "$task_affinity" >> "$run_dir/tasks.tsv"
            fi
        done <&"$task_procs_fd"
        exec {task_procs_fd}<&-
    fi
done

while :; do
    check_stop
    check_completed_clients
    running=()
    for pid in "${clients[@]}"; do
        [[ ${client_done[$pid]} == 1 ]] || running+=("$pid")
    done
    (( ${#running[@]} != 0 )) || break
    finished_pid=
    if wait -n -p finished_pid "${running[@]}"; then result=0; else result=$?; fi
    check_stop
    # A child can finish between the readiness check and wait -n. Reap it on
    # the next iteration; 127 is wait's no-running-child status, not its exit.
    [[ -n ${finished_pid:-} ]] || continue
    record_exit "$finished_pid" "$result"
    if (( result != 0 )); then
        printf 'Worker %s failed (client status %s); stopping the collection.\n' \
            "${client_alias[$finished_pid]}" "$result" >&2
        exit "$result"
    fi
done
printf 'All %s workers completed successfully.\n' "$(( ${#aliases[@]} * randlist_workers_per_job ))"
