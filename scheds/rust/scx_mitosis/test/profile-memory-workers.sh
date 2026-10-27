#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Record memory-worker samples and generate a Mitosis subcell configuration.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: profile-memory-workers.sh [OUTPUT_DIR [SECONDS]]
       profile-memory-workers.sh --help

Run on the workload host after start-memory-workers.sh has started all seven
workers. Record memory samples, process them, and extract the experiment's
Mitosis cell/subcell configuration.

Defaults: OUTPUT_DIR=/tmp/mitosis-profile, SECONDS=10
Outputs:  OUTPUT_DIR/perf.mem.data
          OUTPUT_DIR.post/perf.mem.jsonl
          OUTPUT_DIR.learned.json

Output paths must not already exist. No directories need to be created first.
Capture uses --ldlat 0, disables scheduling traces, and does not use hints.
Load the learned configuration separately with Mitosis --cell-config.

SCX_CHARACTERIZE_BIN overrides the default target/release/scx_characterize
binary in this worktree. Build it with:
  cargo build --release -p scx_characterize

Examples:
  ./profile-memory-workers.sh
  ./profile-memory-workers.sh /tmp/mitosis-profile-2 30
EOF
}

die() {
    printf 'profile-memory-workers: %s\n' "$*" >&2
    exit 1
}

if [[ $# == 1 && ( $1 == --help || $1 == -h ) ]]; then
    usage
    exit 0
fi
[[ $# -le 2 ]] || die 'expected an output directory and optional seconds; use --help'

profile_dir=${1-/tmp/mitosis-profile}
duration_seconds=${2-10}
[[ -n $profile_dir && $profile_dir != -* ]] || die 'invalid output directory; use --help'
[[ $duration_seconds =~ ^[1-9][0-9]*$ ]] || die 'seconds must be a positive integer'

profile_dir=${profile_dir%/}
[[ -n $profile_dir ]] || die 'cannot use the filesystem root as output'
if [[ $profile_dir != /* ]]; then
    profile_dir="$PWD/$profile_dir"
fi
processed_dir="${profile_dir}.post"
config_file="${profile_dir}.learned.json"
for output_path in "$profile_dir" "$processed_dir" "$config_file"; do
    [[ ! -e $output_path && ! -L $output_path ]] ||
        die "output already exists: $output_path (choose another output directory)"
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../../../.." && pwd)
profiler=${SCX_CHARACTERIZE_BIN:-"$repo_root/target/release/scx_characterize"}
[[ -x $profiler && ! -d $profiler ]] ||
    die "profiler not executable: $profiler. Run cargo build --release -p scx_characterize or set SCX_CHARACTERIZE_BIN"

sudo_cmd=()
if (( EUID != 0 )); then
    command -v sudo >/dev/null || die 'sudo is required'
    sudo -v
    sudo_cmd=(sudo)
fi

printf 'Recording memory samples for %s seconds...\n' "$duration_seconds"
"${sudo_cmd[@]}" "$profiler" record \
    --output "$profile_dir" --timeout "$duration_seconds" --ldlat 0 \
    --disable-sched-trace --disable-archive

printf 'Processing memory samples...\n'
"${sudo_cmd[@]}" "$profiler" process --file "$profile_dir"

printf 'Generating Mitosis cell/subcell configuration...\n'
"${sudo_cmd[@]}" "$profiler" extract mem \
    --file "$processed_dir/perf.mem.jsonl" \
    --workload-cgroup-regex workload-tw-cache \
    --workload-allotment-cgroup-regex \
        '(^|/)workload\.slice/workload-tw\.slice/workload-tw-cache[A-Za-z0-9]+\.slice($|/)' \
    -vv > "$config_file"

printf '\nProfile and learned configuration saved:\n'
printf '%s\n' "$profile_dir/perf.mem.data" "$processed_dir/perf.mem.jsonl" "$config_file"
