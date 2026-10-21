#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: task_weights.sh [--source ROOT]
       task_weights.sh --live [--cpu CPU] [--duration SECONDS]
Default: compile current C callbacks and drive runnable tasks with weights
100:1 and 100:100:1 on CPU and shared DSQs, plus renewal and direct-wake controls.
This is a source harness, not a live test.
The adapter uses 1ms slices, FIFO ties, and the kernel's dispatch(prev) order.
--source ROOT or MITOSIS_SOURCE selects a checkout (or mitosis.bpf.c path).
Default source discovery walks script and current-directory ancestors.
--live uses the already running Mitosis scheduler and two private busy workers
at nice 0 and nice 19. It never starts or replaces a scheduler. Reports active
ops and measured process CPU times; a running binary may differ from checkout.
--cpu defaults to the first CPU in this process's allowed affinity mask.
--duration is the measurement window (default 5 seconds, range 5..300), following
a CPU-bound warmup; pipe barriers coordinate both workers.
Requires Python 3 and a C compiler; live mode also requires Linux and Mitosis.
Exit: 0=pass/bug absent in scenario, 1=bug reproduced (live: suspicious split),
2=error, 77=unsupported or inconclusive live result.
HELP
}

source_root=${MITOSIS_SOURCE:-}
live=0
live_cpu=
live_duration=5
live_options_set=0

while (($#)); do
    case "$1" in
        --source) (($# >= 2)) || { usage >&2; exit 2; }; source_root=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        --live) live=1; shift ;;
        --cpu) (($# >= 2)) || { usage >&2; exit 2; }; live_cpu=$2; live_options_set=1; shift 2 ;;
        --duration) (($# >= 2)) || { usage >&2; exit 2; }; live_duration=$2; live_options_set=1; shift 2 ;;

        *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
if ((!live && live_options_set)); then
    printf 'ERROR: --cpu and --duration require --live\n' >&2
    exit 2
fi
command -v python3 >/dev/null || { printf 'UNSUPPORTED: python3 required\n' >&2; exit 77; }
command -v "${CC:-cc}" >/dev/null || { printf 'UNSUPPORTED: C compiler required (CC or cc)\n' >&2; exit 77; }
repro_tmp=$(mktemp -d "${TMPDIR:-/tmp}/mitosis-vtime-02.XXXXXX") || exit 2
trap 'rm -rf -- "$repro_tmp"' EXIT

if ((live)); then
    python3 - "$live_cpu" "$live_duration" > "$repro_tmp/live.config" <<'LIVE_CONFIG'
import math
import os
import pathlib
import sys
if not sys.platform.startswith("linux"):
    print("UNSUPPORTED: live mode requires Linux", file=sys.stderr)
    raise SystemExit(77)
try:
    ops = pathlib.Path("/sys/kernel/sched_ext/root/ops").read_text().strip()
except OSError as exc:
    print(f"UNSUPPORTED: cannot read active sched_ext ops: {exc}", file=sys.stderr)
    raise SystemExit(77)
if "mitosis" not in ops.lower():
    print(f"UNSUPPORTED: active ops are {ops!r}, expected Mitosis", file=sys.stderr)
    raise SystemExit(77)
try:
    allowed = os.sched_getaffinity(0)
    cpu = int(sys.argv[1]) if sys.argv[1] else min(allowed)
    duration = float(sys.argv[2])
except (ValueError, OSError) as exc:
    print(f"ERROR: invalid live options: {exc}", file=sys.stderr)
    raise SystemExit(2)
if cpu not in allowed or cpu >= 1024:
    print(f"UNSUPPORTED: CPU {cpu} is outside the supported allowed affinity", file=sys.stderr)
    raise SystemExit(77)
if not math.isfinite(duration) or not 5 <= duration <= 300:
    print("ERROR: duration must be finite and in [5, 300] seconds", file=sys.stderr)
    raise SystemExit(2)
print(ops)
print(cpu)
print(duration)
LIVE_CONFIG
    mapfile -t live_config < "$repro_tmp/live.config"
    printf 'MODE: live workload on existing scheduler\nACTIVE_OPS: %s\n' "${live_config[0]}"
    cat > "$repro_tmp/live.c" <<'C_LIVE'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Diagnostic only: this measures observed nice shares, not kernel scx.weight. */
#define WORKERS 2
#define NS_PER_SEC UINT64_C(1000000000)
#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

enum { READY = 1, DONE = 2, FAILED = 3 };
struct window {
        uint64_t start_ns;
        uint64_t stop_ns;
};
struct event {
        int phase, exit_code, error_number, nice_value, policy;
        uint64_t cpu_ns, start_late_ns, stop_late_ns;
        char operation[48];
};
struct worker {
        pid_t pid;
        int command[2], result[2];
        int ready, done, reaped, wait_status;
        size_t used;
        struct event message, final;
};
static volatile sig_atomic_t interrupted;
static int signal_write_fd = -1;

static void signal_handler(int number)
{
        int saved_errno = errno;
        unsigned char byte = (unsigned char)number;
        if (number != SIGCHLD)
                interrupted = number;
        if (signal_write_fd >= 0) {
                ssize_t ignored = write(signal_write_fd, &byte, 1);
                (void)ignored;
        }
        errno = saved_errno;
}

static int clock_ns(clockid_t which, uint64_t *value)
{
        struct timespec ts;
        if (clock_gettime(which, &ts))
                return -1;
        *value = (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
        return 0;
}

static int timeout_ms(uint64_t deadline)
{
        uint64_t now, delta;
        if (clock_ns(CLOCK_MONOTONIC, &now))
                return -2;
        if (now >= deadline)
                return 0;
        delta = (deadline - now + UINT64_C(999999)) / UINT64_C(1000000);
        return delta > INT_MAX ? INT_MAX : (int)delta;
}

static int write_all(int fd, const void *data, size_t count)
{
        const unsigned char *p = data;
        while (count) {
                ssize_t written = write(fd, p, count);
                if (written < 0) {
                        if (errno == EINTR && !interrupted)
                                continue;
                        return -1;
                }
                if (!written) {
                        errno = EIO;
                        return -1;
                }
                p += written;
                count -= (size_t)written;
        }
        return 0;
}

static void child_fail(int fd, int code, const char *operation)
{
        struct event event = { .phase = FAILED, .exit_code = code,
                               .error_number = errno };
        snprintf(event.operation, sizeof(event.operation), "%s", operation);
        (void)write_all(fd, &event, sizeof(event));
        _exit(code);
}

static int prerequisite_error(void)
{
        return errno == EPERM || errno == EACCES || errno == EINVAL ||
               errno == ENOSYS ? 77 : 2;
}

static void child_run(int command_fd, int result_fd, int cpu, int nice_value,
                      pid_t parent_pid)
{
        cpu_set_t mask;
        struct event ready = { .phase = READY };
        struct event result = { .phase = DONE };
        struct window window;
        uint64_t now, cpu_start, cpu_stop;
        volatile uint64_t busy = (uint64_t)getpid() | 1;
        size_t used = 0;

        signal_write_fd = -1;
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGTERM, SIG_DFL);
        (void)signal(SIGHUP, SIG_DFL);
        (void)signal(SIGCHLD, SIG_DFL);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL))
                child_fail(result_fd, 2, "PR_SET_PDEATHSIG");
        if (getppid() != parent_pid)
                _exit(2);
        if (prctl(PR_SET_NAME, nice_value == 0 ? "vt_weight_hi" : "vt_weight_lo"))
                child_fail(result_fd, 2, "PR_SET_NAME");
        CPU_ZERO(&mask);
        CPU_SET(cpu, &mask);
        if (sched_setaffinity(0, sizeof(mask), &mask))
                child_fail(result_fd, prerequisite_error(), "sched_setaffinity");
        ready.policy = sched_getscheduler(0);
        if (ready.policy < 0)
                child_fail(result_fd, 2, "sched_getscheduler");
        if (ready.policy != SCHED_OTHER && ready.policy != SCHED_EXT) {
                errno = ENOTSUP;
                child_fail(result_fd, 77, "requires SCHED_OTHER or SCHED_EXT");
        }
        if (setpriority(PRIO_PROCESS, 0, nice_value))
                child_fail(result_fd, prerequisite_error(), "setpriority");
        errno = 0;
        ready.nice_value = getpriority(PRIO_PROCESS, 0);
        if (errno)
                child_fail(result_fd, 2, "getpriority");
        if (ready.nice_value != nice_value) {
                errno = ENOTSUP;
                child_fail(result_fd, 77, "requested nice value not effective");
        }
        if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &cpu_start))
                child_fail(result_fd, 77, "CLOCK_PROCESS_CPUTIME_ID");
        if (write_all(result_fd, &ready, sizeof(ready)))
                _exit(2);
        while (used < sizeof(window)) {
                ssize_t got = read(command_fd, (unsigned char *)&window + used,
                                   sizeof(window) - used);
                if (got < 0 && errno == EINTR)
                        continue;
                if (got <= 0)
                        _exit(2);
                used += (size_t)got;
        }
        close(command_fd);

        /* Both ready workers receive the same warmup boundary and deadline.
         * Warmup is CPU-bound so that runnable-task accounting has settled.
         * The parent never guesses readiness using a sleep.
         */
        do {
                for (unsigned int i = 0; i < 256; i++)
                        busy = busy * UINT64_C(6364136223846793005) + 1;
                if (clock_ns(CLOCK_MONOTONIC, &now))
                        child_fail(result_fd, 2, "warmup monotonic clock");
        } while (now < window.start_ns);
        result.start_late_ns = now - window.start_ns;
        if (now >= window.stop_ns) {
                errno = ETIMEDOUT;
                child_fail(result_fd, 77, "worker missed measurement window");
        }
        if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &cpu_start))
                child_fail(result_fd, 2, "measurement CPU clock start");
        do {
                for (unsigned int i = 0; i < 256; i++)
                        busy = busy * UINT64_C(6364136223846793005) + 1;
                if (clock_ns(CLOCK_MONOTONIC, &now))
                        child_fail(result_fd, 2, "measurement monotonic clock");
        } while (now < window.stop_ns);
        if (clock_ns(CLOCK_PROCESS_CPUTIME_ID, &cpu_stop))
                child_fail(result_fd, 2, "measurement CPU clock end");
        result.cpu_ns = cpu_stop - cpu_start;
        result.stop_late_ns = now - window.stop_ns;
        result.nice_value = ready.nice_value;
        result.policy = ready.policy;
        if (write_all(result_fd, &result, sizeof(result)))
                _exit(2);
        close(result_fd);
        _exit(0);
}

static void drain_signals(int fd)
{
        unsigned char bytes[64];
        while (read(fd, bytes, sizeof(bytes)) > 0)
                ;
}

static void reap_available(struct worker workers[WORKERS])
{
        for (int i = 0; i < WORKERS; i++) {
                if (workers[i].pid > 0 && !workers[i].reaped) {
                        pid_t got = waitpid(workers[i].pid,
                                            &workers[i].wait_status, WNOHANG);
                        if (got == workers[i].pid)
                                workers[i].reaped = 1;
                        else if (got < 0 && errno == ECHILD)
                                workers[i].reaped = 1;
                }
        }
}

static int all_reaped(const struct worker workers[WORKERS])
{
        for (int i = 0; i < WORKERS; i++)
                if (workers[i].pid > 0 && !workers[i].reaped)
                        return 0;
        return 1;
}

/* All waits use either pipe events or SIGCHLD; deadlines bound every wait. */
static int await_events(struct worker workers[WORKERS], int signal_fd,
                        int phase, uint64_t deadline)
{
        for (;;) {
                struct pollfd fds[WORKERS + 1];
                int complete = 1;
                for (int i = 0; i < WORKERS; i++) {
                        if (!(phase == READY ? workers[i].ready : workers[i].done))
                                complete = 0;
                        fds[i] = (struct pollfd){ .fd = workers[i].result[0],
                                                 .events = POLLIN };
                }
                if (interrupted) {
                        fprintf(stderr, "Interrupted by signal %d\n", interrupted);
                        return 2;
                }
                if (complete)
                        return 0;
                fds[WORKERS] = (struct pollfd){ .fd = signal_fd, .events = POLLIN };
                int milliseconds = timeout_ms(deadline);
                if (milliseconds < 0) {
                        perror("monotonic clock");
                        return 2;
                }
                if (!milliseconds) {
                        fprintf(stderr, "Inconclusive: timed out waiting for worker %s\n",
                                phase == READY ? "readiness" : "results");
                        return 77;
                }
                int count = poll(fds, WORKERS + 1, milliseconds);
                if (count < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("poll");
                        return 2;
                }
                if (fds[WORKERS].revents & POLLIN)
                        drain_signals(signal_fd);
                for (int i = 0; i < WORKERS; i++) {
                        struct worker *w = &workers[i];
                        if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
                                continue;
                        for (;;) {
                                ssize_t got = read(w->result[0],
                                        (unsigned char *)&w->message + w->used,
                                        sizeof(w->message) - w->used);
                                if (got < 0) {
                                        if (errno == EINTR)
                                                continue;
                                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                                break;
                                        perror("worker result read");
                                        return 2;
                                }
                                if (!got) {
                                        if (w->used || !(phase == READY ? w->ready : w->done)) {
                                                fprintf(stderr, "Worker %d exited without complete %s\n",
                                                        i, phase == READY ? "readiness" : "result");
                                                return 2;
                                        }
                                        close(w->result[0]);
                                        w->result[0] = -1;
                                        break;
                                }
                                w->used += (size_t)got;
                                if (w->used != sizeof(w->message))
                                        continue;
                                w->used = 0;
                                if (w->message.phase == FAILED) {
                                        fprintf(stderr, "Worker %d: %s: %s\n", i,
                                                w->message.operation,
                                                strerror(w->message.error_number));
                                        return w->message.exit_code == 77 ? 77 : 2;
                                }
                                if (w->message.phase == READY && !w->ready)
                                        w->ready = 1;
                                else if (w->message.phase == DONE && w->ready && !w->done) {
                                        w->done = 1;
                                        w->final = w->message;
                                } else {
                                        fprintf(stderr, "Malformed worker event\n");
                                        return 2;
                                }
                        }
                }
                reap_available(workers);
        }
}

static int wait_for_exit(struct worker workers[WORKERS], int signal_fd,
                         uint64_t deadline)
{
        for (;;) {
                reap_available(workers);
                if (all_reaped(workers))
                        return 0;
                int milliseconds = timeout_ms(deadline);
                if (milliseconds <= 0)
                        return -1;
                struct pollfd fd = { .fd = signal_fd, .events = POLLIN };
                if (poll(&fd, 1, milliseconds) < 0 && errno != EINTR)
                        return -1;
                drain_signals(signal_fd);
        }
}

static void close_fd(int *fd)
{
        if (*fd >= 0) {
                close(*fd);
                *fd = -1;
        }
}

int main(int argc, char **argv)
{
        struct worker workers[WORKERS];
        int signals[2] = { -1, -1 }, exit_code = 2;
        cpu_set_t allowed;
        char *end;
        uint64_t now, runtime_ns;
        struct window window;
        struct sigaction action = { .sa_handler = signal_handler };
        pid_t parent_pid = getpid();

        memset(workers, 0, sizeof(workers));
        for (int i = 0; i < WORKERS; i++) {
                workers[i].command[0] = workers[i].command[1] = -1;
                workers[i].result[0] = workers[i].result[1] = -1;
        }
        if (argc != 3) {
                fprintf(stderr, "Usage: %s CPU DURATION_SECONDS (5..300)\n", argv[0]);
                return 2;
        }
        errno = 0;
        long requested_cpu = strtol(argv[1], &end, 10);
        if (errno || *end || end == argv[1] || requested_cpu < 0 ||
            requested_cpu >= CPU_SETSIZE) {
                fprintf(stderr, "Unsupported CPU; use an available CPU below %d\n", CPU_SETSIZE);
                return 77;
        }
        errno = 0;
        double duration = strtod(argv[2], &end);
        if (errno || *end || end == argv[2] || !isfinite(duration) ||
            duration < 5.0 || duration > 300.0) {
                fprintf(stderr, "Duration must be finite and in [5, 300] seconds\n");
                return 2;
        }
        runtime_ns = (uint64_t)(duration * (double)NS_PER_SEC);
        CPU_ZERO(&allowed);
        if (sched_getaffinity(0, sizeof(allowed), &allowed)) {
                perror("sched_getaffinity");
                return 77;
        }
        if (!CPU_ISSET((int)requested_cpu, &allowed)) {
                fprintf(stderr, "CPU %ld is unavailable in this process's affinity\n", requested_cpu);
                return 77;
        }
        if (pipe2(signals, O_CLOEXEC | O_NONBLOCK)) {
                perror("signal pipe");
                goto cleanup;
        }
        signal_write_fd = signals[1];
        sigemptyset(&action.sa_mask);
        for (int i = 0; i < 4; i++) {
                const int numbers[] = { SIGINT, SIGTERM, SIGHUP, SIGCHLD };
                if (sigaction(numbers[i], &action, NULL)) {
                        perror("sigaction");
                        goto cleanup;
                }
        }
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
                perror("ignore SIGPIPE");
                goto cleanup;
        }
        for (int i = 0; i < WORKERS; i++) {
                if (pipe2(workers[i].command, O_CLOEXEC) ||
                    pipe2(workers[i].result, O_CLOEXEC)) {
                        perror("worker pipe");
                        goto cleanup;
                }
                if (fcntl(workers[i].result[0], F_SETFL, O_NONBLOCK)) {
                        perror("nonblocking result pipe");
                        goto cleanup;
                }
        }
        for (int i = 0; i < WORKERS; i++) {
                if (interrupted)
                        goto cleanup;
                workers[i].pid = fork();
                if (workers[i].pid < 0) {
                        perror("fork");
                        goto cleanup;
                }
                if (!workers[i].pid) {
                        close(signals[0]);
                        close(signals[1]);
                        for (int j = 0; j < WORKERS; j++) {
                                close(workers[j].command[1]);
                                close(workers[j].result[0]);
                                if (j != i) {
                                        close(workers[j].command[0]);
                                        close(workers[j].result[1]);
                                }
                        }
                        child_run(workers[i].command[0], workers[i].result[1],
                                  (int)requested_cpu, i ? 19 : 0, parent_pid);
                }
        }
        for (int i = 0; i < WORKERS; i++) {
                close_fd(&workers[i].command[0]);
                close_fd(&workers[i].result[1]);
        }
        if (clock_ns(CLOCK_MONOTONIC, &now)) {
                perror("monotonic clock");
                goto cleanup;
        }
        exit_code = await_events(workers, signals[0], READY, now + 10 * NS_PER_SEC);
        if (exit_code)
                goto cleanup;
        if (clock_ns(CLOCK_MONOTONIC, &now)) {
                perror("monotonic clock");
                exit_code = 2;
                goto cleanup;
        }
        window.start_ns = now + NS_PER_SEC;
        window.stop_ns = window.start_ns + runtime_ns;
        for (int i = 0; i < WORKERS; i++) {
                if (write_all(workers[i].command[1], &window, sizeof(window))) {
                        perror("worker start barrier");
                        exit_code = 2;
                        goto cleanup;
                }
                close_fd(&workers[i].command[1]);
        }
        exit_code = await_events(workers, signals[0], DONE,
                                 window.stop_ns + 5 * NS_PER_SEC);
        if (exit_code)
                goto cleanup;
        if (wait_for_exit(workers, signals[0], window.stop_ns + 5 * NS_PER_SEC)) {
                fprintf(stderr, "Worker exit timeout\n");
                exit_code = 2;
                goto cleanup;
        }
        for (int i = 0; i < WORKERS; i++) {
                if (!WIFEXITED(workers[i].wait_status) || WEXITSTATUS(workers[i].wait_status)) {
                        fprintf(stderr, "Worker %d did not exit successfully\n", i);
                        exit_code = 2;
                        goto cleanup;
                }
        }
        if (interrupted) {
                exit_code = 2;
                goto cleanup;
        }
        double high = (double)workers[0].final.cpu_ns / (double)NS_PER_SEC;
        double low = (double)workers[1].final.cpu_ns / (double)NS_PER_SEC;
        double total = high + low;
        double ratio = low > 0 ? high / low : INFINITY;
        double utilization = total / duration;
        printf("LIVE nice-weight probe: CPU=%ld duration=%.3fs warmup=1s\n",
               requested_cpu, duration);
        printf("nice0: cpu=%.6fs normalized_share=%.4f%% policy=%d\n",
               high, total > 0 ? 100 * high / total : 0, workers[0].final.policy);
        printf("nice19: cpu=%.6fs normalized_share=%.4f%% policy=%d\n",
               low, total > 0 ? 100 * low / total : 0, workers[1].final.policy);
        printf("high:low_ratio=%.4f combined_cpu_utilization=%.4f\n", ratio, utilization);
        printf("Nominal ratio=100:1 from the scheduler's task-weight scaling assumption.\n"
               "The probe verifies nice values, not the kernel's effective scx.weight.\n"
               "The active scheduler binary may differ from this source checkout.\n");
        uint64_t max_lateness = 0;
        for (int i = 0; i < WORKERS; i++) {
                if (workers[i].final.start_late_ns > max_lateness)
                        max_lateness = workers[i].final.start_late_ns;
                if (workers[i].final.stop_late_ns > max_lateness)
                        max_lateness = workers[i].final.stop_late_ns;
        }
        printf("maximum_boundary_lateness=%.6fs\n", (double)max_lateness / (double)NS_PER_SEC);
        if (utilization < 0.8 || utilization > 1.05 || low <= 0 ||
            max_lateness > runtime_ns / 20) {
                printf("INCONCLUSIVE: insufficient CPU time or substantial scheduling interference.\n");
                exit_code = 77;
        } else if (ratio < 20.0) {
                printf("SUSPICIOUS: CPU shares collapsed far below the nominal 100:1 ratio.\n");
                exit_code = 1;
        } else if (ratio >= 80.0 && ratio <= 125.0) {
                printf("PASS: measured high:low ratio is within [80, 125] around 100:1.\n");
                exit_code = 0;
        } else {
                printf("INCONCLUSIVE: intermediate ratio requires longer or more isolated measurement.\n");
                exit_code = 77;
        }

cleanup:
        reap_available(workers);
        for (int i = 0; i < WORKERS; i++)
                if (workers[i].pid > 0 && !workers[i].reaped)
                        (void)kill(workers[i].pid, SIGKILL);
        if (!all_reaped(workers)) {
                if (!clock_ns(CLOCK_MONOTONIC, &now) && signals[0] >= 0)
                        (void)wait_for_exit(workers, signals[0], now + 2 * NS_PER_SEC);
                reap_available(workers);
                if (!all_reaped(workers)) {
                        fprintf(stderr, "Could not reap all owned workers within cleanup deadline\n");
                        exit_code = 2;
                }
        }
        for (int i = 0; i < WORKERS; i++) {
                close_fd(&workers[i].command[0]);
                close_fd(&workers[i].command[1]);
                close_fd(&workers[i].result[0]);
                close_fd(&workers[i].result[1]);
        }
        signal_write_fd = -1;
        close_fd(&signals[0]);
        close_fd(&signals[1]);
        return exit_code;
}
C_LIVE
    if ! "${CC:-cc}" -O2 -std=c11 -Wall -Wextra -Werror "$repro_tmp/live.c" -o "$repro_tmp/live"; then
        printf 'ERROR: live CPU probe failed to compile\n' >&2
        exit 2
    fi
    live_probe_pid=
    cleanup_live() {
        if [[ -n $live_probe_pid ]]; then
            kill -TERM "$live_probe_pid" 2>/dev/null || true
            wait "$live_probe_pid" 2>/dev/null || true
        fi
        rm -rf -- "$repro_tmp"
    }
    trap cleanup_live EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    "$repro_tmp/live" "${live_config[1]}" "${live_config[2]}" &
    live_probe_pid=$!
    live_status=0
    wait "$live_probe_pid" || live_status=$?
    live_probe_pid=
    after_ops=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null) || after_ops=
    if [[ $after_ops != "${live_config[0]}" ]]; then
        printf 'INCONCLUSIVE: active scheduler changed during measurement (%s -> %s)\n' "${live_config[0]}" "$after_ops"
        exit 77
    fi
    exit "$live_status"
fi

python3 - "$source_root" "${BASH_SOURCE[0]}" "$repro_tmp/repro.c" <<'PYTHON'
import pathlib
import re
import sys


def unsupported(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


def locate_source(explicit, script):
    if explicit:
        candidates = [pathlib.Path(explicit).expanduser()]
    else:
        candidates = list(pathlib.Path(script).resolve().parents)
        candidates += [pathlib.Path.cwd(), *pathlib.Path.cwd().parents]
    for root in candidates:
        if root.is_file() and root.name == "mitosis.bpf.c":
            return root.resolve()
        for relative in ("scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c", "mitosis.bpf.c"):
            path = root / relative
            if path.is_file():
                return path.resolve()
    unsupported("cannot find checkout; use --source ROOT or MITOSIS_SOURCE")


def mask_literals(text):
    # Keep positions and newlines; ignore braces in comments and literals.
    masked = list(text)
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                unsupported("unterminated source comment")
            end += 2
        elif text[i] in (chr(34), chr(39)):
            quote = text[i]
            end = i + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                unsupported("unterminated source literal")
        else:
            i += 1
            continue
        for j in range(i, min(end, len(text))):
            if text[j] != "\n":
                masked[j] = " "
        i = end
    return "".join(masked)


def extract_function(text, masked, name, required=True, source_path=None):
    pattern = re.compile(
        r"(?m)^(?:static\s+)?(?:(?:__always_inline|inline)\s+)?"
        r"(?:(?:void|int|bool|u64|u32|s32|dsq_id_t)\s+|const\s+struct\s+cpumask\s*\*\s*)"
        r"(?:BPF_STRUCT_OPS\(\s*"
        + re.escape(name) + r"\s*,|" + re.escape(name) + r"\s*\()"
    )
    matches = list(pattern.finditer(masked))
    if not matches and not required:
        return ""
    if len(matches) != 1:
        unsupported(f"expected one definition of {name}, found {len(matches)}")
    start = matches[0].start()
    opening = masked.find("{", matches[0].end())
    semicolon = masked.find(";", matches[0].end())
    if opening < 0 or (0 <= semicolon < opening):
        unsupported(f"cannot locate body of {name}")
    depth = 1
    end = opening + 1
    while end < len(masked) and depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    if depth:
        unsupported(f"unterminated body of {name}")
    line = text.count("\n", 0, start) + 1
    source_path = source_path or path
    return f'\n#line {line} "{source_path.as_posix()}"\n' + text[start:end] + "\n"


path = locate_source(sys.argv[1], sys.argv[2])
try:
    text = path.read_text()
except (OSError, UnicodeError) as exc:
    print(f"ERROR: cannot read source: {exc}", file=sys.stderr)
    raise SystemExit(2)
masked = mask_literals(text)
constants = []
for name in ("VTIME_DEBT_CAP_SLICES", "PINNED_MAX_WAIT_SLICES"):
    match = re.search(r"(?m)^#define\s+" + name + r"\s+([0-9]+)\s*$", text)
    if not match:
        unsupported(f"missing supported integer constant {name}")
    constants.append(f"#define {name} {match.group(1)}\n")

rescue_take = extract_function(text, masked, "take_task_rescue", required=False)
rescue_helpers = ""
llc_helpers = ""
llc_globals = ""
rescue_initial_state = "0"
dsq_declarations = "typedef struct { u64 raw; } dsq_id_t;\n#define DSQ_INVALID ((dsq_id_t){~0ULL})\n"
dsq_helpers = r"""
static s32 pack_subcell_id(u32 cell, u32 subcell) { return (s32)(cell * MAX_SUBCELLS_PER_CELL + subcell); }
static dsq_id_t get_cpu_dsq_id(u32 cpu) { return (dsq_id_t){1 + cpu}; }
static dsq_id_t get_subcell_llc_dsq_id(u32 cell, u32 subcell, u32 llc) { return (dsq_id_t){100 + (cell * MAX_SUBCELLS_PER_CELL + subcell) * MAX_LLCS + llc}; }
static bool dsq_is_invalid(dsq_id_t dsq) { return dsq.raw == ~0ULL; }
static s32 get_cpu_from_dsq(dsq_id_t dsq) { return (s32)dsq.raw - 1; }
"""
dsq_path = path.with_name("dsq.bpf.h")
if dsq_path.is_file():
    try:
        dsq_text = dsq_path.read_text()
    except (OSError, UnicodeError) as exc:
        unsupported(f"cannot read DSQ helper dependencies: {exc}")
    dsq_start = re.search(r"(?m)^#define\s+CPU_B\b", dsq_text)
    dsq_end = re.search(r"(?m)^static\s+inline\s+bool\s+dsq_is_invalid\s*\(", dsq_text)
    if not dsq_start or not dsq_end:
        unsupported("cannot extract DSQ declarations")
    dsq_declarations = dsq_text[dsq_start.start():dsq_end.start()]
    dsq_masked = mask_literals(dsq_text)
    dsq_helpers = "".join(
        extract_function(dsq_text, dsq_masked, name, source_path=dsq_path)
        for name in ("dsq_is_invalid", "is_user_dsq", "is_cpu_dsq",
                     "get_cpu_from_dsq", "get_cpu_dsq_id", "pack_subcell_id",
                     "get_subcell_llc_dsq_id")
    )
if rescue_take:
    if not dsq_path.is_file():
        unsupported("rescue helpers require sibling dsq.bpf.h")
    try:
        header = path.with_name("mitosis.bpf.h").read_text()
        llc_path = path.with_name("llc_aware.bpf.h")
        llc_text = llc_path.read_text()
    except (OSError, UnicodeError) as exc:
        unsupported(f"cannot read rescue helper dependencies: {exc}")
    rescue_enum = re.search(r"(?ms)^enum\s+task_rescue_phase\s*\{.*?^\};", header)
    if not rescue_enum:
        unsupported("cannot extract enum task_rescue_phase")
    constants.append(rescue_enum.group() + "\n")
    constants.append("#define FIXTURE_HAS_TASK_RESCUE 1\n")
    for name in ("TASK_RESCUE_PHASE_MASK", "TASK_RESCUE_GENERATION_STEP"):
        match = re.search(r"(?m)^#define\s+" + name + r"\b[^\n]*", text + "\n" + header)
        if not match:
            unsupported(f"missing rescue constant {name}")
        constants.append(match.group() + "\n")
    rescue_initial_state = "TASK_RESCUE_NONE"
    for pattern, description in (
        (r"(?m)^typedef\s+u32\s+llc_id_t\s*;", "llc_id_t"),
        (r"(?m)^#define\s+LLC_INVALID\b[^\n]*", "LLC_INVALID"),
    ):
        match = re.search(pattern, llc_text)
        if not match:
            unsupported(f"cannot extract {description}")
        constants.append(match.group() + "\n")
    llc_masked = mask_literals(llc_text)
    llc_helpers = "".join(
        extract_function(llc_text, llc_masked, name, source_path=llc_path)
        for name in ("llc_is_valid", "lookup_llc_cpumask",
                     "invalidate_task_llc_cpumask", "invalidate_task_llc",
                     "llc_from_cpu", "choose_task_llc", "refresh_task_llc_cpumask",
                     "subcell_llc_drain_enable", "subcell_llc_nr_queued_inc",
                     "subcell_llc_nr_queued_dec", "subcell_llc_has_cpus",
                     "kick_subcell_idle_cpu_locked", "kick_subcell_idle_cpu",
                     "account_subcell_llc_enqueue", "set_task_llc",
                     "maybe_update_task_llc")
    )
    llc_globals = r"""
struct llc_cpumask { u64 bits; };
u32 cpu_to_llc[MAX_CPUS];
struct llc_cpumask llc_to_cpus[MAX_LLCS];
static struct bpf_cpumask fixture_llc_mask;
"""
    rescue_helpers += "".join(
        extract_function(text, masked, name)
        for name in ("restore_task_rescue_vtime", "repair_running_task_rescue")
    )
constants.append(f"#define FIXTURE_TASK_RESCUE_NONE {rescue_initial_state}\n")

print("MODE: source callback harness; kernel dispatch(prev) order and 1ms slices")
try:
    print("~/" + path.relative_to(pathlib.Path.home()).as_posix())
except ValueError:
    print(path)
prelude = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef long long s64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define MEMBER_VPTR(base, member) (&((base) member))
#define barrier_var(x) ((void)(x))
#define unlikely(x) (x)
#define bpf_for(i, begin, end) for ((i) = (begin); (i) < (end); (i)++)
#define time_before(a, b) ((s64)((u64)(a) - (u64)(b)) < 0)
#define time_after(a, b) time_before(b, a)
#define FAKE_FLAT_SUBCELL_LLC 0
#define MAX_CPUS 4
#define MAX_CELLS 4
#define MAX_SUBCELLS_PER_CELL 2
#define MAX_LLCS 2
#define SCX_ENQ_WAKEUP 1ULL
#define SCX_ENQ_CPU_SELECTED (1ULL << 20)
#define SCX_ENQ_LAST (1ULL << 41)
#define SCX_WAKE_TTWU 0x08ULL
#define SCX_TASK_QUEUED 1ULL
#define PF_IDLE 2U
#define SCX_KICK_IDLE 1
#define SCX_KICK_PREEMPT 2
#define SCX_PICK_IDLE_CORE 1ULL
#define SCX_DSQ_LOCAL (~0ULL - 1)
#define scoped_guard(name) for (int fixture_guard = 0; fixture_guard < 1; fixture_guard++)
@FIXTURE_DSQ_DECLARATIONS@
#define CSTAT_AFFN_VIOL 0
#define CSTAT_PIN_SKIP 0
#define CSTAT_CPU_DSQ 0
#define CSTAT_CELL_DSQ 0
#define CSTAT_DRAIN_CNT 0
#define CSTAT_STEAL 0
#define CSTAT_CLAMP_USED 0
struct cpumask { u64 bits; };
struct bpf_cpumask { u64 bits; };
struct subcell_llc { u64 vtime_now; u32 nr_queued; };
struct subcell { struct subcell_llc llcs[MAX_LLCS]; u64 llcs_to_drain, llcs_with_cpus; };
struct cpu_ctx {
    u64 pinned_waiting_since, vtime_now, vtime_bias, pending_vtime_owner, running_ns[MAX_CELLS];
    u32 cell, subcell, llc;
};
struct scx_dispatch_q { u64 id; };
struct task_ctx {
    struct bpf_cpumask *cpumask, *llc_cpumask;
    u64 started_running_at, charged_at, basis_vtime, avg_runtime_ns;
    u64 rescue_seq, rescue_vtime;
    u32 cell, subcell, configuration_seq, vtime_charge_subcell;
    dsq_id_t dsq;
    bool all_cell_cpus_allowed, borrowed;
    s32 llc, llc_cpumask_id;
};
struct task_struct {
    struct { u64 dsq_vtime, flags, slice; u32 weight; struct scx_dispatch_q *dsq; } scx;
    struct task_ctx ctx;
    int pid, cpu;
    u32 flags;
    const struct cpumask *cpus_ptr;
    bool queued;
    u64 arrival;
};
static const u32 nr_possible_cpus = 3;
static u32 nr_llc = 1;
static const u64 slice_ns = 1000000;
static bool enable_llc_awareness;
static bool enable_borrowing;
static const bool dynamic_affinity_cpu_selection = false, enable_slice_shrinking = false;
static struct cpu_ctx cpus[MAX_CPUS];
static struct subcell subcells[MAX_CELLS][MAX_SUBCELLS_PER_CELL];
static struct scx_dispatch_q cpu_dsqs[MAX_CPUS];
static struct scx_dispatch_q shared_dsqs[MAX_CELLS][MAX_SUBCELLS_PER_CELL][MAX_LLCS];
static struct scx_dispatch_q local_dsq = { .id = SCX_DSQ_LOCAL };
static struct task_struct tasks[3], *local_task, *running_task;
static u64 now_ns = 1, arrival_seq;
static int errors;
static bool direct_select_control;
static bool direct_enqueue_control;
static unsigned direct_insertions;
static const struct cpumask task_affinity = {.bits = 1};
static const struct cpumask shared_affinity = {.bits = 7};
static const struct cpumask partial_affinity = {.bits = 3};
static struct bpf_cpumask task_mask = {.bits = 1}, shared_mask = {.bits = 7};
static struct bpf_cpumask partial_mask = {.bits = 3};
#define scx_bpf_error(...) do { errors++; fprintf(stderr, "callback error: "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
static struct cpu_ctx *lookup_cpu_ctx(int cpu) { return &cpus[cpu < 0 ? 0 : cpu]; }
static struct task_ctx *lookup_task_ctx(struct task_struct *p) { return &p->ctx; }
static struct subcell *lookup_subcell(u32 cell, u32 subcell) { return &subcells[cell][subcell]; }
static struct subcell_llc *lookup_subcell_llc(struct subcell *s, u32 llc) { return &s->llcs[llc]; }
@FIXTURE_DSQ_HELPERS@
static bool llc_is_valid(s32 llc) { return llc >= 0 && llc < MAX_LLCS; }
static u64 scx_bpf_now(void) { return now_ns; }
static u64 bpf_ktime_get_ns(void) { return now_ns; }
static u64 time_delta(u64 a, u64 b) { return a >= b ? a - b : 0; }
static s32 scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 v) { p->scx.dsq_vtime = v; return true; }
static bool scx_bpf_task_set_slice(struct task_struct *p, u64 v) { p->scx.slice = v; return true; }
static int maybe_refresh_cell(struct task_struct *p, struct task_ctx *t) { (void)p; (void)t; return 0; }
static bool task_needs_refresh(struct task_struct *p, struct task_ctx *t) { (void)p; (void)t; return false; }
static bool __COMPAT_is_enq_cpu_selected(u64 flags) { return (flags & SCX_ENQ_CPU_SELECTED) != 0; }
static s32 enqueue_pinned_cpu(struct task_struct *p, struct task_ctx *t) { (void)p; return get_cpu_from_dsq(t->dsq); }
static void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags);
static s32 try_pick_idle_cpu(struct task_struct *p, s32 cpu, struct cpu_ctx *c, struct task_ctx *t, bool kick) {
    (void)cpu; (void)c; (void)t;
    /* The direct shared fixture fixes the idle CPU and home charge domain
     * at CPU 0 / cell 0. Its transfer preserves the task's virtual time.
     */
    if (direct_select_control && kick == direct_enqueue_control) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
        return 0;
    }
    return -EBUSY;
}
static u32 bpf_cpumask_weight(const struct cpumask *mask) { return (u32)__builtin_popcountll(mask->bits); }
static bool bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *mask) { return cpu >= 0 && cpu < 64 && !!(mask->bits & (1ULL << cpu)); }
static bool bpf_cpumask_empty(const struct cpumask *mask) { return !mask->bits; }
static void bpf_cpumask_and(struct bpf_cpumask *dst, const struct cpumask *a, const struct cpumask *b) { dst->bits = a->bits & b->bits; }
static const struct cpumask *cast_mask(const struct bpf_cpumask *mask) { return (const struct cpumask *)mask; }
static bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) { return direct_select_control && cpu == 0; }
static s32 select_pinned_cpu(struct task_struct *p, s32 cpu, struct task_ctx *t, bool *cleared) {
    (void)p; (void)cpu; (void)t; (void)cleared;
    fprintf(stderr, "ERROR: dynamic pinned selection is inactive in this fixture\n");
    errors++;
    return -1;
}
static int maybe_update_task_llc(struct task_struct *p, struct task_ctx *t, s32 cpu) { (void)p; (void)t; (void)cpu; return 0; }
static u32 bpf_cpumask_any_distribute(const struct cpumask *m) { (void)m; return 0; }
static void scx_bpf_kick_cpu(s32 cpu, int flags) { (void)cpu; (void)flags; }
static s32 scx_bpf_pick_idle_cpu(const struct cpumask *mask, u64 flags) { (void)mask; (void)flags; return -EBUSY; }
static const struct cpumask *lookup_subcell_cpumask(u32 cell, u32 subcell) { (void)cell; (void)subcell; return &shared_affinity; }
static void cstat_inc(int idx, u32 cell, struct cpu_ctx *c) { (void)idx; (void)cell; (void)c; }
static int account_subcell_llc_enqueue(u32 cell, u32 subcell, u32 llc) { (void)cell; (void)subcell; (void)llc; return 0; }
static void subcell_llc_nr_queued_dec(struct subcell *s, u32 llc) { (void)s; (void)llc; }
static int try_draining_work(u32 cell, u32 subcell, u32 llc, struct cpu_ctx *c) { (void)cell; (void)subcell; (void)llc; (void)c; return -ENOENT; }
static int try_stealing_work(u32 cell, u32 subcell, u32 llc) { (void)cell; (void)subcell; (void)llc; return -ENOENT; }
static struct task_struct *__COMPAT_scx_bpf_cpu_curr(s32 cpu) { (void)cpu; return running_task; }
static int slice_shrink_on_enqueue(struct task_struct *p, struct task_ctx *t, u32 cell, struct cpu_ctx *c) { (void)p; (void)t; (void)cell; (void)c; return 0; }
static int slice_shrink_on_running(struct task_struct *p, u32 cell, struct cpu_ctx *c) { (void)p; (void)cell; (void)c; return 0; }

/* Kernel DSQ adapter: priority by task vtime, FIFO for equal vtime.
 * Every insertion updates p->scx.dsq_vtime, as the kernel helper does.
 * All test tasks can execute on CPU 0; no concurrent dequeue is modeled.
 */
static struct scx_dispatch_q *fixture_dsq(u64 id) {
    if (id == SCX_DSQ_LOCAL) return &local_dsq;
    for (u32 cpu = 0; cpu < MAX_CPUS; cpu++)
        if (id == get_cpu_dsq_id(cpu).raw) return &cpu_dsqs[cpu];
    for (u32 cell = 0; cell < MAX_CELLS; cell++)
        for (u32 subcell = 0; subcell < MAX_SUBCELLS_PER_CELL; subcell++)
            for (u32 llc = 0; llc < MAX_LLCS; llc++)
                if (id == get_subcell_llc_dsq_id(cell, subcell, llc).raw)
                    return &shared_dsqs[cell][subcell][llc];
    errors++;
    return NULL;
}
static struct task_struct *dsq_peek(u64 dsq) {
    struct task_struct *head = NULL;
    for (unsigned i = 0; i < 3; i++) {
        struct task_struct *p = &tasks[i];
        if (!p->queued || !p->scx.dsq || p->scx.dsq->id != dsq) continue;
        if (!head || time_before(p->scx.dsq_vtime, head->scx.dsq_vtime) ||
            (p->scx.dsq_vtime == head->scx.dsq_vtime && p->arrival < head->arrival)) head = p;
    }
    return head;
}
static s32 scx_bpf_dsq_nr_queued(u64 dsq) {
    s32 count = 0;
    for (unsigned i = 0; i < 3; i++)
        count += tasks[i].queued && tasks[i].scx.dsq && tasks[i].scx.dsq->id == dsq;
    return count;
}
static bool scx_bpf_dsq_move_to_local(u64 dsq, u64 flags) {
    (void)flags;
    struct task_struct *p = dsq_peek(dsq);
    if (!p) return false;
    p->queued = false;
    p->scx.dsq = &local_dsq;
    local_task = p;
    return true;
}
static void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq, u64 slice, u64 vtime, u64 flags) {
    (void)flags;
    if (p->queued || dsq != p->ctx.dsq.raw) { errors++; return; }
    p->scx.dsq_vtime = vtime;
    p->scx.slice = slice;
    p->scx.flags = SCX_TASK_QUEUED;
    p->scx.dsq = fixture_dsq(dsq);
    p->arrival = ++arrival_seq;
    p->queued = true;
}
static void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    if (!direct_select_control || dsq != SCX_DSQ_LOCAL || slice != slice_ns ||
        flags || p->queued || local_task) {
        fprintf(stderr, "ERROR: unexpected direct-local placement\n");
        errors++;
        return;
    }
    /* FIFO/direct insertion updates slice and runnable state, preserving
     * dsq_vtime. Enqueue is skipped before the subsequent running callback.
     */
    p->scx.slice = slice;
    p->scx.flags = SCX_TASK_QUEUED;
    p->scx.dsq = &local_dsq;
    direct_insertions++;
    local_task = p;
}
static unsigned queued_tasks(unsigned count) {
    unsigned queued = 0;
    for (unsigned i = 0; i < count; i++) queued += tasks[i].queued;
    return queued;
}
"""
prelude = prelude.replace("@FIXTURE_DSQ_DECLARATIONS@", dsq_declarations)
prelude = prelude.replace("@FIXTURE_DSQ_HELPERS@", dsq_helpers)
if rescue_take:
    for name in ("llc_is_valid", "maybe_update_task_llc",
                 "account_subcell_llc_enqueue", "subcell_llc_nr_queued_dec"):
        prelude = re.sub(r"(?m)^static[^\n]*\b" + name + r"\([^\n]*\}\n", "", prelude)

# Import the checkout's task state and accounting helpers. The fixture maps
# and CPU-task clock keep demand accounting separate from weighted vtime.
try:
    task_text = path.with_name("mitosis.bpf.h").read_text()
except (OSError, UnicodeError) as exc:
    unsupported(f"cannot read task-state declaration: {exc}")
task_declaration = re.search(r"(?ms)^struct task_ctx\s*\{.*?^\};", mask_literals(task_text))
if not task_declaration:
    unsupported("cannot extract task_ctx")
prelude, count = re.subn(r"(?ms)^struct task_ctx\s*\{.*?^\};\n",
                        task_text[task_declaration.start():task_declaration.end()] + "\n", prelude)
if count != 1:
    unsupported("cannot replace task-state adapter")
prelude = "#define __kptr\n" + prelude
constants.append("#define FIXTURE_INIT_RESCUE(ctx) " +
                 ("((ctx).rescue_seq = FIXTURE_TASK_RESCUE_NONE)" if rescue_take
                  else "((void)(ctx))") + "\n")
accounting_functions = ""
account_running = extract_function(text, masked, "account_task_running", required=False)
if account_running:
    try:
        intf_text = path.with_name("intf.h").read_text()
    except (OSError, UnicodeError) as exc:
        unsupported(f"cannot read demand-account declaration: {exc}")
    intf_masked = mask_literals(intf_text)
    account_declaration = re.search(r"(?ms)^struct subcell_account\s*\{.*?^\};", intf_masked)
    demand_shift = re.search(r"\bDEMAND_SHIFT\s*=\s*([0-9]+)\s*,", intf_masked)
    if not account_declaration or not demand_shift:
        unsupported("cannot extract subcell_account or DEMAND_SHIFT")
    constants.append("#define FIXTURE_HAS_DEMAND_ACCOUNTING 1\n")
    constants.append("#define FIXTURE_ACCOUNTED_AT running_accounted_at\n")
    constants.append(f"#define DEMAND_SHIFT {demand_shift.group(1)}\n")
    for name in ("DEMAND_TAU_NS", "DEMAND_MAX_WINDOW_NS"):
        match = re.search(r"(?m)^#define\s+" + name + r"\b[^\n]*", text)
        if not match:
            unsupported(f"missing demand constant {name}")
        constants.append(match.group() + "\n")
    prelude += intf_text[account_declaration.start():account_declaration.end()] + r"""

static int subcell_accounts;
static struct subcell_account fixture_accounts[MAX_CPUS][MAX_CELLS * MAX_SUBCELLS_PER_CELL];
static u64 scx_clock_task(s32 cpu) { (void)cpu; return now_ns; }
static void *bpf_map_lookup_percpu_elem(void *map, u32 *key, u32 cpu) {
    if (map == &subcell_accounts && cpu < MAX_CPUS && *key < MAX_CELLS * MAX_SUBCELLS_PER_CELL)
        return &fixture_accounts[cpu][*key];
    return NULL;
}
static void *bpf_map_lookup_elem(void *map, u32 *key) {
    return bpf_map_lookup_percpu_elem(map, key, 0);
}
"""
    accounting_functions = extract_function(text, masked, "update_task_demand")
    accounting_functions += account_running
    accounting_functions += extract_function(text, masked, "account_task_queued")
else:
    constants.append("#define FIXTURE_ACCOUNTED_AT charged_at\n")

code = prelude + "".join(constants)
code += rescue_take
code += llc_globals + llc_helpers
code += extract_function(text, masked, "advance_vtime", required=False)
functions = ["set_pinned_vtime_charge_cpu", "set_vtime_charge_subcell",
             "cap_vtime_debt", "advance_subcell_llc_vtime"]
code += extract_function(text, masked, "apply_cpu_vtime_assignment", required=False)
code += "".join(extract_function(text, masked, name) for name in functions)
code += extract_function(text, masked, "advance_task_vtime", required=False)
code += extract_function(text, masked, "clear_pinned_wait", required=False)
code += extract_function(text, masked, "task_shared_vtime", required=False)
code += rescue_helpers
code += accounting_functions
functions = ["mitosis_enqueue", "pinned_dsq_overdue", "mitosis_dispatch",
             "mitosis_running", "update_task_runtime_ewma"]
if extract_function(text, masked, "charge_running", required=False):
    functions.append("charge_running")
functions += ["mitosis_stopping", "mitosis_select_cpu"]
code += "".join(extract_function(text, masked, name) for name in functions)
code += r"""
static void reset_fixture(void) {
    memset(tasks, 0, sizeof(tasks));
    for (unsigned i = 0; i < 3; i++)
        FIXTURE_INIT_RESCUE(tasks[i].ctx);
    memset(cpus, 0, sizeof(cpus));
    memset(subcells, 0, sizeof(subcells));
#ifdef FIXTURE_HAS_DEMAND_ACCOUNTING
    memset(fixture_accounts, 0, sizeof(fixture_accounts));
#endif
    for (u32 cpu = 0; cpu < MAX_CPUS; cpu++)
        cpu_dsqs[cpu].id = get_cpu_dsq_id(cpu).raw;
    for (u32 cell = 0; cell < MAX_CELLS; cell++)
        for (u32 subcell = 0; subcell < MAX_SUBCELLS_PER_CELL; subcell++)
            for (u32 llc = 0; llc < MAX_LLCS; llc++)
                shared_dsqs[cell][subcell][llc].id = get_subcell_llc_dsq_id(cell, subcell, llc).raw;
    now_ns = 1;
    arrival_seq = 0;
    errors = 0;
    enable_llc_awareness = false;
    nr_llc = 1;
    enable_borrowing = false;
    direct_select_control = false;
    direct_enqueue_control = false;
    direct_insertions = 0;
    local_task = running_task = NULL;
}

static int run_case(unsigned count, bool shared) {
    const u64 rounds = count == 2 ? 30300 : 60300;
    u64 runs[3] = {0}, switches = 0, retained = 0;
    reset_fixture();
    /* Affinity covers either CPU 0 or the whole three-CPU cell. No sleeping,
     * borrowing, migration, refresh or slice shrinking occurs.
     */
    for (unsigned i = 0; i < count; i++) {
        struct task_struct *p = &tasks[i];
        p->pid = (int)i + 1;
        p->cpu = 0;
        p->cpus_ptr = shared ? &shared_affinity : &task_affinity;
        p->scx.weight = i + 1 == count ? 1 : 100;
        p->ctx.cpumask = shared ? &shared_mask : &task_mask;
        p->ctx.all_cell_cpus_allowed = shared;
        p->ctx.dsq = shared ? get_subcell_llc_dsq_id(0, 0, 0) : get_cpu_dsq_id(0);
        mitosis_enqueue(p, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED);
    }
    /* Bootstrap the first task. There is no runnable prev yet. */
    mitosis_dispatch(0, NULL);
    if (errors || !local_task) {
        fprintf(stderr, "ERROR: bootstrap dispatch made no progress\n");
        return 2;
    }
    running_task = local_task;
    running_task->scx.dsq = NULL;
    mitosis_running(running_task);
    for (u64 i = 0; i < rounds; i++) {
        struct task_struct *prev = running_task;
        unsigned idx = (unsigned)(prev - tasks);
        if (idx >= count || prev->queued || !(prev->scx.flags & SCX_TASK_QUEUED) ||
            queued_tasks(count) != count - 1) {
            fprintf(stderr, "ERROR: running task must be runnable outside its DSQ\n");
            return 2;
        }
        if (prev->scx.slice != slice_ns) {
            fprintf(stderr, "ERROR: fixture requires a full 1ms slice per service quantum\n");
            return 2;
        }
        runs[idx]++;
        now_ns += slice_ns;
        prev->scx.slice = 0;

        /*
         * The kernel dispatches before stopping and re-enqueuing runnable
         * prev. Renewing its slice keeps it running without either callback.
         */
        local_task = NULL;
        mitosis_dispatch(0, prev);
        if (errors) return 2;
        if (prev->scx.slice) {
            if (local_task) {
                fprintf(stderr, "ERROR: dispatch both renewed prev and moved a competitor\n");
                return 2;
            }
            retained++;
            continue;
        }
        if (!local_task || local_task == prev || queued_tasks(count) != count - 2) {
            fprintf(stderr, "ERROR: dispatch neither renewed prev nor selected a competitor\n");
            return 2;
        }
        struct task_struct *next = local_task;
        mitosis_stopping(prev, true);
        mitosis_enqueue(prev, 0);
        running_task = next;
        next->scx.dsq = NULL;
        mitosis_running(next);
        switches++;
        if (errors) return 2;
    }
    mitosis_stopping(running_task, true);
    if (errors || cpus[0].running_ns[0] != rounds * slice_ns) {
        fprintf(stderr, "ERROR: callback accounting disagrees with elapsed CPU service\n");
        return 2;
    }
    unsigned low = count - 1;
    double ratio0 = runs[low] ? (double)runs[0] / runs[low] : 0;
    double ratio1 = runs[low] ? (double)runs[1] / runs[low] : 0;
    double peers = runs[1] ? (double)runs[0] / runs[1] : 0;
    bool fair = runs[low] && ratio0 >= 95.0 && ratio0 <= 105.0;
    printf("Queue: %s DSQ.\n", shared ? "shared" : "CPU");
    if (count == 2) {
        printf("Two tasks, weights 100:1: service=%llu:%llu slices, ratio=%.4f:1.\n",
               runs[0], runs[1], ratio0);
        puts("Expected service=30000:300 slices, ratio=100:1.");
    } else {
        printf("Three tasks, weights 100:100:1: service=%llu:%llu:%llu slices.\n",
               runs[0], runs[1], runs[2]);
        printf("High/low ratios=%.4f:1 and %.4f:1; equal-weight peer ratio=%.4f:1.\n",
               ratio0, ratio1, peers);
        puts("Expected service=30000:30000:300 slices, ratios=100:1, 100:1, and 1:1.");
        fair = fair && runs[1] && ratio1 >= 95.0 && ratio1 <= 105.0 &&
               peers >= 0.98 && peers <= 1.02;
    }
    printf("Dispatch switches=%llu; retained slices=%llu.\n", switches, retained);
    if (!fair) {
        printf("BUG 2 REPRODUCED: %u continuously runnable tasks violate weighted fairness.\n",
               count);
        return 1;
    }
    return 0;
}

/*
 * A weight-50 task has run for 5ms since vtime 100ms. Its fair finish is
 * 110ms. A tick accounted the first 2ms, leaving 3ms for the next charge.
 */
static struct task_struct *prepare_prev(bool shared) {
    reset_fixture();
    struct task_struct *p = &tasks[0];
    p->pid = 1;
    p->cpu = 0;
    p->cpus_ptr = shared ? &shared_affinity : &task_affinity;
    p->scx.flags = SCX_TASK_QUEUED;
    p->scx.weight = 50;
    p->scx.dsq_vtime = 100000000;
    p->ctx.cpumask = shared ? &shared_mask : &task_mask;
    p->ctx.all_cell_cpus_allowed = shared;
    p->ctx.dsq = shared ? get_subcell_llc_dsq_id(0, 0, 0) : get_cpu_dsq_id(0);
    p->ctx.vtime_charge_subcell = pack_subcell_id(0, 0);
    p->ctx.basis_vtime = 100000000;
    p->ctx.started_running_at = 15000000;
    p->ctx.FIXTURE_ACCOUNTED_AT = 17000000;
    cpus[0].vtime_now = subcells[0][0].llcs[0].vtime_now = 100000000;
    cpus[0].running_ns[0] = 2000000;
#ifdef FIXTURE_HAS_DEMAND_ACCOUNTING
    fixture_accounts[0][pack_subcell_id(0, 0)].running_ns = 2000000;
    p->ctx.window_run_ns = 2000000;
    p->ctx.demand_window_at = 15000000;
#endif
    now_ns = 20000000;
    running_task = p;
    return p;
}

static struct task_struct *queue_head(void) {
    struct task_struct *p = &tasks[1];
    p->pid = 2;
    p->cpu = 0;
    p->cpus_ptr = &task_affinity;
    p->scx.weight = 100;
    p->scx.dsq_vtime = 115000000;
    p->ctx.cpumask = &task_mask;
    p->ctx.dsq = get_cpu_dsq_id(0);
    mitosis_enqueue(p, SCX_ENQ_CPU_SELECTED);
    if (errors || !p->queued || p->scx.dsq_vtime != 115000000) {
        fprintf(stderr, "ERROR: control head must retain its valid 15ms debt\n");
        return NULL;
    }
    return p;
}

static bool prev_accounting_unchanged(struct task_struct *p) {
    return p->scx.dsq_vtime == 100000000 &&
           p->ctx.started_running_at == 15000000 && p->ctx.FIXTURE_ACCOUNTED_AT == 17000000 &&
           cpus[0].running_ns[0] == 2000000;
}

static bool prev_renewal_accounting_valid(struct task_struct *p) {
#ifdef FIXTURE_HAS_DEMAND_ACCOUNTING
    /* Main accounts elapsed CPU-task time when retaining prev. Fair vtime
     * and the complete slice's wall-clock start remain for stopping(). */
    return p->scx.dsq_vtime == 100000000 &&
           p->ctx.started_running_at == 15000000 &&
           p->ctx.running_accounted_at == 20000000 &&
           cpus[0].running_ns[0] == 5000000;
#else
    return prev_accounting_unchanged(p);
#endif
}

static int rejected_prev(bool borrowed, bool head_present) {
    struct task_struct *prev = prepare_prev(borrowed);
    struct task_struct *head = head_present ? queue_head() : NULL;
    if (head_present && !head) return 2;
    if (borrowed) {
        /* CPU 0 joined the home cell before the new sequence was published. */
        enable_borrowing = true;
        prev->ctx.borrowed = true;
    } else {
        prev->ctx.vtime_charge_subcell = pack_subcell_id(0, 1);
    }
    /* The configuration is current; the separate placement guard must reject. */
    if (task_needs_refresh(prev, &prev->ctx)) {
        fprintf(stderr, "ERROR: rejection control requires a current configuration\n");
        return 2;
    }
    mitosis_dispatch(0, prev);
    if (errors) return 2;
    if (prev->scx.slice || local_task != head || !prev_accounting_unchanged(prev) ||
        cpus[0].vtime_now != 100000000 || subcells[0][0].llcs[0].vtime_now != 100000000) {
        printf("BUG 2: %s prev renewed or changed accounting %s a queued head.\n",
               borrowed ? "borrowed" : "stale-charge", head_present ? "with" : "without");
        return 1;
    }
    return 0;
}

static int overdue_pinned_head(void) {
    struct task_struct *prev = prepare_prev(true);
    struct task_struct *head = queue_head();
    if (!head) return 2;
    cpus[0].pinned_waiting_since = 1000000;
    if (!pinned_dsq_overdue(&cpus[0])) {
        fprintf(stderr, "ERROR: pinned control head must be overdue\n");
        return 2;
    }
    mitosis_dispatch(0, prev);
    if (errors) return 2;
    if (prev->scx.slice || local_task != head || !prev_accounting_unchanged(prev)) {
        puts("BUG 2: shared prev overrides an overdue pinned head.");
        return 1;
    }
    return 0;
}

static int valid_no_head(bool shared) {
    struct task_struct *prev = prepare_prev(shared);
    mitosis_dispatch(0, prev);
    if (errors) return 2;
    if (local_task || prev->scx.slice != slice_ns || !prev_renewal_accounting_valid(prev) ||
        cpus[0].vtime_now != 110000000 || subcells[0][0].llcs[0].vtime_now != 110000000) {
        printf("BUG 2: valid %s prev renewal changes its charge or fails to advance the frontier.\n",
               shared ? "shared" : "CPU");
        return 1;
    }
    mitosis_stopping(prev, true);
    if (errors) return 2;
    if (prev->scx.dsq_vtime != 110000000 || cpus[0].running_ns[0] != 5000000) {
        puts("BUG 2: stopping a renewed prev fails to charge its service exactly once.");
        return 1;
    }
    return 0;
}

/*
 * A sleeping weight-100 task retains vtime 0 while its assigned clock reaches
 * 100ms. A direct wakeup may receive one 1ms slice of credit, so an equal-weight
 * competitor at vtime 100ms must win after that slice. Partial affinity 0,1
 * within the three-CPU cell makes the pinned select_cpu call kernel-reachable.
 */
static int direct_wakeup(bool shared, bool retagged, bool skip_select) {
    reset_fixture();
    direct_select_control = true;
    direct_enqueue_control = skip_select;
    struct task_struct *prev = &tasks[0];
    u32 owner = retagged ? 1 : 0;
    prev->pid = 1;
    prev->cpu = 0;
    prev->cpus_ptr = shared ? &shared_affinity : &partial_affinity;
    prev->scx.weight = 100;
    prev->ctx.cpumask = shared ? &shared_mask : &partial_mask;
    prev->ctx.all_cell_cpus_allowed = shared;
    prev->ctx.dsq = shared ? get_subcell_llc_dsq_id(0, 0, 0) : get_cpu_dsq_id(0);
    prev->ctx.vtime_charge_subcell = pack_subcell_id(0, 0);
    if (skip_select) {
        /* This shared cell has only CPU 0, so the kernel skips select_cpu. */
        prev->cpus_ptr = &task_affinity;
        prev->ctx.cpumask = &task_mask;
    }
    cpus[0].cell = owner;
    cpus[0].vtime_now = subcells[owner][0].llcs[0].vtime_now = 100000000;
    s32 selected = 0;
    if (skip_select) {
        mitosis_enqueue(prev, SCX_ENQ_WAKEUP);
    } else {
        if (bpf_cpumask_weight(prev->cpus_ptr) <= 1) {
            fprintf(stderr, "ERROR: select_cpu control requires multi-CPU affinity\n");
            return 2;
        }
        selected = mitosis_select_cpu(prev, 0, SCX_WAKE_TTWU);
    }
    if (errors || selected != 0 || local_task != prev || direct_insertions != 1 ||
        prev->queued || prev->scx.slice != slice_ns) {
        fprintf(stderr, "ERROR: wakeup control requires direct insertion on CPU 0\n");
        return 2;
    }
    if (prev->scx.dsq_vtime != 99000000) {
        printf("BUG 2: direct %s wakeup via %s%s retained vtime %llu, expected 99000000.\n",
               shared ? "shared" : "pinned", skip_select ? "enqueue" : "select_cpu",
               retagged ? " after CPU retag" : "",
               prev->scx.dsq_vtime);
        return 1;
    }
    /* The CPU is occupied from here onward; later enqueues use normal DSQs. */
    direct_select_control = false;
    running_task = prev;
    prev->scx.dsq = NULL;
    mitosis_running(prev);
    now_ns += slice_ns;
    prev->scx.slice = 0;
    struct task_struct *head = &tasks[1];
    head->pid = 2;
    head->cpu = 0;
    head->cpus_ptr = shared ? &shared_affinity : &partial_affinity;
    head->scx.weight = 100;
    head->scx.dsq_vtime = 100000000;
    head->ctx.cpumask = shared ? &shared_mask : &partial_mask;
    head->ctx.all_cell_cpus_allowed = shared;
    head->ctx.dsq = prev->ctx.dsq;
    if (skip_select) {
        head->cpus_ptr = &task_affinity;
        head->ctx.cpumask = &task_mask;
    }
    mitosis_enqueue(head, SCX_ENQ_WAKEUP | (skip_select ? 0 : SCX_ENQ_CPU_SELECTED));
    local_task = NULL;
    mitosis_dispatch(0, prev);
    if (errors) return 2;
    if (prev->scx.slice || local_task != head || prev->scx.dsq_vtime != 99000000) {
        printf("BUG 2: direct %s waker%s retained the CPU after using its wakeup credit.\n",
               shared ? "shared" : "pinned", retagged ? " after CPU retag" : "");
        return 1;
    }
    mitosis_stopping(prev, true);
    mitosis_enqueue(prev, 0);
    if (errors) return 2;
    if (prev->scx.dsq_vtime != 100000000 || cpus[0].running_ns[0] != 1000000) {
        puts("BUG 2: direct waker's subsequent enqueue loses its weighted runtime charge.");
        return 1;
    }
    return 0;
}

#ifdef FIXTURE_HAS_TASK_RESCUE
/*
 * A dequeue after a remote rescue retains the old LLC assignment. The task's
 * original key owes 15ms to LLC 0's 100ms clock. Only a changed rescue key must
 * be reset to that old clock before normal placement translates it to LLC 1's
 * 200ms clock. An unchanged key retains its 15ms debt through the translation.
 */
static int ready_placement(bool use_select, bool changed_key) {
    reset_fixture();
    enable_llc_awareness = true;
    nr_llc = 2;
    cpu_to_llc[0] = 0;
    cpu_to_llc[1] = cpu_to_llc[2] = 1;
    llc_to_cpus[0].bits = 1;
    llc_to_cpus[1].bits = 6;
    fixture_llc_mask.bits = 1;
    cpus[0].llc = 0;
    cpus[1].llc = 1;
    cpus[0].vtime_now = subcells[0][0].llcs[0].vtime_now = 100000000;
    cpus[1].vtime_now = subcells[0][0].llcs[1].vtime_now = 200000000;
    subcells[0][0].llcs_with_cpus = 3;

    struct task_struct *p = &tasks[0];
    p->pid = 1;
    p->cpu = 1;
    p->cpus_ptr = &shared_affinity;
    p->scx.flags = SCX_TASK_QUEUED;
    p->scx.weight = 100;
    p->scx.dsq_vtime = changed_key ? 350000000 : 115000000;
    /* The kernel has removed the task from its physical rescue DSQ. */
    p->scx.dsq = NULL;
    p->ctx.cpumask = &shared_mask;
    p->ctx.llc_cpumask = &fixture_llc_mask;
    p->ctx.all_cell_cpus_allowed = true;
    p->ctx.dsq = get_subcell_llc_dsq_id(0, 0, 0);
    p->ctx.llc = p->ctx.llc_cpumask_id = 0;
    p->ctx.vtime_charge_subcell = pack_subcell_id(0, 0);
    p->ctx.basis_vtime = 100000000;
    p->ctx.rescue_seq = TASK_RESCUE_GENERATION_STEP | TASK_RESCUE_READY;
    p->ctx.rescue_vtime = 115000000;

    if (use_select) {
        s32 selected = mitosis_select_cpu(p, 1, SCX_WAKE_TTWU);
        if (errors || selected != 1 || p->queued || p->scx.dsq) {
            fputs("ERROR: READY select_cpu control did not retain the busy CPU\n", stderr);
            return 2;
        }
        if (p->scx.dsq_vtime != (changed_key ? 100000000 : 115000000)) {
            printf("BUG: select_cpu %s the READY rescue key before ordinary placement.\n",
                   changed_key ? "retained" : "discarded debt from");
            return 1;
        }
        if ((p->ctx.rescue_seq & TASK_RESCUE_PHASE_MASK) != TASK_RESCUE_NONE) {
            puts("BUG: select_cpu left READY rescue state for a later placement.");
            return 1;
        }
    }

    mitosis_enqueue(p, SCX_ENQ_WAKEUP | SCX_ENQ_CPU_SELECTED);
    dsq_id_t placed_dsq = get_subcell_llc_dsq_id(0, 0, 1);
    if (errors || !p->queued || !p->scx.dsq || p->scx.dsq->id != placed_dsq.raw ||
        p->ctx.dsq.raw != placed_dsq.raw || p->ctx.llc != 1) {
        fputs("ERROR: READY enqueue control did not place the task in LLC 1\n", stderr);
        return 2;
    }
    if (p->scx.dsq_vtime != (changed_key ? 200000000 : 215000000)) {
        printf("BUG: %sREADY enqueue %s across the ordinary LLC translation.\n",
               use_select ? "selected " : "",
               changed_key ? "retained a foreign key" : "lost legitimate debt");
        return 1;
    }
    if ((p->ctx.rescue_seq & TASK_RESCUE_PHASE_MASK) != TASK_RESCUE_NONE) {
        puts("BUG: enqueue left READY rescue state behind the translated key.");
        return 1;
    }
    return 0;
}
#endif

int main(void) {
    int result, reproduced = 0;
    result = run_case(2, false);
    if (result == 2) return 2;
    reproduced |= result;
    result = run_case(3, false);
    if (result == 2) return 2;
    reproduced |= result;
    result = run_case(3, true);
    if (result == 2) return 2;
    reproduced |= result;
    int controls_failed = 0;
    for (unsigned borrowed = 0; borrowed < 2; borrowed++) {
        for (unsigned head = 0; head < 2; head++) {
            result = rejected_prev(borrowed, head);
            if (result == 2) return 2;
            controls_failed |= result;
        }
    }
    result = overdue_pinned_head();
    if (result == 2) return 2;
    controls_failed |= result;
    for (unsigned shared = 0; shared < 2; shared++) {
        result = valid_no_head(shared);
        if (result == 2) return 2;
        controls_failed |= result;
    }
    if (!controls_failed)
        puts("PASS: renewal guards and CPU/shared no-head accounting controls.");
    int direct_failed = 0;
    result = direct_wakeup(false, false, false);
    if (result == 2) return 2;
    direct_failed |= result;
    result = direct_wakeup(false, true, false);
    if (result == 2) return 2;
    direct_failed |= result;
    result = direct_wakeup(true, false, false);
    if (result == 2) return 2;
    direct_failed |= result;
    result = direct_wakeup(true, false, true);
    if (result == 2) return 2;
    direct_failed |= result;
    if (!direct_failed)
        puts("PASS: direct pinned/shared wakeup credit, including CPU ownership changes.");
#ifdef FIXTURE_HAS_TASK_RESCUE
    int rescue_failed = 0;
    for (unsigned use_select = 0; use_select < 2; use_select++) {
        for (unsigned changed_key = 0; changed_key < 2; changed_key++) {
            result = ready_placement(use_select, changed_key);
            if (result == 2) return 2;
            rescue_failed |= result;
        }
    }
    if (rescue_failed) return 1;
    puts("PASS: READY placement restores the old clock before LLC translation and preserves unchanged debt.");
#endif
    if (reproduced || controls_failed || direct_failed) return 1;
    puts("PASS: all task sets follow their weights without starving an equal-weight peer.");
    return 0;
}
"""
try:
    pathlib.Path(sys.argv[3]).write_text(code)
except OSError as exc:
    print(f"ERROR: cannot write generated harness: {exc}", file=sys.stderr)
    raise SystemExit(2)
PYTHON
if ! "${CC:-cc}" -O2 -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -Wno-unused-const-variable -Wno-sign-compare -Wno-attributes "$repro_tmp/repro.c" -o "$repro_tmp/repro"; then
    printf 'ERROR: cannot compile callbacks with this harness; checkout may need new adapters\n' >&2
    exit 2
fi
"$repro_tmp/repro"
