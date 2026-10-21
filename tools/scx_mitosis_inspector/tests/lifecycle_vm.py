#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise real BPF attachment/reset/restart inside a disposable virtme guest.

Run with a read-only guest filesystem and at least 72 vCPUs, for example:
  vng --run /boot/vmlinuz --name mitosis-inspector-test --cpus 72 --memory 4G \
      --user root --overlay-rwdir /tmp --exec \
      'python3 tools/scx_mitosis_inspector/tests/lifecycle_vm.py'
"""
import ctypes
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
import urllib.request


def main():
    if os.geteuid() != 0 or "virtme" not in Path("/proc/cmdline").read_text():
        raise SystemExit("This test owns its scheduler and must run as root inside a virtme guest")
    repo = Path(__file__).resolve().parents[3]
    inspector_bin = repo / "tools/scx_mitosis_inspector/target/release/scx_mitosis_inspector"
    scheduler_bin = Path(os.environ.get("MITOSIS_BIN", "/home/tommyu/scx/target/release/scx_mitosis"))
    url = "http://127.0.0.1:44103"
    scheduler = inspector = worker = None
    logs = []

    def log_file(name):
        stream = open(f"/tmp/{name}.log", "w+")
        logs.append(stream)
        return stream

    def fetch(path, method="GET"):
        with urllib.request.urlopen(urllib.request.Request(url + path, method=method), timeout=20) as response:
            assert response.status == 200
            return json.load(response)

    def until(predicate, label, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if inspector and inspector.poll() is not None:
                raise AssertionError(f"inspector exited: {inspector.returncode}")
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.2)
        raise AssertionError(f"timed out waiting for {label}")

    def snapshot(status):
        value = fetch("/api/counters")
        return value if value["collector"]["status"] == status else None

    def start_scheduler():
        return subprocess.Popen([
            str(scheduler_bin), "--cell-parent-cgroup", "/workload.slice/workload-tw.slice",
            "--cell0-min-cpus", "4",
        ], stdout=log_file("mitosis-vm-scheduler"), stderr=subprocess.STDOUT)

    def stop(process):
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    try:
        assert Path("/sys/kernel/sched_ext/state").read_text().strip() == "disabled"
        Path("/sys/fs/cgroup/workload.slice/workload-tw.slice").mkdir(parents=True, exist_ok=True)
        inspector = subprocess.Popen([str(inspector_bin)], stdout=log_file("mitosis-vm-inspector"), stderr=subprocess.STDOUT)
        waiting = until(lambda: snapshot("waiting"), "HTTP while no scheduler is attached")
        assert waiting["meta"]["sample_seq"] == 0
        scheduler = start_scheduler()
        active = until(lambda: snapshot("active"), "initial attachment")
        epoch = active["meta"]["epoch"]
        seq = active["collector"]["scheduler_enable_seq"]
        assert active["meta"]["captured_at_unix_ms"] is not None
        assert active["migration_quality"] == "complete"
        assert active["migration_map_capacity"] > 4096
        until(lambda: fetch("/api/stats")["metrics"], "stats socket collection")
        print(f"Attached: epoch={epoch}, enable_seq={seq}, capacity={active['migration_map_capacity']}", flush=True)

        # Fill the actual inspector-owned kernel HASH beyond the old 4096 limit.
        maps = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))
        migration_maps = [m for m in maps if m["name"] == "migration_counts"[:15]]
        assert len(migration_maps) == 1
        migration_map = migration_maps[0]
        assert migration_map["type"] == "hash"
        assert migration_map["max_entries"] == active["migration_map_capacity"]
        lib = ctypes.CDLL("libbpf.so.1", use_errno=True)
        lib.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint32]
        lib.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
        lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        fd = lib.bpf_map_get_fd_by_id(migration_map["id"])
        assert fd >= 0
        marker = ctypes.c_uint64(1_000_000_000)
        cpus = os.cpu_count()
        pairs = list(itertools.islice(((a, b) for a in range(cpus) for b in range(cpus) if a != b), 4097))
        assert len(pairs) == 4097
        try:
            for pair in pairs:
                key = (ctypes.c_uint32 * 2)(*pair)
                assert lib.bpf_map_update_elem(fd, key, ctypes.byref(marker), 0) == 0
            for pair in pairs:
                key = (ctypes.c_uint32 * 2)(*pair)
                count = ctypes.c_uint64()
                assert lib.bpf_map_lookup_elem(fd, key, ctypes.byref(count)) == 0
                assert count.value >= marker.value
        finally:
            os.close(fd)
        print("Actual kernel map retained 4097 distinct migration pairs", flush=True)
        receipt = fetch("/api/reset", "POST")
        assert receipt["epoch"] > epoch and receipt["sample_seq"] == 1
        fresh = fetch("/api/counters")
        assert fresh["meta"]["epoch"] == receipt["epoch"]
        assert fresh["meta"]["sample_seq"] >= receipt["sample_seq"]
        assert fresh["collector"]["scheduler_enable_seq"] == seq
        assert scheduler.poll() is None
        assert not any(row["count"] >= marker.value for row in fresh["migrations"])
        migration_view = fetch("/api/migrations")
        assert migration_view["meta"]["epoch"] == receipt["epoch"]
        print(f"Reset published epoch={receipt['epoch']} without restarting scheduler", flush=True)

        # A controller on CPU C moves a worker A -> B; C must not be the source.
        worker = subprocess.Popen(["yes"], stdout=subprocess.DEVNULL)
        os.sched_setaffinity(0, {10})
        os.sched_setaffinity(worker.pid, {8})
        time.sleep(0.1)
        for _ in range(20):
            os.sched_setaffinity(worker.pid, {9})
            time.sleep(0.01)
            os.sched_setaffinity(worker.pid, {8})
            time.sleep(0.01)
        until(lambda: any(row["from_cpu"] == 8 and row["to_cpu"] == 9 and row["count"] >= 10
                          for row in fetch("/api/counters")["migrations"]), "origin CPU attribution")
        print("Task migrations from CPU8 to9 observed with controller on CPU10", flush=True)
        stop(worker)
        worker = None

        stop(scheduler)
        scheduler = None
        stopped = until(lambda: snapshot("waiting"), "scheduler stop invalidation")
        assert stopped["meta"]["sample_seq"] == 0 and stopped["counters"] == []
        assert stopped["migrations"] == [] and stopped["meta"]["captured_at_unix_ms"] is None
        assert stopped["meta"]["last_success_at_unix_ms"] is not None
        scheduler = start_scheduler()
        restarted = until(lambda: snapshot("active"), "scheduler restart reattachment")
        assert restarted["meta"]["epoch"] > receipt["epoch"]
        assert restarted["collector"]["scheduler_enable_seq"] > seq
        assert restarted["target_program_ids"] != active["target_program_ids"]
        print(f"Restart reattached: epoch={restarted['meta']['epoch']}, enable_seq={restarted['collector']['scheduler_enable_seq']}", flush=True)
        print("PASS: waiting HTTP, real BPF map retention/source, reset, stop, restart", flush=True)
    except Exception:
        for stream in logs:
            stream.flush()
            stream.seek(0)
            text = stream.read()
            print(f"--- {stream.name} (tail) ---\n{text[-10000:]}")
        raise
    finally:
        stop(worker)
        stop(inspector)
        stop(scheduler)
        for stream in logs:
            stream.close()


if __name__ == "__main__":
    main()
