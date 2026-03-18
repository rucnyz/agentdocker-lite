#!/usr/bin/env python3
"""Benchmark: agentdocker-lite vs Docker lifecycle and command performance.

Usage:
    python examples/benchmark.py

Runs identical operations on both backends and prints a comparison table.
Requires Docker daemon running. No root required.
"""

import subprocess
import time

IMAGE = "ubuntu:22.04"
N_COMMANDS = 20
CONTAINER_NAME = "adl-bench-docker"


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

def _docker_run(cmd: str) -> str:
    return subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
        capture_output=True, text=True,
    ).stdout


def bench_docker() -> dict:
    # Pull image (not timed — same for both)
    subprocess.run(["docker", "pull", "-q", IMAGE], capture_output=True)

    # Create + start
    t0 = time.monotonic()
    subprocess.run(
        ["docker", "run", "-d", "--name", CONTAINER_NAME, IMAGE, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    create_ms = (time.monotonic() - t0) * 1000

    # Per-command latency
    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        _docker_run(f"echo iteration-{i}")
        cmd_times.append((time.monotonic() - t0) * 1000)
    avg_cmd_ms = sum(cmd_times) / len(cmd_times)

    # "Reset" = remove + recreate (Docker has no built-in reset)
    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    subprocess.run(
        ["docker", "run", "-d", "--name", CONTAINER_NAME, IMAGE, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    reset_ms = (time.monotonic() - t0) * 1000

    # Delete
    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    delete_ms = (time.monotonic() - t0) * 1000

    return {
        "create_ms": create_ms,
        "cmd_ms": avg_cmd_ms,
        "reset_ms": reset_ms,
        "delete_ms": delete_ms,
    }


# ---------------------------------------------------------------------------
# agentdocker-lite
# ---------------------------------------------------------------------------

def bench_sandbox() -> dict:
    from agentdocker_lite import Sandbox, SandboxConfig

    config = SandboxConfig(image=IMAGE, working_dir="/workspace")

    # Create
    t0 = time.monotonic()
    sb = Sandbox(config, name="adl-bench-sandbox")
    create_ms = (time.monotonic() - t0) * 1000

    # Per-command latency
    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        sb.run(f"echo iteration-{i}")
        cmd_times.append((time.monotonic() - t0) * 1000)
    avg_cmd_ms = sum(cmd_times) / len(cmd_times)

    # Reset
    t0 = time.monotonic()
    sb.reset()
    reset_ms = (time.monotonic() - t0) * 1000

    # Delete
    t0 = time.monotonic()
    sb.delete()
    delete_ms = (time.monotonic() - t0) * 1000

    return {
        "create_ms": create_ms,
        "cmd_ms": avg_cmd_ms,
        "reset_ms": reset_ms,
        "delete_ms": delete_ms,
    }


# ---------------------------------------------------------------------------
# CRIU checkpoint/restore benchmark
# ---------------------------------------------------------------------------

N_CRIU_ITERS = 5

def bench_criu() -> dict | None:
    import os
    import shutil

    if os.geteuid() != 0:
        return None

    from agentdocker_lite import Sandbox, SandboxConfig, CheckpointManager

    config = SandboxConfig(image=IMAGE, working_dir="/workspace")
    sb = Sandbox(config, name="adl-bench-criu")

    if not CheckpointManager.check_available():
        sb.delete()
        return None

    mgr = CheckpointManager(sb)
    sb.run("echo data > /workspace/test.txt")

    # Save latency
    save_times = []
    for i in range(N_CRIU_ITERS):
        ckpt = f"/tmp/adl_bench_ckpt_{i}"
        shutil.rmtree(ckpt, ignore_errors=True)
        t0 = time.monotonic()
        mgr.save(ckpt)
        save_times.append((time.monotonic() - t0) * 1000)

    # Restore latency
    restore_times = []
    for i in range(N_CRIU_ITERS):
        sb.run("echo modified > /workspace/test.txt")
        t0 = time.monotonic()
        mgr.restore(f"/tmp/adl_bench_ckpt_{i}")
        restore_times.append((time.monotonic() - t0) * 1000)

    sb.delete()
    for i in range(N_CRIU_ITERS):
        shutil.rmtree(f"/tmp/adl_bench_ckpt_{i}", ignore_errors=True)

    return {
        "save_ms": sum(save_times) / len(save_times),
        "restore_ms": sum(restore_times) / len(restore_times),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Cleanup stale container
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)

    print(f"Benchmarking with {IMAGE}, {N_COMMANDS} commands each\n")

    # Warmup: ensure rootfs is cached (first export is slow)
    from agentdocker_lite import Sandbox, SandboxConfig
    print("Warming up (caching rootfs)...")
    _sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/"), name="adl-bench-warmup")
    _sb.delete()

    print("Running Docker benchmark...")
    docker = bench_docker()

    print("Running agentdocker-lite benchmark...")
    sandbox = bench_sandbox()

    # Results
    print(f"\n{'':20} {'Docker':>12} {'adl':>12} {'speedup':>10}")
    print("-" * 56)
    for label, key in [
        ("Create", "create_ms"),
        ("Per command (avg)", "cmd_ms"),
        ("Reset", "reset_ms"),
        ("Delete", "delete_ms"),
    ]:
        d = docker[key]
        s = sandbox[key]
        speedup = d / s if s > 0 else float("inf")
        print(f"{label:20} {d:>10.1f}ms {s:>10.1f}ms {speedup:>9.1f}x")

    # CRIU benchmark
    print("\nRunning CRIU checkpoint benchmark...")
    criu = bench_criu()
    if criu:
        print(f"{'CRIU save':20} {'—':>12} {criu['save_ms']:>10.1f}ms {'—':>9}")
        print(f"{'CRIU restore':20} {'—':>12} {criu['restore_ms']:>10.1f}ms {'—':>9}")
    else:
        print("CRIU not available (requires root + CRIU binary)")


if __name__ == "__main__":
    main()
