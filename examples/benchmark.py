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


def bench_docker_throughput() -> dict:
    """1000 sequential docker exec commands."""
    N = 1000
    # Ensure container is running
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    subprocess.run(
        ["docker", "run", "-d", "--name", CONTAINER_NAME, IMAGE, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    t0 = time.monotonic()
    for i in range(N):
        _docker_run(f"echo {i}")
    elapsed = time.monotonic() - t0
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    return {"total_s": elapsed, "ops_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}


def bench_docker_reset_loop() -> dict:
    """exec → rm+run (reset) 100 times."""
    N = 100
    t0 = time.monotonic()
    for i in range(N):
        subprocess.run(
            ["docker", "run", "-d", "--name", CONTAINER_NAME, IMAGE, "sleep", "infinity"],
            capture_output=True, check=True,
        )
        _docker_run(f"echo episode-{i}")
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    elapsed = time.monotonic() - t0
    return {"total_s": elapsed, "cycles_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}


def bench_docker_concurrent() -> dict:
    """Parallel docker containers — 10 cmds each."""
    from concurrent.futures import ThreadPoolExecutor

    results = {}
    for n in [4, 8, 16]:
        def worker(i):
            name = f"adl-bench-docker-par-{i}"
            subprocess.run(
                ["docker", "run", "-d", "--name", name, IMAGE, "sleep", "infinity"],
                capture_output=True, check=True,
            )
            for j in range(10):
                subprocess.run(
                    ["docker", "exec", name, "bash", "-c", f"echo {j}"],
                    capture_output=True,
                )
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)

        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(worker, range(n)))
        elapsed = time.monotonic() - t0
        results[n] = {"total_s": elapsed, "cmds_per_sec": n * 10 / elapsed}
    return results


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
# Sustained workload benchmarks
# ---------------------------------------------------------------------------

def bench_throughput() -> dict:
    """1000 sequential commands — measures sustained throughput."""
    from agentdocker_lite import Sandbox, SandboxConfig
    N = 1000

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="adl-bench-tp")
    t0 = time.monotonic()
    for i in range(N):
        sb.run(f"echo {i}")
    elapsed = time.monotonic() - t0
    sb.delete()

    return {
        "total_s": elapsed,
        "ops_per_sec": N / elapsed,
        "avg_ms": elapsed / N * 1000,
    }


def bench_reset_loop() -> dict:
    """run → reset → run → reset 100 times — simulates RL episode resets."""
    from agentdocker_lite import Sandbox, SandboxConfig
    N = 100

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="adl-bench-reset")
    t0 = time.monotonic()
    for i in range(N):
        sb.run(f"echo episode-{i} > /workspace/state.txt")
        sb.reset()
    elapsed = time.monotonic() - t0
    sb.delete()

    return {
        "total_s": elapsed,
        "cycles_per_sec": N / elapsed,
        "avg_ms": elapsed / N * 1000,
    }


def bench_checkpoint_loop() -> dict | None:
    """save → run → restore 50 times — simulates partial rollout."""
    import os
    import shutil

    if os.geteuid() != 0:
        return None

    from agentdocker_lite import Sandbox, SandboxConfig, CheckpointManager

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="adl-bench-ckpt-loop")
    if not CheckpointManager.check_available():
        sb.delete()
        return None

    mgr = CheckpointManager(sb)
    N = 50
    ckpt = "/tmp/adl_bench_ckpt_loop"

    sb.run("echo base_state > /workspace/data.txt")
    shutil.rmtree(ckpt, ignore_errors=True)
    mgr.save(ckpt)

    t0 = time.monotonic()
    for i in range(N):
        sb.run(f"echo step-{i} >> /workspace/log.txt")
        mgr.restore(ckpt)
    elapsed = time.monotonic() - t0

    sb.delete()
    shutil.rmtree(ckpt, ignore_errors=True)

    return {
        "total_s": elapsed,
        "cycles_per_sec": N / elapsed,
        "avg_ms": elapsed / N * 1000,
    }


def bench_ab_comparison() -> None:
    """Side-by-side timing comparison against real Docker.

    Matches Harbor's DockerEnvironment flow:
      Docker:           docker build → docker run -d → docker exec (N times) → docker rm -f
      AgentDockerLite:  Sandbox(config) → sb.run() (N times) → sb.delete()
    """
    from agentdocker_lite import Sandbox, SandboxConfig

    commands = [
        "echo hello",
        "python3 --version 2>&1 || true",
        "ls /",
        "cat /etc/os-release | head -1",
        "echo done > /tmp/out.txt && cat /tmp/out.txt",
    ]

    docker_tag = "adl_bench_docker"
    docker_container = "adl_bench_container"

    # ── AgentDockerLite ──
    config = SandboxConfig(image=IMAGE, working_dir="/app")
    t0 = time.monotonic()
    sb = Sandbox(config, name="bench-ab")
    adl_start = (time.monotonic() - t0) * 1000

    adl_exec_times = []
    for cmd in commands:
        t = time.monotonic()
        sb.run(cmd)
        adl_exec_times.append((time.monotonic() - t) * 1000)

    t0 = time.monotonic()
    sb.delete()
    adl_stop = (time.monotonic() - t0) * 1000

    # ── Docker (matches Harbor's DockerEnvironment flow) ──
    subprocess.run(["docker", "rm", "-f", docker_container], capture_output=True)

    # Build + start
    t0 = time.monotonic()
    subprocess.run(
        ["docker", "build", "-t", docker_tag, "-"],
        input=b"FROM ubuntu:22.04\nRUN mkdir -p /app\nWORKDIR /app\n",
        capture_output=True, check=True,
    )
    subprocess.run(
        ["docker", "run", "-d", "--name", docker_container, docker_tag, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    docker_start = (time.monotonic() - t0) * 1000

    docker_exec_times = []
    for cmd in commands:
        t = time.monotonic()
        subprocess.run(
            ["docker", "exec", docker_container, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=30,
        )
        docker_exec_times.append((time.monotonic() - t) * 1000)

    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", docker_container], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", docker_tag], capture_output=True)
    docker_stop = (time.monotonic() - t0) * 1000

    # ── Print comparison ──
    print("\n" + "=" * 70)
    print("  A/B Benchmark: AgentDockerLite vs Docker")
    print("  (Docker flow: build + run -d + exec + rm, like Harbor)")
    print("=" * 70)
    print(f"  {'Operation':30s} {'ADL':>10s} {'Docker':>10s} {'Speedup':>10s}")
    print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*10}")

    def _row(label, a, d):
        sp = d / a if a > 0 else float("inf")
        print(f"  {label:30s} {a:7.1f} ms {d:7.1f} ms {sp:8.1f}x")

    _row("Create / Start", adl_start, docker_start)
    adl_exec_mean = sum(adl_exec_times) / len(adl_exec_times)
    docker_exec_mean = sum(docker_exec_times) / len(docker_exec_times)
    _row("Exec (mean)", adl_exec_mean, docker_exec_mean)
    _row("Stop / Cleanup", adl_stop, docker_stop)

    print()
    print(f"  {'Per-command breakdown':30s} {'ADL':>10s} {'Docker':>10s} {'Speedup':>10s}")
    print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*10}")
    for i, cmd in enumerate(commands):
        _row(cmd[:28], adl_exec_times[i], docker_exec_times[i])
    print("=" * 70)


def bench_concurrent() -> dict:
    """Parallel sandboxes — measures scalability."""
    from concurrent.futures import ThreadPoolExecutor
    from agentdocker_lite import Sandbox, SandboxConfig

    results = {}
    for n in [4, 8, 16]:
        def worker(i):
            sb = Sandbox(
                SandboxConfig(image=IMAGE, working_dir="/workspace"),
                name=f"adl-bench-par-{i}",
            )
            for j in range(10):
                sb.run(f"echo {j}")
            sb.delete()

        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(worker, range(n)))
        elapsed = time.monotonic() - t0

        total_cmds = n * 10
        results[n] = {
            "total_s": elapsed,
            "cmds_per_sec": total_cmds / elapsed,
        }

    return results


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

    # CRIU single-op benchmark
    print("\nRunning CRIU checkpoint benchmark...")
    criu = bench_criu()
    if criu:
        print(f"{'CRIU save':20} {'—':>12} {criu['save_ms']:>10.1f}ms {'—':>9}")
        print(f"{'CRIU restore':20} {'—':>12} {criu['restore_ms']:>10.1f}ms {'—':>9}")
    else:
        print("CRIU not available (requires root + CRIU binary)")

    # Sustained workloads
    print("\n--- Sustained workloads ---\n")

    print("Throughput (1000 sequential commands)...")
    docker_tp = bench_docker_throughput()
    adl_tp = bench_throughput()
    speedup = adl_tp["ops_per_sec"] / docker_tp["ops_per_sec"]
    print(f"  Docker: {docker_tp['ops_per_sec']:.0f} cmd/s  (avg {docker_tp['avg_ms']:.1f}ms)")
    print(f"  adl:    {adl_tp['ops_per_sec']:.0f} cmd/s  (avg {adl_tp['avg_ms']:.1f}ms)  {speedup:.1f}x")

    print("Reset loop (100 run+reset cycles)...")
    docker_rl = bench_docker_reset_loop()
    adl_rl = bench_reset_loop()
    speedup = adl_rl["cycles_per_sec"] / docker_rl["cycles_per_sec"]
    print(f"  Docker: {docker_rl['cycles_per_sec']:.1f} resets/s  (avg {docker_rl['avg_ms']:.0f}ms)")
    print(f"  adl:    {adl_rl['cycles_per_sec']:.1f} resets/s  (avg {adl_rl['avg_ms']:.0f}ms)  {speedup:.1f}x")

    print("Checkpoint loop (50 run+restore cycles)...")
    cl = bench_checkpoint_loop()
    if cl:
        print(f"  adl:    {cl['cycles_per_sec']:.1f} restores/s  (avg {cl['avg_ms']:.0f}ms)")
        print("  (Docker checkpoint requires experimental daemon — not benchmarked)")
    else:
        print("  Skipped (requires root + CRIU)")

    print("\n--- A/B comparison (Harbor-style flow) ---\n")
    bench_ab_comparison()

    print("\nConcurrent sandboxes (4/8/16 parallel, 10 cmds each)...")
    docker_conc = bench_docker_concurrent()
    adl_conc = bench_concurrent()
    for n in [4, 8, 16]:
        d = docker_conc[n]
        a = adl_conc[n]
        speedup = a["cmds_per_sec"] / d["cmds_per_sec"]
        print(f"  {n:2d}x: Docker {d['cmds_per_sec']:.0f} cmd/s | adl {a['cmds_per_sec']:.0f} cmd/s  {speedup:.1f}x")


def bench_port_map():
    """Compare sandbox creation with and without port_map."""
    import os
    from agentdocker_lite import Sandbox, SandboxConfig

    if os.geteuid() != 0:
        print("  Skipped (requires root)")
        return
    if not os.path.exists("/dev/net/tun"):
        print("  Skipped (requires /dev/net/tun)")
        return

    N = 5
    # Without port_map
    times_no_port = []
    for i in range(N):
        t0 = time.monotonic()
        sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/"), name=f"bench-noport-{i}")
        times_no_port.append((time.monotonic() - t0) * 1000)
        sb.delete()

    # With port_map (pasta networking, parallelized)
    times_port = []
    for i in range(N):
        t0 = time.monotonic()
        sb = Sandbox(SandboxConfig(
            image=IMAGE, working_dir="/",
            net_isolate=True, port_map=[f"{19800+i}:8000"],
        ), name=f"bench-port-{i}")
        times_port.append((time.monotonic() - t0) * 1000)
        sb.delete()

    avg_no = sum(times_no_port) / len(times_no_port)
    avg_port = sum(times_port) / len(times_port)
    overhead = avg_port - avg_no
    print(f"  Without port_map:  {avg_no:.1f}ms")
    print(f"  With port_map:     {avg_port:.1f}ms  (+{overhead:.1f}ms overhead)")


if __name__ == "__main__":
    main()
    print("\n--- Port mapping overhead ---\n")
    bench_port_map()
