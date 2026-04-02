#!/usr/bin/env python3
"""Benchmark: nitrobox vs Docker/Podman/OpenSandbox/SWE-MiniSandbox.

Usage:
    python examples/benchmark.py
    python examples/benchmark.py --no-docker --no-podman
    python examples/benchmark.py --no-opensandbox --no-swe

Runs identical operations on all available backends and prints comparison tables.
Auto-detects which backends are available and skips unavailable ones.
"""

import subprocess
import time

IMAGE = "ubuntu:22.04"
N_COMMANDS = 20
CONTAINER_NAME = "nbx-bench-docker"


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
            name = f"nbx-bench-docker-par-{i}"
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
# Podman (rootless, same CLI as Docker)
# ---------------------------------------------------------------------------

PODMAN_CONTAINER = "nbx-bench-podman"

def _podman_available() -> bool:
    return subprocess.run(["podman", "--version"], capture_output=True).returncode == 0


def _podman_run(cmd: str) -> str:
    return subprocess.run(
        ["podman", "exec", PODMAN_CONTAINER, "bash", "-c", cmd],
        capture_output=True, text=True,
    ).stdout


def bench_podman() -> dict | None:
    if not _podman_available():
        return None

    subprocess.run(["podman", "rm", "-f", PODMAN_CONTAINER], capture_output=True)

    # Create + start
    t0 = time.monotonic()
    subprocess.run(
        ["podman", "run", "-d", "--name", PODMAN_CONTAINER, IMAGE, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    create_ms = (time.monotonic() - t0) * 1000

    # Per-command latency
    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        _podman_run(f"echo iteration-{i}")
        cmd_times.append((time.monotonic() - t0) * 1000)
    avg_cmd_ms = sum(cmd_times) / len(cmd_times)

    # "Reset" = remove + recreate
    t0 = time.monotonic()
    subprocess.run(["podman", "rm", "-f", PODMAN_CONTAINER], capture_output=True)
    subprocess.run(
        ["podman", "run", "-d", "--name", PODMAN_CONTAINER, IMAGE, "sleep", "infinity"],
        capture_output=True, check=True,
    )
    reset_ms = (time.monotonic() - t0) * 1000

    # Delete
    t0 = time.monotonic()
    subprocess.run(["podman", "rm", "-f", PODMAN_CONTAINER], capture_output=True)
    delete_ms = (time.monotonic() - t0) * 1000

    return {
        "create_ms": create_ms,
        "cmd_ms": avg_cmd_ms,
        "reset_ms": reset_ms,
        "delete_ms": delete_ms,
    }




# ---------------------------------------------------------------------------
# OpenSandbox (HTTP API → Docker + execd daemon)
# ---------------------------------------------------------------------------

OPENSANDBOX_DOMAIN = "localhost:8080"

def _opensandbox_available() -> bool:
    try:
        from urllib.request import urlopen
        r = urlopen(f"http://{OPENSANDBOX_DOMAIN}/health", timeout=3)
        return "healthy" in r.read().decode()
    except Exception:
        return False


def bench_opensandbox() -> dict | None:
    import asyncio
    if not _opensandbox_available():
        return None

    async def _run():
        from opensandbox import Sandbox as OSSandbox
        from opensandbox.config import ConnectionConfig
        from datetime import timedelta

        config = ConnectionConfig(domain=OPENSANDBOX_DOMAIN,
                                  request_timeout=timedelta(seconds=60))

        async def _create():
            return await OSSandbox.create(image=IMAGE, connection_config=config,
                                          timeout=timedelta(minutes=5))

        # Create
        t0 = time.monotonic()
        sb = await _create()
        create_ms = (time.monotonic() - t0) * 1000

        # Per-command latency
        cmd_times = []
        for i in range(N_COMMANDS):
            t0 = time.monotonic()
            await sb.commands.run(f"echo iteration-{i}")
            cmd_times.append((time.monotonic() - t0) * 1000)
        avg_cmd_ms = sum(cmd_times) / len(cmd_times)

        # "Reset" = kill + create
        t0 = time.monotonic()
        await sb.kill(); await sb.close()
        sb = await _create()
        reset_ms = (time.monotonic() - t0) * 1000

        # Delete
        t0 = time.monotonic()
        await sb.kill(); await sb.close()
        delete_ms = (time.monotonic() - t0) * 1000

        return {"create_ms": create_ms, "cmd_ms": avg_cmd_ms,
                "reset_ms": reset_ms, "delete_ms": delete_ms}

    return asyncio.run(_run())


def bench_opensandbox_throughput() -> dict | None:
    import asyncio
    if not _opensandbox_available():
        return None

    async def _run():
        from opensandbox import Sandbox as OSSandbox
        from opensandbox.config import ConnectionConfig
        from datetime import timedelta

        config = ConnectionConfig(domain=OPENSANDBOX_DOMAIN,
                                  request_timeout=timedelta(seconds=60))
        sb = await OSSandbox.create(image=IMAGE, connection_config=config,
                                    timeout=timedelta(minutes=5))
        await sb.commands.run("echo warmup")
        N = 100
        t0 = time.monotonic()
        for i in range(N):
            await sb.commands.run(f"echo {i}")
        elapsed = time.monotonic() - t0
        await sb.kill(); await sb.close()
        return {"total_s": elapsed, "ops_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}

    return asyncio.run(_run())


def bench_opensandbox_reset_loop() -> dict | None:
    import asyncio
    if not _opensandbox_available():
        return None

    async def _run():
        from opensandbox import Sandbox as OSSandbox
        from opensandbox.config import ConnectionConfig
        from datetime import timedelta

        config = ConnectionConfig(domain=OPENSANDBOX_DOMAIN,
                                  request_timeout=timedelta(seconds=60))
        N = 20  # Fewer iterations — each reset is slow
        t0_total = time.monotonic()
        sb = await OSSandbox.create(image=IMAGE, connection_config=config,
                                    timeout=timedelta(minutes=5))
        for i in range(N):
            await sb.commands.run(f"echo episode-{i}")
            await sb.kill(); await sb.close()
            sb = await OSSandbox.create(image=IMAGE, connection_config=config,
                                        timeout=timedelta(minutes=5))
        await sb.kill(); await sb.close()
        elapsed = time.monotonic() - t0_total
        return {"total_s": elapsed, "cycles_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# SWE-MiniSandbox (pexpect + PS1 matching, no container)
# ---------------------------------------------------------------------------

def _swe_available() -> bool:
    try:
        from swerex.runtime.local import LocalRuntime  # noqa: F401
        from swerex.runtime.abstract import CreateBashSessionRequest, BashAction  # noqa: F401
        return True
    except (ImportError, ModuleNotFoundError):
        return False


def bench_swe() -> dict | None:
    import asyncio
    if not _swe_available():
        return None

    async def _run():
        from swerex.runtime.local import LocalRuntime
        from swerex.runtime.abstract import CreateBashSessionRequest, BashAction

        async def _create():
            rt = LocalRuntime()
            await rt.create_session(CreateBashSessionRequest(
                startup_cmd="/bin/bash --norc --noprofile", startup_timeout=10))
            return rt

        # Create
        t0 = time.monotonic()
        rt = await _create()
        create_ms = (time.monotonic() - t0) * 1000

        # Per-command latency
        cmd_times = []
        for i in range(N_COMMANDS):
            t0 = time.monotonic()
            await rt.run_in_session(BashAction(
                command=f"echo iteration-{i}", timeout=10, check="silent"))
            cmd_times.append((time.monotonic() - t0) * 1000)
        avg_cmd_ms = sum(cmd_times) / len(cmd_times)

        # "Reset" = close + recreate session
        t0 = time.monotonic()
        await rt.close()
        rt = await _create()
        reset_ms = (time.monotonic() - t0) * 1000

        # Delete
        t0 = time.monotonic()
        await rt.close()
        delete_ms = (time.monotonic() - t0) * 1000

        return {"create_ms": create_ms, "cmd_ms": avg_cmd_ms,
                "reset_ms": reset_ms, "delete_ms": delete_ms}

    return asyncio.run(_run())


def bench_swe_throughput() -> dict | None:
    import asyncio
    if not _swe_available():
        return None

    async def _run():
        from swerex.runtime.local import LocalRuntime
        from swerex.runtime.abstract import CreateBashSessionRequest, BashAction

        rt = LocalRuntime()
        await rt.create_session(CreateBashSessionRequest(
            startup_cmd="/bin/bash --norc --noprofile", startup_timeout=10))
        await rt.run_in_session(BashAction(command="echo warmup", timeout=10, check="silent"))
        N = 100
        t0 = time.monotonic()
        for i in range(N):
            await rt.run_in_session(BashAction(
                command=f"echo {i}", timeout=10, check="silent"))
        elapsed = time.monotonic() - t0
        await rt.close()
        return {"total_s": elapsed, "ops_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}

    return asyncio.run(_run())


def bench_swe_reset_loop() -> dict | None:
    import asyncio
    if not _swe_available():
        return None

    async def _run():
        from swerex.runtime.local import LocalRuntime
        from swerex.runtime.abstract import CreateBashSessionRequest, BashAction

        N = 50
        rt = LocalRuntime()
        await rt.create_session(CreateBashSessionRequest(
            startup_cmd="/bin/bash --norc --noprofile", startup_timeout=10))
        t0_total = time.monotonic()
        for i in range(N):
            await rt.run_in_session(BashAction(
                command=f"echo episode-{i}", timeout=10, check="silent"))
            await rt.close()
            rt = LocalRuntime()
            await rt.create_session(CreateBashSessionRequest(
                startup_cmd="/bin/bash --norc --noprofile", startup_timeout=10))
        await rt.close()
        elapsed = time.monotonic() - t0_total
        return {"total_s": elapsed, "cycles_per_sec": N / elapsed, "avg_ms": elapsed / N * 1000}

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# nitrobox
# ---------------------------------------------------------------------------

def bench_sandbox() -> dict:
    from nitrobox import Sandbox, SandboxConfig

    config = SandboxConfig(image=IMAGE, working_dir="/workspace")

    # Create
    t0 = time.monotonic()
    sb = Sandbox(config, name="nbx-bench-sandbox")
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

    from nitrobox import Sandbox, SandboxConfig, CheckpointManager

    config = SandboxConfig(image=IMAGE, working_dir="/workspace")
    sb = Sandbox(config, name="nbx-bench-criu")

    if not CheckpointManager.check_available():
        sb.delete()
        return None

    mgr = CheckpointManager(sb)
    sb.run("echo data > /workspace/test.txt")

    # Save latency
    save_times = []
    for i in range(N_CRIU_ITERS):
        ckpt = f"/tmp/nbx_bench_ckpt_{i}"
        shutil.rmtree(ckpt, ignore_errors=True)
        t0 = time.monotonic()
        mgr.save(ckpt)
        save_times.append((time.monotonic() - t0) * 1000)

    # Restore latency
    restore_times = []
    for i in range(N_CRIU_ITERS):
        sb.run("echo modified > /workspace/test.txt")
        t0 = time.monotonic()
        mgr.restore(f"/tmp/nbx_bench_ckpt_{i}")
        restore_times.append((time.monotonic() - t0) * 1000)

    sb.delete()
    for i in range(N_CRIU_ITERS):
        shutil.rmtree(f"/tmp/nbx_bench_ckpt_{i}", ignore_errors=True)

    return {
        "save_ms": sum(save_times) / len(save_times),
        "restore_ms": sum(restore_times) / len(restore_times),
    }


# ---------------------------------------------------------------------------
# Sustained workload benchmarks
# ---------------------------------------------------------------------------

def bench_throughput() -> dict:
    """1000 sequential commands — measures sustained throughput."""
    from nitrobox import Sandbox, SandboxConfig
    N = 1000

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="nbx-bench-tp")
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
    from nitrobox import Sandbox, SandboxConfig
    N = 100

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="nbx-bench-reset")
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

    from nitrobox import Sandbox, SandboxConfig, CheckpointManager

    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="nbx-bench-ckpt-loop")
    if not CheckpointManager.check_available():
        sb.delete()
        return None

    mgr = CheckpointManager(sb)
    N = 50
    ckpt = "/tmp/nbx_bench_ckpt_loop"

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
      NitroBoxLite:  Sandbox(config) → sb.run() (N times) → sb.delete()
    """
    from nitrobox import Sandbox, SandboxConfig

    commands = [
        "echo hello",
        "python3 --version 2>&1 || true",
        "ls /",
        "cat /etc/os-release | head -1",
        "echo done > /tmp/out.txt && cat /tmp/out.txt",
    ]

    docker_tag = "nbx_bench_docker"
    docker_container = "nbx_bench_container"

    N_ROUNDS = 5

    # ── NitroBoxLite ──
    config = SandboxConfig(image=IMAGE, working_dir="/app")
    t0 = time.monotonic()
    sb = Sandbox(config, name="bench-ab")
    nbx_start = (time.monotonic() - t0) * 1000

    # Run each command N_ROUNDS times, take median
    nbx_exec_all: dict[int, list[float]] = {i: [] for i in range(len(commands))}
    for _ in range(N_ROUNDS):
        for i, cmd in enumerate(commands):
            t = time.monotonic()
            sb.run(cmd)
            nbx_exec_all[i].append((time.monotonic() - t) * 1000)
    nbx_exec_times = [sorted(nbx_exec_all[i])[N_ROUNDS // 2] for i in range(len(commands))]

    t0 = time.monotonic()
    sb.delete()
    nbx_stop = (time.monotonic() - t0) * 1000

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

    docker_exec_all: dict[int, list[float]] = {i: [] for i in range(len(commands))}
    for _ in range(N_ROUNDS):
        for i, cmd in enumerate(commands):
            t = time.monotonic()
            subprocess.run(
                ["docker", "exec", docker_container, "bash", "-c", cmd],
                capture_output=True, text=True, timeout=30,
            )
            docker_exec_all[i].append((time.monotonic() - t) * 1000)
    docker_exec_times = [sorted(docker_exec_all[i])[N_ROUNDS // 2] for i in range(len(commands))]

    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", docker_container], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", docker_tag], capture_output=True)
    docker_stop = (time.monotonic() - t0) * 1000

    # ── Print comparison ──
    print(f"\n{'=' * 70}")
    print(f"  A/B Benchmark: NitroBoxLite vs Docker (median of {N_ROUNDS} rounds)")
    print(f"  (Docker flow: build + run -d + exec + rm, like Harbor)")
    print(f"{'=' * 70}")
    print(f"  {'Operation':30s} {'NBX':>10s} {'Docker':>10s} {'Speedup':>10s}")
    print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*10}")

    def _row(label, a, d):
        sp = d / a if a > 0 else float("inf")
        print(f"  {label:30s} {a:7.1f} ms {d:7.1f} ms {sp:8.1f}x")

    _row("Create / Start", nbx_start, docker_start)
    nbx_exec_mean = sum(nbx_exec_times) / len(nbx_exec_times)
    docker_exec_mean = sum(docker_exec_times) / len(docker_exec_times)
    _row("Exec (median avg)", nbx_exec_mean, docker_exec_mean)
    _row("Stop / Cleanup", nbx_stop, docker_stop)

    print()
    print(f"  {'Per-command breakdown':30s} {'NBX':>10s} {'Docker':>10s} {'Speedup':>10s}")
    print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*10}")
    for i, cmd in enumerate(commands):
        _row(cmd[:28], nbx_exec_times[i], docker_exec_times[i])
    print("=" * 70)


def bench_concurrent() -> dict:
    """Parallel sandboxes — measures scalability."""
    from concurrent.futures import ThreadPoolExecutor
    from nitrobox import Sandbox, SandboxConfig

    results = {}
    for n in [4, 8, 16]:
        def worker(i):
            sb = Sandbox(
                SandboxConfig(image=IMAGE, working_dir="/workspace"),
                name=f"nbx-bench-par-{i}",
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

def _docker_available() -> bool:
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def main(skip_docker: bool = False, skip_podman: bool = False,
         skip_opensandbox: bool = False, skip_swe: bool = False):
    # Auto-detect unavailable backends
    if not skip_docker and not _docker_available():
        print("Docker not available, skipping")
        skip_docker = True
    if not skip_podman and not _podman_available():
        print("Podman not available, skipping")
        skip_podman = True
    if not skip_opensandbox and not _opensandbox_available():
        print("OpenSandbox not available, skipping")
        skip_opensandbox = True
    if not skip_swe and not _swe_available():
        print("SWE-MiniSandbox not available, skipping")
        skip_swe = True

    # Cleanup stale containers
    if not skip_docker:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    if not skip_podman:
        subprocess.run(["podman", "rm", "-f", PODMAN_CONTAINER], capture_output=True)

    print(f"Benchmarking with {IMAGE}, {N_COMMANDS} commands each")
    backends = ["nbx"]
    if not skip_docker:
        backends.append("Docker")
    if not skip_podman:
        backends.append("Podman")
    if not skip_opensandbox:
        backends.append("OpenSandbox")
    if not skip_swe:
        backends.append("SWE-Mini")
    print(f"Backends: {', '.join(backends)}\n")

    # Warmup: ensure rootfs is cached (first export is slow)
    from nitrobox import Sandbox, SandboxConfig
    print("Warming up (caching rootfs)...")
    _sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/"), name="nbx-bench-warmup")
    _sb.delete()

    docker = None
    if not skip_docker:
        print("Running Docker benchmark...")
        docker = bench_docker()

    podman = None
    if not skip_podman:
        print("Running Podman benchmark...")
        podman = bench_podman()

    opensandbox = None
    if not skip_opensandbox:
        print("Running OpenSandbox benchmark...")
        opensandbox = bench_opensandbox()

    swe = None
    if not skip_swe:
        print("Running SWE-MiniSandbox benchmark...")
        swe = bench_swe()

    print("Running nitrobox benchmark...")
    sandbox = bench_sandbox()

    # Results table
    cols = []
    if docker:
        cols.append(("Docker", docker))
    if podman:
        cols.append(("Podman", podman))
    if opensandbox:
        cols.append(("OpenSandbox", opensandbox))
    if swe:
        cols.append(("SWE-Mini", swe))
    cols.append(("nbx", sandbox))

    header = f"{'':20}" + "".join(f" {name:>12}" for name, _ in cols)
    if len(cols) > 1:
        header += "  speedup"
    print(f"\n{header}")
    print("-" * len(header))
    for label, key in [
        ("Create", "create_ms"),
        ("Per command (avg)", "cmd_ms"),
        ("Reset", "reset_ms"),
        ("Delete", "delete_ms"),
    ]:
        row = f"{label:20}"
        for _, data in cols:
            row += f" {data[key]:>10.1f}ms"
        if len(cols) > 1:
            # Speedup vs slowest non-nbx backend
            others = [d[key] for name, d in cols if name != "nbx"]
            if others:
                slowest = max(others)
                sp = slowest / sandbox[key] if sandbox[key] > 0 else float("inf")
                row += f"  {sp:.1f}x"
        print(row)

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

    print("Throughput (sequential commands)...")
    docker_tp = bench_docker_throughput() if not skip_docker else None
    os_tp = bench_opensandbox_throughput() if not skip_opensandbox else None
    swe_tp = bench_swe_throughput() if not skip_swe else None
    nbx_tp = bench_throughput()
    if docker_tp:
        print(f"  Docker:      {docker_tp['ops_per_sec']:.0f} cmd/s  (avg {docker_tp['avg_ms']:.1f}ms)")
    if os_tp:
        print(f"  OpenSandbox: {os_tp['ops_per_sec']:.0f} cmd/s  (avg {os_tp['avg_ms']:.1f}ms)")
    if swe_tp:
        print(f"  SWE-Mini:    {swe_tp['ops_per_sec']:.0f} cmd/s  (avg {swe_tp['avg_ms']:.1f}ms)")
    comparisons = []
    if docker_tp:
        comparisons.append(f"{nbx_tp['ops_per_sec']/docker_tp['ops_per_sec']:.1f}x vs Docker")
    if os_tp:
        comparisons.append(f"{nbx_tp['ops_per_sec']/os_tp['ops_per_sec']:.1f}x vs OpenSandbox")
    if swe_tp:
        comparisons.append(f"{nbx_tp['ops_per_sec']/swe_tp['ops_per_sec']:.1f}x vs SWE-Mini")
    print(f"  nbx:         {nbx_tp['ops_per_sec']:.0f} cmd/s  (avg {nbx_tp['avg_ms']:.1f}ms)"
          + (f"  {', '.join(comparisons)}" if comparisons else ""))

    print("\nReset loop...")
    print("  Note: Docker/Podman/OpenSandbox 'reset' = rm + run; SWE-Mini = close + reopen session")
    docker_rl = bench_docker_reset_loop() if not skip_docker else None
    os_rl = bench_opensandbox_reset_loop() if not skip_opensandbox else None
    swe_rl = bench_swe_reset_loop() if not skip_swe else None
    nbx_rl = bench_reset_loop()
    if docker_rl:
        print(f"  Docker:      {docker_rl['cycles_per_sec']:.1f} resets/s  (avg {docker_rl['avg_ms']:.0f}ms)")
    if os_rl:
        print(f"  OpenSandbox: {os_rl['cycles_per_sec']:.1f} resets/s  (avg {os_rl['avg_ms']:.0f}ms)")
    if swe_rl:
        print(f"  SWE-Mini:    {swe_rl['cycles_per_sec']:.1f} resets/s  (avg {swe_rl['avg_ms']:.0f}ms)")
    comparisons = []
    if docker_rl:
        comparisons.append(f"{nbx_rl['cycles_per_sec']/docker_rl['cycles_per_sec']:.1f}x vs Docker")
    if os_rl:
        comparisons.append(f"{nbx_rl['cycles_per_sec']/os_rl['cycles_per_sec']:.1f}x vs OpenSandbox")
    if swe_rl:
        comparisons.append(f"{nbx_rl['cycles_per_sec']/swe_rl['cycles_per_sec']:.1f}x vs SWE-Mini")
    print(f"  nbx:         {nbx_rl['cycles_per_sec']:.1f} resets/s  (avg {nbx_rl['avg_ms']:.0f}ms)"
          + (f"  {', '.join(comparisons)}" if comparisons else ""))

    print("\nCheckpoint loop (50 run+restore cycles)...")
    cl = bench_checkpoint_loop()
    if cl:
        print(f"  nbx:    {cl['cycles_per_sec']:.1f} restores/s  (avg {cl['avg_ms']:.0f}ms)")
        print("  (Docker/Podman checkpoint requires experimental daemon — not benchmarked)")
    else:
        print("  Skipped (requires root + CRIU)")

    if not skip_docker:
        print("\n--- A/B comparison (Harbor-style flow) ---\n")
        bench_ab_comparison()

    print("\nConcurrent sandboxes (4/8/16 parallel, 10 cmds each)...")
    docker_conc = bench_docker_concurrent() if not skip_docker else None
    nbx_conc = bench_concurrent()
    for n in [4, 8, 16]:
        a = nbx_conc[n]
        parts = []
        if docker_conc:
            parts.append(f"Docker {docker_conc[n]['cmds_per_sec']:.0f}")
        parts.append(f"nbx {a['cmds_per_sec']:.0f} cmd/s")
        comparisons = []
        if docker_conc:
            comparisons.append(f"{a['cmds_per_sec']/docker_conc[n]['cmds_per_sec']:.1f}x vs Docker")
        line = f"  {n:2d}x: {' | '.join(parts)}"
        if comparisons:
            line += f"  {', '.join(comparisons)}"
        print(line)


def bench_port_map():
    """Compare sandbox creation with and without port_map."""
    import os
    from nitrobox import Sandbox, SandboxConfig

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
    import argparse
    parser = argparse.ArgumentParser(description="Benchmark nitrobox vs Docker/Podman/OpenSandbox/SWE-MiniSandbox")
    parser.add_argument("--no-docker", action="store_true", help="Skip Docker benchmarks")
    parser.add_argument("--no-podman", action="store_true", help="Skip Podman benchmarks")
    parser.add_argument("--no-opensandbox", action="store_true", help="Skip OpenSandbox benchmarks")
    parser.add_argument("--no-swe", action="store_true", help="Skip SWE-MiniSandbox benchmarks")
    parser.add_argument("--no-port-map", action="store_true", help="Skip port mapping benchmark")
    args = parser.parse_args()

    main(skip_docker=args.no_docker, skip_podman=args.no_podman,
         skip_opensandbox=args.no_opensandbox, skip_swe=args.no_swe)
    if not args.no_port_map:
        print("\n--- Port mapping overhead ---\n")
        bench_port_map()
