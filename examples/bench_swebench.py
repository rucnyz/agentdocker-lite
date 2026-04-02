#!/usr/bin/env python3
"""Benchmark: SWE-bench-style evaluation loop — Docker vs nitrobox.

Simulates the SWE-bench harness flow:
  create container → apply patch → run tests → reset/destroy → repeat

Usage:
    python examples/bench_swebench.py
    python examples/bench_swebench.py --episodes 50
    python examples/bench_swebench.py --no-docker   # skip Docker (nitrobox only)
"""

import subprocess
import time

IMAGE = "ubuntu:22.04"
CONTAINER_NAME = "nbx-bench-swebench"
N_CMDS_PER_EPISODE = 5  # simulate: apply patch, run tests, collect results


def _docker_available() -> bool:
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


# ---------------------------------------------------------------------------
# Docker — SWE-bench style (create → exec → stop+remove → repeat)
# ---------------------------------------------------------------------------

def bench_docker_swebench(n_episodes: int) -> dict:
    subprocess.run(["docker", "pull", "-q", IMAGE], capture_output=True)

    create_times = []
    exec_times = []
    reset_times = []  # stop + remove + run = "reset"

    for ep in range(n_episodes):
        # Create
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
        t0 = time.monotonic()
        subprocess.run(
            ["docker", "run", "-d", "--name", CONTAINER_NAME, IMAGE, "sleep", "infinity"],
            capture_output=True, check=True,
        )
        create_times.append((time.monotonic() - t0) * 1000)

        # Exec (simulate patch + eval)
        for i in range(N_CMDS_PER_EPISODE):
            t0 = time.monotonic()
            subprocess.run(
                ["docker", "exec", CONTAINER_NAME, "bash", "-c", f"echo step-{i}"],
                capture_output=True,
            )
            exec_times.append((time.monotonic() - t0) * 1000)

        # "Reset" = stop + remove (SWE-bench destroys container each episode)
        t0 = time.monotonic()
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
        reset_times.append((time.monotonic() - t0) * 1000)

    return {
        "create_ms": sum(create_times) / len(create_times),
        "exec_ms": sum(exec_times) / len(exec_times),
        "reset_ms": sum(reset_times) / len(reset_times),
        "total_s": sum(create_times + exec_times + reset_times) / 1000,
        "episodes": n_episodes,
    }


# ---------------------------------------------------------------------------
# nitrobox — same flow but with instant reset
# ---------------------------------------------------------------------------

def bench_nbx_swebench(n_episodes: int) -> dict:
    from nitrobox import Sandbox, SandboxConfig

    config = SandboxConfig(image=IMAGE, working_dir="/testbed")

    create_times = []
    exec_times = []
    reset_times = []

    # First create
    t0 = time.monotonic()
    sb = Sandbox(config, name="nbx-bench-swebench")
    create_times.append((time.monotonic() - t0) * 1000)

    for ep in range(n_episodes):
        # Exec (simulate patch + eval)
        for i in range(N_CMDS_PER_EPISODE):
            t0 = time.monotonic()
            sb.run(f"echo step-{i}")
            exec_times.append((time.monotonic() - t0) * 1000)

        # Reset — O(1) overlayfs rename, no recreate
        t0 = time.monotonic()
        sb.reset()
        reset_times.append((time.monotonic() - t0) * 1000)

    sb.delete()

    return {
        "create_ms": sum(create_times) / len(create_times),
        "exec_ms": sum(exec_times) / len(exec_times),
        "reset_ms": sum(reset_times) / len(reset_times),
        "total_s": sum(create_times + exec_times + reset_times) / 1000,
        "episodes": n_episodes,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(n_episodes: int = 20, skip_docker: bool = False):
    if not skip_docker and not _docker_available():
        print("Docker not available, skipping Docker benchmark")
        skip_docker = True

    print(f"SWE-bench-style benchmark: {n_episodes} episodes × {N_CMDS_PER_EPISODE} cmds/episode\n")

    # Warmup nitrobox (cache rootfs)
    from nitrobox import Sandbox, SandboxConfig
    print("Warming up (caching rootfs)...")
    _sb = Sandbox(SandboxConfig(image=IMAGE), name="nbx-bench-warmup")
    _sb.delete()

    docker = None
    if not skip_docker:
        print("Running Docker benchmark...")
        docker = bench_docker_swebench(n_episodes)

    print("Running nitrobox benchmark...")
    nbx = bench_nbx_swebench(n_episodes)

    # Print results
    def _row(label, nbx_v, docker_v=None):
        if docker_v is not None:
            sp = docker_v / nbx_v if nbx_v > 0 else float("inf")
            print(f"  {label:25s} {docker_v:8.1f} ms   {nbx_v:8.1f} ms   {sp:6.1f}x")
        else:
            print(f"  {label:25s} {'—':>8s}      {nbx_v:8.1f} ms")

    print(f"\n{'':25s} {'Docker':>8s}      {'nbx':>8s}      {'Speedup':>7s}")
    print(f"  {'-'*25} {'-'*8}      {'-'*8}      {'-'*7}")
    _row("Create", nbx["create_ms"], docker["create_ms"] if docker else None)
    _row("Exec (per cmd)", nbx["exec_ms"], docker["exec_ms"] if docker else None)
    _row("Reset", nbx["reset_ms"], docker["reset_ms"] if docker else None)

    total_nbx = nbx["total_s"]
    print(f"\n  Total wall time:         ", end="")
    if docker:
        total_docker = docker["total_s"]
        print(f"{total_docker:.1f}s (Docker)  vs  {total_nbx:.1f}s (nbx)  — {total_docker/total_nbx:.1f}x faster")
    else:
        print(f"{total_nbx:.1f}s (nbx)")

    if docker:
        # Extrapolate to full SWE-bench (2294 instances)
        scale = 2294 / n_episodes
        docker_full = docker["total_s"] * scale
        nbx_full = nbx["total_s"] * scale
        saved = docker_full - nbx_full
        print(f"\n  Extrapolated to full SWE-bench (2,294 instances):")
        print(f"    Docker:  {docker_full/60:.0f} min")
        print(f"    nbx:     {nbx_full/60:.0f} min")
        print(f"    Saved:   {saved/60:.0f} min")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", type=int, default=20)
    parser.add_argument("--no-docker", action="store_true")
    args = parser.parse_args()
    main(n_episodes=args.episodes, skip_docker=args.no_docker)
