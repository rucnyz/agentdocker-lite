#!/usr/bin/env python3
"""Benchmark: Harbor e2e — Docker vs nitrobox.

Runs the same tasks with both environments using harbor's default
settings, then compares wall-clock time, overhead, and correctness.

No special cache warming or force-build — both environments start
from the same state and let harbor handle image pulling/building.

Setup:
    cd harbor && uv sync --all-extras --dev
    pip install nitrobox
    docker login   # avoid Docker Hub rate limits

Usage:
    # Full TB2 comparison
    python examples/bench_harbor_e2e.py \
        --harbor-dir /path/to/harbor \
        --dataset terminal-bench@2.0 \
        --agent oracle \
        --concurrency 4

    # Concurrency sweep
    python examples/bench_harbor_e2e.py \
        --harbor-dir /path/to/harbor \
        --dataset terminal-bench@2.0 \
        --agent oracle \
        --concurrency 1,4,8

    # Specific tasks only
    python examples/bench_harbor_e2e.py \
        --harbor-dir /path/to/harbor \
        --dataset terminal-bench@2.0 \
        --agent oracle \
        -i vulnerable-secret -i portfolio-optimization

    # Claude agent
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \
        --harbor-dir /path/to/harbor \
        --dataset terminal-bench@2.0 \
        --agent claude-code --model anthropic/claude-sonnet-4-6 \
        --concurrency 1,4
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path


def run_harbor(
    harbor_dir: str,
    dataset: str,
    agent: str | None,
    agent_import_path: str | None,
    model: str | None,
    env_type: str,
    n_tasks: int | None,
    n_concurrent: int,
    job_name: str,
    include_tasks: list[str] | None = None,
    exclude_tasks: list[str] | None = None,
) -> dict:
    """Run harbor with default settings and return timing results."""
    cmd = [
        "uv", "run", "harbor", "run",
        "-d", dataset,
        "-e", env_type,
        "--n-concurrent", str(n_concurrent),
        "--n-attempts", "1",
        "--job-name", job_name,
        "-y",
    ]
    if n_tasks is not None:
        cmd.extend(["-l", str(n_tasks)])
    if agent:
        cmd.extend(["-a", agent])
    if include_tasks:
        for t in include_tasks:
            cmd.extend(["-i", t])
    if exclude_tasks:
        for t in exclude_tasks:
            cmd.extend(["-x", t])
    if agent_import_path:
        cmd.extend(["--agent-import-path", agent_import_path])
    if model:
        cmd.extend(["-m", model])

    start = time.monotonic()
    result = subprocess.run(
        cmd, cwd=harbor_dir, env={**os.environ},
        capture_output=True, text=True,
    )
    wall_time = time.monotonic() - start

    if result.returncode != 0:
        print(f"  [WARN] harbor exited with code {result.returncode}")
        print(f"  stderr: {result.stderr[-500:]}")

    job_dir = Path(harbor_dir) / "jobs" / job_name
    return _parse_job_results(job_dir, wall_time)


def _parse_job_results(job_dir: Path, wall_time: float) -> dict:
    """Parse trial results from a harbor job directory."""
    results = {
        "wall_time_s": wall_time,
        "trials": 0,
        "rewards": {"1.0": 0, "0.0": 0},
        "errors": 0,
        "phases": {
            "environment_setup": [],
            "agent_execution": [],
            "verifier": [],
        },
    }

    if not job_dir.exists():
        return results

    for trial_dir in job_dir.iterdir():
        if not trial_dir.is_dir():
            continue
        result_file = trial_dir / "result.json"
        if not result_file.exists():
            continue

        with open(result_file) as f:
            data = json.load(f)

        results["trials"] += 1

        vr = data.get("verifier_result")
        if vr:
            reward = vr.get("rewards", {}).get("reward")
            if reward is not None:
                key = str(float(reward))
                results["rewards"][key] = results["rewards"].get(key, 0) + 1

        if data.get("exception_info"):
            results["errors"] += 1

        for phase in ["environment_setup", "agent_execution", "verifier"]:
            timing = data.get(phase)
            if timing and timing.get("started_at") and timing.get("finished_at"):
                start = datetime.fromisoformat(timing["started_at"].rstrip("Z"))
                end = datetime.fromisoformat(timing["finished_at"].rstrip("Z"))
                results["phases"][phase].append((end - start).total_seconds())

    return results


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _print_results(
    all_results: dict[str, dict],
    concurrency_levels: list[int],
    env_types: list[str],
) -> None:
    """Print formatted results table and comparisons."""
    # Table
    print(
        f"| {'C':>3} | {'Env':>8} | {'Wall':>7} | "
        f"{'Setup':>7} | {'Agent':>7} | {'Verify':>7} | "
        f"{'Overhead':>8} | {'Pass':>4} | {'Fail':>4} | {'Err':>4} |"
    )
    print(
        f"|{'-'*5}|{'-'*10}|{'-'*9}|"
        f"{'-'*9}|{'-'*9}|{'-'*9}|"
        f"{'-'*10}|{'-'*6}|{'-'*6}|{'-'*6}|"
    )

    for c in concurrency_levels:
        for env_type in env_types:
            key = f"{env_type}_c{c}"
            r = all_results.get(key)
            if not r or r["trials"] == 0:
                continue

            wall = r["wall_time_s"]
            setup = _mean(r["phases"]["environment_setup"])
            agent = _mean(r["phases"]["agent_execution"])
            verify = _mean(r["phases"]["verifier"])
            total_task = setup + agent + verify
            overhead_pct = (setup / total_task * 100) if total_task > 0 else 0
            pass_n = r["rewards"].get("1.0", 0)
            fail_n = r["rewards"].get("0.0", 0)
            err_n = r["errors"]

            print(
                f"| {c:>3} | {env_type:>8} | {wall:>6.1f}s | "
                f"{setup:>6.1f}s | {agent:>6.1f}s | {verify:>6.1f}s | "
                f"{overhead_pct:>7.1f}% | {pass_n:>4} | {fail_n:>4} | {err_n:>4} |"
            )

    # Speedup
    print("\nSpeedup (wall-clock):")
    for c in concurrency_levels:
        dk = f"docker_c{c}"
        nk = f"nitrobox_c{c}"
        if dk in all_results and nk in all_results:
            d = all_results[dk]["wall_time_s"]
            n = all_results[nk]["wall_time_s"]
            sp = d / n if n > 0 else float("inf")
            print(f"  c={c}: Docker {d:.1f}s vs nitrobox {n:.1f}s = {sp:.2f}x")

    # Correctness
    print("\nCorrectness:")
    for c in concurrency_levels:
        dk = f"docker_c{c}"
        nk = f"nitrobox_c{c}"
        if dk in all_results and nk in all_results:
            d_pass = all_results[dk]["rewards"].get("1.0", 0)
            n_pass = all_results[nk]["rewards"].get("1.0", 0)
            d_err = all_results[dk]["errors"]
            n_err = all_results[nk]["errors"]
            match = "MATCH" if d_pass == n_pass else "MISMATCH"
            print(
                f"  c={c}: Docker {d_pass} pass ({d_err} err), "
                f"nitrobox {n_pass} pass ({n_err} err) — {match}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Harbor e2e benchmark: Docker vs nitrobox",
    )
    parser.add_argument("--harbor-dir", required=True)
    parser.add_argument("--dataset", default="terminal-bench@2.0")
    parser.add_argument("--agent", default=None)
    parser.add_argument("--agent-import-path", default=None)
    parser.add_argument("--model", "-m", default=None)
    parser.add_argument("--n-tasks", type=int, default=None,
                        help="Max tasks (default: all)")
    parser.add_argument("--concurrency", default="4")
    parser.add_argument("--envs", default="docker,nitrobox")
    parser.add_argument("--output", default=None)
    parser.add_argument("-i", "--include-task", action="append", default=None)
    parser.add_argument("-x", "--exclude-task", action="append", default=None)
    args = parser.parse_args()

    concurrency_levels = [int(c) for c in args.concurrency.split(",")]
    env_types = [e.strip() for e in args.envs.split(",")]

    if not args.agent and not args.agent_import_path:
        args.agent = "oracle"

    print(f"Harbor e2e benchmark")
    print(f"  Dataset:     {args.dataset}")
    print(f"  Agent:       {args.agent or args.agent_import_path}")
    if args.model:
        print(f"  Model:       {args.model}")
    print(f"  Tasks:       {args.n_tasks or 'all'}")
    print(f"  Concurrency: {concurrency_levels}")
    print(f"  Envs:        {env_types}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    all_results = {}
    for c in concurrency_levels:
        for env_type in env_types:
            job_name = f"bench_{env_type}_c{c}_{timestamp}"
            key = f"{env_type}_c{c}"

            print(f"\nRunning: {env_type} @ concurrency={c} ...")
            r = run_harbor(
                harbor_dir=args.harbor_dir,
                dataset=args.dataset,
                agent=args.agent,
                agent_import_path=args.agent_import_path,
                model=args.model,
                env_type=env_type,
                n_tasks=args.n_tasks,
                n_concurrent=c,
                job_name=job_name,
                include_tasks=args.include_task,
                exclude_tasks=args.exclude_task,
            )
            all_results[key] = r
            print(
                f"  Done: {r['wall_time_s']:.1f}s wall, "
                f"{r['trials']} trials, "
                f"{r['rewards'].get('1.0', 0)} pass, "
                f"{r['errors']} errors"
            )

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80 + "\n")
    _print_results(all_results, concurrency_levels, env_types)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
