#!/usr/bin/env python3
"""Benchmark: Harbor e2e — Docker vs nitrobox at different concurrency levels.

Runs the same set of tasks with both Docker and nitrobox environments,
comparing wall-clock time, per-phase overhead, and result correctness.

The benchmark includes a warmup phase to populate both Docker layer cache
and nitrobox rootfs digest cache, so comparisons measure pure runtime
overhead rather than one-time build costs.

Setup:
    # 1. Clone harbor (with nitrobox support)
    git clone https://github.com/yuzhounie/harbor.git
    cd harbor && git checkout feat/nitrobox-environment
    uv sync --all-extras --dev

    # 2. Install nitrobox
    pip install nitrobox

    # 3. Install uidmap (required for nitrobox rootless multi-UID mapping)
    sudo apt-get install -y uidmap

    # 4. Verify Docker is running
    docker info

Usage:
    # Oracle agent (no API key needed, measures pure environment overhead)
    python examples/bench_harbor_e2e.py \\
        --harbor-dir /path/to/harbor \\
        --dataset terminal-bench@2.0 \\
        --agent oracle \\
        --n-tasks 5 --concurrency 1,4

    # Claude agent (real LLM, measures end-to-end including inference)
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \\
        --harbor-dir /path/to/harbor \\
        --dataset terminal-bench@2.0 \\
        --agent claude-code --model anthropic/claude-sonnet-4-6 \\
        --n-tasks 5 --concurrency 1,4

    # Custom agent with vLLM endpoint
    MODEL_NAME=my-model MODEL_ENDPOINT=http://localhost:8002/v1 \\
    python examples/bench_harbor_e2e.py \\
        --harbor-dir /path/to/harbor \\
        --dataset swebench-verified \\
        --agent-import-path my_agent:MyAgent \\
        --n-tasks 20 --concurrency 1,4,8,16,32

    # Full sweep (save results to JSON)
    python examples/bench_harbor_e2e.py \\
        --harbor-dir /path/to/harbor \\
        --dataset terminal-bench@2.0 \\
        --agent oracle \\
        --n-tasks 20 --concurrency 1,4,8,16,32 \\
        --output results.json

Environment variables:
    MODEL_NAME         Model name for custom agents
    MODEL_ENDPOINT     Model API endpoint URL
    ANTHROPIC_API_KEY  API key for Claude agents
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
    n_tasks: int,
    n_concurrent: int,
    job_name: str,
) -> dict:
    """Run harbor and return timing results."""
    cmd = [
        "uv", "run", "harbor", "run",
        "-d", dataset,
        "-e", env_type,
        "--n-concurrent", str(n_concurrent),
        "--n-attempts", "1",
        "-l", str(n_tasks),
        "--job-name", job_name,
    ]
    if agent:
        cmd.extend(["-a", agent])
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
        "phases": {
            "environment_setup": [],
            "agent_execution": [],
            "verifier": [],
        },
        "errors": 0,
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


def _format_results_table(
    all_results: dict[str, dict],
    concurrency_levels: list[int],
    env_types: list[str],
) -> str:
    """Format results as a markdown table with overhead percentages."""
    lines = []
    lines.append(
        f"| {'C':>3} | {'Env':>8} | {'Wall':>7} | "
        f"{'Setup':>7} | {'Agent':>7} | {'Verify':>7} | "
        f"{'Overhead':>8} | {'Pass':>4} | {'Fail':>4} |"
    )
    lines.append(
        f"|{'-'*5}|{'-'*10}|{'-'*9}|"
        f"{'-'*9}|{'-'*9}|{'-'*9}|"
        f"{'-'*10}|{'-'*6}|{'-'*6}|"
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

            lines.append(
                f"| {c:>3} | {env_type:>8} | {wall:>6.1f}s | "
                f"{setup:>6.1f}s | {agent:>6.1f}s | {verify:>6.1f}s | "
                f"{overhead_pct:>7.1f}% | {pass_n:>4} | {fail_n:>4} |"
            )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Harbor e2e benchmark: Docker vs nitrobox",
    )
    parser.add_argument("--harbor-dir", required=True)
    parser.add_argument("--dataset", default="terminal-bench@2.0")
    parser.add_argument("--agent", default=None)
    parser.add_argument("--agent-import-path", default=None)
    parser.add_argument("--model", "-m", default=None)
    parser.add_argument("--n-tasks", type=int, default=10)
    parser.add_argument("--concurrency", default="1,4")
    parser.add_argument("--envs", default="docker,nitrobox")
    parser.add_argument("--output", default=None)
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
    print(f"  Tasks:       {args.n_tasks}")
    print(f"  Concurrency: {concurrency_levels}")
    print(f"  Envs:        {env_types}")

    # ── Warmup: run 1 task with each env to populate caches ──────────
    print(f"\nWarmup (populating Docker layer cache + nitrobox rootfs cache)...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for env_type in env_types:
        warmup_name = f"_warmup_{env_type}_{timestamp}"
        run_harbor(
            harbor_dir=args.harbor_dir,
            dataset=args.dataset,
            agent=args.agent,
            agent_import_path=args.agent_import_path,
            model=args.model,
            env_type=env_type,
            n_tasks=1,
            n_concurrent=1,
            job_name=warmup_name,
        )
        print(f"  {env_type}: warmed up")

    # ── Benchmark runs ───────────────────────────────────────────────
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
            )
            all_results[key] = r
            print(
                f"  Done: {r['wall_time_s']:.1f}s wall, "
                f"{r['trials']} trials, "
                f"{r['rewards'].get('1.0', 0)} pass"
            )

    # ── Results ──────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("RESULTS (warmed caches — measures pure runtime overhead)")
    print("=" * 78 + "\n")
    print(_format_results_table(all_results, concurrency_levels, env_types))

    # Speedup summary
    print("\nSpeedup (wall-clock):")
    for c in concurrency_levels:
        dk = f"docker_c{c}"
        nk = f"nitrobox_c{c}"
        if dk in all_results and nk in all_results:
            d = all_results[dk]["wall_time_s"]
            n = all_results[nk]["wall_time_s"]
            sp = d / n if n > 0 else float("inf")
            print(f"  c={c}: Docker {d:.1f}s vs nitrobox {n:.1f}s — {sp:.2f}x")

    # Overhead comparison
    print("\nSetup overhead (% of total per-task time):")
    for c in concurrency_levels:
        for env_type in env_types:
            key = f"{env_type}_c{c}"
            r = all_results.get(key)
            if not r or r["trials"] == 0:
                continue
            setup = _mean(r["phases"]["environment_setup"])
            agent = _mean(r["phases"]["agent_execution"])
            verify = _mean(r["phases"]["verifier"])
            total = setup + agent + verify
            pct = setup / total * 100 if total > 0 else 0
            print(f"  {env_type} c={c}: {setup:.1f}s / {total:.1f}s = {pct:.1f}%")

    # Correctness
    print("\nCorrectness (rewards match):")
    for c in concurrency_levels:
        dk = f"docker_c{c}"
        nk = f"nitrobox_c{c}"
        if dk in all_results and nk in all_results:
            d_pass = all_results[dk]["rewards"].get("1.0", 0)
            n_pass = all_results[nk]["rewards"].get("1.0", 0)
            match = "✓ MATCH" if d_pass == n_pass else "✗ MISMATCH"
            print(f"  c={c}: Docker {d_pass} pass, nitrobox {n_pass} pass — {match}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
