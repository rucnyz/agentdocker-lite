#!/usr/bin/env python3
"""Benchmark nitrobox vs docker compose setup (build + up) in isolation.

Simulates what harbor does during env_setup for swebench-verified tasks:
  1. Merge compose templates (base + build)
  2. Init (image resolution + build)
  3. Up (create container/sandbox)

Usage:
    python bench_setup_only.py                          # 16 tasks, concurrency 16, both
    python bench_setup_only.py -n 4 -c 4                # 4 tasks, concurrency 4
    python bench_setup_only.py --envs nitrobox           # nitrobox only
    python bench_setup_only.py --envs docker             # docker only
    python bench_setup_only.py --envs nitrobox,docker    # both (default)
"""

import argparse
import os
import shutil
import string
import random
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ---------------------------------------------------------------------------
# Locate cached swebench task Dockerfiles
# ---------------------------------------------------------------------------

HARBOR_TASK_CACHE = Path.home() / ".cache/harbor/tasks"

def find_task_dockerfiles(n: int) -> list[tuple[str, Path]]:
    """Return up to n (task_name, dockerfile_dir) pairs from harbor cache."""
    results = []
    if not HARBOR_TASK_CACHE.exists():
        raise FileNotFoundError(
            f"No harbor task cache at {HARBOR_TASK_CACHE}. "
            "Run a harbor benchmark first to populate it."
        )
    for hash_dir in HARBOR_TASK_CACHE.iterdir():
        if not hash_dir.is_dir():
            continue
        for task_dir in hash_dir.iterdir():
            env_dir = task_dir / "environment"
            if (env_dir / "Dockerfile").exists():
                results.append((task_dir.name, env_dir))
            if len(results) >= n:
                return results
    if not results:
        raise FileNotFoundError("No Dockerfiles found in harbor task cache")
    while len(results) < n:
        results.extend(results[:n - len(results)])
    return results[:n]


# ---------------------------------------------------------------------------
# Compose file templates
# ---------------------------------------------------------------------------

COMPOSE_BASE = """\
services:
  main:
    volumes:
      - {verifier_dir}:/logs/verifier
      - {agent_dir}:/logs/agent
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 4G
"""

COMPOSE_BUILD = """\
services:
  main:
    build:
      context: {context_dir}
    pull_policy: build
    command: ["sh", "-c", "sleep infinity"]
    stop_grace_period: 1s
"""


def random_session_id(task_name: str) -> str:
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=7))
    # docker compose requires lowercase alphanumeric + hyphens only
    name = f"{task_name}-{suffix}".lower().replace("__", "-").replace("_", "-")
    return name


def _prepare_trial_dir(task_name: str, dockerfile_dir: Path, work_dir: Path):
    """Create trial dir with compose files, return (session_id, trial_dir, compose_file)."""
    session_id = random_session_id(task_name)
    trial_dir = work_dir / session_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    verifier_dir = trial_dir / "verifier"
    agent_dir = trial_dir / "agent"
    verifier_dir.mkdir(exist_ok=True)
    agent_dir.mkdir(exist_ok=True)

    # Single merged compose file for docker compose
    compose_file = trial_dir / "docker-compose.yaml"
    compose_file.write_text(
        f"services:\n"
        f"  main:\n"
        f"    build:\n"
        f"      context: {dockerfile_dir.resolve()}\n"
        f"    command: ['sh', '-c', 'sleep infinity']\n"
        f"    stop_grace_period: 1s\n"
        f"    volumes:\n"
        f"      - {verifier_dir}:/logs/verifier\n"
        f"      - {agent_dir}:/logs/agent\n"
        f"    deploy:\n"
        f"      resources:\n"
        f"        limits:\n"
        f"          cpus: '1'\n"
        f"          memory: 4G\n"
    )

    # Also write separate files for nitrobox
    base_yml = trial_dir / "docker-compose-base.yaml"
    build_yml = trial_dir / "docker-compose-build.yaml"
    base_yml.write_text(COMPOSE_BASE.format(
        verifier_dir=verifier_dir, agent_dir=agent_dir,
    ))
    build_yml.write_text(COMPOSE_BUILD.format(
        context_dir=dockerfile_dir.resolve(),
    ))

    return session_id, trial_dir, compose_file, base_yml, build_yml


# ---------------------------------------------------------------------------
# Nitrobox trial
# ---------------------------------------------------------------------------

def run_nitrobox_trial(task_name: str, dockerfile_dir: Path, work_dir: Path) -> dict:
    from nitrobox import ComposeProject

    session_id, trial_dir, _, base_yml, build_yml = _prepare_trial_dir(
        task_name, dockerfile_dir, work_dir
    )
    result = {"task": task_name, "session": session_id, "env": "nitrobox"}

    t0 = time.monotonic()
    try:
        proj = ComposeProject(
            [base_yml, build_yml],
            project_name=session_id,
        )
    except Exception as e:
        result["init_s"] = time.monotonic() - t0
        result["error"] = f"init: {e}"
        return result
    result["init_s"] = time.monotonic() - t0

    t1 = time.monotonic()
    try:
        proj.up()
    except Exception as e:
        result["up_s"] = time.monotonic() - t1
        result["error"] = f"up: {e}"
        try:
            proj.down(rmi=None, volumes=False)
        except Exception:
            pass
        return result
    result["up_s"] = time.monotonic() - t1

    t2 = time.monotonic()
    try:
        proj.down(rmi=None, volumes=False)
    except Exception:
        pass
    result["down_s"] = time.monotonic() - t2

    result["total_s"] = result["init_s"] + result["up_s"] + result["down_s"]
    return result


# ---------------------------------------------------------------------------
# Docker compose trial
# ---------------------------------------------------------------------------

def run_docker_trial(task_name: str, dockerfile_dir: Path, work_dir: Path) -> dict:
    session_id, trial_dir, compose_file, _, _ = _prepare_trial_dir(
        task_name, dockerfile_dir, work_dir
    )
    result = {"task": task_name, "session": session_id, "env": "docker"}

    # Phase 1: build
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(compose_file),
             "-p", session_id, "build"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            result["init_s"] = time.monotonic() - t0
            result["error"] = f"build: {r.stderr[:300]}"
            return result
    except Exception as e:
        result["init_s"] = time.monotonic() - t0
        result["error"] = f"build: {e}"
        return result
    result["init_s"] = time.monotonic() - t0

    # Phase 2: up
    t1 = time.monotonic()
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(compose_file),
             "-p", session_id, "up", "-d", "--wait"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            result["up_s"] = time.monotonic() - t1
            result["error"] = f"up: {r.stderr[:300]}"
            # cleanup
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file),
                 "-p", session_id, "down"],
                capture_output=True, timeout=60,
            )
            return result
    except Exception as e:
        result["up_s"] = time.monotonic() - t1
        result["error"] = f"up: {e}"
        return result
    result["up_s"] = time.monotonic() - t1

    # Phase 3: down (keep images)
    t2 = time.monotonic()
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file),
             "-p", session_id, "down"],
            capture_output=True, timeout=60,
        )
    except Exception:
        pass
    result["down_s"] = time.monotonic() - t2

    result["total_s"] = result["init_s"] + result["up_s"] + result["down_s"]
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_env(env_name: str, tasks, concurrency: int, work_dir: Path) -> list[dict]:
    runner = run_nitrobox_trial if env_name == "nitrobox" else run_docker_trial
    sub_dir = work_dir / env_name
    sub_dir.mkdir(exist_ok=True)

    print(f"\nRunning: {env_name} @ concurrency={concurrency} ...")
    wall_start = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(runner, name, df_dir, sub_dir): name
            for name, df_dir in tasks
        }
        for fut in as_completed(futures):
            r = fut.result()
            err = r.get("error", "")
            status = f"ERROR: {err[:80]}" if err else "ok"
            init = r.get("init_s", 0)
            up = r.get("up_s", 0)
            down = r.get("down_s", 0)
            total = r.get("total_s", init + up + down)
            print(
                f"  {r['task']:50s}  "
                f"init={init:6.1f}s  up={up:5.1f}s  down={down:5.1f}s  "
                f"total={total:6.1f}s  {status}"
            )
            results.append(r)

    wall_time = time.monotonic() - wall_start
    return results, wall_time


def print_summary(env_name: str, results: list[dict], wall_time: float):
    ok = [r for r in results if "error" not in r]
    errs = [r for r in results if "error" in r]

    if ok:
        inits = [r["init_s"] for r in ok]
        ups = [r["up_s"] for r in ok]
        downs = [r["down_s"] for r in ok]
        totals = [r["total_s"] for r in ok]
        print(f"  {env_name:10s}  wall={wall_time:6.1f}s  "
              f"init={sum(inits)/len(inits):5.1f}s  "
              f"up={sum(ups)/len(ups):5.1f}s  "
              f"down={sum(downs)/len(downs):5.1f}s  "
              f"total={sum(totals)/len(totals):5.1f}s  "
              f"ok={len(ok)} err={len(errs)}")
    else:
        print(f"  {env_name:10s}  wall={wall_time:6.1f}s  "
              f"ALL FAILED ({len(errs)} errors)")

    if errs:
        for r in errs:
            print(f"    ERR {r['task']}: {r['error'][:100]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Benchmark setup: nitrobox vs docker")
    parser.add_argument("-n", "--n-tasks", type=int, default=16)
    parser.add_argument("-c", "--concurrency", type=int, default=16)
    parser.add_argument("--envs", type=str, default="nitrobox,docker",
                        help="Comma-separated: nitrobox,docker")
    args = parser.parse_args()

    envs = [e.strip() for e in args.envs.split(",")]
    tasks = find_task_dockerfiles(args.n_tasks)
    print(f"Tasks: {len(tasks)}, Concurrency: {args.concurrency}, Envs: {envs}")
    print(f"Tasks: {[t[0] for t in tasks]}")

    work_dir = Path(tempfile.mkdtemp(prefix="nbx_bench_setup_"))

    all_results = {}
    for env_name in envs:
        results, wall_time = run_env(env_name, tasks, args.concurrency, work_dir)
        all_results[env_name] = (results, wall_time)

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    for env_name in envs:
        results, wall_time = all_results[env_name]
        print_summary(env_name, results, wall_time)

    shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
