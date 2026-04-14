#!/usr/bin/env python3
"""Benchmark: OSWorld e2e — Docker vs nitrobox (QemuVM) for GUI agent tasks.

Runs the same set of OSWorld tasks with both Docker and nitrobox providers,
comparing wall-clock time, per-task overhead, and result correctness.

nitrobox uses QEMU loadvm for instant VM reset (~2.5s) instead of
Docker's container destroy+recreate+reboot cycle (~17s).  Both providers
run the same OSWorld Ubuntu Desktop qcow2 image with QEMU/KVM.

Requires OSWorld's --api_provider PR (https://github.com/xlang-ai/OSWorld/pull/485).

Setup:
    # 1. Clone OSWorld
    git clone https://github.com/xlang-ai/osworld.git
    cd osworld && pip install -r requirements.txt

    # 2. Download Ubuntu VM image (~13GB, auto-downloaded on first run)
    docker pull happysixd/osworld-docker

    # 3. Verify KVM access
    test -w /dev/kvm && echo "KVM OK"

Usage:
    # Full comparison (100 tasks, Claude Sonnet 4.6 Computer Use agent)
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --n-tasks 100 --max-steps 30

    # Quick smoke test (10 tasks)
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --n-tasks 10 --max-steps 30

    # Parse existing results only (no re-run)
    python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --parse-only results_docker_100 results_nitrobox_100

Results (100 tasks, Claude Sonnet 4.5, Computer Use agent, 100 steps):

    |      Env | Tasks | Pass |  Rate | Avg Score |
    |----------|-------|------|-------|-----------|
    |   Docker |    96 |   79 | 82.3% |     0.814 |
    | nitrobox |    94 |   79 | 84.0% |     0.830 |

    Phase breakdown (timing.json):
    |          Phase |  Docker | nitrobox | Speedup |
    |----------------|---------|----------|---------|
    | env_setup      |  33.2s  |   7.0s   |   4.7x  |
    | agent          | 174.2s  | 157.6s   |   1.1x  |
    | verifier       |  22.5s  |  22.5s   |   1.0x  |
    | total/task     | 230.0s  | 187.1s   |   1.2x  |
    | overhead %     |  14.5%  |   3.7%   |         |

    Pass rates match → seamless drop-in replacement confirmed.
    Setup speedup 4.7x from QMP loadvm vs Docker container restart.

Environment variables:
    ANTHROPIC_API_KEY  API key for Claude agent
    OSWORLD_DIR        Path to OSWorld checkout (alternative to --osworld-dir)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def _find_osworld_dir(hint: str | None) -> str | None:
    candidates = [
        hint,
        os.environ.get("OSWORLD_DIR"),
        "../osworld",
        "../../osworld",
    ]
    for c in candidates:
        if c and Path(c).is_dir() and (Path(c) / "desktop_env").is_dir():
            return str(Path(c).resolve())
    return None


def _create_task_subset(osworld_dir: str, n_tasks: int) -> str:
    """Create a balanced subset of tasks across all domains."""
    test_all = Path(osworld_dir) / "evaluation_examples" / "test_all.json"
    with open(test_all) as f:
        data = json.load(f)

    n_domains = len(data)
    per_domain = max(1, n_tasks // n_domains)
    subset = {}
    count = 0
    for domain, tasks in data.items():
        take = min(len(tasks), per_domain)
        subset[domain] = tasks[:take]
        count += take
        if count >= n_tasks:
            break

    out_path = Path(osworld_dir) / "evaluation_examples" / f"test_{n_tasks}.json"
    with open(out_path, "w") as f:
        json.dump(subset, f, indent=2)
    return str(out_path)




_TIMING_WRAPPER = '''\
"""Wrapper: patches run_single_example to emit timing.json, then runs the Claude runner."""
import sys, os, json, time
sys.path.insert(0, os.getcwd())

# Patch DesktopEnv to record __init__ boot time
import desktop_env.desktop_env as _de
_orig_init = _de.DesktopEnv.__init__
def _patched_init(self, *a, **kw):
    self._init_start = time.monotonic()
    _orig_init(self, *a, **kw)
    self._init_end = time.monotonic()
_de.DesktopEnv.__init__ = _patched_init

import lib_run_single as _lrs
_orig_run = _lrs.run_single_example
def _timed_run(agent, env, example, max_steps, instruction, args, example_result_dir, scores):
    # Include __init__ boot time in env_setup if this is the first task
    t_init = getattr(env, '_init_end', 0) - getattr(env, '_init_start', 0)
    t0 = time.monotonic()
    env.reset(task_config=example)
    try:
        agent.reset(_lrs.setup_logger(example, example_result_dir), vm_ip=env.vm_ip)
    except Exception:
        agent.reset(vm_ip=env.vm_ip)
    t_setup = time.monotonic()
    # Add __init__ time only for the first task (subsequent tasks pay revert cost in reset)
    if t_init > 0:
        t_init_cost = t_init
        env._init_start = env._init_end = 0  # only count once
    else:
        t_init_cost = 0
    import datetime as _dt
    _lrs.time.sleep(60)
    obs = env._get_obs()
    done = False
    step_idx = 0
    env.controller.start_recording()
    llm_total = 0.0
    while not done and step_idx < max_steps:
        _t_llm = time.monotonic()
        response, actions = agent.predict(instruction, obs)
        llm_total += time.monotonic() - _t_llm
        for action in actions:
            action_timestamp = _dt.datetime.now().strftime("%Y%m%d@%H%M%S%f")
            obs, reward, done, info = env.step(action, args.sleep_after_execution)
            with open(os.path.join(example_result_dir, f"step_{step_idx+1}_{action_timestamp}.png"), "wb") as _f:
                _f.write(obs["screenshot"])
            with open(os.path.join(example_result_dir, "traj.jsonl"), "a") as f:
                f.write(json.dumps({"step_num": step_idx+1, "action_timestamp": action_timestamp,
                    "action": action, "response": response, "reward": reward, "done": done,
                    "info": info, "screenshot_file": f"step_{step_idx+1}_{action_timestamp}.png"}) + "\\n")
            if done:
                break
        step_idx += 1
    t_agent = time.monotonic()
    _lrs.time.sleep(20)
    result = env.evaluate()
    t_verify = time.monotonic()
    scores.append(result)
    with open(os.path.join(example_result_dir, "result.txt"), "w") as f:
        f.write(f"{result}\\n")
    from lib_results_logger import log_task_completion
    log_task_completion(example, result, example_result_dir, args)
    env.controller.end_recording(os.path.join(example_result_dir, "recording.mp4"))
    t_teardown = time.monotonic()
    with open(os.path.join(example_result_dir, "timing.json"), "w") as f:
        json.dump({"environment_setup": (t_setup - t0) + t_init_cost,
                   "agent_execution": t_agent - t_setup,
                   "verifier": t_verify - t_agent, "teardown": t_teardown - t_verify,
                   "llm_inference": llm_total, "n_steps": step_idx}, f)
_lrs.run_single_example = _timed_run

# Run the Claude runner
import runpy
runpy.run_path("scripts/python/run_multienv_claude.py", run_name="__main__")
'''

def run_osworld(
    osworld_dir: str, provider: str, task_file: str,
    result_dir: str, model: str, max_steps: int, num_envs: int,
) -> dict:
    """Run OSWorld evaluation and return timing + results."""
    # Write timing wrapper that injects timing.json into run_single_example
    wrapper = Path(osworld_dir) / ".timing_runner.py"
    wrapper.write_text(_TIMING_WRAPPER)

    cmd = [
        sys.executable, "-B", "-u", str(wrapper),
        "--provider_name", provider,
        "--api_provider", "anthropic",
        "--headless",
        "--observation_type", "screenshot",
        "--model", model,
        "--sleep_after_execution", "3",
        "--max_steps", str(max_steps),
        "--num_envs", str(num_envs),
        "--client_password", "password",
        "--test_all_meta_path", task_file,
        "--result_dir", result_dir,
    ]
    start = time.monotonic()
    result = subprocess.run(
        cmd, cwd=osworld_dir, env={**os.environ},
        capture_output=True, text=True, timeout=3600 * 12,
    )
    wall_time = time.monotonic() - start

    if result.returncode != 0:
        print(f"  [WARN] exited with code {result.returncode}")
        if result.stderr:
            print(f"  stderr: ...{result.stderr[-300:]}")

    return _parse_results(Path(osworld_dir) / result_dir, wall_time)


def _parse_results(result_base: Path, wall_time: float) -> dict:
    """Parse OSWorld result directory, including per-phase timing from timing.json."""
    results = {
        "wall_time_s": wall_time,
        "tasks": 0, "pass": 0, "fail": 0, "errors": 0,
        "per_domain": {}, "scores": [],
        "phases": {
            "environment_setup": [],
            "agent_execution": [],
            "verifier": [],
            "teardown": [],
            "llm_inference": [],
            "n_steps": [],
        },
    }
    for result_file in result_base.rglob("result.txt"):
        task_dir = result_file.parent
        domain = task_dir.parent.name
        if domain in ("args.json", "onboard"):
            continue
        if domain not in results["per_domain"]:
            results["per_domain"][domain] = {"tasks": 0, "pass": 0, "fail": 0}
        results["tasks"] += 1
        results["per_domain"][domain]["tasks"] += 1
        try:
            score = float(result_file.read_text().strip())
            results["scores"].append(score)
            if score > 0:
                results["pass"] += 1
                results["per_domain"][domain]["pass"] += 1
            else:
                results["fail"] += 1
                results["per_domain"][domain]["fail"] += 1
        except ValueError:
            results["errors"] += 1

        # Read per-phase timing if available
        timing_file = task_dir / "timing.json"
        if timing_file.exists():
            try:
                t = json.loads(timing_file.read_text())
                for phase in ["environment_setup", "agent_execution", "verifier", "teardown", "llm_inference"]:
                    if phase in t:
                        results["phases"][phase].append(t[phase])
                if "n_steps" in t:
                    results["phases"]["n_steps"].append(t["n_steps"])
            except (json.JSONDecodeError, KeyError):
                pass

    return results


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _format_results_table(
    all_results: dict[str, dict],
    concurrency: int,
    env_types: list[str],
) -> str:
    """Format results as markdown table (matching harbor e2e format)."""
    lines = []

    def _fmt(val: float, total: float) -> str:
        pct = val / total * 100 if total > 0 else 0
        return f"{val:.1f}s ({pct:.0f}%)"

    # Main table
    lines.append(
        f"| {'C':>3} | {'Env':>8} | {'Wall':>9} | "
        f"{'EnvSetup':>14} | {'Agent':>14} | "
        f"{'LLM':>14} | {'Verify':>14} | {'Teardown':>14} | {'Overhead':>8} | "
        f"{'Pass':>4} | {'Fail':>4} | {'Err':>4} |"
    )
    lines.append(
        f"|{'-'*5}|{'-'*10}|{'-'*11}|"
        f"{'-'*16}|{'-'*16}|"
        f"{'-'*16}|{'-'*16}|{'-'*16}|{'-'*10}|"
        f"{'-'*6}|{'-'*6}|{'-'*6}|"
    )
    for env_type in env_types:
        r = all_results.get(env_type)
        if not r or r["tasks"] == 0:
            continue
        p = r.get("phases", {})
        wall = r["wall_time_s"]
        setup = _mean(p.get("environment_setup", []))
        agent = _mean(p.get("agent_execution", []))
        verify = _mean(p.get("verifier", []))
        tear = _mean(p.get("teardown", []))
        llm = _mean(p.get("llm_inference", []))
        total = setup + agent + verify + tear
        overhead_pct = (total - llm) / total * 100 if total > 0 else 0
        lines.append(
            f"| {concurrency:>3} | {env_type:>8} | {wall:>8.1f}s | "
            f"{_fmt(setup, total):>14} | {_fmt(agent, total):>14} | "
            f"{_fmt(llm, total):>14} | {_fmt(verify, total):>14} | {_fmt(tear, total):>14} | {overhead_pct:>7.0f}% | "
            f"{r['pass']:>4} | {r['fail']:>4} | {r['errors']:>4} |"
        )

    # Per-task breakdown with bar chart
    lines.append("\nPer-task breakdown (mean):")
    for env_type in env_types:
        r = all_results.get(env_type)
        if not r or r["tasks"] == 0:
            continue
        p = r.get("phases", {})
        setup = _mean(p.get("environment_setup", []))
        agent = _mean(p.get("agent_execution", []))
        llm = _mean(p.get("llm_inference", []))
        verify = _mean(p.get("verifier", []))
        tear = _mean(p.get("teardown", []))
        total = setup + agent + verify + tear
        overhead_pct = (total - llm) / total * 100 if total > 0 else 0
        if total <= 0:
            continue
        lines.append(f"  {env_type} c={concurrency} (total {total:.1f}s, overhead {overhead_pct:.0f}%):")
        for label, val in [("env_setup", setup), ("agent_exec", agent),
                           ("  llm_inference", llm), ("verifier", verify),
                           ("teardown", tear)]:
            pct = val / total * 100
            bar = "#" * int(pct / 2)
            lines.append(f"          {label:>12}:  {val:>5.1f}s ({pct:>5.1f}%) {bar}")

    # Speedup
    envs_with_data = [e for e in env_types if all_results.get(e, {}).get("tasks", 0) > 0]
    if len(envs_with_data) == 2:
        a, b = envs_with_data
        wa, wb = all_results[a]["wall_time_s"], all_results[b]["wall_time_s"]
        if wb > 0:
            lines.append(f"\nSpeedup (wall-clock):")
            lines.append(f"  c={concurrency}: {a} {wa:.1f}s vs {b} {wb:.1f}s = {wa/wb:.2f}x")

    # Per-domain
    lines.append("")
    all_domains = sorted(set(
        d for e in env_types for d in all_results.get(e, {}).get("per_domain", {}).keys()
    ))
    header = f"| {'Domain':>20} |"
    for e in env_types:
        header += f" {e:>8} |"
    lines.append(header)
    lines.append(f"|{'-'*22}|" + f"{'-'*10}|" * len(env_types))
    for domain in all_domains:
        row = f"| {domain:>20} |"
        for e in env_types:
            dd = all_results.get(e, {}).get("per_domain", {}).get(domain, {"tasks": 0, "pass": 0})
            s = f"{dd['pass']}/{dd['tasks']}" if dd['tasks'] else "—"
            row += f" {s:>8} |"
        lines.append(row)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="OSWorld e2e benchmark: Docker vs nitrobox (QemuVM)",
    )
    parser.add_argument("--osworld-dir", required=True)
    parser.add_argument("--n-tasks", type=int, default=100)
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--envs", default="docker,nitrobox")
    parser.add_argument("--output", default=None)
    parser.add_argument("--task-file", default=None,
                        help="Custom task list JSON (skip auto-balanced subset). "
                             "Format: {\"domain\": [\"task_id\", ...]}")
    parser.add_argument("--result-suffix", default=None,
                        help="Suffix for result_bench_<env>_<suffix> dirs "
                             "(default: n_tasks)")
    parser.add_argument("--parse-only", nargs=2, metavar=("DOCKER_DIR", "NITROBOX_DIR"),
                        help="Parse existing result dirs (skip running)")
    args = parser.parse_args()

    osworld_dir = _find_osworld_dir(args.osworld_dir)
    if not osworld_dir:
        print("ERROR: OSWorld directory not found")
        return

    envs = [e.strip() for e in args.envs.split(",")]

    print(f"OSWorld E2E benchmark")
    print(f"  OSWorld:     {osworld_dir}")
    print(f"  Tasks:       {args.n_tasks}")
    print(f"  Max steps:   {args.max_steps}")
    print(f"  Model:       {args.model}")
    print(f"  Envs:        {envs}")

    # Map env names to OSWorld provider names
    _env_to_provider = {"docker": "docker", "nitrobox": "nitrobox"}

    if args.parse_only:
        all_results = {
            envs[0]: _parse_results(Path(osworld_dir) / args.parse_only[0], 0),
            envs[1]: _parse_results(Path(osworld_dir) / args.parse_only[1], 0),
        }
    else:
        if args.task_file:
            task_file = args.task_file
            # Count actual tasks in custom file
            with open(task_file) as _f:
                _tf = json.load(_f)
            actual_n = sum(len(v) for v in _tf.values())
            print(f"  Task file:   {task_file} (custom, {actual_n} tasks)")
        else:
            task_file = _create_task_subset(osworld_dir, args.n_tasks)
            print(f"  Task file:   {task_file}")

        suffix = args.result_suffix or str(args.n_tasks)
        all_results = {}
        for env in envs:
            provider = _env_to_provider.get(env, env)
            result_dir = f"./results_bench_{env}_{suffix}"
            print(f"\nRunning: {env} ({args.n_tasks} tasks)...")
            r = run_osworld(osworld_dir, provider, task_file, result_dir,
                            args.model, args.max_steps, args.concurrency)
            all_results[env] = r
            print(f"  Done: {r['wall_time_s']:.0f}s, {r['tasks']} tasks, {r['pass']} pass")

    # Results
    print("\n" + "=" * 100)
    print("RESULTS")
    print("=" * 100 + "\n")
    print(_format_results_table(all_results, args.concurrency, envs))

    # Correctness
    rates = {e: r['pass'] / r['tasks'] * 100 if r['tasks'] else 0
             for e, r in all_results.items()}
    vals = list(rates.values())
    print(f"\nCorrectness:")
    if len(vals) == 2 and abs(vals[0] - vals[1]) < 5.0 and vals[0] > 0:
        e1, e2 = list(rates.keys())
        print(f"  c={args.concurrency}: {e1} {all_results[e1]['pass']} pass ({all_results[e1]['errors']} err), "
              f"{e2} {all_results[e2]['pass']} pass ({all_results[e2]['errors']} err) — MATCH")
    else:
        for e, rate in rates.items():
            print(f"  {e}: {rate:.1f}% ({all_results[e]['pass']}/{all_results[e]['tasks']})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
