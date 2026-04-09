#!/usr/bin/env python3
"""Benchmark: OSWorld e2e — Docker vs nitrobox (QemuVM) for GUI agent tasks.

Runs the same set of OSWorld tasks with both Docker and nitrobox providers,
comparing wall-clock time, per-task overhead, and result correctness.

nitrobox uses QEMU loadvm for instant VM reset (~2.5s) instead of
Docker's container destroy+recreate+reboot cycle (~17s).  Both providers
run the same OSWorld Ubuntu Desktop qcow2 image with QEMU/KVM.

Setup:
    # 1. Clone OSWorld
    git clone https://github.com/xlang-ai/osworld.git
    cd osworld && pip install -r requirements.txt

    # 2. Install the nitrobox provider into OSWorld
    #    (copies provider.py and manager.py into desktop_env/providers/adl/)
    python examples/bench_osworld_e2e.py --install-provider --osworld-dir /path/to/osworld

    # 3. Download Ubuntu VM image (~13GB, auto-downloaded on first run)
    docker pull happysixd/osworld-docker

    # 4. Verify KVM access
    test -w /dev/kvm && echo "KVM OK"

Usage:
    # Full comparison (100 tasks, Claude Computer Use agent)
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --n-tasks 100 --max-steps 100

    # Quick smoke test (10 tasks)
    ANTHROPIC_API_KEY=sk-ant-... python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --n-tasks 10 --max-steps 100

    # Parse existing results only (no re-run)
    python examples/bench_osworld_e2e.py \\
        --osworld-dir /path/to/osworld \\
        --parse-only results_docker_100 results_adl_100

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
import shutil
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


def _install_provider(osworld_dir: str) -> None:
    """Install the adl provider into OSWorld's provider directory."""
    provider_src = Path(__file__).parent / "osworld_adl_provider"
    provider_dst = Path(osworld_dir) / "desktop_env" / "providers" / "adl"

    if not provider_src.exists():
        # Create from inline template
        provider_dst.mkdir(parents=True, exist_ok=True)
        _write_provider_files(provider_dst)
    else:
        if provider_dst.exists():
            shutil.rmtree(provider_dst)
        shutil.copytree(str(provider_src), str(provider_dst))

    # Patch __init__.py to register adl
    init_file = Path(osworld_dir) / "desktop_env" / "providers" / "__init__.py"
    init_text = init_file.read_text()
    if '"adl"' not in init_text:
        patch = '''    elif provider_name == "adl":
        from desktop_env.providers.adl.manager import AdlVMManager
        from desktop_env.providers.adl.provider import AdlProvider
        return AdlVMManager(), AdlProvider(region)
'''
        init_text = init_text.replace(
            '    else:\n        raise NotImplementedError',
            patch + '    else:\n        raise NotImplementedError',
        )
        init_file.write_text(init_text)

    # Patch desktop_env.py to accept adl
    env_file = Path(osworld_dir) / "desktop_env" / "desktop_env.py"
    env_text = env_file.read_text()
    if '"adl"' not in env_text:
        env_text = env_text.replace(
            '{"vmware", "virtualbox"}',
            '{"vmware", "virtualbox", "adl"}',
        )
        env_file.write_text(env_text)

    # Patch run_multienv.py choices
    runner = Path(osworld_dir) / "scripts" / "python" / "run_multienv.py"
    if runner.exists():
        runner_text = runner.read_text()
        if '"adl"' not in runner_text:
            runner_text = runner_text.replace(
                '"docker", "azure"',
                '"docker", "azure", "adl"',
            )
            runner.write_text(runner_text)

    print(f"  nitrobox provider installed at {provider_dst}")


def _write_provider_files(dst: Path) -> None:
    """Write the adl provider files (inline, no external dependency)."""
    (dst / "__init__.py").write_text("")

    (dst / "manager.py").write_text('''\
"""VM manager for adl (nitrobox QemuVM) provider."""
import os
from desktop_env.providers.base import VMManager
from desktop_env.providers.docker.manager import _download_vm, VMS_DIR, UBUNTU_X86_URL, WINDOWS_X86_URL

class AdlVMManager(VMManager):
    def __init__(self, registry_path=""): pass
    def add_vm(self, vm_path): pass
    def check_and_clean(self): pass
    def delete_vm(self, vm_path, region=None, **kwargs): pass
    def initialize_registry(self): pass
    def list_free_vms(self): return os.path.join(VMS_DIR, "Ubuntu.qcow2")
    def occupy_vm(self, vm_path, pid, region=None, **kwargs): pass
    def get_vm_path(self, os_type, region, screen_size=(1920, 1080), **kwargs):
        url = UBUNTU_X86_URL if os_type == "Ubuntu" else WINDOWS_X86_URL
        fn = url.split("/")[-1]
        vm_name = fn[:-4] if fn.endswith(".zip") else fn
        if not os.path.exists(os.path.join(VMS_DIR, vm_name)):
            _download_vm(VMS_DIR)
        return os.path.join(VMS_DIR, vm_name)
''')

    (dst / "provider.py").write_text('''\
"""nitrobox QemuVM provider for OSWorld — loadvm-based instant reset."""
import json, logging, os, socket, subprocess, time
import requests
from filelock import FileLock
from pathlib import Path
from desktop_env.providers.base import Provider

logger = logging.getLogger("desktopenv.providers.adl.AdlProvider")
SNAPSHOT_TAG = "adl_ready"

class AdlProvider(Provider):
    def __init__(self, region=None):
        super().__init__(region)
        self.qemu_proc = None
        self.qmp_sock = None
        self.server_port = self.vnc_port = self.chromium_port = self.vlc_port = None
        self._has_snapshot = False
        self.lock_file = Path("/tmp/adl_port_allocation.lck")

    def _get_available_port(self, start):
        import psutil
        used = set(c.laddr.port for c in psutil.net_connections())
        p = start
        while p < 65354:
            if p not in used: return p
            p += 1
        raise RuntimeError(f"No ports from {start}")

    def _qmp_send(self, command, arguments=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(120); s.connect(self.qmp_sock); s.recv(4096)
        s.sendall(b\'{"execute": "qmp_capabilities"}\\n\'); s.recv(4096)
        msg = {"execute": command}
        if arguments: msg["arguments"] = arguments
        s.sendall(json.dumps(msg).encode() + b"\\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if b\'"return"\' in data or b\'"error"\' in data: break
        s.close()
        for line in data.decode(errors="ignore").strip().split("\\n"):
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                if "return" in obj or "error" in obj: return obj
            except json.JSONDecodeError: continue
        return {"return": {}}

    def _hmp(self, command):
        resp = self._qmp_send("human-monitor-command", {"command-line": command})
        if "error" in resp: raise RuntimeError(f"HMP failed: {resp[\'error\']}")
        return resp.get("return", "")

    def _wait_for_vm_ready(self, timeout=300):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                r = requests.get(f"http://localhost:{self.server_port}/screenshot", timeout=(10,10))
                if r.status_code == 200: return
            except Exception: pass
            time.sleep(1)
        raise TimeoutError("VM not ready")

    def start_emulator(self, path_to_vm, headless, os_type="Ubuntu"):
        if self.qemu_proc and self.qemu_proc.poll() is None:
            return  # Already running after loadvm
        lock = FileLock(str(self.lock_file), timeout=10)
        try:
            with lock:
                self.server_port = self._get_available_port(5000)
                self.chromium_port = self._get_available_port(9222)
                self.vnc_port = self._get_available_port(8006)
                self.vlc_port = self._get_available_port(8080)
        except Exception:
            pid_off = os.getpid() % 1000
            self.server_port, self.chromium_port = 15000+pid_off, 19222+pid_off
            self.vnc_port, self.vlc_port = 18006+pid_off, 18080+pid_off
        self.qmp_sock = f"/tmp/adl_osworld_qmp_{self.server_port}.sock"
        try: os.unlink(self.qmp_sock)
        except FileNotFoundError: pass
        hostfwd = (f"hostfwd=tcp::{self.server_port}-:5000,"
                   f"hostfwd=tcp::{self.chromium_port}-:9222,"
                   f"hostfwd=tcp::{self.vnc_port}-:8006,"
                   f"hostfwd=tcp::{self.vlc_port}-:8080")
        cmd = ["qemu-system-x86_64", "-enable-kvm", "-m", "4G", "-smp", "4",
               "-drive", f"file={path_to_vm},format=qcow2,if=virtio,snapshot=on",
               "-qmp", f"unix:{self.qmp_sock},server,nowait",
               "-display", "none", "-serial", "null", "-no-shutdown", "-nographic",
               "-device", "virtio-vga", "-nic", f"user,{hostfwd}"]
        self.qemu_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if os.path.exists(self.qmp_sock):
                try: self._qmp_send("query-status"); break
                except Exception: pass
            time.sleep(0.2)
        else: self.qemu_proc.kill(); raise TimeoutError("QMP not ready")
        if self._has_snapshot:
            self._hmp(f"loadvm {SNAPSHOT_TAG}")
        else:
            self._wait_for_vm_ready()
            self._hmp(f"savevm {SNAPSHOT_TAG}")
            self._qmp_send("cont")  # savevm pauses VM
            self._has_snapshot = True

    def get_ip_address(self, path_to_vm):
        return f"localhost:{self.server_port}:{self.chromium_port}:{self.vnc_port}:{self.vlc_port}"

    def save_state(self, path_to_vm, snapshot_name):
        self._hmp(f"savevm {snapshot_name}")
        self._qmp_send("cont")

    def revert_to_snapshot(self, path_to_vm, snapshot_name):
        if self.qemu_proc and self.qemu_proc.poll() is None:
            tag = SNAPSHOT_TAG if self._has_snapshot else snapshot_name
            self._hmp(f"loadvm {tag}")
        else:
            self.stop_emulator(path_to_vm)
            self.start_emulator(path_to_vm, headless=True)

    def stop_emulator(self, path_to_vm, region=None, *args, **kwargs):
        if self.qemu_proc:
            try: self._qmp_send("quit")
            except Exception: pass
            try: self.qemu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired: self.qemu_proc.kill(); self.qemu_proc.wait()
            self.qemu_proc = None
        if self.qmp_sock:
            try: os.unlink(self.qmp_sock)
            except FileNotFoundError: pass
        self.server_port = self.vnc_port = self.chromium_port = self.vlc_port = None
''')


def run_osworld(
    osworld_dir: str, provider: str, task_file: str,
    result_dir: str, model: str, max_steps: int, num_envs: int,
) -> dict:
    """Run OSWorld evaluation and return timing + results."""
    cmd = [
        sys.executable, "-B", "-u",
        "scripts/python/run_multienv.py",
        "--provider_name", provider,
        "--headless",
        "--observation_type", "screenshot",
        "--model", model,
        "--max_steps", str(max_steps),
        "--num_envs", str(num_envs),
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
                for phase in ["environment_setup", "agent_execution", "verifier"]:
                    if phase in t:
                        results["phases"][phase].append(t[phase])
                if "n_steps" in t:
                    results["phases"]["n_steps"].append(t["n_steps"])
            except (json.JSONDecodeError, KeyError):
                pass

    return results


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _format_results_table(docker: dict, nitrobox: dict) -> str:
    """Format results as markdown table (matching harbor e2e format)."""
    lines = []

    # Overall
    lines.append(
        f"| {'Env':>8} | {'Tasks':>5} | {'Pass':>4} | {'Fail':>4} | "
        f"{'Rate':>5} | {'Errors':>6} | {'Steps/task':>10} |"
    )
    lines.append(
        f"|{'-'*10}|{'-'*7}|{'-'*6}|{'-'*6}|{'-'*7}|{'-'*8}|{'-'*12}|"
    )
    for name, r in [("Docker", docker), ("nitrobox", nitrobox)]:
        rate = r['pass'] / r['tasks'] * 100 if r['tasks'] else 0
        n_steps = _mean(r.get("phases", {}).get("n_steps", []))
        steps_str = f"{n_steps:.1f}" if n_steps > 0 else "—"
        lines.append(
            f"| {name:>8} | {r['tasks']:>5} | {r['pass']:>4} | {r['fail']:>4} | "
            f"{rate:>4.1f}% | {r['errors']:>6} | {steps_str:>10} |"
        )

    # Phase timing breakdown (if timing.json available)
    has_phases = any(
        r.get("phases", {}).get("environment_setup", [])
        for r in [docker, nitrobox]
    )
    if has_phases:
        lines.append("")
        lines.append("Phase breakdown (from timing.json, provider-relevant metric in bold):")
        lines.append(
            f"| {'Env':>8} | {'**Setup**':>9} | {'Agent':>7} | {'Verify':>7} | "
            f"{'Overhead':>8} |"
        )
        lines.append(
            f"|{'-'*10}|{'-'*11}|{'-'*9}|{'-'*9}|{'-'*10}|"
        )
        for name, r in [("Docker", docker), ("nitrobox", nitrobox)]:
            p = r.get("phases", {})
            setup = _mean(p.get("environment_setup", []))
            agent = _mean(p.get("agent_execution", []))
            verify = _mean(p.get("verifier", []))
            total = setup + agent + verify
            overhead = setup / total * 100 if total > 0 else 0
            if setup > 0:
                lines.append(
                    f"| {name:>8} | {setup:>7.1f}s | {agent:>5.1f}s | {verify:>5.1f}s | "
                    f"{overhead:>6.1f}% |"
                )

    # Per-domain
    lines.append("")
    all_domains = sorted(set(list(docker["per_domain"].keys()) + list(nitrobox["per_domain"].keys())))
    lines.append(f"| {'Domain':>20} | {'Docker':>8} | {'nitrobox':>8} |")
    lines.append(f"|{'-'*22}|{'-'*10}|{'-'*10}|")
    for domain in all_domains:
        dd = docker["per_domain"].get(domain, {"tasks": 0, "pass": 0})
        nd = nitrobox["per_domain"].get(domain, {"tasks": 0, "pass": 0})
        d_str = f"{dd['pass']}/{dd['tasks']}" if dd['tasks'] else "—"
        n_str = f"{nd['pass']}/{nd['tasks']}" if nd['tasks'] else "—"
        lines.append(f"| {domain:>20} | {d_str:>8} | {n_str:>8} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="OSWorld e2e benchmark: Docker vs nitrobox (QemuVM)",
    )
    parser.add_argument("--osworld-dir", required=True)
    parser.add_argument("--n-tasks", type=int, default=100)
    parser.add_argument("--max-steps", type=int, default=15)
    parser.add_argument("--model", default="claude-sonnet-4-20250514")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--envs", default="docker,nitrobox")
    parser.add_argument("--output", default=None)
    parser.add_argument("--install-provider", action="store_true",
                        help="Install nitrobox provider into OSWorld and exit")
    parser.add_argument("--parse-only", nargs=2, metavar=("DOCKER_DIR", "NITROBOX_DIR"),
                        help="Parse existing result dirs (skip running)")
    args = parser.parse_args()

    osworld_dir = _find_osworld_dir(args.osworld_dir)
    if not osworld_dir:
        print("ERROR: OSWorld directory not found")
        return

    if args.install_provider:
        _install_provider(osworld_dir)
        return

    envs = [e.strip() for e in args.envs.split(",")]

    print(f"OSWorld E2E benchmark")
    print(f"  OSWorld:     {osworld_dir}")
    print(f"  Tasks:       {args.n_tasks}")
    print(f"  Max steps:   {args.max_steps}")
    print(f"  Model:       {args.model}")
    print(f"  Envs:        {envs}")

    # Map env names to OSWorld provider names
    _env_to_provider = {"docker": "docker", "nitrobox": "adl"}

    if args.parse_only:
        docker = _parse_results(Path(osworld_dir) / args.parse_only[0], 0)
        nitrobox = _parse_results(Path(osworld_dir) / args.parse_only[1], 0)
    else:
        # Ensure nitrobox provider is installed
        provider_dir = Path(osworld_dir) / "desktop_env" / "providers" / "adl"
        if "nitrobox" in envs and not provider_dir.exists():
            print("\nInstalling nitrobox provider...")
            _install_provider(osworld_dir)

        task_file = _create_task_subset(osworld_dir, args.n_tasks)
        print(f"  Task file:   {task_file}")

        all_results = {}
        for env in envs:
            provider = _env_to_provider.get(env, env)
            result_dir = f"./results_bench_{env}_{args.n_tasks}"
            print(f"\nRunning: {env} ({args.n_tasks} tasks)...")
            r = run_osworld(osworld_dir, provider, task_file, result_dir,
                            args.model, args.max_steps, args.concurrency)
            all_results[env] = r
            print(f"  Done: {r['wall_time_s']:.0f}s, {r['tasks']} tasks, {r['pass']} pass")

        docker = all_results.get("docker", {"tasks": 0, "pass": 0, "fail": 0,
                                             "errors": 0, "per_domain": {}, "scores": []})
        nitrobox = all_results.get("nitrobox", docker)

    # Results
    print("\n" + "=" * 68)
    print("RESULTS")
    print("=" * 68 + "\n")
    print(_format_results_table(docker, nitrobox))

    # Correctness
    d_rate = docker['pass'] / docker['tasks'] * 100 if docker['tasks'] else 0
    n_rate = nitrobox['pass'] / nitrobox['tasks'] * 100 if nitrobox['tasks'] else 0

    print(f"\nCorrectness:")
    if abs(d_rate - n_rate) < 5.0 and docker['tasks'] > 0:
        print(f"  Pass rates match: Docker {d_rate:.1f}% vs nitrobox {n_rate:.1f}%")
    elif docker['tasks'] == 0:
        print(f"  nitrobox only: {n_rate:.1f}% pass rate")
    else:
        print(f"  Pass rates differ: Docker {d_rate:.1f}% vs nitrobox {n_rate:.1f}%")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"docker": docker, "nitrobox": nitrobox}, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
