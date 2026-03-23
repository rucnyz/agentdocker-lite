#!/usr/bin/env python3
"""Per-operation latency breakdown: agentdocker-lite vs Docker vs OpenSandbox.

Three sections:
  1. Overall comparison (create, command, reset, delete, throughput, RL loop)
  2. Per-phase breakdown (what each operation spends time on)
  3. Command-level profiling (sub-ms breakdown of a single echo command)

Auto-detects available backends (Docker, OpenSandbox) and skips unavailable ones.

Usage:
    python examples/benchmark_breakdown.py
    python examples/benchmark_breakdown.py --no-opensandbox
    python examples/benchmark_breakdown.py --no-docker
"""

import argparse
import asyncio
import os
import select
import shlex
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

IMAGE = "ubuntu:22.04"
N_COMMANDS = 20
OPENSANDBOX_DOMAIN = "localhost:8080"


def _med(times):
    return statistics.median(times) if times else 0


def _fmt(ms):
    return f"{ms/1000:.2f}s" if ms >= 1000 else f"{ms:.1f}ms"


def _bar(pct, width=40):
    n = int(pct / 100 * width)
    return "█" * n


# ====================================================================== #
#  agentdocker-lite                                                       #
# ====================================================================== #

def adl_lifecycle():
    from agentdocker_lite import Sandbox, SandboxConfig
    config = SandboxConfig(image=IMAGE, working_dir="/workspace")

    t0 = time.monotonic()
    sb = Sandbox(config, name="bench-adl")
    create_ms = (time.monotonic() - t0) * 1000

    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        sb.run(f"echo iteration-{i}")
        cmd_times.append((time.monotonic() - t0) * 1000)

    t0 = time.monotonic()
    sb.reset()
    reset_ms = (time.monotonic() - t0) * 1000

    t0 = time.monotonic()
    sb.delete()
    delete_ms = (time.monotonic() - t0) * 1000

    return {"create": create_ms, "command": _med(cmd_times),
            "reset": reset_ms, "delete": delete_ms}


def adl_throughput(n=100):
    from agentdocker_lite import Sandbox, SandboxConfig
    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="bench-adl-tp")
    sb.run("echo warmup")
    t0 = time.monotonic()
    for i in range(n):
        sb.run(f"echo {i}")
    elapsed = time.monotonic() - t0
    sb.delete()
    return {"ops_sec": n / elapsed, "avg_ms": elapsed / n * 1000}


def adl_reset_loop(n=50):
    from agentdocker_lite import Sandbox, SandboxConfig
    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="bench-adl-rl")
    times = []
    for i in range(n):
        sb.run(f"echo episode-{i} > /workspace/state.txt")
        t0 = time.monotonic()
        sb.reset()
        times.append((time.monotonic() - t0) * 1000)
    sb.delete()
    return {"median_ms": _med(times)}


def adl_reset_breakdown(n=10):
    from agentdocker_lite import Sandbox, SandboxConfig
    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="prof-adl-rst")

    samples = []
    for i in range(n):
        sb.run("mkdir -p /workspace/d && seq 1 500 | xargs -I{} touch /workspace/d/f_{}")

        t0 = time.monotonic()
        sb._persistent_shell.kill()
        kill_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        if sb._userns:
            for d in (sb._upper_dir, sb._work_dir):
                if d and d.exists():
                    dead = d.with_name(f"{d.name}.dead.{time.monotonic_ns()}")
                    try:
                        d.rename(dead)
                    except OSError:
                        import shutil
                        shutil.rmtree(d, ignore_errors=True)
                if d:
                    d.mkdir(parents=True, exist_ok=True)
        else:
            subprocess.run(["umount", "-l", str(sb._rootfs)], capture_output=True)
            for d in (sb._upper_dir, sb._work_dir):
                if d and d.exists():
                    dead = d.with_name(f"{d.name}.dead.{time.monotonic_ns()}")
                    try:
                        d.rename(dead)
                    except OSError:
                        import shutil
                        shutil.rmtree(d, ignore_errors=True)
                if d:
                    d.mkdir(parents=True, exist_ok=True)
        fs_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        if not sb._userns:
            sb._setup_overlay()
            sb._apply_config_volumes()
        if sb._config.working_dir and sb._config.working_dir != "/":
            target = sb._upper_dir if sb._userns else sb._rootfs
            wd = target / sb._config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)
        target = sb._upper_dir if sb._userns else sb._rootfs
        sb._write_security_files(target, skip_dev=sb._userns)
        setup_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        sb._persistent_shell.start()
        shell_ms = (time.monotonic() - t0) * 1000

        samples.append({"kill_shell": kill_ms, "clear_fs": fs_ms,
                        "setup_overlay_seccomp": setup_ms, "restart_shell": shell_ms,
                        "total": kill_ms + fs_ms + setup_ms + shell_ms})

    sb.delete()
    keys = list(samples[0].keys())
    return {k: _med([s[k] for s in samples]) for k in keys}


def adl_command_breakdown(n=20):
    from agentdocker_lite import Sandbox, SandboxConfig
    sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/workspace"), name="prof-adl-cmd")
    sb.run("echo warmup")
    shell = sb._persistent_shell

    samples = []
    for _ in range(n):
        cmd = "echo hello"
        script = (
            f"cd /workspace 2>/dev/null\n"
            f"bash -c {shlex.quote(cmd)} </dev/null 2>&1\n"
            f"echo $? >&{shell._signal_fd}\n"
        )

        t0 = time.monotonic()
        shell._write_input(script.encode())
        write_ms = (time.monotonic() - t0) * 1000

        stdout_fd = shell._stdout_fd
        signal_fd = shell._signal_r
        ep = select.epoll()
        ep.register(stdout_fd, select.EPOLLIN)
        ep.register(signal_fd, select.EPOLLIN)

        t0 = time.monotonic()
        events = ep.poll(5.0)
        epoll_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        buf = b""
        ready_fds = {fd for fd, _ in events}
        if stdout_fd in ready_fds:
            buf = os.read(stdout_fd, 65536)
        read_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        if signal_fd in ready_fds:
            os.read(signal_fd, 256)
        else:
            events2 = ep.poll(5.0)
            for fd, _ in events2:
                if fd == signal_fd:
                    os.read(signal_fd, 256)
                elif fd == stdout_fd:
                    buf += os.read(stdout_fd, 65536)
        signal_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        while True:
            if not ep.poll(0.01):
                break
            try:
                chunk = os.read(stdout_fd, 65536)
                if not chunk:
                    break
                buf += chunk
            except OSError:
                break
        drain_ms = (time.monotonic() - t0) * 1000

        ep.close()
        total = write_ms + epoll_ms + read_ms + signal_ms + drain_ms
        samples.append({"write_stdin": write_ms, "epoll_wait_bash": epoll_ms,
                        "read_stdout": read_ms, "read_signal": signal_ms,
                        "drain_loop": drain_ms, "total": total})

    sb.delete()
    keys = list(samples[0].keys())
    return {k: _med([s[k] for s in samples]) for k in keys}


# ====================================================================== #
#  Docker                                                                 #
# ====================================================================== #

_docker_ctr = [0]

def _docker_name():
    _docker_ctr[0] += 1
    return f"bench-docker-{_docker_ctr[0]}"


def docker_lifecycle():
    n = _docker_name()
    t0 = time.monotonic()
    subprocess.run(["docker", "run", "-d", "--name", n, "-w", "/workspace",
                    IMAGE, "sleep", "infinity"], capture_output=True, check=True)
    create_ms = (time.monotonic() - t0) * 1000

    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        subprocess.run(["docker", "exec", n, "bash", "-c", f"echo iteration-{i}"],
                       capture_output=True)
        cmd_times.append((time.monotonic() - t0) * 1000)

    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", n], capture_output=True)
    n2 = _docker_name()
    subprocess.run(["docker", "run", "-d", "--name", n2, "-w", "/workspace",
                    IMAGE, "sleep", "infinity"], capture_output=True, check=True)
    reset_ms = (time.monotonic() - t0) * 1000

    t0 = time.monotonic()
    subprocess.run(["docker", "rm", "-f", n2], capture_output=True)
    delete_ms = (time.monotonic() - t0) * 1000

    return {"create": create_ms, "command": _med(cmd_times),
            "reset": reset_ms, "delete": delete_ms}


def docker_throughput(n=100):
    nm = _docker_name()
    subprocess.run(["docker", "run", "-d", "--name", nm, IMAGE, "sleep", "infinity"],
                   capture_output=True, check=True)
    t0 = time.monotonic()
    for i in range(n):
        subprocess.run(["docker", "exec", nm, "bash", "-c", f"echo {i}"], capture_output=True)
    elapsed = time.monotonic() - t0
    subprocess.run(["docker", "rm", "-f", nm], capture_output=True)
    return {"ops_sec": n / elapsed, "avg_ms": elapsed / n * 1000}


def docker_reset_loop(n=20):
    times = []
    nm = _docker_name()
    subprocess.run(["docker", "run", "-d", "--name", nm, "-w", "/workspace",
                    IMAGE, "sleep", "infinity"], capture_output=True, check=True)
    for i in range(n):
        subprocess.run(["docker", "exec", nm, "bash", "-c", f"echo episode-{i}"],
                       capture_output=True)
        t0 = time.monotonic()
        subprocess.run(["docker", "rm", "-f", nm], capture_output=True)
        nm = _docker_name()
        subprocess.run(["docker", "run", "-d", "--name", nm, "-w", "/workspace",
                        IMAGE, "sleep", "infinity"], capture_output=True, check=True)
        times.append((time.monotonic() - t0) * 1000)
    subprocess.run(["docker", "rm", "-f", nm], capture_output=True)
    return {"median_ms": _med(times)}


def docker_reset_breakdown(n=10):
    samples = []
    nm = _docker_name()
    subprocess.run(["docker", "run", "-d", "--name", nm, "-w", "/workspace",
                    IMAGE, "sleep", "infinity"], capture_output=True, check=True)

    for i in range(n):
        subprocess.run(["docker", "exec", nm, "bash", "-c",
                        "seq 1 500 | xargs -I{} touch /workspace/f_{}"], capture_output=True)
        t0 = time.monotonic()
        subprocess.run(["docker", "rm", "-f", nm], capture_output=True)
        rm_ms = (time.monotonic() - t0) * 1000

        nm = _docker_name()
        t0 = time.monotonic()
        subprocess.run(["docker", "run", "-d", "--name", nm, "-w", "/workspace",
                        IMAGE, "sleep", "infinity"], capture_output=True, check=True)
        run_ms = (time.monotonic() - t0) * 1000

        samples.append({"docker_rm": rm_ms, "docker_run": run_ms, "total": rm_ms + run_ms})

    subprocess.run(["docker", "rm", "-f", nm], capture_output=True)
    keys = list(samples[0].keys())
    return {k: _med([s[k] for s in samples]) for k in keys}


# ====================================================================== #
#  OpenSandbox                                                            #
# ====================================================================== #

async def _os_create():
    from opensandbox import Sandbox as OSSandbox
    from opensandbox.config import ConnectionConfig
    from datetime import timedelta
    config = ConnectionConfig(domain=OPENSANDBOX_DOMAIN,
                              request_timeout=timedelta(seconds=60))
    sb = await OSSandbox.create(image=IMAGE, connection_config=config,
                                timeout=timedelta(minutes=5))
    return sb


async def os_lifecycle():
    t0 = time.monotonic()
    sb = await _os_create()
    create_ms = (time.monotonic() - t0) * 1000

    cmd_times = []
    for i in range(N_COMMANDS):
        t0 = time.monotonic()
        await sb.commands.run(f"echo iteration-{i}")
        cmd_times.append((time.monotonic() - t0) * 1000)

    t0 = time.monotonic()
    await sb.kill(); await sb.close()
    sb = await _os_create()
    reset_ms = (time.monotonic() - t0) * 1000

    t0 = time.monotonic()
    await sb.kill(); await sb.close()
    delete_ms = (time.monotonic() - t0) * 1000

    return {"create": create_ms, "command": _med(cmd_times),
            "reset": reset_ms, "delete": delete_ms}


async def os_throughput(n=100):
    sb = await _os_create()
    await sb.commands.run("echo warmup")
    t0 = time.monotonic()
    for i in range(n):
        await sb.commands.run(f"echo {i}")
    elapsed = time.monotonic() - t0
    await sb.kill(); await sb.close()
    return {"ops_sec": n / elapsed, "avg_ms": elapsed / n * 1000}


async def os_reset_loop(n=20):
    times = []
    sb = await _os_create()
    for i in range(n):
        await sb.commands.run(f"echo episode-{i}")
        t0 = time.monotonic()
        await sb.kill(); await sb.close()
        sb = await _os_create()
        times.append((time.monotonic() - t0) * 1000)
    await sb.kill(); await sb.close()
    return {"median_ms": _med(times)}


async def os_reset_breakdown(n=10):
    samples = []
    sb = await _os_create()
    for i in range(n):
        await sb.commands.run(f"echo episode-{i}")
        t0 = time.monotonic()
        await sb.kill(); await sb.close()
        kill_ms = (time.monotonic() - t0) * 1000

        t0 = time.monotonic()
        sb = await _os_create()
        create_ms = (time.monotonic() - t0) * 1000

        samples.append({"kill_container": kill_ms, "create_new": create_ms,
                        "total": kill_ms + create_ms})
    await sb.kill(); await sb.close()
    keys = list(samples[0].keys())
    return {k: _med([s[k] for s in samples]) for k in keys}


# ====================================================================== #
#  Printing helpers                                                       #
# ====================================================================== #

def print_header(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}\n")


def print_breakdown(label, d):
    total = d.get("total", 1)
    print(f"  {label}:")
    for k, v in d.items():
        if not isinstance(v, (int, float)):
            continue
        pct = v / total * 100 if total > 0 else 0
        print(f"    {k:30s} {_fmt(v):>10s}  {pct:5.1f}%  {_bar(pct)}")
    print()


def print_comparison_table(rows, backends):
    """rows: list of (label, {backend: value})"""
    header = f"  {'':20s}" + "".join(f" {b:>12s}" for b in backends)
    if len(backends) > 1:
        header += "   adl speedup"
    print(header)
    print(f"  {'-'*20}" + f" {'-'*12}" * len(backends) + (" " + "-"*13 if len(backends) > 1 else ""))
    for label, vals in rows:
        row = f"  {label:20s}"
        for b in backends:
            row += f" {_fmt(vals.get(b, 0)):>12s}"
        if len(backends) > 1 and "adl" in vals and vals["adl"] > 0:
            others = [vals[b] for b in backends if b != "adl" and b in vals]
            if others:
                sp = max(others) / vals["adl"]
                row += f"   {sp:.1f}x"
        print(row)


# ====================================================================== #
#  Main                                                                   #
# ====================================================================== #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-docker", action="store_true")
    parser.add_argument("--no-opensandbox", action="store_true")
    args = parser.parse_args()

    # Auto-detect
    has_docker = not args.no_docker
    if has_docker:
        r = subprocess.run(["docker", "info"], capture_output=True)
        if r.returncode != 0:
            print("Docker not available, skipping")
            has_docker = False

    has_os = not args.no_opensandbox
    if has_os:
        try:
            r = subprocess.run(["curl", "-s", f"http://{OPENSANDBOX_DOMAIN}/health"],
                               capture_output=True, text=True, timeout=3)
            if "healthy" not in r.stdout:
                has_os = False
        except Exception:
            has_os = False
        if not has_os:
            print("OpenSandbox not available, skipping")

    backends = ["adl"]
    if has_docker:
        backends.append("Docker")
    if has_os:
        backends.append("OpenSandbox")
    print(f"Backends: {', '.join(backends)}")
    print(f"Image: {IMAGE}, Commands per test: {N_COMMANDS}")

    # Warmup
    from agentdocker_lite import Sandbox, SandboxConfig
    print("Warming up rootfs cache...")
    _sb = Sandbox(SandboxConfig(image=IMAGE, working_dir="/"), name="warmup")
    _sb.delete()

    # ================================================================= #
    #  Section 1: Overall comparison                                     #
    # ================================================================= #
    print_header("SECTION 1: Overall Comparison")

    print("  Running adl...")
    adl = adl_lifecycle()
    adl_tp = adl_throughput()
    adl_rl = adl_reset_loop()

    docker = docker_tp = docker_rl = None
    if has_docker:
        print("  Running Docker...")
        docker = docker_lifecycle()
        docker_tp = docker_throughput()
        docker_rl = docker_reset_loop()

    os_r = os_tp = os_rl = None
    if has_os:
        print("  Running OpenSandbox...")
        os_r = asyncio.run(os_lifecycle())
        os_tp = asyncio.run(os_throughput())
        os_rl = asyncio.run(os_reset_loop())

    rows = []
    for label, key in [("Create", "create"), ("Command (median)", "command"),
                        ("Reset", "reset"), ("Delete", "delete")]:
        vals = {"adl": adl[key]}
        if docker:
            vals["Docker"] = docker[key]
        if os_r:
            vals["OpenSandbox"] = os_r[key]
        rows.append((label, vals))

    tp_vals = {"adl": adl_tp["avg_ms"]}
    if docker_tp:
        tp_vals["Docker"] = docker_tp["avg_ms"]
    if os_tp:
        tp_vals["OpenSandbox"] = os_tp["avg_ms"]
    rows.append(("Throughput (avg/cmd)", tp_vals))

    rl_vals = {"adl": adl_rl["median_ms"]}
    if docker_rl:
        rl_vals["Docker"] = docker_rl["median_ms"]
    if os_rl:
        rl_vals["OpenSandbox"] = os_rl["median_ms"]
    rows.append(("RL Reset Loop", rl_vals))

    print()
    print_comparison_table(rows, backends)

    # ================================================================= #
    #  Section 2: Reset breakdown                                        #
    # ================================================================= #
    print_header("SECTION 2: Reset Breakdown (500 files/episode)")

    print("  Profiling adl...")
    adl_rb = adl_reset_breakdown()
    print_breakdown("agentdocker-lite", adl_rb)

    if has_docker:
        print("  Profiling Docker...")
        d_rb = docker_reset_breakdown()
        print_breakdown("Docker", d_rb)

    if has_os:
        print("  Profiling OpenSandbox...")
        os_rb = asyncio.run(os_reset_breakdown())
        print_breakdown("OpenSandbox", os_rb)

    # ================================================================= #
    #  Section 3: Command breakdown (adl only, sub-ms)                   #
    # ================================================================= #
    print_header("SECTION 3: Command Breakdown (adl, sub-ms profiling)")

    adl_cb = adl_command_breakdown()
    print_breakdown("agentdocker-lite (echo hello)", adl_cb)

    print("  Key insight: actual bash execution takes ~1.7ms.")
    print(f"  The drain loop ({_fmt(adl_cb['drain_loop'])}) dominates — it waits")
    print("  for ep.poll(0.01) to confirm no more stdout data.")


if __name__ == "__main__":
    main()
