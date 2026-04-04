"""Minimal CLI for nitrobox sandbox management.

Thin wrapper over Rust _core functions.

Usage::

    nitrobox ps                  # list sandboxes
    nitrobox cleanup             # remove stale sandboxes
    nitrobox kill <name>         # kill a sandbox by name
    nitrobox kill --all          # kill all sandboxes
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path


def _env_base_dir(args: argparse.Namespace) -> Path:
    if hasattr(args, "dir") and args.dir:
        return Path(args.dir)
    return Path(
        os.environ.get("NITROBOX_ENV_BASE_DIR", f"/tmp/nitrobox_{os.getuid()}")
    )


def _pid_alive(pid: int) -> bool:
    """Check if a process is alive (not zombie, not dead)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" not in line and "X" not in line
        return True
    except (FileNotFoundError, PermissionError):
        return False


def _scan_sandboxes(base: Path) -> list[dict]:
    if not base.exists():
        return []
    results = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        pid_file = entry / ".pid"
        if not pid_file.exists():
            continue
        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError):
            continue
        results.append({
            "name": entry.name,
            "pid": pid,
            "alive": _pid_alive(pid),
            "path": str(entry),
        })
    return results


def cmd_ps(args: argparse.Namespace) -> None:
    base = _env_base_dir(args)
    sandboxes = _scan_sandboxes(base)
    if not sandboxes:
        print("No sandboxes found.")
        return
    print(f"{'NAME':<30} {'PID':>7} {'STATUS':<8} {'PATH'}")
    print("-" * 80)
    for box in sandboxes:
        status = "running" if box["alive"] else "dead"
        print(f"{box['name']:<30} {box['pid']:>7} {status:<8} {box['path']}")
    alive = sum(1 for s in sandboxes if s["alive"])
    dead = sum(1 for s in sandboxes if not s["alive"])
    print(f"\n{alive} running, {dead} stale")


def cmd_cleanup(args: argparse.Namespace) -> None:
    from nitrobox.sandbox import Sandbox
    cleaned = Sandbox.cleanup_stale(str(_env_base_dir(args)))
    if cleaned:
        print(f"Cleaned up {cleaned} stale sandbox(es).")
    else:
        print("No stale sandboxes found.")


def cmd_kill(args: argparse.Namespace) -> None:
    base = _env_base_dir(args)
    sandboxes = _scan_sandboxes(base)

    if args.all:
        targets = [s for s in sandboxes if s["alive"]]
    elif args.name:
        targets = [s for s in sandboxes if s["name"] == args.name]
        if not targets:
            print(f"Sandbox {args.name!r} not found.", file=sys.stderr)
            sys.exit(1)
    else:
        print("Specify a sandbox name or --all.", file=sys.stderr)
        sys.exit(1)

    pids_to_wait: list[int] = []
    for box in targets:
        if not box["alive"]:
            print(f"{box['name']}: already dead")
            pids_to_wait.append(box["pid"])
            continue
        try:
            os.kill(box["pid"], signal.SIGTERM)
            print(f"{box['name']}: killed (pid {box['pid']})")
            pids_to_wait.append(box["pid"])
        except ProcessLookupError:
            print(f"{box['name']}: already dead")
            pids_to_wait.append(box["pid"])
        except PermissionError:
            print(f"{box['name']}: permission denied (pid {box['pid']})", file=sys.stderr)

    if not pids_to_wait:
        return

    for _ in range(10):
        pids_to_wait = [p for p in pids_to_wait if _pid_alive(p)]
        if not pids_to_wait:
            break
        time.sleep(0.5)
    for pid in pids_to_wait:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.1)

    from nitrobox.sandbox import Sandbox
    Sandbox.cleanup_stale(str(base))


def cmd_setup(args: argparse.Namespace) -> None:
    """Set up rootless prerequisites using Docker (no sudo required)."""
    import shutil
    import subprocess

    uid = os.getuid()
    gid = os.getgid()
    user = os.environ.get("USER", str(uid))
    cgroup_dir = "/sys/fs/cgroup/nitrobox"
    vendor_dir = Path(__file__).parent / "_vendor"
    ok = True
    manual_steps: list[str] = []

    # ---- Docker check (required) -----------------------------------------
    docker = shutil.which("docker")
    if not docker:
        print(
            "ERROR: Docker is required for 'nitrobox setup'.\n"
            "Without Docker, configure manually with sudo:"
        )
        manual_steps.append(
            f"  sudo mkdir -p {cgroup_dir} && "
            f"sudo chown {uid}:{gid} {cgroup_dir} && "
            f"echo '+cpu +memory +pids +io +cpuset' | "
            f"sudo tee {cgroup_dir}/cgroup.subtree_control"
        )
        criu_bin = vendor_dir / "criu"
        if criu_bin.exists():
            manual_steps.append(
                f"  sudo setcap cap_checkpoint_restore,cap_sys_ptrace,cap_sys_admin+eip {criu_bin}"
            )
        for step in manual_steps:
            print(step)
        return

    # ---- cgroup v2 check ------------------------------------------------
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        print("SKIP: cgroup v2 not available on this system.")
        return

    # ---- cgroup delegation -----------------------------------------------
    cg_path = Path(cgroup_dir)
    cg_procs = cg_path / "cgroup.procs"
    # Check that both the directory AND cgroup.procs are writable.
    # The directory can be writable while the control files inside are
    # root-owned (e.g. after a reboot or partial setup).
    cgroup_ok = (
        cg_path.exists()
        and os.access(cg_path, os.W_OK)
        and cg_procs.exists()
        and os.access(str(cg_procs), os.W_OK)
    )
    if cgroup_ok:
        print(f"OK: cgroup delegation already configured ({cgroup_dir})")
    else:
        if cg_path.exists() and not os.access(str(cg_procs), os.W_OK):
            print(f"WARN: {cgroup_dir} exists but cgroup.procs is not writable, re-configuring...")
        print("Setting up cgroup delegation via Docker...")
        result = subprocess.run(
            [
                docker, "run", "--rm",
                "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "alpine", "sh", "-c",
                # 1. Create directory and enable controllers (as root)
                f"mkdir -p {cgroup_dir} && "
                f"echo '+cpu +memory +pids +io +cpuset' > "
                f"{cgroup_dir}/cgroup.subtree_control && "
                # 2. Chown AFTER enabling controllers (kernel creates
                #    new control files when controllers are enabled)
                f"chown {uid}:{gid} {cgroup_dir} && "
                f"chown {uid}:{gid} {cgroup_dir}/cgroup.procs && "
                f"chown {uid}:{gid} {cgroup_dir}/cgroup.subtree_control && "
                f"chown {uid}:{gid} /sys/fs/cgroup/cgroup.procs",
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"OK: cgroup delegation configured ({cgroup_dir})")
        else:
            print(
                f"ERROR: Docker cgroup setup failed:\n  {result.stderr.strip()}\n"
                f"  Manual fix: sudo mkdir -p {cgroup_dir} && "
                f"sudo chown {uid}:{gid} {cgroup_dir}"
            )
            ok = False

    # ---- checkpoint helper (setuid) ----------------------------------------
    helper_bin = vendor_dir / "nitrobox-checkpoint-helper"
    system_helper = Path("/usr/local/bin/nitrobox-checkpoint-helper")
    if system_helper.exists() and os.access(str(system_helper), os.X_OK):
        # Check setuid bit
        mode = system_helper.stat().st_mode
        if mode & 0o4000:
            print("OK: checkpoint helper installed (setuid)")
        else:
            print("WARN: checkpoint helper exists but lacks setuid bit")
    elif helper_bin.exists():
        print("Installing checkpoint helper (setuid) via Docker...")
        result = subprocess.run(
            [
                docker, "run", "--rm",
                "-v", f"{helper_bin}:/tmp/helper:ro",
                "-v", "/usr/local/bin:/host-bin",
                "alpine", "sh", "-c",
                "cp /tmp/helper /host-bin/nitrobox-checkpoint-helper && "
                "chown root:root /host-bin/nitrobox-checkpoint-helper && "
                "chmod u+s /host-bin/nitrobox-checkpoint-helper",
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("OK: checkpoint helper installed (setuid)")
        else:
            print(
                f"ERROR: checkpoint helper install failed:\n  {result.stderr.strip()}\n"
                f"  Manual fix: sudo cp {helper_bin} /usr/local/bin/ && "
                f"sudo chmod u+s /usr/local/bin/nitrobox-checkpoint-helper"
            )
            ok = False
    else:
        print("WARN: checkpoint helper binary not found in vendor dir")

    # ---- CRIU binary (install next to helper) --------------------------------
    criu_bin = vendor_dir / "criu"
    criu_libs = vendor_dir / "criu-libs"
    system_criu = Path("/usr/local/bin/criu")
    if system_criu.exists():
        print("OK: CRIU binary installed")
    elif criu_bin.exists():
        print("Installing CRIU binary via Docker...")
        # Copy CRIU + libs next to the helper
        bind_args = ["-v", f"{criu_bin}:/tmp/criu:ro"]
        copy_cmd = "cp /tmp/criu /host-bin/criu && chmod +x /host-bin/criu"
        if criu_libs.is_dir():
            bind_args.extend(["-v", f"{criu_libs}:/tmp/criu-libs:ro"])
            copy_cmd += " && cp -r /tmp/criu-libs /host-bin/"
        result = subprocess.run(
            [docker, "run", "--rm",
             "-v", "/usr/local/bin:/host-bin"] + bind_args +
            ["alpine", "sh", "-c", copy_cmd],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("OK: CRIU binary installed")
        else:
            print(f"WARN: CRIU install failed: {result.stderr.strip()[:200]}")
    else:
        print("WARN: CRIU binary not found (checkpoint/restore unavailable)")

    # ---- checks (detect only, no action) ---------------------------------
    has_newuidmap = shutil.which("newuidmap") is not None
    has_subuid = False
    try:
        with open("/etc/subuid") as f:
            has_subuid = any(line.startswith(f"{user}:") or line.startswith(f"{uid}:")
                            for line in f)
    except FileNotFoundError:
        pass

    if has_newuidmap and has_subuid:
        print("OK: subuid/subgid configured (multi-UID mapping)")
    elif not has_newuidmap:
        print(
            "WARN: newuidmap not found — multi-UID mapping unavailable.\n"
            "  Fix: sudo apt-get install -y uidmap"
        )
    elif not has_subuid:
        print(
            f"WARN: no /etc/subuid entry for {user}.\n"
            f"  Fix: echo '{user}:100000:65536' | sudo tee -a /etc/subuid /etc/subgid"
        )

    vendored_pasta = vendor_dir / "pasta"
    has_pasta = shutil.which("pasta") is not None or vendored_pasta.exists()
    has_slirp = shutil.which("slirp4netns") is not None
    if has_pasta:
        print("OK: pasta available (rootless networking)")
    elif has_slirp:
        print("OK: slirp4netns available (rootless networking)")
    else:
        print(
            "WARN: no rootless network helper found.\n"
            "  Fix: sudo apt-get install -y passt"
        )

    import platform
    kver = platform.release().split("-")[0]
    major, minor = (int(x) for x in kver.split(".")[:2])
    if (major, minor) >= (5, 11):
        print(f"OK: kernel {kver} (>= 5.11, rootless overlayfs supported)")
    else:
        print(f"WARN: kernel {kver} (< 5.11, rootless overlayfs may not work)")

    # ---- summary ----------------------------------------------------------
    if ok:
        print("\nSetup complete.")
    else:
        print("\nSetup incomplete. See errors above.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nitrobox",
        description="nitrobox sandbox manager",
    )
    parser.add_argument(
        "--dir", metavar="PATH",
        help="sandbox base directory (default: /tmp/nitrobox_$UID)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("ps", help="list sandboxes")
    sub.add_parser("cleanup", help="remove stale sandboxes")
    sub.add_parser("setup", help="configure rootless prerequisites")

    kill_p = sub.add_parser("kill", help="kill a sandbox")
    kill_p.add_argument("name", nargs="?", help="sandbox name")
    kill_p.add_argument("--all", action="store_true", help="kill all sandboxes")

    args = parser.parse_args()

    if args.command == "ps":
        cmd_ps(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)
    elif args.command == "kill":
        cmd_kill(args)
    elif args.command == "setup":
        cmd_setup(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
