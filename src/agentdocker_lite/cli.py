"""Minimal CLI for agentdocker-lite sandbox management.

Usage::

    adl ps                  # list sandboxes
    adl cleanup             # remove stale sandboxes
    adl kill <name>         # kill a sandbox by name
    adl kill --all          # kill all sandboxes
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path


def _env_base_dir(args: argparse.Namespace) -> Path:
    if hasattr(args, "dir") and args.dir:
        return Path(args.dir)
    return Path(
        os.environ.get("ADL_ENV_BASE_DIR", f"/tmp/agentdocker_lite_{os.getuid()}")
    )


def _scan_sandboxes(base: Path) -> list[dict]:
    """Scan for sandbox directories and return their status."""
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

        alive = _pid_alive(pid)

        results.append({
            "name": entry.name,
            "pid": pid,
            "alive": alive,
            "path": str(entry),
        })
    return results


def _pid_alive(pid: int) -> bool:
    """Check if a process is alive (not zombie, not dead)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    # Z = zombie, X = dead — treat both as not alive
                    return "Z" not in line and "X" not in line
        return True
    except (FileNotFoundError, PermissionError):
        return False


def cmd_ps(args: argparse.Namespace) -> None:
    """List sandboxes."""
    base = _env_base_dir(args)
    sandboxes = _scan_sandboxes(base)

    if not sandboxes:
        print("No sandboxes found.")
        return

    # Header
    print(f"{'NAME':<30} {'PID':>7} {'STATUS':<8} {'PATH'}")
    print("-" * 80)
    for sb in sandboxes:
        status = "running" if sb["alive"] else "dead"
        print(f"{sb['name']:<30} {sb['pid']:>7} {status:<8} {sb['path']}")

    alive = sum(1 for s in sandboxes if s["alive"])
    dead = sum(1 for s in sandboxes if not s["alive"])
    print(f"\n{alive} running, {dead} stale")


def cmd_cleanup(args: argparse.Namespace) -> None:
    """Remove stale sandboxes."""
    from agentdocker_lite.backends.base import SandboxBase

    cleaned = SandboxBase.cleanup_stale(str(_env_base_dir(args)))
    if cleaned:
        print(f"Cleaned up {cleaned} stale sandbox(es).")
    else:
        print("No stale sandboxes found.")


def cmd_kill(args: argparse.Namespace) -> None:
    """Kill a sandbox by name or all sandboxes."""
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
    for sb in targets:
        if not sb["alive"]:
            print(f"{sb['name']}: already dead")
            pids_to_wait.append(sb["pid"])
            continue
        try:
            os.kill(sb["pid"], signal.SIGTERM)
            print(f"{sb['name']}: killed (pid {sb['pid']})")
            pids_to_wait.append(sb["pid"])
        except ProcessLookupError:
            print(f"{sb['name']}: already dead")
            pids_to_wait.append(sb["pid"])
        except PermissionError:
            print(f"{sb['name']}: permission denied (pid {sb['pid']})", file=sys.stderr)

    if not pids_to_wait:
        return

    # Wait for processes to die (SIGTERM → wait → SIGKILL fallback)
    import time
    for _ in range(10):  # 5 seconds max
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

    # Clean up remains — SIGTERM doesn't trigger Python atexit,
    # so the sandbox dir is left behind.
    from agentdocker_lite.backends.base import SandboxBase
    SandboxBase.cleanup_stale(str(base))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="adl",
        description="agentdocker-lite sandbox manager",
    )
    parser.add_argument(
        "--dir", metavar="PATH",
        help="sandbox base directory (default: /tmp/agentdocker_lite_$UID)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("ps", help="list sandboxes")

    sub.add_parser("cleanup", help="remove stale sandboxes")

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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
