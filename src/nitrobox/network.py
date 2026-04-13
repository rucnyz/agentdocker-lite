"""Pasta NAT networking and DNS configuration for sandboxes."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from nitrobox._errors import SandboxInitError, SandboxKernelError

logger = logging.getLogger(__name__)


def find_pasta_bin() -> str | None:
    """Find the pasta binary (vendored or system)."""
    vendored = Path(__file__).parent / "_vendor" / "pasta"
    if vendored.exists() and vendored.is_file():
        return str(vendored)
    if shutil.which("pasta"):
        return "pasta"
    return None


def write_dns(
    host_path_write_fn: Callable[[str], Path],
    dns_servers: list[str],
) -> None:
    """Write /etc/resolv.conf inside the sandbox via a host-path writer."""
    resolv = host_path_write_fn("/etc/resolv.conf")
    resolv.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(f"nameserver {s}\n" for s in dns_servers)
    resolv.write_text(content)


def start_pasta_rootful(
    name: str,
    shell_pid: int,
    config_net_isolate: bool,
    config_port_map: list[str],
    config_ipv6: bool,
    env_dir: Path,
) -> str | None:
    """Attach pasta to the sandbox's existing network namespace (rootful only).

    The sandbox was created with ``net_isolate=True`` (its own netns via
    ``unshare(CLONE_NEWNET)``).  Pasta connects to that netns from the host
    and provides NAT + TCP port forwarding.

    Returns the netns_path string, or None if no netns was created.
    """
    pasta_bin = find_pasta_bin()
    if not pasta_bin:
        raise SandboxKernelError(
            "port_map requires 'pasta' (from the passt package)."
        )

    netns_name = f"nitrobox-{name}"

    # Bind mount the sandbox's netns to /run/netns/ so pasta can open it
    # (pasta's internal sandboxing blocks direct /proc/{pid}/ns/net access).
    from nitrobox._core import py_bind_mount, py_umount_lazy

    netns_path = f"/run/netns/{netns_name}"
    os.makedirs("/run/netns", exist_ok=True)
    if os.path.exists(netns_path):
        try:
            py_umount_lazy(netns_path)
        except OSError:
            pass
        try:
            os.unlink(netns_path)
        except OSError:
            pass
    fd = os.open(netns_path, os.O_WRONLY | os.O_CREAT, 0o644)
    os.close(fd)
    py_bind_mount(f"/proc/{shell_pid}/ns/net", netns_path)

    cmd: list[str] = [
        pasta_bin, "--config-net", "--runas", "0:0",
    ]
    if not config_ipv6:
        cmd.append("--ipv4-only")
    # Podman: add explicit port mappings, or -t none to disable default
    # TCP forwarding (pasta_linux.go:248-259).  Without -t none, pasta
    # forwards ALL host TCP ports into the sandbox.
    if config_port_map:
        for mapping in config_port_map:
            cmd.extend(["-t", mapping])
    else:
        cmd.extend(["-t", "none"])
    # Write PID file so stop_pasta_rootful can kill the daemon.
    pasta_pid_file = str(env_dir / "pasta.pid")
    cmd.extend([
        "-u", "none", "-T", "none", "-U", "none",
        "--dns-forward", "169.254.1.1",
        "--no-map-gw", "--quiet",
        "--netns", netns_path,
        "--map-guest-addr", "169.254.1.2",
        "-P", pasta_pid_file,
    ])

    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SandboxInitError(
            f"pasta failed (exit={out.returncode}): {out.stderr.strip()}"
        )

    logger.debug("pasta ready (rootful): pid=%d ports=%s", shell_pid, config_port_map)
    return netns_path


def stop_pasta_rootful(
    netns_path: str | None,
    env_dir: Path | None = None,
) -> None:
    """Kill pasta daemon and clean up netns bind mount."""
    # Kill pasta daemon and its children via PID file
    if env_dir:
        pid_file = env_dir / "pasta.pid"
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                # Kill entire process group to catch child processes
                try:
                    os.killpg(os.getpgid(pid), 9)
                except (ProcessLookupError, PermissionError):
                    # Fallback: kill just the PID
                    try:
                        os.kill(pid, 9)
                    except (ProcessLookupError, PermissionError):
                        pass
                logger.debug("Killed pasta daemon pid=%d", pid)
            except (ValueError, ProcessLookupError, PermissionError):
                pass
            try:
                pid_file.unlink()
            except OSError:
                pass

    if netns_path and os.path.exists(netns_path):
        from nitrobox._core import py_umount_lazy
        try:
            py_umount_lazy(netns_path)
        except OSError:
            pass
        try:
            os.unlink(netns_path)
        except OSError:
            pass
