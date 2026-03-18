"""Namespace-based sandbox (root mode) with overlayfs or btrfs backend.

Provides near-zero-overhead environment isolation using Linux namespaces and
copy-on-write filesystems, designed for high-frequency workloads where
environments need to be created, reset, and destroyed thousands of times.

Supported filesystem backends:
- **overlayfs** (default): lowerdir (base) + upperdir (per-env changes).
  Reset clears upperdir -- O(n) in number of changed files.
- **btrfs**: Subvolume snapshots.  Reset = delete snapshot + re-snapshot
  from base -- O(1) regardless of changes.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from agentdocker_lite.backends.base import SandboxBase, SandboxConfig
from agentdocker_lite._shell import _PersistentShell

logger = logging.getLogger(__name__)


class RootfulSandbox(SandboxBase):
    """Linux namespace sandbox with pluggable CoW filesystem backend.

    Each instance manages one isolated environment with:
    - ``unshare --pid --mount --fork`` for PID and mount namespace isolation
    - Persistent shell (chroot) for low-latency command execution
    - Copy-on-write filesystem (overlayfs or btrfs) for instant reset
    - Bind mounts for shared volumes
    - cgroup v2 for optional CPU / memory / PID limits

    Example::

        from agentdocker_lite import Sandbox, SandboxConfig

        config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
        sb = Sandbox(config, name="worker-0")
        output, ec = sb.run("echo hello world")
        sb.reset()        # instant filesystem reset
        sb.delete()       # full cleanup
    """

    SUPPORTED_FS_BACKENDS = ("overlayfs", "btrfs")

    def __init__(self, config: SandboxConfig, name: str = "default"):
        self._config = config
        self._name = name
        self._userns = False
        self._init_rootful(config, name)
        self._register(self)

    # ------------------------------------------------------------------ #
    #  Rootful init (full namespace / overlayfs / cgroup isolation)        #
    # ------------------------------------------------------------------ #

    def _init_rootful(self, config: SandboxConfig, name: str) -> None:
        """Initialize in rootful mode -- full isolation."""
        if not config.image:
            raise ValueError("SandboxConfig.image is required.")

        self._fs_backend = config.fs_backend

        if self._fs_backend not in self.SUPPORTED_FS_BACKENDS:
            raise ValueError(
                f"Unsupported fs_backend {self._fs_backend!r}. "
                f"Choose from: {self.SUPPORTED_FS_BACKENDS}"
            )

        self._check_prerequisites(self._fs_backend)

        # --- paths --------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        self._base_rootfs = self._resolve_base_rootfs(
            image=config.image,
            fs_backend=self._fs_backend,
            rootfs_cache_dir=rootfs_cache_dir,
        )

        env_base = Path(config.env_base_dir)
        self._env_dir = env_base / name
        self._rootfs = self._env_dir / "rootfs"

        # overlayfs-only paths
        self._upper_dir: Optional[Path] = None
        self._work_dir: Optional[Path] = None

        # --- state tracking -----------------------------------------------
        self._overlay_mounted = False
        self._btrfs_active = False
        self._bind_mounts: list[Path] = []
        self._cow_tmpdirs: list[str] = []
        self._cgroup_path: Optional[Path] = None
        self._cgroup_limits = {
            "cpu_max": config.cpu_max,
            "memory_max": config.memory_max,
            "pids_max": config.pids_max,
            "io_max": config.io_max,
            "cpuset_cpus": config.cpuset_cpus,
        }

        # --- setup --------------------------------------------------------
        t0 = time.monotonic()
        if self._fs_backend == "btrfs":
            self._setup_btrfs()
        else:
            self._upper_dir = self._env_dir / "upper"
            self._work_dir = self._env_dir / "work"
            self._setup_overlay()
        fs_ms = (time.monotonic() - t0) * 1000

        t1 = time.monotonic()
        self._setup_cgroup()
        cg_ms = (time.monotonic() - t1) * 1000

        t2 = time.monotonic()
        self._apply_config_volumes()
        vol_ms = (time.monotonic() - t2) * 1000

        if config.working_dir and config.working_dir != "/":
            wd = self._rootfs / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)

        # Write custom DNS config
        if config.dns:
            self._write_dns(config.dns)

        # Write seccomp helper into rootfs (called from init_script inside chroot)
        if config.seccomp:
            self._write_seccomp_helper()

        # Read-only rootfs: bind-mount on itself then remount ro
        if config.read_only:
            subprocess.run(
                ["mount", "--bind", str(self._rootfs), str(self._rootfs)],
                capture_output=True,
            )
            subprocess.run(
                ["mount", "-o", "remount,ro,bind", str(self._rootfs)],
                capture_output=True,
            )

        self._shell = self._detect_shell()
        self._cached_env = self._build_env()

        t3 = time.monotonic()
        self._persistent_shell = _PersistentShell(
            rootfs=self._rootfs,
            shell=self._shell,
            env=self._cached_env,
            working_dir=config.working_dir or "/",
            cgroup_path=self._cgroup_path,
            tty=config.tty,
            net_isolate=config.net_isolate,
            seccomp=config.seccomp,
            landlock_read=config.landlock_read,
            landlock_write=config.landlock_write,
            landlock_tcp_ports=config.landlock_tcp_ports,
            hostname=config.hostname,
        )
        shell_ms = (time.monotonic() - t3) * 1000

        self._bg_handles: dict[str, str] = {}  # handle -> pid
        self._pasta_process = None
        self._start_pasta()

        if config.oom_score_adj is not None:
            self._apply_oom_score_adj(config.oom_score_adj)

        # Write PID file for stale sandbox cleanup
        pid_file = self._env_dir / ".pid"
        pid_file.write_text(str(os.getpid()))

        self.features: dict[str, object] = {
            "pidfd": self._persistent_shell._pidfd is not None,
            "cgroup_v2": self._cgroup_path is not None,
            "seccomp": config.seccomp,
            "netns": config.net_isolate,
            "timens": getattr(self._persistent_shell, "_timens", False),
            "cpuset_cpus": config.cpuset_cpus,
            "oom_score_adj": config.oom_score_adj,
            "mask_paths": True,
            "cap_drop": True,
        }
        feat_str = ", ".join(
            k if v is True else f"{k}={v}"
            for k, v in self.features.items()
            if v
        )
        logger.info(
            "Sandbox ready: name=%s rootfs=%s fs=%s features=[%s] "
            "[setup: fs=%.1fms cgroup=%.1fms volumes=%.1fms shell=%.1fms]",
            name,
            self._rootfs,
            self._fs_backend,
            feat_str,
            fs_ms,
            cg_ms,
            vol_ms,
            shell_ms,
        )

    # ------------------------------------------------------------------ #
    #  User namespace init (no real root required)                          #
    # ------------------------------------------------------------------ #

    def _init_userns(self, config: SandboxConfig, name: str) -> None:
        """Initialize in user namespace mode -- namespace+overlayfs without root."""
        if not config.image:
            raise ValueError("SandboxConfig.image is required.")

        if config.fs_backend != "overlayfs":
            raise ValueError(
                f"Rootless mode only supports overlayfs, got fs_backend={config.fs_backend!r}. "
                f"btrfs requires root."
            )
        self._fs_backend = "overlayfs"

        self._check_prerequisites_userns()

        # --- paths --------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        self._base_rootfs = self._resolve_base_rootfs(
            image=config.image,
            fs_backend="overlayfs",
            rootfs_cache_dir=rootfs_cache_dir,
        )

        env_base = Path(config.env_base_dir)
        self._env_dir = env_base / name
        self._rootfs = self._env_dir / "rootfs"   # overlay merged (inside namespace only)
        self._upper_dir = self._env_dir / "upper"
        self._work_dir = self._env_dir / "work"

        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        # --- state tracking -----------------------------------------------
        self._overlay_mounted = False
        self._btrfs_active = False
        self._bind_mounts: list[Path] = []
        self._cow_tmpdirs: list[str] = []
        self._cgroup_path: Optional[Path] = None
        self._cgroup_limits = {
            "cpu_max": config.cpu_max,
            "memory_max": config.memory_max,
            "pids_max": config.pids_max,
            "io_max": config.io_max,
            "cpuset_cpus": config.cpuset_cpus,
        }

        # --- cgroup via systemd delegation --------------------------------
        self._systemd_scope_properties: list[str] = []
        if any(self._cgroup_limits.values()):
            if shutil.which("systemd-run"):
                prop_map = {
                    "cpu_max": "CPUQuota",
                    "memory_max": "MemoryMax",
                    "pids_max": "TasksMax",
                    "io_max": "IOWriteBandwidthMax",
                }
                for key, sd_prop in prop_map.items():
                    value = self._cgroup_limits.get(key)
                    if value:
                        if key == "cpu_max":
                            # Convert "50000 100000" → "50%"
                            parts = value.split()
                            if len(parts) == 2:
                                pct = int(int(parts[0]) / int(parts[1]) * 100)
                                self._systemd_scope_properties.append(f"{sd_prop}={pct}%")
                        elif key == "io_max":
                            # io_max is raw cgroup format "MAJ:MIN wbps=N"
                            # systemd uses "IOWriteBandwidthMax=/dev/X N"
                            # Pass as-is; user must use systemd format
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                        else:
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                logger.debug(
                    "cgroup via systemd delegation: %s",
                    self._systemd_scope_properties,
                )
            else:
                logger.warning(
                    "cgroup resource limits requested but systemd-run not found. "
                    "Run as root for direct cgroup access."
                )
        if config.devices:
            logger.warning(
                "Device passthrough is not available in user namespace mode. "
                "Run as root to enable device passthrough."
            )

        # --- seccomp helper in upper dir ----------------------------------
        if config.seccomp:
            self._write_seccomp_helper_userns()

        # --- DNS ----------------------------------------------------------
        if config.dns:
            self._write_dns(config.dns)

        # --- working dir in upper dir -------------------------------------
        if config.working_dir and config.working_dir != "/":
            wd = self._upper_dir / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)

        # --- generate setup script ----------------------------------------
        self._shell = self._detect_shell()
        setup_script_path = self._generate_userns_setup_script()

        self._cached_env = self._build_env()

        # --- start persistent shell ---------------------------------------
        t0 = time.monotonic()
        self._persistent_shell = _PersistentShell(
            rootfs=self._rootfs,
            shell=self._shell,
            env=self._cached_env,
            working_dir=config.working_dir or "/",
            tty=config.tty,
            net_isolate=config.net_isolate,
            seccomp=config.seccomp,
            userns_setup_script=str(setup_script_path),
            systemd_scope_properties=self._systemd_scope_properties or None,
            hostname=config.hostname,
        )
        shell_ms = (time.monotonic() - t0) * 1000

        self._bg_handles: dict[str, str] = {}
        self._pasta_process = None
        self._start_pasta()

        if config.oom_score_adj is not None:
            self._apply_oom_score_adj(config.oom_score_adj)

        # Write PID file for stale sandbox cleanup
        pid_file = self._env_dir / ".pid"
        pid_file.write_text(str(os.getpid()))

        self.features: dict[str, object] = {
            "userns": True,
            "pidfd": self._persistent_shell._pidfd is not None,
            "seccomp": config.seccomp,
            "netns": config.net_isolate,
            "mask_paths": True,
            "cap_drop": True,
        }
        feat_str = ", ".join(
            k if v is True else f"{k}={v}"
            for k, v in self.features.items()
            if v
        )
        logger.info(
            "Sandbox ready (userns): name=%s rootfs=%s features=[%s] [shell=%.1fms]",
            name, self._rootfs, feat_str, shell_ms,
        )

    def _generate_userns_setup_script(self) -> Path:
        """Generate bash setup script for user namespace mode.

        This script runs inside the user namespace (before chroot) and:
        1. Mounts overlayfs
        2. Mounts /proc and /dev (with bind-mounted devices, no mknod)
        3. Bind-mounts volumes
        4. Execs into chroot -- after this, stdin commands go to the inner bash
        """
        merged = self._rootfs
        base = self._base_rootfs
        upper = self._upper_dir
        work = self._work_dir
        shell = self._shell
        norc = " --norc --noprofile" if "bash" in shell else ""

        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# Fix 000-perm dirs left by previous overlayfs (shell restart)",
            f"chmod -R 700 {work} 2>/dev/null || true",
            f"rm -rf {work}/work 2>/dev/null || true",
            "",
            "# Mount overlayfs",
            f"mount -t overlay overlay "
            f"-o lowerdir={base},upperdir={upper},workdir={work} {merged}",
        ]

        # Read-only rootfs: bind + remount ro BEFORE other mounts.
        # Mounts added afterwards (/proc, /dev, volumes) are on top and stay rw.
        if self._config.read_only:
            lines.append(f"mount --bind {merged} {merged}")
            lines.append(f"mount -o remount,ro,bind {merged}")

        lines.extend([
            "",
            "# Mount /proc",
            f"mount -t proc proc {merged}/proc",
            # sysfs only works in userns when network namespace is also new
            f"mount -t sysfs sysfs {merged}/sys 2>/dev/null || true"
            if self._config.net_isolate else
            "# /sys: skipped (requires net_isolate=True in userns)",
            "",
            "# Setup /dev (bind mount from host -- mknod not available in userns)",
            f"mount -t tmpfs -o nosuid,mode=0755 tmpfs {merged}/dev",
        ])

        for dev in ["null", "zero", "full", "random", "urandom", "tty"]:
            lines.append(f"touch {merged}/dev/{dev} 2>/dev/null || true")
            lines.append(
                f"mount --bind /dev/{dev} {merged}/dev/{dev} 2>/dev/null || true"
            )

        lines.extend([
            f"ln -sf /proc/self/fd {merged}/dev/fd 2>/dev/null || true",
            f"ln -sf /proc/self/fd/0 {merged}/dev/stdin 2>/dev/null || true",
            f"ln -sf /proc/self/fd/1 {merged}/dev/stdout 2>/dev/null || true",
            f"ln -sf /proc/self/fd/2 {merged}/dev/stderr 2>/dev/null || true",
            f"mkdir -p {merged}/dev/pts {merged}/dev/shm 2>/dev/null || true",
            "",
        ])

        # Volume mounts
        for spec in self._config.volumes:
            if not isinstance(spec, str) or ":" not in spec:
                continue
            parts = spec.split(":")
            host_path = parts[0]
            container_path = parts[1] if len(parts) > 1 else "/"
            mode = parts[2] if len(parts) > 2 else "rw"
            target = f"{merged}/{container_path.lstrip('/')}"
            lines.append(f"mkdir -p {target}")
            if mode == "cow":
                safe = container_path.replace("/", "_").strip("_")
                cow_upper = self._env_dir / f"cow_{safe}_upper"
                cow_work = self._env_dir / f"cow_{safe}_work"
                cow_upper.mkdir(parents=True, exist_ok=True)
                cow_work.mkdir(parents=True, exist_ok=True)
                lines.append(
                    f"mount -t overlay overlay "
                    f"-o lowerdir={host_path},upperdir={cow_upper},"
                    f"workdir={cow_work} {target}"
                )
            else:
                lines.append(f"mount --bind {host_path} {target}")
                if mode == "ro":
                    lines.append(f"mount -o remount,ro,bind {target}")

        # Enter chroot
        lines.extend([
            "",
            f"exec chroot {merged} {shell}{norc}",
        ])

        script_path = self._env_dir / "setup.sh"
        script_path.write_text("\n".join(lines) + "\n")
        script_path.chmod(0o755)
        return script_path

    def _write_seccomp_helper_userns(self) -> None:
        """Write seccomp helper to upper_dir (visible inside chroot via overlay)."""
        import inspect
        from agentdocker_lite import security

        src = inspect.getsource(security)
        helper = (
            "#!/usr/bin/env python3\n"
            "# Auto-generated security helper\n"
            + src
            + "\ndrop_capabilities()\n"
            + "apply_seccomp_filter()\n"
        )
        target = self._upper_dir / "tmp" / ".adl_seccomp.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(helper)
        target.chmod(0o755)

    @staticmethod
    def _check_prerequisites_userns() -> None:
        """Check user namespace prerequisites."""
        if shutil.which("unshare") is None:
            raise FileNotFoundError(
                "unshare not found. Install util-linux: apt-get install util-linux"
            )
        # Test if user namespaces actually work
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "true"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "User namespaces are not available. Possible fixes:\n"
                "  sysctl -w kernel.unprivileged_userns_clone=1\n"
                "  sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n"
                f"Error: {result.stderr.decode().strip()}"
            )

    # ------------------------------------------------------------------ #
    #  Public API -- reset / delete                                        #
    # ------------------------------------------------------------------ #

    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state.

        This is the RL fast-path: ~27ms for overlayfs, ~28ms for btrfs.
        """
        self._bg_handles.clear()
        self._stop_pasta()
        t0 = time.monotonic()

        self._persistent_shell.kill()

        if self._userns:
            # Mount namespace died with shell -- mounts auto-cleaned.
            # Clear upper/work on host filesystem.
            # The kernel's overlayfs creates work/work with 000 perms;
            # fix permissions before rmtree.
            for d in (self._upper_dir, self._work_dir):
                if d and d.exists():
                    # Overlayfs kernel creates work/work with 000 perms.
                    # Fix permissions so rmtree can delete.
                    for child in d.iterdir():
                        try:
                            child.chmod(0o700)
                        except OSError:
                            pass
                    shutil.rmtree(d)
                if d:
                    d.mkdir(parents=True)

            # Re-create working dir in upper
            if self._config.working_dir and self._config.working_dir != "/":
                wd = self._upper_dir / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

            # Re-write seccomp helper to upper
            if self._config.seccomp:
                self._write_seccomp_helper_userns()
        else:
            self._unmount_binds()
            if self._fs_backend == "btrfs":
                self._reset_btrfs()
            else:
                self._reset_overlayfs()
            self._apply_config_volumes()
            if self._config.working_dir and self._config.working_dir != "/":
                wd = self._rootfs / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

        self._persistent_shell.start()
        self._start_pasta()

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug("Environment reset (%.3fms): %s", elapsed_ms, self._env_dir)

    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        t0 = time.monotonic()

        self._stop_pasta()
        self._persistent_shell.kill()

        if not self._userns:
            self._unmount_all()
            if self._fs_backend == "btrfs" and self._btrfs_active:
                subprocess.run(
                    ["btrfs", "subvolume", "delete", str(self._rootfs)],
                    capture_output=True,
                )
                self._btrfs_active = False
            self._cleanup_cgroup()

        if self._env_dir.exists():
            # Fix 000-perm dirs left by overlayfs kernel in userns mode
            if self._userns and self._work_dir and self._work_dir.exists():
                for child in self._work_dir.iterdir():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            shutil.rmtree(self._env_dir, ignore_errors=True)

        self._unregister(self)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info("Deleted sandbox (%.1fms): %s", elapsed_ms, self._env_dir)

    # ------------------------------------------------------------------ #
    #  Auto rootfs preparation                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_base_rootfs(
        image: str,
        fs_backend: str,
        rootfs_cache_dir: Path,
    ) -> Path:
        import fcntl

        candidate = Path(image)
        if candidate.exists() and candidate.is_dir():
            return candidate

        from agentdocker_lite.rootfs import (
            prepare_btrfs_rootfs_from_docker,
            prepare_rootfs_from_docker,
        )

        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        cached_rootfs = rootfs_cache_dir / safe_name

        if cached_rootfs.exists() and cached_rootfs.is_dir():
            logger.info("Using cached rootfs for %s: %s", image, cached_rootfs)
            if fs_backend == "btrfs":
                RootfulSandbox._verify_btrfs_subvolume(cached_rootfs)
            return cached_rootfs

        lock_path = rootfs_cache_dir / f".{safe_name}.lock"
        rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if cached_rootfs.exists() and cached_rootfs.is_dir():
                    logger.info("Rootfs prepared by another worker: %s", cached_rootfs)
                    if fs_backend == "btrfs":
                        RootfulSandbox._verify_btrfs_subvolume(cached_rootfs)
                    return cached_rootfs

                t0 = time.monotonic()
                logger.info(
                    "Auto-preparing rootfs from Docker image %s -> %s (fs=%s)",
                    image,
                    cached_rootfs,
                    fs_backend,
                )

                if fs_backend == "btrfs":
                    prepare_btrfs_rootfs_from_docker(image, cached_rootfs)
                else:
                    prepare_rootfs_from_docker(image, cached_rootfs)

                elapsed_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "Auto-prepared rootfs (%.1fms): %s -> %s",
                    elapsed_ms,
                    image,
                    cached_rootfs,
                )
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)

        return cached_rootfs

    # ------------------------------------------------------------------ #
    #  Prerequisites                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_prerequisites(fs_backend: str = "overlayfs"):
        if os.geteuid() != 0:
            raise PermissionError(
                "Sandbox requires root for mount / cgroup operations. "
                "Run as root or with CAP_SYS_ADMIN."
            )
        if shutil.which("unshare") is None:
            raise FileNotFoundError(
                "unshare not found. Install util-linux: apt-get install util-linux"
            )
        if fs_backend == "overlayfs":
            result = subprocess.run(
                ["grep", "-q", "overlay", "/proc/filesystems"],
                capture_output=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    "Kernel does not support overlayfs. Load it: modprobe overlay"
                )
        elif fs_backend == "btrfs":
            if shutil.which("btrfs") is None:
                raise FileNotFoundError(
                    "btrfs-progs not found. Install: apt-get install btrfs-progs"
                )

    # ------------------------------------------------------------------ #
    #  Filesystem -- seccomp helper                                        #
    # ------------------------------------------------------------------ #

    def _write_seccomp_helper(self) -> None:
        """Write a self-contained seccomp helper script into the rootfs.

        Called from the init_script inside the chroot (after mounts are done).
        Uses the security module's apply_seccomp_filter via a copy of the source.

        Also checks whether any python interpreter exists in the rootfs and
        logs a warning if none is found (seccomp will be silently skipped at
        runtime in that case).
        """
        import inspect
        from agentdocker_lite import security

        src = inspect.getsource(security)
        helper = (
            "#!/usr/bin/env python3\n"
            "# Auto-generated security helper — applied inside sandbox chroot\n"
            + src
            + "\ndrop_capabilities()\n"
            + "apply_seccomp_filter()\n"
        )
        target = self._rootfs / "tmp" / ".adl_seccomp.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(helper)
        target.chmod(0o755)

        # Check if any python interpreter exists in rootfs
        python_candidates = [
            "python3", "python3.13", "python3.12", "python3.11", "python3.10", "python",
        ]
        found = False
        for py in python_candidates:
            for bin_dir in ("usr/bin", "usr/local/bin", "bin"):
                if (self._rootfs / bin_dir / py).exists():
                    found = True
                    break
            if found:
                break
        if not found:
            logger.warning(
                "No python interpreter found in rootfs %s — seccomp filter "
                "will NOT be applied inside the sandbox. Install python3 in "
                "the Docker image to enable seccomp hardening.",
                self._rootfs,
            )

    def _write_dns(self, dns_servers: list[str]) -> None:
        """Write custom /etc/resolv.conf into the sandbox rootfs."""
        resolv = self._host_path_write("/etc/resolv.conf")
        resolv.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(f"nameserver {s}\n" for s in dns_servers)
        resolv.write_text(content)

    # ------------------------------------------------------------------ #
    #  Filesystem -- overlayfs                                             #
    # ------------------------------------------------------------------ #

    def _setup_overlay(self):
        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                "mount",
                "-t",
                "overlay",
                "overlay",
                "-o",
                f"lowerdir={self._base_rootfs},"
                f"upperdir={self._upper_dir},"
                f"workdir={self._work_dir}",
                str(self._rootfs),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to mount overlayfs: {result.stderr.strip()}")
        self._overlay_mounted = True
        logger.debug("Mounted overlayfs at %s", self._rootfs)

    # ------------------------------------------------------------------ #
    #  Filesystem -- btrfs                                                 #
    # ------------------------------------------------------------------ #

    def _setup_btrfs(self):
        self._verify_btrfs_subvolume(self._base_rootfs)
        self._env_dir.mkdir(parents=True, exist_ok=True)

        if self._rootfs.exists():
            check = subprocess.run(
                ["btrfs", "subvolume", "show", str(self._rootfs)],
                capture_output=True,
                text=True,
            )
            if check.returncode == 0:
                subprocess.run(
                    ["btrfs", "subvolume", "delete", str(self._rootfs)],
                    capture_output=True,
                )
            else:
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            [
                "btrfs",
                "subvolume",
                "snapshot",
                str(self._base_rootfs),
                str(self._rootfs),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"btrfs snapshot failed: {result.stderr.strip()}. "
                f"Ensure {self._base_rootfs} is a btrfs subvolume and "
                f"{self._env_dir} is on the same btrfs filesystem."
            )
        self._btrfs_active = True
        logger.debug(
            "Created btrfs snapshot: %s -> %s", self._base_rootfs, self._rootfs
        )

    @staticmethod
    def _verify_btrfs_subvolume(path: Path):
        result = subprocess.run(
            ["btrfs", "subvolume", "show", str(path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(
                f"Not a btrfs subvolume: {path}. "
                f"Create one via: btrfs subvolume create {path}"
            )

    # ------------------------------------------------------------------ #
    #  Volume management                                                   #
    # ------------------------------------------------------------------ #

    def _apply_config_volumes(self):
        for spec in self._config.volumes:
            if not isinstance(spec, str) or ":" not in spec:
                continue
            parts = spec.split(":")
            host_path = parts[0]
            container_path = parts[1] if len(parts) > 1 else "/"
            mode = parts[2] if len(parts) > 2 else "rw"
            if mode == "cow":
                self._overlay_mount(host_path, container_path)
            else:
                self._bind_mount(host_path, container_path, read_only=(mode == "ro"))

    def _bind_mount(
        self, host_path: str, container_path: str, read_only: bool = False
    ):
        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["mount", "--bind", host_path, str(target)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Failed to bind mount %s -> %s: %s",
                host_path,
                container_path,
                result.stderr.strip(),
            )
            return

        self._bind_mounts.append(target)

        if read_only:
            subprocess.run(
                ["mount", "-o", "remount,ro,bind", str(target)],
                capture_output=True,
            )
        logger.debug(
            "Bind mounted %s -> %s (%s)",
            host_path,
            container_path,
            "ro" if read_only else "rw",
        )

    def _overlay_mount(self, host_path: str, container_path: str):
        """Mount a host directory as copy-on-write via overlayfs.

        Writes inside the sandbox go to a temporary upperdir; the host
        directory is never modified.  Mode ``"cow"`` in volume specs.
        """
        import tempfile

        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        work_base = tempfile.mkdtemp(prefix="adl_cow_")
        upper = Path(work_base) / "upper"
        work = Path(work_base) / "work"
        upper.mkdir()
        work.mkdir()

        result = subprocess.run(
            [
                "mount", "-t", "overlay", "overlay",
                "-o", f"lowerdir={host_path},upperdir={upper},workdir={work}",
                str(target),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Failed to overlay mount %s -> %s: %s",
                host_path, container_path, result.stderr.strip(),
            )
            return

        # Track for cleanup (unmount overlay, then remove tmpdir)
        self._bind_mounts.append(target)
        self._cow_tmpdirs.append(work_base)
        logger.debug(
            "Overlay mounted %s -> %s (cow, upper=%s)", host_path, container_path, upper,
        )

    def _unmount_binds(self):
        import shutil as _shutil

        for mount_point in reversed(self._bind_mounts):
            subprocess.run(["umount", "-l", str(mount_point)], capture_output=True)
        self._bind_mounts.clear()
        for tmpdir in self._cow_tmpdirs:
            _shutil.rmtree(tmpdir, ignore_errors=True)
        self._cow_tmpdirs = []

    def _unmount_all(self):
        self._unmount_binds()
        if self._fs_backend == "overlayfs" and self._overlay_mounted:
            subprocess.run(["umount", "-l", str(self._rootfs)], capture_output=True)
            self._overlay_mounted = False

    # ------------------------------------------------------------------ #
    #  cgroup v2 resource limits                                           #
    # ------------------------------------------------------------------ #

    def _setup_cgroup(self):
        if not any(self._cgroup_limits.values()):
            return

        if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            logger.warning(
                "cgroup v2 not available -- resource limits will not be enforced."
            )
            return

        cgroup_name = self._env_dir.name
        self._cgroup_path = Path(f"/sys/fs/cgroup/agentdocker_lite/{cgroup_name}")
        try:
            self._cgroup_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Failed to create cgroup %s: %s", self._cgroup_path, e)
            self._cgroup_path = None
            return

        parent = self._cgroup_path.parent
        try:
            subtree_ctl = parent / "cgroup.subtree_control"
            if subtree_ctl.exists():
                for key, ctrl in [
                    ("cpu_max", "cpu"),
                    ("memory_max", "memory"),
                    ("pids_max", "pids"),
                    ("io_max", "io"),
                    ("cpuset_cpus", "cpuset"),
                ]:
                    if self._cgroup_limits.get(key):
                        try:
                            subtree_ctl.write_text(f"+{ctrl}")
                        except OSError:
                            logger.debug(
                                "Could not enable cgroup controller %s", ctrl
                            )
        except OSError:
            pass

        limit_files = {
            "cpu_max": "cpu.max",
            "memory_max": "memory.max",
            "pids_max": "pids.max",
            "io_max": "io.max",
            "cpuset_cpus": "cpuset.cpus",
        }
        for key, filename in limit_files.items():
            value = self._cgroup_limits.get(key)
            if value:
                try:
                    (self._cgroup_path / filename).write_text(str(value))
                    logger.debug("cgroup %s = %s", filename, value)
                except OSError as e:
                    logger.warning("Failed to set cgroup %s: %s", filename, e)

    def _cleanup_cgroup(self):
        if not self._cgroup_path or not self._cgroup_path.exists():
            return
        try:
            procs_file = self._cgroup_path / "cgroup.procs"
            if procs_file.exists():
                for pid in procs_file.read_text().strip().split():
                    try:
                        os.kill(int(pid), 9)
                    except (ProcessLookupError, ValueError):
                        pass
            kill_file = self._cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1")
                except OSError:
                    pass
            self._cgroup_path.rmdir()
        except OSError as e:
            logger.debug("cgroup cleanup (non-fatal): %s", e)

    # ------------------------------------------------------------------ #
    #  Reset helpers                                                       #
    # ------------------------------------------------------------------ #

    def _reset_overlayfs(self):
        if self._overlay_mounted:
            subprocess.run(["umount", "-l", str(self._rootfs)], capture_output=True)
            self._overlay_mounted = False

        if self._upper_dir and self._upper_dir.exists():
            shutil.rmtree(self._upper_dir)
        if self._upper_dir:
            self._upper_dir.mkdir(parents=True)

        if self._work_dir and self._work_dir.exists():
            shutil.rmtree(self._work_dir)
        if self._work_dir:
            self._work_dir.mkdir(parents=True)

        self._setup_overlay()

    def _reset_btrfs(self):
        result = subprocess.run(
            ["btrfs", "subvolume", "delete", str(self._rootfs)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "btrfs subvolume delete failed (proceeding): %s",
                result.stderr.strip(),
            )
            if self._rootfs.exists():
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            [
                "btrfs",
                "subvolume",
                "snapshot",
                str(self._base_rootfs),
                str(self._rootfs),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"btrfs snapshot failed on reset: {result.stderr.strip()}"
            )
        self._btrfs_active = True

    # ------------------------------------------------------------------ #
    #  OOM score                                                            #
    # ------------------------------------------------------------------ #

    def _apply_oom_score_adj(self, score: int) -> None:
        pid = self._persistent_shell._process.pid
        try:
            Path(f"/proc/{pid}/oom_score_adj").write_text(str(score))
        except OSError as e:
            logger.warning("Failed to set oom_score_adj=%d: %s", score, e)

    # ------------------------------------------------------------------ #
    #  Pasta networking                                                    #
    # ------------------------------------------------------------------ #

    def _start_pasta(self) -> None:
        """Start pasta for NAT'd networking with port mapping.

        Attaches to the sandbox's network namespace.  Requires
        ``net_isolate=True`` (separate network namespace) and the
        ``pasta`` binary from the ``passt`` package.
        """
        port_map = self._config.port_map
        if not port_map:
            return
        if not self._config.net_isolate:
            logger.warning("port_map requires net_isolate=True; ignoring port_map")
            return

        # Find pasta: vendored binary first, then system PATH
        vendored = Path(__file__).parent.parent / "_vendor" / "pasta"
        if vendored.exists() and vendored.is_file():
            pasta_bin = str(vendored)
        elif shutil.which("pasta"):
            pasta_bin = "pasta"
        else:
            raise FileNotFoundError(
                "port_map requires 'pasta' (from the passt package). "
                "Install: pacman -S passt / apt install passt"
            )

        shell_pid = self._persistent_shell._process.pid
        cmd: list[str] = [pasta_bin, "--config-net", "-q"]
        for mapping in port_map:
            # "8080:80" → -t 8080:80 (TCP), -u for UDP
            cmd.extend(["-t", mapping])
        cmd.append(str(shell_pid))

        self._pasta_process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.debug("pasta started: pid=%d, ports=%s", self._pasta_process.pid, port_map)

    def _stop_pasta(self) -> None:
        """Stop the pasta networking process."""
        proc = getattr(self, "_pasta_process", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
                proc.wait(timeout=2)
        self._pasta_process = None

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _detect_shell(self) -> str:
        if self._host_path("/bin/bash").exists():
            return "/bin/bash"
        return "/bin/sh"

    # ------------------------------------------------------------------ #
    #  Userns file I/O: manual overlay (upper dir + base rootfs)           #
    # ------------------------------------------------------------------ #

    def _host_path(self, container_path: str) -> Path:
        """Resolve container_path for reads.

        In userns mode, check upper dir (modified files) first, then
        fall back to base rootfs (original image files).
        """
        if self._userns:
            stripped = container_path.lstrip("/")
            upper = self._upper_dir / stripped
            if upper.exists():
                return upper
            base = self._base_rootfs / stripped
            if base.exists():
                return base
            # Return upper as default (caller checks existence)
            return upper
        return self._rootfs / container_path.lstrip("/")

    def _host_path_write(self, container_path: str) -> Path:
        """Resolve container_path for writes.

        In userns mode, always write to the upper dir so the overlay
        picks up the change.
        """
        if self._userns:
            return self._upper_dir / container_path.lstrip("/")
        return self._rootfs / container_path.lstrip("/")
