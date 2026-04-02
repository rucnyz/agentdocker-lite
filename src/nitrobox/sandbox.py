"""Unified sandbox implementation.

Auto-selects rootful or rootless mode based on effective UID.
Rootful mode uses real root for mount/cgroup; rootless mode uses
user namespaces (kernel >= 5.11).
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict

from nitrobox._errors import (
    SandboxConfigError,
    SandboxInitError,
    SandboxKernelError,
    SandboxTimeoutError,
)
from nitrobox.config import SandboxConfig, cap_names_to_numbers

if TYPE_CHECKING:
    from nitrobox._shell import _PersistentShell

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Types                                                                   #
# ====================================================================== #


class SandboxFeatures(TypedDict, total=False):
    """Feature flags reported after sandbox creation."""

    userns: bool
    layer_cache: bool
    whiteout: str
    pidfd: bool
    cgroup_v2: bool
    seccomp: bool
    landlock: bool
    netns: bool
    devices: bool
    timens: bool
    cpuset_cpus: str | None
    oom_score_adj: int | None
    mask_paths: bool
    cap_drop: bool


# ====================================================================== #
#  Image defaults                                                          #
# ====================================================================== #


def _apply_image_defaults(config: SandboxConfig) -> None:
    """Fill unset config fields from the OCI image config.

    User-specified values always take precedence.  ``working_dir``,
    ``environment``, and ``entrypoint`` are backfilled from the image.
    """
    if not config.image:
        return
    from nitrobox.rootfs import get_image_config

    img_cfg = get_image_config(config.image)
    if not img_cfg:
        return

    # working_dir: backfill only if user left the default "/"
    img_wd = img_cfg.get("working_dir")
    if img_wd and config.working_dir == "/":
        config.working_dir = img_wd
        logger.debug("Applied image WORKDIR: %s", img_wd)

    # environment: image env as base, user env overrides
    img_env = img_cfg.get("env") or {}
    if img_env:
        merged = dict(img_env)
        merged.update(config.environment)  # user wins
        config.environment = merged
        logger.debug("Merged %d image ENV vars", len(img_env))

    # entrypoint: backfill only if user didn't set one explicitly
    img_ep = img_cfg.get("entrypoint")
    if img_ep and config.entrypoint is None:
        config.entrypoint = img_ep
        logger.debug("Applied image ENTRYPOINT: %s", img_ep)


# ====================================================================== #
#  Sandbox                                                                 #
# ====================================================================== #


class Sandbox:
    """Linux namespace sandbox with pluggable CoW filesystem backend.

    Each instance manages one isolated environment with:
    - ``unshare --pid --mount --fork`` for PID and mount namespace isolation
    - Persistent shell (chroot) for low-latency command execution
    - Copy-on-write filesystem (overlayfs or btrfs) for instant reset
    - Bind mounts for shared volumes
    - cgroup v2 for optional CPU / memory / PID limits

    Auto-selects rootful or rootless mode based on ``os.geteuid()``.

    Example::

        from nitrobox import Sandbox, SandboxConfig

        config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
        with Sandbox(config, name="worker-0") as sb:
            output, ec = sb.run("echo hello world")
            sb.reset()        # instant filesystem reset
    """

    SUPPORTED_FS_BACKENDS = ("overlayfs", "btrfs")

    # -- global registry for atexit cleanup -------------------------------- #
    _live_instances: list[Sandbox] = []
    _atexit_registered: bool = False

    # -- rootless caches (class-level) ------------------------------------- #
    _prereq_checked = False
    _cached_subuid_range: tuple[int, int, int] | None = None
    _subuid_detected = False

    def __init__(self, config: SandboxConfig, name: str = "default"):
        self._config = config
        self._name = name
        self._bg_handles: dict[str, str] = {}
        self._subuid_range: tuple[int, int, int] | None = None

        _apply_image_defaults(config)

        if os.geteuid() == 0:
            self._userns = False
            try:
                self._init_rootful(config, name)
            except Exception:
                self._cleanup_on_init_failure()
                raise
        else:
            self._userns = True
            try:
                self._init_userns(config, name)
            except Exception:
                self._cleanup_on_init_failure()
                raise

        self._register(self)

    def _cleanup_on_init_failure(self) -> None:
        env_dir = getattr(self, "_env_dir", None)
        if env_dir and env_dir.exists():
            rootfs = getattr(self, "_rootfs", None)
            if rootfs and not self._userns:
                from nitrobox._core import py_umount_lazy
                try:
                    py_umount_lazy(str(rootfs))
                except OSError:
                    pass
            for child in env_dir.rglob("*"):
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
            shutil.rmtree(env_dir, ignore_errors=True)

    # -- context manager --------------------------------------------------- #

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.delete()

    # ================================================================== #
    #  Public API                                                          #
    # ================================================================== #

    def run(
        self, command: str | list[str], timeout: int | None = None
    ) -> tuple[str, int]:
        """Run a command inside the sandbox.

        Args:
            command: Shell command string or list of arguments.
            timeout: Timeout in seconds (None = no timeout).

        Returns:
            ``(stdout_output, exit_code)`` tuple.
        """
        t0 = time.monotonic()
        if isinstance(command, list):
            cmd_str = shlex.join(command)
        else:
            cmd_str = command

        output, exit_code = self._persistent_shell.execute(cmd_str, timeout=timeout)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug("cmd (%.1fms exit=%d): %.200s", elapsed_ms, exit_code, cmd_str)
        return output, exit_code

    async def arun(
        self, command: str | list[str], timeout: int | None = None
    ) -> tuple[str, int]:
        """Async version of :meth:`run`."""
        import asyncio
        return await asyncio.to_thread(self.run, command, timeout)

    async def areset(self) -> None:
        """Async version of :meth:`reset`."""
        import asyncio
        await asyncio.to_thread(self.reset)

    async def adelete(self) -> None:
        """Async version of :meth:`delete`."""
        import asyncio
        await asyncio.to_thread(self.delete)

    def write_stdin(self, data: str | bytes) -> None:
        """Write raw data to the sandbox shell's stdin (PTY mode only).

        Use this to send input to interactive programs.  Requires
        ``SandboxConfig(tty=True)``.
        """
        self._persistent_shell.write_stdin(data)

    # -- background processes ---------------------------------------------- #

    def run_background(self, command: str | list[str]) -> str:
        """Start a command in the background inside the sandbox.

        Returns a handle string to use with :meth:`check_background` and
        :meth:`stop_background`.
        """
        if isinstance(command, list):
            command = shlex.join(command)
        handle = uuid.uuid4().hex[:8]
        out_file = f"/tmp/.bg_{handle}.out"
        pid_file = f"/tmp/.bg_{handle}.pid"
        shell = os.path.basename(self._shell)
        self.run(
            f"nohup {shell} -c {shlex.quote(command)} > {out_file} 2>&1 & echo $! > {pid_file}"
        )
        pid_str, _ = self.run(f"cat {pid_file} 2>/dev/null")
        self._bg_handles[handle] = pid_str.strip()
        return handle

    def check_background(self, handle: str) -> tuple[str, bool]:
        """Check a background process started with :meth:`run_background`.

        Returns ``(output_so_far, is_running)`` tuple.
        """
        out_file = f"/tmp/.bg_{handle}.out"
        pid = self._bg_handles.get(handle, "")
        output, _ = self.run(f"cat {out_file} 2>/dev/null")
        if pid:
            _, ec = self.run(f"kill -0 {pid} 2>/dev/null")
            running = ec == 0
        else:
            running = False
        return output, running

    def list_background(self) -> dict[str, dict[str, Any]]:
        """List all background processes and their status."""
        result: dict[str, dict[str, Any]] = {}
        for handle, pid in self._bg_handles.items():
            if pid:
                _, ec = self.run(f"kill -0 {pid} 2>/dev/null")
                running = ec == 0
            else:
                running = False
            result[handle] = {"pid": pid, "running": running}
        return result

    def stop_background(self, handle: str) -> str:
        """Stop a background process and return its final output."""
        out_file = f"/tmp/.bg_{handle}.out"
        pid_file = f"/tmp/.bg_{handle}.pid"
        pid = self._bg_handles.pop(handle, "")
        if pid:
            self.run(f"kill {pid} 2>/dev/null; kill -9 {pid} 2>/dev/null")
        output, _ = self.run(f"cat {out_file} 2>/dev/null")
        self.run(f"rm -f {out_file} {pid_file}")
        return output

    # -- interactive processes --------------------------------------------- #

    def popen(
        self,
        command: str | list[str],
        **kwargs: Any,
    ) -> subprocess.Popen[Any]:
        """Start an interactive process inside the sandbox with stdio pipes.

        Returns a :class:`subprocess.Popen` object with direct
        ``stdin``/``stdout``/``stderr`` pipes for bidirectional communication.
        """
        if isinstance(command, list):
            cmd_args = command
        else:
            cmd_args = ["bash", "-c", command]

        shell_pid = self._persistent_shell.pid

        if self._userns:
            from nitrobox._core import py_userns_preexec

            _shell_pid = shell_pid
            _rootfs = str(self._rootfs)
            _wd = self._config.working_dir or "/"

            def _userns_preexec() -> None:
                py_userns_preexec(_shell_pid, _rootfs, _wd)

            defaults: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)
            proc = subprocess.Popen(cmd_args, preexec_fn=_userns_preexec, **defaults)
        else:
            from nitrobox._core import py_nsenter_preexec

            _shell_pid = shell_pid

            def _rootful_preexec() -> None:
                py_nsenter_preexec(_shell_pid)

            defaults: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)
            proc = subprocess.Popen(
                cmd_args, preexec_fn=_rootful_preexec, **defaults
            )

        logger.debug("popen pid=%d in sandbox: %s", proc.pid, cmd_args)
        return proc

    # -- file operations --------------------------------------------------- #

    def copy_to(self, local_path: str, container_path: str) -> None:
        """Copy a file from host into the sandbox."""
        host_dst = self._host_path_write(container_path)
        host_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, str(host_dst))

    def copy_from(self, container_path: str, local_path: str) -> None:
        """Copy a file from the sandbox to host."""
        host_src = self._host_path(container_path)
        if not host_src.exists():
            raise FileNotFoundError(
                f"File {container_path} does not exist in the sandbox."
            )
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        shutil.copy2(str(host_src), local_path)

    def read_file(self, container_path: str) -> str:
        """Read file content from the sandbox."""
        host_path = self._host_path(container_path)
        if not host_path.exists():
            raise FileNotFoundError(
                f"File {container_path} does not exist in the sandbox."
            )
        return host_path.read_text(encoding="latin-1")

    def write_file(self, container_path: str, content: str | bytes) -> None:
        """Write content to a file inside the sandbox."""
        host_path = self._host_path_write(container_path)
        host_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            host_path.write_bytes(content)
        else:
            host_path.write_text(content)

    @property
    def rootfs(self) -> Path:
        """Path to the sandbox's rootfs on the host."""
        return self._rootfs

    # -- cgroup pressure (PSI) --------------------------------------------- #

    def pressure(self) -> dict[str, dict[str, float]]:
        """Read cgroup v2 Pressure Stall Information for this sandbox."""
        cg = getattr(self, "_cgroup_path", None)
        if not cg:
            return {}
        result: dict[str, dict[str, float]] = {}
        for resource in ("cpu", "memory", "io"):
            psi_file = cg / f"{resource}.pressure"
            if not psi_file.exists():
                continue
            try:
                line = psi_file.read_text().split("\n")[0]
                vals: dict[str, float] = {}
                for part in line.split():
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k.startswith("avg"):
                            vals[k] = float(v)
                if vals:
                    result[resource] = vals
            except (OSError, ValueError):
                continue
        return result

    # -- memory management ------------------------------------------------- #

    def reclaim_memory(self) -> bool:
        """Hint the kernel to reclaim this sandbox's memory via MADV_COLD."""
        shell = self._persistent_shell
        pidfd = getattr(shell, "_pidfd", None)
        if pidfd is None:
            return False

        if not getattr(Sandbox, "_swap_warned", False):
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("SwapTotal:"):
                            if int(line.split()[1]) == 0:
                                logger.warning(
                                    "reclaim_memory: no swap available, "
                                    "hint will have no effect."
                                )
                            Sandbox._swap_warned = True  # type: ignore[attr-defined]
                            break
            except (OSError, ValueError):
                pass

        from nitrobox._core import py_process_madvise_cold
        return py_process_madvise_cold(pidfd)

    # -- Docker image export ----------------------------------------------- #

    def save_as_image(self, image_name: str) -> None:
        """Save current sandbox state as a Docker image."""
        rootfs = self._rootfs
        if not rootfs or not rootfs.exists():
            raise SandboxInitError("No rootfs available to export")

        tar_proc = subprocess.Popen(
            ["tar", "-C", str(rootfs), "-c", "."],
            stdout=subprocess.PIPE,
        )
        import_proc = subprocess.Popen(
            ["docker", "import", "--change", "CMD /bin/sh", "-", image_name],
            stdin=tar_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if tar_proc.stdout is not None:
            tar_proc.stdout.close()
        _, stderr_bytes = import_proc.communicate()
        stderr = (stderr_bytes or b"").decode(errors="replace")

        if import_proc.returncode != 0:
            raise SandboxInitError(f"docker import failed: {stderr.strip()}")
        logger.info("Saved sandbox as Docker image: %s", image_name)

    # ================================================================== #
    #  Lifecycle: reset / delete                                           #
    # ================================================================== #

    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state."""
        self._bg_handles.clear()
        self._stop_pasta_rootful()
        t0 = time.monotonic()

        self._fixup_userns_ownership()
        self._persistent_shell.kill()

        # Clean up Rust-side pasta netns bind mount before directory operations.
        netns_file = self._env_dir / ".netns"
        if netns_file.exists():
            from nitrobox._core import py_umount_lazy
            try:
                py_umount_lazy(str(netns_file))
            except OSError:
                pass

        if self._userns:
            # Mount namespace died with shell -- mounts auto-cleaned.
            self._cleanup_dead_dirs()
            for d in (self._upper_dir, self._work_dir):
                if d and d.exists():
                    dead = d.with_name(f"{d.name}.dead.{time.monotonic_ns()}")
                    try:
                        d.rename(dead)
                    except OSError:
                        for child in d.iterdir():
                            try:
                                child.chmod(0o700)
                            except OSError:
                                pass
                        shutil.rmtree(d, ignore_errors=True)
                if d:
                    d.mkdir(parents=True, exist_ok=True)

            # Clear cow volume upper dirs
            for spec in self._config.volumes:
                if isinstance(spec, str) and spec.endswith(":cow"):
                    parts = spec.split(":")
                    container_path = parts[1] if len(parts) > 2 else "/"
                    safe = container_path.replace("/", "_").strip("_")
                    for suffix in ("upper", "work"):
                        cow_dir = self._env_dir / f"cow_{safe}_{suffix}"
                        if cow_dir.exists():
                            shutil.rmtree(cow_dir, ignore_errors=True)
                        cow_dir.mkdir(parents=True, exist_ok=True)

            # Re-create working dir in upper
            if self._config.working_dir and self._config.working_dir != "/":
                assert self._upper_dir is not None
                wd = self._upper_dir / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

            if self._config.dns:
                self._write_dns(self._config.dns)
        else:
            self._unmount_binds()
            if self._fs_backend == "btrfs":
                self._reset_btrfs()
            else:
                self._reset_overlayfs()
            # NOTE: volumes are NOT re-applied here on the Python side.
            # In rootful mode, volumes are mounted by Rust inside the new
            # mount namespace when _persistent_shell.start() is called below.
            if self._config.working_dir and self._config.working_dir != "/":
                wd = self._rootfs / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

            if self._config.dns:
                self._write_dns(self._config.dns)

        self._persistent_shell.start()

        # Re-attach pasta after shell restart (rootful only — new shell = new netns)
        if not self._userns and self._config.port_map:
            self._start_pasta_rootful(self._config)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug("Environment reset (%.3fms): %s", elapsed_ms, self._env_dir)

    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        t0 = time.monotonic()
        self._stop_pasta_rootful()

        for handle in list(self._bg_handles):
            try:
                self.stop_background(handle)
            except Exception:
                pass

        self._fixup_userns_permissions()
        self._fixup_userns_ownership()
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

        # Clean up Rust-side pasta netns bind mount (userns mode).
        netns_file = self._env_dir / ".netns"
        if netns_file.exists():
            from nitrobox._core import py_umount_lazy
            try:
                py_umount_lazy(str(netns_file))
            except OSError:
                pass

        if self._env_dir.exists():
            if self._userns:
                for work in self._env_dir.glob("*work*"):
                    if work.is_dir():
                        for child in work.rglob("*"):
                            try:
                                child.chmod(0o700)
                            except OSError:
                                pass
            shutil.rmtree(self._env_dir, ignore_errors=True)

        self._unregister(self)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info("Deleted sandbox (%.1fms): %s", elapsed_ms, self._env_dir)

    # ================================================================== #
    #  Snapshots                                                           #
    # ================================================================== #

    def fs_snapshot(self, path: str) -> None:
        """Save current filesystem state to a directory."""
        upper = getattr(self, "_upper_dir", None)
        if not upper or not upper.exists():
            raise SandboxConfigError("fs_snapshot() requires overlayfs")
        shutil.copytree(str(upper), path)

    def fs_restore(self, path: str) -> None:
        """Restore filesystem state from a snapshot."""
        upper = getattr(self, "_upper_dir", None)
        if not upper:
            raise SandboxConfigError("restore() requires overlayfs")
        if not Path(path).exists():
            raise FileNotFoundError(f"Snapshot not found: {path}")

        self._persistent_shell.kill()

        rootfs = getattr(self, "_rootfs", None)
        base_rootfs = getattr(self, "_base_rootfs", None)
        if not self._userns and rootfs:
            from nitrobox._core import py_umount
            try:
                py_umount(str(rootfs))
            except OSError:
                pass

        if self._userns:
            for child in upper.iterdir():
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
        if upper.exists():
            shutil.rmtree(upper)
        shutil.copytree(path, str(upper))

        work = getattr(self, "_work_dir", None)
        if work and work.exists():
            if self._userns:
                for child in work.iterdir():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            shutil.rmtree(work)
            work.mkdir(parents=True)

        lowerdir_spec = getattr(self, "_lowerdir_spec", None) or base_rootfs
        if not self._userns and rootfs and lowerdir_spec and work:
            from nitrobox._core import py_mount_overlay
            py_mount_overlay(
                str(lowerdir_spec), str(upper), str(work), str(rootfs),
            )

        self._persistent_shell.start()

    _snapshot_counter: int = 0

    def snapshot(self, tag: str | int | None = None) -> str | int:
        """Save current filesystem state, returning a snapshot ID or tag."""
        snap_dir = self._env_dir / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)

        if tag is None:
            tag = self._snapshot_counter
            self._snapshot_counter += 1

        self.fs_snapshot(str(snap_dir / str(tag)))
        return tag

    def restore(self, tag: str | int | None = None) -> None:
        """Restore filesystem to a previously saved snapshot."""
        if tag is None:
            snaps = self.list_snapshots()
            if not snaps:
                raise FileNotFoundError("No snapshots available")
            tag = snaps[-1]

        snap_path = self._env_dir / "snapshots" / str(tag)
        if not snap_path.exists():
            raise FileNotFoundError(
                f"Snapshot {tag!r} not found. Available: {self.list_snapshots()}"
            )
        self.fs_restore(str(snap_path))
        if isinstance(tag, int):
            self._snapshot_counter = tag + 1

    def list_snapshots(self) -> list[str | int]:
        """Return sorted list of available snapshot tags/IDs."""
        snap_dir = self._env_dir / "snapshots"
        if not snap_dir.exists():
            return []
        result: list[str | int] = []
        for p in sorted(snap_dir.iterdir()):
            if p.is_dir():
                result.append(int(p.name) if p.name.isdigit() else p.name)
        return result

    def delete_snapshot(self, tag: str | int) -> None:
        """Delete a specific snapshot to free disk space."""
        snap_path = self._env_dir / "snapshots" / str(tag)
        if snap_path.exists():
            shutil.rmtree(snap_path)

    async def asnapshot(self, tag: str | int | None = None) -> str | int:
        """Async version of :meth:`snapshot`."""
        import asyncio
        return await asyncio.to_thread(self.snapshot, tag)

    async def arestore(self, tag: str | int | None = None) -> None:
        """Async version of :meth:`restore`."""
        import asyncio
        await asyncio.to_thread(self.restore, tag)

    # ================================================================== #
    #  Class-level registry                                                #
    # ================================================================== #

    @classmethod
    def _register(cls, instance: Sandbox) -> None:
        cls._live_instances.append(instance)
        if not cls._atexit_registered:
            import atexit
            atexit.register(cls._atexit_cleanup)
            cls._atexit_registered = True

    @classmethod
    def _unregister(cls, instance: Sandbox) -> None:
        try:
            cls._live_instances.remove(instance)
        except ValueError:
            pass

    @classmethod
    def _atexit_cleanup(cls) -> None:
        for sb in list(cls._live_instances):
            try:
                sb.delete()
            except Exception:
                pass
        cls._live_instances.clear()

    @staticmethod
    def cleanup_stale(env_base_dir: str = "") -> int:
        """Clean up orphaned sandboxes left by crashed processes.

        Scans *env_base_dir* for sandbox directories, checks if the owner
        process is still alive, and cleans up dead ones.

        Returns:
            Number of cleaned-up sandboxes.
        """
        if not env_base_dir:
            env_base_dir = f"/tmp/nitrobox_{os.getuid()}"
        base = Path(env_base_dir)
        if not base.exists():
            return 0

        cleaned = 0
        for entry in base.iterdir():
            if not entry.is_dir():
                continue

            pid_file = entry / ".pid"
            if not pid_file.exists():
                if (entry / "work").exists() or (entry / "upper").exists():
                    logger.info("Cleaning up orphaned sandbox dir %s (no .pid)", entry.name)
                    for child in entry.rglob("*"):
                        try:
                            child.chmod(0o700)
                        except OSError:
                            pass
                    shutil.rmtree(entry, ignore_errors=True)
                    cleaned += 1
                continue

            try:
                pid = int(pid_file.read_text().strip())
            except (ValueError, OSError):
                continue

            alive = False
            try:
                with open(f"/proc/{pid}/status") as _f:
                    for _line in _f:
                        if _line.startswith("State:"):
                            alive = "Z" not in _line and "X" not in _line
                            break
                    else:
                        alive = True
            except (FileNotFoundError, PermissionError):
                alive = False

            if alive:
                continue

            logger.info("Cleaning up stale sandbox %s (pid %d dead)", entry.name, pid)

            rootfs_dir = entry / "rootfs"
            if rootfs_dir.exists():
                from nitrobox._core import py_umount_recursive_lazy
                try:
                    py_umount_recursive_lazy(str(rootfs_dir))
                except OSError:
                    pass

            netns_path = Path(f"/run/netns/nitrobox-{entry.name}")
            if netns_path.exists():
                from nitrobox._core import py_fuser_kill, py_umount
                try:
                    py_fuser_kill(str(netns_path))
                except OSError:
                    pass
                try:
                    py_umount(str(netns_path))
                except OSError:
                    pass
                try:
                    netns_path.unlink()
                except OSError:
                    pass

            cgroup_path = Path(f"/sys/fs/cgroup/nitrobox/{entry.name}")
            if cgroup_path.exists():
                kill_file = cgroup_path / "cgroup.kill"
                if kill_file.exists():
                    try:
                        kill_file.write_text("1")
                    except OSError:
                        pass
                procs_file = cgroup_path / "cgroup.procs"
                if procs_file.exists():
                    try:
                        for p in procs_file.read_text().strip().split():
                            try:
                                os.kill(int(p), 9)
                            except (ProcessLookupError, ValueError):
                                pass
                    except OSError:
                        pass
                try:
                    cgroup_path.rmdir()
                except OSError as e:
                    logger.debug("cgroup cleanup for %s (non-fatal): %s", entry.name, e)

            for child in entry.rglob("*"):
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
            shutil.rmtree(entry, ignore_errors=True)
            cleaned += 1

        if cleaned:
            logger.info("Cleaned up %d stale sandbox(es) under %s", cleaned, env_base_dir)
        return cleaned

    # ================================================================== #
    #  Init helpers (shared between rootful / userns)                      #
    # ================================================================== #

    def _init_common_state(self, config: SandboxConfig, name: str) -> None:
        """Set up state that is identical in rootful and userns modes."""
        if not config.image:
            raise SandboxConfigError("SandboxConfig.image is required.")

        env_base = Path(config.env_base_dir)
        self._env_dir = env_base / name
        self._rootfs = self._env_dir / "rootfs"

        self._overlay_mounted = False
        self._btrfs_active = False
        self._bind_mounts: list[Path] = []
        self._cow_tmpdirs: list[str] = []
        self._cgroup_path: Path | None = None
        self._cgroup_limits = {
            "cpu_max": config.cpu_max,
            "memory_max": config.memory_max,
            "pids_max": config.pids_max,
            "io_max": config.io_max,
            "cpuset_cpus": config.cpuset_cpus,
            "cpu_shares": config.cpu_shares,
            "memory_swap": config.memory_swap,
        }

    def _build_spawn_config(
        self, config: SandboxConfig, ll_result: tuple[list[str], list[str], list[int], bool],
        **overrides: Any,
    ) -> dict[str, Any]:
        """Build SpawnConfig dict with shared defaults + per-mode overrides."""
        ll_read, ll_write, ll_ports, ll_strict = ll_result
        self._shell = self._detect_shell()
        self._cached_env = self._build_env()

        cfg: dict[str, Any] = {
            "rootfs": str(self._rootfs),
            "shell": self._shell,
            "working_dir": config.working_dir or "/",
            "env": self._cached_env,
            "rootful": not self._userns,
            "userns": self._userns,
            # Userns: when port_map is set, pasta (Rust) handles the netns.
            # Rootful: net_isolate stays True, pasta connects to the existing netns post-init.
            "net_isolate": (config.net_isolate and not config.port_map and not config.net_ns)
                if self._userns else config.net_isolate,
            "net_ns": config.net_ns,
            "shared_userns": None,
            "subuid_range": None,
            "seccomp": config.seccomp,
            "cap_add": cap_names_to_numbers(config.cap_add) if config.cap_add else [],
            "hostname": config.hostname,
            "read_only": config.read_only,
            "entrypoint": config.entrypoint or [],
            "tty": config.tty,
            "lowerdir_spec": None,
            "upper_dir": None,
            "work_dir": None,
            "volumes": [],
            "devices": config.devices or [],
            "shm_size": None,
            "tmpfs_mounts": [],
            "landlock_read_paths": ll_read,
            "landlock_write_paths": ll_write,
            "landlock_ports": ll_ports,
            "landlock_strict": ll_strict,
            "cgroup_path": str(self._cgroup_path) if self._cgroup_path else None,
            "port_map": list(config.port_map) if config.port_map else [],
            "pasta_bin": self._find_pasta_bin() if config.port_map else None,
            "ipv6": config.ipv6,
            "env_dir": str(self._env_dir),
            "vm_mode": config.vm_mode,
        }
        cfg.update(overrides)
        return cfg

    def _finalize_init(
        self, config: SandboxConfig, name: str,
        ll_strict: bool,
        extra_features: dict[str, Any] | None = None,
    ) -> None:
        """Post-shell-start: pasta (rootful), OOM, pid file, features, logging."""
        # Rootful pasta: sandbox already has its own netns (net_isolate=True),
        # pasta connects to it and provides NAT + port forwarding.
        if not self._userns and config.port_map:
            self._start_pasta_rootful(config)

        if config.oom_score_adj is not None:
            self._apply_oom_score_adj(config.oom_score_adj)

        pid_file = self._env_dir / ".pid"
        pid_file.write_text(str(self._persistent_shell.pid))

        self.features: SandboxFeatures = {
            "pidfd": self._persistent_shell._pidfd is not None,
            "seccomp": config.seccomp,
            "landlock": ll_strict,
            "netns": config.net_isolate,
            "devices": bool(config.devices),
            "mask_paths": True,
            "cap_drop": True,
        }
        if extra_features:
            self.features.update(extra_features)  # type: ignore[typeddict-item]

        feat_str = ", ".join(
            k if v is True else f"{k}={v}"
            for k, v in self.features.items()
            if v
        )
        mode = "userns" if self._userns else "rootful"
        logger.info(
            "Sandbox ready (%s): name=%s rootfs=%s features=[%s]",
            mode, name, self._rootfs, feat_str,
        )

    # ================================================================== #
    #  Init paths                                                          #
    # ================================================================== #

    def _init_rootful(self, config: SandboxConfig, name: str) -> None:
        """Initialize in rootful mode -- full isolation."""
        self._fs_backend = config.fs_backend
        if self._fs_backend not in self.SUPPORTED_FS_BACKENDS:
            raise SandboxConfigError(
                f"Unsupported fs_backend {self._fs_backend!r}. "
                f"Choose from: {self.SUPPORTED_FS_BACKENDS}"
            )
        self._check_prerequisites(self._fs_backend)
        self._init_common_state(config, name)

        # --- rootfs -------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        self._base_rootfs, self._layer_dirs = self._resolve_base_rootfs(
            image=config.image,
            fs_backend=self._fs_backend,
            rootfs_cache_dir=rootfs_cache_dir,
        )
        if self._layer_dirs:
            self._lowerdir_spec = ":".join(
                str(d) for d in reversed(self._layer_dirs)
            )
        else:
            self._lowerdir_spec = str(self._base_rootfs)

        self._upper_dir: Path | None = None
        self._work_dir: Path | None = None

        # --- filesystem + cgroup ----------------------------------------
        if self._fs_backend == "btrfs":
            self._setup_btrfs()
        else:
            self._upper_dir = self._env_dir / "upper"
            self._work_dir = self._env_dir / "work"
            self._setup_overlay()
        self._setup_cgroup()
        # NOTE: volumes are NOT bind-mounted here on the Python side.
        # In rootful mode the Rust child_init mounts them after pivot_root
        # inside the new mount namespace.  The Python-side bind mounts done
        # before fork would be hidden by the pivot_root self-bind and the
        # new PID namespace anyway.

        if config.working_dir and config.working_dir != "/":
            wd = self._rootfs / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)
        if config.dns:
            self._write_dns(config.dns)

        # --- spawn shell --------------------------------------------------
        ll_result = self._build_landlock_config(config)
        spawn_cfg = self._build_spawn_config(config, ll_result,
            volumes=list(config.volumes) if config.volumes else [],
            shm_size=int(config.shm_size) if config.shm_size else None,
            tmpfs_mounts=list(config.tmpfs) if config.tmpfs else [],
            env_dir=str(self._env_dir),
        )

        from nitrobox._shell import _PersistentShell
        self._persistent_shell = _PersistentShell(
            spawn_cfg, ulimits=config.ulimits or None,  # type: ignore[arg-type]
        )

        self._finalize_init(config, name, ll_result[3], extra_features={
            "cgroup_v2": self._cgroup_path is not None,
            "timens": getattr(self._persistent_shell, "_timens", False),
            "cpuset_cpus": config.cpuset_cpus,
            "oom_score_adj": config.oom_score_adj,
        })

    def _init_userns(self, config: SandboxConfig, name: str) -> None:
        """Initialize in user namespace mode -- namespace+overlayfs without root."""
        if config.fs_backend != "overlayfs":
            raise SandboxConfigError(
                f"Rootless mode only supports overlayfs, got fs_backend={config.fs_backend!r}."
            )
        self._fs_backend = "overlayfs"
        self._check_prerequisites_userns()
        self._init_common_state(config, name)

        # --- rootfs -------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        from nitrobox.rootfs import _detect_whiteout_strategy
        whiteout_strategy = _detect_whiteout_strategy()

        if whiteout_strategy == "none":
            logger.debug("Kernel too old for rootless layer cache, using flat rootfs")
            self._base_rootfs = self._resolve_flat_rootfs(
                image=config.image,
                rootfs_cache_dir=rootfs_cache_dir,
            )
            self._layer_dirs: list[Path] | None = None
            self._lowerdir_spec = str(self._base_rootfs)
        else:
            self._base_rootfs, self._layer_dirs = self._resolve_base_rootfs(
                image=config.image,
                rootfs_cache_dir=rootfs_cache_dir,
                fs_backend="overlayfs",
            )
            if self._layer_dirs:
                self._lowerdir_spec = ":".join(
                    str(d) for d in reversed(self._layer_dirs)
                )
            else:
                self._lowerdir_spec = str(self._base_rootfs)

        self._upper_dir = self._env_dir / "upper"
        self._work_dir = self._env_dir / "work"
        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        # --- cgroup via systemd delegation --------------------------------
        self._systemd_scope_properties: list[str] = []
        if any(self._cgroup_limits.values()):
            if shutil.which("systemd-run"):
                prop_map = {
                    "cpu_max": "CPUQuota",
                    "memory_max": "MemoryMax",
                    "pids_max": "TasksMax",
                    "io_max": "IOWriteBandwidthMax",
                    "cpu_shares": "CPUWeight",
                    "memory_swap": "MemorySwapMax",
                }
                for key, sd_prop in prop_map.items():
                    value = self._cgroup_limits.get(key)
                    if value:
                        if key == "cpu_max":
                            parts = str(value).split()
                            if len(parts) == 2:
                                pct = int(int(parts[0]) / int(parts[1]) * 100)
                                self._systemd_scope_properties.append(f"{sd_prop}={pct}%")
                        elif key == "io_max":
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                        elif key == "cpu_shares":
                            from nitrobox.config import _convert_cpu_shares
                            weight = _convert_cpu_shares(int(value))
                            self._systemd_scope_properties.append(f"{sd_prop}={weight}")
                        else:
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                logger.debug(
                    "cgroup via systemd delegation: %s",
                    self._systemd_scope_properties,
                )
            else:
                logger.warning(
                    "cgroup resource limits requested but systemd-run not found."
                )

        # --- DNS + working dir --------------------------------------------
        if config.dns:
            self._write_dns(config.dns)
        if config.working_dir and config.working_dir != "/":
            wd = self._upper_dir / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)

        # --- detect subordinate uid range for full mapping -----------------
        self._subuid_range = self._detect_subuid_range()

        # --- spawn shell (Rust init chain) --------------------------------
        ll_result = self._build_landlock_config(config)
        spawn_cfg = self._build_spawn_config(config, ll_result,
            shared_userns=config.shared_userns,
            subuid_range=self._subuid_range,
            lowerdir_spec=self._lowerdir_spec,
            upper_dir=str(self._upper_dir),
            work_dir=str(self._work_dir),
            volumes=list(config.volumes) if config.volumes else [],
            shm_size=int(config.shm_size) if config.shm_size else None,
            tmpfs_mounts=list(config.tmpfs) if config.tmpfs else [],
        )

        from nitrobox._shell import _PersistentShell
        self._persistent_shell = _PersistentShell(
            spawn_cfg, ulimits=config.ulimits or None,  # type: ignore[arg-type]
        )

        self._finalize_init(config, name, ll_result[3], extra_features={
            "userns": True,
            "layer_cache": self._layer_dirs is not None,
            "whiteout": whiteout_strategy,
        })

    # ================================================================== #
    #  Rootfs resolution                                                   #
    # ================================================================== #

    @staticmethod
    def _resolve_base_rootfs(
        image: str,
        fs_backend: str,
        rootfs_cache_dir: Path,
    ) -> tuple[Path, list[Path] | None]:
        """Resolve the base rootfs for a sandbox."""
        candidate = Path(image)
        if candidate.exists() and candidate.is_dir():
            return candidate, None

        if fs_backend == "btrfs":
            return Sandbox._resolve_btrfs_rootfs(image, rootfs_cache_dir), None

        # --- overlayfs: layer-level caching ---
        from nitrobox.rootfs import prepare_rootfs_layers_from_docker

        t0 = time.monotonic()
        layer_dirs = prepare_rootfs_layers_from_docker(
            image, rootfs_cache_dir, pull=True,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "Layer cache ready (%.1fms): %s (%d layers)",
            elapsed_ms, image, len(layer_dirs),
        )
        return layer_dirs[0], layer_dirs

    @staticmethod
    def _resolve_cached_rootfs(
        image: str,
        rootfs_cache_dir: Path,
        prepare_fn: Any,
        *,
        verify_fn: Any = None,
        label: str = "rootfs",
    ) -> Path:
        """Resolve a flat rootfs with file-lock-based caching.

        Shared logic for btrfs and docker-export rootfs preparation.
        """
        import fcntl

        candidate = Path(image)
        if candidate.exists() and candidate.is_dir():
            if verify_fn:
                verify_fn(candidate)
            return candidate

        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        cached_rootfs = rootfs_cache_dir / safe_name

        if cached_rootfs.exists() and cached_rootfs.is_dir():
            if verify_fn:
                verify_fn(cached_rootfs)
            return cached_rootfs

        lock_path = rootfs_cache_dir / f".{safe_name}.lock"
        rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if cached_rootfs.exists() and cached_rootfs.is_dir():
                    if verify_fn:
                        verify_fn(cached_rootfs)
                    return cached_rootfs

                t0 = time.monotonic()
                prepare_fn(image, cached_rootfs)
                elapsed_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "Auto-prepared %s (%.1fms): %s -> %s",
                    label, elapsed_ms, image, cached_rootfs,
                )
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        return cached_rootfs

    @staticmethod
    def _resolve_btrfs_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
        """Resolve flat rootfs for btrfs backend."""
        from nitrobox.rootfs import prepare_btrfs_rootfs_from_docker
        return Sandbox._resolve_cached_rootfs(
            image, rootfs_cache_dir, prepare_btrfs_rootfs_from_docker,
            verify_fn=Sandbox._verify_btrfs_subvolume,
            label="btrfs rootfs",
        )

    @staticmethod
    def _resolve_flat_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
        """Resolve flat rootfs via docker export (for userns/rootless)."""
        from nitrobox.rootfs import prepare_rootfs_from_docker
        return Sandbox._resolve_cached_rootfs(
            image, rootfs_cache_dir, prepare_rootfs_from_docker,
            label="flat rootfs",
        )

    # ================================================================== #
    #  Prerequisites                                                       #
    # ================================================================== #

    @staticmethod
    def _check_prerequisites(fs_backend: str = "overlayfs") -> None:
        if os.geteuid() != 0:
            raise SandboxKernelError(
                "Sandbox requires root for mount / cgroup operations."
            )
        if shutil.which("unshare") is None:
            raise SandboxKernelError(
                "unshare not found. Install util-linux."
            )
        if fs_backend == "overlayfs":
            result = subprocess.run(
                ["grep", "-q", "overlay", "/proc/filesystems"],
                capture_output=True,
            )
            if result.returncode != 0:
                raise SandboxKernelError("Kernel does not support overlayfs.")
        elif fs_backend == "btrfs":
            if shutil.which("btrfs") is None:
                raise SandboxKernelError("btrfs-progs not found.")

    @classmethod
    def _check_prerequisites_userns(cls) -> None:
        """Check user namespace prerequisites (cached after first success)."""
        if cls._prereq_checked:
            return
        if shutil.which("unshare") is None:
            raise SandboxKernelError(
                "unshare not found. Install util-linux."
            )
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "true"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise SandboxKernelError(
                "User namespaces are not available. Possible fixes:\n"
                "  sysctl -w kernel.unprivileged_userns_clone=1\n"
                "  sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n"
                f"Error: {result.stderr.decode().strip()}"
            )
        cls._prereq_checked = True

    @classmethod
    def _detect_subuid_range(cls) -> tuple[int, int, int] | None:
        """Detect subordinate UID range for full uid mapping in user namespaces."""
        if cls._subuid_detected:
            return cls._cached_subuid_range

        if shutil.which("newuidmap") is None or shutil.which("newgidmap") is None:
            logger.debug(
                "newuidmap/newgidmap not found. Falling back to root-only mapping."
            )
            cls._subuid_detected = True
            return None

        import getpass
        try:
            username = getpass.getuser()
        except (KeyError, OSError):
            cls._subuid_detected = True
            return None

        uid = os.getuid()

        try:
            with open("/etc/subuid") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) != 3:
                        continue
                    if parts[0] == username or parts[0] == str(uid):
                        sub_start = int(parts[1])
                        sub_count = int(parts[2])
                        logger.debug(
                            "Full uid mapping available: %s:%d:%d",
                            username, sub_start, sub_count,
                        )
                        cls._cached_subuid_range = (uid, sub_start, sub_count)
                        cls._subuid_detected = True
                        return cls._cached_subuid_range
        except FileNotFoundError:
            pass

        logger.debug(
            "No /etc/subuid entry for %s. Falling back to root-only mapping.",
            username,
        )
        cls._subuid_detected = True
        return None

    # ================================================================== #
    #  Filesystem -- overlayfs                                             #
    # ================================================================== #

    def _setup_overlay(self) -> None:
        from nitrobox._core import py_mount_overlay

        assert self._upper_dir is not None and self._work_dir is not None
        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        py_mount_overlay(
            self._lowerdir_spec,
            str(self._upper_dir),
            str(self._work_dir),
            str(self._rootfs),
        )

        from nitrobox._core import py_make_private
        try:
            py_make_private(str(self._rootfs))
        except OSError:
            pass

        self._overlay_mounted = True
        logger.debug("Mounted overlayfs at %s", self._rootfs)

    def _reset_overlayfs(self) -> None:
        if self._overlay_mounted:
            from nitrobox._core import py_umount_lazy
            try:
                py_umount_lazy(str(self._rootfs))
            except OSError:
                pass
            self._overlay_mounted = False

        self._cleanup_dead_dirs()
        for d in (self._upper_dir, self._work_dir):
            if d and d.exists():
                dead = d.with_name(f"{d.name}.dead.{time.monotonic_ns()}")
                try:
                    d.rename(dead)
                except OSError:
                    shutil.rmtree(d, ignore_errors=True)
            if d:
                d.mkdir(parents=True, exist_ok=True)

        self._setup_overlay()

    # ================================================================== #
    #  Filesystem -- btrfs                                                 #
    # ================================================================== #

    def _setup_btrfs(self) -> None:
        self._verify_btrfs_subvolume(self._base_rootfs)
        self._env_dir.mkdir(parents=True, exist_ok=True)

        if self._rootfs.exists():
            check = subprocess.run(
                ["btrfs", "subvolume", "show", str(self._rootfs)],
                capture_output=True, text=True,
            )
            if check.returncode == 0:
                subprocess.run(
                    ["btrfs", "subvolume", "delete", str(self._rootfs)],
                    capture_output=True,
                )
            else:
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            ["btrfs", "subvolume", "snapshot", str(self._base_rootfs), str(self._rootfs)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise SandboxInitError(f"btrfs snapshot failed: {result.stderr.strip()}")
        self._btrfs_active = True

    @staticmethod
    def _verify_btrfs_subvolume(path: Path) -> None:
        result = subprocess.run(
            ["btrfs", "subvolume", "show", str(path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise SandboxConfigError(f"Not a btrfs subvolume: {path}")

    def _reset_btrfs(self) -> None:
        result = subprocess.run(
            ["btrfs", "subvolume", "delete", str(self._rootfs)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.warning("btrfs subvolume delete failed: %s", result.stderr.strip())
            if self._rootfs.exists():
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            ["btrfs", "subvolume", "snapshot", str(self._base_rootfs), str(self._rootfs)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise SandboxInitError(f"btrfs snapshot failed on reset: {result.stderr.strip()}")
        self._btrfs_active = True

    # ================================================================== #
    #  Volume management                                                   #
    # ================================================================== #

    def _apply_config_volumes(self) -> None:
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
    ) -> None:
        from nitrobox._core import py_bind_mount, py_remount_ro_bind

        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        try:
            py_bind_mount(host_path, str(target))
        except OSError as e:
            logger.warning("Failed to bind mount %s -> %s: %s",
                           host_path, container_path, e)
            return

        self._bind_mounts.append(target)

        if read_only:
            try:
                py_remount_ro_bind(str(target))
            except OSError:
                pass

    def _overlay_mount(self, host_path: str, container_path: str) -> None:
        """Mount a host directory as copy-on-write via overlayfs."""
        import tempfile
        from nitrobox._core import py_mount_overlay

        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        work_base = tempfile.mkdtemp(prefix="nbx_cow_")
        upper = Path(work_base) / "upper"
        work = Path(work_base) / "work"
        upper.mkdir()
        work.mkdir()

        try:
            py_mount_overlay(str(host_path), str(upper), str(work), str(target))
        except OSError as e:
            logger.warning("Failed to overlay mount %s -> %s: %s",
                           host_path, container_path, e)
            return

        self._bind_mounts.append(target)
        self._cow_tmpdirs.append(work_base)

    def _unmount_binds(self) -> None:
        from nitrobox._core import py_umount_lazy
        for mount_point in reversed(self._bind_mounts):
            try:
                py_umount_lazy(str(mount_point))
            except OSError:
                pass
        self._bind_mounts.clear()
        for tmpdir in self._cow_tmpdirs:
            shutil.rmtree(tmpdir, ignore_errors=True)
        self._cow_tmpdirs = []

    def _unmount_all(self) -> None:
        from nitrobox._core import py_umount_recursive_lazy
        self._unmount_binds()
        if self._fs_backend == "overlayfs" and self._overlay_mounted:
            try:
                py_umount_recursive_lazy(str(self._rootfs))
            except OSError:
                pass
            self._overlay_mounted = False

    # ================================================================== #
    #  cgroup v2 resource limits                                           #
    # ================================================================== #

    def _setup_cgroup(self) -> None:
        if not any(self._cgroup_limits.values()):
            return

        from nitrobox._core import (
            py_apply_cgroup_limits,
            py_cgroup_v2_available,
            py_create_cgroup,
        )

        if not py_cgroup_v2_available():
            logger.warning("cgroup v2 not available -- resource limits will not be enforced.")
            return

        cgroup_name = self._env_dir.name
        try:
            cgroup_path_str = py_create_cgroup(cgroup_name)
            self._cgroup_path = Path(cgroup_path_str)
        except OSError as e:
            logger.warning("Failed to create cgroup: %s", e)
            self._cgroup_path = None
            return

        # Build limits dict with only non-None values
        limits: dict[str, str] = {}
        for key, value in self._cgroup_limits.items():
            if value:
                limits[key] = str(value)
        if limits:
            try:
                py_apply_cgroup_limits(str(self._cgroup_path), limits)
            except OSError as e:
                logger.warning("Failed to apply cgroup limits: %s", e)

    def _cleanup_cgroup(self) -> None:
        if not self._cgroup_path or not self._cgroup_path.exists():
            return
        try:
            from nitrobox._core import py_cleanup_cgroup
            py_cleanup_cgroup(str(self._cgroup_path))
        except OSError as e:
            logger.debug("cgroup cleanup (non-fatal): %s", e)

    # ================================================================== #
    #  Network: pasta / DNS                                                #
    # ================================================================== #

    def _write_dns(self, dns_servers: list[str]) -> None:
        resolv = self._host_path_write("/etc/resolv.conf")
        resolv.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(f"nameserver {s}\n" for s in dns_servers)
        resolv.write_text(content)

    def _start_pasta_rootful(self, config: SandboxConfig) -> None:
        """Attach pasta to the sandbox's existing network namespace (rootful only).

        The sandbox was created with ``net_isolate=True`` (its own netns via
        ``unshare(CLONE_NEWNET)``).  Pasta connects to that netns from the host
        and provides NAT + TCP port forwarding.
        """
        pasta_bin = self._find_pasta_bin()
        if not pasta_bin:
            raise SandboxKernelError(
                "port_map requires 'pasta' (from the passt package)."
            )

        shell_pid = self._persistent_shell.pid
        netns_name = f"nitrobox-{self._name}"

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
        self._netns_path = netns_path

        cmd: list[str] = [
            pasta_bin, "--config-net", "--runas", "0:0",
        ]
        if not config.ipv6:
            cmd.append("--ipv4-only")
        for mapping in config.port_map:
            cmd.extend(["-t", mapping])
        cmd.extend([
            "-u", "none", "-T", "none", "-U", "none",
            "--dns-forward", "169.254.1.1",
            "--no-map-gw", "--quiet",
            "--netns", netns_path,
            "--map-guest-addr", "169.254.1.2",
        ])

        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            raise SandboxInitError(
                f"pasta failed (exit={out.returncode}): {out.stderr.strip()}"
            )

        # Bring up loopback inside the netns
        self._persistent_shell.execute(
            "ip link set lo up 2>/dev/null || true",
            timeout=5,
        )
        logger.debug("pasta ready (rootful): pid=%d ports=%s", shell_pid, config.port_map)

    def _stop_pasta_rootful(self) -> None:
        """Clean up rootful pasta netns bind mount."""
        netns_path = getattr(self, "_netns_path", None)
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
            self._netns_path = None

    @staticmethod
    def _find_pasta_bin() -> str | None:
        """Find the pasta binary (vendored or system)."""
        vendored = Path(__file__).parent / "_vendor" / "pasta"
        if vendored.exists() and vendored.is_file():
            return str(vendored)
        if shutil.which("pasta"):
            return "pasta"
        return None

    # ================================================================== #
    #  Reset / cleanup helpers                                             #
    # ================================================================== #

    def _fixup_userns_permissions(self) -> None:
        """Make mapped-uid files deletable before destroying userns sandbox.

        In userns mode, non-root users inside the sandbox (e.g. _apt,
        www-data) create files with mapped UIDs that the host user can't
        delete.  Uses Rust ``py_userns_fixup_for_delete`` to fork, enter
        the user namespace via ``setns()``, and recursively chmod+chown
        the overlayfs upper dir — no ``nsenter`` subprocess needed.
        """
        if not self._userns:
            return
        upper = getattr(self, "_upper_dir", None)
        if not upper or not upper.exists():
            return
        shell = self._persistent_shell
        if not shell.alive:
            return
        try:
            from nitrobox._core import py_userns_fixup_for_delete
            py_userns_fixup_for_delete(shell.pid, str(upper))
        except (OSError, ImportError) as e:
            logger.debug("_fixup_userns_permissions: %s", e)

    def _fixup_userns_ownership(self) -> None:
        """Fix ownership of files in env_dir created by mapped uids.

        Uses Rust ``py_userns_fixup_for_delete`` to enter the user
        namespace and recursively lchown to root (= host user outside
        the namespace).
        """
        if not self._userns or not self._subuid_range:
            return
        shell = self._persistent_shell
        if not shell.alive:
            return
        try:
            from nitrobox._core import py_userns_fixup_for_delete
            py_userns_fixup_for_delete(shell.pid, str(self._env_dir))
        except (OSError, ImportError) as e:
            logger.warning("_fixup_userns_ownership failed: %s", e)

    def _cleanup_dead_dirs(self) -> None:
        """Remove ``*.dead.*`` dirs left by previous rename-based resets."""
        for dead in self._env_dir.glob("*.dead.*"):
            if dead.is_dir():
                for child in dead.rglob("*"):
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
                shutil.rmtree(dead, ignore_errors=True)

    def _apply_oom_score_adj(self, score: int) -> None:
        pid = self._persistent_shell.pid
        try:
            Path(f"/proc/{pid}/oom_score_adj").write_text(str(score))
        except OSError as e:
            logger.warning("Failed to set oom_score_adj=%d: %s", score, e)

    # ================================================================== #
    #  Internal helpers                                                    #
    # ================================================================== #

    def _detect_shell(self) -> str:
        if self._host_path("/bin/bash").exists():
            return "/bin/bash"
        return "/bin/sh"

    def _host_path(self, container_path: str) -> Path:
        """Resolve container_path for reads.

        In userns mode the overlayfs is inside the sandbox mount namespace
        (not visible from the host), so we manually search:
        upper_dir → each layer dir (top to bottom) → fallback to upper.
        """
        if self._userns:
            assert self._upper_dir is not None
            stripped = container_path.lstrip("/")
            upper = self._upper_dir / stripped
            if upper.exists():
                return upper
            # Search all layers top-to-bottom (reversed because _layer_dirs
            # is stored bottom-to-top, matching the Docker layer order).
            if self._layer_dirs:
                for layer in reversed(self._layer_dirs):
                    candidate = layer / stripped
                    if candidate.exists():
                        return candidate
            elif self._base_rootfs is not None:
                base = self._base_rootfs / stripped
                if base.exists():
                    return base
            return upper
        assert self._rootfs is not None
        return self._rootfs / container_path.lstrip("/")

    def _host_path_write(self, container_path: str) -> Path:
        """Resolve container_path for writes."""
        if self._userns:
            assert self._upper_dir is not None
            return self._upper_dir / container_path.lstrip("/")
        assert self._rootfs is not None
        return self._rootfs / container_path.lstrip("/")

    def _build_env(self) -> dict[str, str]:
        env = {
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
        }
        if self._config.tty:
            env["TERM"] = "dumb"
            env["NO_COLOR"] = "1"
        env.update(self._config.environment)
        return env

    @staticmethod
    def _build_landlock_config(
        config: SandboxConfig,
    ) -> tuple[list[str], list[str], list[int], bool]:
        """Validate Landlock settings and build path/port lists for Rust init.

        Returns ``(read_paths, write_paths, ports, strict)`` tuple.
        When no Landlock params are set, returns empty lists and ``strict=False``.
        """
        if not any([config.writable_paths, config.readable_paths, config.allowed_ports]):
            return [], [], [], False

        from nitrobox._core import py_landlock_abi_version
        abi = py_landlock_abi_version()
        if abi == 0:
            raise SandboxKernelError(
                "Landlock not available (kernel < 5.13), "
                "but writable_paths/readable_paths/allowed_ports were set."
            )
        if config.allowed_ports is not None and abi < 4:
            raise SandboxKernelError(
                f"Landlock network port rules require ABI v4+ (kernel 6.7+), "
                f"but this kernel only supports ABI v{abi}."
            )

        essential_writable = {"/dev", "/proc", "/tmp"}
        essential_readable = {"/dev", "/proc", "/sys", "/tmp"}
        writable_set: set[str] = set()
        ll_write: list[str] = []
        ll_read: list[str] = []
        ll_ports: list[int] = []

        if config.writable_paths is not None:
            writable_set = set(config.writable_paths) | essential_writable
            ll_write = sorted(writable_set)
        if config.readable_paths is not None:
            all_readable = set(config.readable_paths) | essential_readable
            ll_read = sorted(all_readable - writable_set)
        if config.allowed_ports is not None:
            ll_ports = list(config.allowed_ports)

        return ll_read, ll_write, ll_ports, True

    def __del__(self) -> None:
        try:
            if hasattr(self, "_persistent_shell"):
                self._persistent_shell.kill()
            if not getattr(self, "_userns", False):
                self._unmount_all()
        except Exception:
            pass

    def __repr__(self) -> str:
        fs = getattr(self, "_fs_backend", "?")
        return f"Sandbox(name={self._name!r}, fs={fs}, rootfs={self._rootfs})"
