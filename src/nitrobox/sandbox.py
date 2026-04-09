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
)
from nitrobox.config import SandboxConfig, cap_names_to_numbers

if TYPE_CHECKING:
    pass

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
#  Cleanup helpers                                                         #
# ====================================================================== #


def _force_rmtree(entry: Path) -> None:
    """Remove a sandbox directory, handling overlay workdir perms and mapped UIDs.

    1. chmod everything we can (fixes overlay's 000 workdir)
    2. Try shutil.rmtree
    3. If that fails, use rmtree_mapped (fork + userns + rm -rf)
    """
    # Fix overlay workdir 000 permissions
    for child in entry.rglob("*"):
        try:
            child.chmod(0o700)
        except OSError:
            pass

    try:
        shutil.rmtree(entry)
        return
    except (PermissionError, OSError):
        pass

    from nitrobox.image.layers import rmtree_mapped
    rmtree_mapped(entry)


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
        with Sandbox(config, name="worker-0") as box:
            output, ec = box.run("echo hello world")
            box.reset()        # instant filesystem reset
    """

    SUPPORTED_FS_BACKENDS = ("overlayfs", "btrfs")

    # -- global registry for atexit cleanup -------------------------------- #
    _live_instances: list[Sandbox] = []
    _atexit_registered: bool = False

    # -- rootless caches (class-level) ------------------------------------- #
    _prereq_checked = False

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
            if self._userns:
                from nitrobox.image.layers import rmtree_mapped
                rmtree_mapped(env_dir)
            else:
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

        if (
            exit_code != 0
            and self._subuid_range is None
            and ("setgroups" in output or "setegid" in output or "seteuid" in output)
        ):
            logger.error(
                "Command failed due to missing multi-UID mapping. "
                "Install the 'uidmap' package: "
                "sudo apt-get install -y uidmap"
            )

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

        Uses ``nitrobox-core nsenter-exec`` to enter the sandbox's namespace
        and exec the command. This avoids ``preexec_fn`` which is incompatible
        with the Go binary (CGO constructor for namespace entry).

        Returns a :class:`subprocess.Popen` object with direct
        ``stdin``/``stdout``/``stderr`` pipes for bidirectional communication.
        """
        if isinstance(command, list):
            cmd_args = command
        else:
            cmd_args = ["sh", "-c", command]

        shell_pid = self._persistent_shell.pid

        # Use Rust preexec_fn to setns into the sandbox's namespaces.
        # preexec_fn runs after fork (single-threaded child), so setns
        # to CLONE_NEWUSER works (requires single-threaded caller).
        if self._userns:
            from nitrobox._core import py_userns_preexec
            rootfs = str(self._rootfs)
            workdir = self._config.working_dir or "/"
            preexec = lambda: py_userns_preexec(shell_pid, rootfs, workdir)
        else:
            from nitrobox._core import py_nsenter_preexec
            preexec = lambda: py_nsenter_preexec(shell_pid)

        defaults: dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "preexec_fn": preexec,
        }
        defaults.update(kwargs)
        proc = subprocess.Popen(cmd_args, **defaults)

        logger.debug("popen pid=%d in sandbox: %s", proc.pid, cmd_args)
        return proc

    # -- file operations --------------------------------------------------- #

    def copy_to(self, local_path: str, container_path: str) -> None:
        """Copy a file or directory from host into the sandbox."""
        host_dst = self._host_path_write(container_path)
        host_dst.parent.mkdir(parents=True, exist_ok=True)
        src = Path(local_path)
        if src.is_dir():
            shutil.copytree(local_path, str(host_dst), dirs_exist_ok=True)
        else:
            shutil.copy2(local_path, str(host_dst))

    def copy_from(self, container_path: str, local_path: str) -> None:
        """Copy a file or directory from the sandbox to host."""
        host_src = self._host_path(container_path)
        if not host_src.exists():
            raise FileNotFoundError(
                f"File {container_path} does not exist in the sandbox."
            )
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        if host_src.is_dir():
            shutil.copytree(str(host_src), local_path, dirs_exist_ok=True)
        else:
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

        # Create tar of rootfs and import via Docker Engine API.
        tar_proc = subprocess.Popen(
            ["tar", "-C", str(rootfs), "-c", "."],
            stdout=subprocess.PIPE,
        )
        try:
            from nitrobox.docker_api import get_client
            # Split "name:tag" if provided.
            if ":" in image_name:
                repo, tag = image_name.rsplit(":", 1)
            else:
                repo, tag = image_name, "latest"
            get_client().image_import(tar_proc.stdout, repo, tag)
        except Exception as e:
            raise SandboxInitError(f"docker import failed: {e}") from e
        finally:
            tar_proc.wait()
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

        self._unmount_all()
        # If overlay is still mounted (e.g. after checkpoint restore which
        # mounts via the setuid helper), force a lazy umount as fallback.
        if self._overlay_mounted and self._rootfs.is_mount():
            try:
                subprocess.run(
                    ["umount", "-l", str(self._rootfs)],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
            self._overlay_mounted = False
        if not self._userns:
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
                from nitrobox.image.layers import rmtree_mapped
                rmtree_mapped(self._env_dir)
            else:
                shutil.rmtree(self._env_dir, ignore_errors=True)

        # Release shared locks on layer dirs — allows cache cleanup to proceed.
        if hasattr(self, "_layer_lock_fds") and self._layer_lock_fds:
            from nitrobox.image.layers import release_layer_locks
            release_layer_locks(self._layer_lock_fds)
            self._layer_lock_fds = []

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
        for box in list(cls._live_instances):
            try:
                box.delete()
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
                    rootfs_dir = entry / "rootfs"
                    if rootfs_dir.exists():
                        from nitrobox._core import py_umount_recursive_lazy
                        try:
                            py_umount_recursive_lazy(str(rootfs_dir))
                        except OSError:
                            # Mount was created in a different userns that no longer
                            # exists — only real root or a reboot can unmount it.
                            # Skip the dir; rmtree would fail on the mountpoint.
                            if rootfs_dir.is_mount():
                                logger.warning(
                                    "Cannot unmount orphaned %s (stale userns mount, "
                                    "needs sudo umount -l or reboot)", rootfs_dir,
                                )
                                continue
                    _force_rmtree(entry)
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

            _force_rmtree(entry)
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
            "memory_high": config.memory_high,
            "pids_max": config.pids_max,
            "io_max": config.io_max,
            "cpuset_cpus": config.cpuset_cpus,
            "cpuset_mems": config.cpuset_mems,
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
            "cap_drop": cap_names_to_numbers(config.cap_drop) if config.cap_drop else [],
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

        # Save UID mapping so cleanup_stale can enter a userns with the
        # same mapping to delete mapped-UID files after a crash.
        if self._userns and self._subuid_range:
            import json
            uid_map_file = self._env_dir / ".uidmap"
            outer_uid, sub_start, sub_count = self._subuid_range
            uid_map_file.write_text(json.dumps({
                "outer_uid": outer_uid,
                "outer_gid": os.getgid(),
                "sub_start": sub_start,
                "sub_count": sub_count,
            }))

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

        # Acquire shared locks on layer dirs
        self._layer_lock_fds: list[int] = []
        if self._layer_dirs:
            from nitrobox.image.layers import acquire_layer_locks
            self._layer_lock_fds = acquire_layer_locks(self._layer_dirs)

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
        from nitrobox.storage.whiteout import _detect_whiteout_strategy
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

        # Acquire shared locks on layer dirs — prevents concurrent deletion
        # while this sandbox's overlayfs uses them as lowerdir.
        self._layer_lock_fds: list[int] = []
        if self._layer_dirs:
            from nitrobox.image.layers import acquire_layer_locks
            self._layer_lock_fds = acquire_layer_locks(self._layer_dirs)

        self._upper_dir = self._env_dir / "upper"
        self._work_dir = self._env_dir / "work"
        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        # --- cgroup via delegation ----------------------------------------
        self._setup_cgroup_rootless()

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
            "cgroup_v2": self._cgroup_path is not None,
        })

    # ================================================================== #
    #  Rootfs resolution                                                   #
    # ================================================================== #

    @staticmethod
    def _resolve_base_rootfs(image, fs_backend="overlayfs", rootfs_cache_dir=Path()):
        from nitrobox.image.layers import resolve_base_rootfs
        return resolve_base_rootfs(image, rootfs_cache_dir, fs_backend)

    @staticmethod
    def _get_image_digest(image):
        from nitrobox.image.layers import _get_image_digest
        return _get_image_digest(image)

    @staticmethod
    def _resolve_cached_rootfs(image, rootfs_cache_dir, prepare_fn, *, verify_fn=None, label="rootfs"):
        from nitrobox.image.layers import _resolve_cached_rootfs
        return _resolve_cached_rootfs(image, rootfs_cache_dir, prepare_fn, verify_fn=verify_fn, label=label)

    @staticmethod
    def _resolve_btrfs_rootfs(image, rootfs_cache_dir):
        from nitrobox.image.layers import resolve_btrfs_rootfs
        return resolve_btrfs_rootfs(image, rootfs_cache_dir)

    @staticmethod
    def _resolve_flat_rootfs(image, rootfs_cache_dir):
        from nitrobox.image.layers import resolve_flat_rootfs
        return resolve_flat_rootfs(image, rootfs_cache_dir)

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
        from nitrobox.config import detect_subuid_range
        return detect_subuid_range()

    # ================================================================== #
    #  Filesystem -- overlayfs                                             #
    # ================================================================== #

    def _setup_overlay(self) -> None:
        from nitrobox.storage.overlay import setup_overlay

        assert self._upper_dir is not None and self._work_dir is not None
        setup_overlay(
            self._lowerdir_spec,
            str(self._upper_dir),
            str(self._work_dir),
            str(self._rootfs),
        )
        self._overlay_mounted = True

    def _reset_overlayfs(self) -> None:
        from nitrobox.storage.overlay import reset_overlayfs

        self._cleanup_dead_dirs()
        reset_overlayfs(
            rootfs=str(self._rootfs),
            upper_dir=str(self._upper_dir),
            work_dir=str(self._work_dir),
            lowerdir_spec=self._lowerdir_spec,
            overlay_mounted=self._overlay_mounted,
        )
        self._overlay_mounted = True

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
        from nitrobox.storage.overlay import bind_mount

        target = bind_mount(
            host_path,
            container_path,
            str(self._rootfs),
            read_only=read_only,
        )
        if target is not None:
            self._bind_mounts.append(target)

    def _overlay_mount(self, host_path: str, container_path: str) -> None:
        """Mount a host directory as copy-on-write via overlayfs."""
        from nitrobox.storage.overlay import overlay_mount

        target, work_base = overlay_mount(
            host_path,
            container_path,
            str(self._rootfs),
        )
        if target is not None:
            self._bind_mounts.append(target)
            self._cow_tmpdirs.append(work_base)

    def _unmount_binds(self) -> None:
        from nitrobox.storage.overlay import unmount_binds

        unmount_binds(self._bind_mounts, self._cow_tmpdirs)
        self._cow_tmpdirs = []

    def _unmount_all(self) -> None:
        from nitrobox.storage.overlay import unmount_all

        unmount_all(
            rootfs=str(self._rootfs),
            bind_mounts=self._bind_mounts,
            cow_tmpdirs=self._cow_tmpdirs,
            fs_backend=self._fs_backend,
            overlay_mounted=self._overlay_mounted,
        )
        self._cow_tmpdirs = []
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
        from nitrobox._core import py_cleanup_cgroup
        try:
            py_cleanup_cgroup(str(self._cgroup_path))
        except OSError:
            pass
        # Rust retries for 200ms. If cgroup still exists, schedule a
        # background retry — don't block teardown.
        if self._cgroup_path.exists():
            cg = self._cgroup_path
            def _deferred_rmdir():
                for _ in range(20):
                    if not cg.exists():
                        return
                    try:
                        cg.rmdir()
                        return
                    except OSError:
                        time.sleep(0.1)
            threading.Thread(target=_deferred_rmdir, daemon=True).start()

    # -- rootless cgroup via delegation -------------------------------- #

    def _setup_cgroup_rootless(self) -> None:
        """Set up cgroup for rootless mode using delegated cgroup hierarchy."""
        if not any(self._cgroup_limits.values()):
            return

        from nitrobox._core import py_cgroup_v2_available

        if not py_cgroup_v2_available():
            logger.warning("cgroup v2 not available -- resource limits not enforced.")
            return

        cg_path = self._try_own_cgroup()
        if cg_path is None:
            cg_path = self._try_preallocated_cgroup()
        if cg_path is None:
            logger.warning(
                "Rootless cgroup: no delegated cgroup available. "
                "Resource limits will not be enforced. "
                "Run 'nitrobox setup' to configure cgroup delegation."
            )
            return

        self._cgroup_path = cg_path

        limits: dict[str, str] = {}
        for key, value in self._cgroup_limits.items():
            if value:
                limits[key] = str(value)
        if limits:
            from nitrobox._core import py_apply_cgroup_limits
            try:
                py_apply_cgroup_limits(str(cg_path), limits)
            except OSError as e:
                logger.warning("Failed to apply rootless cgroup limits: %s", e)

        logger.debug("Rootless cgroup ready: %s", cg_path)

    def _try_own_cgroup(self) -> Path | None:
        """Try to create a child cgroup under our own delegated cgroup.

        On systems with systemd user sessions, the user's cgroup is
        delegated and we can create sub-cgroups without root.
        """
        try:
            cg_content = Path("/proc/self/cgroup").read_text().strip()
            # cgroup v2 format: "0::/user.slice/user-1000.slice/..."
            for line in cg_content.splitlines():
                if line.startswith("0::"):
                    own_cg = line[3:]
                    break
            else:
                return None

            if not own_cg:
                return None

            base = Path(f"/sys/fs/cgroup{own_cg}")
            if not base.exists():
                return None

            cg_dir = base / f"nitrobox-{self._env_dir.name}"
            cg_dir.mkdir(exist_ok=True)

            # Verify we can actually write to it
            test_file = cg_dir / "cgroup.procs"
            if not test_file.exists():
                cg_dir.rmdir()
                return None

            logger.debug("Using delegated cgroup: %s", cg_dir)
            return cg_dir
        except OSError as e:
            logger.debug("Delegated cgroup not available: %s", e)
            return None

    # Pre-allocated cgroup path created by ``nitrobox setup``.
    CGROUP_PREALLOCATED = Path("/sys/fs/cgroup/nitrobox")

    def _try_preallocated_cgroup(self) -> Path | None:
        """Try the pre-allocated cgroup created by ``nitrobox setup``.

        ``nitrobox setup`` uses Docker to create ``/sys/fs/cgroup/nitrobox``
        owned by the current user, so no sudo is needed.
        """
        base = self.CGROUP_PREALLOCATED
        if not base.exists():
            return None
        try:
            cg_dir = base / self._env_dir.name
            cg_dir.mkdir(exist_ok=True)

            # Verify we can write
            test_file = cg_dir / "cgroup.procs"
            if not test_file.exists():
                cg_dir.rmdir()
                return None

            logger.debug("Using pre-allocated cgroup: %s", cg_dir)
            return cg_dir
        except OSError as e:
            logger.debug("Pre-allocated cgroup not available: %s", e)
            return None

    # ================================================================== #
    #  Network: pasta / DNS                                                #
    # ================================================================== #

    def _write_dns(self, dns_servers: list[str]) -> None:
        from nitrobox.network import write_dns
        write_dns(self._host_path_write, dns_servers)

    def _start_pasta_rootful(self, config: SandboxConfig) -> None:
        from nitrobox.network import start_pasta_rootful
        self._netns_path = start_pasta_rootful(
            self._name, self._persistent_shell.pid,
            config.net_isolate, config.port_map or [], config.ipv6,
            self._env_dir,
        )
        # Bring up loopback inside the netns
        self._persistent_shell.execute(
            "ip link set lo up 2>/dev/null || true",
            timeout=5,
        )

    def _stop_pasta_rootful(self) -> None:
        from nitrobox.network import stop_pasta_rootful
        stop_pasta_rootful(getattr(self, '_netns_path', None))
        self._netns_path = None

    @staticmethod
    def _find_pasta_bin() -> str | None:
        from nitrobox.network import find_pasta_bin
        return find_pasta_bin()


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
